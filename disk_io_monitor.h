/**
 * disk_io_monitor.h - Disk I/O saturation monitoring for VoIPmonitor sniffer
 *
 * Monitors disk write performance and detects saturation using:
 *   1. Throughput comparison with calibrated knee_throughput
 *   2. Write latency from /proc/diskstats (with baseline calibration)
 *   3. Queue depth and utilization from /proc/diskstats
 *   4. Buffer level from sniffer heap (asyncwrite)
 *
 * Key features:
 *   - Calibration profile: Stored in .disk_io_calibration.conf
 *   - Background calibration thread: Non-blocking startup
 *   - Capacity-based detection: Shows % of sustainable throughput used
 *   - UUID tracking: Auto-recalibrate when disk changes
 *
 * Output format: IO[B0.5|L1.2|U45|C75|W125|R10|WI1.2k|RI500]
 *   B = baseline latency (calibrated, ms)
 *   L = current latency (ms)
 *   U = disk utilization %
 *   C = capacity % (current throughput / knee throughput)
 *   W = write throughput MB/s
 *   R = read throughput MB/s
 *   WI = write IOPS (k = thousands)
 *   RI = read IOPS (k = thousands)
 */

#ifndef DISK_IO_MONITOR_H
#define DISK_IO_MONITOR_H

#include <string>
#include <vector>
#include <stdint.h>
#include <pthread.h>

// C++11 atomic support - fallback to volatile for older compilers
// Use DIOM_ prefix to avoid conflict with sync.h macros
#if __cplusplus >= 201103L
    #include <atomic>
    #define DIOM_ATOMIC_BOOL std::atomic<bool>
    #define DIOM_ATOMIC_INT std::atomic<int>
    #define DIOM_ATOMIC_UINT64 std::atomic<uint64_t>
    #define DIOM_ATOMIC_LOAD(x) (x).load()
    #define DIOM_ATOMIC_LOAD_PTR(x) (x)->load()
    #define DIOM_ATOMIC_CAS(x, expected, desired) (x).compare_exchange_strong(expected, desired)
#else
    #define DIOM_ATOMIC_BOOL volatile bool
    #define DIOM_ATOMIC_INT volatile int
    #define DIOM_ATOMIC_UINT64 volatile uint64_t
    #define DIOM_ATOMIC_LOAD(x) (x)
    #define DIOM_ATOMIC_LOAD_PTR(x) (*(x))
    #define DIOM_ATOMIC_CAS(x, expected, desired) __sync_bool_compare_and_swap(&(x), expected, desired)
#endif

// String helpers for pre-C++11 compatibility
inline char str_back(const std::string &s) { return s[s.length() - 1]; }
inline void str_pop_back(std::string &s) { if (!s.empty()) s.erase(s.length() - 1); }
inline char str_front(const std::string &s) { return s[0]; }


#define CALIBRATION_FILENAME ".disk_io_calibration.conf"


/**
 * Calibration profile loaded from file
 */
struct sCalibrationProfile {
    std::string uuid;
    std::string device;
    std::string filesystem;
    std::string spool_path;
    time_t calibration_time;

    // Latency metrics
    double baseline_latency_ms;       // Latency at minimal load
    double knee_latency_ms;           // Latency at knee point
    double saturation_latency_ms;     // Latency when saturated

    // Throughput metrics
    double knee_throughput_mbs;       // Throughput where latency starts increasing
    double max_throughput_mbs;        // Maximum measured throughput

    // IOPS metrics
    double baseline_iops;             // IOPS at minimal load (single writer)
    double knee_iops;                 // IOPS at knee point
    double max_iops;                  // Maximum measured IOPS

    bool valid;

    sCalibrationProfile() { clear(); }
    void clear() {
        uuid.clear();
        device.clear();
        filesystem.clear();
        spool_path.clear();
        calibration_time = 0;
        baseline_latency_ms = 0;
        knee_latency_ms = 0;
        saturation_latency_ms = 0;
        knee_throughput_mbs = 0;
        max_throughput_mbs = 0;
        baseline_iops = 0;
        knee_iops = 0;
        max_iops = 0;
        valid = false;
    }
};


/**
 * Raw disk statistics from /proc/diskstats
 */
struct sDiskStats {
    uint64_t reads_completed;
    uint64_t writes_completed;
    uint64_t read_time_ms;
    uint64_t write_time_ms;
    uint64_t io_in_progress;
    uint64_t io_time_ms;           // Time spent doing I/O (for utilization)
    uint64_t weighted_io_time_ms;  // Weighted I/O time (for queue depth)
    uint64_t sectors_read;
    uint64_t sectors_written;
    uint64_t timestamp_ms;

    sDiskStats() { clear(); }
    void clear() {
        reads_completed = writes_completed = 0;
        read_time_ms = write_time_ms = 0;
        io_in_progress = io_time_ms = weighted_io_time_ms = 0;
        sectors_read = sectors_written = timestamp_ms = 0;
    }
};


/**
 * Saturation state
 */
enum eSaturationState {
    STATE_OK,                    // Everything normal
    STATE_CALIBRATING,           // Background calibration in progress
    STATE_WARNING,               // Approaching capacity limits
    STATE_DISK_SATURATED         // Disk cannot keep up
};


/**
 * Computed I/O metrics
 */
struct sIOMetrics {
    // Throughput metrics
    double write_throughput_mbs;  // Current write throughput MB/s
    double read_throughput_mbs;   // Current read throughput MB/s
    double capacity_pct;          // Throughput as % of knee_throughput (0-100+)
    double reserve_pct;           // Headroom before knee (100 - capacity_pct, min 0)

    // IOPS metrics
    double write_iops;            // Current write IOPS
    double read_iops;             // Current read IOPS

    // Latency metrics (from /proc/diskstats)
    double write_latency_ms;      // Current write latency
    double latency_ratio;         // current / baseline
    double baseline_latency_ms;   // Calibrated baseline latency

    // Other disk metrics
    double queue_depth;           // Average I/O queue depth
    double utilization_pct;       // % of time disk was busy (0-100)

    // Buffer metrics (from sniffer)
    double buffer_level_pct;      // Current asyncwrite buffer fill %
    bool buffer_growing;          // Is buffer level increasing?

    // Status
    eSaturationState state;

    sIOMetrics() { clear(); }
    void clear() {
        write_throughput_mbs = read_throughput_mbs = 0;
        capacity_pct = reserve_pct = 0;
        write_iops = read_iops = 0;
        write_latency_ms = latency_ratio = baseline_latency_ms = 0;
        queue_depth = utilization_pct = 0;
        buffer_level_pct = 0;
        buffer_growing = false;
        state = STATE_CALIBRATING;
    }

    const char* getStateString() const {
        switch (state) {
            case STATE_DISK_SATURATED: return "DISK_SAT";
            case STATE_WARNING: return "WARN";
            case STATE_CALIBRATING: return "calibrating";
            default: return "";
        }
    }
};


/**
 * Disk I/O Monitor class
 */
class cDiskIOMonitor {
public:
    cDiskIOMonitor();
    ~cDiskIOMonitor();

    /**
     * Initialize monitoring for the given spool directory.
     * Loads calibration profile or starts background calibration.
     *
     * @param spool_path Path to spool directory
     * @param allow_calibration If false, skip calibration even if profile missing
     *        (use for read-from-file mode, sender mode, etc.)
     * @return true if successful
     */
    bool init(const char *spool_path, bool allow_calibration = true);

    /**
     * Update all metrics. Call periodically (~10 seconds).
     *
     * @param buffer_level_pct Current asyncwrite buffer level (0-100%)
     */
    void update(double buffer_level_pct);

    /**
     * Get current metrics.
     */
    sIOMetrics getMetrics() const { return metrics_; }

    /**
     * Format status string for syslog output.
     * Format: IO[85%|L1.2ms×1.1|U45] or IO[97%|L8.5ms×7.5|U100] DISK_SAT
     */
    std::string formatStatusString() const;

    /**
     * Check if monitoring is active (calibration complete).
     */
    bool isActive() const { return active_ && !calibrating_; }

    /**
     * Check if calibration is in progress.
     */
    bool isCalibrating() const { return calibrating_; }

    /**
     * Get calibration progress (0-100%).
     */
    int getCalibrationProgress() const { return calibration_progress_; }

    /**
     * Get detected device name.
     */
    std::string getDeviceName() const { return device_name_; }

    /**
     * Get calibration profile.
     */
    sCalibrationProfile getProfile() const { return profile_; }

    /**
     * Force recalibration.
     */
    void forceRecalibrate();

private:
    // Device detection
    std::string detectBlockDevice(const char *path);
    std::string getFilesystemUUID(const char *path);

    // Calibration profile I/O
    bool loadCalibrationProfile();
    bool saveCalibrationProfile();

    // Background calibration
    static void* calibrationThreadFunc(void *arg);
    void runCalibration();

    // Disk stats
    bool readDiskStats(sDiskStats &stats);
    void calculateMetrics();
    void detectSaturation();

    // Utilities
    static uint64_t getTimestampMs();
    static std::string execCommand(const char *cmd);

private:
    // Configuration
    std::string spool_path_;
    std::string device_name_;
    std::string filesystem_uuid_;

    // State
    bool active_;
    DIOM_ATOMIC_BOOL init_started_;  // Guard against concurrent init() calls
    DIOM_ATOMIC_BOOL calibrating_;
    DIOM_ATOMIC_INT calibration_progress_;

    // Calibration profile
    sCalibrationProfile profile_;

    // Calibration thread
    pthread_t calibration_thread_;
    bool calibration_thread_started_;

    // Disk stats for delta calculation
    sDiskStats prev_stats_;
    sDiskStats curr_stats_;
    bool first_sample_;

    // Buffer tracking
    double prev_buffer_level_;
    int buffer_growing_count_;  // Consecutive samples with growing buffer

    // Computed metrics
    sIOMetrics metrics_;

    // Thresholds for DISK_SAT detection
    static const double CAPACITY_WARNING_PCT;      // Show WARN at 80%
    static const double CAPACITY_CRITICAL_PCT;     // Show DISK_SAT at 95%
    static const double LATENCY_CRITICAL_RATIO;    // Latency 3× baseline
    static const double BUFFER_GROW_THRESHOLD;     // % buffer increase
    static const int BUFFER_GROW_SAMPLES = 3;      // Consecutive samples (int OK inline)
};


// Global instance
extern cDiskIOMonitor diskIOMonitor;


#endif // DISK_IO_MONITOR_H
