/**
 * disk_io_monitor.cpp - Disk I/O saturation monitoring implementation
 *
 * Includes built-in calibration (no external tools needed).
 */

#include "disk_io_monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <math.h>
#include <syslog.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>


// Global instance
cDiskIOMonitor diskIOMonitor;

// Static const definitions
const double cDiskIOMonitor::CAPACITY_WARNING_PCT = 80.0;
const double cDiskIOMonitor::CAPACITY_CRITICAL_PCT = 95.0;
const double cDiskIOMonitor::LATENCY_CRITICAL_RATIO = 3.0;
const double cDiskIOMonitor::BUFFER_GROW_THRESHOLD = 5.0;


// ============================================================================
// Calibration Constants
// ============================================================================

#define CALIBRATION_BLOCK_SIZE (1024 * 1024)    // 1 MB blocks
#define CALIBRATION_WARMUP_MB 2048              // 2 GB warmup
#define CALIBRATION_TEST_MB_PER_LEVEL 512       // 512 MB per level
#define CALIBRATION_MAX_WRITERS 32
#define CALIBRATION_KNEE_FACTOR 1.5             // Knee = latency 1.5x baseline
#define CALIBRATION_SATURATION_FACTOR 5.0       // Saturated = latency 5x baseline


// ============================================================================
// Utility Functions
// ============================================================================

uint64_t cDiskIOMonitor::getTimestampMs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
}

static uint64_t getTimestampUs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

std::string cDiskIOMonitor::execCommand(const char *cmd) {
    std::string result;
    FILE *pipe = popen(cmd, "r");
    if (pipe) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            result += buffer;
        }
        pclose(pipe);
    }
    while (!result.empty() && (str_back(result) == '\n' || str_back(result) == '\r' || str_back(result) == ' ')) {
        str_pop_back(result);
    }
    return result;
}


// ============================================================================
// Constructor / Destructor
// ============================================================================

cDiskIOMonitor::cDiskIOMonitor()
    : active_(false)
    , init_started_(false)
    , calibrating_(false)
    , calibration_progress_(0)
    , calibration_thread_started_(false)
    , first_sample_(true)
    , prev_buffer_level_(0)
    , buffer_growing_count_(0)
{
}

cDiskIOMonitor::~cDiskIOMonitor() {
    if (calibration_thread_started_) {
        pthread_join(calibration_thread_, NULL);
    }
}


// ============================================================================
// Device Detection
// ============================================================================

std::string cDiskIOMonitor::detectBlockDevice(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return "";
    }

    unsigned int maj = major(st.st_dev);
    unsigned int min = minor(st.st_dev);

    char sys_path[256];
    snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u", maj, min);

    char link_target[PATH_MAX];
    ssize_t len = readlink(sys_path, link_target, sizeof(link_target) - 1);
    if (len < 0) {
        return "";
    }
    link_target[len] = '\0';

    const char *last_slash = strrchr(link_target, '/');
    if (!last_slash) {
        return link_target;
    }

    std::string dev_name = last_slash + 1;

    // Strip partition number but keep md* and dm-* as-is
    if (dev_name.substr(0, 2) != "md" && dev_name.substr(0, 3) != "dm-") {
        // NVMe: nvme0n1p3 -> nvme0n1
        size_t p_pos = dev_name.rfind('p');
        if (p_pos != std::string::npos && p_pos > 0 &&
            dev_name.find("nvme") == 0 && isdigit(dev_name[p_pos + 1])) {
            dev_name = dev_name.substr(0, p_pos);
        }
        // SATA/SAS: sda1 -> sda
        else {
            while (!dev_name.empty() && isdigit(str_back(dev_name))) {
                str_pop_back(dev_name);
            }
        }
    }

    return dev_name;
}

std::string cDiskIOMonitor::getFilesystemUUID(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "findmnt -n -o UUID --target '%s' 2>/dev/null", path);
    std::string uuid = execCommand(cmd);

    if (!uuid.empty()) {
        return uuid;
    }

    std::string device = detectBlockDevice(path);
    if (!device.empty()) {
        snprintf(cmd, sizeof(cmd), "blkid -s UUID -o value /dev/%s 2>/dev/null", device.c_str());
        uuid = execCommand(cmd);
    }

    return uuid;
}


// ============================================================================
// Calibration Profile I/O
// ============================================================================

bool cDiskIOMonitor::loadCalibrationProfile() {
    std::string filepath = spool_path_ + "/" + CALIBRATION_FILENAME;

    std::ifstream f(filepath.c_str());
    if (!f.is_open()) {
        return false;
    }

    profile_.clear();
    std::string line;
    std::string section;

    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;

        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != std::string::npos) {
                section = line.substr(1, end - 1);
            }
            continue;
        }

        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        while (!key.empty() && isspace(str_back(key))) str_pop_back(key);
        while (!key.empty() && isspace(str_front(key))) key.erase(0, 1);
        while (!value.empty() && isspace(str_back(value))) str_pop_back(value);
        while (!value.empty() && isspace(str_front(value))) value.erase(0, 1);

        if (section == "identity") {
            if (key == "uuid") profile_.uuid = value;
            else if (key == "device") profile_.device = value;
            else if (key == "calibration_time") profile_.calibration_time = atol(value.c_str());
        }
        else if (section == "results") {
            if (key == "baseline_latency_ms") profile_.baseline_latency_ms = atof(value.c_str());
            else if (key == "knee_throughput_mbs") profile_.knee_throughput_mbs = atof(value.c_str());
            else if (key == "knee_latency_ms") profile_.knee_latency_ms = atof(value.c_str());
            else if (key == "max_throughput_mbs") profile_.max_throughput_mbs = atof(value.c_str());
            else if (key == "saturation_latency_ms") profile_.saturation_latency_ms = atof(value.c_str());
            else if (key == "baseline_iops") profile_.baseline_iops = atof(value.c_str());
            else if (key == "knee_iops") profile_.knee_iops = atof(value.c_str());
            else if (key == "max_iops") profile_.max_iops = atof(value.c_str());
        }
    }

    profile_.spool_path = spool_path_;
    profile_.valid = (profile_.baseline_latency_ms > 0 && profile_.knee_throughput_mbs > 0);

    return profile_.valid;
}

bool cDiskIOMonitor::saveCalibrationProfile() {
    std::string filepath = spool_path_ + "/" + CALIBRATION_FILENAME;

    std::ofstream f(filepath.c_str());
    if (!f.is_open()) {
        syslog(LOG_ERR, "disk_io_monitor: Failed to save calibration to %s", filepath.c_str());
        return false;
    }

    char time_str[64];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

    f << "# VoIPmonitor Disk I/O Calibration Profile\n";
    f << "# Generated: " << time_str << "\n";
    f << "# Spool path: " << profile_.spool_path << "\n";
    f << "# Device: /dev/" << profile_.device << "\n";
    f << "# UUID: " << (profile_.uuid.empty() ? "(unknown)" : profile_.uuid) << "\n";
    f << "\n";

    f << "[identity]\n";
    f << "uuid = " << profile_.uuid << "\n";
    f << "device = " << profile_.device << "\n";
    f << "calibration_time = " << profile_.calibration_time << "\n";
    f << "\n";

    f << "[results]\n";
    f << std::fixed << std::setprecision(2);
    f << "baseline_latency_ms = " << profile_.baseline_latency_ms << "\n";
    f << std::setprecision(1);
    f << "knee_throughput_mbs = " << profile_.knee_throughput_mbs << "\n";
    f << std::setprecision(2);
    f << "knee_latency_ms = " << profile_.knee_latency_ms << "\n";
    f << std::setprecision(1);
    f << "max_throughput_mbs = " << profile_.max_throughput_mbs << "\n";
    f << std::setprecision(2);
    f << "saturation_latency_ms = " << profile_.saturation_latency_ms << "\n";
    f << std::setprecision(0);
    f << "baseline_iops = " << profile_.baseline_iops << "\n";
    f << "knee_iops = " << profile_.knee_iops << "\n";
    f << "max_iops = " << profile_.max_iops << "\n";
    f << "\n";

    f << "[summary]\n";
    f << "# This disk can sustain approximately " << std::setprecision(0)
      << profile_.knee_throughput_mbs << " MB/s / " << profile_.knee_iops << " IOPS sequential writes\n";
    f << "# before latency increases significantly.\n";
    f << "# Baseline: " << std::setprecision(2) << profile_.baseline_latency_ms << " ms, "
      << std::setprecision(0) << profile_.baseline_iops << " IOPS\n";
    f << "# Saturation latency: " << std::setprecision(2) << profile_.saturation_latency_ms << " ms ("
      << std::setprecision(1) << (profile_.saturation_latency_ms / profile_.baseline_latency_ms)
      << "x baseline)\n";

    f.close();
    syslog(LOG_INFO, "disk_io_monitor: Calibration saved to %s", filepath.c_str());
    return true;
}


// ============================================================================
// Initialization
// ============================================================================

bool cDiskIOMonitor::init(const char *spool_path, bool allow_calibration) {
    // Prevent double initialization (thread-safe)
    // Atomic compare-and-swap: only proceed if init_started_ was false
    bool expected = false;
    if (!ATOMIC_CAS(init_started_, expected, true)) {
        return active_;  // Already initialized or initialization in progress
    }

    spool_path_ = spool_path;

    device_name_ = detectBlockDevice(spool_path);
    filesystem_uuid_ = getFilesystemUUID(spool_path);

    if (device_name_.empty()) {
        syslog(LOG_WARNING, "disk_io_monitor: Could not detect block device for %s", spool_path);
        init_started_ = false;  // Allow retry
        return false;
    }

    syslog(LOG_INFO, "disk_io_monitor: Detected device /dev/%s (UUID: %s) for %s",
           device_name_.c_str(),
           filesystem_uuid_.empty() ? "unknown" : filesystem_uuid_.c_str(),
           spool_path);

    if (loadCalibrationProfile()) {
        if (!filesystem_uuid_.empty() && !profile_.uuid.empty() &&
            filesystem_uuid_ != profile_.uuid) {
            syslog(LOG_WARNING, "disk_io_monitor: UUID changed (old: %s, new: %s) - need recalibration",
                   profile_.uuid.c_str(), filesystem_uuid_.c_str());
            profile_.clear();
        }
    }

    if (profile_.valid) {
        syslog(LOG_INFO, "disk_io_monitor: Loaded calibration - baseline: %.2fms, knee: %.0f MB/s, max: %.0f MB/s",
               profile_.baseline_latency_ms, profile_.knee_throughput_mbs, profile_.max_throughput_mbs);
        active_ = true;
        calibrating_ = false;
        // Initialize metrics with profile values so first output is not all zeros
        metrics_.baseline_latency_ms = profile_.baseline_latency_ms;
        metrics_.state = STATE_OK;
    } else if (allow_calibration) {
        syslog(LOG_INFO, "disk_io_monitor: No valid calibration found - starting background calibration");
        calibrating_ = true;
        calibration_progress_ = 0;
        active_ = true;

        if (pthread_create(&calibration_thread_, NULL, calibrationThreadFunc, this) == 0) {
            calibration_thread_started_ = true;
        } else {
            syslog(LOG_ERR, "disk_io_monitor: Failed to start calibration thread");
            calibrating_ = false;
        }
    } else {
        syslog(LOG_INFO, "disk_io_monitor: No calibration profile and calibration not allowed - monitoring disabled");
        active_ = false;
    }

    return true;
}


// ============================================================================
// Calibration Implementation (built-in)
// ============================================================================

// Writer thread data
struct sWriterThreadData {
    int thread_id;
    std::string test_dir;
    char *buffer;
    ATOMIC_BOOL *stop_flag;
    ATOMIC_UINT64 bytes_written;
    ATOMIC_UINT64 writes_completed;
    ATOMIC_UINT64 total_latency_us;
    ATOMIC_BOOL running;

    sWriterThreadData() : bytes_written(0), writes_completed(0), total_latency_us(0), running(false) {}
};

static void* calibrationWriterThread(void *arg) {
    sWriterThreadData *data = (sWriterThreadData*)arg;

    char filename[512];
    snprintf(filename, sizeof(filename), "%s/.calib_test_%d.tmp",
             data->test_dir.c_str(), data->thread_id);

    int flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef O_DIRECT
    flags |= O_DIRECT;
#endif

    int fd = open(filename, flags, 0644);
    if (fd < 0) {
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            return NULL;
        }
    }

    data->running = true;

    while (!ATOMIC_LOAD_PTR(data->stop_flag)) {
        uint64_t start = getTimestampUs();

        ssize_t written = write(fd, data->buffer, CALIBRATION_BLOCK_SIZE);
        if (written != CALIBRATION_BLOCK_SIZE) {
            if (errno == ENOSPC) {
                if (ftruncate(fd, 0) == 0) {
                    lseek(fd, 0, SEEK_SET);
                }
                continue;
            }
            break;
        }

        fdatasync(fd);

        uint64_t end = getTimestampUs();
        uint64_t latency = end - start;

        data->bytes_written += CALIBRATION_BLOCK_SIZE;
        data->writes_completed++;
        data->total_latency_us += latency;
    }

    data->running = false;
    close(fd);
    unlink(filename);

    return NULL;
}

struct sCalibrationPoint {
    int writers;
    double throughput_mbs;
    double latency_ms;
    double iops;
};

static sCalibrationPoint measureWithWriters(const std::string &spool_path, char *buffer, int num_writers, int total_mb);

void* cDiskIOMonitor::calibrationThreadFunc(void *arg) {
    cDiskIOMonitor *self = (cDiskIOMonitor*)arg;
    self->runCalibration();
    return NULL;
}

void cDiskIOMonitor::runCalibration() {
    syslog(LOG_INFO, "disk_io_monitor: Starting disk calibration for %s", spool_path_.c_str());

    // Allocate aligned buffer
    char *write_buffer = NULL;
    if (posix_memalign((void**)&write_buffer, 4096, CALIBRATION_BLOCK_SIZE) != 0) {
        write_buffer = (char*)malloc(CALIBRATION_BLOCK_SIZE);
    }
    if (!write_buffer) {
        syslog(LOG_ERR, "disk_io_monitor: Failed to allocate calibration buffer");
        calibrating_ = false;
        return;
    }
    // Fill with pattern
    for (int i = 0; i < CALIBRATION_BLOCK_SIZE; i++) {
        write_buffer[i] = (char)(i * 17 + 31);
    }

    std::vector<sCalibrationPoint> curve;
    double baseline_latency = 0;
    double baseline_iops = 0;
    double max_throughput = 0;
    double max_iops = 0;
    double knee_throughput = 0;
    double knee_latency = 0;
    double knee_iops = 0;
    double saturation_latency = 0;
    bool knee_found = false;

    // Phase 1: Warmup (bypass disk cache)
    syslog(LOG_INFO, "disk_io_monitor: Phase 1 - Cache warmup (%d MB)", CALIBRATION_WARMUP_MB);
    calibration_progress_ = 5;

    {
        char warmup_file[512];
        snprintf(warmup_file, sizeof(warmup_file), "%s/.calib_warmup.tmp", spool_path_.c_str());

        int flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef O_DIRECT
        flags |= O_DIRECT;
#endif
        int fd = open(warmup_file, flags, 0644);
        if (fd < 0) {
            fd = open(warmup_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        }

        if (fd >= 0) {
            int blocks = CALIBRATION_WARMUP_MB;
            for (int i = 0; i < blocks; i++) {
                if (write(fd, write_buffer, CALIBRATION_BLOCK_SIZE) != CALIBRATION_BLOCK_SIZE) {
                    if (errno == ENOSPC) {
                        if (ftruncate(fd, 0) == 0) {
                            lseek(fd, 0, SEEK_SET);
                        }
                        continue;
                    }
                    break;
                }
                fdatasync(fd);

                // Update progress (warmup is 5-30%)
                if ((i + 1) % 256 == 0) {
                    calibration_progress_ = 5 + (i * 25) / blocks;
                }
            }
            close(fd);
            unlink(warmup_file);
        }
    }

    calibration_progress_ = 30;
    syslog(LOG_INFO, "disk_io_monitor: Phase 2 - Measuring baseline (single writer)");

    // Phase 2: Baseline measurement
    {
        sCalibrationPoint point = measureWithWriters(spool_path_, write_buffer, 1, 256);
        baseline_latency = point.latency_ms;
        baseline_iops = point.iops;
        max_throughput = point.throughput_mbs;
        max_iops = point.iops;
        curve.push_back(point);

        syslog(LOG_INFO, "disk_io_monitor: Baseline: %.2f ms, %.1f MB/s, %.0f IOPS",
               baseline_latency, point.throughput_mbs, point.iops);
    }

    calibration_progress_ = 40;
    syslog(LOG_INFO, "disk_io_monitor: Phase 3 - Ramping up load");

    // Phase 3: Ramp up writers
    double prev_throughput = curve[0].throughput_mbs;
    double prev_iops = curve[0].iops;
    bool saturated = false;

    for (int writers = 2; writers <= CALIBRATION_MAX_WRITERS && !saturated; writers *= 2) {
        sCalibrationPoint point = measureWithWriters(spool_path_, write_buffer, writers, CALIBRATION_TEST_MB_PER_LEVEL);
        curve.push_back(point);

        double ratio = point.latency_ms / baseline_latency;

        // Track max throughput and IOPS
        if (point.throughput_mbs > max_throughput) {
            max_throughput = point.throughput_mbs;
        }
        if (point.iops > max_iops) {
            max_iops = point.iops;
        }

        // Detect knee
        if (!knee_found && ratio >= CALIBRATION_KNEE_FACTOR) {
            knee_found = true;
            knee_throughput = prev_throughput;
            knee_latency = point.latency_ms;
            knee_iops = prev_iops;
            syslog(LOG_INFO, "disk_io_monitor: Knee found at %.1f MB/s, %.0f IOPS (latency %.1fx baseline)",
                   knee_throughput, knee_iops, ratio);
        }

        // Detect saturation
        if (ratio >= CALIBRATION_SATURATION_FACTOR) {
            saturated = true;
            saturation_latency = point.latency_ms;
            syslog(LOG_INFO, "disk_io_monitor: Saturation at %.1f MB/s (latency %.1fx baseline)",
                   point.throughput_mbs, ratio);
        }

        syslog(LOG_DEBUG, "disk_io_monitor: %d writers: %.1f MB/s, %.0f IOPS, %.2f ms (%.1fx)",
               writers, point.throughput_mbs, point.iops, point.latency_ms, ratio);

        prev_throughput = point.throughput_mbs;
        prev_iops = point.iops;
        calibration_progress_ = 40 + (writers * 50) / CALIBRATION_MAX_WRITERS;
    }

    free(write_buffer);

    // Set defaults if not found
    if (!knee_found || knee_throughput == 0) {
        knee_throughput = max_throughput * 0.8;
        knee_latency = baseline_latency * 1.5;
        knee_iops = max_iops * 0.8;
    }
    if (saturation_latency == 0) {
        saturation_latency = baseline_latency * CALIBRATION_SATURATION_FACTOR;
    }

    // Save profile
    profile_.device = device_name_;
    profile_.uuid = filesystem_uuid_;
    profile_.spool_path = spool_path_;
    profile_.calibration_time = time(NULL);
    profile_.baseline_latency_ms = baseline_latency;
    profile_.knee_throughput_mbs = knee_throughput;
    profile_.knee_latency_ms = knee_latency;
    profile_.max_throughput_mbs = max_throughput;
    profile_.saturation_latency_ms = saturation_latency;
    profile_.baseline_iops = baseline_iops;
    profile_.knee_iops = knee_iops;
    profile_.max_iops = max_iops;
    profile_.valid = true;

    saveCalibrationProfile();

    calibration_progress_ = 100;
    syslog(LOG_INFO, "disk_io_monitor: Calibration complete - baseline: %.2fms/%.0f IOPS, knee: %.0f MB/s/%.0f IOPS, max: %.0f MB/s/%.0f IOPS",
           baseline_latency, baseline_iops, knee_throughput, knee_iops, max_throughput, max_iops);

    calibrating_ = false;
}

static sCalibrationPoint measureWithWriters(const std::string &spool_path, char *buffer, int num_writers, int total_mb) {
    sCalibrationPoint result;
    result.writers = num_writers;

    std::vector<pthread_t> threads(num_writers);
    std::vector<sWriterThreadData*> thread_data(num_writers);
    ATOMIC_BOOL stop_flag(false);

    // Allocate per-thread buffers
    std::vector<char*> buffers(num_writers);
    for (int i = 0; i < num_writers; i++) {
        if (posix_memalign((void**)&buffers[i], 4096, CALIBRATION_BLOCK_SIZE) != 0) {
            buffers[i] = (char*)malloc(CALIBRATION_BLOCK_SIZE);
        }
        memcpy(buffers[i], buffer, CALIBRATION_BLOCK_SIZE);

        thread_data[i] = new sWriterThreadData();
        thread_data[i]->thread_id = i;
        thread_data[i]->test_dir = spool_path;
        thread_data[i]->buffer = buffers[i];
        thread_data[i]->stop_flag = &stop_flag;
    }

    // Start threads
    for (int i = 0; i < num_writers; i++) {
        pthread_create(&threads[i], NULL, calibrationWriterThread, thread_data[i]);
    }

    // Wait for all to start
    bool all_running = false;
    int wait_count = 0;
    while (!all_running && wait_count < 100) {
        all_running = true;
        for (int i = 0; i < num_writers; i++) {
            if (!thread_data[i]->running) {
                all_running = false;
                break;
            }
        }
        if (!all_running) {
            usleep(10000);
            wait_count++;
        }
    }

    // Run until enough data written
    uint64_t target_bytes = (uint64_t)total_mb * 1024 * 1024;
    uint64_t start_time = getTimestampUs();

    while (true) {
        usleep(100000);  // 100ms

        uint64_t total_written = 0;
        for (int i = 0; i < num_writers; i++) {
            total_written += ATOMIC_LOAD(thread_data[i]->bytes_written);
        }

        if (total_written >= target_bytes) {
            break;
        }

        // Safety timeout (60 seconds)
        if (getTimestampUs() - start_time > 60000000ULL) {
            break;
        }
    }

    // Stop threads
    stop_flag = true;
    for (int i = 0; i < num_writers; i++) {
        pthread_join(threads[i], NULL);
    }

    // Calculate results
    uint64_t total_written = 0;
    uint64_t total_writes = 0;
    uint64_t total_latency = 0;

    for (int i = 0; i < num_writers; i++) {
        total_written += ATOMIC_LOAD(thread_data[i]->bytes_written);
        total_writes += ATOMIC_LOAD(thread_data[i]->writes_completed);
        total_latency += ATOMIC_LOAD(thread_data[i]->total_latency_us);

        free(buffers[i]);
        delete thread_data[i];
    }

    uint64_t elapsed_us = getTimestampUs() - start_time;

    result.throughput_mbs = (double)total_written / elapsed_us;  // bytes/us = MB/s
    result.latency_ms = (total_writes > 0) ? (double)total_latency / total_writes / 1000.0 : 0;
    result.iops = (double)total_writes * 1000000.0 / elapsed_us;  // writes per second

    return result;
}

void cDiskIOMonitor::forceRecalibrate() {
    if (calibrating_) {
        return;
    }

    if (calibration_thread_started_) {
        pthread_join(calibration_thread_, NULL);
        calibration_thread_started_ = false;
    }

    profile_.clear();
    calibrating_ = true;
    calibration_progress_ = 0;

    if (pthread_create(&calibration_thread_, NULL, calibrationThreadFunc, this) == 0) {
        calibration_thread_started_ = true;
    }
}


// ============================================================================
// Disk Statistics Reading
// ============================================================================

bool cDiskIOMonitor::readDiskStats(sDiskStats &stats) {
    stats.clear();

    std::ifstream f("/proc/diskstats");
    if (!f.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(f, line)) {
        unsigned int major_num, minor_num;
        char name[64];
        uint64_t reads, rd_merge, rd_sect, rd_time;
        uint64_t writes, wr_merge, wr_sect, wr_time;
        uint64_t io_curr, io_time, io_time_weighted;

        int parsed = sscanf(line.c_str(),
            "%u %u %63s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
            &major_num, &minor_num, name,
            &reads, &rd_merge, &rd_sect, &rd_time,
            &writes, &wr_merge, &wr_sect, &wr_time,
            &io_curr, &io_time, &io_time_weighted);

        if (parsed >= 14 && device_name_ == name) {
            stats.reads_completed = reads;
            stats.writes_completed = writes;
            stats.read_time_ms = rd_time;
            stats.write_time_ms = wr_time;
            stats.io_in_progress = io_curr;
            stats.io_time_ms = io_time;
            stats.weighted_io_time_ms = io_time_weighted;
            stats.sectors_read = rd_sect;
            stats.sectors_written = wr_sect;
            stats.timestamp_ms = getTimestampMs();
            return true;
        }
    }

    return false;
}


// ============================================================================
// Metrics Calculation
// ============================================================================

void cDiskIOMonitor::calculateMetrics() {
    if (first_sample_) {
        return;
    }

    uint64_t time_delta_ms = curr_stats_.timestamp_ms - prev_stats_.timestamp_ms;
    if (time_delta_ms == 0) {
        return;
    }

    double time_delta_sec = time_delta_ms / 1000.0;

    // Write throughput
    uint64_t sectors_written_delta = curr_stats_.sectors_written - prev_stats_.sectors_written;
    double bytes_written = sectors_written_delta * 512.0;
    metrics_.write_throughput_mbs = (bytes_written / 1024.0 / 1024.0) / time_delta_sec;

    // Read throughput
    uint64_t sectors_read_delta = curr_stats_.sectors_read - prev_stats_.sectors_read;
    double bytes_read = sectors_read_delta * 512.0;
    metrics_.read_throughput_mbs = (bytes_read / 1024.0 / 1024.0) / time_delta_sec;

    // IOPS
    uint64_t writes_delta = curr_stats_.writes_completed - prev_stats_.writes_completed;
    uint64_t reads_delta = curr_stats_.reads_completed - prev_stats_.reads_completed;
    metrics_.write_iops = (double)writes_delta / time_delta_sec;
    metrics_.read_iops = (double)reads_delta / time_delta_sec;

    // Capacity % and Reserve %
    if (profile_.valid && profile_.knee_throughput_mbs > 0) {
        metrics_.capacity_pct = (metrics_.write_throughput_mbs / profile_.knee_throughput_mbs) * 100.0;
        metrics_.reserve_pct = std::max(0.0, 100.0 - metrics_.capacity_pct);
    } else {
        metrics_.capacity_pct = 0;
        metrics_.reserve_pct = 100;
    }

    // Latency
    uint64_t write_time_delta = curr_stats_.write_time_ms - prev_stats_.write_time_ms;

    if (writes_delta > 0) {
        metrics_.write_latency_ms = (double)write_time_delta / writes_delta;
    } else {
        metrics_.write_latency_ms = 0;
    }

    // Latency ratio
    metrics_.baseline_latency_ms = profile_.valid ? profile_.baseline_latency_ms : 1.0;
    if (metrics_.baseline_latency_ms > 0 && metrics_.write_latency_ms > 0) {
        metrics_.latency_ratio = metrics_.write_latency_ms / metrics_.baseline_latency_ms;
    } else {
        metrics_.latency_ratio = 1.0;
    }

    // Queue depth
    uint64_t weighted_delta = curr_stats_.weighted_io_time_ms - prev_stats_.weighted_io_time_ms;
    metrics_.queue_depth = (double)weighted_delta / time_delta_ms;

    // Utilization
    uint64_t io_time_delta = curr_stats_.io_time_ms - prev_stats_.io_time_ms;
    metrics_.utilization_pct = std::min(100.0, (double)io_time_delta * 100.0 / time_delta_ms);
}


// ============================================================================
// Saturation Detection
// ============================================================================

void cDiskIOMonitor::detectSaturation() {
    if (!profile_.valid) {
        metrics_.state = STATE_CALIBRATING;
        return;
    }

    // Track buffer growth
    if (metrics_.buffer_level_pct > prev_buffer_level_ + BUFFER_GROW_THRESHOLD ||
        metrics_.buffer_level_pct > 30.0) {
        buffer_growing_count_++;
    } else {
        buffer_growing_count_ = 0;
    }
    metrics_.buffer_growing = (buffer_growing_count_ >= BUFFER_GROW_SAMPLES);

    bool capacity_critical = (metrics_.capacity_pct >= CAPACITY_CRITICAL_PCT);
    bool capacity_warning = (metrics_.capacity_pct >= CAPACITY_WARNING_PCT);
    bool latency_critical = (metrics_.latency_ratio >= LATENCY_CRITICAL_RATIO);

    // DISK_SAT: buffer growing AND (high capacity OR high latency)
    if (metrics_.buffer_growing && (capacity_critical || latency_critical)) {
        metrics_.state = STATE_DISK_SATURATED;
    }
    // WARNING: approaching limits
    else if (capacity_warning || (metrics_.buffer_growing && metrics_.latency_ratio > 1.5)) {
        metrics_.state = STATE_WARNING;
    }
    // OK
    else {
        metrics_.state = STATE_OK;
    }
}


// ============================================================================
// Update
// ============================================================================

void cDiskIOMonitor::update(double buffer_level_pct) {
    if (!active_) {
        return;
    }

    metrics_.buffer_level_pct = buffer_level_pct;

    prev_stats_ = curr_stats_;
    if (!readDiskStats(curr_stats_)) {
        return;
    }

    if (first_sample_) {
        first_sample_ = false;
        prev_buffer_level_ = buffer_level_pct;
        return;
    }

    calculateMetrics();
    detectSaturation();
    prev_buffer_level_ = buffer_level_pct;
}


// ============================================================================
// Status String Formatting
// ============================================================================

std::string cDiskIOMonitor::formatStatusString() const {
    char buf[256];

    if (calibrating_) {
        snprintf(buf, sizeof(buf), "IO[calibrating %d%%]", (int)ATOMIC_LOAD(calibration_progress_));
        return buf;
    }

    if (!profile_.valid) {
        return "IO[no calib]";
    }

    // Format: IO[B0.5|L1.2|Q3.2|U45|C75|W125|R10|WI1.2k|RI500]
    // B = baseline latency (calibrated, ms)
    // L = current latency (ms)
    // Q = queue depth
    // U = utilization %
    // C = capacity % (current throughput / knee throughput)
    // W = write MB/s
    // R = read MB/s
    // WI = write IOPS
    // RI = read IOPS

    // Baseline latency
    char baseline_str[16];
    if (metrics_.baseline_latency_ms < 0.1) {
        snprintf(baseline_str, sizeof(baseline_str), "%.2f", metrics_.baseline_latency_ms);
    } else if (metrics_.baseline_latency_ms < 10.0) {
        snprintf(baseline_str, sizeof(baseline_str), "%.1f", metrics_.baseline_latency_ms);
    } else {
        snprintf(baseline_str, sizeof(baseline_str), "%.0f", metrics_.baseline_latency_ms);
    }

    // Current latency
    char latency_str[16];
    if (metrics_.write_latency_ms < 0.1) {
        snprintf(latency_str, sizeof(latency_str), "%.2f", metrics_.write_latency_ms);
    } else if (metrics_.write_latency_ms < 10.0) {
        snprintf(latency_str, sizeof(latency_str), "%.1f", metrics_.write_latency_ms);
    } else {
        snprintf(latency_str, sizeof(latency_str), "%.0f", metrics_.write_latency_ms);
    }

    // Write IOPS formatting (always use k)
    char wiops_str[16];
    snprintf(wiops_str, sizeof(wiops_str), "%.1fk", metrics_.write_iops / 1000.0);

    // Read IOPS formatting (always use k)
    char riops_str[16];
    snprintf(riops_str, sizeof(riops_str), "%.1fk", metrics_.read_iops / 1000.0);

    // Queue depth formatting
    char qdepth_str[16];
    if (metrics_.queue_depth < 10.0) {
        snprintf(qdepth_str, sizeof(qdepth_str), "%.1f", metrics_.queue_depth);
    } else {
        snprintf(qdepth_str, sizeof(qdepth_str), "%.0f", metrics_.queue_depth);
    }

    // Format output
    snprintf(buf, sizeof(buf), "IO[B%s|L%s|Q%s|U%.0f|C%.0f|W%.0f|R%.0f|WI%s|RI%s]",
             baseline_str,
             latency_str,
             qdepth_str,
             metrics_.utilization_pct,
             metrics_.capacity_pct,
             metrics_.write_throughput_mbs,
             metrics_.read_throughput_mbs,
             wiops_str,
             riops_str);

    std::string result = buf;
    const char *state_str = metrics_.getStateString();
    if (state_str && state_str[0]) {
        result += " ";
        result += state_str;
    }

    return result;
}
