# Disk I/O Saturation Monitoring

VoIPmonitor includes automated disk I/O monitoring that detects when storage cannot keep up with spool directory writes. This helps identify disk bottlenecks before they cause call recording drops.

## Features

- **Automatic calibration**: Measures disk performance on first run
- **Capacity-based detection**: Shows percentage of sustainable throughput used
- **Background calibration**: Non-blocking startup
- **UUID tracking**: Auto-recalibrates when disk changes
- **RRD integration**: All metrics stored for graphing

## Syslog Output Format

The I/O metrics appear in the periodic status line after `[Mb/s]`:

```
[283.4/283.4Mb/s] IO[B1.1|L0.7|U45|C75|W125|R10|WI1.2k|RI0.5k] tarQ[0]
```

### Field Description

| Field | Description | Unit |
|-------|-------------|------|
| B | Baseline latency (calibrated) | ms |
| L | Current write latency | ms |
| U | Disk utilization | % |
| C | Capacity (current/knee throughput) | % |
| W | Write throughput | MB/s |
| R | Read throughput | MB/s |
| WI | Write IOPS | k = thousands |
| RI | Read IOPS | k = thousands |

### Status Indicators

- **No suffix**: Normal operation
- **WARN**: Approaching capacity limits (C >= 80%)
- **DISK_SAT**: Disk saturated, cannot keep up (C >= 95% or latency 3x baseline)

## Calibration

On first run, the sniffer performs automatic calibration:

1. Measures baseline latency with minimal I/O
2. Progressively increases write load
3. Identifies "knee point" where latency starts increasing
4. Stores profile in `.disk_io_calibration.conf` in spool directory

Calibration takes approximately 2-3 minutes and runs in background.

### Calibration Profile

Stored in `<spool_dir>/.disk_io_calibration.conf`:

```ini
[calibration]
uuid=abc123...
device=nvme0n1
filesystem=ext4
spool_path=/var/spool/voipmonitor
calibration_time=1706000000
baseline_latency_ms=0.5
knee_latency_ms=2.0
saturation_latency_ms=10.0
knee_throughput_mbs=800.0
max_throughput_mbs=1200.0
baseline_iops=50000
knee_iops=80000
max_iops=120000
```

### Recalibration

Calibration is automatically triggered when:
- No calibration profile exists
- Filesystem UUID changes (disk replaced)
- Manual recalibration requested via manager

## RRD Data Sources

Chart: `2db-diskio`

| Data Source | Description | Range |
|-------------|-------------|-------|
| io-latency | Write latency (ms) | 0-10000 |
| io-qdepth | I/O queue depth | 0-1000 |
| io-util | Disk utilization (%) | 0-100 |
| io-capacity | Capacity used (%) | 0-200 |
| io-write-throughput | Write throughput (MB/s) | 0-10000 |
| io-read-throughput | Read throughput (MB/s) | 0-10000 |
| io-write-iops | Write IOPS | 0-1000000 |
| io-read-iops | Read IOPS | 0-1000000 |
| io-reserve | Headroom before knee (%) | 0-100 |

## Implementation Details

### Source Files

- `disk_io_monitor.h` - Class definition and structures
- `disk_io_monitor.cpp` - Implementation

### Key Structures

```cpp
struct sCalibrationProfile {
    std::string uuid;           // Filesystem UUID
    std::string device;         // Block device (nvme0n1, sda, etc.)
    double baseline_latency_ms; // Latency at minimal load
    double knee_throughput_mbs; // Throughput where latency increases
    // ... more fields
};

struct sIOMetrics {
    double write_throughput_mbs;  // Current write MB/s
    double capacity_pct;          // % of knee throughput
    double write_latency_ms;      // Current latency
    double utilization_pct;       // % time disk busy
    eSaturationState state;       // OK, WARNING, DISK_SATURATED
    // ... more fields
};
```

### Detection Logic

Saturation is detected when ANY of these conditions is true:
- Capacity >= 95% (throughput at 95% of knee point)
- Latency >= 3x baseline
- Buffer level growing for 3+ consecutive samples

Warning is shown when:
- Capacity >= 80%

### Data Sources

Metrics are collected from:
- `/proc/diskstats` - utilization, latency, queue depth, throughput, IOPS
- Sniffer asyncwrite buffer level - buffer fill percentage

## Limitations

- Calibration requires write access to spool directory
- Not active in read-from-file mode or sender mode
- PSI (Pressure Stall Information) not currently used (future enhancement)

## Troubleshooting

### "calibrating" shown continuously

- Check write permissions to spool directory
- Verify disk is not already saturated during calibration
- Check `.disk_io_calibration.conf` for errors

### High capacity % but disk seems fine

- Recalibrate after system changes
- Delete `.disk_io_calibration.conf` to force recalibration

### Metrics show 0 values

- First sample after startup may show zeros
- Verify spool directory path is correct
