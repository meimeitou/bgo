# biosnoop - Block I/O Monitoring Tool

## Overview

`biosnoop` is an eBPF-based tool that traces block device I/O activity in real-time. It monitors disk I/O operations by tracing kernel tracepoints and provides detailed information about I/O patterns, latency, and process activities.

## Implementation

This tool implements the `biosnoop` functionality by:

1. **Tracing kernel tracepoints**: Uses stable kernel tracepoints instead of kprobes for better compatibility across kernel versions:
   - `block:block_rq_issue` - when I/O request is issued 
   - `block:block_rq_complete` - when I/O request completes

2. **Tracking I/O lifecycle**: Correlates I/O start and completion events to calculate:
   - **Latency**: Time from I/O issue to completion
   - **Queue time**: Time from process issuing I/O to actual device processing (optional)
   - **Process information**: PID and command name of process issuing I/O

3. **Real-time reporting**: Outputs I/O events as they happen with detailed metrics

## Features

- **Process tracking**: Shows which process (PID, command) initiated each I/O
- **I/O characteristics**: Read/Write operation, sector, size
- **Performance metrics**: I/O latency and optional queue time
- **Device information**: Block device identification
- **Real-time monitoring**: Live stream of I/O events
- **Cross-kernel compatibility**: Uses stable tracepoints

## Usage

```bash
# Basic usage - trace all block I/O
sudo bgo biosnoop

# Include OS queue time in addition to device service time  
sudo bgo biosnoop --queue

# Trace for specific duration
timeout 10 sudo bgo biosnoop
```

## Output Format

```
TIME(s)     COMM           PID     DISK      T SECTOR     BYTES   LAT(ms)
0.000000    jbd2/sda1-8    330     8,0       W 2187768    65536      0.53
0.000544    kworker/3:1H   206     8,0       W 2187896    4096       0.38
```

**Column descriptions:**
- **TIME(s)**: Timestamp relative to first event (seconds)
- **COMM**: Process/command name that issued the I/O
- **PID**: Process ID
- **DISK**: Block device (major,minor)
- **T**: Operation type (R=read, W=write)
- **SECTOR**: Starting sector number
- **BYTES**: I/O size in bytes
- **LAT(ms)**: I/O latency in milliseconds
- **QUE(ms)**: Queue time in milliseconds (when --queue option used)

## Technical Implementation

### BPF Program (`biosnoop.c`)

The eBPF program consists of:

1. **Data structures**:
   - `hash_key`: Uniquely identifies I/O requests (device, sector, operation type)
   - `start_req_t`: Tracks I/O start time and data length
   - `val_t`: Stores process information and queue timestamp
   - `data_t`: Event data sent to userspace

2. **BPF Maps**:
   - `start`: Hash map tracking I/O start times
   - `infobyreq`: Hash map storing process information
   - `events`: Perf event array for sending data to userspace

3. **Tracepoint handlers**:
   - `trace_block_rq_issue`: Captures I/O issue events
   - `trace_block_rq_complete`: Captures I/O completion events

### Go Implementation (`biosnoop.go`)

The userspace program:

1. **BPF Management**: Loads and attaches eBPF programs to tracepoints
2. **Event Processing**: Reads events from perf buffer and parses binary data  
3. **Output Formatting**: Formats and displays I/O events in human-readable format
4. **Device Translation**: Converts device IDs to device names using `/proc/diskstats`

### Command Integration (`cmd/biosnoop.go`)

Cobra command implementation providing:
- Command-line interface with `--queue` flag
- Help documentation and usage examples
- Integration with the main `bgo` command

## Use Cases

1. **Performance Analysis**: Identify I/O bottlenecks and latency issues
2. **Process Monitoring**: Find which processes are generating disk activity
3. **Storage Debugging**: Analyze I/O patterns and identify problematic operations
4. **Capacity Planning**: Understand I/O workload characteristics
5. **System Troubleshooting**: Debug storage-related performance problems

## Comparison with BCC biosnoop.py

This implementation provides similar functionality to the BCC `biosnoop.py` tool but with several advantages:

- **Single binary**: No Python dependencies or runtime interpretation
- **Better performance**: Compiled Go userspace with efficient eBPF handling
- **Integrated toolchain**: Part of the unified `bgo` command suite
- **Stable tracepoints**: Uses kernel tracepoints instead of kprobes for better compatibility

## Requirements

- Linux kernel with eBPF support
- CAP_SYS_ADMIN or root privileges
- Block device tracepoints enabled in kernel

## Limitations

- Queue time calculation may show overflow values in some kernel versions
- Requires root privileges due to eBPF program loading
- Only traces block layer I/O (not filesystem-only operations)
