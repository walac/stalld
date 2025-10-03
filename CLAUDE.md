# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`stalld` is a starvation detection and avoidance daemon for Linux
systems. It monitors CPU run queues for threads that are starving
(ready to run but not getting CPU time), and temporarily boosts their
priority using SCHED_DEADLINE (or SCHED_FIFO as fallback) to allow
them to make progress. This prevents indefinite starvation when
high-priority RT tasks monopolize CPUs, at the cost of small latencies
for the application monopolizing the CPU. 

**Primary use case**: DPDK deployments with isolated CPUs running single busy-loop RT tasks, where kernel threads can starve.

**Not recommended for**: Safety-critical systems (see README.md).

## Repository Structure

```
stalld/
├── src/               # Main source code (5 C files)
│   ├── stalld.c      # Main daemon logic (1,218 LOC), entry point, boosting
│   ├── sched_debug.c # Procfs backend for parsing /proc|sys/.../sched/debug
│   ├── queue_track.c # eBPF backend for BPF-based task tracking
│   ├── utils.c       # Utilities: logging, CPU parsing, argument parsing
│   ├── throttling.c  # RT throttling detection and control
│   └── *.h           # Headers (stalld.h, sched_debug.h, queue_track.h)
├── bpf/              # eBPF code
│   └── stalld.bpf.c  # BPF tracepoint programs for task tracking
├── tests/            # Comprehensive test suite
│   ├── run_tests.sh              # Main test runner (auto-discovery, color output)
│   ├── test01.c                  # Original starvation test (fixed)
│   ├── helpers/
│   │   ├── test_helpers.sh       # Helper library (20+ functions)
│   │   └── starvation_gen.c      # Configurable starvation generator
│   ├── functional/               # Functional tests (shell scripts)
│   │   ├── test_foreground.sh
│   │   ├── test_log_only.sh
│   │   └── test_logging_destinations.sh
│   ├── unit/                     # Unit tests (C programs)
│   ├── integration/              # Integration tests (shell scripts)
│   ├── fixtures/                 # Test data and configurations
│   ├── results/                  # Test output logs (gitignored)
│   └── README.md                 # Test documentation
├── systemd/          # systemd integration (service file, config)
├── man/              # Man page (stalld.8)
├── scripts/          # Helper scripts (throttlectl.sh)
└── Makefile          # Build system with arch/kernel detection
```

## Source File Guide

### Core Implementation Files

**src/stalld.c** (1,218 LOC) - Main daemon
- Entry point: `main()` at line 1121
- Boosting logic: `boost_with_deadline()`, `boost_with_fifo()` (lines 438-563)
- Threading modes: `single_threaded_main()`, `conservative_main()`, `aggressive_main()`
- Task merging: `merge_taks_info()` preserves starvation timestamps (lines 370-397)

**src/utils.c** - Utilities
- Command-line parsing: `parse_args()`
- CPU list parsing and affinity setting
- Logging infrastructure (syslog, kmsg, verbose)
- sched_debug path detection: `find_sched_debug_path()`
- Buffer resizing and memory allocation

**src/sched_debug.c** - Procfs backend
- Parses `/sys/kernel/debug/sched/debug` or `/proc/sched_debug`
- Auto-detects kernel format (3.x, 4.18+, 6.12+)
- Implements `sched_debug_backend` interface defined in stalld.h
- Fallback when eBPF unavailable (i686, powerpc, ppc64le, legacy kernels)

**src/queue_track.c** - eBPF backend
- Loads and manages BPF programs via skeleton (`stalld.skel.h`)
- Implements `queue_track_backend` interface defined in stalld.h
- Reads task data from BPF maps populated by kernel-side programs
- Default on x86_64, aarch64, s390x with modern kernels

**src/throttling.c** - RT throttling management
- Checks if RT throttling is disabled (`sched_rt_runtime_us == -1`)
- Disables throttling when needed
- Dies if throttling is enabled (unless running under systemd)

### eBPF Components

**bpf/stalld.bpf.c** - Kernel-side BPF programs
- Tracepoints: `sched_wakeup`, `sched_switch`, `sched_migrate_task`, `sched_process_exit`
- Maintains per-CPU task queues in BPF maps
- Tracks task state changes in real-time without polling
- Generated files: `bpf/vmlinux.h` (kernel BTF), `src/stalld.skel.h` (userspace skeleton)

## Program Flow

### Startup Sequence (src/stalld.c:main)

1. Parse command-line arguments (`parse_args()`)
2. Set CPU affinity if configured (`-a` option)
3. Check for DL-server presence (newer kernels have built-in starvation handling)
4. **Verify RT throttling is disabled** (die if enabled, unless systemd manages it)
5. **Detect boost method**: Try SCHED_DEADLINE first, fall back to SCHED_FIFO if unavailable
6. Initialize backend: `queue_track_backend` (eBPF) or `sched_debug_backend` (procfs)
7. Allocate per-CPU info structures
8. Setup signal handling
9. Daemonize (unless `-f/--foreground`)
10. Enter main monitoring loop (single/adaptive/aggressive mode)

### Monitoring Loop (per-CPU or global depending on mode)

1. **Idle detection** (if enabled): Check `/proc/stat` for idle CPUs, skip if idle
2. **Get task info**: Call backend's `get()` or `get_cpu()` to read task data
3. **Parse tasks**: Call backend's `parse()` to populate `cpu_info` structures
4. **Merge tasks**: Preserve starvation timestamps for tasks making no progress (same context switch count)
5. **Check for starvation**: Identify tasks on runqueue for ≥`starving_threshold` with no context switches
6. **Apply denylist**: Skip tasks matching ignore patterns (`-i` option)
7. **Boost starving tasks**: Apply SCHED_DEADLINE (or FIFO) for `boost_duration` seconds
8. **Restore policy**: Return task to original scheduling policy
9. **Sleep**: Wait `granularity` seconds before next check cycle

### Threading Modes

- **Single-threaded** (default): One thread calls `boost_cpu_starving_vector()` to boost all CPUs at once
- **Adaptive**: Spawns per-CPU threads when tasks approach ½ starvation threshold, threads exit after 10 idle cycles
- **Aggressive** (`-A`): Per-CPU threads from startup, never exit, continuous monitoring

## Command Line Interface

### Key Options (see man/stalld.8 for complete list)

**Monitoring:**
- `-c/--cpu <list>`: CPUs to monitor (default: all)
- `-t/--starving_threshold <sec>`: Starvation threshold in seconds (default: 60s)

**Boosting:**
- `-p/--boost_period <ns>`: SCHED_DEADLINE period (default: 1,000,000,000 ns = 1s)
- `-r/--boost_runtime <ns>`: SCHED_DEADLINE runtime (default: 20,000 ns = 20μs)
- `-d/--boost_duration <sec>`: Boost duration (default: 3s)
- `-F/--force_fifo`: Force SCHED_FIFO instead of SCHED_DEADLINE

**Threading:**
- `-A/--aggressive_mode`: Spawn per-CPU threads immediately (vs. adaptive)

**Filtering:**
- `-i <regex>`: Ignore thread names matching regex (comma-separated)
- `-I <regex>`: Ignore process names matching regex

**Logging:**
- `-v/--verbose`: Print to stdout
- `-k/--log_kmsg`: Log to kernel buffer (dmesg)
- `-s/--log_syslog`: Log to syslog (default: true)
- `-l/--log_only`: Only log, don't boost (testing mode)

**Daemon:**
- `-f/--foreground`: Run in foreground (don't daemonize)
- `-P/--pidfile <path>`: Write PID file
- `-a/--affinity <cpu-list>`: Set stalld affinity to specific CPUs

Entry point: `main()` in `src/stalld.c:1121`
Argument parsing: `parse_args()` in `src/utils.c`

## Build Commands

### Standard Build
```bash
make                  # Build stalld and tests
make stalld           # Build only stalld executable
make static           # Build statically linked stalld-static
make tests            # Build tests only
```

### Architecture-Specific Notes
- The build system auto-detects architecture and kernel version
- eBPF support: Disabled on i686, powerpc, ppc64le, and kernels ≤3.x
- On legacy kernels (≤3.x), build uses `LEGACY=1` and disables BPF

### Clean and Install
```bash
make clean            # Clean all build artifacts
make install          # Install to system directories
make uninstall        # Remove installed files
```

### Development
```bash
make DEBUG=1          # Build with debug symbols (-g3)
make annocheck        # Run security analysis on stalld executable
```

## Testing

### Automated Test Suite

The `tests/` directory contains a comprehensive test suite with automated test runner, helper library, and multiple test categories.

```bash
# Run all tests
make test
cd tests && ./run_tests.sh

# Run specific test categories
make test-unit           # Unit tests only
make test-functional     # Functional tests only
make test-integration    # Integration tests only

# Run individual tests
cd tests && ./run_tests.sh --functional-only
cd tests && functional/test_foreground.sh
```

**Test Infrastructure:**
- **run_tests.sh** (328 lines): Main test orchestrator with auto-discovery, color-coded output, statistics
- **helpers/test_helpers.sh** (331 lines): Reusable helper library with 20+ functions for assertions, stalld management, system checks
- **helpers/starvation_gen.c** (267 lines): Configurable starvation generator for controlled testing
- **Test organization**: `unit/`, `functional/`, `integration/`, `fixtures/`, `results/`

**Current Test Coverage:**

✅ **Phase 1 Complete** (Foundation):
- `test01.c` - Fixed original starvation test (7 critical fixes: error handling, buffer safety, memory cleanup)
- `test_foreground.sh` - Tests `-f` flag prevents daemonization
- `test_log_only.sh` - Tests `-l` flag logs but doesn't boost
- `test_logging_destinations.sh` - Tests `-v`, `-k`, `-s` logging options

🔄 **Phase 2 Planned** (Command-Line Options):
- Monitoring options: `-c` (CPU selection), `-t` (starvation threshold)
- Boosting options: `-p` (period), `-r` (runtime), `-d` (duration), `-F` (force FIFO)
- Daemon options: `-P` (pidfile), `-a` (affinity)

🔄 **Phase 3 Planned** (Core Logic):
- Starvation detection verification
- SCHED_DEADLINE boosting verification
- SCHED_FIFO boosting verification
- Task merging logic
- Idle detection

🔄 **Phase 4 Planned** (Advanced):
- Threading modes (adaptive vs aggressive)
- Filtering (`-i`, `-I` options)
- Backend comparison (eBPF vs procfs)
- Integration and stress tests

**Test Requirements:**
- Root privileges for most tests
- RT throttling disabled: `echo -1 > /proc/sys/kernel/sched_rt_runtime_us`
- stalld built: `make` in project root

**Helper Functions Available:**
```bash
# Assertions
assert_equals expected actual "message"
assert_contains haystack needle "message"
assert_file_exists "/path/to/file"
assert_process_running $PID

# stalld Management
start_stalld [args...]      # Start stalld, track PID
stop_stalld                 # Stop stalld gracefully

# System Helpers
require_root                # Skip test if not root
check_rt_throttling         # Check RT throttling status
pick_test_cpu               # Pick CPU for testing
wait_for_log_message "pattern" timeout

# Starvation Generator
../helpers/starvation_gen -c CPU -p priority -n num_threads -d duration -v
```

See `tests/README.md` for complete test documentation, writing tests, and troubleshooting.

### Manual Testing Workflow

1. Run stalld in foreground with verbose mode:
   ```bash
   sudo ./stalld -f -v -t 5  # 5 second threshold for faster testing
   ```

2. In another terminal, create a CPU-intensive RT task to monopolize a CPU

3. Create a normal task on the same CPU that will starve

4. Observe stalld detecting and boosting the starving task

## Development Workflow

### Debugging

```bash
make DEBUG=1          # Build with -g3 debug symbols
make clean && make    # Full rebuild after changing build options
```

**Runtime debugging options:**
- Use `-v` (verbose) to see detailed logging to stdout
- Use `-l` (log-only) to test starvation detection without actually boosting tasks
- Use `-k` to log to kernel buffer (view with `dmesg`)
- Check `/var/log/messages` or `journalctl -u stalld` for syslog output
- Use `-f` to run in foreground (don't daemonize)

### Code Navigation Tips

**Starting points for common tasks:**
- Adding new command-line option: `parse_args()` in `src/utils.c`
- Modifying boost behavior: `boost_with_deadline()` and `boost_with_fifo()` in `src/stalld.c:438-563`
- Changing detection logic: `check_starving_tasks()` in `src/stalld.c:616-659`
- Backend implementation: `struct stalld_backend` in `src/stalld.h:79-110`
- eBPF tracepoints: `bpf/stalld.bpf.c` (requires kernel rebuild/reload)

### Understanding Backend Selection

The default backend is chosen **at compile time only** (no runtime fallback):

```c
// src/stalld.c:158-162
#if USE_BPF
    backend = &queue_track_backend;  // eBPF backend
#else
    backend = &sched_debug_backend;  // Procfs backend
#endif
```

`USE_BPF` is set in Makefile based on:
- Architecture (disabled on i686, powerpc, ppc64le)
- Kernel version (disabled on kernels ≤3.x)

If eBPF is compiled in but BPF programs fail to load at runtime, stalld will fail to start (it won't fall back to sched_debug).

## Architecture

### Backend System (src/stalld.h lines 79-110)

`stalld` uses a **pluggable backend architecture** to collect task information:

1. **queue_track_backend** (eBPF-based, default on x86_64/aarch64/s390x)
   - Uses BPF tracepoints to track task queue state in real-time
   - Source: `bpf/stalld.bpf.c` + `src/queue_track.c`
   - More efficient, lower overhead
   - Tracks: `sched_wakeup`, `sched_switch`, `sched_migrate_task`, `sched_process_exit`

2. **sched_debug_backend** (procfs-based, fallback)
   - Parses `/sys/kernel/debug/sched/debug` or `/proc/sched_debug`
   - Source: `src/sched_debug.c`
   - Used on i686, powerpc, ppc64le, and legacy kernels (≤3.x)
   - Handles multiple kernel sched_debug formats (3.x, 4.18+, 6.12+)

Backend selection is automatic at compile time (src/stalld.c:158-162) based on architecture and kernel version.

### Operating Modes (src/stalld.c)

Three threading modes controlled by `-A` and internal flags:

1. **Single-threaded mode** (default, `config_single_threaded=1`)
   - One thread monitors all CPUs
   - Uses `boost_cpu_starving_vector()` to boost all starving tasks at once
   - Lower CPU usage, lower precision
   - **Only works with SCHED_DEADLINE** (not FIFO)

2. **Conservative/Adaptive mode** (`config_adaptive_multi_threaded=1`)
   - Starts with single thread
   - Spawns per-CPU threads when tasks approach starvation (½ threshold)
   - Per-CPU threads exit after 10 idle cycles

3. **Aggressive mode** (`-A`, `config_aggressive=1`)
   - Dedicated thread per monitored CPU from start
   - Highest precision, highest CPU usage
   - Never exit, continuous monitoring

### Key Data Structures

- **`struct task_info`** (src/stalld.h:53-60): Per-task tracking (PID, comm, priority, context switches, starvation timestamp)
- **`struct cpu_info`** (src/stalld.h:65-77): Per-CPU state (running tasks, RT tasks, starving tasks array)
- **`struct stalld_cpu_data`** (src/queue_track.h:19-24): eBPF per-CPU map data
- **`struct queued_task`** (src/queue_track.h:11-17): Task entry in eBPF queue

### Boosting Logic (src/stalld.c:438-563)

1. Detect starvation: Task on runqueue for ≥`starving_threshold` seconds with no context switches
2. Save current scheduling policy
3. Boost to SCHED_DEADLINE (runtime/period) or SCHED_FIFO (priority)
4. Sleep for `boost_duration` seconds
5. Restore original policy

**Important**: FIFO boosting emulates DEADLINE behavior by manually sleeping runtime, restoring policy, sleeping remainder (src/stalld.c:500-526).

### Task Format Auto-Detection (src/sched_debug.h:43-48)

The sched_debug backend handles 3 different kernel formats:
- **OLD_TASK_FORMAT**: 3.x kernels (no state column, 'R' prefix for running task)
- **NEW_TASK_FORMAT**: 4.18+ kernels (has 'S' state column)
- **6.12+ format**: Added EEVDF fields (vruntime, eligible, deadline, slice)

Parser auto-detects format on first read and sets offsets accordingly.

### eBPF Build Process (Makefile:161-189)

When `USE_BPF=1`:
1. Generate `bpf/vmlinux.h` from kernel BTF via `bpftool`
2. Compile `bpf/stalld.bpf.c` → `bpf/stalld.bpf.o` using `clang -target bpf`
3. Generate `src/stalld.skel.h` skeleton from `.bpf.o` via `bpftool gen skeleton`
4. Include skeleton in userspace code compilation

### Idle Detection Optimization (src/stalld.c:226-308)

When `config_idle_detection=1` (default):
- Parse `/proc/stat` to check CPU idle time before expensive parsing
- Skip parsing for CPUs with increasing idle counter
- Reduces overhead when CPUs aren't busy

## Configuration Files

- **systemd/stalld.service**: systemd unit file
- **systemd/stalld.conf**: Configuration options for systemd deployment
- **scripts/throttlectl.sh**: Helper script for RT throttling control

## RT Throttling

`stalld` requires RT throttling to be disabled. The daemon handles this automatically unless running under systemd (where systemd should handle it via `CPUQuota=-1`).

Check: `/proc/sys/kernel/sched_rt_runtime_us` should be `-1`.

## Important Code Patterns

### Task Merging (src/stalld.c:370-397)
When re-parsing tasks, `merge_taks_info()` preserves starvation timestamps for tasks that haven't made progress (same PID, same context switch count).

### Denylist/Ignore Feature
- `-i` flag: Ignore threads/processes matching regex patterns
- Uses POSIX regex via `regexec()`
- Check both thread name and process group name (src/stalld.c:570-614)

### Buffer Management
The buffer for sched_debug automatically grows when content increases (src/sched_debug.c:55-58, src/stalld.h:192).

## Common Gotchas

1. **Single-threaded mode only works with SCHED_DEADLINE**, not FIFO (dies at src/stalld.c:973)
2. **RT throttling must be off** or stalld exits (src/stalld.c:1154-1161)
3. **sched_debug path varies**: `/sys/kernel/debug/sched/debug` or `/proc/sched_debug` (auto-detected in `utils.c`)
4. **Architecture differences**: eBPF not available on all platforms
5. **Kernel version differences**: Legacy kernels (≤3.x) need special handling

## Quick Reference

### Critical Files and Functions

**Entry points:**
- Main entry: `src/stalld.c:main()` line 1121
- Boost logic: `src/stalld.c:boost_with_deadline()` line 438
- Starvation detection: `src/stalld.c:check_starving_tasks()` line 616
- Backend interface: `src/stalld.h:struct stalld_backend` line 79

**Backends:**
- eBPF backend: `src/queue_track.c` + `bpf/stalld.bpf.c`
- Procfs backend: `src/sched_debug.c`

**Configuration:**
- Argument parsing: `src/utils.c:parse_args()`
- Defaults in: `src/stalld.c` global variables (lines 49-169)

### Build Quick Reference

```bash
make                  # Build stalld + tests
make DEBUG=1          # Debug build with -g3
make static           # Static binary
make clean            # Clean build artifacts
make install          # Install to system
```

### Key Runtime Requirements

- **RT throttling must be disabled**: `/proc/sys/kernel/sched_rt_runtime_us == -1`
- **Default starvation threshold**: 60 seconds
- **Default boost**: 20μs runtime / 1s period for 3 seconds
- **Minimum kernel**: 3.10+ (older kernels untested)
- **eBPF requires**: Modern kernel (4.x+), x86_64/aarch64/s390x architecture

### Debugging Commands

```bash
sudo ./stalld -f -v -t 5    # Foreground, verbose, 5s threshold
sudo ./stalld -l -v         # Log-only mode (no boosting)
dmesg | grep stalld         # Check kernel messages (if -k used)
journalctl -u stalld -f     # Follow systemd logs
```
