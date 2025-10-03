# Test Suite Implementation Plan

This document tracks the comprehensive test suite implementation for stalld.

## Overview

**Goal**: Create comprehensive test suite covering all stalld functionality including command-line options, core logic, and edge cases.

**Languages**: Shell, Python, and C

**Status**: Phase 1 Complete (Foundation) ✅

---

## ✅ Phase 1: Foundation (COMPLETE)

**Goal**: Fix existing test, create infrastructure, basic functional tests

### Phase 1.1: Fix test01.c Critical Issues ✅
- [x] Buffer overflow: sprintf → snprintf for CPU path construction
- [x] Error handling: Save errno before calling functions that may modify it
- [x] Format consistency: Add newlines to error() calls, remove redundant \n
- [x] Resource cleanup: Add cleanup() function to destroy pthread barriers
- [x] Exit codes: Use proper exit codes (1 instead of -1, preserve errno)
- [x] File descriptor: Close fd on read() error path to prevent leak
- [x] Initialization: Track barrier initialization state for safe cleanup

**Files Modified**: `test01.c`

### Phase 1.2: Create Test Infrastructure ✅
- [x] Create directory structure (helpers/, functional/, unit/, integration/, fixtures/, results/)
- [x] Create `helpers/test_helpers.sh` (355 lines, 20+ helper functions)
  - Assertions: assert_equals, assert_contains, assert_file_exists, assert_process_running
  - stalld management: start_stalld, stop_stalld with PID tracking
  - System helpers: require_root, check_rt_throttling, pick_test_cpu, wait_for_log_message
  - Automatic cleanup via trap (EXIT, INT, TERM)
- [x] Create `helpers/starvation_gen.c` (266 lines)
  - Configurable CPU, priority, thread count, duration
  - SCHED_FIFO blocker + SCHED_OTHER blockee threads
  - Usage: `starvation_gen -c CPU -p priority -n num_threads -d duration -v`
- [x] Create `run_tests.sh` (311 lines)
  - Auto-discovery of tests in unit/, functional/, integration/
  - Color-coded output (RED/GREEN/YELLOW)
  - Individual test logs in results/
  - Statistics tracking (total/passed/failed/skipped)
  - Exit codes: 0=pass, 1=fail, 77=skip (autotools convention)
- [x] Update `Makefile` with test targets
  - `make test`, `make test-unit`, `make test-functional`, `make test-integration`
  - Build helper binaries (starvation_gen)
- [x] Update `.gitignore` (test artifacts)

**Files Created**: `run_tests.sh`, `helpers/test_helpers.sh`, `helpers/starvation_gen.c`, `Makefile` (modified), `.gitignore` (modified)

### Phase 1.3: Create Basic Functional Tests ✅
- [x] `test_foreground.sh` - Tests `-f` flag prevents daemonization
  - Verify default daemonization (parent PID = 1)
  - Verify -f prevents daemonization (parent PID != 1)
  - Verify -v implies foreground mode
- [x] `test_log_only.sh` - Tests `-l` flag logs but doesn't boost
  - Create starvation using starvation_gen
  - Verify "starved" appears in logs (detection works)
  - Verify "boosted" does NOT appear (no boosting with -l)
- [x] `test_logging_destinations.sh` - Tests `-v`, `-k`, `-s` logging options
  - Test -v logs to stdout/stderr
  - Test -k logs to kernel message buffer (dmesg)
  - Test -s logs to syslog/journalctl
  - Test combined logging modes
- [x] Create `README.md` - Complete test documentation

**Files Created**: `functional/test_foreground.sh`, `functional/test_log_only.sh`, `functional/test_logging_destinations.sh`, `README.md`

**Test Results**: 3/4 tests passing (test01 requires root + RT throttling disabled)

---

## 🔄 Phase 2: Command-Line Options Testing (PENDING)

**Goal**: Test all stalld command-line options for correctness

### Phase 2.1: Monitoring Option Tests
- [ ] `test_cpu_selection.sh` - Test `-c/--cpu <list>` option
  - Test single CPU monitoring
  - Test CPU list (e.g., "0,2,4")
  - Test CPU range (e.g., "0-3")
  - Test combined format (e.g., "0,2-4,6")
  - Verify stalld only monitors specified CPUs
  - Test invalid CPU numbers (error handling)
- [ ] `test_starvation_threshold.sh` - Test `-t/--starving_threshold <sec>` option
  - Test custom threshold (e.g., 5s, 10s, 30s)
  - Verify stalld detects starvation after threshold
  - Verify stalld doesn't detect before threshold
  - Test with starvation_gen creating controlled starvation
  - Test invalid threshold values (0, negative, non-numeric)

**Estimated Time**: 2-3 days

### Phase 2.2: Boosting Option Tests
- [ ] `test_boost_period.sh` - Test `-p/--boost_period <ns>` option
  - Test custom period values (default: 1,000,000,000 ns = 1s)
  - Test very short period (100ms)
  - Test very long period (10s)
  - Verify SCHED_DEADLINE uses correct period
  - Test invalid values (0, negative)
- [ ] `test_boost_runtime.sh` - Test `-r/--boost_runtime <ns>` option
  - Test custom runtime values (default: 20,000 ns = 20μs)
  - Test runtime < period (valid)
  - Test runtime > period (should error)
  - Test invalid values
- [ ] `test_boost_duration.sh` - Test `-d/--boost_duration <sec>` option
  - Test custom durations (default: 3s)
  - Test short duration (1s)
  - Test long duration (10s)
  - Verify task is boosted for correct duration
  - Verify policy restored after duration
- [ ] `test_force_fifo.sh` - Test `-F/--force_fifo` option
  - Verify SCHED_FIFO used instead of SCHED_DEADLINE
  - Test FIFO priority setting
  - Compare behavior with DEADLINE boosting
  - Note: Single-threaded mode requires DEADLINE (dies with FIFO)

**Estimated Time**: 3-4 days

### Phase 2.3: Daemon Option Tests
- [ ] `test_pidfile.sh` - Test `-P/--pidfile <path>` option
  - Verify PID file created at specified path
  - Verify PID file contains correct PID
  - Verify PID file removed on clean shutdown
  - Test custom pidfile locations
  - Test invalid paths (permission denied, etc.)
- [ ] `test_affinity.sh` - Test `-a/--affinity <cpu-list>` option
  - Verify stalld process runs on specified CPUs
  - Test single CPU affinity
  - Test multi-CPU affinity
  - Verify using /proc/$PID/stat or taskset
  - Test invalid CPU specifications

**Estimated Time**: 2 days

**Phase 2 Total Estimated Time**: 1-2 weeks

---

## 🔄 Phase 3: Core Logic Testing (PENDING)

**Goal**: Verify starvation detection and boosting mechanisms work correctly

### Phase 3.1: Starvation Detection Tests
- [ ] `test_starvation_detection.sh` - Verify starvation detection logic
  - Create controlled starvation scenario
  - Verify detection of starved tasks
  - Test context switch count tracking
  - Test task merging (preserves timestamps for non-progressing tasks)
  - Verify detection across multiple CPUs
  - Test edge case: task making minimal progress (context switches but still starved)
- [ ] `test_runqueue_parsing.sh` - Test backend parsing
  - Verify correct task info extraction (PID, comm, priority, switches)
  - Test with both eBPF and procfs backends (if available)
  - Verify handling of different kernel formats (3.x, 4.18+, 6.12+)

**Estimated Time**: 3-4 days

### Phase 3.2: Boosting Mechanism Tests
- [ ] `test_deadline_boosting.sh` - Verify SCHED_DEADLINE boosting
  - Create starvation, verify boosting occurs
  - Verify correct SCHED_DEADLINE parameters applied
  - Verify starved task makes progress during boost
  - Verify policy restored after boost
  - Test multiple simultaneous boosts
- [ ] `test_fifo_boosting.sh` - Verify SCHED_FIFO boosting
  - Test with -F flag
  - Verify FIFO priority setting
  - Verify FIFO emulation (sleep runtime, restore, sleep remainder)
  - Compare effectiveness with DEADLINE boosting
- [ ] `test_boost_restoration.sh` - Verify policy restoration
  - Test restoration of SCHED_OTHER
  - Test restoration of original SCHED_FIFO (if task was RT)
  - Test restoration of nice values
  - Verify restoration after signal interruption

**Estimated Time**: 4-5 days

### Phase 3.3: Task Merging and Idle Detection
- [ ] `test_task_merging.sh` - Test task merging logic
  - Verify starvation timestamps preserved for non-progressing tasks
  - Verify same PID + same context switches = merged
  - Test across multiple monitoring cycles
- [ ] `test_idle_detection.sh` - Test idle CPU detection
  - Verify idle CPUs skipped (if idle detection enabled)
  - Test /proc/stat parsing
  - Verify monitoring resumes when CPU becomes busy

**Estimated Time**: 2-3 days

**Phase 3 Total Estimated Time**: 2 weeks

---

## 🔄 Phase 4: Advanced Features (PENDING)

**Goal**: Test threading modes, filtering, backends, and complex scenarios

### Phase 4.1: Threading Mode Tests
- [ ] `test_single_threaded_mode.sh` - Test default single-threaded mode
  - Verify one thread monitors all CPUs
  - Verify boost_cpu_starving_vector() called
  - Test with multiple CPUs starving simultaneously
  - Verify only works with SCHED_DEADLINE (dies with FIFO)
- [ ] `test_adaptive_mode.sh` - Test adaptive multi-threading
  - Verify starts with single thread
  - Verify per-CPU threads spawn when approaching threshold (½)
  - Verify threads exit after 10 idle cycles
  - Test thread lifecycle across multiple starvation events
- [ ] `test_aggressive_mode.sh` - Test aggressive mode (-A)
  - Verify per-CPU threads created at startup
  - Verify threads never exit
  - Verify continuous monitoring
  - Compare overhead vs. adaptive mode

**Estimated Time**: 3-4 days

### Phase 4.2: Filtering Tests
- [ ] `test_thread_ignore.sh` - Test `-i <regex>` thread name filtering
  - Test single regex pattern
  - Test multiple patterns (comma-separated)
  - Verify matching threads not boosted
  - Test regex syntax (literals, wildcards, anchors)
  - Test invalid regex (error handling)
- [ ] `test_process_ignore.sh` - Test `-I <regex>` process name filtering
  - Test process group name matching
  - Verify entire process tree ignored
  - Test combined with thread filtering

**Estimated Time**: 2-3 days

### Phase 4.3: Backend Comparison
- [ ] `test_backend_comparison.sh` - Compare eBPF vs procfs backends
  - Run identical scenarios with both backends (if available)
  - Compare detection accuracy
  - Compare performance/overhead
  - Verify consistent behavior
  - Test backend-specific edge cases
- [ ] `test_sched_debug_formats.sh` - Test procfs backend format handling
  - Test with different kernel formats (if test data available)
  - Verify auto-detection works
  - Test parsing of all supported formats (3.x, 4.18+, 6.12+)

**Estimated Time**: 3-4 days

**Phase 4 Total Estimated Time**: 1.5-2 weeks

---

## 🔄 Phase 5: Integration and Edge Cases (PENDING)

**Goal**: Test complex scenarios, error handling, and edge cases

### Phase 5.1: Integration Tests
- [ ] `test_full_lifecycle.sh` - Complete stalld lifecycle
  - Start, detect starvation, boost, restore, shutdown
  - Test clean shutdown (SIGTERM)
  - Test forced shutdown (SIGKILL)
  - Test restart behavior
- [ ] `test_multi_cpu_starvation.sh` - Multiple CPUs starving simultaneously
  - Create starvation on multiple CPUs
  - Verify all detected and boosted
  - Test with different threading modes
- [ ] `test_systemd_integration.sh` - systemd integration (if systemd available)
  - Test with systemd unit file
  - Verify RT throttling handling under systemd
  - Test systemd logging
  - Test systemd restart policies

**Estimated Time**: 3-4 days

### Phase 5.2: Edge Cases and Error Handling
- [ ] `test_error_handling.sh` - Error handling
  - Test with RT throttling enabled (should die or handle gracefully)
  - Test with no permission to boost (non-root)
  - Test with invalid CPU specifications
  - Test with /proc/sched_debug unavailable
  - Test with BPF loading failures
- [ ] `test_signal_handling.sh` - Signal handling
  - Test SIGTERM (graceful shutdown)
  - Test SIGINT (keyboard interrupt)
  - Test SIGHUP (if handled)
  - Test signal during boost operation
- [ ] `test_resource_limits.sh` - Resource limits and stress
  - Test with many starving tasks
  - Test with high-frequency starvation
  - Test memory usage over time
  - Test CPU overhead

**Estimated Time**: 3-4 days

**Phase 5 Total Estimated Time**: 1-1.5 weeks

---

## 🔄 Phase 6: Polish and Documentation (PENDING)

**Goal**: CI/CD integration, documentation polish, final validation

### Phase 6.1: CI/CD Integration
- [ ] Create GitHub Actions / GitLab CI configuration
- [ ] Automated test runs on pull requests
- [ ] Test coverage reporting
- [ ] Performance regression testing

### Phase 6.2: Documentation
- [ ] Polish README.md with complete examples
- [ ] Document all test helpers in detail
- [ ] Create troubleshooting guide
- [ ] Add test writing best practices

### Phase 6.3: Final Validation
- [ ] Run full test suite on multiple kernel versions
- [ ] Test on multiple architectures (x86_64, aarch64, if available)
- [ ] Validate test coverage completeness
- [ ] Performance benchmarking

**Estimated Time**: 1 week

**Phase 6 Total Estimated Time**: 1 week

---

## Summary

| Phase | Status | Estimated Time | Description |
|-------|--------|----------------|-------------|
| Phase 1 | ✅ Complete | - | Foundation: Infrastructure and basic tests |
| Phase 2 | 🔄 Pending | 1-2 weeks | Command-line options testing |
| Phase 3 | 🔄 Pending | 2 weeks | Core logic testing |
| Phase 4 | 🔄 Pending | 1.5-2 weeks | Advanced features |
| Phase 5 | 🔄 Pending | 1-1.5 weeks | Integration and edge cases |
| Phase 6 | 🔄 Pending | 1 week | Polish and documentation |

**Total Remaining Time**: 7-9 weeks

---

## Current Test Coverage

### Completed Tests (4)
1. ✅ `test01.c` - Original starvation test (fixed)
2. ✅ `test_foreground.sh` - Foreground mode (-f)
3. ✅ `test_log_only.sh` - Log-only mode (-l)
4. ✅ `test_logging_destinations.sh` - Logging options (-v, -k, -s)

### Planned Tests (30+)
- 8 command-line option tests (Phase 2)
- 9 core logic tests (Phase 3)
- 8 advanced feature tests (Phase 4)
- 6 integration/edge case tests (Phase 5)
- CI/CD and polish (Phase 6)

---

## Test Requirements

### Prerequisites
- Root privileges (most tests)
- RT throttling disabled: `echo -1 > /proc/sys/kernel/sched_rt_runtime_us`
- stalld built: `make` in project root
- Kernel version 3.10+ (older untested)

### Optional
- systemd (for systemd integration tests)
- Multiple CPU cores (for multi-CPU tests)
- eBPF support (for backend comparison tests)

---

## Running Tests

```bash
# Run all tests
make test
cd tests && ./run_tests.sh

# Run specific categories
make test-unit
make test-functional
make test-integration

# Run individual tests
cd tests && functional/test_foreground.sh

# Run with verbose output
cd tests && ./run_tests.sh -v
```

---

## Contributing

When adding new tests:
1. Use appropriate directory (unit/, functional/, integration/)
2. Follow naming convention: `test_<feature>.sh` or `test_<feature>.c`
3. Include SPDX license header: `# SPDX-License-Identifier: GPL-2.0-or-later`
4. Use helper functions from `helpers/test_helpers.sh`
5. Add cleanup for any resources created (automatic via CLEANUP_PIDS/CLEANUP_FILES)
6. Document what the test verifies
7. Use exit codes: 0=pass, 1=fail, 77=skip
8. Update this TODO.md with completion status

---

## References

- **tests/README.md** - Complete test documentation
- **CLAUDE.md** - stalld architecture and development guide
- **README.md** - stalld project overview
- **man/stalld.8** - Complete command-line reference

---

*Last Updated: 2025-10-02*
*Status: Phase 1 Complete, Phases 2-6 Pending*
