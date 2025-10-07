# Legacy Tests

This directory contains legacy test code that has been preserved and integrated into the modern test infrastructure.

## Overview

Legacy tests are older tests (typically written in C) that existed before the comprehensive test suite was developed. Rather than rewriting these tests from scratch, they have been:

1. **Preserved** - The original test logic remains intact
2. **Improved** - Critical bugs have been fixed
3. **Wrapped** - Modern test infrastructure provides consistent setup/teardown
4. **Integrated** - They run as part of the standard test suite

## Current Legacy Tests

### test01 - Original Starvation Test

**File**: `test01.c` (505 lines)
**Wrapper**: `test01_wrapper.sh`

**Purpose**: Creates a simple starvation scenario and validates that stalld detects and resolves it.

**Test Scenario**:
- Creates a SCHED_FIFO "blocker" thread that busy-loops on a CPU
- Creates a SCHED_OTHER "blockee" thread on the same CPU that tries to run
- The blockee starves while the blocker monopolizes the CPU
- stalld should detect the starvation and temporarily boost the blockee
- Test succeeds when both threads complete

**Improvements Made** (Phase 1.1):
1. ✅ Buffer overflow fix: `sprintf` → `snprintf` for CPU path construction
2. ✅ Error handling: Proper errno preservation before library calls
3. ✅ Format consistency: Proper newlines in error messages
4. ✅ Resource cleanup: `cleanup()` function to destroy pthread barriers
5. ✅ Exit codes: Use proper exit codes (1 instead of -1)
6. ✅ File descriptor leak fix: Close fd on error path
7. ✅ Initialization tracking: Safe barrier cleanup state management

**Wrapper Features**:
- Automatic RT throttling save/disable/restore
- Automatic DL-server save/disable/restore (Linux 6.6+)
- Automatic stalld lifecycle management (start/stop)
- Proper cleanup on exit/interrupt
- Integration with test_helpers.sh infrastructure
- Exit code compatibility (0=pass, 1=fail, 77=skip)

**Usage**:

```bash
# Via test runner (recommended)
cd tests && ./run_tests.sh

# Via Makefile
make test-legacy

# Direct execution (wrapper)
cd tests && ./legacy/test01_wrapper.sh

# Direct execution (binary only - requires manual setup)
# You must manually disable RT throttling and start stalld first
cd tests && ./legacy/test01 -v
```

**Options** (test01 binary):
- `-c N` - Use CPU N for test (default: auto-pick last CPU)
- `-p N` - Use priority N for blocker thread (default: 2)
- `-v` - Verbose output
- `-q` - Quiet mode
- `-d` - Debug mode (implies verbose)

## Integration Details

### How Legacy Tests Are Run

1. **Build**: `make` in `tests/` builds `legacy/test01` binary
2. **Discovery**: `run_tests.sh` finds `legacy/test01_wrapper.sh`
3. **Execution**: Wrapper script:
   - Sources `helpers/test_helpers.sh` for infrastructure
   - Saves and disables RT throttling
   - Saves and disables DL-server (if present)
   - Starts stalld with appropriate options
   - Runs the legacy test binary
   - Stops stalld
   - Restores system state
4. **Reporting**: Test results integrated into standard test output

### Directory Structure

```
legacy/
├── README.md           # This file
├── test01.c            # Legacy test source (C code)
├── test01              # Compiled binary (gitignored)
└── test01_wrapper.sh   # Modern wrapper script
```

### Changes from Original test01.c

The legacy test01.c has been modified minimally:

1. **Removed**: Manual RT throttling check (`check_throttling()` function)
   - The wrapper now handles this automatically
   - Added comment explaining the change
   - Standalone execution still possible (with manual RT throttling setup)

2. **Fixed**: 7 critical bugs (see improvements list above)

3. **Preserved**: All original test logic, thread creation, and synchronization

## Adding New Legacy Tests

If you have another legacy test to integrate:

1. **Place source code** in `legacy/` directory (e.g., `legacy/testNN.c`)

2. **Create wrapper script** (e.g., `legacy/testNN_wrapper.sh`):
```bash
#!/bin/bash
source "${TEST_ROOT}/helpers/test_helpers.sh"
start_test "TestNN Description"

# Setup
require_root
save_rt_throttling
disable_rt_throttling
start_stalld -f -v -t 5

# Run legacy test
"${LEGACY_DIR}/testNN" "$@"

# Cleanup (automatic via trap)
stop_stalld
restore_rt_throttling

end_test
```

3. **Update Makefile**:
```makefile
LEGACY_TESTS := legacy/test01 legacy/testNN

legacy/testNN: legacy/testNN.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
```

4. **Update run_tests.sh** (optional - if not using standard naming):
   - Legacy tests using `test_*.sh` naming are auto-discovered
   - Or explicitly add like test01_wrapper.sh

5. **Document in this README**

## Philosophy

Legacy tests represent important test coverage that was developed with significant effort. Rather than discarding them or completely rewriting them, we:

- **Respect** the original test author's work
- **Preserve** the test logic and intent
- **Improve** critical bugs and safety issues
- **Modernize** the infrastructure around them
- **Integrate** them seamlessly into the test suite

This approach provides the best of both worlds: proven test coverage with modern infrastructure.

## References

- **Test Suite Overview**: `tests/README.md`
- **Test Implementation Plan**: `tests/TODO.md`
- **Phase 1.1 Fixes**: See TODO.md Phase 1.1 section
- **stalld Architecture**: `CLAUDE.md`
