# stalld Test Suite

Comprehensive test suite for the stalld (starvation daemon) project.

## Overview

This test suite validates all aspects of stalld functionality:
- Command-line option handling
- Starvation detection logic
- Thread boosting behavior
- Backend functionality (eBPF and procfs)
- Edge cases and integration scenarios

## Quick Start

### Prerequisites

- Root privileges (most tests require root)
- RT throttling disabled: `echo -1 > /proc/sys/kernel/sched_rt_runtime_us`
- stalld built: run `make` in project root

### Running Tests

```bash
# Run all tests
make test

# Run specific test categories
make test-unit           # Unit tests only
make test-functional     # Functional tests only
make test-integration    # Integration tests only

# Run test runner directly
./run_tests.sh
./run_tests.sh --unit-only
./run_tests.sh --functional-only
```

## Test Organization

```
tests/
├── run_tests.sh              # Main test runner
├── Makefile                  # Build system
├── test01.c                  # Original starvation test (fixed)
├── helpers/
│   ├── test_helpers.sh       # Common helper functions
│   └── starvation_gen.c      # Configurable starvation generator
├── functional/               # Functional tests (shell scripts)
│   ├── test_foreground.sh
│   ├── test_log_only.sh
│   └── test_logging_destinations.sh
├── unit/                     # Unit tests (C programs)
├── integration/              # Integration tests (shell scripts)
├── fixtures/                 # Test data and configurations
└── results/                  # Test output logs (gitignored)
```

## Writing Tests

### Functional Test Template (Shell)

```bash
#!/bin/bash
# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

start_test "Your Test Name"

# Require root if needed
require_root

# Your test logic here
start_stalld -f -v -l -t 5
assert_process_running "${STALLD_PID}" "stalld should be running"

# Cleanup handled automatically
stop_stalld

end_test
```

### Unit Test Template (C)

```c
#include <stdio.h>
#include <assert.h>

int main(void) {
    // Your test logic
    assert(condition);
    printf("Test passed\n");
    return 0;
}
```

### Test Exit Codes

- `0`: Test passed
- `1`: Test failed
- `77`: Test skipped (autotools convention)

## Helper Functions

### Test Assertions

```bash
assert_equals expected actual "message"
assert_contains haystack needle "message"
assert_file_exists "/path/to/file"
assert_process_running $PID
```

### stalld Management

```bash
start_stalld [args...]      # Start stalld in background
stop_stalld                 # Stop stalld gracefully
```

### System Helpers

```bash
require_root                # Skip test if not root
check_rt_throttling         # Check if RT throttling is disabled
pick_test_cpu               # Pick a CPU for testing
wait_for_log_message "pattern" timeout
```

### Starvation Generator

```bash
# Create controlled starvation
../helpers/starvation_gen -c CPU -p priority -n num_threads -d duration -v

# Example: CPU 2, priority 10, 3 blockee threads, 60 seconds
../helpers/starvation_gen -c 2 -p 10 -n 3 -d 60 -v
```

## Test Results

Test results are stored in `results/` directory:
- `test_run_YYYYMMDD_HHMMSS.log` - Full test run log
- `test_name.log` - Individual test output

## Current Test Coverage

### Phase 1: Foundation (✅ Complete)
- [x] test01.c - Fixed and improved
- [x] Test infrastructure (run_tests.sh, helpers)
- [x] test_foreground.sh - Foreground mode
- [x] test_log_only.sh - Log-only mode
- [x] test_logging_destinations.sh - Logging options

### Phase 2: Command-Line Options (Planned)
- [ ] CPU selection (-c)
- [ ] Starvation threshold (-t)
- [ ] Boost parameters (-p, -r, -d)
- [ ] Force FIFO (-F)
- [ ] Threading modes (-A)
- [ ] Filtering (-i, -I)
- [ ] PID file (-P)
- [ ] CPU affinity (-a)

### Phase 3: Core Logic (Planned)
- [ ] Starvation detection
- [ ] SCHED_DEADLINE boosting
- [ ] SCHED_FIFO boosting
- [ ] Task merging
- [ ] Idle detection

### Phase 4: Advanced (Planned)
- [ ] Backend comparison
- [ ] Threading mode verification
- [ ] Integration tests
- [ ] Stress tests

## Troubleshooting

### Tests fail with "RT throttling not disabled"

```bash
echo -1 > /proc/sys/kernel/sched_rt_runtime_us
```

### Tests fail with "permission denied"

Run as root:
```bash
sudo make test
```

### stalld fails to start

1. Check if stalld is already running: `pkill stalld`
2. Verify binary exists: `ls -l ../stalld`
3. Check build: `cd .. && make clean && make`

## Contributing

When adding new tests:
1. Use the appropriate directory (unit/, functional/, integration/)
2. Follow naming convention: `test_<feature>.sh` or `test_<feature>.c`
3. Include SPDX license header
4. Use helper functions from test_helpers.sh
5. Add cleanup for any resources created
6. Document what the test verifies

## References

- [CLAUDE.md](../CLAUDE.md) - stalld architecture and development guide
- [README.md](../README.md) - stalld project overview
- [Makefile](Makefile) - Build system
