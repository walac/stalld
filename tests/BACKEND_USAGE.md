# Backend Selection in Tests

## Overview

stalld supports two backends for task monitoring:

1. **sched_debug** (Procfs) - Parses `/sys/kernel/debug/sched/debug` or `/proc/sched_debug`
2. **queue_track** (eBPF) - Uses BPF tracepoints for real-time task tracking

The test infrastructure provides helper functions to detect available backends and start stalld with a specific backend.

## Quick Start

### Using the Helper Function

```bash
#!/bin/bash
source "helpers/test_helpers.sh"

# Start stalld with specific backend
start_stalld_with_backend "sched_debug" -f -v -t 60

# Or with eBPF backend (if available)
start_stalld_with_backend "queue_track" -f -v -t 60
```

### Using start_stalld Directly

```bash
# Start with sched_debug backend
start_stalld -b sched_debug -f -v -t 60

# Start with queue_track backend (short name)
start_stalld -b Q -f -v -t 60
```

## Backend Detection

### Detect Default Backend

```bash
default=$(detect_default_backend)
echo "Default backend: $default"
# Output: "queue_track" or "sched_debug"
```

### Check Backend Availability

```bash
if is_backend_available "queue_track"; then
    echo "eBPF backend is available"
    start_stalld_with_backend "queue_track" -f -v
else
    echo "eBPF backend not available, using sched_debug"
    start_stalld_with_backend "sched_debug" -f -v
fi
```

### List All Available Backends

```bash
backends=$(get_available_backends)
echo "Available backends: $backends"
# Output: "sched_debug queue_track" or "sched_debug"
```

## Backend Names

| Full Name | Short | Description | Availability |
|-----------|-------|-------------|--------------|
| sched_debug | S | Procfs backend | Always available |
| queue_track | Q | eBPF backend | x86_64, aarch64, s390x + kernel 4.x+ |

## Writing Tests with Backend Support

### Test Both Backends

```bash
#!/bin/bash
source "helpers/test_helpers.sh"

start_test "My Test - sched_debug backend"

# Test with sched_debug
start_stalld_with_backend "sched_debug" -f -v -t 5
# ... run test logic ...
stop_stalld

# Test with queue_track (if available)
if is_backend_available "queue_track"; then
    start_test "My Test - queue_track backend"
    start_stalld_with_backend "queue_track" -f -v -t 5
    # ... run test logic ...
    stop_stalld
fi

end_test
```

### Skip Test If Backend Not Available

```bash
#!/bin/bash
source "helpers/test_helpers.sh"

start_test "eBPF Backend Test"

# This automatically skips (exit 77) if queue_track not available
start_stalld_with_backend "queue_track" -f -v -t 60
if [ $? -eq 77 ]; then
    echo "eBPF backend not available, skipping test"
    exit 77
fi

# ... test logic ...

end_test
```

### Test Specific Backend Feature

```bash
#!/bin/bash
source "helpers/test_helpers.sh"

start_test "Test BPF Tracepoint Accuracy"

if ! is_backend_available "queue_track"; then
    echo "This test requires eBPF backend"
    exit 77  # Skip
fi

start_stalld_with_backend "queue_track" -f -v -t 5
# ... BPF-specific test logic ...
stop_stalld

end_test
```

## Backend Characteristics

### sched_debug (Procfs)

**Pros:**
- Always available (no BPF dependency)
- Works on all architectures
- Works on legacy kernels (3.x)

**Cons:**
- Higher overhead (file I/O + parsing)
- Polling-based (not real-time)
- Can miss very short-lived events

**Use Cases:**
- Legacy systems
- Architectures without BPF support (i686, powerpc, ppc64le)
- Baseline compatibility testing

### queue_track (eBPF)

**Pros:**
- Lower overhead
- Real-time event tracking
- More accurate task state tracking

**Cons:**
- Requires modern kernel (4.x+)
- Only on x86_64, aarch64, s390x
- Requires BPF support

**Use Cases:**
- Modern systems
- Performance-sensitive scenarios
- Real-time accuracy testing

## Example Test

See `functional/test_backend_selection.sh` for a complete example that:
- Detects available backends
- Tests both backends
- Verifies backend selection works
- Demonstrates helper function usage

## Helper Functions Reference

### Detection Functions

```bash
detect_default_backend              # Returns default backend name
is_backend_available "backend"      # Returns 0 if available, 1 otherwise
get_available_backends              # Returns space-separated list
```

### Start Functions

```bash
start_stalld_with_backend "backend" [args...]
# - Checks if backend is available
# - Returns 77 (skip) if not available
# - Starts stalld with -b backend
# - Returns start_stalld exit code

start_stalld -b "backend" [args...]
# - Direct stalld invocation
# - No availability checking
# - Fails if backend not available
```

## Architecture-Specific Behavior

| Architecture | Default Backend | eBPF Available |
|--------------|-----------------|----------------|
| x86_64       | queue_track     | Yes            |
| aarch64      | queue_track     | Yes            |
| s390x        | queue_track     | Yes            |
| i686         | sched_debug     | No             |
| ppc64le      | sched_debug     | No             |
| powerpc      | sched_debug     | No             |

**Note:** On kernels ≤3.x, sched_debug is used regardless of architecture.

## Common Patterns

### Run Test on All Available Backends

```bash
for backend in $(get_available_backends); do
    echo "Testing with backend: $backend"
    start_stalld_with_backend "$backend" -f -v -t 5
    # ... test logic ...
    stop_stalld
done
```

### Require Specific Backend

```bash
required_backend="queue_track"
if ! is_backend_available "$required_backend"; then
    echo "Test requires $required_backend backend"
    exit 77  # Skip
fi
```

### Compare Backend Behavior

```bash
# Test with sched_debug
start_stalld_with_backend "sched_debug" -f -v -t 5
result_sched_debug=$(run_test_scenario)
stop_stalld

# Test with queue_track
if is_backend_available "queue_track"; then
    start_stalld_with_backend "queue_track" -f -v -t 5
    result_queue_track=$(run_test_scenario)
    stop_stalld

    assert_equals "$result_sched_debug" "$result_queue_track" \
        "Both backends should detect same starvation"
fi
```

## References

- stalld source: `src/stalld.c:158-162` (backend selection)
- stalld backend option: `src/utils.c:779` (command-line help)
- Helper implementation: `tests/helpers/test_helpers.sh:521-605`
- Example test: `tests/functional/test_backend_selection.sh`
