# Context Snapshot: stalld Test Suite Fixes
**Date:** October 31, 2025
**Branch:** tests-devel
**Commits:** 21ad4c2c3661, 21f80e410c9e

## Summary

Fixed three consistently failing functional tests by identifying and resolving a critical timing race condition in the test infrastructure. All three tests now pass reliably with no regressions introduced.

## Problem Statement

Three functional tests were failing consistently:
- `test_fifo_boosting.sh`
- `test_starvation_detection.sh`
- `test_starvation_threshold.sh`

Additionally, DL-server interference needed to be addressed as a default configuration.

## Root Cause Analysis

### Timing Race Condition
The fundamental issue was **execution order**:
- **Before:** Tests started stalld first, then created starvation workload
- **Problem:** stalld detected pre-existing kworker kernel tasks instead of the test's intentional starvation scenarios
- **Result:** Tests failed because grep patterns couldn't find "starvation_gen" in logs (only kworker tasks were detected)

### Secondary Issues
1. **Idle detection interference:** Kworker tasks were being detected due to idle CPU scanning
2. **Multi-CPU affinity bug:** In test_starvation_detection.sh Test 4, stalld could run on the same CPU as test workloads, causing interference
3. **Path resolution:** test_helpers.sh used hardcoded relative path `../stalld` which failed when tests ran through the test runner
4. **DL-server interference:** DL-server was not disabled by default, causing issues on Linux 6.6+ kernels

## Solution Implemented

### Core Fix: Reverse Execution Order
**Pattern applied across all affected tests:**
```bash
# OLD (failing):
start_stalld -f -v -l -t $threshold -c ${TEST_CPU}
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &

# NEW (passing):
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
sleep 2  # Allow starvation to establish
start_stalld -f -v -N -l -t $threshold -c ${TEST_CPU}
```

### Additional Fixes

**1. Disable Idle Detection (-N flag)**
- Added `-N` flag to all stalld invocations
- Prevents stalld from detecting idle kworker tasks
- Focuses detection on actual test workloads

**2. Specific Task Matching (grep patterns)**
```bash
# OLD:
grep "starved on CPU" "${STALLD_LOG}"

# NEW:
grep -qE "starvation_gen.*starved on CPU|starved on CPU.*starvation_gen" "${STALLD_LOG}"
```

**3. Multi-CPU Affinity Fix (test_starvation_detection.sh Test 4)**
```bash
# Pick stalld CPU that avoids both test CPUs
STALLD_CPU_MULTI=${STALLD_CPU}
if [ ${STALLD_CPU} -eq ${CPU0} ] || [ ${STALLD_CPU} -eq ${CPU1} ]; then
    for cpu in $(get_online_cpus); do
        if [ $cpu -ne ${CPU0} ] && [ $cpu -ne ${CPU1} ]; then
            STALLD_CPU_MULTI=$cpu
            break
        fi
    done
fi
```

**4. Path Resolution Fix (test_helpers.sh)**
```bash
# OLD:
local stalld_bin="../stalld"

# NEW:
local stalld_bin="${TEST_ROOT}/../stalld"
if [ -z "${TEST_ROOT}" ]; then
    stalld_bin="../stalld"
fi
```

**5. DL-server Default Disabled (run_tests.sh)**
```bash
# OLD:
DISABLE_DL_SERVER=0

# NEW:
DISABLE_DL_SERVER=1
```

## Files Modified

### Test Files (3)
1. **tests/functional/test_fifo_boosting.sh**
   - Modified all 4 sub-tests
   - Reversed execution order
   - Added -N flag
   - Updated grep patterns

2. **tests/functional/test_starvation_detection.sh**
   - Modified all 6 sub-tests
   - Reversed execution order
   - Added -N flag to all tests
   - Fixed Test 4 multi-CPU affinity bug
   - Updated grep patterns

3. **tests/functional/test_starvation_threshold.sh**
   - Modified all 3 sub-tests
   - Reversed execution order
   - Updated grep patterns

### Infrastructure Files (2)
4. **tests/helpers/test_helpers.sh**
   - Fixed `start_stalld()` function
   - Changed from hardcoded `../stalld` to `${TEST_ROOT}/../stalld`
   - Maintains backward compatibility with fallback

5. **tests/run_tests.sh**
   - Changed `DISABLE_DL_SERVER=0` to `DISABLE_DL_SERVER=1`
   - DL-server now disabled by default for all test runs

### Documentation (1)
6. **tests/TODO.md**
   - Added comprehensive entry documenting the fixes
   - Updated status and known issues

## Test Results

### Before Fixes
- test_fifo_boosting: **FAIL** (detected kworker tasks, not starvation_gen)
- test_starvation_detection: **FAIL** (detected kworker tasks, Test 4 had CPU affinity bug)
- test_starvation_threshold: **FAIL** (detected kworker tasks)

### After Fixes
- test_fifo_boosting: **PASS** (all 4 sub-tests)
- test_starvation_detection: **PASS** (all 6 sub-tests)
- test_starvation_threshold: **PASS** (all 4 sub-tests)

### Full Test Suite Results
```
Total:   21
Passed:  17  ✓
Failed:  2   (pre-existing, unrelated to this work)
Skipped: 2
```

**No regressions introduced.**

## Verification Steps

Individual test verification:
```bash
sudo ./run_tests.sh --quick -t test_starvation_threshold  # PASS
sudo ./run_tests.sh --quick -t test_starvation_detection  # PASS
sudo ./run_tests.sh --quick -t test_fifo_boosting         # PASS
```

Full suite verification:
```bash
sudo ./run_tests.sh --quick  # 17/21 PASS
```

## Key Insights

1. **Timing matters:** Test infrastructure must ensure workloads exist before monitoring tools start
2. **Task identification:** Generic patterns like "starved on CPU" can match unintended targets
3. **CPU affinity:** Multi-CPU tests require careful CPU assignment to avoid interference
4. **Path assumptions:** Hardcoded relative paths break when execution context changes
5. **Kernel features:** DL-server on modern kernels interferes with RT starvation detection

## Benefits Achieved

- ✅ Eliminated false positives from kworker task detection
- ✅ Fixed multi-CPU test interference issues
- ✅ Consistent test results across multiple runs
- ✅ Improved test reliability and maintainability
- ✅ Better default configuration for modern kernels (DL-server disabled)

## Remaining Known Issues

Two pre-existing test failures unrelated to this work:
- `test_backend_selection` - Different issue
- `test_logging_destinations` - Different issue

These were failing before our changes and remain as future work items.

## Commits

### Commit 1: 21ad4c2c3661
```
tests: Fix timing race conditions in starvation detection tests

Fix three consistently failing functional tests by addressing
the root cause: a timing race condition where stalld starts before
the test workload, causing it to detect pre-existing kworker tasks
instead of the test's intentional starvation scenarios.
```

### Commit 2: 21f80e410c9e
```
docs: Update TODO.md with test suite timing race condition fixes

Document the comprehensive fix for three consistently failing functional
tests completed on 2025-10-31.
```

## Lessons Learned

1. **Start workload first, then monitoring:** When testing detection systems, ensure the target condition exists before starting the detector
2. **Specific task matching:** Always match on unique identifiers (task names) rather than generic patterns
3. **Resource isolation:** Tests should explicitly manage CPU affinity to prevent interference
4. **Path robustness:** Use variables like `${TEST_ROOT}` for portability across execution contexts
5. **Modern kernel awareness:** Keep test infrastructure updated for new kernel features like DL-server

## Conclusion

All three previously failing tests now pass reliably. The timing race condition has been eliminated through systematic reversal of execution order, improved task matching, and proper resource isolation. Test infrastructure has been hardened with path fixes and better default configuration for modern kernels.

---

**Generated:** 2025-10-31
**Context:** stalld test suite development (tests-devel branch)
**Next Steps:** Address remaining two pre-existing test failures (test_backend_selection, test_logging_destinations)
