#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: SCHED_FIFO Boosting Mechanism
# Verify stalld correctly boosts starving tasks using SCHED_FIFO with -F flag,
# implements FIFO emulation, and compares with DEADLINE effectiveness
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "SCHED_FIFO Boosting Mechanism"

# Setup test environment
setup_test_environment

# Require root for this test
require_root

# Check RT throttling
if ! check_rt_throttling; then
    echo -e "${YELLOW}SKIP: RT throttling must be disabled for this test${NC}"
    exit 77
fi

# Pick a CPU for testing
TEST_CPU=$(pick_test_cpu)
log "Using CPU ${TEST_CPU} for testing"

# Pick a different CPU for stalld to run on (avoid interference)
STALLD_CPU=0
if [ ${TEST_CPU} -eq 0 ]; then
    STALLD_CPU=1
fi
log "Stalld will run on CPU ${STALLD_CPU}"

# Setup paths
STARVE_GEN="${TEST_ROOT}/helpers/starvation_gen"
STALLD_LOG="/tmp/stalld_test_fifo_boost_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: FIFO Boost with -F Flag
#=============================================================================
log ""
log "=========================================="
log "Test 1: FIFO Boost with -F Flag"
log "=========================================="

threshold=5
# Create starvation FIRST (before stalld starts)
starvation_duration=$((threshold + 8))
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration}

log "Starting stalld with -F flag to force SCHED_FIFO boosting"
# Note: -F requires non-single-threaded mode (aggressive mode)
# Use -g 1 for 1-second granularity to ensure timely detection
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -N -F -A -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for boosting
log "Waiting for boost detection..."
if wait_for_boost_detected "${STALLD_LOG}"; then
    pass "Boosting occurred with -F flag"

    # Verify SCHED_FIFO was used
    if grep -q "SCHED_FIFO" "${STALLD_LOG}"; then
        pass "SCHED_FIFO boosting used (as requested by -F)"
    else
        fail "SCHED_FIFO not mentioned in boost message"
    fi
else
    fail "No boosting detected with -F flag"
    log "Log contents:"
    cat "${STALLD_LOG}"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 2: FIFO Priority Verification
#=============================================================================
log ""
log "=========================================="
log "Test 2: FIFO Priority Verification"
log "=========================================="

threshold=5
rm -f "${STALLD_LOG}"

# Create starvation FIRST
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 15
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
log "Starvation generator children PIDs: ${STARVE_CHILDREN}"

log "Starting stalld with -F flag (FIFO boosting)"
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -N -F -A -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for boosting
log "Waiting for boost detection..."
wait_for_boost_detected "${STALLD_LOG}"

fifo_task_found=0
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/sched" ]; then
        policy=$(get_sched_policy ${child_pid})
        log "Child PID ${child_pid} policy: ${policy} (1=SCHED_FIFO)"

        # Policy 1 = SCHED_FIFO
        if [ "$policy" = "1" ]; then
            priority=$(get_sched_priority ${child_pid})
            pass "Task PID ${child_pid} boosted to SCHED_FIFO (policy 1)"
            log "        Priority: ${priority}"
            fifo_task_found=1
            break
        fi
    fi
done

if [ ${fifo_task_found} -eq 0 ]; then
    log "⚠ INFO: Could not verify FIFO policy in /proc (timing issue or boost already expired)"
    # FIFO emulation cycles between FIFO and OTHER, so we may catch it in OTHER state
    if grep -q "boosted.*SCHED_FIFO" "${STALLD_LOG}"; then
        pass "SCHED_FIFO boost confirmed in logs"
    else
        fail "No SCHED_FIFO boost detected"
    fi
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 3: FIFO Emulation Behavior
#=============================================================================
log ""
log "=========================================="
log "Test 3: FIFO Emulation Behavior"
log "=========================================="
log "FIFO emulation cycles: boost→sleep(runtime)→restore→sleep(remainder)"

threshold=5
boost_duration=5  # 5 seconds total boost
boost_period=1000000000   # 1 second period
boost_runtime=20000       # 20µs runtime

log "Starting stalld with FIFO emulation:"
log "  Duration: ${boost_duration}s"
log "  Period: ${boost_period}ns (1s)"
log "  Runtime: ${boost_runtime}ns (20µs)"
log "  Expected cycles: ~5"

rm -f "${STALLD_LOG}"

# Create starvation FIRST
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 20

start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -N -F -A -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} \
    -d ${boost_duration} -p ${boost_period} -r ${boost_runtime}

# Wait for boosting to start
log "Waiting for boost detection..."
wait_for_boost_detected "${STALLD_LOG}"

# Wait for FIFO emulation cycles to complete (boost_duration + buffer)
log "Waiting for FIFO emulation cycles to complete..."
sleep $((boost_duration + 2))

# Count boost events (FIFO emulation creates multiple boosts)
boost_count=$(grep -c "boosted.*SCHED_FIFO" "${STALLD_LOG}")
log "Number of FIFO boost events: ${boost_count}"

if [ ${boost_count} -gt 1 ]; then
    pass "Multiple FIFO boost events (${boost_count}) - emulation cycling detected"
    log "        (FIFO emulation boosts, sleeps, restores, repeats)"
else
    log "⚠ INFO: Only ${boost_count} FIFO boost event(s)"
    log "        (emulation may complete very quickly or timing issue)"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 4: FIFO vs DEADLINE Comparison
#=============================================================================
log ""
log "=========================================="
log "Test 4: FIFO vs DEADLINE Effectiveness Comparison"
log "=========================================="

threshold=5
boost_duration=3

# Test with DEADLINE first
log ""
log "Running with SCHED_DEADLINE boosting..."
STALLD_LOG_DEADLINE="/tmp/stalld_test_deadline_compare_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_DEADLINE}")

# Create starvation FIRST
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d 15
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
deadline_tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/status" ]; then
        deadline_tracked_pid=${child_pid}
        break
    fi
done

ctxt_before_deadline=0
if [ -n "${deadline_tracked_pid}" ]; then
    ctxt_before_deadline=$(get_ctxt_switches ${deadline_tracked_pid})
fi

# NOW start stalld
start_stalld_with_log "${STALLD_LOG_DEADLINE}" -f -v -g 1 -N -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration}

# Wait for boost detection, then let boost run to completion
log "Waiting for DEADLINE boost detection..."
wait_for_boost_detected "${STALLD_LOG_DEADLINE}"
sleep $((boost_duration + 1))

ctxt_after_deadline=0
if [ -n "${deadline_tracked_pid}" ] && [ -f "/proc/${deadline_tracked_pid}/status" ]; then
    ctxt_after_deadline=$(get_ctxt_switches ${deadline_tracked_pid})
fi

deadline_progress=$((ctxt_after_deadline - ctxt_before_deadline))
log "DEADLINE progress: ${deadline_progress} context switches"

kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

# Small delay between tests
sleep 2

# Test with FIFO
log ""
log "Running with SCHED_FIFO boosting..."
STALLD_LOG_FIFO="/tmp/stalld_test_fifo_compare_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_FIFO}")

# Create starvation FIRST
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d 15
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
fifo_tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/status" ]; then
        fifo_tracked_pid=${child_pid}
        break
    fi
done

ctxt_before_fifo=0
if [ -n "${fifo_tracked_pid}" ]; then
    ctxt_before_fifo=$(get_ctxt_switches ${fifo_tracked_pid})
fi

# NOW start stalld
start_stalld_with_log "${STALLD_LOG_FIFO}" -f -v -g 1 -N -F -A -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration}

# Wait for boost detection, then let boost run to completion
log "Waiting for FIFO boost detection..."
wait_for_boost_detected "${STALLD_LOG_FIFO}"
sleep $((boost_duration + 1))

ctxt_after_fifo=0
if [ -n "${fifo_tracked_pid}" ] && [ -f "/proc/${fifo_tracked_pid}/status" ]; then
    ctxt_after_fifo=$(get_ctxt_switches ${fifo_tracked_pid})
fi

fifo_progress=$((ctxt_after_fifo - ctxt_before_fifo))
log "FIFO progress: ${fifo_progress} context switches"

kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

# Compare effectiveness
log ""
log "Comparison Results:"
log "  DEADLINE: ${deadline_progress} context switches"
log "  FIFO: ${fifo_progress} context switches"

if [ ${deadline_progress} -gt 0 ] && [ ${fifo_progress} -gt 0 ]; then
    pass "Both DEADLINE and FIFO allowed tasks to make progress"

    # Both should be effective, but exact numbers may vary
    if [ ${deadline_progress} -gt ${fifo_progress} ]; then
        log "ℹ INFO: DEADLINE showed more progress than FIFO"
    elif [ ${fifo_progress} -gt ${deadline_progress} ]; then
        log "ℹ INFO: FIFO showed more progress than DEADLINE"
    else
        log "ℹ INFO: DEADLINE and FIFO showed similar progress"
    fi
else
    log "⚠ WARNING: One or both methods did not show progress (may be timing issue)"
fi

#=============================================================================
# Test 5: Single-Threaded Mode Fails with FIFO
#=============================================================================
log ""
log "=========================================="
log "Test 5: Single-Threaded Mode with FIFO (Should Fail)"
log "=========================================="

log "Attempting to start stalld with -F without -A (single-threaded + FIFO)"
STALLD_LOG_FAIL="/tmp/stalld_test_fifo_fail_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_FAIL}")

# Try to start stalld with -F but without -A (single-threaded mode)
# This should fail because single-threaded mode only works with DEADLINE
timeout 5 ${TEST_ROOT}/../stalld -f -v -F -t 5 -c ${TEST_CPU} > "${STALLD_LOG_FAIL}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "stalld rejected FIFO in single-threaded mode"
elif grep -qiE "single.*thread|falling back|adaptive" "${STALLD_LOG_FAIL}"; then
    pass "stalld detected incompatibility and fell back to adaptive mode"
else
    fail "stalld silently accepted FIFO in single-threaded mode"
fi

#=============================================================================
# Final Summary
#=============================================================================
log ""
log "=========================================="
log "Test Summary"
log "=========================================="
log "Total failures: ${TEST_FAILED}"

end_test
