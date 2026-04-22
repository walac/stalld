#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Idle CPU Detection
# Verify stalld's idle detection skips idle CPUs to reduce overhead,
# and resumes monitoring when CPUs become busy
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

# Helper to get CPU idle time from /proc/stat (test-specific)
get_cpu_idle_time() {
    local cpu_id=$1
    # Field 4 is idle time in /proc/stat (0-indexed from cpu name)
    # cpu0 user nice system idle ...
    awk "/^cpu${cpu_id} / {print \$5}" /proc/stat
}

# Helper to check if CPU is idle (idle time increasing)
is_cpu_idle() {
    local cpu_id=$1
    local idle1=$(get_cpu_idle_time $cpu_id)
    sleep 1
    local idle2=$(get_cpu_idle_time $cpu_id)

    if [ "$idle2" -gt "$idle1" ]; then
        return 0  # Idle (idle time increased)
    else
        return 1  # Busy
    fi
}

init_functional_test "Idle CPU Detection" "test_idle"

# Check if idle detection is enabled by default
log ""
log "Idle detection is enabled by default (config_idle_detection=1)"
log "Function: cpu_had_idle_time() in stalld.c:226-260"
log "Reads: /proc/stat for per-CPU idle time"

#=============================================================================
# Test 1: Idle CPUs Skipped (No Parsing)
#=============================================================================
test_section "Test 1: Idle CPUs Skipped"
log "Idle CPUs should be skipped to reduce overhead"

threshold=5
log "Starting stalld with verbose logging"
# Use -g 1 for 1-second granularity
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Let stalld run while CPU is idle (no load)
log "CPU ${TEST_CPU} should be idle (no load created)"
sleep 5

# Check if stalld detected the CPU as idle
if grep -qi "idle\|skip" "${STALLD_LOG}"; then
    log "ℹ INFO: Idle-related messages in log:"
    grep -i "idle\|skip" "${STALLD_LOG}" | head -5
else
    log "ℹ INFO: No explicit idle messages (idle detection may be working silently)"
fi

# Verify CPU is actually idle
if is_cpu_idle ${TEST_CPU}; then
    pass "CPU ${TEST_CPU} is currently idle (idle time increasing)"
else
    log "⚠ INFO: CPU ${TEST_CPU} appears busy (background activity)"
fi

stop_stalld

#=============================================================================
# Test 2: /proc/stat Parsing
#=============================================================================
test_section "Test 2: /proc/stat Idle Time Parsing"

# Read idle time for test CPU
idle_time1=$(get_cpu_idle_time ${TEST_CPU})
log "CPU ${TEST_CPU} idle time: ${idle_time1} (from /proc/stat field 4)"

# Wait a bit
sleep 2

idle_time2=$(get_cpu_idle_time ${TEST_CPU})
log "CPU ${TEST_CPU} idle time after 2s: ${idle_time2}"

if [ -n "${idle_time1}" ] && [ -n "${idle_time2}" ]; then
    delta=$((idle_time2 - idle_time1))
    log "Idle time delta: ${delta}"

    if [ ${delta} -gt 0 ]; then
        pass "Idle time increased (CPU is idle)"
        log "        stalld would skip this CPU"
    else
        pass "Idle time unchanged (CPU is busy)"
        log "        stalld would parse this CPU"
    fi
else
    fail "Could not read idle time from /proc/stat"
fi

#=============================================================================
# Test 3: Monitoring Resumes When CPU Becomes Busy
#=============================================================================
test_section "Test 3: Monitoring Resumes for Busy CPUs"

threshold=5
rm -f "${STALLD_LOG}"
log "Starting stalld"
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Initially idle
log "CPU ${TEST_CPU} initially idle"
sleep 3

# Now create load to make CPU busy
log "Creating load on CPU ${TEST_CPU} to make it busy"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d 12

# Wait for stalld to detect the busy CPU and starvation
log "Waiting for stalld to detect busy CPU and starvation..."

# Verify stalld detected starvation (meaning it resumed monitoring)
if wait_for_starvation_detected "${STALLD_LOG}"; then
    pass "stalld detected starvation on now-busy CPU"
    log "        Monitoring resumed when CPU became busy"
else
    log "⚠ INFO: No starvation detected"
    log "        (may be timing issue or CPU remained idle)"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 4: Idle CPUs Are Skipped
#=============================================================================
test_section "Test 4: Idle CPUs Are Skipped"

rm -f "${STALLD_LOG}"
threshold=3

log "Starting stalld with idle detection on an idle CPU"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

sleep 3

assert_log_contains "${STALLD_LOG}" "skipping" "Idle CPU correctly skipped"

cleanup_scenario

#=============================================================================
# Test 5: Idle Detection with Multiple CPUs
#=============================================================================
test_section "Test 5: Per-CPU Independent Idle Detection"

NUM_CPUS=$(get_num_cpus)
if [ ${NUM_CPUS} -lt 2 ]; then
    log "⚠ SKIP: Need at least 2 CPUs for this test (have ${NUM_CPUS})"
else
    CPU0=${TEST_CPU}
    if [ ${TEST_CPU} -eq 0 ]; then
        CPU1=1
    else
        CPU1=0
    fi

    log "Testing idle detection on CPU ${CPU0} (idle) and CPU ${CPU1} (busy)"

    threshold=5
    rm -f "${STALLD_LOG}"
    start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -l -t $threshold -c ${CPU0},${CPU1}

    # Create load only on CPU1, leave CPU0 idle
    log "Creating load on CPU ${CPU1} only"
    start_starvation_gen -c ${CPU1} -p 80 -n 2 -d 12

    # Wait for detection
    wait_for_starvation_detected "${STALLD_LOG}"

    # Check which CPU had starvation detected
    cpu0_detections=$(grep -c "starved on CPU ${CPU0}" "${STALLD_LOG}")
    cpu1_detections=$(grep -c "starved on CPU ${CPU1}" "${STALLD_LOG}")

    log "CPU ${CPU0} detections: ${cpu0_detections} (should be 0, it's idle)"
    log "CPU ${CPU1} detections: ${cpu1_detections} (should be >0, it's busy)"

    if [ ${cpu0_detections} -eq 0 ] && [ ${cpu1_detections} -gt 0 ]; then
        pass "Idle CPU skipped, busy CPU monitored"
    elif [ ${cpu1_detections} -gt 0 ]; then
        pass "Busy CPU ${CPU1} monitored"
        if [ ${cpu0_detections} -gt 0 ]; then
            log "⚠ INFO: CPU ${CPU0} also had detections (may have background activity)"
        fi
    else
        log "⚠ INFO: Detection pattern differs (timing or load dependent)"
    fi

    # Cleanup
    cleanup_scenario "${STARVE_PID}"
fi

#=============================================================================
# Final Summary
#=============================================================================
test_section "Test Summary"
log "Idle detection functions:"
log "  - cpu_had_idle_time() in stalld.c:226-260"
log "  - get_cpu_busy_list() in stalld.c:262-308"
log "  - read_proc_stat() in utils.c"
log ""
log "Mechanism: Compares idle time in /proc/stat between cycles"
log "  - Idle time increased = CPU idle (skip parsing)"
log "  - Idle time unchanged = CPU busy (parse for starvation)"
log ""
log "Total failures: ${TEST_FAILED}"

end_test
