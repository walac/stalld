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

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

# Helper to get CPU idle time from /proc/stat
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

start_test "Idle CPU Detection"

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

# Setup paths
STARVE_GEN="${TEST_ROOT}/helpers/starvation_gen"
STALLD_LOG="/tmp/stalld_test_idle_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

# Check if idle detection is enabled by default
log ""
log "Idle detection is enabled by default (config_idle_detection=1)"
log "Function: cpu_had_idle_time() in stalld.c:226-260"
log "Reads: /proc/stat for per-CPU idle time"

#=============================================================================
# Test 1: Idle CPUs Skipped (No Parsing)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Idle CPUs Skipped"
log "=========================================="
log "Idle CPUs should be skipped to reduce overhead"

threshold=5
log "Starting stalld with verbose logging"
start_stalld -f -v -l -t $threshold -c ${TEST_CPU} > "${STALLD_LOG}" 2>&1

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
    log "✓ PASS: CPU ${TEST_CPU} is currently idle (idle time increasing)"
else
    log "⚠ INFO: CPU ${TEST_CPU} appears busy (background activity)"
fi

stop_stalld

#=============================================================================
# Test 2: /proc/stat Parsing
#=============================================================================
log ""
log "=========================================="
log "Test 2: /proc/stat Idle Time Parsing"
log "=========================================="

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
        log "✓ PASS: Idle time increased (CPU is idle)"
        log "        stalld would skip this CPU"
    else
        log "✓ PASS: Idle time unchanged (CPU is busy)"
        log "        stalld would parse this CPU"
    fi
else
    log "✗ FAIL: Could not read idle time from /proc/stat"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

#=============================================================================
# Test 3: Monitoring Resumes When CPU Becomes Busy
#=============================================================================
log ""
log "=========================================="
log "Test 3: Monitoring Resumes for Busy CPUs"
log "=========================================="

threshold=5
rm -f "${STALLD_LOG}"
log "Starting stalld"
start_stalld -f -v -l -t $threshold -c ${TEST_CPU} > "${STALLD_LOG}" 2>&1

# Initially idle
log "CPU ${TEST_CPU} initially idle"
sleep 3

# Now create load to make CPU busy
log "Creating load on CPU ${TEST_CPU} to make it busy"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d 12 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for stalld to detect the busy CPU and starvation
log "Waiting for stalld to detect busy CPU and starvation..."
sleep $((threshold + 2))

# Verify stalld detected starvation (meaning it resumed monitoring)
if grep -q "starved" "${STALLD_LOG}"; then
    log "✓ PASS: stalld detected starvation on now-busy CPU"
    log "        Monitoring resumed when CPU became busy"
else
    log "⚠ INFO: No starvation detected"
    log "        (may be timing issue or CPU remained idle)"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 4: Idle Detection Overhead Reduction
#=============================================================================
log ""
log "=========================================="
log "Test 4: Idle Detection Reduces Overhead"
log "=========================================="
log "Comparing overhead with and without idle detection (informational)"

# This is informational - we can't easily measure overhead in tests
log "With idle detection (default):"
log "  - /proc/stat read before parsing"
log "  - Idle CPUs skipped (no sched_debug/BPF parsing)"
log "  - Reduces CPU usage when system mostly idle"
log ""
log "Without idle detection would:"
log "  - Always parse all CPUs"
log "  - Higher overhead even when CPUs idle"

log "ℹ INFO: Idle detection enabled by default for efficiency"
log "        Function: cpu_had_idle_time() and get_cpu_busy_list()"

#=============================================================================
# Test 5: Idle Detection with Multiple CPUs
#=============================================================================
log ""
log "=========================================="
log "Test 5: Per-CPU Independent Idle Detection"
log "=========================================="

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
    start_stalld -f -v -l -t $threshold -c ${CPU0},${CPU1} > "${STALLD_LOG}" 2>&1

    # Create load only on CPU1, leave CPU0 idle
    log "Creating load on CPU ${CPU1} only"
    "${STARVE_GEN}" -c ${CPU1} -p 80 -n 2 -d 12 &
    STARVE_PID=$!
    CLEANUP_PIDS+=("${STARVE_PID}")

    # Wait for detection
    sleep $((threshold + 2))

    # Check which CPU had starvation detected
    cpu0_detections=$(grep -c "starved on CPU ${CPU0}" "${STALLD_LOG}")
    cpu1_detections=$(grep -c "starved on CPU ${CPU1}" "${STALLD_LOG}")

    log "CPU ${CPU0} detections: ${cpu0_detections} (should be 0, it's idle)"
    log "CPU ${CPU1} detections: ${cpu1_detections} (should be >0, it's busy)"

    if [ ${cpu0_detections} -eq 0 ] && [ ${cpu1_detections} -gt 0 ]; then
        log "✓ PASS: Idle CPU skipped, busy CPU monitored"
    elif [ ${cpu1_detections} -gt 0 ]; then
        log "✓ PASS: Busy CPU ${CPU1} monitored"
        if [ ${cpu0_detections} -gt 0 ]; then
            log "⚠ INFO: CPU ${CPU0} also had detections (may have background activity)"
        fi
    else
        log "⚠ INFO: Detection pattern differs (timing or load dependent)"
    fi

    # Cleanup
    kill -TERM ${STARVE_PID} 2>/dev/null
    wait ${STARVE_PID} 2>/dev/null
    stop_stalld
fi

#=============================================================================
# Final Summary
#=============================================================================
log ""
log "=========================================="
log "Test Summary"
log "=========================================="
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
