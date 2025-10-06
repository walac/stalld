#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Runqueue Parsing - Backend Task Extraction
# Verify both eBPF and sched_debug backends correctly extract task information
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

# Helper to check if a backend is available
backend_available() {
    local backend=$1
    ./stalld -b "$backend" -h >/dev/null 2>&1
    return $?
}

# Helper to extract task info from stalld verbose log
# Returns count of detected tasks
count_detected_tasks() {
    local log_file=$1
    grep -c "starved on CPU" "$log_file" 2>/dev/null || echo "0"
}

start_test "Runqueue Parsing - Backend Task Extraction"

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
STALLD_LOG_BPF="/tmp/stalld_test_parse_bpf_$$.log"
STALLD_LOG_SCHED="/tmp/stalld_test_parse_sched_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_BPF}" "${STALLD_LOG_SCHED}")

# Check which backends are available
BPF_AVAILABLE=0
SCHED_DEBUG_AVAILABLE=0

if backend_available "queue_track"; then
    BPF_AVAILABLE=1
    log "✓ eBPF (queue_track) backend available"
else
    log "⚠ eBPF (queue_track) backend not available"
fi

if backend_available "sched_debug"; then
    SCHED_DEBUG_AVAILABLE=1
    log "✓ sched_debug backend available"
else
    log "⚠ sched_debug backend not available"
fi

if [ ${BPF_AVAILABLE} -eq 0 ] && [ ${SCHED_DEBUG_AVAILABLE} -eq 0 ]; then
    echo -e "${YELLOW}SKIP: No backends available for testing${NC}"
    exit 77
fi

#=============================================================================
# Test 1: eBPF Backend Task Extraction
#=============================================================================
if [ ${BPF_AVAILABLE} -eq 1 ]; then
    log ""
    log "=========================================="
    log "Test 1: eBPF Backend Task Extraction"
    log "=========================================="

    threshold=5
    log "Starting stalld with eBPF backend (queue_track)"
    start_stalld -f -v -l -b queue_track -t $threshold -c ${TEST_CPU} > "${STALLD_LOG_BPF}" 2>&1

    # Create starvation to generate task data
    starvation_duration=$((threshold + 5))
    log "Creating starvation for ${starvation_duration}s"
    "${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
    STARVE_PID=$!
    CLEANUP_PIDS+=("${STARVE_PID}")

    # Wait for detection
    sleep $((threshold + 2))

    # Verify eBPF backend detected starvation
    if grep -q "starved on CPU" "${STALLD_LOG_BPF}"; then
        log "✓ PASS: eBPF backend detected starving tasks"

        # Verify task info is present (PID, comm)
        if grep -E "starvation_gen.*starved on CPU ${TEST_CPU}" "${STALLD_LOG_BPF}"; then
            log "✓ PASS: Task name (comm) correctly extracted"
        else
            log "✗ FAIL: Task name not found in eBPF backend output"
            TEST_FAILED=$((TEST_FAILED + 1))
        fi

        # Verify PID is logged
        if grep -E "\[[0-9]+\].*starved on CPU" "${STALLD_LOG_BPF}"; then
            log "✓ PASS: Task PID correctly extracted"
        else
            log "⚠ INFO: PID format may have changed"
        fi
    else
        log "✗ FAIL: eBPF backend did not detect starvation"
        log "Log contents:"
        cat "${STALLD_LOG_BPF}"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Cleanup
    kill -TERM ${STARVE_PID} 2>/dev/null
    wait ${STARVE_PID} 2>/dev/null
    stop_stalld
else
    log ""
    log "=========================================="
    log "Test 1: eBPF Backend - SKIPPED"
    log "=========================================="
    log "eBPF backend not available on this system"
fi

#=============================================================================
# Test 2: sched_debug Backend Task Extraction
#=============================================================================
if [ ${SCHED_DEBUG_AVAILABLE} -eq 1 ]; then
    log ""
    log "=========================================="
    log "Test 2: sched_debug Backend Task Extraction"
    log "=========================================="

    threshold=5
    log "Starting stalld with sched_debug backend"
    start_stalld -f -v -l -b sched_debug -t $threshold -c ${TEST_CPU} > "${STALLD_LOG_SCHED}" 2>&1

    # Create starvation
    starvation_duration=$((threshold + 5))
    log "Creating starvation for ${starvation_duration}s"
    "${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
    STARVE_PID=$!
    CLEANUP_PIDS+=("${STARVE_PID}")

    # Wait for detection
    sleep $((threshold + 2))

    # Verify sched_debug backend detected starvation
    if grep -q "starved on CPU" "${STALLD_LOG_SCHED}"; then
        log "✓ PASS: sched_debug backend detected starving tasks"

        # Verify task info is present
        if grep -E "starvation_gen.*starved on CPU ${TEST_CPU}" "${STALLD_LOG_SCHED}"; then
            log "✓ PASS: Task name (comm) correctly extracted"
        else
            log "✗ FAIL: Task name not found in sched_debug backend output"
            TEST_FAILED=$((TEST_FAILED + 1))
        fi

        # Verify PID is logged
        if grep -E "\[[0-9]+\].*starved on CPU" "${STALLD_LOG_SCHED}"; then
            log "✓ PASS: Task PID correctly extracted"
        else
            log "⚠ INFO: PID format may have changed"
        fi

        # Check for format detection message
        if grep -q "task_format.*detected" "${STALLD_LOG_SCHED}"; then
            format=$(grep "task_format.*detected" "${STALLD_LOG_SCHED}" | tail -1)
            log "ℹ INFO: Kernel format detected: $format"
        fi
    else
        log "✗ FAIL: sched_debug backend did not detect starvation"
        log "Log contents:"
        cat "${STALLD_LOG_SCHED}"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Cleanup
    kill -TERM ${STARVE_PID} 2>/dev/null
    wait ${STARVE_PID} 2>/dev/null
    stop_stalld
else
    log ""
    log "=========================================="
    log "Test 2: sched_debug Backend - SKIPPED"
    log "=========================================="
    log "sched_debug backend not available on this system"
fi

#=============================================================================
# Test 3: Backend Comparison (Both Should Detect Same Starvation)
#=============================================================================
if [ ${BPF_AVAILABLE} -eq 1 ] && [ ${SCHED_DEBUG_AVAILABLE} -eq 1 ]; then
    log ""
    log "=========================================="
    log "Test 3: Backend Comparison"
    log "=========================================="
    log "Testing that both backends detect the same starvation condition"

    threshold=5
    starvation_duration=$((threshold + 5))

    # Test with eBPF backend
    log ""
    log "Running with eBPF backend..."
    rm -f "${STALLD_LOG_BPF}"
    start_stalld -f -v -l -b queue_track -t $threshold -c ${TEST_CPU} > "${STALLD_LOG_BPF}" 2>&1

    "${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
    STARVE_PID=$!
    CLEANUP_PIDS+=("${STARVE_PID}")

    sleep $((threshold + 2))
    bpf_detections=$(count_detected_tasks "${STALLD_LOG_BPF}")
    log "eBPF backend detected: ${bpf_detections} starvation events"

    kill -TERM ${STARVE_PID} 2>/dev/null
    wait ${STARVE_PID} 2>/dev/null
    stop_stalld

    # Small delay between tests
    sleep 2

    # Test with sched_debug backend
    log ""
    log "Running with sched_debug backend..."
    rm -f "${STALLD_LOG_SCHED}"
    start_stalld -f -v -l -b sched_debug -t $threshold -c ${TEST_CPU} > "${STALLD_LOG_SCHED}" 2>&1

    "${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
    STARVE_PID=$!
    CLEANUP_PIDS+=("${STARVE_PID}")

    sleep $((threshold + 2))
    sched_detections=$(count_detected_tasks "${STALLD_LOG_SCHED}")
    log "sched_debug backend detected: ${sched_detections} starvation events"

    kill -TERM ${STARVE_PID} 2>/dev/null
    wait ${STARVE_PID} 2>/dev/null
    stop_stalld

    # Compare results
    log ""
    if [ ${bpf_detections} -gt 0 ] && [ ${sched_detections} -gt 0 ]; then
        log "✓ PASS: Both backends detected starvation"

        # Check if detection counts are similar (within reasonable variance)
        diff=$((bpf_detections - sched_detections))
        diff=${diff#-}  # absolute value

        if [ ${diff} -le 2 ]; then
            log "✓ PASS: Detection counts are consistent (eBPF: ${bpf_detections}, sched_debug: ${sched_detections})"
        else
            log "⚠ INFO: Detection counts differ (eBPF: ${bpf_detections}, sched_debug: ${sched_detections})"
            log "        This may be due to timing differences between backends"
        fi
    else
        log "✗ FAIL: One or both backends failed to detect starvation"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log ""
    log "=========================================="
    log "Test 3: Backend Comparison - SKIPPED"
    log "=========================================="
    log "Both backends required for comparison test"
fi

#=============================================================================
# Test 4: Verify Task Field Extraction (PID, comm, priority, switches)
#=============================================================================
log ""
log "=========================================="
log "Test 4: Task Field Extraction Verification"
log "=========================================="

# Use whichever backend is available
if [ ${BPF_AVAILABLE} -eq 1 ]; then
    test_backend="queue_track"
    log_file="${STALLD_LOG_BPF}"
elif [ ${SCHED_DEBUG_AVAILABLE} -eq 1 ]; then
    test_backend="sched_debug"
    log_file="${STALLD_LOG_SCHED}"
else
    log "SKIP: No backend available"
    test_backend=""
fi

if [ -n "$test_backend" ]; then
    threshold=5
    log "Testing task field extraction with ${test_backend} backend"

    rm -f "${log_file}"
    start_stalld -f -v -l -b ${test_backend} -t $threshold -c ${TEST_CPU} > "${log_file}" 2>&1

    # Create starvation with known parameters
    log "Creating starvation with known task name (starvation_gen)"
    "${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 10 -v &
    STARVE_PID=$!
    CLEANUP_PIDS+=("${STARVE_PID}")

    # Wait for detection
    sleep $((threshold + 2))

    # Verify fields are present
    log ""
    log "Verifying extracted fields in log:"

    # Check for task name (comm field)
    if grep -q "starvation_gen" "${log_file}"; then
        log "✓ PASS: Task name (comm) field extracted"
    else
        log "✗ FAIL: Task name (comm) field not found"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Check for PID field (format: name-PID or [PID])
    if grep -qE "(starvation_gen-[0-9]+|\[[0-9]+\])" "${log_file}"; then
        log "✓ PASS: PID field extracted"
    else
        log "✗ FAIL: PID field not found"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Check for CPU ID
    if grep -q "CPU ${TEST_CPU}" "${log_file}"; then
        log "✓ PASS: CPU ID field extracted"
    else
        log "✗ FAIL: CPU ID field not found"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Check for starvation duration
    if grep -qE "for [0-9]+ seconds" "${log_file}"; then
        log "✓ PASS: Starvation duration calculated from context switches/time"
    else
        log "✗ FAIL: Starvation duration not found"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Cleanup
    kill -TERM ${STARVE_PID} 2>/dev/null
    wait ${STARVE_PID} 2>/dev/null
    stop_stalld
fi

#=============================================================================
# Test 5: Kernel Format Handling (sched_debug backend)
#=============================================================================
if [ ${SCHED_DEBUG_AVAILABLE} -eq 1 ]; then
    log ""
    log "=========================================="
    log "Test 5: Kernel Format Detection (sched_debug)"
    log "=========================================="

    threshold=5
    rm -f "${STALLD_LOG_SCHED}"
    start_stalld -f -v -l -b sched_debug -t $threshold -c ${TEST_CPU} > "${STALLD_LOG_SCHED}" 2>&1

    # Create brief starvation just to initialize the backend
    "${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 8 &
    STARVE_PID=$!
    CLEANUP_PIDS+=("${STARVE_PID}")

    sleep $((threshold + 2))

    # Check for format detection messages
    if grep -q "detect_task_format" "${STALLD_LOG_SCHED}"; then
        detected_format=$(grep "detect_task_format" "${STALLD_LOG_SCHED}" | grep "detected" | tail -1)
        log "✓ PASS: Kernel format auto-detection occurred"
        log "ℹ INFO: ${detected_format}"

        # Check if field offsets were detected
        if grep -q "found 'task' at word" "${STALLD_LOG_SCHED}"; then
            log "✓ PASS: Task field offset detected"
        fi
        if grep -q "found 'PID' at word" "${STALLD_LOG_SCHED}"; then
            log "✓ PASS: PID field offset detected"
        fi
        if grep -q "found 'switches' at word" "${STALLD_LOG_SCHED}"; then
            log "✓ PASS: Switches field offset detected"
        fi
        if grep -q "found 'prio' at word" "${STALLD_LOG_SCHED}"; then
            log "✓ PASS: Priority field offset detected"
        fi
    else
        log "⚠ INFO: Format detection messages not in log (may not be verbose enough)"
    fi

    # Verify the backend still works despite format
    if grep -q "starved on CPU" "${STALLD_LOG_SCHED}"; then
        log "✓ PASS: Backend successfully parsed tasks despite kernel format"
    else
        log "⚠ INFO: No starvation detected in this test run"
    fi

    # Cleanup
    kill -TERM ${STARVE_PID} 2>/dev/null
    wait ${STARVE_PID} 2>/dev/null
    stop_stalld
else
    log ""
    log "=========================================="
    log "Test 5: Kernel Format Detection - SKIPPED"
    log "=========================================="
    log "sched_debug backend required for format detection tests"
fi

#=============================================================================
# Final Summary
#=============================================================================
log ""
log "=========================================="
log "Test Summary"
log "=========================================="
log "Backends tested:"
[ ${BPF_AVAILABLE} -eq 1 ] && log "  - eBPF (queue_track): available"
[ ${SCHED_DEBUG_AVAILABLE} -eq 1 ] && log "  - sched_debug: available"
log ""
log "Total failures: ${TEST_FAILED}"

end_test
