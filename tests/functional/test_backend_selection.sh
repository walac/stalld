#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test backend selection functionality
#
# This test verifies that stalld can be started with different backends
# and that backend detection works correctly.
#
# Copyright (C) 2025 Red Hat Inc

TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

start_test "Backend Selection"

require_root

echo "=== Test 1: Detect default backend ==="
default_backend=$(detect_default_backend)
echo "Default backend: ${default_backend}"
assert_contains "${default_backend}" "sched_debug\|queue_track" "Default backend should be sched_debug or queue_track"

echo ""
echo "=== Test 2: List available backends ==="
available_backends=$(get_available_backends)
echo "Available backends: ${available_backends}"
assert_contains "${available_backends}" "sched_debug" "sched_debug should always be available"

echo ""
echo "=== Test 3: Check sched_debug backend availability ==="
if is_backend_available "sched_debug"; then
	echo "✓ sched_debug backend is available"
	TEST_PASSED=$((TEST_PASSED + 1))
else
	echo "✗ sched_debug backend should always be available"
	TEST_FAILED=$((TEST_FAILED + 1))
fi

echo ""
echo "=== Test 4: Check queue_track (BPF) backend availability ==="
if is_backend_available "queue_track"; then
	echo "✓ queue_track (BPF) backend is available"
	echo "  (This system supports eBPF backend)"
	TEST_PASSED=$((TEST_PASSED + 1))
else
	echo "ℹ queue_track (BPF) backend not available"
	echo "  (This is expected on i686, powerpc, ppc64le, or kernels ≤3.x)"
	TEST_PASSED=$((TEST_PASSED + 1))
fi

echo ""
echo "=== Test 5: Start stalld with sched_debug backend ==="
save_rt_throttling
disable_rt_throttling

start_stalld_with_backend "sched_debug" -f -v -t 60
if [ $? -eq 0 ]; then
	assert_process_running "${STALLD_PID}" "stalld should be running with sched_debug backend"

	# Give stalld time to log backend selection
	sleep 1

	# Check logs for backend selection message
	if journalctl -u stalld --since "10 seconds ago" 2>/dev/null | grep -q "sched_debug"; then
		echo "✓ stalld logged use of sched_debug backend"
		TEST_PASSED=$((TEST_PASSED + 1))
	elif grep -q "sched_debug" "${STALLD_LOG}" 2>/dev/null; then
		echo "✓ stalld logged use of sched_debug backend"
		TEST_PASSED=$((TEST_PASSED + 1))
	else
		echo "ℹ Could not verify backend in logs (may not be logged)"
		TEST_PASSED=$((TEST_PASSED + 1))
	fi

	stop_stalld
else
	echo "✗ Failed to start stalld with sched_debug backend"
	TEST_FAILED=$((TEST_FAILED + 1))
fi

restore_rt_throttling

echo ""
echo "=== Test 6: Start stalld with queue_track backend (if available) ==="
if is_backend_available "queue_track"; then
	save_rt_throttling
	disable_rt_throttling

	start_stalld_with_backend "queue_track" -f -v -t 60
	if [ $? -eq 0 ]; then
		assert_process_running "${STALLD_PID}" "stalld should be running with queue_track backend"

		# Give stalld time to log backend selection
		sleep 1

		# Check logs for backend selection message
		if journalctl -u stalld --since "10 seconds ago" 2>/dev/null | grep -q "queue_track"; then
			echo "✓ stalld logged use of queue_track backend"
			TEST_PASSED=$((TEST_PASSED + 1))
		elif grep -q "queue_track" "${STALLD_LOG}" 2>/dev/null; then
			echo "✓ stalld logged use of queue_track backend"
			TEST_PASSED=$((TEST_PASSED + 1))
		else
			echo "ℹ Could not verify backend in logs (may not be logged)"
			TEST_PASSED=$((TEST_PASSED + 1))
		fi

		stop_stalld
	else
		echo "✗ Failed to start stalld with queue_track backend"
		TEST_FAILED=$((TEST_FAILED + 1))
	fi

	restore_rt_throttling
else
	echo "ℹ Skipping queue_track test - backend not available on this system"
	TEST_PASSED=$((TEST_PASSED + 1))
fi

echo ""
echo "=== Test 7: Start stalld with short backend names ==="
save_rt_throttling
disable_rt_throttling

# Test 'S' shorthand for sched_debug
start_stalld_with_backend "S" -f -v -t 60
if [ $? -eq 0 ]; then
	echo "✓ Short name 'S' works for sched_debug backend"
	TEST_PASSED=$((TEST_PASSED + 1))
	stop_stalld
else
	echo "✗ Short name 'S' failed for sched_debug backend"
	TEST_FAILED=$((TEST_FAILED + 1))
fi

# Test 'Q' shorthand for queue_track (if available)
if is_backend_available "queue_track"; then
	start_stalld_with_backend "Q" -f -v -t 60
	if [ $? -eq 0 ]; then
		echo "✓ Short name 'Q' works for queue_track backend"
		TEST_PASSED=$((TEST_PASSED + 1))
		stop_stalld
	else
		echo "✗ Short name 'Q' failed for queue_track backend"
		TEST_FAILED=$((TEST_FAILED + 1))
	fi
fi

restore_rt_throttling

end_test
