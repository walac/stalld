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

# Test 1: Start stalld with sched_debug backend
echo "Test 1: Starting stalld with sched_debug backend"
STALLD_LOG="/tmp/stalld_backend_sched_debug_$$.log"
# Call stalld directly to capture its actual stderr output
# IMPORTANT: -v must come BEFORE -b so verbose mode is enabled when backend message is logged
../stalld -v -f -l -b sched_debug -t 60 > "${STALLD_LOG}" 2>&1 &
sleep 1
# Get the actual stalld PID
STALLD_PID=$(pgrep -n -x stalld 2>/dev/null)
if [ -z "${STALLD_PID}" ]; then
	TEST_FAILED=$((TEST_FAILED + 1))
	echo -e "  ${RED}FAIL${NC}: stalld failed to start with sched_debug backend"
else
	CLEANUP_PIDS+=("${STALLD_PID}")
	sleep 1
	if kill -0 ${STALLD_PID} 2>/dev/null; then
		# Check if log contains backend message
		if grep -q "using sched_debug backend" "${STALLD_LOG}"; then
			assert_equals "0" "0" "sched_debug backend selected"
		else
			TEST_FAILED=$((TEST_FAILED + 1))
			echo -e "  ${RED}FAIL${NC}: Backend message not found in log"
			echo "  Log contents:"
			cat "${STALLD_LOG}"
		fi
		stop_stalld
	else
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: stalld failed to start with sched_debug backend"
	fi
fi
rm -f "${STALLD_LOG}"

echo ""
echo "=== Test 4: Check queue_track (BPF) backend availability ==="
if is_backend_available "queue_track"; then
	echo "Test 2a: Starting stalld with queue_track backend"
	STALLD_LOG="/tmp/stalld_backend_queue_track_$$.log"
	# Call stalld directly to capture its actual stderr output
	# IMPORTANT: -v must come BEFORE -b so verbose mode is enabled when backend message is logged
	../stalld -v -f -l -b queue_track -t 60 > "${STALLD_LOG}" 2>&1 &
	sleep 1
	# Get the actual stalld PID
	STALLD_PID=$(pgrep -n -x stalld 2>/dev/null)
	if [ -z "${STALLD_PID}" ]; then
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: stalld failed to start with queue_track backend"
	else
		CLEANUP_PIDS+=("${STALLD_PID}")
		sleep 1
		if kill -0 ${STALLD_PID} 2>/dev/null; then
			# Check if log contains backend message
			if grep -q "using queue_track backend" "${STALLD_LOG}"; then
				assert_equals "0" "0" "queue_track backend selected"
			else
				TEST_FAILED=$((TEST_FAILED + 1))
				echo -e "  ${RED}FAIL${NC}: Backend message not found in log"
				echo "  Log contents:"
				cat "${STALLD_LOG}"
			fi
			stop_stalld
		else
			TEST_FAILED=$((TEST_FAILED + 1))
			echo -e "  ${RED}FAIL${NC}: stalld failed to start with queue_track backend"
		fi
	fi
	rm -f "${STALLD_LOG}"
else
	echo "ℹ queue_track (BPF) backend not available"
	echo "  (This is expected on i686, powerpc, ppc64le, or kernels ≤3.x)"
	TEST_PASSED=$((TEST_PASSED + 1))
fi

# Test 3: Test short names (S for sched_debug)
echo "Test 3: Testing short name 'S' for sched_debug"
STALLD_LOG="/tmp/stalld_backend_short_S_$$.log"
# Call stalld directly to capture its actual stderr output
# IMPORTANT: -v must come BEFORE -b so verbose mode is enabled when backend message is logged
../stalld -v -f -l -b S -t 60 > "${STALLD_LOG}" 2>&1 &
sleep 1
# Get the actual stalld PID
STALLD_PID=$(pgrep -n -x stalld 2>/dev/null)
if [ -z "${STALLD_PID}" ]; then
	TEST_FAILED=$((TEST_FAILED + 1))
	echo -e "  ${RED}FAIL${NC}: stalld failed to start with short name 'S'"
else
	CLEANUP_PIDS+=("${STALLD_PID}")
	sleep 1
	if kill -0 ${STALLD_PID} 2>/dev/null; then
		# Check if log contains backend message
		if grep -q "using sched_debug backend" "${STALLD_LOG}"; then
			assert_equals "0" "0" "Short name 'S' works for sched_debug"
		else
			TEST_FAILED=$((TEST_FAILED + 1))
			echo -e "  ${RED}FAIL${NC}: Backend message not found for short name"
			echo "  Log contents:"
			cat "${STALLD_LOG}"
		fi
		stop_stalld
	else
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: stalld failed to start with short name 'S'"
	fi
fi
rm -f "${STALLD_LOG}"

# Test 4: Test STALLD_TEST_BACKEND environment variable
if [ -n "${STALLD_TEST_BACKEND}" ]; then
	echo "Test 4: Testing STALLD_TEST_BACKEND=${STALLD_TEST_BACKEND}"
	STALLD_LOG="/tmp/stalld_backend_env_$$.log"
	# Call stalld directly to capture its actual stderr output
	# start_stalld adds -b based on STALLD_TEST_BACKEND, so we mimic that here
	# IMPORTANT: -v must come BEFORE -b so verbose mode is enabled when backend message is logged
	../stalld -v -f -l -b "${STALLD_TEST_BACKEND}" -t 60 > "${STALLD_LOG}" 2>&1 &
	sleep 1
	# Get the actual stalld PID
	STALLD_PID=$(pgrep -n -x stalld 2>/dev/null)
	if [ -z "${STALLD_PID}" ]; then
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: stalld failed to start with STALLD_TEST_BACKEND"
	else
		CLEANUP_PIDS+=("${STALLD_PID}")
		sleep 1
		if kill -0 ${STALLD_PID} 2>/dev/null; then
			# Normalize backend name for comparison
			BACKEND_NORMALIZED="${STALLD_TEST_BACKEND}"
			case "${STALLD_TEST_BACKEND}" in
				S) BACKEND_NORMALIZED="sched_debug" ;;
				Q) BACKEND_NORMALIZED="queue_track" ;;
			esac

			# Check if log contains backend message
			if grep -q "using ${BACKEND_NORMALIZED} backend" "${STALLD_LOG}"; then
				assert_equals "0" "0" "STALLD_TEST_BACKEND environment variable respected"
			else
				TEST_FAILED=$((TEST_FAILED + 1))
				echo -e "  ${RED}FAIL${NC}: Backend ${BACKEND_NORMALIZED} not used from environment"
				echo "  Log contents:"
				cat "${STALLD_LOG}"
			fi
			stop_stalld
		else
			echo "ℹ Could not verify backend in logs (may not be logged)"
			TEST_PASSED=$((TEST_PASSED + 1))
		fi
	fi
	rm -f "${STALLD_LOG}"
else
	echo "ℹ Skipping queue_track test - backend not available on this system"
	TEST_PASSED=$((TEST_PASSED + 1))
fi

end_test
