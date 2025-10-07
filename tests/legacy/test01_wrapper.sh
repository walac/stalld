#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Wrapper script for legacy test01
#
# This wrapper provides proper integration of the legacy test01.c into the
# modern test infrastructure. It handles:
# - RT throttling save/disable/restore
# - DL-server save/disable/restore
# - stalld lifecycle management
# - Proper cleanup and exit codes
#
# Copyright (C) 2025 Red Hat Inc

set -e

# Get absolute paths
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEGACY_DIR="${TEST_ROOT}/legacy"
TEST01_BIN="${LEGACY_DIR}/test01"

# Source test helpers
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Test configuration
TEST_NAME="test01 (legacy starvation test)"
STARVATION_THRESHOLD=5
STALLD_STARTUP_WAIT=2

if [[ "$1" == "" ]]; then
    backend="sched_debug"
else
    backend="queue_track"
fi

#
# Main test execution
#
main() {
	start_test "${TEST_NAME}"

	# Note: test_helpers.sh already sets up cleanup traps for:
	# - Stopping stalld
	# - Restoring DL-server
	# - Restoring RT throttling
	# - Killing background processes
	# So we don't need to duplicate that here

	# Require root privileges
	require_root

	# Check if test01 binary exists
	if [ ! -x "${TEST01_BIN}" ]; then
		echo "ERROR: test01 binary not found at ${TEST01_BIN}"
		echo "Please run 'make' in tests/ directory first"
		exit 1
	fi

	echo "Legacy test01 wrapper starting..."

	# Save and disable RT throttling
	echo "Saving RT throttling state..."
	save_rt_throttling

	echo "Disabling RT throttling..."
	disable_rt_throttling

 	# Check for DL-server and disable if present
	if [ -d "/sys/kernel/debug/sched/fair_server" ]; then
		echo "DL-server detected, saving state..."
		save_dl_server

		echo "Disabling DL-server..."
		disable_dl_server
	else
		echo "DL-server not present (kernel < 6.6 or not enabled)"
	fi

	# Start stalld in foreground with verbose logging and short threshold
	echo "Starting stalld with threshold=${STARVATION_THRESHOLD}s..."
	start_stalld -f -v -t "${STARVATION_THRESHOLD}" -b ${backend}

	assert_process_running "${STALLD_PID}" "stalld should be running"
	echo "stalld started successfully (PID: ${STALLD_PID})"

	# Give stalld time to initialize
	sleep "${STALLD_STARTUP_WAIT}"

	# Run the legacy test01 binary
	echo "Executing legacy test01 binary..."
	local test_output
	local test_exit_code=0

	# Capture output and exit code
	set +e
	test_output=$("${TEST01_BIN}" -v 2>&1)
	test_exit_code=$?
	set -e

	# Show test output
	echo "${test_output}"

	# Check exit code
	if [ ${test_exit_code} -eq 0 ]; then
		echo "test01 binary completed successfully"

		# Verify stalld is still running
		if ! kill -0 "${STALLD_PID}" 2>/dev/null; then
			echo "ERROR: stalld died during test execution"
			exit 1
		fi

		# Check if stalld detected and boosted the starving task
		# Wait a bit for logs to flush
		sleep 1

		# Look for starvation detection in stalld output
		if wait_for_log_message "starv" 10 "${STALLD_LOG}"; then
			echo "✓ stalld detected starvation"
		else
			echo "WARNING: stalld may not have detected starvation"
			echo "This could be due to:"
			echo "  - Test completing too quickly"
			echo "  - DL-server preventing starvation (if enabled)"
			echo "  - System load preventing proper starvation scenario"
		fi

		# Check for boosting (if starvation was detected)
		if grep -q "boost" "${STALLD_LOG}" 2>/dev/null; then
			echo "✓ stalld boosted starving task"
		fi

	else
		echo "ERROR: test01 binary failed with exit code ${test_exit_code}"
		exit 1
	fi

	# Stop stalld
	echo "Stopping stalld..."
	stop_stalld

	end_test
}

# Execute main
main "$@"
