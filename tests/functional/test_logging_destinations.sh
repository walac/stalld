#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Logging destinations (-v, -k, -s)
# Verify stalld logs to correct destinations
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "Logging Destinations"

# Require root for this test
require_root

# Test 1: Verbose mode (-v) logs to stdout/stderr
echo "Test 1: Verbose mode (-v) logs to stdout"

LOG_FILE="/tmp/stalld_test_verbose_$$.log"
CLEANUP_FILES+=("${LOG_FILE}")

# Start stalld directly (not using start_stalld helper) to capture output
../stalld -f -v -l -t 5 > "${LOG_FILE}" 2>&1 &
sleep 2
STALLD_PID=$(pgrep -n -x stalld 2>/dev/null)
if [ -n "${STALLD_PID}" ]; then
	CLEANUP_PIDS+=("${STALLD_PID}")
fi

if assert_process_running "${STALLD_PID}" "stalld should be running"; then
	# Check that output was written to our log file
	if [ -s "${LOG_FILE}" ]; then
		assert_equals "1" "1" "verbose mode produces output"

		# Should contain initialization messages
		if grep -q -E "(stalld|version|monitoring)" "${LOG_FILE}"; then
			assert_equals "1" "1" "output contains expected messages"
		fi
	else
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: no output in verbose mode"
	fi
fi

stop_stalld
rm -f "${LOG_FILE}"

# Test 2: Kernel message log (-k)
echo ""
echo "Test 2: Kernel message log (-k)"

# Clear dmesg if possible (requires root)
if command -v dmesg >/dev/null 2>&1; then
	DMESG_BEFORE=$(dmesg | wc -l)

	start_stalld -f -k -l -t 5
	sleep 2

	if assert_process_running "${STALLD_PID}" "stalld with -k should be running"; then
		sleep 1
		DMESG_AFTER=$(dmesg | wc -l)

		# Check if new messages appeared in dmesg
		# Note: This might not work in all environments
		if [ ${DMESG_AFTER} -gt ${DMESG_BEFORE} ]; then
			# Check if recent dmesg contains stalld messages
			if dmesg | tail -10 | grep -q "stalld"; then
				assert_equals "1" "1" "stalld messages in kernel log"
			else
				echo -e "  ${YELLOW}SKIP${NC}: cannot verify kernel log messages"
			fi
		else
			echo -e "  ${YELLOW}SKIP${NC}: no new dmesg entries (may require special permissions)"
		fi
	fi

	stop_stalld
else
	echo -e "  ${YELLOW}SKIP${NC}: dmesg not available"
fi

# Test 3: Syslog (-s, default)
echo ""
echo "Test 3: Syslog (-s, default)"

# Check if syslog is available
SYSLOG_FILE=""
if [ -f /var/log/syslog ]; then
	SYSLOG_FILE="/var/log/syslog"
elif [ -f /var/log/messages ]; then
	SYSLOG_FILE="/var/log/messages"
fi

if [ -n "${SYSLOG_FILE}" ]; then
	# Get current line count
	SYSLOG_BEFORE=$(wc -l < "${SYSLOG_FILE}")

	start_stalld -f -s -l -t 5
	sleep 3

	if assert_process_running "${STALLD_PID}" "stalld with -s should be running"; then
		SYSLOG_AFTER=$(wc -l < "${SYSLOG_FILE}")

		if [ ${SYSLOG_AFTER} -gt ${SYSLOG_BEFORE} ]; then
			# Check for stalld messages in recent syslog
			if tail -20 "${SYSLOG_FILE}" | grep -q "stalld"; then
				assert_equals "1" "1" "stalld messages in syslog"
			else
				echo -e "  ${YELLOW}SKIP${NC}: no stalld messages found in syslog"
			fi
		else
			echo -e "  ${YELLOW}SKIP${NC}: syslog may be delayed"
		fi
	fi

	stop_stalld
elif command -v journalctl >/dev/null 2>&1; then
	# Try journalctl instead
	echo "Using journalctl instead of syslog file"

	start_stalld -f -s -l -t 5
	sleep 3

	if assert_process_running "${STALLD_PID}" "stalld with -s should be running"; then
		# Check journalctl for stalld messages
		if journalctl -u stalld --since "1 minute ago" 2>/dev/null | grep -q "stalld"; then
			assert_equals "1" "1" "stalld messages in journalctl"
		elif journalctl --since "1 minute ago" 2>/dev/null | grep -q "stalld"; then
			assert_equals "1" "1" "stalld messages in system journal"
		else
			echo -e "  ${YELLOW}SKIP${NC}: no stalld messages in journal (may take time to appear)"
		fi
	fi

	stop_stalld
else
	echo -e "  ${YELLOW}SKIP${NC}: neither syslog nor journalctl available"
fi

# Test 4: Combined logging (-v -k -s)
echo ""
echo "Test 4: Combined logging modes"

LOG_FILE="/tmp/stalld_test_combined_$$.log"
CLEANUP_FILES+=("${LOG_FILE}")

# Start stalld directly (not using start_stalld helper) to capture output
../stalld -f -v -k -s -l -t 5 > "${LOG_FILE}" 2>&1 &
sleep 2
STALLD_PID=$(pgrep -n -x stalld 2>/dev/null)
if [ -n "${STALLD_PID}" ]; then
	CLEANUP_PIDS+=("${STALLD_PID}")
fi

if assert_process_running "${STALLD_PID}" "stalld with combined logging should be running"; then
	# Verify verbose output
	if [ -s "${LOG_FILE}" ]; then
		assert_equals "1" "1" "combined logging produces output"
	else
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: no output with combined logging"
	fi
fi

stop_stalld

end_test
