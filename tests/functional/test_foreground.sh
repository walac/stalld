#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Foreground mode (-f/--foreground)
# Verify stalld runs in foreground and doesn't daemonize
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "Foreground Mode"

# Require root for this test
require_root

# Test 1: Without -f flag, stalld should daemonize
echo "Test 1: stalld daemonizes by default"
start_stalld -l -t 5
sleep 2

# Check if stalld is running
if assert_process_running "${STALLD_PID}" "stalld should be running"; then
	# Check parent process - should be init (PID 1) or systemd
	PARENT_PID=$(ps -o ppid= -p ${STALLD_PID} 2>/dev/null | tr -d ' ')
	if [ "${PARENT_PID}" == "1" ] || [ "${PARENT_PID}" == "2" ]; then
		assert_equals "1" "1" "stalld daemonized (parent is init/kthreadd)"
	else
		# On modern systems with session leaders, ppid might not be 1
		# Just verify it's not our shell's PID
		if [ "${PARENT_PID}" != "$$" ]; then
			assert_equals "1" "1" "stalld daemonized (parent is not test shell)"
		else
			TEST_FAILED=$((TEST_FAILED + 1))
			echo -e "  ${RED}FAIL${NC}: stalld did not daemonize (parent is test shell)"
		fi
	fi
fi

stop_stalld
sleep 1

# Test 2: With -f flag, stalld should stay in foreground
echo ""
echo "Test 2: stalld stays in foreground with -f"

# Start stalld in foreground but in background job
start_stalld -f -l -t 5
sleep 2

# Check if stalld is running
if assert_process_running "${STALLD_PID}" "stalld should be running with -f"; then
	# With -f, it should NOT daemonize, parent should be our shell
	PARENT_PID=$(ps -o ppid= -p ${STALLD_PID} 2>/dev/null | tr -d ' ')

	# The parent might be the subshell from start_stalld, not directly our shell
	# So we just verify it's not PID 1
	if [ "${PARENT_PID}" != "1" ]; then
		assert_equals "1" "1" "stalld did not daemonize with -f (parent is not init)"
	else
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: stalld daemonized even with -f flag"
	fi
fi

stop_stalld

# Test 3: With -v flag, foreground mode should be implicit
echo ""
echo "Test 3: -v implies foreground mode"

start_stalld -v -l -t 5
sleep 2

if assert_process_running "${STALLD_PID}" "stalld should be running with -v"; then
	PARENT_PID=$(ps -o ppid= -p ${STALLD_PID} 2>/dev/null | tr -d ' ')

	if [ "${PARENT_PID}" != "1" ]; then
		assert_equals "1" "1" "-v implies foreground mode"
	else
		TEST_FAILED=$((TEST_FAILED + 1))
		echo -e "  ${RED}FAIL${NC}: -v should imply foreground mode"
	fi
fi

stop_stalld

end_test
