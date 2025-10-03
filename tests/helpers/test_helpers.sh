#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Common helper functions for stalld tests
#
# Copyright (C) 2025 Red Hat Inc

# Test result tracking
TEST_NAME=""
TEST_PASSED=0
TEST_FAILED=0

# stalld PID
STALLD_PID=""

# Cleanup list
CLEANUP_PIDS=()
CLEANUP_FILES=()

# Color output
if [ -t 1 ]; then
	RED='\033[0;31m'
	GREEN='\033[0;32m'
	YELLOW='\033[1;33m'
	BLUE='\033[0;34m'
	NC='\033[0m' # No Color
else
	RED=''
	GREEN=''
	YELLOW=''
	BLUE=''
	NC=''
fi

# Start a test
start_test() {
	TEST_NAME=$1
	echo -e "${BLUE}=== Starting test: ${TEST_NAME} ===${NC}"
}

# End a test
end_test() {
	if [ ${TEST_FAILED} -eq 0 ]; then
		echo -e "${GREEN}=== Test ${TEST_NAME}: PASSED ===${NC}"
		return 0
	else
		echo -e "${RED}=== Test ${TEST_NAME}: FAILED ===${NC}"
		return 1
	fi
}

# Assert functions
assert_equals() {
	local expected=$1
	local actual=$2
	local message=${3:-""}

	if [ "${expected}" == "${actual}" ]; then
		echo -e "  ${GREEN}PASS${NC}: ${message}"
		TEST_PASSED=$((TEST_PASSED + 1))
		return 0
	else
		echo -e "  ${RED}FAIL${NC}: ${message}"
		echo "    Expected: ${expected}"
		echo "    Actual:   ${actual}"
		TEST_FAILED=$((TEST_FAILED + 1))
		return 1
	fi
}

assert_contains() {
	local haystack=$1
	local needle=$2
	local message=${3:-""}

	if echo "${haystack}" | grep -q "${needle}"; then
		echo -e "  ${GREEN}PASS${NC}: ${message}"
		TEST_PASSED=$((TEST_PASSED + 1))
		return 0
	else
		echo -e "  ${RED}FAIL${NC}: ${message}"
		echo "    String '${needle}' not found"
		TEST_FAILED=$((TEST_FAILED + 1))
		return 1
	fi
}

assert_not_contains() {
	local haystack=$1
	local needle=$2
	local message=${3:-""}

	if ! echo "${haystack}" | grep -q "${needle}"; then
		echo -e "  ${GREEN}PASS${NC}: ${message}"
		TEST_PASSED=$((TEST_PASSED + 1))
		return 0
	else
		echo -e "  ${RED}FAIL${NC}: ${message}"
		echo "    String '${needle}' found but should not be present"
		TEST_FAILED=$((TEST_FAILED + 1))
		return 1
	fi
}

assert_file_exists() {
	local file=$1
	local message=${2:-"File should exist: ${file}"}

	if [ -f "${file}" ]; then
		echo -e "  ${GREEN}PASS${NC}: ${message}"
		TEST_PASSED=$((TEST_PASSED + 1))
		return 0
	else
		echo -e "  ${RED}FAIL${NC}: ${message}"
		TEST_FAILED=$((TEST_FAILED + 1))
		return 1
	fi
}

assert_file_not_exists() {
	local file=$1
	local message=${2:-"File should not exist: ${file}"}

	if [ ! -f "${file}" ]; then
		echo -e "  ${GREEN}PASS${NC}: ${message}"
		TEST_PASSED=$((TEST_PASSED + 1))
		return 0
	else
		echo -e "  ${RED}FAIL${NC}: ${message}"
		TEST_FAILED=$((TEST_FAILED + 1))
		return 1
	fi
}

assert_process_running() {
	local pid=$1
	local message=${2:-"Process ${pid} should be running"}

	if kill -0 ${pid} 2>/dev/null; then
		echo -e "  ${GREEN}PASS${NC}: ${message}"
		TEST_PASSED=$((TEST_PASSED + 1))
		return 0
	else
		echo -e "  ${RED}FAIL${NC}: ${message}"
		TEST_FAILED=$((TEST_FAILED + 1))
		return 1
	fi
}

assert_process_not_running() {
	local pid=$1
	local message=${2:-"Process ${pid} should not be running"}

	if ! kill -0 ${pid} 2>/dev/null; then
		echo -e "  ${GREEN}PASS${NC}: ${message}"
		TEST_PASSED=$((TEST_PASSED + 1))
		return 0
	else
		echo -e "  ${RED}FAIL${NC}: ${message}"
		TEST_FAILED=$((TEST_FAILED + 1))
		return 1
	fi
}

# Start stalld in background
start_stalld() {
	local args="$@"

	# Find stalld binary
	local stalld_bin="../stalld"
	if [ ! -x "${stalld_bin}" ]; then
		echo -e "${RED}ERROR: stalld binary not found at ${stalld_bin}${NC}"
		return 1
	fi

	${stalld_bin} ${args} &
	STALLD_PID=$!
	CLEANUP_PIDS+=("${STALLD_PID}")

	# Wait for stalld to initialize
	sleep 1

	# Verify it's running
	if ! kill -0 ${STALLD_PID} 2>/dev/null; then
		echo -e "${RED}ERROR: stalld failed to start${NC}"
		return 1
	fi

	echo "stalld started with PID ${STALLD_PID}"
	return 0
}

# Stop stalld
stop_stalld() {
	if [ -n "${STALLD_PID}" ]; then
		if kill -0 ${STALLD_PID} 2>/dev/null; then
			kill ${STALLD_PID} 2>/dev/null
			wait ${STALLD_PID} 2>/dev/null
		fi
		STALLD_PID=""
	fi
}

# Cleanup function (call in trap)
cleanup() {
	# Stop stalld
	stop_stalld

	# Kill any tracked processes
	for pid in "${CLEANUP_PIDS[@]}"; do
		if [ -n "${pid}" ] && kill -0 ${pid} 2>/dev/null; then
			kill ${pid} 2>/dev/null
			wait ${pid} 2>/dev/null
		fi
	done

	# Remove tracked files
	for file in "${CLEANUP_FILES[@]}"; do
		rm -f "${file}" 2>/dev/null
	done

	# Kill any starvation generators
	pkill -f starvation_gen 2>/dev/null

	# Remove temp files
	rm -f /tmp/stalld_test_* 2>/dev/null
}

# Trap to ensure cleanup
trap cleanup EXIT INT TERM

# Parse stalld log for specific message
wait_for_log_message() {
	local pattern=$1
	local timeout=${2:-10}
	local log_file=${3:-/var/log/syslog}

	# If log_file doesn't exist, try journalctl
	if [ ! -f "${log_file}" ]; then
		# Using journalctl instead
		local elapsed=0
		while [ ${elapsed} -lt ${timeout} ]; do
			if journalctl -u stalld --since "1 minute ago" 2>/dev/null | grep -q "${pattern}"; then
				return 0
			fi
			sleep 1
			elapsed=$((elapsed + 1))
		done
		return 1
	fi

	local elapsed=0
	while [ ${elapsed} -lt ${timeout} ]; do
		if grep -q "${pattern}" "${log_file}"; then
			return 0
		fi
		sleep 1
		elapsed=$((elapsed + 1))
	done

	return 1
}

# Get thread scheduling policy
get_thread_policy() {
	local pid=$1
	if [ -f /proc/${pid}/sched ]; then
		awk '/policy/ {print $3}' /proc/${pid}/sched 2>/dev/null
	else
		echo "unknown"
	fi
}

# Get thread priority
get_thread_priority() {
	local pid=$1
	if [ -f /proc/${pid}/sched ]; then
		awk '/prio/ {print $3}' /proc/${pid}/sched 2>/dev/null
	else
		echo "unknown"
	fi
}

# Create CPU load on specific CPU
create_cpu_load() {
	local cpu=$1
	local duration=${2:-60}

	taskset -c ${cpu} dd if=/dev/zero of=/dev/null bs=1M count=999999 &
	local pid=$!
	CLEANUP_PIDS+=("${pid}")
	echo ${pid}
}

# Check if running as root
require_root() {
	if [ $EUID -ne 0 ]; then
		echo -e "${YELLOW}SKIP: This test requires root privileges${NC}"
		exit 0
	fi
}

# Check if RT throttling is disabled
check_rt_throttling() {
	if [ -f /proc/sys/kernel/sched_rt_runtime_us ]; then
		local throttle=$(cat /proc/sys/kernel/sched_rt_runtime_us)
		if [ "${throttle}" != "-1" ]; then
			echo -e "${YELLOW}WARNING: RT throttling is enabled (${throttle})${NC}"
			return 1
		fi
	fi
	return 0
}

# Get number of CPUs
get_num_cpus() {
	nproc
}

# Get a list of online CPUs
get_online_cpus() {
	local num_cpus=$(get_num_cpus)
	local cpus=""

	for ((i=0; i<num_cpus; i++)); do
		if [ -f /sys/devices/system/cpu/cpu${i}/online ]; then
			if [ "$(cat /sys/devices/system/cpu/cpu${i}/online)" == "1" ]; then
				cpus="${cpus} ${i}"
			fi
		else
			# CPU 0 doesn't have online file, it's always online
			cpus="${cpus} ${i}"
		fi
	done

	echo ${cpus}
}

# Pick a CPU for testing (prefer last CPU)
pick_test_cpu() {
	local cpus=$(get_online_cpus)
	echo ${cpus##* }  # Return last CPU
}

# Export functions for use in tests
export -f start_test end_test
export -f assert_equals assert_contains assert_not_contains
export -f assert_file_exists assert_file_not_exists
export -f assert_process_running assert_process_not_running
export -f start_stalld stop_stalld cleanup
export -f wait_for_log_message
export -f get_thread_policy get_thread_priority
export -f create_cpu_load
export -f require_root check_rt_throttling
export -f get_num_cpus get_online_cpus pick_test_cpu
