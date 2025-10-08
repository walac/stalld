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

# Parse common test options
# Usage: parse_test_options "$@"
# This function should be called at the beginning of each test script
parse_test_options() {
	while [[ $# -gt 0 ]]; do
		case $1 in
			-b|--backend)
				export STALLD_TEST_BACKEND="$2"
				shift 2
				;;
			-h|--help)
				echo "Common test options:"
				echo "  -b, --backend <name>  Backend to use (sched_debug|S or queue_track|Q)"
				echo "  -h, --help            Show this help"
				return 1
				;;
			*)
				echo "Unknown option: $1"
				echo "Usage: $0 [-b|--backend <backend>] [-h|--help]"
				return 1
				;;
		esac
	done
	return 0
}

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
	local exit_code=$?

	# Don't print cleanup messages if exiting normally (exit code 0)
	if [ ${exit_code} -ne 0 ]; then
		echo -e "${YELLOW}Cleaning up test resources...${NC}" >&2
	fi

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
	pkill -f starvation_gen 2>/dev/null || true

	# Remove temp files
	rm -f /tmp/stalld_test_* 2>/dev/null || true

	# Restore DL-server if it was saved
	restore_dl_server || true

	# Restore RT throttling if it was saved
	restore_rt_throttling || true

	# Exit with the original exit code
	exit ${exit_code}
}

# Signal handler for interrupts
handle_signal() {
	echo ""
	echo -e "${YELLOW}Test interrupted by signal (Ctrl-C)${NC}" >&2
	exit 130  # Standard exit code for SIGINT
}

# Trap to ensure cleanup
trap cleanup EXIT
trap handle_signal INT TERM

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

# RT throttling state management
SAVED_RT_RUNTIME=""

# Save current RT throttling state
save_rt_throttling() {
	if [ -f /proc/sys/kernel/sched_rt_runtime_us ]; then
		SAVED_RT_RUNTIME=$(cat /proc/sys/kernel/sched_rt_runtime_us)
		echo "Saved RT throttling state: ${SAVED_RT_RUNTIME}"
	else
		echo -e "${YELLOW}WARNING: /proc/sys/kernel/sched_rt_runtime_us not found${NC}"
		SAVED_RT_RUNTIME=""
	fi
}

# DL-server state management
declare -A SAVED_DL_SERVER_RUNTIME

# Save current DL-server state for all CPUs
save_dl_server() {
	local dl_server_dir="/sys/kernel/debug/sched/fair_server"

	if [ ! -d "${dl_server_dir}" ]; then
		return 0  # DL-server not present, nothing to save
	fi

	echo "Saving DL-server state for all CPUs..."
	local cpu_count=0

	for cpu_dir in "${dl_server_dir}"/cpu*; do
		if [ -d "${cpu_dir}" ]; then
			local cpu=$(basename "${cpu_dir}")
			local runtime_file="${cpu_dir}/runtime"

			if [ -f "${runtime_file}" ]; then
				SAVED_DL_SERVER_RUNTIME["${cpu}"]=$(cat "${runtime_file}" 2>/dev/null)
				if [ $? -eq 0 ]; then
					cpu_count=$((cpu_count + 1))
				fi
			fi
		fi
	done

	if [ ${cpu_count} -gt 0 ]; then
		echo "Saved DL-server state for ${cpu_count} CPUs"
		return 0
	else
		echo -e "${YELLOW}WARNING: No DL-server runtime files found${NC}"
		return 1
	fi
}

# Restore DL-server state for all CPUs
restore_dl_server() {
	local dl_server_dir="/sys/kernel/debug/sched/fair_server"

	if [ ! -d "${dl_server_dir}" ]; then
		return 0  # DL-server not present, nothing to restore
	fi

	if [ ${#SAVED_DL_SERVER_RUNTIME[@]} -eq 0 ]; then
		return 0  # Nothing was saved
	fi

	echo "Restoring DL-server state..."
	local cpu_count=0

	for cpu in "${!SAVED_DL_SERVER_RUNTIME[@]}"; do
		local runtime_file="${dl_server_dir}/${cpu}/runtime"
		local saved_value="${SAVED_DL_SERVER_RUNTIME[${cpu}]}"

		if [ -f "${runtime_file}" ]; then
			echo "${saved_value}" > "${runtime_file}" 2>/dev/null
			if [ $? -eq 0 ]; then
				cpu_count=$((cpu_count + 1))
			else
				echo -e "${YELLOW}WARNING: Failed to restore ${cpu}/runtime${NC}"
			fi
		fi
	done

	if [ ${cpu_count} -gt 0 ]; then
		echo "Restored DL-server state for ${cpu_count} CPUs"
	fi

	# Clear saved state
	unset SAVED_DL_SERVER_RUNTIME
	declare -gA SAVED_DL_SERVER_RUNTIME
}

# Disable DL-server for all CPUs (set runtime to 0)
disable_dl_server() {
	local dl_server_dir="/sys/kernel/debug/sched/fair_server"

	if [ ! -d "${dl_server_dir}" ]; then
		return 0  # DL-server not present, nothing to disable
	fi

	echo "Disabling DL-server for all CPUs..."
	local cpu_count=0

	for cpu_dir in "${dl_server_dir}"/cpu*; do
		if [ -d "${cpu_dir}" ]; then
			local cpu=$(basename "${cpu_dir}")
			local runtime_file="${cpu_dir}/runtime"

			if [ -f "${runtime_file}" ]; then
				echo 0 > "${runtime_file}" 2>/dev/null
				if [ $? -eq 0 ]; then
					cpu_count=$((cpu_count + 1))
				else
					echo -e "${YELLOW}WARNING: Failed to disable ${cpu}/runtime${NC}"
				fi
			fi
		fi
	done

	if [ ${cpu_count} -gt 0 ]; then
		echo "Disabled DL-server for ${cpu_count} CPUs"
		return 0
	else
		echo -e "${RED}ERROR: Failed to disable DL-server${NC}"
		return 1
	fi
}

# Restore RT throttling state
restore_rt_throttling() {
	if [ -n "${SAVED_RT_RUNTIME}" ] && [ -f /proc/sys/kernel/sched_rt_runtime_us ]; then
		echo "${SAVED_RT_RUNTIME}" > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null
		if [ $? -eq 0 ]; then
			echo "Restored RT throttling state: ${SAVED_RT_RUNTIME}"
		else
			echo -e "${YELLOW}WARNING: Failed to restore RT throttling state${NC}"
		fi
		SAVED_RT_RUNTIME=""
	fi
}

# Disable RT throttling (for tests that require it)
disable_rt_throttling() {
	if [ -f /proc/sys/kernel/sched_rt_runtime_us ]; then
		echo -1 > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null
		if [ $? -eq 0 ]; then
			echo "Disabled RT throttling"
			return 0
		else
			echo -e "${RED}ERROR: Failed to disable RT throttling (need root?)${NC}"
			return 1
		fi
	else
		echo -e "${YELLOW}WARNING: /proc/sys/kernel/sched_rt_runtime_us not found${NC}"
		return 1
	fi
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

#
# Backend detection and helpers
#

# Detect which backend stalld was compiled with (default)
detect_default_backend() {
	local stalld_bin="../stalld"
	if [ ! -x "${stalld_bin}" ]; then
		echo "unknown"
		return 1
	fi

	# Check if stalld was built with BPF support
	# Look for queue_track symbols in the binary
	if command -v nm >/dev/null 2>&1; then
		if nm "${stalld_bin}" 2>/dev/null | grep -q "queue_track"; then
			echo "queue_track"
			return 0
		fi
	fi

	# Fall back to sched_debug
	echo "sched_debug"
	return 0
}

# Check if a specific backend is available
is_backend_available() {
	local backend=$1
	local stalld_bin="../stalld"

	if [ ! -x "${stalld_bin}" ]; then
		return 1
	fi

	case "${backend}" in
		"sched_debug"|"S")
			# sched_debug is always available
			return 0
			;;
		"queue_track"|"Q")
			# Check if BPF backend is available
			if command -v nm >/dev/null 2>&1; then
				if nm "${stalld_bin}" 2>/dev/null | grep -q "queue_track"; then
					return 0
				fi
			fi
			return 1
			;;
		*)
			return 1
			;;
	esac
}

# Get list of available backends
get_available_backends() {
	local backends=()

	# sched_debug is always available
	backends+=("sched_debug")

	# Check for queue_track (BPF)
	if is_backend_available "queue_track"; then
		backends+=("queue_track")
	fi

	echo "${backends[@]}"
}

# Start stalld with specific backend
start_stalld_with_backend() {
	local backend=$1
	shift  # Remove backend from args
	local extra_args="$@"

	if ! is_backend_available "${backend}"; then
		echo -e "${YELLOW}WARNING: Backend '${backend}' not available, skipping test${NC}"
		return 77  # Skip exit code
	fi

	echo "Starting stalld with backend: ${backend}"
	start_stalld -b "${backend}" ${extra_args}
	return $?
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
export -f detect_default_backend is_backend_available get_available_backends start_stalld_with_backend
export -f require_root check_rt_throttling
export -f save_rt_throttling restore_rt_throttling disable_rt_throttling
export -f save_dl_server restore_dl_server disable_dl_server
export -f get_num_cpus get_online_cpus pick_test_cpu
