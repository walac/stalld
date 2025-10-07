#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Main test runner for stalld test suite
#
# Copyright (C) 2025 Red Hat Inc

set -e

# Configuration
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STALLD_BIN="${TEST_ROOT}/../stalld"
RESULTS_DIR="${TEST_ROOT}/results"
LOG_FILE="${RESULTS_DIR}/test_run_$(date +%Y%m%d_%H%M%S).log"

# Source test helpers for RT throttling and DL-server management
source "${TEST_ROOT}/helpers/test_helpers.sh" 2>/dev/null || true

# RT throttling state
SAVED_RT_RUNTIME=""

# DL-server state
declare -A SAVED_DL_SERVER_RUNTIME

# Configuration flags
DISABLE_DL_SERVER=0

# Test categories
declare -a UNIT_TESTS
declare -a FUNC_TESTS
declare -a INTEG_TESTS

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Color output
if [ -t 1 ]; then
	RED='\033[0;31m'
	GREEN='\033[0;32m'
	YELLOW='\033[1;33m'
	BLUE='\033[0;34m'
	BOLD='\033[1m'
	NC='\033[0m' # No Color
else
	RED=''
	GREEN=''
	YELLOW=''
	BLUE=''
	BOLD=''
	NC=''
fi

# Print banner
print_banner() {
	echo -e "${BOLD}=========================================${NC}"
	echo -e "${BOLD}   stalld Test Suite - $(date)${NC}"
	echo -e "${BOLD}=========================================${NC}"
}

# Save and disable RT throttling
save_and_disable_rt_throttling() {
	if [ -f /proc/sys/kernel/sched_rt_runtime_us ]; then
		SAVED_RT_RUNTIME=$(cat /proc/sys/kernel/sched_rt_runtime_us)
		echo -e "${BLUE}Saving RT throttling state: ${SAVED_RT_RUNTIME}${NC}" | tee -a "${LOG_FILE}"

		if [ "${SAVED_RT_RUNTIME}" != "-1" ]; then
			echo -e "${BLUE}Disabling RT throttling for test run...${NC}" | tee -a "${LOG_FILE}"
			echo -1 > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null
			if [ $? -eq 0 ]; then
				echo -e "${GREEN}RT throttling disabled${NC}" | tee -a "${LOG_FILE}"
			else
				echo -e "${YELLOW}WARNING: Failed to disable RT throttling${NC}" | tee -a "${LOG_FILE}"
			fi
		fi
	fi
	echo "" | tee -a "${LOG_FILE}"
}

# Save and disable DL-server
save_and_disable_dl_server() {
	local dl_server_dir="/sys/kernel/debug/sched/fair_server"

	if [ ! -d "${dl_server_dir}" ]; then
		return 0  # DL-server not present
	fi

	echo -e "${BLUE}Saving DL-server state for all CPUs...${NC}" | tee -a "${LOG_FILE}"
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
		echo -e "${GREEN}Saved DL-server state for ${cpu_count} CPUs${NC}" | tee -a "${LOG_FILE}"

		# Now disable DL-server
		echo -e "${BLUE}Disabling DL-server for all CPUs...${NC}" | tee -a "${LOG_FILE}"
		local disabled_count=0

		for cpu_dir in "${dl_server_dir}"/cpu*; do
			if [ -d "${cpu_dir}" ]; then
				local cpu=$(basename "${cpu_dir}")
				local runtime_file="${cpu_dir}/runtime"

				if [ -f "${runtime_file}" ]; then
					echo 0 > "${runtime_file}" 2>/dev/null
					if [ $? -eq 0 ]; then
						disabled_count=$((disabled_count + 1))
					fi
				fi
			fi
		done

		if [ ${disabled_count} -gt 0 ]; then
			echo -e "${GREEN}Disabled DL-server for ${disabled_count} CPUs${NC}" | tee -a "${LOG_FILE}"
		else
			echo -e "${YELLOW}WARNING: Failed to disable DL-server${NC}" | tee -a "${LOG_FILE}"
		fi
	fi
	echo "" | tee -a "${LOG_FILE}"
}

# Restore RT throttling
restore_rt_throttling_state() {
	if [ -n "${SAVED_RT_RUNTIME}" ] && [ -f /proc/sys/kernel/sched_rt_runtime_us ]; then
		echo -e "\n${BLUE}Restoring RT throttling state: ${SAVED_RT_RUNTIME}${NC}"
		echo "${SAVED_RT_RUNTIME}" > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null
		if [ $? -eq 0 ]; then
			echo -e "${GREEN}RT throttling restored${NC}"
		else
			echo -e "${YELLOW}WARNING: Failed to restore RT throttling state${NC}"
		fi
	fi
}

# Restore DL-server
restore_dl_server_state() {
	local dl_server_dir="/sys/kernel/debug/sched/fair_server"

	if [ ! -d "${dl_server_dir}" ]; then
		return 0  # DL-server not present
	fi

	if [ ${#SAVED_DL_SERVER_RUNTIME[@]} -eq 0 ]; then
		return 0  # Nothing was saved
	fi

	echo -e "\n${BLUE}Restoring DL-server state...${NC}"
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
		echo -e "${GREEN}Restored DL-server state for ${cpu_count} CPUs${NC}"
	fi
}

# Cleanup function
cleanup_runner() {
	local exit_code=$?

	# If interrupted by signal, print message
	if [ ${exit_code} -gt 128 ]; then
		echo ""
		echo -e "${YELLOW}Test run interrupted by signal${NC}"
	fi

	if [ $EUID -eq 0 ]; then
		restore_dl_server_state
		restore_rt_throttling_state
	fi
}

# Signal handler for clean interrupts
handle_interrupt() {
	echo ""
	echo -e "${YELLOW}Caught interrupt signal (Ctrl-C), cleaning up...${NC}"
	exit 130  # Standard exit code for SIGINT
}

# Set up cleanup traps
trap cleanup_runner EXIT
trap handle_interrupt INT TERM

# Initialize
init_tests() {
	mkdir -p "${RESULTS_DIR}"

	print_banner | tee "${LOG_FILE}"
	echo "" | tee -a "${LOG_FILE}"

	# Save and disable RT throttling if running as root
	if [ $EUID -eq 0 ]; then
		save_and_disable_rt_throttling

		# Save and disable DL-server if requested
		if [ ${DISABLE_DL_SERVER} -eq 1 ]; then
			save_and_disable_dl_server
		fi
	fi

	# Check prerequisites
	check_prerequisites
}

# Check prerequisites
check_prerequisites() {
	echo -e "${BLUE}Checking prerequisites...${NC}" | tee -a "${LOG_FILE}"

	# Check if running as root
	if [ $EUID -ne 0 ]; then
		echo -e "${YELLOW}WARNING: Not running as root. Some tests will be skipped.${NC}" | tee -a "${LOG_FILE}"
	fi

	# Check if stalld binary exists
	if [ ! -f "${STALLD_BIN}" ]; then
		echo -e "${RED}ERROR: stalld binary not found at ${STALLD_BIN}${NC}" | tee -a "${LOG_FILE}"
		echo "Please run 'make' in the project root first." | tee -a "${LOG_FILE}"
		exit 1
	fi

	# Check if stalld is executable
	if [ ! -x "${STALLD_BIN}" ]; then
		echo -e "${RED}ERROR: stalld binary is not executable${NC}" | tee -a "${LOG_FILE}"
		exit 1
	fi

	# Check kernel version for BPF support
	KERNEL_VER=$(uname -r | cut -d. -f1)
	if [ "${KERNEL_VER}" -lt 4 ]; then
		echo -e "${YELLOW}WARNING: Kernel < 4.x, BPF tests will be skipped${NC}" | tee -a "${LOG_FILE}"
	fi

	echo "" | tee -a "${LOG_FILE}"
}

# Discover tests
discover_tests() {
	# Find unit tests (C executables)
	if [ -d "${TEST_ROOT}/unit" ]; then
		while IFS= read -r test; do
			UNIT_TESTS+=("${test}")
		done < <(find "${TEST_ROOT}/unit" -type f -executable -name "test_*" 2>/dev/null)
	fi

	# Find functional tests (shell scripts)
	if [ -d "${TEST_ROOT}/functional" ]; then
		while IFS= read -r test; do
			FUNC_TESTS+=("${test}")
		done < <(find "${TEST_ROOT}/functional" -type f -name "test_*.sh" 2>/dev/null)
	fi

	# Find integration tests (shell scripts)
	if [ -d "${TEST_ROOT}/integration" ]; then
		while IFS= read -r test; do
			INTEG_TESTS+=("${test}")
		done < <(find "${TEST_ROOT}/integration" -type f -name "test_*.sh" 2>/dev/null)
	fi

	# Add legacy test wrapper
	if [ -x "${TEST_ROOT}/legacy/test01_wrapper.sh" ]; then
		UNIT_TESTS=("${TEST_ROOT}/legacy/test01_wrapper.sh" "${UNIT_TESTS[@]}")
	fi
}

# Run unit tests
run_unit_tests() {
	if [ ${#UNIT_TESTS[@]} -eq 0 ]; then
		echo -e "${YELLOW}No unit tests found${NC}" | tee -a "${LOG_FILE}"
		return
	fi

	echo -e "\n${BOLD}${GREEN}Running Unit Tests${NC}" | tee -a "${LOG_FILE}"
	echo "-------------------------------------------" | tee -a "${LOG_FILE}"

	for test in "${UNIT_TESTS[@]}"; do
		run_unit_test "${test}"
	done
}

run_unit_test() {
	local test_path=$1
	local test_name=$(basename "${test_path}")

	TOTAL_TESTS=$((TOTAL_TESTS + 1))

	if [ ! -x "${test_path}" ]; then
		echo -e "${YELLOW}SKIP${NC}: ${test_name} (not executable)" | tee -a "${LOG_FILE}"
		SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
		return
	fi

	echo -n "Running ${test_name}... " | tee -a "${LOG_FILE}"

	local test_log="${RESULTS_DIR}/${test_name}.log"

	if "${test_path}" > "${test_log}" 2>&1; then
		echo -e "${GREEN}PASS${NC}" | tee -a "${LOG_FILE}"
		PASSED_TESTS=$((PASSED_TESTS + 1))
	else
		echo -e "${RED}FAIL${NC}" | tee -a "${LOG_FILE}"
		echo "  See ${test_log} for details" | tee -a "${LOG_FILE}"
		FAILED_TESTS=$((FAILED_TESTS + 1))
	fi
}

# Run functional tests
run_functional_tests() {
	if [ ${#FUNC_TESTS[@]} -eq 0 ]; then
		echo -e "${YELLOW}No functional tests found${NC}" | tee -a "${LOG_FILE}"
		return
	fi

	echo -e "\n${BOLD}${GREEN}Running Functional Tests${NC}" | tee -a "${LOG_FILE}"
	echo "-------------------------------------------" | tee -a "${LOG_FILE}"

	for test in "${FUNC_TESTS[@]}"; do
		run_shell_test "${test}"
	done
}

# Run integration tests
run_integration_tests() {
	if [ ${#INTEG_TESTS[@]} -eq 0 ]; then
		echo -e "${YELLOW}No integration tests found${NC}" | tee -a "${LOG_FILE}"
		return
	fi

	echo -e "\n${BOLD}${GREEN}Running Integration Tests${NC}" | tee -a "${LOG_FILE}"
	echo "-------------------------------------------" | tee -a "${LOG_FILE}"

	for test in "${INTEG_TESTS[@]}"; do
		run_shell_test "${test}"
	done
}

run_shell_test() {
	local test_path=$1
	local test_name=$(basename "${test_path}" .sh)

	TOTAL_TESTS=$((TOTAL_TESTS + 1))

	echo -n "Running ${test_name}... " | tee -a "${LOG_FILE}"

	local test_log="${RESULTS_DIR}/${test_name}.log"

	if bash "${test_path}" > "${test_log}" 2>&1; then
		echo -e "${GREEN}PASS${NC}" | tee -a "${LOG_FILE}"
		PASSED_TESTS=$((PASSED_TESTS + 1))
	else
		local exit_code=$?
		if [ ${exit_code} -eq 77 ]; then
			# Exit code 77 = SKIP (autotools convention)
			echo -e "${YELLOW}SKIP${NC}" | tee -a "${LOG_FILE}"
			SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
		else
			echo -e "${RED}FAIL${NC}" | tee -a "${LOG_FILE}"
			echo "  See ${test_log} for details" | tee -a "${LOG_FILE}"
			FAILED_TESTS=$((FAILED_TESTS + 1))
		fi
	fi
}

# Print summary
print_summary() {
	echo -e "\n${BOLD}=========================================== ${NC}" | tee -a "${LOG_FILE}"
	echo -e "${BOLD}Test Summary:${NC}" | tee -a "${LOG_FILE}"
	echo "  Total:   ${TOTAL_TESTS}" | tee -a "${LOG_FILE}"
	echo -e "  ${GREEN}Passed:  ${PASSED_TESTS}${NC}" | tee -a "${LOG_FILE}"
	echo -e "  ${RED}Failed:  ${FAILED_TESTS}${NC}" | tee -a "${LOG_FILE}"
	echo -e "  ${YELLOW}Skipped: ${SKIPPED_TESTS}${NC}" | tee -a "${LOG_FILE}"

	if [ ${FAILED_TESTS} -eq 0 ]; then
		echo -e "\n${BOLD}${GREEN}All tests passed!${NC}" | tee -a "${LOG_FILE}"
	else
		echo -e "\n${BOLD}${RED}Some tests failed.${NC}" | tee -a "${LOG_FILE}"
	fi

	echo -e "${BOLD}===========================================${NC}" | tee -a "${LOG_FILE}"
	echo "" | tee -a "${LOG_FILE}"
	echo "Full log: ${LOG_FILE}" | tee -a "${LOG_FILE}"

	# Exit with failure if any tests failed
	[ ${FAILED_TESTS} -eq 0 ]
}

# Parse command-line options
UNIT_ONLY=0
FUNCTIONAL_ONLY=0
INTEGRATION_ONLY=0

while [[ $# -gt 0 ]]; do
	case $1 in
		--unit-only)
			UNIT_ONLY=1
			shift
			;;
		--functional-only)
			FUNCTIONAL_ONLY=1
			shift
			;;
		--integration-only)
			INTEGRATION_ONLY=1
			shift
			;;
		--disable-dl-server)
			DISABLE_DL_SERVER=1
			shift
			;;
		-h|--help)
			echo "Usage: $0 [OPTIONS]"
			echo ""
			echo "Options:"
			echo "  --unit-only          Run only unit tests"
			echo "  --functional-only    Run only functional tests"
			echo "  --integration-only   Run only integration tests"
			echo "  --disable-dl-server  Disable DL-server before running tests"
			echo "                       (allows testing stalld starvation detection)"
			echo "  -h, --help           Show this help"
			exit 0
			;;
		*)
			echo "Unknown option: $1"
			exit 1
			;;
	esac
done

# Main execution
main() {
	init_tests
	discover_tests

	# Run test suites based on options
	if [ ${UNIT_ONLY} -eq 1 ]; then
		run_unit_tests
	elif [ ${FUNCTIONAL_ONLY} -eq 1 ]; then
		run_functional_tests
	elif [ ${INTEGRATION_ONLY} -eq 1 ]; then
		run_integration_tests
	else
		# Run all tests
		run_unit_tests
		run_functional_tests
		run_integration_tests
	fi

	# Print summary and exit
	print_summary
}

main "$@"
