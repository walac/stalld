# stalld v1.26.1 Release Notes

## Overview

This release focuses on build system improvements, adding RISC-V 64-bit architecture support and enhancing cross-platform compatibility through better compiler flag detection.

## New Features

### RISC-V 64-bit Architecture Support

**Add support for riscv64** (commit 336ab89f022c)
- **Author**: David Abdurachmanov
- **Impact**: stalld can now be built for RISC-V 64-bit systems
- **Details**: Added riscv64 to the list of supported architectures in the Makefile

## Build System Improvements

### Compiler Flag Detection

**1. Conditionally add -mno-omit-leaf-frame-pointer** (commit 0a406b85e6aa)
- **Author**: Wander Lairson Costa
- **Problem**: The `-mno-omit-leaf-frame-pointer` option is not available on all architectures (e.g., s390x) or with older compiler versions
- **Solution**: Added a check to ensure the option is only used when the compiler supports it
- **Impact**: Avoids compilation errors on systems where this flag is unavailable

**2. Improve compiler flag detection for -fcf-protection** (commit b668100ac7c7)
- **Author**: Wander Lairson Costa
- **Problem**: Previous method relied on minimum GCC version check, which was not always accurate across different architectures or compiler toolchains
- **Solution**: Replaced version check with direct compiler feature testing
- **Impact**: Better portability and avoids compilation errors on systems where the flag is not available

**3. Remove redundant GCC version check** (commit 5f3ab7923101)
- **Author**: Wander Lairson Costa
- **Problem**: Minimum GCC version check was introduced for `-fcf-protection` but became redundant after implementing direct feature detection
- **Solution**: Removed the now-unnecessary version check
- **Impact**: Simplified Makefile, relies on more accurate feature detection

### Build Process Improvements

**4. Print BPF tool versions for debugging** (commit a8be98b6bb2f)
- **Author**: Wander Lairson Costa
- **Problem**: BPF-related compilation issues were difficult to debug without knowing the build environment
- **Solution**: Added informational messages to print kernel version, clang version, and bpftool version during build
- **Impact**: Easier debugging of BPF compilation issues

**5. Explicitly run the 'test' target in the tests directory** (commit ce9c7dc59b6a)
- **Author**: Wander Lairson Costa
- **Problem**: The 'tests' target invoked make in the tests subdirectory without specifying a target
- **Solution**: Added explicit 'test' target to the make command
- **Impact**: Clearer and more robust build process

## Bug Fixes

### Code Quality

**Fix typo: rename 'merge_taks_info' to 'merge_tasks_info'** (commit e90c6fc8dd7a)
- **Author**: luffyluo
- **Impact**: Corrected function name typo in source code

## Other Changes

### Repository Maintenance

**gitignore: Exclude Serena and Claude Code metadata** (commit e95348b13861)
- **Author**: Wander Lairson Costa
- **Details**: Added `.serena` and `.claude` directories to `.gitignore` to prevent IDE-specific and AI-assisted development files from being tracked

## Contributors

- David Abdurachmanov (RISC-V support)
- luffyluo (typo fix)
- Wander Lairson Costa (build system improvements)
- Clark Williams (maintainer)

## Upgrade Notes

No configuration changes required. This is a build system improvement release that enhances cross-platform compatibility.

## Supported Architectures

With this release, stalld supports the following architectures:
- x86_64 (with eBPF support)
- aarch64 (with eBPF support)
- s390x (with eBPF support)
- **riscv64** (new in v1.26.1)
- i686 (sched_debug backend only)
- powerpc/ppc64le (sched_debug backend only)
