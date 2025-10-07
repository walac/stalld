# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for stalld test suite
#
CC	:= gcc
CFLAGS	:= -g -Wall -pthread
LIBS	:= -lpthread

# Test binaries
UNIT_TESTS :=
HELPER_BINS := helpers/starvation_gen
LEGACY_TESTS := legacy/test01

ALL_BINS := $(LEGACY_TESTS) $(UNIT_TESTS) $(HELPER_BINS)

.PHONY: all clean test test-unit test-functional test-integration test-legacy

all: $(ALL_BINS)

# Legacy tests
legacy/test01: legacy/test01.c
	@mkdir -p legacy
	$(CC) $(CFLAGS) -o legacy/test01 legacy/test01.c $(LIBS)

# Unit tests
unit/test_%: unit/test_%.c
	@mkdir -p unit
	$(CC) $(CFLAGS) -I../src -o $@ $< $(LIBS)

# Helper binaries
helpers/starvation_gen: helpers/starvation_gen.c
	@mkdir -p helpers
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Run all tests
test: all
	@echo "Running test suite..."
	@./run_tests.sh

# Run specific test category
test-unit: $(UNIT_TESTS)
	@echo "Running unit tests..."
	@./run_tests.sh --unit-only

test-functional: $(HELPER_BINS)
	@echo "Running functional tests..."
	@./run_tests.sh --functional-only

test-integration: all
	@echo "Running integration tests..."
	@./run_tests.sh --integration-only

test-legacy: $(LEGACY_TESTS)
	@echo "Running legacy tests..."
	@./run_tests.sh --unit-only

clean:
	@rm -f $(ALL_BINS)
	@rm -rf results/
	@rm -f *~ unit/*~ functional/*~ integration/*~ helpers/*~ legacy/*~
	@rm -f *.o unit/*.o helpers/*.o legacy/*.o
