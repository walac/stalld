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

ALL_BINS := test01 $(UNIT_TESTS) $(HELPER_BINS)

.PHONY: all clean test test-unit test-functional test-integration

all: $(ALL_BINS)

# Original test
test01: test01.c
	$(CC) $(CFLAGS) -o test01 test01.c $(LIBS)

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
test-unit: $(UNIT_TESTS) test01
	@echo "Running unit tests..."
	@./run_tests.sh --unit-only

test-functional: $(HELPER_BINS)
	@echo "Running functional tests..."
	@./run_tests.sh --functional-only

test-integration: all
	@echo "Running integration tests..."
	@./run_tests.sh --integration-only

clean:
	@rm -f $(ALL_BINS)
	@rm -rf results/
	@rm -f *~ unit/*~ functional/*~ integration/*~ helpers/*~
	@rm -f *.o unit/*.o helpers/*.o
