/*
 * starvation_gen.c - Controllable starvation generator for testing stalld
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2025 Red Hat Inc
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

struct config {
	int cpu;
	int blocker_priority;
	int num_blockees;
	int duration;
	int verbose;
};

static struct config cfg = {
	.cpu = -1,
	.blocker_priority = 10,
	.num_blockees = 1,
	.duration = 30,
	.verbose = 0
};

volatile int running = 1;

void *blocker_thread(void *arg) {
	if (cfg.verbose)
		printf("[blocker] Started on CPU %d with priority %d\n", cfg.cpu, cfg.blocker_priority);

	/* Busy loop to monopolize CPU */
	while (running) {
		/* Intentionally empty - monopolize CPU */
	}

	if (cfg.verbose)
		printf("[blocker] Exiting\n");

	return NULL;
}

void *blockee_thread(void *arg) {
	int id = *(int*)arg;

	if (cfg.verbose)
		printf("[blockee %d] Started - will starve\n", id);

	/* Try to run but will be starved by blocker */
	while (running) {
		usleep(1000);  /* Try to sleep but will be preempted */
	}

	if (cfg.verbose)
		printf("[blockee %d] Exiting\n", id);

	return NULL;
}

void signal_handler(int sig) {
	printf("\nReceived signal %d, exiting...\n", sig);
	running = 0;
}

void usage(void) {
	printf("Usage: starvation_gen [OPTIONS]\n");
	printf("Generate controlled starvation conditions for testing stalld\n\n");
	printf("Options:\n");
	printf("  -c, --cpu N              CPU to use for test (default: auto-select)\n");
	printf("  -p, --priority N         SCHED_FIFO priority for blocker (default: 10)\n");
	printf("  -n, --num-blockees N     Number of blockee threads (default: 1)\n");
	printf("  -d, --duration N         Duration in seconds (default: 30)\n");
	printf("  -v, --verbose            Verbose output\n");
	printf("  -h, --help               Show this help\n");
	printf("\nExample:\n");
	printf("  starvation_gen -c 2 -p 15 -n 3 -d 60 -v\n");
	printf("  (Create starvation on CPU 2 with 1 blocker at priority 15 and 3 blockees for 60 seconds)\n");
}

int pick_cpu(void) {
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	/* Pick last CPU */
	return num_cpus - 1;
}

int main(int argc, char **argv) {
	pthread_t blocker;
	pthread_t *blockees = NULL;
	cpu_set_t cpuset;
	struct sched_param param;
	pthread_attr_t attr;
	int *blockee_ids = NULL;
	int i, ret;

	struct option long_options[] = {
		{"cpu",          required_argument, 0, 'c'},
		{"priority",     required_argument, 0, 'p'},
		{"num-blockees", required_argument, 0, 'n'},
		{"duration",     required_argument, 0, 'd'},
		{"verbose",      no_argument,       0, 'v'},
		{"help",         no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	/* Parse command line */
	while (1) {
		int option_index = 0;
		int c = getopt_long(argc, argv, "c:p:n:d:vh", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'c':
			cfg.cpu = atoi(optarg);
			break;
		case 'p':
			cfg.blocker_priority = atoi(optarg);
			break;
		case 'n':
			cfg.num_blockees = atoi(optarg);
			break;
		case 'd':
			cfg.duration = atoi(optarg);
			break;
		case 'v':
			cfg.verbose = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			usage();
			exit(1);
		}
	}

	/* Auto-select CPU if not specified */
	if (cfg.cpu == -1)
		cfg.cpu = pick_cpu();

	/* Validate parameters */
	if (cfg.blocker_priority < 1 || cfg.blocker_priority > 99) {
		fprintf(stderr, "Error: blocker priority must be 1-99\n");
		exit(1);
	}

	if (cfg.num_blockees < 1 || cfg.num_blockees > 10) {
		fprintf(stderr, "Error: num_blockees must be 1-10\n");
		exit(1);
	}

	/* Setup signal handler */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Initialize pthread attributes */
	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_init failed: %s\n", strerror(ret));
		exit(1);
	}

	ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_setinheritsched failed: %s\n", strerror(ret));
		exit(1);
	}

	/* Set CPU affinity */
	CPU_ZERO(&cpuset);
	CPU_SET(cfg.cpu, &cpuset);
	ret = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_setaffinity_np failed: %s\n", strerror(ret));
		exit(1);
	}

	/* Setup blocker thread */
	ret = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_setschedpolicy failed: %s\n", strerror(ret));
		exit(1);
	}

	param.sched_priority = cfg.blocker_priority;
	ret = pthread_attr_setschedparam(&attr, &param);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_setschedparam failed: %s\n", strerror(ret));
		exit(1);
	}

	ret = pthread_create(&blocker, &attr, blocker_thread, NULL);
	if (ret != 0) {
		fprintf(stderr, "pthread_create (blocker) failed: %s\n", strerror(ret));
		exit(1);
	}

	/* Setup blockee threads */
	blockees = malloc(cfg.num_blockees * sizeof(pthread_t));
	blockee_ids = malloc(cfg.num_blockees * sizeof(int));
	if (!blockees || !blockee_ids) {
		fprintf(stderr, "malloc failed\n");
		exit(1);
	}

	ret = pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_setschedpolicy (blockee) failed: %s\n", strerror(ret));
		exit(1);
	}

	param.sched_priority = 0;
	ret = pthread_attr_setschedparam(&attr, &param);
	if (ret != 0) {
		fprintf(stderr, "pthread_attr_setschedparam (blockee) failed: %s\n", strerror(ret));
		exit(1);
	}

	for (i = 0; i < cfg.num_blockees; i++) {
		blockee_ids[i] = i;
		ret = pthread_create(&blockees[i], &attr, blockee_thread, &blockee_ids[i]);
		if (ret != 0) {
			fprintf(stderr, "pthread_create (blockee %d) failed: %s\n", i, strerror(ret));
			exit(1);
		}
	}

	/* Print configuration */
	printf("Starvation generator started:\n");
	printf("  CPU:            %d\n", cfg.cpu);
	printf("  Blocker priority: %d\n", cfg.blocker_priority);
	printf("  Blockee threads:  %d\n", cfg.num_blockees);
	printf("  Duration:       %d seconds\n", cfg.duration);
	printf("  Blocker TID:    %ld\n", (long)blocker);
	for (i = 0; i < cfg.num_blockees; i++) {
		printf("  Blockee %d TID:   %ld\n", i, (long)blockees[i]);
	}
	printf("\nPress Ctrl+C to stop early\n");

	/* Run for specified duration */
	sleep(cfg.duration);

	/* Cleanup */
	running = 0;
	pthread_join(blocker, NULL);
	for (i = 0; i < cfg.num_blockees; i++) {
		pthread_join(blockees[i], NULL);
	}

	free(blockees);
	free(blockee_ids);
	pthread_attr_destroy(&attr);

	printf("Starvation generator completed\n");
	return 0;
}
