/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022 Red Hat Inc, Daniel Bristot de Oliveira <bristot@kernel.org>
 */

#include "vmlinux.h"
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../src/queue_track.h"

#ifndef TASK_RUNNING
#define TASK_RUNNING 0
#endif

/*
 * bpf_helpers.h might not be updated to have barrier, yet.
 */
#ifndef barrier
#define barrier() asm volatile("" ::: "memory")
#endif
/*
 * It is not a per-cpu data because a remote CPU can enqueue a
 * task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	/* it will be resized */
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct stalld_cpu_data);
} stalld_per_cpu_data SEC(".maps");

#if DEBUG_STALLD
#define log(msg, ...) bpf_printk("%s: " msg, __func__, ##__VA_ARGS__)
#else
#define log(msg, ...) do {} while(0)
#endif

#define log_task_prefix(prefix, p)			\
	log(prefix "%s(%d) pid=%d cpu=%d class=%s",	\
	    p->comm, p->tgid, p->pid, task_cpu(p),	\
	    task_is_rt(p) ? "rt" : "fair")

#define log_task(p) log_task_prefix("", p)
#define log_task_error(p) log_task_prefix("error: ", p)

/*
 * BPF CO-RE "weak" or "candidate" definition.
 *
 * This struct provides a definition for fields that may not exist in the
 * kernel headers used at compile time (e.g., the 'cpu' field was removed
 * from task_struct in modern kernels).
 *
 * Its sole purpose is to satisfy the compiler, allowing the BPF program to
 * build successfully. At runtime, the BPF loader uses the target kernel's BTF
 * (BPF Type Format) to perform a CO-RE (Compile Once - Run Everywhere)
 * relocation. The bpf_core_field_exists() check will correctly determine if
 * the field is actually present on the target system, making the program
 * portable across different kernel versions.
 */
struct task_struct___legacy {
	int cpu;
};

/**
 * task_is_rt - Check if a task is a real-time task.
 * @p: A pointer to the kernel's `task_struct` for the task.
 *
 * This function determines if a task belongs to a real-time (RT) scheduling
 * class based on its priority. In the Linux kernel, static priorities from
 * 0 to 99 are reserved for RT tasks (SCHED_FIFO and SCHED_RR), while
 * priorities from 100 to 139 are used for normal tasks (SCHED_NORMAL,
 * SCHED_BATCH, etc.).
 *
 * This check is essential for `stalld` to distinguish between high-priority
 * RT tasks that have strict scheduling deadlines and normal tasks.
 *
 * Return: `true` if the task has a real-time priority (0-99),
 *         `false` otherwise.
 */
static inline bool task_is_rt(const struct task_struct *p)
{
	return p->prio >= 0 && p->prio <= 99;
}

/**
 * task_cpu - Get the CPU number that a task is currently running on.
 * @p: A pointer to the kernel's `task_struct` for the task.
 *
 * This function retrieves the CPU identifier where the task is currently
 * scheduled.
 *
 * The CPU number is crucial for `stalld` to associate a task with the
 * correct per-CPU data map, ensuring that task tracking and starvation
 * analysis are performed in the right context.
 *
 * Return: The integer ID of the CPU the task is running on.
 */
static inline int task_cpu(const struct task_struct *p)
{
	const struct task_struct___legacy *lp = (const struct task_struct___legacy *) p;

	return bpf_core_field_exists(lp->cpu)
		? BPF_CORE_READ(lp, cpu)
		: BPF_CORE_READ(p, thread_info.cpu);
}

/**
 * compute_ctxswc - Compute the total context switch count for a task.
 * @p: A pointer to the `task_struct` (process descriptor) of the task.
 *
 * This function calculates the total number of context switches a task
 * has undergone by summing its voluntary and involuntary context switch
 * counts.
 *
 * The `nvcsw` (number of voluntary context switches) increments when a task
 * explicitly yields the CPU (e.g., waiting for I/O, sleeping, or blocking
 * on a lock).
 *
 * The `nivcsw` (number of involuntary context switches) increments when a task
 * is preempted by the scheduler (e.g., its timeslice expires, or a higher
 * priority task becomes runnable).
 *
 * The sum of these two counters provides a comprehensive measure of how many
 * times the task has been context-switched in and out of the CPU. This value
 * is crucial for tools like `stalld` to detect if a task has made progress
 * (i.e., has run at least once) since a previous observation.
 *
 * Return: The total context switch count (nvcsw + nivcsw) for the given task.
 */
static inline long compute_ctxswc(const struct task_struct *p)
{
	return p->nvcsw + p->nivcsw;
}

/**
 * Each CPU has its own set of statistics stored on a per-cpu
 * array, this function returns the variable of the current
 * CPU.
 */
static struct stalld_cpu_data *get_cpu_data(int cpu)
{
	struct stalld_cpu_data *stalld_data;
	u32 key = cpu;

	stalld_data = bpf_map_lookup_elem(&stalld_per_cpu_data, &key);

	if (stalld_data && stalld_data->monitoring)
		return stalld_data;

	return NULL;
}

static int enqueue_task(const struct task_struct *p, struct stalld_cpu_data *cpu_data)
{
	struct queued_task *task;
	const long pid = p->pid;

	for_each_task_entry(cpu_data, task) {
		if (task->pid == 0 || task->pid == pid) {
			task->ctxswc = compute_ctxswc(p);
			task->prio = p->prio;
			task->is_rt = task_is_rt(p);
			task->tgid = p->tgid;

			/*
			 * User reads pid to know that there is no data here.
			 * Update it last.
			 */
			barrier();
			task->pid = pid;
			log_task(p);
			return 0;
		}
	}

	log_task_error(p);

	return 0;
}

/**
 * dequeue_task - Removes a task from a CPU's queue.
 * @p:        Pointer to the task_struct of the task to remove.
 * @cpu_data: Pointer to the per-CPU data structure.
 *
 * This function finds and removes a task from the specified CPU's run queue.
 * It updates the appropriate counter (RT or non-RT) for the queued tasks.
 *
 * Return: 1 if the task was found and removed, 0 otherwise.
 */
static int dequeue_task(const struct task_struct *p, struct stalld_cpu_data *cpu_data)
{
	struct queued_task *task;
	long pid = p->pid;

	task = find_queued_task(cpu_data, pid);
	if (task) {
		task->pid = 0;
		log_task(p);
		return 1;
	}

	log_task_error(p);
	return 0;
}

/*
 * update_or_add_task - Manages a task's lifecycle within a per-CPU tracking queue.
 *
 * This function handles the logic for managing individual task entries within
 * stalld's BPF program. It dynamically adds, updates, or removes a task from a
 * specific CPU's tracking array based on its current state. This ensures the
 * array provides an accurate, real-time view of tasks on the run queue.
 *
 * The function's logic is organized into three primary scenarios:
 * 1.  Update: If a task is already tracked and is still in the TASK_RUNNING
 * state, its dynamic properties (context switch count, priority) are
 * refreshed.
 * 2.  Remove: If a tracked task is no longer in the TASK_RUNNING state
 * (e.g., it has gone to sleep or terminated), it is removed from the queue
 * by invalidating its entry (setting pid to 0).
 * 3.  Add: If a new, previously unseen task is encountered and is in the
 * TASK_RUNNING state, it is added to the first available empty slot in
 * the queue.
 *
 * Parameters:
 * cpu_data: A pointer to the `stalld_cpu_data` structure for the target CPU.
 * p:        A pointer to the kernel's `task_struct` for the task to be processed.
 */
static void update_or_add_task(struct stalld_cpu_data *cpu_data,
			       const struct task_struct *p)
{
	struct queued_task *task_entry;

	/* Try to find the task first */
	task_entry = find_queued_task(cpu_data, p->pid);
	if (task_entry) {
		if (p->__state == TASK_RUNNING) {
			/* Task found: Update its dynamic fields */
			task_entry->ctxswc = compute_ctxswc(p);
			task_entry->prio = p->prio;
			task_entry->is_rt = task_is_rt(p);
		} else {
			/* Task is not running. Remove it. */
			log_task_prefix("dequeue ", p);
			task_entry->pid = 0;
		}

		return;
	}

	/*
	 * If we reach here, the task was NOT found, so it's new.
	 * Check if the new task is in the `TASK_RUNNING` state before adding to queue.
	 */
	if (p->__state != TASK_RUNNING)
		return;

	/*
	 * Task not found and is running: find an empty slot to add it
	 * We iterate through all slots to find the first empty one.
	 */
	enqueue_task(p, cpu_data);
}

/**
 * __sched_wakeup - Common handler for task wakeup tracepoints.
 * @ctx: A pointer to the tracepoint context.
 *
 * This function serves as the common implementation for handling both
 * `sched_wakeup` and `sched_wakeup_new` tracepoints. It extracts the
 * task_struct from the context, determines its target CPU, and if that
 * CPU is being monitored, enqueues the task for tracking.
 *
 * This centralized approach avoids code duplication and provides a
 * single point of logic for task wakeup events.
 *
 * Return: Always returns 0.
 */
static int __sched_wakeup(u64 *ctx)
{
	const struct task_struct *p = (void *) ctx[0];
	struct stalld_cpu_data *cpu_data = get_cpu_data(task_cpu(p));

	if (cpu_data)
		update_or_add_task(cpu_data, p);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	return __sched_wakeup(ctx);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	return __sched_wakeup(ctx);
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64 *ctx)
{
	const struct task_struct *p = (void *) ctx[0];
	struct stalld_cpu_data *cpu_data = get_cpu_data(task_cpu(p));

	if (cpu_data)
		dequeue_task(p, cpu_data);

	return 0;
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	struct stalld_cpu_data *cpu_data = get_cpu_data(bpf_get_smp_processor_id());
	const struct task_struct *prev = (void *) ctx[1];
	const struct task_struct *next = (void *) ctx[2];

	if (!cpu_data)
		return 0;
	cpu_data->current = next->pid;

	cpu_data->nr_rt_running = task_is_rt(next);

	// update the context switch count of the tasks
	update_or_add_task(cpu_data, next);
	update_or_add_task(cpu_data, prev);

	return 0;
}

SEC("tp_btf/sched_migrate_task")
int handle__sched_migrate_task(u64 *ctx)
{
	const struct task_struct *p = (void *) ctx[0];
	const int dest_cpu = ctx[1];
	const int orig_cpu = task_cpu(p);
	struct stalld_cpu_data *cpu_data;

	cpu_data = get_cpu_data(orig_cpu);

	/*
	 * Dequeue the task from its original CPU and re-enqueue it on the
	 * destination CPU. This ensures its run queue state is tracked
	 * correctly across migrations. If the task was not found on the
	 * original CPU, there is no need to enqueue it on the new one, as
	 * it was not being monitored.
	 */
	if (cpu_data) {
		log("task=%s(%ld) orig=%d dest=%d",
		    p->comm, p->tgid, orig_cpu, dest_cpu);
		if (dequeue_task(p, cpu_data)) {
			cpu_data = get_cpu_data(dest_cpu);
			if (cpu_data)
				enqueue_task(p, cpu_data);
		}
	}

	return 0;
}

/**
 * iter_task - BPF iterator program for task enumeration
 * @ctx: Iterator context containing the current task
 *
 * This BPF iterator program walks through all tasks in the system and
 * provides visibility into their scheduling state. It's useful for getting
 * a system-wide snapshot of task states, complementing the event-driven
 * tracepoint programs that track dynamic task state changes.
 */
SEC("iter/task")
int iter_task(struct bpf_iter__task *ctx)
{
	const struct task_struct *p = ctx->task;
	struct stalld_cpu_data *cpu_data;

	if (!p)
		return 0;

	cpu_data = get_cpu_data(task_cpu(p));
	if (!cpu_data)
		return 0;

	log_task(p);

	if (p->__state == TASK_RUNNING)
		enqueue_task(p, cpu_data);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
