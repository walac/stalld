#define OLD_TASK_FORMAT  1
#define NEW_TASK_FORMAT  2
#define TASK_MARKER	"runnable tasks:"

int sched_debug_init(void);
int sched_debug_get(char *buffer, int size);
int sched_debug_parse(struct cpu_info *cpu_info, char *buffer, size_t buffer_size);
int sched_debug_has_starving_task(struct cpu_info *cpu);
void sched_debug_destroy(void);
