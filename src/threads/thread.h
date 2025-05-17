#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"

/* Thread identifier type. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Maximum number of open files per process */
#define MAX_FILES 128
#ifndef NO_RETURN
#define NO_RETURN __attribute__((noreturn))
#endif

/* States in a thread's life cycle. */
enum thread_status {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
};

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                 /* Default priority. */
#define PRI_MAX 63                     /* Highest priority. */

struct child_process {
    tid_t tid;
    int exit_status;
    bool exited;
    bool load_success;
    struct semaphore load_sema;
    struct semaphore exit_sema;
    struct list_elem elem;
};


/* A kernel thread or user process. */
struct thread
{
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /* Process management */
    struct list children;               /* List of child processes */
    struct child_process *cp;  // used for exec/wait
    struct semaphore child_wait_sema;   /* Semaphore for waiting on child exit */
    int exit_status;                    /* Exit status of the process */
    bool exited;                        /* Whether the process has exited */
    struct thread *parent;              /* Parent thread */
    tid_t parent_tid;

    /* File management */
    struct file *files[MAX_FILES];      /* Array of open files */
    int next_fd;                        /* Next available file descriptor */

    /* Memory management */
    uint32_t *pagedir;                  /* Page directory */

    unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

/* Process management helpers */
struct child_process *get_child_process(tid_t tid);
void remove_child_process(struct child_process *child);

/* File descriptor management */
struct file *process_get_file(int fd);
int process_add_file(struct file *f);
void process_close_file(int fd);

/* Helper function to get thread by tid */
struct thread *get_thread_by_tid(tid_t tid);

#endif /* THREADS_THREAD_H */