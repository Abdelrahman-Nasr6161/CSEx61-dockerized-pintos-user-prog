#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Additional functions for parent-child process management */
struct thread *get_child_process (tid_t tid);
void remove_child_process (struct thread *child);
struct file *proccess_get_file(int fd);
#endif /* userprog/process.h */