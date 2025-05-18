#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
static struct lock filesys_lock;
void check_address(const void *ptr);

void check_valid_address(const void* pt);   // Check if the address is valid.

void exit(int status);

#endif /* userprog/syscall.h */