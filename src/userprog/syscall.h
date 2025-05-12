#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/file.h"
#include "filesys/off_t.h"
void syscall_init (void);
/* Prototypes for file system functions */
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
off_t file_read(struct file *f, void *buffer, off_t size);
off_t file_write(struct file *f, const void *buffer, off_t size);
struct file *process_get_file(int fd);
void file_close(struct file *f);
uint8_t input_getc(void);  // Correct the return type to uint8_t
int process_add_file(struct file *f);
void close_handler(int fd);
#endif /* userprog/syscall.h */
