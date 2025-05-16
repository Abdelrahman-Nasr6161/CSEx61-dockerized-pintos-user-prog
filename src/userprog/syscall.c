#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);
static void check_user_ptr(const void *ptr);
static void check_buffer(const void *buffer, unsigned size);

/* System call implementations */
static void halt(void);
static void exit(int status);
static tid_t exec(const char *cmd_line);
static int wait(tid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);

/* File system lock */
struct lock filesys_lock;

void syscall_init(void) {
    lock_init(&filesys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f) {
    if (!is_user_vaddr(f->esp) || !pagedir_get_page(thread_current()->pagedir, f->esp)) {
        exit(-1);
    }

    int syscall_number;
    if (!get_user(&syscall_number, (int *)f->esp)) {
        exit(-1);
    }

    int *args = (int *)f->esp + 1;

    switch (syscall_number) {
        case SYS_HALT:
            halt();
            break;

        case SYS_EXIT: {
            int status;
            if (!get_user(&status, args)) exit(-1);
            exit(status);
            break;
        }

        case SYS_EXEC: {
        const char *cmd_line;
        if (!get_user(&cmd_line, args) || !is_user_vaddr(cmd_line)) 
            exit(-1);
        
        // Validate entire command line string
        validate_string(cmd_line);
        
        // Make a copy in kernel space
        char *kcmd = palloc_get_page(0);
        if (!kcmd) exit(-1);
        strlcpy(kcmd, cmd_line, PGSIZE);
        
        f->eax = exec(kcmd);
        palloc_free_page(kcmd);
        break;
    }

        case SYS_WAIT: {
            tid_t pid;
            if (!get_user(&pid, args)) exit(-1);
            f->eax = wait(pid);
            break;
        }

        case SYS_CREATE:
            check_user_ptr((const char *)args[0]);
            f->eax = create((const char *)args[0], (unsigned)args[1]);
            break;

        case SYS_REMOVE:
            check_user_ptr((const char *)args[0]);
            f->eax = remove((const char *)args[0]);
            break;

        case SYS_OPEN:
            check_user_ptr((const char *)args[0]);
            f->eax = open((const char *)args[0]);
            break;

        case SYS_FILESIZE:
            f->eax = filesize((int)args[0]);
            break;

        case SYS_READ:
            check_buffer((void *)args[1], (unsigned)args[2]);
            f->eax = read((int)args[0], (void *)args[1], (unsigned)args[2]);
            break;

        case SYS_WRITE:
            check_buffer((void *)args[1], (unsigned)args[2]);
            f->eax = write((int)args[0], (const void *)args[1], (unsigned)args[2]);
            break;

        case SYS_SEEK:
            seek((int)args[0], (unsigned)args[1]);
            break;

        case SYS_TELL:
            f->eax = tell((int)args[0]);
            break;

        case SYS_CLOSE:
            close((int)args[0]);
            break;

        default:
            exit(-1);
    }
}

/* Validation functions */
static void validate_string(const char *str) {
    if (str == NULL)
        exit(-1);
        
    while (true) {
        check_user_ptr(str);
        if (*str == '\0') break;
        str++;
    }
}

static void check_user_ptr(const void *ptr) {
    if (ptr == NULL || !is_user_vaddr(ptr) || !pagedir_get_page(thread_current()->pagedir, ptr)) {
        exit(-1);
    }
}

static void check_buffer(const void *buffer, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        check_user_ptr((const char *)buffer + i);
    }
}

/* System call implementations */
static void halt(void) {
    shutdown_power_off();
}

static void exit(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

static tid_t exec(const char *cmd_line) {
    validate_string(cmd_line);
    lock_acquire(&filesys_lock);
    tid_t tid = process_execute(cmd_line);
    lock_release(&filesys_lock);
    return tid;
}

static int wait(tid_t pid) {
    return process_wait(pid);
}

static bool create(const char *file, unsigned initial_size) {
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

static bool remove(const char *file) {
    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);
    return success;
}

static int open(const char *file) {
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int fd = process_add_file(f);
    lock_release(&filesys_lock);
    return fd;
}

static int filesize(int fd) {
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    int size = f ? file_length(f) : -1;
    lock_release(&filesys_lock);
    return size;
}

static int read(int fd, void *buffer, unsigned size) {
    check_buffer(buffer, size);
    
    if (fd == STDIN_FILENO) {
        for (unsigned i = 0; i < size; i++)
            ((char *)buffer)[i] = input_getc();
        return size;
    }

    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    int bytes_read = f ? file_read(f, buffer, size) : -1;
    lock_release(&filesys_lock);
    return bytes_read;
}

static int write(int fd, const void *buffer, unsigned size) {
    check_buffer(buffer, size);
    
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }

    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    int bytes_written = f ? file_write(f, buffer, size) : -1;
    lock_release(&filesys_lock);
    return bytes_written;
}

static void seek(int fd, unsigned position) {
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (f) file_seek(f, position);
    lock_release(&filesys_lock);
}

static unsigned tell(int fd) {
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    unsigned pos = f ? file_tell(f) : -1;
    lock_release(&filesys_lock);
    return pos;
}

static void close(int fd) {
    lock_acquire(&filesys_lock);
    process_close_file(fd);
    lock_release(&filesys_lock);
}