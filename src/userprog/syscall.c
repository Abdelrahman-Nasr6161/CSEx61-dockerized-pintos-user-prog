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
bool validate_string(const char *uaddr);
int get_user_byte(const uint8_t *uaddr);
bool put_user(uint8_t *udst, uint8_t byte);
bool get_user(int *dst, const int *user_src);

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
            int user_ptr_raw;
            if (!get_user(&user_ptr_raw, args)) exit(-1);
            const char *cmd_line = (const char *)user_ptr_raw;

            if (!is_user_vaddr(cmd_line))
                exit(-1);

            validate_string(cmd_line);

            char *kcmd = palloc_get_page(0);
            if (!kcmd) exit(-1);
            strlcpy(kcmd, cmd_line, PGSIZE);

            f->eax = exec(kcmd);
            palloc_free_page(kcmd);
            break;
        }

        case SYS_WAIT: {
            int pid;
            if (!get_user(&pid, args)) exit(-1);
            f->eax = wait(pid);
            break;
        }

        case SYS_CREATE: {
            int file_ptr_raw, size;
            if (!get_user(&file_ptr_raw, args) || !get_user(&size, args + 1))
                exit(-1);
            const char *file = (const char *)file_ptr_raw;
            check_user_ptr(file);
            f->eax = create(file, size);
            break;
        }

        case SYS_REMOVE: {
            int file_ptr_raw;
            if (!get_user(&file_ptr_raw, args)) exit(-1);
            const char *file = (const char *)file_ptr_raw;
            check_user_ptr(file);
            f->eax = remove(file);
            break;
        }

        case SYS_OPEN: {
            int file_ptr_raw;
            if (!get_user(&file_ptr_raw, args)) exit(-1);
            const char *file = (const char *)file_ptr_raw;
            check_user_ptr(file);
            f->eax = open(file);
            break;
        }

        case SYS_FILESIZE: {
            int fd;
            if (!get_user(&fd, args)) exit(-1);
            f->eax = filesize(fd);
            break;
        }

        case SYS_READ: {
            int fd, buf_ptr_raw, size;
            if (!get_user(&fd, args) ||
                !get_user(&buf_ptr_raw, args + 1) ||
                !get_user(&size, args + 2))
                exit(-1);
            void *buffer = (void *)buf_ptr_raw;
            check_buffer(buffer, size);
            f->eax = read(fd, buffer, size);
            break;
        }

        case SYS_WRITE: {
            int fd, buf_ptr_raw, size;
            if (!get_user(&fd, args) ||
                !get_user(&buf_ptr_raw, args + 1) ||
                !get_user(&size, args + 2))
                exit(-1);
            const void *buffer = (const void *)buf_ptr_raw;
            check_buffer(buffer, size);
            f->eax = write(fd, buffer, size);
            break;
        }

        case SYS_SEEK: {
            int fd, position;
            if (!get_user(&fd, args) || !get_user(&position, args + 1))
                exit(-1);
            seek(fd, position);
            break;
        }

        case SYS_TELL: {
            int fd;
            if (!get_user(&fd, args)) exit(-1);
            f->eax = tell(fd);
            break;
        }

        case SYS_CLOSE: {
            int fd;
            if (!get_user(&fd, args)) exit(-1);
            close(fd);
            break;
        }

        default:
            exit(-1);
    }
}

/* Validation functions */
/* Validates a user string by checking each byte is accessible */
bool validate_string(const char *uaddr) {
    if (!uaddr) 
        return false;

    while (true) {
        uint8_t byte;
        // Check current byte is readable
        if (!get_user(&byte, (const uint8_t*)uaddr))
            return false;
            
        // Stop at null terminator
        if (byte == '\0')
            return true;
            
        uaddr++;
    }
}


static void check_user_ptr(const void *ptr) {
    if (ptr == NULL || !is_user_vaddr(ptr) || !pagedir_get_page(thread_current()->pagedir, ptr)) {
        exit(-1);
    }
}

static void check_buffer(const void *buffer, unsigned size) {
    char *check_valid = (char *) buffer;
    for (unsigned i = 0; i < size; i++) {
        check_user_ptr(check_valid++);
    }
}

int get_user_byte(const uint8_t *uaddr) {
    int result;
    asm ("movl $1f, %0\n"
         "movzbl %1, %0\n"
         "1:"
         : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   Returns true if successful, false if a segfault occurred. */
bool put_user(uint8_t *udst, uint8_t byte) {
    int error_code;
    asm ("movl $1f, %0\n"
         "movb %b2, %1\n"
         "1:"
         : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

bool get_user(int *dst, const int *user_src) {
    // Check each byte in the user_src's range to ensure accessibility
    for (size_t i = 0; i < sizeof(int); i++) {
        uint8_t *byte_addr = (uint8_t *)user_src + i;
        if (!is_user_vaddr(byte_addr) || 
            !pagedir_get_page(thread_current()->pagedir, byte_addr)) {
            return false;
        }
    }
    // Copy the value from user to kernel memory
    *dst = *user_src;
    return true;
}




/* System call implementations */
static void halt(void) {
    shutdown_power_off();
}

static void exit(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status);
    
    /* Notify parent if we're a child process */
        if (cur->parent != NULL) {
        struct child_process *cp = get_child_process(cur->tid);
        if (cp != NULL) {
            cp->exit_status = status;
            cp->exited = true;
            sema_up(&cp->exit_sema);
        }
    }
    
    thread_exit();
}

static tid_t exec(const char *cmd_line) {
    validate_string(cmd_line);

    // Make a copy of the command in kernel memory
    char *cmd_copy = palloc_get_page(0);
    if (!cmd_copy) return -1;
    strlcpy(cmd_copy, cmd_line, PGSIZE);

    lock_acquire(&filesys_lock);
    tid_t tid = process_execute(cmd_copy);
    lock_release(&filesys_lock);

    // Free the copy
    palloc_free_page(cmd_copy);

    // Wait for child to finish loading
    struct thread *cur = thread_current();
    struct child_process *cp = get_child_process(tid);

    if (cp == NULL)
        return -1;

    // Wait for the child to finish loading
    sema_down(&cp->load_sema);

    if (!cp->load_success)
        return -1;

    return tid;
}


static int wait(tid_t pid) {
    return process_wait(pid);
}

static bool create(const char *file, unsigned initial_size) {
    validate_string(file);
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

static bool remove(const char *file) {
    validate_string(file);
    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);
    return success;
}

static int open(const char *file) {
    validate_string(file);
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
    unsigned pos = f ? file_tell(f) : (unsigned)-1;
    lock_release(&filesys_lock);
    return pos;
}

static void close(int fd) {
    lock_acquire(&filesys_lock);
    process_close_file(fd);
    lock_release(&filesys_lock);
}