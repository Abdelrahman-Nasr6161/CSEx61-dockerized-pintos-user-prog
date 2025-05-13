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
#include "filesys/off_t.h"

static void syscall_handler (struct intr_frame *);
static void check_user_ptr (const void *ptr);
static void check_buffer (const void *buffer, unsigned size);

/* System call implementations */
static void halt (void);
static void exit (int status);
static tid_t exec (const char *cmd_line);
static int wait (tid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

/* File system lock */
static struct lock filesys_lock;

/* Initialize system call infrastructure. */
void
syscall_init (void) 
{
    lock_init(&filesys_lock);
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Handles system calls. */
static void
syscall_handler (struct intr_frame *f) 
{
    /* Check if stack pointer is valid */
    check_user_ptr((const void *) f->esp);
    
    /* Get the system call number */
    int syscall_number = *(int *) f->esp;
    
    /* Arguments for system calls */
    int *args = ((int *) f->esp) + 1;
    
    /* Handle the system call based on its number */
    switch (syscall_number) 
    {
        case SYS_HALT:
            halt();
            break;
            
        case SYS_EXIT:
            check_user_ptr((const void *) args);
            exit(args[0]);
            break;
            
        case SYS_EXEC:
            check_user_ptr((const void *) args);
            f->eax = exec((const char *) args[0]);
            break;
            
        case SYS_WAIT:
            check_user_ptr((const void *) args);
            f->eax = wait(args[0]);
            break;
            
        case SYS_CREATE:
            check_user_ptr((const void *) args);
            check_user_ptr((const void *) (args + 1));
            f->eax = create((const char *) args[0], (unsigned) args[1]);
            break;
            
        case SYS_REMOVE:
            check_user_ptr((const void *) args);
            f->eax = remove((const char *) args[0]);
            break;
            
        case SYS_OPEN:
            check_user_ptr((const void *) args);
            f->eax = open((const char *) args[0]);
            break;
            
        case SYS_FILESIZE:
            check_user_ptr((const void *) args);
            f->eax = filesize(args[0]);
            break;
            
        case SYS_READ:
            check_user_ptr((const void *) args);
            check_user_ptr((const void *) (args + 1));
            check_user_ptr((const void *) (args + 2));
            f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
            break;
            
        case SYS_WRITE:
            check_user_ptr((const void *) args);
            check_user_ptr((const void *) (args + 1));
            check_user_ptr((const void *) (args + 2));
            f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
            break;
            
        case SYS_SEEK:
            check_user_ptr((const void *) args);
            check_user_ptr((const void *) (args + 1));
            seek(args[0], (unsigned) args[1]);
            break;
            
        case SYS_TELL:
            check_user_ptr((const void *) args);
            f->eax = tell(args[0]);
            break;
            
        case SYS_CLOSE:
            check_user_ptr((const void *) args);
            close(args[0]);
            break;
            
        default:
            printf("Invalid system call number: %d\n", syscall_number);
            exit(-1);
            break;
    }
}

/* Verifies that pointer is in user space and is mapped.
   If not, terminates the current process. */
static void
check_user_ptr (const void *ptr)
{
    if (ptr == NULL || !is_user_vaddr(ptr) || 
        !pagedir_get_page(thread_current()->pagedir, ptr))
        exit(-1);
}

/* Verifies that buffer is entirely in user space and mapped */
static void
check_buffer (const void *buffer, unsigned size)
{
    for (unsigned i = 0; i < size; i++) {
        check_user_ptr((const char *)buffer + i);
    }
}

/* System call implementations */

/* Terminates Pintos by calling shutdown_power_off() */
static void
halt (void)
{
    shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel */
static void
exit (int status)
{
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status);
    process_exit();
}

/* Starts a new process running the executable whose name is given in CMD_LINE.
   Returns the new process's process id (pid), or -1 if the process cannot be created. */
static tid_t
exec (const char *cmd_line)
{
    check_user_ptr(cmd_line);
    return process_execute(cmd_line);
}

/* Waits for a child process with PID to die and returns its exit status.
   If PID is still alive, waits until it terminates. Returns -1 immediately
   if PID is invalid or if the calling process is not PID's parent. */
static int
wait (tid_t pid)
{
    return process_wait(pid);
}

/* File operations */

/* Creates a new file called FILE initially INITIAL_SIZE bytes in size.
   Returns true if successful, false otherwise. */
static bool
create (const char *file, unsigned initial_size)
{
    check_user_ptr(file);
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

/* Deletes the file called FILE.
   Returns true if successful, false otherwise. */
static bool
remove (const char *file)
{
    check_user_ptr(file);
    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);
    return success;
}

/* Opens the file called FILE.
   Returns the new file descriptor, or -1 if the file could not be opened. */
static int
open (const char *file)
{
    check_user_ptr(file);
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int fd = process_add_file(f);
    if (fd == -1)
        file_close(f);
    lock_release(&filesys_lock);
    return fd;
}

/* Returns the size in bytes of the file open as FD. */
static int
filesize (int fd)
{
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int size = file_length(f);
    lock_release(&filesys_lock);
    return size;
}

/* Reads SIZE bytes from FD into BUFFER.
   Returns the number of bytes actually read (0 at end of file),
   or -1 if the file could not be read (or if the BUFFER is invalid). */
static int
read (int fd, void *buffer, unsigned size)
{
    check_buffer(buffer, size);
    
    if (fd == STDIN_FILENO) {
        for (unsigned i = 0; i < size; i++)
            ((char *)buffer)[i] = input_getc();
        return size;
    }
    
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int bytes_read = file_read(f, buffer, size);
    lock_release(&filesys_lock);
    return bytes_read;
}

/* Writes SIZE bytes from BUFFER to FD.
   Returns the number of bytes actually written, or -1 if the
   file could not be written (or if the BUFFER is invalid). */
static int
write (int fd, const void *buffer, unsigned size)
{
    check_buffer(buffer, size);
    
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        return size;
    }
    
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (f == NULL || f->deny_write) {
        lock_release(&filesys_lock);
        return -1;
    }
    int bytes_written = file_write(f, buffer, size);
    lock_release(&filesys_lock);
    return bytes_written;
}

/* Changes the next byte to be read or written in FD to POSITION. */
static void
seek (int fd, unsigned position)
{
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (f != NULL)
        file_seek(f, position);
    lock_release(&filesys_lock);
}

/* Returns the position of the next byte to be read or written in FD. */
static unsigned
tell (int fd)
{
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    unsigned position = file_tell(f);
    lock_release(&filesys_lock);
    return position;
}

/* Closes file descriptor FD. */
static void
close (int fd)
{
    lock_acquire(&filesys_lock);
    process_close_file(fd);
    lock_release(&filesys_lock);
}