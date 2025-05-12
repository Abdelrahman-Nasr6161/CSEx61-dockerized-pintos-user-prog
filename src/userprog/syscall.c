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
static void halt (void);
static void exit (int status);
static tid_t exec (const char *cmd_line);
static int wait (tid_t pid);
static struct lock filesys_lock;
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
/* Initialize system call infrastructure. */
void
syscall_init (void) 
{
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
    case SYS_READ:
      check_user_ptr((const void *) args);
      check_user_ptr((const void *) (args+1));
      check_user_ptr((const void *) (args+2));
      f->eax = read(args[0],(void * ) args[1] , (unsigned) args[2]);
      break;
    case SYS_WRITE:
      check_user_ptr((const void *) args);
      check_user_ptr((const void *) (args+1));
      check_user_ptr((const void *) (args+2));
      f->eax = write(args[0] , (void *) args[1] , (unsigned) args[2]);
      break;
    /* Stubs for other system calls */
    case SYS_CREATE:
      check_user_ptr((const void *) args);
      check_user_ptr((const void *) args+1);
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
    case SYS_SEEK:
      check_user_ptr((const void *) args);
      check_user_ptr((const void *) args+1);
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
      /* Placeholder for other system calls */
      // printf("System call not yet implemented: %d\n", syscall_number);
      // exit(-1);
      // break;
      
    default:
      /* Invalid system call */
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
  /* Check if pointer is null */
  if (ptr == NULL)
    exit(-1);
    
  /* Check if pointer is in user space */
  if (!is_user_vaddr(ptr))
    exit(-1);
    
  /* Verify that the address is mapped in the page directory */
  if (!pagedir_get_page(thread_current()->pagedir, ptr))
    exit(-1);
}

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
  
  /* Print process termination message with status */
  printf("%s: exit(%d)\n", cur->name, status);
  
  /* Store exit status for parent process */
  cur->exit_status = status;
  
  /* Notify parent if it's waiting */
  if (cur->parent != NULL) 
  {
    sema_up(&cur->parent->child_wait_sema);
  }
  
  /* Close all open files */
  for (int i = 0; i < cur->MAX_FILES; i++) 
  {
    if (cur->files[i] != NULL) 
    {
      file_close(cur->files[i]);
      cur->files[i] = NULL;
    }
  }
  
  /* Free resources */
  process_exit();
  
  /* Terminate this process */
  thread_exit();
}

/* Starts a new process running the executable whose name is given in CMD_LINE.
   Returns the new process's process id (pid), or -1 if the process cannot be created. */
static tid_t
exec (const char *cmd_line)
{
  check_user_ptr(cmd_line);
  
  /* Create a new process */
  tid_t tid = process_execute(cmd_line);
  
  if (tid == TID_ERROR)
    return -1;
  
  /* Find the child thread and set up parent-child relationship */
  struct thread *child = get_child_process(tid);
  if (child == NULL)
    return -1;
  
  child->parent = thread_current();
  
  return tid;
}

/* Waits for a child process with PID to die and returns its exit status.
   If PID is still alive, waits until it terminates. Returns -1 immediately
   if PID is invalid or if the calling process is not PID's parent. */
static int
wait (tid_t pid)
{
  struct thread *child = get_child_process(pid);
  struct thread *cur = thread_current();
  
  /* Check if PID is valid and is our child */
  if (child == NULL || child->parent != cur)
    return -1;
  
  /* Wait for child to exit */
  sema_down(&cur->child_wait_sema);
  
  /* Get child's exit status */
  int status = child->exit_status;
  
  /* Remove child from process list */
  remove_child_process(child);
  
  return status;
}
off_t
read (int fd, void *buffer, unsigned size) {
  check_buffer(buffer, size);
  if (fd == 0) {
    for (unsigned i = 0; i < size; i++) {
      ((char *) buffer)[i] = input_getc();
    }
    return size;
  } else if (fd == 1 || fd < 0) {
    return -1;
  } else {
    struct file *f = process_get_file(fd);
    if (f == NULL) return -1;
    sema_down(&f->lock);
    off_t bytes = file_read(f, buffer, size);
    sema_up(&f->lock);
    return bytes;
  }
}

off_t
write (int fd, const void *buffer, unsigned size) {
  check_buffer(buffer, size);
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  } else if (fd == 0 || fd < 0) {
    return -1;
  } else {
    struct file *f = process_get_file(fd);
    if (f == NULL || f->deny_write)
      return -1;
    sema_down(&f->lock);
    off_t bytes = file_write(f, buffer, size);
    sema_up(&f->lock);
    return bytes;
  }
}
void check_buffer(const void *buffer, unsigned size) {
  for (unsigned i = 0; i < size; i++) {
    check_user_ptr((const char *)buffer + i);
  }
}

bool 
create (const char *file, unsigned initial_size){
  check_user_ptr(file);
  lock_acquire(&filesys_lock);
  bool created = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return created;
}
bool
remove (const char *file){
  check_user_ptr(file);
  lock_acquire(&filesys_lock);
  bool removed = filesys_remove(file);
  lock_release(&filesys_lock);
  return removed;
}
int
open (const char *file){
  check_user_ptr(file);
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  int fd = process_add_file(f);
  if (fd == -1) {
    file_close(f);
  }
  lock_release(&filesys_lock);
  return fd;
}
int
filesize (int fd){
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if(f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  int size = file_length(f);
  lock_release(&filesys_lock);
  return size;
}
void
seek (int fd, unsigned position){
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (f == NULL) {
    lock_release(&filesys_lock);
    return;
  }
  file_seek(f, position);
  lock_release(&filesys_lock);
}
unsigned
tell (int fd){
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  int curr_position = file_tell(f);
  lock_release(&filesys_lock);
  return curr_position;
}
void
close (int fd){
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (f == NULL) {
    lock_release(&filesys_lock);
    return;
  }
  close_handler(fd);
  file_close(f);
  lock_release(&filesys_lock);
}
