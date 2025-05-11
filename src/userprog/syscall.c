#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static void check_user_ptr (const void *ptr);
static void halt (void);
static void exit (int status);

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
      
    /* Stubs for other system calls that will be implemented by other team members */
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_CREATE:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ:
    case SYS_WRITE:
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE:
      /* Placeholder for other system calls */
      printf("System call not yet implemented: %d\n", syscall_number);
      exit(-1);
      break;
      
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
    
  /* Additional check could be added here to verify that the address is mapped
     in the page directory, but that would require thread manipulation */
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
  
  /* Store exit status for parent process if it waits */
  /* This will be expanded when implementing parent-child relationships */
  
  /* Terminate this process */
  thread_exit();
}