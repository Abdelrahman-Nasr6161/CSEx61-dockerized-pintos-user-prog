#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include <string.h>
#include <stdlib.h>
#include "syscall.h"
#include "threads/synch.h"
static void syscall_handler(struct intr_frame *);




void exit(int status);
struct used_file *get_file(int fd);
void exec(struct intr_frame *f); 
void wait(struct intr_frame *f);
void create(struct intr_frame *f);
void remove(struct intr_frame *f);
void open(struct intr_frame *f);
void size(struct intr_frame *f);
void read(struct intr_frame *f);
void write(struct intr_frame *f);
void seek(struct intr_frame *f);
void tell(struct intr_frame *f);
void close(struct intr_frame *f);
void syscall_init(void){
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

void
check_address(const void *t){
    if (t == NULL || !is_user_vaddr(t) || pagedir_get_page(thread_current()->pagedir, t) == NULL)
        exit(-1);
}

static void syscall_handler(struct intr_frame *f) {
    check_address(f->esp);
    int syscall_number = *((int *)(f->esp));
    switch(syscall_number) {
        case SYS_HALT:
            syscall_halt(f);
            break;
        case SYS_EXIT:
        {
            check_address(f->esp + 4);
            int status = *((int *)f->esp + 1);
            exit(status);
        }
            break;
        case SYS_EXEC:
            exec(f);
            break;
        case SYS_WAIT:
            wait(f);
            break;
        case SYS_CREATE:
            create(f);
            break;
        case SYS_REMOVE:
            remove(f);
            break;
        case SYS_OPEN:
            open(f);
            break;
        case SYS_FILESIZE:
            size(f);
            break;
        case SYS_READ:
            read(f);
            break;
        case SYS_WRITE:
            write(f);
            break;
        case SYS_SEEK:
            seek(f);
            break;
        case SYS_TELL:
            tell(f);
            break;
        case SYS_CLOSE:
            close(f);
            break;
        default:
            thread_exit();
            break;
    }
}

void syscall_halt() {
    shutdown_power_off();
}

void exec(struct intr_frame *f) {
    check_address(f->esp + 4);
    char *cmd_line = (char *)(*((int *)f->esp + 1));
    if (cmd_line == NULL) {
        exit(-1);
    }
    lock_acquire(&filesys_lock);
    f->eax = process_execute(cmd_line);
    lock_release(&filesys_lock);
}

struct used_file *get_file(int fd){
    struct thread *t = thread_current();
    for (struct list_elem *e = list_begin(&t->files); e != list_end(&t->files);e = list_next(e)){
        struct file_inode *opened = list_entry(e, struct file_inode, elem);
        if (opened->fd == fd)
            return opened;
    }
    return NULL;
}

void exit(int status) {
    struct thread *cur = thread_current()->parent;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    if (cur)
        cur->child_status = status;
    thread_exit();
}
 void wait(struct intr_frame *f) {
   check_address(f->esp + 4);
    int pid = (*((int *)f->esp + 1));
    f->eax = process_wait(pid);
}

void create(struct intr_frame *f) {
    check_address(f->esp + 4); 
    check_address(f->esp + 8);
    char *fileName = (char *)(*((uint32_t *)f->esp + 1));
    unsigned initial_size = *((unsigned *)f->esp + 2);
    if (fileName == NULL) {
        exit(-1);
    }
    lock_acquire(&filesys_lock);
    f->eax = filesys_create(fileName, initial_size);
    lock_release(&filesys_lock);
}

 void remove(struct intr_frame *f) {
    check_address(f->esp + 4);
    char *fileName = (char *)(*((uint32_t *)f->esp + 1));
    if (fileName == NULL) {
        exit(-1);
    }
    lock_acquire(&filesys_lock);
    f->eax = filesys_remove(fileName);
    lock_release(&filesys_lock);
}
void open(struct intr_frame *f) {
    check_address(f->esp + 4);
    char *fileName = (char *)(*((uint32_t *)f->esp + 1));
    if (fileName == NULL) 
        exit(-1);
    struct file_inode *fd_elem = palloc_get_page(0);
    if (fd_elem == NULL) {
        f->eax = -1;
        return;
    }
   lock_acquire(&filesys_lock);
    fd_elem->file = filesys_open(fileName);
    if (fd_elem->file == NULL) {
        lock_release(&filesys_lock);
        palloc_free_page(fd_elem);
        f->eax = -1; 
    } else {
        fd_elem->fd = ++thread_current()->fd;
        list_push_back(&thread_current()->files, &fd_elem->elem);
        f->eax = fd_elem->fd;
        lock_release(&filesys_lock);
    }
}
 void size(struct intr_frame *f) {
    check_address(f->esp + 4);
    int  fd = *((uint32_t *)f->esp + 1);;
    struct file_inode *fdObject = get_file(fd);
    if (fdObject->file == NULL) {
        f->eax = -1; 
    } else {
        lock_acquire(&filesys_lock);
        f->eax = file_length(fdObject->file);
        lock_release(&filesys_lock);
    }
}
void read(struct intr_frame *f) {
    check_address(f->esp + 4);
    check_address(f->esp + 8);
    check_address(f->esp + 12);
    int  fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    int size = *((int *)f->esp + 3);
    check_address(buffer+size);
    if (fd == 0) {
        for (int i = 0; i < size; i++) {
           lock_acquire(&filesys_lock);
            ((char*)buffer)[i] = input_getc();
            lock_release(&filesys_lock);
        }
        f->eax = size;
    } else {
        struct file_inode* fileToRead = get_file(fd);
        if (fileToRead->file == NULL) {
            f->eax = -1; 
        } else {
            lock_acquire(&filesys_lock);
            f->eax = file_read(fileToRead->file, buffer, size);
            lock_release(&filesys_lock);
        }
    }
}
void write(struct intr_frame *f) {
    check_address(f->esp + 4);
    check_address(f->esp + 8);
    check_address(f->esp + 12);
    int  fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    int size = *((int *)f->esp + 3);
    if (buffer ==NULL) 
        exit(-1);
    
    if (fd == 1) {
        lock_acquire(&filesys_lock);
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        f->eax = size;
    } else {
        struct file_inode *fileTowriteIn = get_file(fd);
        if (fileTowriteIn->file == NULL) {
            f->eax = -1; 
        } else {
            lock_acquire(&filesys_lock);
            f->eax = file_write(fileTowriteIn->file, buffer, size);
            lock_release(&filesys_lock);
        }
    }
}
void seek(struct intr_frame *f) {
    check_address(f->esp + 4);
    check_address(f->esp + 8);
    int fd = *((uint32_t *)f->esp + 1);
    int position = (*((unsigned *)f->esp + 2));
    struct file_inode *fileToSeek = get_file(fd);
    if (fileToSeek == NULL) 
        return; 

    lock_acquire(&filesys_lock);
    file_seek(fileToSeek->file, position);
    lock_release(&filesys_lock);
}
void tell(struct intr_frame *f) {
    check_address(f->esp + 4);
    int fd = *((uint32_t *)f->esp + 1);
    struct file_inode *fileToTell = get_file(fd);
    if (fileToTell->file == NULL) {
        f->eax = -1; 
    } else {
        lock_acquire(&filesys_lock);
        f->eax = file_tell(fileToTell->file);
        lock_release(&filesys_lock);
    }
}
void close(struct intr_frame *f) {
    check_address(f->esp + 4);
    int fd = *((uint32_t *)f->esp + 1);
    struct file_inode *fileToClose = get_file(fd);
    if (fileToClose->file == NULL)
        exit(-1);

    lock_acquire(&filesys_lock);
    file_close(fileToClose->file);
    lock_release(&filesys_lock);
    list_remove(&fileToClose->elem);
    palloc_free_page(fileToClose); 
}