#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"

#ifndef ASM_VOLATILE
#define ASM_VOLATILE(...) asm volatile (__VA_ARGS__)
#endif

static void start_process (void *file_name_);
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool setup_stack_args (void **esp, int argc, char *argv[]);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name) {
    char *fn_copy;
    tid_t tid;

    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);

    if (tid != TID_ERROR) {
        struct thread *cur = thread_current();
        struct child_process *cp = malloc(sizeof(struct child_process));
        if (cp != NULL) {
            cp->tid = tid;
            cp->exit_status = 0;
            cp->exited = false;
            cp->load_success = false;
            sema_init(&cp->load_sema, 0);
            sema_init(&cp->exit_sema, 0);
            list_push_back(&cur->children, &cp->elem);
        }

        struct thread *child = get_thread_by_tid(tid);
        if (child != NULL) {
            child->parent = cur;
        }
    }

    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void *file_name_) {
    char *file_name = file_name_;
    struct intr_frame if_;
    bool success;

    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    /* Copy command line */
    char *save_ptr;
    char *cmd_line = palloc_get_page(0);
    if (cmd_line == NULL)
        thread_exit();
    strlcpy(cmd_line, file_name, PGSIZE);

    /* Parse program name */
    char *prog_name = strtok_r(cmd_line, " ", &save_ptr);

    success = load(prog_name, &if_.eip, &if_.esp);

    if (!success) {
        struct thread *cur = thread_current();
        if (cur->cp != NULL) {
            cur->cp->load_success = false;
            sema_up(&cur->cp->load_sema);
        }
        palloc_free_page(cmd_line);
        palloc_free_page(file_name);
        thread_exit();
    }

    /* After successful load: */
    struct thread *cur = thread_current();
    if (cur->cp != NULL) {
        cur->cp->load_success = true;
        sema_up(&cur->cp->load_sema);
    }

    /* Parse and push arguments */
    int argc = 0;
    char *argv[64];
    argv[argc++] = prog_name;
    char *token;
    while ((token = strtok_r(NULL, " ", &save_ptr)) && argc < 64)
        argv[argc++] = token;

    if (!setup_stack_args(&if_.esp, argc, argv)) {
        palloc_free_page(cmd_line);
        palloc_free_page(file_name);
        thread_exit();
    }

    palloc_free_page(cmd_line);
    palloc_free_page(file_name);

    ASM_VOLATILE("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

static bool setup_stack_args(void **esp, int argc, char *argv[]) {
    uint8_t *sp = (uint8_t *)PHYS_BASE;
    char *arg_ptrs[64];
    
    /* Validate argument count */
    if (argc < 0 || argc > 64)
        return false;

    /* Push arguments and collect pointers */
    for (int i = argc-1; i >= 0; i--) {
        if (!validate_string(argv[i]))
            return false;
            
        size_t len = strlen(argv[i]) + 1;
        if (sp - len < (uint8_t *)PHYS_BASE - (1 << 20))  // Don't grow stack too much
            return false;
            
        sp -= len;
        memcpy(sp, argv[i], len);
        arg_ptrs[i] = (char *)sp;
    }

    /* Align to 16-byte boundary (System V ABI requirement) */
    sp -= (uintptr_t)sp % 16;

    /* Push null sentinel */
    if (sp - sizeof(char *) < (uint8_t *)PHYS_BASE - (1 << 20))
        return false;
    sp -= sizeof(char *);
    *(char **)sp = NULL;

    /* Push argv pointers */
    for (int i = argc-1; i >= 0; i--) {
        if (sp - sizeof(char *) < (uint8_t *)PHYS_BASE - (1 << 20))
            return false;
        sp -= sizeof(char *);
        *(char **)sp = arg_ptrs[i];
    }

    /* Push argv address */
    char **argv_addr = (char **)sp;
    if (sp - sizeof(char **) < (uint8_t *)PHYS_BASE - (1 << 20))
        return false;
    sp -= sizeof(char **);
    *(char ***)sp = argv_addr;

    /* Push argc */
    if (sp - sizeof(int) < (uint8_t *)PHYS_BASE - (1 << 20))
        return false;
    sp -= sizeof(int);
    *(int *)sp = argc;

    /* Push fake return address */
    if (sp - sizeof(void *) < (uint8_t *)PHYS_BASE - (1 << 20))
        return false;
    sp -= sizeof(void *);
    *(void **)sp = 0;

    *esp = sp;
    return true;
}

/* Waits for thread TID to die and returns its exit status. */
int process_wait(tid_t child_tid) {
    struct thread *child = get_child_process(child_tid);
    if (child == NULL)
        return -1;

    struct child_process *cp = get_child_process(child_tid);
    if (cp == NULL) return -1;

    /* Wait for child to finish loading */
    sema_down(&cp->load_sema);
    if (!cp->load_success) {
        remove_child_process(cp);
        return -1;
    }

    /* Wait for child to exit */
    sema_down(&cp->exit_sema);
    int status = cp->exit_status;
    remove_child_process(cp);
    free(cp);
    return status;
}

/* Free the current process's resources. */
void process_exit(void) {
    struct thread *cur = thread_current();
    cur->exited = true;
    if (cur->parent != NULL) {
        struct child_process *cp = get_child_process(cur->tid);
        if (cp != NULL) {
            cp->exit_status = cur->exit_status;
            sema_up(&cp->exit_sema);
        }
    }

    /* Close all open files */
    for (int i = 0; i < MAX_FILES; i++) {
        if (cur->files[i] != NULL) {
            file_close(cur->files[i]);
            cur->files[i] = NULL;
        }
    }

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    if (cur->pagedir != NULL) {
        process_activate();
        pagedir_destroy(cur->pagedir);
        cur->pagedir = NULL;
    }
}

/* Sets up the CPU for running user code in the current
   thread. */
void process_activate(void) {
    struct thread *t = thread_current();

    /* Activate thread's page tables. */
    if (t->pagedir != NULL)
        pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update();
}

/* We load ELF binaries. The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim. */

/* ELF types. See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header. See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header. See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type. See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags. See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                        uint32_t read_bytes, uint32_t zero_bytes,
                        bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp) {
    struct thread *t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    if (t->pagedir == NULL)
        goto done;
    process_activate();

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }
    file_deny_write(file);

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
            || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
            || ehdr.e_type != 2
            || ehdr.e_machine != 3
            || ehdr.e_version != 1
            || ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
            || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint32_t file_page = phdr.p_offset & ~PGMASK;
                    uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint32_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                           Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                    } else {
                        /* Entirely zero.
                           Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *) mem_page,
                            read_bytes, zero_bytes, writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp))
        goto done;

    /* Start address. */
    *eip = (void (*)(void)) ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    file_close(file);
    return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                        uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **esp) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page(t->pagedir, upage) == NULL
            && pagedir_set_page(t->pagedir, upage, kpage, writable));
}