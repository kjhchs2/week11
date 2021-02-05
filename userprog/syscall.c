#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void get_argument(intptr_t rsp, intptr_t *arg, int count);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);

/* ssystem call */
tid_t exec(const char *cmd_line);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
    uintptr_t *cmd;
    uintptr_t rsp = f->rsp;
    check_address(rsp);
    int syscall_n = *(int *)f->rsp;

    hex_dump(f->rsp, (void *)(f->rsp), 300, 1);

    switch (syscall_n)
    {
    case SYS_EXEC:
        get_argument(rsp, cmd, 1);
        check_address((void *)cmd[0]);
        // 아닐 수도 있음
        *(int *)f->R.rax = exec((const char *)cmd[0]);
        /*
        *
        * 
        * 
        * */
        break;
    default:
        thread_exit();
    }
}

tid_t exec(const char *cmd_line)
{
    int success;
    success = process_create_initd(cmd_line);
    return success;
}

void get_argument(intptr_t rsp, intptr_t *arg, int count)
{
    for (int i = 0; i < count; i++)
    {
        arg[i] = rsp + 8 * (i + 1);
    }
    return;
}

void check_address(void *addr)
{
    if ((intptr_t)addr > USER_STACK)
    {
        printf("invalid stack pointer access\n");
        thread_exit();
    }
}

void exit(int status)
{
    struct thread *cur = thread_current();
    /* 프로세스 디스크립터에 exit status 저장 */
    cur->exit_status = 0;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

void halt(void)
{
    power_off();
}

bool create(const char *file, unsigned initial_size)
{
    return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
    return filesys_remove(file);
}