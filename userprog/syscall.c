#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *if_);
void get_argument(struct intr_frame *f, intptr_t *arg, int count);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(struct intr_frame *f, const char *thread_name);
tid_t exec(const char *cmd_line);
struct lock filesys_lock;

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
    lock_init(&filesys_lock);
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
    uintptr_t rsp = f->rsp;
    check_address(rsp);
    int syscall_n = f->R.rax;
    uintptr_t args[6];
    get_argument(f, args, 6);
    // printf("%d %d %d\n\n", f->R.rax, f->R.rsi, f->R.rdx);

    // hex_dump(f->rsp, (void *)(f->rsp), USER_STACK - f->rsp, 1);

    switch (syscall_n)
    {
    case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        exit(args[0]);
        break;
    case SYS_FORK:
        f->R.rax = fork(f, args[0]);
        break;
    case SYS_EXEC:
        check_address((void *)args[0]);
        f->R.rax = exec((const char *)args[0]);
        break;
    case SYS_WAIT:
        f->R.rax = wait(args[0]);
        break;
    case SYS_CREATE:
        f->R.rax = create(args[0], args[1]);
        break;
    case SYS_REMOVE:
        f->R.rax = remove(args[0]);
        break;
    case SYS_OPEN:
        f->R.rax = open(args[0]);
        break;
    case SYS_FILESIZE:
        f->R.rax = filesize(args[0]);
        break;
    case SYS_READ:
        f->R.rax = read(args[0], args[1], args[2]);
        break;
    case SYS_WRITE:
        f->R.rax = write(args[0], args[1], args[2]);
        break;
    case SYS_SEEK:
        seek(args[0], args[1]);
        break;
    case SYS_TELL:
        f->R.rax = tell(args[0]);
        break;
    case SYS_CLOSE:
        close(args[0]);
        break;
    case SYS_DUP2:
        // dup2(args[0], args[1]);
        break;
    case SYS_MOUNT:
        // mmap(args[0], args[1], args[2], args[3], args[4]);
        break;
    case SYS_UMOUNT:
        // munmap(args[0]);
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

tid_t fork(struct intr_frame *f, const char *thread_name)
{
    tid_t tid;
    if ((tid = process_fork(thread_name, f)) == TID_ERROR)
    {
        return TID_ERROR;
    };
    return tid;
}

int wait(tid_t pid)
{
    return process_wait(pid);
}

void get_argument(struct intr_frame *f, intptr_t *arg, int count)
{
    arg[0] = f->R.rdi;
    arg[1] = f->R.rsi;
    arg[2] = f->R.rdx;
    arg[3] = f->R.r10;
    arg[4] = f->R.r8;
    arg[5] = f->R.r9;
    return;
}

void check_address(void *addr)
{
    if ((intptr_t)addr > USER_STACK)
    {
        thread_exit();
    }
}

void exit(int status)
{
    struct thread *cur = thread_current();
    /* 프로세스 디스크립터에 exit status 저장 */
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

void halt(void)
{
    power_off();
}

bool create(const char *file, unsigned initial_size)
{
    if ((intptr_t)file > USER_STACK || file == NULL || strlen(file) == 0)
    {
        exit(-1);
    }
    if (strlen(file) >= 14)
    {
        return 0;
    }
    struct dir *d = dir_open_root();
    struct inode **in;

    if (dir_lookup(d, file, in))
    {
        return 0;
    }
    return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
    return filesys_remove(file);
}

int open(const char *file)
{
    struct file *new_file;
    int fd;
    struct thread *cur_t = thread_current();

    struct dir *dir = dir_open_root();
    struct inode *new = NULL;
    if (file == NULL)
    {
        return -1;
    }

    new_file = filesys_open(file);
    for (int i = 2; i < cur_t->fd_num; i++)
    {
        if (file_get_inode(cur_t->fd_table[i]) == new_file)
        {
            new_file = file_reopen(new_file);
            return process_add_file(new_file);
        }
    }

    if (new_file != NULL)
        return process_add_file(new_file);
    else
        return -1;
}

int filesize(int fd)
{
    struct file *new_file;
    int length;

    return file_length(thread_current()->fd_table[fd]);
}

int read(int fd, void *buffer, unsigned size)
{
    struct file *new_file;
    lock_acquire(&filesys_lock);
    new_file = thread_current()->fd_table[fd];
    int readn = 0;
    if (fd == 0)
    {
        for (readn; readn < size; readn += input_getc())
            ;
        return readn;
    }
    lock_release(&filesys_lock);
    return file_read(new_file, buffer, size);
}

int write(int fd, void *buffer, unsigned size)
{
    struct file *new_file;

    // lock_acquire(&filesys_lock);
    new_file = thread_current()->fd_table[fd];
    int writen = 0;
    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    // lock_release(&filesys_lock);
    return file_write(new_file, buffer, size);
}

// check address 해야함.
void seek(int fd, unsigned position)
{
    struct file *new_file;
    /* 파일 디스크립터를 이용하여 파일 객체 검색 */
    new_file = process_get_file(fd);
    /* 해당 열린 파일의 위치(offset)를 position만큼 이동 */
    file_seek(new_file, position);
}

unsigned tell(int fd)
{
    struct file *new_file;
    new_file = process_get_file(fd);
    return file_tell(new_file);
}

void close(int fd)
{
    /* 해당 파일 디스크립터에 해당하는 파일을 닫음 */
    /* 파일 디스크립터 엔트리 초기화 */
    lock_acquire(&filesys_lock);
    process_close_file();
    lock_release(&filesys_lock);
}
