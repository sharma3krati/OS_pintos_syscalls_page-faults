#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"
void syscall_init (void);

#define ERROR -1
#define NOT_LOADED 0
#define LOADED 1
#define LOAD_FAIL 2
#define USER_VADDR_BOTTOM ((void *) 0x08048000)

struct child_proc {
  int pid;
  int load_status;
  int wait;
  int exit;
  int status;
  struct semaphore load_sema;
  struct semaphore exit_sema;
  struct list_elem elem;
};

struct process_file {
    struct file *file;
    int fd;
    struct list_elem elem;
};

struct lock file_system_lock;


struct child_proc* find(int pid);

void syscall_exit (int status);
#endif /* userprog/syscall.h */
