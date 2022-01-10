#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAX_ARGS 3


static void syscall_handler (struct intr_frame *);
void get_args (struct intr_frame *f, int *arg, int num_of_args);
void syscall_halt (void);
pid_t syscall_exec(const char* cmdline);
int syscall_wait(pid_t pid);
int syscall_fileopen(const char *file);
int syscall_filesize(int filedes);
int syscall_fileread(int filedes, void *buffer, unsigned length);
int syscall_write (int filedes, const void * buffer, unsigned byte_size);
void syscall_close(int filedes);
void validate_ptr (const void* vaddr);

void validate_buffer (const void* buf, unsigned byte_size);
bool syscall_filecreate(const char *file, unsigned initial_size);
int usraddr_to_kerneladdr(const void *vaddr);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
bool syscall_remove(const char *file);
struct file* fd_to_file(int fd);
bool check_valid_pointer(const void *vaddr);



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  
  
  int arg[MAX_ARGS];
  int esp = usraddr_to_kerneladdr((const void *) f->esp);

  if(!check_valid_pointer(f->esp))
    {
 	syscall_exit(-1);
    }
  int *esp1 = f->esp;
  int syscall = *esp1;
  switch (syscall)
  {
    case SYS_HALT:
      syscall_halt();
      break;
      
    case SYS_EXIT:
      get_args(f, &arg[0], 1);
      syscall_exit(arg[0]);
      break;
      
    case SYS_EXEC:
      get_args(f, &arg[0], 1);

      arg[0] = usraddr_to_kerneladdr((const void *)arg[0]);
      f->eax = syscall_exec((const char*)arg[0]); 
      break;
      
    case SYS_WAIT:
      get_args(f, &arg[0], 1);
      f->eax = syscall_wait(arg[0]);
      break;
      
    case SYS_CREATE:
      get_args(f, &arg[0], 2);
      arg[0] = usraddr_to_kerneladdr((const void *) arg[0]);
	f->eax=syscall_filecreate((const char *)arg[0], (unsigned) arg[1]);
      break;
      
    case SYS_REMOVE:
      	get_args(f, &arg[0], 1);
	arg[0] = usraddr_to_kerneladdr((const void *) arg[0]);
	f->eax = syscall_remove((const char *) arg[0]);
      break;
      
    case SYS_OPEN:
       //printf("name= %s", arg[0]);
	get_args(f, &arg[0], 1);
	arg[0] = usraddr_to_kerneladdr((const void *) arg[0]);
	//printf("Name = %s", arg[0]);
        f->eax = syscall_fileopen((const char *) arg[0]);
	//printf("finished open");
      break;
      
    case SYS_FILESIZE:
        //printf("its here");
	get_args(f, &arg[0], 1);
	//printf("next line");
	//printf("Arg0-%d",arg[0]);
	//arg[0] = usraddr_to_kerneladdr((const void *) arg[0]);
	
	f->eax = syscall_filesize(arg[0]);
	//printf("Done filesize");
     break;
      
    case SYS_READ:
      //printf("in Read");
	get_args(f, &arg[0], 3);
	
	validate_buffer((const void*)arg[1], (unsigned)arg[2]);
	
	arg[1] = usraddr_to_kerneladdr((const void *) arg[1]);
	
	f->eax = syscall_fileread(arg[0], (void *) arg[1], (unsigned) arg[2]);
      break;
      
    case SYS_WRITE:
      get_args(f, &arg[0], 3);
      validate_buffer((const void*)arg[1], (unsigned)arg[2]);
      arg[1] = usraddr_to_kerneladdr((const void *)arg[1]); 
      f->eax = syscall_write(arg[0], (const void *) arg[1], (unsigned) arg[2]);
	//syscall_exit(ERROR);
	//printf("Done write:");
	
      break;
      
    case SYS_SEEK:
       get_args(f, &arg[0], 2);
       syscall_seek((int)arg[0], (unsigned) arg[1]);
      break;
      
    case SYS_TELL:
      get_args(f, &arg[0], 1);
	f->eax = syscall_tell((int)arg[0]);
      break;
    
    case SYS_CLOSE:
      get_args(f, &arg[0], 1);
	syscall_close(arg[0]);
      break;
      
    default:
      break;
  }
}


void
syscall_halt (void)
{
  shutdown_power_off(); 
}


void get_args(struct intr_frame *f, int *args, int arg_size)
{

  int *ptr;
  for (int i = 0; i < arg_size; i++)
  {
    ptr = (int *) f->esp + i + 1;
    validate_ptr((const void *) ptr);
    args[i] = *ptr;
  }
}



bool syscall_filecreate(const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
}




void
syscall_exit (int status)
{
  struct thread *cur = thread_current();
  if (thread_ongoing(cur->parent) && cur->cp)
  {
    if (status < 0)
    {
      status = -1;
    }
    cur->cp->status = status;
  }
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}


pid_t syscall_exec(const char* cmdline)
{
    pid_t pid = process_execute(cmdline);
    struct child_proc *ptr = find(pid);
    if (!ptr)
    {
      return ERROR;
    }
    if (ptr->load_status == NOT_LOADED)
    {
      sema_down(&ptr->load_sema);
    }
    if (ptr->load_status == LOAD_FAIL)
    {
	list_remove(&ptr->elem);
	free(ptr);
      return ERROR;
    }
    return pid;
}

/* wait */
int
syscall_wait(pid_t pid)
{
  return process_wait(pid);
}



/* syscall_open */
int syscall_fileopen(const char *file)
{
	//if(!filesys_open(file))
	//	return ERROR;
	/*unsigned long fd = (unsigned long) filesys_open(file);
	printf("Fd= %d", fd);
	if (fd <0)
		return fd*-1;
	else if (fd ==0)
		return -1;
	else
		return fd;
	
//	return fd *-1;*/
	
	struct file *fd = filesys_open(file);
	struct process_file *fs = malloc(sizeof(struct process_file));
	
	int fdes= thread_current()->fd;
	if (fd==0)
		return -1;
	//else
	//{
		fs->file=fd;
		fs->fd= fdes;
		//int fdes = thread_current()->fd;	
		thread_current()->fd++;
		list_push_back(&thread_current()->file_list, &fs->elem);
		
		return fs->fd;
	//}
}


/* syscall_filesize */
int syscall_filesize(int fd)
{
	//printf("in function");
	struct file *file= fd_to_file(fd);
	//printf("Done fd to file");
	
	if(!file)
	{
		
		return ERROR;
	}
	//printf("past if");
	
	//printf("before file_length");
	int filesize=  file_length(file);
	//printf("%d",filesize);
	
	
	return filesize;

}


int syscall_fileread(int fd, void *buffer, unsigned size)
{

	uint8_t  *buff = (uint8_t  *) buffer;
	//printf("In read");
	
	if(size <= 0)
		return size;
	if( fd ==0)
	{
		
		for(int i=0; i<size; i++)
		{
			buff[i] = input_getc();
		}
	return size;
	}

	
	//printf("Past if");
	
	struct file *file= fd_to_file(fd);
	if(!file)
		return ERROR;	
	int read_bytes = file_read(file, buffer, size);
	//printf("Return value: %d", read_bytes);
	//syscall_exit(ERROR);
	//printf("Return value: %d", read_bytes);
	
	return read_bytes;
	

}


/* syscall_write */
int syscall_write(int fd, const void *buffer, unsigned size)
{
	if(fd == 1)
	{
		putbuf(buffer, size);
		return size;
	}
	struct file *f = fd_to_file(fd);
	if(!f)
		return ERROR;
	//syscall_exit(ERROR);
	return file_write(f, buffer, size);
}	

bool syscall_remove(const char *file)
{
	return filesys_remove(file);
}


struct file* fd_to_file(int fd)
{
	//printf("in fd");
	struct list_elem *nxt_pointer;
	struct thread *curr = thread_current();
	
	struct list_elem *pointer =  list_begin(&curr->file_list);
	
	//if(!fd)
		//return ERROR;
	//syscall_exit(ERROR);
	while (pointer != list_end(&curr->file_list))
	{
		
		nxt_pointer=list_next(pointer);
			
		struct process_file *fs = list_entry(pointer, struct process_file, elem);
		//printf("FD:%d",fs->file);
		
    		if (fd == fs->fd)
    		{
			//printf("above syscall");
      			return fs->file;
			
    		}
		
		pointer=nxt_pointer;
	}
	return NULL;
}



/* syscall_close */
void syscall_close(int fd)
{
      if (fd != -1)
	 return;
       struct file *f = fd_to_file(fd);
       file_close(f);
}


bool
check_valid_pointer(const void *vaddr)
{
    if((vaddr != NULL) && (((unsigned int)vaddr) < ((unsigned int)PHYS_BASE)))
    {
    	if((pagedir_get_page(thread_current()->pagedir, vaddr)) != NULL)
     		return true;
    	
   	else
     		 return false;
  	
    }
  return false;
}

/* function to check if pointer is valid */
void validate_ptr (const void *vaddr)
{
    if (vaddr < USER_VADDR_BOTTOM || !is_user_vaddr(vaddr))
    {
      syscall_exit(ERROR);
    }
}



/* function to check if buffer is valid */
void validate_buffer(const void* buf, unsigned byte_size)
{
  unsigned counter = 0;
  char* temp_buff = (char *)buf;
  while ( counter < byte_size)
  {
    validate_ptr((const void*)temp_buff);
    temp_buff++;
    counter++;
  }
}



/* find a child process based on pid */
struct child_proc* find(int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e = list_begin(&t->child_list);
  struct list_elem *next;
  
  while(e != list_end(&t->child_list))
   {
      next = list_next(e);
    struct child_proc *cp = list_entry(e, struct child_proc, elem);
    if (pid == cp->pid)
      return cp;
    e = next;
   }
  return NULL;
}


void syscall_seek(int fd, unsigned position)
{
  struct file *f = fd_to_file(fd);
  file_seek(f, position);
}

unsigned syscall_tell(int fd)
{
	struct file *f = fd_to_file(fd);
	return file_tell(f);
}


int usraddr_to_kerneladdr(const void *vaddr)
{
	//printf("in usraddr");
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	//printf("reached here");
  if (!ptr)
  {
	//printf("in exit");
	//printf("Ptr: %d",(int)ptr);
    syscall_exit(ERROR);
  }
  return (int)ptr;
}



