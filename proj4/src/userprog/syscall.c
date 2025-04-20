#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include <debug.h>
#include <string.h>
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);

static void sys_halt (void);
static void sys_exit (struct intr_frame *);
static void sys_exec (struct intr_frame *);
static void sys_wait (struct intr_frame *);
static void sys_create (struct intr_frame *);
static void sys_remove (struct intr_frame *);
static void sys_open (struct intr_frame *);
static void sys_filesize (struct intr_frame *);
static void sys_read (struct intr_frame *);
static void sys_write (struct intr_frame *);
static void sys_seek (struct intr_frame *);
static void sys_tell (struct intr_frame *);
static void sys_close (struct intr_frame *);
static void sys_symlink (struct intr_frame *);

static int get_user (const uintptr_t uaddr, size_t size, void *dest);
static bool is_user_ptr_valid (const uintptr_t ptr, size_t size);

struct lock file_lock;

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t syscall_num;
  if (!is_user_vaddr (f->esp) ||
      get_user ((uintptr_t) f->esp, sizeof (syscall_num), &syscall_num) == -1)
    exit (-1);

  switch (syscall_num)
    {
      case SYS_HALT: /* Halt the operating system. */
        sys_halt ();
        break;
      case SYS_EXIT: /* Terminate this process. */
        sys_exit (f);
        break;
      case SYS_EXEC: /* Start another process. */
        sys_exec (f);
        break;
      case SYS_WAIT: /* Wait for a child process to die. */
        sys_wait (f);
        break;
      case SYS_CREATE: /* Create a file. */
        sys_create (f);
        break;
      case SYS_REMOVE: /* Delete a file. */
        sys_remove (f);
        break;
      case SYS_OPEN: /* Open a file. */
        sys_open (f);
        break;
      case SYS_FILESIZE: /* Obtain a file's size. */
        sys_filesize (f);
        break;
      case SYS_READ: /* Read from a file. */
        sys_read (f);
        break;
      case SYS_WRITE: /* Write to a file. */
        sys_write (f);
        break;
      case SYS_SEEK: /* Change position in a file. */
        sys_seek (f);
        break;
      case SYS_TELL: /* Report current position in a file. */
        sys_tell (f);
        break;
      case SYS_CLOSE: /* Close a file. */
        sys_close (f);
        break;
      case SYS_SYMLINK: /* Create soft link */
        sys_symlink (f);
        break;

      default:
        exit (-1);
        break;
    }
}
static void sys_halt (void) { shutdown_power_off (); }

static void sys_exit (struct intr_frame *f)
{
  int status;
  if (get_user ((uintptr_t) f->esp + 4, sizeof (int), &status) == -1)
    {
      exit (-1);
      return;
    }
  exit (status);
}

/* Helper function used to exit with status */
void exit (int status)
{
  struct thread *cur = thread_current ();
  if (cur->child_info != NULL)
    cur->child_info->exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);

  thread_exit ();
}

static void sys_exec (struct intr_frame *f)
{
  char *cmd_line;
  int buf_len = 128;
  char buf[buf_len];

  if (get_user ((uintptr_t) f->esp + 4, sizeof (char *), &cmd_line) == -1 ||
      !is_user_vaddr (cmd_line))
    {
      exit (-1);
      return;
    }

  if (get_user ((uintptr_t) cmd_line, buf_len, (void *) buf) == -1)
    {
      exit (-1);
      return;
    }
  buf[buf_len - 1] = '\0'; // Null termination

  tid_t tid = process_execute (buf);

  if (tid == TID_ERROR)
    f->eax = -1;
  else
    f->eax = tid;
}

static void sys_wait (struct intr_frame *f)
{
  tid_t pid;
  if (get_user ((uintptr_t) f->esp + 4, sizeof (tid_t), &pid) == -1)
    {
      exit (-1);
      return;
    }
  f->eax = process_wait (pid);
}

static void sys_create (struct intr_frame *f)
{
  char *file;
  unsigned initial_size;
  bool out;
  if (get_user ((uintptr_t) f->esp + 4, sizeof (char *), &file) == -1 ||
      get_user ((uintptr_t) f->esp + 8, sizeof (unsigned), &initial_size) == -1)
    {
      exit (-1);
      return;
    }

  if (file == NULL || !is_user_ptr_valid ((uintptr_t) file, sizeof (char *)))
    {
      exit (-1);
      return;
    }

  lock_acquire (&file_lock);
  out = filesys_create (file, initial_size);
  lock_release (&file_lock);

  f->eax = out;
}

static void sys_remove (struct intr_frame *f)
{
  char *file;
  bool out;
  if (get_user ((uintptr_t) f->esp + 4, sizeof (char *), &file) == -1 ||
      file == NULL || !is_user_ptr_valid ((uintptr_t) file, sizeof (char *)))
    {
      exit (-1);
      return;
    }

  lock_acquire (&file_lock);
  out = filesys_remove (file);
  lock_release (&file_lock);

  f->eax = out;
}

static void sys_open (struct intr_frame *f)
{
  char *file;
  int fd = -1;
  struct file *file_opened;
  if (get_user ((uintptr_t) f->esp + 4, sizeof (char *), &file) == -1 ||
      file == NULL || !is_user_ptr_valid ((uintptr_t) file, sizeof (char *)))
    {
      exit (-1);
      return;
    }

  lock_acquire (&file_lock);
  file_opened = filesys_open (file);
  lock_release (&file_lock);

  if (file_opened == NULL)
    {
      f->eax = -1;
      return;
    }

  struct thread *cur = thread_current ();
  for (int i = 2; i < MAX_FILES; i++)
    {
      if (cur->files[i] == NULL)
        {
          cur->files[i] = file_opened;
          fd = i;
          break;
        }
    }

  if (fd == -1)
    {
      lock_acquire (&file_lock);
      file_close (file_opened);
      lock_release (&file_lock);
    }

  f->eax = fd;
}

static void sys_filesize (struct intr_frame *f)
{
  int fd;
  if (get_user ((uintptr_t) f->esp + 4, sizeof (int), &fd) == -1)
    {
      exit (-1);
      return;
    }

  if (fd < 0 || fd >= MAX_FILES || thread_current ()->files[fd] == NULL)
    {
      f->eax = -1;
      return;
    }

  lock_acquire (&file_lock);
  f->eax = file_length (thread_current ()->files[fd]);
  lock_release (&file_lock);
}

static void sys_read (struct intr_frame *f)
{
  int fd;
  void *buffer;
  unsigned size;
  int out;
  if (get_user ((uintptr_t) f->esp + 4, sizeof (int), &fd) == -1 ||
      get_user ((uintptr_t) f->esp + 8, sizeof (void *), &buffer) == -1 ||
      get_user ((uintptr_t) f->esp + 12, sizeof (unsigned), &size) == -1)
    {
      exit (-1);
      return;
    }

  // Ensure buffer is valid and does not wrap around
  if (buffer == NULL || (uintptr_t) buffer + size < (uintptr_t) buffer)
    {
      exit (-1);
      return;
    }

  // Touch each page to ensure it's loaded into memory (trigger page fault if needed)
  uint8_t *buf_ptr = (uint8_t *) buffer;
  for (unsigned offset = 0; offset < size; offset += PGSIZE)
    {
      uint8_t tmp;
      if (get_user ((uintptr_t)(buf_ptr + offset), 1, &tmp) == -1)
	{
	  exit (-1);
	  return;
	}
    }

  if (size > 0)
    {
      uint8_t tmp;

      if (get_user((uintptr_t)(buf_ptr + size - 1), 1, &tmp) == -1)
	{
	  exit(-1);
	  return;
	}
    }

  lock_acquire (&file_lock);

  if (fd == 0) // STDIN_FILENO
    {
      uint8_t *byte_buf = (uint8_t *) buffer;
      for (int i = 0; i < (int) size; i++)
        {
          byte_buf[i] = input_getc ();
        }
      out = size; // Set the return value to bytes read
    }
  else
    {
      struct thread *cur = thread_current ();
      if (fd < 0 || fd >= MAX_FILES || cur->files[fd] == NULL)
        {
          lock_release (&file_lock);
          f->eax = -1;
          return;
        }
      // Read file
      out = file_read (cur->files[fd], buffer, size);
    }

  lock_release (&file_lock);
  f->eax = out; // Return number of bytes read
}

static void sys_write (struct intr_frame *f)
{
  int fd;
  const void *buffer;
  unsigned size;
  int out;
  // Retrieve the arguments using get_user
  if (get_user ((uintptr_t) f->esp + 4, sizeof (int), &fd) == -1 ||
      get_user ((uintptr_t) f->esp + 8, sizeof (void *), &buffer) == -1 ||
      get_user ((uintptr_t) f->esp + 12, sizeof (unsigned), &size) == -1)
    {
      exit (-1); // Exit on invalid pointer
      return;
    }

  if (!is_user_ptr_valid ((uintptr_t) buffer, size))
    {
      exit (-1);
      return;
    }

  if (fd == 1) // STDOUT_FILENO
    {
      putbuf (buffer, size);
      out = size;   // Set the return value to bytes written
      f->eax = out; // Return number of bytes written
      return;
    }

  lock_acquire (&file_lock);
  struct thread *cur = thread_current ();

  if (fd < 0 || fd >= MAX_FILES || cur->files[fd] == NULL) // Invalid fd
    {
      lock_release (&file_lock);
      f->eax = -1;
      return;
    }

  // write to file if fd is valid
  out = file_write (cur->files[fd], buffer, size);

  lock_release (&file_lock);
  f->eax = out; // Return number of bytes written
}

static void sys_seek (struct intr_frame *f)
{
  int fd;
  unsigned position;

  if (get_user ((uintptr_t) f->esp + 4, sizeof (int), &fd) == -1 ||
      get_user ((uintptr_t) f->esp + 8, sizeof (unsigned), &position) == -1)
    {
      exit (-1);
      return;
    }

  struct thread *cur = thread_current ();

  if (fd < 0 || fd >= MAX_FILES || cur->files[fd] == NULL) // Invalid fd
    {
      exit (-1);
      return;
    }

  lock_acquire (&file_lock);
  file_seek (cur->files[fd], position);
  lock_release (&file_lock);
}

static void sys_tell (struct intr_frame *f)
{
  int fd;
  unsigned out = 0;

  if (get_user ((uintptr_t) f->esp + 4, sizeof (int), &fd) == -1)
    {
      exit (-1);
      return;
    }

  struct thread *cur = thread_current ();
  if (fd < 0 || fd >= MAX_FILES || cur->files[fd] == NULL) // Invalid fd
    {
      exit (-1);
      return;
    }

  lock_acquire (&file_lock);
  out = file_tell (cur->files[fd]);
  lock_release (&file_lock);

  f->eax = out; // Return the position.
}

static void sys_close (struct intr_frame *f)
{
  int fd;

  if (get_user ((uintptr_t) f->esp + 4, sizeof (int), &fd) == -1)
    {
      exit (-1);
      return;
    }

  struct thread *cur = thread_current ();
  if (fd < 0 || fd >= MAX_FILES || cur->files[fd] == NULL) // Invalid fd
    {
      exit (-1);
      return;
    }

  lock_acquire (&file_lock);
  file_close (cur->files[fd]);
  cur->files[fd] = NULL; // Clear the fd.
  lock_release (&file_lock);
}

static void sys_symlink (struct intr_frame *f)
{
  char *target;
  char *linkpath;

  int out = -1; // Assuming failure (-1)

  if (get_user ((uintptr_t) f->esp + 4, sizeof (char **), &target) == -1 ||
      get_user ((uintptr_t) f->esp + 8, sizeof (char **), &linkpath) == -1)
    {
      exit (-1);
      return;
    }

  if (target == NULL ||
      !is_user_ptr_valid ((uintptr_t) target, sizeof (char *)))
    {
      exit (-1);
      return;
    }

  if (linkpath == NULL ||
      !is_user_ptr_valid ((uintptr_t) linkpath, sizeof (char *)))
    {
      exit (-1);
      return;
    }

  lock_acquire (&file_lock);

  // Check if target file can be opened
  struct file *target_file = filesys_open (target);
  if (target_file == NULL)
    {
      lock_release (&file_lock);
      f->eax = -1;
      return;
    }
  file_close (target_file);

  if (filesys_symlink (target, linkpath))
    out = 0;
  lock_release (&file_lock);

  f->eax = out;
}

/* Reads (size) bytes from uaddr to dest. Returns -1 if failed, 0 if successful
 */
static int get_user (const uintptr_t uaddr, size_t size, void *dest)
{

  if (!is_user_vaddr((void *)uaddr) || !is_user_vaddr ((void *) (uaddr + size - 1))){
    return -1;
  }
  
  if (!is_user_ptr_valid (uaddr, size)){
    if(!page_in(uaddr, false)){
      return -1;
    }
  }

  memcpy (dest, (void *) uaddr, size);
  return 0;
}

/* Check if the user pointer is in the correct size */
static bool is_user_ptr_valid (const uintptr_t ptr, size_t size)
{
  
  if ((void *) ptr == NULL)
    return false;

  // Is mappable to physical address?
  void *pagedir_start = pagedir_get_page (thread_current ()->pagedir, (void *) ptr);
  void *pagedir_end = pagedir_get_page (thread_current ()->pagedir, (void *) (ptr + size - 1));

  if (pagedir_start == NULL || pagedir_end == NULL)
    {
      return false;
    }
  return true;
}

/* Clears all open files in a given thread. */
void clear_all_files (struct thread *cur)
{
  //lock_acquire (&file_lock);

  // Iterate all files in current thread
  for (int i = 2; i < MAX_FILES; i++)
    {
      if (cur->files[i] != NULL)
        {
          file_close (cur->files[i]);
          cur->files[i] = NULL;
        }
    }
  //lock_release (&file_lock);
}
