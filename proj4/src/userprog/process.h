#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

#define MAX_ARGS 32 // Defining a maximum number of arguments

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Structure to pass arguments to the new thread. */
struct cmdline_args
{
  char *file_name;      // Executable name
  char *argv[MAX_ARGS]; // Array of argument strings
  int argc;             // Number of arguments

  char *fn_copy; // ptr to the copied command line

  struct semaphore load_sema; // Semaphore for synchronization while loading
  bool load_flag;             // True if successfully loaded
};

#endif /* userprog/process.h */
