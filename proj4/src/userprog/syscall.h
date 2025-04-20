#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"

void syscall_init (void);
void exit (int status);
void clear_all_files(struct thread *cur);

#endif /* userprog/syscall.h */
