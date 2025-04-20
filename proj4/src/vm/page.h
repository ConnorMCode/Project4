#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/thread.h"
#include "vm/frame.h"

enum page_type {
  PAGE_FILE,
  PAGE_ZERO,
  PAGE_STACK
};

struct page_entry {
  void *upage;
  struct thread *thread;
  struct frame_entry *frame;
  enum page_type type;
  struct file *file;
  off_t file_offset;
  size_t read_bytes;
  size_t zero_bytes;
  bool writable;
  bool in_swap;
  size_t swap_index;
  struct list_elem page_elem;
};

struct page_entry *page_lookup(const void *addr);

void page_table_init(struct thread *t);
struct page_entry *page_allocate(void *uaddr, bool writable);
void page_deallocate(void *uaddr);
bool page_in(void *fault_addr, bool write);
bool page_out(struct page_entry *p);
bool page_relevant(struct page_entry *p);
bool page_lock(const void *uaddr, bool write);
void page_unlock(const void *uaddr);
void page_table_destroy(struct thread *t);

#endif
