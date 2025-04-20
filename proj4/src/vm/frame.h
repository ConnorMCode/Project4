#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "vm/page.h"

struct frame_entry {
  void *base;
  struct page_entry *page;
  struct lock lock;
  struct thread *owner;
  struct list_elem frame_elem;
};

void frame_table_init(void);

struct frame_entry *frame_alloc(struct page_entry *page);

void frame_free(struct frame_entry *f);

void frame_lock(struct page_entry *p);

void frame_unlock(struct frame_entry *f);

#endif
