#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include <string.h>
#include <stdio.h>

#define STACK_MAX (4 * 1024 * 1024)

void page_table_init(struct thread *t){
  list_init(&t->page_table);
}

struct page_entry *page_lookup(const void *addr){
  struct list_elem *e;
  struct thread *t = thread_current();
  
  for(e = list_begin(&t->page_table); e != list_end(&t->page_table); e = list_next(e)){
    struct page_entry *entry = list_entry(e, struct page_entry, page_elem);
    if (entry->upage == pg_round_down(addr)){
      return entry;
    }
  }
  
  if (addr < PHYS_BASE) {
    void *upage = pg_round_down(addr);

    uintptr_t phys_base = (uintptr_t)PHYS_BASE;
    uintptr_t stack_max = (uintptr_t)STACK_MAX;
    uintptr_t upage_addr = (uintptr_t)upage;

    /*if ((upage_addr > phys_base - stack_max) && ((uint8_t *)thread_current()->user_esp - 32 < addr)) {
      return page_allocate(upage, true);
      }*/

    if ((uintptr_t)addr >= (uintptr_t)(PHYS_BASE) - STACK_MAX && (uintptr_t)addr < (uintptr_t)PHYS_BASE)  {

      if ((uintptr_t)addr < (uintptr_t)thread_current()->user_esp - (PGSIZE/2)) {
	exit(-1);
      }
      
      return page_allocate(upage, true);
    }
    
  }

  return NULL;
}

bool page_in(void *fault_addr, bool write){
  struct thread *t = thread_current();
  void *upage = pg_round_down(fault_addr);
  
  // Find the page in the thread's page list
  struct page_entry *p = page_lookup(fault_addr);

  if(write){
    if(!p->writable){
      exit(-1);
    }
  }
  
  if (p == NULL) {
    return false;
  }

  // Allocate a frame
  p->frame = frame_alloc(p);
  if (p->frame == NULL) {
    return false;
  }

  if (p->frame == NULL || p->frame->base == NULL) {
    printf("Invalid frame for page %p\n", p->upage);
    frame_unlock(p->frame);
    return false; // Return false if the frame is not valid
  }

  // Check if the page is already mapped, and skip the mapping if it is
  if (pagedir_get_page(t->pagedir, p->upage) != NULL) {
    // The page is already mapped, no need to map it again
    frame_unlock(p->frame);
    return false; // Return false without attempting to map the page
  }

  // Load the data into the frame
  if (p->in_swap) {
    swap_in(p);
  } else if (p->file != NULL) {
    off_t read_bytes = file_read_at (p->file, p->frame->base, p->read_bytes, p->file_offset);
    off_t zero_bytes = PGSIZE - read_bytes;
    memset ((uint8_t *)p->frame->base + read_bytes, 0, zero_bytes);
  } else {
    memset(p->frame->base, 0, PGSIZE);
  }
  
  // Install the page into the page directory
  if (!pagedir_set_page(t->pagedir, p->upage, p->frame->base, p->writable)) {
    printf("pagedir_set_page failed for %p\n", upage);
    frame_unlock(p->frame);
    return false;
  }

  frame_unlock (p->frame);
  return true;
}

bool page_out(struct page_entry *p){
  bool dirty;
  bool ok = false;

  dirty = pagedir_is_dirty(p->thread->pagedir, (const void *) p->upage);

  pagedir_clear_page(p->thread->pagedir, (void *) p->upage);

  if(!dirty){
    ok = true;
  }

  if(p->file == NULL){
    ok = swap_out(p);
  }else{
    if(dirty){
      if(!p->writable){
	ok = swap_out(p);
      }else{
	ok = file_write_at(p->file, (const void *)p->frame->base, p->read_bytes, p->file_offset);
      }
    }
  }

  if(ok){
    p->frame = NULL;
  }
  return ok;
}

bool page_relevant(struct page_entry *p){
  if(pagedir_is_accessed(p->thread->pagedir, p->upage)){
    pagedir_set_accessed(p->thread->pagedir, p->upage, false);
  }
  return pagedir_is_accessed(p->thread->pagedir, p->upage);
}

struct page_entry *page_allocate(void *uaddr, bool writable){
  struct thread *t = thread_current();
  struct page_entry *p = palloc_get_page(PAL_ZERO);
  //struct page_entry *p = malloc(sizeof(struct page_entry));
  
  if(p != NULL){
    p->upage = pg_round_down(uaddr);
    p->writable = writable;
    p->frame = NULL;

    p->in_swap = false;
    p->swap_index = (size_t) -1;

    p->file = NULL;
    p->file_offset = 0;
    p->read_bytes = 0;
    p->zero_bytes = 0;

    p->type = PAGE_ZERO;
    p->thread = t;

    list_push_back(&t->page_table, &p->page_elem);
  }

  return p;
}

void page_deallocate(void *uaddr){
  struct page_entry *p = page_lookup(uaddr);
  frame_lock(p);
  if(p->frame){
    struct frame_entry *f = p->frame;
    if(p->file && p->writable){
      page_out(p);
    }
    frame_free(f);
  }
  list_remove(&p->page_elem);
  palloc_free_page(p);
  //free(p);
}

bool page_lock(const void *uaddr, bool write){
  struct page_entry *p = page_lookup(uaddr);
  if(p == NULL ||(!p->writable && write)){
    return false;
  }

  frame_lock(p);
  if(p->frame == NULL){
    return(page_in(p, write) && pagedir_set_page(thread_current()->pagedir, p->upage, p->frame->base, p->writable));
  }else{
    return true;
  }
}

void page_unlock(const void *uaddr){
  struct page_entry *p = page_lookup(uaddr);
  ASSERT (p != NULL);
  frame_unlock(p->frame);
}

void page_table_destroy(struct thread *t){
  struct list_elem *e;
  while(!list_empty(&t->page_table)){
    e = list_pop_front(&t->page_table);
    struct page_entry *entry = list_entry(e, struct page_entry, page_elem);
    free(entry);
  }
}
