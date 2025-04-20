#include "vm/swap.h"
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include <bitmap.h>
#include <debug.h>

#define PAGE_SECTORS (PGSIZE/ BLOCK_SECTOR_SIZE)

static struct block *swap_block;
static struct bitmap *swap_bitmap;
static struct lock swap_lock;

void swap_init(void){
  swap_block = block_get_role(BLOCK_SWAP);
  size_t swap_size = block_size(swap_block) / PAGE_SECTORS;
  swap_bitmap = bitmap_create(swap_size);
  bitmap_set_all(swap_bitmap, false);
  lock_init(&swap_lock);
}

bool swap_out(struct page_entry *p){
  ASSERT(p != NULL);
  ASSERT(p->frame != NULL);
  //ASSERT(lock_held_by_current_thread(&p->frame->lock));

  lock_acquire(&swap_lock);
  size_t slot = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  lock_release(&swap_lock);

  if(slot == BITMAP_ERROR){
    return false;
  }

  size_t start_sector = slot * PAGE_SECTORS;
  for(size_t i = 0; i < PAGE_SECTORS; i++){
    block_write(swap_block, start_sector + i, (uint8_t *)p->frame->base + i * BLOCK_SECTOR_SIZE);
  }

  p->in_swap = true;
  p->swap_index = slot;

  return true;
}

void swap_in(struct page_entry *p){
  size_t i;

  ASSERT(p->frame != NULL);
  //ASSERT(lock_held_by_current_thread (&p->frame->lock));
  ASSERT(p->in_swap);
  ASSERT(p->swap_index != (size_t) - 1);

  size_t start_sector = p->swap_index * PAGE_SECTORS;
  for(size_t i = 0; i < PAGE_SECTORS; i++){
    block_read(swap_block, start_sector + i, (uint8_t *)p->frame->base + i * BLOCK_SECTOR_SIZE);
  }

  lock_acquire(&swap_lock);
  bitmap_reset(swap_bitmap, p->swap_index);
  lock_release(&swap_lock);

  p->in_swap = false;
  p->swap_index = (size_t)-1;
}

void swap_free(size_t swap_index){
  lock_acquire(&swap_lock);
  bitmap_reset(swap_bitmap, swap_index);
  lock_release(&swap_lock);
}
