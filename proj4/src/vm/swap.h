#include <stdbool.h>
#include "threads/synch.h"
#include "vm/page.h"

void swap_init(void);
bool swap_out(struct page_entry *p);
void swap_in(struct page_entry *p);
void swap_free(size_t swap_index);
