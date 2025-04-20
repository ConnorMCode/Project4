#include "syscall.h"
#include "stdio.h"

#define PAGE_SIZE 4096
#define NUM_PAGES 100
#define TOTAL_SIZE (PAGE_SIZE * NUM_PAGES)

static char big_array[TOTAL_SIZE];

int main(void) {
  int i;

  // Write a unique value to each page to ensure they get swapped
  for (i = 0; i < NUM_PAGES; i++) {
    big_array[i * PAGE_SIZE] = (char)(i + 1);
  }

  // Read back and verify
  for (i = 0; i < NUM_PAGES; i++) {
    if (big_array[i * PAGE_SIZE] != (char)(i + 1)) {
      printf("Mismatch at page %d: expected %d, got %d\n",
	     i, i + 1, big_array[i * PAGE_SIZE]);
      return 1;
    }
  }

  printf("swap_test passed!\n");
  return 0;
}
