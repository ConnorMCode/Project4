#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

// #define FREE_MAP_DEBUG

#ifdef FREE_MAP_DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...) ((void)0)
#endif

static struct file *free_map_file; /* Free map file. */
static struct bitmap *free_map;    /* Free map, one bit per sector. */

/* Initializes the free map. */
void free_map_init (void)
{
  free_map = bitmap_create (block_size (fs_device));
  if (free_map == NULL)
    PANIC ("bitmap creation failed--file system device is too large");
  bitmap_mark (free_map, FREE_MAP_SECTOR);
  bitmap_mark (free_map, ROOT_DIR_SECTOR);
}

/* Allocates CNT consecutive sectors from the free map and stores
   the first into *SECTORP.
   Returns true if successful, false if not enough consecutive
   sectors were available or if the free_map file could not be
   written. */
bool free_map_allocate (size_t cnt, block_sector_t *sectorp)
{
  block_sector_t sector = bitmap_scan_and_flip (free_map, 0, cnt, false);
  if (sector != BITMAP_ERROR && free_map_file != NULL &&
      !bitmap_write (free_map, free_map_file))
    {
      bitmap_set_multiple (free_map, sector, cnt, false);
      sector = BITMAP_ERROR;
    }
  if (sector != BITMAP_ERROR)
    *sectorp = sector;
  return sector != BITMAP_ERROR;
}

/* Makes CNT sectors starting at SECTOR available for use. */
void free_map_release (block_sector_t sector, size_t cnt)
{
  ASSERT (bitmap_all (free_map, sector, cnt));
  bitmap_set_multiple (free_map, sector, cnt, false);
  bitmap_write (free_map, free_map_file);
}

/* Opens the free map file and reads it from disk. */
void free_map_open (void)
{

  dprintf("[free_map_open] Opening free map at sector %d\n", FREE_MAP_SECTOR);
  
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");

  dprintf("[free_map_open] Successfully opened free map file. Now reading bitmap...\n");
  
  if (!bitmap_read (free_map, free_map_file))
    PANIC ("can't read free map");

  dprintf("[free_map_open] Successfully read free map bitmap from disk.\n");
}

/* Writes the free map to disk and closes the free map file. */
void free_map_close (void) { file_close (free_map_file); }

/* Creates a new free map file on disk and writes the free map to
   it. */
void free_map_create (void)
{
  /* Create inode. */

  dprintf("[free_map_create] bitmap_file_size = %d\n", bitmap_file_size(free_map));
  
  if (!inode_create (FREE_MAP_SECTOR, bitmap_file_size (free_map), false))
    PANIC ("free map creation failed");

  /* Write bitmap to file. */
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_write (free_map, free_map_file))
    PANIC ("can't write free map");
}
