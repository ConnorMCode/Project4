#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

// #define INODE_DEBUG

#ifdef INODE_DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...) ((void)0)
#endif

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCKS 12
#define INDIRECT_BLOCKS 1
#define DOUBLE_INDIRECT_BLOCKS 1

#define PTRS_PER_BLOCK (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  block_sector_t direct[DIRECT_BLOCKS]; /* First data sector. */
  block_sector_t indirect;
  block_sector_t double_indirect;
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  bool is_symlink;      /* True if symbolic link, false otherwise. */
  bool is_dir;
  uint8_t unused[BLOCK_SECTOR_SIZE
		 - (DIRECT_BLOCKS * sizeof(block_sector_t))
		 - 2 * sizeof(block_sector_t)
		 - sizeof(off_t)
		 - sizeof(unsigned)
		 - 2 * sizeof(bool)];
}__attribute__((packed));

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if (pos >= inode->data.length)
    return (block_sector_t) -1;

  off_t index = pos / BLOCK_SECTOR_SIZE;

  if((size_t)index < DIRECT_BLOCKS){
    return inode->data.direct[index];
  }

  index -= DIRECT_BLOCKS;
  if((size_t)index < PTRS_PER_BLOCK) {
    block_sector_t indirect_block[PTRS_PER_BLOCK];

    block_read(fs_device, inode->data.indirect, indirect_block);

    return indirect_block[index];
  }

  index -= PTRS_PER_BLOCK;
  if((size_t)index < PTRS_PER_BLOCK * PTRS_PER_BLOCK){
    block_sector_t double_indirect_block[PTRS_PER_BLOCK];

    block_read(fs_device, inode->data.double_indirect, double_indirect_block);

    block_sector_t indirect_sector = double_indirect_block[index / PTRS_PER_BLOCK];
    if(indirect_sector == 0){
      return (block_sector_t) -1;
    }

    block_sector_t indirect_block[PTRS_PER_BLOCK];
    block_read(fs_device, indirect_sector, indirect_block);

    return indirect_block[index % PTRS_PER_BLOCK];
  }

  return (block_sector_t) -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init (void) { list_init (&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  ASSERT (length >= 0);

  struct inode_disk *disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL){
    dprintf("[inode_create] Failed to allocate disk_inode\n");
    return false;
  }

  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  dprintf("[inode_create] Creating inode at sector %d with length %d, is_dir=%d\n", (int)sector, (int)length, is_dir);
  
  disk_inode->length = 0; // Start at 0, will grow via inode_resize
  disk_inode->magic = INODE_MAGIC;
  disk_inode->is_symlink = false;
  disk_inode->is_dir = is_dir;

  struct inode tmp_inode;
  memset(&tmp_inode, 0, sizeof tmp_inode);
  tmp_inode.data = *disk_inode;

  dprintf("[inode_create] Before inode_resize: tmp_inode length=%d\n", (int)tmp_inode.data.length);
  
  // Use inode_resize to allocate and initialize sectors
  if (!inode_resize(&tmp_inode, length)) {
    dprintf("[inode_create] inode_resize failed\n");
    free(disk_inode);
    return false;
  }

  dprintf("[inode_create] After inode_resize: tmp_inode length=%d\n", (int)tmp_inode.data.length);

  // Copy updated inode_disk structure back
  *disk_inode = tmp_inode.data;

  dprintf("[inode_create] After resize copy in disk_inode length=%d\n", disk_inode->length);

  // Write inode to disk
  dprintf("[inode_create] Writing inode to sector %d\n", (int)sector);
  block_write(fs_device, sector, disk_inode);

  free(disk_inode);
  dprintf("[inode_create] Inode creation complete\n");
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
	  dprintf("[inode_open] At sector %d found length %d\n", (int)inode->sector, (int)inode->data.length);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  dprintf("[inode_open] At sector %d found length %d\n", (int)inode->sector, (int)inode->data.length);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      block_write (fs_device, inode->sector, &inode->data);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
          inode_deallocate_sectors(&(inode->data));
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size,
                     off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  dprintf("[inode_read_at] Starting read: inode sector=%d, inode length=%d, requested size=%d, start offset=%d\n",
	  (int)inode->sector, (int)inode_length(inode), (int)size, (int)offset);

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0){
	dprintf("[inode_read_at] Breaking: chunk_size <= 0 (inode_left=%d, sector_left=%d, size=%d)\n",
		(int)inode_left, (int)sector_left, (int)size);
        break;
      }

      dprintf("[inode_read_at] Reading sector %d at offset %d, chunk size %d\n",
	      sector_idx, sector_ofs, chunk_size);
      
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
	  dprintf("[inode_read_at] Full sector read into buffer\n");
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL){
		dprintf("[inode_read_at] Bounce buffer malloc failed!\n");
                break;
	      }
            }
	  dprintf("[inode_read_at] Partial sector read using bounce buffer\n");
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  dprintf("[inode_read_at] Read %d bytes\n", (int)bytes_read);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                      off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  off_t end_offset = offset + size;
  if (end_offset > inode_length(inode)){
    if (!inode_resize(inode, end_offset)){
      return bytes_written;
    }
  }
  
  while (size > 0)
    {
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int chunk_size = size < sector_left ? size : sector_left;

      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (const struct inode *inode) { return inode->data.length; }

bool inode_get_symlink (struct inode *inode) { 
  ASSERT (inode != NULL);
  return inode->data.is_symlink; 
}

void inode_set_symlink (struct inode *inode, bool is_symlink)
{
  inode->data.is_symlink = is_symlink;
  block_write (fs_device, inode->sector, &inode->data);
}

bool inode_resize(struct inode *inode, off_t new_length){
  if (new_length < inode->data.length){
    //implement shrinking
    return false;
  }

  off_t old_length = inode->data.length;
  size_t old_sectors = bytes_to_sectors(old_length);
  size_t new_sectors = bytes_to_sectors(new_length);

  if (new_sectors > old_sectors){
    for (size_t i = old_sectors; i < new_sectors; i++){
      block_sector_t new_sector;
      if(!free_map_allocate(1, &new_sector)){
	return false;
      }

      static char zeros[BLOCK_SECTOR_SIZE];
      block_write(fs_device, new_sector, zeros);

      if (!inode_allocate_sector(&inode->data, i, new_sector)){
	return false;
      }
    }
  }

  inode->data.length = new_length;

  block_write(fs_device, inode->sector, &inode->data);

  return true;
}

bool inode_allocate_sector(struct inode_disk *disk_inode, size_t index, block_sector_t new_sector){

  static char zeros[BLOCK_SECTOR_SIZE];
  
  if ((size_t)index < DIRECT_BLOCKS){
    disk_inode->direct[index] = new_sector;
    return true;
  }

  index -= DIRECT_BLOCKS;

  if ((size_t)index < PTRS_PER_BLOCK){
    if (disk_inode->indirect == 0){
      if (!free_map_allocate(1, &disk_inode->indirect)){
	return false;
      }
      block_write(fs_device, disk_inode->indirect, zeros);
    }

    block_sector_t indirect_block[PTRS_PER_BLOCK];
    block_read(fs_device, disk_inode->indirect, indirect_block);
    indirect_block[index] = new_sector;
    block_write(fs_device, disk_inode->indirect, indirect_block);
    return true;
  }

  index -= PTRS_PER_BLOCK;
  if ((size_t)index < PTRS_PER_BLOCK * PTRS_PER_BLOCK) {
    if (disk_inode->double_indirect == 0) {
      if (!free_map_allocate(1, &disk_inode->double_indirect)) return false;
      block_write(fs_device, disk_inode->double_indirect, zeros);
    }

    block_sector_t outer_block[PTRS_PER_BLOCK];
    block_read(fs_device, disk_inode->double_indirect, outer_block);

    size_t outer_index = index / PTRS_PER_BLOCK;
    size_t inner_index = index % PTRS_PER_BLOCK;

    if (outer_block[outer_index] == 0) {
      if (!free_map_allocate(1, &outer_block[outer_index])) return false;
      block_write(fs_device, outer_block[outer_index], zeros);
      block_write(fs_device, disk_inode->double_indirect, outer_block); // update outer block
    }

    block_sector_t inner_block[PTRS_PER_BLOCK];
    block_read(fs_device, outer_block[outer_index], inner_block);
    inner_block[inner_index] = new_sector;
    block_write(fs_device, outer_block[outer_index], inner_block);
    return true;
  }

  return false; // index too large
}

void inode_deallocate_sectors(struct inode_disk *disk_inode) {
  //static char zeros[BLOCK_SECTOR_SIZE];
  size_t num_sectors = bytes_to_sectors(disk_inode->length);

  // 1. Direct blocks
  size_t i = 0;
  for (; i < DIRECT_BLOCKS && i < num_sectors; i++) {
    if (disk_inode->direct[i] != 0)
      free_map_release(disk_inode->direct[i], 1);
  }

  // 2. Indirect block
  if (i < num_sectors && disk_inode->indirect != 0) {
    block_sector_t indirect_block[PTRS_PER_BLOCK];
    block_read(fs_device, disk_inode->indirect, indirect_block);

    size_t indirect_count = num_sectors - i;
    if (indirect_count > PTRS_PER_BLOCK) indirect_count = PTRS_PER_BLOCK;

    for (size_t j = 0; j < indirect_count; j++) {
      if (indirect_block[j] != 0)
	free_map_release(indirect_block[j], 1);
    }

    free_map_release(disk_inode->indirect, 1);
    i += indirect_count;
  }

  // 3. Double indirect block
  if (i < num_sectors && disk_inode->double_indirect != 0) {
    block_sector_t outer_block[PTRS_PER_BLOCK];
    block_read(fs_device, disk_inode->double_indirect, outer_block);

    size_t total_double = num_sectors - i;
    size_t outer_limit = DIV_ROUND_UP(total_double, PTRS_PER_BLOCK);

    for (size_t outer = 0; outer < outer_limit; outer++) {
      if (outer_block[outer] != 0) {
	block_sector_t inner_block[PTRS_PER_BLOCK];
	block_read(fs_device, outer_block[outer], inner_block);

	size_t inner_limit = total_double > PTRS_PER_BLOCK ? PTRS_PER_BLOCK : total_double;

	for (size_t inner = 0; inner < inner_limit; inner++) {
	  if (inner_block[inner] != 0)
	    free_map_release(inner_block[inner], 1);
	}

	free_map_release(outer_block[outer], 1);
	total_double -= inner_limit;
      }
    }

    free_map_release(disk_inode->double_indirect, 1);
  }
}

bool inode_is_dir(struct inode *inode){
  return inode != NULL && inode->data.is_dir;
}
