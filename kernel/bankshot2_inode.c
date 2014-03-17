#include "bankshot2.h"

static inline unsigned int
bankshot2_inode_blk_shift (struct bankshot2_inode *pi)
{
	return blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t bankshot2_inode_blk_size (struct bankshot2_inode *pi)
{
	return blk_type_to_size[pi->i_blk_type];
}

/* If this is part of a read-modify-write of the inode metadata,
 * bankshot2_memunlock_inode() before calling! */
struct bankshot2_inode *bankshot2_get_inode(struct bankshot2_device *bs2_dev,
						u64 ino)
{
	struct bankshot2_inode *inode_table = bankshot2_get_inode_table(sb);
	u64 bp, block, ino_offset;

	if (ino == 0)
		return NULL;

	block = ino >> bankshot2_inode_blk_shift(inode_table);
	bp = __bankshot2_find_data_block(sb, inode_table, block);

	if (bp == 0)
		return NULL;
	ino_offset = (ino & (bankshot2_inode_blk_size(inode_table) - 1));
	return (struct bankshot2_inode *)((void *)ps + bp + ino_offset);
}
