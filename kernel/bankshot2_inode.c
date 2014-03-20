/*
 * inode code.
 * Copied from bankshot2 inode code.
 */

#include "bankshot2.h"

unsigned int blk_type_to_shift[3] = {12, 21, 30};
uint32_t blk_type_to_size[3] = {0x1000, 0x200000, 0x40000000};

static inline unsigned int
bankshot2_inode_blk_shift (struct bankshot2_inode *pi)
{
	return blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t bankshot2_inode_blk_size (struct bankshot2_inode *pi)
{
	return blk_type_to_size[pi->i_blk_type];
}

static inline struct bankshot2_inode *
bankshot2_get_inode_table(struct bankshot2_device *bs2_dev)
{
	struct bankshot2_super_block *ps = bankshot2_get_super(bs2_dev);

	return (struct bankshot2_inode *)((char *)ps +
			le64_to_cpu(ps->s_inode_table_offset));
}

/* Initialize the inode table. The bankshot2_inode struct corresponding to the
 * inode table has already been zero'd out */
int bankshot2_init_inode_table(struct bankshot2_device *bs2_dev)
{
	struct bankshot2_inode *pi = bankshot2_get_inode_table(bs2_dev);
	unsigned long num_blocks = 0, init_inode_table_size;
	int errval;

	if (bs2_dev->num_inodes == 0) {
		/* initial inode table size was not specified. */
		init_inode_table_size = PAGE_SIZE;
	} else {
		init_inode_table_size =
			bs2_dev->num_inodes << BANKSHOT2_INODE_BITS;
	}

//	bankshot2_memunlock_inode(sb, pi);
	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;
	pi->height = 0;
	pi->i_dtime = 0;
	pi->i_blk_type = BANKSHOT2_BLOCK_TYPE_4K;

	// Allocate 1 block for now
	num_blocks = (init_inode_table_size + bankshot2_inode_blk_size(pi) - 1) 
			>> bankshot2_inode_blk_shift(pi);

	// PAGE_SIZE
	pi->i_size = cpu_to_le64(num_blocks << bankshot2_inode_blk_shift(pi));
	/* bankshot2_sync_inode(pi); */
//	bankshot2_memlock_inode(sb, pi);

	// 4096 / 128 = 32
	bs2_dev->s_inodes_count = num_blocks <<
			(bankshot2_inode_blk_shift(pi) - BANKSHOT2_INODE_BITS);
	/* calculate num_blocks in terms of 4k blocksize */
	num_blocks = num_blocks << (bankshot2_inode_blk_shift(pi) -
				bs2_dev->s_blocksize_bits);
	errval = __bankshot2_alloc_blocks(NULL, bs2_dev, pi, 0, num_blocks, true);

	if (errval != 0) {
		bs2_info("Err: initializing the Inode Table: %d\n", errval);
		return errval;
	}

	/* inode 0 is considered invalid and hence never used */
	bs2_dev->s_free_inodes_count =
		(bs2_dev->s_inodes_count - BANKSHOT2_FREE_INODE_HINT_START);
	bs2_dev->s_free_inode_hint = (BANKSHOT2_FREE_INODE_HINT_START);

	return 0;
}

/* If this is part of a read-modify-write of the inode metadata,
 * bankshot2_memunlock_inode() before calling! */
struct bankshot2_inode *bankshot2_get_inode(struct bankshot2_device *bs2_dev,
						u64 ino)
{
	struct bankshot2_super_block *ps = bankshot2_get_super(bs2_dev);
	struct bankshot2_inode *inode_table = bankshot2_get_inode_table(bs2_dev);
	u64 bp, block, ino_offset;

	if (ino == 0)
		return NULL;

	block = ino >> (bankshot2_inode_blk_shift(inode_table)
			- BANKSHOT2_INODE_BITS);
	bp = __bankshot2_find_data_block(bs2_dev, inode_table, block);

	if (bp == 0)
		return NULL;
	ino_offset = ((ino << BANKSHOT2_INODE_BITS)
			& (bankshot2_inode_blk_size(inode_table) - 1));
	bs2_info("%s: internal block %llu, actual block %llu, ino_offset %llu\n",
			__func__, block, bp / PAGE_SIZE, ino_offset);
	return (struct bankshot2_inode *)((void *)ps + bp + ino_offset);
}
