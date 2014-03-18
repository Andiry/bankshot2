/*
 * Handle memory allocation.
 * Copied from PMFS balloc.c.
 */

#include "bankshot2.h"

static struct bankshot2_blocknode *
bankshot2_alloc_blocknode(struct bankshot2_device *bs2_dev)
{
	struct bankshot2_blocknode *p;

	p = (struct bankshot2_blocknode *)
		kmem_cache_alloc(bs2_dev->bs2_blocknode_cachep, GFP_NOFS);
	if (p) {
		bs2_dev->num_blocknode_allocated++;
	}
	return p;
}

void bankshot2_init_blockmap(struct bankshot2_device *bs2_dev,
				unsigned long init_used_size)
{
	unsigned long num_used_block;
	struct bankshot2_blocknode *blknode;

	num_used_block = (init_used_size + bs2_dev->blocksize - 1) >>
		bs2_dev->s_blocksize_bits;

	bs2_info("blockmap init: used %lu blocks\n", num_used_block);
	blknode = bankshot2_alloc_blocknode(bs2_dev);
	if (blknode == NULL)
		bs2_info("WARNING: blocknode allocation failed\n");

	blknode->block_low = bs2_dev->block_start;
	blknode->block_high = bs2_dev->block_start + num_used_block - 1;
	bs2_dev->num_free_blocks -= num_used_block;
	list_add(&blknode->link, &bs2_dev->block_inuse_head);
}

int bankshot2_init_kmem(struct bankshot2_device *bs2_dev)
{
	bs2_dev->bs2_blocknode_cachep = kmem_cache_create(
					"bankshot2_blocknode_cache",
					sizeof(struct bankshot2_blocknode),
					0, (SLAB_RECLAIM_ACCOUNT |
                                        SLAB_MEM_SPREAD), NULL);
	if (bs2_dev->bs2_blocknode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void bankshot2_destroy_kmem(struct bankshot2_device *bs2_dev)
{
	kmem_cache_destroy(bs2_dev->bs2_blocknode_cachep);
}

