/*
 * Handle memory allocation.
 * Copied from PMFS super.c.
 */

#include "bankshot2.h"


void bankshot2_init_memblocks(struct bankshot2_device *bs2_dev)
{
	bs2_dev->block_start = (BANKSHOT2_RESERVE_SPACE >> PAGE_SHIFT);
	bs2_dev->block_end = (bs2_dev->size >> PAGE_SHIFT);
	bs2_dev->num_free_blocks = bs2_dev->block_end - bs2_dev->block_start;

}

