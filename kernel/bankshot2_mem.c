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

static void __bankshot2_free_blocknode(struct bankshot2_device *bs2_dev,
					struct bankshot2_blocknode *bnode)
{
	kmem_cache_free(bs2_dev->bs2_blocknode_cachep, bnode);
}

static struct bankshot2_blocknode *bankshot2_next_blocknode(
		struct bankshot2_blocknode *i, struct list_head *head)
{
	if (list_is_last(&i->link, head))
		return NULL;
	return list_first_entry(&i->link, typeof(*i), link);
}

int bankshot2_new_block(struct bankshot2_device *bs2_dev,
		unsigned long *blocknr, unsigned short btype, int zero)
{
	struct list_head *head = &(bs2_dev->block_inuse_head);
	struct bankshot2_blocknode *i, *next_i;
	struct bankshot2_blocknode *free_blocknode = NULL;
	void *bp;
	unsigned long num_blocks = 0;
	struct bankshot2_blocknode *curr_node;
	int errval = 0;
	bool found = 0;
	unsigned long next_block_low;
	unsigned long new_block_low;
	unsigned long new_block_high;

	num_blocks = bankshot2_get_numblocks(btype);

	mutex_lock(&bs2_dev->s_lock);

	list_for_each_entry(i, head, link) {
		if (i->link.next == head) {
			next_i = NULL;
			next_block_low = bs2_dev->block_end;
		} else {
			next_i = list_entry(i->link.next, typeof(*i), link);
			next_block_low = next_i->block_low;
		}

		new_block_low = (i->block_high + num_blocks) & ~(num_blocks - 1);
		new_block_high = new_block_low + num_blocks - 1;

		if (new_block_high >= next_block_low) {
			/* Does not fit - skip to next blocknode */
			continue;
		}

		if ((new_block_low == (i->block_high + 1)) &&
			(new_block_high == (next_block_low - 1)))
		{
			/* Fill the gap completely */
			if (next_i) {
				i->block_high = next_i->block_high;
				list_del(&next_i->link);
				free_blocknode = next_i;
				bs2_dev->num_blocknode_allocated--;
			} else {
				i->block_high = new_block_high;
			}
			found = 1;
			break;
		}

		if ((new_block_low == (i->block_high + 1)) &&
			(new_block_high < (next_block_low - 1))) {
			/* Aligns to left */
			i->block_high = new_block_high;
			found = 1;
			break;
		}

		if ((new_block_low > (i->block_high + 1)) &&
			(new_block_high == (next_block_low - 1))) {
			/* Aligns to right */
			if (next_i) {
				/* right node exist */
				next_i->block_low = new_block_low;
			} else {
				/* right node does NOT exist */
				curr_node = bankshot2_alloc_blocknode(bs2_dev);
				BUG_ON(!curr_node);
				if (curr_node == NULL) {
					errval = -ENOSPC;
					break;
				}
				curr_node->block_low = new_block_low;
				curr_node->block_high = new_block_high;
				list_add(&curr_node->link, &i->link);
			}
			found = 1;
			break;
		}

		if ((new_block_low > (i->block_high + 1)) &&
			(new_block_high < (next_block_low - 1))) {
			/* Aligns somewhere in the middle */
			curr_node = bankshot2_alloc_blocknode(bs2_dev);
			BUG_ON(!curr_node);
			if (curr_node == NULL) {
				errval = -ENOSPC;
				break;
			}
			curr_node->block_low = new_block_low;
			curr_node->block_high = new_block_high;
			list_add(&curr_node->link, &i->link);
			found = 1;
			break;
		}
	}
	
	if (found == 1) {
		bs2_dev->num_free_blocks -= num_blocks;
	}	

	mutex_unlock(&bs2_dev->s_lock);

	if (free_blocknode)
		__bankshot2_free_blocknode(bs2_dev, free_blocknode);

	if (found == 0) {
		return -ENOSPC;
	}

	if (zero) {
		size_t size;
		bp = bankshot2_get_block(bs2_dev,
			bankshot2_get_block_off(bs2_dev, new_block_low, btype));
//		bankshot2_memunlock_block(bs2_dev, bp); //TBDTBD: Need to fix this
		if (btype == BANKSHOT2_BLOCK_TYPE_4K)
			size = 0x1 << 12;
		else if (btype == BANKSHOT2_BLOCK_TYPE_2M)
			size = 0x1 << 21;
		else
			size = 0x1 << 30;
		memset_nt(bp, 0, size);
//		bankshot2_memlock_block(bs2_dev, bp);
	}
	*blocknr = new_block_low;

	return errval;
}

static int bankshot2_increase_btree_height(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, u32 new_height)
{
	u32 height = pi->height;
	__le64 *root, prev_root = pi->root;
	unsigned long blocknr;
	int errval = 0;

	bs2_dbg("increasing tree height %x:%x\n", height, new_height);
	while (height < new_height) {
		/* allocate the meta block */
		errval = bankshot2_new_block(bs2_dev, &blocknr,
						BANKSHOT2_BLOCK_TYPE_4K, 1);
		if (errval) {
			bs2_info("failed to increase btree height\n");
			break;
		}
		blocknr = bankshot2_get_block_off(bs2_dev, blocknr,
						BANKSHOT2_BLOCK_TYPE_4K);
		root = bankshot2_get_block(bs2_dev, blocknr);
//		bankshot2_memunlock_block(bs2_dev, root);
		root[0] = prev_root;
//		bankshot2_memlock_block(bs2_dev, root);
		bankshot2_flush_buffer(root, sizeof(*root), false);
		prev_root = cpu_to_le64(blocknr);
		height++;
	}
//	bankshot2_memunlock_inode(bs2_dev, pi);
	pi->root = prev_root;
	pi->height = height;
//	bankshot2_memlock_inode(bs2_dev, pi);
	return errval;
}

/*
 * allocate a data block for inode and return it's absolute blocknr.
 * Zeroes out the block if zero set. Increments inode->i_blocks.
 */
static int bankshot2_new_data_block(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, unsigned long *blocknr, int zero)
{
	unsigned int data_bits = PAGE_SHIFT;

	int errval = bankshot2_new_block(bs2_dev, blocknr, pi->i_blk_type, zero);

	if (!errval) {
//		bankshot2_memunlock_inode(bs2_dev, pi);
		le64_add_cpu(&pi->i_blocks,
			(1 << (data_bits - bs2_dev->s_blocksize_bits)));
//		bankshot2_memlock_inode(bs2_dev, pi);
	}

	return errval;
}

/* recursive_alloc_blocks: recursively allocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * zero: whether to zero-out the allocated block(s)
 */
static int recursive_alloc_blocks(bankshot2_transaction_t *trans,
	struct bankshot2_device *bs2_dev, struct bankshot2_inode *pi,
	__le64 block, u32 height, unsigned long first_blocknr,
	unsigned long last_blocknr, bool new_node, bool zero)
{
	int i, errval;
	unsigned int meta_bits = META_BLK_SHIFT, node_bits;
	__le64 *node;
	bool journal_saved = 0;
	unsigned long blocknr, first_blk, last_blk;
	unsigned int first_index, last_index;
	unsigned int flush_bytes;

	node = bankshot2_get_block(bs2_dev, le64_to_cpu(block));

	node_bits = (height - 1) * meta_bits;

	first_index = first_blocknr >> node_bits;
	last_index = last_blocknr >> node_bits;

	for (i = first_index; i <= last_index; i++) {
		if (height == 1) {
			if (node[i] == 0) {
				errval = bankshot2_new_data_block(bs2_dev, pi, &blocknr,
							zero);
				if (errval) {
					bs2_dbg("alloc data blk failed %d\n", errval);
					/* For later recovery in truncate... */
//					bankshot2_memunlock_inode(bs2_dev, pi);
//					pi->i_flags |= cpu_to_le32(
//							PMFS_EOFBLOCKS_FL);
//					bankshot2_memlock_inode(bs2_dev, pi);
					return errval;
				}
				/* save the meta-data into the journal before
				 * modifying */
				if (new_node == 0 && journal_saved == 0) {
//					int le_size = (last_index - i + 1) << 3;
//					bankshot2_add_logentry(bs2_dev, trans, &node[i],
//						le_size, LE_DATA);
					journal_saved = 1;
				}
//				bankshot2_memunlock_block(bs2_dev, node);
				node[i] = cpu_to_le64(bankshot2_get_block_off(bs2_dev,
						blocknr, pi->i_blk_type));
//				bankshot2_memlock_block(bs2_dev, node);
			}
		} else {
			if (node[i] == 0) {
				/* allocate the meta block */
				errval = bankshot2_new_block(bs2_dev, &blocknr,
						BANKSHOT2_BLOCK_TYPE_4K, 1);
				if (errval) {
					bs2_dbg("alloc meta blk failed\n");
					goto fail;
				}
				/* save the meta-data into the journal before
				 * modifying */
				if (new_node == 0 && journal_saved == 0) {
//					int le_size = (last_index - i + 1) << 3;
//					bankshot2_add_logentry(bs2_dev, trans, &node[i],
//						le_size, LE_DATA);
					journal_saved = 1;
				}
//				bankshot2_memunlock_block(bs2_dev, node);
				node[i] = cpu_to_le64(bankshot2_get_block_off(bs2_dev,
					    blocknr, BANKSHOT2_BLOCK_TYPE_4K));
//				bankshot2_memlock_block(bs2_dev, node);
				new_node = 1;
			}

			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			errval = recursive_alloc_blocks(trans, bs2_dev, pi, node[i],
			height - 1, first_blk, last_blk, new_node, zero);
			if (errval < 0)
				goto fail;
		}
	}
	if (new_node || trans == NULL) {
		/* if the changes were not logged, flush the cachelines we may
	 	* have modified */
		flush_bytes = (last_index - first_index + 1) * sizeof(node[0]);
		bankshot2_flush_buffer(&node[first_index], flush_bytes, false);
	}
	errval = 0;
fail:
	return errval;
}

int __bankshot2_alloc_blocks(bankshot2_transaction_t *trans,
	struct bankshot2_device *bs2_dev,
	struct bankshot2_inode *pi, unsigned long file_blocknr, unsigned int num,
	bool zero)
{
	int errval;
	unsigned long max_blocks;
	unsigned int height;
	unsigned int data_bits = PAGE_SHIFT;
	unsigned int blk_shift, meta_bits = META_BLK_SHIFT;
	unsigned long blocknr, first_blocknr, last_blocknr, total_blocks;
	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - bs2_dev->s_blocksize_bits;

	first_blocknr = file_blocknr >> blk_shift;
	last_blocknr = (file_blocknr + num - 1) >> blk_shift;

	bs2_dbg("alloc_blocks height %d file_blocknr %lx num %x, "
		   "first blocknr 0x%lx, last_blocknr 0x%lx\n",
		   pi->height, file_blocknr, num, first_blocknr, last_blocknr);

	height = pi->height;

	blk_shift = height * meta_bits;

	max_blocks = 0x1UL << blk_shift;

	if (last_blocknr > max_blocks - 1) {
		/* B-tree height increases as a result of this allocation */
		total_blocks = last_blocknr >> blk_shift;
		while (total_blocks > 0) {
			total_blocks = total_blocks >> meta_bits;
			height++;
		}
		if (height > 3) {
			bs2_dbg("[%s:%d] Max file size. Cant grow the file\n",
				__func__, __LINE__);
			errval = -ENOSPC;
			goto fail;
		}
	}

	if (!pi->root) {
		if (height == 0) {
			__le64 root;
			errval = bankshot2_new_data_block(bs2_dev, pi, &blocknr, zero);
			if (errval) {
				bs2_dbg("[%s:%d] failed: alloc data"
					" block\n", __func__, __LINE__);
				goto fail;
			}
			root = cpu_to_le64(bankshot2_get_block_off(bs2_dev, blocknr,
					   pi->i_blk_type));
//			bankshot2_memunlock_inode(bs2_dev, pi);
			pi->root = root;
			pi->height = height;
//			bankshot2_memlock_inode(bs2_dev, pi);
		} else {
			errval = bankshot2_increase_btree_height(bs2_dev, pi, height);
			if (errval) {
				bs2_dbg("[%s:%d] failed: inc btree"
					" height\n", __func__, __LINE__);
				goto fail;
			}
			errval = recursive_alloc_blocks(trans, bs2_dev, pi, pi->root,
			pi->height, first_blocknr, last_blocknr, 1, zero);
			if (errval < 0)
				goto fail;
		}
	} else {
		/* Go forward only if the height of the tree is non-zero. */
		if (height == 0)
			return 0;

		if (height > pi->height) {
			errval = bankshot2_increase_btree_height(bs2_dev, pi, height);
			if (errval) {
				bs2_dbg("Err: inc height %x:%x tot %lx"
					"\n", pi->height, height, total_blocks);
				goto fail;
			}
		}
		errval = recursive_alloc_blocks(trans, bs2_dev, pi, pi->root, height,
				first_blocknr, last_blocknr, 0, zero);
		if (errval < 0)
			goto fail;
	}
	return 0;
fail:
	return errval;
}

/*
 * Allocate num data blocks for inode, starting at given file-relative
 * block number.
 */
int bankshot2_alloc_blocks(bankshot2_transaction_t *trans,
		struct bankshot2_device *bs2_dev, struct bankshot2_inode *pi,
		unsigned long file_blocknr, unsigned int num, bool zero)
{
	int errval;

	errval = __bankshot2_alloc_blocks(trans, bs2_dev, pi, file_blocknr,
						num, zero);
//	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	return errval;
}

/* Examine the meta-data block node up to the end_idx for any non-null
 * pointers. If found return false, else return true.
 * Required to determine if a meta-data block contains no pointers and hence
 * can be freed.
 */
static inline bool is_empty_meta_block(__le64 *node, unsigned int start_idx,
					unsigned int end_idx)
{
	int i, last_idx = (1 << META_BLK_SHIFT) - 1;
	for (i = 0; i < start_idx; i++)
		if (unlikely(node[i]))
			return false;
	for (i = end_idx + 1; i < last_idx; i++)
		if (unlikely(node[i]))
			return false;
	return true;
}

/* Caller must hold super_block lock. If start_hint procided, it is
 * only valid until the caller releases the super_block lock */
void __bankshot2_free_block(struct bankshot2_device *bs2_dev,
		unsigned long blocknr, unsigned short btype,
		struct bankshot2_blocknode **start_hint)
{
	struct list_head *head = &(bs2_dev->block_inuse_head);
	unsigned long new_block_low;
	unsigned long new_block_high;
	unsigned long num_blocks = 0;
	struct bankshot2_blocknode *i;
	struct bankshot2_blocknode *free_blocknode = NULL;
	struct bankshot2_blocknode *curr_node;

	num_blocks = bankshot2_get_numblocks(btype);
	new_block_low = blocknr;
	new_block_high = blocknr + num_blocks - 1;

	BUG_ON(list_empty(head));

	if (start_hint && *start_hint &&
			new_block_low >= (*start_hint)->block_low)
		i = *start_hint;
	else
		i = list_first_entry(head, typeof(*i), link);

	list_for_each_entry_from(i, head, link) {
		if (new_block_low > i->block_high) {
			// Skip to next blocknode
			continue;
		}

		if ((new_block_low == i->block_low) &&
		    (new_block_high == i->block_high)) {
			// Fits entire datablock
			if (start_hint)
				*start_hint = bankshot2_next_blocknode(i, head);
			list_del(&i->link);
			free_blocknode = i;
			bs2_dev->num_blocknode_allocated--;
			bs2_dev->num_free_blocks += num_blocks;
			goto block_found;
		}

		if ((new_block_low == i->block_low) &&
		    (new_block_high < i->block_high)) {
			// Align to left
			i->block_low = new_block_high + 1;
			bs2_dev->num_free_blocks += num_blocks;
			if (start_hint)
				*start_hint = i;
			goto block_found;
		}

		if ((new_block_low > i->block_low) &&
		    (new_block_high == i->block_high)) {
			// Align to right
			i->block_high = new_block_low - 1;
			bs2_dev->num_free_blocks += num_blocks;
			if (start_hint)
				*start_hint = bankshot2_next_blocknode(i, head);
			goto block_found;
		}

		if ((new_block_low > i->block_low) &&
		    (new_block_high < i->block_high)) {
			// Align in the middle
			curr_node = bankshot2_alloc_blocknode(bs2_dev);
			if (!curr_node)
				goto block_found;
			curr_node->block_low = new_block_high + 1;
			curr_node->block_high = i->block_high;
			i->block_high = new_block_low - 1;
			list_add(&curr_node->link, &i->link);
			bs2_dev->num_free_blocks += num_blocks;
			if (start_hint)
				*start_hint = curr_node;
			goto block_found;
		}
	}

	bs2_info("Unable to free block %ld\n", blocknr);

block_found:
	if (free_blocknode)
		__bankshot2_free_blocknode(bs2_dev, free_blocknode);
}

void bankshot2_free_block(struct bankshot2_device *bs2_dev,
		unsigned long blocknr, unsigned short btype)
{
	mutex_lock(&bs2_dev->s_lock);
	__bankshot2_free_block(bs2_dev, blocknr, btype, NULL);
	mutex_unlock(&bs2_dev->s_lock);
}

/* recursive_truncate_blocks: recursively deallocate a range of blocks from
 * the first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the b-tree
 * first_blocknr: first block in the specified range
 * last_blocknr: last blocknr in the specified range
 * end: last byte offset of the range
 */
int recursive_truncate_blocks(struct bankshot2_device *bs2_dev, __le64 block,
		u32 height, u32 btype, unsigned long first_blocknr,
		unsigned long last_blocknr, bool *meta_empty)
{
	struct bankshot2_blocknode *start_hint = NULL;
	unsigned long blocknr, first_blk, last_blk;
	unsigned int node_bits, first_index, last_index, i;
	__le64 *node;
	unsigned int freed = 0, bzero;
	int start, end;
	bool mpty, all_range_freed = true;

	node = bankshot2_get_block(bs2_dev, le64_to_cpu(block));
	node_bits = (height - 1) * META_BLK_SHIFT;

	start = first_index = first_blocknr >> node_bits;
	end = last_index = last_blocknr >> node_bits;

	if (height == 1) {
		mutex_lock(&bs2_dev->s_lock);
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			/* Freeing the data block */
			blocknr = bankshot2_get_blocknr(le64_to_cpu(node[i]));
			__bankshot2_free_block(bs2_dev, blocknr, btype,
						&start_hint);
			freed++;
		}
		mutex_unlock(&bs2_dev->s_lock);
	} else {
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;
			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			freed += recursive_truncate_blocks(bs2_dev, node[i],
					height - 1, btype, first_blk,
					last_blk, &mpty);

			if (mpty) {
				/* Free the meta-data block; */
				blocknr = bankshot2_get_blocknr(
							le64_to_cpu(node[i]));
				bankshot2_free_block(bs2_dev, blocknr,
						BANKSHOT2_BLOCK_TYPE_4K);
			} else {
				if (i == first_index)
					start++;
				else if (i == last_index)
					end--;
				all_range_freed = false;
			}
		}
	}

	if (all_range_freed &&
			is_empty_meta_block(node, first_index, last_index)) {
		*meta_empty = true;
	} else {
		/* Zero out the freed range if the meta-block is not empty */
		if (start <= end) {
			bzero = (end - start + 1) * sizeof(u64);
//			bankshot2_memunlock_block(bs2_dev, node);
			memset(&node[start], 0, bzero);
//			bankshot2_memlock_block(bs2_dev, node);
			bankshot2_flush_buffer(&node[start], bzero, false);
		}
		*meta_empty = false;
	}

	return freed;
}

int bankshot2_init_blockmap(struct bankshot2_device *bs2_dev,
				unsigned long init_used_size)
{
	unsigned long num_used_block;
	struct bankshot2_blocknode *blknode;

	num_used_block = (init_used_size + bs2_dev->blocksize - 1) >>
		bs2_dev->s_blocksize_bits;

	bs2_info("blockmap init: used %lu blocks\n", num_used_block);
	blknode = bankshot2_alloc_blocknode(bs2_dev);
	if (blknode == NULL) {
		bs2_info("WARNING: blocknode allocation failed\n");
		return -ENOMEM;
	}

	blknode->block_low = bs2_dev->block_start;
	blknode->block_high = bs2_dev->block_start + num_used_block - 1;
	bs2_dev->num_free_blocks -= num_used_block;
	list_add(&blknode->link, &bs2_dev->block_inuse_head);

	return 0;
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

