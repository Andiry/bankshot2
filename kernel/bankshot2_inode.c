/*
 * inode code.
 * Copied from Pmfs inode code.
 */

#include "bankshot2.h"

unsigned int blk_type_to_shift[3] = {12, 21, 30};
uint32_t blk_type_to_size[3] = {0x1000, 0x200000, 0x40000000};

static inline struct bankshot2_inode *
bankshot2_get_inode_table(struct bankshot2_device *bs2_dev)
{
	struct bankshot2_super_block *ps = bankshot2_get_super(bs2_dev);

	return (struct bankshot2_inode *)((char *)ps +
			le64_to_cpu(ps->s_inode_table_offset));
}

/*
 * find the offset to the block represented by the given inode's file
 * relative block number.
 */
u64 bankshot2_find_data_block(struct bankshot2_device *bs2_dev,
			struct bankshot2_inode *pi, unsigned long file_blocknr)
{
	u32 blk_shift;
	unsigned long blk_offset, blocknr = file_blocknr;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int meta_bits = META_BLK_SHIFT;
	u64 bp;

	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - bs2_dev->s_blocksize_bits;
	blk_offset = file_blocknr & ((1 << blk_shift) - 1);
	blocknr = file_blocknr >> blk_shift;

	if (blocknr >= (1UL << (pi->height * meta_bits)))
		return 0;

	bp = __bankshot2_find_data_block(bs2_dev, pi, blocknr);
	bs2_dbg("find_data_block %lu, %x %llu blk_p %p blk_shift %x"
		" blk_offset %lx\n", file_blocknr, pi->height, bp,
		bankshot2_get_block(bs2_dev, bp), blk_shift, blk_offset);

	if (bp == 0)
		return 0;
	return bp + (blk_offset << bs2_dev->s_blocksize_bits);
}

u64 bankshot2_find_data_block_verbose(struct bankshot2_device *bs2_dev,
			struct bankshot2_inode *pi, unsigned long file_blocknr)
{
	u32 blk_shift;
	unsigned long blk_offset, blocknr = file_blocknr;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int meta_bits = META_BLK_SHIFT;
	u64 bp;

	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - bs2_dev->s_blocksize_bits;
	blk_offset = file_blocknr & ((1 << blk_shift) - 1);
	blocknr = file_blocknr >> blk_shift;

	if (blocknr >= (1UL << (pi->height * meta_bits)))
		return 0;

	bp = __bankshot2_find_data_block_verbose(bs2_dev, pi, blocknr);
	bs2_info("find_data_block %lu, %x %llu blk_p %p blk_shift %x"
		" blk_offset %lx\n", file_blocknr, pi->height, bp,
		bankshot2_get_block(bs2_dev, bp), blk_shift, blk_offset);

	if (bp == 0)
		return 0;
	return bp + (blk_offset << bs2_dev->s_blocksize_bits);
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

static int bankshot2_increase_inode_table_size(struct bankshot2_device *bs2_dev)
{
	struct bankshot2_inode *pi = bankshot2_get_inode_table(bs2_dev);
	bankshot2_transaction_t *trans = NULL;
	int errval;

	/* 1 log entry for inode-table inode, 1 lentry for inode-table b-tree */
	trans = bankshot2_new_transaction(bs2_dev, MAX_INODE_LENTRIES);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	bankshot2_add_logentry(bs2_dev, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	errval = __bankshot2_alloc_blocks(trans, bs2_dev, pi,
			le64_to_cpup(&pi->i_size) >> bs2_dev->s_blocksize_bits,
			1, true);

	if (errval == 0) {
		u64 i_size = le64_to_cpu(pi->i_size);

		bs2_dev->s_free_inode_hint = i_size >> BANKSHOT2_INODE_BITS;
		i_size += bankshot2_inode_blk_size(pi);

//		bankshot2_memunlock_inode(sb, pi);
		pi->i_size = cpu_to_le64(i_size);
//		bankshot2_memlock_inode(sb, pi);

		bs2_dev->s_free_inodes_count +=
			INODES_PER_BLOCK(pi->i_blk_type);
		bs2_dev->s_inodes_count = i_size >> BANKSHOT2_INODE_BITS;
	} else
		bs2_dbg("no space left to inc inode table!\n");
	/* commit the transaction */
	bankshot2_commit_transaction(bs2_dev, trans);
	return errval;
}

void bankshot2_get_inode_flags(struct inode *inode, struct bankshot2_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int bankshot2_flags = le32_to_cpu(pi->i_flags);

	bankshot2_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
				FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		bankshot2_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		bankshot2_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		bankshot2_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		bankshot2_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		bankshot2_flags |= FS_DIRSYNC_FL;

	pi->i_flags = cpu_to_le32(bankshot2_flags);
}

static void bankshot2_update_inode(struct inode *inode,
					struct bankshot2_inode *pi)
{
//	bankshot2_memunlock_inode(inode->i_sb, pi);
	pi->i_mode = cpu_to_le16(inode->i_mode);
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_blocks = cpu_to_le64(inode->i_blocks);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
//	pi->i_generation = cpu_to_le32(inode->i_generation);
	bankshot2_get_inode_flags(inode, pi);

//	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
//		pi->dev.rdev = cpu_to_le32(inode->i_rdev);

//	bankshot2_memlock_inode(inode->i_sb, pi);
}

int bankshot2_new_inode(struct bankshot2_device *bs2_dev, struct inode *inode,
		bankshot2_transaction_t *trans,
		struct bankshot2_inode **new_pi, u64 *new_ino)
{
	struct bankshot2_inode *pi = NULL, *inode_table;
	int i, errval;
	u32 num_inodes, inodes_per_block;
	u64 ino = 0;

#if 0
	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	inode->i_generation = atomic_add_return(1, &sbi->next_generation);
#endif

	inode_table = bankshot2_get_inode_table(bs2_dev);

	bs2_dbg("free_inodes %x total_inodes %x hint %x\n",
		bs2_dev->s_free_inodes_count, bs2_dev->s_inodes_count,
		bs2_dev->s_free_inode_hint);

//	mutex_lock(&bs2_dev->inode_table_mutex);

	/* find the oldest unused bankshot2 inode */
	i = (bs2_dev->s_free_inode_hint);
	inodes_per_block = INODES_PER_BLOCK(inode_table->i_blk_type);
retry:
	num_inodes = (bs2_dev->s_inodes_count);
	while (i < num_inodes) {
		u32 end_ino;
		end_ino = i + (inodes_per_block - (i & (inodes_per_block - 1)));
//		ino = i << PMFS_INODE_BITS;
		pi = bankshot2_get_inode(bs2_dev, i);
		for (; i < end_ino; i++) {
			/* check if the inode is active. */
			if (le16_to_cpu(pi->i_links_count) == 0 &&
			(le16_to_cpu(pi->i_mode) == 0 ||
			 le32_to_cpu(pi->i_dtime)))
				/* this inode is free */
				break;
			pi = (struct bankshot2_inode *)((void *)pi +
							BANKSHOT2_INODE_SIZE);
		}
		/* found a free inode */
		if (i < end_ino)
			break;
	}
	if (unlikely(i >= num_inodes)) {
		errval = bankshot2_increase_inode_table_size(bs2_dev);
		if (errval == 0)
			goto retry;
		mutex_unlock(&bs2_dev->inode_table_mutex);
		bs2_dbg("Bankshot2: could not find a free inode\n");
		goto fail1;
	}

//	ino = i << PMFS_INODE_BITS;
	ino = i;
	bs2_dbg("allocating inode %llu\n", ino);

	/* chosen inode is in ino */
//	inode->i_ino = ino;
	bankshot2_add_logentry(bs2_dev, trans, pi, sizeof(*pi), LE_DATA);

//	bankshot2_memunlock_inode(sb, pi);
	pi->i_blk_type = BANKSHOT2_DEFAULT_BLOCK_TYPE;
//	pi->i_flags = bankshot2_mask_flags(mode, diri->i_flags);
	pi->height = 0;
	pi->start_index = ULONG_MAX;
	pi->root = 0;
	pi->i_dtime = 0;
	pi->extent_tree = RB_ROOT;
	pi->access_tree = RB_ROOT;
	init_waitqueue_head(&pi->wait_queue);
//	pi->extent_tree_lock = __RW_LOCK_UNLOCKED(extent_tree_lock);
	mutex_init(&pi->tree_lock);
	pi->num_extents = 0;
	pi->num_access_extents = 0;
	INIT_LIST_HEAD(&pi->lru_list);
	list_add_tail(&pi->lru_list, &bs2_dev->pi_lru_list);
	bs2_dev->cache_stats.inode_alloc++;

//	bankshot2_memlock_inode(sb, pi);

	bs2_dev->s_free_inodes_count -= 1;

	if (i < (bs2_dev->s_inodes_count) - 1)
		bs2_dev->s_free_inode_hint = (i + 1);
	else
		bs2_dev->s_free_inode_hint = (BANKSHOT2_FREE_INODE_HINT_START);

//	mutex_unlock(&bs2_dev->inode_table_mutex);

	bankshot2_update_inode(inode, pi);

//	bankshot2_set_inode_flags(inode, pi);

	*new_ino = ino;
	pi->i_ino = cpu_to_le64(ino);
	pi->backup_ino = cpu_to_le64(inode->i_ino);

	*new_pi = pi;
	return 0;
fail1:
	*new_pi = NULL;
	return errval;
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
//	bs2_dbg("%s: internal block %llu, actual block %llu, ino_offset %llu\n",
//			__func__, block, bp / PAGE_SIZE, ino_offset);
	return (struct bankshot2_inode *)((void *)ps + bp + ino_offset);
}

struct bankshot2_inode *
bankshot2_check_existing_inodes(struct bankshot2_device *bs2_dev,
		struct inode *inode, u64 *st_ino)
{
	struct hash_inode *entry;
	struct bankshot2_inode *pi;
	int key, i;
	u64 ino;

#if 0
	for (i = BANKSHOT2_FREE_INODE_HINT_START;
			i < bs2_dev->s_inodes_count; i++) {
		pi = bankshot2_get_inode(bs2_dev, i);
		if (pi && le64_to_cpu(pi->backup_ino) == inode->i_ino) {
			*st_ino = i;
			return pi;
		}
	}
#endif

	key = inode->i_ino % HASH_ARRAY_SIZE;
	entry = &bs2_dev->inode_hash_array[key];
	if (entry->count == 0)
		return NULL;

	if (entry->size == 1) {
		pi = bankshot2_get_inode(bs2_dev, entry->ino);
		if (pi && le64_to_cpu(pi->backup_ino) == inode->i_ino) {
			*st_ino = entry->ino;
			return pi;
		}
		return NULL;
	}

	for (i = 0; i < entry->count; i++) {
		ino = entry->ino_array[i];
		pi = bankshot2_get_inode(bs2_dev, ino);
		if (pi && le64_to_cpu(pi->backup_ino) == inode->i_ino) {
			*st_ino = ino;
			return pi;
		}
	}

	return NULL;
}

static int bankshot2_insert_inode_hash_array(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi)
{
	struct hash_inode *entry;
	u64 temp_ino;
	u64 *new_array;
	int key, i;

	bs2_dbg("Pi %p ino %llu, backup ino %llu insert\n",
			pi, pi->i_ino, pi->backup_ino);

	key = pi->backup_ino % HASH_ARRAY_SIZE;
	entry = &bs2_dev->inode_hash_array[key];

	/* First insert */
	if (entry->count == 0 && entry->size == 1) {
		entry->ino = pi->i_ino;
		entry->count++;
		return 0;
	}

	/* Space in ino_array */
	if (entry->count < entry->size) {
		entry->ino_array[entry->count] = pi->i_ino;
		entry->count++;
		return 0;
	}

	/* Move from ino to array, 4 entries */
	if (entry->size == 1) {
		temp_ino = entry->ino;
		entry->ino_array = kzalloc(4 * sizeof(u64), GFP_KERNEL);
		entry->ino_array[0] = temp_ino;
		entry->ino_array[1] = pi->i_ino;
		entry->size = 4;
		entry->count = 2;
		return 0;
	}

	/* Double the array */
	new_array = kzalloc(entry->size * 2 * sizeof(u64), GFP_KERNEL);
	for (i = 0; i < entry->count; i++)
		new_array[i] = entry->ino_array[i];
	new_array[entry->count] = pi->i_ino;
	kfree(entry->ino_array);
	entry->ino_array = new_array;
	entry->size = entry->size * 2;
	entry->count++;

	return 0;
}

static int bankshot2_remove_inode_hash_array(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi)
{
	struct hash_inode *entry;
	int key, i, j;

	key = pi->backup_ino % HASH_ARRAY_SIZE;
	entry = &bs2_dev->inode_hash_array[key];

	if (entry->size == 1) {
		if (entry->ino == pi->i_ino) {
			entry->count = 0;
			entry->ino = 0;
			return 0;
		}

		goto not_found;
	}

	for (i = 0; i < entry->count; i++) {
		if (entry->ino_array[i] == pi->i_ino) {
			for (j = i; j < entry->count - 1; j++)
				entry->ino_array[j] = entry->ino_array[j + 1];
			entry->ino_array[j] = 0;
			entry->count--;
			return 0;
		}
	}

not_found:
	bs2_info("Pi %p ino %llu, backup ino %llu not found!\n",
			pi, pi->i_ino, pi->backup_ino);
	return -1;
}

struct bankshot2_inode *
bankshot2_find_cache_inode(struct bankshot2_device *bs2_dev,
			struct bankshot2_cache_data *data, u64 *st_ino)
{
	struct bankshot2_inode *pi;
	struct inode *inode;
	bankshot2_transaction_t *trans;
	u64 ino;
	int ret;

	inode = data->inode;

	if (data->cache_ino) {
		ino = data->cache_ino;
		pi = bankshot2_get_inode(bs2_dev, ino);
		if (pi && le64_to_cpu(pi->backup_ino) == inode->i_ino) {
			bs2_dbg("Found cache inode %llu\n", ino);
			data->cache_file_size = le64_to_cpu(pi->i_size);
			if (pi->backup_ino == 0)
				bs2_info("pi %llu backup ino is 0?\n",
						pi->i_ino);
			goto found;
		} else if (!pi) {
			bs2_info("Try to get ino %llu but cache inode not found"
					", Allocate new inode\n", ino);
		} else {
			bs2_info("Data cache_ino and cache inode doesn't match,"
					" data cache ino %llu,"
					" pi->backup ino %llu,"
					" inode->i_ino %lu\n",
					ino, le64_to_cpu(pi->backup_ino),
					inode->i_ino);
		}
	}

	pi = bankshot2_check_existing_inodes(bs2_dev, inode, &ino);
	if (pi) {
		bs2_info("Found existing match inode %llu\n", ino);
		goto found;
	}

	/* Allocate new inode */
	trans = bankshot2_new_transaction(bs2_dev, MAX_INODE_LENTRIES * 2 +
			MAX_DIRENTRY_LENTRIES);
	if (IS_ERR(trans))
		return NULL;

	ret = bankshot2_new_inode(bs2_dev, inode, trans, &pi, &ino);
	if (ret) {
		bs2_info("Allocate new inode failed %d\n", ret);
		bankshot2_abort_transaction(bs2_dev, trans);
		return NULL;
	}

	bankshot2_insert_inode_hash_array(bs2_dev, pi);

	bankshot2_commit_transaction(bs2_dev, trans);
	bs2_info("Allocated new pi %llu, backup ino %llu\n",
			ino, pi->backup_ino);
	data->cache_file_size = 0;
found:
	bs2_dbg("Return pi %llu, backup ino %llu\n",
			ino, pi->backup_ino);
	*st_ino = ino;
	data->cache_ino = ino;
	pi->inode = inode;

	return pi;
}

static int bankshot2_free_inode(struct bankshot2_device *bs2_dev,
				struct bankshot2_inode *pi)
{
	unsigned long inode_nr;
	bankshot2_transaction_t *trans;
	int err = 0;

	mutex_lock(&bs2_dev->inode_table_mutex);

	bs2_dbg("Before free_inode: %llx free_inodes %x "
		"total inodes %x hint %x\n",
		pi->i_ino, bs2_dev->s_free_inodes_count,
		bs2_dev->s_inodes_count, bs2_dev->s_free_inode_hint);

	inode_nr = pi->i_ino;

	trans = bankshot2_new_transaction(bs2_dev, MAX_INODE_LENTRIES);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto out;
	}

	bankshot2_add_logentry(bs2_dev, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

//	bankshot2_memunlock_inode(sb, pi);

	pi->root = 0;
//	pi->i_links_count = 0;
//	pi->i_xattr = 0;
	pi->start_index = ULONG_MAX;
	pi->i_size = 0;
	pi->i_dtime = cpu_to_le32(get_seconds());
//	bankshot2_memlock_inode(sb, pi);

	bankshot2_commit_transaction(bs2_dev, trans);

	/* increment s_free_inodes_count */
	if (inode_nr < (bs2_dev->s_free_inode_hint))
		bs2_dev->s_free_inode_hint = (inode_nr);

	bs2_dev->s_free_inodes_count += 1;

	if ((bs2_dev->s_free_inodes_count) ==
	    (bs2_dev->s_inodes_count) - BANKSHOT2_FREE_INODE_HINT_START) {
		/* filesystem is empty */
		bs2_dbg("fs is empty!\n");
		bs2_dev->s_free_inode_hint = (BANKSHOT2_FREE_INODE_HINT_START);
	}

	bs2_dbg("After free_inode: free_nodes %x total_nodes %x hint %x\n",
		   bs2_dev->s_free_inodes_count, bs2_dev->s_inodes_count,
		   bs2_dev->s_free_inode_hint);

	list_del(&pi->lru_list);

	bankshot2_remove_inode_hash_array(bs2_dev, pi);
	pi->backup_ino = 0;
	pi->height = 0;
	pi->i_blocks = 0;
out:
	mutex_unlock(&bs2_dev->inode_table_mutex);
	return err;
}

unsigned int bankshot2_free_inode_subtree(struct bankshot2_device *bs2_dev,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr)
{
	unsigned long first_blocknr;
	unsigned int freed;
	bool mpty;

	if (!root)
		return 0;

	if (height == 0) {
		first_blocknr = bankshot2_get_blocknr(le64_to_cpu(root));
		bankshot2_free_block(bs2_dev, first_blocknr, btype);
		freed = 1;
	} else {
		first_blocknr = 0;

		freed = recursive_truncate_blocks(bs2_dev, root, height, btype,
				first_blocknr, last_blocknr, &mpty);
		BUG_ON(!mpty);
		first_blocknr = bankshot2_get_blocknr(le64_to_cpu(root));
		bankshot2_free_block(bs2_dev, first_blocknr,
					BANKSHOT2_BLOCK_TYPE_4K);
	}

	return freed;
}

void bankshot2_evict_inode(struct bankshot2_device *bs2_dev,
				struct bankshot2_inode *pi)
{
	__le64 root;
	unsigned long last_blocknr;
	unsigned int height, btype;
	int err = 0;

	if (!pi)
		return;

	bs2_info("%s: inode %llu\n", __func__, pi->i_ino);

	root = pi->root;
	height = pi->height;
	btype = pi->i_blk_type;

	if (likely(pi->i_size))
		last_blocknr = (pi->i_size - 1) >>
				bankshot2_inode_blk_shift(pi);
	else
		last_blocknr = 0;

	last_blocknr = bankshot2_sparse_last_blocknr(pi->height, last_blocknr);
	err = bankshot2_free_inode(bs2_dev, pi);
	if (err) {
		bs2_info("%s: free_inode failed %d\n", __func__, err);
		return;
	}
	pi = NULL;

	bankshot2_free_inode_subtree(bs2_dev, root, height, btype,
					last_blocknr);
	bs2_dev->cache_stats.inode_evict++;
}

#if 0
unsigned int bankshot2_free_inode_num_blocks(struct bankshot2_device *bs2_dev,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr,
		int num_free)
{
	unsigned long first_blocknr;
	unsigned int freed;
	bool mpty;

	if (!root)
		return 0;

	if (height == 0) {
		first_blocknr = bankshot2_get_blocknr(le64_to_cpu(root));
		bankshot2_free_block(bs2_dev, first_blocknr, btype);
		freed = 1;
	} else {
		first_blocknr = 0;

		freed = recursive_reclaim_blocks(bs2_dev, root, height, btype,
				first_blocknr, last_blocknr, &mpty, num_free);
		BUG_ON(!mpty);
//		first_blocknr = bankshot2_get_blocknr(le64_to_cpu(root));
//		bankshot2_free_block(bs2_dev, first_blocknr,
//					BANKSHOT2_BLOCK_TYPE_4K);
	}

	return freed;
}
#endif

/* FIXME: Deprecated */
int bankshot2_reclaim_num_blocks(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, int num_free)
{
	int num_freed;

	if (!pi || pi->i_size < num_free * PAGE_SIZE) {
		bs2_info("pi %llu does not have %d pages: size %llu\n",
				pi->i_ino, num_free, pi->i_size);
		return -ENOSPC;
	}

//	num_freed = bankshot2_free_num_blocks(bs2_dev, pi, num_free);
	num_freed = 0;

	bs2_info("pi %llu freed %d blocks, requires %d blocks\n",
				pi->i_ino, num_freed, num_free);

	if (num_freed >= num_free)
		return 0;
	else
		return -ENOSPC;
}

int bankshot2_get_backing_inode(struct bankshot2_device *bs2_dev,
					void *arg, struct inode **st_inode)
{
	struct file *fileinfo;
	struct inode *inode;
	struct bankshot2_cache_data *data;

	data = (struct bankshot2_cache_data *)arg;
	fileinfo = fget(data->file);
	if (!fileinfo) {
		bs2_info("fget failed\n");
		return -EINVAL;
	}

	inode = fileinfo->f_dentry->d_inode;
	if (!inode) {
		fput(fileinfo);
		bs2_info("inode get failed %p\n", inode);
		return -EINVAL;
	}

	data->read = data->write = 0;
	if (fileinfo->f_mode & FMODE_READ)
		data->read = 1;
	if (fileinfo->f_mode & FMODE_WRITE)
		data->write = 1;

	//we should invalidate the inode's buffer-cache mappings as well, so we don't get invalid data later

	fput(fileinfo);
	*st_inode = inode;
	bs2_dbg("Inode %p permissions: Read %d Write %d\n", *st_inode,
			data->read, data->write);

	return 0;
}

int bankshot2_ioctl_get_cache_inode(struct bankshot2_device *bs2_dev, void *arg)
{
	struct bankshot2_cache_data _data, *data;
	struct bankshot2_inode *pi;
	int ret;
	u64 st_ino;
	struct inode *inode;
	timing_t get_inode_time;

	data = &_data;

	BANKSHOT2_START_TIMING(bs2_dev, get_inode_t, get_inode_time);
	ret = bankshot2_get_backing_inode(bs2_dev, arg, &inode);
	if (ret) {
		bs2_info("Get backing inode returned %d\n", ret);
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	data->inode = inode;

	mutex_lock(&bs2_dev->inode_table_mutex);
	pi = bankshot2_find_cache_inode(bs2_dev, data, &st_ino);
	mutex_unlock(&bs2_dev->inode_table_mutex);

	if (!pi) {
		bs2_info("No cache inode found\n");
		return -EINVAL;
	}

	copy_to_user(arg, data, sizeof(struct bankshot2_cache_data));

	bs2_dbg("Cache ino %llu, ret %d\n", data->cache_ino, ret);
	BANKSHOT2_END_TIMING(bs2_dev, get_inode_t, get_inode_time);

	return ret;
}

int bankshot2_ioctl_evict_cache_inode(struct bankshot2_device *bs2_dev, void *arg)
{
	struct bankshot2_cache_data _data, *data;
	struct bankshot2_inode *pi;
	int ret;
	u64 st_ino;
	struct inode *inode;
	timing_t evict_inode_time;

	data = &_data;

	BANKSHOT2_START_TIMING(bs2_dev, evict_inode_t, evict_inode_time);
	ret = bankshot2_get_backing_inode(bs2_dev, arg, &inode);
	if (ret) {
		bs2_info("Get backing inode returned %d\n", ret);
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	data->inode = inode;

	mutex_lock(&bs2_dev->inode_table_mutex);
	pi = bankshot2_find_cache_inode(bs2_dev, data, &st_ino);
	mutex_unlock(&bs2_dev->inode_table_mutex);

	if (!pi) {
		bs2_info("No cache inode found\n");
		return -EINVAL;
	}

	bankshot2_evict_inode(bs2_dev, pi);

	BANKSHOT2_END_TIMING(bs2_dev, evict_inode_t, evict_inode_time);

	return ret;
}

