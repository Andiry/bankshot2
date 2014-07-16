/*
 * Copied from pmfs/xip.c
 */

#include "bankshot2.h"

static void bankshot2_decide_mmap_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		u64 *pos, size_t *count, u64 *b_offset)
{
	/* If mmap length > 0, we need to copy start from mmap offset;
	   otherwise we will just copy start from offset. */
	/* Must ensure that the required extent is covered by fiemap extent */

	if (data->extent_start_file_offset <= ALIGN_DOWN_MMAP(data->offset)) {
		data->mmap_offset = ALIGN_DOWN_MMAP(data->offset);
	} else {
		data->mmap_offset = ALIGN_DOWN(data->extent_start_file_offset);
	}

	data->mmap_length = ALIGN_DOWN(data->extent_start_file_offset +
			data->extent_length - data->mmap_offset);

	if (data->mmap_length > MAX_MMAP_SIZE)
		data->mmap_length = MAX_MMAP_SIZE;

	/* (data->mmap_offset + data->mmap_length) should be aligned to
	 * MAX_MMAP size */
	if (((ALIGN_DOWN_MMAP(data->mmap_offset + data->mmap_length)
				> ALIGN_DOWN_MMAP(data->mmap_offset)) &&
			(data->mmap_offset + data->mmap_length) % MAX_MMAP_SIZE))
		data->mmap_length -= 
			(data->mmap_offset + data->mmap_length) % MAX_MMAP_SIZE;

	if (data->extent_start_file_offset + data->extent_length
			<= data->mmap_offset)
		bs2_info("ERROR: mmap length will be less than zero! "
			"start file offset 0x%llx, extent length %lu, "
			"mmap offset 0x%llx\n",
			data->extent_start_file_offset, data->extent_length,
			data->mmap_offset);

	/* If we cannot mmap MAX_MMAP_SIZE, don't do mmap.
	 * Otherwise there will be numerous unmapping and remapping. */
	if (data->mmap_length < MAX_MMAP_SIZE)
		data->mmap_length = 0;

	if (data->mmap_length) {
		*pos = data->mmap_offset;
		*count = data->mmap_offset + data->mmap_length
					> data->offset + data->size ?
				data->mmap_length :
				data->offset + data->size - data->mmap_offset;
		*b_offset = data->extent_start + data->mmap_offset
				- data->extent_start_file_offset;
	} else {
		*pos = data->offset;
		*count = data->size;
		*b_offset = data->extent_start + data->offset
				- data->extent_start_file_offset;
	}

//	/* Limit request length to 2MB */
//	if (*count > MAX_MMAP_SIZE)
//		*count = MAX_MMAP_SIZE - (*pos & (MAX_MMAP_SIZE - 1));

	data->actual_offset = *pos;
	bs2_dbg("%s, inode %llu, offset %llu, length %lu\n",
			__func__, pi->i_ino, *pos, *count);
}

static int bankshot2_reclaim_blocks(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		int *num_free)
{
	struct bankshot2_inode *victim_pi;

	bs2_info("Reclaim blocks for pi %llu\n", pi->i_ino);
	victim_pi = list_first_entry(&bs2_dev->pi_lru_list,
				struct bankshot2_inode, lru_list);

	if (!victim_pi) {
		bs2_info("ERROR: victim pi not found\n");
		*num_free = 0;
		return -EINVAL;
	}

	/* Now victim pi can be the pi requesting blocks, or not */
	if (victim_pi == pi) {
		bs2_info("victim pi same as current pi\n");
		bankshot2_evict_extent(bs2_dev, victim_pi, data, num_free);
	} else {
		/* Get lock first */
		bs2_info("victim pi: %llu\n", victim_pi->i_ino);
		mutex_lock(victim_pi->btree_lock);
		bankshot2_evict_extent(bs2_dev, victim_pi, data, num_free);
		mutex_unlock(victim_pi->btree_lock);

		if (*num_free == 0) {
			*num_free = victim_pi->i_blocks;
			bankshot2_evict_inode(bs2_dev, victim_pi);
		}
	}

	return 0;			
}

/* Pre allocate the blocks we need.
 * Return 1 means we evicted a extent. */
static int bankshot2_prealloc_blocks(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		char **void_array, u64 offset, size_t length, u64 user_offset,
		size_t req_len,	struct extent_entry **access_extent, int write)
{
	unsigned long index;
	unsigned long count;
	unsigned long unallocated = 0;
	unsigned long required = 0;
	u64 block;
	u64 curr_offset;
	char *array, *alloc_array;
	int num_free, i;
	int err = 0;
	timing_t alloc, evict, update_phy;

	index = offset >> bs2_dev->s_blocksize_bits;
	count = length >> bs2_dev->s_blocksize_bits;
	if (length % bs2_dev->blocksize)
		count++;

	array = kzalloc(count, GFP_KERNEL);
	BUG_ON(!array);
	alloc_array = kzalloc(count, GFP_KERNEL);
	BUG_ON(!alloc_array);

	bs2_dbg("%s: %llu, %lu\n", __func__, offset, length);
//	bankshot2_print_tree(bs2_dev, pi);
	bs2_dbg("pi root @ 0x%llx, height %u", pi->root, pi->height);

	mutex_lock(pi->btree_lock);

	for (i = 0; i < count; i++) {
		block = bankshot2_find_data_block(bs2_dev, pi, index + i);
		if (!block) {
			unallocated++;
			required++;
			alloc_array[i] = 0x1;
			array[i] = 0x1;
			curr_offset = (index + i) << bs2_dev->s_blocksize_bits;
			if ((write == 1) && (user_offset <= curr_offset) &&
			    (user_offset + req_len >=
					curr_offset + bs2_dev->blocksize)) {
				/* If write covers the whole page,
				 * no need to copy to cache first */
				required--;
				array[i] = 0;
			}
		}
	}

	data->required = required;

	while (bs2_dev->num_free_blocks < unallocated * 2) {
		bs2_info("Need eviction: %lu free, %lu required\n",
				bs2_dev->num_free_blocks, unallocated);
		num_free = 0;
		BANKSHOT2_START_TIMING(bs2_dev, evict_t, evict);
		bankshot2_reclaim_blocks(bs2_dev, pi, data, &num_free);
		BANKSHOT2_END_TIMING(bs2_dev, evict_t, evict);

		bs2_info("Freed %d blocks, %lu free, %lu required\n",
				num_free, bs2_dev->num_free_blocks,
				unallocated);
		if (!num_free)
			bs2_info("Reclaim blocks failed\n");
	}

	bs2_dbg("Before alloc: %lu free\n", bs2_dev->num_free_blocks);
	if (unallocated) {
		BANKSHOT2_START_TIMING(bs2_dev, alloc_t, alloc);
		err = bankshot2_alloc_blocks(NULL, bs2_dev, pi, index,
						count, true);
		BANKSHOT2_END_TIMING(bs2_dev, alloc_t, alloc);

		BANKSHOT2_START_TIMING(bs2_dev, update_physical_t, update_phy);
//		mutex_lock(&bs2_dev->phy_tree_lock);
		bankshot2_update_physical_tree(bs2_dev, pi, data, offset,
					length, alloc_array, unallocated);
//		mutex_unlock(&bs2_dev->phy_tree_lock);
		BANKSHOT2_END_TIMING(bs2_dev, update_physical_t, update_phy);
	}

	kfree(alloc_array);
	if (err)
		bs2_info("[%s:%d] Alloc failed\n", __func__, __LINE__);

	/* First add the new mapping, then remove the old mapping */
	err = bankshot2_mmap_extent(bs2_dev, pi, data, access_extent);
	if (err)
		bs2_info("bankshot2_mmap_extent failed: %d\n", err);

	*void_array = array;

	mutex_unlock(pi->btree_lock);
	bs2_dbg("After alloc: %lu free\n", bs2_dev->num_free_blocks);

	if (err) {
		kfree(array);
		return err;
	}

	return required;
}

static int bankshot2_find_and_alloc_blocks(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, sector_t iblock,
		sector_t *data_block, int create)
{
	int err = -EIO;
	u64 block;
//	int num_free;
//	bankshot2_transaction_t *trans;

	mutex_lock(pi->btree_lock);
	block = bankshot2_find_data_block(bs2_dev, pi, iblock);

	if (!block) {
		if (!create) {
			err = -ENODATA;
			goto err;
		}
//retry:
		err = bankshot2_alloc_blocks(NULL, bs2_dev, pi, iblock,
						1, true);
		if (err) {
			bs2_dbg("[%s:%d] Alloc failed, "
				"trying to reclaim some blocks\n",
				__func__, __LINE__);
			goto err;
#if 0
			err = bankshot2_evict_extent(bs2_dev, pi, data, 
							&num_free);
			if (err || num_free != MMAP_UNIT / PAGE_SIZE) {
				bs2_info("Evict extent failed! return %d, "
					"%d freed\n", err, num_free);
				goto err;
			}
			goto retry;
#endif
		}
		
		block = bankshot2_find_data_block(bs2_dev, pi, iblock);
		if (!block) {
			bs2_dbg("[%s:%d] But alloc didn't fail!\n",
				  __func__, __LINE__);
			err = -ENODATA;
			goto err;
		}
		err = 1;
	} else {
		err = 0;
	}

	bs2_dbg("iblock 0x%lx allocated_block 0x%llx\n", iblock, block);

	*data_block = block;

err:
	mutex_unlock(pi->btree_lock);
	return err;
}


static inline int __bankshot2_get_block(struct bankshot2_device *bs2_dev,
			struct bankshot2_inode *pi, pgoff_t pgoff, int create,
			sector_t *block)
{
	int ret = 0;

	ret = bankshot2_find_and_alloc_blocks(bs2_dev, pi, (sector_t)pgoff,
						block, create);

	return ret;
}

int bankshot2_get_xip_mem(struct bankshot2_device *bs2_dev,
			struct bankshot2_inode *pi, pgoff_t pgoff, int create,
			void **kmem, unsigned long *pfn)
{
	int ret;
	sector_t block = 0;

	ret = __bankshot2_get_block(bs2_dev, pi, pgoff, create, &block);
	if (ret < 0)
		return ret;

	*kmem = bankshot2_get_block(bs2_dev, block);
	*pfn = bankshot2_get_pfn(bs2_dev, block);
	bs2_dbg("xip_mem: mem %p, pfn %lu\n", *kmem, *pfn);

	return ret;
}

static int bankshot2_xip_file_fault(struct vm_area_struct *vma,
					struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct bankshot2_inode *pi;
	u64 block;
	pgoff_t size;
//	void *xip_mem;
	unsigned long xip_pfn;
	int ret = 0;
	u64 ino;
//	timing_t page_fault;

//	pi = bankshot2_get_inode(bs2_dev, inode->i_ino);
//	BANKSHOT2_START_TIMING(bs2_dev, page_fault_t, page_fault);

	pi = bankshot2_check_existing_inodes(bs2_dev, inode, &ino);
	if (!pi) {
		bs2_info("Not found existing match inode\n");
		return VM_FAULT_SIGBUS;
	}

	bs2_dbg("%s: ino %llu, request pgoff %lu, virtual addr %p\n",
			__func__, ino, vmf->pgoff, vmf->virtual_address);
	rcu_read_lock();
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		bs2_info("pgoff %lu >= size %lu (SIGBUS).\n",
				vmf->pgoff, size);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

//	ret = bankshot2_get_xip_mem(bs2_dev, pi, vmf->pgoff, 1,
//				&xip_mem, &xip_pfn);
	block = bankshot2_find_data_block(bs2_dev, pi, vmf->pgoff);
	if (!block) {
		bs2_info("%s: pgoff 0x%lx get block failed: %d\n", __func__,
				vmf->pgoff, -ENODATA);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	xip_pfn = bankshot2_get_pfn(bs2_dev, block);

	ret = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address,
				xip_pfn);
	bs2_dbg("%s: insert page: vma %p, pfn %lu, request pgoff %lu, "
			"vaddr %p, mapping %p\n",
			__func__, vma, xip_pfn, vmf->pgoff,
			vmf->virtual_address, mapping);
	if (ret == -ENOMEM) {
		bs2_info("vm_insert_mixed failed: %d\n", ret);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	ret = VM_FAULT_NOPAGE;
out:
	rcu_read_unlock();
//	BANKSHOT2_END_TIMING(bs2_dev, page_fault_t, page_fault);

	return ret;
}

int bankshot2_xip_file_read(struct bankshot2_device *bs2_dev,
		struct bankshot2_cache_data *data, struct bankshot2_inode *pi,
		ssize_t *actual_length)
{
	size_t bytes, user_bytes;
	ssize_t read = 0;
	u64 pos, block;
	u64 user_offset = data->offset;
	size_t count;
	size_t req_len = data->size;
	u64 b_offset;
	char *buf = data->buf;
	unsigned long index;
	unsigned long offset, user_offset_in_page;
	size_t copy_user;
	void *xmem;
	char *void_array;
	int ret;
	unsigned long required;
	struct extent_entry *access_extent = NULL;
	timing_t bs_read_r, copy_user_time;

	bankshot2_decide_mmap_extent(bs2_dev, pi, data, &pos, &count, &b_offset);

	/* Pre-allocate the blocks we need */
	ret = bankshot2_prealloc_blocks(bs2_dev, pi, data, &void_array,
					pos, count, user_offset, req_len,
					&access_extent, 0);
	if (ret < 0)
		return ret;

	required = ret;

	/* Copy to cache first if it's not in cache */
	BANKSHOT2_START_TIMING(bs2_dev, bs_read_r_t, bs_read_r);
	ret = bankshot2_copy_to_cache(bs2_dev, pi, data, pos, count, b_offset,
					void_array, required);
	BANKSHOT2_END_TIMING(bs2_dev, bs_read_r_t, bs_read_r);
	bs2_dev->bs_read_blocks += required;

	if (ret) {
		kfree(void_array);
		return ret;
	}

	/* Now copy to user buffer */
	do {
		offset = pos & (bs2_dev->blocksize - 1); /* Within page */
		index = pos >> bs2_dev->s_blocksize_bits;
		bytes = bs2_dev->blocksize - offset;
//		i = index - start_index;

		if (bytes > count)
			bytes = count;

		if (req_len > 0 && ((user_offset >> bs2_dev->s_blocksize_bits)
				== index)) { // Same page
			BANKSHOT2_START_TIMING(bs2_dev, copy_to_user_t,
						copy_user_time);
			user_offset_in_page =
				user_offset & (bs2_dev->blocksize - 1);
			user_bytes = bs2_dev->blocksize - user_offset_in_page;
			block = bankshot2_find_data_block(bs2_dev, pi, index);
			if (!block) {
				bs2_info("%s: get block failed, index 0x%lx\n",
						__func__, index);
				break;
			}
			xmem = bankshot2_get_block(bs2_dev, block);
			copy_user = min(req_len, user_bytes);
			__copy_to_user(buf, xmem + user_offset_in_page,
					copy_user);
			req_len -= copy_user;
			buf += copy_user;
			user_offset += copy_user;
			BANKSHOT2_END_TIMING(bs2_dev, copy_to_user_t,
						copy_user_time);
		}

//		bankshot2_flush_edge_cachelines(pos, bytes, xmem + offset);

		read += bytes;
		count -= bytes;
		pos += bytes;
		b_offset += bytes;
	} while (count);

	if (pos > pi->i_size) {
		bankshot2_update_isize(pi, pos);
	}	

	*actual_length = read;
	kfree(void_array);
//	bankshot2_clear_extent_access(bs2_dev, pi, start_index);
	if (access_extent)
		atomic_set(&access_extent->access, 0);

	return 0;
}

ssize_t bankshot2_xip_file_write(struct bankshot2_device *bs2_dev,
		struct bankshot2_cache_data *data, struct bankshot2_inode *pi,
		ssize_t *actual_length)
{
	long status = 0;
	size_t bytes, user_bytes;
	ssize_t written = 0;
	u64 pos;
	u64 block;
	u64 user_offset = data->offset;
	size_t count;
	size_t req_len = data->size;
	u64 b_offset;
	char *buf = data->buf;
	unsigned long index;
	unsigned long offset, user_offset_in_page;
	size_t copied, copy_user;
	void *xmem;
	char *void_array;
	int ret;
	unsigned long required;
	struct extent_entry *access_extent = NULL;
	timing_t bs_read_w, copy_user_time;

	bankshot2_decide_mmap_extent(bs2_dev, pi, data, &pos, &count,
					&b_offset);

	/* Pre-allocate the blocks we need */
	ret = bankshot2_prealloc_blocks(bs2_dev, pi, data, &void_array,
					pos, count, user_offset, req_len,
					&access_extent, 1);
	if (ret < 0)
		return ret;

	required = ret;

//	start_index = pos >> bs2_dev->s_blocksize_bits;

	/* Copy to cache first if it's not in cache */
	BANKSHOT2_START_TIMING(bs2_dev, bs_read_w_t, bs_read_w);
	ret = bankshot2_copy_to_cache(bs2_dev, pi, data, pos, count, b_offset,
					void_array, required);
	BANKSHOT2_END_TIMING(bs2_dev, bs_read_w_t, bs_read_w);
	bs2_dev->bs_write_blocks += required;

	if (ret) {
		kfree(void_array);
		return ret;
	}

	do {
		offset = pos & (bs2_dev->blocksize - 1); /* Within page */
		index = pos >> bs2_dev->s_blocksize_bits;
		bytes = bs2_dev->blocksize - offset;

		if (bytes > count)
			bytes = count;

#if 0
		/* If it's not fully write to whole page,
		 * copy data to cache first */
		if (bytes != bs2_dev->blocksize && void_array[i] == 0x1) {
			ret = bankshot2_copy_to_cache(bs2_dev, pi, pos,
						PAGE_SIZE, b_offset, &c, 1);
			if (ret) {
				kfree(void_array);
				return ret;
			}
		}
#endif


		if (req_len > 0 && ((user_offset >> bs2_dev->s_blocksize_bits)
					== index)) { // Same page
			BANKSHOT2_START_TIMING(bs2_dev, copy_from_user_t,
						copy_user_time);
			block = bankshot2_find_data_block(bs2_dev, pi, index);
			if (!block) {
				bs2_info("%s: get block failed, index 0x%lx\n",
						__func__, index);
				break;
			}
			xmem = bankshot2_get_block(bs2_dev, block);

			user_offset_in_page =
				user_offset & (bs2_dev->blocksize - 1);
			user_bytes = bs2_dev->blocksize - user_offset_in_page;
			copy_user = min(req_len, user_bytes);

			bs2_dbg("copy %p to index %lu, offset 0x%llx\n",
					xmem, index, pos);
			copied = copy_user -
				__copy_from_user_inatomic_nocache(
					xmem + user_offset_in_page,
					buf, copy_user);
			if (unlikely(copied != copy_user)) {
				bs2_info("%s: copied %lu, bytes %lu\n",
						__func__, copied, copy_user);
				status = -EFAULT;
				break;
			}
			req_len -= copied;
			buf += copied;
			user_offset += copied;
			bankshot2_flush_edge_cachelines(pos, copied,
						xmem + user_offset_in_page);
			BANKSHOT2_END_TIMING(bs2_dev, copy_from_user_t,
						copy_user_time);
		}

//		bs2_dbg("After copy from user\n");

//		bankshot2_copy_from_cache(bs2_dev, addr, bytes, xmem);
//		bankshot2_flush_edge_cachelines(pos, copied, xmem + offset);
		status = bytes;
		written += status;
		count -= status;
		pos += status;
		b_offset += status;
	} while (count);

	if (pos > pi->i_size) {
		bankshot2_update_isize(pi, pos);
	}	

	*actual_length = written;
	kfree(void_array);
//	bankshot2_clear_extent_access(bs2_dev, pi, start_index);
	if (access_extent)
		atomic_set(&access_extent->access, 0);

	return status < 0 ? status : 0;
}

#if 0
static int page_dirty(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, unsigned long pgoff)
{
	// FIXME: check PTE's dirty bit
	return 1;
}
#endif

int bankshot2_write_back_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		struct extent_entry *extent)
{
	u64 pos;
	size_t count;
	u64 b_offset;
//	unsigned long index;
	char *void_array;
	int ret;
//	int i;
	unsigned long required = 0;

	pos = extent->offset;
	b_offset = extent->b_offset;
	count = extent->length >> bs2_dev->s_blocksize_bits;

	bs2_dbg("%s: inode %llu, offset %llu, length %lu\n",
			__func__, pi->i_ino, pos, count);

	/* Format the dirty array */
	void_array = kzalloc(count, GFP_KERNEL);
	BUG_ON(!void_array);

#if 0
	index = pos >> bs2_dev->s_blocksize_bits;
	for (i = 0; i < count; i++) {
		if (page_dirty(bs2_dev, pi, index)) {
			void_array[i] = 0x1;
			required++;
		}
		index++;
	}
#endif

	/* Get dirty array before munmap */
	required = bankshot2_get_dirty_page_array(bs2_dev, pi, extent,
							void_array, count);

	bankshot2_munmap_extent(bs2_dev, pi, extent);

	ret = bankshot2_copy_from_cache(bs2_dev, pi, data, pos, extent->length,
					b_offset, void_array, required);

	kfree(void_array);
	return ret;
}

static const struct vm_operations_struct bankshot2_xip_vm_ops = {
	.fault	= bankshot2_xip_file_fault,
};

int bankshot2_xip_file_mmap(struct file *file, struct vm_area_struct *vma)
{
//	unsigned long block_sz;
	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP;
	//FIXME: HUGE MMAP does not support yet
	vma->vm_ops = &bankshot2_xip_vm_ops;
	return 0;
}

void bankshot2_init_mmap(struct bankshot2_device *bs2_dev)
{
	bs2_dev->mmap = bankshot2_xip_file_mmap;
}
