/*
 * Copied from pmfs/xip.c
 */

#include "bankshot2.h"
#include "bankshot2_cache.h"

static int bankshot2_find_and_alloc_blocks(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, sector_t iblock,
		sector_t *data_block, int create)
{
	int err = -EIO;
	u64 block;
	int num_free;
//	bankshot2_transaction_t *trans;

	spin_lock(&pi->btree_lock);
	block = bankshot2_find_data_block(bs2_dev, pi, iblock);

	if (!block) {
		if (!create) {
			err = -ENODATA;
			goto err;
		}
retry:
		err = bankshot2_alloc_blocks(NULL, bs2_dev, pi, iblock,
						1, true);
		if (err) {
			bs2_dbg("[%s:%d] Alloc failed, "
				"trying to reclaim some blocks\n",
				__func__, __LINE__);

//			err = bankshot2_reclaim_num_blocks(bs2_dev, pi,
//				num_free);
			err = bankshot2_evict_extent(bs2_dev, pi, &num_free);
			if (err || num_free != MMAP_UNIT / PAGE_SIZE) {
				bs2_info("Evict extent failed! return %d, "
					"%d freed\n", err, num_free);
				goto err;
			}
			goto retry;
		}
		
# if 0
		trans = bankshot2_current_transaction();
		if (trans) {
			err = bankshot2_alloc_blocks(trans, inode, iblock, 1, true);
			if (err) {
				bankshot2_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		} else {
			/* 1 lentry for inode, 1 lentry for inode's b-tree */
			trans = bankshot2_new_transaction(sb, MAX_INODE_LENTRIES);
			if (IS_ERR(trans)) {
				err = PTR_ERR(trans);
				goto err;
			}

			rcu_read_unlock();
			mutex_lock(&inode->i_mutex);

			bankshot2_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY,
				LE_DATA);
			err = bankshot2_alloc_blocks(trans, inode, iblock, 1, true);

			bankshot2_commit_transaction(sb, trans);

			mutex_unlock(&inode->i_mutex);
			rcu_read_lock();
			if (err) {
				bankshot2_dbg_verbose("[%s:%d] Alloc failed!\n",
					__func__, __LINE__);
				goto err;
			}
		}
#endif
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
	spin_unlock(&pi->btree_lock);
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

#if 0
static inline unsigned long vma_start_pgoff(struct vm_area_struct *v)
{
	return v->vm_pgoff;
}

static inline unsigned long vma_last_pgoff(struct vm_area_struct *v)
{
	return v->vm_pgoff + ((v->vm_end - v->vm_start) >> PAGE_SHIFT) - 1;
}

static void bankshot2_insert_vma(struct address_space *mapping,
				struct vm_area_struct *vma)
{
	struct rb_root *root = &mapping->i_mmap; 
	struct rb_node **link = &root->rb_node, *rb_parent = NULL;
	unsigned long last = vma_last_pgoff(vma);
	struct vm_area_struct *parent;

	mutex_lock(&mapping->i_mmap_mutex);

	if (unlikely(vma->vm_flags & VM_NONLINEAR)) {
		vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
	} else {
//		vma_interval_tree_insert(vma, &mapping->i_mmap);
		bs2_info("insert vma %p: start %lx, pgoff %lx, end %lx, last %lx, mm %p\n",
				vma, vma->vm_start, vma_start_pgoff(vma),
				vma->vm_end, vma_last_pgoff(vma),
				vma->vm_mm);
#if 0
		while (*link) {
			rb_parent = *link;
			parent = rb_entry(rb_parent, vm_area_struct,
						shared.linear.rb);
			if (parent->vm_mm != vma->vm_mm) {
				if (parent->vm_mm < vma->vm_mm)
					link = &parent->shared.linear.rb.rb_left;
				else
					link = &parent->shared.linear.rb.rb_right;
				continue;
			}
			if (parent->shared.linear.rb_subtree_last < last)
				parent->shared.linear.rb_subtree_last = last;
			if (start < vma_start_pgoff)
				link = &parent->shared.linear.rb.rb_left;
			else
				link = &parent->shared.linear.rb.rb_right;
		}
#endif
	}

	mutex_unlock(&mapping->i_mmap_mutex);
}
#endif

static int bankshot2_xip_file_fault(struct vm_area_struct *vma,
					struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct bankshot2_inode *pi;
//	struct page *page;
	pgoff_t size;
	void *xip_mem;
	unsigned long xip_pfn;
	int ret = 0;
	u64 ino;

//	pi = bankshot2_get_inode(bs2_dev, inode->i_ino);
	ret = bankshot2_check_existing_inodes(bs2_dev, inode, &ino);
	if (ret) {
		bs2_info("Not found existing match inode\n");
		return ret;
	}
	pi = bankshot2_get_inode(bs2_dev, ino);

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

	ret = bankshot2_get_xip_mem(bs2_dev, pi, vmf->pgoff, 1,
				&xip_mem, &xip_pfn);
	if (unlikely(ret < 0)) {
		bs2_info("get_xip_mem failed: %d\n", ret);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}
//	page = pfn_to_page(xip_pfn);
//	page->mapping = mapping;
//	atomic_inc(&page->_mapcount);

	ret = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address,
				xip_pfn);
	bs2_dbg("%s: insert page: vma %p, pfn %lu, request pgoff %lu, "
			"vaddr %p, mapping %p\n",
			__func__, vma, xip_pfn, vmf->pgoff,
			vmf->virtual_address, mapping);
	if (ret == -ENOMEM) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

//	bankshot2_insert_vma(mapping, vma);

	ret = VM_FAULT_NOPAGE;
out:
	rcu_read_unlock();
	return ret;
}

static inline void bankshot2_flush_edge_cachelines(loff_t pos, ssize_t len,
	void *start_addr)
{
	if (unlikely(pos & 0x7))
		bankshot2_flush_buffer(start_addr, 1, false);
	if (unlikely(((pos + len) & 0x7) && ((pos & (CACHELINE_SIZE - 1)) !=
			((pos + len) & (CACHELINE_SIZE - 1)))))
		bankshot2_flush_buffer(start_addr + len, 1, false);
}

int bankshot2_xip_file_read(struct bankshot2_device *bs2_dev,
		void *data1, struct bankshot2_inode *pi,
		ssize_t *actual_length)
{
	struct bankshot2_cache_data *data =
		(struct bankshot2_cache_data *)data1;
	long status = 0;
	size_t bytes;
	ssize_t read = 0;
	u64 pos;
	u64 user_offset = data->offset;
	size_t count;
	size_t req_len = data->size;
	u64 b_offset;
	char *buf = data->buf;
	unsigned long index;
	unsigned long offset;
	size_t copied, copy_user;
	void *xmem;
	unsigned long xpfn;
	int ret;

	/* If mmap length > 0, we need to copy start from mmap offset;
	   otherwise we will just copy start from offset. */
	/* Must ensure that the required extent is covered by fiemap extent */
	if (data->mmap_length) {
		pos = data->mmap_offset;
		count = data->mmap_offset + data->mmap_length
					> data->offset + data->size ?
				data->mmap_length :
				data->offset + data->size - data->mmap_offset;
		b_offset = data->extent_start + data->mmap_offset
				- data->extent_start_file_offset;
	} else {
		pos = data->offset;
		count = data->size;
		b_offset = data->extent_start + data->offset
				- data->extent_start_file_offset;
	}

	data->actual_offset = pos;
	bs2_dbg("%s, inode %llu, offset %llu, length %lu\n",
			__func__, pi->i_ino, pos, count);


	do {
		offset = pos & (bs2_dev->blocksize - 1); /* Within page */
		index = pos >> bs2_dev->s_blocksize_bits;
		bytes = bs2_dev->blocksize - offset;
		if (bytes > count)
			bytes = count;

		status = bankshot2_get_xip_mem(bs2_dev, pi,
				index, 1, &xmem, &xpfn);
		if (status < 0) {
			bs2_info("get_xip_mem returned %ld\n", status);
			break;
		}

		/* status 1 means it's newly allocated. Copy to cache. */
		if (status == 1) {
			ret = bankshot2_copy_to_cache(bs2_dev, b_offset,
							bytes, xmem);
			if (ret)
				return ret;
		}

		copied = bytes;
		if (req_len > 0 && ((user_offset >> bs2_dev->s_blocksize_bits)
				== index)) { // Same page
			copy_user = min(req_len, bytes);
			__copy_to_user(buf, xmem + offset, copy_user);
			req_len -= copy_user;
			buf += copy_user;
			user_offset += copy_user;
		}

		bankshot2_flush_edge_cachelines(pos, copied, xmem + offset);

		if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				read += status;
				count -= status;
				pos += status;
				b_offset += status;
//				buf += status;
			}
		}
		if (status < 0)
			break;
	} while (count);

	if (pos > pi->i_size) {
		bankshot2_update_isize(pi, pos);
	}	

	*actual_length = read;
	return status < 0 ? status : 0;
}

ssize_t bankshot2_xip_file_write(struct bankshot2_device *bs2_dev,
		void *data1, struct bankshot2_inode *pi,
		ssize_t *actual_length)
{
	struct bankshot2_cache_data *data =
		(struct bankshot2_cache_data *)data1;
	long status = 0;
	size_t bytes;
	ssize_t written = 0;
	u64 pos;
	u64 user_offset = data->offset;
	size_t count;
	size_t req_len = data->size;
	u64 b_offset;
	char *buf = data->buf;
	unsigned long index;
	unsigned long offset;
	size_t copied, copy_user;
	void *xmem;
	unsigned long xpfn;
	int ret;
//	char *buf1;

	/* If mmap length > 0, we need to copy start from mmap offset;
	   otherwise we will just copy start from offset. */
	/* Must ensure that the required extent is covered by fiemap extent */
	if (data->mmap_length) {
		pos = data->mmap_offset;
		count = data->mmap_offset + data->mmap_length
					> data->offset + data->size ?
				data->mmap_length :
				data->offset + data->size - data->mmap_offset;
		b_offset = data->extent_start + data->mmap_offset
				- data->extent_start_file_offset;
	} else {
		pos = data->offset;
		count = data->size;
		b_offset = data->extent_start + data->offset
				- data->extent_start_file_offset;
	}

	data->actual_offset = pos;
	bs2_dbg("%s, inode %llu, offset %llu, length %lu\n",
			__func__, pi->i_ino, pos, count);

	do {
		offset = pos & (bs2_dev->blocksize - 1); /* Within page */
		index = pos >> bs2_dev->s_blocksize_bits;
		bytes = bs2_dev->blocksize - offset;
		if (bytes > count)
			bytes = count;

		status = bankshot2_get_xip_mem(bs2_dev, pi,
				index, 1, &xmem, &xpfn);
		if (status < 0) {
			bs2_info("get_xip_mem returned %ld\n", status);
			break;
		}

		/* Since we are mmaped to user space,
		    need to copy data to cache first */
		/* If it's already in cache then don't copy */
		if (status == 1) {
			ret = bankshot2_copy_to_cache(bs2_dev, b_offset,
							bytes, xmem);
			if (ret)
				return ret;
		}

//		buf1 = (char *)xmem;
//		bs2_dbg("Before copy from user\n");

		if (req_len > 0 && ((user_offset >> bs2_dev->s_blocksize_bits)
					== index)) { // Same page
			copy_user = min(req_len, bytes);
			copied = bytes -
				__copy_from_user_inatomic_nocache(xmem + offset,
								buf, copy_user);
			req_len -= copied;
			buf += copied;
			user_offset += copied;
		} else {
			copied = bytes;
		}

//		bs2_dbg("After copy from user\n");

//		bankshot2_copy_from_cache(bs2_dev, addr, bytes, xmem);
		bankshot2_flush_edge_cachelines(pos, copied, xmem + offset);

		if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
//				buf += status;
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;
	} while (count);

	if (pos > pi->i_size) {
		bankshot2_update_isize(pi, pos);
	}	

	*actual_length = written;
	return status < 0 ? status : 0;
}

static int page_dirty(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, unsigned long pgoff,
		void *xmem)
{
	// FIXME: check PTE's dirty bit
	return 1;
}

int bankshot2_write_back_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct extent_entry *extent)
{
	long status = 0;
	size_t bytes;
	u64 pos;
	size_t count;
	u64 b_offset;
	unsigned long index;
	size_t copied;
	void *xmem;
	unsigned long xpfn;
	int ret;

	pos = extent->offset;
	b_offset = extent->b_offset;
	count = extent->length;

	bs2_dbg("%s, inode %llu, offset %llu, length %lu\n",
			__func__, pi->i_ino, pos, count);

	do {
		index = pos >> bs2_dev->s_blocksize_bits;
		bytes = PAGE_SIZE;
		if (bytes > count)
			bytes = count;

		status = bankshot2_get_xip_mem(bs2_dev, pi,
				index, 0, &xmem, &xpfn);
		if (status < 0) {
			bs2_info("get_xip_mem returned %ld\n", status);
			break;
		}

		if (page_dirty(bs2_dev, pi, index, xmem)) {
			ret = bankshot2_copy_from_cache(bs2_dev, b_offset,
							bytes, xmem);
			if (ret)
				return ret;
		}

//		buf1 = (char *)xmem;
//		bs2_dbg("Before copy from user\n");

		copied = bytes;

//		bs2_dbg("After copy from user\n");

//		bankshot2_flush_edge_cachelines(pos, copied, xmem + offset);

		if (likely(copied > 0)) {
			count -= copied;
			pos += copied;
			b_offset += copied;
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;
	} while (count);

	return 0;
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
