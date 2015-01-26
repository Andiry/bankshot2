/*
 * Bankshot2 Mmap manager.
 * Basically copied from mm/mmap.c and other mm source files.
 */

#include "bankshot2.h"

static inline unsigned long vma_start_pgoff(struct vm_area_struct *v)
{
	return v->vm_pgoff;
}

static inline unsigned long vma_last_pgoff(struct vm_area_struct *v)
{
	return v->vm_pgoff + ((v->vm_end - v->vm_start) >> PAGE_SHIFT) - 1;
}

#if 0
static void unmap_page(struct address_space *mapping, unsigned long pgoff)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long address;
	struct rb_node *temp, *remove;

	bs2_dbg("%s:\n", __func__);
	temp = rb_first(&mapping->i_mmap);
	while (temp) {
//	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		vma = rb_entry(temp, struct vm_area_struct, shared.linear.rb);
		mm = vma->vm_mm;
		address = vma->vm_start +
				((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
		bs2_dbg("vma %p: start %lx, pgoff %lx, end %lx, last %lx, "
				"mm %p, address %lx\n",
				vma, vma->vm_start, vma_start_pgoff(vma),
				vma->vm_end, vma_last_pgoff(vma),
				vma->vm_mm, address);
		if (address < vma->vm_start || address >= vma->vm_end) {
			temp = rb_next(temp);
			continue;
		}

		vm_munmap_page(mm, address, PAGE_SIZE);
		remove = temp;
		temp = rb_next(temp);
		rb_erase(remove, &mapping->i_mmap);
	}
}

void bankshot2_munmap(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, off_t offset, int num_pages)
{
	struct page *page;
	u64 block;
	off_t curr = offset;
	unsigned long iblock = 0;
	unsigned long pfn;

	bs2_info("%s: unmap offset %lu, %d pages\n", __func__,
			offset, num_pages);
	while(num_pages > 0) {
		iblock = offset >> PAGE_SHIFT;
		block = bankshot2_find_data_block(bs2_dev, pi, iblock);
		if (!block) {
			bs2_info("%s: Offset %lu not found!\n",
					__func__, curr);
			goto update;
		}

		pfn = bankshot2_get_pfn(bs2_dev, block);
		page = pfn_to_page(pfn);
		bs2_info("%s: unmap pfn %lu, mmaped %d, mapping %p\n", __func__, pfn, page_mapped(page), page->mapping);
//		lock_page(page);
//		print_mapping_tree(page->mapping, iblock);
//		bankshot2_unmap(page->mapping, page, iblock);
//		print_mapping_tree(page->mapping, iblock);
//		unlock_page(page);

//		if (ret != SWAP_SUCCESS)
//			bs2_info("%s: Offset %lu try_to_unmap failed %d!\n",
//					__func__, curr, ret);
		unmap_page(page->mapping, iblock);
update:
		offset += PAGE_SIZE;
		num_pages--;
	}
}
#endif

void bankshot2_munmap_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct extent_entry *extent)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct vma_list *vma_list;
	unsigned long address;
	unsigned long pgoff = 0;

	bs2_dbg("%s: unmap offset 0x%lx, %lu pages\n",
			__func__, extent->offset, extent->length / PAGE_SIZE);

	pgoff = extent->offset >> PAGE_SHIFT;

	list_for_each_entry(vma_list, &extent->vma_list, list) {
		vma = vma_list->vma;
		mm = vma->vm_mm;
		address = vma->vm_start +
				((pgoff - vma->vm_pgoff) << PAGE_SHIFT);

		bs2_info("unmap vma: start 0x%lx, pgoff 0x%lx, end 0x%lx, "
				"last 0x%lx, mm %p, address 0x%lx\n",
				vma->vm_start, vma_start_pgoff(vma),
				vma->vm_end, vma_last_pgoff(vma),
				vma->vm_mm, address);

		if (address < vma->vm_start || address >= vma->vm_end) {
			bs2_info("address not in vma area! "
				"vma start 0x%lx, end 0x%lx, "
				"pgoff 0x%lx, extent pgoff 0x%lx, "
				"address 0x%lx\n",
				vma->vm_start, vma->vm_end,
				vma->vm_pgoff, pgoff, address);
			continue;
		}

		vm_munmap_page(mm, address, extent->length);
	}
}

int bankshot2_ioctl_remove_mappings(struct bankshot2_device *bs2_dev,
		void *arg)
{
	struct bankshot2_inode *pi;
	u64 st_ino = *(u64 *)arg;
	int ret;

	pi = bankshot2_get_inode(bs2_dev, st_ino);
	if (!pi) {
		bs2_info("Failed to get inode %llu to remove mappings\n",
				st_ino);
		return -EINVAL;
	}

	mutex_lock(&pi->tree_lock);
	ret = bankshot2_remove_mapping_from_tree(bs2_dev, pi);
	mutex_unlock(&pi->tree_lock);

	return ret;
}

/*
 * Find out if the request mmap region is already mmaped.
 * Extent not exists: return 0
 * Extent exists but no mapping for curent mm: return 1
 * Extent exists and mmaped for current mm: return 2
 *	and update data with mmap_addr
 */
static int bankshot2_check_existing_mmap(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data)
{
	struct extent_entry *extent;
	struct vma_list *delete, *next;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long pgoff = data->mmap_offset >> PAGE_SHIFT;

	extent = bankshot2_find_extent(bs2_dev, pi, data->mmap_offset);
	if (!extent)
		return 0;

	mm = current->mm;
	list_for_each_entry_safe(delete, next, &extent->vma_list, list) {
		vma = delete->vma;
		if (vma->vm_mm == mm) {
			/* Mmaped for current process. Update mmap_addr */
			if (pgoff < vma_start_pgoff(vma) ||
					pgoff > vma_last_pgoff(vma)) {
				bs2_info("ERROR: Found mmap extent but "
					"not match: Request pgoff 0x%lx, "
					"vma start pgoff 0x%lx, "
					"last pgoff 0x%lx\n", pgoff,
					vma_start_pgoff(vma),
					vma_last_pgoff(vma));
				goto not_mmaped;
			}
			if (data->mmap_offset == extent->offset &&
					data->mmap_length <= extent->length) {
				data->mmap_addr = vma->vm_start;
				data->mmap_length = extent->length;
				return 2;
			}

			if (data->mmap_offset == extent->offset &&
					data->mmap_length > extent->length) {
				/* Extend the mapping, remove current vma */
//				data->mmap_addr = vma->vm_start;
				vm_munmap_page(mm, vma->vm_start,
					vma->vm_end - vma->vm_start);

				list_del(&delete->list);
				kfree(delete);
				return 1;
			}
		}
	}

	/* The extent exists but is not mmaped for current mm.
	 * Return the extent for mmap. */
not_mmaped:
	data->mmap_offset = extent->offset;
	data->mmap_length = data->mmap_length > extent->length ?
				data->mmap_length : extent->length;

	return 1;
}

int bankshot2_mmap_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		struct extent_entry **access_extent, int *mmaped)
{
	struct vm_area_struct *vma = NULL;
	struct file *file = fget(data->file);
	struct inode *inode;
	unsigned long b_offset;
	int ret;
	timing_t check_mmap, mmap, add_extent;

	inode = data->inode;

	if (data->mmap_length == 0) {
		bs2_dbg("mmap length is 0. return.\n");
		return 0;
	}

	if (!(file->f_mode & FMODE_READ)) {
		bs2_dbg("File not readable.\n");
		fput(file);
		data->mmap_length = 0;
		return 0;
	}
	fput(file);

	/* Maybe some other guy has already done the mapping.
	 * Check before doing mmap */

	BANKSHOT2_START_TIMING(bs2_dev, check_mmap_t, check_mmap);
	ret = bankshot2_check_existing_mmap(bs2_dev, pi, data);
	BANKSHOT2_END_TIMING(bs2_dev, check_mmap_t, check_mmap);

	if (ret == 2) {
		/* It's already mmaped */
		bs2_dev->mmap_hit++;
		*mmaped = 1;
		return 0;
	}

	BANKSHOT2_START_TIMING(bs2_dev, mmap_t, mmap);
	mutex_unlock(&pi->tree_lock);
	data->mmap_addr = bankshot2_mmap(bs2_dev, data->mmap_addr,
			data->mmap_length,
			data->write ? PROT_WRITE : PROT_READ,
			MAP_SHARED | MAP_POPULATE, data->file,
			data->mmap_offset / PAGE_SIZE, &vma);
	mutex_lock(&pi->tree_lock);
	BANKSHOT2_END_TIMING(bs2_dev, mmap_t, mmap);

	if (data->mmap_addr >= (unsigned long)(-64)) {
		// mmap failed
		bs2_info("Mmap failed, returned %d, "
				"mmap offset 0x%llx, length %lu\n",
				(int)(data->mmap_addr),
				data->mmap_offset, data->mmap_length);
//		ret = (int)(data->mmap_addr);
		data->mmap_length = 0;
		data->mmap_addr = 0;
		return 0;
	}

	b_offset = data->extent_start + data->mmap_offset
				- data->extent_start_file_offset;

	BANKSHOT2_START_TIMING(bs2_dev, add_extent_t, add_extent);
	ret = bankshot2_add_extent(bs2_dev, pi, data->mmap_offset,
			data->mmap_length, b_offset, inode->i_mapping,
			vma, access_extent);
	BANKSHOT2_END_TIMING(bs2_dev, add_extent_t, add_extent);

	if (ret) {
		bs2_info("bankshot2_add_extent failed: %d\n", ret);
		return ret;
	}

	bs2_dbg("bankshot2 mmap: file %d, offset 0x%llx, "
		"size %lu, mmap offset 0x%llx, mmaped len %lu, "
		"extent offset 0x%llx, extent length %lu\n",
		data->file, data->offset, data->size,
		data->mmap_offset, data->mmap_length,
		data->extent_start_file_offset, data->extent_length);
	bs2_dbg("Insert vma: start %lx, pgoff %lx, end %lx, mm %p\n",
		vma->vm_start, vma->vm_pgoff, vma->vm_end, vma->vm_mm);

	return 0;
}
