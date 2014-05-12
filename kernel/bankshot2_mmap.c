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

static void unmap_page(struct address_space *mapping, unsigned long pgoff)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long address;
	struct rb_node *temp, *remove;

	bs2_info("%s:\n", __func__);
	temp = rb_first(&mapping->i_mmap);
	while (temp) {
//	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff, pgoff) {
		vma = rb_entry(temp, struct vm_area_struct, shared.linear.rb);
		mm = vma->vm_mm;
		address = vma->vm_start +
				((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
		bs2_info("vma %p: start %lx, pgoff %lx, end %lx, last %lx, "
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

void bankshot2_munmap_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct extent_entry *extent)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	struct vma_list *vma_list;
	unsigned long address;
	unsigned long pgoff = 0;

	bs2_dbg("%s: unmap offset 0x%lx, %lu pages\n", __func__,
			extent->offset, extent->length / PAGE_SIZE);

	pgoff = extent->offset >> PAGE_SHIFT;

	list_for_each_entry(vma_list, &extent->vma_list, list) {
		vma = vma_list->vma;
		mm = vma->vm_mm;
		address = vma->vm_start +
				((pgoff - vma->vm_pgoff) << PAGE_SHIFT);

		bs2_info("unmap vma %p: start 0x%lx, pgoff 0x%lx, end 0x%lx, "
				"last 0x%lx, mm %p, address 0x%lx\n",
				vma, vma->vm_start, vma_start_pgoff(vma),
				vma->vm_end, vma_last_pgoff(vma),
				vma->vm_mm, address);

		if (address < vma->vm_start || address >= vma->vm_end) {
			bs2_info("address not in vma area! "
				"vma start 0x%lx, end 0x%lx, address 0x%lx\n",
				vma->vm_start, vma->vm_end, address);
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
		bs2_info("Failed to get inode to remove mappings\n");
		return -EINVAL;
	}

	ret = bankshot2_remove_mapping_from_tree(bs2_dev, pi);

	return ret;
}
