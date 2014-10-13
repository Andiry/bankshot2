/*
 * Char device code.
 * Embed a char device in bankshot2. Handle ioctl requests from user sapce.
 */

#include "bankshot2.h"

static struct class *bankshot2_chardev_class;

int bankshot2_char_open(struct inode *inode, struct file *filp)
{
	struct bankshot2_device *bs2_dev = container_of(inode->i_cdev,
			struct bankshot2_device, chardev);

	filp->private_data = bs2_dev;

	return 0;
}

int bankshot2_char_release(struct inode *inode, struct file *filp)
{
//	bs2_info("release bankshot2 char class\n");
	return 0;
}

static void bankshot2_ioctl_show_inode_info(struct bankshot2_device *bs2_dev,
						u64 ino)
{
	struct bankshot2_inode *pi;

	bs2_info("Ioctl show inode info: inode %llu\n", ino);

	pi = bankshot2_get_inode(bs2_dev, ino);
	if (!pi) {
		bs2_info("inode %llu does not exist\n", ino);
		return;
	}

	bs2_info("Inode %llu: root @ %llu, size %llu, blocks %llu\n",
			ino, pi->root, pi->i_size, pi->i_blocks);

	return;
}

static void bankshot2_ioctl_mmap_request(struct bankshot2_device *bs2_dev,
						void *arg)
{
	struct bankshot2_mmap_request *mmap_request;
	struct vm_area_struct *vma;

	mmap_request = (struct bankshot2_mmap_request *)arg;

	mmap_request->mmap_addr = bankshot2_mmap(bs2_dev,
		 (unsigned long)mmap_request->addr, mmap_request->length,
				mmap_request->prot, mmap_request->flags,
				mmap_request->fd,   mmap_request->offset,
				&vma);
}

static void bankshot2_ioctl_munmap_request(struct bankshot2_device *bs2_dev,
						void *arg)
{
	struct bankshot2_mmap_request *mmap_request;
	struct bankshot2_inode *pi;

	pi = bankshot2_get_inode(bs2_dev, 3);

	mmap_request = (struct bankshot2_mmap_request *)arg;

//	vm_munmap((unsigned long)mmap_request->addr, mmap_request->length);
//	bankshot2_munmap(bs2_dev, pi, mmap_request->offset,
//				mmap_request->length / PAGE_SIZE);
}

static int bankshot2_ioctl_add_extent(struct bankshot2_device *bs2_dev,
					void *arg)
{
	struct extent_entry_user *data1;
	struct extent_entry *access_extent;
	struct bankshot2_inode *pi;
	int ret;

	data1 = (struct extent_entry_user *)arg;
	pi = bankshot2_get_inode(bs2_dev, BANKSHOT2_ROOT_INO);

	ret = bankshot2_add_extent(bs2_dev, pi, data1->offset,
			data1->length, data1->offset, NULL, NULL,
			&access_extent);

	if (data1->dirty)
		bankshot2_print_tree(bs2_dev, pi);
	return ret;
}

static int bankshot2_ioctl_remove_extent(struct bankshot2_device *bs2_dev,
					void *arg)
{
	off_t offset;
	struct bankshot2_inode *pi;

	offset = *(off_t *)arg;
	pi = bankshot2_get_inode(bs2_dev, BANKSHOT2_ROOT_INO);

	bankshot2_remove_extent(bs2_dev, pi, offset);

	bankshot2_print_tree(bs2_dev, pi);
	return 0;
}

static int bankshot2_ioctl_free_blocks(struct bankshot2_device *bs2_dev,
					void *arg)
{
	int num_free;
//	struct bankshot2_inode *pi;

	num_free = *(int *)arg;
//	pi = bankshot2_get_inode(bs2_dev, 3);

//	bankshot2_reclaim_num_blocks(bs2_dev, pi, num_free);
	bs2_info("%d\n", num_free);
//	bankshot2_print_tree(bs2_dev, pi);
	return 0;
}

static void bankshot2_ioctl_clear_cache(struct bankshot2_device *bs2_dev)
{
	int i;
	struct bankshot2_inode *pi;
	struct hash_inode *entry;

	bs2_info("Clear cache.\n");
	for (i = BANKSHOT2_FREE_INODE_HINT_START;
			i < bs2_dev->s_inodes_count; i++) {
		pi = bankshot2_get_inode(bs2_dev, i);
		if (pi && pi->backup_ino) {
			bankshot2_evict_inode(bs2_dev, pi);
			pi->backup_ino = 0;
			pi->i_links_count = 0;
			pi->i_mode = 0;
			pi->i_dtime = 0;
		}
	}

	bs2_dev->s_free_inode_hint = BANKSHOT2_FREE_INODE_HINT_START;

	for (i = 0; i < HASH_ARRAY_SIZE; i++) {
		entry = &bs2_dev->inode_hash_array[i];
		if (entry->size > 1)
			kfree(entry->ino_array);
		entry->ino = 0;
		entry->count = 0;
		entry->size = 1;
	}

	bankshot2_print_time_stats(bs2_dev);
	bankshot2_print_io_stats(bs2_dev);
	bankshot2_clear_stats(bs2_dev);
}

static void bankshot2_ioctl_clear_timing(struct bankshot2_device *bs2_dev)
{
	bankshot2_clear_stats(bs2_dev);
}

static void bankshot2_ioctl_print_cache_info(struct bankshot2_device *bs2_dev,
						void *arg)
{
	int i;
	int print_dirty = *(int *)arg;
	struct bankshot2_inode *pi;

	bs2_info("Print cache info:\n");
	for (i = BANKSHOT2_FREE_INODE_HINT_START;
			i < bs2_dev->s_inodes_count; i++) {
		pi = bankshot2_get_inode(bs2_dev, i);
		if (pi && pi->backup_ino) {
			bs2_info("%d: Pi %llu: size %llu, %llu blocks, "
				"%u extents\n", i, pi->backup_ino, pi->i_size,
				pi->i_blocks, pi->num_extents);
			if (print_dirty)
				bankshot2_print_tree(bs2_dev, pi);
			if (pi->num_access_extents)
				bankshot2_print_access_tree(bs2_dev, pi);
		}
	}

	bankshot2_print_physical_tree(bs2_dev);
	bankshot2_print_time_stats(bs2_dev);
	bankshot2_print_io_stats(bs2_dev);
}

static int bankshot2_ioctl_get_dirty_info(struct bankshot2_device *bs2_dev,
		void *arg)
{
	struct mm_struct *mm = current->mm;
	unsigned long address = (unsigned long)arg;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	bs2_info("%s: check address 0x%lx\n", __func__, address);
	spin_lock(&mm->page_table_lock);

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd)) {
		bs2_info("%s: pgd not found\n", __func__);
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud)) {
		bs2_info("%s: pud not found\n", __func__);
		goto out;
	}

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd)) {
		bs2_info("%s: pmd not found\n", __func__);
		goto out;
	}

	pte = pte_offset_map(pmd, address);
	if (!pte_present(*pte)) {
		bs2_info("%s: pte not found\n", __func__);
		goto out;
	}

	if (pte_dirty(*pte)) {
		bs2_info("%s: address 0x%lx dirty\n", __func__, address);
	}

out:
	spin_unlock(&mm->page_table_lock);
	return 0;
}

static int bankshot2_ioctl_fsync_to_bs(struct bankshot2_device *bs2_dev,
		void *arg)
{
	struct bankshot2_cache_data _data, *data;
	struct bankshot2_inode *pi;
	int ret;
	u64 ino;
	struct inode *inode;

	data = &_data;

	ret = bankshot2_get_backing_inode(bs2_dev, arg, &inode);
	if (ret) {
		bs2_info("Get backing inode returned %d\n", ret);
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	ino = data->cache_ino;
	if (ino == 0) {
		bs2_info("cache ino invalid\n");
		return -EINVAL;
	}

	pi = bankshot2_get_inode(bs2_dev, ino);

	if (!pi || le64_to_cpu(pi->backup_ino) != inode->i_ino) {
		bs2_info("ERROR: Inode does not match.\n");
		return -EINVAL;
	}

	data->file_length = i_size_read(inode);

	ret = bankshot2_fsync_to_bs(bs2_dev, pi, data, 0, data->file_length,
					data->datasync);

	return ret;
}

static int bankshot2_ioctl_fsync_to_cache(struct bankshot2_device *bs2_dev,
		void *arg)
{
	struct bankshot2_cache_data _data, *data;
	int ret;

	data = &_data;

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	ret = bankshot2_fsync_to_cache(bs2_dev, data, data->offset,
			data->offset + data->size, data->datasync);

	return ret;
}

long bankshot2_char_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
//	struct timespec start, end;
	struct bankshot2_device *bs2_dev = filp->private_data;
	int ret = 0;

	bs2_dbg("ioctl sends to device, cmd 0x%x\n", cmd);
//	getrawmonotonic(&start);
	switch (cmd) {
	case BANKSHOT2_IOCTL_CACHE_DATA:
		ret = bankshot2_ioctl_cache_data(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_SHOW_INODE_INFO:
		bankshot2_ioctl_show_inode_info(bs2_dev, *(u64 *)arg);
		break;
	case BANKSHOT2_IOCTL_MMAP_REQUEST:
		bankshot2_ioctl_mmap_request(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_GET_INODE:
		ret = bankshot2_ioctl_get_cache_inode(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_ADD_EXTENT: /* Test purpose only */
		ret = bankshot2_ioctl_add_extent(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_REMOVE_EXTENT: /* Test purpose only */
		ret = bankshot2_ioctl_remove_extent(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_FREE_BLOCKS: /* Test purpose only */
		ret = bankshot2_ioctl_free_blocks(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_MUNMAP_REQUEST:
		bankshot2_ioctl_munmap_request(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_REMOVE_MAPPING:
		ret = bankshot2_ioctl_remove_mappings(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_CLEAR_CACHE:
		bankshot2_ioctl_clear_cache(bs2_dev);
		break;
	case BANKSHOT2_IOCTL_CLEAR_TIMING:
		bankshot2_ioctl_clear_timing(bs2_dev);
		break;
	case BANKSHOT2_IOCTL_GET_CACHE_INFO:
		bankshot2_ioctl_print_cache_info(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_GET_DIRTY_INFO:
		bankshot2_ioctl_get_dirty_info(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_FSYNC_TO_BS:
		ret = bankshot2_ioctl_fsync_to_bs(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_FSYNC_TO_CACHE:
		ret = bankshot2_ioctl_fsync_to_cache(bs2_dev, (void *)arg);
		break;
	case BANKSHOT2_IOCTL_EVICT_INODE:
		ret = bankshot2_ioctl_evict_cache_inode(bs2_dev, (void *)arg);
		break;
	default:
		break;
	}

//	getrawmonotonic(&end);
//	bs2_info("Ioctl time %lu\n", end.tv_nsec - start.tv_nsec);
	return ret;
}

const struct file_operations bankshot2_char_fops = {
	.open = bankshot2_char_open,
	.release = bankshot2_char_release,
	.unlocked_ioctl = bankshot2_char_ioctl,
};

int bankshot2_init_char(struct bankshot2_device *bs2_dev)
{
	bankshot2_chardev_class = class_create(THIS_MODULE, "bankshot2Ctrl");
	bs2_info("create char class\n");

	if (alloc_chrdev_region(&bs2_dev->chardevnum, 0, 1, "bankshot2Ctrl"))
		goto err_alloc_chrdev;

	cdev_init(&bs2_dev->chardev, &bankshot2_char_fops);
	bs2_dev->chardev.owner = THIS_MODULE;

	cdev_add(&bs2_dev->chardev, bs2_dev->chardevnum, 1);

	device_create(bankshot2_chardev_class, NULL, bs2_dev->chardevnum, NULL,
			"bankshot2Ctrl%d", MINOR(bs2_dev->chardevnum));

	bs2_info("Add char device %d, %d as bankshot2Ctrl%d\n",
		 MAJOR(bs2_dev->chardevnum), MINOR(bs2_dev->chardevnum), 
		 MINOR(bs2_dev->chardevnum));

	return 0;

err_alloc_chrdev:
	bs2_info("Failed to register char device\n");
	return -EINVAL;
}

void bankshot2_destroy_char(struct bankshot2_device* bs2_dev)
{
	device_destroy(bankshot2_chardev_class, bs2_dev->chardevnum);
	unregister_chrdev_region(bs2_dev->chardevnum, 1);
	cdev_del(&bs2_dev->chardev);
	class_destroy(bankshot2_chardev_class);
	bs2_info("%s returns.\n", __func__);
}

