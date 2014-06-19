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

	bs2_info("Clear cache.\n");
	for (i = BANKSHOT2_FREE_INODE_HINT_START;
			i < bs2_dev->s_inodes_count; i++) {
		pi = bankshot2_get_inode(bs2_dev, i);
		if (pi && pi->root) {
			pi->backup_ino = 0;
			pi->i_links_count = 0;
			pi->i_mode = 0;
			pi->i_dtime = 0;
			bankshot2_evict_inode(bs2_dev, pi);
		}
	}

	bs2_dev->s_free_inode_hint = BANKSHOT2_FREE_INODE_HINT_START;
}

static void bankshot2_ioctl_print_cache_info(struct bankshot2_device *bs2_dev)
{
	int i;
	struct bankshot2_inode *pi;

	bs2_info("Print cache info:\n");
	for (i = BANKSHOT2_FREE_INODE_HINT_START;
			i < bs2_dev->s_inodes_count; i++) {
		pi = bankshot2_get_inode(bs2_dev, i);
		if (pi && pi->root) {
			bs2_info("Pi %llu: size %llu, %llu blocks, "
				"%u extents\n", pi->i_ino, pi->i_size,
				pi->i_blocks, pi->num_extents);
		}
	}
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
	case BANKSHOT2_IOCTL_GET_CACHE_INFO:
		bankshot2_ioctl_print_cache_info(bs2_dev);
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
}

