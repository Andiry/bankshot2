/*
 * Char device code.
 * Embed a char device in bankshot2. Handle ioctl requests from user sapce.
 */

#include "bankshot2.h"
#include "bankshot2_cache.h"

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

	mmap_request = (struct bankshot2_mmap_request *)arg;

	mmap_request->mmap_addr = bankshot2_mmap(bs2_dev,
		 (unsigned long)mmap_request->addr, mmap_request->length,
				mmap_request->prot, mmap_request->flags,
				mmap_request->fd,   mmap_request->offset);
}

int bankshot2_ioctl_add_extent(struct bankshot2_device *bs2_dev, void *arg)
{
	struct extent_entry *data;
	struct extent_entry_user *data1;
	struct bankshot2_inode *pi;
	int ret;

	data = kmalloc(sizeof(struct extent_entry), GFP_KERNEL);
	data1 = (struct extent_entry_user *)arg;
	pi = bankshot2_get_inode(bs2_dev, BANKSHOT2_ROOT_INO);

	data->offset = data1->offset;
	data->length = data1->length;
	data->dirty = data1->dirty;
	data->mmap_addr = data1->mmap_addr;

	ret = bankshot2_add_extent(bs2_dev, pi, data);

	if (data->dirty)
		bankshot2_print_tree(bs2_dev, pi);
	return ret;
}

int bankshot2_ioctl_remove_extent(struct bankshot2_device *bs2_dev, void *arg)
{
	off_t offset;
	struct bankshot2_inode *pi;

	offset = *(off_t *)arg;
	pi = bankshot2_get_inode(bs2_dev, BANKSHOT2_ROOT_INO);

	bankshot2_remove_extent(bs2_dev, pi, offset);

	bankshot2_print_tree(bs2_dev, pi);
	return 0;
}

long bankshot2_char_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	struct bankshot2_device *bs2_dev = filp->private_data;
	int ret = 0;

	bs2_info("ioctl sends to device, cmd 0x%x\n", cmd);
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
	default:
		break;
	}

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

