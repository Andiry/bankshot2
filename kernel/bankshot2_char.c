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

long bankshot2_char_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	struct bankshot2_device *bs2_dev = filp->private_data;

	switch (cmd) {
	case BANKSHOT2_IOCTL_CACHE_DATA:
		bs2_info("ioctl sends to device, cmd 0x%x, arg %d\n",
				cmd, *(int *)arg);
		bankshot2_ioctl_cache_data(bs2_dev, (void *)arg);
		break;
	default:
		break;
	}

	return 0;
}

const struct file_operations bankshot2_char_fops = {
	.open = bankshot2_char_open,
	.release = bankshot2_char_release,
	.unlocked_ioctl = bankshot2_char_ioctl,
};

int bankshot2_char_init(void)
{
	bankshot2_chardev_class = class_create(THIS_MODULE, "bankshot2Ctrl");
	bs2_info("create char class\n");
	return 0;
}	

void bankshot2_char_exit(void)
{
	class_destroy(bankshot2_chardev_class);
	bs2_info("destroy char class\n");
}	

int bankshot2_init_char(struct bankshot2_device *bs2_dev)
{
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
}

