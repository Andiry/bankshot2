/*
 * Bankshot2 kernel device driver
 *
 * 2/26/2014 - Andiry Xu <jix024@cs.ucsd.edu>
 *
 */

/*
 * Bankshot2 core code. Init entrance.
 */

#include "bankshot2.h"

static unsigned long phys_addr;
static unsigned long cache_size;
char *backing_dev_name = "/dev/ram0";
module_param(phys_addr, ulong, S_IRUGO);
MODULE_PARM_DESC(phys_addr, "Start physical address");
module_param(cache_size, ulong, S_IRUGO);
MODULE_PARM_DESC(cache_size, "Cache size");
module_param(backing_dev_name, charp, S_IRUGO);
MODULE_PARM_DESC(backing_dev_name, "Backing store");

struct bankshot2_device *bs2_dev;

static int __init bankshot2_init(void)
{
	int ret;

	if (cache_size <= BANKSHOT2_RESERVE_SPACE * 2) {
		bs2_info("Minimal Bankshot2 cache size 8MB.\n");
		ret = -ENOMEM;
		goto check_fail;
	}

	bs2_dev = kzalloc(sizeof(struct bankshot2_device), GFP_KERNEL);
	if (!bs2_dev)
		return -ENOMEM;

	bankshot2_char_init();

	ret = bankshot2_char_setup(bs2_dev);
	if (ret) {
		bs2_info("Bankshot2 char setup failed.\n");
		goto char_fail;
	}

	ret = bankshot2_init_super(bs2_dev, phys_addr, cache_size);
	if (ret) {
		bs2_info("Bankshot2 super setup failed.\n");
		ret = -EINVAL;
		goto super_fail;
	}

	ret = bankshot2_init_job_queue(bs2_dev);
	if (ret) {
		bs2_info("Bankshot2 job queue init failed.\n");
		ret = -EINVAL;
		goto job_fail;
	}

	ret = bankshot2_init_cache(bs2_dev, backing_dev_name);
	if (ret) {
		bs2_info("Bankshot2 cache init failed.\n");
		ret = -EINVAL;
		goto cache_fail;
	}

	ret = bankshot2_block_setup(bs2_dev);
	if (ret) {
		bs2_info("Bankshot2 block setup failed.\n");
		goto block_fail;
	}

	return 0;

block_fail:
	blkdev_put(bs2_dev->bs_bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);

cache_fail:
	bankshot2_destroy_job_queue(bs2_dev);

job_fail:
	bankshot2_destroy_super(bs2_dev);

super_fail:
	bankshot2_char_destroy(bs2_dev);

char_fail:
	bankshot2_char_exit();
	kfree(bs2_dev);

check_fail:
	return ret;

}

static void __exit bankshot2_exit(void)
{
	bankshot2_destroy_job_queue(bs2_dev);
	blkdev_put(bs2_dev->bs_bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	bankshot2_block_destroy(bs2_dev);
	bankshot2_destroy_super(bs2_dev);
	bankshot2_char_destroy(bs2_dev);
	bankshot2_char_exit();
	kfree(bs2_dev);
}


MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
MODULE_DESCRIPTION("Bankshot2 kernel cache manager");
MODULE_LICENSE("GPL");

module_init(bankshot2_init);
module_exit(bankshot2_exit);
