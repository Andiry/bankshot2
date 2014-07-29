/*
 * Bankshot2 kernel device driver
 *
 * 2/26/2014 - Andiry Xu <jix024@cs.ucsd.edu>
 *
 */

/*
 * Bankshot2 Init entrance.
 */

#include "bankshot2.h"

static unsigned long phys_addr;
static unsigned long cache_size;
int measure_timing = 0;
int bio_interception = 0;
char *backing_dev_name = "/dev/ram0";

module_param(phys_addr, ulong, S_IRUGO);
MODULE_PARM_DESC(phys_addr, "Start physical address");
module_param(cache_size, ulong, S_IRUGO);
MODULE_PARM_DESC(cache_size, "Cache size");
module_param(measure_timing, int, S_IRUGO);
MODULE_PARM_DESC(measure_timing, "Timing measurement");
module_param(bio_interception, int, S_IRUGO);
MODULE_PARM_DESC(bio_interception, "Bio to cache interception");
module_param(backing_dev_name, charp, S_IRUGO);
MODULE_PARM_DESC(backing_dev_name, "Backing store");

struct bankshot2_device *bs2_dev;

static int bankshot2_device_alloc(void)
{
	int i;

	bs2_dev = kzalloc(sizeof(struct bankshot2_device), GFP_KERNEL);
	if (!bs2_dev) {
		bs2_info("Bankshot2 mem alloc failed.\n");
		return -ENOMEM;
	}

	bs2_dev->inode_hash_array =
		kzalloc(sizeof(struct hash_inode) * HASH_ARRAY_SIZE,
			GFP_KERNEL);

	if (!bs2_dev->inode_hash_array) {
		bs2_info("Bankshot2 hash array alloc failed.\n");
		kfree(bs2_dev);
		return -ENOMEM;
	}

	for (i = 0; i < HASH_ARRAY_SIZE; i++)
		bs2_dev->inode_hash_array[i].size = 1;

	return 0;
}

static int bankshot2_device_free(struct bankshot2_device *bs2_dev)
{
	int i;

	for (i = 0; i < HASH_ARRAY_SIZE; i++) {
		if (bs2_dev->inode_hash_array[i].size > 1)
			kfree(bs2_dev->inode_hash_array[i].ino_array);
	}

	kfree(bs2_dev->inode_hash_array);
	kfree(bs2_dev);

	return 0;
}

static int __init bankshot2_init(void)
{
	int ret;

	if (cache_size < BANKSHOT2_RESERVE_SPACE) {
		bs2_info("Minimal Bankshot2 cache size 4MB.\n");
		ret = -ENOMEM;
		goto check_fail;
	}

	if (sizeof(struct bankshot2_inode) > BANKSHOT2_INODE_SIZE) {
		bs2_info("Inode size too big: limit %d bytes, "
				"actual %lu bytes\n",
				BANKSHOT2_INODE_SIZE,
				sizeof(struct bankshot2_inode));
		ret = -EINVAL;
		goto check_fail;
	}

	ret = bankshot2_device_alloc();
	if (ret) {
		bs2_info("Bankshot2 device alloc failed.\n");
		return -ENOMEM;
	}

	ret = bankshot2_init_kmem(bs2_dev);
	if (ret) {
		bs2_info("Bankshot2 kmem setup failed.\n");
		goto kmem_fail;
	}

	ret = bankshot2_init_char(bs2_dev);
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

	ret = bankshot2_init_block(bs2_dev);
	if (ret) {
		bs2_info("Bankshot2 block setup failed.\n");
		goto block_fail;
	}

	bankshot2_init_mmap(bs2_dev);

	ret = bankshot2_init_extents(bs2_dev);
	if (ret) {
		bs2_info("Bankshot2 extents init failed.\n");
		goto block_fail;
	}

	ret = bankshot2_init_transactions(bs2_dev);
	if (ret) {
		bs2_info("Bankshot2 transactions init failed.\n");
		goto extents_fail;
	}

	bs2_info("Bankshot2 initialization succeed.\n");
	return 0;

extents_fail:
	bankshot2_destroy_extents(bs2_dev);

block_fail:
	blkdev_put(bs2_dev->bs_bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);

cache_fail:
	bankshot2_destroy_job_queue(bs2_dev);

job_fail:
	bankshot2_destroy_super(bs2_dev);

super_fail:
	bankshot2_destroy_char(bs2_dev);

char_fail:
	bankshot2_destroy_kmem(bs2_dev);

kmem_fail:
	bankshot2_device_free(bs2_dev);

check_fail:
	return ret;

}

static void __exit bankshot2_exit(void)
{
	bs2_info("Exiting Bankshot2...\n");
	bankshot2_destroy_physical_tree(bs2_dev);
	bankshot2_destroy_transactions(bs2_dev);
	bankshot2_destroy_extents(bs2_dev);
	bankshot2_destroy_job_queue(bs2_dev);
	blkdev_put(bs2_dev->bs_bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	bankshot2_destroy_block(bs2_dev);
	bankshot2_destroy_super(bs2_dev);
	bankshot2_destroy_char(bs2_dev);
	bankshot2_destroy_kmem(bs2_dev);
	bankshot2_device_free(bs2_dev);
	bs2_info("Exit Bankshot2.\n");
}


MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
MODULE_DESCRIPTION("Bankshot2 kernel cache manager");
MODULE_LICENSE("GPL");

module_init(bankshot2_init);
module_exit(bankshot2_exit);
