/*
 * Bankshot2 kernel device driver
 *
 * 2/26/2014 - Andiry Xu <jix024@cs.ucsd.edu>
 *
 */

#include "bankshot2.h"

static unsigned long phys_addr;
static unsigned long cache_size;
module_param(phys_addr, ulong, S_IRUGO);
MODULE_PARM_DESC(phys_addr, "Start physical address");
module_param(cache_size, ulong, S_IRUGO);
MODULE_PARM_DESC(cache_size, "Cache size");

struct bankshot2_device *bs2_dev;

static int bankshot2_ioremap(struct bankshot2_device *bs2_dev,
				unsigned long phys_addr, unsigned long size)
{
	void *ret;

	ret = request_mem_region_exclusive(phys_addr, size, "bankshot2");
	if (!ret)
		return -EINVAL;

	ret = ioremap_cache(phys_addr, size);
	if (!ret)
		return -EINVAL;

	bs2_dev->virt_addr = ret;
	bs2_dev->phys_addr = phys_addr;
	bs2_dev->size = size;
	return 0;
}

static void bankshot2_iounmap(struct bankshot2_device *bs2_dev)
{
	iounmap(bs2_dev->virt_addr);
	release_mem_region(bs2_dev->phys_addr, bs2_dev->size);
}

static void bankshot2_init_blocks(struct bankshot2_device *bs2_dev)
{
	bs2_dev->block_start = (BANKSHOT2_RESERVE_SPACE >> PAGE_SHIFT);
	bs2_dev->block_end = (bs2_dev->size >> PAGE_SHIFT);
	bs2_dev->num_free_blocks = bs2_dev->block_end - bs2_dev->block_start;

}

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

	ret = bankshot2_ioremap(bs2_dev, phys_addr, cache_size);
	if (ret) {
		bs2_info("Bankshot2 ioremap failed.\n");
		ret = -EINVAL;
		goto ioremap_fail;
	}

	bankshot2_init_blocks(bs2_dev);
	bs2_info("Bankshot2 initialized, cache start at %ld, size %ld, "
			"remap @%p, block start %ld, block end %ld, "
			"free blocks %ld\n",
			phys_addr, cache_size, bs2_dev->virt_addr,
			bs2_dev->block_start, bs2_dev->block_end,
			bs2_dev->num_free_blocks);
	return 0;

ioremap_fail:
	bankshot2_char_destroy(bs2_dev);
char_fail:
	bankshot2_char_exit();
	kfree(bs2_dev);
check_fail:
	return ret;

}

static void __exit bankshot2_exit(void)
{
	bankshot2_iounmap(bs2_dev);
	bankshot2_char_destroy(bs2_dev);
	bankshot2_char_exit();
	kfree(bs2_dev);
}


MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
MODULE_DESCRIPTION("Bankshot2 kernel cache manager");
MODULE_LICENSE("GPL");

module_init(bankshot2_init);
module_exit(bankshot2_exit);
