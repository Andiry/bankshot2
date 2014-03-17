/*
 * Handle memory allocation.
 * Copied from PMFS super.c.
 */

#include "bankshot2.h"

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

static void bankshot2_init_memblocks(struct bankshot2_device *bs2_dev)
{
	bs2_dev->block_start = (BANKSHOT2_RESERVE_SPACE >> PAGE_SHIFT);
	bs2_dev->block_end = (bs2_dev->size >> PAGE_SHIFT);
	bs2_dev->num_free_blocks = bs2_dev->block_end - bs2_dev->block_start;
	bs2_info("Bankshot2 initialized, cache start at %ld, size %ld, "
			"remap @%p, block start %ld, block end %ld, "
			"free blocks %ld\n",
			phys_addr, cache_size, bs2_dev->virt_addr,
			bs2_dev->block_start, bs2_dev->block_end,
			bs2_dev->num_free_blocks);

}

int bankshot2_init_super(struct bankshot2_device *bs2_dev,
			unsigned long phys_addr, unsigned long cache_size)
{
	int ret;

	ret = bankshot2_ioremap(bs2_dev, phys_addr, size);
	if (!ret)
		return ret;

	bankshot2_init_memblocks(bs2_dev);
}
	
void bankshot2_destroy_super(struct bankshot2_device *)
{
	bankshot2_iounmap(bs2_dev);
}
