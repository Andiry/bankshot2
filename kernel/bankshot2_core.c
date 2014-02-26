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

static int __init bankshot2_init(void)
{
	int ret;

	bs2_dev = kzalloc(sizeof(struct bankshot2_device), GFP_KERNEL);
	if (!bs2_dev)
		return -ENOMEM;

	bankshot2_char_init();

	ret = bankshot2_char_setup(bs2_dev);
	if (ret)
		goto char_fail;

	bs2_info("Bankshot2 initialized, cache start at %ld, size %ld\n",
			phys_addr, cache_size);
	return 0;

char_fail:
	kfree(bs2_dev);
	return ret;	

}

static void __exit bankshot2_exit(void)
{
	bankshot2_char_destroy(bs2_dev);
	bankshot2_char_exit();
	kfree(bs2_dev);
}


MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
MODULE_DESCRIPTION("Bankshot2 kernel cache manager");
MODULE_LICENSE("GPL");

module_init(bankshot2_init);
module_exit(bankshot2_exit);
