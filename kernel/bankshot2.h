#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/device.h>
//#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/fs.h>
//#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/types.h>
//#include <linux/radix-tree.h>
#include <linux/buffer_head.h> /* invalidate_bh_lrus() */
//#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/file.h>

#include <asm/uaccess.h>

#define bs2_dbg(s, args ...)	pr_info(s, ## args)
#define bs2_info(s, args ...)	pr_info(s, ## args)

#define BANKSHOT2_RESERVE_SPACE	(4 << 20)

#if 0
/* cache.c */
struct brd_cache_info {
	struct block_device *bs_bdev;
	struct request_queue *backing_store_rqueue;
};
#endif

struct bankshot2_device {
//	int		brd_number;
//	int		brd_refcnt;
//	loff_t		brd_offset;
//	loff_t		brd_sizelimit;
//	unsigned	brd_blocksize;

//	struct request_queue	*brd_queue;
//	struct gendisk		*brd_disk;
//	struct list_head	brd_list;

	void *virt_addr;
	unsigned long phys_addr;
	unsigned long size;
	unsigned long block_start;
	unsigned long block_end;
	unsigned long num_free_blocks;

	struct cdev chardev;
	dev_t chardevnum;

	/*
	 * Backing store of pages and lock to protect it. This is the contents
	 * of the block device.
	 */
//	spinlock_t		brd_lock;
//	struct radix_tree_root	brd_pages;
//	struct brd_cache_info *cache_info;
};


#if 0
int submit_bio_to_cache(struct brd_device *brd, struct bio *bio);
int brd_cache_open_backing_dev(struct block_device **bdev,
					char* backing_dev_name,
					struct brd_device* brd);
int brd_cache_init(struct brd_device *brd, struct block_device* bdev);
void brd_cache_exit(struct brd_device *brd);
#endif

/* bankshot2_char.c */
int bankshot2_char_init(void);
void bankshot2_char_exit(void);
int bankshot2_char_setup(struct bankshot2_device *);
void bankshot2_char_destroy(struct bankshot2_device *);

/* bankshot2_cache.c */
int bankshot2_ioctl_cache_data(struct bankshot2_device *, void *);
