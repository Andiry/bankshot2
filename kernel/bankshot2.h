#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/bio.h>
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
#define BANKSHOT2_NUM_MINORS	1

#define DISK 0
#define cache 1

#if 0
/* cache.c */
struct brd_cache_info {
	struct block_device *bs_bdev;
	struct request_queue *backing_store_rqueue;
};
#endif

/* From PMFS */

unsigned int blk_type_to_shift[3] = {12, 21, 30};
uint32_t blk_type_to_size[3] = {0x1000, 0x200000, 0x40000000};

/*
 * Structure of the super block in PMFS
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * pmfs_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we 
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and pmfs_get_block() returns correct
 * pointers even for offset 0.
 */
struct bankshot2_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below */
	__le16		s_sum;              /* checksum of this sb */
	__le16		s_magic;            /* magic signature */
	__le32		s_blocksize;        /* blocksize in bytes */
	__le64		s_size;             /* total size of fs in bytes */
	char		s_volume_name[16];  /* volume name */
	/* points to the location of pmfs_journal_t */
	__le64          s_journal_offset;
	/* points to the location of struct pmfs_inode for the inode table */
	__le64          s_inode_table_offset;

	__le64  	s_start_dynamic; 

	/* all the dynamic fields should go here */
	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically */
	__le32		s_mtime;            /* mount time */
	__le32		s_wtime;            /* write time */
	/* fields for fast mount support. Always keep them together */
	__le64		s_num_blocknode_allocated;
	__le64		s_num_free_blocks;
	__le32		s_inodes_count;
	__le32		s_free_inodes_count;
	__le32		s_inodes_used_count;
	__le32		s_free_inode_hint;
};


static inline struct bankshot2_super_block *
bankshot2_get_super(struct bankshot2_device *bs2_dev)
{
	return (struct bankshot2_super_block *)bs2_dev->virt_addr;
}

/* job part */

#define STATUS(flag)	((uint8_t)(1 << flag))

struct cache_stats{
	atomic_t hitcount;
	atomic_t misscount;
	atomic_t dirtycount;
	atomic_t cleancount;
	atomic_t evict_count;
	atomic_t evict_chunk_count;
	atomic_t release_chunk_count;
	atomic_t async_wb_chunk_count;
	atomic_t async_release_chunk_count;
	atomic_t write_back;
	atomic_t system_reads;
	atomic_t system_writes;
	atomic64_t system_writes_bytes;
	atomic_t protmiss;
	atomic_t sync_queued_count;
	uint64_t async_wb_blocks;
	uint64_t async_cleaned_blocks;
	int async_triggered;
	atomic_t sync_eviction_triggered;
	
};

typedef enum {
	WAKEUP_ON_COMPLETION=0,
	DO_COMPLETION=1, /*End of job. Could be endio for read or write  */	
	SYS_BIO=2, /*use orig bio to call endio and destroy job descriptor*/
	SYS_BIO_LAST=3, /* we call endio on sys bio only once*/
	FREE_ON_COMPLETION=4
}JOB_TYPE;

/* Valid status flags bit offsets - used to track request */
#define JOB_QUEUED_TO_DISK	1 /* The job is added to the backing store list */
#define JOB_ISSUED_TO_DISK	2 /* The job as been submitted to the backing store */
#define JOB_QUEUED_TO_CACHE	3 /* THe job has been queued for cache io */ 
#define JOB_ISSUED_TO_CACHE	4 /* The job has been submitted to cache */ 
#define JOB_DONE		5  /* The job has completed */ 
#define JOB_ERROR		6 /* The job has error */
#define JOB_ABORT 		7 /* Say the cached block is accessed again, we abort eviction */

struct job_descriptor{
	struct list_head store_queue;  /* This is the queue on which the job is placed before issuing. can be backing store or cache queue. Null if no queue */ 
	struct list_head jobs; /* List of jobs that are issued by the thread. Used to track completion */
	struct bankshot2_device *bs2_dev;
	struct task_struct *job_parent; /* Pointer to the task struct of the thread that initiated this job */
	uint64_t b_offset;
	uint64_t c_offset;
	size_t num_bytes; 
	atomic_t status; /* use atomic operations to set the status of the job queue. Only when the list is global we need locks. I use mb() when operating on it */
//	uint8_t moneta_cmd;
	unsigned long disk_cmd;
	JOB_TYPE type; 
	struct bio *bio;	
	struct bio *sys_bio;
};

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

	struct block_device *bs_bdev;
	struct request_queue	*backing_store_rqueue;
	struct bio_set *bio_set;
	struct kmem_cache *job_descriptor_slab;

	struct cache_stats cache_stats;
	struct list_head disk_queue;
	struct list_head cache_queue;

	atomic_t io_limit;
	spinlock_t io_queue_lock;

	int major;
	struct request_queue *queue;
	struct gendisk *gd;
	struct block_device *self_bdev;
	uint64_t bs_sects;

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
int bankshot2_init_cache(struct bankshot2_device *, char *);

/* bankshot2_io.c */
int bankshot2_init_job_queue(struct bankshot2_device *);
void bankshot2_destroy_job_queue(struct bankshot2_device *);
void bankshot2_reroute_bio(struct bankshot2_device *bs2_dev, int idx,
				size_t sector, size_t size,
				struct bio *bio, struct block_device *bdev,
				int where, JOB_TYPE type);

/* bankshot2_block.c */
int bankshot2_block_setup(struct bankshot2_device *);
void bankshot2_block_destroy(struct bankshot2_device *);
