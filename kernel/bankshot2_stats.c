/*
 * Bankshot2 kernel device driver
 *
 * 2/26/2014 - Andiry Xu <jix024@cs.ucsd.edu>
 *
 */

/*
 * Bankshot2 Timing measurement.
 */

#include "bankshot2.h"

const char *Timingstring[TIMING_NUM] = 
{
	"cache_data",
	"get_extent",
	"get_extent_failed",
	"xip_read",
	"xip_write",
	"allocation",
	"check_mmap",
	"mmap",
	"copy_to_cache_for_read",
	"copy_to_cache_for_write",
	"vfs_read_for_read",
	"vfs_read_for_write",
	"vfs_cache_fill_for_read",
	"vfs_cache_fill_for_write",
	"copy_from_cache",
	"copy_to_user",
	"copy_from_user",
	"add_extent",
	"evict_cache",
	"update_physical_tree",
	"add_physical_extent",
	"insert_access_tree",
	"remove_access_tree",
	"wait_on_access_tree",
	"fiemap",
	"bio_to_cache",
	"get_cache_inode",
	"evict_cache_inode",
};

void bankshot2_print_time_stats(struct bankshot2_device *bs2_dev)
{
	int i;

	bs2_info("======== Bankshot2 kernel timing stats: ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		if (measure_timing) {
			bs2_info("%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				bs2_dev->countstats[i],
				bs2_dev->timingstats[i],
				bs2_dev->countstats[i] ?
				bs2_dev->timingstats[i] /
					bs2_dev->countstats[i] : 0);
		} else {
			bs2_info("%s: count %llu\n",
				Timingstring[i],
				bs2_dev->countstats[i]);
		}
	}
}

void bankshot2_print_io_stats(struct bankshot2_device *bs2_dev)
{
	int i;
	int num_pi = 0;
	unsigned long allocated_blocks = 0;
	struct bankshot2_inode *pi;

	bs2_info("======== Bankshot2 kernel IO stats: ========\n");
	bs2_info("copy_to_cache for read blocks: %llu\n",
				bs2_dev->bs_read_blocks);
	bs2_info("copy_to_cache for write blocks: %llu\n",
				bs2_dev->bs_write_blocks);
	bs2_info("bio to cache size: %llu\n",
				bs2_dev->bio_cache_size);
	bs2_info("Fiemap count: %llu\n", bs2_dev->fiemap_count);
	bs2_info("Bio to backing store: count %llu, total size %llu, "
		"average size %llu\n", bs2_dev->num_bio,
		bs2_dev->total_bio_size,
		bs2_dev->num_bio ?
		bs2_dev->total_bio_size / bs2_dev->num_bio : 0);

	for (i = BANKSHOT2_FREE_INODE_HINT_START;
			i < bs2_dev->s_inodes_count; i++) {
		pi = bankshot2_get_inode(bs2_dev, i);
		if (pi && pi->backup_ino) {
			num_pi++;
			allocated_blocks += pi->i_blocks;
		}
	}

	bs2_info("Total %d Pi, s_inodes_count %u, s_inodes_used_count %u, "
		"s_free_inodes_count %u\n", num_pi, bs2_dev->s_inodes_count,
		bs2_dev->s_inodes_used_count, bs2_dev->s_free_inodes_count);

	bs2_info("Allocated %lu blocks, bankshot2 has %lu blocks, "
		"free blocks %lu\n", allocated_blocks, bs2_dev->block_end,
		bs2_dev->num_free_blocks);

	bs2_info("Inode alloc %u, evict %u\n",
		bs2_dev->cache_stats.inode_alloc,
		bs2_dev->cache_stats.inode_evict);
}

void bankshot2_clear_stats(struct bankshot2_device *bs2_dev)
{
	int i;

	for (i = 0; i < TIMING_NUM; i++) {
		bs2_dev->countstats[i] = 0;
		bs2_dev->timingstats[i] = 0;
	}

	bs2_dev->bs_read_blocks = 0;
	bs2_dev->bs_write_blocks = 0;
	bs2_dev->bio_cache_size = 0;
	bs2_dev->fiemap_count = 0;
	bs2_dev->num_bio = 0;
	bs2_dev->total_bio_size = 0;
}

