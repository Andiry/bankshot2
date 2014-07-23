
/*
 * Block device part.
 * Represent bankshot2 as a block device.
 */

#include "bankshot2.h"

int bankshot2_block_open(struct block_device *bd, fmode_t mode)
{
	struct bankshot2_device *bs2_dev = bd->bd_disk->private_data;

	bs2_dev->self_bdev = bd;
	check_disk_change(bd);

	return 0;
}

void bankshot2_block_release(struct gendisk *gd, fmode_t mode)
{
//	bs2_info("release bankshot2 char class\n");
	return;
}

int bankshot2_block_ioctl(struct block_device *bd, fmode_t mode,
				unsigned int cmd, unsigned long arg)
{
//	struct bankshot2_device *bs2_dev = bd->bd_disk->private_data;

	bs2_dbg("ioctl sends to block device, cmd 0x%x\n", cmd);

	return 0;
}

const struct block_device_operations bankshot2_block_fops = {
	.owner = THIS_MODULE,
	.open = bankshot2_block_open,
	.release = bankshot2_block_release,
	.ioctl = bankshot2_block_ioctl,
};

void bankshot2_make_cache_request(struct request_queue *q, struct bio *bio)
{
	struct bankshot2_device *bs2_dev;
	struct bankshot2_inode *pi;
	struct extent_entry *extent;
	size_t size;
	struct bio_vec *bvec;
	u64 b_offset;
	u64 block;
	void *xmem;
	char *buf;
	unsigned long index;
	unsigned int i;
	timing_t bio_cache;

	bs2_dev = (struct bankshot2_device *)q->queuedata;
//	bs2_dbg("Bio sends to block device\n");
//	bio_get(bio);
//	size = bio->bi_size;
//	sectors = bio->bi_sector;
//	idx = bio->bi_idx;

//	bankshot2_reroute_bio(bs2_dev, idx, sectors, size, bio,
//				bs2_dev->bs_bdev, DISK, SYS_BIO_LAST);
//	jd->disk_cmd = bio_data_dir(bio) ? WRITE : READ;

	if (bio_interception == 0)
		goto out;

	/* If it's a write and b_offset in physical tree, copy to cache */
	if (bio_data_dir(bio)) {
		b_offset = bio->bi_sector << 9;
		size = bio->bi_size;

		bs2_dbg("b_offset 0x%llx, size %lu\n", b_offset, size);
		extent = bankshot2_find_physical_extent(bs2_dev, b_offset);

		if (!extent)
			goto out;

		BANKSHOT2_START_TIMING(bs2_dev, bio_cache_t, bio_cache);
		pi = bankshot2_get_inode(bs2_dev, extent->ino);
		if (!pi) {
			bs2_info("Pi not found: %llu\n", extent->ino);
			goto out;
		}

		index = (extent->offset + b_offset - extent->b_offset)
				>> bs2_dev->s_blocksize_bits;

		if (b_offset + size > extent->b_offset + extent->length)
			bs2_info("Err: bio length larger than extent length: "
			"pi %llu, extent offset 0x%lx, b_offset 0x%lx, "
			"length %lu, bio b_offset 0x%llx, length %lu\n",
			extent->ino, extent->offset, extent->b_offset,
			extent->length, b_offset, size);

		bs2_dbg("Found: pi %llu, offset 0x%lx, length %lu\n",
			extent->ino, index << bs2_dev->s_blocksize_bits, size);
		bio_for_each_segment(bvec, bio, i) {
			block = bankshot2_find_data_block(bs2_dev, pi, index);
			if (!block) {
				bs2_info("Transfer to cache failed\n");
				break;
			}

			xmem = bankshot2_get_block(bs2_dev, block);
			buf = kmap_atomic(bvec->bv_page);
			bs2_dbg("Memcpy: index %lu, length %u\n",
					index, bvec->bv_len);
			memcpy(xmem, buf + bvec->bv_offset, bvec->bv_len);
			kunmap_atomic(buf);
			bankshot2_flush_edge_cachelines(
				index << bs2_dev->s_blocksize_bits,
				PAGE_SIZE, xmem);

			index++;
			if (index << bs2_dev->s_blocksize_bits
					>= extent->offset + extent->length)
				break;
		}

		bs2_dev->bio_cache_size += size;
		bio->bi_size = size;
		bio->bi_idx = 0;
		BANKSHOT2_END_TIMING(bs2_dev, bio_cache_t, bio_cache);
	}

out:
	bs2_dev->num_bio++;
	bs2_dev->total_bio_size += bio->bi_size;
	bio->bi_bdev = bs2_dev->bs_bdev;
	submit_bio(bio_data_dir(bio) ? WRITE : READ, bio);

	return;
}

static void bankshot2_setup_queue(struct bankshot2_device *bs2_dev)
{
	blk_queue_max_hw_sectors(bs2_dev->queue,
		queue_max_hw_sectors(bs2_dev->backing_store_rqueue));
	blk_queue_max_segments(bs2_dev->queue,
		queue_max_segments(bs2_dev->backing_store_rqueue));
	blk_queue_max_segment_size(bs2_dev->queue,
		queue_max_segment_size(bs2_dev->backing_store_rqueue));
	blk_queue_segment_boundary(bs2_dev->queue,
		queue_segment_boundary(bs2_dev->backing_store_rqueue));
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT,
				bs2_dev->backing_store_rqueue);
//	queue_flag_set_unlocked(QUEUE_FLAG_ELVSWITCH,
//				bs2_dev->backing_store_rqueue);
	queue_flag_set_unlocked(QUEUE_FLAG_NOMERGES,
				bs2_dev->backing_store_rqueue);
	blk_queue_io_min(bs2_dev->queue,
		queue_io_min(bs2_dev->backing_store_rqueue));
	blk_queue_io_opt(bs2_dev->queue,
		queue_io_opt(bs2_dev->backing_store_rqueue));
	blk_queue_alignment_offset(bs2_dev->queue,
		queue_alignment_offset(bs2_dev->backing_store_rqueue));
	blk_queue_dma_alignment(bs2_dev->queue,
		queue_dma_alignment(bs2_dev->backing_store_rqueue));
}

int bankshot2_init_block(struct bankshot2_device *bs2_dev)
{
	int bankshot2_major = 0;
	sector_t nr_sects;

	bankshot2_major = register_blkdev(bankshot2_major, "bankshot2");
	if (bankshot2_major <= 0) {
		bs2_info("Failed to register block device major num\n");
		return -EINVAL;
	}

	bs2_dev->major = bankshot2_major;
	bs2_dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!bs2_dev->queue) {
		bs2_info("Failed to alloc block queue\n");
		unregister_blkdev(bankshot2_major, "bankshot2");
		return -ENOMEM;
	}

	bs2_dev->queue->queuedata = bs2_dev;

	blk_queue_make_request(bs2_dev->queue, bankshot2_make_cache_request);

	blk_queue_bounce_limit(bs2_dev->queue, BLK_BOUNCE_ANY);

	bankshot2_setup_queue(bs2_dev);

	bs2_dev->gd = alloc_disk(BANKSHOT2_NUM_MINORS);
	if (!bs2_dev->gd)
		goto alloc_disk_fail;

	bs2_dev->gd->major = bankshot2_major;
	bs2_dev->gd->first_minor = 0;
	bs2_dev->gd->fops = &bankshot2_block_fops;
	bs2_dev->gd->queue = bs2_dev->queue;
	bs2_dev->gd->private_data = bs2_dev;

	snprintf(bs2_dev->gd->disk_name, 32, "bankshot2Block%d", 0);

	nr_sects = get_capacity(bs2_dev->bs_bdev->bd_disk);
	set_capacity(bs2_dev->gd, nr_sects);
	bs2_info("Size of backing store %llu\n", (uint64_t)nr_sects);
	bs2_dev->bs_sects = (uint64_t)nr_sects;

	add_disk(bs2_dev->gd);

	return 0;

alloc_disk_fail:
	bankshot2_destroy_block(bs2_dev);

	return -EINVAL;
}


void bankshot2_destroy_block(struct bankshot2_device* bs2_dev)
{
	del_gendisk(bs2_dev->gd);
	put_disk(bs2_dev->gd);
	blk_cleanup_queue(bs2_dev->queue);
	bs2_dev->queue = NULL;
	unregister_blkdev(bs2_dev->major, "bankshot2");
	bs2_info("%s returns.\n", __func__);
}

