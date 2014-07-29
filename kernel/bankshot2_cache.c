/*
 * Cache code.
 * Copied from bee3_cache.c
 */

#include "bankshot2.h"

static inline int bankshot2_check_zero_length(struct bankshot2_device *bs2_dev,
			struct bankshot2_cache_data *data)
{
	if (data->extent_start_file_offset + data->extent_length
				<= data->offset)
		return 1;
	return 0;
}

/*
 * Get the file extent which overlaps with request extent.
 */
static int bankshot2_get_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_cache_data *data, struct inode **st_inode)
{
	struct file *fileinfo;
	struct inode *inode;
	int ret = 0;
	uint64_t test_offset;

	fileinfo = fget(data->file);
	if (!fileinfo) {
		bs2_info("fget failed\n");
		return -EINVAL;
	}

	inode = fileinfo->f_dentry->d_inode;
	if (!inode) {
		fput(fileinfo);
		bs2_info("inode get failed %p\n", inode);
		return -EINVAL;
	}

	data->read = data->write = 0;
	if (fileinfo->f_mode & FMODE_READ)
		data->read = 1;
	if (fileinfo->f_mode & FMODE_WRITE)
		data->write = 1;

	if (data->rnw == READ_EXTENT && !data->read) {
		bs2_info("Request want to read but no read permission!\n");
		fput(fileinfo);
		return -EINVAL;
	} else if (data->rnw == WRITE_EXTENT && !data->write) {
		bs2_info("Request want to write but no write permission!\n");
		fput(fileinfo);
		return -EINVAL;
	}

	if (S_ISREG(inode->i_mode)) {
		data->file_length = i_size_read(inode);
		bs2_dbg("File length: %llu\n", data->file_length);

		if (data->offset >= data->file_length) {
			bs2_dbg("File offset >= file length: %llu %llu\n",
					data->offset, data->file_length);
			data->extent_start = -512;
			data->extent_length = -512;
			data->extent_start_file_offset = -512;
			goto out;
		}

		/* Test if we can start mmap from MAX_MMAP boundary */
		test_offset = ALIGN_DOWN_MMAP(data->offset);

		data->extent_start_file_offset = test_offset;
		data->extent_start = test_offset;
		data->extent_length = data->file_length - test_offset;
//		bs2_dev->fiemap_count++;

		ret = 1;

		bs2_dbg("Extent: PhyStart: 0x%llx, len: 0x%lx,"
			" LogStart: 0x%llx, offset 0x%llx\n",
			data->extent_start, data->extent_length,
			data->extent_start_file_offset,
			data->offset);
	} else {
		bs2_dbg("Raw device.\n");
		if (data->offset < bs2_dev->bs_sects * 512) {
			data->extent_start = data->offset;
			data->extent_length = bs2_dev->bs_sects * 512
						- data->offset;
			data->extent_start_file_offset = data->offset;
			data->file_length = bs2_dev->bs_sects * 512;
		} else {
			ret = -1;
		}
	}

out:
	fput(fileinfo);
	*st_inode = inode;
	bs2_dbg("Inode %p permissions: Read %d Write %d\n", *st_inode,
			data->read, data->write);

	if (data->extent_start == (uint64_t)(-1) ||
	    data->extent_start == (uint64_t)(-512) ||
	    data->extent_start_file_offset > data->offset ||
	    data->file_length == 0)
		return -3;

	return ret;

}

int bankshot2_get_backing_inode(struct bankshot2_device *bs2_dev,
					void *arg, struct inode **st_inode)
{
	struct file *fileinfo;
	struct inode *inode;
	struct bankshot2_cache_data *data;

	data = (struct bankshot2_cache_data *)arg;
	fileinfo = fget(data->file);
	if (!fileinfo) {
		bs2_info("fget failed\n");
		return -EINVAL;
	}

	inode = fileinfo->f_dentry->d_inode;
	if (!inode) {
		fput(fileinfo);
		bs2_info("inode get failed %p\n", inode);
		return -EINVAL;
	}

	data->read = data->write = 0;
	if (fileinfo->f_mode & FMODE_READ)
		data->read = 1;
	if (fileinfo->f_mode & FMODE_WRITE)
		data->write = 1;

	//we should invalidate the inode's buffer-cache mappings as well, so we don't get invalid data later

	fput(fileinfo);
	*st_inode = inode;
	bs2_dbg("Inode %p permissions: Read %d Write %d\n", *st_inode,
			data->read, data->write);

	return 0;
}

/*
 * cache_data input:
 * offset: request offset, not aligned
 * size: request length, not aligned
 *
 * output:
 * mmap_offset: mmap offset, aligned to MMAP_UNIT
 * mmap_length: mmap length, aligned ot MMAP_UNIT
 * mmap_addr:   mmap address
 * file_length: File length
 */
int bankshot2_ioctl_cache_data(struct bankshot2_device *bs2_dev, void *arg)
{
	struct bankshot2_cache_data _data, *data;
	struct bankshot2_inode *pi;
	int ret;
	u64 st_ino;
	struct inode *inode;
	ssize_t actual_length = 0;
	size_t request_len;
	timing_t cache_data, xip_read, xip_write;

	data = &_data;

	BANKSHOT2_START_TIMING(bs2_dev, cache_data_t, cache_data);

	ret = bankshot2_get_extent(bs2_dev, arg, &inode);
	if (ret < 0) {
		bs2_dbg("Get extent returned %d\n", ret);
		if (ret == -3)
			ret = EOF_OR_HOLE;
		BANKSHOT2_END_TIMING(bs2_dev, get_extent_fail_t, cache_data);
		return ret;
	}
	BANKSHOT2_END_TIMING(bs2_dev, get_extent_t, cache_data);

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	bs2_dbg("Request: file %d, length %llu, offset 0x%llx, "
		"request len %lu\n", data->file, data->file_length,
		data->offset, data->size);

	data->inode = inode;
	/* Request len: the length that user space required
	   Start from offset, unaligned */
	request_len = (data->extent_start_file_offset + data->extent_length)
			> (data->offset + data->size) ?
			data->size :
			data->extent_start_file_offset + data->extent_length
				- data->offset;

	if (request_len == 0)
		bs2_info("Request length is 0! file %d, offset 0x%llx, "
			"size %lu, mmap offset 0x%llx, mmaped len %lu, "
			"extent offset 0x%llx, extent length %lu\n",
			data->file, data->offset, data->size,
			data->mmap_offset, data->mmap_length,
			data->extent_start_file_offset, data->extent_length);

	data->size = request_len;

	mutex_lock(&bs2_dev->inode_table_mutex);
	pi = bankshot2_find_cache_inode(bs2_dev, data, &st_ino);
	if (!pi) {
		bs2_info("No cache inode found\n");
		ret = -EINVAL;
		mutex_unlock(&bs2_dev->inode_table_mutex);
		goto out;
	}

	/* Move the pi to the tail of pi_lru_list */
	list_move_tail(&pi->lru_list, &bs2_dev->pi_lru_list);
	mutex_unlock(&bs2_dev->inode_table_mutex);

	if (data->rnw == WRITE_EXTENT) {
		BANKSHOT2_START_TIMING(bs2_dev, xip_write_t, xip_write);
		ret = bankshot2_xip_file_write(bs2_dev, data, pi,
						&actual_length);
		BANKSHOT2_END_TIMING(bs2_dev, xip_write_t, xip_write);
	} else {
		BANKSHOT2_START_TIMING(bs2_dev, xip_read_t, xip_read);
		ret = bankshot2_xip_file_read(bs2_dev, data, pi,
						&actual_length);
		BANKSHOT2_END_TIMING(bs2_dev, xip_read_t, xip_read);
	}

	if (ret) {
		bs2_info("xip_file operation returned %d, "
			"offset 0x%llx, request len %lu, actual len %lu\n",
			ret, data->offset, data->size, actual_length);
	}

	if (actual_length <= 0) {
		bs2_info("data size incorrect: %lu\n", actual_length);
		data->mmap_addr = 0;
		ret = -EINVAL;
		goto out;
	}

	data->actual_length = actual_length;

//	bankshot2_print_tree(bs2_dev, pi);
out:
	// Align extent_start_file_offset and extent_length to PAGE_SIZE
//	data->extent_start_file_offset = data->mmap_offset;
//	data->extent_length = actual_length + data->offset
//				- data->extent_start_file_offset;
	bs2_dbg("%s: file %d, inode %llu, length %llu, offset 0x%llx(%llu), "
		"request len %lu, mmap offset 0x%llx, mmaped len %lu, "
		"mmap_addr %lx, actual offset 0x%llx, actual length %lu, "
		"extent start offset 0x%llx, extent length %lu\n",
		__func__, data->file, pi->i_ino, data->file_length,
		data->offset, data->offset,
		data->size, data->mmap_offset, data->mmap_length,
		data->mmap_addr, data->actual_offset, data->actual_length,
		data->extent_start_file_offset, data->extent_length);

	copy_to_user(arg, data, sizeof(struct bankshot2_cache_data));

	if (ret)
		bs2_info("%s: return %d\n", __func__, ret);

	BANKSHOT2_END_TIMING(bs2_dev, cache_data_t, cache_data);
	return ret;
}

int bankshot2_ioctl_get_cache_inode(struct bankshot2_device *bs2_dev, void *arg)
{
	struct bankshot2_cache_data _data, *data;
	struct bankshot2_inode *pi;
	int ret;
	u64 st_ino;
	struct inode *inode;
	timing_t get_inode_time;

	data = &_data;

	BANKSHOT2_START_TIMING(bs2_dev, get_inode_t, get_inode_time);
	ret = bankshot2_get_backing_inode(bs2_dev, arg, &inode);
	if (ret) {
		bs2_info("Get backing inode returned %d\n", ret);
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	data->inode = inode;

	mutex_lock(&bs2_dev->inode_table_mutex);
	pi = bankshot2_find_cache_inode(bs2_dev, data, &st_ino);
	mutex_unlock(&bs2_dev->inode_table_mutex);

	if (!pi) {
		bs2_info("No cache inode found\n");
		return -EINVAL;
	}

	copy_to_user(arg, data, sizeof(struct bankshot2_cache_data));

	bs2_dbg("Cache ino %llu, ret %d\n", data->cache_ino, ret);
	BANKSHOT2_END_TIMING(bs2_dev, get_inode_t, get_inode_time);

	return ret;
}

int bankshot2_init_cache(struct bankshot2_device *bs2_dev, char *bsdev_name)
{
	struct block_device *bdev;
	dev_t dev;
	int ret;

	bdev = lookup_bdev(bsdev_name);
	if (IS_ERR(bdev)) {
		bs2_info("Backing device not found\n");
		ret = -EINVAL;
		goto fail;
	}

	dev = bdev->bd_dev;
	if (!bdev->bd_inode) {
		bs2_info("Backing device inode is NULL\n");
		ret = -EINVAL;
		goto fail;
	}

	if (dev) {
		bdev = blkdev_get_by_dev(dev, FMODE_READ |
					FMODE_WRITE | FMODE_EXCL, bs2_dev);
		if(IS_ERR(bdev)) {
			ret = -EINVAL;
			goto fail;
		}
	} else {
		bs2_info("Backing store bdisk is null\n");
		ret = -EINVAL;
		goto fail;
	}

	bs2_info("Opened handle to the block device %p\n", bdev);

	if (bdev->bd_disk){
		bs2_dev->backing_store_rqueue = bdev_get_queue(bdev);
		bs2_info("Backing store %p request queue is %p\n",
				bdev, bs2_dev->backing_store_rqueue);
		if (bs2_dev->backing_store_rqueue) {
			bs2_info("max_request_in_queue %lu, "
				"max_sectors %d, "
				"physical_block_size %d, "
				"io_min %d, io_op %d, "
				"make_request_fn %p\n",
			bs2_dev->backing_store_rqueue->nr_requests,
			bs2_dev->backing_store_rqueue->limits.max_sectors,
			bs2_dev->backing_store_rqueue->limits.physical_block_size,
		 	bs2_dev->backing_store_rqueue->limits.io_min,
			bs2_dev->backing_store_rqueue->limits.io_opt,
			bs2_dev->backing_store_rqueue->make_request_fn
			);
			bs2_info("Backing store number %d\n",
				bdev->bd_dev);

			bs2_dev->bs_bdev = bdev;
//			bs2_dev->backingdevnum = bdev->bd_dev;

			return 0;

		} else
			bs2_info("Backing store request queue "
					"is null pointer\n");
	} else
		bs2_info("Backing store bdisk is null\n");

	blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	return -EINVAL;
fail:
	return ret;
}
