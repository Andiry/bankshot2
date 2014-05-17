/*
 * Cache code.
 * Copied from bee3_cache.c
 */

#include "bankshot2.h"
#include "bankshot2_cache.h"

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
 * return 0: extent start from mmap_offset.
 * return 1: extent start from offset.
 */
static int bankshot2_get_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_cache_data *data, struct inode **st_inode)
{
	struct file *fileinfo;
	struct inode *inode;
	int ret = 0;
	uint64_t req_end;

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
		struct fiemap_extent_info fieinfo = {0,};
		fieinfo.fi_flags = FIEMAP_FLAG_SYNC;
		fieinfo.fi_extents_max = 1;
		fieinfo.fi_extents_start = &data->extent_start_file_offset;

		bs2_dbg("Detected normal file, try fiemap\n");
		if (!inode->i_op->fiemap) {
			fput(fileinfo);
			bs2_info("file system does not support fiemap.\n");
			return -EINVAL;
		}

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

		/* Align offset and request length to 2MB */
		data->mmap_offset = ALIGN_DOWN(data->offset);
		req_end = data->offset + data->size;
		req_end = ALIGN_UP(req_end);
		req_end = min(req_end, ALIGN_DOWN(data->file_length));

		data->mmap_length = req_end - data->mmap_offset;
		
		bs2_dbg("Request offset 0x%llx, size %lu, "
			"mmap offset 0x%llx, length %llu\n",
			data->offset, data->size, data->mmap_offset,
			data->file_length);

		filemap_write_and_wait(inode->i_mapping);

		/* Check the mapping start from mmap offset
		   to the end of file */
		ret = inode->i_op->fiemap(inode, &fieinfo,
			data->mmap_offset,
			data->file_length - data->mmap_offset);

		bs2_dbg("Extent fiemap return %d extents, ret %d\n",
				fieinfo.fi_extents_mapped, ret);
		if (fieinfo.fi_extents_mapped == 0) {
			data->extent_start = -512;
			data->extent_length = -512;
			data->extent_start_file_offset = -512;
			goto out;
		}
		
		ret = bankshot2_check_zero_length(bs2_dev, data);
		if (ret == 1) {
			memset(&fieinfo, 0, sizeof(struct fiemap_extent_info));
			fieinfo.fi_flags = FIEMAP_FLAG_SYNC;
			fieinfo.fi_extents_max = 1;
			fieinfo.fi_extents_start = &data->extent_start_file_offset;

			bs2_dbg("Extent does not overlap with request "
				"extent. Find the next extent.\n");
			ret = inode->i_op->fiemap(inode, &fieinfo,
					data->offset,
					data->file_length - data->offset);

			if (fieinfo.fi_extents_mapped == 0) {
				data->extent_start = -512;
				data->extent_length = -512;
				data->extent_start_file_offset = -512;
				goto out;
			}
			ret = 1;
		}

		bs2_dbg("Extent: PhyStart: 0x%llx, len: 0x%lx,"
			" LogStart: 0x%llx, offset 0x%llx, "
			"mmap offset 0x%llx\n",
			data->extent_start, data->extent_length,
			data->extent_start_file_offset,
			data->offset, data->mmap_offset);
	} else {
		bs2_dbg("Raw device.\n");
		ret = -1;
		//FIXME
	}

	//we should invalidate the inode's buffer-cache mappings as well, so we don't get invalid data later
	if (inode->i_mapping){
//		invalidate_inode_pages2(inode->i_mapping);
		truncate_inode_pages(inode->i_mapping, 0);
		filemap_write_and_wait(inode->i_mapping);
	}

	truncate_inode_pages(&inode->i_data, 0);
	filemap_write_and_wait(&inode->i_data);
	if (unlikely(inode->i_mapping->nrpages || inode->i_data.nrpages))
		bs2_info("Still has dirty pages %lu %lu\n",
			inode->i_mapping->nrpages, inode->i_data.nrpages);

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

static int bankshot2_get_backing_inode(struct bankshot2_device *bs2_dev,
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
 * mmap_offset: mmap offset, aligned to 2MB
 * mmap_length: mmap length, aligned ot 2MB
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
	size_t map_len;

	data = &_data;

	ret = bankshot2_get_extent(bs2_dev, arg, &inode);
	if (ret < 0) {
		bs2_dbg("Get extent returned %d\n", ret);
		if (ret == -3)
			ret = EOF_OR_HOLE;
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	// Update length for mmap and request
	/* map_len: the length that will be mmaped to user space
	   Aligned to 2MB, start from mmap_offset */
	/* If retval == 1, the extent starts from offset */
	if (ret == 0) {
		map_len = (data->extent_start_file_offset + data->extent_length)
				> (data->mmap_offset + data->mmap_length) ?
			data->mmap_length :
			data->extent_start_file_offset + data->extent_length
					- data->mmap_offset;

		map_len = ALIGN_DOWN(map_len);
	} else {
		map_len = 0;
	}

	data->inode = inode;
	/* Request len: the length that user space required
	   Start from offset, unaligned */
	request_len = (data->extent_start_file_offset + data->extent_length)
			> (data->offset + data->size) ?
			data->size :
			data->extent_start_file_offset + data->extent_length
				- data->offset;

	data->mmap_length = map_len;

	if (request_len == 0)
		bs2_info("Request length is 0! file %d, offset 0x%llx, "
			"size %lu, mmap offset 0x%llx, mmaped len %lu, "
			"extent offset 0x%llx, extent length %lu\n",
			data->file, data->offset, data->size,
			data->mmap_offset, data->mmap_length,
			data->extent_start_file_offset, data->extent_length);

	data->size = request_len;
	bs2_dbg("data map_len %lu, size %lu\n", map_len, request_len);

	ret = bankshot2_find_cache_inode(bs2_dev, data, &st_ino);
	if (ret) {
		bs2_info("No cache inode found, returned %d\n", ret);
		goto out;
	}

	pi = bankshot2_get_inode(bs2_dev, st_ino);
	if (!pi) {
		bs2_info("Failed to get cache inode\n");
		ret = -EINVAL;
		goto out;
	}

	if (data->rnw == WRITE_EXTENT)
		ret = bankshot2_xip_file_write(bs2_dev, data, pi,
						&actual_length);
	else
		ret = bankshot2_xip_file_read(bs2_dev, data, pi,
						&actual_length);

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
	bs2_dbg("bankshot2 cache data: file %d, offset 0x%llx, "
		"request len %lu, mmap offset 0x%llx, mmaped len %lu, "
		"mmap_addr %lx, actual offset 0x%llx, actual length %lu\n",
		data->file, data->offset, data->size,
		data->mmap_offset, data->mmap_length,
		data->mmap_addr, data->actual_offset, data->actual_length);

	copy_to_user(arg, data, sizeof(struct bankshot2_cache_data));

	bs2_dbg("%s: return %d\n", __func__, ret);
	return ret;
}

int bankshot2_ioctl_get_cache_inode(struct bankshot2_device *bs2_dev, void *arg)
{
	struct bankshot2_cache_data _data, *data;
	int ret;
	u64 st_ino;
	struct inode *inode;

	data = &_data;

	ret = bankshot2_get_backing_inode(bs2_dev, arg, &inode);
	if (ret) {
		bs2_dbg("Get extent returned %d\n", ret);
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	//FIXME: need a lock here

	data->inode = inode;
	ret = bankshot2_find_cache_inode(bs2_dev, data, &st_ino);
	if (ret) {
		bs2_info("No cache inode found, returned %d\n", ret);
		return ret;
	}

	copy_to_user(arg, data, sizeof(struct bankshot2_cache_data));

	bs2_dbg("Cache ino %llu, ret %d\n", data->cache_ino, ret);
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
