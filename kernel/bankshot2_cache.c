/*
 * Cache code.
 * Copied from bee3_cache.c
 */

#include "bankshot2.h"
#include "bankshot2_cache.h"

static int bankshot2_get_extent(struct bankshot2_device *bs2_dev, void *arg,
					u64 *st_ino)
{
	struct file *fileinfo;
	struct inode *inode;
	struct bankshot2_cache_data *data;
	int ret;

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

	if (S_ISREG(inode->i_mode)) {
		struct fiemap_extent_info fieinfo = {0,};
		fieinfo.fi_flags = FIEMAP_FLAG_SYNC;
		fieinfo.fi_extents_max = 1;
		fieinfo.fi_extents_start = &data->extent_start_file_offset;

		bs2_dbg("Datected normal file, try fiemap\n");
		if (!inode->i_op->fiemap) {
			fput(fileinfo);
			bs2_info("file system does not support fiemap.\n");
			return -EINVAL;
		}

		data->file_length = i_size_read(inode);
		bs2_dbg("File length: %llu\n", data->file_length);

		if (data->offset >= data->file_length) {
			bs2_dbg("File offset >= file length: %llu %llu\n", data->offset,
					data->file_length);
			//FIXME: set extents
		} else {
			filemap_write_and_wait(inode->i_mapping);
			ret = inode->i_op->fiemap(inode, &fieinfo, data->offset / 512 * 512,
						data->file_length - data->offset / 512 * 512);
			bs2_dbg("Extent fiemap return %d extents, ret %d\n",
					fieinfo.fi_extents_mapped, ret);
			if (fieinfo.fi_extents_mapped == 0) {
				//FIXME
			} else {
				bs2_dbg("Extent: PhyStart: 0x%llx, len: 0x%lx, LogStart: 0x%llx\n",
						data->extent_start, data->extent_length,
						data->extent_start_file_offset);
			}
		}
	} else {
		bs2_dbg("Raw device.\n");
		//FIXME
	}

	data->read = data->write = 0;
	if (fileinfo->f_mode & FMODE_READ)
		data->read = 1;
	if (fileinfo->f_mode & FMODE_WRITE)
		data->write = 1;

	//we should invalidate the inode's buffer-cache mappings as well, so we don't get invalid data later
	if (inode->i_mapping){
		invalidate_inode_pages2(inode->i_mapping);
		truncate_inode_pages(inode->i_mapping, 0);
		filemap_write_and_wait(inode->i_mapping);
	}
	truncate_inode_pages(&inode->i_data, 0);
	filemap_write_and_wait(&inode->i_data);
	if (unlikely(inode->i_mapping->nrpages || inode->i_data.nrpages))
		bs2_info("Still has dirty pages %lu %lu\n",
			inode->i_mapping->nrpages, inode->i_data.nrpages);

	fput(fileinfo);
	*st_ino = inode->i_ino;
	bs2_dbg("Inode %llu permissions: Read %d Write %d\n", *st_ino,
			data->read, data->write);

	if (data->rnw == READ_EXTENT && !data->read) {
		bs2_info("Request want to read but no read permission!\n");
		ret = -EINVAL;
	} else if (data->rnw == WRITE_EXTENT && !data->write) {
		bs2_info("Request want to write but no write permission!\n");
		ret = -EINVAL;
	}

	return 0;

}

static int bankshot2_lookup_key(void)
{
	return 0;
}

/* Copied from do_xip_mapping_read(), filemap_xip.c */
static int bankshot2_find_or_alloc_extents(struct bankshot2_device *bs2_dev,
		u64 st_ino, struct bankshot2_cache_data *data, int create)
{
	struct bankshot2_inode *pi;
	pgoff_t index;
	u64 offset;
	size_t size;
	int ret;

	pi = bankshot2_get_inode(bs2_dev, st_ino);

	if (!pi) {
		bs2_info("pi %llu invalid!\n", st_ino);
		return -EINVAL;
	}

	if (!create && (!pi->root || pi->i_size == 0)) {
		bs2_info("pi %llu is empty\n", st_ino);
		return -EINVAL;
	}

	index = data->offset >> PAGE_SHIFT;
	offset = data->offset & (PAGE_SIZE - 1);

	size = data->size + offset;

	while (size) {
		void *xip_mem;
		unsigned long xip_pfn;
		unsigned long nr;

		nr = PAGE_SIZE;
		if (nr > size)
			nr = size;

		ret = bankshot2_get_xip_mem(bs2_dev, pi, index, create,
						&xip_mem, &xip_pfn);
		if (ret) {
			bs2_info("bankshot2_get_xip_mem returns %d, "
				"inode %llu, index %lu, offset %llu, "
				"size %lu\n",
				ret, st_ino, index, offset, nr);
			break;
		}
		bs2_info("%s: inode %llu, index %lu, offset %llu, size %lu, "
				"mem %p, pfn %lu\n",
				__func__, st_ino, index, 
				offset, nr, xip_mem, xip_pfn);

		offset += nr;
		size -= nr;
		index += offset >> PAGE_SHIFT;
		offset &= (PAGE_SIZE - 1);
	}

	if (create && PAGE_SIZE * index > pi->i_size)
		bankshot2_update_isize(pi, PAGE_SIZE * index);

	return 0;
}

int bankshot2_ioctl_cache_data(struct bankshot2_device *bs2_dev, void *arg)
{
	struct bankshot2_cache_data _data, *data;
	int ret;
	u64 st_ino;

	data = &_data;

	ret = bankshot2_get_extent(bs2_dev, arg, &st_ino);
	if (ret) {
		bs2_info("Get extent returned %d\n", ret);
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	//FIXME: need a lock here

	ret = bankshot2_lookup_key();
	st_ino = 1;
	bankshot2_find_or_alloc_extents(bs2_dev, st_ino, data, 1);

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
