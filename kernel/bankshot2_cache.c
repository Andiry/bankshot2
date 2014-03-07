#include "bankshot2.h"
#include "bankshot2_cache.h"

static int bankshot2_get_extent(struct bankshot2_device *bs2_dev, void *arg,
					unsigned long *st_ino)
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
	bs2_dbg("Inode %lu permissions: Read %d Write %d\n", *st_ino, data->read,
								data->write);

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

int bankshot2_ioctl_cache_data(struct bankshot2_device *bs2_dev, void *arg)
{
	struct bankshot2_cache_data _data, *data;
	int ret;
	unsigned long st_ino;

	data = &_data;

	ret = bankshot2_get_extent(bs2_dev, arg, &st_ino);
	if (ret) {
		bs2_info("Get extent returned %d\n", ret);
		return ret;
	}

	copy_from_user(data, arg, sizeof(struct bankshot2_cache_data));

	//FIXME: need a lock here

	ret = bankshot2_lookup_key();

	return ret;

}
