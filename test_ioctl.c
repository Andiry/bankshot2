#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>

#include "kernel/bankshot2_cache.h"

struct extent_entry {
	off_t offset;
	size_t length;
	int dirty;
	unsigned long mmap_addr;
};

int main(void)
{
	int fd, fd1, fd2;
	unsigned long a = 1, b = 4;
	struct bankshot2_cache_data data;
	struct extent_entry extent;
	off_t offset;
	struct bankshot2_mmap_request mmap1;
	void *addr;
	int rnw = 1;
	int ret = 0;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	data.file = fd1;
//	data.offset = 1024000000;
//	data.size = 8192;
	data.cache_ino = 0;
	data.rnw = READ_EXTENT;
	data.read = (rnw == READ_EXTENT);
	data.write = (rnw == WRITE_EXTENT);

	mmap1.fd = fd1;
	mmap1.addr = NULL;
	mmap1.length = 4096;
	mmap1.prot = PROT_WRITE;
	mmap1.flags = MAP_SHARED;
	mmap1.offset = 0;

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);
	printf("fds: %d %d\n", fd1, fd);
	ret = ioctl(fd, BANKSHOT2_IOCTL_GET_INODE, &data);

	if (ret < 0)
		printf("IOCTL_GET_INODE failed\n");

	printf("Cache inode number: %lu\n", data.cache_ino);

	extent.offset = 0;
	extent.length = 4096;
	extent.dirty = 1;
	extent.mmap_addr = 0x10000;

	ret = ioctl(fd, BANKSHOT2_IOCTL_ADD_EXTENT, &extent);

	extent.offset = 4096;
	extent.length = 4096;
	extent.dirty = 1;
	extent.mmap_addr = 0x11000;

	ret = ioctl(fd, BANKSHOT2_IOCTL_ADD_EXTENT, &extent);

	extent.offset = 8192;
	extent.length = 4096;
	extent.dirty = 1;
	extent.mmap_addr = 0x13000;

	ret = ioctl(fd, BANKSHOT2_IOCTL_ADD_EXTENT, &extent);

	extent.offset = 16384;
	extent.length = 4096;
	extent.dirty = 1;
	extent.mmap_addr = 0x18000;

	ret = ioctl(fd, BANKSHOT2_IOCTL_ADD_EXTENT, &extent);

	offset = 4096;
	ret = ioctl(fd, BANKSHOT2_IOCTL_REMOVE_EXTENT, &offset);
	offset = 4096;
	ret = ioctl(fd, BANKSHOT2_IOCTL_REMOVE_EXTENT, &offset);
	offset = 16387;
	ret = ioctl(fd, BANKSHOT2_IOCTL_REMOVE_EXTENT, &offset);
//	ret = ioctl(fd, BANKSHOT2_IOCTL_REMOVE_EXTENT, &extent);
	return 0;


	fd2 = open("/dev/bankshot2Block0", O_RDWR);
	printf("fds: %d %d %d\n", fd1, fd, fd2);
	ioctl(fd2, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &a);
	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &b);

	addr = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd1, 0);
	printf("mmap addr: \t%p\n", addr);
	munmap(addr, 4096);
	ioctl(fd, BANKSHOT2_IOCTL_MMAP_REQUEST, &mmap1);
	addr = (void *)mmap1.mmap_addr;
	printf("mmap1 addr: \t%p\n", addr);
	munmap(addr, 4096);
	close(fd);
	close(fd1);
	close(fd2);

	return 0;
}
