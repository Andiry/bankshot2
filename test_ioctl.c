#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>

#include "kernel/bankshot2_cache.h"

int main(void)
{
	int fd, fd1, fd2;
	unsigned long a = 1, b = 4;
	struct bankshot2_cache_data data;
	struct bankshot2_mmap_request mmap;
	int rnw = 1;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	data.file = fd1;
	data.offset = 1024000000;
	data.size = 8192;
	data.rnw = READ_EXTENT;
	data.read = (rnw == READ_EXTENT);
	data.write = (rnw == WRITE_EXTENT);

	mmap.fd = fd1;
	mmap.addr = NULL;
	mmap.length = 4096;
	mmap.prot = PROT_WRITE;
	mmap.flags = MAP_SHARED;
	mmap.offset = 0;

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);
	printf("fds: %d %d\n", fd1, fd);
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	fd2 = open("/dev/bankshot2Block0", O_RDWR);
	printf("fds: %d %d %d\n", fd1, fd, fd2);
	ioctl(fd2, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &a);
	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &b);

	ioctl(fd, BANKSHOT2_IOCTL_MMAP_REQUEST, &mmap);
	close(fd);
	close(fd1);
	close(fd2);

	return 0;
}
