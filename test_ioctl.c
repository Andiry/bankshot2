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
	struct bankshot2_mmap_request mmap1;
	void *addr;
	int rnw = 1;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	data.file = fd1;
	data.offset = 1024000000;
	data.size = 8192;
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
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	fd2 = open("/dev/bankshot2Block0", O_RDWR);
	printf("fds: %d %d %d\n", fd1, fd, fd2);
	ioctl(fd2, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &a);
	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &b);

	addr = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd1, 0);
	printf("mmap addr: %p\n", addr);
	munmap(addr, 4096);
	ioctl(fd, BANKSHOT2_IOCTL_MMAP_REQUEST, &mmap1);
	close(fd);
	close(fd1);
	close(fd2);

	return 0;
}
