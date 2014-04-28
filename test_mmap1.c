#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>

#include "kernel/bankshot2_cache.h"

int main(void)
{
	int fd, fd1;
	struct bankshot2_cache_data data;
	struct bankshot2_mmap_request mmap1;
	void *addr;
	int rnw = 1;
	char *buf;
	int i;

	buf = malloc(4096);
	memset(buf, 'c', 4096);

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	fd = open("/dev/bankshot2Ctrl0", O_RDWR);

	mmap1.fd = fd1;
	mmap1.addr = NULL;
	mmap1.length = 4096;
	mmap1.prot = PROT_WRITE;
	mmap1.flags = MAP_SHARED;
	mmap1.offset = 0;

//	addr = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd1, 0);
	ioctl(fd, BANKSHOT2_IOCTL_MMAP_REQUEST, &mmap1);
	addr = (void *)mmap1.mmap_addr;

	printf("mmap addr: \t%p\n", addr);
	memset(buf, 'c', 4096);
	memcpy(addr, buf, 4096);
	mmap1.addr = addr;
	mmap1.length = 4096;
//	munmap(addr, 4096);
//	ioctl(fd, BANKSHOT2_IOCTL_MUNMAP_REQUEST, &mmap1);

	for (i = 0; i < 10; i++) {
		sleep(1);
		printf("memcpy to addr: \t%p\n", addr);
//	sleep(10);
		memcpy(buf, addr, 4096);
	}

	return 0;

	data.file = fd1;
	data.offset = 0;
	data.size = 4096;
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
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);
	printf("cache inode: %llu\n", data.cache_ino);
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	return 0;
	addr = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd1, 0);
	printf("mmap addr: \t%p\n", addr);
	memset(buf, 'c', 4096);
	memcpy(addr, buf, 4096);
	munmap(addr, 4096);

	ioctl(fd, BANKSHOT2_IOCTL_MMAP_REQUEST, &mmap1);
	addr = (void *)mmap1.mmap_addr;
	printf("mmap1 addr: \t%p\n", addr);

	memset(buf, 'd', 4096);
	memcpy(addr, buf, 4096);

	munmap(addr, 4096);

	ioctl(fd, BANKSHOT2_IOCTL_MMAP_REQUEST, &mmap1);
	addr = (void *)mmap1.mmap_addr;
	printf("mmap1 addr: \t%p\n", addr);

	write(fd1, addr, 4096);

	munmap(addr, 4096);
	close(fd);
	close(fd1);
	free(buf);

	return 0;
}
