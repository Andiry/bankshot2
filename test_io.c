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
	char *addr;
	int rnw = 1;
	char *buf, *buf1;;

	buf = malloc(4096);
	memset(buf, 'c', 4096);
	buf1 = malloc(4096);
//	memset(buf1, 'd', 4096);

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	data.file = fd1;
	data.offset = 0;
	data.size = 4096;
	data.cache_ino = 0;
	data.rnw = READ_EXTENT;
	data.read = (rnw == READ_EXTENT);
	data.write = (rnw == WRITE_EXTENT);
	data.buf = buf1;

	mmap1.fd = fd1;
	mmap1.addr = NULL;
	mmap1.length = 4096;
	mmap1.prot = PROT_WRITE;
	mmap1.flags = MAP_SHARED;
	mmap1.offset = 0;

	printf("Posix write to file: %c\n", buf[0]);
	pwrite(fd1, buf, 4096, 0);

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);
	printf("fds: %d %d\n", fd1, fd);
	ioctl(fd, BANKSHOT2_IOCTL_GET_INODE, &data);
	printf("cache ino: %lu\n", data.cache_ino);
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);
	printf("Read from cache: %c %c\n", data.buf[0], data.buf[4095]);

	ioctl(fd, BANKSHOT2_IOCTL_MMAP_REQUEST, &mmap1);
	addr = (char *)mmap1.mmap_addr;
	printf("mmap addr: %p\n", addr);
	memset(addr, 'd', 4096);
	munmap(addr, 4096);

	memset(buf1, 'e', 4096);
	data.rnw = WRITE_EXTENT;
	data.read = (rnw == READ_EXTENT);
	data.write = (rnw == WRITE_EXTENT);

	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);
	printf("Write to cache: %c %c\n", data.buf[0], data.buf[4095]);

	data.rnw = READ_EXTENT;
	data.read = (rnw == READ_EXTENT);
	data.write = (rnw == WRITE_EXTENT);
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);
	printf("Read from cache: %c %c\n", data.buf[0], data.buf[4095]);

	close(fd);
	close(fd1);
	free(buf);
	free(buf1);
//	munmap(addr, 4096);
	return 0;
#if 0
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
#endif
}
