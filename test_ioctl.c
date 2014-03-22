#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "kernel/bankshot2_cache.h"

int main(void)
{
	int fd, fd1, fd2;
	unsigned long a = 1, b = 4;
	struct bankshot2_cache_data data;
	int rnw = 1;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	data.file = fd1;
	data.offset = 102400;
	data.size = 8192;
	data.rnw = READ_EXTENT;
	data.read = (rnw == READ_EXTENT);
	data.write = (rnw == WRITE_EXTENT);

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);
	printf("fds: %d %d\n", fd1, fd);
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	fd2 = open("/dev/bankshot2Block0", O_RDWR);
	printf("fds: %d %d %d\n", fd1, fd, fd2);
	ioctl(fd2, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &a);
	ioctl(fd, BANKSHOT2_IOCTL_SHOW_INODE_INFO, &b);

	close(fd);
	close(fd1);
	close(fd2);

	return 0;
}
