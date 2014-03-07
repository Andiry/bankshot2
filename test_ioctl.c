#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>

#include "kernel/bankshot2_cache.h"

int main(void)
{
	int fd, fd1;
	int a = 3, b = 4;
	struct bankshot2_cache_data data;
	int rnw;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	data.file = fd1;
	data.offset = 4096;
	data.rnw = READ_EXTENT;
	data.read = (rnw == READ_EXTENT);
	data.write = (rnw == WRITE_EXTENT);

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);
	printf("fds: %d %d\n", fd1, fd);
	ioctl(fd, BANKSHOT2_IOCTL_CACHE_DATA, &data);

	close(fd);
	close(fd1);

	return 0;
}
