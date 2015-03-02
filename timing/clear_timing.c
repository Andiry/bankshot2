#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>

#define	PMFS_PRINT_TIMING	0xBCD00010
#define	PMFS_CLEAR_STATS	0xBCD00011

int main(void)
{
	int fd;

	fd = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);

	ioctl(fd, PMFS_CLEAR_STATS, &fd);

	close(fd);

	return 0;
}
