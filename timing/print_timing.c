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

int main(int argc, char **argv)
{
	int fd;
	int print_dirty = 0;

	fd = open("/mnt/ramdisk/test1", O_RDWR);

	ioctl(fd, PMFS_PRINT_TIMING, &print_dirty);

	close(fd);

	return 0;
}
