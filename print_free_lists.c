#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <time.h>

#define PMFS_PRINT_FREE_LISTS	0xBCD00018

int main(int argc, char *argv[])
{
	int fd1;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);

	ioctl(fd1, PMFS_PRINT_FREE_LISTS, &fd1);

	close(fd1);

	return 0;
}
