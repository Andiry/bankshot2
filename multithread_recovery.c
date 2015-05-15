#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <time.h>

#define PMFS_TEST_MULTITHREAD_RECOVERY	0xBCD00017

struct malloc_request {
	int category;
	int size;
};

int main(int argc, char *argv[])
{
	int fd1;
	struct malloc_request req;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);

	ioctl(fd1, PMFS_TEST_MULTITHREAD_RECOVERY, &req);

	close(fd1);

	return 0;
}
