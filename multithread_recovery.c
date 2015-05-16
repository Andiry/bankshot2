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
	int multithread;
	struct timespec start, end;

	if (argc < 2) {
		printf("Usage: ./multithread_recovery $MULTITHREAD\n");
		return 0;
	}

	multithread = atoi(argv[1]);

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);

	clock_gettime(CLOCK_MONOTONIC, &start);
	ioctl(fd1, PMFS_TEST_MULTITHREAD_RECOVERY, &multithread);
	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("%s recovery time: %lu\n",
		multithread ?	"Multithread" : "Singlethread",
		1e9 * (end.tv_sec - start.tv_sec) +
		end.tv_nsec - start.tv_nsec);

	close(fd1);

	return 0;
}
