#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>

#include "kernel/bankshot2_cache.h"

int main(int argc, char **argv)
{
	int fd;
	int print_dirty = 0;

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);

	if (argc > 1)
		print_dirty = 1;

	ioctl(fd, BANKSHOT2_IOCTL_GET_CACHE_INFO, &print_dirty);

	close(fd);

	return 0;
}
