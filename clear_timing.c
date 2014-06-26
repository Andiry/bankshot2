#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>

#include "kernel/bankshot2_cache.h"

int main(void)
{
	int fd;

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);

	ioctl(fd, BANKSHOT2_IOCTL_CLEAR_TIMING, &fd);

	close(fd);

	return 0;
}
