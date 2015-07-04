#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <malloc.h>

int main(int argc, char **argv)
{
	struct statfs buf;

	statfs("/mnt/ramdisk/", &buf);

	printf("Type: 0x%lx\n", buf.f_type);
	printf("bsize: %lu\n", buf.f_bsize);
	printf("Total blocks: %lu\n", buf.f_blocks);
	printf("Free blocks: %lu\n", buf.f_bfree);
	printf("Available blocks: %lu\n", buf.f_bavail);
	printf("Total file nodes: %lu\n", buf.f_files);
	printf("Free file nodes: %lu\n", buf.f_ffree);
	printf("File system id: %lu\n", buf.f_fsid);
	printf("Maximum file namelen: %lu\n", buf.f_namelen);
	printf("Fragment size: %lu\n", buf.f_frsize);

	return 0;
}
