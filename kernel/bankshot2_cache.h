/* Shared by kernel and user space */

#define READ_EXTENT	1
#define WRITE_EXTENT	1

struct bankshot2_cache_data{
	int file;
	uint64_t offset; //file offset in bytes
	uint8_t rnw;
	char *buf;
	//return values
	size_t chunk_len;
	uint64_t file_length; //total file length in bytes
	int read;
	int write;
	/* -=-=-= These Entries Must Match struct fiemap_extent -=-=-=- */
	uint64_t extent_start_file_offset; //file offset at which this extent starts (in bytes)
	uint64_t extent_start; //starting byte address of this extent
	size_t extent_length; //number of bytes that this extent spans
	uint64_t reserved64[2];
	uint32_t fe_flags;
	uint32_t reserved32[3];
	/* -=-=-= End Match Requirement -=-=-= */
};

/* ioctls */
#define BANKSHOT2_IOCTL_CACHE_DATA	0xBCD00000

