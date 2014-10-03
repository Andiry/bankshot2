/* Shared by kernel and user space */

#define READ_EXTENT	0
#define WRITE_EXTENT	1

/* get extent return value */
#define	EOF_OR_HOLE	3

/* Default mmap size : 4096 */
#define MMAP_UNIT	PAGE_SIZE
#define MAX_MMAP_SIZE	2097152

#define ALIGN_DOWN(addr) ((addr) & ~(MMAP_UNIT - 1))
#define ALIGN_UP(addr) (((addr) & (MMAP_UNIT - 1)) ? \
		(ALIGN_DOWN(addr + MMAP_UNIT)) : (addr))

#define ALIGN_DOWN_MMAP(addr) ((addr) & ~(MAX_MMAP_SIZE - 1))
#define ALIGN_UP_MMAP(addr) (((addr) & (MAX_MMAP_SIZE - 1)) ? \
		(ALIGN_DOWN_2MB(addr + MAX_MMAP_SIZE)) : (addr))

struct bankshot2_mmap_request {
	void*	addr;
	size_t	length;
	int	prot;
	int	flags;
	int	fd;
	off_t	offset;
	unsigned long mmap_addr; // returned mmap address
};

struct bankshot2_cache_data{
	int file;
	uint64_t cache_ino; //Inode number in cache
	uint64_t offset; //file offset in bytes
	uint64_t mmap_offset; //Mmap offset, align to 2MB
	uint64_t actual_offset; //Actual offset, either offset or mmap_offset
	size_t size; //request size in bytes
	size_t mmap_length; //mmap length, must be multiply of 2MB
	size_t actual_length; //Actual transferred length, start from actual_offset
	size_t cache_file_size;
	uint8_t rnw;
	char *buf;
	char *carrier;	// Carry data between backing store and cache
	struct inode *inode;
	//return values
	size_t chunk_len;
	uint64_t file_length; //total file length in bytes
	int read;
	int write;
	int datasync;
	unsigned long required;
	unsigned long mmap_addr; // returned mmap address
	/* -=-=-= These Entries Must Match struct fiemap_extent -=-=-=- */
	struct fiemap_extent *extent;
	uint64_t extent_start_file_offset; //file offset at which this extent starts (in bytes)
	uint64_t extent_start; //starting byte address of this extent
	size_t extent_length; //number of bytes that this extent spans
//	uint64_t reserved64[2];
//	uint32_t fe_flags;
//	uint32_t reserved32[3];
	/* -=-=-= End Match Requirement -=-=-= */
};

/* ioctls */
#define BANKSHOT2_IOCTL_CACHE_DATA	0xBCD00000
#define BANKSHOT2_IOCTL_SHOW_INODE_INFO	0xBCD00001
#define BANKSHOT2_IOCTL_MMAP_REQUEST	0xBCD00002
#define BANKSHOT2_IOCTL_GET_INODE	0xBCD00003
#define BANKSHOT2_IOCTL_ADD_EXTENT	0xBCD00004
#define BANKSHOT2_IOCTL_REMOVE_EXTENT	0xBCD00005
#define BANKSHOT2_IOCTL_FREE_BLOCKS	0xBCD00006
#define BANKSHOT2_IOCTL_MUNMAP_REQUEST	0xBCD00007
#define BANKSHOT2_IOCTL_REMOVE_MAPPING	0xBCD00008
#define BANKSHOT2_IOCTL_CLEAR_CACHE	0xBCD00009
#define BANKSHOT2_IOCTL_GET_CACHE_INFO	0xBCD0000A
#define BANKSHOT2_IOCTL_CLEAR_TIMING	0xBCD0000B
#define BANKSHOT2_IOCTL_GET_DIRTY_INFO	0xBCD0000C
#define BANKSHOT2_IOCTL_FSYNC_TO_BS	0xBCD0000D
#define BANKSHOT2_IOCTL_EVICT_INODE	0xBCD0000E
