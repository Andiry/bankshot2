/*
 * Handle Pmem with super block and inode.
 * Copied from PMFS super.c.
 */

#include "bankshot2.h"

static int bankshot2_ioremap(struct bankshot2_device *bs2_dev,
				unsigned long phys_addr, unsigned long size)
{
	void *ret;

	ret = request_mem_region_exclusive(phys_addr, size, "bankshot2");
	if (!ret)
		return -EINVAL;

	ret = ioremap_cache(phys_addr, size);
	if (!ret)
		return -EINVAL;

	bs2_dev->virt_addr = ret;
	bs2_dev->size = size;
	memset_nt(bs2_dev->virt_addr, 0, size);
	return 0;
}

static void bankshot2_iounmap(struct bankshot2_device *bs2_dev)
{
	iounmap(bs2_dev->virt_addr);
	release_mem_region(bs2_dev->phys_addr, bs2_dev->size);
}

static void bankshot2_init_memblocks(struct bankshot2_device *bs2_dev,
					unsigned long phys_addr)
{
	bs2_dev->block_start = 0;
	bs2_dev->block_end = (bs2_dev->size >> PAGE_SHIFT);
	bs2_dev->num_free_blocks = bs2_dev->block_end;
}

int bankshot2_init_super(struct bankshot2_device *bs2_dev,
			unsigned long phys_addr, unsigned long cache_size)
{
	int ret;
	unsigned long blocksize;
	u64 journal_meta_start, journal_data_start, inode_table_start;
	struct bankshot2_inode *root_i;
	struct bankshot2_super_block *super;
	unsigned long blocknr;

	bs2_dev->jsize = BANKSHOT2_DEFAULT_JOURNAL_SIZE;
	bs2_dev->phys_addr = phys_addr;

	INIT_LIST_HEAD(&bs2_dev->block_inuse_head);
	INIT_LIST_HEAD(&bs2_dev->pi_lru_list);
	bs2_dev->mode = (S_IRUGO | S_IXUGO | S_IWUSR);
	bs2_dev->uid = current_fsuid();
	bs2_dev->gid = current_fsgid();
//	INIT_LIST_HEAD(&bs2_dev->s_truncate);
//	mutex_init(&bs2_dev->s_truncate_lock);
	mutex_init(&bs2_dev->inode_table_mutex);
	mutex_init(&bs2_dev->s_lock);

	bs2_dev->physical_tree = RB_ROOT;
	mutex_init(&bs2_dev->phy_tree_lock);

	ret = bankshot2_ioremap(bs2_dev, phys_addr, cache_size);
	if (ret) {
		bs2_info("Bankshot2 ioremap failed\n");
		return ret;
	}

	bankshot2_init_memblocks(bs2_dev, phys_addr);
	blocksize = bs2_dev->blocksize = PAGE_SIZE;
	bs2_dev->s_blocksize_bits = PAGE_SHIFT;
	/* Make sure enough room for sb, root, inode table and journal */
	if (cache_size < PAGE_SIZE * 3 + bs2_dev->jsize) {
		bs2_info("Not enough space for init\n");
		bankshot2_iounmap(bs2_dev);
		return -EINVAL;
	}

	journal_meta_start = sizeof(struct bankshot2_super_block);
	journal_meta_start = (journal_meta_start + CACHELINE_SIZE - 1) &
		~(CACHELINE_SIZE - 1);
	inode_table_start = journal_meta_start + sizeof(bankshot2_journal_t);
	inode_table_start = (inode_table_start + CACHELINE_SIZE - 1) &
		~(CACHELINE_SIZE - 1);

	if ((inode_table_start + sizeof(struct bankshot2_inode)) >
			BANKSHOT2_SB_SIZE) {
		bs2_info("Bankshot2 super block defined too small. "
				"defined 0x%x, "
				"required 0x%llx\n", BANKSHOT2_SB_SIZE,
			inode_table_start + sizeof(struct bankshot2_inode));
		bankshot2_iounmap(bs2_dev);
		return -EINVAL;
	}

	journal_data_start = BANKSHOT2_SB_SIZE * 2;
	journal_data_start = (journal_data_start + blocksize - 1) &
		~(blocksize - 1);

	bs2_info("journal meta start %llx data start 0x%llx, "
		"journal size 0x%x, inode_table 0x%llx\n", journal_meta_start,
		journal_data_start, bs2_dev->jsize, inode_table_start);

	/* Clear out super-block and inode table */
	super = bankshot2_get_super(bs2_dev);
	memset_nt(super, 0, journal_data_start);
	super->s_size = cpu_to_le64(cache_size);
	super->s_blocksize = cpu_to_le32(blocksize);
	super->s_magic = cpu_to_le16(BANKSHOT2_SUPER_MAGIC);
	super->s_journal_offset = cpu_to_le64(journal_meta_start);
	super->s_inode_table_offset = cpu_to_le64(inode_table_start);

	ret = bankshot2_init_blockmap(bs2_dev,
					journal_data_start + bs2_dev->jsize);

	if (ret) {
		bs2_info("blockmap init failed\n");
		bankshot2_iounmap(bs2_dev);
		return ret;
	}

/* FIXME: ignore journal part
	if (bankshot2_journal_hard_init(bs2_dev, journal_data_start,
			bs2_dev->jsize) < 0) {
		bs2_info("Journal hard initialization failed\n");
		return -EINVAL;
	}
*/

	if (bankshot2_init_inode_table(bs2_dev) < 0) {
		bs2_info("Inode table init failed\n");
		bankshot2_iounmap(bs2_dev);
		return -EINVAL;
	}

	bankshot2_flush_buffer(super, BANKSHOT2_SB_SIZE, false);
	bankshot2_flush_buffer((char *)super + BANKSHOT2_SB_SIZE,
				sizeof(*super), false);

	bankshot2_new_block(bs2_dev, &blocknr, BANKSHOT2_BLOCK_TYPE_4K, 1);

	root_i = bankshot2_get_inode(bs2_dev, BANKSHOT2_ROOT_INO);
	if (!root_i) {
		bs2_info("Get root_i failed\n");
		bankshot2_iounmap(bs2_dev);
		return -EINVAL;
	}

	root_i->i_mode = cpu_to_le16(bs2_dev->mode | S_IFDIR);
	root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, bs2_dev->uid));
	root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, bs2_dev->gid));
	root_i->i_links_count = cpu_to_le16(2);
	root_i->i_blk_type = BANKSHOT2_BLOCK_TYPE_4K;
	root_i->i_flags = 0;
	root_i->i_blocks = cpu_to_le64(1);
	root_i->start_index = ULONG_MAX;
	root_i->i_size = cpu_to_le64(super->s_blocksize);
	root_i->i_atime = root_i->i_mtime = root_i->i_ctime =
		cpu_to_le32(get_seconds());
	root_i->root = cpu_to_le64(bankshot2_get_block_off(bs2_dev, blocknr,
					BANKSHOT2_BLOCK_TYPE_4K));
	root_i->height = 0;
	root_i->i_ino = BANKSHOT2_ROOT_INO;
	root_i->extent_tree = RB_ROOT;
	root_i->access_tree = RB_ROOT;
	init_waitqueue_head(&root_i->wait_queue);
//	root_i->extent_tree_lock = __RW_LOCK_UNLOCKED(extent_tree_lock);
	mutex_init(&root_i->tree_lock);
	INIT_LIST_HEAD(&root_i->lru_list);

	/* bankshot2_sync_inode(root_i); */
	bankshot2_flush_buffer(root_i, sizeof(*root_i), false);

	bs2_info("Bankshot2 super block initialized, cache start at %ld, "
			"size %ld, remap @%p, block start 0x%lx, "
			"block end 0x%lx, free blocks %ld\n",
			bs2_dev->phys_addr, bs2_dev->size, bs2_dev->virt_addr,
			bs2_dev->block_start, bs2_dev->block_end,
			bs2_dev->num_free_blocks);

	return ret;
}
	
void bankshot2_destroy_super(struct bankshot2_device *bs2_dev)
{
	bankshot2_iounmap(bs2_dev);
}
