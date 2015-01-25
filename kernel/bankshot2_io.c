/*
 * Handle IO requests.
 * Copied from bee3cache_io2.c.
 */

#include "bankshot2.h"

inline void set_job_status(struct job_descriptor *job, uint8_t flag) 
{
	uint8_t res = atomic_read(&job->status);
	atomic_set(&job->status, res|flag); 
}

inline bool verify_job_status(struct job_descriptor *job, uint8_t flag) {
	bool res;
	res = !!(atomic_read(&job->status) & flag); 
	return res;
}
  
inline void clear_job_status(struct job_descriptor *job) {
	atomic_set(&job->status, 0); 
}

inline uint8_t get_job_status(struct job_descriptor *job) {
	return atomic_read(&job->status);
}

void free_job(struct bankshot2_device *bs2_dev,
		struct job_descriptor *jd, struct list_head *idx)
{
	struct bio_vec *bv;
	int j;
	//if(jd->job_parent != current)
	//	return;
	bio_for_each_segment(bv, jd->bio, j){
		if(!bv->bv_page)
			break;
		__free_page(bv->bv_page);
	}
	if(idx)
		list_del(idx);

	bio_put(jd->bio);			
	kmem_cache_free(bs2_dev->job_descriptor_slab, jd);
}

static void bankshot2_job_bio_destructor(struct bio *bio)
{
	struct job_descriptor *jd = (struct job_descriptor *) (bio->bi_private);
	if (jd) {
		struct bankshot2_device *bs2_dev =
			(struct bankshot2_device *) jd->bs2_dev;
		bio_put(bio);
		kmem_cache_free(bs2_dev->job_descriptor_slab, jd);
	}
}

static void bankshot2_cache_io_callback(struct bio *bio, int error)
{
	struct job_descriptor *jd = (struct job_descriptor*) bio->bi_private;
	struct bankshot2_device *bs2_dev;

	if(!jd)
	{
		//unkown bio 
		bs2_info("bankshot2_cache_io_callback called with NULL job\n");
		bio_put(bio);
		return;
	}
	bs2_dev = jd->bs2_dev;

	if(!test_bit(BIO_UPTODATE, &bio->bi_flags)) {
		//BEE3_DEBUG("Test bio bit shows error %llu %d %lu", bio->bi_sector, jd->target, bio->bi_size );
		set_job_status(jd, STATUS(JOB_ERROR));
	}
//	decrement_io_limit(jd);
	switch(jd->type){
		case WAKEUP_ON_COMPLETION:
			/* Data transfer completed. Pure read/write from disk or cache */
			clear_job_status(jd);
			set_job_status(jd, STATUS(JOB_DONE));
			if(jd->job_parent)
				wake_up_process(jd->job_parent);
			break;
		
		case DO_COMPLETION:
			set_job_status(jd, STATUS(JOB_DONE));
			break;
		case FREE_ON_COMPLETION:
			//the job was for disk. We just free up the job 
			atomic_dec(&bs2_dev->cache_stats.sync_queued_count);
			free_job(bs2_dev, jd, NULL);
			break;
		case SYS_BIO:
			/* System bio parital complete. Destroy the job descriptor and free bio */				
			if(error)
				clear_bit(BIO_UPTODATE, &jd->sys_bio->bi_flags);
			else if(!test_bit(BIO_UPTODATE, &jd->sys_bio->bi_flags))
				error = -EIO;
			if(error)
				bs2_dbg("Sys bio had error\n");
			bankshot2_job_bio_destructor(bio);
			break;
		case SYS_BIO_LAST:
			if(error)
				clear_bit(BIO_UPTODATE, &jd->sys_bio->bi_flags);
			else if(!test_bit(BIO_UPTODATE, &jd->sys_bio->bi_flags))
				error = -EIO;
			if(error)
				bs2_dbg("Sys bio had error\n");
			if(jd->sys_bio->bi_end_io)
				jd->sys_bio->bi_end_io(jd->sys_bio, error);
			bio_put(jd->sys_bio);
			bankshot2_job_bio_destructor(bio);	
			break;
		default:
			bs2_info("Unkown job type %u\n", (unsigned int) jd->type);
			set_job_status(jd, STATUS(JOB_DONE));
			if(jd->job_parent)
				wake_up_process(jd->job_parent);
			break;	
	}	
}

static inline void init_job_descriptor(struct job_descriptor *jd, JOB_TYPE type,
			size_t done, uint64_t b_offset)
{
	if(jd->bio){
		jd->bio->bi_size = done; 
		jd->bio->bi_private = jd; 
		jd->bio->bi_end_io = bankshot2_cache_io_callback;
	}
	jd->b_offset = b_offset; 
//	jd->c_offset = c_offset; 
	jd->num_bytes = done; 
	jd->job_parent = current;
	clear_job_status(jd); 
	jd->type = type; 
}

int bankshot2_init_job_queue(struct bankshot2_device *bs2_dev)
{
	bs2_dev->bio_set = bioset_create(512, 0);
	if(!bs2_dev->bio_set)
	{
		bs2_info("Failed to create bio set for job descriptor bios\n");
		return -EINVAL;
	}

	bs2_dev->job_descriptor_slab = kmem_cache_create("job_descriptor_slab",
				sizeof(struct job_descriptor), 0, 0, NULL);
	if(!bs2_dev->job_descriptor_slab)
	{
		bs2_info("Failed to allocate job descriptor\n");
		bioset_free(bs2_dev->bio_set);
		return -EINVAL;
	}	
	atomic_set(&bs2_dev->io_limit,0);
	INIT_LIST_HEAD(&bs2_dev->disk_queue);
	INIT_LIST_HEAD(&bs2_dev->cache_queue);
	spin_lock_init(&bs2_dev->io_queue_lock);
	return 0;
}

void bankshot2_destroy_job_queue(struct bankshot2_device *bs2_dev)
{
	while (atomic_read(&bs2_dev->cache_stats.sync_queued_count) != 0)
	{
		schedule_timeout(usecs_to_jiffies(1000));
		set_current_state(TASK_INTERRUPTIBLE);
	}

	if(bs2_dev->bio_set)
		bioset_free(bs2_dev->bio_set);
	if(bs2_dev->job_descriptor_slab)
		kmem_cache_destroy(bs2_dev->job_descriptor_slab);
	bs2_info("%s returns.\n", __func__);
	/* Iterate through the list and destroy jobs */
}

/*Allocates a job descriptor and adds to the list */
struct job_descriptor*
bankshot2_alloc_job_descriptor(struct bankshot2_device *bs2_dev,
			size_t bio_pages, struct job_descriptor *jd)
{
	struct job_descriptor *job;
//	timing_t timing;

//	BBD_START_TIMING(BBD, memory_alloc, timing); 	
	job = (struct job_descriptor*)
		kmem_cache_alloc(bs2_dev->job_descriptor_slab, GFP_KERNEL);
	if (!job)
	{
		bs2_info("failed to allocate job descriptor\n");
		return NULL;
	}
	if (bio_pages)
	{
		job->bio = bio_alloc_bioset(GFP_KERNEL, bio_pages, bs2_dev->bio_set);
//		BBD_END_TIMING(BBD, memory_alloc, timing); 	
		if (!job->bio)
		{
			bs2_info("Failed to allocate bio in copy to cache\n");
			return NULL;
		}
		bio_get(job->bio);
		job->bio->bi_size = (bio_pages >> PAGE_SHIFT) ;
	} else {
		job->bio = NULL;
	}

	INIT_LIST_HEAD(&job->jobs);
	INIT_LIST_HEAD(&job->store_queue);
	job->bs2_dev = bs2_dev;

	if (jd)
	{
		list_add_tail(&job->jobs, &jd->jobs);	//track the jobs we are submitting
	}

	return job;
}

static inline size_t align_offset_and_len(uint64_t *b_offset, size_t *b_len)
{
	*b_offset = *b_offset - ( ( (uint64_t)(*b_offset) ) & (PAGE_SIZE - 1) );
	*b_len  = *b_len + ( ( (uint64_t) (*b_offset) ) & (PAGE_SIZE - 1) );
	*b_len = PAGE_ALIGN((size_t) (*b_len));
	return *b_len >> PAGE_SHIFT;
}

size_t add_pages_to_job_bio(struct bankshot2_device *bs2_dev,
			struct bio *bio, size_t nr_pages)
{
	struct page *page;
	size_t done = 0;

	while (done < nr_pages){
//		BBD_START_TIMING(BBD, memory_alloc, timing);
		page = alloc_page(GFP_KERNEL);
//		page = pfn_to_page(xpfn);
//		BBD_END_TIMING(BBD, memory_alloc, timing); 	
		if(!page)
			break;

		if(bio_add_page(bio, page, PAGE_SIZE, 0) != PAGE_SIZE)
		{
			__free_page(page);
			break;
		}
		done++;
	}

	if (done != nr_pages)
		bs2_info("%s wants to add %lu pages but done %lu\n",
				__func__, nr_pages, done);
	return done;
}

void bankshot2_add_to_disk_list(struct bankshot2_device *bs2_dev,
			struct job_descriptor *jd, struct list_head *head)
{
	set_job_status(jd, STATUS(JOB_QUEUED_TO_DISK));
	set_job_status(jd, STATUS(JOB_ISSUED_TO_DISK));
//	disk_rate_limit(jd);
	//	if(current->io_context){
	//		if(current->io_context->ioprio == IOPRIO_CLASS_NONE)
	//			set_task_ioprio(current, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, SYNC_IOPRIO));
	//	}
	//	else{
	//		current->io_context = get_io_context(GFP_KERNEL, -1); 
	//		if(!current->io_context) 
	//		{
	//			BEE3_INFO("Failed to allocate io context");
	//			return; 
	//		}
	//		set_task_ioprio(current, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, SYNC_IOPRIO));	
	//	}	

		//atomic64_set(&bs2_dev->last_offset, jd->bio->bi_sector * 512);
		//BEE3_INFO("Bio to disk %lu %u %x %x", jd->bio->bi_sector, jd->bio->bi_size, jd->disk_cmd, jd->type);
	submit_bio(jd->disk_cmd, jd->bio);	
}

int bankshot2_submit_to_cache(struct bankshot2_device *bs2_dev, struct job_descriptor *jd,
				bool end, int read, size_t transferred, char* void_array)
{
	struct bankshot2_inode *pi;
	struct bio *bio = jd->bio;
	struct bio_vec *bvec;
	unsigned int i;
	char *buf;
	unsigned long index;
	int array_index;
	u64 block;
	void *xmem;

	/* get the file offset and index */
	pi = jd->inode;
	array_index = (jd->job_offset - jd->start_offset) >> PAGE_SHIFT;
	index = jd->job_offset >> bs2_dev->s_blocksize_bits;

	bio_for_each_segment(bvec, bio, i) {
		if (void_array[array_index] == 0x1) {
			block = bankshot2_find_data_block(bs2_dev, pi, index);
			if (!block) {
				bs2_info("%s: get block failed, index 0x%lx\n",
						__func__, index);
				bio_endio(bio, 0);
				return -EINVAL;
			}
			xmem = bankshot2_get_block(bs2_dev, block);
			buf = kmap_atomic(bvec->bv_page);
			if (read)
				memcpy(xmem, buf + bvec->bv_offset,
						bvec->bv_len);
			else
				memcpy(buf + bvec->bv_offset, xmem,
						bvec->bv_len);
			kunmap_atomic(buf);
			bankshot2_flush_edge_cachelines(
				index << bs2_dev->s_blocksize_bits,
				PAGE_SIZE, xmem);
		}
		//FIXME: Need to check bv_len and update index
		array_index++;
		index++;
	}

	if (end)
		bio_endio(bio, 0);

	return 0;
}

static void bankshot2_add_to_cache_list(struct bankshot2_device *bs2_dev,
			struct job_descriptor *jd, int read,
			size_t transferred, char* void_array)
{
//	set_job_status(jd, STATUS(JOB_QUEUED_TO_CACHE));
	/* Moneta IO Is always blocking and not possible to have event driven operation */
	set_job_status(jd, STATUS(JOB_ISSUED_TO_CACHE));
//	if(jd->bio->bi_sector > jd->bs2_dev->sector_count)
//		BEE3_INFO("Bio too big for cache %lu %u %x", jd->bio->bi_sector, jd->bio->bi_size, jd->moneta_cmd);
	bankshot2_submit_to_cache(jd->bs2_dev, jd, 1, read, transferred,
					void_array);
}

static void reset_job_bio(struct job_descriptor *jd, sector_t sector,
				struct block_device *bdev, unsigned long op)
{
	jd->bio->bi_sector = sector;
	jd->bio->bi_size = jd->num_bytes;
	jd->bio->bi_bdev = bdev;
	jd->bio->bi_rw = op;
	jd->bio->bi_idx = 0;
	clear_job_status(jd);
}

uint8_t do_cache_fill(struct bankshot2_device *bs2_dev,
			struct job_descriptor *head, spinlock_t *lock,
			size_t transferred, char *void_array)
{
	struct job_descriptor *jd;
	uint8_t result = 0;
	
	list_for_each_entry(jd, &head->jobs, jobs) 
	{
			
		while(true){
			/* Wait on job to complete */
			if(lock)
				spin_lock(lock);	
			if(verify_job_status(jd, STATUS(JOB_DONE)) )// | STATUS(JOB_ERROR) | STATUS(JOB_ABORT)))
			{
				if(lock)
					spin_unlock(lock);
				/*set  in the job list */
				result |= get_job_status(jd);
				break;
			}
			if(lock)
				spin_unlock(lock);
			/*release cpu till job status changes Make sure current task_struct is set*/
			if(!jd->job_parent) 
			{
				/* we sleep */
				msleep(2);
			}else{
				/* Get of the running process list */
				bs2_dbg("Thread put to sleep %x\n",
						get_job_status(jd));
				io_schedule();
				set_current_state(TASK_INTERRUPTIBLE);
			}	
			__set_current_state(TASK_RUNNING);
		}
		reset_job_bio(jd, jd->job_offset >> 9, bs2_dev->bs_bdev, WRITE);
		jd->type = DO_COMPLETION;			
		bankshot2_add_to_cache_list(bs2_dev, jd, 1, transferred,
						void_array);
	}
	return result;
}

uint8_t do_disk_fill(struct bankshot2_device *bs2_dev,
			struct job_descriptor *head, spinlock_t *lock)
{
	struct list_head *i, *temp;
	struct job_descriptor *jd;
	uint8_t result = 0;
	
	list_for_each_safe(i, temp, &head->jobs) 
	{
		jd = list_entry(i, struct job_descriptor, jobs);
		while(true){
			/* Wait on job to complete */
			if(lock)
				spin_lock(lock);	
			if(verify_job_status(jd, STATUS(JOB_DONE)) )// | STATUS(JOB_ERROR) | STATUS(JOB_ABORT)))
			{
				if(lock)
					spin_unlock(lock);
				/*set  in the job list */
				result |= get_job_status(jd);
				break;
			}
			if(lock)
				spin_unlock(lock);
			/*release cpu till job status changes Make sure current task_struct is set*/
			if(!jd->job_parent) 
			{
				/* we sleep */
				msleep(2);
			}else{
				/* Get of the running process list */
				bs2_dbg("Thread put to sleep %x\n",
						get_job_status(jd));
				io_schedule();
				set_current_state(TASK_INTERRUPTIBLE);
			}	
			__set_current_state(TASK_RUNNING);
		}
		reset_job_bio(jd, jd->b_offset >> 9, bs2_dev->bs_bdev,
				jd->disk_cmd);
		jd->type = FREE_ON_COMPLETION;
		list_del(i);
		atomic_inc(&bs2_dev->cache_stats.sync_queued_count);
		bankshot2_add_to_disk_list(bs2_dev, jd, &bs2_dev->disk_queue);
	}
	return result;
}

static void free_jobs_in_list(struct bankshot2_device *bs2_dev,
				struct job_descriptor *head, spinlock_t *lock)
{
	struct list_head *i, *temp;
	struct job_descriptor *jd;
	if(lock)
		spin_lock(lock);
	list_for_each_safe(i, temp, &head->jobs)
	{
		jd = list_entry(i, struct job_descriptor, jobs);
		/* free the bio pages and job descriptor structure */
		free_job(bs2_dev, jd, i);		
	}
	if(lock)
		spin_unlock(lock);	
}

void bankshot2_reroute_bio(struct bankshot2_device *bs2_dev, int idx,
				size_t sector, size_t size,
				struct bio *bio, struct block_device *bdev,
				int where, JOB_TYPE type)
{
	struct job_descriptor *jd, jd_head;

	INIT_LIST_HEAD(&(jd_head.jobs));
	jd = bankshot2_alloc_job_descriptor(bs2_dev,
				bio->bi_max_vecs, &jd_head);

	BUG_ON(!jd);

	jd->disk_cmd = bio_data_dir(bio) ? WRITE : READ;
	init_job_descriptor(jd, type, bio->bi_size, 0);
	__bio_clone(jd->bio, bio);

#if 0
	if (bio_integrity(bio)) {
		ret = bio_integrity_clone(jd->bio, bio, GFP_KERNEL,
						bs2_dev->bio_set);
		if (ret < 0) {
			bs2_info("Bio Integrity test failed\n");
		}
	}
#endif

	jd->bio->bi_sector = sector;
	jd->bio->bi_size = size; 
	jd->bio->bi_idx = idx;
	jd->bio->bi_bdev = bdev;
	jd->bio->bi_next = NULL;
	jd->sys_bio = bio;

	if (where == DISK)
		bankshot2_add_to_disk_list(bs2_dev, jd, &bs2_dev->disk_queue);
//	else
//		bbd_add_to_cache_list(cache_info, jd, &cache_info->cache_queue);

	return;
}

static unsigned long find_continuous_pages(char *void_array, size_t nr_pages,
		unsigned long start, unsigned long *first)
{
	unsigned long i = start;
	unsigned long last = 0;

	while(i < nr_pages) {
		if (void_array[i] == 0x1)
			break;
		i++;
	}

	if (i < nr_pages)
		*first = i;
	else
		return 0;

	while(i < nr_pages) {
		if (void_array[i] == 0)
			break;
		last = i;
		i++;
	}

	if (last < *first) {
		bs2_info("%s: last smaller than first, first %lu, last %lu\n",
				__func__, *first, last);
		return 0;
	}

	return (last - *first + 1);	
}

static size_t do_vfs_cache_fill(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, char *buf, u64 job_offset,
		u64 start_offset, size_t done, char* void_array, int read)
{
	unsigned long index;
	int array_index;
	u64 block;
	void *xmem;
	size_t ret = 0;
	int i = 0;

	/* get the file offset and index */
	array_index = (job_offset - start_offset) >> PAGE_SHIFT;
	index = job_offset >> bs2_dev->s_blocksize_bits;

	while(done) {
		if (void_array[array_index] != 0x1) {
			bs2_info("%s: ERROR: void_array is zero\n", __func__);
			goto next;
		}

		block = bankshot2_find_data_block(bs2_dev, pi, index);
		if (!block) {
			bs2_info("%s: get block failed, index 0x%lx\n",
					__func__, index);
			return -EINVAL;
		}
		xmem = bankshot2_get_block(bs2_dev, block);
		if (read)
			memcpy(xmem, buf + i * PAGE_SIZE, PAGE_SIZE);
		else
			memcpy(buf + i * PAGE_SIZE, xmem, PAGE_SIZE);
		bankshot2_flush_edge_cachelines(
				index << bs2_dev->s_blocksize_bits,
				PAGE_SIZE, xmem);
next:
		array_index++;
		index++;
		i++;
		if (done < PAGE_SIZE)
			done = 0;
		else
			done -= PAGE_SIZE;
		ret += PAGE_SIZE;
	}

	return ret;
}

/*To keep up with the iops capabilities of moneta, we have the io kernel
  issuing multiple request simultaneously */
int bankshot2_copy_to_cache(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		u64 pos, size_t count, u64 b_offset, char *void_array,
		unsigned long required, int read)
{
	struct file *file;
	size_t nr_pages, done, transferred = 0;
	uint8_t result;
	unsigned long start, first, length;
	u64 job_offset, start_b_offset;
	char *buf;
	timing_t vfs_read_time, cache_fill_time;

////	BEE3_INFO("Copy to cache, %llu block %llu -> %llu / %llu", b_offset, (b_offset - 49152)/(1024 * 1024), c_offset, c_offset/(PAGE_SIZE * 256));

	if (required == 0)
		return 0;

	align_offset_and_len(&b_offset, &count);
	pos = job_offset = ALIGN_DOWN(pos);
	start_b_offset = b_offset;

	nr_pages = count >> bs2_dev->s_blocksize_bits;

	if (nr_pages == 0 || nr_pages < required)
	{
		bs2_info("Copy to cache Len is incorrect: %lu, required %lu\n",
				nr_pages, required);
		return -EINVAL;
	}

	file = fget(data->file);
	if (!file) {
		bs2_info("fget failed\n");
		return -EINVAL;
	}

	buf = data->carrier;
	if (!buf) {
		fput(file);
		return -ENOMEM;
	}

	start = first = 0;
	while(required) {
		length = find_continuous_pages(void_array, nr_pages, start,
						&first);

		if (length == 0 || length > required) {
			bs2_info("ERROR: Consecutive pages get error, "
				"required %lu, start %lu, first %lu, "
				"length %lu\n", required, start, first, length);
			fput(file);
			return -EINVAL;
		}

		b_offset = start_b_offset + (first << PAGE_SHIFT);
		job_offset = pos + (first << PAGE_SHIFT);

		if (read) {
			BANKSHOT2_START_TIMING(bs2_dev, vfs_read_read_t,
						vfs_read_time);
		} else {
			BANKSHOT2_START_TIMING(bs2_dev, vfs_read_write_t,
						vfs_read_time);
		}

		/* If the extent is mmaped and writeable,
		 * directly read to mmap address
		 */
		if (data->write && data->mmap_addr) {
			done = vfs_read(file,
				(char *)(data->mmap_addr + (job_offset - pos)),
				length << PAGE_SHIFT, &b_offset);
			if (done >= (unsigned long)(-64)) {
				bs2_info("vfs read failed, returned %d\n",
						(int)done);
				bs2_info("mmap addr 0x%lx, mmap pos 0x%llx, "
					"offset 0x%llx, length %lu pages, "
					"file offset 0x%llx, read %d, "
					"read prot %d, write prot %d\n",
				 	data->mmap_addr, pos, job_offset,
					length, b_offset, read,
					data->read, data->write);
				return -EINVAL;
			}
			goto update_length;
		}

		done = vfs_read(file, buf, length << PAGE_SHIFT, &b_offset);

		if (read) {
			BANKSHOT2_END_TIMING(bs2_dev, vfs_read_read_t,
						vfs_read_time);
		} else {
			BANKSHOT2_END_TIMING(bs2_dev, vfs_read_write_t,
						vfs_read_time);
		}
		if (done >= (unsigned long)(-64)) {
			bs2_info("vfs read failed, returned %d\n", (int)done);
			fput(file);
			return -EINVAL;
		}

		bs2_dbg("vfs read: offset %llu, request %lu, done %lu\n",
					b_offset, length << PAGE_SHIFT, done);
		if (done <= 0) 
			break;

		if (done != (length << PAGE_SHIFT))
			bs2_dbg("read length unmatch: request %lu, done %lu\n",
						length << PAGE_SHIFT, done);

		if (read) {
			BANKSHOT2_START_TIMING(bs2_dev, vfs_cache_fill_read_t,
						cache_fill_time);
		} else {
			BANKSHOT2_START_TIMING(bs2_dev, vfs_cache_fill_write_t,
						cache_fill_time);
		}
		done = do_vfs_cache_fill(bs2_dev, pi, buf, job_offset, pos,
						done, void_array, 1);

		if (read) {
			BANKSHOT2_END_TIMING(bs2_dev, vfs_cache_fill_read_t,
						cache_fill_time);
		} else {
			BANKSHOT2_END_TIMING(bs2_dev, vfs_cache_fill_write_t,
						cache_fill_time);
		}

update_length:
		if (done < PAGE_SIZE) {
			bs2_info("ERROR: cache filled less than one page!\n");
			break;
		}

		required -= (done >> bs2_dev->s_blocksize_bits);
		transferred += (done >> bs2_dev->s_blocksize_bits);
		start = first + (done >> bs2_dev->s_blocksize_bits);
	}
//	atomic64_set(&bs2_dev->last_offset, b_offset);
	fput(file);
	bs2_dbg("%s result: %d\n", __func__, result);

	return 0;
}

static int do_fsync_cache_fill(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, char *buf, u64 start_offset,
		size_t length)
{
	unsigned long index;
	u64 block;
	void *xmem;
	int i = 0;

	index = start_offset >> bs2_dev->s_blocksize_bits;

	while(length) {
		block = bankshot2_find_data_block(bs2_dev, pi, index);
		if (!block) {
			bs2_info("%s: get block failed, index 0x%lx\n",
					__func__, index);
			return -EINVAL;
		}
		xmem = bankshot2_get_block(bs2_dev, block);
		memcpy(buf + i * PAGE_SIZE, xmem, PAGE_SIZE);
		bankshot2_flush_edge_cachelines(
				index << bs2_dev->s_blocksize_bits,
				PAGE_SIZE, xmem);
		index++;
		i++;
		if (length < PAGE_SIZE)
			length = 0;
		else
			length -= PAGE_SIZE;
	}

	return 0;
}

/*
 * Fsync/Fdatasync handler.
 * FIXME: It's a waste to copy to user buffer first.
 * FIXME: Need to detect dirty pages.
 */
int bankshot2_fsync_to_bs(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		loff_t start, loff_t end, int datasync)
{
	struct file *file;
	size_t nr_pages, done, transferred = 0;
//	uint8_t result;
	unsigned long length;
	size_t count;
	off_t start_aligned, end_aligned;
	loff_t b_offset;
	char *buf;
	int ret;

////	BEE3_INFO("Copy to cache, %llu block %llu -> %llu / %llu", b_offset, (b_offset - 49152)/(1024 * 1024), c_offset, c_offset/(PAGE_SIZE * 256));
	if (end <= start)
		return 0;

	buf = data->carrier;
	if (!buf)
		return -ENOMEM;

	start_aligned = ALIGN_DOWN(start);
	end_aligned = ALIGN_UP(end);
	count = end_aligned - start_aligned;

	nr_pages = count >> bs2_dev->s_blocksize_bits;

	if (nr_pages == 0)
	{
		bs2_info("Fsync length incorrect\n");
		return -EINVAL;
	}

	file = fget(data->file);
	if (!file) {
		bs2_info("fget failed\n");
		return -EINVAL;
	}

	while(count) {
#if 0
		length = find_continuous_pages(void_array, nr_pages, start,
					&first);

		if (length == 0 || length > required) {
			bs2_info("ERROR: Consecutive pages get error, "
				"required %lu, start %lu, first %lu, "
				"length %lu\n", required, start,
				first, length);
			fput(file);
			return -EINVAL;
		}
#endif
		length = MAX_MMAP_SIZE;
		if (length > count)
			length = count;

		b_offset = start_aligned;

		ret = do_fsync_cache_fill(bs2_dev, pi, buf, start_aligned,
						length);
		if (ret) {
			/* Don't write to disk if cache block invalid */
			done = length;
			goto next;
		}

		done = vfs_write(file, buf, length, &b_offset);

		if (done >= (unsigned long)(-64)) {
			bs2_info("vfs write failed, returned %d\n", (int)done);
			fput(file);
			return -EINVAL;
		}

		bs2_dbg("vfs write: offset %lu, request %lu, done %lu\n",
					start_aligned, length, done);
		if (done <= 0) 
			break;

		if (done != length)
			bs2_info("write length unmatch: request %lu, "
				"done %lu\n", length, done);
next:
		if (done < count)
			count -= done;
		else
			count = 0;

		transferred += (done >> bs2_dev->s_blocksize_bits);
		start_aligned += done;
	}
	/* Wait on the jobs to complete, submit tthe transfer to cache and, free memory for completed jobs*/
//	do_disk_fill(bs2_dev, &jd_head, NULL);	
//	free_jobs_in_list(bs2_dev, &jd_head, NULL);
//	atomic64_set(&bs2_dev->last_offset, b_offset);

	fput(file);
	return 0;
}

static int find_bs_offset(struct inode *inode,
		struct bankshot2_cache_data *data, u64 job_offset)
{
	struct fiemap_extent_info fieinfo = {0,};
	u64 file_length;
	int ret;

	file_length = i_size_read(inode);

	memset(&fieinfo, 0, sizeof(struct fiemap_extent_info));
	fieinfo.fi_flags = FIEMAP_FLAG_SYNC;
	fieinfo.fi_extents_max = 1;
	fieinfo.fi_extents_start = data->extent;

	ret = inode->i_op->fiemap(inode, &fieinfo, job_offset,
					file_length - job_offset);

	if (fieinfo.fi_extents_mapped == 0)
		return -1;

	return ret;
}

int bankshot2_copy_from_cache(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		u64 pos, size_t count, u64 b_offset, char *void_array,
		unsigned long required)
{
	/*
	create bios and submit job_descritpors (we have to split and submit
	jobs sometimes to satisfy iovec alignment, page availability etc) with
	job type  COPY_TO_CACHE.
	we then wait on completion of all job descriptors in sequential order
	*/
	struct inode *inode = pi->inode;
	struct bio *bio;
	size_t nr_pages, bio_pages, max_pages, done, transferred = 0;
	struct request_queue *q = bs2_dev->backing_store_rqueue;
	struct job_descriptor jd_head, *jd;
	unsigned long start, first, length;
//	uint8_t result;
	u64 job_offset;
	size_t b_length;
	int ret;

	max_pages = queue_max_hw_sectors(q) >> (PAGE_SHIFT - 9);

////	BEE3_INFO("Copy to cache, %llu block %llu -> %llu / %llu", b_offset, (b_offset - 49152)/(1024 * 1024), c_offset, c_offset/(PAGE_SIZE * 256));
	if (required == 0)
		return 0;

	align_offset_and_len(&b_offset, &count);
	pos = job_offset = ALIGN_DOWN(pos);

	nr_pages = count >> bs2_dev->s_blocksize_bits;

	if(nr_pages == 0 || nr_pages < required)
	{
		bs2_info("Copy from cache Len is incorrect: %lu, "
				"required %lu\n", nr_pages, required);
		return -EINVAL;
	}

	if (max_pages > BIO_MAX_PAGES)
		max_pages = BIO_MAX_PAGES;

	if (max_pages > bs2_dev->backing_store_rqueue->nr_requests)
		max_pages = bs2_dev->backing_store_rqueue->nr_requests;

	INIT_LIST_HEAD(&jd_head.jobs);
	start = first = 0;
	while(required) {
		length = find_continuous_pages(void_array, nr_pages, start,
						&first);

		if (length == 0 || length > required) {
			bs2_info("ERROR: Consecutive pages get error, "
				"required %lu, start %lu, first %lu, "
				"length %lu\n", required, start, first, length);
			return -EINVAL;
		}

		bio_pages = (length > max_pages) ? max_pages : length;

		job_offset = pos + (first << PAGE_SHIFT);

		ret = find_bs_offset(inode, data, job_offset);

		if (ret) {
			bs2_info("ERROR: Find bs offset failed %d\n", ret);
			return -EINVAL;
		}

		b_offset = data->extent->fe_physical + job_offset -
						data->extent->fe_logical;

		b_length = data->extent->fe_length - (job_offset - 
						data->extent->fe_logical);

		if (bio_pages > (b_length >> PAGE_SHIFT))
			bio_pages = (b_length >> PAGE_SHIFT);

		jd = bankshot2_alloc_job_descriptor(bs2_dev, bio_pages,
							&jd_head);
		if (!jd) {
			break;
		}
		bio = jd->bio;

		bio->bi_sector = b_offset >> 9;
		bio->bi_bdev = bs2_dev->bs_bdev;
		bio->bi_rw = WRITE;

		done = add_pages_to_job_bio(bs2_dev, bio, bio_pages);
		if (done <= 0) 
			break;
		/* Setup the bio fields before submit */
		init_job_descriptor(jd, WAKEUP_ON_COMPLETION,
					done << PAGE_SHIFT, b_offset);
		jd->disk_cmd = WRITE;
		jd->inode = pi;
		jd->job_offset = job_offset;
		jd->start_offset = pos;
		bankshot2_add_to_cache_list(bs2_dev, jd, 0, transferred,
						void_array);
		
		required -= done;
		transferred += done;
		start = first + done;
	}
	/* Wait on the jobs to complete, submit tthe transfer to cache and, free memory for completed jobs*/
	do_disk_fill(bs2_dev, &jd_head, NULL);	
//	free_jobs_in_list(bs2_dev, &jd_head, NULL);
//	atomic64_set(&bs2_dev->last_offset, b_offset);

	return 0;
}

/* Get the backing store extent info of newly allocated cache blocks
 * and insert into the physical extent tree. */
int bankshot2_update_physical_tree(struct bankshot2_device *bs2_dev, 
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data,
		u64 offset, size_t length, char *alloc_array,
		unsigned long unallocated)
{
	struct inode *inode = pi->inode;
	size_t nr_pages, bio_pages;
	unsigned long start, first, cont_length;
	u64 pos;
	u64 extent_offset, b_offset;
	size_t extent_length, b_length;
	int ret;
	timing_t timing, add_phy;

	if (unallocated == 0)
		return 0;

	nr_pages = length >> bs2_dev->s_blocksize_bits;
	if (length % bs2_dev->blocksize)
		nr_pages++;

	if (nr_pages == 0) {
		bs2_info("%s len is incorrect\n", __func__);
		return -EINVAL;
	}

	pos = ALIGN_DOWN(offset);
	start = first = 0;
	while(unallocated) {
		cont_length = find_continuous_pages(alloc_array, nr_pages,
						start, &first);

		if (cont_length == 0 || cont_length > unallocated) {
			bs2_info("ERROR: Consecutive pages get error, "
				"required %lu, start %lu, first %lu, "
				"length %lu\n", unallocated, start, first,
				cont_length);
			return -EINVAL;
		}

		bio_pages = cont_length;

		extent_offset = pos + (first << PAGE_SHIFT);

		BANKSHOT2_START_TIMING(bs2_dev, fiemap_t, timing); 	
		ret = find_bs_offset(inode, data, extent_offset);
		BANKSHOT2_END_TIMING(bs2_dev, fiemap_t, timing); 	

		if (ret) {
			bs2_info("ERROR: Find bs offset failed %d\n", ret);
			return -EINVAL;
		}

		b_offset = data->extent->fe_physical + extent_offset -
						data->extent->fe_logical;

		b_length = data->extent->fe_length - (extent_offset - 
						data->extent->fe_logical);

		if (bio_pages > (b_length >> PAGE_SHIFT))
			bio_pages = (b_length >> PAGE_SHIFT);

		extent_length = bio_pages << PAGE_SHIFT;

		BANKSHOT2_START_TIMING(bs2_dev, add_physical_t, add_phy);
		bankshot2_insert_physical_tree(bs2_dev, pi, extent_offset,
					extent_length, b_offset);
		BANKSHOT2_END_TIMING(bs2_dev, add_physical_t, add_phy);

		unallocated -= bio_pages;
		start = first + bio_pages;
	}

	return ret;
}
