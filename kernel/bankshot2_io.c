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

/* Currently only supper 1 page */
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
		bs2_info("ERROR: %s failed\n", __func__);
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

int bankshot2_submit_to_cache(struct bankshot2_device *bs2_dev, struct bio *bio,
				bool end, int read, void *xmem)
{
	struct bio_vec *bvec;
	unsigned int i;
	char *buf;

	bio_for_each_segment(bvec, bio, i) {
		buf = kmap_atomic(bvec->bv_page);
		if (read)
			memcpy(xmem, buf + bvec->bv_offset, bvec->bv_len);
		else
			memcpy(buf + bvec->bv_offset, xmem, bvec->bv_len);
		kunmap_atomic(buf);
	}

	if (end)
		bio_endio(bio, 0);

	return 0;
}

static void bankshot2_add_to_cache_list(struct bankshot2_device *bs2_dev,
			struct job_descriptor *jd, int read)
{
//	set_job_status(jd, STATUS(JOB_QUEUED_TO_CACHE));
	/* Moneta IO Is always blocking and not possible to have event driven operation */
	set_job_status(jd, STATUS(JOB_ISSUED_TO_CACHE));
//	if(jd->bio->bi_sector > jd->bs2_dev->sector_count)
//		BEE3_INFO("Bio too big for cache %lu %u %x", jd->bio->bi_sector, jd->bio->bi_size, jd->moneta_cmd);
	bankshot2_submit_to_cache(jd->bs2_dev, jd->bio, 1, read, jd->xmem);
}

uint8_t do_cache_fill(struct bankshot2_device *bs2_dev,
			struct job_descriptor *head, spinlock_t *lock)
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
//		reset_job_bio(jd, jd->c_offset >> 9, bs2_dev->self_bdev, WRITE);
		clear_job_status(jd);
		jd->type = DO_COMPLETION;			
		bankshot2_add_to_cache_list(bs2_dev, jd, 1);
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
//		reset_job_bio(jd, jd->c_offset >> 9, bs2_dev->self_bdev, WRITE);
		clear_job_status(jd);
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

/*To keep up with the iops capabilities of moneta, we have the io kernel
  issuing multiple request simultaneously */
int bankshot2_copy_to_cache(struct bankshot2_device *bs2_dev, uint64_t b_offset,
			size_t b_len, void *xmem) 
{
	/*
	create bios and submit job_descritpors (we have to split and submit
	jobs sometimes to satisfy iovec alignment, page availability etc) with
	job type  COPY_TO_CACHE.
	we then wait on completion of all job descriptors in sequential order
	*/
	struct bio *bio;
	size_t nr_pages, bio_pages, max_pages, done;
	struct request_queue *q = bs2_dev->backing_store_rqueue;
	struct job_descriptor jd_head, *jd;
	uint8_t result;
	max_pages = queue_max_hw_sectors(q) >> (PAGE_SHIFT - 9);

////	BEE3_INFO("Copy to cache, %llu block %llu -> %llu / %llu", b_offset, (b_offset - 49152)/(1024 * 1024), c_offset, c_offset/(PAGE_SIZE * 256));
	nr_pages = align_offset_and_len(&b_offset, &b_len);
	if(nr_pages == 0)
	{
		bs2_info("Copy to cache Len is too small %lu\n", b_len);
		return -EINVAL;
	}

	if(max_pages > BIO_MAX_PAGES)
		max_pages = BIO_MAX_PAGES;

	INIT_LIST_HEAD(&jd_head.jobs);
	while(nr_pages){
		bio_pages = (nr_pages > max_pages)?max_pages:nr_pages;

		jd = bankshot2_alloc_job_descriptor(bs2_dev, bio_pages, &jd_head);
		if(!jd){
			break;
		}
		bio = jd->bio;

		bio->bi_sector = b_offset >> 9;
		bio->bi_bdev = bs2_dev->bs_bdev;
		bio->bi_rw = READ;

		done = add_pages_to_job_bio(bs2_dev, bio, bio_pages);
		if(!done) 
			break;
		/* Setup the bio fields before submit */
		init_job_descriptor(jd, WAKEUP_ON_COMPLETION, done << PAGE_SHIFT, b_offset);
//		jd->moneta_cmd = BBD_CMD_CACHE_CLEAN_WRITE; 
//		jd->moneta_cmd = BBD_CMD_WRITE; 
		jd->disk_cmd = READ;
		jd->xmem = xmem;
		bankshot2_add_to_disk_list(bs2_dev, jd, &bs2_dev->disk_queue);
		
		nr_pages -= done;
		b_offset += (done << PAGE_SHIFT);
//		c_offset += (done << PAGE_SHIFT);
	}
	/* Wait on the jobs to complete, submit tthe transfer to cache and, free memory for completed jobs*/
	result = do_cache_fill(bs2_dev, &jd_head, NULL);	
	free_jobs_in_list(bs2_dev, &jd_head, NULL);
//	atomic64_set(&bs2_dev->last_offset, b_offset);
	bs2_dbg("%s result: %d\n", __func__, result);
	return (result & ~(1 << JOB_DONE))?-1:0;
}

int bankshot2_copy_from_cache(struct bankshot2_device *bs2_dev,
			uint64_t b_offset, size_t b_len, void *xmem) 
{
	/*
	create bios and submit job_descritpors (we have to split and submit
	jobs sometimes to satisfy iovec alignment, page availability etc) with
	job type  COPY_TO_CACHE.
	we then wait on completion of all job descriptors in sequential order
	*/
	struct bio *bio;
	size_t nr_pages, bio_pages, max_pages, done;
	struct request_queue *q = bs2_dev->backing_store_rqueue;
	struct job_descriptor jd_head, *jd;
//	uint8_t result;
	max_pages = queue_max_hw_sectors(q) >> (PAGE_SHIFT - 9);

////	BEE3_INFO("Copy to cache, %llu block %llu -> %llu / %llu", b_offset, (b_offset - 49152)/(1024 * 1024), c_offset, c_offset/(PAGE_SIZE * 256));
	nr_pages = align_offset_and_len(&b_offset, &b_len);
	if(nr_pages == 0)
	{
		bs2_info("Copy from cache Len is too small %lu\n", b_len);
		return -EINVAL;
	}

	if(max_pages > BIO_MAX_PAGES)
		max_pages = BIO_MAX_PAGES;

	INIT_LIST_HEAD(&jd_head.jobs);
	while(nr_pages){
		bio_pages = (nr_pages > max_pages)?max_pages:nr_pages;

		jd = bankshot2_alloc_job_descriptor(bs2_dev, bio_pages, &jd_head);
		if(!jd){
			break;
		}
		bio = jd->bio;

		bio->bi_sector = b_offset >> 9;
		bio->bi_bdev = bs2_dev->bs_bdev;
		bio->bi_rw = WRITE;

		done = add_pages_to_job_bio(bs2_dev, bio, bio_pages);
		if(!done) 
			break;
		/* Setup the bio fields before submit */
		init_job_descriptor(jd, WAKEUP_ON_COMPLETION, done << PAGE_SHIFT, b_offset);
//		jd->moneta_cmd = BBD_CMD_CACHE_CLEAN_WRITE; 
//		jd->moneta_cmd = BBD_CMD_WRITE; 
		jd->disk_cmd = WRITE;
		jd->xmem = xmem;
		bankshot2_add_to_cache_list(bs2_dev, jd, 0);
		
		nr_pages -= done;
		b_offset += (done << PAGE_SHIFT);
//		c_offset += (done << PAGE_SHIFT);
	}
	/* Wait on the jobs to complete, submit tthe transfer to cache and, free memory for completed jobs*/
	do_disk_fill(bs2_dev, &jd_head, NULL);	
//	free_jobs_in_list(bs2_dev, &jd_head, NULL);
//	atomic64_set(&bs2_dev->last_offset, b_offset);

	return 0;
}

