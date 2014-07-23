/*
 * Bankshot2 journal support.
 * Basically copied from bankshot2/journal.c.
 */

#include "bankshot2.h"

static void dump_transaction(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans)
{
	int i;
	bankshot2_logentry_t *le = trans->start_addr;

	for (i = 0; i < trans->num_entries; i++) {
		bs2_dbg("ao %llx tid %x gid %x type %x sz %x\n",
			le->addr_offset, le->transaction_id, le->gen_id,
			le->type, le->size);
		le++;
	}
}

static inline uint32_t next_log_entry(uint32_t jsize, uint32_t le_off)
{
	le_off = le_off + LOGENTRY_SIZE;
	if (le_off >= jsize)
		le_off = 0;
	return le_off;
}

static inline uint32_t prev_log_entry(uint32_t jsize, uint32_t le_off)
{
	if (le_off == 0)
		le_off = jsize;
	le_off = le_off - LOGENTRY_SIZE;
	return le_off;
}

static inline uint16_t next_gen_id(uint16_t gen_id)
{
	gen_id++;
	/* check for wraparound */
	if (gen_id == 0)
		gen_id++;
	return gen_id;
}

static inline uint16_t prev_gen_id(uint16_t gen_id)
{
	gen_id--;
	/* check for wraparound */
	if (gen_id == 0)
		gen_id--;
	return gen_id;
}

/* Undo a valid log entry */
static inline void bankshot2_undo_logentry(struct bankshot2_device *bs2_dev,
	bankshot2_logentry_t *le)
{
	char *data;

	if (le->size > 0) {
		data = bankshot2_get_block(bs2_dev,
					le64_to_cpu(le->addr_offset));
		/* Undo changes by flushing the log entry to bankshot2 */
		bankshot2_memunlock_range(bs2_dev, data, le->size);
		memcpy(data, le->data, le->size);
		bankshot2_memlock_range(bs2_dev, data, le->size);
		bankshot2_flush_buffer(data, le->size, false);
	}
}

/* can be called during journal recovery or transaction abort */
/* We need to Undo in the reverse order */
static void bankshot2_undo_transaction(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans)
{
	bankshot2_logentry_t *le;
	int i;
	uint16_t gen_id = trans->gen_id;

	le = trans->start_addr + trans->num_used;
	le--;
	for (i = trans->num_used - 1; i >= 0; i--, le--) {
		if (gen_id == le16_to_cpu(le->gen_id))
			bankshot2_undo_logentry(bs2_dev, le);
	}
}

/* can be called by either during log cleaning or during journal recovery */
static void bankshot2_flush_transaction(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans)
{
	bankshot2_logentry_t *le = trans->start_addr;
	int i;
	char *data;

	for (i = 0; i < trans->num_used; i++, le++) {
		if (le->size) {
			data = bankshot2_get_block(bs2_dev,
					le64_to_cpu(le->addr_offset));
			if (bs2_dev->redo_log) {
				bankshot2_memunlock_range(bs2_dev, data,
								le->size);
				memcpy(data, le->data, le->size);
				bankshot2_memlock_range(bs2_dev, data,
								le->size);
			} else
				bankshot2_flush_buffer(data, le->size, false);
		}
	}
}

static inline void invalidate_gen_id(bankshot2_logentry_t *le)
{
	le->gen_id = 0;
	bankshot2_flush_buffer(le, LOGENTRY_SIZE, false);
}

/* can be called by either during log cleaning or during journal recovery */
static void bankshot2_invalidate_logentries(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans)
{
	bankshot2_logentry_t *le = trans->start_addr;
	int i;

	bankshot2_memunlock_range(bs2_dev, trans->start_addr,
			trans->num_entries * LOGENTRY_SIZE);
	for (i = 0; i < trans->num_entries; i++) {
		invalidate_gen_id(le);
		if (le->type == LE_START) {
			PERSISTENT_MARK();
			PERSISTENT_BARRIER();
		}
		le++;
	}
	bankshot2_memlock_range(bs2_dev, trans->start_addr,
			trans->num_entries * LOGENTRY_SIZE);
}

/* can be called by either during log cleaning or during journal recovery */
static void bankshot2_redo_transaction(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans, bool recover)
{
	bankshot2_logentry_t *le = trans->start_addr;
	int i;
	uint16_t gen_id = trans->gen_id;
	char *data;

	for (i = 0; i < trans->num_entries; i++) {
		if (gen_id == le16_to_cpu(le->gen_id) && le->size > 0) {
			data = bankshot2_get_block(bs2_dev,
						le64_to_cpu(le->addr_offset));
			/* flush data if we are called during recovery */
			if (recover) {
				bankshot2_memunlock_range(bs2_dev, data,
						le->size);
				memcpy(data, le->data, le->size);
				bankshot2_memlock_range(bs2_dev, data,
						 le->size);
			}
			bankshot2_flush_buffer(data, le->size, false);
		}
		le++;
	}
}

/* recover the transaction ending at a valid log entry *le */
/* called for Undo log and traverses the journal backward */
static uint32_t bankshot2_recover_transaction(struct bankshot2_device *bs2_dev,
		uint32_t head, uint32_t tail, bankshot2_logentry_t *le)
{
	bankshot2_transaction_t trans;
	bool cmt_or_abrt_found = false, start_found = false;
	uint16_t gen_id = le16_to_cpu(le->gen_id);

	memset(&trans, 0, sizeof(trans));
	trans.transaction_id = le32_to_cpu(le->transaction_id);
	trans.gen_id = gen_id;

	do {
		trans.num_entries++;
		trans.num_used++;

		if (gen_id == le16_to_cpu(le->gen_id)) {
			/* Handle committed/aborted transactions */
			if (le->type & LE_COMMIT || le->type & LE_ABORT)
				cmt_or_abrt_found = true;
			if (le->type & LE_START) {
				trans.start_addr = le;
				start_found = true;
				break;
			}
		}
		if (tail == 0 || tail == head)
		    break;
		/* prev log entry */
		le--;
		/* Handle uncommitted transactions */
		if ((gen_id == le16_to_cpu(le->gen_id))
			&& (le->type & LE_COMMIT || le->type & LE_ABORT)) {
			BUG_ON(trans.transaction_id == 
				le32_to_cpu(le->transaction_id));
			le++;
			break;
		}
		tail = prev_log_entry(bs2_dev->jsize, tail);
	} while (1);

	if (start_found && !cmt_or_abrt_found)
		bankshot2_undo_transaction(bs2_dev, &trans);

	if (gen_id == MAX_GEN_ID) {
		if (!start_found)
			trans.start_addr = le;
		/* make sure the changes made by bankshot2_undo_transaction() are
		 * persistent before invalidating the log entries */
		if (start_found && !cmt_or_abrt_found) {
			PERSISTENT_MARK();
			PERSISTENT_BARRIER();
		}
		bankshot2_invalidate_logentries(bs2_dev, &trans);
	}
	return tail;
}

/* process the transaction starting at a valid log entry *le */
/* called by the log cleaner and journal recovery */
static uint32_t bankshot2_process_transaction(struct bankshot2_device *bs2_dev,
		uint32_t head, uint32_t tail, bankshot2_logentry_t *le,
		bool recover)
{
	bankshot2_transaction_t trans;
	uint16_t gen_id;
	uint32_t new_head = head;

	gen_id = le16_to_cpu(le->gen_id);
	if (!(le->type & LE_START)) {
		bs2_dbg("start of trans %x but LE_START not set. gen_id %d\n",
				le32_to_cpu(le->transaction_id), gen_id);
		return next_log_entry(bs2_dev->jsize, new_head);
	}
	memset(&trans, 0, sizeof(trans));
	trans.transaction_id = le32_to_cpu(le->transaction_id);
	trans.start_addr = le;
	trans.gen_id = gen_id;
	do {
		trans.num_entries++;
		trans.num_used++;
		new_head = next_log_entry(bs2_dev->jsize, new_head);

		/* Handle committed/aborted transactions */
		if ((gen_id == le16_to_cpu(le->gen_id)) && (le->type & LE_COMMIT
					|| le->type & LE_ABORT)) {
			head = new_head;
			if ((le->type & LE_COMMIT) && bs2_dev->redo_log)
				bankshot2_redo_transaction(bs2_dev, &trans,
							recover);

			if (gen_id == MAX_GEN_ID) {
				if ((le->type & LE_COMMIT) && bs2_dev->redo_log)
				{
					PERSISTENT_MARK();
					PERSISTENT_BARRIER();
				}
				bankshot2_invalidate_logentries(bs2_dev,
							&trans);
			}
			break;
		}
		/* next log entry */
		le++;
		/* Handle uncommitted transactions */
		if ((new_head == tail) || ((gen_id == le16_to_cpu(le->gen_id))
			    && (le->type & LE_START))) {
			/* found a new valid transaction w/o finding a commit */
			if (recover) {
				/* if this function is called by recovery, move
				 * ahead even if we didn't find a commit record
				 * for this transaction */
				head = new_head;
				if (gen_id == MAX_GEN_ID)
					bankshot2_invalidate_logentries(bs2_dev,
							&trans);
			}
			bs2_dbg("no cmt tid %d sa %p nle %d tail %x gen %d\n",
				trans.transaction_id, trans.start_addr,
				trans.num_entries, trans.num_used,
				trans.gen_id);
			/* dump_transaction(bs2_dev, &trans); */
			break;
		}
	} while (new_head != tail);

	return head;
}

static void bankshot2_clean_journal(struct bankshot2_device *bs2_dev,
		bool unmount)
{
	bankshot2_journal_t *journal = bankshot2_get_journal(bs2_dev);
	uint32_t head = le32_to_cpu(journal->head);
	uint32_t new_head, tail;
	uint16_t gen_id;
	volatile __le64 *ptr_tail_genid = (volatile __le64 *)&journal->tail;
	u64 tail_genid;
	bankshot2_logentry_t *le;

	/* atomically read both tail and gen_id of journal. Normally use of
	 * volatile is prohibited in kernel code but since we use volatile
	 * to write to journal's tail and gen_id atomically, we thought we
	 * should use volatile to read them simultaneously and avoid locking
	 * them. */
	tail_genid = le64_to_cpu(*ptr_tail_genid);
	tail = tail_genid & 0xFFFFFFFF;
	gen_id = (tail_genid >> 32) & 0xFFFF;

	/* journal wraparound happened. so head points to prev generation id */
	if (tail < head)
		gen_id = prev_gen_id(gen_id);
	bs2_dbg("starting journal cleaning %x %x\n", head, tail);
	while (head != tail) {
		le = (bankshot2_logentry_t *)(bs2_dev->journal_base_addr + head);
		if (gen_id == le16_to_cpu(le->gen_id)) {
			/* found a valid log entry, process the transaction */
			new_head = bankshot2_process_transaction(bs2_dev, head,
				tail, le, false);
			/* no progress was made. return */
			if (new_head == head)
				break;
			head = new_head;
		} else {
			if (gen_id == MAX_GEN_ID) {
				bankshot2_memunlock_range(bs2_dev, le,
						sizeof(*le));
				invalidate_gen_id(le);
				bankshot2_memlock_range(bs2_dev, le,
						sizeof(*le));
			}
			head = next_log_entry(bs2_dev->jsize, head);
		}
		/* handle journal wraparound */
		if (head == 0)
			gen_id = next_gen_id(gen_id);
	}
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	bankshot2_memunlock_range(bs2_dev, journal, sizeof(*journal));
	journal->head = cpu_to_le32(head);
	bankshot2_memlock_range(bs2_dev, journal, sizeof(*journal));
	bankshot2_flush_buffer(&journal->head, sizeof(journal->head), true);
	if (unmount) {
		PERSISTENT_MARK();
		if (journal->head != journal->tail)
			bs2_dbg("umount but journal not empty %x:%x\n",
			le32_to_cpu(journal->head), le32_to_cpu(journal->tail));
		PERSISTENT_BARRIER();
	}
	bs2_dbg("leaving journal cleaning %x %x\n", head, tail);
}

static void log_cleaner_try_sleeping(struct bankshot2_device *bs2_dev)
{
	DEFINE_WAIT(wait);
	prepare_to_wait(&bs2_dev->log_cleaner_wait, &wait, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(&bs2_dev->log_cleaner_wait, &wait);
}

static int bankshot2_log_cleaner(void *arg)
{
	struct bankshot2_device *bs2_dev = (struct bankshot2_device *)arg;

	bankshot2_dbg_trans("Running log cleaner thread\n");
	for (;;) {
		log_cleaner_try_sleeping(bs2_dev);

		if (kthread_should_stop())
			break;

		bankshot2_clean_journal(bs2_dev, false);
	}
	bankshot2_clean_journal(bs2_dev, true);
	bs2_dbg("Exiting log cleaner thread\n");
	return 0;
}

static int bankshot2_journal_cleaner_run(struct bankshot2_device *bs2_dev)
{
	int ret = 0;

	init_waitqueue_head(&bs2_dev->log_cleaner_wait);

	bs2_dev->log_cleaner_thread = kthread_run(bankshot2_log_cleaner,
		bs2_dev, "bankshot2_log_cleaner_0x%llx", bs2_dev->phys_addr);
	if (IS_ERR(bs2_dev->log_cleaner_thread)) {
		/* failure at boot is fatal */
		bs2_info(bs2_dev, "Failed to start bankshot2 "
					"log cleaner thread\n");
		ret = -1;
	}
	return ret;
}

int bankshot2_journal_soft_init(struct bankshot2_device *bs2_dev)
{
	bankshot2_journal_t *journal = bankshot2_get_journal(bs2_dev);

	bs2_dev->next_transaction_id = 0;
	bs2_dev->journal_base_addr = bankshot2_get_block(bs2_dev,
					le64_to_cpu(journal->base));
	bs2_dev->jsize = le32_to_cpu(journal->size);
	mutex_init(&bs2_dev->journal_mutex);
	bs2_dev->redo_log = !!le16_to_cpu(journal->redo_logging);

	return bankshot2_journal_cleaner_run(bs2_dev);
}

int bankshot2_journal_hard_init(struct bankshot2_device *bs2_dev, uint64_t base,
	uint32_t size)
{
	bankshot2_journal_t *journal = bankshot2_get_journal(bs2_dev);

	bankshot2_memunlock_range(bs2_dev, journal, sizeof(*journal));
	journal->base = cpu_to_le64(base);
	journal->size = cpu_to_le32(size);
	journal->gen_id = cpu_to_le16(1);
	journal->head = journal->tail = 0;
	/* lets do Undo logging for now */
	journal->redo_logging = 0;
	bankshot2_memlock_range(bs2_dev, journal, sizeof(*journal));

	bs2_dev->journal_base_addr = bankshot2_get_block(bs2_dev, base);
	bankshot2_memunlock_range(bs2_dev, bs2_dev->journal_base_addr, size);
	memset_nt(bs2_dev->journal_base_addr, 0, size);
	bankshot2_memlock_range(bs2_dev, bs2_dev->journal_base_addr, size);

	return bankshot2_journal_soft_init(bs2_dev);
}

static void wakeup_log_cleaner(struct bankshot2_device *bs2_dev)
{
	if (!waitqueue_active(&bs2_dev->log_cleaner_wait))
		return;
	bs2_dbg("waking up the cleaner thread\n");
	wake_up_interruptible(&bs2_dev->log_cleaner_wait);
}

int bankshot2_journal_uninit(struct bankshot2_device *bs2_dev)
{
	if (bs2_dev->log_cleaner_thread)
		kthread_stop(bs2_dev->log_cleaner_thread);
	return 0;
}

inline bankshot2_transaction_t *bankshot2_current_transaction(void)
{
	return (bankshot2_transaction_t *)current->journal_info;
}

static int bankshot2_free_logentries(int max_log_entries)
{
	bs2_info("bankshot2_free_logentries: Not Implemented\n");
	return -ENOMEM;
}

bankshot2_transaction_t *
bankshot2_new_transaction(struct bankshot2_device *bs2_dev, int max_log_entries)
{
	bankshot2_journal_t *journal = bankshot2_get_journal(bs2_dev);
	bankshot2_transaction_t *trans;
	uint32_t head, tail, req_size, avail_size;
	uint64_t base;
#if 0
	trans = bankshot2_current_transaction();

	if (trans) {
		BUG_ON(trans->t_journal != journal);
		return trans;
	}
#endif
	/* If it is an undo log, need one more log-entry for commit record */
	if (!bs2_dev->redo_log)
		max_log_entries++;

	trans = bankshot2_alloc_transaction();
	if (!trans)
		return ERR_PTR(-ENOMEM);
	memset(trans, 0, sizeof(*trans));

	trans->num_used = 0;
	trans->num_entries = max_log_entries;
	trans->t_journal = journal;
	req_size = max_log_entries << LESIZE_SHIFT;

	mutex_lock(&bs2_dev->journal_mutex);

	tail = le32_to_cpu(journal->tail);
	head = le32_to_cpu(journal->head);
	trans->transaction_id = bs2_dev->next_transaction_id++;
again:
	trans->gen_id = le16_to_cpu(journal->gen_id);
	avail_size = (tail >= head) ?
		(bs2_dev->jsize - (tail - head)) : (head - tail);
	avail_size = avail_size - LOGENTRY_SIZE;

	if (avail_size < req_size) {
		uint32_t freed_size;
		/* run the log cleaner function to free some log entries */
		freed_size = bankshot2_free_logentries(max_log_entries);
		if ((avail_size + freed_size) < req_size)
			goto journal_full;
	}
	base = le64_to_cpu(journal->base) + tail;
	tail = tail + req_size;
	/* journal wraparound because of this transaction allocation.
	 * start the transaction from the beginning of the journal so
	 * that we don't have any wraparound within a transaction */
	bankshot2_memunlock_range(bs2_dev, journal, sizeof(*journal));
	if (tail >= bs2_dev->jsize) {
		u64 *ptr;
		tail = 0;
		ptr = (u64 *)&journal->tail;
		/* writing 8-bytes atomically setting tail to 0 */
		set_64bit(ptr, (__force u64)cpu_to_le64((u64)next_gen_id(
					le16_to_cpu(journal->gen_id)) << 32));
		bankshot2_memlock_range(bs2_dev, journal, sizeof(*journal));
		bs2_dbg("journal wrapped. tail %x gid %d cur tid %d\n",
			le32_to_cpu(journal->tail),le16_to_cpu(journal->gen_id),
			bs2_dev->next_transaction_id - 1);
		goto again;
	} else {
		journal->tail = cpu_to_le32(tail);
		bankshot2_memlock_range(bs2_dev, journal, sizeof(*journal));
	}
	bankshot2_flush_buffer(&journal->tail, sizeof(u64), false);
	mutex_unlock(&bs2_dev->journal_mutex);

	avail_size = avail_size - req_size;
	/* wake up the log cleaner if required */
	if ((bs2_dev->jsize - avail_size) > (bs2_dev->jsize >> 3))
		wakeup_log_cleaner(bs2_dev);

	bs2_dbg("new transaction tid %d nle %d avl sz %x sa %llx\n",
		trans->transaction_id, max_log_entries, avail_size, base);
	trans->start_addr = bankshot2_get_block(bs2_dev, base);

	trans->parent = (bankshot2_transaction_t *)current->journal_info;
	current->journal_info = trans;
	return trans;
journal_full:
	mutex_unlock(&bs2_dev->journal_mutex);
	bs2_info(bs2_dev, "Journal full. base %llx sz %x head:tail %x:%x "
		"ncl %x\n",
		le64_to_cpu(journal->base), le32_to_cpu(journal->size),
		le32_to_cpu(journal->head), le32_to_cpu(journal->tail),
		max_log_entries);
	bankshot2_free_transaction(trans);
	return ERR_PTR(-EAGAIN);
}

static inline void bankshot2_commit_logentry(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans, bankshot2_logentry_t *le)
{
	if (bs2_dev->redo_log) {
		/* Redo Log */
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
		/* Atomically write the commit type */
		le->type |= LE_COMMIT;
		barrier();
		/* Atomically make the log entry valid */
		le->gen_id = cpu_to_le16(trans->gen_id);
		bankshot2_flush_buffer(le, LOGENTRY_SIZE, false);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
		/* Update the FS in place */
		bankshot2_flush_transaction(bs2_dev, trans);
	} else {
		/* Undo Log */
		/* Update the FS in place: currently already done. so
		 * only need to clflush */
		bankshot2_flush_transaction(bs2_dev, trans);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
		/* Atomically write the commit type */
		le->type |= LE_COMMIT;
		barrier();
		/* Atomically make the log entry valid */
		le->gen_id = cpu_to_le16(trans->gen_id);
		bankshot2_flush_buffer(le, LOGENTRY_SIZE, true);
	}
}

int bankshot2_add_logentry(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans, void *addr,
		uint16_t size, u8 type)
{
	bankshot2_logentry_t *le;
	int num_les = 0, i;
	uint64_t le_start = size ? bankshot2_get_addr_off(bs2_dev, addr) : 0;
	uint8_t le_size;

	if (trans == NULL)
		return -EINVAL;
	le = trans->start_addr + trans->num_used;

	if (size == 0) {
		/* At least one log entry required for commit/abort log entry */
		if ((type & LE_COMMIT) || (type & LE_ABORT))
			num_les = 1;
	} else
		num_les = (size + sizeof(le->data) - 1)/sizeof(le->data);

	bs2_dbg("add le id %d size %x, num_les %d tail %x le %p\n",
		trans->transaction_id, size, trans->num_entries,
		trans->num_used, le);

	if ((trans->num_used + num_les) > trans->num_entries) {
		bs2_info(bs2_dev, "Log Entry full. tid %x ne %x tail %x "
			"size %x\n",
			trans->transaction_id, trans->num_entries,
			trans->num_used, size);
		dump_transaction(bs2_dev, trans);
		dump_stack();
		return -ENOMEM;
	}

	bankshot2_memunlock_range(bs2_dev, le, sizeof(*le) * num_les);
	for (i = 0; i < num_les; i++) {
		le->addr_offset = cpu_to_le64(le_start);
		le->transaction_id = cpu_to_le32(trans->transaction_id);
		le_size = (i == (num_les - 1)) ? size : sizeof(le->data);
		le->size = le_size;
		size -= le_size;
		if (le_size)
			memcpy(le->data, addr, le_size);
		le->type = type;

		if (i == 0 && trans->num_used == 0)
			le->type |= LE_START;
		trans->num_used++;

		/* handle special log entry */
		if (i == (num_les - 1) && (type & LE_COMMIT)) {
			bankshot2_commit_logentry(bs2_dev, trans, le);
			bankshot2_memlock_range(bs2_dev, le,
						sizeof(*le) * num_les);
			return 0;
		}
		/* put a compile time barrier so that compiler doesn't reorder
		 * the writes to the log entry */
		barrier();

		/* Atomically make the log entry valid */
		le->gen_id = cpu_to_le16(trans->gen_id);
		bankshot2_flush_buffer(le, LOGENTRY_SIZE, false);

		addr += le_size;
		le_start += le_size;
		le++;
	}
	bankshot2_memlock_range(bs2_dev, le, sizeof(*le) * num_les);
	if (!bs2_dev->redo_log) {
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}
	return 0;
}

int bankshot2_commit_transaction(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans)
{
	if (trans == NULL)
		return 0;
	/* Add the commit log-entry */
	bankshot2_add_logentry(bs2_dev, trans, NULL, 0, LE_COMMIT);

	bs2_dbg("completing transaction for id %d\n", trans->transaction_id);

	current->journal_info = trans->parent;
	bankshot2_free_transaction(trans);
	return 0;
}

int bankshot2_abort_transaction(struct bankshot2_device *bs2_dev,
		bankshot2_transaction_t *trans)
{
	if (trans == NULL)
		return 0;
	bs2_dbg("abort trans for tid %x sa %p numle %d tail %x gen %d\n",
		trans->transaction_id, trans->start_addr, trans->num_entries,
		trans->num_used, trans->gen_id);
	dump_transaction(bs2_dev, trans);
	/*dump_stack();*/

	if (!bs2_dev->redo_log) {
		/* Undo Log */
		bankshot2_undo_transaction(bs2_dev, trans);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}
	/* add a abort log entry */
	bankshot2_add_logentry(bs2_dev, trans, NULL, 0, LE_ABORT);
	current->journal_info = trans->parent;
	bankshot2_free_transaction(trans);
	return 0;
}

static void invalidate_remaining_journal(struct bankshot2_device *bs2_dev,
		void *journal_vaddr, uint32_t jtail, uint32_t jsize)
{
	bankshot2_logentry_t *le =
		(bankshot2_logentry_t *)(journal_vaddr + jtail);
	void *start = le;

	bankshot2_memunlock_range(bs2_dev, start, jsize - jtail);
	while (jtail < jsize) {
		invalidate_gen_id(le);
		le++;
		jtail += LOGENTRY_SIZE;
	}
	bankshot2_memlock_range(bs2_dev, start, jsize - jtail);
}

/* we need to increase the gen_id to invalidate all the journal log
 * entries. This is because after the recovery, we may still have some
 * valid log entries beyond the tail (before power failure, they became
 * persistent before the journal tail could become persistent.
 * should gen_id and head be updated atomically? not necessarily? we
 * can update gen_id before journal head because gen_id and head are in
 * the same cacheline */
static void bankshot2_forward_journal(struct bankshot2_device *bs2_dev,
		bankshot2_journal_t *journal)
{
	uint16_t gen_id = le16_to_cpu(journal->gen_id);
	/* handle gen_id wrap around */
	if (gen_id == MAX_GEN_ID) {
		invalidate_remaining_journal(bs2_dev,
			bs2_dev->journal_base_addr,
			le32_to_cpu(journal->tail), bs2_dev->jsize);
	}
	PERSISTENT_MARK();
	gen_id = next_gen_id(gen_id);
	/* make all changes persistent before advancing gen_id and head */
	PERSISTENT_BARRIER();
	bankshot2_memunlock_range(bs2_dev, journal, sizeof(*journal));
	journal->gen_id = cpu_to_le16(gen_id);
	barrier();
	journal->head = journal->tail;
	bankshot2_memlock_range(bs2_dev, journal, sizeof(*journal));
	bankshot2_flush_buffer(journal, sizeof(*journal), false);
}

static int bankshot2_recover_undo_journal(struct bankshot2_device *bs2_dev)
{
	bankshot2_journal_t *journal = bankshot2_get_journal(bs2_dev);
	uint32_t tail = le32_to_cpu(journal->tail);
	uint32_t head = le32_to_cpu(journal->head);
	uint16_t gen_id = le16_to_cpu(journal->gen_id);
	bankshot2_logentry_t *le;

	while (head != tail) {
		/* handle journal wraparound */
		if (tail == 0)
			gen_id = prev_gen_id(gen_id);
		tail = prev_log_entry(bs2_dev->jsize, tail);

		le = (bankshot2_logentry_t *)
				(bs2_dev->journal_base_addr + tail);
		if (gen_id == le16_to_cpu(le->gen_id)) {
			tail = bankshot2_recover_transaction(bs2_dev, head,
				tail, le);
		} else {
			if (gen_id == MAX_GEN_ID) {
				bankshot2_memunlock_range(bs2_dev, le,
						sizeof(*le));
				invalidate_gen_id(le);
				bankshot2_memlock_range(bs2_dev, le,
						sizeof(*le));
			}
		}
	}
	bankshot2_forward_journal(bs2_dev, bs2_dev, journal);
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	return 0;
}

static int bankshot2_recover_redo_journal(struct bankshot2_device *bs2_dev)
{
	bankshot2_journal_t *journal = bankshot2_get_journal(bs2_dev);
	uint32_t tail = le32_to_cpu(journal->tail);
	uint32_t head = le32_to_cpu(journal->head);
	uint16_t gen_id = le16_to_cpu(journal->gen_id);
	bankshot2_logentry_t *le;

	/* journal wrapped around. so head points to previous generation id */
	if (tail < head)
		gen_id = prev_gen_id(gen_id);

	while (head != tail) {
		le = (bankshot2_logentry_t *)
				(bs2_dev->journal_base_addr + head);
		if (gen_id == le16_to_cpu(le->gen_id)) {
			head = bankshot2_process_transaction(bs2_dev, head,
				tail, le, true);
		} else {
			if (gen_id == MAX_GEN_ID) {
				bankshot2_memunlock_range(bs2_dev, le,
						sizeof(*le));
				invalidate_gen_id(le);
				bankshot2_memlock_range(bs2_dev, le,
						sizeof(*le));
			}
			head = next_log_entry(bs2_dev->jsize, head);
		}
		/* handle journal wraparound */
		if (head == 0)
			gen_id = next_gen_id(gen_id);
	}
	bankshot2_forward_journal(bs2_dev, bs2_dev, journal);
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	return 0;
}

int bankshot2_recover_journal(struct bankshot2_device *bs2_dev)
{
	bankshot2_journal_t *journal = bankshot2_get_journal(bs2_dev);
	uint32_t tail = le32_to_cpu(journal->tail);
	uint32_t head = le32_to_cpu(journal->head);
	uint16_t gen_id = le16_to_cpu(journal->gen_id);

	/* is the journal empty? true if unmounted properly. */
	if (head == tail)
		return 0;
	bs2_dbg("journal recovery. head:tail %x:%x gen_id %d\n",
		head, tail, gen_id);
	if (bs2_dev->redo_log)
		bankshot2_recover_redo_journal(bs2_dev);
	else
		bankshot2_recover_undo_journal(bs2_dev);
	return 0;
}

