#include "bankshot2.h"

static inline int bankshot2_rbtree_compare(struct extent_entry *curr,
		struct extent_entry *new)
{
	if (new->offset < curr->offset) return -1;
	if (new->offset > curr->offset) return 1;

	return 0;
}

static inline int bankshot2_rbtree_compare_find(struct extent_entry *curr,
		off_t offset)
{
	if ((curr->offset <= offset) &&
			(curr->offset + curr->length > offset))
		return 0;

	if (offset < curr->offset) return -1;
	if (offset > curr->offset) return 1;

	return 0;
}

int bankshot2_find_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct extent_entry *extent)
{
	struct extent_entry *curr;
	struct rb_node *temp;
	int compVal;

	temp = pi->extent_tree.rb_node;
	read_lock(&pi->extent_tree_lock);
	while (temp) {
		curr = container_of(temp, struct extent_entry, node);
		compVal = bankshot2_rbtree_compare_find(curr, extent->offset);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			extent->offset = curr->offset;
			extent->length = curr->length;
			extent->dirty = curr->dirty;
//			extent->mmap_addr = curr->mmap_addr;
			read_unlock(&pi->extent_tree_lock);
			return 1;
		}
	}

	read_unlock(&pi->extent_tree_lock);
	return 0;
}

void bankshot2_remove_extent(struct bankshot2_device *bs2_dev,
			struct bankshot2_inode *pi, off_t offset)
{
	struct extent_entry *curr;
	struct rb_node *temp;
	int compVal;

	temp = pi->extent_tree.rb_node;
	write_lock(&pi->extent_tree_lock);
	while (temp) {
		curr = container_of(temp, struct extent_entry, node);
		compVal = bankshot2_rbtree_compare_find(curr, offset);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			bs2_dbg("Delete extent to pi %llu, extent offset %lu, "
				"length %lu\n",
				pi->i_ino, curr->offset, curr->length);
			rb_erase(&curr->node, &pi->extent_tree);
			kmem_cache_free(bs2_dev->bs2_extent_slab, curr);
			break;
		}
	}

	write_unlock(&pi->extent_tree_lock);
	return;
}

int bankshot2_add_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, off_t offset, size_t length,
		unsigned long b_offset, struct address_space *mapping)
{
	struct extent_entry *curr, *new;
	struct rb_node **temp, *parent;
	off_t extent_offset;
	size_t extent_length;
	unsigned long extent_b_offset;
	int count, i;
	int compVal;

	bs2_dbg("Insert extent to pi %llu, extent offset %lx, "
			"length %lu,  b_offset %lx\n",
			pi->i_ino, offset, length, b_offset);

	/* Break the extent to 2MB chunks */
	if (offset != ALIGN_DOWN(offset) || length != ALIGN_DOWN(length)) {
		bs2_info("%s: inode %llu: offset or length not aligned to mmap "
				"unit size! offset 0x%lx, length %lu\n",
				__func__, pi->i_ino, offset, length);
		return 0;
	}

	count = length / MMAP_UNIT;

	write_lock(&pi->extent_tree_lock);
	for (i = 0; i < count; i++) {
		temp = &(pi->extent_tree.rb_node);
		parent = NULL;

		extent_offset = offset + i * MMAP_UNIT;
		extent_b_offset = b_offset + i * MMAP_UNIT;
		extent_length = MMAP_UNIT;

		while (*temp) {
			curr = container_of(*temp, struct extent_entry, node);
			compVal = bankshot2_rbtree_compare_find(curr,
					extent_offset);
			parent = *temp;

			if (compVal == -1) {
				temp = &((*temp)->rb_left);
			} else if (compVal == 1) {
				temp = &((*temp)->rb_right);
			} else {
				if (curr->offset != extent_offset || curr->length != extent_length
						|| curr->b_offset != extent_b_offset) {
					bs2_info("Existing extent hit but unmatch! "
					"existing extent offset 0x%lx, "
					"length %lu, b_offset 0x%lx, "
					"new extent offset 0x%lx, length %lu, "
					"b_offset 0x%lx\n",
					curr->offset, curr->length,
					curr->b_offset, extent_offset,
					extent_length, extent_b_offset);
					continue;
				}
				bankshot2_insert_mapping(bs2_dev,
					curr, mapping);
				continue;
			}
		}

		new = (struct extent_entry *)
			kmem_cache_alloc(bs2_dev->bs2_extent_slab, GFP_KERNEL);
		if (!new) {
			write_unlock(&pi->extent_tree_lock);
			return -ENOMEM;
		}

		new->offset = extent_offset;
		new->length = extent_length;
		new->b_offset = extent_b_offset;
		new->dirty = 1; //FIXME: assume all extents are dirty
		bankshot2_insert_mapping(bs2_dev, new, mapping);

		rb_link_node(&new->node, parent, temp);
		rb_insert_color(&new->node, &pi->extent_tree);
	}

#if 0
	// Check the prev node see if it can merge
	pre_node = rb_prev(&new->node);
	if (pre_node) {
		prev = container_of(pre_node, struct extent_entry, node);
		if (prev->offset + prev->length >= new->offset) {
			if (prev->offset + prev->length
					< new->offset + new->length) {
				prev->length = new->offset + new->length
						- prev->offset;
			}

			rb_erase(&new->node, &pi->extent_tree);
			if (new->dirty)
				prev->dirty = 1;
			kmem_cache_free(bs2_dev->bs2_extent_slab, new);
			new = prev;
		}
	}

	// Check the next node see if it can merge
	while (1) {
		next_node = rb_next(&new->node);
		if (!next_node)
			break;

		next = container_of(next_node, struct extent_entry, node);
		if (new->offset + new->length >= next->offset) {
			if (next->offset + next->length
					> new->offset + new->length) {
				new->length = next->offset + next->length
						- new->offset;
			}

			if (next->dirty)
				new->dirty = next->dirty;
			rb_erase(&next->node, &pi->extent_tree);
			kmem_cache_free(bs2_dev->bs2_extent_slab, next);
		} else {
			break;
		}
	}
#endif
	write_unlock(&pi->extent_tree_lock);
	return 0;
}

void bankshot2_print_tree(struct bankshot2_device *bs2_dev,
				struct bankshot2_inode *pi)
{
	struct extent_entry *curr;
	struct rb_node *temp;

	temp = rb_first(&pi->extent_tree);
	read_lock(&pi->extent_tree_lock);
	bs2_info("Print extent tree for pi %llu\n", pi->i_ino);
	while (temp) {
		curr = container_of(temp, struct extent_entry, node);
		bs2_info("pi %llu, extent offset %lu, length %lu\n",
				pi->i_ino, curr->offset, curr->length);
		temp = rb_next(temp);
	}

	read_unlock(&pi->extent_tree_lock);
	return;
}

void bankshot2_delete_tree(struct bankshot2_device *bs2_dev,
				struct bankshot2_inode *pi)
{
	struct extent_entry *curr;
	struct rb_node *temp;

	temp = rb_first(&pi->extent_tree);
	write_lock(&pi->extent_tree_lock);
	while (temp) {
		curr = container_of(temp, struct extent_entry, node);
//		bs2_info("pi %llu, extent offset %lu, length %lu, "
//				"mmap addr %lx\n", pi->i_ino, curr->offset,
//				curr->length, curr->mmap_addr);
		temp = rb_next(temp);
		rb_erase(&curr->node, &pi->extent_tree);
		kmem_cache_free(bs2_dev->bs2_extent_slab, curr);
	}

	write_unlock(&pi->extent_tree_lock);
	return;
}

int bankshot2_free_num_blocks(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, int num_free)
{
	struct extent_entry *curr;
	struct rb_node *temp;
	off_t offset;
	int num_pages;
	int total_freed = 0, freed;

//	bs2_info("Before free:\n");
//	bankshot2_print_tree(bs2_dev, pi);

	temp = rb_first(&pi->extent_tree);
	write_lock(&pi->extent_tree_lock);
	while (temp && num_free > 0) {
		curr = container_of(temp, struct extent_entry, node);
		bs2_info("Free: pi %llu, extent offset %lu, length %lu\n",
				pi->i_ino, curr->offset, curr->length);
		temp = rb_next(temp);
		offset = curr->offset;
		num_pages = curr->length / PAGE_SIZE;
		if (num_pages > num_free) {
			// Shrink the extent;
			freed = num_free;
//			vm_munmap(curr->mmap_addr, num_free * PAGE_SIZE);
			curr->length -= num_free * PAGE_SIZE;
			curr->offset += num_free * PAGE_SIZE;
		} else {
			// Delete the extent;
			freed = num_pages;
//			vm_munmap(curr->mmap_addr, curr->length);
			rb_erase(&curr->node, &pi->extent_tree);
			kmem_cache_free(bs2_dev->bs2_extent_slab, curr);
		}

		bankshot2_munmap(bs2_dev, pi, offset, freed);
		bankshot2_free_blocks(bs2_dev, pi, offset, freed); 
		total_freed += freed;
		num_free -= freed;
	}

	write_unlock(&pi->extent_tree_lock);

//	bs2_info("After free:\n");
//	bankshot2_print_tree(bs2_dev, pi);
	return total_freed;
}

int bankshot2_init_extents(struct bankshot2_device *bs2_dev)
{
	bs2_dev->bs2_extent_slab = kmem_cache_create(
					"bankshot2_extent_slab",
					sizeof(struct extent_entry),
					0, 0, NULL);
	if (bs2_dev->bs2_extent_slab == NULL)
		return -ENOMEM;
	return 0;
}

void bankshot2_destroy_extents(struct bankshot2_device *bs2_dev)
{
	kmem_cache_destroy(bs2_dev->bs2_extent_slab);
}

