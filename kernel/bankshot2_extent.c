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
			extent->mmap_addr = curr->mmap_addr;
			read_unlock(&pi->extent_tree_lock);
			return 0;
		}
	}

	read_unlock(&pi->extent_tree_lock);
	return -1;
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
				"length %lu, mmap addr %lx\n",
				pi->i_ino, curr->offset, curr->length,
				curr->mmap_addr);
			rb_erase(&curr->node, &pi->extent_tree);
			kmem_cache_free(bs2_dev->bs2_extent_slab, curr);
			break;
		}
	}

	write_unlock(&pi->extent_tree_lock);
	return;
}

int bankshot2_add_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct extent_entry *new)
{
	struct extent_entry *curr, *prev, *next;
	struct rb_node *pre_node, *next_node;
	struct rb_node **temp, *parent;
	int compVal;

	new->dirty = 1; //FIXME: We need to assume all extents are dirty

	bs2_dbg("Insert extent to pi %llu, extent offset %lu, length %lu, "
			"mmap addr %lx\n", pi->i_ino, new->offset,
			new->length, new->mmap_addr);

	temp = &(pi->extent_tree.rb_node);
	parent = NULL;

	write_lock(&pi->extent_tree_lock);
	while (*temp) {
		curr = container_of(*temp, struct extent_entry, node);
		compVal = bankshot2_rbtree_compare(curr, new);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			bs2_info("want to insert extent but it already exists, "
			"pi %llu, existing extent offset %lu, length %lu, "
			"mmap addr %lx, new extent offset %lu, length %lu, "
			"mmap addr %lx\n", pi->i_ino, curr->offset,
			curr->length, curr->mmap_addr, new->offset, new->length,
			new->mmap_addr);
			write_unlock(&pi->extent_tree_lock);
			kmem_cache_free(bs2_dev->bs2_extent_slab, new);
			return 0;
		}
	}

	rb_link_node(&new->node, parent, temp);
	rb_insert_color(&new->node, &pi->extent_tree);
	
	// Check the prev node see if it can merge
	pre_node = rb_prev(&new->node);
	if (pre_node) {
		prev = container_of(pre_node, struct extent_entry, node);
		if ((prev->offset + prev->length >= new->offset) &&
		    (prev->mmap_addr + (new->offset - prev->offset)
				== new->mmap_addr)) {
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
		if ((new->offset + new->length >= next->offset) &&
		    (new->mmap_addr + (next->offset - new->offset)
				== next->mmap_addr)) {
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
	while (temp) {
		curr = container_of(temp, struct extent_entry, node);
		bs2_info("pi %llu, extent offset %lu, length %lu, "
				"mmap addr %lx\n", pi->i_ino, curr->offset,
				curr->length, curr->mmap_addr);
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

