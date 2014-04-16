#include "bankshot2.h"
#include "bankshot2_cache.h"

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

int bankshot2_add_extent(struct bankshot2_device *bs2_dev,
		struct bankshot2_inode *pi, struct bankshot2_cache_data *data)
{
	struct extent_entry *new, *curr, *prev, *next;
	struct rb_node *pre_node, *next_node;
	struct rb_node **temp, *parent;
	int compVal;

	new = kzalloc(sizeof(struct extent_entry), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->offset = data->offset;
	new->length = data->size;
	new->mmap_addr = data->mmap_addr;
	new->dirty = 1; //FIXME: We need to assume all extents are dirty
//	rb_init_node(&new->node);

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
			kfree(new);
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
			kfree(new);
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
			kfree(next);
		} else {
			break;
		}
	}

	write_unlock(&pi->extent_tree_lock);
	return 0;
}
