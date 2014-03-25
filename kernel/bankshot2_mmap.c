#include <linux/mman.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include "bankshot2.h"

unsigned long vm_mmap_pgoff(struct file *file, unsigned long addr,
		unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;
	struct mm_struct *mm = current->mm;
	unsigned long populate;

//	ret = security_mmap_file(file, prot, flag);
	ret = 0;
	if (!ret) {
		down_write(&mm->mmap_sem);
		ret = do_mmap_pgoff(file, addr, len, prot, flag, pgoff,
					&populate);
		up_write(&mm->mmap_sem);
		if (populate)
			mm_populate(ret, populate);
	}
	return ret;
}

unsigned long bankshot2_mmap(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long pgoff)
{
	struct file *file = NULL;
	unsigned long retval = -EBADF;

//	audit_mmap_fd(fd, flags);
	file = fget(fd);
	if (!file)
		goto out;
//	if (is_file_hugepages(file))
//		len = ALIGN(len, huge_page_size(hstate_file(file)));
	retval = -EINVAL;
//	if (unlikely(flags & MAP_HUGETLB && !is_file_hugepages(file)))
//		goto out_fput;

	//FIXME: ignore MAP_HUGETLB;

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);

	retval = vm_mmap_pgoff(file, addr, len, prot, flags, pgoff);

//out_fput:
	if (file)
		fput(file);
out:
	return retval;
}

