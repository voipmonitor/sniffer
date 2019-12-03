#ifndef TCMALLOC_HUGEPAGES_H
#define TCMALLOC_HUGEPAGES_H

bool HugetlbSysAllocator_init();
u_int64_t HugetlbSysAllocator_base();

bool init_hugepages(int *fd, int64_t *page_size);
void *mmap_hugepage(int mmap_fd, long int mmap_offset, bool use_ftruncate,
		    size_t size, size_t *actual_size, size_t *mmap_size,
		    size_t alignment, size_t pagesize, 
		    bool anon, bool *failed);
void munmap_hugepage(void *ptr, size_t size);

#endif
