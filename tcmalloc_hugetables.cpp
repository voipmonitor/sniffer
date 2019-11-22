#include "voipmonitor.h"

#if HAVE_LIBTCMALLOC

#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <gperftools/malloc_extension.h>
#include <syslog.h>
#include <errno.h>

#include "log_buffer.h"


extern cLogBuffer *logBuffer;
extern bool opt_hugepages_anon;
extern int opt_hugepages_max;
extern int opt_hugepages_overcommit_max;


class HugetlbSysAllocator: public SysAllocator {
public:
	HugetlbSysAllocator(SysAllocator* fallback)
	: failed_(true),  // To disable allocator until Initialize() is called.
	  big_page_size_(0),
	  hugetlb_fd_(-1),
	  hugetlb_base_(0),
	  fallback_(fallback) {
	}
	void* Alloc(size_t size, size_t *actual_size, size_t alignment);
	bool Initialize();
	
	u_int64_t getBase() {
		return(hugetlb_base_);
	}

	bool failed_;          // Whether failed to allocate memory.

private:
	void* AllocInternal(size_t size, size_t *actual_size, size_t alignment);
  
	int64_t big_page_size_;
	int hugetlb_fd_;       // file descriptor for hugetlb
	off_t hugetlb_base_;

	SysAllocator* fallback_;  // Default system allocator to fall back to.
};


static HugetlbSysAllocator *hugetlbSysAllocator;


void* HugetlbSysAllocator::Alloc(size_t size, size_t *actual_size,
                                 size_t alignment) {
	if (failed_) {
		return fallback_->Alloc(size, actual_size, alignment);
	}

	// We don't respond to allocation requests smaller than big_page_size_ unless
	// the caller is ok to take more than they asked for. Used by MetaDataAlloc.
	if (actual_size == NULL && size < big_page_size_) {
		return fallback_->Alloc(size, actual_size, alignment);
	}

	// Enforce huge page alignment.  Be careful to deal with overflow.
	size_t new_alignment = alignment;
	if (new_alignment < big_page_size_) new_alignment = big_page_size_;
	size_t aligned_size = ((size + new_alignment - 1) / new_alignment) * new_alignment;
	if (aligned_size < size) {
		return fallback_->Alloc(size, actual_size, alignment);
	}

	void* result = AllocInternal(aligned_size, actual_size, new_alignment);
	if (result != NULL) {
		return result;
	}
	
	return fallback_->Alloc(size, actual_size, alignment);
}

void* HugetlbSysAllocator::AllocInternal(size_t size, size_t* actual_size,
                                         size_t alignment) {
	if(opt_hugepages_anon) {
		size_t pagesize = getpagesize();
		if (alignment < pagesize) alignment = pagesize;
		size_t aligned_size = ((size + alignment - 1) / alignment) * alignment;
		if (aligned_size < size) {
			return NULL;
		}
		size = aligned_size;

		// "actual_size" indicates that the bytes from the returned pointer
		// p up to and including (p + actual_size - 1) have been allocated.
		if (actual_size) {
			*actual_size = size;
		}

		// Ask for extra memory if alignment > pagesize
		size_t extra = 0;
		if (alignment > pagesize) {
			extra = alignment - pagesize;
		}

		// Note: size + extra does not overflow since:
		//            size + alignment < (1<<NBITS).
		// and        extra <= alignment
		// therefore  size + extra < (1<<NBITS)
		void* result = mmap(NULL, size + extra,
				    PROT_READ|PROT_WRITE,
				    MAP_PRIVATE|MAP_ANONYMOUS,
				    -1, 0);
		
		if (result == reinterpret_cast<void*>(MAP_FAILED)) {
			return NULL;
		}
		
		// Adjust the return memory so it is aligned
		uintptr_t ptr = reinterpret_cast<uintptr_t>(result);
		size_t adjust = 0;
		if ((ptr & (alignment - 1)) != 0) {
			adjust = alignment - (ptr & (alignment - 1));
		}

		// Return the unused memory to the system
		if (adjust > 0) {
			munmap(reinterpret_cast<void*>(ptr), adjust);
		}
		if (adjust < extra) {
			munmap(reinterpret_cast<void*>(ptr + adjust + size), extra - adjust);
		}

		ptr += adjust;
		
		madvise((void*)ptr, size, MADV_HUGEPAGE);

		return reinterpret_cast<void*>(ptr);
	} else {
		// Ask for extra memory if alignment > pagesize
		size_t extra = 0;
		if (alignment > big_page_size_) {
			extra = alignment - big_page_size_;
		}

		// This is not needed for hugetlbfs, but needed for tmpfs.  Annoyingly
		// hugetlbfs returns EINVAL for ftruncate.
		int ret = ftruncate(hugetlb_fd_, hugetlb_base_ + size + extra);
		if (ret != 0 && errno != EINVAL) {
			failed_ = true;
			if(logBuffer) {
				logBuffer->add(LOG_WARNING, "hugepages error: ftruncate failed '%'", strerror(errno));
			}
			return NULL;
		}

		// Note: size + extra does not overflow since:
		//            size + alignment < (1<<NBITS).
		// and        extra <= alignment
		// therefore  size + extra < (1<<NBITS)
		void *result;
		result = mmap(0, size + extra, PROT_WRITE|PROT_READ,
			      MAP_SHARED,
			      hugetlb_fd_, hugetlb_base_);
		if (result == reinterpret_cast<void*>(MAP_FAILED)) {
			failed_ = true;
			if(logBuffer) {
				logBuffer->add(LOG_WARNING, "hugepages error: mmap failed '%'", strerror(errno));
			}
			return NULL;
		}
		
		uintptr_t ptr = reinterpret_cast<uintptr_t>(result);

		// Adjust the return memory so it is aligned
		size_t adjust = 0;
		if ((ptr & (alignment - 1)) != 0) {
			adjust = alignment - (ptr & (alignment - 1));
		}
		ptr += adjust;
		hugetlb_base_ += (size + extra);

		if (actual_size) {
			*actual_size = size + extra - adjust;
		}

		return reinterpret_cast<void*>(ptr);
	}
}

bool HugetlbSysAllocator::Initialize() {
 
	char path[PATH_MAX];
	strcpy(path, "/dev/hugepages/voipmonitor");
	strcat(path, ".XXXXXX");

	int hugetlb_fd = mkstemp(path);
	if (hugetlb_fd == -1) {
		syslog(LOG_WARNING, "hugepages error: unable to create memfs_malloc_path");
		return false;
	}

	// Cleanup memory on process exit
	if (unlink(path) == -1) {
		syslog(LOG_WARNING, "hugepages error: failed unlinking memfs_malloc_path '%s' error: '%s'", path, strerror(errno));
		return false;
	}

	// Use fstatfs to figure out the default page size for memfs
	struct statfs sfs;
	if (fstatfs(hugetlb_fd, &sfs) == -1) {
		syslog(LOG_WARNING, "hugepages error: failed fstatfs of memfs_malloc_path '%s'", strerror(errno));
		return false;
	}
	int64_t page_size = sfs.f_bsize;

	hugetlb_fd_ = hugetlb_fd;
	big_page_size_ = page_size;
	failed_ = false;
	
	if(!opt_hugepages_anon) {
		for(int type_max = 0; type_max < 2; type_max++) {
			int need_hugepages_max = ((u_int64_t)(type_max == 0 ? opt_hugepages_max : opt_hugepages_overcommit_max) * 1024ull * 1024 / big_page_size_);
			int act_hugepages_max = 0;
			const char *hugepages_config_max = type_max == 0 ? "/proc/sys/vm/nr_hugepages" : "/proc/sys/vm/nr_overcommit_hugepages";
			for(int pass = 0; pass < 2; pass++) {
				FILE *f = fopen(hugepages_config_max, pass == 0 ? "r" : "w");
				if (f) {
					if(pass == 0) {
						fscanf(f, "%i", &act_hugepages_max);
					} else {
						system("echo 3 > /proc/sys/vm/drop_caches");
						system("echo 1 > /proc/sys/vm/compact_memory");
						fprintf(f, "%i", (int)need_hugepages_max);
					}
					fclose(f);
					if(pass == 0 && need_hugepages_max <= act_hugepages_max) {
						break;
					}
				} else {
					syslog(LOG_WARNING, "hugepages error: failed open for %s: '%s' error: '%s'", 
					       pass == 0 ? "read" : "write", hugepages_config_max, strerror(errno));
					return false;
				}
			}
		}
	}
 
	return true;
}

bool HugetlbSysAllocator_init() {
	SysAllocator* alloc = MallocExtension::instance()->GetSystemAllocator();
	HugetlbSysAllocator* hp = new HugetlbSysAllocator(alloc);
	if (hp->Initialize()) {
	       MallocExtension::instance()->SetSystemAllocator(hp);
	       hugetlbSysAllocator = hp;
	       return(true);
	}
	return(false);
}


u_int64_t HugetlbSysAllocator_base() {
	if(hugetlbSysAllocator) {
		return(hugetlbSysAllocator->getBase());
	}
	return(0);
}

#else

bool HugetlbSysAllocator_init() {
	return(false);
}

u_int64_t HugetlbSysAllocator_base() {
	return(0);
}

#endif
