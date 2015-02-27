#include <iostream>
#include <sstream>
#include <iomanip>

#include "heap_safe.h"


unsigned int HeapSafeCheck = 0;
u_int64_t memoryStat[100000];
u_int32_t memoryStatLength = 0;
std::map<std::string, u_int32_t> memoryStatType;
volatile int memoryStat_sync;


inline void *_heapsafe_alloc(size_t sizeOfObject) {
	return(malloc(sizeOfObject));
}
 
inline void _heapsafe_free(void *pointerToObject) {
	free(pointerToObject);
}
 
inline void * heapsafe_safe_alloc(size_t sizeOfObject) { 
	void *pointerToObject = _heapsafe_alloc(sizeOfObject + HEAPSAFE_SAFE_ALLOC_RESERVE * 2);
	if(!pointerToObject) {
		HeapSafeAllocError(_HeapSafeErrorNotEnoughMemory);
	}
	return((char*)pointerToObject + HEAPSAFE_SAFE_ALLOC_RESERVE);
}

inline void * heapsafe_alloc(size_t sizeOfObject) { 
	extern unsigned int HeapSafeCheck;
	void *pointerToObject = NULL;
	int error = 0;
	try { 
		pointerToObject = _heapsafe_alloc(sizeOfObject + HEAPSAFE_ALLOC_RESERVE +
						  (HeapSafeCheck & _HeapSafeErrorBeginEnd ?
						    2 * sizeof(sHeapSafeMemoryControlBlock):
						    0));
	}
	catch(...) { 
		if(HeapSafeCheck & _HeapSafeErrorInAllocFce) {
			error = _HeapSafeErrorInAllocFce;
		}
	}
	if(!error && !pointerToObject) {
		error = _HeapSafeErrorNotEnoughMemory;
	}
	if(error) {
		      HeapSafeAllocError(error);
		return(pointerToObject);
	}
	memset(pointerToObject,
	       HeapSafeCheck & _HeapSafeErrorFillFF ? 0xFF : 0,
	       sizeOfObject + HEAPSAFE_ALLOC_RESERVE +
	       (HeapSafeCheck & _HeapSafeErrorBeginEnd ?
                2 * sizeof(sHeapSafeMemoryControlBlock):
		0));
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd) {
		sHeapSafeMemoryControlBlock *begin = (sHeapSafeMemoryControlBlock*)pointerToObject;
		HEAPSAFE_COPY_BEGIN_MEMORY_CONTROL_BLOCK(begin->stringInfo);
		begin->length = sizeOfObject;
		begin->memory_type = 0;
		sHeapSafeMemoryControlBlock *end = (sHeapSafeMemoryControlBlock*)
							((unsigned char*)pointerToObject + sizeOfObject + HEAPSAFE_ALLOC_RESERVE +
							 sizeof(sHeapSafeMemoryControlBlock));
		HEAPSAFE_COPY_END_MEMORY_CONTROL_BLOCK(end->stringInfo);
		end->length = sizeOfObject;
		end->memory_type = 0;
	}
	return((unsigned char*)pointerToObject +
	       (HeapSafeCheck & _HeapSafeErrorBeginEnd ?
		 sizeof(sHeapSafeMemoryControlBlock) :
		 0));
}

inline void heapsafe_safe_free(void *pointerToObject) {
	if(!pointerToObject) {
		return;
	}
	_heapsafe_free((char*)pointerToObject - HEAPSAFE_SAFE_ALLOC_RESERVE);
}

inline void heapsafe_free(void *pointerToObject) {
	extern unsigned int HeapSafeCheck;
	if(!pointerToObject) {
		return;
	}
	int error = 0;
	bool findBeginMemoryBlock = false;
	sHeapSafeMemoryControlBlock *beginMemoryBlock = NULL;
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd) {
		beginMemoryBlock = (sHeapSafeMemoryControlBlock*)((unsigned char*)pointerToObject - sizeof(sHeapSafeMemoryControlBlock));
		if(HEAPSAFE_CMP_BEGIN_MEMORY_CONTROL_BLOCK(beginMemoryBlock->stringInfo)) { 
			findBeginMemoryBlock = true;
			sHeapSafeMemoryControlBlock *end = (sHeapSafeMemoryControlBlock*)((unsigned char*)pointerToObject + beginMemoryBlock->length + HEAPSAFE_ALLOC_RESERVE);
			if(!HEAPSAFE_CMP_END_MEMORY_CONTROL_BLOCK(end->stringInfo)) {
				error = _HeapSafeErrorBeginEnd;
			} else if(HeapSafeCheck & _HeapSafeErrorFillFF) {
				memset(pointerToObject, 0xFF, beginMemoryBlock->length);
			}
			if(beginMemoryBlock->memory_type) {
				__sync_fetch_and_sub(&memoryStat[beginMemoryBlock->memory_type], beginMemoryBlock->length);
			}
		} else if(HeapSafeCheck & _HeapSafeErrorFreed&&
			  HEAPSAFE_CMP_FREED_MEMORY_CONTROL_BLOCK(beginMemoryBlock->stringInfo)) {
			error = _HeapSafeErrorFreed;
		} else {
			error = _HeapSafeErrorBeginEnd;
		}
	}
	if(HeapSafeCheck & _HeapSafeErrorAllocReserve &&
           findBeginMemoryBlock && !error) { 
		unsigned char *allocReserve = (unsigned char*)pointerToObject + beginMemoryBlock->length;
		int i;
		for(i = 0; i < HEAPSAFE_ALLOC_RESERVE && allocReserve[i] == (HeapSafeCheck & _HeapSafeErrorFillFF ? 0xFF : 0); i++);
		if(i<HEAPSAFE_ALLOC_RESERVE) {
			error = _HeapSafeErrorAllocReserve;
		}
        }
	if(!error) {
		try {
			if(findBeginMemoryBlock && beginMemoryBlock) {
				HEAPSAFE_COPY_FREED_MEMORY_CONTROL_BLOCK(beginMemoryBlock->stringInfo);
			}
			_heapsafe_free(findBeginMemoryBlock && beginMemoryBlock ? (void*)beginMemoryBlock : (void*)pointerToObject);
		}
		catch(...) {
			if(HeapSafeCheck & _HeapSafeErrorInAllocFce) {
				error = _HeapSafeErrorInAllocFce;
			}
		}
	}
	if(error) {
		HeapSafeAllocError(error);
	}
}


void * operator new(size_t sizeOfObject) { 
	return(HeapSafeCheck ?
		(HeapSafeCheck & _HeapSafeSafeReserve ?
		  heapsafe_safe_alloc(sizeOfObject) :
		  heapsafe_alloc(sizeOfObject)) :
		_heapsafe_alloc(sizeOfObject));
}
 
void * operator new[](size_t sizeOfObject) {
	return(HeapSafeCheck ? 
		(HeapSafeCheck & _HeapSafeSafeReserve ?
		  heapsafe_safe_alloc(sizeOfObject) :
		  heapsafe_alloc(sizeOfObject)) :
		_heapsafe_alloc(sizeOfObject));
}
 
void operator delete(void *pointerToObject) {
	if(HeapSafeCheck)
	 if(HeapSafeCheck & _HeapSafeSafeReserve)
	  heapsafe_safe_free(pointerToObject);
	 else
	  heapsafe_free(pointerToObject);
	else 
	 _heapsafe_free(pointerToObject);
}
 
void operator delete[](void *pointerToObject) {
	if(HeapSafeCheck)
	 if(HeapSafeCheck & _HeapSafeSafeReserve)
	  heapsafe_safe_free(pointerToObject);
	 else
	  heapsafe_free(pointerToObject);
	else 
	 _heapsafe_free(pointerToObject);
}


void HeapSafeAllocError(int error) {
	if(error) {
		const char *errorString =
			error & _HeapSafeErrorBeginEnd ?
				"Cannot find begin of memory block or corrupt end of memory block." :
			error & _HeapSafeErrorFreed ?
				"Memory block is freed." :
			error & _HeapSafeErrorAllocReserve ?
				"Using alloc reserve." :
			error & _HeapSafeErrorInHeap ?
				"Heap corrupted." :
			error & _HeapSafeErrorInAllocFce ?
				"Error in allocation function." :
			error & _HeapSafeErrorNotEnoughMemory ?
				"Not enough memory." :
				NULL;
		if(errorString) {
			syslog(LOG_ERR, "HEAPSAFE ALLOCATION ERROR: %s", errorString);
		}
	}
}

void HeapSafeMemcpyError(const char *errorString, const char *file, unsigned int line) {
	if(errorString) {
		syslog(LOG_ERR, "HEAPSAFE MEMCPY ERROR: %s - %s:%d", errorString, 
		       file ? file : "unknown source file", line);
	}
}

void HeapSafeMemsetError(const char *errorString, const char *file, unsigned int line) {
	if(errorString) {
		syslog(LOG_ERR, "HEAPSAFE MEMSET ERROR: %s - %s:%d", errorString, 
		       file ? file : "unknown source file", line);
	}
}

std::string getMemoryStat() {
	extern sVerbose sverb;
	std::ostringstream outStr;
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd && sverb.memory_stat) {
		while(__sync_lock_test_and_set(&memoryStat_sync, 1));
		std::map<std::string, u_int32_t>::iterator iter = memoryStatType.begin();
		while(iter != memoryStatType.end()) {
			if(memoryStat[iter->second] > 0) {
				outStr << std::fixed
				       << std::left << std::setw(30) << iter->first << " : " 
				       << std::right <<  std::setw(12) << memoryStat[iter->second] << std::endl;
			}
			++iter;
		}
		__sync_lock_release(&memoryStat_sync);
		return(outStr.str());
	} else {
		return("memory stat is not activated\n");
	}
}

void printMemoryStat() {
	std::cout << getMemoryStat();
}
