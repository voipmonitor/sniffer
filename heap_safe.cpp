#include <iostream>
#include <sstream>
#include <iomanip>
#include <malloc.h>
#include <execinfo.h>

#include "heap_safe.h"
#include "tools.h"

extern sVerbose sverb;

unsigned int HeapSafeCheck = 0;
volatile u_int64_t memoryStat[10000];
volatile u_int64_t memoryStatOther[10000];
u_int32_t memoryStatLength = 0;
u_int32_t memoryStatOtherLength = 0;
volatile int64_t memoryStatOtherSum;
std::map<std::string, u_int32_t> memoryStatType;
std::map<u_int64_t, u_int32_t> memoryStatOtherType;
std::map<u_int32_t, string> memoryStatOtherName;
volatile int memoryStat_sync;
volatile u_int16_t threadRecursion[65536];


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
						    (SIZEOF_MCB + sizeof(sHeapSafeMemoryControlBlock)) :
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
                (SIZEOF_MCB + sizeof(sHeapSafeMemoryControlBlock)) :
		0));
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd) {
		sHeapSafeMemoryControlBlock *begin = (sHeapSafeMemoryControlBlock*)pointerToObject;
		HEAPSAFE_COPY_BEGIN_MEMORY_CONTROL_BLOCK(begin->stringInfo);
		begin->length = sizeOfObject;
		begin->memory_type = 0;
		sHeapSafeMemoryControlBlock *end = (sHeapSafeMemoryControlBlock*)
							((unsigned char*)pointerToObject + sizeOfObject + HEAPSAFE_ALLOC_RESERVE +
							 SIZEOF_MCB);
		HEAPSAFE_COPY_END_MEMORY_CONTROL_BLOCK(end->stringInfo);
		end->length = sizeOfObject;
		end->memory_type = 0;
		if(sverb.memory_stat) {
			if(MCB_STACK) {
				unsigned int tid = get_unix_tid();
				sHeapSafeMemoryControlBlockEx *beginEx = (sHeapSafeMemoryControlBlockEx*)begin;
				if(!threadRecursion[tid]) {
					uint skip_top_traces = 2;
					uint max_use_trace_size = 10;
					uint max_trace_size = skip_top_traces + max_use_trace_size;
					void* stack_addr[max_trace_size];
					uint trace_size = backtrace(stack_addr, max_trace_size);
					u_int64_t sum_stack_addr = 0;
					for(uint i = 0; i < trace_size - skip_top_traces; i++) {
						sum_stack_addr += (u_int64_t)stack_addr[i + skip_top_traces];
					}
					while(__sync_lock_test_and_set(&memoryStat_sync, 1));
					__sync_fetch_and_add(&threadRecursion[tid], 1);
					std::map<u_int64_t, u_int32_t>::iterator iter = memoryStatOtherType.find(sum_stack_addr);
					if(iter == memoryStatOtherType.end()) {
						beginEx->memory_type_other = ++memoryStatOtherLength;;
						memoryStatOtherType[sum_stack_addr] = beginEx->memory_type_other;
						
						char trace_string[max_use_trace_size * 100];
						trace_string[0] = '\0';
						
						char **messages = backtrace_symbols(stack_addr, trace_size);
						
						for(uint i = 0; i < trace_size - skip_top_traces; i++) {
							if(i) {
								strcat(trace_string, " / ");
							}
							if(strstr(messages[i + skip_top_traces], "libstdc++")) {
								strcat(trace_string, "stdc++");
							} else if(strstr(messages[i + skip_top_traces], "libc")) {
								strcat(trace_string, "libc");
							} else if(strstr(messages[i + skip_top_traces], "voipmonitor()")) {
								sprintf(trace_string + strlen(trace_string), "%lx", (u_int64_t)stack_addr[i + skip_top_traces]);
							} else {
								strcat(trace_string, messages[i + skip_top_traces]);
							}
						}
						memoryStatOtherName[beginEx->memory_type_other] = trace_string;
					} else {
						beginEx->memory_type_other = iter->second;
					}
					__sync_fetch_and_sub(&threadRecursion[tid], 1);
					__sync_lock_release(&memoryStat_sync);
					__sync_fetch_and_add(&memoryStatOther[beginEx->memory_type_other], sizeOfObject);
				} else {
					beginEx->memory_type_other = 0;
					__sync_fetch_and_add(&memoryStatOtherSum, sizeOfObject);
				}
			} else {
				__sync_fetch_and_add(&memoryStatOtherSum, sizeOfObject);
			}
		}
	}
	return((unsigned char*)pointerToObject +
	       (HeapSafeCheck & _HeapSafeErrorBeginEnd ?
		 SIZEOF_MCB :
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
		beginMemoryBlock = (sHeapSafeMemoryControlBlock*)((unsigned char*)pointerToObject - SIZEOF_MCB);
		if(HEAPSAFE_CMP_BEGIN_MEMORY_CONTROL_BLOCK(beginMemoryBlock->stringInfo)) { 
			findBeginMemoryBlock = true;
			sHeapSafeMemoryControlBlock *end = (sHeapSafeMemoryControlBlock*)((unsigned char*)pointerToObject + beginMemoryBlock->length + HEAPSAFE_ALLOC_RESERVE);
			if(!HEAPSAFE_CMP_END_MEMORY_CONTROL_BLOCK(end->stringInfo)) {
				error = _HeapSafeErrorBeginEnd;
			} else if(HeapSafeCheck & _HeapSafeErrorFillFF) {
				memset(pointerToObject, 0xFF, beginMemoryBlock->length);
			}
			if(sverb.memory_stat) {
				if(beginMemoryBlock->memory_type) {
					__sync_fetch_and_sub(&memoryStat[beginMemoryBlock->memory_type], beginMemoryBlock->length);
				} else if(MCB_STACK && ((sHeapSafeMemoryControlBlockEx*)beginMemoryBlock)->memory_type_other) {
					__sync_fetch_and_sub(&memoryStatOther[((sHeapSafeMemoryControlBlockEx*)beginMemoryBlock)->memory_type_other], beginMemoryBlock->length);
				} else {
					__sync_fetch_and_sub(&memoryStatOtherSum, beginMemoryBlock->length);
				}
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

std::string getMemoryStat(bool all) {
	std::ostringstream outStr;
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd && sverb.memory_stat) {
		unsigned int tid = get_unix_tid();
		__sync_fetch_and_add(&threadRecursion[tid], 1);
		while(__sync_lock_test_and_set(&memoryStat_sync, 1));
		std::map<std::string, u_int32_t>::iterator iter = memoryStatType.begin();
		while(iter != memoryStatType.end()) {
			if(memoryStat[iter->second] > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
				outStr << std::fixed
				       << std::left << std::setw(30) << iter->first << " : " 
				       << std::right << std::setw(16) << addThousandSeparators(memoryStat[iter->second])
				       << std::endl;
			}
			++iter;
		}
		std::map<u_int64_t, u_int32_t>::iterator iterOther = memoryStatOtherType.begin();
		while(iterOther != memoryStatOtherType.end()) {
			if(memoryStatOther[iterOther->second] > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
				outStr << std::fixed
				       << std::left << memoryStatOtherName[iterOther->second] << " : " 
				       << std::right << addThousandSeparators(memoryStatOther[iterOther->second])
				       << std::endl;
			}
			++iterOther;
		}
		__sync_lock_release(&memoryStat_sync);
		if(memoryStatOtherSum > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
			if(MCB_STACK) {
				outStr << std::fixed
				       << std::left << "other" << " : " 
				       << std::right << addThousandSeparators(memoryStatOtherSum)
				       << std::endl;
			} else {
				outStr << std::fixed
				       << std::left << std::setw(30) << "other" << " : " 
				       << std::right << std::setw(16) << addThousandSeparators(memoryStatOtherSum)
				       << std::endl;
			}
		}
		__sync_fetch_and_sub(&threadRecursion[tid], 1);
		return(outStr.str());
	} else {
		return("memory stat is not activated\n");
	}
}

std::string addThousandSeparators(u_int64_t num) {
	char length_str[20];
	sprintf(length_str, "%lu", num);
	std::string length;
	while(strlen(length_str) > 3) {
		length = std::string(length_str + strlen(length_str) - 3) + " " + length;
		length_str[strlen(length_str) - 3] = 0;
	}
	length = std::string(length_str) + " " + length;
	return(length);
}

void printMemoryStat(bool all) {
	malloc_trim(0);
	std::cout << getMemoryStat(all);
}
