#include <iostream>
#include <sstream>
#include <iomanip>
#include <execinfo.h>

#include "heap_safe.h"
#include "tools.h"
#include "common.h"

#ifndef FREEBSD
#include <malloc.h>
#endif

//#ifdef HEAP_CHUNK_ENABLE
#include "heap_chunk.h"
//#endif

extern sVerbose sverb;

unsigned int HeapSafeCheck = 0;
unsigned int MemoryStatQuick = 0;
unsigned int HeapChunk = 0;
volatile u_int64_t *memoryStat;
volatile u_int64_t *memoryStatOther;
u_int32_t memoryStatLength = 0;
u_int32_t memoryStatOtherLength = 0;
volatile int64_t memoryStatOtherSum;
std::map<std::string, u_int32_t> memoryStatType;
std::map<u_int64_t, u_int32_t> memoryStatOtherType;
std::map<u_int32_t, string> memoryStatOtherName;
volatile int memoryStat_sync;
volatile u_int16_t threadRecursion[65536];
void* threadStack[65536][10];
u_int16_t threadStackSize[65536];
bool notEnoughFreeMemory = false;

sFileLine AllocFileLines[] = {
#include "alloc_file_lines"
};


#ifdef HEAP_CHUNK_ENABLE
extern cHeap *heap_vm;
extern bool heap_vm_active;
extern size_t heap_vm_size_call;
extern size_t heap_vm_size_packetbuffer;

static unsigned heap_vm_shift = 4;
#endif //HEAP_CHUNK_ENABLE


inline void *_heapsafe_alloc(size_t sizeOfObject) {
	#ifdef HEAP_CHUNK_ENABLE
	if(heap_vm_active && 
	   (sizeOfObject == heap_vm_size_call || sizeOfObject == heap_vm_size_packetbuffer)) {
		u_int16_t heapItemIndex;
		void *ptr = heap_vm->MAlloc(sizeOfObject + heap_vm_shift, &heapItemIndex);
		if(ptr) {
			*(u_int16_t*)ptr = heapItemIndex;
			return((char*)ptr + heap_vm_shift);
		}
	}
	#endif //HEAP_CHUNK_ENABLE
	return(malloc(sizeOfObject));
}
 
inline void _heapsafe_free(void *pointerToObject) {
	#ifdef HEAP_CHUNK_ENABLE
	if(heap_vm_active && (char*)pointerToObject > heap_vm->getMinPtr()) {
		char *_pointerToObject = (char*)pointerToObject - heap_vm_shift;
		if(heap_vm->Free(_pointerToObject, *(u_int16_t*)_pointerToObject)) {
			return;
		}
	}
	#endif //HEAP_CHUNK_ENABLE
	free(pointerToObject);
}

inline void *_heapsafe_realloc(void *pointerToObject, size_t sizeOfObject) {
	#ifdef HEAP_CHUNK_ENABLE
	if(heap_vm_active && (char*)pointerToObject > heap_vm->getMinPtr()) {
		_heapsafe_free(pointerToObject);
		return(_heapsafe_alloc(sizeOfObject));
	}
	#endif //HEAP_CHUNK_ENABLE
	return(realloc(pointerToObject, sizeOfObject));
}
 
inline void * heapsafe_safe_alloc(size_t sizeOfObject) { 
	void *pointerToObject = _heapsafe_alloc(sizeOfObject + HEAPSAFE_SAFE_ALLOC_RESERVE * 2);
	if(!pointerToObject) {
		HeapSafeAllocError(_HeapSafeErrorNotEnoughMemory);
	}
	return((char*)pointerToObject + HEAPSAFE_SAFE_ALLOC_RESERVE);
}

inline void * heapsafe_alloc(size_t sizeOfObject, const char *memory_type1 = NULL, int memory_type2 = 0) { 
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
		if(MCB_PLUS) {
			((sHeapSafeMemoryControlBlockPlus*)begin)->block_addr = (void*)((unsigned long)begin + sizeof(sHeapSafeMemoryControlBlockPlus));
			if(memory_type1) {
				#if __GNUC__ >= 8
				#pragma GCC diagnostic push
				#pragma GCC diagnostic ignored "-Wstringop-truncation"
				#endif
				strncpy(((sHeapSafeMemoryControlBlockPlus*)begin)->memory_type1, memory_type1, 20);
				#if __GNUC__ >= 8
				#pragma GCC diagnostic pop
				#endif
			}
			if(memory_type2) {
				((sHeapSafeMemoryControlBlockPlus*)begin)->memory_type2 = memory_type2;
			}
			u_int16_t check_sum = 0;
			u_char *start_check_sum = (u_char*)&((sHeapSafeMemoryControlBlockPlus*)begin)->block_addr;
			u_char *end_check_sum = (u_char*)&((sHeapSafeMemoryControlBlockPlus*)begin)->check_sum;
			for(u_char *ch = start_check_sum; ch < end_check_sum; ch++) {
				check_sum += *ch;
			}
			((sHeapSafeMemoryControlBlockPlus*)begin)->check_sum = check_sum;
		}
		sHeapSafeMemoryControlBlock *end = (sHeapSafeMemoryControlBlock*)
							((unsigned char*)pointerToObject + sizeOfObject + HEAPSAFE_ALLOC_RESERVE +
							 SIZEOF_MCB);
		HEAPSAFE_COPY_END_MEMORY_CONTROL_BLOCK(end->stringInfo);
		end->length = sizeOfObject;
		end->memory_type = 0;
#ifndef FREEBSD
		if(sverb.memory_stat) {
			if(memory_type1) {
				std::string memory_type = memory_type1;
				if(memory_type2) {
					char memory_type2_str[20];
					snprintf(memory_type2_str, sizeof(memory_type2_str), " %i", memory_type2);
					memory_type.append(memory_type2_str);
				}
				while(__sync_lock_test_and_set(&memoryStat_sync, 1));
				std::map<std::string, u_int32_t>::iterator iter = memoryStatType.find(memory_type);
				if(iter == memoryStatType.end()) {
					begin->memory_type = ++memoryStatLength;
					unsigned int tid = 0;
					if(MCB_STACK) {
						tid = get_unix_tid();
						__sync_fetch_and_add(&threadRecursion[tid], 1);
					}
					memoryStatType[memory_type] = begin->memory_type;
					if(tid) {
						__sync_fetch_and_sub(&threadRecursion[tid], 1);
					}
				} else {
					begin->memory_type = iter->second;
				}
				__sync_lock_release(&memoryStat_sync);
				__sync_fetch_and_add(&memoryStat[begin->memory_type], sizeOfObject);
			} else if(MCB_STACK) {
				unsigned int tid = get_unix_tid();
				sHeapSafeMemoryControlBlockEx *beginEx = (sHeapSafeMemoryControlBlockEx*)begin;
				if(!threadRecursion[tid]) {
					if(threadStackSize[tid]) {
						uint use_trace_size = min(10, (int)threadStackSize[tid]);
						u_int64_t sum_stack_addr = 0;
						for(uint i = 0; i < use_trace_size; i++) {
							sum_stack_addr += (u_int64_t)threadStack[tid][i];
						}
						while(__sync_lock_test_and_set(&memoryStat_sync, 1));
						std::map<u_int64_t, u_int32_t>::iterator iter = memoryStatOtherType.find(sum_stack_addr);
						if(iter == memoryStatOtherType.end()) {
							__sync_fetch_and_add(&threadRecursion[tid], 1);
							beginEx->memory_type_other = ++memoryStatOtherLength;;
							memoryStatOtherType[sum_stack_addr] = beginEx->memory_type_other;
							__sync_lock_release(&memoryStat_sync);
							char trace_string[use_trace_size * 100];
							trace_string[0] = '\0';
							/*
							char **messages = backtrace_symbols(threadStack[tid], use_trace_size);
							for(uint i = 0; i < use_trace_size; i++) {
								if(i) {
									strcat(trace_string, " / ");
								}
								if(strstr(messages[i], "libstdc++")) {
									strcat(trace_string, "stdc++");
								} else if(strstr(messages[i], "libc")) {
									strcat(trace_string, "libc");
								} else if(strstr(messages[i], "voipmonitor()")) {
									sprintf(trace_string + strlen(trace_string), "%lx", (u_int64_t)threadStack[tid][i]);
								} else {
									strcat(trace_string, messages[i]);
								}
							}
							*/
							for(uint i = 0; i < use_trace_size; i++) {
								if(i) {
									strcat(trace_string, " / ");
								}
								sprintf(trace_string + strlen(trace_string), "%" int_64_format_prefix "lx", (u_int64_t)threadStack[tid][i]);
							}
							while(__sync_lock_test_and_set(&memoryStat_sync, 1));
							memoryStatOtherName[beginEx->memory_type_other] = trace_string;
							__sync_lock_release(&memoryStat_sync);
							__sync_fetch_and_sub(&threadRecursion[tid], 1);
						} else {
							__sync_lock_release(&memoryStat_sync);
							beginEx->memory_type_other = iter->second;
						}
						__sync_fetch_and_add(&memoryStatOther[beginEx->memory_type_other], sizeOfObject);
					} else {
						uint skip_top_traces = 2;
						uint max_use_trace_size = 8;
						uint max_trace_size = skip_top_traces + max_use_trace_size;
						void* stack_addr[max_trace_size];
						uint trace_size = backtrace(stack_addr, max_trace_size);
						if(trace_size) {
							u_int64_t sum_stack_addr = 0;
							for(uint i = 0; i < trace_size - skip_top_traces; i++) {
								sum_stack_addr += (u_int64_t)stack_addr[i + skip_top_traces];
							}
							while(__sync_lock_test_and_set(&memoryStat_sync, 1));
							std::map<u_int64_t, u_int32_t>::iterator iter = memoryStatOtherType.find(sum_stack_addr);
							if(iter == memoryStatOtherType.end()) {
								__sync_fetch_and_add(&threadRecursion[tid], 1);
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
										sprintf(trace_string + strlen(trace_string), "%" int_64_format_prefix "lx", (u_int64_t)stack_addr[i + skip_top_traces]);
									} else {
										strcat(trace_string, messages[i + skip_top_traces]);
									}
								}
								memoryStatOtherName[beginEx->memory_type_other] = trace_string;
								__sync_fetch_and_sub(&threadRecursion[tid], 1);
							} else {
								beginEx->memory_type_other = iter->second;
							}
							__sync_lock_release(&memoryStat_sync);
							__sync_fetch_and_add(&memoryStatOther[beginEx->memory_type_other], sizeOfObject);
						}
					}
				} else {
					beginEx->memory_type_other = 0;
					__sync_fetch_and_add(&memoryStatOtherSum, sizeOfObject);
				}
			} else {
				__sync_fetch_and_add(&memoryStatOtherSum, sizeOfObject);
			}
		}
#endif
	}
	return((unsigned char*)pointerToObject +
	       (HeapSafeCheck & _HeapSafeErrorBeginEnd ?
		 SIZEOF_MCB :
		 0));
}

inline void * alloc_memory_stat_quick(size_t sizeOfObject, int alloc_number = 0) { 
	void *pointerToObject = NULL;
	try { 
		pointerToObject = _heapsafe_alloc(sizeOfObject + sizeof(sMemoryStatQuickBlock));
	}
	catch(...) { 
		return(NULL);
	}
	((sMemoryStatQuickBlock*)pointerToObject)->alloc_number = alloc_number;
	((sMemoryStatQuickBlock*)pointerToObject)->size = sizeOfObject;
	__sync_add_and_fetch(&memoryStat[alloc_number], sizeOfObject);
	return((unsigned char*)pointerToObject + sizeof(sMemoryStatQuickBlock));
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
			} else if(MCB_PLUS) {
				memset(pointerToObject, 0, beginMemoryBlock->length);
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
        if(!error &&
	   MCB_PLUS &&
	   beginMemoryBlock) {
		u_char *start_check_sum = (u_char*)&((sHeapSafeMemoryControlBlockPlus*)beginMemoryBlock)->block_addr;
		u_char *end_check_sum = (u_char*)&((sHeapSafeMemoryControlBlockPlus*)beginMemoryBlock)->check_sum;
		u_int16_t check_sum = 0;
		for(u_char *ch = start_check_sum; ch < end_check_sum; ch++) {
			check_sum += *ch;
		}
		if(((sHeapSafeMemoryControlBlockPlus*)beginMemoryBlock)->check_sum != check_sum) {
			error = _HeapSafeErrorBeginEnd;
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

inline void free_memory_stat_quick(void *pointerToObject) {
	if(pointerToObject) {
		sMemoryStatQuickBlock *memoryStatQuickBlock = (sMemoryStatQuickBlock *)((unsigned char*)pointerToObject - sizeof(sMemoryStatQuickBlock));
		__sync_sub_and_fetch(&memoryStat[memoryStatQuickBlock->alloc_number], memoryStatQuickBlock->size);
		free(memoryStatQuickBlock);
	}
}

inline void *heapsafe_safe_realloc(void *pointerToObject, size_t sizeOfObject) {
	char *_pointerToBegin;
	if(pointerToObject) {
		_pointerToBegin = (char*)pointerToObject - HEAPSAFE_SAFE_ALLOC_RESERVE;
	} else {
		_pointerToBegin = NULL;
	}
	_pointerToBegin = (char*)_heapsafe_realloc(_pointerToBegin, sizeOfObject + HEAPSAFE_SAFE_ALLOC_RESERVE * 2);
	if(!_pointerToBegin) {
		HeapSafeAllocError(_HeapSafeErrorNotEnoughMemory);
	}
	return(_pointerToBegin + HEAPSAFE_SAFE_ALLOC_RESERVE);
}

inline void * heapsafe_realloc(void *pointerToObject, size_t sizeOfObject, const char *memory_type1 = NULL, int memory_type2 = 0) { 
	size_t oldSize = 0;
	if(pointerToObject) {
		sHeapSafeMemoryControlBlock *beginMemoryBlock = NULL;
		if(HeapSafeCheck & _HeapSafeErrorBeginEnd) {
			beginMemoryBlock = (sHeapSafeMemoryControlBlock*)((unsigned char*)pointerToObject - SIZEOF_MCB);
			if(HEAPSAFE_CMP_BEGIN_MEMORY_CONTROL_BLOCK(beginMemoryBlock->stringInfo)) {
				oldSize = beginMemoryBlock->length;
			}
		}
	}
	if(sizeOfObject <= oldSize) {
		return(pointerToObject);
	}
	void *newPointerToObject = heapsafe_alloc(sizeOfObject, memory_type1, memory_type2);
	if(newPointerToObject) {
		if(oldSize) {
			memcpy(newPointerToObject, pointerToObject, min(oldSize, sizeOfObject));
		}
	}
	if(pointerToObject) {
		heapsafe_free(pointerToObject);
	}
	return(newPointerToObject);
}

inline void * realloc_memory_stat_quick(void *pointerToObject, size_t sizeOfObject, int alloc_number = 0) { 
	size_t oldSize = 0;
	if(pointerToObject) {
		sMemoryStatQuickBlock *memoryStatQuickBlock = (sMemoryStatQuickBlock *)((unsigned char*)pointerToObject - sizeof(sMemoryStatQuickBlock));
		oldSize = memoryStatQuickBlock->size;
	}
	if(sizeOfObject <= oldSize) {
		return(pointerToObject);
	}
	void *newPointerToObject = alloc_memory_stat_quick(sizeOfObject, alloc_number);
	if(newPointerToObject) {
		if(oldSize) {
			memcpy(newPointerToObject, pointerToObject, min(oldSize, sizeOfObject));
		}
	}
	if(pointerToObject) {
		free_memory_stat_quick(pointerToObject);
	}
	return(newPointerToObject);
}


#if HEAPSAFE
void * operator new(size_t sizeOfObject) { 
	if(sizeOfObject > 1000000000ull) {
		syslog(LOG_WARNING, "too big allocated block - %zd", sizeOfObject);
	}
	void *newPointer = HeapSafeCheck ?
			    (HeapSafeCheck & _HeapSafeSafeReserve ?
			      heapsafe_safe_alloc(sizeOfObject) :
			      heapsafe_alloc(sizeOfObject)) :
			   MemoryStatQuick ?
			    alloc_memory_stat_quick(sizeOfObject) :
			    _heapsafe_alloc(sizeOfObject);
	if(!newPointer) {
		notEnoughFreeMemory = true;
		syslog(LOG_ERR, "allocation (operator new) failed - size %zd", sizeOfObject);
	}
	return(newPointer);
}
 
void * operator new[](size_t sizeOfObject) {
	if(sizeOfObject > 1000000000ull) {
		syslog(LOG_WARNING, "too big allocated block - %zd", sizeOfObject);
	}
	void *newPointer = HeapSafeCheck ? 
			    (HeapSafeCheck & _HeapSafeSafeReserve ?
			      heapsafe_safe_alloc(sizeOfObject) :
			      heapsafe_alloc(sizeOfObject)) :
			   MemoryStatQuick ?
			    alloc_memory_stat_quick(sizeOfObject) :
			    _heapsafe_alloc(sizeOfObject);
	if(!newPointer) {
		notEnoughFreeMemory = true;
		syslog(LOG_ERR, "allocation (operator new[]) failed - size %zd", sizeOfObject);
	}
	return(newPointer);
}

void * operator new(size_t sizeOfObject, const char *memory_type1, int memory_type2, int alloc_number) { 
	if(sizeOfObject > 1000000000ull) {
		syslog(LOG_WARNING, "too big allocated block - %zd, %s, %i", sizeOfObject, memory_type1 ? memory_type1 : "", memory_type2);
	}
	void *newPointer = HeapSafeCheck ?
			    (HeapSafeCheck & _HeapSafeSafeReserve ?
			      heapsafe_safe_alloc(sizeOfObject) :
			      heapsafe_alloc(sizeOfObject, memory_type1, memory_type2)) :
			   MemoryStatQuick ?
			    alloc_memory_stat_quick(sizeOfObject, alloc_number) :
			    _heapsafe_alloc(sizeOfObject);
	if(!newPointer) {
		notEnoughFreeMemory = true;
		syslog(LOG_ERR, "allocation (operator new) failed - size %zd, %s, %i", sizeOfObject, memory_type1 ? memory_type1 : "", memory_type2);
	}
	return(newPointer);
}
 
void * operator new[](size_t sizeOfObject, const char *memory_type1, int memory_type2, int alloc_number) {
	if(sizeOfObject > 1000000000ull) {
		syslog(LOG_WARNING, "too big allocated block - %zd, %s, %i", sizeOfObject, memory_type1 ? memory_type1 : "", memory_type2);
	}
	void *newPointer = HeapSafeCheck ? 
			    (HeapSafeCheck & _HeapSafeSafeReserve ?
			      heapsafe_safe_alloc(sizeOfObject) :
			      heapsafe_alloc(sizeOfObject, memory_type1, memory_type2)) :
			   MemoryStatQuick ?
			    alloc_memory_stat_quick(sizeOfObject, alloc_number) :
			    _heapsafe_alloc(sizeOfObject);
	if(!newPointer) {
		notEnoughFreeMemory = true;
		syslog(LOG_ERR, "allocation (operator new[]) failed - size %zd, %s, %i", sizeOfObject, memory_type1 ? memory_type1 : "", memory_type2);
	}
	return(newPointer);
}

inline void _delete_object(void *pointerToObject) {
	if(HeapSafeCheck) {
		if(HeapSafeCheck & _HeapSafeSafeReserve) {
			heapsafe_safe_free(pointerToObject);
		} else {
			heapsafe_free(pointerToObject);
		}
	} else if(MemoryStatQuick) {
		free_memory_stat_quick(pointerToObject);
	} else {
		_heapsafe_free(pointerToObject);
	}
}
 
void delete_object(void *pointerToObject) {
	_delete_object(pointerToObject);
}

void operator delete(void *pointerToObject) {
	_delete_object(pointerToObject);
}
 
void operator delete[](void *pointerToObject) {
	_delete_object(pointerToObject);
}

void operator delete(void *pointerToObject, size_t) {
	_delete_object(pointerToObject);
}
 
void operator delete[](void *pointerToObject, size_t) {
	_delete_object(pointerToObject);
}
#endif


void *realloc_object(void *pointerToObject, size_t sizeOfObject, const char *memory_type1, int memory_type2, int alloc_number) {
	void *newPointer = HeapSafeCheck ?
			    (HeapSafeCheck & _HeapSafeSafeReserve ?
			      heapsafe_safe_realloc(pointerToObject, sizeOfObject) :
			      heapsafe_realloc(pointerToObject, sizeOfObject, memory_type1, memory_type2)) :
			   MemoryStatQuick ?
			    realloc_memory_stat_quick(pointerToObject, sizeOfObject, alloc_number) :
			    _heapsafe_realloc(pointerToObject, sizeOfObject);
	if(!newPointer) {
		syslog(LOG_ERR, "reallocation failed - size %zd, %s, %i", sizeOfObject, memory_type1 ? memory_type1 : "", memory_type2);
	}
	return(newPointer);
}


extern "C" {
void * c_heapsafe_alloc(size_t sizeOfObject, const char *memory_type1, int memory_type2, int alloc_number) { 
	void *newPointer = HeapSafeCheck ?
			    (HeapSafeCheck & _HeapSafeSafeReserve ?
			      heapsafe_safe_alloc(sizeOfObject) :
			      heapsafe_alloc(sizeOfObject, memory_type1, memory_type2)) :
			   MemoryStatQuick ?
			    alloc_memory_stat_quick(sizeOfObject, alloc_number) :
			    _heapsafe_alloc(sizeOfObject);
	if(!newPointer) {
		syslog(LOG_ERR, "allocation failed - size %zd, %s, %i", sizeOfObject, memory_type1 ? memory_type1 : "", memory_type2);
	}
	return(newPointer);
}

void c_heapsafe_free(void *pointerToObject) {
	if(HeapSafeCheck) {
		if(HeapSafeCheck & _HeapSafeSafeReserve) {
			heapsafe_safe_free(pointerToObject);
		} else {
			heapsafe_free(pointerToObject);
		}
	} else if(MemoryStatQuick) {
		free_memory_stat_quick(pointerToObject);
	} else {
		_heapsafe_free(pointerToObject);
	}
}

void * c_heapsafe_realloc(void *pointerToObject, size_t sizeOfObject, const char *memory_type1, int memory_type2, int alloc_number) {
	void *newPointer = HeapSafeCheck ?
			    (HeapSafeCheck & _HeapSafeSafeReserve ?
			      heapsafe_safe_realloc(pointerToObject, sizeOfObject) :
			      heapsafe_realloc(pointerToObject, sizeOfObject, memory_type1, memory_type2)) :
			   MemoryStatQuick ?
			    realloc_memory_stat_quick(pointerToObject, sizeOfObject, alloc_number) :
			    _heapsafe_realloc(pointerToObject, sizeOfObject);
	if(!newPointer) {
		syslog(LOG_ERR, "reallocation failed - size %zd, %s, %i", sizeOfObject, memory_type1 ? memory_type1 : "", memory_type2);
	}
	return(newPointer);
}
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
			abort();
		}
	}
}

void HeapSafeMemcpyError(const char *errorString, const char *file, unsigned int line) {
	if(errorString) {
		syslog(LOG_ERR, "HEAPSAFE MEMCPY ERROR: %s - %s:%d", errorString, 
		       file ? file : "unknown source file", line);
		abort();
	}
}

void HeapSafeMemsetError(const char *errorString, const char *file, unsigned int line) {
	if(errorString) {
		syslog(LOG_ERR, "HEAPSAFE MEMSET ERROR: %s - %s:%d", errorString, 
		       file ? file : "unknown source file", line);
		abort();
	}
}

std::string getMemoryStat(bool all) {
	if(MemoryStatQuick) {
		return(getMemoryStatQuick(all));
	}
	std::ostringstream outStr;
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd && sverb.memory_stat) {
		u_int64_t sum = 0;
		unsigned int tid = get_unix_tid();
		__sync_fetch_and_add(&threadRecursion[tid], 1);
		while(__sync_lock_test_and_set(&memoryStat_sync, 1));
		std::map<std::string, u_int32_t>::iterator iter = memoryStatType.begin();
		while(iter != memoryStatType.end()) {
			if(memoryStat[iter->second] > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
				u_int64_t memSize = memoryStat[iter->second];
				outStr << std::fixed
				       << std::left << std::setw(35) << iter->first << " : " 
				       << std::right << std::setw(16) << addThousandSeparators(memSize)
				       << std::endl;
				sum += memSize;
			}
			++iter;
		}
		std::map<u_int64_t, u_int32_t>::iterator iterOther = memoryStatOtherType.begin();
		while(iterOther != memoryStatOtherType.end()) {
			if(memoryStatOther[iterOther->second] > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
				u_int64_t memSize = memoryStatOther[iterOther->second];
				outStr << std::fixed
				       << std::left << memoryStatOtherName[iterOther->second] << " : " 
				       << std::right << addThousandSeparators(memSize)
				       << std::endl;
				sum += memSize;
			}
			++iterOther;
		}
		__sync_lock_release(&memoryStat_sync);
		if(memoryStatOtherSum > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
			u_int64_t memSize = memoryStatOtherSum;
			if(MCB_STACK) {
				outStr << std::fixed
				       << std::left << "other" << " : " 
				       << std::right << addThousandSeparators(memSize)
				       << std::endl;
			} else {
				outStr << std::fixed
				       << std::left << std::setw(35) << "other" << " : " 
				       << std::right << std::setw(16) << addThousandSeparators(memSize)
				       << std::endl;
			}
			sum += memSize;
		}
		__sync_fetch_and_sub(&threadRecursion[tid], 1);
		outStr << std::fixed
		       << std::left << std::setw(35) << "sum" << " : " 
		       << std::right << std::setw(16) << addThousandSeparators(sum)
		       << std::endl;
		return(outStr.str());
	} else {
		return("memory stat is not activated\n");
	}
}

std::string getMemoryStatQuick(bool all) {
	std::ostringstream outStr;
	u_int64_t sum = 0;
	for(unsigned i = 0; i < sizeof(AllocFileLines) / sizeof(AllocFileLines[0]); i++) {
		u_int64_t memSize = memoryStat[AllocFileLines[i].alloc_number];
		if(memSize > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
			outStr << std::fixed
			       << std::left << std::setw(35) << AllocFileLines[i].file
			       << std::left << std::setw(10) << AllocFileLines[i].line << " : " 
			       << std::right << std::setw(16) << addThousandSeparators(memSize)
			       << std::endl;
			sum += memSize;
		}
	}
	u_int64_t memSize = memoryStat[0];
	if(memSize > (!all && sverb.memory_stat_ignore_limit ? (unsigned)sverb.memory_stat_ignore_limit : 0)) {
		outStr << std::fixed
		       << std::left << std::setw(35) << "other"
		       << std::left << std::setw(10) << "" << " : " 
		       << std::right << std::setw(16) << addThousandSeparators(memSize)
		       << std::endl;
		sum += memSize;
	}
	outStr << std::fixed
	       << std::left << std::setw(35) << "sum"
	       << std::left << std::setw(10) << "" << " : " 
	       << std::right << std::setw(16) << addThousandSeparators(sum)
	       << std::endl;
	return(outStr.str());
}

std::string addThousandSeparators(u_int64_t num) {
	char length_str[20];
	snprintf(length_str, sizeof(length_str), "%" int_64_format_prefix "lu", num);
	std::string length;
	while(strlen(length_str) > 3) {
		length = std::string(length_str + strlen(length_str) - 3) + " " + length;
		length_str[strlen(length_str) - 3] = 0;
	}
	length = std::string(length_str) + " " + length;
	return(length);
}

void printMemoryStat(bool all) {
#ifndef FREEBSD
	malloc_trim(0);
#endif
	std::cout << getMemoryStat(all);
}

void memoryStatInit() {
	memoryStat = (volatile u_int64_t*)calloc(1000000, sizeof(u_int64_t));
	memoryStatOther = (volatile u_int64_t*)calloc(1000000, sizeof(u_int64_t));
}

struct sParseHeapsafeplusBlockInfo {
	unsigned length[2];
	string file;
	unsigned line;
};
void parse_heapsafeplus_coredump(const char *corefile, const char *outfile) {
 
	cout << endl;
 
	map<unsigned long, sParseHeapsafeplusBlockInfo> map_ok_blocks;
	map<unsigned long, sParseHeapsafeplusBlockInfo> map_bad_blocks;
	map<unsigned long, unsigned long> map_size_ok_blocks;

	unsigned buffer_length = 50000000;
	unsigned use_buffer_length = 0;
	u_char *buffer = new FILE_LINE(10001) u_char[buffer_length];
	
	FILE *core = fopen(corefile, "r");
	if(!core) {
		cout << "core file " << corefile << " not found" << endl;
		return;
	}
	FILE *out = NULL;
	if(outfile) {
		out = fopen(outfile, "w");
	}
	
	unsigned long file_length = 0;
	unsigned long begin_pos = 0;
	size_t read_length = 0;
	
	unsigned long bmb_last_pos = 0;
	unsigned long bmb_count = 0;
	
	bool indik_bad_block = false;
 
	do {
		if(use_buffer_length > buffer_length / 2) {
			memcpy(buffer, buffer + buffer_length / 2, use_buffer_length - buffer_length / 2);
			use_buffer_length -= buffer_length / 2;
			begin_pos += buffer_length / 2;
		}
		read_length = fread(buffer + use_buffer_length, 1, buffer_length / 2, core);
		use_buffer_length += read_length;
		file_length += read_length;
		
		if(!read_length || use_buffer_length > buffer_length / 2) {
		
			size_t find_length = read_length ? min(use_buffer_length, buffer_length / 2 + 2) : use_buffer_length;
			
			u_char *posBMB = NULL;
			do {
				u_char *startFind = posBMB ? posBMB + 1 : buffer;
				posBMB = (u_char*)memmem(startFind,
							 find_length - (startFind - buffer), 
							 "BMB", 3);
				if(posBMB) {
					unsigned long bmb_act_pos = (unsigned long)posBMB - (unsigned long)buffer + begin_pos;
					sHeapSafeMemoryControlBlockPlus *mbBMB = (sHeapSafeMemoryControlBlockPlus*)posBMB;
					if(mbBMB->memory_type == 0 &&
					   mbBMB->memory_type1[0] &&
					   mbBMB->block_addr &&
					   mbBMB->length < buffer_length / 2) {
						sParseHeapsafeplusBlockInfo block_info;
						block_info.length[0] = mbBMB->length;
						block_info.length[1] = mbBMB->length + sizeof(sHeapSafeMemoryControlBlockPlus) + 20 + sizeof(sHeapSafeMemoryControlBlock);
						block_info.file = string(mbBMB->memory_type1).c_str();
						block_info.line = mbBMB->memory_type2;
						sHeapSafeMemoryControlBlock *mbEMB = (sHeapSafeMemoryControlBlock*)((long)posBMB + sizeof(sHeapSafeMemoryControlBlockPlus) + mbBMB->length + 20);
						if(strncmp(mbEMB->stringInfo, "EMB", 3) ||
						   mbBMB->memory_type != mbEMB->memory_type ||
						   mbBMB->length != mbEMB->length) {
							map_bad_blocks[(unsigned long)mbBMB->block_addr] = block_info;
							if(out) {
								fprintf(out, "BAD BLOCK - length: %u", mbBMB->length);
								fwrite(posBMB, mbBMB->length + sizeof(sHeapSafeMemoryControlBlockPlus) + sizeof(sHeapSafeMemoryControlBlock) + 20, 1, out);
								indik_bad_block = true;
							}
						} else {
							map_ok_blocks[(unsigned long)mbBMB->block_addr] = block_info;
							++map_size_ok_blocks[mbBMB->length];
							if(indik_bad_block) {
								cout << (bmb_act_pos - bmb_last_pos) << endl;
								indik_bad_block= false;
							}
						}
					}
					
					++bmb_count;
					bmb_last_pos = bmb_act_pos;
				}
			 
			} while(posBMB);
		
		}
		
		
	} while(read_length);
	
	cout << "core length: " << file_length << endl;
	cout << "bmb count: " << bmb_count << endl;
	cout << "bad blocks: " << map_bad_blocks.size() << endl;
	
	cout << endl;
	
	if(map_bad_blocks.size()) {
		map<unsigned long, sParseHeapsafeplusBlockInfo>::iterator it;
		for(it = map_bad_blocks.begin(); it != map_bad_blocks.end(); it++) {
			cout << "BAD BLOCK - "
			     << hex << it->first << dec << ", " 
			     << it->second.length[0] << "(" << it->second.length[1] << "), "
			     << it->second.file << ":" << it->second.line;
			map<unsigned long, sParseHeapsafeplusBlockInfo>::iterator it2 = map_ok_blocks.lower_bound(it->first);
			if(it2 != map_ok_blocks.end()) {
				cout << " / next ok block - "
				     << hex << it2->first << dec << "+" << (it2->first - it->first) << ", "
				     << it2->second.length[0] << "(" << it2->second.length[1] << "), "
				     << it2->second.file << ":" << it2->second.line;
			}
			cout << endl;
		}
	}
	
	cout << endl;
	
	unsigned long count_lt_100 = 0;
	unsigned long sum_lt_100 = 0;
	
	if(map_size_ok_blocks.size()) {
		map<unsigned long, unsigned long>::iterator it = map_size_ok_blocks.end();
		do {
			--it;
			cout << it->first << " : " << it->second << endl;
			if(it->first < 100) {
				count_lt_100 += it->second;
				sum_lt_100 += it->first * it->second;
			}
		} while(it != map_size_ok_blocks.begin());
	}
	
	cout << "count <100 blocks: " << count_lt_100 << endl;
	cout << "sum <100 blocks: " << sum_lt_100 << endl;
	cout << "avg <100 block: " << (sum_lt_100 / count_lt_100) << endl;
 
}
