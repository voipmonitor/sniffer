#ifndef HEAP_SAFE_H
#define HEAP_SAFE_H


#include <alloca.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>


#define HEAPSAFE_ALLOC_RESERVE			20

#define HEAPSAFE_BEGIN_MEMORY_CONTROL_BLOCK	"BMB"
#define HEAPSAFE_FREED_MEMORY_CONTROL_BLOCK	"FMB"
#define HEAPSAFE_END_MEMORY_CONTROL_BLOCK	"EMB"

#define HEAPSAFE_COPY_BEGIN_MEMORY_CONTROL_BLOCK(stringInfo) { \
	stringInfo[0] = HEAPSAFE_BEGIN_MEMORY_CONTROL_BLOCK[0]; \
	stringInfo[1] = HEAPSAFE_BEGIN_MEMORY_CONTROL_BLOCK[1]; \
	stringInfo[2] = HEAPSAFE_BEGIN_MEMORY_CONTROL_BLOCK[2]; }
#define HEAPSAFE_COPY_FREED_MEMORY_CONTROL_BLOCK(stringInfo) { \
	stringInfo[0] = HEAPSAFE_FREED_MEMORY_CONTROL_BLOCK[0]; \
	stringInfo[1] = HEAPSAFE_FREED_MEMORY_CONTROL_BLOCK[1]; \
	stringInfo[2] = HEAPSAFE_FREED_MEMORY_CONTROL_BLOCK[2]; }
#define HEAPSAFE_COPY_END_MEMORY_CONTROL_BLOCK(stringInfo) { \
	stringInfo[0] = HEAPSAFE_END_MEMORY_CONTROL_BLOCK[0]; \
	stringInfo[1] = HEAPSAFE_END_MEMORY_CONTROL_BLOCK[1]; \
	stringInfo[2] = HEAPSAFE_END_MEMORY_CONTROL_BLOCK[2]; }

#define HEAPSAFE_CMP_BEGIN_MEMORY_CONTROL_BLOCK(stringInfo) \
	(stringInfo[0] == HEAPSAFE_BEGIN_MEMORY_CONTROL_BLOCK[0] && \
	 stringInfo[1] == HEAPSAFE_BEGIN_MEMORY_CONTROL_BLOCK[1] && \
	 stringInfo[2] == HEAPSAFE_BEGIN_MEMORY_CONTROL_BLOCK[2])
#define HEAPSAFE_CMP_FREED_MEMORY_CONTROL_BLOCK(stringInfo) \
	(stringInfo[0] == HEAPSAFE_FREED_MEMORY_CONTROL_BLOCK[0] && \
	 stringInfo[1] == HEAPSAFE_FREED_MEMORY_CONTROL_BLOCK[1] && \
	 stringInfo[2] == HEAPSAFE_FREED_MEMORY_CONTROL_BLOCK[2])
#define HEAPSAFE_CMP_END_MEMORY_CONTROL_BLOCK(stringInfo) \
	(stringInfo[0] == HEAPSAFE_END_MEMORY_CONTROL_BLOCK[0] && \
	 stringInfo[1] == HEAPSAFE_END_MEMORY_CONTROL_BLOCK[1] && \
	 stringInfo[2] == HEAPSAFE_END_MEMORY_CONTROL_BLOCK[2])


enum eHeapSafeErrors {
	_HeapSafeErrorNotEnoughMemory =   1,
	_HeapSafeErrorBeginEnd        =   2,
	_HeapSafeErrorFreed           =   4,
	_HeapSafeErrorInAllocFce      =   8,
	_HeapSafeErrorAllocReserve    =  16,
	_HeapSafeErrorFillFF          =  32,
	_HeapSafeErrorInHeap          =  64,
};

struct sHeapSafeMemoryControlBlock {
	char stringInfo[3];
	u_int32_t length;
};


void HeapSafeAllocError(int error);
void HeapSafeMemcpyError(const char *errorString);
void HeapSafeMemsetError(const char *errorString);


inline void *memcpy_heapsafe(void *destination, const void *destination_begin, const void *source, const void *source_begin, size_t length) {
	extern unsigned int HeapSafeCheck;
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd) {
		bool error = false;
		sHeapSafeMemoryControlBlock *destination_beginMemoryBlock;
		u_int32_t destinationLength = 0;
		if(destination_begin) {
			destination_beginMemoryBlock = (sHeapSafeMemoryControlBlock*)((unsigned char*)destination_begin - sizeof(sHeapSafeMemoryControlBlock));
			if(HEAPSAFE_CMP_BEGIN_MEMORY_CONTROL_BLOCK(destination_beginMemoryBlock->stringInfo)) {
				destinationLength = destination_beginMemoryBlock->length;
			} else {
				error = true;
				HeapSafeMemcpyError("destination corrupted (bad begin memory block)");
			}
		}
		sHeapSafeMemoryControlBlock *source_beginMemoryBlock;
		u_int32_t sourceLength = 0;
		if(source_begin) {
			source_beginMemoryBlock = (sHeapSafeMemoryControlBlock*)((unsigned char*)source_begin - sizeof(sHeapSafeMemoryControlBlock));
			if(HEAPSAFE_CMP_BEGIN_MEMORY_CONTROL_BLOCK(source_beginMemoryBlock->stringInfo)) {
				sourceLength = source_beginMemoryBlock->length;
			} else {
				error = true;
				HeapSafeMemcpyError("source corrupted (bad begin memory block)");
			}
		}
		if(!error) {
			if(destination_begin) {
				if((unsigned char*)destination_begin < (unsigned char*)destination) {
					HeapSafeMemcpyError("negative offset of destination");
				}
				if((unsigned char*)destination_begin - (unsigned char*)destination + length > destinationLength) {
					HeapSafeMemcpyError("write after destination length");
				}
			}
			if(source_begin) {
				if((unsigned char*)source_begin < (unsigned char*)source) {
					HeapSafeMemcpyError("negative offset of source");
				}
				if((unsigned char*)source_begin - (unsigned char*)source + length > sourceLength) {
					HeapSafeMemcpyError("write after source length");
				}
			}
		}
	}
	return(memcpy(destination, source, length));
}

inline void *memset_heapsafe(void *ptr, void *ptr_begin, int value, size_t length) {
	extern unsigned int HeapSafeCheck;
	if(HeapSafeCheck & _HeapSafeErrorBeginEnd) {
		bool error = false;
		sHeapSafeMemoryControlBlock *ptr_beginMemoryBlock;
		u_int32_t ptrLength = 0;
		if(ptr_begin) {
			ptr_beginMemoryBlock = (sHeapSafeMemoryControlBlock*)((unsigned char*)ptr_begin - sizeof(sHeapSafeMemoryControlBlock));
			if(HEAPSAFE_CMP_BEGIN_MEMORY_CONTROL_BLOCK(ptr_beginMemoryBlock->stringInfo)) {
				ptrLength = ptr_beginMemoryBlock->length;
			} else {
				error = true;
				HeapSafeMemsetError("ptr corrupted (bad begin memory block)");
			}
		}
		if(!error) {
			if(ptr_begin) {
				if((unsigned char*)ptr_begin < (unsigned char*)ptr) {
					HeapSafeMemsetError("negative offset of ptr");
				}
				if((unsigned char*)ptr_begin - (unsigned char*)ptr + length > ptrLength) {
					HeapSafeMemsetError("write after ptr length");
				}
			}
		}
	}
	return(memset(ptr, value, length));
}

#endif //HEAP_SAFE_H