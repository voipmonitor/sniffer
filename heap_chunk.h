#ifndef HEAP_CHUNK_H
#define HEAP_CHUNK_H

#include "config.h"

#ifdef HEAP_CHUNK_ENABLE


class cHeap_base {
public:
	cHeap_base() {
		min_ptr = NULL;
		sum_size = 0;
	}
	inline void setMinPtr(char *ptr) {
		if(!min_ptr || ptr < min_ptr) {
			min_ptr = ptr;
		}
	}
	inline char *getMinPtr() {
		return(min_ptr);
	}
	inline u_int64_t getSumSize() {
		return(sum_size);
	}
protected:
	virtual void *initHeapBuffer(u_int32_t *size, u_int32_t *size_reserve) = 0;
	virtual void termHeapBuffer(void *ptr, u_int32_t size, u_int32_t size_reserve) = 0;
protected:
	char *min_ptr;
	u_int64_t sum_size;
friend class cHeapItem;
};

class cHeapItem { 
protected:
	struct sHeader { 
		u_int32_t Size;
		sHeader *PrevReal;
		sHeader *PrevFree;
		sHeader *NextFree;
	};
public:
	cHeapItem(cHeap_base *heap);
	void *MAlloc(u_int32_t sizeOfObject);
	bool Free(void *pointerToObject);
	bool InitBuff();
	void TermBuff();
	bool Check();
private:
	inline void *Alloc(u_int32_t size);
	inline void *CreateHeap(u_int32_t size);
	inline void *ExtendHeap(u_int32_t size);
	inline void *AllocatePartialBlock(sHeader *block,u_int32_t size);
	inline void PullFreeBlock(sHeader *block);
	inline void FreeLastBlock();
	inline void FreeInnerBlock(sHeader *block);
	inline void InsertFreeBlock(sHeader *block);
	inline void JoinFreeBlocks(sHeader *block1,sHeader *block2);
	inline void SetBreak(void *pointer);
	inline void *IncrementBreak(u_int32_t increment);
	inline bool IsOwnItem(const void *pointerToObject);
private:
	u_int32_t Size;
	u_int32_t Size_reserve;
	char *Buff;
	char *Break;
	sHeader *First;
	sHeader *Last;
	sHeader *Rover;
	bool InitBuffError;
	cHeap_base *Heap;
	volatile bool IsFull;
friend class cHeap;
};

#define HEAP_MAX_ITEMS_DEFULT 1000

class cHeap : public cHeap_base {
public:
	cHeap(u_int16_t maxHeapItems = HEAP_MAX_ITEMS_DEFULT);
	~cHeap();
	void *MAlloc(u_int32_t sizeOfObject, u_int16_t *heapItemIndex = NULL);
	bool Free(void *pointerToObject, u_int16_t heapItemIndex = 0);
	bool IsOwnItem(const void *pointerToObject);
	bool Check();
	virtual bool setActive();
	inline bool isActive() {
		return(active);
	}
private:
	cHeapItem *createHeapItem();
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	u_int16_t maxHeapItems;
	volatile u_int16_t countHeapItems;
	cHeapItem **heapItems;
	bool active;
	volatile int _sync;
};


#endif // HEAP_CHUNK_ENABLE


#endif //HEAP_CHUNK_H
