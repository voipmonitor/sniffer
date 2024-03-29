#include <stdlib.h>
#include <syslog.h>
#include <algorithm> 
#include "tools_global.h"

#include "heap_chunk.h"


using namespace std;


#define FREE_HEADER_SIZE sizeof(sHeader)
#define DELTA_FACTOR     64


cHeapItem::cHeapItem(cHeap_base *heap) { 
	this->Heap = heap;
	Buff = NULL;
	Break = NULL;
	First = NULL;
	Last = NULL;
	Rover=NULL;
	InitBuffError = false;
	IsFull = false;
}

void *cHeapItem::MAlloc(u_int32_t sizeOfObject) { 
	if(!Buff) {
		if(InitBuffError || !InitBuff()) {
			return(NULL);
		}
	}
	return(Alloc(sizeOfObject));
}

int8_t cHeapItem::Free(void *pointerToObject) { 
	if(IsOwnItem(pointerToObject)) { 
		pointerToObject = (char*)pointerToObject - HEAP_CHUNK_USED_HEADER_SIZE;
		if(pointerToObject == Last) {
			FreeLastBlock();
		} else {
			FreeInnerBlock((sHeader*)pointerToObject);
		}
		IsFull = false;
		if(Buff == Break) {
			TermBuff();
			return(2);
		}
		return(1);
	}
	return(0);
}

bool cHeapItem::InitBuff() {
	Buff = (char*)Heap->initHeapBuffer(&Size, &Size_reserve);
	if(Buff) {
		Heap->setMinPtr(Buff);
		Break = Buff;
		return(true);
	}
	return(false);
}

void cHeapItem::TermBuff() {
	Heap->termHeapBuffer(Buff, Size, Size_reserve);
	Buff = NULL;
}

bool cHeapItem::Check() { 
	if(!Buff) {
		return(true);
	}
	if(First && First != Last) { 
		sHeader *temp = First;
		while(temp != Last) {
			sHeader *next = (sHeader*)((char*)temp + temp->Size - (temp->Size & 1));
			if(next->PrevReal != temp) {
				return(false);
			}
			temp = next;
		}
	}
	return(true);
}

void *cHeapItem::Alloc(u_int32_t size) { 
	if(!size) {
		return(NULL);
	}
	size = (size + HEAP_CHUNK_USED_HEADER_SIZE + sizeof(sHeader) - 1) / sizeof(sHeader) * sizeof(sHeader);
	if(!First) {
		return(CreateHeap(size));
	}
	sHeader *temp = Rover;
	if(temp) {
		do { 
			if(temp->Size >= size + FREE_HEADER_SIZE + DELTA_FACTOR) {
				return(AllocatePartialBlock(temp, size));
			}
			if(temp->Size >= size) { 
				PullFreeBlock(temp);
				++temp->Size;
				return(&temp->PrevFree);
			}
			temp = temp->NextFree;
		} while(temp != Rover);
	}
	return(ExtendHeap(size));
}

void *cHeapItem::CreateHeap(u_int32_t size) { 
	sHeader *temp = (sHeader*)IncrementBreak(size);
	if(!temp) {
		return(NULL);
	}
	temp->PrevReal = NULL;
	First = temp;
	Last = temp;
	temp->Size = size + 1;
	return(&temp->PrevFree);
}

void *cHeapItem::ExtendHeap(u_int32_t size) { 
	sHeader *temp = (sHeader*)IncrementBreak(size);
	if(!temp) {
		return(NULL);
	}
	temp->PrevReal = Last;
	temp->Size = size + 1;
	Last = temp;
	return(&Last->PrevFree);
}

void *cHeapItem::AllocatePartialBlock(sHeader *block, u_int32_t size) { 
	block->Size -= size;
	sHeader *temp = (sHeader*)((char*)block + block->Size);
	temp->Size = size + 1;
	temp->PrevReal = block;
	if(Last == block) {
		Last = temp;
	} else { 
		block = (sHeader*)((char*)temp + size);
		block->PrevReal = temp;
	}
	return(&temp->PrevFree);
}

void cHeapItem::PullFreeBlock(sHeader *block) { 
	if(block->NextFree == block) {
		Rover = NULL;
	} else { 
		Rover = block->NextFree;
		sHeader *temp = block->PrevFree;
		Rover->PrevFree = temp;
		temp->NextFree = Rover;
	}
}

void cHeapItem::FreeLastBlock() { 
	if(First == Last) { 
		SetBreak(First);
		First = NULL;
		Last = NULL;
	} else {
		sHeader *temp = Last->PrevReal;
		if((temp->Size & 1) == 0) { 
			PullFreeBlock(temp);
			if(temp == First) { 
				First = NULL;
				Last = NULL;
			} else {
				Last = temp->PrevReal;
			}
			SetBreak(temp);
		} else { 
			SetBreak(Last);
			Last=temp;
		}
	}
}

void cHeapItem::FreeInnerBlock(sHeader *block) { 
	--block->Size;
	sHeader *temp1 = (sHeader*)((char*)block + block->Size);
	sHeader *temp2 = block->PrevReal;
	if(temp2 && (temp2->Size& 1 ) == 0 && block != First) { 
		temp2->Size += block->Size;
		temp1->PrevReal = temp2;
		block = temp2;
	} else {
		InsertFreeBlock(block);
	}
	if((temp1->Size & 1) == 0) {
		JoinFreeBlocks(block,temp1);
	}
}

void cHeapItem::InsertFreeBlock(sHeader *block) { 
	if(Rover) { 
		sHeader *temp = Rover->NextFree;
		Rover->NextFree = block;
		temp->PrevFree = block;
		block->NextFree = temp;
		block->PrevFree = Rover;
	} else { 
		Rover = block;
		block->PrevFree = block;
		block->NextFree = block;
	}
}

void cHeapItem::JoinFreeBlocks(sHeader *block1,sHeader *block2) {
	block1->Size += block2->Size;
	if(Last == block2) {
		Last = block1;
	} else {
		sHeader *temp = (sHeader*)((char*)block2+block2->Size);
		temp->PrevReal = block1;
	}
	PullFreeBlock(block2);
}

void cHeapItem::SetBreak(void *pointer) { 
	Break = (char*)pointer;
}

void *cHeapItem::IncrementBreak(u_int32_t increment) { 
	if(!Buff || !Break || Break < Buff) {
		return(NULL);
	}
	if((u_int32_t)(Break + increment - Buff) > Size) {
		IsFull = true;
		return(NULL);
	}
	void *temp = Break;
	Break += increment;
	return(temp);
}

bool cHeapItem::IsOwnItem(const void *pointerToObject) { 
	return(Buff != NULL && pointerToObject != NULL &&
	       (char*)pointerToObject > Buff && (char*)pointerToObject < Buff + Size);
}


cHeap::cHeap(u_int16_t maxHeapItems) {
	this->maxHeapItems = maxHeapItems;
	countHeapItems = 0;
	allocSize = 0;
	heapItems = (cHeapItem**)calloc(maxHeapItems ,sizeof(cHeapItem*));
	active = false;
	min_ptr = 0;
	_sync = 0;
}

cHeap::~cHeap() {
	free(heapItems);
}

void *cHeap::MAlloc(u_int32_t sizeOfObject, u_int16_t *heapItemIndex) {
	lock();
	if(!countHeapItems) {
		heapItems[0] = createHeapItem();
		countHeapItems = 1;
		void *p = heapItems[0]->MAlloc(sizeOfObject);
		incAllocSize(p);
		unlock();
		if(heapItemIndex) {
			*heapItemIndex = 1;
		}
		return(p);
	}
	for(unsigned i = 0; i < countHeapItems; i++) {
		if(heapItems[i]->IsFull) {
			continue;
		}
		void *allocObject = heapItems[i]->MAlloc(sizeOfObject);
		if(allocObject) {
			incAllocSize(allocObject);
			unlock();
			if(heapItemIndex) {
				*heapItemIndex = i + 1;
			}
			return(allocObject);
		}
	}
	if(countHeapItems < maxHeapItems) {
		u_int16_t _heapItemIndex = countHeapItems;
		heapItems[countHeapItems] = createHeapItem();
		++countHeapItems;
		void *p = heapItems[_heapItemIndex]->MAlloc(sizeOfObject);
		incAllocSize(p);
		unlock();
		if(heapItemIndex) {
			*heapItemIndex = _heapItemIndex + 1;
		}
		return(p);
	}
	unlock();
        return(NULL);
}

bool cHeap::Free(void *pointerToObject, u_int16_t heapItemIndex) { 
	if((char*)pointerToObject < min_ptr) {
		return(false);
	}
	lock();
	int8_t rsltFree = 0;
	decAllocSize(pointerToObject);
	if(heapItemIndex && heapItemIndex <= countHeapItems &&
	   (rsltFree = heapItems[heapItemIndex - 1]->Free(pointerToObject)) > 0) {
		if(rsltFree == 2 && heapItemIndex == countHeapItems) {
			destroyLastHeapItem();
		}
		unlock();
		return(true);
	}
	for(int i = 0; i < countHeapItems; i++) {
		if((rsltFree = heapItems[i]->Free(pointerToObject)) > 0) {
			if(rsltFree == 2 && i == countHeapItems - 1) {
				destroyLastHeapItem();
			}
			unlock();
			return(true);
		}
	}
	unlock();
	return(false);
}

bool cHeap::IsOwnItem(const void *pointerToObject) {
	lock();
	for(int i = 0; i < countHeapItems; i++) {
		if(heapItems[i]->IsOwnItem(pointerToObject)) {
			unlock();
			return(true);
		}
	}
	unlock();
	return(false);
}

bool cHeap::Check() {
	lock();
	for(int i = 0; i < countHeapItems; i++) {
		if(!heapItems[i]->Check()) {
			unlock();
			return(false);
		}
	}
	unlock();
	return(true);
}

bool cHeap::setActive() {
	active = true;
	return(true);
}

u_int64_t cHeap::getSumSize() {
	u_int64_t rslt = 0;
	lock();
	for(int i = 0; i < countHeapItems; i++) {
		if(!heapItems[i]->isEmpty()) {
			rslt += heapItems[i]->Size + heapItems[i]->Size_reserve;
		}
	}
	unlock();
	return(rslt);
}

cHeapItem *cHeap::createHeapItem() {
	cHeapItem *heapItem = (cHeapItem*)calloc(1, sizeof(cHeapItem));
	heapItem->Heap = this;
	return(heapItem);
}

void cHeap::destroyLastHeapItem() {
	if(countHeapItems > 0 && heapItems[countHeapItems - 1]->isEmpty()) {
		free(heapItems[countHeapItems - 1]);
		heapItems[countHeapItems - 1] = NULL;
		--countHeapItems;
	}
}
