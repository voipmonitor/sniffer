#include <stdlib.h>
#include <syslog.h>
#include <algorithm> 

#ifdef HEAP_CHUNK_ENABLE

#include "heap_chunk.h"


using namespace std;

#define USED_HEADER_SIZE 16 // p (long)&temp->PrevFree - (long)temp; (sizeof(unsigned int)+sizeof(void*))
#define FREE_HEADER_SIZE sizeof(sHeader)
#define DELTA_FACTOR     64


cLocalHeap::cLocalHeap(unsigned int size,bool initBuff,
                       bool autoDeallocInDestructor)
 { Size=size;
   Buff=NULL;
   Break=NULL;
   First=NULL;
   Last=NULL;
   Rover=NULL;
   if(initBuff)
    InitBuff();
   AutoDeallocInDestructor=autoDeallocInDestructor;
 }


cLocalHeap::~cLocalHeap()
 { if(Buff)
    { if(Buff!=Break&&!Check())
       { syslog(LOG_WARNING, "incomplete free heap chunk");
       }
      if(AutoDeallocInDestructor)
       { free(Buff);
         Buff=NULL;
       }
    }
 }


void *cLocalHeap::MAlloc(unsigned int sizeOfObject)
 { return(Alloc(sizeOfObject));
 }


void cLocalHeap::Free(void *pointerToObject)
 { if(pointerToObject!=NULL&&(char*)pointerToObject>Buff&&
      (char*)pointerToObject<Buff+Size)
    { pointerToObject=(char*)pointerToObject-USED_HEADER_SIZE;
      if(pointerToObject==Last)
       FreeLastBlock();
      else
       FreeInnerBlock((sHeader*)pointerToObject);
    }
 }


bool cLocalHeap::IsOwnItem(const void *pointerToObject)
 { return(Buff!=NULL&&pointerToObject!=NULL&&
          (char*)pointerToObject>Buff&&(char*)pointerToObject<Buff+Size);
 }


void cLocalHeap::InitBuff()
 { if(!Buff)
    { Buff=(char*)malloc(Size*1.05);
      Break=Buff;
    }
 }


bool cLocalHeap::Check()
 { if(!Buff)
    return(true);
   if(First&&First!=Last)
    { sHeader *temp = First;
      while(temp!=Last)
       { sHeader *next = (sHeader*)((char*)temp+temp->Size-(temp->Size&1));
         if(next->PrevReal!=temp)
          return(false);
         temp=next;
       }
    }
   return(true);
 }


void *cLocalHeap::Alloc(unsigned int size)
 { if(!size)
    return(NULL);
   size=(size+USED_HEADER_SIZE+sizeof(sHeader)-1)/sizeof(sHeader)*
                                                                sizeof(sHeader);
   if(!First)
    return(CreateHeap(size));
   sHeader *temp = Rover;
   if(temp)
    do
     { if(temp->Size>=size+FREE_HEADER_SIZE+DELTA_FACTOR)
        return(AllocatePartialBlock(temp,size));
       if(temp->Size>=size)
        { PullFreeBlock(temp);
          ++temp->Size;
          return(&temp->PrevFree);
        }
       temp=temp->NextFree;
     }
    while(temp!=Rover);
   return(ExtendHeap(size));
 }


void *cLocalHeap::CreateHeap(unsigned int size)
 { sHeader *temp = (sHeader*)IncrementBreak(size);
   if(!temp)
    return(NULL);
   temp->PrevReal=NULL;
   First=temp;
   Last=temp;
   temp->Size=size+1;
   return(&temp->PrevFree);
 }


void *cLocalHeap::ExtendHeap(unsigned int size)
 { sHeader *temp = (sHeader*)IncrementBreak(size);
   if(!temp)
    return(NULL);
   temp->PrevReal=Last;
   temp->Size=size+1;
   Last=temp;
   return(&Last->PrevFree);
 }


void *cLocalHeap::AllocatePartialBlock(sHeader *block,unsigned int size)
 { block->Size-=size;
   sHeader *temp = (sHeader*)((char*)block+block->Size);
   temp->Size=size+1;
   temp->PrevReal=block;
   if(Last==block)
    Last=temp;
   else
    { block=(sHeader*)((char*)temp+size);
      block->PrevReal=temp;
    }
   return(&temp->PrevFree);
 }


void cLocalHeap::PullFreeBlock(sHeader *block)
 { if(block->NextFree==block)
    Rover=NULL;
   else
    { Rover=block->NextFree;
      sHeader *temp = block->PrevFree;
      Rover->PrevFree=temp;
      temp->NextFree=Rover;
    }
 }


void cLocalHeap::FreeLastBlock()
 { if(First==Last)
    { SetBreak(First);
      First=NULL;
      Last=NULL;
    }
   else
    { sHeader *temp = Last->PrevReal;
      if((temp->Size&1)==0)
       { PullFreeBlock(temp);
         if(temp==First)
          { First=NULL;
            Last=NULL;
          }
         else
          Last=temp->PrevReal;
         SetBreak(temp);
       }
      else
       { SetBreak(Last);
         Last=temp;
       }
    }
 }


void cLocalHeap::FreeInnerBlock(sHeader *block)
 { --block->Size;
   sHeader *temp1 = (sHeader*)((char*)block+block->Size);
   sHeader *temp2 = block->PrevReal;
   if(temp2&&(temp2->Size&1)==0&&block!=First)
    { temp2->Size+=block->Size;
      temp1->PrevReal=temp2;
      block=temp2;
    }
   else
    InsertFreeBlock(block);
   if((temp1->Size&1)==0)
    JoinFreeBlocks(block,temp1);
 }


void cLocalHeap::InsertFreeBlock(sHeader *block)
 { if(Rover)
    { sHeader *temp = Rover->NextFree;
      Rover->NextFree=block;
      temp->PrevFree=block;
      block->NextFree=temp;
      block->PrevFree=Rover;
    }
   else
    { Rover=block;
      block->PrevFree=block;
      block->NextFree=block;
    }
 }


void cLocalHeap::JoinFreeBlocks(sHeader *block1,sHeader *block2)
 { block1->Size+=block2->Size;
   if(Last==block2)
    Last=block1;
   else
    { sHeader *temp = (sHeader*)((char*)block2+block2->Size);
      temp->PrevReal=block1;
    }
   PullFreeBlock(block2);
 }


void cLocalHeap::SetBreak(void *pointer)
 { Break=(char*)pointer;
 }


void *cLocalHeap::IncrementBreak(unsigned int increment)
 { if(!Buff||!Break||Break<Buff||(unsigned int)(Break+increment-Buff)>Size)
    return(NULL);
   void *temp = Break;
   Break+=increment;
   return(temp);
 }


static cChunkAllocHeap ChunkAllocHeap;


void *ChunkMAlloc(unsigned int sizeOfObject)
 { void *allocObject = NULL;
   if(ChunkAllocHeap.Active)
    allocObject=ChunkAllocHeap.MAlloc(sizeOfObject);
   if(!allocObject)
    allocObject=malloc(sizeOfObject);
   return(allocObject);
 }


void ChunkFree(void *pointerToObject)
 { ChunkAllocHeap.Free(pointerToObject);
 }


bool IsChunkAllocItem(const void *pointerToObject)
 { return(ChunkAllocHeap.IsOwnItem(pointerToObject));
 }


bool CheckChunkAlloc()
 { return(ChunkAllocHeap.Check());
 }


cChunkAllocHeapItem::cChunkAllocHeapItem()
 : cLocalHeap(DEFAULT_CHUNK_ALLOC_SIZE,false,false)
 { Active=false;
   Full=false;
 }


static volatile int _sync;
void *cChunkAllocHeapItem::MAlloc(unsigned int sizeOfObject)
 { while(__sync_lock_test_and_set(&_sync, 1));
   if(!Active)
    { cLocalHeap::InitBuff();
      Active=true;
    }
   void *allocObject = cLocalHeap::MAlloc(sizeOfObject);
   if(!allocObject)
    Full=true;
   __sync_lock_release(&_sync);
   return(allocObject);
 }


void cChunkAllocHeapItem::Free(void *pointerToObject)
 { while(__sync_lock_test_and_set(&_sync, 1));
   if(IsOwnItem(pointerToObject))
    { cLocalHeap::Free(pointerToObject);
      if(Full)
       Full=false;
    }
    __sync_lock_release(&_sync);
 }


bool cChunkAllocHeapItem::IsOwnItem(const void *pointerToObject)
 { return(Active&&cLocalHeap::IsOwnItem(pointerToObject));
 }


bool cChunkAllocHeapItem::Check()
 { return(Active&&cLocalHeap::Check());
 }


cChunkAllocHeap::cChunkAllocHeap()
 { CountActiveAllocHeapItems=0;
   Active=true;
 }


void *cChunkAllocHeap::MAlloc(unsigned int sizeOfObject)
 { if(sizeOfObject<DEFAULT_CHUNK_ALLOC_SIZE/10)
    { void *allocObject;
      for(int i=0;i<max(CountActiveAllocHeapItems+1,MAX_CHUNK_ALLOC_ITEMS);i++)
       if(!AllocHeapItems[i].Full&&
          (allocObject=AllocHeapItems[i].MAlloc(sizeOfObject))!=NULL)
        { if(CountActiveAllocHeapItems<i+1)
           CountActiveAllocHeapItems=i+1;
          return(allocObject);
        }
    }
   return(NULL);
 }


void cChunkAllocHeap::Free(void *pointerToObject)
 { for(int i=0;i<CountActiveAllocHeapItems;i++)
    if(AllocHeapItems[i].IsOwnItem(pointerToObject))
     { AllocHeapItems[i].Free(pointerToObject);
       return;
     }
   free(pointerToObject);
 }


bool cChunkAllocHeap::IsOwnItem(const void *pointerToObject)
 { for(int i=0;i<CountActiveAllocHeapItems;i++)
    if(AllocHeapItems[i].IsOwnItem(pointerToObject))
     return(true);
   return(false);
 }


bool cChunkAllocHeap::Check()
 { for(int i=0;i<CountActiveAllocHeapItems;i++)
    if(!AllocHeapItems[i].Check())
     return(false);
   return(true);
 }

#endif //HEAP_CHUNK_ENABLE
