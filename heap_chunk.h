#ifndef HEAP_CHUNK_H
#define HEAP_CHUNK_H

#ifdef HEAP_CHUNK_ENABLE

class cLocalHeap
 { protected:
    struct sHeader
     { unsigned int Size;
       sHeader *PrevReal;
       sHeader *PrevFree;
       sHeader *NextFree;
     };
   public:
    cLocalHeap(unsigned int size,bool initBuff = true,
               bool autoDeallocInDestructor = true);
    ~cLocalHeap();
    void *MAlloc(unsigned int sizeOfObject);
    void Free(void *pointerToObject);
    bool IsOwnItem(const void *pointerToObject);
    void InitBuff();
    bool Check();
   private:
    inline void *Alloc(unsigned int size);
    inline void *CreateHeap(unsigned int size);
    inline void *ExtendHeap(unsigned int size);
    inline void *AllocatePartialBlock(sHeader *block,unsigned int size);
    inline void PullFreeBlock(sHeader *block);
    inline void FreeLastBlock();
    inline void FreeInnerBlock(sHeader *block);
    inline void InsertFreeBlock(sHeader *block);
    inline void JoinFreeBlocks(sHeader *block1,sHeader *block2);
    inline void SetBreak(void *pointer);
    inline void *IncrementBreak(unsigned int increment);
   private:
    unsigned int Size;
    char *Buff;
    char *Break;
    sHeader *First;
    sHeader *Last;
    sHeader *Rover;
    bool AutoDeallocInDestructor;
 };
 
 
void *ChunkMAlloc(unsigned int sizeOfObject);
void ChunkFree(void *pointerToObject);
bool IsChunkAllocItem(const void *pointerToObject);
bool CheckChunkAlloc();


#define MAX_CHUNK_ALLOC_ITEMS    1000
#define DEFAULT_CHUNK_ALLOC_SIZE 100000000


class cChunkAllocHeapItem : public cLocalHeap
 { public:
    cChunkAllocHeapItem();
    void *MAlloc(unsigned int sizeOfObject);
    void Free(void *pointerToObject);
    bool IsOwnItem(const void *pointerToObject);
    bool Check();
   private:
    bool Active;
    bool Full;
   friend class cChunkAllocHeap;
 };


class cChunkAllocHeap
 { public:
    cChunkAllocHeap();
    void *MAlloc(unsigned int sizeOfObject);
    void Free(void *pointerToObject);
    bool IsOwnItem(const void *pointerToObject);
    bool Check();
   public:
    bool Active;
   private:
    cChunkAllocHeapItem AllocHeapItems[MAX_CHUNK_ALLOC_ITEMS];
    int CountActiveAllocHeapItems;
 };
 
#endif //HEAP_CHUNK_ENABLE

#endif //HEAP_CHUNK_H
