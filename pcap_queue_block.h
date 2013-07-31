#ifndef PCAP_QUEUE_BLOCK_H
#define PCAP_QUEUE_BLOCK_H


#include <stdlib.h>
#include <memory.h>
#include <pcap.h>
#include <string>

#define PCAP_BLOCK_STORE_HEADER_STRING		"pcap_block_store"
#define PCAP_BLOCK_STORE_HEADER_STRING_LEN	16


u_long getTimeMS();
unsigned long long getTimeNS();


struct pcap_pkthdr_plus : public pcap_pkthdr {
	pcap_pkthdr_plus() {
		memset(this, 0, sizeof(pcap_pkthdr_plus));
	}
	pcap_pkthdr_plus(pcap_pkthdr header, int offset = -1) {
		memset(this, 0, sizeof(pcap_pkthdr_plus));
		this->ts = header.ts;
		this->caplen = header.caplen;
		this->len = header.len;
		this->offset = offset;
	}
	int offset;
};

struct pcap_block_store {
	struct pcap_pkthdr_pcap {
		pcap_pkthdr_pcap() {
			this->header = NULL;
			this->packet = NULL;
		}
		pcap_pkthdr_plus *header;
		u_char *packet;
	};
	struct pcap_block_store_header {
		pcap_block_store_header() {
			strncpy(this->title, PCAP_BLOCK_STORE_HEADER_STRING, PCAP_BLOCK_STORE_HEADER_STRING_LEN);
			this->size = 0;
			this->size_compress = 0;
			this->count = 0;
		}
		char title[PCAP_BLOCK_STORE_HEADER_STRING_LEN];
		uint32_t size;
		uint32_t size_compress;
		uint32_t count;
	};
	pcap_block_store() {
		this->offsets = NULL;
		this->block = NULL;
		this->destroy();
		this->restoreBuffer = NULL;
		this->destroyRestoreBuffer();
		this->idFileStore = 0;
		this->filePosition = 0;
		this->timestampMS = getTimeMS();
		/*
		this->packet_lock = NULL;
		*/
		this->_sync_packet_lock = 0;
	}
	~pcap_block_store() {
		this->destroy();
		this->destroyRestoreBuffer();
		/*
		if(this->packet_lock) {
			free(this->packet_lock);
		}
		*/
	}
	inline bool add(pcap_pkthdr *header, u_char *packet, int offset = -1);
	inline bool add(pcap_pkthdr_plus *header, u_char *packet);
	pcap_pkthdr_pcap operator [] (size_t indexItem) {
		pcap_pkthdr_pcap headerPcap;
		if(indexItem < this->count) {
			headerPcap.header = (pcap_pkthdr_plus*)(this->block + this->offsets[indexItem]);
			headerPcap.packet = (u_char*)(this->block + this->offsets[indexItem] + sizeof(pcap_pkthdr_plus));
		}
		return(headerPcap);
	}
	void destroy();
	void destroyRestoreBuffer();
	bool isEmptyRestoreBuffer();
	void freeBlock();
	size_t getSizeSaveBuffer() {
		return(sizeof(pcap_block_store_header) + this->count * sizeof(uint32_t) + this->getUseSize());
	}
	int getSizeSaveBufferFromRestoreBuffer() {
		if(this->restoreBufferSize >= sizeof(pcap_block_store_header)) {
			pcap_block_store_header *header = (pcap_block_store_header*)this->restoreBuffer;
			return(sizeof(pcap_block_store_header) + header->count * sizeof(uint32_t) + 
			       (header->size_compress ? header->size_compress : header->size));
		}
		return(-1);
	}
	size_t getUseSize() {
		return(this->size_compress ? this->size_compress : this->size);
	}
	u_char *getSaveBuffer();
	void restoreFromSaveBuffer(u_char *saveBuffer);
	int addRestoreChunk(u_char *buffer, size_t size, size_t *offset = NULL, bool autoRestore = true);
	bool compress();
	bool uncompress();
	void lock_packet(int index) {
		__sync_add_and_fetch(&this->_sync_packet_lock, 1);
		/*
		this->lock_sync_packet_lock();
		if(!this->packet_lock) {
			this->packet_lock = (bool*)calloc(this->count, sizeof(bool));
		}
		this->packet_lock[index] = true;
		this->unlock_sync_packet_lock();
		*/
	}
	void unlock_packet(int index) {
		__sync_sub_and_fetch(&this->_sync_packet_lock, 1);
		/*
		this->lock_sync_packet_lock();
		if(this->packet_lock) {
			this->packet_lock[index] = false;
		}
		this->unlock_sync_packet_lock();
		*/
	}
	bool enableDestroy() {
		return(this->_sync_packet_lock == 0);
		/*
		bool enableDestroy = true;
		this->lock_sync_packet_lock();
		bool checkLock = true;
		if(this->packet_lock &&
		   memmem(this->packet_lock, this->count * sizeof(bool), &checkLock, sizeof(bool))) {
			enableDestroy = false;
		}
		this->unlock_sync_packet_lock();
		return(enableDestroy);
		*/
	}
	/*
	void lock_sync_packet_lock() {
		while(__sync_lock_test_and_set(&this->_sync_packet_lock, 1));
	}
	void unlock_sync_packet_lock() {
		__sync_lock_release(&this->_sync_packet_lock);
	}
	*/
	//
	uint32_t *offsets;
	u_char *block;
	size_t size;
	size_t size_compress;
	size_t count;
	size_t offsets_size;
	bool full;
	u_char *restoreBuffer;
	size_t restoreBufferSize;
	size_t restoreBufferAllocSize;
	u_int idFileStore;
	u_long filePosition;
	u_long timestampMS;
	//bool *packet_lock;
	volatile int _sync_packet_lock;
};


#endif
