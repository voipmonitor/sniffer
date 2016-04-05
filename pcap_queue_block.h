#ifndef PCAP_QUEUE_BLOCK_H
#define PCAP_QUEUE_BLOCK_H


#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <pcap.h>
#include <string>

#include "tools.h"
#include "voipmonitor.h"

#define PCAP_BLOCK_STORE_HEADER_STRING		"pcap_block_st_03"
#define PCAP_BLOCK_STORE_HEADER_STRING_LEN	16


extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;

struct pcap_pkthdr_fix_size {
	uint64_t ts_tv_sec;
	uint64_t ts_tv_usec;
	uint64_t caplen;
	uint64_t len;
};


struct pcap_pkthdr_plus {
	inline pcap_pkthdr_plus() {
		memset(this, 0, sizeof(pcap_pkthdr_plus));
	}
	inline pcap_pkthdr_plus(pcap_pkthdr header, int offset, u_int16_t dlink) {
		memset(this, 0, sizeof(pcap_pkthdr_plus));
		this->header_fix_size.ts_tv_sec = header.ts.tv_sec;
		this->header_fix_size.ts_tv_usec = header.ts.tv_usec;
		this->header_fix_size.caplen = header.caplen;
		this->header_fix_size.len = header.len;
		this->offset = offset;
		this->dlink = dlink;
	}
	inline pcap_pkthdr *convertToStdHeader() {
		if(!this->std) {
			pcap_pkthdr header;
			header.ts.tv_sec = this->header_fix_size.ts_tv_sec;
			header.ts.tv_usec = this->header_fix_size.ts_tv_usec;
			header.caplen = this->header_fix_size.caplen;
			header.len = this->header_fix_size.len;
			this->header_std = header;
			this->std = 1;
		}
		return(&this->header_std);
	}
	union {
		pcap_pkthdr_fix_size header_fix_size;
		pcap_pkthdr header_std;
	};
	int32_t offset;
	int8_t std;
	u_int16_t dlink;
};

struct pcap_block_store {
	enum compress_method {
		compress_method_default,
		snappy,
		lz4
	};
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
			this->dlink = 0;
			this->sensor_id = 0;
			memset(this->ifname, 0, sizeof(this->ifname));
		}
		char title[PCAP_BLOCK_STORE_HEADER_STRING_LEN];
		uint32_t size;
		uint32_t size_compress;
		uint32_t count;
		uint16_t dlink;
		int16_t sensor_id;
		char ifname[10];
	};
	pcap_block_store() {
		this->offsets = NULL;
		this->block = NULL;
		this->is_voip = NULL;
		this->destroy();
		this->restoreBuffer = NULL;
		this->destroyRestoreBuffer();
		this->idFileStore = 0;
		this->filePosition = 0;
		this->timestampMS = getTimeMS_rdtsc();
		this->_sync_packet_lock = 0;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		this->_sync_packets_lock = new FILE_LINE volatile int[100000];
		memset((void*)this->_sync_packets_lock, 0, sizeof(int) * 100000);
		#endif
	}
	~pcap_block_store() {
		this->destroy();
		this->destroyRestoreBuffer();
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		delete [] this->_sync_packets_lock;
		#endif
	}
	inline bool add(pcap_pkthdr *header, u_char *packet, int offset, int dlink, int memcpy_packet_size = 0);
	inline bool add(pcap_pkthdr_plus *header, u_char *packet);
	inline void inc(pcap_pkthdr *header);
	inline bool get_add_pointers(pcap_pkthdr_plus **header, u_char **packet, unsigned min_size_for_packet);
	inline bool isFull_checkTimeout();
	inline bool isTimeout();
	pcap_pkthdr_pcap operator [] (size_t indexItem) {
		pcap_pkthdr_pcap headerPcap;
		if(indexItem < this->count) {
			headerPcap.header = (pcap_pkthdr_plus*)(this->block + this->offsets[indexItem]);
			headerPcap.packet = (u_char*)headerPcap.header + sizeof(pcap_pkthdr_plus);
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
	inline bool compress();
	bool compress_snappy();
	bool compress_lz4();
	inline bool uncompress(compress_method method = compress_method_default);
	bool uncompress_snappy();
	bool uncompress_lz4();
	bool check_offsets() {
		for(size_t i = 0; i < this->offsets_size - 1; i++) {
			if(this->offsets[i] >= this->offsets[i + 1]) {
				return(false);
			}
		}
		return(this->offsets[this->offsets_size - 1] < this->size);
	}
	bool check_headers() {
		for(size_t i = 0; i < this->count; i++) {
			pcap_pkthdr_plus *header = (pcap_pkthdr_plus*)(this->block + this->offsets[i]);
			if(header->header_fix_size.caplen > 65535 || header->offset > 1000) {
				return(false);
			}
		}
		return(true);
	}
	void lock_packet(int index) {
		__sync_add_and_fetch(&this->_sync_packet_lock, 1);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		__sync_add_and_fetch(&this->_sync_packets_lock[index], 1);
		#endif
	}
	void unlock_packet(int index) {
		__sync_sub_and_fetch(&this->_sync_packet_lock, 1);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		__sync_sub_and_fetch(&this->_sync_packets_lock[index], 1);
		if(this->_sync_packets_lock[index] < 0) {
			syslog(LOG_ERR, "error in sync (unlock) packetbuffer block %lx / %i / %i", (u_int64_t)this, index, this->_sync_packets_lock[index]);
			abort();
		}
		#endif
	}
	bool enableDestroy() {
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		if(this->_sync_packet_lock == 0) {
			for(unsigned i = 0; i < count; i++) {
				if(this->_sync_packets_lock[i] != 0) {
					syslog(LOG_ERR, "error in sync (unlock) packetbuffer block %lx / %i / %i", (u_int64_t)this, i, this->_sync_packets_lock[i]);
					abort();
				}
			}
			return(true);
		} else {
			return(false);
		}
		#else
		return(this->_sync_packet_lock == 0);
		#endif
	}
	void setVoipPacket(int index) {
		if(is_voip && index < (int)count) {
			is_voip[index] = 1;
		}
	}
	uint32_t *offsets;
	u_char *block;
	size_t size;
	size_t size_compress;
	size_t size_packets;
	size_t count;
	size_t offsets_size;
	bool full;
	uint16_t dlink;
	int16_t sensor_id;
	uint32_t sensor_ip;
	char ifname[10];
	u_char *restoreBuffer;
	size_t restoreBufferSize;
	size_t restoreBufferAllocSize;
	u_int idFileStore;
	u_long filePosition;
	u_long timestampMS;
	volatile int _sync_packet_lock;
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	volatile int *_sync_packets_lock;
	#endif
	u_int8_t *is_voip;
};


#endif
