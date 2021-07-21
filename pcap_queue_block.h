#ifndef PCAP_QUEUE_BLOCK_H
#define PCAP_QUEUE_BLOCK_H


#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <pcap.h>
#include <string>

#include "tools.h"
#include "voipmonitor.h"
#include "md5.h"
#include "header_packet.h"

#define PCAP_BLOCK_STORE_HEADER_STRING		"pcap_block_store"
#define PCAP_BLOCK_STORE_HEADER_STRING_LEN	16
#define PCAP_BLOCK_STORE_HEADER_VERSION		7

#define FLAG_AUDIOCODES 1
#define FLAG_FRAGMENTED 2


extern int opt_enable_ss7;
extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;
extern bool opt_ipfix;

struct pcap_pkthdr_fix_size {
	uint32_t ts_tv_sec;
	uint32_t ts_tv_usec;
	uint32_t caplen;
	uint32_t len;
	uint32_t _filler1; // sizeof(pcap_pkthdr_fix_size) need eq sizeof(pcap_pkthdr) - for compatibility 32 / 64 bits
	uint32_t _filler2;
};

struct pcap_pkthdr_plus {
	inline pcap_pkthdr_plus() {
		#if __GNUC__ >= 8
		#pragma GCC diagnostic push
		#pragma GCC diagnostic ignored "-Wclass-memaccess"
		#endif
		memset(this, 0, sizeof(pcap_pkthdr_plus));
		#if __GNUC__ >= 8
		#pragma GCC diagnostic pop
		#endif
	}
	inline void convertFromStdHeader(pcap_pkthdr *header) {
		this->std = 0;
		this->header_fix_size.ts_tv_sec = header->ts.tv_sec;
		this->header_fix_size.ts_tv_usec = header->ts.tv_usec;
		this->header_fix_size.caplen = header->caplen;
		this->header_fix_size.len = header->len;
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
		#if __GNUC__ >= 8
		#pragma GCC diagnostic push
		#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
		#endif
		return(&this->header_std);
		#if __GNUC__ >= 8
		#pragma GCC diagnostic pop
		#endif
	}
	inline pcap_pkthdr getStdHeader() {
		if(this->std) {
			return(this->header_std);
		} else {
			pcap_pkthdr header;
			header.ts.tv_sec = this->header_fix_size.ts_tv_sec;
			header.ts.tv_usec = this->header_fix_size.ts_tv_usec;
			header.caplen = this->header_fix_size.caplen;
			header.len = this->header_fix_size.len;
			return(header);
		}
	}
	inline uint32_t get_caplen() {
		return(std ? this->header_std.caplen : this->header_fix_size.caplen);
	}
	inline uint32_t get_len() {
		return(std ? this->header_std.len : this->header_fix_size.len);
	}
	inline void set_caplen(uint32_t caplen) {
		if(std) {
			this->header_std.caplen = caplen;
		} else { 
			this->header_fix_size.caplen = caplen;
		}
	}
	inline void set_len(uint32_t len) {
		if(std) {
			this->header_std.len = len;
		} else {
			this->header_fix_size.len = len;
		}
	}
	inline uint32_t get_tv_sec() {
		return(std ? this->header_std.ts.tv_sec : this->header_fix_size.ts_tv_sec);
	}
	inline uint32_t get_tv_usec() {
		return(std ? this->header_std.ts.tv_usec : this->header_fix_size.ts_tv_usec);
	}
	inline u_int64_t get_time_ms() {
		return(get_tv_sec() * 1000ull + get_tv_usec() / 1000);
	}
	union {
		pcap_pkthdr_fix_size header_fix_size;
		pcap_pkthdr header_std;
	}  __attribute__((packed));
	u_int16_t header_ip_encaps_offset;
	u_int16_t header_ip_offset;
	int16_t std;
	u_int16_t dlink;
	sPacketInfoData pid;
};

struct pcap_pkthdr_plus2 : public pcap_pkthdr_plus {
	inline pcap_pkthdr_plus2() {
		clear();
	}
	inline void clear() {
		detect_headers = 0;
		md5[0] = 0;
		ignore = false;
		pid.clear();
	}
	u_int8_t detect_headers;
	u_int16_t eth_protocol;
	uint16_t md5[MD5_DIGEST_LENGTH / (sizeof(uint16_t) / sizeof(unsigned char))];
	u_int8_t ignore;
};

struct pcap_block_store {
	enum header_mode {
		plus,
		plus2
	};
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
			extern bool opt_pcap_queues_mirror_require_confirmation;
			#if __GNUC__ >= 8
			#pragma GCC diagnostic push
			#pragma GCC diagnostic ignored "-Wstringop-truncation"
			#endif
			strncpy(this->title, PCAP_BLOCK_STORE_HEADER_STRING, PCAP_BLOCK_STORE_HEADER_STRING_LEN);
			#if __GNUC__ >= 8
			#pragma GCC diagnostic pop
			#endif
			this->version = PCAP_BLOCK_STORE_HEADER_VERSION;
			this->hm = plus;
			this->size = 0;
			this->size_compress = 0;
			this->count = 0;
			this->dlink = 0;
			this->sensor_id = 0;
			memset(this->ifname, 0, sizeof(this->ifname));
			this->checksum = 0;
			this->counter = 0;
			this->require_confirmation = opt_pcap_queues_mirror_require_confirmation;
			this->time_s = 0;
		}
		char title[PCAP_BLOCK_STORE_HEADER_STRING_LEN];
		uint8_t version;
		uint32_t size;
		uint32_t size_compress;
		uint32_t count;
		uint16_t dlink;
		int16_t sensor_id;
		char ifname[10];
		int8_t hm;
		uint32_t checksum;
		uint32_t counter;
		uint8_t require_confirmation;
		uint32_t time_s;
	};
	pcap_block_store(header_mode hm = plus) {
		this->hm = hm;
		this->offsets = NULL;
		this->block = NULL;
		this->is_voip = NULL;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		this->_sync_packets_lock = NULL;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		this->_sync_packets_flag = NULL;
		#endif
		#endif
		this->destroy();
		this->restoreBuffer = NULL;
		this->destroyRestoreBuffer();
		this->idFileStore = 0;
		this->filePosition = 0;
		this->timestampMS = getTimeMS_rdtsc();
		this->_sync_packet_lock = 0;
	}
	~pcap_block_store() {
		this->destroy();
		this->destroyRestoreBuffer();
	}
	inline bool add_hp(pcap_pkthdr_plus *header, u_char *packet, int memcpy_packet_size = 0);
	inline void inc_h(pcap_pkthdr_plus2 *header);
	inline bool get_add_hp_pointers(pcap_pkthdr_plus2 **header, u_char **packet, unsigned min_size_for_packet);
	inline bool isFull_checkTimeout();
	inline bool isTimeout();
	inline pcap_pkthdr_pcap operator [] (size_t indexItem) {
		pcap_pkthdr_pcap headerPcap;
		if(indexItem < this->count) {
			headerPcap.header = (pcap_pkthdr_plus*)(this->block + this->offsets[indexItem]);
			headerPcap.packet = (u_char*)headerPcap.header + (hm == plus2 ? sizeof(pcap_pkthdr_plus2) : sizeof(pcap_pkthdr_plus));
		}
		return(headerPcap);
	}
	inline pcap_pkthdr_plus* get_header(size_t indexItem) {
		return((pcap_pkthdr_plus*)(this->block + this->offsets[indexItem]));
	}
	inline u_char* get_packet(size_t indexItem) {
		return((u_char*)(this->block + this->offsets[indexItem] + (hm == plus2 ? sizeof(pcap_pkthdr_plus2) : sizeof(pcap_pkthdr_plus))));
	}
	inline u_char* get_space_after_packet(size_t indexItem) {
		return(get_packet(indexItem) + get_header(indexItem)->get_caplen());
	}
	inline bool is_ignore(size_t indexItem) {
		return(((pcap_pkthdr_plus2*)(this->block + this->offsets[indexItem]))->ignore);
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
	size_t getUseAllSize() {
		return((this->size_compress ? this->size_compress : this->size) + 
		       sizeof(uint32_t) * offsets_size + 
		       sizeof(*this));
	}
	u_char *getSaveBuffer(uint32_t block_counter = 0);
	void restoreFromSaveBuffer(u_char *saveBuffer);
	int addRestoreChunk(u_char *buffer, size_t size, size_t *offset = NULL, bool restoreFromStore = false, string *error = NULL);
	string addRestoreChunk_getErrorString(int errorCode);
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
	bool check_headers(string **error) {
		for(size_t i = 0; i < this->count; i++) {
			pcap_pkthdr_plus *header = (pcap_pkthdr_plus*)(this->block + this->offsets[i]);
			if(header->header_fix_size.caplen > 65535) {
				if(error) {
					*error = new FILE_LINE(0) string("caplen = " + intToString(header->header_fix_size.caplen));
				}
				return(false);
			}
			if(header->header_ip_offset > 1000) {
				if(error) {
					*error = new FILE_LINE(0) string("header_ip_offset = " + intToString(header->header_ip_offset));
				}
				return(false);
			}
		}
		return(true);
	}
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	void lock_packet(int index, int flag) {
	#else
	void lock_packet(int /*index*/, int /*flag*/) {
	#endif
		__sync_add_and_fetch(&this->_sync_packet_lock, 1);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		__sync_add_and_fetch(&this->_sync_packets_lock[index], 1);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		if(flag && this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH] < DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH - 1) {
			__sync_add_and_fetch(&this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH + this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH] + 1], flag);
			__sync_add_and_fetch(&this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH], 1);
		}
		#endif
		#endif
	}
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	void unlock_packet(int index) {
	#else
	void unlock_packet(int /*index*/) {
	#endif
		__sync_sub_and_fetch(&this->_sync_packet_lock, 1);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		if(this->_sync_packets_lock[index] <= 0) {
			syslog(LOG_ERR, "error in sync (unlock) packetbuffer block %lx / %i / %i", (u_int64_t)this, index, this->_sync_packets_lock[index]);
			#if DEBUG_SYNC_PCAP_BLOCK_STORE_ABORT_IF_ERROR
			abort();
			#endif
		}
		__sync_sub_and_fetch(&this->_sync_packets_lock[index], 1);
		#endif
	}
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	void add_flag(int index, int flag) {
	#else
	void add_flag(int /*index*/, int /*flag*/) {
	#endif
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		if(flag && this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH] < DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH - 1) {
			__sync_add_and_fetch(&this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH + this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH] + 1], flag);
			__sync_add_and_fetch(&this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH], 1);
		}
		#endif
		#endif
	}
	bool enableDestroy() {
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		if(this->_sync_packet_lock == 0) {
			for(unsigned i = 0; i < count; i++) {
				if(this->_sync_packets_lock[i] != 0) {
					syslog(LOG_ERR, "error in sync (enableDestroy) packetbuffer block %lx / %i / %i", (u_int64_t)this, i, this->_sync_packets_lock[i]);
					#if DEBUG_SYNC_PCAP_BLOCK_STORE_ABORT_IF_ERROR
					abort();
					#endif
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
	u_int64_t getLastPacketHeaderTimeMS() {
		pcap_pkthdr_plus *pkthdr = (pcap_pkthdr_plus*)(this->block + this->offsets[this->count - 1]);
		return(getTimeMS(pkthdr->header_fix_size.ts_tv_sec, pkthdr->header_fix_size.ts_tv_usec));
	}
	header_mode hm;
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
	vmIP sensor_ip;
	char ifname[10];
	u_int32_t block_counter;
	bool require_confirmation;
	u_char *restoreBuffer;
	size_t restoreBufferSize;
	size_t restoreBufferAllocSize;
	u_int idFileStore;
	u_int64_t filePosition;
	u_int64_t timestampMS;
	volatile int _sync_packet_lock;
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	volatile int8_t *_sync_packets_lock;
	#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
	volatile int8_t *_sync_packets_flag;
	#endif
	#endif
	u_int8_t *is_voip;
};


#endif
