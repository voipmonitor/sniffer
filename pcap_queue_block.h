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
#include "dpdk.h"

#define PCAP_BLOCK_STORE_HEADER_STRING		"pcap_block_store"
#define PCAP_BLOCK_STORE_HEADER_STRING_LEN	16
#define PCAP_BLOCK_STORE_HEADER_VERSION		7

#define FLAG_AUDIOCODES 1
#define FLAG_FRAGMENTED 2

#if PACKETBUFFER_ALIGNMENT
#define PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE ((sizeof(pcap_pkthdr_plus2) + PACKETBUFFER_ALIGNMENT - 1) & ~(PACKETBUFFER_ALIGNMENT - 1))
#define PACKETBUFFER_ALIGN_PCAP_SIZE(size) (((size) + PACKETBUFFER_ALIGNMENT - 1) & ~(PACKETBUFFER_ALIGNMENT - 1))
#else
#define PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE (sizeof(pcap_pkthdr_plus2))
#define PACKETBUFFER_ALIGN_PCAP_SIZE(size) (size)
#endif

extern int opt_enable_ss7;
extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;
extern bool opt_ipfix;
extern bool opt_hep;

#if not PCAP_QUEUE_PCAP_HEADER_FORCE_STD
struct pcap_pkthdr_fix_size {
	uint32_t ts_tv_sec;
	uint32_t ts_tv_usec;
	uint32_t caplen;
	uint32_t len;
	uint32_t _filler1; // sizeof(pcap_pkthdr_fix_size) need eq sizeof(pcap_pkthdr) - for compatibility 32 / 64 bits
	uint32_t _filler2;
};
#endif

struct pcap_pkthdr_plus {
	inline pcap_pkthdr_plus() {
		memset((void*)this, 0, sizeof(pcap_pkthdr_plus));
	}
	inline void convertFromStdHeader(pcap_pkthdr *header) {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			this->header = *header;
		#else
			this->std = 0;
			this->header_fix_size.ts_tv_sec = header->ts.tv_sec;
			this->header_fix_size.ts_tv_usec = header->ts.tv_usec;
			this->header_fix_size.caplen = header->caplen;
			this->header_fix_size.len = header->len;
		#endif
	}
	inline void convertFromStdHeaderToStd(pcap_pkthdr *header) {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			this->header = *header;
		#else
			this->std = 1;
			this->header_std = *header;
		#endif
	}
	inline pcap_pkthdr *convertToStdHeader() {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			return(&this->header);
		#else
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
		#endif
	}
	inline pcap_pkthdr getStdHeader() {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			return(this->header);
		#else
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
		#endif
	}
	inline pcap_pkthdr *_getStdHeader() {
		return((pcap_pkthdr*)this);
	}
	inline uint32_t get_caplen() {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			return(this->header.caplen);
		#else
			return(std ? this->header_std.caplen : this->header_fix_size.caplen);
		#endif
	}
	inline uint32_t get_len() {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			return(this->header.len);
		#else
			return(std ? this->header_std.len : this->header_fix_size.len);
		#endif
	}
	inline void set_caplen(uint32_t caplen) {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			this->header.caplen = caplen;
		#else
			if(std) {
				this->header_std.caplen = caplen;
			} else { 
				this->header_fix_size.caplen = caplen;
			}
		#endif
	}
	inline void set_len(uint32_t len) {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			this->header.len = len;
		#else
			if(std) {
				this->header_std.len = len;
			} else {
				this->header_fix_size.len = len;
			}
		#endif
	}
	inline uint32_t get_tv_sec() {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			return(this->header.ts.tv_sec);
		#else
			return(std ? this->header_std.ts.tv_sec : this->header_fix_size.ts_tv_sec);
		#endif
	}
	inline uint32_t get_tv_usec() {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			return(this->header.ts.tv_usec);
		#else
			return(std ? this->header_std.ts.tv_usec : this->header_fix_size.ts_tv_usec);
		#endif
	}
	inline timeval get_ts() {
		#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			return(this->header.ts);
		#else
			if(std) {
				return(this->header_std.ts);
			} else {
				timeval ts;
				ts.tv_sec = this->header_fix_size.ts_tv_sec;
				ts.tv_usec = this->header_fix_size.ts_tv_usec;
				return(ts);
			}
		#endif
	}
	inline u_int64_t get_time_ms() {
		return(get_tv_sec() * 1000ull + get_tv_usec() / 1000);
	}
	inline u_int64_t get_time_us() {
		return(get_tv_sec() * 1000000ull + get_tv_usec());
	}
	#if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
		pcap_pkthdr header;
	#else
		union {
			pcap_pkthdr_fix_size header_fix_size;
			pcap_pkthdr header_std;
		}  __attribute__((packed));
	#endif
	u_int16_t header_ip_encaps_offset;
	u_int16_t header_ip_offset;
	#if not PCAP_QUEUE_PCAP_HEADER_FORCE_STD
		int16_t std;
	#endif
	u_int16_t dlink;
	sPacketInfoData pid;
};

struct pcap_pkthdr_plus2 : public pcap_pkthdr_plus {
	inline pcap_pkthdr_plus2() {
		clear();
	}
	inline void clear() {
		detect_headers = 0;
		dc.clear();
		#if DEDUPLICATE_COLLISION_TEST
		dc_ct_md5.clear();
		#endif
		ignore = false;
		pid.clear();
	}
	inline void clear_ext() {
		memset((void*)this, 0, sizeof(*this));
		clear();
	}
	u_int8_t detect_headers;
	u_int16_t eth_protocol;
	sPacketDuplCheck dc;
	#if DEDUPLICATE_COLLISION_TEST
	sPacketDuplCheck dc_ct_md5;
	#endif
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
	struct s_dpdk_data {
		pcap_pkthdr_plus2 header;
		u_char *packet;
		void *mbuf;
	};
	pcap_block_store(header_mode hm = plus, bool dpdk = false) {
		this->hm = hm;
		this->dpdk = dpdk;
		this->offsets = NULL;
		this->dpdk_data_size = 0;
		this->dpdk_data = NULL;
		this->block = NULL;
		this->is_voip = NULL;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		this->_sync_packets_lock = NULL;
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		this->_sync_packets_flag = NULL;
		#endif
		#endif
		this->destroy(true);
		this->restoreBuffer = NULL;
		this->destroyRestoreBuffer();
		this->idFileStore = 0;
		this->filePosition = 0;
		this->timestampMS = getTimeMS_rdtsc();
		this->pushToTrashMS = 0;
		this->_sync_packet_lock = 0;
		this->_destroy_flag = 0;
		#if DEBUG_DESTROY_PCAP_BLOCK_STORE
		destroy_src_flag[0] = 0;
		destroy_src_flag[1] = 0;
		strcpy(destroy_bt, "empty");
		#endif
		#if DEBUG_PB_BLOCKS_SEQUENCE
		static u_int64_t pb_blocks_sequence_init = 0;
		pb_blocks_sequence = ++pb_blocks_sequence_init;
		#endif
	}
	~pcap_block_store() {
		if(SAFE_ATOMIC_LOAD(this->_destroy_flag) == 0) {
			this->destroy();
			this->destroyRestoreBuffer();
		} else {
			double_destroy_log();
		}
	}
	inline void init(bool prefetch);
	inline void clear(bool prefetch);
	inline void copy(pcap_block_store *from);
	inline bool add_hp(pcap_pkthdr_plus *header, u_char *packet, int memcpy_packet_size = 0);
	bool add_hp_ext(pcap_pkthdr_plus *header, u_char *packet, int memcpy_packet_size = 0);
	inline void inc_h(pcap_pkthdr_plus2 *header) {
		inc_h(header->get_caplen());
	}
	void inc_h(u_int32_t caplen);
	inline bool get_add_hp_pointers(pcap_pkthdr_plus2 **header, u_char **packet, unsigned min_size_for_packet);
	inline void add_dpdk(pcap_pkthdr_plus2 *header, void *mbuf);
	inline bool is_dpkd_data_full();
	inline bool isFull_checkTimeout(unsigned timeout_ms = 0);
	bool isFull_checkTimeout_ext(unsigned timeout_ms = 0);
	inline bool isTimeout();
	inline pcap_pkthdr_pcap operator [] (size_t indexItem) {
		pcap_pkthdr_pcap headerPcap;
		if(indexItem < this->count) {
			if(dpdk) {
				headerPcap.header = (pcap_pkthdr_plus*)&this->dpdk_data[indexItem].header;
				headerPcap.packet = this->dpdk_data[indexItem].packet;
			} else {
				headerPcap.header = (pcap_pkthdr_plus*)(this->block + this->offsets[indexItem]);
				headerPcap.packet = (u_char*)headerPcap.header + (hm == plus2 ? PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE : sizeof(pcap_pkthdr_plus));
			}
		}
		return(headerPcap);
	}
	inline pcap_pkthdr_plus* get_header(size_t indexItem) {
		return(dpdk ?
			(pcap_pkthdr_plus*)&this->dpdk_data[indexItem].header :
			(pcap_pkthdr_plus*)(this->block + this->offsets[indexItem]));
	}
	inline u_char* get_packet(size_t indexItem) {
		return(dpdk ?
			this->dpdk_data[indexItem].packet :
			(u_char*)(this->block + this->offsets[indexItem] + (hm == plus2 ? PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE : sizeof(pcap_pkthdr_plus))));
	}
	inline u_char* get_space_after_packet(size_t indexItem) {
		return(get_packet(indexItem) + get_header(indexItem)->get_caplen());
	}
	inline bool is_ignore(size_t indexItem) {
		return(dpdk ?
			this->dpdk_data[this->count - 1].header.ignore :
			hm == plus2 && ((pcap_pkthdr_plus2*)(this->block + this->offsets[indexItem]))->ignore);
	}
	void dpdk_free(size_t indexItem) {
		if(dpdk && this->dpdk_data[indexItem].mbuf) {
			dpdk_mbuf_free(this->dpdk_data[indexItem].mbuf);
			this->dpdk_data[indexItem].mbuf = NULL;
		}
	}
	void destroy(bool init = false);
	void double_destroy_log();
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
	size_t getSizePackets() {
		if(size_packets) {
			return(size_packets);
		}
		size_t size_headers = count * (hm == plus2 ? PACKETBUFFER_ALIGN_PCAP_PKTHDR_PLUS2_SIZE : sizeof(pcap_pkthdr_plus));
		if(size > size_headers) {
			return(size - size_headers);
		}
		return(0);
	}
	size_t getCountPackets() {
		return(count);
	}
	u_char *getSaveBuffer(uint32_t block_counter = 0);
	void restoreFromSaveBuffer(u_char *saveBuffer);
	int addRestoreChunk(u_char *buffer, u_char *buffer_alloc_begin, size_t size, size_t *offset = NULL, bool restoreFromStore = false, string *error = NULL);
	string addRestoreChunk_getErrorString(int errorCode);
	inline bool compress();
	bool compress_snappy();
	bool compress_lz4();
	inline bool uncompress(compress_method method = compress_method_default);
	bool uncompress_snappy();
	bool uncompress_lz4();
	bool check_offsets() {
		if(dpdk) {
			return(true);
		} else {
			for(size_t i = 0; i < this->offsets_size - 1; i++) {
				if(this->offsets[i] >= this->offsets[i + 1]) {
					return(false);
				}
			}
			return(this->offsets[this->offsets_size - 1] < this->size);
		}
	}
	bool check_headers(string **error) {
		for(size_t i = 0; i < this->count; i++) {
			pcap_pkthdr_plus *header = dpdk ? 
						    &this->dpdk_data[this->count - 1].header :
						    (pcap_pkthdr_plus*)(this->block + this->offsets[i]);
			if(
			   #if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
			   header->header.caplen
			   #else
			   header->header_fix_size.caplen
			   #endif
			   > 65535) {
				if(error) {
					*error = new FILE_LINE(0) string("caplen = " + intToString(
												   #if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
												   header->header.caplen
												   #else
												   header->header_fix_size.caplen
												   #endif
												   ));
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
		__SYNC_INC(this->_sync_packet_lock);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		__SYNC_INC(this->_sync_packets_lock[index]);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		if(flag && this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH] < DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH - 1) {
			__SYNC_ADD(this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH + this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH] + 1], flag);
			__SYNC_INC(this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH]);
		}
		#endif
		#endif
	}
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	void unlock_packet(int index) {
	#else
	void unlock_packet(int index) {
	#endif
		__SYNC_DEC(this->_sync_packet_lock);
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		if(this->_sync_packets_lock[index] <= 0) {
			syslog(LOG_ERR, "error in sync (unlock) packetbuffer block %lx / %i / %i", (u_int64_t)this, index, this->_sync_packets_lock[index]);
			#if DEBUG_SYNC_PCAP_BLOCK_STORE_ABORT_IF_ERROR
			abort();
			#endif
		}
		__SYNC_DEC(this->_sync_packets_lock[index]);
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
			__SYNC_ADD(this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH + this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH] + 1], flag);
			__SYNC_INC(this->_sync_packets_flag[index * DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH]);
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
		return(SAFE_ATOMIC_LOAD(this->_sync_packet_lock) == 0);
		#endif
	}
	void setVoipPacket(int index) {
		if(is_voip && index < (int)count) {
			is_voip[index] = 1;
		}
	}
	u_int64_t getLastPacketHeaderTimeMS() {
		pcap_pkthdr_plus *pkthdr = dpdk ? 
					    &this->dpdk_data[this->count - 1].header :
					    (pcap_pkthdr_plus*)(this->block + this->offsets[this->count - 1]);
		return(
		       #if PCAP_QUEUE_PCAP_HEADER_FORCE_STD
		       getTimeMS(pkthdr->header.ts.tv_sec, pkthdr->header.ts.tv_usec)
		       #else
		       getTimeMS(pkthdr->header_fix_size.ts_tv_sec, pkthdr->header_fix_size.ts_tv_usec)
		       #endif
		);
	}
	header_mode hm;
	bool dpdk;
	uint32_t *offsets;
	unsigned dpdk_data_size;
	s_dpdk_data *dpdk_data;
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
	u_int64_t pushToTrashMS;
	volatile int _sync_packet_lock;
	volatile int _destroy_flag;
	#if DEBUG_DESTROY_PCAP_BLOCK_STORE
	volatile int destroy_src_flag[2];
	char destroy_bt[1000];
	#endif
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	volatile int8_t *_sync_packets_lock;
	#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
	volatile int8_t *_sync_packets_flag;
	#endif
	#endif
	u_int8_t *is_voip;
	#if DEBUG_PB_BLOCKS_SEQUENCE
	u_int64_t pb_blocks_sequence;
	#endif
};


struct packet_flags {
 
	static const uint16_t TCP_MASK            = ((1 << 0) | (1 << 1));
	static const uint16_t SS7_MASK            = (1 << 2);
	static const uint16_t MRCP_MASK           = (1 << 3);
	static const uint16_t SSL_MASK            = (1 << 4);
	static const uint16_t SKINNY_MASK         = (1 << 5);
	static const uint16_t MGCP_MASK           = (1 << 6);
	static const uint16_t DTLS_HANDSHAKE_MASK = (1 << 7);
	static const uint16_t DIAMETER_MASK       = (1 << 8);
	
	uint16_t flags;

	inline void init() { flags = 0; }
	
	inline void set_tcp(uint8_t value) { flags = (flags & ~TCP_MASK) | (value & TCP_MASK); }
	inline uint8_t get_tcp() { return(flags & TCP_MASK); }
	
	inline void set_ss7(bool value) { flags = (flags & ~SS7_MASK) | (value ? SS7_MASK : 0); }
	inline bool is_ss7() { return(flags & SS7_MASK) != 0; }
	
	inline void set_mrcp(bool value) { flags = (flags & ~MRCP_MASK) | (value ? MRCP_MASK : 0); }
	inline bool is_mrcp() { return((flags & MRCP_MASK) != 0); }

	inline void set_ssl(bool value) { flags = (flags & ~SSL_MASK) | (value ? SSL_MASK : 0); }
	inline bool is_ssl() { return((flags & SSL_MASK) != 0); }

	inline void set_skinny(bool value) { flags = (flags & ~SKINNY_MASK) | (value ? SKINNY_MASK : 0); }
	inline bool is_skinny() { return((flags & SKINNY_MASK) != 0); }

	inline void set_mgcp(bool value) { flags = (flags & ~MGCP_MASK) | (value ? MGCP_MASK : 0); }
	inline bool is_mgcp() { return((flags & MGCP_MASK) != 0); }

	inline void set_dtls_handshake(bool value) { flags = (flags & ~DTLS_HANDSHAKE_MASK) | (value ? DTLS_HANDSHAKE_MASK : 0); }
	inline bool is_dtls_handshake() { return((flags & DTLS_HANDSHAKE_MASK) != 0); }

	inline void set_diameter(bool value) { flags = (flags & ~DIAMETER_MASK) | (value ? DIAMETER_MASK : 0); }
	inline bool is_diameter() { return((flags & DIAMETER_MASK) != 0); }

	inline bool other_processing() {
		return(is_ss7());
	}
	inline bool rtp_processing() {
		return(is_mrcp());
	}
	inline bool call_signalling() {
		return((flags & (TCP_MASK | SS7_MASK | SSL_MASK | SKINNY_MASK | MGCP_MASK)) != 0);
	}
};

struct sHeaderPacketPQout {
	pcap_pkthdr_plus *header;
	u_char *packet;
	pcap_block_store *block_store;
	u_int32_t block_store_index;
	u_int16_t dlt; 
	int16_t sensor_id; 
	vmIP sensor_ip;
	bool block_store_locked;
	u_int16_t header_ip_last_offset;
	//
	u_int16_t header_ip_offset;
	u_int16_t header_ip_encaps_offset;
	u_int8_t header_ip_protocol;
	packet_flags pflags;
	vmPort sport, dport;
	u_int16_t data_offset;
	u_int32_t datalen;
	sHeaderPacketPQout() {
	}
	sHeaderPacketPQout(pcap_pkthdr *header, u_char *packet,
			   u_int16_t dlt, int16_t sensor_id, vmIP sensor_ip) {
		this->header = new FILE_LINE(0) pcap_pkthdr_plus;
		this->header->convertFromStdHeaderToStd(header);
		delete header;
		this->packet = packet;
		this->block_store = NULL;
		this->block_store_index = 0;
		this->dlt = dlt;
		this->sensor_id = sensor_id;
		this->sensor_ip = sensor_ip;
		this->block_store_locked = false;
		this->header_ip_last_offset = 0xFFFF;
		//
		this->header_ip_offset = 0xFFFF;
		this->header_ip_encaps_offset = 0xFFFF;
		this->header_ip_protocol = 0;
		this->pflags.init();
		this->sport = 0;
		this->dport = 0;
		this->data_offset = 0;
		this->datalen = 0;
		#if DEBUG_ALLOC_PACKETS
		if(!block_store) {
			debug_alloc_packet_alloc(packet, "sHeaderPacketPQout::sHeaderPacketPQout");
		}
		#endif
	}
	void destroy_or_unlock_blockstore() {
		if(block_store) {
			if(block_store_locked) {
				block_store->unlock_packet(block_store_index);
				block_store_locked = false;
			}
		} else {
			delete header;
			#if DEBUG_ALLOC_PACKETS
			debug_alloc_packet_free(packet);
			#endif
			delete [] packet;
		}
	}
	void alloc_and_copy_blockstore() {
		if(block_store) {
			pcap_pkthdr_plus *alloc_header = new FILE_LINE(16001) pcap_pkthdr_plus;
			u_char *alloc_packet = new FILE_LINE(16002) u_char[header->get_caplen()];
			#if DEBUG_ALLOC_PACKETS
			debug_alloc_packet_alloc(alloc_packet, "sHeaderPacketPQout::alloc_and_copy_blockstore");
			#endif
			memcpy(alloc_header, header, sizeof(pcap_pkthdr_plus));
			memcpy(alloc_packet, packet, header->get_caplen());
			header = alloc_header;
			packet = alloc_packet;
			if(block_store_locked) {
				block_store->unlock_packet(block_store_index);
				block_store_locked = false;
			}
			block_store = NULL;
			block_store_index = 0;
		}
	}
	#if DEBUG_SYNC_PCAP_BLOCK_STORE
	inline void blockstore_addflag(int flag) {
	#else
	inline void blockstore_addflag(int /*flag*/) {
	#endif
		#if DEBUG_SYNC_PCAP_BLOCK_STORE
		#if DEBUG_SYNC_PCAP_BLOCK_STORE_FLAGS_LENGTH
		if(block_store) {
			block_store->add_flag(block_store_index, flag);
		}
		#endif
		#endif
	}
};


#endif
