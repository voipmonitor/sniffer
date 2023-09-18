#ifndef PACKET_DUPL_CHECK_H
#define PACKET_DUPL_CHECK_H


#include <zlib.h>

#include "crc.h"


struct sPacketDuplCheck {
	union {
		uint16_t md5[MD5_DIGEST_LENGTH / (sizeof(uint16_t) / sizeof(unsigned char))];
		uint32_t crc;
		uint32_t first_32_bits;
		struct {
			uint16_t low_16_bits;
			uint16_t high_16_bits;
		};
	};
	inline void clear() {
		first_32_bits = 0;
	}
	inline bool is_empty() {
		return(first_32_bits == 0);
	}
	inline bool check_dupl_md5(u_char *dedup_buffer) {
		return(memcmp(md5, dedup_buffer + (md5[0] * MD5_DIGEST_LENGTH), MD5_DIGEST_LENGTH) == 0);
	}
	inline bool check_dupl_crc(u_char *dedup_buffer) {
		return(*(uint16_t*)(dedup_buffer + (low_16_bits * sizeof(high_16_bits))) == high_16_bits);
	}
	inline void store_md5(u_char *dedup_buffer) {
		memcpy(dedup_buffer + (md5[0] * MD5_DIGEST_LENGTH), md5, MD5_DIGEST_LENGTH);
	}
	inline void store_crc(u_char *dedup_buffer) {
		*(uint16_t*)(dedup_buffer + (low_16_bits * sizeof(high_16_bits))) = high_16_bits;
	}
	inline bool check_dupl(u_char *dedup_buffer, int8_t _type) {
		return(_type == 1 ? 
			check_dupl_md5(dedup_buffer) :
			check_dupl_crc(dedup_buffer));
	}
	inline void store(u_char *dedup_buffer, int8_t _type) {
		if(_type == 1) {
			store_md5(dedup_buffer);
		} else {
			store_crc(dedup_buffer);
		}
	}
} __attribute__((packed));

struct sPacketDuplCheckProc {
	inline sPacketDuplCheckProc(sPacketDuplCheck *dc, int8_t _type) {
		this->dc = dc;
		this->_type = _type;
		dc->clear();
		if(_type == 1) {
			MD5_Init(&ctx);
		}
	}
	inline void data_md5(u_char *data, unsigned len) {
		MD5_Update(&ctx, data, len);
	}
	inline void final_md5() {
		MD5_Final((unsigned char*)dc->md5, &ctx);
	}
	inline void data_crc(u_char *data, unsigned len) {
		dc->crc = 
			  #if CRC_SSE and (defined(__x86_64__) or defined(__i386__))
			  _type == 3 ? crc32_sse(dc->crc, (const char*)data, len) :
			  #endif
			  crc32(dc->crc, data, len);
	}
	inline void data(void *data, unsigned len) {
		if(_type == 1) {
			data_md5((u_char*)data, len);
		} else {
			data_crc((u_char*)data, len);
		}
	}
	inline void final() {
		if(_type == 1) {
			final_md5();
		}
	}
	sPacketDuplCheck *dc;
	int8_t _type;
	MD5_CTX ctx;
};


#endif
