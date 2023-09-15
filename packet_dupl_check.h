#ifndef PACKET_DUPL_CHECK_H
#define PACKET_DUPL_CHECK_H


#include <zlib.h>


struct sPacketDuplCheck {
	union {
		uint16_t md5[MD5_DIGEST_LENGTH / (sizeof(uint16_t) / sizeof(unsigned char))];
		uint32_t crc;
		uint32_t first_32_bits;
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
		return(memcmp(&crc, dedup_buffer + ((u_int16_t)crc * sizeof(crc)), sizeof(crc)) == 0);
	}
	inline void store_md5(u_char *dedup_buffer) {
		memcpy(dedup_buffer + (md5[0] * MD5_DIGEST_LENGTH), md5, MD5_DIGEST_LENGTH);
	}
	inline void store_crc(u_char *dedup_buffer) {
		memcpy(dedup_buffer + ((u_int16_t)crc * sizeof(crc)), &crc, sizeof(crc));
	}
	inline bool check_dupl(u_char *dedup_buffer, bool _crc = false) {
		return(_crc ? 
			check_dupl_crc(dedup_buffer) :
			check_dupl_md5(dedup_buffer));
	}
	inline void store(u_char *dedup_buffer, bool _crc = false) {
		if(_crc) {
			store_crc(dedup_buffer);
		} else {
			store_md5(dedup_buffer);
		}
	}
} __attribute__((packed));

struct sPacketDuplCheckProc {
	inline sPacketDuplCheckProc(sPacketDuplCheck *dc, bool _crc = false) {
		this->dc = dc;
		this->_crc = _crc;
		dc->clear();
		if(!_crc) {
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
		dc->crc = crc32(dc->crc, data, len);
	}
	inline void data(void *data, unsigned len) {
		if(_crc) {
			data_crc((u_char*)data, len);
		} else {
			data_md5((u_char*)data, len);
		}
	}
	inline void final() {
		if(!_crc) {
			final_md5();
		}
	}
	sPacketDuplCheck *dc;
	bool _crc;
	MD5_CTX ctx;
};


#endif
