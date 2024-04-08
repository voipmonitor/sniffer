#ifndef PACKET_DUPL_CHECK_H
#define PACKET_DUPL_CHECK_H


#include <zlib.h>
#if HAVE_LIBBLAKE3
#include <blake3.h>
#endif

#include "crc.h"
#include "tools_rdtsc.h"

#ifdef CLOUD_ROUTER_CLIENT
#include "murmur_hash.h"
#endif


enum eDedupType {
	_dedup_na,
	_dedup_md5,
	_dedup_crc32_sw,
	_dedup_crc32_hw,
	_dedup_crc64,
	#if HAVE_LIBBLAKE3
	_dedup_blake3,
	#endif
	#if MURMUR_HASH
	_dedup_murmur,
	#endif
	_dedup_last
};


struct sPacketDuplCheck {
	union {
		uint16_t md5[MD5_DIGEST_LENGTH / (sizeof(uint16_t) / sizeof(u_char))];
		uint32_t crc32;
		uint64_t crc64;
		#if HAVE_LIBBLAKE3
		uint8_t b3[16];
		#endif
		uint8_t mm[16];
		uint16_t first_16_bits;
		uint32_t first_32_bits;
	};
	inline void clear() {
		first_32_bits = 0;
	}
	inline bool is_empty() {
		return(first_32_bits == 0);
	}
} __attribute__((packed));


class cPacketDuplBuffer {
public:
	enum eType {
		_simple,
		_hashtable
	};
private:
	struct sHashItem {
		sHashItem *next;
		u_int32_t time;
		u_char hash[1];
	};
public:
	cPacketDuplBuffer(eType type, eDedupType dedup_type) {
		this->type = type;
		this->dedup_type = dedup_type;
		hash_size = 0;
		hash_size_simple_cmp = 0;
		extern int opt_dup_check_hashtable_lifetime;
		lifetime = opt_dup_check_hashtable_lifetime;
		simple_buffer = NULL;
		hash_table = NULL;
		init();
	}
	~cPacketDuplBuffer() {
		term();
	}
	void init() {
		switch(dedup_type) {
		case _dedup_md5:
			hash_size = MD5_DIGEST_LENGTH;
			break;
		case _dedup_crc32_sw:
		case _dedup_crc32_hw:
			hash_size = sizeof(uint32_t);
			break;
		case _dedup_crc64:
			hash_size = sizeof(uint64_t);
			break;
		#if HAVE_LIBBLAKE3
		case _dedup_blake3:
			hash_size = 16;
			break;
		#endif
		#if MURMUR_HASH
		case _dedup_murmur:
			hash_size = 16;
			break;
		#endif
		default:
			hash_size = 4;
			break;
		}
		hash_size_simple_cmp = hash_size - 2;
		if(type == _simple) {
			simple_buffer = new u_char[65536 * hash_size_simple_cmp];
			memset(simple_buffer, 0, 65536 * hash_size_simple_cmp);
		} else {
			hash_table = new sHashItem*[65536];
			memset(hash_table, 0, sizeof(sHashItem*) * 65536);
		}
	}
	void term() {
		if(simple_buffer) {
			delete []  simple_buffer;
		}
		if(hash_table) {
			for(unsigned i = 0; i < 65536; i++) {
				sHashItem *hi = hash_table[i];
				while(hi) {
					sHashItem *next = hi->next;
					free(hi);
					hi = next;
				}
			}
			delete [] hash_table;
		}
	}
	inline bool check_dupl(sPacketDuplCheck *hash, eDedupType dedup_type) {
		if(this->dedup_type != dedup_type) {
			this->dedup_type = dedup_type;
			term();
			init();
		}
		bool rslt;
		if(type == _simple) {
			rslt = memcmp((u_char*)hash + 2, simple_buffer + (hash->first_16_bits * hash_size_simple_cmp), hash_size_simple_cmp) == 0;
		} else {
			rslt = check_dupl_hashtable(hash);
		}
		if(!rslt) {
			store(hash);
		}
		return(rslt);
	}
	inline bool check_dupl_hashtable(sPacketDuplCheck *hash) {
		/*
		static unsigned maxc;
		*/
		sHashItem *hi = hash_table[hash->first_16_bits];
		if(hi) {
			u_int32_t limit_time = getTimeS_rdtsc() - lifetime;
			sHashItem *prev = NULL;
			/*
			unsigned c = 0;
			*/
			do {
				/*
				++c;
				if(c > maxc) {
					maxc = c;
					std::cout << " *** " << maxc << std::endl;
				}
				*/
				if(hi->time < limit_time) {
					sHashItem *next = hi->next;
					if(prev) {
						prev->next = next;
					} else {
						hash_table[hash->first_16_bits] = next;
					}
					free(hi);
					hi = next;
					continue;
				} else if(*((u_char*)hash + 2) == hi->hash[0] &&
					  !memcmp((u_char*)hash + 3, hi->hash + 1, hash_size_simple_cmp - 1)) {
					hi->time = getTimeS_rdtsc();
					return(true);
				}
				prev = hi;
				hi = hi->next;
			} while(hi);
		}
		return(false);
	}
	inline void store(sPacketDuplCheck *hash) {
		if(type == _simple) {
			memcpy(simple_buffer + (hash->first_16_bits * hash_size_simple_cmp), (u_char*)hash + 2, hash_size_simple_cmp);
		} else {
			store_hashtable(hash);
		}
	}
	inline void store_hashtable(sPacketDuplCheck *hash) {
		sHashItem *hi = (sHashItem*)malloc(sizeof(sHashItem) + hash_size - 1 - 2);
		hi->next = hash_table[hash->first_16_bits];
		hi->time = getTimeS_rdtsc();
		memcpy(hi->hash, (u_char*)hash + 2, hash_size_simple_cmp);
		hash_table[hash->first_16_bits] = hi;
	}
	void print_hash(sPacketDuplCheck *hash) {
		switch(dedup_type) {
		case _dedup_crc32_sw:
		case _dedup_crc32_hw:
			std::cout << "HASH: " << hash->crc32 << std::endl;
			break;
		case _dedup_crc64:
			std::cout << "HASH: " << hash->crc64 << std::endl;
			break;
		default:
			std::cout << "HASH:" << std::endl;
			void hexdump(u_char *data, unsigned size);
			hexdump((u_char*)hash, hash_size);
			break;
		}
	}
private:
	eType type;
	eDedupType dedup_type;
	u_int8_t hash_size;
	u_int8_t hash_size_simple_cmp;
	u_int16_t lifetime;
	u_char *simple_buffer;
	sHashItem **hash_table;
};


struct sPacketDuplCheckProc {
	inline sPacketDuplCheckProc(sPacketDuplCheck *dc, eDedupType dedup_type) {
		this->dc = dc;
		this->dedup_type = dedup_type;
		dc->clear();
		switch(dedup_type) {
		case _dedup_md5:
			MD5_Init(&ctx);
			break;
		case _dedup_crc64:
			crc64_prepare(dc->crc64);
			break;
		#if HAVE_LIBBLAKE3
		case _dedup_blake3:
			blake3_hasher_init(&b3h);
			break;
		#endif
		default:
			break;
		}
	}
	inline void data_md5(u_char *data, unsigned len) {
		MD5_Update(&ctx, data, len);
	}
	inline void data_crc32(u_char *data, unsigned len) {
		dc->crc32 = 
			#if defined(__x86_64__) or defined(__i386__)
			dedup_type == _dedup_crc32_hw ? crc32_sse(dc->crc32, (const char*)data, len) :
			#endif
			crc32(dc->crc32, data, len);
	}
	inline void data_crc64(u_char *data, unsigned len) {
		dc->crc64 = crc64_update(dc->crc64, data, len);
	}
	#if HAVE_LIBBLAKE3
	inline void data_blake3(u_char *data, unsigned len) {
		blake3_hasher_update(&b3h, data, len);
	}
	#endif
	#if MURMUR_HASH
	inline void data_murmur(u_char *data, unsigned len) {
		u_int32_t seed = len >= 8 ? *(u_int32_t*)(data + len/2) :
				 len >= 4 ? *(u_int32_t*)(data + len - 4) : 64;
		MurmurHash3_x64_128(data, len, seed, dc->mm);
	}
	#endif
	inline void data(void *data, unsigned len) {
		switch(dedup_type) {
		case _dedup_md5:
			data_md5((u_char*)data, len);
			break;
		case _dedup_crc32_sw:
		case _dedup_crc32_hw:
			data_crc32((u_char*)data, len);
			break;
		case _dedup_crc64:
			data_crc64((u_char*)data, len);
			break;
		#if HAVE_LIBBLAKE3
		case _dedup_blake3:
			data_blake3((u_char*)data, len);
			break;
		#endif
		#if MURMUR_HASH
		case _dedup_murmur:
			data_murmur((u_char*)data, len);
			break;
		#endif
		default:
			break;
		}
	}
	inline void final() {
		switch(dedup_type) {
		case _dedup_md5:
			MD5_Final((unsigned char*)dc->md5, &ctx);
			break;
		case _dedup_crc64:
			crc64_final(dc->crc64);
			break;
		#if HAVE_LIBBLAKE3
		case _dedup_blake3:
			blake3_hasher_finalize(&b3h, dc->b3, 16);
			break;
		#endif
		default:
			break;
		}
	}
	sPacketDuplCheck *dc;
	eDedupType dedup_type;
	MD5_CTX ctx;
	#if HAVE_LIBBLAKE3
	blake3_hasher b3h;
	#endif
};


#endif
