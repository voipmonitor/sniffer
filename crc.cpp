#include <sys/types.h>

#include "crc.h"


#define CRC_64_POLY 0x42F0E1EBA9EA3693ULL // Polynom ECMA-182

u_int64_t crc_64_tab_ecma182[256];

void crc64_init() {
	for(int i = 0; i < 256; i++) {
		u_int64_t crc = i;
		crc <<= 56;
		for(int j = 0; j < 8; j++) {
			if(crc & 0x8000000000000000ULL) {
				crc = (crc << 1) ^ CRC_64_POLY;
			} else {
				crc <<= 1;
			}
		}
		crc_64_tab_ecma182[i] = crc;
	}
}
