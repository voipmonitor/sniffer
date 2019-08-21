#ifndef BSWAP_H
#define BSWAP_H


#include "endian.h"


#define BSWAP16(n) ((n) << 8 | ((n) >> 8 & 0x00FF))

#define BSWAP32(n) ((n) >> 24) | (((n) << 8) & 0x00FF0000L) | (((n) >> 8) & 0x0000FF00L) | ((n) << 24)

#define BSWAP64(n) ((n) >> 56) | (((n) << 40) & 0x00FF000000000000LL) | \
                                 (((n) << 24) & 0x0000FF0000000000LL) | \
                                 (((n) << 8)  & 0x000000FF00000000LL) | \
                                 (((n) >> 8)  & 0x00000000FF000000LL) | \
                                 (((n) >> 24) & 0x0000000000FF0000LL) | \
                                 (((n) >> 40) & 0x000000000000FF00LL) | \
                                 ((n) << 56)

#define _BSWAP(n) n = bswap(n);


inline u_int16_t bswap(u_int16_t n) {
	return(BSWAP16(n));
}

inline u_int32_t bswap(u_int32_t n) {
	return(BSWAP32(n));
}

inline u_int64_t bswap(u_int64_t n) {
	return(BSWAP64(n));
}
                                 
                                 
#endif //BSWAP_H                                 
