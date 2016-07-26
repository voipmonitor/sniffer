#ifndef CRC_H
#define CRC_H


#include <sys/types.h>


u_int32_t crc32buf(char *buf, size_t len);
u_int32_t crc32buf(u_char *buf, size_t len) {
	return(crc32buf((char*)buf, len));
}


#endif
