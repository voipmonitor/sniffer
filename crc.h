#ifndef CRC_H
#define CRC_H


#include <inttypes.h>
#include <sys/types.h>


u_int32_t crc32buf(char *buf, size_t len);
u_int32_t crc32buf(u_char *buf, size_t len) {
	return(crc32buf((char*)buf, len));
}

#if defined(__x86_64__) or defined(__i386__)

#include <nmmintrin.h>

#define CRC_SSE_ALIGN_SIZE 0x08UL           // Align at an 8-byte boundary
#define CRC_SSE_ALIGN_MASK (CRC_SSE_ALIGN_SIZE - 1) // Bitmask for 8-byte bound addresses

#define CRC_SSE_CALC(op, crc, type, buf, len)                                      \
  do {                                                                         \
    for (; (len) >= sizeof(type);                                              \
         (len) -= sizeof(type), buf += sizeof(type)) {                         \
      (crc) = op((crc), *(type *)(buf));                                       \
    }                                                                          \
  } while (0)


inline bool crc32_sse_is_available() {
	uint32_t reg[4];
	#if defined(__x86_64__)
	__asm__ volatile("pushq %%rbx       \n\t"
			 "cpuid             \n\t"
			 "movl  %%ebx, %1   \n\t"
			 "popq  %%rbx       \n\t"
			 : "=a"(reg[0]), "=r"(reg[1]), "=c"(reg[2]), "=d"(reg[3])
			 : "a"(1)
			 : "cc");
	return(((reg[2] >> 20) & 1) == 1);
	#elif defined(__i386__)
	__asm__ volatile("pushl %%ebx       \n\t"
			 "cpuid             \n\t"
			 "movl  %%ebx, %1   \n\t"
			 "popl  %%ebx       \n\t"
			 : "=a"(reg[0]), "=r"(reg[1]), "=c"(reg[2]), "=d"(reg[3])
			 : "a"(1)
			 : "cc");
	return(((reg[2] >> 20) & 1) == 1);
	#endif
	return(0);
}

__attribute__((target("sse4.2")))
inline uint32_t crc32_sse(uint32_t crc, const char *buf, size_t len) {
	// If the string is empty, return the initial crc
	if (len == 0)
		return crc;

	// XOR the initial CRC with INT_MAX
	crc ^= 0xFFFFFFFF;

	// Align the input to the word boundary
	for (; (len > 0) && ((size_t)buf & CRC_SSE_ALIGN_MASK); len--, buf++) {
		crc = _mm_crc32_u8(crc, *buf);
	}

	// Blast off the CRC32 calculation on hardware
	#if defined(__x86_64__)
	CRC_SSE_CALC(_mm_crc32_u64, crc, uint64_t, buf, len);
	#endif
	CRC_SSE_CALC(_mm_crc32_u32, crc, uint32_t, buf, len);
	CRC_SSE_CALC(_mm_crc32_u16, crc, uint16_t, buf, len);
	CRC_SSE_CALC(_mm_crc32_u8, crc, uint8_t, buf, len);

	// XOR again with INT_MAX
	return (crc ^= 0xFFFFFFFF);
}

#endif

#endif
