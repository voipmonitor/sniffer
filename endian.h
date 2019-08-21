#ifndef ENDIAN_H
#define ENDIAN_H

/* For compatibility with Linux definitions... */
#include "tools_define.h"

#ifdef FREEBSD
# include <sys/endian.h>
# define __BYTE_ORDER _BYTE_ORDER
# define __BIG_ENDIAN _BIG_ENDIAN
# define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
# include <endian.h>
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
# ifndef __BIG_ENDIAN_BITFIELD
#  define __BIG_ENDIAN_BITFIELD
# endif
#else
# ifndef __LITTLE_ENDIAN_BITFIELD
#  define __LITTLE_ENDIAN_BITFIELD
# endif
#endif
#if defined(__BIG_ENDIAN_BITFIELD) && defined(__LITTLE_ENDIAN_BITFIELD)
# error Cannot define both __BIG_ENDIAN_BITFIELD and __LITTLE_ENDIAN_BITFIELD
#endif

#endif //ENDIAN_H
