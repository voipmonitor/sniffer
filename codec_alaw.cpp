#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec_alaw.h"

short __alaw[256];

static inline short int alaw2linear (unsigned char alaw)
{
    int i;
    int seg;

    alaw ^= AMI_MASK;
    i = ((alaw & 0x0F) << 4) + 8 /* rounding error */;
    seg = (((int) alaw & 0x70) >> 4);
    if (seg)
        i = (i + 0x100) << (seg - 1);
    return (short int) ((alaw & 0x80)  ?  i  :  -i);
}

void alaw_init(void)
{
        int i;
        /*
         *  Set up a-law conversion table
         */
        for(i = 0;i < 256;i++) {
		__alaw[i] = alaw2linear(i);
	}
}
