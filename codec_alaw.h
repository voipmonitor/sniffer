#ifndef CODEC_ALAW_H
#define CODEC_ALAW_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern short __alaw[256];

#define ALAW(a) (__alaw[(int)(a)])
#define AMI_MASK 0x55

//static inline short int alaw2linear (unsigned char alaw);
void alaw_init(void);


#endif //CODEC_ALAW_H
