#ifndef CODEC_ULAW_H
#define CODEC_ULAW_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern short __ulaw[256];

#define ULAW(a) (__ulaw[(a)])

//static inline short int alaw2linear (unsigned char alaw);
void ulaw_init(void);


#endif //CODEC_ULAW_H
