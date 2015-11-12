#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec_ulaw.h"

short __ulaw[256];

void ulaw_init(void)
{
        int i;
        for (i = 0; i < 256; i++) {
                short mu, e, f, y;
                static short etab[] = {0,132,396,924,1980,4092,8316,16764};

                mu = 255 - i;
                e = (mu & 0x70) / 16;
                f = mu & 0x0f;
                y = f * (1 << (e + 3));
                y += etab[e];
                if (mu & 0x80)
                        y = -y;
                __ulaw[i] = y;
        }
}

