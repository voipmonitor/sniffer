#ifndef FORMAT_WAV_H
#define FORMAT_WAV_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>


#define WAV_BUF_SIZE		320
#define BLOCKSIZE 160

#define GAIN 0					/* 2^GAIN is the multiple to increase the volume by.	The original value of GAIN was 2, or 4x (12 dB),
												 * but there were many reports of the clipping of loud signal peaks (issue 5823 for example). */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htoll(b) (b)
#define htols(b) (b)
#define ltohl(b) (b)
#define ltohs(b) (b)
#else
#if __BYTE_ORDER == __BIG_ENDIAN
#define htoll(b)	\
					(((((b)			) & 0xFF) << 24) | \
							 ((((b) >>	8) & 0xFF) << 16) | \
									 ((((b) >> 16) & 0xFF) <<	8) | \
									 ((((b) >> 24) & 0xFF)			))
#define htols(b) \
					(((((b)			) & 0xFF) << 8) | \
									 ((((b) >> 8) & 0xFF)			))
#define ltohl(b) htoll(b)
#define ltohs(b) htols(b)
#else
#error "Endianess not defined"
#endif
#endif

void slinear_saturated_add(short *input, short *value);
int wav_write_header(FILE *f, int samplerate, int stereo);
int wav_update_header(FILE *f);
int wav_mix(char *in1, char *in2, char *out, int samplerate, int swap, int stereo);


#endif //FORMAT_WAV_H
