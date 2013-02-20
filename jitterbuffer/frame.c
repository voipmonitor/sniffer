/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Frame and codec manipulation routines
 *
 * \author Mark Spencer <markster@digium.com> 
 */

#include "asterisk.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "asterisk/lock.h"
#include "asterisk/frame.h"
#include "asterisk/logger.h"
#include "asterisk/options.h"
#include "asterisk/channel.h"
#include "asterisk/cli.h"
#include "asterisk/term.h"
#include "asterisk/utils.h"
#include "asterisk/threadstorage.h"
#include "asterisk/linkedlists.h"
#include "asterisk/translate.h"
#include "asterisk/dsp.h"
#include "asterisk/file.h"
#include "asterisk/time.h"

#if !defined(LOW_MEMORY)
static void frame_cache_cleanup(void *data);

/*! \brief A per-thread cache of frame headers */
AST_THREADSTORAGE_CUSTOM(frame_cache, frame_cache_init, frame_cache_cleanup);

/*! 
 * \brief Maximum ast_frame cache size
 *
 * In most cases where the frame header cache will be useful, the size
 * of the cache will stay very small.  However, it is not always the case that
 * the same thread that allocates the frame will be the one freeing them, so
 * sometimes a thread will never have any frames in its cache, or the cache
 * will never be pulled from.  For the latter case, we limit the maximum size. 
 */ 
#define FRAME_CACHE_MAX_SIZE	10

/*! \brief This is just so ast_frames, a list head struct for holding a list of
 *  ast_frame structures, is defined. */
AST_LIST_HEAD_NOLOCK(ast_frames, ast_frame);

struct ast_frame_cache {
	struct ast_frames list;
	size_t size;
};
#endif

#define SMOOTHER_SIZE 8000

enum frame_type {
	TYPE_HIGH,     /* 0x0 */
	TYPE_LOW,      /* 0x1 */
	TYPE_SILENCE,  /* 0x2 */
	TYPE_DONTSEND  /* 0x3 */
};

#define TYPE_MASK 0x3

struct ast_smoother {
	int size;
	int format;
	int flags;
	float samplesperbyte;
	unsigned int opt_needs_swap:1;
	struct ast_frame f;
	struct timeval delivery;
	char data[SMOOTHER_SIZE];
	char framedata[SMOOTHER_SIZE + AST_FRIENDLY_OFFSET];
	struct ast_frame *opt;
	int len;
};

/*! \brief Definition of supported media formats (codecs) */
static struct ast_format_list AST_FORMAT_LIST[] = {					/*!< Bit number: comment  - Bit numbers are hard coded in show_codec() */
	{ 1, AST_FORMAT_G723_1 , "g723" , "G.723.1", 24, 30, 300, 30, 30 },	/*!<  1 */
	{ 1, AST_FORMAT_GSM, "gsm" , "GSM", 33, 20, 300, 20, 20 },		/*!<  2: codec_gsm.c */
	{ 1, AST_FORMAT_ULAW, "ulaw", "G.711 u-law", 80, 10, 150, 10, 20 },	/*!<  3: codec_ulaw.c */
	{ 1, AST_FORMAT_ALAW, "alaw", "G.711 A-law", 80, 10, 150, 10, 20 },	/*!<  4: codec_alaw.c */
	{ 1, AST_FORMAT_G726, "g726", "G.726 RFC3551", 40, 10, 300, 10, 20 },	/*!<  5: codec_g726.c */
	{ 1, AST_FORMAT_ADPCM, "adpcm" , "ADPCM", 40, 10, 300, 10, 20 },	/*!<  6: codec_adpcm.c */
	{ 1, AST_FORMAT_SLINEAR, "slin", "16 bit Signed Linear PCM", 160, 10, 70, 10, 20, AST_SMOOTHER_FLAG_BE },	/*!< 7 */
	{ 1, AST_FORMAT_LPC10, "lpc10", "LPC10", 7, 20, 20, 20, 20 },		/*!<  8: codec_lpc10.c */ 
	{ 1, AST_FORMAT_G729A, "g729", "G.729A", 10, 10, 230, 10, 20, AST_SMOOTHER_FLAG_G729 },	/*!<  9: Binary commercial distribution */
	{ 1, AST_FORMAT_SPEEX, "speex", "SpeeX", 10, 10, 60, 10, 20 },		/*!< 10: codec_speex.c */
	{ 1, AST_FORMAT_ILBC, "ilbc", "iLBC", 50, 30, 30, 30, 30 },		/*!< 11: codec_ilbc.c */ /* inc=30ms - workaround */
	{ 1, AST_FORMAT_G726_AAL2, "g726aal2", "G.726 AAL2", 40, 10, 300, 10, 20 },	/*!<  12: codec_g726.c */
	{ 1, AST_FORMAT_G722, "g722", "G722"},					/*!< 13 */
	{ 0, 0, "nothing", "undefined" },
	{ 0, 0, "nothing", "undefined" },
	{ 0, 0, "nothing", "undefined" },
	{ 0, 0, "nothing", "undefined" },
	{ 0, AST_FORMAT_MAX_AUDIO, "maxaudio", "Maximum audio format" },	
	{ 1, AST_FORMAT_JPEG, "jpeg", "JPEG image"},	/*!< 17: See format_jpeg.c */
	{ 1, AST_FORMAT_PNG, "png", "PNG image"},	/*!< 18: Image format */
	{ 1, AST_FORMAT_H261, "h261", "H.261 Video" },	/*!< 19: Video Passthrough */
	{ 1, AST_FORMAT_H263, "h263", "H.263 Video" },	/*!< 20: Passthrough support, see format_h263.c */
	{ 1, AST_FORMAT_H263_PLUS, "h263p", "H.263+ Video" },	/*!< 21: See format_h263.c */
	{ 1, AST_FORMAT_H264, "h264", "H.264 Video" },	/*!< 22: Passthrough support, see format_h263.c */
	{ 0, 0, "nothing", "undefined" },
	{ 0, 0, "nothing", "undefined" },
	{ 0, 0, "nothing", "undefined" },
	{ 0, AST_FORMAT_MAX_VIDEO, "maxvideo", "Maximum video format" },
};

struct ast_frame ast_null_frame = { AST_FRAME_NULL, };

static int smoother_frame_feed(struct ast_smoother *s, struct ast_frame *f, int swap)
{
	if (s->flags & AST_SMOOTHER_FLAG_G729) {
		if (s->len % 10) {
			printf("Dropping extra frame of G.729 since we already have a VAD frame at the end\n");
			return 0;
		}
	}
	if (swap) {
		ast_swapcopy_samples(s->data + s->len, f->data, f->samples);
	} else {
		memcpy(s->data + s->len, f->data, f->datalen);
	}
	/* If either side is empty, reset the delivery time */
	if (!s->len || ast_tvzero(f->delivery) || ast_tvzero(s->delivery)) {	/* XXX really ? */
		s->delivery = f->delivery;
	}
	s->len += f->datalen;

	return 0;
}

void ast_smoother_reset(struct ast_smoother *s, int bytes)
{
	memset(s, 0, sizeof(*s));
	s->size = bytes;
}

void ast_smoother_reconfigure(struct ast_smoother *s, int bytes)
{
	/* if there is no change, then nothing to do */
	if (s->size == bytes) {
		return;
	}
	/* set the new desired output size */
	s->size = bytes;
	/* if there is no 'optimized' frame in the smoother,
	 *   then there is nothing left to do
	 */
	if (!s->opt) {
		return;
	}
	/* there is an 'optimized' frame here at the old size,
	 * but it must now be put into the buffer so the data
	 * can be extracted at the new size
	 */
	smoother_frame_feed(s, s->opt, s->opt_needs_swap);
	s->opt = NULL;
}

struct ast_smoother *ast_smoother_new(int size)
{
	struct ast_smoother *s;
	if (size < 1)
		return NULL;
	if ((s = malloc(sizeof(*s))))
		ast_smoother_reset(s, size);
	return s;
}

int ast_smoother_get_flags(struct ast_smoother *s)
{
	return s->flags;
}

void ast_smoother_set_flags(struct ast_smoother *s, int flags)
{
	s->flags = flags;
}

int ast_smoother_test_flag(struct ast_smoother *s, int flag)
{
	return (s->flags & flag);
}

int __ast_smoother_feed(struct ast_smoother *s, struct ast_frame *f, int swap)
{
	if (f->frametype != AST_FRAME_VOICE) {
		printf("Huh?  Can't smooth a non-voice frame!\n");
		return -1;
	}
	if (!s->format) {
		s->format = f->subclass;
		s->samplesperbyte = (float)f->samples / (float)f->datalen;
	} else if (s->format != f->subclass) {
		printf("Smoother was working on %d format frames, now trying to feed %d?\n", s->format, f->subclass);
		return -1;
	}
	if (s->len + f->datalen > SMOOTHER_SIZE) {
		printf("Out of smoother space\n");
		return -1;
	}
	if (((f->datalen == s->size) ||
	     ((f->datalen < 10) && (s->flags & AST_SMOOTHER_FLAG_G729))) &&
	    !s->opt &&
	    !s->len &&
	    (f->offset >= AST_MIN_OFFSET)) {
		/* Optimize by sending the frame we just got
		   on the next read, thus eliminating the douple
		   copy */
		if (swap)
			ast_swapcopy_samples(f->data, f->data, f->samples);
		s->opt = f;
		s->opt_needs_swap = swap ? 1 : 0;
		return 0;
	}

	return smoother_frame_feed(s, f, swap);
}

struct ast_frame *ast_smoother_read(struct ast_smoother *s)
{
	struct ast_frame *opt;
	int len;

	/* IF we have an optimization frame, send it */
	if (s->opt) {
		if (s->opt->offset < AST_FRIENDLY_OFFSET)
			printf("Returning a frame of inappropriate offset (%d).\n",
							s->opt->offset);
		opt = s->opt;
		s->opt = NULL;
		return opt;
	}

	/* Make sure we have enough data */
	if (s->len < s->size) {
		/* Or, if this is a G.729 frame with VAD on it, send it immediately anyway */
		if (!((s->flags & AST_SMOOTHER_FLAG_G729) && (s->len % 10)))
			return NULL;
	}
	len = s->size;
	if (len > s->len)
		len = s->len;
	/* Make frame */
	s->f.frametype = AST_FRAME_VOICE;
	s->f.subclass = s->format;
	s->f.data = s->framedata + AST_FRIENDLY_OFFSET;
	s->f.offset = AST_FRIENDLY_OFFSET;
	s->f.datalen = len;
	/* Samples will be improper given VAD, but with VAD the concept really doesn't even exist */
	s->f.samples = len * s->samplesperbyte;	/* XXX rounding */
	s->f.delivery = s->delivery;
	/* Fill Data */
	memcpy(s->f.data, s->data, len);
	s->len -= len;
	/* Move remaining data to the front if applicable */
	if (s->len) {
		/* In principle this should all be fine because if we are sending
		   G.729 VAD, the next timestamp will take over anyawy */
		memmove(s->data, s->data + len, s->len);
		if (!ast_tvzero(s->delivery)) {
			/* If we have delivery time, increment it, otherwise, leave it at 0 */
			s->delivery = ast_tvadd(s->delivery, ast_samp2tv(s->f.samples, 8000));
		}
	}
	/* Return frame */
	return &s->f;
}

void ast_smoother_free(struct ast_smoother *s)
{
	free(s);
}

/*
static struct ast_frame *ast_frame_header_new(void)
{
	struct ast_frame *f;

	if (!(f = calloc(1, sizeof(*f))))
		return NULL;

	f->mallocd_hdr_len = sizeof(*f);
	
	return f;
}
*/

#if !defined(LOW_MEMORY)
static void frame_cache_cleanup(void *data)
{
	struct ast_frame_cache *frames = data;
	struct ast_frame *f;

	while ((f = AST_LIST_REMOVE_HEAD(&frames->list, frame_list)))
		free(f);
	
	free(frames);
}
#endif

static void __frame_free(struct ast_frame *fr, int cache)
{
	if (!fr->mallocd)
		return;

	
	if (fr->mallocd & AST_MALLOCD_DATA) {
		if (fr->data) 
			free(fr->data - fr->offset);
	}
	if (fr->mallocd & AST_MALLOCD_SRC) {
		if (fr->src)
			free((void *) fr->src);
	}
	if (fr->mallocd & AST_MALLOCD_HDR) {
		free(fr);
	}
}


void ast_frame_free(struct ast_frame *frame, int cache)
{
	struct ast_frame *next;

	for (next = AST_LIST_NEXT(frame, frame_list);
	     frame;
	     frame = next, next = frame ? AST_LIST_NEXT(frame, frame_list) : NULL) {
		__frame_free(frame, cache);
	}
}


struct ast_frame *ast_frdup(const struct ast_frame *f)
{
	struct ast_frame *out = NULL;
	int len, srclen = 0;
	void *buf = NULL;

	/* Start with standard stuff */
	len = sizeof(*out) + AST_FRIENDLY_OFFSET + f->datalen;
	/* If we have a source, add space for it */
	/*
	 * XXX Watch out here - if we receive a src which is not terminated
	 * properly, we can be easily attacked. Should limit the size we deal with.
	 */
	if (f->src)
		srclen = strlen(f->src);
	if (srclen > 0)
		len += srclen + 1;

	if (!buf) {
		if (!(buf = calloc(1, len)))
			return NULL;
		out = buf;
		out->mallocd_hdr_len = len;
	}

	out->frametype = f->frametype;
	out->subclass = f->subclass;
	out->datalen = f->datalen;
	out->samples = f->samples;
	out->delivery = f->delivery;
	out->skip = f->skip;
	/* Set us as having malloc'd header only, so it will eventually
	   get freed. */
	out->mallocd = AST_MALLOCD_HDR;
	out->offset = AST_FRIENDLY_OFFSET;
	if (out->datalen > 0) {
		out->data = buf + sizeof(*out) + AST_FRIENDLY_OFFSET;
		memcpy(out->data, f->data, out->datalen);	
	}
	if (srclen > 0) {
		/* This may seem a little strange, but it's to avoid a gcc (4.2.4) compiler warning */
		char *src;
		out->src = buf + sizeof(*out) + AST_FRIENDLY_OFFSET + f->datalen;
		src = (char *) out->src;
		/* Must have space since we allocated for it */
		strcpy(src, f->src);
	}
	ast_copy_flags(out, f, AST_FRFLAG_HAS_TIMING_INFO);
	out->ts = f->ts;
	out->len = f->len;
	out->seqno = f->seqno;
	out->marker = f->marker;
	return out;
}

void ast_swapcopy_samples(void *dst, const void *src, int samples)
{
	int i;
	unsigned short *dst_s = dst;
	const unsigned short *src_s = src;

	for (i = 0; i < samples; i++)
		dst_s[i] = (src_s[i]<<8) | (src_s[i]>>8);
}


struct ast_format_list *ast_get_format_list_index(int index) 
{
	return &AST_FORMAT_LIST[index];
}

struct ast_format_list *ast_get_format_list(size_t *size) 
{
	*size = (sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]));
	return AST_FORMAT_LIST;
}

char* ast_getformatname(int format)
{
	int x;
	char *ret = "unknown";
	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(AST_FORMAT_LIST[x].visible && AST_FORMAT_LIST[x].bits == format) {
			ret = AST_FORMAT_LIST[x].name;
			break;
		}
	}
	return ret;
}

char *ast_getformatname_multiple(char *buf, size_t size, int format)
{
	int x;
	unsigned len;
	char *start, *end = buf;

	if (!size)
		return buf;
	snprintf(end, size, "0x%x (", format);
	len = strlen(end);
	end += len;
	size -= len;
	start = end;
	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if (AST_FORMAT_LIST[x].visible && (AST_FORMAT_LIST[x].bits & format)) {
			snprintf(end, size,"%s|",AST_FORMAT_LIST[x].name);
			len = strlen(end);
			end += len;
			size -= len;
		}
	}
	if (start == end)
		snprintf(start, size, "nothing)");
	else if (size > 1)
		*(end -1) = ')';
	return buf;
}

static struct ast_codec_alias_table {
	char *alias;
	char *realname;
} ast_codec_alias_table[] = {
	{ "slinear", "slin"},
	{ "g723.1", "g723"},
};

static const char *ast_expand_codec_alias(const char *in)
{
	int x;

	for (x = 0; x < sizeof(ast_codec_alias_table) / sizeof(ast_codec_alias_table[0]); x++) {
		if(!strcmp(in,ast_codec_alias_table[x].alias))
			return ast_codec_alias_table[x].realname;
	}
	return in;
}

int ast_getformatbyname(const char *name)
{
	int x, all, format = 0;

	all = strcasecmp(name, "all") ? 0 : 1;
	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(AST_FORMAT_LIST[x].visible && (all || 
			  !strcasecmp(AST_FORMAT_LIST[x].name,name) ||
			  !strcasecmp(AST_FORMAT_LIST[x].name,ast_expand_codec_alias(name)))) {
			format |= AST_FORMAT_LIST[x].bits;
			if(!all)
				break;
		}
	}

	return format;
}

char *ast_codec2str(int codec)
{
	int x;
	char *ret = "unknown";
	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(AST_FORMAT_LIST[x].visible && AST_FORMAT_LIST[x].bits == codec) {
			ret = AST_FORMAT_LIST[x].desc;
			break;
		}
	}
	return ret;
}




void ast_codec_pref_convert(struct ast_codec_pref *pref, char *buf, size_t size, int right) 
{
	int x, differential = (int) 'A', mem;
	char *from, *to;

	if(right) {
		from = pref->order;
		to = buf;
		mem = size;
	} else {
		to = pref->order;
		from = buf;
		mem = 32;
	}

	memset(to, 0, mem);
	for (x = 0; x < 32 ; x++) {
		if(!from[x])
			break;
		to[x] = right ? (from[x] + differential) : (from[x] - differential);
	}
}

int ast_codec_pref_string(struct ast_codec_pref *pref, char *buf, size_t size) 
{
	int x, codec; 
	size_t total_len, slen;
	char *formatname;
	
	memset(buf,0,size);
	total_len = size;
	buf[0] = '(';
	total_len--;
	for(x = 0; x < 32 ; x++) {
		if(total_len <= 0)
			break;
		if(!(codec = ast_codec_pref_index(pref,x)))
			break;
		if((formatname = ast_getformatname(codec))) {
			slen = strlen(formatname);
			if(slen > total_len)
				break;
			strncat(buf, formatname, total_len - 1); /* safe */
			total_len -= slen;
		}
		if(total_len && x < 31 && ast_codec_pref_index(pref , x + 1)) {
			strncat(buf, "|", total_len - 1); /* safe */
			total_len--;
		}
	}
	if(total_len) {
		strncat(buf, ")", total_len - 1); /* safe */
		total_len--;
	}

	return size - total_len;
}

int ast_codec_pref_index(struct ast_codec_pref *pref, int index) 
{
	int slot = 0;

	
	if((index >= 0) && (index < sizeof(pref->order))) {
		slot = pref->order[index];
	}

	return slot ? AST_FORMAT_LIST[slot-1].bits : 0;
}

/*! \brief Remove codec from pref list */
void ast_codec_pref_remove(struct ast_codec_pref *pref, int format)
{
	struct ast_codec_pref oldorder;
	int x, y = 0;
	int slot;
	int size;

	if(!pref->order[0])
		return;

	memcpy(&oldorder, pref, sizeof(oldorder));
	memset(pref, 0, sizeof(*pref));

	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		slot = oldorder.order[x];
		size = oldorder.framing[x];
		if(! slot)
			break;
		if(AST_FORMAT_LIST[slot-1].bits != format) {
			pref->order[y] = slot;
			pref->framing[y++] = size;
		}
	}
	
}

/*! \brief Append codec to list */
int ast_codec_pref_append(struct ast_codec_pref *pref, int format)
{
	int x, newindex = 0;

	ast_codec_pref_remove(pref, format);

	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(AST_FORMAT_LIST[x].bits == format) {
			newindex = x + 1;
			break;
		}
	}

	if(newindex) {
		for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
			if(!pref->order[x]) {
				pref->order[x] = newindex;
				break;
			}
		}
	}

	return x;
}

/*! \brief Prepend codec to list */
void ast_codec_pref_prepend(struct ast_codec_pref *pref, int format, int only_if_existing)
{
	int x, newindex = 0;

	/* First step is to get the codecs "index number" */
	for (x = 0; x < ARRAY_LEN(AST_FORMAT_LIST); x++) {
		if (AST_FORMAT_LIST[x].bits == format) {
			newindex = x + 1;
			break;
		}
	}
	/* Done if its unknown */
	if (!newindex)
		return;

	/* Now find any existing occurrence, or the end */
	for (x = 0; x < 32; x++) {
		if (!pref->order[x] || pref->order[x] == newindex)
			break;
	}

	if (only_if_existing && !pref->order[x])
		return;

	/* Move down to make space to insert - either all the way to the end,
	   or as far as the existing location (which will be overwritten) */
	for (; x > 0; x--) {
		pref->order[x] = pref->order[x - 1];
		pref->framing[x] = pref->framing[x - 1];
	}

	/* And insert the new entry */
	pref->order[0] = newindex;
	pref->framing[0] = 0; /* ? */
}

/*! \brief Set packet size for codec */
int ast_codec_pref_setsize(struct ast_codec_pref *pref, int format, int framems)
{
	int x, index = -1;

	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(AST_FORMAT_LIST[x].bits == format) {
			index = x;
			break;
		}
	}

	if(index < 0)
		return -1;

	/* size validation */
	if(!framems)
		framems = AST_FORMAT_LIST[index].def_ms;

	if(AST_FORMAT_LIST[index].inc_ms && framems % AST_FORMAT_LIST[index].inc_ms) /* avoid division by zero */
		framems -= framems % AST_FORMAT_LIST[index].inc_ms;

	if(framems < AST_FORMAT_LIST[index].min_ms)
		framems = AST_FORMAT_LIST[index].min_ms;

	if(framems > AST_FORMAT_LIST[index].max_ms)
		framems = AST_FORMAT_LIST[index].max_ms;


	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(pref->order[x] == (index + 1)) {
			pref->framing[x] = framems;
			break;
		}
	}

	return x;
}

/*! \brief Get packet size for codec */
struct ast_format_list ast_codec_pref_getsize(struct ast_codec_pref *pref, int format)
{
	int x, index = -1, framems = 0;
	struct ast_format_list fmt = {0};

	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(AST_FORMAT_LIST[x].bits == format) {
			fmt = AST_FORMAT_LIST[x];
			index = x;
			break;
		}
	}

	for (x = 0; x < sizeof(AST_FORMAT_LIST) / sizeof(AST_FORMAT_LIST[0]); x++) {
		if(pref->order[x] == (index + 1)) {
			framems = pref->framing[x];
			break;
		}
	}

	/* size validation */
	if(!framems)
		framems = AST_FORMAT_LIST[index].def_ms;

	if(AST_FORMAT_LIST[index].inc_ms && framems % AST_FORMAT_LIST[index].inc_ms) /* avoid division by zero */
		framems -= framems % AST_FORMAT_LIST[index].inc_ms;

	if(framems < AST_FORMAT_LIST[index].min_ms)
		framems = AST_FORMAT_LIST[index].min_ms;

	if(framems > AST_FORMAT_LIST[index].max_ms)
		framems = AST_FORMAT_LIST[index].max_ms;

	fmt.cur_ms = framems;

	return fmt;
}

#if 0
static unsigned char get_n_bits_at(unsigned char *data, int n, int bit)
{
	int byte = bit / 8;       /* byte containing first bit */
	int rem = 8 - (bit % 8);  /* remaining bits in first byte */
	unsigned char ret = 0;
	
	if (n <= 0 || n > 8)
		return 0;

	if (rem < n) {
		ret = (data[byte] << (n - rem));
		ret |= (data[byte + 1] >> (8 - n + rem));
	} else {
		ret = (data[byte] >> (rem - n));
	}

	return (ret & (0xff >> (8 - n)));
}
#endif

int ast_frame_adjust_volume(struct ast_frame *f, int adjustment)
{
	int count;
	short *fdata = f->data;
	short adjust_value = abs(adjustment);

	if ((f->frametype != AST_FRAME_VOICE) || (f->subclass != AST_FORMAT_SLINEAR))
		return -1;

	if (!adjustment)
		return 0;

	for (count = 0; count < f->samples; count++) {
		if (adjustment > 0) {
			ast_slinear_saturated_multiply(&fdata[count], &adjust_value);
		} else if (adjustment < 0) {
			ast_slinear_saturated_divide(&fdata[count], &adjust_value);
		}
	}

	return 0;
}

int ast_frame_slinear_sum(struct ast_frame *f1, struct ast_frame *f2)
{
	int count;
	short *data1, *data2;

	if ((f1->frametype != AST_FRAME_VOICE) || (f1->subclass != AST_FORMAT_SLINEAR))
		return -1;

	if ((f2->frametype != AST_FRAME_VOICE) || (f2->subclass != AST_FORMAT_SLINEAR))
		return -1;

	if (f1->samples != f2->samples)
		return -1;

	for (count = 0, data1 = f1->data, data2 = f2->data;
	     count < f1->samples;
	     count++, data1++, data2++)
		ast_slinear_saturated_add(data1, data2);

	return 0;
}
