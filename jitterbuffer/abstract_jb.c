/*
 * abstract_jb: common implementation-independent jitterbuffer stuff
 *
 * Copyright (C) 2005, Attractel OOD
 *
 * Contributors:
 * Slav Klenov <slav@securax.org>
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
 *
 * A license has been granted to Digium (via disclaimer) for the use of
 * this code.
 */

/*! \file
 *
 * \brief Common implementation-independent jitterbuffer stuff.
 *
 * \author Slav Klenov <slav@securax.org>
 */

#include "asterisk.h"


#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "asterisk/frame.h"
#include "asterisk/channel.h"
#include "asterisk/logger.h"
#include "asterisk/term.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/time.h"

#include "asterisk/abstract_jb.h"
#include "fixedjitterbuf.h"
#include "jitterbuf.h"
#include "../codecs.h"
#include "../common.h"

#define JB_LONGMAX 2147483647L

#define ONLY_RAW 0


extern struct sVerbose sverb;

/*! \brief On and Off plc*/
extern int opt_disableplc;
extern int opt_fix_packetization_in_create_audio;
extern int opt_ignore_mos_degradation_for_contiguous_packet_loss_greater_than;

/*! Internal jb flags */
enum {
	JB_USE =                  (1 << 0),
	JB_TIMEBASE_INITIALIZED = (1 << 1),
	JB_CREATED =              (1 << 2)
};

/* Hooks for the abstract jb implementation */

typedef void * (*jb_create_impl)(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *channel);
typedef void (*jb_destroy_impl)(void *jb);
typedef int (*jb_put_first_impl)(void *jb, struct ast_frame *fin, long now);
typedef int (*jb_put_impl)(void *jb, struct ast_frame *fin, long now);
typedef int (*jb_get_impl)(void *jb, struct ast_frame **fout, long now, long interpl);
typedef long (*jb_next_impl)(void *jb);
typedef int (*jb_remove_impl)(void *jb, struct ast_frame **fout);
typedef void (*jb_force_resynch_impl)(void *jb);
typedef void (*jb_empty_and_reset_impl)(void *jb);

struct ast_jb_impl
{
	char name[AST_JB_IMPL_NAME_SIZE];
	jb_create_impl create;
	jb_destroy_impl destroy;
	jb_put_first_impl put_first;
	jb_put_impl put;
	jb_get_impl get;
	jb_next_impl next;
	jb_remove_impl remove;
	jb_force_resynch_impl force_resync;
	jb_empty_and_reset_impl empty_and_reset;
};

extern void fifobuff_add(void *fifo_buff, const char *data, unsigned int datalen);
extern void save_rtp_energylevels(void *rtp_stream, void *data, int datalen, int codec);

/* Implementation functions */
/* fixed */
static void * jb_create_fixed(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *chan);
static void jb_destroy_fixed(void *jb);
static int jb_put_first_fixed(void *jb, struct ast_frame *fin, long now);
static int jb_put_fixed(void *jb, struct ast_frame *fin, long now);
static int jb_get_fixed(void *jb, struct ast_frame **fout, long now, long interpl);
static long jb_next_fixed(void *jb);
static int jb_remove_fixed(void *jb, struct ast_frame **fout);
static void jb_force_resynch_fixed(void *jb);
static void jb_empty_and_reset_fixed(void *jb);
/* adaptive */
static void * jb_create_adaptive(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *chan);
static void jb_destroy_adaptive(void *jb);
static int jb_put_first_adaptive(void *jb, struct ast_frame *fin, long now);
static int jb_put_adaptive(void *jb, struct ast_frame *fin, long now);
static int jb_get_adaptive(void *jb, struct ast_frame **fout, long now, long interpl);
static long jb_next_adaptive(void *jb);
static int jb_remove_adaptive(void *jb, struct ast_frame **fout);
static void jb_force_resynch_adaptive(void *jb);
static void jb_empty_and_reset_adaptive(void *jb);

/* Available jb implementations */
static struct ast_jb_impl avail_impl[] =
{
	{
		.name = "fixed",
		.create = jb_create_fixed,
		.destroy = jb_destroy_fixed,
		.put_first = jb_put_first_fixed,
		.put = jb_put_fixed,
		.get = jb_get_fixed,
		.next = jb_next_fixed,
		.remove = jb_remove_fixed,
		.force_resync = jb_force_resynch_fixed,
		.empty_and_reset = jb_empty_and_reset_fixed,
	},
	{
		.name = "adaptive",
		.create = jb_create_adaptive,
		.destroy = jb_destroy_adaptive,
		.put_first = jb_put_first_adaptive,
		.put = jb_put_adaptive,
		.get = jb_get_adaptive,
		.next = jb_next_adaptive,
		.remove = jb_remove_adaptive,
		.force_resync = jb_force_resynch_adaptive,
		.empty_and_reset = jb_empty_and_reset_adaptive,
	}
};

/*! Abstract return codes */
enum {
	JB_IMPL_OK,
	JB_IMPL_DROP,
	JB_IMPL_INTERP,
	JB_IMPL_NOFRAME,
	JB_IMPL_ERROR
};

/* Translations between impl and abstract return codes */
static const int fixed_to_abstract_code[] =
	{JB_IMPL_OK, JB_IMPL_DROP, JB_IMPL_INTERP, JB_IMPL_NOFRAME, JB_IMPL_ERROR};
static const int adaptive_to_abstract_code[] =
	{JB_IMPL_OK, JB_IMPL_NOFRAME, JB_IMPL_NOFRAME, JB_IMPL_INTERP, JB_IMPL_DROP, JB_IMPL_OK};

/* JB_GET actions (used only for the frames log) */
static const char *jb_get_actions[] = {"Delivered", "Dropped", "Interpolated", "No"};

/* Fast inline timeval diff helper (exact match to ast_tvdiff_ms) */
static inline long tvdiff_ms_fast(const struct timeval *end, const struct timeval *start)
{
	return ((end->tv_sec - start->tv_sec) * 1000L) +
	       (((1000000L + end->tv_usec - start->tv_usec) / 1000L) - 1000L);
}

static inline __attribute__((always_inline)) void jb_force_resync_impl(struct ast_jb *jb, int is_fixed)
{
	if (is_fixed) {
		fixed_jb_set_force_resynch((struct fixed_jb *)jb->jbobj);
	} else {
		jb_empty_and_reset_adaptive(jb->jbobj);
	}
}

/* Unified zero-alloc metadata slot put (compile-time specialized on is_fixed / is_first) */
static inline __attribute__((always_inline)) int jb_put_meta_slot_inl(
	struct ast_channel *chan, long ts, long len, int seqno,
	char marker, uint8_t flags, long now, int is_fixed, int is_first)
{
	struct ast_jb *jb = &chan->jb;
	int rslt;

	if (is_fixed) {
		struct fixed_jb *fjb = (struct fixed_jb *)jb->jbobj;
		struct fixed_jb_slot in;
		in.ts = ts;
		in.delivery = 0;
		in.orig_ts = ts;
		in.ms = (int32_t)len;
		in.seqno = (uint16_t)seqno;
		in.flags = flags;
		in.pad = 0;
		rslt = fixed_to_abstract_code[
			is_first ? fixed_jb_put_first_slot(fjb, &in, now, marker)
				 : fixed_jb_put_slot_inl(fjb, &in, now, marker, chan->audio_decode)
		];
		if (!is_first) {
			if (__builtin_expect(chan->prev_frame_is_dtmf != 0, 0))
				chan->prev_frame_is_dtmf = 0;
		}
		if (is_first || __builtin_expect(rslt == JB_IMPL_OK, 1)) {
			jb->next = fixed_jb_next_inl(fjb);
		}
	} else {
		jitterbuf *ajb = (jitterbuf *)jb->jbobj;
		jb_slot in;
		in.ts = ts;
		in.orig_ts = ts;
		in.ms = (int32_t)len;
		in.seqno = (uint16_t)seqno;
		in.type = JB_TYPE_VOICE;
		in.flags = flags;
		rslt = adaptive_to_abstract_code[jb_put_slot_inl(ajb, &in, now)];
		if (!is_first) {
			if (__builtin_expect(chan->prev_frame_is_dtmf != 0, 0))
				chan->prev_frame_is_dtmf = 0;
		}
		if (is_first || __builtin_expect(rslt == JB_IMPL_OK, 1)) {
			jb->next = jb_next_inl(ajb);
		}
	}

	return rslt;
}

static inline int chan_needs_audio_frame(const struct ast_channel *chan, const struct ast_frame *f)
{
	return (chan->rawstream != NULL || chan->audiobuf != NULL || chan->enable_save_energylevels || f->datalen > 0);
}

static inline uint8_t frame_to_slot_flags(const struct ast_frame *f)
{
	uint8_t fl = 0;
	if (f->marker) fl |= JB_SLOT_FLAG_MARKER;
	if (f->lastframetype == AST_FRAME_VOICE) fl |= JB_SLOT_FLAG_LAST_VOICE;
	if (f->skip) fl |= JB_SLOT_FLAG_SKIP;
	if (f->ignore) fl |= JB_SLOT_FLAG_IGNORE;
	return fl;
}

static inline void record_loss_and_update_chan(struct ast_channel *chan, int seqno, long orig_ts, int marker, int last_is_voice)
{
	if (__builtin_expect(chan->last_loss_burst > 0, 0)) {
		if (!((((unsigned int)seqno - chan->last_seqno) == 1) && (abs((int)(orig_ts - chan->last_ms)) > chan->packetization))
		    && !marker
		    && chan->last_loss_burst < opt_ignore_mos_degradation_for_contiguous_packet_loss_greater_than
		    && last_is_voice) {
			while (chan->last_loss_burst > 128) {
				chan->loss[127]++;
				if (sverb.jitter) fprintf(stdout, "\tSAVING chan->loss[128] packetization[%d]\n", chan->packetization);
				chan->last_loss_burst -= 128;
			}
			chan->loss[chan->last_loss_burst]++;
			if (sverb.jitter) fprintf(stdout, "\tSAVING chan->loss[%d] = %d packetization[%d]\n", chan->last_loss_burst, chan->loss[chan->last_loss_burst], chan->packetization);
		}
		chan->last_loss_burst = 0;
	}
	chan->last_seqno = (unsigned int)seqno;
	chan->last_ms = (unsigned int)orig_ts;
}

/* Internal utility functions */
static void jb_choose_impl(struct ast_channel *chan);
static void jb_get_and_deliver(struct ast_channel *chan, const struct timeval *mynow);
static int create_jb(struct ast_channel *chan, struct ast_frame *first_frame, const struct timeval *mynow);

static void jb_choose_impl(struct ast_channel *chan)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_conf *jbconf = &jb->conf;
	struct ast_jb_impl *test_impl;
	int i, avail_impl_count = (int)(sizeof(avail_impl) / sizeof(avail_impl[0]));

	jb->impl = &avail_impl[chan->jitter_impl];

	if (ast_strlen_zero(jbconf->impl))
		return;

	for (i = 0; i < avail_impl_count; i++) {
		test_impl = &avail_impl[i];
		if (!strcasecmp(jbconf->impl, test_impl->name)) {
			jb->impl = test_impl;
			return;
		}
	}
}

int ast_jb_test(struct ast_channel *c0)
{
	struct ast_jb *jb0 = &c0->jb;
	return ast_test_flag(jb0, JB_CREATED);
}

int ast_jb_do_usecheck(struct ast_channel *c0, struct timeval *ts)
{
	struct ast_jb *jb0 = &c0->jb;

	ast_set_flag(jb0, JB_USE);
	if (__builtin_expect(!ast_test_flag(jb0, JB_TIMEBASE_INITIALIZED), 0)) {
		jb0->timebase = *ts;
		ast_set_flag(jb0, JB_TIMEBASE_INITIALIZED);
	}

	if (__builtin_expect(!ast_test_flag(jb0, JB_CREATED), 0)) {
		jb_choose_impl(c0);
	}

	return 1;
}

static int create_jb_meta(struct ast_channel *chan, long ts, long len, int seqno, char marker, uint8_t flags, int subclass, const struct timeval *mynow)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj;
	long now;
	int res;

	jbobj = jb->jbobj = jbimpl->create(&jb->conf, jb->conf.resync_threshold, chan);
	if (!jbobj) {
		if (sverb.jitter) fprintf(stdout, "Failed to create jitterbuffer on channel\n");
		return -1;
	}

	now = tvdiff_ms_fast(mynow, &jb->timebase);
	res = jb_put_meta_slot_inl(chan, ts, len, seqno, marker, flags, now, jbimpl == &avail_impl[0], 1);

	if (res != JB_IMPL_OK) {
		if (sverb.jitter) fprintf(stdout, "Failed to put first frame in the jitterbuffer on channel\n");
	}

	jb->last_format = subclass;

	if (sverb.jitter) {
		if (ast_test_flag(&jb->conf, AST_JB_LOG)) {
			if (res == JB_IMPL_OK) {
				fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Queued frame with ts=%ld and len=%ld\n", now, ts, len);
			} else {
				fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Dropped frame with ts=%ld and len=%ld seq=%d\n", now, ts, len, seqno);
			}
		}
		fprintf(stdout, "%s jitterbuffer[%p] created on channel\n", jbimpl->name, jb);
	}

	return 0;
}

int ast_jb_put(struct ast_channel *chan, struct ast_frame *f, struct timeval *mynow)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj = jb->jbobj;
	long now = 0;
	int rslt;

	if (__builtin_expect(f->frametype != AST_FRAME_VOICE, 0)) {
		if (f->frametype == AST_FRAME_DTMF && ast_test_flag(jb, JB_CREATED)) {
			if (sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Received DTMF frame.\n", jb, now);
			chan->prev_frame_is_dtmf = 1;
		}
		return -1;
	}

	if (__builtin_expect(chan->resync && f->marker, 0)) {
		if (sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: marker bit set, Force resynching jb...\n", jb, now);
		if (ast_test_flag(jb, JB_CREATED)) {
			jb_force_resync_impl(jb, jbimpl == &avail_impl[0]);
		}
	}

	if (__builtin_expect(f->len < 2 || f->ts < 0, 0)) {
		if (sverb.jitter) fprintf(stdout, "recieved frame with invalid timing info: "
			"has_timing_info=%d, len=%ld, ts=%ld, src=%s\n",
			ast_test_flag(f, AST_FRFLAG_HAS_TIMING_INFO), f->len, f->ts, f->src);
		return -1;
	}

	/* Zero-allocation fast path when channel has no audio payload / recording sink */
	if (__builtin_expect(!chan_needs_audio_frame(chan, f), 1)) {
		uint8_t flags = frame_to_slot_flags(f);

		if (__builtin_expect(!ast_test_flag(jb, JB_CREATED), 0)) {
			if (create_jb_meta(chan, f->ts, f->len, f->seqno, f->marker, flags, f->subclass, mynow)) {
				ast_clear_flag(jb, JB_USE);
				return -1;
			}
			ast_set_flag(jb, JB_CREATED);
			return 0;
		}

		now = tvdiff_ms_fast(mynow, &jb->timebase);
		rslt = (jbimpl == &avail_impl[0])
			? jb_put_meta_slot_inl(chan, f->ts, f->len, f->seqno, f->marker, flags, now, 1, 0)
			: jb_put_meta_slot_inl(chan, f->ts, f->len, f->seqno, f->marker, flags, now, 0, 0);
		if (__builtin_expect(rslt != JB_IMPL_OK, 0)) {
			if (sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Dropped frame with ts=%ld and len=%ld and seq=%d\n", jb, now, f->ts, f->len, f->seqno);
			return 0;
		}
		if (sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Queued frame with ts=%ld and len=%ld and seq=%d\n", jb, now, f->ts, f->len, f->seqno);
		return 0;
	}

	/* Audio recording / energylevels path: duplicate frame with payload */
	struct ast_frame *frr = ast_frdup(f);
	if (!frr) {
		if (sverb.jitter) fprintf(stdout, "Failed to isolate frame for the jitterbuffer on channel\n");
		return -1;
	}

	if (!ast_test_flag(jb, JB_CREATED)) {
		if (create_jb(chan, frr, mynow)) {
			ast_frfree(frr);
			ast_clear_flag(jb, JB_USE);
			return -1;
		}
		ast_set_flag(jb, JB_CREATED);
		return 0;
	} else {
		now = tvdiff_ms_fast(mynow, &jb->timebase);
		rslt = jbimpl->put(jbobj, frr, now);
		if (frr->frametype != AST_FRAME_DTMF) {
			chan->prev_frame_is_dtmf = 0;
		}
		if (rslt != JB_IMPL_OK) {
			if (sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Dropped frame with ts=%ld and len=%ld and seq=%d\n", jb, now, frr->ts, frr->len, frr->seqno);
			ast_frfree(frr);
			return 0;
		}

		jb->next = jbimpl->next(jbobj);
		if (sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Queued frame with ts=%ld and len=%ld and seq=%d\n", jb, now, frr->ts, frr->len, frr->seqno);
		return 0;
	}
}


void ast_jb_get_and_deliver(struct ast_channel *c0, struct timeval *mynow)
{
	struct ast_jb *jb0 = &c0->jb;

	if (__builtin_expect(ast_test_flag(jb0, JB_USE) && ast_test_flag(jb0, JB_CREATED), 1)) {
		if (__builtin_expect(mynow->tv_sec < jb0->timebase.tv_sec ||
				     (mynow->tv_sec == jb0->timebase.tv_sec &&
				      mynow->tv_usec < jb0->timebase.tv_usec), 0)) {
			syslog(LOG_NOTICE, "warning - mynow < c0->jb.timebase in ast_jb_get_and_deliver - ignored");
		} else {
			jb_get_and_deliver(c0, mynow);
		}
	}
}

void jb_fixed_flush_deliver(struct ast_channel *chan)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_frame *f;
	struct fixed_jb_slot slot;
	short int stmp;
	struct fixed_jb *fjb = (struct fixed_jb *)jb->jbobj;

	if (!fjb) {
		return;
	}

	while (fixed_jb_flush_slot(fjb, &slot)) {
		if (!(slot.flags & JB_SLOT_FLAG_IS_AST_FRAME)) {
			continue;
		}
		f = (struct ast_frame *)slot.data;
		if (!f->ignore && (chan->rawstream || chan->audiobuf) && (chan->codec != 13 && chan->codec != 19)) {
			stmp = (short int)f->datalen;
			if (CODEC_LEN && (chan->codec == PAYLOAD_G72218 || chan->codec == PAYLOAD_G722112 || chan->codec == PAYLOAD_G722116 || chan->codec == PAYLOAD_G722124 || chan->codec == PAYLOAD_G722132 || chan->codec == PAYLOAD_G722148 || chan->codec == PAYLOAD_OPUS8 || chan->codec == PAYLOAD_OPUS12 || chan->codec == PAYLOAD_OPUS16 || chan->codec == PAYLOAD_OPUS24 || chan->codec == PAYLOAD_OPUS48 || chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM || chan->codec == PAYLOAD_AMR || chan->codec == PAYLOAD_AMRWB || chan->codec == PAYLOAD_EVS)) {
				if (chan->rawstream) {
					#if ONLY_RAW == 0
					fwrite(&stmp, 1, sizeof(short int), chan->rawstream);
					#endif
				}
			}
			if (chan->rawstream)
				fwrite(f->data, 1, f->datalen, chan->rawstream);
			if (chan->audiobuf)
				fifobuff_add(chan->audiobuf, f->data, f->datalen);
			if (!chan->lastbuf) {
				chan->lastbufsize = f->datalen > 1600 ? f->datalen : 1600;
				chan->lastbuf = (char *)ast_malloc(chan->lastbufsize);
			} else if (chan->lastbufsize < f->datalen) {
				ast_free(chan->lastbuf);
				chan->lastbufsize = f->datalen;
				chan->lastbuf = (char *)ast_malloc(chan->lastbufsize);
			}
			memcpy(chan->lastbuf, f->data, f->datalen);
			chan->lastbuflen = f->datalen;
		}
		if (!f->ignore && chan->enable_save_energylevels && chan->rtp_stream && (chan->codec == 0 || chan->codec == 8)) {
			save_rtp_energylevels(chan->rtp_stream, f->data, f->datalen, chan->codec);
			chan->last_datalen_energylevels = f->datalen;
		}
		ast_frfree(f);
	}
}

void save_empty_frame(struct ast_channel *chan)
{
	if (__builtin_expect(chan->rawstream == NULL && chan->audiobuf == NULL && !chan->enable_save_energylevels, 1)) {
		return;
	}
	if ((chan->rawstream || chan->audiobuf) && (chan->codec != 13 && chan->codec != 19)) {
		int i;
		if (chan->codec == PAYLOAD_G72218 || chan->codec == PAYLOAD_G722112 || chan->codec == PAYLOAD_G722116 || chan->codec == PAYLOAD_G722124 || chan->codec == PAYLOAD_G722132 || chan->codec == PAYLOAD_G722148 ||
		    chan->codec == PAYLOAD_OPUS8 || chan->codec == PAYLOAD_OPUS12 || chan->codec == PAYLOAD_OPUS16 || chan->codec == PAYLOAD_OPUS24 || chan->codec == PAYLOAD_OPUS48 ||
		    chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 ||
		    chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 ||
		    chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM || chan->codec == PAYLOAD_AMR ||
		    chan->codec == PAYLOAD_AMRWB || chan->codec == PAYLOAD_EVS) {
			if (chan->codec == PAYLOAD_G723) {
				#if ONLY_RAW == 0
				short int zero = 0;
				for (i = 1; (i * 30) <= chan->packetization; i++) {
					if (chan->rawstream)
						fwrite(&zero, 1, sizeof(short int), chan->rawstream);
					if (chan->audiobuf)
						fifobuff_add(chan->audiobuf, (const char *)(&zero), sizeof(short int));
				}
				#endif
			} else if (chan->codec == PAYLOAD_G729) {
				short int zero = 0;
				for (i = 1; (i * 10) <= chan->packetization; i++) {
					if (chan->rawstream)
						fwrite(&zero, 1, sizeof(short int), chan->rawstream);
					if (chan->audiobuf)
						fifobuff_add(chan->audiobuf, (const char *)(&zero), sizeof(short int));
				}
			} else {
				short int zero = 0;
				for (i = 1; (i * 20) <= chan->packetization; i++) {
					if (chan->rawstream)
						fwrite(&zero, 1, sizeof(short int), chan->rawstream);
					if (chan->audiobuf)
						fifobuff_add(chan->audiobuf, (const char *)(&zero), sizeof(short int));
				}
			}
		} else {
			unsigned pcm_datalen = 0;
			if (chan->codec == PAYLOAD_PCMA || chan->codec == PAYLOAD_PCMU) {
				pcm_datalen = 8000 * chan->packetization / 1000;
			}
			if (chan->lastbuflen && opt_disableplc == 0 &&
			    (!opt_fix_packetization_in_create_audio ||
			     !(chan->codec == PAYLOAD_PCMA || chan->codec == PAYLOAD_PCMU) ||
			     chan->lastbuflen == pcm_datalen)) {
				if (chan->rawstream)
					fwrite(chan->lastbuf, 1, chan->lastbuflen, chan->rawstream);
				if (chan->audiobuf)
					fifobuff_add(chan->audiobuf, chan->lastbuf, chan->lastbuflen);
				chan->lastbuflen = 0;
			} else {
				if (chan->codec == PAYLOAD_PCMA || chan->codec == PAYLOAD_PCMU) {
					unsigned char zero = chan->codec == PAYLOAD_PCMA ? 213 : 255;
					for (i = 0; i < (int)(opt_fix_packetization_in_create_audio ? pcm_datalen : (unsigned)chan->last_datalen); i++) {
						if (chan->rawstream)
							fwrite(&zero, 1, 1, chan->rawstream);
						if (chan->audiobuf)
							fifobuff_add(chan->audiobuf, (const char *)(&zero), sizeof(char));
					}
				} else {
					unsigned short int zero = chan->codec == PAYLOAD_G722 ? 65535 : 32767;
					short int zero_audiobuff = 0;
					for (i = 0; i < chan->last_datalen / 2; i++) {
						if (chan->rawstream)
							fwrite(&zero, 2, 1, chan->rawstream);
						if (chan->audiobuf)
							fifobuff_add(chan->audiobuf, (const char *)(&zero_audiobuff), sizeof(char));
					}
				}
			}
		}
	}
	if (chan->enable_save_energylevels && chan->rtp_stream && (chan->codec == 0 || chan->codec == 8) &&
	    (chan->last_datalen_energylevels > 0 || chan->last_datalen > 0)) {
		save_rtp_energylevels(chan->rtp_stream, NULL, 0, chan->codec);
	}
}

__attribute__((noinline))
static void deliver_audio_frame(struct ast_channel *chan, struct ast_frame *f, long now, int res)
{
	short int stmp;
	int i;

	if (f->skip) {
		save_empty_frame(chan);
		if (sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: Skip frame\n", &chan->jb, now);
		ast_frfree(f);
		return;
	}
	if (f->ignore) {
		return;
	}
	if ((chan->rawstream || chan->audiobuf) && f->data && f->datalen > 0 && (chan->codec != 13 && chan->codec != 19)) {
		stmp = (short int)f->datalen;
		if (chan->codec == PAYLOAD_G72218 || chan->codec == PAYLOAD_G722112 || chan->codec == PAYLOAD_G722116 || chan->codec == PAYLOAD_G722124 || chan->codec == PAYLOAD_G722132 || chan->codec == PAYLOAD_G722148 || chan->codec == PAYLOAD_OPUS8 || chan->codec == PAYLOAD_OPUS12 || chan->codec == PAYLOAD_OPUS16 || chan->codec == PAYLOAD_OPUS24 || chan->codec == PAYLOAD_OPUS48 || chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM || chan->codec == PAYLOAD_AMR || chan->codec == PAYLOAD_AMRWB || chan->codec == PAYLOAD_EVS) {
			#if ONLY_RAW == 0
			if (chan->rawstream) {
				fwrite(&stmp, 1, sizeof(short int), chan->rawstream);
			}
			#endif
		}
		if (chan->rawstream)
			fwrite(f->data, 1, f->datalen, chan->rawstream);
		if (chan->audiobuf) {
			fifobuff_add(chan->audiobuf, f->data, f->datalen);
		}
		if (opt_fix_packetization_in_create_audio &&
		    (chan->codec == PAYLOAD_PCMA || chan->codec == PAYLOAD_PCMU)) {
			unsigned pcm_datalen = 8000 * chan->packetization / 1000;
			if (pcm_datalen > (unsigned)f->datalen) {
				unsigned char zero = chan->codec == PAYLOAD_PCMA ? 213 : 255;
				for (i = 0; i < (int)(pcm_datalen - f->datalen); i++) {
					if (chan->rawstream)
						fwrite(&zero, 1, 1, chan->rawstream);
					if (chan->audiobuf)
						fifobuff_add(chan->audiobuf, (const char *)(&zero), sizeof(char));
				}
			}
		}
		if (!chan->lastbuf) {
			chan->lastbufsize = f->datalen > 1600 ? f->datalen : 1600;
			chan->lastbuf = (char *)ast_malloc(chan->lastbufsize);
		} else if (chan->lastbufsize < f->datalen) {
			ast_free(chan->lastbuf);
			chan->lastbufsize = f->datalen;
			chan->lastbuf = (char *)ast_malloc(chan->lastbufsize);
		}
		memcpy(chan->lastbuf, f->data, f->datalen);
		chan->lastbuflen = f->datalen;
	}
	if (chan->enable_save_energylevels && chan->rtp_stream && f->data && f->datalen > 0 && (chan->codec == 0 || chan->codec == 8)) {
		save_rtp_energylevels(chan->rtp_stream, f->data, f->datalen, chan->codec);
		chan->last_datalen_energylevels = f->datalen;
	}
	if (sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: %s frame with ts=%ld and len=%ld and seq=%d\n", &chan->jb, now, jb_get_actions[res], f->ts, f->len, f->seqno);
	record_loss_and_update_chan(chan, f->seqno, f->ts, f->marker, f->lastframetype == AST_FRAME_VOICE);
	ast_frfree(f);
}

/* Unified inline get-and-deliver (compile-time specialized on is_fixed / has_audio_sink) */
static inline __attribute__((always_inline)) void jb_get_and_deliver_now(
	struct ast_channel *chan, long now, int has_audio_sink, int is_fixed)
{
	struct ast_jb *jb = &chan->jb;
	long next = is_fixed ? fixed_jb_next_inl((struct fixed_jb *)jb->jbobj)
			     : jb_next_inl((jitterbuf *)jb->jbobj);
	int interpl;

	jb->next = next;

	if (__builtin_expect(next == JB_LONGMAX, 0)) {
		if (has_audio_sink) save_empty_frame(chan);
		chan->last_loss_burst++;
		return;
	} else if (now < next) {
		if (has_audio_sink) save_empty_frame(chan);
		return;
	}

	interpl = chan->packetization;
	while (now >= next) {
		int res;
		long orig_ts = 0;
		void *data = NULL;
		int32_t ms = 0;
		uint16_t seqno = 0;
		uint8_t flags = 0;

		if (is_fixed) {
			struct fixed_jb_slot slot;
			res = fixed_to_abstract_code[fixed_jb_get_slot_inl((struct fixed_jb *)jb->jbobj, &slot, now, interpl)];
			if (res == JB_IMPL_OK || res == JB_IMPL_DROP) {
				orig_ts = slot.orig_ts;
				data = slot.data;
				ms = slot.ms;
				seqno = slot.seqno;
				flags = slot.flags;
			}
		} else {
			jb_slot slot;
			res = adaptive_to_abstract_code[jb_get_slot_inl((jitterbuf *)jb->jbobj, &slot, now, interpl)];
			if (res == JB_IMPL_OK || res == JB_IMPL_DROP) {
				orig_ts = slot.orig_ts;
				data = slot.data;
				ms = slot.ms;
				seqno = slot.seqno;
				flags = slot.flags;
			}
		}

		switch (res) {
		case JB_IMPL_OK:
			if (__builtin_expect(!(flags & JB_SLOT_FLAG_IS_AST_FRAME), 1)) {
				if (__builtin_expect(flags & (JB_SLOT_FLAG_SKIP | JB_SLOT_FLAG_IGNORE), 0)) {
					if ((flags & JB_SLOT_FLAG_SKIP) && has_audio_sink) save_empty_frame(chan);
					break;
				}
				if (__builtin_expect(sverb.jitter, 0))
					fprintf(stdout, "\tJB_GET[%p] {now=%ld}: Delivered frame with ts=%ld and len=%d and seq=%u\n", jb, now, orig_ts, ms, seqno);
				record_loss_and_update_chan(chan, seqno, orig_ts,
							    (flags & JB_SLOT_FLAG_MARKER) != 0,
							    (flags & JB_SLOT_FLAG_LAST_VOICE) != 0);
			} else {
				deliver_audio_frame(chan, (struct ast_frame *)data, now, JB_IMPL_OK);
			}
			break;
		case JB_IMPL_DROP:
			if (has_audio_sink) save_empty_frame(chan);
			if (flags & JB_SLOT_FLAG_IS_AST_FRAME) {
				struct ast_frame *f = (struct ast_frame *)data;
				if (sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: Dropped frame with ts=%ld and len=%ld seq=%d\n", jb, now, f->ts, f->len, f->seqno);
				ast_frfree(f);
			} else if (__builtin_expect(sverb.jitter, 0)) {
				fprintf(stdout, "\tJB_GET[%p] {now=%ld}: Dropped frame with ts=%ld and len=%d seq=%u\n", jb, now, orig_ts, ms, seqno);
			}
			chan->last_loss_burst++;
			break;
		case JB_IMPL_INTERP:
			if (has_audio_sink) save_empty_frame(chan);
			if (__builtin_expect(sverb.jitter, 0))
				fprintf(stdout, "\tJB_GET[%p] {now=%ld}: Interpolated frame with len=%d\n", jb, now, interpl);
			chan->last_loss_burst++;
			break;
		case JB_IMPL_NOFRAME:
			if (has_audio_sink) save_empty_frame(chan);
			chan->last_loss_burst++;
			return;
		case JB_IMPL_ERROR:
			return;
		}
		next = is_fixed ? fixed_jb_next_inl((struct fixed_jb *)jb->jbobj)
				: jb_next_inl((jitterbuf *)jb->jbobj);
		jb->next = next;
	}
}

static void jb_get_and_deliver(struct ast_channel *chan, const struct timeval *mynow)
{
	struct ast_jb *jb = &chan->jb;
	long now = tvdiff_ms_fast(mynow, &jb->timebase);
	int has_audio_sink = (chan->rawstream != NULL || chan->audiobuf != NULL || chan->enable_save_energylevels);

	if (jb->impl == &avail_impl[0]) {
		jb_get_and_deliver_now(chan, now, has_audio_sink, 1);
	} else {
		jb_get_and_deliver_now(chan, now, has_audio_sink, 0);
	}
}

__attribute__((noinline, cold))
static void ast_jb_sim_step_cold(struct ast_channel *chan, const struct timeval *header_ts,
				 long frame_ts, int packetization, int seqno,
				 char marker, int last_is_voice, uint8_t flags)
{
	struct ast_jb *jb = &chan->jb;
	long now;
	int is_fixed;

	ast_set_flag(jb, JB_USE);
	if (!ast_test_flag(jb, JB_TIMEBASE_INITIALIZED)) {
		jb->timebase = *header_ts;
		ast_set_flag(jb, JB_TIMEBASE_INITIALIZED);
		chan->last_ts = *header_ts;
	} else if (jb->timebase.tv_sec == header_ts->tv_sec &&
		   jb->timebase.tv_usec == header_ts->tv_usec) {
		chan->last_ts = *header_ts;
	}

	if (!ast_test_flag(jb, JB_CREATED)) {
		jb_choose_impl(chan);
		if (!chan->jb_reseted) {
			chan->jb_reseted = 1;
			chan->last_ts = *header_ts;
		} else {
			struct timeval next_ts = ast_tv_add_ms_fast(chan->last_ts, packetization);
			int msdiff = (int)tvdiff_ms_fast(header_ts, &next_ts);
			if (msdiff > packetization * 10000) {
				chan->last_ts = *header_ts;
			} else if (msdiff >= packetization) {
				int steps = msdiff / packetization;
				if (marker || !last_is_voice) {
					chan->last_loss_burst = 0;
				}
				chan->last_ts = ast_tv_add_ms_fast(chan->last_ts, steps * packetization);
			}
		}
		if (packetization < 2 || frame_ts < 0)
			return;
		if (create_jb_meta(chan, frame_ts, packetization, seqno, marker, flags, 0, header_ts) == 0) {
			ast_set_flag(jb, JB_CREATED);
		} else {
			ast_clear_flag(jb, JB_USE);
		}
		return;
	}

	/* !chan->jb_reseted while JB_CREATED */
	ast_jb_empty_and_reset(chan);
	chan->jb_reseted = 1;
	chan->last_ts = *header_ts;
	is_fixed = (jb->impl == &avail_impl[0]);
	if (chan->resync && marker) {
		jb_force_resync_impl(jb, is_fixed);
	}
	if (packetization < 2 || frame_ts < 0)
		return;
	now = tvdiff_ms_fast(header_ts, &jb->timebase);
	if (is_fixed) {
		jb_put_meta_slot_inl(chan, frame_ts, packetization, seqno, marker, flags, now, 1, 0);
	} else {
		jb_put_meta_slot_inl(chan, frame_ts, packetization, seqno, marker, flags, now, 0, 0);
	}
}

/* Fused ultra-fast MOS simulation step: steady-state hot path, cold init out-of-line */
static inline void ast_jb_sim_step_inl(struct ast_channel *chan, const struct timeval *header_ts,
				       long frame_ts, int packetization, int seqno,
				       char marker, int last_is_voice, char ignore, int codec)
{
	struct ast_jb *jb = &chan->jb;
	uint8_t flags;
	int is_fixed, msdiff;
	struct timeval next_ts;
	long now;

	chan->codec = codec;
	if (__builtin_expect(chan->rawstream != NULL, 0))
		chan->rawstream = NULL;

	flags = (uint8_t)((marker ? JB_SLOT_FLAG_MARKER : 0) |
			  (last_is_voice ? JB_SLOT_FLAG_LAST_VOICE : 0) |
			  (ignore ? JB_SLOT_FLAG_IGNORE : 0));

	if (__builtin_expect((jb->flags & (JB_USE | JB_TIMEBASE_INITIALIZED | JB_CREATED)) != (JB_USE | JB_TIMEBASE_INITIALIZED | JB_CREATED) ||
			     !chan->jb_reseted, 0)) {
		ast_jb_sim_step_cold(chan, header_ts, frame_ts, packetization, seqno, marker, last_is_voice, flags);
		return;
	}

	if (__builtin_expect(jb->timebase.tv_sec == header_ts->tv_sec &&
			     jb->timebase.tv_usec == header_ts->tv_usec, 0)) {
		chan->last_ts = *header_ts;
	}

	is_fixed = (jb->impl == &avail_impl[0]);
	next_ts = ast_tv_add_ms_fast(chan->last_ts, packetization);
	msdiff = (int)tvdiff_ms_fast(header_ts, &next_ts);

	if (__builtin_expect(msdiff > packetization * 10000, 0)) {
		chan->last_ts = *header_ts;
	} else if (msdiff >= packetization) {
		long now_last = tvdiff_ms_fast(&chan->last_ts, &jb->timebase);
		int clear_burst = (marker || !last_is_voice);
		int bad_time = (chan->last_ts.tv_sec < jb->timebase.tv_sec ||
				(chan->last_ts.tv_sec == jb->timebase.tv_sec &&
				 chan->last_ts.tv_usec < jb->timebase.tv_usec));

		while (msdiff >= packetization) {
			if (__builtin_expect(clear_burst, 0)) {
				chan->last_loss_burst = 0;
			}
			if (__builtin_expect(!bad_time, 1)) {
				if (is_fixed) {
					jb_get_and_deliver_now(chan, now_last, 0, 1);
				} else {
					jb_get_and_deliver_now(chan, now_last, 0, 0);
				}
			} else {
				syslog(LOG_NOTICE, "warning - mynow < c0->jb.timebase in ast_jb_get_and_deliver - ignored");
				chan->last_ts = ast_tv_add_ms_fast(chan->last_ts, packetization);
				bad_time = (chan->last_ts.tv_sec < jb->timebase.tv_sec ||
					    (chan->last_ts.tv_sec == jb->timebase.tv_sec &&
					     chan->last_ts.tv_usec < jb->timebase.tv_usec));
				now_last += packetization;
				msdiff -= packetization;
				continue;
			}
			chan->last_ts = ast_tv_add_ms_fast(chan->last_ts, packetization);
			now_last += packetization;
			msdiff -= packetization;
		}
	}

	if (__builtin_expect(chan->resync && marker, 0)) {
		jb_force_resync_impl(jb, is_fixed);
	}

	if (__builtin_expect(packetization < 2 || frame_ts < 0, 0))
		return;

	now = tvdiff_ms_fast(header_ts, &jb->timebase);
	if (is_fixed) {
		jb_put_meta_slot_inl(chan, frame_ts, packetization, seqno, marker, flags, now, 1, 0);
	} else {
		jb_put_meta_slot_inl(chan, frame_ts, packetization, seqno, marker, flags, now, 0, 0);
	}
}

void ast_jb_sim_step(struct ast_channel *chan, const struct timeval *header_ts,
		     long frame_ts, int packetization, int seqno,
		     char marker, int last_is_voice, char ignore, int codec)
{
	ast_jb_sim_step_inl(chan, header_ts, frame_ts, packetization, seqno, marker, last_is_voice, ignore, codec);
}

void ast_jb_sim_step_3(struct ast_channel *ch_fix1, struct ast_channel *ch_fix2, struct ast_channel *ch_adapt,
		       const struct timeval *header_ts, long frame_ts, int packetization, int seqno,
		       char marker1, char marker2, char marker3, int last_is_voice, char ignore, int codec)
{
	/* Overlap DRAM fetches of ch_fix2/ch_adapt and their jbobj headers with ch_fix1 execution */
	if (ch_fix2) {
		__builtin_prefetch(ch_fix2, 0, 3);
		if (ch_fix2->jb.jbobj) __builtin_prefetch(ch_fix2->jb.jbobj, 0, 3);
	}
	if (ch_adapt) {
		__builtin_prefetch(ch_adapt, 0, 3);
		if (ch_adapt->jb.jbobj) {
			__builtin_prefetch(ch_adapt->jb.jbobj, 0, 3);
			__builtin_prefetch((const char *)ch_adapt->jb.jbobj + 64, 0, 3);
		}
	}

	if (ch_fix1) {
		ast_jb_sim_step_inl(ch_fix1, header_ts, frame_ts, packetization, seqno, marker1, last_is_voice, ignore, codec);
	}
	if (ch_fix2) {
		ast_jb_sim_step_inl(ch_fix2, header_ts, frame_ts, packetization, seqno, marker2, last_is_voice, ignore, codec);
	}
	if (ch_adapt) {
		ast_jb_sim_step_inl(ch_adapt, header_ts, frame_ts, packetization, seqno, marker3, last_is_voice, ignore, codec);
	}
}

static int create_jb(struct ast_channel *chan, struct ast_frame *frr, const struct timeval *mynow)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_conf *jbconf = &jb->conf;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj;
	long now;
	int res;

	jbobj = jb->jbobj = jbimpl->create(jbconf, jbconf->resync_threshold, chan);
	if (!jbobj) {
		if (sverb.jitter) fprintf(stdout, "Failed to create jitterbuffer on channel\n");
		return -1;
	}

	now = tvdiff_ms_fast(mynow, &jb->timebase);
	res = jbimpl->put_first(jbobj, frr, now);

	if (res != JB_IMPL_OK) {
		if (sverb.jitter) fprintf(stdout, "Failed to put first frame in the jitterbuffer on channel\n");
	}

	jb->next = jbimpl->next(jbobj);
	jb->last_format = frr->subclass;

	if (ast_test_flag(jbconf, AST_JB_LOG)) {
		if (res == JB_IMPL_OK) {
			if (sverb.jitter) fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Queued frame with ts=%ld and len=%ld\n",
				now, frr->ts, frr->len);
		} else {
			if (sverb.jitter) fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Dropped frame with ts=%ld and len=%ld seq=%d\n",
				now, frr->ts, frr->len, frr->seqno);
		}
	}

	if (sverb.jitter) fprintf(stdout, "%s jitterbuffer[%p] created on channel\n", jbimpl->name, jb);

	if (res != JB_IMPL_OK)
		ast_frfree(frr);

	return 0;
}


void ast_jb_destroy(struct ast_channel *chan)
{
	if (chan->lastbuf) {
		ast_free(chan->lastbuf);
		chan->lastbuf = NULL;
		chan->lastbufsize = 0;
		chan->lastbuflen = 0;
		chan->last_datalen_energylevels = 0;
	}

	struct ast_jb *jb = &chan->jb;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj = jb->jbobj;

	if (jb->logfile) {
		fclose(jb->logfile);
		jb->logfile = NULL;
	}

	if (ast_test_flag(jb, JB_CREATED)) {
		if (jbimpl == &avail_impl[0]) {
			struct fixed_jb *fjb = (struct fixed_jb *)jbobj;
			struct fixed_jb_slot slot;
			while (fixed_jb_remove_slot(fjb, &slot) == FIXED_JB_OK) {
				if (slot.flags & JB_SLOT_FLAG_IS_AST_FRAME) {
					ast_frfree((struct ast_frame *)slot.data);
				}
			}
			fixed_jb_destroy(fjb);
		} else {
			jitterbuf *ajb = (jitterbuf *)jbobj;
			jb_slot slot;
			while (jb_getall_slot(ajb, &slot) == JB_OK) {
				if (slot.flags & JB_SLOT_FLAG_IS_AST_FRAME) {
					ast_frfree((struct ast_frame *)slot.data);
				}
			}
			jb_destroy(ajb);
		}
		jb->jbobj = NULL;

		ast_clear_flag(jb, JB_CREATED);

		if (sverb.jitter) fprintf(stdout, "%s jitterbuffer destroyed on channel\n", jbimpl->name);
	}
	ast_clear_flag(jb, JB_TIMEBASE_INITIALIZED);
}


int ast_jb_read_conf(struct ast_jb_conf *conf, char *varname, char *value)
{
	int prefixlen = sizeof(AST_JB_CONF_PREFIX) - 1;
	char *name;
	int tmp;

	if (strncasecmp(AST_JB_CONF_PREFIX, varname, prefixlen))
		return -1;

	name = varname + prefixlen;

	if (!strcasecmp(name, AST_JB_CONF_ENABLE)) {
		ast_set2_flag(conf, ast_true(value), AST_JB_ENABLED);
	} else if (!strcasecmp(name, AST_JB_CONF_FORCE)) {
		ast_set2_flag(conf, ast_true(value), AST_JB_FORCED);
	} else if (!strcasecmp(name, AST_JB_CONF_MAX_SIZE)) {
		if ((tmp = atoi(value)) > 0)
			conf->max_size = tmp;
	} else if (!strcasecmp(name, AST_JB_CONF_RESYNCH_THRESHOLD)) {
		if ((tmp = atoi(value)) > 0)
			conf->resync_threshold = tmp;
	} else if (!strcasecmp(name, AST_JB_CONF_IMPL)) {
		if (!ast_strlen_zero(value))
			snprintf(conf->impl, sizeof(conf->impl), "%s", value);
	} else if (!strcasecmp(name, AST_JB_CONF_LOG)) {
		ast_set2_flag(conf, ast_true(value), AST_JB_LOG);
	} else {
		return -1;
	}

	return 0;
}


void ast_jb_configure(struct ast_channel *chan, const struct ast_jb_conf *conf)
{
	memcpy(&chan->jb.conf, conf, sizeof(*conf));
}


void ast_jb_get_config(const struct ast_channel *chan, struct ast_jb_conf *conf)
{
	memcpy(conf, &chan->jb.conf, sizeof(*conf));
}

void ast_jb_empty_and_reset(struct ast_channel *c0)
{
	struct ast_jb *jb0 = &c0->jb;

	if (ast_test_flag(jb0, JB_USE) && ast_test_flag(jb0, JB_CREATED) && jb0->impl->empty_and_reset) {
		jb0->impl->empty_and_reset(jb0->jbobj);
	}
}

/* Implementation functions */

/* fixed */
static void * jb_create_fixed(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *chan)
{
	struct fixed_jb_conf conf;
	conf.jbsize = chan->jitter_max;
	conf.resync_threshold = chan->jitter_resync_threshold;
	return fixed_jb_new(&conf, chan);
}

static void jb_destroy_fixed(void *jb)
{
	fixed_jb_destroy((struct fixed_jb *)jb);
}

static int jb_put_first_fixed(void *jb, struct ast_frame *fin, long now)
{
	int res = fixed_jb_put_first((struct fixed_jb *)jb, fin, fin->len, fin->ts, now, fin->marker);
	return fixed_to_abstract_code[res];
}

static int jb_put_fixed(void *jb, struct ast_frame *fin, long now)
{
	int res = fixed_jb_put((struct fixed_jb *)jb, fin, fin->len, fin->ts, now, fin->marker);
	return fixed_to_abstract_code[res];
}

static int jb_get_fixed(void *jb, struct ast_frame **fout, long now, long interpl)
{
	struct fixed_jb_frame frame;
	int res = fixed_jb_get((struct fixed_jb *)jb, &frame, now, interpl);
	*fout = (struct ast_frame *)frame.data;
	return fixed_to_abstract_code[res];
}

static long jb_next_fixed(void *jb)
{
	return fixed_jb_next((struct fixed_jb *)jb);
}

static int jb_remove_fixed(void *jb, struct ast_frame **fout)
{
	struct fixed_jb_frame frame;
	int res = fixed_jb_remove((struct fixed_jb *)jb, &frame);
	*fout = (struct ast_frame *)frame.data;
	return fixed_to_abstract_code[res];
}

static void jb_force_resynch_fixed(void *jb)
{
	fixed_jb_set_force_resynch((struct fixed_jb *)jb);
}

static void jb_empty_and_reset_fixed(void *jb)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *)jb;
	struct fixed_jb_slot slot;

	while (fixed_jb_remove_slot(fixedjb, &slot) == FIXED_JB_OK) {
		if (slot.flags & JB_SLOT_FLAG_IS_AST_FRAME) {
			ast_frfree((struct ast_frame *)slot.data);
		}
	}
}

/* adaptive */

static void *jb_create_adaptive(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *chan)
{
	jb_conf jbconf;
	jitterbuf *adaptivejb;

	adaptivejb = jb_new();
	if (adaptivejb) {
		jbconf.max_jitterbuf = chan->jitter_max;
		jbconf.resync_threshold = chan->jitter_resync_threshold;
		jbconf.max_contig_interp = 10;
		jb_setconf(adaptivejb, &jbconf);
	}

	return adaptivejb;
}

static void jb_destroy_adaptive(void *jb)
{
	jb_destroy((jitterbuf *)jb);
}

static int jb_put_first_adaptive(void *jb, struct ast_frame *fin, long now)
{
	return jb_put_adaptive(jb, fin, now);
}

static int jb_put_adaptive(void *jb, struct ast_frame *fin, long now)
{
	int res = jb_put((jitterbuf *)jb, fin, JB_TYPE_VOICE, fin->len, fin->ts, now);
	return adaptive_to_abstract_code[res];
}

static int jb_get_adaptive(void *jb, struct ast_frame **fout, long now, long interpl)
{
	jb_frame frame;
	int res = jb_get((jitterbuf *)jb, &frame, now, interpl);
	*fout = (struct ast_frame *)frame.data;
	return adaptive_to_abstract_code[res];
}

static long jb_next_adaptive(void *jb)
{
	return jb_next((jitterbuf *)jb);
}

static int jb_remove_adaptive(void *jb, struct ast_frame **fout)
{
	jb_frame frame;
	int res = jb_getall((jitterbuf *)jb, &frame);
	*fout = (struct ast_frame *)frame.data;
	return adaptive_to_abstract_code[res];
}

static void jb_force_resynch_adaptive(void *jb)
{
	jb_empty_and_reset_adaptive(jb);
}

static void jb_empty_and_reset_adaptive(void *jb)
{
	jitterbuf *adaptivejb = (jitterbuf *)jb;
	jb_slot slot;

	while (jb_getall_slot(adaptivejb, &slot) == JB_OK) {
		if (slot.flags & JB_SLOT_FLAG_IS_AST_FRAME) {
			ast_frfree((struct ast_frame *)slot.data);
		}
	}

	jb_reset(adaptivejb);
}
