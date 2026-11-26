/*
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
 * \brief Jitterbuffering algorithm.
 *
 * \author Slav Klenov <slav@securax.org>
 */

#include "asterisk.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include "asterisk/utils.h"
#include "asterisk/channel.h"
#include "fixedjitterbuf.h"
#include "../common.h"

#undef FIXED_JB_DEBUG

#ifdef FIXED_JB_DEBUG
#define ASSERT(a)
#else
#define ASSERT(a) assert(a)
#endif

extern struct sVerbose sverb;

static int debug = 0;

#define RESYNCH_V1 1

//#define JB_PUT_LOG 1
#if JB_PUT_LOG
static unsigned jb_put_log_counter;
#endif

static inline void slot_to_frame(const struct fixed_jb_slot *slot, struct fixed_jb_frame *frame)
{
	frame->data = (slot->flags & JB_SLOT_FLAG_IS_AST_FRAME) ? slot->data : NULL;
	frame->ts = slot->ts;
	frame->ms = slot->ms;
	frame->delivery = slot->delivery;
	frame->next = NULL;
	frame->prev = NULL;
}

static inline void pop_jb_head_slot(struct fixed_jb *jb, struct fixed_jb_slot *slot_out)
{
	struct fixed_jb_slot *fr = &jb->slots[jb->head];
	jb->next_delivery = fr->delivery + fr->ms;
	*slot_out = *fr;
	jb->head = (jb->head + 1) & jb->mask;
	jb->count--;
}

__attribute__((noinline, cold))
int fixed_jb_grow_slots(struct fixed_jb *jb)
{
	int new_cap = jb->cap * 2;
	struct fixed_jb_slot *new_slots = (struct fixed_jb_slot *)ast_malloc((size_t)new_cap * sizeof(struct fixed_jb_slot));
	if (!new_slots)
		return -1;

	int first_part = jb->cap - jb->head;
	if (first_part > jb->count)
		first_part = jb->count;
	memcpy(new_slots, jb->slots + jb->head, (size_t)first_part * sizeof(struct fixed_jb_slot));
	if (jb->count > first_part) {
		memcpy(new_slots + first_part, jb->slots, (size_t)(jb->count - first_part) * sizeof(struct fixed_jb_slot));
	}

	if (jb->slots != jb->inline_slots) {
		ast_free(jb->slots);
	}
	jb->slots = new_slots;
	jb->head = 0;
	jb->cap = new_cap;
	jb->mask = new_cap - 1;
	return 0;
}

__attribute__((noinline, cold))
void fixed_jb_put_invalid_slow(const struct fixed_jb_slot *in)
{
	extern int opt_enable_jitterbuffer_asserts;
	if ((in->flags & JB_SLOT_FLAG_IS_AST_FRAME) && !(in->data != NULL)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_put - data != NULL");
		if (opt_enable_jitterbuffer_asserts) {
			ASSERT(in->data != NULL);
		}
		return;
	}
	if (!(in->ms >= 2)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_put - ms >= 2");
		if (opt_enable_jitterbuffer_asserts) {
			ASSERT(in->ms >= 2);
		}
		return;
	}
	if (!(in->ts >= 0)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_put - ts >= 0");
		if (opt_enable_jitterbuffer_asserts) {
			ASSERT(in->ts >= 0);
		}
		return;
	}
}

__attribute__((noinline, cold))
void fixed_jb_get_invalid_slow(long now, long interpl)
{
	extern int opt_enable_jitterbuffer_asserts;
	if (!(now >= 0)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_get - now >= 0");
		if (opt_enable_jitterbuffer_asserts) {
			ASSERT(now >= 0);
		}
		return;
	}
	if (!(interpl >= 2)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_get - interpl >= 2");
		if (opt_enable_jitterbuffer_asserts) {
			ASSERT(interpl >= 2);
		}
		return;
	}
}

struct fixed_jb *fixed_jb_new(struct fixed_jb_conf *conf, struct ast_channel *chan)
{
	struct fixed_jb *jb;
	long jbsize = conf->jbsize < 1 ? FIXED_JB_SIZE_DEFAULT : conf->jbsize;
	long resync_threshold = conf->resync_threshold < 1 ? FIXED_JB_RESYNCH_THRESHOLD_DEFAULT : conf->resync_threshold;
	int init_cap;

	if (jbsize <= 80)
		init_cap = 8;
	else if (jbsize <= 240)
		init_cap = 16;
	else
		init_cap = 32;

	if (!(jb = (struct fixed_jb *)ast_malloc(sizeof(*jb) + (size_t)init_cap * sizeof(struct fixed_jb_slot))))
		return NULL;

	jb->slots = jb->inline_slots;
	jb->head = 0;
	jb->count = 0;
	jb->cap = init_cap;
	jb->mask = init_cap - 1;
	jb->rxcore = 0;
	jb->delay = jbsize;
	jb->next_delivery = 0;
	jb->conf.jbsize = jbsize;
	jb->conf.resync_threshold = resync_threshold;
	jb->force_resynch = 0;
	jb->chan = chan;
	jb->skew_sum = 0;
	jb->skew_counter = 0;

	return jb;
}

void fixed_jb_destroy(struct fixed_jb *jb)
{
	/* jitterbuf MUST be empty before it can be destroyed */
	if (!(jb->count == 0)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_destroy - jb->frames == NULL");
		extern int opt_enable_jitterbuffer_asserts;
		if (opt_enable_jitterbuffer_asserts) {
			ASSERT(jb->count == 0);
		}
		return;
	}

	if (jb->slots != jb->inline_slots) {
		ast_free(jb->slots);
	}
	ast_free(jb);
}

static int resynch_jb_slot(struct fixed_jb *jb, const struct fixed_jb_slot *in, long now, const char *debug_str)
{
	long diff, offset;

	if (sverb.jitter) fprintf(stdout, "RESYNC_JB (%s)\n", debug_str);

	/* If jb is empty, just reinitialize the jb */
	if (jb->count == 0) {
		if (debug) fprintf(stdout, "resynch_jb: empty jb\n");
		jb->force_resynch = 0;
		return fixed_jb_put_first_slot(jb, in, now, 0);
	}

	struct fixed_jb_slot *tail = &jb->slots[(jb->head + jb->count - 1) & jb->mask];

	/* Get the diff in timestamps */
	diff = in->ts - tail->ts;

	/* Ideally this should be just the length of the last frame. The deviation is the desired offset */
	offset = diff - tail->ms;

#if RESYNCH_V1
	if (offset < jb->conf.resync_threshold && offset > -jb->conf.resync_threshold) {
		if (!jb->force_resynch) {
			if (!jb->chan->audio_decode && jb->skew_counter > 10 && llabs(jb->skew_sum / jb->skew_counter) > jb->delay / 2) {
				jb->skew_sum = 0;
				jb->skew_counter = 0;
				jb_fixed_flush_deliver(jb->chan);
				return fixed_jb_put_first_slot(jb, in, now, 0);
			} else if (offset < 0 ||
				   now - in->ts < jb->rxcore - jb->delay) {
				return FIXED_JB_DROP;
			} else {
				jb_fixed_flush_deliver(jb->chan);
				return fixed_jb_put_first_slot(jb, in, now, 0);
			}
		} else {
			jb->force_resynch = 0;
			if (offset < 0) {
				return FIXED_JB_DROP;
			} else {
				jb_fixed_flush_deliver(jb->chan);
				return fixed_jb_put_first_slot(jb, in, now, 0);
			}
		}
	}
#endif

	/* Reset the force resynch flag */
	jb->force_resynch = 0;

	if (debug) fprintf(stdout, "fixedjb: resync_jb\n");

	/* apply the offset to the jb state */
	jb->rxcore -= offset;
	for (int i = 0; i < jb->count; i++) {
		jb->slots[(jb->head + i) & jb->mask].ts += offset;
	}

	/* now jb_put() should add the frame at a last position */
	return fixed_jb_put_slot_inl(jb, in, now, 0, jb->chan->audio_decode);
}

void fixed_jb_set_force_resynch(struct fixed_jb *jb)
{
	jb->force_resynch = 1;
}

int fixed_jb_put_first_slot(struct fixed_jb *jb, const struct fixed_jb_slot *in, long now, char marker)
{
	/* this is our first frame - set the base of the receivers time */
	jb->rxcore = now - in->ts;

	/* init next for a first time - it should be the time the first frame should be played */
	jb->next_delivery = now + jb->delay;

	/* put the frame */
	return fixed_jb_put_slot_inl(jb, in, now, marker, jb->chan->audio_decode);
}

__attribute__((noinline, cold))
int fixed_jb_put_slot_slow(struct fixed_jb *jb, const struct fixed_jb_slot *in, long delivery, long now, char marker)
{
	int res;

	if (delivery < jb->next_delivery) {
		if (debug) fprintf(stdout, "put: delivery < jb->next_delivery\n");
		if (marker != 1) {
			jb->chan->last_loss_burst++;
		}
		int rslt = resynch_jb_slot(jb, in, now, "1 / delivery < jb->next_delivery");
		if (marker == 1) {
			jb->rxcore = now - in->ts;
		}
		return rslt;
	}

#if RESYNCH_V1
	if (marker == 1 && jb->count > 0) {
		struct fixed_jb_slot *tail = &jb->slots[(jb->head + jb->count - 1) & jb->mask];
		long mult = jb->chan->prev_frame_is_dtmf ? 4 : 2;
		if (in->ts > tail->ts + tail->ms + tail->ms * mult ||
		    in->ts < tail->ts + tail->ms - tail->ms * mult) {
			if (debug) fprintf(stdout, "call resync_jb for marker\n");
			jb->force_resynch = 1;
			return resynch_jb_slot(jb, in, now, "2 / marker");
		}
	}
	{
		int tolerance = jb->chan->audio_decode ? 200 : 0;
		if (delivery > jb->next_delivery + jb->delay + jb->conf.resync_threshold + tolerance) {
			if (debug) fprintf(stdout, "put: delivery[%lu] > ...\n", delivery);
			return resynch_jb_slot(jb, in, now, "3 / delivery > jb->next_delivery + jb->delay + jb->conf.resync_threshold + tolerance");
		}
	}
#endif

	/* Find the right place in the sorted ring buffer (largest idx with delivery <= new delivery) */
	int idx = jb->count - 1;
	while (idx >= 0 && jb->slots[(jb->head + idx) & jb->mask].delivery > delivery) {
		idx--;
	}

	/* Check overlap or force_resynch */
	if (jb->force_resynch) {
		res = resynch_jb_slot(jb, in, now, "4 / jb->force_resynch || ...");
		jb->force_resynch = 0;
		return res;
	}
	if (idx >= 0) {
		struct fixed_jb_slot *cur = &jb->slots[(jb->head + idx) & jb->mask];
		if (cur->delivery == delivery ||
		    (delivery + 10 < cur->delivery + cur->ms) ||
		    (idx + 1 < jb->count && (delivery + in->ms > jb->slots[(jb->head + idx + 1) & jb->mask].delivery))) {
			res = resynch_jb_slot(jb, in, now, "4 / jb->force_resynch || ...");
			jb->force_resynch = 0;
			return res;
		}
	}

	/* Reset the force resynch flag */
	jb->force_resynch = 0;

	if (jb->count == jb->cap) {
		if (fixed_jb_grow_slots(jb) != 0)
			return FIXED_JB_ERROR;
	}

	int ins = idx + 1;
	if (jb->count == 0) {
		jb->head = 0;
		jb->slots[0] = *in;
		jb->slots[0].delivery = delivery;
		jb->count = 1;
	} else if (ins == 0) {
		jb->head = (jb->head - 1) & jb->mask;
		jb->slots[jb->head] = *in;
		jb->slots[jb->head].delivery = delivery;
		jb->count++;
	} else {
		for (int k = jb->count - 1; k >= ins; k--) {
			jb->slots[(jb->head + k + 1) & jb->mask] = jb->slots[(jb->head + k) & jb->mask];
		}
		struct fixed_jb_slot *dst = &jb->slots[(jb->head + ins) & jb->mask];
		*dst = *in;
		dst->delivery = delivery;
		jb->count++;
	}

	return FIXED_JB_OK;
}

int fixed_jb_put_first(struct fixed_jb *jb, void *data, long ms, long ts, long now, char marker)
{
	struct fixed_jb_slot in;
	in.ts = ts;
	in.delivery = 0;
	in.data = data;
	in.ms = (int32_t)ms;
	in.seqno = 0;
	in.flags = JB_SLOT_FLAG_IS_AST_FRAME;
	in.pad = 0;
	return fixed_jb_put_first_slot(jb, &in, now, marker);
}

int fixed_jb_put(struct fixed_jb *jb, void *data, long ms, long ts, long now, char marker)
{
	struct fixed_jb_slot in;
	in.ts = ts;
	in.delivery = 0;
	in.data = data;
	in.ms = (int32_t)ms;
	in.seqno = 0;
	in.flags = JB_SLOT_FLAG_IS_AST_FRAME;
	in.pad = 0;
	return fixed_jb_put_slot_inl(jb, &in, now, marker, jb->chan->audio_decode);
}

int fixed_jb_flush_slot(struct fixed_jb *jb, struct fixed_jb_slot *slot_out)
{
	if (jb->count > 0) {
		pop_jb_head_slot(jb, slot_out);
		return 1;
	}
	return 0;
}

int fixed_jb_flush(struct fixed_jb *jb, struct fixed_jb_frame *frame)
{
	if (jb->count > 0) {
		struct fixed_jb_slot slot;
		pop_jb_head_slot(jb, &slot);
		slot_to_frame(&slot, frame);
		return 1;
	}
	return 0;
}

int fixed_jb_get(struct fixed_jb *jb, struct fixed_jb_frame *frame, long now, long interpl)
{
	struct fixed_jb_slot slot;
	int res = fixed_jb_get_slot_inl(jb, &slot, now, interpl);
	if (res == FIXED_JB_OK || res == FIXED_JB_DROP) {
		slot_to_frame(&slot, frame);
	}
	return res;
}

long fixed_jb_next(struct fixed_jb *jb)
{
	return jb->next_delivery;
}

int fixed_jb_remove_slot(struct fixed_jb *jb, struct fixed_jb_slot *slot_out)
{
	if (jb->count == 0)
		return FIXED_JB_NOFRAME;

	pop_jb_head_slot(jb, slot_out);
	return FIXED_JB_OK;
}

int fixed_jb_remove(struct fixed_jb *jb, struct fixed_jb_frame *frameout)
{
	if (jb->count == 0)
		return FIXED_JB_NOFRAME;

	struct fixed_jb_slot slot;
	pop_jb_head_slot(jb, &slot);
	slot_to_frame(&slot, frameout);
	return FIXED_JB_OK;
}
