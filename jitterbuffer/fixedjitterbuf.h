/*
 * Copyright (C) 2005, Attractel OOD
 *
 * Contributors:
 * Slav Klenov <slav@securax.org>
 *
 * Copyright on this file is disclaimed to Digium for inclusion in Asterisk
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
 * \brief Jitterbuffering algorithm.
 *
 */

#ifndef _FIXEDJITTERBUF_H_
#define _FIXEDJITTERBUF_H_

#include <stdint.h>

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif


/* return codes */
enum {
	FIXED_JB_OK,
	FIXED_JB_DROP,
	FIXED_JB_INTERP,
	FIXED_JB_NOFRAME,
	FIXED_JB_ERROR
};


/* defaults */
#define FIXED_JB_SIZE_DEFAULT 200
#define FIXED_JB_RESYNCH_THRESHOLD_DEFAULT 500


/* Slot metadata flags shared across fixed and adaptive jitterbuffers */
#ifndef JB_SLOT_FLAG_MARKER
#define JB_SLOT_FLAG_MARKER        (1 << 0)
#define JB_SLOT_FLAG_LAST_VOICE    (1 << 1)
#define JB_SLOT_FLAG_SKIP          (1 << 2)
#define JB_SLOT_FLAG_IGNORE        (1 << 3)
#define JB_SLOT_FLAG_IS_AST_FRAME  (1 << 7)
#endif


/* jb configuration properties */
struct fixed_jb_conf
{
	long jbsize;
	long resync_threshold;
};


struct fixed_jb_frame
{
	void *data;
	long ts;
	long ms;
	long delivery;
	struct fixed_jb_frame *next;
	struct fixed_jb_frame *prev;
};


/*! \brief Compact 32-byte slot stored contiguously in fixed_jb ring buffer.
 *  When JB_SLOT_FLAG_IS_AST_FRAME is set, data points to a heap ast_frame*.
 *  Otherwise (MOS simulation mode), orig_ts/seqno/flags hold frame metadata inline
 *  with zero heap allocations. */
struct fixed_jb_slot
{
	long ts;
	long delivery;
	union {
		void *data;
		long orig_ts;
	};
	int32_t ms;
	uint16_t seqno;
	uint8_t flags;
	uint8_t pad;
};


struct ast_channel;

/*! \brief fixed_jb structure with contiguous power-of-2 ring buffer */
struct fixed_jb
{
	struct fixed_jb_slot *slots;
	int head;
	int count;
	int cap;
	int mask;
	long rxcore;
	long delay;
	long next_delivery;
	struct fixed_jb_conf conf;
	int force_resynch;
	struct ast_channel *chan;
	long long skew_sum;
	long skew_counter;
	struct fixed_jb_slot inline_slots[];
};


/* jb interface */

struct fixed_jb * fixed_jb_new(struct fixed_jb_conf *conf, struct ast_channel *chan);

void fixed_jb_destroy(struct fixed_jb *jb);

int fixed_jb_put_first(struct fixed_jb *jb, void *data, long ms, long ts, long now, char marker);

int fixed_jb_put(struct fixed_jb *jb, void *data, long ms, long ts, long now, char marker);

int fixed_jb_get(struct fixed_jb *jb, struct fixed_jb_frame *frame, long now, long interpl);

long fixed_jb_next(struct fixed_jb *jb);

int fixed_jb_remove(struct fixed_jb *jb, struct fixed_jb_frame *frameout);

void fixed_jb_set_force_resynch(struct fixed_jb *jb);

int fixed_jb_flush(struct fixed_jb *jb, struct fixed_jb_frame *frame);

/* Fast-path slot-based interface and cold out-of-line helpers */
int fixed_jb_put_first_slot(struct fixed_jb *jb, const struct fixed_jb_slot *in, long now, char marker);
int fixed_jb_put_slot_slow(struct fixed_jb *jb, const struct fixed_jb_slot *in, long delivery, long now, char marker);
void fixed_jb_put_invalid_slow(const struct fixed_jb_slot *in);
void fixed_jb_get_invalid_slow(long now, long interpl);
int fixed_jb_grow_slots(struct fixed_jb *jb);
int fixed_jb_flush_slot(struct fixed_jb *jb, struct fixed_jb_slot *slot_out);
int fixed_jb_remove_slot(struct fixed_jb *jb, struct fixed_jb_slot *slot_out);

static inline long fixed_jb_next_inl(const struct fixed_jb *jb)
{
	return jb->next_delivery;
}

static inline int fixed_jb_get_slot_inl(struct fixed_jb *jb, struct fixed_jb_slot *slot_out, long now, long interpl)
{
	if (__builtin_expect(now < 0 || interpl < 2, 0)) {
		fixed_jb_get_invalid_slow(now, interpl);
		return FIXED_JB_ERROR;
	}

	if (now < jb->next_delivery)
		return FIXED_JB_NOFRAME;

	if (__builtin_expect(jb->count == 0, 0)) {
		jb->next_delivery += interpl;
		return FIXED_JB_INTERP;
	}

	struct fixed_jb_slot *fr = &jb->slots[jb->head];
	if (__builtin_expect(now > fr->delivery + fr->ms, 0)) {
		jb->next_delivery = fr->delivery + fr->ms;
		*slot_out = *fr;
		jb->head = (jb->head + 1) & jb->mask;
		jb->count--;
		return FIXED_JB_DROP;
	}

	if (__builtin_expect(now < fr->delivery, 0)) {
		jb->next_delivery += interpl;
		return FIXED_JB_INTERP;
	}

	jb->next_delivery = fr->delivery + fr->ms;
	*slot_out = *fr;
	jb->head = (jb->head + 1) & jb->mask;
	jb->count--;
	return FIXED_JB_OK;
}

static inline int fixed_jb_put_slot_inl(struct fixed_jb *jb, const struct fixed_jb_slot *in, long now, char marker, int audio_decode)
{
	if (__builtin_expect(((in->flags & JB_SLOT_FLAG_IS_AST_FRAME) && !in->data) || in->ms < 2 || in->ts < 0, 0)) {
		fixed_jb_put_invalid_slow(in);
		return FIXED_JB_ERROR;
	}

	long delivery = jb->rxcore + jb->delay + in->ts;

	jb->skew_sum += in->ts - (now - jb->rxcore);
	++jb->skew_counter;

	int tolerance = audio_decode ? 200 : 0;
	if (__builtin_expect(delivery < jb->next_delivery ||
			     marker == 1 ||
			     jb->force_resynch ||
			     delivery > jb->next_delivery + jb->delay + jb->conf.resync_threshold + tolerance, 0)) {
		return fixed_jb_put_slot_slow(jb, in, delivery, now, marker);
	}

	int count = jb->count;
	if (__builtin_expect(count > 0, 1)) {
		struct fixed_jb_slot *tail = &jb->slots[(jb->head + count - 1) & jb->mask];
		if (__builtin_expect(tail->delivery < delivery && (delivery + 10 >= tail->delivery + tail->ms), 1)) {
			if (__builtin_expect(count == jb->cap, 0)) {
				if (fixed_jb_grow_slots(jb) != 0)
					return FIXED_JB_ERROR;
			}
			struct fixed_jb_slot *dst = &jb->slots[(jb->head + count) & jb->mask];
			*dst = *in;
			dst->delivery = delivery;
			jb->count = count + 1;
			return FIXED_JB_OK;
		}
		return fixed_jb_put_slot_slow(jb, in, delivery, now, marker);
	} else {
		jb->head = 0;
		jb->slots[0] = *in;
		jb->slots[0].delivery = delivery;
		jb->count = 1;
		return FIXED_JB_OK;
	}
}

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _FIXEDJITTERBUF_H_ */
