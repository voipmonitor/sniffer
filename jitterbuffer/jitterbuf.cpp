/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2004-2005, Horizon Wimba, Inc.
 *
 * Contributors:
 * Steve Kann <stevek@stevek.com>
 *
 * A license has been granted to Digium (via disclaimer) for the use of
 * this code.
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
 * \brief jitterbuf: an application-independent jitterbuffer
 * \author Steve Kann <stevek@stevek.com>
 *
 */

#include "asterisk.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#include "jitterbuf.h"
#include "asterisk/utils.h"

static jb_output_function_t warnf, errf, dbgf;

void jb_setoutput(jb_output_function_t err, jb_output_function_t warn, jb_output_function_t dbg)
{
	errf = err;
	warnf = warn;
	dbgf = dbg;
}

static inline void jb_slot_to_frame(const jb_slot *slot, jb_frame *frame)
{
	frame->data = (slot->flags & JB_SLOT_FLAG_IS_AST_FRAME) ? slot->data : NULL;
	frame->ts = slot->ts;
	frame->ms = slot->ms;
	frame->type = (enum jb_frame_type)slot->type;
	frame->next = NULL;
	frame->prev = NULL;
}

void jb_reset(jitterbuf *jb)
{
	jb_conf s = jb->info.conf;

	if (jb->slots && jb->slots != jb->inline_slots) {
		ast_free(jb->slots);
	}
	if (jb->history32) {
		ast_free(jb->history32);
	}

	/* Zero only hot header fields (info + ring/history metadata), skip inline_slots & history16 */
	memset(jb, 0, offsetof(jitterbuf, inline_slots));
	jb->info.conf = s;

	/* initialize length */
	jb->info.current = jb->info.target = JB_TARGET_EXTRA;
	jb->info.silence_begin_ts = -1;

	jb->slots = jb->inline_slots;
	jb->slot_cap = JB_INLINE_SLOTS;
	jb->slot_mask = JB_INLINE_SLOTS - 1;
	jb->hist_min_valid = 1;
	jb->hist_max_valid = 1;
	jb->hist_dirty = 1;
}

jitterbuf *jb_new(void)
{
	jitterbuf *jb;

	if (!(jb = (jitterbuf *)ast_malloc(sizeof(*jb))))
		return NULL;

	jb->slots = NULL;
	jb->history32 = NULL;
	memset(&jb->info.conf, 0, sizeof(jb->info.conf));
	jb_reset(jb);
	return jb;
}

void jb_destroy(jitterbuf *jb)
{
	if (jb->slots && jb->slots != jb->inline_slots) {
		ast_free(jb->slots);
	}
	if (jb->history32) {
		ast_free(jb->history32);
	}
	ast_free(jb);
}

__attribute__((noinline, cold))
void jb_history_promote32(jitterbuf *jb)
{
	int32_t *h32 = (int32_t *)ast_malloc(JB_HISTORY_SZ * sizeof(int32_t));
	int count, i;
	if (!h32)
		return;
	count = jb->hist_count;
	for (i = 0; i < count; i++) {
		h32[i] = (int32_t)jb->history16[i];
	}
	jb->history32 = h32;
}

template<bool IsMax, typename ElemT>
static inline void jb_hist_rebuild_scan(int32_t *buf, const ElemT *hist, int count, int32_t &T, int &eq_out)
{
	for (int i = JB_HIST_TRACK_SZ; i < count; i++) {
		int32_t x = (int32_t)hist[i];
		if (__builtin_expect(IsMax ? (x >= T) : (x <= T), 0)) {
			if (IsMax ? (x > T) : (x < T)) {
				int j = JB_HIST_TRACK_SZ - 1;
				while (j > 0 && (IsMax ? (buf[j - 1] < x) : (buf[j - 1] > x))) {
					buf[j] = buf[j - 1];
					j--;
				}
				buf[j] = x;
				int32_t new_T = buf[JB_HIST_TRACK_SZ - 1];
				if (new_T == T) {
					eq_out++;
				} else {
					eq_out = 0;
					T = new_T;
				}
			} else {
				eq_out++;
			}
		}
	}
}

template<bool IsMax>
__attribute__((noinline, cold))
static void jb_history_rebuild_impl(jitterbuf *jb, int32_t *buf, int16_t *p_len, int16_t *p_eq_out, uint8_t *p_valid)
{
	int count = jb->hist_count;
	const int32_t *h32 = jb->history32;
	const int16_t *h16 = jb->history16;
	int init_n = (count < JB_HIST_TRACK_SZ) ? count : JB_HIST_TRACK_SZ;
	int eq_out = 0;

	for (int i = 0; i < init_n; i++) {
		int32_t x = h32 ? h32[i] : (int32_t)h16[i];
		int j = i;
		while (j > 0 && (IsMax ? (buf[j - 1] < x) : (buf[j - 1] > x))) {
			buf[j] = buf[j - 1];
			j--;
		}
		buf[j] = x;
	}

	if (count > JB_HIST_TRACK_SZ) {
		int32_t T = buf[JB_HIST_TRACK_SZ - 1];
		if (__builtin_expect(h32 == NULL, 1)) {
			jb_hist_rebuild_scan<IsMax>(buf, h16, count, T, eq_out);
		} else {
			jb_hist_rebuild_scan<IsMax>(buf, h32, count, T, eq_out);
		}
	}

	*p_len = (int16_t)init_n;
	*p_eq_out = (int16_t)eq_out;
	*p_valid = 1;
}

void jb_history_rebuild_min(jitterbuf *jb)
{
	jb_history_rebuild_impl<false>(jb, jb->hist_minbuf, &jb->hist_min_len, &jb->hist_min_eq_out, &jb->hist_min_valid);
}

void jb_history_rebuild_max(jitterbuf *jb)
{
	jb_history_rebuild_impl<true>(jb, jb->hist_maxbuf, &jb->hist_max_len, &jb->hist_max_eq_out, &jb->hist_max_valid);
}

__attribute__((noinline, cold))
int jb_grow_slots(jitterbuf *jb)
{
	int new_cap = jb->slot_cap * 2;
	jb_slot *new_slots = (jb_slot *)ast_malloc((size_t)new_cap * sizeof(jb_slot));
	if (!new_slots)
		return -1;

	int first_part = jb->slot_cap - jb->slot_head;
	if (first_part > jb->slot_count)
		first_part = jb->slot_count;
	memcpy(new_slots, jb->slots + jb->slot_head, (size_t)first_part * sizeof(jb_slot));
	if (jb->slot_count > first_part) {
		memcpy(new_slots + first_part, jb->slots, (size_t)(jb->slot_count - first_part) * sizeof(jb_slot));
	}

	if (jb->slots != jb->inline_slots) {
		ast_free(jb->slots);
	}
	jb->slots = new_slots;
	jb->slot_head = 0;
	jb->slot_cap = new_cap;
	jb->slot_mask = new_cap - 1;
	return 0;
}

/* returns 1 if frame was inserted into head of queue, 0 otherwise */
__attribute__((noinline, cold))
int jb_queue_put_ooo_slow(jitterbuf *jb, const jb_slot *in, long resync_ts)
{
	if (jb->slot_count == jb->slot_cap) {
		if (jb_grow_slots(jb) != 0)
			return 0;
	}

	jb->info.frames_ooo++;
	jb->info.frames_cur++;

	if (resync_ts < jb->slots[jb->slot_head].ts) {
		jb->slot_head = (jb->slot_head - 1) & jb->slot_mask;
		jb_slot *dst = &jb->slots[jb->slot_head];
		*dst = *in;
		dst->ts = resync_ts;
		jb->slot_count++;
		return 1;
	}

	/* Walk backwards from tail while resync_ts < slot.ts (preserves stable order for ties) */
	int idx = jb->slot_count - 1;
	while (idx > 0 && resync_ts < jb->slots[(jb->slot_head + idx) & jb->slot_mask].ts) {
		jb->slots[(jb->slot_head + idx + 1) & jb->slot_mask] = jb->slots[(jb->slot_head + idx) & jb->slot_mask];
		idx--;
	}
	jb_slot *dst = &jb->slots[(jb->slot_head + idx + 1) & jb->slot_mask];
	*dst = *in;
	dst->ts = resync_ts;
	jb->slot_count++;
	return 0;
}

__attribute__((noinline, cold))
enum jb_return_code jb_get_slot_silent_slow(jitterbuf *jb, jb_slot *slotout, long now, long interpl)
{
	long diff = jb->info.target - jb->info.current;

	/* shrink interpl len every 10ms during silence */
	if (diff < -JB_TARGET_EXTRA &&
	    jb->info.last_adjustment + 10 <= now) {
		jb->info.current -= interpl;
		jb->info.last_adjustment = now;
	}

	long wanted = now - jb->info.current;
	if (jb->slot_count == 0 || wanted < jb->slots[jb->slot_head].ts) {
		return JB_NOFRAME;
	}

	jb_slot fr = jb->slots[jb->slot_head];
	jb->slot_head = (jb->slot_head + 1) & jb->slot_mask;
	jb->slot_count--;
	jb->info.frames_cur--;

	if (fr.type != JB_TYPE_VOICE) {
		*slotout = fr;
		jb->info.frames_out++;
		return JB_OK;
	}

	if (fr.ts < jb->info.silence_begin_ts) {
		*slotout = fr;
		jb->info.frames_out++;
		jb_decrement_losspct_inl(jb);
		jb->info.frames_late++;
		jb->info.frames_lost--;
		return JB_DROP;
	} else {
		jb->info.current = jb->info.target;
		jb->info.silence_begin_ts = 0;
		jb->info.next_voice_ts = fr.ts + jb->info.current + fr.ms;
		jb->info.last_voice_ms = fr.ms;
		jb->info.frames_out++;
		jb_decrement_losspct_inl(jb);
		*slotout = fr;
		return JB_OK;
	}
}

enum jb_return_code jb_put(jitterbuf *jb, void *data, const enum jb_frame_type type, long ms, long ts, long now)
{
	jb_slot in;
	in.ts = ts;
	in.data = data;
	in.ms = (int32_t)ms;
	in.seqno = 0;
	in.type = (uint8_t)type;
	in.flags = JB_SLOT_FLAG_IS_AST_FRAME;
	return jb_put_slot_inl(jb, &in, now);
}

long jb_next(jitterbuf *jb)
{
	return jb_next_inl(jb);
}

enum jb_return_code jb_get(jitterbuf *jb, jb_frame *frameout, long now, long interpl)
{
	jb_slot slot;
	enum jb_return_code ret = jb_get_slot_inl(jb, &slot, now, interpl);
	if (ret == JB_OK || ret == JB_DROP) {
		jb_slot_to_frame(&slot, frameout);
	} else if (ret == JB_INTERP) {
		frameout->ms = jb->info.last_voice_ms;
	}
	return ret;
}

enum jb_return_code jb_getall_slot(jitterbuf *jb, jb_slot *slotout)
{
	if (jb->slot_count == 0)
		return JB_NOFRAME;

	*slotout = jb->slots[jb->slot_head];
	jb->slot_head = (jb->slot_head + 1) & jb->slot_mask;
	jb->slot_count--;
	jb->info.frames_cur--;
	return JB_OK;
}

enum jb_return_code jb_getall(jitterbuf *jb, jb_frame *frameout)
{
	jb_slot slot;
	if (jb_getall_slot(jb, &slot) != JB_OK)
		return JB_NOFRAME;

	jb_slot_to_frame(&slot, frameout);
	return JB_OK;
}

enum jb_return_code jb_getinfo(jitterbuf *jb, jb_info *stats)
{
	jb_history_get_inl(jb);
	*stats = jb->info;
	return JB_OK;
}

enum jb_return_code jb_setconf(jitterbuf *jb, jb_conf *conf)
{
	jb->info.conf.max_jitterbuf = conf->max_jitterbuf;
	jb->info.conf.resync_threshold = conf->resync_threshold;
	jb->info.conf.max_contig_interp = conf->max_contig_interp;
	return JB_OK;
}
