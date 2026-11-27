/*
 * jitterbuf: an application-independent jitterbuffer
 *
 * Copyrights:
 * Copyright (C) 2004-2005, Horizon Wimba, Inc.
 *
 * Contributors:
 * Steve Kann <stevek@stevek.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU Lesser (Library) General Public License
 *
 * Copyright on this file is disclaimed to Digium for inclusion in Asterisk
 */

#ifndef _JITTERBUF_H_
#define _JITTERBUF_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* configuration constants */
	/* Number of historical timestamps to use in calculating jitter and drift */
#define JB_HISTORY_SZ		500
	/* what percentage of timestamps should we drop from the history when we examine it;
	 * this might eventually be something made configurable */
#define JB_HISTORY_DROPPCT	3
	/* the maximum droppct we can handle (say it was configurable). */
#define JB_HISTORY_DROPPCT_MAX	4
	/* the size of the buffer we use to keep the top and botton timestamps for dropping */
#define JB_HISTORY_MAXBUF_SZ	(JB_HISTORY_SZ * JB_HISTORY_DROPPCT_MAX / 100)
	/* amount of additional jitterbuffer adjustment  */
#define JB_TARGET_EXTRA 40
	/* ms between growing and shrinking; may not be honored if jitterbuffer runs out of space */
#define JB_ADJUST_DELAY 40

/* Internal tracker capacity (cushion above max index=15 to amortize rebuilds to ~1 per 2500 pkts) */
#define JB_HIST_TRACK_SZ 32
#define JB_HIST_MAX_INDEX (JB_HISTORY_SZ * JB_HISTORY_DROPPCT / 100)
#define JB_INLINE_SLOTS 8

#ifndef JB_SLOT_FLAG_MARKER
#define JB_SLOT_FLAG_MARKER        (1 << 0)
#define JB_SLOT_FLAG_LAST_VOICE    (1 << 1)
#define JB_SLOT_FLAG_SKIP          (1 << 2)
#define JB_SLOT_FLAG_IGNORE        (1 << 3)
#define JB_SLOT_FLAG_IS_AST_FRAME  (1 << 7)
#endif

enum jb_return_code {
	/* return codes */
	JB_OK,            /* 0 */
	JB_EMPTY,         /* 1 */
	JB_NOFRAME,       /* 2 */
	JB_INTERP,        /* 3 */
	JB_DROP,          /* 4 */
	JB_SCHED          /* 5 */
};

enum jb_frame_type {
	/* frame types */
	JB_TYPE_CONTROL,  /* 0            */
	JB_TYPE_VOICE,    /* 1            */
	JB_TYPE_VIDEO,    /* 2 - reserved */
	JB_TYPE_SILENCE   /* 3            */
};

typedef struct jb_conf {
	/* settings */
	long max_jitterbuf;	/* defines a hard clamp to use in setting the jitter buffer delay */
	long resync_threshold;  /* the jb will resync when delay increases to (2 * jitter) + this param */
	long max_contig_interp; /* the max interp frames to return in a row */
} jb_conf;

typedef struct jb_info {
	jb_conf conf;

	/* statistics */
	long frames_in;  	/* number of frames input to the jitterbuffer.*/
	long frames_out;  	/* number of frames output from the jitterbuffer.*/
	long frames_late; 	/* number of frames which were too late, and dropped.*/
	long frames_lost; 	/* number of missing frames.*/
	long frames_dropped; 	/* number of frames dropped (shrinkage) */
	long frames_ooo; 	/* number of frames received out-of-order */
	long frames_cur; 	/* number of frames presently in jb, awaiting delivery.*/
	long jitter; 		/* jitter measured within current history interval*/
	long min;		/* minimum lateness within current history interval */
	long current; 		/* the present jitterbuffer adjustment */
	long target; 		/* the target jitterbuffer adjustment */
	long losspct; 		/* recent lost frame percentage (* 1000) */
	long next_voice_ts;	/* the ts of the next frame to be read from the jb - in receiver's time */
	long last_voice_ms;	/* the duration of the last voice frame */
	long silence_begin_ts;	/* the time of the last CNG frame, when in silence */
	long last_adjustment;   /* the time of the last adjustment */
	long last_delay;        /* the last now added to history */
	long cnt_delay_discont;	/* the count of discontinuous delays */
	long resync_offset;     /* the amount to offset ts to support resyncs */
	long cnt_contig_interp; /* the number of contiguous interp frames returned */
} jb_info;

typedef struct jb_frame {
	void *data;               /* the frame data */
	long ts;                  /* the relative delivery time expected */
	long ms;                  /* the time covered by this frame, in sec/8000 */
	enum jb_frame_type type;  /* the type of frame */
	struct jb_frame *next, *prev;
} jb_frame;

/*! \brief Compact 24-byte slot stored contiguously in jitterbuf ring buffer */
typedef struct jb_slot {
	long ts;
	union {
		void *data;
		long orig_ts;
	};
	int32_t ms;
	uint16_t seqno;
	uint8_t type;
	uint8_t flags;
} jb_slot;

typedef struct jitterbuf {
	jb_info info; /* MUST remain first field */

	/* Hot ring buffer state */
	jb_slot *slots;
	int32_t *history32;     /* NULL unless a delay falls outside int16_t range [-32768, 32767] */
	int slot_head;
	int slot_count;
	int slot_cap;
	int slot_mask;

	/* Hot incremental history tracker state */
	int16_t hist_pos;
	int16_t hist_count;
	int16_t hist_min_len;
	int16_t hist_max_len;
	int16_t hist_min_eq_out;
	int16_t hist_max_eq_out;
	uint8_t hist_min_valid;
	uint8_t hist_max_valid;
	uint8_t hist_dirty;     /* 1 if info.min/info.jitter need refresh from minbuf/maxbuf */
	uint8_t dropem;

	/* Inline slot storage (8 * 24 = 192 bytes) */
	jb_slot inline_slots[JB_INLINE_SLOTS];

	/* Sorted top-32 and bottom-32 trackers (256 bytes) */
	int32_t hist_maxbuf[JB_HIST_TRACK_SZ];	/* descending: [0] >= [1] >= ... */
	int32_t hist_minbuf[JB_HIST_TRACK_SZ];	/* ascending:  [0] <= [1] <= ... */

	/* Compact 16-bit sliding window history (1000 bytes, 4x smaller than long[500]) */
	int16_t history16[JB_HISTORY_SZ];
} jitterbuf;


/* new jitterbuf */
jitterbuf *		jb_new(void);

/* destroy jitterbuf */
void			jb_destroy(jitterbuf *jb);

/* reset jitterbuf */
void			jb_reset(jitterbuf *jb);

/* queue a frame */
enum jb_return_code jb_put(jitterbuf *jb, void *data, const enum jb_frame_type type, long ms, long ts, long now);

/* get a frame for time now */
enum jb_return_code jb_get(jitterbuf *jb, jb_frame *frame, long now, long interpl);

/* unconditionally get frames from jitterbuf until empty */
enum jb_return_code jb_getall(jitterbuf *jb, jb_frame *frameout);

/* when is the next frame due out, in receiver's time */
long			jb_next(jitterbuf *jb);

/* get jitterbuf info */
enum jb_return_code jb_getinfo(jitterbuf *jb, jb_info *stats);

/* set jitterbuf conf */
enum jb_return_code jb_setconf(jitterbuf *jb, jb_conf *conf);

typedef void __attribute__((format(printf, 1, 2))) (*jb_output_function_t)(const char *fmt, ...);
void jb_setoutput(jb_output_function_t err, jb_output_function_t warn, jb_output_function_t dbg);

/* Cold out-of-line helpers for inline fast paths */
void jb_history_rebuild_min(jitterbuf *jb);
void jb_history_rebuild_max(jitterbuf *jb);
void jb_history_promote32(jitterbuf *jb);
int jb_grow_slots(jitterbuf *jb);
int jb_queue_put_ooo_slow(jitterbuf *jb, const jb_slot *in, long resync_ts);
enum jb_return_code jb_get_slot_silent_slow(jitterbuf *jb, jb_slot *slotout, long now, long interpl);
enum jb_return_code jb_getall_slot(jitterbuf *jb, jb_slot *slotout);

#define JB_LONGMAX_VAL 2147483647L

static inline void jb_increment_losspct_inl(jitterbuf *jb)
{
	jb->info.losspct = (100000 + 499 * jb->info.losspct) / 500;
}

static inline void jb_decrement_losspct_inl(jitterbuf *jb)
{
	if (__builtin_expect(jb->info.losspct != 0, 0)) {
		jb->info.losspct = (499 * jb->info.losspct) / 500;
	}
}

static inline __attribute__((always_inline)) void jb_hist_add_only_impl(
	int32_t *buf, int16_t *p_len, int16_t *p_eq_out, int32_t delay, int is_max)
{
	int len = *p_len;
	if (__builtin_expect(len < JB_HIST_TRACK_SZ, 0)) {
		int j = len;
		while (j > 0 && (is_max ? (buf[j - 1] < delay) : (buf[j - 1] > delay))) {
			buf[j] = buf[j - 1];
			j--;
		}
		buf[j] = delay;
		*p_len = (int16_t)(len + 1);
	} else {
		int32_t T = buf[JB_HIST_TRACK_SZ - 1];
		int j;
		if (is_max ? (delay < T) : (delay > T)) return;
		if (delay == T) {
			(*p_eq_out)++;
			return;
		}
		j = JB_HIST_TRACK_SZ - 1;
		while (j > 0 && (is_max ? (buf[j - 1] < delay) : (buf[j - 1] > delay))) {
			buf[j] = buf[j - 1];
			j--;
		}
		buf[j] = delay;
		if (buf[JB_HIST_TRACK_SZ - 1] == T) {
			(*p_eq_out)++;
		} else {
			*p_eq_out = 0;
		}
	}
}

static inline void jb_hist_min_add_only(jitterbuf *jb, int32_t delay)
{
	jb_hist_add_only_impl(jb->hist_minbuf, &jb->hist_min_len, &jb->hist_min_eq_out, delay, 0);
}

static inline void jb_hist_max_add_only(jitterbuf *jb, int32_t delay)
{
	jb_hist_add_only_impl(jb->hist_maxbuf, &jb->hist_max_len, &jb->hist_max_eq_out, delay, 1);
}

static inline __attribute__((always_inline)) void jb_hist_replace_impl(
	jitterbuf *jb, int32_t *buf, int16_t *p_len, int16_t *p_eq_out, uint8_t *p_valid,
	int32_t kicked, int32_t delay, int is_max)
{
	int len = *p_len;
	int32_t T = buf[len - 1];

	if (__builtin_expect(is_max ? (kicked < T && delay < T) : (kicked > T && delay > T), 1))
		return;

	jb->hist_dirty = 1;

	if (is_max ? (kicked > T) : (kicked < T)) {
		int lo = 0, hi = len - 2, j;
		while (lo < hi) {
			int mid = (lo + hi) >> 1;
			if (is_max ? (buf[mid] > kicked) : (buf[mid] < kicked)) lo = mid + 1;
			else hi = mid;
		}
		for (j = lo; j < len - 1; j++) {
			buf[j] = buf[j + 1];
		}
		len--;
		if (*p_eq_out > 0) {
			buf[len++] = T;
			(*p_eq_out)--;
		}
	} else if (kicked == T) {
		if (*p_eq_out > 0) {
			(*p_eq_out)--;
		} else {
			len--;
			T = buf[len - 1];
		}
	}

	if (is_max ? (delay > T) : (delay < T)) {
		if (len < JB_HIST_TRACK_SZ) {
			int j = len;
			while (j > 0 && (is_max ? (buf[j - 1] < delay) : (buf[j - 1] > delay))) {
				buf[j] = buf[j - 1];
				j--;
			}
			buf[j] = delay;
			len++;
		} else {
			int j = JB_HIST_TRACK_SZ - 1;
			while (j > 0 && (is_max ? (buf[j - 1] < delay) : (buf[j - 1] > delay))) {
				buf[j] = buf[j - 1];
				j--;
			}
			buf[j] = delay;
			if (buf[JB_HIST_TRACK_SZ - 1] == T) {
				(*p_eq_out)++;
			} else {
				*p_eq_out = 0;
			}
		}
	} else if (delay == T) {
		if (len < JB_HIST_TRACK_SZ) {
			buf[len++] = T;
		} else {
			(*p_eq_out)++;
		}
	}

	*p_len = (int16_t)len;
	if (__builtin_expect(len <= JB_HIST_MAX_INDEX, 0)) {
		*p_valid = 0;
	}
}

static inline void jb_hist_min_replace(jitterbuf *jb, int32_t kicked, int32_t delay)
{
	jb_hist_replace_impl(jb, jb->hist_minbuf, &jb->hist_min_len, &jb->hist_min_eq_out, &jb->hist_min_valid, kicked, delay, 0);
}

static inline void jb_hist_max_replace(jitterbuf *jb, int32_t kicked, int32_t delay)
{
	jb_hist_replace_impl(jb, jb->hist_maxbuf, &jb->hist_max_len, &jb->hist_max_eq_out, &jb->hist_max_valid, kicked, delay, 1);
}

static inline void jb_history_reset_state(jitterbuf *jb, long ts, long now)
{
	jb->info.cnt_delay_discont = 0;
	jb->hist_pos = 0;
	jb->hist_count = 0;
	jb->hist_min_len = 0;
	jb->hist_max_len = 0;
	jb->hist_min_eq_out = 0;
	jb->hist_max_eq_out = 0;
	jb->hist_min_valid = 1;
	jb->hist_max_valid = 1;
	jb->hist_dirty = 1;
	jb->info.resync_offset = ts - now;
	jb->info.last_delay = 0;
}

static inline int jb_history_put_inl(jitterbuf *jb, long ts, long now)
{
	long delay = now - (ts - jb->info.resync_offset);
	long threshold = 2 * jb->info.jitter + jb->info.conf.resync_threshold;
	int32_t d32;
	int pos, next_pos;

	/* don't add special/negative times to history */
	if (__builtin_expect(ts <= 0, 0))
		return 0;

	/* check for drastic change in delay */
	if (__builtin_expect(jb->info.conf.resync_threshold != -1, 1)) {
		if (__builtin_expect(jb->info.frames_in == 0, 0)) {
			jb_history_reset_state(jb, ts, now);
			delay = 0;
		} else {
			if (__builtin_expect(abs((int)(delay - jb->info.last_delay)) > threshold, 0)) {
				jb->info.cnt_delay_discont++;
				if (jb->info.cnt_delay_discont > 3) {
					jb_history_reset_state(jb, ts, now);
					delay = 0;
				} else {
					return -1;
				}
			} else {
				jb->info.last_delay = delay;
				jb->info.cnt_delay_discont = 0;
			}
		}
	}

	d32 = (int32_t)delay;
	if (__builtin_expect(jb->history32 == NULL && (d32 < -32768 || d32 > 32767), 0)) {
		jb_history_promote32(jb);
	}

	pos = jb->hist_pos;
	next_pos = pos + 1;
	if (next_pos == JB_HISTORY_SZ) next_pos = 0;
	jb->hist_pos = (int16_t)next_pos;

	if (__builtin_expect(jb->hist_count < JB_HISTORY_SZ, 0)) {
		if (__builtin_expect(jb->history32 == NULL, 1))
			jb->history16[pos] = (int16_t)d32;
		else
			jb->history32[pos] = d32;
		jb->hist_count++;
		jb->hist_dirty = 1;
		if (jb->hist_min_valid) jb_hist_min_add_only(jb, d32);
		if (jb->hist_max_valid) jb_hist_max_add_only(jb, d32);
	} else {
		int32_t kicked;
		if (__builtin_expect(jb->history32 == NULL, 1)) {
			kicked = (int32_t)jb->history16[pos];
			jb->history16[pos] = (int16_t)d32;
		} else {
			kicked = jb->history32[pos];
			jb->history32[pos] = d32;
		}
		if (d32 == kicked)
			return 0;
		if (jb->hist_min_valid) jb_hist_min_replace(jb, kicked, d32);
		if (jb->hist_max_valid) jb_hist_max_replace(jb, kicked, d32);
	}

	return 0;
}

static inline void jb_history_get_inl(jitterbuf *jb)
{
	if (__builtin_expect(!jb->hist_dirty, 1))
		return;

	int count = jb->hist_count;
	if (__builtin_expect(count == 0, 0)) {
		jb->info.min = 0;
		jb->info.jitter = 0;
		jb->hist_dirty = 0;
		return;
	}

	if (__builtin_expect(!jb->hist_min_valid, 0))
		jb_history_rebuild_min(jb);
	if (__builtin_expect(!jb->hist_max_valid, 0))
		jb_history_rebuild_max(jb);

	int index = (count == JB_HISTORY_SZ) ? JB_HIST_MAX_INDEX : (count * JB_HISTORY_DROPPCT / 100);
	if (index > (JB_HISTORY_MAXBUF_SZ - 1))
		index = JB_HISTORY_MAXBUF_SZ - 1;

	long max = jb->hist_maxbuf[index];
	long min = jb->hist_minbuf[index];

	jb->info.min = min;
	jb->info.jitter = max - min;
	jb->hist_dirty = 0;
}

static inline enum jb_return_code jb_put_slot_inl(jitterbuf *jb, const jb_slot *in, long now)
{
	long numts = 0;
	if (__builtin_expect(jb->slot_count > 0, 1)) {
		numts = jb->slots[(jb->slot_head + jb->slot_count - 1) & jb->slot_mask].ts -
			jb->slots[jb->slot_head].ts;
	}

	if (__builtin_expect(numts >= jb->info.conf.max_jitterbuf, 0)) {
		jb->dropem = 1;
		jb->info.frames_dropped++;
		return JB_DROP;
	} else {
		jb->dropem = 0;
	}

	if (__builtin_expect(in->type == JB_TYPE_VOICE, 1)) {
		if (__builtin_expect(jb_history_put_inl(jb, in->ts, now) != 0, 0)) {
			jb->info.frames_dropped++;
			return JB_DROP;
		}
	}

	jb->info.frames_in++;

	long resync_ts = in->ts - jb->info.resync_offset;
	int count = jb->slot_count;
	if (__builtin_expect(count > 0, 1)) {
		long tail_ts = jb->slots[(jb->slot_head + count - 1) & jb->slot_mask].ts;
		if (__builtin_expect(resync_ts >= tail_ts, 1)) {
			if (__builtin_expect(count == jb->slot_cap, 0)) {
				if (jb_grow_slots(jb) != 0)
					return JB_OK;
			}
			jb_slot *dst = &jb->slots[(jb->slot_head + count) & jb->slot_mask];
			*dst = *in;
			dst->ts = resync_ts;
			jb->slot_count = count + 1;
			jb->info.frames_cur++;
			return JB_OK;
		}
		return jb_queue_put_ooo_slow(jb, in, resync_ts) ? JB_SCHED : JB_OK;
	} else {
		jb->slot_head = 0;
		jb->slots[0] = *in;
		jb->slots[0].ts = resync_ts;
		jb->slot_count = 1;
		jb->info.frames_cur++;
		return JB_SCHED;
	}
}

static inline long jb_next_inl(jitterbuf *jb)
{
	if (__builtin_expect(!jb->info.silence_begin_ts, 1)) {
		return jb->info.next_voice_ts;
	}
	if (jb->slot_count > 0) {
		long next = jb->slots[jb->slot_head].ts;
		jb_history_get_inl(jb);
		if (jb->info.target - jb->info.current < -JB_TARGET_EXTRA)
			return jb->info.last_adjustment + 10;
		return next + jb->info.target;
	}
	return JB_LONGMAX_VAL;
}

static inline enum jb_return_code jb_get_slot_inl(jitterbuf *jb, jb_slot *slotout, long now, long interpl)
{
	jb_history_get_inl(jb);

	long target = jb->info.jitter + jb->info.min + JB_TARGET_EXTRA;
	if (jb->info.conf.max_jitterbuf && ((target - jb->info.min) > jb->info.conf.max_jitterbuf)) {
		target = jb->info.min + jb->info.conf.max_jitterbuf;
	}
	jb->info.target = target;

	long diff = target - jb->info.current;

	if (__builtin_expect(!jb->info.silence_begin_ts, 1)) {
		/* we want to grow */
		if (__builtin_expect(diff > 0, 0)) {
			long qspan = jb->slot_count > 0
				? (jb->slots[(jb->slot_head + jb->slot_count - 1) & jb->slot_mask].ts - jb->slots[jb->slot_head].ts)
				: 0;
			if (((jb->info.last_adjustment + JB_ADJUST_DELAY) < now) || (diff > qspan)) {
				jb->info.current += interpl;
				jb->info.next_voice_ts += interpl;
				jb->info.last_voice_ms = interpl;
				jb->info.last_adjustment = now;
				jb->info.cnt_contig_interp++;
				if (jb->info.conf.max_contig_interp && jb->info.cnt_contig_interp >= jb->info.conf.max_contig_interp) {
					jb->info.silence_begin_ts = jb->info.next_voice_ts - jb->info.current;
				}
				slotout->ms = (int32_t)jb->info.last_voice_ms;
				return JB_INTERP;
			}
		}

		/* queue_get(jb, jb->info.next_voice_ts - jb->info.current) */
		long wanted = jb->info.next_voice_ts - jb->info.current;
		int has_frame = 0;
		jb_slot fr;
		if (__builtin_expect(jb->slot_count > 0 && wanted >= jb->slots[jb->slot_head].ts, 1)) {
			fr = jb->slots[jb->slot_head];
			jb->slot_head = (jb->slot_head + 1) & jb->slot_mask;
			jb->slot_count--;
			jb->info.frames_cur--;
			has_frame = 1;
		}

		if (has_frame) {
			/* not a voice frame; just return it. */
			if (__builtin_expect(fr.type != JB_TYPE_VOICE, 0)) {
				if (fr.type == JB_TYPE_SILENCE) {
					jb->info.silence_begin_ts = fr.ts;
					jb->info.cnt_contig_interp = 0;
				}
				*slotout = fr;
				jb->info.frames_out++;
				return JB_OK;
			}

			/* voice frame is later than expected */
			if (__builtin_expect(fr.ts + jb->info.current < jb->info.next_voice_ts, 0)) {
				if (fr.ts + jb->info.current > jb->info.next_voice_ts - jb->info.last_voice_ms) {
					*slotout = fr;
					jb->info.next_voice_ts = fr.ts + jb->info.current + fr.ms;
					jb->info.frames_out++;
					jb_decrement_losspct_inl(jb);
					jb->info.cnt_contig_interp = 0;
					return JB_OK;
				} else {
					*slotout = fr;
					jb->info.frames_out++;
					jb_decrement_losspct_inl(jb);
					jb->info.frames_late++;
					jb->info.frames_lost--;
					return JB_DROP;
				}
			}

			if (fr.ms > 0) {
				jb->info.last_voice_ms = fr.ms;
			}

			/* we want to shrink */
			if (__builtin_expect(diff < -JB_TARGET_EXTRA && (jb->info.last_adjustment + 500 < now), 0)) {
				jb->info.last_adjustment = now;
				jb->info.cnt_contig_interp = 0;
				*slotout = fr;
				jb->info.current -= fr.ms;
				jb->info.frames_out++;
				jb_decrement_losspct_inl(jb);
				jb->info.frames_dropped++;
				return JB_DROP;
			}

			/* normal case; return the frame */
			*slotout = fr;
			jb->info.next_voice_ts += fr.ms;
			jb->info.frames_out++;
			jb->info.cnt_contig_interp = 0;
			jb_decrement_losspct_inl(jb);
			return JB_OK;
		} else {
			/* !frame: check shrink during missing frame */
			if (__builtin_expect(diff < -JB_TARGET_EXTRA && (jb->info.last_adjustment + 80 < now), 0)) {
				jb->info.last_adjustment = now;
				jb->info.cnt_contig_interp = 0;
				jb->info.current -= jb->info.last_voice_ms;
				jb->info.frames_lost++;
				jb_increment_losspct_inl(jb);
				return JB_NOFRAME;
			}

			/* lost frame */
			jb->info.frames_lost++;
			jb_increment_losspct_inl(jb);
			jb->info.next_voice_ts += interpl;
			jb->info.last_voice_ms = interpl;
			jb->info.cnt_contig_interp++;
			if (jb->info.conf.max_contig_interp && jb->info.cnt_contig_interp >= jb->info.conf.max_contig_interp) {
				jb->info.silence_begin_ts = jb->info.next_voice_ts - jb->info.current;
			}
			slotout->ms = (int32_t)jb->info.last_voice_ms;
			return JB_INTERP;
		}
	} else {
		return jb_get_slot_silent_slow(jb, slotout, now, interpl);
	}
}

#ifdef __cplusplus
}
#endif


#endif
