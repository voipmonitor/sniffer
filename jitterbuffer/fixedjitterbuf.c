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

#undef FIXED_JB_DEBUG

#ifdef FIXED_JB_DEBUG
#define ASSERT(a)
#else
#define ASSERT(a) assert(a)
#endif

static int debug = 0;

#define RESYNCH_V1 1

/*! \brief private fixed_jb structure */
struct fixed_jb
{
	struct fixed_jb_frame *frames;
	struct fixed_jb_frame *tail;
	struct fixed_jb_conf conf;
	long rxcore;
	long delay;
	long next_delivery;
	int force_resynch;
	struct ast_channel *chan;
};


static struct fixed_jb_frame *alloc_jb_frame(struct fixed_jb *jb);
static void release_jb_frame(struct fixed_jb *jb, struct fixed_jb_frame *frame);
static void get_jb_head(struct fixed_jb *jb, struct fixed_jb_frame *frame);
static int resynch_jb(struct fixed_jb *jb, void *data, long ms, long ts, long now);

static inline struct fixed_jb_frame *alloc_jb_frame(struct fixed_jb *jb)
{
	return ast_calloc(1, sizeof(struct fixed_jb_frame));
}

static inline void release_jb_frame(struct fixed_jb *jb, struct fixed_jb_frame *frame)
{
	ast_free(frame);
}

static void get_jb_head(struct fixed_jb *jb, struct fixed_jb_frame *frame)
{
	struct fixed_jb_frame *fr;
	
	/* unlink the frame */
	fr = jb->frames;
	jb->frames = fr->next;
	if (jb->frames) {
		jb->frames->prev = NULL;
	} else {
		/* the jb is empty - update tail */
		jb->tail = NULL;
	}
	
	/* update next */
	jb->next_delivery = fr->delivery + fr->ms;
	
	/* copy the destination */
	memcpy(frame, fr, sizeof(struct fixed_jb_frame));
	
	/* and release the frame */
	release_jb_frame(jb, fr);
}


struct fixed_jb *fixed_jb_new(struct fixed_jb_conf *conf, struct ast_channel *chan)
{
	struct fixed_jb *jb;
	
	if (!(jb = ast_calloc(1, sizeof(*jb))))
		return NULL;

	jb->chan = chan;
	
	/* First copy our config */
	memcpy(&jb->conf, conf, sizeof(struct fixed_jb_conf));

	/* we dont need the passed config anymore - continue working with the saved one */
	conf = &jb->conf;
	
	/* validate the configuration */
	if (conf->jbsize < 1)
		conf->jbsize = FIXED_JB_SIZE_DEFAULT;

	if (conf->resync_threshold < 1)
		conf->resync_threshold = FIXED_JB_RESYNCH_THRESHOLD_DEFAULT;
	
	/* Set the constant delay to the jitterbuf */
	jb->delay = conf->jbsize;
	
	return jb;
}


void fixed_jb_destroy(struct fixed_jb *jb)
{
	/* jitterbuf MUST be empty before it can be destroyed */
	if(!(jb->frames == NULL)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_destroy - jb->frames == NULL");
		extern int opt_enable_jitterbuffer_asserts;
		if(opt_enable_jitterbuffer_asserts) {
			ASSERT(jb->frames == NULL);
		}
		return;
	}
	
	ast_free(jb);
}


static int resynch_jb(struct fixed_jb *jb, void *data, long ms, long ts, long now)
{
	long diff, offset;
	struct fixed_jb_frame *frame;

	
	/* If jb is empty, just reinitialize the jb */
	if (!jb->frames) {
		/* debug check: tail should also be NULL */
		if(debug) fprintf(stdout, "resynch_jb: empty jb\n");
		if(!(jb->tail == NULL)) {
			syslog(5 /*notice */, "JB ASSERT - resynch_jb - jb->tail == NULL");
			extern int opt_enable_jitterbuffer_asserts;
			if(opt_enable_jitterbuffer_asserts) {
				ASSERT(jb->tail == NULL);
			}
			return FIXED_JB_ERROR;
		}
		
		jb->force_resynch = 0;
		return fixed_jb_put_first(jb, data, ms, ts, now, 0);
	}
	
	/* Adjust all jb state just as the new frame is with delivery = the delivery of the last
	   frame (e.g. this one with max delivery) + the length of the last frame. */
	
	/* Get the diff in timestamps */
	diff = ts - jb->tail->ts;
	
	/* Ideally this should be just the length of the last frame. The deviation is the desired
	   offset */
	offset = diff - jb->tail->ms;
	
	/* Do we really need to resynch, or this is just a frame for dropping? */
	//if(debug) fprintf(stdout, "resync_jb: offset %ld, threshold %d force:%d\n", offset, jb->conf.resync_threshold, jb->force_resynch);


#if RESYNCH_V0

	if ( !jb->force_resynch && (offset < jb->conf.resync_threshold && offset > -jb->conf.resync_threshold)) {
		if(debug) fprintf(stdout, "resynch_jb - dropping offset [%ld] < jb->conf.resync_threshold [%ld] && offset [%lu] > -jb->conf.resync_threshol [%ld] | ts[%lu] jb->tail->ts[%lu] jb->tail->ms[%lu]\n", 
			offset, jb->conf.resync_threshold, offset, -jb->conf.resync_threshold, ts, jb->tail->ts, jb->tail->ms);
		jb->force_resynch = 0;

		jb_fixed_flush_deliver(jb->chan);
		return fixed_jb_put_first(jb, data, ms, ts, now, 0);
		return FIXED_JB_DROP;
	}
	if(jb->force_resynch) {
		jb->force_resynch = 0;
		jb_fixed_flush_deliver(jb->chan);
		return fixed_jb_put_first(jb, data, ms, ts, now, 0);
	}
	
#elif RESYNCH_V1
	
	if (offset < jb->conf.resync_threshold && offset > -jb->conf.resync_threshold) {
		if(debug) 
			fprintf(stdout, 
				"resynch_jb - force[%i] - dropping offset [%ld] < jb->conf.resync_threshold [%ld] && offset [%lu] > -jb->conf.resync_threshol [%ld] | ts[%lu] jb->tail->ts[%lu] jb->tail->ms[%lu] "
				"now[%ld] ts[%ld] now-ts[%ld] rxcore[%ld] delay[%ld] "
				"delivery[%ld] next_delivery[%ld] [%ld]\n", 
				jb->force_resynch, offset, jb->conf.resync_threshold, offset, -jb->conf.resync_threshold, ts, jb->tail->ts, jb->tail->ms,
				now, ts, now - ts, jb->rxcore, jb->delay,
				jb->rxcore + ts, jb->next_delivery, jb->rxcore + ts - jb->next_delivery);
		if (!jb->force_resynch) {
			if(offset < 0 || 
			   jb->rxcore + ts > jb->next_delivery + jb->delay + jb->conf.resync_threshold) {
				return FIXED_JB_DROP;
			} else {
				jb_fixed_flush_deliver(jb->chan);
				return fixed_jb_put_first(jb, data, ms, ts, now, 0);
			}
		} else {
			jb->force_resynch = 0;
			if(offset < 0) {
				return FIXED_JB_DROP;
			} else {
				jb_fixed_flush_deliver(jb->chan);
				return fixed_jb_put_first(jb, data, ms, ts, now, 0);
			}
		}
	}
	
#endif

	/* Reset the force resynch flag */
	jb->force_resynch = 0;

	if(debug) fprintf(stdout, "fixedjb: resync_jb\n");
	
	/* apply the offset to the jb state */
	jb->rxcore -= offset;
	frame = jb->frames;
	while (frame) {
		frame->ts += offset;
		frame = frame->next;
	}

	//jb_fixed_flush_deliver(jb->chan);
	
	/* now jb_put() should add the frame at a last position */
	return fixed_jb_put(jb, data, ms, ts, now, 0);
}


void fixed_jb_set_force_resynch(struct fixed_jb *jb)
{
	jb->force_resynch = 1;
}


int fixed_jb_put_first(struct fixed_jb *jb, void *data, long ms, long ts, long now, char marker)
{
	/* this is our first frame - set the base of the receivers time */
	jb->rxcore = now - ts;
	
	/* init next for a first time - it should be the time the first frame should be played */
	jb->next_delivery = now + jb->delay;
	
	/* put the frame */
	return fixed_jb_put(jb, data, ms, ts, now, marker);
}


int fixed_jb_put(struct fixed_jb *jb, void *data, long ms, long ts, long now, char marker)
{
	struct fixed_jb_frame *frame, *next, *newframe;
	long delivery;
	int res;
	
	/* debug check the validity of the input params */
	extern int opt_enable_jitterbuffer_asserts;
	if(!(data != NULL)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_put - data != NULL");
		if(opt_enable_jitterbuffer_asserts) {
			ASSERT(data != NULL);
		}
		return FIXED_JB_ERROR;
	}
	/* do not allow frames shorter than 2 ms */
	if(!(ms >= 2)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_put - ms >= 2");
		if(opt_enable_jitterbuffer_asserts) {
			ASSERT(ms >= 2);
		}
		return FIXED_JB_ERROR;
	}
	if(!(ts >= 0)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_put - ts >= 0");
		if(opt_enable_jitterbuffer_asserts) {
			ASSERT(ts >= 0);
		}
		return FIXED_JB_ERROR;
	}
        // TODO: implement pcap reordering queue, ASSERT(now >= 0);
	
	
	delivery = jb->rxcore + jb->delay + ts;
	
	/* check if the new frame is not too late */
	//if(debug) fprintf(stdout, "delivery: %d, jb->next_delivery: %d\n", delivery, jb->next_delivery);
	if (delivery < jb->next_delivery) {
		/* should drop the frame, but let first resynch_jb() check if this is not a jump in ts, or
		   the force resynch flag was not set. */
		if(debug) fprintf(stdout, "put: delivery < jb->next_delivery\n");
		jb->chan->last_loss_burst++;
		return resynch_jb(jb, data, ms, ts, now);
	}
	
	/* what if the delivery time is bigger than next + delay? Seems like a frame for the future.
	   However, allow more resync_threshold ms in advance */
	/* festr 5.5.2014 - be more tolerant for future frame (bursts) and add 200ms more) */
	/* festr 30.6.2014 - adding more tolerace is not good idea because it ignores 50ms fixed jitter len. add it only for audio decoder */
	
#if RESYNCH_V0
	
	int tolerance = audio_decode ? 200 : 0; // for audio decode add 200ms more
	if (delivery > jb->next_delivery + jb->delay + jb->conf.resync_threshold + tolerance) {
		/* should drop the frame, but let first resynch_jb() check if this is not a jump in ts, or
		   the force resynch flag was not set. */
		if(debug) fprintf(stdout, "put: delivery[%lu] > jb->next_delivery[%lu] + jb->delay[%lu] + jb->conf.resync_threshold[%lu]\n", delivery, jb->next_delivery, jb->delay, jb->conf.resync_threshold);
		return resynch_jb(jb, data, ms, ts, now, audio_decode);
	} else if(marker) {
		if(debug) fprintf(stdout, "call resync_jb for marker\n");
		jb->force_resynch = 1;
		return resynch_jb(jb, data, ms, ts, now, audio_decode);
	}
	
#elif RESYNCH_V1

	if(marker == 1 &&  // only for rtp marker (forcemark is > 1)
	   jb->tail && 
	   (ts > jb->tail->ts + jb->tail->ms + jb->tail->ms * (jb->chan->prev_frame_is_dtmf ? 4 : 2) ||
	    ts < jb->tail->ts + jb->tail->ms - jb->tail->ms * (jb->chan->prev_frame_is_dtmf ? 4 : 2))) {
		if(debug) fprintf(stdout, "call resync_jb for marker\n");
		jb->force_resynch = 1;
		return resynch_jb(jb, data, ms, ts, now);
	} else {
		int tolerance = jb->chan->audio_decode ? 200 : 0; // for audio decode add 200ms more
		if (delivery > jb->next_delivery + jb->delay + jb->conf.resync_threshold + tolerance) {
			/* should drop the frame, but let first resynch_jb() check if this is not a jump in ts, or
			   the force resynch flag was not set. */
			if(debug) fprintf(stdout, "put: delivery[%lu] > jb->next_delivery[%lu] + jb->delay[%lu] + jb->conf.resync_threshold[%lu]\n", delivery, jb->next_delivery, jb->delay, jb->conf.resync_threshold);
			return resynch_jb(jb, data, ms, ts, now);
		}
	}

#endif

	/* find the right place in the frames list, sorted by delivery time */
	frame = jb->tail;
	while (frame && frame->delivery > delivery) {
		frame = frame->prev;
	}
	
	/* Check if the new delivery time is not covered already by the chosen frame
	 * be tolerant (10ms) (iLBC from asterisk is coming 20/40/20/40/20 ms
	 * XXX: check if that 10ms tolerant does not brake statistics on various loss or delay samples */
	if (jb->force_resynch || (frame && (frame->delivery == delivery ||
			(delivery + 10 < frame->delivery + frame->ms) ||
		         (frame->next && (delivery + ms > frame->next->delivery)))))
	{
		/* TODO: Should we check for resynch here? Be careful to do not allow threshold smaller than
		   the size of the jb */
		
		/* should drop the frame, but let first resynch_jb() check if this is not a jump in ts, or
		   the force resynch flag was not set. */
		//if(debug) fprintf(stdout, "put: check if the new delivery time is not covered already by the chosen frame %d, delivery %d frame->delivery %d frame->ms %d ms %d frame->next->delivery %d\n",jb->force_resynch, delivery, frame->delivery, frame->ms, (frame->next) ? frame->next->delivery : 0);
		res = resynch_jb(jb, data, ms, ts, now);
		jb->force_resynch = 0;
		return res;
	}
	
	/* Reset the force resynch flag */
	jb->force_resynch = 0;
	
	/* Get a new frame */
	newframe = alloc_jb_frame(jb);
	newframe->data = data;
	newframe->ts = ts;
	newframe->ms = ms;
	newframe->delivery = delivery;

	
	/* and insert it right on place */
	if (frame) {
		next = frame->next;
		frame->next = newframe;
		if (next) {
			newframe->next = next;
			next->prev = newframe;
		} else {
			/* insert after the last frame - should update tail */
			jb->tail = newframe;
			newframe->next = NULL;
		}
		newframe->prev = frame;
		
		return FIXED_JB_OK;
	} else if (!jb->frames) {
		/* the frame list is empty or thats just the first frame ever */
		/* tail should also be NULL is that case */
		if(!(jb->tail == NULL)) {
			syslog(5 /*notice */, "JB ASSERT - fixed_jb_put - jb->tail == NULL");
			if(opt_enable_jitterbuffer_asserts) {
				ASSERT(jb->tail == NULL);
			}
			return FIXED_JB_ERROR;
		}
		jb->frames = jb->tail = newframe;
		newframe->next = NULL;
		newframe->prev = NULL;
		
		return FIXED_JB_OK;
	} else {
		/* insert on a first position - should update frames head */
		newframe->next = jb->frames;
		newframe->prev = NULL;
		jb->frames->prev = newframe;
		jb->frames = newframe;
		
		return FIXED_JB_OK;
	}
}


int fixed_jb_flush(struct fixed_jb *jb, struct fixed_jb_frame *frame)
{
	if (jb->frames) {
		get_jb_head(jb, frame);
		return 1;
	} else {
		return 0;
	}
}

int fixed_jb_get(struct fixed_jb *jb, struct fixed_jb_frame *frame, long now, long interpl)
{
	extern int opt_enable_jitterbuffer_asserts;
	if(!(now >= 0)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_get - now >= 0");
		if(opt_enable_jitterbuffer_asserts) {
			ASSERT(now >= 0);
		}
		return FIXED_JB_ERROR;
	}
	if(!(interpl >= 2)) {
		syslog(5 /*notice */, "JB ASSERT - fixed_jb_get - interpl >= 2");
		if(opt_enable_jitterbuffer_asserts) {
			ASSERT(interpl >= 2);
		}
		return FIXED_JB_ERROR;
	}
	
	if (now < jb->next_delivery) {
		/* too early for the next frame */
		return FIXED_JB_NOFRAME;
	}
	
	/* Is the jb empty? */
	if (!jb->frames) {
		/* should interpolate a frame */
		/* update next */
		jb->next_delivery += interpl;
	
		if(debug) fprintf(stdout, "empty jb!\n");
		return FIXED_JB_INTERP;
	}
	
	/* Isn't it too late for the first frame available in the jb? */
	if (now > jb->frames->delivery + jb->frames->ms) {
		/* yes - should drop this frame and update next to point the next frame (get_jb_head() does it) */
		get_jb_head(jb, frame);
		
		return FIXED_JB_DROP;
	}
	
	/* isn't it too early to play the first frame available?
	 */
	if (now  < jb->frames->delivery) {

		/* yes - should interpolate one frame */
		/* this can happen if sequence number is ok but timestamp in frame is bigger than previous. that comes from asterisk servers which generates its own sequence but timestamp not */
		if(debug) fprintf(stdout, "\tisn't it too early to play the first frame available? now(%ld) <  jb->frames->delivery (%ld)\n", now, jb->frames->delivery);
		/* update next */
		jb->next_delivery += interpl;
		
		return FIXED_JB_INTERP;
	}
	
	/* we have a frame for playing now (get_jb_head() updates next) */
	get_jb_head(jb, frame);
	
	return FIXED_JB_OK;
}


long fixed_jb_next(struct fixed_jb *jb)
{
	return jb->next_delivery;
}


int fixed_jb_remove(struct fixed_jb *jb, struct fixed_jb_frame *frameout)
{
	if (!jb->frames)
		return FIXED_JB_NOFRAME;
	
	get_jb_head(jb, frameout);
	
	return FIXED_JB_OK;
}
