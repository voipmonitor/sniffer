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

/*! Internal jb flags */
enum {
	JB_USE =                  (1 << 0),
	JB_TIMEBASE_INITIALIZED = (1 << 1),
	JB_CREATED =              (1 << 2)
};

/* Hooks for the abstract jb implementation */

/*! \brief Create */
typedef void * (*jb_create_impl)(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *channel);
/*! \brief Destroy */
typedef void (*jb_destroy_impl)(void *jb);
/*! \brief Put first frame */
typedef int (*jb_put_first_impl)(void *jb, struct ast_frame *fin, long now);
/*! \brief Put frame */
typedef int (*jb_put_impl)(void *jb, struct ast_frame *fin, long now);
/*! \brief Get frame for now */
typedef int (*jb_get_impl)(void *jb, struct ast_frame **fout, long now, long interpl);
/*! \brief Get next */
typedef long (*jb_next_impl)(void *jb);
/*! \brief Remove first frame */
typedef int (*jb_remove_impl)(void *jb, struct ast_frame **fout);
/*! \brief Force resynch */
typedef void (*jb_force_resynch_impl)(void *jb);
/*! \brief Empty and reset jb */
typedef void (*jb_empty_and_reset_impl)(void *jb);

/*!
 * \brief Jitterbuffer implementation private struct.
 */
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

//static int default_impl = 1;


/*! Abstract return codes */
enum {
	JB_IMPL_OK,
	JB_IMPL_DROP,
	JB_IMPL_INTERP,
	JB_IMPL_NOFRAME
};

static int debug = 0;

/* Translations between impl and abstract return codes */
static int fixed_to_abstract_code[] =
	{JB_IMPL_OK, JB_IMPL_DROP, JB_IMPL_INTERP, JB_IMPL_NOFRAME};
static int adaptive_to_abstract_code[] =
	{JB_IMPL_OK, JB_IMPL_NOFRAME, JB_IMPL_NOFRAME, JB_IMPL_INTERP, JB_IMPL_DROP, JB_IMPL_OK};

/* JB_GET actions (used only for the frames log) */
static char *jb_get_actions[] = {"Delivered", "Dropped", "Interpolated", "No"};

/*! \brief Macros for the frame log files */
#define printf(...) do { \
	if (jb->logfile) { \
		if(debug) fprintf(jb->logfile, __VA_ARGS__); \
		fflush(jb->logfile); \
	} \
} while (0)

//#define if(debug) fprintf(...) if (debug) { if(debug) fprintf(__VA_ARGS__); }


/* Internal utility functions */
static void jb_choose_impl(struct ast_channel *chan);
static void jb_get_and_deliver(struct ast_channel *chan, struct timeval *mynow);
static int create_jb(struct ast_channel *chan, struct ast_frame *first_frame, struct timeval *mynow);
static long get_now(struct ast_jb *jb, struct timeval *tv, struct timeval *mynow);


/* Interface ast jb functions impl */


static void jb_choose_impl(struct ast_channel *chan)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_conf *jbconf = &jb->conf;
	struct ast_jb_impl *test_impl;
	int i, avail_impl_count = sizeof(avail_impl) / sizeof(avail_impl[0]);
	
	//jb->impl = &avail_impl[default_impl];
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
	int c0_jb_timebase_initialized = ast_test_flag(jb0, JB_TIMEBASE_INITIALIZED);
	int c0_jb_created = ast_test_flag(jb0, JB_CREATED);
	int inuse = 0;

	/* Determine whether audio going to c0 needs a jitter buffer */
	ast_set_flag(jb0, JB_USE);
	if (!c0_jb_timebase_initialized) {
		//gettimeofday(&jb0->timebase, NULL);
		memcpy(&jb0->timebase, ts, sizeof(struct timeval));
		ast_set_flag(jb0, JB_TIMEBASE_INITIALIZED);
	}

	if (!c0_jb_created) {
		jb_choose_impl(c0);
	}

	inuse = 1;
	
	/* Determine whether audio going to c1 needs a jitter buffer */
	/*
	if (((!c1_wants_jitter && c0_creates_jitter) || (c1_force_jb && c0_creates_jitter)) && c1_jb_enabled) {
		ast_set_flag(jb1, JB_USE);
		if (!c1_jb_timebase_initialized) {
			if (c0_jb_timebase_initialized) {
				memcpy(&jb1->timebase, &jb0->timebase, sizeof(struct timeval));
			} else {
				gettimeofday(&jb1->timebase, NULL);
			}
			ast_set_flag(jb1, JB_TIMEBASE_INITIALIZED);
		}
		
		if (!c1_jb_created) {
			jb_choose_impl(c1);
		}

		inuse = 1;
	}
	*/

	return inuse;
}

int ast_jb_put(struct ast_channel *chan, struct ast_frame *f, struct timeval *mynow)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj = jb->jbobj;
	struct ast_frame *frr;
	long now = 0;
	
//	if (!ast_test_flag(jb, JB_USE))
//		return -1;

	if (f->frametype != AST_FRAME_VOICE) {
		if (f->frametype == AST_FRAME_DTMF && ast_test_flag(jb, JB_CREATED)) {
			if(debug) fprintf(stdout, "JB_PUT {now=%ld}: Received DTMF frame.\n", now);
                        /* this is causing drops if RAW data is recording. deactivate it. Hope it will not cause problems (tested on previously recorded DTMF pcap patterns and it is the same)
			//if(debug) fprintf(stdout, "JB_PUT {now=%ld}: Received DTMF frame. Force resynching jb...\n", now);
			if(ast_test_flag(jb, JB_CREATED)) {
				jbimpl->force_resync(jbobj);
			}
                        */
		}
		return -1;
	}

	if (chan->resync && f->marker) {
		if(debug) fprintf(stdout, "JB_PUT {now=%ld}: marker bit set, Force resynching jb...\n", now);
		if(ast_test_flag(jb, JB_CREATED)) {
			jbimpl->force_resync(jbobj);
		}
	}

	/* We consider an enabled jitterbuffer should receive frames with valid timing info. */

	if (f->len < 2 || f->ts < 0) {
		if(debug) fprintf(stdout, "%s recieved frame with invalid timing info: "
			"has_timing_info=%d, len=%ld, ts=%ld, src=%s\n",
			chan->name, ast_test_flag(f, AST_FRFLAG_HAS_TIMING_INFO), f->len, f->ts, f->src);
		return -1;
	}
	frr = ast_frdup(f);

	if (!frr) {
		if(debug) fprintf(stdout, "Failed to isolate frame for the jitterbuffer on channel '%s'\n", chan->name);
		return -1;
	}

	if (!ast_test_flag(jb, JB_CREATED)) {
		if (create_jb(chan, frr, mynow)) {
			ast_frfree(frr);
			/* Disable the jitterbuffer */
			ast_clear_flag(jb, JB_USE);
			return -1;
		}

		ast_set_flag(jb, JB_CREATED);
		return 0;
	} else {
		now = get_now(jb, NULL, mynow);
		if (jbimpl->put(jbobj, frr, now) != JB_IMPL_OK) {
			if(debug) fprintf(stdout, "JB_PUT {now=%ld}: Dropped frame with ts=%ld and len=%ld and seq=%d\n", now, frr->ts, frr->len, frr->seqno);
			ast_frfree(frr);
			/*return -1;*/
			/* TODO: Check this fix - should return 0 here, because the dropped frame shouldn't 
			   be delivered at all */
			return 0;
		}

		jb->next = jbimpl->next(jbobj);

		if(debug) fprintf(stdout, "JB_PUT {now=%ld}: Queued frame with ts=%ld and len=%ld and seq=%d\n", now, frr->ts, frr->len, frr->seqno);

		return 0;
	}
}


void ast_jb_get_and_deliver(struct ast_channel *c0, struct timeval *mynow)
{
	struct ast_jb *jb0 = &c0->jb;
	int c0_use_jb = ast_test_flag(jb0, JB_USE);
	int c0_jb_is_created = ast_test_flag(jb0, JB_CREATED);
	
	if (c0_use_jb && c0_jb_is_created)
		jb_get_and_deliver(c0, mynow);
	
}

void jb_fixed_flush_deliver(struct ast_channel *chan)
{
        struct ast_jb *jb = &chan->jb;
        struct ast_frame *f;
        struct fixed_jb_frame ff;
        short int stmp;

	if(!(struct fixed_jb*)jb->jbobj) {
		return;
	}

	while ( fixed_jb_flush((struct fixed_jb*)jb->jbobj, &ff)) {
		if(chan->rawstream || chan->fifofd) { 
			f = ff.data;
			//write frame to file
			stmp = (short int)f->datalen;
			if(chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM) {
				if(chan->rawstream)
					fwrite(&stmp, 1, sizeof(short int), chan->rawstream);   // write packet len
				if(chan->fifofd > 0)
					write(chan->fifofd, &stmp, sizeof(short int));   // write packet len
			}
			if(chan->rawstream)
				fwrite(f->data, 1, f->datalen, chan->rawstream);
			if(chan->fifofd > 0)
				write(chan->fifofd, f->data, f->datalen);
			if(chan->audiobuf)
				circbuf_write(chan->audiobuf,f->data, f->datalen);
			//save last frame
			memcpy(chan->lastbuf, f->data, f->datalen);
			chan->lastbuflen = f->datalen; 
			ast_frfree(f);
		}       
	}
}       

void save_empty_frame(struct ast_channel *chan) {
	if(chan->rawstream) {
		int i;
		short int zero = 0;
		int zero2 = 0;
		short int zero3 = 32767;
		//write frame to file
		if(chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM) {
			if(chan->codec == PAYLOAD_G723) {
				for(i = 1; (i * 30) <= chan->packetization; i++) {
					fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->fifofd > 0)
						write(chan->fifofd, &zero, sizeof(short int));   // write packet len
					if(chan->audiobuf)
						circbuf_write(chan->audiobuf,(const char*)(&zero), sizeof(short int));
				}
			} else if(chan->codec == PAYLOAD_ISAC16) {
				for(i = 1; (i * 30) <= chan->packetization / 2; i++) {
					fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->fifofd > 0)
						write(chan->fifofd, &zero, sizeof(short int));   // write packet len
					if(chan->audiobuf)
						circbuf_write(chan->audiobuf,(const char*)(&zero), sizeof(short int));
				}
			} else if(chan->codec == PAYLOAD_ISAC32) {
				for(i = 1; (i * 30) <= chan->packetization / 4; i++) {
					fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->fifofd > 0)
						write(chan->fifofd, &zero, sizeof(short int));   // write packet len
					if(chan->audiobuf)
						circbuf_write(chan->audiobuf,(const char*)(&zero), sizeof(short int));
				}
			} else if(chan->codec == PAYLOAD_SILK16) {
				for(i = 1; (i * 20) <= chan->packetization / 2; i++) {
					fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->fifofd > 0)
						write(chan->fifofd, &zero, sizeof(short int));   // write packet len
					if(chan->audiobuf)
						circbuf_write(chan->audiobuf,(const char*)(&zero), sizeof(short int));
				}
			} else {
				for(i = 1; (i * 20) <= chan->packetization ; i++) {
					fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->fifofd > 0)
						write(chan->fifofd, &zero, sizeof(short int));   // write packet len
					if(chan->audiobuf)
						circbuf_write(chan->audiobuf,(const char*)(&zero), sizeof(short int));
				}
			}
		} else {
			// write previouse frame (better than zero frame), but only once
			if(chan->lastbuflen) {
				fwrite(chan->lastbuf, 1, chan->lastbuflen, chan->rawstream);
				if(chan->fifofd > 0)
					write(chan->fifofd, chan->lastbuf, chan->lastbuflen);   // write packet len
				if(chan->audiobuf)
					circbuf_write(chan->audiobuf,chan->lastbuf, chan->lastbuflen);
				chan->lastbuflen = 0;
			} else {
				// write empty frame
				for(i = 0; i < chan->last_datalen / 2; i++) {
					fwrite(&zero3, 2, 1, chan->rawstream);
					//fputc(0, chan->rawstream);
					if(chan->fifofd > 0)
						write(chan->fifofd, &zero2, sizeof(char));   // write packet len
					if(chan->audiobuf)
						circbuf_write(chan->audiobuf,(const char*)(&zero2), sizeof(char));
				}
			}
		}
	}
}

static void jb_get_and_deliver(struct ast_channel *chan, struct timeval *mynow)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj = jb->jbobj;
	//struct ast_frame *f, finterp = { .frametype = AST_FRAME_VOICE, };
	struct ast_frame *f;
	long now;
	int interpolation_len, res;
	short int stmp;
	int res2;

	now = get_now(jb, NULL, mynow);
	jb->next = jbimpl->next(jbobj);
	if (now < jb->next) {
		// here we are buffering frames 
		if(debug) fprintf(stdout, "\tJB_GET {now=%ld}: now < next=%ld (still buffering)\n", now, jb->next);
		save_empty_frame(chan);
		return;
	}
	
	while (now >= jb->next) {
		//interpolation_len = ast_codec_interp_len(jb->last_format);
		interpolation_len = chan->packetization;
		
		res = jbimpl->get(jbobj, &f, now, interpolation_len);
	
		switch(res) {
		case JB_IMPL_OK:
			if(f->skip) {
				save_empty_frame(chan);
				break;
			}	
			/* deliver the frame */
			//ast_write(chan, f);
			if((chan->rawstream || chan->fifofd || chan->audiobuf) && f->data && f->datalen > 0) {
				//write frame to file
				stmp = (short int)f->datalen;
				if(chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM) {
					if(chan->rawstream)
						fwrite(&stmp, 1, sizeof(short int), chan->rawstream);   // write packet len
					if(chan->fifofd > 0)
						write(chan->fifofd, &stmp, sizeof(short int));   // write packet len
				}
				if(chan->rawstream)
					fwrite(f->data, 1, f->datalen, chan->rawstream);
				if(chan->fifofd > 0) {
					res2 = write(chan->fifofd, f->data, f->datalen);
					//fprintf(stdout, "WRITING! fd[%d] size[%d]\n", chan->fifofd, res2);
				}
				if(chan->audiobuf) {
					circbuf_write(chan->audiobuf, f->data, f->datalen);
				}
				//save last frame
				memcpy(chan->lastbuf, f->data, f->datalen);
				chan->lastbuflen = f->datalen;
			}
			if(debug) fprintf(stdout, "\tJB_GET {now=%ld}: %s frame with ts=%ld and len=%ld and seq=%d\n", now, jb_get_actions[res], f->ts, f->len, f->seqno);
			/* if frame is marked do not put previous interpolated frames to statistics 
			 * also if there is no seqno gaps between frames and time differs 
			 * and also if there was dtmf last time
			 * */
			if( !(((f->seqno - chan->last_seqno) == 1) && (abs(f->ts - chan->last_ms) > (chan->packetization)))
				&& !f->marker && chan->last_loss_burst > 0 && chan->last_loss_burst < 1024
				&& f->lastframetype == AST_FRAME_VOICE // if the lastframetype was no frame voice(for example dtmf), do not count packet loss 
				) {
				
				if(debug) fprintf(stdout, "\tSAVING chan->loss[%d] packetization[%d]\n", chan->last_loss_burst, chan->packetization);
				chan->loss[chan->last_loss_burst]++;
			}
			chan->last_loss_burst = 0;
			chan->last_seqno = f->seqno;
			chan->last_ms = f->ts;
			ast_frfree(f);
			break;
		case JB_IMPL_DROP:
			save_empty_frame(chan);
			if(debug) fprintf(stdout, "\tJB_GET {now=%ld}: %s frame with ts=%ld and len=%ld seq=%d\n", now, jb_get_actions[res], f->ts, f->len, f->seqno);
			ast_frfree(f);
			chan->last_loss_burst++;
			break;
		case JB_IMPL_INTERP:
			/* interpolate a frame */
			/* deliver the interpolated frame */
			save_empty_frame(chan);
			//ast_write(chan, f);
			if(debug) fprintf(stdout, "\tJB_GET {now=%ld}: Interpolated frame with len=%d\n", now, interpolation_len);
			// if marker bit, reset counter
			chan->last_loss_burst++;
			break;
		case JB_IMPL_NOFRAME:
			save_empty_frame(chan);
			if(debug) fprintf(stdout, "JB_IMPL_NOFRAME is retuned from the %s jb when now=%ld >= next=%ld, jbnext=%ld!\n", jbimpl->name, now, jb->next, jbimpl->next(jbobj));
			if(debug) fprintf(stdout, "\tJB_GET {now=%ld}: No frame for now!?\n", now);
			chan->last_loss_burst++;
			return;
		default:
			if(debug) fprintf(stdout, "This should never happen!\n");
			ast_assert("JB type unknown" == NULL);
			break;
		}
		
		jb->next = jbimpl->next(jbobj);
	}
}


static int create_jb(struct ast_channel *chan, struct ast_frame *frr, struct timeval *mynow)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_conf *jbconf = &jb->conf;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj;
	struct ast_channel *bridged = NULL;
	long now;
	char logfile_pathname[20 + AST_JB_IMPL_NAME_SIZE + 2*AST_CHANNEL_NAME + 1];
	char name1[AST_CHANNEL_NAME], name2[AST_CHANNEL_NAME], *tmp;
	int res;

	jbobj = jb->jbobj = jbimpl->create(jbconf, jbconf->resync_threshold, chan);
	if (!jbobj) {
		if(debug) fprintf(stdout, "Failed to create jitterbuffer on channel '%s'\n", chan->name);
		return -1;
	}

	now = get_now(jb, NULL, mynow);
	res = jbimpl->put_first(jbobj, frr, now);
	
	/* The result of putting the first frame should not differ from OK. However, its possible
	   some implementations (i.e. adaptive's when resynch_threshold is specified) to drop it. */
	if (res != JB_IMPL_OK) {
		if(debug) fprintf(stdout, "Failed to put first frame in the jitterbuffer on channel '%s'\n", chan->name);
		/*
		jbimpl->destroy(jbobj);
		return -1;
		*/
	}
	
	/* Init next */
	jb->next = jbimpl->next(jbobj);
	
	/* Init last format for a first time. */
	jb->last_format = frr->subclass;
	
	/* Create a frame log file */
	if (ast_test_flag(jbconf, AST_JB_LOG)) {
		snprintf(name2, sizeof(name2), "%s", chan->name);
		tmp = strchr(name2, '/');
		if (tmp)
			*tmp = '#';
		
		// festr: bridged = ast_bridged_channel(chan);
		/* We should always have bridged chan if a jitterbuffer is in use */
		ast_assert(bridged != NULL);

		snprintf(name1, sizeof(name1), "%s", bridged->name);
		tmp = strchr(name1, '/');
		if (tmp)
			*tmp = '#';
		
		snprintf(logfile_pathname, sizeof(logfile_pathname),
			"/tmp/ast_%s_jb_%s--%s.log", jbimpl->name, name1, name2);
		jb->logfile = fopen(logfile_pathname, "w+b");
		
		if (!jb->logfile)
			if(debug) fprintf(stdout, "Failed to create frame log file with pathname '%s'\n", logfile_pathname);
		
		if (res == JB_IMPL_OK) {
			if(debug) fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Queued frame with ts=%ld and len=%ld\n",
				now, frr->ts, frr->len);
		} else {
			if(debug) fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Dropped frame with ts=%ld and len=%ld seq=%d\n",
				now, frr->ts, frr->len, frr->seqno);
		}
	}

	//if (option_verbose > 2) 
		if(debug) fprintf(stdout, "%s jitterbuffer created on channel %s\n", jbimpl->name, chan->name);
	
	/* Free the frame if it has not been queued in the jb */
	if (res != JB_IMPL_OK)
		ast_frfree(frr);
	
	return 0;
}


void ast_jb_destroy(struct ast_channel *chan)
{
	struct ast_jb *jb = &chan->jb;
	struct ast_jb_impl *jbimpl = jb->impl;
	void *jbobj = jb->jbobj;
	struct ast_frame *f;

	if (jb->logfile) {
		fclose(jb->logfile);
		jb->logfile = NULL;
	}
	
	if (ast_test_flag(jb, JB_CREATED)) {
		/* Remove and free all frames still queued in jb */
		while (jbimpl->remove(jbobj, &f) == JB_IMPL_OK) {
			ast_frfree(f);
		}
		
		jbimpl->destroy(jbobj);
		jb->jbobj = NULL;
		
		ast_clear_flag(jb, JB_CREATED);

			if(debug) fprintf(stdout, "%s jitterbuffer destroyed on channel %s\n", jbimpl->name, chan->name);
	}
}


static long get_now(struct ast_jb *jb, struct timeval *tv, struct timeval *mynow)
{
	struct timeval now;

	if (!tv) {
		tv = &now;
		memcpy(tv, mynow, sizeof(struct timeval));
		//gettimeofday(tv, NULL);
	}

	return ast_tvdiff_ms(*tv, jb->timebase);
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
	int c0_use_jb = ast_test_flag(jb0, JB_USE);
	int c0_jb_is_created = ast_test_flag(jb0, JB_CREATED);

	if (c0_use_jb && c0_jb_is_created && jb0->impl->empty_and_reset) {
		jb0->impl->empty_and_reset(jb0->jbobj);
	}
}

/* Implementation functions */

/* fixed */
static void * jb_create_fixed(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *chan)
{
	struct fixed_jb_conf conf;

	//conf.jbsize = general_config->max_size;
	//conf.resync_threshold = resynch_threshold;
	conf.jbsize = chan->jitter_max;
	conf.resync_threshold = chan->jitter_resync_threshold;

	return fixed_jb_new(&conf);
}

static void jb_destroy_fixed(void *jb)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	
	/* destroy the jb */
	fixed_jb_destroy(fixedjb);
}


static int jb_put_first_fixed(void *jb, struct ast_frame *fin, long now)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	int res;
	
	res = fixed_jb_put_first(fixedjb, fin, fin->len, fin->ts, now);
	
	return fixed_to_abstract_code[res];
}


static int jb_put_fixed(void *jb, struct ast_frame *fin, long now)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	int res;
	
	res = fixed_jb_put(fixedjb, fin, fin->len, fin->ts, now);
	
	return fixed_to_abstract_code[res];
}


static int jb_get_fixed(void *jb, struct ast_frame **fout, long now, long interpl)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	struct fixed_jb_frame frame;
	int res;
	
	res = fixed_jb_get(fixedjb, &frame, now, interpl);
	*fout = frame.data;
	
	return fixed_to_abstract_code[res];
}


static long jb_next_fixed(void *jb)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	
	return fixed_jb_next(fixedjb);
}


static int jb_remove_fixed(void *jb, struct ast_frame **fout)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	struct fixed_jb_frame frame;
	int res;
	
	res = fixed_jb_remove(fixedjb, &frame);
	*fout = frame.data;
	
	return fixed_to_abstract_code[res];
}


static void jb_force_resynch_fixed(void *jb)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	
	fixed_jb_set_force_resynch(fixedjb);
}

static void jb_empty_and_reset_fixed(void *jb)
{
	struct fixed_jb *fixedjb = jb;
	struct fixed_jb_frame f;

	while (fixed_jb_remove(fixedjb, &f) == FIXED_JB_OK) {
		ast_frfree(f.data);
	}
}

/* adaptive */

static void *jb_create_adaptive(struct ast_jb_conf *general_config, long resynch_threshold, struct ast_channel *chan)
{
	jb_conf jbconf;
	jitterbuf *adaptivejb;

	adaptivejb = jb_new();
	if (adaptivejb) {
		//jbconf.max_jitterbuf = general_config->max_size;
		//jbconf.resync_threshold = general_config->resync_threshold;
		//jbconf.max_contig_interp = 10;

		jbconf.max_jitterbuf = chan->jitter_max;
		jbconf.resync_threshold = chan->jitter_resync_threshold;
		jbconf.max_contig_interp = 10;
		jb_setconf(adaptivejb, &jbconf);
	}
	
	return adaptivejb;
}


static void jb_destroy_adaptive(void *jb)
{
	jitterbuf *adaptivejb = (jitterbuf *) jb;
	
	jb_destroy(adaptivejb);
}


static int jb_put_first_adaptive(void *jb, struct ast_frame *fin, long now)
{
	return jb_put_adaptive(jb, fin, now);
}


static int jb_put_adaptive(void *jb, struct ast_frame *fin, long now)
{
	jitterbuf *adaptivejb = (jitterbuf *) jb;
	int res;
	
	res = jb_put(adaptivejb, fin, JB_TYPE_VOICE, fin->len, fin->ts, now);
	
	return adaptive_to_abstract_code[res];
}


static int jb_get_adaptive(void *jb, struct ast_frame **fout, long now, long interpl)
{
	jitterbuf *adaptivejb = (jitterbuf *) jb;
	jb_frame frame;
	int res;
	
	res = jb_get(adaptivejb, &frame, now, interpl);
	*fout = frame.data;
	
	return adaptive_to_abstract_code[res];
}


static long jb_next_adaptive(void *jb)
{
	jitterbuf *adaptivejb = (jitterbuf *) jb;
	
	return jb_next(adaptivejb);
}


static int jb_remove_adaptive(void *jb, struct ast_frame **fout)
{
	jitterbuf *adaptivejb = (jitterbuf *) jb;
	jb_frame frame;
	int res;
	
	res = jb_getall(adaptivejb, &frame);
	*fout = frame.data;
	
	return adaptive_to_abstract_code[res];
}


static void jb_force_resynch_adaptive(void *jb)
{
}

static void jb_empty_and_reset_adaptive(void *jb)
{
	jitterbuf *adaptivejb = jb;
	jb_frame f;

	while (jb_getall(adaptivejb, &f) == JB_OK) {
		ast_frfree(f.data);
	}

	jb_reset(adaptivejb);
}
