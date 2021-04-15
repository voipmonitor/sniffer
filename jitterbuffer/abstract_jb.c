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


extern struct sVerbose sverb;

/*! \brief On and Off plc*/
extern int opt_disableplc ;

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

extern void fifobuff_add(void *fifo_buff, const char *data, unsigned int datalen);
//extern void test_raw(const char *descr, const char *data, unsigned int datalen);
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

//static int default_impl = 1;


/*! Abstract return codes */
enum {
	JB_IMPL_OK,
	JB_IMPL_DROP,
	JB_IMPL_INTERP,
	JB_IMPL_NOFRAME,
	JB_IMPL_ERROR
};

/* Translations between impl and abstract return codes */
static int fixed_to_abstract_code[] =
	{JB_IMPL_OK, JB_IMPL_DROP, JB_IMPL_INTERP, JB_IMPL_NOFRAME, JB_IMPL_ERROR};
static int adaptive_to_abstract_code[] =
	{JB_IMPL_OK, JB_IMPL_NOFRAME, JB_IMPL_NOFRAME, JB_IMPL_INTERP, JB_IMPL_DROP, JB_IMPL_OK};

/* JB_GET actions (used only for the frames log) */
static char *jb_get_actions[] = {"Delivered", "Dropped", "Interpolated", "No"};

/*! \brief Macros for the frame log files */
#define printf(...) do { \
	if (jb->logfile) { \
		if(sverb.jitter) fprintf(jb->logfile, __VA_ARGS__); \
		fflush(jb->logfile); \
	} \
} while (0)

//#define if(sverb.jitter) fprintf(...) if (sverb.jitter) { if(sverb.jitter) fprintf(__VA_ARGS__); }


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
	int rslt;
	
//	if (!ast_test_flag(jb, JB_USE))
//		return -1;

	if (f->frametype != AST_FRAME_VOICE) {
		if (f->frametype == AST_FRAME_DTMF && ast_test_flag(jb, JB_CREATED)) {
			if(sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Received DTMF frame.\n", jb, now);
                        /* this is causing drops if RAW data is recording. deactivate it. Hope it will not cause problems (tested on previously recorded DTMF pcap patterns and it is the same)
			//if(sverb.jitter) fprintf(stdout, "JB_PUT {now=%ld}: Received DTMF frame. Force resynching jb...\n", now);
			if(ast_test_flag(jb, JB_CREATED)) {
				jbimpl->force_resync(jbobj);
			}
                        */
			chan->prev_frame_is_dtmf = 1;
		}
		if(ast_test_flag(jb, JB_CREATED)) {
			return -1;
		}
	}

	if (chan->resync && f->marker) {
		if(sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: marker bit set, Force resynching jb...\n", jb, now);
		if(ast_test_flag(jb, JB_CREATED)) {
			jbimpl->force_resync(jbobj);
		}
	}

	/* We consider an enabled jitterbuffer should receive frames with valid timing info. */

	if (f->len < 2 || f->ts < 0) {
		if(sverb.jitter) fprintf(stdout, "recieved frame with invalid timing info: "
			"has_timing_info=%d, len=%ld, ts=%ld, src=%s\n",
			ast_test_flag(f, AST_FRFLAG_HAS_TIMING_INFO), f->len, f->ts, f->src);
		return -1;
	}
	frr = ast_frdup(f);

	if (!frr) {
		if(sverb.jitter) fprintf(stdout, "Failed to isolate frame for the jitterbuffer on channel\n");
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
		//fprintf(stdout, "mynow [%u][%u], tb [%u][%u] tvdiff[%u] seq[%u]\n", mynow->tv_sec, mynow->tv_usec, jb->timebase.tv_sec, jb->timebase.tv_usec, ast_tvdiff_ms(*mynow, jb->timebase), frr->seqno);
		now = get_now(jb, NULL, mynow);
		rslt = jbimpl->put(jbobj, frr, now);
		if(frr->frametype != AST_FRAME_DTMF) {
			chan->prev_frame_is_dtmf = 0;
		}
		if (rslt != JB_IMPL_OK) {
			if(sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Dropped frame with ts=%ld and len=%ld and seq=%d\n", jb, now, frr->ts, frr->len, frr->seqno);
			ast_frfree(frr);
			/*return -1;*/
			/* TODO: Check this fix - should return 0 here, because the dropped frame shouldn't 
			   be delivered at all */
			return 0;
		}

		jb->next = jbimpl->next(jbobj);

		if(sverb.jitter) fprintf(stdout, "JB_PUT[%p] {now=%ld}: Queued frame with ts=%ld and len=%ld and seq=%d\n", jb, now, frr->ts, frr->len, frr->seqno);

		return 0;
	}
}


void ast_jb_get_and_deliver(struct ast_channel *c0, struct timeval *mynow)
{
	struct ast_jb *jb0 = &c0->jb;
	int c0_use_jb = ast_test_flag(jb0, JB_USE);
	int c0_jb_is_created = ast_test_flag(jb0, JB_CREATED);
	
	if (c0_use_jb && c0_jb_is_created) {
		if(mynow->tv_sec < c0->jb.timebase.tv_sec ||
		   (mynow->tv_sec == c0->jb.timebase.tv_sec &&
		    mynow->tv_usec < c0->jb.timebase.tv_usec)) {
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
        struct fixed_jb_frame ff;
        short int stmp;

	if(!(struct fixed_jb*)jb->jbobj) {
		return;
	}

	while ( fixed_jb_flush((struct fixed_jb*)jb->jbobj, &ff)) {
		f = ff.data;
		if(!f->ignore && (chan->rawstream || chan->audiobuf) && (chan->codec != 13 && chan->codec != 19)) { 
			//write frame to file
			stmp = (short int)f->datalen;
			if(CODEC_LEN && (chan->codec == PAYLOAD_G72218 || chan->codec == PAYLOAD_G722112 || chan->codec == PAYLOAD_G722116 || chan->codec == PAYLOAD_G722124 || chan->codec == PAYLOAD_G722132 || chan->codec == PAYLOAD_G722148 || chan->codec == PAYLOAD_OPUS8 || chan->codec == PAYLOAD_OPUS12 || chan->codec == PAYLOAD_OPUS16 || chan->codec == PAYLOAD_OPUS24 || chan->codec == PAYLOAD_OPUS48 || chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM || chan->codec == PAYLOAD_AMR || chan->codec == PAYLOAD_AMRWB)) {
				if(chan->rawstream) {
					fwrite(&stmp, 1, sizeof(short int), chan->rawstream);   // write packet len
				}
			}
			if(chan->rawstream)
				fwrite(f->data, 1, f->datalen, chan->rawstream);
			if(chan->audiobuf)
				fifobuff_add(chan->audiobuf, f->data, f->datalen);
			//test_raw("flush", f->data, f->datalen);
			//save last frame
			if(!chan->lastbuf) {
				chan->lastbufsize = f->datalen > 1600 ? f->datalen : 1600;
				chan->lastbuf = (char*)ast_malloc(chan->lastbufsize);
			} else if(chan->lastbufsize < f->datalen) {
				ast_free(chan->lastbuf);
				chan->lastbufsize = f->datalen;
				chan->lastbuf = (char*)ast_malloc(chan->lastbufsize);
			}
			memcpy(chan->lastbuf, f->data, f->datalen);
			chan->lastbuflen = f->datalen; 
		}       
		if(!f->ignore && chan->enable_save_energylevels && chan->rtp_stream && (chan->codec == 0 || chan->codec == 8)) {
			save_rtp_energylevels(chan->rtp_stream, f->data, f->datalen, chan->codec);
			chan->last_datalen_energylevels = f->datalen;
		}
		ast_frfree(f);
	}
}       

void save_empty_frame(struct ast_channel *chan) {
	if((chan->rawstream || chan->audiobuf) && (chan->codec != 13 && chan->codec != 19)) {
		int i;
		//write frame to file
		if(chan->codec == PAYLOAD_G72218 || chan->codec == PAYLOAD_G722112 || chan->codec == PAYLOAD_G722116 || chan->codec == PAYLOAD_G722124 || chan->codec == PAYLOAD_G722132 || chan->codec == PAYLOAD_G722148 || 
		   chan->codec == PAYLOAD_OPUS8 || chan->codec == PAYLOAD_OPUS12 || chan->codec == PAYLOAD_OPUS16 || chan->codec == PAYLOAD_OPUS24 || chan->codec == PAYLOAD_OPUS48 || 
		   chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || 
		   chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || 
		   chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM || chan->codec == PAYLOAD_AMR || chan->codec == PAYLOAD_AMRWB) {
			if(chan->codec == PAYLOAD_G723) {
				short int zero = 0;
				for(i = 1; (i * 30) <= chan->packetization; i++) {
					if(chan->rawstream)
						fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->audiobuf)
						fifobuff_add(chan->audiobuf,(const char*)(&zero), sizeof(short int));
					//test_raw("empty frame", (const char*)(&zero), sizeof(short int));
				}
			} else if(chan->codec == PAYLOAD_G729) {
				short int zero = 0;
				for(i = 1; (i * 10) <= chan->packetization; i++) {
					if(chan->rawstream)
						fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->audiobuf)
						fifobuff_add(chan->audiobuf,(const char*)(&zero), sizeof(short int));
					//test_raw("empty frame", (const char*)(&zero), sizeof(short int));
				}
			} else {
				short int zero = 0;
				for(i = 1; (i * 20) <= chan->packetization ; i++) {
					if(chan->rawstream)
						fwrite(&zero, 1, sizeof(short int), chan->rawstream);   // write zero packet
					if(chan->audiobuf)
						fifobuff_add(chan->audiobuf,(const char*)(&zero), sizeof(short int));
					//test_raw("empty frame", (const char*)(&zero), sizeof(short int));
				}
			}
		} else {
			// write previouse frame (better than zero frame), but only once
			if(chan->lastbuflen && opt_disableplc == 0) {
				if(chan->rawstream)
					fwrite(chan->lastbuf, 1, chan->lastbuflen, chan->rawstream);
				if(chan->audiobuf)
					fifobuff_add(chan->audiobuf,chan->lastbuf, chan->lastbuflen);
				//test_raw("empty frame", chan->lastbuf, chan->lastbuflen);
				chan->lastbuflen = 0;
			} else {
				// write empty frame
				if(chan->codec == PAYLOAD_PCMA || chan->codec == PAYLOAD_PCMU) {
					unsigned char zero = chan->codec == PAYLOAD_PCMA ? 213 : 255;
					for(i = 0; i < chan->last_datalen; i++) {
						if(chan->rawstream)
							fwrite(&zero, 1, 1, chan->rawstream);
						if(chan->audiobuf)
							fifobuff_add(chan->audiobuf,(const char*)(&zero), sizeof(char));
						//test_raw("empty frame", (const char*)(&zero), sizeof(char));
					}
				} else {
					unsigned short int zero = chan->codec == PAYLOAD_G722 ? 65535 : 32767;
					short int zero_audiobuff = 0;
					for(i = 0; i < chan->last_datalen / 2; i++) {
						if(chan->rawstream)
							fwrite(&zero, 2, 1, chan->rawstream);
						if(chan->audiobuf)
							fifobuff_add(chan->audiobuf,(const char*)(&zero_audiobuff), sizeof(char));
						//test_raw("empty frame", (const char*)(&zero_audiobuff), sizeof(char));
					}
				}
			}
		}
	}
	if(chan->enable_save_energylevels && chan->rtp_stream && (chan->codec == 0 || chan->codec == 8) &&
	   (chan->last_datalen_energylevels > 0 || chan->last_datalen > 0)) {
		save_rtp_energylevels(chan->rtp_stream, NULL, 0, chan->codec);
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
	//int res2;

	now = get_now(jb, NULL, mynow);
	jb->next = jbimpl->next(jbobj);
	//if jb-next return JB_LONGMAX it means the buffer is empty 
	//if (now < jb->next && jb->next != JB_LONGMAX) {

	if (jb->next == JB_LONGMAX) {
		//adaptive jitterbuffer is empty - interpolate frame 
		save_empty_frame(chan);
		interpolation_len = chan->packetization;
		if(sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld next=%ld}: Interpolated frame with len=%d\n", jb, now, jb->next, interpolation_len);
		chan->last_loss_burst++;
		return;
	} else if (now < jb->next ) {
		// here we are buffering frames 
		if(sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: now < next=%ld (still buffering)\n", jb, now, jb->next);
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
				if(sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: Skip frame\n", jb, now);
				ast_frfree(f);
				break;
			}	
			if(f->ignore) {
				break;
			}
			/* deliver the frame */
			if((chan->rawstream || chan->audiobuf) && f->data && f->datalen > 0 && (chan->codec != 13 && chan->codec != 19)) {
				//write frame to file
				stmp = (short int)f->datalen;
				if(chan->codec == PAYLOAD_G72218 || chan->codec == PAYLOAD_G722112 || chan->codec == PAYLOAD_G722116 || chan->codec == PAYLOAD_G722124 || chan->codec == PAYLOAD_G722132 || chan->codec == PAYLOAD_G722148 || chan->codec == PAYLOAD_OPUS8 || chan->codec == PAYLOAD_OPUS12 || chan->codec == PAYLOAD_OPUS16 || chan->codec == PAYLOAD_OPUS24 || chan->codec == PAYLOAD_OPUS48 || chan->codec == PAYLOAD_ISAC16 || chan->codec == PAYLOAD_ISAC32 || chan->codec == PAYLOAD_SILK || chan->codec == PAYLOAD_SILK8 || chan->codec == PAYLOAD_SILK12 || chan->codec == PAYLOAD_SILK16 || chan->codec == PAYLOAD_SILK24 || chan->codec == PAYLOAD_SPEEX || chan->codec == PAYLOAD_G723 || chan->codec == PAYLOAD_G729 || chan->codec == PAYLOAD_GSM || chan->codec == PAYLOAD_AMR || chan->codec == PAYLOAD_AMRWB) {
					if(chan->rawstream) {
						fwrite(&stmp, 1, sizeof(short int), chan->rawstream);   // write packet len
					}
				}
				if(chan->rawstream)
					fwrite(f->data, 1, f->datalen, chan->rawstream);
				if(chan->audiobuf) {
					fifobuff_add(chan->audiobuf, f->data, f->datalen);
				}
				//test_raw("get", f->data, f->datalen);
				//save last frame
				if(!chan->lastbuf) {
					chan->lastbufsize = f->datalen > 1600 ? f->datalen : 1600;
					chan->lastbuf = (char*)ast_malloc(chan->lastbufsize);
				} else if(chan->lastbufsize < f->datalen) {
					ast_free(chan->lastbuf);
					chan->lastbufsize = f->datalen;
					chan->lastbuf = (char*)ast_malloc(chan->lastbufsize);
				}
				memcpy(chan->lastbuf, f->data, f->datalen);
				chan->lastbuflen = f->datalen;
			}
			if(chan->enable_save_energylevels && chan->rtp_stream && f->data && f->datalen > 0 && (chan->codec == 0 || chan->codec == 8)) {
				save_rtp_energylevels(chan->rtp_stream, f->data, f->datalen, chan->codec);
				chan->last_datalen_energylevels = f->datalen;
			}
			if(sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: %s frame with ts=%ld and len=%ld and seq=%d\n", jb, now, jb_get_actions[res], f->ts, f->len, f->seqno);
			/* if frame is marked do not put previous interpolated frames to statistics 
			 * also if there is no seqno gaps between frames and time differs 
			 * and also if there was dtmf last time
			 * */
			if( !(((f->seqno - chan->last_seqno) == 1) && (abs(f->ts - chan->last_ms) > (chan->packetization)))
				&& !f->marker && chan->last_loss_burst > 0 && chan->last_loss_burst < 1024
				&& f->lastframetype == AST_FRAME_VOICE // if the lastframetype was no frame voice(for example dtmf), do not count packet loss 
				//&& !(chan->codec == PAYLOAD_AMR && f->datalen2 <= 7) // if AMR frame is VAD frame do not count interpolated frames
			//	&& !(chan->codec == PAYLOAD_G729 && f->datalen2 <= 12) // if g729 frame is CNG frame do not count interpolated frames
				) {
				
				while(chan->last_loss_burst > 128) {
					chan->loss[127]++;
					if(sverb.jitter) fprintf(stdout, "\tSAVING chan->loss[128] packetization[%d]\n", chan->packetization);
					chan->last_loss_burst -= 128;
				}
				chan->loss[chan->last_loss_burst]++;
				if(sverb.jitter) fprintf(stdout, "\tSAVING chan->loss[%d] = %d packetization[%d]\n", chan->last_loss_burst, chan->loss[chan->last_loss_burst], chan->packetization);
			}
			chan->last_loss_burst = 0;
			chan->last_seqno = f->seqno;
			chan->last_ms = f->ts;
			ast_frfree(f);
			break;
		case JB_IMPL_DROP:
			save_empty_frame(chan);
			if(sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: %s frame with ts=%ld and len=%ld seq=%d\n", jb, now, jb_get_actions[res], f->ts, f->len, f->seqno);
			ast_frfree(f);
			chan->last_loss_burst++;
			break;
		case JB_IMPL_INTERP:
			/* interpolate a frame */
			save_empty_frame(chan);
			if(sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: Interpolated frame with len=%d\n", jb, now, interpolation_len);
			chan->last_loss_burst++;
			break;
		case JB_IMPL_NOFRAME:
			save_empty_frame(chan);
			if(sverb.jitter) fprintf(stdout, "JB_IMPL_NOFRAME is retuned from the %s jb when now=%ld >= next=%ld, jbnext=%ld!\n", jbimpl->name, now, jb->next, jbimpl->next(jbobj));
			if(sverb.jitter) fprintf(stdout, "\tJB_GET[%p] {now=%ld}: No frame for now!?\n", jb, now);
			chan->last_loss_burst++;
			return;
		case JB_IMPL_ERROR:
			return;
		default:
			if(sverb.jitter) fprintf(stdout, "This should never happen!\n");
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
	long now;
	int res;

	jbobj = jb->jbobj = jbimpl->create(jbconf, jbconf->resync_threshold, chan);
	if (!jbobj) {
		if(sverb.jitter) fprintf(stdout, "Failed to create jitterbuffer on channel\n");
		return -1;
	}

	now = get_now(jb, NULL, mynow);
	res = jbimpl->put_first(jbobj, frr, now);
	
	/* The result of putting the first frame should not differ from OK. However, its possible
	   some implementations (i.e. adaptive's when resynch_threshold is specified) to drop it. */
	if (res != JB_IMPL_OK) {
		if(sverb.jitter) fprintf(stdout, "Failed to put first frame in the jitterbuffer on channel\n");
		/*
		jbimpl->destroy(jbobj);
		return -1;
		*/
	}
	
	/* Init next */
	jb->next = jbimpl->next(jbobj);
	
	/* Init last format for a first time. */
	jb->last_format = frr->subclass;
	
	if (ast_test_flag(jbconf, AST_JB_LOG)) {
		if (res == JB_IMPL_OK) {
			if(sverb.jitter) fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Queued frame with ts=%ld and len=%ld\n",
				now, frr->ts, frr->len);
		} else {
			if(sverb.jitter) fprintf(stdout, "JB_PUT_FIRST {now=%ld}: Dropped frame with ts=%ld and len=%ld seq=%d\n",
				now, frr->ts, frr->len, frr->seqno);
		}
	}

	//if (option_verbose > 2) 
		if(sverb.jitter) fprintf(stdout, "%s jitterbuffer[%p] created on channel\n", jbimpl->name, jb);
	
	/* Free the frame if it has not been queued in the jb */
	if (res != JB_IMPL_OK)
		ast_frfree(frr);
	
	return 0;
}


void ast_jb_destroy(struct ast_channel *chan)
{
	if(chan->lastbuf) {
		ast_free(chan->lastbuf);
		chan->lastbuf = NULL;
		chan->lastbufsize = 0;
		chan->lastbuflen = 0;
		chan->last_datalen_energylevels = 0;
	}
	
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

			if(sverb.jitter) fprintf(stdout, "%s jitterbuffer destroyed on channel\n", jbimpl->name);
	}
	ast_clear_flag(jb, JB_TIMEBASE_INITIALIZED);
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

	return fixed_jb_new(&conf, chan);
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
	
	res = fixed_jb_put_first(fixedjb, fin, fin->len, fin->ts, now, fin->marker);
	
	return fixed_to_abstract_code[res];
}


static int jb_put_fixed(void *jb, struct ast_frame *fin, long now)
{
	struct fixed_jb *fixedjb = (struct fixed_jb *) jb;
	int res;
	
	res = fixed_jb_put(fixedjb, fin, fin->len, fin->ts, now, fin->marker);
	
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
	jb_empty_and_reset_adaptive(jb);
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
