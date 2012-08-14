/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/* 
   
This unit implements class RTP which processes RTP packets and make statistics on them. 
Each Call class contains two RTP classes. 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#include <pcap.h>

#include "rtp.h"
#include "calltable.h"
#include "codecs.h"
#include "jitterbuffer/asterisk/channel.h"
#include "jitterbuffer/asterisk/frame.h"
#include "jitterbuffer/asterisk/abstract_jb.h"
#include "jitterbuffer/asterisk/strings.h"

extern int verbosity;
extern int opt_saveRAW;                //save RTP payload RAW data?
extern int opt_saveWAV;                //save RTP payload RAW data?
extern int opt_saveGRAPH;	//save GRAPH data?
extern int opt_gzipGRAPH;	//save gzip GRAPH data?
extern int opt_jitterbuffer_f1;            // turns off/on jitterbuffer simulator to compute MOS score mos_f1
extern int opt_jitterbuffer_f2;            // turns off/on jitterbuffer simulator to compute MOS score mos_f2
extern int opt_jitterbuffer_adapt;         // turns off/on jitterbuffer simulator to compute MOS score mos_adapt
extern char opt_cachedir[1024];
extern int opt_savewav_force;

using namespace std;

/* Convert timeval structure into microsecond representation */
inline u_int32_t timeval2micro(const timeval t) {
	return ((t.tv_sec * 1000000ul) + t.tv_usec); 
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */

int
timeval_subtract (struct timeval *result, struct timeval x, struct timeval y) {
	/* Perform the carry for the later subtraction by updating y. */
	if (x.tv_usec < y.tv_usec) {
		int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
		y.tv_usec -= 1000000 * nsec;
		y.tv_sec += nsec;
	}
	if (x.tv_usec - y.tv_usec > 1000000) {
		int nsec = (x.tv_usec - y.tv_usec) / 1000000;
		y.tv_usec += 1000000 * nsec;
		y.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	tv_usec is certainly p60itive. */
	result->tv_sec = x.tv_sec - y.tv_sec;
	result->tv_usec = x.tv_usec - y.tv_usec;

	/* Return 1 if result is negative. */
	return x.tv_sec < y.tv_sec;
}



/* constructor */
RTP::RTP() {
	first = true;
	s = new source;
	memset(s, 0, sizeof(source));
	memset(&stats, 0, sizeof(stats));
	nintervals = 1;
	saddr = 0;
	ssrc = 0;
	gfilename[0] = '\0';
	gfileRAW = NULL;

	channel_fix1 = (ast_channel*)calloc(1, sizeof(*channel_fix1));
	channel_fix1->jitter_impl = 0; // fixed
	channel_fix1->jitter_max = 50; 
	channel_fix1->jitter_resync_threshold = 50;
	channel_fix1->last_datalen = 0;
	channel_fix1->lastbuflen = 0;
	channel_fix1->resync = 1;
	channel_fix1->fifofd = 0;

	channel_fix2 = (ast_channel*)calloc(1, sizeof(*channel_fix2));
	channel_fix2->jitter_impl = 0; // fixed
	channel_fix2->jitter_max = 200; 
	channel_fix2->jitter_resync_threshold = 200; 
	channel_fix2->last_datalen = 0;
	channel_fix2->lastbuflen = 0;
	channel_fix2->resync = 1;
	channel_fix2->fifofd = 0;

	channel_adapt = (ast_channel*)calloc(1, sizeof(*channel_adapt));
	channel_adapt->jitter_impl = 1; // adaptive
	channel_adapt->jitter_max = 500; 
	channel_adapt->jitter_resync_threshold = 500; 
	channel_adapt->last_datalen = 0;
	channel_adapt->lastbuflen = 0;
	channel_adapt->resync = 1;
	channel_adapt->fifofd = 0;

	channel_record = (ast_channel*)calloc(1, sizeof(*channel_record));
	channel_record->jitter_impl = 0; // fixed
	channel_record->jitter_max = 60; 
	channel_record->jitter_resync_threshold = 1000; 
	channel_record->last_datalen = 0;
	channel_record->lastbuflen = 0;
	channel_record->resync = 0;
	channel_record->fifofd = 0;


	//channel->name = "SIP/fixed";
	frame = (ast_frame*)calloc(1, sizeof(*frame));
	frame->frametype = AST_FRAME_VOICE;
	lastframetype = AST_FRAME_VOICE;
	//frame->src = "DUMMY";
	last_seq = 0;
	last_ts = 0;
	packetization = 0;
	last_packetization = 0;
	packetization_iterator = 0;
	payload = -1;
	prev_payload = -1;
	codec = -1;
	for(int i = 0; i < MAX_RTPMAP; i++) {
		rtpmap[i] = 0;
	}
	gfileRAW_buffer = NULL;
	sid = false;
	prev_sid = false;
	call_owner = NULL;
}

/* destructor */
RTP::~RTP() {
	/*
	if(packetization)
		RTP::dump();
	*/

	if(gfileRAW) {
		jitterbuffer_fixed_flush(channel_record);
		fclose(gfileRAW);
	}

	delete s;
	ast_jb_destroy(channel_fix1);
	ast_jb_destroy(channel_fix2);
	ast_jb_destroy(channel_adapt);
	ast_jb_destroy(channel_record);
	free(channel_fix1);
	free(channel_fix2);
	free(channel_adapt);
	free(channel_record);
	free(frame);

	Call *owner = (Call*)call_owner;
	if(opt_saveGRAPH || (owner && (owner->flags & FLAG_SAVEGRAPH))) {
		if(opt_gzipGRAPH && gfileGZ.is_open()) {
			gfileGZ.close();
		} else if(gfile.is_open()){
			gfile.close();
		}
		if(gfilename[0] != '\0' && opt_cachedir[0] != '\0') {
			owner->addtocachequeue(gfilename);
		}
	}

	if(gfileRAW_buffer) {
		free(gfileRAW_buffer);
	}
}

const unsigned int RTP::get_payload_len() {
	payload_data = data + sizeof(RTPFixedHeader);
	payload_len = len - sizeof(RTPFixedHeader);
	if(getPadding()) {
		/*
		* If set, this packet contains one or more additional padding
		* bytes at the end which are not part of the payload. The last
		* byte of the padding contains a count of how many padding bytes
		* should be ignored. Padding may be needed by some encryption
		* algorithms with fixed block sizes or for carrying several RTP
		* packets in a lower-layer protocol data unit.
		*/
		payload_len -= ((u_int8_t *)data)[payload_len - 1];
	}
	if(getCC() > 0) {
		/*
		* The number of CSRC identifiers that follow the fixed header.
		*/
		payload_data += 4 * getCC();
		payload_len -= 4 * getCC();
	}
	if(getExtension()) {
		/*
		* If set, the fixed header is followed by exactly one header extension.
		*/
		extension_hdr_t *rtpext;
		if (payload_len < 4)
			payload_len = 0;

		// the extension, if present, is after the CSRC list.
		rtpext = (extension_hdr_t *)((u_int8_t *)payload_data);
		payload_data += sizeof(extension_hdr_t) + rtpext->length;
		payload_len -= sizeof(extension_hdr_t) + rtpext->length;
	}
	return payload_len;
}

/* flush jitterbuffer */
void RTP::jitterbuffer_fixed_flush(struct ast_channel *jchannel) {
	jb_fixed_flush_deliver(channel_record);
}

/* add silence to RTP stream from last packet time to current time which is in header->ts */
void
RTP::jt_tail(struct pcap_pkthdr *header) {

	if(!ast_jb_test(channel_record)) {
		// there is no ongoing recording, return
		return;
	}

	/* protect for endless loops (it cannot happen in theory but to be sure */
	if(packetization <= 0) {
		Call *owner = (Call*)call_owner;
		if(owner) {
			syslog(LOG_ERR, "call-id[%s]: packetization is 0 in jitterbuffer function.", owner->fbasename);
		} else {
			syslog(LOG_ERR, "call-id[N/A]: packetization is 0 in jitterbuffer function.");
		}
		return;
	}

	/* calculate time difference between last pakcet and current packet + packetization time*/ 
	if(channel_record->last_ts.tv_sec == 0) {
		// previouuse tv_sec is not set, set it
		memcpy(&channel_record->last_ts, &header->ts, sizeof(timeval));
		return;
	}
	int msdiff = ast_tvdiff_ms(header->ts, channel_record->last_ts);
	msdiff -= packetization;

	while( msdiff >= packetization )  {
		ast_jb_get_and_deliver(channel_record, &channel_record->last_ts);
		/* adding packetization time to last_ts time */ 
		struct timeval tmp = ast_tvadd(channel_record->last_ts, ast_samp2tv(packetization, 1000));
		memcpy(&channel_record->last_ts, &tmp, sizeof(struct timeval));
		msdiff -= packetization;
	}
}

#if 1
/* simulate jitterbuffer */
void
RTP::jitterbuffer(struct ast_channel *channel, int savePayload) {
	struct timeval tsdiff;	
	frame->ts = getTimestamp() / 8;
	frame->len = packetization;
	frame->marker = getMarker();
	frame->seqno = getSeqNum();
	channel->codec = codec;
	memcpy(&frame->delivery, &header->ts, sizeof(struct timeval));

	/* protect for endless loops (it cannot happen in theory but to be sure */
	if(packetization <= 0) {
		Call *owner = (Call*)call_owner;
		if(owner) {
			syslog(LOG_ERR, "call-id[%s]: packetization is 0 in jitterbuffer function.", owner->fbasename);
		} else {
			syslog(LOG_ERR, "call-id[N/A]: packetization is 0 in jitterbuffer function.");
		}
		return;
	}

	if(savePayload) {
		/* get RTP payload header and datalen */
		payload_data = data + sizeof(RTPFixedHeader);
		payload_len = len - sizeof(RTPFixedHeader);
		if(getPadding()) {
			/*
			* If set, this packet contains one or more additional padding
			* bytes at the end which are not part of the payload. The last
			* byte of the padding contains a count of how many padding bytes
			* should be ignored. Padding may be needed by some encryption
			* algorithms with fixed block sizes or for carrying several RTP
			* packets in a lower-layer protocol data unit.
			*/
			payload_len -= ((u_int8_t *)data)[payload_len - 1];
		}
		if(getCC() > 0) {
			/*
			* The number of CSRC identifiers that follow the fixed header.
			*/
			payload_data += 4 * getCC();
			payload_len -= 4 * getCC();
		}
		if(getExtension()) {
			/*
			* If set, the fixed header is followed by exactly one header extension.
			*/
			extension_hdr_t *rtpext;
			if (payload_len < 4)
				payload_len = 0;

			// the extension, if present, is after the CSRC list.
			rtpext = (extension_hdr_t *)((u_int8_t *)payload_data);
			payload_data += sizeof(extension_hdr_t) + rtpext->length;
			payload_len -= sizeof(extension_hdr_t) + rtpext->length;
		}
		frame->data = payload_data;
		frame->datalen = payload_len > 0 ? payload_len : 0; /* ensure that datalen is never negative */

		if(getPayload() == PAYLOAD_G723) {
			// voipmonitor does not handle SID packets well (silence packets) it causes out of sync
			if((unsigned char)payload_data[0] & 2)  {
				/* check if jitterbuffer is already created. If not we have to create it because 
				   if call starts with SID packets first it will than cause out of sync calls 
				*/
				if(ast_test_flag(&channel->jb, (1 << 2))) {
					// jitterbuffer is created so we can skip SID packets now
					return;
				}
			}
		}

		channel->rawstream = gfileRAW;

		Call *owner = (Call*)call_owner;
		if(iscaller)
			channel->fifofd = owner->fifo1;
		else
			channel->fifofd = owner->fifo2;

		if(payload_len > 0) {
			channel->last_datalen = frame->datalen;
		}
	} else {
		frame->datalen = 0;
		frame->data = NULL;
		channel->rawstream = NULL;
	}


	// create jitter buffer structures 
	ast_jb_do_usecheck(channel, &header->ts);
	
	if(!channel->jb_reseted) {
		// initializing jitterbuffer 
		ast_jb_empty_and_reset(channel);
		channel->jb_reseted = 1;
		memcpy(&channel->last_ts, &header->ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header->ts);
		return;
	}

	/* calculate time difference between last pakcet and current packet + packetization time*/ 
	int msdiff = ast_tvdiff_ms( header->ts, ast_tvadd(channel->last_ts, ast_samp2tv(packetization, 1000)) );
	//printf("ms:%d\n", msdiff);
	if(msdiff > packetization * 1000) {
		// difference is too big, reseting last_ts to current packet. If we dont check this it could happen to run while cycle endlessly
		memcpy(&channel->last_ts, &header->ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header->ts);
		if(verbosity > 4) syslog(LOG_ERR, "big timestamp jump (msdiff:%d packetization: %d) in this file: %s\n", msdiff, packetization, gfilename);
		return;
	}

	/* between last packet and current packet is big timestamp difference and it could count 
	 * interpolated framed although it was silence so calculate real number of packets based 
	 * on timestamps in packet header, timestamps in rtp header and sequence numbers between 
	 * last packet and current packet
	 */

	// relative time difference calculated from packet sequence 
	u_int32_t sequencems = (frame->seqno - last_seq) * packetization;

	/* difference (in ms) between timestamps in packet header and rtp timestamps. this should 
	 * be ideally equel to zero. Negative values mean that packet arrives earlier and positive 
	 * values indicates that packet was late 
	 */
	long double transit = (timeval_subtract(&tsdiff, header->ts, s->lastTimeRec) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0) - (double)(getTimestamp() - s->lastTimeStamp)/8.0;
	
	/* and now if there is bigger (lets say one second) timestamp difference (calculated from pakcet headers) 
	 * between two last packets and transit time is equel or smaller than sequencems (with 200ms toleration), 
	 * it was silence and manually mark the frame which indicates to not count interpolated frame and resynchronize jitterbuffer
	 */
	if( msdiff > 1000 and (transit <= (sequencems + 200)) ) {
		if(verbosity > 4) printf("jitterbuffer: manually marking packet, msdiff(%d) > 1000 and transit (%Lf) <= ((sequencems(%u) + 200)\n", msdiff, transit, sequencems);
		frame->marker = 1;
	}
	
	// fetch pakcet from jitterbuffer every 20 ms regardless on packet loss or delay
	while( msdiff >= packetization )  {
		if(frame->marker or lastframetype == AST_FRAME_DTMF) {
			/* if last frame was marked or DTMF, ignore interpolated frames */
			channel->last_loss_burst = 0;
		}
		ast_jb_get_and_deliver(channel, &channel->last_ts);
		/* adding packetization time to last_ts time */ 
		struct timeval tmp = ast_tvadd(channel->last_ts, ast_samp2tv(packetization, 1000));
		memcpy(&channel->last_ts, &tmp, sizeof(struct timeval));
		msdiff -= packetization;
	}

	ast_jb_put(channel, frame, &header->ts);
}
#endif

/* read rtp packet */
void
RTP::read(unsigned char* data, int len, struct pcap_pkthdr *header,  u_int32_t saddr, int seeninviteok) {
	this->data = data; 
	this->len = len;
	this->header = header;
	this->saddr =  saddr;

	Call *owner = (Call*)call_owner;


	if(getVersion() != 2) {
		return;
	}

	u_int16_t seq = getSeqNum();

	if(seq == last_seq) {
		// ignore duplicated RTP packets
		return;
	}

	int curpayload = getPayload();

	// ignore CNG
	if(curpayload == 13 or curpayload == 19) {
		last_seq = seq;
		if(update_seq(seq)) {
			update_stats();
		}
		return;
	}

	if(!owner) return;

	int fifo1 = owner->fifo1;
	int fifo2 = owner->fifo2;
	
	/* codec changed */
	if((codec == -1 || (curpayload != prev_payload)) && (curpayload != 101 && prev_payload != 101)) {
		if(curpayload >= 96 && curpayload <= 127) {
			/* for dynamic payload we look into rtpmap */
			for(int i = 0; i < MAX_RTPMAP; i++) {
				if(rtpmap[i] != 0 && curpayload == rtpmap[i] / 1000) {
					codec = rtpmap[i] - curpayload * 1000;
				}
			}
		} else {
			codec = curpayload;
		}

		if(iscaller) {
			owner->last_callercodec = codec;
		} else {
			owner->last_calledcodec = codec;
		}

		if(opt_saveRAW || opt_savewav_force || (owner && (owner->flags & FLAG_SAVEWAV)) ||
			fifo1 || fifo2 // if recording requested 
		) {
			if(verbosity > 0) syslog(LOG_ERR, "converting WAV! [%u] [%d] [%d]\n", owner->flags, fifo1, fifo2);
			/* open file for raw codec */
			unsigned long unique = getTimestamp();
			char tmp[1024];
			sprintf(tmp, "%s.%d.%lu.%d.%ld.%ld.raw", basefilename, ssrc_index, unique, codec, header->ts.tv_sec, header->ts.tv_usec);
			if(gfileRAW) {
				//there is already opened gfileRAW
                                jitterbuffer_fixed_flush(channel_record);
				fclose(gfileRAW);
			} else {
				/* look for the last RTP stream belonging to this direction and let jitterbuffer put silence 
				 * which fills potentionally gap between this and previouse RTP so it will stay in sync with
				 * the other direction of call 
				 */
				RTP *prevrtp = (RTP*)(owner->rtp_prev[iscaller]);
				if(prevrtp && prevrtp != this) {
					prevrtp->data = data; 
					prevrtp->len = len;
					prevrtp->header = header;
					prevrtp->saddr = saddr;
					prevrtp->jitterbuffer(prevrtp->channel_record, opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) || fifo1 || fifo2);
				}
			}
			gfileRAW = fopen(tmp, "w");
			if(!gfileRAW_buffer) {
				gfileRAW_buffer = (char*)malloc(32768 * sizeof(char));
				if(gfileRAW_buffer == NULL) {
					syslog(LOG_ERR, "Cannot allocate memory for gfileRAW_buffer - low memory this is FATAL");
					exit(2);
				}
			}
			if(!gfileRAW) {
				syslog(LOG_ERR, "Cannot open file %s for writing: %s\n", tmp, strerror (errno));
				exit(2);
			}
			if(gfileRAW_buffer) {
				setvbuf(gfileRAW, gfileRAW_buffer, _IOFBF, 32768);
			}

			/* write file info to "playlist" */
			sprintf(tmp, "%s.rawInfo", basefilename);
			FILE *gfileRAWInfo = fopen(tmp, "a");
			if(gfileRAWInfo) {
				fprintf(gfileRAWInfo, "%d:%lu:%d:%ld:%ld\n", ssrc_index, unique, codec, header->ts.tv_sec, header->ts.tv_usec);
				fclose(gfileRAWInfo);
			} else {
				syslog(LOG_ERR, "Cannot open file %s.rawInfo for writing\n", basefilename);
			}
		}
	}

	if(payload < 0) {
		/* save payload to statistics based on first payload. TODO: what if payload is dynamically changing? */
		payload = curpayload;
	}

	if(curpayload == 101) {
		frame->frametype = AST_FRAME_DTMF;
	} else {
		frame->frametype = AST_FRAME_VOICE;
	}

// voipmonitor now handles RTP streams including progress  XXX: remove this comment if it will be confirmed stable enough
//	if(seeninviteok) {


		if(packetization_iterator == 0 || packetization_iterator == 1) {
			// we dont know packetization yet. Behave differently n G723 codec 
			if(curpayload == PAYLOAD_G723) {
				default_packetization = 30;
				/* check if RTP packet is not Silence packet (SID). Silence packets can have different
				   packetization and if call starts with SID packets it will guess wrong packetization.
				   typical sitation is for 60ms packetization and 30ms SID packetization */
				payload_data = data + sizeof(RTPFixedHeader);
				sid = (unsigned char)payload_data[0] & 2;
			} else {
				sid = false;
				default_packetization = 20;
			}
		}
		if(packetization_iterator == 0) {
			if(last_ts != 0 && seq == (last_seq + 1) && (prev_payload != 101 && curpayload != 101) && !sid && !prev_sid) {
				// sequence numbers are ok, we can calculate packetization
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(get_payload_len() == 20) {
						packetization = 20;
					} else {
						packetization = (getTimestamp() - last_ts) / 8;
					}
				} else {
					packetization = (getTimestamp() - last_ts) / 8;
				}
				if(packetization > 0) {
					last_packetization = packetization;
					packetization_iterator++;
				}
			}

#if 1
			// new way of getting packetization from packet datalen 
			if(curpayload == PAYLOAD_PCMU or curpayload == PAYLOAD_PCMA) {
				channel_fix1->packetization = default_packetization = channel_fix2->packetization = channel_adapt->packetization = channel_record->packetization = packetization = get_payload_len() / 8;

				if(verbosity > 3) printf("[%x] packetization:[%d]\n", getSSRC(), packetization);


				packetization_iterator = 10; // this will cause that packetization is estimated as final

				if(opt_jitterbuffer_f1)
					jitterbuffer(channel_fix1, 0);
				if(opt_jitterbuffer_f2)
					jitterbuffer(channel_fix2, 0);
				if(opt_jitterbuffer_adapt)
					jitterbuffer(channel_adapt, 0);
			} 
#endif

			/* for recording, we cannot loose any packet */
			if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
				fifo1 || fifo2 // if recording requested 
			){
				packetization = channel_record->packetization = default_packetization;
				jitterbuffer(channel_record, opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) || fifo1 || fifo2);
			}
		} else if(packetization_iterator == 1) {
			if(last_ts != 0 && seq == (last_seq + 1) && curpayload != 101 && prev_payload != 101 && !sid && !prev_sid) {
				// sequence numbers are ok, we can calculate packetization
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(get_payload_len() == 20) {
						packetization = 20;
					} else {
						packetization = (getTimestamp() - last_ts) / 8;
					}
				} else {
					packetization = (getTimestamp() - last_ts) / 8;
				}

				// now make packetization average
				packetization = (packetization + last_packetization) / 2;

				if(packetization <= 0 or getMarker()) {
					// packetization failed or Marker bit is set, fall back to start
					packetization_iterator = 0;

					/* for recording, we cannot loose any packet */
					if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
						fifo1 || fifo2 // if recording requested 
					){
						packetization = channel_record->packetization = default_packetization;
						jitterbuffer(channel_record, 1);
					}
				} else {
					packetization_iterator++;
					channel_fix1->packetization = channel_fix2->packetization = channel_adapt->packetization = channel_record->packetization = packetization;
					if(verbosity > 3) printf("[%x] packetization:[%d]\n", getSSRC(), packetization);

					if(opt_jitterbuffer_f1)
						jitterbuffer(channel_fix1, 0);
					if(opt_jitterbuffer_f2)
						jitterbuffer(channel_fix2, 0);
					if(opt_jitterbuffer_adapt)
						jitterbuffer(channel_adapt, 0);
					if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
						fifo1 || fifo2 // if recording requested 
					){
						jitterbuffer(channel_record, 1);
					}
				}
			} else {
				packetization_iterator = 0;
				/* for recording, we cannot loose any packet */
				if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
					fifo1 || fifo2 // if recording requested 
				){
					packetization = channel_record->packetization = default_packetization;
					jitterbuffer(channel_record, 1);
				}
			}
		} else {
			if(opt_jitterbuffer_f1)
				jitterbuffer(channel_fix1, 0);
			if(opt_jitterbuffer_f2)
				jitterbuffer(channel_fix2, 0);
			if(opt_jitterbuffer_adapt)
				jitterbuffer(channel_adapt, 0);
			if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
				fifo1 || fifo2 // if recording requested 
			){
				jitterbuffer(channel_record, 1);
			}
		}
//	}
	prev_payload = curpayload;
	prev_sid = sid;

	if(getMarker()) {
		// if RTP packet is Marked, we have to reset last_ts to 0 so in next cycle it will count packetization from ground
		last_ts = 0;
	} else {
		last_ts = getTimestamp();
	}
	last_seq = seq;

	if(first) {
		first = false;
		init_seq(seq);
		s->max_seq = seq - 1;
		s->probation = MIN_SEQUENTIAL;
		s->lastTimeRec = header->ts;
		s->lastTimeStamp = getTimestamp();
	} else {
		if(update_seq(seq)) {
			update_stats();
		}
	}
	lastframetype = frame->frametype;
}

/* fill internal structures by the input RTP packet */
void
RTP::fill(unsigned char* data, int len, struct pcap_pkthdr *header,  u_int32_t saddr) {
	this->data = data; 
	this->len = len;
	this->header = header;
	this->saddr = saddr;
}

/* update statistics data */
void
RTP::update_stats() {
	
	int lost = int((s->cycles + s->max_seq - (s->base_seq + 1)) - s->received);
	int adelay = 0;
	struct timeval tsdiff;	
	double tsdiff2;

	Call *owner = (Call*)call_owner;

	/* if payload == 101 (EVENT) dont make delayes on this because it confuses stats */
	if(getPayload() == 101)
		return;

	/* differences between last timestamp and current timestamp (timestamp from ip heade)
	 * frame1.time - frame0.time */
	tsdiff2 = timeval_subtract(&tsdiff, header->ts, s->lastTimeRec) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0;

	long double transit = tsdiff2 - (double)(getTimestamp() - s->lastTimeStamp)/8.0;
	
	if(abs((int)transit) > 5000) {
		/* timestamp skew, discard delay, it is possible that timestamp changed  */
		s->fdelay = s->avgdelay;
		//s->fdelay = 0;
		transit = 0;
	} else {
		adelay = abs(int(transit));
		s->fdelay += transit;
	}

	/* Jitterbuffer calculation
	 * J(1) = J(0) + (|D(0,1)| - J(0))/16 */
	if(transit < 0) transit = -transit;
	long double jitter = s->prevjitter + (transit - s->prevjitter)/16. ;

	s->avgdelay = ((s->avgdelay * (long double)(s->received) - 1) + transit ) / (double)s->received;
	stats.avgjitter = ((stats.avgjitter * ( stats.received - 1 )  + jitter )) / (double)s->received;
	if(stats.maxjitter < jitter) stats.maxjitter = jitter;
	s->lastTimeRec = header->ts;
	s->lastTimeStamp = getTimestamp();
	
	if((lost > stats.last_lost) > 0) {
		stats.lost += lost - stats.last_lost;
		if((lost - stats.last_lost) < 10)
			stats.slost[lost - stats.last_lost]++;
		else 
			stats.slost[10]++;

		if(owner && (owner->flags & FLAG_SAVEGRAPH)) {
			nintervals += lost - stats.last_lost;
			while(nintervals > 20) {
				if(opt_gzipGRAPH) {
					// compressed
					if(gfileGZ.is_open()) {
						gfile << endl;
					}
				} else {
					// uncompressed
					if(gfile.is_open()) {
						gfile << endl;
					}
				}
				nintervals -= 20;
			}
		}
	} else {
		if(owner && (owner->flags & FLAG_SAVEGRAPH)) {
			if(opt_gzipGRAPH && gfileGZ.is_open()) {
				// compressed
				if(nintervals > 20) {
					/* after 20 packets, send new line */
					gfileGZ << endl;
					nintervals -= 20;
				}
				//gfile << s->fdelay << ":" << transit << ";";
				gfileGZ << s->fdelay << ":" << jitter << ";";
				nintervals++;
			} else if(gfile.is_open()) {
				// uncompressed
				if(nintervals > 20) {
					/* after 20 packets, send new line */
					gfile << endl;
					nintervals -= 20;
				}
				//gfile << s->fdelay << ":" << transit << ";";
				gfile << s->fdelay << ":" << jitter << ";";
				nintervals++;
			}
		}
	}
	stats.last_lost = lost;

	/* delay statistics */
	if(adelay >= 50 && adelay < 70) {
		stats.d50++;
	} else if (adelay >= 70 && adelay < 90) {
		stats.d70++;
	} else if (adelay >= 90 && adelay < 120) {
		stats.d90++;
	} else if (adelay >= 120 && adelay < 150) {
		stats.d120++;
	} else if (adelay >= 150 && adelay < 200) {
		stats.d150++;
	} else if (adelay >= 200 && adelay < 300) {
		stats.d200++;
	} else if (adelay >= 300) {
		stats.d300++;
	}
}

void
RTP::init_seq(u_int16_t seq) {
	s->base_seq = seq;
	s->max_seq = seq;
	s->bad_seq = RTP_SEQ_MOD + 1;   /* so seq == bad_seq is false */
	s->cycles = 0;
	s->received = 0;
	s->received_prior = 0;
	s->expected_prior = 0;
	s->delay = 0;
	s->fdelay = 0;
	s->prevjitter = 0;
}

/* this function is borrowed from the http://www.ietf.org/rfc/rfc3550.txt */
int
RTP::update_seq(u_int16_t seq) {
	u_int16_t udelta = seq - s->max_seq;
	/*
	* Source is not valid until MIN_SEQUENTIAL packets with
	* sequential sequence numbers have been received.
	*/
	if (s->probation) {
		/* packet is in sequence */
		if (seq == s->max_seq + 1) {
			s->probation--;
			s->max_seq = seq;
			if (s->probation == 0) {
				init_seq(seq);
				s->received++;
				stats.received++;
				return 1;
			}
		} else {
			s->probation = MIN_SEQUENTIAL - 1;
			s->max_seq = seq;
		}
		return 0;
	} else if (udelta < MAX_DROPOUT) {
		/* in order, with permissible gap */
		if (seq < s->max_seq) {
			/*
			* Sequence number wrapped - count another 64K cycle.
			*/
			s->cycles += RTP_SEQ_MOD;
		}
		s->max_seq = seq;
	} else if (udelta <= RTP_SEQ_MOD - MAX_MISORDER) {
		/* the sequence number made a very large jump */
		if (seq == s->bad_seq) {
			/*
			* Two sequential packets -- assume that the other side
			* restarted without telling us so just re-sync
			* (i.e., pretend this was the first packet).
			*/
			init_seq(seq);
		} else {
			s->bad_seq = (seq + 1) & (RTP_SEQ_MOD-1);
			return 0;
		}
	} else {
		 /* duplicate or reordered packet */
	}
	stats.received++;
	s->received++;
	return 1;
}	

void burstr_calculate(struct ast_channel *chan, u_int32_t received, double *burstr, double *lossr) {
	int lost = 0;
	int bursts = 0;
	for(int i = 0; i < 500; i++) {
		lost += i * chan->loss[i];
		bursts += chan->loss[i];
		if(verbosity > 4 and chan->loss[i] > 0) printf("loss[%d]: %d\t", i, chan->loss[i]);
	}
	if(verbosity > 4) printf("\n");
	if(received > 0 && bursts > 0) {
		*burstr = (double)((double)lost / (double)bursts) / (double)(1.0 / ( 1.0 - (double)lost / (double)received ));
		if(*burstr < 0) {
			*burstr = - *burstr;
		}
	} else {
		*burstr = 0;
	}
	//printf("total loss: %d\n", lost);
	if(received > 0) {
		*lossr = (double)((double)lost / (double)received);
	} else {
		*lossr = 0;
	}
}

/* for debug purpose */
void
RTP::dump() {
	int i;
	printf("SSRC:%u\n", ssrc);
	printf("payload:%d\n", payload);
	printf("src ip:%u\n", saddr);
	printf("Packetization:%u\n", packetization);
	printf("s->received: %d\n", s->received);
	printf("total loss:%u\n", stats.lost);
	printf("loss ratio:%f\n", (double)stats.lost / (double)s->received);
	printf("serial loss: ");
	for(i = 1; i < 11; i++) 
		printf("%d:%u ", i, stats.slost[i]);
	printf("\n");
	printf("d50: %d, d70: %d, d90: %d, d120: %d, d150: %d, d200: %d, d300: %d\n",
		stats.d50, stats.d70, stats.d90, stats.d120, stats.d150, stats.d200, stats.d300);

	double burstr, lossr;
	printf("jitter stats:\n");
	burstr_calculate(channel_fix1, s->received, &burstr, &lossr);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("fix(50/50)\tloss rate:\t%f\n", lossr);
	printf("fix(50/50)\tburst rate:\t%f\n", burstr);

	burstr_calculate(channel_fix2, s->received, &burstr, &lossr);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("fix(200/200)\tloss rate:\t%f\n", lossr);
	printf("fix(200/200)\tburst rate:\t%f\n", burstr);

	burstr_calculate(channel_adapt, s->received, &burstr, &lossr);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("adapt(500/500)\tloss rate:\t%f\n", lossr);
	printf("adapt(500/500)\tburst rate:\t%f\n", burstr);
	printf("---\n");
}
