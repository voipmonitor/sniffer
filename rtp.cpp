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
#include <errno.h>

#include <pcap.h>

#include "voipmonitor.h"
#include "tools.h"
#include "rtp.h"
#include "calltable.h"
#include "codecs.h"
#include "sniff.h"
#include "format_slinear.h"
#include "codec_alaw.h"
#include "codec_ulaw.h"
#include "flags.h"

#include "jitterbuffer/asterisk/channel.h"
#include "jitterbuffer/asterisk/frame.h"
#include "jitterbuffer/asterisk/abstract_jb.h"
#include "jitterbuffer/asterisk/strings.h"

extern int verbosity;
extern int opt_saveRAW;                //save RTP payload RAW data?
extern int opt_saveWAV;                //save RTP payload RAW data?
extern int opt_saveGRAPH;	//save GRAPH data?
extern FileZipHandler::eTypeCompress opt_gzipGRAPH;	//save gzip GRAPH data?
extern int opt_jitterbuffer_f1;            // turns off/on jitterbuffer simulator to compute MOS score mos_f1
extern int opt_jitterbuffer_f2;            // turns off/on jitterbuffer simulator to compute MOS score mos_f2
extern int opt_jitterbuffer_adapt;         // turns off/on jitterbuffer simulator to compute MOS score mos_adapt
extern char opt_cachedir[1024];
extern int opt_savewav_force;
extern int opt_rtp_check_timestamp;
int dtmfdebug = 0;

extern unsigned int graph_delimiter;
extern unsigned int graph_mark;
extern int opt_faxt30detect;

using namespace std;

/* Convert timeval structure into microsecond representation */
inline u_int32_t timeval2micro(const timeval t) {
	return ((t.tv_sec * 1000000ull) + t.tv_usec); 
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

int get_ticks_bycodec(int codec) {
	switch(codec) {
	case PAYLOAD_PCMU: 
		return 8;
		break;
	case PAYLOAD_GSM:
		return 8;
		break;
	case PAYLOAD_G723:
		return 8;
		break;
	case PAYLOAD_PCMA:
		return 8;
		break;
	case PAYLOAD_G722:
		return 8;
		break;
	case PAYLOAD_G729:
		return 8;
		break;
	case PAYLOAD_ILBC:
		return 8;
		break;
	case PAYLOAD_SPEEX:
		return 8;
		break;
	case PAYLOAD_SILK8:
		return 8;
		break;
	case PAYLOAD_SILK12:
		return 12;
		break;
	case PAYLOAD_SILK16:
		return 16;
		break;
	case PAYLOAD_SILK24:
		return 24;
		break;
	case PAYLOAD_ISAC16:
		return 16;
		break;
	case PAYLOAD_ISAC32:
		return 32;
		break;
	case PAYLOAD_OPUS:
	case PAYLOAD_OPUS8:
		return 8;
		break;
	case PAYLOAD_OPUS12:
		return 12;
		break;
	case PAYLOAD_OPUS16:
		return 16;
		break;
	case PAYLOAD_OPUS24:
		return 24;
		break;
	case PAYLOAD_OPUS48:
		return 48;
		break;
	case PAYLOAD_G7221:
		return 8;
		break;
	case PAYLOAD_G722112:
		return 12;
		break;
	case PAYLOAD_G722116:
		return 16;
		break;
	case PAYLOAD_G722124:
		return 24;
		break;
	case PAYLOAD_G722132:
		return 32;
		break;
	case PAYLOAD_G722148:
		return 48;
		break;
	default:
		return 8;
	}
}

/* constructor */
RTP::RTP(int sensor_id) 
 : graph(this) {
	DSP = NULL;
	samplerate = 8000;
	first = true;
	first_packet_time = 0;
	first_packet_usec = 0;
	s = new source;
	memset(s, 0, sizeof(source));
	memset(&stats, 0, sizeof(stats));
	memset(&rtcp, 0, sizeof(rtcp));
	nintervals = 1;
	saddr = 0;
	daddr = 0;
	dport = 0;
	ssrc = 0;
	ssrc2 = 0;
	gfilename[0] = '\0';
	gfileRAW = NULL;

	channel_fix1 = (ast_channel*)calloc(1, sizeof(*channel_fix1));
	channel_fix1->jitter_impl = 0; // fixed
	channel_fix1->jitter_max = 50; 
	channel_fix1->jitter_resync_threshold = 100;
	channel_fix1->last_datalen = 0;
	channel_fix1->lastbuflen = 0;
	channel_fix1->resync = 1;
	channel_fix1->audiobuf = NULL;

	channel_fix2 = (ast_channel*)calloc(1, sizeof(*channel_fix2));
	channel_fix2->jitter_impl = 0; // fixed
	channel_fix2->jitter_max = 200; 
	channel_fix2->jitter_resync_threshold = 200; 
	channel_fix2->last_datalen = 0;
	channel_fix2->lastbuflen = 0;
	channel_fix2->resync = 1;
	channel_fix2->audiobuf = NULL;

	channel_adapt = (ast_channel*)calloc(1, sizeof(*channel_adapt));
	channel_adapt->jitter_impl = 1; // adaptive
	channel_adapt->jitter_max = 500; 
	channel_adapt->jitter_resync_threshold = 500; 
	channel_adapt->last_datalen = 0;
	channel_adapt->lastbuflen = 0;
	channel_adapt->resync = 1;
	channel_adapt->audiobuf = NULL;

	channel_record = (ast_channel*)calloc(1, sizeof(*channel_record));
	channel_record->jitter_impl = 0; // fixed
	channel_record->jitter_max = 60; 
	channel_record->jitter_resync_threshold = 1000; 
	channel_record->last_datalen = 0;
	channel_record->lastbuflen = 0;
	channel_record->resync = 0;
	channel_record->audiobuf = NULL;

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
	first_codec = -1;
	prev_payload = -1;
	prev_codec = -1;
	payload2 = -1;
	codec = -1;
	for(int i = 0; i < MAX_RTPMAP; i++) {
		rtpmap[i] = 0;
	}
	gfileRAW_buffer = NULL;
	sid = false;
	prev_sid = false;
	call_owner = NULL;
	pinformed = 0;
	last_end_timestamp = 0;
	lastdtmf = 0;
	forcemark = 0;
	ignore = 0;
	lastcng = 0;
	dscp = 0;
	
	this->sensor_id = sensor_id;
	
	this->_last_ts.tv_sec = 0;
	this->_last_ts.tv_usec = 0;
	this->_last_sensor_id = 0;
	this->_last_ifname[0] = 0;
	
	lastTimeSyslog = 0;
}

/* destructor */
RTP::~RTP() {
	/*
	if(packetization)
		RTP::dump();
	*/
	//Call *owner = (Call*)call_owner;

	if(verbosity > 9) {
		RTP::dump();
	}

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

	if(gfileRAW_buffer) {
		free(gfileRAW_buffer);
	}

	if(DSP) {
		dsp_free(DSP);
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
			syslog(LOG_ERR, "call-id[%s]: packetization is 0 in jitterbuffer function.", owner->get_fbasename_safe());
		} else {
			syslog(LOG_ERR, "call-id[N/A]: packetization is 0 in jitterbuffer function.");
		}
		return;
	}

	/* calculate time difference between last packet and current packet + packetization time*/ 
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

	if(codec == PAYLOAD_TELEVENT) return;

	Call *owner = (Call*)call_owner;
	if(owner and savePayload and owner->silencerecording) {
		// skip recording 
		frame->skip = 1;
	} else {
		frame->skip = 0;
	}
	struct timeval tsdiff;
	frame->len = packetization;
	switch(codec) {
		case PAYLOAD_OPUS12:
		case PAYLOAD_G722112:
			frame->ts = getTimestamp() / 12;
			//frame->len = packetization * 2 / 3;
			break;
		case PAYLOAD_ISAC16:
		case PAYLOAD_SILK16:
		case PAYLOAD_OPUS16:
		case PAYLOAD_G722116:
			frame->ts = getTimestamp() / 16;
			//frame->len = packetization / 2;
			break;
		case PAYLOAD_SILK24:
		case PAYLOAD_OPUS24:
		case PAYLOAD_G722124:
			frame->ts = getTimestamp() / 24;
			//frame->len = packetization / 3;
			break;
		case PAYLOAD_ISAC32:
		case PAYLOAD_G722132:
			frame->ts = getTimestamp() / 32;
			//frame->len = packetization / 4;
			break;
		case PAYLOAD_OPUS48:
			frame->ts = getTimestamp() / 48;
			//frame->len = packetization / 6;
			break;
		default: 
			frame->ts = getTimestamp() / 8;
			//frame->len = packetization;
	}
	frame->marker = getMarker();
	frame->seqno = getSeqNum();
	channel->codec = codec;
	frame->ignore = ignore;
	memcpy(&frame->delivery, &header->ts, sizeof(struct timeval));

	/* protect for endless loops (it cannot happen in theory but to be sure */
	if(packetization <= 0) {
		if(pinformed == 0) {
			if(owner) {
				syslog(LOG_ERR, "call-id[%s] ssrc[%x]: packetization is 0 in jitterbuffer function.", owner->get_fbasename_safe(), getSSRC());
				
			} else {
				syslog(LOG_ERR, "call-id[N/A] ssrc[%x]: packetization is 0 in jitterbuffer function.", getSSRC());
			}
		}
		pinformed = 1;
		return;
	} else {
		pinformed = 0;
	}

	struct iphdr2 *header_ip = (struct iphdr2 *)(data - sizeof(struct iphdr2) - sizeof(udphdr2));
	int mylen = MIN((unsigned int)len, ntohs(header_ip->tot_len) - header_ip->ihl * 4 - sizeof(udphdr2));


	if(savePayload or (codec == PAYLOAD_G729 or codec == PAYLOAD_G723)) {
		/* get RTP payload header and datalen */
		payload_data = data + sizeof(RTPFixedHeader);
		payload_len = mylen - sizeof(RTPFixedHeader);
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

		if(codec == PAYLOAD_G723) {
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

		if(codec == PAYLOAD_G729 and (payload_len <= (packetization == 10 ? 9 : 12))) {
			frame->frametype = AST_FRAME_DTMF;
			frame->marker = 1;
		}
	}

	if(lastcng or lastframetype == AST_FRAME_DTMF) {
		frame->marker = 1;
	}

	if(savePayload) {
		channel->rawstream = gfileRAW;
		Call *owner = (Call*)call_owner;
		if(iscaller) {
			owner->codec_caller = codec;
			if(owner->audiobuffer1 &&
			   (!owner->last_seq_audiobuffer1 ||
			    owner->last_seq_audiobuffer1 < frame->seqno)) {
				channel->audiobuf = owner->audiobuffer1;
				owner->last_seq_audiobuffer1 = frame->seqno;
			}
		} else {
			owner->codec_called = codec;
			if(owner->audiobuffer2 &&
			   (!owner->last_seq_audiobuffer2 ||
			    owner->last_seq_audiobuffer2 < frame->seqno)) {
				channel->audiobuf = owner->audiobuffer2;
				owner->last_seq_audiobuffer2 = frame->seqno;
			}
		}
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
	if(channel->jb.timebase.tv_sec == header->ts.tv_sec &&
	   channel->jb.timebase.tv_usec == header->ts.tv_usec) {
		channel->last_ts = header->ts;
	}
	
	if(!channel->jb_reseted) {
		// initializing jitterbuffer 
		if(savePayload) {
			channel_record->jitter_max = frame->len * 3; 
		}
		
		ast_jb_empty_and_reset(channel);
		channel->jb_reseted = 1;
		memcpy(&channel->last_ts, &header->ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header->ts);
		this->clearAudioBuff(owner, channel);
		return;
	}

	/* calculate time difference between last packet and current packet + packetization time*/ 
	int msdiff = ast_tvdiff_ms( header->ts, ast_tvadd(channel->last_ts, ast_samp2tv(packetization, 1000)) );
	//printf("ms:%d\n", msdiff);
	if(msdiff > packetization * 10000) {
		// difference is too big, reseting last_ts to current packet. If we dont check this it could happen to run while cycle endlessly
		memcpy(&channel->last_ts, &header->ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header->ts);
		if(verbosity > 4) syslog(LOG_ERR, "big timestamp jump (msdiff:%d packetization: %d) in this file: %s\n", msdiff, packetization, gfilename);
		this->clearAudioBuff(owner, channel);
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
	long double transit = (timeval_subtract(&tsdiff, header->ts, s->lastTimeRecJ) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0) - (double)(getTimestamp() - s->lastTimeStampJ)/(double)samplerate/1000;
	
	/* and now if there is bigger (lets say one second) timestamp difference (calculated from packet headers) 
	 * between two last packets and transit time is equel or smaller than sequencems (with 200ms toleration), 
	 * it was silence and manually mark the frame which indicates to not count interpolated frame and resynchronize jitterbuffer
	 */
	if( msdiff > 1000 and (transit <= (sequencems + 200)) ) {
		// check if the last frame was CNG or the last frame was DTMF - force mark bit
		if(lastcng or (lastframetype == AST_FRAME_DTMF)) {
			if(verbosity > 4) printf("jitterbuffer: manually marking packet, msdiff(%d) > 1000 and transit (%Lf) <= ((sequencems(%u) + 200)\n", msdiff, transit, sequencems);
			frame->marker = 1;
		}
	}
	
	// fetch packet from jitterbuffer every 20 ms regardless on packet loss or delay
	while( msdiff >= packetization )  {
		if(frame->marker or lastframetype == AST_FRAME_DTMF) {
			/* if last frame was marked or DTMF, ignore interpolated frames */
			channel->last_loss_burst = 0;
		}
		ast_jb_get_and_deliver(channel, &channel->last_ts);
		/* adding packetization time to last_ts time */ 
		struct timeval tmp = ast_tvadd(channel->last_ts, ast_samp2tv(frame->len, 1000));
		memcpy(&channel->last_ts, &tmp, sizeof(struct timeval));
		msdiff -= packetization;
	}

	//printf("s[%u] codec[%d]\n",getSeqNum(), codec);
	ast_jb_put(channel, frame, &header->ts);
	
	this->clearAudioBuff(owner, channel);
}
#endif

void 
RTP::process_dtmf_rfc2833() {

	unsigned int seqno = getSeqNum();
	unsigned int event, event_end, samples;
	char resp = 0;
	unsigned int timestamp = getTimestamp();

	unsigned char *pdata = data + sizeof(RTPFixedHeader);

	/* Figure out event, event end, and samples */
	event = ntohl(*((unsigned int *)(pdata)));
	event >>= 24;
	event_end = ntohl(*((unsigned int *)(pdata)));
	event_end <<= 8;
	event_end >>= 24;
	samples = ntohl(*((unsigned int *)(pdata)));
	samples &= 0xFFFF;

	if(dtmfdebug) syslog(LOG_ERR, "Got  RTP RFC2833 from %u (seq %-6.6u, ts %-6.6u, len %-6.6u, mark %d, event %08x, end %d, duration %-5.5d) \n",
		    getMarker(), seqno, timestamp, len, (getMarker()?1:0), event, ((event_end & 0x80)?1:0), samples);

	/* Figure out what digit was pressed */
	if (event < 10) {
		resp = '0' + event;
	} else if (event < 11) {
		resp = '*';
	} else if (event < 12) {
		resp = '#';
	} else if (event < 16) {
		resp = 'A' + (event - 12);
	} else if (event < 17) {	/* Event 16: Hook flash */
		resp = 'X';
	} else {
		/* Not a supported event */
		//syslog(LOG_ERR, "Ignoring RTP 2833 Event: %08x. Not a DTMF Digit.\n", event);
		return;
	}

	if ((last_end_timestamp != timestamp) || (lastdtmf && lastdtmf != resp)) {
		lastdtmf = resp;
		if(dtmfdebug) syslog(LOG_ERR, "dtmfevent %c\n", resp);
		last_end_timestamp = timestamp;
		Call *owner = (Call*)call_owner;
		if(owner) {
			owner->handle_dtmf(resp, ts2double(header->ts.tv_sec, header->ts.tv_usec), saddr, daddr);
		}
	}

        return;
}

/* read rtp packet */
void
RTP::read(unsigned char* data, int len, struct pcap_pkthdr *header,  u_int32_t saddr, u_int32_t daddr, u_int16_t sport, u_int16_t dport, int seeninviteok, int sensor_id, char *ifname) {
	this->data = data; 
	this->len = len;
	this->header = header;
	this->saddr =  saddr;
	this->daddr =  daddr;
	this->dport = dport;
	this->ignore = 0;
	
	if(sverb.read_rtp) {
		cout << "RTP - read: " 
		     << "ssrc:" << hex << this->ssrc << dec << " "
		     << "seq:" << getSeqNum() << " "
		     << "saddr/sport:" << inet_ntostring(htonl(saddr)) << " / " << sport << " "
		     << "daddr/dport:" << inet_ntostring(htonl(daddr)) << " / " << dport << " "
		     << (this->iscaller ? "caller" : "called") 
		     << " packets received: " << this->stats.received
		     << endl;
	}
	
	if(this->sensor_id >= 0 && this->sensor_id != sensor_id) {
		u_long actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			syslog(5 /*LOG_NOTICE*/, "warning - packet from sensor (%i) in RTP created for sensor (%i)",
			       sensor_id, this->sensor_id);
			lastTimeSyslog = actTime;
		}
		return;
	}
	
	if(this->first_packet_time == 0 and this->first_packet_usec == 0) {
		this->first_packet_time = header->ts.tv_sec;
		this->first_packet_usec = header->ts.tv_usec;
	}

	unsigned int payload_len = get_payload_len();

	Call *owner = (Call*)call_owner;

	if(sverb.ssrc and getSSRC() != sverb.ssrc) return;

	if(getVersion() != 2) {
		return;
	}

	seq = getSeqNum();

	if(seq == last_seq) {
		// ignore duplicated RTP packets
		return;
	}

	if(opt_rtp_check_timestamp) {
		if(this->_last_ts.tv_sec &&
		   (header->ts.tv_sec < this->_last_ts.tv_sec ||
		    (header->ts.tv_sec == this->_last_ts.tv_sec &&
		     header->ts.tv_usec < this->_last_ts.tv_usec))) {
			u_long actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(5 /*LOG_NOTICE*/, "warning - bad packet order (%llu us) in RTP::read (seq/lastseq: %u/%u, ifname/lastifname: %s/%s, sensor/lastsenspor: %i/%i)- packet ignored",
				       this->_last_ts.tv_sec * 1000000ull + this->_last_ts.tv_usec - header->ts.tv_sec * 1000000ull - header->ts.tv_usec,
				       seq, last_seq,
				       ifname && ifname[0] ? ifname : "--", this->_last_ifname[0] ? this->_last_ifname : "--",
				       sensor_id, this->_last_sensor_id);
				lastTimeSyslog = actTime;
			}
			return;
		}
		this->_last_ts = header->ts;
		this->_last_sensor_id = sensor_id;
		if(ifname) {
			strcpy(this->_last_ifname, ifname);
		} else {
			this->_last_ifname[0] = 0;
		}
	}
	
	int curpayload = getPayload();

	if((codec == -1 || (curpayload != prev_payload))) {
		if(curpayload >= 96 && curpayload <= 127) {
			/* for dynamic payload we look into rtpmap */
			int found = 0;
			for(int i = 0; i < MAX_RTPMAP; i++) {
				if(rtpmap[i] != 0 && curpayload == rtpmap[i] / 1000) {
					codec = rtpmap[i] - curpayload * 1000;
					found = 1;
				}
			}
			if(curpayload == 101 and !found) {
				// payload 101 was not in SDP, assume it is televent 
				codec = PAYLOAD_TELEVENT;
			}
		} else {
			codec = curpayload;
		}
	}

	/* in case there was packet loss we must predict lastTimeStamp to not add nonexistant delays */
	forcemark = 0;
	if(last_seq != 0 and ((last_seq + 1) != seq)) {
		if(s->lastTimeStamp == getTimestamp() - samplerate / 1000 * packetization) {
			// there was packet loss but the timestamp is like there was no packet loss 

			if(opt_jitterbuffer_adapt) {
				ast_jb_empty_and_reset(channel_adapt);
				ast_jb_destroy(channel_adapt);
			}
			if(opt_jitterbuffer_f1) {
				ast_jb_empty_and_reset(channel_fix1);
				ast_jb_destroy(channel_fix1);
			}
			if(opt_jitterbuffer_f2) {
				ast_jb_empty_and_reset(channel_fix2);
				ast_jb_destroy(channel_fix2);
			}

			forcemark = 1;
		} 
	
		// this fixes jumps in .graph in case of pcaket loss 	
		s->lastTimeStamp = getTimestamp() - samplerate / 1000 * packetization;
		struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(packetization, 1000));
		memcpy(&s->lastTimeRec, &tmp, sizeof(struct timeval));
	}

	if(getMarker()) {
		s->lastTimeStamp = getTimestamp() - samplerate / 1000 * packetization;
		struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(packetization, 1000));
		memcpy(&s->lastTimeRec, &tmp, sizeof(struct timeval));
		s->cycles = s->cycles - s->base_seq + s->max_seq;
		s->base_seq = seq;
		s->max_seq = seq;
	}

	if(lastframetype == AST_FRAME_DTMF and codec != PAYLOAD_TELEVENT) {
		// last frame was DTMF and now we have voice. Reset jitterbuffers (case 338f884b17f9e5de6c830c237dcc09dd) 
		if(opt_jitterbuffer_adapt) {
			ast_jb_empty_and_reset(channel_adapt);
			ast_jb_destroy(channel_adapt);
		}
		if(opt_jitterbuffer_f1) {
			ast_jb_empty_and_reset(channel_fix1);
			ast_jb_destroy(channel_fix1);
		}
		if(opt_jitterbuffer_f2) {
			ast_jb_empty_and_reset(channel_fix2);
			ast_jb_destroy(channel_fix2);
		}
	}

	// ignore CNG
	if(curpayload == 13 or curpayload == 19) {
		last_seq = seq;
		if(update_seq(seq)) {
			update_stats();
		}
		prev_payload = curpayload;
		prev_codec = codec;
		lastframetype = AST_FRAME_VOICE;
		lastcng = 1;
		return;
	}
	if(curpayload == PAYLOAD_G729 and (payload_len <= (packetization == 10 or packetization == 0 ? 9 : 12) or payload_len == 22)) {
		last_seq = seq;
		if(update_seq(seq)) {
			update_stats();
		}
		lastframetype = AST_FRAME_VOICE;
		lastcng = 1;
		return;
	}
	if(codec == PAYLOAD_TELEVENT) {
		process_dtmf_rfc2833();
		last_seq = seq;
		if(update_seq(seq)) {
			update_stats();
		}
		prev_payload = curpayload;
		prev_codec = codec;
		lastframetype = AST_FRAME_DTMF;
		lastcng = 0;
		return;
	}

	if(!owner) { 
		lastcng = 0;
		return;
	}

/* this breaks 4 RTP streams (7b3fa6fb57a719f036fddfbf351234fe pcap sample) and it is not needed anymore (31955aa570d1f71624cea503052de62c)
	if(iscaller) {
		if(owner->lastcallerrtp and owner->lastcallerrtp != this) {
			// reset last sequence 
			s->cycles = s->cycles - s->base_seq + s->max_seq;
			s->base_seq = seq;
			s->max_seq = seq - 1;
		}
	} else {
		if(owner->lastcalledrtp and owner->lastcalledrtp != this) {
			s->cycles = s->cycles - s->base_seq + s->max_seq;
			s->base_seq = seq;
			s->max_seq = seq - 1;
		}
	}
*/

	if(owner->forcemark[iscaller]) {
		// on reinvite (which indicates forcemark[iscaller] completely reset rtp jitterbuffer simulator and 
		// there are cases where on reinvite rtp stream stops and there is gap in rtp sequence and timestamp but 
		// since it was reinvite the stream just continues as expected
		if(opt_jitterbuffer_adapt) {
			ast_jb_empty_and_reset(channel_adapt);
			ast_jb_destroy(channel_adapt);
		}
		if(opt_jitterbuffer_f1) {
			ast_jb_empty_and_reset(channel_fix1);
			ast_jb_destroy(channel_fix1);
		}
		if(opt_jitterbuffer_f2) {
			ast_jb_empty_and_reset(channel_fix2);
			ast_jb_destroy(channel_fix2);
		}

		owner->forcemark[iscaller] = 0;
		forcemark  = 1;

		// this fixes jumps in .graph in case of pcaket loss 	
		s->lastTimeStamp = getTimestamp() - samplerate / 1000 * packetization;
		struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(packetization, 1000));
		memcpy(&s->lastTimeRec, &tmp, sizeof(struct timeval));

		// reset last sequence 
		s->cycles = s->cycles - s->base_seq + s->max_seq;
		s->base_seq = seq;
		s->max_seq = seq;
	}

	// codec changed 
	if(curpayload != prev_payload and codec != PAYLOAD_TELEVENT and prev_codec != PAYLOAD_TELEVENT and codec != 13 and codec != 19 and prev_codec != 13 and prev_codec != 19) {
		switch(codec) {
		case PAYLOAD_SILK12:
		case PAYLOAD_OPUS12:
		case PAYLOAD_G722112:
			samplerate = 12000;
			break;
		case PAYLOAD_ISAC16:
		case PAYLOAD_SILK16:
		case PAYLOAD_OPUS16:
		case PAYLOAD_G722116:
			samplerate = 16000;
			break;
		case PAYLOAD_SILK24:
		case PAYLOAD_OPUS24:
		case PAYLOAD_G722124:
			samplerate = 24000;
			break;
		case PAYLOAD_ISAC32:
		case PAYLOAD_G722132:
			samplerate = 32000;
			break;
		case PAYLOAD_OPUS48:
		case PAYLOAD_G722148:
			samplerate = 48000;
			break;
		default: 
			samplerate = 8000;
		}

		if(iscaller) {
			owner->last_callercodec = codec;
		} else {
			owner->last_calledcodec = codec;
		}

		if(opt_saveRAW || opt_savewav_force || (owner && (owner->flags & FLAG_SAVEWAV)) ||
			(owner && (owner->audiobuffer1 || owner->audiobuffer2))// if recording requested 
		) {
//			if(verbosity > 0) syslog(LOG_ERR, "converting WAV! [%u]\n", owner->flags);
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
					prevrtp->ignore = 1; 
					prevrtp->data = data; 
					prevrtp->len = len;
					prevrtp->header = header;
					prevrtp->saddr = saddr;
					prevrtp->daddr = daddr;
					prevrtp->dport = dport;
					prevrtp->codec = prevrtp->prev_codec;
					if(owner->flags & FLAG_RUNAMOSLQO or owner->flags & FLAG_RUNBMOSLQO) {
						// MOS LQO is calculated only if the call is connected 
						if(owner->connect_time) {
							prevrtp->jitterbuffer(prevrtp->channel_record, opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) || (owner && (owner->audiobuffer1 || owner->audiobuffer2)));
						}
					} else {
						prevrtp->jitterbuffer(prevrtp->channel_record, opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) || (owner && (owner->audiobuffer1 || owner->audiobuffer2)));
					}
				}
			}
			for(int passOpen = 0; passOpen < 2; passOpen++) {
				if(passOpen == 1) {
					char *pointToLastDirSeparator = strrchr(tmp, '/');
					if(pointToLastDirSeparator) {
						*pointToLastDirSeparator = 0;
						mkdir_r(tmp, 0777);
						*pointToLastDirSeparator = '/';
					} else {
						break;
					}
				}
				gfileRAW = fopen(tmp, "w");
				if(gfileRAW) {
					break;
				}
			}
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

	if(first_codec < 0 && codec != PAYLOAD_TELEVENT && codec != 13 && codec != 19) {
		/* save payload to statistics based on first payload. TODO: what if payload is dynamically changing? */
		first_codec = codec;
		if(owner->first_codec < 0) {
			owner->first_codec = codec;
		}
	}

	if(codec == PAYLOAD_TELEVENT) {
		frame->frametype = AST_FRAME_DTMF;
	} else {
		frame->frametype = AST_FRAME_VOICE;
	}
	frame->lastframetype = (enum ast_frame_type)(lastframetype);

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
		if(last_ts != 0 && seq == (last_seq + 1) && (prev_codec != PAYLOAD_TELEVENT && codec != PAYLOAD_TELEVENT) && !sid && !prev_sid) {
			// sequence numbers are ok, we can calculate packetization
			if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(payload_len == 20) {
					packetization = 20;
				} else if(payload_len == 10) {
					packetization = 10;
				} else {
					packetization = (getTimestamp() - last_ts) / 8;
				}
			} else if(curpayload == PAYLOAD_G723) {
				if(payload_len == 24) {
					packetization = 30;
				} else if(payload_len == 24*2) {
					packetization = 60;
				} else if(payload_len == 24*3) {
					packetization = 90;
				}
			} else {
				packetization = (getTimestamp() - last_ts) / (samplerate / 1000);
			}
			if(packetization > 0) {
				last_packetization = packetization;
				packetization_iterator++;
			}
		}

#if 1
		// new way of getting packetization from packet datalen 
		if(curpayload == PAYLOAD_PCMU or curpayload == PAYLOAD_PCMA) {

			channel_fix1->packetization = default_packetization = 
				channel_fix2->packetization = channel_adapt->packetization = 
				channel_record->packetization = packetization = payload_len / 8;

			if(packetization >= 10) {
				if(verbosity > 3) printf("packetization:[%d] ssrc[%x]\n", packetization, getSSRC());

				packetization_iterator = 10; // this will cause that packetization is estimated as final

				if(opt_jitterbuffer_f1)
					jitterbuffer(channel_fix1, 0);
				if(opt_jitterbuffer_f2)
					jitterbuffer(channel_fix2, 0);
				if(opt_jitterbuffer_adapt)
					jitterbuffer(channel_adapt, 0);
			} 

		} 

		// new way of getting packetization from packet datalen 
		if(curpayload == PAYLOAD_GSM) {

			channel_fix1->packetization = default_packetization = 
				channel_fix2->packetization = channel_adapt->packetization = 
				channel_record->packetization = packetization = payload_len / 33 * 20;

			if(packetization >= 10) {
				if(verbosity > 3) printf("packetization:[%d] ssrc[%x]\n", packetization, getSSRC());

				packetization_iterator = 10; // this will cause that packetization is estimated as final

				if(opt_jitterbuffer_f1)
					jitterbuffer(channel_fix1, 0);
				if(opt_jitterbuffer_f2)
					jitterbuffer(channel_fix2, 0);
				if(opt_jitterbuffer_adapt)
					jitterbuffer(channel_adapt, 0);
			} 

		} 
#endif

		/* for recording, we cannot loose any packet */
		if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) || (owner && (owner->audiobuffer1 || owner->audiobuffer2))) { // if recording requested 
			if(packetization < 10) {
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(payload_len == 20) {
						packetization = channel_record->packetization = 20;
					} else if(payload_len == 10) {
						packetization = channel_record->packetization = 10;
					} else {
						packetization = channel_record->packetization = default_packetization;
					}
				} else {
					packetization = channel_record->packetization = default_packetization;
				}
			}
			if(owner->flags & FLAG_RUNAMOSLQO or owner->flags & FLAG_RUNBMOSLQO) {
				if(owner->connect_time) {
					jitterbuffer(channel_record, opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) || (owner && (owner->audiobuffer1 || owner->audiobuffer2)));
				}
			} else {
				jitterbuffer(channel_record, opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) || (owner && (owner->audiobuffer1 || owner->audiobuffer2)));
			}
		}
	} else if(packetization_iterator == 1) {
		if(last_ts != 0 && seq == (last_seq + 1) && codec != PAYLOAD_TELEVENT && prev_codec != PAYLOAD_TELEVENT && !sid && !prev_sid) {
			// sequence numbers are ok, we can calculate packetization
			if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(payload_len == 20) {
					packetization = 20;
				} else if(payload_len == 10) {
					packetization = 10;
				} else {
					packetization = (getTimestamp() - last_ts) / 8;
				}
			} else {
				packetization = (getTimestamp() - last_ts) / (samplerate / 1000);
			}

			// now make packetization average
			packetization = (packetization + last_packetization) / 2;

			if(packetization <= 0 or getMarker()) {
				// packetization failed or Marker bit is set, fall back to start
				packetization_iterator = 0;

				/* for recording, we cannot loose any packet */
				if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
					(owner && (owner->audiobuffer1 || owner->audiobuffer2))// if recording requested 
				){
					packetization = channel_record->packetization = default_packetization;
					if(owner->flags & FLAG_RUNAMOSLQO or owner->flags & FLAG_RUNBMOSLQO) {
						if(owner->connect_time) {
							jitterbuffer(channel_record, 1);
						}
					} else {
						jitterbuffer(channel_record, 1);
					}
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
					(owner && (owner->audiobuffer1 || owner->audiobuffer2))// if recording requested 
				){
					if(owner->flags & FLAG_RUNAMOSLQO or owner->flags & FLAG_RUNBMOSLQO) {
						if(owner->connect_time) {
							jitterbuffer(channel_record, 1);
						}
					} else {
						jitterbuffer(channel_record, 1);
					}
				}
			}
		} else {
			packetization_iterator = 0;
			/* for recording, we cannot loose any packet */
			if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
				(owner && (owner->audiobuffer1 || owner->audiobuffer2))// if recording requested 
			){
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(payload_len == 20) {
						packetization = channel_record->packetization = 20;
					} else if(payload_len == 10) {
						packetization = channel_record->packetization = 10;
					} else {
						packetization = channel_record->packetization = default_packetization;
					}
				} else {
					packetization = channel_record->packetization = default_packetization;
				}

				if(owner->flags & FLAG_RUNAMOSLQO or owner->flags & FLAG_RUNBMOSLQO) {
					if(owner->connect_time) {
						jitterbuffer(channel_record, 1);
					}
				} else {
					jitterbuffer(channel_record, 1);
				}
			}
		}
	} else {
		if(last_ts != 0 and seq == (last_seq + 1) and codec != PAYLOAD_TELEVENT and !getMarker()) {
			// packetization can change over time
			int curpacketization = 0;

			if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(payload_len == 20) {
					curpacketization = 20;	
				} else if(payload_len == 10) {
					curpacketization = 10;	
				} else {
					curpacketization = (getTimestamp() - last_ts) / 8;
				}
			} else if(curpayload == PAYLOAD_G723) {
				if(payload_len == 24) {
					curpacketization = 30;	
				} else if(payload_len == 24*2) {
					curpacketization = 60;
				} else if(payload_len == 24*3) {
					curpacketization = 90;
				}
			} else if(curpayload == PAYLOAD_PCMU or curpayload == PAYLOAD_PCMA) {
				if((payload_len / 8) >= 20) {
					// do not change packetization to 10ms frames. Case g711_20_10_sync.pcap
					curpacketization = payload_len / 8;
				}
			} else if(curpayload == PAYLOAD_GSM) {
				curpacketization = payload_len / 33 * 20;
			} else {
				curpacketization = (getTimestamp() - last_ts) / (samplerate / 1000);
				if(verbosity > 3) printf("curpacketization = (getTimestamp()[%u] - last_ts[%u]) / (samplerate[%u] / 1000)", getTimestamp(), last_ts, samplerate);
			}

			if(curpacketization != packetization and curpacketization % 10 == 0 and curpacketization >= 10 and curpacketization <= 120) {
				if(verbosity > 3) printf("[%x] changing packetization:[%d]->[%d]\n", getSSRC(), curpacketization, packetization);
				channel_fix1->packetization = channel_fix2->packetization = channel_adapt->packetization = channel_record->packetization = packetization = curpacketization;
			}

		}
		//printf("packetization [%d]\n", packetization);
		if(opt_jitterbuffer_f1)
			jitterbuffer(channel_fix1, 0);
		if(opt_jitterbuffer_f2)
			jitterbuffer(channel_fix2, 0);
		if(opt_jitterbuffer_adapt)
			jitterbuffer(channel_adapt, 0);
		if(opt_saveRAW || opt_savewav_force || (owner->flags & FLAG_SAVEWAV) ||
			(owner && (owner->audiobuffer1 || owner->audiobuffer2))// if recording requested 
		){
			if(owner->flags & FLAG_RUNAMOSLQO or owner->flags & FLAG_RUNBMOSLQO) {
				if(owner->connect_time) {
					jitterbuffer(channel_record, 1);
				}
			} else {
				jitterbuffer(channel_record, 1);
			}
		}
	}

	prev_payload = curpayload;
	prev_codec = codec;
	prev_sid = sid;


	// FAX T.30 detection if enabled
	if(opt_faxt30detect and frame->frametype == AST_FRAME_VOICE and (codec == 0 or codec == 8)) {
		int res;
		if(!DSP) DSP = dsp_new();
		char event_digit;
		int event_len;
		short int *sdata = (short int*)malloc(payload_len * 2);
		char *payload = (char*)data + sizeof(RTPFixedHeader);
		if(codec == 0) {
			for(unsigned int i = 0; i < payload_len; i++) {
				sdata[i] = ULAW((unsigned char)payload[i]);
			}
		} else if(codec == 8) {
			for(unsigned int i = 0; i < payload_len; i++) {
				sdata[i] = ALAW((unsigned char)payload[i]);
			}
		}
		res = dsp_process(DSP, sdata, payload_len, &event_digit, &event_len);
		if(res) {
			if(owner and (event_digit == 'f' or event_digit == 'e')) {
				//printf("dsp_process: digit[%c] len[%u]\n", event_digit, event_len);
				owner->isfax = 2;
				owner->flags1 |= T30FAX;
			}
		}
	}

	if(getMarker()) {
		// if RTP packet is Marked, we have to reset last_ts to 0 so in next cycle it will count packetization from ground
		last_ts = 0;
	} else {
		last_ts = getTimestamp();
	}

	if(update_seq(seq)) {
		update_stats();
	}
	lastframetype = frame->frametype;
	last_seq = seq;
	lastcng = 0;
}

/* fill internal structures by the input RTP packet */
void
RTP::fill(unsigned char* data, int len, struct pcap_pkthdr *header,  u_int32_t saddr, u_int32_t daddr, u_int16_t sport, u_int16_t dport) {
	this->data = data; 
	this->len = len;
	this->header = header;
	this->saddr = saddr;
	this->daddr = daddr;
	this->dport = dport;
}

/* update statistics data */
void
RTP::update_stats() {
	
	int lost = int((s->cycles + s->max_seq - (s->base_seq + 1)) - s->received);
	int adelay = 0;
	struct timeval tsdiff;	
	double tsdiff2;
	static double mx = 0;

//	printf("seq[%d] lseq[%d] lost[%d], ((s->cycles[%d] + s->max_seq[%d] - (s->base_seq[%d] + 1)) - s->received[%d]);\n", seq, last_seq, lost, s->cycles, s->max_seq, s->base_seq, s->received);

	Call *owner = (Call*)call_owner;

	/* if payload == PAYLOAD_TELEVENT dont make delayes on this because it confuses stats */
	if(codec == PAYLOAD_TELEVENT or lastframetype == AST_FRAME_DTMF) {
		s->lastTimeStamp = getTimestamp();
		memcpy(&s->lastTimeRec, &header->ts, sizeof(struct timeval));
		return;
	}

	/* differences between last timestamp and current timestamp (timestamp from ip heade)
	 * frame1.time - frame0.time */
	tsdiff2 = timeval_subtract(&tsdiff, header->ts, s->lastTimeRec) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0;

	long double transit = tsdiff2 - (double)(getTimestamp() - s->lastTimeStamp)/((double)samplerate/1000.0);
	mx += transit;
	
	if(abs((int)transit) > 5000) {
		/* timestamp skew, discard delay, it is possible that timestamp changed  */
		s->fdelay = s->avgdelay;
		//s->fdelay = 0;
		transit = 0;
	} else {
		adelay = abs(int(transit));
		s->fdelay += transit;
	}
//	printf("seq[%u] adelay[%u]\n", seq, adelay);

	/* Jitterbuffer calculation
	 * J(1) = J(0) + (|D(0,1)| - J(0))/16 */
	if(transit < 0) transit = -transit;
	double jitter = s->prevjitter + (double)(transit - s->prevjitter)/16. ;
	s->prevjitter = jitter;

	s->avgdelay = ((s->avgdelay * (long double)(s->received) - 1) + transit ) / (double)s->received;
	stats.avgjitter = ((stats.avgjitter * ( stats.received - 1 )  + jitter )) / (double)s->received;
	if(stats.maxjitter < jitter) stats.maxjitter = jitter;
	s->lastTimeRec = header->ts;
	s->lastTimeRecJ = header->ts;
	s->lastTimeStamp = getTimestamp();
	s->lastTimeStampJ = getTimestamp();

	// store mark bit in graph file
	if(getMarker() and owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpen()) {
		this->graph.write((char*)&graph_mark, 4);
	}
		
	if((lost > stats.last_lost) > 0) {
		if(sverb.packet_lost) {
			cout << "RTP - packet_lost: " 
			     << "ssrc:" << hex << this->ssrc << dec << " "
			     << "saddr:" << inet_ntostring(htonl(this->saddr)) << " " 
			     << "daddr/dport:" << inet_ntostring(htonl(this->daddr)) << " / " << this->dport << " " 
			     << "lost:" << (lost - stats.last_lost) << endl;
		}
		stats.lost += lost - stats.last_lost;
		if((lost - stats.last_lost) < 10)
			stats.slost[lost - stats.last_lost]++;
		else 
			stats.slost[10]++;

		if(owner && (owner->flags & FLAG_SAVEGRAPH)) {
			nintervals += lost - stats.last_lost;
			while(nintervals > 20) {
				if(this->graph.isOpen()) {
					this->graph.write((char*)&graph_delimiter, 4);
				}
				nintervals -= 20;
			}
		}
	} else {
		if(owner && (owner->flags & FLAG_SAVEGRAPH)) {
			if(this->graph.isOpen()) {
				if(nintervals > 20) {
					/* after 20 packets, send new line */
					this->graph.write((char*)&graph_delimiter, 4);
					nintervals -= 20;
				}
				float tmp = s->fdelay;
				if(tmp == graph_delimiter) tmp = graph_delimiter - 1;
				this->graph.write((char*)&tmp, 4);
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
	if(first) {
		first = false;
		init_seq(seq);
		s->max_seq = seq - 1;
		s->probation = MIN_SEQUENTIAL;
		s->lastTimeRec = header->ts;
		s->lastTimeRecJ = header->ts;
		s->lastTimeStamp = getTimestamp();
		s->lastTimeStampJ = getTimestamp();
		return 0;
	}

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
	for(int i = 0; i <= 500; i++) {
		lost += i * chan->loss[i];
		bursts += chan->loss[i];
		if((verbosity > 4 or sverb.jitter) and chan->loss[i] > 0) printf("bc loss[%d]: %d\t", i, chan->loss[i]);
	}

	if(lost < 5) {
		// ignore such small packet loss 
		*lossr = *burstr = 0;
		return;
	}

	if(verbosity > 4 or sverb.jitter) printf("\n");
	if(received > 0 && bursts > 0) {
		*burstr = (double)((double)lost / (double)bursts) / (double)(1.0 / ( 1.0 - (double)lost / (double)received ));
		if(sverb.jitter) printf("*burstr[%f] = (lost[%u] / bursts[%u]) / (1 / ( 1 - lost[%u] / received[%u]\n", *burstr, lost, bursts, lost, received);
		if(*burstr < 0) {
			*burstr = - *burstr;
		} else if(*burstr < 1) {
			*burstr = 1;
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
	if(sverb.jitter) printf("burstr: %f lossr: %f\n", *burstr, *lossr);
}

/* for debug purpose */
void
RTP::dump() {
	int i;
	printf("SSRC:%x %u ssrc_index[%d]\n", ssrc, ssrc, ssrc_index);
	printf("codec:%d\n", first_codec);
	printf("src ip:%u\n", saddr);
	printf("dst ip:%u\n", daddr);
	printf("dst port:%u\n", dport);
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

void RTP::clearAudioBuff(Call *call, ast_channel *channel) {
	if(iscaller) {
		if(call->audiobuffer1) {
			channel->audiobuf = NULL;
		}
	} else {
		if(call->audiobuffer2) {
			channel->audiobuf = NULL;
		}
	}
}

