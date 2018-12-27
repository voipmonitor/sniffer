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
#include <math.h>

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
#include "mos_g729.h"   
#include "sql_db.h"   
#include "srtp.h"

#include "jitterbuffer/asterisk/channel.h"
#include "jitterbuffer/asterisk/frame.h"
#include "jitterbuffer/asterisk/abstract_jb.h"
#include "jitterbuffer/asterisk/strings.h"

int dtmfdebug = 0;

extern int verbosity;
extern int opt_saveRAW;                //save RTP payload RAW data?
extern int opt_saveWAV;                //save RTP payload RAW data?
extern int opt_saveGRAPH;	//save GRAPH data?
extern bool opt_srtp_rtp_decrypt;
extern FileZipHandler::eTypeCompress opt_gzipGRAPH;	//save gzip GRAPH data?
extern int opt_jitterbuffer_f1;            // turns off/on jitterbuffer simulator to compute MOS score mos_f1
extern int opt_jitterbuffer_f2;            // turns off/on jitterbuffer simulator to compute MOS score mos_f2
extern int opt_jitterbuffer_adapt;         // turns off/on jitterbuffer simulator to compute MOS score mos_adapt
extern char opt_cachedir[1024];
extern int opt_savewav_force;
extern int opt_rtp_check_timestamp;
extern int opt_mos_g729;
extern unsigned int graph_delimiter;
extern unsigned int graph_mark;
extern unsigned int graph_mos;
extern unsigned int graph_silence;
extern unsigned int graph_event;
extern int opt_faxt30detect;
extern int opt_inbanddtmf;
extern int opt_silencedetect;
extern int opt_clippingdetect;
extern int opt_fasdetect;
extern char opt_pb_read_from_file[256];
extern int opt_read_from_file;
extern SqlDb *sqlDbSaveCall;
extern int opt_mysqlstore_max_threads_cdr;
extern MySqlStore *sqlStore;
extern int opt_id_sensor;
extern bool opt_saveaudio_answeronly;
extern bool opt_saveaudio_big_jitter_resync_threshold;
extern int opt_mysql_enable_multiple_rows_insert;
extern int opt_mysql_max_multiple_rows_insert;

RTPstat rtp_stat;

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
	case PAYLOAD_XOPUS:
	case PAYLOAD_XOPUS8:
	case PAYLOAD_VXOPUS:
	case PAYLOAD_VXOPUS8:
		return 8;
		break;
	case PAYLOAD_XOPUS12:
	case PAYLOAD_VXOPUS12:
	case PAYLOAD_OPUS12:
		return 12;
		break;
	case PAYLOAD_XOPUS16:
	case PAYLOAD_VXOPUS16:
	case PAYLOAD_OPUS16:
		return 16;
		break;
	case PAYLOAD_XOPUS24:
	case PAYLOAD_VXOPUS24:
	case PAYLOAD_OPUS24:
		return 24;
		break;
	case PAYLOAD_XOPUS48:
	case PAYLOAD_VXOPUS48:
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
	case PAYLOAD_AMRWB:
		return 16;
		break;
	default:
		return 8;
	}
}

/* constructor */
RTP::RTP(int sensor_id, u_int32_t sensor_ip) 
 : graph(this) {
	counter = 0;
	DSP = NULL;
	samplerate = 8000;
	first = true;
	first_packet_time = 0;
	first_packet_usec = 0;
	s = new FILE_LINE(24001) source;
	memset(s, 0, sizeof(source));
	memset(&stats, 0, sizeof(stats));
	memset(&rtcp, 0, sizeof(rtcp));
	memset(&rtcp_xr, 0, sizeof(rtcp_xr));
	rtcp_xr.minmos = 45;
	nintervals = 1;
	saddr = 0;
	daddr = 0;
	sport = 0;
	dport = 0;
	prev_sport = 0;
	prev_dport = 0;
	change_src_port = false;
	find_by_dest = false;
	ok_other_ip_side_by_sip = false;
	ssrc = 0;
	ssrc2 = 0;
	gfilename[0] = '\0';
	gfileRAW = NULL;
	last_interval_mosf1 = 45;
	last_interval_mosf2 = 45;
	last_interval_mosAD = 45;
	mosf1_min = 45;
	mosf2_min = 45;
	mosAD_min = 45;
	mosf1_avg = 0;
	mosf2_avg = 0;
	mosAD_avg = 0;
	mos_counter = 0;
	resetgraph = false;
	jitter = 0;
	last_stat_lost = 0;
	last_stat_received = 0;
	last_stat_loss_perc_mult10 = 0;
	codecchanged = false;
	had_audio = false;

	channel_fix1 = new FILE_LINE(24002) ast_channel;
	memset(channel_fix1, 0, sizeof(ast_channel));
	channel_fix1->jitter_impl = 0; // fixed
	channel_fix1->jitter_max = 50; 
	channel_fix1->jitter_resync_threshold = 100;
	channel_fix1->last_datalen = 0;
	channel_fix1->lastbuflen = 0;
	channel_fix1->resync = 1;
	channel_fix1->audiobuf = NULL;

	channel_fix2  = new FILE_LINE(24003) ast_channel;
	memset(channel_fix2, 0, sizeof(ast_channel));
	channel_fix2->jitter_impl = 0; // fixed
	channel_fix2->jitter_max = 200; 
	channel_fix2->jitter_resync_threshold = 200; 
	channel_fix2->last_datalen = 0;
	channel_fix2->lastbuflen = 0;
	channel_fix2->resync = 1;
	channel_fix2->audiobuf = NULL;

	channel_adapt = new FILE_LINE(24004) ast_channel;
	memset(channel_adapt, 0, sizeof(ast_channel));
	channel_adapt->jitter_impl = 1; // adaptive
	channel_adapt->jitter_max = 500; 
	channel_adapt->jitter_resync_threshold = 500; 
	channel_adapt->last_datalen = 0;
	channel_adapt->lastbuflen = 0;
	channel_adapt->resync = 1;
	channel_adapt->audiobuf = NULL;

	channel_record = new FILE_LINE(24005) ast_channel;
	memset(channel_record, 0, sizeof(ast_channel));
	channel_record->jitter_impl = 0; // fixed
	channel_record->jitter_max = 60; 
	channel_record->jitter_resync_threshold = opt_saveaudio_big_jitter_resync_threshold ? 5000 : 1000; 
	channel_record->last_datalen = 0;
	channel_record->lastbuflen = 0;
	channel_record->resync = 0;
	channel_record->audiobuf = NULL;
	last_mos_time = 0;
	mos_processed = false;
	save_mos_graph_wait = false;

	last_voice_frame_ts.tv_sec = 0;
	last_voice_frame_ts.tv_usec = 0;
	last_voice_frame_timestamp = 0;

	//channel->name = "SIP/fixed";
	frame = new FILE_LINE(24006) ast_frame;
	memset(frame, 0, sizeof(ast_frame));
	frame->frametype = AST_FRAME_VOICE;
	lastframetype = AST_FRAME_VOICE;
	//frame->src = "DUMMY";
	last_seq = 0;
	for(unsigned i = 0; i < sizeof(channel_record_seq_ringbuffer) / sizeof(channel_record_seq_ringbuffer[0]); i++) {
		channel_record_seq_ringbuffer[i] = 0;
	}
	channel_record_seq_ringbuffer_pos = 0;
	last_ts = 0;
	last_pcap_header_ts = 0;
	pcap_header_ts_bad_time = false;
	packetization = 0;
	last_packetization = 0;
	packetization_iterator = 0;
	first_codec = -1;
	prev_payload = -1;
	prev_codec = -1;
	payload2 = -1;
	codec = -1;
	frame_size = 0;
	gfileRAW_buffer = NULL;
	sid = false;
	prev_sid = false;
	call_owner = NULL;
	pinformed = 0;
	last_end_timestamp = 0;
	lastdtmf = 0;
	forcemark = 0;
	forcemark2 = 0;
	forcemark_by_owner = 0;
	forcemark_by_owner_set = 0;
	forcemark_owner_used = 0;
	ignore = 0;
	lastcng = 0;
	dscp = 0;
	
	this->sensor_id = sensor_id;
	this->sensor_ip = sensor_ip;
	this->index_call_ip_port = -1;
	this->index_call_ip_port_by_dest = false;
	
	this->_last_ts.tv_sec = 0;
	this->_last_ts.tv_usec = 0;
	this->_last_sensor_id = 0;
	this->_last_ifname[0] = 0;
	
	lastTimeSyslog = 0;
	avg_ptime = 0;
	avg_ptime_count = 0;

	last_markbit = 0;

	skip = false;
	stopReadProcessing = false;

	defer_codec_change = false;
	stream_in_multiple_calls = false;
	prev_payload_len = 0;
	padding_len = 0;
	tailedframes = 0;

	change_packetization_iterator = 0;
	srtp_decrypt = NULL;
}


void 
RTP::setSRtpDecrypt(RTPsecure *srtp_decrypt) {
	this->srtp_decrypt = srtp_decrypt;
}


void
RTP::save_mos_graph(bool delimiter) {
	Call *owner = (Call*)call_owner;

	if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
		this->graph.write((char*)&graph_mos, 4);
	}

	if(opt_jitterbuffer_f1 and channel_fix1) {
		last_interval_mosf1 = calculate_mos_fromrtp(this, 1, 1);

		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&last_interval_mosf1, 1);
		}
		// reset 10 second MOS stats
		memcpy(channel_fix1->last_interval_loss, channel_fix1->loss, sizeof(unsigned short int) * 128);
		if(mosf1_min > last_interval_mosf1) {
			mosf1_min = last_interval_mosf1;
		}
		mosf1_avg = ((mosf1_avg * mos_counter) + last_interval_mosf1) / (mos_counter + 1);
//		if(sverb.graph) printf("rtp[%p] saddr[%s] ts[%u] ssrc[%x] mosf1_avg[%f] mosf1[%u]\n", this, inet_ntostring(htonl(saddr)).c_str(), header->ts.tv_sec, ssrc, mosf1_avg, last_interval_mosf1);
	} else {
		last_interval_mosf1 = 45;
		mosf1_min = 45;
		mosf1_avg = 45;
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&last_interval_mosf1, 1);
		}
	}
	if(opt_jitterbuffer_f2 and channel_fix2) {
		last_interval_mosf2 = calculate_mos_fromrtp(this, 2, 1);
		//if(verbosity > 1) printf("mosf2[%d]\n", last_interval_mosf2);
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&last_interval_mosf2, 1);
		}
		// reset 10 second MOS stats
		memcpy(channel_fix2->last_interval_loss, channel_fix2->loss, sizeof(unsigned short int) * 128);
		if(mosf2_min > last_interval_mosf2) {
			mosf2_min = last_interval_mosf2;
		}
		mosf2_avg = ((mosf2_avg * mos_counter) + last_interval_mosf2) / (mos_counter + 1);
//		if(sverb.graph) printf("rtp[%p] saddr[%s] ts[%u] ssrc[%x] mosf2_avg[%f] mosf2[%u]\n", this, inet_ntostring(htonl(saddr)).c_str(), header->ts.tv_sec, ssrc, mosf2_avg, last_interval_mosf2);
	} else {
		last_interval_mosf2 = 45;
		mosf2_min = 45;
		mosf2_avg = 45;
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&last_interval_mosf2, 1);
		}
	}
	if(opt_jitterbuffer_adapt and channel_adapt) {
		last_interval_mosAD = calculate_mos_fromrtp(this, 3, 1);
		//if(verbosity > 1) printf("mosAD[%d]\n", last_interval_mosAD);
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&last_interval_mosAD, 1);
		}
		// reset 10 second MOS stats
		memcpy(channel_adapt->last_interval_loss, channel_adapt->loss, sizeof(unsigned short int) * 128);
		if(mosAD_min > last_interval_mosAD) {
			mosAD_min = last_interval_mosAD;
		}
		mosAD_avg = ((mosAD_avg * mos_counter) + last_interval_mosAD) / (mos_counter + 1);
//		if(sverb.graph) printf("rtp[%p] saddr[%s] ts[%u] ssrc[%x] mosAD_avg[%f] mosAD[%u]\n", this, inet_ntostring(htonl(saddr)).c_str(), header->ts.tv_sec, ssrc, mosAD_avg, last_interval_mosAD);
	} else {
		last_interval_mosAD = 45;
		mosAD_min = 45;
		mosAD_avg = 45;
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&last_interval_mosAD, 1);
		}
	}
	// align to 4 byte
	char zero = 0;
	if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
		this->graph.write((char*)&zero, 1);
	}
	
	if(delimiter) {
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&graph_delimiter, 4);
		}
	}
	mos_counter++;

	if(sverb.graph) printf("rtp[%p] saddr[%s] ssrc[%x] time[%u] seq[%u] \nMOS F1 cur[%d] min[%d] avg[%f]\nMOS F2 cur[%d] min[%d] avg[%f]\nMOS AD cur[%d] min[%d] avg[%f]\n ------\n", this, inet_ntostring(htonl(saddr)).c_str(), ssrc, (unsigned int)header_ts.tv_sec, seq, 
		last_interval_mosf1, mosf1_min, mosf1_avg,
		last_interval_mosf2, mosf2_min, mosf2_avg,
		last_interval_mosAD, mosAD_min, mosAD_avg
	);


	uint32_t lost = stats.lost2 - last_stat_lost;
	uint32_t received = stats.received - last_stat_received;

	last_stat_lost = lost;
	last_stat_received = received;

	last_stat_loss_perc_mult10 = (double)lost / ((double)received + (double)lost) * 100.0;

	if(!is_read_from_file_simple()) {
		rtp_stat.update(saddr, header_ts.tv_sec, last_interval_mosf1, last_interval_mosf2, last_interval_mosAD, jitter, last_stat_loss_perc_mult10);
	}
}

/* destructor */
RTP::~RTP() {
	/*
	if(packetization)
		RTP::dump();
	*/

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
	delete channel_fix1;
	delete channel_fix2;
	delete channel_adapt;
	delete channel_record;
	delete frame;

	if(gfileRAW_buffer) {
		delete [] gfileRAW_buffer;
	}

	if(DSP) {
		dsp_free(DSP);
	}
}

const int RTP::get_payload_len() {
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
		payload_len -= ((u_int8_t *)data)[len - 1];
		padding_len = ((u_int8_t *)data)[len - 1];
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
		// the extension, if present, is after the CSRC list.
		rtpext = (extension_hdr_t *)((u_int8_t *)payload_data);
		payload_data += sizeof(extension_hdr_t) + ntohs(rtpext->length);
		payload_len -= sizeof(extension_hdr_t) + ntohs(rtpext->length);

		if (payload_len < 2) {
			payload_data = data + sizeof(RTPFixedHeader);
			payload_len = 0;
		}

	}
	return payload_len;
}

/* flush jitterbuffer */
void RTP::jitterbuffer_fixed_flush(struct ast_channel */*jchannel*/) {
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
		tailedframes++;
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
		case PAYLOAD_VXOPUS12:
		case PAYLOAD_XOPUS12:
		case PAYLOAD_OPUS12:
		case PAYLOAD_G722112:
			frame->ts = getTimestamp() / 12;
			//frame->len = packetization * 2 / 3;
			break;
		case PAYLOAD_ISAC16:
		case PAYLOAD_SILK16:
		case PAYLOAD_VXOPUS16:
		case PAYLOAD_XOPUS16:
		case PAYLOAD_OPUS16:
		case PAYLOAD_G722116:
		case PAYLOAD_AMRWB:
			frame->ts = getTimestamp() / 16;
			//frame->len = packetization / 2;
			break;
		case PAYLOAD_SILK24:
		case PAYLOAD_VXOPUS24:
		case PAYLOAD_XOPUS24:
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
		case PAYLOAD_VXOPUS48:
		case PAYLOAD_XOPUS48:
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
	memcpy(&frame->delivery, &header_ts, sizeof(struct timeval));

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


	if(savePayload or (codec == PAYLOAD_G729 or codec == PAYLOAD_G723 or codec == PAYLOAD_AMR or codec == PAYLOAD_AMRWB)) {
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
			padding_len = ((u_int8_t *)data)[payload_len - 1];
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

			// the extension, if present, is after the CSRC list.
			rtpext = (extension_hdr_t *)((u_int8_t *)payload_data);
			payload_data += sizeof(extension_hdr_t) + ntohs(rtpext->length);
			payload_len -= sizeof(extension_hdr_t) + ntohs(rtpext->length);
			if (payload_len < 4) {
				payload_data = data + sizeof(RTPFixedHeader);
				payload_len = 0;
			}
			
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
		if((codec == PAYLOAD_AMR or codec == PAYLOAD_AMRWB) and payload_len <= 7) {
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
			owner->audioBufferData[0].set(&channel->audiobuf, frame->seqno, this->ssrc, &this->header_ts);
		} else {
			owner->codec_called = codec;
			owner->audioBufferData[1].set(&channel->audiobuf, frame->seqno, this->ssrc, &this->header_ts);
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
	ast_jb_do_usecheck(channel, &header_ts);
	if(channel->jb.timebase.tv_sec == header_ts.tv_sec &&
	   channel->jb.timebase.tv_usec == header_ts.tv_usec) {
		channel->last_ts = header_ts;
	}
	
	if(!channel->jb_reseted) {
		// initializing jitterbuffer 
		if(savePayload) {
			channel_record->jitter_max = frame->len * 3; 
		}
		
		ast_jb_empty_and_reset(channel);
		channel->jb_reseted = 1;
		memcpy(&channel->last_ts, &header_ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header_ts);
		this->clearAudioBuff(owner, channel);
		return;
	}

	/* calculate time difference between last packet and current packet + packetization time*/ 
	int msdiff = ast_tvdiff_ms( header_ts, ast_tvadd(channel->last_ts, ast_samp2tv(packetization, 1000)) );
	//printf("ms:%d\n", msdiff);
	if(msdiff > packetization * 10000) {
		// difference is too big, reseting last_ts to current packet. If we dont check this it could happen to run while cycle endlessly
		memcpy(&channel->last_ts, &header_ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header_ts);
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
	 * be ideally equal to zero. Negative values mean that packet arrives earlier and positive 
	 * values indicates that packet was late 
	 */
	long double transit = (timeval_subtract(&tsdiff, header_ts, s->lastTimeRecJ) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0) - ((double)getTimestamp() - s->lastTimeStampJ)/(double)samplerate/1000;
	
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
	ast_jb_put(channel, frame, &header_ts);
	
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
			owner->handle_dtmf(resp, ts2double(header_ts.tv_sec, header_ts.tv_usec), saddr, daddr, s_dtmf::rfc2833);
		}
	}

        return;
}

/* read rtp packet */
bool
RTP::read(unsigned char* data, unsigned *len, struct pcap_pkthdr *header,  u_int32_t saddr, u_int32_t daddr, u_int16_t sport, u_int16_t dport,
	  int sensor_id, u_int32_t sensor_ip, char *ifname) {
 
	if(this->stopReadProcessing) {
		return(false);
	}
 
	this->data = data; 
	this->len = *len;
	this->header_ts = header->ts;
	this->saddr =  saddr;
	this->daddr =  daddr;
	this->dport = dport;
	this->sport = sport;
	this->ignore = 0;
	resetgraph = 0;

	if(codec != -1 and codec != 13 and codec != 19 and codec != PAYLOAD_TELEVENT) {
		had_audio = true;
	}

	if(last_mos_time == 0) { 
		last_mos_time = header->ts.tv_sec;
	}
	if(sverb.ssrc and getSSRC() != sverb.ssrc) return(false);
	
	if(sverb.read_rtp) {
		extern u_int64_t read_rtp_counter;
		++read_rtp_counter;
		cout << "RTP - read [" << this << "]-" 
		     << " ssrc: " << hex << this->ssrc << dec << " "
		     << " src: " << inet_ntostring(htonl(saddr)) << " : " << sport
		     << " dst: " << inet_ntostring(htonl(daddr)) << " : " << dport
		     << " seq: " << getSeqNum() << " "
		     << " direction: " << iscaller_description(iscaller) 
		     << " packets_received: " << this->stats.received
		     << " counter: " << read_rtp_counter
		     << endl;
	}
	
	Call *owner = (Call*)call_owner;

	extern bool opt_receiver_check_id_sensor;
	if(opt_receiver_check_id_sensor && ((this->sensor_id >= 0 && this->sensor_id != sensor_id) ||
	   (this->sensor_ip > 0 && this->sensor_ip != sensor_ip))) {
		if(!owner || !owner->rtp_from_multiple_sensors) {
			extern bool opt_disable_rtp_warning;
			if(!opt_disable_rtp_warning) {
				u_long actTime = getTimeMS();
				if(actTime - 1000 > lastTimeSyslog) {
					syslog(LOG_NOTICE, "warning - packet from sensor (%i/%s) in RTP created for sensor (%i/%s) - call %s", 
					       sensor_id, sensor_ip ? inet_ntostring(htonl(sensor_ip)).c_str() : "-", 
					       this->sensor_id, this->sensor_ip ? inet_ntostring(htonl(this->sensor_ip)).c_str() : "-",
					       owner->fbasename);
					lastTimeSyslog = actTime;
				}
			}
			if(owner) {
				owner->rtp_from_multiple_sensors = true;
			}
		}
		return(false);
	}
	
	u_int64_t pcap_header_ts = header->ts.tv_sec * 1000000ull + header->ts.tv_usec;
	if(this->last_pcap_header_ts && pcap_header_ts < (this->last_pcap_header_ts - 50000)) {
		if(!this->pcap_header_ts_bad_time) {
			if(pcap_header_ts < (this->last_pcap_header_ts - 200000)) {
				extern bool opt_disable_rtp_warning;
				if(!opt_disable_rtp_warning) {
					u_long actTime = getTimeMS();
					static u_long s_lastTimeSyslog;
					if(actTime - 500 > s_lastTimeSyslog) {
						syslog(LOG_NOTICE, "warning - packet (seq:%i, ssrc: %x) from sensor (%i) has bad pcap header time (-%luus) - call %s", getSeqNum(), getSSRC(), sensor_id, this->last_pcap_header_ts - pcap_header_ts, owner ? owner->fbasename : "unknown");
						s_lastTimeSyslog = actTime;
					}
				}
			}
			this->pcap_header_ts_bad_time = true;
		}
		return(false);
	}
	this->last_pcap_header_ts = pcap_header_ts;

	if(this->first_packet_time == 0 and this->first_packet_usec == 0) {
		this->first_packet_time = header->ts.tv_sec;
		this->first_packet_usec = header->ts.tv_usec;
	}

	if(owner && 
	   !opt_pb_read_from_file[0] && !is_read_from_file()) {
		u_int64_t seenbyeandok_time_usec = owner->getSeenbyeAndOkTimeUS();
		if(seenbyeandok_time_usec && getTimeUS(header) > seenbyeandok_time_usec) {
			return(false);
		}
	}

	if(owner) {
		owner->forcemark_lock();
		bool checkNextForcemark = false;
		do {
			checkNextForcemark = false;
			size_t _forcemark_size = owner->forcemark_time.size();
			if(_forcemark_size > forcemark_owner_used) {
				u_int64_t _forcemark_time = owner->forcemark_time[forcemark_owner_used];
				u_int64_t _header_time = getTimeUS(header);
				if(_forcemark_time < _header_time) {
					if(_forcemark_time > (first_packet_time * 1000000ull + first_packet_usec)) {
						if(sverb.forcemark) {
							cout << "set forcemark: " << _forcemark_time 
							     << " header time: " << _header_time 
							     << " forcemarks size: " << (_forcemark_size - forcemark_owner_used)
							     << " ssrc: " << hex << getSSRC() << dec
							     << " seq: " << seq 
							     << " direction: " << iscaller_description(iscaller)
							     << endl;
						}
						forcemark_by_owner = true;
						forcemark_by_owner_set = true;
					} 
					++forcemark_owner_used;
					checkNextForcemark = true;
				}
			}
		} while(checkNextForcemark);
		owner->forcemark_unlock();
	}	       

	payload_len = get_payload_len();
	if(payload_len < 0) {
		if(owner) {
			if(!owner->error_negative_payload_length) {
				syslog(LOG_NOTICE, "warning - negative payload_len in call %s", owner->fbasename);
				owner->error_negative_payload_length = true;
			}
		} else {
			u_long actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - negative payload_len");
				lastTimeSyslog = actTime;
			}
		}
		return(false);
	}
	
	bool recordingRequested = 
		opt_saveRAW || opt_savewav_force || 
		(owner && 
		 ((owner->flags & FLAG_SAVEAUDIO) ||
		  owner->audioBufferData[0].audiobuffer || owner->audioBufferData[1].audiobuffer));
	
	if(srtp_decrypt && (opt_srtp_rtp_decrypt || recordingRequested)) {
		srtp_decrypt->decrypt_rtp(data, len, payload_data, (unsigned int*)&payload_len, getTimeUS(header)); 
		this->len = *len;
	}

	if(getVersion() != 2) {
		return(false);
	}

	seq = getSeqNum();

	if(seq == last_seq and !(last_markbit == 0 and getMarker() == 1)) {
		// ignore duplicated RTP packets unless the second packet has mark bit set but the previous not
		return(false);
	}

	last_markbit = getMarker();

	if(opt_rtp_check_timestamp) {
		if(this->_last_ts.tv_sec &&
		   (header->ts.tv_sec < this->_last_ts.tv_sec ||
		    (header->ts.tv_sec == this->_last_ts.tv_sec &&
		     header->ts.tv_usec < this->_last_ts.tv_usec))) {
			u_long actTime = getTimeMS();
			if(actTime - 1000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - bad packet order (%llu us) in RTP::read (seq/lastseq: %u/%u, ifname/lastifname: %s/%s, sensor/lastsenspor: %i/%i)- packet ignored",
				       this->_last_ts.tv_sec * 1000000ull + this->_last_ts.tv_usec - header->ts.tv_sec * 1000000ull - header->ts.tv_usec,
				       seq, last_seq,
				       ifname && ifname[0] ? ifname : "--", this->_last_ifname[0] ? this->_last_ifname : "--",
				       sensor_id, this->_last_sensor_id);
				lastTimeSyslog = actTime;
			}
			return(false);
		}
		this->_last_sensor_id = sensor_id;
		if(ifname) {
			strcpy(this->_last_ifname, ifname);
		} else {
			this->_last_ifname[0] = 0;
		}
	}
	this->_last_ts = header->ts;
	
	int curpayload = getPayload();

	if((codec == -1 || (curpayload != prev_payload))) {
		if(curpayload >= 96 && curpayload <= 127) {
			/* for dynamic payload we look into rtpmap */
			int found = 0;
			for(int i = 0; i < MAX_RTPMAP; i++) {
				if(rtpmap[i].is_set() && curpayload == rtpmap[i].payload) {
					codec = rtpmap[i].codec;
					frame_size = rtpmap[i].frame_size;
					found = 1;
				}
			}
			if(curpayload == 101 and !found) {
				// payload 101 was not in SDP, assume it is televent 
				codec = PAYLOAD_TELEVENT;
			}
		} else {
			codec = curpayload;
			if(codec == PAYLOAD_ILBC) {
				for(int i = 0; i < MAX_RTPMAP; i++) {
					if(rtpmap[i].is_set() && curpayload == rtpmap[i].payload) {
						frame_size = rtpmap[i].frame_size;
					}
				}
			}
		}
		if(codec == -1) {
			// codec cannot be determinad - ignore it
			return(false);
		}
	}

	/* in case there was packet loss we must predict lastTimeStamp to not add nonexistant delays */
	forcemark = 0;
	if(last_seq != 0 and ((last_seq + 1) != seq)) {
		if(s->lastTimeStamp == getTimestamp() - samplerate / 1000 * packetization) {
			// there was packet loss but the timestamp is like there was no packet loss 

			resetgraph = true;

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
		} else {
	
			// this fixes jumps in .graph in case of pcaket loss 	
			s->lastTimeStamp = getTimestamp() - samplerate / 1000 * packetization;
			struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(packetization, 1000));
			memcpy(&s->lastTimeRec, &tmp, sizeof(struct timeval));
		}
	}

	unsigned int *lastssrc = NULL;
	RTP *lastrtp = NULL;
	bool diffSsrcInEqAddrPort = false;
	if(owner) {
		lastssrc = iscaller ? 
			(owner->lastcallerrtp ? &owner->lastcallerrtp->ssrc : NULL) :
			(owner->lastcalledrtp ? &owner->lastcalledrtp->ssrc : NULL);
		lastrtp = iscaller ?
			(owner->lastcallerrtp ? owner->lastcallerrtp : NULL) :
			(owner->lastcalledrtp ? owner->lastcalledrtp : NULL);
		diffSsrcInEqAddrPort = lastssrc and *lastssrc != ssrc and 
				       lastrtp and this->eqAddrPort(lastrtp);
	}
	
	// if packet has Mark bit OR last frame was not dtmf and current frame is voice and last ssrc is different then current ssrc packet AND (last RTP saddr == current RTP saddr)  - reset
	if(getMarker() or
	   (!(lastframetype == AST_FRAME_DTMF and codec != PAYLOAD_TELEVENT) and diffSsrcInEqAddrPort)) {
		if(sverb.graph) printf("rtp[%p] mark[%u] lastframetype[%u] codec[%u] lastssrc[%x] ssrc[%x] iscaller[%u] lastframetype[%u][%u] codec[%u]\n", this, getMarker(), lastframetype, codec, (lastssrc ? *lastssrc : 0), ssrc, iscaller, lastframetype, AST_FRAME_DTMF, codec);

		resetgraph = true;

/*
		s->lastTimeStamp = getTimestamp() - samplerate / 1000 * packetization;
		struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(packetization, 1000));
		memcpy(&s->lastTimeRec, &tmp, sizeof(struct timeval));
*/

		s->cycles = s->cycles - s->base_seq + s->max_seq;
		s->base_seq = seq;
		s->max_seq = seq;
		if(sverb.rtp_set_base_seq) {
			cout << "RTP - packet_lost - set base_seq #1" 
			     << " ssrc: " << hex << this->ssrc << dec << " "
			     << " src: " << inet_ntostring(htonl(saddr)) << " : " << sport
			     << " dst: " << inet_ntostring(htonl(daddr)) << " : " << dport
			     << endl;
		}

		if(!(lastframetype == AST_FRAME_DTMF and codec != PAYLOAD_TELEVENT) and diffSsrcInEqAddrPort) {
			// reset jitter if ssrc changed
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
		return(true);
	}
	if(curpayload == PAYLOAD_G729 and (payload_len <= (packetization == 10 or packetization == 0 ? 9 : 12) or (payload_len + padding_len == 22) or (payload_len + padding_len == 32))) {
		last_seq = seq;
		if(update_seq(seq)) {
			update_stats();
		}
		lastframetype = AST_FRAME_VOICE;
		lastcng = 1;
		return(true);
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
		return(true);
	}

	if(!owner) { 
		lastcng = 0;
		return(false);
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
	
	if(forcemark_by_owner) {
		// on reinvite (which indicates forcemark_by_owner completely reset rtp jitterbuffer simulator and 
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

		forcemark_by_owner = false;
		forcemark  = 1;

		// this fixes jumps in .graph in case of pcaket loss 	
/*
		s->lastTimeStamp = getTimestamp() - samplerate / 1000 * packetization;
		struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(packetization, 1000));
		memcpy(&s->lastTimeRec, &tmp, sizeof(struct timeval));
*/

		// reset last sequence 
		s->cycles = s->cycles - s->base_seq + s->max_seq;
		s->base_seq = seq;
		s->max_seq = seq;
		if(sverb.rtp_set_base_seq) {
			cout << "RTP - packet_lost - set base_seq #2" 
			     << " ssrc: " << hex << this->ssrc << dec << " "
			     << " src: " << inet_ntostring(htonl(saddr)) << " : " << sport
			     << " dst: " << inet_ntostring(htonl(daddr)) << " : " << dport
			     << " seq: " << seq
			     << endl;
		}
		resetgraph = true;
	}
	
	bool recordingRequested_use_jitterbuffer_channel_record = false;
	bool recordingRequested_enable_jitterbuffer_savepayload = false;
	if(recordingRequested) {
		// MOS LQO is calculated only if the call is connected 
		recordingRequested_use_jitterbuffer_channel_record =
			!owner ||
			!((owner->flags & FLAG_RUNAMOSLQO) || (owner->flags & FLAG_RUNBMOSLQO)) || 
			(owner->connect_time &&
			 (header->ts.tv_sec *1000000ull + header->ts.tv_usec) > (owner->connect_time * 1000000ull + owner->connect_time_usec));
		recordingRequested_enable_jitterbuffer_savepayload = 
			!opt_saveaudio_answeronly ||
			!owner ||
			(owner->connect_time &&
			 (header->ts.tv_sec *1000000ull + header->ts.tv_usec) > (owner->connect_time * 1000000ull + owner->connect_time_usec));
	}

	// codec changed 
	RTP *laststream = iscaller ? owner->lastcallerrtp : owner->lastcalledrtp;


	if(defer_codec_change or 
	    (owner->iscaller_consecutive[iscaller] >= 5 and owner->lastraw[iscaller] != this and (lastssrc and *lastssrc != ssrc and (laststream and laststream->daddr == daddr))) or
	   (curpayload != prev_payload and 
	    codec != PAYLOAD_TELEVENT and 
	    (prev_codec != PAYLOAD_TELEVENT or !codecchanged) and 
	    curpayload != 13 and prev_payload != 13 and codec != 13 and codec != 19 and prev_codec != 13 and prev_codec != 19)) {

		if(defer_codec_change) {
			defer_codec_change = false;
		}
		if(curpayload == PAYLOAD_G723 and *(data + sizeof(RTPFixedHeader)) & 2) {
			// codec changed but it is still SID frames (silence) we have to defer this until first valid speech frame otherwise call will be out of sync
			defer_codec_change = true;
		} else {
			codecchanged = true;
			switch(codec) {
			case PAYLOAD_SILK12:
			case PAYLOAD_OPUS12:
			case PAYLOAD_XOPUS12:
			case PAYLOAD_VXOPUS12:
			case PAYLOAD_G722112:
				samplerate = 12000;
				break;
			case PAYLOAD_ISAC16:
			case PAYLOAD_SILK16:
			case PAYLOAD_OPUS16:
			case PAYLOAD_XOPUS16:
			case PAYLOAD_VXOPUS16:
			case PAYLOAD_G722116:
			case PAYLOAD_AMRWB:
				samplerate = 16000;
				break;
			case PAYLOAD_SILK24:
			case PAYLOAD_OPUS24:
			case PAYLOAD_XOPUS24:
			case PAYLOAD_VXOPUS24:
			case PAYLOAD_G722124:
				samplerate = 24000;
				break;
			case PAYLOAD_ISAC32:
			case PAYLOAD_G722132:
				samplerate = 32000;
				break;
			case PAYLOAD_OPUS48:
			case PAYLOAD_XOPUS48:
			case PAYLOAD_VXOPUS48:
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

			if(recordingRequested) {
				//if(verbosity > 0) syslog(LOG_ERR, "converting WAV! [%u]\n", owner->flags);
				/* open file for raw codec */
				unsigned long unique = getTimestamp();
				char tmp[1024+16];
				snprintf(tmp, sizeof(tmp), "%s.%d.%lu.%d.%ld.%ld.raw", basefilename, ssrc_index, unique, codec, header->ts.tv_sec, header->ts.tv_usec);
				if(gfileRAW)  {
					jitterbuffer_fixed_flush(channel_record);
					ast_jb_empty_and_reset(channel_record);
					ast_jb_destroy(channel_record);
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
						prevrtp->len = *len;
						prevrtp->header_ts = header_ts;
						prevrtp->codec = prevrtp->prev_codec;
						if(recordingRequested_use_jitterbuffer_channel_record) {
							prevrtp->jitterbuffer(prevrtp->channel_record, recordingRequested_enable_jitterbuffer_savepayload);
						}
					}
				}
				for(int passOpen = 0; passOpen < 2; passOpen++) {
					if(passOpen == 1) {
						char *pointToLastDirSeparator = strrchr(tmp, '/');
						if(pointToLastDirSeparator) {
							*pointToLastDirSeparator = 0;
							spooldir_mkdir(tmp);
							*pointToLastDirSeparator = '/';
						} else {
							break;
						}
					}
					gfileRAW = fopen(tmp, "w");
					if(gfileRAW) {
						spooldir_file_chmod_own(tmp);
						break;
					}
				}
				if(!gfileRAW_buffer) {
					gfileRAW_buffer = new FILE_LINE(24007) char[32768];
					if(gfileRAW_buffer == NULL) {
						syslog(LOG_ERR, "Cannot allocate memory for gfileRAW_buffer - low memory this is FATAL");
						exit(2);
					}
				}
				if(!gfileRAW) {
					syslog(LOG_ERR, "Cannot open file %s for writing: %s\n", tmp, strerror (errno));
				} else if(gfileRAW_buffer) {
					setvbuf(gfileRAW, gfileRAW_buffer, _IOFBF, 32768);
				}

				/* write file info to "playlist" */
				snprintf(tmp, sizeof(tmp), "%s.rawInfo", basefilename);
				owner->iscaller_consecutive[iscaller] = 0;
				bool gfileRAWInfo_exists = file_exists(tmp);
				FILE *gfileRAWInfo = fopen(tmp, "a");
				if(gfileRAWInfo) {
					if(!gfileRAWInfo_exists) {
						spooldir_file_chmod_own(tmp);
					}
					fprintf(gfileRAWInfo, "%d:%lu:%d:%d:%ld:%ld\n", ssrc_index, unique, codec, frame_size, header->ts.tv_sec, header->ts.tv_usec);
					fclose(gfileRAWInfo);
				} else {
					syslog(LOG_ERR, "Cannot open file %s.rawInfo for writing\n", basefilename);
				}
			}
		}
	}


	if(owner->lastraw[iscaller] != this) {
		owner->iscaller_consecutive[iscaller] = 0;
	} else {
		owner->iscaller_consecutive[iscaller]++;
	}
	owner->lastraw[iscaller] = this;


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
		} else if(curpayload == PAYLOAD_AMR or curpayload == PAYLOAD_AMRWB) {
			if(payload_len == 7) {
				sid = 1;
			}
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
				if(payload_len == 60) {
					packetization = 60;
				} else if(payload_len == 50) {
					packetization = 50;
				} else if(payload_len == 40) {
					packetization = 40;
				} else if(payload_len == 30) {
					packetization = 30;
				} else if(payload_len == 20) {
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
			} else if(codec == PAYLOAD_ILBC) {
				if(payload_len % 50 == 0) {
					packetization = 30 * payload_len / 50;
				} else {
					packetization = (getTimestamp() - last_ts) / (samplerate / 1000);
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
		if(curpayload == PAYLOAD_PCMU or curpayload == PAYLOAD_PCMA or curpayload == PAYLOAD_GSM or curpayload == PAYLOAD_G722 or curpayload == PAYLOAD_G723) {

			int apacketization = 0;
			switch(curpayload) {
			case PAYLOAD_PCMU:
			case PAYLOAD_PCMA:
				apacketization = payload_len / 8;
				break;
			case PAYLOAD_GSM:
				apacketization = payload_len / 33 * 20;
				break;
			case PAYLOAD_G722:
				apacketization = payload_len / 8;
				break;
			case PAYLOAD_G723:
				if(payload_len == 24) {
					apacketization = 30;
				} else if(payload_len == 24*2) {
					apacketization = 60;
				} else if(payload_len == 24*3) {
					apacketization = 90;
				}
				break;
			}

			channel_fix1->packetization = default_packetization = 
				channel_fix2->packetization = channel_adapt->packetization = 
				channel_record->packetization = packetization = apacketization;

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
		if(recordingRequested) {
			if(packetization < 10) {
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(payload_len == 60) {
						packetization = channel_record->packetization = 60;
					} else if(payload_len == 50) {
						packetization = channel_record->packetization = 50;
					} else if(payload_len == 40) {
						packetization = channel_record->packetization = 40;
					} else if(payload_len == 30) {
						packetization = channel_record->packetization = 30;
					} else if(payload_len == 20) {
						packetization = channel_record->packetization = 20;
					} else if(payload_len == 10) {
						packetization = channel_record->packetization = 10;
					} else {
						packetization = channel_record->packetization = default_packetization;
					}
				} else if(codec == PAYLOAD_ILBC) {
					if(payload_len % 50 == 0) {
						packetization = channel_record->packetization = 30 * payload_len / 50;
					} else {
						packetization = channel_record->packetization = default_packetization;
					}
				} else if(curpayload == PAYLOAD_G723) {
					if(payload_len == 24) {
						packetization = channel_record->packetization = 30;
					} else if(payload_len == 24*2) {
						packetization = channel_record->packetization = 60;
					} else if(payload_len == 24*3) {
						packetization = channel_record->packetization = 90;
					}
				} else {
					packetization = channel_record->packetization = default_packetization;
				}
			}
			if(recordingRequested_use_jitterbuffer_channel_record &&
			   checkDuplChannelRecordSeq(seq)) {
				jitterbuffer(channel_record, recordingRequested_enable_jitterbuffer_savepayload);
			}
		}
	} else if(packetization_iterator == 1) {
		if(last_ts != 0 && seq == (last_seq + 1) && codec != PAYLOAD_TELEVENT && prev_codec != PAYLOAD_TELEVENT && !sid && !prev_sid) {
			// sequence numbers are ok, we can calculate packetization
			if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(payload_len == 60) {
					packetization = 60;
				} else if(payload_len == 50) {
					packetization = 50;
				} else if(payload_len == 40) {
					packetization = 40;
				} else if(payload_len == 30) {
					packetization = 30;
				} else if(payload_len == 20) {
					packetization = 20;
				} else if(payload_len == 10) {
					packetization = 10;
				} else {
					packetization = (getTimestamp() - last_ts) / 8;
				}
			} else if(codec == PAYLOAD_ILBC) {
				if(payload_len % 50 == 0) {
					packetization = 30 * payload_len / 50;
				} else {
					packetization = default_packetization;
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
				if(recordingRequested) {
					packetization = channel_record->packetization = default_packetization;
					if(recordingRequested_use_jitterbuffer_channel_record &&
					   checkDuplChannelRecordSeq(seq)) {
						jitterbuffer(channel_record, recordingRequested_enable_jitterbuffer_savepayload);
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
				if(recordingRequested) {
					if(recordingRequested_use_jitterbuffer_channel_record &&
					   checkDuplChannelRecordSeq(seq)) {
						jitterbuffer(channel_record, recordingRequested_enable_jitterbuffer_savepayload);
					}
				}
			}
		} else {
			packetization_iterator = 0;
			/* for recording, we cannot loose any packet */
			if(recordingRequested) {
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(payload_len == 60) {
						packetization = channel_record->packetization = 60;
					} else if(payload_len == 50) {
						packetization = channel_record->packetization = 50;
					} else if(payload_len == 40) {
						packetization = channel_record->packetization = 40;
					} else if(payload_len == 30) {
						packetization = channel_record->packetization = 30;
					} else if(payload_len == 20) {
						packetization = channel_record->packetization = 20;
					} else if(payload_len == 10) {
						packetization = channel_record->packetization = 10;
					} else {
						packetization = channel_record->packetization = default_packetization;
					}
				} else if(codec == PAYLOAD_ILBC) {
					if(payload_len % 50 == 0) {
						packetization = channel_record->packetization = 30 * payload_len / 50;
					} else {
						packetization = channel_record->packetization = default_packetization;
					}
				} else if(curpayload == PAYLOAD_G723) {
					if(payload_len == 24) {
						packetization = channel_record->packetization = 30;
					} else if(payload_len == 24*2) {
						packetization = channel_record->packetization = 60;
					} else if(payload_len == 24*3) {
						packetization = channel_record->packetization = 90;
					}
				} else {
					packetization = channel_record->packetization = default_packetization;
				}

				if(recordingRequested_use_jitterbuffer_channel_record &&
				   checkDuplChannelRecordSeq(seq)) {
					jitterbuffer(channel_record, recordingRequested_enable_jitterbuffer_savepayload);
				}
			}
		}
	} else {
		if(last_ts != 0 and seq == (last_seq + 1) and codec != PAYLOAD_TELEVENT and !getMarker() and prev_payload_len > 8) {
			// packetization can change over time
			int curpacketization = 0;

			if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(payload_len == 60) {
					curpacketization = 60;	
				} else if(payload_len == 50) {
					curpacketization = 50;	
				} else if(payload_len == 40) {
					curpacketization = 40;	
				} else if(payload_len == 30) {
					curpacketization = 30;	
				} else if(payload_len == 20) {
					curpacketization = 20;	
				} else if(payload_len == 10) {
					curpacketization = 10;	
				} else {
					curpacketization = (getTimestamp() - last_ts) / 8;
				}
			} else if(codec == PAYLOAD_ILBC) {
				if(payload_len % 50 == 0) {
					curpacketization = 30 * payload_len / 50;
				} else {
					curpacketization = default_packetization;
				}
			} else if(curpayload == PAYLOAD_G723) {
				if(payload_len == 24) {
					curpacketization = 30;	
				} else if(payload_len == 24*2) {
					curpacketization = 60;
				} else if(payload_len == 24*3) {
					curpacketization = 90;
				}
				if((unsigned char)*(data + sizeof(RTPFixedHeader)) & 2) {
					//it is sid data - do not change packetization
					curpacketization = last_packetization;
				}
			} else if(curpayload == PAYLOAD_PCMU or curpayload == PAYLOAD_PCMA or curpayload == PAYLOAD_G722) {
				if((payload_len / 8) >= 20) {
					// do not change packetization to 10ms frames. Case g711_20_10_sync.pcap
					curpacketization = payload_len / 8;
				}
			} else if(curpayload == PAYLOAD_GSM) {
				curpacketization = payload_len / 33 * 20;
			} else if(codec == PAYLOAD_AMR or codec == PAYLOAD_AMRWB) {
				if(payload_len > 7) {
					//printf("curpac[%u]\n", curpacketization);
					curpacketization = (getTimestamp() - last_ts) / 8;
				} else {
					curpacketization = packetization;
				}
			} else {
				curpacketization = (getTimestamp() - last_ts) / (samplerate / 1000);
			}

			if(curpacketization < 10) {
				// it cannot be, reset it to 20
				curpacketization = default_packetization;
			}

			if(verbosity > 3) printf("curpacketization[%u] = (getTimestamp()[%u] - last_ts[%u]) / (samplerate[%u] / 1000) pl[%u] curpayload[%u] seq[%u]\n", curpacketization, getTimestamp(), last_ts, samplerate, payload_len, curpayload, seq);

			if(curpacketization != packetization and curpacketization % 10 == 0 and curpacketization >= 10 and curpacketization <= 120) {
				// packetization changed, check if next packet is the same packetization
				change_packetization_iterator++;
			} else {
				// packetization changed back, reset the iterator
				change_packetization_iterator = 0;
			}

			if(change_packetization_iterator > 1) { 
				//packetization changed for two last packets
				if(verbosity > 3) printf("[%x] changing packetization:[%d]->[%d]\n", getSSRC(), packetization, curpacketization);
				channel_fix1->packetization = channel_fix2->packetization = channel_adapt->packetization = channel_record->packetization = packetization = curpacketization;
				last_packetization = curpacketization;
				change_packetization_iterator = 0;
			}
			
		}
		if(curpayload == PAYLOAD_G723) {
			if(payload_len == 24) {
				packetization = 30;	
			} else if(payload_len == 24*2) {
				packetization = 60;
			} else if(payload_len == 24*3) {
				packetization = 90;
			}
			channel_fix1->packetization = channel_fix2->packetization = channel_adapt->packetization = channel_record->packetization = packetization;
		}
		//printf("packetization [%d]\n", packetization);
		if(opt_jitterbuffer_f1)
			jitterbuffer(channel_fix1, 0);
		if(opt_jitterbuffer_f2)
			jitterbuffer(channel_fix2, 0);
		if(opt_jitterbuffer_adapt)
			jitterbuffer(channel_adapt, 0);
		if(recordingRequested) {
			if(recordingRequested_use_jitterbuffer_channel_record &&
			   checkDuplChannelRecordSeq(seq)) {
				jitterbuffer(channel_record, recordingRequested_enable_jitterbuffer_savepayload);
			}
		}
	}

	prev_payload_len = payload_len;
	prev_payload = curpayload;
	prev_codec = codec;
	prev_sid = sid;

	// DSP processing
	bool do_fasdetect = opt_fasdetect && !this->iscaller &&  owner->connect_time && (this->header_ts.tv_sec - owner->connect_time < 10);
	if(owner and (opt_inbanddtmf or opt_faxt30detect or opt_silencedetect or opt_clippingdetect or do_fasdetect)
		and frame->frametype == AST_FRAME_VOICE and (codec == 0 or codec == 8)) {

		int res;
		if (!DSP) {
			DSP = dsp_new();
			if (DSP) {
				int features = 0;
				if (opt_inbanddtmf) {
					features |= DSP_FEATURE_DIGIT_DETECT;
				}
				if (opt_faxt30detect) {
					features |= DSP_FEATURE_FAX_DETECT;
				}
				if (opt_silencedetect) {
					features |= DSP_FEATURE_SILENCE_SUPPRESS;
				}
				dsp_set_features(DSP, features);
			}
		}

		if (DSP) {
			if (do_fasdetect) {
				dsp_set_feature(DSP, DSP_FEATURE_CALL_PROGRESS);
			} else {
				dsp_clear_feature(DSP, DSP_FEATURE_CALL_PROGRESS);
			}
		}

		char event_digit;
		int event_len;
		short int *sdata = new FILE_LINE(24008) short int[payload_len];
		if(!sdata) {
			syslog(LOG_ERR, "sdata malloc failed [%u]\n", (unsigned int)(payload_len * 2));
			return(false);
		}
		if(codec == 0) {
			for(int i = 0; i < payload_len; i++) {
				sdata[i] = ULAW((unsigned char)payload_data[i]);
				if(opt_clippingdetect and ((abs(sdata[i])) >= 32124)) {
					if(iscaller) {
						owner->caller_clipping_8k++;
					} else {
						owner->called_clipping_8k++;
					}
				}
			}
		} else if(codec == 8) {
			for(int i = 0; i < payload_len; i++) {
				sdata[i] = ALAW((unsigned char)payload_data[i]);
				if(opt_clippingdetect and ((abs(sdata[i])) >= 32256)) {
					if(iscaller) {
						owner->caller_clipping_8k++;
					} else {
						owner->called_clipping_8k++;
					}
				}
			}
		}
		if(opt_inbanddtmf or opt_faxt30detect or opt_silencedetect or do_fasdetect) {
			int silence0 = 0;
			int totalsilence = 0;
			int totalnoise = 0;
			res = dsp_process(DSP, sdata, payload_len, &event_digit, &event_len, &silence0, &totalsilence, &totalnoise);
			if(silence0) {
				if(iscaller) {
					owner->caller_lastsilence += payload_len / 8;
					owner->caller_silence += payload_len / 8;
				} else {
					owner->called_lastsilence += payload_len / 8;
					owner->called_silence += payload_len / 8;
				}
			} else {
				if(iscaller) {
					owner->caller_lastsilence = 0;
					owner->caller_noise += payload_len / 8;
				} else {
					owner->called_lastsilence = 0;
					owner->called_noise += payload_len / 8;
				}
			}
			if(res) {
				if(opt_faxt30detect and (event_digit == 'f' or event_digit == 'e')) {
					//printf("dsp_process: digit[%c] len[%u]\n", event_digit, event_len);
					owner->isfax = T30FAX;
				} else if(opt_inbanddtmf and res == 5) {
					owner->handle_dtmf(event_digit, ts2double(header->ts.tv_sec, header->ts.tv_usec), saddr, daddr, s_dtmf::inband);
				}
				if (do_fasdetect)
					owner->is_fas_detected = (res == AST_CONTROL_RINGING) ? true : false;
			}
		}

		delete [] sdata;
	} else if (DSP) {
		dsp_free(DSP);
		DSP = NULL;
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

	avg_ptime_count++;
	avg_ptime = (avg_ptime * (avg_ptime_count - 1) + packetization) / avg_ptime_count;

	// write MOS to .graph every 10 seconds and reset jitter last mos interval
	if((last_mos_time + 10 < header->ts.tv_sec) or save_mos_graph_wait) {
		mos_processed = true;
		if(save_mos_graph_wait > 1) {
			save_mos_graph_wait--;
		} else {
			if(!save_mos_graph_wait and ((header->ts.tv_sec - last_mos_time) > 10)) {
				//wait few frames - there was loss generated so the jitter can settle 
				save_mos_graph_wait = 20; // wait 10 packets
			} else {
				save_mos_graph_wait = false;
				save_mos_graph(false);
				last_mos_time = header->ts.tv_sec;
			}
		}
	}
	resetgraph = false;

	if(forcemark_by_owner_set) {
		forcemark_by_owner_set = false;
		forcemark2 = 1; // set this flag and keep it until next update_stats call
	}

	return(true);
}

/* fill internal structures by the input RTP packet */
void
RTP::fill(unsigned char* data, int len, struct pcap_pkthdr *header,  u_int32_t saddr, u_int32_t daddr, u_int16_t sport, u_int16_t dport) {
	this->data = data; 
	this->len = len;
	this->header_ts = header->ts;
	this->saddr = saddr;
	this->daddr = daddr;
	this->sport = sport;
	this->dport = dport;
}

/* update statistics data */
void
RTP::update_stats() {

	int lost = int((s->cycles + s->max_seq - (s->base_seq + 1)) - s->received);
	
	// recalculation base_seq for interlaced streams
	if(lost > 100 && 
	   s->max_seq - this->last_seq >= lost) {
		Call *owner = (Call*)call_owner;
		u_int16_t maxSeqOtherSsrc = 0;
		for(int i = 0; i < owner->ssrc_n; i++) {
			if(owner->rtp[i] != this && owner->rtp[i]->ssrc == this->ssrc) {
				if(owner->rtp[i]->s->max_seq > maxSeqOtherSsrc) {
					maxSeqOtherSsrc = owner->rtp[i]->s->max_seq;
				}
			}
		}
		if(maxSeqOtherSsrc > this->last_seq &&
		   maxSeqOtherSsrc < s->max_seq) {
			s->base_seq = s->cycles + s->max_seq - s->received - 1 - (s->max_seq - maxSeqOtherSsrc - 1);
			lost = int((s->cycles + s->max_seq - (s->base_seq + 1)) - s->received);
		}
	}
	
	if(lost < 0) {
		s->cycles += lost * -1;
		lost = 0;
	}
	int adelay = 0;
	struct timeval tsdiff;	
	double tsdiff2;

	//printf("seq[%d] lseq[%d] lost[%d], ((s->cycles[%d] + s->max_seq[%d] - (s->base_seq[%d] + 1)) - s->received[%d]);\n", seq, last_seq, lost, s->cycles, s->max_seq, s->base_seq, s->received);

	Call *owner = (Call*)call_owner;

	/* differences between last timestamp and current timestamp (timestamp from ip header)
	 * frame1.time - frame0.time */
	tsdiff2 = timeval_subtract(&tsdiff, header_ts, last_voice_frame_ts) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0;

	long double transit = tsdiff2 - ((double)getTimestamp() - last_voice_frame_timestamp)/((double)samplerate/1000.0);

//	if(verbosity > 1) printf("transit rtp[%p] ssrc[%x] seq[%u] transit[%f]\n", this, getSSRC(), seq, (float)transit);

	/* if payload == PAYLOAD_TELEVENT dont make delayes on this because it confuses stats */
	if(codec == PAYLOAD_TELEVENT or lastframetype == AST_FRAME_DTMF) {
		if(codec != PAYLOAD_TELEVENT) {
			if(last_voice_frame_ts.tv_sec == 0) {
				// it is not EVENT frame and it is first voice packet 
				last_voice_frame_ts = header_ts;
				last_voice_frame_timestamp = getTimestamp();
				return;
			}

			uint32_t diff = timeval_subtract(&tsdiff, header_ts, last_voice_frame_ts) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0;
			this->graph.write((char*)&graph_event, 4);
			this->graph.write((char*)&diff, 4);
			if(verbosity > 1) printf("rtp[%p] ssrc[%x] seq[%u] silence[%u]ms ip[%u] DTMF\n", this, getSSRC(), seq, diff, saddr);


			//s->fdelay = s->avgdelay;
/*
			s->lastTimeStamp = getTimestamp() - samplerate / 1000 * packetization;
			struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(packetization, 1000));
			memcpy(&s->lastTimeRec, &tmp, sizeof(struct timeval));
*/
			forcemark2 = 0;

			return;
		} else {
			forcemark2 = 0;
			return;
		}
	} else {
		
		if(abs((int)transit) > 5000) {
			/* timestamp skew, discard delay, it is possible that timestamp changed  */
			s->fdelay = s->avgdelay;
			//s->fdelay = 0;
			transit = 0;
		} else {
			adelay = abs(int(transit));
			s->fdelay += transit;
		}
	}

	if(last_voice_frame_ts.tv_sec == 0) {
		// it is not EVENT frame and it is first voice packet - ignore stats for first voice packet
		last_voice_frame_ts = header_ts;
		last_voice_frame_timestamp = getTimestamp();
		forcemark2 = 0;
		return;
	}

	last_voice_frame_ts = header_ts;
	last_voice_frame_timestamp = getTimestamp();
//	printf("rtp[%p] transit[%f]\t[%f]\tseq[%u]\tavgdelay[%f]\n", this, (float)transit, (float)s->fdelay, seq, float(s->avgdelay));

	//printf("seq[%u] adelay[%u]\n", seq, adelay);


	// store mark bit in graph file
	if((getMarker() or ((codec == PAYLOAD_AMR or codec == PAYLOAD_AMRWB) and (payload_len <= 7))) 
	    and owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {

		uint32_t diff = (uint32_t)tsdiff2;
		this->graph.write((char*)&graph_mark, 4);
		this->graph.write((char*)&diff, 4);
		if(sverb.graph) printf("rtp[%p] ssrc[%x] seq[%u] silence[%u]ms transit[%Lf] avgdelay[%f] mark\n", this, getSSRC(), seq, diff, transit, s->avgdelay);

		//s->fdelay = 0;
		//s->fdelay -= transit;
		s->fdelay = s->avgdelay;
		adelay = 0;
	} else if(resetgraph and owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
		uint32_t diff = (uint32_t)tsdiff2;
		this->graph.write((char*)&graph_silence, 4);
		this->graph.write((char*)&diff, 4);
		if(sverb.graph) printf("rtp[%p] ssrc[%x] seq[%u] silence[%u]ms avgdelay[%f]\n", this, getSSRC(), seq, diff, s->avgdelay);

		//s->fdelay = 0;
		s->fdelay = s->avgdelay;
		//s->fdelay -= transit;
		adelay = 0;
	}

	// keep average only for last 30 packets
	uint32_t lastpackets = 30;
	if(counter > lastpackets) {
		s->avgdelay = (lastpackets * s->avgdelay - avgdelays[counter % lastpackets] + s->fdelay) / lastpackets;
	} else {
		s->avgdelay = ((s->avgdelay * (double)(counter)) + s->fdelay ) / (double)(counter + 1);
	}
	avgdelays[counter % lastpackets] = s->fdelay;
	//s->avgdelay = ((s->avgdelay * (long double)(counter)) + s->fdelay ) / (double)(counter + 1);

	
	/* Jitterbuffer calculation
	 * J(1) = J(0) + (|D(0,1)| - J(0))/16 */
	jitter = s->prevjitter + (double)(((transit < 0) ? -transit : transit) - s->prevjitter)/16. ;
	s->prevjitter = jitter;

	counter++;
	stats.avgjitter = ((stats.avgjitter * ( stats.received - 1 )  + jitter )) / (double)stats.received;
	//printf("jitter[%f] avg[%llf] [%u] [%u]\n", jitter, stats.avgjitter, stats.received, s->received);
	if(stats.maxjitter < jitter) stats.maxjitter = jitter;
	s->lastTimeRec = header_ts;
	s->lastTimeRecJ = header_ts;
	s->lastTimeStamp = getTimestamp();
	s->lastTimeStampJ = getTimestamp();

	if(forcemark2) {
		// do not store loss / delay in case this is first packet after reinvite 
		stats.lost2 += lost - stats.last_lost;
		stats.last_lost = lost;
	} else {
		if((lost > stats.last_lost) > 0) {
			if(sverb.packet_lost) {
				cout << this << " RTP - packet_lost -" 
				     << " ssrc: " << hex << this->ssrc << dec << " "
				     << " src: " << inet_ntostring(htonl(saddr))
				     << " dst: " << inet_ntostring(htonl(daddr)) << " : " << dport
				     << " forcemark: " << forcemark2 << " "
				     << " seq: " << getSeqNum() << " "
				     << " lost - last_lost: " << (lost - stats.last_lost) << " " 
				     << " lost: " << lost << " "
				     << " last_lost: " << stats.last_lost << endl;
			}
			stats.lost2 += lost - stats.last_lost;
			stats.lost += lost - stats.last_lost;
			if((lost - stats.last_lost) < 10)
				stats.slost[lost - stats.last_lost]++;
			else 
				stats.slost[10]++;

			if(owner && (owner->flags & FLAG_SAVEGRAPH)) {
				nintervals += lost - stats.last_lost;
				while(nintervals > 20) {
					if(this->graph.isOpenOrEnableAutoOpen()) {
						this->graph.write((char*)&graph_delimiter, 4);
					}
					nintervals -= 20;
				}
			}
		}
		if(owner && (owner->flags & FLAG_SAVEGRAPH)) {
			if(this->graph.isOpenOrEnableAutoOpen()) {
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

	forcemark2 = 0;
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

	struct timeval tsdiff;	
	double tsdiff2;
	tsdiff2 = timeval_subtract(&tsdiff, header_ts, s->lastTimeRecJ) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0;

	int lost = int((s->cycles + seq - (s->base_seq + 1)) - s->received);
//	printf("seq[%u] lost[%u] tsdiff2[%f] tsdiff-sec[%d] tsdiff-miscro[%d] header->ts[%u.%u] s->lastTimeRecJ[%u.%u]\n", seq, lost, tsdiff2, tsdiff.tv_sec, tsdiff.tv_usec, header->ts.tv_sec, header->ts.tv_usec, s->lastTimeRecJ.tv_sec, s->lastTimeRecJ.tv_usec);
	if((lost - stats.last_lost) > 200 and (abs((int)tsdiff2) < 1000)) {
		// it cannot be loss because difference is < 1000ms and loss is too big. It is probably sequence reset without mark bit 
		//printf("lost[%d] last_lost[%d] tsdiff2[%f] seq[%u] rec[%lu] max_seq[%u] base_seq[%u] cyc[%u] nlost[%d]\n", lost, stats.last_lost, tsdiff2, seq, s->received, s->max_seq, s->base_seq, s->cycles, int((s->cycles + s->max_seq - (s->base_seq + 1)) - s->received));
		s->cycles = s->cycles - s->base_seq + s->max_seq;
		s->base_seq = seq;
		s->max_seq = seq;
		if(sverb.rtp_set_base_seq) {
			cout << "RTP - packet_lost - set base_seq #1" 
			     << " ssrc: " << hex << this->ssrc << dec << " "
			     << " src: " << inet_ntostring(htonl(saddr)) << " : " << sport
			     << " dst: " << inet_ntostring(htonl(daddr)) << " : " << dport
			     << endl;
		}
	}

	if(first) {
		first = false;
		init_seq(seq);
		s->max_seq = seq - 1;
		s->probation = MIN_SEQUENTIAL;
		s->lastTimeRec = header_ts;
		s->lastTimeRecJ = header_ts;
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

void burstr_calculate(struct ast_channel *chan, u_int32_t received, double *burstr, double *lossr, int lastinterval) {
	int lost = 0;
	int bursts = 0;
	unsigned int received2 = 0 and lastinterval ? received - chan->last_received : received;
	for(int i = 0; i < 128; i++) {
		if(lastinterval) {
			lost += i * (chan->loss[i] - chan->last_interval_loss[i]);
			bursts += chan->loss[i] - chan->last_interval_loss[i];
			if((verbosity > 4 or sverb.jitter) and (chan->loss[i] - chan->last_interval_loss[i]) > 0) printf("bc loss[%d]: %d\t", i, chan->loss[i] - chan->last_interval_loss[i]);
		} else {
			lost += i * chan->loss[i];
			bursts += chan->loss[i];
			if((verbosity > 4 or sverb.jitter) and chan->loss[i] > 0) printf("bc loss[%d]: %d\t", i, chan->loss[i]);
		}
	}

	if(lost < 5) {
		// ignore such small packet loss 
		*lossr = *burstr = 0;
		return;
	}

	if(verbosity > 4 or sverb.jitter) printf("\n");
	
	if(received > 0 && bursts > 0) {
		*burstr = (double)((double)lost / (double)bursts) / (double)(1.0 / ( 1.0 - (double)lost / (double)received2 ));
		if(sverb.jitter) printf("mos: *burstr[%f] = (lost[%u] / bursts[%u]) / (1 / ( 1 - lost[%u] / received[%u]\n", *burstr, lost, bursts, lost, received2);
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
		*lossr = (double)((double)lost / (double)received2);
	} else {
		*lossr = 0;
	}
	chan->last_received = received;
	if(sverb.jitter) printf("burstr: %f lossr: %f lost[%d]/received[%d]\n", *burstr, *lossr, lost, received2);
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
	burstr_calculate(channel_fix1, s->received, &burstr, &lossr, 1);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("fix(50/50)\tloss rate:\t%f\n", lossr);
	printf("fix(50/50)\tburst rate:\t%f\n", burstr);

	burstr_calculate(channel_fix2, s->received, &burstr, &lossr, 1);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("fix(200/200)\tloss rate:\t%f\n", lossr);
	printf("fix(200/200)\tburst rate:\t%f\n", burstr);

	burstr_calculate(channel_adapt, s->received, &burstr, &lossr, 1);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("adapt(500/500)\tloss rate:\t%f\n", lossr);
	printf("adapt(500/500)\tburst rate:\t%f\n", burstr);
	printf("---\n");
}

void RTP::clearAudioBuff(Call *call, ast_channel *channel) {
	if(iscaller) {
		if(call->audioBufferData[0].audiobuffer) {
			channel->audiobuf = NULL;
		}
	} else {
		if(call->audioBufferData[1].audiobuffer) {
			channel->audiobuf = NULL;
		}
	}
}

double calculate_mos_g711(double ppl, double burstr, int version) {
	double r;
	double bpl = 8.47627; //mos = -4.23836 + 0.29873 * r - 0.00416744 * r * r + 0.0000209855 * r * r * r;
	double mos;

	if(ppl == 0 or burstr == 0) {
		return 4.5;
	}

	if(ppl > 0.5) {
		return 1;
	}

	switch(version) {
	case 1:
	case 2:
	default:
		// this mos is calculated for G.711 and PLC
		bpl = 17.2647;
		r = 93.2062077233 - 95.0 * (ppl*100/(ppl*100/burstr + bpl));
		mos = 2.06405 + 0.031738 * r - 0.000356641 * r * r + 2.93143 * pow(10,-6) * r * r * r;
		if(mos < 1)	    
			return 1;      
		if(mos > 4.5)   
			return 4.5;
	}

	return mos;
}

double calculate_mos(double ppl, double burstr, int codec, unsigned int received) {
	if(codec == PAYLOAD_G729) {
		if(opt_mos_g729) {
			if(received < 100) {
				return 3.92;
			}
			return (double)mos_g729((long double)ppl, (long double)burstr);
		} else {
			if(received < 100) {
				return 4.5;
			}
			return calculate_mos_g711(ppl, burstr, 2);
		}
	} else {
		if(received < 100) {
			return 4.5;
		}
		return calculate_mos_g711(ppl, burstr, 2); 
	}       
}		

int calculate_mos_fromrtp(RTP *rtp, int jittertype, int lastinterval) {
	double burstr, lossr;
	switch(jittertype) {
	case 1: 
		if(rtp->channel_fix1) {
			burstr_calculate(rtp->channel_fix1, rtp->stats.received, &burstr, &lossr, lastinterval);
		} else {
			return 45;
		}
		break;  
	case 2: 
		if(rtp->channel_fix2) {
			burstr_calculate(rtp->channel_fix2, rtp->stats.received, &burstr, &lossr, lastinterval);
		} else {
			return 45;
		}
		break;  
	case 3: 
		if(rtp->channel_adapt) {
			burstr_calculate(rtp->channel_adapt, rtp->stats.received, &burstr, &lossr, lastinterval);
		} else {
			return 45;
		}
		break;  
	}       
	int mos = (int)round(calculate_mos(lossr, burstr, rtp->first_codec, rtp->stats.received) * 10);
	return mos;
}       

void
RTPstat::update(uint32_t saddr, uint32_t time, uint8_t mosf1, uint8_t mosf2, uint8_t mosAD, uint16_t jitter, double loss) {

	uint32_t curtime = time / mod;

	if(lasttime1 == 0) {
		lasttime1 = curtime;
		lasttime2 = curtime;
	}

	if(curtime < lasttime1) {
		// update time is too old - discard
		return;
	}
	
	lock();
	
	map<uint32_t, node_t> *cmap;
	if(curtime < lasttime2) {
		// update time belongs to previous interval
		cmap = maps[0];
	} else if(curtime == lasttime2) {
		// update time belongs to current interval 
		cmap = maps[1];
	} else {
		// update time is new - shift maps left and flush the left one 
		lasttime1 = lasttime2;
		lasttime2 = curtime;
		flush_and_clean(maps[0], false);
		// swap maps 
		map<uint32_t, node_t> *saddr_map_tmp =maps[0];
		maps[0] = maps[1];
		maps[1] = saddr_map_tmp;
		cmap = maps[1];
	}

	map<uint32_t, node_t>::iterator saddr_map_it = cmap->find(saddr);

	if(saddr_map_it == cmap->end()){
		// not found
		node_t node;
		node.time = curtime * mod;
		node.mosf1_min = mosf1;
		node.mosf1_avg = mosf1;
		node.mosf2_min = mosf2;
		node.mosf2_avg = mosf2;
		node.mosAD_min = mosAD;
		node.mosAD_avg = mosAD;
		node.jitter_max = jitter;
		node.jitter_avg = jitter;
		node.loss_max = loss;
		node.loss_avg = loss;
		node.counter = 1;

		(*cmap)[saddr] = node;
	} else {
		// found
		node_t *node = &(saddr_map_it->second);

		if(node->mosf1_min > mosf1) {
			node->mosf1_min = mosf1;
		}
		node->mosf1_avg = ((node->mosf1_avg * node->counter ) + mosf1) / (node->counter + 1);
		if(node->mosf2_min > mosf2) {
			node->mosf2_min = mosf2;
		}
		node->mosf1_avg = ((node->mosf1_avg * node->counter ) + mosf1) / (node->counter + 1);
		if(node->mosAD_min > mosAD) {
			node->mosAD_min = mosAD;
		}
		node->mosAD_avg = ((node->mosAD_avg * node->counter ) + mosAD) / (node->counter + 1);

		if(node->jitter_max < jitter) {
			node->jitter_max = jitter;
		}
		node->jitter_avg = ((node->jitter_avg * node->counter ) + jitter) / (node->counter + 1);

		if(node->loss_max < loss) {
			node->loss_max = loss;
		}
		node->loss_avg = ((node->loss_avg * node->counter ) + loss) / (node->counter + 1.0);

		node->counter++;
	}

	unlock();
}

/*

walk through saddr_map (all RTP source IPs) and store result to the datbase 

*/
void
RTPstat::flush_and_clean(map<uint32_t, node_t> *cmap, bool needLock) {
	if(needLock) lock();

	extern int opt_nocdr;
	string query_str;
	if(!opt_nocdr) {
		map<uint32_t, node_t>::iterator it;

		if(!sqlDbSaveCall) {
			sqlDbSaveCall = createSqlObject();
			sqlDbSaveCall->setEnableSqlStringInContent(true);
		}

		vector<SqlDb_row> rtp_stat_rows;
		for(it = cmap->begin(); it != cmap->end(); it++) {
			node_t *node = &it->second;
			SqlDb_row rtp_stat;
			// create queries 
			rtp_stat.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor");
			rtp_stat.add(sqlDateTimeString(node->time), "time");
			rtp_stat.add(sqlDateTimeString(node->time), "time");
			rtp_stat.add(htonl(it->first), "saddr");
			rtp_stat.add(node->mosf1_min, "mosf1_min");
			rtp_stat.add((int)(node->mosf1_avg), "mosf1_avg");
			rtp_stat.add(node->mosf2_min, "mosf2_min");
			rtp_stat.add((int)(node->mosf2_avg), "mosf2_avg");
			rtp_stat.add(node->mosAD_min, "mosAD_min");
			rtp_stat.add((int)(node->mosAD_avg), "mosAD_avg");
			rtp_stat.add(node->jitter_max, "jitter_max");
			rtp_stat.add((int)(node->jitter_avg), "jitter_avg");
			rtp_stat.add((int)round(node->loss_max * 10), "loss_max_mult10");
			rtp_stat.add((int)round(node->loss_avg * 10), "loss_avg_mult10");
			rtp_stat.add(node->counter, "counter");
			if(opt_mysql_enable_multiple_rows_insert) {
				rtp_stat_rows.push_back(rtp_stat);
			} else {
				query_str += sqlDbSaveCall->insertQuery("rtp_stat", rtp_stat, false, false, true) + ";";
			}
		}
		if(opt_mysql_enable_multiple_rows_insert && rtp_stat_rows.size()) {
			query_str += sqlDbSaveCall->insertQueryWithLimitMultiInsert("rtp_stat", &rtp_stat_rows, opt_mysql_max_multiple_rows_insert, NULL, false, false, true) + ";";
		}
	}

	cmap->clear();
	if(needLock) unlock();

	//TODO enableBatchIfPossible
	if(!opt_nocdr && isSqlDriver("mysql") && !query_str.empty()) {
		static unsigned int counterSqlStore = 0;
		int storeId = STORE_PROC_ID_CDR_1 +
			      (opt_mysqlstore_max_threads_cdr > 1 &&
			       sqlStore->getSize(STORE_PROC_ID_CDR_1) > 1000 ?
				counterSqlStore % opt_mysqlstore_max_threads_cdr :
				0);
		//cout << query_str << "\n";
		
		++counterSqlStore;
		sqlStore->query_lock(query_str.c_str(), storeId);
	}
}

void
RTPstat::flush() {
	flush_and_clean(maps[0]);
	flush_and_clean(maps[1]);
}
