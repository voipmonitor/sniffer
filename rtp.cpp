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
#include "codec_alaw.h"
#include "codec_ulaw.h"
#include "mos_g729.h"   
#include "sql_db.h"   
#include "srtp.h"
#include "ssl_dssl.h"

#include "jitterbuffer/jitterbuf.h"
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
extern bool opt_srtp_rtp_dtls_decrypt;
extern bool opt_srtp_rtp_dtmf_decrypt;
extern int opt_srtp_rtp_verify_tag_max_attempts;
extern int opt_jitterbuffer_f1;            // turns off/on jitterbuffer simulator to compute MOS score mos_f1
extern int opt_jitterbuffer_f2;            // turns off/on jitterbuffer simulator to compute MOS score mos_f2
extern int opt_jitterbuffer_adapt;         // turns off/on jitterbuffer simulator to compute MOS score mos_adapt
extern int opt_jitterbuffer_f1_jbsize;
extern int opt_jitterbuffer_f1_resync_threshold;
extern int opt_jitterbuffer_f2_jbsize;
extern int opt_jitterbuffer_f2_resync_threshold;
extern int opt_jitterbuffer_adapt_jbsize;
extern int opt_jitterbuffer_adapt_resync_threshold;
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
extern u_int64_t opt_silence_detect_after_answer;
extern int opt_ivrdetect;
extern SqlDb *sqlDbSaveCall;
extern int opt_mysqlstore_max_threads_cdr;
extern MySqlStore *sqlStore;
extern int opt_id_sensor;
extern bool opt_saveaudio_answeronly;
extern bool opt_saveaudio_resync_jitterbuffer;
extern bool opt_saveaudio_adaptive_jitterbuffer;
extern int opt_saveaudio_jitterbuffer_jbsize;
extern int opt_saveaudio_jitterbuffer_resync_threshold;
extern int opt_mysql_enable_multiple_rows_insert;
extern int opt_mysql_max_multiple_rows_insert;
extern int opt_jitter_forcemark_transit_threshold;
extern int opt_jitter_forcemark_delta_threshold;
extern bool opt_save_energylevels;
extern bool opt_save_energylevels_check_seq;
extern bool opt_save_energylevels_via_jb;
extern char opt_energylevelheader[128];
extern bool opt_rtp_count_all_sequencegap_as_loss;
extern bool opt_check_diff_ssrc_on_same_ip_port;
extern int opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap;
extern bool opt_disable_rtp_seq_probation;
extern bool opt_disable_rtp_seq_check;
extern bool opt_rtp_seq_dupl_skip_ext;

extern sStreamAnalysisData *rtp_stream_analysis_data;

int calculate_mos_fromdsp(RTP *rtp, struct dsp *DSP);

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
	case PAYLOAD_EVS:
		return 16;
		break;
	default:
		return 8;
	}
}

#if not EXPERIMENTAL_LITE_RTP_MOD

/* constructor */
RTP::RTP(int sensor_id, vmIP sensor_ip) 
 : graph(this) {
	id.init();
	pkt.init();
	jb.init();
	jb.lastframetype = AST_FRAME_VOICE;
	media.init();
	timing.init();
	ttl.init();
	forcemark.init();
	link.init();
	stats.init();
	s.init();
	delay_win.init();
	srtp.init();
	nintervals = 1;

	mos.init();
	sdp.init();
	dtmf.init();
	silence.init();
	rtcp.init();
	rtcp_xr.init();
	raw.init();
	files.init();
	energy.init();
	diag.init(sensor_id, sensor_ip);

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	jb.channel_fix1 = new FILE_LINE(24002) ast_channel;
	memset(jb.channel_fix1, 0, sizeof(ast_channel));
	jb.channel_fix1->jitter_impl = 0; // fixed
	jb.channel_fix1->jitter_max = opt_jitterbuffer_f1_jbsize > 0 ? opt_jitterbuffer_f1_jbsize : 50;
	jb.channel_fix1->jitter_resync_threshold = opt_jitterbuffer_f1_resync_threshold > 0 ? opt_jitterbuffer_f1_resync_threshold : 100;
	jb.channel_fix1->last_datalen = 0;
	jb.channel_fix1->lastbuflen = 0;
	jb.channel_fix1->resync = 1;
	jb.channel_fix1->audiobuf = NULL;
	jb.channel_fix1->rtp_stream = this;

	jb.channel_fix2 = new FILE_LINE(24003) ast_channel;
	memset(jb.channel_fix2, 0, sizeof(ast_channel));
	jb.channel_fix2->jitter_impl = 0; // fixed
	jb.channel_fix2->jitter_max = opt_jitterbuffer_f2_jbsize > 0 ? opt_jitterbuffer_f2_jbsize : 200;
	jb.channel_fix2->jitter_resync_threshold = opt_jitterbuffer_f2_resync_threshold > 0 ? opt_jitterbuffer_f2_resync_threshold : 200;
	jb.channel_fix2->last_datalen = 0;
	jb.channel_fix2->lastbuflen = 0;
	jb.channel_fix2->resync = 1;
	jb.channel_fix2->audiobuf = NULL;
	jb.channel_fix2->rtp_stream = this;

	jb.channel_adapt = new FILE_LINE(24004) ast_channel;
	memset(jb.channel_adapt, 0, sizeof(ast_channel));
	jb.channel_adapt->jitter_impl = 1; // adaptive
	jb.channel_adapt->jitter_max = opt_jitterbuffer_adapt_jbsize > 0 ? opt_jitterbuffer_adapt_jbsize : 500;
	jb.channel_adapt->jitter_resync_threshold = opt_jitterbuffer_adapt_resync_threshold > 0 ? opt_jitterbuffer_adapt_resync_threshold : 500;
	jb.channel_adapt->last_datalen = 0;
	jb.channel_adapt->lastbuflen = 0;
	jb.channel_adapt->resync = 1;
	jb.channel_adapt->audiobuf = NULL;
	jb.channel_adapt->rtp_stream = this;

	jb.channel_record = new FILE_LINE(24005) ast_channel;
	memset(jb.channel_record, 0, sizeof(ast_channel));
	if(opt_saveaudio_adaptive_jitterbuffer) {
		jb.channel_record->jitter_impl = 1;
		jb.channel_record->jitter_max = opt_saveaudio_jitterbuffer_jbsize > 0 ? opt_saveaudio_jitterbuffer_jbsize : 500;
	} else {
		jb.channel_record->jitter_impl = 0;
		jb.channel_record->jitter_max = opt_saveaudio_jitterbuffer_jbsize > 0 ? opt_saveaudio_jitterbuffer_jbsize : 60;
	}
	jb.channel_record->jitter_resync_threshold = opt_saveaudio_jitterbuffer_resync_threshold > 0 ? opt_saveaudio_jitterbuffer_resync_threshold : 1000;
	jb.channel_record->last_datalen = 0;
	jb.channel_record->lastbuflen = 0;
	jb.channel_record->resync = opt_saveaudio_resync_jitterbuffer;
	jb.channel_record->audiobuf = NULL;
	jb.channel_record->audio_decode = true;
	jb.channel_record->rtp_stream = this;

	jb.frame = new FILE_LINE(24006) ast_frame;
	memset(jb.frame, 0, sizeof(ast_frame));
	jb.frame->frametype = AST_FRAME_VOICE;
	#endif

	if(opt_save_energylevels && opt_save_energylevels_via_jb) {
		#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
		jb.channel_record->enable_save_energylevels = 1;
		#endif
		energy.via_jb = true;
	}
}

void 
RTP::setSRtpDecrypt(RTPsecure *srtp_decrypt, int index_call_ip_port, bool local) {
	srtp.decrypt = srtp_decrypt;
	srtp.decrypt_index_call_ip_port = index_call_ip_port;
	srtp.decrypt_local = local;
}


void
RTP::save_mos_graph(bool delimiter) {
	sStreamAnalysisData::sStreamAnalysisRowMos *rtp_stream_analysis_mos = NULL;
 
	Call *owner = (Call*)id.call_owner;

	if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
		this->graph.write((char*)&graph_mos, 4);
		owner->save_rtp_graph = true;
	}

	u_int64_t new_mos_time_ms = TIME_US_TO_MS(timing.last_packet_time_us - timing.first_packet_time_us);
	u_int64_t diff_mos_time_ms = mos.time_ms ? new_mos_time_ms - mos.time_ms : 0;
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(opt_jitterbuffer_f1 > 0 and jb.channel_fix1) {
		mos.last_interval_f1 = calculate_mos_fromrtp(this, 1, 1);

		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&mos.last_interval_f1, 1);
		}
		// reset 10 second MOS stats
		memcpy(jb.channel_fix1->last_interval_loss, jb.channel_fix1->loss, sizeof(unsigned short int) * 128);
		if(mos.f1_min > mos.last_interval_f1) {
			mos.f1_min = mos.last_interval_f1;
		}
		if(mos.time_ms && new_mos_time_ms) {
			mos.f1_avg = ((mos.f1_avg * mos.time_ms) + (mos.last_interval_f1 * diff_mos_time_ms)) / new_mos_time_ms;
		} else {
			mos.f1_avg = mos.last_interval_f1;
		}
		if(rtp_stream_analysis_data) {
			if(!rtp_stream_analysis_mos) {
				rtp_stream_analysis_mos = new sStreamAnalysisData::sStreamAnalysisRowMos;
			}
			rtp_stream_analysis_mos->f1 = mos.last_interval_f1;
		}
		if(sverb.graph_mos) {
			cout << "MOS F1"
			     << " saddr: " << id.saddr.getString().c_str() << " ssrc: " << hex << id.ssrc << dec
			     << " act_time: " << (double)new_mos_time_ms / 1000 << "s " << " old_time: " << (double)mos.time_ms / 1000 << "s" << " diff_time: " << (double)diff_mos_time_ms / 1000 << "s"
			     << " last_mos: " << (int)mos.last_interval_f1 << " avg_mos: " << mos.f1_avg
			     << endl;
		}
	} else 
	#endif
	{
		if(opt_jitterbuffer_f1 == 0) {
			mos.last_interval_f1 = 45;
			mos.f1_min = 45;
			mos.f1_avg = 45;
			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				this->graph.write((char*)&mos.last_interval_f1, 1);
			}
		} else {
			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				char zero = 0;
				this->graph.write(&zero, 1);
			}
		}
	}
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(opt_jitterbuffer_f2 > 0 and jb.channel_fix2) {
		mos.last_interval_f2 = calculate_mos_fromrtp(this, 2, 1);
		//if(verbosity > 1) printf("mosf2[%d]\n", mos.last_interval_f2);
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&mos.last_interval_f2, 1);
		}
		// reset 10 second MOS stats
		memcpy(jb.channel_fix2->last_interval_loss, jb.channel_fix2->loss, sizeof(unsigned short int) * 128);
		if(mos.f2_min > mos.last_interval_f2) {
			mos.f2_min = mos.last_interval_f2;
		}
		if(mos.time_ms && new_mos_time_ms) {
			mos.f2_avg = ((mos.f2_avg * mos.time_ms) + (mos.last_interval_f2 * diff_mos_time_ms)) / new_mos_time_ms;
		} else {
			mos.f2_avg = mos.last_interval_f2;
		}
		if(rtp_stream_analysis_data) {
			if(!rtp_stream_analysis_mos) {
				rtp_stream_analysis_mos = new sStreamAnalysisData::sStreamAnalysisRowMos;
			}
			rtp_stream_analysis_mos->f2 = mos.last_interval_f2;
		}
		if(sverb.graph_mos) {
			cout << "MOS F2"
			     << " saddr: " << id.saddr.getString().c_str() << " ssrc: " << hex << id.ssrc << dec
			     << " act_time: " << (double)new_mos_time_ms / 1000 << "s " << " old_time: " << (double)mos.time_ms / 1000 << "s" << " diff_time: " << (double)diff_mos_time_ms / 1000 << "s"
			     << " last_mos: " << (int)mos.last_interval_f2 << " avg_mos: " << mos.f2_avg
			     << endl;
		}
	} else 
	#endif
	{
		if(opt_jitterbuffer_f2 == 0) {
			mos.last_interval_f2 = 45;
			mos.f2_min = 45;
			mos.f2_avg = 45;
			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				this->graph.write((char*)&mos.last_interval_f2, 1);
			}
		} else {
			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				char zero = 0;
				this->graph.write(&zero, 1);
			}
		}
	}
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(opt_jitterbuffer_adapt > 0 and jb.channel_adapt) {
		mos.last_interval_AD = calculate_mos_fromrtp(this, 3, 1);
		//if(verbosity > 1) printf("mosAD[%d]\n", mos.last_interval_AD);
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&mos.last_interval_AD, 1);
		}
		// reset 10 second MOS stats
		memcpy(jb.channel_adapt->last_interval_loss, jb.channel_adapt->loss, sizeof(unsigned short int) * 128);
		if(mos.AD_min > mos.last_interval_AD) {
			mos.AD_min = mos.last_interval_AD;
		}
		if(mos.time_ms && new_mos_time_ms) {
			mos.AD_avg = ((mos.AD_avg * mos.time_ms) + (mos.last_interval_AD * diff_mos_time_ms)) / new_mos_time_ms;
		} else {
			mos.AD_avg = mos.last_interval_AD;
		}
		if(rtp_stream_analysis_data) {
			if(!rtp_stream_analysis_mos) {
				rtp_stream_analysis_mos = new sStreamAnalysisData::sStreamAnalysisRowMos;
			}
			rtp_stream_analysis_mos->adapt = mos.last_interval_AD;
		}
		if(sverb.graph_mos) {
			cout << "MOS AD"
			     << " saddr: " << id.saddr.getString().c_str() << " ssrc: " << hex << id.ssrc << dec
			     << " act_time: " << (double)new_mos_time_ms / 1000 << "s " << " old_time: " << (double)mos.time_ms / 1000 << "s" << " diff_time: " << (double)diff_mos_time_ms / 1000 << "s"
			     << " last_mos: " << (int)mos.last_interval_AD << " avg_mos: " << mos.AD_avg
			     << endl;
		}
	} else 
	#endif
	{
		if(opt_jitterbuffer_adapt == 0) {
			mos.last_interval_AD = 45;
			mos.AD_min = 45;
			mos.AD_avg = 45;
			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				this->graph.write((char*)&mos.last_interval_AD, 1);
			}
		} else {
			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				char zero = 0;
				this->graph.write(&zero, 1);
			}
		}
	}

	if(opt_silencedetect and jb.DSP) {
		mos.last_interval_Silence = calculate_mos_fromdsp(this, jb.DSP);
		//if(verbosity > 1) printf("mosSilence[%d]\n", mos.last_interval_Silence);
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&mos.last_interval_Silence, 1);
		}
		// reset 10 second MOS stats
		memcpy(jb.DSP->last_interval_loss_hist, jb.DSP->loss_hist, sizeof(unsigned short int) * 32);
		jb.DSP->received = 0;
		bool mosSilence_first = mos.Silence_min == (uint8_t)-1;
		if(mos.Silence_min > mos.last_interval_Silence) {
			mos.Silence_min = mos.last_interval_Silence;
			//printf("[%p] min[%u] %p DSP[%p]\n", this, mos.Silence_min, &mos.Silence_min, jb.DSP);
		}
		if(mos.time_ms && new_mos_time_ms && !mosSilence_first) {
			mos.Silence_avg = ((mos.Silence_avg * mos.time_ms) + (mos.last_interval_Silence * diff_mos_time_ms)) / new_mos_time_ms;
		} else {
			mos.Silence_avg = mos.last_interval_Silence;
		}
		if(rtp_stream_analysis_data) {
			if(!rtp_stream_analysis_mos) {
				rtp_stream_analysis_mos = new sStreamAnalysisData::sStreamAnalysisRowMos;
			}
			rtp_stream_analysis_mos->silence = mos.last_interval_Silence;
		}
		if(sverb.graph_mos) {
			cout << "MOS SL"
			     << " saddr: " << id.saddr.getString().c_str() << " ssrc: " << hex << id.ssrc << dec
			     << " act_time: " << (double)new_mos_time_ms / 1000 << "s " << " old_time: " << (double)mos.time_ms / 1000 << "s" << " diff_time: " << (double)diff_mos_time_ms / 1000 << "s"
			     << " last_mos: " << (int)mos.last_interval_Silence << " avg_mos: " << mos.Silence_avg
			     << endl;
		}
	} else if(opt_silencedetect and mos.Silence_min != (uint8_t)-1) {
		mos.last_interval_Silence = 45;
		mos.Silence_min = 45;
		mos.Silence_avg = 45;
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&mos.last_interval_Silence, 1);
		}
	} else {
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			char zero = 0;
			this->graph.write(&zero, 1);
		}
	}

	// write end zero byte after mos
	if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
		char zero = 0;
		this->graph.write(&zero, 1);
	}
	
	if(delimiter) {
		if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
			this->graph.write((char*)&graph_delimiter, 4);
		}
	}
	
	mos.time_ms = new_mos_time_ms;

	if(sverb.graph) {
		printf("rtp[%p] saddr[%s] ssrc[%x] time[%u] seq[%u] \nMOS F1 cur[%d] min[%d] avg[%f]\nMOS F2 cur[%d] min[%d] avg[%f]\nMOS AD cur[%d] min[%d] avg[%f]\n ------\n", 
		       this, id.saddr.getString().c_str(), id.ssrc, (unsigned int)pkt.header_ts.tv_sec, pkt.seq, 
		       mos.last_interval_f1, mos.f1_min, mos.f1_avg,
		       mos.last_interval_f2, mos.f2_min, mos.f2_avg,
		       mos.last_interval_AD, mos.AD_min, mos.AD_avg);
	}

	uint32_t lost = stats.lost_with_reinvite_gaps - mos.last_stat_lost;
	uint32_t received = stats.received - mos.last_stat_received;

	mos.last_stat_lost = stats.lost_with_reinvite_gaps;
	mos.last_stat_received = stats.received;

	mos.last_stat_loss_perc_mult10 = (double)lost / ((double)received + (double)lost) * 100.0;

	if(!is_read_from_file_simple()) {
		rtp_stat.update(id.saddr, pkt.header_ts.tv_sec, mos.last_interval_f1, mos.last_interval_f2, mos.last_interval_AD, timing.jitter, mos.last_stat_loss_perc_mult10);
	}
	
	if(rtp_stream_analysis_data && rtp_stream_analysis_mos) {
		rtp_stream_analysis_data->mos[new_mos_time_ms] = rtp_stream_analysis_mos;
	}
}

/* destructor */
RTP::~RTP() {
	/*
	if(media.packetization)
		RTP::dump();
	*/

	if(verbosity > 9) {
		RTP::dump();
	}

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(raw.gfile || raw.init_done) {
		jitterbuffer_fixed_flush(jb.channel_record);
		__SYNC_LOCK(raw.gfile_lock);
		FILE *tmp_gfileRAW = raw.gfile;
		raw.gfile = NULL;
		__SYNC_UNLOCK(raw.gfile_lock);
		if(tmp_gfileRAW) {
			fclose(tmp_gfileRAW);
		}
	}
	#endif

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	ast_jb_destroy(jb.channel_fix1);
	ast_jb_destroy(jb.channel_fix2);
	ast_jb_destroy(jb.channel_adapt);
	ast_jb_destroy(jb.channel_record);
	delete jb.channel_fix1;
	delete jb.channel_fix2;
	delete jb.channel_adapt;
	delete jb.channel_record;
	delete jb.frame;

	if(raw.gfile_buffer) {
		delete [] raw.gfile_buffer;
	}
	#endif

	if(jb.DSP) {
		dsp_free(jb.DSP);
	}
	if(jb.DSP_ivr) {
		dsp_free(jb.DSP_ivr);
	}
	
	if(energy.buf) {
		delete energy.buf;
	}
	
	if(srtp.decrypt && srtp.decrypt_local) {
		delete srtp.decrypt;
	}
}

const int RTP::get_payload_len() {
	pkt.payload_data = pkt.data + sizeof(RTPFixedHeader);
	pkt.payload_len = pkt.len - sizeof(RTPFixedHeader);
	if(getPadding()) {
		/*
		* If set, this packet contains one or more additional padding
		* bytes at the end which are not part of the payload. The last
		* byte of the padding contains a count of how many padding bytes
		* should be ignored. Padding may be needed by some encryption
		* algorithms with fixed block sizes or for carrying several RTP
		* packets in a lower-layer protocol data unit.
		*/
		u_int8_t padding = ((u_int8_t *)pkt.data)[pkt.len - 1];
		if(padding > 0 && padding < pkt.payload_len) {
			pkt.payload_len -= padding;
			pkt.padding_len = padding;
		}
	}
	if(getCC() > 0) {
		/*
		* The number of CSRC identifiers that follow the fixed header.
		*/
		int cc = 4 * getCC();
		if(cc > 0 && cc < pkt.payload_len) {
			pkt.payload_data += cc;
			pkt.payload_len -= cc;
		}
	}
	if(getExtension()) {
		/*
		* If set, the fixed header is followed by exactly one header extension.
		*/
		extension_hdr_t *rtpext;
		// the extension, if present, is after the CSRC list.
		rtpext = (extension_hdr_t *)((u_int8_t *)pkt.payload_data);
		pkt.payload_data += sizeof(extension_hdr_t) + ntohs(rtpext->length) * 4;
		pkt.payload_len -= sizeof(extension_hdr_t) + ntohs(rtpext->length) * 4;

		if (pkt.payload_len < 2) {
			pkt.payload_data = pkt.data + sizeof(RTPFixedHeader);
			pkt.payload_len = 0;
		}

	}
	return pkt.payload_len;
}

/* flush jitterbuffer */
void RTP::jitterbuffer_fixed_flush(struct ast_channel */*jchannel*/) {
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	jb_fixed_flush_deliver(jb.channel_record);
	#endif
}

static inline void rtp_scale_codec_ts(int codec, u_int32_t cur_ts, u_int32_t prev_ts,
				      long *out_frame_ts, u_int32_t *out_last_ts) {
	switch(codec) {
		case PAYLOAD_VXOPUS12:
		case PAYLOAD_XOPUS12:
		case PAYLOAD_OPUS12:
		case PAYLOAD_G722112:
			*out_frame_ts = cur_ts / 12;
			*out_last_ts = prev_ts / 12;
			break;
		case PAYLOAD_ISAC16:
		case PAYLOAD_SILK16:
		case PAYLOAD_VXOPUS16:
		case PAYLOAD_XOPUS16:
		case PAYLOAD_OPUS16:
		case PAYLOAD_G722116:
		case PAYLOAD_AMRWB:
		case PAYLOAD_EVS:
			*out_frame_ts = cur_ts / 16;
			*out_last_ts = prev_ts / 16;
			break;
		case PAYLOAD_SILK24:
		case PAYLOAD_VXOPUS24:
		case PAYLOAD_XOPUS24:
		case PAYLOAD_OPUS24:
		case PAYLOAD_G722124:
			*out_frame_ts = cur_ts / 24;
			*out_last_ts = prev_ts / 24;
			break;
		case PAYLOAD_ISAC32:
		case PAYLOAD_G722132:
			*out_frame_ts = cur_ts / 32;
			*out_last_ts = prev_ts / 32;
			break;
		case PAYLOAD_VXOPUS48:
		case PAYLOAD_XOPUS48:
		case PAYLOAD_OPUS48:
			*out_frame_ts = cur_ts / 48;
			*out_last_ts = prev_ts / 48;
			break;
		default:
			*out_frame_ts = cur_ts / 8;
			*out_last_ts = prev_ts / 8;
			break;
	}
}

static inline bool rtp_check_packetization_valid(int packetization, int &pinformed, Call *owner, u_int32_t ssrc) {
	if(__builtin_expect(packetization <= 1, 0)) {
		if(pinformed == 0) {
			if(owner) {
				syslog(LOG_ERR, "call-id[%s] ssrc[%x]: packetization is %i in jitterbuffer function.", owner->get_fbasename_safe(), ssrc, packetization);
			} else {
				syslog(LOG_ERR, "call-id[N/A] ssrc[%x]: packetization is %i in jitterbuffer function.", ssrc, packetization);
			}
		}
		pinformed = 1;
		return false;
	}
	pinformed = 0;
	return true;
}

static inline bool rtp_pause_seq_ts_match(int seqno, u_int16_t last_seq, long frame_ts, u_int32_t prev_ts, int packetization) {
	return (seqno == ROT_SEQ(last_seq + 1) &&
		frame_ts > prev_ts &&
		(int)(frame_ts - prev_ts) < packetization * 2);
}

static inline bool rtp_channel_has_rtp_pause(struct ast_channel *ch, const struct timeval &header_ts, int packetization) {
	if(!ch || !ch->jb_reseted || !ast_jb_test(ch)) {
		return false;
	}
	struct timeval next_ts = ast_tv_add_ms_fast(ch->last_ts, packetization);
	int msdiff = ast_tvdiff_ms(header_ts, next_ts);
	return (msdiff <= packetization * 10000 &&
		msdiff >= opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap);
}

/* add silence to RTP stream from last packet time to current time which is in header->ts */
void
RTP::jt_tail(struct pcap_pkthdr *header) {

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
 
	if(!ast_jb_test(jb.channel_record)) {
		// there is no ongoing recording, return
		return;
	}

	/* protect for endless loops (it cannot happen in theory but to be sure */
	if(media.packetization <= 1) {
		Call *owner = (Call*)id.call_owner;
		if(owner) {
			syslog(LOG_ERR, "call-id[%s]: packetization is %i in jitterbuffer function.", owner->get_fbasename_safe(), media.packetization);
		} else {
			syslog(LOG_ERR, "call-id[N/A]: packetization is %i in jitterbuffer function.", media.packetization);
		}
		return;
	}

	/* calculate time difference between last packet and current packet + packetization time*/ 
	if(jb.channel_record->last_ts.tv_sec == 0) {
		// previouuse tv_sec is not set, set it
		memcpy(&jb.channel_record->last_ts, &header->ts, sizeof(timeval));
		return;
	}
	int msdiff = ast_tvdiff_ms(header->ts, jb.channel_record->last_ts);
	msdiff -= media.packetization;

	while( msdiff >= media.packetization )  {
		silence.tailedframes++;
		ast_jb_get_and_deliver(jb.channel_record, &jb.channel_record->last_ts);
		/* adding packetization time to last_ts time */ 
		jb.channel_record->last_ts = ast_tv_add_ms_fast(jb.channel_record->last_ts, media.packetization);
		msdiff -= media.packetization;
	}
	
	#endif
	
}

#if 1
/* simulate jitterbuffer */
void
RTP::jitterbuffer(struct ast_channel *channel, bool save_audio, bool energylevels, bool mos_lqo) {
 
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS

	if(media.codec == PAYLOAD_TELEVENT) return;

	Call *owner = (Call*)id.call_owner;
 
	extern int opt_jitterbuffer_adapt_ooo_limit;
	if(channel->jitter_impl == 1 && opt_jitterbuffer_adapt_ooo_limit > 0 && 
	   channel->jb.jbobj && ((jitterbuf*)channel->jb.jbobj)->info.frames_ooo > 0) {
		if(channel->stopped_due_to_high_ooo) {
			return;
		} else if(((jitterbuf*)channel->jb.jbobj)->info.frames_ooo > opt_jitterbuffer_adapt_ooo_limit &&
			  (!((jitterbuf*)channel->jb.jbobj)->info.frames_in ||
			   (double)((jitterbuf*)channel->jb.jbobj)->info.frames_ooo / ((jitterbuf*)channel->jb.jbobj)->info.frames_in > 0.5)) {
			channel->stopped_due_to_high_ooo = true;
			media.stopped_jb_due_to_high_ooo = true;
			if(owner) {
				owner->stopped_jb_due_to_high_ooo = true;
			}
			return;
		}
	}
 
	if((save_audio || energylevels) && owner && owner->silencerecording) {
		// skip recording 
		jb.frame->skip = 1;
	} else {
		jb.frame->skip = 0;
	}
	struct timeval tsdiff;
	jb.frame->len = media.packetization;
	u_int32_t _last_ts;
	rtp_scale_codec_ts(media.codec, getTimestamp(), pkt.last_ts, &jb.frame->ts, &_last_ts);
	jb.frame->marker = getMarker();
	jb.frame->seqno = getSeqNum();
	channel->codec = media.codec;
	jb.frame->ignore = pkt.ignore;
	memcpy(&jb.frame->delivery, &pkt.header_ts, sizeof(struct timeval));

	/* protect for endless loops (it cannot happen in theory but to be sure */
	if(!rtp_check_packetization_valid(media.packetization, jb.pinformed, owner, getSSRC())) {
		return;
	}

	int mylen = MIN((unsigned int)pkt.len, pkt.header_ip->get_tot_len() - pkt.header_ip->get_hdr_size() - sizeof(udphdr2));

	if(save_audio || energylevels || mos_lqo ||
	   (media.codec == PAYLOAD_G729 || media.codec == PAYLOAD_G723 || media.codec == PAYLOAD_AMR || media.codec == PAYLOAD_AMRWB || media.codec == PAYLOAD_EVS)) {
		/* get RTP payload header and datalen */
		pkt.payload_data = pkt.data + sizeof(RTPFixedHeader);
		pkt.payload_len = mylen - sizeof(RTPFixedHeader);
		if(getPadding()) {
			/*
			* If set, this packet contains one or more additional padding
			* bytes at the end which are not part of the payload. The last
			* byte of the padding contains a count of how many padding bytes
			* should be ignored. Padding may be needed by some encryption
			* algorithms with fixed block sizes or for carrying several RTP
			* packets in a lower-layer protocol data unit.
			*/
			pkt.payload_len -= ((u_int8_t *)pkt.data)[pkt.payload_len - 1];
			pkt.padding_len = ((u_int8_t *)pkt.data)[pkt.payload_len - 1];
		}
		if(getCC() > 0) {
			/*
			* The number of CSRC identifiers that follow the fixed header.
			*/
			pkt.payload_data += 4 * getCC();
			pkt.payload_len -= 4 * getCC();
		}
		if(getExtension()) {
			/*
			* If set, the fixed header is followed by exactly one header extension.
			*/
			extension_hdr_t *rtpext;

			// the extension, if present, is after the CSRC list.
			rtpext = (extension_hdr_t *)((u_int8_t *)pkt.payload_data);
			pkt.payload_data += sizeof(extension_hdr_t) + ntohs(rtpext->length) * 4;
			pkt.payload_len -= sizeof(extension_hdr_t) + ntohs(rtpext->length) * 4;
			if (pkt.payload_len < 4) {
				pkt.payload_data = pkt.data + sizeof(RTPFixedHeader);
				pkt.payload_len = 0;
			}
			
		}
		jb.frame->data = pkt.payload_data;
		jb.frame->datalen = pkt.payload_len > 0 ? pkt.payload_len : 0; /* ensure that datalen is never negative */

		if(media.codec == PAYLOAD_G723) {
			// voipmonitor does not handle SID packets well (silence packets) it causes out of sync
			if((unsigned char)pkt.payload_data[0] & 2)  {

				/* check if jitterbuffer is already created. If not we have to create it because 
				   if call starts with SID packets first it will than cause out of sync calls 
				*/
				if(ast_test_flag(&channel->jb, (1 << 2))) {
					// jitterbuffer is created so we can skip SID packets now
					return;
				}
			}
		}

		if(!(pkt.payload_len == 0 && sverb.process_rtp_header)) {
			if(media.codec == PAYLOAD_G729 and (pkt.payload_len <= (media.packetization == 10 ? 9 : 12))) {
				jb.frame->frametype = AST_FRAME_DTMF;
				jb.frame->marker = 1;
			}
			if((media.codec == PAYLOAD_AMR or media.codec == PAYLOAD_AMRWB or media.codec == PAYLOAD_EVS) and pkt.payload_len <= 7) {
				jb.frame->frametype = AST_FRAME_DTMF;
				jb.frame->marker = 1;
			}
		}
	}

	if(media.lastcng or jb.lastframetype == AST_FRAME_DTMF) {
		jb.frame->marker = 1;
	}

	if(save_audio || energylevels || mos_lqo) {
		channel->rawstream = raw.gfile;
		if(id.iscaller) {
			owner->codec_caller = media.codec;
			owner->audioBufferData[0].set(&channel->audiobuf, jb.frame->seqno, id.ssrc, &pkt.header_ts);
		} else {
			owner->codec_called = media.codec;
			owner->audioBufferData[1].set(&channel->audiobuf, jb.frame->seqno, id.ssrc, &pkt.header_ts);
		}
		if(pkt.payload_len > 0) {
			channel->last_datalen = jb.frame->datalen;
		}
	} else {
		jb.frame->datalen = 0;
		jb.frame->data = NULL;
		channel->rawstream = NULL;
	}

	if(!save_audio && !energylevels && !mos_lqo &&
	   !channel->audiobuf && !channel->enable_save_energylevels &&
	   jb.frame->frametype == AST_FRAME_VOICE) {
		channel->rawstream = NULL;
		if(__builtin_expect(opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap && !jb.frame->marker, 0) &&
		   rtp_pause_seq_ts_match(jb.frame->seqno, pkt.last_seq, jb.frame->ts, _last_ts, media.packetization) &&
		   rtp_channel_has_rtp_pause(channel, pkt.header_ts, media.packetization)) {
			jb.frame->marker = 1;
		}
		ast_jb_sim_step(channel, &pkt.header_ts, jb.frame->ts, media.packetization, jb.frame->seqno,
				jb.frame->marker, jb.frame->lastframetype == AST_FRAME_VOICE, jb.frame->ignore, media.codec);
		return;
	}

	// create jitter buffer structures 
	ast_jb_do_usecheck(channel, &pkt.header_ts);
	if(channel->jb.timebase.tv_sec == pkt.header_ts.tv_sec &&
	   channel->jb.timebase.tv_usec == pkt.header_ts.tv_usec) {
		channel->last_ts = pkt.header_ts;
	}
	
	if(!channel->jb_reseted) {
		// initializing jitterbuffer 
		if(save_audio || energylevels) {
			jb.channel_record->jitter_max = jb.frame->len * 3; 
		}
		
		ast_jb_empty_and_reset(channel);
		channel->jb_reseted = 1;
		memcpy(&channel->last_ts, &pkt.header_ts, sizeof(struct timeval));
		ast_jb_put(channel, jb.frame, &pkt.header_ts);
		this->clearAudioBuff(owner, channel);
		return;
	}

	/* calculate time difference between last packet and current packet + packetization time*/ 
	int msdiff = ast_tvdiff_ms( pkt.header_ts, ast_tv_add_ms_fast(channel->last_ts, media.packetization) );
	//printf("ms:%d\n", msdiff);
	if(msdiff > media.packetization * 10000) {
		// difference is too big, reseting last_ts to current packet. If we dont check this it could happen to run while cycle endlessly
		memcpy(&channel->last_ts, &pkt.header_ts, sizeof(struct timeval));
		ast_jb_put(channel, jb.frame, &pkt.header_ts);
		if(verbosity > 4) syslog(LOG_ERR, "big timestamp jump (msdiff:%d packetization: %d) in this file: %s\n", msdiff, media.packetization, files.gfilename);
		this->clearAudioBuff(owner, channel);
		return;
	}

	/* between last packet and current packet is big timestamp difference and it could count 
	 * interpolated framed although it was silence so calculate real number of packets based 
	 * on timestamps in packet header, timestamps in rtp header and sequence numbers between 
	 * last packet and current packet
	 */

	// relative time difference calculated from packet sequence
	u_int32_t sequencems = (jb.frame->seqno - pkt.last_seq) * media.packetization;

	/* and now if there is bigger (lets say one second) timestamp difference (calculated from packet headers)
	 * between two last packets and transit time is equel or smaller than sequencems (with 200ms toleration),
	 * it was silence and manually mark the frame which indicates to not count interpolated frame and resynchronize jitterbuffer
	 */
	if(msdiff > 1000) {
		/* difference (in ms) between timestamps in packet header and rtp timestamps. this should
		 * be ideally equal to zero. Negative values mean that packet arrives earlier and positive
		 * values indicates that packet was late
		 */
		long double transit = (timeval_subtract(&tsdiff, pkt.header_ts, s.lastTimeRecJ) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0) - ((double)getTimestamp() - s.lastTimeStampJ)/(double)media.samplerate/1000;
		if(transit <= sequencems + 200) {
			// check if the last frame was CNG or the last frame was DTMF - force mark bit
			if(media.lastcng || jb.lastframetype == AST_FRAME_DTMF) {
				if(verbosity > 4) printf("jitterbuffer: manually marking packet, msdiff(%d) > 1000 and transit (%Lf) <= ((sequencems(%u) + 200)\n", msdiff, transit, sequencems);
				jb.frame->marker = 1;
			}
		}
	}
	
	if(opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap &&
	   msdiff >= opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap &&
	   rtp_pause_seq_ts_match(jb.frame->seqno, pkt.last_seq, jb.frame->ts, _last_ts, media.packetization)) {
		jb.frame->marker = 1;
	}

	// fetch packet from jitterbuffer every 20 ms regardless on packet loss or delay
	while( msdiff >= media.packetization )  {
		if(jb.frame->marker or jb.lastframetype == AST_FRAME_DTMF) {
			/* if last frame was marked or DTMF, ignore interpolated frames */
			channel->last_loss_burst = 0;
		}
		ast_jb_get_and_deliver(channel, &channel->last_ts);
		/* adding packetization time to last_ts time */ 
		channel->last_ts = ast_tv_add_ms_fast(channel->last_ts, (int)jb.frame->len);
		msdiff -= media.packetization;
	}

	//printf("s[%u] codec[%d]\n",getSeqNum(), media.codec);
	ast_jb_put(channel, jb.frame, &pkt.header_ts);
	
	this->clearAudioBuff(owner, channel);
	
	#endif
	
}

void
RTP::jitterbuffer_mos_all() {
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(!opt_jitterbuffer_f1 && !opt_jitterbuffer_f2 && !opt_jitterbuffer_adapt) {
		return;
	}
	if(media.codec == PAYLOAD_TELEVENT) return;

	if(__builtin_expect(media.codec == PAYLOAD_G729 || media.codec == PAYLOAD_G723 || media.codec == PAYLOAD_AMR || media.codec == PAYLOAD_AMRWB || media.codec == PAYLOAD_EVS, 0)) {
		if(opt_jitterbuffer_f1 > 0) jitterbuffer(jb.channel_fix1, false, false, false);
		if(opt_jitterbuffer_f2 > 0) jitterbuffer(jb.channel_fix2, false, false, false);
		if(opt_jitterbuffer_adapt > 0) jitterbuffer(jb.channel_adapt, false, false, false);
		return;
	}

	Call *owner = (Call*)id.call_owner;
	if(!rtp_check_packetization_valid(media.packetization, jb.pinformed, owner, getSSRC())) {
		return;
	}

	long frame_ts;
	u_int32_t _last_ts;
	rtp_scale_codec_ts(media.codec, getTimestamp(), pkt.last_ts, &frame_ts, &_last_ts);

	char base_marker = getMarker();
	int seqno = getSeqNum();
	if(media.lastcng || jb.lastframetype == AST_FRAME_DTMF) {
		base_marker = 1;
	}
	int last_is_voice = (jb.frame->lastframetype == AST_FRAME_VOICE);

	struct ast_channel *ch1 = (opt_jitterbuffer_f1 > 0) ? jb.channel_fix1 : NULL;
	struct ast_channel *ch2 = (opt_jitterbuffer_f2 > 0) ? jb.channel_fix2 : NULL;
	struct ast_channel *ch3 = (opt_jitterbuffer_adapt > 0) ? jb.channel_adapt : NULL;

	extern int opt_jitterbuffer_adapt_ooo_limit;
	if(__builtin_expect(ch3 && opt_jitterbuffer_adapt_ooo_limit > 0 &&
			    ch3->jb.jbobj && ((jitterbuf*)ch3->jb.jbobj)->info.frames_ooo > 0, 0)) {
		if(ch3->stopped_due_to_high_ooo) {
			ch3 = NULL;
		} else if(((jitterbuf*)ch3->jb.jbobj)->info.frames_ooo > opt_jitterbuffer_adapt_ooo_limit &&
			  (!((jitterbuf*)ch3->jb.jbobj)->info.frames_in ||
			   (double)((jitterbuf*)ch3->jb.jbobj)->info.frames_ooo / ((jitterbuf*)ch3->jb.jbobj)->info.frames_in > 0.5)) {
			ch3->stopped_due_to_high_ooo = true;
			media.stopped_jb_due_to_high_ooo = true;
			if(owner) {
				owner->stopped_jb_due_to_high_ooo = true;
			}
			ch3 = NULL;
		}
	}

	if(__builtin_expect(jb.frame->frametype != AST_FRAME_VOICE, 0)) {
		if(ch1) jitterbuffer(ch1, false, false, false);
		if(ch2) jitterbuffer(ch2, false, false, false);
		if(ch3) jitterbuffer(ch3, false, false, false);
		return;
	}

	char m1 = base_marker, m2 = base_marker, m3 = base_marker;
	if(__builtin_expect(opt_ignore_mos_degradation_in_rtp_pause_without_seq_gap && !base_marker, 0) &&
	   rtp_pause_seq_ts_match(seqno, pkt.last_seq, frame_ts, _last_ts, media.packetization)) {
		if(rtp_channel_has_rtp_pause(ch1, pkt.header_ts, media.packetization)) m1 = 1;
		if(rtp_channel_has_rtp_pause(ch2, pkt.header_ts, media.packetization)) m2 = 1;
		if(rtp_channel_has_rtp_pause(ch3, pkt.header_ts, media.packetization)) m3 = 1;
	}

	ast_jb_sim_step_3(ch1, ch2, ch3, &pkt.header_ts, frame_ts, media.packetization, seqno,
			  m1, m2, m3, last_is_voice, pkt.ignore, media.codec);
	#endif
}
#endif

void 
RTP::process_dtmf_rfc2833() {
 
	if(pkt.len <= (int)sizeof(RTPFixedHeader)) {
		return;
	}

	unsigned int seqno = getSeqNum();
	unsigned int event, event_end, samples;
	char resp = 0;
	unsigned int timestamp = getTimestamp();

	unsigned char *pdata = pkt.data + sizeof(RTPFixedHeader);

	/* Figure out event, event end, and samples */
	event = ntohl(*((unsigned int *)(pdata)));
	event >>= 24;
	event_end = ntohl(*((unsigned int *)(pdata)));
	event_end <<= 8;
	event_end >>= 24;
	samples = ntohl(*((unsigned int *)(pdata)));
	samples &= 0xFFFF;

	if(dtmfdebug) syslog(LOG_ERR, "Got  RTP RFC2833 from %u (seq %-6.6u, ts %-6.6u, len %-6.6u, mark %d, event %08x, end %d, duration %-5.5d) \n",
		    getMarker(), seqno, timestamp, pkt.len, (getMarker()?1:0), event, ((event_end & 0x80)?1:0), samples);

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

	if ((dtmf.last_end_timestamp != timestamp) || (dtmf.lastdtmf && dtmf.lastdtmf != resp)) {
		dtmf.lastdtmf = resp;
		if(dtmfdebug) syslog(LOG_ERR, "dtmfevent %c\n", resp);
		dtmf.last_end_timestamp = timestamp;
		Call *owner = (Call*)id.call_owner;
		if(owner) {
			owner->handle_dtmf(resp, ts2double(pkt.header_ts.tv_sec, pkt.header_ts.tv_usec), id.saddr, id.daddr, s_dtmf::rfc2833);
		}
	}

        return;
}

//minimum uninterrupted noise from the called party that ends the
//"dead air after answer" measurement (silence_detect_after_answer);
//the value is documented in config/voipmonitor.conf
#define SILENCE_AFTERANSWER_MIN_NOISE_MS 40

//ivrdetect: minimum voice (audible, not a call progress tone) from the called
//party in early media; the value is documented in config/voipmonitor.conf
#define IVRDETECT_MIN_VOICE_MS 500

/* read rtp packet */
bool RTP::read(CallBranch *c_branch,
	       unsigned char* data, iphdr2 *header_ip, unsigned *len, struct pcap_pkthdr *header, vmIP saddr, vmIP daddr, vmPort sport, vmPort dport,
	       int sensor_id, vmIP sensor_ip, char *ifname, bool *decrypt_ok, volatile int8_t *decrypt_sync) {
 
	if(if_unlikely(link.stopReadProcessing)) {
		return(false);
	}
 
	pkt.data = data; 
	pkt.header_ip = header_ip;
	pkt.len = *len;
	pkt.header_ts = header->ts;
	id.saddr = saddr;
	id.daddr = daddr;
	id.dport = dport;
	id.sport = sport;
	pkt.ignore = 0;
	pkt.resetgraph = 0;
	
	if(if_likely(media.codec != -1 && media.codec != 13 && media.codec != 19 && media.codec != PAYLOAD_TELEVENT && !is_video())) {
		media.had_audio = true;
	}

	if(if_unlikely(sverb.ssrc && getSSRC() != sverb.ssrc)) return(false);
	
	u_int8_t ip_ttl = header_ip->get_ttl();
	if(if_unlikely(ttl.min < 0 || ip_ttl < ttl.min)) {
		ttl.min = ip_ttl;
	}
	if(if_unlikely(ttl.max < 0 || ip_ttl > ttl.max)) {
		ttl.max = ip_ttl;
	}
	ttl.sum += ip_ttl;
	++ttl.count;
	
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(if_unlikely(sverb.read_rtp)) {
		++diag.read_rtp_counter;
		cout << "RTP - read [" << this << "]-" 
		     << " ssrc: " << hex << id.ssrc << dec << " "
		     << " src: " << saddr.getString() << " : " << sport
		     << " dst: " << daddr.getString() << " : " << dport
		     << " seq: " << getSeqNum() << " "
		     << " direction: " << iscaller_description(id.iscaller) 
		     << " packets_received: " << this->stats.received
		     << " counter: " << diag.read_rtp_counter
		     << " ifname: " << (ifname ? ifname : "undefined")
		     << endl;
	}
	#endif
	
	Call *owner = (Call*)id.call_owner;

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	extern bool opt_receiver_check_id_sensor;
	if(if_unlikely(opt_receiver_check_id_sensor && ((diag.sensor_id >= 0 && diag.sensor_id != sensor_id) ||
	   (diag.sensor_ip.isSet() && diag.sensor_ip != sensor_ip)))) {
		if(!owner || !owner->rtp_from_multiple_sensors) {
			extern bool opt_disable_rtp_warning;
			if(!opt_disable_rtp_warning) {
				u_int64_t actTime = getTimeMS();
				if(actTime - 1000 > diag.lastTimeSyslog) {
					syslog(LOG_NOTICE, "warning - packet from sensor (%i/%s) in RTP created for sensor (%i/%s) - call %s", 
					       sensor_id, sensor_ip.isSet() ? sensor_ip.getString().c_str() : "-", 
					       diag.sensor_id, diag.sensor_ip.isSet() ? diag.sensor_ip.getString().c_str() : "-",
					       owner->fbasename);
					diag.lastTimeSyslog = actTime;
				}
			}
			if(owner) {
				owner->rtp_from_multiple_sensors = true;
			}
		}
		return(false);
	}
	#endif
	
	u_int64_t pcap_header_us = getTimeUS(header->ts);
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(if_unlikely(timing.last_packet_time_us && pcap_header_us < (timing.last_packet_time_us - 50000))) {
		if(!timing.pcap_header_ts_bad_time) {
			if(pcap_header_us < (timing.last_packet_time_us - 200000)) {
				extern bool opt_disable_rtp_warning;
				if(!opt_disable_rtp_warning) {
					u_int64_t actTime = getTimeMS();
					static u_int64_t s_lastTimeSyslog;
					if(actTime - 500 > s_lastTimeSyslog) {
						syslog(LOG_NOTICE, "warning - packet (seq:%i, ssrc: %x) from sensor (%i) has bad pcap header time (-%" int_64_format_prefix "luus) - call %s", 
						       getSeqNum(), getSSRC(), sensor_id, timing.last_packet_time_us - pcap_header_us, owner ? owner->fbasename : "unknown");
						s_lastTimeSyslog = actTime;
					}
				}
			}
			timing.pcap_header_ts_bad_time = true;
		}
		return(false);
	}
	#endif

	if(if_unlikely(timing.first_packet_time_us == 0)) {
		timing.first_packet_time_us = pcap_header_us;
		timing.next_save_mos_graph_us = (TIME_US_TO_MS(pcap_header_us) + 10001ULL) * 1000ULL;
	}
	timing.last_packet_time_us = pcap_header_us;

	extern bool opt_ignore_rtp_after_bye_confirmed;
	if(owner && !is_read_from_file_simple() && opt_ignore_rtp_after_bye_confirmed) {
		u_int64_t seenbye_and_ok_time_usec = owner->getSeenByeAndOkTimeUS(c_branch);
		if(if_unlikely(seenbye_and_ok_time_usec && pcap_header_us > seenbye_and_ok_time_usec)) {
			return(false);
		}
	}

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(if_unlikely(owner && owner->forcemark_time_size > forcemark.owner_used)) {
		owner->forcemark_lock();
		bool checkNextForcemark = false;
		do {
			checkNextForcemark = false;
			size_t _forcemark_size = owner->forcemark_time.size();
			if(_forcemark_size > forcemark.owner_used) {
				u_int64_t _forcemark_time = owner->forcemark_time[forcemark.owner_used];
				u_int64_t _header_time = pcap_header_us;
				if(_forcemark_time < _header_time) {
					if(_forcemark_time > timing.first_packet_time_us) {
						if(sverb.forcemark) {
							cout << "set forcemark: " << _forcemark_time 
							     << " header time: " << _header_time 
							     << " forcemarks size: " << (_forcemark_size - forcemark.owner_used)
							     << " ssrc: " << hex << getSSRC() << dec
							     << " seq: " << pkt.seq 
							     << " direction: " << iscaller_description(id.iscaller)
							     << endl;
						}
						forcemark.by_owner = true;
						forcemark.by_owner_set = true;
					} 
					++forcemark.owner_used;
					checkNextForcemark = true;
				}
			}
		} while(checkNextForcemark);
		owner->forcemark_unlock();
	}
	#endif

	pkt.payload_len = get_payload_len_fast();
	if(if_unlikely(pkt.payload_len < 0)) {
		if(owner) {
			if(!owner->error_negative_payload_length) {
				syslog(LOG_NOTICE, "warning - negative payload_len in call %s", owner->fbasename);
				owner->error_negative_payload_length = true;
			}
		} else {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > diag.lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - negative payload_len");
				diag.lastTimeSyslog = actTime;
			}
		}
		return(false);
	}
	
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	bool save_audio = 
		opt_saveRAW || opt_savewav_force || 
		(owner && 
		 (enable_audio_any(owner) ||
		  owner->audioBufferData[0].audiobuffer || owner->audioBufferData[1].audiobuffer));
	bool energylevels = 
		opt_save_energylevels && (!opt_energylevelheader[0] || (owner && owner->save_energylevels));
	bool mos_lqo = 
		owner &&
		((owner->flags & FLAG_RUNAMOSLQO) || (owner->flags & FLAG_RUNBMOSLQO)) &&
		(owner->connect_time_us && getTimeUS(header) > owner->connect_time_us);
	bool use_channel_record =
		((save_audio || energylevels) &&
		 (!opt_saveaudio_answeronly ||
		  (owner && owner->connect_time_us && getTimeUS(header) > owner->connect_time_us))) ||
		mos_lqo;
	#endif
	
	if(if_unlikely(srtp.decrypt)) {
		if(!srtp.decrypt_rtp_attempt[0]) {
			if(sverb.dtls && ssl_sessionkey_enable()) {
				string log_str;
				log_str += string("try call decrypt_rtp for call: ") + (owner ? owner->call_id : "unknown");
				log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(sdp.ssrc_index);
				ssl_sessionkey_log(log_str);
			}
		}
		++srtp.decrypt_rtp_attempt[0];
		if(srtp.decrypt->isVerifyOnly()) {
			if(!srtp.tag_verified && srtp.decrypt_rtp_attempt[0] <= (unsigned)opt_srtp_rtp_verify_tag_max_attempts) {
				if(srtp.decrypt->need_prepare_decrypt()) {
					srtp.decrypt->prepare_decrypt(saddr, daddr, sport, dport, false, pcap_header_us);
				}
				if(decrypt_sync) {
					__SYNC_LOCK(*decrypt_sync);
				}
				unsigned verify_data_len = *len;
				unsigned verify_payload_len = pkt.payload_len;
				if(srtp.decrypt->decrypt_rtp(data, &verify_data_len, pkt.payload_data, &verify_payload_len, pcap_header_us,
							     saddr, daddr, sport, dport, this)) {
					srtp.is_srtp = true;
					srtp.auth_tag_size = srtp.decrypt->tag_size();
					srtp.tag_verified = true;
				}
				if(decrypt_sync) {
					__SYNC_UNLOCK(*decrypt_sync);
				}
				if(!srtp.tag_verified && !srtp.probably_unencrypted_payload && is_unencrypted_payload(pkt.payload_data, pkt.payload_len)) {
					srtp.probably_unencrypted_payload = true;
				}
			}
		} else if(opt_srtp_rtp_decrypt ||
			  (opt_srtp_rtp_dtmf_decrypt && media.codec == PAYLOAD_TELEVENT) ||
			  (opt_srtp_rtp_dtls_decrypt && srtp.decrypt->is_dtls())
			  #if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
			  || use_channel_record
			  #endif
			  ) {
			if(!srtp.decrypt_rtp_attempt[1]) {
				if(sverb.dtls && ssl_sessionkey_enable()) {
					string log_str;
					log_str += string("call decrypt_rtp for call: ") + (owner ? owner->call_id : "unknown");
					log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(sdp.ssrc_index);
					ssl_sessionkey_log(log_str);
				}
			}
			++srtp.decrypt_rtp_attempt[1];
			if(srtp.decrypt->need_prepare_decrypt()) {
				srtp.decrypt->prepare_decrypt(saddr, daddr, sport, dport, false, pcap_header_us);
			}
			if(decrypt_sync) {
				__SYNC_LOCK(*decrypt_sync);
			}
			if(decrypt_ok && *decrypt_ok) {
				srtp.probably_unencrypted_payload = true;
			} else {
				if(srtp.decrypt->decrypt_rtp(data, len, pkt.payload_data, (unsigned int*)&pkt.payload_len, pcap_header_us,
							     saddr, daddr, sport, dport, this)) {
					if(decrypt_ok) {
						*decrypt_ok = true;
					}
				} else {
					if(!srtp.probably_unencrypted_payload && is_unencrypted_payload(pkt.payload_data, pkt.payload_len)) {
						srtp.probably_unencrypted_payload = true;
						if(decrypt_ok) {
							*decrypt_ok = true;
						}
					}
				}
			}
			if(decrypt_sync) {
				__SYNC_UNLOCK(*decrypt_sync);
			}
			pkt.len = *len;
		}
	} else {
		if(srtp.is_srtp && srtp.auth_tag_size && !srtp.probably_unencrypted_payload &&
		   stats.received <= (unsigned)opt_srtp_rtp_verify_tag_max_attempts && is_unencrypted_payload(pkt.payload_data, pkt.payload_len)) {
			srtp.probably_unencrypted_payload = true;
		}
		if(owner && owner->dtls &&
		   sverb.dtls && ssl_sessionkey_enable()) {
			if(!owner->dtls->debug_flags[0]) {
				string log_str;
				log_str += string("error (potentialy missing srtp_decrypt instance) decrypt_rtp for call: ") + (owner ? owner->call_id : "unknown");
				log_str += "; stream: " + saddr.getString() + ":" + sport.getString() + " -> " + daddr.getString() + ":" + dport.getString() + " ssrc_index " + intToString(sdp.ssrc_index);
				ssl_sessionkey_log(log_str);
				++owner->dtls->debug_flags[0];
			}
		}
	}

	if(if_unlikely(srtp.is_srtp && srtp.auth_tag_size && pkt.payload_len > (int)srtp.auth_tag_size && !srtp.probably_unencrypted_payload &&
	   (!srtp.decrypt || srtp.decrypt->isVerifyOnly()))) {
		pkt.payload_len -= srtp.auth_tag_size;
		pkt.len -= srtp.auth_tag_size;
	}

	RTPFixedHeader *hdr = getHeader();
	if(if_unlikely(hdr->version != 2)) {
		return(false);
	}

	pkt.seq = ntohs(hdr->sequence);
	if(if_unlikely((!dupl_check_seq.exists_dupl || opt_rtp_seq_dupl_skip_ext) && 
	   pkt.last_seq != -1 && pkt.seq != ROT_SEQ(pkt.last_seq + 1) && dupl_check_seq.check(pkt.seq))) {
		dupl_check_seq.exists_dupl = true;
		if(opt_rtp_seq_dupl_skip_ext) {
			return(false);
		}
	}
	dupl_check_seq.push(pkt.seq);

	bool hdr_marker = hdr->marker != 0;
	if(if_unlikely(pkt.seq == pkt.last_seq && !(pkt.last_markbit == 0 && (hdr_marker || forcemark.mark)) && !opt_disable_rtp_seq_check)) {
		// ignore duplicated RTP packets unless the second packet has mark bit set but the previous not
		return(false);
	}

	pkt.last_markbit = hdr_marker || forcemark.mark;

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	if(if_unlikely(opt_rtp_check_timestamp)) {
		if(timing._last_ts.tv_sec &&
		   (header->ts.tv_sec < timing._last_ts.tv_sec ||
		    (header->ts.tv_sec == timing._last_ts.tv_sec &&
		     header->ts.tv_usec < timing._last_ts.tv_usec))) {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > diag.lastTimeSyslog) {
				syslog(LOG_NOTICE, "warning - bad packet order (%" int_64_format_prefix "lu us) in RTP::read (seq/lastseq: %u/%u, ifname/lastifname: %s/%s, sensor/lastsenspor: %i/%i)- packet ignored",
				       getTimeUS(timing._last_ts) - getTimeUS(header),
				       pkt.seq, pkt.last_seq,
				       ifname && ifname[0] ? ifname : "--", diag._last_ifname[0] ? diag._last_ifname : "--",
				       sensor_id, diag._last_sensor_id);
				diag.lastTimeSyslog = actTime;
			}
			return(false);
		}
		diag._last_sensor_id = sensor_id;
		if(ifname) {
			strcpy_null_term(diag._last_ifname, ifname);
		} else {
			diag._last_ifname[0] = 0;
		}
	}
	timing._last_ts = header->ts;
	#endif
	
	int curpayload = is_video() ? PAYLOAD_VIDEO : getPayload();

	if((media.codec == -1 || (curpayload != media.prev_payload))) {
		if(curpayload >= 96 && curpayload <= 127) {
			/* for dynamic payload we look into rtpmap */
			int found = 0;
			RTPMAP *_rtpmap = get_rtpmap(owner, c_branch);
			if(_rtpmap) {
				for(int i = 0; i < MAX_RTPMAP; i++) {
					if(_rtpmap[i].is_set() && curpayload == _rtpmap[i].payload) {
						media.codec = _rtpmap[i].codec;
						sdp.frame_size = _rtpmap[i].frame_size;
						sdp.bit_rate = _rtpmap[i].bit_rate;
						found = 1;
						break;
					}
				}
			}
			if(!found) {
				_rtpmap = get_rtpmap(owner, c_branch, true);
				if(_rtpmap) {
					for(int i = 0; i < MAX_RTPMAP; i++) {
						if(_rtpmap[i].is_set() && curpayload == _rtpmap[i].payload) {
							media.codec = _rtpmap[i].codec;
							sdp.frame_size = _rtpmap[i].frame_size;
							sdp.bit_rate = _rtpmap[i].bit_rate;
							found = 1;
							break;
						}
					}
				}
			}
			if(!found && owner) {
				for(int i = 0; i < MAX_IP_PER_CALL && !found; i++) {
					if(!c_branch->rtpmap_used_flags[i]) {
						for(int j = 0; j < MAX_RTPMAP; j++) {
							if(c_branch->rtpmap[i][j].is_set() && curpayload == c_branch->rtpmap[i][j].payload) {
								media.codec = c_branch->rtpmap[i][j].codec;
								sdp.frame_size = c_branch->rtpmap[i][j].frame_size;
								sdp.bit_rate = c_branch->rtpmap[i][j].bit_rate;
								found = 1;
								break;
							}
						}
					}
				}
			}
			if(curpayload == 101 and !found) {
				// payload 101 was not in SDP, assume it is televent 
				media.codec = PAYLOAD_TELEVENT;
			}
		} else {
			media.codec = curpayload;
			if(media.codec == PAYLOAD_ILBC) {
				RTPMAP *_rtpmap = get_rtpmap(owner, c_branch);
				if(_rtpmap) {
					for(int i = 0; i < MAX_RTPMAP; i++) {
						if(_rtpmap[i].is_set() && curpayload == _rtpmap[i].payload) {
							sdp.frame_size = _rtpmap[i].frame_size;
							sdp.bit_rate = _rtpmap[i].bit_rate;
							break;
						}
					}
				}
			}
		}
		if(media.codec == -1) {
			// codec cannot be determinad - ignore it
			return(false);
		}
	}

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	/* in case there was packet loss we must predict lastTimeStamp to not add nonexistant delays */
	forcemark.mark = 0;
	if(pkt.last_seq != -1 and (ROT_SEQ(pkt.last_seq + 1) != pkt.seq)) {
		if(!opt_rtp_count_all_sequencegap_as_loss &&
		   s.lastTimeStamp == getTimestamp() - media.samplerate / 1000 * media.packetization) {
			// there was packet loss but the timestamp is like there was no packet loss 

			pkt.resetgraph = true;

			if(opt_jitterbuffer_adapt > 0) {
				ast_jb_empty_and_reset(jb.channel_adapt);
				ast_jb_destroy(jb.channel_adapt);
			}
			if(opt_jitterbuffer_f1 > 0) {
				ast_jb_empty_and_reset(jb.channel_fix1);
				ast_jb_destroy(jb.channel_fix1);
			}
			if(opt_jitterbuffer_f2 > 0) {
				ast_jb_empty_and_reset(jb.channel_fix2);
				ast_jb_destroy(jb.channel_fix2);
			}

			forcemark.mark = _forcemark_diff_seq;
		} else {
			if(!opt_rtp_count_all_sequencegap_as_loss &&
			   ROT_SEQ(pkt.last_seq + 2) == pkt.seq) {
				int64_t delta = (int64_t)((getTimestamp() - s.lastTimeStamp)/(media.samplerate/1000.0)*1000);
				if(delta > opt_jitter_forcemark_delta_threshold * 1000ll) {
					int64_t transit = ((int64_t)(getTimeUS(pkt.header_ts) - getTimeUS(s.lastTimeRec)) - (int64_t)((getTimestamp() - s.lastTimeStamp)/(media.samplerate/1000.0)*1000));
					if((transit >= 0 ? transit : -transit) < opt_jitter_forcemark_transit_threshold * 1000ll) {
						forcemark.mark = _forcemark_diff_seq;
					}
				}
			}
			// this fixes jumps in .graph in case of pcaket loss 	
			s.lastTimeStamp = getTimestamp() - media.samplerate / 1000 * media.packetization;
			struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(media.packetization, 1000));
			memcpy(&s.lastTimeRec, &tmp, sizeof(struct timeval));
		}
	}
	#endif

	unsigned int *lastssrc = NULL;
	RTP *lastrtp = NULL;
	RTP *lastactivertp = NULL;
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	bool diffSsrcInEqAddrPort = false;
	#endif
	if(owner) {
		lastssrc = id.iscaller ?
			(owner->lastcallerrtp ? &owner->lastcallerrtp->id.ssrc : NULL) :
			(owner->lastcalledrtp ? &owner->lastcalledrtp->id.ssrc : NULL);
		lastrtp = id.iscaller ?
			owner->lastcallerrtp :
			owner->lastcalledrtp;
		lastactivertp = id.iscaller ?
			owner->lastactivecallerrtp :
			owner->lastactivecalledrtp;
		#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
		if(opt_check_diff_ssrc_on_same_ip_port) {
			diffSsrcInEqAddrPort = lastssrc and *lastssrc != id.ssrc and 
					       lastrtp and this->eqAddrPort(lastrtp);
		}
		#endif
	}
	
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	extern cProcessingLimitations processing_limitations;
	if(processing_limitations.suppressRtpRead() && owner) {
		owner->suppress_rtp_read_due_to_insufficient_hw_performance = true;
	}
	if(is_video() || 
	   (owner && owner->suppress_rtp_read_due_to_insufficient_hw_performance)) {
	#endif
		pkt.last_seq = pkt.seq;
		if(update_seq(pkt.seq)) {
			update_stats();
		}
		media.prev_payload = curpayload;
		media.prev_codec = media.codec;
		jb.lastframetype = is_video() ? AST_FRAME_VIDEO : AST_FRAME_VOICE;
		if(media.first_codec < 0) {
			media.first_codec = media.codec;
		}
		return(true);
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	}
	#endif
	
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	// if packet has Mark bit OR last frame was not dtmf and current frame is voice and last ssrc is different then current ssrc packet AND (last RTP saddr == current RTP saddr)  - reset
	if(getMarker() or
	   (diffSsrcInEqAddrPort and !(jb.lastframetype == AST_FRAME_DTMF and media.codec != PAYLOAD_TELEVENT))) {
		if(sverb.graph) printf("rtp[%p] mark[%u] lastframetype[%u] codec[%u] lastssrc[%x] ssrc[%x] iscaller[%u] lastframetype[%u][%u] codec[%u]\n", this, getMarker(), jb.lastframetype, media.codec, (lastssrc ? *lastssrc : 0), id.ssrc, id.iscaller, jb.lastframetype, AST_FRAME_DTMF, media.codec);

		pkt.resetgraph = true;

/*
		s.lastTimeStamp = getTimestamp() - media.samplerate / 1000 * media.packetization;
		struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(media.packetization, 1000));
		memcpy(&s.lastTimeRec, &tmp, sizeof(struct timeval));
*/

		s.cycles = s.cycles - s.base_seq + s.max_seq;
		s.base_seq = pkt.seq;
		s.max_seq = pkt.seq;
		if(sverb.rtp_set_base_seq) {
			cout << "RTP - packet_lost - set base_seq #1" 
			     << " ssrc: " << hex << id.ssrc << dec << " "
			     << " src: " << id.saddr.getString() << " : " << id.sport
			     << " dst: " << id.daddr.getString() << " : " << id.dport
			     << endl;
		}

		if(!(jb.lastframetype == AST_FRAME_DTMF and media.codec != PAYLOAD_TELEVENT) and diffSsrcInEqAddrPort) {
			// reset jitter if ssrc changed
			if(opt_jitterbuffer_adapt > 0) {
				ast_jb_empty_and_reset(jb.channel_adapt);
				ast_jb_destroy(jb.channel_adapt);
			}
			if(opt_jitterbuffer_f1 > 0) {
				ast_jb_empty_and_reset(jb.channel_fix1);
				ast_jb_destroy(jb.channel_fix1);
			}
			if(opt_jitterbuffer_f2 > 0) {
				ast_jb_empty_and_reset(jb.channel_fix2);
				ast_jb_destroy(jb.channel_fix2);
			}
		}
		//reset silence DSP
		if(jb.DSP) {
			memcpy(jb.DSP->last_interval_loss_hist, jb.DSP->loss_hist, sizeof(unsigned short int) * 32);
		}
	}

	if(jb.lastframetype == AST_FRAME_DTMF and media.codec != PAYLOAD_TELEVENT) {
		// last frame was DTMF and now we have voice. Reset jitterbuffers (case 338f884b17f9e5de6c830c237dcc09dd) 
		if(opt_jitterbuffer_adapt > 0) {
			ast_jb_empty_and_reset(jb.channel_adapt);
			ast_jb_destroy(jb.channel_adapt);
		}
		if(opt_jitterbuffer_f1 > 0) {
			ast_jb_empty_and_reset(jb.channel_fix1);
			ast_jb_destroy(jb.channel_fix1);
		}
		if(opt_jitterbuffer_f2 > 0) {
			ast_jb_empty_and_reset(jb.channel_fix2);
			ast_jb_destroy(jb.channel_fix2);
		}
		//reset silence DSP
		if(jb.DSP) {
			memcpy(jb.DSP->last_interval_loss_hist, jb.DSP->loss_hist, sizeof(unsigned short int) * 32);
		}
	}

	// ignore CNG
	if(curpayload == 13 or curpayload == 19) {
		pkt.last_seq = pkt.seq;
		if(update_seq(pkt.seq)) {
			update_stats();
		}
		media.prev_payload = curpayload;
		media.prev_codec = media.codec;
		jb.lastframetype = AST_FRAME_VOICE;
		media.lastcng = 1;
		return(true);
	}
	if(curpayload == PAYLOAD_G729 and 
	   (pkt.payload_len <= (media.packetization == 10 or media.packetization == 0 ? 9 : 12) or (pkt.payload_len + pkt.padding_len == 22) or (pkt.payload_len + pkt.padding_len == 32)) and
	   !(pkt.payload_len == 0 && sverb.process_rtp_header)) {
		pkt.last_seq = pkt.seq;
		if(update_seq(pkt.seq)) {
			update_stats();
		}
		jb.lastframetype = AST_FRAME_VOICE;
		media.lastcng = 1;
		if(jb.channel_record) {
			jb.channel_record->prev_frame_is_dtmf = true;
		}
		return(true);
	}
	if(media.codec == PAYLOAD_TELEVENT) {
		process_dtmf_rfc2833();
		pkt.last_seq = pkt.seq;
		if(update_seq(pkt.seq)) {
			update_stats();
		}
		media.prev_payload = curpayload;
		media.prev_codec = media.codec;
		jb.lastframetype = AST_FRAME_DTMF;
		media.lastcng = 0;
		return(true);
	}

	if(!owner) { 
		media.lastcng = 0;
		return(false);
	}

/* this breaks 4 RTP streams (7b3fa6fb57a719f036fddfbf351234fe pcap sample) and it is not needed anymore (31955aa570d1f71624cea503052de62c)
	if(id.iscaller) {
		if(owner->lastcallerrtp and owner->lastcallerrtp != this) {
			// reset last sequence 
			s.cycles = s.cycles - s.base_seq + s.max_seq;
			s.base_seq = pkt.seq;
			s.max_seq = pkt.seq - 1;
		}
	} else {
		if(owner->lastcalledrtp and owner->lastcalledrtp != this) {
			s.cycles = s.cycles - s.base_seq + s.max_seq;
			s.base_seq = pkt.seq;
			s.max_seq = pkt.seq - 1;
		}
	}
*/
	
	if(forcemark.by_owner) {
		// on reinvite (which indicates forcemark.by_owner completely reset rtp jitterbuffer simulator and 
		// there are cases where on reinvite rtp stream stops and there is gap in rtp sequence and timestamp but 
		// since it was reinvite the stream just continues as expected
		if(opt_jitterbuffer_adapt > 0) {
			ast_jb_empty_and_reset(jb.channel_adapt);
			ast_jb_destroy(jb.channel_adapt);
		}
		if(opt_jitterbuffer_f1 > 0) {
			ast_jb_empty_and_reset(jb.channel_fix1);
			ast_jb_destroy(jb.channel_fix1);
		}
		if(opt_jitterbuffer_f2 > 0) {
			ast_jb_empty_and_reset(jb.channel_fix2);
			ast_jb_destroy(jb.channel_fix2);
		}

		forcemark.by_owner = false;
		forcemark.mark = _forcemark_sip_sdp;

		// this fixes jumps in .graph in case of pcaket loss 	
/*
		s.lastTimeStamp = getTimestamp() - media.samplerate / 1000 * media.packetization;
		struct timeval tmp = ast_tvadd(header->ts, ast_samp2tv(media.packetization, 1000));
		memcpy(&s.lastTimeRec, &tmp, sizeof(struct timeval));
*/

		// reset last sequence 
		s.cycles = s.cycles - s.base_seq + s.max_seq;
		s.base_seq = pkt.seq;
		s.max_seq = pkt.seq;
		if(sverb.rtp_set_base_seq) {
			cout << "RTP - packet_lost - set base_seq #2" 
			     << " ssrc: " << hex << id.ssrc << dec << " "
			     << " src: " << id.saddr.getString() << " : " << id.sport
			     << " dst: " << id.daddr.getString() << " : " << id.dport
			     << " seq: " << pkt.seq
			     << endl;
		}
		pkt.resetgraph = true;
	}
	
	// codec changed 
	RTP *laststream = id.iscaller ? owner->lastcallerrtp : owner->lastcalledrtp;

	bool doInitRaw = false;
	if(media.defer_codec_change or 
	    (owner->iscaller_consecutive[id.iscaller] >= 5 and owner->lastraw[id.iscaller] != this and (lastssrc and *lastssrc != id.ssrc and (laststream and laststream->id.daddr == id.daddr))) or
	   (curpayload != media.prev_payload and 
	    media.codec != PAYLOAD_TELEVENT and 
	    (media.prev_codec != PAYLOAD_TELEVENT or !media.codecchanged) and 
	    curpayload != 13 and media.prev_payload != 13 and media.codec != 13 and media.codec != 19 and media.prev_codec != 13 and media.prev_codec != 19)) {

		if(media.defer_codec_change) {
			media.defer_codec_change = false;
		}
		if(curpayload == PAYLOAD_G723 and *(data + sizeof(RTPFixedHeader)) & 2) {
			// codec changed but it is still SID frames (silence) we have to defer this until first valid speech frame otherwise call will be out of sync
			media.defer_codec_change = true;
		} else {
			media.codecchanged = true;
			switch(media.codec) {
			case PAYLOAD_SILK12:
			case PAYLOAD_OPUS12:
			case PAYLOAD_XOPUS12:
			case PAYLOAD_VXOPUS12:
			case PAYLOAD_G722112:
				media.samplerate = 12000;
				break;
			case PAYLOAD_ISAC16:
			case PAYLOAD_SILK16:
			case PAYLOAD_OPUS16:
			case PAYLOAD_XOPUS16:
			case PAYLOAD_VXOPUS16:
			case PAYLOAD_G722116:
			case PAYLOAD_AMRWB:
			case PAYLOAD_EVS:
				media.samplerate = 16000;
				break;
			case PAYLOAD_SILK24:
			case PAYLOAD_OPUS24:
			case PAYLOAD_XOPUS24:
			case PAYLOAD_VXOPUS24:
			case PAYLOAD_G722124:
				media.samplerate = 24000;
				break;
			case PAYLOAD_ISAC32:
			case PAYLOAD_G722132:
				media.samplerate = 32000;
				break;
			case PAYLOAD_OPUS48:
			case PAYLOAD_XOPUS48:
			case PAYLOAD_VXOPUS48:
			case PAYLOAD_G722148:
				media.samplerate = 48000;
				break;
			default: 
				media.samplerate = 8000;
			}

			if(id.iscaller) {
				owner->last_callercodec = media.codec;
			} else {
				owner->last_calledcodec = media.codec;
			}

			doInitRaw = true;
			raw.need_init_for_channel_record = true;
		}
	}

	if(use_channel_record &&
	   (doInitRaw || (raw.need_init_for_channel_record && !raw.init_done))) {
		//if(verbosity > 0) syslog(LOG_ERR, "converting WAV! [%u]\n", owner->flags);
		/* open file for raw codec */
		if(raw.gfile || raw.init_done) {
			jitterbuffer_fixed_flush(jb.channel_record);
			ast_jb_empty_and_reset(jb.channel_record);
			ast_jb_destroy(jb.channel_record);
			__SYNC_LOCK(raw.gfile_lock);
			FILE *tmp_gfileRAW = raw.gfile;
			raw.gfile = NULL;
			__SYNC_UNLOCK(raw.gfile_lock);
			if(tmp_gfileRAW) {
				fclose(tmp_gfileRAW);
			}
		} else {
			/* look for the last RTP stream belonging to this direction and let jitterbuffer put silence 
			 * which fills potentionally gap between this and previouse RTP so it will stay in sync with
			 * the other direction of call 
			 */
			RTP *prevrtp = (RTP*)(owner->rtp_prev[id.iscaller]);
			if(prevrtp && prevrtp != this) {
				prevrtp->pkt.ignore = 1; 
				prevrtp->pkt.data = data; 
				prevrtp->pkt.header_ip = header_ip; 
				prevrtp->pkt.len = *len;
				prevrtp->pkt.header_ts = pkt.header_ts;
				prevrtp->media.codec = prevrtp->media.prev_codec;
				prevrtp->jitterbuffer(prevrtp->jb.channel_record, save_audio, energylevels, mos_lqo);
			}
		}
		unsigned long raw_unique = getTimestamp();
		if(save_audio || mos_lqo) {
			char raw_filename[1024 + 100];
			snprintf(raw_filename, sizeof(raw_filename), "%s.%d.%lu.%d.%ld.%ld.raw", files.basefilename, sdp.ssrc_index, raw_unique, media.codec, header->ts.tv_sec, header->ts.tv_usec);
			FILE *new_gfileRAW = NULL;
			for(int passOpen = 0; passOpen < 2; passOpen++) {
				if(passOpen == 1) {
					char *pointToLastDirSeparator = strrchr(raw_filename, '/');
					if(pointToLastDirSeparator) {
						*pointToLastDirSeparator = 0;
						spooldir_mkdir(raw_filename);
						*pointToLastDirSeparator = '/';
					} else {
						break;
					}
				}
				new_gfileRAW = fopen(raw_filename, "w");
				if(new_gfileRAW) {
					spooldir_file_chmod_own(raw_filename);
					break;
				}
			}
			if(!raw.gfile_buffer) {
				raw.gfile_buffer = new FILE_LINE(24007) char[32768];
				if(raw.gfile_buffer == NULL) {
					syslog(LOG_ERR, "Cannot allocate memory for gfileRAW_buffer - low memory this is FATAL");
					exit(2);
				}
			}
			if(!new_gfileRAW) {
				syslog(LOG_ERR, "Cannot open file %s for writing: %s\n", raw_filename, strerror (errno));
			} else if(raw.gfile_buffer) {
				setvbuf(new_gfileRAW, raw.gfile_buffer, _IOFBF, 32768);
			}
			__SYNC_LOCK(raw.gfile_lock);
			raw.gfile = new_gfileRAW;
			__SYNC_UNLOCK(raw.gfile_lock);
			
			/* write file info to "playlist" */
			char rawinfo_filename[1024 + 100];
			snprintf(rawinfo_filename, sizeof(rawinfo_filename), "%s.rawInfo", files.basefilename);
			owner->iscaller_consecutive[id.iscaller] = 0;
			bool gfileRAWInfo_exists = file_exists(rawinfo_filename);
			FILE *gfileRAWInfo = fopen(rawinfo_filename, "a");
			if(gfileRAWInfo) {
				if(!gfileRAWInfo_exists) {
					spooldir_file_chmod_own(rawinfo_filename);
				}
				fprintf(gfileRAWInfo, "%d:%lu:%d:%d:%ld:%ld:%d\n", sdp.ssrc_index, raw_unique, media.codec, sdp.frame_size, header->ts.tv_sec, header->ts.tv_usec, sdp.bit_rate);
				fclose(gfileRAWInfo);
			} else {
				syslog(LOG_ERR, "Cannot open file %s.rawInfo for writing\n", files.basefilename);
			}
		}
		raw.init_done = true;
	}

	if(owner->lastraw[id.iscaller] != this) {
		owner->iscaller_consecutive[id.iscaller] = 0;
	} else {
		owner->iscaller_consecutive[id.iscaller]++;
	}
	owner->lastraw[id.iscaller] = this;


	if(media.first_codec < 0 && media.codec != PAYLOAD_TELEVENT && media.codec != 13 && media.codec != 19) {
		/* save payload to statistics based on first payload. TODO: what if payload is dynamically changing? */
		media.first_codec = media.codec;
		if(owner->first_codec < 0) {
			owner->first_codec = media.codec;
		}
	}

	if(media.codec == PAYLOAD_TELEVENT) {
		jb.frame->frametype = AST_FRAME_DTMF;
	} else {
		jb.frame->frametype = AST_FRAME_VOICE;
	}
	jb.frame->lastframetype = (enum ast_frame_type)(jb.lastframetype);

	if(if_unlikely(media.packetization_iterator == 0 || media.packetization_iterator == 1)) {
		// we dont know packetization yet. Behave differently n G723 codec 
		if(curpayload == PAYLOAD_G723) {
			media.default_packetization = 30;
			/* check if RTP packet is not Silence packet (SID). Silence packets can have different
			   packetization and if call starts with SID packets it will guess wrong packetization.
			   typical sitation is for 60ms packetization and 30ms SID packetization */
			pkt.payload_data = data + sizeof(RTPFixedHeader);
			media.sid = (unsigned char)pkt.payload_data[0] & 2;
		} else if(curpayload == PAYLOAD_AMR or curpayload == PAYLOAD_AMRWB or curpayload == PAYLOAD_EVS) {
			if(pkt.payload_len == 7) {
				media.sid = 1;
			}
		} else {
			media.sid = false;
			media.default_packetization = 20;
		}
	}

	if(media.packetization_iterator == 0) {
		if(pkt.last_ts != 0 && pkt.seq == ROT_SEQ(pkt.last_seq + 1) && (media.prev_codec != PAYLOAD_TELEVENT && media.codec != PAYLOAD_TELEVENT) && !media.sid && !media.prev_sid) {
			// sequence numbers are ok, we can calculate packetization
			if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(pkt.payload_len == 60) {
					media.packetization = 60;
				} else if(pkt.payload_len == 50) {
					media.packetization = 50;
				} else if(pkt.payload_len == 40) {
					media.packetization = 40;
				} else if(pkt.payload_len == 30) {
					media.packetization = 30;
				} else if(pkt.payload_len == 20) {
					media.packetization = 20;
				} else if(pkt.payload_len == 10) {
					media.packetization = 10;
				} else {
					media.packetization = (getTimestamp() - pkt.last_ts) / 8;
				}
			} else if(curpayload == PAYLOAD_G723) {
				if(pkt.payload_len == 24) {
					media.packetization = 30;
				} else if(pkt.payload_len == 24*2) {
					media.packetization = 60;
				} else if(pkt.payload_len == 24*3) {
					media.packetization = 90;
				}
			} else if(media.codec == PAYLOAD_ILBC) {
				if(pkt.payload_len % 50 == 0) {
					media.packetization = 30 * pkt.payload_len / 50;
				} else {
					media.packetization = (getTimestamp() - pkt.last_ts) / (media.samplerate / 1000);
				}
			} else {
				media.packetization = (getTimestamp() - pkt.last_ts) / (media.samplerate / 1000);
			}
			if(media.packetization > 0) {
				media.last_packetization = media.packetization;
				media.packetization_iterator++;
			}
		}

#if 1
		// new way of getting packetization from packet datalen 
		if(curpayload == PAYLOAD_PCMU or curpayload == PAYLOAD_PCMA or curpayload == PAYLOAD_GSM or curpayload == PAYLOAD_G722 or curpayload == PAYLOAD_G723) {

			int apacketization = 0;
			switch(curpayload) {
			case PAYLOAD_PCMU:
			case PAYLOAD_PCMA:
				apacketization = pkt.payload_len / 8;
				break;
			case PAYLOAD_GSM:
				apacketization = pkt.payload_len / 33 * 20;
				break;
			case PAYLOAD_G722:
				apacketization = pkt.payload_len / 8;
				break;
			case PAYLOAD_G723:
				if(pkt.payload_len == 24) {
					apacketization = 30;
				} else if(pkt.payload_len == 24*2) {
					apacketization = 60;
				} else if(pkt.payload_len == 24*3) {
					apacketization = 90;
				}
				break;
			}

			jb.channel_fix1->packetization = media.default_packetization = 
				jb.channel_fix2->packetization = jb.channel_adapt->packetization = 
				jb.channel_record->packetization = media.packetization = apacketization;

			if(media.packetization >= 10) {
				if(verbosity > 3) printf("packetization:[%d] ssrc[%x]\n", media.packetization, getSSRC());

				media.packetization_iterator = 10; // this will cause that packetization is estimated as final

				jitterbuffer_mos_all();
			} 

		} 
#endif

		/* for recording, we cannot loose any packet */
		if(use_channel_record) {
			if(media.packetization < 10) {
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(pkt.payload_len == 60) {
						media.packetization = jb.channel_record->packetization = 60;
					} else if(pkt.payload_len == 50) {
						media.packetization = jb.channel_record->packetization = 50;
					} else if(pkt.payload_len == 40) {
						media.packetization = jb.channel_record->packetization = 40;
					} else if(pkt.payload_len == 30) {
						media.packetization = jb.channel_record->packetization = 30;
					} else if(pkt.payload_len == 20) {
						media.packetization = jb.channel_record->packetization = 20;
					} else if(pkt.payload_len == 10) {
						media.packetization = jb.channel_record->packetization = 10;
					} else {
						media.packetization = jb.channel_record->packetization = media.default_packetization;
					}
				} else if(media.codec == PAYLOAD_ILBC) {
					if(pkt.payload_len % 50 == 0) {
						media.packetization = jb.channel_record->packetization = 30 * pkt.payload_len / 50;
					} else {
						media.packetization = jb.channel_record->packetization = media.default_packetization;
					}
				} else if(curpayload == PAYLOAD_G723) {
					if(pkt.payload_len == 24) {
						media.packetization = jb.channel_record->packetization = 30;
					} else if(pkt.payload_len == 24*2) {
						media.packetization = jb.channel_record->packetization = 60;
					} else if(pkt.payload_len == 24*3) {
						media.packetization = jb.channel_record->packetization = 90;
					}
				} else {
					media.packetization = jb.channel_record->packetization = media.default_packetization;
				}
			}
			if(checkDuplChannelRecordSeq(pkt.seq)) {
				jitterbuffer(jb.channel_record, save_audio, energylevels, mos_lqo);
			}
		}
	} else if(media.packetization_iterator == 1) {
		if(pkt.last_ts != 0 && pkt.seq == ROT_SEQ(pkt.last_seq + 1) && media.codec != PAYLOAD_TELEVENT && media.prev_codec != PAYLOAD_TELEVENT && !media.sid && !media.prev_sid) {
			// sequence numbers are ok, we can calculate packetization
			if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(pkt.payload_len == 60) {
					media.packetization = 60;
				} else if(pkt.payload_len == 50) {
					media.packetization = 50;
				} else if(pkt.payload_len == 40) {
					media.packetization = 40;
				} else if(pkt.payload_len == 30) {
					media.packetization = 30;
				} else if(pkt.payload_len == 20) {
					media.packetization = 20;
				} else if(pkt.payload_len == 10) {
					media.packetization = 10;
				} else {
					media.packetization = (getTimestamp() - pkt.last_ts) / 8;
				}
			} else if(media.codec == PAYLOAD_ILBC) {
				if(pkt.payload_len % 50 == 0) {
					media.packetization = 30 * pkt.payload_len / 50;
				} else {
					media.packetization = media.default_packetization;
				}
			} else {
				media.packetization = (getTimestamp() - pkt.last_ts) / (media.samplerate / 1000);
			}

			// now make packetization average
			media.packetization = (media.packetization + media.last_packetization) / 2;

			if(media.packetization <= 0 or getMarker()) {
				// packetization failed or Marker bit is set, fall back to start
				media.packetization_iterator = 0;

				/* for recording, we cannot loose any packet */
				if(use_channel_record) {
					media.packetization = jb.channel_record->packetization = media.default_packetization;
					if(checkDuplChannelRecordSeq(pkt.seq)) {
						jitterbuffer(jb.channel_record, save_audio, energylevels, mos_lqo);
					}
				}
			} else {
				media.packetization_iterator++;
				jb.channel_fix1->packetization = jb.channel_fix2->packetization = jb.channel_adapt->packetization = jb.channel_record->packetization = media.packetization;
				if(verbosity > 3) printf("[%x] packetization:[%d]\n", getSSRC(), media.packetization);

				jitterbuffer_mos_all();
				if(use_channel_record) {
					if(checkDuplChannelRecordSeq(pkt.seq)) {
						jitterbuffer(jb.channel_record, save_audio, energylevels, mos_lqo);
					}
				}
			}
		} else {
			media.packetization_iterator = 0;
			/* for recording, we cannot loose any packet */
			if(use_channel_record) {
				if(curpayload == PAYLOAD_G729) {
					// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
					if(pkt.payload_len == 60) {
						media.packetization = jb.channel_record->packetization = 60;
					} else if(pkt.payload_len == 50) {
						media.packetization = jb.channel_record->packetization = 50;
					} else if(pkt.payload_len == 40) {
						media.packetization = jb.channel_record->packetization = 40;
					} else if(pkt.payload_len == 30) {
						media.packetization = jb.channel_record->packetization = 30;
					} else if(pkt.payload_len == 20) {
						media.packetization = jb.channel_record->packetization = 20;
					} else if(pkt.payload_len == 10) {
						media.packetization = jb.channel_record->packetization = 10;
					} else {
						media.packetization = jb.channel_record->packetization = media.default_packetization;
					}
				} else if(media.codec == PAYLOAD_ILBC) {
					if(pkt.payload_len % 50 == 0) {
						media.packetization = jb.channel_record->packetization = 30 * pkt.payload_len / 50;
					} else {
						media.packetization = jb.channel_record->packetization = media.default_packetization;
					}
				} else if(curpayload == PAYLOAD_G723) {
					if(pkt.payload_len == 24) {
						media.packetization = jb.channel_record->packetization = 30;
					} else if(pkt.payload_len == 24*2) {
						media.packetization = jb.channel_record->packetization = 60;
					} else if(pkt.payload_len == 24*3) {
						media.packetization = jb.channel_record->packetization = 90;
					}
				} else {
					media.packetization = jb.channel_record->packetization = media.default_packetization;
				}

				if(checkDuplChannelRecordSeq(pkt.seq)) {
					jitterbuffer(jb.channel_record, save_audio, energylevels, mos_lqo);
				}
			}
		}
	} else {
		if(if_likely(pkt.last_ts != 0 && pkt.seq == ROT_SEQ(pkt.last_seq + 1) && media.codec != PAYLOAD_TELEVENT && !(hdr_marker || forcemark.mark) && 
		   (pkt.prev_payload_len > 8 || (sverb.process_rtp_header && pkt.prev_payload_len == 0)))) {
			// packetization can change over time
			int curpacketization = 0;

			if(if_likely(curpayload == PAYLOAD_PCMU || curpayload == PAYLOAD_PCMA || curpayload == PAYLOAD_G722)) {
				int p = pkt.payload_len >> 3;
				if(if_likely(p >= 20)) {
					// do not change packetization to 10ms frames. Case g711_20_10_sync.pcap
					curpacketization = p;
				}
			} else if(curpayload == PAYLOAD_G729) {
				// if G729 packet len is 20, packet len is 20ms. In other cases - will be added later (do not have 40ms packetizations samples right now)
				if(pkt.payload_len == 60) {
					curpacketization = 60;	
				} else if(pkt.payload_len == 50) {
					curpacketization = 50;	
				} else if(pkt.payload_len == 40) {
					curpacketization = 40;	
				} else if(pkt.payload_len == 30) {
					curpacketization = 30;	
				} else if(pkt.payload_len == 20) {
					curpacketization = 20;	
				} else if(pkt.payload_len == 10) {
					curpacketization = 10;	
				} else {
					curpacketization = (getTimestamp() - pkt.last_ts) / 8;
				}
			} else if(media.codec == PAYLOAD_ILBC) {
				if(pkt.payload_len % 50 == 0) {
					curpacketization = 30 * pkt.payload_len / 50;
				} else {
					curpacketization = media.default_packetization;
				}
			} else if(curpayload == PAYLOAD_G723) {
				if(pkt.payload_len == 24) {
					curpacketization = 30;	
				} else if(pkt.payload_len == 24*2) {
					curpacketization = 60;
				} else if(pkt.payload_len == 24*3) {
					curpacketization = 90;
				}
				if((unsigned char)*(data + sizeof(RTPFixedHeader)) & 2) {
					//it is sid data - do not change packetization
					curpacketization = media.last_packetization;
				}
			} else if(curpayload == PAYLOAD_GSM) {
				curpacketization = pkt.payload_len / 33 * 20;
			} else if(media.codec == PAYLOAD_AMR || media.codec == PAYLOAD_AMRWB || media.codec == PAYLOAD_EVS) {
				if(pkt.payload_len > 7) {
					//printf("curpac[%u]\n", curpacketization);
					curpacketization = (getTimestamp() - pkt.last_ts) / (media.codec == PAYLOAD_AMR ? 8 : 16);
				} else {
					curpacketization = media.packetization;
				}
			} else {
				curpacketization = (getTimestamp() - pkt.last_ts) / (media.samplerate / 1000);
			}

			if(if_unlikely(curpacketization < 10)) {
				// it cannot be, reset it to 20
				curpacketization = media.default_packetization;
			}

			if(if_unlikely(verbosity > 3)) printf("curpacketization[%u] = (getTimestamp()[%u] - last_ts[%u]) / (samplerate[%u] / 1000) pl[%u] curpayload[%u] seq[%u]\n", curpacketization, getTimestamp(), pkt.last_ts, media.samplerate, pkt.payload_len, curpayload, pkt.seq);

			if(if_unlikely(curpacketization != media.packetization && curpacketization % 10 == 0 && curpacketization >= 10 && curpacketization <= 120)) {
				// packetization changed, check if next packet is the same packetization
				media.change_packetization_iterator++;
				if(media.change_packetization_iterator > 1) { 
					//packetization changed for two last packets
					if(verbosity > 3) printf("[%x] changing packetization:[%d]->[%d]\n", getSSRC(), media.packetization, curpacketization);
					jb.channel_fix1->packetization = jb.channel_fix2->packetization = jb.channel_adapt->packetization = jb.channel_record->packetization = media.packetization = curpacketization;
					media.last_packetization = curpacketization;
					media.change_packetization_iterator = 0;
				}
			} else {
				// packetization changed back, reset the iterator
				media.change_packetization_iterator = 0;
			}
			
		}
		if(if_unlikely(curpayload == PAYLOAD_G723)) {
			if(pkt.payload_len == 24) {
				media.packetization = 30;	
			} else if(pkt.payload_len == 24*2) {
				media.packetization = 60;
			} else if(pkt.payload_len == 24*3) {
				media.packetization = 90;
			}
			jb.channel_fix1->packetization = jb.channel_fix2->packetization = jb.channel_adapt->packetization = jb.channel_record->packetization = media.packetization;
		}
		//printf("packetization [%d]\n", media.packetization);
		jitterbuffer_mos_all();
		if(if_unlikely(use_channel_record)) {
			if(checkDuplChannelRecordSeq(pkt.seq)) {
				jitterbuffer(jb.channel_record, save_audio, energylevels, mos_lqo);
			}
		}
	}

	pkt.prev_payload_len = pkt.payload_len;
	media.prev_payload = curpayload;
	media.prev_codec = media.codec;
	media.prev_sid = media.sid;

	// DSP processing
	bool do_fasdetect = opt_fasdetect && !id.iscaller &&  owner->connect_time_us && 
			    (pkt.header_ts.tv_sec - TIME_US_TO_S(owner->connect_time_us) < 10) &&
			    getTimeUS(pkt.header_ts) > owner->connect_time_us;
	bool do_energylevels = opt_save_energylevels && (!opt_energylevelheader[0] || (owner && owner->save_energylevels)) &&
			       !energy.via_jb;
	bool do_silencedetect = opt_silencedetect && this == lastactivertp;
	bool do_silence_afteranswer = opt_silence_detect_after_answer && !id.iscaller &&
				      owner && owner->connect_time_us &&
				      !owner->silence_afteranswer_noise_start_us &&
				      timing.last_packet_time_us > owner->connect_time_us;
	if(owner and (opt_inbanddtmf or opt_faxt30detect or do_silencedetect or opt_clippingdetect or do_fasdetect or do_silence_afteranswer or do_energylevels)
	   and jb.frame->frametype == AST_FRAME_VOICE and (media.codec == 0 or media.codec == 8) and pkt.payload_len > 0) {

		int res;
		if (!jb.DSP) {
			jb.DSP = dsp_new();
			if (jb.DSP) {
				int features = 0;
				if (opt_inbanddtmf) {
					features |= DSP_FEATURE_DIGIT_DETECT;
				}
				if (opt_faxt30detect) {
					features |= DSP_FEATURE_FAX_DETECT;
				}
				if (do_silencedetect) {
					features |= DSP_FEATURE_SILENCE_SUPPRESS;
				}
				dsp_set_features(jb.DSP, features);
			}
		}

		if (jb.DSP) {
			if (do_fasdetect) {
				dsp_set_feature(jb.DSP, DSP_FEATURE_CALL_PROGRESS);
			} else {
				dsp_clear_feature(jb.DSP, DSP_FEATURE_CALL_PROGRESS);
			}
			if (do_energylevels) {
				dsp_set_feature(jb.DSP, DSP_FEATURE_ENERGYLEVEL);
			} else {
				dsp_clear_feature(jb.DSP, DSP_FEATURE_ENERGYLEVEL);
			}
			if (do_silencedetect || do_silence_afteranswer) {
				dsp_set_feature(jb.DSP, DSP_FEATURE_SILENCE_SUPPRESS);
			} else {
				dsp_clear_feature(jb.DSP, DSP_FEATURE_SILENCE_SUPPRESS);
			}
		}

		char event_digit;
		int event_len;
		short int *sdata = new FILE_LINE(24008) short int[pkt.payload_len];
		if(!sdata) {
			syslog(LOG_ERR, "sdata malloc failed [%u]\n", (unsigned int)(pkt.payload_len * 2));
			return(false);
		}
		if(media.codec == 0) {
			for(int i = 0; i < pkt.payload_len; i++) {
				sdata[i] = ULAW((unsigned char)pkt.payload_data[i]);
				if(opt_clippingdetect && this == lastactivertp && ((abs(sdata[i])) >= 32124)) {
					if(id.iscaller) {
						owner->caller_clipping_8k++;
					} else {
						owner->called_clipping_8k++;
					}
				}
			}
		} else if(media.codec == 8) {
			for(int i = 0; i < pkt.payload_len; i++) {
				sdata[i] = ALAW((unsigned char)pkt.payload_data[i]);
				if(opt_clippingdetect && this == lastactivertp && ((abs(sdata[i])) >= 32256)) {
					if(id.iscaller) {
						owner->caller_clipping_8k++;
					} else {
						owner->called_clipping_8k++;
					}
				}
			}
		}
		if(opt_inbanddtmf or opt_faxt30detect or do_silencedetect or do_fasdetect or do_silence_afteranswer or do_energylevels) {
			int silence0 = 0;
			int totalsilence = 0;
			int totalnoise = 0;
			int res_call_progress = 0;
			u_int16_t energylevel = 0;
			jb.DSP->codec = media.codec;
			res = dsp_process(jb.DSP, sdata, pkt.payload_len, &event_digit, &event_len, &silence0, &totalsilence, &totalnoise, &res_call_progress, &energylevel);
			if(do_silencedetect) {
				if(silence0) {
					if(!silence.last_was_silence) {
						silence.sum_changes++;
					}
					if(id.iscaller) {
						owner->caller_lastsilence += pkt.payload_len / 8;
						owner->caller_silence += pkt.payload_len / 8;
					} else {
						owner->called_lastsilence += pkt.payload_len / 8;
						owner->called_silence += pkt.payload_len / 8;
					}
					silence.last_was_silence = true;
				} else {
					if(id.iscaller) {
						owner->caller_lastsilence = 0;
						owner->caller_noise += pkt.payload_len / 8;
					} else {
						owner->called_lastsilence = 0;
						owner->called_noise += pkt.payload_len / 8;
					}
					silence.last_was_silence = false;
				}
			}
			if(do_silence_afteranswer) {
				if(!owner->silence_afteranswer_rtp_seen) {
					//guarded to avoid a per-packet store into the shared Call
					owner->silence_afteranswer_rtp_seen = true;
				}
				if(!silence0 && totalnoise >= SILENCE_AFTERANSWER_MIN_NOISE_MS) {
					//dead air from the called party ended; backdate to the
					//start of the noise run (totalnoise includes this packet)
					u_int64_t prev_noise_us = totalnoise > pkt.payload_len / 8 ?
								  TIME_MS_TO_US(totalnoise - pkt.payload_len / 8) : 0;
					u_int64_t noise_start_us = timing.last_packet_time_us > prev_noise_us ?
								   timing.last_packet_time_us - prev_noise_us : timing.last_packet_time_us;
					if(noise_start_us <= owner->connect_time_us) {
						//noise run already in progress at connect - dead air is zero
						//(+1 keeps the latch distinguishable from the unset 0)
						noise_start_us = owner->connect_time_us + 1;
					}
					owner->silence_afteranswer_noise_start_us = noise_start_us;
				}
			}
			if(res) {
				if(opt_faxt30detect and (event_digit == 'f' or event_digit == 'e')) {
					//printf("dsp_process: digit[%c] len[%u]\n", event_digit, event_len);
					owner->isfax = T30FAX;
				} else if(opt_inbanddtmf and (res & DSP_PROCESS_RES_DTMF) and event_digit >= 20 and event_digit <= 127) {
					owner->handle_dtmf(event_digit, ts2double(header->ts.tv_sec, header->ts.tv_usec), saddr, daddr, s_dtmf::inband);
				}
				if (do_fasdetect and (res & DSP_PROCESS_RES_CALL_PROGRESSS)) {
					//update only on call progress events; other features
					//(silencedetect, inbanddtmf, faxdetect) set res on ordinary
					//packets and would wipe the flag after the last ring burst
					//syslog(LOG_ERR, "fas detected");
					owner->is_fas_detected = (res_call_progress == AST_CONTROL_RINGING) ? true : false;
				}
			}
			if(do_energylevels) {
				this->addEnergyLevel(energylevel, pkt.seq);
			}
		}

		delete [] sdata;
	} else if (jb.DSP) {
		dsp_free(jb.DSP);
		jb.DSP = NULL;
	}

	// ivrdetect: voice without ringback in the called party early media (before 200 OK)
	// own DSP instance - call progress / silence state of the shared DSP (fasdetect,
	// silence_detect_after_answer, mosSilence) stays untouched
	bool do_ivrdetect = opt_ivrdetect && !id.iscaller &&
			    !owner->ivr_ringback_detected &&
			    (!owner->connect_time_us || timing.last_packet_time_us < owner->connect_time_us);
	if(do_ivrdetect && jb.frame->frametype == AST_FRAME_VOICE &&
	   (media.codec == PAYLOAD_PCMU || media.codec == PAYLOAD_PCMA) && pkt.payload_len > 0) {
		if(!jb.DSP_ivr) {
			jb.DSP_ivr = dsp_new();
			//replaces the dsp_new defaults (digit detection would need the event arguments);
			//ringing is the only call progress event enabled - talk / busy events
			//would make the dsp switch call progress off
			dsp_set_features(jb.DSP_ivr, DSP_PROGRESS_RINGING | DSP_FEATURE_SILENCE_SUPPRESS);
		}
		short int *sdata_ivr = new FILE_LINE(0) short int[pkt.payload_len];
		for(int i = 0; i < pkt.payload_len; i++) {
			sdata_ivr[i] = media.codec == PAYLOAD_PCMU ? ULAW((unsigned char)pkt.payload_data[i]) : ALAW((unsigned char)pkt.payload_data[i]);
		}
		int silence_ivr = 0;
		int res_call_progress_ivr = 0;
		dsp_process(jb.DSP_ivr, sdata_ivr, pkt.payload_len, NULL, NULL, &silence_ivr, NULL, NULL, &res_call_progress_ivr, NULL);
		delete [] sdata_ivr;
		int tstate_ivr = dsp_get_tstate(jb.DSP_ivr);
		if(res_call_progress_ivr == AST_CONTROL_RINGING) {
			owner->ivr_ringback_detected = true;
		} else if(!silence_ivr && tstate_ivr != DSP_TONE_STATE_RINGING &&
			  tstate_ivr != DSP_TONE_STATE_BUSY && tstate_ivr != DSP_TONE_STATE_DIALTONE) {
			owner->ivr_voice_ms += pkt.payload_len / 8;
			if(!owner->ivr_voice_reached_us && owner->ivr_voice_ms >= IVRDETECT_MIN_VOICE_MS) {
				owner->ivr_voice_reached_us = timing.last_packet_time_us;
			}
		}
	} else if(!do_ivrdetect && jb.DSP_ivr) {
		dsp_free(jb.DSP_ivr);
		jb.DSP_ivr = NULL;
	}

	if(if_unlikely(hdr_marker || forcemark.mark)) {
		// if RTP packet is Marked, we have to reset last_ts to 0 so in next cycle it will count packetization from ground
		pkt.last_ts = 0;
	} else {
		pkt.last_ts = ntohl(hdr->timestamp);
	}

	if(if_likely(update_seq(pkt.seq))) {
		update_stats();
	}
	jb.lastframetype = jb.frame->frametype;
	pkt.last_seq = pkt.seq;
	media.lastcng = 0;

	if(if_likely(media.packetization > 0)) {
		media.avg_ptime_count++;
		float p = (float)media.packetization;
		if(if_unlikely(media.avg_ptime_count == 1)) {
			media.avg_ptime = p;
		} else if(if_unlikely(media.avg_ptime != p)) {
			media.avg_ptime = (media.avg_ptime * (media.avg_ptime_count - 1) + p) / media.avg_ptime_count;
		}
	}

	// write MOS to .graph every 10 seconds and reset jitter last mos interval
	if(if_unlikely(timing.last_packet_time_us >= timing.next_save_mos_graph_us || timing.save_mos_graph_wait > 0)) {
		if(if_unlikely(timing.next_save_mos_graph_us == 0)) {
			u_int64_t base_ms = mos.last_save_graph_ms ? mos.last_save_graph_ms : TIME_US_TO_MS(timing.first_packet_time_us);
			timing.next_save_mos_graph_us = (base_ms + 10001ULL) * 1000ULL;
		}
		if(timing.last_packet_time_us >= timing.next_save_mos_graph_us || timing.save_mos_graph_wait > 0) {
			if(!timing.save_mos_graph_wait) {
				timing.save_mos_graph_wait = 20; // After a packet loss, it may happen that the mos discovery period hits the first packets after the loss and the jitterbuffer is not yet aware of the mos degradation due to the loss. Therefore there is a pause of 20 packets.
				mos.last_save_graph_ms = TIME_US_TO_MS(timing.last_packet_time_us);
				timing.next_save_mos_graph_us = (mos.last_save_graph_ms + 10001ULL) * 1000ULL;
			} else {
				timing.save_mos_graph_wait--;
				if(!timing.save_mos_graph_wait) {
					save_mos_graph(false);
					mos.last_call_save_graph_ms = TIME_US_TO_MS(timing.last_packet_time_us);
				}
			}
		}
	}

	pkt.resetgraph = false;

	if(if_unlikely(forcemark.by_owner_set)) {
		forcemark.by_owner_set = false;
		forcemark.mark2 = 1; // set this flag and keep it until next update_stats call
	}

	return(true);
	#endif
}

/* fill internal structures by the input RTP packet */
void
RTP::fill_data(unsigned char* data, int len) {
	pkt.data = data; 
	pkt.len = len;
}

/* update statistics data */
void
RTP::update_stats() {

	int lost = int((s.cycles + s.max_seq - (s.base_seq + 1)) - s.received);
	
	// recalculation base_seq for interlaced streams
	if(lost > 100 && 
	   s.max_seq - pkt.last_seq >= lost) {
		Call *owner = (Call*)id.call_owner;
		u_int16_t maxSeqOtherSsrc = 0;
		for(int i = 0; i < owner->rtp_size(); i++) { RTP *rtp_i = owner->rtp_stream_by_index(i);
			if(rtp_i != this && rtp_i->id.ssrc == id.ssrc) {
				if(rtp_i->s.max_seq > maxSeqOtherSsrc) {
					maxSeqOtherSsrc = rtp_i->s.max_seq;
				}
			}
		}
		if(maxSeqOtherSsrc > pkt.last_seq &&
		   maxSeqOtherSsrc < s.max_seq) {
			s.base_seq = s.cycles + s.max_seq - s.received - 1 - (s.max_seq - maxSeqOtherSsrc - 1);
			lost = int((s.cycles + s.max_seq - (s.base_seq + 1)) - s.received);
		}
	}
	
	if(lost < 0) {
		s.cycles += lost * -1;
		lost = 0;
	}
	
	int adelay = 0;
	Call *owner = (Call*)id.call_owner;
	
	if(if_likely(!is_video())) {
		u_int32_t cur_ts = getTimestamp();

		/* if payload == PAYLOAD_TELEVENT dont make delayes on this because it confuses stats */
		if(if_unlikely(media.codec == PAYLOAD_TELEVENT || jb.lastframetype == AST_FRAME_DTMF)) {
			if(media.codec != PAYLOAD_TELEVENT) {
				if(timing.last_voice_frame_ts.tv_sec == 0) {
					// it is not EVENT frame and it is first voice packet 
					timing.last_voice_frame_ts = pkt.header_ts;
					timing.last_voice_frame_timestamp = cur_ts;
					return;
				}

				if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
					int64_t diff_us = (int64_t)(pkt.header_ts.tv_sec - timing.last_voice_frame_ts.tv_sec) * 1000000LL +
							  (int64_t)(pkt.header_ts.tv_usec - timing.last_voice_frame_ts.tv_usec);
					uint32_t diff = (uint32_t)((double)diff_us * 0.001);
					this->graph.write((char*)&graph_event, 4);
					this->graph.write((char*)&diff, 4);
					if(sverb.graph) printf("rtp[%p] ssrc[%x] seq[%u] silence[%u]ms ip[%s] DTMF\n", this, getSSRC(), pkt.seq, diff, id.saddr.getString().c_str());
					owner->save_rtp_graph = true;
				}

				forcemark.mark2 = 0;

				return;
			} else {
				forcemark.mark2 = 0;
				return;
			}
		}

		if(if_unlikely(timing.last_voice_frame_ts.tv_sec == 0)) {
			// it is not EVENT frame and it is first voice packet - ignore stats for first voice packet
			timing.last_voice_frame_ts = pkt.header_ts;
			timing.last_voice_frame_timestamp = cur_ts;
			forcemark.mark2 = 0;
			return;
		}

		/* differences between last timestamp and current timestamp (timestamp from ip header)
		 * frame1.time - frame0.time */
		int64_t diff_us = (int64_t)(pkt.header_ts.tv_sec - timing.last_voice_frame_ts.tv_sec) * 1000000LL +
				  (int64_t)(pkt.header_ts.tv_usec - timing.last_voice_frame_ts.tv_usec);
		double tsdiff2 = (double)diff_us * 0.001;
		double inv_sr_ms = (media.samplerate == 8000) ? 0.125 :
				   ((media.samplerate == 16000) ? 0.0625 : (1000.0 / (double)media.samplerate));
		double transit = tsdiff2 - ((double)cur_ts - (double)timing.last_voice_frame_timestamp) * inv_sr_ms;

	//	if(verbosity > 1) printf("transit rtp[%p] ssrc[%x] seq[%u] transit[%f]\n", this, getSSRC(), pkt.seq, (float)transit);

		if(if_unlikely(!(fabs(transit) < 5001.0))) {
			/* timestamp skew, discard delay, it is possible that timestamp changed  */
			s.fdelay = s.avgdelay;
			//s.fdelay = 0;
			transit = 0;
		} else {
			adelay = abs((int)transit);
			s.fdelay += transit;
		}

		timing.last_voice_frame_ts = pkt.header_ts;
		timing.last_voice_frame_timestamp = cur_ts;
	//	printf("rtp[%p] transit[%f]\t[%f]\tseq[%u]\tavgdelay[%f]\n", this, (float)transit, (float)s.fdelay, pkt.seq, float(s.avgdelay));

		//printf("seq[%u] adelay[%u]\n", pkt.seq, adelay);


		// store mark bit in graph file
		if(if_unlikely(getMarker() || ((media.codec == PAYLOAD_AMR || media.codec == PAYLOAD_AMRWB || media.codec == PAYLOAD_EVS) && (pkt.payload_len <= 7)))) {

			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				uint32_t diff = (uint32_t)tsdiff2;
				this->graph.write((char*)&graph_mark, 4);
				this->graph.write((char*)&diff, 4);
				if(sverb.graph) printf("rtp[%p] ssrc[%x] seq[%u] silence[%u]ms transit[%f] avgdelay[%f] mark\n", this, getSSRC(), pkt.seq, diff, transit, s.avgdelay);
				owner->save_rtp_graph = true;
			}

			//s.fdelay = 0;
			//s.fdelay -= transit;
			s.fdelay = s.avgdelay;
			adelay = 0;
		} else if(if_unlikely(pkt.resetgraph)) {
			if(owner and (owner->flags & FLAG_SAVEGRAPH) and this->graph.isOpenOrEnableAutoOpen()) {
				uint32_t diff = (uint32_t)tsdiff2;
				this->graph.write((char*)&graph_silence, 4);
				this->graph.write((char*)&diff, 4);
				if(sverb.graph) printf("rtp[%p] ssrc[%x] seq[%u] silence[%u]ms avgdelay[%f]\n", this, getSSRC(), pkt.seq, diff, s.avgdelay);
				owner->save_rtp_graph = true;
			}

			//s.fdelay = 0;
			s.fdelay = s.avgdelay;
			//s.fdelay -= transit;
			adelay = 0;
		}

		// keep average only for last 30 packets
		static const uint32_t lastpackets = 30;
		static const double inv_lastpackets = 1.0 / 30.0;
		if(if_likely(delay_win.counter > lastpackets)) {
			s.avgdelay = (30.0 * s.avgdelay - delay_win.avgdelays[delay_win.idx] + s.fdelay) * inv_lastpackets;
		} else {
			s.avgdelay = ((s.avgdelay * (double)(delay_win.counter)) + s.fdelay) / (double)(delay_win.counter + 1);
		}
		delay_win.avgdelays[delay_win.idx] = (float)s.fdelay;
		if(++delay_win.idx == lastpackets) {
			delay_win.idx = 0;
		}

		/* Jitterbuffer calculation
		 * J(1) = J(0) + (|D(0,1)| - J(0))/16 */
		timing.jitter = s.prevjitter + (((transit < 0) ? -transit : transit) - s.prevjitter) * 0.0625;
		s.prevjitter = timing.jitter;

		delay_win.counter++;
		stats.avgjitter = ((stats.avgjitter * (stats.received - 1) + timing.jitter)) / (double)stats.received;
		//printf("jitter[%f] avg[%f] [%u] [%u]\n", timing.jitter, stats.avgjitter, stats.received, s.received);
		if(stats.maxjitter < timing.jitter) stats.maxjitter = timing.jitter;
		s.lastTimeRec = pkt.header_ts;
		s.lastTimeRecJ = pkt.header_ts;
		s.lastTimeStamp = cur_ts;
		s.lastTimeStampJ = cur_ts;
	}

	if(forcemark.mark2) {
		// do not store loss / delay in case this is first packet after reinvite 
		if(lost >= stats.last_lost || stats.lost_with_reinvite_gaps >= (u_int32_t)(stats.last_lost - lost)) {
			stats.lost_with_reinvite_gaps += lost - stats.last_lost;
		} else {
			stats.lost_with_reinvite_gaps = 0;
		}
		stats.last_lost = lost;
	} else {
		if(lost > stats.last_lost) {
			if(sverb.packet_lost) {
				cout << this << " RTP - packet_lost -"
				     << " ssrc: " << hex << id.ssrc << dec << " "
				     << " src: " << id.saddr.getString()
				     << " dst: " << id.daddr.getString() << " : " << id.dport
				     << " forcemark: " << forcemark.mark2 << " "
				     << " seq: " << getSeqNum() << " "
				     << " lost - last_lost: " << (lost - stats.last_lost) << " "
				     << " lost: " << lost << " "
				     << " last_lost: " << stats.last_lost
				     << endl;
			}
			if((lost - stats.last_lost) < 10)
				stats.slost[lost - stats.last_lost]++;
			else
				stats.slost[10]++;
			if(owner && (owner->flags & FLAG_SAVEGRAPH) && !is_video()) {
				nintervals += lost - stats.last_lost;
				while(nintervals > 20) {
					if(this->graph.isOpenOrEnableAutoOpen()) {
						this->graph.write((char*)&graph_delimiter, 4);
					}
					nintervals -= 20;
				}
			}
		} else if(lost < stats.last_lost) {
			stats.reordered += stats.last_lost - lost;
		}
		if(lost >= stats.last_lost || stats.lost_with_reinvite_gaps >= (u_int32_t)(stats.last_lost - lost)) {
			stats.lost_with_reinvite_gaps += lost - stats.last_lost;
		} else {
			stats.lost_with_reinvite_gaps = 0;
		}
		if(lost >= stats.last_lost || stats.lost >= (u_int32_t)(stats.last_lost - lost)) {
			stats.lost += lost - stats.last_lost;
		} else {
			stats.lost = 0;
		}
		stats.last_lost = lost;
		if(owner && (owner->flags & FLAG_SAVEGRAPH) && !is_video()) {
			if(this->graph.isOpenOrEnableAutoOpen()) {
				if(nintervals > 20) {
					/* after 20 packets, send new line */
					this->graph.write((char*)&graph_delimiter, 4);
					nintervals -= 20;
				}
				float tmp = s.fdelay;
				if(tmp == graph_delimiter) tmp = graph_delimiter - 1;
				this->graph.write((char*)&tmp, 4);
				nintervals++;
			}
		}

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

	forcemark.mark2 = 0;
}

void
RTP::init_seq(u_int16_t seq) {
	s.base_seq = seq;
	s.max_seq = seq;
	s.bad_seq = RTP_SEQ_MOD + 1;   /* so seq == bad_seq is false */
	s.cycles = 0;
	s.received = 0;
	s.received_prior = 0;
	s.expected_prior = 0;
	s.delay = 0;
	s.fdelay = 0;
	s.prevjitter = 0;
}

/* this function is borrowed from the http://www.ietf.org/rfc/rfc3550.txt */
int
RTP::update_seq(u_int16_t seq) {

	int lost = int((s.cycles + seq - (s.base_seq + 1)) - s.received);
	if(if_unlikely((lost - stats.last_lost) > 200)) {
		int64_t diff_us = (int64_t)(pkt.header_ts.tv_sec - s.lastTimeRecJ.tv_sec) * 1000000LL +
				  (int64_t)(pkt.header_ts.tv_usec - s.lastTimeRecJ.tv_usec);
		if(llabs(diff_us) < 1000000LL) {
			// it cannot be loss because difference is < 1000ms and loss is too big. It is probably sequence reset without mark bit 
			s.cycles = s.cycles - s.base_seq + s.max_seq;
			s.base_seq = seq;
			s.max_seq = seq;
			if(sverb.rtp_set_base_seq) {
				cout << "RTP - packet_lost - set base_seq #1" 
				     << " ssrc: " << hex << id.ssrc << dec << " "
				     << " src: " << id.saddr.getString() << " : " << id.sport
				     << " dst: " << id.daddr.getString() << " : " << id.dport
				     << endl;
			}
		}
	}

	if(s.first) {
		s.first = false;
		init_seq(seq);
		s.max_seq = seq - 1;
		s.probation = opt_disable_rtp_seq_probation ? 0 : MIN_SEQUENTIAL;
		s.lastTimeRec = pkt.header_ts;
		s.lastTimeRecJ = pkt.header_ts;
		s.lastTimeStamp = getTimestamp();
		s.lastTimeStampJ = getTimestamp();
		if(rtp_stream_analysis_data) {
			timing.last_voice_frame_ts = pkt.header_ts;
			timing.last_voice_frame_timestamp = getTimestamp();
		}
		return 0;
	}

	u_int16_t udelta = seq - s.max_seq;
	/*
	* Source is not valid until MIN_SEQUENTIAL packets with
	* sequential sequence numbers have been received.
	*/
	if (s.probation) {
		/* packet is in sequence */
		if (seq == s.max_seq + 1) {
			s.probation--;
			s.max_seq = seq;
			if (s.probation == 0) {
				init_seq(seq);
				s.received++;
				stats.received++;
				return 1;
			}
		} else {
			s.probation = MIN_SEQUENTIAL - 1;
			s.max_seq = seq;
		}
		return 0;
	} else if (udelta < MAX_DROPOUT) {
		/* in order, with permissible gap */
		if (seq < s.max_seq && 
		    (!opt_disable_rtp_seq_probation || s.received > 0)) {
			/*
			* Sequence number wrapped - count another 64K cycle.
			*/
			s.cycles += RTP_SEQ_MOD;
		}
		s.max_seq = seq;
	} else if (udelta <= RTP_SEQ_MOD - MAX_MISORDER) {
		/* the sequence number made a very large jump */
		if (seq == s.bad_seq) {
			/*
			* Two sequential packets -- assume that the other side
			* restarted without telling us so just re-sync
			* (i.e., pretend this was the first packet).
			*/
			init_seq(seq);
		} else {
			s.bad_seq = (seq + 1) & (RTP_SEQ_MOD-1);
			return 0;
		}
	} else {
		 /* duplicate or reordered packet */
	}
	stats.received++;
	s.received++;
	return 1;
}

#define RTP_TS_SUB(ts1, ts2) \
	((u_int32_t)ts2 > (u_int32_t)ts1 && (u_int32_t)ts2 - (u_int32_t)ts1 < (u_int32_t)0xFFFFFFu ? \
		-(int64_t)((u_int32_t)ts2 - (u_int32_t)ts1) : \
		(int64_t)((u_int32_t)ts1 - (u_int32_t)ts2))

void RTP::rtp_stream_analysis_output() {
	if(!rtp_stream_analysis_data) {
		return;
	}
	if(!rsa.first_packet_time_us) {
		rsa.first_packet_time_us = getTimeUS(pkt.header_ts);
		rsa.first_timestamp = getTimestamp();
	}
	if(!rsa.counter) {
		rtp_stream_analysis_data->exportCsvHeader();
	}
	++rsa.counter;
	int64_t transit = rsa.counter > 1 ? 
			   (((int64_t)getTimeUS(pkt.header_ts) - (int64_t)rsa.last_packet_time_us) -
			    (RTP_TS_SUB(getTimestamp(), rsa.last_timestamp)/(media.samplerate/1000.0)*1000)) : 
			   0;
	double jitter = rsa.jitter + (double)(((transit < 0) ? -transit/1000. : transit/1000.) - rsa.jitter)/16. ;
	sStreamAnalysisData::sStreamAnalysisRow *row = new sStreamAnalysisData::sStreamAnalysisRow;
	row->counter = rsa.counter;
	row->time_real_us = (int64_t)getTimeUS(pkt.header_ts) - (int64_t)rsa.first_packet_time_us;
	row->time_rtp_us = RTP_TS_SUB(getTimestamp(), rsa.first_timestamp)/(media.samplerate/1000.0)*1000;
	row->seq = getSeqNum();
	row->delta_real_us = rsa.counter > 1 ? ((int64_t)getTimeUS(pkt.header_ts) - (int64_t)rsa.last_packet_time_us) : 0;
	row->delta_rtp_us = rsa.counter > 1 ? (RTP_TS_SUB(getTimestamp(), rsa.last_timestamp)/(media.samplerate/1000.0)*1000) : 0;
	row->transit = transit;
	row->skew = row->time_rtp_us - row->time_real_us;
	row->jitter = timing.jitter;
	row->jitter_rsa = jitter;
	row->marker = getHeader()->marker ? 1 : 0;
	row->bad_seq = rsa.counter > 1 ? getSeqNum() != ROT_SEQ(rsa.prev_seq + 1) : 0;
	row->payload_len = get_payload_len();
	row->codec = media.codec;
	if(pkt.payload_len > 0 && (media.codec == PAYLOAD_PCMU || media.codec == PAYLOAD_PCMA)) {
		row->set_energylevel = true;
		row->energylevel = get_energylevel(pkt.payload_data, pkt.payload_len, media.codec);
	}
	rtp_stream_analysis_data->rows.push_back(row);
	rsa.last_packet_time_us = getTimeUS(pkt.header_ts);
	rsa.last_timestamp = getTimestamp();
	rsa.jitter = jitter;
	rsa.prev_seq = getSeqNum();
	rtp_stream_analysis_data->exportCsvRows();
}

void sStreamAnalysisData::exportCsvHeader() {
	cout << "rsa,"
	     << "counter" << ","
	     << "time_real" << ","
	     << "time_rtp" << ","
	     << "seq" << ","
	     << "delta_real" << ","
	     << "delta_rtp" << ","
	     << "transit" << ","
	     << "skew" << ","
	     << "jitter" << ","
	     << "jitter_rsa" << ","
	     << "marker" << ","
	     << "bad_seq" << ","
	     << "mos_f1" << ","
	     << "mos_f2" << ","
	     << "mos_adapt" << ","
	     << "mos_silence" << ","
	     << "payload_len" <<  ","
	     << "codec" << ","
	     << "energylevel"
	     << endl;
}
#endif // not EXPERIMENTAL_LITE_RTP_MOD

void sStreamAnalysisData::exportCsvRow(sStreamAnalysisRow *row, sStreamAnalysisRowMos *row_mos) {
	cout << fixed << setprecision(3);
	cout << "rsa,"
	     << row->counter << ","
	     << row->time_real_us << ","
	     << row->time_rtp_us << ","
	     << row->seq << ","
	     << row->delta_real_us << ","
	     << row->delta_rtp_us << ","
	     << row->transit << ","
	     << row->skew << ","
	     << row->jitter << ","
	     << row->jitter_rsa << ","
	     << row->marker << ","
	     << row->bad_seq << ",";
	exportCsvMos(row_mos);
	cout << row->payload_len << ","
	     << row->codec;
	if(row->set_energylevel) {
		cout << "," << row->energylevel;
	}
	cout << endl;
}

void sStreamAnalysisData::exportCsvMos(sStreamAnalysisRowMos *row) {
	if(row && row->f1) cout << row->f1;
	cout << ",";
	if(row && row->f2) cout << row->f2;
	cout << ",";
	if(row && row->adapt) cout << row->adapt;
	cout << ",";
	if(row && row->silence) cout << row->silence;
	cout << ",";
}

void sStreamAnalysisData::exportCsvRows(bool all) {
	if(!mos.size() && !all) {
		return;
	}
	sStreamAnalysisRowMos *row_mos = NULL;
	if(mos.size()) {
		row_mos = mos.begin()->second;
	}
	for(unsigned i = 0; i < rows.size(); i++) {
		exportCsvRow(rows[i], row_mos);
	}
	clear();
}

void sStreamAnalysisData::clear() {
	for(unsigned i = 0; i < rows.size(); i++) {
		delete rows[i];
	}
	rows.clear();
	for(map<u_int64_t, sStreamAnalysisRowMos*>::iterator it = mos.begin(); it != mos.end(); it++) {
		delete it->second;
	}
	mos.clear();
}

#if not EXPERIMENTAL_LITE_RTP_MOD
int RTP::mos_min_mult10_from_avg(bool prefer_f2) {
	int mos_min_mult10 = -1;
	if(mos.f1_avg > 0 && mos.f1_avg != (uint8_t)-1) {
		mos_min_mult10 = (int)round(mos.f1_avg);
	}
	if(mos.f2_avg > 0 && mos.f2_avg != (uint8_t)-1) {
		int mos_f2_mult10 = (int)round(mos.f2_avg);
		if(mos_min_mult10 < 0 || mos_f2_mult10 < mos_min_mult10) {
			mos_min_mult10 = mos_f2_mult10;
		}
	}
	if(mos.AD_avg > 0 && mos.AD_avg != (uint8_t)-1) {
		int mos_adapt_mult10 = (int)round(mos.AD_avg);
		if(mos_min_mult10 < 0 || mos_adapt_mult10 < mos_min_mult10) {
			mos_min_mult10 = mos_adapt_mult10;
		}
	}
	if(prefer_f2 && mos.f2_avg > 0 && mos.f2_avg != (uint8_t)-1) {
		mos_min_mult10 = (int)round(mos.f2_avg);
	}
	if(mos_min_mult10 > 0) {
		mos_min_mult10 = LIMIT_TINYINT_UNSIGNED(mos_min_mult10);
	}
	return(mos_min_mult10);
}

double RTP::mos_min_from_avg(bool *null, bool prefer_f2) {
	int mos_min_mult10 = mos_min_mult10_from_avg(prefer_f2);
	if(null) *null = mos_min_mult10 <= 0;
	return(mos_min_mult10 > 0 ? mos_min_mult10 / 10. : 0);
}

int RTP::mos_min_mult10_from_min(bool prefer_f2) {
	int mos_min_mult10 = -1;
	if(mos.f1_min > 0 && mos.f1_min != (uint8_t)-1) {
		mos_min_mult10 = mos.f1_min;
	}
	if(mos.f2_min > 0 && mos.f2_min != (uint8_t)-1) {
		if(mos_min_mult10 < 0 || mos.f2_min < mos_min_mult10) {
			mos_min_mult10 = mos.f2_min;
		}
	}
	if(mos.AD_min > 0 && mos.AD_min != (uint8_t)-1) {
		if(mos_min_mult10 < 0 || mos.AD_min < mos_min_mult10) {
			mos_min_mult10 = mos.AD_min;
		}
	}
	if(prefer_f2 && mos.f2_min > 0 && mos.f2_min != (uint8_t)-1) {
		mos_min_mult10 = mos.f2_min;
	}
	return(mos_min_mult10);
}

double RTP::mos_min_from_min(bool *null, bool prefer_f2) {
	int mos_min_mult10 = mos_min_mult10_from_min(prefer_f2);
	if(null) *null = mos_min_mult10 <= 0;
	return(mos_min_mult10 > 0 ? mos_min_mult10 / 10. : 0);
}

double RTP::mos_xr_min(bool *null) {
	if(this->rtcp_xr.counter_mos > 0 && this->rtcp_xr.minmos > 0) {
		if(null) *null = false;
		return(this->rtcp_xr.minmos / 10.);
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::mos_xr_avg(bool *null) {
	if(this->rtcp_xr.counter_mos > 0 && this->rtcp_xr.avgmos > 0) {
		if(null) *null = false;
		return(round(this->rtcp_xr.avgmos) / 10.);
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::mos_silence_min(bool *null) {
	if(mos.Silence_min != (uint8_t)-1 && mos.Silence_min > 0) {
		if(null) *null = false;
		return(mos.Silence_min / 10.);
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::mos_silence_avg(bool *null) {
	if(mos.Silence_min != (uint8_t)-1 && mos.Silence_avg > 0) {
		if(null) *null = false;
		return(round(mos.Silence_avg) / 10.);
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::packet_loss(bool *null) {
	if(this->stats.received + this->stats.lost > 0) {
		if(null) *null = false;
		return(round((double)this->stats.lost / (this->stats.received + 2 + this->stats.lost) * 100 * 1000) / 1000);
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::jitter_avg(bool *null) {
	if(null) *null = false;
	return(this->stats.avgjitter);
}

double RTP::jitter_max(bool *null) {
	if(null) *null = false;
	return(this->stats.maxjitter);
}

double RTP::delay_sum(bool *null) {
	if(null) *null = false;
	return(this->stats.d50 * 60 + 
	       this->stats.d70 * 80 + 
	       this->stats.d90 * 105 + 
	       this->stats.d120 * 135 +
	       this->stats.d150 * 175 + 
	       this->stats.d200 * 250 + 
	       this->stats.d300 * 300);
}

double RTP::delay_cnt(bool *null) {
	if(null) *null = false;
	return(this->stats.d50 + 
	       this->stats.d70 + 
	       this->stats.d90 + 
	       this->stats.d120 +
	       this->stats.d150 + 
	       this->stats.d200 + 
	       this->stats.d300);
}

double RTP::jitter_rtcp_avg(bool *null) {
	if(this->rtcp.counter > 0) {
		if(null) *null = false;
		return(this->rtcp.avgjitter / get_ticks_bycodec(media.first_codec));
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::jitter_rtcp_max(bool *null) {
	if(this->rtcp.counter > 0) {
		if(null) *null = false;
		return(this->rtcp.maxjitter / get_ticks_bycodec(media.first_codec));
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::fr_rtcp_avg(bool *null) {
	if(this->rtcp.counter > 0) {
		if(null) *null = false;
		return(this->rtcp.avgfr / 2.56);
	} else {
		if(null) *null = true;
		return(0);
	}
}

double RTP::fr_rtcp_max(bool *null) {
	if(this->rtcp.counter > 0) {
		if(null) *null = false;
		return(this->rtcp.maxfr / 2.56);
	} else {
		if(null) *null = true;
		return(0);
	}
}

void RTP::addEnergyLevel(u_int16_t energyLevel, u_int16_t seq) {
	bool ok_save = false;
	if(!energy.buf) {
		energy.buf = new FILE_LINE(0) SimpleChunkBuffer();
		ok_save = true;
	} else {
		if(!opt_save_energylevels_check_seq) {
			ok_save = true;
		} else {
			if(seq == ROT_SEQ(energy.last_seq + 1)) {
				ok_save = true;
			} else if(seq != energy.last_seq &&
				  (u_int16_t)(seq - energy.last_seq) < MAX_DROPOUT) {
					while(seq != ROT_SEQ(energy.last_seq + 1)) {
						u_int16_t energyLevel_zero = 0;
						energy.buf->add((u_char*)&energyLevel_zero, sizeof(energyLevel_zero));
						energy.last_seq = ROT_SEQ(energy.last_seq + 1);
						if(sverb.energylevels) {
							cout << " el " << "ssrc:" << hex << id.ssrc << dec 
							     << " #:" << (++energy.counter) << " el:zero" << endl;
						}
					}
					ok_save = true;
			}
		}
	}
	if(ok_save) {
		energy.buf->add((u_char*)&energyLevel, sizeof(energyLevel));
		if(sverb.energylevels) {
			cout << " el " << "ssrc:" << hex << id.ssrc << dec 
			     << " #:" << (++energy.counter) << " el:" << energyLevel << " seq:" << seq << endl;
		}
		energy.last_seq = seq;
	}
}

void RTP::addEnergyLevel(void *data, int datalen, int codec) {
	if(!((!opt_energylevelheader[0] || (id.call_owner && ((Call*)id.call_owner)->save_energylevels)) &&
	     (codec == PAYLOAD_PCMU || codec == PAYLOAD_PCMA))) {
		return;
	}
	if(!energy.buf) {
		energy.buf = new FILE_LINE(0) SimpleChunkBuffer();
	}
	if(data && datalen) {
		u_int16_t energylevel = get_energylevel((u_char*)data, datalen, codec);
		energy.buf->add((u_char*)&energylevel, sizeof(energylevel));
		if(sverb.energylevels) {
			cout << " el(jb) " << "ssrc:" << hex << id.ssrc << dec 
			     << " #:" << (++energy.counter) << " el:" << energylevel << endl;
		}
	} else {
		u_int16_t energyLevel_zero = 0;
		energy.buf->add((u_char*)&energyLevel_zero, sizeof(energyLevel_zero));
		if(sverb.energylevels) {
			cout << " el(jb) " << "ssrc:" << hex << id.ssrc << dec
			     << " #:" << (++energy.counter) << " el:zero" << endl;
		}
	}
}

RTPMAP *RTP::get_rtpmap(Call *call, CallBranch *c_branch, bool other_side) {
	extern bool opt_rtpmap_indirect;
	if(opt_rtpmap_indirect) {
		if(call) {
			int rtpmap_call_index = other_side ? sdp.rtpmap_other_side_call_index : sdp.rtpmap_call_index;
			if(rtpmap_call_index >= 0) {
				return((link.c_branch_created ? link.c_branch_created : c_branch)->rtpmap[rtpmap_call_index]);
			}
		}
		return(NULL);
	} else {
		return(other_side ? rtpmap.other_side : rtpmap.local);
	}
}

bool RTP::is_unencrypted_payload(u_char *data, unsigned datalen) {
	if(media.codec == PAYLOAD_PCMA) {
		for(unsigned i = 0; i < min(datalen, 20u); i++) {
			if(!((data[i] >= 0x50 && data[i] <= 0x5F) || (data[i] >= 0xD0 && data[i] <= 0xDF) || data[i] == 0xFF)) {
				return(false);
			}
		}
		return(true);
	} else if(media.codec == PAYLOAD_PCMU) {
		for(unsigned i = 0; i < min(datalen, 20u); i++) {
			if(!((data[i] >= 0xC0 && data[i] <= 0xCF) || (data[i] >= 0xF0 && data[i] <= 0xFF) || data[i] == 0xFF)) {
				return(false);
			}
		}
		return(true);
	}
	return(false);
}

bool RTP::channel_is_adaptive(struct ast_channel *channel) {
	return(channel && channel->jitter_impl);
}

string RTP::getJson() {
	JsonExport json;
	json.add("src_ip", id.saddr.getString());
	json.add("src_port", id.sport.getString());
	json.add("dst_ip", id.daddr.getString());
	json.add("dst_port", id.dport.getString());
	json.add("time", timing.first_packet_time_us);
	json.add("time_last", timing.last_packet_time_us);
	json.add("ssrc", id.ssrc);
	json.add("codec", media.codec);
	json.add("received", stats.received);
	json.add("lost", stats.lost);
	json.add("jitter_avg", (double)stats.avgjitter);
	json.add("jitter_max", (double)stats.maxjitter);
	return(json.getJson());
}

#endif // not EXPERIMENTAL_LITE_RTP_MOD

extern "C" {
void save_rtp_energylevels(void *rtp_stream, void *data, int datalen, int codec) {
	#if not EXPERIMENTAL_LITE_RTP_MOD
	((RTP*)rtp_stream)->addEnergyLevel(data, datalen, codec);
	#endif
}
}

void burstr_calculate(struct ast_channel *chan, u_int32_t received, double *burstr, double *lossr, int lastinterval) {
	int lost = 0;
	int bursts = 0;
	unsigned int received2 = lastinterval ? received - chan->last_received : received;
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
		chan->last_received = received;
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

#if not EXPERIMENTAL_LITE_RTP_MOD

/* for debug purpose */
void
RTP::dump() {
	int i;
	printf("SSRC:%x %u ssrc_index[%d]\n", id.ssrc, id.ssrc, sdp.ssrc_index);
	printf("codec:%d\n", media.first_codec);
	printf("src ip:%s\n", id.saddr.getString().c_str());
	printf("dst ip:%s\n", id.daddr.getString().c_str());
	printf("dst port:%u\n", id.dport.getPort());
	printf("Packetization:%u\n", media.packetization);
	printf("s.received: %d\n", s.received);
	printf("total loss:%u\n", stats.lost);
	printf("loss ratio:%f\n", (double)stats.lost / (double)s.received);
	printf("serial loss: ");
	for(i = 1; i < 11; i++) 
		printf("%d:%u ", i, stats.slost[i]);
	printf("\n");
	printf("d50: %d, d70: %d, d90: %d, d120: %d, d150: %d, d200: %d, d300: %d\n",
		stats.d50, stats.d70, stats.d90, stats.d120, stats.d150, stats.d200, stats.d300);

	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
	double burstr, lossr;
	printf("jitter stats:\n");
	burstr_calculate(jb.channel_fix1, s.received, &burstr, &lossr, 1);
	//printf("s.received: %d, loss: %d, bursts: %d\n", s.received, lost, bursts);
	printf("fix(50/50)\tloss rate:\t%f\n", lossr);
	printf("fix(50/50)\tburst rate:\t%f\n", burstr);

	burstr_calculate(jb.channel_fix2, s.received, &burstr, &lossr, 1);
	//printf("s.received: %d, loss: %d, bursts: %d\n", s.received, lost, bursts);
	printf("fix(200/200)\tloss rate:\t%f\n", lossr);
	printf("fix(200/200)\tburst rate:\t%f\n", burstr);

	burstr_calculate(jb.channel_adapt, s.received, &burstr, &lossr, 1);
	//printf("s.received: %d, loss: %d, bursts: %d\n", s.received, lost, bursts);
	printf("adapt(500/500)\tloss rate:\t%f\n", lossr);
	printf("adapt(500/500)\tburst rate:\t%f\n", burstr);
	#endif
	
	printf("---\n");
}

void RTP::clearAudioBuff(Call *call, ast_channel *channel) {
	if(id.iscaller) {
		if(call->audioBufferData[0].audiobuffer) {
			channel->audiobuf = NULL;
		}
	} else {
		if(call->audioBufferData[1].audiobuffer) {
			channel->audiobuf = NULL;
		}
	}
}

#endif // not EXPERIMENTAL_LITE_RTP_MOD

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

double calculate_mos(double ppl, double burstr, int codec, unsigned int received, bool call_is_connected) {
	if(codec == PAYLOAD_G729) {
		if(opt_mos_g729) {
			if(!call_is_connected && received < 100) {
				return 3.92;
			}
			return (double)mos_g729((long double)ppl, (long double)burstr);
		} else {
			if(!call_is_connected && received < 100) {
				return 4.5;
			}
			return calculate_mos_g711(ppl, burstr, 2);
		}
	} else {
		if(!call_is_connected && received < 100) {
			return 4.5;
		}
		return calculate_mos_g711(ppl, burstr, 2); 
	}       
}		

int calculate_mos_fromdsp(RTP *rtp, struct dsp *DSP) {
	double burstr, lossr;
	int lost = 0;
	int bursts = 0;
	int mos = 0;

	for(int i = 0; i < 32; i++) {
		//if(DSP->loss_hist[i] > 0) printf("loss_hist[%d] = %d - %d\n", i, DSP->loss_hist[i], DSP->last_interval_loss_hist[i]);
		lost += i * (DSP->loss_hist[i] - DSP->last_interval_loss_hist[i]);
		bursts += DSP->loss_hist[i] - DSP->last_interval_loss_hist[i];
	}
	//printf("[%p] ------- \n", rtp);
	//if((verbosity > 4 or sverb.jitter) and chan->loss[i] > 0) printf("bc loss[%d]: %d\t", i, chan->loss[i]);

	if(lost < 5) {
		// ignore such small packet loss 
		lossr = burstr = 0;
		return 45;
	}

	if(DSP->received > 0 && bursts > 0) {
		burstr = (double)((double)lost / (double)bursts) / (double)(1.0 / ( 1.0 - (double)lost / (double)DSP->received ));
		//if(sverb.jitter) printf("SilenceMOS: burstr[%f] = (lost[%u] / bursts[%u]) / (1 / ( 1 - lost[%u] / received[%u]\n", burstr, lost, bursts, lost, DSP->received);
		if(burstr < 0) {
			burstr = - burstr;
		} else if(burstr < 1) {
			burstr = 1;
		}
	} else {
		burstr = 0;
	}
	//printf("total loss: %d\n", lost);
	if(DSP->received > 0) {
		lossr = (double)((double)lost / (double)DSP->received);
	} else {
		lossr = 0;
	}
	mos = (int)round(calculate_mos(lossr, burstr, rtp->first_codec_(), rtp->received_(), rtp->id.call_owner && ((Call*)rtp->id.call_owner)->connect_time_us) * 10);
	if(0) printf("[%p] SilenceMOS - burstr: %f lossr: %f lost[%d]/received[%d] mos[%u]\n", rtp, burstr, lossr, lost, DSP->received, mos);
	return mos;
}

int calculate_mos_fromrtp(RTP *rtp, int jittertype, int lastinterval) {
	#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS and not EXPERIMENTAL_LITE_RTP_MOD
	double burstr, lossr;
	switch(jittertype) {
	case 1: 
		if(rtp->jb.channel_fix1) {
			burstr_calculate(rtp->jb.channel_fix1, rtp->stats.received, &burstr, &lossr, lastinterval);
		} else {
			return 45;
		}
		break;  
	case 2: 
		if(rtp->jb.channel_fix2) {
			burstr_calculate(rtp->jb.channel_fix2, rtp->stats.received, &burstr, &lossr, lastinterval);
		} else {
			return 45;
		}
		break;  
	case 3: 
		if(rtp->jb.channel_adapt) {
			burstr_calculate(rtp->jb.channel_adapt, rtp->stats.received, &burstr, &lossr, lastinterval);
		} else {
			return 45;
		}
		break;  
	}       
	int mos = (int)round(calculate_mos(lossr, burstr, rtp->media.first_codec, rtp->stats.received, rtp->id.call_owner && ((Call*)rtp->id.call_owner)->connect_time_us) * 10);
	return mos;
	#else
	return 45;
	#endif
}       

void
RTPstat::update(vmIP saddr, uint32_t time, uint8_t mosf1, uint8_t mosf2, uint8_t mosAD, uint16_t jitter, double loss) {

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
	
	map<vmIP, node_t> *cmap;
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
		map<vmIP, node_t> *saddr_map_tmp =maps[0];
		maps[0] = maps[1];
		maps[1] = saddr_map_tmp;
		cmap = maps[1];
	}

	map<vmIP, node_t>::iterator saddr_map_it = cmap->find(saddr);

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
RTPstat::flush_and_clean(map<vmIP, node_t> *cmap, bool needLock) {
	if(needLock) lock();

	extern int opt_nocdr;
	string query_str;
	if(!opt_nocdr && !sverb.disable_store_rtp_stat) {
		map<vmIP, node_t>::iterator it;

		if(!sqlDbSaveCall) {
			sqlDbSaveCall = createSqlObject();
			sqlDbSaveCall->setEnableSqlStringInContent(true);
		}

		string rtp_stat_table = "rtp_stat";
		vector<SqlDb_row> rtp_stat_rows;
		for(it = cmap->begin(); it != cmap->end(); it++) {
			node_t *node = &it->second;
			SqlDb_row rtp_stat;
			// create queries 
			rtp_stat.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor");
			rtp_stat.add(sqlDateTimeString(node->time), "time");
			rtp_stat.add(sqlDateTimeString(node->time), "time");
			rtp_stat.add(it->first, "saddr", false, sqlDbSaveCall, rtp_stat_table.c_str());
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
				query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
					     sqlDbSaveCall->insertQuery(rtp_stat_table, rtp_stat, false, false, true));
			}
		}
		if(opt_mysql_enable_multiple_rows_insert && rtp_stat_rows.size()) {
			query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
				     sqlDbSaveCall->insertQueryWithLimitMultiInsert(rtp_stat_table, &rtp_stat_rows, opt_mysql_max_multiple_rows_insert, 
										    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str(), false, false, true), false);
		}
	}

	cmap->clear();
	if(needLock) unlock();

	//TODO enableBatchIfPossible
	if(!opt_nocdr && isSqlDriver("mysql") && !query_str.empty()) {
		static unsigned int counterSqlStore = 0;
		sqlStore->query_lock(query_str.c_str(),
				     STORE_PROC_ID_CDR,
				     opt_mysqlstore_max_threads_cdr > 1 &&
				     sqlStore->getSize(STORE_PROC_ID_CDR, 0) > 1000 ?
				      counterSqlStore % opt_mysqlstore_max_threads_cdr :
				      0);
		++counterSqlStore;
	}
}

void
RTPstat::flush() {
	flush_and_clean(maps[0]);
	flush_and_clean(maps[1]);
}


u_int16_t get_energylevel(u_char *data, int datalen, int codec) {
	if((codec == PAYLOAD_PCMU || codec == PAYLOAD_PCMA) && data && datalen > 0) {
		u_int64_t accum = 0;
		for(int i = 0; i < datalen; i++) {
			accum += abs((int16_t)(codec == PAYLOAD_PCMU ? ULAW((data)[i]) : ALAW((data)[i])));
		}
		return((u_int16_t)(accum / datalen));
	}
	return(0);
}
