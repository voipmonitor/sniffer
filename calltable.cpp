/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. 
*/

/**
  * This file implements Calltable and Call class. Calltable implements operations 
  * on Call list. Call class implements operations on one call. 
*/


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <math.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <net/if.h>
#include <dirent.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <list>
#include <set>
#include <iterator>

//#include <.h>

#include "voipmonitor.h"
#include "calltable.h"
#include "format_wav.h"
#include "format_ogg.h"
#include "codecs.h"
#include "codec_alaw.h"
#include "codec_ulaw.h"
#include "mos_g729.h"
#include "jitterbuffer/asterisk/time.h"
#include "odbc.h"
#include "sql_db.h"
#include "rtcp.h"
#include "ipaccount.h"
#include "cleanspool.h"
#include "regcache.h"
#include "fraud.h"
#include "billing.h"
#include "tar.h"
#include "filter_mysql.h"
#include "sniff_inline.h"
#include "register.h"
#include "manager.h"
#include "srtp.h"
#include "dtls.h"
#include "filter_call.h"
#include "options.h"
#include "sniff_proc_class.h"
#include "charts.h"
#include "server.h"


#define MIN(x,y) ((x) < (y) ? (x) : (y))

using namespace std;

extern int verbosity;
extern int verbosityE;
extern int opt_sip_register;
extern int opt_saveRTP;
extern int opt_onlyRTPheader;
extern int opt_saveSIP;
extern int opt_use_libsrtp;
extern int opt_rtcp;
extern int opt_saveRAW;                // save RTP payload RAW data?
extern int opt_saveWAV;                // save RTP payload RAW data?
extern int opt_saveGRAPH;	// save GRAPH data to graph file? 
extern FileZipHandler::eTypeCompress opt_gzipGRAPH;	// compress GRAPH data to graph file? 
extern bool opt_srtp_rtp_decrypt;
extern bool opt_srtp_rtp_dtls_decrypt;
extern bool opt_srtp_rtp_audio_decrypt;
extern bool opt_srtp_rtcp_decrypt;
extern int opt_savewav_force;
extern int opt_save_sdp_ipport;
extern int opt_save_ip_from_first_header;
extern int opt_mos_g729;
extern int opt_nocdr;
extern NoStoreCdrRules nocdr_rules;
extern int opt_only_cdr_next;
extern char opt_cachedir[1024];
extern char sql_cdr_table[256];
extern char sql_cdr_table_last30d[256];
extern char sql_cdr_table_last7d[256];
extern char sql_cdr_table_last1d[256];
extern char sql_cdr_next_table[256];
extern char sql_cdr_ua_table[256];
extern char sql_cdr_sip_response_table[256];
extern char sql_cdr_sip_request_table[256];
extern char sql_cdr_reason_table[256];
extern int opt_callend;
extern int opt_id_sensor;
extern int opt_id_sensor_cleanspool;
extern int rtptimeout;
extern int sipwithoutrtptimeout;
extern int absolute_timeout;
extern bool opt_ss7_use_sam_subsequent_number;
extern int opt_ss7timeout_rlc;
extern int opt_ss7timeout_rel;
extern int opt_ss7timeout;
extern unsigned int gthread_num;
extern volatile int num_threads_active;
extern int opt_printinsertid;
extern int opt_cdronlyanswered;
extern int opt_cdronlyrtp;
extern int opt_newdir;
extern int opt_video_recording;
extern char opt_keycheck[1024];
extern char opt_convert_char[256];
extern int opt_norecord_dtmf;
extern char opt_silencedtmfseq[16];
extern int opt_pauserecordingdtmf_timeout;
extern char get_customers_pn_query[1024];
extern int opt_saverfc2833;
extern int opt_dscp;
extern int opt_cdrproxy;
extern int opt_messageproxy;
extern int opt_cdr_country_code;
extern int opt_message_country_code;
extern int opt_pcap_dump_tar;
extern struct pcap_stat pcapstat;
extern int opt_filesclean;
extern int opt_allow_zerossrc;
extern int opt_cdr_sip_response_number_max_length;
extern vector<string> opt_cdr_sip_response_reg_remove;
extern int opt_cdr_ua_enable;
extern vector<string> opt_cdr_ua_reg_remove;
extern vector<string> opt_cdr_ua_reg_whitelist;
extern unsigned int graph_delimiter;
extern int opt_mosmin_f2;
extern char opt_mos_lqo_bin[1024];
extern char opt_mos_lqo_ref[1024];
extern char opt_mos_lqo_ref16[1024];
extern int opt_mos_lqo;
extern regcache *regfailedcache;
extern MySqlStore *sqlStore;
extern int global_pcap_dlink;
extern pcap_t *global_pcap_handle;
extern int opt_mysqlstore_max_threads_cdr;
extern int opt_mysqlstore_max_threads_message;
extern int opt_mysqlstore_max_threads_register;
extern int opt_mysqlstore_max_threads_http;
extern int opt_mysqlstore_max_threads_charts_cache;
extern int opt_mysqlstore_limit_queue_register;
extern Calltable *calltable;
extern int opt_silencedetect;
extern int opt_clippingdetect;
extern CustomHeaders *custom_headers_cdr;
extern CustomHeaders *custom_headers_message;
extern int opt_custom_headers_last_value;
extern bool _save_sip_history;
extern int opt_saveudptl;
extern int opt_rtpip_find_endpoints;
extern rtp_read_thread *rtp_threads;
extern bool opt_rtpmap_by_callerd;
extern bool opt_rtpmap_combination;
extern int opt_register_timeout_disable_save_failed;
extern int opt_rtpfromsdp_onlysip;
extern int opt_rtpfromsdp_onlysip_skinny;
extern int opt_rtp_streams_max_in_call;
extern int opt_rtp_check_both_sides_by_sdp;
extern int opt_hash_modify_queue_length_ms;
extern int opt_mysql_enable_multiple_rows_insert;
extern int opt_mysql_max_multiple_rows_insert;
extern PreProcessPacket **preProcessPacketCallX;
extern int preProcessPacketCallX_count;
extern volatile PreProcessPacket::eCallX_state preProcessPacketCallX_state;
extern bool opt_disable_sdp_multiplication_warning;
extern bool opt_save_energylevels;

volatile int calls_counter = 0;
volatile int calls_for_store_counter = 0;
volatile int registers_counter = 0;

extern char mac[32];

unsigned int last_register_clean = 0;

extern int opt_onewaytimeout;
extern int opt_saveaudio_reversestereo;
extern int opt_saveaudio_stereo;
extern int opt_saveaudio_reversestereo;
extern float opt_saveaudio_oggquality;
extern bool opt_saveaudio_filteripbysipip;
extern bool opt_saveaudio_filter_ext;
extern bool opt_saveaudio_wav_mix;
extern bool opt_saveaudio_from_first_invite;
extern bool opt_saveaudio_afterconnect;
extern bool opt_saveaudio_from_rtp;
extern int opt_skinny;
extern int opt_enable_fraud;
extern char opt_call_id_alternative[256];
extern char opt_callidmerge_header[128];
extern int opt_sdp_multiplication;
extern int opt_hide_message_content;
extern char opt_hide_message_content_secret[1024];
extern vector<string> opt_message_body_url_reg;

SqlDb *sqlDbSaveCall = NULL;
SqlDb *sqlDbSaveSs7 = NULL;
extern sExistsColumns existsColumns;

extern int opt_pcap_dump_tar_sip_use_pos;
extern int opt_pcap_dump_tar_rtp_use_pos;
extern int opt_pcap_dump_tar_graph_use_pos;

extern unsigned int glob_ssl_calls;
extern bool opt_cdr_partition;
extern bool opt_cdr_partition_by_hours;
extern int opt_t2_boost;
extern int opt_t2_boost_call_find_threads;
extern int opt_t2_boost_call_threads;
extern bool opt_time_precision_in_ms;

extern cBilling *billing;

extern cSqlDbData *dbData;

extern char *opt_rtp_stream_analysis_params;

extern int opt_charts_cache_max_threads;
extern bool opt_charts_cache_ip_boost;
extern int terminating_charts_cache;
extern volatile int terminating;

extern sSnifferClientOptions snifferClientOptions;

extern char opt_curl_hook_wav[256];

extern bool opt_processing_limitations;
extern bool opt_processing_limitations_active_calls_cache;
extern int opt_processing_limitations_active_calls_cache_type;
extern cProcessingLimitations processing_limitations;

sCallField callFields[] = {
	{ cf_callreference, "callreference" },
	{ cf_callid, "callid" },
	{ cf_calldate, "calldate" },
	{ cf_calldate_num, "calldate_num" },
	{ cf_lastpackettime, "lastpackettime" },
	{ cf_duration, "duration" },
	{ cf_connect_duration, "connect_duration" },
	{ cf_caller, "caller" },
	{ cf_called, "called" },
	{ cf_caller_country, "caller_country" },
	{ cf_called_country, "called_country" },
	{ cf_caller_international, "caller_international" },
	{ cf_called_international, "called_international" },
	{ cf_callername, "callername" },
	{ cf_callerdomain, "callerdomain" },
	{ cf_calleddomain, "calleddomain" },
	{ cf_calleragent, "calleragent" },
	{ cf_calledagent, "calledagent" },
	{ cf_callerip, "callerip" },
	{ cf_calledip, "calledip" },
	{ cf_callerip_country, "callerip_country" },
	{ cf_calledip_country, "calledip_country" },
	{ cf_callerip_encaps, "callerip_encaps" },
	{ cf_calledip_encaps, "calledip_encaps" },
	{ cf_callerip_encaps_prot, "callerip_encaps_prot" },
	{ cf_calledip_encaps_prot, "calledip_encaps_prot" },
	{ cf_sipproxies, "sipproxies" },
	{ cf_lastSIPresponseNum, "lastSIPresponseNum" },
	{ cf_rtp_src, "rtp_src" },
	{ cf_rtp_dst, "rtp_dst" },
	{ cf_rtp_src_country, "rtp_src_country" },
	{ cf_rtp_dst_country, "rtp_dst_country" },
	{ cf_callercodec, "callercodec" },
	{ cf_calledcodec, "calledcodec" },
	{ cf_src_mosf1, "src_mosf1" },
	{ cf_src_mosf2, "src_mosf2" },
	{ cf_src_mosAD, "src_mosAD" },
	{ cf_dst_mosf1, "dst_mosf1" },
	{ cf_dst_mosf2, "dst_mosf2" },
	{ cf_dst_mosAD, "dst_mosAD" },
	{ cf_src_jitter, "src_jitter" },
	{ cf_dst_jitter, "dst_jitter" },
	{ cf_src_loss, "src_loss" },
	{ cf_dst_loss, "dst_loss" },
	{ cf_src_loss_last10sec, "src_loss_last10sec" },
	{ cf_dst_loss_last10sec, "dst_loss_last10sec" },
	{ cf_id_sensor, "id_sensor" },
	{ cf_vlan, "vlan" }
};


Call_abstract::Call_abstract(int call_type, u_int64_t time_us) {
	alloc_flag = 1;
	type_base = call_type;
	type_next = 0;
	first_packet_time_us = time_us;
	fbasename[0] = 0;
	fbasename_safe[0] = 0;
	fname_register = 0;
	useSensorId = opt_id_sensor;
	useDlt = global_pcap_dlink;
	useHandle = global_pcap_handle;
	flags = 0;
	user_data = NULL;
	user_data_type = 0;
	#if DEBUG_ASYNC_TAR_WRITE
	chunkBuffersCount_sync = 0;
	for(unsigned i = 0; i < P_FLAGS_IMAX; i++) {
		p_flags_count[i] = 0;
	}
	#else
	chunkBuffersCount = 0;
	#endif
	this->created_at = getTimeUS();
}

bool 
Call_abstract::addNextType(int type) {
	if(!type_next &&
	   ((type_base == INVITE && type == MESSAGE) ||
	    (type_base == MESSAGE && type == INVITE))) {
		type_next = type;
		if(type == INVITE) {
			((Call*)this)->setRtpThreadNum();
		}
		return(true);
	}
	return(false);
}

string
Call_abstract::get_sensordir() {
	string sensorDir;
	extern int opt_spooldir_by_sensor;
	extern int opt_spooldir_by_sensorname;
	if((opt_spooldir_by_sensor && useSensorId > 0) || 
	   opt_spooldir_by_sensorname) {
		if(opt_spooldir_by_sensorname) {
			extern SensorsMap sensorsMap;
			sensorDir = sensorsMap.getSensorNameFile(useSensorId);
		} else if(opt_spooldir_by_sensor) {
			sensorDir = intToString(useSensorId);
		}
	}
	return(sensorDir);
}

string
Call_abstract::get_pathname(eTypeSpoolFile typeSpoolFile, const char *substSpoolDir) {
	if(!force_spool_path.empty()) {
		return(force_spool_path);
	}
	string spoolDir;
	string sensorDir;
	string typeDir;
	spoolDir = substSpoolDir ?
		    substSpoolDir :
		    (opt_cachedir[0] ? opt_cachedir : getSpoolDir(typeSpoolFile));
	sensorDir = get_sensordir();
	struct tm t = time_r(first_packet_time_us);
	char timeDir_buffer[100];
	if(opt_newdir) {
		static volatile int timeDirCache_sync = 0;
		static volatile u_int32_t timeDirCache_index[60];
		static volatile char timeDirCache_buffer[60][100];
		timeDir_buffer[0] = 0;
		u_int8_t _time_index_arr[4];
		_time_index_arr[0] = t.tm_mon;
		_time_index_arr[1] = t.tm_mday;
		_time_index_arr[2] = t.tm_hour;
		_time_index_arr[3] = t.tm_min;
		u_int32_t *_time_index = (u_int32_t*)_time_index_arr;
		while(__sync_lock_test_and_set(&timeDirCache_sync, 1));
		if(*_time_index == timeDirCache_index[t.tm_min]) {
			strcpy_null_term(timeDir_buffer, (const char*)timeDirCache_buffer[t.tm_min]);
		}
		__sync_lock_release(&timeDirCache_sync);
		if(!timeDir_buffer[0]) {
			snprintf(timeDir_buffer, sizeof(timeDir_buffer), 
				 "%04d-%02d-%02d/%02d/%02d", 
				 t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min);
			while(__sync_lock_test_and_set(&timeDirCache_sync, 1));
			timeDirCache_index[t.tm_min] = *_time_index;
			strncpy_null_term((char*)timeDirCache_buffer[t.tm_min], timeDir_buffer, sizeof(timeDir_buffer));
			__sync_lock_release(&timeDirCache_sync);
		}
	} else {
		snprintf(timeDir_buffer, sizeof(timeDir_buffer), 
			 "%04d-%02d-%02d", 
			 t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
	}
	typeDir = opt_newdir ? getSpoolTypeDir(typeSpoolFile) : "";
	return(spoolDir + (spoolDir.length() ? "/" : "") +
	       sensorDir + (sensorDir.length() ? "/" : "") +
	       timeDir_buffer + "/" +
	       typeDir + (typeDir.length() ? "/" : ""));
}

string 
Call_abstract::get_filename(eTypeSpoolFile typeSpoolFile, const char *fileExtension) {
	string extension = fileExtension ? fileExtension : getFileTypeExtension(typeSpoolFile);
	if(((typeIs(OPTIONS) && user_data_type == OPTIONS) ||
	    (typeIs(SUBSCRIBE) && user_data_type == SUBSCRIBE) ||
	    (typeIs(NOTIFY) && user_data_type == NOTIFY)) && 
	   user_data) {
		 cSipMsgRequestResponse *sipMsgRequestResponse = (cSipMsgRequestResponse*)user_data;
		 return(sipMsgRequestResponse->getPcapFileName() +
			(extension.length() ? "." : "") + extension);
	}
	return((typeIs(REGISTER) ?
		 intToString(fname_register) :
		 get_fbasename_safe()) + 
	       (extension.length() ? "." : "") + extension);
}

string
Call_abstract::get_pathfilename(eTypeSpoolFile typeSpoolFile, const char *fileExtension) {
	string pathname = get_pathname(typeSpoolFile);
	string filename = get_filename(typeSpoolFile, fileExtension);
	return(pathname + (pathname.length() && pathname[pathname.length() - 1] != '/' ? "/" : "") +
	       filename);
}

/* returns name of the directory in format YYYY-MM-DD */
string
Call_abstract::dirnamesqlfiles() {
	char sdirname[50];
	struct tm t = time_r(first_packet_time_us);
	snprintf(sdirname, sizeof(sdirname), "%04d%02d%02d%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour);
	return(sdirname);
}

char *
Call_abstract::get_fbasename_safe() {
	strcpy_null_term(fbasename_safe, fbasename);
	prepare_string_to_filename(fbasename_safe);
	return fbasename_safe;
}

void 
Call_abstract::addTarPos(u_int64_t pos, int type) {
	switch(type) {
	case FileZipHandler::pcap_sip:
		if(opt_pcap_dump_tar_sip_use_pos) {
			this->tarPosSip.push_back(pos);
		}
		break;
	case FileZipHandler::pcap_rtp:
		if(opt_pcap_dump_tar_rtp_use_pos) {
			this->tarPosRtp.push_back(pos);
		}
		break;
	case FileZipHandler::graph_rtp:
		if(opt_pcap_dump_tar_graph_use_pos) {
			this->tarPosGraph.push_back(pos);
		}
		break;
	}
}


/* constructor */
Call::Call(int call_type, char *call_id, unsigned long call_id_len, vector<string> *call_id_alternative, u_int64_t time_us) :
 Call_abstract(call_type, time_us),
 pcap(PcapDumper::na, this),
 pcapSip(PcapDumper::sip, this),
 pcapRtp(PcapDumper::rtp, this) {
	//increaseTartimemap(time);
	has_second_merged_leg = false;
	isfax = NOFAX;
	seenudptl = 0;
	exists_udptl_data = false;
	not_acceptable = false;
	sip_fragmented = false;
	rtp_fragmented = false;
	last_callercodec = -1;
	ipport_n = 0;
	last_signal_packet_time_us = time_us;
	last_rtp_packet_time_us = 0;
	last_rtcp_packet_time_us = 0;
	last_rtp_a_packet_time_us = 0;
	last_rtp_b_packet_time_us = 0;
	if(call_id_len) {
		this->call_id = string(call_id, call_id_len);
		this->call_id_len = call_id_len;
	} else {
		this->call_id = string(call_id);
		this->call_id_len = this->call_id.length();
	}
	if(opt_call_id_alternative[0]) {
		this->call_id_alternative = new FILE_LINE(0) map<string, bool>;
		if(call_id_alternative) {
			for(unsigned i = 0; i < call_id_alternative->size(); i++) {
				(*this->call_id_alternative)[(*call_id_alternative)[i]] = true;
			}
		}
	} else {
		this->call_id_alternative = NULL;
	}
	_call_id_alternative_lock = 0;
	whohanged = -1;
	seeninvite = false;
	seeninviteok = false;
	seenmessage = false;
	seenmessageok = false;
	seenbye = false;
	seenbye_time_usec = 0;
	seenbyeandok = false;
	seenbyeandok_permanent = false;
	seenbyeandok_time_usec = 0;
	seencancelandok = false;
	seencancelandok_time_usec = 0;
	seenauthfailed = false;
	seenauthfailed_time_usec = 0;
	unconfirmed_bye = false;
	seenRES2XX = false;
	seenRES2XX_no_BYE = false;
	seenRES18X = false;
	caller[0] = '\0';
	caller_domain[0] = '\0';
	callername[0] = '\0';
	called_to[0] = '\0';
	called_uri[0] = '\0';
	called_final[0] = '\0';
	called_domain_to[0] = '\0';
	called_domain_uri[0] = '\0';
	contact_num[0] = '\0';
	contact_domain[0] = '\0';
	digest_username[0] = '\0';
	digest_realm[0] = '\0';
	register_expires = -1;
	for(unsigned i = 0; i < (sizeof(byecseq) / sizeof(byecseq[0])); i++) {
		byecseq[i].null();
	}
	invitecseq.null();
	messagecseq.null();
	registercseq.null();
	cancelcseq.null();
	updatecseq.null();
	sighup = false;
	progress_time_us = 0;
	first_rtp_time_us = 0;
	connect_time_us = 0;
	first_invite_time_us = 0;
	first_response_100_time_us = 0;
	first_response_xxx_time_us = 0;
	first_message_time_us = 0;
	first_response_200_time_us = 0;
	a_ua[0] = '\0';
	b_ua[0] = '\0';
	memset(rtpmap, 0, sizeof(rtpmap));
	memset(rtpmap_used_flags, 0, sizeof(rtpmap_used_flags));
	rtp_cur[0] = NULL;
	rtp_cur[1] = NULL;
	rtp_prev[0] = NULL;
	rtp_prev[1] = NULL;
	lastSIPresponse[0] = '\0';
	lastSIPresponseNum = 0;
	new_invite_after_lsr487 = false;
	cancel_lsr487 = false;
	reason_sip_cause = 0;
	reason_q850_cause = 0;
	hold_status = false;
	is_fas_detected = false;
	is_zerossrc_detected = false;
	is_sipalg_detected = false;
	msgcount = 0;
	regcount = 0;
	regcount_after_4xx = 0;
	reg401count = 0;
	reg401count_all = 0;
	reg403count = 0;
	reg404count = 0;
	reg200count = 0;
	regstate = 0;
	regresponse = false;
	regrrddiff = -1;
	//regsrcmac = 0;
	reg_tcp_seq = NULL;
	last_sip_method = 0;
	for(int i = 0; i < MAX_SSRC_PER_CALL_FIX; i++) {
		rtp_fix[i] = NULL;
	}
	ssrc_n = 0;
	#if CALL_RTP_DYNAMIC_ARRAY
	rtp_dynamic = NULL;
	#endif
	rtp_canceled = NULL;
	rtp_remove_flag = false;
	rtpab[0] = NULL;
	rtpab[1] = NULL;
	dtls = NULL;
	rtplock_sync = 0;
	listening_worker_run = NULL;
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	saddr.clear();
	sport.clear();
	daddr.clear();
	dport.clear();
	destroy_call_at = 0;
	destroy_call_at_bye = 0;
	destroy_call_at_bye_confirmed = 0;
	custom_header1[0] = '\0';
	match_header[0] = '\0';
	thread_num = 0;
	thread_num_rd = 0;
	setRtpThreadNum();
	recordstopped = 0;
	dtmfflag = 0;
	for(unsigned int i = 0; i < sizeof(dtmfflag2) / sizeof(dtmfflag2[0]); i++) {
		dtmfflag2[i] = 0;
	}
	silencerecording = 0;
	recordingpausedby182 = 0;
	save_energylevels = false;
	rtppacketsinqueue = 0;
	end_call_rtp = 0;
	end_call_hash_removed = 0;
	push_call_to_calls_queue = 0;
	push_register_to_registers_queue = 0;
	push_call_to_storing_cdr_queue = 0;
	message = NULL;
	message_info = NULL;
	contenttype = NULL;
	content_length = 0;
	dcs = 0;
	voicemail = voicemail_na;
	max_length_sip_data = 0;
	max_length_sip_packet = 0;
	for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
		 sipcallerip[i].clear();
		 sipcalledip[i].clear();
		 sipcallerport[i].clear();
		 sipcalledport[i].clear();
	}
	sipcalledip_mod.clear();
	sipcalledport_mod.clear();
	sipcallerip_encaps.clear();
	sipcalledip_encaps.clear();
	sipcallerip_encaps_prot = 0xFF;
	sipcalledip_encaps_prot = 0xFF;
	lastsipcallerip.clear();
	sipcallerdip_reverse = false;
	skinny_partyid = 0;
	pthread_mutex_init(&listening_worker_run_lock, NULL);
	caller_sipdscp = 0;
	called_sipdscp = 0;
	ps_ifdrop = pcapstat.ps_ifdrop;
	ps_drop = pcapstat.ps_drop;
	if(verbosity && verbosityE > 1) {
		syslog(LOG_NOTICE, "CREATE CALL %s", this->call_id.c_str());
	}
	_custom_headers_content_sync = 0;
	_forcemark_lock = 0;
	_proxies_lock = 0;
	a_mos_lqo = -1;
	b_mos_lqo = -1;
	oneway = 1;
	absolute_timeout_exceeded = 0;
	zombie_timeout_exceeded = 0;
	bye_timeout_exceeded = 0;
	rtp_timeout_exceeded = 0;
	sipwithoutrtp_timeout_exceeded = 0;
	oneway_timeout_exceeded = 0;
	force_terminate = 0;
	pcap_drop = 0;
	
	onInvite = false;
	onCall_2XX = false;
	onCall_18X = false;
	onHangup = false;
	updateDstnumOnAnswer = false;
	updateDstnumFromMessage = false;
	
	force_close = false;
	
	first_codec = -1;
	
        caller_silence = 0;
        called_silence = 0;
        caller_noise = 0;
        called_noise = 0;
	caller_lastsilence = 0;
	called_lastsilence = 0;

	caller_clipping_8k = 0;
	called_clipping_8k = 0;
	
	vlan = VLAN_UNSET;
	
	_mergecalls_lock = 0;
	
	exists_srtp = false;
	exists_srtp_crypto_config = false;
	exists_srtp_fingerprint = false;
	for(int i = 0; i < 2; i++) {
		callerd_confirm_rtp_by_both_sides_sdp[i] = 0;
	}
	log_srtp_callid = false;
	
	error_negative_payload_length = false;
	rtp_ip_port_counter = 0;
	hash_queue_counter = 0;
	attemptsClose = 0;
	useInListCalls = 0;
	use_rtcp_mux = false;
	use_sdp_sendonly = false;
	rtp_from_multiple_sensors = false;
	
	sdp_exists_media_type_audio = false;
	sdp_exists_media_type_image = false;
	sdp_exists_media_type_video = false;
	sdp_exists_media_type_application = false;
	
	is_ssl = false;

	rtp_zeropackets_stored = 0;
	
	lastraw[0] = NULL;
	lastraw[1] = NULL;

	iscaller_consecutive[0] = 0;
	iscaller_consecutive[1] = 0;
	
	last_mgcp_connect_packet_time_us = 0;
	
	_hash_add_lock = 0;
	
	counter = ++counter_s;
	
	syslog_sdp_multiplication = false;
	
	_txt_lock = 0;
	
	televent_exists_request = false;
	televent_exists_response = false;
	
	exclude_from_active_calls = false;
	
	cdr.setIgnoreCheckExistsField();
	cdr_next.setIgnoreCheckExistsField();
	for(int i = 0; i < CDR_NEXT_MAX; i++) {
		cdr_next_ch[i].setIgnoreCheckExistsField();
	}
	cdr_country_code.setIgnoreCheckExistsField();
	
	set_call_counter = false;
	set_register_counter = false;
	
	suppress_rtp_read_due_to_insufficient_hw_performance = false;
	suppress_rtp_proc_due_to_insufficient_hw_performance = false;
}

u_int64_t Call::counter_s = 0;

void
Call::hashRemove(struct timeval *ts, bool useHashQueueCounter) {
	for(int i = 0; i < ipport_n; i++) {
		calltable->hashRemove(this, this->ip_port[i].addr, this->ip_port[i].port, ts, false, useHashQueueCounter);
		if(opt_rtcp) {
			calltable->hashRemove(this, this->ip_port[i].addr, this->ip_port[i].port.inc(), ts, true, useHashQueueCounter);
		}
		this->evDestroyIpPortRtpStream(i);
	}
	
	if(!opt_hash_modify_queue_length_ms && this->rtp_ip_port_counter) {
		syslog(LOG_WARNING, "WARNING: rest before hash cleanup for callid: %s: %i", this->fbasename, this->rtp_ip_port_counter);
		if(this->rtp_ip_port_counter > 0) {
			calltable->hashRemove(this, ts, useHashQueueCounter);
			if(this->rtp_ip_port_counter) {
				syslog(LOG_WARNING, "WARNING: rest after hash cleanup for callid: %s: %i", this->fbasename, this->rtp_ip_port_counter);
			}
		}
	}
}

void
Call::skinnyTablesRemove() {
	if(opt_skinny) {
		calltable->lock_skinny_maps();
		if(skinny_partyid) {
			calltable->skinny_partyID.erase(skinny_partyid);
			skinny_partyid = 0;
		}
		for (map<d_item<vmIP>, Call*>::iterator skinny_ipTuplesIT = calltable->skinny_ipTuples.begin(); skinny_ipTuplesIT != calltable->skinny_ipTuples.end();) {
			if(skinny_ipTuplesIT->second == this) {
				calltable->skinny_ipTuples.erase(skinny_ipTuplesIT++);
			} else {
				++skinny_ipTuplesIT;
			}
		}
		calltable->unlock_skinny_maps();
	}
}

void
Call::removeFindTables(struct timeval *ts, bool set_end_call, bool destroy) {
	if(set_end_call) {
		hash_add_lock();
		this->end_call_rtp = 1;
		if(!(opt_hash_modify_queue_length_ms && this->end_call_hash_removed)) {
			this->hashRemove(ts, true);
			this->end_call_hash_removed = 1;
		}
		hash_add_unlock();
	} else if(destroy) {
		if(opt_hash_modify_queue_length_ms && this->rtp_ip_port_counter) {
			calltable->hashRemoveForce(this);
		}
		this->hashRemove(ts);
	} else {
		this->hashRemove(ts, true);
	}
	this->skinnyTablesRemove();
}

void
Call::destroyCall() {
	this->removeFindTables(NULL, false, true);
	this->atFinish();
	this->calls_counter_dec();
}

void
Call::addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, long long writeBytes) {
	_addtofilesqueue(typeSpoolFile, file, dirnamesqlfiles(), writeBytes, getSpoolIndex());
}

void 
Call::_addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, string dirnamesqlfiles, long long writeBytes, int spoolIndex) {
 
	if(!opt_filesclean or opt_nocdr or file == "" or !isSqlDriver("mysql") or
	   !CleanSpool::isSetCleanspool(spoolIndex) or
	   !CleanSpool::check_datehour(dirnamesqlfiles.c_str())) {
		return;
	}

	string dst_file_cachedir;
	if(opt_cachedir[0] != '\0') {
		int cachedir_length = strlen(opt_cachedir);
		if(!strncmp(file.c_str(), opt_cachedir, cachedir_length)) {
			while(file[cachedir_length] == '/') {
				++cachedir_length;
			}
			dst_file_cachedir = string(::getSpoolDir(typeSpoolFile, spoolIndex)) + '/' + file.substr(cachedir_length);
		}
	}
	
	bool fileExists = file_exists((char*)file.c_str());
	bool fileCacheExists = false;
	string fileCache;
	if(opt_cachedir[0] != '\0') {
		fileCache = string(opt_cachedir) + "/" + file;
		fileCacheExists = file_exists((char*)fileCache.c_str());
	}
	if(!fileExists && !fileCacheExists) return;

	long long size = 0;
	if(fileExists) {
		size = GetFileSizeDU(file, typeSpoolFile, spoolIndex);
	}
	if(!size && fileCacheExists) {
		size = GetFileSizeDU(fileCache, typeSpoolFile, spoolIndex);
	}
	if(writeBytes) {
		writeBytes = GetDU(writeBytes, typeSpoolFile, spoolIndex);
		if(writeBytes > size) {
			size = writeBytes;
		}
	}

	if(size == (long long)-1) {
		//error or file does not exists
		char buf[4092];
		buf[0] = '\0';
		strerror_r(errno, buf, 4092);
		syslog(LOG_ERR, "addtofilesqueue ERROR file[%s] - error[%d][%s]", file.c_str(), errno, buf);
		return;
	}

	if(size == 0) {
		// if the file has 0 size we still need to add it to cleaning procedure
		size = 1;
	}

	extern CleanSpool *cleanSpool[2];
	if(cleanSpool[spoolIndex]) {
		cleanSpool[spoolIndex]->addFile(dirnamesqlfiles.c_str(), typeSpoolFile, dst_file_cachedir.empty() ? file.c_str() : dst_file_cachedir.c_str(), size);
	}
}

void 
Call::evStartRtpStream(int /*index_ip_port*/, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time) {
	/*cout << "start rtp stream : "
	     << saddr.getString() << ":" << sport << " -> " 
	     << daddr.getString() << ":" << dport << endl;*/
	if(opt_enable_fraud) {
		fraudBeginRtpStream(saddr, sport, daddr, dport, this, time);
	}
}

void 
Call::evEndRtpStream(int /*index_ip_port*/, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time) {
	/*cout << "stop rtp stream : "
	     << saddr.getString() << ":" << sport << " -> " 
	     << daddr.getString() << ":" << dport << endl;*/
	if(opt_enable_fraud) {
		fraudEndRtpStream(saddr, sport, daddr, dport, this, time);
	}
}

void
Call::addtocachequeue(string file) {
	_addtocachequeue(file);
}

void 
Call::_addtocachequeue(string file) {
	int cachedir_length = strlen(opt_cachedir);
	if(!strncmp(file.c_str(), opt_cachedir, cachedir_length)) {
		while(file[cachedir_length] == '/') {
			++cachedir_length;
		}
		file = file.substr(cachedir_length);
	}
	calltable->lock_files_queue();
	calltable->files_queue.push(file);
	calltable->unlock_files_queue();
}

void
Call::setFlagForRemoveRTP() {
	while(rtppacketsinqueue > 0) {
		if(!opt_t2_boost && rtp_threads) {
			extern int num_threads_max;
			for(int i = 0; i < num_threads_max; i++) {
				if(rtp_threads[i].threadId) {
					rtp_threads[i].push_batch();
				}
			}
		}
		USLEEP(100);
	}
	rtp_remove_flag = true;
}

void
Call::_removeRTP() {
	closeRawFiles();
	if(!rtp_canceled) {
		rtp_canceled = new FILE_LINE(0) list<RTP*>;
	}
	for(int i = 0; i < MAX_SSRC_PER_CALL_FIX; i++) {
		if(rtp_fix[i]) {
			rtp_canceled->push_back(rtp_fix[i]);
			rtp_fix[i] = NULL;
		}
	}
	#if CALL_RTP_DYNAMIC_ARRAY
	if(rtp_dynamic) {
		for(CALL_RTP_DYNAMIC_ARRAY_TYPE::iterator iter = rtp_dynamic->begin(); iter != rtp_dynamic->end(); iter++) {
			rtp_canceled->push_back(*iter);
		}
		rtp_dynamic->clear();
	}
	#endif
	ssrc_n = 0;
	for(int i = 0; i < 2; i++) {
		rtp_cur[i] = NULL;
		rtp_prev[i] = NULL;
	}
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	rtp_remove_flag = false;
}

/* destructor */
Call::~Call(){
 
	#if DEBUG_ASYNC_TAR_WRITE
 	extern cDestroyCallsInfo *destroy_calls_info;
	if(destroy_calls_info) {
		destroy_calls_info->add(this);
	}
	#endif
 
	alloc_flag = 0;
	
	if(opt_call_id_alternative[0] && call_id_alternative) {
		delete call_id_alternative;
	}
 
	removeMergeCalls();
	
	if(is_ssl) {
		glob_ssl_calls--;
	}

	if(contenttype) delete [] contenttype;
	
	for(int i = 0; i < MAX_SSRC_PER_CALL_FIX; i++) {
		if(rtp_fix[i]) {
			delete rtp_fix[i];
		}
	}
	#if CALL_RTP_DYNAMIC_ARRAY
	if(rtp_dynamic) {
		for(CALL_RTP_DYNAMIC_ARRAY_TYPE::iterator iter = rtp_dynamic->begin(); iter != rtp_dynamic->end(); iter++) {
			delete *iter;
		}
		delete rtp_dynamic;
	}
	#endif
	if(rtp_canceled) {
		for(list<RTP*>::iterator iter = rtp_canceled->begin(); iter != rtp_canceled->end(); iter++) {
			delete *iter;
		}
		delete rtp_canceled;
	}
	
	if(dtls) {
		delete dtls;
	}
	
	// tell listening_worker to stop listening
	if(listening_worker_run) {
		*listening_worker_run = 0;
	}
	destroyListeningBuffers();
	listening_remove_worker(this);
	pthread_mutex_destroy(&listening_worker_run_lock);
	
	if(this->message) {
		delete [] message;
	}
	if(this->message_info) {
		delete [] message_info;
	}
	//decreaseTartimemap(this->first_packet_time);
	//printf("caller s[%u] n[%u] ls[%u]  called s[%u] n[%u] ls[%u]\n", caller_silence, caller_noise, caller_lastsilence, called_silence, called_noise, called_lastsilence);
	//printf("caller_clipping_8k [%u] [%u]\n", caller_clipping_8k, called_clipping_8k);
	
	if(typeIs(INVITE) && is_enable_rtp_threads() && num_threads_active > 0 && rtp_threads) {
		extern void lock_add_remove_rtp_threads();
		extern void unlock_add_remove_rtp_threads();
		lock_add_remove_rtp_threads();
		if(rtp_threads[thread_num].calls > 0) {
			__sync_sub_and_fetch(&rtp_threads[thread_num].calls, 1);
		}
		unlock_add_remove_rtp_threads();
	}
	
	if(reg_tcp_seq) {
		delete reg_tcp_seq;
	}
	
	for(map<sStreamId, sUdptlDumper*>::iterator iter = udptlDumpers.begin(); iter != udptlDumpers.end(); iter++) {
		delete iter->second;
	}
	
	for(map<int, class RTPsecure*>::iterator iter = rtp_secure_map.begin(); iter != rtp_secure_map.end(); iter++) {
		delete iter->second;
	}
	
	if(set_call_counter) {
		calls_counter_dec();
	}
	if(set_register_counter) {
		registers_counter_dec();
	}
	
}

void
Call::closeRawFiles() {
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if(!rtp_i) {
			continue;
		}
		// close RAW files
		if(rtp_i->gfileRAW || rtp_i->initRAW) {
			rtp_i->jitterbuffer_fixed_flush(rtp_i->channel_record);
			if(rtp_i->gfileRAW) {
				/* preventing race condition as gfileRAW is checking for NULL pointer in rtp classes */ 
				FILE *tmp;
				tmp = rtp_i->gfileRAW;
				rtp_i->gfileRAW = NULL;
				fclose(tmp);
			}
			rtp_i->initRAW = false;
		}
		// close GRAPH files
		if(opt_saveGRAPH || (flags & FLAG_SAVEGRAPH)) {
			if(rtp_i->graph.isOpen()) {
				if(!rtp_i->mos_processed or (rtp_i->last_mos_time + 1 < rtp_i->_last_ts.tv_sec)) {
					rtp_i->save_mos_graph(true);
				}
				rtp_i->graph.close();
			} else {
				rtp_i->graph.clearAutoOpen();
			}
		}
	}
}

/* add ip adress and port to this call */
int
Call::add_ip_port(vmIP sip_src_addr, vmIP addr, ip_port_call_info::eTypeAddr type_addr, vmPort port, struct timeval *ts, 
		  char *sessid, char *sdp_label, 
		  list<srtp_crypto_config> *srtp_crypto_config_list, string *srtp_fingerprint,
		  char *to, char *branch, int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags) {
	if(this->end_call_rtp) {
		return(-1);
	}
 
	if(verbosity >= 4) {
		printf("call:[%p] ip:[%s] port:[%d] iscaller:[%d]\n", this, addr.getString().c_str(), port.getPort(), iscaller);
	}

	if(ipport_n > 0) {
		if(this->refresh_data_ip_port(addr, port, ts, 
					      srtp_crypto_config_list, srtp_fingerprint,
					      iscaller, rtpmap, sdp_flags)) {
			return 1;
		}
	}
	
	if(sverb.process_rtp) {
		cout << "RTP - add_ip_port: " << addr.getString() << " / " << port << " " << iscaller_description(iscaller) << endl;
	}

	if(ipport_n == MAX_IP_PER_CALL){
		syslog(LOG_ERR,"callid [%s]: to much INVITEs in this call [%s:%d], raise MAX_IP_PER_CALL and recompile sniffer", call_id.c_str(), addr.getString().c_str(), port.getPort());
	}
	// add ip and port
	if(ipport_n >= MAX_IP_PER_CALL){
		return -1;
	}

	this->ip_port[ipport_n].sip_src_addr = sip_src_addr;
	this->ip_port[ipport_n].addr = addr;
	this->ip_port[ipport_n].type_addr = type_addr;
	this->ip_port[ipport_n].port = port;
	this->ip_port[ipport_n].iscaller = iscaller;
	this->ip_port[ipport_n].sdp_flags = sdp_flags;
	if(sessid) {
		this->ip_port[ipport_n].sessid = sessid;
	}
	if(sdp_label) {
		this->ip_port[ipport_n].sdp_label = sdp_label;
	}
	if(sdp_flags.protocol == sdp_proto_srtp) {
		this->ip_port[ipport_n].setSrtp();
		this->exists_srtp = true;
	}
	if(srtp_crypto_config_list && srtp_crypto_config_list->size()) {
		this->ip_port[ipport_n].setSrtpCryptoConfig(srtp_crypto_config_list, getTimeUS(ts));
		this->exists_srtp_crypto_config = true;
	}
	if(srtp_fingerprint) {
		this->ip_port[ipport_n].setSrtpFingerprint(srtp_fingerprint);
		this->exists_srtp_fingerprint = true;
	}
	if(to) {
		this->ip_port[ipport_n].to = to;
	}
	if(branch) {
		this->ip_port[ipport_n].branch = branch;
	}
	nullIpPortInfoRtpStream(ipport_n);
	
	if(!opt_rtpmap_by_callerd || iscaller_is_set(iscaller)) {
		memcpy(this->rtpmap[opt_rtpmap_by_callerd ? iscaller : ipport_n], rtpmap, MAX_RTPMAP * sizeof(RTPMAP));
	}
	
	ipport_n++;
	return 0;
}

bool 
Call::refresh_data_ip_port(vmIP addr, vmPort port, struct timeval *ts, 
			   list<srtp_crypto_config> *srtp_crypto_config_list, string *srtp_fingerprint,
			   int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags) {
	for(int i = 0; i < ipport_n; i++) {
		if(this->ip_port[i].addr == addr && this->ip_port[i].port == port) {
			// reinit rtpmap
			if(!opt_rtpmap_by_callerd || iscaller_is_set(iscaller)) {
				if(opt_rtpmap_combination) {
					RTPMAP *rtpmap_src = rtpmap;
					RTPMAP *rtpmap_dst = this->rtpmap[opt_rtpmap_by_callerd ? iscaller : i];
					for(int i_src = 0; i_src < MAX_RTPMAP - 1; i_src++) {
						if(rtpmap_src[i_src].is_set()) {
							int indexEqPayload = -1;
							int indexZero = -1;
							for(int i_dst = 0; i_dst < MAX_RTPMAP - 2; i_dst++) {
								if(!rtpmap_dst[i_dst].is_set()) {
									if(indexZero == -1) {
										indexZero = i_dst;
										break;
									}
								} else if(rtpmap_dst[i_dst].payload == rtpmap_src[i_src].payload) {
									if(indexEqPayload == -1) {
										indexEqPayload = i_dst;
										break;
									}
								}
							}
							if(indexEqPayload >= 0) {
								rtpmap_dst[indexEqPayload] = rtpmap_src[i_src];
							} else if(indexZero >= 0) {
								rtpmap_dst[indexZero] = rtpmap_src[i_src];
								rtpmap_dst[indexZero + 1].clear();
							}
						}
					}
				} else {
					memcpy(this->rtpmap[opt_rtpmap_by_callerd ? iscaller : i], rtpmap, MAX_RTPMAP * sizeof(RTPMAP));
				}
			}
			// force mark bit for reinvite for both direction
			u_int64_t _forcemark_time_us = getTimeUS(ts);
			forcemark_lock();
			forcemark_time.push_back(_forcemark_time_us);
			if(sverb.forcemark) {
				cout << "add forcemark: " << _forcemark_time_us 
				     << " forcemarks size: " << forcemark_time.size() 
				     << endl;
			}
			forcemark_unlock();
			if(sdp_flags != this->ip_port[i].sdp_flags) {
				if(this->ip_port[i].sdp_flags.is_image()) {
					sdp_flags.media_type |= sdp_media_type_image;
				}
				this->ip_port[i].sdp_flags = sdp_flags;
				calltable->lock_calls_hash();
				node_call_rtp *n_call = calltable->hashfind_by_ip_port(addr, port, false);
				if(n_call) {
					#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
					for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end(); iter++) {
						if((*iter)->call == this) {
							(*iter)->sdp_flags = sdp_flags;
						}
					}
					#else
					for(; n_call; n_call = n_call->next) {
						if(n_call->call == this) {
							n_call->sdp_flags = sdp_flags;
						}
					}
					#endif
				}
				calltable->unlock_calls_hash();
			}
			if(sdp_flags.protocol == sdp_proto_srtp) {
				this->ip_port[i].setSrtp();
				this->exists_srtp = true;
			}
			if(srtp_crypto_config_list && srtp_crypto_config_list->size()) {
				this->ip_port[i].setSrtpCryptoConfig(srtp_crypto_config_list, getTimeUS(ts));
				this->exists_srtp_crypto_config = true;
			}
			if(srtp_fingerprint) {
				this->ip_port[i].setSrtpFingerprint(srtp_fingerprint);
				this->exists_srtp_fingerprint = true;
			}
			return true;
		}
	}
	return false;
}

void
Call::add_ip_port_hash(vmIP sip_src_addr, vmIP addr, ip_port_call_info::eTypeAddr type_addr, vmPort port, struct timeval *ts, 
		       char *sessid, char *sdp_label, bool multipleSdpMedia, 
		       list<srtp_crypto_config> *srtp_crypto_config_list, string *srtp_fingerprint,
		       char *to, char *branch, int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags) {
	if(this->end_call_rtp) {
		return;
	}

	if(sessid && !multipleSdpMedia) {
		int sessidIndex = get_index_by_sessid_to(sessid, to, sip_src_addr, type_addr);
		if(sessidIndex >= 0) {
			if(this->ip_port[sessidIndex].sip_src_addr == sip_src_addr &&
			   (this->ip_port[sessidIndex].addr != addr ||
			    this->ip_port[sessidIndex].port != port ||
			    this->ip_port[sessidIndex].iscaller != iscaller)) {
				((Calltable*)calltable)->hashRemove(this, ip_port[sessidIndex].addr, ip_port[sessidIndex].port, ts);
				((Calltable*)calltable)->hashAdd(addr, port, ts, this, iscaller, 0, sdp_flags);
				if(opt_rtcp) {
					((Calltable*)calltable)->hashRemove(this, ip_port[sessidIndex].addr, ip_port[sessidIndex].port.inc(), ts, true);
					if(!sdp_flags.rtcp_mux && !sdp_flags.is_application()) {
						((Calltable*)calltable)->hashAdd(addr, port.inc(), ts, this, iscaller, 1, sdp_flags);
					}
				}
				//cout << "change ip/port for sessid " << sessid << " ip:" << addr.getString() << "/" << this->ip_port[sessidIndex].addr.getString() << " port:" << port << "/" <<  this->ip_port[sessidIndex].port << endl;
				if(this->ip_port[sessidIndex].addr != addr ||
				   this->ip_port[sessidIndex].port != port) {
					evDestroyIpPortRtpStream(sessidIndex);
					this->ip_port[sessidIndex].addr = addr;
					this->ip_port[sessidIndex].port = port;
				}
				this->ip_port[sessidIndex].iscaller = iscaller;
			}
			this->refresh_data_ip_port(addr, port, ts, 
						   srtp_crypto_config_list, srtp_fingerprint,
						   iscaller, rtpmap, sdp_flags);
			return;
		}
	}
	if(this->add_ip_port(sip_src_addr, addr, type_addr, port, ts, 
			     sessid, sdp_label, 
			     srtp_crypto_config_list, srtp_fingerprint,
			     to, branch, iscaller, rtpmap, sdp_flags) != -1) {
		((Calltable*)calltable)->hashAdd(addr, port, ts, this, iscaller, 0, sdp_flags);
		if(opt_rtcp && !sdp_flags.rtcp_mux) {
			((Calltable*)calltable)->hashAdd(addr, port.inc(), ts, this, iscaller, 1, sdp_flags);
		}
	}
}

void 
Call::cancel_ip_port_hash(vmIP sip_src_addr, char *to, char *branch, struct timeval *ts) {
	for(int i = 0; i < ipport_n; i++) {
		if(this->ip_port[i].sip_src_addr == sip_src_addr &&
		   !strcmp(this->ip_port[i].branch.c_str(), branch) &&
		   !strcmp(this->ip_port[i].to.c_str(), to)) {
			this->ip_port[i].canceled = true;
			((Calltable*)calltable)->hashRemove(this, ip_port[i].addr, ip_port[i].port, ts);
			if(opt_rtcp) {
				((Calltable*)calltable)->hashRemove(this, ip_port[i].addr, ip_port[i].port.inc(), ts, true);
			}
		}
	}
}

int
Call::get_index_by_ip_port(vmIP addr, vmPort port, bool use_sip_src_addr, bool rtcp) {
	for(int i = 0; i < ipport_n; i++) {
		if((use_sip_src_addr ? this->ip_port[i].sip_src_addr : this->ip_port[i].addr) == addr &&
		   this->ip_port[i].port == (rtcp && !this->ip_port[i].sdp_flags.rtcp_mux ? port.dec() : port)) {
			// we have found it
			return i;
		}
	}
	// not found
	return -1;
}

int
Call::get_index_by_sessid_to(char *sessid, char *to, vmIP sip_src_addr, ip_port_call_info::eTypeAddr type_addr) {
	for(int i = 0; i < ipport_n; i++) {
		if(!strcmp(this->ip_port[i].sessid.c_str(), sessid) &&
		   !strcmp(this->ip_port[i].to.c_str(), to) &&
		   this->ip_port[i].sip_src_addr == sip_src_addr &&
		   this->ip_port[i].type_addr == type_addr) {
			// we have found it
			return i;
		}
	}
	// not found
	return -1;
}

int 
Call::get_index_by_iscaller(int iscaller) {
	for(int i = 0; i < ipport_n; i++) {
		if(this->ip_port[i].iscaller == iscaller) {
			// we have found it
			return i;
		}
	}
	// not found
	return -1;
}

bool 
Call::is_multiple_to_branch() {
	for(int i = 0; i < ipport_n; i++) {
		if(sipcallerip[0] == this->ip_port[i].sip_src_addr) {
			for(int j = 0; j < ipport_n; j++) {
				if(j != i &&
				   sipcallerip[0] == this->ip_port[j].sip_src_addr &&
				   this->ip_port[i].to.length() && this->ip_port[j].to.length() &&
				   this->ip_port[i].to != this->ip_port[j].to &&
				   this->ip_port[i].branch.length() && this->ip_port[j].branch.length() &&
				   this->ip_port[i].branch != this->ip_port[j].branch) {
					return(true);
				}
			}
		}
	}
	return(false);
}

bool
Call::all_invite_is_multibranch(vmIP saddr) {
	if(invite_sdaddr.size() < 2) {
		return(false);
	}
	list<Call::sInviteSD_Addr>::iterator iter1;
	list<Call::sInviteSD_Addr>::iterator iter2;
	unsigned int counter1 = 0;
	unsigned int counter2 = 0;
	for(iter1 = invite_sdaddr.begin(); iter1 != invite_sdaddr.end(); iter1++) {
		if(iter1->saddr == saddr) {
			++counter1;
			counter2 = 0;
			for(iter2 = invite_sdaddr.begin(); iter2 != invite_sdaddr.end(); iter2++) {
				if(iter2->saddr == saddr) {
					++counter2;
					if(counter2 > counter1) {
						if(iter1->called == iter2->called || iter1->branch == iter2->branch) {
							return(false);
						}
					}
				}
			}
		}
	}
	return(counter1 >= 1);
}

bool 
Call::to_is_canceled(char *to) {
	for(int i = 0; i < ipport_n; i++) {
		if(sipcallerip[0] == this->ip_port[i].sip_src_addr &&
		   !strcmp(this->ip_port[i].to.c_str(), to) &&
		   this->ip_port[i].canceled) {
			return(true);
		}
	}
	return(false);
}

string
Call::get_to_not_canceled() {
	for(int i = 0; i < ipport_n; i++) {
		if(sipcallerip[0] == this->ip_port[i].sip_src_addr &&
		   this->ip_port[i].to.length() &&
		   !this->ip_port[i].canceled) {
			return(this->ip_port[i].to);
		}
	}
	return("");
}

/* analyze rtcp packet */
bool
Call::read_rtcp(packet_s *packetS, int iscaller, char enable_save_packet) {
	extern int opt_vlan_siprtpsame;
	if(opt_vlan_siprtpsame && VLAN_IS_SET(this->vlan) &&
	   packetS->pid.vlan != this->vlan) {
		return(false);
	}

	RTPsecure *srtp_decrypt = NULL;
	if(exists_srtp && opt_srtp_rtcp_decrypt) {
		int index_call_ip_port_by_src = get_index_by_ip_port(packetS->saddr_(), packetS->source_(), false, true);
		if(index_call_ip_port_by_src < 0) {
			index_call_ip_port_by_src = get_index_by_ip_port(packetS->saddr_(), packetS->source_(), true, true);
		}
		if(index_call_ip_port_by_src < 0 && iscaller_is_set(iscaller)) {
			index_call_ip_port_by_src = get_index_by_iscaller(iscaller_inv_index(iscaller));
		}
		if(index_call_ip_port_by_src >= 0 && 
		   this->ip_port[index_call_ip_port_by_src].srtp) {
			if(!rtp_secure_map[index_call_ip_port_by_src]) {
				rtp_secure_map[index_call_ip_port_by_src] = 
					new FILE_LINE(0) RTPsecure(opt_use_libsrtp ? RTPsecure::mode_libsrtp : RTPsecure::mode_native,
								   this, index_call_ip_port_by_src);
				if(sverb.log_srtp_callid && !log_srtp_callid) {
					syslog(LOG_INFO, "SRTCP exists in call %s", call_id.c_str());
					log_srtp_callid = true;
				}
			}
			srtp_decrypt = rtp_secure_map[index_call_ip_port_by_src];
		}
	}
	
	unsigned datalen_orig = packetS->datalen_();
	if(srtp_decrypt && opt_srtp_rtcp_decrypt) {
		u_int32_t datalen = packetS->datalen_();
		if(srtp_decrypt->need_prepare_decrypt()) {
			srtp_decrypt->prepare_decrypt(packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_());
		}
		srtp_decrypt->decrypt_rtcp((u_char*)packetS->data_(), &datalen, getTimeUS(packetS->header_pt));
		packetS->set_datalen_(datalen);
	}

	parse_rtcp((char*)packetS->data_(), packetS->datalen_(), packetS->getTimeval_pt(), this);
	
	if(enable_save_packet) {
		save_packet(this, packetS, _t_packet_rtcp, packetS->datalen_() != datalen_orig);
	}
	return(true);
}

/* analyze rtp packet */
bool
Call::read_rtp(packet_s *packetS, int iscaller, bool find_by_dest, bool stream_in_multiple_calls, s_sdp_flags_base sdp_flags, char enable_save_packet, char *ifname) {
	extern int opt_enable_ssl;
	extern bool opt_srtp_rtp_dtls_decrypt;
	if(opt_enable_ssl && opt_srtp_rtp_dtls_decrypt && packetS->isDtls()) {
		read_dtls(packetS);
		if(enable_save_packet) {
			save_packet(this, packetS, _t_packet_dtls);
		}
		return(true);
	} else if(packetS->pflags.mrcp) {
		if(enable_save_packet) {
			save_packet(this, packetS, _t_packet_mrcp);
		}
		return(true);
	}
	extern bool opt_null_rtppayload;
	if(opt_null_rtppayload) {
		RTP tmprtp(0, 0);
		tmprtp.fill_data((u_char*)packetS->data_(), packetS->datalen_());
		int payload_len = tmprtp.get_payload_len();
		if(payload_len > 0) {
			memset(tmprtp.payload_data, 0, payload_len);
		}
	}
	bool record_dtmf = false;
	bool disable_save = false;
	unsigned datalen_orig = packetS->datalen_();
	bool rtp_read_rslt = _read_rtp(packetS, iscaller, sdp_flags, find_by_dest, stream_in_multiple_calls, ifname, &record_dtmf, &disable_save);
	if(!disable_save) {
		_save_rtp(packetS, sdp_flags, enable_save_packet, record_dtmf, packetS->datalen_() != datalen_orig);
	}
	if(packetS->pid.flags & FLAG_FRAGMENTED) {
		this->rtp_fragmented = true;
	}
	return(rtp_read_rslt);
}
 
bool
Call::_read_rtp(packet_s *packetS, int iscaller, s_sdp_flags_base sdp_flags, bool find_by_dest, bool stream_in_multiple_calls, char *ifname, bool *record_dtmf, bool *disable_save) {
 
	removeRTP_ifSetFlag();
 
	if(iscaller < 0) {
		if(this->is_sipcaller(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_()) || 
		   this->is_sipcalled(packetS->daddr_(), packetS->dest_(), packetS->saddr_(), packetS->source_()) ||
		   this->is_sipcaller(packetS->saddr_(), packetS->source_(), 0, 0) || 
		   this->is_sipcalled(packetS->daddr_(), packetS->dest_(), 0, 0)) {
			iscaller = 1;
		} else {
			iscaller = 0;
		}
	}
	
	extern int opt_vlan_siprtpsame;
	bool rtp_read_rslt = false;
	int curpayload;
	
	*record_dtmf = false;
	*disable_save = false;
	*is_video = false;
	
	if(opt_vlan_siprtpsame && VLAN_IS_SET(this->vlan) &&
	   packetS->pid.vlan != this->vlan) {
		*disable_save = true;
		return(false);
	}

	if(first_rtp_time_us == 0) {
		first_rtp_time_us = getTimeUS(packetS->header_pt);
	}
	
	unsigned int curSSRC;
	bool udptl = false;
	if(packetS->isRtp()) {
		void *data = packetS->data_();
		if(RTP::getVersion(data) == 2) {
			curSSRC = RTP::getSSRC(data);
			if(curSSRC == 0) {
				is_zerossrc_detected = true;
				if(!opt_allow_zerossrc) {
					return(false);
				}
			}
			curpayload = sdp_flags.is_video() ? PAYLOAD_VIDEO : RTP::getPayload(data);
		} else {
			return(false);
		}
	} else if(this->seenudptl || this->isfax) {
		udptl = true;
		curSSRC = -1;
		curpayload = -1;
	} else {
		return(false);
	}
	if (curpayload == 101 && !enable_save_dtmf_pcap(this)) {
		*disable_save = true;
	}
	// chekc if packet is DTMF and saverfc2833 is enabled 
	if(opt_saverfc2833 and curpayload == 101) {
		*record_dtmf = true;
	}

	if(!packetS->isRtpUdptlOkDataLen() && !sverb.process_rtp_header) {
		//Ignoring RTP packets without data
		if (sverb.read_rtp) syslog(LOG_DEBUG,"RTP packet skipped because of its datalen: %i", packetS->datalen_());
		return(false);
	}

	/* TODO:IPHDR ?
	if(opt_dscp && packetS->header_ip_offset) {
		packetS->header_ip_offset = packetS->dataoffset - sizeof(struct iphdr2) - sizeof(udphdr2);
	}
	*/
	
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if(rtp_i->ssrc2 == curSSRC) {
/*
			if(rtp_i->last_seq == tmprtp.getSeqNum()) {
				//ignore duplicated RTP with the same sequence
				//if(verbosity > 1) printf("ignoring lastseq[%u] seq[%u] saddr[%u] dport[%u]\n", rtp_stream_by_index(i)->last_seq, tmprtp.getSeqNum(), packetS->saddr_(), packetS->dest_());
				if(rtp_locked) rtp_unlock();
				return(false);
			}
*/

			if (opt_saverfc2833 || !enable_save_dtmf_pcap(this)) { // DTMF in dynamic payload types (rfc4733)
				for(int j = 0; j < MAX_RTPMAP; j++) {
					if(rtp_i->rtpmap[j].is_set() && rtp_i->rtpmap[j].codec == PAYLOAD_TELEVENT && rtp_i->rtpmap[j].payload == curpayload) {
						if (!enable_save_dtmf_pcap(this)) {
							*disable_save = true;
						}
						if (opt_saverfc2833) {
							*record_dtmf = true;
						}
						break;
					}
				}
			}
			if(rtp_i->eqAddrPort(packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_())) {
				//if(verbosity > 1) printf("found seq[%u] saddr[%u] dport[%u]\n", tmprtp.getSeqNum(), packetS->saddr_(), packetS->dest_());
				// found
			 
				if(rtp_i->iscaller) {
					last_rtp_a_packet_time_us = getTimeUS(packetS->header_pt);
				} else {
					last_rtp_b_packet_time_us = getTimeUS(packetS->header_pt);
				}

				if(rtp_i->stopReadProcessing && opt_rtp_check_both_sides_by_sdp == 1) {
					*disable_save = true;
					return(false);
				}

				if(opt_dscp) {
					rtp_i->dscp = packetS->header_ip_()->get_tos() >> 2;
					if(sverb.dscp) {
						cout << "rtpdscp " << (int)(packetS->header_ip_()->get_tos()>>2) << endl;
					}
				}
				
				if(udptl) {
					++rtp_i->s->received;
					++rtp_i->stats.received;
					return(true);
				}
				
				// check if codec did not changed but ignore payload 13 and 19 which is CNG and 101 which is DTMF
				int oldcodec = rtp_i->codec;
				if(curpayload == 13 or curpayload == 19 or rtp_i->codec == PAYLOAD_TELEVENT or rtp_i->payload2 == curpayload) {
					goto read;
				} else {
					// check if the stream started with DTMF
					if(rtp_i->payload2 >= 96 && rtp_i->payload2 <= 127) {
						for(int pass_find_rtpmap = 0; pass_find_rtpmap < 2; pass_find_rtpmap++) {
							RTPMAP *rtpmap = pass_find_rtpmap ? rtp_i->rtpmap_other_side : rtp_i->rtpmap;
							for(int j = 0; j < MAX_RTPMAP; j++) {
								if(rtpmap[j].is_set() && rtp_i->payload2 == rtpmap[j].payload) {
									if(rtpmap[j].codec == PAYLOAD_TELEVENT) {
										//it is DTMF 
										rtp_i->payload2 = curpayload;
										goto read;
									}
								}
							}
						}
					}

					//codec changed, check if it is not DTMF 
					if(curpayload >= 96 && curpayload <= 127) {
						bool found = false;
						for(int pass_find_rtpmap = 0; pass_find_rtpmap < 2 && !found; pass_find_rtpmap++) {
							RTPMAP *rtpmap = pass_find_rtpmap ? rtp_i->rtpmap_other_side : rtp_i->rtpmap;
							for(int j = 0; j < MAX_RTPMAP; j++) {
								if(rtpmap[j].is_set() && curpayload == rtpmap[j].payload) {
									rtp_i->codec = rtpmap[j].codec;
									found = true;
								}
							}
						}
						if(!found) {
							// dynamic type codec changed but was not negotiated - do not create new RTP stream
							return(rtp_read_rslt);
						}
					} else {
						rtp_i->codec = curpayload;
					}
					if(rtp_i->codec == PAYLOAD_TELEVENT) {
read:
						if(rtp_i->index_call_ip_port >= 0) {
							evProcessRtpStream(rtp_i->index_call_ip_port, rtp_i->index_call_ip_port_by_dest,
									   packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), packetS->header_pt->ts.tv_sec);
						}
						if(find_by_dest ?
						    rtp_i->prev_sport.isSet() && rtp_i->prev_sport != packetS->source_() :
						    rtp_i->prev_dport.isSet() && rtp_i->prev_dport != packetS->dest_()) {
							rtp_i->change_src_port = true;
						}
						u_int32_t datalen = packetS->datalen_();
						if(rtp_i->read((u_char*)packetS->data_(), packetS->header_ip_(), &datalen, packetS->header_pt, packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(),
							       packetS->sensor_id_(), packetS->sensor_ip, ifname)) {
							rtp_read_rslt = true;
							if(stream_in_multiple_calls) {
								rtp_i->stream_in_multiple_calls = true;
							}
						}
						if(opt_rtp_stream_analysis_params) {
							rtp_i->rtp_stream_analysis_output();
						}
						packetS->set_datalen_(datalen);
						rtp_i->prev_sport = packetS->source_();
						rtp_i->prev_dport = packetS->dest_();
						if(rtp_i->iscaller) {
							lastcallerrtp = rtp_i;
						} else {
							lastcalledrtp = rtp_i;
						}
						return(rtp_read_rslt);
					} else if(oldcodec != rtp_i->codec){
						//codec changed and it is not DTMF, reset ssrc so the stream will not match and new one is used
						if(verbosity > 1) printf("mchange [%d] [%d]?\n", rtp_i->codec, oldcodec);
						rtp_i->ssrc2 = 0;
					} else {
						//if(verbosity > 1) printf("wtf lastseq[%u] seq[%u] saddr[%u] dport[%u] oldcodec[%u] rtp_stream_by_index(i)->codec[%u] rtp_stream_by_index(i)->payload2[%u] curpayload[%u]\n", rtp_stream_by_index(i)->last_seq, tmprtp.getSeqNum(), packetS->saddr_(), packetS->dest_(), oldcodec, rtp_stream_by_index(i)->codec, rtp_stream_by_index(i)->payload2, curpayload);
					}
				}
			}
		}
	}
	// adding new RTP source
	#if CALL_RTP_DYNAMIC_ARRAY
	if(rtp_size() < opt_rtp_streams_max_in_call) {
	#else
	if(rtp_size() < MAX_SSRC_PER_CALL_FIX) {
	#endif
	
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(rtp_i->saddr == packetS->daddr_() &&
			   rtp_i->daddr == packetS->saddr_() &&
			   rtp_i->sport == packetS->dest_() &&
			   rtp_i->dport == packetS->source_() &&
			   rtp_i->iscaller == iscaller) {
				iscaller = !rtp_i->iscaller;
			}
		}
		
		if(iscaller) {
			last_rtp_a_packet_time_us = getTimeUS(packetS->header_pt);
		} else {
			last_rtp_b_packet_time_us = getTimeUS(packetS->header_pt);
		}
		
		if(udptl) {
			RTP *rtp_new = new FILE_LINE(0) RTP(packetS->sensor_id_(), packetS->sensor_ip); 
			rtp_new->ssrc_index = rtp_size();
			rtp_new->call_owner = this;
			rtp_new->ssrc2 = curSSRC;
			rtp_new->iscaller = iscaller; 
			rtp_new->find_by_dest = find_by_dest;
			rtp_new->saddr = packetS->saddr_();
			rtp_new->daddr = packetS->daddr_();
			rtp_new->sport = packetS->source_();
			rtp_new->dport = packetS->dest_();
			++rtp_new->s->received;
			++rtp_new->stats.received;
			add_rtp_stream(rtp_new);
			return(true);
		}
		
		bool confirm_both_sides_by_sdp = false;
		int index_call_ip_port_find_side = this->get_index_by_ip_port(find_by_dest ? packetS->daddr_() : packetS->saddr_(),
									      find_by_dest ? packetS->dest_() : packetS->source_());
		int index_call_ip_port_other_side = this->get_index_by_ip_port(find_by_dest ? packetS->saddr_() : packetS->daddr_(),
									       find_by_dest ? packetS->source_() : packetS->dest_());
		if(this->txt.size()) {
			const char *sdp_label = NULL;
			if(index_call_ip_port_find_side >= 0 && !this->ip_port[index_call_ip_port_find_side].sdp_label.empty()) {
				sdp_label = this->ip_port[index_call_ip_port_find_side].sdp_label.c_str();
			} else if(index_call_ip_port_other_side >= 0 && !this->ip_port[index_call_ip_port_other_side].sdp_label.empty()) {
				sdp_label = this->ip_port[index_call_ip_port_other_side].sdp_label.c_str();
			}
			if(sdp_label && *sdp_label) {
				int _iscaller = this->detectCallerdByLabelInXml(sdp_label);
				if(_iscaller >= 0) {
					iscaller = _iscaller;
				}
			}
		}
		if(opt_rtp_check_both_sides_by_sdp && index_call_ip_port_find_side >= 0 && iscaller_is_set(iscaller)) {
			/*
			cout << " * new rtp stream " 
			     << packetS->saddr_().getString() << " : " << packetS->source_().getString() 
			     << " -> "
			     << packetS->daddr_().getString() << " : " << packetS->dest_().getString() 
			     << endl;
			*/
			if(index_call_ip_port_other_side < 0) {
				index_call_ip_port_other_side = this->get_index_by_ip_port(find_by_dest ? packetS->saddr_() : packetS->daddr_(),
											   find_by_dest ? packetS->source_() : packetS->dest_(),
											   true);
			}
			if(index_call_ip_port_other_side < 0 &&
			   callerd_confirm_rtp_by_both_sides_sdp[iscaller_index(iscaller)]) {
				if(opt_rtp_check_both_sides_by_sdp == 1) {
					*disable_save = true;
				}
				return(false);
			}
			if(index_call_ip_port_other_side >= 0) {
				callerd_confirm_rtp_by_both_sides_sdp[iscaller_index(iscaller)] = true;
				confirm_both_sides_by_sdp = true;
				for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
					if(rtp_i->iscaller == iscaller && !rtp_i->confirm_both_sides_by_sdp) {
						rtp_i->stopReadProcessing = true;
					}
				}
			}
		}
		
		// if previouse RTP streams are present it should be filled by silence to keep it in sync
		if(iscaller) {
			audioBufferData[0].clearLast();
			if(lastcallerrtp) {
				lastcallerrtp->jt_tail(packetS->header_pt);
			}
		} else { 
			audioBufferData[1].clearLast();
			if(lastcalledrtp) {
				lastcalledrtp->jt_tail(packetS->header_pt);
			}
		}
		
		/*
		if(index_call_ip_port_find_side >= 0) {
			unsigned counter_active_streams_with_eq_sdp_node = 0;
			for(int i = 0; i < ssrc_n; i++) {
				if(curSSRC != rtp_stream_by_index(i)->ssrc &&
				   getTimeUS(rtp_stream_by_index(i)->header_ts) > getTimeUS(packetS->header_pt->ts) - 1000000 &&
				   rtp_stream_by_index(i)->iscaller == iscaller &&
				   rtp_stream_by_index(i)->index_call_ip_port == index_call_ip_port_find_side) {
					++counter_active_streams_with_eq_sdp_node;
					cout << "multiple streams with eq sdp node" << endl
					     << " - new stream " << hex << curSSRC << dec << endl
					     << " - old stream " << hex << rtp_stream_by_index(i)->ssrc << dec << endl;
				}
			}
		}
		*/
		
		RTP *rtp_new = new FILE_LINE(1001) RTP(packetS->sensor_id_(), packetS->sensor_ip);
		rtp_new->ssrc_index = rtp_size();
		if(exists_srtp && 
		   (opt_srtp_rtp_decrypt || 
		    (opt_srtp_rtp_dtls_decrypt && (exists_srtp_fingerprint || !exists_srtp_crypto_config)) ||
		    (opt_srtp_rtp_audio_decrypt && (flags & FLAG_SAVEAUDIO)) || 
		    opt_saveRAW || opt_savewav_force)) {
			int index_call_ip_port_by_src = get_index_by_ip_port(packetS->saddr_(), packetS->source_());
			if(index_call_ip_port_by_src < 0) {
				index_call_ip_port_by_src = get_index_by_ip_port(packetS->saddr_(), packetS->source_(), true);
			}
			if(index_call_ip_port_by_src < 0 && iscaller_is_set(iscaller)) {
				index_call_ip_port_by_src = get_index_by_iscaller(iscaller_inv_index(iscaller));
			}
			if(index_call_ip_port_by_src >= 0 && 
			   this->ip_port[index_call_ip_port_by_src].srtp) {
				if(!rtp_secure_map[index_call_ip_port_by_src]) {
					rtp_secure_map[index_call_ip_port_by_src] = 
						new FILE_LINE(0) RTPsecure(opt_use_libsrtp ? RTPsecure::mode_libsrtp : RTPsecure::mode_native,
									   this, index_call_ip_port_by_src);
					if(sverb.log_srtp_callid && !log_srtp_callid) {
						syslog(LOG_INFO, "SRTP exists in call %s", call_id.c_str());
						log_srtp_callid = true;
					}
				}
				rtp_new->setSRtpDecrypt(rtp_secure_map[index_call_ip_port_by_src]);
			}
		}
		rtp_new->call_owner = this;
		rtp_new->iscaller = iscaller; 
		rtp_new->find_by_dest = find_by_dest;
		rtp_new->ok_other_ip_side_by_sip = typeIs(MGCP) || 
						   (typeIs(SKINNY_NEW) ? opt_rtpfromsdp_onlysip_skinny : opt_rtpfromsdp_onlysip) ||
						   this->checkKnownIP_inSipCallerdIP(find_by_dest ? packetS->saddr_() : packetS->daddr_()) ||
						   (this->get_index_by_ip_port(find_by_dest ? packetS->saddr_() : packetS->daddr_(), find_by_dest ? packetS->source_() : packetS->dest_()) >= 0 &&
						    this->checkKnownIP_inSipCallerdIP(find_by_dest ? packetS->daddr_() : packetS->saddr_()));
		rtp_new->confirm_both_sides_by_sdp = confirm_both_sides_by_sdp;
		rtp_new->sdp_flags = sdp_flags;
		if(rtp_cur[iscaller]) {
			rtp_prev[iscaller] = rtp_cur[iscaller];
		}
		rtp_cur[iscaller] = rtp_new; 
		
		if(opt_dscp) {
			rtp_new->dscp = packetS->header_ip_()->get_tos() >> 2;
			if(sverb.dscp) {
				cout << "rtpdscp " << (int)(packetS->header_ip_()->get_tos()>>2) << endl;
			}
		}

		char graph_extension[100];
		snprintf(graph_extension, sizeof(graph_extension), "%d.graph%s", rtp_new->ssrc_index, opt_gzipGRAPH == FileZipHandler::gzip ? ".gz" : "");
		string graph_pathfilename = get_pathfilename(tsf_graph, graph_extension);
		strcpy(rtp_new->gfilename, graph_pathfilename.c_str());
		if((flags & FLAG_SAVEGRAPH) && !sverb.disable_save_graph) {
			rtp_new->graph.auto_open(tsf_graph, graph_pathfilename.c_str());
		}
		
		char ird_extension[100];
		snprintf(ird_extension, sizeof(ird_extension), "i%d", !iscaller);
		string ird_pathfilename = get_pathfilename(tsf_audio, ird_extension);
		strncpy(rtp_new->basefilename, ird_pathfilename.c_str(), 1023);
		rtp_new->basefilename[1023] = 0;

		rtp_new->index_call_ip_port = index_call_ip_port_find_side;
		if(rtp_new->index_call_ip_port >= 0) {
			rtp_new->index_call_ip_port_by_dest = find_by_dest;
			evProcessRtpStream(rtp_new->index_call_ip_port, rtp_new->index_call_ip_port_by_dest, 
					   packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), packetS->header_pt->ts.tv_sec);
		}
		if(opt_rtpmap_by_callerd) {
			unsigned index_rtpmap = isFillRtpMap(iscaller) ? iscaller : !iscaller;
			memcpy(rtp_new->rtpmap, rtpmap[index_rtpmap], MAX_RTPMAP * sizeof(RTPMAP));
			rtpmap_used_flags[index_rtpmap] = true;
		} else {
			if(rtp_new->index_call_ip_port >= 0 && isFillRtpMap(rtp_new->index_call_ip_port)) {
				memcpy(rtp_new->rtpmap, rtpmap[rtp_new->index_call_ip_port], MAX_RTPMAP * sizeof(RTPMAP));
				rtpmap_used_flags[rtp_new->index_call_ip_port] = true;
				if(index_call_ip_port_other_side >= 0 && isFillRtpMap(index_call_ip_port_other_side)) {
					memcpy(rtp_new->rtpmap_other_side, rtpmap[index_call_ip_port_other_side], MAX_RTPMAP * sizeof(RTPMAP));
					rtpmap_used_flags[index_call_ip_port_other_side] = true;
				}
			} else {
				for(int j = 0; j < 2; j++) {
					int index_ip_port_first_for_callerd = getFillRtpMapByCallerd(j ? !iscaller : iscaller);
					if(index_ip_port_first_for_callerd >= 0) {
						memcpy(rtp_new->rtpmap, rtpmap[index_ip_port_first_for_callerd], MAX_RTPMAP * sizeof(RTPMAP));
						rtpmap_used_flags[index_ip_port_first_for_callerd] = true;
						break;
					}
				}
			}
		}

		u_int32_t datalen = packetS->datalen_();
		if(rtp_new->read((u_char*)packetS->data_(), packetS->header_ip_(), &datalen, packetS->header_pt, packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(),
				 packetS->sensor_id_(), packetS->sensor_ip, ifname)) {
			rtp_read_rslt = true;
			if(stream_in_multiple_calls) {
				rtp_new->stream_in_multiple_calls = true;
			}
		}
		if(opt_rtp_stream_analysis_params) {
			rtp_new->rtp_stream_analysis_output();
		}
		packetS->set_datalen_(datalen);
		rtp_new->prev_sport = packetS->source_();
		rtp_new->prev_dport = packetS->dest_();
		if(sverb.check_is_caller_called) printf("new rtp[%p] ssrc[%x] seq[%u] saddr[%s] dport[%u] iscaller[%u]\n", rtp_new, curSSRC, rtp_new->seq, packetS->saddr_().getString().c_str(), packetS->dest_().getPort(), rtp_new->iscaller);
		rtp_new->ssrc = rtp_new->ssrc2 = curSSRC;
		rtp_new->payload2 = curpayload;

		//set codec
		if(curpayload >= 96 && curpayload <= 127) {
			for(int i = 0; i < MAX_RTPMAP; i++) {
				if(rtp_new->rtpmap[i].is_set() && curpayload == rtp_new->rtpmap[i].payload) {
					rtp_new->codec = rtp_new->rtpmap[i].codec;
					rtp_new->frame_size = rtp_new->rtpmap[i].frame_size;
					if(rtp_new->rtpmap[i].is_set() && rtp_new->rtpmap[i].codec == PAYLOAD_TELEVENT) {
						if (!enable_save_dtmf_pcap(this)) {
							*disable_save = true;
						}
						if (opt_saverfc2833) {
							*record_dtmf = true;
						}
					}
				}
			}
		} else {
			rtp_new->codec = curpayload;
			if(curpayload == PAYLOAD_ILBC) {
				for(int i = 0; i < MAX_RTPMAP; i++) {
					if(rtp_new->rtpmap[i].is_set() && curpayload == rtp_new->rtpmap[i].payload) {
						rtp_new->frame_size = rtp_new->rtpmap[i].frame_size;
					}
				}
			}
    }
		
		if(iscaller) {
			lastcallerrtp = rtp_new;
		} else {
			lastcalledrtp = rtp_new;
		}
		
		add_rtp_stream(rtp_new);
		
	}
	
	return(rtp_read_rslt);
}

void 
Call::read_dtls(struct packet_s *packetS) {
	if(!dtls) {
		dtls = new FILE_LINE(0) cDtls;
	}
	dtls->processHandshake(packetS->saddr_(), packetS->source_(),
			       packetS->daddr_(), packetS->dest_(),
			       (u_char*)packetS->data_(), packetS->datalen_());
}

void
Call::_save_rtp(packet_s *packetS, s_sdp_flags_base sdp_flags, char enable_save_packet, bool record_dtmf, u_int8_t forceVirtualUdp) {
	extern int opt_fax_create_udptl_streams;
	extern int opt_fax_dup_seq_check;
	if(opt_fax_create_udptl_streams) {
		if(sdp_flags.is_image() && packetS->okDataLenForUdptl()) {
			sUdptlDumper *udptlDumper;
			sStreamId streamId(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
			map<sStreamId, sUdptlDumper*>::iterator iter = udptlDumpers.find(streamId);
			if(iter == udptlDumpers.end()) {
				udptlDumper = new FILE_LINE(0) sUdptlDumper();
				udptlDumper->dumper = new FILE_LINE(0) PcapDumper();
				extern pcap_t *global_pcap_handle;
				string filename = "udptl_stream_" + 
						  packetS->saddr_().getString() + "_" + 
						  intToString(packetS->source_().getPort()) + "_" + 
						  packetS->daddr_().getString() + "_" + 
						  intToString(packetS->dest_().getPort()) + ".pcap";
				udptlDumper->dumper->open(tsf_na, (get_pathname(tsf_rtp) + "/" + filename).c_str(), global_pcap_handle, DLT_EN10MB);
				udptlDumpers[streamId] = udptlDumper;
			} else {
				udptlDumper = iter->second;
			}
			bool enableDump;
			if(packetS->isRtp()) {
				enableDump = false;
			} else {
				enableDump = true;
				UDPTLFixedHeader *udptl = (UDPTLFixedHeader*)packetS->data_();
				if(udptl->data_field) {
					unsigned seq = htons(udptl->sequence);
					if(seq <= udptlDumper->last_seq) {
						enableDump = false;
					}
					udptlDumper->last_seq = seq;
				}
			}
			if(enableDump) {
				sll_header *header_sll = NULL;
				ether_header *header_eth = NULL;
				u_int16_t header_ip_offset = 0;
				u_int16_t protocol = 0;
				u_int16_t vlan = VLAN_UNSET;
				if(parseEtherHeader(packetS->dlt, (u_char*)packetS->packet, 
						    header_sll, header_eth, NULL,
						    header_ip_offset, protocol, vlan)) {
					pcap_pkthdr *header = NULL;
					u_char *packet = NULL;
					u_int16_t old_ether_type = 0;
					ether_header eth_header_tmp;
					if(packetS->dlt == DLT_EN10MB) {
						old_ether_type = header_eth->ether_type;
					} else {
						memset(&eth_header_tmp, 0, sizeof(eth_header_tmp));
						header_eth = &eth_header_tmp;
					}
					header_eth->ether_type = htons(0x800);
					unsigned dataLen = // eliminate padding
						htons(((udphdr2*)(packetS->packet + packetS->header_ip_offset + packetS->header_ip_()->get_hdr_size()))->len) - 
						sizeof(udphdr2);
					createSimpleUdpDataPacket(sizeof(ether_header), &header, &packet,
								  (u_char*)header_eth, (u_char*)packetS->data_(), dataLen,
								  packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(),
								  packetS->header_pt->ts.tv_sec, packetS->header_pt->ts.tv_usec);
					udptlDumper->dumper->dump(header, packet, DLT_EN10MB);
					if(packetS->dlt == DLT_EN10MB) {
						header_eth->ether_type = old_ether_type;
					}
					delete [] packet;
					delete header;
					enable_save_packet = false;
				}
			}
		}
	} else if(opt_fax_dup_seq_check) {
		if(sdp_flags.is_image() && packetS->isUdptlOkDataLen()) {
			UDPTLFixedHeader *udptl = (UDPTLFixedHeader*)packetS->data_();
			if(udptl->data_field) {
				unsigned seq = htons(udptl->sequence);
				d_item<vmIPport> last_udptl_seq_index = d_item<vmIPport>(vmIPport(packetS->saddr_(), packetS->source_()), vmIPport(packetS->daddr_(), packetS->dest_()));
				if(seq <= this->last_udptl_seq[last_udptl_seq_index]) {
					enable_save_packet = false;
				}
				this->last_udptl_seq[last_udptl_seq_index] = seq;
			}
		}
	} else {
		if(sdp_flags.is_image() && packetS->isUdptlOkDataLen()) {
			UDPTLFixedHeader *udptl = (UDPTLFixedHeader*)packetS->data_();
			if(udptl->data_field) {
				this->exists_udptl_data = true;
			}
		}
	}
	if(enable_save_packet) {
		if((this->silencerecording || (this->flags & (sdp_flags.is_video() ? FLAG_SAVERTP_VIDEO_HEADER : FLAG_SAVERTPHEADER))) && 
		   !this->isfax && !record_dtmf) {
			if(packetS->isStun()) {
				save_packet(this, packetS, _t_packet_rtp, forceVirtualUdp);
			} else if(packetS->datalen_() >= RTP_FIXED_HEADERLEN &&
			   packetS->header_pt->caplen > (unsigned)(packetS->datalen_() - RTP_FIXED_HEADERLEN)) {
				unsigned int tmp_u32 = packetS->header_pt->caplen;
				packetS->header_pt->caplen = min(packetS->header_pt->caplen - (packetS->datalen_() - RTP_FIXED_HEADERLEN),
								 packetS->dataoffset_() + RTP_FIXED_HEADERLEN);
				save_packet(this, packetS, _t_packet_rtp);
				packetS->header_pt->caplen = tmp_u32;
			}
		} else if((this->flags & (sdp_flags.is_video() ? FLAG_SAVERTP_VIDEO : FLAG_SAVERTP)) || this->isfax || record_dtmf) {
			save_packet(this, packetS, _t_packet_rtp, forceVirtualUdp);
		}
	}
}

void Call::stoprecording() {
	if(recordstopped == 0) {

		this->flags = 0;
		this->pcap.remove();
		this->pcapSip.remove();
		this->pcapRtp.remove();

		this->recordstopped = 1;
		if(verbosity >= 1) {
			syslog(LOG_ERR,"Call %s was stopped due to dtmf or norecord sip header. ", this->get_pathfilename(tsf_main).c_str());
		}
	} else {
		if(verbosity >= 1) {
			syslog(LOG_ERR,"Call %s was stopped before. Ignoring now. ", this->get_pathfilename(tsf_main).c_str());
		}
	}
}
		
int convertALAW2WAV(const char *fname1, char *fname3, int maxsamplerate) {
	unsigned char *bitstream_buf1;
	int16_t buf_out1;
	unsigned char *p1;
	unsigned char *f1;
	long file_size1;

	//TODO: move it to main program to not init it overtimes or make alaw_init not reinitialize
	alaw_init();
 
	int inFrameSize = 1;
	int outFrameSize = 2;
 
	FILE *f_in1 = fopen(fname1, "r");
	if(!f_in1) {
		syslog(LOG_ERR,"File [%s] cannot be opened for read", fname1);
		return -1;
	}

	FILE *f_out = fopen(fname3, "a"); // THIS HAS TO BE APPEND!
	if(f_out) {
		spooldir_file_chmod_own(f_out);
	} else {
		fclose(f_in1);
		syslog(LOG_ERR,"File [%s] cannot be opened for write", fname3);
		return -1;
	}
	char f_out_buffer[32768];
	setvbuf(f_out, f_out_buffer, _IOFBF, 32768);
 
	// wav_write_header(f_out);
 
	fseek(f_in1, 0, SEEK_END);
	file_size1 = ftell(f_in1);
	fseek(f_in1, 0, SEEK_SET);
 
	bitstream_buf1 = new FILE_LINE(1002) unsigned char[file_size1];
	if(!bitstream_buf1) {
		syslog(LOG_ERR,"Cannot malloc bitsream_buf1[%ld]", file_size1);
		fclose(f_in1);
		fclose(f_out);
		return 1;
	}
	fread(bitstream_buf1, file_size1, 1, f_in1);
	p1 = bitstream_buf1;
	f1 = bitstream_buf1 + file_size1;
	while(p1 < f1) {
		buf_out1 = ALAW(*p1);
		p1 += inFrameSize;
		for(int i = 0; i < maxsamplerate / 8000; i++) {
			fwrite(&buf_out1, outFrameSize, 1, f_out);
		}
	}
 
	// wav_update_header(f_out);
 
	delete [] bitstream_buf1;
 
	fclose(f_out);
	fclose(f_in1);

	return 0;
}
 
int convertULAW2WAV(const char *fname1, char *fname3, int maxsamplerate) {
	unsigned char *bitstream_buf1;
	int16_t buf_out1;
	unsigned char *p1;
	unsigned char *f1;
	long file_size1;
 
	//TODO: move it to main program to not init it overtimes or make ulaw_init not reinitialize
	ulaw_init();
 
	int inFrameSize = 1;
	int outFrameSize = 2;
 
	FILE *f_in1 = fopen(fname1, "r");
	if(!f_in1) {
		syslog(LOG_ERR,"File [%s] cannot be opened for read", fname1);
		return -1;
	}
		
	FILE *f_out = fopen(fname3, "a"); // THIS HAS TO BE APPEND!
	if(f_out) {
		spooldir_file_chmod_own(f_out);
	} else {
		fclose(f_in1);
		syslog(LOG_ERR,"File [%s] cannot be opened for write", fname3);
		return -1;
	}
	char f_out_buffer[32768];
	setvbuf(f_out, f_out_buffer, _IOFBF, 32768);
 
	// wav_write_header(f_out);
 
	fseek(f_in1, 0, SEEK_END);
	file_size1 = ftell(f_in1);
	fseek(f_in1, 0, SEEK_SET);
 
	bitstream_buf1 = new FILE_LINE(1003) unsigned char[file_size1];
	if(!bitstream_buf1) {
		fclose(f_in1);
		fclose(f_out);
		syslog(LOG_ERR,"Cannot malloc bitsream_buf1[%ld]", file_size1);
		return 1;
	}
	fread(bitstream_buf1, file_size1, 1, f_in1);
	p1 = bitstream_buf1;
	f1 = bitstream_buf1 + file_size1;
 
	while(p1 < f1) {
		buf_out1 = ULAW(*p1);
		p1 += inFrameSize;
		for(int i = 0; i < maxsamplerate / 8000; i++) {
			fwrite(&buf_out1, outFrameSize, 1, f_out);
		}
	}
 
	// wav_update_header(f_out);
 
	if(bitstream_buf1)
		delete [] bitstream_buf1;
 
	fclose(f_out);
	fclose(f_in1);
 
	return 0;
}

float
Call::mos_lqo(char *deg, int samplerate) {
	char buf[4092];
	switch(samplerate) {
	case 8000:
		snprintf(buf, 4091, "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin %s +%d %s %s", opt_mos_lqo_bin, samplerate, opt_mos_lqo_ref, deg);
		break;
	case 16000:
		snprintf(buf, 4091, "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin %s +%d %s %s", opt_mos_lqo_bin, samplerate, opt_mos_lqo_ref16, deg);
		break;
	default:
		if(verbosity > 0) syslog(LOG_INFO, "MOS_LQO unsupported samplerate:[%d] only 8000 and 16000 are supported\n", samplerate);
		return -1;
	}
	buf[4091] = 0;
	if(verbosity > 1) syslog(LOG_INFO, "MOS_LQO CMD [%s]\n", buf);
	string out;
	out = pexec(buf);
	if(out == "ERROR") {
		syslog(LOG_ERR, "mos_lqo exec failed: %s\n", buf);
		return -1;
	}
	float mos, mos_lqo;

	char *tmp = new FILE_LINE(1004) char[out.length() + 1];
	char *a = NULL;

	strcpy(tmp, out.c_str());

	a = strstr(tmp, "P.862 Prediction (Raw MOS, MOS-LQO):");

	if(a) {
		if(sscanf(a, "P.862 Prediction (Raw MOS, MOS-LQO):  = %f   %f", &mos, &mos_lqo) != EOF) {
			if(mos_lqo > 0 and mos_lqo < 5) {
				return mos_lqo;
			}
			//printf("mos[%f] [%f]\n", mos, mos_lqo);
		}
	}

	delete [] tmp;
	
//	cout << out << "\n";
	return -1;
}

void
Call::HandleHold(bool sdp_sendonly, bool sdp_sendrecv) {

	if (hold_status) {
		if (sdp_sendrecv or (!sdp_sendrecv and !sdp_sendonly)) {
			hold_status = false;
			ostringstream o;
			o << "-" << duration_s() << ",";
			hold_times.append(o.str());
		}
	} else {
		if (sdp_sendonly) {
			hold_status = true;
			ostringstream o;
			o << "+" << duration_s() << ",";
			hold_times.append(o.str());
		}
	}
	return;
}


class cWavMix {
public:
	class cWav {
	public:
		cWav(u_int64_t start, unsigned bytes_per_sample, unsigned samplerate);
		~cWav();
		bool load(const char *wavFileName, unsigned samplerate_dst);
		u_int64_t getEnd(bool withoutEndSilence) {
			return(start + 
			       get_length_samples(withoutEndSilence) * 1000000ull / samplerate);
		}
		u_int32_t get_length_samples(bool withoutEndSilence) {
			return(withoutEndSilence ? length_data_samples() : length_samples);
		}
		u_int32_t length_data_samples() {
			return(length_samples - end_silence_samples);
		}
		bool is_silence_sample(u_int32_t i) {
			for(unsigned j = 0; j < bytes_per_sample; j++) {
				if(wav_buffer[i * bytes_per_sample + j]) {
					return(false);
				}
			}
			return(true);
		}
		d_u_int32_t is_in_silence_interval(u_int32_t i) {
			for(unsigned j = 0; j < silence_samples_intervals.size(); j++) {
				if(i >= silence_samples_intervals[j][0] &&
				   i <= silence_samples_intervals[j][1]) {
					return(silence_samples_intervals[j]);
				}
			}
			return(d_u_int32_t());
		}
		d_u_int32_t get_next_silence_interval(u_int32_t i) {
			for(unsigned j = 0; j < silence_samples_intervals.size(); j++) {
				if(i < silence_samples_intervals[j][0]) {
					return(silence_samples_intervals[j]);
				}
			}
			return(d_u_int32_t());
		}
	private:
		u_int64_t start;
		unsigned bytes_per_sample;
		unsigned samplerate;
		u_char *wav_buffer;
		u_int32_t length_samples;
		u_int32_t end_silence_samples;
		bool use_in_mix;
		vector<d_u_int32_t> silence_samples_intervals;
	friend class cWavMix;
	};
public:
	cWavMix(unsigned bytes_per_sample, unsigned samplerate);
	~cWavMix();
	void setStartTime(u_int64_t start_time);
	bool addWav(const char *wavFileName, u_int64_t start,
		    unsigned bytes_per_sample = 0, unsigned samplerate = 0);
	void mixTo(const char *wavOutFileName, bool withoutEndSilence, bool withoutEndSilenceInRslt);
private:
	void mix(bool withoutEndSilence, bool withoutEndSilenceInRslt);
	void mix(cWav *wav, bool withoutEndSilence);
	u_int64_t getMinStartTime();
	u_int64_t getMaxEndTime(bool withoutEndSilence);
	u_int32_t getAllSamples(bool withoutEndSilence);
	cWav *getWavNoMix(bool withoutEndSilence);
private:
        list<cWav*> wavs;
	unsigned bytes_per_sample;
	unsigned samplerate;
	u_int64_t start_time;
	u_char *mix_buffer;
	u_int32_t mix_buffer_length_samples;
};

cWavMix::cWav::cWav(u_int64_t start, unsigned bytes_per_sample, unsigned samplerate) {
	this->start = start;
	this->bytes_per_sample = bytes_per_sample;
	this->samplerate = samplerate;
	this->wav_buffer = NULL;
	this->length_samples = 0;
	this->end_silence_samples = 0;
	this->use_in_mix = false;
}

cWavMix::cWav::~cWav() {
	if(wav_buffer) {
		delete [] wav_buffer;
	}
}

bool cWavMix::cWav::load(const char *wavFileName, unsigned samplerate_dst) {
	u_int32_t fileSize = GetFileSize(wavFileName);
	if(!fileSize) {
		return(false);
	}
	FILE *file = fopen(wavFileName, "r");
	if(!file) {
		return(false);
	}
	u_int32_t wav_buffer_pos = 0;
	unsigned samplerate_orig = samplerate;
	if(samplerate_dst > samplerate) {
		u_int32_t wav_buffer_length = (u_int64_t)fileSize * samplerate_dst / samplerate;
		wav_buffer = new FILE_LINE(0) u_char[wav_buffer_length + 100];
		unsigned read_buffer_length = 16 * 1024;
		u_char *read_buffer = new FILE_LINE(0) u_char[read_buffer_length];
		u_int32_t read_pos = 0;
		u_int32_t readLength;
		while((readLength = fread(read_buffer, 1, read_buffer_length, file)) > 0) {
			for(u_int32_t i = 0; i < readLength; i++) {
				wav_buffer[wav_buffer_pos++] = read_buffer[i];
				if(!((i + 1) % bytes_per_sample)) {
					while((u_int64_t)(read_pos + i) * samplerate_dst / samplerate > wav_buffer_pos) {
						for(int j = bytes_per_sample - 1; j >= 0; j--) {
							wav_buffer[wav_buffer_pos++] = read_buffer[i - j];
						}
					}
				}
				if(wav_buffer_pos >= wav_buffer_length) {
					break;
				}
			}
			read_pos += readLength;
			if(wav_buffer_pos >= wav_buffer_length) {
				break;
			}
		}
		delete [] read_buffer;
		samplerate = samplerate_dst;
	} else {
		wav_buffer = new FILE_LINE(0) u_char[fileSize];
		u_int32_t readLength;
		while((readLength = fread(wav_buffer + wav_buffer_pos, 1, min(fileSize - wav_buffer_pos, (u_int32_t)1024 * 16), file)) > 0) {
			wav_buffer_pos += readLength;
			if(wav_buffer_pos >= fileSize) {
				break;
			}
		}
	}
	fclose(file);
	if(wav_buffer_pos > 0) {
		length_samples = wav_buffer_pos / bytes_per_sample;
	} else {
		delete [] wav_buffer;
		wav_buffer = NULL;
		return(false);
	}
	while(end_silence_samples < length_samples) {
		u_int32_t check_pos = (length_samples - end_silence_samples - 1) * bytes_per_sample;
		bool silence = true;
		for(unsigned i = 0; i < bytes_per_sample; i++) {
			if(wav_buffer[check_pos + i]) {
				silence = false;
				break;
			}
		}
		if(silence) {
			++end_silence_samples;
		} else {
			break;
		}
	}
	for(u_int32_t i = 0; i < length_data_samples(); i++) {
		if(is_silence_sample(i)) {
			u_int32_t j = i;
			while(j < length_data_samples() - 1 && is_silence_sample(j + 1)) {
				++j;
			}
			if(j > i) {
				if(j - i > samplerate) {
					silence_samples_intervals.push_back(d_u_int32_t(i, j));
				}
				i = j;
			}
		}
	}
	if(sverb.wavmix) {
		cout << "load wav"
		     << " " << wavFileName
		     << " start " << start
		     << " samplerate " << samplerate_orig
		     << " samplerate_dst " << samplerate_dst
		     << " length_samples " << length_samples << " " << ((float)length_samples/samplerate)
		     << " end_silence_samples " << end_silence_samples << " " << ((float)end_silence_samples/samplerate)
		     << endl;
		for(unsigned i = 0; i < silence_samples_intervals.size(); i++) {
			cout << "si "
			     << silence_samples_intervals[i][0] << " " << ((float)silence_samples_intervals[i][0]/samplerate)
			     << " - " << silence_samples_intervals[i][1] << " " << ((float)silence_samples_intervals[i][1]/samplerate)
			     << endl;
		}
	}
	return(true);
}

cWavMix::cWavMix(unsigned bytes_per_sample, unsigned samplerate) {
	this->bytes_per_sample = bytes_per_sample;
	this->samplerate = samplerate;
	this->start_time = 0;
	this->mix_buffer = NULL;
	this->mix_buffer_length_samples = 0;
}

cWavMix::~cWavMix() {
	while(wavs.size()) {
		list<cWav*>::iterator iter = wavs.begin();
		cWav *wav = *iter;
		delete wav;
		wavs.erase(iter);
	}
	if(mix_buffer) {
		delete [] mix_buffer;
	}
}

void cWavMix::setStartTime(u_int64_t start_time) {
	this->start_time = start_time;
}

bool cWavMix::addWav(const char *wavFileName, u_int64_t start,
		     unsigned bytes_per_sample, unsigned samplerate) {
	cWav *wav = new FILE_LINE(0) cWav(start,
					  bytes_per_sample ? bytes_per_sample : this->bytes_per_sample, 
					  samplerate ? samplerate : this->samplerate);
	if(wav->load(wavFileName, this->samplerate)) {
		wavs.push_back(wav);
		return(true);
	} else {
		delete wav;
		return(false);
	}
}

void cWavMix::mixTo(const char *wavOutFileName, bool withoutEndSilence, bool withoutEndSilenceInRslt) {
	mix(withoutEndSilence, withoutEndSilenceInRslt);
	if(mix_buffer_length_samples) {
		FILE *file = fopen(wavOutFileName, "w");
		if(file) {
			u_int32_t pos = 0;
			while(pos < (mix_buffer_length_samples * bytes_per_sample)) {
				size_t writeLength = fwrite(mix_buffer + pos, 1, min(mix_buffer_length_samples * bytes_per_sample - pos, (u_int32_t)1024 * 16), file);
				pos += writeLength;
			}
			fclose(file);
		}
	}
}

void cWavMix::mix(bool withoutEndSilence, bool withoutEndSilenceInRslt) {
	mix_buffer_length_samples = getAllSamples(withoutEndSilenceInRslt);
	if(!mix_buffer_length_samples) {
		return;
	}
	mix_buffer = new FILE_LINE(0) u_char[mix_buffer_length_samples * bytes_per_sample];
	memset(mix_buffer, 0, mix_buffer_length_samples * bytes_per_sample);
	cWav *wav;
	while((wav = getWavNoMix(withoutEndSilence)) != NULL) {
		mix(wav, withoutEndSilence);
		wav->use_in_mix = true;
	}
}

void cWavMix::mix(cWav *wav, bool withoutEndSilence) {
	if(sverb.wavmix) {
		cout << "mix " << wav->silence_samples_intervals.size() << endl;
	}
	u_int64_t startTime = getMinStartTime();
	u_int32_t startSamples = 0;
	int32_t offsetSamples = 0;
	if(startTime > wav->start) {
		startSamples = (startTime - wav->start) * samplerate / 1000000ull;
		offsetSamples = -startSamples;
	} else if(wav->start > startTime) {
		offsetSamples = (wav->start - startTime) * samplerate / 1000000ull;
	}
	u_int32_t lengthSamples = wav->get_length_samples(withoutEndSilence);
	d_u_int32_t silence_interval = wav->is_in_silence_interval(startSamples);
	if(!silence_interval.isSet()) {
		silence_interval = wav->get_next_silence_interval(startSamples);
	}
	if(sverb.wavmix && silence_interval.isSet()) {
		 cout << "first si " << silence_interval[0] << " - " << silence_interval[1] << endl;
	}
	for(u_int32_t i = startSamples; i < lengthSamples; i++) {
		if(i + offsetSamples < mix_buffer_length_samples) {
			if(silence_interval.isSet() && silence_interval.isIn(i)) {
				i = silence_interval[1];
				silence_interval = wav->get_next_silence_interval(i + 1);
				if(sverb.wavmix && silence_interval.isSet()) {
					cout << "next si " << silence_interval[0] << " - " << silence_interval[1] << endl;
				}
			} else {
				for(unsigned j = 0; j < bytes_per_sample; j++) {
					mix_buffer[(i + offsetSamples) * bytes_per_sample + j] = wav->wav_buffer[i * bytes_per_sample + j];
				}
			}
		}
	}
}

u_int64_t cWavMix::getMinStartTime() {
	if(this->start_time) {
		return(this->start_time);
	}
	u_int64_t minStartTime = 0;
	for(list<cWav*>::iterator iter = wavs.begin(); iter != wavs.end(); iter++) {
		if(minStartTime == 0 ||
		   (*iter)->start < minStartTime) {
			minStartTime = (*iter)->start;
		}
	}
	return(minStartTime);
}

u_int64_t cWavMix::getMaxEndTime(bool withoutEndSilence) {
	u_int64_t maxEndTime = 0;
	for(list<cWav*>::iterator iter = wavs.begin(); iter != wavs.end(); iter++) {
		if(maxEndTime == 0 ||
		   (*iter)->getEnd(withoutEndSilence) > maxEndTime) {
			maxEndTime = (*iter)->getEnd(withoutEndSilence);
		}
	}
	return(maxEndTime);
}

u_int32_t cWavMix::getAllSamples(bool withoutEndSilence) {
	u_int64_t startTime = getMinStartTime();
	u_int64_t endTime = getMaxEndTime(withoutEndSilence);
	if(startTime && endTime && startTime < endTime) {
		return((endTime - startTime) * samplerate / 1000000ull);
	}
	return(0);
}

cWavMix::cWav *cWavMix::getWavNoMix(bool withoutEndSilence) {
	u_int32_t max_length_samples = 0;
	cWav *wav_max_length_samples = NULL;
	for(list<cWav*>::iterator iter = wavs.begin(); iter != wavs.end(); iter++) {
		if(!(*iter)->use_in_mix &&
		   (max_length_samples == 0 ||
		    (*iter)->get_length_samples(withoutEndSilence) > max_length_samples)) {
			max_length_samples = (*iter)->get_length_samples(withoutEndSilence);
			wav_max_length_samples = *iter;
		}
	}
	return(wav_max_length_samples);
}


int
Call::convertRawToWav() {
	char cmd[4092];
	int cmd_len = sizeof(cmd) - 1;
	char wav0[1024] = "";
	char wav1[1024] = "";
	char out[1024];
	char rawInfo[1024];
	char line[1024];
	struct timeval tv0, tv1;
	FILE *pl;
	int ssrc_index, codec, frame_size;
	unsigned long int rawiterator;
	FILE *wav = NULL;
	int adir = 0;
	int bdir = 0;
	
	bool useWavMix = opt_saveaudio_wav_mix;
	if(useWavMix && connect_duration_s() > 3600) {
		int maxsamplerate = 0;
		for(int i = 0; i <= 1; i++) {
			/* open playlist */
			char rawinfo_extension[100];
			snprintf(rawinfo_extension, sizeof(rawinfo_extension), "i%d.rawInfo", i);
			strcpy_null_term(rawInfo, get_pathfilename(tsf_audio, rawinfo_extension).c_str());
			pl = fopen(rawInfo, "r");
			if(pl) {
				while(fgets(line, 256, pl)) {
					line[strlen(line)] = '\0'; // remove '\n' which is last character
					sscanf(line, "%d:%lu:%d:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &frame_size, &tv0.tv_sec, &tv0.tv_usec);
					int samplerate = 1000 * get_ticks_bycodec(codec);
					if(codec == PAYLOAD_G722) samplerate = 1000 * 16;
					if(maxsamplerate < samplerate) {
						maxsamplerate = samplerate;
					}
				}
				fclose(pl);
			}
		}
		if(connect_duration_s() * maxsamplerate * 2 > 512 * 1024 * 1024) {
			useWavMix = false;
		}
	}
	bool force_convert_raw_to_wav = this->call_id == string("conv-raw-info") &&
					!force_spool_path.empty();

	if(!force_convert_raw_to_wav) {
		bool okSelect = false;
		if(opt_saveaudio_filteripbysipip) {
			if(selectRtpStreams_bySipcallerip()) {
				okSelect = true;
			}
		}
		if(!useWavMix) {
			if(!okSelect) {
				this->selectRtpStreams();
				if(opt_saveaudio_filter_ext &&
				   (this->existsConcurenceInSelectedRtpStream(-1, 200) ||
				    TIME_US_TO_S(this->getLengthStreams_us()) >= duration_s() + 2)) {
					if(!selectRtpStreams_byMaxLengthInLink()) {
						this->selectRtpStreams();
					}
				}
			}
			this->setSkipConcurenceStreams(-1);
		}
	
		if(sverb.read_rtp || sverb.rtp_streams) {
			this->printSelectedRtpStreams(-1, false);
		}
	} else {
		DIR* dp = opendir(get_pathname(tsf_audio).c_str());
		if(dp) {
			dirent* de;
			while((de = readdir(dp)) != NULL) {
				if(de->d_type != 4 && string(de->d_name) != ".." && string(de->d_name) != ".") {
					if(strstr(de->d_name, ".i0.rawInfo") ||
					   strstr(de->d_name, ".i1.rawInfo")) {
						this->call_id = de->d_name;
						this->call_id.resize(this->call_id.length() - 11);
						strcpy_null_term(this->fbasename, this->call_id.c_str());
						this->fbasename[sizeof(this->fbasename) - 1] = 0;
						break;
					}
				}
			}
			closedir(dp);
		}
	}

	if(!(flags & FLAG_FORMATAUDIO_OGG)) {
		strcpy_null_term(out, get_pathfilename(tsf_audio, "wav").c_str());
	} else {
		strcpy_null_term(out, get_pathfilename(tsf_audio, "ogg").c_str());
	}

	/* caller direction */
	strcpy_null_term(rawInfo, get_pathfilename(tsf_audio, "i0.rawInfo").c_str());
	pl = fopen(rawInfo, "r");
	if(pl) {
		while(fgets(line, sizeof(line), pl)) {
			sscanf(line, "%d:%lu:%d:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &frame_size, &tv0.tv_sec, &tv0.tv_usec);
			if(!force_convert_raw_to_wav &&
			   (ssrc_index < 0 || ssrc_index >= rtp_size() || !rtp_stream_by_index(ssrc_index) || rtp_stream_by_index(ssrc_index)->skip)) {
				continue;
			}
			adir = 1;
			strcpy_null_term(wav0, get_pathfilename(tsf_audio, "i0.wav").c_str());
			break;
		}
		fclose(pl);
	}

	/* called direction */
	strcpy_null_term(rawInfo, get_pathfilename(tsf_audio, "i1.rawInfo").c_str());
	pl = fopen(rawInfo, "r");
	if(pl) {
		while(fgets(line, sizeof(line), pl)) {
			sscanf(line, "%d:%lu:%d:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &frame_size, &tv1.tv_sec, &tv1.tv_usec);
			if(!force_convert_raw_to_wav &&
			   (ssrc_index < 0 || ssrc_index >= rtp_size() || !rtp_stream_by_index(ssrc_index) || rtp_stream_by_index(ssrc_index)->skip)) {
				continue;
			}
			bdir = 1;
			strcpy_null_term(wav1, get_pathfilename(tsf_audio, "i1.wav").c_str());
			break;
		}
		fclose(pl);
	}

	if(adir == 0 && bdir == 0) {
		syslog(LOG_ERR, "PCAP file %s cannot be decoded to WAV probably missing RTP\n", get_pathfilename(tsf_sip).c_str());
		return 1;
	}
	
	u_int64_t minStartTime = 0;
	if(useWavMix) {
		if(opt_saveaudio_from_first_invite && !opt_saveaudio_from_rtp) {
			minStartTime = this->first_packet_time_us;
		}
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(!minStartTime ||
			   rtp_i->first_packet_time_us < minStartTime) {
				minStartTime = rtp_i->first_packet_time_us;
			}
		}
	}

	/* do synchronisation - calculate difference between start of both RTP direction and put silence to achieve proper synchronisation */
	if(!useWavMix && (adir && bdir)) {
		/* calculate difference in milliseconds */
		int msdiff = ast_tvdiff_ms(tv1, tv0);
		char *fileNameWav = msdiff < 0 ? wav0 : wav1;
		for(int passOpen = 0; passOpen < 2; passOpen++) {
			if(passOpen == 1) {
				char *pointToLastDirSeparator = strrchr(fileNameWav, '/');
				if(pointToLastDirSeparator) {
					*pointToLastDirSeparator = 0;
					spooldir_mkdir(fileNameWav);
					*pointToLastDirSeparator = '/';
				} else {
					break;
				}
			}
			wav = fopen(fileNameWav, "w");
			if(wav) {
				spooldir_file_chmod_own(fileNameWav);
				break;
			}
		}
		if(!wav) {
			syslog(LOG_ERR, "Cannot open %s or %s\n", wav0, wav1);
			return 1;
		}
		char wav_buffer[32768];
		setvbuf(wav, wav_buffer, _IOFBF, 32768);

		/* write silence of msdiff duration */
		short int zero = 0;
		int samplerate = 8000;
		switch(this->first_codec) {
			case PAYLOAD_SILK8:
				samplerate = 8000;
				break;
			case PAYLOAD_SILK12:
				samplerate = 12000;
				break;
			case PAYLOAD_SILK16:
				samplerate = 16000;
				break;
			case PAYLOAD_SILK24:
				samplerate = 24000;
				break;
			case PAYLOAD_ISAC16:
				samplerate = 16000;
				break;
			case PAYLOAD_ISAC32:
				samplerate = 32000;
				break;
			case PAYLOAD_VXOPUS8:
			case PAYLOAD_XOPUS8:
			case PAYLOAD_OPUS8:
				samplerate = 8000;
				break;
			case PAYLOAD_VXOPUS12:
			case PAYLOAD_XOPUS12:
			case PAYLOAD_OPUS12:
				samplerate = 12000;
				break;
			case PAYLOAD_VXOPUS16:
			case PAYLOAD_XOPUS16:
			case PAYLOAD_OPUS16:
				samplerate = 16000;
				break;
			case PAYLOAD_VXOPUS24:
			case PAYLOAD_XOPUS24:
			case PAYLOAD_OPUS24:
				samplerate = 24000;
				break;
			case PAYLOAD_VXOPUS48:
			case PAYLOAD_XOPUS48:
			case PAYLOAD_OPUS48:
				samplerate = 48000;
				break;
			case PAYLOAD_G722:
			case PAYLOAD_G722116:
				samplerate = 16000;
				break;
			case PAYLOAD_G722132:
				samplerate = 32000;
				break;
			case PAYLOAD_AMRWB:
				samplerate = 16000;
				break;
		}
		for(int i = 0; i < (abs(msdiff) / 20) * samplerate / 50; i++) {
			fwrite(&zero, 1, 2, wav);
		}
		fclose(wav);
		/* end synchronisation */
	}

	int maxsamplerate = 0;

	/* get max sample rate */
	int samplerate = 8000;
	for(int i = 0; i <= 1; i++) {
		if(i == 0 and adir == 0) continue;
		if(i == 1 and bdir == 0) continue;

		/* open playlist */
		char rawinfo_extension[100];
		snprintf(rawinfo_extension, sizeof(rawinfo_extension), "i%d.rawInfo", i);
		strcpy_null_term(rawInfo, get_pathfilename(tsf_audio, rawinfo_extension).c_str());
		pl = fopen(rawInfo, "r");
		if(pl) {
			while(fgets(line, 256, pl)) {
				line[strlen(line)] = '\0'; // remove '\n' which is last character
				sscanf(line, "%d:%lu:%d:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &frame_size, &tv0.tv_sec, &tv0.tv_usec);
				samplerate = 1000 * get_ticks_bycodec(codec);
				if(codec == PAYLOAD_G722) samplerate = 1000 * 16;
				if(maxsamplerate < samplerate) {
					maxsamplerate = samplerate;
				}
			}
			fclose(pl);
		}
	}

	/* process all files in playlist for each direction */
	for(int i = 0; i <= 1; i++) {
		char *wav = NULL;
		if(i == 0 and adir == 0) continue;
		if(i == 1 and bdir == 0) continue;
		wav = i == 0 ? wav0 : wav1;

		/* open playlist */
		char rawinfo_extension[100];
		snprintf(rawinfo_extension, sizeof(rawinfo_extension), "i%d.rawInfo", i);
		strcpy_null_term(rawInfo, get_pathfilename(tsf_audio, rawinfo_extension).c_str());
		pl = fopen(rawInfo, "r");
		if(!pl) {
			syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
			return 1;
		}
		// get max sample rate 
		list<raws_t> raws;
		struct timeval lasttv;
		lasttv.tv_sec = 0;
		lasttv.tv_usec = 0;
		int iter = 0;
		unsigned int last_ssrc_index = 0;
		long long last_size = 0;
		unsigned int unknown_codec_counter = 0;
		/* 
			read rawInfo file where there are stored raw files (rtp streams) 
			if any of such stream has same SSRC as previous stream and it starts at the same time with 500ms tolerance that stream is eliminated (it is probably duplicate stream)
		*/
		while(fgets(line, 256, pl)) {
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &frame_size, &tv0.tv_sec, &tv0.tv_usec);
			char raw_extension[1024];
			snprintf(raw_extension, sizeof(raw_extension), "i%d.%d.%lu.%d.%ld.%ld.raw", i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);
			string raw_pathfilename = this->get_pathfilename(tsf_audio, raw_extension);
			samplerate = 1000 * get_ticks_bycodec(codec);
			if(codec == PAYLOAD_G722) samplerate = 1000 * 16;
			if(!force_convert_raw_to_wav &&
			   (ssrc_index < 0 || ssrc_index >= rtp_size() ||
			    last_ssrc_index >= (unsigned)rtp_size())) {
				syslog(LOG_NOTICE, "ignoring rtp stream - bad ssrc_index[%i] or last_ssrc_index[%i] ssrc_n[%i]; call [%s] stream[%s] ssrc[%x] ssrc/last[%x]", 
				       ssrc_index, last_ssrc_index, 
				       rtp_size(), fbasename, raw_pathfilename.c_str(), 
				       ssrc_index >= rtp_size() ? 0 : rtp_stream_by_index(ssrc_index)->ssrc,
				       last_ssrc_index >= (unsigned)rtp_size() ? 0 : rtp_stream_by_index(last_ssrc_index)->ssrc);
				if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
			} else {
				struct raws_t rawl;
				rawl.ssrc_index = ssrc_index;
				rawl.rawiterator = rawiterator;
				rawl.tv.tv_sec = tv0.tv_sec;
				rawl.tv.tv_usec = tv0.tv_usec;
				rawl.codec = codec;
				rawl.frame_size = frame_size;
				rawl.filename = raw_pathfilename.c_str();
				if(iter > 0) {
					if(!force_convert_raw_to_wav &&
					   (rtp_stream_by_index(ssrc_index)->ssrc == rtp_stream_by_index(last_ssrc_index)->ssrc and
					    rtp_stream_by_index(ssrc_index)->codec == rtp_stream_by_index(last_ssrc_index)->codec and
					    abs(ast_tvdiff_ms(tv0, lasttv)) < 200 and
					    abs((long)rtp_stream_by_index(ssrc_index)->stats.received - (long)rtp_stream_by_index(last_ssrc_index)->stats.received) < max(rtp_stream_by_index(ssrc_index)->stats.received, rtp_stream_by_index(last_ssrc_index)->stats.received) * 0.02 and
					    last_size > 10000)) {
						// ignore this raw file it is duplicate 
						if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
						if(verbosity > 1) syslog(LOG_NOTICE, "A ignoring duplicate stream [%s] ssrc[%x] ssrc[%x] ast_tvdiff_ms(tv0, lasttv)=[%d]", raw_pathfilename.c_str(), rtp_stream_by_index(last_ssrc_index)->ssrc, rtp_stream_by_index(ssrc_index)->ssrc, ast_tvdiff_ms(tv0, lasttv));
					} else {
						if(!force_convert_raw_to_wav &&
						   rtp_stream_by_index(rawl.ssrc_index)->skip) {
							if(verbosity > 1) syslog(LOG_NOTICE, "B ignoring duplicate stream [%s] ssrc[%x] ssrc[%x] skip==1", raw_pathfilename.c_str(), rtp_stream_by_index(last_ssrc_index)->ssrc, rtp_stream_by_index(ssrc_index)->ssrc);
							if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
						} else {
							raws.push_back(rawl);
						}
					}
				} else {
					if(force_convert_raw_to_wav ||
					   !rtp_stream_by_index(rawl.ssrc_index)->skip) {
						raws.push_back(rawl);
					} else {
						if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
						if(verbosity > 1) syslog(LOG_NOTICE, "C ignoring duplicate stream [%s] ssrc[%x] ssrc[%x] ast_tvdiff_ms(lasttv, tv0)=[%d]", raw_pathfilename.c_str(), rtp_stream_by_index(last_ssrc_index)->ssrc, rtp_stream_by_index(ssrc_index)->ssrc, ast_tvdiff_ms(lasttv, tv0));
					}
				}
				lasttv.tv_sec = tv0.tv_sec;
				lasttv.tv_usec = tv0.tv_usec;
				last_ssrc_index = ssrc_index;
				iter++;
				last_size = GetFileSize(raw_pathfilename.c_str());
			}
		}
		fclose(pl);
		
		cWavMix *wavMix = NULL;
		if(useWavMix) {
			wavMix = new FILE_LINE(0) cWavMix(2, maxsamplerate);
			if(opt_saveaudio_afterconnect && !opt_saveaudio_from_rtp && this->connect_time_us > minStartTime) {
				minStartTime = this->connect_time_us;
			}
			wavMix->setStartTime(minStartTime);
		}

		for (std::list<raws_t>::const_iterator rawf = raws.begin(), end = raws.end(); rawf != end; ++rawf) {
			if(wavMix) {
				unlink(wav);
			}
			switch(rawf->codec) {
			case PAYLOAD_PCMA:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMA to WAV ssrc[%x] wav[%s] index[%u]\n", rtp_stream_by_index(rawf->ssrc_index)->ssrc, wav, rawf->ssrc_index);
				convertALAW2WAV(rawf->filename.c_str(), wav, maxsamplerate);
				samplerate = max(8000, maxsamplerate);
				break;
			case PAYLOAD_PCMU:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMU to WAV ssrc[%x] wav[%s] index[%u]\n", rtp_stream_by_index(rawf->ssrc_index)->ssrc, wav, rawf->ssrc_index);
				convertULAW2WAV(rawf->filename.c_str(), wav, maxsamplerate);
				samplerate = max(8000, maxsamplerate);
				break;
		/* following decoders are not included in free version. Please contact support@voipmonitor.org */
			case PAYLOAD_G722:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g722 \"%s\" \"%s\" 64000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g722 \"%s\" \"%s\" 64000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.722 to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.722 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_G7221:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s siren \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-siren \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 32000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.7221 to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.7221 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_G722116:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s siren \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-siren \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.7221 to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.7221 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_G722132:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s siren \"%s\" \"%s\" 32000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-siren \"%s\" \"%s\" 32000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 32000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.7221c to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.7221 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_GSM:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s gsm \"%s\" \"%s\"", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-gsm \"%s\" \"%s\"", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting GSM to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_G729:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g729 \"%s\" \"%s\"", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g729 \"%s\" \"%s\"", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.729 to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_G723:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g723 \"%s\" \"%s\"", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g723 \"%s\" \"%s\"", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.723 to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_ILBC:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s ilbc \"%s\" \"%s\" %d", opt_keycheck, rawf->filename.c_str(), wav, frame_size ? frame_size : 30);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-ilbc \"%s\" \"%s\" %d", rawf->filename.c_str(), wav, frame_size ? frame_size : 30);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting iLBC to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_SPEEX:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s speex \"%s\" \"%s\"", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-speex \"%s\" \"%s\"", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting speex to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_SILK8:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 8000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 8000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK8 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK12:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 12000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 12000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 12000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK12 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK24:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 24000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 24000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK16 to WAV.\n");
				samplerate = 24000;
				system(cmd);
				break;
			case PAYLOAD_ISAC16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s isac \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-isac \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting ISAC16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_ISAC32:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s isac \"%s\" \"%s\" 32000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-isac \"%s\" \"%s\" 32000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 32000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting ISAC32 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS8:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 8000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 8000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS8 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS12:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 12000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 12000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 12000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS12 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS24:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 24000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 24000", rawf->filename.c_str(), wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 24000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS24 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS48:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 48000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 48000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 48000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS48 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_AMR:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s amrnb \"%s\" \"%s\" 8000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-amrnb \"%s\" \"%s\" 8000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting AMRNB[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_AMRWB:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s amrwb \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-amrwb \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting AMRWB[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_G72616:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g726 \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g726 \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.726-16[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_G72624:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g726 \"%s\" \"%s\" 24000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g726 \"%s\" \"%s\" 24000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.726-24[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_G72632:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g726 \"%s\" \"%s\" 32000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g726 \"%s\" \"%s\" 32000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.726-32[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_G72640:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g726 \"%s\" \"%s\" 40000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g726 \"%s\" \"%s\" 40000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.726-40[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_AAL2_G72616:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s aal2g726 \"%s\" \"%s\" 16000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-aal2g726 \"%s\" \"%s\" 16000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting AAL2 G.726-16[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_AAL2_G72624:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s aal2g726 \"%s\" \"%s\" 24000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-aal2g726 \"%s\" \"%s\" 24000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting AAL2 G.726-24[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_AAL2_G72632:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s aal2g726 \"%s\" \"%s\" 32000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-aal2g726 \"%s\" \"%s\" 32000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting AAL2 G.726-32[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			case PAYLOAD_AAL2_G72640:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s aal2g726 \"%s\" \"%s\" 40000", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-aal2g726 \"%s\" \"%s\" 40000", rawf->filename.c_str(), wav);
					cout << cmd << "\n";
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting AAL2 G.726-40[%s] to WAV[%s].\n", rawf->filename.c_str(), wav);
				system(cmd);
				break;
			default:
				if (++unknown_codec_counter > 2) {
					syslog(LOG_ERR, "Call [%s] has more than 2 parts with the unsupported codec [%s][%d].\n", rawf->filename.c_str(), codec2text(rawf->codec), rawf->codec);
				}
			}
			if(!sverb.noaudiounlink) unlink(rawf->filename.c_str());
			
			if(wavMix && file_exists(wav)) {
				wavMix->addWav(wav, getTimeUS(rawf->tv), 0, samplerate);
			}
		}
		if(!sverb.noaudiounlink) unlink(rawInfo);
		
		if(wavMix) {
			wavMix->mixTo(wav, true, false);
			delete wavMix;
			wavMix = NULL;
		}
		
		if(i == 0 and opt_mos_lqo and adir == 1 and flags & FLAG_RUNAMOSLQO and (samplerate == 8000 or samplerate == 16000)) {
			a_mos_lqo = mos_lqo(wav0, samplerate);
		}
		if(i == 1 and opt_mos_lqo and bdir == 1 and flags & FLAG_RUNBMOSLQO and (samplerate == 8000 or samplerate == 16000)) {
			b_mos_lqo = mos_lqo(wav1, samplerate);
		}

	}

	if(adir == 1 && bdir == 1) {
		// merge caller and called 
		if(!(flags & FLAG_FORMATAUDIO_OGG)) {
			if(!opt_saveaudio_reversestereo) {
				wav_mix(wav0, wav1, out, maxsamplerate, 0, opt_saveaudio_stereo);
			} else {
				wav_mix(wav1, wav0, out, maxsamplerate, 0, opt_saveaudio_stereo);
			}
		} else {
			if(!opt_saveaudio_reversestereo) {
				ogg_mix(wav0, wav1, out, opt_saveaudio_stereo, maxsamplerate, opt_saveaudio_oggquality, 0);
			} else {
				ogg_mix(wav1, wav0, out, opt_saveaudio_stereo, maxsamplerate, opt_saveaudio_oggquality, 0);
			}
		}
		if(!sverb.noaudiounlink) unlink(wav0);
		if(!sverb.noaudiounlink) unlink(wav1);
	} else if(adir == 1) {
		// there is only caller sound
		if(!(flags & FLAG_FORMATAUDIO_OGG)) {
			wav_mix(wav0, NULL, out, maxsamplerate, 0, opt_saveaudio_stereo);
		} else {
			ogg_mix(wav0, NULL, out, opt_saveaudio_stereo, maxsamplerate, opt_saveaudio_oggquality, 0);
		}
		if(!sverb.noaudiounlink) unlink(wav0);
	} else if(bdir == 1) {
		// there is only called sound
		if(!(flags & FLAG_FORMATAUDIO_OGG)) {
			wav_mix(wav1, NULL, out, maxsamplerate, 1, opt_saveaudio_stereo);
		} else {
			ogg_mix(wav1, NULL, out, opt_saveaudio_stereo, maxsamplerate, opt_saveaudio_oggquality, 1);
		}
		if(!sverb.noaudiounlink) unlink(wav1);
	}
	string tmp;
	tmp.append(out);
	addtofilesqueue(tsf_audio, tmp, 0);
	if(opt_cachedir[0] != '\0') {
		Call::_addtocachequeue(tmp);
	}
	// CURL hook
	if (strlen(opt_curl_hook_wav) > 0) {
		string url;
		url.append(opt_curl_hook_wav);
		string postData;
		postData.append("{ \"voipmonitor\": true");
		postData.append(", \"stereo\":");
		postData.append(useWavMix ? "false" : "true");
		postData.append(", \"wav_file_name_with_path\": \"");
		postData.append(out);
		postData.append("\", \"call_id\": \"");
		postData.append(this->call_id);
		postData.append("\" }\n");
		string getParams; // Not used actually
		SimpleBuffer responseBuffer;
		string error;
		s_get_url_response_params curl_params;

		if (!post_url_response((url + getParams).c_str(), &responseBuffer, &postData, &error, &curl_params)) {
			if(verbosity > 1) syslog(LOG_ERR, "FAIL: Send event to hook[%s] for call_id[%s], error[%s]\n", opt_curl_hook_wav, this->call_id.c_str(), error.c_str());
		} else {
			if(verbosity > 1) syslog(LOG_INFO, "SUCCESS: Send event to hook[%s] for call_id[%s], response[%s]\n", opt_curl_hook_wav, this->call_id.c_str(), (char*)responseBuffer);
		}
	}
	return 0;
}

bool Call::selectRtpStreams() {
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		rtp_i->skip = false;
	}
	// decide which RTP streams should be skipped 
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		Call *owner = (Call*)rtp_i->call_owner;
		if(!owner) continue;
		//check for SSRC duplicity  - walk all RTP 
		RTP *A = rtp_i;
		RTP *B = NULL;
		RTP *C = NULL;
		for(int k = 0; k < rtp_size(); k++) { RTP *rtp_k = rtp_stream_by_index(k);
			B = rtp_k;
			if((!B->had_audio or B->stats.received == 0) and B->tailedframes < 2) {
				if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] codec is comfortnoise received[%u] tailedframes[%u] had_audio[%u]\n", 
					B->ssrc, B->saddr.getString().c_str(), B->sport.getPort(), B->daddr.getString().c_str(), B->dport.getPort(), B->iscaller, k, B->stats.received, B->tailedframes, B->had_audio);
				B->skip = true;
			}

			if(A == B or A->skip or B->skip or A->stats.received < 50 or B->stats.received < 50) continue; // do not compare with ourself or already removed RTP or with RTP with <20 packets

			// check if A or B time overlaps - if not we cannot treat it as duplicate stream 
			u_int64_t Astart = A->first_packet_time_us;
			u_int64_t Astop = A->last_pcap_header_us;
			u_int64_t Bstart = B->first_packet_time_us;
			u_int64_t Bstop = B->last_pcap_header_us;
			if(((Bstart > Astart) and (Bstart > Astop)) or ((Astart > Bstart) and (Astart > Bstop))) {
				if(verbosity > 1) syslog(LOG_ERR, "Not removing SSRC[%x][%p] and SSRC[%x][%p] %" int_64_format_prefix "lu %" int_64_format_prefix "lu\n", A->ssrc, A, B->ssrc, B, Astart, Bstop);
				continue;
				
			}

			if(A->ssrc == B->ssrc) {
				if(A->daddr == B->daddr and A->saddr == B->saddr and A->sport == B->sport and A->dport == B->dport){
					// A and B have the same SSRC but both is identical ips and ports
					continue;
				}
				// found another stream with the same SSRC 

				if(owner->get_index_by_ip_port(A->daddr, A->dport) >= 0) {
					//A.daddr is in SDP
					if(owner->get_index_by_ip_port(B->daddr, B->dport) >= 0) {
						//B.daddr is also in SDP now we have to decide if A or B will be removed. Check if we remove B if there will be still B.dst in some other RTP stream 
						bool test = false;
						for(int l = 0; l < rtp_size(); i++) { RTP *rtp_l = rtp_stream_by_index(l);
							C = rtp_l;
							if(C->skip or C == B or C->codec != B->codec) continue; 
							if(B->daddr == C->daddr){
								// we have found another stream C with the same B.daddr so we can remove the stream B
								test = true;
								break;
							}
						}
						if(test) {
							B->skip = true;
							if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x][%p] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 0\n", 
								B->ssrc, B, B->saddr.getString().c_str(), B->sport.getPort(), B->daddr.getString().c_str(), B->dport.getPort(), B->iscaller, k);
						} else {
							// test is not true which means that if we remove B there will be no other stream with the B.daddr so we can remove A
							A->skip = true;
							if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x][%p] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 1\n", 
								A->ssrc, A, A->saddr.getString().c_str(), A->sport.getPort(), A->daddr.getString().c_str(), A->dport.getPort(), A->iscaller, k);
						}
					} else {
						// B.daddr is not in SDP but A.dst is in SDP - but lets check if removing B will not remove all caller/called streams 
						int caller_called = B->iscaller;
						bool test = false;
						for(int l = 0; l < rtp_size(); i++) { RTP *rtp_l = rtp_stream_by_index(l);
							C = rtp_l;
							if(C == B or C->skip) continue;
							if(C->iscaller == caller_called) {
								test = true;
							}
						}
						if(test) {
							// B can be removed because removing it will still leave some caller/called stream
							B->skip = 1;
							if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 2B\n", 
								B->ssrc, B->saddr.getString().c_str(), B->sport.getPort(), B->daddr.getString().c_str(), B->dport.getPort(), B->iscaller, k);
						} else {
							// B cannot be removed because the B is the last caller/called stream
							A->skip = 1;
							if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 2A\n", 
								A->ssrc, A->saddr.getString().c_str(), A->sport.getPort(), A->daddr.getString().c_str(), A->dport.getPort(), A->iscaller, k);
						}
					}
				} else {
					//A.daddr is not in SDP so we can remove that stream 
					A->skip = 1;
					if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 33\n", 
						A->ssrc, A->saddr.getString().c_str(), A->sport.getPort(), A->daddr.getString().c_str(), A->dport.getPort(), A->iscaller, k);
				}
			}
		}
	}
	return(true);
}

bool Call::selectRtpStreams_bySipcallerip() {
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		rtp_i->skip = false;
	}
	unsigned countSelectStreams = 0;
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if(rtp_i->saddr != this->sipcallerip[0] && rtp_i->daddr != this->sipcallerip[0]) {
			rtp_i->skip = true;
		} else {
			++countSelectStreams;
		}
	}
	if(!countSelectStreams) {
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			rtp_i->skip = false;
		}
	}
	return(countSelectStreams > 0);
}

struct selectRtpStreams_byMaxLengthInLink_sLink {
	selectRtpStreams_byMaxLengthInLink_sLink() {
		bad = false;
	}
	u_int64_t getLength(Call *call) {
		return(call->getLengthStreams_us(&streams_i));
	}
	list<int> streams_i;
	bool bad;
};
bool Call::selectRtpStreams_byMaxLengthInLink() {
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		rtp_i->skip = false;
	}
	map<d_item<vmIP>, selectRtpStreams_byMaxLengthInLink_sLink> links;
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		d_item<vmIP> linkIndex = d_item<vmIP>(MIN(rtp_i->saddr, rtp_i->daddr),
						      MAX(rtp_i->saddr, rtp_i->daddr));
		links[linkIndex].streams_i.push_back(i);
	}
	while(true) {
		unsigned max_count_streams = 0;
		for(map<d_item<vmIP>, selectRtpStreams_byMaxLengthInLink_sLink>::iterator iter = links.begin(); iter != links.end(); iter++) {
			if(!iter->second.bad &&
			   iter->second.streams_i.size() > max_count_streams) {
				max_count_streams = iter->second.streams_i.size();
			}
		}
		if(!max_count_streams) {
			break;
		}
		u_int64_t max_length = 0;
		d_item<vmIP> max_length_linkIndex;
		for(map<d_item<vmIP>, selectRtpStreams_byMaxLengthInLink_sLink>::iterator iter = links.begin(); iter != links.end(); iter++) {
			if(!iter->second.bad &&
			   iter->second.streams_i.size() == max_count_streams &&
			   iter->second.getLength(this) > max_length) {
				max_length = iter->second.getLength(this);
				max_length_linkIndex = iter->first;
			}
		}
		if(!max_length) {
			break;
		}
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			rtp_i->skip = true;
		}
		for(list<int>::iterator iter = links[max_length_linkIndex].streams_i.begin(); iter != links[max_length_linkIndex].streams_i.end(); iter++) {
			rtp_stream_by_index(*iter)->skip = false;
		}
		if(!this->existsConcurenceInSelectedRtpStream(-1, 200) &&
		   this->existsBothDirectionsInSelectedRtpStream()) {
			return(true);
		} else {
			links[max_length_linkIndex].bad = true;
		}
	}
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		rtp_i->skip = false;
	}
	return(false);
}

u_int64_t Call::getLengthStreams_us(list<int> *streams_i) {
	u_int64_t minStart = 0;
	u_int64_t maxEnd = 0;
	for(list<int>::iterator iter = streams_i->begin(); iter != streams_i->end(); ++iter) {
		if(!minStart ||
		   minStart > rtp_stream_by_index(*iter)->first_packet_time_us) {
			minStart = rtp_stream_by_index(*iter)->first_packet_time_us;
		}
		if(!maxEnd ||
		   maxEnd < rtp_stream_by_index(*iter)->last_pcap_header_us) {
			maxEnd = rtp_stream_by_index(*iter)->last_pcap_header_us;
		}
	}
	return(maxEnd - minStart);
}

u_int64_t Call::getLengthStreams_us() {
	list<int> streams_i;
	for(int i = 0; i < rtp_size(); i++) {
		streams_i.push_back(i);
	}
	return(getLengthStreams_us(&streams_i));
}

void Call::setSkipConcurenceStreams(int caller) {
	if(caller == -1) {
		setSkipConcurenceStreams(0);
		setSkipConcurenceStreams(1);
		return;
	}
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if(rtp_i->iscaller == caller && !rtp_i->skip) {
			u_int64_t a_start = rtp_i->first_packet_time_us;
			u_int64_t a_stop = rtp_i->last_pcap_header_us;
			u_int64_t a_length = a_stop - a_start;
			for(int j = 0; j < rtp_size(); j++) { RTP *rtp_j = rtp_stream_by_index(j);
				if(rtp_j != rtp_i && rtp_j->iscaller == caller && !rtp_j->skip &&
				   !rtp_i->eqAddrPort(rtp_j)) {
					u_int64_t b_start = rtp_j->first_packet_time_us;
					u_int64_t b_stop = rtp_j->last_pcap_header_us;
					u_int64_t b_length = b_stop - b_start;
					if(b_start > a_start && b_start < a_stop &&
					   a_length > 0 && b_length > 0 &&
					   a_length / b_length > 0.8 && a_length / b_length < 1.25 &&
					   b_start - a_start < a_length / 10) {
						rtp_j->skip = true;
					}
				}
			}
		}
	}
}

u_int64_t Call::getFirstTimeInRtpStreams_us(int caller, bool selected) {
	u_int64_t firstTime = 0;
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if((caller == -1 || rtp_i->iscaller == caller) &&
		   (!selected || !rtp_i->skip)) {
			if(!firstTime || rtp_i->first_packet_time_us < firstTime) {
				firstTime = rtp_i->first_packet_time_us;
			}
		}
	}
	return(firstTime);
}

void Call::printSelectedRtpStreams(int caller, bool selected) {
	u_int64_t firstTime = this->getFirstTimeInRtpStreams_us(caller, selected);
	for(int pass_caller = 1; pass_caller >= 0; pass_caller--) {
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if((caller == -1 || pass_caller == caller) && 
			   rtp_i->iscaller == pass_caller &&
			   (!selected || !rtp_i->skip)) {
				u_int64_t start = rtp_i->first_packet_time_us - firstTime;
				u_int64_t stop = rtp_i->last_pcap_header_us - firstTime;
				cout << hex << setw(10) << rtp_i->ssrc << dec << "   "
				     << iscaller_description(rtp_i->iscaller) << "   "
				     << setw(10) << (start / 1000000.) << " - "
				     << setw(10) << (stop / 1000000.) <<  "   "
				     << setw(15) << rtp_i->saddr.getString() << " -> " << setw(15) << rtp_i->daddr.getString() << "   "
				     << setw(10) << rtp_i->s->received <<  "   "
				     << (rtp_i->skip ? "SKIP" : "")
				     << endl;
			}
		}
	}
}

bool Call::existsConcurenceInSelectedRtpStream(int caller, unsigned tolerance_ms) {
	if(caller == -1) {
		return(existsConcurenceInSelectedRtpStream(0, tolerance_ms) ||
		       existsConcurenceInSelectedRtpStream(1, tolerance_ms));
	}
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if(rtp_i->iscaller == caller && !rtp_i->skip) {
			u_int64_t a_start = rtp_i->first_packet_time_us;
			u_int64_t a_stop = rtp_i->last_pcap_header_us;
			for(int j = 0; j < rtp_size(); j++) { RTP *rtp_j = rtp_stream_by_index(j);
				if(rtp_j != rtp_i && rtp_j->iscaller == caller && !rtp_j->skip &&
				   !rtp_i->eqAddrPort(rtp_j)) {
					u_int64_t b_start = rtp_j->first_packet_time_us;
					u_int64_t b_stop = rtp_j->last_pcap_header_us;
					if(!(b_start + tolerance_ms * 1000 > a_stop ||
					     a_start + tolerance_ms * 1000 > b_stop)) {
						return(true);
					}
				}
			}
		}
	}
	return(false);
}

bool Call::existsBothDirectionsInSelectedRtpStream() {
	bool existsCalllerDirection = false;
	bool existsCallledDirection = false;
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if(!rtp_i->skip) {
			if(rtp_i->iscaller) {
				existsCalllerDirection = true;
			} else {
				existsCallledDirection = true;
			}
		}
	}
	return(existsCalllerDirection && existsCallledDirection);
}

void Call::removeCallIdMap() {
	if(opt_call_id_alternative[0]) {
		map<string, Call*>::iterator callMAPIT;
		callMAPIT = ((Calltable*)calltable)->calls_listMAP.find(call_id);
		if(callMAPIT != ((Calltable*)calltable)->calls_listMAP.end()) {
			((Calltable*)calltable)->calls_listMAP.erase(callMAPIT);
		}
		if(call_id_alternative) {
			for(map<string, bool>::iterator iter = call_id_alternative->begin(); iter != call_id_alternative->end(); iter++) {
				callMAPIT = ((Calltable*)calltable)->calls_listMAP.find(iter->first);
				if(callMAPIT != ((Calltable*)calltable)->calls_listMAP.end()) {
					((Calltable*)calltable)->calls_listMAP.erase(callMAPIT);
				}
			}
		}
	}
}

void Call::removeMergeCalls() {
	if(isSetCallidMergeHeader()) {
		((Calltable*)calltable)->lock_calls_mergeMAP();
		mergecalls_lock();
		for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
			((Calltable*)calltable)->calls_mergeMAP.erase(it->first);
		}
		mergecalls_unlock();
		((Calltable*)calltable)->unlock_calls_mergeMAP();
	}
}

void Call::getValue(eCallField field, RecordArrayField *rfield) {
	switch(field) {
	case cf_callreference:
		rfield->set(this);
		break;
	case cf_callid:
		rfield->set(call_id.c_str());
		break;
	case cf_calldate:
		if(opt_time_precision_in_ms) {
			rfield->set(calltime_us(), RecordArrayField::tf_time_ms);
		} else {
			rfield->set(calltime_s(), RecordArrayField::tf_time);
		}
		break;
	case cf_calldate_num:
		rfield->set(calltime_s());
		break;
	case cf_lastpackettime:
		rfield->set(get_last_packet_time_s());
		break;
	case cf_duration:
		rfield->set(duration_active_s());
		break;
	case cf_connect_duration:
		rfield->set(connect_duration_active_s());
		break;
	case cf_caller:
		rfield->set(caller);
		break;
	case cf_called:
		rfield->set(called());
		break;
	case cf_caller_country:
		rfield->set(getCountryByPhoneNumber(caller, true).c_str());
		break;
	case cf_called_country:
		rfield->set(getCountryByPhoneNumber(called(), true).c_str());
		break;
	case cf_caller_international:
		rfield->set(!isLocalByPhoneNumber(caller));
		break;
	case cf_called_international:
		rfield->set(!isLocalByPhoneNumber(called()));
		break;
	case cf_callername:
		rfield->set(callername);
		break;
	case cf_callerdomain:
		rfield->set(caller_domain);
		break;
	case cf_calleddomain:
		rfield->set(called_domain());
		break;
	case cf_calleragent:
		rfield->set(a_ua);
		break;
	case cf_calledagent:
		rfield->set(b_ua);
		break;
	case cf_callerip:
		rfield->set(getSipcallerip(), RecordArrayField::tf_ip_n4);
		break;
	case cf_calledip:
		rfield->set(getSipcalledip(), RecordArrayField::tf_ip_n4);
		break;
	case cf_callerip_country:
		rfield->set(getCountryByIP(getSipcallerip(), true).c_str());
		break;
	case cf_calledip_country:
		rfield->set(getCountryByIP(getSipcalledip(), true).c_str());
		break;
	case cf_callerip_encaps:
		rfield->set(getSipcallerip_encaps(), RecordArrayField::tf_ip_n4);
		break;
	case cf_calledip_encaps:
		rfield->set(getSipcalledip_encaps(), RecordArrayField::tf_ip_n4);
		break;
	case cf_callerip_encaps_prot:
		rfield->set(getSipcallerip_encaps_prot());
		break;
	case cf_calledip_encaps_prot:
		rfield->set(getSipcalledip_encaps_prot());
		break;
	case cf_sipproxies:
		rfield->set(get_proxies_str().c_str());
		break;
	case cf_lastSIPresponseNum:
		rfield->set(lastSIPresponseNum);
		break;
	case cf_callercodec:
		rfield->set(last_callercodec);
		break;
	case cf_calledcodec:
		rfield->set(last_calledcodec);
		break;
	case cf_id_sensor:
		rfield->set(useSensorId);
		break;
	case cf_vlan:
		rfield->set(vlan);
		break;
	default:
		break;
	};
	if(lastcallerrtp) {
		switch(field) {
		case cf_rtp_src:
			rfield->set(lastcallerrtp->saddr, RecordArrayField::tf_ip_n4);
			break;
		case cf_rtp_dst:
			rfield->set(lastcallerrtp->daddr, RecordArrayField::tf_ip_n4);
			break;
		case cf_rtp_src_country:
			rfield->set(getCountryByIP(lastcallerrtp->saddr, true).c_str());
			break;
		case cf_rtp_dst_country:
			rfield->set(getCountryByIP(lastcallerrtp->daddr, true).c_str());
			break;
		case cf_src_mosf1:
			rfield->set(lastcallerrtp->last_interval_mosf1);
			break;
		case cf_src_mosf2:
			rfield->set(lastcallerrtp->last_interval_mosf2);
			break;
		case cf_src_mosAD:
			rfield->set(lastcallerrtp->last_interval_mosAD);
			break;
		case cf_src_jitter:
			rfield->set(round(lastcallerrtp->jitter));
			break;
		case cf_src_loss:
			if(lastcallerrtp->stats.received + lastcallerrtp->stats.lost) {
				rfield->set((double)lastcallerrtp->stats.lost / (lastcallerrtp->stats.received + lastcallerrtp->stats.lost) * 100.0);
			}
			break;
		case cf_src_loss_last10sec:
			rfield->set(lastcallerrtp->last_stat_loss_perc_mult10);
			break;
		default:
			break;
		}
	}
	if(lastcalledrtp) {
		switch(field) {
		case cf_dst_mosf1:
			rfield->set(lastcalledrtp->last_interval_mosf1);
			break;
		case cf_dst_mosf2:
			rfield->set(lastcalledrtp->last_interval_mosf2);
			break;
		case cf_dst_mosAD:
			rfield->set(lastcalledrtp->last_interval_mosAD);
			break;
		case cf_dst_jitter:
			rfield->set(round(lastcalledrtp->jitter));
			break;
		case cf_dst_loss:
			if(lastcalledrtp->stats.received + lastcalledrtp->stats.lost) {
				rfield->set((double)lastcalledrtp->stats.lost / (lastcalledrtp->stats.received + lastcalledrtp->stats.lost) * 100.0);
			}
			break;
		case cf_dst_loss_last10sec:
			rfield->set(lastcalledrtp->last_stat_loss_perc_mult10);
			break;
		default:
			break;
		}
	}
	if(!rfield->isSet()) {
		switch(field) {
		case cf_src_mosf1:
		case cf_src_mosf2:
		case cf_src_mosAD:
		case cf_dst_mosf1:
		case cf_dst_mosf2:
		case cf_dst_mosAD:
			rfield->set(45);
		default:
			break;
		}
	}
}

string Call::getJsonHeader() {
	string header = "[";
	for(unsigned i = 0; i < sizeof(callFields) / sizeof(callFields[0]); i++) {
		if(i) {
			header += ",";
		}
		header += '"' + string(callFields[i].fieldName) + '"';
	}
	if(custom_headers_cdr) {
		list<string> headers;
		custom_headers_cdr->getHeaders(&headers);
		for(list<string>::iterator iter = headers.begin(); iter != headers.end(); iter++) {
			header += ",\"" + *iter + '"';
		}
	}
	header += "]";
	return(header);
}

void Call::getRecordData(RecordArray *rec) {
	unsigned i;
	for(i = 0; i < sizeof(callFields) / sizeof(callFields[0]); i++) {
		getValue(callFields[i].fieldType, &rec->fields[i]);
	}
	if(custom_headers_cdr) {
		list<string> values;
		custom_headers_cdr->getValues(this, INVITE, &values);
		for(list<string>::iterator iter = values.begin(); iter != values.end(); iter++) {
			rec->fields[i++].set(iter->c_str());
		}
	}
}

string Call::getJsonData() {
	RecordArray rec(sizeof(callFields) / sizeof(callFields[0]));
	getRecordData(&rec);
	string data = rec.getJson();
	rec.free();
	return(data);
}

void Call::setRtpThreadNum() {
	if(typeIs(INVITE) && is_enable_rtp_threads() && num_threads_active > 0) {
		thread_num = get_index_rtp_read_thread_min_calls();
		if(thread_num < 0) {
			extern void lock_add_remove_rtp_threads();
			extern void unlock_add_remove_rtp_threads();
			lock_add_remove_rtp_threads();
			thread_num = gthread_num % num_threads_active;
			__sync_add_and_fetch(&rtp_threads[thread_num].calls, 1);
			unlock_add_remove_rtp_threads();
		}
		gthread_num++;
		extern int process_rtp_packets_distribute_threads_use;
		thread_num_rd = process_rtp_packets_distribute_threads_use ? gthread_num % process_rtp_packets_distribute_threads_use : 0;
	}
}

void Call::add_txt(u_int64_t time, eTxtType type, const char *txt, unsigned txt_length) {
	sTxt txt_item;
	txt_item.time = time;
	txt_item.txt = string(txt, txt_length);
	txt_item.type = type;
	txt_lock();
	this->txt.push_back(txt_item);
	txt_unlock();
}

void Call::getChartCacheValue(int type, double *value, string *value_str, bool *null, cCharts *chartsCache) {
	bool setNull = false;
	double v = 0;
	string v_str;
	switch(type) {
	case _chartType_total:
	case _chartType_count:
	case _chartType_cps:
	case _chartType_minutes:
	case _chartType_count_perc_short:
		v = 1;
		break;
	case _chartType_mos:
	case _chartType_mos_caller:
	case _chartType_mos_called:
	case _chartType_mos_xr_avg:
	case _chartType_mos_xr_avg_caller:
	case _chartType_mos_xr_avg_called:
	case _chartType_mos_xr_min:
	case _chartType_mos_xr_min_caller:
	case _chartType_mos_xr_min_called:
	case _chartType_mos_silence_avg:
	case _chartType_mos_silence_avg_caller:
	case _chartType_mos_silence_avg_called:
	case _chartType_mos_silence_min:
	case _chartType_mos_silence_min_caller:
	case _chartType_mos_silence_min_called:
	case _chartType_mos_lqo_caller:
	case _chartType_mos_lqo_called:
	case _chartType_packet_lost:
	case _chartType_packet_lost_caller:
	case _chartType_packet_lost_called:
	case _chartType_jitter:
	case _chartType_delay:
	case _chartType_rtcp_avgjitter:
	case _chartType_rtcp_maxjitter:
	case _chartType_rtcp_avgfr:
	case _chartType_rtcp_maxfr:
	case _chartType_rtcp_avgrtd:
	case _chartType_rtcp_maxrtd:
	case _chartType_rtcp_avgrtd_w:
	case _chartType_rtcp_maxrtd_w:
	case _chartType_silence:
	case _chartType_silence_caller:
	case _chartType_silence_called:
	case _chartType_silence_end:
	case _chartType_silence_end_caller:
	case _chartType_silence_end_called:
	case _chartType_clipping:
	case _chartType_clipping_caller:
	case _chartType_clipping_called:
		if(!rtpab[0] && !rtpab[1]) {
			setNull = true;
			break;
		}
		if(!rtpab[0] &&
		   (type == _chartType_mos_caller ||
		    type == _chartType_mos_xr_avg_caller ||
		    type == _chartType_mos_xr_min_caller ||
		    type == _chartType_mos_silence_avg_caller ||
		    type == _chartType_mos_silence_min_caller ||
		    type == _chartType_mos_lqo_caller ||
		    type == _chartType_packet_lost_caller ||
		    type == _chartType_silence_caller ||
		    type == _chartType_silence_end_caller ||
		    type == _chartType_clipping_caller)) {
			setNull = true;
			break;
		}
		if(!rtpab[1] &&
		   (type == _chartType_mos_called ||
		    type == _chartType_mos_xr_avg_called ||
		    type == _chartType_mos_xr_min_called ||
		    type == _chartType_mos_silence_avg_called ||
		    type == _chartType_mos_silence_min_called ||
		    type == _chartType_mos_lqo_called ||
		    type == _chartType_packet_lost_called ||
		    type == _chartType_silence_called ||
		    type == _chartType_silence_end_called ||
		    type == _chartType_clipping_called)) {
			setNull = true;
			break;
		}
		switch(type) {
		case _chartType_mos:
		case _chartType_mos_xr_avg:
		case _chartType_mos_xr_min:
		case _chartType_mos_silence_avg:
		case _chartType_mos_silence_min:;
			setNull = true;
			for(unsigned i = 0; i < 2; i++) {
				if(rtpab[i]) {
					double _v = 0; bool _null = false;
					switch(type) {
					case _chartType_mos:
						_v = rtpab[i]->mos_min_from_avg(&_null, opt_mosmin_f2);
						break;
					case _chartType_mos_xr_avg:
						_v = rtpab[i]->mos_xr_avg(&_null);
						break;
					case _chartType_mos_xr_min:
						_v = rtpab[i]->mos_xr_min(&_null);
						break;
					case _chartType_mos_silence_avg:
						_v = rtpab[i]->mos_silence_avg(&_null);
						break;
					case _chartType_mos_silence_min:
						_v = rtpab[i]->mos_silence_min(&_null);
						break;
					}
					if(!_null) {
						setNull = false;
						if(!v || _v < v) {
							v = _v;
						}
					}
				}
			}
			break;
		case _chartType_mos_caller:
			v = rtpab[0]->mos_min_from_avg(&setNull, opt_mosmin_f2);
			break;
		case _chartType_mos_called:
			v = rtpab[1]->mos_min_from_avg(&setNull, opt_mosmin_f2);
			break;
		case _chartType_mos_xr_avg_caller:
			v = rtpab[0]->mos_xr_avg(&setNull);
			break;
		case _chartType_mos_xr_avg_called:
			v = rtpab[1]->mos_xr_avg(&setNull);
			break;
		case _chartType_mos_xr_min_caller:
			v = rtpab[0]->mos_xr_min(&setNull);
			break;
		case _chartType_mos_xr_min_called:
			v = rtpab[1]->mos_xr_min(&setNull);
			break;
		case _chartType_mos_silence_avg_caller:
			v = rtpab[0]->mos_silence_avg(&setNull);
			break;
		case _chartType_mos_silence_avg_called:
			v = rtpab[1]->mos_silence_avg(&setNull);
			break;
		case _chartType_mos_silence_min_caller:
			v = rtpab[0]->mos_silence_min(&setNull);
			break;
		case _chartType_mos_silence_min_called:
			v = rtpab[1]->mos_silence_min(&setNull);
			break;
		case _chartType_mos_lqo_caller:
			if(a_mos_lqo > 0) {
				v = a_mos_lqo;
			} else {
				setNull = true;
			}
			break;
		case _chartType_mos_lqo_called:
			if(b_mos_lqo > 0) {
				v = b_mos_lqo;
			} else {
				setNull = true;
			}
			break;
		case _chartType_packet_lost:
		case _chartType_jitter:
			setNull = true;
			for(unsigned i = 0; i < 2; i++) {
				if(rtpab[i]) {
					double _v = 0; bool _null = false;
					switch(type) {
					case _chartType_packet_lost:
						_v = rtpab[i]->packet_loss(&_null);
						break;
					case _chartType_jitter:
						_v = rtpab[i]->jitter_avg(&_null);
						break;
					}
					if(!_null) {
						setNull = false;
						if(_v > v) {
							v = _v;
						}
					}
				}
			}
			break;
		case _chartType_packet_lost_caller:
			v = rtpab[0]->packet_loss(&setNull);
			break;
		case _chartType_packet_lost_called:
			v = rtpab[1]->packet_loss(&setNull);
			break;
		case _chartType_delay:
			setNull = true;
			for(unsigned i = 0; i < 2; i++) {
				if(rtpab[i]) {
					bool _null_s = false;
					bool _null_c = false;
					double _v_s = rtpab[i]->delay_sum(&_null_s);
					double _v_c = rtpab[i]->delay_cnt(&_null_c);
					if(!_null_s && !_null_c && _v_c != 0) {
						setNull = false;
						if(_v_s / _v_c > v) {
							v = _v_s / _v_c;
						}
					}
				}
			}
			/* xPDV v2
			setNull = true;
			if(connect_duration_s()) {
				for(unsigned i = 0; i < 2; i++) {
					if(rtpab[i]) {
						bool _null = false;
						double _v = rtpab[i]->delay_sum(&_null);
						if(!_null) {
							setNull = false;
							if(_v > v) {
								v = _v;
							}
						}
					}
				}
				if(!setNull) {
					v /= connect_duration_s();
				}
			}
			*/
			break;
		case _chartType_rtcp_avgjitter:
		case _chartType_rtcp_maxjitter:
		case _chartType_rtcp_avgfr:
		case _chartType_rtcp_maxfr:
		case _chartType_rtcp_avgrtd:
		case _chartType_rtcp_maxrtd:
		case _chartType_rtcp_avgrtd_w:
		case _chartType_rtcp_maxrtd_w:
			setNull = true;
			for(unsigned i = 0; i < 2; i++) {
				if(rtpab[i]) {
					double _v = 0; bool _null = false;
					switch(type) {
					case _chartType_rtcp_avgjitter:
						_v = rtpab[i]->jitter_rtcp_avg(&_null);
						break;
					case _chartType_rtcp_maxjitter:
						_v = rtpab[i]->jitter_rtcp_max(&_null);
						break;
					case _chartType_rtcp_avgfr:
						_v = rtpab[i]->fr_rtcp_avg(&_null);
						break;
					case _chartType_rtcp_maxfr:
						_v = rtpab[i]->fr_rtcp_max(&_null);
						break;
					case _chartType_rtcp_avgrtd:
						_v = rtpab[i]->rtcp.rtd_count ? (rtpab[i]->rtcp.rtd_sum * 1000 / 65536 / rtpab[i]->rtcp.rtd_count) : 0;
						break;
					case _chartType_rtcp_maxrtd:
						_v = rtpab[i]->rtcp.rtd_max * 1000 / 65536;
						break;
					case _chartType_rtcp_avgrtd_w:
						_v = rtpab[i]->rtcp.rtd_w_count ? (rtpab[i]->rtcp.rtd_w_sum / rtpab[i]->rtcp.rtd_w_count) : 0;
						break;
					case _chartType_rtcp_maxrtd_w:
						_v = rtpab[i]->rtcp.rtd_w_max;
						break;
					}
					if(!_null) {
						setNull = false;
						if(_v > v) {
							v = _v;
						}
					}
				}
			}
			break;
		case _chartType_silence:
		case _chartType_silence_caller:
		case _chartType_silence_called:
			{
			setNull = true;
			unsigned begin = type == _chartType_silence ? 1 :
					 type == _chartType_silence_caller ? 1 :
					 type == _chartType_silence_called ? 2 : 0;
			unsigned end = type == _chartType_silence ? 2 :
				       type == _chartType_silence_caller ? 1 :
				       type == _chartType_silence_called ? 2 : 0;
			for(unsigned i = begin; i <= end; i++) {
				double _v = 0;
				if(i == 1 && caller_silence + caller_noise > 0) {
					_v = caller_silence * 100. / (caller_silence + caller_noise);
					setNull = false;
					if(_v > v) {
						v = _v;
					}
				}
				if(i == 2 && called_silence + called_noise > 0) {
					_v = called_silence * 100. / (called_silence + called_noise);
					setNull = false;
					if(_v > v) {
						v = _v;
					}
				}
			}
			}
			break;
		case _chartType_silence_end:
		case _chartType_silence_end_caller:
		case _chartType_silence_end_called:
			{
			setNull = true;
			unsigned begin = type == _chartType_silence ? 1 :
					 type == _chartType_silence_caller ? 1 :
					 type == _chartType_silence_called ? 2 : 0;
			unsigned end = type == _chartType_silence ? 2 :
				       type == _chartType_silence_caller ? 1 :
				       type == _chartType_silence_called ? 2 : 0;
			for(unsigned i = begin; i <= end; i++) {
				double _v = 0;
				if(i == 1 && caller_lastsilence > 0) {
					_v = caller_lastsilence / 1000.;
					setNull = false;
					if(_v > v) {
						v = _v;
					}
				}
				if(i == 2 && called_lastsilence > 0) {
					_v = called_lastsilence / 1000;
					setNull = false;
					if(_v > v) {
						v = _v;
					}
				}
			}
			}
			break;
		case _chartType_clipping:
		case _chartType_clipping_caller:
		case _chartType_clipping_called:
			{
			setNull = true;
			unsigned begin = type == _chartType_silence ? 1 :
					 type == _chartType_silence_caller ? 1 :
					 type == _chartType_silence_called ? 2 : 0;
			unsigned end = type == _chartType_silence ? 2 :
				       type == _chartType_silence_caller ? 1 :
				       type == _chartType_silence_called ? 2 : 0;
			for(unsigned i = begin; i <= end; i++) {
				double _v = 0;
				if(i == 1 && caller_clipping_8k > 0) {
					_v = caller_clipping_8k / 3.;
					setNull = false;
					if(_v > v) {
						v = _v;
					}
				}
				if(i == 2 && called_clipping_8k > 0) {
					_v = called_clipping_8k / 3.;
					setNull = false;
					if(_v > v) {
						v = _v;
					}
				}
			}
			}
			break;
		}
		break;
	case _chartType_pdd:
		if(progress_time_us) {
			v = (progress_time_us - first_packet_time_us) / 1e6;
		} else {
			setNull = true;
		}
		break;
	case _chartType_acd_avg:
	case _chartType_acd:
	case _chartType_asr_avg:
	case _chartType_asr:
	case _chartType_ner_avg:
	case _chartType_ner:
		v = 1;
		break;
	case _chartType_sipResp:
		if(lastSIPresponseNum) {
			v = lastSIPresponseNum;
		} else {
			setNull = true;
		}
		break;
	case _chartType_sipResponse:
		if(lastSIPresponse[0]) {
			v_str = lastSIPresponse;
			if(chartsCache->maxLengthSipResponseText && v_str.length() > chartsCache->maxLengthSipResponseText) {
				v_str.resize(chartsCache->maxLengthSipResponseText);
			}
		} else {
			v_str = "000 not response";
		}
		break;
	case _chartType_sipResponse_base:
		{
		int lsr = lastSIPresponseNum;
		while(lsr >= 10) lsr /= 10;
		v = lsr;
		}
		break;
	case _chartType_codecs:
		if(payload_rslt >= 0) {
			v = payload_rslt;
		} else {
			setNull = true;
		}
		break;
	case _chartType_IP_src:
		v_str = getSipcallerip().getString();
		break;
	case _chartType_IP_dst:
		v_str = sipcalledip_rslt.getString();
		break;
	case _chartType_domain_src:
		v_str = caller_domain;
		break;
	case _chartType_domain_dst:
		v_str = called_domain();
		break;
	}
	if(setNull) {
		v = 0; 
		v_str = "";
	}
	if(value) *value = v;
	if(value_str) *value_str = v_str;
	if(null) {
		*null = setNull;
	}
}

void Call::getChartCacheValue(cDbTablesContent *tablesContent,
			      int type, double *value, string *value_str, bool *null, cCharts *chartsCache) {
	bool setNull = false;
	double v = 0;
	string v_str;
	switch(type) {
	case _chartType_total:
	case _chartType_count:
	case _chartType_cps:
	case _chartType_minutes:
	case _chartType_count_perc_short:
		v = 1;
		break;
	case _chartType_mos:
		v = tablesContent->getValue_float(_t_cdr, "mos_min_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_caller:
		v = tablesContent->getValue_float(_t_cdr, "a_mos_min_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		/*
		{
		const char *c[] = { "a_mos_f1_mult10", "a_mos_f2_mult10", "a_mos_adapt_mult10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		if(!setNull && v) v /= 10;
		}
		*/
		break;
	case _chartType_mos_called:
		v = tablesContent->getValue_float(_t_cdr, "b_mos_min_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		/*
		{
		const char *c[] = { "b_mos_f1_mult10", "b_mos_f2_mult10", "b_mos_adapt_mult10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		if(!setNull && v) v /= 10;
		}
		*/
		break;
	case _chartType_mos_xr_avg:
		{
		const char *c[] = { "a_mos_xr_mult10", "b_mos_xr_mult10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		if(!setNull && v) v /= 10;
		}
		break;
	case _chartType_mos_xr_avg_caller:
		v = tablesContent->getValue_float(_t_cdr, "a_mos_xr_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_xr_avg_called:
		v = tablesContent->getValue_float(_t_cdr, "b_mos_xr_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_xr_min:
		{
		const char *c[] = { "a_mos_xr_min_mult10", "b_mos_xr_min_mult10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		if(!setNull && v) v /= 10;
		}
		break;
	case _chartType_mos_xr_min_caller:
		v = tablesContent->getValue_float(_t_cdr, "a_mos_xr_min_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_xr_min_called:
		v = tablesContent->getValue_float(_t_cdr, "b_mos_xr_min_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_silence_avg:
		{
		const char *c[] = { "a_mos_silence_mult10", "b_mos_silence_mult10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		if(!setNull && v) v /= 10;
		}
		break;
	case _chartType_mos_silence_avg_caller:
		v = tablesContent->getValue_float(_t_cdr, "a_mos_silence_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_silence_avg_called:
		v = tablesContent->getValue_float(_t_cdr, "b_mos_silence_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_silence_min:
		{
		const char *c[] = { "a_mos_silence_min_mult10", "b_mos_silence_min_mult10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		if(!setNull && v) v /= 10;
		}
		break;
	case _chartType_mos_silence_min_caller:
		v = tablesContent->getValue_float(_t_cdr, "a_mos_silence_min_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_silence_min_called:
		v = tablesContent->getValue_float(_t_cdr, "b_mos_silence_min_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_lqo_caller:
		v = tablesContent->getValue_float(_t_cdr, "a_mos_lqo_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_mos_lqo_called:
		v = tablesContent->getValue_float(_t_cdr, "b_mos_lqo_mult10", true, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_packet_lost:
		v = tablesContent->getValue_float(_t_cdr, "packet_loss_perc_mult1000", false, &setNull);
		if(!setNull && v) v /= 1000;
		break;
	case _chartType_packet_lost_caller:
		v = tablesContent->getValue_float(_t_cdr, "a_packet_loss_perc_mult1000", false, &setNull);
		if(!setNull && v) v /= 1000;
		break;
	case _chartType_packet_lost_called:
		v = tablesContent->getValue_float(_t_cdr, "b_packet_loss_perc_mult1000", false, &setNull);
		if(!setNull && v) v /= 1000;
		break;
	case _chartType_jitter:
		v = tablesContent->getValue_float(_t_cdr, "jitter_mult10", false, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_delay:
		v = tablesContent->getValue_float(_t_cdr, "delay_avg_mult100", false, &setNull);
		if(!setNull && v) v /= 100;
		/* xPDV v2
		{
		bool delay_sum_null;
		double delay_sum = tablesContent->getValue_float(_t_cdr, "delay_sum", false, &delay_sum_null);
		bool connect_duration_null;
		double connect_duration = tablesContent->getValue_float(_t_cdr, "connect_duration", false, &connect_duration_null);
		if(!delay_sum_null && !connect_duration_null && connect_duration > 0) {
			v = delay_sum / connect_duration;
		} else {
			setNull = true;
		}
		}
		*/
		break;
	case _chartType_rtcp_avgjitter:
		v = tablesContent->getValue_float(_t_cdr, "rtcp_avgjitter_mult10", false, &setNull);
		if(!setNull && v) v /= 10;
		break;
	case _chartType_rtcp_maxjitter:
		{
		const char *c[] = { "a_rtcp_maxjitter", "b_rtcp_maxjitter", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, false, false, &setNull);
		}
		break;
	case _chartType_rtcp_avgfr:
		v = tablesContent->getValue_float(_t_cdr, "rtcp_avgfr_mult10", false, &setNull);
		if(!setNull && v) v /= (10 * 2.56);
		break;
	case _chartType_rtcp_maxfr:
		{
		const char *c[] = { "a_rtcp_maxfr", "b_rtcp_maxfr", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, false, false, &setNull);
		if(!setNull && v) v /= 2.56;
		}
		break;
	case _chartType_rtcp_maxrtd:
		{
		const char *c[] = { "a_rtcp_maxrtd_mult10", "b_rtcp_maxrtd_multi10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, false, false, &setNull);
		if(!setNull && v) v /= 10;
		}
		break;
	case _chartType_rtcp_avgrtd:
		{
		const char *c[] = { "a_rtcp_avgrtd_mult10", "b_rtcp_maxavg_mult10", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		if(!setNull && v) v /= 10;
		}
		break;
	case _chartType_rtcp_maxrtd_w:
		{
		const char *c[] = { "a_rtcp_maxrtd_w", "b_rtcp_maxrtd_w", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, false, false, &setNull);
		}
		break;
	case _chartType_rtcp_avgrtd_w:
		{
		const char *c[] = { "a_rtcp_avgrtd_w", "b_rtcp_maxavg_w", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, true, true, &setNull);
		}
		break;
	case _chartType_silence:
		{
		const char *c[] = { "caller_silence", "called_silence", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, false, false, &setNull);
		}
		break;
	case _chartType_silence_caller:
		v = tablesContent->getValue_float(_t_cdr, "caller_silence", false, &setNull);
		break;
	case _chartType_silence_called:
		v = tablesContent->getValue_float(_t_cdr, "called_silence", false, &setNull);
		break;
	case _chartType_silence_end:
		{
		const char *c[] = { "caller_silence_end", "called_silence_end", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, false, false, &setNull);
		}
		break;
	case _chartType_silence_end_caller:
		v = tablesContent->getValue_float(_t_cdr, "caller_silence_end", false, &setNull);
		break;
	case _chartType_silence_end_called:
		v = tablesContent->getValue_float(_t_cdr, "called_silence_end", false, &setNull);
		break;
	case _chartType_clipping:
		{
		const char *c[] = { "caller_clipping_div3", "called_clipping_div3", NULL };
		v = tablesContent->getMinMaxValue(_t_cdr, c, false, false, &setNull);
		if(!setNull && v) v *= 3;
		}
		break;
	case _chartType_clipping_caller:
		v = tablesContent->getValue_float(_t_cdr, "caller_clipping_div3", false, &setNull);
		if(!setNull && v) v *= 3;
		break;
	case _chartType_clipping_called:
		v = tablesContent->getValue_float(_t_cdr, "called_clipping_div3", false, &setNull);
		if(!setNull && v) v *= 3;
		break;
	case _chartType_pdd:
		v = tablesContent->getValue_float(_t_cdr, "progress_time", false, &setNull);
		break;
	case _chartType_acd_avg:
	case _chartType_acd:
	case _chartType_asr_avg:
	case _chartType_asr:
	case _chartType_ner_avg:
	case _chartType_ner:
		v = 1;
		break;
	case _chartType_sipResp:
		v = tablesContent->getValue_int(_t_cdr, "lastSIPresponseNum", false, &setNull);
		break;
	case _chartType_sipResponse:
		v_str = tablesContent->getValue_string(_t_cdr, "lastSIPresponse_id", &setNull);
		if(!setNull) {
			if(v_str[0]) {
				if(chartsCache->maxLengthSipResponseText && v_str.length() > chartsCache->maxLengthSipResponseText) {
					v_str.resize(chartsCache->maxLengthSipResponseText);
				}
			} else {
				v_str = "000 not response";
			}
		}
		break;
	case _chartType_sipResponse_base:
		v = tablesContent->getValue_int(_t_cdr, "lastSIPresponseNum", false, &setNull);
		if(!setNull && v) { while(v >= 10) v = (int)(v / 10); }
		break;
	case _chartType_codecs:
		v = tablesContent->getValue_int(_t_cdr, "payload", false, &setNull);
		break;
	case _chartType_IP_src:
		v_str = tablesContent->getValue_string(_t_cdr, "sipcallerip");
		break;
	case _chartType_IP_dst:
		v_str = tablesContent->getValue_string(_t_cdr, "sipcallerip");
		break;
	case _chartType_domain_src:
		v_str = tablesContent->getValue_string(_t_cdr, "caller_domain");
		break;
	case _chartType_domain_dst:
		v_str = tablesContent->getValue_string(_t_cdr, "called_domain");
		break;
	}
	if(setNull) {
		v = 0; 
		v_str = "";
	}
	if(value) *value = v;
	if(value_str) *value_str = v_str;
	if(null) {
		*null = setNull;
	}
}

bool Call::sqlFormulaOperandReplace(cEvalFormula::sValue *value, string *table, string *column, void *_callData, 
				    string *child_table, unsigned child_index, cEvalFormula::sOperandReplaceData *ord) {
	//sChartsCacheCallData *callData = (sChartsCacheCallData*)_callData;
 
	/*
	*value = cEvalFormula::sValue(1);
	//value->null();
	return(true);
	*/
 
	int table_enum = 0;
	int child_table_enum = 0;
	SqlDb_row::SqlDb_rowField *field = NULL;
	if(child_table) {
		if(*column == "cdr_id" || *column == "id") {
			*value = cEvalFormula::sValue(1);
			value->v_id = true;
			if(ord) {
				ord->u.s.column = 1;
			}
			return(true);
		}
		child_table_enum = getTableEnumIndex(child_table);
		if(child_table_enum >= _t_cdr_next && child_table_enum < _t_cdr_next_end) {
			table = child_table;
			child_table = NULL;
			table_enum = child_table_enum;
		} else {
			int column_index = 0;
			switch(child_table_enum) {
			case _t_cdr_proxy:
				{
				list<vmIP>::iterator iter = proxies.begin();
				for(unsigned i = 0; i < child_index; i++) {
					++iter;
				}
				if(*column == "dst") {
					*value = cEvalFormula::sValue(*iter);
					column_index = 1;
					return(true);
				}
				}
				break;
			case _t_cdr_sipresp:
				{
				list<sSipResponse>::iterator iter = SIPresponse.begin();
				for(unsigned i = 0; i < child_index; i++) {
					++iter;
				}
				if(*column == "lastsipresponse") {
					*value = cEvalFormula::sValue(iter->SIPresponse);
					column_index = 1;
					return(true);
				}
				}
				break;
			case _t_cdr_siphistory:
				{
				list<sSipHistory>::iterator iter = SIPhistory.begin();
				for(unsigned i = 0; i < child_index; i++) {
					++iter;
				}
				if(*column == "lastsipresponse") {
					*value = cEvalFormula::sValue(iter->SIPresponse);
					column_index = 1;
					return(true);
				}
				if(*column == "request") {
					*value = cEvalFormula::sValue(iter->SIPrequest);
					column_index = 2;
					return(true);
				}
				}
				break;
			case _t_cdr_rtp:
				if(*column == "saddr") {
					*value = cEvalFormula::sValue(rtp_stream_by_index(rtp_rows_indexes[child_index])->saddr);
					column_index = 1;
					return(true);
				}
				if(*column == "daddr") {
					*value = cEvalFormula::sValue(rtp_stream_by_index(rtp_rows_indexes[child_index])->daddr);
					column_index = 2;
					return(true);
				}
				if(*column == "sport") {
					*value = cEvalFormula::sValue(rtp_stream_by_index(rtp_rows_indexes[child_index])->sport.getPort());
					column_index = 3;
					return(true);
				}
				if(*column == "dport") {
					*value = cEvalFormula::sValue(rtp_stream_by_index(rtp_rows_indexes[child_index])->dport.getPort());
					column_index = 4;
					return(true);
				}
				if(*column == "received") {
					*value = cEvalFormula::sValue(rtp_stream_by_index(rtp_rows_indexes[child_index])->s->received);
					column_index = 5;
					return(true);
				}
				break;
			case _t_cdr_sdp:
				if(*column == "ip") {
					*value = cEvalFormula::sValue(sdp_rows_list[child_index].item1.ip);
					column_index = 1;
					return(true);
				}
				if(*column == "port") {
					*value = cEvalFormula::sValue(sdp_rows_list[child_index].item1.port);
					column_index = 2;
					return(true);
				}
				if(*column == "is_caller") {
					*value = cEvalFormula::sValue(sdp_rows_list[child_index].item2);
					column_index = 3;
					return(true);
				}
				break;
			}
			if(column_index && ord) {
				ord->u.s.child_table = child_table_enum;
				ord->u.s.child_index = child_index;
				ord->u.s.column = column_index;
			}
		}
	}
	if(*column == "id" && (table->empty() || *table == "cdr")) {
		*value = cEvalFormula::sValue(1);
		value->v_id = true;
		if(ord) {
			ord->u.s.column = 1;
		}
		return(true);
	}
	if(*column == "lastsipresponse") {
		*value = cEvalFormula::sValue(lastSIPresponse);
		if(ord) {
			ord->u.s.column = 2;
		}
		return(true);
	} else if(*column == "reason") {
		*value = cEvalFormula::sValue(table->find("sip") != string::npos ? reason_sip_text : reason_q850_text);
		if(ord) {
			ord->u.s.column = table->find("sip") != string::npos ? 3 : 4;
		}
		return(true);
	} else if(*column == "ua") {
		*value = cEvalFormula::sValue(table->find("a_ua") != string::npos ? a_ua : b_ua);
		if(ord) {
			ord->u.s.column = table->find("a_ua") != string::npos ? 5 : 6;
		}
		return(true);
	}
	if(!table_enum) {
		table_enum = getTableEnumIndex(table);
	}
	int indexField = 0;
	if(table_enum == _t_cdr) {
		field = this->cdr.getField(*column, &indexField);
	} else if(table_enum == _t_cdr_next) {
		field = this->cdr_next.getField(*column, &indexField);
	} else if(table_enum > _t_cdr_next && table_enum < _t_cdr_next_end) {
		int ch_index = table_enum - _t_cdr_next;
		if(ch_index > 0 && ch_index <= CDR_NEXT_MAX) {
			field = this->cdr_next_ch[ch_index - 1].getField(*column, &indexField);
		}
	} else if(table_enum == _t_cdr_country_code) {
		field = this->cdr_country_code.getField(*column, &indexField);
	}
	if(!field) {
		field = this->cdr.getField(*column, &indexField);
		if(field) {
			table_enum = _t_cdr;
		} else {
			field = this->cdr_next.getField(*column, &indexField);
			if(field) {
				table_enum = _t_cdr_next;
			} else {
				for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
					field = this->cdr_next_ch[i].getField(*column, &indexField);
					if(field) {
						table_enum = _t_cdr_next + i + 1;
						break;
					}
				}
			}
		}
		if(!field) {
			field = this->cdr_country_code.getField(*column, &indexField);
			if(field) {
				table_enum = _t_cdr_country_code;
			}
		}
	}
	if(field) {
		value->setFromField(field);
		if(ord) {
			ord->u.s.table = table_enum;
			ord->u.s.column = indexField + 1;
		}
		return(true);
	} else {
		value->null();
	}
	return(false);
}

bool Call::sqlFormulaOperandReplace(cDbTablesContent *tablesContent,
				    cEvalFormula::sValue *value, string *table, string *column, void *callData, 
				    string *child_table, unsigned child_index, cEvalFormula::sOperandReplaceData *ord) {
	int table_enum = 0;
	int child_table_enum = 0;
	sDbString *column_str = NULL;
	if(child_table) {
		if(*column == "cdr_id" || *column == "id") {
			*value = cEvalFormula::sValue(1);
			value->v_id = true;
			if(ord) {
				ord->u.s.column = 1;
			}
			return(true);
		}
 		child_table_enum = getTableEnumIndex(child_table);
		if(child_table_enum >= _t_cdr_next && child_table_enum < _t_cdr_next_end) {
			table = child_table;
			table_enum = child_table_enum;
		}
	}
	if(*column == "id" && (table->empty() || *table == "cdr")) {
		*value = cEvalFormula::sValue(1);
		value->v_id = true;
		if(ord) {
			ord->u.s.column = 1;
		}
		return(true);
	}
	unsigned table_enum_subst = 0;
	string column_subst;
	if(*column == "lastsipresponse") {
		if(child_table_enum) {
			table_enum_subst = child_table_enum;
			column_subst = "SIPresponse_id";
		} else {
			table_enum_subst = _t_cdr;
			column_subst = "lastSIPresponse_id";
		}
	} else if(*column == "request") {
		if(child_table_enum) {
			table_enum_subst = child_table_enum;
			column_subst = "SIPrequest_id";
		}
	} else if(*column == "reason") {
		table_enum_subst = _t_cdr;
		column_subst = table->find("sip") != string::npos ? "reason_sip_id" : "reason_q850_id";
	} else if(*column == "ua") {
		table_enum_subst = _t_cdr;
		column_subst = table->find("a_ua") != string::npos ? "a_ua_id" : "b_ua_id";
	} else if(child_table_enum) {
		table_enum_subst = child_table_enum;
	}
	int columnIndex = 0;
	if(table_enum_subst) {
		column_str = tablesContent->findColumn(table_enum_subst, !column_subst.empty() ? column_subst.c_str() : column->c_str(), child_index, &columnIndex);
	} else {
		if(!table_enum) {
			table_enum = getTableEnumIndex(table);
		}
		column_str = tablesContent->findColumn(table_enum, column->c_str(), child_index, &columnIndex);
		if(!column_str) {
			column_str = tablesContent->findColumn(_t_cdr, column->c_str(), child_index, &columnIndex);
			if(column_str) {
				table_enum = _t_cdr;
			} else {
				column_str = tablesContent->findColumn(_t_cdr_next, column->c_str(), child_index, &columnIndex);
				if(column_str) {
					table_enum = _t_cdr_next;
				} else {
					for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
						column_str = tablesContent->findColumn(_t_cdr_next + i + 1, column->c_str(), child_index, &columnIndex);
						if(column_str) {
							table_enum = _t_cdr_next + i + 1;
							break;
						}
					}
				}
			}
			if(!column_str) {
				column_str = tablesContent->findColumn(_t_cdr_country_code, column->c_str(), child_index, &columnIndex);
				if(column_str) {
					table_enum = _t_cdr_country_code;
				}
			}
		}
	}
	if(column_str) {
		value->setFromDbString(column_str);
	} else {
		value->v_type = cEvalFormula::_v_int;
		value->v._int = 0;
		value->v_null = true;
	}
	if(ord) {
		ord->u.s.table = table_enum;
		ord->u.s.column = columnIndex + 1;
		ord->u.s.child_table = child_table_enum;
		ord->u.s.child_index = child_index;
	}
	return(true);
}

int Call::sqlChildTableSize(string *child_table, void */*_callData*/) {
	//sChartsCacheCallData *callData = (sChartsCacheCallData*)_callData;
	int enumTable = getTableEnumIndex(child_table);
	if(enumTable < _t_cdr_next_end) {
		return(1);
	} else {
		switch(enumTable) {
		case _t_cdr_proxy:
			return(proxies.size());
		case _t_cdr_sipresp:
			return(SIPresponse.size());
		case _t_cdr_siphistory:
			return(SIPhistory.size());
		case _t_cdr_rtp:
			return(rtp_rows_count);
		case _t_cdr_sdp:
			return(sdp_rows_list.size());
		}
	}
	return(-1);
}

int Call::getTableEnumIndex(string *table) {
	if(!strcasecmp(table->c_str(), "cdr")) {
		return(_t_cdr);
	} else if(!strncasecmp(table->c_str(), "cdr_next", 7)) {
		if((*table)[8] == '_') {
			int ch_index = atof(table->c_str() + 9);
			if(ch_index > 0 && ch_index <= CDR_NEXT_MAX) {
				return(_t_cdr_next + ch_index);
			}
		} else {
			return(_t_cdr_next);
		}
	}
	return(!strcasecmp(table->c_str(), "cdr_country_code") ? _t_cdr_country_code :
	       !strcasecmp(table->c_str(), "cdr_proxy") ? _t_cdr_proxy :
	       !strcasecmp(table->c_str(), "cdr_sipresp") ? _t_cdr_sipresp :
	       !strcasecmp(table->c_str(), "cdr_siphistory") ? _t_cdr_siphistory :
	       !strcasecmp(table->c_str(), "cdr_rtp") ? _t_cdr_rtp :
	       !strcasecmp(table->c_str(), "cdr_sdp") ? _t_cdr_sdp : 0);
}

int Call::detectCallerdByLabelInXml(const char *label) {
	int rslt = -1;
	txt_lock();
	for(list<sTxt>::iterator iter = txt.begin(); iter != txt.end(); iter++) {
		if(iter->type == txt_type_sdp_xml) {
			map<string, string> streams; // label -> stream_id
			map<string, string> participantstreamassoc; // stream_id -> participant_id
			vector<dstring> participants; // participant_id, stream_id
			list<string> streams_br;
			if(!getbranch_xml("stream", iter->txt.c_str(), &streams_br)) {
				continue;
			}
			for(list<string>::iterator iter = streams_br.begin(); iter != streams_br.end(); iter++) {
				string stream_id = gettag_xml("stream_id", iter->c_str());
				if(stream_id.empty()) {
					stream_id = gettag_xml("id", iter->c_str());
				}
				string label = getvalue_xml("label", iter->c_str());
				if(!stream_id.empty() && !label.empty()) {
					streams[label] = stream_id;
				}
			}
			list<string> participantstreamassoc_br;
			if(getbranch_xml("participantstreamassoc", iter->txt.c_str(), &participantstreamassoc_br)) {
				for(list<string>::iterator iter = participantstreamassoc_br.begin(); iter != participantstreamassoc_br.end(); iter++) {
					string participant_id = gettag_xml("participant_id", iter->c_str());
					string stream_id = getvalue_xml("send", iter->c_str());
					if(!participant_id.empty() && !stream_id.empty()) {
						participantstreamassoc[stream_id] = participant_id;
					}
				}
			}
			list<string> participants_br;
			if(!getbranch_xml("participant", iter->txt.c_str(), &participants_br)) {
				continue;
			}
			for(list<string>::iterator iter = participants_br.begin(); iter != participants_br.end(); iter++) {
				string participant_id;
				string stream_id;
				participant_id = gettag_xml("participant_id", iter->c_str());
				if(participant_id.empty()) {
					participant_id = gettag_xml("id", iter->c_str());
				}
				if(!participant_id.empty()) {
					stream_id = getvalue_xml("send", iter->c_str());
					participants.push_back(dstring(participant_id, stream_id));
				}
			}
			string stream_id = streams[label];
			if(stream_id.empty()) {
				continue;
			}
			string participant_id = participantstreamassoc[stream_id];
			for(unsigned participant_i = 0; participant_i < participants.size(); participant_i++) {
				if(participants[participant_i][0] == participant_id ||
				   participants[participant_i][1] == stream_id) {
					rslt = participant_i == 0 ? 0 : 1;
					break;
				}
			}
			if(rslt >= 0) {
				break;
			}
		}
	}
	txt_unlock();
	return(rslt);
}

void Call::selectRtpAB() {
	if(!rtp_size()) {
		return;
	}
	
	if(sverb.rtp_streams) {
		cout << "call " << call_id << endl;
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			cout << "RTP stream: " 
			     << hex << rtp_i->ssrc << dec << " : "
			     << rtp_i->saddr.getString() << " -> "
			     << rtp_i->daddr.getString() << " /"
			     << " iscaller: " << rtp_i->iscaller << " " 
			     << " packets received: " << rtp_i->s->received << " "
			     << " packets lost: " << rtp_i->s->lost << " "
			     << " ssrc index: " << rtp_i->ssrc_index << " "
			     << " ok_other_ip_side_by_sip: " << rtp_i->ok_other_ip_side_by_sip << " " 
			     << " payload: " << rtp_i->first_codec << " "
			     << " rtcp.counter_mos: " << rtp_i->rtcp_xr.counter_mos << " "
			     << endl;
		}
	}
	
	map<unsigned, unsigned> indexes;
	bool rtpab_ok = false;
	
	if(rtp_size() == 1) {
		if(rtp_stream_by_index(0)->allowed_for_ab()) {
			rtpab[rtp_stream_by_index(0)->iscaller ? 0 : 1] = rtp_stream_by_index(0);
			rtpab_ok = true;
		}
	} else if(rtp_size() == 2) {
		if(rtp_stream_by_index(0)->allowed_for_ab() &&
		   rtp_stream_by_index(1)->allowed_for_ab()) {
			if(rtp_stream_by_index(0)->iscaller != rtp_stream_by_index(1)->iscaller) {
				if(rtp_stream_by_index(0)->iscaller) {
					rtpab[0] = rtp_stream_by_index(0);
					rtpab[1] = rtp_stream_by_index(1);
				} else {
					rtpab[0] = rtp_stream_by_index(1);
					rtpab[1] = rtp_stream_by_index(0);
				}
				rtpab_ok = true;
			} else if(rtp_stream_by_index(0)->saddr == rtp_stream_by_index(1)->daddr &&
				  rtp_stream_by_index(1)->saddr == rtp_stream_by_index(0)->daddr) {
				rtpab[0] = rtp_stream_by_index(0);
				rtpab[1] = rtp_stream_by_index(1);
				rtpab[1]->iscaller = !rtpab[0]->iscaller;
				rtpab_ok = true;
			}
		}
	}
	
	int rtp_size_reduct = rtp_size();
	if(!rtpab_ok) {
		// init indexex
		int j = 0;
		for(int i = 0; i < rtp_size(); i++) {
			if(rtp_stream_by_index(i)->allowed_for_ab()) {
				indexes[j++] = i;
			}
		}
		rtp_size_reduct = j;
		// bubble sort
		for(int k = 0; k < rtp_size_reduct; k++) {
			for(int j = 0; j < rtp_size_reduct; j++) {
				if((rtp_stream_by_index(indexes[k])->stats.received + rtp_stream_by_index(indexes[k])->stats.lost) > (rtp_stream_by_index(indexes[j])->stats.received + rtp_stream_by_index(indexes[j])->stats.lost)) {
					int kTmp = indexes[k];
					indexes[k] = indexes[j];
					indexes[j] = kTmp;
				}
			}
		}
		if(rtp_size_reduct > 2 &&
		   ((rtp_stream_by_index(indexes[2])->stats.received + rtp_stream_by_index(indexes[2])->stats.lost) == 0 ||
		    (rtp_stream_by_index(indexes[1])->stats.received + rtp_stream_by_index(indexes[1])->stats.lost) / (rtp_stream_by_index(indexes[2])->stats.received + rtp_stream_by_index(indexes[2])->stats.lost) > 10) &&
		   rtp_stream_by_index(indexes[0])->first_codec >= 0 && rtp_stream_by_index(indexes[1])->first_codec >= 0) {
			if(rtp_stream_by_index(indexes[0])->iscaller != rtp_stream_by_index(indexes[1])->iscaller) {
				if(rtp_stream_by_index(indexes[0])->iscaller) {
					rtpab[0] = rtp_stream_by_index(indexes[0]);
					rtpab[1] = rtp_stream_by_index(indexes[1]);
				} else {
					rtpab[0] = rtp_stream_by_index(indexes[1]);
					rtpab[1] = rtp_stream_by_index(indexes[0]);
				}
				rtpab_ok = true;
			} else if(rtp_stream_by_index(indexes[0])->saddr == rtp_stream_by_index(indexes[1])->daddr &&
				  rtp_stream_by_index(indexes[1])->saddr == rtp_stream_by_index(indexes[0])->daddr) {
				rtpab[0] = rtp_stream_by_index(indexes[0]);
				rtpab[1] = rtp_stream_by_index(indexes[1]);
				rtpab[1]->iscaller = !rtpab[0]->iscaller;
				rtpab_ok = true;
			}
		}
	}
	
	if(!rtpab_ok) {
		if(opt_rtpip_find_endpoints) {
			for(int i = 0; i < 2; i++) {
				bool _iscaller = i == 0 ? 1 : 0;
				map<unsigned, bool> skip_stream;
				unsigned count_streams = 0;
				for(int j = 0; j < rtp_size_reduct; j++) {
					if(rtp_stream_by_index(indexes[j])->iscaller == _iscaller && 
					   rtp_stream_by_index(indexes[j])->saddr != rtp_stream_by_index(indexes[j])->daddr) {
						++count_streams;
						for(int k = 0; k < rtp_size_reduct; k++) {
							if(k != j &&
							   rtp_stream_by_index(indexes[k])->iscaller == _iscaller &&
							   rtp_stream_by_index(indexes[k])->saddr != rtp_stream_by_index(indexes[k])->daddr &&
							   rtp_stream_by_index(indexes[k])->daddr == rtp_stream_by_index(indexes[j])->saddr) {
								skip_stream[indexes[j]] = true;
								if(sverb.process_rtp || sverb.read_rtp || sverb.rtp_streams) {
									cout << "RTP - stream over proxy: " 
									     << hex << rtp_stream_by_index(indexes[j])->ssrc << dec << " : "
									     << rtp_stream_by_index(indexes[j])->saddr.getString() << " -> "
									     << rtp_stream_by_index(indexes[j])->daddr.getString() << " /"
									     << " iscaller: " << rtp_stream_by_index(indexes[j])->iscaller << " " 
									     << " packets received: " << rtp_stream_by_index(indexes[j])->s->received << " "
									     << " packets lost: " << rtp_stream_by_index(indexes[j])->s->lost << " "
									     << " ssrc index: " << rtp_stream_by_index(indexes[j])->ssrc_index << " "
									     << " ok_other_ip_side_by_sip: " << rtp_stream_by_index(indexes[j])->ok_other_ip_side_by_sip << " " 
									     << " payload: " << rtp_stream_by_index(indexes[j])->first_codec << " "
									     << " rtcp.counter_mos: " << rtp_stream_by_index(indexes[j])->rtcp_xr.counter_mos << " "
									     << endl;
								}
								break;
							}
						}
					}
				}
				if(skip_stream.size()) {
					if(skip_stream.size() < count_streams) {
						int _rtp_size_reduct = 0;
						for(int i = 0; i < rtp_size_reduct; i++) {
							if(!skip_stream[indexes[i]]) {
								indexes[_rtp_size_reduct++] = indexes[i];
							}
						}
						rtp_size_reduct = _rtp_size_reduct;
					} else {
						if(sverb.process_rtp || sverb.read_rtp || sverb.rtp_streams) {
							cout << "RTP - suppress skip streams over proxy (LOOP)" 
							     << " iscaller: " << _iscaller
							     << " skip streams: " << skip_stream.size()
							     << " count streams: " << count_streams
							     << endl;
						}
					}
				}
			}
		}
	 
		// find first caller and first called
		bool rtpab_ok[2] = {false, false};
		bool pass_rtpab_simple = typeIs(MGCP) ||
					 (typeIs(SKINNY_NEW) ? opt_rtpfromsdp_onlysip_skinny : opt_rtpfromsdp_onlysip);
		if(!pass_rtpab_simple && typeIs(INVITE) && rtp_size_reduct >= 2 &&
		   (rtp_stream_by_index(indexes[0])->iscaller + rtp_stream_by_index(indexes[1])->iscaller) == 1 &&
		   rtp_stream_by_index(indexes[0])->first_codec >= 0 && rtp_stream_by_index(indexes[1])->first_codec >= 0) {
			if(rtp_size_reduct == 2) {
				pass_rtpab_simple = true;
			} else {
				unsigned callerStreams = 0;
				unsigned calledStreams = 0;
				map<unsigned, unsigned> callerReceivedPackets;
				map<unsigned, unsigned> calledReceivedPackets;
				for(int k = 0; k < rtp_size_reduct; k++) {
					if(rtp_stream_by_index(indexes[k])->iscaller) {
						callerReceivedPackets[callerStreams++] = rtp_stream_by_index(indexes[k])->s->received;
					} else {
						calledReceivedPackets[calledStreams++] = rtp_stream_by_index(indexes[k])->s->received;
					}
				}
				if((!callerReceivedPackets[1] || (callerReceivedPackets[0] / callerReceivedPackets[1]) > 5) &&
				   (!calledReceivedPackets[1] || (calledReceivedPackets[0] / calledReceivedPackets[1]) > 5)) {
					pass_rtpab_simple = true;
				}
			}
		}
		for(int pass_rtpab = 0; pass_rtpab < (pass_rtpab_simple ? 1 : 3); pass_rtpab++) {
			for(int k = 0; k < rtp_size_reduct; k++) {
				if(pass_rtpab == 0) {
					if(sverb.process_rtp || sverb.read_rtp || sverb.rtp_streams) {
						cout << "RTP - final stream: " 
						     << hex << rtp_stream_by_index(indexes[k])->ssrc << dec << " : "
						     << rtp_stream_by_index(indexes[k])->saddr.getString() << " -> "
						     << rtp_stream_by_index(indexes[k])->daddr.getString() << " /"
						     << " iscaller: " << rtp_stream_by_index(indexes[k])->iscaller << " " 
						     << " packets received: " << rtp_stream_by_index(indexes[k])->s->received << " "
						     << " packets lost: " << rtp_stream_by_index(indexes[k])->s->lost << " "
						     << " ssrc index: " << rtp_stream_by_index(indexes[k])->ssrc_index << " "
						     << " ok_other_ip_side_by_sip: " << rtp_stream_by_index(indexes[k])->ok_other_ip_side_by_sip << " " 
						     << " payload: " << rtp_stream_by_index(indexes[k])->first_codec << " "
						     << " rtcp.counter_mos: " << rtp_stream_by_index(indexes[k])->rtcp_xr.counter_mos << " "
						     << endl;
					}
				}
				if(rtp_stream_by_index(indexes[k])->stats.received &&
				   (pass_rtpab_simple || rtp_stream_by_index(indexes[k])->ok_other_ip_side_by_sip || 
				    (pass_rtpab == 1 && rtp_stream_by_index(indexes[k])->first_codec >= 0) ||
				    pass_rtpab == 2)) {
					if(!rtpab_ok[0] &&
					   rtp_stream_by_index(indexes[k])->iscaller && 
					   (!rtpab[0] || rtp_stream_by_index(indexes[k])->stats.received > rtpab[0]->stats.received)) {
						rtpab[0] = rtp_stream_by_index(indexes[k]);
					}
					if(!rtpab_ok[1] &&
					   !rtp_stream_by_index(indexes[k])->iscaller && 
					   (!rtpab[1] || rtp_stream_by_index(indexes[k])->stats.received > rtpab[1]->stats.received)) {
						rtpab[1] = rtp_stream_by_index(indexes[k]);
					}
				}
			}
			if(!pass_rtpab_simple && pass_rtpab == 0) {
				if(rtpab[0]) {
					rtpab_ok[0] = true;
				}
				if(rtpab[1]) {
					rtpab_ok[1] = true;
				}
				if(rtpab_ok[0] && rtpab_ok[1]) {
					break;
				}
			}
		}
	}
	
	if(sverb.rtp_streams) {
		for(int k = 0; k < 2; k++) {
			if(rtpab[k]) {
				cout << "RTP - select stream: " 
				     << hex << rtpab[k]->ssrc << dec << " : "
				     << rtpab[k]->saddr.getString() << " -> "
				     << rtpab[k]->daddr.getString() << " /"
				     << " iscaller: " << rtpab[k]->iscaller << " "
				     << " packets received: " << rtpab[k]->s->received << " "
				     << " packets lost: " << rtpab[k]->s->lost << " "
				     << " ssrc index: " << rtpab[k]->ssrc_index << " "
				     << " ok_other_ip_side_by_sip: " << rtpab[k]->ok_other_ip_side_by_sip << " " 
				     << " payload: " << rtpab[k]->first_codec << " "
				     << " rtcp.counter_mos: " << rtpab[k]->rtcp_xr.counter_mos << " "
				     << endl;
			}
		}
	}
}

volatile u_int64_t counter_calls_save_1;
volatile u_int64_t counter_calls_save_2;

/* TODO: implement failover -> write INSERT into file */
int
Call::saveToDb(bool enableBatchIfPossible) {
 
	if(sverb.disable_save_call) {
		return(0);
	}
	
	__SYNC_INC(counter_calls_save_1);
	
	if((flags & FLAG_SKIPCDR) ||
	   (lastSIPresponseNum >= 0 && nocdr_rules.isSet() && nocdr_rules.check(this))) {
		return(0);
	}
	
	/*
	strcpy(this->caller, "ěščřžý");
	this->proxies.push_back(1);
	this->proxies.push_back(2);
	*/
 
	if(!sqlDbSaveCall) {
		sqlDbSaveCall = createSqlObject();
		sqlDbSaveCall->setEnableSqlStringInContent(true);
	}
	
	removeRTP_ifSetFlag();

	if((opt_cdronlyanswered and !connect_time_us) or 
	   (opt_cdronlyrtp and !rtp_size())) {
		// skip this CDR 
		return 1;
	}
	
	__SYNC_INC(counter_calls_save_2);
	
	/* only needed to tune storage speed
	cdr.clear();
	cdr_next.clear();
	for(int i = 0; i < CDR_NEXT_MAX; i++) {
		cdr_next_ch[i].clear();
	}
	cdr_country_code.clear();
	*/
	
	adjustUA();
	
	if(opt_only_cdr_next) {
		static u_int32_t last_id_cdr_next = 0;
		if(!last_id_cdr_next) {
			sqlDbSaveCall->query("select max(cdr_ID) from cdr_next");
			SqlDb_row rslt = sqlDbSaveCall->fetchRow();
			if(rslt) {
				last_id_cdr_next = atol(rslt[0].c_str());
			}
		}
		SqlDb_row cdr_next;
		cdr_next.add(++last_id_cdr_next, "cdr_ID");
		cdr_next.add(sqlEscapeString(fbasename), "fbasename");
		cdr_next.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_next_calldate_ms);
		if(enableBatchIfPossible && isSqlDriver("mysql")) {
			string query_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT + 
					   sqlDbSaveCall->insertQuery(sql_cdr_next_table, cdr_next));
			
			static unsigned int counterSqlStore = 0;
			sqlStore->query_lock(query_str.c_str(), 
					     STORE_PROC_ID_CDR,
					     opt_mysqlstore_max_threads_cdr > 1 &&
					     sqlStore->getSize(STORE_PROC_ID_CDR, 0) > 1000 ? 
					      counterSqlStore % opt_mysqlstore_max_threads_cdr : 
					      0);
			++counterSqlStore;
		} else {
			sqlDbSaveCall->insert(sql_cdr_next_table, cdr_next);
		}
		return(0);
	}

	string sql_cdr_proxy_table = "cdr_proxy";
	string sql_cdr_rtp_table = "cdr_rtp";
	string sql_cdr_rtp_energylevels_table = "cdr_rtp_energylevels";
	string sql_cdr_sdp_table = "cdr_sdp";
	string sql_cdr_txt_table = "cdr_txt";
	string sql_cdr_dtmf_table = "cdr_dtmf";
	
	char _cdr_next_ch_name[CDR_NEXT_MAX][100];
	char *cdr_next_ch_name[CDR_NEXT_MAX];
	for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
		_cdr_next_ch_name[i][0] = 0;
		cdr_next_ch_name[i] = _cdr_next_ch_name[i];
	}
	unsigned int /*
			caller_id = 0,
			called_id = 0,
			callername_id = 0,
			caller_domain_id = 0,
			called_domain_id = 0,
			*/
			lastSIPresponse_id = 0,
			reason_sip_id = 0,
			reason_q850_id = 0,
			a_ua_id = 0,
			b_ua_id = 0;
	u_int64_t cdr_flags = this->unconfirmed_bye ? CDR_UNCONFIRMED_BYE : 0;
	if (is_fas_detected)
		cdr_flags |= CDR_FAS_DETECTED;
	if (is_zerossrc_detected)
		cdr_flags |= CDR_ZEROSSRC_DETECTED;
	if (is_sipalg_detected)
		cdr_flags |= CDR_SIPALG_DETECTED;
	for(int i = 0; i < ipport_n; i++) {
		if(ip_port[i].srtp) {
			bool stream_is_used =  false;
			for(int j = 0; j < rtp_size(); j++) {
				if(rtp_stream_by_index(j)->index_call_ip_port == i &&
				   rtp_stream_by_index(j)->stats.received > 0) {
					stream_is_used = true;
					break;
				}
			}
			if(stream_is_used &&
			   !(ip_port[i].srtp_crypto_config_list ||
			     (rtp_secure_map[i] && rtp_secure_map[i]->isOK_decrypt_rtp()))) {
				cdr_flags |= CDR_SRTP_WITHOUT_KEY;
			}
		}
	}
	if (televent_exists_request) {
		cdr_flags |= CDR_TELEVENT_EXISTS_REQUEST;
	}
	if (televent_exists_response) {
		cdr_flags |= CDR_TELEVENT_EXISTS_RESPONSE;
	}
	if (sip_fragmented) {
		cdr_flags |= CDR_SIP_FRAGMENTED;
	}
	if (rtp_fragmented) {
		cdr_flags |= CDR_RTP_FRAGMENTED;
	}
	if (sdp_exists_media_type_audio) {
		cdr_flags |= CDR_SDP_EXISTS_MEDIA_TYPE_AUDIO;
	}
	if (sdp_exists_media_type_image) {
		cdr_flags |= CDR_SDP_EXISTS_MEDIA_TYPE_IMAGE;
	}
	if (sdp_exists_media_type_video) {
		cdr_flags |= CDR_SDP_EXISTS_MEDIA_TYPE_VIDEO;
	}
	
	if(suppress_rtp_proc_due_to_insufficient_hw_performance) {
		cdr_flags |= CDR_PROCLIM_SUPPRESS_RTP_PROC;
	} else if(suppress_rtp_read_due_to_insufficient_hw_performance) {
		cdr_flags |= CDR_PROCLIM_SUPPRESS_RTP_READ;
	}

	vmIP sipcalledip_confirmed;
	vmIP sipcalledip_encaps_confirmed;
	u_int8_t sipcalledip_encaps_prot_confirmed;
	vmPort sipcalledport_confirmed;
	sipcalledip_confirmed = getSipcalledipConfirmed(&sipcalledport_confirmed, &sipcalledip_encaps_confirmed, &sipcalledip_encaps_prot_confirmed);
	sipcalledip_rslt = sipcalledip_confirmed.isSet() ? sipcalledip_confirmed : getSipcalledip();
	sipcalledip_encaps_rslt = sipcalledip_encaps_confirmed.isSet() ? sipcalledip_encaps_confirmed : getSipcalledip_encaps();
	sipcalledip_encaps_prot_rslt = sipcalledip_encaps_confirmed.isSet() ? sipcalledip_encaps_prot_confirmed : getSipcalledip_encaps_prot();
	sipcalledport_rslt = sipcalledport_confirmed.isSet() ? sipcalledport_confirmed : getSipcalledport();
	
	string query_str_cdrproxy;
	if(opt_cdrproxy) {
		vector<SqlDb_row> cdrproxy_rows;
		set<vmIP> proxies_undup;
		this->proxies_undup(&proxies_undup);
		set<vmIP>::iterator iter_undup = proxies_undup.begin();
		while(iter_undup != proxies_undup.end()) {
			if(*iter_undup == sipcalledip_rslt) { ++iter_undup; continue; }
			SqlDb_row cdrproxy;
			cdrproxy.setIgnoreCheckExistsField();
			cdrproxy.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
			cdrproxy.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_proxy_calldate_ms);
			cdrproxy.add((vmIP)(*iter_undup), "dst", false, sqlDbSaveCall, sql_cdr_proxy_table.c_str() );
			if(opt_mysql_enable_multiple_rows_insert) {
				cdrproxy_rows.push_back(cdrproxy);
			} else {
				query_str_cdrproxy += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						      sqlDbSaveCall->insertQuery(sql_cdr_proxy_table, cdrproxy));
			}
			++iter_undup;
		}
		if(opt_mysql_enable_multiple_rows_insert && cdrproxy_rows.size()) {
			if(useCsvStoreFormat()) {
				query_str_cdrproxy += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_proxy") + cdrproxy_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
				for(unsigned i = 0; i < cdrproxy_rows.size(); i++) {
					query_str_cdrproxy += MYSQL_MAIN_INSERT_CSV_ROW("cdr_proxy") + cdrproxy_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
				}
			} else {
				query_str_cdrproxy += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						      sqlDbSaveCall->insertQueryWithLimitMultiInsert(sql_cdr_proxy_table, &cdrproxy_rows, opt_mysql_max_multiple_rows_insert, 
												     MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
			}
		}
	}

	list<sSipResponse> SIPresponseUnique;
	for(list<sSipResponse>::iterator iterSipresp = SIPresponse.begin(); iterSipresp != SIPresponse.end(); iterSipresp++) {
		bool existsInUnique = false;
		for(list<sSipResponse>::iterator iterSiprespUnique = SIPresponseUnique.begin(); iterSiprespUnique != SIPresponseUnique.end(); iterSiprespUnique++) {
			if(iterSiprespUnique->SIPresponseNum == iterSipresp->SIPresponseNum &&
			   iterSiprespUnique->SIPresponse == iterSipresp->SIPresponse) {
				existsInUnique = true;
				break;
			}
		}
		if(!existsInUnique) {
			SIPresponseUnique.push_back(*iterSipresp);
		}
	}
	
	if(opt_save_sdp_ipport) {
		bool save_iscaller = false;
		bool save_iscalled = false;
		for(int i = ipport_n - 1; i >= 0; i--) {
			if(ip_port[i].addr.isSet() &&
			   ip_port[i].type_addr == ip_port_call_info::_ta_base &&
			   (opt_save_sdp_ipport == 2 ||
			    (ip_port[i].iscaller ? !save_iscaller : !save_iscalled))) {
				d_item2<vmIPport, bool> ipPortIscaller(vmIPport(ip_port[i].addr, ip_port[i].port), ip_port[i].iscaller);
				if(std::find(sdp_rows_list.begin(), sdp_rows_list.end(), ipPortIscaller) == sdp_rows_list.end()) {
					sdp_rows_list.push_back(ipPortIscaller);
					if(opt_save_sdp_ipport == 1) {
						if(ip_port[i].iscaller) {
							save_iscaller = true;
						} else {
							save_iscalled = true;
						}
						if(save_iscaller && save_iscalled) {
							break;
						}
					}
				}
			}
		}
		for(int i = 0; i < 2; i++) {
			for(list<vmPort>::iterator iter = sdp_ip0_ports[i].begin(); iter != sdp_ip0_ports[i].end(); iter++) {
				d_item2<vmIPport, bool> ipPortIscaller(vmIPport(0, *iter), iscaller_inv_index(i));
				if(std::find(sdp_rows_list.begin(), sdp_rows_list.end(), ipPortIscaller) == sdp_rows_list.end()) {
					sdp_rows_list.push_back(ipPortIscaller);
				}
			}
		}
	}
	
	if(useSensorId > -1) {
		cdr.add(useSensorId, "id_sensor");
	}

	cdr.add(sqlEscapeString(caller), "caller");
	cdr.add(sqlEscapeString(reverseString(caller).c_str()), "caller_reverse");
	if(is_multiple_to_branch() && to_is_canceled(called())) {
		string called_not_canceled = get_to_not_canceled();
		if(called_not_canceled.length()) {
			strcpy_null_term(called_final, called_not_canceled.c_str());
		}
	}
	cdr.add(sqlEscapeString(called()), "called");
	cdr.add(sqlEscapeString(reverseString(called()).c_str()), "called_reverse");
	cdr.add(sqlEscapeString(caller_domain), "caller_domain");
	cdr.add(sqlEscapeString(called_domain()), "called_domain");
	cdr.add(sqlEscapeString(callername), "callername");
	cdr.add(sqlEscapeString(reverseString(callername).c_str()), "callername_reverse");
	/*
	cdr_phone_number_caller.add(sqlEscapeString(caller), "number");
	cdr_phone_number_caller.add(sqlEscapeString(reverseString(caller).c_str()), "number_reverse");
	cdr_phone_number_called.add(sqlEscapeString(called), "number");
	cdr_phone_number_called.add(sqlEscapeString(reverseString(called).c_str()), "number_reverse");
	cdr_domain_caller.add(sqlEscapeString(caller_domain), "domain");
	cdr_domain_called.add(sqlEscapeString(called_domain), "domain");
	cdr_name.add(sqlEscapeString(callername), "name");
	cdr_name.add(sqlEscapeString(reverseString(callername).c_str()), "name_reverse");
	*/
	
	unsigned int dscp_a = caller_sipdscp,
		     dscp_b = called_sipdscp,
		     dscp_c = 0,
		     dscp_d = 0;
	
	cdr.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, sql_cdr_table);
	cdr.add(sipcalledip_rslt, "sipcalledip", false, sqlDbSaveCall, sql_cdr_table);
	if(existsColumns.cdr_sipport) {
		cdr.add(getSipcallerport().getPort(), "sipcallerport");
		cdr.add(sipcalledport_rslt.getPort(), "sipcalledport");
	}
	if(existsColumns.cdr_sipcallerdip_encaps) {
		cdr.add(getSipcallerip_encaps(), "sipcallerip_encaps", !getSipcallerip_encaps().isSet(), sqlDbSaveCall, sql_cdr_table);
		cdr.add(sipcalledip_encaps_rslt, "sipcalledip_encaps", !sipcalledip_encaps_rslt.isSet(), sqlDbSaveCall, sql_cdr_table);
		cdr.add(getSipcallerip_encaps().isSet() && getSipcallerip_encaps_prot() != 0xFF ? getSipcallerip_encaps_prot() : 0, 
			"sipcallerip_encaps_prot", 
			!getSipcallerip_encaps().isSet() || getSipcallerip_encaps_prot() == 0xFF);
		cdr.add(sipcalledip_encaps_rslt.isSet() && sipcalledip_encaps_prot_rslt != 0xFF ? sipcalledip_encaps_prot_rslt : 0, 
			"sipcalledip_encaps_prot", 
			!sipcalledip_encaps_rslt.isSet() || sipcalledip_encaps_prot_rslt == 0xFF);
	}
	cdr.add_duration(duration_us(), "duration", existsColumns.cdr_duration_ms);
	if(progress_time_us) {
		cdr.add_duration(progress_time_us - first_packet_time_us, "progress_time", existsColumns.cdr_progress_time_ms);
	} else {
		cdr.add(0, "progress_time", true);
	}
	if(first_rtp_time_us) {
		cdr.add_duration(first_rtp_time_us  - first_packet_time_us, "first_rtp_time", existsColumns.cdr_first_rtp_time_ms);
	} else {
		cdr.add(0, "first_rtp_time", true);
	}
	if(connect_time_us) {
		cdr.add_duration(connect_duration_us(), "connect_duration", existsColumns.cdr_connect_duration_ms);
	} else {
		cdr.add(0, "connect_duration", true);
	}
	if(existsColumns.cdr_vlan) {
		if(VLAN_IS_SET(vlan)) {
			cdr.add(vlan, "vlan");
		} else {
			cdr.add(0, "vlan", true);
		}
	}
	if(existsColumns.cdr_last_rtp_from_end && !use_sdp_sendonly) {
		if(last_rtp_a_packet_time_us) {
			if(existsColumns.cdr_a_last_rtp_from_end_unsigned) {
				cdr.add_duration((typeIs(MGCP) ? last_mgcp_connect_packet_time_us : last_signal_packet_time_us) - last_rtp_a_packet_time_us,
						 "a_last_rtp_from_end", existsColumns.cdr_a_last_rtp_from_end_time_ms,
						 false, existsColumns.cdr_a_last_rtp_from_end_time_ms ? 999999 : 65535);
			} else {
				cdr.add_duration((int64_t)((typeIs(MGCP) ? last_mgcp_connect_packet_time_us : last_signal_packet_time_us) - last_rtp_a_packet_time_us),
						 "a_last_rtp_from_end", existsColumns.cdr_a_last_rtp_from_end_time_ms,
						 false, existsColumns.cdr_a_last_rtp_from_end_time_ms ? 999999 : 32767);
			}
		}
		if(last_rtp_b_packet_time_us) {
			if(existsColumns.cdr_b_last_rtp_from_end_unsigned) {
				cdr.add_duration((typeIs(MGCP) ? last_mgcp_connect_packet_time_us : last_signal_packet_time_us) - last_rtp_b_packet_time_us,
						 "b_last_rtp_from_end", existsColumns.cdr_b_last_rtp_from_end_time_ms,
						 false, existsColumns.cdr_a_last_rtp_from_end_time_ms ? 999999 : 65535);
			} else {
				cdr.add_duration((int64_t)(typeIs(MGCP) ? last_mgcp_connect_packet_time_us : last_signal_packet_time_us) - last_rtp_b_packet_time_us,
						 "b_last_rtp_from_end", existsColumns.cdr_b_last_rtp_from_end_time_ms,
						 false, existsColumns.cdr_a_last_rtp_from_end_time_ms ? 999999 : 32767);
			}
		}
	}
	cdr.add_calldate(calltime_us(), "calldate", existsColumns.cdr_calldate_ms);
	if(opt_callend) {
		cdr.add_calldate(callend_us(), "callend", existsColumns.cdr_callend_ms);
	}
	
	cdr_next.add(sqlEscapeString(fbasename), "fbasename");
	if(!geoposition.empty()) {
		cdr_next.add(sqlEscapeString(geoposition), "GeoPosition");
	}
	if(existsColumns.cdr_next_hold && !hold_times.empty()) {
		hold_times.erase(hold_times.end() - 1);
		cdr_next.add(hold_times, "hold");
	}
	cdr.add(sighup ? 1 : 0, "sighup");
	cdr.add(lastSIPresponseNum, "lastSIPresponseNum");
	if(existsColumns.cdr_reason) {
		if(reason_sip_cause) {
			cdr.add(reason_sip_cause, "reason_sip_cause");
		}
		if(reason_q850_cause) {
			cdr.add(reason_q850_cause, "reason_q850_cause");
		}
	}
	if(this->first_invite_time_us) {
		if(existsColumns.cdr_response_time_100 && this->first_response_100_time_us) {
			cdr.add(MIN(65535, round((this->first_response_100_time_us - this->first_invite_time_us) / 1000.0)), "response_time_100");
		}
		if(existsColumns.cdr_response_time_xxx && this->first_response_xxx_time_us) {
			cdr.add(MIN(65535, round((this->first_response_xxx_time_us - this->first_invite_time_us) / 1000.0)), "response_time_xxx");
		}
	}

	int bye;
	if(force_terminate) {
		bye = 110;
	} else if(absolute_timeout_exceeded) {
		bye = 102;
	} else if(bye_timeout_exceeded) {
		bye = 103;
	} else if(rtp_timeout_exceeded) {
		bye = 104;
	} else if(oneway_timeout_exceeded) {
		bye = 105;
	} else if(zombie_timeout_exceeded) {
		bye = 107;
	} else if(sipwithoutrtp_timeout_exceeded) {
		bye = 108;
	} else if(oneway && typeIsNot(SKINNY_NEW) && typeIsNot(MGCP)) {
		bye = 101;
	} else if(pcap_drop) {
		bye = 100;
	} else if(!seenRES2XX_no_BYE && !seenRES18X && seenbye) {
		bye = 106;
	} else {
		bye = seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0;
	}
	cdr.add(bye, "bye");

	if(strlen(match_header)) {
		cdr_next.add(sqlEscapeString(match_header), "match_header");
	}
	if(strlen(custom_header1)) {
		cdr_next.add(sqlEscapeString(custom_header1), "custom_header1");
	}
	/* obsolete
	for(map<string, string>::iterator iCustHeadersIter = custom_headers.begin(); iCustHeadersIter != custom_headers.end(); iCustHeadersIter++) {
		cdr_next.add(sqlEscapeString(iCustHeadersIter->second), iCustHeadersIter->first);
	}
	*/
	if(existsColumns.cdr_next_calldate) {
		cdr_next.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_next_calldate_ms);
	}
	
	if(custom_headers_cdr) {
		custom_headers_cdr->prepareSaveRows(this, INVITE, NULL, 0, &cdr_next, cdr_next_ch, cdr_next_ch_name);
	}

	if(whohanged == 0 || whohanged == 1) {
		cdr.add(whohanged ? 2/*"callee"*/ : 1/*"caller"*/, "whohanged");
	}
	
	if(get_customers_pn_query[0]) {
		CustPhoneNumberCache *custPnCache = getCustPnCache();
		if(custPnCache) {
			cust_reseller cr;
			cr = custPnCache->getCustomerByPhoneNumber(caller);
			if(cr.cust_id) {
				cdr.add(cr.cust_id, "caller_customer_id");
				cdr.add(cr.reseller_id, "caller_reseller_id");
			}
			cr = custPnCache->getCustomerByPhoneNumber(called());
			if(cr.cust_id) {
				cdr.add(cr.cust_id, "called_customer_id");
				cdr.add(cr.reseller_id, "called_reseller_id");
			}
		}
	}

	if(a_mos_lqo != -1 && existsColumns.cdr_mos_lqo) {
		int mos = a_mos_lqo * 10;
		cdr.add(mos, "a_mos_lqo_mult10");
	}
	if(b_mos_lqo != -1 && existsColumns.cdr_mos_lqo) {
		int mos = b_mos_lqo * 10;
		cdr.add(mos, "b_mos_lqo_mult10");
	}
	
	selectRtpAB();
	
	rtp_rows_count = 0;
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		if(rtp_i &&
		   !(rtp_i->stopReadProcessing && opt_rtp_check_both_sides_by_sdp == 1) &&
		   (rtp_i->s->received or !existsColumns.cdr_rtp_index || (rtp_i->s->received == 0 && rtp_zeropackets_stored == false)) &&
		   (sverb.process_rtp_header || rtp_i->first_codec != -1)) {
			if(rtp_i->s->received == 0 and rtp_zeropackets_stored == false) rtp_zeropackets_stored = true;
			rtp_rows_indexes[rtp_rows_count++] = i;
		}
	}
	
	payload_rslt = -1;
	
	// first caller and called
	if(rtp_size() > 0) {
	 
		this->applyRtcpXrDataToRtp();
		
		if(opt_silencedetect && existsColumns.cdr_silencedetect) {
			if(caller_silence > 0 or caller_noise > 0) {
				cdr.add(caller_silence * 100 / (caller_silence + caller_noise), "caller_silence");
			}
			if(called_silence > 0 or called_noise > 0) {
				cdr.add(called_silence * 100 / (called_silence + called_noise), "called_silence");
			}
			cdr.add(caller_lastsilence / 1000, "caller_silence_end");
			cdr.add(called_lastsilence / 1000, "called_silence_end");
		}
		if(opt_clippingdetect && existsColumns.cdr_clippingdetect) {
			if(caller_clipping_8k) {
				cdr.add(MIN(USHRT_MAX, round(caller_clipping_8k / 3)), "caller_clipping_div3");
			}
			if(called_clipping_8k) {
				cdr.add(MIN(USHRT_MAX, round(called_clipping_8k / 3)), "called_clipping_div3");
			}
		}

		// save only two streams with the biggest received packets
		int payload[2] = { -1, -1 };
		int jitter_mult10[2] = { -1, -1 };
		int mos_min_mult10[2] = { -1, -1 };
		int packet_loss_perc_mult1000[2] = { -1, -1 };
		int delay_sum[2] = { -1, -1 };
		int delay_cnt[2] = { -1, -1 };
		int delay_avg_mult100[2] = { -1, -1 };
		int rtcp_avgfr_mult10[2] = { -1, -1 };
		int rtcp_avgjitter_mult10[2] = { -1, -1 };
		int lost[2] = { -1, -1 };
		
		for(int i = 0; i < 2; i++) {
			if(!rtpab[i]) continue;
			
			if(i) {
				dscp_d = rtpab[i]->dscp;
			} else {
				dscp_c = rtpab[i]->dscp;
			}

			string c = i == 0 ? "a" : "b";
			
			cdr.add(rtpab[i]->ssrc_index, c+"_index");
			cdr.add(rtpab[i]->stats.received + (rtpab[i]->first_codec >= 0 ? 2 : 0), c+"_received"); // received is always 2 packet less compared to wireshark (add it here)
			lost[i] = rtpab[i]->stats.lost;
			cdr.add(lost[i], c+"_lost");
			packet_loss_perc_mult1000[i] = (int)round((double)rtpab[i]->stats.lost / 
									(rtpab[i]->stats.received + 2 + rtpab[i]->stats.lost) * 100 * 1000);
			cdr.add(packet_loss_perc_mult1000[i], c+"_packet_loss_perc_mult1000");
			jitter_mult10[i] = ceil(rtpab[i]->stats.avgjitter * 10);
			cdr.add(jitter_mult10[i], c+"_avgjitter_mult10");
			cdr.add(int(ceil(rtpab[i]->stats.maxjitter)), c+"_maxjitter");
			payload[i] = rtpab[i]->first_codec;
			if(payload[i] >= 0) {
				cdr.add(payload[i], c+"_payload");
			} else if(sverb.process_rtp_header) {
				cdr.add(0, c+"_payload");
			}
			
			// build a_sl1 - b_sl10 fields
			for(int j = 1; j < 11; j++) {
				char str_j[3];
				snprintf(str_j, sizeof(str_j), "%d", j);
				cdr.add(rtpab[i]->stats.slost[j], c+"_sl"+str_j);
			}
			// build a_d50 - b_d300 fileds
			cdr.add(rtpab[i]->stats.d50, c+"_d50");
			cdr.add(rtpab[i]->stats.d70, c+"_d70");
			cdr.add(rtpab[i]->stats.d90, c+"_d90");
			cdr.add(rtpab[i]->stats.d120, c+"_d120");
			cdr.add(rtpab[i]->stats.d150, c+"_d150");
			cdr.add(rtpab[i]->stats.d200, c+"_d200");
			cdr.add(rtpab[i]->stats.d300, c+"_d300");
			delay_sum[i] = rtpab[i]->stats.d50 * 60 + 
					rtpab[i]->stats.d70 * 80 + 
					rtpab[i]->stats.d90 * 105 + 
					rtpab[i]->stats.d120 * 135 +
					rtpab[i]->stats.d150 * 175 + 
					rtpab[i]->stats.d200 * 250 + 
					rtpab[i]->stats.d300 * 300;
			delay_cnt[i] = rtpab[i]->stats.d50 + 
					rtpab[i]->stats.d70 + 
					rtpab[i]->stats.d90 + 
					rtpab[i]->stats.d120 +
					rtpab[i]->stats.d150 + 
					rtpab[i]->stats.d200 + 
					rtpab[i]->stats.d300;
			delay_avg_mult100[i] = (delay_cnt[i] != 0  ? (int)round((double)delay_sum[i] / delay_cnt[i] * 100) : 0);
			cdr.add(delay_sum[i], c+"_delay_sum");
			cdr.add(delay_cnt[i], c+"_delay_cnt");
			cdr.add(delay_avg_mult100[i], c+"_delay_avg_mult100");
			
			// store source addr
			cdr.add(rtpab[i]->saddr, c+"_saddr", false, sqlDbSaveCall, sql_cdr_table);

			// calculate MOS score for fixed 50ms 
			//double burstr, lossr;
			//burstr_calculate(rtpab[i]->channel_fix1, rtpab[i]->stats.received, &burstr, &lossr, 0);
			//int mos_f1_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			if(rtpab[i]->mosf1_avg > 0) {
				int mos_f1_mult10 = (int)rtpab[i]->mosf1_avg;
				cdr.add(mos_f1_mult10, c+"_mos_f1_mult10");
				mos_min_mult10[i] = mos_f1_mult10;
			}
			if(existsColumns.cdr_mos_min && rtpab[i]->mosf1_min > 0 && rtpab[i]->mosf1_min != (uint8_t)-1) {
				cdr.add(rtpab[i]->mosf1_min, c+"_mos_f1_min_mult10");
			}

			// calculate MOS score for fixed 200ms 
			//burstr_calculate(rtpab[i]->channel_fix2, rtpab[i]->stats.received, &burstr, &lossr, 0);
			//int mos_f2_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			if(rtpab[i]->mosf2_avg > 0) {
				int mos_f2_mult10 = (int)round(rtpab[i]->mosf2_avg);
				cdr.add(mos_f2_mult10, c+"_mos_f2_mult10");
				if(mos_min_mult10[i] < 0 || mos_f2_mult10 < mos_min_mult10[i]) {
					mos_min_mult10[i] = mos_f2_mult10;
				}
			}
			if(existsColumns.cdr_mos_min && rtpab[i]->mosf2_min > 0 && rtpab[i]->mosf2_min != (uint8_t)-1) {
				cdr.add(rtpab[i]->mosf2_min, c+"_mos_f2_min_mult10");
			}

			// calculate MOS score for adaptive 500ms 
			//burstr_calculate(rtpab[i]->channel_adapt, rtpab[i]->stats.received, &burstr, &lossr, 0);
			//int mos_adapt_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			if(rtpab[i]->mosAD_avg > 0) {
				int mos_adapt_mult10 = (int)round(rtpab[i]->mosAD_avg);
				cdr.add(mos_adapt_mult10, c+"_mos_adapt_mult10");
				if(mos_min_mult10[i] < 0 || mos_adapt_mult10 < mos_min_mult10[i]) {
					mos_min_mult10[i] = mos_adapt_mult10;
				}
			}
			if(existsColumns.cdr_mos_min && rtpab[i]->mosAD_min > 0 && rtpab[i]->mosAD_min != (uint8_t)-1) {
				cdr.add(rtpab[i]->mosAD_min, c+"_mos_adapt_min_mult10");
			}

			// silence MOS 
			if(existsColumns.cdr_mos_silence and rtpab[i]->mosSilence_min != (uint8_t)-1) {
				int mos_silence_mult10 = (int)round(rtpab[i]->mosSilence_avg);
				if(mos_silence_mult10 > 0) {
					cdr.add(mos_silence_mult10, c+"_mos_silence_mult10");
				}
				if(rtpab[i]->mosSilence_min > 0) {
					cdr.add(rtpab[i]->mosSilence_min, c+"_mos_silence_min_mult10");
				}
			}

			// XR MOS 
			if(existsColumns.cdr_mos_xr and rtpab[i]->rtcp_xr.counter_mos > 0) {
				if(rtpab[i]->rtcp_xr.minmos > 0) {
					cdr.add(rtpab[i]->rtcp_xr.minmos, c+"_mos_xr_min_mult10");
				}
				if(rtpab[i]->rtcp_xr.avgmos > 0) {
					cdr.add(rtpab[i]->rtcp_xr.avgmos, c+"_mos_xr_mult10");
				}
			}

			if(opt_mosmin_f2 && rtpab[i]->mosf2_avg > 0) {
				mos_min_mult10[i] = (int)round(rtpab[i]->mosf2_avg);
			}
			
			if(mos_min_mult10[i] >= 0) {
				cdr.add(mos_min_mult10[i], c+"_mos_min_mult10");
			}

			if(rtpab[i]->rtcp.counter) {
				if ((rtpab[i]->rtcp.loss > 0xFFFF || rtpab[i]->rtcp.loss < 0) && existsColumns.cdr_rtcp_loss_is_smallint_type) {
					cdr.add(0xFFFF, c+"_rtcp_loss");
				} else {
					cdr.add(rtpab[i]->rtcp.loss, c+"_rtcp_loss");
				}
				cdr.add(rtpab[i]->rtcp.maxfr, c+"_rtcp_maxfr");
				rtcp_avgfr_mult10[i] = (int)round(rtpab[i]->rtcp.avgfr * 10);
				cdr.add(rtcp_avgfr_mult10[i], c+"_rtcp_avgfr_mult10");
				/* max jitter (interarrival jitter) may be 32bit unsigned int, so use MIN for sure (we use smallint unsigned) */
				cdr.add(MIN(0xFFFF, rtpab[i]->rtcp.maxjitter / get_ticks_bycodec(rtpab[i]->first_codec)), c+"_rtcp_maxjitter");
				rtcp_avgjitter_mult10[i] = (int)round(rtpab[i]->rtcp.avgjitter / get_ticks_bycodec(rtpab[i]->first_codec) * 10);
				cdr.add(rtcp_avgjitter_mult10[i], c+"_rtcp_avgjitter_mult10");
				if (existsColumns.cdr_rtcp_fraclost_pktcount)
					cdr.add(rtpab[i]->rtcp.fraclost_pkt_counter, c+"_rtcp_fraclost_pktcount");
			}
			if(existsColumns.cdr_rtp_ptime) {
				cdr.add(rtpab[i]->avg_ptime, c+"_rtp_ptime");
			}
			if(existsColumns.cdr_rtcp_rtd && rtpab[i]->rtcp.rtd_count) {
				cdr.add(rtpab[i]->rtcp.rtd_max * 10000 / 65536, c+"_rtcp_maxrtd_mult10");
				cdr.add(rtpab[i]->rtcp.rtd_sum * 10000 / 65536 / rtpab[i]->rtcp.rtd_count, c+"_rtcp_avgrtd_mult10");
			}
			if(existsColumns.cdr_rtcp_rtd_w && rtpab[i]->rtcp.rtd_w_count) {
				cdr.add(rtpab[i]->rtcp.rtd_w_max, c+"_rtcp_maxrtd_w");
				cdr.add(rtpab[i]->rtcp.rtd_w_sum / rtpab[i]->rtcp.rtd_w_count, c+"_rtcp_avgrtd_w");
			}

		}
		if(seenudptl && (exists_udptl_data || !not_acceptable)) {
			// T.38
			payload_rslt = 1000;
		} else if(isfax == T30FAX && !not_acceptable) {
			// T.30
			payload_rslt = 1001;
		} else if(payload[0] >= 0 || payload[1] >= 0) {
			payload_rslt = payload[0] >= 0 ? payload[0] : payload[1];
		}
		cdr.add(payload_rslt, "payload");

		if(jitter_mult10[0] >= 0 || jitter_mult10[1] >= 0) {
			cdr.add(max(jitter_mult10[0], jitter_mult10[1]), 
				"jitter_mult10");
		}
		if(mos_min_mult10[0] >= 0 || mos_min_mult10[1] >= 0) {
			cdr.add(mos_min_mult10[0] >= 0 && mos_min_mult10[1] >= 0 ?
					min(mos_min_mult10[0], mos_min_mult10[1]) :
					(mos_min_mult10[0] >= 0 ? mos_min_mult10[0] : mos_min_mult10[1]),
				"mos_min_mult10");
			/* DEBUG
			unsigned mos = mos_min_mult10[0] >= 0 && mos_min_mult10[1] >= 0 ?
					min(mos_min_mult10[0], mos_min_mult10[1]) :
					(mos_min_mult10[0] >= 0 ? mos_min_mult10[0] : mos_min_mult10[1]);
			double v;
			string v_str;
			bool v_null;
			getChartCacheValue(_chartType_mos, &v, &v_str, &v_null, NULL);
			if((unsigned)(v * 10) != mos) {
				cout << "** MOS ** " << mos << " / " << (unsigned)(v * 10) << " / " << v << " / " << round(v * 10) / 10 << endl;
			}
			*/
		}
		if(packet_loss_perc_mult1000[0] >= 0 || packet_loss_perc_mult1000[1] >= 0) {
			cdr.add(max(packet_loss_perc_mult1000[0], packet_loss_perc_mult1000[1]), 
				"packet_loss_perc_mult1000");
			/* DEBUG
			unsigned pl = max(packet_loss_perc_mult1000[0], packet_loss_perc_mult1000[1]);
			double v;
			string v_str;
			bool v_null;
			getChartCacheValue(_chartType_packet_lost, &v, &v_str, &v_null, NULL);
			if((unsigned)round(v * 1000) != pl) {
				cout << "** PL ** " << pl << " / " << (unsigned)(v * 1000) << " / " << v << " / " << round(v * 1000) / 1000 << endl;
			}
			*/
		}
		if(delay_sum[0] >= 0 || delay_sum[1] >= 0) {
			cdr.add(max(delay_sum[0], delay_sum[1]), 
				"delay_sum");
		}
		if(delay_cnt[0] >= 0 || delay_cnt[1] >= 0) {
			cdr.add(max(delay_cnt[0], delay_cnt[1]), 
				"delay_cnt");
		}
		if(delay_avg_mult100[0] >= 0 || delay_avg_mult100[1] >= 0) {
			cdr.add(max(delay_avg_mult100[0], delay_avg_mult100[1]), 
				"delay_avg_mult100");
		}
		if(rtcp_avgfr_mult10[0] >= 0 || rtcp_avgfr_mult10[1] >= 0) {
			cdr.add((rtcp_avgfr_mult10[0] >= 0 ? rtcp_avgfr_mult10[0] : 0) + 
				(rtcp_avgfr_mult10[1] >= 0 ? rtcp_avgfr_mult10[1] : 0),
				"rtcp_avgfr_mult10");
		}
		if(rtcp_avgjitter_mult10[0] >= 0 || rtcp_avgjitter_mult10[1] >= 0) {
			cdr.add((rtcp_avgjitter_mult10[0] >= 0 ? rtcp_avgjitter_mult10[0] : 0) + 
				(rtcp_avgjitter_mult10[1] >= 0 ? rtcp_avgjitter_mult10[1] : 0),
				"rtcp_avgjitter_mult10");
		}
		if(lost[0] >= 0 || lost[1] >= 0) {
			cdr.add(max(lost[0], lost[1]), 
				"lost");
		}

		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(rtp_i->change_src_port) {
				cdr_flags |= rtp_i->iscaller ? CDR_CHANGE_SRC_PORT_CALLER : CDR_CHANGE_SRC_PORT_CALLED;
			}
		}
	}

	if(opt_dscp && existsColumns.cdr_dscp) {
		cdr.add((dscp_a << 24) + (dscp_b << 16) + (dscp_c << 8) + dscp_d, "dscp");
	}
	
	if(cdr_flags && existsColumns.cdr_flags) {
		cdr.add(cdr_flags, "flags");
	}
	
	if(existsColumns.cdr_max_retransmission_invite) {
		unsigned max_retrans = getMaxRetransmissionInvite();
		if(max_retrans > 0) {
			cdr.add(max_retrans, "max_retransmission_invite");
		}
	}
	
	list<string> billingAggregationsInserts;
	if(connect_time_us && billing && billing->isSet()) {
		double operator_price = 0; 
		double customer_price = 0;
		unsigned operator_currency_id = 0;
		unsigned customer_currency_id = 0;
		unsigned operator_id = 0;
		unsigned customer_id = 0;
		if(billing->billing(calltime_s(), connect_duration_s(),
				    getSipcallerip(), getSipcalledip(),
				    caller, called(),
				    caller_domain, called_domain(),
				    &operator_price, &customer_price,
				    &operator_currency_id, &customer_currency_id,
				    &operator_id, &customer_id)) {
			if(existsColumns.cdr_price_operator_mult1000000) {
				cdr.add(round(operator_price * 1000000), "price_operator_mult1000000", operator_id == 0);
			} else if(existsColumns.cdr_price_operator_mult100) {
				cdr.add(round(operator_price * 100), "price_operator_mult100", operator_id == 0);
			}
			if(existsColumns.cdr_price_customer_mult1000000) {
				cdr.add(round(customer_price * 1000000), "price_customer_mult1000000", customer_id == 0);
			} else if(existsColumns.cdr_price_customer_mult100) {
				cdr.add(round(customer_price * 100), "price_customer_mult100", customer_id == 0);
			}
			if(existsColumns.cdr_price_operator_currency_id) {
				cdr.add(operator_currency_id, "price_operator_currency_id", operator_currency_id == 0);
			}
			if(existsColumns.cdr_price_customer_currency_id) {
				cdr.add(customer_currency_id, "price_customer_currency_id", customer_currency_id == 0);
			}
			if(operator_price > 0 || customer_price > 0) {
				billing->saveAggregation(calltime_s(),
							 getSipcallerip(), getSipcalledip(),
							 caller, called(),
							 caller_domain, called_domain(),
							 operator_price, customer_price,
							 operator_currency_id, customer_currency_id,
							 &billingAggregationsInserts);
			}
		} else {
			if(existsColumns.cdr_price_operator_currency_id) {
				cdr.add(255, "price_operator_currency_id");
			}
			if(existsColumns.cdr_price_customer_currency_id) {
				cdr.add(255, "price_customer_currency_id");
			}
		}
	}
	
	if(getSpoolIndex() && existsColumns.cdr_next_spool_index) {
		cdr_next.add(getSpoolIndex(), "spool_index");
	}
	
	if(opt_cdr_country_code) {
		CountryDetectApplyReload();
		if(opt_cdr_country_code == 2) {
			cdr_country_code.add(getCountryIdByIP(getSipcallerip()), "sipcallerip_country_code");
			cdr_country_code.add(getCountryIdByIP(getSipcalledip()), "sipcalledip_country_code");
			cdr_country_code.add(getCountryIdByPhoneNumber(caller), "caller_number_country_code");
			cdr_country_code.add(getCountryIdByPhoneNumber(called()), "called_number_country_code");
		} else {
			cdr_country_code.add(getCountryByIP(getSipcallerip(), true), "sipcallerip_country_code");
			cdr_country_code.add(getCountryByIP(getSipcalledip(), true), "sipcalledip_country_code");
			cdr_country_code.add(getCountryByPhoneNumber(caller, true), "caller_number_country_code");
			cdr_country_code.add(getCountryByPhoneNumber(called(), true), "called_number_country_code");
		}
		if(existsColumns.cdr_country_code_calldate) {
			cdr_country_code.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_country_code_calldate_ms);
		}
	}
	
	adjustSipResponse(lastSIPresponse, 0);
	
	if(useChartsCacheInProcessCall() && sverb.charts_cache_only) {
		return(0);
	}
	
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		
		if(useSetId()) {
			cdr.add_cb_string(lastSIPresponse, "lastSIPresponse_id", cSqlDbCodebook::_cb_sip_response);
		} else {
			unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, lastSIPresponse, false, true);
			if(_cb_id) {
				cdr.add(_cb_id, "lastSIPresponse_id");
			} else {
				query_str += MYSQL_ADD_QUERY_END(string("set @lSresp_id = ") + 
					     "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")");
				cdr.add(MYSQL_VAR_PREFIX + "@lSresp_id", "lastSIPresponse_id");
				//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
			}
		}
		if(existsColumns.cdr_reason) {
			if(reason_sip_text.length()) {
				if(useSetId()) {
					cdr.add_cb_string(reason_sip_text, "reason_sip_text_id", cSqlDbCodebook::_cb_reason_sip);
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_reason_sip, reason_sip_text.c_str(), false, true);
					if(_cb_id) {
						cdr.add(_cb_id, "reason_sip_text_id");
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @r_sip_tid = ") + 
							     "getIdOrInsertREASON(1," + sqlEscapeStringBorder(reason_sip_text.c_str()) + ")");
						cdr.add(MYSQL_VAR_PREFIX + "@r_sip_tid", "reason_sip_text_id");
						//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertREASON(1," + sqlEscapeStringBorder(reason_sip_text.c_str()) + ")", "reason_sip_text_id");
					}
				}
			}
			if(reason_q850_text.length()) {
				if(useSetId()) {
					cdr.add_cb_string(reason_q850_text, "reason_q850_text_id", cSqlDbCodebook::_cb_reason_q850);
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_reason_q850, reason_q850_text.c_str(), false, true);
					if(_cb_id) {
						cdr.add(_cb_id, "reason_q850_text_id");
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @r_q850_tid = ") + 
							     "getIdOrInsertREASON(2," + sqlEscapeStringBorder(reason_q850_text.c_str()) + ")");
						cdr.add(MYSQL_VAR_PREFIX + "@r_q850_tid", "reason_q850_text_id");
						//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertREASON(2," + sqlEscapeStringBorder(reason_q850_text.c_str()) + ")", "reason_q850_text_id");
					}
				}
			}
		}
		if(opt_cdr_ua_enable) {
			if(a_ua[0]) {
				if(useSetId()) {
					cdr.add_cb_string(a_ua, "a_ua_id", cSqlDbCodebook::_cb_ua);
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, false, true);
					if(_cb_id) {
						cdr.add(_cb_id, "a_ua_id");
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @uaA_id = ") + 
							     "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")");
						cdr.add(MYSQL_VAR_PREFIX + "@uaA_id", "a_ua_id");
						//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
					}
				}
			}
			if(b_ua[0]) {
				if(useSetId()) {
					cdr.add_cb_string(b_ua, "b_ua_id", cSqlDbCodebook::_cb_ua);
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, b_ua, false, true);
					if(_cb_id) {
						cdr.add(_cb_id, "b_ua_id");
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @uaB_id = ") + 
							     "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")");
						cdr.add(MYSQL_VAR_PREFIX + "@uaB_id", "b_ua_id");
						//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
					}
				}
			}
		}
		
		extern int opt_cdr_check_exists_callid;
		extern string opt_cdr_check_unique_callid_in_sensors;
		extern list<int> opt_cdr_check_unique_callid_in_sensors_list;
		extern bool opt_cdr_check_duplicity_callid_in_next_pass_insert;
		string cdr_callid_lock_name;
		if(!useNewStore() &&
		   (opt_cdr_check_exists_callid ||
		    opt_cdr_check_unique_callid_in_sensors_list.size() ||
		    opt_cdr_check_duplicity_callid_in_next_pass_insert)) {
			// check if exists call-id & rtp records - begin if
			if(opt_cdr_check_exists_callid ||
			   opt_cdr_check_unique_callid_in_sensors_list.size()) {
				if(opt_cdr_check_exists_callid == 2) {
					cdr_callid_lock_name = "vm_cdr_callid_";
					if(opt_cdr_check_unique_callid_in_sensors_list.size()) {
						cdr_callid_lock_name += GetStringMD5(fbasename + opt_cdr_check_unique_callid_in_sensors);
					} else {
						cdr_callid_lock_name += GetStringMD5(fbasename);
					}
					query_str +=
						"do get_lock('" + cdr_callid_lock_name + "', 60);\n";
				}
				string condIdSensor;
				if(opt_cdr_check_unique_callid_in_sensors_list.size()) {
					string inSensors;
					bool nullSensor = false;
					for(list<int>::iterator iter = opt_cdr_check_unique_callid_in_sensors_list.begin();
					    iter != opt_cdr_check_unique_callid_in_sensors_list.end();
					    iter++) {
						if(*iter > -1) {
							if(!inSensors.empty()) {
								inSensors += ',';
							}
							inSensors += intToString(*iter);
						} else {
							nullSensor = true;
						}
					}
					if(!inSensors.empty()) {
						condIdSensor = "id_sensor in (" + inSensors + ")";
					}
					if(nullSensor) {
						string condNullSensor = "id_sensor is null";
						if(!condIdSensor.empty()) {
							condIdSensor = "(" + condIdSensor + " or " + condNullSensor + ")";
						} else {
							condIdSensor = condNullSensor;
						}
					}
				} else if(opt_cdr_check_exists_callid != 2) {
					condIdSensor = useSensorId > -1 ? 
							"id_sensor = " + intToString(useSensorId) : 
							"id_sensor is null";
				}
				query_str += string(
					"set @exists_call_id = coalesce(\n") +
					"(select cdr.ID from cdr\n" +
					" join cdr_next on (cdr_next.cdr_ID = cdr.ID and cdr_next.calldate = cdr.calldate)\n" +
					" where cdr.calldate > ('" + sqlDateTimeString(calltime_s()) + "' - interval 1 hour) and\n" +
					"       cdr.calldate < ('" + sqlDateTimeString(calltime_s()) + "' + interval 1 hour) and\n" +
					"       " + (!condIdSensor.empty() ? (condIdSensor + " and\n") : "") +
					"       fbasename = '" + sqlEscapeString(fbasename) + "' limit 1), 0);\n";
				query_str += string(
					"set @exists_rtp =\n") +
					"if(@exists_call_id,\n" +
					"   exists (select * from cdr_rtp where cdr_id = @exists_call_id),\n" +
					"   0);\n";
				bool existsRtp = false;
				for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
					if(rtp_i and rtp_i->s->received) {
						existsRtp = true;
						break;
					}
				}
				query_str += string(
					"if @exists_call_id and not @exists_rtp and ") + (existsRtp ? "1" : "0") + " then\n" +
					"  delete from cdr where id = @exists_call_id;\n" +
					"  delete from cdr_next where cdr_id = @exists_call_id;\n";
				if(custom_headers_cdr) {
					query_str += custom_headers_cdr->getDeleteQuery("@exists_call_id", "  ", ";\n");
				}
				query_str += string("") +
					(opt_cdr_country_code ? "  delete from cdr_country_code where cdr_id = @exists_call_id;\n" : "") +
					"  delete from cdr_rtp where cdr_id = @exists_call_id;\n" +
					(opt_save_energylevels ? "  delete from cdr_rtp_energylevels where cdr_id = @exists_call_id;\n" : "") +
					(enable_save_dtmf_db ? "  delete from cdr_dtmf where cdr_id = @exists_call_id;\n" : "") +
					"  delete from cdr_sipresp where cdr_id = @exists_call_id;\n" +
					(opt_pcap_dump_tar ? "  delete from cdr_tar_part where cdr_id = @exists_call_id;\n" : "") +
					"  set @exists_call_id = 0;\n" +
					"end if;\n";
				query_str += "if not @exists_call_id then\n";
			} else if(opt_cdr_check_duplicity_callid_in_next_pass_insert) {
				query_str += "__NEXT_PASS_QUERY_BEGIN__";
				query_str += string(
					"set @exists_call_id = coalesce(\n") +
					"(select cdr.ID from cdr\n" +
					" join cdr_next on (cdr_next.cdr_ID = cdr.ID and cdr_next.calldate = cdr.calldate)\n" +
					" where cdr.calldate > ('" + sqlDateTimeString(calltime_s()) + "' - interval 1 minute) and\n" +
					"       cdr.calldate < ('" + sqlDateTimeString(calltime_s()) + "' + interval 1 minute) and\n" +
					"       " + (useSensorId > -1 ? 
						      "id_sensor = " + intToString(useSensorId) : 
						      "id_sensor is null") + " and\n" +
					"       fbasename = '" + sqlEscapeString(fbasename) + "' limit 1), 0);\n";
				query_str += "if not @exists_call_id then\n";
				query_str += "__NEXT_PASS_QUERY_END__";
			}
		}
		
		if(useNewStore()) {
			if(useSetId()) {
				cdr.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "ID");
			} else {
				query_str += MYSQL_GET_MAIN_INSERT_ID_OLD;
			}
		}
		if(!useCsvStoreFormat()) {
			query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT + 
				     sqlDbSaveCall->insertQuery(sql_cdr_table, cdr));
		}
		if(useNewStore()) {
			if(!useSetId()) {
				query_str += MYSQL_GET_MAIN_INSERT_ID + 
					     MYSQL_IF_MAIN_INSERT_ID;
			}
		} else {
			query_str += "if row_count() > 0 then\n" +
				     MYSQL_GET_MAIN_INSERT_ID;
		}
		
		cdr_next.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
		if(useCsvStoreFormat()) {
			query_str += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_next") + cdr_next.implodeFields(",", "\"") + MYSQL_CSV_END +
				     MYSQL_MAIN_INSERT_CSV_ROW("cdr_next") + cdr_next.implodeContentTypeToCsv(true) + MYSQL_CSV_END;
		} else {
			query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
				     sqlDbSaveCall->insertQuery(sql_cdr_next_table, cdr_next));
		}
		
		if(!cdr_callid_lock_name.empty()) {
			query_str +=
				"do release_lock('" + cdr_callid_lock_name + "');\n";
		}
		
		bool existsNextCh = false;
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(cdr_next_ch_name[i][0]) {
				cdr_next_ch[i].add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER(cdr_next_ch_name[i]) + cdr_next_ch[i].implodeFields(",", "\"") + MYSQL_CSV_END +
						     MYSQL_MAIN_INSERT_CSV_ROW(cdr_next_ch_name[i]) + cdr_next_ch[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQuery(cdr_next_ch_name[i], cdr_next_ch[i]));
				}
				existsNextCh = true;
			}
		}
		if(existsNextCh && custom_headers_cdr) {
			if(useCsvStoreFormat()) {
				// TODO
			} else {
				string queryForSaveUseInfo = custom_headers_cdr->getQueryForSaveUseInfo(this, INVITE, NULL);
				if(!queryForSaveUseInfo.empty()) {
					vector<string> queryForSaveUseInfo_vect = split(queryForSaveUseInfo.c_str(), ";");
					for(unsigned i = 0; i < queryForSaveUseInfo_vect.size(); i++) {
						query_str += MYSQL_ADD_QUERY_END(queryForSaveUseInfo_vect[i]);
					}
				}
			}
		}
		
		if(opt_cdr_country_code) {
			cdr_country_code.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
			if(useCsvStoreFormat()) {
				query_str += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_country_code") + cdr_country_code.implodeFields(",", "\"") + MYSQL_CSV_END +
					     MYSQL_MAIN_INSERT_CSV_ROW("cdr_country_code") + cdr_country_code.implodeContentTypeToCsv(true) + MYSQL_CSV_END;
			} else {
				query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
					     sqlDbSaveCall->insertQuery("cdr_country_code", cdr_country_code));
			}
		}

		if(!useNewStore() &&
		   (sql_cdr_table_last30d[0] ||
		    sql_cdr_table_last7d[0] ||
		    sql_cdr_table_last1d[0])) {
			cdr.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "ID");
			if(sql_cdr_table_last30d[0]) {
				query_str += sqlDbSaveCall->insertQuery(sql_cdr_table_last30d, cdr) + ";\n";
			}
			if(sql_cdr_table_last7d[0]) {
				query_str += sqlDbSaveCall->insertQuery(sql_cdr_table_last7d, cdr) + ";\n";
			}
			if(sql_cdr_table_last1d[0]) {
				query_str += sqlDbSaveCall->insertQuery(sql_cdr_table_last1d, cdr) + ";\n";
			}
		}

		query_str += query_str_cdrproxy;

		vector<SqlDb_row> rtp_rows;
		for(unsigned ir = 0; ir < rtp_rows_count; ir++) {
			int i = rtp_rows_indexes[ir];
			RTP *rtp_i = rtp_stream_by_index(i);
			double stime = TIME_US_TO_SF(this->first_packet_time_us);
			double rtime = TIME_US_TO_SF(rtp_i->first_packet_time_us);
			double diff = rtime - stime;

			SqlDb_row rtps;
			rtps.setIgnoreCheckExistsField();
			rtps.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
			if(rtp_i->first_codec >= 0) {
				rtps.add(rtp_i->first_codec, "payload");
			} else {
				rtps.add(0, "payload", true);
			}
			rtps.add(rtp_i->saddr, "saddr", false, sqlDbSaveCall, sql_cdr_rtp_table.c_str());
			rtps.add(rtp_i->daddr, "daddr", false, sqlDbSaveCall, sql_cdr_rtp_table.c_str());
			if(existsColumns.cdr_rtp_sport) {
				rtps.add(rtp_i->sport.getPort(), "sport");
			}
			if(existsColumns.cdr_rtp_dport) {
				rtps.add(rtp_i->dport.getPort(), "dport");
			}
			rtps.add(rtp_i->ssrc, "ssrc");
			if(rtp_i->s->received > 0 || rtp_i->first_codec < 0) {
				rtps.add(rtp_i->s->received + (rtp_i->first_codec >= 0 ? 2 : 0), "received");
			} else {
				rtps.add(0, "received", true);
			}
			rtps.add(rtp_i->stats.lost, "loss");
			rtps.add((unsigned int)(rtp_i->stats.maxjitter * 10), "maxjitter_mult10");
			rtps.add(diff, "firsttime");
			if(existsColumns.cdr_rtp_index) {
				rtps.add(i + 1, "index");
			}
			if(existsColumns.cdr_rtp_flags) {
				u_int64_t flags = 0;
				if(rtp_i->stream_in_multiple_calls) {
					flags |= CDR_RTP_STREAM_IN_MULTIPLE_CALLS;
				}
				// mark used rtp stream in a/b
				if (rtp_stream_by_index(i) == rtpab[0] or rtp_stream_by_index(i) == rtpab[1]) {
					flags |= CDR_RTP_STREAM_IS_AB;
				}
				flags |= rtp_i->iscaller ? CDR_RTP_STREAM_IS_CALLER : CDR_RTP_STREAM_IS_CALLED;
				rtps.add(flags, "flags", !flags);
			}
			if(existsColumns.cdr_rtp_duration) {
				double ltime = TIME_US_TO_SF(rtp_i->last_packet_time_us);
				double duration = ltime - rtime;
				rtps.add(duration, "duration");
			}
			if(existsColumns.cdr_rtp_calldate) {
				rtps.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_rtp_calldate_ms);
			}
			if(opt_mysql_enable_multiple_rows_insert) {
				rtp_rows.push_back(rtps);
			} else {
				query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
					     sqlDbSaveCall->insertQuery(sql_cdr_rtp_table, rtps));
			}
		}
		if(opt_mysql_enable_multiple_rows_insert && rtp_rows.size()) {
			if(useCsvStoreFormat()) {
				query_str += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_rtp") + rtp_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
				for(unsigned i = 0; i < rtp_rows.size(); i++) {
					query_str += MYSQL_MAIN_INSERT_CSV_ROW("cdr_rtp") + rtp_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
				}
			} else {
				query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
					     sqlDbSaveCall->insertQueryWithLimitMultiInsert(sql_cdr_rtp_table, &rtp_rows, opt_mysql_max_multiple_rows_insert, 
											    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
			}
		}
		
		if(opt_save_energylevels) {
			vector<SqlDb_row> rtp_el_rows;
			for(unsigned ir = 0; ir < rtp_rows_count; ir++) {
				int i = rtp_rows_indexes[ir];
				RTP *rtp_i = rtp_stream_by_index(i);
				if(rtp_i->energylevels && rtp_i->energylevels->size()) {
					u_int32_t data_el_length = rtp_i->energylevels->size();
					u_char *data_el = rtp_i->energylevels->data();
					cGzip *zip = new FILE_LINE(0) cGzip;
					size_t data_el_zip_length;
					u_char *data_el_zip;
					if(zip->compress(data_el, data_el_length, &data_el_zip, &data_el_zip_length) && data_el_zip_length > 0) {
						SqlDb_row rtp_el;
						rtp_el.setIgnoreCheckExistsField();
						rtp_el.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
						rtp_el.add(i + 1, "index");
						rtp_el.add(MYSQL_VAR_PREFIX +
							   "from_base64('" + 
							   base64_encode((u_char*)data_el_zip, data_el_zip_length) +
							   "')",
							   "energylevels");
						/*
						string data_el_zip_e = _sqlEscapeString((char*)data_el_zip, data_el_zip_length, NULL);
						rtp_el.add(data_el_zip_e, "energylevels");
						*/
						if(existsColumns.cdr_rtp_energylevels_calldate) {
							rtp_el.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_rtp_energylevels_calldate_ms);
						}
						if(opt_mysql_enable_multiple_rows_insert) {
							rtp_el_rows.push_back(rtp_el);
						} else {
							query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
								     sqlDbSaveCall->insertQuery(sql_cdr_rtp_energylevels_table, rtp_el));
						}
						delete [] data_el_zip;
					}
					delete zip;
					delete [] data_el;
				}
			}
			if(opt_mysql_enable_multiple_rows_insert && rtp_el_rows.size()) {
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_rtp_energylevels") + rtp_el_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
					for(unsigned i = 0; i < rtp_el_rows.size(); i++) {
						query_str += MYSQL_MAIN_INSERT_CSV_ROW("cdr_rtp_energylevels") + rtp_el_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					}
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQueryWithLimitMultiInsert(sql_cdr_rtp_energylevels_table, &rtp_el_rows, opt_mysql_max_multiple_rows_insert, 
												    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
				}
			}
		}
		
		if(opt_save_sdp_ipport) {
			vector<SqlDb_row> sdp_rows;
			if(sdp_rows_list.size()) {
				for(vector<d_item2<vmIPport, bool> >::iterator iter = sdp_rows_list.begin(); iter != sdp_rows_list.end(); iter++) {
					SqlDb_row sdp;
					sdp.setIgnoreCheckExistsField();
					sdp.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
					sdp.add(iter->item1.ip, "ip", false, sqlDbSaveCall, sql_cdr_sdp_table.c_str());
					sdp.add(iter->item1.port.getPort(), "port");
					sdp.add(iter->item2, "is_caller");
					if(existsColumns.cdr_sdp_calldate) {
						sdp.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_sdp_calldate_ms);
					}
					if(opt_mysql_enable_multiple_rows_insert) {
						sdp_rows.push_back(sdp);
					} else {
						query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
							     sqlDbSaveCall->insertQuery(sql_cdr_sdp_table, sdp));
					}
				}
			}
			if(opt_mysql_enable_multiple_rows_insert && sdp_rows.size()) {
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER(sql_cdr_sdp_table) + sdp_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
					for(unsigned i = 0; i < sdp_rows.size(); i++) {
						query_str += MYSQL_MAIN_INSERT_CSV_ROW(sql_cdr_sdp_table) + sdp_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					}
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQueryWithLimitMultiInsert(sql_cdr_sdp_table, &sdp_rows, opt_mysql_max_multiple_rows_insert, 
												    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
				}
			}
		}
		
		if(txt.size()) {
			vector<SqlDb_row> txt_rows;
			for(list<sTxt>::iterator iter = txt.begin(); iter != txt.end(); iter++) {
				SqlDb_row txt;
				txt.setIgnoreCheckExistsField();
				txt.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
				txt.add(iter->time - this->first_packet_time_us, "time");
				txt.add(iter->type, "type");
				txt.add(sqlEscapeString(iter->txt), "content");
				if(existsColumns.cdr_txt_calldate) {
					txt.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_txt_calldate_ms);
				}
				if(opt_mysql_enable_multiple_rows_insert) {
					txt_rows.push_back(txt);
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
						     sqlDbSaveCall->insertQuery(sql_cdr_txt_table, txt));
				}
			}
			if(opt_mysql_enable_multiple_rows_insert && txt_rows.size()) {
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER(sql_cdr_txt_table) + txt_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
					for(unsigned i = 0; i < txt_rows.size(); i++) {
						query_str += MYSQL_MAIN_INSERT_CSV_ROW(sql_cdr_txt_table) + txt_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					}
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQueryWithLimitMultiInsert(sql_cdr_txt_table, &txt_rows, opt_mysql_max_multiple_rows_insert, 
												    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
				}
			}
		}

		if(enable_save_dtmf_db) {
			vector<SqlDb_row> dtmf_rows;
			while(dtmf_history.size()) {
				s_dtmf q;
				q = dtmf_history.front();
				dtmf_history.pop();
				SqlDb_row dtmf;
				dtmf.setIgnoreCheckExistsField();
				string tmp;
				tmp = q.dtmf;
				dtmf.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
				dtmf.add(q.saddr, "saddr", false, sqlDbSaveCall, sql_cdr_dtmf_table.c_str());
				dtmf.add(q.daddr, "daddr", false, sqlDbSaveCall, sql_cdr_dtmf_table.c_str());
				dtmf.add(sqlEscapeString(tmp), "dtmf");
				dtmf.add(q.ts, "firsttime");
				if(existsColumns.cdr_dtmf_type) {
					dtmf.add(q.type, "type");
				}
				if(existsColumns.cdr_dtmf_calldate) {
					dtmf.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_dtmf_calldate_ms);
				}
				if(opt_mysql_enable_multiple_rows_insert) {
					dtmf_rows.push_back(dtmf);
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
						     sqlDbSaveCall->insertQuery(sql_cdr_dtmf_table, dtmf));
				}
			}
			if(opt_mysql_enable_multiple_rows_insert && dtmf_rows.size()) {
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER(sql_cdr_dtmf_table) + dtmf_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
					for(unsigned i = 0; i < dtmf_rows.size(); i++) {
						query_str += MYSQL_MAIN_INSERT_CSV_ROW(sql_cdr_dtmf_table) + dtmf_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					}
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQueryWithLimitMultiInsert(sql_cdr_dtmf_table, &dtmf_rows, opt_mysql_max_multiple_rows_insert, 
												    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
				}
			}
		}

		extern bool opt_cdr_sipresp;	
		if(opt_cdr_sipresp) {
			vector<SqlDb_row> sipresp_rows;
			for(list<sSipResponse>::iterator iterSiprespUnique = SIPresponseUnique.begin(); iterSiprespUnique != SIPresponseUnique.end(); iterSiprespUnique++) {
				bool enableMultiInsert = true;
				SqlDb_row sipresp;
				sipresp.setIgnoreCheckExistsField();
				sipresp.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
				if(useSetId()) {
					sipresp.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_sip_response, iterSiprespUnique->SIPresponse), "SIPresponse_id");
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, iterSiprespUnique->SIPresponse.c_str(), false, true);
					if(_cb_id) {
						sipresp.add(_cb_id, "SIPresponse_id");
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @sip_resp_id = ") + 
							     "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(iterSiprespUnique->SIPresponse.c_str()) + ")");
						sipresp.add(MYSQL_VAR_PREFIX + "@sip_resp_id", "SIPresponse_id");
						//sipresp.add(MYSQL_VAR_PREFIX + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(iterSiprespUnique->SIPresponse.c_str()) + ")", "SIPresponse_id");
						enableMultiInsert = false;
					}
				}
				sipresp.add(iterSiprespUnique->SIPresponseNum, "SIPresponseNum");
				if(existsColumns.cdr_sipresp_calldate) {
					sipresp.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_sipresp_calldate_ms);
				}
				if(opt_mysql_enable_multiple_rows_insert && enableMultiInsert) {
					sipresp_rows.push_back(sipresp);
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
						     sqlDbSaveCall->insertQuery("cdr_sipresp", sipresp));
				}
			}
			if(opt_mysql_enable_multiple_rows_insert && sipresp_rows.size()) {
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_sipresp") + sipresp_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
					for(unsigned i = 0; i < sipresp_rows.size(); i++) {
						query_str += MYSQL_MAIN_INSERT_CSV_ROW("cdr_sipresp") + sipresp_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					}
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQueryWithLimitMultiInsert("cdr_sipresp", &sipresp_rows, opt_mysql_max_multiple_rows_insert, 
												    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
				}
			}
		}
		
		if(_save_sip_history) {
			vector<SqlDb_row> siphist_rows;
			for(list<sSipHistory>::iterator iterSiphistory = SIPhistory.begin(); iterSiphistory != SIPhistory.end(); iterSiphistory++) {
				bool enableMultiInsert = true;
				SqlDb_row siphist;
				siphist.setIgnoreCheckExistsField();
				siphist.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
				siphist.add(iterSiphistory->time_us - first_packet_time_us, "time");
				if(iterSiphistory->SIPrequest.length()) {
					if(useSetId()) {
						siphist.add_cb_string(iterSiphistory->SIPrequest, "SIPrequest_id", cSqlDbCodebook::_cb_sip_request);
					} else {
						unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_request, iterSiphistory->SIPrequest.c_str(), false, true);
						if(_cb_id) {
							siphist.add(_cb_id, "SIPrequest_id");
						} else {
							query_str += MYSQL_ADD_QUERY_END(string("set @sip_req_id = ") + 
								     "getIdOrInsertSIPREQUEST(" + sqlEscapeStringBorder(iterSiphistory->SIPrequest.c_str()) + ")");
							siphist.add(MYSQL_VAR_PREFIX + "@sip_req_id", "SIPrequest_id");
							//siphist.add(MYSQL_VAR_PREFIX + "getIdOrInsertSIPREQUEST(" + sqlEscapeStringBorder(iterSiphistory->SIPrequest.c_str()) + ")", "SIPrequest_id");
							enableMultiInsert = false;
						}
					}
				} else {
					siphist.add((const char*)NULL, "SIPrequest_id");
				}
				if(iterSiphistory->SIPresponseNum && iterSiphistory->SIPresponse.length()) {
					siphist.add(iterSiphistory->SIPresponseNum, "SIPresponseNum");
					if(useSetId()) {
						siphist.add_cb_string(iterSiphistory->SIPresponse, "SIPresponse_id", cSqlDbCodebook::_cb_sip_response);
					} else {
						unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, iterSiphistory->SIPresponse.c_str(), false, true);
						if(_cb_id) {
							siphist.add(_cb_id, "SIPresponse_id");
						} else {
							query_str += MYSQL_ADD_QUERY_END(string("set @sip_resp_id = ") + 
								     "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(iterSiphistory->SIPresponse.c_str()) + ")");
							siphist.add(MYSQL_VAR_PREFIX + "@sip_resp_id", "SIPresponse_id");
							//siphist.add(MYSQL_VAR_PREFIX + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(iterSiphistory->SIPresponse.c_str()) + ")", "SIPresponse_id");
							enableMultiInsert = false;
						}
					}
				} else {
					siphist.add((const char*)NULL, "SIPresponseNum");
					siphist.add((const char*)NULL, "SIPresponse_id");
				}
				if(existsColumns.cdr_siphistory_calldate) {
					siphist.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_siphistory_calldate_ms);
				}
				if(opt_mysql_enable_multiple_rows_insert && enableMultiInsert/* && indexMultiInsert*/) {
					siphist_rows.push_back(siphist);
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
						     sqlDbSaveCall->insertQuery("cdr_siphistory", siphist));
				}
			}
			if(opt_mysql_enable_multiple_rows_insert && siphist_rows.size()) {
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_siphistory") + siphist_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
					for(unsigned i = 0; i < siphist_rows.size(); i++) {
						query_str += MYSQL_MAIN_INSERT_CSV_ROW("cdr_siphistory") + siphist_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					}
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQueryWithLimitMultiInsert("cdr_siphistory", &siphist_rows, opt_mysql_max_multiple_rows_insert, 
												    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
				}
			}
		}
		
		if(opt_pcap_dump_tar) {
			vector<SqlDb_row> tar_part_rows;
			for(int i = 1; i <= 3; i++) {
				if(!(i == 1 ? opt_pcap_dump_tar_sip_use_pos :
				     i == 2 ? opt_pcap_dump_tar_rtp_use_pos :
					      opt_pcap_dump_tar_graph_use_pos)) {
					continue;
				}
				list<u_int64_t> *tarPos = i == 1 ? &this->tarPosSip :
							  i == 2 ? &this->tarPosRtp :
								   &this->tarPosGraph;
				for(list<u_int64_t>::iterator it = tarPos->begin(); it != tarPos->end(); it++) {
					SqlDb_row tar_part;
					tar_part.setIgnoreCheckExistsField();
					tar_part.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "cdr_ID");
					tar_part.add(i, "type");
					tar_part.add(*it, "pos");
					if(existsColumns.cdr_tar_part_calldate) {
						tar_part.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_tar_part_calldate_ms);
					}
					if(opt_mysql_enable_multiple_rows_insert) {
						tar_part_rows.push_back(tar_part);
					} else {
						query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT + 
							     sqlDbSaveCall->insertQuery("cdr_tar_part", tar_part));
					}
				}
			}
			if(opt_mysql_enable_multiple_rows_insert && tar_part_rows.size()) {
				if(useCsvStoreFormat()) {
					query_str += MYSQL_MAIN_INSERT_CSV_HEADER("cdr_tar_part") + tar_part_rows[0].implodeFields(",", "\"") + MYSQL_CSV_END;
					for(unsigned i = 0; i < tar_part_rows.size(); i++) {
						query_str += MYSQL_MAIN_INSERT_CSV_ROW("cdr_tar_part") + tar_part_rows[i].implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					}
				} else {
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveCall->insertQueryWithLimitMultiInsert("cdr_tar_part", &tar_part_rows, opt_mysql_max_multiple_rows_insert, 
												    MYSQL_QUERY_END.c_str(), MYSQL_QUERY_END_SUBST.c_str()), false);
				}
			}
		}
		
		if(billingAggregationsInserts.size()) {
			if(useCsvStoreFormat()) {
				// TODO
			} else {
				for(list<string>::iterator iter = billingAggregationsInserts.begin(); iter != billingAggregationsInserts.end(); iter++) {
					query_str += MYSQL_ADD_QUERY_END(*iter);
				}
			}
		}
		
		if(useNewStore()) {
			if(!useSetId()) {
				query_str += MYSQL_ENDIF_QE;
			}
		} else {
			query_str += "end if";
		}
		
		if(!useNewStore() &&
		   (opt_cdr_check_exists_callid ||
		    opt_cdr_check_unique_callid_in_sensors_list.size() ||
		    opt_cdr_check_duplicity_callid_in_next_pass_insert)) {
			// check if exists call-id & rtp records - end if
			if(opt_cdr_check_exists_callid ||
			   opt_cdr_check_unique_callid_in_sensors_list.size()) {
				query_str += ";\nend if";
				if(!cdr_callid_lock_name.empty()) {
					query_str +=
						";\ndo release_lock('" + cdr_callid_lock_name + "')";
				}
			} else if(opt_cdr_check_duplicity_callid_in_next_pass_insert) {
				query_str += "__NEXT_PASS_QUERY_BEGIN__";
				query_str += ";\nend if";
				query_str += "__NEXT_PASS_QUERY_END__";
			}
		}
		
		static unsigned int counterSqlStore = 0;
		int storeId2 = opt_mysqlstore_max_threads_cdr > 1 &&
			       sqlStore->getSize(STORE_PROC_ID_CDR, 0) > 1000 ? 
				counterSqlStore % opt_mysqlstore_max_threads_cdr : 
				0;
		++counterSqlStore;
		if(!sverb.suppress_cdr_insert) {
			if(useCsvStoreFormat()) {
				if(existsChartsCacheServer()) {
					SqlDb_row::SqlDb_rowField *f_store_flags = cdr.add(_sf_db, "store_flags");
					string query_str_cdr = MYSQL_MAIN_INSERT_CSV_HEADER("cdr") + cdr.implodeFields(",", "\"") + MYSQL_CSV_END +
							       MYSQL_MAIN_INSERT_CSV_ROW("cdr") + cdr.implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					sqlStore->query_lock((query_str_cdr + query_str).c_str(), STORE_PROC_ID_CDR, storeId2);
					f_store_flags->content = intToString(_sf_charts_cache);
					f_store_flags->ifv.v._int = _sf_charts_cache;
					query_str_cdr = MYSQL_MAIN_INSERT_CSV_HEADER("cdr") + cdr.implodeFields(",", "\"") + MYSQL_CSV_END +
							MYSQL_MAIN_INSERT_CSV_ROW("cdr") + cdr.implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					sqlStore->query_lock((query_str_cdr + query_str).c_str(),
							     STORE_PROC_ID_CHARTS_CACHE,
							     opt_mysqlstore_max_threads_charts_cache > 1 &&
							     sqlStore->getSize(STORE_PROC_ID_CHARTS_CACHE, 0) > 1000 ? 
							      counterSqlStore % opt_mysqlstore_max_threads_charts_cache : 
							      0);
				} else {
					cdr.add(_sf_db | (useChartsCacheInStore() ? _sf_charts_cache : 0), "store_flags");
					string query_str_cdr = MYSQL_MAIN_INSERT_CSV_HEADER("cdr") + cdr.implodeFields(",", "\"") + MYSQL_CSV_END +
							       MYSQL_MAIN_INSERT_CSV_ROW("cdr") + cdr.implodeContentTypeToCsv(true) + MYSQL_CSV_END;
					sqlStore->query_lock((query_str_cdr + query_str).c_str(), STORE_PROC_ID_CDR, storeId2);
				}
			} else {
				sqlStore->query_lock(query_str.c_str(), STORE_PROC_ID_CDR, storeId2);
			}
		}
		
		//cout << endl << endl << query_str << endl << endl << endl;
		return(0);
	}

	lastSIPresponse_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, lastSIPresponse, true);
	if(existsColumns.cdr_reason) {
		if(reason_sip_text.length()) {
			reason_sip_id = dbData->getCbId(cSqlDbCodebook::_cb_reason_sip, reason_sip_text.c_str(), true);
		}
		if(reason_q850_text.length()) {
			reason_q850_id = dbData->getCbId(cSqlDbCodebook::_cb_reason_q850, reason_q850_text.c_str(), true);
		}
	}
	if(a_ua[0]) {
		a_ua_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, true);
	}
	if(b_ua[0]) {
		b_ua_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, b_ua, true);
	}

	/*
	cdr.add(caller_id, "caller_id", true);
	cdr.add(called_id, "called_id", true);
	cdr.add(callername_id, "callername_id", true);
	cdr.add(caller_domain_id, "caller_domain_id", true);
	cdr.add(called_domain_id, "called_domain_id", true);
	*/
	
	cdr.add(lastSIPresponse_id, "lastSIPresponse_id", true);
	if(existsColumns.cdr_reason) {
		cdr.add(reason_sip_id, "reason_sip_text_id", true);
		cdr.add(reason_q850_id, "reason_q850_text_id", true);
	}
	cdr.add(a_ua_id, "a_ua_id", true);
	cdr.add(b_ua_id, "b_ua_id", true);
	
	int64_t cdrID = sqlDbSaveCall->insert(sql_cdr_table, cdr);
	if (is_read_from_file_simple()) {
		ostringstream outStr;
		outStr << "Found new call. Added to db with cdr.ID:" << cdrID ;
		cout << outStr.str() << endl;
	}

	if(cdrID > 0) {

		if(opt_cdrproxy) {
			set<vmIP> proxies_undup;
			this->proxies_undup(&proxies_undup);
			set<vmIP>::iterator iter_undup = proxies_undup.begin();
			while(iter_undup != proxies_undup.end()) {
				if(*iter_undup == sipcalledip_rslt) { ++iter_undup; continue; }
				SqlDb_row cdrproxy;
				cdrproxy.add(cdrID, "cdr_ID");
				cdrproxy.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_proxy_calldate_ms);
				cdrproxy.add((vmIP)(*iter_undup), "dst", false, sqlDbSaveCall, sql_cdr_proxy_table.c_str());
				sqlDbSaveCall->insert(sql_cdr_proxy_table, cdrproxy);
				++iter_undup;
			}
		}

		for(unsigned ir = 0; ir < rtp_rows_count; ir++) {
			int i = rtp_rows_indexes[ir];
			RTP *rtp_i = rtp_stream_by_index(i);
			double stime = TIME_US_TO_SF(this->first_packet_time_us);
			double rtime = TIME_US_TO_SF(rtp_i->first_packet_time_us);
			double diff = rtime - stime;
			SqlDb_row rtps;
			rtps.add(cdrID, "cdr_ID");
			if(rtp_i->first_codec >= 0) {
				rtps.add(rtp_i->first_codec, "payload");
			} else {
				rtps.add(0, "payload", true);
			}
			rtps.add(rtp_i->saddr, "saddr", false, sqlDbSaveCall, sql_cdr_rtp_table.c_str());
			rtps.add(rtp_i->daddr, "daddr", false, sqlDbSaveCall, sql_cdr_rtp_table.c_str());
			if(existsColumns.cdr_rtp_sport) {
				rtps.add(rtp_i->sport.getPort(), "sport");
			}
			if(existsColumns.cdr_rtp_dport) {
				rtps.add(rtp_i->dport.getPort(), "dport");
			}
			rtps.add(rtp_i->ssrc, "ssrc");
			if(rtp_i->s->received > 0 || rtp_i->first_codec < 0) {
				rtps.add(rtp_i->s->received + (rtp_i->first_codec >= 0 ? 2 : 0), "received");
			} else {
				rtps.add(0, "received", true);
			}
			rtps.add(rtp_i->stats.lost, "loss");
			rtps.add((unsigned int)(rtp_i->stats.maxjitter * 10), "maxjitter_mult10");
			rtps.add(diff, "firsttime");
			if(existsColumns.cdr_rtp_index) {
				rtps.add(i + 1, "index");
			}
			if(existsColumns.cdr_rtp_flags) {
				u_int64_t flags = 0;
				if(rtp_i->stream_in_multiple_calls) {
					flags |= CDR_RTP_STREAM_IN_MULTIPLE_CALLS;
				}
				// mark used rtp stream in a/b
				if (rtp_i == rtpab[0] or rtp_i == rtpab[1]) {
					flags |= CDR_RTP_STREAM_IS_AB;
				}
				flags |= rtp_i->iscaller ? CDR_RTP_STREAM_IS_CALLER : CDR_RTP_STREAM_IS_CALLED;
				if(flags) {
					rtps.add(flags, "flags");
				}
			}
			if(existsColumns.cdr_rtp_duration) {
				double ltime = TIME_US_TO_SF(rtp_i->last_packet_time_us);
				double duration = ltime - rtime;
				rtps.add(duration, "duration");
			}
			if(existsColumns.cdr_rtp_calldate) {
				rtps.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_rtp_calldate_ms);
			}
			sqlDbSaveCall->insert(sql_cdr_rtp_table, rtps);
		}
		
		if(opt_save_energylevels) {
			for(unsigned ir = 0; ir < rtp_rows_count; ir++) {
				int i = rtp_rows_indexes[ir];
				RTP *rtp_i = rtp_stream_by_index(i);
				if(rtp_i->energylevels && rtp_i->energylevels->size()) {
					u_int32_t data_el_length = rtp_i->energylevels->size();
					u_char *data_el = rtp_i->energylevels->data();
					cGzip *zip = new FILE_LINE(0) cGzip;
					size_t data_el_zip_length;
					u_char *data_el_zip;
					if(zip->compress(data_el, data_el_length, &data_el_zip, &data_el_zip_length) && data_el_zip_length > 0) {
						SqlDb_row rtp_el;
						rtp_el.add(cdrID, "cdr_ID");
						rtp_el.add(i + 1, "index");
						rtp_el.add(MYSQL_VAR_PREFIX +
							   "from_base64('" + 
							   base64_encode((u_char*)data_el_zip, data_el_zip_length) + 
							   "')",
							   "energylevels");
						/*
						string data_el_zip_e = _sqlEscapeString((char*)data_el_zip, data_el_zip_length, NULL);
						rtp_el.add(data_el_zip_e, "energylevels");
						*/
						if(existsColumns.cdr_rtp_energylevels_calldate) {
							rtp_el.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_rtp_energylevels_calldate_ms);
						}
						sqlDbSaveCall->insert(sql_cdr_rtp_energylevels_table, rtp_el);
						delete [] data_el_zip;
					}
					delete zip;
					delete [] data_el;
				}
			}
		}

		if(opt_save_sdp_ipport) {
			if(sdp_rows_list.size()) {
				for(vector<d_item2<vmIPport, bool> >::iterator iter = sdp_rows_list.begin(); iter != sdp_rows_list.end(); iter++) {
					SqlDb_row sdp;
					sdp.add(cdrID, "cdr_ID");
					sdp.add(iter->item1.ip, "ip", false, sqlDbSaveCall, sql_cdr_sdp_table.c_str());
					sdp.add(iter->item1.port.getPort(), "port");
					sdp.add(iter->item2, "is_caller");
					if(existsColumns.cdr_sdp_calldate) {
						sdp.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_sdp_calldate_ms);
					}
					sqlDbSaveCall->insert(sql_cdr_sdp_table, sdp);
				}
			}
		}
		
		if(txt.size()) {
			for(list<sTxt>::iterator iter = txt.begin(); iter != txt.end(); iter++) {
				SqlDb_row txt;
				txt.add(cdrID, "cdr_ID");
				txt.add(iter->time - this->first_packet_time_us, "time");
				txt.add(iter->type, "type");
				txt.add(sqlEscapeString(iter->txt), "content");
				if(existsColumns.cdr_txt_calldate) {
					txt.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_txt_calldate_ms);
				}
				sqlDbSaveCall->insert(sql_cdr_txt_table, txt);
			}
		}
		
		if(enable_save_dtmf_db) {
			while(dtmf_history.size()) {
				s_dtmf q;
				q = dtmf_history.front();
				dtmf_history.pop();

				SqlDb_row dtmf;
				string tmp;
				tmp = q.dtmf;
				dtmf.add(cdrID, "cdr_ID");
				dtmf.add(q.saddr, "saddr", false, sqlDbSaveCall, sql_cdr_dtmf_table.c_str());
				dtmf.add(q.daddr, "daddr", false, sqlDbSaveCall, sql_cdr_dtmf_table.c_str());
				dtmf.add(tmp, "dtmf");
				dtmf.add(q.ts, "firsttime");
				if(existsColumns.cdr_dtmf_type) {
					dtmf.add(q.type, "type");
				}
				if(existsColumns.cdr_dtmf_calldate) {
					dtmf.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_dtmf_calldate_ms);
				}
				sqlDbSaveCall->insert(sql_cdr_dtmf_table, dtmf);
			}
		}
		
		for(list<sSipResponse>::iterator iterSiprespUnique = SIPresponseUnique.begin(); iterSiprespUnique != SIPresponseUnique.end(); iterSiprespUnique++) {
			SqlDb_row sipresp;
			sipresp.add(cdrID, "cdr_ID");
			sipresp.add(dbData->getCbId(cSqlDbCodebook::_cb_sip_response, iterSiprespUnique->SIPresponse.c_str(), true), "SIPresponse_id");
			sipresp.add(iterSiprespUnique->SIPresponseNum, "SIPresponseNum");
			if(existsColumns.cdr_sipresp_calldate) {
				sipresp.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_sipresp_calldate_ms);
			}
			sqlDbSaveCall->insert("cdr_sipresp", sipresp);
		}

		if(_save_sip_history) {
			for(list<sSipHistory>::iterator iterSiphistory = SIPhistory.begin(); iterSiphistory != SIPhistory.end(); iterSiphistory++) {
				SqlDb_row siphist;
				siphist.add(cdrID, "cdr_ID");
				siphist.add(iterSiphistory->time_us - first_packet_time_us, "time");
				if(iterSiphistory->SIPrequest.length()) {
					 siphist.add(dbData->getCbId(cSqlDbCodebook::_cb_sip_request, iterSiphistory->SIPrequest.c_str(), true), "SIPrequest_id");
				}
				if(iterSiphistory->SIPresponseNum && iterSiphistory->SIPresponse.length()) {
					 siphist.add(iterSiphistory->SIPresponseNum, "SIPresponseNum");
					 siphist.add(dbData->getCbId(cSqlDbCodebook::_cb_sip_response, iterSiphistory->SIPresponse.c_str(), true), "SIPresponse_id");
				}
				if(existsColumns.cdr_siphistory_calldate) {
					siphist.add_calldate(calltime_us(), "calldate", existsColumns.cdr_child_siphistory_calldate_ms);
				}
				sqlDbSaveCall->insert("cdr_siphistory", siphist);
			}
		}
		
		if(billingAggregationsInserts.size()) {
			for(list<string>::iterator iter = billingAggregationsInserts.begin(); iter != billingAggregationsInserts.end(); iter++) {
				sqlDbSaveCall->query(*iter);
			}
		}
		
		if(opt_printinsertid) {
			printf("CDRID:%" int_64_format_prefix "li\n", cdrID);
		}

		cdr_next.add(cdrID, "cdr_ID");
		sqlDbSaveCall->insert(sql_cdr_next_table, cdr_next);
		
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(cdr_next_ch_name[i][0]) {
				cdr_next_ch[i].add(cdrID, "cdr_ID");
				sqlDbSaveCall->insert(cdr_next_ch_name[i], cdr_next_ch[i]);
			}
		}
		
		if(opt_cdr_country_code) {
			cdr_country_code.add(cdrID, "cdr_ID");
			sqlDbSaveCall->insert("cdr_country_code", cdr_country_code);
		}
		
		if(sql_cdr_table_last30d[0] ||
		   sql_cdr_table_last7d[0] ||
		   sql_cdr_table_last1d[0]) {
			cdr.add(cdrID, "ID");
			if(sql_cdr_table_last30d[0]) {
				sqlDbSaveCall->insert(sql_cdr_table_last30d, cdr);
			}
			if(sql_cdr_table_last7d[0]) {
				sqlDbSaveCall->insert(sql_cdr_table_last7d, cdr);
			}
			if(sql_cdr_table_last1d[0]) {
				sqlDbSaveCall->insert(sql_cdr_table_last1d, cdr);
			}
		}
	}
	
	return(cdrID <= 0);
}

int
Call::saveAloneByeToDb(bool enableBatchIfPossible) {
	if(lastSIPresponseNum != 481 ||
	   !existsColumns.cdr_next_calldate ||
	   !existsColumns.cdr_flags) {
		return(0);
	}
	
	if(!sqlDbSaveCall) {
		sqlDbSaveCall = createSqlObject();
		sqlDbSaveCall->setEnableSqlStringInContent(true);
	}
	
	string updateFlagsQuery =
	       "update cdr \
		set flags = coalesce(flags, 0) | " + intToString(CDR_ALONE_UNCONFIRMED_BYE) + " \
		where id = ( \
			select max(cdr_id) \
			from cdr_next \
			where calldate > '" + sqlDateTimeString(calltime_s() - 60 * 60) + "' and \
			      fbasename = '" + fbasename + "' \
			limit 1)";
	if(enableBatchIfPossible) {
		static unsigned int counterSqlStore = 0;
		sqlStore->query_lock(MYSQL_ADD_QUERY_END(updateFlagsQuery).c_str(),
				     STORE_PROC_ID_CDR, 
				     opt_mysqlstore_max_threads_cdr > 1 &&
				     sqlStore->getSize(STORE_PROC_ID_CDR, 0) > 1000 ? 
				      counterSqlStore % opt_mysqlstore_max_threads_cdr : 
				      0);
		++counterSqlStore;
	} else {
		sqlDbSaveCall->query(updateFlagsQuery);
	}
	
	return(0);
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveRegisterToDb(bool enableBatchIfPossible) {
 
	if(sverb.disable_save_register) {
		return(0);
	}
	
	if(this->msgcount <= 1 or 
	   this->lastSIPresponseNum == 401 or this->lastSIPresponseNum == 403 or this->lastSIPresponseNum == 404) {
		this->regstate = 2;
	}
	
	if(sqlStore->getSize(STORE_PROC_ID_REGISTER, -1) > opt_mysqlstore_limit_queue_register) {
		static u_int64_t lastTimeSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			syslog(LOG_NOTICE, "size of register queue exceeded limit - register record ignored");
			lastTimeSyslog = actTime;
		}
		return(0);
	}

	if(!sqlDbSaveCall) {
		sqlDbSaveCall = createSqlObject();
		sqlDbSaveCall->setEnableSqlStringInContent(true);
	}
	
	adjustUA();

	const char *register_table = "register";
	
	string query;

	unsigned int now = time(NULL);

	string qp;
	
	static unsigned int counterSqlStore = 0;
	int storeId2 = opt_mysqlstore_max_threads_register > 1 &&
		       sqlStore->getSize(STORE_PROC_ID_REGISTER, 0) > 1000 ? 
			counterSqlStore % opt_mysqlstore_max_threads_register : 
			0;
	++counterSqlStore;

	if(last_register_clean == 0) {
		// on first run the register table has to be deleted 
		if(enableBatchIfPossible && isTypeDb("mysql")) {
			qp += "DELETE FROM register";
			sqlStore->query_lock(qp.c_str(), STORE_PROC_ID_REGISTER, storeId2);
		} else {
			sqlDbSaveCall->query("DELETE FROM register");
		}
		last_register_clean = now;
	} else if((last_register_clean + REGISTER_CLEAN_PERIOD) < now){
		// last clean was done older than CLEAN_PERIOD seconds
		string calldate_str = sqlDateTimeString(calltime_s());

		query = "INSERT INTO register_state \
			 (created_at, \
			  sipcallerip, \
			  from_num, \
			  to_num, \
			  to_domain, \
			  contact_num, \
			  contact_domain, \
			  digestusername, \
			  expires, \
			  state, \
			  ua_id) \
			 SELECT expires_at, \
				sipcallerip, \
				from_num, \
				to_num, \
				to_domain, \
				contact_num, \
				contact_domain, \
				digestusername, \
				expires, \
				5, \
				ua_id \
			FROM register \
			WHERE expires_at <= '" + calldate_str + "'";
		if(enableBatchIfPossible && isTypeDb("mysql")) {
			qp = query + "; ";
			qp += "DELETE FROM register WHERE expires_at <= '" + calldate_str + "'";
			sqlStore->query_lock(qp.c_str(), STORE_PROC_ID_REGISTER, storeId2);
		} else {
			sqlDbSaveCall->query(query);
			sqlDbSaveCall->query("DELETE FROM register WHERE expires_at <= '"+ calldate_str + "'");
		}
		last_register_clean = now;
	}

	switch(regstate) {
	case 1:
	case 3:
		if(enableBatchIfPossible && isTypeDb("mysql")) {
			//stored procedure is much faster and eliminates latency reducing uuuuuuuuuuuuu
			query = "CALL PROCESS_SIP_REGISTER(" + sqlEscapeStringBorder(sqlDateTimeString(calltime_s())) + ", " +
				sqlEscapeStringBorder(caller) + "," +
				sqlEscapeStringBorder(callername) + "," +
				sqlEscapeStringBorder(caller_domain) + "," +
				sqlEscapeStringBorder(called()) + "," +
				sqlEscapeStringBorder(called_domain()) + ",'" +
				getSipcallerip().getStringForMysqlIpColumn("register", "sipcallerip") + "','" +
				getSipcalledip().getStringForMysqlIpColumn("register", "sipcalledip") + "'," +
				sqlEscapeStringBorder(contact_num) + "," +
				sqlEscapeStringBorder(contact_domain) + "," +
				sqlEscapeStringBorder(digest_username) + "," +
				sqlEscapeStringBorder(digest_realm) + ",'" +
				intToString(regstate) + "'," +
				sqlEscapeStringBorder(sqlDateTimeString(calltime_s() + register_expires).c_str()) + ",'" + //mexpires_at
				intToString(register_expires) + "', " +
				sqlEscapeStringBorder(a_ua) + ", " +
				sqlEscapeStringBorder(intToString(fname_register)) + ", " +
				intToString(useSensorId);
				//srcmac ;
			if (existsColumns.register_rrd_count) {
				query = query + ", " + intToString(regrrddiff) + ")";
			} else {
				query = query + ")";
			}
			sqlStore->query_lock(query.c_str(), STORE_PROC_ID_REGISTER, storeId2);
		} else {
			if (existsColumns.register_rrd_count) {
				query = string(
					"SELECT ID, state, rrd_avg, rrd_count, ") +
					       "UNIX_TIMESTAMP(expires_at) AS expires_at, " +
					       "_LC_[(UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(" + sqlEscapeStringBorder(sqlDateTimeString(calltime_s())) + "))] AS expired " +
					"FROM " + register_table + " " +
					"WHERE to_num = " + sqlEscapeStringBorder(called()) + " AND to_domain = " + sqlEscapeStringBorder(called_domain()) + " AND " +
					      "contact_num = " + sqlEscapeStringBorder(contact_num) + " AND contact_domain = " + sqlEscapeStringBorder(contact_domain) + 
					      //" AND digestusername = " + sqlEscapeStringBorder(digest_username) + " " +
					"ORDER BY ID DESC"; // LIMIT 1 
	//			if(verbosity > 2) cout << query << "\n";
			} else {
				query = string(
					"SELECT ID, state, ") +
					       "UNIX_TIMESTAMP(expires_at) AS expires_at, " +
					       "_LC_[(UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(" + sqlEscapeStringBorder(sqlDateTimeString(calltime_s())) + "))] AS expired " +
					"FROM " + register_table + " " +
					"WHERE to_num = " + sqlEscapeStringBorder(called()) + " AND to_domain = " + sqlEscapeStringBorder(called_domain()) + " AND " +
					      "contact_num = " + sqlEscapeStringBorder(contact_num) + " AND contact_domain = " + sqlEscapeStringBorder(contact_domain) + 
					"ORDER BY ID DESC";
			}

			{
				if(!sqlDbSaveCall->query(query)) {
					syslog(LOG_ERR, "Error: Query [%s] failed.", query.c_str());
					break;
				}

				SqlDb_row rsltRow = sqlDbSaveCall->fetchRow();
				int rrd_avg = regrrddiff;
				int rrd_count = 1;
				//char srcmac[24];
				//snprintf(srcmac, 23, "%lu", regsrcmac);
				//srcmac[23] = 0;

				if(rsltRow) {
					// REGISTER message is already in register table, delete old REGISTER and save the new one
					int expired = atoi(rsltRow["expired"].c_str()) == 1;
					time_t expires_at = atoi(rsltRow["expires_at"].c_str());

					// compute rrdavgtime [RFC-6076] from regrrddiff - REGISTER->OK and increase count if less than 10.
					if (existsColumns.register_rrd_count) {
						rrd_count = atoi(rsltRow["rrd_count"].c_str());
						if (rrd_count < 10) rrd_count ++;
						rrd_avg = (atoi(rsltRow["rrd_avg"].c_str()) * (rrd_count - 1) + regrrddiff) / rrd_count;
					}

					string query = "DELETE FROM " + (string)register_table + " WHERE ID = '" + (rsltRow["ID"]).c_str() + "'";
					if(!sqlDbSaveCall->query(query)) {
						syslog(LOG_WARNING, "Query [%s] failed.", query.c_str());
					}

					if(expired) {
						// the previous REGISTER expired, save to register_state
						SqlDb_row reg;
						reg.add(sqlEscapeString(sqlDateTimeString(expires_at).c_str()), "created_at");
						reg.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, "register_state");
						reg.add(getSipcalledip(), "sipcalledip", false, sqlDbSaveCall, "register_state");
						reg.add(sqlEscapeString(caller), "from_num");
						reg.add(sqlEscapeString(called()), "to_num");
						reg.add(sqlEscapeString(called_domain()), "to_domain");
						reg.add(sqlEscapeString(contact_num), "contact_num");
						reg.add(sqlEscapeString(contact_domain), "contact_domain");
						reg.add(sqlEscapeString(digest_username), "digestusername");
						reg.add(register_expires, "expires");
						reg.add(5, "state");
						reg.add(intToString(fname_register), "fname");
						reg.add(useSensorId, "id_sensor");
						if(a_ua[0]) {
							reg.add(dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, true), "ua_id");
						}
						sqlDbSaveCall->insert("register_state", reg);
					}

					if(atoi(rsltRow["state"].c_str()) != regstate || register_expires == 0) {
						// state changed or device unregistered, store to register_state
						SqlDb_row reg;
						reg.add(sqlEscapeString(sqlDateTimeString(calltime_s()).c_str()), "created_at");
						reg.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, "register_state");
						reg.add(getSipcalledip(), "sipcalledip", false, sqlDbSaveCall, "register_state");
						reg.add(sqlEscapeString(caller), "from_num");
						reg.add(sqlEscapeString(called()), "to_num");
						reg.add(sqlEscapeString(called_domain()), "to_domain");
						reg.add(sqlEscapeString(contact_num), "contact_num");
						reg.add(sqlEscapeString(contact_domain), "contact_domain");
						reg.add(sqlEscapeString(digest_username), "digestusername");
						reg.add(register_expires, "expires");
						reg.add(regstate, "state");
						if(a_ua[0]) {
							reg.add(dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, true), "ua_id");
						}
						reg.add(intToString(fname_register), "fname");
						reg.add(useSensorId, "id_sensor");
						sqlDbSaveCall->insert("register_state", reg);
					}
				} else {
					// REGISTER message is new, store it to register_state
					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(calltime_s()).c_str()), "created_at");
					reg.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, "register_state");
					reg.add(getSipcalledip(), "sipcalledip", false, sqlDbSaveCall, "register_state");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(called()), "to_num");
					reg.add(sqlEscapeString(called_domain()), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					reg.add(register_expires, "expires");
					reg.add(regstate, "state");
					if(a_ua[0]) {
						reg.add(dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, true), "ua_id");
					}
					reg.add(intToString(fname_register), "fname");
					reg.add(useSensorId, "id_sensor");
					sqlDbSaveCall->insert("register_state", reg);
				}

				// save successfull REGISTER to register table in case expires is not negative
				if(register_expires > 0) {


					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(calltime_s()).c_str()), "calldate");
					reg.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, register_table);
					reg.add(getSipcalledip(), "sipcalledip", false, sqlDbSaveCall, register_table);
					//reg.add(sqlEscapeString(fbasename), "fbasename");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(callername), "from_name");
					reg.add(sqlEscapeString(caller_domain), "from_domain");
					reg.add(sqlEscapeString(called()), "to_num");
					reg.add(sqlEscapeString(called_domain()), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					reg.add(sqlEscapeString(digest_realm), "digestrealm");
					if(a_ua[0]) {
						reg.add(dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, true), "ua_id");
					}
					reg.add(register_expires, "expires");
					reg.add(sqlEscapeString(sqlDateTimeString(calltime_s() + register_expires).c_str()), "expires_at");
					reg.add(intToString(fname_register), "fname");
					reg.add(useSensorId, "id_sensor");
					reg.add(regstate, "state");
					//reg.add(srcmac, "src_mac");

					if (existsColumns.register_rrd_count) {
						char rrdavg[12];
						char rrdcount[12];
						snprintf(rrdavg, sizeof(rrdavg), "%d", rrd_avg);
						snprintf(rrdcount, sizeof(rrdcount), "%d", rrd_count);
						reg.add(rrdavg,"rrd_avg");
						reg.add(rrdcount,"rrd_count");
					}
					int res = sqlDbSaveCall->insert(register_table, reg) <= 0;
					return res;
				}
			}
		}
		break;
	case 2:
		// REGISTER failed. Check if there is already in register_failed table failed register within last hour 

		if(enableBatchIfPossible && isTypeDb("mysql")) {

			stringstream ssipcallerip;
			ssipcallerip << getSipcallerip().getString();
			stringstream ssipcalledip;
			ssipcalledip << getSipcalledip().getString();

			unsigned int count = 1;
			int res = regfailedcache->check(getSipcallerip(), getSipcalledip(), calltime_s(), &count);
			if(res) {
				break;
			}

			stringstream cnt;
			cnt << count;

			string calldate_str = sqlDateTimeString(calltime_s());

			string q1 = string(
				"SELECT counter FROM register_failed ") +
				"WHERE sipcallerip = " + ssipcallerip.str() + " AND sipcalledip = " + ssipcalledip.str() + 
				" AND created_at >= SUBTIME('" + calldate_str + "', '01:00:00') LIMIT 1";

			string q2 = string(
				"UPDATE register_failed SET created_at = '" + calldate_str + "', fname = " + sqlEscapeStringBorder(intToString(fname_register)) + ", counter = counter + " + cnt.str()) +
				", to_num = " + sqlEscapeStringBorder(called()) + ", from_num = " + sqlEscapeStringBorder(called()) + ", digestusername = " + sqlEscapeStringBorder(digest_username) +
				"WHERE sipcallerip = " + ssipcallerip.str() + " AND sipcalledip = " + ssipcalledip.str() + 
				" AND created_at >= SUBTIME('" + calldate_str + "', '01:00:00')";

			SqlDb_row reg;
			reg.add(sqlEscapeString(sqlDateTimeString(calltime_s()).c_str()), "created_at");
			reg.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, "register_failed");
			reg.add(getSipcalledip(), "sipcalledip", false, sqlDbSaveCall, "register_failed");
			reg.add(sqlEscapeString(caller), "from_num");
			reg.add(sqlEscapeString(called()), "to_num");
			reg.add(sqlEscapeString(called_domain()), "to_domain");
			reg.add(sqlEscapeString(contact_num), "contact_num");
			reg.add(sqlEscapeString(contact_domain), "contact_domain");
			reg.add(sqlEscapeString(digest_username), "digestusername");

			//reg.add(MYSQL_VAR_PREFIX + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "ua_id");
			reg.add(MYSQL_VAR_PREFIX + "@ua_id", "ua_id");

			reg.add(intToString(fname_register), "fname");
			if(useSensorId > -1) {
				reg.add(useSensorId, "id_sensor");
			}
			string q3 = string("set @ua_id = ") +  "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ");\n";
			q3 += sqlDbSaveCall->insertQuery("register_failed", reg);

			string query = "SET @mcounter = (" + q1 + ");";
			query += "IF @mcounter IS NOT NULL THEN " + q2 + "; ELSE " + q3 + "; END IF";

			sqlStore->query_lock(query.c_str(), STORE_PROC_ID_REGISTER, storeId2);
		} else {
			string calldate_str = sqlDateTimeString(calltime_s());
			query = string(
				"SELECT counter FROM register_failed ") +
				"WHERE to_num = " + sqlEscapeStringBorder(called()) + " AND to_domain = " + sqlEscapeStringBorder(called_domain()) + 
					" AND digestusername = " + sqlEscapeStringBorder(digest_username) + " AND created_at >= SUBTIME('" + calldate_str+ "', '01:00:00')";
			if(sqlDbSaveCall->query(query)) {
				SqlDb_row rsltRow = sqlDbSaveCall->fetchRow();
				if(rsltRow) {
					// there is already failed register, update counter and do not insert
					string query = string(
						"UPDATE register_failed SET created_at = '" + calldate_str+ "', fname = " + sqlEscapeStringBorder(intToString(fname_register)) + ", counter = counter + 1 ") +
						"WHERE to_num = " + sqlEscapeStringBorder(called()) + " AND digestusername = " + sqlEscapeStringBorder(digest_username) + 
							" AND created_at >= SUBTIME('" + calldate_str+ "', '01:00:00');";
					sqlDbSaveCall->query(query);
				} else {
					// this is new failed attempt within hour, insert
					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(calltime_s()).c_str()), "created_at");
					reg.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, "register_failed");
					reg.add(getSipcalledip(), "sipcalledip", false, sqlDbSaveCall, "register_failed");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(called()), "to_num");
					reg.add(sqlEscapeString(called_domain()), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					if(a_ua[0]) {
						reg.add(dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, true), "ua_id");
					}
					reg.add(intToString(fname_register), "fname");
					if(useSensorId > -1) {
						reg.add(useSensorId, "id_sensor");
					}
					sqlDbSaveCall->insert("register_failed", reg);
				}
			}
		}
		break;
	}
	
	return 1;
}

int
Call::saveMessageToDb(bool enableBatchIfPossible) {
 
	if(sverb.disable_save_message) {
		return(0);
	}
	
	/*
	strcpy(this->caller, "ěščřžý");
	this->proxies.push_back(1);
	this->proxies.push_back(2);
	*/
	
	if(!sqlDbSaveCall) {
		sqlDbSaveCall = createSqlObject();
		sqlDbSaveCall->setEnableSqlStringInContent(true);
	}
	
	adjustUA();
	
	string sql_message_table = "message";
	string sql_message_proxy_table = "message_proxy";

	SqlDb_row msg,
		  msg_next_ch[CDR_NEXT_MAX],
		  msg_country_code;
	char _msg_next_ch_name[CDR_NEXT_MAX][100];
	char *msg_next_ch_name[CDR_NEXT_MAX];
	for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
		_msg_next_ch_name[i][0] = 0;
		msg_next_ch_name[i] = _msg_next_ch_name[i];
	}

	string query_str_messageproxy;

	if(opt_messageproxy) {
		set<vmIP> proxies_undup;
		this->proxies_undup(&proxies_undup);
		set<vmIP>::iterator iter_undup = proxies_undup.begin();
		while (iter_undup != proxies_undup.end()) {
			if(*iter_undup == getSipcalledip()) { ++iter_undup; continue; };
			SqlDb_row messageproxy;
			messageproxy.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "message_ID");
			messageproxy.add_calldate(calltime_us(), "calldate", existsColumns.message_child_proxy_calldate_ms);
			messageproxy.add((vmIP)(*iter_undup), "dst", false, sqlDbSaveCall, sql_message_proxy_table.c_str());
			query_str_messageproxy += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						  sqlDbSaveCall->insertQuery(sql_message_proxy_table, messageproxy));
			++iter_undup;
		}
	}
	
	if(useSensorId > -1) {
		msg.add(useSensorId, "id_sensor");
	}
	msg.add(sqlEscapeString(caller), "caller");
	msg.add(sqlEscapeString(reverseString(caller).c_str()), "caller_reverse");
	msg.add(sqlEscapeString(called()), "called");
	msg.add(sqlEscapeString(reverseString(called()).c_str()), "called_reverse");
	msg.add(sqlEscapeString(caller_domain), "caller_domain");
	msg.add(sqlEscapeString(called_domain()), "called_domain");
	msg.add(sqlEscapeString(callername), "callername");
	msg.add(sqlEscapeString(reverseString(callername).c_str()), "callername_reverse");
	msg.add(getSipcallerip(), "sipcallerip", false, sqlDbSaveCall, sql_message_table.c_str());
	msg.add(getSipcalledip(), "sipcalledip", false, sqlDbSaveCall, sql_message_table.c_str());
	msg.add_calldate(calltime_us(), "calldate", existsColumns.message_calldate_ms);
	if(!geoposition.empty()) {
		msg.add(sqlEscapeString(geoposition), "GeoPosition");
	}
	msg.add(sqlEscapeString(fbasename), "fbasename");
	if((message && message[0]) || (message_info && message_info[0])) {
		string message_save;
		bool message_is_url = false;
		if(message && message[0]) {
			for(unsigned i = 0; i < opt_message_body_url_reg.size(); i++) {
				if(reg_match(message, opt_message_body_url_reg[i].c_str(), __FILE__, __LINE__)) {
					message_is_url = true;
					break;
				}
			}
			extern NoHashMessageRules *no_hash_message_rules;
			if((flags & FLAG_HIDEMESSAGE) && !message_is_url && 
			   (!no_hash_message_rules ||
			    !no_hash_message_rules->checkNoHash(this))) {
				message_save = "SHA256: " + GetStringSHA256(trim_str(message) + trim_str(opt_hide_message_content_secret));
			} else {
				message_save = message;
			}
		}
		if(message_is_url || (message_info && message_info[0])) {
			if(message) {
				message_save += '\n';
			}
			message_save += string("_INF:") + (message_is_url ? "URL" : message_info);
		}
		msg.add(sqlEscapeString(message_save), "message");
	}
	if(existsColumns.message_content_length && content_length) {
		msg.add(content_length, "content_length");
	}

	if(existsColumns.message_vlan && VLAN_IS_SET(vlan)) {
		msg.add(vlan, "vlan");
	}

	msg.add(lastSIPresponseNum, "lastSIPresponseNum");
	
	if(existsColumns.message_response_time && this->first_message_time_us) {
		if(this->first_response_200_time_us) {
			msg.add(MIN(65535, round((this->first_response_200_time_us - this->first_message_time_us) / 1000.0)), "response_time");
		}
	}

	if(getSpoolIndex() && existsColumns.message_spool_index) {
		msg.add(getSpoolIndex(), "spool_index");
	}

	if(custom_headers_message) {
		custom_headers_message->prepareSaveRows(this, MESSAGE, NULL, 0, &msg, msg_next_ch, msg_next_ch_name);
	}

	if(opt_message_country_code) {
		CountryDetectApplyReload();
		if(opt_message_country_code == 2) {
			msg_country_code.add(getCountryIdByIP(getSipcallerip()), "sipcallerip_country_code");
			msg_country_code.add(getCountryIdByIP(getSipcalledip()), "sipcalledip_country_code");
			msg_country_code.add(getCountryIdByPhoneNumber(caller), "caller_number_country_code");
			msg_country_code.add(getCountryIdByPhoneNumber(called()), "called_number_country_code");
		} else {
			msg_country_code.add(getCountryByIP(getSipcallerip(), true), "sipcallerip_country_code");
			msg_country_code.add(getCountryByIP(getSipcalledip(), true), "sipcalledip_country_code");
			msg_country_code.add(getCountryByPhoneNumber(caller, true), "caller_number_country_code");
			msg_country_code.add(getCountryByPhoneNumber(called(), true), "called_number_country_code");
		}
		msg_country_code.add_calldate(calltime_us(), "calldate", existsColumns.message_child_country_code_calldate_ms);
	}
	
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		
		if(useSetId()) {
			msg.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_sip_response, lastSIPresponse), "lastSIPresponse_id");
		} else {
			unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, lastSIPresponse, false, true);
			if(_cb_id) {
				msg.add(_cb_id, "lastSIPresponse_id");
			} else {
				query_str += MYSQL_ADD_QUERY_END(string("set @lSresp_id = ") + 
					     "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")");
				msg.add(MYSQL_VAR_PREFIX + "@lSresp_id", "lastSIPresponse_id");
				//msg.add(MYSQL_VAR_PREFIX + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
			}
		}
		if(opt_cdr_ua_enable) {
			if(a_ua[0]) {
				if(useSetId()) {
					msg.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_ua, a_ua), "a_ua_id");
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, false, true);
					if(_cb_id) {
						msg.add(_cb_id, "a_ua_id");
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @uaA_id = ") + 
							     "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")");
						msg.add(MYSQL_VAR_PREFIX + "@uaA_id", "a_ua_id");
						//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
					}
				}
			}
			if(b_ua[0]) {
				if(useSetId()) {
					msg.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_ua, b_ua), "b_ua_id");
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, b_ua, false, true);
					if(_cb_id) {
						msg.add(_cb_id, "b_ua_id");
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @uaB_id = ") + 
							     "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")");
						msg.add(MYSQL_VAR_PREFIX + "@uaB_id", "b_ua_id");
						//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
					}
				}
			}
		}
		if(contenttype && contenttype[0]) {
			if(useSetId()) {
				msg.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_contenttype, contenttype), "id_contenttype");
			} else {
				unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_contenttype, contenttype, false, true);
				if(_cb_id) {
					msg.add(_cb_id, "id_contenttype");
				} else {
					query_str += MYSQL_ADD_QUERY_END(string("set @cntt_id = ") + 
						     "getIdOrInsertCONTENTTYPE(" + sqlEscapeStringBorder(contenttype) + ")");
					msg.add(MYSQL_VAR_PREFIX + "@cntt_id", "id_contenttype");
					//cdr.add(MYSQL_VAR_PREFIX + "getIdOrInsertCONTENTTYPE(" + sqlEscapeStringBorder(contenttype) + ")", "id_contenttype");
				}
			}
		}
		
		extern bool opt_message_check_duplicity_callid_in_next_pass_insert;
		if(!useNewStore() &&
		   opt_message_check_duplicity_callid_in_next_pass_insert) {
			// check if exists call-id - begin if
			query_str += "__NEXT_PASS_QUERY_BEGIN__";
			query_str += string("set @exists_call_id = coalesce(\n") +
				     "(select ID from message\n" +
				     " where calldate > ('" + sqlDateTimeString(calltime_s()) + "' - interval 1 minute) and\n" +
				     "       calldate < ('" + sqlDateTimeString(calltime_s()) + "' + interval 1 minute) and\n" +
				     "       " + (useSensorId > -1 ? 
						   "id_sensor = " + intToString(useSensorId) : 
						   "id_sensor is null") + " and\n" +
				     "       fbasename = '" + sqlEscapeString(fbasename) + "' limit 1), 0);\n";
			query_str += "if not @exists_call_id then\n";
			query_str += "__NEXT_PASS_QUERY_END__";
		}
		
		if(useNewStore()) {
			if(useSetId()) {
				msg.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "ID");
			} else {
				query_str += MYSQL_GET_MAIN_INSERT_ID_OLD;
			}
		}
		query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT + 
			     sqlDbSaveCall->insertQuery(sql_message_table, msg));
		if(useNewStore()) {
			if(!useSetId()) {
				query_str += MYSQL_GET_MAIN_INSERT_ID + 
					     MYSQL_IF_MAIN_INSERT_ID;
			}
		} else {
			query_str += "if row_count() > 0 then\n" +
				     MYSQL_GET_MAIN_INSERT_ID;
		}
		
		bool existsNextCh = false;
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(msg_next_ch_name[i][0]) {
				msg_next_ch[i].add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "message_ID");
				query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
					     sqlDbSaveCall->insertQuery(msg_next_ch_name[i], msg_next_ch[i]));
				existsNextCh = true;
			}
		}
		if(existsNextCh && custom_headers_message) {
			string queryForSaveUseInfo = custom_headers_message->getQueryForSaveUseInfo(this, MESSAGE, NULL);
			if(!queryForSaveUseInfo.empty()) {
				vector<string> queryForSaveUseInfo_vect = split(queryForSaveUseInfo.c_str(), ";");
				for(unsigned i = 0; i < queryForSaveUseInfo_vect.size(); i++) {
					query_str += MYSQL_ADD_QUERY_END(queryForSaveUseInfo_vect[i]);
				}
			}
		}
		
		if(opt_message_country_code) {
			msg_country_code.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "message_ID");
			query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
				     sqlDbSaveCall->insertQuery("message_country_code", msg_country_code));
		}
		
		query_str += query_str_messageproxy;
		
		if(useNewStore()) {
			if(!useSetId()) {
				query_str += MYSQL_ENDIF_QE;
			}
		} else {
			query_str += "end if";
		}
		
		if(!useNewStore() &&
		   opt_message_check_duplicity_callid_in_next_pass_insert) {
			// check if exists call-id - end if
			query_str += "__NEXT_PASS_QUERY_BEGIN__";
			query_str += ";\nend if";
			query_str += "__NEXT_PASS_QUERY_END__";
		}
		
		static unsigned int counterSqlStore = 0;
		sqlStore->query_lock(query_str.c_str(),
				     STORE_PROC_ID_MESSAGE,
				     opt_mysqlstore_max_threads_message > 1 &&
				     sqlStore->getSize(STORE_PROC_ID_MESSAGE, 0) > 1000 ? 
				      counterSqlStore % opt_mysqlstore_max_threads_message : 
				      0);
		++counterSqlStore;
		
		//cout << endl << endl << query_str << endl << endl << endl;
		return(0);
	}
	
	unsigned int 
			lastSIPresponse_id = 0,
			a_ua_id = 0,
			b_ua_id = 0;

	lastSIPresponse_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, lastSIPresponse, true);
	if(a_ua[0]) {
		a_ua_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, a_ua, true);
	}
	if(b_ua[0]) {
		b_ua_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, b_ua, true);
	}
	if(contenttype && contenttype[0]) {
		msg.add(dbData->getCbId(cSqlDbCodebook::_cb_contenttype, contenttype, true), "id_contenttype");
	}

	msg.add(lastSIPresponse_id, "lastSIPresponse_id", true);
	msg.add(a_ua_id, "a_ua_id", true);
	msg.add(b_ua_id, "b_ua_id", true);

	int msgID = sqlDbSaveCall->insert("message", msg);
	
	if(msgID > 0) {
	
		if(opt_messageproxy) {
			set<vmIP> proxies_undup;
			this->proxies_undup(&proxies_undup);
			set<vmIP>::iterator iter_undup = proxies_undup.begin();
			while(iter_undup != proxies_undup.end()) {
				SqlDb_row messageproxy;
				messageproxy.add(msgID, "message_ID");
				messageproxy.add_calldate(calltime_us(), "calldate", existsColumns.message_child_proxy_calldate_ms);
				messageproxy.add((vmIP)(*iter_undup), "dst", false, sqlDbSaveCall, sql_message_proxy_table.c_str());
				sqlDbSaveCall->insert(sql_message_proxy_table, messageproxy);
				++iter_undup;
			}
		}
		
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(msg_next_ch_name[i][0]) {
				msg_next_ch[i].add(msgID, "message_ID");
				sqlDbSaveCall->insert(msg_next_ch_name[i], msg_next_ch[i]);
			}
		}
	
		if(opt_message_country_code) {
			msg_country_code.add(msgID, "message_ID");
			sqlDbSaveCall->insert("message_country_code", msg_country_code);
		}
		
	}

	return(msgID <= 0);

}

/* for debug purpose */
void
Call::dump(){
	//print call_id
	printf("cidl:%lu\n", call_id_len);
	printf("-call dump %p---------------------------------\n", this);
	printf("callid:%s\n", call_id.c_str());
	printf("last packet time:%d\n", (int)get_last_packet_time_s());
	printf("last SIP response [%d] [%s]\n", lastSIPresponseNum, lastSIPresponse);
	
	// print assigned IP:port 
	if(ipport_n > 0) {
		printf("ipport_n:%d\n", ipport_n);
		for(int i = 0; i < ipport_n; i++) 
			printf("addr: %s, port: %d\n", ip_port[i].addr.getString().c_str(), ip_port[i].port.getPort());
	} else {
		printf("no IP:port assigned\n");
	}
	if(seeninvite || seenmessage) {
		printf("From:%s\n", caller);
		printf("To:%s\n", called());
	}
	printf("First packet: %d, Last packet: %d\n", (int)get_first_packet_time_s(), (int)get_last_packet_time_s());
	if(rtp_size() > 0) {
		printf("ssrc_n:%d\n", rtp_size());
		printf("Call statistics:\n");
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			rtp_i->dump();
		}
	}
	printf("-end call dump  %p----------------------------\n", this);
}

void Call::atFinish() {
	if(!(typeIs(INVITE) || typeIs(MESSAGE))) {
		return;
	}
	extern char pcapcommand[4092];
	if(pcapcommand[0]) {
		string source(pcapcommand);
		string find1 = "%pcap%";
		string find2 = "%basename%";
		string find3 = "%dirname%";
		find_and_replace(source, find1, escapeShellArgument(this->get_pathfilename(tsf_sip)));
		find_and_replace(source, find2, escapeShellArgument(this->fbasename));
		find_and_replace(source, find3, escapeShellArgument(this->get_pathname(tsf_sip)));
		if(verbosity >= 2) printf("command: [%s]\n", source.c_str());
		calltable->addSystemCommand(source.c_str());
	};
	extern char filtercommand[4092];
	if(filtercommand[0] && this->flags & FLAG_RUNSCRIPT) {
		string source(filtercommand);
		find_and_replace(source, string("%callid%"), escapeShellArgument(this->fbasename));
		find_and_replace(source, string("%dirname%"), escapeShellArgument(this->get_pathname(tsf_sip)));
		find_and_replace(source, string("%calldate%"), escapeShellArgument(sqlDateTimeString(this->calltime_s())));
		find_and_replace(source, string("%caller%"), escapeShellArgument(this->caller));
		find_and_replace(source, string("%called%"), escapeShellArgument(this->called()));
		if(verbosity >= 2) printf("command: [%s]\n", source.c_str());
		calltable->addSystemCommand(source.c_str());
	}
}

u_int32_t 
Call::getAllReceivedRtpPackets() {
	u_int32_t receivedPackets = 0;
	for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
		receivedPackets += rtp_i->stats.received;
	}
	return(receivedPackets);
}

void
Call::applyRtcpXrDataToRtp() {
	map<u_int32_t, sRtcpXrDataSsrc>::iterator iter_ssrc;
	for(iter_ssrc = this->rtcpXrData.begin(); iter_ssrc != this->rtcpXrData.end(); iter_ssrc++) {
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(rtp_i->ssrc == iter_ssrc->first) {
				list<sRtcpXrDataItem>::iterator iter;
				for(iter = iter_ssrc->second.begin(); iter != iter_ssrc->second.end(); iter++) {
					if((!iter->ip_local.isSet() || iter->ip_local == rtp_i->saddr || iter->ip_local == rtp_i->daddr) &&
					   (!iter->ip_remote.isSet() || iter->ip_remote == rtp_i->saddr || iter->ip_remote == rtp_i->daddr)) {
						if(iter->moslq >= 0) {
							rtp_i->rtcp_xr.counter_mos++;
							if(iter->moslq < rtp_i->rtcp_xr.minmos) {
								rtp_i->rtcp_xr.minmos = iter->moslq;
							}
							rtp_i->rtcp_xr.avgmos = (rtp_i->rtcp_xr.avgmos * (rtp_i->rtcp_xr.counter_mos - 1) + iter->moslq) / rtp_i->rtcp_xr.counter_mos;
						}
						if(iter->nlr >= 0) {
							rtp_i->rtcp_xr.counter_fr++;
							if(iter->nlr > rtp_i->rtcp_xr.maxfr) {
								rtp_i->rtcp_xr.maxfr = iter->nlr;
							}
							rtp_i->rtcp_xr.avgfr = (rtp_i->rtcp_xr.avgfr * (rtp_i->rtcp_xr.counter_fr - 1) + iter->nlr) / rtp_i->rtcp_xr.counter_fr;
						}
					}
				}
			}
		}
	}
}

void Call::adjustUA() {
	if(opt_cdr_ua_reg_remove.size() || opt_cdr_ua_reg_whitelist.size()) {
		if(a_ua[0]) {
			::adjustUA(a_ua, sizeof(a_ua));
		}
		if(b_ua[0]) {
			::adjustUA(b_ua, sizeof(b_ua));
		}
	}
}

bool Call::is_set_proxies() {
	bool set_proxies;
	proxies_lock();
	set_proxies = proxies.size() > 0;
	proxies_unlock();
	return(set_proxies);
}

void Call::proxies_undup(set<vmIP> *proxies_undup) {
	proxies_lock();
	list<vmIP>::iterator iter = proxies.begin();
	while (iter != proxies.end()) {
		if (proxies_undup->find(*iter) == proxies_undup->end()) {
			proxies_undup->insert(*iter);
		}
		++iter;
	}
	proxies_unlock();
}

string Call::get_proxies_str() {
	string sipproxies;
	if(is_set_proxies()) {
		stringstream spp;
		set<vmIP> proxies_undup;
		this->proxies_undup(&proxies_undup);
		set<vmIP>::iterator iter_undup;
		for (iter_undup = proxies_undup.begin(); iter_undup != proxies_undup.end(); ) {
			if(*iter_undup == getSipcalledip()) { ++iter_undup; continue; };
			spp << ((vmIP)(*iter_undup)).getString();
			++iter_undup;
			if (iter_undup != proxies_undup.end()) {
				spp << ',';
			}
		}
		sipproxies = spp.str();
	}
	return(sipproxies);
}

void Call::createListeningBuffers() {
	pthread_mutex_lock(&listening_worker_run_lock);
	for(int i = 0; i < 2; i++) {
		if(audioBufferData[i].audiobuffer) {
			audioBufferData[i].audiobuffer->enable();
		} else {
			audioBufferData[i].audiobuffer = new FILE_LINE(1005) FifoBuffer((string("audiobuffer") + intToString(i+1) + " for call " + call_id).c_str());
			audioBufferData[i].audiobuffer->setMinItemBufferLength(1000);
			audioBufferData[i].audiobuffer->setMaxSize(1000000);
			if(sverb.call_listening) {
			       audioBufferData[i].audiobuffer->setDebugOut((string("/tmp/audiobuffer") + intToString(i+1)).c_str());
			}
		}
	}
	pthread_mutex_unlock(&listening_worker_run_lock);
}

void Call::destroyListeningBuffers() {
	pthread_mutex_lock(&listening_worker_run_lock);
	for(int i = 0; i < 2; i++) {
		if(audioBufferData[i].audiobuffer) {
			delete audioBufferData[i].audiobuffer;
			audioBufferData[i].audiobuffer = NULL;
			audioBufferData[i].clearLast();
		}
	}
	pthread_mutex_unlock(&listening_worker_run_lock);
}

void Call::disableListeningBuffers() {
	pthread_mutex_lock(&listening_worker_run_lock);
	for(int i = 0; i < 2; i++) {
		if(audioBufferData[i].audiobuffer) {
			audioBufferData[i].audiobuffer->clean_and_disable();
			audioBufferData[i].clearLast();
		}
	}
	pthread_mutex_unlock(&listening_worker_run_lock);
}

vmIP Call::getSipcalledipConfirmed(vmPort *dport, vmIP *daddr_first, u_int8_t *daddr_first_protocol) {
	if(dport) {
		dport->clear();
	}
	if(daddr_first) {
		daddr_first->clear();
	}
	if(daddr_first_protocol) {
		*daddr_first_protocol = 0xFF;
	}
	vmIP saddr, daddr;
	list<vmIP> proxies;
	for(list<unsigned>::iterator iter_order = invite_sdaddr_order.begin(); iter_order != invite_sdaddr_order.end(); iter_order++) {
		list<Call::sInviteSD_Addr>::iterator iter = invite_sdaddr.begin();
		for(unsigned i = 0; i < *iter_order; i++) {
			iter++;
		}
		if(iter->confirmed) {
			if(!saddr.isSet() && !daddr.isSet()) {
				saddr = iter->saddr;
				daddr = iter->daddr;
				if(dport) {
					*dport = iter->dport;
				}
				if(daddr_first) {
					*daddr_first = iter->daddr_first;
					if(daddr_first_protocol) {
						*daddr_first_protocol = iter->daddr_first_protocol;
					}
				}
			}
			if(iter->saddr != saddr && find(proxies.begin(), proxies.end(), iter->saddr) == proxies.end()) {
				proxies.push_back(iter->saddr);
			}
			if(iter->daddr != saddr && iter->daddr != daddr && find(proxies.begin(), proxies.end(), iter->daddr) == proxies.end()) {
				proxies.push_back(daddr);
				daddr = iter->daddr;
				if(dport) {
					*dport = iter->dport;
				}
				if(daddr_first) {
					*daddr_first = iter->daddr_first;
					if(daddr_first_protocol) {
						*daddr_first_protocol = iter->daddr_first_protocol;
					}
				}
			}
		}
	}
	/* old version
	vmIP saddr, 
	     daddr, 
	     lastsaddr;
	for(list<unsigned>::iterator iter_order = invite_sdaddr_order.begin(); iter_order != invite_sdaddr_order.end(); iter_order++) {
		list<Call::sInviteSD_Addr>::iterator iter = invite_sdaddr.begin();
		for(unsigned i = 0; i < *iter_order; i++) {
			iter++;
		}
		bool exists = false;
		list<Call::sInviteSD_Addr>::iterator iter_check_exists = invite_sdaddr.begin();
		for(unsigned i = 0; i < (*iter_order - 1); i++) {
			if(iter_check_exists->saddr == iter->saddr && iter_check_exists->daddr == iter->daddr) {
				exists = true;
				break;
			}
			iter_check_exists++;
		}
		if(iter->confirmed && !exists) {
			if((daddr != iter->daddr && saddr != iter->daddr && 
			    lastsaddr != iter->saddr) ||
			   lastsaddr == iter->saddr) {
				if(!saddr.isSet()) {
					saddr = iter->saddr;
				}
				daddr = iter->daddr;
				if(dport) {
					*dport = iter->dport;
				}
				lastsaddr = iter->saddr;
			}
		}
	}
	*/
	return(daddr);
}

unsigned Call::getMaxRetransmissionInvite() {
	unsigned max_retrans = 0;
	for(list<Call::sInviteSD_Addr>::iterator iter = invite_sdaddr.begin(); iter != invite_sdaddr.end(); iter++) {
		if(iter->counter > 1 && (iter->counter - 1) > max_retrans) {
			max_retrans = iter->counter - 1;
		}
		if(iter->counter_reverse > 1 && (iter->counter_reverse - 1) > max_retrans) {
			max_retrans = iter->counter_reverse - 1;
		}
	}
	return(max_retrans);
}

void adjustSipResponse(string *sipResponse) {
	bool adjustLength = false;
	const char *new_sipResponse = adjustSipResponse((char*)sipResponse->c_str(), 0, &adjustLength);
	if(new_sipResponse) {
		*sipResponse = new_sipResponse;
	} else if(adjustLength) {
		sipResponse->resize(strlen(sipResponse->c_str()));
	}
}

const char *adjustSipResponse(char *sipResponse, unsigned sipResponse_size, bool *adjustLength) {
	if(opt_cdr_sip_response_reg_remove.size()) {
		bool adjust = false;
		for(unsigned i = 0; i < opt_cdr_sip_response_reg_remove.size(); i++) {
			vector<string> matches;
			if(reg_match(sipResponse, opt_cdr_sip_response_reg_remove[i].c_str(), &matches, true, __FILE__, __LINE__)) {
				for(unsigned j = 0; j < matches.size(); j++) {
					char *str_pos = strstr(sipResponse, matches[j].c_str());
					if(str_pos) {
						char sipResponse_temp[1024];
						strcpy_null_term(sipResponse_temp, str_pos + matches[j].size());
						strcpy(str_pos, sipResponse_temp);
						adjust = true;
						if(adjustLength) {
							*adjustLength = true;
						}
					}
				}
			}
		}
		if(adjust) {
			int length = strlen(sipResponse);
			while(sipResponse[length - 1] == ' ') {
				sipResponse[length - 1] = 0;
				--length;
			}
			int start = 0;
			while(sipResponse[start] == ' ') {
				++start;
			}
			if(start) {
				char sipResponse_temp[1024];
				strcpy_null_term(sipResponse_temp, sipResponse + start);
				strcpy(sipResponse, sipResponse_temp);
			}
			if(adjustLength) {
				*adjustLength = true;
			}
		}
	}
	if(opt_cdr_sip_response_number_max_length) {
		char *pointer = sipResponse;
		while(*pointer) {
			if(isdigit(*pointer)) {
				unsigned number_length = 1;
				while(isdigit(*(pointer + number_length))) {
					++number_length;
				}
				if(number_length > (unsigned)opt_cdr_sip_response_number_max_length) {
					char sipResponse_temp[1024];
					strcpy_null_term(sipResponse_temp, pointer + number_length);
					unsigned ellipsis_length = min(3u, number_length - opt_cdr_sip_response_number_max_length);
					strncpy(pointer + opt_cdr_sip_response_number_max_length, "...", ellipsis_length);
					strcpy(pointer + opt_cdr_sip_response_number_max_length + ellipsis_length, sipResponse_temp);
					pointer += opt_cdr_sip_response_number_max_length + ellipsis_length;
					if(adjustLength) {
						*adjustLength = true;
					}
				} else {
					pointer += number_length;
				}
			} else {
				++pointer;
			}
		}
	}
	return(NULL);
}

void adjustUA(string *ua) {
	bool adjustLength = false;
	const char *new_ua = adjustUA((char*)ua->c_str(), 0, &adjustLength);
	if(new_ua) {
		*ua = new_ua;
	} else if(adjustLength) {
		ua->resize(strlen(ua->c_str()));
	}
}

const char *adjustUA(char *ua, unsigned ua_size, bool *adjustLength) {
	if(opt_cdr_ua_reg_remove.size()) {
		bool adjust = false;
		for(unsigned i = 0; i < opt_cdr_ua_reg_remove.size(); i++) {
			vector<string> matches;
			if(reg_match(ua, opt_cdr_ua_reg_remove[i].c_str(), &matches, true, __FILE__, __LINE__)) {
				for(unsigned j = 0; j < matches.size(); j++) {
					char *str_pos = strstr(ua, matches[j].c_str());
					if(str_pos) {
						char ua_temp[1024];
						strcpy_null_term(ua_temp, str_pos + matches[j].size());
						strcpy(str_pos, ua_temp);
						adjust = true;
						if(adjustLength) {
							*adjustLength = true;
						}
					}
				}
			}
		}
		if(adjust) {
			int length = strlen(ua);
			while(ua[length - 1] == ' ') {
				ua[length - 1] = 0;
				--length;
			}
			int start = 0;
			while(ua[start] == ' ') {
				++start;
			}
			if(start) {
				char ua_temp[1024];
				strcpy_null_term(ua_temp, ua + start);
				strcpy(ua, ua_temp);
			}
			if(adjustLength) {
				*adjustLength = true;
			}
		}
	}
	if(opt_cdr_ua_reg_whitelist.size()) {
		bool match = false;
		for(unsigned i = 0; i < opt_cdr_ua_reg_whitelist.size(); i++) {
			if(reg_match(ua, opt_cdr_ua_reg_whitelist[i].c_str(),  __FILE__, __LINE__)) {
				match = true;
				break;
			}
		}
		if(!match) {
			const char *banned_ua_str = "banned UA";
			if(ua_size) {
				strncpy_null_term(ua, banned_ua_str, ua_size);
			} else {
				return(banned_ua_str);
			}
		}
	}
	return(NULL);
}


bool Ss7::sParseData::parse(packet_s_stack *packetS, const char *dissect_rslt) {
	extern void ws_dissect_packet(pcap_pkthdr* header, const u_char* packet, int dlt, string *rslt);
	string dissect_rslt_str;
	if(!dissect_rslt) {
		ws_dissect_packet(packetS->header_pt, packetS->packet, packetS->dlt, &dissect_rslt_str);
		if(!dissect_rslt_str.empty()) {
			dissect_rslt = dissect_rslt_str.c_str();
		}
	}
	if(dissect_rslt) {
		gettag_json(dissect_rslt, "isup.message_type", &isup_message_type, UINT_MAX);
		gettag_json(dissect_rslt, "isup.cic", &isup_cic, UINT_MAX);
		gettag_json(dissect_rslt, "isup.satellite_indicator", &isup_satellite_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "isup.echo_control_device_indicator", &isup_echo_control_device_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "isup.calling_partys_category", &isup_calling_partys_category, UINT_MAX);
		gettag_json(dissect_rslt, "isup.calling_party_nature_of_address_indicator", &isup_calling_party_nature_of_address_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "isup.ni_indicator", &isup_ni_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "isup.address_presentation_restricted_indicator", &isup_address_presentation_restricted_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "isup.screening_indicator", &isup_screening_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "isup.transmission_medium_requirement", &isup_transmission_medium_requirement, UINT_MAX);
		gettag_json(dissect_rslt, "isup.called_party_nature_of_address_indicator", &isup_called_party_nature_of_address_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "isup.inn_indicator", &isup_inn_indicator, UINT_MAX);
		gettag_json(dissect_rslt, "m3ua.protocol_data_opc", &m3ua_protocol_data_opc, UINT_MAX);
		gettag_json(dissect_rslt, "m3ua.protocol_data_dpc", &m3ua_protocol_data_dpc, UINT_MAX);
		gettag_json(dissect_rslt, "mtp3.opc", &mtp3_opc, UINT_MAX);
		gettag_json(dissect_rslt, "mtp3.dpc", &mtp3_dpc, UINT_MAX);
		gettag_json(dissect_rslt, "e164.called_party_number.digits", &e164_called_party_number_digits);
		gettag_json(dissect_rslt, "e164.calling_party_number.digits", &e164_calling_party_number_digits);
		gettag_json(dissect_rslt, "isup.subsequent_number", &isup_subsequent_number);
		gettag_json(dissect_rslt, "isup.cause_indicator", &isup_cause_indicator, UINT_MAX);
		return(true);
	}
	return(false);
}

void Ss7::sParseData::debugOutput() {
	cout << "isup.message_type: " << isup_message_type << endl
	     << "isup.cic: " << isup_cic << endl
	     << "isup.satellite_indicator: " << isup_satellite_indicator << endl
	     << "isup.echo_control_device_indicator: " << isup_echo_control_device_indicator << endl
	     << "isup.calling_partys_category: " << isup_calling_partys_category << endl
	     << "isup.calling_party_nature_of_address_indicator: " << isup_calling_party_nature_of_address_indicator << endl
	     << "isup.ni_indicator: " << isup_ni_indicator << endl
	     << "isup.address_presentation_restricted_indicator: " << isup_address_presentation_restricted_indicator << endl
	     << "isup.screening_indicator: " << isup_screening_indicator << endl
	     << "isup.transmission_medium_requirement: " << isup_transmission_medium_requirement << endl
	     << "isup.called_party_nature_of_address_indicator: " << isup_called_party_nature_of_address_indicator << endl
	     << "isup.inn_indicator: " << isup_inn_indicator << endl
	     << "m3ua.protocol_data_opc: " << m3ua_protocol_data_opc << endl
	     << "m3ua.protocol_data_dpc: " << m3ua_protocol_data_dpc << endl
	     << "mtp3.opc: " << mtp3_opc << endl
	     << "mtp3.dpc: " << mtp3_dpc << endl
	     << "e164.called_party_number.digits: " << e164_called_party_number_digits << endl
	     << "e164.calling_party_number.digits: " << e164_calling_party_number_digits << endl
	     << "isup.subsequent_number: " << isup_subsequent_number << endl
	     << "---" << endl;
}

Ss7::Ss7(u_int64_t time_us) :
 Call_abstract(SS7, time_us),
 pcap(PcapDumper::sip, this) {
	init();
}

void Ss7::processData(packet_s_stack *packetS, sParseData *data) {
	switch(data->isup_message_type) {
	case SS7_IAM:
		last_message_type = iam;
		iam_data = *data;
		iam_src_ip = packetS->saddr_();
		iam_dst_ip = packetS->daddr_();
		if(!iam_time_us) {
			iam_time_us = getTimeUS(packetS->header_pt);
		}
		strcpy_null_term(fbasename, filename().c_str());
		break;
	case SS7_SAM:
		last_message_type = iam;
		sam_data = *data;
		break;
	case SS7_ACM:
		last_message_type = acm;
		if(!acm_time_us) {
			acm_time_us = getTimeUS(packetS->header_pt);
		}
		break;
	case SS7_CPG:
		last_message_type = cpg;
		if(!cpg_time_us) {
			cpg_time_us = getTimeUS(packetS->header_pt);
		}
		break;
	case SS7_ANM:
		last_message_type = anm;
		if(!anm_time_us) {
			anm_time_us = getTimeUS(packetS->header_pt);
		}
		break;
	case SS7_REL:
		last_message_type = rel;
		rel_time_us = getTimeUS(packetS->header_pt);
		rlc_time_us = 0;
		destroy_at_s = getTimeS(packetS->header_pt) + opt_ss7timeout_rel;
		if(isset_unsigned(data->isup_cause_indicator)) {
			rel_cause_indicator = data->isup_cause_indicator;
		}
		break;
	case SS7_RLC:
		last_message_type = rlc;
		rlc_time_us = getTimeUS(packetS->header_pt);
		destroy_at_s = getTimeS(packetS->header_pt) + opt_ss7timeout_rlc;
		break;
	}
	switch(data->isup_message_type) {
	case SS7_IAM:
	case SS7_ACM:
	case SS7_CPG:
	case SS7_ANM:
		destroy_at_s = 0;
		rel_time_us = 0;
		rlc_time_us = 0;
		break;
	}
	last_time_us = getTimeUS(packetS->header_pt);
	if(!pcap.isOpen()) {
		string pathfilename = get_pathfilename(tsf_ss7);
		pcap.open(tsf_ss7, pathfilename.c_str(), useHandle, useDlt);
	}
	if(pcap.isOpen()) {
		if(packetS->header_pt->ts.tv_sec != last_dump_ts.tv_sec ||
		   packetS->header_pt->ts.tv_usec != last_dump_ts.tv_usec) {
			pcap.dump(packetS->header_pt, packetS->packet, packetS->dlt);
			last_dump_ts = packetS->header_pt->ts;
		}
	}
}

void Ss7::pushToQueue(string *ss7_id) {
	calltable->lock_process_ss7_queue();
	calltable->ss7_queue.push_back(this);
	calltable->unlock_process_ss7_queue();
	if(ss7_id) {
		calltable->lock_ss7_listMAP();
		calltable->ss7_listMAP.erase(*ss7_id);
		calltable->unlock_ss7_listMAP();
	}
}

int Ss7::saveToDb(bool enableBatchIfPossible) {
	if(!sqlDbSaveSs7) {
		sqlDbSaveSs7 = createSqlObject();
		sqlDbSaveSs7->setEnableSqlStringInContent(true);
	}
	string sql_ss7_table = "ss7";
	SqlDb_row ss7;
	ss7.add_calldate(iam_time_us, "time_iam", existsColumns.ss7_time_iam_ms);
	if(acm_time_us) {
		ss7.add_calldate(acm_time_us, "time_acm", existsColumns.ss7_time_acm_ms);
	}
	if(cpg_time_us) {
		ss7.add_calldate(cpg_time_us, "time_cpg", existsColumns.ss7_time_cpg_ms);
	}
	if(anm_time_us) {
		ss7.add_calldate(anm_time_us, "time_anm", existsColumns.ss7_time_anm_ms);
	}
	if(rel_time_us) {
		ss7.add_calldate(rel_time_us, "time_rel", existsColumns.ss7_time_rel_ms);
	}
	if(rlc_time_us) {
		ss7.add_calldate(rlc_time_us, "time_rlc", existsColumns.ss7_time_rlc_ms);
	}
	if(rel_time_us || rlc_time_us) {
		ss7.add_duration(max(rel_time_us, rlc_time_us) - iam_time_us, "duration", existsColumns.ss7_duration_ms, true);
		if(anm_time_us) {
			ss7.add_duration(max(rel_time_us, rlc_time_us) - anm_time_us, "connect_duration", existsColumns.ss7_connect_duration_ms, true);
		}
	}
	if(anm_time_us) {
		ss7.add_duration(anm_time_us - iam_time_us, "progress_time", existsColumns.ss7_progress_time_ms, true);
	}
	if(isset_unsigned(iam_data.isup_cic)) {
		ss7.add(iam_data.isup_cic, "cic");
	}
	if(isset_unsigned(iam_data.isup_satellite_indicator)) {
		ss7.add(iam_data.isup_satellite_indicator, "satellite_indicator");
	}
	if(isset_unsigned(iam_data.isup_satellite_indicator)) {
		ss7.add(iam_data.isup_satellite_indicator, "echo_control_device_indicator");
	}
	if(isset_unsigned(iam_data.isup_calling_partys_category)) {
		ss7.add(iam_data.isup_calling_partys_category, "caller_partys_category");
	}
	if(isset_unsigned(iam_data.isup_calling_party_nature_of_address_indicator)) {
		ss7.add(iam_data.isup_calling_party_nature_of_address_indicator, "caller_party_nature_of_address_indicator");
	}
	if(isset_unsigned(iam_data.isup_ni_indicator)) {
		ss7.add(iam_data.isup_ni_indicator, "ni_indicator");
	}
	if(isset_unsigned(iam_data.isup_address_presentation_restricted_indicator)) {
		ss7.add(iam_data.isup_address_presentation_restricted_indicator, "address_presentation_restricted_indicator");
	}
	if(isset_unsigned(iam_data.isup_screening_indicator)) {
		ss7.add(iam_data.isup_screening_indicator, "screening_indicator");
	}
	if(isset_unsigned(iam_data.isup_transmission_medium_requirement)) {
		ss7.add(iam_data.isup_transmission_medium_requirement, "transmission_medium_requirement");
	}
	if(isset_unsigned(iam_data.isup_called_party_nature_of_address_indicator)) {
		ss7.add(iam_data.isup_called_party_nature_of_address_indicator, "called_party_nature_of_address_indicator");
	}
	if(isset_unsigned(iam_data.isup_inn_indicator)) {
		ss7.add(iam_data.isup_inn_indicator, "inn_indicator");
	}
	if(isset_unsigned(iam_data.m3ua_protocol_data_opc)) {
		ss7.add(iam_data.m3ua_protocol_data_opc, "m3ua_protocol_data_opc");
	}
	if(isset_unsigned(iam_data.m3ua_protocol_data_dpc)) {
		ss7.add(iam_data.m3ua_protocol_data_dpc, "m3ua_protocol_data_dpc");
	}
	if(isset_unsigned(iam_data.mtp3_opc)) {
		ss7.add(iam_data.mtp3_opc, "mtp3_opc");
	}
	if(isset_unsigned(iam_data.mtp3_dpc)) {
		ss7.add(iam_data.mtp3_dpc, "mtp3_dpc");
	}
	if(isset_unsigned(iam_data.m3ua_protocol_data_opc) ||
	   isset_unsigned(iam_data.mtp3_opc)) {
		ss7.add(isset_unsigned(iam_data.m3ua_protocol_data_opc) ? iam_data.m3ua_protocol_data_opc : iam_data.mtp3_opc, "opc");
	}
	if(isset_unsigned(iam_data.m3ua_protocol_data_dpc) ||
	   isset_unsigned(iam_data.mtp3_dpc)) {
		ss7.add(isset_unsigned(iam_data.m3ua_protocol_data_dpc) ? iam_data.m3ua_protocol_data_dpc : iam_data.mtp3_dpc, "dpc");
	}
	if(!iam_data.e164_called_party_number_digits.empty()) {
		string called_number = iam_data.e164_called_party_number_digits;
		if(opt_ss7_use_sam_subsequent_number && !sam_data.isup_subsequent_number.empty()) {
			called_number += sam_data.isup_subsequent_number;
		}
		ss7.add(sqlEscapeString(called_number), "called_number");
		ss7.add(sqlEscapeString(reverseString(called_number.c_str())), "called_number_reverse");
		ss7.add(getCountryByPhoneNumber(called_number.c_str(), true), "called_number_country_code");
	}
	if(!iam_data.e164_calling_party_number_digits.empty()) {
		ss7.add(sqlEscapeString(iam_data.e164_calling_party_number_digits), "caller_number");
		ss7.add(sqlEscapeString(reverseString(iam_data.e164_calling_party_number_digits.c_str())), "caller_number_reverse");
		ss7.add(getCountryByPhoneNumber(iam_data.e164_calling_party_number_digits.c_str(), true), "caller_number_country_code");
	}
	if(isset_unsigned(rel_cause_indicator)) {
		ss7.add(rel_cause_indicator, "rel_cause_indicator");
	}
	ss7.add(sqlEscapeString(getStateToString()), "state");
	ss7.add(sqlEscapeString(lastMessageTypeToString()), "last_message_type");
	if(iam_src_ip.isSet()) {
		ss7.add(iam_src_ip, "src_ip", false, sqlDbSaveSs7, sql_ss7_table.c_str());
		ss7.add(getCountryByIP(iam_src_ip, true), "src_ip_country_code");
	}
	if(iam_dst_ip.isSet()) {
		ss7.add(iam_dst_ip, "dst_ip", false, sqlDbSaveSs7, sql_ss7_table.c_str());
		ss7.add(getCountryByIP(iam_dst_ip, true), "dst_ip_country_code");
	}
	ss7.add(sqlEscapeString(ss7_id()), "ss7_id");
	ss7.add(sqlEscapeString(filename()), "pcap_filename");
	if(useSensorId > -1) {
		ss7.add(useSensorId, "id_sensor");
	}
	if(existsColumns.ss7_flags) {
		u_int64_t flags = 0;
		if(sonus) {
			flags |= SS7_FLAG_SONUS;
		}
		if(rudp) {
			flags |= SS7_FLAG_RUDP;
		}
		if(flags) {
			ss7.add(flags, "flags");
		}
	}
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT + 
				   sqlDbSaveSs7->insertQuery("ss7", ss7));
		sqlStore->query_lock(query_str.c_str(), STORE_PROC_ID_SS7, 0);
	} else {
		sqlDbSaveSs7->insert("ss7", ss7);
	}
	return(0);
}

void Ss7::init() {
	last_message_type = iam;
	iam_src_ip.clear();
	iam_dst_ip.clear();
	iam_time_us = 0;
	acm_time_us = 0;
	cpg_time_us = 0;
	anm_time_us = 0;
	rel_time_us = 0;
	rlc_time_us = 0;
	last_time_us = 0;
	rel_cause_indicator = UINT_MAX;
	destroy_at_s = 0;
	sonus = false;
	rudp = false;
	last_dump_ts.tv_sec = 0;
	last_dump_ts.tv_usec = 0;
}


/* constructor */
Calltable::Calltable(SqlDb *sqlDb) {
	/*
	pthread_mutex_init(&qlock, NULL);
	pthread_mutex_init(&qaudiolock, NULL);
	pthread_mutex_init(&qcharts_chache_lock, NULL);
	pthread_mutex_init(&qdellock, NULL);
	pthread_mutex_init(&flock, NULL);
	pthread_mutex_init(&calls_listMAPlock, NULL);
	pthread_mutex_init(&calls_mergeMAPlock, NULL);
	pthread_mutex_init(&registers_listMAPlock, NULL);
	*/

	#if NEW_RTP_FIND__NODES
	calls_ip_port = new FILE_LINE(0) cNodeData<node_call_rtp_ports>;
	calls_ipv6_port = new FILE_LINE(0) cNodeData<node_call_rtp_ports>;
	#elif NEW_RTP_FIND__PORT_NODES || NEW_RTP_FIND__MAP_LIST
	#else
	memset(calls_hash, 0x0, sizeof(calls_hash));
	#endif
	_sync_lock_calls_hash = 0;
	_sync_lock_calls_listMAP = 0;
	_sync_lock_calls_mergeMAP = 0;
	_sync_lock_registers_listMAP = 0;
	_sync_lock_calls_queue = 0;
	_sync_lock_calls_audioqueue = 0;
	_sync_lock_calls_charts_cache_queue = 0;
	_sync_lock_calls_deletequeue = 0;
	_sync_lock_registers_queue = 0;
	_sync_lock_registers_deletequeue = 0;
	_sync_lock_skinny_maps = 0;
	_sync_lock_files_queue = 0;
	_sync_lock_ss7_listMAP = 0;
	_sync_lock_process_ss7_listmap = 0;
	_sync_lock_process_ss7_queue = 0;
	
	if(preProcessPacketCallX_count > 0) {
		calls_listMAP_X = new FILE_LINE(0) map<string, Call*>[preProcessPacketCallX_count];
		_sync_lock_calls_listMAP_X = new FILE_LINE(0) volatile int[preProcessPacketCallX_count];
		for(int i = 0; i < preProcessPacketCallX_count; i++) {
			_sync_lock_calls_listMAP_X[i] = 0;
		}
	} else {
		calls_listMAP_X = NULL;
		_sync_lock_calls_listMAP_X = NULL;
	}
	
	extern int opt_audioqueue_threads_max;
	audioQueueThreadsMax = min(max(2l, sysconf( _SC_NPROCESSORS_ONLN ) - 1), (long)opt_audioqueue_threads_max);
	audioQueueTerminating = 0;
	
	extern char pcapcommand[4092];
	extern char filtercommand[4092];
	if(pcapcommand[0] || filtercommand[0]) {
		asyncSystemCommand = new FILE_LINE(0) AsyncSystemCommand;
	} else {
		asyncSystemCommand = NULL;
	}

	hash_modify_queue_begin_ms = 0;
	_sync_lock_hash_modify_queue = 0;
	
	if(useChartsCacheProcessThreads()) {
		chc_threads = new FILE_LINE(0) sChcThreadData[opt_charts_cache_max_threads];
		for(int i = 0; i < opt_charts_cache_max_threads; i++) {
			chc_threads[i].tid = 0;
			chc_threads[i].thread = 0;
			memset(chc_threads[i].pstat, 0, sizeof(chc_threads[i].pstat));
			chc_threads[i].init = false;
			chc_threads[i].calls = NULL;
			chc_threads[i].cache = NULL;
		}
		chc_threads_count = 0;
		chc_threads_count_mod = 0;
		chc_threads_count_mod_request = 0;
		chc_threads_count_sync = 0;
		chc_threads_count_last_change = 0;
	}
	
	active_calls_cache = NULL;
	active_calls_cache_size = 0;
	active_calls_cache_count = 0;
	active_calls_cache_fill_at_ms = 0;
	active_calls_cache_sync = 0;
	
};

/* destructor */
Calltable::~Calltable() {
	/*
	pthread_mutex_destroy(&qlock);
	pthread_mutex_destroy(&qaudiolock);
	pthread_mutex_destroy(&qcharts_chache_lock);
	pthread_mutex_destroy(&qdellock);
	pthread_mutex_destroy(&flock);
	pthread_mutex_destroy(&calls_listMAPlock);
	pthread_mutex_destroy(&calls_mergeMAPlock);
	pthread_mutex_destroy(&registers_listMAPlock);
	*/
	
	if(calls_listMAP_X) {
		delete [] calls_listMAP_X;
	}
	if(_sync_lock_calls_listMAP_X) {
		delete [] _sync_lock_calls_listMAP_X;
	}
	
	if(asyncSystemCommand) {
		delete asyncSystemCommand;
	}
	
	if(useChartsCacheProcessThreads()) {
		for(int i = 0; i < opt_charts_cache_max_threads; i++) {
			if(chc_threads[i].cache) {
				delete chc_threads[i].cache; 
			}
		}
		delete [] chc_threads;
	}
	
};

/* add node to hash. collisions are linked list of nodes*/
void
Calltable::hashAdd(vmIP addr, vmPort port, struct timeval *ts, Call* call, int iscaller, int is_rtcp, s_sdp_flags sdp_flags) {
 
	call->hash_add_lock();
	if(call->end_call_rtp) {
		call->hash_add_unlock();
		return;
	}
	
	if(sverb.hash_rtp) {
		cout << "hashAdd: " 
		     << call->call_id << " " << addr.getString() << ":" << port << " " 
		     << (is_rtcp ? "rtcp " : "")
		     << iscaller_description(iscaller) << " "
		     << endl;
	}
	
	if(opt_hash_modify_queue_length_ms) {
		sHashModifyData hmd;
		hmd.oper = hmo_add;
		hmd.addr = addr;
		hmd.port = port;
		hmd.time_s = ts ? ts->tv_sec : 0;
		hmd.call = call;
		hmd.iscaller = iscaller;
		hmd.is_rtcp = is_rtcp;
		hmd.sdp_flags = sdp_flags;
		hmd.use_hash_queue_counter = true;
		lock_hash_modify_queue();
		hash_modify_queue.push_back(hmd);
		++call->hash_queue_counter;
		if(ts) {
			_applyHashModifyQueue(ts, true);
		}
		unlock_hash_modify_queue();
	} else {
		_hashAdd(addr, port, ts ? ts->tv_sec : 0, call, iscaller, is_rtcp, sdp_flags);
	}
	
	call->hash_add_unlock();
	
}
 
void
Calltable::_hashAdd(vmIP addr, vmPort port, long int time_s, Call* call, int iscaller, int is_rtcp, s_sdp_flags sdp_flags, bool useLock) {
 
	if(call->end_call_rtp) {
		return;
	}
	
#if NEW_RTP_FIND__NODES

	#if NEW_RTP_FIND__NODES__LIST
	
	node_call_rtp_ports *ports;
	if (useLock) lock_calls_hash();
	if(addr.is_v6()) {
		ports = calls_ipv6_port->add((u_char*)addr.getPointerToIP(), 16
					     #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					     ,(u_char*)&port.port + 1, 1
					     #endif
					     );
	} else {
		ports = calls_ip_port->add((u_char*)addr.getPointerToIP(), 4
					   #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					   ,(u_char*)&port.port + 1, 1
					   #endif
					   );
	}
	node_call_rtp *n_call = &ports->ports[
					      #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					      *((u_char*)&port.port + 0)
					      #else
					      port.port
					      #endif
					      ];
	int found = 0;
	for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end();) {
		if((*iter)->call->destroy_call_at != 0 &&
		   ((*iter)->call->seenbye ||
		    (*iter)->call->lastSIPresponseNum / 10 == 48 ||
		    (time_s != 0 && time_s > (*iter)->call->destroy_call_at))) {
			if(sverb.hash_rtp) {
				cout << "remove call with destroy_call_at: " 
				     << (*iter)->call->call_id << " " << addr.getString() << ":" << port.getString() << " " 
				     << endl;
			}
			--(*iter)->call->rtp_ip_port_counter;
			delete *iter;
			n_call->erase(iter++);
		} else {
			if((*iter)->call == call) {
				found = 1;
				(*iter)->sdp_flags = sdp_flags;
			}
			iter++;
		}
	}
	if(!found) {
		if((int)n_call->size() >= opt_sdp_multiplication) {
			// this port/ip combination is already in (opt_sdp_multiplication) calls - do not add to (opt_sdp_multiplication+1)th to not cause multiplication attack. 
			if(!opt_disable_sdp_multiplication_warning && !call->syslog_sdp_multiplication) {
				string call_ids;
				for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end(); iter++) {
					if(!call_ids.empty()) {
						call_ids += " ";
					}
					call_ids += string("[") + (*iter)->call->fbasename + "]";
				}
				syslog(LOG_NOTICE, "call-id[%s] SDP: %s:%u is already in calls %s. Limit is %u to not cause multiplication DDOS. You can increase it sdp_multiplication = N\n", 
				       call->fbasename, addr.getString().c_str(), (int)port,
				       call_ids.c_str(),
				       opt_sdp_multiplication);
				call->syslog_sdp_multiplication = true;
			}
			if (useLock) unlock_calls_hash();
			return;
		}
		call_rtp *call_new = new FILE_LINE(0) call_rtp;
		call_new->call = call;
		call_new->iscaller = iscaller;
		call_new->is_rtcp = is_rtcp;
		call_new->sdp_flags = sdp_flags;
		n_call->push_back(call_new);
		++call->rtp_ip_port_counter;
		call->rtp_ip_port_list.push_back(vmIPport(addr, port));
	}
	if (useLock) unlock_calls_hash();
	
	#else
	
	node_call_rtp_ports *ports;
	if (useLock) lock_calls_hash();
	if(addr.is_v6()) {
		ports = calls_ipv6_port->add((u_char*)addr.getPointerToIP(), 16
					     #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					     ,(u_char*)&port.port + 1, 1
					     #endif
					     );
	} else {
		ports = calls_ip_port->add((u_char*)addr.getPointerToIP(), 4
					   #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					   ,(u_char*)&port.port + 1, 1
					   #endif
					   );
	}
	node_call_rtp **n_call_ptr = &ports->ports[
						   #if NEW_RTP_FIND__NODES__PORT_MODE == 1
						   *((u_char*)&port.port + 0)
						   #else
						   port.port
						   #endif
						   ];
	node_call_rtp *n_call = *n_call_ptr;
	node_call_rtp *n_prev = NULL;
	int found = 0;
	if(n_call) {
		int count = 0;
		while(n_call) {
			if(n_call->call->destroy_call_at != 0 &&
			   (n_call->call->seenbye ||
			    n_call->call->lastSIPresponseNum / 10 == 48 ||
			    (time_s != 0 && time_s > n_call->call->destroy_call_at))) {
				if(sverb.hash_rtp) {
					cout << "remove call with destroy_call_at: " 
					     << n_call->call->call_id << " " << addr.getString() << ":" << port.getString() << " " 
					     << endl;
				}
				// remove this call
				if(n_prev) {
					n_prev->next = n_call->next;
					--n_call->call->rtp_ip_port_counter;
					delete n_call;
					n_call = n_prev;
					continue;
				} else {
					//removing first node
					*n_call_ptr = (*n_call_ptr)->next;
					--n_call->call->rtp_ip_port_counter;
					delete n_call;
					n_call = *n_call_ptr;
					continue;
				}
			} else {
				if(n_call->call == call) {
					found = 1;
					n_call->sdp_flags = sdp_flags;
				}
				n_prev = n_call;
				n_call = n_call->next;
				count++;
			}
		}
		if(!found && count >= opt_sdp_multiplication) {
			if(!opt_disable_sdp_multiplication_warning && !call->syslog_sdp_multiplication) {
				string call_ids;
				n_call = *n_call_ptr;
				while(n_call != NULL) {
					if(!call_ids.empty()) {
						call_ids += " ";
					}
					call_ids += string("[") + n_call->call->fbasename + "]";
					n_call = n_call->next;
				}
				syslog(LOG_NOTICE, "call-id[%s] SDP: %s:%u is already in calls %s. Limit is %u to not cause multiplication DDOS. You can increase it sdp_multiplication = N\n", 
				       call->fbasename, addr.getString().c_str(), (int)port,
				       call_ids.c_str(),
				       opt_sdp_multiplication);
				call->syslog_sdp_multiplication = true;
			}
			if (useLock) unlock_calls_hash();
			return;
		}
	}
	if(!found) {
		#if 1
		n_call = new FILE_LINE(0) node_call_rtp;
		n_call->next = *n_call_ptr;
		n_call->call = call;
		n_call->iscaller = iscaller;
		n_call->is_rtcp = is_rtcp;
		n_call->sdp_flags = sdp_flags;
		*n_call_ptr = n_call;
		#else
		n_call = new FILE_LINE(0) node_call_rtp;
		n_call->next = NULL;
		n_call->call = call;
		n_call->iscaller = iscaller;
		n_call->is_rtcp = is_rtcp;
		n_call->sdp_flags = sdp_flags;
		if(n_prev) {
			n_prev->next = n_call;
		} else {
			*n_call_ptr = n_call;
		}
		#endif
		++call->rtp_ip_port_counter;
		call->rtp_ip_port_list.push_back(vmIPport(addr, port));
	}
	if (useLock) unlock_calls_hash();
	
	#endif
	
#elif NEW_RTP_FIND__PORT_NODES
	
	node_call_rtp **n_call_ptr;
	if (useLock) lock_calls_hash();
	if(addr.is_v6()) {
		n_call_ptr = (node_call_rtp**)calls_ipv6_port[port.port]._add((u_char*)addr.getPointerToIP(), 16);
	} else {
		n_call_ptr = (node_call_rtp**)calls_ip_port[port.port]._add((u_char*)addr.getPointerToIP(), 4);
	}
	int found = 0;
	if(*n_call_ptr) {
		int count = 0;
		node_call_rtp *n_call = *n_call_ptr;
		node_call_rtp *n_prev = NULL;
		while(n_call) {
			if(n_call->call->destroy_call_at != 0 &&
			   (n_call->call->seenbye ||
			    n_call->call->lastSIPresponseNum / 10 == 48 ||
			    (time_s != 0 && time_s > n_call->call->destroy_call_at))) {
				if(sverb.hash_rtp) {
					cout << "remove call with destroy_call_at: " 
					     << n_call->call->call_id << " " << addr.getString() << ":" << port.getString() << " " 
					     << endl;
				}
				// remove this call
				if(n_prev) {
					n_prev->next = n_call->next;
					--n_call->call->rtp_ip_port_counter;
					delete n_call;
					n_call = n_prev;
					continue;
				} else {
					//removing first node
					*n_call_ptr = (*n_call_ptr)->next;
					--n_call->call->rtp_ip_port_counter;
					delete n_call;
					n_call = *n_call_ptr;
					continue;
				}
			} else {
				if(n_call->call == call) {
					found = 1;
					n_call->sdp_flags = sdp_flags;
				}
				n_prev = n_call;
				n_call = n_call->next;
				count++;
			}
		}
		if(!found && count >= opt_sdp_multiplication) {
			if(!opt_disable_sdp_multiplication_warning && !call->syslog_sdp_multiplication) {
				string call_ids;
				n_call = *n_call_ptr;
				while(n_call != NULL) {
					if(!call_ids.empty()) {
						call_ids += " ";
					}
					call_ids += string("[") + n_call->call->fbasename + "]";
					n_call = n_call->next;
				}
				syslog(LOG_NOTICE, "call-id[%s] SDP: %s:%u is already in calls %s. Limit is %u to not cause multiplication DDOS. You can increase it sdp_multiplication = N\n", 
				       call->fbasename, addr.getString().c_str(), (int)port,
				       call_ids.c_str(),
				       opt_sdp_multiplication);
				call->syslog_sdp_multiplication = true;
			}
			if (useLock) unlock_calls_hash();
			return;
		}
	}
	if(!found) {
		node_call_rtp *n_call = new FILE_LINE(0) node_call_rtp;
		n_call->next = *n_call_ptr;
		n_call->call = call;
		n_call->iscaller = iscaller;
		n_call->is_rtcp = is_rtcp;
		n_call->sdp_flags = sdp_flags;
		*n_call_ptr = n_call;
		++call->rtp_ip_port_counter;
	}
	if (useLock) unlock_calls_hash();
	
	
#elif NEW_RTP_FIND__MAP_LIST
	
	if (useLock) lock_calls_hash();
	u_int64_t ip_port = addr.ip.v4.n;
	ip_port = (ip_port << 32) + port.port;
	node_call_rtp *n_call_rtp;
	map<u_int64_t, node_call_rtp*>::iterator iter = calls_ip_port.find(ip_port);
	if(iter != calls_ip_port.end()) {
		n_call_rtp = iter->second;
	} else {
		n_call_rtp = new FILE_LINE(0) node_call_rtp;
		calls_ip_port[ip_port] = n_call_rtp;
	}
	int found = 0;
	for(list<call_rtp*>::iterator iter = n_call_rtp->begin(); iter != n_call_rtp->end();) {
		if((*iter)->call->destroy_call_at != 0 &&
		   ((*iter)->call->seenbye ||
		    (*iter)->call->lastSIPresponseNum / 10 == 48 ||
		    (time_s != 0 && time_s > (*iter)->call->destroy_call_at))) {
			if(sverb.hash_rtp) {
				cout << "remove call with destroy_call_at: " 
				     << (*iter)->call->call_id << " " << addr.getString() << ":" << port.getString() << " " 
				     << endl;
			}
			--(*iter)->call->rtp_ip_port_counter;
			delete *iter;
			n_call_rtp->erase(iter++);
		} else {
			if((*iter)->call == call) {
				found = 1;
				(*iter)->sdp_flags = sdp_flags;
			}
			iter++;
		}
	}
	if(!found) {
		if((int)n_call_rtp->size() >= opt_sdp_multiplication) {
			// this port/ip combination is already in (opt_sdp_multiplication) calls - do not add to (opt_sdp_multiplication+1)th to not cause multiplication attack. 
			if(!opt_disable_sdp_multiplication_warning && !call->syslog_sdp_multiplication) {
				string call_ids;
				for(list<call_rtp*>::iterator iter = n_call_rtp->begin(); iter != n_call_rtp->end(); iter++) {
					if(!call_ids.empty()) {
						call_ids += " ";
					}
					call_ids += string("[") + (*iter)->call->fbasename + "]";
				}
				syslog(LOG_NOTICE, "call-id[%s] SDP: %s:%u is already in calls %s. Limit is %u to not cause multiplication DDOS. You can increase it sdp_multiplication = N\n", 
				       call->fbasename, addr.getString().c_str(), (int)port,
				       call_ids.c_str(),
				       opt_sdp_multiplication);
				call->syslog_sdp_multiplication = true;
			}
			if (useLock) unlock_calls_hash();
			return;
		}
		call_rtp *call_new = new FILE_LINE(0) call_rtp;
		call_new->call = call;
		call_new->iscaller = iscaller;
		call_new->is_rtcp = is_rtcp;
		call_new->sdp_flags = sdp_flags;
		n_call_rtp->push_back(call_new);
		++call->rtp_ip_port_counter;
	}
	if (useLock) unlock_calls_hash();
	
#else 
	
	u_int32_t h;
	node_call_rtp_ip_port *node = NULL;
	#if not HASH_RTP_FIND__LIST
	node_call_rtp *node_call = NULL;
	#endif

	h = tuplehash(addr.getHashNumber(), port);
	if (useLock) lock_calls_hash();
	// check if there is not already call in hash 
	for (node = calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			// there is already some call which is receiving packets to the same IP:port
			// this can happen if the old call is waiting for hangup and is still in memory or two SIP different sessions shares the same call.
			int found = 0;
			#if HASH_RTP_FIND__LIST
				for(list<call_rtp*>::iterator iter = node->calls.begin(); iter != node->calls.end();) {
					if((*iter)->call->destroy_call_at != 0 &&
					   ((*iter)->call->seenbye ||
					    (*iter)->call->lastSIPresponseNum / 10 == 48 ||
					    (time_s != 0 && time_s > (*iter)->call->destroy_call_at))) {
						if(sverb.hash_rtp) {
							cout << "remove call with destroy_call_at: " 
							     << (*iter)->call->call_id << " " << addr.getString() << ":" << port.getString() << " " 
							     << endl;
						}
						--(*iter)->call->rtp_ip_port_counter;
						delete *iter;
						node->calls.erase(iter++);
					} else {
						if((*iter)->call == call) {
							found = 1;
							(*iter)->sdp_flags = sdp_flags;
						}
						iter++;
					}
				}
				if(!found) {
					if((int)node->calls.size() >= opt_sdp_multiplication) {
						// this port/ip combination is already in (opt_sdp_multiplication) calls - do not add to (opt_sdp_multiplication+1)th to not cause multiplication attack. 
						if(!opt_disable_sdp_multiplication_warning && !call->syslog_sdp_multiplication) {
							string call_ids;
							for(list<call_rtp*>::iterator iter = node->calls.begin(); iter != node->calls.end(); iter++) {
								if(!call_ids.empty()) {
									call_ids += " ";
								}
								call_ids += string("[") + (*iter)->call->fbasename + "]";
							}
							syslog(LOG_NOTICE, "call-id[%s] SDP: %s:%u is already in calls %s. Limit is %u to not cause multiplication DDOS. You can increase it sdp_multiplication = N\n", 
							       call->fbasename, addr.getString().c_str(), (int)port,
							       call_ids.c_str(),
							       opt_sdp_multiplication);
							call->syslog_sdp_multiplication = true;
						}
						if (useLock) unlock_calls_hash();
						return;
					}
					call_rtp *call_new = new FILE_LINE(0) call_rtp;
					call_new->call = call;
					call_new->iscaller = iscaller;
					call_new->is_rtcp = is_rtcp;
					call_new->sdp_flags = sdp_flags;
					node->calls.push_back(call_new);
					++call->rtp_ip_port_counter;
				}
			#else
				int count = 0;
				node_call_rtp *prev = NULL;
				node_call = node->calls;
				while(node_call != NULL) {
					if(node_call->call->destroy_call_at != 0 &&
					   (node_call->call->seenbye ||
					    node_call->call->lastSIPresponseNum / 10 == 48 ||
					    (time_s != 0 && time_s > node_call->call->destroy_call_at))) {
						if(sverb.hash_rtp) {
							cout << "remove call with destroy_call_at: " 
							     << node_call->call->call_id << " " << addr.getString() << ":" << port.getString() << " " 
							     << endl;
						}
						// remove this call
						if(prev) {
							prev->next = node_call->next;
							--node_call->call->rtp_ip_port_counter;
							delete node_call;
							node_call = prev->next;
							continue;
						} else {
							//removing first node
							node->calls = node->calls->next;
							--node_call->call->rtp_ip_port_counter;
							delete node_call;
							node_call = node->calls;
							continue;
						}
					}
					prev = node_call;
					count++;
					if(node_call->call == call) {
						found = 1;
						node_call->sdp_flags = sdp_flags;
					}
					node_call = node_call->next;
				}
				if(!found) {
					if(opt_sdp_multiplication == 0 && count == 1 && node->calls && node->calls->call) {
						--node->calls->call->rtp_ip_port_counter;
						node->calls->call = call;
						node->calls->iscaller = iscaller;
						node->calls->is_rtcp = is_rtcp;
						node->calls->sdp_flags = sdp_flags;
						++call->rtp_ip_port_counter;
					} else {
						if(opt_sdp_multiplication > 0 && count >= opt_sdp_multiplication) {
							// this port/ip combination is already in (opt_sdp_multiplication) calls - do not add to (opt_sdp_multiplication+1)th to not cause multiplication attack. 
							if(!opt_disable_sdp_multiplication_warning && !call->syslog_sdp_multiplication) {
								static u_int64_t lastTimeSyslog = 0;
								u_int64_t actTime = getTimeMS();
								if(actTime - 10 * 1000 > lastTimeSyslog) {
									string call_ids;
									node_call = node->calls;
									while(node_call != NULL) {
										if(!call_ids.empty()) {
											call_ids += " ";
										}
										call_ids += string("[") + node_call->call->fbasename + "]";
										node_call = node_call->next;
									}
									syslog(LOG_NOTICE, "call-id[%s] SDP: %s:%u is already in calls %s. Limit is %u to not cause multiplication DDOS. You can increase it sdp_multiplication = N\n", 
									       call->fbasename, addr.getString().c_str(), (int)port,
									       call_ids.c_str(),
									       opt_sdp_multiplication);
									call->syslog_sdp_multiplication = true;
									lastTimeSyslog = actTime;
								}
							}
							if (useLock) unlock_calls_hash();
							return;
						}
					 
						// the same ip/port is shared with some other call which is not yet in node - add it
						node_call_rtp *node_call_new = new FILE_LINE(1007) node_call_rtp;
						node_call_new->next = node->calls;
						node_call_new->call = call;
						node_call_new->iscaller = iscaller;
						node_call_new->is_rtcp = is_rtcp;
						node_call_new->sdp_flags = sdp_flags;

						//insert at first position
						node->calls = node_call_new;
						++call->rtp_ip_port_counter;
					}
				}
			#endif
			if (useLock) unlock_calls_hash();
			return;
		}
	}

	// addr / port combination not found - add it to hash at first position

	#if HASH_RTP_FIND__LIST
		call_rtp *new_call_rtp = new FILE_LINE(0) call_rtp;
		new_call_rtp->call = call;
		new_call_rtp->iscaller = iscaller;
		new_call_rtp->is_rtcp = is_rtcp;
		new_call_rtp->sdp_flags = sdp_flags;
	
		node = new FILE_LINE(0) node_call_rtp_ip_port;
		node->addr = addr;
		node->port = port;
		node->next = calls_hash[h];
		node->calls.push_back(new_call_rtp);
		calls_hash[h] = node;
	#else
		node_call = new FILE_LINE(1008) node_call_rtp;
		node_call->next = NULL;
		node_call->call = call;
		node_call->iscaller = iscaller;
		node_call->is_rtcp = is_rtcp;
		node_call->sdp_flags = sdp_flags;

		node = new FILE_LINE(1009) node_call_rtp_ip_port;
		node->addr = addr;
		node->port = port;
		node->next = calls_hash[h];
		node->calls = node_call;
		calls_hash[h] = node;
	#endif
	++call->rtp_ip_port_counter;
	if (useLock) unlock_calls_hash();
	
#endif
	
}

/* remove node from hash */
void
Calltable::hashRemove(Call *call, vmIP addr, vmPort port, struct timeval *ts, bool rtcp, bool useHashQueueCounter) {
 
	if(sverb.hash_rtp) {
		cout << "hashRemove: " 
		     << call->call_id << " " 
		     << addr.getString() << ":" << port << " "
		     << (rtcp ? "rtcp" : "") << " "
		     << endl;
	}

	if(opt_hash_modify_queue_length_ms) {
		sHashModifyData hmd;
		hmd.oper = hmo_remove;
		hmd.addr = addr;
		hmd.port = port;
		hmd.call = call;
		hmd.is_rtcp = rtcp;
		hmd.use_hash_queue_counter = useHashQueueCounter;
		lock_hash_modify_queue();
		hash_modify_queue.push_back(hmd);
		if(useHashQueueCounter) {
			++call->hash_queue_counter;
		}
		if(ts) {
			_applyHashModifyQueue(ts, true);
		}
		unlock_hash_modify_queue();
	} else {
		_hashRemove(call, addr, port, rtcp);
	}
	
}

int
Calltable::_hashRemove(Call *call, vmIP addr, vmPort port, bool rtcp, bool use_lock) {
 
#if NEW_RTP_FIND__NODES
 
	#if NEW_RTP_FIND__NODES__LIST
 
	int removeCounter = 0;
	node_call_rtp_ports *ports;
	if (use_lock) lock_calls_hash();
	if(addr.is_v6()) {
		ports = calls_ipv6_port->find((u_char*)addr.getPointerToIP(), 16
					      #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					      ,(u_char*)&port.port + 1, 1
					      #endif
					      );
	} else {
		ports = calls_ip_port->find((u_char*)addr.getPointerToIP(), 4
					    #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					    ,(u_char*)&port.port + 1, 1
					    #endif
					    );
	}
	if(ports) {
		node_call_rtp *n_call = &ports->ports[
						      #if NEW_RTP_FIND__NODES__PORT_MODE == 1
						      *((u_char*)&port.port + 0)
						      #else
						      port.port
						      #endif
						      ];
		for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end();) {
			if((*iter)->call == call && (!rtcp || (rtcp && ((*iter)->is_rtcp || !(*iter)->sdp_flags.rtcp_mux)))) {
				--call->rtp_ip_port_counter;
				delete *iter;
				n_call->erase(iter++);
				++removeCounter;
			} else {
				iter++;
			}
		}
	}
	if (use_lock) unlock_calls_hash();
	return(removeCounter);
	
	#else
	
	int removeCounter = 0;
	node_call_rtp_ports *ports;
	if (use_lock) lock_calls_hash();
	if(addr.is_v6()) {
		ports = calls_ipv6_port->find((u_char*)addr.getPointerToIP(), 16
					      #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					      ,(u_char*)&port.port + 1, 1
					      #endif
					      );
	} else {
		ports = calls_ip_port->find((u_char*)addr.getPointerToIP(), 4
					    #if NEW_RTP_FIND__NODES__PORT_MODE == 1
					    ,(u_char*)&port.port + 1, 1
					    #endif
					    );
	}
	if(ports) {
		node_call_rtp **n_call_ptr = &ports->ports[
							   #if NEW_RTP_FIND__NODES__PORT_MODE == 1
							   *((u_char*)&port.port + 0)
							   #else
							   port.port
							   #endif
							   ];
		node_call_rtp *n_call = *n_call_ptr;
		node_call_rtp *n_prev = NULL;
		for(; n_call; n_call = n_call->next) {
			if(n_call->call == call && (!rtcp || (rtcp && (n_call->is_rtcp || !n_call->sdp_flags.rtcp_mux)))) {
				if(n_prev) {
					n_prev->next = n_call->next;
					--call->rtp_ip_port_counter;
					delete n_call;
					++removeCounter;
				} else {
					*n_call_ptr = n_call->next;
					--call->rtp_ip_port_counter;
					delete n_call;
					++removeCounter;
				}
				break;
			}
			n_prev = n_call;
		}
	}
	if (use_lock) unlock_calls_hash();
	return(removeCounter);
	
	#endif
	
#elif NEW_RTP_FIND__PORT_NODES
	
	int removeCounter = 0;
	node_call_rtp **n_call_ptr;
	if (use_lock) lock_calls_hash();
	if(addr.is_v6()) {
		n_call_ptr = (node_call_rtp**)calls_ipv6_port[port.port]._find_ptr((u_char*)addr.getPointerToIP(), 16);
	} else {
		n_call_ptr = (node_call_rtp**)calls_ip_port[port.port]._find_ptr((u_char*)addr.getPointerToIP(), 4);
	}
	if(n_call_ptr && *n_call_ptr) {
		node_call_rtp *n_call = *n_call_ptr;
		node_call_rtp *n_prev = NULL;
		for(; n_call; n_call = n_call->next) {
			if(n_call->call == call && (!rtcp || (rtcp && (n_call->is_rtcp || !n_call->sdp_flags.rtcp_mux)))) {
				if(n_prev) {
					n_prev->next = n_call->next;
					--call->rtp_ip_port_counter;
					delete n_call;
					++removeCounter;
				} else {
					*n_call_ptr = n_call->next;
					--call->rtp_ip_port_counter;
					delete n_call;
					++removeCounter;
				}
				break;
			}
			n_prev = n_call;
		}
	}
	if (use_lock) unlock_calls_hash();
	return(removeCounter);
	
#elif NEW_RTP_FIND__MAP_LIST
	
	int removeCounter = 0;
	if (use_lock) lock_calls_hash();
	u_int64_t ip_port = addr.ip.v4.n;
	ip_port = (ip_port << 32) + port.port;
	map<u_int64_t, node_call_rtp*>::iterator iter = calls_ip_port.find(ip_port);
	if(iter != calls_ip_port.end()) {
		node_call_rtp *n_call_rtp = iter->second;
		for(list<call_rtp*>::iterator iter = n_call_rtp->begin(); iter != n_call_rtp->end();) {
			if((*iter)->call == call && (!rtcp || (rtcp && ((*iter)->is_rtcp || !(*iter)->sdp_flags.rtcp_mux)))) {
				--call->rtp_ip_port_counter;
				delete *iter;
				n_call_rtp->erase(iter++);
				++removeCounter;
			} else {
				iter++;
			}
		}
		if(!n_call_rtp->size()) {
			delete n_call_rtp;
			calls_ip_port.erase(iter);
		}
	}
	if (use_lock) unlock_calls_hash();
	return(removeCounter);
		
#else 
	
	int removeCounter = 0;
	node_call_rtp_ip_port *node = NULL, *prev = NULL;
	#if not HASH_RTP_FIND__LIST
	node_call_rtp *node_call = NULL, *prev_call = NULL;
	#endif
	int h = tuplehash(addr.getHashNumber(), port);
	if (use_lock) lock_calls_hash();
	for (node = calls_hash[h]; node != NULL; node = node->next) {
		if (node->addr == addr && node->port == port) {
			#if HASH_RTP_FIND__LIST
				for(list<call_rtp*>::iterator iter = node->calls.begin(); iter != node->calls.end();) {
					if((*iter)->call == call && (!rtcp || (rtcp && ((*iter)->is_rtcp || !(*iter)->sdp_flags.rtcp_mux)))) {
						--call->rtp_ip_port_counter;
						delete *iter;
						node->calls.erase(iter++);
						++removeCounter;
					} else {
						iter++;
					}
				}
			#else
				for (node_call = node->calls; node_call != NULL; node_call = node_call->next) {
					// walk through all calls under the node and check if the call matches
					if(node_call->call == call && (!rtcp || (rtcp && (node_call->is_rtcp || !node_call->sdp_flags.rtcp_mux)))) {
						// call matches - remote the call from node->calls
						if (prev_call == NULL) {
							node->calls = node_call->next;
							--node_call->call->rtp_ip_port_counter;
							delete node_call;
							++removeCounter;
						} else {
							prev_call->next = node_call->next;
							--node_call->call->rtp_ip_port_counter;
							delete node_call;
							++removeCounter;
						}
						break;
					}
					prev_call = node_call;
				}
			#endif
			if(
			#if HASH_RTP_FIND__LIST
			node->calls.empty()
			#else
			node->calls == NULL
			#endif
			) {
				// node now contains no calls so we can remove it 
				if (prev == NULL) {
					calls_hash[h] = node->next;
					delete node;
				} else {
					prev->next = node->next;
					delete node;
				}
			}
			break;
		}
		prev = node;
	}
	if (use_lock) unlock_calls_hash();
	return(removeCounter);
	
#endif
	
}

int
Calltable::hashRemove(Call *call, struct timeval *ts, bool useHashQueueCounter) {

	if(opt_hash_modify_queue_length_ms) {
		sHashModifyData hmd;
		hmd.oper = hmo_remove_call;
		hmd.call = call;
		hmd.use_hash_queue_counter = useHashQueueCounter;
		lock_hash_modify_queue();
		hash_modify_queue.push_back(hmd);
		if(useHashQueueCounter) {
			++call->hash_queue_counter;
		}
		if(ts) {
			_applyHashModifyQueue(ts, true);
		}
		unlock_hash_modify_queue();
		return(-1);
	} else {
		return(_hashRemove(call));
	}

}

int
Calltable::hashRemoveForce(Call *call) {
	return(_hashRemove(call));
}
  
int
Calltable::_hashRemove(Call *call, bool use_lock) {
 
#if NEW_RTP_FIND__NODES
 
	int removeCounter = 0;
	if (use_lock) lock_calls_hash();
	for(list<vmIPport>::iterator iter = call->rtp_ip_port_list.begin(); iter != call->rtp_ip_port_list.end(); iter++) {
		removeCounter += _hashRemove(call, iter->ip, iter->port, false, false);
	}
	if (use_lock) unlock_calls_hash();
	return(removeCounter);
	
#elif NEW_RTP_FIND__PORT_NODES || NEW_RTP_FIND__MAP_LIST
	
	return(0);
	
#else
	
	int removeCounter = 0;
	node_call_rtp_ip_port *node = NULL, *prev_node = NULL;
	#if not HASH_RTP_FIND__LIST
	node_call_rtp *node_call = NULL, *prev_node_call = NULL;
	#endif
	if (use_lock) lock_calls_hash();
	for(int h = 0; h < MAXNODE; h++) {
		prev_node = NULL;
		for(node = calls_hash[h]; node != NULL;) {
			#if HASH_RTP_FIND__LIST
				for(list<call_rtp*>::iterator iter = node->calls.begin(); iter != node->calls.end();) {
					if((*iter)->call == call) {
						--call->rtp_ip_port_counter;
						delete *iter;
						node->calls.erase(iter++);
						++removeCounter;
					} else {
						iter++;
					}
				}
			#else
				prev_node_call = NULL;
				for(node_call = node->calls; node_call != NULL;) {
					if(node_call->call == call) {
						++removeCounter;
						if(prev_node_call == NULL) {
							node->calls = node_call->next;
							--node_call->call->rtp_ip_port_counter;
							delete node_call;
							node_call = node->calls; 
						} else {
							prev_node_call->next = node_call->next;
							--node_call->call->rtp_ip_port_counter;
							delete node_call;
							node_call = prev_node_call->next;
						}
					} else {
						prev_node_call = node_call;
						node_call = node_call->next;
					}
				}
			#endif
			if(
			#if HASH_RTP_FIND__LIST
			node->calls.empty()
			#else
			node->calls == NULL
			#endif
			) {
				if(prev_node == NULL) {
					calls_hash[h] = node->next;
					delete node;
					node = calls_hash[h];
				} else {
					prev_node->next = node->next;
					delete node;
					node = prev_node->next;
				}
			} else {
				prev_node = node;
				node = node->next;
			}
		}
	}
	if (use_lock) unlock_calls_hash();
	return(removeCounter);

#endif
	
}

void 
Calltable::applyHashModifyQueue(struct timeval *ts, bool setBegin, bool use_lock_calls_hash) {
	_applyHashModifyQueue(ts, setBegin, use_lock_calls_hash);
}

void 
Calltable::_applyHashModifyQueue(struct timeval *ts, bool setBegin, bool use_lock_calls_hash) {
	if(hash_modify_queue_begin_ms) {
		if(getTimeMS(ts) >= hash_modify_queue_begin_ms + opt_hash_modify_queue_length_ms) {
			if (use_lock_calls_hash) lock_calls_hash();
			for(list<sHashModifyData>::iterator iter = hash_modify_queue.begin(); iter != hash_modify_queue.end(); iter++) {
				switch(iter->oper) {
				case hmo_add:
					_hashAdd(iter->addr, iter->port, iter->time_s, iter->call, iter->iscaller, iter->is_rtcp, iter->sdp_flags, false);
					break;
				case hmo_remove:
					_hashRemove(iter->call, iter->addr, iter->port, iter->is_rtcp, false);
					break;
				case hmo_remove_call:
					_hashRemove(iter->call, false);
					break;
				}
				if(iter->use_hash_queue_counter) {
					--iter->call->hash_queue_counter;
				}
			}
			if (use_lock_calls_hash) unlock_calls_hash();
			hash_modify_queue.clear();
			hash_modify_queue_begin_ms = 0;
		}
	} else {
		if(setBegin) {
			hash_modify_queue_begin_ms = getTimeMS(ts);
		}
	}
}

string Calltable::getHashStats() {
	#if NEW_RTP_FIND__NODES || NEW_RTP_FIND__PORT_NODES || NEW_RTP_FIND__MAP_LIST || HASH_RTP_FIND__LIST
	return("");
	#else
	lock_calls_hash();
	unsigned count_use_nodes = 0;
	unsigned max_node_size = 0;
	unsigned sum_nodes_size = 0;
	for(unsigned i = 0; i < MAXNODE; i++) {
		if(calls_hash[i]) {
			++count_use_nodes;
			unsigned node_size = 0;
			for(node_call_rtp_ip_port *node_ip_port = calltable->calls_hash[i]; node_ip_port; node_ip_port = node_ip_port->next) {
				++node_size;
			}
			if(node_size > max_node_size) {
				max_node_size = node_size;
			}
			sum_nodes_size += node_size;
		}
	}
	unlock_calls_hash();
	return("nodes: " + intToString(count_use_nodes) + "\n" +
	       "max size: " + intToString(max_node_size) + "\n" +
	       "sum size: " + intToString(sum_nodes_size) + "\n" + 
	       "avg size: " + (count_use_nodes ? floatToString((double)sum_nodes_size / count_use_nodes, 1) : "-") + "\n");
	#endif
}

void Calltable::processCallsInAudioQueue(bool lock) {
	if(lock) {
		lock_calls_audioqueue();
	}
	if(audio_queue.size() && 
	   audio_queue.size() > audioQueueThreads.size() * 2 && 
	   audioQueueThreads.size() < audioQueueThreadsMax) {
		sAudioQueueThread *audioQueueThread = new FILE_LINE(1010) sAudioQueueThread();
		audioQueueThreads.push_back(audioQueueThread);
		vm_pthread_create_autodestroy("audio convert",
					      &audioQueueThread->thread_handle, NULL, this->processAudioQueueThread, audioQueueThread, __FILE__, __LINE__);
	}
	if(lock) {
		unlock_calls_audioqueue();
	}
}

void *Calltable::processAudioQueueThread(void *audioQueueThread) {
	((sAudioQueueThread*)audioQueueThread)->thread_id = get_unix_tid();
	setpriority(PRIO_PROCESS, ((sAudioQueueThread*)audioQueueThread)->thread_id, 20);
	u_long last_use_at = getTimeS();
	while(!calltable->audioQueueTerminating) {
		calltable->lock_calls_audioqueue();
		Call *call = NULL;
		if(calltable->audio_queue.size()) {
			call = calltable->audio_queue.front();
			calltable->audio_queue.pop_front();
		}
		calltable->unlock_calls_audioqueue();
		if(call) {
			if(verbosity > 0) printf("converting RAW file to WAV %s\n", call->fbasename);
			call->convertRawToWav();
			if(useChartsCacheInProcessCall()) {
				calltable->lock_calls_charts_cache_queue();
				calltable->calls_charts_cache_queue.push_back(sChartsCallData(sChartsCallData::_call, call));
				calltable->unlock_calls_charts_cache_queue();
			} else {
				calltable->lock_calls_deletequeue();
				calltable->calls_deletequeue.push_back(call);
				calltable->unlock_calls_deletequeue();
			}
			last_use_at = getTimeS();
		} else {
			if((getTimeS() - last_use_at) > 5 * 60) {
				break;
			} else {
				USLEEP(1000);
			}
		}
	}
	calltable->lock_calls_audioqueue();
	calltable->audioQueueThreads.remove((sAudioQueueThread*)audioQueueThread);
	calltable->unlock_calls_audioqueue();
	delete (sAudioQueueThread*)audioQueueThread;
	return(NULL);
}

void Calltable::processCallsInChartsCache_start() {
	chc_threads[0].init = true;
	chc_threads_count = 1;
	vm_pthread_create("charts cache - main thread",
			  &chc_threads[0].thread, NULL, _processCallsInChartsCache_thread, (void*)(long)0, __FILE__, __LINE__);
}

void Calltable::processCallsInChartsCache_stop() {
	if(!chc_threads_count) {
		return;
	}
	terminating_charts_cache = 1;
	pthread_join(chc_threads[0].thread, NULL);
	while(__sync_lock_test_and_set(&chc_threads_count_sync, 1));
	for(int i = 1; i < chc_threads_count; i++) {
		sem_post(&chc_threads[i].sem[0]);
		pthread_join(chc_threads[i].thread, NULL);
		for(int j = 0; j < 2; j++) {
			sem_destroy(&chc_threads[i].sem[j]);
		}
	}
	__sync_lock_release(&chc_threads_count_sync);
}

u_int32_t counter_charts_cache;
u_int64_t counter_charts_cache_delay_us;

void Calltable::processCallsInChartsCache_thread(int threadIndex) {
	chc_threads[threadIndex].tid = get_unix_tid();
	if(!chc_threads[threadIndex].cache && opt_charts_cache_ip_boost) {
		chc_threads[threadIndex].cache = new FILE_LINE(0) cFiltersCache(2000, 10000);
	}
	if(threadIndex == 0) {
		chc_threads[0].calls = new FILE_LINE(0) list<sChartsCallData>;
		while(1) {
			while(__sync_lock_test_and_set(&chc_threads_count_sync, 1));
			chc_threads_count_mod = chc_threads_count_mod_request;
			chc_threads_count_mod_request = 0;
			if((chc_threads_count_mod > 0 && chc_threads_count == opt_charts_cache_max_threads) ||
			   (chc_threads_count_mod < 0 && chc_threads_count == 1)) {
				chc_threads_count_mod = 0;
			}
			if(chc_threads_count_mod > 0) {
				syslog(LOG_NOTICE, "charts cache - creating next thread %i", chc_threads_count);
				if(!chc_threads[chc_threads_count].init) {
					chc_threads[chc_threads_count].calls = new FILE_LINE(0) list<sChartsCallData>;
					for(int i = 0; i < 2; i++) {
						sem_init(&chc_threads[chc_threads_count].sem[i], 0, 0);
					}
					chc_threads[chc_threads_count].init = true;
				}
				memset(chc_threads[chc_threads_count].pstat, 0, sizeof(chc_threads[chc_threads_count].pstat));
				vm_pthread_create(("charts cache - next thread " + intToString(chc_threads_count)).c_str(),
						  &chc_threads[chc_threads_count].thread, NULL, _processCallsInChartsCache_thread, (void*)(long)(chc_threads_count), __FILE__, __LINE__);
				while(chc_threads_count_mod > 0) {
					USLEEP(100000);
				}
				++chc_threads_count;
				USLEEP(250000);
			}
			calltable->lock_calls_charts_cache_queue();
			size_t chc_count = 0;
			size_t chc_size = calltable->calls_charts_cache_queue.size();
			while(chc_size > 0) {
				sChartsCallData callData = calltable->calls_charts_cache_queue.front();
				if(chc_threads_count > 1) {
					chc_threads[chc_count % chc_threads_count].calls->push_back(callData);
				} else {
					chc_threads[0].calls->push_back(callData);
				}
				++chc_count;
				calltable->calls_charts_cache_queue.pop_front();
				--chc_size;
				if(chc_count >= 5000) {
					break;
				}
			}
			calltable->unlock_calls_charts_cache_queue();
			if(chc_count) {
				u_int64_t _start = getTimeUS();
				if(chc_threads_count > 1) {
					for(int i = 1; i < chc_threads_count; i++) {
						sem_post(&chc_threads[i].sem[0]);
					}
				}
				list<Call*> calls_for_delete;
				for(list<sChartsCallData>::iterator iter_call_data = chc_threads[threadIndex].calls->begin(); iter_call_data != chc_threads[threadIndex].calls->end(); iter_call_data++) {
					switch(iter_call_data->type) {
					case sChartsCallData::_call:
						{
						Call *call = (Call*)iter_call_data->data;
						if(!call->isEmptyCdrRow()) {
							sChartsCacheCallData chartsCacheCallData;
							chartsCacheAddCall(&*iter_call_data, &chartsCacheCallData, chc_threads[threadIndex].cache, threadIndex);
						}
						calls_for_delete.push_back(call);
						}
						break;
					case sChartsCallData::_tables_content:
						{
						cDbTablesContent *tablesContent = (cDbTablesContent*)iter_call_data->data;
						sChartsCacheCallData chartsCacheCallData;
						chartsCacheAddCall(&*iter_call_data, &chartsCacheCallData, chc_threads[threadIndex].cache, threadIndex);
						delete tablesContent;
						}
						break;
					case sChartsCallData::_csv:
						{
						string *csv = (string*)iter_call_data->data;
						cDbTablesContent *tablesContent = new FILE_LINE(0) cDbTablesContent;
						vector<string> query_vect = split(csv->c_str(), "\n", false, false);
						for(unsigned i = 0; i < query_vect.size(); i++) {
							tablesContent->addCsvRow(query_vect[i].c_str());
						}
						sChartsCallData call_data(sChartsCallData::_tables_content, tablesContent);
						sChartsCacheCallData chartsCacheCallData;
						chartsCacheAddCall(&call_data, &chartsCacheCallData, chc_threads[threadIndex].cache, threadIndex);
						delete tablesContent;
						delete csv;
						}
						break;
					}
				}
				if(calls_for_delete.size()) {
					calltable->lock_calls_deletequeue();
					for(list<Call*>::iterator iter_call = calls_for_delete.begin(); iter_call != calls_for_delete.end(); iter_call++) {
						calltable->calls_deletequeue.push_back(*iter_call);
					}
					calltable->unlock_calls_deletequeue();
				}
				chc_threads[threadIndex].calls->clear();
				if(chc_threads_count > 1) {
					for(int i = 1; i < chc_threads_count; i++) {
						sem_wait(&chc_threads[i].sem[1]);
					}
				}
				u_int64_t _end = getTimeUS();
				counter_charts_cache += chc_count;
				counter_charts_cache_delay_us += _end - _start;
				if(chc_threads_count_mod < 0) {
					--chc_threads_count;
					chc_threads_count_mod = 0;
				}
			}
			__sync_lock_release(&chc_threads_count_sync);
			chartsCacheStore();
			chartsCacheCleanup();
			chartsCacheReload();
			chartsCacheInitIntervals();
			if(!chc_size) {
				USLEEP(100000);
			}
			if(terminating_charts_cache && (!chc_count || terminating > 1)) {
				break;
			}
		}
		terminating_charts_cache = 2;
	} else {
		if(chc_threads_count_mod > 0 &&
		   threadIndex == chc_threads_count) {
			 chc_threads_count_mod = 0;
		}
		while(terminating_charts_cache < 2) {
			sem_wait(&chc_threads[threadIndex].sem[0]);
			if(terminating_charts_cache == 2) {
				break;
			}
			list<Call*> calls_for_delete;
			for(list<sChartsCallData>::iterator iter_call_data = chc_threads[threadIndex].calls->begin(); iter_call_data != chc_threads[threadIndex].calls->end(); iter_call_data++) {
				switch(iter_call_data->type) {
				case sChartsCallData::_call:
					{
					Call *call = (Call*)iter_call_data->data;
					if(!call->isEmptyCdrRow()) {
						sChartsCacheCallData chartsCacheCallData;
						chartsCacheAddCall(&*iter_call_data, &chartsCacheCallData, chc_threads[threadIndex].cache, threadIndex);
					}
					calls_for_delete.push_back(call);
					}
					break;
				case sChartsCallData::_tables_content:
					{
					cDbTablesContent *tablesContent = (cDbTablesContent*)iter_call_data->data;
					sChartsCacheCallData chartsCacheCallData;
					chartsCacheAddCall(&*iter_call_data, &chartsCacheCallData, chc_threads[threadIndex].cache, threadIndex);
					delete tablesContent;
					}
					break;
				case sChartsCallData::_csv:
					{
					string *csv = (string*)iter_call_data->data;
					cDbTablesContent *tablesContent = new FILE_LINE(0) cDbTablesContent;
					vector<string> query_vect = split(csv->c_str(), "\n", false, false);
					for(unsigned i = 0; i < query_vect.size(); i++) {
						tablesContent->addCsvRow(query_vect[i].c_str());
					}
					sChartsCallData call_data(sChartsCallData::_tables_content, tablesContent);
					sChartsCacheCallData chartsCacheCallData;
					chartsCacheAddCall(&call_data, &chartsCacheCallData, chc_threads[threadIndex].cache, threadIndex);
					delete tablesContent;
					delete csv;
					}
					break;
				}
			}
			if(calls_for_delete.size()) {
				calltable->lock_calls_deletequeue();
				for(list<Call*>::iterator iter_call = calls_for_delete.begin(); iter_call != calls_for_delete.end(); iter_call++) {
					calltable->calls_deletequeue.push_back(*iter_call);
				}
				calltable->unlock_calls_deletequeue();
			}
			chc_threads[threadIndex].calls->clear();
			bool stop = false;
			if(chc_threads_count_mod < 0 &&
			   (threadIndex + 1) == chc_threads_count) {
				stop = true;
			}
			sem_post(&chc_threads[threadIndex].sem[1]);
			if(stop) {
				syslog(LOG_NOTICE, "charts cache - stop next thread %i", threadIndex);
				break;
			}
		}
	}
	chc_threads[threadIndex].tid = 0;
	chc_threads[threadIndex].thread = 0;
	delete chc_threads[threadIndex].calls;
}

void *Calltable::_processCallsInChartsCache_thread(void *_threadIndex) {
	calltable->processCallsInChartsCache_thread((int)(long)_threadIndex);
	return(NULL);
}

void Calltable::processCallsInChartsCache_thread_add() {
	if(getTimeS() > chc_threads_count_last_change + 30) {
		if(chc_threads_count < opt_charts_cache_max_threads &&
		   chc_threads_count_mod == 0 &&
		   chc_threads_count_mod_request == 0) {
			chc_threads_count_mod_request = 1;
			chc_threads_count_last_change = getTimeS();
		}
	}
}

void Calltable::processCallsInChartsCache_thread_remove() {
 
	return;
	// suppress - unstable !
 
	if(getTimeS() > chc_threads_count_last_change + 300) {
		if(chc_threads_count > 1 &&
		   chc_threads_count_mod == 0 &&
		   chc_threads_count_mod_request == 0) {
			chc_threads_count_mod_request = -1;
			chc_threads_count_last_change = getTimeS();
		}
	}
}

string Calltable::processCallsInChartsCache_cpuUsagePerc(double *avg) {
	if(!useChartsCacheProcessThreads()) {
		return("");
	}
	ostringstream cpuStr;
	cpuStr << fixed;
	double cpu_sum = 0;
	unsigned cpu_count = 0;
	while(__sync_lock_test_and_set(&chc_threads_count_sync, 1));
	for(int i = 0; i < chc_threads_count; i++) {
		double cpu = get_cpu_usage_perc(chc_threads[i].tid, chc_threads[i].pstat);
		if(cpu > 0) {
			if(cpu_count) {
				cpuStr << '/';
			}
			cpuStr << setprecision(1) << cpu;
			cpu_sum += cpu;
			++cpu_count;
		}
	}
	__sync_lock_release(&chc_threads_count_sync);
	if(avg) {
		*avg = cpu_count ? cpu_sum / cpu_count : 0;
	}
	return(cpuStr.str());
}

void
Calltable::destroyCallsIfPcapsClosed() {
	this->lock_calls_deletequeue();
	if(this->calls_deletequeue.size() > 0) {
		size_t size = this->calls_deletequeue.size();
		for(size_t i = 0; i < size;) {
			Call *call = this->calls_deletequeue[i];
			if(call->isPcapsClose() && call->isEmptyChunkBuffersCount()) {
				call->destroyCall();
				delete call;
				this->calls_deletequeue.erase(this->calls_deletequeue.begin() + i);
				--size;
			} else {
				i++;
			}
		}
	}
	this->unlock_calls_deletequeue();
}

void
Calltable::destroyRegistersIfPcapsClosed() {
	this->lock_registers_deletequeue();
	if(this->registers_deletequeue.size() > 0) {
		size_t size = this->registers_deletequeue.size();
		for(size_t i = 0; i < size;) {
			Call *reg = this->registers_deletequeue[i];
			if(reg->isPcapsClose() && reg->isEmptyChunkBuffersCount()) {
				reg->atFinish();
				reg->registers_counter_dec();
				delete reg;
				this->registers_deletequeue.erase(this->registers_deletequeue.begin() + i);
				--size;
			} else {
				i++;
			}
		}
	}
	this->unlock_registers_deletequeue();
}

void 
Calltable::mgcpCleanupTransactions(Call *call) {
	for(list<u_int32_t>::iterator iter_transactions = call->mgcp_transactions.begin(); iter_transactions != call->mgcp_transactions.end(); iter_transactions++) {
		sStreamId2 streamId2(call->saddr, call->sport, call->daddr, call->dport, *iter_transactions, true);
		map<sStreamId2, Call*>::iterator iter_streamid2 = calls_by_stream_id2_listMAP.find(streamId2);
		if(iter_streamid2 != calls_by_stream_id2_listMAP.end()) {
			calls_by_stream_id2_listMAP.erase(iter_streamid2);
		}
	}
}

void 
Calltable::mgcpCleanupStream(Call *call) {
	sStreamId streamId(call->saddr, call->sport, call->daddr, call->dport, true);
	map<sStreamId, Call*>::iterator iter_stream = calls_by_stream_listMAP.find(streamId);
	if(iter_stream != calls_by_stream_listMAP.end() && iter_stream->second == call) {
		calls_by_stream_listMAP.erase(streamId);
	}
}

string 
Calltable::getCallTableJson(char *params, bool *zip) {
 
	unsigned int now = time(NULL);
	u_int64_t now_ms = getTimeMS();
	
	if(opt_processing_limitations && opt_processing_limitations_active_calls_cache &&
	   opt_processing_limitations_active_calls_cache_type == 2) {
		__SYNC_LOCK(active_calls_cache_sync);
		for(map<string, d_item2<u_int32_t, string> >::iterator iter = active_calls_cache_map.begin();
		    iter != active_calls_cache_map.end();) {
			if(now > iter->second.item1 && now - iter->second.item1 > processing_limitations.activeCallsCacheTimeout()) {
				active_calls_cache_map.erase(iter++);
			} else {
				iter++;
			}
		}
		map<string, d_item2<u_int32_t, string> >::iterator iter = active_calls_cache_map.find(params);
		if(iter != active_calls_cache_map.end()) {
			string rslt = iter->second.item2;
			__SYNC_UNLOCK(active_calls_cache_sync);
			return(rslt);
		}
		__SYNC_UNLOCK(active_calls_cache_sync);
	}
 
	vector<cCallFilter*> callFilters;
	int limit = -1;
	int sortByIndex = convCallFieldToFieldIndex(cf_calldate_num);
	bool sortDesc = true;
	bool needSensorMap = false;
	bool needIpMap = false;
	if(params && *params) {
		JsonItem jsonParams;
		jsonParams.parse(params);
		if(jsonParams.getItem("limit")) {
			limit = atol(jsonParams.getValue("limit").c_str());
		}
		if(jsonParams.getItem("sort_field")) {
			string sortBy = jsonParams.getValue("sort_field");
			int _sortByIndex = convCallFieldToFieldIndex(convCallFieldToFieldId(sortBy.c_str()));
			if(_sortByIndex >= 0) {
				sortByIndex = _sortByIndex;
			}
		}
		if(jsonParams.getItem("sort_dir")) {
			string sortDir = jsonParams.getValue("sort_dir");
			std::transform(sortDir.begin(), sortDir.end(), sortDir.begin(), ::tolower);
			sortDesc = sortDir.substr(0, 4) == "desc";
		}
		if(zip && jsonParams.getItem("zip")) {
			string zipParam = jsonParams.getValue("zip");
			std::transform(zipParam.begin(), zipParam.end(), zipParam.begin(), ::tolower);
			*zip = zipParam == "yes";
		}
		if(jsonParams.getItem("sensor_map")) {
			string sensor_map = jsonParams.getValue("sensor_map");
			std::transform(sensor_map.begin(), sensor_map.end(), sensor_map.begin(), ::tolower);
			needSensorMap = sensor_map == "yes";
		}
		if(jsonParams.getItem("ip_map")) {
			string ip_map = jsonParams.getValue("ip_map");
			std::transform(ip_map.begin(), ip_map.end(), ip_map.begin(), ::tolower);
			needIpMap = ip_map == "yes";
		}
		string filter = jsonParams.getValue("filter");
		if(!filter.empty()) {
			if(filter[0] == '[') {
				JsonItem jsonFilter;
				jsonFilter.parse(filter);
				for(unsigned i = 0; i < jsonFilter.getLocalCount(); i++) {
					JsonItem *item = jsonFilter.getLocalItem(i);
					string filter = item->getLocalValue();
					callFilters.push_back(new FILE_LINE(0) cCallFilter(filter.c_str()));
				}
			} else {
				callFilters.push_back(new FILE_LINE(0) cCallFilter(filter.c_str()));
			}
		}
	} else {
		if(zip) {
			*zip = false;
		}
	}
	
	Call **active_calls = NULL;
	u_int32_t active_calls_size = 0;
	u_int32_t active_calls_count = 0;
	bool need_refresh_active_calls_cache = false;

	if(opt_processing_limitations && opt_processing_limitations_active_calls_cache &&
	   opt_processing_limitations_active_calls_cache_type == 1) {
		__SYNC_LOCK(active_calls_cache_sync);
		if(active_calls_cache && now_ms > active_calls_cache_fill_at_ms &&
		   now_ms - active_calls_cache_fill_at_ms > processing_limitations.activeCallsCacheTimeout() * 1000) {
			need_refresh_active_calls_cache = true;
		} else if(active_calls_cache) {
			active_calls_size = active_calls_cache_size;
			active_calls_count = active_calls_cache_count;
			active_calls = new FILE_LINE(0) Call*[active_calls_size];
			memcpy(active_calls, active_calls_cache, active_calls_count * sizeof(Call*));
		}
	}
	
	if(!active_calls) {
		active_calls_size = getCountCalls();
		if(active_calls_size) {
			active_calls_size += active_calls_size / 4;
			active_calls = new FILE_LINE(0) Call*[active_calls_size];
			active_calls_count = 0;
			for(int passTypeCall = 0; passTypeCall < 2; passTypeCall++) {
				int typeCall = passTypeCall == 0 ? INVITE : MGCP;
				for(int passListMap = -1; passListMap < (typeCall == INVITE && useCallFindX() ? preProcessPacketCallX_count : 0); passListMap++) {
					map<string, Call*> *_calls_listMAP;
					list<Call*>::iterator callIT1;
					map<string, Call*>::iterator callMAPIT1;
					map<sStreamIds2, Call*>::iterator callMAPIT2;
					if(typeCall == INVITE) {
						if(opt_call_id_alternative[0]) {
							lock_calls_listMAP();
							callIT1 = calltable->calls_list.begin();
						} else {
							if(passListMap == -1) {
								lock_calls_listMAP();
								_calls_listMAP = &calls_listMAP;
							} else {
								lock_calls_listMAP_X(passListMap);
								_calls_listMAP = &calls_listMAP_X[passListMap];
							}
							callMAPIT1 = _calls_listMAP->begin();
						}
					} else {
						lock_calls_listMAP();
						callMAPIT2 = calltable->calls_by_stream_callid_listMAP.begin();
					}
					while(typeCall == INVITE ? 
					       (opt_call_id_alternative[0] ?
						 callIT1 != calltable->calls_list.end() :
						 callMAPIT1 != _calls_listMAP->end()) : 
					       callMAPIT2 != calltable->calls_by_stream_callid_listMAP.end()) {
						Call *call;
						if(typeCall == INVITE) {
							call = opt_call_id_alternative[0] ? *callIT1 : callMAPIT1->second;
						} else {
							call = (*callMAPIT2).second;
						}
						extern int opt_blockcleanupcalls;
						if(!(call->exclude_from_active_calls or
						     call->attemptsClose or
						     call->typeIs(REGISTER) or call->typeIsOnly(MESSAGE) or 
						     (call->seenbye and call->seenbyeandok) or
						     (!opt_blockcleanupcalls &&
						      ((call->destroy_call_at and call->destroy_call_at < now) or 
						       (call->destroy_call_at_bye and call->destroy_call_at_bye < now) or 
						       (call->destroy_call_at_bye_confirmed and call->destroy_call_at_bye_confirmed < now))))) {
							if(active_calls_count < active_calls_size) {
								active_calls[active_calls_count++] = call;
								__SYNC_INC(call->useInListCalls);
							}
						}
						if(typeCall == INVITE) {
							if(opt_call_id_alternative[0]) {
								++callIT1;
							} else {
								++callMAPIT1;
							}
						} else {
							++callMAPIT2;
						}
					}
					if(typeCall == INVITE) {
						if(opt_call_id_alternative[0]) {
							unlock_calls_listMAP();
						} else {
							if(passListMap == -1) {
								unlock_calls_listMAP();
							} else {
								unlock_calls_listMAP_X(passListMap);
							}
						}
					} else {
						unlock_calls_listMAP();
					}
				}
			}
		}
	}
	
	if(opt_processing_limitations && opt_processing_limitations_active_calls_cache &&
	   opt_processing_limitations_active_calls_cache_type == 1) {
		if(active_calls_count) {
			for(unsigned i = 0; i < active_calls_count; i++) {
				__SYNC_INC(active_calls[i]->useInListCalls);
			}
		}
		if(need_refresh_active_calls_cache) {
			for(unsigned i = 0; i < active_calls_cache_count; i++) {
				__SYNC_DEC(active_calls_cache[i]->useInListCalls);
			}
			delete [] active_calls_cache;
			active_calls_cache = NULL;
			active_calls_cache_size = 0;
			active_calls_cache_count = 0;
		}
		if(active_calls_count) {
			if(!active_calls_cache) {
				active_calls_cache_size = active_calls_size;
				active_calls_cache_count = active_calls_count;
				active_calls_cache = new FILE_LINE(0) Call*[active_calls_cache_size];
				memcpy(active_calls_cache, active_calls, active_calls_cache_count * sizeof(Call*));
				active_calls_cache_fill_at_ms = now_ms;
			}
		}
		__SYNC_UNLOCK(active_calls_cache_sync);
	}
	
	unsigned custom_headers_size = 0;
	unsigned custom_headers_reserve = 0;
	if(custom_headers_cdr) {
		custom_headers_size = custom_headers_cdr->getSize();
		custom_headers_reserve = 5;
	}
	list<RecordArray*> records;
	u_int32_t counter = 0;
	map<int32_t, u_int32_t> sensor_map;
	map<vmIP, u_int32_t> ip_src_map;
	map<vmIP, u_int32_t> ip_dst_map;
	for(unsigned i = 0; i < active_calls_count; i++) {	
		Call *call = active_calls[i];
		bool okCallFilters = true;
		if(callFilters.size()) {
			for(unsigned i = 0; i < callFilters.size(); i++) {
				if(!callFilters[i]->check(call)) {
					okCallFilters = false;
					break;
				}
			}
		}
		if(okCallFilters) {
			if(limit != 0) {
				RecordArray *rec = new FILE_LINE(0) RecordArray(sizeof(callFields) / sizeof(callFields[0]) + 
										custom_headers_size + custom_headers_reserve);
				call->getRecordData(rec);
				rec->sortBy = sortByIndex;
				rec->sortBy2 = convCallFieldToFieldIndex(cf_calldate_num);
				records.push_back(rec);
			} else {
				++counter;
			}
			if(needSensorMap) {
				if(sensor_map.find(call->useSensorId) == sensor_map.end()) {
					sensor_map[call->useSensorId] = 1;
				} else {
					++sensor_map[call->useSensorId];
				}
			}
			if(needIpMap) {
				if(ip_src_map.find(call->getSipcallerip()) == ip_src_map.end()) {
					ip_src_map[call->getSipcallerip()] = 1;
				} else {
					++ip_src_map[call->getSipcallerip()];
				}
				if(ip_dst_map.find(call->getSipcalledip()) == ip_dst_map.end()) {
					ip_dst_map[call->getSipcalledip()] = 1;
				} else {
					++ip_dst_map[call->getSipcalledip()];
				}
				if(call->is_set_proxies()) {
					set<vmIP> proxies_undup;
					call->proxies_undup(&proxies_undup);
					for(set<vmIP>::iterator iter_undup = proxies_undup.begin(); iter_undup != proxies_undup.end(); ++iter_undup) {
						if(*iter_undup == call->getSipcalledip()) { 
							continue;
						}
						if(ip_dst_map.find(*iter_undup) == ip_dst_map.end()) {
							ip_dst_map[*iter_undup] = 1;
						} else {
							++ip_dst_map[*iter_undup];
						}
					}
				}
			}
		}
		__SYNC_DEC(call->useInListCalls);
	}
	
	delete [] active_calls;
	
	string table;
	JsonExport jsonExport;
	jsonExport.add("total", limit != 0 ? records.size() : counter);
	jsonExport.add("is_receiver", is_receiver());
	jsonExport.add("is_server", is_server());
	jsonExport.add("id_sensor", opt_id_sensor);
	if(needSensorMap) {
		JsonExport *jsonExport_sensor_map = jsonExport.addObject("sensors");
		for(map<int32_t, u_int32_t>::iterator iter = sensor_map.begin(); iter != sensor_map.end(); iter++) {
			jsonExport_sensor_map->add(intToString(iter->first).c_str(), iter->second);
		}
	}
	if(needIpMap) {
		JsonExport *jsonExport_ip_src_map = jsonExport.addObject("ip_src");
		for(map<vmIP, u_int32_t>::iterator iter = ip_src_map.begin(); iter != ip_src_map.end(); iter++) {
			jsonExport_ip_src_map->add(((vmIP)iter->first).getString().c_str(), iter->second);
		}
		JsonExport *jsonExport_ip_dst_map = jsonExport.addObject("ip_dst");
		for(map<vmIP, u_int32_t>::iterator iter = ip_dst_map.begin(); iter != ip_dst_map.end(); iter++) {
			jsonExport_ip_dst_map->add(((vmIP)iter->first).getString().c_str(), iter->second);
		}
	}
	string total = jsonExport.getJson();
	if(limit != 0) {
		table = "[" + 
			Call::getJsonHeader();
		if(params && *params) {
			table += ",[" + total + "]";
		}
		if(sortByIndex >= 0) {
			records.sort();
		}
		list<RecordArray*>::iterator iter_rec = sortDesc ? records.end() : records.begin();
		if(sortDesc) {
			iter_rec--;
		}
		u_int32_t counter = 0;
		while(counter < records.size() && iter_rec != records.end()) {
			string rec_json = (*iter_rec)->getJson();
			extern cUtfConverter utfConverter;
			if(!utfConverter.check(rec_json.c_str())) {
				rec_json = utfConverter.remove_no_ascii(rec_json.c_str());
			}
			table += "," + rec_json;
			if(sortDesc) {
				if(iter_rec != records.begin()) {
					iter_rec--;
				} else {
					break;
				}
			} else {
				iter_rec++;
			}
			++counter;
			if(limit > 0 && counter >= (unsigned)limit) {
				break;
			}
		}
		table += "]";
	} else {
		table = total;
	}
	for(list<RecordArray*>::iterator iter_rec = records.begin(); iter_rec != records.end(); iter_rec++) {
		(*iter_rec)->free();
		delete *iter_rec;
	}
	if(callFilters.size()) {
		for(unsigned i = 0; i < callFilters.size(); i++) {
			delete callFilters[i];
		}
	}
	
	if(opt_processing_limitations && opt_processing_limitations_active_calls_cache &&
	   opt_processing_limitations_active_calls_cache_type == 2) {
		__SYNC_LOCK(active_calls_cache_sync);
		d_item2<u_int32_t, string> cache_data(now, table);
		active_calls_cache_map[params] = cache_data;
		__SYNC_UNLOCK(active_calls_cache_sync);
	}
	
	return(table);
}

Call*
Calltable::add(int call_type, char *call_id, unsigned long call_id_len, vector<string> *call_id_alternative,
	       u_int64_t time_us, vmIP saddr, vmPort port,
	       pcap_t *handle, int dlt, int sensorId, int8_t ci) {
	Call *newcall = new FILE_LINE(1011) Call(call_type, call_id, call_id_len, call_id_alternative, time_us);
	newcall->in_preprocess_queue_before_process_packet = is_enable_packetbuffer() ? 1 : 0;
	newcall->in_preprocess_queue_before_process_packet_at[0] = TIME_US_TO_S(time_us);
	newcall->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;

	if(handle) {
		newcall->useHandle = handle;
	}
	if(dlt) {
		newcall->useDlt = dlt;
	}
	if(sensorId > -1) {
		newcall->useSensorId = sensorId;
	}
	newcall->saddr = saddr;
	newcall->sport = port;
	
	//flags
	set_global_flags(newcall->flags);

	string call_idS = call_id_len ? string(call_id, call_id_len) : string(call_id);
	if(call_type == REGISTER) {
		lock_registers_listMAP();
		registers_listMAP[call_idS] = newcall;
		newcall->registers_counter_inc();
		unlock_registers_listMAP();
	} else {
		if(ci >= 0) {
			lock_calls_listMAP_X(ci);
			calls_listMAP_X[ci][call_idS] = newcall;
			newcall->calls_counter_inc();
			unlock_calls_listMAP_X(ci);
		} else {
			lock_calls_listMAP();
			calls_listMAP[call_idS] = newcall;
			if(opt_call_id_alternative[0]) {
				calls_list.push_back(newcall);
				if(call_id_alternative) {
					for(unsigned i = 0; i < call_id_alternative->size(); i++) {
						calls_listMAP[(*call_id_alternative)[i]] = newcall;
					}
				}
			}
			newcall->calls_counter_inc();
			unlock_calls_listMAP();
		}
	}
	return newcall;
}

Ss7 *
Calltable::add_ss7(packet_s_stack *packetS, Ss7::sParseData *data) {
	Ss7 *newss7 = new FILE_LINE(0) Ss7(getTimeUS(packetS->header_pt));
	newss7->useHandle = get_pcap_handle(packetS->handle_index);
	newss7->useDlt = packetS->dlt;
	newss7->processData(packetS, data);
	string ss7_id = data->ss7_id();
	lock_ss7_listMAP();
	ss7_listMAP[ss7_id] = newss7;
	unlock_ss7_listMAP();
	return(newss7);
}

Call *
Calltable::add_mgcp(sMgcpRequest *request, time_t time, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport,
		    pcap_t *handle, int dlt, int sensorId) {
	string call_id = request->call_id();
	Call *newcall = new FILE_LINE(0) Call(MGCP, (char*)call_id.c_str(), call_id.length(), NULL, time);

	if(handle) {
		newcall->useHandle = handle;
	}
	if(dlt) {
		newcall->useDlt = dlt;
	}
	if(sensorId > -1) {
		newcall->useSensorId = sensorId;
	}
	newcall->mgcp_callid = request->parameters.call_id;
	newcall->saddr = saddr;
	newcall->sport = sport;
	newcall->daddr = daddr;
	newcall->dport = dport;
	newcall->oneway = 0;
	
	//flags
	set_global_flags(newcall->flags);
	
	lock_calls_listMAP();
	calls_by_stream_callid_listMAP[sStreamIds2(saddr, sport, daddr, dport, request->parameters.call_id.c_str(), true)] = newcall;
	calls_by_stream_id2_listMAP[sStreamId2(saddr, sport, daddr, dport, request->transaction_id, true)] = newcall;
	calls_by_stream_listMAP[sStreamId(saddr, sport, daddr, dport, true)] = newcall;
	newcall->calls_counter_inc();
	newcall->mgcp_transactions.push_back(request->transaction_id);
	unlock_calls_listMAP();
	
	return(newcall);
}


/* iterate all calls in table which are 5 minutes inactive and save them into SQL 
 * ic currtime = 0, save it immediatly
*/

int
Calltable::cleanup_calls( struct timeval *currtime, bool forceClose, const char *file, int line ) {
 
	u_int64_t beginTimeMS = getTimeMS_rdtsc();
	if(sverb.cleanup_calls) {
		cout << "*** cleanup_calls begin";
		if(file) {
			cout << " from: " << file;
			if(line) {
				cout << " : " << line;
			}
			cout << " tid: " << get_unix_tid();
		}
		cout << endl;
	}
 
	extern int opt_blockcleanupcalls;
	if(opt_blockcleanupcalls) {
		return 0;
	}

	if(verbosity && verbosityE > 1) {
		syslog(LOG_NOTICE, "call Calltable::cleanup_calls");
	}
	
	unsigned closeCallsMax = getCountCalls();
	if(!closeCallsMax) {
		return 0;
	}
	closeCallsMax += closeCallsMax / 4;
	Call **closeCalls = new FILE_LINE(0) Call*[closeCallsMax];
	unsigned closeCallsCount = 0;
	
	if(opt_processing_limitations && opt_processing_limitations_active_calls_cache &&
	   opt_processing_limitations_active_calls_cache_type == 1) {
		u_int64_t now_ms = getTimeMS();
		__SYNC_LOCK(active_calls_cache_sync);
		if(active_calls_cache && now_ms > active_calls_cache_fill_at_ms &&
		   now_ms - active_calls_cache_fill_at_ms > processing_limitations.activeCallsCacheTimeout() * 1000) {
			for(unsigned i = 0; i < active_calls_cache_count; i++) {
				__SYNC_DEC(active_calls_cache[i]->useInListCalls);
			}
			delete [] active_calls_cache;
			active_calls_cache = NULL;
			active_calls_cache_size = 0;
			active_calls_cache_count = 0;
		}
		__SYNC_UNLOCK(active_calls_cache_sync);
	}
	
	int rejectedCalls_count = 0;
	for(int passTypeCall = 0; passTypeCall < 2; passTypeCall++) {
		int typeCall = passTypeCall == 0 ? INVITE : MGCP;
		for(int passListMap = -1; passListMap < (typeCall == INVITE && useCallFindX() ? preProcessPacketCallX_count : 0); passListMap++) {
			map<string, Call*> *_calls_listMAP;
			list<Call*>::iterator callIT1;
			map<string, Call*>::iterator callMAPIT1;
			map<sStreamIds2, Call*>::iterator callMAPIT2;
			if(typeCall == INVITE) {
				if(opt_call_id_alternative[0]) {
					lock_calls_listMAP();
					callIT1 = calltable->calls_list.begin();
				} else {
					if(passListMap == -1) {
						lock_calls_listMAP();
						_calls_listMAP = &calls_listMAP;
					} else {
						lock_calls_listMAP_X(passListMap);
						_calls_listMAP = &calls_listMAP_X[passListMap];
					}
					callMAPIT1 = _calls_listMAP->begin();
				}
			} else {
				lock_calls_listMAP();
				callMAPIT2 = calltable->calls_by_stream_callid_listMAP.begin();
			}
			while(typeCall == INVITE ? 
			       (opt_call_id_alternative[0] ?
				 callIT1 != calltable->calls_list.end() :
				 callMAPIT1 != _calls_listMAP->end()) : 
			       callMAPIT2 != calltable->calls_by_stream_callid_listMAP.end()) {
				Call* call;
				if(typeCall == INVITE) {
					call = opt_call_id_alternative[0] ? *callIT1 : callMAPIT1->second;
				} else {
					call = (*callMAPIT2).second;
				}
				if(verbosity > 2) {
					call->dump();
				}
				if(verbosity && verbosityE > 1) {
					syslog(LOG_NOTICE, "Calltable::cleanup - try callid %s", call->call_id.c_str());
				}
				// rtptimeout seconds of inactivity will save this call and remove from call table
				bool closeCall = false;
				if(!currtime || call->force_close) {
					closeCall = true;
					if(!is_read_from_file()) {
						call->force_terminate = true;
					}
				} else if(call->typeIs(SKINNY_NEW) ||
					  call->typeIs(MGCP) ||
					  call->in_preprocess_queue_before_process_packet <= 0 ||
					  (!is_read_from_file() &&
					   (call->in_preprocess_queue_before_process_packet_at[0] && call->in_preprocess_queue_before_process_packet_at[0] < currtime->tv_sec - 300 &&
					    call->in_preprocess_queue_before_process_packet_at[1] && call->in_preprocess_queue_before_process_packet_at[1] < (getTimeMS_rdtsc() / 1000) - 300))) {
					if(call->destroy_call_at != 0 && call->destroy_call_at <= currtime->tv_sec) {
						closeCall = true;
					} else if((call->destroy_call_at_bye != 0 && call->destroy_call_at_bye <= currtime->tv_sec) ||
						  (call->destroy_call_at_bye_confirmed != 0 && call->destroy_call_at_bye_confirmed <= currtime->tv_sec)) {
						closeCall = true;
						call->bye_timeout_exceeded = true;
					} else if(call->first_rtp_time_us &&
						  currtime->tv_sec - call->get_last_packet_time_s() > rtptimeout) {
						closeCall = true;
						call->rtp_timeout_exceeded = true;
					} else if(!call->first_rtp_time_us &&
						  currtime->tv_sec - call->get_first_packet_time_s() > sipwithoutrtptimeout) {
						closeCall = true;
						call->sipwithoutrtp_timeout_exceeded = true;
					} else if(currtime->tv_sec - call->get_first_packet_time_s() > absolute_timeout) {
						closeCall = true;
						call->absolute_timeout_exceeded = true;
					} else if(currtime->tv_sec - call->get_first_packet_time_s() > 300 &&
						  !call->seenRES18X && !call->seenRES2XX && !call->first_rtp_time_us) {
						closeCall = true;
						call->zombie_timeout_exceeded = true;
					}
					if(!closeCall &&
					   (call->oneway == 1 && (currtime->tv_sec - call->get_last_packet_time_s() > opt_onewaytimeout))) {
						closeCall = true;
						call->oneway_timeout_exceeded = true;
					}
				}
				if(closeCall) {
					++call->attemptsClose;
					call->removeFindTables(currtime, true);
					if((currtime || !forceClose) &&
					   ((opt_hash_modify_queue_length_ms && call->hash_queue_counter > 0) ||
					    call->rtppacketsinqueue != 0 ||
					    call->useInListCalls)) {
						closeCall = false;
						++rejectedCalls_count;
					}
				}
				if(closeCall) {
					if(call->listening_worker_run) {
						*call->listening_worker_run = 0;
					}
					if(closeCallsCount < closeCallsMax) {
						closeCalls[closeCallsCount++] = call;
					}
					if(typeCall == INVITE) {
						if(opt_call_id_alternative[0]) {
							calls_list.erase(callIT1++);
							call->removeCallIdMap();
						} else {
							_calls_listMAP->erase(callMAPIT1++);
						}
						call->removeMergeCalls();
					} else {
						calls_by_stream_callid_listMAP.erase(callMAPIT2++);
						mgcpCleanupTransactions(call);
						mgcpCleanupStream(call);
					}
				} else {
					if(typeCall == INVITE) {
						if(opt_call_id_alternative[0]) {
							++callIT1;
						} else {
							++callMAPIT1;
						}
					} else {
						++callMAPIT2;
					}
				}
			}
			if(typeCall == INVITE) {
				if(opt_call_id_alternative[0]) {
					unlock_calls_listMAP();
				} else {
					if(passListMap == -1) {
						unlock_calls_listMAP();
					} else {
						unlock_calls_listMAP_X(passListMap);
					}
				}
			} else {
				unlock_calls_listMAP();
			}
		}
	}
	for(unsigned i = 0; i < closeCallsCount; i++) {
		Call *call = closeCalls[i];
		if(verbosity && verbosityE > 1) {
			syslog(LOG_NOTICE, "Calltable::cleanup - callid %s", call->call_id.c_str());
		}
		// Close RTP dump file ASAP to save file handles
		if((!currtime && is_terminating()) ||
		   (useCallX() && preProcessPacketCallX && preProcessPacketCallX[0]->isActiveOutThread())) {
			call->getPcap()->close();
			call->getPcapSip()->close();
		}
		call->getPcapRtp()->close();

		if(!currtime) {
			/* we are saving calls because of terminating SIGTERM and we dont know 
			 * if the call ends successfully or not. So we dont want to confuse monitoring
			 * applications which reports unterminated calls so mark this call as sighup */
			call->sighup = true;
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Set call->sighup\n");
		}
		// we have to close all raw files as there can be data in buffers 
		call->closeRawFiles();
		
		if(opt_enable_fraud && currtime) {
			fraudEndCall(call, *currtime);
		}
		extern u_int64_t counter_calls_clean;
		++counter_calls_clean;
	}
	/* move call to queue for mysql processing */
	lock_calls_queue();
	for(unsigned i = 0; i < closeCallsCount; i++) {
		Call *call = closeCalls[i];
		if(call->push_call_to_calls_queue) {
			syslog(LOG_WARNING,"try to duplicity push call %s / %i to calls_queue", call->call_id.c_str(), call->getTypeBase());
		} else {
			call->push_call_to_calls_queue = 1;
			calls_queue.push_back(call);
		}
	}
	unlock_calls_queue();
	
	delete [] closeCalls;
	
	if(!currtime && is_terminating()) {
		extern int terminated_call_cleanup;
		terminated_call_cleanup = 1;
		syslog(LOG_NOTICE, "terminated - cleanup calls");
	}
	
	if(sverb.cleanup_calls) {
		cout << "*** cleanup_calls end "
		     << setprecision(3) << (getTimeMS_rdtsc() - beginTimeMS) / 1000. << "s" << endl;
	}
	
	return rejectedCalls_count;
}

int
Calltable::cleanup_registers(struct timeval *currtime) {

	if(verbosity && verbosityE > 1) {
		syslog(LOG_NOTICE, "call Calltable::cleanup_registers");
	}
	Call* reg;

	lock_registers_listMAP();
	for (map<string, Call*>::iterator registerMAPIT = registers_listMAP.begin(); registerMAPIT != registers_listMAP.end();) {
		reg = (*registerMAPIT).second;
		if(verbosity > 2) {
			reg->dump();
		}
		if(verbosity && verbosityE > 1) {
			syslog(LOG_NOTICE, "Calltable::cleanup - try callid %s", reg->call_id.c_str());
		}
		// rtptimeout seconds of inactivity will save this call and remove from call table
		bool closeReg = false;
		if(!currtime || reg->force_close) {
			closeReg = true;
			if(!is_read_from_file()) {
				reg->force_terminate = true;
			}
		} else {
			if(reg->destroy_call_at != 0 && reg->destroy_call_at <= currtime->tv_sec) {
				closeReg = true;
			} else if(currtime->tv_sec - reg->get_first_packet_time_s() > absolute_timeout) {
				closeReg = true;
				reg->absolute_timeout_exceeded = true;
			} else if(currtime->tv_sec - reg->get_first_packet_time_s() > 300 &&
				  !reg->seenRES18X && !reg->seenRES2XX) {
				closeReg = true;
				reg->zombie_timeout_exceeded = true;
			}
			if(!closeReg &&
			   (reg->oneway == 1 && (currtime->tv_sec - reg->get_last_packet_time_s() > opt_onewaytimeout))) {
				closeReg = true;
				reg->oneway_timeout_exceeded = true;
			}
		}
		if(closeReg) {
			if(verbosity && verbosityE > 1) {
				syslog(LOG_NOTICE, "Calltable::cleanup - callid %s", reg->call_id.c_str());
			}
			// Close RTP dump file ASAP to save file handles
			if(!currtime && is_terminating()) {
				reg->getPcap()->close();
				reg->getPcapSip()->close();
			}

			if(!currtime) {
				/* we are saving calls because of terminating SIGTERM and we dont know 
				 * if the call ends successfully or not. So we dont want to confuse monitoring
				 * applications which reports unterminated calls so mark this call as sighup */
				reg->sighup = true;
				if(verbosity > 2)
					syslog(LOG_NOTICE, "Set call->sighup\n");
			}
			/* move call to queue for mysql processing */
			if(reg->push_register_to_registers_queue) {
				syslog(LOG_WARNING,"try to duplicity push call %s to registers_queue", reg->call_id.c_str());
			} else {
				reg->push_register_to_registers_queue = 1;
				if(opt_sip_register == 1) {
					extern Registers registers;
					if(reg->msgcount <= 1 || 
					   reg->lastSIPresponseNum == 401 || reg->lastSIPresponseNum == 403 || reg->lastSIPresponseNum == 404) {
						reg->regstate = 2;
					}
					if(reg->regstate != 2 ||
					   !opt_register_timeout_disable_save_failed) {
						registers.add(reg);
					}
					reg->getPcap()->close();
					reg->getPcapSip()->close();
					lock_registers_deletequeue();
					registers_deletequeue.push_back(reg);
					unlock_registers_deletequeue();
				} else {
					lock_registers_queue();
					registers_queue.push_back(reg);
					unlock_registers_queue();
				}
			}
			registers_listMAP.erase(registerMAPIT++);
			if(opt_enable_fraud && currtime) {
				fraudEndCall(reg, *currtime);
			}
			extern u_int64_t counter_registers_clean;
			++counter_registers_clean;
		} else {
			++registerMAPIT;
		}
	}
	unlock_registers_listMAP();
	
	if(!currtime && is_terminating()) {
		extern int terminated_call_cleanup;
		terminated_call_cleanup = 1;
		syslog(LOG_NOTICE, "terminated - call cleanup");
	}
	
	return 0;
}

int Calltable::cleanup_ss7( struct timeval *currtime ) {
	lock_process_ss7_listmap();
	lock_ss7_listMAP();
	map<string, Ss7*>::iterator iter;
	for(iter = ss7_listMAP.begin(); iter != ss7_listMAP.end(); ) {
		if((currtime && iter->second->destroy_at_s &&
		    ((iter->second->last_message_type == Ss7::rel || iter->second->last_message_type == Ss7::rlc) && 
		     iter->second->destroy_at_s <= currtime->tv_sec)) || 
		   !currtime ||
		   (currtime->tv_sec - TIME_US_TO_S(iter->second->last_time_us)) > (opt_ss7timeout ? opt_ss7timeout : absolute_timeout)) {
			iter->second->pushToQueue();
			ss7_listMAP.erase(iter++);
			continue;
		}
		iter++;
	}
	unlock_ss7_listMAP();
	unlock_process_ss7_listmap();
	lock_process_ss7_queue();
	for(unsigned i = 0; i < ss7_queue.size(); i++) {
		if(ss7_queue[i]->pcap.isOpen()) {
			ss7_queue[i]->pcap.close();
		}
	}
	Ss7 *ss7;
	while(ss7_queue.size() &&
	      (ss7 = ss7_queue.front()) &&
	      ss7->pcap.isClose() &&
	      ss7->isEmptyChunkBuffersCount()) {
		ss7->saveToDb();
		delete ss7;
		ss7_queue.pop_front();
	}
	unlock_process_ss7_queue();
	return(0);
}

void Calltable::addSystemCommand(const char *command) {
	if(asyncSystemCommand) {
		asyncSystemCommand->addSystemCommand(command);
	}
}

size_t Calltable::getCountCalls() {
	size_t count = 0;
	for(int passTypeCall = 0; passTypeCall < 2; passTypeCall++) {
		int typeCall = passTypeCall == 0 ? INVITE : MGCP;
		for(int passListMap = -1; passListMap < (typeCall == INVITE && useCallFindX() ? preProcessPacketCallX_count : 0); passListMap++) {
			if(typeCall == INVITE) {
				if(opt_call_id_alternative[0]) {
					count += calls_list.size();
				} else {
					map<string, Call*> *_calls_listMAP;
					if(passListMap == -1) {
						_calls_listMAP = &calls_listMAP;
					} else {
						_calls_listMAP = &calls_listMAP_X[passListMap];
					}
					count += _calls_listMAP->size();
				}
			} else {
				count += calls_by_stream_callid_listMAP.size();
			}
		}
	}
	return(count);
}

bool Calltable::enableCallX() {
	return(opt_t2_boost && opt_t2_boost_call_threads > 0);
}

bool Calltable::useCallX() {
	return(enableCallX() &&
	       (preProcessPacketCallX_state == PreProcessPacket::callx_process ||
		preProcessPacketCallX_state == PreProcessPacket::callx_find));
}

bool Calltable::enableCallFindX() {
	return(opt_t2_boost && opt_t2_boost_call_threads > 0 && opt_t2_boost_call_find_threads &&
	       !opt_call_id_alternative[0]);
}

bool Calltable::useCallFindX() {
	return(enableCallFindX() &&
	       preProcessPacketCallX_state == PreProcessPacket::callx_find);
}


void Call::saveregister(struct timeval *currtime) {
	((Calltable*)calltable)->lock_registers_listMAP();
        map<string, Call*>::iterator registerMAPIT = ((Calltable*)calltable)->registers_listMAP.find(call_id);
	if(registerMAPIT == ((Calltable*)calltable)->registers_listMAP.end()) {
		syslog(LOG_ERR,"Fatal error REGISTER call_id[%s] not found in registerMAPIT", call_id.c_str());
		((Calltable*)calltable)->unlock_registers_listMAP();
		return;
	} else {
		((Calltable*)calltable)->registers_listMAP.erase(registerMAPIT);
	}
	((Calltable*)calltable)->unlock_registers_listMAP();
	extern u_int64_t counter_registers_clean;
	++counter_registers_clean;
	
	removeFindTables(currtime);
	this->pcap.close();
	this->pcapSip.close();
	/* move call to queue for mysql processing */
	if(push_register_to_registers_queue) {
		syslog(LOG_WARNING,"try to duplicity push call %s / %i to registers_queue", call_id.c_str(), getTypeBase());
	} else {
		push_register_to_registers_queue = 1;
		if(opt_sip_register == 1) {
			extern Registers registers;
			registers.add(this);
			((Calltable*)calltable)->lock_registers_deletequeue();
			((Calltable*)calltable)->registers_deletequeue.push_back(this);
			((Calltable*)calltable)->unlock_registers_deletequeue();
		} else {
			((Calltable*)calltable)->lock_registers_queue();
			((Calltable*)calltable)->registers_queue.push_back(this);
			((Calltable*)calltable)->unlock_registers_queue();
		}
	}
}

void
Call::handle_dtmf(char dtmf, double dtmf_time, vmIP saddr, vmIP daddr, s_dtmf::e_type dtmf_type) {

	if(enable_save_dtmf_db) {
		s_dtmf q;
		q.dtmf = dtmf;
		q.ts = dtmf_time - TIME_US_TO_SF(first_packet_time_us);
		q.type = dtmf_type;
		q.saddr = saddr;
		q.daddr = daddr;

		//printf("push [%c] [%f] [%f] [%f]\n", q.dtmf, q.ts, dtmf_time, ts2double(first_packet_time, first_packet_usec));
		dtmf_history.push(q);
	}

	if(opt_norecord_dtmf) {
		if(dtmfflag == 0) { 
			if(dtmf == '*') {
				// received ftmf '*', set flag so if next dtmf will be '0' stop recording
				dtmfflag = 1;
			}
		} else {
			if(dtmf == '0') {
				// we have complete *0 sequence
				stoprecording();
				dtmfflag = 0;
			} else {
				// reset flag because we did not received '0' after '*'
				dtmfflag = 0;
			}       
		}       
	}
	if(opt_silencedtmfseq[0] != '\0') {
		unsigned int dtmfflag2_index = dtmf_type == s_dtmf::sip_info ? 0 : 1;
		const char *dtmf_type_string = "";
		if(sverb.dtmf) {
			dtmf_type_string = dtmf_type == s_dtmf::sip_info ? "sip_info" :
					   dtmf_type == s_dtmf::inband ? "inband" :
					   dtmf_type == s_dtmf::rfc2833 ? "rfc2833" : "";
		}

		if (dtmfflag2[dtmfflag2_index] == 0) {
			if (sverb.dtmf)
				syslog(LOG_NOTICE, "[%s] initial DTMF detected %s ", fbasename, dtmf_type_string);
		} else {
			if (dtmf_time - this->lastdtmf_time > opt_pauserecordingdtmf_timeout) {	//timeout reset flag
				dtmfflag2[dtmfflag2_index] = 0;
				if (sverb.dtmf)
					syslog(LOG_NOTICE, "[%s] DTMF detected %s / Diff from last DTMF: %lf s / possible timeout %i s. Too late, resetting dtmf flag",
					    fbasename, dtmf_type_string, dtmf_time - this->lastdtmf_time, opt_pauserecordingdtmf_timeout);
			} else {
				if (sverb.dtmf)
					syslog(LOG_NOTICE, "[%s] DTMF detected %s / Diff from last DTMF: %lf s.", fbasename, dtmf_type_string, dtmf_time - this->lastdtmf_time);
			}
		}
		this->lastdtmf_time = dtmf_time;

		if(dtmfflag2[dtmfflag2_index] == 0) {
			if(dtmf == opt_silencedtmfseq[dtmfflag2[dtmfflag2_index]]) {
				// received ftmf '*', set flag so if next dtmf will be '0' stop recording
				dtmfflag2[dtmfflag2_index]++;
			}
		} else {
			if(dtmf == opt_silencedtmfseq[dtmfflag2[dtmfflag2_index]]) {
				// we have complete *0 sequence
				if(dtmfflag2[dtmfflag2_index] + 1 == strlen(opt_silencedtmfseq)) {
					if(silencerecording == 0) {
						if(sverb.dtmf)
							syslog(LOG_NOTICE, "[%s] pause DTMF sequence detected - pausing recording - %s / %lf s", fbasename, 
							       dtmf_type_string, dtmf_time - TIME_US_TO_SF(this->first_packet_time_us));
						silencerecording = 1;
					} else {
						if(sverb.dtmf)
							syslog(LOG_NOTICE, "[%s] pause DTMF sequence detected - unpausing recording - %s / %lf s", fbasename, 
							       dtmf_type_string, dtmf_time - TIME_US_TO_SF(this->first_packet_time_us));
						silencerecording = 0;
					}       
					dtmfflag2[dtmfflag2_index] = 0;
				} else {
					dtmfflag2[dtmfflag2_index]++;
				}       
			} else {
				// reset flag 
				dtmfflag2[dtmfflag2_index] = 0;
			}       
		}       
	}
}

void
Call::handle_dscp(struct iphdr2 *header_ip, bool iscaller) {
	if(iscaller) {
		this->called_sipdscp = header_ip->get_tos() >> 2;
		if(sverb.dscp) {
			cout << "called_sipdscp " << (int)(header_ip->get_tos()>>2) << endl;
		}
	} else {
		this->caller_sipdscp = header_ip->get_tos() >> 2;
		if(sverb.dscp) {
			cout << "caller_sipdscp " << (int)(header_ip->get_tos()>>2) << endl;
		}
	}
}

bool 
Call::check_is_caller_called(const char *call_id, int sip_method, int cseq_method,
			     vmIP saddr, vmIP daddr, 
			     vmIP saddr_first, vmIP daddr_first, u_int8_t first_protocol,
			     vmPort sport, vmPort dport,
			     int *iscaller, int *iscalled, bool enableSetSipcallerdip) {
	*iscaller = 0;
	bool _iscalled = 0;
	string debug_str_set;
	string debug_str_cmp;
	if(this->typeIsOnly(MESSAGE) || sip_method == MESSAGE || cseq_method == MESSAGE) {
		if(sip_method == MESSAGE) {
			_iscalled = 1;
			debug_str_cmp = string(" / == MSG");
		} else {
			*iscaller = 1;
			debug_str_cmp = string(" / != MSG");
		}
	} else if(this->typeIsOnly(REGISTER)) {
		if(sip_method == REGISTER) {
			_iscalled = 1;
			debug_str_cmp = string(" / == REGISTER");
		} else {
			*iscaller = 1;
			debug_str_cmp = string(" / != REGISTER");
		}
	} else {
		vmIP *sipcallerip;
		vmIP *sipcalledip;
		vmPort *sipcallerport;
		vmPort *sipcalledport;
		if(isSetCallidMergeHeader()) {
			if(call_id) {
				sipcallerip = this->map_sipcallerdip[call_id].sipcallerip;
				sipcalledip = this->map_sipcallerdip[call_id].sipcalledip;
				sipcallerport = this->map_sipcallerdip[call_id].sipcallerport;
				sipcalledport = this->map_sipcallerdip[call_id].sipcalledport;
			} else {
				sipcallerip = this->map_sipcallerdip.begin()->second.sipcallerip;
				sipcalledip = this->map_sipcallerdip.begin()->second.sipcalledip;
				sipcallerport = this->map_sipcallerdip.begin()->second.sipcallerport;
				sipcalledport = this->map_sipcallerdip.begin()->second.sipcalledport;
			}
			if(!sipcallerip[0].isSet() && !sipcalledip[0].isSet()) {
				sipcallerip[0] = saddr;
				sipcalledip[0] = daddr;
				sipcallerip_encaps = saddr_first;
				sipcalledip_encaps = daddr_first;
				sipcallerip_encaps_prot = first_protocol;
				sipcalledip_encaps_prot = first_protocol;
				sipcallerport[0] = sport;
				sipcalledport[0] = dport;
			}
		} else {
			sipcallerip = this->sipcallerip;
			sipcalledip = this->sipcalledip;
			sipcallerport = this->sipcallerport;
			sipcalledport = this->sipcalledport;
		}
		int i;
		for(i = 0; i < MAX_SIPCALLERDIP; i++) {
			if(enableSetSipcallerdip && i > 0 && !sipcallerip[i].isSet() && saddr.isSet() && daddr.isSet()) {
				if(sip_method == INVITE) {
					sipcallerip[i] = saddr;
					sipcalledip[i] = daddr;
					sipcallerport[i] = sport;
					sipcalledport[i] = dport;
					if(sverb.check_is_caller_called) {
						debug_str_set += string(" / set sipcaller/dip[") + intToString(i) + "]: " + 
								 saddr.getString() + ':' + sport.getString() + " -> " +
								 daddr.getString() + ':' + dport.getString();
					}
				} else if(IS_SIP_RES18X(sip_method) || sip_method == RES2XX_INVITE)  {
					sipcallerip[i] = daddr;
					sipcalledip[i] = saddr;
					sipcallerport[i] = dport;
					sipcalledport[i] = sport;
					if(sverb.check_is_caller_called) {
						debug_str_set += string(" / set sipcaller/dip[") + intToString(i) + "]: " + 
								 daddr.getString() + ':' + dport.getString() + " -> " + 
								 saddr.getString() + ':' + sport.getString();
					}
				}
			}
			if(sipcallerip[i].isSet()) {
				if((use_both_side_for_check_direction() ?
				     sipcallerip[i] == saddr && sipcalledip[i] == daddr : 
				     sipcallerip[i] == saddr) &&
				   (sipcallerip[i] != sipcalledip[i] ||
				    !use_port_for_check_direction(saddr) || 
				    (use_both_side_for_check_direction() ?
				      sipcallerport[i] == sport && sipcalledport[i] == dport :
				      sipcallerport[i] == sport))) {
					// SDP message is coming from the first IP address seen in first INVITE thus incoming stream to ip/port in this 
					// SDP will be stream from called
					_iscalled = 1;
					if(sverb.check_is_caller_called) {
						debug_str_cmp += string(" / cmp sipcallerip[") + intToString(i) + "] " + 
								 (use_both_side_for_check_direction() ?
								   "(sipcaller/dip) " + sipcallerip[i].getString() + ':' + sipcallerport[i].getString() + " -> " +
								   sipcalledip[i].getString() + ':' + sipcalledport[i].getString() +
								   " == " + 
								   "(s/daddr) " + saddr.getString() + ':' + sport.getString() + " -> " + 
								   daddr.getString() + ':' + dport.getString()
								   :
								   "(sipcallerip) " + sipcallerip[i].getString() + ':' + sipcallerport[i].getString() + 
								   " == " + 
								   "(saddr) " + saddr.getString() + ':' + sport.getString());
					}
					break;
				} else {
					// The IP address is different, check if the request matches one of the address from the first invite
					if((use_both_side_for_check_direction() ?
					     sipcallerip[i] == daddr && sipcalledip[i] == saddr :
					     sipcallerip[i] == daddr) &&
					   (sipcallerip[i] != sipcalledip[i] ||
					    !use_port_for_check_direction(daddr) || 
					    (use_both_side_for_check_direction() ?
					      sipcallerport[i] == dport && sipcalledport[i] == sport :
					      sipcallerport[i] == dport))) {
						// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
						*iscaller = 1;
						if(sverb.check_is_caller_called) {
							debug_str_cmp += string(" / cmp sipcallerip[") + intToString(i) + "] " + 
									 (use_both_side_for_check_direction() ?
									   "(sipcaller/dip) " + sipcallerip[i].getString() + ':' + sipcallerport[i].getString() + " -> " +
									   sipcalledip[i].getString() + ':' + sipcalledport[i].getString() +
									   " == " + 
									   "(d/saddr) " + daddr.getString() + ':' + dport.getString() + " -> " + 
									   saddr.getString() + ':' + sport.getString()
									   :
									   "(sipcallerip) " + sipcallerip[i].getString() + ':' + sipcallerport[i].getString() + 
									   " == " + 
									   "(daddr) " + daddr.getString() + ':' + dport.getString());
						}
						break;
					}
				}
			} else {
				break;
			}
		}
		if(i == MAX_SIPCALLERDIP && !*iscaller && !_iscalled) {
			*iscaller = 1;
			if(sverb.check_is_caller_called) {
				debug_str_cmp += " / last set";
			}
		}
	}
	if(sverb.check_is_caller_called) {
		cout << "check_is_caller_called: " 
		     << "call_id: " << call_id  << " "
		     << "sip_method: " << sip_method << " "
		     << saddr.getString() << " -> " << daddr.getString()
		     << " = " << (*iscaller ? "CALLER" : (_iscalled ? "CALLED" : "UNDEFINED"))
		     << debug_str_set
		     << debug_str_cmp
		     << endl;
		
	}
	if(*iscaller || _iscalled) {
		if(iscalled) {
			*iscalled = _iscalled;
		}
		return(true);
	} else {
		*iscaller = -1;
		if(iscalled) {
			*iscalled = -1;
		}
		return(false);
	}
}

bool 
Call::is_sipcaller(vmIP saddr, vmPort sport, vmIP daddr, vmPort dport) {
	vmIP *sipcallerip;
	vmIP *sipcalledip;
	vmPort *sipcallerport;
	vmPort *sipcalledport;
	if(isSetCallidMergeHeader()) {
		sipcallerip = this->map_sipcallerdip.begin()->second.sipcallerip;
		sipcalledip = this->map_sipcallerdip.begin()->second.sipcalledip;
		sipcallerport = this->map_sipcallerdip.begin()->second.sipcallerport;
		sipcalledport = this->map_sipcallerdip.begin()->second.sipcalledport;
	} else {
		sipcallerip = this->sipcallerip;
		sipcalledip = this->sipcalledip;
		sipcallerport = this->sipcallerport;
		sipcalledport = this->sipcalledport;
	}
	for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
		if((use_both_side_for_check_direction() && daddr.isSet() ?
		     saddr == sipcallerip[i] && daddr == sipcalledip[i] :
		     saddr == sipcallerip[i]) &&
		   (sipcallerip[i] != sipcalledip[i] ||
		    !use_port_for_check_direction(saddr) || 
		    (use_both_side_for_check_direction() && dport.isSet() ?
		      sport == sipcallerport[i] && dport == sipcalledport[i] :
		      sport == sipcallerport[i]))) {
			return(true);
		}
	}
	return(false);
}

bool 
Call::is_sipcalled(vmIP daddr, vmPort dport, vmIP saddr, vmPort sport) {
	vmIP *sipcallerip;
	vmIP *sipcalledip;
	vmPort *sipcallerport;
	vmPort *sipcalledport;
	if(isSetCallidMergeHeader()) {
		sipcallerip = this->map_sipcallerdip.begin()->second.sipcallerip;
		sipcalledip = this->map_sipcallerdip.begin()->second.sipcalledip;
		sipcallerport = this->map_sipcallerdip.begin()->second.sipcallerport;
		sipcalledport = this->map_sipcallerdip.begin()->second.sipcalledport;
	} else {
		sipcallerip = this->sipcallerip;
		sipcalledip = this->sipcalledip;
		sipcallerport = this->sipcallerport;
		sipcalledport = this->sipcalledport;
	}
	for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
		if((use_both_side_for_check_direction() && saddr.isSet() ?
		     daddr == sipcalledip[i] && saddr == sipcallerip[i] :
		     daddr == sipcalledip[i]) &&
		   (sipcallerip[i] != sipcalledip[i] ||
		    !use_port_for_check_direction(daddr) || 
		    (use_both_side_for_check_direction() && sport.isSet() ?
		      dport == sipcalledport[i] && sport == sipcallerport[i] :
		      dport == sipcalledport[i]))) {
			return(true);
		}
	}
	return(false);
}


CustomHeaders::CustomHeaders(eType type, SqlDb *sqlDb) {
	this->type = type;
	switch(type) {
	case cdr:
		this->configTable = "cdr_custom_headers"; 
		this->mainTable = "cdr";
		this->nextTablePrefix = "cdr_next_";
		this->fixedTable = "cdr_next";
		this->relIdColumn = "cdr_ID";
		this->relTimeColumn = "calldate";
		break;
	case message:
		this->configTable = "message_custom_headers"; 
		this->mainTable = "message";
		this->nextTablePrefix = "message_next_";
		this->fixedTable = "message";
		this->relIdColumn = "message_ID";
		this->relTimeColumn = "calldate";
		break;
	case sip_msg:
		this->configTable = "sip_msg_custom_headers";
		this->mainTable = "sip_msg";
		this->nextTablePrefix = "sip_msg_next_";
		this->fixedTable = "";
		this->relIdColumn = "sip_msg_ID";
		this->relTimeColumn = "time";
		break;
	}
	this->loadTime = 0;
	this->lastTimeSaveUseInfo = 0;
	this->_sync_custom_headers = 0;
	this->load(sqlDb);
}

void CustomHeaders::load(SqlDb *sqlDb, bool enableCreatePartitions, bool lock) {
	if(sverb.disable_custom_headers) {
		return;
	}
	if(lock) lock_custom_headers();
	custom_headers.clear();
	allNextTables.clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool existsConfigTable = false;
	if(sqlDb->existsTable(this->configTable)) {
		existsConfigTable = true;
		if(sqlDb->existsColumn(this->configTable, "state")) {
			sqlDb->query("SELECT * FROM " + this->configTable + " \
				      where state is null or state='active'");
			list<sCustomHeaderDataPlus> customHeaderData;
			SqlDb_rows rows;
			sqlDb->fetchRows(&rows);
			SqlDb_row row;
			while((row = rows.fetchRow())) {
				sCustomHeaderDataPlus ch_data;
				string specialType = row["special_type"];
				ch_data.specialType = specialType == "max_length_sip_data" ? max_length_sip_data :
						      specialType == "max_length_sip_packet" ? max_length_sip_packet :
						      specialType == "gsm_dcs" ? gsm_dcs :
						      specialType == "gsm_voicemail" ? gsm_voicemail : 
						      specialType == "max_retransmission_invite" ? max_retransmission_invite : st_na;
				ch_data.db_id = atoi(row["id"].c_str());
				ch_data.type = row.getIndexField("type") < 0 || row.isNull("type") ? "fixed" : row["type"];
				ch_data.header = row["header_field"];
				ch_data.doNotAddColon = atoi(row["do_not_add_colon"].c_str());
				ch_data.leftBorder = row["left_border"];
				ch_data.rightBorder = row["right_border"];
				ch_data.regularExpression = row["regular_expression"];
				ch_data.screenPopupField = atoi(row["screen_popup_field"].c_str());
				if(type == sip_msg) {
					ch_data.reqRespDirection = row["direction"] == "request" ? dir_request :
								   row["direction"] == "response" ? dir_response :
								   row["direction"] == "both" ? dir_both : dir_na;
				} else {
					ch_data.reqRespDirection = dir_na;
				}
				int tmpOcc = atoi(row["select_occurrence"].c_str());
				if (tmpOcc) {
					if (tmpOcc == 1) {
						ch_data.selectOccurrence = false;
					} else {
						ch_data.selectOccurrence = true;
					}
				} else {
					ch_data.selectOccurrence = (bool) opt_custom_headers_last_value;
				}
				ch_data.cseqMethod = split2int(row["cseq_method"], ',');
				std::vector<int> tmpvect = split2int(row["sip_response_code"], split(",|;| |", "|"), true);
				if (!tmpvect.empty()) {
					ch_data.sipResponseCodeInfo = getResponseCodeSizes(tmpvect);
				}
				ch_data.dynamic_table = atoi(row["dynamic_table"].c_str());
				ch_data.dynamic_column = atoi(row["dynamic_column"].c_str());
				customHeaderData.push_back(ch_data);
			}
			for(list<sCustomHeaderDataPlus>::iterator iter = customHeaderData.begin(); iter != customHeaderData.end(); iter++) {
				if(iter->type == "fixed") {
					if(!this->fixedTable.empty()) {
						if(sqlDb->existsColumn(this->fixedTable, "custom_header__" + iter->header)) {
							custom_headers[0][custom_headers[0].size()] = *iter;
						}
					}
				} else {
					custom_headers[iter->dynamic_table][iter->dynamic_column] = *iter;
				}
			}
			map<int, map<int, sCustomHeaderData> >::iterator iter;
			for(iter = custom_headers.begin(); iter != custom_headers.end();) {
				if(iter->first) {
					char nextTable[100];
					snprintf(nextTable, sizeof(nextTable), "%s%i", this->nextTablePrefix.c_str(), iter->first);
					allNextTables.push_back(nextTable);
				}
				iter++;
			}
		}
	}
	extern vector<dstring> opt_custom_headers_cdr;
	extern vector<dstring> opt_custom_headers_message;
	extern vector<dstring> opt_custom_headers_sip_msg;
	vector<dstring> *_customHeaders = type == cdr ? &opt_custom_headers_cdr : 
					  type == message ? &opt_custom_headers_message :
					  type == sip_msg ? &opt_custom_headers_sip_msg : NULL;
	for(vector<dstring>::iterator iter = _customHeaders->begin(); iter != _customHeaders->end(); iter++) {
		SqlDb_row row;
		if(existsConfigTable) {
			sqlDb->query("SELECT * FROM " + this->configTable + " \
				      where header_field = '" + (*iter)[0] + "'");
			row = sqlDb->fetchRow();
		}
		if(!existsConfigTable ||
		   !row || row.getIndexField("state") < 0 || row["state"] != "delete") {
			sCustomHeaderData ch_data;
			ch_data.header = (*iter)[0];
			ch_data.db_id = 0;
			bool exists =  false;
			for(unsigned i = 0; i < custom_headers[0].size(); i++) {
				if(!strcasecmp(custom_headers[0][i].header.c_str(), ch_data.header.c_str())) {
					exists = true;
					break;
				}
			}
			if(!exists) {
				custom_headers[0][custom_headers[0].size()] = ch_data;
			}
		}
	}
	if(enableCreatePartitions) {
		this->createTablesIfNotExists(sqlDb, true);
		extern bool opt_disable_partition_operations;
		if(!opt_disable_partition_operations && !is_client()) {
			this->createMysqlPartitions(sqlDb);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	loadTime = getTimeMS();
	if(lock) unlock_custom_headers();
}

void CustomHeaders::clear(bool lock) {
	if(lock) lock_custom_headers();
	custom_headers.clear();
	allNextTables.clear();
	if(lock) unlock_custom_headers();
}

void CustomHeaders::refresh(SqlDb *sqlDb, bool enableCreatePartitions) {
	lock_custom_headers();
	clear(false);
	load(sqlDb, enableCreatePartitions, false);
	checkTablesColumns(sqlDb);
	unlock_custom_headers();
}

void CustomHeaders::addToStdParse(ParsePacket *parsePacket) {
	lock_custom_headers();
	map<int, map<int, sCustomHeaderData> >::iterator iter;
	for(iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		map<int, sCustomHeaderData>::iterator iter2;
		for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			string findHeader = iter2->second.header;
			if(findHeader.length()) {
				if(!iter2->second.doNotAddColon &&
				   findHeader[findHeader.length() - 1] != ':' &&
				   findHeader[findHeader.length() - 1] != '=' &&
				   strcasecmp(findHeader.c_str(), "invite")) {
					findHeader.append(":");
				}
				parsePacket->addNode(findHeader.c_str(), ParsePacket::typeNode_custom);
			}
		}
	}
	unlock_custom_headers();
}

extern char * gettag_ext(const void *ptr, unsigned long len, ParsePacket::ppContentsX *parseContents, 
			 const char *tag, unsigned long *gettaglen, unsigned long *limitLen = NULL);
void CustomHeaders::parse(Call *call, int type, tCH_Content *ch_content, packet_s_process *packetS, eReqRespDirection reqRespDirection) {
	char *data = packetS->data_() + packetS->sipDataOffset;
	int datalen = packetS->sipDataLen;
	ParsePacket::ppContentsX *parseContents = &packetS->parseContents;

	lock_custom_headers();
	if(call) {
		call->custom_headers_content_lock();
	}
	unsigned long gettagLimitLen = 0;
	map<int, map<int, sCustomHeaderData> >::iterator iter;
	for(iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		map<int, sCustomHeaderData>::iterator iter2;
		for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(iter2->second.specialType) {
				string content;
				switch(iter2->second.specialType) {
				case max_length_sip_data:
					if(call && call->max_length_sip_data) {
						content = intToString(call->max_length_sip_data);
					}
					break;
				case max_length_sip_packet:
					if(call && call->max_length_sip_packet) {
						content = intToString(call->max_length_sip_packet);
					}
					break;
				case gsm_dcs:
					if(call && call->dcs) {
						content = intToString(call->dcs);
					}
					break;
				case gsm_voicemail:
					if(call) {
						switch(call->voicemail) {
						case Call::voicemail_active:
							content = "active";
							break;
						case Call::voicemail_inactive:
							content = "inactive";
							break;
						case Call::voicemail_na:
							break;
						}
					}
					break;
				case max_retransmission_invite:
					if(call) {
						unsigned max_retrans = call->getMaxRetransmissionInvite();
						if(max_retrans > 0) {
							content = intToString(max_retrans);
						}
					}
					break;
				case st_na:
					break;
				}
				dstring ds_content(iter2->second.header, content);
				this->setCustomHeaderContent(call, type, ch_content, iter->first, iter2->first, &ds_content, true);
			} else {
				if(this->type == sip_msg &&
				   reqRespDirection != dir_na &&
				   !(reqRespDirection & iter2->second.reqRespDirection)) {
					continue;
				}
				if (!iter2->second.sipResponseCodeInfo.empty() &&
				    !matchResponseCodes(iter2->second.sipResponseCodeInfo, packetS->lastSIPresponseNum)) {
					continue;
				}
				if (!iter2->second.cseqMethod.empty() &&
				    std::find(iter2->second.cseqMethod.begin(), iter2->second.cseqMethod.end(), packetS->cseq.method) == iter2->second.cseqMethod.end()) {
					continue;
				}
				string findHeader = iter2->second.header;
				if(findHeader.length()) {
					if(findHeader[findHeader.length() - 1] != ':' &&
					   findHeader[findHeader.length() - 1] != '=') {
						findHeader.append(":");
					}
					unsigned long l;
					char *s = gettag_ext(data, datalen, parseContents,
							     findHeader.c_str(), &l, &gettagLimitLen);
					if(l) {
						char customHeaderContent[256];
						memcpy(customHeaderContent, s, min(l, 255lu));
						customHeaderContent[min(l, 255lu)] = '\0';
						char *customHeaderBegin = customHeaderContent;
						if(!iter2->second.leftBorder.empty()) {
							customHeaderBegin = strcasestr(customHeaderBegin, iter2->second.leftBorder.c_str());
							if(customHeaderBegin) {
								customHeaderBegin += iter2->second.leftBorder.length();
							} else {
								continue;
							}
						}
						if(!iter2->second.rightBorder.empty()) {
							char *customHeaderEnd = strcasestr(customHeaderBegin, iter2->second.rightBorder.c_str());
							if(customHeaderEnd) {
								*customHeaderEnd = 0;
							} else {
								continue;
							}
						}
						if(!iter2->second.regularExpression.empty()) {
							string customHeader = reg_replace(customHeaderBegin, iter2->second.regularExpression.c_str(), "$1", __FILE__, __LINE__);
							if(customHeader.empty()) {
								continue;
							} else {
								dstring content(iter2->second.header, customHeader);
								this->setCustomHeaderContent(call, type, ch_content, iter->first, iter2->first, &content, iter2->second.selectOccurrence);
							}
						} else {
							dstring content(iter2->second.header, customHeaderBegin);
							this->setCustomHeaderContent(call, type, ch_content, iter->first, iter2->first, &content, iter2->second.selectOccurrence);
						}
					}
				}
			}
		}
	}
	if(call) {
		call->custom_headers_content_unlock();
	}
	unlock_custom_headers();
}

void CustomHeaders::setCustomHeaderContent(Call *call, int type, tCH_Content *ch_content, int pos1, int pos2, dstring *content, bool useLastValue) {
	if(!ch_content) {
		if(call) {
			ch_content = getCustomHeadersCallContent(call, type);
		}
		if(!ch_content) {
			return;
		}
	}
	bool exists = false;
	if(!useLastValue) {
		tCH_Content::iterator iter = ch_content->find(pos1);
		if(iter != ch_content->end()) {
			map<int, dstring>::iterator iter2 = iter->second.find(pos2);
			if(iter2 != iter->second.end()) {
				exists = true;
			}
		}
	}
	if(!exists || useLastValue) {
		(*ch_content)[pos1][pos2] = *content;
	}
}

void CustomHeaders::prepareSaveRows(Call *call, int type, tCH_Content *ch_content, u_int64_t time_us, SqlDb_row *cdr_next, SqlDb_row cdr_next_ch[], char *cdr_next_ch_name[]) {
	if(!ch_content) {
		if(call) {
			ch_content = getCustomHeadersCallContent(call, type);
		}
		if(!ch_content) {
			return;
		}
	}
	if(call) {
		call->custom_headers_content_lock();
	}
	tCH_Content::iterator iter;
	for(iter = ch_content->begin(); iter != ch_content->end(); iter++) {
		if(iter->first > CDR_NEXT_MAX) {
			break;
		}
		map<int, dstring>::iterator iter2;
		for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(iter2->second[1].empty()) {
				continue;
			}
			if(!iter->first) {
				cdr_next->add(sqlEscapeString(iter2->second[1]), "custom_header__" + iter2->second[0]);
			} else {
				if(!cdr_next_ch_name[iter->first - 1][0]) {
					sprintf(cdr_next_ch_name[iter->first - 1], "%s%i", this->nextTablePrefix.c_str(), iter->first);
					if(opt_cdr_partition) {
						bool use_ms = false;
						map<int, bool>::iterator calldate_ms_iter = calldate_ms.find(iter->first - 1);
						if(calldate_ms_iter != calldate_ms.end() && calldate_ms_iter->second) {
							use_ms = true;
						}
						cdr_next_ch[iter->first - 1].add_calldate(call ? call->calltime_us() : time_us, this->relTimeColumn, use_ms);
					}
				}
				char fieldName[20];
				snprintf(fieldName, sizeof(fieldName), "custom_header_%i", iter2->first);
				cdr_next_ch[iter->first - 1].add(sqlEscapeString(iter2->second[1]), fieldName);
			}
		}
	}
	if(call) {
		call->custom_headers_content_unlock();
	}
}

string CustomHeaders::getScreenPopupFieldsString(Call *call, int type) {
	tCH_Content *ch_content = getCustomHeadersCallContent(call, type);
	string fields;
	tCH_Content::iterator iter;
	for(iter = ch_content->begin(); iter != ch_content->end(); iter++) {
		map<int, dstring>::iterator iter2;
		for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(!this->custom_headers[iter->first][iter2->first].screenPopupField ||
			   iter2->second[1].empty()) {
				continue;
			}
			if(!fields.empty()) {
				fields += "||";
			}
			string name = iter2->second[0];
			std::transform(name.begin(), name.end(), name.begin(), ::toupper);
			fields += name;
			fields += "::";
			fields += iter2->second[1];
		}
	}
	return(fields);
}

string CustomHeaders::getDeleteQuery(const char *id, const char *prefix, const char *suffix) {
	string deleteQuery;
	list<string>::iterator iter;
	for(iter = allNextTables.begin(); iter != allNextTables.end(); iter++) {
		 deleteQuery += string(prefix ? prefix : "") + 
				"delete from " + *iter + 
				" where " + this->relIdColumn + " = " + id + 
				(suffix ? suffix : "");
	}
	return(deleteQuery);
}

void CustomHeaders::createMysqlPartitions(SqlDb *sqlDb) {
	extern bool cloud_db;
	unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
	char type = opt_cdr_partition_by_hours ? 'h' : 'd';
	for(int next_day = 0; next_day < LIMIT_DAY_PARTITIONS; next_day++) {
		if((!next_day && type == 'd') ||
		   isCloud() || cloud_db) {
			sqlDb->setMaxQueryPass(1);
		}
		this->createMysqlPartitions(sqlDb, type, next_day);
		sqlDb->setMaxQueryPass(maxQueryPassOld);
	}
}

void CustomHeaders::createMysqlPartitions(class SqlDb *sqlDb, char type, int next_day) {
	extern bool opt_cdr_partition_oldver;
	list<string>::iterator iter;
	for(iter = allNextTables.begin(); iter != allNextTables.end(); iter++) {
		_createMysqlPartition(*iter, type, next_day, opt_cdr_partition_oldver, NULL, sqlDb);
	}
}

string CustomHeaders::getQueryForSaveUseInfo(Call* call, int type, tCH_Content *ch_content) {
	if(!ch_content) {
		if(call) {
			ch_content = getCustomHeadersCallContent(call, type);
		}
		if(!ch_content) {
			return("");
		}
	}
	return(getQueryForSaveUseInfo(call->calltime_us(), ch_content));
}

string CustomHeaders::getQueryForSaveUseInfo(u_int64_t time_us, tCH_Content *ch_content) {
	string query = "";
	if(TIME_US_TO_S(time_us) > this->lastTimeSaveUseInfo + 60) {
		tCH_Content::iterator iter;
		for(iter = ch_content->begin(); iter != ch_content->end(); iter++) {
			if(iter->first > CDR_NEXT_MAX) {
				break;
			}
			if(iter->first) {
				map<int, dstring>::iterator iter2;
				for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
					if(!iter2->second[1].empty()) {
						if(!query.empty()) {
							query += ";";
						}
						char queryBuff[200];
						snprintf(queryBuff, sizeof(queryBuff),
							 "update %s set use_at = '%s' where dynamic_table=%i and dynamic_column=%i",
							 this->configTable.c_str(),
							 sqlDateTimeString(TIME_US_TO_S(time_us)).c_str(),
							 iter->first,
							 iter2->first);
						query += queryBuff;
					}
				}
			}
		}
		this->lastTimeSaveUseInfo = TIME_US_TO_S(time_us);
	}
	return(query);
}

void CustomHeaders::createTablesIfNotExists(SqlDb *sqlDb, bool enableOldPartition) {
	list<string> tables = getAllNextTables();
	for(list<string>::iterator it = tables.begin(); it != tables.end(); it++) {
		createTableIfNotExists(it->c_str(), sqlDb, enableOldPartition);
	}
}

void CustomHeaders::createTableIfNotExists(const char *tableName, SqlDb *sqlDb, bool enableOldPartition) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	
	if(sqlDb->existsTable(tableName)) {
		if(_createSqlObject) {
			delete sqlDb;
		}
		return;
	}
	
	extern bool opt_cdr_partition;
	extern bool opt_cdr_partition_oldver;
	extern int opt_create_old_partitions;
	extern int opt_mysqlcompress;
	extern char opt_mysqlcompress_type[256];
	
	string limitDay;
	string partDayName;
	string limitHour;
	string partHourName;
	string limitHourNext;
	string partHourNextName;
	if(opt_cdr_partition) {
		partDayName = (dynamic_cast<SqlDb_mysql*>(sqlDb))->getPartDayName(&limitDay, opt_create_old_partitions > 0 ? -opt_create_old_partitions : 0);
		if(opt_cdr_partition_by_hours) {
			partHourName = (dynamic_cast<SqlDb_mysql*>(sqlDb))->getPartHourName(&limitHour);
			partHourNextName = (dynamic_cast<SqlDb_mysql*>(sqlDb))->getPartHourName(&limitHourNext, 1);
		}
	}
	
	string compress = opt_mysqlcompress ? (opt_mysqlcompress_type[0] ? opt_mysqlcompress_type : MYSQL_ROW_FORMAT_COMPRESSED) : "";
	
	SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
	sqlDb->query(string(
	"CREATE TABLE IF NOT EXISTS `") + tableName + "` (\
			`" + this->relIdColumn + "` bigint unsigned NOT NULL," +
			(opt_cdr_partition ?
				"`" + this->relTimeColumn + "` " + sqlDb_mysql->column_type_datetime_ms() + " NOT NULL," :
				"") + 
			"`custom_header_1` varchar(255) DEFAULT NULL,\
			`custom_header_2` varchar(255) DEFAULT NULL,\
			`custom_header_3` varchar(255) DEFAULT NULL,\
			`custom_header_4` varchar(255) DEFAULT NULL,\
			`custom_header_5` varchar(255) DEFAULT NULL,\
			`custom_header_6` varchar(255) DEFAULT NULL,\
			`custom_header_7` varchar(255) DEFAULT NULL,\
			`custom_header_8` varchar(255) DEFAULT NULL,\
			`custom_header_9` varchar(255) DEFAULT NULL,\
			`custom_header_10` varchar(255) DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`" + this->relIdColumn + "`, `" + this->relTimeColumn + "`)" :
			"PRIMARY KEY (`" + this->relIdColumn + "`)") +
		(opt_cdr_partition ?
			"" :
			(string(",CONSTRAINT `") + tableName + "_ibfk_1` FOREIGN KEY (`" + this->relIdColumn + "`) REFERENCES `" + this->mainTable + "` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE").c_str()) +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(") + this->relTimeColumn + ")(\
				 PARTITION " + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(" + this->relTimeColumn + "))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(" + this->relTimeColumn + ")(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(enableOldPartition && opt_cdr_partition && opt_create_old_partitions > 0) {
		for(int i = opt_create_old_partitions - 1; i > 0; i--) {
			this->createMysqlPartitions(sqlDb, 'd', -i);
		}
		for(int next_day = 0; next_day < LIMIT_DAY_PARTITIONS_INIT; next_day++) {
			this->createMysqlPartitions(sqlDb, opt_cdr_partition_by_hours ? 'h' : 'd', next_day);
		}
	}
	
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void CustomHeaders::checkTablesColumns(SqlDb *sqlDb, bool checkColumnsSilentLog) {
	list<string> tables = getAllNextTables();
	unsigned tableIndex = 0;
	for(list<string>::iterator it = tables.begin(); it != tables.end(); it++) {
		checkTableColumns(it->c_str(), tableIndex++, sqlDb, checkColumnsSilentLog);
	}
}

void CustomHeaders::checkTableColumns(const char *tableName, int tableIndex, SqlDb *sqlDb, bool checkColumnsSilentLog) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
	map<string, u_int64_t> tableSize;
	for(int pass = 0; pass < 2; pass++) {
		string alter_ms;
		if(!(calldate_ms[tableIndex] = sqlDb->getTypeColumn(tableName, "calldate").find("(3)") != string::npos)) {
			alter_ms = "modify column " + this->relTimeColumn + " " + sqlDb_mysql->column_type_datetime_ms() + " not null";
		}
		if(pass == 0 && opt_time_precision_in_ms) {
			if(!alter_ms.empty()) {
				if(sqlDb_mysql->isSupportForDatetimeMs()) {
					sqlDb->logNeedAlter(tableName,
							    "time accuracy in milliseconds",
							    string("ALTER TABLE ") + tableName + " " + alter_ms + ";",
							    !checkColumnsSilentLog, &tableSize, NULL);
					continue;
				} else {
					cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
					opt_time_precision_in_ms = false;
				}
			}
		}
		break;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void CustomHeaders::createColumnsForFixedHeaders(SqlDb *sqlDb) {
	if(this->fixedTable.empty()) {
		return;
	}
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	for(unsigned i = 0; i < custom_headers[0].size(); i++) {
		if(!sqlDb->existsColumn(this->fixedTable, "custom_header__" + custom_headers[0][i].header)) {
			sqlDb->query(string("ALTER TABLE `") + this->fixedTable + "` ADD COLUMN `custom_header__" + custom_headers[0][i].header + "` VARCHAR(255);");
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

bool CustomHeaders::getPosForDbId(unsigned db_id, d_u_int32_t *pos) {
	lock_custom_headers();
	bool find = false;
	map<int, map<int, sCustomHeaderData> >::iterator iter;
	for(iter = custom_headers.begin(); iter != custom_headers.end() && !find; iter++) {
		map<int, sCustomHeaderData>::iterator iter2;
		for(iter2 = iter->second.begin(); iter2 != iter->second.end() && !find; iter2++) {
			if(iter2->second.db_id == db_id) {
				pos->val[0] = iter->first;
				pos->val[1] = iter2->first;
				find = true;
			}
		}
	}
	unlock_custom_headers();
	if(!find) {
		pos->val[0] = 0;
		pos->val[1] = 0;
	}
	return(find);
}

CustomHeaders::tCH_Content *CustomHeaders::getCustomHeadersCallContent(Call *call, int type) {
	return(type == INVITE ?
		&call->custom_headers_content_cdr :
	       type == MESSAGE ? 
		&call->custom_headers_content_message :
		NULL);
}

void CustomHeaders::getHeaders(list<string> *rslt) {
	lock_custom_headers();
	for(map<int, map<int, sCustomHeaderData> >::iterator iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		for(map<int, sCustomHeaderData>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(!iter->first) {
				rslt->push_back("custom_header__" + iter2->second.header);
			} else {
				rslt->push_back("custom_header_" + intToString(iter->first) + "_" + intToString(iter2->first));
			}
		}
	}
	unlock_custom_headers();
}

void CustomHeaders::getValues(Call *call, int type, list<string> *rslt) {
	lock_custom_headers();
	call->custom_headers_content_lock();
	tCH_Content *ch_content = getCustomHeadersCallContent(call, type);
	for(map<int, map<int, sCustomHeaderData> >::iterator iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		for(map<int, sCustomHeaderData>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			rslt->push_back(tCH_Content_value(ch_content, iter->first, iter2->first));
		}
	}
	call->custom_headers_content_unlock();
	unlock_custom_headers();
}

void CustomHeaders::getHeaderValues(Call *call, int type, map<string, string> *rslt) {
	lock_custom_headers();
	call->custom_headers_content_lock();
	tCH_Content *ch_content = getCustomHeadersCallContent(call, type);
	for(map<int, map<int, sCustomHeaderData> >::iterator iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		for(map<int, sCustomHeaderData>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(!iter->first) {
				(*rslt)["custom_header__" + iter2->second.header] = tCH_Content_value(ch_content, iter->first, iter2->first);
			} else {
				(*rslt)["custom_header_" + intToString(iter->first) + "_" + intToString(iter2->first)] = tCH_Content_value(ch_content, iter->first, iter2->first);
			}
		}
	}
	call->custom_headers_content_unlock();
	unlock_custom_headers();
}

string CustomHeaders::getValue(Call *call, int type, const char *header) {
	string rslt;
	lock_custom_headers();
	call->custom_headers_content_lock();
	tCH_Content *ch_content = getCustomHeadersCallContent(call, type);
	for(map<int, map<int, sCustomHeaderData> >::iterator iter = custom_headers.begin(); iter != custom_headers.end() && rslt.empty(); iter++) {
		for(map<int, sCustomHeaderData>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end() && rslt.empty(); iter2++) {
			string cmpHeaderName = !iter->first ?
						"custom_header__" + iter2->second.header :
						"custom_header_" + intToString(iter->first) + "_" + intToString(iter2->first);
			if(header == cmpHeaderName) {
				rslt = tCH_Content_value(ch_content, iter->first, iter2->first);
			}
		}
	}
	call->custom_headers_content_unlock();
	unlock_custom_headers();
	return(rslt);
}

string CustomHeaders::tCH_Content_value(tCH_Content *ch_content, int i1, int i2) {
	tCH_Content::iterator iter = ch_content->find(i1);
	if(iter != ch_content->end()) {
		map<int, dstring>::iterator iter2 = iter->second.find(i2);
		if(iter2 != iter->second.end()) {
			return(iter2->second[1]);
		}
	}
	return("");
}

unsigned CustomHeaders::getSize() {
	unsigned size = 0;
	lock_custom_headers();
	for(map<int, map<int, sCustomHeaderData> >::iterator iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		size += iter->second.size();
	}
	unlock_custom_headers();
	return(size);
}


NoHashMessageRule::NoHashMessageRule() {
	customHeader_db_id = 0;
	customHeader_ok = false;
}

NoHashMessageRule::~NoHashMessageRule() {
	clean_list_regexp();
}

bool NoHashMessageRule::checkNoHash(Call *call) {
	if(!this->customHeader_ok &&
	   !this->content_regexp.size()) {
		return(false);
	}
	bool noHashByHeader = false;
	if(this->customHeader_ok) {
		string header = call->custom_headers_content_message[this->customHeader_pos[0]][this->customHeader_pos[1]][1];
		if(header.length()) {
			if(this->header_regexp.size()) {
				list<cRegExp*>::iterator iter_header_regexp;
				for(iter_header_regexp = this->header_regexp.begin(); iter_header_regexp != this->header_regexp.end(); iter_header_regexp++) {
					if((*iter_header_regexp)->match(header.c_str())) {
						noHashByHeader = true;
						break;
					}
				}
			} else {
				noHashByHeader = true;
			}
		}
	}
	bool noHashByContent = false;
	if(call->message) {
		list<cRegExp*>::iterator iter_content_regexp;
		for(iter_content_regexp = this->content_regexp.begin(); iter_content_regexp != this->content_regexp.end(); iter_content_regexp++) {
			if((*iter_content_regexp)->match(call->message)) {
				noHashByContent = true;
				break;
			}
		}
	}
	return((!this->customHeader_ok || noHashByHeader) &&
	       (!this->content_regexp.size() || noHashByContent));
}

void NoHashMessageRule::load(const char *name, 
			     unsigned customHeader_db_id, const char *customHeader_name, 
			     const char *header_regexp, const char *content_regexp) {
	this->name = name;
	if(customHeader_db_id) {
		this->customHeader_db_id = customHeader_db_id;
		this->customHeader_name = customHeader_name;
		extern CustomHeaders *custom_headers_message;
		this->customHeader_ok = custom_headers_message->getPosForDbId(this->customHeader_db_id, &this->customHeader_pos);
		
	} else {
		this->customHeader_db_id = 0;
		this->customHeader_pos.val[0] = 0;
		this->customHeader_pos.val[1] = 0;
		this->customHeader_ok = false;
	}
	clean_list_regexp();
	if(header_regexp && *header_regexp) {
		vector<string> header_regexp_a = split(header_regexp, "\n", true);
		for(unsigned i = 0; i < header_regexp_a.size(); i++) {
			cRegExp *regExp = new FILE_LINE(1013) cRegExp(header_regexp_a[i].c_str());
			this->header_regexp.push_back(regExp);
		}
	}
	if(content_regexp && *content_regexp) {
		vector<string> content_regexp_a = split(content_regexp, "\n", true);
		for(unsigned i = 0; i < content_regexp_a.size(); i++) {
			cRegExp *regExp = new FILE_LINE(1014) cRegExp(content_regexp_a[i].c_str());
			this->content_regexp.push_back(regExp);
		}
	}
}

void NoHashMessageRule::clean_list_regexp() {
	while(header_regexp.size()) {
		list<cRegExp*>::iterator iter = header_regexp.begin();
		delete *iter;
		header_regexp.erase(iter);
	}
	while(content_regexp.size()) {
		list<cRegExp*>::iterator iter = content_regexp.begin();
		delete *iter;
		content_regexp.erase(iter);
	}
}

NoHashMessageRules::NoHashMessageRules(SqlDb *sqlDb) {
	loadTime = 0;
	_sync_no_hash = 0;
	load(sqlDb);
}

NoHashMessageRules::~NoHashMessageRules() {
	clear();
}

bool NoHashMessageRules::checkNoHash(Call *call) {
	bool noHash = false;
	lock_no_hash();
	list<NoHashMessageRule*>::iterator rules_iter;
	for(rules_iter = rules.begin(); rules_iter != rules.end(); ++rules_iter) {
		if((*rules_iter)->checkNoHash(call)) {
			noHash = true;
			break;
		}
	}
	unlock_no_hash();
	return(noHash);
}

void NoHashMessageRules::load(SqlDb *sqlDb, bool lock) {
	if(lock) lock_no_hash();
	clear(false);
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("message_no_hash_rules")) {
		sqlDb->query("SELECT nhr.*, \
				     ch.name as msg_custom_headers_name \
			      FROM message_no_hash_rules nhr \
			      JOIN message_custom_headers ch on (ch.id = nhr.msg_custom_headers_id)");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			NoHashMessageRule *rule = new FILE_LINE(1015) NoHashMessageRule;
			rule->load(row["name"].c_str(), 
				   atoi(row["msg_custom_headers_id"].c_str()),
				   row["msg_custom_headers_name"].c_str(),
				   row["header_regexp"].c_str(), 
				   row["content_regexp"].c_str());
			rules.push_back(rule);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	loadTime = getTimeMS();
	if(lock) unlock_no_hash();
}

void NoHashMessageRules::clear(bool lock) {
	if(lock) lock_no_hash();
	while(rules.size()) {
		list<NoHashMessageRule*>::iterator iter = rules.begin();
		delete *iter;
		rules.erase(iter);
	}
	if(lock) unlock_no_hash();
}

void NoHashMessageRules::refresh(SqlDb *sqlDb) {
	lock_no_hash();
	clear(false);
	load(sqlDb, false);
	unlock_no_hash();
}


NoStoreCdrRule::NoStoreCdrRule() {
	lastResponseNum = 0;
	lastResponseNumLength = 0;
	ip.clear();
	ip_mask_length = 0;
	number_check = NULL;
	number_regexp = NULL;
	name_check = NULL;
	name_regexp = NULL;
	lsr_check = NULL;
	lsr_regexp = NULL;
}

NoStoreCdrRule::~NoStoreCdrRule() {
	if(number_check) {
		delete number_check;
	}
	if(number_regexp) {
		delete number_regexp;
	}
	if(name_check) {
		delete name_check;
	}
	if(name_regexp) {
		delete name_regexp;
	}
	if(lsr_check) {
		delete lsr_check;
	}
	if(lsr_regexp) {
		delete lsr_regexp;
	}
}

bool NoStoreCdrRule::check(Call *call) {
	bool ok = matchResponseCode(lastResponseNum, lastResponseNumLength, call->lastSIPresponseNum);
 	if(ok && ip.isSet()) {
		if(!check_ip(call->getSipcallerip(), ip, ip_mask_length) &&
		   !check_ip(call->getSipcalledip(), ip, ip_mask_length) &&
		   !check_ip(call->getSipcalledipConfirmed(), ip, ip_mask_length)) {
			ok = false;
		}
	}
	if(ok && number.length()) {
		if(!check_number(call->caller) &&
		   !check_number(call->called())) {
			ok = false;
		}
	}
	if(ok && name.length()) {
		if(!check_name(call->callername)) {
			ok = false;
		}
	}
	if(ok && lsr.length()) {
		if(!check_lsr(call->lastSIPresponse)) {
			ok = false;
		}
	}
	return(ok);
}

void NoStoreCdrRule::set(const char *pattern) {
	while(*pattern == ' ') {
		++pattern;
	}
	lastResponseNum = atoi(pattern);
	if(lastResponseNum > 0) {
		lastResponseNumLength = log10int(lastResponseNum) + 1;
	} else if(lastResponseNum == 0) {
		lastResponseNumLength = 1;
	} else {
		return;
	}
	//cout << "* " << lastResponseNum << "/" << lastResponseNumLength << endl;
	const char *cond_prefix[] = {
		"ip",
		"number",
		"name",
		"lsr"
	};
	for(unsigned i = 0; i < sizeof(cond_prefix) / sizeof(cond_prefix[0]); i++) {
		const char *cond_prefix_pos = strcasestr(pattern, cond_prefix[i]);
		if(cond_prefix_pos) {
			const char *cond_data_pos = cond_prefix_pos + strlen(cond_prefix[i]);
			if(*cond_data_pos == ' ' || *cond_data_pos == ':' || *cond_data_pos == '=') {
				bool ok_cond_data_sep = false;
				while(*cond_data_pos == ' ' || *cond_data_pos == ':' || *cond_data_pos == '=') {
					if(*cond_data_pos == ':' || *cond_data_pos == '=') {
						ok_cond_data_sep = true;
					}
					++cond_data_pos;
				}
				if(*cond_data_pos && ok_cond_data_sep) {
					const char *cond_data_pos_end = cond_data_pos;
					while(*(cond_data_pos_end + 1) && *(cond_data_pos_end + 1) != ' ') {
						++cond_data_pos_end;
					}
					string cond_data = string(cond_data_pos, cond_data_pos_end - cond_data_pos + 1);
					//cout << "* " << cond_prefix[i] << " : " << cond_data << endl;
					if(i == 0) {
						size_t posMaskSep = cond_data.find('/');
						if(posMaskSep != string::npos) {
							ip.setFromString(cond_data.substr(0, posMaskSep).c_str());
							ip_mask_length = atoi(cond_data.substr(posMaskSep + 1).c_str());
						} else {
							ip.setFromString(cond_data.c_str());
						}
					} else if(i == 1) {
						number = cond_data;
						number_check = new FILE_LINE(0) CheckString(number.c_str());
						if(!string_is_alphanumeric(number.c_str()) && check_regexp(number.c_str())) {
							number_regexp = new FILE_LINE(0) cRegExp(number.c_str());
						}
					} else if(i == 2) {
						name = cond_data;
						name_check = new FILE_LINE(0) CheckString(name.c_str());
						if(!string_is_alphanumeric(name.c_str()) && check_regexp(name.c_str())) {
							name_regexp = new FILE_LINE(0) cRegExp(name.c_str());
						}
					} else if(i == 3) {
						lsr = cond_data;
						lsr_check = new FILE_LINE(0) CheckString(lsr.c_str());
						if(!string_is_alphanumeric(lsr.c_str()) && check_regexp(lsr.c_str())) {
							lsr_regexp = new FILE_LINE(0) cRegExp(lsr.c_str());
						}
					}
				}
			}
		}
	}
}

bool NoStoreCdrRule::isSet() {
	return(lastResponseNumLength > 0);
}

bool NoStoreCdrRule::check_number(const char *number) {
	return((number_check && number_check->check(number)) ||
	       (number_regexp && number_regexp->match(number)));
}

bool NoStoreCdrRule::check_name(const char *name) {
	return((name_check && name_check->check(name)) ||
	       (name_regexp && name_regexp->match(name)));
}

bool NoStoreCdrRule::check_lsr(const char *lsr) {
	return((lsr_check && lsr_check->check(lsr)) ||
	       (lsr_regexp && lsr_regexp->match(lsr)));
}

NoStoreCdrRules::~NoStoreCdrRules() {
	for(list<NoStoreCdrRule*>::iterator iter = rules.begin(); iter != rules.end(); iter++) {
		delete (*iter);
	}
}

bool NoStoreCdrRules::check(Call *call) {
	for(list<NoStoreCdrRule*>::iterator iter = rules.begin(); iter != rules.end(); iter++) {
		if((*iter)->check(call)) {
			return(true);
		}
	}
	return(false);
}

void NoStoreCdrRules::set(const char *pattern) {
	NoStoreCdrRule *rule = new FILE_LINE(0) NoStoreCdrRule; 
	rule->set(pattern);
	if(rule->isSet()) {
		rules.push_back(rule);
	} else {
		delete rule;
	}
}

bool NoStoreCdrRules::isSet() {
	return(rules.size() > 0);
}


AsyncSystemCommand::AsyncSystemCommand() {
	threadPopSystemCommand = 0;
	termPopSystemCommand = false;
	initPopSystemCommandThread();
}

AsyncSystemCommand::~AsyncSystemCommand() {
	stopPopSystemCommandThread();
}

void AsyncSystemCommand::stopPopSystemCommandThread() {
	termPopSystemCommand = true;
	pthread_join(this->threadPopSystemCommand, NULL);
}

void AsyncSystemCommand::addSystemCommand(const char *command) {
	string command_str = command;
	systemCommandQueue.push(command_str);
}

void AsyncSystemCommand::initPopSystemCommandThread() {
	vm_pthread_create("async system command",
			  &this->threadPopSystemCommand, NULL, AsyncSystemCommand::popSystemCommandThread, this, __FILE__, __LINE__);
}

void AsyncSystemCommand::popSystemCommandThread() {
	while(!is_terminating() && !termPopSystemCommand) {
		bool okPop = false;
		string command;
		if(systemCommandQueue.pop(&command)) {
			if(sverb.system_command) {
				syslog(LOG_NOTICE, "call system command: %s (queue size: %i)", command.c_str(), systemCommandQueue.getSize());
			}
			system(command.c_str());
			okPop = true;
		}
		if(!okPop) {
			USLEEP(1000);
		}
	}
}

void *AsyncSystemCommand::popSystemCommandThread(void *arg) {
	((AsyncSystemCommand*)arg)->popSystemCommandThread();
	return(NULL);
}


struct sRequestNameCode {
	const char *name;
	int code;
	bool response;
} requestNameCode[] = {
	{ "INVITE", INVITE, 0 },
	{ "BYE", BYE, 0 },
	{ "CANCEL", CANCEL, 0 },
	{ "RES10X" , RES10X, 1 },
	{ "RES18X", RES18X, 1 },
	{ "RES182", RES182, 1 },
	{ "RES2XX", RES2XX, 1 },
	{ "RES300", RES300, 1 },
	{ "RES3XX", RES3XX, 1 },
	{ "RES401", RES401, 1 },
	{ "RES403", RES403, 1 },
	{ "RES404", RES404, 1 },
	{ "RES4XX", RES4XX, 1 },
	{ "RES5XX", RES5XX, 1 },
	{ "RES6XX", RES6XX, 1 },
	{ "REGISTER", REGISTER, 0 },
	{ "MESSAGE", MESSAGE, 0 },
	{ "INFO", INFO, 0 },
	{ "SUBSCRIBE", SUBSCRIBE, 0 },
	{ "OPTIONS", OPTIONS, 0 },
	{ "NOTIFY", NOTIFY, 0 },
	{ "ACK", ACK, 0 },
	{ "PRACK", PRACK, 0 },
	{ "PUBLISH", PUBLISH, 0 },
	{ "REFER" , REFER, 0 },
	{ "UPDATE", UPDATE, 0 }
};

int sip_request_name_to_int(const char *requestName, bool withResponse) {
	if(!requestName || !requestName[0]) {
		return(0);
	}
	for(size_t i = 0; i < sizeof(requestNameCode) / sizeof(requestNameCode[0]); i++) {
		if(!withResponse && requestNameCode[i].response) {
			continue;
		}
		if(requestName[0] == requestNameCode[i].name[0] && !strcmp(requestName, requestNameCode[i].name)) {
			return(requestNameCode[i].code);
		}
	}
	return(0);
}

const char *sip_request_int_to_name(int requestCode, bool withResponse) {
	if(!requestCode) {
		return(NULL);
	}
	for(size_t i = 0; i < sizeof(requestNameCode) / sizeof(requestNameCode[0]); i++) {
		if(!withResponse && requestNameCode[i].response) {
			continue;
		}
		if(requestCode == requestNameCode[i].code) {
			return(requestNameCode[i].name);
		}
	}
	return(NULL);
}


string printCallFlags(unsigned long int flags) {
	ostringstream outStr;
	if(flags & FLAG_SAVERTP)		outStr << "savertp ";
	if(flags & FLAG_SAVERTP_VIDEO)		outStr << "savertp_video ";
	if(flags & FLAG_SAVERTCP)		outStr << "savertcp ";
	if(flags & FLAG_SAVESIP)		outStr << "savesip ";
	if(flags & FLAG_SAVEREGISTER)		outStr << "saveregister ";
	if(flags & FLAG_SAVEAUDIO)		outStr << "saveaudio ";
	if(flags & FLAG_FORMATAUDIO_WAV)	outStr << "format_wav ";
	if(flags & FLAG_FORMATAUDIO_OGG)	outStr << "format_ogg ";
	if(flags & FLAG_SAVEGRAPH)		outStr << "savegraph ";
	if(flags & FLAG_SAVERTPHEADER)		outStr << "savertpheader ";
	if(flags & FLAG_SAVERTP_VIDEO_HEADER)	outStr << "savertp_video_header ";
	if(flags & FLAG_PROCESSING_RTP_VIDEO)	outStr << "processing_rtp_video ";
	if(flags & FLAG_SKIPCDR)		outStr << "skipcdr ";
	if(flags & FLAG_RUNSCRIPT)		outStr << "runscript ";
	if(flags & FLAG_RUNAMOSLQO)		outStr << "runamoslqo ";
	if(flags & FLAG_RUNBMOSLQO)		outStr << "runbmoslqo ";
	if(flags & FLAG_HIDEMESSAGE)		outStr << "hidemessage ";
	if(flags & FLAG_USE_SPOOL_2)		outStr << "use_spool_2 ";
	if(flags & FLAG_SAVEDTMFDB)		outStr << "savedtmfdb ";
	if(flags & FLAG_SAVEDTMFPCAP)		outStr << "savedtmfpcap ";
	if(flags & FLAG_SAVEOPTIONSDB)		outStr << "saveoptionsdb ";
	if(flags & FLAG_SAVEOPTIONSPCAP)	outStr << "saveoptionspcap ";
	if(flags & FLAG_SAVENOTIFYDB)		outStr << "savenotifydb ";
	if(flags & FLAG_SAVENOTIFYPCAP)		outStr << "savenotifypcap ";
	if(flags & FLAG_SAVESUBSCRIBEDB)	outStr << "savesubscribedb ";
	if(flags & FLAG_SAVESUBSCRIBEPCAP)	outStr << "savesubscribepcap ";
	return(outStr.str());
}

eCallField convCallFieldToFieldId(const char *field) {
	for(unsigned i = 0; i < sizeof(callFields) / sizeof(callFields[0]); i++) {
		if(!strcmp(field, callFields[i].fieldName)) {
			return(callFields[i].fieldType);
		}
	}
	return(cf_na);
}

int convCallFieldToFieldIndex(eCallField field) {
	for(unsigned i = 0; i < sizeof(callFields) / sizeof(callFields[0]); i++) {
		if(callFields[i].fieldType == field) {
			return(i);
		}
	}
	return(-1);
}


void reset_counters() {
	calls_counter = 0;
	registers_counter = 0;
}


#if DEBUG_ASYNC_TAR_WRITE
cDestroyCallsInfo::~cDestroyCallsInfo() {
	lock();
	while(queue.size() > 0) {
		sCallInfo *ci = queue.front();
		q_map.erase(ci->fbasename);
		queue.pop_front();
		delete ci;
	}
	unlock();
}

void cDestroyCallsInfo::add(Call *call) {
	lock();
	if(q_map.find(call->fbasename) == q_map.end()) {
		sCallInfo *ci = new FILE_LINE(0) sCallInfo(call);
		queue.push_back(ci);
		q_map[call->fbasename] = ci;
		while(queue.size() > limit) {
			sCallInfo *ci = queue.front();
			q_map.erase(ci->fbasename);
			queue.pop_front();
			delete ci;
		}
	}
	unlock();
}

string cDestroyCallsInfo::find(string fbasename, int index) {
	lock();
	map<string, sCallInfo*>::iterator iter = q_map.find(fbasename);
	if(iter == q_map.end()) {
		unlock();
		return("");
	}
	sCallInfo ci = *iter->second;
	unlock();
	ostringstream outStr;
	outStr << "pt: " << hex << ci.pointer_to_call << dec << ", "
	       << "dt: " << ci.destroy_time << ", "
	       << "tid: " << ci.tid << ", "
	       << "cnt: " << ci.chunk_buffers_count << ", "
	       << "ss: " << ci.dump_sip_state;
	if(index >= 0 && index < P_FLAGS_IMAX) {
	       outStr << ", pf: ";
	       for(unsigned i = 0; i < ci.p_flags_count[index]; i++) {
		       if(i) outStr << ',';
		       outStr << (int)(ci.p_flags[index][i]);
	       }
	}
	outStr  << " / ";
	return(outStr.str());
}
#endif
