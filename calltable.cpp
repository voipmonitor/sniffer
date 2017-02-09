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

#include <iostream>
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
#include "tar.h"
#include "filter_mysql.h"
#include "sniff_inline.h"
#include "register.h"
#include "manager.h"

#if HAVE_LIBTCMALLOC    
#include <gperftools/malloc_extension.h>
#endif


#define MIN(x,y) ((x) < (y) ? (x) : (y))

using namespace std;

extern int verbosity;
extern int verbosityE;
extern int opt_sip_register;
extern int opt_saveRTP;
extern int opt_onlyRTPheader;
extern int opt_saveSIP;
extern int opt_rtcp;
extern int opt_saveRAW;                // save RTP payload RAW data?
extern int opt_saveWAV;                // save RTP payload RAW data?
extern int opt_saveGRAPH;	// save GRAPH data to graph file? 
extern FileZipHandler::eTypeCompress opt_gzipGRAPH;	// compress GRAPH data to graph file? 
extern int opt_mos_g729;
extern int opt_nocdr;
extern int nocdr_for_last_responses[100];
extern int nocdr_for_last_responses_length[100];
extern int nocdr_for_last_responses_count;
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
extern unsigned int gthread_num;
extern volatile int num_threads_active;
extern int opt_printinsertid;
extern int opt_cdronlyanswered;
extern int opt_cdronlyrtp;
extern int opt_newdir;
extern char opt_keycheck[1024];
extern char opt_convert_char[256];
extern int opt_norecord_dtmf;
extern char opt_silencedtmfseq[16];
extern int opt_pauserecordingdtmf_timeout;
extern char get_customers_pn_query[1024];
extern int opt_saverfc2833;
extern int opt_dbdtmf;
extern int opt_dscp;
extern int opt_cdrproxy;
extern int opt_messageproxy;
extern int opt_pcap_dump_tar;
extern struct pcap_stat pcapstat;
extern int opt_filesclean;
extern int opt_allow_zerossrc;
extern int opt_cdr_ua_enable;
extern vector<string> opt_cdr_ua_reg_remove;
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
extern int opt_mysqlstore_limit_queue_register;
extern Calltable *calltable;
extern int opt_silencedetect;
extern int opt_clippingdetect;
extern int opt_read_from_file;
extern char opt_pb_read_from_file[256];
extern CustomHeaders *custom_headers_cdr;
extern CustomHeaders *custom_headers_message;
extern int opt_custom_headers_last_value;
extern bool _save_sip_history;
extern int opt_saveudptl;
extern rtp_read_thread *rtp_threads;
extern bool opt_rtpmap_by_callerd;
extern bool opt_rtpmap_combination;
extern int opt_register_timeout_disable_save_failed;
extern int opt_rtpfromsdp_onlysip;

volatile int calls_counter = 0;
volatile int registers_counter = 0;

extern char mac[32];

unsigned int last_register_clean = 0;

extern int opt_onewaytimeout;
extern int opt_saveaudio_reversestereo;
extern int opt_saveaudio_stereo;
extern int opt_saveaudio_reversestereo;
extern float opt_saveaudio_oggquality;
extern int opt_skinny;
extern int opt_enable_fraud;
extern char opt_callidmerge_header[128];
extern int opt_sdp_multiplication;
extern int opt_hide_message_content;
extern char opt_hide_message_content_secret[1024];
extern vector<string> opt_message_body_url_reg;

SqlDb *sqlDbSaveCall = NULL;
extern sExistsColumns existsColumns;

extern int opt_pcap_dump_tar_sip_use_pos;
extern int opt_pcap_dump_tar_rtp_use_pos;
extern int opt_pcap_dump_tar_graph_use_pos;

extern unsigned int glob_ssl_calls;
extern bool opt_cdr_partition;


/* constructor */
Call::Call(int call_type, char *call_id, unsigned long call_id_len, time_t time) :
 tmprtp(-1, 0),
 pcap(PcapDumper::na, this),
 pcapSip(PcapDumper::sip, this),
 pcapRtp(PcapDumper::rtp, this) {
	//increaseTartimemap(time);
	type = call_type;
	has_second_merged_leg = false;
	isfax = 0;
	seenudptl = 0;
	not_acceptable = false;
	last_callercodec = -1;
	ipport_n = 0;
	ssrc_n = 0;
	first_packet_time = time;
	first_packet_usec = 0;
	last_packet_time = time;
	last_rtp_a_packet_time = 0;
	last_rtp_b_packet_time = 0;
	if(call_id_len) {
		this->call_id = string(call_id, call_id_len);
		this->call_id_len = call_id_len;
	} else {
		this->call_id = string(call_id);
		this->call_id_len = this->call_id.length();
	}
	whohanged = -1;
	seeninvite = false;
	seeninviteok = false;
	seenbye = false;
	seenbye_time_usec = 0;
	seenbyeandok = false;
	seenbyeandok_time_usec = 0;
	unconfirmed_bye = false;
	seenRES2XX = false;
	seenRES2XX_no_BYE = false;
	seenRES18X = false;
	caller[0] = '\0';
	caller_domain[0] = '\0';
	callername[0] = '\0';
	called[0] = '\0';
	called_domain[0] = '\0';
	contact_num[0] = '\0';
	contact_domain[0] = '\0';
	digest_username[0] = '\0';
	digest_realm[0] = '\0';
	register_expires = -1;
	byecseq[0] = '\0';
	invitecseq[0] = '\0';
	cancelcseq[0] = '\0';
	updatecseq[0] = '\0';
	sighup = false;
	progress_time = 0;
	first_rtp_time = 0;
	connect_time = 0;
	connect_time_usec = 0;
	first_invite_time_usec = 0;
	first_response_100_time_usec = 0;
	first_response_xxx_time_usec = 0;
	first_message_time_usec = 0;
	first_response_200_time_usec = 0;
	a_ua[0] = '\0';
	b_ua[0] = '\0';
	memset(rtpmap, 0, sizeof(rtpmap));
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
	msgcount = 0;
	regcount = 0;
	reg401count = 0;
	reg401count_distinct = 0;
	for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
		reg401count_sipcallerip[i] = 0;
	}
	reg403count = 0;
	reg403count_distinct = 0;
	for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
		reg403count_sipcallerip[i] = 0;
	}
	reg200count = 0;
	regstate = 0;
	regresponse = false;
	regrrddiff = -1;
	//regsrcmac = 0;
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
		rtp[i] = NULL;
	}
	rtplock = 0;
	audiobuffer1 = NULL;
	last_seq_audiobuffer1 = 0;
	last_ssrc_audiobuffer1 = 0;
	audiobuffer2 = NULL;
	last_seq_audiobuffer2 = 0;
	last_ssrc_audiobuffer2 = 0;
	listening_worker_run = NULL;
	tmprtp.call_owner = this;
	flags = 0;
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	destroy_call_at = 0;
	destroy_call_at_bye = 0;
	destroy_call_at_bye_confirmed = 0;
	custom_header1[0] = '\0';
	match_header[0] = '\0';
	if(type == INVITE && is_enable_rtp_threads() && num_threads_active > 0) {
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
	} else {
		thread_num = 0;
		thread_num_rd = 0;
	}
	recordstopped = 0;
	dtmfflag = 0;
	for(unsigned int i = 0; i < sizeof(dtmfflag2) / sizeof(dtmfflag2[0]); i++) {
		dtmfflag2[i] = 0;
	}
	silencerecording = 0;
	recordingpausedby182 = 0;
	flags1 = 0;
	rtppacketsinqueue = 0;
	end_call = 0;
	push_call_to_calls_queue = 0;
	push_register_to_registers_queue = 0;
	message = NULL;
	message_info = NULL;
	contenttype = NULL;
	content_length = 0;
	dcs = 0;
	voicemail = voicemail_na;
	max_length_sip_data = 0;
	max_length_sip_packet = 0;
	unrepliedinvite = 0;
	for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
		 sipcallerip[i] = 0;
		 sipcalledip[i] = 0;
	}
	lastsipcallerip = 0;
	sipcallerport = 0;
	sipcalledport = 0;
	fname_register = 0;
	skinny_partyid = 0;
	pthread_mutex_init(&listening_worker_run_lock, NULL);
	caller_sipdscp = 0;
	called_sipdscp = 0;
	ps_ifdrop = pcapstat.ps_ifdrop;
	ps_drop = pcapstat.ps_drop;
	if(verbosity && verbosityE > 1) {
		syslog(LOG_NOTICE, "CREATE CALL %s", this->call_id.c_str());
	}
	forcemark[0] = forcemark[1] = 0;
	_forcemark_lock = 0;
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
	
	onCall_2XX = false;
	onCall_18X = false;
	updateDstnumOnAnswer = false;
	updateDstnumFromMessage = false;
	
	useSensorId = opt_id_sensor;
	useDlt = global_pcap_dlink;
	useHandle = global_pcap_handle;
	
	force_close = false;
	
	first_codec = -1;
	chantype = 0;
	
	chunkBuffersCount = 0;

        caller_silence = 0;
        called_silence = 0;
        caller_noise = 0;
        called_noise = 0;
	caller_lastsilence = 0;
	called_lastsilence = 0;

	caller_clipping_8k = 0;
	called_clipping_8k = 0;
	
	vlan = -1;
	
	error_negative_payload_length = false;
	use_removeRtp = false;
	hash_counter = 0;
	use_rtcp_mux = false;
	rtp_from_multiple_sensors = false;
	
	is_ssl = false;

	rtp_zeropackets_stored = 0;
}

void
Call::hashRemove() {
	int i;
	Calltable *ct = (Calltable *)calltable;

	for(i = 0; i < ipport_n; i++) {
		ct->hashRemove(this, this->ip_port[i].addr, this->ip_port[i].port);
		if(opt_rtcp) {
			ct->hashRemove(this, this->ip_port[i].addr, this->ip_port[i].port + 1, true);
		}
		this->evDestroyIpPortRtpStream(i);
	}
	
	if(this->hash_counter) {
		syslog(LOG_WARNING, "WARNING: rest before hash cleanup for callid: %s: %i", this->fbasename, this->hash_counter);
		if(this->hash_counter > 0) {
			ct->hashRemove(this);
			if(this->hash_counter) {
				syslog(LOG_WARNING, "WARNING: rest after hash cleanup for callid: %s: %i", this->fbasename, this->hash_counter);
			}
		}
	}
}

void
Call::skinnyTablesRemove() {
	if(opt_skinny) {
		if(skinny_partyid) {
			((Calltable *)calltable)->skinny_partyID.erase(skinny_partyid);
			skinny_partyid = 0;
		}
		/*
		stringstream tmp[2];

		tmp[0] << this->sipcallerip << '|' << this->sipcalledip;
		tmp[1] << this->sipcallerip << '|' << this->sipcalledip;
		*/

		for (map<string, Call*>::iterator skinny_ipTuplesIT = ((Calltable *)calltable)->skinny_ipTuples.begin(); skinny_ipTuplesIT != ((Calltable *)calltable)->skinny_ipTuples.end();) {
			if(skinny_ipTuplesIT->second == this) {
				((Calltable *)calltable)->skinny_ipTuples.erase(skinny_ipTuplesIT++);
			} else {
				++skinny_ipTuplesIT;
			}
		}
	}
}

void
Call::removeFindTables(bool set_end_call) {
	if(set_end_call) {
		this->end_call = 1;
	}
	this->hashRemove();
	this->skinnyTablesRemove();
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
Call::evStartRtpStream(int /*index_ip_port*/, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, time_t time) {
	/*cout << "start rtp stream : "
	     << inet_ntostring(htonl(saddr)) << ":" << sport << " -> " 
	     << inet_ntostring(htonl(daddr)) << ":" << dport << endl;*/
	if(opt_enable_fraud) {
		fraudBeginRtpStream(saddr, sport, daddr, dport, this, time);
	}
}

void 
Call::evEndRtpStream(int /*index_ip_port*/, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, time_t time) {
	/*cout << "stop rtp stream : "
	     << inet_ntostring(htonl(saddr)) << ":" << sport << " -> " 
	     << inet_ntostring(htonl(daddr)) << ":" << dport << endl;*/
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
Call::removeRTP() {
	while(this->rtppacketsinqueue > 0) {
		extern bool opt_t2_boost;
		if(!opt_t2_boost && rtp_threads) {
			extern int num_threads_max;
			for(int i = 0; i < num_threads_max; i++) {
				if(rtp_threads[i].threadId) {
					rtp_threads[i].push_batch();
				}
			}
		}
		usleep(100);
	}
	while(__sync_lock_test_and_set(&rtplock, 1)) {
		usleep(100);
	}
	closeRawFiles();
	ssrc_n = 0;
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
	// lets check whole array as there can be holes due rtp[0] <=> rtp[1] swaps in mysql rutine
		if(rtp[i]) {
			delete rtp[i];
			rtp[i] = NULL;
		}
	}
	for(int i = 0; i < 2; i++) {
		rtp_cur[i] = NULL;
		rtp_prev[i] = NULL;
	}
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	__sync_lock_release(&rtplock);
	use_removeRtp = true;
}

/* destructor */
Call::~Call(){
	if(opt_callidmerge_header[0] != '\0') {
		((Calltable*)calltable)->lock_calls_mergeMAP();
		for(std::vector<string>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
			((Calltable*)calltable)->calls_mergeMAP.erase(*it);
		}
		((Calltable*)calltable)->unlock_calls_mergeMAP();
	}
	
	if(is_ssl) {
		glob_ssl_calls--;
	}

	if(contenttype) delete [] contenttype;
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
		// lets check whole array as there can be holes due rtp[0] <=> rtp[1] swaps in mysql rutine
		if(rtp[i]) {
			delete rtp[i];
		}
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
	
	if(type == INVITE && is_enable_rtp_threads() && num_threads_active > 0 && rtp_threads) {
		extern void lock_add_remove_rtp_threads();
		extern void unlock_add_remove_rtp_threads();
		lock_add_remove_rtp_threads();
		if(rtp_threads[thread_num].calls > 0) {
			__sync_sub_and_fetch(&rtp_threads[thread_num].calls, 1);
		}
		unlock_add_remove_rtp_threads();
	}
}

void
Call::closeRawFiles() {
	for(int i = 0; i < ssrc_n; i++) {
		// close RAW files
		if(rtp[i]->gfileRAW) {
			FILE *tmp;
			rtp[i]->jitterbuffer_fixed_flush(rtp[i]->channel_record);
			/* preventing race condition as gfileRAW is checking for NULL pointer in rtp classes */ 
			tmp = rtp[i]->gfileRAW;
			rtp[i]->gfileRAW = NULL;
			fclose(tmp);
		}
		// close GRAPH files
		if(opt_saveGRAPH || (flags & FLAG_SAVEGRAPH)) {
			if(rtp[i]->graph.isOpen()) {
				if(!rtp[i]->mos_processed or (rtp[i]->last_mos_time + 4 < rtp[i]->_last_ts.tv_sec)) {
					rtp[i]->save_mos_graph(true);
				}
				rtp[i]->graph.close();
			} else {
				rtp[i]->graph.clearAutoOpen();
			}
		}
	}
}

string
Call::get_sensordir() {
	string sensorDir;
	extern int opt_spooldir_by_sensor;
	extern int opt_spooldir_by_sensorname;
	if((opt_spooldir_by_sensor && useSensorId > 0) || 
	   opt_spooldir_by_sensorname) {
		if(opt_spooldir_by_sensorname) {
			extern SensorsMap sensorsMap;
			sensorDir = sensorsMap.getSensorNameFile(useSensorId);
		} else if(opt_spooldir_by_sensor) {
			char sensorDir_buff[10];
			snprintf(sensorDir_buff, sizeof(sensorDir_buff), "%i", useSensorId);
			sensorDir = sensorDir_buff;
		}
	}
	return(sensorDir);
}

string
Call::get_pathname(eTypeSpoolFile typeSpoolFile, const char *substSpoolDir) {
	string spoolDir;
	string sensorDir;
	string timeDir;
	string typeDir;
	spoolDir = substSpoolDir ?
		    substSpoolDir :
		    (opt_cachedir[0] ? opt_cachedir : getSpoolDir(typeSpoolFile));
	sensorDir = get_sensordir();
	struct tm t = time_r((const time_t*)(&first_packet_time));
	char timeDir_buffer[100];
	if(opt_newdir) {
		snprintf(timeDir_buffer, sizeof(timeDir_buffer), 
			 "%04d-%02d-%02d/%02d/%02d", 
			 t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min);
	} else {
		snprintf(timeDir_buffer, sizeof(timeDir_buffer), 
			 "%04d-%02d-%02d", 
			 t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
	}
	timeDir = timeDir_buffer;
	typeDir = opt_newdir ? getSpoolTypeDir(typeSpoolFile) : "";
	return(spoolDir + (spoolDir.length() ? "/" : "") +
	       sensorDir + (sensorDir.length() ? "/" : "") +
	       timeDir + (timeDir.length() ? "/" : "") +
	       typeDir + (typeDir.length() ? "/" : ""));
}

string 
Call::get_filename(eTypeSpoolFile typeSpoolFile, const char *fileExtension) {
	string extension = fileExtension ? fileExtension : getFileTypeExtension(typeSpoolFile);
	return((type == REGISTER ?
		 intToString(fname_register) :
		 get_fbasename_safe()) + 
	       (extension.length() ? "." : "") + extension);
}

string
Call::get_pathfilename(eTypeSpoolFile typeSpoolFile, const char *fileExtension) {
	string pathname = get_pathname(typeSpoolFile);
	string filename = get_filename(typeSpoolFile, fileExtension);
	return(pathname + (pathname.length() && pathname[pathname.length() - 1] != '/' ? "/" : "") +
	       filename);
}

/* returns name of the directory in format YYYY-MM-DD */
string
Call::dirnamesqlfiles() {
	char sdirname[11];
	struct tm t = time_r((const time_t*)(&first_packet_time));
	snprintf(sdirname, 11, "%04d%02d%02d%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour);
	sdirname[10] = 0;
	string s(sdirname);
	return s;
}


/* add ip adress and port to this call */
int
Call::add_ip_port(in_addr_t sip_src_addr, in_addr_t addr, unsigned short port, pcap_pkthdr *header, char *sessid, char *to, bool iscaller, int *rtpmap, s_sdp_flags sdp_flags) {
	if(this->end_call) {
		return(-1);
	}
 
	if(verbosity >= 4) {
		struct in_addr in;
		in.s_addr = addr;
		printf("call:[%p] ip:[%s] port:[%d] iscaller:[%d]\n", this, inet_ntoa(in), port, iscaller);
	}

	if(ipport_n > 0) {
		if(this->refresh_data_ip_port(addr, port, header, iscaller, rtpmap, sdp_flags)) {
			return 1;
		}
	}
	
	if(sverb.process_rtp) {
		cout << "RTP - add_ip_port: " << inet_ntostring(htonl(addr)) << " / " << port << " " << (iscaller ? "caller" : "called") << endl;
	}

	if(ipport_n == MAX_IP_PER_CALL){
		char tmp[18];
		struct in_addr in;
		in.s_addr = addr;
		strcpy(tmp, inet_ntoa(in));
		syslog(LOG_ERR,"callid [%s]: to much INVITEs in this call [%s:%d], raise MAX_IP_PER_CALL and recompile sniffer", call_id.c_str(), tmp, port);
	}
	// add ip and port
	if(ipport_n >= MAX_IP_PER_CALL){
		return -1;
	}

	this->ip_port[ipport_n].sip_src_addr = sip_src_addr;
	this->ip_port[ipport_n].addr = addr;
	this->ip_port[ipport_n].port = port;
	this->ip_port[ipport_n].iscaller = iscaller;
	this->ip_port[ipport_n].sdp_flags = sdp_flags;
	if(sessid) {
		strncpy(this->ip_port[ipport_n].sessid, sessid, MAXLEN_SDP_SESSID);
	} else {
		this->ip_port[ipport_n].sessid[0] = 0;
	}
	if(to) {
		strncpy(this->ip_port[ipport_n].to, to, MAXLEN_SDP_TO);
	} else {
		this->ip_port[ipport_n].to[0] = 0;
	}
	nullIpPortInfoRtpStream(ipport_n);
	
	memcpy(this->rtpmap[opt_rtpmap_by_callerd ? iscaller : ipport_n], rtpmap, MAX_RTPMAP * sizeof(int));
	ipport_n++;
	return 0;
}

bool 
Call::refresh_data_ip_port(in_addr_t addr, unsigned short port, pcap_pkthdr *header, bool iscaller, int *rtpmap, s_sdp_flags sdp_flags) {
	for(int i = 0; i < ipport_n; i++) {
		if(this->ip_port[i].addr == addr && this->ip_port[i].port == port) {
			// reinit rtpmap
			if(opt_rtpmap_combination) {
				int *rtpmap_src = rtpmap;
				int *rtpmap_dst = this->rtpmap[opt_rtpmap_by_callerd ? iscaller : i];
				for(int i_src = 0; i_src < MAX_RTPMAP - 1; i_src++) {
					if(rtpmap_src[i_src]) {
						int indexEqCodec = -1;
						int indexZero = -1;
						for(int i_dst = 0; i_dst < MAX_RTPMAP - 2; i_dst++) {
							if(!rtpmap_dst[i_dst]) {
								if(indexZero == -1) {
									indexZero = i_dst;
									break;
								}
							} else if(rtpmap_dst[i_dst] / 1000 == rtpmap_src[i_src] / 1000) {
								if(indexEqCodec == -1) {
									indexEqCodec = i_dst;
									break;
								}
							}
						}
						if(indexEqCodec >= 0) {
							rtpmap_dst[indexEqCodec] = rtpmap_src[i_src];
						} else if(indexZero >= 0) {
							rtpmap_dst[indexZero] = rtpmap_src[i_src];
							rtpmap_dst[indexZero + 1] = 0;
						}
					}
				}
			} else {
				memcpy(this->rtpmap[opt_rtpmap_by_callerd ? iscaller : i], rtpmap, MAX_RTPMAP * sizeof(int));
			}
			// force mark bit for reinvite for both direction
			u_int64_t _forcemark_time = header->ts.tv_sec * 1000000ull + header->ts.tv_usec;
			forcemark_lock();
			for(int j = 0; j < 2; j++) {
				forcemark_time[j].push(_forcemark_time);
				/*
				cout << "add forcemark " << _forcemark_time << " forcemarks size " << forcemark_time[j].size() << endl;
				*/
			}
			forcemark_unlock();
			if(sdp_flags != this->ip_port[i].sdp_flags) {
				if(this->ip_port[i].sdp_flags.is_fax) {
					sdp_flags.is_fax = 1;
				}
				this->ip_port[i].sdp_flags = sdp_flags;
				calltable->lock_calls_hash();
				hash_node_call *calls = calltable->hashfind_by_ip_port(addr, port, false);
				if(calls) {
					for(hash_node_call *node_call = calls; node_call != NULL; node_call = node_call->next) {
						node_call->sdp_flags = sdp_flags;
					}
				}
				calltable->unlock_calls_hash();
			}
			return true;
		}
	}
	return false;
}

void
Call::add_ip_port_hash(in_addr_t sip_src_addr, in_addr_t addr, unsigned short port, pcap_pkthdr *header, char *sessid, char *to, bool iscaller, int *rtpmap, s_sdp_flags sdp_flags) {
	if(this->end_call) {
		return;
	}

	if(sessid) {
		int sessidIndex = get_index_by_sessid_to(sessid, to, sip_src_addr);
		if(sessidIndex >= 0) {
			if(this->ip_port[sessidIndex].sip_src_addr == sip_src_addr &&
			   (this->ip_port[sessidIndex].addr != addr ||
			    this->ip_port[sessidIndex].port != port ||
			    this->ip_port[sessidIndex].iscaller != iscaller)) {
				((Calltable*)calltable)->hashRemove(this, ip_port[sessidIndex].addr, ip_port[sessidIndex].port);
				((Calltable*)calltable)->hashAdd(addr, port, header->ts.tv_sec, this, iscaller, 0, sdp_flags);
				if(opt_rtcp) {
					((Calltable*)calltable)->hashRemove(this, ip_port[sessidIndex].addr, ip_port[sessidIndex].port + 1, true);
					if(!sdp_flags.rtcp_mux) {
						((Calltable*)calltable)->hashAdd(addr, port + 1, header->ts.tv_sec, this, iscaller, 1, sdp_flags);
					}
				}
				//cout << "change ip/port for sessid " << sessid << " ip:" << inet_ntostring(htonl(addr)) << "/" << inet_ntostring(htonl(this->ip_port[sessidIndex].addr)) << " port:" << port << "/" <<  this->ip_port[sessidIndex].port << endl;
				if(this->ip_port[sessidIndex].addr != addr ||
				   this->ip_port[sessidIndex].port != port) {
					evDestroyIpPortRtpStream(sessidIndex);
					this->ip_port[sessidIndex].addr = addr;
					this->ip_port[sessidIndex].port = port;
				}
				this->ip_port[sessidIndex].iscaller = iscaller;
			}
			this->refresh_data_ip_port(addr, port, header, iscaller, rtpmap, sdp_flags);
			return;
		}
	}
	if(this->add_ip_port(sip_src_addr, addr, port, header, sessid, to, iscaller, rtpmap, sdp_flags) != -1) {
		((Calltable*)calltable)->hashAdd(addr, port, header->ts.tv_sec, this, iscaller, 0, sdp_flags);
		if(opt_rtcp && !sdp_flags.rtcp_mux) {
			((Calltable*)calltable)->hashAdd(addr, port + 1, header->ts.tv_sec, this, iscaller, 1, sdp_flags);
		}
	}
}

int
Call::get_index_by_ip_port(in_addr_t addr, unsigned short port){
	for(int i = 0; i < ipport_n; i++) {
		if(this->ip_port[i].addr == addr && this->ip_port[i].port == port) {
			// we have found it
			return i;
		}
	}
	// not found
	return -1;
}

int
Call::get_index_by_sessid_to(char *sessid, char *to, in_addr_t sip_src_addr){
	for(int i = 0; i < ipport_n; i++) {
		if(!strncmp(this->ip_port[i].sessid, sessid, MAXLEN_SDP_SESSID) &&
		   !strncmp(this->ip_port[i].to, to, MAXLEN_SDP_TO) &&
		   (!sip_src_addr || sip_src_addr == this->ip_port[i].sip_src_addr)) {
			// we have found it
			return i;
		}
	}
	// not found
	return -1;
}

/* analyze rtcp packet */
bool
Call::read_rtcp(packet_s *packetS, int /*iscaller*/, char enable_save_packet) {

	extern int opt_vlan_siprtpsame;
	if(opt_vlan_siprtpsame && this->vlan >= 0) {
		sll_header *header_sll;
		ether_header *header_eth;
		u_int header_ip_offset;
		int protocol;
		int vlan;
		parseEtherHeader(packetS->dlt, (u_char*)packetS->packet,
				 header_sll, header_eth, header_ip_offset, protocol, &vlan);
		if(vlan != this->vlan) {
			return(false);
		}
	}

	parse_rtcp((char*)packetS->data_(), packetS->datalen, this);
	
	if(enable_save_packet) {
		save_packet(this, packetS, TYPE_RTCP);
	}
	return(true);
}

/* analyze rtp packet */
bool
Call::read_rtp(packet_s *packetS, int iscaller, bool find_by_dest, bool stream_in_multiple_calls, char enable_save_packet, char *ifname) {
 
	extern int opt_vlan_siprtpsame;
	if(packetS->datalen == 12) {
		//Ignoring RTP packets without data
		if (sverb.read_rtp) syslog(LOG_DEBUG,"RTP packet skipped because of its datalen: %i", packetS->datalen);
		return(false);
	}

	if(opt_vlan_siprtpsame && this->vlan >= 0) {
		sll_header *header_sll;
		ether_header *header_eth;
		u_int header_ip_offset;
		int protocol;
		int vlan;
		parseEtherHeader(packetS->dlt, (u_char*)packetS->packet,
				 header_sll, header_eth, header_ip_offset, protocol, &vlan);
		if(vlan != this->vlan) {
			return(false);
		}
	}

	bool record_dtmf = 0;
	bool rtp_read_rslt = false;

	if(first_rtp_time == 0) {
		first_rtp_time = packetS->header_pt->ts.tv_sec;
	}
	
	//RTP tmprtp; moved to Call structure to avoid creating and destroying class which is not neccessary
	tmprtp.fill((u_char*)packetS->data_(), packetS->datalen, packetS->header_pt, packetS->saddr, packetS->daddr, packetS->source, packetS->dest);
	int curpayload = tmprtp.getPayload();
	
	// chekc if packet is DTMF and saverfc2833 is enabled 
	if(opt_saverfc2833 and curpayload == 101) {
		record_dtmf = 1;
	}
	
	unsigned int curSSRC = tmprtp.getSSRC();
	bool okRTP = (curSSRC != 0 || opt_allow_zerossrc) && tmprtp.getVersion() == 2;
	if(okRTP || this->seenudptl || this->isfax) {
		if(iscaller) {
			last_rtp_a_packet_time = packetS->header_pt->ts.tv_sec;
		} else {
			last_rtp_b_packet_time = packetS->header_pt->ts.tv_sec;
		}
	}
	if(!okRTP) {
		// invalid ssrc or version
		goto end;
	}

	if(opt_dscp && packetS->header_ip_offset) {
		packetS->header_ip_offset = packetS->dataoffset - sizeof(struct iphdr2) - sizeof(udphdr2);
	}

	for(int i = 0; i < ssrc_n; i++) {
		if(rtp[i]->ssrc2 == curSSRC) {
/*
			if(rtp[i]->last_seq == tmprtp.getSeqNum()) {
				//ignore duplicated RTP with the same sequence
				//if(verbosity > 1) printf("ignoring lastseq[%u] seq[%u] saddr[%u] dport[%u]\n", rtp[i]->last_seq, tmprtp.getSeqNum(), packetS->saddr, packetS->dest);
				goto end;
			}
*/

			if(
			    (rtp[i]->saddr == packetS->saddr and rtp[i]->dport == packetS->dest) or (rtp[i]->saddr == packetS->saddr and rtp[i]->sport == packetS->source)
//				or (rtp[i]->daddr == packetS->saddr and rtp[i]->dport == packetS->source)

			   ) {
				//if(verbosity > 1) printf("found seq[%u] saddr[%u] dport[%u]\n", tmprtp.getSeqNum(), packetS->saddr, packetS->dest);
				// found 
				if(opt_dscp) {
					rtp[i]->dscp = packetS->header_ip_()->tos >> 2;
					if(sverb.dscp) {
						cout << "rtpdscp " << (int)(packetS->header_ip_()->tos>>2) << endl;
					}
				}
				
				// check if codec did not changed but ignore payload 13 and 19 which is CNG and 101 which is DTMF
				int oldcodec = rtp[i]->codec;
				if(curpayload == 13 or curpayload == 19 or rtp[i]->codec == PAYLOAD_TELEVENT or rtp[i]->payload2 == curpayload) {
					goto read;
				} else {
					// check if the stream started with DTMF
					if(rtp[i]->payload2 >= 96 && rtp[i]->payload2 <= 127) {
						for(int j = 0; j < MAX_RTPMAP; j++) {
							if(rtp[i]->rtpmap[j] != 0 && rtp[i]->payload2 == rtp[i]->rtpmap[j] / 1000) {
								if((rtp[i]->rtpmap[j] - rtp[i]->payload2 * 1000) == PAYLOAD_TELEVENT) {
									//it is DTMF 
									rtp[i]->payload2 = curpayload;
									goto read;
								}
							}
						}
					}

					//codec changed, check if it is not DTMF 
					if(curpayload >= 96 && curpayload <= 127) {
						bool found = false;
						for(int j = 0; j < MAX_RTPMAP; j++) {
							if(rtp[i]->rtpmap[j] != 0 && curpayload == rtp[i]->rtpmap[j] / 1000) {
								rtp[i]->codec = rtp[i]->rtpmap[j] - curpayload * 1000;
								found = true;
							}
						}
						if(!found) {
							// dynamic type codec changed but was not negotiated - do not create new RTP stream
							goto end;
						}
					} else {
						rtp[i]->codec = curpayload;
					}
					if(rtp[i]->codec == PAYLOAD_TELEVENT) {
read:
						if(rtp[i]->index_call_ip_port >= 0) {
							evProcessRtpStream(rtp[i]->index_call_ip_port, rtp[i]->index_call_ip_port_by_dest,
									   packetS->saddr, packetS->source, packetS->daddr, packetS->dest, packetS->header_pt->ts.tv_sec);
						}
						if(find_by_dest ?
						    rtp[i]->prev_sport && rtp[i]->prev_sport != packetS->source :
						    rtp[i]->prev_dport && rtp[i]->prev_dport != packetS->dest) {
							rtp[i]->change_src_port = true;
						}
						if(rtp[i]->read((u_char*)packetS->data_(), packetS->datalen, packetS->header_pt, packetS->saddr, packetS->daddr, packetS->source, packetS->dest,
								packetS->sensor_id_(), packetS->sensor_ip, ifname)) {
							rtp_read_rslt = true;
							if(stream_in_multiple_calls) {
								rtp[i]->stream_in_multiple_calls = true;
							}
						}
						rtp[i]->prev_sport = packetS->source;
						rtp[i]->prev_dport = packetS->dest;
						if(rtp[i]->iscaller) {
							lastcallerrtp = rtp[i];
						} else {
							lastcalledrtp = rtp[i];
						}
						goto end;
					} else if(oldcodec != rtp[i]->codec){
						//codec changed and it is not DTMF, reset ssrc so the stream will not match and new one is used
						if(verbosity > 1) printf("mchange [%d] [%d]?\n", rtp[i]->codec, oldcodec);
						rtp[i]->ssrc2 = 0;
					} else {
						//if(verbosity > 1) printf("wtf lastseq[%u] seq[%u] saddr[%u] dport[%u] oldcodec[%u] rtp[i]->codec[%u] rtp[i]->payload2[%u] curpayload[%u]\n", rtp[i]->last_seq, tmprtp.getSeqNum(), packetS->saddr, packetS->dest, oldcodec, rtp[i]->codec, rtp[i]->payload2, curpayload);
					}
				}
			}
		}
	}
	// adding new RTP source
	if(ssrc_n < MAX_SSRC_PER_CALL) {
		// if previouse RTP streams are present it should be filled by silence to keep it in sync
		if(iscaller) {
			last_seq_audiobuffer1 = 0;
			if(lastcallerrtp) {
				lastcallerrtp->jt_tail(packetS->header_pt);
			}
		} else { 
			last_seq_audiobuffer2 = 0;
			if(lastcalledrtp) {
				lastcalledrtp->jt_tail(packetS->header_pt);
			}
		}
		while(__sync_lock_test_and_set(&rtplock, 1)) {
			usleep(100);
		}
		rtp[ssrc_n] = new FILE_LINE(1001) RTP(packetS->sensor_id_(), packetS->sensor_ip);
		rtp[ssrc_n]->call_owner = this;
		rtp[ssrc_n]->ssrc_index = ssrc_n; 
		rtp[ssrc_n]->iscaller = iscaller; 
		rtp[ssrc_n]->find_by_dest = find_by_dest;
		rtp[ssrc_n]->ok_other_ip_side_by_sip = opt_rtpfromsdp_onlysip ||
						       this->type == SKINNY_NEW ||
						       this->checkKnownIP_inSipCallerdIP(find_by_dest ? packetS->saddr : packetS->daddr) ||
						       (this->get_index_by_ip_port(find_by_dest ? packetS->saddr : packetS->daddr, find_by_dest ? packetS->source : packetS->dest) >= 0 &&
							this->checkKnownIP_inSipCallerdIP(find_by_dest ? packetS->daddr : packetS->saddr));
		if(rtp_cur[iscaller]) {
			rtp_prev[iscaller] = rtp_cur[iscaller];
		}
		rtp_cur[iscaller] = rtp[ssrc_n]; 
		
		if(opt_dscp) {
			rtp[ssrc_n]->dscp = packetS->header_ip_()->tos >> 2;
			if(sverb.dscp) {
				cout << "rtpdscp " << (int)(packetS->header_ip_()->tos>>2) << endl;
			}
		}

		char graph_extension[100];
		snprintf(graph_extension, sizeof(graph_extension), "%d.graph%s", ssrc_n, opt_gzipGRAPH == FileZipHandler::gzip ? ".gz" : "");
		string graph_pathfilename = get_pathfilename(tsf_graph, graph_extension);
		strcpy(rtp[ssrc_n]->gfilename, graph_pathfilename.c_str());
		if(flags & FLAG_SAVEGRAPH) {
			rtp[ssrc_n]->graph.auto_open(tsf_graph, graph_pathfilename.c_str());
		}
		if(rtp[ssrc_n]->gfileRAW) {
			fclose(rtp[ssrc_n]->gfileRAW);
			rtp[ssrc_n]->gfileRAW = NULL;
		}
		
		char ird_extension[100];
		snprintf(ird_extension, sizeof(ird_extension), "i%d", !iscaller);
		string ird_pathfilename = get_pathfilename(tsf_audio, ird_extension);
		strncpy(rtp[ssrc_n]->basefilename, ird_pathfilename.c_str(), 1023);
		rtp[ssrc_n]->basefilename[1023] = 0;

		rtp[ssrc_n]->index_call_ip_port = get_index_by_ip_port(find_by_dest ? packetS->daddr : packetS->saddr, find_by_dest ? packetS->dest : packetS->source);
		if(rtp[ssrc_n]->index_call_ip_port >= 0) {
			rtp[ssrc_n]->index_call_ip_port_by_dest = find_by_dest;
			evProcessRtpStream(rtp[ssrc_n]->index_call_ip_port, rtp[ssrc_n]->index_call_ip_port_by_dest, 
					   packetS->saddr, packetS->source, packetS->daddr, packetS->dest, packetS->header_pt->ts.tv_sec);
		}
		if(opt_rtpmap_by_callerd) {
			memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[isFillRtpMap(iscaller) ? iscaller : !iscaller], MAX_RTPMAP * sizeof(int));
		} else {
			if(rtp[ssrc_n]->index_call_ip_port >= 0 && isFillRtpMap(rtp[ssrc_n]->index_call_ip_port)) {
				memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[rtp[ssrc_n]->index_call_ip_port], MAX_RTPMAP * sizeof(int));
			} else {
				for(int j = 0; j < 2; j++) {
					int index_ip_port_first_for_callerd = getFillRtpMapByCallerd(j ? !iscaller : iscaller);
					if(index_ip_port_first_for_callerd >= 0) {
						memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[index_ip_port_first_for_callerd], MAX_RTPMAP * sizeof(int));
						break;
					}
				}
			}
		}

		if(rtp[ssrc_n]->read((u_char*)packetS->data_(), packetS->datalen, packetS->header_pt, packetS->saddr, packetS->daddr, packetS->source, packetS->dest,
				     packetS->sensor_id_(), packetS->sensor_ip, ifname)) {
			rtp_read_rslt = true;
			if(stream_in_multiple_calls) {
				rtp[ssrc_n]->stream_in_multiple_calls = true;
			}
		}
		rtp[ssrc_n]->prev_sport = packetS->source;
		rtp[ssrc_n]->prev_dport = packetS->dest;
		if(sverb.check_is_caller_called) printf("new rtp[%p] ssrc[%x] seq[%u] saddr[%s] dport[%u] iscaller[%u]\n", rtp[ssrc_n], curSSRC, rtp[ssrc_n]->seq, inet_ntostring(htonl(packetS->saddr)).c_str(), packetS->dest, rtp[ssrc_n]->iscaller);
		this->rtp[ssrc_n]->ssrc = this->rtp[ssrc_n]->ssrc2 = curSSRC;
		this->rtp[ssrc_n]->payload2 = curpayload;

		//set codec
                if(curpayload >= 96 && curpayload <= 127) {
                        for(int i = 0; i < MAX_RTPMAP; i++) {
                                if(this->rtp[ssrc_n]->rtpmap[i] != 0 && curpayload == this->rtp[ssrc_n]->rtpmap[i] / 1000) {
                                        this->rtp[ssrc_n]->codec = this->rtp[ssrc_n]->rtpmap[i] - curpayload * 1000;
                                }      
                        }      
                } else {
                        this->rtp[ssrc_n]->codec = curpayload;
                }
		
		if(iscaller) {
			lastcallerrtp = rtp[ssrc_n];
		} else {
			lastcalledrtp = rtp[ssrc_n];
		}
		ssrc_n++;
		__sync_lock_release(&rtplock);
	}
	
end:
	if(enable_save_packet) {
		if((this->silencerecording || (this->flags & FLAG_SAVERTPHEADER)) && !this->isfax && !record_dtmf) {
			if(packetS->datalen >= RTP_FIXED_HEADERLEN &&
			   packetS->header_pt->caplen > (unsigned)(packetS->datalen - RTP_FIXED_HEADERLEN)) {
				unsigned int tmp_u32 = packetS->header_pt->caplen;
				packetS->header_pt->caplen = packetS->header_pt->caplen - (packetS->datalen - RTP_FIXED_HEADERLEN);
				save_packet(this, packetS, TYPE_RTP);
				packetS->header_pt->caplen = tmp_u32;
			}
		} else if((this->flags & FLAG_SAVERTP) || this->isfax || record_dtmf) {
			save_packet(this, packetS, TYPE_RTP);
		}
	}
	return(rtp_read_rslt);
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
	int ssrc_index, codec;
	unsigned long int rawiterator;
	FILE *wav = NULL;
	int adir = 0;
	int bdir = 0;


	// decide which RTP streams should be skipped 
	for(int i = 0; i < ssrc_n; i++) {
		Call *owner = (Call*)rtp[i]->call_owner;
		if(!owner) continue;
		//check for SSRC duplicity  - walk all RTP 
		RTP *A = rtp[i];
		RTP *B = NULL;
		RTP *C = NULL;
		for(int k = 0; owner and k < ssrc_n; k++) {
			B = rtp[k];
			if(!B->had_audio or B->stats.received == 0) {
				if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] codec is comfortnoise received[%u]\n", 
					B->ssrc, inet_ntostring(htonl(B->saddr)).c_str(), B->sport, inet_ntostring(htonl(B->daddr)).c_str(), B->dport, B->iscaller, k, B->stats.received);
				B->skip = true;
			}

			if(A == B or A->skip or B->skip or A->stats.received < 50 or B->stats.received < 50) continue; // do not compare with ourself or already removed RTP or with RTP with <20 packets

			// check if A or B time overlaps - if not we cannot treat it as duplicate stream 
			u_int64_t Astart = A->first_packet_time * 1000000ull + A->first_packet_usec;
			u_int64_t Astop = A->last_pcap_header_ts;
			u_int64_t Bstart = B->first_packet_time * 1000000ull + B->first_packet_usec;
			u_int64_t Bstop = B->last_pcap_header_ts;
			if(((Bstart > Astart) and (Bstart > Astop)) or ((Astart > Bstart) and (Astart > Bstop))) {
				if(verbosity > 1) syslog(LOG_ERR, "Not removing SSRC[%x][%p] and SSRC[%x][%p] %lu %lu\n", A->ssrc, A, B->ssrc, B, Astart, Bstop);
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
						for(int i = 0; i < ssrc_n; i++) {
							C = rtp[i];
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
								B->ssrc, B, inet_ntostring(htonl(B->saddr)).c_str(), B->sport, inet_ntostring(htonl(B->daddr)).c_str(), B->dport, B->iscaller, k);
						} else {
							// test is not true which means that if we remove B there will be no other stream with the B.daddr so we can remove A
							A->skip = true;
							if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x][%p] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 1\n", 
								A->ssrc, A, inet_ntostring(htonl(A->saddr)).c_str(), A->sport, inet_ntostring(htonl(A->daddr)).c_str(), A->dport, A->iscaller, k);
						}
					} else {
						// B.daddr is not in SDP but A.dst is in SDP - but lets check if removing B will not remove all caller/called streams 
						int caller_called = B->iscaller;
						bool test = false;
						for(int i = 0; i < ssrc_n; i++) {
							C = rtp[i];
							if(C == B or C->skip) continue;
							if(C->iscaller == caller_called) {
								test = true;
							}
						}
						if(test) {
							// B can be removed because removing it will still leave some caller/called stream
							B->skip = 1;
							if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 2B\n", 
								B->ssrc, inet_ntostring(htonl(B->saddr)).c_str(), B->sport, inet_ntostring(htonl(B->daddr)).c_str(), B->dport, B->iscaller, k);
						} else {
							// B cannot be removed because the B is the last caller/called stream
							A->skip = 1;
							if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 2A\n", 
								A->ssrc, inet_ntostring(htonl(A->saddr)).c_str(), A->sport, inet_ntostring(htonl(A->daddr)).c_str(), A->dport, A->iscaller, k);
						}
					}
				} else {
					//A.daddr is not in SDP so we can remove that stream 
					A->skip = 1;
					if(verbosity > 1) syslog(LOG_ERR, "Removing stream with SSRC[%x] srcip[%s]:[%u]->[%s]:[%u] iscaller[%u] index[%u] 33\n", 
						A->ssrc, inet_ntostring(htonl(A->saddr)).c_str(), A->sport, inet_ntostring(htonl(A->daddr)).c_str(), A->dport, A->iscaller, k);
				}
			}
		}
	}

	if(!(flags & FLAG_FORMATAUDIO_OGG)) {
		strncpy(out, get_pathfilename(tsf_audio, "wav").c_str(), sizeof(out));
	} else {
		strncpy(out, get_pathfilename(tsf_audio, "ogg").c_str(), sizeof(out));
	}
	out[sizeof(out) - 1] = 0;

	/* caller direction */
	strncpy(rawInfo, get_pathfilename(tsf_audio, "i0.rawInfo").c_str(), sizeof(rawInfo));
	rawInfo[sizeof(rawInfo) - 1] = 0;
	pl = fopen(rawInfo, "r");
	if(pl) {
		while(fgets(line, sizeof(line), pl)) {
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			if(ssrc_index >= ssrc_n || !rtp[ssrc_index] || rtp[ssrc_index]->skip) continue;
			adir = 1;
			strncpy(wav0, get_pathfilename(tsf_audio, "i0.wav").c_str(), sizeof(wav0));
			wav0[sizeof(wav0) - 1] = 0;
			break;
		}
		fclose(pl);
	}

	/* called direction */
	strncpy(rawInfo, get_pathfilename(tsf_audio, "i1.rawInfo").c_str(), sizeof(rawInfo));
	rawInfo[sizeof(rawInfo) - 1] = 0;
	pl = fopen(rawInfo, "r");
	if(pl) {
		while(fgets(line, sizeof(line), pl)) {
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv1.tv_sec, &tv1.tv_usec);
			if(ssrc_index >= ssrc_n || !rtp[ssrc_index] || rtp[ssrc_index]->skip) continue;
			bdir = 1;
			strncpy(wav1, get_pathfilename(tsf_audio, "i1.wav").c_str(), sizeof(wav1));
			wav1[sizeof(wav1) - 1] = 0;
			break;
		}
		fclose(pl);
	}

	if(adir == 0 && bdir == 0) {
		syslog(LOG_ERR, "PCAP file %s cannot be decoded to WAV probably missing RTP\n", get_pathfilename(tsf_sip).c_str());
		return 1;
	}

	/* do synchronisation - calculate difference between start of both RTP direction and put silence to achieve proper synchronisation */
	if(adir && bdir) {
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
				system(cmd);
				break;
			case PAYLOAD_ISAC16:
				samplerate = 16000;
				break;
			case PAYLOAD_ISAC32:
				samplerate = 32000;
				break;
			case PAYLOAD_XOPUS8:
			case PAYLOAD_OPUS8:
				samplerate = 8000;
				break;
			case PAYLOAD_XOPUS12:
			case PAYLOAD_OPUS12:
				samplerate = 12000;
				break;
			case PAYLOAD_XOPUS16:
			case PAYLOAD_OPUS16:
				samplerate = 16000;
				break;
			case PAYLOAD_XOPUS24:
			case PAYLOAD_OPUS24:
				samplerate = 24000;
				system(cmd);
				break;
			case PAYLOAD_XOPUS48:
			case PAYLOAD_OPUS48:
				samplerate = 48000;
				system(cmd);
				break;
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
		strncpy(rawInfo, get_pathfilename(tsf_audio, rawinfo_extension).c_str(), sizeof(rawInfo));
		rawInfo[sizeof(rawInfo) - 1] = 0;
		pl = fopen(rawInfo, "r");
		while(fgets(line, 256, pl)) {
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			char raw_extension[1024];
			snprintf(raw_extension, sizeof(raw_extension), "i%d.%d.%lu.%d.%ld.%ld.raw", i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);
			string raw_pathfilename = this->get_pathfilename(tsf_audio, raw_extension);
			samplerate = 1000 * get_ticks_bycodec(codec);
			if(codec == PAYLOAD_G722) samplerate = 1000 * 16;
			if(maxsamplerate < samplerate) {
				maxsamplerate = samplerate;
			}
		}
		fclose(pl);
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
		strncpy(rawInfo, get_pathfilename(tsf_audio, rawinfo_extension).c_str(), sizeof(rawInfo));
		rawInfo[sizeof(rawInfo) - 1] = 0;
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
		/* 
			read rawInfo file where there are stored raw files (rtp streams) 
			if any of such stream has same SSRC as previous stream and it starts at the same time with 500ms tolerance that stream is eliminated (it is probably duplicate stream)
		*/
		while(fgets(line, 256, pl)) {
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			char raw_extension[1024];
			snprintf(raw_extension, sizeof(raw_extension), "i%d.%d.%lu.%d.%ld.%ld.raw", i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);
			string raw_pathfilename = this->get_pathfilename(tsf_audio, raw_extension);
			samplerate = 1000 * get_ticks_bycodec(codec);
			if(codec == PAYLOAD_G722) samplerate = 1000 * 16;
			if(ssrc_index >= ssrc_n ||
			   last_ssrc_index >= (unsigned)ssrc_n) {
				syslog(LOG_NOTICE, "ignoring rtp stream - bad ssrc_index[%i] or last_ssrc_index[%i] ssrc_n[%i]; call [%s] stream[%s] ssrc[%x] ssrc/last[%x]", 
				       ssrc_index, last_ssrc_index, 
				       ssrc_n, fbasename, raw_pathfilename.c_str(), 
				       ssrc_index >= ssrc_n ? 0 : rtp[ssrc_index]->ssrc,
				       last_ssrc_index >= (unsigned)ssrc_n ? 0 : rtp[last_ssrc_index]->ssrc);
				if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
			} else {
				struct raws_t rawl;
				rawl.ssrc_index = ssrc_index;
				rawl.rawiterator = rawiterator;
				rawl.tv.tv_sec = tv0.tv_sec;
				rawl.tv.tv_usec = tv0.tv_usec;
				rawl.codec = codec;
				rawl.filename = raw_pathfilename.c_str();
				if(iter > 0) {
					if(rtp[ssrc_index]->ssrc == rtp[last_ssrc_index]->ssrc and
						  abs(ast_tvdiff_ms(tv0, lasttv)) < 200 and
						  last_size > 10000) {
						// ignore this raw file it is duplicate 
						if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
						if(verbosity > 1) syslog(LOG_NOTICE, "A ignoring duplicate stream [%s] ssrc[%x] ssrc[%x] ast_tvdiff_ms(lasttv, tv0)=[%d]", raw_pathfilename.c_str(), rtp[last_ssrc_index]->ssrc, rtp[ssrc_index]->ssrc, ast_tvdiff_ms(lasttv, tv0));
					} else {
						if(rtp[rawl.ssrc_index]->skip) {
							if(verbosity > 1) syslog(LOG_NOTICE, "B ignoring duplicate stream [%s] ssrc[%x] ssrc[%x] ast_tvdiff_ms(lasttv, tv0)=[%d]", raw_pathfilename.c_str(), rtp[last_ssrc_index]->ssrc, rtp[ssrc_index]->ssrc, ast_tvdiff_ms(lasttv, tv0));
							if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
						} else {
							raws.push_back(rawl);
						}
					}
				} else {
					if(!rtp[rawl.ssrc_index]->skip) {
						raws.push_back(rawl);
					} else {
						if(!sverb.noaudiounlink) unlink(raw_pathfilename.c_str());
						if(verbosity > 1) syslog(LOG_NOTICE, "C ignoring duplicate stream [%s] ssrc[%x] ssrc[%x] ast_tvdiff_ms(lasttv, tv0)=[%d]", raw_pathfilename.c_str(), rtp[last_ssrc_index]->ssrc, rtp[ssrc_index]->ssrc, ast_tvdiff_ms(lasttv, tv0));
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

		for (std::list<raws_t>::const_iterator rawf = raws.begin(), end = raws.end(); rawf != end; ++rawf) {
			switch(rawf->codec) {
			case PAYLOAD_PCMA:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMA to WAV ssrc[%x] wav[%s] index[%u]\n", rtp[rawf->ssrc_index]->ssrc, wav, rawf->ssrc_index);
				convertALAW2WAV(rawf->filename.c_str(), wav, maxsamplerate);
				samplerate = 8000;
				break;
			case PAYLOAD_PCMU:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMU to WAV ssrc[%x] wav[%s] index[%u]\n", rtp[rawf->ssrc_index]->ssrc, wav, rawf->ssrc_index);
				convertULAW2WAV(rawf->filename.c_str(), wav, maxsamplerate);
				samplerate = 8000;
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
					snprintf(cmd, cmd_len, "vmcodecs %s ilbc \"%s\" \"%s\"", opt_keycheck, rawf->filename.c_str(), wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-ilbc \"%s\" \"%s\"", rawf->filename.c_str(), wav);
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
			default:
				syslog(LOG_ERR, "Call [%s] cannot be converted to WAV because the codec [%s][%d] is not supported.\n", rawf->filename.c_str(), codec2text(rawf->codec), rawf->codec);
			}
			if(!sverb.noaudiounlink) unlink(rawf->filename.c_str());
		}
		if(!sverb.noaudiounlink) unlink(rawInfo);
	}

	if(opt_mos_lqo and adir == 1 and flags & FLAG_RUNAMOSLQO and (samplerate == 8000 or samplerate == 16000)) {
		a_mos_lqo = mos_lqo(wav0, samplerate);
	}
	if(opt_mos_lqo and bdir == 1 and flags & FLAG_RUNBMOSLQO and (samplerate == 8000 or samplerate == 16000)) {
		b_mos_lqo = mos_lqo(wav1, samplerate);
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
	return 0;
}

size_t write_data(char *ptr, size_t size, size_t nmemb, void *userdata) {
	std::ostringstream *stream = (std::ostringstream*)userdata;
	size_t count = size * nmemb;
	stream->write(ptr, count);
	return count;
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveToDb(bool enableBatchIfPossible) {
 
	if(lastSIPresponseNum && nocdr_for_last_responses_count) {
		for(int i = 0; i < nocdr_for_last_responses_count; i++) {
			int lastSIPresponseNum_left = lastSIPresponseNum;
			int lastSIPresponseNum_length = log10(lastSIPresponseNum) + 1;
			while(lastSIPresponseNum_length > nocdr_for_last_responses_length[i]) {
				lastSIPresponseNum_left /= 10;
				--lastSIPresponseNum_length;
			}
			if(lastSIPresponseNum_left == nocdr_for_last_responses[i]) {
				return(0);
			}
		}
	}
 
	if(!sqlDbSaveCall) {
		sqlDbSaveCall = createSqlObject();
		sqlDbSaveCall->setEnableSqlStringInContent(true);
	}

	if((opt_cdronlyanswered and !connect_time) or 
		(opt_cdronlyrtp and !ssrc_n)) {
		// skip this CDR 
		return 1;
	}
	
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
		cdr_next.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
		if(enableBatchIfPossible && isSqlDriver("mysql")) {
			string query_str = sqlDbSaveCall->insertQuery(sql_cdr_next_table, cdr_next);
			
			static unsigned int counterSqlStore = 0;
			int storeId = STORE_PROC_ID_CDR_1 + 
				      (opt_mysqlstore_max_threads_cdr > 1 &&
				       sqlStore->getSize(STORE_PROC_ID_CDR_1) > 1000 ? 
					counterSqlStore % opt_mysqlstore_max_threads_cdr : 
					0);
			++counterSqlStore;
			sqlStore->query_lock(query_str.c_str(), storeId);
		} else {
			sqlDbSaveCall->insert(sql_cdr_next_table, cdr_next);
		}
		return(0);
	}

	SqlDb_row cdr,
			cdr_next,
			cdr_next_ch[CDR_NEXT_MAX],
			cdr_country_code,
			/*
			cdr_phone_number_caller,
			cdr_phone_number_called,
			cdr_name,
			cdr_domain_caller,
			cdr_domain_called,
			*/
			cdr_sip_response,
			cdr_reason_sip,
			cdr_reason_q850,
			cdr_ua_a,
			cdr_ua_b;
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

	string query_str_cdrproxy;
	if(opt_cdrproxy) {
		set<unsigned int> proxies_undup;
		this->proxies_undup(&proxies_undup);
		set<unsigned int>::iterator iter_undup = proxies_undup.begin();
		while(iter_undup != proxies_undup.end()) {
			if(*iter_undup == sipcalledip[0]) { ++iter_undup; continue; };
			SqlDb_row cdrproxy;
			cdrproxy.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
			cdrproxy.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
			cdrproxy.add(htonl(*iter_undup), "dst");
			query_str_cdrproxy += sqlDbSaveCall->insertQuery("cdr_proxy", cdrproxy) + ";\n";
			++iter_undup;
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

	if(useSensorId > -1) {
		cdr.add(useSensorId, "id_sensor");
	}

	cdr.add(sqlEscapeString(caller), "caller");
	cdr.add(sqlEscapeString(reverseString(caller).c_str()), "caller_reverse");
	cdr.add(sqlEscapeString(called), "called");
	cdr.add(sqlEscapeString(reverseString(called).c_str()), "called_reverse");
	cdr.add(sqlEscapeString(caller_domain), "caller_domain");
	cdr.add(sqlEscapeString(called_domain), "called_domain");
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
	
	cdr_sip_response.add(sqlEscapeString(lastSIPresponse), "lastSIPresponse");
	if(existsColumns.cdr_reason) {
		if(reason_sip_text.length()) {
			cdr_reason_sip.add(1, "type");
			cdr_reason_sip.add(sqlEscapeString(reason_sip_text.c_str()), "reason");
		}
		if(reason_q850_text.length()) {
			cdr_reason_q850.add(2, "type");
			cdr_reason_q850.add(sqlEscapeString(reason_q850_text.c_str()), "reason");
		}
	}

	unsigned int dscp_a = caller_sipdscp,
		     dscp_b = called_sipdscp,
		     dscp_c = 0,
		     dscp_d = 0;
	
	u_int32_t sipcalledip_confirmed;
	u_int16_t sipcalledport_confirmed;
	sipcalledip_confirmed = getSipcalledipConfirmed(&sipcalledport_confirmed);
	
	cdr.add(htonl(sipcallerip[0]), "sipcallerip");
	cdr.add(htonl(sipcalledip_confirmed ? sipcalledip_confirmed : sipcalledip[0]), "sipcalledip");
	if(existsColumns.cdr_sipport) {
		cdr.add(sipcallerport, "sipcallerport");
		cdr.add(sipcalledport_confirmed ? sipcalledport_confirmed : sipcalledport, "sipcalledport");
	}
	cdr.add(duration(), "duration");
	if(progress_time) {
		cdr.add(progress_time - first_packet_time, "progress_time");
	}
	if(first_rtp_time) {
		cdr.add(first_rtp_time  - first_packet_time, "first_rtp_time");
	}
	if(connect_time) {
		cdr.add(duration() - (connect_time - first_packet_time), "connect_duration");
	}
	if(existsColumns.cdr_last_rtp_from_end) {
		if(last_rtp_a_packet_time) {
			cdr.add(last_packet_time - last_rtp_a_packet_time, "a_last_rtp_from_end");
		}
		if(last_rtp_b_packet_time) {
			cdr.add(last_packet_time - last_rtp_b_packet_time, "b_last_rtp_from_end");
		}
	}
	cdr.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
	if(opt_callend) {
		cdr.add(sqlEscapeString(sqlDateTimeString(calltime() + duration()).c_str()), "callend");
	}
	
	cdr_next.add(sqlEscapeString(fbasename), "fbasename");
	if(!geoposition.empty()) {
		cdr_next.add(sqlEscapeString(geoposition), "GeoPosition");
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
	if(existsColumns.cdr_response_time && this->first_invite_time_usec) {
		if(this->first_response_100_time_usec) {
			cdr.add(MIN(65535, round((this->first_response_100_time_usec - this->first_invite_time_usec) / 1000.0)), "response_time_100");
		}
		if(this->first_response_xxx_time_usec) {
			cdr.add(MIN(65535, round((this->first_response_xxx_time_usec - this->first_invite_time_usec) / 1000.0)), "response_time_xxx");
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
	} else if(oneway && chantype != CHAN_SKINNY) {
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
		cdr_next.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
	}
	
	if(custom_headers_cdr) {
		custom_headers_cdr->prepareSaveRows_cdr(this, &cdr_next, cdr_next_ch, cdr_next_ch_name);
	}

	if(whohanged == 0 || whohanged == 1) {
		cdr.add(whohanged ? "callee" : "caller", "whohanged");
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
			cr = custPnCache->getCustomerByPhoneNumber(called);
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
	
	if(ssrc_n > 0) {
	 
		this->applyRtcpXrDataToRtp();
	 
		// sort all RTP streams by received packets + loss packets descend and save only those two with the biggest received packets.
		int indexes[MAX_SSRC_PER_CALL];
		// init indexex
		for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
			indexes[i] = i;
		}
		// bubble sort
		for(int k = 0; k < ssrc_n; k++) {
			for(int j = 0; j < ssrc_n; j++) {
				if((rtp[indexes[k]]->stats.received + rtp[indexes[k]]->stats.lost) > ( rtp[indexes[j]]->stats.received + rtp[indexes[j]]->stats.lost)) {
					int kTmp = indexes[k];
					indexes[k] = indexes[j];
					indexes[j] = kTmp;
				}
			}
		}

		// find first caller and first called
		RTP *rtpab[2] = {NULL, NULL};
		bool rtpab_ok[2] = {false, false};
		bool pass_rtpab_simple = opt_rtpfromsdp_onlysip || this->type == SKINNY_NEW;
		for(int pass_rtpab = 0; pass_rtpab < (pass_rtpab_simple ? 1 : 2); pass_rtpab++) {
			for(int k = 0; k < ssrc_n; k++) {
				if(pass_rtpab == 0) {
					if(sverb.process_rtp || sverb.read_rtp) {
						cout << "RTP - final stream: " 
						     << hex << rtp[indexes[k]]->ssrc << dec << " : "
						     << inet_ntostring(htonl(rtp[indexes[k]]->saddr)) << " -> "
						     << inet_ntostring(htonl(rtp[indexes[k]]->daddr)) << " / "
						     << (rtp[indexes[k]]->iscaller ? "caller" : "called") 
						     << " packets received: " << rtp[indexes[k]]->s->received << " "
						     << " ssrc index: " << rtp[indexes[k]]->ssrc_index << " "
						     << endl;
					}
				}
				if(pass_rtpab_simple || rtp[indexes[k]]->ok_other_ip_side_by_sip || pass_rtpab == 1) {
					if(!rtpab_ok[0] &&
					   rtp[indexes[k]]->iscaller && 
					   (!rtpab[0] || rtp[indexes[k]]->stats.received > rtpab[0]->stats.received)) {
						rtpab[0] = rtp[indexes[k]];
					}
					if(!rtpab_ok[1] &&
					   !rtp[indexes[k]]->iscaller && 
					   (!rtpab[1] || rtp[indexes[k]]->stats.received > rtpab[1]->stats.received)) {
						rtpab[1] = rtp[indexes[k]];
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
			string cneg = i == 0 ? "b" : "a";
			
			cdr.add(rtpab[i]->ssrc_index, c+"_index");
			cdr.add(rtpab[i]->stats.received + 2, c+"_received"); // received is always 2 packet less compared to wireshark (add it here)
			lost[i] = rtpab[i]->stats.lost;
			cdr.add(lost[i], c+"_lost");
			packet_loss_perc_mult1000[i] = (int)round((double)rtpab[i]->stats.lost / 
									(rtpab[i]->stats.received + 2 + rtpab[i]->stats.lost) * 100 * 1000);
			cdr.add(packet_loss_perc_mult1000[i], c+"_packet_loss_perc_mult1000");
			jitter_mult10[i] = ceil(rtpab[i]->stats.avgjitter * 10);
			cdr.add(jitter_mult10[i], c+"_avgjitter_mult10");
			cdr.add(int(ceil(rtpab[i]->stats.maxjitter)), c+"_maxjitter");
			payload[i] = rtpab[i]->first_codec;
			cdr.add(payload[i], c+"_payload");
			
			// build a_sl1 - b_sl10 fields
			for(int j = 1; j < 11; j++) {
				char str_j[3];
				sprintf(str_j, "%d", j);
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
			cdr.add(htonl(rtpab[i]->saddr), c+"_saddr");

			// calculate MOS score for fixed 50ms 
			double burstr, lossr;
			burstr_calculate(rtpab[i]->channel_fix1, rtpab[i]->stats.received, &burstr, &lossr, 0);
			//int mos_f1_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			int mos_f1_mult10 = (int)rtpab[i]->mosf1_avg;
			cdr.add(mos_f1_mult10, c+"_mos_f1_mult10");
			if(mos_f1_mult10) {
				mos_min_mult10[i] = mos_f1_mult10;
			}
			if(existsColumns.cdr_mos_min and rtpab[i]->mosf1_min != (uint8_t)-1) {
				cdr.add(rtpab[i]->mosf1_min, c+"_mos_f1_min_mult10");
			}

			if(existsColumns.cdr_mos_xr and rtpab[i]->rtcp_xr.counter > 0) {
				cdr.add(rtpab[i]->rtcp_xr.minmos, c+"_mos_xr_min_mult10");
				cdr.add(rtpab[i]->rtcp_xr.avgmos, c+"_mos_xr_mult10");
			}

			// calculate MOS score for fixed 200ms 
			burstr_calculate(rtpab[i]->channel_fix2, rtpab[i]->stats.received, &burstr, &lossr, 0);
			//int mos_f2_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			int mos_f2_mult10 = (int)round(rtpab[i]->mosf2_avg);
			cdr.add(mos_f2_mult10, c+"_mos_f2_mult10");
			if(mos_f2_mult10 && (mos_min_mult10[i] < 0 || mos_f2_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_f2_mult10;
			}
			if(existsColumns.cdr_mos_min and rtpab[i]->mosf2_min != (uint8_t)-1) {
				cdr.add(rtpab[i]->mosf2_min, c+"_mos_f2_min_mult10");
			}

			// calculate MOS score for adaptive 500ms 
			burstr_calculate(rtpab[i]->channel_adapt, rtpab[i]->stats.received, &burstr, &lossr, 0);
			//int mos_adapt_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			int mos_adapt_mult10 = (int)round(rtpab[i]->mosAD_avg);
			cdr.add(mos_adapt_mult10, c+"_mos_adapt_mult10");
			if(mos_adapt_mult10 && (mos_min_mult10[i] < 0 || mos_adapt_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_adapt_mult10;
			}
			if(existsColumns.cdr_mos_min and rtpab[i]->mosAD_min != (uint8_t)-1) {
				cdr.add(rtpab[i]->mosAD_min, c+"_mos_adapt_min_mult10");
			}

			if(mos_f2_mult10 && opt_mosmin_f2) {
				mos_min_mult10[i] = mos_f2_mult10;
			}
			
			if(mos_min_mult10[i] >= 0) {
				cdr.add(mos_min_mult10[i], c+"_mos_min_mult10");
			}

			if(rtpab[i]->rtcp.counter) {
				cdr.add(rtpab[i]->rtcp.loss, cneg+"_rtcp_loss");
				cdr.add(rtpab[i]->rtcp.maxfr, cneg+"_rtcp_maxfr");
				rtcp_avgfr_mult10[i] = (int)round(rtpab[i]->rtcp.avgfr * 10);
				cdr.add(rtcp_avgfr_mult10[i], cneg+"_rtcp_avgfr_mult10");
				cdr.add(rtpab[i]->rtcp.maxjitter / get_ticks_bycodec(rtpab[i]->first_codec), cneg+"_rtcp_maxjitter");
				rtcp_avgjitter_mult10[i] = (int)round(rtpab[i]->rtcp.avgjitter / get_ticks_bycodec(rtpab[i]->first_codec) * 10);
				cdr.add(rtcp_avgjitter_mult10[i], cneg+"_rtcp_avgjitter_mult10");
			}
			if(existsColumns.cdr_rtp_ptime) {
				cdr.add(rtpab[i]->avg_ptime, c+"_rtp_ptime");
			}

		}
		if(seenudptl && !not_acceptable) {
			// T.38
			cdr.add(1000, "payload");
		} else if(isfax == 2 && !not_acceptable) {
			// T.30
			cdr.add(1001, "payload");
		} else if(payload[0] >= 0 || payload[1] >= 0) {
			cdr.add(payload[0] >= 0 ? payload[0] : payload[1], "payload");
		}

		if(jitter_mult10[0] >= 0 || jitter_mult10[1] >= 0) {
			cdr.add(max(jitter_mult10[0], jitter_mult10[1]), 
				"jitter_mult10");
		}
		if(mos_min_mult10[0] >= 0 || mos_min_mult10[1] >= 0) {
			cdr.add(mos_min_mult10[0] >= 0 && mos_min_mult10[1] >= 0 ?
					min(mos_min_mult10[0], mos_min_mult10[1]) :
					(mos_min_mult10[0] >= 0 ? mos_min_mult10[0] : mos_min_mult10[1]),
				"mos_min_mult10");
		}
		if(packet_loss_perc_mult1000[0] >= 0 || packet_loss_perc_mult1000[1] >= 0) {
			cdr.add(max(packet_loss_perc_mult1000[0], packet_loss_perc_mult1000[1]), 
				"packet_loss_perc_mult1000");
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

		for(int i = 0; i < ssrc_n; i++) {
			if(rtp[i]->change_src_port) {
				cdr_flags |= rtp[i]->iscaller ? CDR_CHANGE_SRC_PORT_CALLER : CDR_CHANGE_SRC_PORT_CALLED;
			}
		}
	}

	if(opt_dscp && existsColumns.cdr_dscp) {
		cdr.add((dscp_a << 24) + (dscp_b << 16) + (dscp_c << 8) + dscp_d, "dscp");
	}
	
	if(cdr_flags && existsColumns.cdr_flags) {
		cdr.add(cdr_flags, "flags");
	}
	
	if(getSpoolIndex() && existsColumns.cdr_next_spool_index) {
		cdr_next.add(getSpoolIndex(), "spool_index");
	}
	
	CountryDetectApplyReload();
	cdr_country_code.add(getCountryByIP(htonl(sipcallerip[0])), "sipcallerip_country_code");
	cdr_country_code.add(getCountryByIP(htonl(sipcalledip[0])), "sipcalledip_country_code");
	cdr_country_code.add(getCountryByPhoneNumber(caller), "caller_number_country_code");
	cdr_country_code.add(getCountryByPhoneNumber(called), "called_number_country_code");
	if(existsColumns.cdr_country_code_calldate) {
		cdr_country_code.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
	}
	
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		
		query_str += string("set @lSresp_id = ") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ");\n";
		cdr.add("_\\_'SQL'_\\_:@lSresp_id", "lastSIPresponse_id");
		//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
		if(existsColumns.cdr_reason) {
			if(reason_sip_text.length()) {
				query_str += string("set @r_sip_tid = ") + "getIdOrInsertREASON(1," + sqlEscapeStringBorder(reason_sip_text.c_str()) + ");\n";
				cdr.add("_\\_'SQL'_\\_:@r_sip_tid", "reason_sip_text_id");
				//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertREASON(1," + sqlEscapeStringBorder(reason_sip_text.c_str()) + ")", "reason_sip_text_id");
			}
			if(reason_q850_text.length()) {
				query_str += string("set @r_q850_tid = ") + "getIdOrInsertREASON(1," + sqlEscapeStringBorder(reason_q850_text.c_str()) + ");\n";
				cdr.add("_\\_'SQL'_\\_:@r_q850_tid", "reason_q850_text_id");
				//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertREASON(2," + sqlEscapeStringBorder(reason_q850_text.c_str()) + ")", "reason_q850_text_id");
			}
		}
		if(opt_cdr_ua_enable) {
			if(a_ua[0]) {
				query_str += string("set @uaA_id = ") +  "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ");\n";
				cdr.add("_\\_'SQL'_\\_:@uaA_id", "a_ua_id");
				//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
			}
			if(b_ua[0]) {
				query_str += string("set @uaB_id = ") +  "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ");\n";
				cdr.add("_\\_'SQL'_\\_:@uaB_id", "b_ua_id");
				//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
			}
		}
		
		extern bool opt_cdr_check_exists_callid;
		extern bool opt_cdr_check_duplicity_callid_in_next_pass_insert;
		if(opt_cdr_check_exists_callid ||
		   opt_cdr_check_duplicity_callid_in_next_pass_insert) {
			// check if exists call-id & rtp records - begin if
			if(opt_cdr_check_exists_callid) {
				query_str += string("set @exists_call_id = coalesce(\n") +
					     "(select cdr_ID from cdr_next\n" +
					     " where calldate > ('" + sqlDateTimeString(calltime()) + "' - interval 1 hour) and\n" +
					     "       calldate < ('" + sqlDateTimeString(calltime()) + "' + interval 1 hour) and\n" +
					     "       fbasename = '" + sqlEscapeString(fbasename) + "' limit 1), 0);\n";
				query_str += string("set @exists_rtp =\n") +
					     "if(@exists_call_id,\n" +
					     "   exists (select * from cdr_rtp where cdr_id = @exists_call_id),\n" +
					     "   0);\n";
				bool existsRtp = false;
				for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
					if(rtp[i] and rtp[i]->s->received) {
						existsRtp = true;
						break;
					}
				}
				query_str += string("if @exists_call_id and not @exists_rtp and ") + (existsRtp ? "1" : "0") + " then\n" +
					     "  delete from cdr where id = @exists_call_id;\n" +
					     "  delete from cdr_next where cdr_id = @exists_call_id;\n";
				if(custom_headers_cdr) {
					query_str += custom_headers_cdr->getDeleteQuery("@exists_call_id", "  ", ";\n");
				}
				query_str += string("  delete from cdr_country_code where cdr_id = @exists_call_id;\n") +
					     "  delete from cdr_rtp where cdr_id = @exists_call_id;\n" +
					     (opt_dbdtmf ? "  delete from cdr_dtmf where cdr_id = @exists_call_id;\n" : "") +
					     "  delete from cdr_sipresp where cdr_id = @exists_call_id;\n" +
					     (opt_pcap_dump_tar ? "  delete from cdr_tar_part where cdr_id = @exists_call_id;\n" : "") +
					     "  set @exists_call_id = 0;\n" +
					     "end if;\n";
				query_str += "if not @exists_call_id then\n";
			} else if(opt_cdr_check_duplicity_callid_in_next_pass_insert) {
				query_str += "__NEXT_PASS_QUERY_BEGIN__";
				query_str += string("set @exists_call_id = coalesce(\n") +
					     "(select cdr_ID from cdr_next\n" +
					     " where calldate > ('" + sqlDateTimeString(calltime()) + "' - interval 1 minute) and\n" +
					     "       calldate < ('" + sqlDateTimeString(calltime()) + "' + interval 1 minute) and\n" +
					     "       fbasename = '" + sqlEscapeString(fbasename) + "' limit 1), 0);\n";
				query_str += "if not @exists_call_id then\n";
				query_str += "__NEXT_PASS_QUERY_END__";
			}
		}
		
		query_str += sqlDbSaveCall->insertQuery(sql_cdr_table, cdr) + ";\n";
		
		query_str += "if row_count() > 0 then\n";
		query_str += "set @cdr_id = last_insert_id();\n";
		
		cdr_next.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
		query_str += sqlDbSaveCall->insertQuery(sql_cdr_next_table, cdr_next) + ";\n";
		
		bool existsNextCh = false;
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(cdr_next_ch_name[i][0]) {
				cdr_next_ch[i].add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
				query_str += sqlDbSaveCall->insertQuery(cdr_next_ch_name[i], cdr_next_ch[i]) + ";\n";
				existsNextCh = true;
			}
		}
		if(existsNextCh && custom_headers_cdr) {
			string queryForSaveUseInfo = custom_headers_cdr->getQueryForSaveUseInfo(this);
			if(!queryForSaveUseInfo.empty()) {
				query_str += queryForSaveUseInfo + ";\n";
			}
		}
		
		cdr_country_code.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
		query_str += sqlDbSaveCall->insertQuery("cdr_country_code", cdr_country_code) + ";\n";

		if(sql_cdr_table_last30d[0] ||
		   sql_cdr_table_last7d[0] ||
		   sql_cdr_table_last1d[0]) {
			cdr.add("_\\_'SQL'_\\_:@cdr_id", "ID");
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

		for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
			// lets check whole array as there can be holes due rtp[0] <=> rtp[1] swaps in mysql rutine
			if(rtp[i] and (rtp[i]->s->received or !existsColumns.cdr_rtp_index or (rtp[i]->s->received == 0 and rtp_zeropackets_stored == false))) {
				if(rtp[i]->s->received == 0 and rtp_zeropackets_stored == false) rtp_zeropackets_stored = true;
				double stime = this->first_packet_time + this->first_packet_usec / 1000000.0;
				double rtime = rtp[i]->first_packet_time + rtp[i]->first_packet_usec / 1000000.0;
				double diff = rtime - stime;

				SqlDb_row rtps;
				rtps.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
				if(rtp[i]->first_codec == -1) {
					//do not store this stream into the database
					continue;
				}
				rtps.add(rtp[i]->first_codec, "payload");
				rtps.add(htonl(rtp[i]->saddr), "saddr");
				rtps.add(htonl(rtp[i]->daddr), "daddr");
				if(existsColumns.cdr_rtp_sport) {
					rtps.add(rtp[i]->sport, "sport");
				}
				if(existsColumns.cdr_rtp_dport) {
					rtps.add(rtp[i]->dport, "dport");
				}
				rtps.add(rtp[i]->ssrc, "ssrc");
				rtps.add(rtp[i]->s->received + 2, "received");
				rtps.add(rtp[i]->stats.lost, "loss");
				rtps.add((unsigned int)(rtp[i]->stats.maxjitter * 10), "maxjitter_mult10");
				rtps.add(diff, "firsttime");
				if(existsColumns.cdr_rtp_index) {
					rtps.add(i + 1, "index");
				}
				if(existsColumns.cdr_rtp_flags) {
					u_int64_t flags = 0;
					if(rtp[i]->stream_in_multiple_calls) {
						flags |= 1;
					}
					if(flags) {
						rtps.add(flags, "flags");
					}
				}
				if(existsColumns.cdr_rtp_calldate) {
					rtps.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDbSaveCall->insertQuery("cdr_rtp", rtps) + ";\n";
			}
		}

		if(opt_dbdtmf) {
			while(dtmf_history.size()) {
				s_dtmf q;
				q = dtmf_history.front();
				dtmf_history.pop();

				SqlDb_row dtmf;
				string tmp;
				tmp = q.dtmf;
				dtmf.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
				dtmf.add(q.saddr, "saddr");
				dtmf.add(q.daddr, "daddr");
				dtmf.add(tmp, "dtmf");
				dtmf.add(q.ts, "firsttime");
				if(existsColumns.cdr_dtmf_type) {
					dtmf.add(q.type, "type");
				}
				if(existsColumns.cdr_dtmf_calldate) {
					dtmf.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDbSaveCall->insertQuery("cdr_dtmf", dtmf) + ";\n";
			}
		}

		extern bool opt_cdr_sipresp;	
		if(opt_cdr_sipresp) {	
			for(list<sSipResponse>::iterator iterSiprespUnique = SIPresponseUnique.begin(); iterSiprespUnique != SIPresponseUnique.end(); iterSiprespUnique++) {
				SqlDb_row sipresp;
				sipresp.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
				sipresp.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(iterSiprespUnique->SIPresponse.c_str()) + ")", "SIPresponse_id");
				sipresp.add(iterSiprespUnique->SIPresponseNum, "SIPresponseNum");
				if(existsColumns.cdr_sipresp_calldate) {
					sipresp.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDbSaveCall->insertQuery("cdr_sipresp", sipresp) + ";\n";
			}
		}
		
		if(_save_sip_history) {
			for(list<sSipHistory>::iterator iterSiphistory = SIPhistory.begin(); iterSiphistory != SIPhistory.end(); iterSiphistory++) {
				SqlDb_row siphist;
				siphist.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
				siphist.add((u_int64_t)(iterSiphistory->time - (first_packet_time * 1000000ull + first_packet_usec)), "time");
				if(iterSiphistory->SIPrequest.length()) {
					 siphist.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPREQUEST(" + sqlEscapeStringBorder(iterSiphistory->SIPrequest.c_str()) + ")", "SIPrequest_id");
				}
				if(iterSiphistory->SIPresponseNum && iterSiphistory->SIPresponse.length()) {
					 siphist.add(iterSiphistory->SIPresponseNum, "SIPresponseNum");
					 siphist.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(iterSiphistory->SIPresponse.c_str()) + ")", "SIPresponse_id");
				}
				if(existsColumns.cdr_siphistory_calldate) {
					siphist.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDbSaveCall->insertQuery("cdr_siphistory", siphist) + ";\n";
			}
		}
		
		if(opt_pcap_dump_tar) {
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
					tar_part.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
					tar_part.add(i, "type");
					tar_part.add(*it, "pos");
					if(existsColumns.cdr_dtmf_calldate) {
						tar_part.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
					}
					query_str += sqlDbSaveCall->insertQuery("cdr_tar_part", tar_part) + ";\n";
				}
			}
		}
		
		query_str += "end if";
		
		if(opt_cdr_check_exists_callid ||
		   opt_cdr_check_duplicity_callid_in_next_pass_insert) {
			// check if exists call-id & rtp records - end if
			if(opt_cdr_check_exists_callid) {
				query_str += ";\nend if";
			} else if(opt_cdr_check_duplicity_callid_in_next_pass_insert) {
				query_str += "__NEXT_PASS_QUERY_BEGIN__";
				query_str += ";\nend if";
				query_str += "__NEXT_PASS_QUERY_END__";
			}
		}
		
		static unsigned int counterSqlStore = 0;
		int storeId = STORE_PROC_ID_CDR_1 + 
			      (opt_mysqlstore_max_threads_cdr > 1 &&
			       sqlStore->getSize(STORE_PROC_ID_CDR_1) > 1000 ? 
				counterSqlStore % opt_mysqlstore_max_threads_cdr : 
				0);
		++counterSqlStore;
		sqlStore->query_lock(query_str.c_str(), storeId);
		
		//cout << endl << endl << query_str << endl << endl << endl;
		return(0);
	}

	/*
	caller_id = sqlDb->getIdOrInsert("cdr_phone_number", "id", "number", cdr_phone_number_caller);
	called_id = sqlDb->getIdOrInsert("cdr_phone_number", "id", "number", cdr_phone_number_called);
	callername_id = sqlDb->getIdOrInsert("cdr_name", "id", "name", cdr_name);
	caller_domain_id = sqlDb->getIdOrInsert("cdr_domain", "id", "domain", cdr_domain_caller);
	called_domain_id = sqlDb->getIdOrInsert("cdr_domain", "id", "domain", cdr_domain_called);
	*/
	lastSIPresponse_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_sip_response_table, "id", "lastSIPresponse", cdr_sip_response);
	if(existsColumns.cdr_reason) {
		if(reason_sip_text.length()) {
			reason_sip_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_reason_table, "id", "reason", cdr_reason_sip, "type");
		}
		if(reason_q850_text.length()) {
			reason_q850_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_reason_table, "id", "reason", cdr_reason_q850, "type");
		}
	}
	if(a_ua[0]) {
		cdr_ua_a.add(sqlEscapeString(a_ua), "ua");
		a_ua_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_a);
	}
	if(b_ua[0]) {
		cdr_ua_b.add(sqlEscapeString(b_ua), "ua");
		b_ua_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_b);
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
	
	int cdrID = sqlDbSaveCall->insert(sql_cdr_table, cdr);
	if (is_read_from_file_simple()) {
		ostringstream outStr;
		outStr << "Found new call. Added to db with cdr.ID:" << cdrID ;
		cout << outStr.str() << endl;
	}

	if(cdrID > 0) {

		if(opt_cdrproxy) {
			set<unsigned int> proxies_undup;
			this->proxies_undup(&proxies_undup);
			set<unsigned int>::iterator iter_undup = proxies_undup.begin();
			while(iter_undup != proxies_undup.end()) {
				SqlDb_row cdrproxy;
				cdrproxy.add(cdrID, "cdr_ID");
				cdrproxy.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				cdrproxy.add(htonl(*iter_undup), "dst");
				sqlDbSaveCall->insert("cdr_proxy", cdrproxy);
				++iter_undup;
			}
		}

		for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
			// lets check whole array as there can be holes due rtp[0] <=> rtp[1] swaps in mysql rutine
			if(rtp[i] and (rtp[i]->s->received or (rtp[i]->s->received == 0 and rtp_zeropackets_stored == false))) {
				if(rtp[i]->s->received == 0 and rtp_zeropackets_stored == false) rtp_zeropackets_stored = true;
				double fpart = this->first_packet_usec;
				while(fpart > 1) fpart /= 10;
				double stime = this->first_packet_time + fpart;

				fpart = rtp[i]->first_packet_usec;
				while(fpart > 1) fpart /= 10;
				double rtime = rtp[i]->first_packet_time + fpart;

				double diff = rtime - stime;

				if(rtp[i]->first_codec == -1) {
					//do not store this stream into the database
					continue;
				}

				SqlDb_row rtps;
				rtps.add(cdrID, "cdr_ID");
				rtps.add(rtp[i]->first_codec, "payload");
				rtps.add(htonl(rtp[i]->saddr), "saddr");
				rtps.add(htonl(rtp[i]->daddr), "daddr");
				if(existsColumns.cdr_rtp_sport) {
					rtps.add(rtp[i]->sport, "sport");
				}
				if(existsColumns.cdr_rtp_dport) {
					rtps.add(rtp[i]->dport, "dport");
				}
				rtps.add(rtp[i]->ssrc, "ssrc");
				rtps.add(rtp[i]->s->received + 2, "received");
				rtps.add(rtp[i]->stats.lost, "loss");
				rtps.add((unsigned int)(rtp[i]->stats.maxjitter * 10), "maxjitter_mult10");
				rtps.add(diff, "firsttime");
				if(existsColumns.cdr_rtp_index) {
					rtps.add(i + 1, "index");
				}
				if(existsColumns.cdr_rtp_flags) {
					u_int64_t flags = 0;
					if(rtp[i]->stream_in_multiple_calls) {
						flags |= 1;
					}
					if(flags) {
						rtps.add(flags, "flags");
					}
				}
				if(existsColumns.cdr_rtp_calldate) {
					rtps.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				sqlDbSaveCall->insert("cdr_rtp", rtps);
			}
		}

		if(opt_dbdtmf) {
			while(dtmf_history.size()) {
				s_dtmf q;
				q = dtmf_history.front();
				dtmf_history.pop();

				SqlDb_row dtmf;
				string tmp;
				tmp = q.dtmf;
				dtmf.add(cdrID, "cdr_ID");
				dtmf.add(q.saddr, "saddr");
				dtmf.add(q.daddr, "daddr");
				dtmf.add(tmp, "dtmf");
				dtmf.add(q.ts, "firsttime");
				if(existsColumns.cdr_dtmf_type) {
					dtmf.add(q.type, "type");
				}
				if(existsColumns.cdr_dtmf_calldate) {
					dtmf.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				sqlDbSaveCall->insert("cdr_dtmf", dtmf);
			}
		}
		
		for(list<sSipResponse>::iterator iterSiprespUnique = SIPresponseUnique.begin(); iterSiprespUnique != SIPresponseUnique.end(); iterSiprespUnique++) {
			SqlDb_row sipresp;
			sipresp.add(cdrID, "cdr_ID");
			SqlDb_row _resp;
			_resp.add(iterSiprespUnique->SIPresponse, "lastSIPresponse");
			sipresp.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_sip_response_table, "id", "lastSIPresponse", _resp), "SIPresponse_id");
			sipresp.add(iterSiprespUnique->SIPresponseNum, "SIPresponseNum");
			if(existsColumns.cdr_sipresp_calldate) {
				sipresp.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
			}
			sqlDbSaveCall->insert("cdr_sipresp", sipresp);
		}

		if(_save_sip_history) {
			for(list<sSipHistory>::iterator iterSiphistory = SIPhistory.begin(); iterSiphistory != SIPhistory.end(); iterSiphistory++) {
				SqlDb_row siphist;
				siphist.add(cdrID, "cdr_ID");
				siphist.add((u_int64_t)(iterSiphistory->time - (first_packet_time * 1000000ull + first_packet_usec)), "time");
				if(iterSiphistory->SIPrequest.length()) {
					 SqlDb_row _req;
					 _req.add(iterSiphistory->SIPrequest, "request");
					 siphist.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_sip_request_table, "id", "request", _req), "SIPrequest_id");
				}
				if(iterSiphistory->SIPresponseNum && iterSiphistory->SIPresponse.length()) {
					 siphist.add(iterSiphistory->SIPresponseNum, "SIPresponseNum");
					 SqlDb_row _resp;
					 _resp.add(iterSiphistory->SIPresponse, "lastSIPresponse");
					 siphist.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_sip_response_table, "id", "lastSIPresponse", _resp), "SIPresponse_id");
				}
				if(existsColumns.cdr_siphistory_calldate) {
					siphist.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				sqlDbSaveCall->insert("cdr_siphistory", siphist);
			}
		}
		
		if(opt_printinsertid) {
			printf("CDRID:%d\n", cdrID);
		}

		cdr_next.add(cdrID, "cdr_ID");
		sqlDbSaveCall->insert(sql_cdr_next_table, cdr_next);
		
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(cdr_next_ch_name[i][0]) {
				cdr_next_ch[i].add(cdrID, "cdr_ID");
				sqlDbSaveCall->insert(cdr_next_ch_name[i], cdr_next_ch[i]);
			}
		}
		
		cdr_country_code.add(cdrID, "cdr_ID");
		sqlDbSaveCall->insert("cdr_country_code", cdr_country_code);
		
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
			where calldate > '" + sqlDateTimeString(calltime() - 60 * 60) + "' and \
			      fbasename = '" + fbasename + "' \
			limit 1)";
	if(enableBatchIfPossible) {
		static unsigned int counterSqlStore = 0;
		int storeId = STORE_PROC_ID_CDR_1 + 
			      (opt_mysqlstore_max_threads_cdr > 1 &&
			       sqlStore->getSize(STORE_PROC_ID_CDR_1) > 1000 ? 
				counterSqlStore % opt_mysqlstore_max_threads_cdr : 
				0);
		++counterSqlStore;
		sqlStore->query_lock(updateFlagsQuery.c_str(), storeId);
	} else {
		sqlDbSaveCall->query(updateFlagsQuery);
	}
	
	return(0);
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveRegisterToDb(bool enableBatchIfPossible) {
 
	if(this->msgcount <= 1 or 
	   this->lastSIPresponseNum == 401 or this->lastSIPresponseNum == 403 or this->lastSIPresponseNum == 404) {
		this->regstate = 2;
	}
	
	if(sqlStore->getSizeVect(STORE_PROC_ID_REGISTER_1, 
				 STORE_PROC_ID_REGISTER_1 + 
				 (opt_mysqlstore_max_threads_register > 1 ? opt_mysqlstore_max_threads_register - 1 : 0)) > opt_mysqlstore_limit_queue_register) {
		static u_long lastTimeSyslog = 0;
		u_long actTime = getTimeMS();
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

	SqlDb_row cdr_ua;
	if(a_ua[0]) {
		cdr_ua.add(sqlEscapeString(a_ua), "ua");
	}

	unsigned int now = time(NULL);

	string qp;
	
	static unsigned int counterSqlStore = 0;
	int storeId = STORE_PROC_ID_REGISTER_1 + 
		      (opt_mysqlstore_max_threads_register > 1 &&
		       sqlStore->getSize(STORE_PROC_ID_REGISTER_1) > 1000 ? 
			counterSqlStore % opt_mysqlstore_max_threads_register : 
			0);
	++counterSqlStore;

	if(last_register_clean == 0) {
		// on first run the register table has to be deleted 
		if(enableBatchIfPossible && isTypeDb("mysql")) {
			qp += "DELETE FROM register";
			sqlStore->query_lock(qp.c_str(), storeId);
		} else {
			sqlDbSaveCall->query("DELETE FROM register");
		}
		last_register_clean = now;
	} else if((last_register_clean + REGISTER_CLEAN_PERIOD) < now){
		// last clean was done older than CLEAN_PERIOD seconds
		string calldate_str = sqlDateTimeString(calltime());

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
			sqlStore->query_lock(qp.c_str(), storeId);
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
			char ips[32];
			char ipd[32];
			char tmpregstate[32];
			char regexpires[32];
			char idsensor[12];
			char rrddiff[12];
			//char srcmac[24];
			snprintf(ips, 31, "%u", htonl(sipcallerip[0]));
			ips[31] = 0;
			snprintf(ipd, 31, "%u", htonl(sipcalledip[0]));
			ipd[31] = 0;
			snprintf(tmpregstate, 31, "%d", regstate);
			tmpregstate[31] = 0;
			snprintf(regexpires, 31, "%d", register_expires);
			regexpires[31] = 0;
			snprintf(idsensor, 11, "%d", useSensorId);
			idsensor[11] = 0;
			snprintf(rrddiff, 11, "%d", regrrddiff);
			rrddiff[11] = 0;
			//snprintf(srcmac, 23, "%lu", regsrcmac);
			//srcmac[23] = 0;

			//stored procedure is much faster and eliminates latency reducing uuuuuuuuuuuuu

			query = "CALL PROCESS_SIP_REGISTER(" + sqlEscapeStringBorder(sqlDateTimeString(calltime())) + ", " +
				sqlEscapeStringBorder(caller) + "," +
				sqlEscapeStringBorder(callername) + "," +
				sqlEscapeStringBorder(caller_domain) + "," +
				sqlEscapeStringBorder(called) + "," +
				sqlEscapeStringBorder(called_domain) + ",'" +
				ips + "','" +
				ipd + "'," +
				sqlEscapeStringBorder(contact_num) + "," +
				sqlEscapeStringBorder(contact_domain) + "," +
				sqlEscapeStringBorder(digest_username) + "," +
				sqlEscapeStringBorder(digest_realm) + ",'" +
				tmpregstate + "'," +
				sqlEscapeStringBorder(sqlDateTimeString(calltime() + register_expires).c_str()) + ",'" + //mexpires_at
				regexpires + "', " +
				sqlEscapeStringBorder(a_ua) + ", " +
				sqlEscapeStringBorder(intToString(fname_register)) + ", " +
				idsensor;
				//srcmac ;
			if (existsColumns.register_rrd_count) {
				query = query + ", " +
				rrddiff +
				")";
			} else {
				query = query + ")";
			}
			sqlStore->query_lock(query.c_str(), storeId);
		} else {
			if (existsColumns.register_rrd_count) {
				query = string(
					"SELECT ID, state, rrd_avg, rrd_count, ") +
					       "UNIX_TIMESTAMP(expires_at) AS expires_at, " +
					       "_LC_[(UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(" + sqlEscapeStringBorder(sqlDateTimeString(calltime())) + "))] AS expired " +
					"FROM " + register_table + " " +
					"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND to_domain = " + sqlEscapeStringBorder(called_domain) + " AND " +
					      "contact_num = " + sqlEscapeStringBorder(contact_num) + " AND contact_domain = " + sqlEscapeStringBorder(contact_domain) + 
					      //" AND digestusername = " + sqlEscapeStringBorder(digest_username) + " " +
					"ORDER BY ID DESC"; // LIMIT 1 
	//			if(verbosity > 2) cout << query << "\n";
			} else {
				query = string(
					"SELECT ID, state, ") +
					       "UNIX_TIMESTAMP(expires_at) AS expires_at, " +
					       "_LC_[(UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(" + sqlEscapeStringBorder(sqlDateTimeString(calltime())) + "))] AS expired " +
					"FROM " + register_table + " " +
					"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND to_domain = " + sqlEscapeStringBorder(called_domain) + " AND " +
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
						reg.add(htonl(sipcallerip[0]), "sipcallerip");
						reg.add(htonl(sipcalledip[0]), "sipcalledip");
						reg.add(sqlEscapeString(caller), "from_num");
						reg.add(sqlEscapeString(called), "to_num");
						reg.add(sqlEscapeString(called_domain), "to_domain");
						reg.add(sqlEscapeString(contact_num), "contact_num");
						reg.add(sqlEscapeString(contact_domain), "contact_domain");
						reg.add(sqlEscapeString(digest_username), "digestusername");
						reg.add(register_expires, "expires");
						reg.add(5, "state");
						reg.add(intToString(fname_register), "fname");
						reg.add(useSensorId, "id_sensor");
						reg.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
						sqlDbSaveCall->insert("register_state", reg);
					}

					if(atoi(rsltRow["state"].c_str()) != regstate || register_expires == 0) {
						// state changed or device unregistered, store to register_state
						SqlDb_row reg;
						reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "created_at");
						reg.add(htonl(sipcallerip[0]), "sipcallerip");
						reg.add(htonl(sipcalledip[0]), "sipcalledip");
						reg.add(sqlEscapeString(caller), "from_num");
						reg.add(sqlEscapeString(called), "to_num");
						reg.add(sqlEscapeString(called_domain), "to_domain");
						reg.add(sqlEscapeString(contact_num), "contact_num");
						reg.add(sqlEscapeString(contact_domain), "contact_domain");
						reg.add(sqlEscapeString(digest_username), "digestusername");
						reg.add(register_expires, "expires");
						reg.add(regstate, "state");
						reg.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
						reg.add(intToString(fname_register), "fname");
						reg.add(useSensorId, "id_sensor");
						sqlDbSaveCall->insert("register_state", reg);
					}
				} else {
					// REGISTER message is new, store it to register_state
					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "created_at");
					reg.add(htonl(sipcallerip[0]), "sipcallerip");
					reg.add(htonl(sipcalledip[0]), "sipcalledip");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(called), "to_num");
					reg.add(sqlEscapeString(called_domain), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					reg.add(register_expires, "expires");
					reg.add(regstate, "state");
					reg.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
					reg.add(intToString(fname_register), "fname");
					reg.add(useSensorId, "id_sensor");
					sqlDbSaveCall->insert("register_state", reg);
				}

				// save successfull REGISTER to register table in case expires is not negative
				if(register_expires > 0) {


					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
					reg.add(htonl(sipcallerip[0]), "sipcallerip");
					reg.add(htonl(sipcalledip[0]), "sipcalledip");
					//reg.add(sqlEscapeString(fbasename), "fbasename");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(callername), "from_name");
					reg.add(sqlEscapeString(caller_domain), "from_domain");
					reg.add(sqlEscapeString(called), "to_num");
					reg.add(sqlEscapeString(called_domain), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					reg.add(sqlEscapeString(digest_realm), "digestrealm");
					reg.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
					reg.add(register_expires, "expires");
					reg.add(sqlEscapeString(sqlDateTimeString(calltime() + register_expires).c_str()), "expires_at");
					reg.add(intToString(fname_register), "fname");
					reg.add(useSensorId, "id_sensor");
					reg.add(regstate, "state");
					//reg.add(srcmac, "src_mac");

					if (existsColumns.register_rrd_count) {
						char rrdavg[12];
						char rrdcount[4];
						snprintf(rrdavg, 11, "%d", rrd_avg);
						snprintf(rrdcount, 3, "%d", rrd_count);
						rrdavg[11] = 0;
						rrdcount[3] = 0;
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
			ssipcallerip << htonl(sipcallerip[0]);
			stringstream ssipcalledip;
			ssipcalledip << htonl(sipcalledip[0]);

			unsigned int count = 1;
			int res = regfailedcache->check(htonl(sipcallerip[0]), htonl(sipcalledip[0]), calltime(), &count);
			if(res) {
				break;
			}

			stringstream cnt;
			cnt << count;

			string calldate_str = sqlDateTimeString(calltime());

			string q1 = string(
				"SELECT counter FROM register_failed ") +
				"WHERE sipcallerip = " + ssipcallerip.str() + " AND sipcalledip = " + ssipcalledip.str() + 
				" AND created_at >= SUBTIME('" + calldate_str + "', '01:00:00') LIMIT 1";

			string q2 = string(
				"UPDATE register_failed SET created_at = '" + calldate_str + "', fname = " + sqlEscapeStringBorder(intToString(fname_register)) + ", counter = counter + " + cnt.str()) +
				", to_num = " + sqlEscapeStringBorder(called) + ", from_num = " + sqlEscapeStringBorder(called) + ", digestusername = " + sqlEscapeStringBorder(digest_username) +
				"WHERE sipcallerip = " + ssipcallerip.str() + " AND sipcalledip = " + ssipcalledip.str() + 
				" AND created_at >= SUBTIME('" + calldate_str + "', '01:00:00')";

			SqlDb_row reg;
			reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "created_at");
			reg.add(htonl(sipcallerip[0]), "sipcallerip");
			reg.add(htonl(sipcalledip[0]), "sipcalledip");
			reg.add(sqlEscapeString(caller), "from_num");
			reg.add(sqlEscapeString(called), "to_num");
			reg.add(sqlEscapeString(called_domain), "to_domain");
			reg.add(sqlEscapeString(contact_num), "contact_num");
			reg.add(sqlEscapeString(contact_domain), "contact_domain");
			reg.add(sqlEscapeString(digest_username), "digestusername");

			//reg.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "ua_id");
			reg.add("_\\_'SQL'_\\_:@ua_id", "ua_id");

			reg.add(intToString(fname_register), "fname");
			if(useSensorId > -1) {
				reg.add(useSensorId, "id_sensor");
			}
			string q3 = string("set @ua_id = ") +  "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ");\n";
			q3 += sqlDbSaveCall->insertQuery("register_failed", reg);

			string query = "SET @mcounter = (" + q1 + ");";
			query += "IF @mcounter IS NOT NULL THEN " + q2 + "; ELSE " + q3 + "; END IF";

			sqlStore->query_lock(query.c_str(), storeId);
		} else {
			string calldate_str = sqlDateTimeString(calltime());
			query = string(
				"SELECT counter FROM register_failed ") +
				"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND to_domain = " + sqlEscapeStringBorder(called_domain) + 
					" AND digestusername = " + sqlEscapeStringBorder(digest_username) + " AND created_at >= SUBTIME('" + calldate_str+ "', '01:00:00')";
			if(sqlDbSaveCall->query(query)) {
				SqlDb_row rsltRow = sqlDbSaveCall->fetchRow();
				if(rsltRow) {
					// there is already failed register, update counter and do not insert
					string query = string(
						"UPDATE register_failed SET created_at = '" + calldate_str+ "', fname = " + sqlEscapeStringBorder(intToString(fname_register)) + ", counter = counter + 1 ") +
						"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND digestusername = " + sqlEscapeStringBorder(digest_username) + 
							" AND created_at >= SUBTIME('" + calldate_str+ "', '01:00:00');";
					sqlDbSaveCall->query(query);
				} else {
					// this is new failed attempt within hour, insert
					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "created_at");
					reg.add(htonl(sipcallerip[0]), "sipcallerip");
					reg.add(htonl(sipcalledip[0]), "sipcalledip");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(called), "to_num");
					reg.add(sqlEscapeString(called_domain), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					reg.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
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
 
	if(!sqlDbSaveCall) {
		sqlDbSaveCall = createSqlObject();
		sqlDbSaveCall->setEnableSqlStringInContent(true);
	}
	
	adjustUA();

	SqlDb_row msg,
			msg_next_ch[CDR_NEXT_MAX],
			msg_country_code,
			m_contenttype,
			cdr_sip_response,
			cdr_ua_a,
			cdr_ua_b;
	char _msg_next_ch_name[CDR_NEXT_MAX][100];
	char *msg_next_ch_name[CDR_NEXT_MAX];
	for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
		_msg_next_ch_name[i][0] = 0;
		msg_next_ch_name[i] = _msg_next_ch_name[i];
	}

	string query_str_messageproxy;

	if(opt_messageproxy) {
		set<unsigned int> proxies_undup;
		this->proxies_undup(&proxies_undup);
		set<unsigned int>::iterator iter_undup = proxies_undup.begin();
		while (iter_undup != proxies_undup.end()) {
			if(*iter_undup == sipcalledip[0]) { ++iter_undup; continue; };
			SqlDb_row messageproxy;
			messageproxy.add("_\\_'SQL'_\\_:@msg_id", "message_ID");
			messageproxy.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
			messageproxy.add(htonl(*iter_undup), "dst");
			query_str_messageproxy += sqlDbSaveCall->insertQuery("message_proxy", messageproxy) + ";\n";
			++iter_undup;
		}
	}
	
	if(useSensorId > -1) {
		msg.add(useSensorId, "id_sensor");
	}
	msg.add(sqlEscapeString(caller), "caller");
	msg.add(sqlEscapeString(reverseString(caller).c_str()), "caller_reverse");
	msg.add(sqlEscapeString(called), "called");
	msg.add(sqlEscapeString(reverseString(called).c_str()), "called_reverse");
	msg.add(sqlEscapeString(caller_domain), "caller_domain");
	msg.add(sqlEscapeString(called_domain), "called_domain");
	msg.add(sqlEscapeString(callername), "callername");
	msg.add(sqlEscapeString(reverseString(callername).c_str()), "callername_reverse");

	cdr_sip_response.add(sqlEscapeString(lastSIPresponse), "lastSIPresponse");

	msg.add(htonl(sipcallerip[0]), "sipcallerip");
	msg.add(htonl(sipcalledip[0]), "sipcalledip");
	msg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
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

	msg.add(lastSIPresponseNum, "lastSIPresponseNum");
	
	if(existsColumns.message_response_time && this->first_message_time_usec) {
		if(this->first_response_200_time_usec) {
			msg.add(MIN(65535, round((this->first_response_200_time_usec - this->first_message_time_usec) / 1000.0)), "response_time");
		}
	}

	if(getSpoolIndex() && existsColumns.message_spool_index) {
		msg.add(getSpoolIndex(), "spool_index");
	}

	if(custom_headers_message) {
		custom_headers_message->prepareSaveRows_message(this, &msg, msg_next_ch, msg_next_ch_name);
	}

	CountryDetectApplyReload();
	msg_country_code.add(getCountryByIP(htonl(sipcallerip[0])), "sipcallerip_country_code");
	msg_country_code.add(getCountryByIP(htonl(sipcalledip[0])), "sipcalledip_country_code");
	msg_country_code.add(getCountryByPhoneNumber(caller), "caller_number_country_code");
	msg_country_code.add(getCountryByPhoneNumber(called), "called_number_country_code");
	msg_country_code.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
	
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		
		msg.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
		if(a_ua[0]) {
			query_str += string("set @uaA_id = ") +  "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ");\n";
			msg.add("_\\_'SQL'_\\_:@uaA_id", "a_ua_id");
			//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
		}
		if(b_ua[0]) {
			query_str += string("set @uaB_id = ") +  "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ");\n";
			msg.add("_\\_'SQL'_\\_:@uaB_id", "b_ua_id");
			//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
		}
		if(contenttype) {
			query_str += string("set @cntt_id = ") +  "getIdOrInsertCONTENTTYPE(" + sqlEscapeStringBorder(contenttype) + ");\n";
			msg.add("_\\_'SQL'_\\_:@cntt_id", "id_contenttype");
			//cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertCONTENTTYPE(" + sqlEscapeStringBorder(contenttype) + ")", "id_contenttype");
		}
		
		extern bool opt_message_check_duplicity_callid_in_next_pass_insert;
		if(opt_message_check_duplicity_callid_in_next_pass_insert) {
			// check if exists call-id - begin if
			query_str += "__NEXT_PASS_QUERY_BEGIN__";
			query_str += string("set @exists_call_id = coalesce(\n") +
				     "(select ID from message\n" +
				     " where calldate > ('" + sqlDateTimeString(calltime()) + "' - interval 1 minute) and\n" +
				     "       calldate < ('" + sqlDateTimeString(calltime()) + "' + interval 1 minute) and\n" +
				     "       fbasename = '" + sqlEscapeString(fbasename) + "' limit 1), 0);\n";
			query_str += "if not @exists_call_id then\n";
			query_str += "__NEXT_PASS_QUERY_END__";
		}
		
		query_str += sqlDbSaveCall->insertQuery("message", msg) + ";\n";

		query_str += "if row_count() > 0 then\n";
		query_str += "set @msg_id = last_insert_id();\n";
		
		bool existsNextCh = false;
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(msg_next_ch_name[i][0]) {
				msg_next_ch[i].add("_\\_'SQL'_\\_:@msg_id", "message_ID");
				query_str += sqlDbSaveCall->insertQuery(msg_next_ch_name[i], msg_next_ch[i]) + ";\n";
				existsNextCh = true;
			}
		}
		if(existsNextCh && custom_headers_message) {
			string queryForSaveUseInfo = custom_headers_message->getQueryForSaveUseInfo(this);
			if(!queryForSaveUseInfo.empty()) {
				query_str += queryForSaveUseInfo + ";\n";
			}
		}
		
		msg_country_code.add("_\\_'SQL'_\\_:@msg_id", "message_ID");
		query_str += sqlDbSaveCall->insertQuery("message_country_code", msg_country_code) + ";\n";
		
		query_str += query_str_messageproxy;
		
		query_str += "end if";
		
		if(opt_message_check_duplicity_callid_in_next_pass_insert) {
			// check if exists call-id - end if
			query_str += "__NEXT_PASS_QUERY_BEGIN__";
			query_str += ";\nend if";
			query_str += "__NEXT_PASS_QUERY_END__";
		}
		
		static unsigned int counterSqlStore = 0;
		int storeId = STORE_PROC_ID_MESSAGE_1 + 
			      (opt_mysqlstore_max_threads_message > 1 &&
			       sqlStore->getSize(STORE_PROC_ID_MESSAGE_1) > 1000 ? 
				counterSqlStore % opt_mysqlstore_max_threads_message : 
				0);
		++counterSqlStore;
		sqlStore->query_lock(query_str.c_str(), storeId);
		
		//cout << endl << endl << query_str << endl << endl << endl;
		return(0);
	}
	
	unsigned int 
			lastSIPresponse_id = 0,
			a_ua_id = 0,
			b_ua_id = 0;

	lastSIPresponse_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_sip_response_table, "id", "lastSIPresponse", cdr_sip_response);
	if(a_ua[0]) {
		cdr_ua_a.add(sqlEscapeString(a_ua), "ua");
		a_ua_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_a);
	}
	if(b_ua[0]) {
		cdr_ua_b.add(sqlEscapeString(b_ua), "ua");
		b_ua_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_b);
	}
	if(contenttype && contenttype[0]) {
		m_contenttype.add(sqlEscapeString(contenttype), "contenttype");
		unsigned int id_contenttype = sqlDbSaveCall->getIdOrInsert("contenttype", "id", "contenttype", m_contenttype);
		msg.add(id_contenttype, "id_contenttype");
	}

	msg.add(lastSIPresponse_id, "lastSIPresponse_id", true);
	msg.add(a_ua_id, "a_ua_id", true);
	msg.add(b_ua_id, "b_ua_id", true);

	int msgID = sqlDbSaveCall->insert("message", msg);
	
	if(msgID > 0) {
	
		if(opt_messageproxy) {
			set<unsigned int> proxies_undup;
			this->proxies_undup(&proxies_undup);
			set<unsigned int>::iterator iter_undup = proxies_undup.begin();
			while(iter_undup != proxies_undup.end()) {
				SqlDb_row messageproxy;
				messageproxy.add(msgID, "message_ID");
				messageproxy.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				messageproxy.add(htonl(*iter_undup), "dst");
				sqlDbSaveCall->insert("message_proxy", messageproxy);
				++iter_undup;
			}
		}
		
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(msg_next_ch_name[i][0]) {
				msg_next_ch[i].add(msgID, "message_ID");
				sqlDbSaveCall->insert(msg_next_ch_name[i], msg_next_ch[i]);
			}
		}
	
		msg_country_code.add(msgID, "message_ID");
		sqlDbSaveCall->insert("message_country_code", msg_country_code);
		
	}

	return(msgID <= 0);

}

char *
Call::get_fbasename_safe() {
	strncpy(fbasename_safe, fbasename, MAX_FNAME * sizeof(char));
	prepare_string_to_filename(fbasename_safe);
	return fbasename_safe;
}

/* for debug purpose */
void
Call::dump(){
	//print call_id
	printf("cidl:%lu\n", call_id_len);
	printf("-call dump %p---------------------------------\n", this);
	printf("callid:%s\n", call_id.c_str());
	printf("last packet time:%d\n", (int)get_last_packet_time());
	printf("last SIP response [%d] [%s]\n", lastSIPresponseNum, lastSIPresponse);
	
	// print assigned IP:port 
	if(ipport_n > 0) {
		printf("ipport_n:%d\n", ipport_n);
		for(int i = 0; i < ipport_n; i++) 
			printf("addr: %u, port: %d\n", ip_port[i].addr, ip_port[i].port);
	} else {
		printf("no IP:port assigned\n");
	}
	if(seeninvite) {
		printf("From:%s\n", caller);
		printf("To:%s\n", called);
	}
	printf("First packet: %d, Last packet: %d\n", (int)get_first_packet_time(), (int)get_last_packet_time());
	printf("ssrc_n:%d\n", ssrc_n);
	printf("Call statistics:\n");
	if(ssrc_n > 0) {
		for(int i = 0; i < ssrc_n; i++) {
			rtp[i]->dump();
		}
	}
	printf("-end call dump  %p----------------------------\n", this);
}

void Call::atFinish() {
	if(this->type != INVITE && type != MESSAGE) {
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
		system(source.c_str());
	};
	extern char filtercommand[4092];
	if(filtercommand[0] && this->flags & FLAG_RUNSCRIPT) {
		string source(filtercommand);
		find_and_replace(source, string("%callid%"), escapeShellArgument(this->fbasename));
		find_and_replace(source, string("%dirname%"), escapeShellArgument(this->get_pathname(tsf_sip)));
		find_and_replace(source, string("%calldate%"), escapeShellArgument(sqlDateTimeString(this->calltime())));
		find_and_replace(source, string("%caller%"), escapeShellArgument(this->caller));
		find_and_replace(source, string("%called%"), escapeShellArgument(this->called));
		if(verbosity >= 2) printf("command: [%s]\n", source.c_str());
		system(source.c_str());
	}
}

u_int32_t 
Call::getAllReceivedRtpPackets() {
	u_int32_t receivedPackets = 0;
	for(int i = 0; i < ssrc_n; i++) {
		receivedPackets += rtp[i]->stats.received;
	}
	return(receivedPackets);
}

void 
Call::addTarPos(u_int64_t pos, int type) {
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

void
Call::applyRtcpXrDataToRtp() {
	map<u_int32_t, sRtcpXrDataSsrc>::iterator iter_ssrc;
	for(iter_ssrc = this->rtcpXrData.begin(); iter_ssrc != this->rtcpXrData.end(); iter_ssrc++) {
		for(int i = 0; i < ssrc_n; i++) {
			if(this->rtp[i]->ssrc == iter_ssrc->first) {
				list<sRtcpXrDataItem>::iterator iter;
				for(iter = iter_ssrc->second.begin(); iter != iter_ssrc->second.end(); iter++) {
					if(iter->moslq >= 0 || iter->nlr >= 0) {
						rtp[i]->rtcp_xr.counter++;
						if(iter->moslq >= 0) {
							if(iter->moslq < rtp[i]->rtcp_xr.minmos) {
								rtp[i]->rtcp_xr.minmos = iter->moslq;
							}
							rtp[i]->rtcp_xr.avgmos = (rtp[i]->rtcp_xr.avgmos * (rtp[i]->rtcp_xr.counter - 1) + iter->moslq) / rtp[i]->rtcp_xr.counter;
						} else {
							if(rtp[i]->rtcp_xr.counter > 1) {
								rtp[i]->rtcp_xr.avgmos *= rtp[i]->rtcp_xr.counter / (rtp[i]->rtcp_xr.counter - 1);
							}
						}
						if(iter->nlr >= 0) {
							if(iter->nlr > rtp[i]->rtcp_xr.maxfr) {
								rtp[i]->rtcp_xr.maxfr = iter->nlr;
							}
							rtp[i]->rtcp_xr.avgfr = (rtp[i]->rtcp_xr.avgfr * (rtp[i]->rtcp_xr.counter - 1) + iter->nlr) / rtp[i]->rtcp_xr.counter;
						} else {
							if(rtp[i]->rtcp_xr.counter > 1) {
								rtp[i]->rtcp_xr.avgfr *= rtp[i]->rtcp_xr.counter / (rtp[i]->rtcp_xr.counter - 1);
							}
						}
					}
				}
				break;
			}
		}
	}
}

void Call::adjustUA() {
	if(opt_cdr_ua_reg_remove.size()) {
		if(a_ua[0]) {
			::adjustUA(a_ua);
		}
		if(b_ua[0]) {
			::adjustUA(b_ua);
		}
	}
}

void Call::proxies_undup(set<unsigned int> *proxies_undup) {
	list<unsigned int>::iterator iter = proxies.begin();
	while (iter != proxies.end()) {
		if (proxies_undup->find(*iter) == proxies_undup->end()) {
			proxies_undup->insert(*iter);
		}
		++iter;
	}
}

void Call::createListeningBuffers() {
	pthread_mutex_lock(&listening_worker_run_lock);
	if(audiobuffer1) {
		audiobuffer1->enable();
	} else {
		audiobuffer1 = new FILE_LINE(1005) FifoBuffer((string("audiobuffer1 for call ") + call_id).c_str());
		audiobuffer1->setMinItemBufferLength(1000);
		audiobuffer1->setMaxSize(1000000);
		if(sverb.call_listening) {
			audiobuffer1->setDebugOut("/tmp/audiobuffer1");
		}
	}
	if(audiobuffer2) {
		audiobuffer2->enable();
	} else {
		audiobuffer2 = new FILE_LINE(1006) FifoBuffer((string("audiobuffer2 for call ") + call_id).c_str());
		audiobuffer2->setMinItemBufferLength(1000);
		audiobuffer2->setMaxSize(1000000);
		if(sverb.call_listening) {
			audiobuffer2->setDebugOut("/tmp/audiobuffer2");
		}
	}
	pthread_mutex_unlock(&listening_worker_run_lock);
}

void Call::destroyListeningBuffers() {
	pthread_mutex_lock(&listening_worker_run_lock);
	if(audiobuffer1) {
		delete audiobuffer1;
		audiobuffer1 = NULL;
	}
	if(audiobuffer2) { 
		delete audiobuffer2;
		audiobuffer2 = NULL;
	}
	pthread_mutex_unlock(&listening_worker_run_lock);
}

void Call::disableListeningBuffers() {
	pthread_mutex_lock(&listening_worker_run_lock);
	if(audiobuffer1) {
		audiobuffer1->clean_and_disable();
	}
	if(audiobuffer2) { 
		audiobuffer2->clean_and_disable();
	}
	pthread_mutex_unlock(&listening_worker_run_lock);
}

u_int32_t Call::getSipcalledipConfirmed(u_int16_t *dport) {
	if(dport) {
		*dport = 0;
	}
	u_int32_t saddr = 0, 
		  daddr = 0, 
		  lastsaddr = 0;
	for(list<Call::sInviteSD_Addr>::iterator iter = invite_sdaddr.begin(); iter != invite_sdaddr.end(); iter++) {
		if(iter->confirmed) {
			if((daddr != iter->daddr && saddr != iter->daddr && 
			    lastsaddr != iter->saddr) ||
			   lastsaddr == iter->saddr) {
				if(!saddr) {
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
	return(daddr);
}

void adjustUA(char *ua) {
	if(opt_cdr_ua_reg_remove.size()) {
		bool adjust = false;
		for(unsigned i = 0; i < opt_cdr_ua_reg_remove.size(); i++) {
			vector<string> matches;
			if(reg_match(ua, opt_cdr_ua_reg_remove[i].c_str(), &matches, true, __FILE__, __LINE__)) {
				for(unsigned j = 0; j < matches.size(); j++) {
					char *str_pos = strstr(ua, matches[j].c_str());
					if(str_pos) {
						char ua_temp[1024];
						strncpy(ua_temp, str_pos + matches[j].size(), sizeof(ua_temp));
						strcpy(str_pos, ua_temp);
						adjust = true;
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
				strncpy(ua_temp, ua + start, sizeof(ua_temp));
				strcpy(ua, ua_temp);
			}
		}
	}
}

/* constructor */
Calltable::Calltable() {
	pthread_mutex_init(&qlock, NULL);
	pthread_mutex_init(&qaudiolock, NULL);
	pthread_mutex_init(&qdellock, NULL);
	pthread_mutex_init(&flock, NULL);
	//pthread_mutex_init(&calls_listMAPlock, NULL);
	//pthread_mutex_init(&calls_mergeMAPlock, NULL);
	//pthread_mutex_init(&registers_listMAPlock, NULL);

	memset(calls_hash, 0x0, sizeof(calls_hash));
	_sync_lock_calls_hash = 0;
	_sync_lock_calls_listMAP = 0;
	_sync_lock_calls_mergeMAP = 0;
	_sync_lock_registers_listMAP = 0;
	_sync_lock_calls_queue = 0;
	_sync_lock_calls_audioqueue = 0;
	_sync_lock_calls_deletequeue = 0;
	_sync_lock_registers_queue = 0;
	_sync_lock_registers_deletequeue = 0;
	_sync_lock_files_queue = 0;
	
	extern int opt_audioqueue_threads_max;
	audioQueueThreadsMax = min(max(2l, sysconf( _SC_NPROCESSORS_ONLN ) - 1), (long)opt_audioqueue_threads_max);
	audioQueueTerminating = 0;
};

/* destructor */
Calltable::~Calltable() {
	pthread_mutex_destroy(&qlock);
	pthread_mutex_destroy(&qaudiolock);
	pthread_mutex_destroy(&qdellock);
	pthread_mutex_destroy(&flock);
	//pthread_mutex_destroy(&calls_listMAPlock);
	//pthread_mutex_destroy(&calls_mergeMAPlock);
	//pthread_mutex_destroy(&registers_listMAPlock);
};

/* add node to hash. collisions are linked list of nodes*/
void
Calltable::hashAdd(in_addr_t addr, unsigned short port, long int time_s, Call* call, int iscaller, int is_rtcp, s_sdp_flags sdp_flags) {
 
	if(call->end_call) {
		return;
	}

	if(sverb.hash_rtp) {
		cout << "hashAdd: " 
		     << call->call_id << " " << inet_ntostring(htonl(addr)) << ":" << port << " " 
		     << (is_rtcp ? "rtcp" : "") << " "
		     << endl;
	}
 
	u_int32_t h;
	hash_node *node = NULL;
	hash_node_call *node_call = NULL;

	h = tuplehash(addr, port);
	lock_calls_hash();
	// check if there is not already call in hash 
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			// there is already some call which is receiving packets to the same IP:port
			// this can happen if the old call is waiting for hangup and is still in memory or two SIP different sessions shares the same call.

			int found = 0;
			int count = 0;
			hash_node_call *prev = NULL;
			node_call = (hash_node_call *)node->calls;
			while(node_call != NULL) {
				if(node_call->call->destroy_call_at != 0 &&
				   (node_call->call->seenbye ||
				    node_call->call->lastSIPresponseNum / 10 == 48 ||
				    (time_s != 0 && time_s > node_call->call->destroy_call_at))) {
					if(sverb.hash_rtp) {
						cout << "remove call with destroy_call_at: " 
						     << node_call->call->call_id << " " << inet_ntostring(htonl(addr)) << ":" << port << " " 
						     << endl;
					}
					// remove this call
					if(prev) {
						prev->next = node_call->next;
						--node_call->call->hash_counter;
						delete node_call;
						node_call = prev->next;
						continue;
					} else {
						//removing first node
						node->calls = node->calls->next;
						--node_call->call->hash_counter;
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
			if(count >= opt_sdp_multiplication) {
				static Call *lastcall = NULL;
				// this port/ip combination is already in 3 calls - do not add to 4th to not cause multiplication attack. 
				if(lastcall != call and opt_sdp_multiplication >= 3) {
					/*
					struct in_addr in;
					in.s_addr = addr;
					char *str = inet_ntoa(in);
					syslog(LOG_NOTICE, "call-id[%s] SDP: %s:%u is already in calls [%s] [%s] [%s]. Limit is %u to not cause multiplication DDOS. You can increas it sdp_multiplication = N\n", 
						call->fbasename, str, port,
						node->calls->call->fbasename,
						node->calls->next->call->fbasename,
						node->calls->next->next->call->fbasename,
						opt_sdp_multiplication);
					*/
					lastcall = call;
				}
				unlock_calls_hash();
				return;
			}
			if(!found) {
				// the same ip/port is shared with some other call which is not yet in node - add it
				hash_node_call *node_call_new = new FILE_LINE(1007) hash_node_call;
				node_call_new->next = node->calls;
				node_call_new->call = call;
				node_call_new->iscaller = iscaller;
				node_call_new->is_rtcp = is_rtcp;
				node_call_new->sdp_flags = sdp_flags;

				//insert at first position
				node->calls = node_call_new;
				++call->hash_counter;
				
			}
			unlock_calls_hash();
			return;
		}
	}

	// addr / port combination not found - add it to hash at first position

	node_call = new FILE_LINE(1008) hash_node_call;
	node_call->next = NULL;
	node_call->call = call;
	node_call->iscaller = iscaller;
	node_call->is_rtcp = is_rtcp;
	node_call->sdp_flags = sdp_flags;

	node = new FILE_LINE(1009) hash_node;
	memset(node, 0x0, sizeof(hash_node));
	node->addr = addr;
	node->port = port;
	node->next = (hash_node *)calls_hash[h];
	node->calls = node_call;
	calls_hash[h] = node;
	++call->hash_counter;
	unlock_calls_hash();
}

/* remove node from hash */
void
Calltable::hashRemove(Call *call, in_addr_t addr, unsigned short port, bool rtcp) {
 
	if(sverb.hash_rtp) {
		cout << "hashRemove: " 
		     << call->call_id << " " 
		     << inet_ntostring(htonl(addr)) << ":" << port << " "
		     << (rtcp ? "rtcp" : "") << " "
		     << endl;
	}
	
	hash_node *node = NULL, *prev = NULL;
	hash_node_call *node_call = NULL, *prev_call = NULL;
	int h;

	h = tuplehash(addr, port);
	lock_calls_hash();
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if (node->addr == addr && node->port == port) {
			for (node_call = (hash_node_call *)node->calls; node_call != NULL; node_call = node_call->next) {
				// walk through all calls under the node and check if the call matches
				if(node_call->call == call && (!rtcp || (rtcp && (node_call->is_rtcp || !node_call->sdp_flags.rtcp_mux)))) {
					// call matches - remote the call from node->calls
					if (prev_call == NULL) {
						node->calls = node_call->next;
						--node_call->call->hash_counter;
						delete node_call;
						break; 
					} else {
						prev_call->next = node_call->next;
						--node_call->call->hash_counter;
						delete node_call;
						break; 
					}
					break;
				}
				prev_call = node_call;
			}
			if(node->calls == NULL) {
				// node now contains no calls so we can remove it 
				if (prev == NULL) {
					calls_hash[h] = node->next;
					delete node;
					unlock_calls_hash();
					return;
				} else {
					prev->next = node->next;
					delete node;
					unlock_calls_hash();
					return;
				}
			}
		}
		prev = node;
	}
	unlock_calls_hash();
}

int
Calltable::hashRemove(Call *call) {
	int removeCounter = 0;
	hash_node *node = NULL, *prev_node = NULL;
	hash_node_call *node_call = NULL, *prev_node_call = NULL;

	lock_calls_hash();
	for(int h = 0; h < MAXNODE; h++) {
		prev_node = NULL;
		for(node = (hash_node*)calls_hash[h]; node != NULL;) {
			prev_node_call = NULL;
			for(node_call = (hash_node_call *)node->calls; node_call != NULL;) {
				if(node_call->call == call) {
					++removeCounter;
					if(prev_node_call == NULL) {
						node->calls = node_call->next;
						--node_call->call->hash_counter;
						delete node_call;
						node_call = node->calls; 
					} else {
						prev_node_call->next = node_call->next;
						--node_call->call->hash_counter;
						delete node_call;
						node_call = prev_node_call->next;
					}
				} else {
					prev_node_call = node_call;
					node_call = node_call->next;
				}
			}
			if(node->calls == NULL) {
				if(prev_node == NULL) {
					calls_hash[h] = node->next;
					delete node;
					node = (hash_node*)calls_hash[h];
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
	unlock_calls_hash();
	return(removeCounter);
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
			calltable->lock_calls_deletequeue();
			calltable->calls_deletequeue.push_back(call);
			calltable->unlock_calls_deletequeue();
			last_use_at = getTimeS();
		} else {
			if((getTimeS() - last_use_at) > 5 * 60) {
				break;
			} else {
				usleep(1000);
			}
		}
	}
	calltable->lock_calls_audioqueue();
	calltable->audioQueueThreads.remove((sAudioQueueThread*)audioQueueThread);
	calltable->unlock_calls_audioqueue();
	delete (sAudioQueueThread*)audioQueueThread;
	return(NULL);
}

void
Calltable::destroyCallsIfPcapsClosed() {
	this->lock_calls_deletequeue();
	if(this->calls_deletequeue.size() > 0) {
		size_t size = this->calls_deletequeue.size();
		for(size_t i = 0; i < size;) {
			Call *call = this->calls_deletequeue[i];
			if(call->isPcapsClose() && call->isEmptyChunkBuffersCount()) {
				call->removeFindTables();
				call->atFinish();
				call->calls_counter_dec();
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
				delete reg;
				registers_counter--;
				this->registers_deletequeue.erase(this->registers_deletequeue.begin() + i);
				--size;
			} else {
				i++;
			}
		}
	}
	this->unlock_registers_deletequeue();
}

Call*
Calltable::add(int call_type, char *call_id, unsigned long call_id_len, time_t time, u_int32_t saddr, unsigned short port,
	       pcap_t *handle, int dlt, int sensorId) {
	Call *newcall = new FILE_LINE(1011) Call(call_type, call_id, call_id_len, time);
	newcall->in_preprocess_queue_before_process_packet = 1;
	newcall->in_preprocess_queue_before_process_packet_at = time;

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
		registers_counter++;
		unlock_registers_listMAP();
	} else {
		lock_calls_listMAP();
		calls_listMAP[call_idS] = newcall;
		newcall->calls_counter_inc();
		unlock_calls_listMAP();
	}
	return newcall;
}

Call*
Calltable::find_by_skinny_partyid(unsigned int partyid) {
	map<unsigned int, Call*>::iterator skinny_partyIDIT = skinny_partyID.find(partyid);
	if(skinny_partyIDIT == skinny_partyID.end()) {
		// not found
		return NULL;
	} else {
		return (*skinny_partyIDIT).second->end_call ? NULL : (*skinny_partyIDIT).second;
	}
}

Call*
Calltable::find_by_skinny_ipTuples(unsigned int saddr, unsigned int daddr) {
	stringstream tmp;

	if(saddr < daddr) {
		tmp << saddr << '|' << daddr;
	} else {
		tmp << daddr << '|' << saddr;
	}

	map<string, Call*>::iterator skinny_ipTuplesIT = skinny_ipTuples.find(tmp.str());
	if(skinny_ipTuplesIT == skinny_ipTuples.end()) {
		return NULL;
	} else {
		return skinny_ipTuplesIT->second->end_call ? NULL : skinny_ipTuplesIT->second;
	}
}


/* iterate all calls in table which are 5 minutes inactive and save them into SQL 
 * ic currtime = 0, save it immediatly
*/

int
Calltable::cleanup_calls( time_t currtime ) {

#if HAVE_LIBTCMALLOC    
	MallocExtension::instance()->ReleaseFreeMemory();
#endif

	if(verbosity && verbosityE > 1) {
		syslog(LOG_NOTICE, "call Calltable::cleanup_calls");
	}
	Call* call;
	lock_calls_listMAP();
	Call **closeCalls = new FILE_LINE(1012) Call*[calls_listMAP.size()];
	unsigned int closeCalls_count = 0;
	for (map<string, Call*>::iterator callMAPIT = calls_listMAP.begin(); callMAPIT != calls_listMAP.end();) {
		call = (*callMAPIT).second;
		if(verbosity > 2) {
			call->dump();
		}
		if(verbosity && verbosityE > 1) {
			syslog(LOG_NOTICE, "Calltable::cleanup - try callid %s", call->call_id.c_str());
		}
		// rtptimeout seconds of inactivity will save this call and remove from call table
		bool closeCall = false;
		if(currtime == 0 || call->force_close) {
			closeCall = true;
			if(!opt_read_from_file && !opt_pb_read_from_file[0]) {
				call->force_terminate = true;
			}
		} else if(call->type == SKINNY_NEW ||
			  call->in_preprocess_queue_before_process_packet <= 0 ||
			  (!is_read_from_file() &&
			   (call->in_preprocess_queue_before_process_packet_at && call->in_preprocess_queue_before_process_packet_at < currtime - 300))) {
			if(call->destroy_call_at != 0 && call->destroy_call_at <= currtime) {
				closeCall = true;
			} else if((call->destroy_call_at_bye != 0 && call->destroy_call_at_bye <= currtime) ||
				  (call->destroy_call_at_bye_confirmed != 0 && call->destroy_call_at_bye_confirmed <= currtime)) {
				closeCall = true;
				call->bye_timeout_exceeded = true;
			} else if(call->first_rtp_time &&
				  currtime - call->get_last_packet_time() > rtptimeout) {
				closeCall = true;
				call->rtp_timeout_exceeded = true;
			} else if(!call->first_rtp_time &&
				  currtime - call->first_packet_time > sipwithoutrtptimeout) {
				closeCall = true;
				call->sipwithoutrtp_timeout_exceeded = true;
			} else if(currtime - call->first_packet_time > absolute_timeout) {
				closeCall = true;
				call->absolute_timeout_exceeded = true;
			} else if(currtime - call->first_packet_time > 300 &&
				  !call->seenRES18X && !call->seenRES2XX && !call->first_rtp_time) {
				closeCall = true;
				call->zombie_timeout_exceeded = true;
			}
			if(!closeCall &&
			   (call->oneway == 1 && (currtime - call->get_last_packet_time() > opt_onewaytimeout))) {
				closeCall = true;
				call->oneway_timeout_exceeded = true;
			}
		}
		if(closeCall) {
			call->removeFindTables(true);
			if(call->rtppacketsinqueue != 0) {
				closeCall = false;
			}
		}
		if(closeCall) {
			if(call->listening_worker_run) {
				*call->listening_worker_run = 0;
			}
			closeCalls[closeCalls_count++] = call;
			calls_listMAP.erase(callMAPIT++);
		} else {
			++callMAPIT;
		}
	}
	unlock_calls_listMAP();
	for(unsigned i = 0; i < closeCalls_count; i++) {
		call = closeCalls[i];
		if(verbosity && verbosityE > 1) {
			syslog(LOG_NOTICE, "Calltable::cleanup - callid %s", call->call_id.c_str());
		}
		// Close RTP dump file ASAP to save file handles
		if(currtime == 0 && is_terminating()) {
			call->getPcap()->close();
			call->getPcapSip()->close();
		}
		call->getPcapRtp()->close();

		if(currtime == 0) {
			/* we are saving calls because of terminating SIGTERM and we dont know 
			 * if the call ends successfully or not. So we dont want to confuse monitoring
			 * applications which reports unterminated calls so mark this call as sighup */
			call->sighup = true;
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Set call->sighup\n");
		}
		// we have to close all raw files as there can be data in buffers 
		call->closeRawFiles();
		/* move call to queue for mysql processing */
		lock_calls_queue();
		if(call->push_call_to_calls_queue) {
			syslog(LOG_WARNING,"try to duplicity push call %s / %i to calls_queue", call->call_id.c_str(), call->type);
		} else {
			call->push_call_to_calls_queue = 1;
			calls_queue.push_back(call);
		}
		unlock_calls_queue();
		
		if(opt_enable_fraud && currtime) {
			struct timeval tv_currtime;
			tv_currtime.tv_sec = currtime;
			tv_currtime.tv_usec = 0;
			fraudEndCall(call, tv_currtime);
		}
		extern u_int64_t counter_calls_clean;
		++counter_calls_clean;
	}
	delete [] closeCalls;
	
	if(currtime == 0 && is_terminating()) {
		extern int terminated_call_cleanup;
		terminated_call_cleanup = 1;
		syslog(LOG_NOTICE, "terminated - cleanup calls");
	}
	
	return 0;
}

int
Calltable::cleanup_registers( time_t currtime ) {

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
		if(currtime == 0 || reg->force_close) {
			closeReg = true;
			if(!opt_read_from_file && !opt_pb_read_from_file[0]) {
				reg->force_terminate = true;
			}
		} else {
			if(reg->destroy_call_at != 0 && reg->destroy_call_at <= currtime) {
				closeReg = true;
			} else if(currtime - reg->first_packet_time > absolute_timeout) {
				closeReg = true;
				reg->absolute_timeout_exceeded = true;
			} else if(currtime - reg->first_packet_time > 300 &&
				  !reg->seenRES18X && !reg->seenRES2XX) {
				closeReg = true;
				reg->zombie_timeout_exceeded = true;
			}
			if(!closeReg &&
			   (reg->oneway == 1 && (currtime - reg->get_last_packet_time() > opt_onewaytimeout))) {
				closeReg = true;
				reg->oneway_timeout_exceeded = true;
			}
		}
		if(closeReg) {
			if(verbosity && verbosityE > 1) {
				syslog(LOG_NOTICE, "Calltable::cleanup - callid %s", reg->call_id.c_str());
			}
			// Close RTP dump file ASAP to save file handles
			if(currtime == 0 && is_terminating()) {
				reg->getPcap()->close();
				reg->getPcapSip()->close();
			}

			if(currtime == 0) {
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
				struct timeval tv_currtime;
				tv_currtime.tv_sec = currtime;
				tv_currtime.tv_usec = 0;
				fraudEndCall(reg, tv_currtime);
			}
			extern u_int64_t counter_registers_clean;
			++counter_registers_clean;
		} else {
			++registerMAPIT;
		}
	}
	unlock_registers_listMAP();
	
	if(currtime == 0 && is_terminating()) {
		extern int terminated_call_cleanup;
		terminated_call_cleanup = 1;
		syslog(LOG_NOTICE, "terminated - call cleanup");
	}
	
	return 0;
}

void Call::saveregister() {
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
	
	removeFindTables();
	this->pcap.close();
	this->pcapSip.close();
	/* move call to queue for mysql processing */
	if(push_register_to_registers_queue) {
		syslog(LOG_WARNING,"try to duplicity push call %s / %i to registers_queue", call_id.c_str(), type);
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
Call::handle_dtmf(char dtmf, double dtmf_time, unsigned int saddr, unsigned int daddr, s_dtmf::e_type dtmf_type) {

	if(opt_dbdtmf) {
		s_dtmf q;
		q.dtmf = dtmf;
		q.ts = dtmf_time - ts2double(first_packet_time, first_packet_usec);
		q.type = dtmf_type;
		q.saddr = ntohl(saddr);
		q.daddr = ntohl(daddr);

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
							       dtmf_type_string, dtmf_time - ts2double(this->first_packet_time, this->first_packet_usec));
						silencerecording = 1;
					} else {
						if(sverb.dtmf)
							syslog(LOG_NOTICE, "[%s] pause DTMF sequence detected - unpausing recording - %s / %lf s", fbasename, 
							       dtmf_type_string, dtmf_time - ts2double(this->first_packet_time, this->first_packet_usec));
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
		this->called_sipdscp = header_ip->tos >> 2;
		if(sverb.dscp) {
			cout << "called_sipdscp " << (int)(header_ip->tos>>2) << endl;
		}
	} else {
		this->caller_sipdscp = header_ip->tos >> 2;
		if(sverb.dscp) {
			cout << "caller_sipdscp " << (int)(header_ip->tos>>2) << endl;
		}
	}
}

bool 
Call::check_is_caller_called(const char *call_id, int sip_method, unsigned int saddr, unsigned int daddr, bool *iscaller, bool *iscalled, bool enableSetSipcallerdip) {
	*iscaller = 0;
	bool _iscalled = 0;
	string debug_str_set;
	string debug_str_cmp;
	if(this->type == MESSAGE) {
		if(sip_method == MESSAGE) {
			_iscalled = 1;
			debug_str_cmp = string(" / == MSG");
		} else {
			*iscaller = 1;
			debug_str_cmp = string(" / != MSG");
		}
	} else if(this->type == REGISTER) {
		if(sip_method == REGISTER) {
			_iscalled = 1;
			debug_str_cmp = string(" / == REGISTER");
		} else {
			*iscaller = 1;
			debug_str_cmp = string(" / != REGISTER");
		}
	} else {
		u_int32_t *sipcallerip;
		u_int32_t *sipcalledip;
		if(opt_callidmerge_header[0] != '\0') {
			sipcallerip = this->map_sipcallerdip[call_id].sipcallerip;
			sipcalledip = this->map_sipcallerdip[call_id].sipcalledip;
			if(!sipcallerip[0] && !sipcalledip[0]) {
				sipcallerip[0] = saddr;
				sipcalledip[0] = daddr;
			}
		} else {
			sipcallerip = this->sipcallerip;
			sipcalledip = this->sipcalledip;
		}
		int i;
		for(i = 0; i < MAX_SIPCALLERDIP; i++) {
			if(enableSetSipcallerdip && i > 0 && !sipcallerip[i] && saddr && daddr) {
				if(sip_method == INVITE) {
					sipcallerip[i] = saddr;
					sipcalledip[i] = daddr;
					if(sverb.check_is_caller_called) {
						debug_str_set += string(" / set sipcallerdip[") + intToString(i) + "]: s " + inet_ntostring(htonl(saddr)) + ", d " + inet_ntostring(htonl(daddr));
					}
				} else if(IS_SIP_RES18X(sip_method))  {
					sipcallerip[i] = daddr;
					sipcalledip[i] = saddr;
					if(sverb.check_is_caller_called) {
						debug_str_set += string(" / set sipcallerdip[") + intToString(i) + "]: s " + inet_ntostring(htonl(daddr)) + ", d " + inet_ntostring(htonl(saddr));
					}
				}
			}
			if(sipcallerip[i]) {
				if(sipcallerip[i] == saddr) {
					// SDP message is coming from the first IP address seen in first INVITE thus incoming stream to ip/port in this 
					// SDP will be stream from called
					_iscalled = 1;
					if(sverb.check_is_caller_called) {
						debug_str_cmp += string(" / cmp sipcallerip[") + intToString(i) + "] (" + inet_ntostring(htonl(sipcallerip[i])) + ") == " + 
								 "saddr (" + inet_ntostring(htonl(saddr)) + ")";
					}
					break;
				} else {
					// The IP address is different, check if the request matches one of the address from the first invite
					if(sipcallerip[i] == daddr) {
						// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
						*iscaller = 1;
						if(sverb.check_is_caller_called) {
							debug_str_cmp += string(" / sipcallerip[") + intToString(i) + "] (" + inet_ntostring(htonl(sipcallerip[i])) + ") == " + 
									 "daddr (" + inet_ntostring(htonl(daddr)) + ")";
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
	if(iscalled) {
		*iscalled = _iscalled;
	}
	if(sverb.check_is_caller_called) {
		cout << "check_is_caller_called: " 
		     << "call_id: " << call_id  << " "
		     << "sip_method: " << sip_method << " "
		     << inet_ntostring(htonl(saddr)) << " -> " << inet_ntostring(htonl(daddr))
		     << " = " << (*iscaller ? "caller" : (_iscalled ? "called" : "undefine"))
		     << debug_str_set
		     << debug_str_cmp
		     << endl;
		
	}
	return(*iscaller || _iscalled);
	
	/* obsolete
	*iscaller = 0;
	bool _iscalled = 0;
	string debug_str_set;
	string debug_str_cmp;
	// 1) check by saddr
	if(this->sipcallerip == saddr) {
		// SDP message is coming from the first IP address seen in first INVITE thus incoming stream to ip/port in this 
		// SDP will be stream from called
		_iscalled = 1;
		if(sverb.check_is_caller_called) {
			debug_str_cmp = "this->sipcallerip (" + inet_ntostring(htonl(this->sipcallerip)) + ") == saddr (" + inet_ntostring(htonl(saddr)) + ")";
		}
	} else {
		// The IP address is different, check if the request matches one of the address from the first invite
		if(this->sipcallerip == daddr) {
			// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
			*iscaller = 1;
			if(sverb.check_is_caller_called) {
				debug_str_cmp = "this->sipcallerip (" + inet_ntostring(htonl(this->sipcallerip)) + ") == daddr (" + inet_ntostring(htonl(daddr)) + ")";
			}
		// src IP address of this SDP SIP message is different from the src/dst IP address used in the first INVITE. 
		} else {
			if(this->sipcallerip2 == 0 && saddr && daddr) { 
				this->sipcallerip2 = saddr;
				this->sipcalledip2 = daddr;
				if(sverb.check_is_caller_called) {
					debug_str_set = "sipcallerdip2: s " + inet_ntostring(htonl(saddr)) + ", d " + inet_ntostring(htonl(daddr));
				}
			}
			if(this->sipcallerip2 == saddr) {
				_iscalled = 1;
				if(sverb.check_is_caller_called) {
					debug_str_cmp = "this->sipcallerip2 (" + inet_ntostring(htonl(this->sipcallerip2)) + ") == saddr (" + inet_ntostring(htonl(saddr)) + ")";
				}
			} else {
				// The IP address is different, check if the request matches one of the address from the first invite
				if(this->sipcallerip2 == daddr) {
					// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
					*iscaller = 1;
					if(sverb.check_is_caller_called) {
						debug_str_cmp = "this->sipcallerip2 (" + inet_ntostring(htonl(this->sipcallerip2)) + ") == daddr (" + inet_ntostring(htonl(daddr)) + ")";
					}
				// src IP address of this SDP SIP message is different from the src/dst IP address used in the first INVITE. 
				} else {
					if(this->sipcallerip3 == 0 && saddr && daddr) { 
						this->sipcallerip3 = saddr;
						this->sipcalledip3 = daddr;
						if(sverb.check_is_caller_called) {
							debug_str_set = "sipcallerdip3: s " + inet_ntostring(htonl(saddr)) + ", d " + inet_ntostring(htonl(daddr));
						}
					}
					if(this->sipcallerip3 == saddr) {
						_iscalled = 1;
						if(sverb.check_is_caller_called) {
							debug_str_cmp = "this->sipcallerip3 (" + inet_ntostring(htonl(this->sipcallerip3)) + ") == saddr (" + inet_ntostring(htonl(saddr)) + ")";
						}
					} else {
						// The IP address is different, check if the request matches one of the address from the first invite
						if(this->sipcallerip3 == daddr) {
							// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
							*iscaller = 1;
							if(sverb.check_is_caller_called) {
								debug_str_cmp = "this->sipcallerip3 (" + inet_ntostring(htonl(this->sipcallerip3)) + ") == daddr (" + inet_ntostring(htonl(daddr)) + ")";
							}
						// src IP address of this SDP SIP message is different from the src/dst IP address used in the first INVITE. 
						} else {
							if(this->sipcallerip4 == 0 && saddr && daddr) { 
								this->sipcallerip4 = saddr;
								this->sipcalledip4 = daddr;
								if(sverb.check_is_caller_called) {
									debug_str_set = "sipcallerdip4: s " + inet_ntostring(htonl(saddr)) + ", d " + inet_ntostring(htonl(daddr));
								}
							}
							if(this->sipcallerip4 == saddr) {
								_iscalled = 1;
								if(sverb.check_is_caller_called) {
									debug_str_cmp = "this->sipcallerip4 (" + inet_ntostring(htonl(this->sipcallerip4)) + ") == saddr (" + inet_ntostring(htonl(saddr)) + ")";
								}
							} else {
								*iscaller = 1;
								if(sverb.check_is_caller_called) {
									debug_str_cmp = "this->sipcallerip4 (" + inet_ntostring(htonl(this->sipcallerip4)) + ") != saddr (" + inet_ntostring(htonl(saddr)) + ")";
								}
							}
						}
					}
				}
			}
		}
	}
	if(iscalled) {
		*iscalled = _iscalled;
	}
	if(sverb.check_is_caller_called) {
		cout << "check_is_caller_called: " 
		     << inet_ntostring(htonl(saddr)) << " -> " << inet_ntostring(htonl(daddr))
		     << " = " << (*iscaller ? "caller" : (_iscalled ? "called" : "undefine"))
		     << (debug_str_set.empty() ? "" : " / " + debug_str_set)
		     << (debug_str_cmp.empty() ? "" : " / " + debug_str_cmp)
		     << endl;
	}
	return(*iscaller || _iscalled);
	*/
}


CustomHeaders::CustomHeaders(eType type) {
	this->type = type;
	this->configTable = type == cdr ? "cdr_custom_headers" : "message_custom_headers";
	this->nextTablePrefix = type == cdr ? "cdr_next_" : "message_next_";
	this->fixedTable = type == cdr ? "cdr_next" : "message";
	this->loadTime = 0;
	this->lastTimeSaveUseInfo = 0;
	this->_sync_custom_headers = 0;
	this->load();
}

void CustomHeaders::load(SqlDb *sqlDb, bool lock) {
	if(lock) lock_custom_headers();
	custom_headers.clear();
	allNextTables.clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool existsConfigTable = false;
	sqlDb->query("show tables like '" + this->configTable + "'");
	if(sqlDb->fetchRow()) {
		existsConfigTable = true;
		sqlDb->query("show columns from " + this->configTable + " where Field='state'");
		if(sqlDb->fetchRow()) {
			sqlDb->query("SELECT * FROM " + this->configTable + " \
				      where state is null or state='active'");
			list<sCustomHeaderDataPlus> customHeaderData;
			SqlDb_row row;
			while((row = sqlDb->fetchRow())) {
				sCustomHeaderDataPlus ch_data;
				string specialType = row["special_type"];
				ch_data.specialType = specialType == "max_length_sip_data" ? max_length_sip_data :
						      specialType == "max_length_sip_packet" ? max_length_sip_packet :
						      specialType == "gsm_dcs" ? gsm_dcs :
						      specialType == "gsm_voicemail" ? gsm_voicemail : st_na;
				ch_data.db_id = atoi(row["id"].c_str());
				ch_data.type = row.getIndexField("type") < 0 || row.isNull("type") ? "fixed" : row["type"];
				ch_data.header = row["header_field"];
				ch_data.leftBorder = row["left_border"];
				ch_data.rightBorder = row["right_border"];
				ch_data.regularExpression = row["regular_expression"];
				ch_data.screenPopupField = atoi(row["screen_popup_field"].c_str());
				ch_data.dynamic_table = atoi(row["dynamic_table"].c_str());
				ch_data.dynamic_column = atoi(row["dynamic_column"].c_str());
				customHeaderData.push_back(ch_data);
			}
			for(list<sCustomHeaderDataPlus>::iterator iter = customHeaderData.begin(); iter != customHeaderData.end(); iter++) {
				if(iter->type == "fixed") {
					if(_createSqlObject) {
						sqlDb->query("show columns from " + this->fixedTable + " where Field='custom_header__" + iter->header + "'");
					}
					if(!_createSqlObject || sqlDb->fetchRow()) {
						custom_headers[0][custom_headers[0].size()] = *iter;
					}
				} else {
					custom_headers[iter->dynamic_table][iter->dynamic_column] = *iter;
				}
			}
			map<int, map<int, sCustomHeaderData> >::iterator iter;
			for(iter = custom_headers.begin(); iter != custom_headers.end();) {
				if(iter->first) {
					char nextTable[100];
					sprintf(nextTable, "%s%i", this->nextTablePrefix.c_str(), iter->first);
					sqlDb->query("show tables like '" + string(nextTable) + "'");
					if(!sqlDb->fetchRow()) {
						custom_headers.erase(iter++);
						continue;
					}
					allNextTables.push_back(nextTable);
				}
				iter++;
			}
		}
	}
	extern vector<dstring> opt_custom_headers_cdr;
	extern vector<dstring> opt_custom_headers_message;
	vector<dstring> *_customHeaders = type == cdr ? &opt_custom_headers_cdr : &opt_custom_headers_message;
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
	this->createMysqlPartitions(sqlDb);
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

void CustomHeaders::refresh(SqlDb *sqlDb) {
	lock_custom_headers();
	clear(false);
	load(sqlDb, false);
	unlock_custom_headers();
}

void CustomHeaders::addToStdParse(ParsePacket *parsePacket) {
	lock_custom_headers();
	map<int, map<int, sCustomHeaderData> >::iterator iter;
	for(iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		map<int, sCustomHeaderData>::iterator iter2;
		for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			string findHeader = iter2->second.header;
			if(findHeader[findHeader.length() - 1] != ':' &&
			   findHeader[findHeader.length() - 1] != '=') {
				findHeader.append(":");
			}
			parsePacket->addNode(findHeader.c_str(), ParsePacket::typeNode_custom);
		}
	}
	unlock_custom_headers();
}

extern char * gettag_ext(const void *ptr, unsigned long len, ParsePacket::ppContentsX *parseContents, 
			 const char *tag, unsigned long *gettaglen, unsigned long *limitLen = NULL);
void CustomHeaders::parse(Call *call, char *data, int datalen, ParsePacket::ppContentsX *parseContents) {
	lock_custom_headers();
	unsigned long gettagLimitLen = 0;
	map<int, map<int, sCustomHeaderData> >::iterator iter;
	for(iter = custom_headers.begin(); iter != custom_headers.end(); iter++) {
		map<int, sCustomHeaderData>::iterator iter2;
		for(iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(iter2->second.specialType) {
				string content;
				switch(iter2->second.specialType) {
				case max_length_sip_data:
					if(call->max_length_sip_data) {
						content = intToString(call->max_length_sip_data);
					}
					break;
				case max_length_sip_packet:
					if(call->max_length_sip_packet) {
						content = intToString(call->max_length_sip_packet);
					}
					break;
				case gsm_dcs:
					if(call->dcs) {
						content = intToString(call->dcs);
					}
					break;
				case gsm_voicemail:
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
					break;
				case st_na:
					break;
				}
				dstring ds_content(iter2->second.header, content);
				this->setCustomHeaderContent(call, iter->first, iter2->first, &ds_content, true);
			} else {
				string findHeader = iter2->second.header;
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
							this->setCustomHeaderContent(call, iter->first, iter2->first, &content);
						}
					} else {
						dstring content(iter2->second.header, customHeaderBegin);
						this->setCustomHeaderContent(call, iter->first, iter2->first, &content);
					}
				}
			}
		}
	}
	unlock_custom_headers();
}

void CustomHeaders::setCustomHeaderContent(Call *call, int pos1, int pos2, dstring *content, bool useLastValue) {
	bool exists = false;
	if(!opt_custom_headers_last_value && !useLastValue) {
		map<int, map<int, dstring> >::iterator iter = call->custom_headers.find(pos1);
		if(iter != call->custom_headers.end()) {
			map<int, dstring>::iterator iter2 = iter->second.find(pos2);
			if(iter2 != iter->second.end()) {
				exists = true;
			}
		}
	}
	if(!exists || opt_custom_headers_last_value || useLastValue) {
		call->custom_headers[pos1][pos2] = *content;
	}
}

void CustomHeaders::prepareSaveRows_cdr(Call *call, SqlDb_row *cdr_next, SqlDb_row cdr_next_ch[], char *cdr_next_ch_name[]) {
	map<int, map<int, dstring> >::iterator iter;
	for(iter = call->custom_headers.begin(); iter != call->custom_headers.end(); iter++) {
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
						cdr_next_ch[iter->first - 1].add(sqlEscapeString(sqlDateTimeString(call->calltime()).c_str()), "calldate");
					}
				}
				char fieldName[20];
				sprintf(fieldName, "custom_header_%i", iter2->first);
				cdr_next_ch[iter->first - 1].add(sqlEscapeString(iter2->second[1]), fieldName);
			}
		}
	}
}

void CustomHeaders::prepareSaveRows_message(Call *call, class SqlDb_row *message, class SqlDb_row message_next_ch[], char *message_next_ch_name[]) {
	this->prepareSaveRows_cdr(call, message, message_next_ch, message_next_ch_name);
}

string CustomHeaders::getScreenPopupFieldsString(Call *call) {
	string fields;
	map<int, map<int, dstring> >::iterator iter;
	for(iter = call->custom_headers.begin(); iter != call->custom_headers.end(); iter++) {
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
				(this->type == cdr ? " where cdr_id = " : " where message_id = ") + id + 
				(suffix ? suffix : "");
	}
	return(deleteQuery);
}

void CustomHeaders::createMysqlPartitions(SqlDb *sqlDb) {
	list<string>::iterator iter;
	for(iter = allNextTables.begin(); iter != allNextTables.end(); iter++) {
	 	if(sqlDb->isCloud()) {
			sqlDb->setMaxQueryPass(1);
			sqlDb->query(
				"call create_partition('" + *iter + "', 'day', 0);");
			sqlDb->query(
				"call create_partition('" + *iter + "', 'day', 1);");
		} else {
			extern char mysql_database[256];
			sqlDb->query(
				string("call `") + mysql_database + "`.create_partition('" + mysql_database + "', '" + *iter + "', 'day', 0);");
			sqlDb->query(
				string("call `") + mysql_database + "`.create_partition('" + mysql_database + "', '" + *iter + "', 'day', 1);");
		}
	}
}

string CustomHeaders::getQueryForSaveUseInfo(Call* call) {
	string query = "";
	if((unsigned)call->calltime() > this->lastTimeSaveUseInfo + 60) {
		map<int, map<int, dstring> >::iterator iter;
		for(iter = call->custom_headers.begin(); iter != call->custom_headers.end(); iter++) {
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
						sprintf(queryBuff, 
							"update %s set use_at = '%s' where dynamic_table=%i and dynamic_column=%i",
							this->configTable.c_str(),
							sqlDateTimeString(call->calltime()).c_str(),
							iter->first,
							iter2->first);
						query += queryBuff;
					}
				}
			}
		}
		this->lastTimeSaveUseInfo = call->calltime();
	}
	return(query);
}

void CustomHeaders::createTablesIfNotExists(SqlDb *sqlDb) {
	list<string> tables = getAllNextTables();
	for(list<string>::iterator it = tables.begin(); it != tables.end(); it++) {
		createTableIfNotExists(it->c_str(), sqlDb);
	}
}

void CustomHeaders::createTableIfNotExists(const char *tableName, SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	
	sqlDb->query(string("show tables like '") + tableName + "'");
	if(sqlDb->fetchRow()) {
		if(_createSqlObject) {
			delete sqlDb;
		}
		return;
	}
	
	extern bool opt_cdr_partition;
	extern bool opt_cdr_partition_oldver;
	extern int opt_mysqlcompress;
	
	char partDayName[20] = "";
	char limitDay[20] = "";
	if(opt_cdr_partition) {
		time_t act_time = time(NULL);
		struct tm actTime = time_r(&act_time);
		strftime(partDayName, sizeof(partDayName), "p%y%m%d", &actTime);
		time_t next_day_time = act_time + 24 * 60 * 60;
		struct tm nextDayTime = time_r(&next_day_time);
		strftime(limitDay, sizeof(partDayName), "%Y-%m-%d", &nextDayTime);
	}
	string compress = "";
	if(opt_mysqlcompress) {
		compress = "ROW_FORMAT=COMPRESSED";
	}
	
	string idColumn = type == cdr ? "cdr_ID" : "message_ID";
	
	sqlDb->query(string(
	"CREATE TABLE IF NOT EXISTS `") + tableName + "` (\
			`" + idColumn + "` bigint unsigned NOT NULL," +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
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
			"PRIMARY KEY (`" + idColumn + "`, `calldate`)" :
			"PRIMARY KEY (`" + idColumn + "`)") +
		(opt_cdr_partition ?
			"" :
			(string(",CONSTRAINT `") + tableName + "_ibfk_1` FOREIGN KEY (`" + idColumn + "`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE").c_str()) +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void CustomHeaders::createColumnsForFixedHeaders(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	for(unsigned i = 0; i < custom_headers[0].size(); i++) {
		sqlDb->query("show columns from " + this->fixedTable + " where Field='custom_header__" + custom_headers[0][i].header + "'");
		if(!sqlDb->fetchRow()) {
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
		string header = call->custom_headers[this->customHeader_pos[0]][this->customHeader_pos[1]][1];
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

NoHashMessageRules::NoHashMessageRules() {
	loadTime = 0;
	_sync_no_hash = 0;
	load();
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

void NoHashMessageRules::load(class SqlDb *sqlDb, bool lock) {
	if(lock) lock_no_hash();
	clear(false);
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("show tables like 'message_no_hash_rules'");
	if(sqlDb->fetchRow()) {
		sqlDb->query("SELECT nhr.*, \
				     ch.name as msg_custom_headers_name \
			      FROM message_no_hash_rules nhr \
			      JOIN message_custom_headers ch on (ch.id = nhr.msg_custom_headers_id)");
		SqlDb_row row;
		while((row = sqlDb->fetchRow())) {
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
