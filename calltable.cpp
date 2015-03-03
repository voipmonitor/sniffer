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
extern int opt_audio_format;	// define format for audio writing (if -W option)
extern int opt_mos_g729;
extern int opt_nocdr;
extern int opt_only_cdr_next;
extern char opt_cachedir[1024];
extern char sql_cdr_table[256];
extern char sql_cdr_table_last30d[256];
extern char sql_cdr_table_last7d[256];
extern char sql_cdr_table_last1d[256];
extern char sql_cdr_next_table[256];
extern char sql_cdr_ua_table[256];
extern char sql_cdr_sip_response_table[256];
extern int opt_callend;
extern int opt_id_sensor;
extern int opt_id_sensor_cleanspool;
extern int rtptimeout;
extern int sipwithoutrtptimeout;
extern int absolute_timeout;
extern unsigned int gthread_num;
extern int num_threads;
extern int opt_printinsertid;
extern int opt_cdronlyanswered;
extern int opt_cdronlyrtp;
extern int opt_newdir;
extern char opt_keycheck[1024];
extern char opt_convert_char[256];
extern int opt_norecord_dtmf;
extern char opt_silencedmtfseq[16];
extern bool opt_cdr_sipport;
extern bool opt_cdr_rtpport;
extern char get_customers_pn_query[1024];
extern int opt_saverfc2833;
extern int opt_dbdtmf;
extern int opt_dscp;
extern int opt_cdrproxy;
extern int opt_pcap_dump_tar;
extern struct pcap_stat pcapstat;
extern int opt_filesclean;
extern int opt_allow_zerossrc;
extern int opt_cdr_ua_enable;
extern unsigned int graph_delimiter;
extern unsigned int graph_version;
extern int opt_mosmin_f2;
extern char opt_mos_lqo_bin[1024];
extern char opt_mos_lqo_ref[1024];
extern char opt_mos_lqo_ref16[1024];
extern int opt_mos_lqo;
extern regcache *regfailedcache;
extern MySqlStore *sqlStore;
extern int global_pcap_dlink;
extern pcap_t *global_pcap_handle;
extern int opt_rtpsave_threaded;
extern int opt_last_rtp_from_end;
extern int opt_mysqlstore_max_threads_cdr;
extern int opt_mysqlstore_max_threads_message;
extern int opt_mysqlstore_max_threads_register;
extern int opt_mysqlstore_max_threads_http;
extern int opt_mysqlstore_limit_queue_register;
extern Calltable *calltable;
extern int opt_silencedetect;
extern int opt_clippingdetect;
extern int terminating;
extern int opt_read_from_file;
extern char opt_pb_read_from_file[256];

volatile int calls_counter = 0;

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

SqlDb *sqlDbSaveCall = NULL;
bool existsColumnCalldateInCdrNext = true;
bool existsColumnCalldateInCdrRtp = true;
bool existsColumnCalldateInCdrDtmf = true;
bool existsColumnCalldateInCdrTarPart = true;

extern int opt_pcap_dump_tar_sip_use_pos;
extern int opt_pcap_dump_tar_rtp_use_pos;
extern int opt_pcap_dump_tar_graph_use_pos;


/* constructor */
Call::Call(char *call_id, unsigned long call_id_len, time_t time) :
 tmprtp(-1),
 pcap(PcapDumper::na, this),
 pcapSip(PcapDumper::sip, this),
 pcapRtp(PcapDumper::rtp, this) {
	//increaseTartimemap(time);
	isfax = 0;
	seenudptl = 0;
	last_callercodec = -1;
	ipport_n = 0;
	ssrc_n = 0;
	first_packet_time = time;
	first_packet_usec = 0;
	last_packet_time = time;
	last_rtp_a_packet_time = 0;
	last_rtp_b_packet_time = 0;
	this->call_id = string(call_id, call_id_len);
	this->call_id_len = call_id_len;
	whohanged = -1;
	seeninvite = false;
	seeninviteok = false;
	seenbye = false;
	seenbyeandok = false;
	seenRES2XX = false;
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
	sighup = false;
	progress_time = 0;
	set_progress_time_via_2XX_or18X = false;
	first_rtp_time = 0;
	connect_time = 0;
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
	msgcount = 0;
	regcount = 0;
	reg401count = 0;
	regstate = 0;
	regresponse = false;
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
		rtp[i] = NULL;
	}
	rtplock = 0;
	audiobuffer1 = NULL;
	last_seq_audiobuffer1 = 0;
	audiobuffer2 = NULL;
	last_seq_audiobuffer2 = 0;
	listening_worker_run = NULL;
	tmprtp.call_owner = this;
	flags = 0;
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	destroy_call_at = 0;
	destroy_call_at_bye = 0;
	custom_header1[0] = '\0';
	match_header[0] = '\0';
	thread_num = num_threads > 0 ? gthread_num % num_threads : 0;
	gthread_num++;
	recordstopped = 0;
	dtmfflag = 0;
	dtmfflag2 = 0;
	silencerecording = 0;
	flags1 = 0;
	#if SYNC_CALL_RTP
	rtppcaketsinqueue = 0;
	#else
	rtppcaketsinqueue_p = 0;
	rtppcaketsinqueue_m = 0;
	#endif
	end_call = 0;
	message = NULL;
	contenttype = NULL;
	content_length = 0;
	unrepliedinvite = 0;
	for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
		 sipcallerip[i] = 0;
		 sipcalledip[i] = 0;
	}
	lastsipcallerip = 0;
	sipcallerport = 0;
	sipcalledport = 0;
	fname2 = 0;
	skinny_partyid = 0;
	pthread_mutex_init(&buflock, NULL);
	pthread_mutex_init(&listening_worker_run_lock, NULL);
	caller_sipdscp = 0;
	called_sipdscp = 0;
	ps_ifdrop = pcapstat.ps_ifdrop;
	ps_drop = pcapstat.ps_drop;
	if(verbosity && verbosityE > 1) {
		syslog(LOG_NOTICE, "CREATE CALL %s", this->call_id.c_str());
	}
	forcemark[0] = forcemark[1] = 0;
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
}

void
Call::mapRemove() {
	int i;
	Calltable *ct = (Calltable *)calltable;

	for(i = 0; i < ipport_n; i++) {
		ct->mapRemove(this->ip_port[i].addr, this->ip_port[i].port);
		if(opt_rtcp) {
			ct->mapRemove(this->ip_port[i].addr, this->ip_port[i].port + 1);
		}

	}
}

void
Call::hashRemove() {
	int i;
	Calltable *ct = (Calltable *)calltable;

	for(i = 0; i < ipport_n; i++) {
		ct->hashRemove(this, this->ip_port[i].addr, this->ip_port[i].port);
		if(opt_rtcp) {
			ct->hashRemove(this, this->ip_port[i].addr, this->ip_port[i].port + 1);
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

		for (((Calltable *)calltable)->skinny_ipTuplesIT = ((Calltable *)calltable)->skinny_ipTuples.begin(); ((Calltable *)calltable)->skinny_ipTuplesIT != ((Calltable *)calltable)->skinny_ipTuples.end();) {
			if(((Calltable *)calltable)->skinny_ipTuplesIT->second == this) {
				((Calltable *)calltable)->skinny_ipTuples.erase(((Calltable *)calltable)->skinny_ipTuplesIT++);
			} else {
				++((Calltable *)calltable)->skinny_ipTuplesIT;
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
Call::addtofilesqueue(string file, string column, long long writeBytes) {
	_addtofilesqueue(file, column, dirnamesqlfiles(), writeBytes);
}

void 
Call::_addtofilesqueue(string file, string column, string dirnamesqlfiles, long long writeBytes) {

	if(!opt_filesclean or opt_nocdr or file == "" or !isSqlDriver("mysql") or
	   !isSetCleanspoolParameters()) return;

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
		size = GetFileSizeDU(file);
	}
	if(!size && fileCacheExists) {
		size = GetFileSizeDU(fileCache);
	}
	if(writeBytes) {
		writeBytes = GetDU(writeBytes);
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

	ostringstream query;

	int id_sensor = opt_id_sensor_cleanspool == -1 ? 0 : opt_id_sensor_cleanspool;
	
	query << "INSERT INTO files SET files.datehour = " << dirnamesqlfiles << ", id_sensor = " << id_sensor << ", "
		<< column << " = " << size << " ON DUPLICATE KEY UPDATE " << column << " = " << column << " + " << size;

	sqlStore->lock(STORE_PROC_ID_CLEANSPOOL);
	sqlStore->query(query.str().c_str(), STORE_PROC_ID_CLEANSPOOL);


	ostringstream fname;
	fname << "filesindex/" << column << "/" << dirnamesqlfiles;
	ofstream myfile(fname.str().c_str(), ios::app | ios::out);
	if(!myfile.is_open()) {
		syslog(LOG_ERR,"error write to [%s]", fname.str().c_str());
	}
	myfile << file << ":" << size << "\n";
	myfile.close();
		
	sqlStore->unlock(STORE_PROC_ID_CLEANSPOOL);
}

void
Call::addtocachequeue(string file) {
	_addtocachequeue(file);
}

void 
Call::_addtocachequeue(string file) {
	calltable->lock_files_queue();
	calltable->files_queue.push(file);
	calltable->unlock_files_queue();
}

void
Call::removeRTP() {
	while(rtplock) {
		//wait until the lock is released
		usleep(100);
	}
	rtplock = 1;
	closeRawFiles();
	ssrc_n = 0;
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
	// lets check whole array as there can be holes due rtp[0] <=> rtp[1] swaps in mysql rutine
		if(rtp[i]) {
			delete rtp[i];
			rtp[i] = NULL;
		}
	}
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	rtplock = 0;
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
	pthread_mutex_lock(&listening_worker_run_lock);

	if(audiobuffer1) delete audiobuffer1;
	if(audiobuffer2) delete audiobuffer2;

	if(this->message) {
		delete [] message;
	}
	pthread_mutex_destroy(&buflock);
	pthread_mutex_unlock(&listening_worker_run_lock);
	pthread_mutex_destroy(&listening_worker_run_lock);
	//decreaseTartimemap(this->first_packet_time);
	//printf("caller s[%u] n[%u] ls[%u]  called s[%u] n[%u] ls[%u]\n", caller_silence, caller_noise, caller_lastsilence, called_silence, called_noise, called_lastsilence);
//	printf("caller_clipping_8k [%u] [%u]\n", caller_clipping_8k, called_clipping_8k);
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
				rtp[i]->graph.close();
			}
		}
	}
}

/* returns name of the directory in format YYYY-MM-DD */
string
Call::dirname() {
	char sdirname[18];
	struct tm t = localtime_r((const time_t*)(&first_packet_time));
	if(opt_newdir) {
		snprintf(sdirname, 17, "%04d-%02d-%02d/%02d/%02d",  t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min);
	} else {
		snprintf(sdirname, 17, "%04d-%02d-%02d",  t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
	}
	sdirname[17] = 0;
	string s(sdirname);
	return s;
}

/* returns name of the directory in format YYYY-MM-DD */
string
Call::dirnamesqlfiles() {
	char sdirname[12];
	struct tm t = localtime_r((const time_t*)(&first_packet_time));
	snprintf(sdirname, 11, "%04d%02d%02d%02d",  t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour);
	sdirname[11] = 0;
	string s(sdirname);
	return s;
}


/* add ip adress and port to this call */
int
Call::add_ip_port(in_addr_t sip_src_addr, in_addr_t addr, unsigned short port, char *sessid, char *ua, unsigned long ua_len, bool iscaller, int *rtpmap, bool fax) {
	if(this->end_call) {
		return(-1);
	}
 
	if(verbosity >= 4) {
		struct in_addr in;
		in.s_addr = addr;
		printf("call:[%p] ip:[%s] port:[%d] iscaller:[%d]\n", this, inet_ntoa(in), port, iscaller);
	}

	if(ipport_n > 0) {
		if(this->refresh_data_ip_port(addr, port, iscaller, rtpmap, fax)) {
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
	if(ua_len && ua_len < 1024) {
		char *tmp = iscaller ? this->b_ua : this->a_ua;
		memcpy(tmp, ua, MIN(ua_len, 1024));
		tmp[MIN(ua_len, 1023)] = '\0';
	}

	this->ip_port[ipport_n].sip_src_addr = sip_src_addr;
	this->ip_port[ipport_n].addr = addr;
	this->ip_port[ipport_n].port = port;
	this->ip_port[ipport_n].iscaller = iscaller;
	this->ip_port[ipport_n].fax = fax;
	if(sessid) {
		memcpy(this->ip_port[ipport_n].sessid, sessid, MAXLEN_SDP_SESSID);
	} else {
		memset(this->ip_port[ipport_n].sessid, 0, MAXLEN_SDP_SESSID);
	}
	
	memcpy(this->rtpmap[RTPMAP_BY_CALLERD ? iscaller : ipport_n], rtpmap, MAX_RTPMAP * sizeof(int));
	ipport_n++;
	return 0;
}

bool 
Call::refresh_data_ip_port(in_addr_t addr, unsigned short port, bool iscaller, int *rtpmap, bool fax) {
	for(int i = 0; i < ipport_n; i++) {
		if(this->ip_port[i].addr == addr && this->ip_port[i].port == port) {
			// reinit rtpmap
			memcpy(this->rtpmap[RTPMAP_BY_CALLERD ? iscaller : i], rtpmap, MAX_RTPMAP * sizeof(int));
			// force mark bit for reinvite 
			forcemark[iscaller] = true;
			if(fax && !this->ip_port[i].fax) {
				this->ip_port[i].fax = fax;
				calltable->lock_calls_hash();
				hash_node_call *calls = calltable->hashfind_by_ip_port(addr, port, 0, false);
				if(calls) {
					for(hash_node_call *node_call = calls; node_call != NULL; node_call = node_call->next) {
						node_call->is_fax = fax;
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
Call::add_ip_port_hash(in_addr_t sip_src_addr, in_addr_t addr, unsigned short port, char *sessid, char *ua, unsigned long ua_len, bool iscaller, int *rtpmap, bool fax, int allowrelation) {
	if(this->end_call) {
		return;
	}

	if(sessid) {
		int sessidIndex = get_index_by_sessid(sessid, sip_src_addr);
		if(sessidIndex >= 0) {
			if(this->ip_port[sessidIndex].sip_src_addr == sip_src_addr &&
			   (this->ip_port[sessidIndex].addr != addr ||
			    this->ip_port[sessidIndex].port != port ||
			    this->ip_port[sessidIndex].iscaller != iscaller)) {
				((Calltable*)calltable)->hashRemove(this, ip_port[sessidIndex].addr, ip_port[sessidIndex].port);
				((Calltable*)calltable)->hashAdd(addr, port, this, iscaller, 0, fax, allowrelation);
				if(opt_rtcp) {
					((Calltable*)calltable)->hashRemove(this, ip_port[sessidIndex].addr, ip_port[sessidIndex].port + 1);
					((Calltable*)calltable)->hashAdd(addr, port + 1, this, iscaller, 1, fax);
				}
				//cout << "change ip/port for sessid " << sessid << " ip:" << inet_ntostring(htonl(addr)) << "/" << inet_ntostring(htonl(this->ip_port[sessidIndex].addr)) << " port:" << port << "/" <<  this->ip_port[sessidIndex].port << endl;
				this->ip_port[sessidIndex].addr = addr;
				this->ip_port[sessidIndex].port = port;
				this->ip_port[sessidIndex].iscaller = iscaller;
			}
			this->refresh_data_ip_port(addr, port, iscaller, rtpmap, fax);
			return;
		}
	}
	if(this->add_ip_port(sip_src_addr, addr, port, sessid, ua, ua_len, iscaller, rtpmap, fax) != -1) {
		((Calltable*)calltable)->hashAdd(addr, port, this, iscaller, 0, fax, allowrelation);
		if(opt_rtcp) {
			((Calltable*)calltable)->hashAdd(addr, port + 1, this, iscaller, 1, fax);
		}
	}
}

/* Return reference to Call if IP:port was found, otherwise return NULL */
Call*
Call::find_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller){
	for(int i = 0; i < ipport_n; i++) {
		if(this->ip_port[i].addr == addr && this->ip_port[i].port == port) {
			// we have found it
			*iscaller = this->ip_port[i].iscaller;
			return this;
		}
	}
	// not found
	return NULL;
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

Call*
Call::find_by_sessid(char *sessid){
	for(int i = 0; i < ipport_n; i++) {
		if(!memcmp(this->ip_port[i].sessid, sessid, MAXLEN_SDP_SESSID)) {
			// we have found it
			return this;
		}
	}
	// not found
	return NULL;
}

int
Call::get_index_by_sessid(char *sessid, in_addr_t sip_src_addr){
	for(int i = 0; i < ipport_n; i++) {
		if(!memcmp(this->ip_port[i].sessid, sessid, MAXLEN_SDP_SESSID) &&
		   (!sip_src_addr || sip_src_addr == this->ip_port[i].sip_src_addr)) {
			// we have found it
			return i;
		}
	}
	// not found
	return -1;
}

/* analyze rtcp packet */
void
Call::read_rtcp(unsigned char* data, int datalen, int dataoffset, struct pcap_pkthdr *header, u_int32_t saddr, u_int32_t daddr, unsigned short sport, unsigned short dport, int iscaller,
		char enable_save_packet, const u_char *packet, char istcp, int dlt, int sensor_id) {
	parse_rtcp((char*)data, datalen, this);

	if(enable_save_packet && opt_rtpsave_threaded) {
		save_packet(this, header, packet, saddr, sport, daddr, dport, istcp, NULL, (char*)data, datalen, dataoffset, TYPE_RTP, 
			    false, dlt, sensor_id);
	}
}

/* analyze rtp packet */
void
Call::read_rtp(unsigned char* data, int datalen, int dataoffset, struct pcap_pkthdr *header, struct iphdr2 *header_ip, u_int32_t saddr, u_int32_t daddr, unsigned short sport, unsigned short dport, int iscaller, int *record,
	       char enable_save_packet, const u_char *packet, char istcp, int dlt, int sensor_id, char *ifname) {

	*record = 0;

	if(first_rtp_time == 0) {
		first_rtp_time = header->ts.tv_sec;
	}
	
	//RTP tmprtp; moved to Call structure to avoid creating and destroying class which is not neccessary
	tmprtp.fill(data, datalen, header, saddr, daddr, sport, dport);
	int curpayload = tmprtp.getPayload();
	unsigned int curSSRC = tmprtp.getSSRC();

	if((!opt_allow_zerossrc and curSSRC == 0) || tmprtp.getVersion() != 2) {
		// invalid ssrc
		goto end;
	}

	if(opt_dscp && !header_ip) {
		header_ip = (struct iphdr2 *)(data - sizeof(struct iphdr2) - sizeof(udphdr2));
	}

	if(iscaller) {
		last_rtp_a_packet_time = header->ts.tv_sec;
	} else {
		last_rtp_b_packet_time = header->ts.tv_sec;
	}

	for(int i = 0; i < ssrc_n; i++) {
		if(rtp[i]->ssrc2 == curSSRC 
#if RTP_BY_SRC_IP
		   && rtp[i]->saddr == saddr
#endif
		   && rtp[i]->dport == dport

		   ) {
			// found 
			if(opt_dscp) {
				rtp[i]->dscp = header_ip->tos >> 2;
				if(sverb.dscp) {
					cout << "rtpdscp " << (int)(header_ip->tos>>2) << endl;
				}
			}
			
			// chekc if packet is DTMF and saverfc2833 is enabled 
			if(opt_saverfc2833 and rtp[i]->codec == PAYLOAD_TELEVENT) {
				*record = 1;
			}
			// check if codec did not changed but ignore payload 13 and 19 which is CNG and 101 which is DTMF
			if(curpayload == 13 or curpayload == 19 or rtp[i]->codec == PAYLOAD_TELEVENT or rtp[i]->payload2 == curpayload) {
				goto read;
			} else {
				//codec changed, check if it is not DTMF 
				if(curpayload >= 96 && curpayload <= 127) {
					for(int j = 0; j < MAX_RTPMAP; j++) {
						if(rtp[i]->rtpmap[j] != 0 && curpayload == rtp[i]->rtpmap[j] / 1000) {
							rtp[i]->codec = rtp[i]->rtpmap[j] - curpayload * 1000;
						}      
					}      
				} else {
					rtp[i]->codec = curpayload;
				}
				if(rtp[i]->codec == PAYLOAD_TELEVENT) {
read:
					rtp[i]->read(data, datalen, header, saddr, daddr, sport, dport, seeninviteok, sensor_id, ifname);
					if(iscaller) {
						lastcallerrtp = rtp[i];
					} else {
						lastcalledrtp = rtp[i];
					}
					goto end;
				} else {
					//codec changed and it is not DTMF, reset ssrc so the stream will not match and new one is used
					rtp[i]->ssrc2 = 0;
				}
			}
		}
	}
	// adding new RTP source
	if(ssrc_n < MAX_SSRC_PER_CALL) {
		// close previouse graph files to save RAM (but only if > 10 
		if(flags & FLAG_SAVEGRAPH && ssrc_n > 6) {
			if(iscaller) {
				if(lastcallerrtp && lastcallerrtp->graph.isOpen()) {
					lastcallerrtp->graph.close();
				}
			} else {
				if(lastcalledrtp && lastcalledrtp->graph.isOpen()) {
					lastcalledrtp->graph.close();
				}
			}
		}

		// if previouse RTP streams are present it should be filled by silence to keep it in sync
		if(iscaller) {
			last_seq_audiobuffer1 = 0;
			if(lastcallerrtp) {
				lastcallerrtp->jt_tail(header);
			}
		} else { 
			last_seq_audiobuffer2 = 0;
			if(lastcalledrtp) {
				lastcalledrtp->jt_tail(header);
			}
		}
		while(rtplock) {
			//wait until the lock is released
			usleep(100);
		}
		rtplock = 1;
		rtp[ssrc_n] = new RTP(sensor_id);
		autoMemoryType(rtp[ssrc_n]);
		rtp[ssrc_n]->call_owner = this;
		rtp[ssrc_n]->ssrc_index = ssrc_n; 
		rtp[ssrc_n]->iscaller = iscaller; 
		if(rtp_cur[iscaller]) {
			rtp_prev[iscaller] = rtp_cur[iscaller];
		}
		rtp_cur[iscaller] = rtp[ssrc_n]; 
		
		if(opt_dscp) {
			rtp[ssrc_n]->dscp = header_ip->tos >> 2;
			if(sverb.dscp) {
				cout << "rtpdscp " << (int)(header_ip->tos>>2) << endl;
			}
		}

		char graphFilePath_spool_relative[1024];
		char graphFilePath[1024];
		snprintf(graphFilePath_spool_relative, 1023, "%s/%s/%s.%d.graph%s", dirname().c_str(), opt_newdir ? "GRAPH" : "", get_fbasename_safe(), ssrc_n, 
			 opt_gzipGRAPH == FileZipHandler::gzip ? ".gz" : "");
		graphFilePath_spool_relative[1023] = 0;
		if(opt_cachedir[0] != '\0') {
			snprintf(graphFilePath, 1023, "%s/%s", opt_cachedir, graphFilePath_spool_relative);
			graphFilePath[1023] = 0;
		} else {
			strcpy(graphFilePath, graphFilePath_spool_relative);
		}
		strcpy(rtp[ssrc_n]->gfilename, graphFilePath);
		if(flags & FLAG_SAVEGRAPH) {
			if(rtp[ssrc_n]->graph.open(graphFilePath, graphFilePath_spool_relative)) {
				rtp[ssrc_n]->graph.write((char*)&graph_version, 4); //every graph starts with graph_version 
			}
		}
		rtp[ssrc_n]->gfileRAW = NULL;
		snprintf(rtp[ssrc_n]->basefilename, 1023, "%s/%s/%s.i%d", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), !iscaller);
		rtp[ssrc_n]->basefilename[1023] = 0;

		if(RTPMAP_BY_CALLERD) {
			memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[isFillRtpMap(iscaller) ? iscaller : !iscaller], MAX_RTPMAP * sizeof(int));
		} else {
			int i = get_index_by_ip_port(saddr, sport);
			if(i >= 0 && isFillRtpMap(i)) {
				memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[i], MAX_RTPMAP * sizeof(int));
			} else {
				for(int j = 0; j < 2; j++) {
					i = getFillRtpMapByCallerd(j ? !iscaller : iscaller);
					if(i >= 0) {
						memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[i], MAX_RTPMAP * sizeof(int));
						break;
					}
				}
			}
		}

		rtp[ssrc_n]->read(data, datalen, header, saddr, daddr, sport, dport, seeninviteok, sensor_id, ifname);
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
		rtplock = 0;
		ssrc_n++;
	}
	
end:
	if(enable_save_packet && opt_rtpsave_threaded) {
		if((this->silencerecording || (opt_onlyRTPheader && !(this->flags & FLAG_SAVERTP))) && !this->isfax) {
			if(datalen >= RTP_FIXED_HEADERLEN &&
			   header->caplen > (unsigned)(datalen - RTP_FIXED_HEADERLEN)) {
				unsigned int tmp_u32 = header->caplen;
				header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
				save_packet(this, header, packet, saddr, sport, daddr, dport, istcp, NULL, (char*)data, datalen, dataoffset, TYPE_RTP, 
					    false, dlt, sensor_id);
				header->caplen = tmp_u32;
			}
		} else {
			save_packet(this, header, packet, saddr, sport, daddr, dport, istcp, NULL, (char*)data, datalen, dataoffset, TYPE_RTP, 
				    false, dlt, sensor_id);
		}
	}
}

void Call::stoprecording() {
	if(recordstopped == 0) {

		this->flags = 0;
		this->pcap.remove();
		this->pcapSip.remove();
		this->pcapRtp.remove();
		/****
		if(this->get_fsip_pcap() != NULL) {
			pcap_dump_flush(this->get_fsip_pcap());
			pcap_dump_close(this->get_fsip_pcap());
			this->set_fsip_pcap(NULL);
			if(opt_cachedir[0] != '\0') {
				snprintf(str2, 2047, "%s/%s.pcap", opt_cachedir, sip_pcapfilename.c_str());
			} else {
				snprintf(str2, 2047, "%s.pcap", sip_pcapfilename.c_str());
			}
			str2[2047] = 0;
			unlink(str2);	
		}
		if(this->get_frtp_pcap() != NULL) {
			pcap_dump_flush(this->get_frtp_pcap());
			pcap_dump_close(this->get_frtp_pcap());
			this->set_frtp_pcap(NULL);
			if(opt_cachedir[0] != '\0') {
				snprintf(str2, 2047, "%s/%s.pcap", opt_cachedir, rtp_pcapfilename.c_str());
			} else {
				snprintf(str2, 2047, "%s.pcap", rtp_pcapfilename.c_str());
			}
			str2[2047] = 0;
			unlink(str2);	
		}
		if(this->get_f_pcap() != NULL) {
			pcap_dump_flush(this->get_f_pcap());
			pcap_dump_close(this->get_f_pcap());
			this->set_f_pcap(NULL);
			if(opt_cachedir[0] != '\0') {
				snprintf(str2, 2047, "%s/%s.pcap", opt_cachedir, pcapfilename.c_str());
			} else {
				snprintf(str2, 2047, "%s.pcap", pcapfilename.c_str());
			}
			str2[2047] = 0;
			unlink(str2);	
		}
		****/

		this->recordstopped = 1;
		if(verbosity >= 1) {
			syslog(LOG_ERR,"Call %s/%s.pcap was stopped due to dtmf or norecord sip header. ", this->dirname().c_str(), this->get_fbasename_safe());
		}
	} else {
		if(verbosity >= 1) {
			syslog(LOG_ERR,"Call %s/%s.pcap was stopped before. Ignoring now. ", this->dirname().c_str(), this->get_fbasename_safe());
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

int convertALAW2WAV(char *fname1, char *fname3, int maxsamplerate) {
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
	if(!f_out) {
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
 
	bitstream_buf1 = new unsigned char[file_size1];
	autoMemoryType(bitstream_buf1);
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
 
int convertULAW2WAV(char *fname1, char *fname3, int maxsamplerate) {
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
	if(!f_out) {
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
 
	bitstream_buf1 = new unsigned char[file_size1];
	autoMemoryType(bitstream_buf1);
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

	char *tmp = new char[out.length() + 1];
	autoMemoryType(tmp);
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

	delete tmp;
	
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

	switch(opt_audio_format) {
	case FORMAT_WAV:
		snprintf(out, 1023, "%s/%s/%s.wav", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
		break;
	case FORMAT_OGG:
		snprintf(out, 1023, "%s/%s/%s.ogg", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
		break;
	}
	out[1023] = 0;

	/* caller direction */
	snprintf(rawInfo, 1023, "%s/%s/%s.i%d.rawInfo", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), 0);
	rawInfo[1023] = 0;
	pl = fopen(rawInfo, "r");
	if(pl) {
		adir = 1;
		fgets(line, sizeof(line), pl);
		fclose(pl);
		sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
		snprintf(wav0, 1023, "%s/%s/%s.i%d.wav", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), 0);
		wav0[1023] = 0;
	}

	/* called direction */
	snprintf(rawInfo, 1023, "%s/%s/%s.i%d.rawInfo", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), 1);
	rawInfo[1023] = 0;
	pl = fopen(rawInfo, "r");
	if(pl) {
		bdir = 1;
		fgets(line, sizeof(line), pl);
		fclose(pl);
		sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv1.tv_sec, &tv1.tv_usec);
		snprintf(wav1, 1023, "%s/%s/%s.i%d.wav", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), 1);
		wav1[1023] = 0;
	}

	if(adir == 0 && bdir == 0) {
		syslog(LOG_ERR, "PCAP file %s/%s/%s.pcap cannot be decoded to WAV probably missing RTP\n", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
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
					mkdir_r(fileNameWav, 0777);
					*pointToLastDirSeparator = '/';
				} else {
					break;
				}
			}
			wav = fopen(fileNameWav, "w");
			if(wav) {
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
		}
		for(int i = 0; i < (abs(msdiff) / 20) * samplerate / 50; i++) {
			fwrite(&zero, 1, 2, wav);
		}
		fclose(wav);
		/* end synchronisation */
	}

	/* process all files in playlist for each direction */
	int samplerate = 8000;
	for(int i = 0; i <= 1; i++) {
		char *wav = NULL;
		if(i == 0 and adir == 0) continue;
		if(i == 1 and bdir == 0) continue;
		wav = i == 0 ? wav0 : wav1;

		/* open playlist */
		snprintf(rawInfo, 1023, "%s/%s/%s.i%d.rawInfo", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), i);
		rawInfo[1023] = 0;
		pl = fopen(rawInfo, "r");
		if(!pl) {
			syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
			return 1;
		}
		int maxsamplerate = 0;
		// get max sample rate 
		while(fgets(line, 256, pl)) {
			char raw[1024];
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			snprintf(raw, 1023, "%s/%s/%s.i%d.%d.%lu.%d.%ld.%ld.raw", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);
			samplerate = 1000 * get_ticks_bycodec(codec);
			if(maxsamplerate < samplerate) {
				maxsamplerate = samplerate;
			}
		}
		// rewind rawInfo file and process one by one
		rewind(pl);
		while(fgets(line, 256, pl)) {
			char raw[1024];
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			snprintf(raw, 1023, "%s/%s/%s.i%d.%d.%lu.%d.%ld.%ld.raw", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);
			raw[1023] = 0;
			switch(codec) {
			case PAYLOAD_PCMA:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMA to WAV.\n");
				convertALAW2WAV(raw, wav, maxsamplerate);
				samplerate = 8000;
				break;
			case PAYLOAD_PCMU:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMU to WAV.\n");
				convertULAW2WAV(raw, wav, maxsamplerate);
				samplerate = 8000;
				break;
		/* following decoders are not included in free version. Please contact support@voipmonitor.org */
			case PAYLOAD_G722:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g722 \"%s\" \"%s\" 64000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g722 \"%s\" \"%s\" 64000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.722 to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.722 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_G7221:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s siren \"%s\" \"%s\" 16000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-siren \"%s\" \"%s\" 16000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 32000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.7221 to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.7221 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_G722116:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s siren \"%s\" \"%s\" 16000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-siren \"%s\" \"%s\" 16000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.7221 to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.7221 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_G722132:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s siren \"%s\" \"%s\" 32000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-siren \"%s\" \"%s\" 32000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 32000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.7221c to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.7221 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_GSM:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s gsm \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-gsm \"%s\" \"%s\"", raw, wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting GSM to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_G729:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g729 \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g729 \"%s\" \"%s\"", raw, wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.729 to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_G723:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s g723 \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-g723 \"%s\" \"%s\"", raw, wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.723 to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_ILBC:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s ilbc \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-ilbc \"%s\" \"%s\"", raw, wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting iLBC to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_SPEEX:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s speex \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-speex \"%s\" \"%s\"", raw, wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting speex to WAV.\n");
				samplerate = 8000;
				system(cmd);
				break;
			case PAYLOAD_SILK8:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 8000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 8000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK8 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK12:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 12000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 12000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 12000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK12 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 16000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 16000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK24:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s silk \"%s\" \"%s\" 24000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-silk \"%s\" \"%s\" 24000", raw, wav);
				}
				cmd[cmd_len] = 0;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK16 to WAV.\n");
				samplerate = 24000;
				system(cmd);
				break;
			case PAYLOAD_ISAC16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s isac \"%s\" \"%s\" 16000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-isac \"%s\" \"%s\" 16000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting ISAC16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_ISAC32:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s isac \"%s\" \"%s\" 32000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-isac \"%s\" \"%s\" 32000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 32000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting ISAC32 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS8:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 8000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 8000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS8 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS12:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 12000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 12000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 12000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS12 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 16000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 16000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS24:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 24000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 24000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 24000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS24 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_OPUS48:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, cmd_len, "vmcodecs %s opus \"%s\" \"%s\" 48000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, cmd_len, "vmcodecs-opus %s a opus \"%s\" \"%s\" 48000", opt_keycheck, raw, wav);
					cout << cmd << "\n";
					//snprintf(cmd, cmd_len, "voipmonitor-opus \"%s\" \"%s\" 48000", raw, wav);
				}
				cmd[cmd_len] = 0;
				samplerate = 48000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting OPUS48 to WAV.\n");
				system(cmd);
				break;
			default:
				syslog(LOG_ERR, "Call [%s] cannot be converted to WAV, unknown payloadtype [%d]\n", raw, codec);
			}
			if(!sverb.noaudiounlink) unlink(raw);
		}
		fclose(pl);
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
		switch(opt_audio_format) {
		case FORMAT_WAV:
			if(!opt_saveaudio_reversestereo) {
				wav_mix(wav0, wav1, out, samplerate, 0, opt_saveaudio_stereo);
			} else {
				wav_mix(wav1, wav0, out, samplerate, 0, opt_saveaudio_stereo);
			}
			break;
		case FORMAT_OGG:
			if(!opt_saveaudio_reversestereo) {
				ogg_mix(wav0, wav1, out, opt_saveaudio_stereo, samplerate, opt_saveaudio_oggquality, 0);
			} else {
				ogg_mix(wav1, wav0, out, opt_saveaudio_stereo, samplerate, opt_saveaudio_oggquality, 0);
			}
			break;
		}
		if(!sverb.noaudiounlink) unlink(wav0);
		if(!sverb.noaudiounlink) unlink(wav1);
	} else if(adir == 1) {
		// there is only caller sound
		switch(opt_audio_format) {
		case FORMAT_WAV:
			wav_mix(wav0, NULL, out, samplerate, 0, opt_saveaudio_stereo);
			break;
		case FORMAT_OGG:
			ogg_mix(wav0, NULL, out, opt_saveaudio_stereo, samplerate, opt_saveaudio_oggquality, 0);
			break;
		}
		if(!sverb.noaudiounlink) unlink(wav0);
	} else if(bdir == 1) {
		// there is only called sound
		switch(opt_audio_format) {
		case FORMAT_WAV:
			wav_mix(wav1, NULL, out, samplerate, 1, opt_saveaudio_stereo);
			break;
		case FORMAT_OGG:
			ogg_mix(wav1, NULL, out, opt_saveaudio_stereo, samplerate, opt_saveaudio_oggquality, 1);
			break;
		}
		if(!sverb.noaudiounlink) unlink(wav1);
	}
	string tmp;
	tmp.append(out);
	addtofilesqueue(tmp, "audiosize", 0);
 
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

	if(!sqlDbSaveCall) {
		sqlDbSaveCall = createSqlObject();
	}

	if((opt_cdronlyanswered and !connect_time) or 
		(opt_cdronlyrtp and !ssrc_n)) {
		// skip this CDR 
		return 1;
	}
	
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
			/*
			cdr_phone_number_caller,
			cdr_phone_number_called,
			cdr_name,
			cdr_domain_caller,
			cdr_domain_called,
			*/
			cdr_sip_response,
			cdr_ua_a,
			cdr_ua_b,	
			cdr_proxy;
	unsigned int /*
			caller_id = 0,
			called_id = 0,
			callername_id = 0,
			caller_domain_id = 0,
			called_domain_id = 0,
			*/
			lastSIPresponse_id = 0,
			a_ua_id = 0,
			b_ua_id = 0;

	string query_str_cdrproxy;

	if(opt_cdrproxy) {

		// remove duplicates
		list<unsigned int>::iterator iter = proxies.begin();
		set<unsigned int> proxies_undup;
		while (iter != proxies.end()) {
			if (proxies_undup.find(*iter) == proxies_undup.end()) {
				proxies_undup.insert(*iter);
			}
			++iter;
		}

		set<unsigned int>::iterator iter_undup = proxies_undup.begin();
		while (iter_undup != proxies_undup.end()) {
			if(*iter_undup == sipcalledip[0]) { ++iter_undup; continue; };
			sqlDbSaveCall->setEnableSqlStringInContent(true);
			SqlDb_row cdrproxy;
			cdrproxy.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
			cdrproxy.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
			cdrproxy.add(htonl(*iter_undup), "dst");
			query_str_cdrproxy += sqlDbSaveCall->insertQuery("cdr_proxy", cdrproxy) + ";\n";
			sqlDbSaveCall->setEnableSqlStringInContent(false);

			++iter_undup;
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

	unsigned int dscp_a = caller_sipdscp,
		     dscp_b = called_sipdscp,
		     dscp_c = 0,
		     dscp_d = 0;
	
	cdr.add(htonl(sipcallerip[0]), "sipcallerip");
	cdr.add(htonl(sipcalledip[0]), "sipcalledip");
	if(opt_cdr_sipport) {
		cdr.add(sipcallerport, "sipcallerport");
		cdr.add(sipcalledport, "sipcalledport");
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
	if(opt_last_rtp_from_end) {
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
	} else if(oneway) {
		bye = 101;
	} else {
		bye = pcap_drop ? 100 :
		      (seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0);
	}
	cdr.add(bye, "bye");

	if(strlen(match_header)) {
		cdr_next.add(sqlEscapeString(match_header), "match_header");
	}
	if(strlen(custom_header1)) {
		cdr_next.add(sqlEscapeString(custom_header1), "custom_header1");
	}
	for(map<string, string>::iterator iCustHeadersIter = custom_headers.begin(); iCustHeadersIter != custom_headers.end(); iCustHeadersIter++) {
		cdr_next.add(sqlEscapeString(iCustHeadersIter->second), iCustHeadersIter->first);
	}
	if(existsColumnCalldateInCdrNext) {
		cdr_next.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
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

	if(a_mos_lqo != -1) {
		int mos = a_mos_lqo * 10;
		cdr.add(mos, "a_mos_lqo_mult10");
	}
	if(b_mos_lqo != -1) {
		int mos = b_mos_lqo * 10;
		cdr.add(mos, "b_mos_lqo_mult10");
	}
	
	if(ssrc_n > 0) {
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
		for(int k = 0; k < ssrc_n; k++) {
			if(sverb.process_rtp) {
				cout << "RTP - final stream: " 
				     << hex << rtp[indexes[k]]->ssrc << dec << " : "
				     << inet_ntostring(htonl(rtp[indexes[k]]->saddr)) << " -> "
				     << inet_ntostring(htonl(rtp[indexes[k]]->daddr)) << " / "
				     << (rtp[indexes[k]]->iscaller ? "caller" : "called") 
				     << " packets received: " << rtp[indexes[k]]->s->received << " "
				     << " ssrc index: " << rtp[indexes[k]]->ssrc_index << " "
				     << endl;
			}
			if(rtp[indexes[k]]->iscaller && (!rtpab[0] || rtp[indexes[k]]->stats.received > rtpab[0]->stats.received)) {
				rtpab[0] = rtp[indexes[k]];
			}
			if(!rtp[indexes[k]]->iscaller && (!rtpab[1] || rtp[indexes[k]]->stats.received > rtpab[1]->stats.received)) {
				rtpab[1] = rtp[indexes[k]];
			}
		}

		cdr_ua_a.add(sqlEscapeString(a_ua), "ua");
		cdr_ua_b.add(sqlEscapeString(b_ua), "ua");

		if(opt_silencedetect) {
			if(caller_silence > 0 or caller_silence > 0) {
				cdr.add(caller_silence * 100 / (caller_silence + caller_noise), "caller_silence");
			}
			if(called_silence > 0 or called_noise > 0) {
				cdr.add(called_silence * 100 / (called_silence + called_noise), "called_silence");
			}
			cdr.add(caller_lastsilence / 1000, "caller_silence_end");
			cdr.add(called_lastsilence / 1000, "called_silence_end");
		}
		if(opt_clippingdetect) {
			cdr.add(caller_clipping_8k / 100 > 255 ? 255 : caller_clipping_8k / 100, "caller_clipping_mult100");
			cdr.add(called_clipping_8k / 100 > 255 ? 255 : called_clipping_8k / 100, "called_clipping_mult100");
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
			cdr.add(rtpab[i]->stats.received + 2, c+"_received"); // received is always 2 packet less compared to wireshark (add it here)
			lost[i] = rtpab[i]->stats.lost;
			cdr.add(lost[i], c+"_lost");
			packet_loss_perc_mult1000[i] = (int)round((double)rtpab[i]->stats.lost / 
									(rtpab[i]->stats.received + 2 + rtpab[i]->stats.lost) * 100 * 1000);
			cdr.add(packet_loss_perc_mult1000[i], c+"_packet_loss_perc_mult1000");
			jitter_mult10[i] = int(ceil(rtpab[i]->stats.avgjitter)) * 10; // !!!
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

			// calculate lossrate and burst rate
			double burstr, lossr;
			burstr_calculate(rtpab[i]->channel_fix1, rtpab[i]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_f1");
			//cdr.add(burstr, c+"_burstr_f1");
			int mos_f1_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			cdr.add(mos_f1_mult10, c+"_mos_f1_mult10");
			if(mos_f1_mult10) {
				mos_min_mult10[i] = mos_f1_mult10;
			}

			// Jitterbuffer MOS statistics
			burstr_calculate(rtpab[i]->channel_fix2, rtpab[i]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_f2");
			//cdr.add(burstr, c+"_burstr_f2");
			int mos_f2_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			cdr.add(mos_f2_mult10, c+"_mos_f2_mult10");
			if(mos_f2_mult10 && (mos_min_mult10[i] < 0 || mos_f2_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_f2_mult10;
			}

			burstr_calculate(rtpab[i]->channel_adapt, rtpab[i]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_adapt");
			//cdr.add(burstr, c+"_burstr_adapt");
			int mos_adapt_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->first_codec, rtpab[i]->stats.received) * 10);
			cdr.add(mos_adapt_mult10, c+"_mos_adapt_mult10");
			if(mos_adapt_mult10 && (mos_min_mult10[i] < 0 || mos_adapt_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_adapt_mult10;
			}

			if(mos_f2_mult10 && opt_mosmin_f2) {
				mos_min_mult10[i] = mos_f2_mult10;
			}
			
			if(mos_min_mult10[i] >= 0) {
				cdr.add(mos_min_mult10[i], c+"_mos_min_mult10");
			}

			if(rtpab[i]->rtcp.counter) {
				cdr.add(rtpab[i]->rtcp.loss, c+"_rtcp_loss");
				cdr.add(rtpab[i]->rtcp.maxfr, c+"_rtcp_maxfr");
				rtcp_avgfr_mult10[i] = (int)round(rtpab[i]->rtcp.avgfr * 10);
				cdr.add(rtcp_avgfr_mult10[i], c+"_rtcp_avgfr_mult10");
				cdr.add(rtpab[i]->rtcp.maxjitter / get_ticks_bycodec(rtpab[i]->first_codec), c+"_rtcp_maxjitter");
				rtcp_avgjitter_mult10[i] = (int)round(rtpab[i]->rtcp.avgjitter / get_ticks_bycodec(rtpab[i]->first_codec) * 10);
				cdr.add(rtcp_avgjitter_mult10[i], c+"_rtcp_avgjitter_mult10");
			}
		}
		if(seenudptl) {
			// T.38
			cdr.add(1000, "payload");
		} else if(isfax == 2) {
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

	}

	if(opt_dscp) {
		cdr.add((dscp_a << 24) + (dscp_b << 16) + (dscp_c << 8) + dscp_d, "dscp");
	}
	
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		
		sqlDbSaveCall->setEnableSqlStringInContent(true);
		
		cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
		if(opt_cdr_ua_enable) {
			if(a_ua) {
				cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
			}
			if(b_ua) {
				cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
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
					     "  delete from cdr_next where cdr_id = @exists_call_id;\n" +
					     "  delete from cdr_rtp where cdr_id = @exists_call_id;\n" +
					     (opt_dbdtmf ? "delete from cdr_dtmf where cdr_id = @exists_call_id\n" : "") +
					     (opt_pcap_dump_tar ? "delete from cdr_tar_part where cdr_id = @exists_call_id\n" : "") +
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
			if(rtp[i] and rtp[i]->s->received) {
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
				if(opt_cdr_rtpport) {
					rtps.add(rtp[i]->dport, "dport");
				}
				rtps.add(rtp[i]->ssrc, "ssrc");
				rtps.add(rtp[i]->s->received + 2, "received");
				rtps.add(rtp[i]->stats.lost, "loss");
				rtps.add((unsigned int)(rtp[i]->stats.maxjitter * 10), "maxjitter_mult10");
				rtps.add(diff, "firsttime");
				if(existsColumnCalldateInCdrRtp) {
					rtps.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDbSaveCall->insertQuery("cdr_rtp", rtps) + ";\n";
			}
		}

		if(opt_dbdtmf) {
			while(dtmf_history.size()) {
				dtmfq q;
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
				if(existsColumnCalldateInCdrDtmf) {
					dtmf.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDbSaveCall->insertQuery("cdr_dtmf", dtmf) + ";\n";
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
					if(existsColumnCalldateInCdrDtmf) {
						tar_part.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
					}
					query_str += sqlDbSaveCall->insertQuery("cdr_tar_part", tar_part) + ";\n";
				}
			}
		}
		
		sqlDbSaveCall->setEnableSqlStringInContent(false);
		
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
	if(cdr_ua_a) {
		a_ua_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_a);
	}
	if(cdr_ua_b) {
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
	cdr.add(a_ua_id, "a_ua_id", true);
	cdr.add(b_ua_id, "b_ua_id", true);
	
	int cdrID = sqlDbSaveCall->insert(sql_cdr_table, cdr);


	if(cdrID > 0) {

		if(opt_cdrproxy) {
			// remove duplicates
			list<unsigned int>::iterator iter = proxies.begin();
			set<unsigned int> elements;
			while (iter != proxies.end()) {
				if (elements.find(*iter) != elements.end()) {
					iter = proxies.erase(iter);
				} else {
					elements.insert(*iter);
					++iter;
				}
			}

			iter = proxies.begin();
			while (iter != proxies.end()) {
				if(*iter == sipcalledip[0]) { ++iter; continue; };
				SqlDb_row cdrproxy;
				cdrproxy.add(cdrID, "cdr_ID");
				cdrproxy.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				cdrproxy.add(htonl(*iter), "dst");
				sqlDbSaveCall->insert("cdr_proxy", cdrproxy);
				++iter;
			}
		}

		for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
			// lets check whole array as there can be holes due rtp[0] <=> rtp[1] swaps in mysql rutine
			if(rtp[i] and rtp[i]->s->received) {
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
				if(opt_cdr_rtpport) {
					rtps.add(rtp[i]->dport, "dport");
				}
				rtps.add(rtp[i]->ssrc, "ssrc");
				rtps.add(rtp[i]->s->received + 2, "received");
				rtps.add(rtp[i]->stats.lost, "loss");
				rtps.add((unsigned int)(rtp[i]->stats.maxjitter * 10), "maxjitter_mult10");
				rtps.add(diff, "firsttime");
				if(existsColumnCalldateInCdrRtp) {
					rtps.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				sqlDbSaveCall->insert("cdr_rtp", rtps);
			}
		}

		if(opt_dbdtmf) {
			while(dtmf_history.size()) {
				dtmfq q;
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
				if(existsColumnCalldateInCdrDtmf) {
					dtmf.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				sqlDbSaveCall->insert("cdr_dtmf", dtmf);
			}
		}

		if(opt_printinsertid) {
			printf("CDRID:%d\n", cdrID);
		}

		cdr_next.add(cdrID, "cdr_ID");
		sqlDbSaveCall->insert(sql_cdr_next_table, cdr_next);
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

/* TODO: implement failover -> write INSERT into file */
int
Call::saveRegisterToDb(bool enableBatchIfPossible) {
 
	if(this->msgcount <= 1 or this->lastSIPresponseNum == 401 or this->lastSIPresponseNum == 403) {
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
	}

	const char *register_table = "register";
	
	string query;

	SqlDb_row cdr_ua;
	cdr_ua.add(sqlEscapeString(a_ua), "ua");

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

	char fname[32];
	snprintf(fname, 31, "%llu", fname2);
	fname[31] = 0;

	switch(regstate) {
	case 1:
	case 3:
		if(enableBatchIfPossible && isTypeDb("mysql")) {
			char ips[32];
			char ipd[32];
			char tmpregstate[32];
			char regexpires[32];
			char idsensor[12];
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
				fname + ", " +
				idsensor +
				")";
			sqlStore->query_lock(query.c_str(), storeId);
		} else {
			query = string(
				"SELECT ID, state, ") +
				       "UNIX_TIMESTAMP(expires_at) AS expires_at, " +
				       "_LC_[(UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(" + sqlEscapeStringBorder(sqlDateTimeString(calltime())) + "))] AS expired " +
				"FROM " + register_table + " " +
				"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND to_domain = " + sqlEscapeStringBorder(called_domain) + " AND " +
				      "contact_num = " + sqlEscapeStringBorder(contact_num) + " AND contact_domain = " + sqlEscapeStringBorder(contact_domain) + 
				      //" AND digestusername = " + sqlEscapeStringBorder(digest_username) + " " +
				"ORDER BY ID DESC"; // LIMIT 1 
//			if(verbosity > 2) cout << query << "\n";
			{
			if(!sqlDbSaveCall->query(query)) {
				syslog(LOG_ERR, "Error: Query [%s] failed.", query.c_str());
				break;
			}

			SqlDb_row rsltRow = sqlDbSaveCall->fetchRow();
			if(rsltRow) {
				// REGISTER message is already in register table, delete old REGISTER and save the new one 
				int expired = atoi(rsltRow["expired"].c_str()) == 1;
				time_t expires_at = atoi(rsltRow["expires_at"].c_str());

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
					reg.add(fname, "fname");
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
					reg.add(fname, "fname");
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
				reg.add(fname, "fname");
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
				reg.add(fname, "fname");
				reg.add(useSensorId, "id_sensor");
				reg.add(regstate, "state");
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

			char fname[32];
			snprintf(fname, 31, "%llu", fname2);
			fname[31] = 0;
			string q2 = string(
				"UPDATE register_failed SET created_at = '" + calldate_str + "', fname = " + sqlEscapeStringBorder(fname) + ", counter = counter + " + cnt.str()) +
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

			sqlDbSaveCall->setEnableSqlStringInContent(true);

			reg.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "ua_id");

//			reg.add(sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");

			reg.add(fname, "fname");
			if(useSensorId > -1) {
				reg.add(useSensorId, "id_sensor");
			}
			string q3 = sqlDbSaveCall->insertQuery("register_failed", reg);

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
				char fname[32];
				snprintf(fname, 31, "%llu", fname2);
				fname[31] = 0;
				if(rsltRow) {
					// there is already failed register, update counter and do not insert
					string query = string(
						"UPDATE register_failed SET created_at = '" + calldate_str+ "', fname = " + sqlEscapeStringBorder(fname) + ", counter = counter + 1 ") +
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
					reg.add(fname, "fname");
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
	}

	SqlDb_row cdr,
			m_contenttype,
			cdr_sip_response,
			cdr_ua_a,
			cdr_ua_b;
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

	cdr_sip_response.add(sqlEscapeString(lastSIPresponse), "lastSIPresponse");

	cdr.add(htonl(sipcallerip[0]), "sipcallerip");
	cdr.add(htonl(sipcalledip[0]), "sipcalledip");
	cdr.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
	if(!geoposition.empty()) {
		cdr.add(sqlEscapeString(geoposition), "GeoPosition");
	}
	cdr.add(sqlEscapeString(fbasename), "fbasename");
	if(message) {
		if(flags & FLAG_HIDEMESSAGE) {
			cdr.add("SHA256: " + GetStringSHA256(trim_str(message) + trim_str(opt_hide_message_content_secret)), "message");
		} else {
			cdr.add(sqlEscapeString(message), "message");
		}
	}
	extern bool exists_column_message_content_length;
	if(exists_column_message_content_length && content_length) {
		cdr.add(content_length, "content_length");
	}

	cdr.add(lastSIPresponseNum, "lastSIPresponseNum");
/*
	if(strlen(match_header)) {
		cdr_next.add(sqlEscapeString(match_header), "match_header");
	}
	if(strlen(custom_header1)) {
		cdr_next.add(sqlEscapeString(custom_header1), "custom_header1");
	}
*/
	for(map<string, string>::iterator iCustHeadersIter = custom_headers.begin(); iCustHeadersIter != custom_headers.end(); iCustHeadersIter++) {
		cdr.add(sqlEscapeString(iCustHeadersIter->second), iCustHeadersIter->first);
	}


	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		
		sqlDbSaveCall->setEnableSqlStringInContent(true);
		
		cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
		if(a_ua) {
			cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
		}
		if(b_ua) {
			cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
		}
		if(contenttype) {
			cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertCONTENTTYPE(" + sqlEscapeStringBorder(contenttype) + ")", "id_contenttype");
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
		
		query_str += sqlDbSaveCall->insertQuery("message", cdr);
		
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
	cdr_ua_a.add(sqlEscapeString(a_ua), "ua");
	a_ua_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_a);
	cdr_ua_b.add(sqlEscapeString(b_ua), "ua");
	b_ua_id = sqlDbSaveCall->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_b);
	if(contenttype) {
		m_contenttype.add(sqlEscapeString(contenttype), "contenttype");
		unsigned int id_contenttype = sqlDbSaveCall->getIdOrInsert("contenttype", "id", "contenttype", m_contenttype);
		cdr.add(id_contenttype, "id_contenttype");
	}

	cdr.add(lastSIPresponse_id, "lastSIPresponse_id", true);
	cdr.add(a_ua_id, "a_ua_id", true);
	cdr.add(b_ua_id, "b_ua_id", true);

	int cdrID = sqlDbSaveCall->insert("message", cdr);

	return(cdrID <= 0);

}

char *
Call::get_fbasename_safe() {
	strncpy(fbasename_safe, fbasename, MAX_FNAME * sizeof(char));
	for(unsigned int i = 0; i < strlen(fbasename_safe) && i < MAX_FNAME; i++) {
		if(strchr(opt_convert_char, fbasename[i]) || 
		   !(fbasename[i] == ':' || fbasename[i] == '-' || fbasename[i] == '.' || fbasename[i] == '@' || 
		   isalnum(fbasename[i])) ) {

			fbasename_safe[i] = '_';
		}
	}
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
	extern char pcapcommand[4092];
	if(pcapcommand[0]) {
		extern char opt_chdir[1024];
		string source(pcapcommand);
		string find1 = "%pcap%";
		string find2 = "%basename%";
		string find3 = "%dirname%";
		string replace;
		replace.append("\"");
		replace.append(opt_chdir);
		replace.append("/");
		replace.append(this->dirname());
		replace.append("/");
		replace.append(this->fbasename);
		replace.append(".pcap");
		replace.append("\"");
		find_and_replace(source, find1, replace);
		find_and_replace(source, find2, this->fbasename);
		find_and_replace(source, find3, this->dirname());
		if(verbosity >= 2) printf("command: [%s]\n", source.c_str());
		system(source.c_str());
	};
	extern char filtercommand[4092];
	if(filtercommand[0]/* && this->flags & FLAG_RUNSCRIPT*/) {
		string source(filtercommand);
		string tmp = this->fbasename;
		find_and_replace(source, string("%callid%"), escapeshellR(tmp));
		tmp = this->dirname();
		find_and_replace(source, string("%dirname%"), escapeshellR(tmp));
		tmp = sqlDateTimeString(this->calltime());
		find_and_replace(source, string("%calldate%"), escapeshellR(tmp));
		tmp = this->caller;
		find_and_replace(source, string("%caller%"), escapeshellR(tmp));
		tmp = this->called;
		find_and_replace(source, string("%called%"), escapeshellR(tmp));
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

/* constructor */
Calltable::Calltable() {
	pthread_mutex_init(&qlock, NULL);
	pthread_mutex_init(&qdellock, NULL);
	pthread_mutex_init(&flock, NULL);

	pthread_mutex_init(&calls_listMAPlock, NULL);
	pthread_mutex_init(&calls_mergeMAPlock, NULL);

	memset(calls_hash, 0x0, sizeof(calls_hash));
	_sync_lock_calls_hash = 0;
};

/* destructor */
Calltable::~Calltable() {
	pthread_mutex_destroy(&qlock);
	pthread_mutex_destroy(&qdellock);
	pthread_mutex_destroy(&flock);
	pthread_mutex_destroy(&calls_listMAPlock);
	pthread_mutex_destroy(&calls_mergeMAPlock);
};

/* add node to hash. collisions are linked list of nodes*/
void
Calltable::mapAdd(in_addr_t addr, unsigned short port, Call* call, int iscaller, int is_rtcp, int is_fax) {

	if (ipportmap.find(addr) != ipportmap.end()) {
		ipportmapIT = ipportmap[addr].find(port);
		if(ipportmapIT != ipportmap[addr].end()) {
			// there is already some call which is receiving packets to the same IP:port
			// this can happen if the old call is waiting for hangup and is still in memory
			Ipportnode *node = (*ipportmapIT).second;
			if(call != node->call) {
				// just replace this IP:port to new call
				node->call = call;
				node->iscaller = iscaller;
				node->is_rtcp = is_rtcp;
				node->is_fax = is_fax;
				return;
			// or it can happen if voipmonitor is sniffing SIP proxy which forwards SIP
			} else {
				// packets to another SIP proxy with the same SDP ports
				// in this case just return 
				return;
			}
		}
	}
	
	// adding to hash at first position
	Ipportnode *node = new Ipportnode;
	autoMemoryType(node);
	memset(node, 0x0, sizeof(Ipportnode));
	node->call = call;
	node->iscaller = iscaller;
	node->is_rtcp = is_rtcp;
	node->is_fax = is_fax;
	ipportmap[addr][port] = node;
}


/* add node to hash. collisions are linked list of nodes*/
void
Calltable::hashAdd(in_addr_t addr, unsigned short port, Call* call, int iscaller, int is_rtcp, int is_fax, int allowrelation) {
	if(call->end_call) {
		return;
	}

	u_int32_t h;
	hash_node *node = NULL;
	hash_node_call *node_call = NULL;

	h = tuplehash(addr, port);
	//allowrelation = 1;
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
				if(node_call->call->destroy_call_at != 0) {
					// remove this call
					if(prev) {
						prev->next = node_call->next;
						delete node_call;
						node_call = prev->next;
						continue;
					} else {
						//removing first node
						node->calls = node->calls->next;
						delete node_call;
						node_call = node->calls;
						continue;
					}
				}
				prev = node_call;
				count++;
				node_call->is_fax = is_fax;
				if(node_call->call == call) {
					found = 1;
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
				hash_node_call *node_call_new = new hash_node_call;
				autoMemoryType(node_call_new);
				node_call_new->next = node->calls;
				node_call_new->call = call;
				node_call_new->iscaller = iscaller;
				node_call_new->is_rtcp = is_rtcp;
				node_call_new->is_fax = is_fax;

				//insert at first position
				node->calls = node_call_new;
				
			}
			unlock_calls_hash();
			return;
		}
	}

	// addr / port combination not found - add it to hash at first position

	node_call = new hash_node_call;
	autoMemoryType(node_call);
	node_call->next = NULL;
	node_call->call = call;
	node_call->iscaller = iscaller;
	node_call->is_rtcp = is_rtcp;
	node_call->is_fax = is_fax;

	node = new hash_node;
	autoMemoryType(node);
	memset(node, 0x0, sizeof(hash_node));
	node->addr = addr;
	node->port = port;
	node->next = (hash_node *)calls_hash[h];
	node->calls = node_call;
	calls_hash[h] = node;
	unlock_calls_hash();
}

/* remove node from hash */
void
Calltable::hashRemove(Call *call, in_addr_t addr, unsigned short port) {
	hash_node *node = NULL, *prev = NULL;
	hash_node_call *node_call = NULL, *prev_call = NULL;
	int h;

	h = tuplehash(addr, port);
	lock_calls_hash();
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if (node->addr == addr && node->port == port) {
			for (node_call = (hash_node_call *)node->calls; node_call != NULL; node_call = node_call->next) {
				// walk through all calls under the node and check if the call matches
				if(node_call->call == call) {
					// call matches - remote the call from node->calls
					if (prev_call == NULL) {
						node->calls = node_call->next;
						delete node_call;
						break; 
					} else {
						prev_call->next = node_call->next;
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

/* remove node from hash */
void
Calltable::mapRemove(in_addr_t addr, unsigned short port) {
	if (ipportmap.find(addr) != ipportmap.end()) {
		ipportmapIT = ipportmap[addr].find(port);
		if(ipportmapIT != ipportmap[addr].end()) {
			Ipportnode *node = (*ipportmapIT).second;
			delete node;
			ipportmap[addr].erase(ipportmapIT);
		}
	}
}

void
Calltable::destroyCallsIfPcapsClosed() {
	this->lock_calls_deletequeue();
	if(this->calls_deletequeue.size() > 0) {
		size_t size = this->calls_deletequeue.size();
		for(size_t i = 0; i < size;) {
			Call *call = this->calls_deletequeue[i];
			if(call->isPcapsClose()) {
				call->removeFindTables();
				call->atFinish();
				delete call;
				calls_counter--;
				this->calls_deletequeue.erase(this->calls_deletequeue.begin() + i);
				--size;
			} else {
				i++;
			}
		}
	}
	this->unlock_calls_deletequeue();
}

/* find call in hash */
Call*
Calltable::mapfind_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller, int *is_rtcp, int *is_fax) {


	if (ipportmap.find(addr) != ipportmap.end()) {
		ipportmapIT = ipportmap[addr].find(port);
		if(ipportmapIT != ipportmap[addr].end()) {
			Ipportnode *node = (*ipportmapIT).second;
			*iscaller = node->iscaller;
			*is_rtcp = node->is_rtcp;
			*is_fax = node->is_fax;
			return node->call;
		}
	}
	return NULL;
}

/* find call in hash */
hash_node_call*
Calltable::hashfind_by_ip_port(in_addr_t addr, unsigned short port, unsigned int hash, bool lock) {
	hash_node *node = NULL;
	u_int32_t h;

	h = hash ? hash : tuplehash(addr, port);
	if(lock) {
		lock_calls_hash();
	}
	hash_node_call *rslt = NULL;
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			rslt = node->calls;
//			*iscaller = node->iscaller;
//			*is_rtcp = node->is_rtcp;
//			*is_fax = node->is_fax;
//			return node->call;
		}
	}
	if(lock) {
		unlock_calls_hash();
	}
	return rslt;
}

Call*
Calltable::add(char *call_id, unsigned long call_id_len, time_t time, u_int32_t saddr, unsigned short port,
	       pcap_t *handle, int dlt, int sensorId
) {
	Call *newcall = new Call(call_id, call_id_len, time);
	autoMemoryType(newcall);

	if(handle) {
		newcall->useHandle = handle;
	}
	if(dlt) {
		newcall->useDlt = dlt;
	}
	if(sensorId > -1) {
		newcall->useSensorId = sensorId;
	}
	calls_counter++;
	newcall->saddr = saddr;
	newcall->sport = port;
	
	//flags
	if(opt_saveSIP) 
		newcall->flags |= FLAG_SAVESIP;

	if(opt_saveRTP) 
		newcall->flags |= FLAG_SAVERTP;

	if(opt_onlyRTPheader)  {
		newcall->flags |= FLAG_SAVERTPHEADER;
	}

	if(opt_saveWAV) 
		newcall->flags |= FLAG_SAVEWAV;

	if(opt_saveGRAPH) 
		newcall->flags |= FLAG_SAVEGRAPH;

//	if(opt_sip_register) 
//		newcall->flags |= FLAG_SAVEREGISTER;

	string call_idS = string(call_id, call_id_len);
	lock_calls_listMAP();
	calls_listMAP[call_idS] = newcall;
	unlock_calls_listMAP();
	return newcall;
}

/* find Call by SIP call-id and  return reference to this Call */
Call*
Calltable::find_by_call_id(char *call_id, unsigned long call_id_len) {
	string call_idS = string(call_id, call_id_len);
	lock_calls_listMAP();
	callMAPIT = calls_listMAP.find(call_idS);
	if(callMAPIT == calls_listMAP.end()) {
		unlock_calls_listMAP();
		// not found
		return NULL;
	} else {
		unlock_calls_listMAP();
		return (*callMAPIT).second->end_call ? NULL : (*callMAPIT).second;
	}
	
/*
	for (call = calls_list.begin(); call != calls_list.end(); ++call) {
		if((*call)->call_id_len == call_id_len &&
		  (memcmp((*call)->call_id, call_id, MIN(call_id_len, MAX_CALL_ID)) == 0)) {
			return *call;
		}
	}
	return NULL;
*/
}

/* find Call by SIP call-id in merge list and return reference to this Call */
Call*
Calltable::find_by_mergecall_id(char *call_id, unsigned long call_id_len) {
	string call_idS = string(call_id, call_id_len);
	lock_calls_mergeMAP();
	mergeMAPIT = calls_mergeMAP.find(call_idS);
	if(mergeMAPIT == calls_mergeMAP.end()) {
		unlock_calls_mergeMAP();
		// not found
		return NULL;
	} else {
		unlock_calls_mergeMAP();
		return (*mergeMAPIT).second;
	}
}

Call*
Calltable::find_by_skinny_partyid(unsigned int partyid) {
	skinny_partyIDIT = skinny_partyID.find(partyid);
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

	skinny_ipTuplesIT = skinny_ipTuples.find(tmp.str());
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
Calltable::cleanup( time_t currtime ) {

#if HAVE_LIBTCMALLOC    
	MallocExtension::instance()->ReleaseFreeMemory();
#endif

	if(verbosity && verbosityE > 1) {
		syslog(LOG_NOTICE, "call Calltable::cleanup");
	}
	Call* call;
	lock_calls_listMAP();
	for (callMAPIT = calls_listMAP.begin(); callMAPIT != calls_listMAP.end();) {
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
		} else {
			if(call->destroy_call_at != 0 && call->destroy_call_at <= currtime) {
				closeCall = true;
			} else if(call->destroy_call_at_bye != 0 && call->destroy_call_at_bye <= currtime) {
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
			if(!(
			     #if SYNC_CALL_RTP
			     call->rtppcaketsinqueue == 0
			     #else
			     call->rtppcaketsinqueue_p == call->rtppcaketsinqueue_m
			     #endif 
			     )) {
				closeCall = false;
			}
		}
		if(closeCall) {
			if(verbosity && verbosityE > 1) {
				syslog(LOG_NOTICE, "Calltable::cleanup - callid %s", call->call_id.c_str());
			}
			#if SYNC_CALL_RTP
			if(currtime == 0 && call->rtppcaketsinqueue) {
				syslog(LOG_WARNING, "force destroy call (rtppcaketsinqueue > 0)");
			}
			#else
			if(currtime == 0 && call->rtppcaketsinqueue_p != call->rtppcaketsinqueue_m) {
				syslog(LOG_WARNING, "force destroy call (rtppcaketsinqueue_p != rtppcaketsinqueue_m)");
			}
			#endif
			// Close RTP dump file ASAP to save file handles
			if(currtime == 0 && terminating) {
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
			calls_queue.push_back(call);
			unlock_calls_queue();
			calls_listMAP.erase(callMAPIT++);
			if(opt_enable_fraud && currtime) {
				struct timeval tv_currtime;
				tv_currtime.tv_sec = currtime;
				tv_currtime.tv_usec = 0;
				fraudEndCall(call, tv_currtime);
			}
		} else {
			++callMAPIT;
		}
	}
	unlock_calls_listMAP();
	
	if(currtime == 0 && terminating) {
		extern int terminated_call_cleanup;
		terminated_call_cleanup = 1;
		syslog(LOG_NOTICE, "terminated - call cleanup");
	}
	
	return 0;
}

void Call::saveregister() {
	removeFindTables();
	this->pcap.close();
	this->pcapSip.close();
	/****
	if (get_fsip_pcap() != NULL){
		pcap_dump_flush(get_fsip_pcap());
		pcap_dump_close(get_fsip_pcap());
		addtofilesqueue(sip_pcapfilename, "regsize");
		if(opt_cachedir[0] != '\0') {
			addtocachequeue(pcapfilename);
		}
		set_fsip_pcap(NULL);
	}
	if (get_f_pcap() != NULL){
		pcap_dump_flush(get_f_pcap());
		pcap_dump_close(get_f_pcap());
		addtofilesqueue(sip_pcapfilename, "regsize");
		if(opt_cachedir[0] != '\0') {
			addtocachequeue(pcapfilename);
		}
		set_f_pcap(NULL);
	}
	****/
	// we have to close all raw files as there can be data in buffers 
	closeRawFiles();
	/* move call to queue for mysql processing */
	((Calltable*)calltable)->lock_calls_queue();
	((Calltable*)calltable)->calls_queue.push_back(this);
	((Calltable*)calltable)->unlock_calls_queue();

	((Calltable*)calltable)->lock_calls_listMAP();
        map<string, Call*>::iterator callMAPIT = ((Calltable*)calltable)->calls_listMAP.find(call_id);
	if(callMAPIT == ((Calltable*)calltable)->calls_listMAP.end()) {
		syslog(LOG_ERR,"Fatal error REGISTER call_id[%s] not found in callMAPIT", call_id.c_str());
	} else {
		((Calltable*)calltable)->calls_listMAP.erase(callMAPIT);
	}
	((Calltable*)calltable)->unlock_calls_listMAP();
}

void
Call::handle_dtmf(char dtmf, double dtmf_time, unsigned int saddr, unsigned int daddr) {

	if(opt_dbdtmf) {
		dtmfq q;
		q.dtmf = dtmf;
		q.ts = dtmf_time - ts2double(first_packet_time, first_packet_usec);
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
	if(opt_silencedmtfseq[0] != '\0') {
		if(dtmfflag2 == 0) {
			if(dtmf == opt_silencedmtfseq[dtmfflag2]) {
				// received ftmf '*', set flag so if next dtmf will be '0' stop recording
				dtmfflag2++;
			}       
		} else {
			if(dtmf == opt_silencedmtfseq[dtmfflag2]) {
				// we have complete *0 sequence
				if(dtmfflag2 + 1 == strlen(opt_silencedmtfseq)) {
					if(silencerecording == 0) {
						if(verbosity >= 1)
							syslog(LOG_NOTICE, "[%s] pause DTMF sequence detected - pausing recording ", fbasename);
						silencerecording = 1;
					} else {
						if(verbosity >= 1)
							syslog(LOG_NOTICE, "[%s] pause DTMF sequence detected - unpausing recording ", fbasename);
						silencerecording = 0;
					}       
					dtmfflag2 = 0;
				} else {
					dtmfflag2++;
				}       
			} else {
				// reset flag 
				dtmfflag2 = 0;
			}       
		}       
	}
}

void
Call::handle_dscp(int sip_method, struct iphdr2 *header_ip, unsigned int saddr, unsigned int daddr, int *iscalledOut, bool enableSetSipcallerdip) {
	bool iscaller = 0;
	bool iscalled = 0;
	this->check_is_caller_called(sip_method, saddr, daddr, &iscaller, &iscalled, enableSetSipcallerdip);
	if(iscalled) {
		this->caller_sipdscp = header_ip->tos >> 2;
		if(sverb.dscp) {
			cout << "caller_sipdscp " << (int)(header_ip->tos>>2) << endl;
		}
	} 
	if(iscaller) {
		this->called_sipdscp = header_ip->tos >> 2;
		if(sverb.dscp) {
			cout << "called_sipdscp " << (int)(header_ip->tos>>2) << endl;
		}
	}
	if(iscalledOut) {
		*iscalledOut = iscalled;
	}
}

bool 
Call::check_is_caller_called(int sip_method, unsigned int saddr, unsigned int daddr, bool *iscaller, bool *iscalled, bool enableSetSipcallerdip) {
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
	} else {
		int i;
		char i_str[3];
		/* reverse sipcaller(d)ip - experiment - disabled
		if(enableSetSipcallerdip) {
			for(i = 1; i < MAX_SIPCALLERDIP; i++) {
				if(sverb.check_is_caller_called) {
					sprintf(i_str, "%i", i);
				}
				if(this->sipcallerip[i] == daddr && this->sipcalledip[i] == saddr) {
					this->sipcallerip[i] = saddr;
					this->sipcalledip[i] = daddr;
					if(sverb.check_is_caller_called) {
						debug_str_set += string(" / reverse sipcallerdip[") + i_str + "]: s " + inet_ntostring(htonl(saddr)) + ", d " + inet_ntostring(htonl(daddr));
					}
				}
			}
		}
		*/
		for(i = 0; i < MAX_SIPCALLERDIP; i++) {
			if(sverb.check_is_caller_called) {
				sprintf(i_str, "%i", i);
			}
			if(enableSetSipcallerdip && i > 0 && !this->sipcallerip[i] && saddr && daddr) {
				this->sipcallerip[i] = saddr;
				this->sipcalledip[i] = daddr;
				if(sverb.check_is_caller_called) {
					debug_str_set += string(" / set sipcallerdip[") + i_str + "]: s " + inet_ntostring(htonl(saddr)) + ", d " + inet_ntostring(htonl(daddr));
				}
			}
			if(this->sipcallerip[i]) {
				if(this->sipcallerip[i] == saddr) {
					// SDP message is coming from the first IP address seen in first INVITE thus incoming stream to ip/port in this 
					// SDP will be stream from called
					_iscalled = 1;
					if(sverb.check_is_caller_called) {
						debug_str_cmp += string(" / cmp this->sipcallerip[") + i_str + "] (" + inet_ntostring(htonl(this->sipcallerip[i])) + ") == " + 
								 "saddr (" + inet_ntostring(htonl(saddr)) + ")";
					}
					break;
				} else {
					// The IP address is different, check if the request matches one of the address from the first invite
					if(this->sipcallerip[i] == daddr) {
						// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
						*iscaller = 1;
						if(sverb.check_is_caller_called) {
							debug_str_cmp += string(" / this->sipcallerip[") + i_str + "] (" + inet_ntostring(htonl(this->sipcallerip[i])) + ") == " + 
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
