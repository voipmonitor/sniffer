/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. 
*/

/**
  * This file implements Calltable and Call class. Calltable implements operations 
  * on Call list. Call class implements operations on one call. 
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <math.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef ISCURL
#include <curl/curl.h>
//#include <curl/types.h>
//#include <curl/easy.h>
#endif

#include <iostream>
#include <sstream>
#include <vector>
#include <list>
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


#define MIN(x,y) ((x) < (y) ? (x) : (y))

using namespace std;

extern int verbosity;
extern int opt_sip_register;
extern int opt_saveRTP;
extern int opt_saveSIP;
extern int opt_rtcp;
extern int opt_saveRAW;                // save RTP payload RAW data?
extern int opt_saveWAV;                // save RTP payload RAW data?
extern int opt_saveGRAPH;	// save GRAPH data to graph file? 
extern int opt_gzipGRAPH;	// compress GRAPH data to graph file? 
extern int opt_audio_format;	// define format for audio writing (if -W option)
extern int opt_mos_g729;
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
extern int rtptimeout;
extern unsigned int gthread_num;
extern int num_threads;
extern char opt_cdrurl[1024];
extern int opt_printinsertid;
extern int opt_sip_register_active_nologbin;
extern pthread_mutex_t mysqlquery_lock;
extern queue<string> mysqlquery;
extern int opt_cdronlyanswered;
extern int opt_cdronlyrtp;
extern int opt_newdir;
extern char opt_keycheck[1024];
extern char opt_convert_char[256];
extern int opt_norecord_dtmf;
extern char opt_silencedmtfseq[16];
extern bool opt_cdr_partition;
extern char get_customers_pn_query[1024];
extern int opt_saverfc2833;
extern int opt_dbdtmf;

volatile int calls = 0;

extern char mac[32];

unsigned int last_register_clean = 0;

extern SqlDb *sqlDb;

extern CustPhoneNumberCache *custPnCache;

/* constructor */
Call::Call(char *call_id, unsigned long call_id_len, time_t time, void *ct) {
	isfax = 0;
	seenudptl = 0;
	last_callercodec = -1;
	ipport_n = 0;
	ssrc_n = 0;
	first_packet_time = time;
	first_packet_usec = 0;
	last_packet_time = time;
	memcpy(this->call_id, call_id, MIN(call_id_len, MAX_CALL_ID));
	this->call_id[MIN(call_id_len, MAX_CALL_ID)] = '\0';
	this->call_id_len = call_id_len;
	f_pcap = NULL;
	fsip_pcap = NULL;
	frtp_pcap = NULL;
	whohanged = -1;
	seeninvite = false;
	seeninviteok = false;
	seenbye = false;
	seenbyeandok = false;
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
	sighup = false;
	calltable = ct;
	progress_time = 0;
	first_rtp_time = 0;
	connect_time = 0;
	a_ua[0] = '\0';
	b_ua[0] = '\0';
	rtp_cur[0] = NULL;
	rtp_cur[1] = NULL;
	rtp_prev[0] = NULL;
	rtp_prev[1] = NULL;
	lastSIPresponse[0] = '\0';
	lastSIPresponseNum = 0;
	msgcount = 0;
	regcount = 0;
	reg401count = 0;
	regstate = 0;
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
		rtp[i] = NULL;
	}
	audiobuffer1 = NULL;
	audiobuffer2 = NULL;
	listening_worker_run = NULL;
	tmprtp.call_owner = this;
	flags = 0;
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	destroy_call_at = 0;
	custom_header1[0] = '\0';
	match_header[0] = '\0';
	thread_num = num_threads > 0 ? gthread_num % num_threads : 0;
	gthread_num++;
	recordstopped = 0;
	dtmfflag = 0;
	dtmfflag2 = 0;
	silencerecording = 0;
	flags1 = 0;
	rtppcaketsinqueue = 0;
	message = NULL;
	contenttype = NULL;
	unrepliedinvite = 0;
	sipcalledip2 = 0;
	sipcallerip2 = 0;
	sipcalledip3 = 0;
	sipcallerip3 = 0;
	sipcalledip4 = 0;
	sipcallerip4 = 0;
	fname2 = 0;
	skinny_partyid = 0;
	relationcall = NULL;
	pthread_mutex_init(&buflock, NULL);
	pthread_mutex_init(&listening_worker_run_lock, NULL);
}

void
Call::mapRemove() {
	int i;
	Calltable *ct = (Calltable *)calltable;

	for(i = 0; i < ipport_n; i++) {
		ct->mapRemove(this->addr[i], this->port[i]);
		if(opt_rtcp) {
			ct->mapRemove(this->addr[i], this->port[i] + 1);
		}

	}
}

void
Call::hashRemove() {
	int i;
	Calltable *ct = (Calltable *)calltable;

	for(i = 0; i < ipport_n; i++) {
		ct->hashRemove(this->addr[i], this->port[i]);
		if(opt_rtcp) {
			ct->hashRemove(this->addr[i], this->port[i] + 1);
		}

	}
}

void
Call::addtocachequeue(string file) {
	Calltable *ct = (Calltable *)calltable;

	ct->lock_files_queue();
	ct->files_queue.push(file);
	ct->unlock_files_queue();
}

void
Call::removeRTP() {
	closeRawFiles();
	ssrc_n = 0;
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
	// lets check whole array as there can be holes due rtp[0] <=> rtp[1] swaps in mysql rutine
		if(rtp[i]) {
			delete rtp[i];
			rtp[i] = NULL;
		}
        }
}

/* destructor */
Call::~Call(){
	if(relationcall) {
		// break relation 
		relationcall->relationcall = NULL;
		relationcall = NULL;
	}

	if(skinny_partyid) {
		((Calltable *)calltable)->skinny_partyID.erase(skinny_partyid);
	}

	if(contenttype) free(contenttype);
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

	if (get_fsip_pcap() != NULL){
		pcap_dump_flush(get_fsip_pcap());
		pcap_dump_close(get_fsip_pcap());
		set_fsip_pcap(NULL);
		if(opt_cachedir[0] != '\0') {
			addtocachequeue(sip_pcapfilename);
		}
	}
	if (get_frtp_pcap() != NULL){
		pcap_dump_flush(get_frtp_pcap());
		pcap_dump_close(get_frtp_pcap());
		set_frtp_pcap(NULL);
		if(opt_cachedir[0] != '\0') {
			addtocachequeue(rtp_pcapfilename);
		}
	}
	if (get_f_pcap() != NULL){
		pcap_dump_flush(get_f_pcap());
		pcap_dump_close(get_f_pcap());
		set_f_pcap(NULL);
		if(opt_cachedir[0] != '\0') {
			addtocachequeue(pcapfilename);
		}
	}

	if(audiobuffer1) delete audiobuffer1;
	if(audiobuffer2) delete audiobuffer2;

	if(this->message) {
		free(message);
	}
	pthread_mutex_destroy(&buflock);
	pthread_mutex_unlock(&listening_worker_run_lock);
	pthread_mutex_destroy(&listening_worker_run_lock);
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
			if(opt_gzipGRAPH && rtp[i]->gfileGZ.is_open()) {
				rtp[i]->gfileGZ.close();
			} else if(rtp[i]->gfile.is_open()){
				rtp[i]->gfile.close();
			}
		}
	}
}

/* returns name of the directory in format YYYY-MM-DD */
string
Call::dirname() {
	char sdirname[255];
	struct tm *t = localtime((const time_t*)(&first_packet_time));
	if(opt_newdir) {
		sprintf(sdirname, "%04d-%02d-%02d/%02d/%02d",  t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min);
	} else {
		sprintf(sdirname, "%04d-%02d-%02d",  t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
	}
	string s(sdirname);
	return s;
}

/* add ip adress and port to this call */
int
Call::add_ip_port(in_addr_t addr, unsigned short port, char *ua, unsigned long ua_len, bool iscaller, int *rtpmap) {
	if(verbosity >= 4) {
		struct in_addr in;
		in.s_addr = addr;
		printf("call:[%p] ip:[%s] port:[%d] iscaller:[%d]\n", this, inet_ntoa(in), port, iscaller);
	}

	if(ipport_n > 0) {
		// check, if there is already IP:port
		for(int i = 0; i < ipport_n; i++) {
			if(this->addr[i] == addr && this->port[i] == port){
				// reinit rtpmap
				memcpy(this->rtpmap[i], rtpmap, MAX_RTPMAP * sizeof(int)); //XXX: is it neccessary?
				return 1;
			}
		}
	}
	// add ip and port
	if(ipport_n >= MAX_IP_PER_CALL){
		char tmp[18];
		struct in_addr in;
		in.s_addr = addr;
		strcpy(tmp, inet_ntoa(in));

		syslog(LOG_ERR,"callid [%s]: no more space for next media stream [%s:%d], raise MAX_IP_PER_CALL", call_id, tmp, port);
		return -1;
	}

	if(ua_len && ua_len < 1024) {
		char *tmp = iscaller ? this->b_ua : this->a_ua;
		memcpy(tmp, ua, MIN(ua_len, 1024));
		tmp[MIN(ua_len, 1023)] = '\0';
	}

	this->addr[ipport_n] = addr;
	this->port[ipport_n] = port;
	//memcpy(this->rtpmap[ipport_n], rtpmap, MAX_RTPMAP * sizeof(int));
	memcpy(this->rtpmap[iscaller], rtpmap, MAX_RTPMAP * sizeof(int));
	this->iscaller[ipport_n] = iscaller;
	ipport_n++;
	return 0;
}

/* Return reference to Call if IP:port was found, otherwise return NULL */
Call*
Call::find_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller){
	for(int i = 0; i < ipport_n; i++) {
		if(this->addr[i] == addr && this->port[i] == port){
			// we have found it
			*iscaller = this->iscaller[i];
			return this;
		}
	}
	// not found
	return NULL;
}

int
Call::get_index_by_ip_port(in_addr_t addr, unsigned short port){
	for(int i = 0; i < ipport_n; i++) {
		if(this->addr[i] == addr && this->port[i] == port){
			// we have found it
			return i;
		}
	}
	// not found
	return -1;
}

/* analyze rtcp packet */
void
Call::read_rtcp(unsigned char* data, int datalen, struct pcap_pkthdr *header, u_int32_t saddr, unsigned short port, int iscaller) {
	parse_rtcp((char*)data, datalen, this);
}

/* analyze rtp packet */
void
Call::read_rtp(unsigned char* data, int datalen, struct pcap_pkthdr *header, u_int32_t saddr, u_int32_t daddr, unsigned short port, int iscaller, int *record) {

	*record = 0;

	if(first_rtp_time == 0) {
		first_rtp_time = header->ts.tv_sec;
	}
	
	//RTP tmprtp; moved to Call structure to avoid creating and destroying class which is not neccessary
	tmprtp.fill(data, datalen, header, saddr, daddr);
	if(tmprtp.getSSRC() == 0 || tmprtp.getVersion() != 2) {
		// invalid ssrc
		return;
	}

	// chekc if packet is DTMF and saverfc2833 is enabled 
	if(opt_saverfc2833 and tmprtp.getPayload() == 101) {
		*record = 1;
	}

	for(int i = 0; i < ssrc_n; i++) {
		if(rtp[i]->ssrc == tmprtp.getSSRC()) {
			// found 
			rtp[i]->read(data, datalen, header, saddr, daddr, seeninviteok);
			return;
		}
	}
	// adding new RTP source
	if(ssrc_n < MAX_SSRC_PER_CALL) {
		// close previouse graph files to save RAM (but only if > 10 
		if(flags & FLAG_SAVEGRAPH && ssrc_n > 6) {
			if(opt_gzipGRAPH) {
				if(iscaller) {
					if(lastcallerrtp && lastcallerrtp->gfileGZ.is_open()) {
						lastcallerrtp->gfileGZ.close();
					}
				} else {
					if(lastcalledrtp && lastcalledrtp->gfileGZ.is_open()) {
						lastcalledrtp->gfileGZ.close();
					}
				}
			} else {
				if(iscaller) {
					if(lastcallerrtp && lastcallerrtp->gfile.is_open()) {
						lastcallerrtp->gfile.close();
					}
				} else {
					if(lastcalledrtp && lastcalledrtp->gfile.is_open()) {
						lastcalledrtp->gfile.close();
					}
				}
			}
		}

		// if previouse RTP streams are present it should be filled by silence to keep it in sync
		if(iscaller) {
			if(lastcallerrtp) {
				lastcallerrtp->jt_tail(header);
			}
		} else { 
			if(lastcalledrtp) {
				lastcalledrtp->jt_tail(header);
			}
		}

		rtp[ssrc_n] = new RTP;
		rtp[ssrc_n]->call_owner = this;
		rtp[ssrc_n]->ssrc_index = ssrc_n; 
		rtp[ssrc_n]->iscaller = iscaller; 
		if(rtp_cur[iscaller]) {
			rtp_prev[iscaller] = rtp_cur[iscaller];
		}
		rtp_cur[iscaller] = rtp[ssrc_n]; 
		char tmp[1024];
		if(opt_cachedir[0] != '\0') {
			sprintf(tmp, "%s/%s/%s/%s.%d.graph%s", opt_cachedir, dirname().c_str(), opt_newdir ? "GRAPH" : "", get_fbasename_safe(), ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		} else {
			sprintf(tmp, "%s/%s/%s.%d.graph%s", dirname().c_str(), opt_newdir ? "GRAPH" : "", get_fbasename_safe(), ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		}
		sprintf(rtp[ssrc_n]->gfilename, "%s/%s/%s.%d.graph%s", dirname().c_str(), opt_newdir ? "GRAPH" : "", get_fbasename_safe(), ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		if(flags & FLAG_SAVEGRAPH) {
			if(opt_gzipGRAPH) {
				rtp[ssrc_n]->gfileGZ.open(tmp);
			} else {
				rtp[ssrc_n]->gfile.open(tmp);
			}
		}
		rtp[ssrc_n]->gfileRAW = NULL;
		sprintf(rtp[ssrc_n]->basefilename, "%s/%s/%s.i%d", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), iscaller);
//		int i = get_index_by_ip_port(saddr, port);
//		if(i >= 0) {
			//memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[i], MAX_RTPMAP * sizeof(int));
			memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[iscaller], MAX_RTPMAP * sizeof(int));
//		}

		rtp[ssrc_n]->read(data, datalen, header, saddr, daddr, seeninviteok);
		this->rtp[ssrc_n]->ssrc = tmprtp.getSSRC();
		if(iscaller) {
			lastcallerrtp = rtp[ssrc_n];
		} else {
			lastcalledrtp = rtp[ssrc_n];
		}
		ssrc_n++;
	}
}

void Call::stoprecording() {
	if(recordstopped == 0) {
		char str2[2048];

		this->flags = 0;
		if(this->get_fsip_pcap() != NULL) {
			pcap_dump_flush(this->get_fsip_pcap());
			pcap_dump_close(this->get_fsip_pcap());
			this->set_fsip_pcap(NULL);
			if(opt_cachedir[0] != '\0') {
				sprintf(str2, "%s/%s.pcap", opt_cachedir, sip_pcapfilename.c_str());
			} else {
				sprintf(str2, "%s.pcap", sip_pcapfilename.c_str());
			}
			unlink(str2);	
		}
		if(this->get_frtp_pcap() != NULL) {
			pcap_dump_flush(this->get_frtp_pcap());
			pcap_dump_close(this->get_frtp_pcap());
			this->set_frtp_pcap(NULL);
			if(opt_cachedir[0] != '\0') {
				sprintf(str2, "%s/%s.pcap", opt_cachedir, rtp_pcapfilename.c_str());
			} else {
				sprintf(str2, "%s.pcap", rtp_pcapfilename.c_str());
			}
			unlink(str2);	
		}
		if(this->get_f_pcap() != NULL) {
			pcap_dump_flush(this->get_f_pcap());
			pcap_dump_close(this->get_f_pcap());
			this->set_f_pcap(NULL);
			if(opt_cachedir[0] != '\0') {
				sprintf(str2, "%s/%s.pcap", opt_cachedir, pcapfilename.c_str());
			} else {
				sprintf(str2, "%s.pcap", pcapfilename.c_str());
			}
			unlink(str2);	
		}

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

int convertALAW2WAV(char *fname1, char *fname3) {
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
 
	bitstream_buf1 = (unsigned char *)malloc(file_size1);
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
		fwrite(&buf_out1, outFrameSize, 1, f_out);
	}
 
	// wav_update_header(f_out);
 
	free(bitstream_buf1);
 
	fclose(f_out);
	fclose(f_in1);

	return 0;
}
 
int convertULAW2WAV(char *fname1, char *fname3) {
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
 
	bitstream_buf1 = (unsigned char *)malloc(file_size1);
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
		fwrite(&buf_out1, outFrameSize, 1, f_out);
	}
 
	// wav_update_header(f_out);
 
	if(bitstream_buf1)
		free(bitstream_buf1);
 
	fclose(f_out);
	fclose(f_in1);
 
	return 0;
}

int
Call::convertRawToWav() {
	char cmd[4092];
	char wav0[1024];
	char wav1[1024];
	char out[1024];
	char rawInfo[1024];
	char line[1024];
	struct timeval tv0, tv1;
	FILE *pl;
	int ssrc_index, codec;
	unsigned long int rawiterator;
	FILE *wav = NULL;
	int adir = 1;
	int bdir = 1;

	sprintf(wav0, "%s/%s/%s.i0.wav", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
	sprintf(wav1, "%s/%s/%s.i1.wav", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
	switch(opt_audio_format) {
	case FORMAT_WAV:
		sprintf(out, "%s/%s/%s.wav", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
		break;
	case FORMAT_OGG:
		sprintf(out, "%s/%s/%s.ogg", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
		break;
	}

	/* do synchronisation - calculate difference between start of both RTP direction and put silence to achieve proper synchronisation */
	/* first direction */
	sprintf(rawInfo, "%s/%s/%s.i%d.rawInfo", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), 0);
	pl = fopen(rawInfo, "r");
	if(!pl) {
		adir = 0;
//		syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
//		return 1;
	} else {
		fgets(line, 1024, pl);
		fclose(pl);
		sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
	}
	/* second direction */
	sprintf(rawInfo, "%s/%s/%s.i%d.rawInfo", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), 1);
	pl = fopen(rawInfo, "r");
	if(!pl) {
		bdir = 0;
//		syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
//		return 1;
	} else {
		fgets(line, 1024, pl);
		fclose(pl);
		sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv1.tv_sec, &tv1.tv_usec);
	}

	if(adir == 0 && bdir == 0) {
		syslog(LOG_ERR, "PCAP file %s/%s/%s.pcap cannot be decoded to WAV probably missing RTP\n", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe());
		return 1;
	}

	if(adir && bdir) {
		/* calculate difference in milliseconds */
		int msdiff = ast_tvdiff_ms(tv1, tv0);
		if(msdiff < 0) {
			/* add msdiff [ms] silence to i1 stream */
			wav = fopen(wav0, "w");
		} else {
			wav = fopen(wav1, "w");
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
		switch(rtp[0]->codec) {
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
		if(i == 0 && adir == 0) {
			continue;
		}
		if(i == 1 && bdir == 0) {
			continue;
		}
		char *wav = i ? wav1 : wav0;

		/* open playlist */
		sprintf(rawInfo, "%s/%s/%s.i%d.rawInfo", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), i);
		pl = fopen(rawInfo, "r");
		if(!pl) {
			syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
			return 1;
		}
		while(fgets(line, 256, pl)) {
			char raw[1024];
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			sprintf(raw, "%s/%s/%s.i%d.%d.%lu.%d.%ld.%ld.raw", dirname().c_str(), opt_newdir ? "AUDIO" : "", get_fbasename_safe(), i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);
			switch(codec) {
			case PAYLOAD_PCMA:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMA to WAV.\n");
				convertALAW2WAV(raw, wav);
				break;
			case PAYLOAD_PCMU:
				if(verbosity > 1) syslog(LOG_ERR, "Converting PCMU to WAV.\n");
				convertULAW2WAV(raw, wav);
				break;
		/* following decoders are not included in free version. Please contact support@voipmonitor.org */
			case PAYLOAD_G722:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s g722 \"%s\" \"%s\" 64000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-g722 \"%s\" \"%s\" 64000", raw, wav);
				}
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.722 to WAV.\n");
				if(verbosity > 2) syslog(LOG_ERR, "Converting G.722 to WAV. %s\n", cmd);
				system(cmd);
				break;
			case PAYLOAD_GSM:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s gsm \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-gsm \"%s\" \"%s\"", raw, wav);
				}
				if(verbosity > 1) syslog(LOG_ERR, "Converting GSM to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_G729:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s g729 \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-g729 \"%s\" \"%s\"", raw, wav);
				}
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.729 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_G723:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s g723 \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-g723 \"%s\" \"%s\"", raw, wav);
				}
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.723 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_ILBC:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s ilbc \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-ilbc \"%s\" \"%s\"", raw, wav);
				}
				if(verbosity > 1) syslog(LOG_ERR, "Converting iLBC to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SPEEX:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s speex \"%s\" \"%s\"", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-speex \"%s\" \"%s\"", raw, wav);
				}
				if(verbosity > 1) syslog(LOG_ERR, "Converting speex to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK8:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s silk \"%s\" \"%s\" 8000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-silk \"%s\" \"%s\" 8000", raw, wav);
				}
				samplerate = 8000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK8 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK12:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s silk \"%s\" \"%s\" 12000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-silk \"%s\" \"%s\" 12000", raw, wav);
				}
				samplerate = 12000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK12 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s silk \"%s\" \"%s\" 16000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-silk \"%s\" \"%s\" 16000", raw, wav);
				}
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SILK24:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s silk \"%s\" \"%s\" 24000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-silk \"%s\" \"%s\" 24000", raw, wav);
				}
				if(verbosity > 1) syslog(LOG_ERR, "Converting SILK16 to WAV.\n");
				samplerate = 24000;
				system(cmd);
				break;
			case PAYLOAD_ISAC16:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s isac \"%s\" \"%s\" 16000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-isac \"%s\" \"%s\" 16000", raw, wav);
				}
				samplerate = 16000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting ISAC16 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_ISAC32:
				if(opt_keycheck[0] != '\0') {
					snprintf(cmd, 4092, "vmcodecs %s isac \"%s\" \"%s\" 32000", opt_keycheck, raw, wav);
				} else {
					snprintf(cmd, 4092, "voipmonitor-isac \"%s\" \"%s\" 32000", raw, wav);
				}
				samplerate = 32000;
				if(verbosity > 1) syslog(LOG_ERR, "Converting ISAC32 to WAV.\n");
				system(cmd);
				break;
			default:
				syslog(LOG_ERR, "Call [%s] cannot be converted to WAV, unknown payloadtype [%d]\n", raw, codec);
			}
			unlink(raw);
		}
		fclose(pl);
		unlink(rawInfo);
	}

	if(adir == 1 && bdir == 1) {
		switch(opt_audio_format) {
		case FORMAT_WAV:
			wav_mix(wav0, wav1, out, samplerate);
			break;
		case FORMAT_OGG:
			ogg_mix(wav0, wav1, out);
			break;
		}
		unlink(wav0);
		unlink(wav1);
	} else if(adir == 1) {
		switch(opt_audio_format) {
		case FORMAT_WAV:
			wav_mix(wav0, NULL, out, samplerate);
			break;
		case FORMAT_OGG:
			ogg_mix(wav0, NULL, out);
			break;
		}
		unlink(wav0);
	} else if(bdir == 1) {
		switch(opt_audio_format) {
		case FORMAT_WAV:
			wav_mix(wav1, NULL, out, samplerate);
			break;
		case FORMAT_OGG:
			ogg_mix(wav1, NULL, out);
			break;
		}
		unlink(wav1);
	}
 
	return 0;
}

bool 
Call::prepareForEscapeString() {
	unsigned int pass = 0;
	while(!sqlDb->connected()) {
		if(pass > 0) {
			sleep(1);
		}
		sqlDb->connect();
		++pass;
	}
	return true;
}

size_t write_data(char *ptr, size_t size, size_t nmemb, void *userdata) {
	std::ostringstream *stream = (std::ostringstream*)userdata;
	size_t count = size * nmemb;
	stream->write(ptr, count);
	return count;
}

#ifdef ISCURL
int
sendCDR(string data) {
	CURL *curl;
	CURLcode res;
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;

startcurl:
	headerlist = NULL;
	formpost=NULL;
	lastptr=NULL;

	/* Fill in the filename field */ 
	curl_formadd(&formpost,
			 &lastptr,
			 CURLFORM_COPYNAME, "mac",
			 CURLFORM_COPYCONTENTS, mac,
			 CURLFORM_END);

	curl_formadd(&formpost,
			 &lastptr,
			 CURLFORM_COPYNAME, "data",
			 CURLFORM_COPYCONTENTS, data.c_str(),
			 CURLFORM_END);

	curl = curl_easy_init();
	/* initalize custom header list (stating that Expect: 100-continue is not
		 wanted */ 
//	headerlist = curl_slist_append(headerlist, buf);
	if(curl) {

		std::ostringstream stream;

		/* what URL that receives this POST */ 
		curl_easy_setopt(curl, CURLOPT_URL, opt_cdrurl);
//		if ( (argc == 2) && (!strcmp(argv[1], "noexpectheader")) )
			/* only disable 100-continue header if explicitly requested */ 
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &stream);
 
		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		/* Check for errors */ 
			
 
		/* always cleanup */ 
		curl_easy_cleanup(curl);
 
		/* then cleanup the formpost chain */ 
		curl_formfree(formpost);
		/* free slist */ 

		if(verbosity > 1) syslog(LOG_NOTICE, "sending CDR data");
		curl_slist_free_all (headerlist);

		if(res != CURLE_OK) {
			syslog(LOG_ERR, "curl_easy_perform() failed: [%s] trying to send again.\n", curl_easy_strerror(res));
			sleep(1);
			goto startcurl;
		}
		if(strcmp(stream.str().c_str(), "TRUE") != 0) {
			syslog(LOG_ERR, "CDR send failed: [%s] trying to send again.", stream.str().c_str());
			sleep(1);
			goto startcurl;
		}
	} else {
		syslog(LOG_ERR, "curl_easy_init() failed\n");
	}

	return 0;
}

string
Call::getKeyValCDRtext() {
	
	SqlDb_row cdr;

	if(opt_id_sensor > -1) {
		cdr.add(opt_id_sensor, "id_sensor");
	}

	cdr.add(caller, "caller");
	cdr.add(reverseString(caller).c_str(), "caller_reverse");
	cdr.add(called, "called");
	cdr.add(reverseString(called).c_str(), "called_reverse");
	cdr.add(caller_domain, "caller_domain");
	cdr.add(called_domain, "called_domain");
	cdr.add(callername, "callername");
	cdr.add(reverseString(callername).c_str(), "callername_reverse");
	cdr.add(lastSIPresponse, "lastSIPresponse");
	cdr.add(htonl(sipcallerip), "sipcallerip");
	cdr.add(htonl(sipcalledip), "sipcalledip");
	cdr.add(duration(), "duration");
	cdr.add(progress_time ? progress_time - first_packet_time : -1, "progress_time");
	cdr.add(first_rtp_time ? first_rtp_time  - first_packet_time : -1, "first_rtp_time");
	cdr.add(connect_time ? (duration() - (connect_time - first_packet_time)) : -1, "connect_duration");
	cdr.add(sqlDateTimeString(calltime()).c_str(), "calldate");
	if(opt_callend) {
		cdr.add(sqlDateTimeString(calltime() + duration()).c_str(), "callend");
	}
	
	cdr.add(fbasename, "fbasename");
	
	cdr.add(sighup ? 1 : 0, "sighup");
	cdr.add(lastSIPresponseNum, "lastSIPresponseNum");
	cdr.add(seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0, "bye");
	
	if(strlen(match_header)) {
		cdr.add(match_header, "match_header");
	}
	if(strlen(custom_header1)) {
		cdr.add(custom_header1, "custom_header1");
	}

	if(whohanged == 0 || whohanged == 1) {
		cdr.add(whohanged ? "callee" : "caller", "whohanged");
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

		// a_ is always caller, so check if we need to swap indexes
		if (!rtp[indexes[0]]->iscaller) {
			int tmp;
			tmp = indexes[1];
			indexes[1] = indexes[0];
			indexes[0] = tmp;
		}
		cdr.add(a_ua, "a_ua");
		cdr.add(b_ua, "b_ua");

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
			if(!rtp[indexes[i]]) continue;

			// if the stream for a_* is not caller there is probably case where one direction is missing at all and the second stream contains more SSRC streams so swap it
			if(i == 0 && !rtp[indexes[i]]->iscaller) {
				int tmp;
				tmp = indexes[1];
				indexes[1] = indexes[0];
				indexes[0] = tmp;
				continue;
			}
			
			string c = i == 0 ? "a" : "b";
			
			cdr.add(indexes[i], c+"_index");
			cdr.add(rtp[indexes[i]]->stats.received + 2, c+"_received"); // received is always 2 packet less compared to wireshark (add it here)
			lost[i] = rtp[indexes[i]]->stats.lost;
			cdr.add(lost[i], c+"_lost");
			packet_loss_perc_mult1000[i] = (int)round((double)rtp[indexes[i]]->stats.lost / 
									(rtp[indexes[i]]->stats.received + 2 + rtp[indexes[i]]->stats.lost) * 100 * 1000);
			cdr.add(packet_loss_perc_mult1000[i], c+"_packet_loss_perc_mult1000");
			jitter_mult10[i] = int(ceil(rtp[indexes[i]]->stats.avgjitter)) * 10; // !!!
			cdr.add(jitter_mult10[i], c+"_avgjitter_mult10");
			cdr.add(int(ceil(rtp[indexes[i]]->stats.maxjitter)), c+"_maxjitter");
			payload[i] = rtp[indexes[i]]->codec;
			cdr.add(payload[i], c+"_payload");
			
			// build a_sl1 - b_sl10 fields
			for(int j = 1; j < 11; j++) {
				char str_j[3];
				sprintf(str_j, "%d", j);
				cdr.add(rtp[indexes[i]]->stats.slost[j], c+"_sl"+str_j);
			}
			// build a_d50 - b_d300 fileds
			cdr.add(rtp[indexes[i]]->stats.d50, c+"_d50");
			cdr.add(rtp[indexes[i]]->stats.d70, c+"_d70");
			cdr.add(rtp[indexes[i]]->stats.d90, c+"_d90");
			cdr.add(rtp[indexes[i]]->stats.d120, c+"_d120");
			cdr.add(rtp[indexes[i]]->stats.d150, c+"_d150");
			cdr.add(rtp[indexes[i]]->stats.d200, c+"_d200");
			cdr.add(rtp[indexes[i]]->stats.d300, c+"_d300");
			delay_sum[i] = rtp[indexes[i]]->stats.d50 * 60 + 
				       rtp[indexes[i]]->stats.d70 * 80 + 
				       rtp[indexes[i]]->stats.d90 * 105 + 
				       rtp[indexes[i]]->stats.d120 * 135 +
				       rtp[indexes[i]]->stats.d150 * 175 + 
				       rtp[indexes[i]]->stats.d200 * 250 + 
				       rtp[indexes[i]]->stats.d300 * 300;
			delay_cnt[i] = rtp[indexes[i]]->stats.d50 + 
				       rtp[indexes[i]]->stats.d70 + 
				       rtp[indexes[i]]->stats.d90 + 
				       rtp[indexes[i]]->stats.d120 +
				       rtp[indexes[i]]->stats.d150 + 
				       rtp[indexes[i]]->stats.d200 + 
				       rtp[indexes[i]]->stats.d300;
			delay_avg_mult100[i] = (delay_cnt[i] != 0  ? (int)round((double)delay_sum[i] / delay_cnt[i] * 100) : 0);
			cdr.add(delay_sum[i], c+"_delay_sum");
			cdr.add(delay_cnt[i], c+"_delay_cnt");
			cdr.add(delay_avg_mult100[i], c+"_delay_avg_mult100");
			
			// store source addr
			cdr.add(htonl(rtp[indexes[i]]->saddr), c+"_saddr");

			// calculate lossrate and burst rate
			double burstr, lossr;
			burstr_calculate(rtp[indexes[i]]->channel_fix1, rtp[indexes[i]]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_f1");
			//cdr.add(burstr, c+"_burstr_f1");
			int mos_f1_mult10 = (int)round(calculate_mos(lossr, burstr, rtp[indexes[i]]->codec, rtp[indexes[i]]->stats.received) * 10);
			cdr.add(mos_f1_mult10, c+"_mos_f1_mult10");
			if(mos_f1_mult10) {
				mos_min_mult10[i] = mos_f1_mult10;
			}

			// Jitterbuffer MOS statistics
			burstr_calculate(rtp[indexes[i]]->channel_fix2, rtp[indexes[i]]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_f2");
			//cdr.add(burstr, c+"_burstr_f2");
			int mos_f2_mult10 = (int)round(calculate_mos(lossr, burstr, rtp[indexes[i]]->codec, rtp[indexes[i]]->stats.received) * 10);
			cdr.add(mos_f2_mult10, c+"_mos_f2_mult10");
			if(mos_f2_mult10 && (mos_min_mult10[i] < 0 || mos_f2_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_f2_mult10;
			}

			burstr_calculate(rtp[indexes[i]]->channel_adapt, rtp[indexes[i]]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_adapt");
			//cdr.add(burstr, c+"_burstr_adapt");
			int mos_adapt_mult10 = (int)round(calculate_mos(lossr, burstr, rtp[indexes[i]]->codec, rtp[indexes[i]]->stats.received) * 10);
			cdr.add(mos_adapt_mult10, c+"_mos_adapt_mult10");
			if(mos_adapt_mult10 && (mos_min_mult10[i] < 0 || mos_adapt_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_adapt_mult10;
			}
			
			if(mos_min_mult10[i] >= 0) {
				cdr.add(mos_min_mult10[i], c+"_mos_min_mult10");
			}

			if(rtp[indexes[i]]->rtcp.counter) {
				cdr.add(rtp[indexes[i]]->rtcp.loss, c+"_rtcp_loss");
				cdr.add(rtp[indexes[i]]->rtcp.maxfr, c+"_rtcp_maxfr");
				rtcp_avgfr_mult10[i] = (int)round(rtp[indexes[i]]->rtcp.avgfr * 10);
				cdr.add(rtcp_avgfr_mult10[i], c+"_rtcp_avgfr_mult10");
				cdr.add(rtp[indexes[i]]->rtcp.maxjitter, c+"_rtcp_maxjitter");
				rtcp_avgjitter_mult10[i] = (int)round(rtp[indexes[i]]->rtcp.avgjitter * 10);
				cdr.add(rtcp_avgjitter_mult10[i], c+"_rtcp_avgjitter_mult10");
			}
		}

		if(seenudptl) {
		//if(isfax) {
			cdr.add(1000, "payload");
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

	cdr.add(mac, "MAC");

	return cdr.keyvalList(":");
}
#endif


/* TODO: implement failover -> write INSERT into file */
int
Call::saveToDb(bool enableBatchIfPossible) {
	if(!prepareForEscapeString())
		return 1;

	if((opt_cdronlyanswered and !connect_time) or 
		(opt_cdronlyrtp and !ssrc_n)) {
		// skip this CDR 
		return 1;
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
			cdr_ua_b;
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

	if(opt_id_sensor > -1) {
		cdr.add(opt_id_sensor, "id_sensor");
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
	
	cdr.add(htonl(sipcallerip), "sipcallerip");
	cdr.add(htonl(sipcalledip), "sipcalledip");
	cdr.add(duration(), "duration");
	cdr.add(progress_time ? progress_time - first_packet_time : -1, "progress_time");
	cdr.add(first_rtp_time ? first_rtp_time  - first_packet_time : -1, "first_rtp_time");
	cdr.add(connect_time ? (duration() - (connect_time - first_packet_time)) : -1, "connect_duration");
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
	cdr.add(seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0, "bye");
	
	if(strlen(match_header)) {
		cdr_next.add(sqlEscapeString(match_header), "match_header");
	}
	if(strlen(custom_header1)) {
		cdr_next.add(sqlEscapeString(custom_header1), "custom_header1");
	}
	for(size_t iCustHeaders = 0; iCustHeaders < custom_headers.size(); iCustHeaders++) {
		cdr_next.add(sqlEscapeString(custom_headers[iCustHeaders][1]), custom_headers[iCustHeaders][0]);
	}
	if(opt_cdr_partition && sqlDb->existsColumnCalldateInCdrNext) {
		cdr_next.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
	}

	if(whohanged == 0 || whohanged == 1) {
		cdr.add(whohanged ? "callee" : "caller", "whohanged");
	}
	
	if(get_customers_pn_query[0] && custPnCache) {
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
			if(rtp[indexes[k]]->iscaller && !rtpab[0]) {
				rtpab[0] = rtp[indexes[k]];
			}
			if(!rtp[indexes[k]]->iscaller && !rtpab[1]) {
				rtpab[1] = rtp[indexes[k]];
			}
		}

		cdr_ua_a.add(sqlEscapeString(a_ua), "ua");
		cdr_ua_b.add(sqlEscapeString(b_ua), "ua");

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
			payload[i] = rtpab[i]->codec;
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
			int mos_f1_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->codec, rtpab[i]->stats.received) * 10);
			cdr.add(mos_f1_mult10, c+"_mos_f1_mult10");
			if(mos_f1_mult10) {
				mos_min_mult10[i] = mos_f1_mult10;
			}

			// Jitterbuffer MOS statistics
			burstr_calculate(rtpab[i]->channel_fix2, rtpab[i]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_f2");
			//cdr.add(burstr, c+"_burstr_f2");
			int mos_f2_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->codec, rtpab[i]->stats.received) * 10);
			cdr.add(mos_f2_mult10, c+"_mos_f2_mult10");
			if(mos_f2_mult10 && (mos_min_mult10[i] < 0 || mos_f2_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_f2_mult10;
			}

			burstr_calculate(rtpab[i]->channel_adapt, rtpab[i]->stats.received, &burstr, &lossr);
			//cdr.add(lossr, c+"_lossr_adapt");
			//cdr.add(burstr, c+"_burstr_adapt");
			int mos_adapt_mult10 = (int)round(calculate_mos(lossr, burstr, rtpab[i]->codec, rtpab[i]->stats.received) * 10);
			cdr.add(mos_adapt_mult10, c+"_mos_adapt_mult10");
			if(mos_adapt_mult10 && (mos_min_mult10[i] < 0 || mos_adapt_mult10 < mos_min_mult10[i])) {
				mos_min_mult10[i] = mos_adapt_mult10;
			}
			
			if(mos_min_mult10[i] >= 0) {
				cdr.add(mos_min_mult10[i], c+"_mos_min_mult10");
			}

			if(rtpab[i]->rtcp.counter) {
				cdr.add(rtpab[i]->rtcp.loss, c+"_rtcp_loss");
				cdr.add(rtpab[i]->rtcp.maxfr, c+"_rtcp_maxfr");
				rtcp_avgfr_mult10[i] = (int)round(rtpab[i]->rtcp.avgfr * 10);
				cdr.add(rtcp_avgfr_mult10[i], c+"_rtcp_avgfr_mult10");
				cdr.add(rtpab[i]->rtcp.maxjitter / get_ticks_bycodec(rtpab[i]->codec), c+"_rtcp_maxjitter");
				rtcp_avgjitter_mult10[i] = (int)round(rtpab[i]->rtcp.avgjitter / get_ticks_bycodec(rtpab[i]->codec) * 10);
				cdr.add(rtcp_avgjitter_mult10[i], c+"_rtcp_avgjitter_mult10");
			}
		}

		if(seenudptl) {
		//if(isfax) {
			cdr.add(1000, "payload");
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

	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		
		sqlDb->setEnableSqlStringInContent(true);
		
		cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
		if(a_ua) {
			cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
		}
		if(b_ua) {
			cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
		}
		query_str += sqlDb->insertQuery(sql_cdr_table, cdr) + ";\n";
		
		query_str += "if row_count() > 0 then\n";
		query_str += "set @cdr_id = last_insert_id();\n";
		
		cdr_next.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
		query_str += sqlDb->insertQuery(sql_cdr_next_table, cdr_next) + ";\n";
		
		if(sql_cdr_table_last30d[0] ||
		   sql_cdr_table_last7d[0] ||
		   sql_cdr_table_last1d[0]) {
			cdr.add("_\\_'SQL'_\\_:@cdr_id", "ID");
			if(sql_cdr_table_last30d[0]) {
				query_str += sqlDb->insertQuery(sql_cdr_table_last30d, cdr) + ";\n";
			}
			if(sql_cdr_table_last7d[0]) {
				query_str += sqlDb->insertQuery(sql_cdr_table_last7d, cdr) + ";\n";
			}
			if(sql_cdr_table_last1d[0]) {
				query_str += sqlDb->insertQuery(sql_cdr_table_last1d, cdr) + ";\n";
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

				SqlDb_row rtps;
				rtps.add("_\\_'SQL'_\\_:@cdr_id", "cdr_ID");
				rtps.add(rtp[i]->payload, "payload");
				rtps.add(htonl(rtp[i]->saddr), "saddr");
				rtps.add(htonl(rtp[i]->daddr), "daddr");
				rtps.add(rtp[i]->ssrc, "ssrc");
				rtps.add(rtp[i]->s->received, "received");
				rtps.add(rtp[i]->stats.lost, "loss");
				rtps.add((unsigned int)(rtp[i]->stats.maxjitter * 10), "maxjitter_mult10");
				rtps.add(diff, "firsttime");
				if(opt_cdr_partition && sqlDb->existsColumnCalldateInCdrRtp) {
					rtps.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDb->insertQuery("cdr_rtp", rtps) + ";\n";
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
				if(opt_cdr_partition) {
					dtmf.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				query_str += sqlDb->insertQuery("cdr_dtmf", dtmf) + ";\n";
			}
		}
		
		sqlDb->setEnableSqlStringInContent(false);
		
		query_str += "end if";
		
		pthread_mutex_lock(&mysqlquery_lock);
		mysqlquery.push(query_str);
		pthread_mutex_unlock(&mysqlquery_lock);
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
	lastSIPresponse_id = sqlDb->getIdOrInsert(sql_cdr_sip_response_table, "id", "lastSIPresponse", cdr_sip_response);
	if(cdr_ua_a) {
		a_ua_id = sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_a);
	}
	if(cdr_ua_b) {
		b_ua_id = sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_b);
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
	
	int cdrID = sqlDb->insert(sql_cdr_table, cdr);

	if(cdrID > 0) {
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

				SqlDb_row rtps;
				rtps.add(cdrID, "cdr_ID");
				rtps.add(rtp[i]->payload, "payload");
				rtps.add(htonl(rtp[i]->saddr), "saddr");
				rtps.add(htonl(rtp[i]->daddr), "daddr");
				rtps.add(rtp[i]->ssrc, "ssrc");
				rtps.add(rtp[i]->s->received, "received");
				rtps.add(rtp[i]->stats.lost, "loss");
				rtps.add((unsigned int)(rtp[i]->stats.maxjitter * 10), "maxjitter_mult10");
				rtps.add(diff, "firsttime");
				if(opt_cdr_partition && sqlDb->existsColumnCalldateInCdrRtp) {
					rtps.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				sqlDb->insert("cdr_rtp", rtps);
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
				if(opt_cdr_partition) {
					dtmf.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				}
				sqlDb->insert("cdr_dtmf", dtmf);
			}
		}

		if(opt_printinsertid) {
			printf("CDRID:%d\n", cdrID);
		}

		cdr_next.add(cdrID, "cdr_ID");
		sqlDb->insert(sql_cdr_next_table, cdr_next);
		if(sql_cdr_table_last30d[0] ||
		   sql_cdr_table_last7d[0] ||
		   sql_cdr_table_last1d[0]) {
			cdr.add(cdrID, "ID");
			if(sql_cdr_table_last30d[0]) {
				sqlDb->insert(sql_cdr_table_last30d, cdr);
			}
			if(sql_cdr_table_last7d[0]) {
				sqlDb->insert(sql_cdr_table_last7d, cdr);
			}
			if(sql_cdr_table_last1d[0]) {
				sqlDb->insert(sql_cdr_table_last1d, cdr);
			}
		}
	}
	
	return(cdrID <= 0);
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveRegisterToDb() {
	const char *register_table = "register";
	
	if(!prepareForEscapeString())
		return(1);
	
	string query;

	SqlDb_row cdr_ua;
	cdr_ua.add(sqlEscapeString(a_ua), "ua");

	unsigned int now = time(NULL);

	if(last_register_clean == 0) {
		// on first run the register table has to be deleted 
		if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
			sqlDb->query("SET sql_log_bin = 0;");
		}
		query = "DELETE FROM register";
		sqlDb->query(query);
		if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
			sqlDb->query("SET sql_log_bin = 1;");
		}
	} else if((last_register_clean + REGISTER_CLEAN_PERIOD) < now){
		// last clean was done older than CLEAN_PERIOD seconds
		query = "INSERT INTO register_state (created_at, sipcallerip, from_num, to_num, to_domain, contact_num, contact_domain, digestusername, expires, state, ua_id) SELECT expires_at, sipcallerip, from_num, to_num, to_domain, contact_num, contact_domain, digestusername, expires, 5, ua_id FROM register WHERE expires_at <= NOW()";
		sqlDb->query(query);
		if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
			sqlDb->query("SET sql_log_bin = 0;");
		}
		query = "DELETE FROM register WHERE expires_at <= NOW()";
		if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
			sqlDb->query("SET sql_log_bin = 1;");
		}
		sqlDb->query(query);
	}
	last_register_clean = now;

	char fname[32];
	sprintf(fname, "%llu", fname2);

	switch(regstate) {
	case 1:
	case 3:
		if(isTypeDb("mysql")) {
			char ips[32];
			char ipd[32];
			sprintf(ips, "%u", htonl(sipcallerip));
			sprintf(ipd, "%u", htonl(sipcalledip));
			char tmpregstate[32];
			sprintf(tmpregstate, "%d", regstate);
			char regexpires[32];
			sprintf(regexpires, "%d", register_expires);
			char idsensor[12];
			sprintf(idsensor, "%d", opt_id_sensor);
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
			pthread_mutex_lock(&mysqlquery_lock);
			mysqlquery.push(query);
			pthread_mutex_unlock(&mysqlquery_lock);
		} else {
			query = string(
				"SELECT ID, state, ") +
				       "UNIX_TIMESTAMP(expires_at) AS expires_at, " +
				       "_LC_[(UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(" + sqlEscapeStringBorder(sqlDateTimeString(calltime())) + "))] AS expired " +
				"FROM " + register_table + " " +
				"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND to_domain = " + sqlEscapeStringBorder(called_domain) + 
					//" AND digestusername = " + sqlEscapeStringBorder(digest_username) + " " +
				"ORDER BY ID DESC"; // LIMIT 1 
//			if(verbosity > 2) cout << query << "\n";
			{
			if(!sqlDb->query(query)) {
				syslog(LOG_ERR, "Error: Query [%s] failed.", query.c_str());
				break;
			}

			SqlDb_row rsltRow = sqlDb->fetchRow();
			if(rsltRow) {
				// REGISTER message is already in register table, delete old REGISTER and save the new one 
				int expired = atoi(rsltRow["expired"].c_str()) == 1;
				time_t expires_at = atoi(rsltRow["expires_at"].c_str());

				if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
					sqlDb->query("SET sql_log_bin = 0;");
				}
				string query = "DELETE FROM " + (string)register_table + " WHERE ID = '" + (rsltRow["ID"]).c_str() + "'";
				if(!sqlDb->query(query)) {
					syslog(LOG_WARNING, "Query [%s] failed.", query.c_str());
				}
				if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
					sqlDb->query("SET sql_log_bin = 1;");
				}

				if(expired) {
					// the previous REGISTER expired, save to register_state
					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(expires_at).c_str()), "created_at");
					reg.add(htonl(sipcallerip), "sipcallerip");
					reg.add(htonl(sipcalledip), "sipcalledip");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(called), "to_num");
					reg.add(sqlEscapeString(called_domain), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					reg.add(register_expires, "expires");
					reg.add(5, "state");
					reg.add(fname, "fname");
					reg.add(opt_id_sensor, "id_sensor");
					reg.add(sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
					sqlDb->insert("register_state", reg);
				}

				if(atoi(rsltRow["state"].c_str()) != regstate || register_expires == 0) {
					// state changed or device unregistered, store to register_state
					SqlDb_row reg;
					reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "created_at");
					reg.add(htonl(sipcallerip), "sipcallerip");
					reg.add(htonl(sipcalledip), "sipcalledip");
					reg.add(sqlEscapeString(caller), "from_num");
					reg.add(sqlEscapeString(called), "to_num");
					reg.add(sqlEscapeString(called_domain), "to_domain");
					reg.add(sqlEscapeString(contact_num), "contact_num");
					reg.add(sqlEscapeString(contact_domain), "contact_domain");
					reg.add(sqlEscapeString(digest_username), "digestusername");
					reg.add(register_expires, "expires");
					reg.add(regstate, "state");
					reg.add(sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
					reg.add(fname, "fname");
					reg.add(opt_id_sensor, "id_sensor");
					sqlDb->insert("register_state", reg);
				}
			} else {
				// REGISTER message is new, store it to register_state
				SqlDb_row reg;
				reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "created_at");
				reg.add(htonl(sipcallerip), "sipcallerip");
				reg.add(htonl(sipcalledip), "sipcalledip");
				reg.add(sqlEscapeString(caller), "from_num");
				reg.add(sqlEscapeString(called), "to_num");
				reg.add(sqlEscapeString(called_domain), "to_domain");
				reg.add(sqlEscapeString(contact_num), "contact_num");
				reg.add(sqlEscapeString(contact_domain), "contact_domain");
				reg.add(sqlEscapeString(digest_username), "digestusername");
				reg.add(register_expires, "expires");
				reg.add(regstate, "state");
				reg.add(sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
				reg.add(fname, "fname");
				reg.add(opt_id_sensor, "id_sensor");
				sqlDb->insert("register_state", reg);
			}

			// save successfull REGISTER to register table in case expires is not negative
			if(register_expires > 0) {
				SqlDb_row reg;
				reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
				reg.add(htonl(sipcallerip), "sipcallerip");
				reg.add(htonl(sipcalledip), "sipcalledip");
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
				reg.add(sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
				reg.add(register_expires, "expires");
				reg.add(sqlEscapeString(sqlDateTimeString(calltime() + register_expires).c_str()), "expires_at");
				reg.add(fname, "fname");
				reg.add(opt_id_sensor, "id_sensor");
				reg.add(regstate, "state");
				if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
					sqlDb->query("SET sql_log_bin = 0;");
				}
				int res = sqlDb->insert(register_table, reg) <= 0;
				if(opt_sip_register_active_nologbin && isTypeDb("mysql")) {
					sqlDb->query("SET sql_log_bin = 1;");
				}
				return res;
			}
			}
		}
		break;
	case 2:
		// REGISTER failed. Check if there is already in register_failed table failed register within last hour 
		query = string(
			"SELECT counter FROM register_failed ") +
			"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND to_domain = " + sqlEscapeStringBorder(called_domain) + 
				" AND digestusername = " + sqlEscapeStringBorder(digest_username) + " AND created_at >= SUBTIME(NOW(), '01:00:00')";
		if(sqlDb->query(query)) {
			SqlDb_row rsltRow = sqlDb->fetchRow();
			char fname[32];
			sprintf(fname, "%llu", fname2);
			if(rsltRow) {
				// there is already failed register, update counter and do not insert
				string query = string(
					"UPDATE register_failed SET created_at = NOW(), fname = " + sqlEscapeStringBorder(fname) + ", counter = counter + 1 ") +
					"WHERE to_num = " + sqlEscapeStringBorder(called) + " AND digestusername = " + sqlEscapeStringBorder(digest_username) + 
						" AND created_at >= SUBTIME(NOW(), '01:00:00')";
				sqlDb->query(query);
			} else {
				// this is new failed attempt within hour, insert
				SqlDb_row reg;
				reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "created_at");
				reg.add(htonl(sipcallerip), "sipcallerip");
				reg.add(htonl(sipcalledip), "sipcalledip");
				reg.add(sqlEscapeString(caller), "from_num");
				reg.add(sqlEscapeString(called), "to_num");
				reg.add(sqlEscapeString(called_domain), "to_domain");
				reg.add(sqlEscapeString(contact_num), "contact_num");
				reg.add(sqlEscapeString(contact_domain), "contact_domain");
				reg.add(sqlEscapeString(digest_username), "digestusername");
				reg.add(sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua), "ua_id");
				reg.add(fname, "fname");
				if(opt_id_sensor > -1) {
					reg.add(opt_id_sensor, "id_sensor");
				}
				sqlDb->insert("register_failed", reg);
			}
		}
		break;
	}
	
	return 1;
}

int
Call::saveMessageToDb() {
	if(!prepareForEscapeString())
		return(1);

	SqlDb_row cdr,
			m_contenttype,
			cdr_sip_response,
			cdr_ua_a,
			cdr_ua_b;
	if(opt_id_sensor > -1) {
		cdr.add(opt_id_sensor, "id_sensor");
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

	cdr.add(htonl(sipcallerip), "sipcallerip");
	cdr.add(htonl(sipcalledip), "sipcalledip");
	cdr.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
	if(!geoposition.empty()) {
		cdr.add(sqlEscapeString(geoposition), "GeoPosition");
	}
	cdr.add(sqlEscapeString(fbasename), "fbasename");
	if(message) {
		cdr.add(sqlEscapeString(message), "message");
	}
	if(contenttype) {
		m_contenttype.add(sqlEscapeString(contenttype), "contenttype");
		unsigned int id_contenttype = sqlDb->getIdOrInsert("contenttype", "id", "contenttype", m_contenttype);
		cdr.add(id_contenttype, "id_contenttype");
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


#if 1
	string query_str;
	
	sqlDb->setEnableSqlStringInContent(true);
	
	cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(lastSIPresponse) + ")", "lastSIPresponse_id");
	if(a_ua) {
		cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(a_ua) + ")", "a_ua_id");
	}
	if(b_ua) {
		cdr.add(string("_\\_'SQL'_\\_:") + "getIdOrInsertUA(" + sqlEscapeStringBorder(b_ua) + ")", "b_ua_id");
	}
	query_str += sqlDb->insertQuery("message", cdr);
	
	pthread_mutex_lock(&mysqlquery_lock);
	mysqlquery.push(query_str);
	pthread_mutex_unlock(&mysqlquery_lock);
	//cout << endl << endl << query_str << endl << endl << endl;
	return(0);
#endif

#if 0

	unsigned int 
			lastSIPresponse_id = 0,
			a_ua_id = 0,
			b_ua_id = 0;

	lastSIPresponse_id = sqlDb->getIdOrInsert(sql_cdr_sip_response_table, "id", "lastSIPresponse", cdr_sip_response);
	cdr_ua_a.add(sqlEscapeString(a_ua), "ua");
	a_ua_id = sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_a);
	cdr_ua_b.add(sqlEscapeString(b_ua), "ua");
	b_ua_id = sqlDb->getIdOrInsert(sql_cdr_ua_table, "id", "ua", cdr_ua_b);

	cdr.add(lastSIPresponse_id, "lastSIPresponse_id", true);
	cdr.add(a_ua_id, "a_ua_id", true);
	cdr.add(b_ua_id, "b_ua_id", true);

	int cdrID = sqlDb->insert("message", cdr);

	return(cdrID <= 0);
#endif
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
	char buf[MAX_CALL_ID];
	printf("cidl:%lu\n", call_id_len);
	memcpy(buf, call_id, MIN(call_id_len,MAX_CALL_ID)); 
	buf[MIN(call_id_len,MAX_CALL_ID)] = '\0';
	printf("-call dump %p---------------------------------\n", this);
	printf("callid:%s\n", buf);
	printf("last packet time:%d\n", (int)get_last_packet_time());
	printf("last SIP response [%d] [%s]\n", lastSIPresponseNum, lastSIPresponse);
	
	// print assigned IP:port 
	if(ipport_n > 0) {
		printf("ipport_n:%d\n", ipport_n);
		for(int i = 0; i < ipport_n; i++) 
			printf("addr: %u, port: %d\n", addr[i], port[i]);
	} else {
		printf("no IP:port assigned\n");
	}
	if(seeninvite) {
		printf("From:%s\n", caller);
		printf("To:%s\n", called);
	}
	printf("First packet: %d, Last pakcet: %d\n", (int)get_first_packet_time(), (int)get_last_packet_time());
	printf("ssrc_n:%d\n", ssrc_n);
	printf("Call statistics:\n");
	if(ssrc_n > 0) {
		for(int i = 0; i < ssrc_n; i++) {
			rtp[i]->dump();
		}
	}
	printf("-end call dump  %p----------------------------\n", this);
}

/* constructor */
Calltable::Calltable() {
	pthread_mutex_init(&qlock, NULL);
	pthread_mutex_init(&qdellock, NULL);
	pthread_mutex_init(&flock, NULL);

//	pthread_mutexattr_init(&calls_listMAPlock_attr);
//	pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_NORMAL);
	pthread_mutex_init(&calls_listMAPlock, NULL);

	memset(calls_hash, 0x0, sizeof(calls_hash));
};

/* destructor */
Calltable::~Calltable() {
	pthread_mutex_destroy(&qlock);
	pthread_mutex_destroy(&qdellock);
	pthread_mutex_destroy(&flock);
	pthread_mutex_destroy(&calls_listMAPlock);
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
	Ipportnode *node = (Ipportnode *)malloc(sizeof(Ipportnode));
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
	u_int32_t h;
	hash_node *node = NULL;

	h = tuplehash(addr, port);

	// check if there is not already call in hash 
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			// there is already some call which is receiving packets to the same IP:port
			// this can happen if the old call is waiting for hangup and is still in memory
			// replace the node but also store the last call to new call and vice versa 
			if(allowrelation && call != node->call) {
				//syslog(LOG_NOTICE, "allowrelation %p %p\n", call, node->call);
				node->call->relationcall = call;
				call->relationcall = node->call;
			}
			if(call != node->call) {
				// just replace this IP:port to new call
				node->addr = addr;
				node->port = port;
				node->call = call;
				node->iscaller = iscaller;
				node->is_rtcp = is_rtcp;
				node->is_fax = is_fax;
				return;
			// or it can happen if voipmonitor is sniffing SIP proxy which forwards SIP
			} else {
				// packets to another SIP proxy with the same SDP ports
				// in this case just return 
				node->is_fax = is_fax;
				return;
			}
		}
	}

	// adding to hash at first position
	node = (hash_node *)malloc(sizeof(hash_node));
	memset(node, 0x0, sizeof(hash_node));
	node->addr = addr;
	node->port = port;
	node->call = call;
	node->iscaller = iscaller;
	node->is_rtcp = is_rtcp;
	node->is_fax = is_fax;
	node->next = (hash_node *)calls_hash[h];
	calls_hash[h] = node;
}

/* remove node from hash */
void
Calltable::hashRemove(in_addr_t addr, unsigned short port) {
	hash_node *node = NULL, *prev = NULL;
	int h;

	h = tuplehash(addr, port);
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if (node->addr == addr && node->port == port) {
			if (prev == NULL) {
				calls_hash[h] = node->next;
				free(node);
				return;
			} else {
				prev->next = node->next;
				free(node);
				return;
			}
		}
		prev = node;
	}
}

/* remove node from hash */
void
Calltable::mapRemove(in_addr_t addr, unsigned short port) {
	if (ipportmap.find(addr) != ipportmap.end()) {
		ipportmapIT = ipportmap[addr].find(port);
		if(ipportmapIT != ipportmap[addr].end()) {
			Ipportnode *node = (*ipportmapIT).second;
			free(node);
			ipportmap[addr].erase(ipportmapIT);
		}
	}
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
Call*
Calltable::hashfind_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller, int *is_rtcp, int *is_fax) {
	hash_node *node = NULL;
	u_int32_t h;

	h = tuplehash(addr, port);
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			*iscaller = node->iscaller;
			*is_rtcp = node->is_rtcp;
			*is_fax = node->is_fax;
			return node->call;
		}
	}
	return NULL;
}

Call*
Calltable::add(char *call_id, unsigned long call_id_len, time_t time, u_int32_t saddr, unsigned short port) {
	Call *newcall = new Call(call_id, call_id_len, time, this);
	calls++;
	newcall->saddr = saddr;
	newcall->sport = port;
	
	//flags
	if(opt_saveSIP) 
		newcall->flags |= FLAG_SAVESIP;

	if(opt_saveRTP) 
		newcall->flags |= FLAG_SAVERTP;

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
	callMAPIT = calls_listMAP.find(call_idS);
	if(callMAPIT == calls_listMAP.end()) {
		// not found
		return NULL;
	} else {
		return (*callMAPIT).second;
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

Call*
Calltable::find_by_skinny_partyid(unsigned int partyid) {
	skinny_partyIDIT = skinny_partyID.find(partyid);
	if(skinny_partyIDIT == skinny_partyID.end()) {
		// not found
		return NULL;
	} else {
		return (*skinny_partyIDIT).second;
	}
}


/* iterate all calls in table which are 5 minutes inactive and save them into SQL 
 * ic currtime = 0, save it immediatly
*/

#if 0
int
Calltable::cleanup_old( time_t currtime ) {
	for (call = calls_list.begin(); call != calls_list.end();) {
		if(verbosity > 2) (*call)->dump();
		// rtptimeout seconds of inactivity will save this call and remove from call table
		if(currtime == 0 || ((*call)->destroy_call_at != 0 and (*call)->destroy_call_at <= currtime) || (currtime - (*call)->get_last_packet_time() > rtptimeout)) {
			if ((*call)->get_f_pcap() != NULL){
				pcap_dump_flush((*call)->get_f_pcap());
				if ((*call)->get_f_pcap() != NULL) 
					pcap_dump_close((*call)->get_f_pcap());
				(*call)->set_f_pcap(NULL);
			}
			if(currtime == 0) {
				/* we are saving calls because of terminating SIGTERM and we dont know 
				 * if the call ends successfully or not. So we dont want to confuse monitoring
				 * applications which reports unterminated calls so mark this call as sighup */
				(*call)->sighup = true;
				if(verbosity > 2)
					syslog(LOG_NOTICE, "Set call->sighup\n");
			}
			// we have to close all raw files as there can be data in buffers 
			(*call)->closeRawFiles();
			/* move call to queue for mysql processing */
			lock_calls_queue();
			calls_queue.push(*call);
			unlock_calls_queue();
			calls_list.erase(call++);
		} else {
			++call;
		}
	}
	return 0;
}
#endif

int
Calltable::cleanup( time_t currtime ) {
	Call* call;
	lock_calls_listMAP();
	for (callMAPIT = calls_listMAP.begin(); callMAPIT != calls_listMAP.end();) {
		call = (*callMAPIT).second;
		if(verbosity > 2) call->dump();
		// rtptimeout seconds of inactivity will save this call and remove from call table
		if(call->rtppcaketsinqueue == 0 and (currtime == 0 || (call->destroy_call_at != 0 and call->destroy_call_at <= currtime) || (currtime - call->get_last_packet_time() > rtptimeout))) {
			if(call->relationcall) {
				// break relation 
				call->relationcall->relationcall = NULL;
				call->relationcall = NULL;
			}
			call->hashRemove();
			if (call->get_fsip_pcap() != NULL){
				pcap_dump_flush(call->get_fsip_pcap());
				if (call->get_fsip_pcap() != NULL) {
					pcap_dump_close(call->get_fsip_pcap());
					if(opt_cachedir[0] != '\0') {
						call->addtocachequeue(call->sip_pcapfilename);
					}
				}
				call->set_fsip_pcap(NULL);
			}
			if (call->get_frtp_pcap() != NULL){
				pcap_dump_flush(call->get_frtp_pcap());
				if (call->get_frtp_pcap() != NULL) {
					pcap_dump_close(call->get_frtp_pcap());
					if(opt_cachedir[0] != '\0') {
						call->addtocachequeue(call->rtp_pcapfilename);
					}
				}
				call->set_frtp_pcap(NULL);
			}
			if (call->get_f_pcap() != NULL){
				pcap_dump_flush(call->get_f_pcap());
				if (call->get_f_pcap() != NULL) {
					pcap_dump_close(call->get_f_pcap());
					if(opt_cachedir[0] != '\0') {
						call->addtocachequeue(call->pcapfilename);
					}
				}
				call->set_f_pcap(NULL);
			}
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
		} else {
			++callMAPIT;
		}
	}
	unlock_calls_listMAP();
	return 0;
}

void Call::saveregister() {
	hashRemove();
	if (get_fsip_pcap() != NULL){
		pcap_dump_flush(get_fsip_pcap());
		if (get_fsip_pcap() != NULL) {
			pcap_dump_close(get_fsip_pcap());
			if(opt_cachedir[0] != '\0') {
				addtocachequeue(pcapfilename);
			}
		}
		set_fsip_pcap(NULL);
	}
	if (get_f_pcap() != NULL){
		pcap_dump_flush(get_f_pcap());
		if (get_f_pcap() != NULL) {
			pcap_dump_close(get_f_pcap());
			if(opt_cachedir[0] != '\0') {
				addtocachequeue(pcapfilename);
			}
		}
		set_f_pcap(NULL);
	}
	// we have to close all raw files as there can be data in buffers 
	closeRawFiles();
	/* move call to queue for mysql processing */
	((Calltable*)calltable)->lock_calls_queue();
	((Calltable*)calltable)->calls_queue.push_back(this);
	((Calltable*)calltable)->unlock_calls_queue();

	string call_idS = string(call_id, call_id_len);
        map<string, Call*>::iterator callMAPIT = ((Calltable*)calltable)->calls_listMAP.find(call_idS);
	if(callMAPIT == ((Calltable*)calltable)->calls_listMAP.end()) {
		syslog(LOG_ERR,"Fatal error REGISTER call_id[%s] not found in callMAPIT", call_id);
	} else {
		((Calltable*)calltable)->calls_listMAP.erase(callMAPIT);
	}
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

