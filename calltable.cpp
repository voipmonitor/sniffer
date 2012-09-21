/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. 
*/

/**
  * This file implements Calltable and Call class. Calltable implements operations 
  * on Call list. Call class implements operations on one call. 
*/


#include <list>
#include <iterator>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <math.h>

#include <iostream>
#include <sstream>
#include <vector>

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
extern char sql_driver[256];
extern char sql_cdr_table[256];
extern char mysql_host[256];
extern char mysql_database[256];
extern char mysql_table[256];
extern char mysql_user[256];
extern char mysql_password[256];
extern char odbc_dsn[256];
extern char odbc_user[256];
extern char odbc_password[256];
extern char odbc_driver[256];
extern int opt_callend;
int calls = 0;

//mysqlpp// mysqlpp::Connection con(false);
Odbc odbc;

extern SqlDb *sqlDb;

/* constructor */
Call::Call(char *call_id, unsigned long call_id_len, time_t time, void *ct) {
	last_callercodec = -1;
	ipport_n = 0;
	ssrc_n = 0;
	first_packet_time = time;
	last_packet_time = time;
	memcpy(this->call_id, call_id, MIN(call_id_len, MAX_CALL_ID));
	this->call_id[MIN(call_id_len, MAX_CALL_ID)] = '\0';
	this->call_id_len = call_id_len;
	f_pcap = NULL;
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
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
		rtp[i] = NULL;
	}
	fifo1 = 0;
	fifo2 = 0;
	listening_worker_run = NULL;
	tmprtp.call_owner = this;
	flags = 0;
	lastcallerrtp = NULL;
	lastcalledrtp = NULL;
	destroy_call_at = 0;
	custom_header1[0] = '\0';
	thread_num = 0;
	recordstopped = 0;
	dtmfflag = 0;
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

/* destructor */
Call::~Call(){
	hashRemove();

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

	if (get_f_pcap() != NULL){
		pcap_dump_flush(get_f_pcap());
		pcap_dump_close(get_f_pcap());
		set_f_pcap(NULL);
		if(opt_cachedir[0] != '\0') {
			addtocachequeue(pcapfilename);
		}
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
			if(opt_gzipGRAPH && rtp[i]->gfileGZ.is_open()) {
				rtp[i]->gfileGZ.close();
			} else if(rtp[i]->gfile.is_open()){
				rtp[i]->gfile.close();
			}
		}
	}
}

/* returns name of the directory in format YYYY-MM-DD */
char *
Call::dirname() {
	struct tm *t = localtime((const time_t*)(&first_packet_time));
	sprintf(sdirname, "%04d-%02d-%02d",  t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
	return sdirname;
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
		memcpy(tmp, ua, ua_len);
		tmp[ua_len] = '\0';
	}

	this->addr[ipport_n] = addr;
	this->port[ipport_n] = port;
	memcpy(this->rtpmap[ipport_n], rtpmap, MAX_RTPMAP * sizeof(int));
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
Call::read_rtp(unsigned char* data, int datalen, struct pcap_pkthdr *header, u_int32_t saddr, unsigned short port, int iscaller) {

	if(first_rtp_time == 0) {
		first_rtp_time = header->ts.tv_sec;
	}
	
	//RTP tmprtp; moved to Call structure to avoid creating and destroying class which is not neccessary
	tmprtp.fill(data, datalen, header, saddr);
	if(tmprtp.getSSRC() == 0 || tmprtp.getVersion() != 2) {
		// invalid ssrc
		return;
	}
	for(int i = 0; i < ssrc_n; i++) {
		if(rtp[i]->ssrc == tmprtp.getSSRC()) {
			// found 
			rtp[i]->read(data, datalen, header, saddr, seeninviteok);
			return;
		}
	}
	// adding new RTP source
	if(ssrc_n < MAX_SSRC_PER_CALL) {
		// close previouse graph files to save RAM 
		if(flags & FLAG_SAVEGRAPH) {
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
			sprintf(tmp, "%s/%s/%s.%d.graph%s", opt_cachedir, dirname(), get_fbasename_safe(), ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		} else {
			sprintf(tmp, "%s/%s.%d.graph%s", dirname(), get_fbasename_safe(), ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		}
		sprintf(rtp[ssrc_n]->gfilename, "%s/%s.%d.graph%s", dirname(), get_fbasename_safe(), ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		if(flags & FLAG_SAVEGRAPH) {
			if(opt_gzipGRAPH) {
				rtp[ssrc_n]->gfileGZ.open(tmp);
			} else {
				rtp[ssrc_n]->gfile.open(tmp);
			}
		}
		rtp[ssrc_n]->gfileRAW = NULL;
		sprintf(rtp[ssrc_n]->basefilename, "%s/%s.i%d", dirname(), get_fbasename_safe(), iscaller);
		int i = get_index_by_ip_port(saddr, port);
		memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[i], MAX_RTPMAP * sizeof(int));

		rtp[ssrc_n]->read(data, datalen, header, saddr, seeninviteok);
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
		pcap_dump_flush(this->get_f_pcap());
		if(this->get_f_pcap() != NULL) {
			pcap_dump_close(this->get_f_pcap());
			this->set_f_pcap(NULL);
		}

		if(opt_cachedir[0] != '\0') {
			addtocachequeue(pcapfilename);
			sprintf(str2, "%s/%s.pcap", opt_cachedir, pcapfilename);
		} else {
			sprintf(str2, "%s.pcap", pcapfilename);
		}

		unlink(str2);	
		this->recordstopped = 1;
		if(verbosity >= 1) {
			syslog(LOG_ERR,"Call %s/%s.pcap was stopped due to dtmf or norecord sip header. ", this->dirname(), this->get_fbasename_safe());
		}
	} else {
		if(verbosity >= 1) {
			syslog(LOG_ERR,"Call %s/%s.pcap was stopped before. Ignoring now. ", this->dirname(), this->get_fbasename_safe());
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


double calculate_mos(double ppl, double burstr, int codec) {

	if(codec == PAYLOAD_G729) {
		if(opt_mos_g729) {
			return (double)mos_g729((long double)ppl, (long double)burstr);
		} else {
			return calculate_mos_g711(ppl, burstr, 2);
		}
	} else {
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
	int payloadtype = -1;
	char cmd[1024];
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

	sprintf(wav0, "%s/%s.i0.wav", dirname(), get_fbasename_safe());
	sprintf(wav1, "%s/%s.i1.wav", dirname(), get_fbasename_safe());
	switch(opt_audio_format) {
	case FORMAT_WAV:
		sprintf(out, "%s/%s.wav", dirname(), get_fbasename_safe());
		break;
	case FORMAT_OGG:
		sprintf(out, "%s/%s.ogg", dirname(), get_fbasename_safe());
		break;
	}

	/* do synchronisation - calculate difference between start of both RTP direction and put silence to achieve proper synchronisation */
	/* first direction */
	sprintf(rawInfo, "%s/%s.i%d.rawInfo", dirname(), get_fbasename_safe(), 0);
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
	sprintf(rawInfo, "%s/%s.i%d.rawInfo", dirname(), get_fbasename_safe(), 1);
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
		syslog(LOG_ERR, "PCAP file %s/%s.pcap cannot be decoded to WAV probably missing RTP\n", dirname(), get_fbasename_safe());
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
		for(int i = 0; i < (abs(msdiff) / 20) * 160; i++) {
			fwrite(&zero, 1, 2, wav);
		}
		fclose(wav);
		/* end synchronisation */
	}

	/* process all files in playlist for each direction */
	for(int i = 0; i <= 1; i++) {
		if(i == 0 && adir == 0) {
			continue;
		}
		if(i == 1 && bdir == 0) {
			continue;
		}
		char *wav = i ? wav1 : wav0;

		/* open playlist */
		sprintf(rawInfo, "%s/%s.i%d.rawInfo", dirname(), get_fbasename_safe(), i);
		pl = fopen(rawInfo, "r");
		if(!pl) {
			syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
			return 1;
		}
		while(fgets(line, 256, pl)) {
			char raw[1024];
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			sprintf(raw, "%s/%s.i%d.%d.%lu.%d.%ld.%ld.raw", dirname(), get_fbasename_safe(), i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);

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
			case PAYLOAD_GSM:
				snprintf(cmd, 4092, "voipmonitor-gsm \"%s\" \"%s\"", raw, wav);
				if(verbosity > 1) syslog(LOG_ERR, "Converting GSM to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_G729:
				snprintf(cmd, 4092, "voipmonitor-g729 \"%s\" \"%s\"", raw, wav);
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.729 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_G723:
				snprintf(cmd, 4092, "voipmonitor-g723 \"%s\" \"%s\"", raw, wav);
				if(verbosity > 1) syslog(LOG_ERR, "Converting G.723 to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_ILBC:
				snprintf(cmd, 4092, "voipmonitor-ilbc \"%s\" \"%s\"", raw, wav);
				if(verbosity > 1) syslog(LOG_ERR, "Converting iLBC to WAV.\n");
				system(cmd);
				break;
			case PAYLOAD_SPEEX:
				snprintf(cmd, 4092, "voipmonitor-speex \"%s\" \"%s\"", raw, wav);
				if(verbosity > 1) syslog(LOG_ERR, "Converting speex to WAV.\n");
				system(cmd);
				break;
			default:
				syslog(LOG_ERR, "Call [%s] cannot be converted to WAV, unknown payloadtype [%d]\n", raw, payloadtype);
			}
			unlink(raw);
		}
		fclose(pl);
		unlink(rawInfo);
	}

	if(adir == 1 && bdir == 1) {
		switch(opt_audio_format) {
		case FORMAT_WAV:
			wav_mix(wav0, wav1, out);
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
			wav_mix(wav0, NULL, out);
			break;
		case FORMAT_OGG:
			ogg_mix(wav0, NULL, out);
			break;
		}
		unlink(wav0);
	} else if(bdir == 1) {
		switch(opt_audio_format) {
		case FORMAT_WAV:
			wav_mix(wav1, NULL, out);
			break;
		case FORMAT_OGG:
			ogg_mix(wav1, NULL, out);
			break;
		}
		unlink(wav1);
	}
 
	return 0;
}

int
Call::buildQuery(stringstream *query) {
	//mysqlpp// using namespace mysqlpp;
	/* walk two first RTP and store it to MySQL. */

	/* bye 
	 * 	3 - call was answered and properly terminated
	 * 	2 - call was answered but one of leg didnt confirm bye
	 * 	1 - call was answered but there was no bye 
	 * 	0 - call was not answered 
	 */
	
	if(isTypeDb("mssql")) {
		stringstream fields;
		stringstream values;
		fields 	<< "caller, caller_domain, caller_reverse, callername, callername_reverse, sipcallerip, "
				"sipcalledip, called, called_domain, called_reverse, duration, progress_time, "
				"first_rtp_time, connect_duration, calldate";
		if(opt_callend) {
			fields << ", callend";
		}

		fields << ", fbasename, sighup, lastSIPresponse, lastSIPresponseNum, bye";

		values 	<< sqlEscapeString(caller)
			<< ", " << sqlEscapeString(caller_domain)
			<< ", " << sqlEscapeString(reverseString(caller).c_str())
			<< ", " << sqlEscapeString(callername)
			<< ", " << sqlEscapeString(reverseString(callername).c_str())
			<< ", " << htonl(sipcallerip)
			<< ", " << htonl(sipcalledip)
			<< ", " << sqlEscapeString(called)
			<< ", " << sqlEscapeString(called_domain)
			<< ", " << sqlEscapeString(reverseString(called).c_str())
			<< ", " << duration()
			<< ", " << (progress_time ? progress_time - first_packet_time : -1)
			<< ", " << (first_rtp_time ? first_rtp_time  - first_packet_time : -1)
			<< ", " << (connect_time ? (duration() - (connect_time - first_packet_time)) : -1)
			<< ", " << sqlEscapeString(sqlDateTimeString(calltime()).c_str());
		
		if(opt_callend) {
			values << ", " << sqlEscapeString(sqlDateTimeString(calltime() + duration()).c_str());
		}

		values 	<< ", " << sqlEscapeString(fbasename)
			<< ", " << (sighup ? 1 : 0)
			<< ", " << sqlEscapeString(lastSIPresponse)
			<< ", " << lastSIPresponseNum
			<< ", " << ( seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0);
			
		if(strlen(custom_header1)) {
			fields << ", custom_header1";
			values << ", " << sqlEscapeString(custom_header1);
		}

		switch(whohanged) {
		case 0:
			fields 	<< ", whohanged";
			values 	<< ", 'caller'";
			break;
		case 1:
			fields 	<< ", whohanged";
			values 	<< ", 'callee'";
		}
		if(ssrc_n > 0) {
			/* sort all RTP streams by received packets + loss packets descend and save only those two with the biggest received packets. */
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
			fields 	<< ", a_ua, b_ua";
			values 	<< ", " << sqlEscapeString(a_ua)
				<< ", " << sqlEscapeString(b_ua);

			// save only two streams with the biggest received packets
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
				
				char c = i == 0 ? 'a' : 'b';

				fields 	<< ", " << c << "_index"
					<< ", " << c << "_received"
					<< ", " << c << "_lost"
					<< ", " << c << "_avgjitter"
					<< ", " << c << "_maxjitter"
					<< ", " << c << "_payload"; 
				values 	<< ", " << indexes[i]
					<< ", " << (rtp[indexes[i]]->stats.received + 2) // received is always 2 packet less compared to wireshark (add it here)
					<< ", " << rtp[indexes[i]]->stats.lost
					<< ", " << int(ceil(rtp[indexes[i]]->stats.avgjitter))
					<< ", " << int(ceil(rtp[indexes[i]]->stats.maxjitter))
					<< ", " << rtp[indexes[i]]->payload; 

				/* build a_sl1 - b_sl10 fields */
				for(int j = 1; j < 11; j++) {
					fields 	<< ", " << c << "_sl" << j;
					values	<< ", " << rtp[indexes[i]]->stats.slost[j];
				}
				/* build a_d50 - b_d300 fileds */
				fields 	<< ", " << c << "_d50"
					<< ", " << c << "_d70"
					<< ", " << c << "_d90"
					<< ", " << c << "_d120"
					<< ", " << c << "_d150"
					<< ", " << c << "_d200"
					<< ", " << c << "_d300";
				values 	<< ", " << rtp[indexes[i]]->stats.d50
					<< ", " << rtp[indexes[i]]->stats.d70
					<< ", " << rtp[indexes[i]]->stats.d90
					<< ", " << rtp[indexes[i]]->stats.d120
					<< ", " << rtp[indexes[i]]->stats.d150
					<< ", " << rtp[indexes[i]]->stats.d200
					<< ", " << rtp[indexes[i]]->stats.d300;
				
				/* store source addr */
				fields 	<< ", " << c << "_saddr";
				values	<< ", " << htonl(rtp[indexes[i]]->saddr);

				/* calculate lossrate and burst rate */
				double burstr, lossr;
				burstr_calculate(rtp[indexes[i]]->channel_fix1, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				fields 	<< ", " << c << "_lossr_f1"
					<< ", " << c << "_burstr_f1"
					<< ", " << c << "_mos_f1";
				values 	<< ", " << lossr
					<< ", " << burstr
					<< ", " << calculate_mos(lossr, burstr, rtp[indexes[i]]->payload);

				/* Jitterbuffer MOS statistics */
				burstr_calculate(rtp[indexes[i]]->channel_fix2, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				fields 	<< ", " << c << "_lossr_f2"
					<< ", " << c << "_burstr_f2"
					<< ", " << c << "_mos_f2";
				values 	<< ", " << lossr
					<< ", " << burstr
					<< ", " << calculate_mos(lossr, burstr, rtp[indexes[i]]->payload);

				burstr_calculate(rtp[indexes[i]]->channel_adapt, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				fields 	<< ", " << c << "_lossr_adapt"
					<< ", " << c << "_burstr_adapt"
					<< ", " << c << "_mos_adapt";
				values	<< ", " << lossr
					<< ", " << burstr
					<< ", " << calculate_mos(lossr, burstr, rtp[indexes[i]]->payload);

				if(rtp[indexes[i]]->rtcp.counter) {
					fields 	<< ", " << c << "_rtcp_loss"
						<< ", " << c << "_rtcp_maxfr"
						<< ", " << c << "_rtcp_avgfr"
						<< ", " << c << "_rtcp_maxjitter"
						<< ", " << c << "_rtcp_avgjitter";
					values	<< ", " << rtp[indexes[i]]->rtcp.loss
						<< ", " << rtp[indexes[i]]->rtcp.maxfr
						<< ", " << rtp[indexes[i]]->rtcp.avgfr
						<< ", " << rtp[indexes[i]]->rtcp.maxjitter
						<< ", " << rtp[indexes[i]]->rtcp.avgjitter;
				}
			}
		}
		*query << "INSERT INTO " << sql_cdr_table << " ( " << fields.str() << " ) VALUES ( " << values.str() << " )";
	} else {
		*query << "INSERT INTO `" << (mysql_table[0]&&strcmp(mysql_table,sql_cdr_table) ? mysql_table : sql_cdr_table) << "` " <<
			"SET caller = " << sqlEscapeString(caller) << 
			", caller_domain = " << sqlEscapeString(caller_domain) << 
			", caller_reverse = " << sqlEscapeString(reverseString(caller).c_str()) <<
			", callername = " << sqlEscapeString(callername) << 
			", callername_reverse = " << sqlEscapeString(reverseString(callername).c_str()) <<
			", sipcallerip = " << htonl(sipcallerip) <<
			", sipcalledip = " << htonl(sipcalledip) <<
			", called = " << sqlEscapeString(called) <<
			", called_domain = " << sqlEscapeString(called_domain) << 
			", called_reverse = " << sqlEscapeString(reverseString(called).c_str()) <<
			", duration = " << duration() << 
			", progress_time = " << (progress_time ? progress_time - first_packet_time : -1) << 
			", first_rtp_time = " << (first_rtp_time ? first_rtp_time  - first_packet_time : -1) << 
			", connect_duration = " << (connect_time ? (duration() - (connect_time - first_packet_time)) : -1) << 
			", calldate = FROM_UNIXTIME(" << calltime() << ")" <<
			", fbasename = " << sqlEscapeString(fbasename) << 
			", sighup = " << (sighup ? 1 : 0) << 
			", lastSIPresponse = " << sqlEscapeString(lastSIPresponse) << 
			", lastSIPresponseNum = " << lastSIPresponseNum << 
			", bye = " << ( seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0);

		if(opt_callend) {
			*query << ", callend = FROM_UNIXTIME(" << (calltime() + duration()) << ")";
		}

		if(strlen(custom_header1)) {
			*query << ", custom_header1 = " << sqlEscapeString(custom_header1);
		}

		switch(whohanged) {
		case 0:
			*query << " , whohanged = 'caller'";
			break;
		case 1:
			*query << " , whohanged = 'callee'";
		}
		if(ssrc_n > 0) {
			/* sort all RTP streams by received packets + loss packets descend and save only those two with the biggest received packets. */
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
			*query << " , " << "a_ua = " << sqlEscapeString(a_ua);
			*query << " , " << "b_ua = " << sqlEscapeString(b_ua);

			// save only two streams with the biggest received packets
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

				char c = i == 0 ? 'a' : 'b';

				*query << " , " << c << "_index = " << indexes[i];
				*query << " , " << c << "_received = " << (rtp[indexes[i]]->stats.received + 2); // received is always 2 packet less compared to wireshark (add it here)
				*query << " , " << c << "_lost = " << rtp[indexes[i]]->stats.lost;
				*query << " , " << c << "_avgjitter = " << int(ceil(rtp[indexes[i]]->stats.avgjitter));
				*query << " , " << c << "_maxjitter = " << int(ceil(rtp[indexes[i]]->stats.maxjitter)); 
				*query << " , " << c << "_payload = " << rtp[indexes[i]]->payload; 

				/* build a_sl1 - b_sl10 fields */
				for(int j = 1; j < 11; j++) {
					*query << " , " << c << "_sl" << j << " = " << rtp[indexes[i]]->stats.slost[j];
				}
				/* build a_d50 - b_d300 fileds */
				*query << " , " << c << "_d50 = " << rtp[indexes[i]]->stats.d50;
				*query << " , " << c << "_d70 = " << rtp[indexes[i]]->stats.d70;
				*query << " , " << c << "_d90 = " << rtp[indexes[i]]->stats.d90;
				*query << " , " << c << "_d120 = " << rtp[indexes[i]]->stats.d120;
				*query << " , " << c << "_d150 = " << rtp[indexes[i]]->stats.d150;
				*query << " , " << c << "_d200 = " << rtp[indexes[i]]->stats.d200;
				*query << " , " << c << "_d300 = " << rtp[indexes[i]]->stats.d300;
				
				/* store source addr */
				*query << " , " << c << "_saddr = " << htonl(rtp[indexes[i]]->saddr);

				/* calculate lossrate and burst rate */
				double burstr, lossr;
				burstr_calculate(rtp[indexes[i]]->channel_fix1, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				*query << " , " << c << "_lossr_f1 = " << lossr;
				*query << " , " << c << "_burstr_f1 = " << burstr;
				*query << " , " << c << "_mos_f1 = " << calculate_mos(lossr, burstr, rtp[indexes[i]]->payload);

				/* Jitterbuffer MOS statistics */
				burstr_calculate(rtp[indexes[i]]->channel_fix2, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				*query << " , " << c << "_lossr_f2 = " << lossr;
				*query << " , " << c << "_burstr_f2 = " << burstr;
				*query << " , " << c << "_mos_f2 = " << calculate_mos(lossr, burstr, rtp[indexes[i]]->payload);

				burstr_calculate(rtp[indexes[i]]->channel_adapt, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				*query << " , " << c << "_lossr_adapt = " << lossr;
				*query << " , " << c << "_burstr_adapt = " << burstr;
				*query << " , " << c << "_mos_adapt = " << calculate_mos(lossr, burstr, rtp[indexes[i]]->payload);

				if(rtp[indexes[i]]->rtcp.counter) {
					*query << " , " << c << "_rtcp_loss = " << rtp[indexes[i]]->rtcp.loss;
					*query << " , " << c << "_rtcp_maxfr = " << rtp[indexes[i]]->rtcp.maxfr;
					*query << " , " << c << "_rtcp_avgfr = " << rtp[indexes[i]]->rtcp.avgfr;
					*query << " , " << c << "_rtcp_maxjitter = " << rtp[indexes[i]]->rtcp.maxjitter;
					*query << " , " << c << "_rtcp_avgjitter = " << rtp[indexes[i]]->rtcp.avgjitter;
				}
			}
		}
	}
	return 0;
}

bool 
Call::prepareForEscapeString() {
	if(isSqlDriver("mysql")) {
		//mysqlpp//
		/*
		using namespace mysqlpp;
		if(!con.connected()) {
			con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
			if(!con.connected()) {
				syslog(LOG_ERR,"DB connection failed: %s", con.error());
				return false;
			}
		}
		*/
		if(sqlDb) {
			unsigned int pass = 0;
			while(!sqlDb->connected()) {
				sqlDb->connect();
				if(pass) {
					sleep(1);
				}
				++pass;
			}
			
		} else {
			return false;
		}
	}
	return true;
}

int
Call::doQuery(string &queryStr) {
	bool okQueryRslt = false;
	if(isSqlDriver("mysql")) {
		//mysqlpp//
		/*
		using namespace mysqlpp;
		for(int attempt = 0; attempt<2; ++attempt) {
			if(attempt>0 || !con.connected()) {
				if(attempt>0)
					con.disconnect();
				con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
				if(!con.connected()) {
					syslog(LOG_ERR,"DB connection failed: %s", con.error());
					return 1;
				}
			}
			mysqlpp::Query query = con.query();
			query << queryStr.c_str();
			query.store();
			if(!con.errnum()) {
				okQueryRslt = true;
				break;
			} else {
				syslog(LOG_ERR,"Error in query [%s] errnum:'%d' error:'%s'", queryStr.c_str(), con.errnum(), con.error());
				if(con.errnum() != 2006) { // errnum 2006 : MySQL server has gone away
					break;
				}
			}
		}
		*/
	} else if(isSqlDriver("odbc")) {
		for(int attempt = 0; attempt<2; ++attempt) {
			if(attempt>0 || !odbc.connected()) {
				if(attempt>0)
					odbc.disconnect();
				if(!odbc.connect(odbc_dsn, odbc_user, odbc_password)) {
					syslog(LOG_ERR, "DB connection failed: %s", odbc.getLastErrorString());
					return 1;
				}
			}
			if(odbc.query(queryStr.c_str())) {
				okQueryRslt = true;
				break;
			} else {
				syslog(LOG_ERR,"Error in query [%s]: '%s'", queryStr.c_str(), odbc.getLastErrorString());
			}
		}
	}
	return !okQueryRslt;
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveToDb() {
	if(verbosity > 0) { 
		cout << "process saveToDb function" << endl;
	}
	if(!prepareForEscapeString())
		return(1);
	
	if(isTypeDb("mysql")) {
		if(!sqlDb) {
			return(false);
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
		
		cdr.add(sighup ? 1 : 0, "sighup");
		cdr.add(lastSIPresponseNum, "lastSIPresponseNum");
		cdr.add(seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0, "bye");
		
		if(strlen(custom_header1)) {
			cdr_next.add(sqlEscapeString(custom_header1), "custom_header1");
		}

		if(whohanged == 0 || whohanged == 1) {
			cdr.add(whohanged ? "'callee'" : "'caller'", "whohanged");
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
			cdr_ua_a.add(sqlEscapeString(a_ua), "ua");
			cdr_ua_b.add(sqlEscapeString(b_ua), "ua");

			// save only two streams with the biggest received packets
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
				cdr.add(rtp[indexes[i]]->stats.lost, c+"_lost");
				cdr.add(int(ceil(rtp[indexes[i]]->stats.avgjitter)) * 10, c+"_avgjitter_mult10"); // !!!
				cdr.add(int(ceil(rtp[indexes[i]]->stats.maxjitter)), c+"_maxjitter");
				cdr.add(rtp[indexes[i]]->payload, c+"_payload"); 

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
				
				// store source addr
				cdr.add(htonl(rtp[indexes[i]]->saddr), c+"_saddr");

				// calculate lossrate and burst rate
				double burstr, lossr;
				burstr_calculate(rtp[indexes[i]]->channel_fix1, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				//cdr.add(lossr, c+"_lossr_f1");
				//cdr.add(burstr, c+"_burstr_f1");
				cdr.add((int)round(calculate_mos(lossr, burstr, rtp[indexes[i]]->payload) * 10), c+"_mos_f1_mult10");

				// Jitterbuffer MOS statistics
				burstr_calculate(rtp[indexes[i]]->channel_fix2, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				//cdr.add(lossr, c+"_lossr_f2");
				//cdr.add(burstr, c+"_burstr_f2");
				cdr.add((int)round(calculate_mos(lossr, burstr, rtp[indexes[i]]->payload) * 10), c+"_mos_f2_mult10");

				burstr_calculate(rtp[indexes[i]]->channel_adapt, rtp[indexes[i]]->stats.received, &burstr, &lossr);
				//cdr.add(lossr, c+"_lossr_adapt");
				//cdr.add(burstr, c+"_burstr_adapt");
				cdr.add((int)round(calculate_mos(lossr, burstr, rtp[indexes[i]]->payload) * 10), c+"_mos_adapt_mult10");

				if(rtp[indexes[i]]->rtcp.counter) {
					cdr.add(rtp[indexes[i]]->rtcp.loss, c+"_rtcp_loss");
					cdr.add(rtp[indexes[i]]->rtcp.maxfr, c+"_rtcp_maxfr");
					cdr.add((int)round(rtp[indexes[i]]->rtcp.avgfr * 10), c+"_rtcp_avgfr_mult10");
					cdr.add(rtp[indexes[i]]->rtcp.maxjitter, c+"_rtcp_maxjitter");
					cdr.add((int)round(rtp[indexes[i]]->rtcp.avgjitter * 10), c+"_rtcp_avgjitter_mult10");
				}
			}
		}
		
		/*
		caller_id = sqlDb->getIdOrInsert("cdr_phone_number", "id", "number", cdr_phone_number_caller, "");
		called_id = sqlDb->getIdOrInsert("cdr_phone_number", "id", "number", cdr_phone_number_called, "");
		callername_id = sqlDb->getIdOrInsert("cdr_name", "id", "name", cdr_name, "");
		caller_domain_id = sqlDb->getIdOrInsert("cdr_domain", "id", "domain", cdr_domain_caller, "");
		called_domain_id = sqlDb->getIdOrInsert("cdr_domain", "id", "domain", cdr_domain_called, "");
		*/
		lastSIPresponse_id = sqlDb->getIdOrInsert("cdr_sip_response", "id", "lastSIPresponse", cdr_sip_response, "");
		if(cdr_ua_a) {
			a_ua_id = sqlDb->getIdOrInsert("cdr_ua", "id", "ua", cdr_ua_a, "");
		}
		if(cdr_ua_a) {
			b_ua_id = sqlDb->getIdOrInsert("cdr_ua", "id", "ua", cdr_ua_b, "");
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
		
		unsigned int cdrID = sqlDb->insert("cdr", cdr, "");
		if(cdrID) {
			cdr_next.add(cdrID, "cdr_ID");
			sqlDb->insert("cdr_next", cdr_next, "");
		}
		
		return(cdrID <= 0);
		
	} else {
		stringstream queryStream;
		buildQuery(&queryStream);
		string queryStr = queryStream.str();
		if(verbosity > 0) { 
			cout << queryStr << "\n";
		}
	
		return doQuery(queryStr);
	}
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveRegisterToDb() {
	const char *register_table = "register";
	
	if(!prepareForEscapeString())
		return(1);
	
	if(isTypeDb("mysql")) {
		if(!sqlDb) {
			return(false);
		}
		SqlDb_row reg;
		reg.add(htonl(sipcallerip), "sipcallerip");
		reg.add(htonl(sipcalledip), "sipcalledip");
		reg.add(sqlEscapeString(sqlDateTimeString(calltime()).c_str()), "calldate");
		reg.add(sqlEscapeString(fbasename), "fbasename");
		reg.add(sighup ? 1 : 0, "sighup");
		return(sqlDb->insert(register_table, reg, "") <= 0);
	} else {
		stringstream queryStream;
		if(isTypeDb("mssql")) {
			stringstream fields;
			stringstream values;
			fields	<< "sipcallerip, sipcalledip, calldate, fbasename, sighup";
			values 	<< htonl(sipcallerip)
				<< ", " << htonl(sipcalledip);
			if(isTypeDb("mssql")) {
				values << ", " << sqlEscapeString(sqlDateTimeString(calltime()).c_str());
			} else {
				values << ", " << "FROM_UNIXTIME(" << calltime() << ")";
			}
			values 	<< ", " << sqlEscapeString(fbasename)
				<< ", " << (sighup ? 1 : 0);
			queryStream << "INSERT INTO " << register_table << " ( " << fields.str() << " ) VALUES ( " << values.str() << " )";
		} else {
			queryStream << "INSERT INTO `" << register_table << "` SET " <<
					"  sipcallerip = " << htonl(sipcallerip) <<
					", sipcalledip = " << htonl(sipcalledip) <<
					", calldate = FROM_UNIXTIME(" << calltime() << ")" <<
					", fbasename = " << sqlEscapeString(fbasename) << 
					", sighup = " << (sighup ? 1 : 0);
		}
		string queryStr = queryStream.str();
		if(verbosity > 2) {
			cout << queryStr << "\n";
		}
		
		return doQuery(queryStr);
	}
}

char *
Call::get_fbasename_safe() {
	strncpy(fbasename_safe, fbasename, MAX_FNAME * sizeof(char));
	for (unsigned int i = 0; i < strlen(fbasename_safe) && i < MAX_FNAME; i++) {
		if (!(fbasename[i] == ':' || fbasename[i] == '-' || fbasename[i] == '.' || fbasename[i] == '@' || isalnum(fbasename[i]))) {
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
	memset(calls_hash, 0x0, sizeof(calls_hash));
};

/* destructor */
Calltable::~Calltable() {
	pthread_mutex_destroy(&qlock);
	pthread_mutex_destroy(&qdellock);
};


/* add node to hash. collisions are linked list of nodes*/
void
Calltable::hashAdd(in_addr_t addr, unsigned short port, Call* call, int iscaller, int is_rtcp) {
	u_int32_t h;
	hash_node *node = NULL;

	h = tuplehash(addr, port);

	// check if there is not already call in hash 
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			// there is already some call which is receiving packets to the same IP:port
			// this can happen if the old call is waiting for hangup and is still in memory
			if(call != node->call) {
				// just replace this IP:port to new call
				node->addr = addr;
				node->port = port;
				node->call = call;
				node->iscaller = iscaller;
				node->is_rtcp = is_rtcp;
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
	node = (hash_node *)malloc(sizeof(hash_node));
	memset(node, 0x0, sizeof(hash_node));
	node->addr = addr;
	node->port = port;
	node->call = call;
	node->iscaller = iscaller;
	node->is_rtcp = is_rtcp;
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

/* find call in hash */
Call*
Calltable::hashfind_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller, int *is_rtcp) {
	hash_node *node = NULL;
	u_int32_t h;

	h = tuplehash(addr, port);
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			*iscaller = node->iscaller;
			*is_rtcp = node->is_rtcp;
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

	if(opt_sip_register) 
		newcall->flags |= FLAG_SAVEREGISTER;

	//calls_list.push_front(newcall);
	string call_idS = string(call_id, call_id_len);
	calls_listMAP[call_idS] = newcall;
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

#if 0
/* find Call by ip addr and port (mathing RTP proto to call) and return reference to this Call */
Call*
Calltable::find_by_ip_port(in_addr_t addr, unsigned short port, int *iscaller) {
	// Calls iterator (whole table) 
	for (call = calls_list.begin(); call != calls_list.end(); ++call) {
		if((*call)->find_by_ip_port(addr, port, iscaller))
			// we have found it
			return *call;
	}
	// IP:port is not in Call table
	return NULL;
}
#endif

/* iterate all calls in table which are 5 minutes inactive and save them into SQL 
 * ic currtime = 0, save it immediatly
*/

#if 0
int
Calltable::cleanup_old( time_t currtime ) {
	for (call = calls_list.begin(); call != calls_list.end();) {
		if(verbosity > 2) (*call)->dump();
		// RTPTIMEOUT seconds of inactivity will save this call and remove from call table
		if(currtime == 0 || ((*call)->destroy_call_at != 0 and (*call)->destroy_call_at <= currtime) || (currtime - (*call)->get_last_packet_time() > RTPTIMEOUT)) {
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
	for (callMAPIT = calls_listMAP.begin(); callMAPIT != calls_listMAP.end();) {
		call = (*callMAPIT).second;
		if(verbosity > 2) call->dump();
		// RTPTIMEOUT seconds of inactivity will save this call and remove from call table
		if(currtime == 0 || (call->destroy_call_at != 0 and call->destroy_call_at <= currtime) || (currtime - call->get_last_packet_time() > RTPTIMEOUT)) {
			call->hashRemove();
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
			calls_queue.push(call);
			unlock_calls_queue();
			calls_listMAP.erase(callMAPIT++);
		} else {
			++callMAPIT;
		}
	}
	return 0;
}

string sqlDateTimeString(time_t unixTime) {
	struct tm * localTime = localtime(&unixTime);
	char dateTimeBuffer[50];
	strftime(dateTimeBuffer, sizeof(dateTimeBuffer), "%Y-%m-%d %H:%M:%S", localTime);
	return string(dateTimeBuffer);
}

string sqlEscapeString(const char *inputStr, char borderChar) {
	string rsltString;
	bool escaped = false;
	if(isSqlDriver("mysql")) {
		//mysqlpp//
		/*
		if(con.connected()) {
			con.query().escape_string(&rsltString, inputStr, strlen(inputStr));
			escaped = true;
		}
		*/
		if(sqlDb && sqlDb->connected()) {
			rsltString = sqlDb->escape(inputStr);
			escaped = true;
		}
	}
	if(!escaped) {
		struct {
			char ch;
			const char* escStr;
		} 
		escCharsMsSql[] = 
					{ 
						{ '\'', "\'\'" },
						{ '\v', "" }, 		// vertical tab
						{ '\b', "" }, 		// backspace
						{ '\f', "" }, 		// form feed
						{ '\a', "" }, 		// alert (bell)
						{ '\e', "" }, 		// escape
					},
		escCharsMySql[] = 
					{
						{ '\'', "\\'" },
						{ '"' , "\\\"" },
						{ '\\', "\\\\" },
						{ '\n', "\\n" }, 	// new line feed
						{ '\r', "\\r" }, 	// cariage return
						{ '\t', "\\t" }, 	// tab
						{ '\v', "\\v" }, 	// vertical tab
						{ '\b', "\\b" }, 	// backspace
						{ '\f', "\\f" }, 	// form feed
						{ '\a', "\\a" }, 	// alert (bell)
						{ '\e', "" }, 		// escape
					},
		*escChars;
		int countEscChars;
		if(isTypeDb("mssql")) {
			escChars = escCharsMsSql;
			countEscChars = sizeof(escCharsMsSql)/sizeof(escCharsMsSql[0]);
		} else {
			escChars = escCharsMySql;
			countEscChars = sizeof(escCharsMySql)/sizeof(escCharsMySql[0]);
		}
		int lengthStr = strlen(inputStr);
		for(int posInputStr = 0; posInputStr<lengthStr; posInputStr++) {
			bool isEscChar = false;
			for(int i = 0; i<countEscChars; i++) {
				if(escChars[i].ch == inputStr[posInputStr]) {
					rsltString += escChars[i].escStr;
					isEscChar = true;
					break;
				}
			}
			if(!isEscChar) {
				rsltString += inputStr[posInputStr];
			}
		}
	}
	if(borderChar) {
		rsltString = borderChar + rsltString + borderChar;
	}
	return rsltString;
}

bool cmpStringIgnoreCase(const char* str1, const char* str2) {
	if(str1 == str2) {
		return true;
	}
	if(((str1 || str2) && !(str1 && str2)) ||
	   ((*str1 || *str2) && !(*str1 && *str2)) ||
	   strlen(str1) != strlen(str2)) {
		return false;
	}
	int length = strlen(str1);
	for(int i=0; i<length; i++) {
		if(tolower(str1[i]) != tolower(str2[i])) {
			return false;
		}
	}
	return true;
}

string reverseString(const char *str) {
	string rslt;
	if(str) {
		int length = strlen(str);
		for(int i=length-1; i>=0; i--) {
			rslt += str[i];
		}
	}
	return rslt;
}

bool isSqlDriver(const char *sqlDriver) {
	return 	cmpStringIgnoreCase(sql_driver, sqlDriver);
}

bool isTypeDb(const char *typeDb) {
	return 	cmpStringIgnoreCase(sql_driver, typeDb) ||
		(cmpStringIgnoreCase(sql_driver, "odbc") && cmpStringIgnoreCase(odbc_driver, typeDb));
}
