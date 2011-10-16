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
#include <vector>

#include <mysql++.h>

#include "voipmonitor.h"
#include "calltable.h"
#include "format_wav.h"
#include "format_ogg.h"
#include "codecs.h"
#include "codec_alaw.h"
#include "codec_ulaw.h"
#include "jitterbuffer/asterisk/time.h"

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
extern char mysql_host[256];
extern char mysql_database[256];
extern char mysql_table[256];
extern char mysql_user[256];
extern char mysql_password[256];
int calls = 0;

static mysqlpp::Connection con(false);

/* constructor */
Call::Call(char *call_id, unsigned long call_id_len, time_t time, void *ct) {
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
	callername[0] = '\0';
	called[0] = '\0';
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
}

/* destructor */
Call::~Call(){
	int i;
	Calltable *ct = (Calltable *)calltable;

	for(i = 0; i < ipport_n; i++) {
		ct->hashRemove(this->addr[i], this->port[i]);
		if(opt_rtcp) {
			ct->hashRemove(this->addr[i], this->port[i] + 1);
		}

	}

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
	}
}

void
Call::closeRawFiles() {
	for(int i = 0; i < ssrc_n; i++) {
		if(rtp[i]->gfileRAW) {
			FILE *tmp;
			rtp[i]->jitterbuffer_fixed_flush(rtp[i]->channel_record);
			/* preventing race condition as gfileRAW is checking for NULL pointer in rtp classes */ 
			tmp = rtp[i]->gfileRAW;
			rtp[i]->gfileRAW = NULL;
			fclose(tmp);
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
		printf("call:[%p] ip:[%s] port:[%d]\n", this, inet_ntoa(in), port);
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
		char *tmp = iscaller ? this->a_ua : this->b_ua;
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
		rtp[ssrc_n] = new RTP;
		rtp[ssrc_n]->call_owner = this;
		rtp[ssrc_n]->ssrc_index = ssrc_n; 
		rtp[ssrc_n]->iscaller = iscaller; 
		if(rtp_cur[iscaller]) {
			rtp_prev[iscaller] = rtp_cur[iscaller];
		}
		rtp_cur[iscaller] = rtp[ssrc_n]; 
		sprintf(rtp[ssrc_n]->gfilename, "%s/%s.%d.graph%s", dirname(), fbasename, ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		if(flags & FLAG_SAVEGRAPH) {
			if(opt_gzipGRAPH) {
				rtp[ssrc_n]->gfileGZ.open(rtp[ssrc_n]->gfilename);
			} else {
				rtp[ssrc_n]->gfile.open(rtp[ssrc_n]->gfilename);
			}
		}
		rtp[ssrc_n]->gfileRAW = NULL;
		sprintf(rtp[ssrc_n]->basefilename, "%s/%s.i%d", dirname(), fbasename, iscaller);
		int i = get_index_by_ip_port(saddr, port);
		memcpy(this->rtp[ssrc_n]->rtpmap, rtpmap[i], MAX_RTPMAP * sizeof(int));

		rtp[ssrc_n]->read(data, datalen, header, saddr, seeninviteok);
		this->rtp[ssrc_n]->ssrc = tmprtp.getSSRC();
		ssrc_n++;
	}
}

double calculate_mos(double ppl, double burstr, int version) {
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

	sprintf(wav0, "%s/%s.i0.wav", dirname(), fbasename);
	sprintf(wav1, "%s/%s.i1.wav", dirname(), fbasename);
	switch(opt_audio_format) {
	case FORMAT_WAV:
		sprintf(out, "%s/%s.wav", dirname(), fbasename);
		break;
	case FORMAT_OGG:
		sprintf(out, "%s/%s.ogg", dirname(), fbasename);
		break;
	}

	/* do synchronisation - calculate difference between start of both RTP direction and put silence to achieve proper synchronisation */
	/* first direction */
	sprintf(rawInfo, "%s/%s.i%d.rawInfo", dirname(), fbasename, 0);
	pl = fopen(rawInfo, "r");
	if(!pl) {
		syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
		return 1;
	}
	fgets(line, 1024, pl);
	fclose(pl);
	sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
	/* second direction */
	sprintf(rawInfo, "%s/%s.i%d.rawInfo", dirname(), fbasename, 1);
	pl = fopen(rawInfo, "r");
	if(!pl) {
		syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
		return 1;
	}
	fgets(line, 1024, pl);
	fclose(pl);
	sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv1.tv_sec, &tv1.tv_usec);
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

	/* process all files in playlist for each direction */
	for(int i = 0; i <= 1; i++) {
		char *wav = i ? wav1 : wav0;

		/* open playlist */
		sprintf(rawInfo, "%s/%s.i%d.rawInfo", dirname(), fbasename, i);
		pl = fopen(rawInfo, "r");
		if(!pl) {
			syslog(LOG_ERR, "Cannot open %s\n", rawInfo);
			return 1;
		}
		while(fgets(line, 256, pl)) {
			char raw[1024];
			line[strlen(line)] = '\0'; // remove '\n' which is last character
			sscanf(line, "%d:%lu:%d:%ld:%ld", &ssrc_index, &rawiterator, &codec, &tv0.tv_sec, &tv0.tv_usec);
			sprintf(raw, "%s/%s.i%d.%d.%lu.%d.%ld.%ld.raw", dirname(), fbasename, i, ssrc_index, rawiterator, codec, tv0.tv_sec, tv0.tv_usec);

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
 
	return 0;
}

int
Call::buildQuery(mysqlpp::Query *query) {
	using namespace mysqlpp;
	/* walk two first RTP and store it to MySQL. */

	/* bye 
	 * 	3 - call was answered and properly terminated
	 * 	2 - call was answered but one of leg didnt confirm bye
	 * 	1 - call was answered but there was no bye 
	 * 	0 - call was not answered 
	 */
	char c;
	double burstr, lossr;
	*query << "INSERT INTO `" << mysql_table << "` SET caller = " << quote << caller << ",  callername = " << quote << callername << 
		", sipcallerip = " << quote << htonl(sipcallerip) <<
		", sipcalledip = " << quote << htonl(sipcalledip) <<
		", called = " << quote << called <<
		", duration = " << duration() << 
		", progress_time = " << (progress_time ? progress_time - first_packet_time : -1) << 
		", first_rtp_time = " << (first_rtp_time  - first_packet_time) << 
		", connect_duration = " << (connect_time ? (duration() - (connect_time - first_packet_time)) : -1) << 
		", calldate = FROM_UNIXTIME(" << calltime() << ")" <<
		", fbasename = " << quote << fbasename << 
		", sighup = " << quote << (sighup ? 1 : 0) << 
		", lastSIPresponse = " << quote << lastSIPresponse << 
		", lastSIPresponseNum = " << quote << lastSIPresponseNum << 
		", bye = " << quote << ( seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0);

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
		*query << " , " << "a_ua = " << quote << a_ua;
		*query << " , " << "b_ua = " << quote << b_ua;

		// save only two streams with the biggest received packets
		for(int i = 0; i < 2; i++) {
			if(!rtp[indexes[i]]) continue;
			
			c = i == 0 ? 'a' : 'b';

			*query << " , " << c << "_index = " << quote << indexes[i];
			*query << " , " << c << "_received = " << (rtp[indexes[i]]->stats.received + 2); // received is always 2 packet less compared to wireshark (add it here)
			*query << " , " << c << "_lost = " << rtp[indexes[i]]->stats.lost;
			*query << " , " << c << "_avgjitter = " << quote << int(ceil(rtp[indexes[i]]->stats.avgjitter));
			*query << " , " << c << "_maxjitter = " << quote << int(ceil(rtp[indexes[i]]->stats.maxjitter)); 
			*query << " , " << c << "_payload = " << quote << rtp[indexes[i]]->payload; 

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
			burstr_calculate(rtp[indexes[i]]->channel_fix1, rtp[indexes[i]]->stats.received, &burstr, &lossr);
			*query << " , " << c << "_lossr_f1 = " << lossr;
			*query << " , " << c << "_burstr_f1 = " << burstr;
			*query << " , " << c << "_mos_f1 = " << quote << calculate_mos(lossr, burstr, 1);

			/* Jitterbuffer MOS statistics */
			burstr_calculate(rtp[indexes[i]]->channel_fix2, rtp[indexes[i]]->stats.received, &burstr, &lossr);
			*query << " , " << c << "_lossr_f2 = " << lossr;
			*query << " , " << c << "_burstr_f2 = " << burstr;
			*query << " , " << c << "_mos_f2 = " << quote << calculate_mos(lossr, burstr, 1);

			burstr_calculate(rtp[indexes[i]]->channel_adapt, rtp[indexes[i]]->stats.received, &burstr, &lossr);
			*query << " , " << c << "_lossr_adapt = " << lossr;
			*query << " , " << c << "_burstr_adapt = " << burstr;
			*query << " , " << c << "_mos_adapt = " << quote << calculate_mos(lossr, burstr, 1);
		}
	}
	return 0;
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveToMysql() {
	using namespace mysqlpp;


	/* we are not interested in calls which do not have RTP */
/*
	if(rtp[0].saddr == 0 && rtp[1].saddr == 0) {
		if(verbosity > 1)
			syslog(LOG_ERR,"This call does not have RTP. SKipping SQL.\n");

		//return 0;
	}
*/
	
	//mysqlpp::Connection con(false);
	if(!con.connected()) {
		con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
		if(!con) {
			syslog(LOG_ERR,"DB connection failed: %s", con.error());
			return 1;
		}
	} 

	mysqlpp::Query query = con.query();
	buildQuery(&query);

	if(verbosity > 0) cout << query << "\n";
	query.store();
	if(con.errnum()) {
		syslog(LOG_ERR,"Error in query errnum:'%d' error:'%s'", con.errnum(), con.error());
		if(con.errnum() == 2006) {
			//error:'MySQL server has gone away'
			syslog(LOG_ERR,"Reconnecting to database");
			con.disconnect();
			con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
			if(!con) {
				syslog(LOG_ERR,"DB connection failed: %s", con.error());
				return 1;
			}
			// try to store cdr again
			mysqlpp::Query query = con.query();
			buildQuery(&query);
			query.store();
			if(con.errnum()) {
				syslog(LOG_ERR,"Error in query errnum:'%d' error:'%s'", con.errnum(), con.error());
				return 0;
			}

		}
	}

	return 0;
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveRegisterToMysql() {
	using namespace mysqlpp;

	extern char mysql_host[256];
	extern char mysql_database[256];
	char *mysql_table = "register";
	extern char mysql_user[256];
	extern char mysql_password[256];

	if(!con.connected()) {
		con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
		if(!con) {
			syslog(LOG_ERR,"DB connection failed: %s", con.error());
			return 1;
		}
	} 
	mysqlpp::Query query = con.query();
	/* walk two first RTP and store it to MySQL. */

	query << "INSERT INTO `" << mysql_table << "` SET " <<
		"  sipcallerip = " << quote << htonl(sipcallerip) <<
		", sipcalledip = " << quote << htonl(sipcalledip) <<
		", calldate = FROM_UNIXTIME(" << calltime() << ")" <<
		", fbasename = " << quote << fbasename << 
		", sighup = " << quote << (sighup ? 1 : 0);

	if(verbosity > 2) cout << query << "\n";
	query.store();
	if(con.errnum()) {
		if(con.errnum() == 2006) {
			//error:'MySQL server has gone away'
			syslog(LOG_ERR,"Reconnecting to database");
			con.disconnect();
			con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
			if(!con) {
				syslog(LOG_ERR,"DB connection failed: %s", con.error());
				return 1;
			}
			// try to store cdr again
			query.store();
			if(con.errnum()) {
				syslog(LOG_ERR,"Error in query errnum:'%d' error:'%s'", con.errnum(), con.error());
				return 0;
			}

		}
		syslog(LOG_ERR,"Error in query errnum:'%d' error:'%s'", con.errnum(), con.error());
	}

	return 0;
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
	memset(calls_hash, 0x0, sizeof(calls_hash));
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
			// there is already same call, overwrite it, but this should probably does not occur 
			node->call = call;
			return;
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

	calls_list.push_front(newcall);
	return newcall;
}

/* find Call by SIP call-id and  return reference to this Call */
Call*
Calltable::find_by_call_id(char *call_id, unsigned long call_id_len) {
	for (call = calls_list.begin(); call != calls_list.end(); ++call) {
		if((*call)->call_id_len == call_id_len &&
		  (memcmp((*call)->call_id, call_id, MIN(call_id_len, MAX_CALL_ID)) == 0)) {
			return *call;
		}
	}
	return NULL;
}

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

/* iterate all calls in table which are 5 minutes inactive and save them into SQL 
 * ic currtime = 0, save it immediatly
*/
int
Calltable::cleanup( time_t currtime ) {
	for (call = calls_list.begin(); call != calls_list.end();) {
		if(verbosity > 2) (*call)->dump();
		// RTPTIMEOUT seconds of inactivity will save this call and remove from call table
		if(currtime == 0 || (currtime - (*call)->get_last_packet_time() > RTPTIMEOUT)) {
			if ((*call)->get_f_pcap() != NULL){
				pcap_dump_flush((*call)->get_f_pcap());
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

