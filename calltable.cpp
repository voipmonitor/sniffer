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

#include "calltable.h"
#include "format_wav.h"
#include "codecs.h"
#include "codec_alaw.h"
#include "codec_ulaw.h"

#define MIN(x,y) ((x) < (y) ? (x) : (y))

using namespace std;

extern int verbosity;
extern int opt_saveRAW;                // save RTP payload RAW data?
extern int opt_saveWAV;                // save RTP payload RAW data?
extern int opt_saveGRAPH;	// save GRAPH data to graph file? 
extern int opt_gzipGRAPH;	// compress GRAPH data to graph file? 
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
}

/* destructor */
Call::~Call(){
	int i;
	Calltable *ct = (Calltable *)calltable;

	for(i = 0; i < ipport_n; i++) {
		ct->hashRemove(this->addr[i], this->port[i]);
	}

	/* close RAW files */
	for(i = 0; i <= ssrc_n; i++) {
		if(rtp[i].gfileRAW) {
			fclose(rtp[i].gfileRAW);
			rtp[i].gfileRAW = NULL;
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
	this->addr[ipport_n] = addr;
	this->port[ipport_n] = port;
	memcpy(this->rtpmap[ipport_n], rtpmap, MAX_RTPMAP * sizeof(int));
	this->iscaller[ipport_n] = iscaller;
	if(ua) {
		memcpy(this->ua[ipport_n], ua, ua_len);
		this->ua[ipport_n][ua_len] = '\0';
	} else {
		this->ua[ipport_n][0] = '\0';
	}
	ipport_n++;
	return 0;
}

/* Return reference to Call if IP:port was found, otherwise return NULL */
Call*
Call::find_by_ip_port(in_addr_t addr, unsigned short port){
	for(int i = 0; i < ipport_n; i++) {
		if(this->addr[i] == addr && this->port[i] == port){
			// we have found it
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
Call::read_rtp(unsigned char* data, unsigned long datalen, struct pcap_pkthdr *header, u_int32_t saddr, unsigned short port) {

	if(first_rtp_time == 0) {
		first_rtp_time = header->ts.tv_sec;
	}
	
	//RTP tmprtp; moved to Call structure to avoid creating and destroying class which is not neccessary
	tmprtp.fill(data, datalen, header, saddr);
	for(int i = 0; i < ssrc_n; i++) {
		if(rtp[i].ssrc == tmprtp.getSSRC()) {
			// found 
			rtp[i].read(data, datalen, header, saddr, seeninviteok);
			return;
		}
	}
	// adding new RTP source
	if(ssrc_n < MAX_SSRC_PER_CALL) {
		sprintf(rtp[ssrc_n].gfilename, "%s/%s.%d.graph%s", dirname(), fbasename, ssrc_n, opt_gzipGRAPH ? ".gz" : "");
		if(opt_saveGRAPH) {
			if(opt_gzipGRAPH) {
				rtp[ssrc_n].gfileGZ.open(rtp[ssrc_n].gfilename);
			} else {
				rtp[ssrc_n].gfile.open(rtp[ssrc_n].gfilename);
			}
		}
		if(opt_saveRAW || opt_saveWAV) {
			char tmp[1024];
			sprintf(tmp, "%s/%s.%d.raw", dirname(), fbasename, ssrc_n);
			//rtp[ssrc_n].gfileRAW.open(tmp, ios::binary);
			rtp[ssrc_n].gfileRAW = fopen(tmp, "w");
		} else {
			rtp[ssrc_n].gfileRAW = NULL;
		}
		int i = get_index_by_ip_port(saddr, port);
		memcpy(this->rtp[ssrc_n].rtpmap, rtpmap[i], MAX_RTPMAP * sizeof(int));

		rtp[ssrc_n].read(data, datalen, header, saddr, seeninviteok);
		this->rtp[ssrc_n].ssrc = tmprtp.getSSRC();
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

 int convertALAW2WAV(char *fname1, char *fname2, char *fname3) {
        unsigned char *bitstream_buf1;
        unsigned char *bitstream_buf2;
        int16_t buf_out1;
        int16_t buf_out2;
        unsigned char *p1;
        unsigned char *f1;
        unsigned char *p2;
        unsigned char *f2;
        long file_size1;
        long file_size2;

        //TODO: move it to main program to not init it overtimes or make alaw_init not reinitialize
        alaw_init();
 
        int inFrameSize = 1;
        int outFrameSize = 2;
 
        FILE *f_in1 = fopen(fname1, "r");
        FILE *f_in2 = fopen(fname2, "r");
        FILE *f_out = fopen(fname3, "w");
        if(!f_in1 || !f_in2 || !f_out) {
                syslog(LOG_ERR,"One of files [%s,%s,%s] cannot be opened. Failed converting raw to wav\n", fname1, fname2, fname3);
                return -1;
        }
 
        wav_write_header(f_out);
 
        fseek(f_in1, 0, SEEK_END);
        file_size1 = ftell(f_in1);
        fseek(f_in1, 0, SEEK_SET);
 
        fseek(f_in2, 0, SEEK_END);
        file_size2 = ftell(f_in2);
        fseek(f_in2, 0, SEEK_SET);
 
        bitstream_buf1 = (unsigned char *)malloc(file_size1);
        bitstream_buf2 = (unsigned char *)malloc(file_size2);
        fread(bitstream_buf1, file_size1, 1, f_in1);
        fread(bitstream_buf2, file_size2, 1, f_in2);
        p1 = bitstream_buf1;
        f1 = bitstream_buf1 + file_size1;
        p2 = bitstream_buf2;
        f2 = bitstream_buf2 + file_size2;
        while(p1 < f1 || p2 < f2 ) {
                if(p1 < f1 && p2 < f2) {
                        buf_out1 = ALAW(*p1);
                        buf_out2 = ALAW(*p2);
                        slinear_saturated_add(&buf_out1, &buf_out2);
                        p1 += inFrameSize;
                        p2 += inFrameSize;
                        fwrite(&buf_out1, sizeof(buf_out1), 1, f_out);
                } else if ( p1 < f1 ) {
                        buf_out1 = ALAW(*p1);
                        p1 += inFrameSize;
                        fwrite(&buf_out1, outFrameSize, 1, f_out);
                } else {
                        buf_out1 = ALAW(*p2);
                        p2 += inFrameSize;
                        fwrite(&buf_out2, outFrameSize, 1, f_out);
                }
        }
 
        wav_update_header(f_out);
 
        if(bitstream_buf1)
                free(bitstream_buf1);
        if(bitstream_buf2)
                free(bitstream_buf2);
 
        fclose(f_out);
        fclose(f_in1);
        fclose(f_in2);
 
        return 0;
 }
 
int convertULAW2WAV(char *fname1, char *fname2, char *fname3) {
	unsigned char *bitstream_buf1;
	unsigned char *bitstream_buf2;
	int16_t buf_out1;
	int16_t buf_out2;
	unsigned char *p1;
	unsigned char *f1;
	unsigned char *p2;
	unsigned char *f2;
	long file_size1;
	long file_size2;
 
	//TODO: move it to main program to not init it overtimes or make ulaw_init not reinitialize
	ulaw_init();
 
	int inFrameSize = 1;
	int outFrameSize = 2;
 
	FILE *f_in1 = fopen(fname1, "r");
	FILE *f_in2 = fopen(fname2, "r");
	FILE *f_out = fopen(fname3, "w");
	if(!f_in1 || !f_in2 || !f_out) {
		syslog(LOG_ERR,"One of files [%s,%s,%s] cannot be opened. Failed converting raw to wav\n", fname1, fname2, fname3);
		return -1;
	}
 
	wav_write_header(f_out);
 
	fseek(f_in1, 0, SEEK_END);
	file_size1 = ftell(f_in1);
	fseek(f_in1, 0, SEEK_SET);
 
	fseek(f_in2, 0, SEEK_END);
	file_size2 = ftell(f_in2);
	fseek(f_in2, 0, SEEK_SET);
 
	bitstream_buf1 = (unsigned char *)malloc(file_size1);
	bitstream_buf2 = (unsigned char *)malloc(file_size2);
	fread(bitstream_buf1, file_size1, 1, f_in1);
	fread(bitstream_buf2, file_size2, 1, f_in2);
	p1 = bitstream_buf1;
	f1 = bitstream_buf1 + file_size1;
	p2 = bitstream_buf2;
	f2 = bitstream_buf2 + file_size2;
 
	while(p1 < f1 || p2 < f2 ) {
		if(p1 < f1 && p2 < f2) {
			buf_out1 = ULAW(*p1);
			buf_out2 = ULAW(*p2);
			slinear_saturated_add(&buf_out1, &buf_out2);
			p1 += inFrameSize;
			p2 += inFrameSize;
			fwrite(&buf_out1, sizeof(buf_out1), 1, f_out);
		} else if ( p1 < f1 ) {
			buf_out1 = ULAW(*p1);
			p1 += inFrameSize;
			fwrite(&buf_out1, outFrameSize, 1, f_out);
		} else {
			buf_out1 = ULAW(*p2);
			p2 += inFrameSize;
			fwrite(&buf_out2, outFrameSize, 1, f_out);
		}
	}
 
	wav_update_header(f_out);
 
	if(bitstream_buf1)
		free(bitstream_buf1);
	if(bitstream_buf2)
		free(bitstream_buf2);
 
	fclose(f_out);
	fclose(f_in1);
	fclose(f_in2);
 
	return 0;
}

int
Call::convertRawToWav() {
 
	char fname1[1024];
	char fname2[1024];
	char fname3[1024];
	int payloadtype = 0;
 
	/* sort all RTP streams by received packets + loss packets descend and save only those two with the biggest received packets. */
	int indexes[MAX_SSRC_PER_CALL];
	// init indexex
	for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
		indexes[i] = i;
	}
	// bubble sort
	for(int k = 0; k < ssrc_n; k++) {
		for(int j = 0; j < ssrc_n; j++) {
			if((rtp[indexes[k]].stats.received + rtp[indexes[k]].stats.lost) > ( rtp[indexes[j]].stats.received + rtp[indexes[j]].stats.lost)) {
				int kTmp = indexes[k];
				indexes[k] = indexes[j];
				indexes[j] = kTmp;
			}
		}
	}
 
	sprintf(fname1, "%s/%s.%d.raw", dirname(), fbasename, indexes[0]);
	sprintf(fname2, "%s/%s.%d.raw", dirname(), fbasename, indexes[1]);
	sprintf(fname3, "%s/%s.wav", dirname(), fbasename);
 
	//printf("r1: %d, r2: %d, r3: %d \n\n", rtp[indexes[0]][0].rtpmap, rtpmap[indexes[1]][0], rtpmap[indexes[2]][0]);
 
	for(int i = 0; i < MAX_RTPMAP && rtp[indexes[0]].rtpmap[i] != 0; i++) {
		if((rtp[indexes[0]].payload == (rtp[indexes[0]].rtpmap[i] / 1000)) && (rtp[indexes[1]].payload == (rtp[indexes[0]].rtpmap[i]) / 1000)) {
			// need to extract 97 from 98097
			payloadtype = rtp[indexes[0]].rtpmap[i] - rtp[indexes[0]].payload * 1000;
		}
	}
 
	char cmd[4092];
 
	switch(payloadtype) {
	case PAYLOAD_PCMA:
		if(verbosity > 1) syslog(LOG_ERR, "Converting PCMA to WAV.\n");
		convertALAW2WAV(fname1, fname2, fname3);
		break;
	case PAYLOAD_PCMU:
		if(verbosity > 1) syslog(LOG_ERR, "Converting PCMA to WAV.\n");
		convertULAW2WAV(fname1, fname2, fname3);
		break;
/* following decoders are not included in free version. Please contact support@voipmonitor.org */
	case PAYLOAD_GSM:
		snprintf(cmd, 4092, "voipmonitor-gsm \"%s\" \"%s\" \"%s\"", fname1, fname2, fname3);
		if(verbosity > 1) syslog(LOG_ERR, "Converting GSM to WAV.\n");
		system(cmd);
		break;
	case PAYLOAD_G729:
		snprintf(cmd, 4092, "g7292wav \"%s\" \"%s\" \"%s\"", fname1, fname2, fname3);
		if(verbosity > 1) syslog(LOG_ERR, "Converting G.729 to WAV.\n");
		system(cmd);
		break;
	case PAYLOAD_G723:
		snprintf(cmd, 4092, "g7232wav \"%s\" \"%s\" \"%s\"", fname1, fname2, fname3);
		if(verbosity > 1) syslog(LOG_ERR, "Converting G.723 to WAV.\n");
		system(cmd);
		break;
	case PAYLOAD_ILBC:
		snprintf(cmd, 4092, "voipmonitor-ilbc \"%s\" \"%s\" \"%s\"", fname1, fname2, fname3);
		if(verbosity > 1) syslog(LOG_ERR, "Converting iLBC to WAV.\n");
		system(cmd);
		break;
	case PAYLOAD_SPEEX:
		snprintf(cmd, 4092, "voipmonitor-speex \"%s\" \"%s\" \"%s\"", fname1, fname2, fname3);
		if(verbosity > 1) syslog(LOG_ERR, "Converting speex to WAV.\n");
		system(cmd);
		break;
	default:
		syslog(LOG_ERR, "Call cannot be converted to WAV, unknown payloadtype [%d]\n", payloadtype);
	}
 
	if(!opt_saveRAW) {
		unlink(fname1);
		unlink(fname2);
	}
 
	return 0;
}

/* TODO: implement failover -> write INSERT into file */
int
Call::saveToMysql() {
	using namespace mysqlpp;

	extern char mysql_host[256];
	extern char mysql_database[256];
	extern char mysql_table[256];
	extern char mysql_user[256];
	extern char mysql_password[256];

	double burstr, lossr;

	/* we are not interested in calls which do not have RTP */
	if(rtp[0].saddr == 0 && rtp[1].saddr == 0) {
		if(verbosity > 1)
			syslog(LOG_ERR,"This call does not have RTP. SKipping SQL.\n");

		return 0;
	}
	
	//mysqlpp::Connection con(false);
	if(!con.connected()) {
		con.connect(mysql_database, mysql_host, mysql_user, mysql_password);
		if(!con) {
			syslog(LOG_ERR,"DB connection failed: %s", con.error());
			return 1;
		}
	} 
	mysqlpp::Query query = con.query();
	/* walk two first RTP and store it to MySQL. */

	/* bye 
	 * 	3 - call was answered and properly terminated
	 * 	2 - call was answered but one of leg didnt confirm bye
	 * 	1 - call was answered but there was no bye 
	 * 	0 - call was not answered 
	 */
	query << "INSERT INTO `" << mysql_table << "` SET caller = " << quote << caller << ",  callername = " << quote << callername << 
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
		", bye = " << quote << ( seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0);
	char c;
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
				if((rtp[indexes[k]].stats.received + rtp[indexes[k]].stats.lost) > ( rtp[indexes[j]].stats.received + rtp[indexes[j]].stats.lost)) {
					int kTmp = indexes[k];
					indexes[k] = indexes[j];
					indexes[j] = kTmp;
				}
			}
		}

		// a_ is always caller, so check if we need to swap indexes
		if (!iscaller[indexes[0]]) {
			int tmp;
			tmp = indexes[1];
			indexes[1] = indexes[0];
			indexes[0] = tmp;
		}

		// save only two streams with the biggest received packets
		for(int i = 0; i < 2; i++) {
			c = i == 0 ? 'a' : 'b';

			query << " , " << c << "_index = " << quote << indexes[i];
			query << " , " << c << "_ua = " << quote << ua[indexes[i]];
			query << " , " << c << "_received = " << rtp[indexes[i]].stats.received;
			query << " , " << c << "_lost = " << rtp[indexes[i]].stats.lost;
			query << " , " << c << "_avgjitter = " << quote << int(ceil(rtp[indexes[i]].stats.avgjitter));
			query << " , " << c << "_maxjitter = " << quote << int(ceil(rtp[indexes[i]].stats.maxjitter)); 
			query << " , " << c << "_payload = " << quote << rtp[indexes[i]].payload; 

			/* build a_sl1 - b_sl10 fields */
			for(int j = 1; j < 11; j++) {
				query << " , " << c << "_sl" << j << " = " << rtp[indexes[i]].stats.slost[j];
			}
			/* build a_d50 - b_d300 fileds */
			query << " , " << c << "_d50 = " << rtp[indexes[i]].stats.d50;
			query << " , " << c << "_d70 = " << rtp[indexes[i]].stats.d70;
			query << " , " << c << "_d90 = " << rtp[indexes[i]].stats.d90;
			query << " , " << c << "_d120 = " << rtp[indexes[i]].stats.d120;
			query << " , " << c << "_d150 = " << rtp[indexes[i]].stats.d150;
			query << " , " << c << "_d200 = " << rtp[indexes[i]].stats.d200;
			query << " , " << c << "_d300 = " << rtp[indexes[i]].stats.d300;
			
			/* store source addr */
			query << " , " << c << "_saddr = " << htonl(rtp[indexes[i]].saddr);

			/* calculate lossrate and burst rate */
			burstr_calculate(rtp[indexes[i]].channel_fix1, rtp[indexes[i]].stats.received, &burstr, &lossr);
			query << " , " << c << "_lossr_f1 = " << lossr;
			query << " , " << c << "_burstr_f1 = " << burstr;
			query << " , " << c << "_mos_f1 = " << quote << calculate_mos(lossr, burstr, 1);

			/* Jitterbuffer MOS statistics */
			burstr_calculate(rtp[indexes[i]].channel_fix2, rtp[indexes[i]].stats.received, &burstr, &lossr);
			query << " , " << c << "_lossr_f2 = " << lossr;
			query << " , " << c << "_burstr_f2 = " << burstr;
			query << " , " << c << "_mos_f2 = " << quote << calculate_mos(lossr, burstr, 1);

			burstr_calculate(rtp[indexes[i]].channel_adapt, rtp[indexes[i]].stats.received, &burstr, &lossr);
			query << " , " << c << "_lossr_adapt = " << lossr;
			query << " , " << c << "_burstr_adapt = " << burstr;
			query << " , " << c << "_mos_adapt = " << quote << calculate_mos(lossr, burstr, 1);
		}
	}

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
			rtp[i].dump();
		}
	}
	printf("-end call dump  %p----------------------------\n", this);
}

/* constructor */
Calltable::Calltable() {
	pthread_mutex_init(&qlock, NULL);
	memset(calls_hash, 0x0, sizeof(calls_hash));
};


/* add node to hash. collisions are linked list of nodes*/
void
Calltable::hashAdd(in_addr_t addr, unsigned short port, Call* call) {
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
Calltable::hashfind_by_ip_port(in_addr_t addr, unsigned short port) {
	hash_node *node = NULL;
	u_int32_t h;

	h = tuplehash(addr, port);
	for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
		if ((node->addr == addr) && (node->port == port)) {
			return node->call;
		}
	}
	return NULL;
}

Call*
Calltable::add(char *call_id, unsigned long call_id_len, time_t time) {
	Call *newcall = new Call(call_id, call_id_len, time, this);
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
Calltable::find_by_ip_port(in_addr_t addr, unsigned short port) {
	// Calls iterator (whole table) 
	for (call = calls_list.begin(); call != calls_list.end(); ++call) {
		if((*call)->find_by_ip_port(addr, port))
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
			/* move call to queue for mysql processing */
			calls_queue.push((*call));
			calls_list.erase(call++);
		} else {
			++call;
		}
	}
	return 0;
}

