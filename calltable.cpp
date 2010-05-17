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

#define MIN(x,y) ((x) < (y) ? (x) : (y))

using namespace std;

extern int verbosity;
extern int opt_saveGRAPH;	// save GRAPH data to graph file? 
static mysqlpp::Connection con(false);

/* constructor */
Call::Call(char *call_id, unsigned long call_id_len, time_t time) {
	ipport_n = 0;
	ssrc_n = 0;
	first_packet_time = time;
	last_packet_time = time;
	memcpy(this->call_id, call_id, MIN(call_id_len, MAX_CALL_ID));
	this->call_id_len = call_id_len;
	f_pcap = NULL;
	seeninvite = false;
	seeninviteok = false;
	seenbye = false;
	seenbyeandok = false;
	caller[0] = '\0';
	called[0] = '\0';
	byecseq[0] = '\0';
	invitecseq[0] = '\0';
	sighup = false;
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
Call::add_ip_port(in_addr_t addr, unsigned short port, char *ua, unsigned long ua_len) {
	if(ipport_n > 0) {
		// check, if there is already IP:port
		for(int i = 0; i < ipport_n; i++) {
			if(this->addr[i] == addr && this->port[i] == port){
				return 1;
			}
		}
	}
	// add ip and port
	if(ipport_n >= MAX_IP_PER_CALL){
		syslog(LOG_ERR,"no more space for next media stream (IP:port), raise MAX_IP_PER_CALL");
		return -1;
	}
	this->addr[ipport_n] = addr;
	this->port[ipport_n] = port;
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

/* analyse rtp packet */
void
Call::read_rtp(unsigned char* data, unsigned long datalen, struct pcap_pkthdr *header, u_int32_t saddr) {
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
		sprintf(rtp[ssrc_n].gfilename, "%s/%s.%d.graph", dirname(), fbasename, ssrc_n);
		if(opt_saveGRAPH) {
			rtp[ssrc_n].gfile.open(rtp[ssrc_n].gfilename);
		}
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
	
	query << "INSERT INTO `" << mysql_table << "` SET caller = " << quote << caller << ", called = " << quote << called <<
		", duration = " << duration() << ", calldate = FROM_UNIXTIME(" << calltime() << ")" <<
		", fbasename = " << quote << fbasename << 
		", sighup = " << quote << (sighup ? 1 : 0) << 
		", bye = " << quote << ( seeninviteok ? (seenbye ? (seenbyeandok ? 3 : 2) : 1) : 0);
	char c;
	if(ssrc_n > 0) {
		/* sort all RTP streams by received packets descend and save only those two with the biggest received packets. */
		int indexes[MAX_SSRC_PER_CALL];
		// init indexex
		for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
			indexes[i] = i;
		}
		// bubble sort
		for(int k = 0; k < MAX_SSRC_PER_CALL; k++) {
			for(int j = 0; j < MAX_SSRC_PER_CALL; j++) {
				if(rtp[indexes[k]].stats.received > rtp[indexes[j]].stats.received) {
					int kTmp = indexes[k];
					indexes[k] = indexes[j];
					indexes[j] = kTmp;
				}
			}
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


Call*
Calltable::add(char *call_id, unsigned long call_id_len, time_t time) {
	Call *newcall = new Call(call_id, call_id_len, time);
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
		if(currtime == 0 || (currtime - (*call)->get_last_packet_time() > RTPTIMEOUT)){
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

