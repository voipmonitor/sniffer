/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/*
This unit reads and parse packets from network interface or file 
and insert them into Call class. 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <semaphore.h>

#include <pcap.h>

#include "flags.h"
#include "codecs.h"
#include "calltable.h"
#include "sniff.h"
#include "voipmonitor.h"
#include "filter_mysql.h"
#include "hash.h"
#include "rtp.h"
#include "rtcp.h"
#include "md5.h"
#include "tools.h"
#include "mirrorip.h"

extern "C" {
#include "liblfds.6/inc/liblfds.h"
}

using namespace std;

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

extern int calls;
extern int opt_saveSIP;	  	// save SIP packets to pcap file?
extern int opt_saveRTP;	 	// save RTP packets to pcap file?
extern int opt_saveRTCP;	// save RTCP packets to pcap file?
extern int opt_saveRAW;	 	
extern int opt_saveWAV;	 	
extern int opt_packetbuffered;	  // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_rtcp;		  // Make .pcap files writing ‘‘packet-buffered’’
extern int verbosity;
extern int terminating;
extern int opt_rtp_firstleg;
extern int opt_sip_register;
extern int opt_norecord_header;
extern char *ipaccountmatrix;
extern pcap_t *handle;
extern read_thread *threads;
extern int opt_norecord_dtmf;
extern int opt_onlyRTPheader;
extern int opt_sipoverlap;
extern int readend;
extern int opt_dup_check;
extern char opt_match_header[128];
extern int opt_domainport;
extern int opt_mirrorip;
extern char opt_scanpcapdir[2048];

extern IPfilter *ipfilter;
extern IPfilter *ipfilter_reload;
extern int ipfilter_reload_do;

extern TELNUMfilter *telnumfilter;
extern TELNUMfilter *telnumfilter_reload;
extern int telnumfilter_reload_do;

extern int rtp_threaded;
extern int opt_pcap_threaded;

extern int opt_rtpnosip;
extern char opt_cachedir[1024];

extern int opt_savewav_force;
extern int opt_saveudptl;

extern nat_aliases_t nat_aliases;

extern pcap_packet *qring;
extern volatile unsigned int readit;
extern volatile unsigned int writeit;
extern unsigned int qringmax;

extern char *ipaccountportmatrix;
extern int opt_pcapdump;

typedef struct {
	unsigned int octects;
	unsigned int numpackets;
	unsigned int lasttimestamp;
} octects_t;

map<string, octects_t*> ipacc_protos;
map<string, octects_t*>::iterator ipacc_protosIT;

map<string, octects_t*> ipacc_ports;
map<string, octects_t*>::iterator ipacc_portsIT;

extern queue<string> mysqlquery;
extern pthread_mutex_t mysqlquery_lock;

unsigned int last_flush = 0;
unsigned int last_flush_ports = 0;

#define IPACC_INTERVAL 5 // seconds

void flush_octets_ip() {
	char *tmp;
	char keycb[64], *keyc;
	octects_t *proto;
	char buf[32];
	pthread_mutex_lock(&mysqlquery_lock);
	for (ipacc_protosIT = ipacc_protos.begin(); ipacc_protosIT != ipacc_protos.end(); ++ipacc_protosIT) {
		string query;
		proto = ipacc_protosIT->second;
		if(ipacc_protosIT->second->octects > 0) {
			strcpy(keycb, ipacc_protosIT->first.c_str());
			keyc = keycb;
//			keyc = (char *)keycpy.c_str();
			tmp = strchr(keyc, 'D');
			*tmp = '\0';
			query.append("INSERT INTO `ipacc_ipall` SET saddr = '");
			query.append(keyc);
			query.append("', `daddr` = '");
			keyc = tmp + 1;
			tmp = strchr(keyc, 'E');
			*tmp = '\0';
			query.append(keyc);
			query.append("', `proto` = '");
			keyc = tmp + 1;
			query.append(keyc);
			query.append("', `octects` = '");
			sprintf(buf, "%u", proto->octects);
			query.append(buf);
			query.append("', `interval` = '");
			sprintf(buf, "%u", proto->lasttimestamp);
			query.append(buf);
			query.append("', `numpackets` = '");
			sprintf(buf, "%u", proto->numpackets);
			query.append(buf);
			query.append("'");

			cout << query << "\n";


			//reset octects 
			ipacc_protosIT->second->octects = 0;
			ipacc_protosIT->second->numpackets = 0;

			mysqlquery.push(query);
		}
	}
	pthread_mutex_unlock(&mysqlquery_lock);

	//printf("flush\n");
}	

void flush_octets_ports() {
	char *tmp;
	char keycb[64], *keyc;
	octects_t *proto;
	char buf[64];
	pthread_mutex_lock(&mysqlquery_lock);
	for (ipacc_portsIT = ipacc_ports.begin(); ipacc_portsIT != ipacc_ports.end(); ++ipacc_portsIT) {
		string query;
		proto = ipacc_portsIT->second;
		if(ipacc_portsIT->second->octects > 0) {
			strcpy(keycb, ipacc_portsIT->first.c_str());
			keyc = keycb;
//			keyc = (char *)keycpy.c_str();
			tmp = strchr(keyc, 'D');
			*tmp = '\0';
			query.append("INSERT INTO `ipacc_ports` SET saddr = '");
			query.append(keyc);
			query.append("', `daddr` = '");

			keyc = tmp + 1;
			tmp = strchr(keyc, 'E');
			*tmp = '\0';
			query.append(keyc);
			query.append("', `sport` = '");

			keyc = tmp + 1;
			tmp = strchr(keyc, 'A');
			*tmp = '\0';
			query.append(keyc);
			query.append("', `dport` = '");

			keyc = tmp + 1;
			query.append(keyc);

			query.append("', `octects` = '");
			sprintf(buf, "%u", proto->octects);
			query.append(buf);
			query.append("', `interval` = '");
			sprintf(buf, "%u", proto->lasttimestamp);
			query.append(buf);
			query.append("', `numpackets` = '");
			sprintf(buf, "%u", proto->numpackets);
			query.append(buf);
			query.append("'");

			cout << query << "\n";

			//reset octects 
			ipacc_portsIT->second->octects = 0;
			ipacc_portsIT->second->numpackets = 0;

			mysqlquery.push(query);
		}
	}
	pthread_mutex_unlock(&mysqlquery_lock);

	//printf("flush\n");
	
}

void add_octects_ip(time_t timestamp, unsigned int saddr, unsigned int daddr, int proto, int packetlen) {
	string key;
	char buf[32];
	octects_t *protos;
	unsigned int cur_interval = timestamp / IPACC_INTERVAL;

	sprintf(buf, "%uD%uE%d", htonl(saddr), htonl(daddr), proto);
	key = buf;

	if(last_flush != cur_interval) {
		flush_octets_ip();
//		printf("%u | %u | %u | %u\n", timestamp, last_flush, cur_interval, timestamp / IPACC_INTERVAL);
		last_flush = cur_interval;
	}


	ipacc_protosIT = ipacc_protos.find(key);
	if(ipacc_protosIT == ipacc_protos.end()) {
		// not found;
		protos = (octects_t*)calloc(1, sizeof(octects_t));
		protos->octects += packetlen;
		protos->numpackets++;
		protos->lasttimestamp = timestamp / IPACC_INTERVAL;
		ipacc_protos[key] = protos;
//		printf("key: %s\n", buf);
	} else {
		//found
		octects_t *tmp = ipacc_protosIT->second;
		tmp->octects += packetlen;
		tmp->numpackets++;
		tmp->lasttimestamp = timestamp / IPACC_INTERVAL;
//		printf("key[%s] %u\n", key.c_str(), tmp->octects);
	}


}

void add_octects_ipport(time_t timestamp, unsigned int saddr, unsigned int daddr, int source, int dest, int proto, int packetlen) {
	string key;
	char buf[64];
	octects_t *ports;
	unsigned int cur_interval = timestamp / IPACC_INTERVAL;

	sprintf(buf, "%uD%uE%dA%d", htonl(saddr), htonl(daddr), source, dest);
	key = buf;

	if(last_flush_ports != cur_interval) {
		flush_octets_ports();
		printf("%u | %u | %u | %u\n", timestamp, last_flush, cur_interval, timestamp / IPACC_INTERVAL);
		last_flush_ports = cur_interval;
	}

	ipacc_portsIT = ipacc_ports.find(key);
	if(ipacc_portsIT == ipacc_ports.end()) {
		// not found;
		ports = (octects_t*)calloc(1, sizeof(octects_t));
		ports->octects += packetlen;
		ports->numpackets++;
		ports->lasttimestamp = timestamp / IPACC_INTERVAL;
		ipacc_ports[key] = ports;
//		printf("key: %s\n", buf);
	} else {
		//found
		octects_t *tmp = ipacc_portsIT->second;
		tmp->octects += packetlen;
		tmp->numpackets++;
		tmp->lasttimestamp = timestamp / IPACC_INTERVAL;
//		printf("key[%s] %u\n", key.c_str(), tmp->octects);
	}


}

void ipaccount(time_t timestamp, struct iphdr *header_ip, int packetlen){
	struct udphdr2 *header_udp;
	struct tcphdr *header_tcp;


	if (header_ip->protocol == IPPROTO_UDP) {
		// prepare packet pointers 
		header_udp = (struct udphdr2 *) ((char *) header_ip + sizeof(*header_ip));

		if(ipaccountportmatrix[htons(header_udp->source)] || ipaccountportmatrix[htons(header_udp->dest)]) {
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, htons(header_udp->source), htons(header_udp->dest), IPPROTO_TCP, packetlen);
		}
	} else if (header_ip->protocol == IPPROTO_TCP) {
		header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));

		if(ipaccountportmatrix[htons(header_tcp->source)] || ipaccountportmatrix[htons(header_tcp->dest)]) {
			add_octects_ipport(timestamp, header_ip->saddr, header_ip->daddr, htons(header_tcp->source), htons(header_tcp->dest), IPPROTO_TCP, packetlen);
		}
	} else {
	}

	add_octects_ip(timestamp, header_ip->saddr, header_ip->daddr, header_ip->protocol, packetlen);

//	printf("proto[%d]\n", header_ip->protocol);
}
