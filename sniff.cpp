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
#include <malloc.h>

#include <sstream>

#include <pcap.h>
//#include <pcap/sll.h>

#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)&x))
#define MAX_TCPSTREAMS 1024
#define RTP_FIXED_HEADERLEN 12

//#define HAS_NIDS 1
#ifdef HAS_NIDS
#include <nids.h>
#endif

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
#include "ipaccount.h"
#include "sql_db.h"

extern MirrorIP *mirrorip;

extern "C" {
#include "liblfds.6/inc/liblfds.h"
}

#define MAXLIVEFILTERS 10

using namespace std;

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

#ifdef	MUTEX_THREAD
queue<pcap_packet*> readpacket_thread_queue;
extern pthread_mutex_t readpacket_thread_queue_lock;
#endif

Calltable *calltable;
extern volatile int calls;
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
extern char *sipportmatrix;
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
extern int opt_mirrorall;
extern int opt_mirroronly;
extern char opt_scanpcapdir[2048];
extern int opt_ipaccount;
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
extern int opt_pcapdump;
extern int opt_id_sensor;
extern pthread_mutex_t mysqlquery_lock;
extern queue<string> mysqlquery;
extern SqlDb *sqlDb;
int pcap_dlink;
extern int opt_udpfrag;
extern int global_livesniffer;
extern int global_livesniffer_all;
extern int opt_pcap_split;
extern int opt_newdir;
extern int opt_callslimit;
extern int opt_skiprtpdata;

#ifdef QUEUE_MUTEX
extern sem_t readpacket_thread_semaphore;
#endif
unsigned int numpackets = 0;

typedef struct tcp_stream2_s {
	char *data;
	int datalen;
	pcap_pkthdr header;
	u_char *packet;
	u_int hash;
	time_t ts;
	u_int32_t seq;
	u_int32_t next_seq;
	u_int32_t ack_seq;
	tcp_stream2_s *next;
	char call_id[128];
	int lastpsh;
} tcp_stream2_t;

typedef struct ip_frag_s {
	char *data;
	int datalen;
	pcap_pkthdr header;
	u_char *packet;
	time_t ts;
	char *firstheader;
	u_int32_t firstheaderlen;
	u_int16_t id;
	u_int32_t offset;
	u_int32_t len;
	u_int32_t totallen;
	ip_frag_s *next;
	ip_frag_s *last;
	char has_last;
} ip_frag_t;

typedef struct pcap_hdr_s {
	u_int32_t magic_number;   /* magic number */
	u_int16_t version_major;  /* major version number */
	u_int16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	u_int32_t sigfigs;        /* accuracy of timestamps */
	u_int32_t snaplen;        /* max length of captured packets, in octets */
	u_int32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	u_int32_t ts_sec;         /* timestamp seconds */
	u_int32_t ts_usec;        /* timestamp microseconds */
	u_int32_t incl_len;       /* number of octets of packet saved in file */
	u_int32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

tcp_stream2_t *tcp_streams_hashed[MAX_TCPSTREAMS];
list<tcp_stream2_t*> tcp_streams_list;
typedef map<unsigned int, ip_frag_t*> ip_frag_queue_t;
typedef map<unsigned int, ip_frag_t*>::iterator ip_frag_queue_it_t;
//map<unsigned int, ip_frag_t*> ip_frag_stream;
map<unsigned int, map<unsigned int, ip_frag_queue_t*> > ip_frag_stream;
map<unsigned int, map<unsigned int, ip_frag_queue_t*> >::iterator ip_frag_streamIT;
map<unsigned int, ip_frag_queue_t*>::iterator ip_frag_streamITinner;

extern struct queue_state *qs_readpacket_thread_queue;

map<unsigned int, livesnifferfilter_t*> usersniffer;

// return IP from nat_aliases[ip] or 0 if not found
in_addr_t match_nat_aliases(in_addr_t ip) {
	nat_aliases_t::iterator iter;
        iter = nat_aliases.find(ip);
        if(iter == nat_aliases.end()) {
                // not found
                return 0;
        } else {
                return iter->second;
        }
	
}

inline void save_packet_sql(Call *call, struct pcap_pkthdr *header, const u_char *packet, unsigned int saddr, int source, unsigned int daddr, int dest, int istcp, char *data, int datalen, int uid) {
	//save packet
	stringstream query;

	// pcap file header
	pcap_hdr_t pcaphdr; // 24bytes
	pcaphdr.magic_number = 0xa1b2c3d4;
	pcaphdr.version_major = 2;
	pcaphdr.version_minor = 4;
	pcaphdr.thiszone = 0;
	pcaphdr.sigfigs = 0;
	pcaphdr.snaplen = 3200;
	pcaphdr.network = pcap_dlink;

	// packet header
	pcaprec_hdr_t pcaph;
	pcaph.ts_sec = header->ts.tv_sec;         /* timestamp seconds */
	pcaph.ts_usec = header->ts.tv_usec;        /* timestamp microseconds */
	pcaph.incl_len = header->caplen;       /* number of octets of packet saved in file */
	pcaph.orig_len = header->caplen;       /* actual length of packet */

	// copy data to mpacket buffer	
	char mpacket[10512];
	char *ptr = mpacket;
	memcpy(ptr, &pcaphdr, sizeof(pcaphdr));	// pcap header
	ptr += sizeof(pcaphdr);
	memcpy(ptr, &pcaph, sizeof(pcaph)); // packet header
	ptr += sizeof(pcaph);
	unsigned int len = MIN(10000, header->caplen);
	memcpy(ptr, packet, len);
	len += sizeof(pcaph) + sizeof(pcaphdr);

	//construct description
	char description[1024] = "";
	if(datalen) {
		void *memptr = memmem(data, datalen, "\r\n", 2);
		if(memptr) {
			memcpy(description, data, (char *)memptr - (char*)data);
			description[(char*)memptr - (char*)data] = '\0';
		} else {
			strcpy(description, "error in description\n");
		}
	}

	// construct query and push it to mysqlquery queue
	int id_sensor = opt_id_sensor > 0 ? opt_id_sensor : 0;
	query << "INSERT INTO livepacket_" << uid << " SET sipcallerip = '" << saddr << "', sipcalledip = '" << daddr << "', id_sensor = " << id_sensor << ", sport = " << source << ", dport = " << dest << ", istcp = " << istcp << ", created_at = " << sqlEscapeStringBorder(sqlDateTimeString(header->ts.tv_sec).c_str()) << ", microseconds = " << header->ts.tv_usec << ", callid = " << sqlEscapeStringBorder(call->call_id) << ", description = " << sqlEscapeStringBorder(description) << ", data = '#" << sqlDb->escape(mpacket, len) << "#'";
	pthread_mutex_lock(&mysqlquery_lock);
	mysqlquery.push(query.str());
	pthread_mutex_unlock(&mysqlquery_lock);
	return;
}


/* 
	stores SIP messags to sql.livepacket based on user filters
*/
inline void save_live_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, unsigned int saddr, int source, unsigned int daddr, int dest, int istcp, char *data, int datalen) {
	// check saddr and daddr filters
	daddr = htonl(daddr);
	saddr = htonl(saddr);

	if(global_livesniffer_all) {
		save_packet_sql(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, 0);
		return;
	}

	map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT;
	for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); usersnifferIT++) {
		livesnifferfilter_t *filter = usersnifferIT->second;
		if(filter->all) {
			 goto save;
		}
		for(int i = 0; i < MAXLIVEFILTERS; i++) {
			if(filter->lv_saddr[i] == saddr) goto save;
			if(filter->lv_daddr[i] == daddr) goto save;
			if(filter->lv_bothaddr[i] == daddr or filter->lv_bothaddr[i] == saddr) goto save;
			if(filter->lv_srcnum[i][0] != '\0' and memmem(call->caller, strlen(call->caller), filter->lv_srcnum[i], strlen(filter->lv_srcnum[i]))) goto save;
			if(filter->lv_dstnum[i][0] != '\0' and memmem(call->caller, strlen(call->caller), filter->lv_dstnum[i], strlen(filter->lv_dstnum[i]))) goto save;
			if(filter->lv_bothnum[i][0] != '\0' and (
				memmem(call->caller, strlen(call->caller), filter->lv_bothnum[i], strlen(filter->lv_bothnum[i])) or
				memmem(call->called, strlen(call->called), filter->lv_bothnum[i], strlen(filter->lv_bothnum[i])))
			)  goto save;
		}
		continue;
save:
		save_packet_sql(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, usersnifferIT->first);
	}

	// nothing matches
	return;
}

/*
   save packet into file 
   type - 1 is SIP, 2 is RTP, 3 is RTCP

*/
inline void save_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, unsigned int saddr, int source, unsigned int daddr, int dest, int istcp, char *data, int datalen, int type) {
	// check if it should be stored to mysql 
	if(global_livesniffer and (sipportmatrix[source] || sipportmatrix[dest])) {
		save_live_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen);
	}

	if(opt_newdir and opt_pcap_split) {
		switch(type) {
		case TYPE_SIP:
			if(call->get_fsip_pcap() != NULL){
				call->set_last_packet_time(header->ts.tv_sec);
				pcap_dump((u_char *) call->get_fsip_pcap(), header, packet);
				if (opt_packetbuffered) 
					pcap_dump_flush(call->get_fsip_pcap());
			}
			break;
		case TYPE_RTP:
		case TYPE_RTCP:
			if(call->get_frtp_pcap() != NULL){
				call->set_last_packet_time(header->ts.tv_sec);
				pcap_dump((u_char *) call->get_frtp_pcap(), header, packet);
				if (opt_packetbuffered) 
					pcap_dump_flush(call->get_frtp_pcap());
			}
			break;
		}
	} else {
		if (call->get_f_pcap() != NULL){
			call->set_last_packet_time(header->ts.tv_sec);
			pcap_dump((u_char *) call->get_f_pcap(), header, packet);
			if (opt_packetbuffered) 
				pcap_dump_flush(call->get_f_pcap());
		}
	}
}

int check_sip20(char *data, unsigned long len){
	int ok;
	if(len < 11) {
		return 0;
	}
	char a = data[9];
	data[9] = '\0';
	//List of SIP request methods
	//RFC 3261
	if(strcasestr(data, "SIP/2.0")) {
		ok = 1;
	} else if(strcasestr(data, "INVITE")) {
		ok = 1;
	} else if(strcasestr(data, "ACK")) {
		ok = 1;
	} else if(strcasestr(data, "BYE")) {
		ok = 1;
	} else if(strcasestr(data, "CANCEL")) {
		ok = 1;
	} else if(strcasestr(data, "OPTIONS")) {
		ok = 1;
	} else if(strcasestr(data, "REGISTER")) {
		ok = 1;
	//RFC 3262
	} else if(strcasestr(data, "PRACK")) {
		ok = 1;
	} else if(strcasestr(data, "SUBSCRIBE")) {
		ok = 1;
	} else if(strcasestr(data, "NOTIFY")) {
		ok = 1;
	} else if(strcasestr(data, "PUBLISH")) {
		ok = 1;
	} else if(strcasestr(data, "INFO")) {
		ok = 1;
	} else if(strcasestr(data, "REFER")) {
		ok = 1;
	} else if(strcasestr(data, "MESSAGE")) {
		ok = 1;
	} else if(strcasestr(data, "UPDATE")) {
		ok = 1;
	} else {
		ok = 0;
	}
	data[9] = a;
	return ok;
}

/* get SIP tag from memory pointed to *ptr length of len */
char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen){
	unsigned long register r, l, tl;
	char *rc = NULL;
	char *tmp;
	char tmp2;
	tmp = (char*)ptr;

	if(len <= 0) {
		*gettaglen = 0;
		return NULL;
	}

	// put '\0' at the end of the packet so it can be used with string functions. then restore the character
	tmp2 = tmp[len - 1];
	tmp[len - 1] = '\0';

	tl = strlen(tag);
	//r = (unsigned long)memmem(ptr, len, tag, tl); memmem cannot be used because SIP headers are case insensitive
	r = (unsigned long)strcasestr(tmp, tag);
	tmp[len - 1] = tmp2;
	if(r == 0){
		// tag did not match
		l = 0;
	} else {
		//tag matches move r pointer behind the tag name
		r += tl;
		l = (unsigned long)memmem((void *)r, len - (r - (unsigned long)ptr), "\r\n", 2);
		if (l > 0){
			// remove trailing \r\n and set l to length of the tag
			l -= r;
		} else {
			// trailing \r\n not found
			l = 0;
		}
	}
	// left trim spacees
	if(l > 0) {
		rc = (char*)r;
		if (rc) {
			while (((char *)ptr + len) > rc && rc[0] == ' '){
				rc++;
				l--;
			}
		}
	}
	*gettaglen = l;
	return rc;
}

int get_sip_peercnam(char *data, int data_len, const char *tag, char *peername, unsigned int peername_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, tag, &peername_tag_len);
	if(!peername_tag_len) {
		goto fail_exit;
	}

/* three types of URI
 1)     "A. G. Bell" <sip:agb@bell-telephone.com> ;tag=a48s
 2)     Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8
 3)     sip:+12125551212@server.phone2net.com;tag=887s
*/
	if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "\"", 1)) == 0){
		// try without ""
		if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "<", 1)) == 0){
			goto fail_exit;
		} else {
			// found case 2)     Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8
			r = (unsigned long)peername_tag;
		}
	} else {
		// found case 1) "A. G. Bell" <sip:agb@bell-telephone.com> ;tag=a48s
		r += 1;
	}
	if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, "\" <", 3)) == 0){
		// try without space ' '
		if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, "\"<", 2)) == 0){
			// try without quotes
			if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, " <", 2)) == 0){
				goto fail_exit;
			}
		}
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)peername_len) ){
		goto fail_exit;
	}
	memcpy(peername, (void*)r, MIN(r2 - r, peername_len));
	peername[MIN(r2 - r, peername_len - 1)] = '\0';
	return 0;
fail_exit:
	strcpy(peername, "");
	return 1;
}


int get_sip_peername(char *data, int data_len, const char *tag, char *peername, unsigned int peername_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, tag, &peername_tag_len);
	if(!peername_tag_len) {
		goto fail_exit;
	}
	if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "sip:", 4)) == 0){
		goto fail_exit;
	}
	r += 4;
	if ((r2 = (unsigned long)memmem((char*)r, peername_tag_len, "@", 1)) == 0){
		goto fail_exit;
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)peername_len)  ){
		goto fail_exit;
	}
	memcpy(peername, (void*)r, MIN(r2 - r, peername_len));
	peername[MIN(r2 - r, peername_len - 1)] = '\0';
	return 0;
fail_exit:
	strcpy(peername, "");
	return 1;
}

int get_sip_domain(char *data, int data_len, const char *tag, char *domain, unsigned int domain_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, tag, &peername_tag_len);
	char *c;
	if(!peername_tag_len) {
		goto fail_exit;
	}
	if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "sip:", 4)) == 0){
		goto fail_exit;
	}
	r += 4;
	if ((r = (unsigned long)memmem((char*)r, peername_tag_len, "@", 1)) == 0){
		goto fail_exit;
	}
	r += 1;
	if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, ">", 1)) == 0){
		if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len + 1, "\r", 1)) == 0){
			goto fail_exit;
		}
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)domain_len)  ){
		goto fail_exit;
	}
	memcpy(domain, (void*)r, MIN(r2 - r, domain_len));
	domain[MIN(r2 - r, domain_len - 1)] = '\0';

	// strip :port
	if(!opt_domainport) {
		c = strchr(domain, ':');
		if(c != NULL)
			*c = '\0';
	}
	// check if there is ; in the string (for example sip:<123@domain;user=phone>
	c = strchr(domain, ';');
	if(c != NULL)
		*c = '\0';
	

	return 0;
fail_exit:
	strcpy(domain, "");
	return 1;
}


int get_sip_branch(char *data, int data_len, const char *tag, char *branch, unsigned int branch_len){
	unsigned long r, r2, branch_tag_len;
	char *branch_tag = gettag(data, data_len, tag, &branch_tag_len);
	if ((r = (unsigned long)memmem(branch_tag, branch_tag_len, "branch=", 7)) == 0){
		goto fail_exit;
	}
	r += 7;
	if ((r2 = (unsigned long)memmem(branch_tag, branch_tag_len, ";", 1)) == 0){
		goto fail_exit;
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)branch_len)  ){
		goto fail_exit;
	}
	memcpy(branch, (void*)r, MIN(r2 - r, branch_len));
	branch[MIN(r2 - r, branch_len - 1)] = '\0';
	return 0;
fail_exit:
	strcpy(branch, "");
	return 1;
}


int get_ip_port_from_sdp(char *sdp_text, in_addr_t *addr, unsigned short *port, int *fax){
	unsigned long l;
	char *s;
	char s1[20];

	*fax = 0;
	s = gettag(sdp_text,strlen(sdp_text), "c=IN IP4 ", &l);
	if(l == 0) return 1;
	memset(s1, '\0', sizeof(s1));
	memcpy(s1, s, MIN(l, 19));
//	printf("---------- [%s]\n", s1);
	if ((int32_t)(*addr = inet_addr(s1)) == -1){
		*addr = 0;
		*port = 0;
		return 1;
	}
	s = gettag(sdp_text, strlen(sdp_text), "m=audio ", &l);
	if (l == 0 || (*port = atoi(s)) == 0){
		s = gettag(sdp_text, strlen(sdp_text), "m=image ", &l);
		if (l == 0 || (*port = atoi(s)) == 0){
			*port = 0;
			return 1;
		} else {
			*fax = 1;
		}
	}
	return 0;
}

int get_value_stringkeyval2(const char *data, unsigned int data_len, const char *key, char *value, int unsigned len) {
	unsigned long r, tag_len;
	char *tmp = gettag(data, data_len, key, &tag_len);
	//gettag removes \r\n but we need it
	if(!tag_len) {
		goto fail_exit;
	} else {
		//gettag remove trailing \r but we need it 
		tag_len++;
	}
	if ((r = (unsigned long)memmem(tmp, tag_len, ";", 1)) == 0){
		if ((r = (unsigned long)memmem(tmp, tag_len, "\r", 1)) == 0){
			goto fail_exit;
		}
	}
	memcpy(value, (void*)tmp, MIN((r - (unsigned long)tmp), len));
	value[MIN(r - (unsigned long)tmp, len - 1)] = '\0';
	return 0;
fail_exit:
	strcpy(value, "");
	return 1;
}

int get_expires_from_contact(char *data, int datalen, int *expires){
	char *s;
	unsigned long l;

	if(datalen < 8) return 1;

	s = gettag(data, datalen, "\nContact:", &l);
	if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
		char tmp[128];
		int res = get_value_stringkeyval2(s, l + 2, "expires=", tmp, sizeof(tmp));
		if(res) {
			// not found, try again in case there is more Contact headers
			return get_expires_from_contact(s, datalen - (s - data), expires);
		} else {
			*expires = atoi(tmp);
			return 0;
		}
	} else {
		return 1;
	}
}

int get_value_stringkeyval(const char *data, unsigned int data_len, const char *key, char *value, unsigned int len) {
	unsigned long r, tag_len;
	char *tmp = gettag(data, data_len, key, &tag_len);
	if(!tag_len) {
		goto fail_exit;
	}
	if ((r = (unsigned long)memmem(tmp, tag_len, "\"", 1)) == 0){
		goto fail_exit;
	}
	memcpy(value, (void*)tmp, MIN(r - (unsigned long)tmp, len));
	value[MIN(r - (unsigned long)tmp, len - 1)] = '\0';
	return 0;
fail_exit:
	strcpy(value, "");
	return 1;
}


int mimeSubtypeToInt(char *mimeSubtype) {
       if(strcasecmp(mimeSubtype,"G729") == 0)
	       return PAYLOAD_G729;
       else if(strcasecmp(mimeSubtype,"GSM") == 0)
	       return PAYLOAD_GSM;
       else if(strcasecmp(mimeSubtype,"G723") == 0)
	       return PAYLOAD_G723;
       else if(strcasecmp(mimeSubtype,"PCMA") == 0)
	       return PAYLOAD_PCMA;
       else if(strcasecmp(mimeSubtype,"PCMU") == 0)
	       return PAYLOAD_PCMU;
       else if(strcasecmp(mimeSubtype,"iLBC") == 0)
	       return PAYLOAD_ILBC;
       else if(strcasecmp(mimeSubtype,"speex") == 0)
	       return PAYLOAD_SPEEX;
       else if(strcasecmp(mimeSubtype,"SPEEX") == 0)
	       return PAYLOAD_SPEEX;
       else if(strcasecmp(mimeSubtype,"SILK") == 0)
	       return PAYLOAD_SILK;
       else if(strcasecmp(mimeSubtype,"ISAC") == 0)
	       return PAYLOAD_ISAC;
       else
	       return 0;
}

int get_rtpmap_from_sdp(char *sdp_text, unsigned long len, int *rtpmap){
	unsigned long l = 0;
	char *s, *z;
	int codec;
	char mimeSubtype[128];
	int i = 0;
	int rate = 0;

	s = gettag(sdp_text, len, "m=audio ", &l);
	if(!l) {
		return 0;
	}
	do {
		s = gettag(s, len - (s - sdp_text), "a=rtpmap:", &l);
		if(l && (z = strchr(s, '\r'))) {
			*z = '\0';
		} else {
			break;
		}
		if (sscanf(s, "%30u %[^/]/%d", &codec, mimeSubtype, &rate) == 3) {
			// store payload type and its codec into one integer with 1000 offset
			int mtype = mimeSubtypeToInt(mimeSubtype);
			if(mtype == PAYLOAD_SILK) {
				switch(rate) {
					case 8000:
						mtype = PAYLOAD_SILK8;
						break;
					case 12000:
						mtype = PAYLOAD_SILK12;
						break;
					case 16000:
						mtype = PAYLOAD_SILK16;
						break;
					case 24000:
						mtype = PAYLOAD_SILK24;
						break;
				}
			} else if(mtype == PAYLOAD_ISAC) {
				switch(rate) {
					case 16000:
						mtype = PAYLOAD_ISAC16;
						break;
					case 32000:
						mtype = PAYLOAD_ISAC32;
						break;
				}
			}
			rtpmap[i] = mtype + 1000*codec;
			//printf("PAYLOAD: rtpmap[%d]:%d codec:%d, mimeSubtype [%d] [%s]\n", i, rtpmap[i], codec, mtype, mimeSubtype);
		}
		// return '\r' into sdp_text
		*z = '\r';
		i++;
	 } while(l);
	 rtpmap[i] = 0; //terminate rtpmap field
	 return 0;
}

void add_to_rtp_thread_queue(Call *call, unsigned char *data, int datalen, struct pcap_pkthdr *header,  u_int32_t saddr, unsigned short port, int iscaller, int is_rtcp) {
	__sync_add_and_fetch(&call->rtppcaketsinqueue, 1);
	read_thread *params = &(threads[call->thread_num]);

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
	rtp_packet *rtpp = (rtp_packet*)malloc(sizeof(rtp_packet));
	rtpp->data = (unsigned char *)malloc(sizeof(unsigned char) * datalen);
#endif

#ifdef QUEUE_NONBLOCK2
	rtp_packet *rtpp = &(params->vmbuffer[params->writeit % params->vmbuffermax]);

	while(params->vmbuffer[params->writeit % params->vmbuffermax].free == 0) {
		// no room left, loop until there is room
		usleep(100);
	}
#endif
	rtpp->call = call;
	rtpp->datalen = datalen;
	rtpp->saddr = saddr;
	rtpp->port = port;
	rtpp->iscaller = iscaller;
	rtpp->is_rtcp = is_rtcp;

	memcpy(&rtpp->header, header, sizeof(struct pcap_pkthdr));
	if(datalen > MAXPACKETLENQRING) {
		syslog(LOG_ERR, "error: packet is to large [%d]b for RTP QRING[%d]b", header->caplen, MAXPACKETLENQRING);
		return;
	}
	if(opt_skiprtpdata) {
		memcpy(rtpp->data, data, MIN(datalen, sizeof(RTPFixedHeader)));
	} else {
		memcpy(rtpp->data, data, datalen);
	}

#ifdef QUEUE_NONBLOCK2
	params->vmbuffer[params->writeit % params->vmbuffermax].free = 0;
	if((params->writeit + 1) == params->vmbuffermax) {
		params->writeit = 0;
	} else {
		params->writeit++;
	}
#endif

#ifdef QUEUE_MUTEX
	pthread_mutex_lock(&(threads[call->thread_num].qlock));
	threads[call->thread_num].pqueue.push(rtpp);
	pthread_mutex_unlock(&(threads[call->thread_num].qlock));
	sem_post(&threads[call->thread_num].semaphore);
#endif

#ifdef QUEUE_NONBLOCK
	if(queue_enqueue(threads[call->thread_num].pqueue, (void*)rtpp) == 0) {
		// enqueue failed, try to raise queue
		if(queue_guaranteed_enqueue(threads[call->thread_num].pqueue, (void*)rtpp) == 0) {
			syslog(LOG_ERR, "error: add_to_rtp_thread_queue cannot allocate memory");
		}
	}
#endif
}


void *rtp_read_thread_func(void *arg) {
	rtp_packet *rtpp;
	read_thread *params = (read_thread*)arg;
	while(1) {

#ifdef QUEUE_MUTEX
		sem_wait(&params->semaphore);

		pthread_mutex_lock(&(params->qlock));
		rtpp = params->pqueue.front();
		params->pqueue.pop();
		pthread_mutex_unlock(&(params->qlock));
#endif
		
#ifdef QUEUE_NONBLOCK
		if(queue_dequeue(params->pqueue, (void **)&rtpp) != 1) {
			// queue is empty
			if(terminating || readend) {
				return NULL;
			}
			usleep(10000);
			continue;
		};
#endif 

#ifdef QUEUE_NONBLOCK2
		if(params->vmbuffer[params->readit % params->vmbuffermax].free == 1) {
			if(terminating || readend) {
				return NULL;
			}
			// no packet to read, wait and try again
			usleep(10000);
			continue;
		} else {
			rtpp = &(params->vmbuffer[params->readit % params->vmbuffermax]);
		}
#endif

		if(rtpp->is_rtcp) {
			rtpp->call->read_rtcp((unsigned char*)rtpp->data, rtpp->datalen, &rtpp->header, rtpp->saddr, rtpp->port, rtpp->iscaller);
		}  else {
			rtpp->call->read_rtp(rtpp->data, rtpp->datalen, &rtpp->header, rtpp->saddr, rtpp->port, rtpp->iscaller);
		}


		rtpp->call->set_last_packet_time(rtpp->header.ts.tv_sec);

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
		free(rtpp->data);
		free(rtpp);
#endif

#ifdef QUEUE_NONBLOCK2
		params->vmbuffer[params->readit % params->vmbuffermax].free = 1;
		if((params->readit + 1) == params->vmbuffermax) {
			params->readit = 0;
		} else {
			params->readit++;
		}
		__sync_sub_and_fetch(&rtpp->call->rtppcaketsinqueue, 1);
#endif
	}

	return NULL;
}

Call *new_invite_register(int sip_method, char *data, int datalen, struct pcap_pkthdr *header, char *callidstr, u_int32_t saddr, u_int32_t daddr, int source, char *s, long unsigned int l){
	if(opt_callslimit != 0 and opt_callslimit > calls) {
		if(verbosity > 0)
			syslog(LOG_NOTICE, "callslimit[%d] > calls[%d] ignoring call\n", opt_callslimit, calls);
	}

	static char str2[1024];
	// store this call only if it starts with invite
	Call *call = calltable->add(s, l, header->ts.tv_sec, saddr, source);
	call->set_first_packet_time(header->ts.tv_sec);
	call->sipcallerip = saddr;
	call->sipcalledip = daddr;
	call->type = sip_method;
	ipfilter->add_call_flags(&(call->flags), ntohl(saddr), ntohl(daddr));
	strncpy(call->fbasename, callidstr, MAX_FNAME - 1);

	/* this logic updates call on the first INVITES */
	if (sip_method == INVITE or sip_method == REGISTER or sip_method == MESSAGE) {
		//geolocation 
		s = gettag(data, datalen, "\nGeoPosition:", &l);
		if(l && l < 255) {
			char buf[255];
			memcpy(buf, s, l);
			buf[l] = '\0';
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen GeoPosition header: [%s]\n", buf);
			call->geoposition = buf;
		}

		int res;
		// callername
		res = get_sip_peercnam(data,datalen,"\nFrom:", call->callername, sizeof(call->callername));
		if(res) {
			// try compact header
			get_sip_peercnam(data,datalen,"\nf:", call->callername, sizeof(call->callername));
		}

		// caller number
		res = get_sip_peername(data,datalen,"\nFrom:", call->caller, sizeof(call->caller));
		if(res) {
			// try compact header
			get_sip_peername(data,datalen,"\nf:", call->caller, sizeof(call->caller));
		}

		// caller number
		res = get_sip_peername(data,datalen,"\nTo:", call->called, sizeof(call->called));
		if(res) {
			// try compact header
			get_sip_peername(data,datalen,"\nt:", call->called, sizeof(call->called));
		}

		// caller domain 
		res = get_sip_domain(data,datalen,"\nFrom:", call->caller_domain, sizeof(call->caller_domain));
		if(res) {
			// try compact header
			get_sip_domain(data,datalen,"\nf:", call->caller_domain, sizeof(call->caller_domain));
		}

		// called domain 
		res = get_sip_domain(data,datalen,"\nTo:", call->called_domain, sizeof(call->called_domain));
		if(res) {
			// try compact header
			get_sip_domain(data,datalen,"\nt:", call->called_domain, sizeof(call->called_domain));
		}

		if(sip_method == REGISTER) {	
			// destroy all REGISTER from memory within 30 seconds 
			call->destroy_call_at = header->ts.tv_sec + 30;

			// copy contact num <sip:num@domain>
			s = gettag(data, datalen, "\nUser-Agent:", &l);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
				call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
			}

			res = get_sip_peername(data,datalen,"\nContact:", call->contact_num, sizeof(call->contact_num));
			if(res) {
				// try compact header
				get_sip_peername(data,datalen,"\nm:", call->contact_num, sizeof(call->contact_num));
			}
			// copy contact domain <sip:num@domain>
			res = get_sip_domain(data,datalen,"\nContact:", call->contact_domain, sizeof(call->contact_domain));
			if(res) {
				// try compact header
				get_sip_domain(data,datalen,"\nm:", call->contact_domain, sizeof(call->contact_domain));
			}

			// copy Authorization
			s = gettag(data, datalen, "\nAuthorization:", &l);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				get_value_stringkeyval(s, datalen - (s - data), "username=\"", call->digest_username, sizeof(call->digest_username));
				get_value_stringkeyval(s, datalen - (s - data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
			}
			// get expires header
			s = gettag(data, datalen, "\nExpires:", &l);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				char c = s[l];
				s[l] = '\0';
				call->register_expires = atoi(s);
				s[l] = c;
			}
			// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
			get_expires_from_contact(data, datalen, &call->register_expires);
/*
			syslog(LOG_NOTICE, "contact_num[%s] contact_domain[%s] from_num[%s] from_name[%s] from_domain[%s] digest_username[%s] digest_realm[%s] expires[%d]\n", 
				call->contact_num, call->contact_domain, call->caller, call->callername, call->caller_domain, 
				call->digest_username, call->digest_realm, call->register_expires);
*/
		}

		if(sip_method == INVITE) {
			call->seeninvite = true;
			telnumfilter->add_call_flags(&(call->flags), call->caller, call->called);
#ifdef DEBUG_INVITE
			syslog(LOG_NOTICE, "New call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s] Call-ID[%s]\n", 
				call->sipcallerip, call->sipcalledip, call->caller, call->called, call->fbasename);
#endif
		}
	}

	if(opt_norecord_header) {
		s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l);
		if(l && l < 33) {
			// do 
			call->stoprecording();
		}
	}

	// opening dump file
	if(call->type != REGISTER && (call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP | FLAG_SAVEWAV) || opt_savewav_force)) {
		static string lastdir;
		if(lastdir != call->dirname()) {
			string tmp, dir;
			if(opt_cachedir[0] != '\0') {
	//			sprintf(str2, "%s/%s", opt_cachedir, call->dirname().c_str());
				string dir;
				dir = opt_cachedir;
				dir += "/" + call->dirname();
				if(opt_newdir) {
					tmp = dir + "/ALL";
					mkdir_r(tmp, 0777);
					tmp = dir + "/SIP";
					mkdir_r(tmp, 0777);
					tmp = dir + "/RTP";
					mkdir_r(tmp, 0777);
					tmp = dir + "/GRAPH";
					mkdir_r(tmp, 0777);
					tmp = dir + "/AUDIO";
					mkdir_r(tmp, 0777);
				} else {
					mkdir_r(dir, 0777);
				}
			}
			dir = call->dirname();
			if(opt_newdir) {
				tmp = dir + "/ALL";
				mkdir_r(tmp, 0777);
				tmp = dir + "/SIP";
				mkdir_r(tmp, 0777);
				tmp = dir + "/RTP";
				mkdir_r(tmp, 0777);
				tmp = dir + "/GRAPH";
				mkdir_r(tmp, 0777);
				tmp = dir + "/AUDIO";
				mkdir_r(tmp, 0777);
				mkdir_r(call->dirname(), 0777);
			} else {
				mkdir_r(dir, 0777);
			}
			
			lastdir = call->dirname();
		}
	}
	if(call->type != REGISTER && ((call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP)) || (call->isfax && opt_saveudptl))) {
		// open one pcap for all packets or open SIP and RTP separatly
		call->set_f_pcap(NULL);
		call->set_fsip_pcap(NULL);
		call->set_frtp_pcap(NULL);
		if(opt_newdir and opt_pcap_split) {
			//SIP
			if(opt_cachedir[0] != '\0') {
				sprintf(str2, "%s/%s/%s/%s.pcap", opt_cachedir, call->dirname().c_str(), opt_newdir ? "SIP" : "", call->get_fbasename_safe());
			} else {
				sprintf(str2, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "SIP" : "", call->get_fbasename_safe());
			}
			call->sip_pcapfilename = call->dirname() + (opt_newdir ? "/SIP" : "") + "/" + call->get_fbasename_safe() + ".pcap";
			if(!file_exists(str2)) {
				call->set_fsip_pcap(pcap_dump_open(handle, str2));
				if(call->get_fsip_pcap() == NULL) {
					syslog(LOG_NOTICE,"pcap [%s] cannot be opened: %s\n", str2, pcap_geterr(handle));
				}
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			} else {
				if(verbosity > 0) {
					syslog(LOG_NOTICE,"pcap_filename: [%s] already exists, do not overwriting\n", str2);
				}
			}
			//RTP
			if(opt_cachedir[0] != '\0') {
				sprintf(str2, "%s/%s/%s/%s.pcap", opt_cachedir, call->dirname().c_str(), opt_newdir ? "RTP" : "", call->get_fbasename_safe());
			} else {
				sprintf(str2, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "RTP" : "", call->get_fbasename_safe());
			}
			call->rtp_pcapfilename = call->dirname() + (opt_newdir ? "/RTP" : "") + "/" + call->get_fbasename_safe() + ".pcap";
			if(!file_exists(str2)) {
				call->set_frtp_pcap(pcap_dump_open(handle, str2));
				if(call->get_frtp_pcap() == NULL) {
					syslog(LOG_NOTICE,"pcap [%s] cannot be opened: %s\n", str2, pcap_geterr(handle));
				}
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			} else {
				if(verbosity > 0) {
					syslog(LOG_NOTICE,"pcap_filename: [%s] already exists, do not overwriting\n", str2);
				}
			}
		} else {
			if(opt_cachedir[0] != '\0') {
				sprintf(str2, "%s/%s/%s/%s.pcap", opt_cachedir, call->dirname().c_str(), opt_newdir ? "ALL" : "", call->get_fbasename_safe());
			} else {
				sprintf(str2, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "ALL" : "", call->get_fbasename_safe());
			}
			call->pcapfilename = call->dirname() + (opt_newdir ? "/ALL/" : "/") + call->get_fbasename_safe() + ".pcap";
			if(!file_exists(str2)) {
				call->set_f_pcap(pcap_dump_open(handle, str2));
				if(call->get_f_pcap() == NULL) {
					syslog(LOG_NOTICE,"pcap [%s] cannot be opened: %s\n", str2, pcap_geterr(handle));
				}
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			} else {
				call->set_f_pcap(NULL);
				if(verbosity > 0) {
					syslog(LOG_NOTICE,"pcap_filename: [%s] already exists, do not overwriting\n", str2);
				}
			}
		}
	}

	//check and save CSeq for later to compare with OK 
	s = gettag(data, datalen, "\nCSeq:", &l);
	if(l && l < 32) {
		memcpy(call->invitecseq, s, l);
		call->unrepliedinvite++;
		call->invitecseq[l] = '\0';
		if(verbosity > 2)
			syslog(LOG_NOTICE, "Seen invite, CSeq: %s\n", call->invitecseq);
	}
	
	// check if we have X-VoipMonitor-Custom1
	s = gettag(data, datalen, "\nX-VoipMonitor-Custom1:", &l);
	if(l && l < 255) {
		memcpy(call->custom_header1, s, l);
		call->custom_header1[l] = '\0';
		if(verbosity > 2)
			syslog(LOG_NOTICE, "Seen X-VoipMonitor-Custom1: %s\n", call->custom_header1);
	}

	// check if we have opt_match_header
	if(opt_match_header[0] != '\0') {
		s = gettag(data, datalen, opt_match_header, &l);
		if(l && l < 128) {
			memcpy(call->match_header, s, l);
			call->match_header[l] = '\0';
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen header %s: %s\n", opt_match_header, call->match_header);
		}
	}

	return call;
}

void clean_tcpstreams() {
	// clean tcp_streams_list
	list<tcp_stream2_t*>::iterator stream;
	for (stream = tcp_streams_list.begin(); stream != tcp_streams_list.end();) {
		// remove tcp stream after 10 minutes
		tcp_stream2_t *next, *tmpstream;
		tmpstream = tcp_streams_hashed[(*stream)->hash];
		tcp_streams_hashed[(*stream)->hash] = NULL;
		while(tmpstream) {
			free(tmpstream->data);
			free(tmpstream->packet);
			next = tmpstream->next;
			free(tmpstream);
			tmpstream = next;
		}
		tcp_streams_list.erase(stream++);
	}
}

Call *process_packet(unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen,
	pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int istcp, int dontsave, int can_thread, int *was_rtp, struct iphdr *header_ip, int *voippacket) {

	Call *call;
	int last_sip_method = -1;
	int iscaller;
	int is_rtcp = 0;
	static unsigned long last_cleanup = 0;	// Last cleaning time
	char *s;
	unsigned long l;
	char callidstr[1024],str2[1024];
	int sip_method = 0;
	char lastSIPresponse[128];
	int lastSIPresponseNum;
	static struct pcap_stat ps;
	static int pcapstatres = 0;
	static int pcapstatresCount = 0;
	static unsigned int lostpacket = 0;
	static unsigned int lostpacketif = 0;
	unsigned int tmp_u32 = 0;

	*was_rtp = 0;

	// checking and cleaning stuff every 10 seconds (if some packet arrive) 
	if (header->ts.tv_sec - last_cleanup > 10){
		if(verbosity > 0) syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d]\n", (int)calltable->calls_listMAP.size(), (int)calltable->calls_queue.size());
		if (last_cleanup >= 0){
			calltable->cleanup(header->ts.tv_sec);
		}
		/* also do every 10 seconds pcap statistics */
		pcapstatres = pcap_stats(handle, &ps);
		if (pcapstatres == 0 && (lostpacket < ps.ps_drop || lostpacketif < ps.ps_ifdrop)) {
			if(pcapstatresCount) {
				syslog(LOG_ERR, "error: libpcap or interface dropped some packets! rx:%i pcapdrop:%i ifdrop:%i increase --ring-buffer (kernel >= 2.6.31 needed and libpcap >= 1.0.0) or use --pcap-thread\n", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
			} else {
				// do not show first error, it is normal on startup. 
				pcapstatresCount++;
			}
			lostpacket = ps.ps_drop;
			lostpacketif = ps.ps_ifdrop;
		}
		last_cleanup = header->ts.tv_sec;
		/* delete all calls */
		calltable->lock_calls_deletequeue();
		while (calltable->calls_deletequeue.size() > 0) {
			call = calltable->calls_deletequeue.front();
			calltable->calls_deletequeue.pop();
			call->hashRemove();
			delete call;
			calls--;
		}
		calltable->unlock_calls_deletequeue();

		// clean tcp_streams_list
		list<tcp_stream2_t*>::iterator stream;
		for (stream = tcp_streams_list.begin(); stream != tcp_streams_list.end();) {
			if((header->ts.tv_sec - (*stream)->ts) > (10 * 60)) {
				// remove tcp stream after 10 minutes
				tcp_stream2_t *next, *tmpstream;
				tmpstream = tcp_streams_hashed[(*stream)->hash];
				tcp_streams_hashed[(*stream)->hash] = NULL;
				while(tmpstream) {
					free(tmpstream->data);
					free(tmpstream->packet);
					next = tmpstream->next;
					free(tmpstream);
					tmpstream = next;
				}
				tcp_streams_list.erase(stream++);
			} else {
				++stream;
			}
		}
		/* You may encounter that voipmonitor process does not have a reduced memory usage although you freed the calls. 
		This is because it allocates memory in a number of small chunks. When freeing one of those chunks, the OS may decide 
		that giving this little memory back to the kernel will cause too much overhead and delay the operation. As all chunks 
		are this small, they get actually freed but not returned to the kernel. On systems using glibc, there is a function call 
		"malloc_trim" from malloc.h which does this missing operation (note that it is allowed to fail). If your OS does not provide 
		malloc_trim, try searching for a similar function.
		*/
		malloc_trim(0);

	}


	// check if the packet is SIP ports 	
	if(sipportmatrix[source] || sipportmatrix[dest]) {
		*voippacket = 1;
#if 0
		/* ugly and dirty hack to detect two SIP messages in one TCP packet. */
		tmp = strstr(data, "SIP/2.0 ");
		if(tmp) {
			tmp = strstr(tmp + 8, "SIP/2.0 ");
			if(tmp) {
				// second SIP message in one packet. Skip the first packet for now. TODO: process both packets
				datalen -= tmp - data;
				data = tmp;
			}
		}
#endif

		/* note that Call-ID isn't the phone number of the caller. It uniquely represents 
		   the whole call, or dialog, between the two user agents. All related SIP 
		   messages use the same Call-ID. For example, when a user agent receives a 
		   BYE message, it knows which call to hang up based on the Call-ID.
		*/
		int issip = check_sip20(data, datalen);
		s = gettag(data, datalen, "\nCall-ID:", &l);
		if(!issip or (l <= 0 || l > 1023)) {
			// try also compact header
			s = gettag(data, datalen,"\ni:", &l);
			if(!issip or (l <= 0 || l > 1023)) {
				// no Call-ID found in packet
				if(istcp && header_ip) {
					// packet is tcp, check if belongs to some previouse TCP stream (reassembling here)
					struct tcphdr *header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));
					tcp_stream2_t *tmpstream;
					u_int hash = mkhash(saddr, source, daddr, dest) % MAX_TCPSTREAMS;
					tmpstream = tcp_streams_hashed[hash];
					if(tcp_streams_hashed[hash] == NULL) {
						// this packet do not belongs to preivious TCP session but check opposite direction and if yes 
						// check if the tcp packet has sequence number which confirms ACK and thus marks end of tcpstream 
						hash = mkhash(daddr, dest, saddr, source) % MAX_TCPSTREAMS;
						if((tmpstream = tcp_streams_hashed[hash])) {
							tcp_stream2_t *laststream;
							for(laststream = tcp_streams_hashed[hash]; laststream->next; laststream = laststream->next) {}; // set cursor to the latest item
							if((laststream->lastpsh and laststream->ack_seq == htonl(header_tcp->seq)) 
								or (datalen >= 2 and (data[datalen - 2] == 0x0d and data[datalen - 1] == 0x0a))) {
								// it is ACK which means that the tcp reassembled packets will be reassembled and processed 
								tcp_streams_list.remove(tcp_streams_hashed[hash]);
								int newlen = 0;
								// get SIP packet length from all TCP segments
								for(tmpstream = tcp_streams_hashed[hash]; tmpstream; tmpstream = tmpstream->next) {
									newlen += tmpstream->datalen;
								};
								// allocate structure for whole SIP packet and concatenate all segments 
								u_char *newdata = (u_char*)malloc(sizeof(u_char) * newlen);
								int len2 = 0;
								for(tmpstream = tcp_streams_hashed[hash]; tmpstream; tmpstream = tmpstream->next) {
									memcpy(newdata + len2, tmpstream->data, tmpstream->datalen);
									len2 += tmpstream->datalen;
								};
								// sip message is now reassembled and can be processed 
								// here we turns out istcp flag so the function process_packet will not reach tcp reassemble and will process the whole message
								int tmp_was_rtp;
								Call *call = process_packet(saddr, source, daddr, dest, (char*)newdata, newlen, handle, header, packet, 0, 1, 0, &tmp_was_rtp, header_ip, voippacket);

								// message was processed so the stream can be released from queue and destroyd all its parts
								tcp_stream2_t *next;
								tmpstream = tcp_streams_hashed[hash];
								while(tmpstream) {
									if(call) {
										// if packet belongs to (or created) call, save each packets to pcap and destroy TCP stream
										save_packet(call, &tmpstream->header, (const u_char*)tmpstream->packet, saddr, source, daddr, dest, istcp, (char *)newdata, sizeof(u_char) * newlen, TYPE_SIP);
									}
									free(tmpstream->data);
									free(tmpstream->packet);
									next = tmpstream->next;
									free(tmpstream);
									tmpstream = next;
								}
								free(newdata);
								tcp_streams_hashed[hash] = NULL;
								// save also current packet 
								if(call) {
									save_packet(call, header, packet, saddr, source, daddr, dest, istcp, (char *)data, datalen, TYPE_SIP);
								}
								return NULL;
							} else {
								// TCP packet does not have CAll-ID header and belongs to no existing stream
								return NULL;
							}
						} else {
							return NULL;
						}
					}

					// the packet belongs to previous stream
					for(tmpstream = tcp_streams_hashed[hash]; tmpstream->next; tmpstream = tmpstream->next) {}; // set cursor to the latest item
					if(tmpstream->next_seq != htonl(header_tcp->seq)) {
						// the packet is out of order or duplicated - skip it. This means that voipmonitor is not able to reassemble reordered packets
						return NULL;
					}

					// append packet to end of streams items 
					tcp_stream2_t *stream = (tcp_stream2_t*)malloc(sizeof(tcp_stream2_t));
					memcpy(stream->call_id, s, MIN(127, l));
					stream->call_id[MIN(127, l)] = '\0';
					stream->next = NULL;
					stream->ts = header->ts.tv_sec;
					stream->hash = hash;

					stream->lastpsh = header_tcp->psh;
					stream->seq = htonl(header_tcp->seq);
					stream->ack_seq = htonl(header_tcp->ack_seq);
					stream->next_seq = stream->seq + (unsigned long int)header->caplen - ((unsigned long int)header_tcp - (unsigned long int)packet + header_tcp->doff * 4);

					// append new created node at the end of list of TCP packets within this TCP connection
					tmpstream->next = stream;

					//copy data 
					stream->data = (char*)malloc(sizeof(char) * datalen);
					memcpy(stream->data, data, datalen);
					stream->datalen = datalen;

					//copy header
					memcpy((void*)(&stream->header), header, sizeof(pcap_pkthdr));

					//copy packet
					stream->packet = (u_char*)malloc(sizeof(u_char) * header->caplen);
					memcpy(stream->packet, packet, header->caplen);

					// check if the latest segment is not erminated by 0x0d or 0x0a which indicates end of SIP message
					// XXX this is repeating block of code 
					if(datalen >= 2 and (data[datalen - 2] == 0x0d and data[datalen - 1] == 0x0a)) {
						// it is ACK which means that the tcp reassembled packets will be reassembled and processed 
						tcp_streams_list.remove(tcp_streams_hashed[hash]);
						int newlen = 0;
						// get SIP packet length from all TCP segments
						for(tmpstream = tcp_streams_hashed[hash]; tmpstream; tmpstream = tmpstream->next) {
							newlen += tmpstream->datalen;
						};
						// allocate structure for whole SIP packet and concatenate all segments 
						u_char *newdata = (u_char*)malloc(sizeof(u_char) * newlen);
						int len2 = 0;
						for(tmpstream = tcp_streams_hashed[hash]; tmpstream; tmpstream = tmpstream->next) {
							memcpy(newdata + len2, tmpstream->data, tmpstream->datalen);
							len2 += tmpstream->datalen;
						};
						// sip message is now reassembled and can be processed 
						// here we turns out istcp flag so the function process_packet will not reach tcp reassemble and will process the whole message
						int tmp_was_rtp;
						Call *call = process_packet(saddr, source, daddr, dest, (char*)newdata, newlen, handle, header, packet, 0, 1, 0, &tmp_was_rtp, header_ip, voippacket);

						// message was processed so the stream can be released from queue and destroyd all its parts
						tcp_stream2_t *next;
						tmpstream = tcp_streams_hashed[hash];
						while(tmpstream) {
							if(call) {
								// if packet belongs to (or created) call, save each packets to pcap and destroy TCP stream
								save_packet(call, &tmpstream->header, (const u_char*)tmpstream->packet, saddr, source, daddr, dest, istcp, (char *)newdata, sizeof(u_char) * newlen, TYPE_SIP);
							}
							free(tmpstream->data);
							free(tmpstream->packet);
							next = tmpstream->next;
							free(tmpstream);
							tmpstream = next;
						}
						free(newdata);
						tcp_streams_hashed[hash] = NULL;
						// save also current packet 
						if(call) {
							save_packet(call, header, packet, saddr, source, daddr, dest, istcp, (char *)data, datalen, TYPE_SIP);
						}
						return NULL;
					}
					return NULL;
				} else {
					// it is not TCP and callid not found
					return NULL;
				}
			}
		}
		memcpy(callidstr, s, MIN(l, 1024));
		callidstr[MIN(l, 1023)] = '\0';

		// Call-ID is present
		if(istcp and datalen >= 2) {
			u_int hash = mkhash(saddr, source, daddr, dest) % MAX_TCPSTREAMS;
			// check if TCP packet contains the whole SIP message
			if(!(data[datalen - 2] == 0x0d && data[datalen - 1] == 0x0a)) {
				// SIP message is not complete, save packet 
				tcp_stream2_t *tmpstream;
				if((tmpstream = tcp_streams_hashed[hash])) {
					tcp_stream2_t test;
					memcpy(&test, tmpstream, sizeof(tmpstream));
					// there is already stream and Call-ID which can happen if previous stream is not closed (lost ACK etc)
					// check if the stream contains the same Call-ID
					if(memmem(tmpstream->call_id, strlen(tmpstream->call_id), s, l)) {
						// callid is same - it must be duplicate or retransmission just ignore the packet 
						return NULL;
					} else {
						// callid is different - end the previous stream 
						tcp_streams_list.remove(tmpstream);
						int newlen = 0;
						// get SIP packet length from all TCP packets
						for(tmpstream = tcp_streams_hashed[hash]; tmpstream; tmpstream = tmpstream->next) {
							newlen += tmpstream->datalen;
						};
						// allocate structure for whole SIP packet and concatenate all segments 
						u_char *newdata = (u_char*)malloc(sizeof(u_char) * newlen);
						int datalen = 0;
						for(tmpstream = tcp_streams_hashed[hash]; tmpstream; tmpstream = tmpstream->next) {
							memcpy(newdata + datalen, tmpstream->data, tmpstream->datalen);
							datalen += tmpstream->datalen;
						};
						// sip message is now reassembled and can be processed 
						// here we turns out istcp flag so the function process_packet will not reach tcp reassemble and will process the whole message
						int tmp_was_rtp;
						Call *call = process_packet(saddr, source, daddr, dest, (char*)newdata, newlen, handle, header, packet, 0, 1, 0, &tmp_was_rtp, header_ip, voippacket);

						// message was processed so the stream can be released from queue and destroyd all its parts
						tcp_stream2_t *next;
						tmpstream = tcp_streams_hashed[hash];
						while(tmpstream) {
							if(call) {
								// if packet belongs to (or created) call, save each packets to pcap and destroy TCP stream
								save_packet(call, &tmpstream->header, (const u_char*)tmpstream->packet, saddr, source, daddr, dest, istcp, (char *)newdata, sizeof(u_char) * newlen, TYPE_SIP);
							}
							free(tmpstream->data);
							free(tmpstream->packet);
							next = tmpstream->next;
							free(tmpstream);
							tmpstream = next;
						}
						// save also current packet 
						if(call) {
							save_packet(call, header, packet, saddr, source, daddr, dest, istcp, (char *)data, datalen, TYPE_SIP);
						}
						free(newdata);
						tcp_streams_hashed[hash] = NULL;
					}
				} 

				// create new tcp stream 
				tcp_stream2_t *stream = (tcp_stream2_t*)malloc(sizeof(tcp_stream2_t));
				tcp_streams_list.push_back(stream);
				memcpy(stream->call_id, s, MIN(127, l));
				stream->call_id[MIN(127, l)] = '\0';
				stream->next = NULL;
				stream->ts = header->ts.tv_sec;
				stream->hash = hash;
				tcp_streams_hashed[hash] = stream;

				struct tcphdr *header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));
				stream->lastpsh = header_tcp->psh;
				stream->seq = htonl(header_tcp->seq);
				stream->ack_seq = htonl(header_tcp->ack_seq);
				stream->next_seq = stream->seq + (unsigned long int)header->caplen - ((unsigned long int)header_tcp - (unsigned long int)packet + header_tcp->doff * 4);

				//copy data
				stream->data = (char*)malloc(sizeof(char) * datalen);
				stream->datalen = datalen;
				memcpy(stream->data, data, datalen);

				//copy header
				memcpy((void*)(&stream->header), header, sizeof(pcap_pkthdr));

				//copy packet
				stream->packet = (u_char*)malloc(sizeof(u_char) * header->caplen);
				memcpy(stream->packet, packet, header->caplen);
				return NULL;
			}
		}

		// parse SIP method 
		if ((datalen > 5) && !(memmem(data, 6, "INVITE", 6) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: INVITE\n");
			sip_method = INVITE;
		} else if ((datalen > 7) && !(memmem(data, 8, "REGISTER", 8) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: REGISTER\n");
			sip_method = REGISTER;
		} else if ((datalen > 6) && !(memmem(data, 7, "MESSAGE", 7) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: MESSAGE\n");
			sip_method = MESSAGE;
		} else if ((datalen > 2) && !(memmem(data, 3, "BYE", 3) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: BYE\n");
			sip_method = BYE;
		} else if ((datalen > 5) && !(memmem(data, 6, "CANCEL", 6) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: CANCEL\n");
			sip_method = CANCEL;
		} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 2", 9) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 2XX\n");
			sip_method = RES2XX;
		} else if ((datalen > 9) && !(memmem(data, 10, "SIP/2.0 18", 10) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 18X\n");
			sip_method = RES18X;
		} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 3", 9) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 3XX\n");
			sip_method = RES3XX;
		} else if ((datalen > 10) && !(memmem(data, 11, "SIP/2.0 401", 11) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 401\n");
			sip_method = RES401;
		} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 4", 9) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 4XX\n");
			sip_method = RES4XX;
		} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 5", 9) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 5XX\n");
			sip_method = RES5XX;
		} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 6", 9) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 6XX\n");
			sip_method = RES6XX;
		} else {
			if(verbosity > 2) {
				syslog(LOG_NOTICE,"SIP msg: 1XX or Unknown msg \n");
			}
			sip_method = 0;
		}
		strcpy(lastSIPresponse, "NO RESPONSE");
		lastSIPresponseNum = 0;
		if(sip_method > 0 && last_sip_method != BYE && sip_method != INVITE && sip_method != REGISTER && sip_method != MESSAGE && sip_method != CANCEL && sip_method != BYE) {
			char a = data[datalen - 1];
			data[datalen - 1] = 0;
			char *tmp = strstr(data, "\r");
			if(tmp) {
				// 8 is len of [SIP/2.0 ], 128 is max buffer size
				strncpy(lastSIPresponse, data + 8, (datalen > 128) ? 128 : datalen);
				lastSIPresponse[tmp - data - 8] = '\0';
				char num[4];
				strncpy(num, data + 8, 3);
				num[3] = '\0';
				lastSIPresponseNum = atoi(num);
				if(lastSIPresponseNum == 0) {
					if(verbosity > 0) syslog(LOG_NOTICE, "lastSIPresponseNum = 0 [%s]\n", lastSIPresponse);
				}
			} 
			data[datalen - 1] = a;
/* XXX: remove it once tested
		} else if(sip_method == CANCEL) {
			lastSIPresponseNum = 487;
			strcpy(lastSIPresponse, "487 Request Terminated CANCEL");
*/
		} else if(sip_method == BYE) {
			strcpy(lastSIPresponse, "BYE");
			lastSIPresponseNum = 0;
		}

		last_sip_method = sip_method;

		// find call */
		if ( ! (call = calltable->find_by_call_id(s, l))){
			// packet does not belongs to any call yet
			if (sip_method == INVITE || sip_method == MESSAGE || (opt_sip_register && sip_method == REGISTER)) {
				call = new_invite_register(sip_method, data, datalen, header, callidstr, saddr, daddr, source, s, l);
			} else {
				// SIP packet does not belong to any call and it is not INVITE 
				return NULL;
			}
		// check if the SIP msg is part of earlier REGISTER
		} else if(call->type == REGISTER) {
			call->msgcount++;
			if(sip_method == REGISTER) {
				call->regcount++;
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER Call-ID[%s] regcount[%d]", call->call_id, call->regcount);

				// update Authorization
				s = gettag(data, datalen, "\nAuthorization:", &l);
				if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
					get_value_stringkeyval(s, datalen - (s - data), "username=\"", call->digest_username, sizeof(call->digest_username));
					get_value_stringkeyval(s, datalen - (s - data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
				}

				if(call->regcount > 4) {
					// to much register attempts without OK or 401 responses
					call->regstate = 4;
					call->saveregister();
					call = new_invite_register(sip_method, data, datalen, header, callidstr, saddr, daddr, source, call->call_id, strlen(call->call_id));
					return call;
				}
				s = gettag(data, datalen, "\nCSeq:", &l);
				if(l && l < 32) {
					memcpy(call->invitecseq, s, l);
					call->invitecseq[l] = '\0';
				}
			} else if(sip_method == RES2XX) {
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER OK Call-ID[%s]", call->call_id);
                                s = gettag(data, datalen, "\nCSeq:", &l);
                                if(l && strncmp(s, call->invitecseq, l) == 0) {
					// registration OK 
					call->regstate = 1;
					call->saveregister();
					return NULL;
				} else {
					call->regstate = 3;
					call->saveregister();
					return NULL;
					// OK to unknown msg close the call
				}
			} else if(sip_method == RES401) {
				call->reg401count++;
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER 401 Call-ID[%s] reg401count[%d]", call->call_id, call->reg401count);
				if(call->reg401count > 1) {
					// registration failed
					call->regstate = 2;
					call->saveregister();
					return NULL;
				}
			}
			if(call->msgcount > 20) {
				// too many REGISTER messages within the same callid
				call->regstate = 4;
				call->saveregister();
				return NULL;
			}
		// packet is already part of call
		// check if SIP packet belongs to the first leg 
		} else if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
			((call->saddr == saddr && call->sport == source) || 
			(call->saddr == daddr && call->sport == dest))))

			{

			char *cseq = NULL;
			long unsigned int cseqlen = 0;
			cseq = gettag(data, datalen, "\nCSeq:", &cseqlen);
			if(cseq && cseqlen < 32) {
				if(memmem(call->invitecseq, strlen(call->invitecseq), cseq, cseqlen)) {
					if(sip_method == INVITE) {
						call->unrepliedinvite++;
					} else if(call->unrepliedinvite > 0){
						call->unrepliedinvite--;
					}
					//syslog(LOG_NOTICE, "[%s] unrepliedinvite--\n", call->call_id);
				}
			}

			if(opt_norecord_header) {
				s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l);
				if(l && l < 33) {
					// do 
					call->stoprecording();
				}
			}

			// we have packet, extend pending destroy requests
			if(call->destroy_call_at > 0) {
				call->destroy_call_at += 5; 
			}

			call->set_last_packet_time(header->ts.tv_sec);
			// save lastSIPresponseNum but only if previouse was not 487 (CANCEL) and call was not answered 
			if(lastSIPresponseNum != 0 && lastSIPresponse[0] != '\0' && call->lastSIPresponseNum != 487 && !call->seeninviteok) {
				strncpy(call->lastSIPresponse, lastSIPresponse, 128);
				call->lastSIPresponseNum = lastSIPresponseNum;
			}

			// check if it is BYE or OK(RES2XX)
			if(sip_method == INVITE) {
				call->destroy_call_at = 0;
				//update called number for each invite due to overlap-dialling
				if (opt_sipoverlap && saddr == call->sipcallerip) {
					int res = get_sip_peername(data,datalen,"\nTo:", call->called, sizeof(call->called));
					if(res) {
						// try compact header
						get_sip_peername(data,datalen,"\nt:", call->called, sizeof(call->called));
					}
				}

				//check and save CSeq for later to compare with OK 
				if(cseq && cseqlen < 32) {
					memcpy(call->invitecseq, cseq, cseqlen);
					call->invitecseq[cseqlen] = '\0';
					if(verbosity > 2)
						syslog(LOG_NOTICE, "Seen INVITE, CSeq: %s\n", call->invitecseq);
				}
			} else if(sip_method == MESSAGE) {
				call->destroy_call_at = header->ts.tv_sec + 60;

				s = gettag(data, datalen, "\nUser-Agent:", &l);
				if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
					memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
					call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
				}

				//check and save CSeq for later to compare with OK 
				if(cseq && cseqlen < 32) {
					memcpy(call->invitecseq, cseq, cseqlen);
					call->invitecseq[cseqlen] = '\0';
					if(verbosity > 2)
						syslog(LOG_NOTICE, "Seen MEESAGE, CSeq: %s\n", call->invitecseq);
				}

				// UPDATE TEXT
				char a = data[datalen - 1];
				data[datalen - 1] = 0;
				char *tmp = strstr(data, "\r\n\r\n");
				if(tmp) {
					tmp += 4; // skip \r\n\r\n and point to start of the message
					int contentlen = 0;
					s = gettag(data, datalen, "\nContent-Length:", &l);
					if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
						char c = s[l];
						s[l] = '\0';
						contentlen = atoi(s);
						s[l] = c;
					}
					char *end = strcasestr(tmp, "\n\nContent-Length:");
					if(!end) {
						end = strstr(tmp, "\r\n"); // strstr is safe becuse tmp ends with '\0'
						if(!end) {
							end = data + datalen;
						}
					}
					if(contentlen > 0) {
						//truncate message to its size announced in content-length
						if(end - tmp > contentlen) {
							end = tmp + MIN(end - tmp, contentlen);
						}
					}
					
					data[datalen - 1] = a;
					if(call->message and (end - tmp) == contentlen) {
						// update message only in case that the new message equels to content length
						free(call->message);
						call->message = (char*)malloc(sizeof(char) * (end - tmp + 1));
						memcpy(call->message, tmp, end - tmp);
						call->message[end - tmp] = '\0';
						//printf("msgu: contentlen[%d] datalen[%d] len[%d] [%s]\n", contentlen, datalen, strlen(call->message), call->message);
					} else if(!call->message) {
						// message is empty - update
						call->message = (char*)malloc(sizeof(char) * (end - tmp + 1));
						memcpy(call->message, tmp, end - tmp);
						call->message[end - tmp] = '\0';
						//printf("msgu: contentlen[%d] datalen[%d] len[%d] [%s]\n", contentlen, datalen, strlen(call->message), call->message);
					}
	
				} else {
					data[datalen - 1] = a;
				}
			} else if(sip_method == BYE) {
				//check and save CSeq for later to compare with OK 
				if(cseq && cseqlen < 32) {
					memcpy(call->byecseq, cseq, cseqlen);
					call->byecseq[cseqlen] = '\0';
					call->seenbye = true;
					if(call->listening_worker_run) {
						*(call->listening_worker_run) = 0;
					}
					if(verbosity > 2)
						syslog(LOG_NOTICE, "Seen bye\n");
						
				}
				// save who hanged up 
				call->whohanged = (call->sipcallerip == saddr) ? 0 : 1;
			} else if(sip_method == CANCEL) {
				// CANCEL continues with Status: 200 canceling; 200 OK; 487 Req. terminated; ACK. Lets wait max 10 seconds and destroy call
				call->destroy_call_at = header->ts.tv_sec + 10;
			} else if(sip_method == RES2XX) {
				// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
				if(call->progress_time == 0) {
					call->progress_time = header->ts.tv_sec;
				}

				// if it is OK check for BYE
				if(cseq && cseqlen < 32) {
					if(verbosity > 2) {
						char a = data[datalen - 1];
						data[datalen - 1] = 0;
						syslog(LOG_NOTICE, "Cseq: %s\n", data);
						data[datalen - 1] = a;
					}
					if(strncmp(cseq, call->byecseq, cseqlen) == 0) {
						// terminate successfully acked call, put it into mysql CDR queue and remove it from calltable 

						call->seenbyeandok = true;
						if(!dontsave && call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER)) {
							save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
						}
/*
	Whan voipmonitor listens for both SIP legs (with the same Call-ID it sees both BYE and should save both 200 OK after BYE so closing call after the 
	first 200 OK will not save the second 200 OK. So rather wait for 5 seconds for some more messages instead of closing the call. 
*/
						// destroy call after 5 seonds from now 
						call->destroy_call_at = header->ts.tv_sec + 5;
						return call;
					} else if(strncmp(cseq, call->invitecseq, cseqlen) == 0) {
						call->seeninviteok = true;
						if(!call->connect_time) {
							call->connect_time = header->ts.tv_sec;
						}
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Call answered\n");
					}
				}
			} else if(sip_method == RES18X) {
				if(call->progress_time == 0) {
					call->progress_time = header->ts.tv_sec;
				}
			}

			// if the call ends with some of SIP [456]XX response code, we can shorten timeout when the call will be closed 
			if( ((call->saddr == saddr && call->sport == source) || (call->saddr == daddr && call->sport == dest))
				&&
			    (sip_method == RES3XX || sip_method == RES4XX || sip_method == RES5XX || sip_method == RES6XX) && lastSIPresponseNum != 401 && lastSIPresponseNum != 407 ) {
					// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
					if(call->progress_time == 0) {
						call->progress_time = header->ts.tv_sec;
					}
					// save packet 
					if(!dontsave && opt_saveSIP) {
						save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
					}
					call->destroy_call_at = header->ts.tv_sec + 5;

					return call;
			}
		}

		if(opt_norecord_header) {
			s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l);
			if(l && l < 33) {
				// do 
				call->stoprecording();
			}
		}

		if(opt_norecord_dtmf) {
			s = gettag(data, datalen, "\nSignal:", &l);
			if(l && l < 33) {
				char *tmp = s + 1;
				tmp[l - 1] = '\0';
				if(call->dtmfflag == 0) {
					if(tmp[0] == '*') {
						// received ftmf '*', set flag so if next dtmf will be '0' stop recording
						call->dtmfflag = 1;
					}
				} else {
					if(tmp[0] == '0') {
						// we have complete *0 sequence
						call->stoprecording();
						call->dtmfflag = 0;
					} else {
						// reset flag because we did not received '0' after '*'
						call->dtmfflag = 0;
					}
				}
			}
		}
		
		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at += 5; 
		}

		// SDP examination
		s = gettag(data,datalen,"\nContent-Type:",&l);
		if(l <= 0 || l > 1023) {
			//try compact header
			s = gettag(data,datalen,"\nc:",&l);
		}
		if(s and l) {
			if(call->contenttype) free(call->contenttype);
			call->contenttype = (char*)malloc(sizeof(char) * (l + 1));
			memcpy(call->contenttype, s, l);
			call->contenttype[l] = '\0';
		}

		char a = data[datalen - 1];
		data[datalen - 1] = 0;
		char *tmp = strstr(data, "\r\n\r\n");;
		if(l > 0 && strncasecmp(s, "application/sdp", l) == 0 && tmp != NULL){
			// we have found SDP, add IP and port to the table
			in_addr_t tmp_addr;
			unsigned short tmp_port;
			int rtpmap[MAX_RTPMAP];
			memset(&rtpmap, 0, sizeof(int) * MAX_RTPMAP);
			int fax;
			if (!get_ip_port_from_sdp(tmp + 1, &tmp_addr, &tmp_port, &fax)){
				if(fax) { 
					if(verbosity >= 1){
						syslog(LOG_ERR, "[%s] T38 detected", call->fbasename);
					}
					call->isfax = 1;
					call->flags1 |= T38FAX;
				} else {
					if(call->isfax) {
						call->flags1 |= T38FAXRESET;
						call->isfax = 0;
					}
				}
				// if rtp-firstleg enabled add RTP only in case the SIP msg belongs to first leg
				if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
					((call->saddr == saddr && call->sport == source) || 
					(call->saddr == daddr && call->sport == dest))))
					{
					// prepare User-Agent
					s = gettag(data,datalen,"\nUser-Agent:", &l);
					// store RTP stream
					get_rtpmap_from_sdp(tmp + 1, datalen - (tmp + 1 - data), rtpmap);

					// determine if the SDP message is coming from caller or called 
					// 1) check by saddr
					int iscalled;
					if(call->sipcallerip == saddr) {
						// SDP message is coming from the first IP address seen in first INVITE thus incoming stream to ip/port in this 
						// SDP will be stream from called
						iscalled = 1;
					} else {
						// The IP address is different, check if the request matches one of the address from the first invite
						if(call->sipcallerip == daddr) {
							// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
							iscalled = 0;
						// src IP address of this SDP SIP message is different from the src/dst IP address used in the first INVITE. 
						} else {
							if(call->sipcallerip2 == 0) { 
								call->sipcallerip2 = saddr;
								call->sipcalledip2 = daddr;
							}
							if(call->sipcallerip2 == saddr) {
								iscalled = 1;
							} else {
								// The IP address is different, check if the request matches one of the address from the first invite
								if(call->sipcallerip2 == daddr) {
									// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
									iscalled = 0;
								// src IP address of this SDP SIP message is different from the src/dst IP address used in the first INVITE. 
								} else {
									if(call->sipcallerip3 == 0) { 
										call->sipcallerip3 = saddr;
										call->sipcalledip3 = daddr;
									}
									if(call->sipcallerip3 == saddr) {
										iscalled = 1;
									} else {
										// The IP address is different, check if the request matches one of the address from the first invite
										if(call->sipcallerip3 == daddr) {
											// SDP message is addressed to caller and announced IP/port in SDP will be from caller. Thus set called = 0;
											iscalled = 0;
										// src IP address of this SDP SIP message is different from the src/dst IP address used in the first INVITE. 
										} else {
											if(call->sipcallerip4 == 0) { 
												call->sipcallerip4 = saddr;
												call->sipcalledip4 = daddr;
											}
											if(call->sipcallerip4 == saddr) {
												iscalled = 1;
											} else {
												iscalled = 0;
											}
										}
									}
								}
							}
						}
					}
					if(call->add_ip_port(tmp_addr, tmp_port, s, l, iscalled, rtpmap) != -1){
						calltable->hashAdd(tmp_addr, tmp_port, call, iscalled, 0);
						//calltable->mapAdd(tmp_addr, tmp_port, call, iscalled, 0);
						if(opt_rtcp) {
							calltable->hashAdd(tmp_addr, tmp_port + 1, call, iscalled, 1); //add rtcp
							//calltable->mapAdd(tmp_addr, tmp_port + 1, call, iscalled, 1); //add rtcp
						}
					}
					
					// check if the IP address is listed in nat_aliases
					in_addr_t alias = 0;
					if((alias = match_nat_aliases(tmp_addr)) != 0) {
						if(call->add_ip_port(alias, tmp_port, s, l, iscalled, rtpmap) != -1) {
							calltable->hashAdd(alias, tmp_port, call, iscalled, 0);
							//calltable->mapAdd(alias, tmp_port, call, iscalled, 0);
							if(opt_rtcp) {
								calltable->hashAdd(alias, tmp_port + 1, call, iscalled, 1); //add rtcp
								//calltable->mapAdd(alias, tmp_port + 1, call, iscalled, 1); //add rtcp
							}
						}
					}

#ifdef NAT
					if(call->add_ip_port(saddr, tmp_port, s, l, iscalled, rtpmap) != -1){
						calltable->hashAdd(saddr, tmp_port, call, iscalled, 0);
						//calltable->mapAdd(saddr, tmp_port, call, iscalled, 0);
						if(opt_rtcp) {
							calltable->hashAdd(saddr, tmp_port + 1, call, iscalled, 1);
							//calltable->mapAdd(saddr, tmp_port + 1, call, iscalled, 1);
						}
					}
#endif
				}
			} else {
				if(verbosity >= 2){
					syslog(LOG_ERR, "Can't get ip/port from SDP:\n%s\n\n", tmp + 1);
				}
			}
		} else if(call->message == NULL && l > 0 && tmp != NULL) {
//				strncasecmp(s, "application/im-iscomposing+xml\r\n", l) == 0 || 
//				strncasecmp(s, "text/plain; charset=UTF-8\r\n", l) == 0)){
			//find end of a message (\r\n)
			tmp += 4; // skip \r\n\r\n and point to start of the message
			int contentlen = 0;
			s = gettag(data, datalen, "\nContent-Length:", &l);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				char c = s[l];
				s[l] = '\0';
				contentlen = atoi(s);
				s[l] = c;
			}
			char *end = strcasestr(tmp, "\n\nContent-Length:");
			if(!end) {
				end = strstr(tmp, "\r\n"); // strstr is safe becuse tmp ends with '\0'
				if(!end) {
					end = data + datalen;
				}
			}
			if(contentlen > 0) {
				//truncate message to its size announced in content-length
				if(end - tmp > contentlen) {
					end = tmp + MIN(end - tmp, contentlen);
				}
			}
			data[datalen - 1] = a;
			call->message = (char*)malloc(sizeof(char) * (end - tmp + 1));
			memcpy(call->message, tmp, end - tmp);
			call->message[end - tmp] = '\0';
			//printf("msg: contentlen[%d] datalen[%d] len[%d] [%s]\n", contentlen, datalen, strlen(call->message), call->message);
			data[datalen - 1] = '\0';
		}
		data[datalen - 1] = a;

		if(!dontsave && call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER)) {
			save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
		}

		return call;
	} else if ((call = calltable->hashfind_by_ip_port(daddr, dest, &iscaller, &is_rtcp))){
	//} else if ((call = calltable->mapfind_by_ip_port(daddr, dest, &iscaller, &is_rtcp))){
	// TODO: remove if hash will be stable
	//if ((call = calltable->find_by_ip_port(daddr, dest, &iscaller)))
		// packet (RTP) by destination:port is already part of some stored call 

		*voippacket = 1;

		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at += 5; 
		}

		if(header->caplen > MAXPACKETLENQRING) {
			// packets larger than MAXPACKETLENQRING was created in special heap and is destroyd immediately after leaving this functino - thus do not queue it 
			// TODO: this can be enhanced by pasing flag that the packet should be freed
			can_thread = 0;
		}

		if(is_rtcp) {
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, source, iscaller, is_rtcp);
			} else {
				call->read_rtcp((unsigned char*) data, datalen, header, saddr, source, iscaller);
			}
			if(!dontsave && (opt_saveRTP || opt_saveRTCP)) {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			}
			return call;
		}

		if(rtp_threaded && can_thread) {
			add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, source, iscaller, is_rtcp);
			*was_rtp = 1;
			if(is_rtcp) return call;
		} else {
			call->read_rtp((unsigned char*) data, datalen, header, saddr, source, iscaller);
			call->set_last_packet_time(header->ts.tv_sec);
		}
		if(!dontsave && ((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl))) {
			if(opt_onlyRTPheader && !call->isfax) {
				tmp_u32 = header->caplen;
				header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
				header->caplen = tmp_u32;
			} else {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			}

		}
	} else if ((call = calltable->hashfind_by_ip_port(saddr, source, &iscaller, &is_rtcp))){
	//} else if ((call = calltable->mapfind_by_ip_port(saddr, source, &iscaller, &is_rtcp))){
	// TODO: remove if hash will be stable
	// else if ((call = calltable->find_by_ip_port(saddr, source, &iscaller)))
		// packet (RTP[C]) by source:port is already part of some stored call 

		*voippacket = 1;

		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at += 5; 
		}

		if(header->caplen > MAXPACKETLENQRING) {
			// packets larger than MAXPACKETLENQRING was created in special heap and is destroyd immediately after leaving this functino - thus do not queue it 
			// TODO: this can be enhanced by pasing flag that the packet should be freed
			can_thread = 0;
		}

		if(is_rtcp) {
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, source, !iscaller, is_rtcp);
			} else {
				call->read_rtcp((unsigned char*) data, datalen, header, saddr, source, !iscaller);
			}
			if(!dontsave && (opt_saveRTP || opt_saveRTCP)) {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			}
			return call;
		}

		// as we are searching by source address and find some call, revert iscaller 
		if(rtp_threaded && can_thread) {
			add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, source, !iscaller, is_rtcp);
			*was_rtp = 1;
		} else {
			call->read_rtp((unsigned char*) data, datalen, header, saddr, source, !iscaller);
			call->set_last_packet_time(header->ts.tv_sec);
		}
		if(!dontsave && ((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl))) {
			if(opt_onlyRTPheader && !call->isfax) {
				tmp_u32 = header->caplen;
				header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
				header->caplen = tmp_u32;
			} else {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			}
		}
	// packet does not belongs to established call, check if it is on SIP port
	} else {
		if(opt_rtpnosip) {
			// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
			char s[256];
			RTP rtp;
			int rtpmap[MAX_RTPMAP];
			memset(&rtpmap, 0, sizeof(int) * MAX_RTPMAP);

			rtp.read((unsigned char*)data, datalen, header, saddr, 0);

			if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
				return NULL;
			}
			snprintf(s, 4092, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

			//printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

			call = calltable->add(s, strlen(s), header->ts.tv_sec, saddr, source);
			call->set_first_packet_time(header->ts.tv_sec);
			call->sipcallerip = saddr;
			call->sipcalledip = daddr;
			call->type = INVITE;
			ipfilter->add_call_flags(&(call->flags), ntohl(saddr), ntohl(daddr));
			strncpy(call->fbasename, s, MAX_FNAME - 1);
			call->seeninvite = true;
			strcpy(call->callername, "RTP");
			strcpy(call->caller, "RTP");
			strcpy(call->called, "RTP");

#ifdef DEBUG_INVITE
			syslog(LOG_NOTICE, "New RTP call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s]\n", call->sipcallerip, call->sipcalledip, call->caller, call->called);
#endif

			// opening dump file
			if((call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP | FLAG_SAVEWAV) || opt_savewav_force ) || (call->isfax && opt_saveudptl)) {
				mkdir_r(call->dirname().c_str(), 0777);
			}
			if((call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP)) || (call->isfax && opt_saveudptl)) {
				sprintf(str2, "%s/%s.pcap", call->dirname().c_str(), s);
				if(!file_exists(str2)) {
					call->set_f_pcap(pcap_dump_open(handle, str2));
					call->pcapfilename = call->dirname() + "/" + call->get_fbasename_safe() + ".pcap";
				} else {
					if(verbosity > 0) {
						syslog(LOG_NOTICE,"pcap_filename: [%s] already exists, do not overwriting\n", str2);
					}
				}
			}

			if(verbosity > 3) {
				syslog(LOG_NOTICE,"pcap_filename: [%s]\n",str2);
			}

			call->add_ip_port(daddr, dest, s, l, 1, rtpmap);
			//calltable->hashAdd(daddr, dest, call, 1, 0);
			calltable->mapAdd(daddr, dest, call, 1, 0);

			call->add_ip_port(saddr, source, s, l, 0, rtpmap);
			//calltable->hashAdd(saddr, source, call, 0, 0);
			calltable->mapAdd(saddr, source, call, 0, 0);
			
		}
		// we are not interested in this packet
		if (verbosity >= 6){
			char st1[16];
			char st2[16];
			struct in_addr in;

			in.s_addr = saddr;
			strcpy(st1, inet_ntoa(in));
			in.s_addr = daddr;
			strcpy(st2, inet_ntoa(in));
			syslog(LOG_ERR, "Skipping udp packet %s:%d->%s:%d\n", st1, source, st2, dest);
		}
		return NULL;
	}

	return NULL;
}

#ifdef HAS_NIDS
void
libnids_tcp_callback(struct tcp_stream *a_tcp, void **this_time_not_needed) {
	char buf[1024];
//	return;
//	strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
	if (a_tcp->nids_state == NIDS_JUST_EST) {
		// connection described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
		a_tcp->client.collect++; // we want data received by a client
		a_tcp->server.collect++; // and by a server, too
		a_tcp->server.collect_urg++; // we want urgent data received by a
		 // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
		a_tcp->client.collect_urg++; // if we don't increase this value,
				 // we won't be notified of urgent data
				 // arrival
#endif
		fprintf (stderr, "%s established\n", buf);
		return;
		}
	if (a_tcp->nids_state == NIDS_CLOSE) {
		// connection has been closed normally
		fprintf (stderr, "%s closing\n", buf);
		return;
	}
	if (a_tcp->nids_state == NIDS_RESET) {
		// connection has been closed by RST
		fprintf (stderr, "%s reset\n", buf);
		return;
	}
	if (a_tcp->nids_state == NIDS_DATA){
		//printf("[%d] [%d]\n", a_tcp->client.count_new, a_tcp->server.count_new);
		// new data has arrived; gotta determine in what direction
		// and if it's urgent or not

		struct half_stream *hlf;

		if (a_tcp->server.count_new_urg) {
			// new byte of urgent data has arrived
			strcat(buf,"(urgent->)");
			buf[strlen(buf)+1]=0;
			buf[strlen(buf)]=a_tcp->server.urgdata;
			write(1,buf,strlen(buf));
			return;
		}
		// We don't have to check if urgent data to client has arrived,
		// because we haven't increased a_tcp->client.collect_urg variable.
		// So, we have some normal data to take care of.
		if (a_tcp->client.count_new) {
			//printf("CLIENT !!! \n");
			// new data for the client
			hlf = &a_tcp->client; // from now on, we will deal with hlf var,
					// which will point to client side of conn
			strcat (buf, "(<-)"); // symbolic direction of data
		} else {
			//printf("SERVER !!! \n");
			hlf = &a_tcp->server; // analogical
			strcat (buf, "(->)");
		}
		fprintf(stderr,"%s",buf); // we print the connection parameters
						// (saddr, daddr, sport, dport) accompanied
						// by data flow direction (-> or <-)

		 write(2,hlf->data,hlf->count_new); // we print the newly arrived data

	}
	return;
}
#endif


#ifdef HAS_NIDS
void
libnids_udp_callback(struct tuple4 *addr, u_char *data, int len, struct ip *pkt) {
	int was_rtp;
	int voippacket;
	process_packet(addr->saddr, addr->source, addr->daddr, addr->dest, (char*)data, len, handle, nids_last_pcap_header, nids_last_pcap_data, 0, 0, 1, &was_rtp, NULL, &voippacket);
	return;
}

void readdump_libnids(pcap_t *handle) {
	struct pcap_pkthdr *header;	// The header that pcap gives us
	const u_char *packet = NULL;		// The actual packet 
	static struct nids_chksum_ctl ctl;
	int res;

	nids_params.pcap_desc = handle;
	if (!nids_init ()) {
	    fprintf (stderr, "%s\n", nids_errbuf);
	    exit (1);
	}

	/* turn off TCP checksums */
	ctl.netaddr = inet_addr("0.0.0.0");
	ctl.mask = inet_addr("0.0.0.0");
	ctl.action = NIDS_DONT_CHKSUM;
	nids_register_chksum_ctl(&ctl, 1);

	/* register tcp and udp handlers */
//	nids_register_tcp((void*)libnids_tcp_callback);
	nids_register_udp((void*)libnids_udp_callback);

	/* read packets from libpcap in a loop */
	while (!terminating) {
		res = pcap_next_ex(handle, &header, &packet);

		if(!packet and res != -2) {
			if(verbosity > 2) {
				syslog(LOG_NOTICE,"NULL PACKET, pcap response is %d",res);
			}
			continue;
		}

		if(res == -1) {
			// error returned, sometimes it returs error 
			if(verbosity > 2) {
				syslog(LOG_NOTICE,"Error reading packets\n");
			}
			continue;
		} else if(res == -2) {
			//packets are being read from a ``savefile'', and there are no more packets to read from the savefile.
			if(opt_scanpcapdir[0] == '\0') {
				syslog(LOG_NOTICE,"End of pcap file, exiting\n");
			}
			break;
		} else if(res == 0) {
			//continue on timeout when reading live packets
			continue;
		}
		nids_pcap_handler(NULL, header, (u_char*)packet);
	}
}
#endif

void *pcap_read_thread_func(void *arg) {
	pcap_packet *pp;
	struct iphdr *header_ip;
	struct udphdr2 *header_udp;
	struct udphdr2 header_udp_tmp;
	struct tcphdr *header_tcp;
	char *data;
	int datalen;
	int istcp = 0;
	int res;
	int was_rtp;
	unsigned int packets = 0;

	res = 0;

	while(1) {

#ifdef QUEUE_MUTEX
		res = sem_wait(&readpacket_thread_semaphore);
		if(res != 0) {
			printf("Error pcap_read_thread_func sem_wait returns != 0\n");
		}

		pthread_mutex_lock(&readpacket_thread_queue_lock);
		pp = readpacket_thread_queue.front();
		readpacket_thread_queue.pop();
		pthread_mutex_unlock(&readpacket_thread_queue_lock);
#endif

#ifdef QUEUE_NONBLOCK
		if((res = queue_dequeue(qs_readpacket_thread_queue, (void **)&pp)) != 1) {
			// queue is empty
			if(terminating || readend) {
				printf("packets: [%u]\n", packets);
				return NULL;
			}
			usleep(10000);
			continue;
		};
#endif

#ifdef QUEUE_NONBLOCK2
		if(qring[readit % qringmax].free == 1) {
			// no packet to read 
			if(terminating || readend) {
				//printf("packets: [%u]\n", packets);
				return NULL;
			}
			usleep(10000);
			continue;
		} else {
			pp = &(qring[readit % qringmax]);
		}
#endif
		packets++;

		int destroypp = 0;
		u_char *packet = pp->packet2 ? pp->packet2 : pp->packet;
		if(pp->packet2) {
			destroypp = 1;
		}

		header_ip = (struct iphdr *) ((char*)packet + pp->offset);

		if(opt_ipaccount) {
			ipaccount(pp->header.ts.tv_sec, (struct iphdr *) ((char*)(packet) + pp->offset), pp->header.caplen - pp->offset, 0);
		}

		if(header_ip->protocol == 4) {
			// ip in ip protocol
			header_ip = (struct iphdr *) ((char*)header_ip + sizeof(iphdr));
		}
		header_udp = &header_udp_tmp;
		if (header_ip->protocol == IPPROTO_UDP) {
			// prepare packet pointers 
			header_udp = (struct udphdr2 *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_udp + sizeof(*header_udp);
			datalen = (int)(pp->header.caplen - ((char*)data - (char*)packet)); 
			istcp = 0;
		} else if (header_ip->protocol == IPPROTO_TCP) {
			istcp = 1;
			// prepare packet pointers 
			header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_tcp + (header_tcp->doff * 4);
			datalen = (int)(pp->header.caplen - ((char*)data - (char*)packet)); 

			header_udp->source = header_tcp->source;
			header_udp->dest = header_tcp->dest;
		} else {
			//packet is not UDP and is not TCP, we are not interested, go to the next packet
#ifdef QUEUE_NONBLOCK2
			if(destroypp) {
				free(pp->packet2);
				pp->packet2 = NULL;
			}
			qring[readit % qringmax].free = 1;
			if((readit + 1) == qringmax) {
				readit = 0;
			} else {
				readit++;
			}
#endif
			continue;
		}

		if(opt_mirrorip && (sipportmatrix[htons(header_udp->source)] || sipportmatrix[htons(header_udp->dest)])) {
			mirrorip->send((char *)header_ip, (int)(pp->header.caplen - ((char*)header_ip - (char*)packet)));
		}
		int voippacket = 0;
		process_packet(header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
			    data, datalen, handle, &pp->header, packet, istcp, 0, 1, &was_rtp, header_ip, &voippacket);

		// if packet was VoIP add it to ipaccount
		if(voippacket && opt_ipaccount) {
			ipaccount(pp->header.ts.tv_sec, (struct iphdr *) ((char*)(packet) + pp->offset), pp->header.caplen - pp->offset, voippacket);
		}

#ifdef QUEUE_NONBLOCK2
		if(destroypp) {
			free(pp->packet2);
			pp->packet2 = NULL;
		}
		qring[readit % qringmax].free = 1;
		if((readit + 1) == qringmax) {
			readit = 0;
		} else {
			readit++;
		}
#endif

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
		free(pp->packet);
		free(pp);
#endif
	}
	//printf("packets: [%u]\n", packets);

	return NULL;
}

/*

defragment packets from queue and allocates memory for new header and packet which is returned 
in **header an **packet 

*/
inline int ipfrag_dequeue(ip_frag_queue_t *queue, struct pcap_pkthdr **header, u_char **packet) {
	//walk queue

	if(!queue) return 1;
	if(!queue->size()) return 1;


	// prepare newpacket structure and header structure
	u_int32_t totallen = queue->begin()->second->totallen + queue->begin()->second->firstheaderlen;
	u_char *newpacket = (u_char *)malloc(totallen);
	*packet = newpacket;
	struct pcap_pkthdr *newheader = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr)); // copy header
	memcpy(newheader, *header, sizeof(struct pcap_pkthdr));
	newheader->len = newheader->caplen = totallen;
	*header = newheader;

	int lastoffset = queue->begin()->second->offset;
	int i = 0;
	unsigned int len = 0;
	for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
		ip_frag_t *node = it->second;
		if(i == 0) {
			// for first packet copy ethernet header and ip header
			if(node->firstheaderlen) {
				memcpy(newpacket, node->firstheader, node->firstheaderlen);
				len += node->firstheaderlen;
			}
			memcpy(newpacket + len, node->packet, node->len);
			len += node->len;
		} else {
			// for rest of a packets append only data 
			if(len > totallen) {
				syslog(LOG_ERR, "%s.%d: Error - bug in voipmonitor len[%d] > totallen[%d]", __FILE__, __LINE__, len, totallen);
				abort();
			}
			memcpy(newpacket + len, node->packet + sizeof(iphdr), node->len - sizeof(iphdr));
			len += node->len - sizeof(iphdr);
		}
		lastoffset = node->offset;
		free(node->packet);
		if(node->firstheader) {
			free(node->firstheader);
		}
		free(node);
		i++;
	}
	return 1;
}


int ipfrag_add(ip_frag_queue_t *queue, struct pcap_pkthdr *header, const u_char *packet, unsigned int len, struct pcap_pkthdr **origheader, u_char **origpacket) {

	unsigned int offset = ntohs(((iphdr*)(packet))->frag_off);
	unsigned int offset_d = (offset & IP_OFFSET) << 3;
	u_int8_t is_last = 0;

	if (((offset & IP_MF) == 0) && ((offset & IP_OFFSET) != 0)) {
		// this packet do not set more fragment indicator but contains offset which means that it is the last packet
		is_last = 1;
		if(queue->size()) {
			// packet is not first - set has_last flag to first node for later use which indicates that the stream has the last packet
			queue->begin()->second->has_last = 1;
		}
	}

	if(!queue->count(offset_d)) {
		// this offset number is not yet in the queue - add packet to queue which automatically sort it into right position

		// create node
		ip_frag_t *node = (ip_frag_t*)malloc(sizeof(ip_frag_t));

		if(queue->size()) {
			// update totallen for the first node 
			ip_frag_t *first = queue->begin()->second;
			first->totallen += len - sizeof(iphdr); 
			node->totallen = first->totallen;
			node->has_last = first->has_last;
		} else {
			// queue is empty
			node->totallen = len;
			node->has_last = is_last;
		}

		node->ts = header->ts.tv_sec;
		node->next = NULL; //TODO: remove, we are using c++ map
		// copy header and set length
		memcpy(&(node->header), header, sizeof(struct pcap_pkthdr));
		node->header.len = len;
		node->header.caplen = len;
		node->len = len;
		// copy packet
		node->packet = (u_char*)malloc(sizeof(u_char) * len);
		memcpy(node->packet, packet, len);
		node->offset = offset_d;

		// if it is first packet, copy first header at the beginning (which is typically ethernet header)
		if((offset & IP_OFFSET) == 0) {
			node->firstheaderlen = (char*)packet - (char*)(*origpacket);
			node->firstheader = (char*)malloc(node->firstheaderlen);
			memcpy(node->firstheader, *origpacket, node->firstheaderlen);
		} else {
			node->firstheader = NULL;
			node->firstheaderlen = 0;
		}
	
		// add to queue (which will sort it automatically
		(*queue)[offset_d] = node;
	} else {
		// node with that offset already exists - discard
		return 0;
	}

	// now check if packets in queue are complete - if yes - defragment - if not, do nithing
	int ok = true;
	unsigned int lastoffset = 0;
	if(queue->begin()->second->has_last and queue->begin()->second->offset == 0) {
		// queue has first and last packet - check if there are all middle fragments
		for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
			ip_frag_t *node = it->second;
			if((node->offset != lastoffset)) {
				ok = false;
				break;
			}
			lastoffset += node->len - sizeof(iphdr);
		}
	} else {
		// queue does not contain a last packet and does not contain a first packet
		ok = false;
	}

	if(ok) {
		// all packets -> defragment 
		ipfrag_dequeue(queue, origheader, origpacket);
		return 1;
	} else {
		return 0;
	}
}

/* 

function inserts packet into fragmentation queue and if all packets within fragmented IP are 
complete it will dequeue and construct large packet from all fragmented packets. 

return: if packet is defragmented from all pieces function returns 1 and set header and packet 
pinters to new allocated data which has to be freed later. If packet is only queued function
returns 0 and header and packet remains same

*/
int handle_defrag(iphdr *header_ip, struct pcap_pkthdr **header, u_char **packet, int destroy) {
	struct pcap_pkthdr *tmpheader = *header;
	u_char *tmppacket = *packet;

	// get queue from ip_frag_stream based on source ip address and ip->id identificator (2-dimensional map array)
	ip_frag_queue_t *queue = ip_frag_stream[header_ip->saddr][header_ip->id];
	if(!queue) {
		// queue does not exists yet - create it and assign to map 
		queue = new ip_frag_queue_t;
		ip_frag_stream[header_ip->saddr][header_ip->id] = queue;
	}
	int res = ipfrag_add(queue, *header, (u_char*)header_ip, ntohs(header_ip->tot_len), header, packet);
	if(res) {
		// packet was created from all pieces - delete queue and remove it from map
		ip_frag_stream[header_ip->saddr].erase(header_ip->id);
		delete queue;
	};
	if(destroy) {
		// defrag was called with destroy=1 delete original packet and header which was replaced by new defragmented packet
		free(tmpheader);
		free(tmppacket);
	}
	return res;
}

void ipfrag_prune(unsigned int tv_sec, int all) {
	ip_frag_queue_t *queue;
	for (ip_frag_streamIT = ip_frag_stream.begin(); ip_frag_streamIT != ip_frag_stream.end(); ip_frag_streamIT++) {
		for (ip_frag_streamITinner = (*ip_frag_streamIT).second.begin(); ip_frag_streamITinner != (*ip_frag_streamIT).second.end();) {
			queue = ip_frag_streamITinner->second;
			if(!queue->size()) {
				ip_frag_streamIT->second.erase(ip_frag_streamITinner++);
				delete queue;
				continue;
			}
			if(all or ((tv_sec - queue->begin()->second->ts) > (30))) {
				for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
					ip_frag_t *node = it->second;
					
					free(node->packet);
					if(node->firstheader) {
						free(node->firstheader);
					}
					free(node);
				}
				ip_frag_streamIT->second.erase(ip_frag_streamITinner++);
				delete queue;
				continue;
			}
			ip_frag_streamITinner++;
		}
	}
}

void readdump_libpcap(pcap_t *handle) {
	struct pcap_pkthdr *headerpcap;	// The header that pcap gives us
	pcap_pkthdr *header;	// The header that pcap gives us
	const u_char *packetpcap = NULL;		// The actual packet 
	u_char *packet = NULL;		// The actual packet 
	struct ether_header *header_eth;
	struct sll_header *header_sll;
	struct iphdr *header_ip;
	struct udphdr2 *header_udp;
	struct udphdr2 header_udp_tmp;
	struct tcphdr *header_tcp;
	char *data = NULL;
	int datalen = 0;
	int res;
	int protocol = 0;
	unsigned int offset;
	int istcp = 0;
	int was_rtp;
	unsigned char md5[32];
	unsigned char prevmd5[32];
	int destroy = 0;
	unsigned int ipfrag_lastprune = 0;

	pcap_dlink = pcap_datalink(handle);

	MD5_CTX ctx;

	init_hash();
	memset(tcp_streams_hashed, 0, sizeof(tcp_stream2_t*) * MAX_TCPSTREAMS);


	pcap_dumper_t *tmppcap = NULL;
	char pname[1024];

	if(opt_pcapdump) {
		sprintf(pname, "/var/spool/voipmonitor/voipmonitordump-%u.pcap", (unsigned int)time(NULL));
		tmppcap = pcap_dump_open(handle, pname);
	}

	while (!terminating) {
		destroy = 0;
		res = pcap_next_ex(handle, &headerpcap, &packetpcap);
		packet = (u_char *)packetpcap;
		header = headerpcap;

		if(!packet and res != -2) {
			if(verbosity > 2) {
				syslog(LOG_NOTICE,"NULL PACKET, pcap response is %d",res);
			}
			continue;
		}

		if(res == -1) {
			// error returned, sometimes it returs error 
			if(verbosity > 2) {
				syslog(LOG_NOTICE,"Error reading packets\n");
			}
			continue;
		} else if(res == -2) {
			//packets are being read from a ``savefile'', and there are no more packets to read from the savefile.
			syslog(LOG_NOTICE,"End of pcap file, exiting\n");
			break;
		} else if(res == 0) {
			//continue on timeout when reading live packets
			continue;
		}

		// check, if ipfilter should be reloaded. Reloading is done in this section to avoid mutex locking around ipfilter structure
		if(ipfilter_reload_do) {
			delete ipfilter;
			ipfilter = ipfilter_reload;
			ipfilter_reload = NULL;
			ipfilter_reload_do = 0; 
		}

		if(telnumfilter_reload_do) {
			delete telnumfilter;
			telnumfilter = telnumfilter_reload;
			telnumfilter_reload = NULL;
			telnumfilter_reload_do = 0; 
		}

		numpackets++;	

		switch(pcap_dlink) {
			case DLT_LINUX_SLL:
				header_sll = (struct sll_header *) (char*)packet;
				protocol = header_sll->sll_protocol;
				if(header_sll->sll_protocol == 129) {
					// VLAN tag
					protocol = *(short *)((char*)packet + 16 + 2);
					offset = 4;
				} else {
					offset = 0;
					protocol = header_sll->sll_protocol;
				}
				offset += sizeof(struct sll_header);
				break;
			case DLT_EN10MB:
				header_eth = (struct ether_header *) (char*)(packet);
				if(header_eth->ether_type == 129) {
					// VLAN tag
					offset = 4;
					//XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
					protocol = *(packet + sizeof(struct ether_header) + 2);
				} else {
					offset = 0;
					protocol = header_eth->ether_type;
				}
				offset += sizeof(struct ether_header);
				break;
			case DLT_RAW:
				offset = 0;
				protocol = 8;
				break;
			default:
				syslog(LOG_ERR, "This datalink number [%d] is not supported yet. For more information write to support@voipmonitor.org\n", pcap_dlink);
				continue;
		}

		if(protocol != 8) {
			// not ipv4 
			continue;
		}

		header_ip = (struct iphdr *) ((char*)packet + offset);

		//if UDP defrag is enabled process only UDP packets and only SIP packets
		if(opt_udpfrag and (header_ip->protocol == IPPROTO_UDP or header_ip->protocol == 4)) {
			int foffset = ntohs(header_ip->frag_off);
			if ((foffset & IP_MF) or ((foffset & IP_OFFSET) > 0)) {
				// packet is fragmented
				if(handle_defrag(header_ip, &header, &packet, 0)) {
					// packets are reassembled
					header_ip = (struct iphdr *)((char*)packet + offset);
					//header_ip = (struct iphdr *)((char*)packet);
					//header_ip = (struct iphdr *)packet;
					destroy = true;
				} else {
					continue;
				}
			}
		}

		if(header_ip->protocol == 4) {
			header_ip = (struct iphdr *) ((char*)header_ip + sizeof(iphdr));

			//if UDP defrag is enabled process only UDP packets and only SIP packets
			if(opt_udpfrag and header_ip->protocol == IPPROTO_UDP) {
				int foffset = ntohs(header_ip->frag_off);
				if ((foffset & IP_MF) or ((foffset & IP_OFFSET) > 0)) {
					// packet is fragmented
					if(handle_defrag(header_ip, &header, &packet, destroy)) {
						// packet was returned
						header_ip = (struct iphdr *)((char*)packet + offset);
						header_ip->frag_off = 0;
						//header_ip = (struct iphdr *)((char*)packet);
						header_ip = (struct iphdr *) ((char*)header_ip + sizeof(iphdr));
						header_ip->frag_off = 0;
						//exit(0);
						destroy = true;
					} else {
						continue;
					}
				}
			}

		}

		// if IP defrag is enabled, run each 10 seconds cleaning 
		if(opt_udpfrag and (ipfrag_lastprune + 10) < header->ts.tv_sec) {
			ipfrag_prune(header->ts.tv_sec, 0);
			ipfrag_lastprune = header->ts.tv_sec;
			//TODO it would be good to still pass fragmented packets even it does not contain the last semant, the ipgrad_prune just wipes all unfinished frags
		}

		header_udp = &header_udp_tmp;
		if (header_ip->protocol == IPPROTO_UDP) {
			// prepare packet pointers 
			header_udp = (struct udphdr2 *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_udp + sizeof(*header_udp);
			datalen = (int)(header->caplen - ((unsigned long) data - (unsigned long) packet)); 
			istcp = 0;
		} else if (header_ip->protocol == IPPROTO_TCP) {
			istcp = 1;
			// prepare packet pointers 
			header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_tcp + (header_tcp->doff * 4);
			datalen = (int)(header->caplen - ((unsigned long) data - (unsigned long) packet)); 
			//if (datalen == 0 || !(sipportmatrix[htons(header_tcp->source)] || sipportmatrix[htons(header_tcp->dest)])) {
			if (!(sipportmatrix[htons(header_tcp->source)] || sipportmatrix[htons(header_tcp->dest)])) {
				// not interested in TCP packet other than SIP port
				if(opt_ipaccount == 0) {
					if(destroy) { 
						free(header); 
						free(packet);
					}
					continue;
				}
			}
#if 0
			char tmp = data[datalen-1];
			data[datalen-1] = '\0';
			printf("tcp packet datalen[%d] [%s]!!!\n", datalen, data);
			data[datalen-1] = tmp;
#endif

			header_udp->source = header_tcp->source;
			header_udp->dest = header_tcp->dest;
		} else {
			//packet is not UDP and is not TCP, we are not interested, go to the next packet (but if ipaccount is enabled, do not skip IP
			if(opt_ipaccount == 0) {
				if(destroy) { free(header); free(packet);};
				continue;
			}
		}
	
		if(datalen < 0) {
			if(destroy) { free(header); free(packet);};
			continue;
		}

		if(opt_pcapdump) {
			pcap_dump((u_char *)tmppcap, header, packet);
		}

		/* check for duplicate packets (md5 is expensive operation - enable only if you really need it */
		if(datalen > 0 and opt_dup_check) {
			MD5_Init(&ctx);
			MD5_Update(&ctx, data, (unsigned long)datalen);
			MD5_Final(md5, &ctx);
			if(memmem(md5, 32, prevmd5, 32)) {
				if(destroy) { free(header); free(packet);};
				continue;
				//printf("md5[%s]\n", md5);
			}
			memcpy(prevmd5, md5, 32);
		}

		if(opt_pcap_threaded) {
			//add packet to queue
#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
			pcap_packet *pp = (pcap_packet*)malloc(sizeof(pcap_packet));
			pp->packet = (u_char*)malloc(sizeof(u_char) * header->caplen);
			pp->offset = offset;
			memcpy(&pp->header, header, sizeof(struct pcap_pkthdr));
			memcpy(pp->packet, packet, header->caplen);
#endif

#ifdef QUEUE_NONBLOCK2
			while(qring[writeit % qringmax].free == 0) {
				// no room left, loop until there is room
				usleep(100);
			}
			if(header->caplen > MAXPACKETLENQRING) {
				//allocate special structure 
				//syslog(LOG_ERR, "error: packet is to large [%d]b for QRING[%d]b", header->caplen, MAXPACKETLENQRING);
				qring[writeit % qringmax].packet2 = (u_char*)malloc(header->caplen * sizeof(u_char));
				memcpy(qring[writeit % qringmax].packet2, packet, header->caplen);
			} else {
				qring[writeit % qringmax].packet2 = NULL;
				memcpy(&qring[writeit % qringmax].packet, packet, header->caplen);
			}
			memcpy(&qring[writeit % qringmax].header, header, sizeof(struct pcap_pkthdr));
			qring[writeit % qringmax].offset = offset;
			qring[writeit % qringmax].free = 0;
			if((writeit + 1) == qringmax) {
				writeit = 0;
			} else {
				writeit++;
			}
#endif

			if(header->caplen > header->caplen) {
				syslog(LOG_ERR, "error: header->caplen > header->caplen FIX!");
			}

#ifdef QUEUE_MUTEX
			pthread_mutex_lock(&readpacket_thread_queue_lock);
			readpacket_thread_queue.push(pp);
			pthread_mutex_unlock(&readpacket_thread_queue_lock);
#endif

#ifdef QUEUE_NONBLOCK
			if(queue_enqueue(qs_readpacket_thread_queue, (void*)pp) == 0) {
				// enqueue failed, try to raise queue
				if(queue_guaranteed_enqueue(qs_readpacket_thread_queue, (void*)pp) == 0) {
					syslog(LOG_ERR, "error: readpacket_queue cannot allocate memory");
				}
			}
#endif 

			//sem_post(&readpacket_thread_semaphore);
			if(destroy) { free(header); free(packet);};
			continue;
		}

		if(opt_mirrorall || (opt_mirrorip && (sipportmatrix[htons(header_udp->source)] || sipportmatrix[htons(header_udp->dest)]))) {
			mirrorip->send((char *)header_ip, (int)(header->caplen - ((unsigned long) header_ip - (unsigned long) packet)));
		}
		if(opt_ipaccount) {
			ipaccount(header->ts.tv_sec, (struct iphdr *) ((char*)packet + offset), header->caplen - offset, 0);
		}
		int voippacket;
		if(!opt_mirroronly) {
			process_packet(header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
				    data, datalen, handle, header, packet, istcp, 0, 1, &was_rtp, header_ip, &voippacket);
		}
		if(voippacket && opt_ipaccount) {
			ipaccount(header->ts.tv_sec, (struct iphdr *) ((char*)packet + offset), header->caplen - offset, voippacket);
		}

		if(destroy) { 
			free(header); 
			free(packet);
		}
	}

	if(opt_pcapdump) {
		pcap_dump_close(tmppcap);
	}
}
