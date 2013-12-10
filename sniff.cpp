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
#include <sys/stat.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include "voipmonitor.h"

#ifdef FREEBSD
#include <machine/endian.h>
#else
#include <malloc.h>
#include <endian.h>
#endif

#include <sys/times.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netinet/tcp.h>
#include <syslog.h>
#include <semaphore.h>

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
#include "rtp.h"
#include "skinny.h"
#include "tcpreassembly.h"
#include "ip_frag.h"

extern MirrorIP *mirrorip;

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK) 
extern "C" {
#include "liblfds.6/inc/liblfds.h"
}
#endif

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

unsigned int duplicate_counter = 0;
extern struct pcap_stat pcapstat;
int pcapstatresCount = 0;

Calltable *calltable;
extern volatile int calls;
extern int opt_pcap_queue;
extern int opt_saveSIP;	  	// save SIP packets to pcap file?
extern int opt_saveRTP;	 	// save RTP packets to pcap file?
extern int opt_saveRTCP;	// save RTCP packets to pcap file?
extern int opt_saveRAW;	 	
extern int opt_saveWAV;	 	
extern int opt_saveGRAPH;	 	
extern int opt_packetbuffered;	  // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_rtcp;		  // Make .pcap files writing ‘‘packet-buffered’’
extern int verbosity;
extern int verbosityE;
extern int terminating;
extern int opt_rtp_firstleg;
extern int opt_sip_register;
extern int opt_norecord_header;
extern int opt_enable_tcpreassembly;
extern int opt_convert_dlt_sll_to_en10;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern pcap_t *handle;
extern pcap_t *handle_dead_EN10MB;
extern read_thread *threads;
extern int opt_norecord_dtmf;
extern int opt_onlyRTPheader;
extern int opt_sipoverlap;
extern int readend;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern char opt_match_header[128];
extern int opt_domainport;
extern int opt_mirrorip;
extern int opt_mirrorall;
extern int opt_mirroronly;
extern char opt_scanpcapdir[2048];
extern int opt_ipaccount;
extern int opt_cdrproxy;
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
int pcap_dlink;
extern int opt_udpfrag;
extern int global_livesniffer;
extern int global_livesniffer_all;
extern int opt_pcap_split;
extern int opt_newdir;
extern int opt_callslimit;
extern int opt_skiprtpdata;
extern char opt_silencedmtfseq[16];
extern int opt_skinny;
extern int opt_read_from_file;
extern int opt_saverfc2833;
extern vector<dstring> opt_custom_headers_cdr;
extern vector<dstring> opt_custom_headers_message;
extern livesnifferfilter_use_siptypes_s livesnifferfilterUseSipTypes;
extern int opt_skipdefault;
extern TcpReassembly *tcpReassembly;
extern char ifname[1024];
extern uint8_t opt_sdp_reverse_ipport;

#ifdef QUEUE_MUTEX
extern sem_t readpacket_thread_semaphore;
#endif

static char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen, unsigned long *limitLen = NULL);
static void logPacketSipMethodCall(int sip_method, int lastSIPresponseNum, pcap_pkthdr *header, Call *call, const char *descr = NULL);
#define logPacketSipMethodCall_enable ((opt_read_from_file && verbosity > 2) || verbosityE > 1)

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
	string call_id;
	int lastpsh;
} tcp_stream2_t;

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
ipfrag_data_s ipfrag_data;

extern struct queue_state *qs_readpacket_thread_queue;

map<unsigned int, livesnifferfilter_t*> usersniffer;

#define ENABLE_CONVERT_DLT_SLL_TO_EN10	(pcap_dlink ==DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 && handle_dead_EN10MB)
#define HANDLE_FOR_PCAP_SAVE 		(ENABLE_CONVERT_DLT_SLL_TO_EN10 ? handle_dead_EN10MB : handle)

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
	pcaphdr.network = ENABLE_CONVERT_DLT_SLL_TO_EN10 ? DLT_EN10MB : pcap_dlink;

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

	//construct description and call-id
	char description[1024] = "";
	char callidstr[1024] = "";
	if(datalen) {
		void *memptr = memmem(data, datalen, "\r\n", 2);
		if(memptr) {
			memcpy(description, data, (char *)memptr - (char*)data);
			description[(char*)memptr - (char*)data] = '\0';
		} else {
			strcpy(description, "error in description\n");
		}
		if(!call) {
			unsigned long l;
			char *s = gettag(data, datalen, "\nCall-ID:", &l);
			if(l > 0 && l < 1024) {
				memcpy(callidstr, s, MIN(l, 1024));
				callidstr[MIN(l, 1023)] = '\0';
			}
		}
	}

	// construct query and push it to mysqlquery queue
	int id_sensor = opt_id_sensor > 0 ? opt_id_sensor : 0;
	query << "INSERT INTO livepacket_" << uid << 
		" SET sipcallerip = '" << saddr << 
		"', sipcalledip = '" << daddr << 
		"', id_sensor = " << id_sensor << 
		", sport = " << source << 
		", dport = " << dest << 
		", istcp = " << istcp << 
		", created_at = " << sqlEscapeStringBorder(sqlDateTimeString(header->ts.tv_sec).c_str()) << 
		", microseconds = " << header->ts.tv_usec << 
		", callid = " << sqlEscapeStringBorder(call ? call->call_id : callidstr) << 
		", description = " << sqlEscapeStringBorder(description) << 
		", data = '#" << sqlEscapeString(mpacket, len) << "#'";
	pthread_mutex_lock(&mysqlquery_lock);
	mysqlquery.push(query.str());
	pthread_mutex_unlock(&mysqlquery_lock);
	return;
}


/* 
	stores SIP messags to sql.livepacket based on user filters
*/

int get_sip_peername(char *data, int data_len, const char *tag, char *peername, unsigned int peername_len);

inline void save_live_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, unsigned int saddr, int source, unsigned int daddr, int dest, int istcp, char *data, int datalen, unsigned char sip_type) {
	if(!global_livesniffer && !global_livesniffer_all) {
		return;
	}
	
	// check saddr and daddr filters
	daddr = htonl(daddr);
	saddr = htonl(saddr);

	if(global_livesniffer_all) {
		save_packet_sql(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, 0);
		return;
	}

	/*
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
			if(call and filter->lv_srcnum[i][0] != '\0' and memmem(call->caller, strlen(call->caller), filter->lv_srcnum[i], strlen(filter->lv_srcnum[i]))) goto save;
			if(call and filter->lv_dstnum[i][0] != '\0' and memmem(call->caller, strlen(call->caller), filter->lv_dstnum[i], strlen(filter->lv_dstnum[i]))) goto save;
			if(call and filter->lv_bothnum[i][0] != '\0' and (
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
	*/
	
	map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT;
	
	char caller[1024] = "", called[1024] = "";
	if(call) {
		strncpy(caller, call->caller, sizeof(caller));
		caller[sizeof(caller) - 1] = 0;
		strncpy(called, call->called, sizeof(called));
		called[sizeof(called) - 1] = 0;
	} else {
		bool needcaller = false;
		bool needcalled = false;
		for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); usersnifferIT++) {
			if(!usersnifferIT->second->state.all_all && !usersnifferIT->second->state.all_num) {
				for(int i = 0; i < MAXLIVEFILTERS; i++) {
					if(!usersnifferIT->second->state.all_srcnum && usersnifferIT->second->lv_srcnum[i][0]) {
						needcaller = true;
					}
					if(!usersnifferIT->second->state.all_dstnum && usersnifferIT->second->lv_dstnum[i][0]) {
						needcalled = true;
					}
					if(!usersnifferIT->second->state.all_bothnum && usersnifferIT->second->lv_bothnum[i][0]) {
						needcaller = true;
						needcalled = true;
					}
				}
			}
		}
		int res;
		if(needcaller) {
			res = get_sip_peername(data,datalen,"\nFrom:", caller, sizeof(caller));
			if(res) {
				// try compact header
				get_sip_peername(data,datalen,"\nf:", caller, sizeof(caller));
			}
		}
		if(needcalled) {
			res = get_sip_peername(data,datalen,"\nTo:", called, sizeof(called));
			if(res) {
				// try compact header
				get_sip_peername(data,datalen,"\nt:", called, sizeof(called));
			}
		}
	}
	
	for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); usersnifferIT++) {
		livesnifferfilter_t *filter = usersnifferIT->second;
		bool save = filter->state.all_all;
		for(int i = 0; i < MAXLIVEFILTERS && !save; i++) {
			bool okAddr = 
				filter->state.all_addr ||
				((filter->state.all_saddr || (filter->lv_saddr[i] && 
					saddr == filter->lv_saddr[i])) &&
				 (filter->state.all_daddr || (filter->lv_daddr[i] && 
					daddr == filter->lv_daddr[i])) &&
				 (filter->state.all_bothaddr || (filter->lv_bothaddr[i] && 
					(saddr == filter->lv_bothaddr[i] || 
					 daddr == filter->lv_bothaddr[i]))));
			bool okNum = 
				filter->state.all_num ||
				((filter->state.all_srcnum || (filter->lv_srcnum[i][0] && 
					memmem(caller, strlen(caller), filter->lv_srcnum[i], strlen(filter->lv_srcnum[i])))) &&
				 (filter->state.all_dstnum || (filter->lv_dstnum[i][0] && 
					memmem(called, strlen(called), filter->lv_dstnum[i], strlen(filter->lv_dstnum[i])))) &&
				 (filter->state.all_bothnum || (filter->lv_bothnum[i][0] && 
					(memmem(caller, strlen(caller), filter->lv_bothnum[i], strlen(filter->lv_bothnum[i])) ||
					 memmem(called, strlen(called), filter->lv_bothnum[i], strlen(filter->lv_bothnum[i]))))));
			bool okSipType =
				filter->state.all_siptypes ||
				filter->lv_siptypes[i] == sip_type;
			if(okAddr && okNum && okSipType) {
				save = true;
			}
		}
		if(save) {
			save_packet_sql(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, usersnifferIT->first);
		}
	}
}

/*
   save packet into file 
   type - 1 is SIP, 2 is RTP, 3 is RTCP

*/
inline void save_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, unsigned int saddr, int source, unsigned int daddr, int dest, int istcp, char *data, int datalen, int type) {
	bool allocPacket = false;
	if(ENABLE_CONVERT_DLT_SLL_TO_EN10) {
		const u_char *packet_orig = packet;
		pcap_pkthdr *header_orig = header;
		packet = (const u_char*) new u_char[header_orig->caplen];
		memcpy((u_char*)packet, (u_char*)packet_orig, 14);
		memset((u_char*)packet, 0, 6);
		((ether_header*)packet)->ether_type = ((sll_header*)packet_orig)->sll_protocol;
		memcpy((u_char*)packet + 14, (u_char*)packet_orig + 16, header_orig->caplen - 16);
		header = new pcap_pkthdr;
		memcpy(header, header_orig, sizeof(pcap_pkthdr));
		header->caplen -= 2;
		header->len -= 2;
		allocPacket = true;
	}
 
	// check if it should be stored to mysql 
	if(type == TYPE_SIP and global_livesniffer and (sipportmatrix[source] || sipportmatrix[dest])) {
		save_live_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, call->type);
	}

	if(opt_newdir and opt_pcap_split) {
		switch(type) {
		case TYPE_SKINNY:
		case TYPE_SIP:
			if(call->getPcapSip()->isOpen()){
				call->set_last_packet_time(header->ts.tv_sec);
				call->getPcapSip()->dump(header, packet);
			}
			break;
		case TYPE_RTP:
		case TYPE_RTCP:
			if(call->getPcapRtp()->isOpen()){
				call->set_last_packet_time(header->ts.tv_sec);
				call->getPcapRtp()->dump(header, packet);
			} else {
				char pcapFilePath_spool_relative[1024];
				snprintf(pcapFilePath_spool_relative , 1023, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "RTP" : "", call->get_fbasename_safe());
				pcapFilePath_spool_relative[1023] = 0;
				static char str2[1024];
				if(opt_cachedir[0] != '\0') {
					snprintf(str2, 1023, "%s/%s", opt_cachedir, pcapFilePath_spool_relative);
				} else {
					strcpy(str2, pcapFilePath_spool_relative);
				}
				if(call->getPcapRtp()->open(str2, pcapFilePath_spool_relative)) {
					if(verbosity > 3) syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
					call->set_last_packet_time(header->ts.tv_sec);
					call->getPcapRtp()->dump(header, packet);
				}
			}
			break;
		}
	} else {
		if (call->getPcap()->isOpen()){
			call->set_last_packet_time(header->ts.tv_sec);
			call->getPcap()->dump(header, packet);
		}
	}
	
	if(allocPacket) {
		delete [] packet;
		delete header;
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
char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen, unsigned long *limitLen){
	unsigned long register r, l, tl;
	char *rc = NULL;
	char *tmp;
	char tmp2;
	tmp = (char*)ptr;
	bool positionOK = true;
	unsigned long _limitLen = 0;

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
	if(r == 0){
		// tag did not match
		l = 0;
	} else {
		//check if position ok
		if(limitLen && *limitLen > 0) {
			_limitLen = *limitLen;
		} else {
			const char *contentLengthString = "Content-Length: ";
			char *contentLengthPos = strcasestr(tmp, contentLengthString);
			if(contentLengthPos) {
				int contentLength = atoi(contentLengthPos + strlen(contentLengthString));
				if(contentLength >= 0) {
					const char *endHeaderSepString = "\r\n\r\n";
					char *endHeaderSepPos = (char*)memmem(tmp, len, endHeaderSepString, strlen(endHeaderSepString));
					if(endHeaderSepPos) {
						_limitLen = (endHeaderSepPos - tmp) + strlen(endHeaderSepString) + contentLength;
						if(limitLen) {
							*limitLen = _limitLen;
						}
					}
				}
			}
		}
		if(_limitLen &&
		   (unsigned long)(_limitLen + tmp) < r) {
			positionOK = false;
		}
		if(positionOK || verbosity > 0) {
			//tag matches move r pointer behind the tag name
			r += tl;
			tmp[len - 1] = tmp2;
			l = (unsigned long)memmem((void *)r, len - (r - (unsigned long)ptr), "\r", 1);
			if (l > 0){
				// remove trailing \r\n and set l to length of the tag
				l -= r;
			} else {
				// trailing \r not found try to find \n
				l = (unsigned long)memmem((void *)r, len - (r - (unsigned long)ptr), "\n", 1);
				if (l > 0){
					// remove trailing \r\n and set l to length of the tag
					l -= r;
				} else {
					// trailing \r not found try to find \n
					l = 0;
				}
			}
		} else {
			l = 0;
		}
	}
	tmp[len - 1] = tmp2;
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
	if(!positionOK && verbosity > 2 && l > 0) {
		char tagc[101];
		strncpy(tagc, rc, min(l, 100ul));
		tagc[min(l, 100ul)] = 0;
		syslog(LOG_NOTICE, "bad tag position - tag: %s, content: %s\n", tag, tagc);
		*gettaglen = 0;
	} else {
		*gettaglen = l;
	}
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
	size_t sdp_text_len = strlen(sdp_text);
	unsigned long gettagLimitLen = 0;

	*fax = 0;
	s = gettag(sdp_text,sdp_text_len, "c=IN IP4 ", &l, &gettagLimitLen);
	if(l == 0) return 1;
	memset(s1, '\0', sizeof(s1));
	memcpy(s1, s, MIN(l, 19));
//	printf("---------- [%s]\n", s1);
	if ((int32_t)(*addr = inet_addr(s1)) == -1){
		*addr = 0;
		*port = 0;
		return 1;
	}
	s = gettag(sdp_text, sdp_text_len, "m=audio ", &l, &gettagLimitLen);
	if (l == 0 || (*port = atoi(s)) == 0){
		s = gettag(sdp_text, sdp_text_len, "m=image ", &l, &gettagLimitLen);
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
	unsigned long gettagLimitLen = 0;

	if(datalen < 8) return 1;

	s = gettag(data, datalen, "\nContact:", &l, &gettagLimitLen);
	if(!l) {
		//try compact header
		s = gettag(data, datalen, "\nm:", &l, &gettagLimitLen);
	}
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
       else if(strcasecmp(mimeSubtype,"CLEARMODE") == 0)
	       return PAYLOAD_CLEARMODE;
       else if(strcasecmp(mimeSubtype,"OPUS") == 0)
	       return PAYLOAD_OPUS;
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
	unsigned long gettagLimitLen = 0;

	s = gettag(sdp_text, len, "m=audio ", &l, &gettagLimitLen);
	if(!l) {
		return 0;
	}
	do {
		s = gettag(s, len - (s - sdp_text), "a=rtpmap:", &l, &gettagLimitLen);
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
			} else if(mtype == PAYLOAD_OPUS) {
				switch(rate) {
					case 8000:
						mtype = PAYLOAD_OPUS8;
						break;
					case 12000:
						mtype = PAYLOAD_OPUS12;
						break;
					case 16000:
						mtype = PAYLOAD_OPUS16;
						break;
					case 24000:
						mtype = PAYLOAD_OPUS24;
						break;
					case 48000:
						mtype = PAYLOAD_OPUS48;
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

void add_to_rtp_thread_queue(Call *call, unsigned char *data, int datalen, struct pcap_pkthdr *header,  u_int32_t saddr, u_int32_t daddr, unsigned short port, int iscaller, int is_rtcp,
			     pcap_block_store *block_store, int block_store_index) {
	if(terminating) {
		return;
	}
	
	__sync_add_and_fetch(&call->rtppcaketsinqueue, 1);
	read_thread *params = &(threads[call->thread_num]);

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
	rtp_packet *rtpp = (rtp_packet*)malloc(sizeof(rtp_packet));
	rtpp->data = (unsigned char *)malloc(sizeof(unsigned char) * datalen);
#endif

#ifdef QUEUE_NONBLOCK2
	rtp_packet *rtpp;
	if(!opt_pcap_queue) {
		rtpp = &(params->vmbuffer[params->writeit % params->vmbuffermax]);
		while(params->vmbuffer[params->writeit % params->vmbuffermax].free == 0) {
			// no room left, loop until there is room
			usleep(100);
		}
	}
#endif
	
	if(opt_pcap_queue) {
		block_store->lock_packet(block_store_index);
		params->rtpp_queue.lock();
		rtp_packet_pcap_queue *rtpp_pq = params->rtpp_queue.push_get_pointer();
		rtpp_pq->call = call;
		rtpp_pq->saddr = saddr;
		rtpp_pq->daddr = daddr;
		rtpp_pq->port = port;
		rtpp_pq->iscaller = iscaller;
		rtpp_pq->is_rtcp = is_rtcp;
		rtpp_pq->data = data;
		rtpp_pq->datalen = datalen;
		rtpp_pq->pkthdr_pcap = (*block_store)[block_store_index];
		rtpp_pq->block_store = block_store;
		rtpp_pq->block_store_index =block_store_index;
		params->rtpp_queue.unlock();
	} else {
		rtpp->call = call;
		rtpp->datalen = datalen;
		rtpp->saddr = saddr;
		rtpp->daddr = daddr;
		rtpp->port = port;
		rtpp->iscaller = iscaller;
		rtpp->is_rtcp = is_rtcp;

		memcpy(&rtpp->header, header, sizeof(struct pcap_pkthdr));
		if(datalen > MAXPACKETLENQRING) {
			syslog(LOG_ERR, "error: packet is to large [%d]b for RTP QRING[%d]b", header->caplen, MAXPACKETLENQRING);
			return;
		}
		if(opt_skiprtpdata) {
			memcpy(rtpp->data, data, MIN((unsigned int)datalen, sizeof(RTPFixedHeader)));
		} else {
			memcpy(rtpp->data, data, datalen);
		}
	}

#ifdef QUEUE_NONBLOCK2
	if(!opt_pcap_queue) {
		params->vmbuffer[params->writeit % params->vmbuffermax].free = 0;
		if((params->writeit + 1) == params->vmbuffermax) {
			params->writeit = 0;
		} else {
			params->writeit++;
		}
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
	rtp_packet *rtpp = NULL;
	rtp_packet_pcap_queue rtpp_pq;
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
		if(opt_pcap_queue) {
			if(!params->rtpp_queue.pop(&rtpp_pq, true)) {
				if(terminating || readend) {
					return NULL;
				}
				// no packet to read, wait and try again
				usleep(10000);
				continue;
			}
		} else {
		
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
		}
#endif

		if(opt_pcap_queue) {
			if(rtpp_pq.is_rtcp) {
				rtpp_pq.call->read_rtcp(rtpp_pq.data, rtpp_pq.datalen, &rtpp_pq.pkthdr_pcap.header->header_std, rtpp_pq.saddr, rtpp_pq.port, rtpp_pq.iscaller);
			}  else {
				int monitor;
				rtpp_pq.call->read_rtp(rtpp_pq.data, rtpp_pq.datalen, &rtpp_pq.pkthdr_pcap.header->header_std, rtpp_pq.saddr, rtpp_pq.daddr, rtpp_pq.port, rtpp_pq.iscaller, &monitor);
			}
			rtpp_pq.call->set_last_packet_time(rtpp_pq.pkthdr_pcap.header->header_std.ts.tv_sec);
			rtpp_pq.block_store->unlock_packet(rtpp_pq.block_store_index);
		} else {
			if(rtpp->is_rtcp) {
				rtpp->call->read_rtcp((unsigned char*)rtpp->data, rtpp->datalen, &rtpp->header, rtpp->saddr, rtpp->port, rtpp->iscaller);
			}  else {
				int monitor;
				rtpp->call->read_rtp(rtpp->data, rtpp->datalen, &rtpp->header, rtpp->saddr, rtpp->daddr, rtpp->port, rtpp->iscaller, &monitor);
			}
			rtpp->call->set_last_packet_time(rtpp->header.ts.tv_sec);
		}

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
		free(rtpp->data);
		free(rtpp);
#endif

#ifdef QUEUE_NONBLOCK2
		if(!opt_pcap_queue) {
			params->vmbuffer[params->readit % params->vmbuffermax].free = 1;
			if((params->readit + 1) == params->vmbuffermax) {
				params->readit = 0;
			} else {
				params->readit++;
			}
		}
#endif

		if(opt_pcap_queue) {
			__sync_sub_and_fetch(&rtpp_pq.call->rtppcaketsinqueue, 1);
		} else {
			__sync_sub_and_fetch(&rtpp->call->rtppcaketsinqueue, 1);
		}

	}
	
	return NULL;
}

Call *new_invite_register(int sip_method, char *data, int datalen, struct pcap_pkthdr *header, char *callidstr, u_int32_t saddr, u_int32_t daddr, int source, char *s, long unsigned int l){
	unsigned long gettagLimitLen = 0;
	unsigned int flags = 0;
	int res;

	if(opt_callslimit != 0 and opt_callslimit < calls) {
		if(verbosity > 0)
			syslog(LOG_NOTICE, "callslimit[%d] > calls[%d] ignoring call\n", opt_callslimit, calls);
		return NULL;
	}

	//caller and called number has to be checked before flags due to skip filter 
	char tcaller[1024] = "", tcalled[1024] = "";
	// caller number
	res = get_sip_peername(data,datalen,"\nFrom:", tcaller, sizeof(tcaller));
	if(res) {
		// try compact header
		get_sip_peername(data,datalen,"\nf:", tcaller, sizeof(tcaller));
	}
	// called number
	res = get_sip_peername(data,datalen,"\nTo:", tcalled, sizeof(tcalled));
	if(res) {
		// try compact header
		get_sip_peername(data,datalen,"\nt:", tcalled, sizeof(tcalled));
	}

	//flags
	if(opt_saveSIP)
		flags |= FLAG_SAVESIP;

	if(opt_saveRTP)
		flags |= FLAG_SAVERTP;

	if(opt_onlyRTPheader)
		flags |= FLAG_SAVERTPHEADER;

	if(opt_saveWAV)
		flags |= FLAG_SAVEWAV;

	if(opt_saveGRAPH)
		flags |= FLAG_SAVEGRAPH;

	if(opt_skipdefault)
		flags |= FLAG_SKIPCDR;

	ipfilter->add_call_flags(&flags, ntohl(saddr), ntohl(daddr));
	telnumfilter->add_call_flags(&flags, tcaller, tcalled);

	if(flags & FLAG_SKIPCDR) {
		if(verbosity > 1)
			syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
		return NULL;
	}


	static char str2[1024];
	// store this call only if it starts with invite
	Call *call = calltable->add(s, l, header->ts.tv_sec, saddr, source);
	call->set_first_packet_time(header->ts.tv_sec, header->ts.tv_usec);
	call->sipcallerip = saddr;
	call->sipcalledip = daddr;
	call->type = sip_method;
	call->flags = flags;
	strncpy(call->fbasename, callidstr, MAX_FNAME - 1);
	call->fbasename[MIN(strlen(callidstr), MAX_FNAME - 1)] = '\0';

	/* this logic updates call on the first INVITES */
	if (sip_method == INVITE or sip_method == REGISTER or sip_method == MESSAGE) {
		//geolocation 
		s = gettag(data, datalen, "\nGeoPosition:", &l, &gettagLimitLen);
		if(l && l < 255) {
			char buf[255];
			memcpy(buf, s, l);
			buf[l] = '\0';
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen GeoPosition header: [%s]\n", buf);
			call->geoposition = buf;
		}

		// callername
		res = get_sip_peercnam(data,datalen,"\nFrom:", call->callername, sizeof(call->callername));
		if(res) {
			// try compact header
			get_sip_peercnam(data,datalen,"\nf:", call->callername, sizeof(call->callername));
		}

		// caller number
		strncpy(call->caller, tcaller, sizeof(call->caller));

		// called number
		strncpy(call->called, tcalled, sizeof(call->called));

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
			s = gettag(data, datalen, "\nUser-Agent:", &l, &gettagLimitLen);
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
			s = gettag(data, datalen, "\nAuthorization:", &l, &gettagLimitLen);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				get_value_stringkeyval(s, datalen - (s - data), "username=\"", call->digest_username, sizeof(call->digest_username));
				get_value_stringkeyval(s, datalen - (s - data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
			}
			// get expires header
			s = gettag(data, datalen, "\nExpires:", &l, &gettagLimitLen);
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
#ifdef DEBUG_INVITE
			syslog(LOG_NOTICE, "New call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s] Call-ID[%s]\n", 
				call->sipcallerip, call->sipcalledip, call->caller, call->called, call->fbasename);
#endif
		}
	}

	if(opt_norecord_header) {
		s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l, &gettagLimitLen);
		if(l && l < 33) {
			// do 
			call->stoprecording();
		}
	}

	// opening dump file
	if((call->type == REGISTER && (call->flags & FLAG_SAVEREGISTER)) || 
		(call->type != REGISTER && (call->flags & (FLAG_SAVESIP | FLAG_SAVERTP | FLAG_SAVEWAV) || opt_savewav_force))) {
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
					tmp = dir + "/REG";
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
				tmp = dir + "/REG";
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

	if(call->type == REGISTER && (call->flags & FLAG_SAVEREGISTER)) {
		/****
		call->set_f_pcap(NULL);
		call->set_fsip_pcap(NULL);
		call->set_frtp_pcap(NULL);
		****/
		char filenamestr[32];
		sprintf(filenamestr, "%u%u", (unsigned int)header->ts.tv_sec, (unsigned int)header->ts.tv_usec);
		if(opt_newdir and opt_pcap_split) {
			char pcapFilePath_spool_relative[1024];
			snprintf(pcapFilePath_spool_relative , 1023, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "REG" : "", filenamestr);
			pcapFilePath_spool_relative[1023] = 0;
			if(opt_cachedir[0] != '\0') {
				snprintf(str2, 1023, "%s/%s", opt_cachedir, pcapFilePath_spool_relative);
				str2[1023] = 0;
			} else {
				strcpy(str2, pcapFilePath_spool_relative);
			}
			unsigned long long num = header->ts.tv_sec;
			unsigned long long num2 = header->ts.tv_usec;
			while(num2 > 0) {
				num2 /= 10;
				num *= 10;
			}
			call->fname2 = num + header->ts.tv_usec;
			call->pcapfilename = call->sip_pcapfilename = pcapFilePath_spool_relative;
			if(call->getPcapSip()->open(str2, pcapFilePath_spool_relative)) {
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			}
		}
	} else if((call->type != REGISTER && (call->flags & (FLAG_SAVESIP | FLAG_SAVERTP))) || 
		(call->isfax && opt_saveudptl)) {
		// open one pcap for all packets or open SIP and RTP separatly
		/****
		call->set_f_pcap(NULL);
		call->set_fsip_pcap(NULL);
		call->set_frtp_pcap(NULL);
		****/
		if(opt_newdir and opt_pcap_split) {
			//SIP
			char pcapFilePath_spool_relative[1024];
			snprintf(pcapFilePath_spool_relative , 1023, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "SIP" : "", call->get_fbasename_safe());
			pcapFilePath_spool_relative[1023] = 0;
			if(opt_cachedir[0] != '\0') {
				snprintf(str2, 1023, "%s/%s", opt_cachedir, pcapFilePath_spool_relative);
				str2[1023] = 0;
			} else {
				strcpy(str2, pcapFilePath_spool_relative);
			}
			call->pcapfilename = call->sip_pcapfilename = pcapFilePath_spool_relative;
			if(call->getPcapSip()->open(str2, pcapFilePath_spool_relative)) {
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			}
			//RTP
			char pcapRtpFilePath_spool_relative[1024];
			snprintf(pcapRtpFilePath_spool_relative , 1023, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "RTP" : "", call->get_fbasename_safe());
			pcapRtpFilePath_spool_relative[1023] = 0;
			if(opt_cachedir[0] != '\0') {
				snprintf(str2, 1023, "%s/%s", opt_cachedir, pcapRtpFilePath_spool_relative);
				str2[1023] = 0;
			} else {
				strcpy(str2, pcapRtpFilePath_spool_relative);
			}
			call->rtp_pcapfilename = pcapRtpFilePath_spool_relative;
/* this is moved to save_packet
			if(!file_exists(str2)) {
				call->set_frtp_pcap(pcap_dump_open(HANDLE_FOR_PCAP_SAVE, str2));
				if(call->get_frtp_pcap() == NULL) {
					syslog(LOG_NOTICE,"pcap [%s] cannot be opened: %s\n", str2, pcap_geterr(HANDLE_FOR_PCAP_SAVE));
				}
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			} else {
				if(verbosity > 0) {
					syslog(LOG_NOTICE,"pcap_filename: [%s] already exists, do not overwriting\n", str2);
				}
			}
*/
		} else {
			char pcapFilePath_spool_relative[1024];
			snprintf(pcapFilePath_spool_relative , 1023, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "ALL" : "", call->get_fbasename_safe());
			pcapFilePath_spool_relative[1023] = 0;
			if(opt_cachedir[0] != '\0') {
				snprintf(str2, 1023, "%s/%s", opt_cachedir, pcapFilePath_spool_relative);
				str2[1023] = 0;
			} else {
				strcpy(str2, pcapFilePath_spool_relative);
			}
			call->pcapfilename = pcapFilePath_spool_relative;
			if(call->getPcap()->open(str2, pcapFilePath_spool_relative)) {
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			}
		}
	}

	//check and save CSeq for later to compare with OK 
	s = gettag(data, datalen, "\nCSeq:", &l, &gettagLimitLen);
	if(l && l < 32) {
		memcpy(call->invitecseq, s, l);
		call->unrepliedinvite++;
		call->invitecseq[l] = '\0';
		if(verbosity > 2)
			syslog(LOG_NOTICE, "Seen invite, CSeq: %s\n", call->invitecseq);
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
			delete tmpstream;
			tmpstream = next;
		}
		tcp_streams_list.erase(stream++);
	}
}

void process_sdp(Call *call, unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, struct iphdr2 *header_ip, char *callidstr, char *ua, unsigned int ua_len){
	char *tmp = strstr(data, "\r\n\r\n");
	if(!tmp) return;

	in_addr_t tmp_addr;
	unsigned short tmp_port;
	int rtpmap[MAX_RTPMAP];
	memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);
	int fax;
	if (!get_ip_port_from_sdp(tmp + 1, &tmp_addr, &tmp_port, &fax)){
		if(fax) { 
			if(verbosity >= 2){
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
			if(iscalled) {
				call->called_sipdscp = header_ip->tos >> 2;
			} else {
				call->caller_sipdscp = header_ip->tos >> 2;
			}
			//syslog(LOG_ERR, "ADDR: %u port %u iscalled[%d]\n", tmp_addr, tmp_port, iscalled);
			if(call->add_ip_port(tmp_addr, tmp_port, ua, ua_len, !iscalled, rtpmap) != -1){
				calltable->hashAdd(tmp_addr, tmp_port, call, !iscalled, 0, fax);
				//calltable->mapAdd(tmp_addr, tmp_port, call, !iscalled, 0);
				if(opt_rtcp) {
					calltable->hashAdd(tmp_addr, tmp_port + 1, call, !iscalled, 1, fax); //add rtcp
					//calltable->mapAdd(tmp_addr, tmp_port + 1, call, !iscalled, 1); //add rtcp
				}
			} else if(fax){
				calltable->hashAdd(tmp_addr, tmp_port, call, !iscalled, 0, fax);
			}
			
			// check if the IP address is listed in nat_aliases
			in_addr_t alias = 0;
			if((alias = match_nat_aliases(tmp_addr)) != 0) {
				if(call->add_ip_port(alias, tmp_port, ua, ua_len, !iscalled, rtpmap) != -1) {
					calltable->hashAdd(alias, tmp_port, call, !iscalled, 0, fax);
					//calltable->mapAdd(alias, tmp_port, call, !iscalled, 0);
					if(opt_rtcp) {
						calltable->hashAdd(alias, tmp_port + 1, call, !iscalled, 1, fax); //add rtcp
						//calltable->mapAdd(alias, tmp_port + 1, call, !iscalled, 1); //add rtcp
					}
				}
			} else if(fax){
				calltable->hashAdd(alias, tmp_port, call, !iscalled, 0, fax);
			}

			if(opt_sdp_reverse_ipport) {
				// add source SIP IP and destination port from SDP
				if(call->add_ip_port(saddr, tmp_port, ua, ua_len, !iscalled, rtpmap) != -1){
					calltable->hashAdd(saddr, tmp_port, call, !iscalled, 0, fax);
					//calltable->mapAdd(saddr, tmp_port, call, !iscalled, 0);
					if(opt_rtcp) {
						calltable->hashAdd(saddr, tmp_port + 1, call, !iscalled, 1, fax);
						//calltable->mapAdd(saddr, tmp_port + 1, call, !iscalled, 1);
					}
				} else if(fax){
					calltable->hashAdd(saddr, tmp_port, call, !iscalled, 0, fax);
				}
			}
		}
	} else {
		if(verbosity >= 2){
			syslog(LOG_ERR, "callid[%s] Can't get ip/port from SDP:\n%s\n\n", callidstr, tmp + 1);
		}
	}
}

static void process_packet__parse_custom_headers(Call *call, char *data, int datalen);

Call *process_packet(unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen,
	pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int istcp, int dontsave, int can_thread, int *was_rtp, struct iphdr2 *header_ip, int *voippacket, int disabledsave,
	pcap_block_store *block_store, int block_store_index) {

	Call *call = NULL;
	int last_sip_method = -1;
	int iscaller;
	int is_rtcp = 0;
	int is_fax = 0;
	static unsigned long last_cleanup = 0;	// Last cleaning time
	char *s;
	unsigned long l;
	char callidstr[1024],str2[1024];
	int sip_method = 0;
	char lastSIPresponse[128];
	int lastSIPresponseNum = 0;
	static int pcapstatres = 0;
	static unsigned int lostpacket = 0;
	static unsigned int lostpacketif = 0;
	unsigned int tmp_u32 = 0;
	int repeat = 0;
	int record = 0;
	unsigned long gettagLimitLen = 0;

	*was_rtp = 0;

	// checking and cleaning stuff every 10 seconds (if some packet arrive) 
if (header->ts.tv_sec - last_cleanup > 10){
		//if(verbosity > 0) syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d] calls in delete queue [%d]\n", (int)calltable->calls_listMAP.size(), (int)calltable->calls_queue.size(), (int)calltable->calls_deletequeue.size());
		if(verbosity > 0 && !opt_pcap_queue) {
			if(opt_dup_check) {
				syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d] skipped dupe pkts [%u]\n", 
					(int)calltable->calls_listMAP.size(), (int)calltable->calls_queue.size(), duplicate_counter);
			} else {
				syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d]\n", 
					(int)calltable->calls_listMAP.size(), (int)calltable->calls_queue.size());
			}
		}
		if (last_cleanup >= 0){
			calltable->cleanup(header->ts.tv_sec);
		}
		/* also do every 10 seconds pcap statistics */
		if(!opt_pcap_queue) {
			pcapstatres = pcap_stats(handle, &pcapstat);
			if (pcapstatres == 0 && (lostpacket < pcapstat.ps_drop || lostpacketif < pcapstat.ps_ifdrop)) {
				if(pcapstatresCount) {
					syslog(LOG_ERR, "warning: libpcap or interface dropped packets! rx:%u pcapdrop:%u ifdrop:%u increase --ring-buffer (kernel >= 2.6.31 and libpcap >= 1.0.0)\n", pcapstat.ps_recv, pcapstat.ps_drop, pcapstat.ps_ifdrop);
				} else {
					// do not show first error, it is normal on startup. 
					pcapstatresCount++;
				}
				lostpacket = pcapstat.ps_drop;
				lostpacketif = pcapstat.ps_ifdrop;
			}
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
					delete tmpstream;
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
#ifndef FREEBSD
		malloc_trim(0);
#endif

	}

	// check if the packet is SKINNY
	if(opt_skinny && (source == 2000 || dest == 2000)) {
		handle_skinny(header, packet, saddr, source, daddr, dest, data, datalen);
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
				"packet is SKINNY");
		}
		return NULL;
	}
	
	// check if the packet is SIP ports or SKINNY ports
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
		s = gettag(data, datalen, "\nCall-ID:", &l, &gettagLimitLen);
		if(!issip or (l <= 0 || l > 1023)) {
			// try also compact header
			s = gettag(data, datalen,"\ni:", &l, &gettagLimitLen);
			if(!issip or (l <= 0 || l > 1023)) {
				// no Call-ID found in packet
				if(istcp && header_ip) {
					// packet is tcp, check if belongs to some previouse TCP stream (reassembling here)
					struct tcphdr2 *header_tcp = (struct tcphdr2 *) ((char *) header_ip + sizeof(*header_ip));
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
								Call *call = process_packet(saddr, source, daddr, dest, (char*)newdata, newlen, handle, header, packet, 0, 1, 0, &tmp_was_rtp, header_ip, voippacket, 1,
											    block_store, block_store_index);

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
									delete tmpstream;
									tmpstream = next;
								}
								free(newdata);
								tcp_streams_hashed[hash] = NULL;
								// save also current packet 
								if(call) {
									save_packet(call, header, packet, saddr, source, daddr, dest, istcp, (char *)data, datalen, TYPE_SIP);
								}
								if(logPacketSipMethodCall_enable) {
									logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
										"no Call-ID found in packet - packet do not belongs to preivious TCP session - the tcp packet has sequence number which confirms ACK");
								}
								return NULL;
							} else {
								// TCP packet does not have CAll-ID header and belongs to no existing stream
								if(logPacketSipMethodCall_enable) {
									logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
										"TCP packet does not have CAll-ID header and belongs to no existing stream");
								}
								return NULL;
							}
						} else {
							if(logPacketSipMethodCall_enable) {
								logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
									"no Call-ID found in packet - packet do not belongs to preivious TCP session - the tcp packet does not have sequence number which confirms ACK");
							}
							return NULL;
						}
					}

					// the packet belongs to previous stream
					for(tmpstream = tcp_streams_hashed[hash]; tmpstream->next; tmpstream = tmpstream->next) {}; // set cursor to the latest item
					if(tmpstream->next_seq != htonl(header_tcp->seq)) {
						// the packet is out of order or duplicated - skip it. This means that voipmonitor is not able to reassemble reordered packets
						if(logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
								"no Call-ID found in packet - the packet is out of order or duplicated - skip it");
						}
						return NULL;
					}

					// append packet to end of streams items 
					tcp_stream2_t *stream = new tcp_stream2_t;
					stream->call_id = string(s, l);
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
						Call *call = process_packet(saddr, source, daddr, dest, (char*)newdata, newlen, handle, header, packet, 0, 1, 0, &tmp_was_rtp, header_ip, voippacket, 1,
									    block_store, block_store_index);

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
							delete tmpstream;
							tmpstream = next;
						}
						free(newdata);
						tcp_streams_hashed[hash] = NULL;
						// save also current packet 
						if(call) {
							save_packet(call, header, packet, saddr, source, daddr, dest, istcp, (char *)data, datalen, TYPE_SIP);
						}
						if(logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
								"no Call-ID found in packet - latest segment is not erminated by 0x0d or 0x0a");
						}
						return NULL;
					}
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
							"no Call-ID found in packet");
					}
					return NULL;
				} else {
					// it is not TCP and callid not found
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
							"it is not TCP and callid not found");
					}
					return NULL;
				}
			}
		}
		memcpy(callidstr, s, MIN(l, 1024));
		callidstr[MIN(l, 1023)] = '\0';

		static int counter = 0;
		counter++;

		// Call-ID is present
		if(istcp and datalen >= 2) {
			u_int hash = mkhash(saddr, source, daddr, dest) % MAX_TCPSTREAMS;
			// check if TCP packet contains the whole SIP message
			if(!(data[datalen - 2] == 0x0d && data[datalen - 1] == 0x0a)) {
				// SIP message is not complete, save packet 
				tcp_stream2_t *tmpstream;
				if((tmpstream = tcp_streams_hashed[hash])) {
					tcp_stream2_t test;
					test = *tmpstream;
					// there is already stream and Call-ID which can happen if previous stream is not closed (lost ACK etc)
					// check if the stream contains the same Call-ID
					if(memmem(tmpstream->call_id.c_str(), tmpstream->call_id.length(), s, l)) {
						// callid is same - it must be duplicate or retransmission just ignore the packet 
						if(logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
								"callid is same - it must be duplicate or retransmission just ignore the packet ");
						}
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
						Call *call = process_packet(saddr, source, daddr, dest, (char*)newdata, newlen, handle, header, packet, 0, 1, 0, &tmp_was_rtp, header_ip, voippacket, 1,
									    block_store, block_store_index);

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
							delete tmpstream;
							tmpstream = next;
						}
						// save also current packet 17.5.2013 - this is nonsense - it creates duplicates do not save here
						//if(call) {
							//save_packet(call, header, packet, saddr, source, daddr, dest, istcp, (char *)data, datalen, TYPE_SIP);
						//}
						free(newdata);
						tcp_streams_hashed[hash] = NULL;
					}
				} 

				// create new tcp stream 
				tcp_stream2_t *stream = new tcp_stream2_t;
				tcp_streams_list.push_back(stream);
				stream->call_id = string(s, l);
				stream->next = NULL;
				stream->ts = header->ts.tv_sec;
				stream->hash = hash;
				tcp_streams_hashed[hash] = stream;

				struct tcphdr2 *header_tcp = (struct tcphdr2 *) ((char *) header_ip + sizeof(*header_ip));
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
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
						"SIP message is not complete");
				}
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
		} else if ((datalen > 5) && !(memmem(data, 4, "INFO", 4) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: INFO\n");
			sip_method = INFO;
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
		} else if ((datalen > 10) && !(memmem(data, 11, "SIP/2.0 403", 11) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 403\n");
			sip_method = RES403;
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
		} else if ((datalen > 6) && !(memmem(data, 7, "OPTIONS", 9) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: OPTIONS\n");
			sip_method = OPTIONS;
			if(livesnifferfilterUseSipTypes.u_options) {
				save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, OPTIONS);
			}
		} else if ((datalen > 8) && !(memmem(data, 9, "SUBSCRIBE", 9) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: SUBSCRIBE\n");
			sip_method = SUBSCRIBE;
			if(livesnifferfilterUseSipTypes.u_subscribe) {
				save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, SUBSCRIBE);
			}
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
/*
				if(lastSIPresponseNum == 0) {
					if(verbosity > 0) syslog(LOG_NOTICE, "lastSIPresponseNum = 0 [%s]\n", lastSIPresponse);
				}
*/
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
				if(call == NULL) {
					return NULL;
				}
			} else {
				// SIP packet does not belong to any call and it is not INVITE 
				// TODO: check if we have enabled live sniffer for SUBSCRIBE or OPTIONS 
				// if yes check for cseq OPTIONS or SUBSCRIBE 
				s = gettag(data, datalen, "\nCSeq:", &l, &gettagLimitLen);
				if(l && l < 32) {
					if(livesnifferfilterUseSipTypes.u_subscribe && memmem(s, l, "SUBSCRIBE", 9)) {
						save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, SUBSCRIBE);
					} else if(livesnifferfilterUseSipTypes.u_options && memmem(s, l, "OPTIONS", 7)) {
						save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, OPTIONS);
					}
				}
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
						"SIP packet does not belong to any call and it is not INVITE");
				}
				return NULL;
			}
		// check if the SIP msg is part of earlier REGISTER
		} else if(call->type == REGISTER) {
			call->msgcount++;
			if(sip_method == REGISTER) {
				call->regcount++;
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER Call-ID[%s] regcount[%d]", call->call_id.c_str(), call->regcount);

				// update Authorization
				s = gettag(data, datalen, "\nAuthorization:", &l, &gettagLimitLen);
				if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
					get_value_stringkeyval(s, datalen - (s - data), "username=\"", call->digest_username, sizeof(call->digest_username));
					get_value_stringkeyval(s, datalen - (s - data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
				}

				if(call->regcount > 4) {
					// to much register attempts without OK or 401 responses
					call->regstate = 4;
					call->saveregister();
					call = new_invite_register(sip_method, data, datalen, header, callidstr, saddr, daddr, source, (char*)call->call_id.c_str(), call->call_id.length());
					if(call == NULL) {
						return NULL;
					}
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
							"to much register attempts without OK or 401 responses");
					}
					return call;
				}
				s = gettag(data, datalen, "\nCSeq:", &l, &gettagLimitLen);
				if(l && l < 32) {
					memcpy(call->invitecseq, s, l);
					call->invitecseq[l] = '\0';
				}


			} else if(sip_method == RES2XX) {
				// update expires header from all REGISTER dialog messages (from 200 OK which can override the expire) 
				s = gettag(data, datalen, "\nExpires:", &l, &gettagLimitLen);
				if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
					char c = s[l];
					s[l] = '\0';
					call->register_expires = atoi(s);
					s[l] = c;
				}
				// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
				get_expires_from_contact(data, datalen, &call->register_expires);

				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER OK Call-ID[%s]", call->call_id.c_str());
                                s = gettag(data, datalen, "\nCSeq:", &l, &gettagLimitLen);
                                if(l && strncmp(s, call->invitecseq, l) == 0) {
					// registration OK 
					call->regstate = 1;
				} else {
					// OK to unknown msg close the call
					call->regstate = 3;
				}
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
				call->saveregister();
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
						"update expires header from all REGISTER dialog messages (from 200 OK which can override the expire)");
				}
				return NULL;
			} else if(sip_method == RES401 or sip_method == RES403) {
				call->reg401count++;
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER 401 Call-ID[%s] reg401count[%d]", call->call_id.c_str(), call->reg401count);
				if(call->reg401count > 1) {
					// registration failed
					call->regstate = 2;
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
					call->saveregister();
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
							"REGISTER 401 count > 1");
					}
					return NULL;
				}
			}
			if(call->msgcount > 20) {
				// too many REGISTER messages within the same callid
				call->regstate = 4;
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
				call->saveregister();
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call, 
						"too many REGISTER messages within the same callid");
				}
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
			cseq = gettag(data, datalen, "\nCSeq:", &cseqlen, &gettagLimitLen);
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
				s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l, &gettagLimitLen);
				if(l && l < 33) {
					// do 
					call->stoprecording();
				}
			}

			// we have packet, extend pending destroy requests
			if(call->destroy_call_at > 0) {
				if(call->seenbye) {
					call->destroy_call_at = header->ts.tv_sec + 60;
				} else {
					call->destroy_call_at = header->ts.tv_sec + (lastSIPresponseNum == 487 || call->lastSIPresponseNum == 487 ? 15 : 5);
				}
			}

			call->set_last_packet_time(header->ts.tv_sec);
			// save lastSIPresponseNum but only if previouse was not 487 (CANCEL) and call was not answered 
			if(lastSIPresponseNum != 0 && lastSIPresponse[0] != '\0' && 
			   (call->lastSIPresponseNum != 487 || (call->new_invite_after_lsr487 && lastSIPresponseNum == 200)) &&
			   !call->seeninviteok &&
			   !(call->cancelcseq[0] && cseq && cseqlen < 32 && strncmp(cseq, call->cancelcseq, cseqlen) == 0)) {
				strncpy(call->lastSIPresponse, lastSIPresponse, 128);
				call->lastSIPresponseNum = lastSIPresponseNum;
			}

			// check if it is BYE or OK(RES2XX)
			if(sip_method == INVITE) {
				if(!call->seenbye) {
					call->destroy_call_at = 0;
				}
				if(call->lastSIPresponseNum == 487) {
					call->new_invite_after_lsr487 = true;
				}
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

				s = gettag(data, datalen, "\nUser-Agent:", &l, &gettagLimitLen);
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
					s = gettag(data, datalen, "\nContent-Length:", &l, &gettagLimitLen);
					if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
						char c = s[l];
						s[l] = '\0';
						contentlen = atoi(s);
						s[l] = c;
					}
					if(contentlen > 0) {
						char *end = strcasestr(tmp, "\n\nContent-Length:");
						if(!end) {
							end = strstr(tmp, "\r\n"); // strstr is safe becuse tmp ends with '\0'
							if(!end) {
								end = data + datalen;
							}
						}
						if(!call->message || (end - tmp) == contentlen) {
							//update message only in case that the new message equels to content length
							//truncate message to its size announced in content-length (only for !call->message)
							if(end - tmp > contentlen) {
								end = tmp + MIN(end - tmp, contentlen);
							}
							if(call->message) {
								free(call->message);
							}
							call->message = (char*)malloc(sizeof(char) * (end - tmp + 1));
							data[datalen - 1] = a;
							memcpy(call->message, tmp, end - tmp);
							call->message[end - tmp] = '\0';
						}
					} else if(!call->message) {
						call->message = (char*)malloc(sizeof(char) * 1);
						call->message[0] = '\0';
					}
					data[datalen - 1] = a;
				} else {
					data[datalen - 1] = a;
				}
			} else if(sip_method == BYE) {
				
				call->destroy_call_at = header->ts.tv_sec + 60;
				
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
				if(call->sipcallerip == saddr) {
					call->whohanged = 0;
				} else if(call->sipcalledip == saddr) {
					call->whohanged = 1;
				}
			} else if(sip_method == CANCEL) {
				// CANCEL continues with Status: 200 canceling; 200 OK; 487 Req. terminated; ACK. Lets wait max 10 seconds and destroy call
				call->destroy_call_at = header->ts.tv_sec + 10;
				
				//check and save CSeq for later to compare with OK 
				if(cseq && cseqlen < 32) {
					memcpy(call->cancelcseq, cseq, cseqlen);
					call->cancelcseq[cseqlen] = '\0';
				}
			} else if(sip_method == RES2XX) {
				// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
				if(call->progress_time == 0) {
					call->progress_time = header->ts.tv_sec;
				}

				// if it is OK check for BYE
				if(cseq && cseqlen < 32) {
					if(verbosity > 2) {
						char a = cseq[cseqlen];
						cseq[cseqlen] = '\0';
						syslog(LOG_NOTICE, "Cseq: %s\n", cseq);
						cseq[cseqlen] = a;
					}
					if(strncmp(cseq, call->byecseq, cseqlen) == 0) {
						// terminate successfully acked call, put it into mysql CDR queue and remove it from calltable 

						call->seenbyeandok = true;
						save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
/*
	Whan voipmonitor listens for both SIP legs (with the same Call-ID it sees both BYE and should save both 200 OK after BYE so closing call after the 
	first 200 OK will not save the second 200 OK. So rather wait for 5 seconds for some more messages instead of closing the call. 
*/
						// destroy call after 5 seonds from now 
						call->destroy_call_at = header->ts.tv_sec + 5;
						if(logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call);
						}
						return call;
					} else if(strncmp(cseq, call->invitecseq, cseqlen) == 0) {
						call->seeninviteok = true;
						if(!call->connect_time) {
							call->connect_time = header->ts.tv_sec;
						}
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Call answered\n");
					} else if(strncmp(cseq, call->cancelcseq, cseqlen) == 0) {
						return NULL;
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
			    (sip_method == RES3XX || sip_method == RES4XX || sip_method == RES5XX || sip_method == RES6XX) && lastSIPresponseNum != 401 && lastSIPresponseNum != 407
				&& lastSIPresponseNum != 501 ) {
					// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
					if(call->progress_time == 0) {
						call->progress_time = header->ts.tv_sec;
					}
					// save packet 
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
					call->destroy_call_at = header->ts.tv_sec + 5;

					if(sip_method == RES3XX) {
						// remove all RTP  
						call->hashRemove();
						call->removeRTP();
						call->ipport_n = 0;
					}
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call);
					}
					process_packet__parse_custom_headers(call, data, datalen);
					return call;
			}
		}

		if(opt_cdrproxy && sip_method == INVITE) {
			if(call->sipcalledip != daddr and call->sipcallerip != daddr and call->lastsipcallerip != saddr) {
				if(daddr != 0) {
					// daddr is already set, store previous daddr as sipproxy
					call->proxies.push_back(call->sipcalledip);
				}
				call->sipcalledip = daddr;
				call->lastsipcallerip = saddr;
			} else if(call->lastsipcallerip == saddr) {
				// update sipcalledip to this new one
				call->sipcalledip = daddr;
				call->lastsipcallerip = saddr;
			}
		}

		if(opt_norecord_header) {
			s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l, &gettagLimitLen);
			if(l && l < 33) {
				// do 
				call->stoprecording();
			}
		}

		if(sip_method == INFO) {
			s = gettag(data, datalen, "\nSignal:", &l, &gettagLimitLen);
			if(l && l < 33) {
				char *tmp = s + 1;
				tmp[l - 1] = '\0';
				if(verbosity >= 2)
					syslog(LOG_NOTICE, "[%s] DTMF SIP INFO [%c]", call->fbasename, tmp[0]);
				call->handle_dtmf(*tmp, ts2double(header->ts.tv_sec, header->ts.tv_usec), saddr, daddr);
			}
			s = gettag(data, datalen, "Signal=", &l, &gettagLimitLen);
			if(l && l < 33) {
				char *tmp = s;
				tmp[l] = '\0';
				if(verbosity >= 2)
					syslog(LOG_NOTICE, "[%s] DTMF SIP INFO [%c]", call->fbasename, tmp[0]);
				call->handle_dtmf(*tmp, ts2double(header->ts.tv_sec, header->ts.tv_usec), saddr, daddr);

			}
		}
		
		// check if we have X-VoipMonitor-Custom1
		s = gettag(data, datalen, "\nX-VoipMonitor-Custom1:", &l, &gettagLimitLen);
		if(l && l < 255) {
			memcpy(call->custom_header1, s, l);
			call->custom_header1[l] = '\0';
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen X-VoipMonitor-Custom1: %s\n", call->custom_header1);
		}

		// check if we have opt_match_header
		if(opt_match_header[0] != '\0') {
			s = gettag(data, datalen, opt_match_header, &l, &gettagLimitLen);
			if(l && l < 128) {
				memcpy(call->match_header, s, l);
				call->match_header[l] = '\0';
				if(verbosity > 2)
					syslog(LOG_NOTICE, "Seen header %s: %s\n", opt_match_header, call->match_header);
			}
		}
	
		// check if we have custom headers
		process_packet__parse_custom_headers(call, data, datalen);
		
		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0 && header->ts.tv_sec + 5 > call->destroy_call_at) {
			call->destroy_call_at = header->ts.tv_sec + 5; 
		}

		// SDP examination
		s = gettag(data,datalen,"\nContent-Type:",&l,&gettagLimitLen);
		if(l <= 0 || l > 1023) {
			//try compact header
			s = gettag(data,datalen,"\nc:",&l,&gettagLimitLen);
		}

		char a = data[datalen - 1];
		data[datalen - 1] = 0;
		char t;
		char *sl;

		if(!(s and l > 0)) {
			goto notfound;
		}

		sl = &s[l];
		t = *sl;
		*sl = '\0';
		// Content-Type found 
		if(call->type == MESSAGE && call->message == NULL) {
			*sl = t;
			//find end of a message (\r\n)
			char *tmp = strstr(s, "\r\n\r\n");;
			if(!tmp) {
				goto notfound;
			}

			tmp += 4; // skip \r\n\r\n and point to start of the message
			int contentlen = 0;
			s = gettag(data, datalen, "\nContent-Length:", &l, &gettagLimitLen);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				char c = s[l];
				s[l] = '\0';
				contentlen = atoi(s);
				s[l] = c;
			}
			if(contentlen > 0) {
				char *end = strcasestr(tmp, "\n\nContent-Length:");
				if(!end) {
					end = strstr(tmp, "\r\n"); // strstr is safe becuse tmp ends with '\0'
					if(!end) {
						end = data + datalen;
					}
				}
				//truncate message to its size announced in content-length
				if(end - tmp > contentlen) {
					end = tmp + MIN(end - tmp, contentlen);
				}
				call->message = (char*)malloc(sizeof(char) * (end - tmp + 1));
				data[datalen - 1] = a;
				memcpy(call->message, tmp, end - tmp);
				call->message[end - tmp] = '\0';
			} else {
				call->message = (char*)malloc(sizeof(char) * 1);
				call->message[0] = '\0';
			}
			//printf("msg: contentlen[%d] datalen[%d] len[%d] [%s]\n", contentlen, datalen, strlen(call->message), call->message);

			if(call->contenttype) free(call->contenttype);
			call->contenttype = (char*)malloc(sizeof(char) * (l + 1));
			memcpy(call->contenttype, s, l);
			call->contenttype[l] = '\0';
		} else if(strcasestr(s, "application/sdp")) {
			*sl = t;
			// prepare User-Agent
			char *ua = NULL;
			unsigned long gettagLimitLen = 0, ua_len = 0;
			ua = gettag(data, datalen, "\nUser-Agent:", &ua_len, &gettagLimitLen);
			process_sdp(call, saddr, source, daddr, dest, s, (unsigned int)datalen - (s - data), header_ip, callidstr, ua, ua_len);
		} else if(strcasestr(s, "multipart/mixed")) {
			*sl = t;
			char *ua = NULL;
			unsigned long gettagLimitLen = 0, ua_len = 0;
			ua = gettag(data, datalen, "\nUser-Agent:", &ua_len, &gettagLimitLen);
			while(1) {
				//continue searching  for another content-type
				char *s2;
				s2 = gettag(s, (unsigned int)datalen - (s - data), "\nContent-Type:", &l, NULL);
				if(l <= 0 || l > 1023) {
					//try compact header
					s2 = gettag(s, (unsigned int)datalen - (s - data), "\nc:", &l, NULL);
				}
				if(s2 and l > 0) {
					//Content-Type found try if it is SDP 
					if(l > 0 && strcasestr(s2, "application/sdp")){
						process_sdp(call, saddr, source, daddr, dest, s2, (unsigned int)datalen - (s - data), header_ip, callidstr, ua, ua_len);
						break;	// stop searching
					} else {
						// it is not SDP continue searching for another content-type 
						s = s2;
						continue;
					}
				} else {
					break;
				}
			}
		} else {
			*sl = t;
		}

notfound:
		data[datalen - 1] = a;

		if(!disabledsave) {
			save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_SIP);
		}
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call);
		}
		return call;
	} else if ((call = calltable->hashfind_by_ip_port(daddr, dest, &iscaller, &is_rtcp, &is_fax))){
	//} else if ((call = calltable->mapfind_by_ip_port(daddr, dest, &iscaller, &is_rtcp))){
	// TODO: remove if hash will be stable
	//if ((call = calltable->find_by_ip_port(daddr, dest, &iscaller)))
		// packet (RTP) by destination:port is already part of some stored call 
		repeat = 0;
repeatrtpA:
		*voippacket = 1;

		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at = header->ts.tv_sec + 5; 
		}

		if(header->caplen > MAXPACKETLENQRING) {
			// packets larger than MAXPACKETLENQRING was created in special heap and is destroyd immediately after leaving this functino - thus do not queue it 
			// TODO: this can be enhanced by pasing flag that the packet should be freed
			can_thread = 0;
		}

		if(is_fax) {
			call->seenudptl = 1;
		}

		if(is_rtcp) {
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, daddr, source, iscaller, is_rtcp,
							block_store, block_store_index);
			} else {
				call->read_rtcp((unsigned char*) data, datalen, header, saddr, source, iscaller);
			}
			save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			if(logPacketSipMethodCall_enable) {
				logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call);
			}
			return call;
		}

		if(rtp_threaded && can_thread) {
			if(!((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl)) && (!dontsave && opt_saverfc2833)) {
				// if RTP is NOT saving but we still wants to save DTMF (rfc2833) and becuase RTP is going to be 
				// queued and processed later in async queue we must decode if the RTP packet is DTMF here 
				call->tmprtp.fill((unsigned char*)data, datalen, header, saddr, daddr); //TODO: datalen can be shortned to only RTP header len
				record = call->tmprtp.getPayload() == 101 ? 1 : 0;
			}
			add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, daddr, source, iscaller, is_rtcp,
						block_store, block_store_index);
			*was_rtp = 1;
			if(is_rtcp) {
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call);
				}
				return call;
			}
		} else {
			call->read_rtp((unsigned char*) data, datalen, header, saddr, daddr, source, iscaller, &record);
			call->set_last_packet_time(header->ts.tv_sec);
		}
		if(!dontsave && ((call->flags & FLAG_SAVERTPHEADER) || (call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record)) {
			if((call->silencerecording || (opt_onlyRTPheader && !(call->flags & FLAG_SAVERTP))) && !call->isfax) {
				tmp_u32 = header->caplen;
				header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
				header->caplen = tmp_u32;
			} else {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			}

		}

		if(call->relationcall and repeat == 0) {	
			repeat = 1;
			call = call->relationcall;
			goto repeatrtpA;
		}
	} else if ((call = calltable->hashfind_by_ip_port(saddr, source, &iscaller, &is_rtcp, &is_fax))){
	//} else if ((call = calltable->mapfind_by_ip_port(saddr, source, &iscaller, &is_rtcp))){
	// TODO: remove if hash will be stable
	// else if ((call = calltable->find_by_ip_port(saddr, source, &iscaller)))
		// packet (RTP[C]) by source:port is already part of some stored call 

		repeat = 0;
repeatrtpB:
		*voippacket = 1;

		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at = header->ts.tv_sec + 5; 
		}

		if(header->caplen > MAXPACKETLENQRING) {
			// packets larger than MAXPACKETLENQRING was created in special heap and is destroyd immediately after leaving this functino - thus do not queue it 
			// TODO: this can be enhanced by pasing flag that the packet should be freed
			can_thread = 0;
		}

		if(is_fax) {
			call->seenudptl = 1;
		}

		if(is_rtcp) {
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, daddr, source, !iscaller, is_rtcp,
							block_store, block_store_index);
			} else {
				call->read_rtcp((unsigned char*) data, datalen, header, saddr, source, !iscaller);
			}
			if(!dontsave && (opt_saveRTP || opt_saveRTCP)) {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			}
			if(logPacketSipMethodCall_enable) {
				logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call);
			}
			return call;
		}

		// as we are searching by source address and find some call, revert iscaller 
		if(rtp_threaded && can_thread) {
			add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, daddr, source, !iscaller, is_rtcp,
						block_store, block_store_index);
			if(!((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl)) && (!dontsave && opt_saverfc2833)) {
				// if RTP is NOT saving but we still wants to save DTMF (rfc2833) and becuase RTP is going to be 
				// queued and processed later in async queue we must decode if the RTP packet is DTMF here 
				call->tmprtp.fill((unsigned char*)data, datalen, header, saddr, daddr); //TODO: datalen can be shortned to only RTP header len
				record = call->tmprtp.getPayload() == 101 ? 1 : 0;
			}
			*was_rtp = 1;
		} else {
			call->read_rtp((unsigned char*) data, datalen, header, saddr, daddr, source, !iscaller, &record);
			call->set_last_packet_time(header->ts.tv_sec);
		}
		if(!dontsave && ((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record)) {
			if((call->silencerecording || (opt_onlyRTPheader && !(call->flags & FLAG_SAVERTP))) && !call->isfax) {
				tmp_u32 = header->caplen;
				header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
				header->caplen = tmp_u32;
			} else {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, TYPE_RTP);
			}
		}

		if(call->relationcall and repeat == 0) {	
			repeat = 1;
			call = call->relationcall;
			goto repeatrtpB;
		}
	// packet does not belongs to established call, check if it is on SIP port
	} else {
		if(opt_rtpnosip) {
			// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
			char s[256];
			RTP rtp;
			int rtpmap[MAX_RTPMAP];
			memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);

			rtp.read((unsigned char*)data, datalen, header, saddr, daddr, 0);

			if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call,
						"decoding RTP without SIP signaling is enabled (rtp.getVersion() != 2 && rtp.getPayload() > 18)");
				}
				return NULL;
			}
			snprintf(s, 4092, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

			//printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

			call = calltable->add(s, strlen(s), header->ts.tv_sec, saddr, source);
			call->set_first_packet_time(header->ts.tv_sec, header->ts.tv_usec);
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
				char pcapFilePath_spool_relative[1024];
				snprintf(pcapFilePath_spool_relative , 1023, "%s/%s.pcap", call->dirname().c_str(), call->get_fbasename_safe());
				pcapFilePath_spool_relative[1023] = 0;
				static char str2[1024];
				if(opt_cachedir[0] != '\0') {
					snprintf(str2, 1023, "%s/%s", opt_cachedir, pcapFilePath_spool_relative);
					str2[1023] = 0;
				} else {
					strcpy(str2, pcapFilePath_spool_relative);
				}
				if(call->getPcap()->open(str2, pcapFilePath_spool_relative)) {
					call->pcapfilename = pcapFilePath_spool_relative;
				}
			}

			if(verbosity > 3) {
				syslog(LOG_NOTICE,"pcap_filename: [%s]\n",str2);
			}

			call->add_ip_port(daddr, dest, s, l, 1, rtpmap);
			calltable->hashAdd(daddr, dest, call, 1, 0, 0);
			//calltable->mapAdd(daddr, dest, call, 1, 0, 0);

			call->add_ip_port(saddr, source, s, l, 0, rtpmap);
			calltable->hashAdd(saddr, source, call, 0, 0, 0);
			//calltable->mapAdd(saddr, source, call, 0, 0, 0);
			
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
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call,
				"we are not interested in this packet");
		}
		return NULL;
	}

	if(logPacketSipMethodCall_enable) {
		logPacketSipMethodCall(sip_method, lastSIPresponseNum, header, call,
			"---");
		}
	return NULL;
}

void process_packet__parse_custom_headers(Call *call, char *data, int datalen) {
	vector<dstring> *_customHeaders = call->type == MESSAGE ? &opt_custom_headers_message : &opt_custom_headers_cdr;
	size_t iCustHeaders;
	unsigned long gettagLimitLen = 0;
	for(iCustHeaders = 0; iCustHeaders < _customHeaders->size(); iCustHeaders++) {
		string findHeader = (*_customHeaders)[iCustHeaders][0];
		if(findHeader[findHeader.length() - 1] != ':') {
			findHeader.append(":");
		}
		unsigned long l;
		char *s = gettag(data, datalen, findHeader.c_str(), &l, &gettagLimitLen);
		if(l) {
			char customHeaderContent[256];
			memcpy(customHeaderContent, s, min(l, 255lu));
			customHeaderContent[min(l, 255lu)] = '\0';
			call->custom_headers.push_back(dstring((*_customHeaders)[iCustHeaders][1],customHeaderContent));
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen header %s: %s\n", (*_customHeaders)[iCustHeaders][0].c_str(), customHeaderContent);
		}
	}
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
	process_packet(addr->saddr, addr->source, addr->daddr, addr->dest, (char*)data, len, handle, nids_last_pcap_header, nids_last_pcap_data, 0, 0, 1, &was_rtp, NULL, &voippacket, 0);
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
	struct iphdr2 *header_ip;
	struct udphdr2 *header_udp;
	struct udphdr2 header_udp_tmp;
	struct tcphdr2 *header_tcp;
	char *data;
	int datalen;
	int istcp = 0;
	int res;
	int was_rtp;
	unsigned int packets = 0;
	bool useTcpReassembly;

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
				//printf("packets: [%u]\n", packets);
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

		header_ip = (struct iphdr2 *) ((char*)packet + pp->offset);

		if(header_ip->protocol == IPPROTO_IPIP) {
			// ip in ip protocol
			header_ip = (struct iphdr2 *) ((char*)header_ip + sizeof(iphdr2));
		} else if(header_ip->protocol == IPPROTO_GRE) {
			// gre protocol 
			struct gre_hdr *grehdr = (struct gre_hdr *)((char*)header_ip + sizeof(iphdr2));
			printf("[%d] [%d] [%x]\n", grehdr->version, grehdr->protocol, grehdr->protocol);
			exit(0);
		}

		header_udp = &header_udp_tmp;
		useTcpReassembly = false;
		if (header_ip->protocol == IPPROTO_UDP) {
			// prepare packet pointers 
			header_udp = (struct udphdr2 *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_udp + sizeof(*header_udp);
			datalen = (int)(pp->header.caplen - ((char*)data - (char*)packet)); 
			istcp = 0;
		} else if (header_ip->protocol == IPPROTO_TCP) {
			header_tcp = (struct tcphdr2 *) ((char *) header_ip + sizeof(*header_ip));
			// dokončit nezbytné paměťové operace pro udržení obsahu paketu !!!!
			// zatím reassemblování v módu bez pb zakázáno
			/*
			if(opt_enable_tcpreassembly && (httpportmatrix[htons(header_tcp->source)] || httpportmatrix[htons(header_tcp->dest)])) {
				tcpReassembly->push(&pp->header, header_ip, packet);
				
				useTcpReassembly = true;
			} else */{
				istcp = 1;
				// prepare packet pointers 
				data = (char *) header_tcp + (header_tcp->doff * 4);
				datalen = (int)(pp->header.caplen - ((char*)data - (char*)packet)); 
				header_udp->source = header_tcp->source;
				header_udp->dest = header_tcp->dest;
			}
		} else {
			//packet is not UDP and is not TCP, we are not interested, go to the next packet
			// - interested only for ipaccount
			if(opt_ipaccount) {
				ipaccount(pp->header.ts.tv_sec, (struct iphdr2 *) ((char*)(packet) + pp->offset), pp->header.len - pp->offset, false);
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
			continue;
		}

		if(opt_mirrorip && (sipportmatrix[htons(header_udp->source)] || sipportmatrix[htons(header_udp->dest)])) {
			mirrorip->send((char *)header_ip, (int)(pp->header.caplen - ((char*)header_ip - (char*)packet)));
		}
		int voippacket = 0;
		if(!useTcpReassembly || opt_enable_tcpreassembly != 2) {
			process_packet(header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
				data, datalen, handle, &pp->header, packet, istcp, 0, 1, &was_rtp, header_ip, &voippacket, 0,
				NULL, 0);
		}

		// if packet was VoIP add it to ipaccount
		if(opt_ipaccount) {
			ipaccount(pp->header.ts.tv_sec, (struct iphdr2 *) ((char*)(packet) + pp->offset), pp->header.len - pp->offset, voippacket);
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
	unsigned int additionallen = 0;
	iphdr2 *iphdr = NULL;

	int lastoffset = queue->begin()->second->offset;
	int i = 0;
	unsigned int len = 0;
	for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
		ip_frag_s *node = it->second;
		if(i == 0) {
			// for first packet copy ethernet header and ip header
			if(node->firstheaderlen) {
				memcpy(newpacket, node->firstheader, node->firstheaderlen);
				len += node->firstheaderlen;
				// reset fragment flag to 0
				((iphdr2 *)(node->packet))->frag_off = 0;
				iphdr = (iphdr2*)(newpacket + len);
			}
			memcpy(newpacket + len, node->packet, node->len);
			len += node->len;
		} else {
			// for rest of a packets append only data 
			if(len > totallen) {
				syslog(LOG_ERR, "%s.%d: Error - bug in voipmonitor len[%d] > totallen[%d]", __FILE__, __LINE__, len, totallen);
				abort();
			}
			memcpy(newpacket + len, node->packet + sizeof(iphdr2), node->len - sizeof(iphdr2));
			len += node->len - sizeof(iphdr2);
			additionallen += node->len - sizeof(iphdr2);
		}
		lastoffset = node->offset;
		free(node->packet);
		if(node->firstheader) {
			free(node->firstheader);
		}
		free(node);
		i++;
	}
	if(iphdr) {
		//increase IP header length 
		iphdr->tot_len = htons((ntohs(iphdr->tot_len)) + additionallen);
		// reset checksum
		iphdr->check = 0;
	}
	
	return 1;
}


int ipfrag_add(ip_frag_queue_t *queue, struct pcap_pkthdr *header, const u_char *packet, unsigned int len, struct pcap_pkthdr **origheader, u_char **origpacket) {

	unsigned int offset = ntohs(((iphdr2*)(packet))->frag_off);
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
		ip_frag_s *node = (ip_frag_s*)malloc(sizeof(ip_frag_s));

		if(queue->size()) {
			// update totallen for the first node 
			ip_frag_s *first = queue->begin()->second;
			first->totallen += len - sizeof(iphdr2); 
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
			ip_frag_s *node = it->second;
			if((node->offset != lastoffset)) {
				ok = false;
				break;
			}
			lastoffset += node->len - sizeof(iphdr2);
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
int handle_defrag(iphdr2 *header_ip, struct pcap_pkthdr **header, u_char **packet, int destroy, ipfrag_data_s *ipfrag_data) {
	if(!ipfrag_data) {
		ipfrag_data = &::ipfrag_data;
	}
 
	struct pcap_pkthdr *tmpheader = *header;
	u_char *tmppacket = *packet;


	//copy header ip to tmp beacuse it can happen that during exectuion of this function the header_ip can be 
	//overwriten in kernel ringbuffer if the ringbuffer is small and thus header_ip->saddr can have different value 
	iphdr2 header_ip2;
	memcpy(&header_ip2, header_ip, sizeof(iphdr2));

	// get queue from ip_frag_stream based on source ip address and ip->id identificator (2-dimensional map array)
	ip_frag_queue_t *queue = ipfrag_data->ip_frag_stream[header_ip2.saddr][header_ip2.id];
	if(!queue) {
		// queue does not exists yet - create it and assign to map 
		queue = new ip_frag_queue_t;
		ipfrag_data->ip_frag_stream[header_ip2.saddr][header_ip2.id] = queue;
	}
	int res = ipfrag_add(queue, *header, (u_char*)header_ip, ntohs(header_ip2.tot_len), header, packet);
	if(res) {
		// packet was created from all pieces - delete queue and remove it from map
		ipfrag_data->ip_frag_stream[header_ip2.saddr].erase(header_ip2.id);
		delete queue;
	};
	if(destroy) {
		// defrag was called with destroy=1 delete original packet and header which was replaced by new defragmented packet
		free(tmpheader);
		free(tmppacket);
	}
	return res;
}

void ipfrag_prune(unsigned int tv_sec, int all, ipfrag_data_s *ipfrag_data) {
	if(!ipfrag_data) {
		ipfrag_data = &::ipfrag_data;
	}
 
	ip_frag_queue_t *queue;
	for (ipfrag_data->ip_frag_streamIT = ipfrag_data->ip_frag_stream.begin(); ipfrag_data->ip_frag_streamIT != ipfrag_data->ip_frag_stream.end(); ipfrag_data->ip_frag_streamIT++) {
		for (ipfrag_data->ip_frag_streamITinner = (*ipfrag_data->ip_frag_streamIT).second.begin(); ipfrag_data->ip_frag_streamITinner != (*ipfrag_data->ip_frag_streamIT).second.end();) {
			queue = ipfrag_data->ip_frag_streamITinner->second;
			if(!queue->size()) {
				ipfrag_data->ip_frag_streamIT->second.erase(ipfrag_data->ip_frag_streamITinner++);
				delete queue;
				continue;
			}
			if(all or ((tv_sec - queue->begin()->second->ts) > (30))) {
				for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
					ip_frag_s *node = it->second;
					
					free(node->packet);
					if(node->firstheader) {
						free(node->firstheader);
					}
					free(node);
				}
				ipfrag_data->ip_frag_streamIT->second.erase(ipfrag_data->ip_frag_streamITinner++);
				delete queue;
				continue;
			}
			ipfrag_data->ip_frag_streamITinner++;
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
	struct iphdr2 *header_ip;
	struct udphdr2 *header_udp = NULL;
	struct udphdr2 header_udp_tmp;
	struct tcphdr2 *header_tcp = NULL;
	char *data = NULL;
	int datalen = 0;
	int res;
	int protocol = 0;
	unsigned int offset;
	int istcp = 0;
	int was_rtp;
	unsigned char md5[MD5_DIGEST_LENGTH];
	unsigned char *prevmd5s = NULL;
	int destroy = 0;
	unsigned int ipfrag_lastprune = 0;
	int traillen = 0;

	// Space to remember up to 65536 previous packet hashes.
	// We use 2 bytes of the md5 hash as the hash (index) by which we access this table.
	// there is no "overflow", so duplicates just overwrite the previous
	// therefore we won't actually remember the last 64k packets - it will be less and a little bit non-determinate
	// but the idea is to answer the question: "did we recently see a packet with this exact md5 hash" without needing a linear search
	if (opt_dup_check)
		prevmd5s = (unsigned char *)calloc(65536, MD5_DIGEST_LENGTH); // 1M

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

		header_ip = (struct iphdr2 *) ((char*)packet + offset);
		//if UDP defrag is enabled process only UDP packets and only SIP packets
		if(opt_udpfrag and (header_ip->protocol == IPPROTO_UDP or header_ip->protocol == 4)) {
			int foffset = ntohs(header_ip->frag_off);
			if ((foffset & IP_MF) or ((foffset & IP_OFFSET) > 0)) {
				// packet is fragmented
				if(handle_defrag(header_ip, &header, &packet, 0)) {
					// packets are reassembled
					header_ip = (struct iphdr2 *)((char*)packet + offset);
					destroy = true;
				} else {
					continue;
				}
			}
		}

headerip:
		if(header_ip->protocol == IPPROTO_IPIP) {
			header_ip = (struct iphdr2 *) ((char*)header_ip + sizeof(iphdr2));

			//if UDP defrag is enabled process only UDP packets and only SIP packets
			if(opt_udpfrag and header_ip->protocol == IPPROTO_UDP) {
				int foffset = ntohs(header_ip->frag_off);
				if ((foffset & IP_MF) or ((foffset & IP_OFFSET) > 0)) {
					// packet is fragmented
					if(handle_defrag(header_ip, &header, &packet, destroy)) {
						// packet was returned, turn off frag flag for both packets
						iphdr2 *header_ip_1 = (struct iphdr2 *)((char*)packet + offset);
						header_ip_1->frag_off = 0;

						// turn off frag for the second IP header 
						header_ip = (struct iphdr2 *) ((char*)header_ip_1 + sizeof(iphdr2));
						header_ip->frag_off = 0;

						// update lenght of the first ip header to the len of the second IP header since it can be changed due to reassemble
						header_ip_1->tot_len = htons((ntohs(header_ip->tot_len)) + sizeof(iphdr2)); 

						destroy = true;
					} else {
						continue;
					}
				}
			}
		} else if(header_ip->protocol == IPPROTO_GRE) {
			// gre protocol 
			char gre[8];
			uint16_t a, b;
			// if anyone know how to make network to hostbyte nicely, redesign this
			a = ntohs(*(uint16_t*)((char*)header_ip + sizeof(iphdr2)));
			b = ntohs(*(uint16_t*)((char*)header_ip + sizeof(iphdr2) + 2));
			memcpy(gre, &a, 2);
			memcpy(gre + 2, &b, 2);

			struct gre_hdr *grehdr = (struct gre_hdr *)gre;
			if(grehdr->version == 0 and grehdr->protocol == 0x6558) {
				header_eth = (struct ether_header *)((char*)header_ip + sizeof(iphdr2) + 8);
				if(header_eth->ether_type == 129) {
					// VLAN tag
					offset = 4;
					//XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
					protocol = *((char*)header_eth + 2);
				} else {
					offset = 0;
					protocol = header_eth->ether_type;
				}
				offset += sizeof(struct ether_header);
				header_ip = (struct iphdr2 *) ((char*)header_eth + offset);
				goto headerip;
			} else {
				if(destroy) { free(header); free(packet);};
				if(opt_ipaccount == 0) {
					continue;
				} else {
					goto skip;
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
			traillen = (int)(header->caplen - ((unsigned long) header_ip - (unsigned long) packet)) - ntohs(header_ip->tot_len);
			istcp = 0;
		} else if (header_ip->protocol == IPPROTO_TCP) {
			istcp = 1;
			// prepare packet pointers 
			header_tcp = (struct tcphdr2 *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_tcp + (header_tcp->doff * 4);
			datalen = (int)(header->caplen - ((unsigned long) data - (unsigned long) packet)); 
			//if (datalen == 0 || !(sipportmatrix[htons(header_tcp->source)] || sipportmatrix[htons(header_tcp->dest)])) {
			if (!(sipportmatrix[htons(header_tcp->source)] || sipportmatrix[htons(header_tcp->dest)]) &&
			    !(opt_enable_tcpreassembly && (httpportmatrix[htons(header_tcp->source)] || httpportmatrix[htons(header_tcp->dest)])) &&
			    !(opt_skinny && (htons(header_tcp->source) == 2000 || htons(header_tcp->dest) == 2000))) {
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

skip:
	
		if(datalen < 0) {
			if(destroy) { free(header); free(packet);};
			continue;
		}

		/* check for duplicate packets (md5 is expensive operation - enable only if you really need it */
		if(datalen > 0 && opt_dup_check && prevmd5s != NULL && (traillen < datalen) && 
		   !(istcp && opt_enable_tcpreassembly && (httpportmatrix[htons(header_tcp->source)] || httpportmatrix[htons(header_tcp->dest)]))) {
			MD5_Init(&ctx);
			if(opt_dup_check_ipheader) {
				// check duplicates based on full ip header and data 
				MD5_Update(&ctx, header_ip, MIN(datalen - ((char*)header_ip - data), ntohs(header_ip->tot_len)));
			} else {
				// check duplicates based only on data (without ip header and without UDP/TCP header). Duplicate packets 
				// will be matched regardless on IP 
				MD5_Update(&ctx, data, MAX(0, (unsigned long)datalen - traillen));
			}
			MD5_Final(md5, &ctx);
			if(memcmp(md5, prevmd5s+( ( (*(uint16_t *)md5) ) * MD5_DIGEST_LENGTH), MD5_DIGEST_LENGTH) == 0) {
				if(destroy) { free(header); free(packet); };
				//printf("dropping duplicate md5[%s]\n", md5);
				duplicate_counter++;
				continue;
			}
			memcpy(prevmd5s+( ( (*(uint16_t *)md5) ) * MD5_DIGEST_LENGTH), md5, MD5_DIGEST_LENGTH);
		}

		if(opt_pcapdump) {
			pcap_dump((u_char *)tmppcap, header, packet);
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
		int voippacket = 0;
		if(!opt_mirroronly) {
			process_packet(header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
				    data, datalen, handle, header, packet, istcp, 0, 1, &was_rtp, header_ip, &voippacket, 0,
				    NULL, 0);
		}
		if(opt_ipaccount) {
			ipaccount(header->ts.tv_sec, (struct iphdr2 *) ((char*)packet + offset), header->len - offset, voippacket);
		}


		if(destroy) { 
			free(header); 
			free(packet);
		}
	}

	if(opt_pcapdump) {
		pcap_dump_close(tmppcap);
	}

	if (prevmd5s) {
		free(prevmd5s);
	}
}

void logPacketSipMethodCall(int sip_method, int lastSIPresponseNum, pcap_pkthdr *header, Call *call, const char *descr) {
	if(!opt_read_from_file && descr && strstr(descr, "we are not interested")) {
		return;
	}
	
	const char *sipMethodStr[] = {
		"INVITE",	// 1
		"BYE",		// 2
		"CANCEL",	// 3
		"RES2XX",	// 4
		"RES3XX",	// 5
		"RES401",	// 6
		"RES403",	// 7
		"RES4XX",	// 8
		"RES5XX",	// 9
		"RES6XX",	// 10
		"RES18X",	// 11
		"REGISTER",	// 12
		"MESSAGE",	// 13
		"INFO",		// 14
		"SUBSCRIBE",	// 15
		"OPTIONS"	// 16
	};
	
	ostringstream outStr;

	outStr << "--- ";
	// ts
	outStr.width(10);
	outStr << sqlDateTimeString(header->ts.tv_sec) << " "
	       << header->ts.tv_sec << ".";
	outStr.width(6);
	outStr << header->ts.tv_usec << "  ";
	// sip metod
	outStr.width(10);
	if(sip_method > 0 && (unsigned)sip_method <= sizeof(sipMethodStr)/sizeof(sipMethodStr[0]))
		outStr << sipMethodStr[sip_method - 1];
	else
		outStr << sip_method;
	outStr << "  ";
	// calldate
	outStr.width(19);
	outStr << (call ? sqlDateTimeString(call->calltime()) : "") << "  ";
	// duration
	outStr.width(5);
	if(call)
		outStr << call->duration() << "s";
	else
		outStr << "" << " ";
	outStr << "  ";
	// caller
	outStr.width(15);
	outStr << (call ? call->caller : "") << "  ";
	// called
	outStr.width(15);
	outStr << (call ? call->called : "") << "  ";
	// lastSIPresponseNum
	outStr.width(3);
	outStr << lastSIPresponseNum << "  ";
	// fbasename
	outStr.width(40);
	outStr << (call ? call->fbasename : "") << "  ";
	// seenbye
	outStr << (call && call->seenbye ? "seenbye  " : "         ") << "  ";
	// destroy_call_at
	outStr.width(19);
	outStr << (call && call->destroy_call_at ? sqlDateTimeString(call->destroy_call_at): "") << "  ";
	// descr
	if(descr) outStr << descr;
	
	if(opt_read_from_file) {
		cout << outStr.str() << endl;
	} else {
		syslog(LOG_NOTICE, outStr.str().c_str());
	}
}
