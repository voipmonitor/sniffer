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
#include <iomanip>
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
#include "regcache.h"
#include "manager.h"
#include "fraud.h"
#include "send_call_info.h"

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

volatile unsigned int glob_last_packet_time;

Calltable *calltable;
extern volatile int calls_counter;
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
extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;
extern int opt_convert_dlt_sll_to_en10;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern pcap_t *global_pcap_handle;
extern pcap_t *global_pcap_handle_dead_EN10MB;
extern rtp_read_thread *rtp_threads;
extern int opt_norecord_dtmf;
extern int opt_onlyRTPheader;
extern int opt_sipoverlap;
extern int readend;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern char opt_match_header[128];
extern char opt_callidmerge_header[128];
extern char opt_callidmerge_secret[128];
extern int opt_domainport;
extern int opt_mirrorip;
extern int opt_mirrorall;
extern int opt_mirroronly;
extern char opt_scanpcapdir[2048];
extern int opt_ipaccount;
extern int opt_cdrproxy;
extern IPfilter *ipfilter;
extern IPfilter *ipfilter_reload;
extern volatile int ipfilter_reload_do;
extern TELNUMfilter *telnumfilter;
extern TELNUMfilter *telnumfilter_reload;
extern volatile int telnumfilter_reload_do;
extern DOMAINfilter *domainfilter;
extern DOMAINfilter *domainfilter_reload;
extern volatile int domainfilter_reload_do;
extern SIP_HEADERfilter *sipheaderfilter;
extern SIP_HEADERfilter *sipheaderfilter_reload;
extern volatile int sipheaderfilter_reload_do;
extern int rtp_threaded;
extern int opt_pcap_threaded;
extern int opt_rtpsave_threaded;
extern int opt_rtpnosip;
extern char opt_cachedir[1024];
extern int opt_savewav_force;
extern int opt_saveudptl;
extern nat_aliases_t nat_aliases;
extern pcap_packet *pcap_qring;
extern volatile unsigned int pcap_readit;
extern volatile unsigned int pcap_writeit;
extern unsigned int pcap_qring_max;
extern unsigned int pcap_qring_usleep;
extern int opt_enable_preprocess_packet;
extern unsigned int opt_preprocess_packets_qring_length;
extern unsigned int opt_preprocess_packets_qring_usleep;
extern unsigned int opt_process_rtp_packets_qring_length;
extern unsigned int opt_process_rtp_packets_qring_usleep;
extern unsigned int rtp_qring_usleep;
extern int opt_pcapdump;
extern int opt_id_sensor;
extern int opt_destination_number_mode;
extern int opt_update_dstnum_onanswer;
extern MySqlStore *sqlStore;
int global_pcap_dlink;
extern int opt_udpfrag;
extern int global_livesniffer;
extern int opt_pcap_split;
extern int opt_newdir;
extern int opt_callslimit;
extern int opt_skiprtpdata;
extern char opt_silencedmtfseq[16];
extern int opt_skinny;
extern int opt_read_from_file;
extern int opt_saverfc2833;
extern livesnifferfilter_use_siptypes_s livesnifferfilterUseSipTypes;
extern int opt_skipdefault;
extern TcpReassembly *tcpReassemblyHttp;
extern TcpReassembly *tcpReassemblyWebrtc;
extern TcpReassembly *tcpReassemblySsl;
extern char ifname[1024];
extern int opt_sdp_reverse_ipport;
extern int opt_fork;
extern regcache *regfailedcache;
extern ManagerClientThreads ClientThreads;
extern int opt_register_timeout;
extern int opt_nocdr;
extern int opt_enable_fraud;
extern int pcap_drop_flag;
extern int opt_hide_message_content;
extern int opt_remotepartyid;
extern int opt_remotepartypriority;
extern int opt_ppreferredidentity;
extern int opt_passertedidentity;
extern char cloud_host[256];
extern SocketSimpleBufferWrite *sipSendSocket;
extern int opt_sip_send_before_packetbuffer;
extern PreProcessPacket *preProcessPacket;
extern ProcessRtpPacket *processRtpPacket[MAX_PROCESS_RTP_PACKET_THREADS];
extern int opt_enable_process_rtp_packet;
extern CustomHeaders *custom_headers_cdr;
extern CustomHeaders *custom_headers_message;
unsigned int glob_ssl_calls = 0;

#ifdef QUEUE_MUTEX
extern sem_t readpacket_thread_semaphore;
#endif

char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen, unsigned long *limitLen = NULL,
	      ParsePacket *parsePacket = NULL);
static void logPacketSipMethodCall(u_int64_t packet_number, int sip_method, int lastSIPresponseNum, pcap_pkthdr *header, 
				   unsigned int saddr, int source, unsigned int daddr, int dest,
				   Call *call, const char *descr = NULL);
#define logPacketSipMethodCall_enable ((opt_read_from_file && verbosity > 2) || verbosityE > 1 || sverb.sip_packets)

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

TcpReassemblySip tcpReassemblySip;
ipfrag_data_s ipfrag_data;

u_int64_t counter_calls;
u_int64_t counter_sip_packets[2];
u_int64_t counter_sip_register_packets;
u_int64_t counter_sip_message_packets;
u_int64_t counter_rtp_packets;
u_int64_t counter_all_packets;

extern struct queue_state *qs_readpacket_thread_queue;

map<unsigned int, livesnifferfilter_t*> usersniffer;
volatile int usersniffer_sync;

#define ENABLE_CONVERT_DLT_SLL_TO_EN10(dlt)	(dlt == DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 && global_pcap_handle_dead_EN10MB)


#include "sniff_inline.h"


static unsigned long process_packet__last_cleanup = 0;
static unsigned long process_packet__last_filter_reload = 0;
static unsigned long process_packet__last_destroy_calls = 0;
static unsigned long preprocess_packet__last_cleanup = 0;


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

inline void save_packet_sql(Call *call, struct pcap_pkthdr *header, const u_char *packet, unsigned int saddr, int source, unsigned int daddr, int dest, int istcp, char *data, int datalen, int uid, int dlt, int sensor_id) {
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
	pcaphdr.network = ENABLE_CONVERT_DLT_SLL_TO_EN10(dlt) ? DLT_EN10MB : dlt;

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
	int id_sensor = sensor_id > 0 ? sensor_id : 0;
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
		", data = ";
	if(cloud_host[0]) {
		query << "concat('#', from_base64('" << base64_encode((unsigned char*)mpacket, len) << "'), '#')";
	} else {
		query << "'#" << _sqlEscapeString(mpacket, len, "mysql") << "#'";
	}
	sqlStore->query_lock(query.str().c_str(), STORE_PROC_ID_SAVE_PACKET_SQL);
	return;
}


/* 
	stores SIP messags to sql.livepacket based on user filters
*/

int get_sip_peername(char *data, int data_len, const char *tag, char *peername, unsigned int peername_len);

inline void save_live_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, unsigned int saddr, int source, unsigned int daddr, int dest, int istcp, char *data, int datalen, unsigned char sip_type, 
			     int dlt, int sensor_id) {
	if(!global_livesniffer) {
		return;
	}
	
	// check saddr and daddr filters
	daddr = htonl(daddr);
	saddr = htonl(saddr);

	while(__sync_lock_test_and_set(&usersniffer_sync, 1));
	
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
		if(!save) {
			bool okAddr = filter->state.all_addr;
			if(!okAddr) {
				for(int i = 0; i < MAXLIVEFILTERS && !okAddr; i++) {
					if((filter->state.all_saddr || (filter->lv_saddr[i] && 
						saddr == filter->lv_saddr[i])) &&
					   (filter->state.all_daddr || (filter->lv_daddr[i] && 
						daddr == filter->lv_daddr[i])) &&
					   (filter->state.all_bothaddr || (filter->lv_bothaddr[i] && 
						(saddr == filter->lv_bothaddr[i] || 
						 daddr == filter->lv_bothaddr[i])))) {
						okAddr = true;
					}
				}
			}
			bool okNum = filter->state.all_num;
			if(!okNum) {
				for(int i = 0; i < MAXLIVEFILTERS && !okNum; i++) {
					if((filter->state.all_srcnum || (filter->lv_srcnum[i][0] && 
						memmem(caller, strlen(caller), filter->lv_srcnum[i], strlen(filter->lv_srcnum[i])))) &&
					   (filter->state.all_dstnum || (filter->lv_dstnum[i][0] && 
						memmem(called, strlen(called), filter->lv_dstnum[i], strlen(filter->lv_dstnum[i])))) &&
					   (filter->state.all_bothnum || (filter->lv_bothnum[i][0] && 
						(memmem(caller, strlen(caller), filter->lv_bothnum[i], strlen(filter->lv_bothnum[i])) ||
						 memmem(called, strlen(called), filter->lv_bothnum[i], strlen(filter->lv_bothnum[i])))))) {
						okNum = true;
					}
				}
			}
			bool okSipType = filter->state.all_siptypes;
			if(!okSipType) {
				for(int i = 0; i < MAXLIVEFILTERS && !okSipType; i++) {
					if(filter->lv_siptypes[i] == sip_type) {
						okSipType = true;
					}
				}
			}
			if(okAddr && okNum && okSipType) {
				save = true;
			}
		}
		if(save) {
			save_packet_sql(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, usersnifferIT->first, 
					dlt, sensor_id);
		}
	}
	
	__sync_lock_release(&usersniffer_sync);
}

/*
   save packet into file 
   type - 1 is SIP, 2 is RTP, 3 is RTCP

*/
inline void save_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, 
			unsigned int saddr, int source, unsigned int daddr, int dest, 
			int istcp, iphdr2 *header_ip, char *data, unsigned int datalen, unsigned int dataoffset, int type, 
			int forceSip, int dlt, int sensor_id) {
	bool allocPacket = false;
	bool allocHeader = false;
	if(ENABLE_CONVERT_DLT_SLL_TO_EN10(dlt)) {
		const u_char *packet_orig = packet;
		pcap_pkthdr *header_orig = header;
		packet = (const u_char*) new FILE_LINE u_char[header_orig->caplen];
		memcpy((u_char*)packet, (u_char*)packet_orig, 14);
		memset((u_char*)packet, 0, 6);
		((ether_header*)packet)->ether_type = ((sll_header*)packet_orig)->sll_protocol;
		memcpy((u_char*)packet + 14, (u_char*)packet_orig + 16, header_orig->caplen - 16);
		header = new FILE_LINE pcap_pkthdr;
		memcpy(header, header_orig, sizeof(pcap_pkthdr));
		header->caplen -= 2;
		header->len -= 2;
		allocPacket = true;
		allocHeader = true;
	}
	unsigned int limitCapLen = 65535;
	if(dataoffset > 0 && dataoffset < 100 &&
	   ((call->type == MESSAGE && opt_hide_message_content) || 
	    (istcp && header->caplen > limitCapLen))) {
		unsigned long l;
		char *s = gettag(data, datalen, "\nContent-Length:", &l);
		if(l && l < datalen) {
			long int contentLength = atol(s);
			if(contentLength) {
				if(istcp &&
				   header->caplen > limitCapLen &&
				   (u_char*)header_ip > packet && 
				   (u_char*)header_ip - packet < 100) {
					u_int32_t diffLen = header->caplen - limitCapLen;
					header->caplen -= diffLen;
					header->len -= diffLen;
					header_ip->tot_len = htons(ntohs(header_ip->tot_len) - diffLen);
					contentLength -= diffLen;
					while(*s == ' ') {
						++s;
					}
					char contLengthStr[10];
					sprintf(contLengthStr, "%u", (unsigned int)contentLength);
					char *pointToModifyContLength = (char*)packet + dataoffset + (s - data); 
					strncpy(pointToModifyContLength, contLengthStr, strlen(contLengthStr));
					char *pointToEndModifyContLength = pointToModifyContLength + strlen(contLengthStr);
					while(*pointToEndModifyContLength != '\r') {
						*pointToEndModifyContLength = ' ';
						++pointToEndModifyContLength;
					}
				}
				if(call->type == MESSAGE && opt_hide_message_content) {
					char *endHeaderSepPos = (char*)memmem(data, datalen, "\r\n\r\n", 4);
					if(endHeaderSepPos) {
						const u_char *packet_orig = packet;
						packet = (const u_char*) new FILE_LINE u_char[header->caplen];
						memcpy((u_char*)packet, packet_orig, header->caplen);
						u_char *message = (u_char*)packet + dataoffset + (endHeaderSepPos - data) + 4;
						memset((u_char*)message, 'x', min(contentLength, (long int)(header->caplen - (message - packet))));
						allocPacket = true;
					}
				}
			}
		}
	}
 
	// check if it should be stored to mysql 
	if(type == TYPE_SIP and global_livesniffer and (sipportmatrix[source] || sipportmatrix[dest] || forceSip)) {
		save_live_packet(call, header, packet, saddr, source, daddr, dest, istcp, data, datalen, call->type, 
				 dlt, sensor_id);
	}

	if(opt_newdir and opt_pcap_split) {
		switch(type) {
		case TYPE_SKINNY:
		case TYPE_SIP:
			if(call->getPcapSip()->isOpen()){
				call->set_last_packet_time(header->ts.tv_sec);
				if(type == TYPE_SIP) {
					call->getPcapSip()->dump(header, packet, dlt, false, (u_char*)data, datalen, saddr, daddr, source, dest, istcp);
				} else {
					call->getPcapSip()->dump(header, packet, dlt);
				}
			}
			break;
		case TYPE_RTP:
		case TYPE_RTCP:
			if(call->getPcapRtp()->isOpen()){
				call->set_last_packet_time(header->ts.tv_sec);
				call->getPcapRtp()->dump(header, packet, dlt);
			} else {
				char pcapFilePath_spool_relative[1024];
				snprintf(pcapFilePath_spool_relative , 1023, "%s/%s/%s.pcap", call->dirname().c_str(), opt_newdir ? "RTP" : "", call->get_fbasename_safe());
				pcapFilePath_spool_relative[1023] = 0;
				char str2[1024];
				if(opt_cachedir[0] != '\0') {
					snprintf(str2, 1023, "%s/%s", opt_cachedir, pcapFilePath_spool_relative);
				} else {
					strcpy(str2, pcapFilePath_spool_relative);
				}
				if(call->getPcapRtp()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
					if(verbosity > 3) syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
					call->set_last_packet_time(header->ts.tv_sec);
					call->getPcapRtp()->dump(header, packet, dlt);
				}
			}
			break;
		}
	} else {
		if (call->getPcap()->isOpen()){
			call->set_last_packet_time(header->ts.tv_sec);
			if(type == TYPE_SIP) {
				call->getPcap()->dump(header, packet, dlt, false, (u_char*)data, datalen, saddr, daddr, source, dest, istcp);
			} else {
				call->getPcap()->dump(header, packet, dlt);
			}
		}
	}
	
	if(allocPacket) {
		delete [] packet;
	}
	if(allocHeader) {
		delete header;
	}
}

inline void save_sip_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, 
			    unsigned int saddr, int source, unsigned int daddr, int dest, 
			    int istcp, iphdr2 *header_ip, char *data, unsigned int sipDatalen, unsigned int dataoffset, int type, 
			    unsigned int datalen, unsigned int sipOffset,
			    int forceSip, int dlt, int sensor_id) {
	if(istcp && 
	   sipDatalen && (sipDatalen < datalen || sipOffset) &&
	   (unsigned)datalen + sipOffset < header->caplen) {
		bpf_u_int32  oldcaplen = header->caplen;
		bpf_u_int32  oldlen = header->len;
		u_int16_t oldHeaderIpLen = header_ip->tot_len;
		unsigned long datalenWithSipOffset = datalen + sipOffset;
		unsigned long diffLen = sipOffset + (datalen - sipDatalen);
		unsigned long newPacketLen = oldcaplen - diffLen;
		header->caplen -= diffLen;
		header->len -= diffLen;
		header_ip->tot_len = htons(ntohs(header_ip->tot_len) - diffLen);
		u_char *newPacket = new FILE_LINE u_char[newPacketLen];
		memcpy(newPacket, packet, oldcaplen - datalenWithSipOffset);
		memcpy(newPacket + (oldcaplen - datalenWithSipOffset), data, sipDatalen);
		iphdr2 *newHeaderIp = header_ip;
		if((u_char*)header_ip > packet && (u_char*)header_ip - packet < 100) {
			newHeaderIp = (iphdr2*)(newPacket + ((u_char*)header_ip - packet));
		}
		save_packet(call, header, newPacket, saddr, source, daddr, dest, istcp, newHeaderIp, data, sipDatalen, dataoffset, TYPE_SIP, 
			    forceSip, dlt, sensor_id);
		delete [] newPacket;
		header->caplen = oldcaplen;
		header->len = oldlen;
		header_ip->tot_len = oldHeaderIpLen;
	} else {
		save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, sipDatalen, dataoffset, TYPE_SIP, 
			    forceSip, dlt, sensor_id);
	}
}

ParsePacket _parse_packet_global;
ParsePacket *_parse_packet_process_packet;

int check_sip20(char *data, unsigned long len){
	if(len < 11) {
		return 0;
	}
	
	ParsePacket *parsePacket = NULL;
	if(_parse_packet_process_packet && _parse_packet_process_packet->getParseData() == data) {
		parsePacket = _parse_packet_process_packet;
	} else if(_parse_packet_global.getParseData() == data) {
		parsePacket = &_parse_packet_global;
	}
	if(parsePacket) {
		return(parsePacket->isSip());
	}
	
	int ok;
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
char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen, unsigned long *limitLen,
	      ParsePacket *parsePacket) {
 
	bool test_pp = false;
	
	const char *rc_pp = NULL;
	long l_pp;
	char _tag[1024];
	
	if(!parsePacket) {
		if(_parse_packet_process_packet && _parse_packet_process_packet->getParseData() == ptr) {
			parsePacket = _parse_packet_process_packet;
		} else if(_parse_packet_global.getParseData() == ptr) {
			parsePacket = &_parse_packet_global;
		}
	}
	if(parsePacket) {
		rc_pp = parsePacket->getContentData(tag, &l_pp);
		if((!rc_pp || l_pp <= 0) && tag[0] != '\n') {
			_tag[0] = '\n';
			strcpy(_tag + 1, tag);
			rc_pp = parsePacket->getContentData(_tag, &l_pp);
		}
		if(!test_pp) {
			if(rc_pp && l_pp > 0) {
				*gettaglen = l_pp;
				return((char*)rc_pp);
			} else {
				*gettaglen = 0;
				return(NULL);
			}
		}
	}
 
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
	if(!positionOK) {
		if(verbosity > 2 && l > 0) {
			char tagc[101];
			strncpy(tagc, rc, min(l, 100ul));
			tagc[min(l, 100ul)] = 0;
			syslog(LOG_NOTICE, "bad tag position - tag: %s, content: %s\n", tag, tagc);
		}
		*gettaglen = 0;
	} else {
		*gettaglen = l;
	}
	
	if(test_pp && rc && l) {
		if(_parse_packet_global.getParseData() == ptr) {
			//cout << "." << flush;
			string content = string(rc_pp, l_pp);
			string content2 = string(rc, l);
			while(content2.length() && content2[content2.length() - 1] == ' ') {
				content2.resize(content2.length() - 1);
			}
			if(content != content2) {
				cout << "GETTAG ERR " << tag << " :: " << content << " // " << string(rc, l) << endl;
				//cout << (char*)ptr << endl << endl << endl << endl;
			}
		} else {
			cout << "GETTAG --- " << tag << " :: " << string(rc, l) << endl;
		}
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
		if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "sips:", 4)) == 0){
			goto fail_exit;
		} else {
			r += 5;
		}
	} else {
		r += 4;
	}
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
		if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "sips:", 4)) == 0){
			goto fail_exit;
		} else {
			r += 4;
		}
	} else {
		r += 4;
	}
	
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
	unsigned long branch_tag_len;
	char *branch_tag = gettag(data, data_len, tag, &branch_tag_len);
	char *branchBegin = (char*)memmem(branch_tag, branch_tag_len, "branch=", 7);
	char *branchEnd;
	if(!branchBegin) {
		goto fail_exit;
	}
	branchBegin += 7;
	branchEnd = (char*)memmem(branchBegin, branch_tag_len - (branchBegin - branch_tag), ";", 1);
	if(!branchEnd) {
		branchEnd = branchBegin + branch_tag_len - (branchBegin - branch_tag);
	}
	if(branchEnd <= branchBegin || ((branchEnd - branchBegin) > branch_len)) {
		goto fail_exit;
	}
	memcpy(branch, branchBegin, MIN(branchEnd - branchBegin, branch_len));
	branch[MIN(branchEnd - branchBegin, branch_len - 1)] = '\0';
	return 0;
fail_exit:
	strcpy(branch, "");
	return 1;
}


int get_ip_port_from_sdp(char *sdp_text, in_addr_t *addr, unsigned short *port, int *fax, char *sessid){
	unsigned long l;
	char *s;
	char s1[20];
	size_t sdp_text_len = strlen(sdp_text);
	unsigned long gettagLimitLen = 0;

	*fax = 0;
	s = gettag(sdp_text,sdp_text_len, "o=", &l, &gettagLimitLen);
	if(l == 0) return 1;
	while(l > 0 && *s != ' ') {
		++s;
		--l;
	}
	if(l <= 1) return 1;
	++s;
	--l;
	unsigned long ispace = 0;
	char *space = s;
	while(ispace < l - 1 && *space != ' ') {
		++ispace;
		++space;
	}
	memset(sessid, 0, MAXLEN_SDP_SESSID);
	memcpy(sessid, s, MIN(ispace, MAXLEN_SDP_SESSID));
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
       else if(strcasecmp(mimeSubtype,"G7221") == 0)
	       return PAYLOAD_G7221;
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
       else if(strcasecmp(mimeSubtype,"X-OPUS") == 0)
	       return PAYLOAD_XOPUS;
       else if(strcasecmp(mimeSubtype,"AMR") == 0)
	       return PAYLOAD_AMR;
       else if(strcasecmp(mimeSubtype,"telephone-event") == 0)
	       return PAYLOAD_TELEVENT;
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
			if(mtype == PAYLOAD_G7221) {
				switch(rate) {
					case 8000:
						mtype = PAYLOAD_G72218;
						break;
					case 12000:
						mtype = PAYLOAD_G722112;
						break;
					case 16000:
						mtype = PAYLOAD_G722116;
						break;
					case 24000:
						mtype = PAYLOAD_G722124;
						break;
					case 32000:
						mtype = PAYLOAD_G722132;
						break;
					case 48000:
						mtype = PAYLOAD_G722148;
						break;
				}
			} else if(mtype == PAYLOAD_SILK) {
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
			} else if(mtype == PAYLOAD_XOPUS) {
				switch(rate) {
					case 8000:
						mtype = PAYLOAD_XOPUS8;
						break;
					case 12000:
						mtype = PAYLOAD_XOPUS12;
						break;
					case 16000:
						mtype = PAYLOAD_XOPUS16;
						break;
					case 24000:
						mtype = PAYLOAD_XOPUS24;
						break;
					case 48000:
						mtype = PAYLOAD_XOPUS48;
						break;
				}
			}
			rtpmap[i++] = mtype + 1000*codec;
			//printf("PAYLOAD: rtpmap[%d]:%d codec:%d, mimeSubtype [%d] [%s]\n", i, rtpmap[i], codec, mtype, mimeSubtype);
		}
		// return '\r' into sdp_text
		*z = '\r';
	 } while(l && i < (MAX_RTPMAP - 2));
	 rtpmap[i] = 0; //terminate rtpmap field
	 return 0;
}

void add_to_rtp_thread_queue(Call *call, unsigned char *data, int datalen, int dataoffset, struct pcap_pkthdr *header,  u_int32_t saddr, u_int32_t daddr, unsigned short sport, unsigned short dport, int iscaller, int is_rtcp,
			     pcap_block_store *block_store, int block_store_index, 
			     int enable_save_packet, const u_char *packet, char istcp, int dlt, int sensor_id,
			     int preSyncRtp) {
	#if RTP_PROF
	unsigned long long __prof_begin = rdtsc();
	#endif
 
	if(terminating) {
		return;
	}
	
	if(!preSyncRtp) {
		#if SYNC_CALL_RTP
		__sync_add_and_fetch(&call->rtppcaketsinqueue, 1);
		#else
		++call->rtppcaketsinqueue_p;
		#endif
	}
	
	rtp_read_thread *params = &(rtp_threads[call->thread_num]);

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
	rtp_packet *rtpp = new FILE_LINE rtp_packet;
	rtpp->data = new FILE_LINE unsigned char[datalen];
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
		if(block_store) {
			block_store->lock_packet(block_store_index);
		}
		if(params->rtpp_queue_quick ||
		   params->rtpp_queue_quick_boost) {
			rtp_packet_pcap_queue rtpp_pq;
			rtpp_pq.call = call;
			rtpp_pq.saddr = saddr;
			rtpp_pq.daddr = daddr;
			rtpp_pq.sport = sport;
			rtpp_pq.dport = dport;
			rtpp_pq.iscaller = iscaller;
			rtpp_pq.is_rtcp = is_rtcp;
			rtpp_pq.save_packet = enable_save_packet;
			rtpp_pq.packet = packet;
			rtpp_pq.istcp = istcp;
			rtpp_pq.dlt = dlt;
			rtpp_pq.sensor_id = sensor_id;
			rtpp_pq.data = data;
			rtpp_pq.datalen = datalen;
			rtpp_pq.dataoffset = dataoffset;
			rtpp_pq.header = *header;
			rtpp_pq.block_store = block_store;
			rtpp_pq.block_store_index =block_store_index;
			if(params->rtpp_queue_quick) {
				params->rtpp_queue_quick->push(&rtpp_pq, true, opt_enable_process_rtp_packet > 1);
			} else {
				params->rtpp_queue_quick_boost->push(&rtpp_pq, true, opt_enable_process_rtp_packet > 1);
			}
		} else {
			params->rtpp_queue->lock();
			rtp_packet_pcap_queue *rtpp_pq;
			while((rtpp_pq = params->rtpp_queue->push_get_pointer()) == NULL) {
				usleep(10);
			}
			rtpp_pq->call = call;
			rtpp_pq->saddr = saddr;
			rtpp_pq->daddr = daddr;
			rtpp_pq->sport = sport;
			rtpp_pq->dport = dport;
			rtpp_pq->iscaller = iscaller;
			rtpp_pq->is_rtcp = is_rtcp;
			rtpp_pq->save_packet = enable_save_packet;
			rtpp_pq->packet = packet;
			rtpp_pq->istcp = istcp;
			rtpp_pq->dlt = dlt;
			rtpp_pq->sensor_id = sensor_id;
			rtpp_pq->data = data;
			rtpp_pq->datalen = datalen;
			rtpp_pq->dataoffset = dataoffset;
			rtpp_pq->header = *header;
			rtpp_pq->block_store = block_store;
			rtpp_pq->block_store_index =block_store_index;
			params->rtpp_queue->unlock();
		}
	} else {
		rtpp->call = call;
		rtpp->datalen = datalen;
		rtpp->dataoffset = dataoffset;
		rtpp->saddr = saddr;
		rtpp->daddr = daddr;
		rtpp->sport = sport;
		rtpp->dport = dport;
		rtpp->iscaller = iscaller;
		rtpp->is_rtcp = is_rtcp;
		rtpp->save_packet = enable_save_packet;
		rtpp->packet = packet;
		rtpp->istcp = istcp;
		rtpp->dlt = dlt;
		rtpp->sensor_id = sensor_id;

		memcpy(&rtpp->header, header, sizeof(struct pcap_pkthdr));
		memcpy(&rtpp->header_ip, (struct iphdr2*)(data - sizeof(struct iphdr2) - sizeof(udphdr2)), sizeof(struct iphdr2));
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

	#if RTP_PROF
	if(preSyncRtp) {
		processRtpPacket[preSyncRtp - 1]->__prof__add_to_rtp_thread_queue += rdtsc() - __prof_begin;
	}
	#endif
}


void *rtp_read_thread_func(void *arg) {
	rtp_packet *rtpp = NULL;
	rtp_packet_pcap_queue rtpp_pq;
	rtp_read_thread *params = (rtp_read_thread*)arg;
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
			usleep(rtp_qring_usleep);
			continue;
		};
#endif 

#ifdef QUEUE_NONBLOCK2
		if(opt_pcap_queue) {
			if(params->rtpp_queue_quick) {
				if(!params->rtpp_queue_quick->pop(&rtpp_pq, true) &&
				   terminating) {
					return(NULL);
				}
			} else if(params->rtpp_queue_quick_boost) {
				if(!params->rtpp_queue_quick_boost->pop(&rtpp_pq, true) &&
				   terminating) {
					return(NULL);
				}
			} else {
				if(!params->rtpp_queue->pop(&rtpp_pq, true)) {
					if(terminating || readend) {
						return NULL;
					}
					// no packet to read, wait and try again
					usleep(rtp_qring_usleep);
					continue;
				}
			}
		} else {
		
			if(params->vmbuffer[params->readit % params->vmbuffermax].free == 1) {
				if(terminating || readend) {
					return NULL;
				}
				// no packet to read, wait and try again
				usleep(rtp_qring_usleep);
				continue;
			} else {
				rtpp = &(params->vmbuffer[params->readit % params->vmbuffermax]);
			}
		}
#endif

		if(opt_pcap_queue) {
			if(rtpp_pq.is_rtcp) {
				rtpp_pq.call->read_rtcp(rtpp_pq.data, rtpp_pq.datalen, rtpp_pq.dataoffset, &rtpp_pq.header, rtpp_pq.saddr, rtpp_pq.daddr, rtpp_pq.sport, rtpp_pq.dport, rtpp_pq.iscaller,
							rtpp_pq.save_packet, rtpp_pq.packet, rtpp_pq.istcp, rtpp_pq.dlt, rtpp_pq.sensor_id);
			}  else {
				int monitor;
				rtpp_pq.call->read_rtp(rtpp_pq.data, rtpp_pq.datalen, rtpp_pq.dataoffset, &rtpp_pq.header, NULL, rtpp_pq.saddr, rtpp_pq.daddr, rtpp_pq.sport, rtpp_pq.dport, rtpp_pq.iscaller, &monitor,
						       rtpp_pq.save_packet, rtpp_pq.packet, rtpp_pq.istcp, rtpp_pq.dlt, rtpp_pq.sensor_id,
						       rtpp_pq.block_store && rtpp_pq.block_store->ifname[0] ? rtpp_pq.block_store->ifname : NULL);
			}
			rtpp_pq.call->set_last_packet_time(rtpp_pq.header.ts.tv_sec);
			if(rtpp_pq.block_store) {
				rtpp_pq.block_store->unlock_packet(rtpp_pq.block_store_index);
			}
		} else {
			if(rtpp->is_rtcp) {
				rtpp->call->read_rtcp((unsigned char*)rtpp->data, rtpp->datalen, rtpp->dataoffset, &rtpp->header, rtpp->saddr, rtpp->daddr, rtpp->sport, rtpp->dport, rtpp->iscaller,
						      rtpp->save_packet, rtpp->packet, rtpp->istcp, rtpp->dlt, rtpp->sensor_id);
			}  else {
				int monitor;
				rtpp->call->read_rtp(rtpp->data, rtpp->datalen, rtpp->dataoffset, &rtpp->header, &rtpp->header_ip, rtpp->saddr, rtpp->daddr, rtpp->sport, rtpp->dport, rtpp->iscaller, &monitor,
						     rtpp->save_packet, rtpp->packet, rtpp->istcp, rtpp->dlt, rtpp->sensor_id);
			}
			rtpp->call->set_last_packet_time(rtpp->header.ts.tv_sec);
		}

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
		delete [] rtpp->data;
		delete rtpp;
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
			#if SYNC_CALL_RTP
			__sync_sub_and_fetch(&rtpp_pq.call->rtppcaketsinqueue, 1);
			#else
			++rtpp_pq.call->rtppcaketsinqueue_m;
			#endif
		} else {
			#if SYNC_CALL_RTP
			__sync_sub_and_fetch(&rtpp->call->rtppcaketsinqueue, 1);
			#else
			++rtpp->call->rtppcaketsinqueue_m;
			#endif
		}

	}
	
	return NULL;
}

Call *new_invite_register(bool is_ssl, int sip_method, char *data, int datalen, struct pcap_pkthdr *header, char *callidstr, u_int32_t saddr, u_int32_t daddr, int source, int dest,
			  pcap_t *handle, int dlt, int sensor_id,
			  bool *detectUserAgent,
			  ParsePacket *parsePacket){
 
	unsigned long gettagLimitLen = 0;
	unsigned int flags = 0;
	int res;
	bool anonymous_useRemotePartyID = false;
	bool anonymous_usePPreferredIdentity = false;
	bool anonymous_usePAssertedIdentity = false;
	bool anonymous_useFrom = false;
	bool caller_useRemotePartyID = false;
	bool caller_usePPreferredIdentity = false;
	bool caller_usePAssertedIdentity = false;
	bool caller_useFrom = false;

	if(opt_callslimit != 0 and opt_callslimit < calls_counter) {
		if(verbosity > 0)
			syslog(LOG_NOTICE, "callslimit[%d] > calls[%d] ignoring call\n", opt_callslimit, calls_counter);
		return NULL;
	}

	//caller and called number has to be checked before flags due to skip filter
	char tcaller[1024] = "", tcalled[1024] = "";

	if (opt_ppreferredidentity || opt_remotepartyid || opt_passertedidentity) {
		if (opt_remotepartypriority && opt_remotepartyid) {
			//Caller number is taken from headers (in this order) Remote-Party-ID,P-Asserted-Identity,P-Preferred-Identity,From,F
			if(!get_sip_peername(data,datalen,"\nRemote-Party-ID:", tcaller, sizeof(tcaller)) &&
			  tcaller[0] != '\0') {
				caller_useRemotePartyID = true;
			} else {
				if(opt_passertedidentity && !get_sip_peername(data,datalen,"\nP-Assserted-Identity:", tcaller, sizeof(tcaller)) &&
				  tcaller[0] != '\0') {
					caller_usePAssertedIdentity = true;
				} else {
					if(opt_ppreferredidentity && !get_sip_peername(data,datalen,"\nP-Preferred-Identity:", tcaller, sizeof(tcaller)) &&
					  tcaller[0] != '\0') {
						caller_usePPreferredIdentity = true;
					} else {
						caller_useFrom = true;
						if(!get_sip_peername(data,datalen,"\nFrom:", tcaller, sizeof(tcaller)) &&
						  tcaller[0] != '\0') {
							get_sip_peername(data,datalen,"\nf:", tcaller, sizeof(tcaller));
						}
					}
				}
			}
		} else {
			//Caller number is taken from headers (in this order) P-Asserted-Identity, P-Preferred-Identity, Remote-Party-ID,From, F
			if(opt_passertedidentity && !get_sip_peername(data,datalen,"\nP-Asserted-Identity:", tcaller, sizeof(tcaller)) &&
			  tcaller[0] != '\0') {
				caller_usePAssertedIdentity = true;
			} else {
				if(opt_ppreferredidentity && !get_sip_peername(data,datalen,"\nP-Preferred-Identity:", tcaller, sizeof(tcaller)) &&
				  tcaller[0] != '\0') {
					caller_usePPreferredIdentity = true;
				} else {
					if(opt_remotepartyid && !get_sip_peername(data,datalen,"\nRemote-Party-ID:", tcaller, sizeof(tcaller)) &&
					  tcaller[0] != '\0') {
						caller_useRemotePartyID = true;
					} else {
						caller_useFrom =  true;
						if(get_sip_peername(data,datalen,"\nFrom:", tcaller, sizeof(tcaller)) ||
						  tcaller[0] == '\0') {
							get_sip_peername(data,datalen,"\nf:", tcaller, sizeof(tcaller));
						}
					}
				}
			}
		}
	} else {
		//Caller is taken from header From , F
		caller_useFrom =  true;
		if(get_sip_peername(data,datalen,"\nFrom:", tcaller, sizeof(tcaller)) ||
		  tcaller[0] == '\0') {
			get_sip_peername(data,datalen,"\nf:", tcaller, sizeof(tcaller));
		}
	}

	if (caller_useFrom && !strcasecmp(tcaller, "anonymous")) {
		//if caller is anonymous
		if (opt_remotepartypriority && !get_sip_peername(data,datalen,"\nRemote-Party-ID:", tcaller, sizeof(tcaller)) &&
		  tcaller[0] != '\0') {
			anonymous_useRemotePartyID = true;
		} else {
			if(opt_passertedidentity && !get_sip_peername(data,datalen,"\nP-Asserted-Identity:", tcaller, sizeof(tcaller)) &&
			  tcaller[0] != '\0') {
				anonymous_usePAssertedIdentity = true;
			} else {
				if(opt_ppreferredidentity && !get_sip_peername(data,datalen,"\nP-Preferred-Identity:", tcaller, sizeof(tcaller)) &&
				  tcaller[0] != '\0') {
					anonymous_usePPreferredIdentity = true;
				} else {
					if (!opt_remotepartypriority && !get_sip_peername(data,datalen,"\nRemote-Party-ID:", tcaller, sizeof(tcaller)) &&
					  tcaller[0] != '\0') {
						anonymous_useRemotePartyID = true;
					} else {
						anonymous_useFrom = true;
					}
				}
			}
		}
	}

	// called number
	res = get_sip_peername(data,datalen,"\nTo:", tcalled, sizeof(tcalled));
	if(res) {
		// try compact header
		get_sip_peername(data,datalen,"\nt:", tcalled, sizeof(tcalled));
	}
	if(sip_method == INVITE && opt_destination_number_mode == 2) {
		char tcalled_invite[1024] = "";
		if(!get_sip_peername(data,datalen,"INVITE ", tcalled_invite, sizeof(tcalled_invite)) &&
		   tcalled_invite[0] != '\0') {
			strncpy(tcalled, tcalled_invite, sizeof(tcalled));
		}
	}
	
	//caller and called domain has to be checked before flags due to skip filter 
	char tcaller_domain[1024] = "", tcalled_domain[1024] = "";
	// caller domain 
	if(anonymous_useFrom || caller_useFrom) {
		res = get_sip_domain(data,datalen,"\nFrom:", tcaller_domain, sizeof(tcaller_domain));
		if(res) {
			// try compact header
			get_sip_domain(data,datalen,"\nf:", tcaller_domain, sizeof(tcaller_domain));
		}
	} else {
		if(anonymous_useRemotePartyID || caller_useRemotePartyID) {
			get_sip_domain(data,datalen,"\nRemote-Party-ID:", tcaller_domain, sizeof(tcaller_domain));
		} else {
			if (anonymous_usePPreferredIdentity || caller_usePPreferredIdentity) {
				get_sip_domain(data,datalen,"\nP-Preferred-Identity:", tcaller_domain, sizeof(tcaller_domain));
			} else {
				if (anonymous_usePAssertedIdentity || caller_usePAssertedIdentity) {
					get_sip_domain(data,datalen,"\nP-Asserted-Identity:", tcaller_domain, sizeof(tcaller_domain));
				}
			}
		}
	}

	// called domain 
	res = get_sip_domain(data,datalen,"\nTo:", tcalled_domain, sizeof(tcalled_domain));
	if(res) {
		// try compact header
		get_sip_domain(data,datalen,"\nt:", tcalled_domain, sizeof(tcalled_domain));
	}
	if(sip_method == INVITE && opt_destination_number_mode == 2) {
		char tcalled_domain_invite[256] = "";
		get_sip_domain(data,datalen,"INVITE ", tcalled_domain_invite, sizeof(tcalled_domain_invite));
		if(tcalled_domain_invite[0] != '\0') {
			strncpy(tcalled_domain, tcalled_domain_invite, sizeof(tcalled_domain));
		}
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

	if(opt_hide_message_content)
		flags |= FLAG_HIDEMESSAGE;

	ipfilter->add_call_flags(&flags, ntohl(saddr), ntohl(daddr));
	telnumfilter->add_call_flags(&flags, tcaller, tcalled);
	domainfilter->add_call_flags(&flags, tcaller_domain, tcalled_domain);
	sipheaderfilter->add_call_flags(parsePacket, &flags, tcaller_domain, tcalled_domain);

	if(flags & FLAG_SKIPCDR) {
		if(verbosity > 1)
			syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
		return NULL;
	}


	static char str2[1024];
	if(is_ssl) {
		glob_ssl_calls++;
	}
	// store this call only if it starts with invite
	Call *call = calltable->add(callidstr, min(strlen(callidstr), (size_t)MAX_FNAME), header->ts.tv_sec, saddr, source, handle, dlt, sensor_id);
	call->chantype = CHAN_SIP;
	call->is_ssl = is_ssl;
	call->set_first_packet_time(header->ts.tv_sec, header->ts.tv_usec);
	call->sipcallerip[0] = saddr;
	call->sipcalledip[0] = daddr;
	call->sipcallerport = source;
	call->sipcalledport = dest;
	call->type = sip_method;
	call->flags = flags;
	call->lastsrcip = saddr;
	strncpy(call->fbasename, callidstr, MAX_FNAME - 1);
	call->fbasename[MIN(strlen(callidstr), MAX_FNAME - 1)] = '\0';
	call->msgcount++;

	char *s;
	unsigned long l;
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
		if (caller_useFrom) {
			//try from header
			res = get_sip_peercnam(data,datalen,"\nFrom:", call->callername, sizeof(call->callername));
			if(res) {
				// try compact header
				get_sip_peercnam(data,datalen,"\nf:", call->callername, sizeof(call->callername));
			}
		} else {
			if (caller_useRemotePartyID) {
				//try Remote-Party-ID
				res = get_sip_peercnam(data,datalen,"\nRemote-Party-ID:", call->callername, sizeof(call->callername));
				if (res) {
				}
			} else {
				if (caller_usePPreferredIdentity) {
					//try P-Preferred-Identity
					res = get_sip_peercnam(data,datalen,"\nP-Preferred-Identity:", call->callername, sizeof(call->callername));
				} else {
					if (caller_usePAssertedIdentity) {
						//try P-Asserted-Identity
						res = get_sip_peercnam(data,datalen,"\nP-Asserted-Identity:", call->callername, sizeof(call->callername));
					} else {
						if(anonymous_useRemotePartyID || anonymous_usePPreferredIdentity || anonymous_usePAssertedIdentity) {
							strcpy(call->callername, "anonymous");
						}
					}
				}
			}
		}

		// caller number
		strncpy(call->caller, tcaller, sizeof(call->caller));

		// called number
		strncpy(call->called, tcalled, sizeof(call->called));

		// caller domain 
		strncpy(call->caller_domain, tcaller_domain, sizeof(call->caller_domain));

		// called domain 
		strncpy(call->called_domain, tcalled_domain, sizeof(call->called_domain));

		if(sip_method == REGISTER) {	
			// destroy all REGISTER from memory within 30 seconds 
			call->regcount++;
			call->destroy_call_at = header->ts.tv_sec + opt_register_timeout;

			// copy contact num <sip:num@domain>
			s = gettag(data, datalen, "\nUser-Agent:", &l, &gettagLimitLen);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
				call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
				if(sverb.set_ua) {
					cout << "set a_ua " << call->a_ua << endl;
				}
			}
			if(detectUserAgent) {
				*detectUserAgent = true;
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
		if(opt_enable_fraud) {
			fraudBeginCall(call, header->ts);
		}
		++counter_calls;
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
		extern int opt_defer_create_spooldir;
		if(!opt_defer_create_spooldir) {
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
			if(call->getPcapSip()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
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
			if(call->getPcapSip()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
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
			if(call->getPcap()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
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

void process_sdp(Call *call, int sip_method, unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, struct iphdr2 *header_ip, char *callidstr, char *ua, unsigned int ua_len){
	char *tmp = strstr(data, "\r\n\r\n");
	if(!tmp) return;

	in_addr_t tmp_addr;
	unsigned short tmp_port;
	int rtpmap[MAX_RTPMAP];
	memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);
	int fax;
	char sessid[MAXLEN_SDP_SESSID];
	if (!get_ip_port_from_sdp(tmp + 1, &tmp_addr, &tmp_port, &fax, sessid)){
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

			int iscalled;
			call->handle_dscp(sip_method, header_ip, saddr, daddr, &iscalled, true);
			//syslog(LOG_ERR, "ADDR: %u port %u iscalled[%d]\n", tmp_addr, tmp_port, iscalled);
		
			call->add_ip_port_hash(saddr, tmp_addr, tmp_port, sessid, ua, ua_len, !iscalled, rtpmap, fax);
			// check if the IP address is listed in nat_aliases
			in_addr_t alias = 0;
			if((alias = match_nat_aliases(tmp_addr)) != 0) {
				call->add_ip_port_hash(saddr, alias, tmp_port, sessid, ua, ua_len, !iscalled, rtpmap, fax);
			}
			if(opt_sdp_reverse_ipport) {
				call->add_ip_port_hash(saddr, saddr, tmp_port, sessid, ua, ua_len, !iscalled, rtpmap, fax);
			}
		}
	} else {
		if(verbosity >= 2){
			syslog(LOG_ERR, "callid[%s] Can't get ip/port from SDP:\n%s\n\n", callidstr, tmp + 1);
		}
	}
}

static void process_packet__parse_custom_headers(Call *call, char *data, int datalen);
static void process_packet__cleanup(pcap_pkthdr *header, pcap_t *handle);
static int process_packet__parse_sip_method(char *data, unsigned int datalen);
static int parse_packet__last_sip_response(char *data, unsigned int datalen, int sip_method,
					   char *lastSIPresponse, bool *call_cancel_lsr487);

Call *process_packet(bool is_ssl, u_int64_t packet_number,
		     unsigned int saddr, int source, unsigned int daddr, int dest, 
		     char *data, int datalen, int dataoffset,
		     pcap_t *handle, pcap_pkthdr *header, const u_char *packet, 
		     int istcp, int *was_rtp, struct iphdr2 *header_ip, int *voippacket, int forceSip,
		     pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id, 
		     bool mainProcess = true, int sipOffset = 0,
		     PreProcessPacket::packet_parse_s *parsePacket = NULL) {

	glob_last_packet_time = header->ts.tv_sec;
	Call *call = NULL;
	int iscaller;
	int is_rtcp = 0;
	int is_fax = 0;
	char *s;
	unsigned long l;
	char callidstr[1024],str2[1024];
	int sip_method = 0;
	char lastSIPresponse[128];
	int lastSIPresponseNum = 0;
	unsigned int tmp_u32 = 0;
	int record = 0;
	unsigned long gettagLimitLen = 0;
	hash_node_call *calls, *node_call;
	bool detectUserAgent = false;
	bool call_cancel_lsr487 = false;

	if (header->ts.tv_sec - process_packet__last_filter_reload > 1){
		if(ipfilter_reload_do) {
			IPfilter::lock_sync();
			delete ipfilter;
			ipfilter = ipfilter_reload;
			ipfilter_reload = NULL;
			ipfilter_reload_do = 0; 
			IPfilter::unlock_sync();
		}
		if(telnumfilter_reload_do) {
			TELNUMfilter::lock_sync();
			delete telnumfilter;
			telnumfilter = telnumfilter_reload;
			telnumfilter_reload = NULL;
			telnumfilter_reload_do = 0; 
			TELNUMfilter::unlock_sync();
		}
		if(domainfilter_reload_do) {
			DOMAINfilter::lock_sync();
			delete domainfilter;
			domainfilter = domainfilter_reload;
			domainfilter_reload = NULL;
			domainfilter_reload_do = 0; 
			DOMAINfilter::unlock_sync();
		}
		if(sipheaderfilter_reload_do) {
			SIP_HEADERfilter::lock_sync();
			delete sipheaderfilter;
			sipheaderfilter = sipheaderfilter_reload;
			sipheaderfilter_reload = NULL;
			sipheaderfilter_reload_do = 0;
			SIP_HEADERfilter::unlock_sync();
		}
		process_packet__last_filter_reload = header->ts.tv_sec;
	}

	*was_rtp = 0;
	//int merged;
	_parse_packet_process_packet = parsePacket ? &parsePacket->parse : NULL;
	
	if(mainProcess && istcp < 2) {
		++counter_all_packets;
	}

	// checking and cleaning stuff every 10 seconds (if some packet arrive) 
	if (header->ts.tv_sec - process_packet__last_cleanup > 10){
		process_packet__cleanup(header, handle);
	}
	
	if(header->ts.tv_sec - process_packet__last_destroy_calls >= 2) {
		calltable->destroyCallsIfPcapsClosed();
		process_packet__last_destroy_calls = header->ts.tv_sec;
	}

	// check if the packet is SKINNY
	if(istcp && opt_skinny && (source == 2000 || dest == 2000)) {
		handle_skinny(header, packet, saddr, source, daddr, dest, data, datalen, dataoffset,
			      handle, dlt, sensor_id);
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
				saddr, source, daddr, dest,
				call, "packet is SKINNY");
		}
		return NULL;
	}

	// check if the packet is SIP ports or SKINNY ports
	if(sipportmatrix[source] || sipportmatrix[dest] || forceSip) {
	 
		++counter_sip_packets[0];

		Call *returnCall = NULL;
		
		unsigned long origDatalen = datalen;
		unsigned long sipDatalen = parsePacket ? 
					    parsePacket->sipDataLen :
					    _parse_packet_global.parseData(data, datalen, true);
		if(sipDatalen > 0) {
			datalen = sipDatalen;
		}

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
		
		int issip = parsePacket ? parsePacket->isSip : check_sip20(data, datalen);
		if(!istcp and !issip) { 
			goto rtpcheck;
		}

		if(parsePacket && parsePacket->_getCallID_reassembly) {
			strncpy(callidstr, parsePacket->callid.c_str(), sizeof(callidstr));
		} else {
			s = gettag(data, datalen, "\nCall-ID:", &l, &gettagLimitLen);
			if(!issip or (l <= 0 || l > 1023)) {
				// try also compact header
				s = gettag(data, datalen,"\ni:", &l, &gettagLimitLen);
				if(!issip or (l <= 0 || l > 1023)) {
					// no Call-ID found in packet
					if(istcp == 1 && header_ip) {
						if(!(preProcessPacket && opt_enable_preprocess_packet == 2)) {
							tcpReassemblySip.processPacket(
								packet_number,
								saddr, source, daddr, dest, data, origDatalen, dataoffset,
								handle, *header, packet, header_ip,
								dlt, sensor_id,
								issip);
							if(logPacketSipMethodCall_enable) {
								logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
									saddr, source, daddr, dest,
									call, "it is TCP and callid not found");
							}
						}
						return NULL;
					} else {
						// it is not TCP and callid not found
						if(!(preProcessPacket && opt_enable_preprocess_packet == 2) && logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
								saddr, source, daddr, dest,
								call, "it is not TCP and callid not found");
						}
						return NULL;
					}
				}
			}
			memcpy(callidstr, s, MIN(l, 1024));
			callidstr[MIN(l, 1023)] = '\0';

			// Call-ID is present
			if(istcp == 1 && datalen >= 2) {
				if(!(preProcessPacket && opt_enable_preprocess_packet == 2)) {
					tcpReassemblySip.processPacket(
						packet_number,
						saddr, source, daddr, dest, data, origDatalen, dataoffset,
						handle, *header, packet, header_ip,
						dlt, sensor_id,
						issip);
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
							saddr, source, daddr, dest,
							call, "it is TCP and callid found");
					}
				}
				return(NULL);
			}
		}
		
		if(issip) {
			if(opt_enable_fraud) {
				fraudSipPacket(saddr, header->ts);
			}
#if 0
//this block was moved at the end so it will mirror only relevant SIP belonging to real calls 
			if(sipSendSocket && !opt_sip_send_before_packetbuffer) {
				u_int16_t header_length = datalen;
				sipSendSocket->addData(&header_length, 2,
						       data, datalen);
			}
#endif 
			++counter_sip_packets[1];
			
			if(sverb.dump_sip) {
				char *dump_data = new FILE_LINE char[datalen + 1];
				memcpy(dump_data, data, datalen);
				dump_data[datalen] = 0;
				cout << counter_sip_packets[1] << endl
				     << dump_data << endl;
				delete [] dump_data;
			}
		}

		sip_method = parsePacket && parsePacket->_getSipMethod ?
			      parsePacket->sip_method :
			      process_packet__parse_sip_method(data, datalen);
		switch(sip_method) {
		case REGISTER:
			counter_sip_register_packets++;
			if(opt_enable_fraud) {
				fraudRegister(saddr, header->ts);
			}
			break;
		case MESSAGE:
			counter_sip_message_packets++;
			break;
		case OPTIONS:
			if(livesnifferfilterUseSipTypes.u_options) {
				save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, OPTIONS, 
						 dlt, sensor_id);
			}
			break;
		case SUBSCRIBE:
			if(livesnifferfilterUseSipTypes.u_subscribe) {
				save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, SUBSCRIBE, 
						 dlt, sensor_id);
			}
			break;
		case NOTIFY:
			if(livesnifferfilterUseSipTypes.u_notify) {
				save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, NOTIFY, 
						 dlt, sensor_id);
			}
			break;
		}
		
		if(parsePacket && parsePacket->_getLastSipResponse) {
			lastSIPresponseNum = parsePacket->lastSIPresponseNum;
			strncpy(lastSIPresponse, parsePacket->lastSIPresponse.c_str(), sizeof(lastSIPresponse));
			lastSIPresponse[sizeof(lastSIPresponse) - 1] = 0;
			call_cancel_lsr487 = parsePacket->call_cancel_lsr487;
		} else {
			lastSIPresponseNum = parse_packet__last_sip_response(data, datalen, sip_method,
									     lastSIPresponse, &call_cancel_lsr487);
		}

		// find call */
		if(parsePacket && parsePacket->_findCall) {
			call = parsePacket->call;
		} else {
			call = calltable->find_by_call_id(callidstr, strlen(callidstr));
			if(call) {
				call->handle_dscp(sip_method, header_ip, saddr, daddr, NULL, !IS_SIP_RESXXX(sip_method));
				if(pcap_drop_flag) {
					call->pcap_drop = pcap_drop_flag;
				}
				if(call_cancel_lsr487) {
					call->cancel_lsr487 = call_cancel_lsr487;
				}
			}
		}

		// check presence of call-id merge header if callidmerge feature is enabled
		//merged = 0;
		if(!call and opt_callidmerge_header[0] != '\0') {
			call = calltable->find_by_mergecall_id(callidstr, strlen(callidstr));
			if(!call) {
				// this call-id is not yet tracked either in calls list or callidmerge list 
				// check if there is SIP callidmerge_header which contains parent call-id call
				char *s2 = NULL;
				long unsigned int l2 = 0;
				unsigned char buf[1024];
				s2 = gettag(data, datalen, opt_callidmerge_header, &l2, &gettagLimitLen);
				if(l2 && l2 < 128) {
					// header exists
					if(opt_callidmerge_secret[0] != '\0') {
						// header is encoded - decode it 
						char c;
						c = s2[l2];
						s2[l2] = '\0';
						int enclen = base64decode(buf, (const char*)s2, l2);
						static int keysize = strlen(opt_callidmerge_secret);
						s2[l2] = c;
						for(int i = 0; i < enclen; i++) {
							buf[i] = buf[i] ^ opt_callidmerge_secret[i % keysize];
						}
						// s2 is now decrypted call-id
						s2 = (char*)buf;
						l2 = enclen;
					}
					// check if the sniffer know about this call-id in mergeheader 
					call = calltable->find_by_call_id(s2, l2);
					if(!call) {
						// there is no call with the call-id in merge header - this call will be created as new
					} else {
						//merged = 1;
						calltable->lock_calls_mergeMAP();
						calltable->calls_mergeMAP[callidstr] = call;
						calltable->unlock_calls_mergeMAP();
						call->mergecalls.push_back(callidstr);
					}
				}
			} else {
				//merged = 1;
			}
		}
	
		if (!call){
			// packet does not belongs to any call yet
			if (sip_method == INVITE || sip_method == MESSAGE || (opt_sip_register && sip_method == REGISTER)) {
				if(parsePacket && parsePacket->_createCall) {
					call = parsePacket->call_created;
					detectUserAgent = parsePacket->detectUserAgent;
				} else {
					call = new_invite_register(is_ssl, sip_method, data, datalen, header, callidstr, saddr, daddr, source, dest,
								   handle, dlt, sensor_id,
								   &detectUserAgent,
								   parsePacket ? &parsePacket->parse : &_parse_packet_global);
				}
				if(call == NULL) {
					goto endsip;
				}
			} else {
				// SIP packet does not belong to any call and it is not INVITE 
				// TODO: check if we have enabled live sniffer for SUBSCRIBE or OPTIONS 
				// if yes check for cseq OPTIONS or SUBSCRIBE 
				s = gettag(data, datalen, "\nCSeq:", &l, &gettagLimitLen);
				if(l && l < 32) {
					if(livesnifferfilterUseSipTypes.u_subscribe && memmem(s, l, "SUBSCRIBE", 9)) {
						save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, SUBSCRIBE, 
								 dlt, sensor_id);
					} else if(livesnifferfilterUseSipTypes.u_options && memmem(s, l, "OPTIONS", 7)) {
						save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, OPTIONS, 
								 dlt, sensor_id);
					} else if(livesnifferfilterUseSipTypes.u_notify && memmem(s, l, "NOTIFY", 6)) {
						save_live_packet(NULL, header, packet, saddr, source, daddr, dest, istcp, data, datalen, NOTIFY, 
								 dlt, sensor_id);
					}
				}
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
						saddr, source, daddr, dest,
						call, "SIP packet does not belong to any call and it is not INVITE");
				}
				goto endsip;
			}
		// check if the SIP msg is part of earlier REGISTER
		} else if(call->type == REGISTER) {
			if(call->lastsrcip != saddr) { call->oneway = 0; };
			call->lastSIPresponseNum = lastSIPresponseNum;
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
					call = new_invite_register(is_ssl, sip_method, data, datalen, header, callidstr, saddr, daddr, source, dest,
								   handle, dlt, sensor_id,
								   &detectUserAgent,
								   parsePacket ? &parsePacket->parse : &_parse_packet_global);
					if(call == NULL) {
						goto endsip;
					}
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
							saddr, source, daddr, dest,
							call, "to much register attempts without OK or 401 responses");
					}
					returnCall = call;
					goto endsip_save_packet;
				}
				s = gettag(data, datalen, "\nCSeq:", &l, &gettagLimitLen);
				if(l && l < 32) {
					memcpy(call->invitecseq, s, l);
					call->invitecseq[l] = '\0';
				}


			} else if(sip_method == RES2XX) {
				call->seenRES2XX = true;
				// update expires header from all REGISTER dialog messages (from 200 OK which can override the expire) but not if register_expires == 0
				if(call->register_expires != 0) {
					s = gettag(data, datalen, "\nExpires:", &l, &gettagLimitLen);
					if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
						char c = s[l];
						s[l] = '\0';
						call->register_expires = atoi(s);
						s[l] = c;
					}
					// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
					get_expires_from_contact(data, datalen, &call->register_expires);
				}
				if(opt_enable_fraud) {
					fraudConnectCall(call, header->ts);
				}
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER OK Call-ID[%s]", call->call_id.c_str());
                                s = gettag(data, datalen, "\nCSeq:", &l, &gettagLimitLen);
                                if(l && strncmp(s, call->invitecseq, l) == 0) {
					// registration OK 
					call->regstate = 1;
				} else {
					// OK to unknown msg close the call
					call->regstate = 3;
				}
				save_sip_packet(call, header, packet, 
						saddr, source, daddr, dest, 
						istcp, header_ip, data, sipDatalen, dataoffset, TYPE_SIP, 
						origDatalen, sipOffset,
						forceSip, dlt, sensor_id);
				call->saveregister();
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
						saddr, source, daddr, dest,
						call, "update expires header from all REGISTER dialog messages (from 200 OK which can override the expire)");
				}
				goto endsip;
			} else if(sip_method == RES401 or sip_method == RES403 or sip_method == RES404) {
				if(sip_method == RES401) {
					call->reg401count++;
					if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER 401 Call-ID[%s] reg401count[%d]", call->call_id.c_str(), call->reg401count);
				}
				if((sip_method == RES401 && call->reg401count > 1) || 
				   sip_method == RES403 || sip_method == RES404) {
					// registration failed
					call->regstate = 2;
					save_sip_packet(call, header, packet, 
							saddr, source, daddr, dest, 
							istcp, header_ip, data, sipDatalen, dataoffset, TYPE_SIP, 
							origDatalen, sipOffset,
							forceSip, dlt, sensor_id);
					call->saveregister();
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
							saddr, source, daddr, dest,
							call, 
							sip_method == RES401 ? "REGISTER 401 count > 1" :
							sip_method == RES403 ? "REGISTER 403" :
							sip_method == RES404 ? "REGISTER 404" : "");
					}
					goto endsip;
				}
			}
			if(call->regstate && !call->regresponse) {
				if(opt_enable_fraud) {
					fraudRegisterResponse(call->sipcallerip[0], call->first_packet_time * 1000000ull + call->first_packet_usec);
				}
				call->regresponse = true;
			}
			if(call->msgcount > 20) {
				// too many REGISTER messages within the same callid
				call->regstate = 4;
				save_sip_packet(call, header, packet, 
						saddr, source, daddr, dest, 
						istcp, header_ip, data, sipDatalen, dataoffset, TYPE_SIP, 
						origDatalen, sipOffset,
						forceSip, dlt, sensor_id);
				call->saveregister();
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
						saddr, source, daddr, dest,
						call, "too many REGISTER messages within the same callid");
				}
				goto endsip;
			}
		// packet is already part of call
		// check if SIP packet belongs to the first leg 
		} else if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
			((call->saddr == saddr && call->sport == source) || 
			(call->saddr == daddr && call->sport == dest))))

			{

			if(call->lastsrcip != saddr) { call->oneway = 0; };

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
			   (call->type == MESSAGE ?
				call->lastSIPresponseNum != 487 &&
				lastSIPresponseNum > call->lastSIPresponseNum :
				(call->lastSIPresponseNum != 487 || 
				 (call->new_invite_after_lsr487 && lastSIPresponseNum == 200) ||
				 (call->cancel_lsr487 && lastSIPresponseNum/10 == 48)) &&
				!call->seeninviteok &&
			        !(call->lastSIPresponseNum / 100 == 5 && lastSIPresponseNum / 100 == 5)) &&
			   !(call->cancelcseq[0] && cseq && cseqlen < 32 && strncmp(cseq, call->cancelcseq, cseqlen) == 0)) {
				strncpy(call->lastSIPresponse, lastSIPresponse, 128);
				call->lastSIPresponseNum = lastSIPresponseNum;
			}
			if(lastSIPresponseNum != 0 && lastSIPresponse[0] != '\0') {
				call->SIPresponse.push_back(Call::sSipResponse(lastSIPresponse, lastSIPresponseNum));
			}
			
			extern bool exists_columns_cdr_reason;
			if(exists_columns_cdr_reason) {
				char *reason = gettag(data, datalen, "reason:", &l);
				if(l && l < (unsigned)datalen) {
					char oldEndChar = data[l];
					data[l] = 0;
					char *pointerToCause = strcasestr(reason, ";cause=");
					if(pointerToCause && (pointerToCause - reason) < 10) {
						char type[10];
						memcpy(type, reason, pointerToCause - reason);
						type[pointerToCause - reason] = 0;
						int cause = atoi(pointerToCause + 7);
						char text[1024];
						char *pointerToText = strcasestr(pointerToCause, ";text=\"");
						if(pointerToText && (pointerToText - pointerToCause - 7) < 5) {
							unsigned int lengthText = MIN(l - (pointerToText - reason + 7), sizeof(text) - 1);
							memcpy(text, pointerToText + 7, lengthText);
							text[lengthText] = 0;
							if(lengthText > 0 && text[lengthText - 1] == '"') {
								--lengthText;
								text[lengthText] = 0;
							}
						} else {
							sprintf(text, "%i (text missing)", cause);
						}
						if(!strcasecmp(type, "SIP")) {
							call->reason_sip_cause = cause;
							call->reason_sip_text = text;
						} else if(!strcasecmp(type, "Q.850")) {
							call->reason_q850_cause = cause;
							call->reason_q850_text = text;
						}
					}
					data[l] = oldEndChar;
				}
			}

			// check if it is BYE or OK(RES2XX)
			if(sip_method == INVITE) {
				if(!call->seenbye) {
					call->destroy_call_at = 0;
					call->destroy_call_at_bye = 0;
				}
				if(call->lastSIPresponseNum == 487) {
					call->new_invite_after_lsr487 = true;
				}
				//update called number for each invite due to overlap-dialling
				if (opt_sipoverlap && saddr == call->sipcallerip[0]) {
					int res = get_sip_peername(data,datalen,"\nTo:", call->called, sizeof(call->called));
					if(res) {
						// try compact header
						get_sip_peername(data,datalen,"\nt:", call->called, sizeof(call->called));
					}
					if(opt_destination_number_mode == 2) {
						char called[1024] = "";
						if(!get_sip_peername(data,datalen,"INVITE ", called, sizeof(called)) &&
						   called[0] != '\0') {
							strncpy(call->called, called, sizeof(call->called));
						}
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
				call->seeninviteok = false;

				s = gettag(data, datalen, "\nUser-Agent:", &l, &gettagLimitLen);
				if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
					memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
					call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
					if(sverb.set_ua) {
						cout << "set a_ua " << call->a_ua << endl;
					}
				}
				detectUserAgent = true;

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
								delete [] call->message;
							}
							call->message = new FILE_LINE char[end - tmp + 1];
							data[datalen - 1] = a;
							memcpy(call->message, tmp, end - tmp);
							call->message[end - tmp] = '\0';
						}
					} else if(!call->message) {
						call->message = new FILE_LINE char[1];
						call->message[0] = '\0';
					}
					data[datalen - 1] = a;
				} else {
					data[datalen - 1] = a;
				}
			} else if(sip_method == BYE) {
				
				call->destroy_call_at = header->ts.tv_sec + 60;
				call->destroy_call_at_bye = header->ts.tv_sec + 20 * 60;
				
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
					if(opt_enable_fraud) {
						fraudSeenByeCall(call, header->ts);
					}
				}
				// save who hanged up 
				if(call->sipcallerip[0] == saddr) {
					call->whohanged = 0;
				} else if(call->sipcalledip[0] == saddr) {
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
				call->seenRES2XX = true;
				// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
				if(!(cseq && cseqlen < 32) || strncmp(cseq, call->byecseq, cseqlen)) {
					call->seenRES2XX_no_BYE = true;
					if(!call->progress_time) {
						call->progress_time = header->ts.tv_sec;
					}
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
/*
	Whan voipmonitor listens for both SIP legs (with the same Call-ID it sees both BYE and should save both 200 OK after BYE so closing call after the 
	first 200 OK will not save the second 200 OK. So rather wait for 5 seconds for some more messages instead of closing the call. 
*/
						// destroy call after 5 seonds from now 
						call->destroy_call_at = header->ts.tv_sec + 5;
						if(logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
								saddr, source, daddr, dest,
								call);
						}
						process_packet__parse_custom_headers(call, data, datalen);
						returnCall = call;
						goto endsip_save_packet;
					} else if(strncmp(cseq, call->invitecseq, cseqlen) == 0) {
						call->seeninviteok = true;
						if(!call->connect_time) {
							call->connect_time = header->ts.tv_sec;
							if(opt_enable_fraud) {
								fraudConnectCall(call, header->ts);
							}
						}
						if(opt_update_dstnum_onanswer &&
						   !call->updateDstnumOnAnswer &&
						   call->called_invite_branch_map.size()) {
							char branch[100];
							if(!get_sip_branch(data, datalen, "via:", branch, sizeof(branch)) &&
							   branch[0] != '\0') {
								map<string, string>::iterator iter = call->called_invite_branch_map.find(branch);
								if(iter != call->called_invite_branch_map.end()) {
									strncpy(call->called, iter->second.c_str(), sizeof(call->called));
									call->updateDstnumOnAnswer = true;
								}
							}
						}
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Call answered\n");
					} else if(strncmp(cseq, call->cancelcseq, cseqlen) == 0) {
						process_packet__parse_custom_headers(call, data, datalen);
						returnCall = call;
						goto endsip_save_packet;
					}
				}
				if(!call->onCall_2XX) {
					ClientThreads.onCall(lastSIPresponseNum, call->callername, call->caller, call->called,
							     call->sipcallerip[0], call->sipcalledip[0]);
					sendCallInfoEvCall(call, sSciInfo::sci_200, header->ts);
					call->onCall_2XX = true;
				}

			} else if(sip_method == RES18X) {
				call->seenRES18X = true;
				if(!call->progress_time) {
					call->progress_time = header->ts.tv_sec;
				}
				if(!call->onCall_18X) {
					ClientThreads.onCall(lastSIPresponseNum, call->callername, call->caller, call->called,
							     call->sipcallerip[0], call->sipcalledip[0]);
					sendCallInfoEvCall(call, sSciInfo::sci_18X, header->ts);
					call->onCall_18X = true;
				}
			}

			// if the call ends with some of SIP [456]XX response code, we can shorten timeout when the call will be closed 
//			if((call->saddr == saddr || call->saddr == daddr || merged) &&
			if (sip_method == RES3XX || IS_SIP_RES4XX(sip_method) || sip_method == RES5XX || sip_method == RES6XX) {
				if(lastSIPresponseNum != 401 && lastSIPresponseNum != 407 && lastSIPresponseNum != 501 && lastSIPresponseNum != 481 && lastSIPresponseNum != 491) {
					// save packet 
					call->destroy_call_at = header->ts.tv_sec + 5;

					if(sip_method == RES3XX) {
						// remove all RTP  
						call->removeFindTables();
						call->removeRTP();
						call->ipport_n = 0;
					}
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
							saddr, source, daddr, dest,
							call);
					}
					process_packet__parse_custom_headers(call, data, datalen);
					returnCall = call;
					goto endsip_save_packet;
				} else if(lastSIPresponseNum == 481) {
					//481 CallLeg/Transaction doesnt exist - set timeout to 180 seconds
					call->destroy_call_at = header->ts.tv_sec + 180;
				} else if(lastSIPresponseNum == 491) {
					// do not set timeout for 491
				} else if(!call->destroy_call_at) {
					call->destroy_call_at = header->ts.tv_sec + 60;
				}
			}
		}

		if(call->lastsrcip != saddr) { call->oneway = 0; };

		if(sip_method == INVITE) {
		 
			bool existInviteSdaddr = false;
			bool reverseInviteSdaddr = false;
			for(list<d_u_int32_t>::iterator iter = call->invite_sdaddr.begin(); iter != call->invite_sdaddr.end(); iter++) {
				if(saddr == (*iter)[0] && daddr == (*iter)[1]) {
					existInviteSdaddr = true;
				} else if(daddr == (*iter)[0] && saddr == (*iter)[1]) {
					reverseInviteSdaddr = true;
				}
			}
			if(!existInviteSdaddr) {
				call->invite_sdaddr.push_back(d_u_int32_t(saddr, daddr));
			}
		 
			if(opt_update_dstnum_onanswer) {
				char branch[100];
				if(!get_sip_branch(data, datalen, "via:", branch, sizeof(branch)) &&
				   branch[0] != '\0') {
					char called_invite[1024] = "";
					if(!get_sip_peername(data,datalen,"INVITE ", called_invite, sizeof(called_invite)) &&
					   called_invite[0] != '\0') {
						call->called_invite_branch_map[branch] = called_invite;
					}
				}
			}
			ipfilter->add_call_flags(&(call->flags), ntohl(saddr), ntohl(daddr));
			if(opt_cdrproxy && !reverseInviteSdaddr) {
				if(call->sipcalledip[0] != daddr and call->sipcallerip[0] != daddr and call->lastsipcallerip != saddr) {
					if(daddr != 0) {
						// daddr is already set, store previous daddr as sipproxy
						call->proxies.push_back(call->sipcalledip[0]);
					}
					call->sipcalledip[0] = daddr;
					call->lastsipcallerip = saddr;
				} else if(call->lastsipcallerip == saddr) {
					// update sipcalledip to this new one
					call->sipcalledip[0] = daddr;
					call->lastsipcallerip = saddr;
				}
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

		// check for opt_match_header
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

		char a;
		a = data[datalen - 1];
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
			
			if(call->contenttype) delete [] call->contenttype;
			call->contenttype = new FILE_LINE char[l + 1];
			memcpy(call->contenttype, s, l);
			call->contenttype[l] = '\0';
			
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
				call->content_length = contentlen;
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
				call->message = new FILE_LINE char[end - tmp + 1];
				data[datalen - 1] = a;
				memcpy(call->message, tmp, end - tmp);
				call->message[end - tmp] = '\0';
			} else {
				call->message = new FILE_LINE char[1];
				call->message[0] = '\0';
			}
			//printf("msg: contentlen[%d] datalen[%d] len[%d] [%s]\n", contentlen, datalen, strlen(call->message), call->message);
		} else if(strcasestr(s, "application/sdp")) {
			*sl = t;
			// prepare User-Agent
			char *ua = NULL;
			unsigned long gettagLimitLen = 0, ua_len = 0;
			ua = gettag(data, datalen, "\nUser-Agent:", &ua_len, &gettagLimitLen);
			detectUserAgent = true;
			process_sdp(call, sip_method, saddr, source, daddr, dest, s, (unsigned int)datalen - (s - data), header_ip, callidstr, ua, ua_len);
		} else if(strcasestr(s, "multipart/mixed")) {
			*sl = t;
			char *ua = NULL;
			unsigned long gettagLimitLen = 0, ua_len = 0;
			ua = gettag(data, datalen, "\nUser-Agent:", &ua_len, &gettagLimitLen);
			detectUserAgent = true;
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
						process_sdp(call, sip_method, saddr, source, daddr, dest, s2, (unsigned int)datalen - (s2 - data), header_ip, callidstr, ua, ua_len);
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
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
				saddr, source, daddr, dest,
				call);
		}
		returnCall = call;
		data[datalen - 1] = a;
endsip_save_packet:
		save_sip_packet(call, header, packet, 
				saddr, source, daddr, dest, 
				istcp, header_ip, data, sipDatalen, dataoffset, TYPE_SIP, 
				origDatalen, sipOffset,
				forceSip, dlt, sensor_id);
endsip:
		if(call && call->type != REGISTER && sipSendSocket && !opt_sip_send_before_packetbuffer) {
			// send packet to socket if enabled
			u_int16_t header_length = datalen;
			sipSendSocket->addData(&header_length, 2,
					       data, datalen);
		}

		if(!detectUserAgent && sip_method && call) {
			bool iscaller = 0;
			if(call->check_is_caller_called(sip_method, saddr, daddr, &iscaller)) {
				s = gettag(data, sipDatalen, "\nUser-Agent:", &l, &gettagLimitLen);
				if(l && ((unsigned int)l < ((unsigned int)sipDatalen - (s - data)))) {
					//cout << "**** " << call->call_id << " " << (iscaller ? "b" : "a") << " / " << string(s).substr(0,l) << endl;
					//cout << "**** " << call->call_id << " " << (iscaller ? "b" : "a") << " / " << string(data).substr(0,datalen) << endl;
					if(iscaller) {
						memcpy(call->b_ua, s, MIN(l, sizeof(call->b_ua)));
						call->b_ua[MIN(l, sizeof(call->b_ua) - 1)] = '\0';
						if(sverb.set_ua) {
							cout << "set b_ua " << call->b_ua << endl;
						}
					} else {
						memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
						call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
						if(sverb.set_ua) {
							cout << "set a_ua " << call->a_ua << endl;
						}
					}
				}
			}
		}
		datalen = origDatalen;
		if(istcp &&
		   sipDatalen < (unsigned)datalen - 11 &&
		   (unsigned)datalen + sipOffset < header->caplen &&
		   check_sip20(data + sipDatalen, datalen - sipDatalen)) {
			process_packet(is_ssl, packet_number,
				       saddr, source, daddr, dest, 
				       data + sipDatalen, datalen - sipDatalen, dataoffset,
				       handle, header, packet, 
				       istcp, was_rtp, header_ip, voippacket, forceSip,
				       block_store, block_store_index, dlt, sensor_id, 
				       false, sipOffset + sipDatalen);
		}
		return returnCall;
	}

rtpcheck:
	if(datalen > 2/* && (htons(*(unsigned int*)data) & 0xC000) == 0x8000*/) { // disable condition - failure for udptl (fax)
	if(processRtpPacket[0]) {
		ProcessRtpPacket *_processRtpPacket = processRtpPacket[1] ?
						       processRtpPacket[min(source, dest) / 2 % opt_enable_process_rtp_packet] :
						       processRtpPacket[0];
		_processRtpPacket->push(saddr, source, daddr, dest, 
					data, datalen, dataoffset,
					handle, header, packet, istcp, header_ip,
					block_store, block_store_index, dlt, sensor_id,
					parsePacket ? parsePacket->hash[0] : tuplehash(saddr, source),
					parsePacket ? parsePacket->hash[1] : tuplehash(daddr, dest));
	} else {
	if ((calls = calltable->hashfind_by_ip_port(daddr, dest, parsePacket ? parsePacket->hash[1] : 0))){
		++counter_rtp_packets;
		// packet (RTP) by destination:port is already part of some stored call  
		for (node_call = (hash_node_call *)calls; node_call != NULL; node_call = node_call->next) {
			call = node_call->call;
			iscaller = node_call->iscaller;
			is_rtcp = node_call->is_rtcp;
			is_fax = node_call->is_fax;
			
			if(sverb.process_rtp) {
				cout << "RTP - process_packet (daddr, dest): " << inet_ntostring(htonl(daddr)) << " / " << dest
				     << " " << (iscaller ? "caller" : "called") 
				     << endl;
			}

			if(pcap_drop_flag) {
				call->pcap_drop = pcap_drop_flag;
			}

			if(!is_rtcp && !is_fax &&
			   (datalen < RTP_FIXED_HEADERLEN ||
			    header->caplen <= (unsigned)(datalen - RTP_FIXED_HEADERLEN))) {
				return(call);
			}

			*voippacket = 1;

			// we have packet, extend pending destroy requests
			if(call->destroy_call_at > 0 && header->ts.tv_sec + 5 > call->destroy_call_at) {
				call->destroy_call_at = header->ts.tv_sec + 5; 
			}

			int can_thread = !sverb.disable_threads_rtp;
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
					add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, iscaller, is_rtcp,
								block_store, block_store_index, 
								opt_saveRTP || opt_saveRTCP, 
								packet, istcp, dlt, sensor_id,
								false);
				} else {
					call->read_rtcp((unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, iscaller,
							false, packet, istcp, dlt, sensor_id);
				}
				if((!rtp_threaded || !opt_rtpsave_threaded) &&
				   (opt_saveRTP || opt_saveRTCP)) {
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
						    forceSip, dlt, sensor_id);
				}
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
						saddr, source, daddr, dest,
						call);
				}
				return call;
			}

			if(rtp_threaded && can_thread) {
				if(!((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl)) && opt_saverfc2833) {
					// if RTP is NOT saving but we still wants to save DTMF (rfc2833) and becuase RTP is going to be 
					// queued and processed later in async queue we must decode if the RTP packet is DTMF here 
					call->tmprtp.fill((unsigned char*)data, datalen, header, saddr, daddr, source, dest); //TODO: datalen can be shortned to only RTP header len
					record = call->tmprtp.getPayload() == 101 ? 1 : 0;
				}
				add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, iscaller, is_rtcp,
							block_store, block_store_index, 
							(call->flags & FLAG_SAVERTPHEADER) || (call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record, 
							packet, istcp, dlt, sensor_id,
							false);
				*was_rtp = 1;
				if(is_rtcp) {
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
							saddr, source, daddr, dest,
							call);
					}
					return call;
				}
			} else {
				call->read_rtp((unsigned char*) data, datalen, dataoffset, header, NULL, saddr, daddr, source, dest, iscaller, &record,
					       false, packet, istcp, dlt, sensor_id,
					       block_store && block_store->ifname[0] ? block_store->ifname : NULL);
				call->set_last_packet_time(header->ts.tv_sec);
			}
			if((!rtp_threaded || !opt_rtpsave_threaded) &&
			   ((call->flags & FLAG_SAVERTPHEADER) || (call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record)) {
				if((call->silencerecording || (opt_onlyRTPheader && !(call->flags & FLAG_SAVERTP))) && !call->isfax) {
					if(datalen >= RTP_FIXED_HEADERLEN &&
					   header->caplen > (unsigned)(datalen - RTP_FIXED_HEADERLEN)) {
						tmp_u32 = header->caplen;
						header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
						save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
							    forceSip, dlt, sensor_id);
						header->caplen = tmp_u32;
					}
				} else {
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
						    forceSip, dlt, sensor_id);
				}

			}
		}
	} else if ((calls = calltable->hashfind_by_ip_port(saddr, source, parsePacket ? parsePacket->hash[0] : 0))){
		++counter_rtp_packets;
		// packet (RTP[C]) by source:port is already part of some stored call 
		for (node_call = (hash_node_call *)calls; node_call != NULL; node_call = node_call->next) {
			call = node_call->call;
#if 0
			if(call->chantype == CHAN_SKINNY) {
				// if channel is skinny do not assign RTP packet based on source IP and source port. 
				continue;
			}
#endif
			iscaller = node_call->iscaller;
			is_rtcp = node_call->is_rtcp;
			is_fax = node_call->is_fax;

			if(sverb.process_rtp) {
				cout << "RTP - process_packet (saddr, source): " << inet_ntostring(htonl(saddr)) << " / " << source
				     << " " << (iscaller ? "caller" : "called") 
				     << endl;
			}
			
			if(pcap_drop_flag) {
				call->pcap_drop = pcap_drop_flag;
			}

			if(!is_rtcp && !is_fax &&
			   (datalen < RTP_FIXED_HEADERLEN ||
			    header->caplen <= (unsigned)(datalen - RTP_FIXED_HEADERLEN))) {
				return(call);
			}

			*voippacket = 1;

			// we have packet, extend pending destroy requests
			if(call->destroy_call_at > 0 && header->ts.tv_sec + 5 > call->destroy_call_at) {
				call->destroy_call_at = header->ts.tv_sec + 5; 
			}

			int can_thread = !sverb.disable_threads_rtp;
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
					add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, !iscaller, is_rtcp,
								block_store, block_store_index, 
								opt_saveRTP || opt_saveRTCP, 
								packet, istcp, dlt, sensor_id,
								false);
				} else {
					call->read_rtcp((unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, !iscaller,
							false, packet, istcp, dlt, sensor_id);
				}
				if((!rtp_threaded || !opt_rtpsave_threaded) &&
				   (opt_saveRTP || opt_saveRTCP)) {
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
						    forceSip, dlt, sensor_id);
				}
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
						saddr, source, daddr, dest,
						call);
				}
				return call;
			}

			// as we are searching by source address and find some call, revert iscaller 
			if(rtp_threaded && can_thread) {
				if(!((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl)) && opt_saverfc2833) {
					// if RTP is NOT saving but we still wants to save DTMF (rfc2833) and becuase RTP is going to be 
					// queued and processed later in async queue we must decode if the RTP packet is DTMF here 
					call->tmprtp.fill((unsigned char*)data, datalen, header, saddr, daddr, source, dest); //TODO: datalen can be shortned to only RTP header len
					record = call->tmprtp.getPayload() == 101 ? 1 : 0;
				}
				add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, !iscaller, is_rtcp,
							block_store, block_store_index, 
							(call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record, 
							packet, istcp, dlt, sensor_id,
							false);
				*was_rtp = 1;
			} else {
				call->read_rtp((unsigned char*) data, datalen, dataoffset, header, NULL, saddr, daddr, source, dest, !iscaller, &record,
					       false, packet, istcp, dlt, sensor_id,
					       block_store && block_store->ifname[0] ? block_store->ifname : NULL);
				call->set_last_packet_time(header->ts.tv_sec);
			}
			if((!rtp_threaded || !opt_rtpsave_threaded) &&
			   ((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record)) {
				if((call->silencerecording || (opt_onlyRTPheader && !(call->flags & FLAG_SAVERTP))) && !call->isfax) {
					if(datalen >= RTP_FIXED_HEADERLEN &&
					   header->caplen > (unsigned)(datalen - RTP_FIXED_HEADERLEN)) {
						tmp_u32 = header->caplen;
						header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
						save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
							    forceSip, dlt, sensor_id);
						header->caplen = tmp_u32;
					}
				} else {
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
						    forceSip, dlt, sensor_id);
				}
			}
		}

	// packet does not belongs to established call, check if it is on SIP port
	} else {
		if(opt_rtpnosip) {
			// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
			char s[256];
			RTP rtp(-1);
			int rtpmap[MAX_RTPMAP];
			memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);

			rtp.read((unsigned char*)data, datalen, header, saddr, daddr, source, dest, 0, sensor_id);

			if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
						saddr, source, daddr, dest,
						call, "decoding RTP without SIP signaling is enabled (rtp.getVersion() != 2 && rtp.getPayload() > 18)");
				}
				return NULL;
			}
			snprintf(s, 4092, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

			//printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

			call = calltable->add(s, strlen(s), header->ts.tv_sec, saddr, source, handle, dlt, sensor_id);
			call->chantype = CHAN_SIP;
			call->set_first_packet_time(header->ts.tv_sec, header->ts.tv_usec);
			call->sipcallerip[0] = saddr;
			call->sipcalledip[0] = daddr;
			call->sipcallerport = source;
			call->sipcalledport = dest;
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
				if(call->getPcap()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
					call->pcapfilename = pcapFilePath_spool_relative;
				}
			}

			if(verbosity > 3) {
				syslog(LOG_NOTICE,"pcap_filename: [%s]\n",str2);
			}

			call->add_ip_port_hash(saddr, daddr, dest, NULL, s, l, 1, rtpmap, false);
			call->add_ip_port_hash(saddr, saddr, source, NULL, s, l, 0, rtpmap, false);
			
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
			logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
				saddr, source, daddr, dest,
				call, "we are not interested in this packet");
		}
		return NULL;
	}
	}
	}

	if(logPacketSipMethodCall_enable) {
		logPacketSipMethodCall(packet_number, sip_method, lastSIPresponseNum, header, 
			saddr, source, daddr, dest,
			call, "---");
		}
	return NULL;
}

void process_packet__parse_custom_headers(Call *call, char *data, int datalen) {
	/* obsolete
	extern vector<dstring> opt_custom_headers_cdr;
	extern vector<dstring> opt_custom_headers_message;
	vector<dstring> *_customHeaders = call->type == MESSAGE ? &opt_custom_headers_message : &opt_custom_headers_cdr;
	size_t iCustHeaders;
	unsigned long gettagLimitLen = 0;
	for(iCustHeaders = 0; iCustHeaders < _customHeaders->size(); iCustHeaders++) {
		map<string, string>::iterator iter = call->custom_headers.find((*_customHeaders)[iCustHeaders][1]);
		if(iter != call->custom_headers.end() && !opt_custom_headers_last_value) {
			continue;
		}
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
			call->custom_headers[(*_customHeaders)[iCustHeaders][1]] = customHeaderContent;
		}
	}
	*/
	CustomHeaders *customHeaders = call->type == MESSAGE ? custom_headers_message : custom_headers_cdr;
	if(customHeaders) {
		 customHeaders->parse(call, data, datalen);
	}
}

void process_packet__cleanup(pcap_pkthdr *header, pcap_t *handle) {
	static int pcapstatres = 0;
	static unsigned int lostpacket = 0;
	static unsigned int lostpacketif = 0;
 
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
	
	if (process_packet__last_cleanup >= 0){
		calltable->cleanup(header->ts.tv_sec);
	}
	
	/* also do every 10 seconds pcap statistics */
	if(!opt_pcap_queue) {
		pcap_drop_flag = 0;
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
			pcap_drop_flag = 1;
		}
	}
	process_packet__last_cleanup = header->ts.tv_sec;

	if(!(preProcessPacket && opt_enable_preprocess_packet == 2)) {
		// clean tcp_streams_list
		tcpReassemblySip.clean(header->ts.tv_sec);
	}

	/* You may encounter that voipmonitor process does not have a reduced memory usage although you freed the calls. 
	This is because it allocates memory in a number of small chunks. When freeing one of those chunks, the OS may decide 
	that giving this little memory back to the kernel will cause too much overhead and delay the operation. As all chunks 
	are this small, they get actually freed but not returned to the kernel. On systems using glibc, there is a function call 
	"malloc_trim" from malloc.h which does this missing operation (note that it is allowed to fail). If your OS does not provide 
	malloc_trim, try searching for a similar function.
	*/
#ifndef FREEBSD
	extern bool exists_thread_delete;
	if(!exists_thread_delete) {
		malloc_trim(0);
	}
#endif
}

int process_packet__parse_sip_method(char *data, unsigned int datalen) {
	int sip_method = 0;
	// parse SIP method 
	if ((datalen > 5) && data[0] == 'I' && !(memmem(data, 6, "INVITE", 6) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: INVITE\n");
		sip_method = INVITE;
	} else if ((datalen > 7) && data[0] == 'R' && !(memmem(data, 8, "REGISTER", 8) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: REGISTER\n");
		sip_method = REGISTER;
	} else if ((datalen > 6) && data[0] == 'M' && !(memmem(data, 7, "MESSAGE", 7) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: MESSAGE\n");
		sip_method = MESSAGE;
	} else if ((datalen > 2) && data[0] == 'B' && !(memmem(data, 3, "BYE", 3) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: BYE\n");
		sip_method = BYE;
	} else if ((datalen > 3) && data[0] == 'I' && !(memmem(data, 4, "INFO", 4) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: INFO\n");
		sip_method = INFO;
	} else if ((datalen > 5) && data[0] == 'C' && !(memmem(data, 6, "CANCEL", 6) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: CANCEL\n");
		sip_method = CANCEL;
	} else if ((datalen > 6) && data[0] == 'O' && !(memmem(data, 7, "OPTIONS", 7) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: OPTIONS\n");
		sip_method = OPTIONS;
	} else if ((datalen > 8) && data[0] == 'S' && data[1] == 'U' && !(memmem(data, 9, "SUBSCRIBE", 9) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: SUBSCRIBE\n");
		sip_method = SUBSCRIBE;
	} else if ((datalen > 5) && data[0] == 'N' && !(memmem(data, 6, "NOTIFY", 6) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: NOTIFY\n");
		sip_method = NOTIFY;
	} else if( (datalen > 8) && data[0] == 'S' && data[1] == 'I' && !(memmem(data, 8, "SIP/2.0 ", 8) == 0)){
		switch(data[8]) {
		case '2':
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 2XX\n");
			sip_method = RES2XX;
			if((data[12] == 'A' or data[12] == 'a') and datalen > 23 and !(memmem(data, 23, "SIP/2.0 200 Auth failed", 23) == 0)) {
				// simulate 4XX response when auth failed received
				sip_method = RES4XX;
			}
			break;
		case '1':
			if ((datalen > 9) && data[9] == '8') {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 18X\n");
				sip_method = RES18X;
			}
			break;
		case '3':
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 3XX\n");
			sip_method = RES3XX;
			break;
		case '4':
			if ((datalen > 10) && data[9] == '0' && data[10] == '1') {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 401\n");
				sip_method = RES401;
			} else if ((datalen > 10) && data[9] == '0' && data[10] == '3') {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 403\n");
				sip_method = RES403;
			} else if ((datalen > 10) && data[9] == '0' && data[10] == '4') {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 404\n");
				sip_method = RES404;
			} else {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 4XX\n");
				sip_method = RES4XX;
			}
			break;
		case '5':
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 5XX\n");
			sip_method = RES5XX;
			break;
		case '6':
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 6XX\n");
			sip_method = RES6XX;
			break;
		}
	}
	if(!sip_method) {
		if(verbosity > 2) {
			syslog(LOG_NOTICE,"SIP msg: 1XX or Unknown msg \n");
		}
	}
	return(sip_method);
}

int parse_packet__last_sip_response(char *data, unsigned int datalen, int sip_method,
				    char *lastSIPresponse, bool *call_cancel_lsr487) {
	strcpy(lastSIPresponse, "NO RESPONSE");
	*call_cancel_lsr487 = false;
	int lastSIPresponseNum = 0;
	if(sip_method > 0 && sip_method != INVITE && sip_method != REGISTER && sip_method != MESSAGE && sip_method != CANCEL && sip_method != BYE) {
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
	} else if(sip_method == CANCEL) {
		if(!lastSIPresponseNum) {
			lastSIPresponseNum = 487;
			strcpy(lastSIPresponse, "487 Request Terminated CANCEL");
			*call_cancel_lsr487 = true;
		}
	} else if(sip_method == BYE) {
		strcpy(lastSIPresponse, "BYE");
		lastSIPresponseNum = 0;
	}
	return(lastSIPresponseNum);
}

inline
Call *process_packet__rtp(ProcessRtpPacket::rtp_call_info *call_info,size_t call_info_length,
			  unsigned int saddr, int source, unsigned int daddr, int dest, 
			  char *data, int datalen, int dataoffset,
			  pcap_pkthdr *header, const u_char *packet, int istcp, struct iphdr2 *header_ip,
			  pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
			  int *voippacket, int *was_rtp,
			  bool find_by_dest, int preSyncRtp) {
	#if RTP_PROF
	unsigned long long __prof_begin = rdtsc();
	#endif
	++counter_rtp_packets;
	Call *call;
	bool iscaller;
	bool is_rtcp;
	bool is_fax;
	int record = 0;
	Call *rsltCall = NULL;
	size_t call_info_index;
	for(call_info_index = 0; call_info_index < call_info_length; call_info_index++) {
		call = call_info[call_info_index].call;
		iscaller = call_info[call_info_index].iscaller;
		is_rtcp = call_info[call_info_index].is_rtcp;
		is_fax = call_info[call_info_index].is_fax;
		
		if(sverb.process_rtp) {
			if(find_by_dest) {
				cout << "RTP - process_packet (daddr, dest): " << inet_ntostring(htonl(daddr)) << " / " << dest
				     << " " << (iscaller ? "caller" : "called") 
				     << endl;
			} else {
				cout << "RTP - process_packet (saddr, source): " << inet_ntostring(htonl(saddr)) << " / " << source
				     << " " << (iscaller ? "caller" : "called") 
				     << endl;
			}
		}
		
		if(!find_by_dest) {
			iscaller = !iscaller;
		}

		if(pcap_drop_flag) {
			call->pcap_drop = pcap_drop_flag;
		}

		if(!is_rtcp && !is_fax &&
		   (datalen < RTP_FIXED_HEADERLEN ||
		    header->caplen <= (unsigned)(datalen - RTP_FIXED_HEADERLEN))) {
			rsltCall = call;
			break;
		}

		if(voippacket) {
			*voippacket = 1;
		}

		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0 && header->ts.tv_sec + 5 > call->destroy_call_at) {
			call->destroy_call_at = header->ts.tv_sec + 5; 
		}

		int can_thread = !sverb.disable_threads_rtp;
		if(can_thread && header->caplen > MAXPACKETLENQRING) {
			// packets larger than MAXPACKETLENQRING was created in special heap and is destroyd immediately after leaving this functino - thus do not queue it 
			// TODO: this can be enhanced by pasing flag that the packet should be freed
			if(preSyncRtp) {
				rsltCall = call;
				break;
			} else {
				can_thread = 0;
			}
		}

		if(is_fax) {
			call->seenudptl = 1;
		}
		
		if(is_rtcp) {
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, iscaller, is_rtcp,
							block_store, block_store_index, 
							opt_saveRTP || opt_saveRTCP, 
							packet, istcp, dlt, sensor_id,
							preSyncRtp);
				call_info[call_info_index].use_sync = true;
			} else {
				call->read_rtcp((unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, iscaller,
						false, packet, istcp, dlt, sensor_id);
			}
			if((!rtp_threaded || !opt_rtpsave_threaded) &&
			   (opt_saveRTP || opt_saveRTCP)) {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
					    false, dlt, sensor_id);
			}
			rsltCall = call;
			break;
		}

		if(rtp_threaded && can_thread) {
			if(!((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl)) && opt_saverfc2833) {
				// if RTP is NOT saving but we still wants to save DTMF (rfc2833) and becuase RTP is going to be 
				// queued and processed later in async queue we must decode if the RTP packet is DTMF here 
				call->tmprtp.fill((unsigned char*)data, datalen, header, saddr, daddr, source, dest); //TODO: datalen can be shortned to only RTP header len
				record = call->tmprtp.getPayload() == 101 ? 1 : 0;
			}
			add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, dataoffset, header, saddr, daddr, source, dest, iscaller, is_rtcp,
						block_store, block_store_index, 
						(call->flags & FLAG_SAVERTPHEADER) || (call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record, 
						packet, istcp, dlt, sensor_id,
						preSyncRtp);
			call_info[call_info_index].use_sync = true;
			if(was_rtp) {
				*was_rtp = 1;
			}
			if(is_rtcp) {
				rsltCall = call;
				break;
			}
		} else {
			call->read_rtp((unsigned char*) data, datalen, dataoffset, header, NULL, saddr, daddr, source, dest, iscaller, &record,
				       false, packet, istcp, dlt, sensor_id,
				       block_store && block_store->ifname[0] ? block_store->ifname : NULL);
			call->set_last_packet_time(header->ts.tv_sec);
		}
		if((!rtp_threaded || !opt_rtpsave_threaded) &&
		   ((call->flags & FLAG_SAVERTPHEADER) || (call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl) || record)) {
			if((call->silencerecording || (opt_onlyRTPheader && !(call->flags & FLAG_SAVERTP))) && !call->isfax) {
				if(datalen >= RTP_FIXED_HEADERLEN &&
				   header->caplen > (unsigned)(datalen - RTP_FIXED_HEADERLEN)) {
					unsigned int tmp_u32 = header->caplen;
					header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
					save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
						    false, dlt, sensor_id);
					header->caplen = tmp_u32;
				}
			} else {
				save_packet(call, header, packet, saddr, source, daddr, dest, istcp, header_ip, data, datalen, dataoffset, TYPE_RTP, 
					    false, dlt, sensor_id);
			}

		}
	}
	if(preSyncRtp) {
		for(call_info_index = 0; call_info_index < call_info_length; call_info_index++) {
			if(!call_info[call_info_index].use_sync) {
				#if SYNC_CALL_RTP
				__sync_sub_and_fetch(&call_info[call_info_index].call->rtppcaketsinqueue, 1);
				#else
				++call_info[call_info_index].call->rtppcaketsinqueue_m;
				#endif
			}
		}
	}
	#if RTP_PROF
	if(preSyncRtp) {
		processRtpPacket[preSyncRtp - 1]->__prof__process_packet__rtp += rdtsc() - __prof_begin;
	}
	#endif
	return(rsltCall);
}

Call *process_packet__rtp_nosip(unsigned int saddr, int source, unsigned int daddr, int dest, 
				char *data, int datalen, int dataoffset,
				pcap_pkthdr *header, const u_char *packet, int istcp, struct iphdr2 *header_ip,
				pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
				pcap_t *handle) {
	++counter_rtp_packets;
	// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
	char s[256];
	RTP rtp(-1);
	int rtpmap[MAX_RTPMAP];
	memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);

	rtp.read((unsigned char*)data, datalen, header, saddr, daddr, source, dest, 0, sensor_id);

	if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
		return NULL;
	}
	snprintf(s, 4092, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

	//printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

	Call *call = calltable->add(s, strlen(s), header->ts.tv_sec, saddr, source, handle, dlt, sensor_id);
	call->chantype = CHAN_SIP;
	call->set_first_packet_time(header->ts.tv_sec, header->ts.tv_usec);
	call->sipcallerip[0] = saddr;
	call->sipcalledip[0] = daddr;
	call->sipcallerport = source;
	call->sipcalledport = dest;
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
		if(call->getPcap()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
			call->pcapfilename = pcapFilePath_spool_relative;
		}
		
		if(verbosity > 3) {
			syslog(LOG_NOTICE,"pcap_filename: [%s]\n",str2);
		}
	}

	call->add_ip_port_hash(saddr, daddr, dest, NULL, s, strlen(s), 1, rtpmap, false);
	call->add_ip_port_hash(saddr, saddr, source, NULL, s, strlen(s), 0, rtpmap, false);
	
	return(call);
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
	process_packet(false, addr->saddr, addr->source, addr->daddr, addr->dest, 
		       (char*)data, len, data - nids_last_pcap_data, 
		       handle, nids_last_pcap_header, nids_last_pcap_data, 
		       0, &was_rtp, NULL, &voippacket, 0);
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
				if(opt_fork) printf("End of pcap file, exiting\n");
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
	int was_rtp;
	unsigned int packets = 0;
	bool useTcpReassemblyHttp;
	bool useTcpReassemblyWebrtc;
	bool useTcpReassemblySsl;
	u_int64_t packet_counter = 0;

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
	int res = 0;
#endif

	while(1) {
	 
		++packet_counter;

#ifdef QUEUE_MUTEX
		int res = sem_wait(&readpacket_thread_semaphore);
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
			usleep(qringusleep);
			continue;
		};
#endif

#ifdef QUEUE_NONBLOCK2
		if(pcap_qring[pcap_readit % pcap_qring_max].free == 1) {
			// no packet to read 
			if(terminating || readend) {
				//printf("packets: [%u]\n", packets);
				return NULL;
			}
			usleep(pcap_qring_usleep);
			continue;
		} else {
			pp = &(pcap_qring[pcap_readit % pcap_qring_max]);
		}
#endif
		packets++;

		int destroypp = 0;
		u_char *packet = pp->packet2 ? pp->packet2 : pp->packet;
		if(pp->packet2) {
			destroypp = 1;
		}

		header_ip = (struct iphdr2 *) ((char*)packet + pp->offset);

		bool nextPass;
		do {
			nextPass = false;
			if(header_ip->protocol == IPPROTO_IPIP) {
				// ip in ip protocol
				header_ip = (struct iphdr2 *) ((char*)header_ip + sizeof(iphdr2));
			} else if(header_ip->protocol == IPPROTO_GRE) {
				// gre protocol 
				header_ip = convertHeaderIP_GRE(header_ip);
				if(header_ip) {
					nextPass = true;
				}
			}
		} while(nextPass);
		if(!header_ip) {
			continue;
		}

		header_udp = &header_udp_tmp;
		useTcpReassemblyHttp = false;
		useTcpReassemblyWebrtc = false;
		useTcpReassemblySsl = false;
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
			if(opt_enable_http && (httpportmatrix[htons(header_tcp->source)] || httpportmatrix[htons(header_tcp->dest)])) {
				tcpReassembly->push(&pp->header, header_ip, packet);
				useTcpReassemblyHttp = true;
			} else if(opt_enable_webrtc && (webrtcportmatrix[htons(header_tcp->source)] || webrtcportmatrix[htons(header_tcp->dest)])) {
				tcpReassemblyWebrtc->push(&pp->header, header_ip, packet);
				useTcpReassemblyWebrtc = true;
			} els if(opt_enable_ssl && 
				 (isSslIpPort(htonl(header_ip->saddr), htons(header_tcp->source)) ||
				  isSslIpPort(htonl(header_ip->daddr), htons(header_tcp->dest)))) {
				tcpReassemblySsl->push(&pp->header, header_ip, packet);
				useTcpReassemblySsl = true;
			} else*/{
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
				delete [] pp->packet2;
				pp->packet2 = NULL;
			}
			pcap_qring[pcap_readit % pcap_qring_max].free = 1;
			if((pcap_readit + 1) == pcap_qring_max) {
				pcap_readit = 0;
			} else {
				pcap_readit++;
			}
#endif
			continue;
		}

		if(opt_mirrorip && (sipportmatrix[htons(header_udp->source)] || sipportmatrix[htons(header_udp->dest)])) {
			mirrorip->send((char *)header_ip, (int)(pp->header.caplen - ((char*)header_ip - (char*)packet)));
		}
		int voippacket = 0;
		if(!useTcpReassemblyHttp && !useTcpReassemblyWebrtc && !useTcpReassemblySsl &&
		   opt_enable_http < 2 && opt_enable_webrtc < 2 && opt_enable_ssl < 2) {
			process_packet(false, packet_counter,
				       header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
				       data, datalen, data - (char*)packet, 
				       global_pcap_handle, &pp->header, packet, 
				       istcp, &was_rtp, header_ip, &voippacket, 0,
				       NULL, 0, global_pcap_dlink, opt_id_sensor);
		}

		// if packet was VoIP add it to ipaccount
		if(opt_ipaccount) {
			ipaccount(pp->header.ts.tv_sec, (struct iphdr2 *) ((char*)(packet) + pp->offset), pp->header.len - pp->offset, voippacket);
		}

#ifdef QUEUE_NONBLOCK2
		if(destroypp) {
			delete [] pp->packet2;
			pp->packet2 = NULL;
		}
		pcap_qring[pcap_readit % pcap_qring_max].free = 1;
		if((pcap_readit + 1) == pcap_qring_max) {
			pcap_readit = 0;
		} else {
			pcap_readit++;
		}
#endif

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
		delete [] pp->packet;
		delete pp;
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
	u_char *newpacket = new FILE_LINE u_char[totallen];
	*packet = newpacket;
	struct pcap_pkthdr *newheader = new FILE_LINE pcap_pkthdr; // copy header
	memcpy(newheader, *header, sizeof(struct pcap_pkthdr));
	newheader->len = newheader->caplen = totallen;
	*header = newheader;
	unsigned int additionallen = 0;
	iphdr2 *iphdr = NULL;

	//int lastoffset = queue->begin()->second->offset;
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
		//lastoffset = node->offset;
		delete [] node->packet;
		if(node->firstheader) {
			delete [] node->firstheader;
		}
		delete node;
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
		ip_frag_s *node = new FILE_LINE ip_frag_s;

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
		node->packet = new FILE_LINE u_char[len];
		memcpy(node->packet, packet, len);
		node->offset = offset_d;

		// if it is first packet, copy first header at the beginning (which is typically ethernet header)
		if((offset & IP_OFFSET) == 0) {
			node->firstheaderlen = (char*)packet - (char*)(*origpacket);
			node->firstheader = new FILE_LINE char[node->firstheaderlen];
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
		queue = new FILE_LINE ip_frag_queue_t;
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
		delete tmpheader;
		delete [] tmppacket;
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
					
					delete [] node->packet;
					if(node->firstheader) {
						delete [] node->firstheader;
					}
					delete node;
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
	bool destroy;
	int was_rtp;
	pcapProcessData ppd;
	u_int64_t packet_counter = 0;

	global_pcap_dlink = pcap_datalink(handle);
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "DLT: %i", global_pcap_dlink);
	}

	init_hash();

	pcap_dumper_t *tmppcap = NULL;
	char pname[1024];

	if(opt_pcapdump) {
		sprintf(pname, "/var/spool/voipmonitor/voipmonitordump-%u.pcap", (unsigned int)time(NULL));
		tmppcap = pcap_dump_open(handle, pname);
	}

	while (!terminating) {
		destroy = 0;
		int res = pcap_next_ex(handle, &headerpcap, &packetpcap);
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
			if(opt_fork) printf("End of pcap file, exiting\n");
			break;
		} else if(res == 0) {
			//continue on timeout when reading live packets
			continue;
		}
		
		++packet_counter;

		if(!pcapProcess(&header, &packet, &destroy,
				true, true, true, true,
				&ppd, global_pcap_dlink, tmppcap, ifname)) {
			if(destroy) { 
				delete header; 
				delete [] packet; 
			}
			continue;
		}

		if(opt_pcap_threaded) {
			//add packet to queue
#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
			pcap_packet *pp = new FILE_LINE pcap_packet;
			pp->packet = new FILE_LINE u_char[header->caplen];
			pp->offset = ppd.header_ip_offset;
			memcpy(&pp->header, header, sizeof(struct pcap_pkthdr));
			memcpy(pp->packet, packet, header->caplen);
#endif

#ifdef QUEUE_NONBLOCK2
			while(pcap_qring[pcap_writeit % pcap_qring_max].free == 0) {
				// no room left, loop until there is room
				usleep(100);
			}
			if(header->caplen > MAXPACKETLENQRING) {
				//allocate special structure 
				//syslog(LOG_ERR, "error: packet is to large [%d]b for QRING[%d]b", header->caplen, MAXPACKETLENQRING);
				pcap_qring[pcap_writeit % pcap_qring_max].packet2 = new FILE_LINE u_char[header->caplen];
				memcpy(pcap_qring[pcap_writeit % pcap_qring_max].packet2, packet, header->caplen);
			} else {
				pcap_qring[pcap_writeit % pcap_qring_max].packet2 = NULL;
				memcpy(&pcap_qring[pcap_writeit % pcap_qring_max].packet, packet, header->caplen);
			}
			memcpy(&pcap_qring[pcap_writeit % pcap_qring_max].header, header, sizeof(struct pcap_pkthdr));
			pcap_qring[pcap_writeit % pcap_qring_max].offset = ppd.header_ip_offset;
			pcap_qring[pcap_writeit % pcap_qring_max].free = 0;
			if((pcap_writeit + 1) == pcap_qring_max) {
				pcap_writeit = 0;
			} else {
				pcap_writeit++;
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
			if(destroy) { delete header; delete [] packet;};
			continue;
		}

		if(opt_mirrorall || (opt_mirrorip && (sipportmatrix[htons(ppd.header_udp->source)] || sipportmatrix[htons(ppd.header_udp->dest)]))) {
			mirrorip->send((char *)ppd.header_ip, (int)(header->caplen - ((unsigned long) ppd.header_ip - (unsigned long) packet)));
		}
		int voippacket = 0;
		if(!opt_mirroronly) {
			process_packet(false, packet_counter,
				       ppd.header_ip->saddr, htons(ppd.header_udp->source), ppd.header_ip->daddr, htons(ppd.header_udp->dest), 
				       ppd.data, ppd.datalen, ppd.data - (char*)packet, 
				       handle, header, packet, 
				       ppd.istcp, &was_rtp, ppd.header_ip, &voippacket, 0,
				       NULL, 0, global_pcap_dlink, opt_id_sensor);
		}
		if(opt_ipaccount) {
			ipaccount(header->ts.tv_sec, (struct iphdr2 *) ((char*)packet + ppd.header_ip_offset), header->len - ppd.header_ip_offset, voippacket);
		}


		if(destroy) { 
			delete header; 
			delete [] packet;
		}
	}

	if(opt_pcapdump) {
		pcap_dump_close(tmppcap);
	}
}

void logPacketSipMethodCall(u_int64_t packet_number, int sip_method, int lastSIPresponseNum, pcap_pkthdr *header, 
			    unsigned int saddr, int source, unsigned int daddr, int dest,
			    Call *call, const char *descr) {
	static timeval firstPacketTime;
	if(!firstPacketTime.tv_sec) {
		firstPacketTime = header->ts;
	}
 
	if(!opt_read_from_file && descr && strstr(descr, "we are not interested")) {
		return;
	}
	
	map<unsigned, string> sipMethods;
	sipMethods[INVITE] = "INVITE";
	sipMethods[BYE] = "BYE";
	sipMethods[CANCEL] = "CANCEL";
	sipMethods[RES2XX] = "RES2XX";
	sipMethods[RES3XX] = "RES3XX";
	sipMethods[RES401] = "RES401";
	sipMethods[RES403] = "RES403";
	sipMethods[RES404] = "RES404";
	sipMethods[RES4XX] = "RES4XX";
	sipMethods[RES5XX] = "RES5XX";
	sipMethods[RES6XX] = "RES6XX";
	sipMethods[RES18X] = "RES18X";
	sipMethods[REGISTER] = "REGISTER";
	sipMethods[MESSAGE] = "MESSAGE";
	sipMethods[INFO] = "INFO";
	sipMethods[SUBSCRIBE] = "SUBSCRIBE";
	sipMethods[OPTIONS] = "OPTIONS";
	sipMethods[NOTIFY] = "NOTIFY";
	sipMethods[SKINNY_NEW] = "SKINNY_NEW";
	
	ostringstream outStr;

	outStr << "--- ";
	outStr << setw(5) << packet_number << " ";
	// ts
	outStr << "abstime: "
	       << setw(10)
	       << sqlDateTimeString(header->ts.tv_sec) << " "
	       << header->ts.tv_sec << "."
	       << setw(6)
	       << header->ts.tv_usec << "  ";
	outStr << "reltime: "
	       << setw(4) 
	       << (header->ts.tv_sec * 1000000ull + header->ts.tv_usec - 
		  (firstPacketTime.tv_sec * 1000000ull + firstPacketTime.tv_usec)) / 1000000ull << "."
	       << setw(6) << setfill('0')
	       << (header->ts.tv_sec * 1000000ull + header->ts.tv_usec - 
		  (firstPacketTime.tv_sec * 1000000ull + firstPacketTime.tv_usec)) % 1000000ull 
	       << setfill(' ')
	       << "  ";
	// ip / port
	outStr << "ip / port: "
	       << setw(15) << inet_ntostring(htonl(saddr))
	       << " / "
	       << setw(5) << source
	       << " -> "
	       << setw(15) << inet_ntostring(htonl(daddr))
	       << " / "
	       << setw(5) << dest;
	// sip metod
	outStr << endl << "    "
	       << "sip method: "
	       << setw(10);
	if(sip_method > 0 && sipMethods.find(sip_method) != sipMethods.end())
		outStr << sipMethods[sip_method];
	else
		outStr << sip_method;
	outStr << "  ";
	// calldate
	outStr << "calldate: "
	       << setw(19)
	       << (call ? sqlDateTimeString(call->calltime()) : "") << "  ";
	// duration
	outStr << "duration: "
	       << setw(5);
	if(call)
		outStr << call->duration() << "s";
	else
		outStr << "" << " ";
	outStr << "  ";
	// caller
	outStr << "caller: "
	       << setw(15)
	       << (call ? call->caller : "") << "  ";
	// called
	outStr << "called: "
	       << setw(15)
	       << (call ? call->called : "") << "  ";
	// lastSIPresponseNum
	outStr << "last response num: "
	       << setw(3)
	       << lastSIPresponseNum << "  ";
	// fbasename
	outStr << endl << "    "
	       << "fbasename: "
	       << setw(40)
	       << (call ? call->fbasename : "") << "  ";
	// seenbye
	outStr << "seenbye: "
	       << (call && call->seenbye ? "seenbye  " : "         ") << "  ";
	// destroy_call_at
	outStr << "destroy call at: "
	       << setw(19)
	       << (call && call->destroy_call_at ? sqlDateTimeString(call->destroy_call_at): "") << "  ";
	// descr
	if(descr) {
		outStr << endl << "    "
		       << "description: "
		       << descr;
	}
	
	if(opt_read_from_file) {
		cout << outStr.str() << endl;
	} else {
		syslog(LOG_NOTICE, outStr.str().c_str());
	}
}


TcpReassemblySip::TcpReassemblySip() {
	memset(tcp_streams_hashed, 0, sizeof(tcp_streams_hashed));
}

void TcpReassemblySip::processPacket(
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id,
		bool issip) {
	u_int hash = mkhash(saddr, source, daddr, dest) % MAX_TCPSTREAMS;
	tcp_stream2_s *findStream;
	if((findStream = tcp_streams_hashed[hash])) {
		addPacket(
			findStream, hash,
			packet_number,
			saddr, source, daddr, dest, data, datalen, dataoffset,
			handle, header, packet, header_ip,
			dlt, sensor_id);
		if(isCompleteStream(findStream)) {
			complete(findStream, hash);
		}
	} else {
		u_int rhash = mkhash(daddr, dest, saddr, source) % MAX_TCPSTREAMS;
		if((findStream = tcp_streams_hashed[rhash])) {
			tcp_stream2_s *lastStreamItem = getLastStreamItem(findStream);
			struct tcphdr2 *header_tcp = (struct tcphdr2 *) ((char *) header_ip + sizeof(*header_ip));
			if(lastStreamItem->lastpsh && lastStreamItem->ack_seq == htonl(header_tcp->seq)) {
				complete(findStream, rhash);
			}
		}
		if(issip) {
			tcp_streams_hashed[hash] = addPacket(
				NULL, hash,
				packet_number,
				saddr, source, daddr, dest, data, datalen, dataoffset,
				handle, header, packet, header_ip,
				dlt, sensor_id);
			tcp_streams_list.push_back(tcp_streams_hashed[hash]);
			if(isCompleteStream(tcp_streams_hashed[hash])) {
				complete(tcp_streams_hashed[hash], hash);
			}
		}
	}
}

void TcpReassemblySip::clean(time_t ts) {
	list<tcp_stream2_s*>::iterator stream;
	for (stream = tcp_streams_list.begin(); stream != tcp_streams_list.end();) {
		if(!ts || (ts - (*stream)->ts) > (10 * 60)) {
			// remove tcp stream after 10 minutes
			tcp_stream2_s *next, *tmpstream;
			tmpstream = tcp_streams_hashed[(*stream)->hash];
			tcp_streams_hashed[(*stream)->hash] = NULL;
			while(tmpstream) {
				delete [] tmpstream->data;
				delete [] tmpstream->packet;
				next = tmpstream->next;
				delete tmpstream;
				tmpstream = next;
			}
			tcp_streams_list.erase(stream++);
		} else {
			++stream;
		}
	}
}

TcpReassemblySip::tcp_stream2_s *TcpReassemblySip::addPacket(
		tcp_stream2_s *stream, u_int hash,
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id) {
	tcp_stream2_s *lastStreamItem = stream ? getLastStreamItem(stream) : NULL;
	
	tcp_stream2_s *newStreamItem = new FILE_LINE tcp_stream2_s;
	newStreamItem->next = NULL;
	newStreamItem->ts = header.ts.tv_sec;
	newStreamItem->hash = hash;

	struct tcphdr2 *header_tcp = (struct tcphdr2 *) ((char *) header_ip + sizeof(*header_ip));
	newStreamItem->lastpsh = header_tcp->psh;
	newStreamItem->seq = htonl(header_tcp->seq);
	newStreamItem->ack_seq = htonl(header_tcp->ack_seq);
	newStreamItem->next_seq = newStreamItem->seq + (unsigned long int)header.caplen - ((unsigned long int)header_tcp - (unsigned long int)packet + header_tcp->doff * 4);

	// append new created node at the end of list of TCP packets within this TCP connection
	if(lastStreamItem) {
		lastStreamItem->next = newStreamItem;
	}

	//copy data 
	newStreamItem->data = new FILE_LINE char[datalen];
	memcpy(newStreamItem->data, data, datalen);
	newStreamItem->datalen = datalen;

	//copy header
	newStreamItem->header = header;

	//copy packet
	newStreamItem->packet = new FILE_LINE u_char[header.caplen];
	memcpy(newStreamItem->packet, packet, header.caplen);
	
	newStreamItem->header_ip = (iphdr2*)(newStreamItem->packet + ((u_char*)header_ip - packet));

	newStreamItem->packet_number = packet_number;
	newStreamItem->saddr = saddr;
	newStreamItem->source = source;
	newStreamItem->daddr = daddr;
	newStreamItem->dest = dest;
	newStreamItem->dataoffset = dataoffset;
	newStreamItem->handle = handle;
	newStreamItem->dlt = dlt;
	newStreamItem->sensor_id = sensor_id;
	
	return(newStreamItem);
}

void TcpReassemblySip::complete(tcp_stream2_s *stream, u_int hash) {
	tcp_streams_list.remove(stream);
	int newlen = 0;
	for(tcp_stream2_s *tmpstream = stream; tmpstream; tmpstream = tmpstream->next) {
		newlen += tmpstream->datalen;
	}
	unsigned long diffLen = newlen - stream->datalen;
	pcap_pkthdr header = stream->header;
	iphdr2 *header_ip;
	u_char *newdata;
	u_char *newpacket;
	bool allocNewpacket = false;
	if(diffLen) {
		newdata = new FILE_LINE u_char[newlen];
		int len = 0;
		for(tcp_stream2_s *tmpstream = stream; tmpstream; tmpstream = tmpstream->next) {
			memcpy(newdata + len, tmpstream->data, tmpstream->datalen);
			len += tmpstream->datalen;
		}
		header.caplen += diffLen;
		header.len += diffLen;
		newpacket = new FILE_LINE u_char[header.caplen];
		allocNewpacket = true;
		memcpy(newpacket, stream->packet, stream->header.caplen - stream->datalen);
		memcpy(newpacket + (stream->header.caplen - stream->datalen), newdata, newlen);
		delete [] newdata;
		newdata = newpacket + (stream->header.caplen - stream->datalen);
		header_ip = (iphdr2*)(newpacket + ((u_char*)stream->header_ip - stream->packet));
		header_ip->tot_len = htons(ntohs(header_ip->tot_len) + diffLen);
	} else {
		newpacket = stream->packet;
		newdata = stream->packet + stream->dataoffset;
		header_ip = stream->header_ip;
	}
	if(preProcessPacket && opt_enable_preprocess_packet == 2) {
		preProcessPacket->push(false, stream->packet_number,
				       stream->saddr, stream->source, stream->daddr, stream->dest, 
				       (char*)newdata, newlen, stream->dataoffset,
				       stream->handle, &header, newpacket, true,
				       2, header_ip, 0,
				       NULL, 0, stream->dlt, stream->sensor_id,
				       true);
		tcp_stream2_s *tmpstream = tcp_streams_hashed[hash];
		while(tmpstream) {
			delete [] tmpstream->data;
			if(diffLen) {
				delete [] tmpstream->packet;
			}
			tcp_stream2_s *next = tmpstream->next;
			delete tmpstream;
			tmpstream = next;
		}
	} else {
		int tmp_was_rtp;
		int tmp_voippacket;
		process_packet(false, stream->packet_number,
			       stream->saddr, stream->source, stream->daddr, stream->dest, 
			       (char*)newdata, newlen, stream->dataoffset,
			       stream->handle, &header, newpacket, 
			       2, &tmp_was_rtp, header_ip, &tmp_voippacket, 0,
			       NULL, 0, stream->dlt, stream->sensor_id, 
			       false);
		if(allocNewpacket) {
			delete [] newpacket;
		}
		tcp_stream2_s *tmpstream = tcp_streams_hashed[hash];
		while(tmpstream) {
			delete [] tmpstream->data; 
			delete [] tmpstream->packet;
			tcp_stream2_s *next = tmpstream->next;
			delete tmpstream;
			tmpstream = next;
		}
	}
	tcp_streams_hashed[hash] = NULL;
}


inline void *_PreProcessPacket_outThreadFunction(void *arg) {
	return(((PreProcessPacket*)arg)->outThreadFunction());
}

PreProcessPacket::PreProcessPacket() {
	this->qringmax = opt_preprocess_packets_qring_length;
	this->readit = 0;
	this->writeit = 0;
	this->qring = new FILE_LINE packet_parse_s*[this->qringmax];
	for(unsigned int i = 0; i < this->qringmax; i++) {
		this->qring[i] = new FILE_LINE packet_parse_s;
		this->qring[i]->used = 0;
		this->qring[i]->parse.setStdParse();
	}
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->outThreadId = 0;
	this->_sync_push = 0;
	this->term_preProcess = false;
	pthread_create(&this->out_thread_handle, NULL, _PreProcessPacket_outThreadFunction, this);
}

PreProcessPacket::~PreProcessPacket() {
	terminate();
	for(unsigned int i = 0; i < this->qringmax; i++) {
		delete this->qring[i];
	}
	delete [] this->qring;
}

void PreProcessPacket::push(bool is_ssl, u_int64_t packet_number,
			    unsigned int saddr, int source, unsigned int daddr, int dest, 
			    char *data, int datalen, int dataoffset,
			    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, bool packetDelete,
			    int istcp, struct iphdr2 *header_ip, int forceSip,
			    pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
			    bool disableLock) {
 
	if (header->ts.tv_sec - preprocess_packet__last_cleanup > 10){
		// clean tcp_streams_list
		tcpReassemblySip.clean(header->ts.tv_sec);
		preprocess_packet__last_cleanup = header->ts.tv_sec;
	}
 
	if(opt_enable_ssl && !disableLock) {
		this->lock_push();
	}
	if(block_store) {
		block_store->lock_packet(block_store_index);
	}
	while(this->qring[this->writeit]->used != 0) {
		usleep(10);
	}
	packet_parse_s *_parse_packet = this->qring[this->writeit];
	packet_s *_packet = &_parse_packet->packet;
	_packet->is_ssl = is_ssl;
	_packet->packet_number = packet_number;
	_packet->saddr = saddr;
	_packet->source = source;
	_packet->daddr = daddr; 
	_packet->dest = dest;
	_packet->data = data; 
	_packet->datalen = datalen; 
	_packet->dataoffset = dataoffset;
	_packet->handle = handle; 
	_packet->header = *header; 
	_packet->packet = packet; 
	_packet->packetDelete = packetDelete; 
	_packet->istcp = istcp; 
	_packet->header_ip = header_ip; 
	_packet->forceSip = forceSip; 
	_packet->block_store = block_store; 
	_packet->block_store_index = block_store_index; 
	_packet->dlt = dlt; 
	_packet->sensor_id = sensor_id;
	if(forceSip ||
	   sipportmatrix[_packet->source] || 
	   sipportmatrix[_packet->dest]) {
		_parse_packet->sipDataLen = _parse_packet->parse.parseData(_packet->data, _packet->datalen, true);
		_parse_packet->isSip = _parse_packet->parse.isSip();
	} else {
		_parse_packet->sipDataLen = 0;
		_parse_packet->isSip = false;
	}
	
	if(_parse_packet->isSip) {
		_parse_packet->init();
		if(opt_enable_preprocess_packet == 2 &&
		   !this->sipProcess(_parse_packet)) {
			if(block_store) {
				block_store->unlock_packet(block_store_index);
			}
			if(opt_enable_ssl && !disableLock) {
				this->unlock_push();
			}
			return;
		}
		_parse_packet->hash[0] = 0;
		_parse_packet->hash[1] = 0;
	} else if(datalen > 2/* && (htons(*(unsigned int*)data) & 0xC000) == 0x8000*/) { // disable condition - failure for udptl (fax)
		_parse_packet->hash[0] = tuplehash(saddr, source);
		_parse_packet->hash[1] = tuplehash(daddr, dest);
	}
	
	_parse_packet->used = 1;
	if((this->writeit + 1) == this->qringmax) {
		this->writeit = 0;
	} else {
		this->writeit++;
	}
	if(opt_enable_ssl && !disableLock) {
		this->unlock_push();
	}
}

void *PreProcessPacket::outThreadFunction() {
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start PreProcessPacket out thread %i", this->outThreadId);
	while(!this->term_preProcess) {
		if(this->qring[this->readit]->used == 1) {
			int was_rtp = 0;
			int voippacket = 0;
			packet_parse_s *_parse_packet = this->qring[this->readit];
			packet_s *_packet = &_parse_packet->packet;
			process_packet(_packet->is_ssl, _packet->packet_number,
				       _packet->saddr, _packet->source, _packet->daddr, _packet->dest, 
				       _packet->data, _packet->datalen, _packet->dataoffset,
				       _packet->handle, &_packet->header, _packet->packet, 
				       _packet->istcp, &was_rtp, _packet->header_ip, &voippacket, _packet->forceSip,
				       _packet->block_store, _packet->block_store_index, _packet->dlt, _packet->sensor_id, 
				       true, 0,
				       _parse_packet);
			if(_packet->block_store) {
				_packet->block_store->unlock_packet(_packet->block_store_index);
			}
			if(_packet->packetDelete) {
				delete [] _packet->packet;
			}
			_parse_packet->used = 0;
			if((this->readit + 1) == this->qringmax) {
				this->readit = 0;
			} else {
				this->readit++;
			}
		} else {
			usleep(opt_preprocess_packets_qring_usleep);
		}
	}
	return(NULL);
}

void PreProcessPacket::preparePstatData() {
	if(this->outThreadId) {
		if(this->threadPstatData[0].cpu_total_time) {
			this->threadPstatData[1] = this->threadPstatData[0];
		}
		pstat_get_data(this->outThreadId, this->threadPstatData);
	}
}

double PreProcessPacket::getCpuUsagePerc(bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData();
	}
	if(this->outThreadId) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[0].cpu_total_time && this->threadPstatData[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[0], &this->threadPstatData[1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

void PreProcessPacket::terminate() {
	this->term_preProcess = true;
	pthread_join(this->out_thread_handle, NULL);
}

bool PreProcessPacket::sipProcess(packet_parse_s *parse_packet) {
	parse_packet->_getCallID_reassembly = true;
	if(!this->sipProcess_getCallID(parse_packet)) {
		return(false);
	}
	if(!this->sipProcess_reassembly(parse_packet)) {
		return(false);
	}
	this->sipProcess_getSipMethod(parse_packet);
	this->sipProcess_getLastSipResponse(parse_packet);
	
	// UNUSED - UNSTABLE
	//this->sipProcess_findCall(parse_packet);
	//this->sipProcess_createCall(parse_packet);
	
	return(true);
}

bool PreProcessPacket::sipProcess_getCallID(packet_parse_s *parse_packet) {
	packet_s *_packet = &parse_packet->packet;
	char *s;
	unsigned long l;
	s = gettag(_packet->data, parse_packet->sipDataLen, "\nCall-ID:", &l, NULL, &parse_packet->parse);
	if(l <= 0 || l > 1023) {
		// try also compact header
		s = gettag(_packet->data, parse_packet->sipDataLen,"\ni:", &l, NULL, &parse_packet->parse);
		if(l <= 0 || l > 1023) {
			// no Call-ID found in packet
			if(_packet->istcp == 1 && _packet->header_ip) {
				tcpReassemblySip.processPacket(
					_packet->packet_number,
					_packet->saddr, _packet->source, _packet->daddr, _packet->dest, _packet->data, _packet->datalen, _packet->dataoffset,
					_packet->handle, _packet->header, _packet->packet, _packet->header_ip,
					_packet->dlt, _packet->sensor_id,
					true);
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(_packet->packet_number, 0, 0, &_packet->header, 
						_packet->saddr, _packet->source, _packet->daddr, _packet->dest,
						NULL, "it is TCP and callid not found");
				}
				return(false);
			} else {
				// it is not TCP and callid not found
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(_packet->packet_number, 0, 0, &_packet->header, 
						_packet->saddr, _packet->source, _packet->daddr, _packet->dest,
						NULL, "it is not TCP and callid not found");
				}
				return(false);
			}
		}
	}
	if(l > 0 && l <= 1023) {
		char callidstr[1024];
		memcpy(callidstr, s, MIN(l, 1024));
		callidstr[MIN(l, 1023)] = '\0';
		parse_packet->callid = callidstr;
		return(true);
	}
	return(false);
}

bool PreProcessPacket::sipProcess_reassembly(packet_parse_s *parse_packet) {
	packet_s *_packet = &parse_packet->packet;
	if(_packet->istcp == 1 && _packet->datalen >= 2) {
		tcpReassemblySip.processPacket(
			_packet->packet_number,
			_packet->saddr, _packet->source, _packet->daddr, _packet->dest, _packet->data, _packet->datalen, _packet->dataoffset,
			_packet->handle, _packet->header, _packet->packet, _packet->header_ip,
			_packet->dlt, _packet->sensor_id,
			true);
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(_packet->packet_number, 0, 0, &_packet->header, 
				_packet->saddr, _packet->source, _packet->daddr, _packet->dest,
				NULL, "it is TCP and callid found");
		}
		return(false);
	}
	return(true);
}

void PreProcessPacket::sipProcess_getSipMethod(packet_parse_s *parse_packet) {
	packet_s *_packet = &parse_packet->packet;
	parse_packet->sip_method = process_packet__parse_sip_method(_packet->data, parse_packet->sipDataLen);
	parse_packet->_getSipMethod = true;
}

void PreProcessPacket::sipProcess_getLastSipResponse(packet_parse_s *parse_packet) {
	char lastSIPresponse[1024];
	packet_s *_packet = &parse_packet->packet;
	parse_packet->lastSIPresponseNum = parse_packet__last_sip_response(_packet->data, parse_packet->sipDataLen, parse_packet->sip_method,
									   lastSIPresponse, &parse_packet->call_cancel_lsr487);
	parse_packet->lastSIPresponse = lastSIPresponse;
	parse_packet->_getLastSipResponse = true;
}

void PreProcessPacket::sipProcess_findCall(packet_parse_s *parse_packet) {
   
	// UNUSED - UNSTABLE
	return;
	
	packet_s *_packet = &parse_packet->packet;
	parse_packet->call = calltable->find_by_call_id((char*)parse_packet->callid.c_str(), parse_packet->callid.length());
	if(parse_packet->call) {
		if(parse_packet->call->type == REGISTER) {
			parse_packet->call = NULL;
			return;
		}
		parse_packet->call->handle_dscp(parse_packet->sip_method, _packet->header_ip, _packet->saddr, _packet->daddr, NULL, !IS_SIP_RESXXX(parse_packet->sip_method));
		if(pcap_drop_flag) {
			parse_packet->call->pcap_drop = pcap_drop_flag;
		}
		if(parse_packet->call_cancel_lsr487) {
			parse_packet->call->cancel_lsr487 = true;
		}
	}
	parse_packet->_findCall = true;
}

void PreProcessPacket::sipProcess_createCall(packet_parse_s *parse_packet) {
 
	// UNUSED - UNSTABLE
	return;
 
	packet_s *_packet = &parse_packet->packet;
	if(!parse_packet->call) {
		if(parse_packet->sip_method == INVITE || parse_packet->sip_method == MESSAGE || 
		   (opt_sip_register && parse_packet->sip_method == REGISTER)) {
			parse_packet->call_created = new_invite_register(false, parse_packet->sip_method, _packet->data, parse_packet->sipDataLen, &_packet->header, (char*)parse_packet->callid.c_str(), 
									 _packet->saddr, _packet->daddr, _packet->source, _packet->dest,
									 _packet->handle, _packet->dlt, _packet->sensor_id,
									 &parse_packet->detectUserAgent,
									 &parse_packet->parse);
		}
	}
	parse_packet->_createCall = true;
}

inline void *_ProcessRtpPacket_outThreadFunction(void *arg) {
	return(((ProcessRtpPacket*)arg)->outThreadFunction());
}

ProcessRtpPacket::ProcessRtpPacket(int indexThread) {
	this->indexThread = indexThread;
	this->qringmax = opt_process_rtp_packets_qring_length;
	this->readit = 0;
	this->writeit = 0;
	this->qring = new FILE_LINE packet_s[this->qringmax];
	for(unsigned int i = 0; i < this->qringmax; i++) {
		this->qring[i].used = 0;
	}
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->outThreadId = 0;
	this->term_processRtp = false;
	#if RTP_PROF
	__prof__ProcessRtpPacket_outThreadFunction_begin = 0;
	__prof__ProcessRtpPacket_outThreadFunction = 0;
	__prof__ProcessRtpPacket_outThreadFunction__usleep = 0;
	__prof__ProcessRtpPacket_rtp = 0;
	__prof__ProcessRtpPacket_rtp__hashfind = 0;
	__prof__ProcessRtpPacket_rtp__fill_call_array = 0;
	__prof__process_packet__rtp = 0;
	__prof__add_to_rtp_thread_queue = 0;
	#endif
	pthread_create(&this->out_thread_handle, NULL, _ProcessRtpPacket_outThreadFunction, this);
}

ProcessRtpPacket::~ProcessRtpPacket() {
	terminate();
	delete [] this->qring;
}

void ProcessRtpPacket::push(unsigned int saddr, int source, unsigned int daddr, int dest, 
			    char *data, int datalen, int dataoffset,
			    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int istcp, struct iphdr2 *header_ip,
			    pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
			    unsigned int hash_s, unsigned int hash_d) {
	if(block_store) {
		block_store->lock_packet(block_store_index);
	}
	while(this->qring[this->writeit].used != 0) {
		usleep(10);
	}
	packet_s *_packet = &this->qring[this->writeit];
	_packet->saddr = saddr;
	_packet->source = source;
	_packet->daddr = daddr; 
	_packet->dest = dest;
	_packet->data = data; 
	_packet->datalen = datalen; 
	_packet->dataoffset = dataoffset;
	_packet->handle = handle;
	_packet->header = *header; 
	_packet->packet = packet; 
	_packet->istcp = istcp;
	_packet->header_ip = header_ip;
	_packet->block_store = block_store; 
	_packet->block_store_index = block_store_index; 
	_packet->dlt = dlt; 
	_packet->sensor_id = sensor_id;
	_packet->hash_s = hash_s;
	_packet->hash_d = hash_d;
	_packet->used = 1;
	if((this->writeit + 1) == this->qringmax) {
		this->writeit = 0;
	} else {
		this->writeit++;
	}
}

void *ProcessRtpPacket::outThreadFunction() {
	#if RTP_PROF
	__prof__ProcessRtpPacket_outThreadFunction_begin = rdtsc();
	#endif
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start ProcessRtpPacket out thread %i", this->outThreadId);
	while(!this->term_processRtp) {
		if(this->qring[this->readit].used == 1) {
			packet_s *_packet = &this->qring[this->readit];
			this->rtp(_packet);
			if(_packet->block_store) {
				_packet->block_store->unlock_packet(_packet->block_store_index);
			}
			_packet->used = 0;
			if((this->readit + 1) == this->qringmax) {
				this->readit = 0;
			} else {
				this->readit++;
			}
		} else {
			#if RTP_PROF
			unsigned long long __prof_begin2 = rdtsc();
			#endif
			usleep(opt_process_rtp_packets_qring_usleep);
			#if RTP_PROF
			__prof__ProcessRtpPacket_outThreadFunction__usleep += rdtsc() - __prof_begin2;
			#endif
		}
		#if RTP_PROF
		__prof__ProcessRtpPacket_outThreadFunction = rdtsc() - __prof__ProcessRtpPacket_outThreadFunction_begin;
		#endif
	}
	return(NULL);
}

void ProcessRtpPacket::rtp(packet_s *_packet) {
	#if RTP_PROF
	unsigned long long __prof_begin = rdtsc();
	#endif
	hash_node_call *calls = NULL;;
	bool find_by_dest = false;
	calltable->lock_calls_hash();
	#if RTP_PROF
	unsigned long long __prof_begin2 = rdtsc();
	#endif
	if((calls = calltable->hashfind_by_ip_port(_packet->daddr, _packet->dest, _packet->hash_d, false))) {
		find_by_dest = true;
	} else {
		calls = calltable->hashfind_by_ip_port(_packet->saddr, _packet->source, _packet->hash_s, false);
	}
	#if RTP_PROF
	__prof__ProcessRtpPacket_rtp__hashfind += rdtsc() - __prof_begin2;
	#endif
	rtp_call_info call_info[20];
	#if RTP_PROF
	unsigned long long __prof_begin3 = rdtsc();
	#endif
	size_t call_info_length = 0;
	if(calls) {
		hash_node_call *node_call;
		for (node_call = (hash_node_call *)calls; node_call != NULL; node_call = node_call->next) {
			call_info[call_info_length].call = node_call->call;
			call_info[call_info_length].iscaller = node_call->iscaller;
			call_info[call_info_length].is_rtcp = node_call->is_rtcp;
			call_info[call_info_length].is_fax = node_call->is_fax;
			call_info[call_info_length].use_sync = false;
			#if SYNC_CALL_RTP
			__sync_add_and_fetch(&node_call->call->rtppcaketsinqueue, 1);
			#else
			++node_call->call->rtppcaketsinqueue_p;
			#endif
			++call_info_length;
		}
	}
	#if RTP_PROF
	__prof__ProcessRtpPacket_rtp__fill_call_array += rdtsc() - __prof_begin3;
	#endif
	calltable->unlock_calls_hash();
	if(call_info_length) {
		process_packet__rtp(call_info, call_info_length,
				    _packet->saddr, _packet->source, _packet->daddr, _packet->dest, 
				    _packet->data, _packet->datalen, _packet->dataoffset,
				    &_packet->header, _packet->packet, _packet->istcp, _packet->header_ip,
				    _packet->block_store, _packet->block_store_index, _packet->dlt, _packet->sensor_id,
				    NULL, NULL,
				    find_by_dest, indexThread + 1);
	} else {
		if(opt_rtpnosip) {
			process_packet__rtp_nosip(_packet->saddr, _packet->source, _packet->daddr, _packet->dest, 
						  _packet->data, _packet->datalen, _packet->dataoffset,
						  &_packet->header, _packet->packet, _packet->istcp, _packet->header_ip,
						  _packet->block_store, _packet->block_store_index, _packet->dlt, _packet->sensor_id,
						  _packet->handle);
		}
	}
	#if RTP_PROF
	__prof__ProcessRtpPacket_rtp += rdtsc() - __prof_begin;
	#endif
}

void ProcessRtpPacket::preparePstatData() {
	if(this->outThreadId) {
		if(this->threadPstatData[0].cpu_total_time) {
			this->threadPstatData[1] = this->threadPstatData[0];
		}
		pstat_get_data(this->outThreadId, this->threadPstatData);
	}
}

double ProcessRtpPacket::getCpuUsagePerc(bool preparePstatData) {
	if(preparePstatData) {
		this->preparePstatData();
	}
	if(this->outThreadId) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[0].cpu_total_time && this->threadPstatData[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[0], &this->threadPstatData[1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

void ProcessRtpPacket::terminate() {
	this->term_processRtp = true;
	pthread_join(this->out_thread_handle, NULL);
}
