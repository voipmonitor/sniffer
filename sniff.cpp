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
#include "sniff_proc_class.h"
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

unsigned int defrag_counter = 0;
unsigned int duplicate_counter = 0;
extern struct pcap_stat pcapstat;
int pcapstatresCount = 0;

volatile unsigned int glob_last_packet_time;

Calltable *calltable;
extern volatile int calls_counter;
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
extern char opt_fbasename_header[128];
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
extern int opt_rtpnosip;
extern char opt_cachedir[1024];
extern int opt_savewav_force;
extern int opt_saveudptl;
extern nat_aliases_t nat_aliases;
extern int opt_enable_preprocess_packet;
extern int opt_enable_process_rtp_packet;
extern int process_rtp_packets_distribute_threads_use;
extern int opt_process_rtp_packets_hash_next_thread;
extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
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
extern PreProcessPacket *preProcessPacket[MAX_PREPROCESS_PACKET_THREADS];
extern ProcessRtpPacket *processRtpPacketHash;
extern ProcessRtpPacket *processRtpPacketDistribute[MAX_PROCESS_RTP_PACKET_THREADS];
extern CustomHeaders *custom_headers_cdr;
extern CustomHeaders *custom_headers_message;
extern bool _save_sip_history;
extern bool _save_sip_history_request_types[1000];
extern bool _save_sip_history_all_requests;
extern bool _save_sip_history_all_responses;
unsigned int glob_ssl_calls = 0;

inline char * gettag(const void *ptr, unsigned long len, ParsePacket *parsePacket,
		     const char *tag, unsigned long *gettaglen, unsigned long *limitLen = NULL);
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
u_int64_t counter_calls_clean;
u_int64_t counter_sip_packets[2];
u_int64_t counter_sip_register_packets;
u_int64_t counter_sip_message_packets;
u_int64_t counter_rtp_packets;
u_int64_t counter_all_packets;
u_int64_t process_rtp_counter;
u_int64_t read_rtp_counter;

extern struct queue_state *qs_readpacket_thread_queue;

map<unsigned int, livesnifferfilter_t*> usersniffer;
volatile int usersniffer_sync;

#define ENABLE_CONVERT_DLT_SLL_TO_EN10(dlt)	(dlt == DLT_LINUX_SLL && opt_convert_dlt_sll_to_en10 && global_pcap_handle_dead_EN10MB)


#include "sniff_inline.h"


unsigned long process_packet__last_cleanup = 0;
unsigned long process_packet__last_filter_reload = 0;
unsigned long process_packet__last_destroy_calls = 0;
unsigned long preprocess_packet__last_cleanup = 0;


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

inline void save_packet_sql(Call *call, 
			    struct pcap_pkthdr *header, const u_char *packet, ParsePacket *parsePacket,
			    unsigned int saddr, int source, unsigned int daddr, int dest, 
			    int istcp, char *data, int datalen, int uid, 
			    int dlt, int sensor_id) {
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
			char *s = gettag(data, datalen, parsePacket,
					 "\nCall-ID:", &l);
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

int get_sip_peername(char *data, int data_len, ParsePacket *parsePacket,
		     const char *tag, char *peername, unsigned int peername_len);
int get_sip_headerstr(char *data, int data_len, ParsePacket *parsePacket,
                     const char *tag, char *headerstr, unsigned int headerstr_len);

inline void save_live_packet(Call *call, packet_s *packetS, ParsePacket *parsePacket, unsigned char sip_type) {
	if(!global_livesniffer) {
		return;
	}
	// check saddr and daddr filters
	unsigned int daddr = htonl(packetS->daddr);
	unsigned int saddr = htonl(packetS->saddr);

	while(__sync_lock_test_and_set(&usersniffer_sync, 1));
	
	map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT;
	
	char caller[1024] = "", called[1024] = "";
	char fromhstr[1024] = "", tohstr[1024] = "";
        //Check if we use from/to header for filtering, if yes gather info from packet to fromhstr tohstr
        {
                bool needfromhstr = false;
                bool needtohstr = false;
                int res;
                for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); usersnifferIT++) {
                        if(!usersnifferIT->second->state.all_all && !usersnifferIT->second->state.all_hstr) {
                                for(int i = 0; i < MAXLIVEFILTERS; i++) {
                                        if(!usersnifferIT->second->state.all_fromhstr && usersnifferIT->second->lv_fromhstr[i][0]) {
                                                needfromhstr = true;
                                        }
                                        if(!usersnifferIT->second->state.all_tohstr && usersnifferIT->second->lv_tohstr[i][0]) {
                                                needtohstr = true;
                                        }
                                        if(!usersnifferIT->second->state.all_bothhstr && usersnifferIT->second->lv_bothhstr[i][0]) {
                                                needfromhstr = true;
                                                needtohstr = true;
                                        }
                                }
                        }
                }
                if(needfromhstr) {
                        res = get_sip_headerstr(packetS->data,packetS->datalen,parsePacket,
						"\nFrom:", fromhstr, sizeof(fromhstr));
                        if(res) {
                                // try compact header
                                get_sip_headerstr(packetS->data,packetS->datalen,parsePacket,
						"\nf:", fromhstr, sizeof(fromhstr));

                        }
                }
                if(needtohstr) {
                        res = get_sip_headerstr(packetS->data,packetS->datalen,parsePacket,
						"\nTo:", tohstr, sizeof(tohstr));
                        if(res) {
                                // try compact header
                                get_sip_headerstr(packetS->data,packetS->datalen,parsePacket,
						"\nt:", tohstr, sizeof(tohstr));
                        }
                }
        }
        //If call is established get caller/called num from packet - else gather it from packet and save to caller called
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
			res = get_sip_peername(packetS->data, packetS->datalen, parsePacket,
					       "\nFrom:", caller, sizeof(caller));
			if(res) {
				// try compact header
				get_sip_peername(packetS->data, packetS->datalen, parsePacket,
						 "\nf:", caller, sizeof(caller));
			}
		}
		if(needcalled) {
			res = get_sip_peername(packetS->data, packetS->datalen, parsePacket,
					       "\nTo:", called, sizeof(called));
			if(res) {
				// try compact header
				get_sip_peername(packetS->data,packetS->datalen, parsePacket,
						 "\nt:", called, sizeof(called));
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
                        bool okHeader = filter->state.all_hstr;
                        if(!okHeader) {
                                for(int i = 0; i < MAXLIVEFILTERS && !okHeader; i++) {
                                        if((filter->state.all_fromhstr || (filter->lv_fromhstr[i][0] &&
                                                memmem(fromhstr, strlen(fromhstr), filter->lv_fromhstr[i], strlen(filter->lv_fromhstr[i])))) &&
                                           (filter->state.all_tohstr || (filter->lv_tohstr[i][0] &&
                                                memmem(tohstr, strlen(tohstr), filter->lv_tohstr[i], strlen(filter->lv_tohstr[i])))) &&
                                           (filter->state.all_bothhstr || (filter->lv_bothhstr[i][0] &&
                                                (memmem(fromhstr, strlen(fromhstr), filter->lv_bothhstr[i], strlen(filter->lv_bothhstr[i])) ||
                                                 memmem(tohstr, strlen(tohstr), filter->lv_bothhstr[i], strlen(filter->lv_bothhstr[i])))))) {
                                                okHeader = true;
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
			if(okAddr && okNum && okSipType && okHeader) {
				save = true;
			}
		}
		if(save) {
			save_packet_sql(call,
					&packetS->header, packetS->packet, parsePacket,
					saddr, packetS->source, daddr, packetS->dest, 
					packetS->istcp, packetS->data, packetS->datalen, usersnifferIT->first, 
					packetS->dlt, packetS->sensor_id);
		}
	}
	
	__sync_lock_release(&usersniffer_sync);
}

inline void save_live_packet(Call *call, 
			     struct pcap_pkthdr *header, const u_char *packet, ParsePacket *parsePacket,
			     unsigned int saddr, int source, unsigned int daddr, int dest, 
			     int istcp, char *data, int datalen, unsigned char sip_type, 
			     int dlt, int sensor_id) {
	packet_s packetS;
	packetS.header = *header;
	packetS.packet = packet;
	packetS.saddr = saddr;
	packetS.source = source;
	packetS.daddr = daddr;
	packetS.dest = dest;
	packetS.istcp = istcp;
	packetS.data = data;
	packetS.datalen = datalen;
	packetS.dlt = dlt;
	packetS.sensor_id = sensor_id;
	save_live_packet(call, &packetS, parsePacket, sip_type);
}

static int parse_packet__message(char *data, unsigned int datalen, ParsePacket *parsePacket, bool strictCheckLength,
				 char **rsltMessage, string *rsltDestNumber, string *rsltSrcNumber, unsigned int *rsltContentLength,
				 bool maskMessage = false);

/*
   save packet into file 
   type - 1 is SIP, 2 is RTP, 3 is RTCP

*/
void save_packet(Call *call, packet_s *packetS, ParsePacket *parsePacket, int type, int forceSip) {
	bool allocPacket = false;
	bool allocHeader = false;
	const u_char *packet = packetS->packet;
	pcap_pkthdr *header = &packetS->header;
	u_int16_t old_header_ip_tot_len = packetS->header_ip->tot_len;
	if(ENABLE_CONVERT_DLT_SLL_TO_EN10(packetS->dlt)) {
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
	if(packetS->dataoffset > 0 && packetS->dataoffset < 100 &&
	   ((call->type == MESSAGE && opt_hide_message_content) || 
	    (packetS->istcp && header->caplen > limitCapLen))) {
		unsigned long l;
		char *s = gettag(packetS->data, packetS->datalen, parsePacket,
				 "\nContent-Length:", &l);
		if(l && l < (unsigned)packetS->datalen) {
			long int contentLength = atol(s);
			if(contentLength > 0) {
				if(packetS->istcp &&
				   header->caplen > limitCapLen &&
				   (u_char*)packetS->header_ip > packet && 
				   (u_char*)packetS->header_ip - packet < 100) {
					u_int32_t diffLen = header->caplen - limitCapLen;
					header->caplen -= diffLen;
					header->len -= diffLen;
					packetS->header_ip->tot_len = htons(ntohs(packetS->header_ip->tot_len) - diffLen);
					contentLength -= diffLen;
					while(*s == ' ') {
						++s;
					}
					char contLengthStr[10];
					sprintf(contLengthStr, "%u", (unsigned int)contentLength);
					char *pointToModifyContLength = (char*)packet + packetS->dataoffset + (s - packetS->data); 
					strncpy(pointToModifyContLength, contLengthStr, strlen(contLengthStr));
					char *pointToEndModifyContLength = pointToModifyContLength + strlen(contLengthStr);
					while(*pointToEndModifyContLength != '\r') {
						*pointToEndModifyContLength = ' ';
						++pointToEndModifyContLength;
					}
				}
				if(call->type == MESSAGE && opt_hide_message_content) {
					const u_char *packet_orig = packet;
					packet = (const u_char*) new FILE_LINE u_char[header->caplen];
					memcpy((u_char*)packet, packet_orig, header->caplen);
					allocPacket = true;
					parse_packet__message((char*)(packet + packetS->dataoffset), packetS->datalen, parsePacket, false,
							      NULL, NULL, NULL, NULL,
							      true);
					/* obsolete
					char *endHeaderSepPos = (char*)memmem(data, datalen, "\r\n\r\n", 4);
					if(endHeaderSepPos) {
						const u_char *packet_orig = packet;
						packet = (const u_char*) new FILE_LINE u_char[header->caplen];
						memcpy((u_char*)packet, packet_orig, header->caplen);
						u_char *message = (u_char*)packet + dataoffset + (endHeaderSepPos - data) + 4;
						memset((u_char*)message, 'x', min(contentLength, (long int)(header->caplen - (message - packet))));
						allocPacket = true;
					}
					*/
				}
			}
		}
	}
 
	// check if it should be stored to mysql 
	if(type == TYPE_SIP and global_livesniffer and (sipportmatrix[packetS->source] || sipportmatrix[packetS->dest] || forceSip)) {
		save_live_packet(call, 
				 header, packet, parsePacket,
				 packetS->saddr, packetS->source, packetS->daddr, packetS->dest, 
				 packetS->istcp, packetS->data, packetS->datalen, call->type, 
				 packetS->dlt, packetS->sensor_id);
	}

	if(opt_newdir and opt_pcap_split) {
		switch(type) {
		case TYPE_SKINNY:
		case TYPE_SIP:
			if(call->getPcapSip()->isOpen()){
				call->set_last_packet_time(header->ts.tv_sec);
				if(type == TYPE_SIP) {
					call->getPcapSip()->dump(header, packet, packetS->dlt, false, (u_char*)packetS->data, packetS->datalen, packetS->saddr, packetS->daddr, packetS->source, packetS->dest, packetS->istcp);
				} else {
					call->getPcapSip()->dump(header, packet, packetS->dlt);
				}
			}
			break;
		case TYPE_RTP:
		case TYPE_RTCP:
			if(call->getPcapRtp()->isOpen()){
				call->set_last_packet_time(header->ts.tv_sec);
				call->getPcapRtp()->dump(header, packet, packetS->dlt);
			} else if(enable_save_rtp(call)) {
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
					call->getPcapRtp()->dump(header, packet, packetS->dlt);
				}
			}
			break;
		}
	} else {
		if (call->getPcap()->isOpen()){
			call->set_last_packet_time(header->ts.tv_sec);
			if(type == TYPE_SIP) {
				call->getPcap()->dump(header, packet, packetS->dlt, false, (u_char*)packetS->data, packetS->datalen, packetS->saddr, packetS->daddr, packetS->source, packetS->dest, packetS->istcp);
			} else {
				call->getPcap()->dump(header, packet, packetS->dlt);
			}
		}
	}
	
	if(allocPacket) {
		delete [] packet;
	}
	if(allocHeader) {
		delete header;
	}
	packetS->header_ip->tot_len = old_header_ip_tot_len;
}

inline void save_sip_packet(Call *call, packet_s *packetS, ParsePacket *parsePacket,
			    unsigned int sipDatalen, int type, 
			    unsigned int datalen, unsigned int sipOffset,
			    int forceSip) {
	if(!enable_save_sip(call)) {
		return;
	}
	if(packetS->istcp && 
	   sipDatalen && (sipDatalen < datalen || sipOffset) &&
	   (unsigned)datalen + sipOffset < packetS->header.caplen) {
		bpf_u_int32  oldcaplen = packetS->header.caplen;
		bpf_u_int32  oldlen = packetS->header.len;
		u_int16_t oldHeaderIpLen = packetS->header_ip->tot_len;
		unsigned long datalenWithSipOffset = datalen + sipOffset;
		unsigned long diffLen = sipOffset + (datalen - sipDatalen);
		unsigned long newPacketLen = oldcaplen - diffLen;
		packetS->header.caplen -= diffLen;
		packetS->header.len -= diffLen;
		packetS->header_ip->tot_len = htons(ntohs(packetS->header_ip->tot_len) - diffLen);
		u_char *newPacket = new FILE_LINE u_char[newPacketLen];
		memcpy(newPacket, packetS->packet, oldcaplen - datalenWithSipOffset);
		memcpy(newPacket + (oldcaplen - datalenWithSipOffset), packetS->data, sipDatalen);
		iphdr2 *newHeaderIp = packetS->header_ip;
		if((u_char*)packetS->header_ip > packetS->packet && (u_char*)packetS->header_ip - packetS->packet < 100) {
			newHeaderIp = (iphdr2*)(newPacket + ((u_char*)packetS->header_ip - packetS->packet));
		}
		const u_char *old_packet = packetS->packet;
		iphdr2 *old_header_ip = packetS->header_ip;
		int old_datalen = packetS->datalen;
		packetS->packet = newPacket;
		packetS->header_ip = newHeaderIp;
		packetS->datalen = sipDatalen;
		save_packet(call, packetS, parsePacket, TYPE_SIP, forceSip);
		packetS->packet = old_packet;
		packetS->header_ip = old_header_ip;
		packetS->datalen = old_datalen;
		delete [] newPacket;
		packetS->header.caplen = oldcaplen;
		packetS->header.len = oldlen;
		packetS->header_ip->tot_len = oldHeaderIpLen;
	} else {
		int old_datalen = packetS->datalen;
		packetS->datalen = sipDatalen;
		save_packet(call, packetS, parsePacket, TYPE_SIP, forceSip);
		packetS->datalen = old_datalen;
	}
}

ParsePacket _parse_packet_global_process_packet;

int check_sip20(char *data, unsigned long len, ParsePacket *parsePacket){
	if(len < 11) {
		return 0;
	}
	
	if(parsePacket && parsePacket->getParseData() == data) {
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

char * gettag_ext(const void *ptr, unsigned long len, ParsePacket *parsePacket,
		  const char *tag, unsigned long *gettaglen, unsigned long *limitLen) {
	return(gettag(ptr, len, parsePacket,
		      tag, gettaglen, limitLen));
}

/* get SIP tag from memory pointed to *ptr length of len */
inline char * gettag(const void *ptr, unsigned long len, ParsePacket *parsePacket,
		     const char *tag, unsigned long *gettaglen, unsigned long *limitLen) {
 
	const char *rc_pp = NULL;
	long l_pp;
	char _tag[1024];
	
	if(parsePacket && parsePacket->getParseData() == ptr) {
		rc_pp = parsePacket->getContentData(tag, &l_pp);
		if((!rc_pp || l_pp <= 0) && tag[0] != '\n') {
			_tag[0] = '\n';
			strcpy(_tag + 1, tag);
			rc_pp = parsePacket->getContentData(_tag, &l_pp);
		}
		if(rc_pp && l_pp > 0) {
			*gettaglen = l_pp;
			return((char*)rc_pp);
		} else {
			*gettaglen = 0;
			return(NULL);
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
	
	/* test results from parse packet
	if(&& rc && l) {
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
	*/
	
	return rc;
}

int get_sip_peercnam(char *data, int data_len, ParsePacket *parsePacket,
		     const char *tag, char *peername, unsigned int peername_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, parsePacket,
				    tag, &peername_tag_len);
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


int get_sip_peername(char *data, int data_len, ParsePacket *parsePacket, 
		     const char *tag, char *peername, unsigned int peername_len){
	struct {
		const char *prefix;
		unsigned length;
		unsigned skip;
		int type;
	} prefixes[] = {
		{ "sip:", 4, 4, 0 },
		{ "sips:", 5, 5, 0 },
		{ "urn:", 4, 0, 1 }
	};
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, parsePacket,
				    tag, &peername_tag_len);
	if(!peername_tag_len) {
		goto fail_exit;
	}
	unsigned i_prefix;
	for(i_prefix = 0; i_prefix < sizeof(prefixes) / sizeof(prefixes[0]); i_prefix++) {
		if((r = (unsigned long)memmem(peername_tag, peername_tag_len, prefixes[i_prefix].prefix, prefixes[i_prefix].length))) {
			r += prefixes[i_prefix].skip;
			break;
		}
	}
	if(i_prefix == sizeof(prefixes) / sizeof(prefixes[0])) {
		goto fail_exit;
	}
	if ((r2 = (unsigned long)memmem((char*)r, peername_tag_len, prefixes[i_prefix].type == 0 ? "@" : ">", 1)) == 0){
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

int get_sip_headerstr(char *data, int data_len, ParsePacket *parsePacket,
		     const char *tag, char *headerstr, unsigned int headerstr_len){
        unsigned long headerstr_tag_len;
        char *header_tag = gettag(data, data_len, parsePacket,
				  tag, &headerstr_tag_len);
        if(!headerstr_tag_len) {
                goto fail_exit;
        }
        memcpy(headerstr, header_tag, MIN(headerstr_tag_len, headerstr_len));
        headerstr[headerstr_tag_len - 1] = '\0';
        return 0;
fail_exit:
	strcpy(headerstr, "");
	return 1;
}

int get_sip_domain(char *data, int data_len, ParsePacket *parsePacket,
		   const char *tag, char *domain, unsigned int domain_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, parsePacket,
				    tag, &peername_tag_len);
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


int get_sip_branch(char *data, int data_len, ParsePacket *parsePacket, 
		   const char *tag, char *branch, unsigned int branch_len){
	unsigned long branch_tag_len;
	char *branch_tag = gettag(data, data_len, parsePacket,
				  tag, &branch_tag_len);
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


int get_ip_port_from_sdp(Call *call, char *sdp_text, in_addr_t *addr, unsigned short *port, int16_t *fax, char *sessid, int16_t *rtcp_mux){
	unsigned long l;
	char *s;
	char s1[20];
	size_t sdp_text_len = strlen(sdp_text);
	unsigned long gettagLimitLen = 0;

	*fax = 0;
	*rtcp_mux = 0;
	s = gettag(sdp_text,sdp_text_len, NULL,
		   "o=", &l, &gettagLimitLen);
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
	s = gettag(sdp_text,sdp_text_len, NULL, 
		   "c=IN IP4 ", &l, &gettagLimitLen);
	if(l == 0) return 1;
	memset(s1, '\0', sizeof(s1));
	memcpy(s1, s, MIN(l, 19));
//	printf("---------- [%s]\n", s1);
	if ((int32_t)(*addr = inet_addr(s1)) == -1){
		*addr = 0;
		*port = 0;
		return 1;
	}
	s = gettag(sdp_text, sdp_text_len, NULL,
		   "m=audio ", &l, &gettagLimitLen);
	if (l == 0 || (*port = atoi(s)) == 0){
		s = gettag(sdp_text, sdp_text_len, NULL,
			   "m=image ", &l, &gettagLimitLen);
		if (l == 0 || (*port = atoi(s)) == 0){
			*port = 0;
			return 1;
		} else {
			*fax = 1;
		}
	}
	if(memmem(sdp_text, sdp_text_len, "a=rtcp-mux", 10)) {
		*rtcp_mux = 1;
		call->use_rtcp_mux = true;
	}
	return 0;
}

int get_value_stringkeyval2(const char *data, unsigned int data_len, const char *key, char *value, int unsigned len) {
	unsigned long r, tag_len;
	char *tmp = gettag(data, data_len, NULL,
			   key, &tag_len);
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

int get_expires_from_contact(char *data, int datalen, ParsePacket *parsePacket, int *expires){
	char *s;
	unsigned long l;
	unsigned long gettagLimitLen = 0;

	if(datalen < 8) return 1;

	s = gettag(data, datalen, parsePacket,
		   "\nContact:", &l, &gettagLimitLen);
	if(!l) {
		//try compact header
		s = gettag(data, datalen, parsePacket,
			   "\nm:", &l, &gettagLimitLen);
	}
	if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
		char tmp[128];
		int res = get_value_stringkeyval2(s, l + 2, "expires=", tmp, sizeof(tmp));
		if(res) {
			// not found, try again in case there is more Contact headers
			return get_expires_from_contact(s, datalen - (s - data), NULL, expires);
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
	char *tmp = gettag(data, data_len, NULL,
			   key, &tag_len);
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
	char mimeSubtype[255];
	int i = 0;
	int rate = 0;
	unsigned long gettagLimitLen = 0;

	s = gettag(sdp_text, len, NULL,
		   "m=audio ", &l, &gettagLimitLen);
	if(!l) {
		return 0;
	}
	do {
		s = gettag(s, len - (s - sdp_text), NULL,
			   "a=rtpmap:", &l, &gettagLimitLen);
		if(l && (z = strchr(s, '\r'))) {
			*z = '\0';
		} else {
			break;
		}
		if (sscanf(s, "%30u %254[^/]/%d", &codec, mimeSubtype, &rate) == 3) {
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

inline
void add_to_rtp_thread_queue(Call *call, packet_s *packetS,
			     int iscaller, int is_rtcp, int enable_save_packet, int preSyncRtp) {
	if(is_terminating()) {
		return;
	}
	
	if(call->type < INVITE || call->type > SKINNY_NEW) {
		syslog(LOG_ERR, "incorrect call type in add_to_rtp_thread_queue: %i, saddr %s daddr %s sport %u dport %u",
		       call->type,
		       inet_ntostring(packetS->saddr).c_str(), inet_ntostring(packetS->daddr).c_str(),
		       packetS->source, packetS->dest);
		return;
	}
	
	if(!preSyncRtp) {
		#if SYNC_CALL_RTP
		__sync_add_and_fetch(&call->rtppacketsinqueue, 1);
		#else
		++call->rtppacketsinqueue_p;
		#endif
	}
	
	rtp_read_thread *params = &(rtp_threads[call->thread_num]);

	if(packetS->block_store) {
		packetS->block_store->lock_packet(packetS->block_store_index);
	}
	if(params->rtpp_queue_quick ||
	   params->rtpp_queue_quick_boost) {
		rtp_packet_pcap_queue rtpp_pq;
		rtpp_pq.call = call;
		rtpp_pq.packet = *packetS;
		rtpp_pq.iscaller = iscaller;
		rtpp_pq.is_rtcp = is_rtcp;
		rtpp_pq.save_packet = enable_save_packet;
		if(params->rtpp_queue_quick) {
			params->rtpp_queue_quick->push(&rtpp_pq, true, process_rtp_packets_distribute_threads_use > 1);
		} else {
			params->rtpp_queue_quick_boost->push(&rtpp_pq, true, process_rtp_packets_distribute_threads_use > 1);
		}
	} else {
		params->rtpp_queue->lock();
		rtp_packet_pcap_queue *rtpp_pq;
		while((rtpp_pq = params->rtpp_queue->push_get_pointer()) == NULL) {
			usleep(10);
		}
		rtpp_pq->call = call;
		rtpp_pq->packet = *packetS;
		rtpp_pq->iscaller = iscaller;
		rtpp_pq->is_rtcp = is_rtcp;
		rtpp_pq->save_packet = enable_save_packet;
		params->rtpp_queue->unlock();
	}
}


static volatile int _sync_add_remove_rtp_threads;
void lock_add_remove_rtp_threads() {
	while(__sync_lock_test_and_set(&_sync_add_remove_rtp_threads, 1));
}

void unlock_add_remove_rtp_threads() {
	__sync_lock_release(&_sync_add_remove_rtp_threads);
}

void *rtp_read_thread_func(void *arg) {
	rtp_packet_pcap_queue rtpp_pq;
	rtp_read_thread *params = (rtp_read_thread*)arg;
	params->threadId = get_unix_tid();
	unsigned usleepCounter = 0;
	while(1) {

		bool emptyQueue = false;
		if(params->rtpp_queue_quick) {
			if(!params->rtpp_queue_quick->pop(&rtpp_pq, false)) {
				emptyQueue = true;
			}
		} else if(params->rtpp_queue_quick_boost) {
			if(!params->rtpp_queue_quick_boost->pop(&rtpp_pq, false)) {
				emptyQueue = true;
			}
		} else {
			if(!params->rtpp_queue->pop(&rtpp_pq, true)) {
				emptyQueue = true;
			}
		}
		if(emptyQueue) {
			if(is_terminating() || readend) {
				return NULL;
			} else if(params->remove_flag &&
				  ((getTimeMS_rdtsc() / 1000) - params->last_use_time_s) > 10 * 60) {
				lock_add_remove_rtp_threads();
				if(params->remove_flag) {
					break;
				}
				unlock_add_remove_rtp_threads();
			}
			// no packet to read, wait and try again
			unsigned usleepTime = rtp_qring_usleep * 
					      (usleepCounter > 1000 ? 20 :
					       usleepCounter > 100 ? 10 :
					       usleepCounter > 10 ? 5 : 1);
			usleep(usleepTime);
			++usleepCounter;
			continue;
		} else {
			usleepCounter = 0;
		}
		
		params->last_use_time_s = rtpp_pq.packet.header.ts.tv_sec;

		if(rtpp_pq.is_rtcp) {
			rtpp_pq.call->read_rtcp(&rtpp_pq.packet, rtpp_pq.iscaller, rtpp_pq.save_packet);
		}  else {
			rtpp_pq.call->read_rtp(&rtpp_pq.packet, rtpp_pq.iscaller, rtpp_pq.save_packet, 
					       rtpp_pq.packet.block_store && rtpp_pq.packet.block_store->ifname[0] ? rtpp_pq.packet.block_store->ifname : NULL);
		}
		rtpp_pq.call->set_last_packet_time(rtpp_pq.packet.header.ts.tv_sec);
		if(rtpp_pq.packet.block_store) {
			rtpp_pq.packet.block_store->unlock_packet(rtpp_pq.packet.block_store_index);
		}

		#if SYNC_CALL_RTP
		__sync_sub_and_fetch(&rtpp_pq.call->rtppacketsinqueue, 1);
		#else
		++rtpp_pq.call->rtppacketsinqueue_m;
		#endif

	}
	
	if(params->remove_flag) {
		params->remove_flag = false;
		params->last_use_time_s = 0;
		memset(params->threadPstatData, 0, sizeof(params->threadPstatData));
	}
	params->thread = 0;
	params->threadId = 0;
	
	unlock_add_remove_rtp_threads();
	
	return NULL;
}

void add_rtp_read_thread() {
	lock_add_remove_rtp_threads();
	extern int num_threads_max;
	extern int num_threads_active;
	if(is_enable_rtp_threads() &&
	   num_threads_active > 0 && num_threads_max > 0 &&
	   num_threads_active < num_threads_max) {
		if(rtp_threads[num_threads_active].threadId) {
			if(rtp_threads[num_threads_active].remove_flag) {
				rtp_threads[num_threads_active].remove_flag = false;
			}
		} else {
			pthread_create(&(rtp_threads[num_threads_active].thread), NULL, rtp_read_thread_func, (void*)&rtp_threads[num_threads_active]);
		}
		++num_threads_active;
	}
	unlock_add_remove_rtp_threads();
}

void set_remove_rtp_read_thread() {
	lock_add_remove_rtp_threads();
	extern int num_threads_active;
	if(is_enable_rtp_threads() &&
	   num_threads_active > 1) {
		rtp_threads[num_threads_active - 1].remove_flag = true;
		--num_threads_active;
	}
	unlock_add_remove_rtp_threads();
}

int get_index_rtp_read_thread_min_size() {
	extern int num_threads_active;
	size_t minSize = 0;
	int minSizeIndex = -1;
	for(int i = 0; i < num_threads_active; i++) {
		if(rtp_threads[i].threadId && !rtp_threads[i].remove_flag) {
			if(!rtp_threads[i].rtpp_queue_quick) {
				return(-1);
			}
			size_t size = rtp_threads[i].rtpp_queue_quick->size();
			if(minSizeIndex == -1 || minSize > size) {
				minSizeIndex = i;
				minSize = size;
			}
		}
	}
	return(minSizeIndex);
}

double get_rtp_sum_cpu_usage(double *max) {
	extern int num_threads_max;
	extern int num_threads_active;
	if(max) {
		*max = 0;
	}
	if(is_enable_rtp_threads() &&
	   num_threads_active > 0 && num_threads_max > 0) {
		bool set = false;
		double sum = 0;
		for(int i = 0; i < num_threads_active; i++) {
			if(rtp_threads[i].threadId) {
				if(rtp_threads[i].threadPstatData[0].cpu_total_time) {
					rtp_threads[i].threadPstatData[1] = rtp_threads[i].threadPstatData[0];
				}
				pstat_get_data(rtp_threads[i].threadId, rtp_threads[i].threadPstatData);
				double ucpu_usage, scpu_usage;
				if(rtp_threads[i].threadPstatData[0].cpu_total_time && rtp_threads[i].threadPstatData[1].cpu_total_time) {
					pstat_calc_cpu_usage_pct(
						&rtp_threads[i].threadPstatData[0], &rtp_threads[i].threadPstatData[1],
						&ucpu_usage, &scpu_usage);
					sum += ucpu_usage + scpu_usage;
					if(max && ucpu_usage + scpu_usage > *max) {
						*max = ucpu_usage + scpu_usage;
					}
					set = true;
				}
			}
		}
		return(set ? sum : -1);
	} else {
		return(-1);
	}
}

inline Call *new_invite_register(packet_s *packetS, ParsePacket *parsePacket, 
				 int sip_method, char *callidstr, bool *detectUserAgent,
				 bool preprocess_queue = false){
 
	unsigned long gettagLimitLen = 0;
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
			if(!get_sip_peername(packetS->data, packetS->datalen, parsePacket,
					     "\nRemote-Party-ID:", tcaller, sizeof(tcaller)) &&
			  tcaller[0] != '\0') {
				caller_useRemotePartyID = true;
			} else {
				if(opt_passertedidentity && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
									      "\nP-Assserted-Identity:", tcaller, sizeof(tcaller)) &&
				  tcaller[0] != '\0') {
					caller_usePAssertedIdentity = true;
				} else {
					if(opt_ppreferredidentity && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
										       "\nP-Preferred-Identity:", tcaller, sizeof(tcaller)) &&
					  tcaller[0] != '\0') {
						caller_usePPreferredIdentity = true;
					} else {
						caller_useFrom = true;
						if(!get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								     "\nFrom:", tcaller, sizeof(tcaller)) &&
						  tcaller[0] != '\0') {
							get_sip_peername(packetS->data, packetS->datalen, parsePacket,
									 "\nf:", tcaller, sizeof(tcaller));
						}
					}
				}
			}
		} else {
			//Caller number is taken from headers (in this order) P-Asserted-Identity, P-Preferred-Identity, Remote-Party-ID,From, F
			if(opt_passertedidentity && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								      "\nP-Asserted-Identity:", tcaller, sizeof(tcaller)) &&
			  tcaller[0] != '\0') {
				caller_usePAssertedIdentity = true;
			} else {
				if(opt_ppreferredidentity && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
									       "\nP-Preferred-Identity:", tcaller, sizeof(tcaller)) &&
				  tcaller[0] != '\0') {
					caller_usePPreferredIdentity = true;
				} else {
					if(opt_remotepartyid && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
										  "\nRemote-Party-ID:", tcaller, sizeof(tcaller)) &&
					  tcaller[0] != '\0') {
						caller_useRemotePartyID = true;
					} else {
						caller_useFrom =  true;
						if(get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								    "\nFrom:", tcaller, sizeof(tcaller)) ||
						  tcaller[0] == '\0') {
							get_sip_peername(packetS->data, packetS->datalen, parsePacket,
									 "\nf:", tcaller, sizeof(tcaller));
						}
					}
				}
			}
		}
	} else {
		//Caller is taken from header From , F
		caller_useFrom =  true;
		if(get_sip_peername(packetS->data, packetS->datalen, parsePacket,
				    "\nFrom:", tcaller, sizeof(tcaller)) ||
		  tcaller[0] == '\0') {
			get_sip_peername(packetS->data, packetS->datalen, parsePacket,
					 "\nf:", tcaller, sizeof(tcaller));
		}
	}

	if (caller_useFrom && !strcasecmp(tcaller, "anonymous")) {
		//if caller is anonymous
		char tcaller2[1024];
		if(opt_remotepartypriority && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								"\nRemote-Party-ID:", tcaller2, sizeof(tcaller2)) &&
		   tcaller2[0] != '\0') {
			strncpy(tcaller, tcaller2, sizeof(tcaller));
			anonymous_useRemotePartyID = true;
		} else {
			if(opt_passertedidentity && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								      "\nP-Asserted-Identity:", tcaller2, sizeof(tcaller2)) &&
			   tcaller2[0] != '\0') {
				strncpy(tcaller, tcaller2, sizeof(tcaller));
				anonymous_usePAssertedIdentity = true;
			} else {
				if(opt_ppreferredidentity && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
									       "\nP-Preferred-Identity:", tcaller2, sizeof(tcaller2)) &&
				   tcaller2[0] != '\0') {
					strncpy(tcaller, tcaller2, sizeof(tcaller));
					anonymous_usePPreferredIdentity = true;
				} else {
					if(!opt_remotepartypriority && !get_sip_peername(packetS->data, packetS->datalen, parsePacket,
											 "\nRemote-Party-ID:", tcaller2, sizeof(tcaller2)) &&
					   tcaller2[0] != '\0') {
						strncpy(tcaller, tcaller2, sizeof(tcaller));
						anonymous_useRemotePartyID = true;
					} else {
						anonymous_useFrom = true;
					}
				}
			}
		}
	}

	// called number
	res = get_sip_peername(packetS->data, packetS->datalen, parsePacket,
			       "\nTo:", tcalled, sizeof(tcalled));
	if(res) {
		// try compact header
		get_sip_peername(packetS->data, packetS->datalen, parsePacket,
				 "\nt:", tcalled, sizeof(tcalled));
	}
	if(sip_method == INVITE && opt_destination_number_mode == 2) {
		char tcalled_invite[1024] = "";
		if(!get_sip_peername(packetS->data, packetS->datalen, parsePacket,
				     "INVITE ", tcalled_invite, sizeof(tcalled_invite)) &&
		   tcalled_invite[0] != '\0') {
			strncpy(tcalled, tcalled_invite, sizeof(tcalled));
		}
	}
	
	//caller and called domain has to be checked before flags due to skip filter 
	char tcaller_domain[1024] = "", tcalled_domain[1024] = "";
	// caller domain 
	if(anonymous_useFrom || caller_useFrom) {
		res = get_sip_domain(packetS->data, packetS->datalen, parsePacket,
				     "\nFrom:", tcaller_domain, sizeof(tcaller_domain));
		if(res) {
			// try compact header
			get_sip_domain(packetS->data, packetS->datalen, parsePacket,
				       "\nf:", tcaller_domain, sizeof(tcaller_domain));
		}
	} else {
		if(anonymous_useRemotePartyID || caller_useRemotePartyID) {
			get_sip_domain(packetS->data, packetS->datalen, parsePacket,
				       "\nRemote-Party-ID:", tcaller_domain, sizeof(tcaller_domain));
		} else {
			if (anonymous_usePPreferredIdentity || caller_usePPreferredIdentity) {
				get_sip_domain(packetS->data, packetS->datalen, parsePacket,
					       "\nP-Preferred-Identity:", tcaller_domain, sizeof(tcaller_domain));
			} else {
				if (anonymous_usePAssertedIdentity || caller_usePAssertedIdentity) {
					get_sip_domain(packetS->data, packetS->datalen, parsePacket,
						       "\nP-Asserted-Identity:", tcaller_domain, sizeof(tcaller_domain));
				}
			}
		}
	}

	// called domain 
	res = get_sip_domain(packetS->data, packetS->datalen, parsePacket,
			     "\nTo:", tcalled_domain, sizeof(tcalled_domain));
	if(res) {
		// try compact header
		get_sip_domain(packetS->data, packetS->datalen, parsePacket,
			       "\nt:", tcalled_domain, sizeof(tcalled_domain));
	}
	if(sip_method == INVITE && opt_destination_number_mode == 2) {
		char tcalled_domain_invite[256] = "";
		get_sip_domain(packetS->data,packetS->datalen, parsePacket,
			       "INVITE ", tcalled_domain_invite, sizeof(tcalled_domain_invite));
		if(tcalled_domain_invite[0] != '\0') {
			strncpy(tcalled_domain, tcalled_domain_invite, sizeof(tcalled_domain));
		}
	}

	//flags
	unsigned int flags = 0;
	set_global_flags(flags);
	ipfilter->add_call_flags(&flags, ntohl(packetS->saddr), ntohl(packetS->daddr));
	telnumfilter->add_call_flags(&flags, tcaller, tcalled);
	domainfilter->add_call_flags(&flags, tcaller_domain, tcalled_domain);
	sipheaderfilter->add_call_flags(parsePacket, &flags, tcaller_domain, tcalled_domain);

	if(flags & FLAG_SKIPCDR) {
		if(verbosity > 1)
			syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
		return NULL;
	}


	static char str2[1024];
	if(packetS->is_ssl) {
		glob_ssl_calls++;
	}
	// store this call only if it starts with invite
	Call *call = calltable->add(callidstr, min(strlen(callidstr), (size_t)MAX_FNAME), packetS->header.ts.tv_sec, packetS->saddr, packetS->source, packetS->handle, packetS->dlt, packetS->sensor_id, preprocess_queue);
	call->chantype = CHAN_SIP;
	call->is_ssl = packetS->is_ssl;
	call->set_first_packet_time(packetS->header.ts.tv_sec, packetS->header.ts.tv_usec);
	call->sipcallerip[0] = packetS->saddr;
	call->sipcalledip[0] = packetS->daddr;
	call->sipcallerport = packetS->source;
	call->sipcalledport = packetS->dest;
	call->type = sip_method;
	call->flags = flags;
	call->lastsrcip = packetS->saddr;
	
	char *s;
	unsigned long l;
	bool use_fbasename_header = false;
	if(opt_fbasename_header[0]) {
		s = gettag(packetS->data, packetS->datalen, parsePacket,
			   opt_fbasename_header, &l, &gettagLimitLen);
		if(l && l < 255) {
			if(l > MAX_FNAME - 1) {
				l = MAX_FNAME - 1;
			}
			strncpy(call->fbasename, s, l);
			call->fbasename[l] = 0;
			use_fbasename_header = true;
		}
	}
	if(!use_fbasename_header) {
		strncpy(call->fbasename, callidstr, MAX_FNAME - 1);
		call->fbasename[MIN(strlen(callidstr), MAX_FNAME - 1)] = '\0';
	}
	call->msgcount++;

	/* this logic updates call on the first INVITES */
	if (sip_method == INVITE or sip_method == REGISTER or sip_method == MESSAGE) {
		//geolocation 
		s = gettag(packetS->data, packetS->datalen, parsePacket,
			   "\nGeoPosition:", &l, &gettagLimitLen);
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
			res = get_sip_peercnam(packetS->data, packetS->datalen, parsePacket,
					       "\nFrom:", call->callername, sizeof(call->callername));
			if(res) {
				// try compact header
				get_sip_peercnam(packetS->data, packetS->datalen, parsePacket,
						 "\nf:", call->callername, sizeof(call->callername));
			}
		} else {
			if (caller_useRemotePartyID) {
				//try Remote-Party-ID
				res = get_sip_peercnam(packetS->data, packetS->datalen, parsePacket,
						       "\nRemote-Party-ID:", call->callername, sizeof(call->callername));
				if (res) {
				}
			} else {
				if (caller_usePPreferredIdentity) {
					//try P-Preferred-Identity
					res = get_sip_peercnam(packetS->data, packetS->datalen, parsePacket,
							       "\nP-Preferred-Identity:", call->callername, sizeof(call->callername));
				} else {
					if (caller_usePAssertedIdentity) {
						//try P-Asserted-Identity
						res = get_sip_peercnam(packetS->data, packetS->datalen, parsePacket, 
								       "\nP-Asserted-Identity:", call->callername, sizeof(call->callername));
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
			call->destroy_call_at = packetS->header.ts.tv_sec + opt_register_timeout;

			// is it first register? set now
			if (call->regrrddiff == -1) {
				//struct timeval nowt;
				//gettimeofday(&nowt, NULL);
				call->regrrdstart.tv_sec = packetS->header.ts.tv_sec;
				call->regrrdstart.tv_usec = packetS->header.ts.tv_usec;
			}

			// copy contact num <sip:num@domain>
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "\nUser-Agent:", &l, &gettagLimitLen);
			if(l && ((unsigned int)l < ((unsigned int)packetS->datalen - (s - packetS->data)))) {
				memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
				call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
				if(sverb.set_ua) {
					cout << "set a_ua " << call->a_ua << endl;
				}
			}
			if(detectUserAgent) {
				*detectUserAgent = true;
			}

			res = get_sip_peername(packetS->data, packetS->datalen, parsePacket,
					       "\nContact:", call->contact_num, sizeof(call->contact_num));
			if(res) {
				// try compact header
				get_sip_peername(packetS->data, packetS->datalen, parsePacket,
						 "\nm:", call->contact_num, sizeof(call->contact_num));
			}
			// copy contact domain <sip:num@domain>
			res = get_sip_domain(packetS->data, packetS->datalen, parsePacket,
					     "\nContact:", call->contact_domain, sizeof(call->contact_domain));
			if(res) {
				// try compact header
				get_sip_domain(packetS->data, packetS->datalen, parsePacket,
					       "\nm:", call->contact_domain, sizeof(call->contact_domain));
			}

			// copy Authorization
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "\nAuthorization:", &l, &gettagLimitLen);
			if(l && ((unsigned int)l < ((unsigned int)packetS->datalen - (s - packetS->data)))) {
				get_value_stringkeyval(s, packetS->datalen - (s - packetS->data), "username=\"", call->digest_username, sizeof(call->digest_username));
				get_value_stringkeyval(s, packetS->datalen - (s - packetS->data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
			}
			// get expires header
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "\nExpires:", &l, &gettagLimitLen);
			if(l && ((unsigned int)l < ((unsigned int)packetS->datalen - (s - packetS->data)))) {
				char c = s[l];
				s[l] = '\0';
				call->register_expires = atoi(s);
				s[l] = c;
			}
			// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
			get_expires_from_contact(packetS->data, packetS->datalen, parsePacket, &call->register_expires);
/*
			syslog(LOG_NOTICE, "contact_num[%s] contact_domain[%s] from_num[%s] from_name[%s] from_domain[%s] digest_username[%s] digest_realm[%s] expires[%d]\n", 
				call->contact_num, call->contact_domain, call->caller, call->callername, call->caller_domain, 
				call->digest_username, call->digest_realm, call->register_expires);
*/
		}
		if(opt_enable_fraud) {
			fraudBeginCall(call, packetS->header.ts);
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
		s = gettag(packetS->data, packetS->datalen, parsePacket,
			   "\nX-VoipMonitor-norecord:", &l, &gettagLimitLen);
		if(l && l < 33) {
			// do 
			call->stoprecording();
		}
	}

	// opening dump file
	if((call->type == REGISTER && enable_save_register(call)) || 
	   (call->type != REGISTER && enable_save_sip_rtp_audio(call))) {
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

	if(call->type == REGISTER && enable_save_register(call)) {
		/****
		call->set_f_pcap(NULL);
		call->set_fsip_pcap(NULL);
		call->set_frtp_pcap(NULL);
		****/
		char filenamestr[32];
		sprintf(filenamestr, "%u%u", (unsigned int)packetS->header.ts.tv_sec, (unsigned int)packetS->header.ts.tv_usec);
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
			unsigned long long num = packetS->header.ts.tv_sec;
			unsigned long long num2 = packetS->header.ts.tv_usec;
			while(num2 > 0) {
				num2 /= 10;
				num *= 10;
			}
			call->fname2 = num + packetS->header.ts.tv_usec;
			call->pcapfilename = call->sip_pcapfilename = pcapFilePath_spool_relative;
			if(call->getPcapSip()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", str2);
				}
			}
		}
	} else if(call->type != REGISTER && enable_save_sip_rtp(call)) {
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
			if(enable_save_sip(call) &&
			   call->getPcapSip()->open(str2, pcapFilePath_spool_relative, call->useHandle, call->useDlt)) {
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
	s = gettag(packetS->data, packetS->datalen, parsePacket,
		   "\nCSeq:", &l, &gettagLimitLen);
	if(l && l < 32) {
		memcpy(call->invitecseq, s, l);
		call->unrepliedinvite++;
		call->invitecseq[l] = '\0';
		if(verbosity > 2)
			syslog(LOG_NOTICE, "Seen invite, CSeq: %s\n", call->invitecseq);
	}
	
	return call;
}

void process_sdp(Call *call, packet_s *packetS,
		 int sip_method, char *data, int datalen, char *callidstr, char *ua, unsigned int ua_len){
	char *tmp = strstr(data, "\r\n\r\n");
	if(!tmp) return;

	in_addr_t tmp_addr;
	unsigned short tmp_port;
	int rtpmap[MAX_RTPMAP];
	memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);
	s_sdp_flags sdp_flags;
	char sessid[MAXLEN_SDP_SESSID];
	if (!get_ip_port_from_sdp(call, tmp + 1, &tmp_addr, &tmp_port, &sdp_flags.is_fax, sessid, &sdp_flags.rtcp_mux)){
		if(sdp_flags.is_fax) { 
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
			((call->saddr == packetS->saddr && call->sport == packetS->source) || 
			(call->saddr == packetS->daddr && call->sport == packetS->dest))))
			{

			//printf("sdp [%u] port[%u]\n", tmp_addr, tmp_port);

			// store RTP stream
			get_rtpmap_from_sdp(tmp + 1, datalen - (tmp + 1 - data), rtpmap);

			int iscalled;
			call->handle_dscp(sip_method, packetS->header_ip, packetS->saddr, packetS->daddr, &iscalled, true);
			//syslog(LOG_ERR, "ADDR: %u port %u iscalled[%d]\n", tmp_addr, tmp_port, iscalled);
		
			call->add_ip_port_hash(packetS->saddr, tmp_addr, tmp_port, sessid, ua, ua_len, !iscalled, rtpmap, sdp_flags, 0);
			// check if the IP address is listed in nat_aliases
			in_addr_t alias = 0;
			if((alias = match_nat_aliases(tmp_addr)) != 0) {
				call->add_ip_port_hash(packetS->saddr, alias, tmp_port, sessid, ua, ua_len, !iscalled, rtpmap, sdp_flags, 0);
			}
			if(opt_sdp_reverse_ipport) {
				call->add_ip_port_hash(packetS->saddr, packetS->saddr, tmp_port, sessid, ua, ua_len, !iscalled, rtpmap, sdp_flags, 0);
			}
		}
	} else {
		if(verbosity >= 2){
			syslog(LOG_ERR, "callid[%s] Can't get ip/port from SDP:\n%s\n\n", callidstr, tmp + 1);
		}
	}
}

static inline void process_packet__parse_custom_headers(Call *call, char *data, int datalen, ParsePacket *parsePacket);
static inline void process_packet__cleanup(pcap_pkthdr *header, u_long timeS = 0);
static inline int process_packet__parse_sip_method(char *data, unsigned int datalen, bool *sip_response);
static inline int parse_packet__last_sip_response(char *data, unsigned int datalen, int sip_method, bool sip_response,
						  char *lastSIPresponse, bool *call_cancel_lsr487);
static inline int parse_packet__message_content(char *message, unsigned int messageLength,
						char **rsltMessage, string *rsltDestNumber, string *rsltSrcNumber,
						bool maskMessage = false);
static inline Call *process_packet__merge(packet_s *packetS, ParsePacket *parsePacket, char *callidstr, int *merged, long unsigned int *gettagLimitLen, bool preprocess_queue = false);

u_char *_process_packet_packet;
pcap_pkthdr *_process_packet_header;
char *_process_packet_data;
int _process_packet_datalen;

Call *process_packet(packet_s *packetS, void *_parsePacketPreproc,
		     int *was_rtp, int *voippacket, int forceSip,
		     bool mainProcess, int sipOffset) {
 
	PreProcessPacket::packet_parse_s *parsePacketPreproc = (PreProcessPacket::packet_parse_s*)_parsePacketPreproc;
	ParsePacket *parsePacket = parsePacketPreproc ? parsePacketPreproc->parse : NULL;
	
	if(parsePacketPreproc && parsePacketPreproc->isSip && PreProcessPacket::isEnableExtend()) {
		if(parsePacketPreproc->_findCall && parsePacketPreproc->call) {
			__sync_sub_and_fetch(&parsePacketPreproc->call->in_preprocess_queue_before_process_packet, 1);
		}
		if(parsePacketPreproc->_createCall && parsePacketPreproc->call_created) {
			__sync_sub_and_fetch(&parsePacketPreproc->call_created->in_preprocess_queue_before_process_packet, 1);
		}
	}
 
	_process_packet_packet = (u_char*)packetS->packet;
	_process_packet_header = &packetS->header;
	_process_packet_data = packetS->data;
	_process_packet_datalen = packetS->datalen;

	/*
	char *dd = (char*)"";
	int dd_len = strlen(dd);
	int difflen = datalen - dd_len;
	datalen = dd_len;
	header->caplen -= difflen;
	header->len = header->caplen;
	u_char *packet_new = new u_char[header->caplen];
	memcpy(packet_new, packet, dataoffset);
	memcpy(packet_new + dataoffset, dd, dd_len);
	packet = packet_new;
	data = (char*)(packet + dataoffset);
	istcp = 2;
	*/
	
	glob_last_packet_time = packetS->header.ts.tv_sec;
	Call *call = NULL;
	int iscaller;
	int is_rtcp = 0;
	s_sdp_flags sdp_flags;
	char *s;
	unsigned long l;
	char callidstr[1024],str2[1024];
	int sip_method = 0;
	bool sip_response = false;
	char lastSIPresponse[128];
	int lastSIPresponseNum = 0;
	unsigned long gettagLimitLen = 0;
	hash_node_call *calls, *node_call;
	bool detectUserAgent = false;
	bool call_cancel_lsr487 = false;

	if (packetS->header.ts.tv_sec - process_packet__last_filter_reload > 1){
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
		process_packet__last_filter_reload = packetS->header.ts.tv_sec;
	}

	*was_rtp = 0;
	int merged;
	
	if(mainProcess && packetS->istcp < 2) {
		++counter_all_packets;
	}

	// checking and cleaning stuff every 10 seconds (if some packet arrive) 
	if (packetS->header.ts.tv_sec - process_packet__last_cleanup > 10){
		process_packet__cleanup(&packetS->header);
	}
	
	if(packetS->header.ts.tv_sec - process_packet__last_destroy_calls >= 2) {
		calltable->destroyCallsIfPcapsClosed();
		process_packet__last_destroy_calls = packetS->header.ts.tv_sec;
	}

	// check if the packet is SKINNY
	if(packetS->istcp && opt_skinny && (packetS->source == 2000 || packetS->dest == 2000)) {
		handle_skinny(&packetS->header, packetS->packet, packetS->saddr, packetS->source, packetS->daddr, packetS->dest, packetS->data, packetS->datalen, packetS->dataoffset,
			      packetS->handle, packetS->dlt, packetS->sensor_id);
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
				packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
				call, "packet is SKINNY");
		}
		return NULL;
	}

	// check if the packet is SIP ports or SKINNY ports
	if(sipportmatrix[packetS->source] || sipportmatrix[packetS->dest] || forceSip) {
	 
		++counter_sip_packets[0];

		Call *returnCall = NULL;
		
		unsigned long origDatalen = packetS->datalen;
		if(!parsePacket) {
			parsePacket = &_parse_packet_global_process_packet;
		}
		unsigned long sipDatalen = parsePacketPreproc && parsePacketPreproc->isSip ? 
					    parsePacketPreproc->sipDataLen :
					    parsePacket->parseData(packetS->data, packetS->datalen, true);
		if(sipDatalen > 0) {
			packetS->datalen = sipDatalen;
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
		
		int issip = parsePacketPreproc ? parsePacketPreproc->isSip : check_sip20(packetS->data, packetS->datalen, parsePacket);
		if(!packetS->istcp and !issip) { 
			goto rtpcheck;
		}

		if(parsePacketPreproc && parsePacketPreproc->isSip && parsePacketPreproc->_getCallID_reassembly) {
			strncpy(callidstr, parsePacketPreproc->callid.c_str(), sizeof(callidstr));
		} else {
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "\nCall-ID:", &l, &gettagLimitLen);
			if(!issip or (l <= 0 || l > 1023)) {
				// try also compact header
				s = gettag(packetS->data, packetS->datalen, parsePacket,
					   "\ni:", &l, &gettagLimitLen);
				if(!issip or (l <= 0 || l > 1023)) {
					// no Call-ID found in packet
					if(packetS->istcp == 1 && packetS->header_ip) {
						if(!PreProcessPacket::isEnableSip()) {
							tcpReassemblySip.processPacket(
								packetS->packet_number,
								packetS->saddr, packetS->source, packetS->daddr, packetS->dest, packetS->data, origDatalen, packetS->dataoffset,
								packetS->handle, packetS->header, packetS->packet, packetS->header_ip,
								packetS->dlt, packetS->sensor_id,
								issip);
							if(logPacketSipMethodCall_enable) {
								logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
									packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
									call, "it is TCP and callid not found");
							}
						}
						return NULL;
					} else {
						// it is not TCP and callid not found
						if(!PreProcessPacket::isEnableSip() && logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
								packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
								call, "it is not TCP and callid not found");
						}
						return NULL;
					}
				}
			}
			memcpy(callidstr, s, MIN(l, 1024));
			callidstr[MIN(l, 1023)] = '\0';

			// Call-ID is present
			if(packetS->istcp == 1 && packetS->datalen >= 2) {
				if(!PreProcessPacket::isEnableSip()) {
					tcpReassemblySip.processPacket(
						packetS->packet_number,
						packetS->saddr, packetS->source, packetS->daddr, packetS->dest, packetS->data, origDatalen, packetS->dataoffset,
						packetS->handle, packetS->header, packetS->packet, packetS->header_ip,
						packetS->dlt, packetS->sensor_id,
						issip);
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
							packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
							call, "it is TCP and callid found");
					}
				}
				return(NULL);
			}
		}
		
		if(sverb.reassembly_sip_output) {
			return(NULL);
		}
		
		if(parsePacketPreproc && parsePacketPreproc->isSip && parsePacketPreproc->_getSipMethod) {
			sip_method = parsePacketPreproc->sip_method;
			sip_response = parsePacketPreproc->sip_response;
		} else {
			sip_method = process_packet__parse_sip_method(packetS->data, packetS->datalen, &sip_response);
		}
		
		if(issip) {
			if(opt_enable_fraud && isFraudReady()) {
				char *ua = NULL;
				unsigned long ua_len = 0;
				ua = gettag(packetS->data, packetS->datalen, parsePacket,
					    "\nUser-Agent:", &ua_len);
				fraudSipPacket(packetS->saddr, sip_method, packetS->header.ts, ua, ua_len);
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
				char *dump_data = new FILE_LINE char[packetS->datalen + 1];
				memcpy(dump_data, packetS->data, packetS->datalen);
				dump_data[packetS->datalen] = 0;
				cout << counter_sip_packets[1] << endl
				     << dump_data << endl;
				delete [] dump_data;
			}
		}

		switch(sip_method) {
		case REGISTER:
			counter_sip_register_packets++;
			if(opt_enable_fraud && isFraudReady()) {
				char *ua = NULL;
				unsigned long ua_len = 0;
				ua = gettag(packetS->data, packetS->datalen, parsePacket,
					    "\nUser-Agent:", &ua_len);
				fraudRegister(packetS->saddr, packetS->header.ts, ua, ua_len);
			}
			break;
		case MESSAGE:
			counter_sip_message_packets++;
			break;
		case OPTIONS:
			if(livesnifferfilterUseSipTypes.u_options) {
				save_live_packet(NULL, packetS, parsePacket, OPTIONS);
			}
			break;
		case SUBSCRIBE:
			if(livesnifferfilterUseSipTypes.u_subscribe) {
				save_live_packet(NULL, packetS, parsePacket, SUBSCRIBE);
			}
			break;
		case NOTIFY:
			if(livesnifferfilterUseSipTypes.u_notify) {
				save_live_packet(NULL, packetS, parsePacket, NOTIFY);
			}
			break;
		}
		
		if(parsePacketPreproc && parsePacketPreproc->isSip && parsePacketPreproc->_getLastSipResponse) {
			lastSIPresponseNum = parsePacketPreproc->lastSIPresponseNum;
			strncpy(lastSIPresponse, parsePacketPreproc->lastSIPresponse.c_str(), sizeof(lastSIPresponse));
			lastSIPresponse[sizeof(lastSIPresponse) - 1] = 0;
			call_cancel_lsr487 = parsePacketPreproc->call_cancel_lsr487;
		} else {
			lastSIPresponseNum = parse_packet__last_sip_response(packetS->data, packetS->datalen, sip_method, sip_response,
									     lastSIPresponse, &call_cancel_lsr487);
		}

		// find call */
		merged = 0;
		if(parsePacketPreproc && parsePacketPreproc->isSip && PreProcessPacket::isEnableExtend() &&
		   parsePacketPreproc->_findCall) {
			call = parsePacketPreproc->call;
			merged = parsePacketPreproc->merged;
		} else {
			call = calltable->find_by_call_id(callidstr, strlen(callidstr));
			if(call) {
				call->handle_dscp(sip_method, packetS->header_ip, packetS->saddr, packetS->daddr, NULL, !IS_SIP_RESXXX(sip_method));
				if(pcap_drop_flag) {
					call->pcap_drop = pcap_drop_flag;
				}
				if(call_cancel_lsr487) {
					call->cancel_lsr487 = call_cancel_lsr487;
				}
			} else if(opt_callidmerge_header[0] != '\0') {
				call = process_packet__merge(packetS, parsePacket, callidstr, &merged, &gettagLimitLen);
			}
		}
	
		if(call && lastSIPresponseNum && IS_SIP_RESXXX(sip_method)) {
			if(call->first_invite_time_usec) {
				if(lastSIPresponseNum == 100) {
					if(!call->first_response_100_time_usec) {
						call->first_response_100_time_usec = packetS->header.ts.tv_sec * 1000000ull + packetS->header.ts.tv_usec;
					}
				} else {
					if(!call->first_response_xxx_time_usec) {
						call->first_response_xxx_time_usec = packetS->header.ts.tv_sec * 1000000ull + packetS->header.ts.tv_usec;
					}
				}
			} else if(call->first_message_time_usec && lastSIPresponseNum == 200) {
				if(!call->first_response_200_time_usec) {
					call->first_response_200_time_usec = packetS->header.ts.tv_sec * 1000000ull + packetS->header.ts.tv_usec;
				}
			}
		}
		
		if (!call){
			// packet does not belongs to any call yet
			if (sip_method == INVITE || sip_method == MESSAGE || (opt_sip_register && sip_method == REGISTER)) {
				if(parsePacketPreproc && parsePacketPreproc->isSip && PreProcessPacket::isEnableExtend() &&
				   parsePacketPreproc->_createCall &&
				   (sip_method == INVITE || sip_method == MESSAGE)) {
					call = parsePacketPreproc->call_created;
					detectUserAgent = parsePacketPreproc->detectUserAgent;
				} else {
					call = new_invite_register(packetS, parsePacket,
								   sip_method, callidstr, &detectUserAgent);
					if(call == NULL) {
						goto endsip;
					}
					extern int opt_vlan_siprtpsame;
					if(sip_method == INVITE && opt_vlan_siprtpsame) {
						sll_header *header_sll;
						ether_header *header_eth;
						u_int header_ip_offset;
						int protocol;
						int vlan;
						parseEtherHeader(packetS->dlt, (u_char*)packetS->packet,
								 header_sll, header_eth, header_ip_offset, protocol, &vlan);
						call->vlan = vlan;
					}
				}
				if(call == NULL) {
					goto endsip;
				} else if(sip_method == INVITE && !call->first_invite_time_usec) {
					call->first_invite_time_usec = packetS->header.ts.tv_sec * 1000000ull + packetS->header.ts.tv_usec;
				} else if(sip_method == MESSAGE && !call->first_message_time_usec) {
					call->first_message_time_usec = packetS->header.ts.tv_sec * 1000000ull + packetS->header.ts.tv_usec;
				}
			} else {
				// SIP packet does not belong to any call and it is not INVITE 
				// TODO: check if we have enabled live sniffer for SUBSCRIBE or OPTIONS 
				// if yes check for cseq OPTIONS or SUBSCRIBE 
				s = gettag(packetS->data, packetS->datalen, parsePacket,
					   "\nCSeq:", &l, &gettagLimitLen);
				if(l && l < 32) {
					if(livesnifferfilterUseSipTypes.u_subscribe && memmem(s, l, "SUBSCRIBE", 9)) {
						save_live_packet(NULL, packetS, parsePacket, SUBSCRIBE);
					} else if(livesnifferfilterUseSipTypes.u_options && memmem(s, l, "OPTIONS", 7)) {
						save_live_packet(NULL, packetS, parsePacket, OPTIONS);
					} else if(livesnifferfilterUseSipTypes.u_notify && memmem(s, l, "NOTIFY", 6)) {
						save_live_packet(NULL, packetS, parsePacket, NOTIFY);
					}
				}
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
						packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
						call, "SIP packet does not belong to any call and it is not INVITE");
				}
				goto endsip;
			}
		// check if the SIP msg is part of earlier REGISTER
		} else if(call->type == REGISTER) {
			if(call->lastsrcip != packetS->saddr) { call->oneway = 0; };
			call->lastSIPresponseNum = lastSIPresponseNum;
			call->msgcount++;
			bool goto_endsip = false;
			if(sip_method == REGISTER) {
				call->regcount++;
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER Call-ID[%s] regcount[%d]", call->call_id.c_str(), call->regcount);

				// update Authorization
				s = gettag(packetS->data, packetS->datalen, parsePacket,
					   "\nAuthorization:", &l, &gettagLimitLen);
				if(l && ((unsigned int)l < ((unsigned int)packetS->datalen - (s - packetS->data)))) {
					get_value_stringkeyval(s, packetS->datalen - (s - packetS->data), "username=\"", call->digest_username, sizeof(call->digest_username));
					get_value_stringkeyval(s, packetS->datalen - (s - packetS->data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
				}

				if(call->regcount > 4) {
					// to much register attempts without OK or 401 responses
					call->regstate = 4;
					call->saveregister();
					call = new_invite_register(packetS, parsePacket,
								   sip_method, callidstr, &detectUserAgent);
					if(call == NULL) {
						goto endsip;
					}
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
							packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
							call, "to much register attempts without OK or 401 responses");
					}
					returnCall = call;
					goto endsip_save_packet;
				}
				s = gettag(packetS->data, packetS->datalen, parsePacket,
					   "\nCSeq:", &l, &gettagLimitLen);
				if(l && l < 32) {
					memcpy(call->invitecseq, s, l);
					call->invitecseq[l] = '\0';
				}


			} else if(sip_method == RES2XX) {
				call->seenRES2XX = true;
				// update expires header from all REGISTER dialog messages (from 200 OK which can override the expire) but not if register_expires == 0
				if(call->register_expires != 0) {
					s = gettag(packetS->data, packetS->datalen, parsePacket,
						   "\nExpires:", &l, &gettagLimitLen);
					if(l && ((unsigned int)l < ((unsigned int)packetS->datalen - (s - packetS->data)))) {
						char c = s[l];
						s[l] = '\0';
						call->register_expires = atoi(s);
						s[l] = c;
					}
					// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
					get_expires_from_contact(packetS->data, packetS->datalen, parsePacket, &call->register_expires);
				}
				if(opt_enable_fraud) {
					fraudConnectCall(call, packetS->header.ts);
				}
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER OK Call-ID[%s]", call->call_id.c_str());
                                s = gettag(packetS->data, packetS->datalen, parsePacket,
					   "\nCSeq:", &l, &gettagLimitLen);
                                if(l && strncmp(s, call->invitecseq, l) == 0) {
					// registration OK 
					call->regstate = 1;

					// diff in ms
					call->regrrddiff = 1000 * (packetS->header.ts.tv_sec - call->regrrdstart.tv_sec) + (packetS->header.ts.tv_usec - call->regrrdstart.tv_usec) / 1000;
				} else {
					// OK to unknown msg close the call
					call->regstate = 3;
				}
				save_sip_packet(call, packetS, parsePacket,
						sipDatalen, TYPE_SIP, 
						origDatalen, sipOffset,
						forceSip);
				call->saveregister();
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
						packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
						call, "update expires header from all REGISTER dialog messages (from 200 OK which can override the expire)");
				}
				goto_endsip = true;
			} else if(sip_method == RES401 or sip_method == RES403 or sip_method == RES404) {
				if(sip_method == RES401) {
					call->reg401count++;
					if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER 401 Call-ID[%s] reg401count[%d]", call->call_id.c_str(), call->reg401count);
				}
				if((sip_method == RES401 && call->reg401count > 1) || 
				   sip_method == RES403 || sip_method == RES404) {
					// registration failed
					call->regstate = 2;
					save_sip_packet(call, packetS, parsePacket,
							sipDatalen, TYPE_SIP, 
							origDatalen, sipOffset,
							forceSip);
					call->saveregister();
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
							packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
							call, 
							sip_method == RES401 ? "REGISTER 401 count > 1" :
							sip_method == RES403 ? "REGISTER 403" :
							sip_method == RES404 ? "REGISTER 404" : "");
					}
					goto_endsip = true;
				}
			}
			if(call->regstate && !call->regresponse) {
				if(opt_enable_fraud) {
					fraudRegisterResponse(call->sipcallerip[0], call->first_packet_time * 1000000ull + call->first_packet_usec,
							      call->a_ua[0] ? call->a_ua : call->b_ua[0] ? call->b_ua : NULL, -1);
				}
				call->regresponse = true;
			}
			if(goto_endsip) {
				goto endsip;
			}
			if(call->msgcount > 20) {
				// too many REGISTER messages within the same callid
				call->regstate = 4;
				save_sip_packet(call, packetS, parsePacket,
						sipDatalen, TYPE_SIP, 
						origDatalen, sipOffset,
						forceSip);
				call->saveregister();
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
						packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
						call, "too many REGISTER messages within the same callid");
				}
				goto endsip;
			}
		// packet is already part of call
		// check if SIP packet belongs to the first leg 
		} else if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
			((call->saddr == packetS->saddr && call->sport == packetS->source) || 
			(call->saddr == packetS->daddr && call->sport == packetS->dest))))

			{

			if(call->lastsrcip != packetS->saddr) { call->oneway = 0; };

			char *cseq = NULL;
			long unsigned int cseqlen = 0;
			cseq = gettag(packetS->data, packetS->datalen, parsePacket,
				      "\nCSeq:", &cseqlen, &gettagLimitLen);
			bool cseq_contain_invite = false;
			if(cseq && cseqlen < 32) {
				if(memmem(call->invitecseq, strlen(call->invitecseq), cseq, cseqlen)) {
					cseq_contain_invite = true;
					if(sip_method == (call->type == MESSAGE ? MESSAGE : INVITE)) {
						call->unrepliedinvite++;
					} else if(call->unrepliedinvite > 0){
						call->unrepliedinvite--;
					}
					//syslog(LOG_NOTICE, "[%s] unrepliedinvite--\n", call->call_id);
				}
				if(!cseq_contain_invite &&
				   memmem(cseq, cseqlen, (call->type == MESSAGE ? "MESSAGE" : "INVITE"), (call->type == MESSAGE ? 7 : 6))) {
					cseq_contain_invite = true;
				}
			}

			if(opt_norecord_header) {
				s = gettag(packetS->data, packetS->datalen, parsePacket,
					   "\nX-VoipMonitor-norecord:", &l, &gettagLimitLen);
				if(l && l < 33) {
					// do 
					call->stoprecording();
				}
			}

			// we have packet, extend pending destroy requests
			call->shift_destroy_call_at(&packetS->header, lastSIPresponseNum);

			call->set_last_packet_time(packetS->header.ts.tv_sec);
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
			   (lastSIPresponseNum != 200 || cseq_contain_invite) &&
			   !(call->cancelcseq[0] && cseq && cseqlen < 32 && strncmp(cseq, call->cancelcseq, cseqlen) == 0)) {
				strncpy(call->lastSIPresponse, lastSIPresponse, 128);
				call->lastSIPresponseNum = lastSIPresponseNum;
			}
			if(lastSIPresponseNum != 0 && lastSIPresponse[0] != '\0') {
				call->SIPresponse.push_back(Call::sSipResponse(lastSIPresponse, lastSIPresponseNum));
			}
			
			extern bool exists_columns_cdr_reason;
			if(exists_columns_cdr_reason) {
				char *reason = gettag(packetS->data, packetS->datalen, parsePacket,
						      "reason:", &l);
				if(l && (l + (reason - packetS->data)) < (unsigned)packetS->datalen) {
					char oldEndChar = reason[l];
					reason[l] = 0;
					char *pointerToCause = strcasestr(reason, ";cause=");
					if(pointerToCause && (pointerToCause - reason) < 10) {
						char type[10];
						memcpy(type, reason, pointerToCause - reason);
						type[pointerToCause - reason] = 0;
						//remove spaces from end of string type
						for(int i = pointerToCause - reason; i > 0; i--) {
							if(type[i] == ' ') {
								type[i] = 0;
							} else {
								break;
							}
						}
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
					reason[l] = oldEndChar;
				}
			}

			// check if it is BYE or OK(RES2XX)
			if(sip_method == INVITE) {
				/* festr - 14.03.2015 - this prevents some type of call to process call in case of call merging
				if(!call->seenbye) {
				*/
					call->seenbye = 0;
					call->destroy_call_at = 0;
					call->destroy_call_at_bye = 0;
				if(call->lastSIPresponseNum == 487) {
					call->new_invite_after_lsr487 = true;
				}
				//update called number for each invite due to overlap-dialling
				if (opt_sipoverlap && packetS->saddr == call->sipcallerip[0]) {
					int res = get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								   "\nTo:", call->called, sizeof(call->called));
					if(res) {
						// try compact header
						get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								 "\nt:", call->called, sizeof(call->called));
					}
					if(opt_destination_number_mode == 2) {
						char called[1024] = "";
						if(!get_sip_peername(packetS->data, packetS->datalen, parsePacket,
								     "INVITE ", called, sizeof(called)) &&
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
				call->destroy_call_at = packetS->header.ts.tv_sec + 60;
				call->seeninviteok = false;

				s = gettag(packetS->data, packetS->datalen, parsePacket,
					   "\nUser-Agent:", &l, &gettagLimitLen);
				if(l && ((unsigned int)l < ((unsigned int)packetS->datalen - (s - packetS->data)))) {
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
				char *rsltMessage;
				string rsltDestNumber;
				string rsltSrcNumber;
				unsigned int rsltContentLength;
				switch(parse_packet__message(packetS->data, packetS->datalen, parsePacket, call->message != NULL,
							     &rsltMessage, &rsltDestNumber, &rsltSrcNumber, &rsltContentLength)) {
				case 2:
					if(call->message) {
						delete [] call->message;
					}
					call->message = rsltMessage;
					break;
				case 1:
					if(!call->message) {
						call->message = new FILE_LINE char[1];
						call->message[0] = '\0';
					}
					break;
				}
				if(rsltDestNumber.length()) {
					strncpy(call->called, rsltDestNumber.c_str(), sizeof(call->called));
					call->updateDstnumFromMessage = true;
				}
				if(rsltSrcNumber.length()) {
					strncpy(call->caller, rsltSrcNumber.c_str(), sizeof(call->caller));
				}
				/* obsolete
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
				*/
			} else if(sip_method == BYE) {
				if(!call->has_second_merged_leg or (call->has_second_merged_leg and merged)) {
					//do not set destroy for BYE which belongs to first leg in case of merged legs through sip header 
					call->destroy_call_at = packetS->header.ts.tv_sec + 60;
					call->destroy_call_at_bye = packetS->header.ts.tv_sec + 20 * 60;
				}
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
						fraudSeenByeCall(call, packetS->header.ts);
					}
				}
				// save who hanged up 
				if(call->sipcallerip[0] == packetS->saddr) {
					call->whohanged = 0;
				} else if(call->sipcalledip[0] == packetS->saddr) {
					call->whohanged = 1;
				}
			} else if(sip_method == CANCEL) {
				// CANCEL continues with Status: 200 canceling; 200 OK; 487 Req. terminated; ACK. Lets wait max 10 seconds and destroy call
				if(!call->has_second_merged_leg or (call->has_second_merged_leg and merged)) {
					//do not set destroy for CANCEL which belongs to first leg in case of merged legs through sip header 
					call->destroy_call_at = packetS->header.ts.tv_sec + 10;
				}
				
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
						call->progress_time = packetS->header.ts.tv_sec;
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
						call->destroy_call_at = packetS->header.ts.tv_sec + 5;
						if(logPacketSipMethodCall_enable) {
							logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
								packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
								call);
						}
						process_packet__parse_custom_headers(call, packetS->data, packetS->datalen, parsePacket);
						returnCall = call;
						goto endsip_save_packet;
					} else if(strncmp(cseq, call->invitecseq, cseqlen) == 0) {
						call->seeninviteok = true;
						if(!call->connect_time) {
							call->connect_time = packetS->header.ts.tv_sec;
							if(opt_enable_fraud) {
								fraudConnectCall(call, packetS->header.ts);
							}
						}
						if(opt_update_dstnum_onanswer &&
						   !call->updateDstnumOnAnswer && !call->updateDstnumFromMessage &&
						   call->called_invite_branch_map.size()) {
							char branch[100];
							if(!get_sip_branch(packetS->data, packetS->datalen, parsePacket, 
									   "via:", branch, sizeof(branch)) &&
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
						process_packet__parse_custom_headers(call, packetS->data, packetS->datalen, parsePacket);
						returnCall = call;
						goto endsip_save_packet;
					}
				}
				if(!call->onCall_2XX) {
					ClientThreads.onCall(lastSIPresponseNum, call->callername, call->caller, call->called,
							     call->sipcallerip[0], call->sipcalledip[0]);
					sendCallInfoEvCall(call, sSciInfo::sci_200, packetS->header.ts);
					call->onCall_2XX = true;
				}

			} else if(sip_method == RES18X) {
				call->seenRES18X = true;
				if(!call->progress_time) {
					call->progress_time = packetS->header.ts.tv_sec;
				}
				if(!call->onCall_18X) {
					ClientThreads.onCall(lastSIPresponseNum, call->callername, call->caller, call->called,
							     call->sipcallerip[0], call->sipcalledip[0]);
					sendCallInfoEvCall(call, sSciInfo::sci_18X, packetS->header.ts);
					call->onCall_18X = true;
				}
				call->destroy_call_at = 0;
				call->destroy_call_at_bye = 0;
			}

			// if the call ends with some of SIP [456]XX response code, we can shorten timeout when the call will be closed 
//			if((call->saddr == saddr || call->saddr == daddr || merged) &&
			if (IS_SIP_RES3XX(sip_method) || IS_SIP_RES4XX(sip_method) || sip_method == RES5XX || sip_method == RES6XX) {
				if(lastSIPresponseNum != 401 && lastSIPresponseNum != 407 && lastSIPresponseNum != 501 && lastSIPresponseNum != 481 && lastSIPresponseNum != 491) {
					// save packet 
					if(!call->has_second_merged_leg or (call->has_second_merged_leg and merged)) {
						call->destroy_call_at = packetS->header.ts.tv_sec + (sip_method == RES300 ? 300 : 5);
					}

					if(IS_SIP_RES3XX(sip_method)) {
						// remove all RTP  
						call->removeFindTables();
						call->removeRTP();
						call->ipport_n = 0;
					}
					if(logPacketSipMethodCall_enable) {
						logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
							packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
							call);
					}
					process_packet__parse_custom_headers(call, packetS->data, packetS->datalen, parsePacket);
					returnCall = call;
					goto endsip_save_packet;
				} else if(lastSIPresponseNum == 481) {
					//481 CallLeg/Transaction doesnt exist - set timeout to 180 seconds

					if(!call->has_second_merged_leg or (call->has_second_merged_leg and merged)) {
						call->destroy_call_at = packetS->header.ts.tv_sec + 180;
					}
				} else if(lastSIPresponseNum == 491) {
					// do not set timeout for 491
				} else if(!call->destroy_call_at) {
					if(!call->has_second_merged_leg or (call->has_second_merged_leg and merged)) {
						call->destroy_call_at = packetS->header.ts.tv_sec + 60;
					}
				}
			}
		}

		if(call->lastsrcip != packetS->saddr) { call->oneway = 0; };

		if(sip_method == INVITE || sip_method == MESSAGE) {
		 
			bool existInviteSdaddr = false;
			bool reverseInviteSdaddr = false;
			for(list<d_u_int32_t>::iterator iter = call->invite_sdaddr.begin(); iter != call->invite_sdaddr.end(); iter++) {
				if(packetS->saddr == (*iter)[0] && packetS->daddr == (*iter)[1]) {
					existInviteSdaddr = true;
				} else if(packetS->daddr == (*iter)[0] && packetS->saddr == (*iter)[1]) {
					reverseInviteSdaddr = true;
				}
			}
			if(!existInviteSdaddr) {
				call->invite_sdaddr.push_back(d_u_int32_t(packetS->saddr, packetS->daddr));
			}
		 
			if(opt_update_dstnum_onanswer) {
				char branch[100];
				if(!get_sip_branch(packetS->data, packetS->datalen, parsePacket, 
						   "via:", branch, sizeof(branch)) &&
				   branch[0] != '\0') {
					char called_invite[1024] = "";
					if(!get_sip_peername(packetS->data, packetS->datalen, parsePacket,
							     sip_method == MESSAGE ? "MESSAGE " : "INVITE ", called_invite, sizeof(called_invite)) &&
					   called_invite[0] != '\0') {
						call->called_invite_branch_map[branch] = called_invite;
					}
				}
			}
			ipfilter->add_call_flags(&(call->flags), ntohl(packetS->saddr), ntohl(packetS->daddr));
			if(opt_cdrproxy && !reverseInviteSdaddr) {
				if(call->sipcalledip[0] != packetS->daddr and call->sipcallerip[0] != packetS->daddr and call->lastsipcallerip != packetS->saddr) {
					if(packetS->daddr != 0) {
						// daddr is already set, store previous daddr as sipproxy
						call->proxies.push_back(call->sipcalledip[0]);
					}
					call->sipcalledip[0] = packetS->daddr;
					call->sipcalledport = packetS->dest;
					call->lastsipcallerip = packetS->saddr;
				} else if(call->lastsipcallerip == packetS->saddr) {
					// update sipcalledip to this new one
					call->sipcalledip[0] = packetS->daddr;
					call->sipcalledport = packetS->dest;
					call->lastsipcallerip = packetS->saddr;
				}
			}
		}

		if(opt_norecord_header) {
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "\nX-VoipMonitor-norecord:", &l, &gettagLimitLen);
			if(l && l < 33) {
				// do 
				call->stoprecording();
			}
		}

		if(sip_method == INFO) {
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "\nSignal:", &l, &gettagLimitLen);
			if(l && l < 33) {
				char *tmp = s + 1;
				tmp[l - 1] = '\0';
				if(verbosity >= 2)
					syslog(LOG_NOTICE, "[%s] DTMF SIP INFO [%c]", call->fbasename, tmp[0]);
				call->handle_dtmf(*tmp, ts2double(packetS->header.ts.tv_sec, packetS->header.ts.tv_usec), packetS->saddr, packetS->daddr);
			}
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "Signal=", &l, &gettagLimitLen);
			if(l && l < 33) {
				char *tmp = s;
				tmp[l] = '\0';
				if(verbosity >= 2)
					syslog(LOG_NOTICE, "[%s] DTMF SIP INFO [%c]", call->fbasename, tmp[0]);
				call->handle_dtmf(*tmp, ts2double(packetS->header.ts.tv_sec, packetS->header.ts.tv_usec), packetS->saddr, packetS->daddr);

			}
		}
		
		// check if we have X-VoipMonitor-Custom1
		s = gettag(packetS->data, packetS->datalen, parsePacket,
			   "\nX-VoipMonitor-Custom1:", &l, &gettagLimitLen);
		if(l && l < 255) {
			memcpy(call->custom_header1, s, l);
			call->custom_header1[l] = '\0';
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen X-VoipMonitor-Custom1: %s\n", call->custom_header1);
		}

		// check for opt_match_header
		if(opt_match_header[0] != '\0') {
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   opt_match_header, &l, &gettagLimitLen);
			if(l && l < 128) {
				memcpy(call->match_header, s, l);
				call->match_header[l] = '\0';
				if(verbosity > 2)
					syslog(LOG_NOTICE, "Seen header %s: %s\n", opt_match_header, call->match_header);
			}
		}
	
		// check if we have custom headers
		process_packet__parse_custom_headers(call, packetS->data, packetS->datalen, parsePacket);
		
		// we have packet, extend pending destroy requests
		call->shift_destroy_call_at(&packetS->header, lastSIPresponseNum);

		// SDP examination
		s = gettag(packetS->data, packetS->datalen, parsePacket,
			   "\nContent-Type:", &l, &gettagLimitLen);
		if(l <= 0 || l > 1023) {
			//try compact header
			s = gettag(packetS->data, packetS->datalen, parsePacket,
				   "\nc:", &l, &gettagLimitLen);
		}

		char a;
		a = packetS->data[packetS->datalen - 1];
		packetS->data[packetS->datalen - 1] = 0;
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
			
			char *rsltMessage;
			string rsltDestNumber;
			string rsltSrcNumber;
			unsigned int rsltContentLength;
			packetS->data[packetS->datalen - 1] = a;
			switch(parse_packet__message(packetS->data, packetS->datalen, parsePacket, false,
						     &rsltMessage, &rsltDestNumber, &rsltSrcNumber, &rsltContentLength)) {
			case 2:
				call->message = rsltMessage;
				break;
			case 1:
				if(!call->message) {
					call->message = new FILE_LINE char[1];
					call->message[0] = '\0';
				}
				break;
			case -1:
				goto notfound;
			}
			if(rsltDestNumber.length()) {
				strncpy(call->called, rsltDestNumber.c_str(), sizeof(call->called));
				call->updateDstnumFromMessage = true;
			}
			if(rsltSrcNumber.length()) {
				strncpy(call->caller, rsltSrcNumber.c_str(), sizeof(call->caller));
			}
			if(rsltContentLength != (unsigned int)-1) {
				call->content_length = rsltContentLength;
			}
			/* obsolete
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
			*/
			//printf("msg: contentlen[%d] datalen[%d] len[%d] [%s]\n", contentlen, datalen, strlen(call->message), call->message);
		} else if(strcasestr(s, "application/sdp")) {
			*sl = t;
			// prepare User-Agent
			char *ua = NULL;
			unsigned long gettagLimitLen = 0, ua_len = 0;
			ua = gettag(packetS->data, packetS->datalen, parsePacket,
				    "\nUser-Agent:", &ua_len, &gettagLimitLen);
			detectUserAgent = true;
			process_sdp(call, packetS,
				    sip_method, s, (unsigned int)packetS->datalen - (s - packetS->data), callidstr, ua, ua_len);
		} else if(strcasestr(s, "multipart/mixed")) {
			*sl = t;
			char *ua = NULL;
			unsigned long gettagLimitLen = 0, ua_len = 0;
			ua = gettag(packetS->data, packetS->datalen, parsePacket,
				    "\nUser-Agent:", &ua_len, &gettagLimitLen);
			detectUserAgent = true;
			while(1) {
				//continue searching  for another content-type
				char *s2;
				s2 = gettag(s, (unsigned int)packetS->datalen - (s - packetS->data), NULL,
					    "\nContent-Type:", &l, NULL);
				if(l <= 0 || l > 1023) {
					//try compact header
					s2 = gettag(s, (unsigned int)packetS->datalen - (s - packetS->data), NULL,
						    "\nc:", &l, NULL);
				}
				if(s2 and l > 0) {
					//Content-Type found try if it is SDP 
					if(l > 0 && strcasestr(s2, "application/sdp")){
						process_sdp(call, packetS,
							    sip_method, s2, (unsigned int)packetS->datalen - (s2 - packetS->data), callidstr, ua, ua_len);
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
			logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
				packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
				call);
		}
		returnCall = call;
		packetS->data[packetS->datalen - 1] = a;
endsip_save_packet:
		save_sip_packet(call, packetS, parsePacket,
				sipDatalen, TYPE_SIP, 
				origDatalen, sipOffset,
				forceSip);
endsip:
		if(_save_sip_history && call) {
			bool save_request = IS_SIP_RESXXX(sip_method) ?
					     lastSIPresponseNum && _save_sip_history_all_responses :
					     sip_method && (_save_sip_history_all_requests || _save_sip_history_request_types[sip_method]);
			bool save_response = lastSIPresponseNum && _save_sip_history_all_responses;
			if(save_request || save_response) {
				char _request[20] = "";
				char *_lastSIPresponse = NULL;
				int _lastSIPresponseNum = 0;
				if(save_request) {
					const char *sip_request_name = sip_request_int_to_name(sip_method, false);
					if(sip_request_name) {
						strncpy(_request, sip_request_name, sizeof(_request) - 1);
						_request[sizeof(_request) - 1] = 0;
					}
				}
				if(save_response) {
					_lastSIPresponse = lastSIPresponse;
					_lastSIPresponseNum = lastSIPresponseNum;
				}
				if(_request[0] || 
				   (_lastSIPresponse && _lastSIPresponse[0]) || 
				   _lastSIPresponseNum) {
					call->SIPhistory.push_back(Call::sSipHistory(
						packetS->header.ts.tv_sec * 1000000ull + packetS->header.ts.tv_usec,
						_request,
						_lastSIPresponse, _lastSIPresponseNum));
				}
			}
		}
		
		if(call && call->type != REGISTER && sipSendSocket && !opt_sip_send_before_packetbuffer) {
			// send packet to socket if enabled
			u_int16_t header_length = packetS->datalen;
			sipSendSocket->addData(&header_length, 2,
					       packetS->data, packetS->datalen);
		}

		if(!detectUserAgent && sip_method && call) {
			bool iscaller = 0;
			if(call->check_is_caller_called(sip_method, packetS->saddr, packetS->daddr, &iscaller)) {
				s = gettag(packetS->data, sipDatalen, parsePacket,
					   "\nUser-Agent:", &l, &gettagLimitLen);
				if(l && ((unsigned int)l < ((unsigned int)sipDatalen - (s - packetS->data)))) {
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
		packetS->datalen = origDatalen;
		if(packetS->istcp &&
		   sipDatalen < (unsigned)packetS->datalen - 11 &&
		   (unsigned)packetS->datalen + sipOffset < packetS->header.caplen) {
			unsigned long skipSipOffset = 0;
			if(check_sip20(packetS->data + sipDatalen, packetS->datalen - sipDatalen, NULL)) {
				skipSipOffset = sipDatalen;
			} else {
				char *pointToDoubleEndLine = (char*)memmem(packetS->data + sipDatalen, packetS->datalen - sipDatalen, "\r\n\r\n", 4);
				if(pointToDoubleEndLine) {
					unsigned long offsetAfterDoubleEndLine = pointToDoubleEndLine - packetS->data + 4;
					if(offsetAfterDoubleEndLine < (unsigned)packetS->datalen - 11 &&
					   check_sip20(packetS->data + offsetAfterDoubleEndLine, packetS->datalen - offsetAfterDoubleEndLine, NULL)) {
						skipSipOffset = offsetAfterDoubleEndLine;
					}
				}
			}
			if(skipSipOffset) {
				packet_s packetS_mod = *packetS;
				packetS_mod.data += skipSipOffset;
				packetS_mod.datalen -= skipSipOffset;
				process_packet(&packetS_mod, NULL,
					       was_rtp, voippacket, forceSip,
					       false, sipOffset + skipSipOffset);
			}
		}
		return returnCall;
	}

rtpcheck:

	if(packetS->datalen > 2/* && (htons(*(unsigned int*)data) & 0xC000) == 0x8000*/) { // disable condition - failure for udptl (fax)
	if(processRtpPacketHash) {
		processRtpPacketHash->push_packet_rtp_1(packetS,
							parsePacketPreproc && parsePacketPreproc->hash[0] ? 
							 parsePacketPreproc->hash[0] : 
							 tuplehash(packetS->saddr, packetS->source),
							parsePacketPreproc && parsePacketPreproc->hash[1] ? 
							 parsePacketPreproc->hash[1] : 
							 tuplehash(packetS->daddr, packetS->dest));
	} else {
	if ((calls = calltable->hashfind_by_ip_port(packetS->daddr, packetS->dest, parsePacketPreproc && parsePacketPreproc->hash[1] ? parsePacketPreproc->hash[1] : 0))){
		++counter_rtp_packets;
		// packet (RTP) by destination:port is already part of some stored call  
		for (node_call = (hash_node_call *)calls; node_call != NULL; node_call = node_call->next) {
			call = node_call->call;
			iscaller = node_call->iscaller;
			sdp_flags = node_call->sdp_flags;
			is_rtcp = node_call->is_rtcp || (sdp_flags.rtcp_mux && packetS->datalen > 1 && (u_char)packetS->data[1] == 0xC8);
			
			if(sverb.process_rtp) {
				++process_rtp_counter;
				cout << "RTP - process_packet -"
				     << " src: " << inet_ntostring(htonl(packetS->saddr)) << " : " << packetS->source
				     << " dst: " << inet_ntostring(htonl(packetS->daddr)) << " : " << packetS->dest
				     << " iscaller: " << (iscaller ? "caller" : "called") 
				     << " counter: " << process_rtp_counter
				     << " #1"
				     << endl;
			}

			if(pcap_drop_flag) {
				call->pcap_drop = pcap_drop_flag;
			}

			if(!is_rtcp && !sdp_flags.is_fax &&
			   (packetS->datalen < RTP_FIXED_HEADERLEN ||
			    packetS->header.caplen <= (unsigned)(packetS->datalen - RTP_FIXED_HEADERLEN))) {
				return(call);
			}

			*voippacket = 1;

			// we have packet, extend pending destroy requests
			call->shift_destroy_call_at(&packetS->header, lastSIPresponseNum);

			int can_thread = !sverb.disable_threads_rtp;

			if(sdp_flags.is_fax) {
				call->seenudptl = 1;
			}

			if(is_rtcp) {
				if(rtp_threaded && can_thread) {
					add_to_rtp_thread_queue(call, packetS, 
								iscaller, is_rtcp, enable_save_rtcp(call), false);
				} else {
					call->read_rtcp(packetS, iscaller, enable_save_rtcp(call));
				}
				return call;
			}

			*was_rtp = 1;
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, packetS, 
							iscaller, is_rtcp, enable_save_rtp(call), false);
			} else {
				call->read_rtp(packetS, iscaller, enable_save_rtp(call),
					       packetS->block_store && packetS->block_store->ifname[0] ? packetS->block_store->ifname : NULL);
				call->set_last_packet_time(packetS->header.ts.tv_sec);
			}
		}
	} else if ((calls = calltable->hashfind_by_ip_port(packetS->saddr, packetS->source, parsePacketPreproc && parsePacketPreproc->hash[0] ? parsePacketPreproc->hash[0] : 0))){
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
			sdp_flags = node_call->sdp_flags;
			is_rtcp = node_call->is_rtcp || (sdp_flags.rtcp_mux && packetS->datalen > 1 && (u_char)packetS->data[1] == 0xC8);

			if(sverb.process_rtp) {
				++process_rtp_counter;
				cout << "RTP - process_packet -"
				     << " src: " << inet_ntostring(htonl(packetS->saddr)) << " : " << packetS->source
				     << " dst: " << inet_ntostring(htonl(packetS->daddr)) << " : " << packetS->dest
				     << " iscaller: " << (iscaller ? "caller" : "called") 
				     << " counter: " << process_rtp_counter
				     << " #2"
				     << endl;
			}
			
			if(pcap_drop_flag) {
				call->pcap_drop = pcap_drop_flag;
			}

			if(!is_rtcp && !sdp_flags.is_fax &&
			   (packetS->datalen < RTP_FIXED_HEADERLEN ||
			    packetS->header.caplen <= (unsigned)(packetS->datalen - RTP_FIXED_HEADERLEN))) {
				return(call);
			}

			*voippacket = 1;

			// we have packet, extend pending destroy requests
			call->shift_destroy_call_at(&packetS->header, lastSIPresponseNum);

			int can_thread = !sverb.disable_threads_rtp;

			if(sdp_flags.is_fax) {
				call->seenudptl = 1;
			}

			if(is_rtcp) {
				if(rtp_threaded && can_thread) {
					add_to_rtp_thread_queue(call, packetS, 
								!iscaller, is_rtcp, enable_save_rtcp(call), false);
				} else {
					call->read_rtcp(packetS, !iscaller, enable_save_rtcp(call));
				}
				return call;
			}

			// as we are searching by source address and find some call, revert iscaller 
			*was_rtp = 1;
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, packetS, 
							!iscaller, is_rtcp, enable_save_rtp(call), false);
			} else {
				call->read_rtp(packetS, !iscaller, enable_save_rtp(call), 
					       packetS->block_store && packetS->block_store->ifname[0] ? packetS->block_store->ifname : NULL);
				call->set_last_packet_time(packetS->header.ts.tv_sec);
			}
		}

	// packet does not belongs to established call, check if it is on SIP port
	} else {
		if(opt_rtpnosip) {
			unsigned int flags = 0;
			set_global_flags(flags);
			ipfilter->add_call_flags(&flags, ntohl(packetS->saddr), ntohl(packetS->daddr));
			if(flags & FLAG_SKIPCDR) {
				if(verbosity > 1)
					syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
				return NULL;
			}
		 
			// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
			char s[256];
			RTP rtp(-1);
			int rtpmap[MAX_RTPMAP];
			memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);

			rtp.read((unsigned char*)packetS->data, packetS->datalen, &packetS->header, packetS->saddr, packetS->daddr, packetS->source, packetS->dest, 0, packetS->sensor_id);

			if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
				if(logPacketSipMethodCall_enable) {
					logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
						packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
						call, "decoding RTP without SIP signaling is enabled (rtp.getVersion() != 2 && rtp.getPayload() > 18)");
				}
				return NULL;
			}
			snprintf(s, 256, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

			//printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

			call = calltable->add(s, strlen(s), packetS->header.ts.tv_sec, packetS->saddr, packetS->source, packetS->handle, packetS->dlt, packetS->sensor_id);
			call->chantype = CHAN_SIP;
			call->set_first_packet_time(packetS->header.ts.tv_sec, packetS->header.ts.tv_usec);
			call->sipcallerip[0] = packetS->saddr;
			call->sipcalledip[0] = packetS->daddr;
			call->sipcallerport = packetS->source;
			call->sipcalledport = packetS->dest;
			call->type = INVITE;
			call->flags = flags;
			strncpy(call->fbasename, s, MAX_FNAME - 1);
			call->seeninvite = true;
			strcpy(call->callername, "RTP");
			strcpy(call->caller, "RTP");
			strcpy(call->called, "RTP");

#ifdef DEBUG_INVITE
			syslog(LOG_NOTICE, "New RTP call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s]\n", call->sipcallerip, call->sipcalledip, call->caller, call->called);
#endif

			// opening dump file
			if(enable_save_any(call)) {
				mkdir_r(call->dirname().c_str(), 0777);
			}
			if(enable_save_packet(call)) {
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

			call->add_ip_port_hash(packetS->saddr, packetS->daddr, packetS->dest, NULL, s, l, 1, rtpmap, s_sdp_flags(), 0);
			call->add_ip_port_hash(packetS->saddr, packetS->saddr, packetS->source, NULL, s, l, 0, rtpmap, s_sdp_flags(), 0);
			
		}
		// we are not interested in this packet
		if (verbosity >= 6){
			char st1[16];
			char st2[16];
			struct in_addr in;

			in.s_addr = packetS->saddr;
			strcpy(st1, inet_ntoa(in));
			in.s_addr = packetS->daddr;
			strcpy(st2, inet_ntoa(in));
			syslog(LOG_ERR, "Skipping udp packet %s:%d->%s:%d\n", st1, packetS->source, st2, packetS->dest);
		}
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
				packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
				call, "we are not interested in this packet");
		}
		return NULL;
	}
	}
	}

	if(logPacketSipMethodCall_enable) {
		logPacketSipMethodCall(packetS->packet_number, sip_method, lastSIPresponseNum, &packetS->header, 
			packetS->saddr, packetS->source, packetS->daddr, packetS->dest,
			call, "---");
		}
	return NULL;
}

inline void process_packet__parse_custom_headers(Call *call, char *data, int datalen, ParsePacket *parsePacket) {
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
		 customHeaders->parse(call, data, datalen, parsePacket);
	}
}

inline void process_packet__cleanup(pcap_pkthdr *header, u_long timeS) {

	if(verbosity > 0 && is_read_from_file_simple()) {
		if(opt_dup_check) {
			syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d] skipped dupe pkts [%u]\n", 
				(int)calltable->calls_listMAP.size(), (int)calltable->calls_queue.size(), duplicate_counter);
		} else {
			syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d]\n", 
				(int)calltable->calls_listMAP.size(), (int)calltable->calls_queue.size());
		}
	}
	
	if(!timeS && header) {
		timeS = header->ts.tv_sec;
	}
	
	if (process_packet__last_cleanup >= 0){
		calltable->cleanup(timeS);
	}
	
	process_packet__last_cleanup = timeS;

	if(!PreProcessPacket::isEnableSip()) {
		// clean tcp_streams_list
		tcpReassemblySip.clean(timeS);
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

inline int process_packet__parse_sip_method(char *data, unsigned int datalen, bool *sip_response) {
	int sip_method = 0;
	*sip_response =  false;
	// parse SIP method 
	if ((datalen > 5) && data[0] == 'I' && !(memmem(data, 6, "INVITE", 6) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: INVITE\n");
		sip_method = INVITE;
	} else if ((datalen > 7) && data[0] == 'R' && data[2] == 'G' && !(memmem(data, 8, "REGISTER", 8) == 0)) {
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
	} else if ((datalen > 2) && data[0] == 'A' && !(memmem(data, 3, "ACK", 3) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: ACK\n");
		sip_method = ACK;
	} else if ((datalen > 4) && data[0] == 'P' && data[1] == 'R' && !(memmem(data, 5, "PRACK", 5) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: PRACK\n");
		sip_method = PRACK;
	} else if ((datalen > 6) && data[0] == 'P' && data[1] == 'U' && !(memmem(data, 7, "PUBLISH", 7) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: PUBLISH\n");
		sip_method = PUBLISH;
	} else if ((datalen > 4) && data[0] == 'R' && data[2] == 'F' && !(memmem(data, 5, "REFER", 5) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: REFER\n");
		sip_method = REFER;
	} else if ((datalen > 5) && data[0] == 'U' && !(memmem(data, 6, "UPDATE", 6) == 0)) {
		if(verbosity > 2) 
			 syslog(LOG_NOTICE,"SIP msg: UPDATE\n");
		sip_method = UPDATE;
	} else if( (datalen > 8) && data[0] == 'S' && data[1] == 'I' && !(memmem(data, 8, "SIP/2.0 ", 8) == 0)){
		*sip_response = true;
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
			if(datalen > 9) {
				if(data[9] == '0') {
					if(verbosity > 2) 
						 syslog(LOG_NOTICE,"SIP msg: 10X\n");
					sip_method = RES10X;
				} else if(data[9] == '8') {
					if(verbosity > 2) 
						 syslog(LOG_NOTICE,"SIP msg: 18X\n");
					sip_method = RES18X;
				}
			}
			break;
		case '3':
			if ((datalen > 10) && data[9] == '0' && data[10] == '0') {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 300\n");
				sip_method = RES300;
			} else {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 3XX\n");
				sip_method = RES3XX;
			}
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

inline int parse_packet__last_sip_response(char *data, unsigned int datalen, int sip_method, bool sip_response,
					   char *lastSIPresponse, bool *call_cancel_lsr487) {
	strcpy(lastSIPresponse, "NO RESPONSE");
	*call_cancel_lsr487 = false;
	int lastSIPresponseNum = 0;
	if(IS_SIP_RESXXX(sip_method) || sip_response) {
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

inline int parse_packet__message(char *data, unsigned int datalen, ParsePacket *parsePacket, bool strictCheckLength,
			  char **rsltMessage, string *rsltDestNumber, string *rsltSrcNumber, unsigned int *rsltContentLength,
			  bool maskMessage) {
	if(rsltMessage) {
		*rsltMessage = NULL;
	}
	if(rsltContentLength) {
		*rsltContentLength = (unsigned int)-1;
	}
	int setMessage = 0;
	char endCharData = data[datalen - 1];
	data[datalen - 1] = 0;
	char *endHeader = strstr(data, "\r\n\r\n");;
	if(!endHeader) {
		data[datalen - 1] = endCharData;
		return(-1);
	}
	char *contentBegin = endHeader + 4;
	int contentLength = 0;
	unsigned long l;
	char *s = gettag(data, datalen, parsePacket,
			 "\nContent-Length:", &l);
	if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
		char endCharContentLength = s[l];
		s[l] = '\0';
		contentLength = atoi(s);
		if(rsltContentLength) {
			*rsltContentLength = 0;
		}
		s[l] = endCharContentLength;
	}
	if(contentLength > 0) {
		char *contentEnd = strcasestr(contentBegin, "\n\nContent-Length:");
		if(!contentEnd) {
			contentEnd = strstr(contentBegin, "\r\n");
		}
		if(!contentEnd) {
			contentEnd = data + datalen;
		}
		if(!strictCheckLength || (contentEnd - contentBegin) == contentLength) {
			if((contentEnd - contentBegin) > contentLength) {
				contentEnd = contentBegin + contentLength;
			}
			data[datalen - 1] = endCharData;
			if(parse_packet__message_content(contentBegin, contentEnd - contentBegin,
							 rsltMessage, rsltDestNumber, rsltSrcNumber,
							 maskMessage)) {
				setMessage = 2;
			} else {
				setMessage = 1;
			}
		} else {
			data[datalen - 1] = endCharData;
		}
	} else {
		setMessage = 1;
		data[datalen - 1] = endCharData;
	}
	return(setMessage);
}

inline Call *process_packet__merge(packet_s *packetS, ParsePacket *parsePacket, char *callidstr, int *merged, long unsigned int *gettagLimitLen, bool preprocess_queue) {
	Call *call = calltable->find_by_mergecall_id(callidstr, strlen(callidstr), preprocess_queue);
	if(!call) {
		// this call-id is not yet tracked either in calls list or callidmerge list 
		// check if there is SIP callidmerge_header which contains parent call-id call
		char *s2 = NULL;
		long unsigned int l2 = 0;
		unsigned char buf[1024];
		s2 = gettag(packetS->data, packetS->datalen, parsePacket,
			    opt_callidmerge_header, &l2, gettagLimitLen);
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
			call = calltable->find_by_call_id(s2, l2, preprocess_queue);
			if(!call) {
				// there is no call with the call-id in merge header - this call will be created as new
			} else {
				*merged = 1;
				calltable->lock_calls_mergeMAP();
				call->has_second_merged_leg = true;
				calltable->calls_mergeMAP[callidstr] = call;
				calltable->unlock_calls_mergeMAP();
				call->mergecalls.push_back(callidstr);
			}
		}
	} else {
		*merged = 1;
	}
	return(call);
}

struct sGsmMessage {
	enum eGsmMessageType {
		gsm_mt_na,
		gsm_mt_data_ms_to_net,
		gsm_mt_data_net_to_ms,
		gsm_mt_ack_ms_to_net,
		gsm_mt_ack_net_to_ms
	};
	sGsmMessage() {
		type = gsm_mt_na;
		originatorAddressLength = -1;
		destinationAddressLength = -1;
		userDataLength = -1;
	}
	unsigned int getLength() {
		switch(type) {
		case gsm_mt_data_ms_to_net:
		case gsm_mt_data_net_to_ms:
			return(2 + 
			       (originatorAddressLength >= 0 ? 1 + originatorAddressLength : 0) + 
			       (destinationAddressLength >= 0 ? 1 + destinationAddressLength : 0) +
			       (userDataLength >= 0 ? 1 + userDataLength : 0));
		case gsm_mt_ack_ms_to_net:
			return(2);
		case gsm_mt_ack_net_to_ms:
			return(2 + 
			       1 +
			       (userDataLength >= 0 ? 1 + userDataLength : 0));
		case gsm_mt_na:
			break;
		}
		return(0);
	}
	unsigned int getOffsetToUserData() {
		switch(type) {
		case gsm_mt_data_ms_to_net:
		case gsm_mt_data_net_to_ms:
			return(2 + 
			       1 + originatorAddressLength +
			       1 + destinationAddressLength +
			       1);
		case gsm_mt_ack_ms_to_net:
			return(0);
		case gsm_mt_ack_net_to_ms:
			return(4);
		case gsm_mt_na:
			break;
		}
		return(0);
	}
	bool load(char *message, unsigned int messageLength) {
		if(!messageLength) {
			return(false);
		}
		if(isDataMStoNET(message)) {
			type = gsm_mt_data_ms_to_net;
		} else if(isDataNETtoMS(message)) {
			type = gsm_mt_data_net_to_ms;
		} else if(isAckMStoNET(message)) {
			type = sGsmMessage::gsm_mt_ack_ms_to_net;
		} else if(isAckNETtoMS(message)) {
			type = sGsmMessage::gsm_mt_ack_net_to_ms;
		} else {
			return(false);
		}
		switch(type) {
		case gsm_mt_data_ms_to_net:
		case gsm_mt_data_net_to_ms:
			for(int pass = 0; pass < 3; pass++) {
				if(messageLength > getLength()) {
					int value = message[getLength()];
					switch(pass) {
					case 0: originatorAddressLength = value; break;
					case 1: destinationAddressLength = value; break;
					case 2: userDataLength = value; break;
					}
				} else {
					break;
				}
			}
			break;
		case gsm_mt_ack_ms_to_net:
			break;
		case gsm_mt_ack_net_to_ms:
			if(messageLength > getLength()) {
				userDataLength = message[getLength()];
			}
			break;
		case gsm_mt_na:
			break;
		}
		return(messageLength == getLength());
	}
	bool isDataMStoNET(char *message) {
		return(message[0] == 0);
	}
	bool isDataNETtoMS(char *message) {
		return(message[0] == 1);
	}
	bool isAckMStoNET(char *message) {
		return(message[0] == 2);
	}
	bool isAckNETtoMS(char *message) {
		return(message[0] == 3);
	}
	eGsmMessageType type;
	int originatorAddressLength;
	int destinationAddressLength;
	int userDataLength;
};

struct sGsmMessageData {
	enum eGsmMessageDataType {
		gsm_mt_data_type_na,
		gsm_mt_data_type_deliver,
		gsm_mt_data_type_submit
	};
	sGsmMessageData() {
		type = gsm_mt_data_type_na;
		addressLength = -1;
		codingIndication = -1;
		userDataLength = -1;
	}
	unsigned int getLength() {
		return((type == gsm_mt_data_type_deliver ? 1 : 2) + 
		       (addressLength >= 0 ? 2 + getAddressLength() + 1 : 0) + 
		       (codingIndication >= 0 ? (type == gsm_mt_data_type_deliver ? 8 : 1) : 0) + 
		       (userDataLength >= 0 ? 1 + getUserDataEncodeLength() : 0));
	}
	unsigned int getOffsetToAddress() {
		return((type == gsm_mt_data_type_deliver ? 1 : 2) + 
		       2);
	}
	unsigned int getOffsetToUserData() {
		return((type == gsm_mt_data_type_deliver ? 1 : 2) + 
		       2 + getAddressLength() + 1 + 
		       (type == gsm_mt_data_type_deliver ? 8 : 1) + 
		       1);
	}
	unsigned int getAddressLength() {
		return(addressLength / 2 + addressLength % 2);
	}
	unsigned int getUserDataEncodeLength() {
		switch(codingIndication) {
		case 0: 
			return(conv7bit::encode_length(userDataLength));
		}
		return(-1);
	}
	bool load(char *data, unsigned int dataLength) {
		if(!dataLength) {
			return(-1);
		}
		if(isDeliver(data)) {
			type = gsm_mt_data_type_deliver;
		} else if(isSubmit(data)) {
			type = gsm_mt_data_type_submit;
		} else {
			return(false);
		}
		for(int pass = 0; pass < 3; pass++) {
			if(dataLength > getLength()) {
				int value = data[getLength()];
				switch(pass) {
				case 0: addressLength = value; break;
				case 1: codingIndication = value; break;
				case 2: userDataLength = value; break;
				}
			} else {
				break;
			}
		}
		return(dataLength == getLength());
	}
	string getAddress(char *data) {
		string address;
		char *addressData = data + getOffsetToAddress();
		for(int i = 0; i < addressLength; i++) {
			int addressNumber = (i % 2 ? (addressData[i / 2] >> 4) : addressData[i / 2]) & 0xF;
			address += '0' + addressNumber;
		}
		return(address);
	}
	string getUserData(char *data) {
		if(userDataLength) {
			switch(codingIndication) {
			case 0: 
				return(getUserData_7bit(data));
			}
		}
		return("");
	}
	void maskUserData(char *data) {
		if(userDataLength) {
			switch(codingIndication) {
			case 0: 
				return(maskUserData_7bit(data));
			}
		}
	}
	string getUserData_7bit(char *data) {
		unsigned char *userDataSrc = (unsigned char*)data + getOffsetToUserData();
		unsigned int userDataDecodeLength;
		unsigned char *userDataDecode = conv7bit::decode(userDataSrc, conv7bit::encode_length(userDataLength), userDataDecodeLength);
		if(userDataDecode) {
			string userDataDecodeString = string((char*)userDataDecode, userDataDecodeLength);
			delete [] userDataDecode;
			return(userDataDecodeString);
		} else {
			return("");
		}
	}
	void maskUserData_7bit(char *data) {
		unsigned char *userDataSrc = (unsigned char*)data + getOffsetToUserData();
		string maskData;
		for(int i = 0; i < userDataLength; i++) {
			maskData += 'x';
		}
		unsigned int userDataEncodeLength;
		unsigned char *userDataEncode = conv7bit::encode((unsigned char*)maskData.c_str(), maskData.length(), userDataEncodeLength);
		if(userDataEncode) {
			memcpy(userDataSrc, userDataEncode, userDataEncodeLength);
			delete [] userDataEncode;
		}
	}
	bool isDeliver(char *data) {
		return((data[0] & 0x3) == 0);
	}
	bool isSubmit(char *data) {
		return((data[0] & 0x3) == 1);
	}
	eGsmMessageDataType type;
	int addressLength;
	int codingIndication;
	int userDataLength;
};

struct sGsmMessageAck {
	sGsmMessageAck() {
		year = -1;
		month = -1;
		day = -1;
		hour = -1;
		minute = -1;
		second = -1;
		timezone = -1;
	}
	bool load(char *data, unsigned int dataLength) {
		if(dataLength != 9) {
			return(false);
		}
		for(int pass = 0; pass < 7; pass++) {
			int value = getValue(data[2 + pass]);
			switch(pass) {
			case 0: year = value; break;
			case 1: month = value; break;
			case 2: day = value; break;
			case 3: hour = value; break;
			case 4: minute = value; break;
			case 5: second = value; break;
			case 6: timezone = value; break;
			}
		}
		return(checkValues());
	}
	bool checkValues() {
		return(year >=0 && year < 99 &&
		       month >= 1 && month <= 12 &&
		       day >= 1 && month <= 31 &&
		       hour >= 0 && month <= 23 &&
		       minute >= 0 && month <= 59 &&
		       second >= 0 && second <= 59 &&
		       timezone >= 0);
	}
	unsigned char getValue(unsigned char value) {
		return((value & 0xF) * 10 + ((value & 0xF0) >> 4));
	}
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int timezone;
};

int parse_packet__message_content(char *message, unsigned int messageLength,
				  char **rsltMessage, string *rsltDestNumber, string *rsltSrcNumber,
				  bool maskMessage) {
	int rslt = 0;
	if(rsltMessage) {
		*rsltMessage = NULL;
	}
	if(messageLength) {
		sGsmMessage gsmMessage;
		if(gsmMessage.load(message, messageLength)) {
			char *userData = message + gsmMessage.getOffsetToUserData();
			switch(gsmMessage.type) {
			case sGsmMessage::gsm_mt_data_net_to_ms:
			case sGsmMessage::gsm_mt_data_ms_to_net:{
				sGsmMessageData gsmMessageData;
				if(gsmMessageData.load(userData, gsmMessage.userDataLength)) {
					if(gsmMessageData.addressLength) {
						if(rsltDestNumber && gsmMessageData.type == sGsmMessageData::gsm_mt_data_type_submit) {
							*rsltDestNumber = gsmMessageData.getAddress(userData);
						} else if(rsltSrcNumber && gsmMessageData.type == sGsmMessageData::gsm_mt_data_type_deliver) {
							*rsltSrcNumber = gsmMessageData.getAddress(userData);
						}
					}
					if(rsltMessage) {
						string rslt_message = gsmMessageData.getUserData(userData);
						if(rslt_message.length()) {
							*rsltMessage = new FILE_LINE char[rslt_message.length() + 1];
							memcpy(*rsltMessage, rslt_message.c_str(), rslt_message.length());
							(*rsltMessage)[rslt_message.length()] = '\0';
							rslt = 1;
						}
					}
					if(maskMessage) {
						gsmMessageData.maskUserData(userData);
					}
				}
				}
				break;
			case sGsmMessage::gsm_mt_ack_net_to_ms: {
				sGsmMessageAck sGsmMessageAck;
				if(sGsmMessageAck.load(userData, gsmMessage.userDataLength)) {
					if(rsltMessage) {
						char rslt_message_buff[100];
						snprintf(rslt_message_buff, 100, 
							 "ACK 20%02i-%02i-%02i %02i:%02i:%02i (timezone code %i)",
							 sGsmMessageAck.year,
							 sGsmMessageAck.month,
							 sGsmMessageAck.day,
							 sGsmMessageAck.hour,
							 sGsmMessageAck.minute,
							 sGsmMessageAck.second,
							 sGsmMessageAck.timezone);
						*rsltMessage = new FILE_LINE char[strlen(rslt_message_buff) + 1];
						strcpy(*rsltMessage, rslt_message_buff);
						rslt = 1;
					}
				}
				}
				break;
			case sGsmMessage::gsm_mt_ack_ms_to_net: {
				if(rsltMessage) {
					char rslt_message_buff[100];
					snprintf(rslt_message_buff, 100, 
						 "ACK");
					*rsltMessage = new FILE_LINE char[strlen(rslt_message_buff) + 1];
					strcpy(*rsltMessage, rslt_message_buff);
					rslt = 1;
				}
				}
				break;
			case sGsmMessage::gsm_mt_na:
				break;
			}
		} else {
			if(rsltMessage) {
				*rsltMessage = new FILE_LINE char[messageLength + 1];
				memcpy(*rsltMessage, message, messageLength);
				(*rsltMessage)[messageLength] = '\0';
			}
			if(maskMessage) {
				memset(message, 'x', messageLength);
			}
			rslt = 1;
		}
	}
	return(rslt);
}

inline
Call *process_packet__rtp(ProcessRtpPacket::rtp_call_info *call_info,size_t call_info_length, packet_s *packetS,
			  int *voippacket, int *was_rtp, bool find_by_dest, int preSyncRtp) {
	++counter_rtp_packets;
	Call *call;
	bool iscaller;
	bool is_rtcp;
	s_sdp_flags sdp_flags;
	Call *rsltCall = NULL;
	size_t call_info_index;
	for(call_info_index = 0; call_info_index < call_info_length; call_info_index++) {
		call = call_info[call_info_index].call;
		iscaller = call_info[call_info_index].iscaller;
		sdp_flags = call_info[call_info_index].sdp_flags;
		is_rtcp = call_info[call_info_index].is_rtcp || (sdp_flags.rtcp_mux && packetS->datalen > 1 && (u_char)packetS->data[1] == 0xC8);
		
		if(sverb.process_rtp) {
			++process_rtp_counter;
			cout << "RTP - process_packet -"
			     << (find_by_dest ? " src: " : " SRC: ") << inet_ntostring(htonl(packetS->saddr)) << " : " << packetS->source
			     << (find_by_dest ? " DST: " : " dst: ") << inet_ntostring(htonl(packetS->daddr)) << " : " << packetS->dest
			     << " iscaller: " << (iscaller ? "caller" : "called") 
			     << " find_by_dest: " << find_by_dest
			     << " counter: " << process_rtp_counter
			     << endl;
		}
		
		if(!find_by_dest) {
			iscaller = !iscaller;
		}

		if(pcap_drop_flag) {
			call->pcap_drop = pcap_drop_flag;
		}

		if(!is_rtcp && !sdp_flags.is_fax &&
		   (packetS->datalen < RTP_FIXED_HEADERLEN ||
		    packetS->header.caplen <= (unsigned)(packetS->datalen - RTP_FIXED_HEADERLEN))) {
			rsltCall = call;
			break;
		}

		if(voippacket) {
			*voippacket = 1;
		}

		// we have packet, extend pending destroy requests
		call->shift_destroy_call_at(&packetS->header);

		int can_thread = !sverb.disable_threads_rtp;

		if(sdp_flags.is_fax) {
			call->seenudptl = 1;
		}
		
		if(is_rtcp) {
			if(rtp_threaded && can_thread) {
				add_to_rtp_thread_queue(call, packetS,
							iscaller, is_rtcp, enable_save_rtcp(call), preSyncRtp);
				call_info[call_info_index].use_sync = true;
			} else {
				call->read_rtcp(packetS, iscaller, enable_save_rtcp(call));
			}
			rsltCall = call;
			break;
		}

		if(was_rtp) {
			*was_rtp = 1;
		}
		if(rtp_threaded && can_thread) {
			add_to_rtp_thread_queue(call, packetS, 
						iscaller, is_rtcp, enable_save_rtp(call), preSyncRtp);
			call_info[call_info_index].use_sync = true;
		} else {
			call->read_rtp(packetS, iscaller, enable_save_rtp(call), 
				       packetS->block_store && packetS->block_store->ifname[0] ? packetS->block_store->ifname : NULL);
			call->set_last_packet_time(packetS->header.ts.tv_sec);
		}
	}
	if(preSyncRtp) {
		for(call_info_index = 0; call_info_index < call_info_length; call_info_index++) {
			if(!call_info[call_info_index].use_sync) {
				#if SYNC_CALL_RTP
				__sync_sub_and_fetch(&call_info[call_info_index].call->rtppacketsinqueue, 1);
				#else
				++call_info[call_info_index].call->rtppacketsinqueue_m;
				#endif
			}
		}
	}
	return(rsltCall);
}

Call *process_packet__rtp_nosip(unsigned int saddr, int source, unsigned int daddr, int dest, 
				char *data, int datalen, int dataoffset,
				pcap_pkthdr *header, const u_char *packet, int istcp, struct iphdr2 *header_ip,
				pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
				pcap_t *handle) {
	++counter_rtp_packets;
	
	unsigned int flags = 0;
	set_global_flags(flags);
	ipfilter->add_call_flags(&flags, ntohl(saddr), ntohl(daddr));
	if(flags & FLAG_SKIPCDR) {
		if(verbosity > 1)
			syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
		return NULL;
	}
	
	// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
	char s[256];
	RTP rtp(-1);
	int rtpmap[MAX_RTPMAP];
	memset(rtpmap, 0, sizeof(int) * MAX_RTPMAP);

	rtp.read((unsigned char*)data, datalen, header, saddr, daddr, source, dest, 0, sensor_id);

	if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
		return NULL;
	}
	snprintf(s, 256, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

	//printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

	Call *call = calltable->add(s, strlen(s), header->ts.tv_sec, saddr, source, handle, dlt, sensor_id);
	call->chantype = CHAN_SIP;
	call->set_first_packet_time(header->ts.tv_sec, header->ts.tv_usec);
	call->sipcallerip[0] = saddr;
	call->sipcalledip[0] = daddr;
	call->sipcallerport = source;
	call->sipcalledport = dest;
	call->type = INVITE;
	call->flags = flags;
	strncpy(call->fbasename, s, MAX_FNAME - 1);
	call->seeninvite = true;
	strcpy(call->callername, "RTP");
	strcpy(call->caller, "RTP");
	strcpy(call->called, "RTP");

#ifdef DEBUG_INVITE
	syslog(LOG_NOTICE, "New RTP call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s]\n", call->sipcallerip, call->sipcalledip, call->caller, call->called);
#endif

	// opening dump file
	if(enable_save_any(call)) {
		mkdir_r(call->dirname().c_str(), 0777);
	}
	if(enable_save_packet(call)) {
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

	call->add_ip_port_hash(saddr, daddr, dest, NULL, s, strlen(s), 1, rtpmap, s_sdp_flags(), 0);
	call->add_ip_port_hash(saddr, saddr, source, NULL, s, strlen(s), 0, rtpmap, s_sdp_flags(), 0);
	
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
		       handle, nids_last_pcap_header, nids_last_pcap_data, NULL,
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
	while (!is_terminating()) {
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
	if(verbosity > 2) {
		syslog(LOG_NOTICE, "DLT: %i", global_pcap_dlink);
	}

	init_hash();

	pcap_dumper_t *tmppcap = NULL;
	char pname[1024];

	if(opt_pcapdump) {
		sprintf(pname, "/var/spool/voipmonitor/voipmonitordump-%u.pcap", (unsigned int)time(NULL));
		tmppcap = pcap_dump_open(handle, pname);
	}

	while (!is_terminating()) {
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

		if(opt_mirrorall || (opt_mirrorip && (sipportmatrix[htons(ppd.header_udp->source)] || sipportmatrix[htons(ppd.header_udp->dest)]))) {
			mirrorip->send((char *)ppd.header_ip, (int)(header->caplen - ((unsigned long) ppd.header_ip - (unsigned long) packet)));
		}
		int voippacket = 0;
		if(!opt_mirroronly) {
			process_packet(false, packet_counter,
				       ppd.header_ip->saddr, htons(ppd.header_udp->source), ppd.header_ip->daddr, htons(ppd.header_udp->dest), 
				       ppd.data, ppd.datalen, ppd.data - (char*)packet, 
				       handle, header, packet, NULL,
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
 
	if(!sip_method ||
	   (!opt_read_from_file && descr && strstr(descr, "we are not interested"))) {
		return;
	}
	
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
	const char *sip_method_str = sip_request_int_to_name(sip_method, true);
	if(sip_method_str)
		outStr << sip_method_str;
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


void process_packet__push_batch() {
	u_long timeS = getTimeS();
	if(timeS - process_packet__last_cleanup > 10) {
		process_packet__cleanup(NULL, timeS);
	}
	if(processRtpPacketHash) {
		processRtpPacketHash->push_batch();
	}
}


void TcpReassemblySip::processPacket(
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id,
		bool issip) {
	if(!datalen) {
		return;
	}
 
	/*
	if(!((inet_ntostring(htonl(saddr)) == "31.47.138.44" &&
	      inet_ntostring(htonl(daddr)) == "81.88.86.11") ||
	     (inet_ntostring(htonl(daddr)) == "31.47.138.44" &&
	      inet_ntostring(htonl(saddr)) == "81.88.86.11"))) {
		 return;
	}
	*/
 
	tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + sizeof(*header_ip));
	u_int32_t seq = htonl(header_tcp->seq);
	u_int32_t ack_seq = htonl(header_tcp->ack_seq);
	tcp_stream_id rev_id(daddr, dest, saddr, source);
	map<tcp_stream_id, tcp_stream>::iterator rev_it = tcp_streams.find(rev_id);
	if(rev_it != tcp_streams.end()) {
		if(rev_it->second.packets) {
			if(isCompleteStream(&rev_it->second)) {
				if(sverb.reassembly_sip) {
					cout << " + call complete (reverse stream)" << endl;
				}
				complete(&rev_it->second, rev_id);
			} else {
				if(sverb.reassembly_sip) {
					cout << " + clean (reverse stream)" << endl;
				}
				cleanStream(&rev_it->second, true);
			}
		}
		if(rev_it->second.last_seq || rev_it->second.last_ack_seq) {
			if(sverb.reassembly_sip) {
				cout << " - reset last seq & ack (reverse stream)" << endl;
			}
			rev_it->second.last_seq = 0;
			rev_it->second.last_ack_seq = 0;
		}
	}
	tcp_stream_id id(saddr, source, daddr, dest);
	map<tcp_stream_id, tcp_stream>::iterator it = tcp_streams.find(id);
	if(it != tcp_streams.end()) {
		if(it->second.packets && it->second.last_ack_seq &&
		   it->second.last_ack_seq != ack_seq) {
			if(isCompleteStream(&it->second)) {
				if(sverb.reassembly_sip) {
					cout << " + call complete (diff ack)" << endl;
				}
				complete(&it->second, id);
			} else {
				if(sverb.reassembly_sip) {
					cout << " + clean (diff ack)" << endl;
				}
				cleanStream(&it->second, true);
			}
		}
		if(it->second.packets && issip) {
			bool existsSeqAck = false;
			for(tcp_stream_packet *packet = it->second.packets; packet; packet = packet->next) {
				if(packet->seq == seq &&
				   packet->ack_seq == ack_seq) {
					existsSeqAck = true;
				}
			}
			if(!existsSeqAck) {
				if(isCompleteStream(&it->second)) {
					if(sverb.reassembly_sip) {
						cout << " + call complete (next packet issip)" << endl;
					}
					complete(&it->second, id);
				} else {
					if(sverb.reassembly_sip) {
						cout << " + clean (next packet issip)" << endl;
					}
					cleanStream(&it->second, true);
				}
			}
		}
		if((it->second.packets || issip) &&
		   addPacket(&it->second,
			     packet_number,
			     saddr, source, daddr, dest, data, datalen, dataoffset,
			     handle, header, packet, header_ip,
			     dlt, sensor_id)) {
			if(isCompleteStream(&it->second)) {
				if(sverb.reassembly_sip) {
					cout << " + call complete (check complete after add 1)" << endl;
				}
				complete(&it->second, id);
			} else if(it->second.complete_data && it->second.complete_data->size() > 65535) {
				cleanStream(&it->second, true);
			}
		}
	} else {
		if(issip) {
			tcp_stream *stream = &tcp_streams[id];
			if(addPacket(stream,
				     packet_number,
				     saddr, source, daddr, dest, data, datalen, dataoffset,
				     handle, header, packet, header_ip,
				     dlt, sensor_id)) {
				if(isCompleteStream(stream)) {
					if(sverb.reassembly_sip) {
						cout << " + call complete (check complete after add 2)" << endl;
					}
					complete(stream, id);
				}
			}
		}
	}
}

void TcpReassemblySip::clean(time_t ts) {
	map<tcp_stream_id, tcp_stream>::iterator it;
	for(it = tcp_streams.begin(); it != tcp_streams.end();) {
		if(!ts || (ts - it->second.last_ts) > (10 * 60)) {
			cleanStream(&it->second, true);
			tcp_streams.erase(it++);
		} else {
			++it;
		}
	}
}

bool TcpReassemblySip::addPacket(
		tcp_stream *stream,
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id) {
	if(!datalen) {
		return(false);
	}
	if(sverb.reassembly_sip) {
		cout << sqlDateTimeString(header.ts.tv_sec) << " "
		     << setw(6) << setfill('0') << header.ts.tv_usec << setfill(' ') << " / "
		     << string(data, MIN(string(data, datalen).find("\r"), MIN(datalen, 100))) << endl;
	}
	tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + sizeof(*header_ip));
	u_int32_t seq = htonl(header_tcp->seq);
	u_int32_t ack_seq = htonl(header_tcp->ack_seq);
	if(stream->packets) {
		for(tcp_stream_packet *packet = stream->packets; packet; packet = packet->next) {
			if(packet->seq == seq &&
			   packet->ack_seq == ack_seq) {
				if(sverb.reassembly_sip) {
					cout << " - skip exists seq & ack" << endl;
				}
				return(false);
			}
		}
	} else {
		if(seq == stream->last_seq && 
		   ack_seq == stream->last_ack_seq) {
			if(sverb.reassembly_sip) {
				cout << " - skip previous completed seq & ack" << endl;
			}
			return(false);
		}
	}
	
	tcp_stream_packet *lastPacket = stream->packets ? getLastStreamPacket(stream) : NULL;
	
	tcp_stream_packet *newPacket = new FILE_LINE tcp_stream_packet;
	newPacket->next = NULL;
	newPacket->ts = header.ts.tv_sec;

	newPacket->lastpsh = header_tcp->psh;
	newPacket->seq = seq;
	newPacket->ack_seq = ack_seq;
	newPacket->next_seq = newPacket->seq + (unsigned long int)header.caplen - ((unsigned long int)header_tcp - (unsigned long int)packet + header_tcp->doff * 4);

	// append new created node at the end of list of TCP packets within this TCP connection
	if(lastPacket) {
		lastPacket->next = newPacket;
	}

	//copy data 
	newPacket->data = new FILE_LINE char[datalen];
	memcpy(newPacket->data, data, datalen);
	newPacket->datalen = datalen;

	//copy header
	newPacket->header = header;

	//copy packet
	newPacket->packet = new FILE_LINE u_char[header.caplen];
	memcpy(newPacket->packet, packet, header.caplen);
	
	newPacket->header_ip = (iphdr2*)(newPacket->packet + ((u_char*)header_ip - packet));

	newPacket->packet_number = packet_number;
	newPacket->saddr = saddr;
	newPacket->source = source;
	newPacket->daddr = daddr;
	newPacket->dest = dest;
	newPacket->dataoffset = dataoffset;
	newPacket->handle = handle;
	newPacket->dlt = dlt;
	newPacket->sensor_id = sensor_id;
	
	if(stream->packets) {
		if(stream->complete_data) {
			stream->complete_data->add(newPacket->data, newPacket->datalen);
		} else {
			stream->complete_data =  new SimpleBuffer(10000);
			stream->complete_data->add(stream->packets->data, stream->packets->datalen);
			stream->complete_data->add(newPacket->data, newPacket->datalen);
		}
	} else {
		stream->packets = newPacket;
	}
	stream->last_seq = seq;
	stream->last_ack_seq = ack_seq;
	stream->last_ts = header.ts.tv_sec;
	
	return(true);
}

void TcpReassemblySip::complete(tcp_stream *stream, tcp_stream_id id) {
	if(!stream->packets) {
		return;
	}
	tcp_stream_packet *firstPacket = stream->packets;
	pcap_pkthdr header = firstPacket->header;
	iphdr2 *header_ip;
	int newdata_len;
	u_char *newdata;
	u_char *newpacket;
	bool allocNewpacket = false;
	bool multiplePackets = stream->complete_data != NULL;
	if(multiplePackets) {
		newdata_len = stream->complete_data->size();
		unsigned long diffLen = newdata_len - firstPacket->datalen;
		newdata = stream->complete_data->data();
		int len = 0;
		for(tcp_stream_packet *packet = firstPacket; packet; packet = packet->next) {
			memcpy(newdata + len, packet->data, packet->datalen);
			len += packet->datalen;
		}
		header.caplen += diffLen;
		header.len += diffLen;
		newpacket = new FILE_LINE u_char[header.caplen];
		allocNewpacket = true;
		memcpy(newpacket, firstPacket->packet, firstPacket->header.caplen - firstPacket->datalen);
		memcpy(newpacket + (firstPacket->header.caplen - firstPacket->datalen), newdata, newdata_len);
		newdata = newpacket + (firstPacket->header.caplen - firstPacket->datalen);
		header_ip = (iphdr2*)(newpacket + ((u_char*)firstPacket->header_ip - firstPacket->packet));
		header_ip->tot_len = htons(ntohs(header_ip->tot_len) + diffLen);
	} else {
		newdata_len = firstPacket->datalen;
		newpacket = firstPacket->packet;
		newdata = firstPacket->packet + firstPacket->dataoffset;
		header_ip = firstPacket->header_ip;
	}
	if(sverb.reassembly_sip || sverb.reassembly_sip_output) {
		if(sverb.reassembly_sip) {
			cout << " * COMPLETE ";
		}
		cout << sqlDateTimeString(firstPacket->header.ts.tv_sec) << " "
		     << setw(6) << setfill('0') << firstPacket->header.ts.tv_usec << setfill(' ') << " / "
		     << setw(15) << inet_ntostring(htonl(firstPacket->saddr)) << " : "
		     << setw(5) << firstPacket->source << " / "
		     << setw(15) << inet_ntostring(htonl(firstPacket->daddr)) << " : "
		     << setw(5) << firstPacket->dest << " / "
		     << setw(9) << stream->last_ack_seq << " / "
		     << string((char*)newdata, MIN(string((char*)newdata, newdata_len).find("\r"), MIN(newdata_len, 100))) << endl;
	}
	bool deletePackets = true;
	if(PreProcessPacket::isEnableSip()) {
		preProcessPacket[1]->push_packet_1(false, firstPacket->packet_number,
						   firstPacket->saddr, firstPacket->source, firstPacket->daddr, firstPacket->dest, 
						   (char*)newdata, newdata_len, firstPacket->dataoffset,
						   firstPacket->handle, &header, newpacket, true,
						   2, header_ip, 0,
						   NULL, 0, firstPacket->dlt, firstPacket->sensor_id,
						   true);
		if(!multiplePackets) {
			deletePackets = false;
		}
	} else {
		int tmp_was_rtp;
		int tmp_voippacket;
		process_packet(false, firstPacket->packet_number,
			       firstPacket->saddr, firstPacket->source, firstPacket->daddr, firstPacket->dest, 
			       (char*)newdata, newdata_len, firstPacket->dataoffset,
			       firstPacket->handle, &header, newpacket, NULL,
			       2, &tmp_was_rtp, header_ip, &tmp_voippacket, 0,
			       NULL, 0, firstPacket->dlt, firstPacket->sensor_id, 
			       false);
		if(allocNewpacket) {
			delete [] newpacket;
		}
	}
	cleanStream(stream, deletePackets);
}

void TcpReassemblySip::cleanStream(tcp_stream* stream, bool deletePackets) {
	if(stream->packets) {
		tcp_stream_packet *packet = stream->packets;
		while(packet) {
			delete [] packet->data;
			if(deletePackets) {
				delete [] packet->packet;
			}
			tcp_stream_packet *next = packet->next;
			delete packet;
			packet = next;
		}
		stream->packets = NULL;
	}
	if(stream->complete_data) {
		delete stream->complete_data;
		stream->complete_data = NULL;
	}
}


inline void *_PreProcessPacket_outThreadFunction(void *arg) {
	return(((PreProcessPacket*)arg)->outThreadFunction());
}

PreProcessPacket::PreProcessPacket(eTypePreProcessThread typePreProcessThread) {
	this->typePreProcessThread = typePreProcessThread;
	this->qring_batch_item_length = min(opt_preprocess_packets_qring_length / 10, 1000u);
	this->qring_length = opt_preprocess_packets_qring_length / this->qring_batch_item_length;
	this->readit = 0;
	this->writeit = 0;
	this->qring = new FILE_LINE batch_packet_parse_s*[this->qring_length];
	for(unsigned int i = 0; i < this->qring_length; i++) {
		this->qring[i] = new FILE_LINE batch_packet_parse_s(opt_preprocess_packets_qring_length / 10);
		this->qring[i]->used = 0;
		if(this->typePreProcessThread == ppt_sip) {
			this->qring[i]->allocParse();
			this->qring[i]->setStdParse();
		}
	}
	this->qring_push_index = 0;
	this->qring_push_index_count = 0;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->outThreadId = 0;
	this->_sync_push = 0;
	this->term_preProcess = false;
	pthread_create(&this->out_thread_handle, NULL, _PreProcessPacket_outThreadFunction, this);
}

PreProcessPacket::~PreProcessPacket() {
	terminate();
	for(unsigned int i = 0; i < this->qring_length; i++) {
		if(this->typePreProcessThread == ppt_sip) {
			this->qring[i]->deleteParse();
		}
		delete this->qring[i];
	}
	delete [] this->qring;
}

void *PreProcessPacket::outThreadFunction() {
	if(this->typePreProcessThread == ppt_extend) {
		 pthread_t thId = pthread_self();
		 pthread_attr_t thAttr;
		 int policy = 0;
		 int max_prio_for_policy = 0;
		 pthread_attr_init(&thAttr);
		 pthread_attr_getschedpolicy(&thAttr, &policy);
		 max_prio_for_policy = sched_get_priority_max(policy);
		 pthread_setschedprio(thId, max_prio_for_policy);
		 pthread_attr_destroy(&thAttr);
	}
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start PreProcessPacket out thread %i", this->outThreadId);
	unsigned usleepCounter = 0;
	u_int64_t usleepSumTimeForPushBatch = 0;
	while(!this->term_preProcess) {
		if(this->qring[this->readit]->used == 1) {
			batch_packet_parse_s *_batch_parse_packet = this->qring[this->readit];
			if(this->typePreProcessThread == ppt_sip && PreProcessPacket::isEnableExtend()) {
				_batch_parse_packet->used = -1;
			}
			for(unsigned batch_index = 0; batch_index < _batch_parse_packet->count; batch_index++) {
				packet_parse_s *_parse_packet = _batch_parse_packet->batch[batch_index];
				packet_s *_packet = &_parse_packet->packet;
				bool do_process_packet =  false;
				switch(this->typePreProcessThread) {
				case ppt_detach:
					if(PreProcessPacket::isEnableSip()) {
						preProcessPacket[1]->push_packet_2(_packet, NULL, 
										   false, _parse_packet->forceSip);
					} else {
						do_process_packet = true;
					}
					break;
				case ppt_sip:
					if(PreProcessPacket::isEnableExtend()) {
						preProcessPacket[2]->push_packet_2(NULL, _parse_packet, 
										   false, _parse_packet->forceSip, false,
										   batch_index == _batch_parse_packet->count - 1, _batch_parse_packet);
					} else {
						do_process_packet = true;
					}
					break;
				case ppt_extend:
					do_process_packet = true; 
					break;
				}
				if(do_process_packet) {
					int was_rtp = 0;
					int voippacket = 0;
					process_packet(_packet, this->typePreProcessThread == ppt_detach ? NULL : _parse_packet,
						       &was_rtp, &voippacket, _parse_packet->forceSip,
						       true, 0);
					if(_packet->block_store) {
						_packet->block_store->unlock_packet(_packet->block_store_index);
					}
					if(_parse_packet->packetDelete) {
						delete [] _packet->packet;
					}
				}
			}
			switch(this->typePreProcessThread) {
			case ppt_detach:
				_batch_parse_packet->count = 0;
				_batch_parse_packet->used = 0;
				break;
			case ppt_sip:
				if(!PreProcessPacket::isEnableExtend()) {
					_batch_parse_packet->count = 0;
					_batch_parse_packet->used = 0;
				}
				break;
			case ppt_extend:
				_batch_parse_packet->batchInPrevQueue->count = 0;
				_batch_parse_packet->batchInPrevQueue->used = 0;
				_batch_parse_packet->count = 0;
				_batch_parse_packet->used = 0;
				break;
			}
			if((this->readit + 1) == this->qring_length) {
				this->readit = 0;
			} else {
				this->readit++;
			}
			usleepCounter = 0;
			usleepSumTimeForPushBatch = 0;
		} else {
			if(usleepSumTimeForPushBatch > 500000ull) {
				bool use_process_packet = false;
				switch(this->typePreProcessThread) {
				case ppt_detach:
					if(PreProcessPacket::isEnableSip()) {
						preProcessPacket[1]->push_batch();
					} else {
						use_process_packet = true;
					}
					break;
				case ppt_sip:
					if(!PreProcessPacket::isEnableExtend()) {
						use_process_packet = true;
					}
					break;
				case ppt_extend:
					use_process_packet = true; 
					break;
				}
				if(use_process_packet) {
					process_packet__push_batch();
				}
				usleepSumTimeForPushBatch = 0;
			}
			unsigned usleepTime = opt_preprocess_packets_qring_usleep * 
					      (usleepCounter > 1000 ? 20 :
					       usleepCounter > 100 ? 5 : 1);
			usleep(usleepTime);
			++usleepCounter;
			usleepSumTimeForPushBatch += usleepTime;
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

bool PreProcessPacket::sipProcess_base(packet_parse_s *parse_packet) {
	parse_packet->_getCallID_reassembly = true;
	if(!this->sipProcess_getCallID(parse_packet)) {
		return(false);
	}
	if(!this->sipProcess_reassembly(parse_packet)) {
		return(false);
	}
	this->sipProcess_getSipMethod(parse_packet);
	this->sipProcess_getLastSipResponse(parse_packet);
	return(true);
}

bool PreProcessPacket::sipProcess_extend(packet_parse_s *parse_packet) {
	if(parse_packet->sip_method != REGISTER) {
		this->sipProcess_findCall(parse_packet);
		this->sipProcess_createCall(parse_packet);
	}
	return(true);
}

bool PreProcessPacket::sipProcess_getCallID(packet_parse_s *parse_packet) {
	packet_s *_packet = &parse_packet->packet;
	char *s;
	unsigned long l;
	s = gettag(_packet->data, parse_packet->sipDataLen, parse_packet->parse,
		   "\nCall-ID:", &l);
	if(l <= 0 || l > 1023) {
		// try also compact header
		s = gettag(_packet->data, parse_packet->sipDataLen, parse_packet->parse,
			   "\ni:", &l);
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
	parse_packet->sip_method = process_packet__parse_sip_method(_packet->data, parse_packet->sipDataLen, &parse_packet->sip_response);
	parse_packet->_getSipMethod = true;
}

void PreProcessPacket::sipProcess_getLastSipResponse(packet_parse_s *parse_packet) {
	char lastSIPresponse[1024];
	packet_s *_packet = &parse_packet->packet;
	parse_packet->lastSIPresponseNum = parse_packet__last_sip_response(_packet->data, parse_packet->sipDataLen, parse_packet->sip_method, parse_packet->sip_response,
									   lastSIPresponse, &parse_packet->call_cancel_lsr487);
	parse_packet->lastSIPresponse = lastSIPresponse;
	parse_packet->_getLastSipResponse = true;
}

void PreProcessPacket::sipProcess_findCall(packet_parse_s *parse_packet) {
	packet_s *_packet = &parse_packet->packet;
	int call_type = 0;
	parse_packet->call = calltable->find_by_call_id((char*)parse_packet->callid.c_str(), parse_packet->callid.length(), true, &call_type);
	if(parse_packet->call) {
		if(call_type == REGISTER) {
			parse_packet->call = NULL;
			return;
		}
		parse_packet->call->in_preprocess_queue_before_process_packet_at = parse_packet->packet.header.ts.tv_sec;
		parse_packet->call->handle_dscp(parse_packet->sip_method, _packet->header_ip, _packet->saddr, _packet->daddr, NULL, !IS_SIP_RESXXX(parse_packet->sip_method));
		if(pcap_drop_flag) {
			parse_packet->call->pcap_drop = pcap_drop_flag;
		}
		if(parse_packet->call_cancel_lsr487) {
			parse_packet->call->cancel_lsr487 = true;
		}
	} else if(opt_callidmerge_header[0] != '\0') {
		parse_packet->call = process_packet__merge(_packet, parse_packet->parse, (char*)parse_packet->callid.c_str(), &parse_packet->merged, NULL, true);
	}
	parse_packet->_findCall = true;
}

void PreProcessPacket::sipProcess_createCall(packet_parse_s *parse_packet) {
	if(parse_packet->_findCall && !parse_packet->call &&
	   (parse_packet->sip_method == INVITE || parse_packet->sip_method == MESSAGE)) {
		parse_packet->call_created = new_invite_register(&parse_packet->packet, parse_packet->parse,
								 parse_packet->sip_method, (char*)parse_packet->callid.c_str(), &parse_packet->detectUserAgent,
								 true);
		parse_packet->call_created->in_preprocess_queue_before_process_packet_at = parse_packet->packet.header.ts.tv_sec;
		parse_packet->_createCall = true;
	}
}

void PreProcessPacket::autoStartNextLevelPreProcessPacket() {
	if(!PreProcessPacket::isEnableDetach()) {
		PreProcessPacket *_preProcessPacket = new FILE_LINE PreProcessPacket(PreProcessPacket::ppt_detach);
		preProcessPacket[0] = _preProcessPacket;
	} else if(!PreProcessPacket::isEnableSip()) {
		PreProcessPacket *_preProcessPacket = new FILE_LINE PreProcessPacket(PreProcessPacket::ppt_sip);
		preProcessPacket[1] = _preProcessPacket;
	} else if(!PreProcessPacket::isEnableExtend()) {
		PreProcessPacket *_preProcessPacket = new FILE_LINE PreProcessPacket(PreProcessPacket::ppt_extend);
		preProcessPacket[2] = _preProcessPacket;
	}
}

inline void *_ProcessRtpPacket_outThreadFunction(void *arg) {
	return(((ProcessRtpPacket*)arg)->outThreadFunction());
}

inline void *_ProcessRtpPacket_nextThreadFunction(void *arg) {
	ProcessRtpPacket::arg_next_thread *_arg = (ProcessRtpPacket::arg_next_thread*)arg;
	void *rsltThread = _arg->processRtpPacket->nextThreadFunction(_arg->next_thread_id);
	delete _arg;
	return(rsltThread);
}

#define find_hash_only_in_next_threads (opt_process_rtp_packets_hash_next_thread_sem_sync == 1 && this->process_rtp_packets_hash_next_threads >= 1)

ProcessRtpPacket::ProcessRtpPacket(eType type, int indexThread) {
	this->type = type;
	this->indexThread = indexThread;
	this->qring_batch_item_length = min(opt_process_rtp_packets_qring_length / 5, 1000u);
	this->qring_length = opt_process_rtp_packets_qring_length / this->qring_batch_item_length;
	this->readit = 0;
	this->writeit = 0;
	this->qring = new FILE_LINE batch_packet_rtp_s*[this->qring_length];
	for(unsigned int i = 0; i < this->qring_length; i++) {
		this->qring[i] = new FILE_LINE batch_packet_rtp_s(this->qring_batch_item_length);
		this->qring[i]->used = 0;
	}
	this->qring_push_index = 0;
	this->qring_push_index_count = 0;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->outThreadId = 0;
	this->term_processRtp = false;
	for(int i = 0; i < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS; i++) {
		this->nextThreadId[i] = 0;
		this->next_thread_handle[i] = 0;
		this->hash_batch_thread_process[i] = 0;
		for(int j = 0; j < 2; j++) {
			sem_sync_next_thread[i][j].__align = 0;
		}
	}
	pthread_create(&this->out_thread_handle, NULL, _ProcessRtpPacket_outThreadFunction, this);
	this->process_rtp_packets_hash_next_threads = opt_process_rtp_packets_hash_next_thread;
	if(type == hash && this->process_rtp_packets_hash_next_threads) {
		for(int i = 0; i < this->process_rtp_packets_hash_next_threads; i++) {
			for(int j = 0; j < opt_process_rtp_packets_hash_next_thread_sem_sync; j++) {
				sem_init(&sem_sync_next_thread[i][j], 0, 0);
			}
			arg_next_thread *arg = new arg_next_thread;
			arg->processRtpPacket = this;
			arg->next_thread_id = i + 1;
			pthread_create(&this->next_thread_handle[i], NULL, _ProcessRtpPacket_nextThreadFunction, arg);
		}
	}
}

ProcessRtpPacket::~ProcessRtpPacket() {
	terminate();
	for(unsigned int i = 0; i < this->qring_length; i++) {
		delete this->qring[i];
	}
	delete [] this->qring;
}

void *ProcessRtpPacket::outThreadFunction() {
	if(this->type == hash) {
		 pthread_t thId = pthread_self();
		 pthread_attr_t thAttr;
		 int policy = 0;
		 int max_prio_for_policy = 0;
		 pthread_attr_init(&thAttr);
		 pthread_attr_getschedpolicy(&thAttr, &policy);
		 max_prio_for_policy = sched_get_priority_max(policy);
		 pthread_setschedprio(thId, max_prio_for_policy);
		 pthread_attr_destroy(&thAttr);
	}
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start ProcessRtpPacket %s out thread %i", this->type == hash ? "hash" : "distribute", this->outThreadId);
	unsigned usleepCounter = 0;
	u_int64_t usleepSumTimeForPushBatch = 0;
	while(!this->term_processRtp) {
		if(this->qring[this->readit]->used == 1) {
			batch_packet_rtp_s *_batch_rtp_packet = this->qring[this->readit];
			this->rtp_batch(_batch_rtp_packet);
			_batch_rtp_packet->count = 0;
			_batch_rtp_packet->used = 0;
			if((this->readit + 1) == this->qring_length) {
				this->readit = 0;
			} else {
				this->readit++;
			}
			usleepCounter = 0;
			usleepSumTimeForPushBatch = 0;
		} else {
			if(usleepSumTimeForPushBatch > 500000ull) {
				if(this->type == hash) {
					for(int i = 0; i < process_rtp_packets_distribute_threads_use; i++) {
						processRtpPacketDistribute[i]->push_batch();
					}
				}
				usleepSumTimeForPushBatch = 0;
			}
			unsigned usleepTime = opt_process_rtp_packets_qring_usleep * 
					      (usleepCounter > 1000 ? 20 :
					       usleepCounter > 100 ? 5 : 1);
			usleep(usleepTime);
			++usleepCounter;
			usleepSumTimeForPushBatch += usleepTime;
		}
	}
	return(NULL);
}

void *ProcessRtpPacket::nextThreadFunction(int next_thread_index_plus) {
	this->nextThreadId[next_thread_index_plus - 1] = get_unix_tid();
	syslog(LOG_NOTICE, "start ProcessRtpPacket %s next thread %i", this->type == hash ? "hash" : "distribute", this->nextThreadId[next_thread_index_plus - 1]);
	int usleepUseconds = 20;
	unsigned usleepCounter = 0;
	while(!this->term_processRtp) {
		if(sem_sync_next_thread[next_thread_index_plus - 1][0].__align) {
			sem_wait(&sem_sync_next_thread[next_thread_index_plus - 1][0]);
		}
		if(this->hash_batch_thread_process[next_thread_index_plus - 1]) {
			unsigned batch_index_start;
			unsigned batch_index_end;
			unsigned batch_index_skip;
			if(find_hash_only_in_next_threads) {
				batch_index_start = next_thread_index_plus - 1;
				batch_index_end = this->hash_batch_thread_process[next_thread_index_plus - 1]->count;
				batch_index_skip = this->process_rtp_packets_hash_next_threads_use_for_batch;
			} else {
				batch_index_start = this->hash_batch_thread_process[next_thread_index_plus - 1]->count / (this->process_rtp_packets_hash_next_threads_use_for_batch + 1) * next_thread_index_plus;
				batch_index_end = next_thread_index_plus == this->process_rtp_packets_hash_next_threads_use_for_batch ? 
							this->hash_batch_thread_process[next_thread_index_plus - 1]->count : 
							this->hash_batch_thread_process[next_thread_index_plus - 1]->count / (this->process_rtp_packets_hash_next_threads_use_for_batch + 1) * (next_thread_index_plus + 1);
				batch_index_skip = 1;
			}
			for(unsigned batch_index = batch_index_start; 
			    batch_index < batch_index_end; 
			    batch_index += batch_index_skip) {
				packet_rtp_s *_packet = this->hash_batch_thread_process[next_thread_index_plus - 1]->batch[batch_index];
				this->find_hash(_packet, false);
			}
			this->hash_batch_thread_process[next_thread_index_plus - 1] = 0;
			usleepCounter = 0;
			if(sem_sync_next_thread[next_thread_index_plus - 1][1].__align) {
				sem_post(&sem_sync_next_thread[next_thread_index_plus - 1][1]);
			}
		} else {
			usleep(usleepUseconds * 
			       (usleepCounter > 1000 ? 20 :
				usleepCounter > 100 ? 5 : 1));
			++usleepCounter;
		}
	}
	return(NULL);
}

void ProcessRtpPacket::rtp_batch(batch_packet_rtp_s *_batch_rtp_packet) {
	if(type == hash) {
		this->process_rtp_packets_hash_next_threads_use_for_batch = this->process_rtp_packets_hash_next_threads;
		int _process_rtp_packets_hash_next_threads_use_for_batch = this->process_rtp_packets_hash_next_threads_use_for_batch;
		int _process_rtp_packets_distribute_threads_use = process_rtp_packets_distribute_threads_use;
		unsigned batch_index_distribute = 0;
		if(find_hash_only_in_next_threads) {
			for(unsigned batch_index = 0; batch_index < _batch_rtp_packet->count; batch_index++) {
				_batch_rtp_packet->batch[batch_index]->hash_find_flag = 0;
			}
		}
		calltable->lock_calls_hash();
		if(this->next_thread_handle[0]) {
			for(int i = 0; i < _process_rtp_packets_hash_next_threads_use_for_batch; i++) {
				this->hash_batch_thread_process[i] = _batch_rtp_packet;
				if(sem_sync_next_thread[i][0].__align) {
					sem_post(&sem_sync_next_thread[i][0]);
				}
			}
			if(find_hash_only_in_next_threads) {
				while(this->hash_batch_thread_process[0] || this->hash_batch_thread_process[1] ||
				      (_process_rtp_packets_hash_next_threads_use_for_batch > 2 && this->isNextThreadsGt2Processing(_process_rtp_packets_hash_next_threads_use_for_batch))) {
					if(batch_index_distribute < _batch_rtp_packet->count &&
					   _batch_rtp_packet->batch[batch_index_distribute]->hash_find_flag) {
						packet_rtp_s *_packet = _batch_rtp_packet->batch[batch_index_distribute];
						ProcessRtpPacket *_processRtpPacket = processRtpPacketDistribute[1] ?
										       processRtpPacketDistribute[min(_packet->packet.source, _packet->packet.dest) / 2 % _process_rtp_packets_distribute_threads_use] :
										       processRtpPacketDistribute[0];
						_processRtpPacket->push_packet_rtp_2(_packet);
						++batch_index_distribute;
					} else {
						usleep(20);
					}
				}
			} else {
				for(unsigned batch_index = 0; 
				    batch_index < _batch_rtp_packet->count / (_process_rtp_packets_hash_next_threads_use_for_batch + 1); 
				    batch_index++) {
					packet_rtp_s *_packet = _batch_rtp_packet->batch[batch_index];
					this->find_hash(_packet, false);
				}
				for(int i = 0; i < _process_rtp_packets_hash_next_threads_use_for_batch; i++) {
					if(sem_sync_next_thread[i][1].__align) {
						sem_wait(&sem_sync_next_thread[i][1]);
					} else {
						while(this->hash_batch_thread_process[i]) { 
							usleep(20); 
						}
					}
				}
			}
		} else {
			for(unsigned batch_index = 0; batch_index < _batch_rtp_packet->count; batch_index++) {
				packet_rtp_s *_packet = _batch_rtp_packet->batch[batch_index];
				this->find_hash(_packet, false);
			}
		}
		calltable->unlock_calls_hash();
		for(;batch_index_distribute < _batch_rtp_packet->count; batch_index_distribute++) {
			packet_rtp_s *_packet = _batch_rtp_packet->batch[batch_index_distribute];
			ProcessRtpPacket *_processRtpPacket = processRtpPacketDistribute[1] ?
							       processRtpPacketDistribute[min(_packet->packet.source, _packet->packet.dest) / 2 % _process_rtp_packets_distribute_threads_use] :
							       processRtpPacketDistribute[0];
			_processRtpPacket->push_packet_rtp_2(_packet);
		}
	} else {
		for(unsigned batch_index = 0; batch_index < _batch_rtp_packet->count; batch_index++) {
			packet_rtp_s *_packet = _batch_rtp_packet->batch[batch_index];
			if(_packet->call_info_length < 0) {
				this->find_hash(_packet);
			}
			if(_packet->call_info_length) {
				process_packet__rtp(_packet->call_info, _packet->call_info_length, &_packet->packet, 
						    NULL, NULL, _packet->call_info_find_by_dest, indexThread + 1);
			} else {
				if(opt_rtpnosip) {
					process_packet__rtp_nosip(_packet->packet.saddr, _packet->packet.source, _packet->packet.daddr, _packet->packet.dest, 
								  _packet->packet.data, _packet->packet.datalen, _packet->packet.dataoffset,
								  &_packet->packet.header, _packet->packet.packet, _packet->packet.istcp, _packet->packet.header_ip,
								  _packet->packet.block_store, _packet->packet.block_store_index, _packet->packet.dlt, _packet->packet.sensor_id,
								  _packet->packet.handle);
				}
			}
			if(_packet->packet.block_store) {
				_packet->packet.block_store->unlock_packet(_packet->packet.block_store_index);
			}
		}
	}
}

void ProcessRtpPacket::find_hash(packet_rtp_s *_packet, bool lock) {
	_packet->call_info_length = 0;
	hash_node_call *calls = NULL;
	_packet->call_info_find_by_dest = false;
	if(lock) {
		calltable->lock_calls_hash();
	}
	if((calls = calltable->hashfind_by_ip_port(_packet->packet.daddr, _packet->packet.dest, _packet->hash_d, false))) {
		_packet->call_info_find_by_dest = true;
	} else {
		calls = calltable->hashfind_by_ip_port(_packet->packet.saddr, _packet->packet.source, _packet->hash_s, false);
	}
	_packet->call_info_length = 0;
	if(calls) {
		hash_node_call *node_call;
		for (node_call = (hash_node_call *)calls; node_call != NULL; node_call = node_call->next) {
			_packet->call_info[_packet->call_info_length].call = node_call->call;
			_packet->call_info[_packet->call_info_length].iscaller = node_call->iscaller;
			_packet->call_info[_packet->call_info_length].is_rtcp = node_call->is_rtcp;
			_packet->call_info[_packet->call_info_length].sdp_flags = node_call->sdp_flags;
			_packet->call_info[_packet->call_info_length].use_sync = false;
			#if SYNC_CALL_RTP
			__sync_add_and_fetch(&node_call->call->rtppacketsinqueue, 1);
			#else
			++node_call->call->rtppacketsinqueue_p;
			#endif
			++_packet->call_info_length;
		}
	}
	if(lock) {
		calltable->unlock_calls_hash();
	}
	if(find_hash_only_in_next_threads) {
		_packet->hash_find_flag = 1;
	}
}

void ProcessRtpPacket::preparePstatData(int nextThreadIndexPlus) {
	if(nextThreadIndexPlus ? this->nextThreadId[nextThreadIndexPlus - 1] : this->outThreadId) {
		if(this->threadPstatData[nextThreadIndexPlus][0].cpu_total_time) {
			this->threadPstatData[nextThreadIndexPlus][1] = this->threadPstatData[nextThreadIndexPlus][0];
		}
		pstat_get_data(nextThreadIndexPlus ? this->nextThreadId[nextThreadIndexPlus - 1] : this->outThreadId, this->threadPstatData[nextThreadIndexPlus]);
	}
}

double ProcessRtpPacket::getCpuUsagePerc(bool preparePstatData, int nextThreadIndexPlus) {
	if(preparePstatData) {
		this->preparePstatData(nextThreadIndexPlus);
	}
	if(nextThreadIndexPlus ? this->nextThreadId[nextThreadIndexPlus - 1] : this->outThreadId) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[nextThreadIndexPlus][0].cpu_total_time && this->threadPstatData[nextThreadIndexPlus][1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[nextThreadIndexPlus][0], &this->threadPstatData[nextThreadIndexPlus][1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

void ProcessRtpPacket::terminate() {
	this->term_processRtp = true;
	pthread_join(this->out_thread_handle, NULL);
	for(int i = 0; i < this->process_rtp_packets_hash_next_threads; i++) {
		if(this->next_thread_handle[i]) {
			if(this->sem_sync_next_thread[i][0].__align) {
				sem_post(&this->sem_sync_next_thread[i][0]);
			}
			pthread_join(this->next_thread_handle[i], NULL);
			for(int j = 0; j < 2; j++) {
				if(sem_sync_next_thread[i][j].__align) {
					sem_destroy(&sem_sync_next_thread[i][j]);
					sem_sync_next_thread[i][j].__align = 0;
				}
			}
		}
	}
}

void ProcessRtpPacket::autoStartProcessRtpPacket() {
	if(!processRtpPacketHash &&
	   opt_enable_process_rtp_packet && opt_pcap_split &&
	   !is_read_from_file_simple()) {
		process_rtp_packets_distribute_threads_use = opt_enable_process_rtp_packet;
		ProcessRtpPacket *_processRtpPacketHash = new FILE_LINE ProcessRtpPacket(ProcessRtpPacket::hash, 0);
		for(int i = 0; i < opt_enable_process_rtp_packet; i++) {
			processRtpPacketDistribute[i] = new FILE_LINE ProcessRtpPacket(ProcessRtpPacket::distribute, i);
		}
		processRtpPacketHash = _processRtpPacketHash;
	}
}

void ProcessRtpPacket::addRtpRhThread() {
	if(this->process_rtp_packets_hash_next_threads < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS) {
		for(int j = 0; j < opt_process_rtp_packets_hash_next_thread_sem_sync; j++) {
			sem_init(&sem_sync_next_thread[this->process_rtp_packets_hash_next_threads][j], 0, 0);
		}
		arg_next_thread *arg = new arg_next_thread;
		arg->processRtpPacket = this;
		arg->next_thread_id = this->process_rtp_packets_hash_next_threads + 1;
		pthread_create(&this->next_thread_handle[this->process_rtp_packets_hash_next_threads], NULL, _ProcessRtpPacket_nextThreadFunction, arg);
		++this->process_rtp_packets_hash_next_threads;
	}
}

void ProcessRtpPacket::addRtpRdThread() {
	if(process_rtp_packets_distribute_threads_use < MAX_PROCESS_RTP_PACKET_THREADS &&
	   !processRtpPacketDistribute[process_rtp_packets_distribute_threads_use]) {
		ProcessRtpPacket *_processRtpPacketDistribute = new FILE_LINE ProcessRtpPacket(ProcessRtpPacket::distribute, process_rtp_packets_distribute_threads_use);
		processRtpPacketDistribute[process_rtp_packets_distribute_threads_use] = _processRtpPacketDistribute;
		++process_rtp_packets_distribute_threads_use;
	}
}
