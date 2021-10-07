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

//#define HAS_NIDS 1
#ifdef HAS_NIDS
#include <nids.h>
#endif

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
#include "mgcp.h"
#include "tcpreassembly.h"
#include "ip_frag.h"
#include "regcache.h"
#include "manager.h"
#include "fraud.h"
#include "send_call_info.h"
#include "ssl_dssl.h"
#include "websocket.h"
#include "options.h"
#include "sniff_inline.h"
#include "config_param.h"

#if HAVE_LIBTCMALLOC    
#include <gperftools/malloc_extension.h>
#endif

#if HAVE_LIBJEMALLOC
#include <jemalloc/jemalloc.h>
#endif


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
u_int64_t glob_packet_number;

Calltable *calltable = NULL;
#if DEBUG_ASYNC_TAR_WRITE
cDestroyCallsInfo *destroy_calls_info = NULL;
#endif
extern volatile int calls_counter;
extern volatile int registers_counter;
extern int opt_saveSIP;		// save SIP packets to pcap file?
extern int opt_saveRTP;		// save RTP packets to pcap file?
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
extern int opt_sip_options;
extern int opt_sip_subscribe;
extern int opt_sip_notify;
extern int opt_norecord_header;
extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;
extern int opt_convert_dlt_sll_to_en10;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern pcap_t *global_pcap_handle;
extern u_int16_t global_pcap_handle_index;
extern pcap_t *global_pcap_handle_dead_EN10MB;
extern rtp_read_thread *rtp_threads;
extern int opt_norecord_dtmf;
extern int opt_onlyRTPheader;
extern int opt_sipoverlap;
extern int opt_last_dest_number;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern char opt_call_id_alternative[256];
extern vector<string> opt_call_id_alternative_v;
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
extern int opt_messageproxy;
extern int rtp_threaded;
extern int opt_rtpnosip;
extern char opt_cachedir[1024];
extern int opt_savewav_force;
extern int opt_saveudptl;
extern nat_aliases_t nat_aliases;
extern int opt_enable_preprocess_packet;
extern int opt_enable_process_rtp_packet;
extern int process_rtp_packets_distribute_threads_use;
extern int opt_pre_process_packets_next_thread;
extern int opt_pre_process_packets_next_thread_max;
extern int opt_process_rtp_packets_hash_next_thread;
extern int opt_process_rtp_packets_hash_next_thread_sem_sync;
extern unsigned int opt_preprocess_packets_qring_length;
extern unsigned int opt_preprocess_packets_qring_item_length;
extern unsigned int opt_preprocess_packets_qring_usleep;
extern bool opt_preprocess_packets_qring_force_push;
extern unsigned int opt_process_rtp_packets_qring_length;
extern unsigned int opt_process_rtp_packets_qring_item_length;
extern unsigned int opt_process_rtp_packets_qring_usleep;
extern bool process_rtp_packets_qring_force_push;
extern unsigned int rtp_qring_usleep;
extern unsigned int rtp_qring_batch_length;
extern int opt_pcapdump;
extern int opt_id_sensor;
extern int opt_destination_number_mode;
extern int opt_update_dstnum_onanswer;
extern MySqlStore *sqlStore;
extern sExistsColumns existsColumns;
int global_pcap_dlink;
extern int opt_udpfrag;
extern int global_livesniffer;
extern int opt_pcap_split;
extern int opt_newdir;
extern int opt_callslimit;
extern int opt_skiprtpdata;
extern char opt_silenceheader[128];
extern char opt_energylevelheader[128];
extern char opt_silencedtmfseq[16];
extern int opt_skinny;
extern int opt_saverfc2833;
extern livesnifferfilter_use_siptypes_s livesnifferfilterUseSipTypes;
extern int opt_skipdefault;
extern TcpReassembly *tcpReassemblyHttp;
extern TcpReassembly *tcpReassemblyWebrtc;
extern TcpReassembly *tcpReassemblySsl;
extern char ifname[1024];
extern int opt_sdp_reverse_ipport;
extern bool opt_sdp_check_direction_ext;
extern vector<vmIPport> opt_sdp_ignore_ip_port;
extern vector<vmIP> opt_sdp_ignore_ip;
extern vector<vmIPmask> opt_sdp_ignore_net;
extern int opt_fork;
extern regcache *regfailedcache;
extern ManagerClientThreads ClientThreads;
extern int opt_register_timeout;
extern int opt_register_ignore_res_401;
extern int opt_register_ignore_res_401_nonce_has_changed;
extern int opt_register_max_registers;
extern int opt_register_max_messages;
extern int opt_nocdr;
extern int opt_enable_fraud;
extern int pcap_drop_flag;
extern int opt_hide_message_content;
extern int opt_remotepartyid;
extern int opt_remotepartypriority;
extern int opt_ppreferredidentity;
extern int opt_passertedidentity;
extern char opt_remoteparty_caller[1024];
extern char opt_remoteparty_called[1024];
extern vector<string> opt_remoteparty_caller_v;
extern vector<string> opt_remoteparty_called_v;
extern int opt_182queuedpauserecording;
extern SocketSimpleBufferWrite *sipSendSocket;
extern int opt_sip_send_before_packetbuffer;
extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
extern PreProcessPacket **preProcessPacketCallX;
extern PreProcessPacket **preProcessPacketCallFindX;
extern int preProcessPacketCallX_count;
extern ProcessRtpPacket *processRtpPacketHash;
extern ProcessRtpPacket *processRtpPacketDistribute[MAX_PROCESS_RTP_PACKET_THREADS];
extern volatile PreProcessPacket::eCallX_state preProcessPacketCallX_state;
extern CustomHeaders *custom_headers_cdr;
extern CustomHeaders *custom_headers_message;
extern CustomHeaders *custom_headers_sip_msg;
extern bool _save_sip_history;
extern bool _save_sip_history_request_types[1000];
extern bool _save_sip_history_all_requests;
extern bool _save_sip_history_all_responses;
extern int opt_rtpfromsdp_onlysip;
extern int opt_rtpfromsdp_onlysip_skinny;
extern int opt_t2_boost;
unsigned int glob_ssl_calls = 0;
extern int opt_bye_timeout;
extern int opt_bye_confirmed_timeout;
extern bool opt_ignore_rtp_after_bye_confirmed;
extern bool opt_ignore_rtp_after_cancel_confirmed;
extern bool opt_ignore_rtp_after_auth_failed;
extern bool opt_detect_alone_bye;
extern bool opt_get_reason_from_bye_cancel;
extern int opt_hash_modify_queue_length_ms;
extern int opt_sipalg_detect;
extern int opt_quick_save_cdr;
extern int opt_cleanup_calls_period;
extern int opt_destroy_calls_period;
extern int opt_ss7timeout_rlc;

extern cProcessingLimitations processing_limitations;

inline char * gettag(const void *ptr, unsigned long len, ParsePacket::ppContentsX *parseContents,
		     const char *tag, unsigned long *gettaglen, unsigned long *limitLen = NULL);
inline char * gettag_sip(packet_s_process *packetS,
			 const char *tag, unsigned long *gettaglen);
inline char * gettag_sip(packet_s_process *packetS,
			 const char *tag, const char *tag2, unsigned long *gettaglen);
inline char * gettag_sip_from(packet_s_process *packetS, const char *from,
			      const char *tag, unsigned long *gettaglen);
inline char * gettag_sip_from(packet_s_process *packetS, const char *from,
			      const char *tag, const char *tag2, unsigned long *gettaglen);
static void logPacketSipMethodCall(u_int64_t packet_number, int sip_method, int lastSIPresponseNum, timeval ts, 
				   vmIP saddr, vmPort source, vmIP daddr, vmPort dest,
				   Call *call, const char *descr = NULL);

#define logPacketSipMethodCall_enable ((is_read_from_file_simple() && verbosity > 2) || verbosityE > 1 || sverb.sip_packets)

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

u_int64_t counter_calls;
u_int64_t counter_calls_clean;
u_int64_t counter_registers;
u_int64_t counter_registers_clean;
volatile u_int64_t counter_sip_packets[2];
u_int64_t counter_sip_register_packets;
u_int64_t counter_sip_message_packets;
u_int64_t counter_rtp_packets[2];
u_int64_t counter_all_packets;
volatile u_int64_t counter_user_packets[5];
u_int64_t process_rtp_counter;
u_int64_t read_rtp_counter;

extern struct queue_state *qs_readpacket_thread_queue;

map<unsigned int, livesnifferfilter_s*> usersniffer;
map<unsigned int, string> usersniffer_kill_reason;
volatile int usersniffer_sync;
volatile int usersniffer_checksize_sync;
pthread_t usersniffer_checksize_thread;


#include "sniff_inline.h"


unsigned long process_packet__last_cleanup_calls = 0;
int64_t process_packet__last_cleanup_calls_diff = 0;
unsigned long process_packet__last_destroy_calls = 0;
unsigned long process_packet__last_cleanup_registers = 0;
int64_t process_packet__last_cleanup_registers_diff = 0;
unsigned long process_packet__last_destroy_registers = 0;
unsigned long process_packet__last_cleanup_ss7 = 0;
int64_t process_packet__last_cleanup_ss7_diff = 0;
unsigned long __last_memory_purge = 0;

volatile unsigned long count_sip_bye;
volatile unsigned long count_sip_bye_confirmed;
volatile unsigned long count_sip_cancel;
volatile unsigned long count_sip_cancel_confirmed;
unsigned long process_packet__last_cleanup_calls__count_sip_bye;
unsigned long process_packet__last_cleanup_calls__count_sip_bye_confirmed;
unsigned long process_packet__last_cleanup_calls__count_sip_cancel;
unsigned long process_packet__last_cleanup_calls__count_sip_cancel_confirmed;


// return IP from nat_aliases[ip] or 0 if not found
vmIP match_nat_aliases(vmIP ip) {
	nat_aliases_t::iterator iter;
        iter = nat_aliases.find(ip);
        if(iter == nat_aliases.end()) {
                return 0;
        } else {
                return iter->second;
        }
}

inline void save_packet_sql(Call *call, packet_s_process *packetS, int uid,
			    pcap_pkthdr *header, u_char *packet) {
	//save packet
	stringstream query;
	
	bool convert_dlt_sll_to_en10 = PcapDumper::enable_convert_dlt_sll_to_en10(packetS->dlt) &&
				       (header ? header->caplen > 16 : packetS->dataoffset_() > 16);
	int convert_dlt_sll_to_en10_reduct_size = convert_dlt_sll_to_en10 ? 2 : 0;

	unsigned int savePacketLen = header ?
				      MIN(10000, header->caplen - convert_dlt_sll_to_en10_reduct_size) :
				      MIN(10000, packetS->dataoffset_() - convert_dlt_sll_to_en10_reduct_size + packetS->sipDataLen);
	unsigned int savePacketLenWithHeaders = savePacketLen + sizeof(pcap_hdr_t) + sizeof(pcaprec_hdr_t);

	// pcap file header
	pcap_hdr_t pcaphdr; // 24bytes
	pcaphdr.magic_number = 0xa1b2c3d4;
	pcaphdr.version_major = 2;
	pcaphdr.version_minor = 4;
	pcaphdr.thiszone = 0;
	pcaphdr.sigfigs = 0;
	pcaphdr.snaplen = 3200;
	pcaphdr.network = PcapDumper::convert_dlt_sll_to_en10(packetS->dlt);
	
	// packet header
	pcaprec_hdr_t pcaph;
	if(header) {
		pcaph.ts_sec = header->ts.tv_sec;            /* timestamp seconds */
		pcaph.ts_usec = header->ts.tv_usec;          /* timestamp microseconds */
		pcaph.incl_len = savePacketLen;              /* number of octets of packet saved in file */
		pcaph.orig_len = header->caplen - convert_dlt_sll_to_en10_reduct_size;             
							     /* actual length of packet */
	} else {
		pcaph.ts_sec = packetS->header_pt->ts.tv_sec;    /* timestamp seconds */
		pcaph.ts_usec = packetS->header_pt->ts.tv_usec;  /* timestamp microseconds */
		pcaph.incl_len = savePacketLen;                  /* number of octets of packet saved in file */
		pcaph.orig_len = packetS->header_pt->caplen - convert_dlt_sll_to_en10_reduct_size;     
								 /* actual length of packet */
	}

	// copy data to mpacket buffer	
	char mpacket[10512];
	char *ptr = mpacket;
	memcpy(ptr, &pcaphdr, sizeof(pcaphdr)); // pcap header
	ptr += sizeof(pcaphdr);
	memcpy(ptr, &pcaph, sizeof(pcaph)); // packet pcaph header
	ptr += sizeof(pcaph);
	if(header) {
		if(convert_dlt_sll_to_en10) {
			PcapDumper::packet_convert_dlt_sll_to_en10(packet, (u_char*)ptr, NULL, NULL, savePacketLen);
		} else {
			memcpy(ptr, packet, savePacketLen);
		}
	} else {
		if(convert_dlt_sll_to_en10) {
			PcapDumper::packet_convert_dlt_sll_to_en10(packetS->packet, (u_char*)ptr, NULL, NULL, packetS->dataoffset_() - convert_dlt_sll_to_en10_reduct_size);
			ptr += packetS->dataoffset_() - convert_dlt_sll_to_en10_reduct_size;
			memcpy(ptr, packetS->data_() + packetS->sipDataOffset, savePacketLen - (packetS->dataoffset_() - convert_dlt_sll_to_en10_reduct_size));
		} else {
			memcpy(ptr, packetS->packet, packetS->dataoffset_()); // packet pcaph header
			ptr += packetS->dataoffset_();
			memcpy(ptr, packetS->data_() + packetS->sipDataOffset, savePacketLen - packetS->dataoffset_());
		}
	}
	
	//construct description and call-id
	char description[1024] = "";
	char callidstr[1024] = "";
	if(packetS->sipDataLen) {
		void *memptr = NULL;
		for(int pass_line_separator = 0; pass_line_separator < 2 && !memptr; pass_line_separator++) {
			memptr = memmem(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen, 
					SIP_LINE_SEPARATOR(pass_line_separator == 1), 
					SIP_LINE_SEPARATOR_SIZE(pass_line_separator == 1));
		}
		if(memptr) {
			unsigned description_src_length = MIN((char*)memptr - (char*)(packetS->data_()+ packetS->sipDataOffset), sizeof(description) - 1);
			memcpy(description, packetS->data_() + packetS->sipDataOffset, description_src_length);
			description[description_src_length] = '\0';
		} else {
			strcpy(description, "error in description\n");
		}
		if(!call) {
			unsigned long l;
			char *s = gettag_sip(packetS, "\nCall-ID:", &l);
			if(s && l < 1024) {
				memcpy(callidstr, s, MIN(l, 1024));
				callidstr[MIN(l, 1023)] = '\0';
			}
		}
	}

	// construct query and push it to mysqlquery queue
	char query_buff[20000];
	char livepacket_table[20];
	snprintf(livepacket_table, sizeof(livepacket_table), "livepacket_%i", uid);
	snprintf(query_buff, sizeof(query_buff),
		"INSERT INTO %s"
		" SET sipcallerip = %s"
		", sipcalledip = %s"
		", id_sensor = %i"
		", sport = %i" 
		", dport = %i" 
		", istcp = %i"
		", created_at = %s"
		", microseconds = %li"
		", callid = %s"
		", description = %s",
		livepacket_table,
		packetS->saddr_().getStringForMysqlIpColumn(livepacket_table, "sipcallerip").c_str(),
		packetS->daddr_().getStringForMysqlIpColumn(livepacket_table, "sipcalledip").c_str(),
		packetS->sensor_id_() > 0 ? packetS->sensor_id_() : 0,
		packetS->source_().getPort(),
		packetS->dest_().getPort(),
		packetS->pflags.tcp,
		sqlEscapeStringBorder(sqlDateTimeString(packetS->header_pt->ts.tv_sec).c_str()).c_str(),
		packetS->header_pt->ts.tv_usec,
		sqlEscapeStringBorder(call ? call->call_id : callidstr).c_str(),
		sqlEscapeStringBorder(description).c_str());
	if(SqlDb_mysql::existsColumnInTypeCache_static(livepacket_table, "vlan")) {
		int query_buff_length = strlen(query_buff);
		snprintf(query_buff + query_buff_length, sizeof(query_buff) - query_buff_length,
			 ", vlan = %s",
			 VLAN_IS_SET(packetS->pid.vlan) ? intToString(packetS->pid.vlan).c_str() : "NULL");
	}
	strcat(query_buff, ", data = ");
	if(isCloud() || useNewStore()) {
		strcat(query_buff, "concat('#', from_base64('");
		_base64_encode((unsigned char*)mpacket, savePacketLenWithHeaders, query_buff + strlen(query_buff));
		strcat(query_buff, "'), '#')");
	} else {
		strcat(query_buff, "'#");
		_sqlEscapeString(mpacket, savePacketLenWithHeaders, query_buff + strlen(query_buff), NULL);
		strcat(query_buff, "#'");
	}
	sqlStore->query_lock(MYSQL_ADD_QUERY_END(string(query_buff)), STORE_PROC_ID_SAVE_PACKET_SQL, 0);
}


/* 
	stores SIP messags to sql.livepacket based on user filters
*/

enum eParsePeernameTagType {
	ppntt_undefined,
	ppntt_invite,
	ppntt_message,
	ppntt_from,
	ppntt_to,
	ppntt_contact,
	ppntt_remote_party,
	ppntt_asserted_identity,
	ppntt_preferred_identity
};
enum eParsePeernameDestType {
	ppndt_undefined,
	ppndt_caller,
	ppndt_called,
	ppndt_contact,
	ppndt_caller_domain,
	ppndt_called_domain,
	ppndt_contact_domain,
	ppndt_caller_name,
	ppndt_called_tag
};

inline int get_sip_peername(packet_s_process *packetS, const char *tag, const char *tag2, 
			    string *peername, 
			    eParsePeernameTagType tagType, eParsePeernameDestType destType);
inline int get_sip_peername(packet_s_process *packetS, const char *tag, const char *tag2, 
			    char *peername, unsigned int peername_len, 
			    eParsePeernameTagType tagType, eParsePeernameDestType destType);
inline int get_sip_headerstr(packet_s_process *packetS, const char *tag, const char *tag2, 
			     char *headerstr, unsigned int headerstr_len);

inline void save_live_packet(Call *call, packet_s_process *packetS, unsigned char sip_type,
			     pcap_pkthdr *header, u_char *packet) {
	if(!global_livesniffer) {
		return;
	}
	// check saddr and daddr filters
	vmIP daddr = packetS->daddr_();
	vmIP saddr = packetS->saddr_();
	//ports
	vmPort srcport = packetS->source_();
	vmPort dstport = packetS->dest_();

	while(__sync_lock_test_and_set(&usersniffer_sync, 1));
	
	map<unsigned int, livesnifferfilter_s*>::iterator usersnifferIT;
	
	char caller[1024] = "", called[1024] = "";
	char fromhstr[1024] = "", tohstr[1024] = "";
        //Check if we use from/to header for filtering, if yes gather info from packet to fromhstr tohstr
        {
		bool needfromhstr = false;
		bool needtohstr = false;
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
			get_sip_headerstr(packetS, "\nFrom:", "\nf:", fromhstr, sizeof(fromhstr));
		}
		if(needtohstr) {
			get_sip_headerstr(packetS, "\nTo:", "\nt:", tohstr, sizeof(tohstr));
		}
	}
        //If call is established get caller/called num from packet - else gather it from packet and save to caller called
	if(call) {
		strcpy_null_term(caller, call->caller);
		strcpy_null_term(called, call->called());
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
		if(needcaller) {
			get_sip_peername(packetS, "\nFrom:", "\nf:", caller, sizeof(caller), ppntt_from, ppndt_caller);
		}
		if(needcalled) {
			get_sip_peername(packetS, "\nTo:", "\nt:", called, sizeof(called), ppntt_to, ppndt_called);
		}
	}
	
	for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); usersnifferIT++) {
		livesnifferfilter_s *filter = usersnifferIT->second;
		if(is_server() &&
		   filter->sensor_id_set && filter->sensor_id &&
		   (filter->sensor_id < 0 ?
		     packetS->sensor_id_() > 0 :
		     filter->sensor_id != packetS->sensor_id_())) {
			continue;
		}
		bool save = filter->state.all_all;
		if(!save) {
			bool okAddr = filter->state.all_addr;
			if(!okAddr) {
				for(int i = 0; i < MAXLIVEFILTERS && !okAddr; i++) {
					if((filter->state.all_saddr || (filter->lv_saddr[i].isSet() && 
						saddr.mask(filter->lv_smask[i]) == filter->lv_saddr[i])) &&
					   (filter->state.all_daddr || (filter->lv_daddr[i].isSet() && 
						daddr.mask(filter->lv_dmask[i]) == filter->lv_daddr[i])) &&
					   (filter->state.all_bothaddr || (filter->lv_bothaddr[i].isSet() && 
						(saddr.mask(filter->lv_bothmask[i]) == filter->lv_bothaddr[i] || 
						 daddr.mask(filter->lv_bothmask[i]) == filter->lv_bothaddr[i])))) {
						okAddr = true;
					}
				}
			}
			bool okPort = filter->state.all_bothport;
			if (!okPort) {
				for(int i = 0; i < MAXLIVEFILTERS && !okPort; i++) {
					if (filter->state.all_bothport || (filter->lv_bothport[i].isSet() &&
					   (srcport == filter->lv_bothport[i] ||
					    dstport == filter->lv_bothport[i]))) {
						okPort = true;
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
			bool okVlan = filter->state.all_vlan;
			if(!okVlan) {
				for(int i = 0; i < MAXLIVEFILTERS && !okVlan; i++) {
					if(filter->state.all_vlan || 
					   (filter->lv_vlan_set[i] && packetS->pid.vlan == filter->lv_vlan[i])) {
						okVlan = true;
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
			if(okAddr && okPort && okNum && okSipType && okHeader && okVlan) {
				save = true;
			}
		}
		if(save) {
			save_packet_sql(call, packetS, usersnifferIT->first, 
					header, packet);
		}
	}
	
	__sync_lock_release(&usersniffer_sync);
}

void save_live_packet(packet_s_process *packetS) {
	if(global_livesniffer) {
		if(packetS->is_message() && livesnifferfilterUseSipTypes.u_message) {
			save_live_packet(NULL, packetS, MESSAGE,
					 NULL, NULL);
		} else if(packetS->is_register() && livesnifferfilterUseSipTypes.u_register) {
			save_live_packet(NULL, packetS, REGISTER,
					 NULL, NULL);
		} else if(packetS->is_subscribe() && livesnifferfilterUseSipTypes.u_subscribe) {
			save_live_packet(NULL, packetS, SUBSCRIBE,
					 NULL, NULL);
		} else if(packetS->is_options() && livesnifferfilterUseSipTypes.u_options) {
			save_live_packet(NULL, packetS, OPTIONS,
					 NULL, NULL);
		} else if(packetS->is_notify() && livesnifferfilterUseSipTypes.u_notify) {
			save_live_packet(NULL, packetS, NOTIFY,
					 NULL, NULL);
		}
	}
}

static int parse_packet__message(packet_s_process *packetS, bool strictCheckLength,
				 char **rsltMessage, char **rsltMessageInfo, string *rsltDestNumber, string *rsltSrcNumber, unsigned int *rsltContentLength,
				 unsigned int *rsltDcs, Call::eVoicemail *rsltVoicemail,
				 bool maskMessage = false);

/*
   save packet into file 
   type - 1 is SIP, 2 is RTP, 3 is RTCP

*/
void save_packet(Call *call, packet_s_process *packetS, int type, u_int8_t forceVirtualUdp) {
	if(call->flags & FLAG_SKIPCDR) {
		return;
	}
	if(packetS->pid.flags & FLAG_AUDIOCODES) {
		forceVirtualUdp = true;
	}
	if(packetS->kamailio_subst ||
	   packetS->header_ip_()->_get_protocol() == IPPROTO_ESP) {
		forceVirtualUdp = 2;
	}
	if(packetS->header_pt->caplen > 1000000) {
		static u_int64_t lastTimeSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			syslog(LOG_ERR, "too big packet caplen (%u) in call %s - skip save packet", packetS->header_pt->caplen, call->call_id.c_str());
			lastTimeSyslog = actTime;
		}
		return;
	}
	if(call->typeIs(MESSAGE) && (call->flags & FLAG_HIDEMESSAGE) && packetS->sip_method == MESSAGE) {
		parse_packet__message(packetS, false,
				      NULL, NULL, NULL, NULL, NULL,
				      NULL, NULL,
				      true);
	}
	pcap_pkthdr *header = packetS->header_pt;
	u_char *packet = (u_char*)packetS->packet;
	bool allocHeader = false;
	bool allocPacket = false;
	unsigned int limitCapLen = 65535;
	unsigned int packetLen = packetS->header_pt->caplen;
	if(type == _t_packet_sip && packetS->typeContentIsSip()) {
		packetLen = packetS->dataoffset_() + packetS->sipDataLen;
	}
	if(packetLen > limitCapLen) {
		packetLen = limitCapLen;
	}
	if(packetLen != packetS->header_pt->caplen) {
		header = new FILE_LINE(26001) pcap_pkthdr;
		memcpy(header, packetS->header_pt, sizeof(pcap_pkthdr));
		allocHeader = true;
		packet = new FILE_LINE(26002) u_char[max(packetLen, header->caplen)];
		memset(packet, 0, max(packetLen, header->caplen));
		allocPacket = true;
		if(packetLen != packetS->header_pt->caplen) {
			if(type == _t_packet_sip && packetS->typeContentIsSip()) {
				memcpy(packet, packetS->packet, packetS->dataoffset_());
				memcpy(packet + packetS->dataoffset_(), packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen);
				if(packetS->dataoffset_() + packetS->sipDataLen != packetLen) {
					unsigned long l;
					char *contLengthPos = NULL;
					for(int pass = 0; pass < 2 && !contLengthPos; ++pass) {
						contLengthPos = gettag_sip(packetS,
									   pass ? 
									    LF_LINE_SEPARATOR "l:" : 
									    LF_LINE_SEPARATOR "Content-Length:",
									   &l);
					}
					if(contLengthPos) {
						char *pointToModifyContLength = (char*)packet + packetS->dataoffset_() + (contLengthPos - (packetS->data_()+ packetS->sipDataOffset));
						char *pointToBeginContent = NULL;
						for(int pass_line_separator = 0; pass_line_separator < 2 && !pointToBeginContent; pass_line_separator++) {
							pointToBeginContent = (char*)memmem(packet + packetS->dataoffset_(), packetS->sipDataLen, 
											       SIP_DBLLINE_SEPARATOR(pass_line_separator == 1), 
											       SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1));
							if(pointToBeginContent) {
								pointToBeginContent += SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1);
							}
						}
						if(pointToBeginContent) {
							int contentLengthOrig = atoi(pointToModifyContLength);
							int contentLengthNew = packetLen - (pointToBeginContent - (char*)packet);
							if(contentLengthNew > 0 && contentLengthOrig != contentLengthNew) {
								char contLengthStr[20];
								snprintf(contLengthStr, sizeof(contLengthStr), "%i", contentLengthNew);
								#if __GNUC__ >= 8
								#pragma GCC diagnostic push
								#pragma GCC diagnostic ignored "-Wstringop-overflow"
								#pragma GCC diagnostic ignored "-Wstringop-truncation"
								#endif
								strncpy(pointToModifyContLength, contLengthStr, strlen(contLengthStr));
								#if __GNUC__ >= 8
								#pragma GCC diagnostic pop
								#endif
								char *pointToEndModifyContLength = pointToModifyContLength + strlen(contLengthStr);
								while(*pointToEndModifyContLength != CR_CHAR && *pointToEndModifyContLength != LF_CHAR) {
									*pointToEndModifyContLength = ' ';
									++pointToEndModifyContLength;
								}
							}
						}
					}
				}
			} else {
				memcpy(packet, packetS->packet, packetLen);
			}
			iphdr2 *header_ip = (iphdr2*)(packet + ((u_char*)packetS->header_ip_() - packetS->packet));
			unsigned header_ip_tot_len = packetLen - ((char*)packetS->header_ip_() - (char*)packetS->packet);
			if(header_ip_tot_len != header_ip->get_tot_len()) {
				header_ip->set_tot_len(header_ip_tot_len);
			}
			unsigned int diffLen = packetS->header_pt->caplen - packetLen;
			header->caplen -= diffLen;
			header->len -= diffLen;
		} else {
			memcpy(packet, packetS->packet, header->caplen);
		}
	}
 
	// check if it should be stored to mysql 
	if(type == _t_packet_sip && global_livesniffer) {
		if(call->typeIs(INVITE) && livesnifferfilterUseSipTypes.u_invite) {
			save_live_packet(call, packetS, INVITE,
					 header, packet);
		} else {
			save_live_packet(packetS);
		}
	}

	if(!sverb.disable_save_packet) {
		if(enable_pcap_split) {
			switch(type) {
			case _t_packet_sip:
			case _t_packet_skinny:
			case _t_packet_mgcp:
				if(call->getPcapSip()->isOpen()){
					if(type == _t_packet_sip) {
						call->getPcapSip()->dump(header, packet, packetS->dlt, false, 
									 (u_char*)packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen,
									 packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(), packetS->pflags.tcp, forceVirtualUdp, 
									 forceVirtualUdp == 2 ? packetS->getTimeval_pt() : NULL);
					} else {
						call->getPcapSip()->dump(header, packet, packetS->dlt, false,
									 (u_char*)packetS->data_(), packetS->datalen_(),
									 packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(), packetS->pflags.tcp, forceVirtualUdp);
					}
				}
				break;
			case _t_packet_rtp:
			case _t_packet_dtls:
			case _t_packet_mrcp:
			case _t_packet_rtcp:
				if(call->getPcapRtp()->isOpen()){
					call->getPcapRtp()->dump(header, packet, packetS->dlt, false,
								 (u_char*)packetS->data_(), packetS->datalen_(),
								 packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(), packetS->pflags.tcp, forceVirtualUdp);
				} else if(type == _t_packet_rtcp ? enable_save_rtcp(call) : enable_save_rtp_packet(call, type)) {
					string pathfilename = call->get_pathfilename(tsf_rtp);
					if(call->getPcapRtp()->open(tsf_rtp, pathfilename.c_str(), call->useHandle, call->useDlt)) {
						call->getPcapRtp()->dump(header, packet, packetS->dlt, false,
									 (u_char*)packetS->data_(), packetS->datalen_(),
									 packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(), packetS->pflags.tcp, forceVirtualUdp);
						if(verbosity > 3) { 
							syslog(LOG_NOTICE,"pcap_filename: [%s]\n", pathfilename.c_str());
						}
					}
				}
				break;
			}
		} else {
			if (call->getPcap()->isOpen()){
				if(type == _t_packet_sip) {
					call->getPcap()->dump(header, packet, packetS->dlt, false, 
							      (u_char*)packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen,
							      packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(), packetS->pflags.tcp, forceVirtualUdp, 
							      forceVirtualUdp == 2 ? packetS->getTimeval_pt() : NULL);
				} else {
					call->getPcap()->dump(header, packet, packetS->dlt, false,
							      (u_char*)packetS->data_(), packetS->datalen_(),
							      packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(), packetS->pflags.tcp, forceVirtualUdp);
				}
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

void save_packet(Call *call, packet_s *packetS, int type, u_int8_t forceVirtualUdp) {
	if(type != _t_packet_sip) {
		save_packet(call, (packet_s_process*)packetS, type, forceVirtualUdp);
	}
}

ParsePacket _parse_packet_global_process_packet;

int check_sip20(char *data, unsigned long len, ParsePacket::ppContentsX *parseContents, bool isTcp) {
 
	if(check_websocket(data, len, isTcp ? cWebSocketHeader::_chdst_na : cWebSocketHeader::_chdst_ge_limit)) {
		cWebSocketHeader ws((u_char*)data, len);
		if(len > ws.getHeaderLength()) {
			bool allocData;
			u_char *ws_data = ws.decodeData(&allocData, len);
			if(!ws_data) {
				return 0;
			}
			int rslt = check_sip20((char*)ws_data,
					       isTcp ?
						min((u_int64_t)(len - ws.getHeaderLength()),
						    ws.getDataLength()) :
						ws.getDataLength(), 
					       parseContents, isTcp);
			if(allocData) {
				delete [] ws_data;
			}
			return(rslt);
		} else {
			return 0;
		}
	}
 
	while(isTcp && len >= 13) {
		if(data[0] == CR_CHAR && data[1] == LF_CHAR) {
			data += 2;
			len -= 2;
		} else if(data[0] == LF_CHAR) {
			data += 1;
			len -= 1;
		} else {
			break;
		}
	}
 
	if(len < 11) {
		return 0;
	}
	
	if(parseContents && parseContents->getParseData() == data) {
		return(parseContents->isSip());
	}
	
	int ok;
	//List of SIP request methods
	//RFC 3261
	if(!strncasecmp(data, "SIP/2.0", 7)) {
		ok = 1;
	} else if(!strncasecmp(data, "INVITE ", 7)) {
		ok = 1;
	} else if(!strncasecmp(data, "ACK ", 4)) {
		ok = 1;
	} else if(!strncasecmp(data, "BYE ", 4)) {
		ok = 1;
	} else if(!strncasecmp(data, "CANCEL ", 7)) {
		ok = 1;
	} else if(!strncasecmp(data, "OPTIONS", 7)) {
		ok = 1;
	} else if(!strncasecmp(data, "REGISTER", 8)) {
		ok = 1;
	//RFC 3262
	} else if(!strncasecmp(data, "PRACK", 5)) {
		ok = 1;
	} else if(!strncasecmp(data, "SUBSCRIBE", 9)) {
		ok = 1;
	} else if(!strncasecmp(data, "NOTIFY", 6)) {
		ok = 1;
	} else if(!strncasecmp(data, "PUBLISH", 7)) {
		ok = 1;
	} else if(!strncasecmp(data, "INFO", 4)) {
		ok = 1;
	} else if(!strncasecmp(data, "REFER", 5)) {
		ok = 1;
	} else if(!strncasecmp(data, "MESSAGE", 7)) {
		ok = 1;
	} else if(!strncasecmp(data, "UPDATE", 6)) {
		ok = 1;
	} else {
		ok = 0;
	}
	return ok;
}

inline char * _gettag(const void *ptr, unsigned long len,
		      const char *tag, unsigned long *gettaglen) {
	char endChar = ((char*)ptr)[len - 1];
	((char*)ptr)[len - 1] = 0;
	char *tagPtr = strcasestr((char*)ptr, tag);
	((char*)ptr)[len - 1] = endChar;
	if(tagPtr) {
		unsigned contentIndex = (tagPtr - (char*)ptr) + strlen(tag);
		while(contentIndex < len - 1 && ((char*)ptr)[contentIndex] == ' ') {
			++contentIndex;
		}
		if(contentIndex < len) {
			unsigned contentIndexEnd = len - 1;
			char *ptrEndLine;
			if((ptrEndLine = (char*)memmem((char*)ptr + contentIndex, len - contentIndex, CR_STR, 1)) == NULL) {
				ptrEndLine = (char*)memmem((char*)ptr + contentIndex, len - contentIndex, LF_STR, 1);
			}
			if(ptrEndLine) {
				contentIndexEnd = ptrEndLine - (char*)ptr - 1;
			}
			while(contentIndexEnd > contentIndex && ((char*)ptr)[contentIndexEnd] == ' ') {
				--contentIndexEnd;
			}
			if(contentIndexEnd >= contentIndex) {
				*gettaglen = contentIndexEnd - contentIndex + 1;
				return((char*)ptr + contentIndex);
			}
		}
	}
	*gettaglen = 0;
	return(NULL);
}

char * gettag_ext(const void *ptr, unsigned long len, ParsePacket::ppContentsX *parseContents,
		  const char *tag, unsigned long *gettaglen, unsigned long *limitLen) {
	return(gettag(ptr, len, parseContents,
		      tag, gettaglen, limitLen));
}

/* get SIP tag from memory pointed to *ptr length of len */
inline char * gettag(const void *ptr, unsigned long len, ParsePacket::ppContentsX *parseContents,
		     const char *tag, unsigned long *gettaglen, unsigned long *limitLen) {
 
	if(parseContents && parseContents->getParseData() == ptr) {
		u_int32_t l_pp;
		const char *rc_pp = parseContents->getContentData(tag, &l_pp);
		/*
		if((!rc_pp || l_pp <= 0) && tag[0] != '\n') {
			char _tag[1024];
			_tag[0] = '\n';
			strcpy(_tag + 1, tag);
			rc_pp = parseContents->getContentData(_tag, &l_pp);
		}
		*/
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
			for(int pass = 0; pass < 2; ++pass) {
				char *contentLengthPos = strcasestr(tmp, 
								    pass ? 
								     LF_LINE_SEPARATOR "l:" : 
								     LF_LINE_SEPARATOR "Content-Length:");
				if(contentLengthPos) {
					contentLengthPos += (pass ? 2 : 15) + 1;
					while(*contentLengthPos == ' ') {
						++contentLengthPos;
					}
					int contentLength = atol(contentLengthPos);
					if(contentLength >= 0 && (unsigned)contentLength < len) {
						char *endHeaderSepPos = NULL;
						for(int pass_line_separator = 0; pass_line_separator < 2 && !endHeaderSepPos; pass_line_separator++) {
							endHeaderSepPos = (char*)memmem(tmp, len,
											SIP_DBLLINE_SEPARATOR(pass_line_separator == 1), 
											SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1));
							if(endHeaderSepPos) {
								_limitLen = (endHeaderSepPos - tmp) + SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1) + contentLength;
								if(limitLen) {
									*limitLen = _limitLen;
								}
								break;
							}
						}
					}
					break;
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
			l = (unsigned long)memmem((void *)r, len - (r - (unsigned long)ptr), CR_STR, 1);
			if (l > 0){
				// remove trailing CR LF and set l to length of the tag
				l -= r;
			} else {
				// trailing CR not found try to find \n
				l = (unsigned long)memmem((void *)r, len - (r - (unsigned long)ptr), LF_STR, 1);
				if (l > 0){
					// remove trailing LF and set l to length of the tag
					l -= r;
				} else {
					// trailing not found
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
		rc = NULL;
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

char * gettag_sip_ext(packet_s_process *packetS,
		      const char *tag, unsigned long *gettaglen) {
	return(gettag_sip(packetS, tag, gettaglen));
}

inline char * gettag_sip(packet_s_process *packetS,
			 const char *tag, unsigned long *gettaglen) {
	return(gettag(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen, &packetS->parseContents,
		      tag, gettaglen));
}

char * gettag_sip_ext(packet_s_process *packetS,
		      const char *tag, const char *tag2, unsigned long *gettaglen) {
	return(gettag_sip(packetS, tag, tag2, gettaglen));
}

inline char * gettag_sip(packet_s_process *packetS,
			 const char *tag, const char *tag2, unsigned long *gettaglen) {
	char *rslt = gettag_sip(packetS, tag, gettaglen);
	if(!rslt && tag2) {
		rslt = gettag_sip(packetS, tag2, gettaglen);
	}
	return(rslt);
}

inline char * gettag_sip_from(packet_s_process *packetS, const char *from,
			      const char *tag, unsigned long *gettaglen) {
	return(gettag(from ? 
		       from : 
		       packetS->data_()+ packetS->sipDataOffset, 
		      from ?
		       packetS->sipDataLen - (from - (packetS->data_()+ packetS->sipDataOffset)) :
		       packetS->sipDataLen, 
		      &packetS->parseContents,
		      tag, gettaglen));
}

inline char * gettag_sip_from(packet_s_process *packetS, const char *from,
			      const char *tag, const char *tag2, unsigned long *gettaglen) {
	char *rslt = gettag_sip_from(packetS, from, tag, gettaglen);
	if(!rslt && tag2) {
		rslt = gettag_sip_from(packetS, from, tag2, gettaglen);
	}
	return(rslt);
}

static struct {
	const char *prefix;
	unsigned length;
	unsigned skip;
	int type;
} peername_sip_tags[] = {
	{ "sip:", 4, 4, 0 },
	{ "sips:", 5, 5, 0 },
	{ "urn:", 4, 0, 1 },
	{ "tel:", 4, 4, 2 }
};

inline const char* get_peername_begin_sip_tag(const char *peername_tag, unsigned int peername_tag_len, int *peer_sip_tags_index) {
	const char *p = NULL;
	for(unsigned i = 0; i < sizeof(peername_sip_tags) / sizeof(peername_sip_tags[0]); i++) {
		if((p = (const char*)memmem(peername_tag, peername_tag_len, peername_sip_tags[i].prefix, peername_sip_tags[i].length))) {
			*peer_sip_tags_index = i;
			break;
		}
	}
	if(p && 
	   (p == peername_tag || *(p-1) == '<')) {
		return(p);
	}
	*peer_sip_tags_index = -1;
	return(NULL);
}
 
inline bool parse_peername(const char *peername_tag, unsigned int peername_tag_len,
			   int parse_type,
			   char *rslt, unsigned int rslt_max_len, 
			   eParsePeernameTagType /*tagType*/, eParsePeernameDestType destType) {
	int peer_sip_tags_index;
	const char *sip_tag = get_peername_begin_sip_tag(peername_tag, peername_tag_len, &peer_sip_tags_index);
	if(!sip_tag) {
		*rslt = 0;
		return(false);
	}
	const char *begin = NULL;
	const char *end = NULL;
	bool ok = false;
	if(parse_type == 1) { // peername
		begin = sip_tag + peername_sip_tags[peer_sip_tags_index].skip;
		for(end = begin; end < peername_tag + peername_tag_len; end++) {
			extern bool opt_callernum_numberonly;
			if(*end == '@' ||
			  (destType == ppndt_caller && opt_callernum_numberonly  && *end == ';') ||
			  (peername_sip_tags[peer_sip_tags_index].type == 2) && *end == ';' ) {
				if((peername_sip_tags[peer_sip_tags_index].type == 0) || (peername_sip_tags[peer_sip_tags_index].type == 2)) {
					--end;
					ok = true;
					break;
				}
			} else if(*end == '>') {
				if(peername_sip_tags[peer_sip_tags_index].type == 0) {
					break;
				} else {
					--end;
					ok = true;
					break;
				}
			}
		}
	} else if(parse_type == 2) { // peercname
		begin = peername_tag;
		end = sip_tag - 1;
		while(end > begin &&
		      (*end == '<' || *end == ' ')) {
			--end;
		}
		if(begin < end && *begin == '"' && *end == '"') {
			++begin;
			--end;
		}
		ok = begin < end;
	} else if(parse_type == 3 && peername_sip_tags[peer_sip_tags_index].type == 0) { // domain
		begin = sip_tag + peername_sip_tags[peer_sip_tags_index].skip;
		while(begin < peername_tag + peername_tag_len) {
			if(*begin == '@') {
				++begin;
				ok = true;
				break;
			} else if(*begin == '>') {
				begin = sip_tag + peername_sip_tags[peer_sip_tags_index].skip;
				ok = true;
				break;
			}
			++begin;
		}
		if(begin == peername_tag + peername_tag_len) {
			begin = sip_tag + peername_sip_tags[peer_sip_tags_index].skip;
			ok = true;
		}
		if(ok) {
			ok = false;
			for(end = begin; end < peername_tag + peername_tag_len; end++) {
				if(*end == '>' || *end == ';' || *end == ':' || *end == ' ') {
					--end;
					ok = true;
					break;
				}
			}
			if(!ok && begin < end) {
				--end;
				ok = true;
			}
		}
	} else if(parse_type == 4 && peername_sip_tags[peer_sip_tags_index].type == 0) { // tag
		begin = sip_tag + peername_sip_tags[peer_sip_tags_index].skip;
		while(begin < peername_tag + peername_tag_len - 4) {
			if(*begin == ';' && strncasestr(begin + 1, "tag=", 4)) {
				begin+=5;
				ok = true;
				break;
			}
			++begin;
		}
		if(ok) {
			ok = false;
			for(end = begin; end < peername_tag + peername_tag_len; end++) {
				if(*end == ';' || *end == ':') {
					--end;
					ok = true;
					break;
				}
			}
			if(!ok && begin < end) {
				--end;
				ok = true;
			}
		}
	}
	if(ok) {
		if(end >= begin && end - begin + 1 <= peername_tag_len) {
			memcpy(rslt, begin, MIN(end - begin + 1, rslt_max_len));
			rslt[MIN(end - begin + 1, rslt_max_len - 1)] = '\0';
			return(true);
		}
	}
	*rslt = 0;
	return(false);
}

inline int get_sip_peername(packet_s_process *packetS, const char *tag, const char *tag2, 
			    string *peername, 
			    eParsePeernameTagType tagType, eParsePeernameDestType destType) {
	char _peername[1024];
	int rslt = get_sip_peername(packetS, tag, tag2,  _peername, sizeof(_peername), tagType, destType);
	if(!rslt) {
		*peername = _peername;
	}
	return(rslt);
}

inline int get_sip_peername(packet_s_process *packetS, const char *tag, const char *tag2, 
			    char *peername, unsigned int peername_len, 
			    eParsePeernameTagType tagType, eParsePeernameDestType destType) {
	unsigned long peername_tag_len;
	char *peername_tag = gettag_sip(packetS, tag, tag2, &peername_tag_len);
	if(!peername_tag_len) {
		*peername = 0;
		return(1);
	}
	return(parse_peername(peername_tag, peername_tag_len,
			      1,
			      peername, peername_len, 
			      tagType, destType) ? 0 : 1);
} 

inline int get_sip_peercnam(packet_s_process *packetS, const char *tag, const char *tag2, 
			    char *peername, unsigned int peername_len,
			    eParsePeernameTagType tagType, eParsePeernameDestType destType) {
	unsigned long peername_tag_len;
	char *peername_tag = gettag_sip(packetS, tag, tag2, &peername_tag_len);
	if(!peername_tag_len) {
		*peername = 0;
		return(1);
	}
	return(parse_peername(peername_tag, peername_tag_len,
			      2,
			      peername, peername_len,
			      tagType, destType) ? 0 : 1);
}

inline int get_sip_domain(packet_s_process *packetS, const char *tag, const char *tag2,
			  char *domain, unsigned int domain_len,
			  eParsePeernameTagType tagType, eParsePeernameDestType destType) {
	unsigned long peername_tag_len;
	char *peername_tag = gettag_sip(packetS, tag, tag2, &peername_tag_len);
	if(!peername_tag_len) {
		*domain = 0;
		return(1);
	}
	return(parse_peername(peername_tag, peername_tag_len,
			      3,
			      domain, domain_len,
			      tagType, destType) ? 0 : 1);
}

inline int get_sip_peertag(packet_s_process *packetS, const char *tag, const char *tag2,
			   char *tag_content, unsigned int tag_content_len,
			   eParsePeernameTagType tagType, eParsePeernameDestType destType) {
	unsigned long peername_tag_len;
	char *peername_tag = gettag_sip(packetS, tag, tag2, &peername_tag_len);
	if(!peername_tag_len) {
		*tag_content = 0;
		return(1);
	}
	return(parse_peername(peername_tag, peername_tag_len,
			      4,
			      tag_content, tag_content_len,
			      tagType, destType) ? 0 : 1);
}

void testPN() {
	const char *e[] = {
		"<sip:706912@sip.odorik.cz>;tag=1645803335",
		"\"A. G. Bell\" <sip:agb@bell-telephone.com> ;tag=a48s",
		"Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8",
		"sip:+12125551212@server.phone2net.com;tag=887s",
		"\"Call Manager\" <sip:10.45.55.17>;tag=486739~121a78c0-1834-4f45-9aef-960da02c9618-29204586",
		"sip:*@10.99.1.6:5060",
		"sip:1234@Abc",
		"<urn:service:sos>",
		"sip:ravsgc01.ims.opt.nc",
		"<sip:ravsgc01.ims.opt.nc>",
		"<tel:011444444;phone-context=ims.mnc010.mcc283.3gppnetwork.org>",
		"<tel:+33970660010>;tag=SDoduqd01-d87d01d6-0000-0bff-0000-0000",
		"tel:+971543274144;tag=p65545t1614290087m188413c29442s3_859345611-1187759289",
		"ů§jk§ůjsip:kljahfkjlahld",
		"klhkjlh"
	};
	for(unsigned i = 0; i < sizeof(e) / sizeof(e[0]); i++) {
		char rslt[1000];
		unsigned int rslt_len = sizeof(rslt);
		
		cout << endl << e[i] << endl;
		
		parse_peername(e[i], strlen(e[i]),
			       1,
			       rslt, rslt_len,
			       ppntt_undefined, ppndt_undefined);
		cout << "peername: " << rslt << endl;
		parse_peername(e[i], strlen(e[i]),
			       2,
			       rslt, rslt_len,
			       ppntt_undefined, ppndt_undefined);
		cout << "peercname: " << rslt << endl;
		parse_peername(e[i], strlen(e[i]),
			       3,
			       rslt, rslt_len,
			       ppntt_undefined, ppndt_undefined);
		cout << "domain: " << rslt << endl;
		parse_peername(e[i], strlen(e[i]),
			       4,
			       rslt, rslt_len,
			       ppntt_undefined, ppndt_undefined);
		cout << "tag: " << rslt << endl;
		
		
	}
}

/*
int get_sip_peername(packet_s_process *packetS, const char *tag, const char *tag2, 
		     char *peername, unsigned int peername_len){
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
	bool r2_ok = false;
	char *peername_tag = gettag_sip(packetS, tag, tag2, &peername_tag_len);
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
	if ((r2 = (unsigned long)memmem((char*)r, peername_tag_len - (r - (unsigned long)peername_tag), prefixes[i_prefix].type == 0 ? "@" : ">", 1)) == 0){
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

int get_sip_peercnam(packet_s_process *packetS, const char *tag, const char *tag2, 
		     char *peername, unsigned int peername_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag_sip(packetS, tag, tag2, &peername_tag_len);
	if(!peername_tag_len) {
		goto fail_exit;
	}

// three types of URI
// 1)     "A. G. Bell" <sip:agb@bell-telephone.com> ;tag=a48s
// 2)     Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8
// 3)     sip:+12125551212@server.phone2net.com;tag=887s

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

int get_sip_domain(packet_s_process *packetS, const char *tag, const char *tag2,
		   char *domain, unsigned int domain_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag_sip(packetS, tag, tag2, &peername_tag_len);
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
		if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len + 1, CR_STR, 1)) == 0){
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
*/

int get_sip_headerstr(packet_s_process *packetS, const char *tag, const char *tag2,
		      char *headerstr, unsigned int headerstr_len){
        unsigned long headerstr_tag_len;
        char *header_tag = gettag_sip(packetS, tag, tag2, &headerstr_tag_len);
        if(!headerstr_tag_len) {
                goto fail_exit;
        }
        memcpy(headerstr, header_tag, MIN(headerstr_tag_len, headerstr_len));
        headerstr[MIN(headerstr_tag_len, headerstr_len - 1)] = '\0';
        return 0;
fail_exit:
	strcpy(headerstr, "");
	return 1;
}

int get_sip_via_ip_hostname(packet_s_process *packetS, char *ip_hostname, unsigned int ip_hostname_len){
	unsigned long via_tag_len;
	char *p1, *p2;
	int len;
	char *via_tag = gettag_sip(packetS, "via:", "v:", &via_tag_len);
	if (!via_tag) {
		goto fail_exit;
	}
	if (!(p1 = (char*)memmem(via_tag, via_tag_len, " ", 1))) {
		goto fail_exit;
	}
	p1++;
	if (!(p2 = (char*)memmem(p1, (via_tag_len - (p1 - via_tag)), ":", 1))) {
		goto fail_exit;
	}
	len = (p2 - p1 > ip_hostname_len) ? ip_hostname_len : p2 - p1;
	memcpy(ip_hostname, p1, len);
	*(ip_hostname + len) = '\0';
	return 0;
fail_exit:
	strcpy(ip_hostname, "");
	return 1;
}

int get_sip_branch(packet_s_process *packetS, const char *tag, char *branch, unsigned int branch_len){
	unsigned long branch_tag_len;
	char *branch_tag = gettag_sip(packetS, tag, &branch_tag_len);
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
       else if(strcasecmp(mimeSubtype,"VX-OPUS") == 0)
	       return PAYLOAD_VXOPUS;
       else if(strcasecmp(mimeSubtype,"AMR") == 0)
	       return PAYLOAD_AMR;
       else if(strcasecmp(mimeSubtype,"AMR-WB") == 0)
	       return PAYLOAD_AMRWB;
       else if(strcasecmp(mimeSubtype,"telephone-event") == 0)
	       return PAYLOAD_TELEVENT;
       else if(strcasecmp(mimeSubtype,"MP4A-LATM") == 0)
	       return PAYLOAD_MP4ALATM128;
       else if(strcasecmp(mimeSubtype,"G726-16") == 0)
	       return PAYLOAD_G72616;
       else if(strcasecmp(mimeSubtype,"G726-24") == 0)
	       return PAYLOAD_G72624;
       else if(strcasecmp(mimeSubtype,"G726-32") == 0)
	       return PAYLOAD_G72632;
       else if(strcasecmp(mimeSubtype,"G726-40") == 0)
	       return PAYLOAD_G72640;
       else if(strcasecmp(mimeSubtype,"AAL2-G726-16") == 0)
	       return PAYLOAD_AAL2_G72616;
       else if(strcasecmp(mimeSubtype,"AAL2-G726-24") == 0)
	       return PAYLOAD_AAL2_G72624;
       else if(strcasecmp(mimeSubtype,"AAL2-G726-32") == 0)
	       return PAYLOAD_AAL2_G72632;
       else if(strcasecmp(mimeSubtype,"AAL2-G726-40") == 0)
	       return PAYLOAD_AAL2_G72640;
       else
	       return 0;
}

int get_rtpmap_from_sdp(char *sdp_text, unsigned long len, bool is_video, RTPMAP *rtpmap, bool *existsPayloadTelevent){
	unsigned long l = 0;
	char *s, *z;
	int payload;
	int codec;
	char mimeSubtype[255];
	int i = 0;
	int rate = 0;

	s = sdp_text;
	
	do {
		s = _gettag(s, len - (s - sdp_text), "a=rtpmap:", &l);
		
		char zchr;
		if(l && 
		   ((z = strnchr(s, CR_CHAR, len - (s - sdp_text))) ||
		    (z = strnchr(s, LF_CHAR, len - (s - sdp_text))))) {
			zchr = *z;
			*z = '\0';
		} else {
			break;
		}
		payload = 0;
		codec = 0;
		if (sscanf(s, "%30u %254[^/]/%d", &payload, mimeSubtype, &rate) == 3) {
			// store payload type and its codec into one integer with 1000 offset
			if(is_video) {
				codec = PAYLOAD_VIDEO;
			} else {
				codec = mimeSubtypeToInt(mimeSubtype);
				if(codec == PAYLOAD_G7221) {
					switch(rate) {
						case 8000:
							codec = PAYLOAD_G72218;
							break;
						case 12000:
							codec = PAYLOAD_G722112;
							break;
						case 16000:
							codec = PAYLOAD_G722116;
							break;
						case 24000:
							codec = PAYLOAD_G722124;
							break;
						case 32000:
							codec = PAYLOAD_G722132;
							break;
						case 48000:
							codec = PAYLOAD_G722148;
							break;
					}
				} else if(codec == PAYLOAD_SILK) {
					switch(rate) {
						case 8000:
							codec = PAYLOAD_SILK8;
							break;
						case 12000:
							codec = PAYLOAD_SILK12;
							break;
						case 16000:
							codec = PAYLOAD_SILK16;
							break;
						case 24000:
							codec = PAYLOAD_SILK24;
							break;
					}
				} else if(codec == PAYLOAD_ISAC) {
					switch(rate) {
						case 16000:
							codec = PAYLOAD_ISAC16;
							break;
						case 32000:
							codec = PAYLOAD_ISAC32;
							break;
					}
				} else if(codec == PAYLOAD_OPUS) {
					switch(rate) {
						case 8000:
							codec = PAYLOAD_OPUS8;
							break;
						case 12000:
							codec = PAYLOAD_OPUS12;
							break;
						case 16000:
							codec = PAYLOAD_OPUS16;
							break;
						case 24000:
							codec = PAYLOAD_OPUS24;
							break;
						case 48000:
							codec = PAYLOAD_OPUS48;
							break;
					}
				} else if(codec == PAYLOAD_XOPUS) {
					switch(rate) {
						case 8000:
							codec = PAYLOAD_XOPUS8;
							break;
						case 12000:
							codec = PAYLOAD_XOPUS12;
							break;
						case 16000:
							codec = PAYLOAD_XOPUS16;
							break;
						case 24000:
							codec = PAYLOAD_XOPUS24;
							break;
						case 48000:
							codec = PAYLOAD_XOPUS48;
							break;
					}
				} else if(codec == PAYLOAD_VXOPUS) {
					switch(rate) {
						case 8000:
							codec = PAYLOAD_VXOPUS8;
							break;
						case 12000:
							codec = PAYLOAD_VXOPUS12;
							break;
						case 16000:
							codec = PAYLOAD_VXOPUS16;
							break;
						case 24000:
							codec = PAYLOAD_VXOPUS24;
							break;
						case 48000:
							codec = PAYLOAD_VXOPUS48;
							break;
					}
				} else if(codec == PAYLOAD_MP4ALATM128) {
					switch(rate) {
						case 128000:
							codec = PAYLOAD_MP4ALATM128;
							break;
						case 64000:
							codec = PAYLOAD_MP4ALATM64;
							break;
					}
				} else if(codec == PAYLOAD_TELEVENT && existsPayloadTelevent) {
					*existsPayloadTelevent = true;
				}
			}
		}
		// return CR/LF into sdp_text
		*z = zchr;
		if(codec || payload) {
			rtpmap[i].codec = codec;
			rtpmap[i].payload = payload;
			if(codec == PAYLOAD_ILBC) {
				char tagFmtpWithPayload[100];
				snprintf(tagFmtpWithPayload, sizeof(tagFmtpWithPayload), "a=fmtp:%i", payload);
				char *s = _gettag(sdp_text, len, tagFmtpWithPayload , &l);
				rtpmap[i].frame_size = s && strncasestr(s, "mode=20", l) ? 20 : 30;
			}
			i++;
			//printf("PAYLOAD: rtpmap[%d]:%d payload:%d, mimeSubtype [%d] [%s]\n", i, rtpmap[i], payload, codec, mimeSubtype);
		}
	 } while(l && i < (MAX_RTPMAP - 2));
	 rtpmap[i].clear(); //terminate rtpmap field
	 return 0;
}

int get_ip_port_from_sdp(Call *call, packet_s_process *packetS, char *sdp_text, size_t sdp_text_len,
			 int sip_method, char *sessid, 
			 s_sdp_media_data *sdp_media_data,
			 list<s_sdp_media_data*> **next_sdp_media_data) {
	unsigned long l;
	char *s;

	if(!sdp_text_len) {
		sdp_text_len = strlen(sdp_text);
	}
	
	s = _gettag(sdp_text,sdp_text_len, "o=", &l);
	if(l == 0) return 0;
	while(l > 0 && *s != ' ') {
		++s;
		--l;
	}
	if(l <= 1) return 0;
	++s;
	--l;
	unsigned long ispace = 0;
	char *space = s;
	while(ispace < l - 1 && *space != ' ') {
		++ispace;
		++space;
	}
	unsigned sessid_length = MIN(ispace, MAXLEN_SDP_SESSID - 1);
	memcpy(sessid, s, sessid_length);
	sessid[sessid_length] = 0;
	
	vmIP ip;
	s = _gettag(sdp_text, sdp_text_len,
		    packetS->saddr_().is_v6() ? "c=IN IP6 " : "c=IN IP4 ",
		    &l);
	if(l > 0) {
		char ip_str[IP_STR_MAX_LENGTH];
		unsigned ip_length = MIN(l, IP_STR_MAX_LENGTH - 1);
		memcpy(ip_str, s, ip_length);
		ip_str[ip_length] = 0;
		ip.setFromString(ip_str);
	}
	
	unsigned sdp_media_start_max = 10;
	unsigned sdp_media_start_count = 0;
	char *sdp_media_start[sdp_media_start_max];
	e_sdp_media_type sdp_media_type[sdp_media_start_max];
	vmPort sdp_media_port[sdp_media_start_max];
	while(sdp_media_start_count < sdp_media_start_max) {
		s = _gettag(sdp_media_start_count ? sdp_media_start[sdp_media_start_count - 1] + 1 : sdp_text,
			    sdp_text_len - (sdp_media_start_count ? sdp_media_start[sdp_media_start_count - 1] + 1 - sdp_text: 0), 
			    "\nm=", &l);
		if(l > 0) {
			e_sdp_media_type media_type = l > 5 ? 
						       (!strncasecmp(s, "audio", 5) ? sdp_media_type_audio :
							!strncasecmp(s, "image", 5) ? sdp_media_type_image :
							!strncasecmp(s, "video", 5) ? sdp_media_type_video :
							l > 11 && !strncasecmp(s, "application", 11) ? sdp_media_type_application : sdp_media_type_na) :
						       sdp_media_type_na;
			while(isalpha(*s)) {
				++s;
			}
			if(*s == ' ') {
				++s;
			}
			vmPort port;
			if(port.setFromString(s).isSet()) {
				sdp_media_start[sdp_media_start_count] = s;
				sdp_media_type[sdp_media_start_count] = media_type;
				sdp_media_port[sdp_media_start_count] = port;
				++sdp_media_start_count;
			} else {
				break;
			}
		} else {
			break;
		}
	}
	
	unsigned sdp_media_counter = 0;
	for(unsigned sdp_media_i = 0; sdp_media_i < sdp_media_start_count; sdp_media_i++) {
	 
		if(sdp_media_type[sdp_media_i] == sdp_media_type_video && !processing_rtp_video(call)) {
			continue;
		}
		
		char *sdp_media_text = sdp_media_start[sdp_media_i];
		unsigned sdp_media_text_len = sdp_media_i < sdp_media_start_count - 1 ?
					       sdp_media_start[sdp_media_i + 1] - sdp_media_start[sdp_media_i] :
					       sdp_text_len - (sdp_media_start[sdp_media_i] - sdp_text);
					       
		e_sdp_protocol sdp_protocol = sdp_proto_na;
		char *pointToBeginProtocol = strnchr(sdp_media_text, ' ', sdp_media_text_len);
		if(pointToBeginProtocol) {
			++pointToBeginProtocol;
			char *pointToEndProtocol = strnchr(pointToBeginProtocol, ' ', sdp_media_text_len - (pointToBeginProtocol - sdp_media_text));
			unsigned lengthProtocol = pointToEndProtocol ? 
						   pointToEndProtocol - pointToBeginProtocol : 
						   sdp_media_text_len - (pointToBeginProtocol - sdp_media_text);
			if(lengthProtocol > 0 && lengthProtocol < 100) {
				static struct {
					const char *protocol_str;
					e_sdp_protocol protocol;
				} sdp_protocols[] = {
					 { "RTP/AVP", sdp_proto_rtp }, // RFC 4566
					 { "UDPTL", sdp_proto_t38 }, // Note: IANA registry contains lower case
					 { "RTP/AVPF", sdp_proto_rtp }, // RFC 4585
					 { "RTP/SAVP", sdp_proto_srtp }, // RFC 3711
					 { "RTP/SAVPF", sdp_proto_srtp }, // RFC 5124
					 { "UDP/TLS/RTP/SAVP", sdp_proto_srtp }, // RFC 5764
					 { "UDP/TLS/RTP/SAVPF", sdp_proto_srtp }, // RFC 5764
					 { "msrp/tcp", sdp_proto_msrp }, // Not in IANA, where is this from?
					 { "UDPSPRT", sdp_proto_sprt }, // Not in IANA, but draft-rajeshkumar-avt-v150-registration-00
					 { "TCP/MRCPv2", sdp_proto_tcp_mrcpv2 }
				};
				for(unsigned i = 0; i < sizeof(sdp_protocols) / sizeof(sdp_protocols[0]); i++) {
					if(!strncasecmp(pointToBeginProtocol, sdp_protocols[i].protocol_str, lengthProtocol) &&
					   lengthProtocol == strlen(sdp_protocols[i].protocol_str)) {
						sdp_protocol = sdp_protocols[i].protocol;
					}
				}
			}
		}
		
		if(sdp_media_type[sdp_media_i] == sdp_media_type_application && 
		   !(sdp_protocol == sdp_proto_tcp_mrcpv2 && cFilters::saveMrcp())) {
			continue;
		}
					       
		s_sdp_media_data *sdp_media_data_item; 
		if(sdp_media_counter == 0) {
			sdp_media_data_item = sdp_media_data;
		} else {
			if(sdp_media_counter == 1) {
				*next_sdp_media_data = new FILE_LINE(0) list<s_sdp_media_data*>;
			}
			sdp_media_data_item = new FILE_LINE(0) s_sdp_media_data;
		}
		
		sdp_media_data_item->ip = ip;
		sdp_media_data_item->port = sdp_media_port[sdp_media_i];
		sdp_media_data_item->sdp_flags.media_type = sdp_media_type[sdp_media_i];
		
		sdp_media_data_item->sdp_flags.protocol = sdp_protocol;
		
		if(sdp_media_i > 0) {
			s = _gettag(sdp_media_text, sdp_media_text_len,
				    packetS->saddr_().is_v6() ? "c=IN IP6 " : "c=IN IP4 ",
				    &l);
			if(l > 0) {
				char ip_str[IP_STR_MAX_LENGTH];
				unsigned ip_length = MIN(l, IP_STR_MAX_LENGTH - 1);
				memcpy(ip_str, s, ip_length);
				ip_str[ip_length] = 0;
				vmIP ip;
				if(ip.setFromString(ip_str)) {
					sdp_media_data_item->ip = ip;
				}
			}
		}
		
		s = _gettag(sdp_media_text, sdp_media_text_len, "a=label:", &l);
		if(l > 0) {
			unsigned label_length = MIN(l, MAXLEN_SDP_LABEL - 1);
			memcpy(sdp_media_data_item->label, s, label_length);
			sdp_media_data_item->label[label_length] = 0;
		}
		
		if(sdp_media_data_item->sdp_flags.protocol == sdp_proto_srtp) {
			s = _gettag(sdp_media_text, sdp_media_text_len, "a=crypto:", &l);
			if(l > 0) {
				char *cryptoContent = s;
				unsigned cryptoContentLength = l;
				do {
					char *pointToParam = s;
					unsigned countParams = 0;
					srtp_crypto_config crypto;
					do {
						++countParams;
						char *pointToSeparator = strnchr(pointToParam, ' ', cryptoContentLength - (pointToParam - cryptoContent));
						unsigned lengthParam = pointToSeparator ? pointToSeparator - pointToParam : cryptoContentLength - (pointToParam - cryptoContent);
						switch(countParams) {
						case 1:
							crypto.tag = atoi(pointToParam);
							break;
						case 2:
							crypto.suite = string(pointToParam, lengthParam);
							break;
						case 3:
							if(!strncasecmp(pointToParam, "inline:", 7)) {
								pointToParam += 7;
								lengthParam -= 7;
							}
							char *lifeTimeSeparator = strnchr(pointToParam, '|', lengthParam);
							crypto.key = string(pointToParam, lifeTimeSeparator ? (lifeTimeSeparator - pointToParam) : lengthParam);
							break;
						}
						pointToParam = pointToSeparator ? pointToSeparator + 1 : NULL;
					} while(pointToParam && countParams < 3);
					if(crypto.suite.length() && crypto.key.length()) {
						if(!sdp_media_data_item->srtp_crypto_config_list) {
							sdp_media_data_item->srtp_crypto_config_list = new FILE_LINE(0) list<srtp_crypto_config>;
						}
						sdp_media_data_item->srtp_crypto_config_list->push_back(crypto);
					}
					s = _gettag(s, sdp_media_text_len - (s - sdp_media_text), "a=crypto:", &l);
					if(l > 0) {
						cryptoContent = s;
						cryptoContentLength = l;
					} else {
						cryptoContent = NULL;
					}
				}
				while(cryptoContent);
			} else {
				s = _gettag(sdp_media_text, sdp_media_text_len, "a=fingerprint:", &l);
				if(l > 0) {
					if(!sdp_media_data_item->srtp_fingerprint) {
						sdp_media_data_item->srtp_fingerprint = new FILE_LINE(0) string;
					}
					*sdp_media_data_item->srtp_fingerprint =  string(s, l);
				} else {
					s = _gettag(sdp_text, sdp_media_start[0] - sdp_text, "a=fingerprint:", &l);
					if(l > 0) {
						if(!sdp_media_data_item->srtp_fingerprint) {
							sdp_media_data_item->srtp_fingerprint = new FILE_LINE(0) string;
						}
						*sdp_media_data_item->srtp_fingerprint =  string(s, l);
					}
				}
			}
		}
		
		if(memmem(sdp_media_text, sdp_media_text_len, "a=rtcp-mux", 10)) {
			sdp_media_data_item->sdp_flags.rtcp_mux = 1;
			call->use_rtcp_mux = true;
		}
		
		bool sdp_sendonly = false;
		bool sdp_sendrecv = false;
		if(memmem(sdp_media_text, sdp_media_text_len, "a=sendonly", 10)) {
			call->use_sdp_sendonly = true;
			if (sip_method == INVITE)
				sdp_sendonly = true;
		}
		if (sip_method == INVITE) {
			if(memmem(sdp_media_text, sdp_media_text_len, "a=sendrecv", 10))
				sdp_sendrecv = true;

			call->HandleHold(sdp_sendonly, sdp_sendrecv);
		}
		
		if(!sdp_media_data_item->ip.isSet() && memmem(sdp_media_text, sdp_media_text_len, "a=inactive", 10)) {
			sdp_media_data_item->inactive_ip0 = true;
		}
		
		if(sdp_media_type[sdp_media_i] != sdp_media_type_application) {
			get_rtpmap_from_sdp(sdp_media_text, sdp_media_text_len, sdp_media_type[sdp_media_i] == sdp_media_type_video, sdp_media_data_item->rtpmap, &sdp_media_data_item->exists_payload_televent);
		}

		if(sdp_media_counter > 0) {
			(*next_sdp_media_data)->push_back(sdp_media_data_item);
		}
		
		++sdp_media_counter;
		
	}
	
	return sdp_media_counter;
}

int get_value_stringkeyval2(const char *data, unsigned int data_len, const char *key, char *value, int unsigned len) {
	unsigned long r, tag_len;
	char *tmp = gettag(data, data_len, NULL,
			   key, &tag_len);
	//gettag removes CR LF but we need it
	if(!tag_len) {
		goto fail_exit;
	} else {
		//gettag remove trailing CR but we need it 
		tag_len++;
	}
	if((r = (unsigned long)memmem(tmp, tag_len, ";", 1)) == 0 &&
	   (r = (unsigned long)memmem(tmp, tag_len, CR_STR, 1)) == 0 &&
	   (r = (unsigned long)memmem(tmp, tag_len, LF_STR, 1)) == 0) {
		goto fail_exit;
	}
	memcpy(value, (void*)tmp, MIN((r - (unsigned long)tmp), len));
	value[MIN(r - (unsigned long)tmp, len - 1)] = '\0';
	return 0;
fail_exit:
	strcpy(value, "");
	return 1;
}

int get_expires_from_contact(packet_s_process *packetS, const char *from, int *expires){
	char *s;
	unsigned long l;

	if(packetS->sipDataLen < 8) return 1;

	s = gettag_sip_from(packetS, from, "\nContact:", "\nm:", &l);
	if(s) {
		char tmp[128];
		int res = get_value_stringkeyval2(s, l + 2, "expires=", tmp, sizeof(tmp));
		if(res) {
			// not found, try again in case there is more Contact headers
			return get_expires_from_contact(packetS, s, expires);
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

inline
void add_to_rtp_thread_queue(Call *call, packet_s_process_0 *packetS,
			     int iscaller, bool find_by_dest, int is_rtcp, bool stream_in_multiple_calls, s_sdp_flags_base sdp_flags, int enable_save_packet, 
			     int preSyncRtp = 0, int threadIndex = 0) {
	if(is_terminating()) {
		return;
	}
	if(call->typeIsNot(INVITE) && call->typeIsNot(SKINNY_NEW) && call->typeIsNot(MGCP)) {
		static u_int64_t lastTimeSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			syslog(LOG_ERR, "incorrect call type in add_to_rtp_thread_queue: %i, saddr %s daddr %s sport %u dport %u",
			       call->getTypeBase(),
			       packetS->saddr_().getString().c_str(), packetS->daddr_().getString().c_str(),
			       packetS->source_().getPort(), packetS->dest_().getPort());
			lastTimeSyslog = actTime;
		}
		if(preSyncRtp) {
			__sync_sub_and_fetch(&call->rtppacketsinqueue, 1);
		}
		PACKET_S_PROCESS_DESTROY(&packetS);
		return;
	}
	if(!preSyncRtp) {
		__sync_add_and_fetch(&call->rtppacketsinqueue, 1);
	}
	rtp_read_thread *read_thread = &(rtp_threads[call->thread_num]);
	read_thread->push(call, packetS, iscaller, find_by_dest, is_rtcp, stream_in_multiple_calls, sdp_flags, enable_save_packet, threadIndex);
}


static volatile int _sync_add_remove_rtp_threads;
void lock_add_remove_rtp_threads() {
	while(__sync_lock_test_and_set(&_sync_add_remove_rtp_threads, 1));
}

void unlock_add_remove_rtp_threads() {
	__sync_lock_release(&_sync_add_remove_rtp_threads);
}

void *rtp_read_thread_func(void *arg) {
	rtp_read_thread *read_thread = (rtp_read_thread*)arg;
	read_thread->threadId = get_unix_tid();
	read_thread->last_use_time_s = getTimeMS_rdtsc() / 1000;
	unsigned int usleepCounter = 0;
	unsigned long usleepSumTime = 0;
	unsigned long usleepSumTime_lastPush = 0;
	while(!is_terminating() && !is_readend()) {
		if(read_thread->qring[read_thread->readit]->used == 1) {
			rtp_read_thread::batch_packet_rtp *batch = read_thread->qring[read_thread->readit];
			__SYNC_LOCK(read_thread->count_lock_sync);
			unsigned count = batch->count;
			__SYNC_UNLOCK(read_thread->count_lock_sync);
			for(unsigned batch_index = 0; batch_index < count && !is_readend(); batch_index++) {
				read_thread->last_use_time_s = getTimeMS_rdtsc() / 1000;
				bool rslt_read_rtp = false;
				rtp_packet_pcap_queue *rtpp_pq = &batch->batch[batch_index];
				if(!sverb.disable_read_rtp) {
					if(rtpp_pq->is_rtcp) {
						rslt_read_rtp = rtpp_pq->call->read_rtcp(rtpp_pq->packet, rtpp_pq->iscaller, rtpp_pq->save_packet);
					} else {
						rslt_read_rtp = rtpp_pq->call->read_rtp(rtpp_pq->packet, rtpp_pq->iscaller, rtpp_pq->find_by_dest, rtpp_pq->stream_in_multiple_calls, rtpp_pq->sdp_flags, rtpp_pq->save_packet,
											rtpp_pq->packet->block_store && rtpp_pq->packet->block_store->ifname[0] ? rtpp_pq->packet->block_store->ifname : NULL);
					}
				}
				rtpp_pq->call->shift_destroy_call_at(rtpp_pq->packet->getTime_s());
				if(rslt_read_rtp) {
					if(rtpp_pq->is_rtcp) {
						rtpp_pq->call->set_last_rtcp_packet_time_us(rtpp_pq->packet->getTimeUS());
					} else {
						rtpp_pq->call->set_last_rtp_packet_time_us(rtpp_pq->packet->getTimeUS());
					}
				}
				rtpp_pq->packet->blockstore_addflag(71 /*pb lock flag*/);
				//PACKET_S_PROCESS_DESTROY(&rtpp_pq->packet);
				PACKET_S_PROCESS_PUSH_TO_STACK(&rtpp_pq->packet, 60 + read_thread->threadNum);
				__sync_sub_and_fetch(&rtpp_pq->call->rtppacketsinqueue, 1);
			}
			#if RQUEUE_SAFE
				__SYNC_NULL(batch->count);
				__SYNC_NULL(batch->used);
				__SYNC_INCR(read_thread->readit, read_thread->qring_length);
			#else
				batch->count = 0;
				__sync_sub_and_fetch(&batch->used, 1);
				if((read_thread->readit + 1) == read_thread->qring_length) {
					read_thread->readit = 0;
				} else {
					read_thread->readit++;
				}
			#endif
			usleepCounter = 0;
			usleepSumTime = 0;
			usleepSumTime_lastPush = 0;
		} else {
			if(read_thread->remove_flag &&
				  ((getTimeMS_rdtsc() / 1000) > (read_thread->last_use_time_s + (opt_ipaccount ? 10 : 60)))) {
				lock_add_remove_rtp_threads();
				if(read_thread->remove_flag && !read_thread->calls) {
					break;
				}
				unlock_add_remove_rtp_threads();
				if(!opt_t2_boost && read_thread->remove_flag &&
				   (opt_ipaccount || 
				    (usleepSumTime > usleepSumTime_lastPush + 100000))) {
					read_thread->push_batch();
					usleepSumTime_lastPush = usleepSumTime;
				}
			}
			// no packet to read, wait and try again
			usleepSumTime += USLEEP_C(rtp_qring_usleep, usleepCounter++);
		}
	}
	
	if(read_thread->remove_flag) {
		read_thread->remove_flag = false;
		read_thread->last_use_time_s = 0;
		read_thread->calls = 0;
		memset(read_thread->threadPstatData, 0, sizeof(read_thread->threadPstatData));
	}
	read_thread->thread = 0;
	read_thread->threadId = 0;
	
	unlock_add_remove_rtp_threads();
	
	if(verbosity) {
		syslog(LOG_NOTICE, "end rtp thread %i", read_thread->threadNum);
	}
	
	return NULL;
}

void add_rtp_read_thread() {
	extern int num_threads_start;
	extern int num_threads_max;
	extern volatile int num_threads_active;
	if(num_threads_start == num_threads_max) {
		return;
	}
	lock_add_remove_rtp_threads();
	if(is_enable_rtp_threads() &&
	   num_threads_active > 0 && num_threads_max > 0 &&
	   num_threads_active < num_threads_max) {
		rtp_threads[num_threads_active].remove_flag = false;
		if(!rtp_threads[num_threads_active].threadId) {
			rtp_threads[num_threads_active].threadId = -1;
			rtp_threads[num_threads_active].alloc_qring();
			vm_pthread_create_autodestroy("rtp read",
						      &(rtp_threads[num_threads_active].thread), NULL, rtp_read_thread_func, (void*)&rtp_threads[num_threads_active], __FILE__, __LINE__);
		}
		++num_threads_active;
	}
	unlock_add_remove_rtp_threads();
}

void set_remove_rtp_read_thread() {
	extern int num_threads_start;
	extern int num_threads_max;
	extern volatile int num_threads_active;
	if(num_threads_start == num_threads_max) {
		return;
	}
	lock_add_remove_rtp_threads();
	if(is_enable_rtp_threads() &&
	   num_threads_active > 1 &&
	   (num_threads_active == num_threads_max ||
	    (!rtp_threads[num_threads_active].remove_flag &&
	     !rtp_threads[num_threads_active].threadId))) {
		rtp_threads[num_threads_active - 1].remove_flag = true;
		--num_threads_active;
	}
	unlock_add_remove_rtp_threads();
}

int get_index_rtp_read_thread_min_size() {
	lock_add_remove_rtp_threads();
	extern volatile int num_threads_active;
	size_t minSize = 0;
	int minSizeIndex = -1;
	for(int i = 0; i < num_threads_active; i++) {
		if(rtp_threads[i].threadId > 0 && !rtp_threads[i].remove_flag) {
			size_t size = rtp_threads[i].qring_size();
			if(minSizeIndex == -1 || minSize > size) {
				minSizeIndex = i;
				minSize = size;
			}
		}
	}
	unlock_add_remove_rtp_threads();
	return(minSizeIndex);
}

int get_index_rtp_read_thread_min_calls() {
	lock_add_remove_rtp_threads();
	extern volatile int num_threads_active;
	size_t minCalls = 0;
	int minCallsIndex = -1;
	for(int i = 0; i < num_threads_active; i++) {
		if(rtp_threads[i].threadId > 0 && !rtp_threads[i].remove_flag) {
			u_int32_t calls = rtp_threads[i].calls;
			if(minCallsIndex == -1 || minCalls > calls) {
				minCallsIndex = i;
				minCalls = calls;
			}
		}
	}
	if(minCallsIndex >= 0) {
		__sync_add_and_fetch(&rtp_threads[minCallsIndex].calls, 1);
	}
	unlock_add_remove_rtp_threads();
	return(minCallsIndex);
}

double get_rtp_sum_cpu_usage(double *max) {
	extern int num_threads_max;
	extern volatile int num_threads_active;
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

string get_rtp_threads_cpu_usage(bool callPstat) {
	extern int num_threads_max;
	extern volatile int num_threads_active;
	if(is_enable_rtp_threads() &&
	   num_threads_active > 0 && num_threads_max > 0) {
		ostringstream outStr;
		outStr << fixed;
		int counter = 0;
		for(int i = 0; i < num_threads_active; i++) {
			if(rtp_threads[i].threadId) {
				if(callPstat) {
					if(rtp_threads[i].threadPstatData[0].cpu_total_time) {
						rtp_threads[i].threadPstatData[1] = rtp_threads[i].threadPstatData[0];
					}
					pstat_get_data(rtp_threads[i].threadId, rtp_threads[i].threadPstatData);
				}
				double ucpu_usage, scpu_usage;
				if(rtp_threads[i].threadPstatData[0].cpu_total_time && rtp_threads[i].threadPstatData[1].cpu_total_time) {
					pstat_calc_cpu_usage_pct(
						&rtp_threads[i].threadPstatData[0], &rtp_threads[i].threadPstatData[1],
						&ucpu_usage, &scpu_usage);
					if(counter) {
						outStr << ';';
					}
					outStr << setprecision(1) << (ucpu_usage + scpu_usage) << '%';
					outStr << 'r' << rtp_threads[i].qring_size();
					outStr << 'c' << rtp_threads[i].calls;
					++counter;
				}
			}
		}
		return(outStr.str());
	} else {
		return("");
	}
}

struct s_detect_callerd {
	inline s_detect_callerd() {
		caller[0] = 0;
		called_to[0] = 0;
		called_uri[0] = 0;
		caller_domain[0] = 0;
		called_domain_to[0] = 0;
		called_domain_uri[0] = 0;
		callername[0] = 0;
	}
	inline char *called() {
		return(called_uri[0] && opt_destination_number_mode == 2 ? called_uri : called_to);
	}
	inline char *called_domain() {
		return(called_domain_uri[0] && opt_destination_number_mode == 2 ? called_domain_uri : called_domain_to);
	}
	char caller[1024];
	char called_to[1024];
	char called_uri[1024];
	char caller_domain[1024];
	char called_domain_to[1024];
	char called_domain_uri[1024];
	char callername[256];
};

inline void detect_callerd(packet_s_process *packetS, int sip_method, s_detect_callerd *data) {
	
	bool anonymous_useRemotePartyID = false;
	bool anonymous_usePPreferredIdentity = false;
	bool anonymous_usePAssertedIdentity = false;
	bool anonymous_useFrom = false;
	bool caller_useRemotePartyID = false;
	bool caller_usePPreferredIdentity = false;
	bool caller_usePAssertedIdentity = false;
	bool caller_useFrom = false;
	
	// caller number
	
	if (opt_ppreferredidentity || opt_remotepartyid || opt_passertedidentity) {
		if (opt_remotepartypriority && opt_remotepartyid) {
			//Caller number is taken from headers (in this order) Remote-Party-ID,P-Asserted-Identity,P-Preferred-Identity,From,F
			if(!get_sip_peername(packetS, "\nRemote-Party-ID:", NULL, data->caller, sizeof(data->caller), ppntt_remote_party, ppndt_caller) &&
			  data->caller[0] != '\0') {
				caller_useRemotePartyID = true;
			} else {
				if(opt_passertedidentity && !get_sip_peername(packetS, "\nP-Assserted-Identity:", NULL, data->caller, sizeof(data->caller), ppntt_asserted_identity, ppndt_caller) &&
				  data->caller[0] != '\0') {
					caller_usePAssertedIdentity = true;
				} else {
					if(opt_ppreferredidentity && !get_sip_peername(packetS, "\nP-Preferred-Identity:", NULL, data->caller, sizeof(data->caller), ppntt_preferred_identity, ppndt_caller) &&
					  data->caller[0] != '\0') {
						caller_usePPreferredIdentity = true;
					} else {
						caller_useFrom = true;
						get_sip_peername(packetS, "\nFrom:", "\nf:", data->caller, sizeof(data->caller), ppntt_from, ppndt_caller);
					}
				}
			}
		} else {
			//Caller number is taken from headers (in this order) P-Asserted-Identity, P-Preferred-Identity, Remote-Party-ID,From, F
			if(opt_passertedidentity && !get_sip_peername(packetS, "\nP-Asserted-Identity:", NULL, data->caller, sizeof(data->caller), ppntt_asserted_identity, ppndt_caller) &&
			  data->caller[0] != '\0') {
				caller_usePAssertedIdentity = true;
			} else {
				if(opt_ppreferredidentity && !get_sip_peername(packetS, "\nP-Preferred-Identity:", NULL, data->caller, sizeof(data->caller), ppntt_preferred_identity, ppndt_caller) &&
				  data->caller[0] != '\0') {
					caller_usePPreferredIdentity = true;
				} else {
					if(opt_remotepartyid && !get_sip_peername(packetS, "\nRemote-Party-ID:", NULL, data->caller, sizeof(data->caller), ppntt_remote_party, ppndt_caller) &&
					  data->caller[0] != '\0') {
						caller_useRemotePartyID = true;
					} else {
						caller_useFrom =  true;
						get_sip_peername(packetS, "\nFrom:", "\nf:", data->caller, sizeof(data->caller), ppntt_from, ppndt_caller);
					}
				}
			}
		}
	} else {
		//Caller is taken from header From , F
		caller_useFrom =  true;
		get_sip_peername(packetS, "\nFrom:", "\nf:", data->caller, sizeof(data->caller), ppntt_from, ppndt_caller);
	}

	if (caller_useFrom && !strcasecmp(data->caller, "anonymous")) {
		//if caller is anonymous
		char _caller[1024];
		if(opt_remotepartypriority && !get_sip_peername(packetS, "\nRemote-Party-ID:", NULL, _caller, sizeof(_caller), ppntt_remote_party, ppndt_caller) &&
		   _caller[0] != '\0') {
			strcpy_null_term(data->caller, _caller);
			anonymous_useRemotePartyID = true;
		} else {
			if(opt_passertedidentity && !get_sip_peername(packetS, "\nP-Asserted-Identity:", NULL, _caller, sizeof(_caller), ppntt_asserted_identity, ppndt_caller) &&
			   _caller[0] != '\0') {
				strcpy_null_term(data->caller, _caller);
				anonymous_usePAssertedIdentity = true;
			} else {
				if(opt_ppreferredidentity && !get_sip_peername(packetS, "\nP-Preferred-Identity:", NULL, _caller, sizeof(_caller), ppntt_preferred_identity, ppndt_caller) &&
				   _caller[0] != '\0') {
					strcpy_null_term(data->caller, _caller);
					anonymous_usePPreferredIdentity = true;
				} else {
					if(!opt_remotepartypriority && !get_sip_peername(packetS, "\nRemote-Party-ID:", NULL, _caller, sizeof(_caller), ppntt_remote_party, ppndt_caller) &&
					   _caller[0] != '\0') {
						strcpy_null_term(data->caller, _caller);
						anonymous_useRemotePartyID = true;
					} else {
						anonymous_useFrom = true;
					}
				}
			}
		}
	}

	// called number
	
	get_sip_peername(packetS, "\nTo:", "\nt:", data->called_to, sizeof(data->called_to), ppntt_to, ppndt_called);
	if(sip_method == INVITE && (opt_destination_number_mode == 2 || isSendCallInfoReady())) {
		get_sip_peername(packetS, "INVITE ", NULL, data->called_uri, sizeof(data->called_uri), ppntt_invite, ppndt_called);
	}
	
	// caller domain 
	
	if(anonymous_useFrom || caller_useFrom) {
		get_sip_domain(packetS, "\nFrom:", "\nf:", data->caller_domain, sizeof(data->caller_domain), ppntt_from, ppndt_caller_domain);
	} else {
		if(anonymous_useRemotePartyID || caller_useRemotePartyID) {
			get_sip_domain(packetS, "\nRemote-Party-ID:", NULL, data->caller_domain, sizeof(data->caller_domain), ppntt_remote_party, ppndt_caller_domain);
		} else {
			if (anonymous_usePPreferredIdentity || caller_usePPreferredIdentity) {
				get_sip_domain(packetS, "\nP-Preferred-Identity:", NULL, data->caller_domain, sizeof(data->caller_domain), ppntt_preferred_identity, ppndt_caller_domain);
			} else {
				if (anonymous_usePAssertedIdentity || caller_usePAssertedIdentity) {
					get_sip_domain(packetS, "\nP-Asserted-Identity:", NULL, data->caller_domain, sizeof(data->caller_domain), ppntt_asserted_identity, ppndt_caller_domain);
				}
			}
		}
	}

	// called domain 
	
	get_sip_domain(packetS, "\nTo:", "\nt:", data->called_domain_to, sizeof(data->called_domain_to), ppntt_to, ppndt_called_domain);
	if(sip_method == INVITE && (opt_destination_number_mode == 2 || isSendCallInfoReady())) {
		get_sip_domain(packetS, "INVITE ", NULL, data->called_domain_uri, sizeof(data->called_domain_uri), ppntt_invite, ppndt_called_domain);
	}
	
	// callername
	
	if (caller_useFrom) {
		//try from header
		get_sip_peercnam(packetS, "\nFrom:", "\nf:", data->callername, sizeof(data->callername), ppntt_from, ppndt_caller_name);
	} else {
		if (caller_useRemotePartyID) {
			//try Remote-Party-ID
			get_sip_peercnam(packetS, "\nRemote-Party-ID:", NULL, data->callername, sizeof(data->callername), ppntt_remote_party, ppndt_caller_name);
		} else {
			if (caller_usePPreferredIdentity) {
				//try P-Preferred-Identity
				get_sip_peercnam(packetS, "\nP-Preferred-Identity:", NULL, data->callername, sizeof(data->callername), ppntt_preferred_identity, ppndt_caller_name);
			} else {
				if (caller_usePAssertedIdentity) {
					//try P-Asserted-Identity
					get_sip_peercnam(packetS,  "\nP-Asserted-Identity:", NULL, data->callername, sizeof(data->callername), ppntt_asserted_identity, ppndt_caller_name);
				} else {
					if(anonymous_useRemotePartyID || anonymous_usePPreferredIdentity || anonymous_usePAssertedIdentity) {
						strcpy(data->callername, "anonymous");
					}
				}
			}
		}
	}
}

inline void detect_called_invite(packet_s_process *packetS, char *called_invite, unsigned called_invite_length, bool *detected) {
	if(!detected || !*detected) {
		get_sip_peername(packetS, packetS->sip_method == MESSAGE ? "MESSAGE " : "INVITE ", NULL,
				 called_invite, called_invite_length,
				 packetS->sip_method == MESSAGE ? ppntt_message : ppntt_invite, ppndt_called);
		if(detected) {
			*detected = true;
		}
	}
}

inline void detect_to(packet_s_process *packetS, char *to, unsigned to_length, bool *detected) {
	if(!detected || !*detected) {
		get_sip_peername(packetS, "\nTo:", "\nt:", to, to_length, ppntt_to, ppndt_called);
		if(detected) {
			*detected = true;
		}
	}
}

void detect_to_extern(packet_s_process *packetS, char *to, unsigned to_length, bool *detected) {
	detect_to(packetS, to, to_length, detected);
}

inline void detect_branch(packet_s_process *packetS, char *branch, unsigned branch_length, bool *detected) {
	if(!detected || !*detected) {
		get_sip_branch(packetS, "via:", branch, branch_length);
		if(detected) {
			*detected = true;
		}
	}
}

void detect_branch_extern(packet_s_process *packetS, char *branch, unsigned branch_length, bool *detected) {
	detect_branch(packetS, branch, branch_length, detected);
}

inline unsigned int setCallFlags(unsigned long int flags,
				 vmIP ip_src, vmIP ip_dst,
				 char *caller, char *called,
				 char *caller_domain, char *called_domain,
				 ParsePacket::ppContentsX *parseContents) {
	unsigned long int flags_old = flags;
	cFilters::applyReload();
	IPfilter::add_call_flags(&flags, ip_src, ip_dst);
	if(sverb.dump_call_flags && flags != flags_old) {
		cout << "set flags for ip " << ip_src.getString() << " -> " << ip_dst.getString() << " : " << printCallFlags(flags) << endl;
		flags_old = flags;
	}
	TELNUMfilter::add_call_flags(&flags, caller, called);
	if(sverb.dump_call_flags && flags != flags_old) {
		cout << "set flags for number " << caller << " -> " << called << " : " << printCallFlags(flags) << endl;
		flags_old = flags;
	}
	DOMAINfilter::add_call_flags(&flags, caller_domain, called_domain);
	if(sverb.dump_call_flags && flags != flags_old) {
		cout << "set flags for domain " << caller_domain << " -> " << called_domain << " : " << printCallFlags(flags) << endl;
		flags_old = flags;
	}
	SIP_HEADERfilter::add_call_flags(parseContents, &flags);
	if(sverb.dump_call_flags && flags != flags_old) {
		cout << "set flags for headers : " << printCallFlags(flags) << endl;
		flags_old = flags;
	}
	return(flags);
}

static inline void process_packet__parse_custom_headers(Call *call, packet_s_process *packetS);

inline Call *new_invite_register(packet_s_process *packetS, int sip_method, char *callidstr, int8_t ci = -1) {
 
	if(sverb.sipcallerip_filter[0] &&
	   packetS->saddr_().getString() != sverb.sipcallerip_filter) {
		return(NULL);
	}
	if(sverb.sipcalledip_filter[0] &&
	   packetS->daddr_().getString() != sverb.sipcalledip_filter) {
		return(NULL);
	}
 
	if(opt_callslimit != 0 and opt_callslimit < (calls_counter + registers_counter)) {
		if(verbosity > 0) {
			static u_int64_t lastTimeSyslog = 0;
			u_int64_t actTime = getTimeMS();
			if(actTime - 5 * 60000 > lastTimeSyslog) {
				syslog(LOG_NOTICE, "callslimit[%d] > calls[%d] ignoring call\n", opt_callslimit, calls_counter + registers_counter);
				lastTimeSyslog = actTime;
			}
		}
		return NULL;
	}
	
	extern bool opt_enable_content_type_application_csta_xml;
	if(!opt_enable_content_type_application_csta_xml) {
		unsigned long content_type_length;
		char *content_type = gettag_sip(packetS, "\nContent-Type:", "\nc:", &content_type_length);
		if(content_type && content_type_length <= 1023) {
			if(strncasestr(content_type, "application/csta+xml", content_type_length)) {
				return(NULL);
			}
		}
	}

	s_detect_callerd data_callerd;
	detect_callerd(packetS, sip_method, &data_callerd);
	
	//flags
	unsigned long int flags = 0;
	set_global_flags(flags);
	if(sverb.dump_call_flags) {
		cout << "flags init " << callidstr << " : " << printCallFlags(flags) << endl;
	}
	flags = setCallFlags(flags,
			     packetS->saddr_(), packetS->daddr_(),
			     data_callerd.caller, data_callerd.called(),
			     data_callerd.caller_domain, data_callerd.called_domain(),
			     &packetS->parseContents);
	if(flags & FLAG_SKIPCDR) {
		if(verbosity > 1)
			syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
		return NULL;
	}

	if(packetS->pflags.ssl) {
		glob_ssl_calls++;
	}
	// store this call only if it starts with invite
	Call *call = calltable->add(sip_method, callidstr, min(strlen(callidstr), (size_t)MAX_FNAME), packetS->callid_alternative,
				    packetS->getTimeUS(), packetS->saddr_(), packetS->source_(), 
				    get_pcap_handle(packetS->handle_index), packetS->dlt, packetS->sensor_id_(), ci);
	call->is_ssl = packetS->pflags.ssl;
	call->set_first_packet_time_us(packetS->getTimeUS());
	call->setSipcallerip(packetS->saddr_(), packetS->saddr_(true), packetS->header_ip_protocol(true), packetS->source_(), packetS->get_callid());
	call->setSipcalledip(packetS->daddr_(), packetS->daddr_(true), packetS->header_ip_protocol(true), packetS->dest_(), packetS->get_callid());
	call->lastsipcallerip = packetS->saddr_();
	call->flags = flags;
	call->lastsrcip = packetS->saddr_();
	call->lastdstip = packetS->daddr_();
	call->lastsrcport = packetS->source_();
	call->vlan = packetS->pid.vlan;

	char *s;
	unsigned long l;
	bool use_fbasename_header = false;
	if(opt_fbasename_header[0]) {
		s = gettag_sip(packetS, opt_fbasename_header, &l);
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
		strcpy_null_term(call->fbasename, callidstr);
	}

	/* this logic updates call on the first INVITES */
	if (sip_method == INVITE or sip_method == REGISTER or sip_method == MESSAGE) {
		//geolocation 
		s = gettag_sip(packetS, "\nGeoPosition:", &l);
		if(l && l < 255) {
			char buf[255];
			memcpy(buf, s, l);
			buf[l] = '\0';
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen GeoPosition header: [%s]\n", buf);
			call->geoposition = buf;
		}

		// caller number
		strcpy_null_term(call->caller, data_callerd.caller);

		// called number
		strcpy_null_term(call->called_to, data_callerd.called_to);
		strcpy_null_term(call->called_uri, data_callerd.called_uri);

		// caller domain 
		strcpy_null_term(call->caller_domain, data_callerd.caller_domain);

		// called domain 
		strcpy_null_term(call->called_domain_to, data_callerd.called_domain_to);
		strcpy_null_term(call->called_domain_uri, data_callerd.called_domain_uri);
		
		// callername
		strcpy_null_term(call->callername, data_callerd.callername);

		if (opt_sipalg_detect) {
			char via_ip_hostname[100];
			if (!get_sip_via_ip_hostname(packetS, via_ip_hostname, sizeof(via_ip_hostname))) {
				vmIP via_ip;
				via_ip.setFromString(via_ip_hostname);
				if (via_ip == call->sipcallerip[0]) {
					call->is_sipalg_detected = true;
				}
			}
		}
		if(sip_method == REGISTER) {	
			// destroy all REGISTER from memory within 30 seconds 
			call->destroy_call_at = packetS->getTime_s() + opt_register_timeout;

			// is it first register? set time and src mac if available
			if (call->regrrddiff == -1) {
				call->regrrdstart.tv_sec = packetS->getTime_s();
				call->regrrdstart.tv_usec = packetS->getTime_us();

/*				//Parse ether header for src mac else 0
				if(packetS->dlt == DLT_EN10MB) {
					sll_header *header_sll;
					ether_header *header_eth;
					u_int header_ip_offset;
					int protocol;
					u_int16_t vlan;
					parseEtherHeader(packetS->dlt, (u_char*)packetS->packet,
							 header_sll, header_eth, NULL,
							 header_ip_offset, protocol, vlan);
					call->regsrcmac = (convert_srcmac_ll(header_eth));
					//syslog(LOG_NOTICE,"srcmac from first register: [%llu]\n", call->regsrcmac);
				}
				//End parse ether header
*/			}

			// copy contact num <sip:num@domain>
			s = gettag_sip(packetS, "\nUser-Agent:", &l);
			if(s) {
				memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
				call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
				if(sverb.set_ua) {
					cout << "set a_ua " << call->a_ua << endl;
				}
			}

			get_sip_peername(packetS, "\nContact:", "\nm:", call->contact_num, sizeof(call->contact_num), ppntt_contact, ppndt_contact);
			// copy contact domain <sip:num@domain>
			get_sip_domain(packetS, "\nContact:", "\nm:", call->contact_domain, sizeof(call->contact_domain), ppntt_contact, ppndt_contact_domain);

			// copy Authorization
			for(int pass_authorization = 0; pass_authorization < 2; pass_authorization++) {
				s = gettag_sip(packetS, pass_authorization == 0 ? "\nAuthorization:" : "\nProxy-Authorization:", &l);
				if(s) {
					get_value_stringkeyval(s, packetS->datalen_() - (s - packetS->data_()), "username=\"", call->digest_username, sizeof(call->digest_username));
					get_value_stringkeyval(s, packetS->datalen_() - (s - packetS->data_()), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
					break;
				}
			}
			// get expires header
			s = gettag_sip(packetS, "\nExpires:", &l);
			if(s) {
				char c = s[l];
				s[l] = '\0';
				call->register_expires = atoi(s);
				s[l] = c;
			}
			// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
			get_expires_from_contact(packetS, NULL, &call->register_expires);
/*
			syslog(LOG_NOTICE, "contact_num[%s] contact_domain[%s] from_num[%s] from_name[%s] from_domain[%s] digest_username[%s] digest_realm[%s] expires[%d]\n", 
				call->contact_num, call->contact_domain, call->caller, call->callername, call->caller_domain, 
				call->digest_username, call->digest_realm, call->register_expires);
*/
			if(packetS->pflags.tcp) {
				u_int32_t seq = packetS->tcp_seq();
				if(seq) {
					extern Registers registers;
					if(opt_sip_register == 1 && registers.existsDuplTcpSeqInRegOK(call, seq)) {
						if(sverb.dump_sip) {
							cout << " - skip duplicate tcp seq " << seq
							     << " in register " << call->call_id << endl;
						}
						((Calltable*)calltable)->lock_registers_listMAP();
						map<string, Call*>::iterator registerMAPIT = ((Calltable*)calltable)->registers_listMAP.find(call->call_id);
						if(registerMAPIT != ((Calltable*)calltable)->registers_listMAP.end()) {
							((Calltable*)calltable)->registers_listMAP.erase(registerMAPIT);
						}
						((Calltable*)calltable)->unlock_registers_listMAP();
						delete call;
						return(NULL);
					}
					call->addRegTcpSeq(seq);
				}
			}
		}
		if(opt_enable_fraud && isFraudReady()) {
			if(needCustomHeadersForFraud()) {
				process_packet__parse_custom_headers(call, packetS);
			}
			fraudBeginCall(call, packetS->getTimeval());
		}
		if(sip_method == INVITE) {
			call->seeninvite = true;
#ifdef DEBUG_INVITE
			syslog(LOG_NOTICE, "New call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s] Call-ID[%s]\n", 
				call->sipcallerip, call->sipcalledip, call->caller, call->called, call->fbasename);
#endif
		}
		if(sip_method == MESSAGE) {
			call->seenmessage = true;
		}
		if(sip_method == INVITE || sip_method == MESSAGE) {
			++counter_calls;
		} else if(sip_method == REGISTER) {
			++counter_registers;
		}
	}

	if(opt_norecord_header) {
		s = gettag_sip(packetS, "\nX-VoipMonitor-norecord:", &l);
		if(s) {
			call->stoprecording();
		}
	}

	// opening dump file
	if(call->typeIs(REGISTER) && enable_save_register(call)) {
		call->fname_register = packetS->getTimeUS();
		string pathfilename = call->get_pathfilename(tsf_reg);
		PcapDumper *dumper = enable_pcap_split ? call->getPcapSip() : call->getPcap();
		if(dumper->open(tsf_reg, pathfilename.c_str(), call->useHandle, call->useDlt)) {
			if(verbosity > 3) {
				syslog(LOG_NOTICE,"pcap_filename: [%s]\n", pathfilename.c_str());
			}
		}
	} else if((call->typeIs(INVITE) || call->typeIs(MESSAGE)) && enable_save_sip_rtp(call)) {
		if(enable_pcap_split ? enable_save_sip(call) : enable_save_sip_rtp(call)) {
			string pathfilename = call->get_pathfilename(tsf_sip);
			PcapDumper *dumper = enable_pcap_split ? call->getPcapSip() : call->getPcap();
			if(dumper->open(tsf_sip, pathfilename.c_str(), call->useHandle, call->useDlt)) {
				if(verbosity > 3) {
					syslog(LOG_NOTICE,"pcap_filename: [%s]\n", pathfilename.c_str());
				}
			}
		}
	}

	//check and save CSeq for later to compare with OK 
	if(packetS->cseq.is_set()) {
		if(sip_method == INVITE) {
			call->invitecseq = packetS->cseq;
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen INVITE, CSeq: %u\n", call->invitecseq.number);
			if(sverb.new_invite) {
				ostringstream outStr;
				outStr << "time: "
				       << setw(10)
				       << sqlDateTimeString(packetS->getTime_s()) << " "
				       << packetS->getTime_s() << "."
				       << setw(6)
				       << packetS->getTime_us() << "  ";
				outStr << "ip / port: "
				       << setw(15) << packetS->saddr_().getString()
				       << " / "
				       << setw(5) << packetS->source_()
				       << " -> "
				       << setw(15) << packetS->daddr_().getString()
				       << " / "
				       << setw(5) << packetS->dest_() << "  ";
				outStr << "caller: "
				       << setw(15)
				       << call->caller << "  ";
				outStr << "called: "
				       << setw(15)
				       << call->called() << "  ";
				if(is_read_from_file()) {
					cout << outStr.str() << endl;
				} else {
					syslog(LOG_NOTICE, "%s", outStr.str().c_str());
				}
			}
		} else if(sip_method == MESSAGE) {
			call->messagecseq = packetS->cseq;
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen MESSAGE, CSeq: %u\n", call->messagecseq.number);
		} else if(sip_method == REGISTER) {
			call->registercseq = packetS->cseq;
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen REGISTER, CSeq: %u\n", call->registercseq.number);
		} else if(sip_method == BYE) {
			unsigned indexSetByeCseq = call->setByeCseq(&packetS->cseq);
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen BYE, CSeq: %u\n", call->byecseq[indexSetByeCseq].number);
		}
	}
	
	return call;
}

void process_sdp(Call *call, packet_s_process *packetS, int iscaller, char *from_data, unsigned sdplen, 
		 char *callidstr, char *to, char *branch) {
 
	extern bool opt_disable_process_sdp;
	if(opt_disable_process_sdp) {
		return;
	}
 
	char *sdp;
	if(sdplen) {
		sdp = from_data;
	} else {
		if(call->typeIs(MGCP)) {
			unsigned datalen = packetS->datalen_() - (from_data - packetS->data_());
			sdp = from_data;
			sdplen = datalen;
		} else {
			unsigned datalen = packetS->sipDataLen - (from_data - (packetS->data_() + packetS->sipDataOffset));
			sdp = NULL;
			for(int pass_line_separator = 0; pass_line_separator < 2 && !sdp; pass_line_separator++) {
				sdp = strnstr(from_data, SIP_DBLLINE_SEPARATOR(pass_line_separator == 1), datalen);
				if(sdp) {
					sdp += SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1);
				}
			}
			if(!sdp) return;
			sdplen = datalen - (sdp - from_data);
		}
	}

	char sessid[MAXLEN_SDP_SESSID];
	s_sdp_media_data sdp_media_data;
	list<s_sdp_media_data*> *next_sdp_media_data = NULL;
	if(get_ip_port_from_sdp(call, packetS, sdp, sdplen,
				packetS->sip_method, sessid,
				&sdp_media_data,
				&next_sdp_media_data)) {
		unsigned sdp_media_data_count = 1 + (next_sdp_media_data ? next_sdp_media_data->size() : 0);
		for(unsigned sdp_media_data_i = 0; sdp_media_data_i < sdp_media_data_count; sdp_media_data_i++) {
			s_sdp_media_data *sdp_media_data_item;
			if(sdp_media_data_i == 0) {
				 sdp_media_data_item = &sdp_media_data;
			} else {
				list<s_sdp_media_data*>::iterator iter = next_sdp_media_data->begin();
				for(unsigned i = 0; i < sdp_media_data_i - 1; i++) {
					iter++;
				}
				sdp_media_data_item = *iter;
			}
			if(sdp_media_data_item->ip.isSet() && sdp_media_data_item->port.isSet()) {
				bool ok_ip_port = true;
				if(opt_sdp_ignore_ip_port.size()) {
					for(vector<vmIPport>::iterator iter = opt_sdp_ignore_ip_port.begin(); iter != opt_sdp_ignore_ip_port.end(); iter++) {
						if(iter->ip == sdp_media_data_item->ip && iter->port == sdp_media_data_item->port) {
							ok_ip_port = false;
							break;
						}
					}
				}
				if((opt_sdp_ignore_ip.size() || opt_sdp_ignore_net.size()) &&
				   check_ip_in(sdp_media_data_item->ip, &opt_sdp_ignore_ip, &opt_sdp_ignore_net, false)) {
					ok_ip_port = false;
				}
				if(ok_ip_port) {
					if(sdp_media_data_item->sdp_flags.is_image()) { 
						if(verbosity >= 2){
							syslog(LOG_ERR, "[%s] T38 detected", call->fbasename);
						}
						call->isfax = T38FAX;
					} else {
						if(call->isfax) {
							call->isfax = NOFAX;
						}
					}
					// if rtp-firstleg enabled add RTP only in case the SIP msg belongs to first leg
					if(opt_rtp_firstleg == 0 || 
					   (opt_rtp_firstleg &&
					    ((call->saddr == packetS->saddr_() && call->sport == packetS->source_()) || 
					     (call->saddr == packetS->daddr_() && call->sport == packetS->dest_())))) {
						//printf("sdp [%u] port[%u]\n", tmp_addr, tmp_port);
						call->add_ip_port_hash(packetS->saddr_(), sdp_media_data_item->ip, ip_port_call_info::_ta_base, sdp_media_data_item->port, packetS->getTimeval_pt(), 
								       sessid, sdp_media_data_item->label, sdp_media_data_count > 1, 
								       sdp_media_data_item->srtp_crypto_config_list, sdp_media_data_item->srtp_fingerprint,
								       to, branch, iscaller, sdp_media_data_item->rtpmap, sdp_media_data_item->sdp_flags);
						// check if the IP address is listed in nat_aliases
						vmIP alias = match_nat_aliases(sdp_media_data_item->ip);
						if(alias.isSet()) {
							call->add_ip_port_hash(packetS->saddr_(), alias, ip_port_call_info::_ta_natalias, sdp_media_data_item->port, packetS->getTimeval_pt(), 
									       sessid, sdp_media_data_item->label, sdp_media_data_count > 1, 
									       sdp_media_data_item->srtp_crypto_config_list, sdp_media_data_item->srtp_fingerprint,
									       to, branch, iscaller, sdp_media_data_item->rtpmap, sdp_media_data_item->sdp_flags);
						}
						if(opt_sdp_reverse_ipport) {
							call->add_ip_port_hash(packetS->saddr_(), packetS->saddr_(), ip_port_call_info::_ta_sdp_reverse_ipport, sdp_media_data_item->port, packetS->getTimeval_pt(), 
									       sessid, sdp_media_data_item->label, sdp_media_data_count > 1, 
									       sdp_media_data_item->srtp_crypto_config_list, sdp_media_data_item->srtp_fingerprint,
									       to, branch, iscaller, sdp_media_data_item->rtpmap, sdp_media_data_item->sdp_flags);
						}
					}
				}
			} else if(!sdp_media_data_item->ip.isSet()) {
				if(sdp_media_data_item->inactive_ip0) {
					u_int64_t _forcemark_time = packetS->getTimeUS();
					call->forcemark_lock();
					call->forcemark_time.push_back(_forcemark_time);
					if(sverb.forcemark) {
						cout << "add forcemark (inactive): " << _forcemark_time 
						     << " forcemarks size: " << call->forcemark_time.size() 
						     << endl;
					}
					call->forcemark_unlock();
				}
				int iscaller_index = iscaller_inv_index(iscaller);
				if(!call->sdp_ip0_ports[iscaller_index].size() ||
				   find(call->sdp_ip0_ports[iscaller_index].begin(), call->sdp_ip0_ports[iscaller_index].end(), sdp_media_data_item->port) == call->sdp_ip0_ports[iscaller_index].end()) {
					call->sdp_ip0_ports[iscaller_index].push_back(sdp_media_data_item->port);
				}
			}
			if(packetS->cseq.method == INVITE && sdp_media_data_item->exists_payload_televent) {
				if(packetS->sip_method == INVITE) {
					call->televent_exists_request = true;
				} else if(packetS->sip_method == RES2XX) {
					call->televent_exists_response = true;
				}
			}
			if(sdp_media_data_item->srtp_crypto_config_list) {
				delete sdp_media_data_item->srtp_crypto_config_list;
			}
			if(sdp_media_data_item->srtp_fingerprint) {
				delete sdp_media_data_item->srtp_fingerprint;
			}
			if(sdp_media_data_i > 0) {
				delete sdp_media_data_item;
			}
		}
		if(next_sdp_media_data) {
			delete next_sdp_media_data;
		}
	} else {
		if(verbosity >= 2){
			syslog(LOG_ERR, "callid[%s] Can't get ip/port from SDP:\n%s\n\n", callidstr, sdp);
		}
	}
}

static inline void process_packet__parse_rtcpxr(Call *call, packet_s_process *packetS, timeval tv);
static inline void process_packet__cleanup_calls(timeval *ts, const char *file, int line);
static inline void process_packet__cleanup_registers(timeval *ts);
static inline void process_packet__cleanup_ss7(timeval *ts);
static inline int process_packet__parse_sip_method(char *data, unsigned int datalen, bool *sip_response);
static inline int process_packet__parse_sip_method(packet_s_process *packetS, bool *sip_response);
static inline bool process_packet__parse_cseq(sCseq *cseq, char *cseqstr, unsigned int cseqlen);
static inline bool process_packet__parse_cseq(sCseq *cseq, packet_s_process *packetS);
static inline int parse_packet__last_sip_response(char *data, unsigned int datalen, int sip_method, bool sip_response,
						  char *lastSIPresponse, bool *call_cancel_lsr487);
static inline int parse_packet__last_sip_response(packet_s_process *packetS, int sip_method, bool sip_response,
						  char *lastSIPresponse, bool *call_cancel_lsr487);
static inline void parse_packet__message_content(char *message, unsigned int messageLength,
						 char **rsltMessage, char **rsltMessageInfo, string *rsltDestNumber, string *rsltSrcNumber,
						 unsigned int *rsltDcs, Call::eVoicemail *rsltVoicemail,
						 bool maskMessage = false);
static inline Call *process_packet__merge(packet_s_process *packetS, char *callidstr, int *merged, bool preprocess);
static inline bool checkEqNumbers(Call::sInviteSD_Addr *item1, Call::sInviteSD_Addr *item2);

void process_packet_sip_call(packet_s_process *packetS) {
	
	Call *call = NULL;
	char *s;
	unsigned long l;
	char contenttypestr[1024] = "";
	char *contenttype_data_ptr = NULL;
	int contenttypetaglen = 0;
	int contenttypelen = 0;
	char content_boundary[1024] = "";
	int content_boundary_length = 0;
	bool contenttype_is_rtcpxr = false;
	bool contenttype_is_app_csta_xml = false;
	char lastSIPresponse[128];
	int lastSIPresponseNum = 0;
	bool existInviteSdaddr = false;
	bool reverseInviteSdaddr = false;
	bool reverseInviteConfirmSdaddr = false;
	Call::sInviteSD_Addr *mainInviteForReverse = NULL;
	Call::sInviteSD_Addr *reverseInvite = NULL;
	int inviteSdaddrIndex = -1;
	int iscaller = -1;
	int iscalled = -1;
	bool detectCallerd = false;
	const char *logPacketSipMethodCallDescr = NULL;
	int merged;
	char branch[100] = "";
	bool branch_detected = false;
	char called_invite[1024] = "";
	bool called_invite_detected = false;
	char to[1024] = "";
	bool to_detected = false;
	bool dont_save = false;

	s = gettag_sip(packetS, "\nContent-Type:", "\nc:", &l);
	if(s && l <= 1023) {
		strncpy(contenttypestr, s, l);
		contenttypestr[l] = 0;
		contenttype_data_ptr = s;
		contenttypetaglen = l;
		contenttypelen = l;
		char *pointerToSeparator = strchr(contenttypestr, ';');
		if(pointerToSeparator) {
			*pointerToSeparator = 0;
			contenttypelen = pointerToSeparator - contenttypestr;
			char *pointerToBoundary = strcasestr(pointerToSeparator + 1, "boundary=");
			if(pointerToBoundary) {
				char *boundary = pointerToBoundary + 9;
				while(*boundary && (*boundary == ' ' || *boundary == '"')) {
					++boundary;
				}
				char *boundaryEnd = boundary;
				while(*boundaryEnd && *boundary != ' ' && *boundary != '"' && *boundary != ';') {
					++boundaryEnd;
				}
				if(boundaryEnd > boundary) {
					content_boundary_length = MIN(sizeof(content_boundary) - 1, boundaryEnd - boundary);
					strncpy(content_boundary, boundary, content_boundary_length);
					content_boundary[content_boundary_length] = 0;
				}
			}
		}
		contenttype_is_rtcpxr = strcasestr(contenttypestr, "application/vq-rtcpxr") != NULL;
		contenttype_is_app_csta_xml = strcasestr(contenttypestr, "application/csta+xml") != NULL;
	}
	
	if(opt_enable_fraud && isFraudReady()) {
		char *ua = NULL;
		unsigned long ua_len = 0;
		ua = gettag_sip(packetS, "\nUser-Agent:", &ua_len);
		fraudSipPacket(packetS->saddr_(), packetS->sip_method, packetS->getTimeval(), ua, ua_len);
	}
#if 0
//this block was moved at the end so it will mirror only relevant SIP belonging to real calls 
	if(sipSendSocket && !opt_sip_send_before_packetbuffer) {
		u_int16_t header_length = datalen;
		sipSendSocket->addData(&header_length, 2,
				       data, datalen);
	}
#endif 
	if(sverb.dump_sip) {
		string dump_data(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen);
		if(sverb.dump_sip_line) {
			find_and_replace(dump_data, CR_STR, CR_STR_ESC);
			find_and_replace(dump_data, LF_STR, LF_STR_ESC);
		}
		if(!sverb.dump_sip_without_counter) {
			#if USE_PACKET_NUMBER
			cout << packetS->packet_number
			#else
			cout << (++glob_packet_number)
			#endif
			<< " "
			<< packetS->saddr_().getString() << ':' << packetS->source_() 
			<< " -> "
			<< packetS->daddr_().getString() << ':' << packetS->dest_() 
			<< endl;
			Call *call = packetS->call ? packetS->call : packetS->call_created;
			if(call) {
				cout << call->caller << " -> " << call->called() << endl;
				cout << call->getSipcallerip().getString() << " -> " << call->getSipcalledip().getString() << endl;
			}
		}
		cout << dump_data << endl;
	}

	if(packetS->is_message()) {
		counter_sip_message_packets++;
	}
	
	lastSIPresponseNum = packetS->lastSIPresponseNum;
	strcpy_null_term(lastSIPresponse, packetS->lastSIPresponse);

	// find call
	call = packetS->call;
	merged = packetS->merged;
		
	if(call && lastSIPresponseNum && IS_SIP_RESXXX(packetS->sip_method)) {
		if(call->first_invite_time_us) {
			if(lastSIPresponseNum == 100) {
				if(!call->first_response_100_time_us) {
					call->first_response_100_time_us = packetS->getTimeUS();
				}
			} else {
				if(!call->first_response_xxx_time_us) {
					call->first_response_xxx_time_us = packetS->getTimeUS();
				}
			}
		} else if(call->first_message_time_us && lastSIPresponseNum == 200) {
			if(!call->first_response_200_time_us) {
				call->first_response_200_time_us = packetS->getTimeUS();
			}
		}
	}
	
	if(!call) {
		// packet does not belongs to any call yet
		call = packetS->call_created;
	}
	
	if(!call) {
		save_live_packet(packetS);
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCallDescr = "SIP packet does not belong to any call and it is not INVITE";
		}
		goto endsip;
	}
	
	if(processing_limitations.suppressRtpAllProcessing()) {
		call->suppress_rtp_proc_due_to_insufficient_hw_performance = true;
	}
	
	if(contenttype_is_app_csta_xml) {
		call->exclude_from_active_calls = true;
	}
	
	if(packetS->pid.flags & FLAG_FRAGMENTED) {
		call->sip_fragmented = true;
	}
	
	if((packetS->sip_method == INVITE && call->typeIsOnly(MESSAGE)) ||
	   (packetS->sip_method == MESSAGE && call->typeIsOnly(INVITE))) {
		call->addNextType(packetS->sip_method);
		if(packetS->sip_method == INVITE) {
			call->seeninvite = true;
		} else {
			call->seenmessage = true;
		}
	}
	
	call->max_length_sip_data = max(call->max_length_sip_data, packetS->sipDataLen);
	call->max_length_sip_packet = max(call->max_length_sip_packet, packetS->header_pt->len);
	
	if(!packetS->_createCall) {
		unsigned long int flags = call->flags;
		if(SIP_HEADERfilter::add_call_flags(&packetS->parseContents, &flags)) {
			if((call->flags & FLAG_SAVERTP) && !(flags & FLAG_SAVERTP)) {
				call->flags &= ~FLAG_SAVERTP;
			}
			if((call->flags & FLAG_SAVEAUDIO) && !(flags & FLAG_SAVEAUDIO)) {
				call->flags &= ~FLAG_SAVEAUDIO;
			}
			if(flags & FLAG_SKIPCDR) {
				call->flags |= FLAG_SKIPCDR;
			}
		}
	}
	 
	if(packetS->sip_method == INVITE && !call->first_invite_time_us) {
		call->first_invite_time_us = packetS->getTimeUS();
	} else if(packetS->sip_method == MESSAGE && !call->first_message_time_us) {
		call->first_message_time_us = packetS->getTimeUS();
	}
	
	if(packetS->sip_method == INVITE || packetS->sip_method == MESSAGE) {
		int inviteSdaddrCounter = 0;
		for(list<Call::sInviteSD_Addr>::iterator iter = call->invite_sdaddr.begin(); iter != call->invite_sdaddr.end(); iter++) {
			if(packetS->saddr_() == iter->saddr && packetS->daddr_() == iter->daddr) {
				existInviteSdaddr = true;
				inviteSdaddrIndex = inviteSdaddrCounter;
				++iter->counter;
				break;
			} else if(packetS->daddr_() == iter->saddr && packetS->saddr_() == iter->daddr) {
				reverseInviteSdaddr = true;
				if(opt_sdp_check_direction_ext) {
					mainInviteForReverse = &(*iter);
				}
				++iter->counter_reverse;
				if(sverb.reverse_invite) {
					cout << "reverse invite: invite / " << call->call_id << endl;
				}
				break;
			}
			++inviteSdaddrCounter;
		}
		if(!existInviteSdaddr) {
		        if(!reverseInviteSdaddr) {
				Call::sInviteSD_Addr invite_sd;
				invite_sd.saddr = packetS->saddr_();
				invite_sd.daddr = packetS->daddr_();
				invite_sd.saddr_first = packetS->saddr_(true);
				invite_sd.daddr_first = packetS->daddr_(true);
				invite_sd.saddr_first_protocol =
				invite_sd.daddr_first_protocol = packetS->header_ip_protocol(true);
				invite_sd.sport = packetS->source_();
				invite_sd.dport = packetS->dest_();
				invite_sd.counter = 1;
				if(opt_sdp_check_direction_ext) {
					get_sip_peername(packetS, "\nFrom:", "\nf:", &invite_sd.caller, ppntt_from, ppndt_caller);
					get_sip_peername(packetS, "\nTo:", "\nt:", &invite_sd.called, ppntt_to, ppndt_called);
					get_sip_peername(packetS, "INVITE ", NULL, &invite_sd.called_invite, ppntt_invite, ppndt_called);
					detect_branch(packetS, branch, sizeof(branch), &branch_detected);
					invite_sd.branch = branch;
				}
				call->invite_sdaddr.push_back(invite_sd);
				inviteSdaddrIndex = call->invite_sdaddr.size() - 1;
			} else if(opt_sdp_check_direction_ext) {
				bool existRInviteSdaddr = false;
				for(list<Call::sInviteSD_Addr>::iterator riter = call->rinvite_sdaddr.begin(); riter != call->rinvite_sdaddr.end(); riter++) {
					if(packetS->saddr_() == riter->saddr && packetS->daddr_() == riter->daddr) {
						existRInviteSdaddr = true;
						reverseInvite = &(*riter);
						++riter->counter;
						break;
					}
				}
				if(!existRInviteSdaddr) {
					Call::sInviteSD_Addr rinvite_sd;
					rinvite_sd.saddr = packetS->saddr_();
					rinvite_sd.daddr = packetS->daddr_();
					rinvite_sd.saddr_first = packetS->saddr_(true);
					rinvite_sd.daddr_first = packetS->daddr_(true);
					rinvite_sd.saddr_first_protocol =
					rinvite_sd.daddr_first_protocol = packetS->header_ip_protocol(true);
					rinvite_sd.sport = packetS->source_();
					rinvite_sd.dport = packetS->dest_();
					rinvite_sd.counter = 1;
					get_sip_peername(packetS, "\nFrom:", "\nf:", &rinvite_sd.caller, ppntt_from, ppndt_caller);
					get_sip_peername(packetS, "\nTo:", "\nt:", &rinvite_sd.called, ppntt_to, ppndt_called);
					get_sip_peername(packetS, "INVITE ", NULL, &rinvite_sd.called_invite, ppntt_invite, ppndt_called);
					detect_branch(packetS, branch, sizeof(branch), &branch_detected);
					rinvite_sd.branch = branch;
					call->rinvite_sdaddr.push_back(rinvite_sd);
					list<Call::sInviteSD_Addr>::iterator riter = call->rinvite_sdaddr.end();
					--riter;
					reverseInvite = &(*riter);
				}
			}
		}
		if(inviteSdaddrIndex >= 0) {
			call->invite_sdaddr_order.push_back(inviteSdaddrIndex);
		}
	}
	
	call->check_reset_oneway(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());

	detectCallerd = call->check_is_caller_called(packetS->get_callid(), packetS->sip_method, packetS->cseq.method,
						     packetS->saddr_(), packetS->daddr_(), 
						     packetS->saddr_(true), packetS->daddr_(true), packetS->header_ip_protocol(true),
						     packetS->source_(), packetS->dest_(),
						     &iscaller, &iscalled, 
						     (packetS->sip_method == INVITE && !existInviteSdaddr && !reverseInviteSdaddr) || 
						     IS_SIP_RES18X(packetS->sip_method));
	if(!detectCallerd && packetS->sip_method == RES2XX && packetS->cseq.method == INVITE) {
		detectCallerd = call->check_is_caller_called(packetS->get_callid(), RES2XX_INVITE, 0,
							     packetS->saddr_(), packetS->daddr_(), 
							     packetS->saddr_(true), packetS->daddr_(true), packetS->header_ip_protocol(true),
							     packetS->source_(), packetS->dest_(),
							     &iscaller, &iscalled, 
							     true);
	}
	if(detectCallerd) {
		call->handle_dscp(packetS->header_ip_(), iscaller > 0);
	}
	
	if(opt_norecord_header) {
		s = gettag_sip(packetS, "\nX-VoipMonitor-norecord:", &l);
		if(s) {
			call->stoprecording();
		}
	}

	// we have packet, extend pending destroy requests
	call->shift_destroy_call_at(packetS->getTime_s(), lastSIPresponseNum);

	call->set_last_signal_packet_time_us(packetS->getTimeUS());
	// save lastSIPresponseNum but only if previouse was not 487 (CANCEL) and call was not answered 
	if(lastSIPresponseNum != 0 && lastSIPresponse[0] != '\0' && 
	   (call->typeIsOnly(MESSAGE) ?
		((call->lastSIPresponseNum != 487 && lastSIPresponseNum > call->lastSIPresponseNum) ||
		 (call->lastSIPresponseNum == 407 && lastSIPresponseNum / 100 == 2)) :
		((call->lastSIPresponseNum != 487 || 
		  (call->new_invite_after_lsr487 && lastSIPresponseNum == 200) ||
		  (call->cancel_lsr487 && lastSIPresponseNum/10 == 48)) &&
		 !call->seeninviteok &&
		 !(call->lastSIPresponseNum / 100 == 5 && lastSIPresponseNum / 100 == 5))) &&
	   (lastSIPresponseNum != 200 || packetS->cseq.method == INVITE || packetS->cseq.method == MESSAGE) &&
	   !(call->cancelcseq.is_set() && packetS->cseq.is_set() && packetS->cseq == call->cancelcseq)) {
		strcpy_null_term(call->lastSIPresponse, lastSIPresponse);
		call->lastSIPresponseNum = lastSIPresponseNum;
	}
	if(lastSIPresponseNum != 0 && lastSIPresponse[0] != '\0') {
		call->SIPresponse.push_back(Call::sSipResponse(lastSIPresponse, lastSIPresponseNum));
	}
	
	if(existsColumns.cdr_reason &&
	   (!opt_get_reason_from_bye_cancel || call->reason_q850_cause == 0 || (opt_get_reason_from_bye_cancel && (packetS->sip_method == BYE || packetS->sip_method == CANCEL))) &&
	   !(packetS->sip_method == CANCEL && call->seeninviteok && 
	     (call->called_invite_branch_map.size() > 1 || call->is_multiple_to_branch()))) {
		char *reason = gettag_sip(packetS, "reason:", &l);
		if(reason) {
			char oldEndChar = reason[l];
			reason[l] = 0;
			char *pointerToCause = strcasestr(reason, ";cause=");
			if(pointerToCause && (pointerToCause - reason) < 10) {
				char type[10];
				memcpy(type, reason, pointerToCause - reason);
				type[pointerToCause - reason] = 0;
				//remove spaces from end of string type
				for(int i = pointerToCause - reason - 1; i > 0; i--) {
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
					pointerToText += 7;
					char *pointerToQmark = strchr(pointerToText, '"');
					unsigned int lengthText;
					if (pointerToQmark)
						lengthText = pointerToQmark - pointerToText;
					else
						lengthText = MIN(l - (pointerToText - reason), sizeof(text) - 1);

					memcpy(text, pointerToText, lengthText);
					text[lengthText] = 0;
					if(lengthText > 0 && text[lengthText - 1] == '"') {
						--lengthText;
						text[lengthText] = 0;
					}
				} else {
					snprintf(text, sizeof(text), "%i (text missing)", cause);
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
	
	if(opt_remoteparty_caller[0] || opt_remoteparty_called[0]) {
		unsigned long remotePartyLen = 0;
		char *remoteParty = gettag_sip(packetS, "\nRemote-Party-ID:", &remotePartyLen);
		map<string, string> partyNumber;
		if(remoteParty && remotePartyLen) {
			do {
				char number[1024] = "";
				char party[1024] = "";
				parse_peername(remoteParty, remotePartyLen,
					       1,
					       number, sizeof(number), 
					       ppntt_undefined, ppndt_undefined);
				char *partyBegin = strncasestr(remoteParty, "party=", remotePartyLen);
				if(partyBegin) {
					partyBegin += 6;
					char *partyEnd = partyBegin;
					while(*partyEnd != ';' && (partyEnd - remoteParty) < (int)remotePartyLen) {
						++partyEnd;
					}
					unsigned partyLen = MIN(partyEnd - partyBegin, (int)sizeof(party) - 1);
					strncpy(party, partyBegin, partyLen);
					party[partyLen] = 0;
				}
				if(party[0] && number[0]) {
					partyNumber[party] = number;
				}
				remoteParty = gettag(remoteParty , packetS->sipDataLen - (remoteParty - (packetS->data_()+ packetS->sipDataOffset)), NULL,
						     "\nRemote-Party-ID:", &remotePartyLen);
			}
			while(remoteParty && remotePartyLen);
			if(partyNumber.size()) {
				if(opt_remoteparty_caller[0]) {
					for(unsigned i = 0; i < opt_remoteparty_caller_v.size(); i++) {
						if(partyNumber.find(opt_remoteparty_caller_v[i]) != partyNumber.end()) {
							strcpy_null_term(call->caller, partyNumber[opt_remoteparty_caller_v[i]].c_str());
						}
					}
				}
				if(opt_remoteparty_called[0]) {
					for(unsigned i = 0; i < opt_remoteparty_called_v.size(); i++) {
						if(partyNumber.find(opt_remoteparty_called_v[i]) != partyNumber.end()) {
							strcpy_null_term(call->called_final, partyNumber[opt_remoteparty_called_v[i]].c_str());
						}
					}
				}
			}
		}
	}

	// check if it is BYE or OK(RES2XX)
	if(packetS->sip_method == INVITE) {
		// festr - 14.03.2015 - this prevents some type of call to process call in case of call merging
		// if(!call->seenbye) {
		call->setSeenBye(false, 0, packetS->get_callid());
		call->setSeenByeAndOk(false, 0, packetS->get_callid());
		call->setSeenCancelAndOk(false, 0, packetS->get_callid());
		call->setSeenAuthFailed(false, 0, packetS->get_callid());
		call->destroy_call_at = 0;
		call->destroy_call_at_bye = 0;
		call->destroy_call_at_bye_confirmed = 0;
		if(call->lastSIPresponseNum == 487) {
			call->new_invite_after_lsr487 = true;
		}
		//update called number for each invite due to overlap-dialling
		if(((opt_sipoverlap && packetS->saddr_() == call->getSipcallerip()) || opt_last_dest_number) && !reverseInviteSdaddr) {
			char called_to[1024] = "";
			get_sip_peername(packetS, "\nTo:", "\nt:",
					 called_to, sizeof(called_to), ppntt_to, ppndt_called);
			if(strcmp(call->caller, called_to)) {
				strcpy_null_term(call->called_to, called_to);
			}
			if(opt_destination_number_mode == 2 || isSendCallInfoReady()) {
				char called_uri[1024] = "";
				if(!get_sip_peername(packetS, "INVITE ", NULL, called_uri, sizeof(called_uri), ppntt_invite, ppndt_called) &&
				   called_uri[0] != '\0' && strcmp(call->caller, called_uri)) {
					strcpy_null_term(call->called_uri, called_uri);
				}
			}
		}
		//check and save CSeq for later to compare with OK 
		if(packetS->cseq.is_set()) {
			if(!call->invitecseq.is_set()) {
				call->invitecseq = packetS->cseq;
			} else if(packetS->cseq != call->invitecseq) {
				char tag_content_to[1024];
				get_sip_peertag(packetS, "\nTo:", "\nt:", tag_content_to, sizeof(tag_content_to), ppntt_to, ppndt_called_tag);
				if(tag_content_to[0]) {
					call->invitecseq_in_dialog.push_back(packetS->cseq);
					if(call->invitecseq_in_dialog.size() > 10) {
						call->invitecseq_in_dialog.pop_front();
					}
				} else {
					call->invitecseq_next.push_back(packetS->cseq);
				}
			}
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen INVITE, CSeq: %u\n", call->invitecseq.number);
		}
		if(!call->onInvite) {
			sendCallInfoEvCall(call, sci_invite, packetS->getTimeval());
			call->onInvite = true;
		}
	} else if(packetS->sip_method == MESSAGE) {
		call->destroy_call_at = packetS->getTime_s() + 60;
		call->seenmessageok = false;

		//check and save CSeq for later to compare with OK 
		if(packetS->cseq.is_set()) {
			call->messagecseq = packetS->cseq;
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen MESSAGE, CSeq: %u\n", call->messagecseq.number);
		}

		if(call->contenttype) delete [] call->contenttype;
		call->contenttype = new FILE_LINE(26003) char[contenttypelen + 1];
		strcpy(call->contenttype, contenttypestr);
		
		// UPDATE TEXT
		char *rsltMessage;
		char *rsltMessageInfo;
		string rsltDestNumber;
		string rsltSrcNumber;
		unsigned int rsltContentLength;
		unsigned int rsltDcs = 0;
		Call::eVoicemail rsltVoicemail = Call::voicemail_na;
		int rslt_parse_packet__message = 
			parse_packet__message(packetS, call->message != NULL,
					      &rsltMessage, &rsltMessageInfo, &rsltDestNumber, &rsltSrcNumber, &rsltContentLength,
					      &rsltDcs, &rsltVoicemail);
		switch(rslt_parse_packet__message) {
		case 2:
			if(rsltMessage) {
				if(call->message) {
					delete [] call->message;
				}
				call->message = rsltMessage;
			} else {
				if(!call->message) {
					call->message = new FILE_LINE(26004) char[1];
					call->message[0] = '\0';
				}
			}
			if(rsltMessageInfo) {
				if(call->message_info) {
					delete [] call->message_info;
				}
				call->message_info = rsltMessageInfo;
			}
		case 1:
			call->dcs = rsltDcs;
			call->voicemail = rsltVoicemail;
			break;
		}
		if(rslt_parse_packet__message != -1) {
			if(rsltDestNumber.length()) {
				strcpy_null_term(call->called_final, rsltDestNumber.c_str());
				call->updateDstnumFromMessage = true;
			}
			if(rsltSrcNumber.length()) {
				strcpy_null_term(call->caller, rsltSrcNumber.c_str());
			}
			if(rsltContentLength != (unsigned int)-1) {
				call->content_length = rsltContentLength;
			}
		}
	} else if(packetS->sip_method == BYE) {
		++count_sip_bye;
		if(call->is_enable_set_destroy_call_at_for_call(NULL, merged)) {
			//do not set destroy for BYE which belongs to first leg in case of merged legs through sip header 
			call->destroy_call_at = packetS->getTime_s() + 60;
			call->destroy_call_at_bye = packetS->getTime_s() + opt_bye_timeout;
		}
		//check and save CSeq for later to compare with OK 
		if(packetS->cseq.is_set()) {
			call->setByeCseq(&packetS->cseq);
			call->setSeenBye(true, packetS->getTimeUS(), packetS->get_callid());
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen bye\n");
			if(opt_enable_fraud && isFraudReady()) {
				if(needCustomHeadersForFraud()) {
					process_packet__parse_custom_headers(call, packetS);
				}
				fraudSeenByeCall(call, packetS->getTimeval());
			}
		}
		// save who hanged up 
		if(detectCallerd) {
			call->whohanged = iscaller ? 1 : 0;
		} else {
			if(call->getSipcallerip() == packetS->saddr_()) {
				call->whohanged = 0;
			} else if(call->sipcalledip[0] == packetS->saddr_() || call->getSipcalledip() == packetS->saddr_()) {
				call->whohanged = 1;
			}
		}
		if(!call->onHangup) {
			sendCallInfoEvCall(call, sci_hangup, packetS->getTimeval());
			call->onHangup = true;
		}
	} else if(packetS->sip_method == CANCEL) {
		++count_sip_cancel;
		// CANCEL continues with Status: 200 canceling; 200 OK; 487 Req. terminated; ACK. Lets wait max 10 seconds and destroy call
		if(call->is_enable_set_destroy_call_at_for_call(NULL, merged)) {
			//do not set destroy for CANCEL which belongs to first leg in case of merged legs through sip header 
			call->destroy_call_at = packetS->getTime_s() + (opt_quick_save_cdr == 2 ? 0 :
									    (opt_quick_save_cdr ? 1 : 10));
		}
		
		if(call->is_multiple_to_branch()) {
			detect_to(packetS, to, sizeof(to), &to_detected);
			detect_branch(packetS, branch, sizeof(branch), &branch_detected);
			call->cancel_ip_port_hash(packetS->saddr_(), to, branch, packetS->getTimeval_pt());
		}
		
		//check and save CSeq for later to compare with OK 
		if(packetS->cseq.is_set()) {
			call->cancelcseq = packetS->cseq;
		}
	} else if(IS_SIP_RESXXX(packetS->sip_method)) {
		if(packetS->sip_method == RES2XX) {
			call->seenRES2XX = true;
			// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
			if(packetS->cseq.method != BYE ||
			   !call->existsByeCseq(&packetS->cseq)) {
				call->seenRES2XX_no_BYE = true;
				if(!call->progress_time_us) {
					call->progress_time_us = packetS->getTimeUS();
				}
			}
			if(opt_call_id_alternative[0] &&
			   (packetS->cseq.method == INVITE || packetS->cseq.method == BYE) &&
			   call->lastSIPresponseNum == 487) {
				call->call_id_alternative_lock();
				if(call->call_id_alternative && call->call_id_alternative->size()) {
					strcpy_null_term(call->lastSIPresponse, packetS->lastSIPresponse);
					call->lastSIPresponseNum = packetS->lastSIPresponseNum;
				}
				call->call_id_alternative_unlock();
			}
			// if it is OK check for BYE
			if(packetS->cseq.is_set()) {
				if(verbosity > 2) {
					syslog(LOG_NOTICE, "Cseq: %i / %u\n", packetS->cseq.method, packetS->cseq.number);
				}
				if(packetS->cseq.method == BYE &&
				   call->existsByeCseq(&packetS->cseq)) {
					++count_sip_bye_confirmed;
					// terminate successfully acked call, put it into mysql CDR queue and remove it from calltable 
					bool okByeRes2xx = true;
					if(call->is_multiple_to_branch()) {
						detect_to(packetS, to, sizeof(to), &to_detected);
						if(call->to_is_canceled(to)) {
							okByeRes2xx = false;
						}
					}
					if(okByeRes2xx) {
						call->setSeenByeAndOk(true, packetS->getTimeUS(), packetS->get_callid());
						call->unconfirmed_bye = false;
						
						// update who hanged up 
						if(detectCallerd) {
							call->whohanged = iscaller ? 0 : 1;
						} else {
							if(call->getSipcallerip() == packetS->daddr_()) {
								call->whohanged = 0;
							} else if(call->sipcalledip[0] == packetS->daddr_() || call->getSipcalledip() == packetS->daddr_()) {
								call->whohanged = 1;
							}
						}

						// Whan voipmonitor listens for both SIP legs (with the same Call-ID it sees both BYE and should save both 200 OK after BYE so closing call after the 
						// first 200 OK will not save the second 200 OK. So rather wait for 5 seconds for some more messages instead of closing the call. 

						// destroy call after 5 seonds from now 
						if(call->is_enable_set_destroy_call_at_for_call(&packetS->cseq, merged)) {
							call->destroy_call_at = packetS->getTime_s() + (opt_quick_save_cdr == 2 ? 0 :
													    (opt_quick_save_cdr ? 1 : 5));
							call->destroy_call_at_bye_confirmed = packetS->getTime_s() + opt_bye_confirmed_timeout;
						}
					}
					process_packet__parse_custom_headers(call, packetS);
					goto endsip_save_packet;
				} else if((packetS->cseq.method == INVITE && 
					   (packetS->cseq == call->invitecseq || 
					    (call->invitecseq_next.size() && find(call->invitecseq_next.begin(), call->invitecseq_next.end(), packetS->cseq) != call->invitecseq_next.end()) ||
					    (call->invitecseq_in_dialog.size() && find(call->invitecseq_in_dialog.begin(), call->invitecseq_in_dialog.end(), packetS->cseq) != call->invitecseq_in_dialog.end()))) ||
					  (packetS->cseq.method == MESSAGE && packetS->cseq == call->messagecseq)) {
					for(list<Call::sInviteSD_Addr>::iterator iter = call->invite_sdaddr.begin(); iter != call->invite_sdaddr.end(); iter++) {
						if(packetS->daddr_() == iter->saddr && packetS->saddr_() == iter->daddr) {
							iter->confirmed = true;
						}
					}
					if(packetS->cseq.method == INVITE) {
						call->seeninviteok = true;
						call->seenbyeandok_permanent = false;
						if(!call->connect_time_us) {
							call->connect_time_us = packetS->getTimeUS();
							if(opt_enable_fraud && isFraudReady()) {
								if(needCustomHeadersForFraud()) {
									process_packet__parse_custom_headers(call, packetS);
								}
								fraudConnectCall(call, packetS->getTimeval());
							}
						}
					} else {
						call->seenmessageok = true;
					}
					if(opt_update_dstnum_onanswer &&
					   !call->updateDstnumOnAnswer && !call->updateDstnumFromMessage &&
					   call->called_invite_branch_map.size() > 1) {
						detect_branch(packetS, branch, sizeof(branch), &branch_detected);
						if(branch[0] != '\0') {
							bool use_called_invite = false;
							if(opt_destination_number_mode == 2) {
								use_called_invite = 1;
							} else {
								map<string, bool> variants_called_invite;
								map<string, bool> variants_to;
								for(map<string, dstring>::iterator iter = call->called_invite_branch_map.begin(); iter != call->called_invite_branch_map.end(); iter++) {
									variants_called_invite[iter->second[0]] = true;
									variants_to[iter->second[1]] = true;
								}
								use_called_invite = variants_called_invite.size() > variants_to.size();
							}
							map<string, dstring>::iterator iter = call->called_invite_branch_map.find(branch);
							if(iter != call->called_invite_branch_map.end()) {
								strcpy_null_term(call->called_to, iter->second[1].c_str());
								strcpy_null_term(call->called_uri, iter->second[0].c_str());
								strcpy_null_term(call->called_final, iter->second[use_called_invite ? 0 : 1].c_str());
								call->updateDstnumOnAnswer = true;
							}
						}
					}
					if(verbosity > 2)
						syslog(LOG_NOTICE, "Call answered\n");
					if(!call->onCall_2XX) {
						if(call->typeIs(INVITE)) {
							process_packet__parse_custom_headers(call, packetS);
							ClientThreads.onCall(call->call_id.c_str(),
									     lastSIPresponseNum, call->callername, call->caller, call->called(),
									     call->getSipcallerip(), call->getSipcalledip(),
									     custom_headers_cdr->getScreenPopupFieldsString(call, INVITE).c_str());
						}
						sendCallInfoEvCall(call, sci_200, packetS->getTimeval());
						call->onCall_2XX = true;
					}
					if(opt_sdp_check_direction_ext) {
						for(list<Call::sInviteSD_Addr>::iterator riter = call->rinvite_sdaddr.begin(); riter != call->rinvite_sdaddr.end(); riter++) {
							if(packetS->saddr_() == riter->daddr && packetS->daddr_() == riter->saddr) {
								reverseInviteConfirmSdaddr = true;
								reverseInvite = &(*riter);
								if(sverb.reverse_invite) {
									cout << "reverse invite: confirm / " << call->call_id << endl;
								}
								for(list<Call::sInviteSD_Addr>::iterator iter = call->invite_sdaddr.begin(); iter != call->invite_sdaddr.end(); iter++) {
									if(packetS->saddr_() == iter->saddr && packetS->daddr_() == iter->daddr) {
										mainInviteForReverse = &(*iter);
										break;
									}
								}
								break;
							}
						}
					} else {
						for(list<Call::sInviteSD_Addr>::iterator iter = call->invite_sdaddr.begin(); iter != call->invite_sdaddr.end(); iter++) {
							if(packetS->saddr_() == iter->saddr && packetS->daddr_() == iter->daddr) {
								reverseInviteConfirmSdaddr = true;
								if(sverb.reverse_invite) {
									cout << "reverse invite: confirm / " << call->call_id << endl;
								}
							}
						}
					}
				} else if(packetS->cseq.method == CANCEL &&
					  call->cancelcseq.is_set() && packetS->cseq == call->cancelcseq) {
					++count_sip_cancel_confirmed;
					call->setSeenCancelAndOk(true, packetS->getTimeUS(), packetS->get_callid());
					process_packet__parse_custom_headers(call, packetS);
					goto endsip_save_packet;
				}
			}
		} else if(IS_SIP_RES18X(packetS->sip_method)) {
			call->seenRES18X = true;
			if(!call->progress_time_us) {
				call->progress_time_us = packetS->getTimeUS();
			}
			if(!call->onCall_18X) {
				if(call->typeIs(INVITE)) {
					process_packet__parse_custom_headers(call, packetS);
					ClientThreads.onCall(call->call_id.c_str(),
							     lastSIPresponseNum, call->callername, call->caller, call->called(),
							     call->getSipcallerip(), call->getSipcalledip(),
							     custom_headers_cdr->getScreenPopupFieldsString(call, INVITE).c_str());
				}
				sendCallInfoEvCall(call, sci_18X, packetS->getTimeval());
				call->onCall_18X = true;
			}
			call->destroy_call_at = 0;
			call->destroy_call_at_bye = 0;
			call->destroy_call_at_bye_confirmed = 0;
		} else if((packetS->cseq.method == INVITE || packetS->cseq.method == MESSAGE) &&
			  (IS_SIP_RES3XX(packetS->sip_method) || IS_SIP_RES4XX(packetS->sip_method) || packetS->sip_method == RES5XX || packetS->sip_method == RES6XX)) {
			if(lastSIPresponseNum == 487) {
				fraudSessionCanceledCall(call, packetS->getTimeval());
			}
			if(lastSIPresponseNum == 481) {
				// 481 CallLeg/Transaction doesnt exist - set timeout to 180 seconds
				if(call->is_enable_set_destroy_call_at_for_call(&packetS->cseq, merged)) {
					call->destroy_call_at = packetS->getTime_s() + 180;
				} else if(call->seenbyeandok_permanent) {
					call->destroy_call_at = packetS->getTime_s() + 60;
				}
			} else if(lastSIPresponseNum == 491) {
				// do not set timeout for 491
			} else if(lastSIPresponseNum != 401 && lastSIPresponseNum != 407 && lastSIPresponseNum != 501) {
				// save packet 
				if(call->is_enable_set_destroy_call_at_for_call(&packetS->cseq, merged)) {
					if(packetS->lastSIPresponseNum == 404) {
						detect_to(packetS, to, sizeof(to), &to_detected);
						detect_branch(packetS, branch, sizeof(branch), &branch_detected);
						call->cancel_ip_port_hash(packetS->daddr_(), to, branch, packetS->getTimeval_pt());
					}
					call->destroy_call_at = packetS->getTime_s() + (packetS->sip_method == RES300 ? 300 : 5);
				}
				if(lastSIPresponseNum == 488 || lastSIPresponseNum == 606) {
					call->not_acceptable = true;
				} else if(lastSIPresponseNum == 403) {
					call->setSeenAuthFailed(true, packetS->getTimeUS(), packetS->get_callid());
				} else if(IS_SIP_RES3XX(packetS->sip_method)) {
					// remove all RTP  
					call->removeFindTables(packetS->getTimeval_pt());
					call->ipport_n = 0;
					call->setFlagForRemoveRTP();
				}
				process_packet__parse_custom_headers(call, packetS);
				goto endsip_save_packet;
			} else if(!call->destroy_call_at) {
				if(call->is_enable_set_destroy_call_at_for_call(&packetS->cseq, merged)) {
					call->destroy_call_at = packetS->getTime_s() + 60;
				}
			}
		} else if(packetS->cseq.method == BYE &&
			  !call->seenbyeandok &&
			  IS_SIP_RES4XX(packetS->sip_method) &&
			  call->existsByeCseq(&packetS->cseq) &&
			  lastSIPresponseNum == 481) {
			call->unconfirmed_bye = true;
		}
	}

	if(packetS->sip_method == INVITE || packetS->sip_method == MESSAGE) {
		detect_branch(packetS, branch, sizeof(branch), &branch_detected);
		if(branch[0] != '\0') {
			detect_called_invite(packetS, called_invite, sizeof(called_invite), &called_invite_detected);
			detect_to(packetS, to, sizeof(to), &to_detected);
			if(called_invite[0] != '\0' || to[0] != '\0') {
				call->called_invite_branch_map[branch] = dstring(called_invite, to);
			}
		}
		if(!packetS->_createCall && !existInviteSdaddr && !reverseInviteSdaddr) {
			call->flags = setCallFlags(call->flags,
						   packetS->saddr_(), packetS->daddr_(),
						   call->caller, call->called(),
						   call->caller_domain, call->called_domain(),
						   &packetS->parseContents);
		}
		if(!reverseInviteSdaddr) {
			if(packetS->saddr_() != call->getSipcallerip() && !call->in_proxy(packetS->saddr_())) {
				call->proxy_add(packetS->saddr_());
			}
			if(packetS->daddr_() != call->getSipcallerip() && packetS->daddr_() != call->getSipcalledip() && !call->in_proxy(packetS->daddr_())) {
				if(!(opt_sdp_check_direction_ext &&
				     packetS->saddr_() == call->getSipcallerip() && call->all_invite_is_multibranch(packetS->saddr_()))) {
					call->proxy_add(call->getSipcalledip());
					call->setSipcalledip(packetS->daddr_(), packetS->daddr_(true), packetS->header_ip_protocol(true), packetS->dest_(), packetS->get_callid());
				}
			}
		}
		/* old version
		if(!reverseInviteSdaddr && !existInviteSdaddr) {
			bool updateDest = false;
			if(call->getSipcalledip() != packetS->daddr_() && call->getSipcallerip() != packetS->daddr_() && 
			   call->lastsipcallerip != packetS->saddr_()) {
				if(((packetS->sip_method == INVITE && opt_cdrproxy) ||
				    (packetS->sip_method == MESSAGE && opt_messageproxy)) &&
				   packetS->daddr_().isSet()) {
					// daddr is already set, store previous daddr as sipproxy
					call->proxy_add(call->getSipcalledip());
				}
				updateDest = true;
			} else if(call->lastsipcallerip == packetS->saddr_()) {
				updateDest = true;
			}
			if(updateDest) {
				call->setSipcalledip(packetS->daddr_(), packetS->daddr_(true), packetS->header_ip_protocol(true), packetS->dest_(), packetS->get_callid());
				call->lastsipcallerip = packetS->saddr_();
			}
		}
		*/
	}

	if(opt_norecord_header) {
		s = gettag_sip(packetS, "\nX-VoipMonitor-norecord:", &l);
		if(s) {
			call->stoprecording();
		}
	}

	// pause or unpause recording based on header defined in config by option pauserecordingheader = X-voipmponitor-pause-recording*/
	if(opt_silenceheader[0] != '\0') {
		char *silenceheaderval = gettag_sip(packetS, opt_silenceheader, &l);
		if(silenceheaderval) {
			syslog(LOG_DEBUG, "opt_silenceheader found, its val: %.*s", (int)l, silenceheaderval);
			if(strncmp(silenceheaderval, "pause", l) == 0) {
				call->silencerecording = 1;
				if (logPacketSipMethodCall_enable)
					 syslog(LOG_NOTICE, "opt_silenceheader PAUSED recording");
			} else {
				call->silencerecording = 0;
				if (logPacketSipMethodCall_enable)
					 syslog(LOG_NOTICE, "opt_silenceheader UNPAUSED recording");
			}
		} else {
			if (logPacketSipMethodCall_enable)
				 syslog(LOG_DEBUG, "No opt_silenceheader in SIP packet");
		}
	}

	if(opt_energylevelheader[0] != '\0') {
		char *energylevelheader_val = gettag_sip(packetS, opt_energylevelheader, &l);
		if(energylevelheader_val) {
			call->save_energylevels = true;
		}
	}
	
	// pause / unpause recording based on 182 queued / update & ok
	if (opt_182queuedpauserecording) {
		switch (packetS->sip_method) {
		case RES182:
			if (logPacketSipMethodCall_enable) 
				 syslog(LOG_DEBUG, "opt_182queuedpauserecording SIP 182 queued, pausing recording.");
			call->recordingpausedby182 = 1;
			call->silencerecording = 1;
			break;
		case UPDATE:
			if (call->recordingpausedby182) {
				if(packetS->cseq.is_set()) {
					if (logPacketSipMethodCall_enable) 
						 syslog(LOG_DEBUG, "opt_182queuedpauserecording UPDATE preparing unpausing recording, waiting for OK with same CSeq");
					call->updatecseq = packetS->cseq;
					call->recordingpausedby182 = 2;
				} else {
					if (logPacketSipMethodCall_enable) 
						 syslog(LOG_WARNING, "opt_182queuedpauserecording WARNING Not recognized UPDATE's CSeq!");
				}
			} 
			break;
		case RES2XX:
			if (call->recordingpausedby182 == 2) {
				if(packetS->cseq.is_set()) {
					if(call->updatecseq.is_set() && packetS->cseq == call->updatecseq) {
						if (logPacketSipMethodCall_enable) 
							 syslog(LOG_DEBUG, "opt_182queuedpauserecording OK on UPDATE unpausing recording");
						call->recordingpausedby182 = 0;
						call->silencerecording = 1;
					}
				} else {
					if (logPacketSipMethodCall_enable) 
						 syslog(LOG_WARNING, "opt_182queuedpauserecording WARNING Not recognized OK's CSeq (received)");
				} 
			}
			break;
		}
	}

	if(packetS->sip_method == INFO) {
		s = gettag_sip(packetS, "\nSignal:", &l);
		if(s && l < 33) {
			char *tmp = s + 1;
			char tmp2 = tmp[l - 1];
			tmp[l - 1] = '\0';
			if(verbosity >= 2)
				syslog(LOG_NOTICE, "[%s] DTMF SIP INFO [%c]", call->fbasename, tmp[0]);
			call->handle_dtmf(*tmp, packetS->getTimeSF(), packetS->saddr_(), packetS->daddr_(), s_dtmf::sip_info);
			tmp[l - 1] = tmp2;
			if(!enable_save_dtmf_pcap(call)) {
				dont_save = true;
			}
		}
		s = gettag_sip(packetS, "Signal=", &l);
		if(s && l < 33) {
			char *tmp = s;
			char tmp2 = tmp[l];
			tmp[l] = '\0';
			if(verbosity >= 2)
				syslog(LOG_NOTICE, "[%s] DTMF SIP INFO [%c]", call->fbasename, tmp[0]);
			call->handle_dtmf(*tmp, packetS->getTimeSF(), packetS->saddr_(), packetS->daddr_(), s_dtmf::sip_info);
			tmp[l] = tmp2;
			if(!enable_save_dtmf_pcap(call)) {
				dont_save = true;
			}
		}
	}
	
	// check if we have X-VoipMonitor-Custom1
	s = gettag_sip(packetS, "\nX-VoipMonitor-Custom1:", &l);
	if(s && l < 255) {
		memcpy(call->custom_header1, s, l);
		call->custom_header1[l] = '\0';
		if(verbosity > 2)
			syslog(LOG_NOTICE, "Seen X-VoipMonitor-Custom1: %s\n", call->custom_header1);
	}

	// check for opt_match_header
	if(opt_match_header[0] != '\0') {
		s = gettag_sip(packetS, opt_match_header, &l);
		if(l && l < 128) {
			memcpy(call->match_header, s, l);
			call->match_header[l] = '\0';
			if(verbosity > 2)
				syslog(LOG_NOTICE, "Seen header %s: %s\n", opt_match_header, call->match_header);
		}
	}

	// check if we have custom headers
	process_packet__parse_custom_headers(call, packetS);
	
	// we have packet, extend pending destroy requests
	call->shift_destroy_call_at(packetS->getTime_s(), lastSIPresponseNum);
	
	if(packetS->sip_method == PUBLISH && contenttype_is_rtcpxr) {
		process_packet__parse_rtcpxr(call, packetS, packetS->getTimeval());
	}

	// SDP examination
	if(contenttypelen &&
	   call->typeIs(INVITE) && packetS->sip_method != MESSAGE) {
	 
		char endchar = packetS->data_()[packetS->datalen_() - 1];
		packetS->data_()[packetS->datalen_() - 1] = 0;
	 
		bool is_application_sdp = false;
		bool is_multipart_mixed = false;
		if(strcasestr(contenttypestr, "application/sdp")) {
			is_application_sdp = true;
		} else if(strcasestr(contenttypestr, "multipart/mixed")) {
			is_multipart_mixed = true;
		}
		if(is_application_sdp || is_multipart_mixed) {
			int _iscaller_process_sdp = iscaller;
			if((reverseInviteSdaddr || reverseInviteConfirmSdaddr) && _iscaller_process_sdp >= 0) {
				if(opt_sdp_check_direction_ext) {
					if(sverb.reverse_invite) {
						cout << "reverse invite: check sdp direction / " << call->call_id << endl;
						if(mainInviteForReverse) {
							cout << " main invite: " << mainInviteForReverse->caller << " / " << mainInviteForReverse->called << " / " << mainInviteForReverse->called_invite << endl;
						}
						if(reverseInvite) {
							cout << " reverse invite: " << reverseInvite->caller << " / " << reverseInvite->called << " / " << reverseInvite->called_invite << endl;
						}
					}
					if(mainInviteForReverse && reverseInvite) {
						if(checkEqNumbers(mainInviteForReverse, reverseInvite)) {
							_iscaller_process_sdp = !_iscaller_process_sdp;
							if(sverb.reverse_invite) {
								cout << "reverse invite: CHANGE SDP DIRECTION / " << call->call_id << endl;
							}
						}
					}
				} else {
					char _caller[1024];
					char _called[1024];
					get_sip_peername(packetS, "\nFrom:", "\nf:", _caller, sizeof(_caller), ppntt_from, ppndt_caller);
					get_sip_peername(packetS, "\nTo:", "\nt:", _called, sizeof(_called), ppntt_to, ppndt_called);
					bool eqCallerMinLength;
					bool eqCalledMinLength;
					size_t eqCallerLength = strCaseEqLengthR(_caller, call->caller, &eqCallerMinLength);
					size_t eqCalledLength = strCaseEqLengthR(_called, call->called_to, &eqCalledMinLength);
					if((eqCallerMinLength || eqCalledMinLength ||
					    eqCallerLength >= 3 || eqCalledLength >= 3) &&
					   (eqCallerLength != eqCalledLength ||
					    strcasecmp(_caller + strlen(_caller) - eqCallerLength, _called + strlen(_called) - eqCalledLength))) {
						_iscaller_process_sdp = !_iscaller_process_sdp;
						if(sverb.reverse_invite) {
							cout << "reverse invite: CHANGE SDP DIRECTION / " << call->call_id << endl;
						}
					}
				}
			}
			if(is_application_sdp) {
				detect_to(packetS, to, sizeof(to), &to_detected);
				detect_branch(packetS, branch, sizeof(branch), &branch_detected);
				process_sdp(call, packetS, _iscaller_process_sdp, contenttype_data_ptr, 0,
					    packetS->get_callid(), to, branch);
			} else if(is_multipart_mixed) {
				char *content_data = contenttype_data_ptr + contenttypetaglen;
				unsigned content_data_len = packetS->sipDataLen - (content_data - (packetS->data_()+ packetS->sipDataOffset));
				unsigned content_boundary_max = 10;
				unsigned content_boundary_count = 0;
				char *content_boundary_ptr[content_boundary_max];
				if(content_boundary[0]) {
					while(content_boundary_count < content_boundary_max) {
						char *_content_boundary_ptr = strncasestr(content_boundary_count ? content_boundary_ptr[content_boundary_count - 1] + 1 : content_data,
											  content_boundary,
											  content_data_len - (content_boundary_count ? content_boundary_ptr[content_boundary_count - 1] + 1 - content_data: 0));
						if(_content_boundary_ptr) {
							content_boundary_ptr[content_boundary_count] = _content_boundary_ptr;
							++content_boundary_count;
						} else {
							break;
						}
					}
				}
				if(content_boundary_count > 1) {
					for(unsigned content_boundary_i = 0; content_boundary_i < content_boundary_count - 1; content_boundary_i++) {
						char *content_data_item = content_boundary_ptr[content_boundary_i] + content_boundary_length;
						unsigned content_data_item_length = content_boundary_ptr[content_boundary_i + 1] - content_boundary_ptr[content_boundary_i] - content_boundary_length;
						while(content_data_item_length > 0 && 
						      content_data_item[content_data_item_length - 1] == '-') {
							--content_data_item_length;
						}
						while(content_data_item_length > 0 && 
						      (content_data_item[content_data_item_length - 1] == CR_CHAR ||
						       content_data_item[content_data_item_length - 1] == LF_CHAR)) {
							--content_data_item_length;
						}
						char content_type[1024] = "";
						for(unsigned pass = 0; pass < 2; pass++) {
							long unsigned _content_type_length;
							char *_content_type = _gettag(content_data_item, content_data_item_length,
										      pass == 0 ? "\nContent-Type:" : "\nc:",
										      &_content_type_length);
							if(_content_type_length > 0) {
								_content_type_length = MIN(_content_type_length, sizeof(content_type) - 1);
								strncpy(content_type, _content_type, _content_type_length);
								content_type[_content_type_length] = 0;
								break;
							}
						}
						if(content_type[0]) {
							/*
							int content_length = -1;
							long unsigned _content_length_length;
							char *_content_length = gettag(content_data_item, content_data_item_length, NULL,
										       "\nContent-Length:",
										       &_content_length_length, NULL);
							if(_content_length_length > 0) {
								content_length = atoi(_content_length);
							}
							*/
							char *content_data_begin = NULL;
							for(int pass_line_separator = 0; pass_line_separator < 2 && !content_data_begin; pass_line_separator++) {
								content_data_begin = strnstr(content_data_item, SIP_DBLLINE_SEPARATOR(pass_line_separator == 1), content_data_item_length);
								if(content_data_begin) {
									content_data_begin += SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1);
								}
							}
							if(content_data_begin) {
								unsigned content_data_offset = content_data_begin - content_data_item;
								unsigned content_data_length = content_data_item_length - content_data_offset;
								if(strcasestr(content_type, "application/sdp")) {
									detect_to(packetS, to, sizeof(to), &to_detected);
									detect_branch(packetS, branch, sizeof(branch), &branch_detected);
									process_sdp(call, packetS, _iscaller_process_sdp, content_data_begin, content_data_length,
										    packetS->get_callid(), to, branch);
								} else if(strcasestr(content_type, "application/rs-metadata+xml")) {
									call->add_txt(packetS->getTimeUS(), Call::txt_type_sdp_xml, content_data_begin, content_data_length);
								}
							}
						}
					}
				} else {
					s = contenttype_data_ptr;
					while(1) {
						//continue searching  for another content-type
						char *s2;
						s2 = gettag_sip_from(packetS, s, "\nContent-Type:", "\nc:", &l);
						if(s2 and l > 0) {
							//Content-Type found try if it is SDP 
							if(l > 0 && strcasestr(s2, "application/sdp")){
								detect_to(packetS, to, sizeof(to), &to_detected);
								detect_branch(packetS, branch, sizeof(branch), &branch_detected);
								process_sdp(call, packetS, _iscaller_process_sdp, s2, 0,
									    packetS->get_callid(), to, branch);
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
				}
			}
		}
		
		packetS->data_()[packetS->datalen_() - 1] = endchar;
		
	}

endsip_save_packet:
	if (!dont_save) {
		save_packet(call, packetS, _t_packet_sip);
	}

endsip:
	if(_save_sip_history && call) {
		bool save_request = IS_SIP_RESXXX(packetS->sip_method) ?
				     lastSIPresponseNum && _save_sip_history_all_responses :
				     packetS->sip_method && (_save_sip_history_all_requests || _save_sip_history_request_types[packetS->sip_method]);
		bool save_response = lastSIPresponseNum && _save_sip_history_all_responses;
		if(save_request || save_response) {
			char _request[20] = "";
			char *_lastSIPresponse = NULL;
			int _lastSIPresponseNum = 0;
			if(save_request) {
				const char *sip_request_name = sip_request_int_to_name(packetS->sip_method, false);
				if(sip_request_name) {
					strcpy_null_term(_request, sip_request_name);
				}
			}
			if(save_response) {
				_lastSIPresponse = lastSIPresponse;
				_lastSIPresponseNum = lastSIPresponseNum;
			}
			if((_request[0] || 
			    (_lastSIPresponse && _lastSIPresponse[0]) || 
			    _lastSIPresponseNum) &&
			   call->SIPhistory.size() < 1000) {
				call->SIPhistory.push_back(Call::sSipHistory(
					packetS->getTimeUS(),
					_request,
					_lastSIPresponse, _lastSIPresponseNum));
			}
		}
	}
	
	if(call && sipSendSocket && !opt_sip_send_before_packetbuffer) {
		// send packet to socket if enabled
		u_int16_t header_length = packetS->datalen_();
		sipSendSocket->addData(&header_length, 2,
				       packetS->data_(), packetS->datalen_());
	}

	if(call && detectCallerd &&
	   (iscaller > 0 ||
	    (iscalled > 0 && !call->a_ua[0]))) {
		s = gettag_sip(packetS, "\nUser-Agent:", &l);
		if(s) {
			//cout << "**** " << call->call_id << " " << (iscaller > 0 ? "b" : "a") << " / " << string(s, l) << endl;
			if(iscaller > 0) {
				memcpy(call->b_ua, s, MIN(l, sizeof(call->b_ua)));
				call->b_ua[MIN(l, sizeof(call->b_ua) - 1)] = '\0';
				if(sverb.set_ua) {
					cout << "set b_ua " << call->b_ua << endl;
				}
			}
			if(iscalled > 0) {
				memcpy(call->a_ua, s, MIN(l, sizeof(call->a_ua)));
				call->a_ua[MIN(l, sizeof(call->a_ua) - 1)] = '\0';
				if(sverb.set_ua) {
					cout << "set a_ua " << call->a_ua << endl;
				}
			}
		}
	}
	
	if(logPacketSipMethodCall_enable) {
		logPacketSipMethodCall(
			#if USE_PACKET_NUMBER
			packetS->packet_number
			#else
			0
			#endif
			, packetS->sip_method, lastSIPresponseNum, packetS->getTimeval(), 
			packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(),
			call, logPacketSipMethodCallDescr);
	}
}

void process_packet_sip_alone_bye(packet_s_process *packetS) {
	if(sverb.dump_sip) {
		string dump_data(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen);
		if(sverb.dump_sip_line) {
			find_and_replace(dump_data, CR_STR, CR_STR_ESC);
			find_and_replace(dump_data, LF_STR, LF_STR_ESC);
		}
		if(!sverb.dump_sip_without_counter) {
			#if USE_PACKET_NUMBER
			cout << packetS->packet_number
			#else
			cout << (++glob_packet_number)
			#endif
			<< " "
			<< packetS->saddr_().getString() << ':' << packetS->source_() 
			<< " -> "
			<< packetS->daddr_().getString() << ':' << packetS->dest_() 
			<< endl;
		}
		cout << dump_data << endl;
	}
	Call *call = packetS->call ? packetS->call : packetS->call_created;
	if(!call) {
		return;
	}
	call->destroy_call_at = packetS->getTime_s() + 60;
	if(IS_SIP_RESXXX(packetS->sip_method) && packetS->cseq.is_set() &&
	   packetS->cseq.method == BYE && 
	   call->existsByeCseq(&packetS->cseq)) {
		call->lastSIPresponseNum = packetS->lastSIPresponseNum;
	}
}

void process_packet_sip_register(packet_s_process *packetS) {
	
	Call *call = NULL;
	char *s;
	unsigned long l;
	bool goto_endsip = false;
	const char *logPacketSipMethodCallDescr = NULL;

	// checking and cleaning stuff every 10 seconds (if some packet arrive) 
	process_packet__cleanup_registers(packetS->getTimeval_pt());
	if(packetS->getTime_s() - process_packet__last_destroy_registers >= 2) {
		calltable->destroyRegistersIfPcapsClosed();
		process_packet__last_destroy_registers = packetS->getTime_s();
	}

	++counter_sip_register_packets;

	if(opt_enable_fraud && isFraudReady()) {
		char *ua = NULL;
		unsigned long ua_len = 0;
		ua = gettag_sip(packetS, "\nUser-Agent:", &ua_len);
		fraudSipPacket(packetS->saddr_(), packetS->sip_method, packetS->getTimeval(), ua, ua_len);
	}
			
	if(sverb.dump_sip) {
		string dump_data(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen);
		if(sverb.dump_sip_line) {
			find_and_replace(dump_data, CR_STR, CR_STR_ESC);
			find_and_replace(dump_data, LF_STR, LF_STR_ESC);
		}
		if(!sverb.dump_sip_without_counter) {
			#if USE_PACKET_NUMBER
			cout << packetS->packet_number
			#else
			cout << (++glob_packet_number)
			#endif
			<< " "
			<< packetS->saddr_().getString() << ':' << packetS->source_() 
			<< " -> "
			<< packetS->daddr_().getString() << ':' << packetS->dest_() 
			<< endl;
		}
		cout << dump_data << endl;
	}

	if(packetS->sip_method == REGISTER) {
		if(opt_enable_fraud && isFraudReady()) {
			char *ua = NULL;
			unsigned long ua_len = 0;
			ua = gettag_sip(packetS, "\nUser-Agent:", &ua_len);
			fraudRegister(packetS->saddr_(), packetS->daddr_(), packetS->getTimeval(), ua, ua_len,
				      packetS);
		}
	}
		
	bool call_created = false;
	call = calltable->find_by_register_id(packetS->get_callid(), 0);
	if(!call) {
		if(packetS->sip_method == REGISTER) {
			call = new_invite_register(packetS, packetS->sip_method, packetS->get_callid());
			call_created = true;
		}
		if(!call) {
			goto endsip;
		}
	}
	call->set_last_signal_packet_time_us(packetS->getTimeUS());
	
	call->check_reset_oneway(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
	
	if(packetS->lastSIPresponseNum) {
		call->lastSIPresponseNum = packetS->lastSIPresponseNum;
	}
	call->msgcount++;
	if(packetS->sip_method == REGISTER) {
		call->regcount++;
		if(IS_SIP_RES4XX(call->last_sip_method)) {
			call->regcount_after_4xx = 0;
		}
		call->regcount_after_4xx++;
		if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER Call-ID[%s] regcount[%d]", call->call_id.c_str(), call->regcount);

		// update Authorization
		for(int pass_authorization = 0; pass_authorization < 2; pass_authorization++) {
			s = gettag_sip(packetS, pass_authorization == 0 ? "\nAuthorization:" : "\nProxy-Authorization:", &l);
			if(s) {
				get_value_stringkeyval(s, packetS->datalen_() - (s - packetS->data_()), "username=\"", call->digest_username, sizeof(call->digest_username));
				get_value_stringkeyval(s, packetS->datalen_() - (s - packetS->data_()), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
				break;
			}
		}

		if(call->regstate == 2 &&
		   (call->last_sip_method == RES403 || call->last_sip_method == RES404)) {
			call->saveregister(packetS->getTimeval_pt());
			call = new_invite_register(packetS, packetS->sip_method, packetS->get_callid());
			if(call == NULL) {
				goto endsip;
			}
			call->msgcount = 1;
			call->regcount = 1;
			if(packetS->cseq.is_set()) {
				call->registercseq = packetS->cseq;
			}
			goto endsip_save_packet;
		}
		if(call->regcount > opt_register_max_registers && !call->reg200count && !call->reg401count_all) {
			// to much register attempts without OK or 401 responses
			call->regstate = 4;
			call->saveregister(packetS->getTimeval_pt());
			call = new_invite_register(packetS, packetS->sip_method, packetS->get_callid());
			if(call == NULL) {
				goto endsip;
			}
			call->msgcount = 1;
			call->regcount = 1;
			if(packetS->cseq.is_set()) {
				call->registercseq = packetS->cseq;
			}
			if(logPacketSipMethodCall_enable) {
				logPacketSipMethodCallDescr = "to much register attempts without OK or 401 responses";
			}
			goto endsip_save_packet;
		}
		if(packetS->cseq.is_set()) {
			call->registercseq = packetS->cseq;
		}
		if(!call_created && packetS->pflags.tcp) {
			u_int32_t seq = packetS->tcp_seq();
			if(seq) {
				call->addRegTcpSeq(packetS->tcp_seq());
			}
		}

	} else if(packetS->sip_method == RES2XX) {
		call->seenRES2XX = true;
		call->reg401count = 0;
		call->reg401count_sipcallerip_vlan.clear();
		call->reg403count = 0;
		call->reg404count = 0;
		// update expires header from all REGISTER dialog messages (from 200 OK which can override the expire) but not if register_expires == 0
		if(call->register_expires != 0) {
			s = gettag_sip(packetS, "\nExpires:", &l);
			if(s) {
				char c = s[l];
				s[l] = '\0';
				call->register_expires = atoi(s);
				s[l] = c;
			}
			// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
			get_expires_from_contact(packetS, NULL, &call->register_expires);
		}
		if(opt_enable_fraud && isFraudReady()) {
			fraudConnectCall(call, packetS->getTimeval());
		}
		if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER OK Call-ID[%s]", call->call_id.c_str());
		if(packetS->cseq.is_set() && packetS->cseq == call->registercseq) {
			call->reg200count++;
			// registration OK 
			call->regstate = 1;

			// diff in ms
			call->regrrddiff = 1000 * (packetS->getTime_s() - call->regrrdstart.tv_sec) + (packetS->getTime_us() - call->regrrdstart.tv_usec) / 1000;
		} else {
			// OK to unknown msg close the call
			call->regstate = 3;
		}
		save_packet(call, packetS, _t_packet_sip);
		if(call->regstate == 1 &&
		   call->reg200count + call->reg401count_all < call->regcount) {
			call->destroy_call_at = packetS->getTime_s() + opt_register_timeout;
		} else {
			call->saveregister(packetS->getTimeval_pt());
		}
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCallDescr = "update expires header from all REGISTER dialog messages (from 200 OK which can override the expire)";
		}
		goto_endsip = true;
	} else if(packetS->sip_method == RES401 or packetS->sip_method == RES403 or packetS->sip_method == RES404) {
		bool okres401 = false;
		switch(packetS->sip_method) {
		case RES401:
			if(opt_register_ignore_res_401) {
				break;
			} else if(opt_register_ignore_res_401_nonce_has_changed) {
				okres401 = true;
				char *pointToEndLine = (char*)memmem(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen, "\n", 1);
				if(pointToEndLine) {
					*pointToEndLine = 0;
					if(strcasestr(packetS->data_()+ packetS->sipDataOffset, "nonce has changed")) {
						okres401 = false;
					}
					*pointToEndLine = '\n';
				}
			} else {
				okres401 = true;
			}
			if(!okres401) {
				break;
			}
			
			{
			++call->reg401count;
			++call->reg401count_all;
			bool find = false;
			for(list<d_item2<vmIP, u_int16_t> >::iterator iter = call->reg401count_sipcallerip_vlan.begin(); iter != call->reg401count_sipcallerip_vlan.end(); iter++) {
				if(iter->item1 == packetS->saddr_() &&
				   iter->item2 == packetS->pid.vlan) {
					find = true;
					break;
				}
			}
			if(!find) {
				call->reg401count_sipcallerip_vlan.push_back(d_item2<vmIP, u_int16_t>(packetS->saddr_(), packetS->pid.vlan));
			}
			}
			if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER 401 Call-ID[%s] reg401count[%d] reg401count_distinct[%zd]", 
						 call->call_id.c_str(), call->reg401count, call->reg401count_sipcallerip_vlan.size());
			break;
		case RES403:
			++call->reg403count;
			break;
		case RES404:
			++call->reg404count;
			break;
		}
		if((packetS->sip_method == RES401 && okres401 && call->reg401count > (int)call->reg401count_sipcallerip_vlan.size()) || 
		   packetS->sip_method == RES403 ||
		   packetS->sip_method == RES404) {
			// registration failed
			call->regstate = 2;
			save_packet(call, packetS, _t_packet_sip);
			if(packetS->sip_method == RES401 ||
			   (packetS->sip_method == RES403 && call->reg403count >= call->regcount_after_4xx) ||
			   (packetS->sip_method == RES404 && call->reg404count >= call->regcount_after_4xx)) {
				call->saveregister(packetS->getTimeval_pt());
			} else {
				call->destroy_call_at = packetS->getTime_s() + 1;
			}
			if(logPacketSipMethodCall_enable) {
				logPacketSipMethodCallDescr =
					packetS->sip_method == RES401 ? "REGISTER 401 count > 1" :
					packetS->sip_method == RES403 ? "REGISTER 403 count > 1" :
					packetS->sip_method == RES404 ? "REGISTER 404" : NULL;
			}
			goto_endsip = true;
		}
	}
	if(call->regstate && !call->regresponse) {
		if(opt_enable_fraud && isFraudReady()) {
			fraudRegisterResponse(call->sipcallerip[0], call->sipcalledip[0], call->first_packet_time_us,
					      call->a_ua[0] ? call->a_ua : call->b_ua[0] ? call->b_ua : NULL, -1);
		}
		call->regresponse = true;
	}
	if(goto_endsip) {
		goto endsip;
	}
	if(call->msgcount > opt_register_max_messages) {
		// too many REGISTER messages within the same callid
		call->regstate = 4;
		save_packet(call, packetS, _t_packet_sip);
		call->saveregister(packetS->getTimeval_pt());
		if(logPacketSipMethodCall_enable) {
			logPacketSipMethodCallDescr = "too many REGISTER messages within the same callid";
		}
		goto endsip;
	}
		
	call->check_reset_oneway(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
	
	if(opt_norecord_header) {
		s = gettag_sip(packetS, "\nX-VoipMonitor-norecord:", &l);
		if(s) {
			call->stoprecording();
		}
	}

	// we have packet, extend pending destroy requests
	call->shift_destroy_call_at(packetS->getTime_s(), packetS->lastSIPresponseNum);

endsip_save_packet:
	save_packet(call, packetS, _t_packet_sip);

endsip:
	if(call && sipSendSocket && !opt_sip_send_before_packetbuffer) {
		// send packet to socket if enabled
		u_int16_t header_length = packetS->datalen_();
		sipSendSocket->addData(&header_length, 2,
				       packetS->data_(), packetS->datalen_());
	}
	
	if(call && packetS->sip_method != REGISTER) {
		s = gettag_sip(packetS, "\nUser-Agent:", &l);
		if(s) {
			memcpy(call->b_ua, s, MIN(l, sizeof(call->b_ua)));
			call->b_ua[MIN(l, sizeof(call->b_ua) - 1)] = '\0';
			if(sverb.set_ua) {
				cout << "set b_ua " << call->b_ua << endl;
			}
		}
	}
	
	if(call) {
		call->last_sip_method = packetS->sip_method;
	}
	
	if(logPacketSipMethodCall_enable) {
		logPacketSipMethodCall(
			#if USE_PACKET_NUMBER
			packetS->packet_number
			#else
			0
			#endif
			, packetS->sip_method, packetS->lastSIPresponseNum, packetS->getTimeval(), 
			packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(),
			call, logPacketSipMethodCallDescr);
	}
}

void process_packet_sip_other_sip_msg(packet_s_process *packetS) {
	extern cSipMsgRelations *sipMsgRelations;
	if(!sipMsgRelations) {
		return;
	}
	int sipMsgType = packetS->is_options() ? smt_options :
			 packetS->is_subscribe() ? smt_subscribe :
			 packetS->is_notify() ? smt_notify : 0;
	if(!sipMsgType) {
		return;
	}
	s_detect_callerd data_callerd;
	detect_callerd(packetS, packetS->sip_method, &data_callerd);
	cSipMsgItem *sipMsg = new FILE_LINE(0) cSipMsgItem;
	sipMsg->type = sipMsgType;
	sipMsg->time_us = packetS->getTimeUS();
	sipMsg->callid = packetS->get_callid();
	sipMsg->cseq_number = packetS->cseq.number;
	if(!IS_SIP_RESXXX(packetS->sip_method)) {
		sipMsg->ip_src = packetS->saddr_();
		sipMsg->ip_dst = packetS->daddr_();
		sipMsg->port_src = packetS->source_();
		sipMsg->port_dst = packetS->dest_();
	} else {
		sipMsg->ip_src = packetS->daddr_();
		sipMsg->ip_dst = packetS->saddr_();
		sipMsg->port_src = packetS->dest_();
		sipMsg->port_dst = packetS->source_();
	}
	sipMsg->vlan = packetS->pid.vlan;
	sipMsg->number_src = data_callerd.caller;
	sipMsg->number_dst = data_callerd.called();
	sipMsg->domain_src = data_callerd.caller_domain;
	sipMsg->domain_dst = data_callerd.called_domain();
	sipMsg->callername = data_callerd.callername;

	long unsigned int ua_len;
	char *ua = gettag_sip(packetS, "\nUser-Agent:", &ua_len);
	if(ua) {
		sipMsg->ua = string(ua, ua_len);
	}
	if(IS_SIP_RESXXX(packetS->sip_method)) {
		sipMsg->response = true;
		sipMsg->response_number = packetS->lastSIPresponseNum;
		sipMsg->response_string = packetS->lastSIPresponse;
	}
	sipMsg->id_sensor = packetS->sensor_id_();
	sipMsgRelations->addSipMsg(sipMsg, packetS);
}

void process_packet_sip_other(packet_s_process *packetS) {
	if(sverb.dump_sip) {
		string dump_data(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen);
		if(sverb.dump_sip_line) {
			find_and_replace(dump_data, CR_STR, CR_STR_ESC);
			find_and_replace(dump_data, LF_STR, LF_STR_ESC);
		}
		if(!sverb.dump_sip_without_counter) {
			#if USE_PACKET_NUMBER
			cout << packetS->packet_number
			#else
			cout << (++glob_packet_number)
			#endif
			<< " "
			<< packetS->saddr_().getString() << ':' << packetS->source_() 
			<< " -> "
			<< packetS->daddr_().getString() << ':' << packetS->dest_() 
			<< endl;
		}
		cout << dump_data << endl;
	}
	if((packetS->is_options() && opt_sip_options) ||
	   (packetS->is_subscribe() && opt_sip_subscribe) ||
	   (packetS->is_notify() && opt_sip_notify)) {
		process_packet_sip_other_sip_msg(packetS);
	}
	save_live_packet(packetS);
}

inline int process_packet__rtp_call_info(packet_s_process_calls_info *call_info, packet_s_process_0 *packetS,
					 int preSyncRtp = false, int threadIndex = 0, int threadIndex2 = 0) {
	packetS->blockstore_addflag(51 /*pb lock flag*/);
	Call *call;
	int iscaller;
	bool is_rtcp;
	bool stream_in_multiple_calls;
	s_sdp_flags sdp_flags;
	unsigned call_info_index;
	int count_use = 0;
	packet_s_process_rtp_call_info call_info_temp[packet_s_process_calls_info::max_calls()];
	size_t call_info_temp_length = 0;
	for(call_info_index = 0; call_info_index < call_info->length; call_info_index++) {
		if(threadIndex &&
		   call_info->calls[call_info_index].call->thread_num_rd != (threadIndex - 1)) {
			continue;
		}
		
		packetS->blockstore_addflag(52 /*pb lock flag*/);
		
		call = call_info->calls[call_info_index].call;
		iscaller = call_info->calls[call_info_index].iscaller;
		sdp_flags = call_info->calls[call_info_index].sdp_flags;
		is_rtcp = call_info->calls[call_info_index].is_rtcp || 
			  ((sdp_flags.is_audio() || sdp_flags.is_video()) && packetS->datalen_() > 1 && RTP::isRTCP_enforce(packetS->data_()));
		stream_in_multiple_calls = call_info->calls[call_info_index].multiple_calls;
		
		if(!call_info->find_by_dest && iscaller_is_set(iscaller)) {
			iscaller = iscaller_inv_index(iscaller);
		}
		
		if(sverb.process_rtp) {
			++process_rtp_counter;
			cout << "RTP - process_packet -"
			     << " callid: " << call->call_id
			     << (call_info->find_by_dest ? " src: " : " SRC: ") << packetS->saddr_().getString() << " : " << packetS->source_()
			     << (call_info->find_by_dest ? " DST: " : " dst: ") << packetS->daddr_().getString() << " : " << packetS->dest_()
			     << " direction: " << iscaller_description(iscaller) 
			     << " find_by_dest: " << call_info->find_by_dest
			     << " counter: " << process_rtp_counter
			     << endl;
		}

		if(pcap_drop_flag) {
			call->pcap_drop = pcap_drop_flag;
		}

		if(!is_rtcp && (sdp_flags.is_audio() || sdp_flags.is_video()) &&
		   (packetS->datalen_() < RTP_FIXED_HEADERLEN ||
		    packetS->header_pt->caplen <= (unsigned)(packetS->datalen_() - RTP_FIXED_HEADERLEN))) {
			break;
		}

		if(opt_ipaccount && packetS->block_store) {
			packetS->block_store->setVoipPacket(packetS->block_store_index);
		}

		if(sdp_flags.is_image()) {
			call->seenudptl = 1;
		}
		
		if(rtp_threaded && !sverb.disable_threads_rtp) {
			call_info_temp[call_info_temp_length].call = call;
			call_info_temp[call_info_temp_length].iscaller = iscaller;
			call_info_temp[call_info_temp_length].sdp_flags = sdp_flags;
			call_info_temp[call_info_temp_length].is_rtcp = is_rtcp;
			call_info_temp[call_info_temp_length].multiple_calls = stream_in_multiple_calls;
			call_info->calls[call_info_index].use_sync = true;
			++call_info_temp_length;
		} else {
			bool rslt_read_rtp = false;
			if(!sverb.disable_read_rtp) {
				if(is_rtcp) {
					rslt_read_rtp = call->read_rtcp(packetS, iscaller, enable_save_rtcp(call));
				} else {
					rslt_read_rtp = call->read_rtp(packetS, iscaller, call_info->find_by_dest, stream_in_multiple_calls, sdp_flags, enable_save_rtp_media(call, sdp_flags), 
								       packetS->block_store && packetS->block_store->ifname[0] ? packetS->block_store->ifname : NULL);
				}
			}
			if(rslt_read_rtp) {
				if(is_rtcp) {
					call->set_last_rtcp_packet_time_us(packetS->getTimeUS());
				} else {
					call->set_last_rtp_packet_time_us(packetS->getTimeUS());
				}
			}
			packetS->blockstore_addflag(59 /*pb lock flag*/);
			PACKET_S_PROCESS_DESTROY(&packetS);
		}
		
		if(packetS) {
			call->shift_destroy_call_at(packetS->getTime_s());
		} else {
			break;
		}
		++count_use;
	}
	for(call_info_index = 0; call_info_index < call_info->length; call_info_index++) {
		if(threadIndex &&
		   call_info->calls[call_info_index].call->thread_num_rd != (threadIndex - 1)) {
			continue;
		}
		if(!call_info->calls[call_info_index].use_sync) {
			if(preSyncRtp) {
				__sync_sub_and_fetch(&call_info->calls[call_info_index].call->rtppacketsinqueue, 1);
			}
			if(packetS) {
				packetS->blockstore_addflag(58 /*pb lock flag*/);
				if(opt_t2_boost ? threadIndex : threadIndex2) {
					PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 50 + (opt_t2_boost ? threadIndex : threadIndex2) - 1);
				} else {
					PACKET_S_PROCESS_DESTROY(&packetS);
				}
			}
		}
	}
	if(packetS &&
	   rtp_threaded && !sverb.disable_threads_rtp &&
	   call_info_temp_length) {
		for(unsigned i = 0; i < call_info_temp_length; i++) {
			call = call_info_temp[i].call;
			iscaller = call_info_temp[i].iscaller;
			sdp_flags = call_info_temp[i].sdp_flags;
			is_rtcp = call_info_temp[i].is_rtcp;
			stream_in_multiple_calls = call_info_temp[i].multiple_calls;
			packetS->blockstore_addflag(55 /*pb lock flag*/);
			if(is_rtcp) {
				packetS->blockstore_addflag(56 /*pb lock flag*/);
				add_to_rtp_thread_queue(call, packetS,
							iscaller, call_info->find_by_dest, is_rtcp, stream_in_multiple_calls, sdp_flags, enable_save_rtcp(call), 
							preSyncRtp, threadIndex);
			} else {
				packetS->blockstore_addflag(57 /*pb lock flag*/);
				add_to_rtp_thread_queue(call, packetS, 
							iscaller, call_info->find_by_dest, is_rtcp, stream_in_multiple_calls, sdp_flags, enable_save_rtp_media(call, sdp_flags),
							preSyncRtp, threadIndex);
			}
		}
	}
	return(count_use);
}

Call *process_packet__rtp_nosip(vmIP saddr, vmPort source, vmIP daddr, vmPort dest, 
				char *data, unsigned datalen, int /*dataoffset*/,
				pcap_pkthdr *header, const u_char */*packet*/, int /*istcp*/, struct iphdr2 *header_ip,
				pcap_block_store */*block_store*/, int /*block_store_index*/, int dlt, int sensor_id, vmIP sensor_ip,
				pcap_t *handle) {
	unsigned long int flags = 0;
	set_global_flags(flags);
	IPfilter::add_call_flags(&flags, saddr, daddr);
	if(flags & FLAG_SKIPCDR) {
		if(verbosity > 1)
			syslog(LOG_NOTICE, "call skipped due to ip or tel capture rules\n");
		return NULL;
	}
	
	// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
	char s[256];
	RTP rtp(sensor_id, sensor_ip);
	RTPMAP rtpmap[MAX_RTPMAP];

	rtp.read((unsigned char*)data, header_ip, &datalen, header, saddr, daddr, source, dest, sensor_id, sensor_ip);

	if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
		return NULL;
	}
	snprintf(s, 256, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

	//printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

	Call *call = calltable->add(INVITE, s, strlen(s), NULL,
				    getTimeUS(header), saddr, source, 
				    handle, dlt, sensor_id);
	call->set_first_packet_time_us(getTimeUS(header));
	call->setSipcallerip(saddr, vmIP(0), 0xFF, source);
	call->setSipcalledip(daddr, vmIP(0), 0xFF, dest);
	call->flags = flags;
	strcpy_null_term(call->fbasename, s);
	call->seeninvite = true;
	strcpy(call->callername, "RTP");
	strcpy(call->caller, "RTP");
	strcpy(call->called_to, "RTP");

#ifdef DEBUG_INVITE
	syslog(LOG_NOTICE, "New RTP call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s]\n", call->sipcallerip, call->sipcalledip, call->caller, call->called);
#endif

	// opening dump file
	if(enable_save_any(call)) {
		spooldir_mkdir(call->get_pathname(tsf_rtp));
	}
	if(enable_save_packet(call)) {
		string pathfilename = call->get_pathfilename(tsf_rtp);
		if(call->getPcap()->open(tsf_rtp, pathfilename.c_str(), call->useHandle, call->useDlt)) {
			if(verbosity > 3) {
				syslog(LOG_NOTICE,"pcap_filename: [%s]\n", pathfilename.c_str());
			}
		}
	}

	call->add_ip_port_hash(saddr, daddr, ip_port_call_info::_ta_base, dest, &header->ts, 
			       NULL, NULL, false, 
			       NULL, NULL,
			       NULL, NULL, 1, rtpmap, s_sdp_flags());
	call->add_ip_port_hash(saddr, saddr, ip_port_call_info::_ta_base, source, &header->ts, 
			       NULL, NULL, false, 
			       NULL, NULL,
			       NULL, NULL, 0, rtpmap, s_sdp_flags());
	
	return(call);
}

inline bool call_confirmation_for_rtp_processing(Call *call, packet_s_process_calls_info *call_info, packet_s_process_0 *packetS) {
	if(call->suppress_rtp_proc_due_to_insufficient_hw_performance) {
		return(false);
	}
	if(!(call->typeIs(SKINNY_NEW) ? opt_rtpfromsdp_onlysip_skinny : opt_rtpfromsdp_onlysip) ||
	   (call_info->find_by_dest ?
	     call->checkKnownIP_inSipCallerdIP(packetS->saddr_()) :
	     call->checkKnownIP_inSipCallerdIP(packetS->daddr_())) ||
	   (call_info->find_by_dest ?
	     calltable->check_call_in_hashfind_by_ip_port(call, packetS->saddr_(), packetS->source_(), false) &&
	     call->checkKnownIP_inSipCallerdIP(packetS->daddr_()) :
	     calltable->check_call_in_hashfind_by_ip_port(call, packetS->daddr_(), packetS->dest_(), false) &&
	     call->checkKnownIP_inSipCallerdIP(packetS->saddr_()))) {
		if((opt_ignore_rtp_after_bye_confirmed &&
		    call->seenbyeandok && call->seenbyeandok_time_usec &&
		    packetS->getTimeUS() > call->seenbyeandok_time_usec) ||
		   (opt_ignore_rtp_after_cancel_confirmed &&
		    call->seencancelandok && call->seencancelandok_time_usec &&
		    packetS->getTimeUS() > call->seencancelandok_time_usec) ||
		   (opt_ignore_rtp_after_auth_failed &&
		    call->seenauthfailed && call->seenauthfailed_time_usec &&
		    packetS->getTimeUS() > call->seenauthfailed_time_usec) ||
		   (opt_hash_modify_queue_length_ms && call->end_call_rtp) ||
		   (call->flags & FLAG_SKIPCDR)) {
			return(false);
		}
		if(processing_limitations.suppressRtpSelectiveProcessing()) {
			call->suppress_rtp_proc_due_to_insufficient_hw_performance = true;
			return(false);
		}
		return(true);
	}
	return(false);
}

bool process_packet_rtp(packet_s_process_0 *packetS) {
	packetS->blockstore_addflag(21 /*pb lock flag*/);
	if(packetS->datalen_() <= 2) { // && (htons(*(unsigned int*)data) & 0xC000) == 0x8000) { // disable condition - failure for udptl (fax)
		packetS->init2_rtp();
		packetS->blockstore_addflag(22 /*pb lock flag*/);
		return(false);
	}
	if(packetS->audiocodes) {
		if(packetS->audiocodes->media_type != sAudiocodes::ac_mt_RTP &&
		   packetS->audiocodes->media_type != sAudiocodes::ac_mt_RTCP &&
		   packetS->audiocodes->media_type != sAudiocodes::ac_mt_RTP_RFC2833) {
			packetS->init2_rtp();
			packetS->blockstore_addflag(22 /*pb lock flag*/);
			return(false);
		}
	}
	if(processRtpPacketHash) {
		packetS->blockstore_addflag(23 /*pb lock flag*/);
		processRtpPacketHash->push_packet(packetS);
		return(true);
	} else {
		packetS->blockstore_addflag(24 /*pb lock flag*/);
		packetS->init2_rtp();
		packet_s_process_calls_info *call_info = packet_s_process_calls_info::create();
		call_info->length = 0;
		call_info->find_by_dest = false;
		calltable->lock_calls_hash();
		node_call_rtp *n_call = NULL;
		if((n_call = calltable->hashfind_by_ip_port(packetS->daddr_(), packetS->dest_(), false))) {
			call_info->find_by_dest = true;
			packetS->blockstore_addflag(25 /*pb lock flag*/);
		} else {
			n_call = calltable->hashfind_by_ip_port(packetS->saddr_(), packetS->source_(), false);
			packetS->blockstore_addflag(26 /*pb lock flag*/);
		}
		#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
		if(n_call && !n_call->empty()) {
		#else
		if(n_call) {
		#endif
			++counter_rtp_packets[0];
			#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
			for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end(); iter++) {
				call_rtp *call_rtp = *iter;
			#else
			for (; n_call != NULL; n_call = n_call->next) {
				call_rtp *call_rtp = n_call;
			#endif
				Call *call = call_rtp->call;
				if(call_confirmation_for_rtp_processing(call, call_info, packetS)) {
					/*
					if(packetS->getTimeUS() < (call->first_packet_time * 1000000ull + call->first_packet_usec) + (0 * 60 + 0) * 1000000ull) {
						continue;
					}
					*/
					++counter_rtp_packets[1];
					packetS->blockstore_addflag(27 /*pb lock flag*/);
					call_info->calls[call_info->length].call = call;
					call_info->calls[call_info->length].iscaller = call_rtp->iscaller;
					call_info->calls[call_info->length].is_rtcp = call_rtp->is_rtcp;
					call_info->calls[call_info->length].sdp_flags = call_rtp->sdp_flags;
					if(call->use_rtcp_mux && !call_info->calls[call_info->length].sdp_flags.rtcp_mux) {
						s_sdp_flags *sdp_flags_other_side = call_info->find_by_dest ?
										     calltable->get_sdp_flags_in_hashfind_by_ip_port(call, packetS->saddr_(), packetS->source_(), false) :
										     calltable->get_sdp_flags_in_hashfind_by_ip_port(call, packetS->daddr_(), packetS->dest_(), false);
						if(sdp_flags_other_side && sdp_flags_other_side->rtcp_mux) {
							call_info->calls[call_info->length].sdp_flags.rtcp_mux = true;
						}
					}
					call_info->calls[call_info->length].use_sync = false;
					call_info->calls[call_info->length].multiple_calls = false;
					++call_info->length;
					if(call_info->length >= packet_s_process_calls_info::max_calls()) {
						break;
					}
				}
			}
			if(call_info->length > 1 && !packetS->audiocodes) {
				for(unsigned i = 0; i < call_info->length; i++) {
					call_info->calls[i].multiple_calls = true;
				}
			}
		}
		calltable->unlock_calls_hash();
		if(call_info->length) {
			if(call_info->length > 1) {
				packetS->set_use_reuse_counter();
				packetS->reuse_counter_inc_sync(call_info->length);
			}
			process_packet__rtp_call_info(call_info, packetS);
			packet_s_process_calls_info::free(call_info);
			return(true);
		} else if(opt_rtpnosip) {
			process_packet__rtp_nosip(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), 
						  packetS->data_(), packetS->datalen_(), packetS->dataoffset_(),
						  packetS->header_pt, packetS->packet, packetS->pflags.tcp, packetS->header_ip_(),
						  packetS->block_store, packetS->block_store_index, packetS->dlt, packetS->sensor_id_(), packetS->sensor_ip,
						  get_pcap_handle(packetS->handle_index));
		}
		packet_s_process_calls_info::free(call_info);
	}
	
	return(false);
}

struct sDissectPart {
	enum eTypePart {
		_sctp,
		_sonus,
		_rudp,
		_other
	};
	size_t pos;
	int type;
};

void process_packet_other(packet_s_stack *packetS) {
	if(!packetS->pflags.tcp && (ss7_rudp_portmatrix[packetS->source_()] || ss7_rudp_portmatrix[packetS->dest_()]) &&
	   packetS->datalen_() <= 5) {
		return;
	}
	process_packet__cleanup_ss7(packetS->getTimeval_pt());
	extern void ws_dissect_packet(pcap_pkthdr* header, const u_char* packet, int dlt, string *rslt);
	string dissect_rslt;
	ws_dissect_packet(packetS->header_pt, packetS->packet, packetS->dlt, &dissect_rslt);
	if(!dissect_rslt.empty()) {
		vector<sDissectPart> dissect_parts;
		for(int i = 0; i < 3; i++) {
			const char *tag = i == 0 ? "sctp" : 
					  i == 1 ? "sonuscm" :
						   "rudp";
			size_t pos = 0;
			size_t _pos;
			do {
				_pos = string::npos;
				for(int j = 0; j < 2; j++) {
					string find_tag = string("\"") + tag + (j == 0 ? "\": {" : "\":{");
					size_t __pos = dissect_rslt.find(find_tag, pos);
					if(__pos != string::npos && (_pos == string::npos || __pos < _pos)) {
						_pos = __pos;
					}
				}
				if(_pos != string::npos) {
					sDissectPart part;
					part.pos = _pos;
					part.type = i == 0 ? sDissectPart::_sctp : 
						    i == 1 ? sDissectPart::_sonus :
							     sDissectPart::_rudp;
					dissect_parts.push_back(part);
					pos = _pos + 1;
				}
			} while(_pos != string::npos);
			if(dissect_parts.size()) {
				break;
			}
		}
		if(!dissect_parts.size()) {
			sDissectPart part;
			part.pos = 0;
			part.type = sDissectPart::_other;
			dissect_parts.push_back(part);
		}
		for(size_t i = 0; i < dissect_parts.size(); i++) {
			Ss7::sParseData parseData;
			string dissect_part = dissect_rslt.substr(dissect_parts[i].pos,
								  i < dissect_parts.size() - 1 ? dissect_parts[i + 1].pos - dissect_parts[i].pos : string::npos);
			if(parseData.parse(packetS, dissect_part.c_str()) && parseData.isOk()) {
				Ss7 *ss7 = NULL;
				string ss7_id = parseData.ss7_id();
				calltable->lock_process_ss7_listmap();
				ss7 = calltable->find_by_ss7_id(&ss7_id);
				if(ss7 && parseData.isup_message_type == SS7_IAM) {
					ss7->pushToQueue(&ss7_id);
					ss7 = NULL;
				}
				if(ss7) {
					ss7->processData(packetS, &parseData);
					if(parseData.isup_message_type == SS7_RLC && !opt_ss7timeout_rlc) {
						ss7->pushToQueue(&ss7_id);
					}
				} else if(parseData.isup_message_type == SS7_IAM) {
					ss7 = calltable->add_ss7(packetS, &parseData);
					if(dissect_parts[i].type == sDissectPart::_sonus) {
						ss7->sonus = true;
					} else if(dissect_parts[i].type == sDissectPart::_rudp) {
						ss7->rudp = true;
					}
				}
				calltable->unlock_process_ss7_listmap();
			}
		}
	}
}

inline void process_packet__parse_custom_headers(Call *call, packet_s_process *packetS) {
	if(packetS->_customHeadersDone) {
		return;
	}
	if(call->typeIs(INVITE) && custom_headers_cdr) {
		custom_headers_cdr->parse(call, INVITE, NULL, packetS);
	}
	if(call->typeIs(MESSAGE) && custom_headers_message) {
		custom_headers_message->parse(call, MESSAGE, NULL, packetS);
	}
	packetS->_customHeadersDone = true;
}

inline void process_packet__parse_rtcpxr(Call* call, packet_s_process *packetS, timeval tv) {
	string ssrc;
	vmIP ipLocal;
	vmIP ipRemote;
	unsigned long localAddrLen;
	char *localAddrPtr = gettag_sip(packetS, "\nLocalAddr:", &localAddrLen);
	if(localAddrPtr && localAddrLen) {
		char endChar = localAddrPtr[localAddrLen];
		localAddrPtr[localAddrLen] = 0;
		char *ssrcPtr = strcasestr(localAddrPtr, "SSRC=");
		if(ssrcPtr) {
			ssrcPtr += 5;
			int ssrcLen = 0;
			while(ssrcPtr[ssrcLen] && ssrcPtr[ssrcLen] != ' ' && ssrcPtr[ssrcLen] != CR_CHAR && ssrcPtr[ssrcLen] != LF_CHAR) {
				++ssrcLen;
			}
			if(ssrcLen) {
				ssrc = string(ssrcPtr, ssrcLen);
			}
		}
		char *ipPtr = strcasestr(localAddrPtr, "IP=");
		if(ipPtr) {
			ipPtr += 3;
			int ipLen = 0;
			while(ipPtr[ipLen] && ipPtr[ipLen] != ' ' && ipPtr[ipLen] != CR_CHAR && ipPtr[ipLen] != LF_CHAR) {
				++ipLen;
			}
			if(ipLen) {
				ipLocal.setFromString(string(ipPtr, ipLen).c_str());
			}
		}
		localAddrPtr[localAddrLen] = endChar;
	}
	if(ssrc.empty()) {
		return;
	}
	unsigned long remoteAddrLen;
	char *remoteAddrPtr = gettag_sip(packetS, "\nRemoteAddr:", &remoteAddrLen);
	if(remoteAddrPtr && remoteAddrLen) {
		char endChar = remoteAddrPtr[remoteAddrLen];
		remoteAddrPtr[localAddrLen] = 0;
		char *ipPtr = strcasestr(remoteAddrPtr, "IP=");
		if(ipPtr) {
			ipPtr += 3;
			int ipLen = 0;
			while(ipPtr[ipLen] && ipPtr[ipLen] != ' ' && ipPtr[ipLen] != CR_CHAR && ipPtr[ipLen] != LF_CHAR) {
				++ipLen;
			}
			if(ipLen) {
				ipRemote.setFromString(string(ipPtr, ipLen).c_str());
			}
		}
		remoteAddrPtr[remoteAddrLen] = endChar;
	}
	int16_t moslq = -1;
	unsigned long qualityEstLen;
	char *qualityEstPtr = gettag_sip(packetS, "\nQualityEst:", &qualityEstLen);
	if(qualityEstPtr && qualityEstLen) {
		char endChar = qualityEstPtr[qualityEstLen];
		qualityEstPtr[qualityEstLen] = 0;
		char *moslqPtr = strcasestr(qualityEstPtr, "MOSLQ=");
		if(moslqPtr) {
			moslq = round(atof(moslqPtr + 6) * 10);
		}
		qualityEstPtr[qualityEstLen] = endChar;
	}
	int16_t nlr = -1;
	unsigned long packetLossLen;
	char *packetLossPtr = gettag_sip(packetS, "\nPacketLoss:", &packetLossLen);
	if(packetLossPtr && packetLossLen) {
		char endChar = packetLossPtr[packetLossLen];
		packetLossPtr[packetLossLen] = 0;
		char *nlrPtr = strcasestr(packetLossPtr, "NLR=");
		if(nlrPtr) {
			nlr= round(atof(nlrPtr + 4) * 255 / 100);
		}
		packetLossPtr[packetLossLen] = endChar;
	}
	u_int32_t ssrc_int;
	if(ssrc.length() > 2 && ssrc[0] == '0' && ssrc[1] == 'x') {
		sscanf(ssrc.c_str() + 2, "%x", &ssrc_int);
	} else {
		ssrc_int = strtol(ssrc.c_str(), 0, 16);
	}
	call->rtcpXrData.add(ssrc_int, tv, moslq, nlr, ipLocal, ipRemote);
}

inline void process_packet__cleanup_calls(timeval *ts_input, const char *file, int line) {
	bool doQuickCleanup = false;
	if(opt_quick_save_cdr &&
	   (count_sip_bye != process_packet__last_cleanup_calls__count_sip_bye ||
	    count_sip_bye_confirmed != process_packet__last_cleanup_calls__count_sip_bye_confirmed ||
	    count_sip_cancel != process_packet__last_cleanup_calls__count_sip_cancel ||
	    count_sip_cancel_confirmed != process_packet__last_cleanup_calls__count_sip_cancel_confirmed)) {
		doQuickCleanup = true;
	}
	u_int64_t actTimeMS = getTimeMS_rdtsc();
	timeval ts;
	if(ts_input) {
		process_packet__last_cleanup_calls_diff = getTimeMS(ts_input) - actTimeMS;
		if(opt_scanpcapdir[0] &&
		   process_packet__last_cleanup_calls > ts_input->tv_sec) {
			process_packet__last_cleanup_calls = ts_input->tv_sec;
		}
		if(!doQuickCleanup &&
		   getTimeS(ts_input) <= (time_t)(process_packet__last_cleanup_calls + (opt_quick_save_cdr ? 1 : (unsigned)opt_cleanup_calls_period))) {
			return;
		}
		ts = *ts_input;
	} else {
		u_int64_t corTimeMS = actTimeMS + process_packet__last_cleanup_calls_diff;
		ts.tv_sec = corTimeMS / 1000;
		ts.tv_usec = corTimeMS % 1000 * 1000;
	}
	if(!doQuickCleanup &&
	   ts.tv_sec <= (time_t)(process_packet__last_cleanup_calls + (opt_quick_save_cdr ? 1 : opt_cleanup_calls_period))) {
		return;
	}
	if(verbosity > 0 && is_read_from_file_simple()) {
		if(opt_dup_check) {
			syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d] skipped dupe pkts [%u]\n", 
				(int)calltable->getCountCalls(), (int)calltable->calls_queue.size(), duplicate_counter);
		} else {
			syslog(LOG_NOTICE, "Active calls [%d] calls in sql queue [%d]\n", 
				(int)calltable->getCountCalls(), (int)calltable->calls_queue.size());
		}
	}
	process_packet__last_cleanup_calls = ts.tv_sec;
	calltable->cleanup_calls(&ts, false, file, line);
	listening_cleanup();
	
	process_packet__last_cleanup_calls__count_sip_bye = count_sip_bye;
	process_packet__last_cleanup_calls__count_sip_bye_confirmed = count_sip_bye_confirmed;
	process_packet__last_cleanup_calls__count_sip_cancel = count_sip_cancel;
	process_packet__last_cleanup_calls__count_sip_cancel_confirmed = count_sip_cancel_confirmed;

	/* You may encounter that voipmonitor process does not have a reduced memory usage although you freed the calls. 
	This is because it allocates memory in a number of small chunks. When freeing one of those chunks, the OS may decide 
	that giving this little memory back to the kernel will cause too much overhead and delay the operation. As all chunks 
	are this small, they get actually freed but not returned to the kernel. On systems using glibc, there is a function call 
	"malloc_trim" from malloc.h which does this missing operation (note that it is allowed to fail). If your OS does not provide 
	malloc_trim, try searching for a similar function.
	*/
	
	extern int opt_memory_purge_interval;
	extern bool opt_hugepages_anon;
	extern int opt_hugepages_max;
	extern int opt_hugepages_overcommit_max;
	if(opt_memory_purge_interval &&
	   ((!opt_hugepages_max && !opt_hugepages_overcommit_max) || opt_hugepages_anon) &&
	   ts.tv_sec - __last_memory_purge >= (unsigned)opt_memory_purge_interval) {
		bool firstRun = __last_memory_purge == 0;
		__last_memory_purge = ts.tv_sec;
		if(!firstRun) {
			rss_purge();
                }
        }

}

inline void process_packet__cleanup_registers(timeval *ts_input) {
	u_int64_t actTimeMS = getTimeMS_rdtsc();
	timeval ts;
	if(ts_input) {
		process_packet__last_cleanup_registers_diff = getTimeMS(ts_input) - actTimeMS;
		if(getTimeS(ts_input) - process_packet__last_cleanup_registers < 10) {
			return;
		}
		ts = *ts_input;
	} else {
		u_int64_t corTimeMS = actTimeMS + process_packet__last_cleanup_registers_diff;
		ts.tv_sec = corTimeMS / 1000;
		ts.tv_usec = corTimeMS % 1000 * 1000;
	}
	if(ts.tv_sec - process_packet__last_cleanup_registers < 10) {
		return;
	}
	calltable->cleanup_registers(&ts);
	if(opt_sip_register == 1) {
		extern Registers registers;
		registers.cleanup(&ts, false, 30);
	}
	process_packet__last_cleanup_registers = ts.tv_sec;
}

inline void process_packet__cleanup_ss7(timeval *ts_input) {
	u_int64_t actTimeMS = getTimeMS_rdtsc();
	timeval ts;
	if(ts_input) {
		process_packet__last_cleanup_ss7_diff = getTimeMS(ts_input) - actTimeMS;
		if(getTimeS(ts_input) - process_packet__last_cleanup_ss7 < 10) {
			return;
		}
		ts = *ts_input;
	} else {
		u_int64_t corTimeMS = actTimeMS + process_packet__last_cleanup_ss7_diff;
		ts.tv_sec = corTimeMS / 1000;
		ts.tv_usec = corTimeMS % 1000 * 1000;
	}
	if(ts.tv_sec - process_packet__last_cleanup_ss7 < 10) {
		return;
	}
	calltable->cleanup_ss7(&ts);
	process_packet__last_cleanup_ss7 = ts.tv_sec;
}

void reset_cleanup_variables() {
	process_packet__last_cleanup_calls = 0;
	process_packet__last_cleanup_calls_diff = 0;
	process_packet__last_destroy_calls = 0;
	process_packet__last_cleanup_registers = 0;
	process_packet__last_cleanup_registers_diff = 0;
	process_packet__last_destroy_registers = 0;
	process_packet__last_cleanup_ss7 = 0;
	process_packet__last_cleanup_ss7_diff = 0;
	__last_memory_purge = 0;
}

inline int process_packet__parse_sip_method(char *data, unsigned int datalen, bool *sip_response) {
	int sip_method = 0;
	if(sip_response) {
		*sip_response =  false;
	}
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
		if(sip_response) {
			*sip_response = true;
		}
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
				} else {
					// SIP/2.0 182 Queued, avaya-cm-data=00480BEE0C18002A
					if(data[9] == '8') {
						if( (datalen > 10) && (data[10] == '2') ) {
							if(verbosity > 2) 
								 syslog(LOG_NOTICE,"SIP msg: 182\n");
							sip_method = RES182;
						} else {
							if(verbosity > 2) 
								 syslog(LOG_NOTICE,"SIP msg: 18X\n");
							sip_method = RES18X;
						}
					}
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

inline int process_packet__parse_sip_method(packet_s_process *packetS, bool *sip_response) {
	return(process_packet__parse_sip_method(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen, sip_response));
}

inline bool process_packet__parse_cseq(sCseq *cseq, char *cseqstr, unsigned int cseqlen) {
	unsigned cseq_pos_method = 0;
	while(cseq_pos_method < cseqlen && (isdigit(cseqstr[cseq_pos_method]) || cseqstr[cseq_pos_method] == ' ')) {
		++cseq_pos_method;
	}
	if(cseq_pos_method < cseqlen) {
		cseq->method = process_packet__parse_sip_method(cseqstr + cseq_pos_method, cseqlen - cseq_pos_method, NULL);
		cseq->number = atol(cseqstr);
		return(true);
	}
	return(false);
}

inline bool process_packet__parse_cseq(sCseq *cseq, packet_s_process *packetS) {
	unsigned long cseqlen;
	char *cseqstr = gettag_sip(packetS, "\nCSeq:", &cseqlen);
	if(cseq && cseqlen < 32) {
		return(process_packet__parse_cseq(cseq, cseqstr, cseqlen));
	}
	return(false);
}

inline int parse_packet__last_sip_response(char *data, unsigned int datalen, int sip_method, bool sip_response,
					   char *lastSIPresponse, bool *call_cancel_lsr487) {
	strcpy(lastSIPresponse, "NO RESPONSE");
	*call_cancel_lsr487 = false;
	int lastSIPresponseNum = 0;
	if(IS_SIP_RESXXX(sip_method) || sip_response) {
		char a = data[datalen - 1];
		data[datalen - 1] = 0;
		char *tmp = NULL;
		if(((tmp = strstr(data, CR_STR)) != NULL ||
		    (tmp = strstr(data, LF_STR)) != NULL) &&
		   tmp > data + 8) {
			// 8 is len of [SIP/2.0 ], 128 is max buffer size
			int lastSIPresponseLength = min((int)(tmp - (data + 8)), 127);
			strncpy(lastSIPresponse, data + 8, lastSIPresponseLength);
			lastSIPresponse[lastSIPresponseLength] = '\0';
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

inline int parse_packet__last_sip_response(packet_s_process *packetS, int sip_method, bool sip_response,
					   char *lastSIPresponse, bool *call_cancel_lsr487) {
	return(parse_packet__last_sip_response(packetS->data_()+ packetS->sipDataOffset, packetS->sipDataLen, sip_method, sip_response,
					       lastSIPresponse, call_cancel_lsr487));
}

inline int parse_packet__message(packet_s_process *packetS, bool strictCheckLength,
				 char **rsltMessage, char **rsltMessageInfo, string *rsltDestNumber, string *rsltSrcNumber, unsigned int *rsltContentLength,
				 unsigned int *rsltDcs, Call::eVoicemail *rsltVoicemail,
				 bool maskMessage) {
	if(rsltMessage) {
		*rsltMessage = NULL;
	}
	if(rsltMessageInfo) {
		*rsltMessageInfo = NULL;
	}
	if(rsltContentLength) {
		*rsltContentLength = (unsigned int)-1;
	}
	char *data = packetS->data_()+ packetS->sipDataOffset;
	unsigned int datalen = packetS->sipDataLen;
	int setMessage = 0;
	char endCharData = data[datalen - 1];
	data[datalen - 1] = 0;
	char *contentBegin = NULL;
	for(int pass_line_separator = 0; pass_line_separator < 2 && !contentBegin; pass_line_separator++) {
		char *endHeader = strstr(data, SIP_DBLLINE_SEPARATOR(pass_line_separator == 1));
		if(endHeader) {
			contentBegin = endHeader + SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1);
		}
	}
	if(!contentBegin) {
		data[datalen - 1] = endCharData;
		return(-1);
	}
	int contentLength = 0;
	unsigned long l;
	char *contLengthPos = NULL;
	for(int pass = 0; pass < 2 && !contLengthPos; ++pass) {
		contLengthPos = gettag_sip(packetS,
					   pass ? 
					    LF_LINE_SEPARATOR "l:" : 
					    LF_LINE_SEPARATOR "Content-Length:",
					   &l);
	}
	if(contLengthPos) {
		char endCharContentLength = contLengthPos[l];
		contLengthPos[l] = '\0';
		contentLength = atoi(contLengthPos);
		if(rsltContentLength) {
			*rsltContentLength = contentLength;
		}
		contLengthPos[l] = endCharContentLength;
	}
	if(contentLength > 0 && (unsigned)contentLength < packetS->sipDataLen) {
		char *contentEnd = strcasestr(contentBegin, "\n\nContent-Length:");
		if(!contentEnd) {
			contentEnd = strstr(contentBegin, CR_LF_LINE_SEPARATOR);
		}
		if(!contentEnd) {
			contentEnd = data + datalen;
		}
		if(!strictCheckLength || (contentEnd - contentBegin) == contentLength) {
			if((contentEnd - contentBegin) > contentLength) {
				contentEnd = contentBegin + contentLength;
			}
			data[datalen - 1] = endCharData;
			parse_packet__message_content(contentBegin, contentEnd - contentBegin,
						      rsltMessage, rsltMessageInfo, rsltDestNumber, rsltSrcNumber,
						      rsltDcs, rsltVoicemail,
						      maskMessage);
			setMessage = (rsltMessage && *rsltMessage) || (rsltMessageInfo && *rsltMessageInfo) ? 2 : 1;
		} else {
			data[datalen - 1] = endCharData;
		}
	} else {
		setMessage = contentLength == 0;
		data[datalen - 1] = endCharData;
	}
	return(setMessage);
}

inline Call *process_packet__merge(packet_s_process *packetS, char *callidstr, int *merged, bool preprocess) {
	Call *call = calltable->find_by_mergecall_id(callidstr, 0, preprocess ? packetS->getTime_s() : 0);
	if(!call) {
		// this call-id is not yet tracked either in calls list or callidmerge list 
		// check if there is SIP callidmerge_header which contains parent call-id call
		char *s2 = NULL;
		long unsigned int l2 = 0;
		unsigned char buf[1024];
		s2 = gettag_sip(packetS, opt_callidmerge_header, &l2);
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
			call = calltable->find_by_call_id(s2, l2, NULL, preprocess ? packetS->getTime_s() : 0);
			if(!call) {
				// there is no call with the call-id in merge header - this call will be created as new
			} else {
				*merged = 1;
				calltable->lock_calls_mergeMAP();
				call->has_second_merged_leg = true;
				calltable->calls_mergeMAP[callidstr] = call;
				calltable->unlock_calls_mergeMAP();
				call->mergecalls_lock();
				call->mergecalls[callidstr] = Call::sMergeLegInfo();
				call->mergecalls_unlock();
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
					int value = (unsigned char)message[getLength()];
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
	struct sConcatenatedInfo {
		int parts;
		int part;
		bool ok;
	};
	sGsmMessageData() {
		type = gsm_mt_data_type_na;
		addressLength = -1;
		dcs = -1;
		userDataLength = -1;
		userDataHeaderLength = -1;
	}
	unsigned int getLength() {
		return((type == gsm_mt_data_type_deliver ? 1 : 2) + 
		       (addressLength >= 0 ? 2 + getAddressLength() + 1 : 0) + 
		       (dcs >= 0 ? (type == gsm_mt_data_type_deliver ? 8 : 1) : 0) + 
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
		if(dcs == 0 || (dcs & 0xC0) == 0xC0) {
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
				int value = (unsigned char)data[getLength()];
				switch(pass) {
				case 0: addressLength = value; break;
				case 1: dcs = value; break;
				case 2: if(getLength() + 2 < dataLength - 1 &&
					   (unsigned char)data[getLength() + 2] == 0) {
						int _userDataHeaderLength = (unsigned char)data[getLength() + 1];
						if(_userDataHeaderLength < value) {
							userDataHeaderLength = _userDataHeaderLength;
						}
					}
					userDataLength = value; 
					break;
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
		if((addressData[-1] & 0x50) == 0x50) {
			unsigned int addressDecodeLength;
			unsigned char *addressDecode = conv7bit::decode((unsigned char*)addressData, conv7bit::encode_length(addressLength), addressDecodeLength);
			if(addressDecode) {
				address = string((char*)addressDecode, addressDecodeLength);
				delete [] addressDecode;
			}
		} else {
			for(int i = 0; i < addressLength; i++) {
				int addressNumber = (i % 2 ? (addressData[i / 2] >> 4) : addressData[i / 2]) & 0xF;
				address += '0' + addressNumber;
			}
		}
		return(address);
	}
	string getUserDataMessage(char *data) {
		if(userDataLength > 0) {
			if(dcs == 0 || (dcs & 0xC0) == 0xC0) {
				return(getUserData_7bit(data));
			}
		}
		return("");
	}
	sConcatenatedInfo getConcatenatedInfo(char *data) {
		sConcatenatedInfo concInfo;
		memset(&concInfo, 0, sizeof(concInfo));
		if(userDataHeaderLength == 5) {
			unsigned char *userDataSrc = (unsigned char*)data + getOffsetToUserData();
			if(userDataSrc[1] == 0 && userDataSrc[2] == 3 &&
			   userDataSrc[5] <= userDataSrc[4]) {
				concInfo.parts = userDataSrc[4];
				concInfo.part = userDataSrc[5];
				concInfo.ok = true;
			}
		}
		return(concInfo);
	}
	void maskUserData(char *data) {
		if(userDataLength > 0) {
			if(dcs == 0 || (dcs & 0xC0) == 0xC0) {
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
			return(userDataHeaderLength >= 0 && userDataHeaderLength < (int)userDataDecodeString.length() ?
				userDataDecodeString.substr(1 + userDataHeaderLength + 1) : 
				userDataDecodeString);
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
			if(userDataHeaderLength >= 0 && userDataHeaderLength < (int)(userDataEncodeLength - 1)) {
				memcpy(userDataSrc + 1 + userDataHeaderLength, userDataEncode + 1 + userDataHeaderLength, userDataEncodeLength - 1 - userDataHeaderLength);
			} else {
				memcpy(userDataSrc, userDataEncode, userDataEncodeLength);
			}
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
	int dcs;
	int userDataLength;
	int userDataHeaderLength;
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

void parse_packet__message_content(char *message, unsigned int messageLength,
				   char **rsltMessage, char **rsltMessageInfo, string *rsltDestNumber, string *rsltSrcNumber,
				   unsigned int *rsltDcs, Call::eVoicemail *rsltVoicemail,
				   bool maskMessage) {
	if(rsltMessage) {
		*rsltMessage = NULL;
	}
	if(rsltMessageInfo) {
		*rsltMessageInfo = NULL;
	}
	if(rsltDcs) {
		*rsltDcs = 0;
	}
	if(rsltVoicemail) {
		*rsltVoicemail = Call::voicemail_na;
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
						string rslt_message = gsmMessageData.getUserDataMessage(userData);
						if(rslt_message.length()) {
							*rsltMessage = new FILE_LINE(26007) char[rslt_message.length() + 1];
							memcpy(*rsltMessage, rslt_message.c_str(), rslt_message.length());
							(*rsltMessage)[rslt_message.length()] = '\0';
						}
						if(rsltMessageInfo) {
							string rslt_message_info;
							if(gsmMessageData.userDataHeaderLength >= 0) {
								sGsmMessageData::sConcatenatedInfo concInfo = gsmMessageData.getConcatenatedInfo(userData);
								if(concInfo.ok) {
									rslt_message_info += "concatenated message: " + 
											     intToString(concInfo.part) + "/" + intToString(concInfo.parts);
								}
							}
							if(gsmMessageData.dcs & 0xC0) {
								if(rslt_message_info.length()) {
									rslt_message_info += "|";
								}
								rslt_message_info += string("dcs: voicemail ") + (gsmMessageData.dcs & 0x8 ? "active" : "inactive");
							}
							if(rslt_message_info.length()) {
								*rsltMessageInfo = new FILE_LINE(26008) char[rslt_message_info.length() + 1];
								strcpy(*rsltMessageInfo, rslt_message_info.c_str());
							}
							if(rsltDcs) {
								*rsltDcs = gsmMessageData.dcs;
							}
							if(rsltVoicemail) {
								*rsltVoicemail = gsmMessageData.dcs & 0xC0 ?
										  (gsmMessageData.dcs & 0x8 ? Call::voicemail_active : Call::voicemail_inactive) :
										  Call::voicemail_na;
							}
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
					if(rsltMessageInfo) {
						char rslt_message_info_buff[100];
						snprintf(rslt_message_info_buff, 100, 
							 "ACK 20%02i-%02i-%02i %02i:%02i:%02i (timezone code %i)",
							 sGsmMessageAck.year,
							 sGsmMessageAck.month,
							 sGsmMessageAck.day,
							 sGsmMessageAck.hour,
							 sGsmMessageAck.minute,
							 sGsmMessageAck.second,
							 sGsmMessageAck.timezone);
						*rsltMessageInfo = new FILE_LINE(26009) char[strlen(rslt_message_info_buff) + 1];
						strcpy(*rsltMessageInfo, rslt_message_info_buff);
					}
				}
				}
				break;
			case sGsmMessage::gsm_mt_ack_ms_to_net: {
				if(rsltMessageInfo) {
					char rslt_message_info_buff[100];
					snprintf(rslt_message_info_buff, 100, 
						 "ACK");
					*rsltMessageInfo = new FILE_LINE(26010) char[strlen(rslt_message_info_buff) + 1];
					strcpy(*rsltMessageInfo, rslt_message_info_buff);
				}
				}
				break;
			case sGsmMessage::gsm_mt_na:
				break;
			}
		} else {
			if(rsltMessage) {
				*rsltMessage = new FILE_LINE(26011) char[messageLength + 1];
				memcpy(*rsltMessage, message, messageLength);
				(*rsltMessage)[messageLength] = '\0';
			}
			if(maskMessage) {
				memset(message, 'x', messageLength);
			}
		}
	}
}

bool checkEqNumbers(Call::sInviteSD_Addr *item1, Call::sInviteSD_Addr *item2) {
	bool eqCallerMinLength;
	bool eqCalledMinLength;
	bool eqCalledInviteMinLength;
	size_t eqCallerLength = strCaseEqLengthR(item1->caller.c_str(), item2->caller.c_str(), &eqCallerMinLength);
	size_t eqCalledLength = strCaseEqLengthR(item1->called.c_str(), item2->called.c_str(), &eqCalledMinLength);
	size_t eqCalledInviteLength = strCaseEqLengthR(item1->called_invite.c_str(), item2->called_invite.c_str(), &eqCalledInviteMinLength);
	return((eqCallerMinLength || eqCallerLength >= 3) &&
	       (eqCalledMinLength || eqCalledLength >= 3) &&
	       (eqCalledInviteMinLength || eqCalledInviteLength >= 3) &&
	       (eqCallerLength != eqCalledLength ||
		strcasecmp(item1->caller.c_str() + item1->caller.length() - eqCallerLength, item1->called.c_str() + item1->called.length() - eqCalledLength)));
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

/* obsolete
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

	// turn off TCP checksums
	ctl.netaddr = inet_addr("0.0.0.0");
	ctl.mask = inet_addr("0.0.0.0");
	ctl.action = NIDS_DONT_CHKSUM;
	nids_register_chksum_ctl(&ctl, 1);

	// register tcp and udp handlers
//	nids_register_tcp((void*)libnids_tcp_callback);
	nids_register_udp((void*)libnids_udp_callback);

	// read packets from libpcap in a loop
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
*/

inline void ipfrag_delete_node(ip_frag_s *node, int pushToStack_queue_index) {
	if(node->header_packet) {
		PUSH_HP(&node->header_packet, pushToStack_queue_index);
	}
	if(node->header_packet_pqout) {
		((sHeaderPacketPQout*)node->header_packet_pqout)->destroy_or_unlock_blockstore();
		delete ((sHeaderPacketPQout*)node->header_packet_pqout);
	}
	delete node;
}

/*

defragment packets from queue and allocates memory for new header and packet which is returned 
in **header an **packet 

*/
inline int _ipfrag_dequeue(ip_frag_queue *queue, 
			   sHeaderPacket **header_packet, sHeaderPacketPQout *header_packet_pqout,
			   int pushToStack_queue_index) {
	//walk queue

	if(!queue) return 1;
	if(!queue->size()) return 1;

	// prepare newpacket structure and header structure
	u_int32_t totallen = queue->begin()->second->header_ip_offset;
	unsigned i = 0;
	for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
		totallen += it->second->len;
		if(i) {
			totallen -= it->second->iphdr_len;
		}
		i++;
	}
	if(totallen > 0xFFFF + queue->begin()->second->header_ip_offset) {
		if(sverb.defrag_overflow) {
			ip_frag_queue_it_t it = queue->begin();
			if(it != queue->end()) {
				ip_frag_s *node = it->second;
				iphdr2 *iph = (iphdr2*)((u_char*)HPP(node->header_packet) + node->header_ip_offset);
				syslog(LOG_NOTICE, "ipfrag overflow: %i src ip: %s dst ip: %s", totallen, iph->get_saddr().getString().c_str(), iph->get_daddr().getString().c_str());
			}
		}
		totallen = 0xFFFF + queue->begin()->second->header_ip_offset;
	}
	
	unsigned int additionallen = 0;
	iphdr2 *iphdr = NULL;
	i = 0;
	unsigned int len = 0;
	
	if(header_packet) {
		*header_packet = CREATE_HP(totallen);
		for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
			ip_frag_s *node = it->second;
			if(i == 0) {
				// for first packet copy ethernet header and ip header
				if(node->header_ip_offset) {
					memcpy_heapsafe(HPP(*header_packet), *header_packet,
							HPP(node->header_packet), node->header_packet,
							node->header_ip_offset);
					len += node->header_ip_offset;
					iphdr = (iphdr2*)(HPP(*header_packet) + len);
				}
				memcpy_heapsafe(HPP(*header_packet) + len, *header_packet,
						HPP(node->header_packet) + node->header_ip_offset, node->header_packet,
						node->len);
				len += node->len;
			} else {
				if(len < totallen) {
					unsigned cpy_len = min((unsigned)(node->len - node->iphdr_len), totallen - len);
					memcpy_heapsafe(HPP(*header_packet) + len, *header_packet,
							HPP(node->header_packet) + node->header_ip_offset + node->iphdr_len, node->header_packet,
							cpy_len);
					len += cpy_len;
					additionallen += cpy_len;
				}
			}
			if(i == queue->size() - 1) {
				memcpy_heapsafe(HPH(*header_packet), *header_packet, 
						HPH(node->header_packet), node->header_packet,
						sizeof(struct pcap_pkthdr));
				HPH(*header_packet)->len = totallen;
				HPH(*header_packet)->caplen = totallen;
			}
			ipfrag_delete_node(node, pushToStack_queue_index);
			i++;
		}
	} else {
		header_packet_pqout->header = new FILE_LINE(26012) pcap_pkthdr_plus;
		header_packet_pqout->packet = new FILE_LINE(26013) u_char[totallen];
		header_packet_pqout->block_store = NULL;
		header_packet_pqout->block_store_index = 0;
		header_packet_pqout->block_store_locked = false;
		for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
			ip_frag_s *node = it->second;
			if(i == 0) {
				// for first packet copy ethernet header and ip header
				if(node->header_ip_offset) {
					memcpy_heapsafe(header_packet_pqout->packet, header_packet_pqout->packet,
							((sHeaderPacketPQout*)node->header_packet_pqout)->packet, 
							((sHeaderPacketPQout*)node->header_packet_pqout)->block_store ?
							 ((sHeaderPacketPQout*)node->header_packet_pqout)->block_store->block :
							 ((sHeaderPacketPQout*)node->header_packet_pqout)->packet,
							node->header_ip_offset);
					len += node->header_ip_offset;
					iphdr = (iphdr2*)(header_packet_pqout->packet + len);
				}
				memcpy_heapsafe(header_packet_pqout->packet + len, header_packet_pqout->packet,
						((sHeaderPacketPQout*)node->header_packet_pqout)->packet + node->header_ip_offset, 
						((sHeaderPacketPQout*)node->header_packet_pqout)->block_store ?
						 ((sHeaderPacketPQout*)node->header_packet_pqout)->block_store->block :
						 ((sHeaderPacketPQout*)node->header_packet_pqout)->packet,
						node->len);
				len += node->len;
			} else {
				// for rest of a packets append only data 
				if(len < totallen) {
					unsigned cpy_len = min((unsigned)(node->len - node->iphdr_len), totallen - len);
					memcpy_heapsafe(header_packet_pqout->packet + len, header_packet_pqout->packet,
							((sHeaderPacketPQout*)node->header_packet_pqout)->packet + node->header_ip_offset + node->iphdr_len, 
							((sHeaderPacketPQout*)node->header_packet_pqout)->block_store ?
							 ((sHeaderPacketPQout*)node->header_packet_pqout)->block_store->block :
							 ((sHeaderPacketPQout*)node->header_packet_pqout)->packet,
							cpy_len);
					len += cpy_len;
					additionallen += cpy_len;
				}
			}
			if(i == queue->size() - 1) {
				memcpy_heapsafe(header_packet_pqout->header, header_packet_pqout->header,
						((sHeaderPacketPQout*)node->header_packet_pqout)->header,
						((sHeaderPacketPQout*)node->header_packet_pqout)->block_store ?
						 ((sHeaderPacketPQout*)node->header_packet_pqout)->block_store->block :
						 (u_char*)((sHeaderPacketPQout*)node->header_packet_pqout)->header,
						sizeof(pcap_pkthdr_plus));
				header_packet_pqout->header->set_len(totallen);
				header_packet_pqout->header->set_caplen(totallen);
			}
			ipfrag_delete_node(node, 0);
			i++;
		}
	}
	if(iphdr) {
		//increase IP header length 
		iphdr->set_tot_len(iphdr->get_tot_len() + additionallen);
		// reset checksum
		iphdr->set_check(0);
		// reset fragment flag to 0
		iphdr->clear_frag_data();
	}
	
	return 1;
}

inline int ipfrag_dequeue(ip_frag_queue *queue,
			  sHeaderPacket **header_packet,
			  int pushToStack_queue_index) {
	return(_ipfrag_dequeue(queue,
			       header_packet, NULL,
			       pushToStack_queue_index));
}

inline int ipfrag_dequeue(ip_frag_queue *queue,
			  sHeaderPacketPQout *header_packet_pqout) {
	return(_ipfrag_dequeue(queue,
			       NULL, header_packet_pqout,
			       -1));
}

inline int _ipfrag_add(ip_frag_queue *queue, 
		       sHeaderPacket **header_packet, sHeaderPacketPQout *header_packet_pqout,
		       unsigned int header_ip_offset, unsigned int len,
		       int pushToStack_queue_index) {
 
	iphdr2 *header_ip = header_packet ?
			     (iphdr2*)((HPP(*header_packet)) + header_ip_offset) :
			     (iphdr2*)(header_packet_pqout->packet + header_ip_offset);

	u_int16_t frag_data = header_ip->get_frag_data();
	unsigned int offset_d = header_ip->get_frag_offset(frag_data);

	if(!header_ip->is_more_frag(frag_data) && offset_d) {
		// this packet do not set more fragment indicator but contains offset which means that it is the last packet
		queue->has_last = true;
	}

	if(!queue->count(offset_d)) {
		// this offset number is not yet in the queue - add packet to queue which automatically sort it into right position

		// create node
		ip_frag_s *node = new FILE_LINE(26014) ip_frag_s;

		if(header_packet) {
			node->ts = HPH(*header_packet)->ts.tv_sec;
			node->header_packet = *header_packet;
			node->header_packet_pqout = NULL;
			*header_packet = NULL;
		} else {
			node->ts = header_packet_pqout->header->get_tv_sec();
			node->header_packet_pqout = new FILE_LINE(26015) sHeaderPacketPQout;
			node->header_packet = NULL;
			*(sHeaderPacketPQout*)node->header_packet_pqout = *header_packet_pqout;
			((sHeaderPacketPQout*)node->header_packet_pqout)->alloc_and_copy_blockstore();
		}
		
		node->header_ip_offset = header_ip_offset;
		node->len = len;
		node->offset = offset_d;
		node->iphdr_len = header_ip->get_hdr_size();

		// add to queue (which will sort it automatically
		(*queue)[offset_d] = node;
	} else {
		// node with that offset already exists - discard
		return -1;
	}

	// now check if packets in queue are complete - if yes - defragment - if not, do nithing
	int ok = true;
	unsigned int lastoffset = 0;
	if(queue->has_last and queue->begin()->second->offset == 0) {
		// queue has first and last packet - check if there are all middle fragments
		for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
			ip_frag_s *node = it->second;
			if((node->offset != lastoffset)) {
				ok = false;
				break;
			}
			lastoffset += node->len - node->iphdr_len;
		}
	} else {
		// queue does not contain a last packet and does not contain a first packet
		ok = false;
	}

	if(ok) {
		// all packets -> defragment 
		_ipfrag_dequeue(queue, header_packet, header_packet_pqout, pushToStack_queue_index);
		return 1;
	} else {
		return 0;
	}
}

inline int ipfrag_add(ip_frag_queue *queue, 
		      sHeaderPacket **header_packet, 
		      unsigned int header_ip_offset, unsigned int len,
		      int pushToStack_queue_index) {
	return(_ipfrag_add(queue, 
			   header_packet, NULL,
			   header_ip_offset, len,
			   pushToStack_queue_index));
}

inline int ipfrag_add(ip_frag_queue *queue, 
		      sHeaderPacketPQout *header_packet_pqout, 
		      unsigned int header_ip_offset, unsigned int len) {
	return(_ipfrag_add(queue, 
			   NULL, header_packet_pqout,
			   header_ip_offset, len,
			   -1));
}

/* 

function inserts packet into fragmentation queue and if all packets within fragmented IP are 
complete it will dequeue and construct large packet from all fragmented packets. 

return: if packet is defragmented from all pieces function returns 1 and set header and packet 
pinters to new allocated data which has to be freed later. If packet is only queued function
returns 0 and header and packet remains same

*/
inline int _handle_defrag(iphdr2 *header_ip, 
			  sHeaderPacket **header_packet, sHeaderPacketPQout *header_packet_pqout, 
			  ipfrag_data_s *ipfrag_data,
			  int pushToStack_queue_index) {
 
	//copy header ip to tmp beacuse it can happen that during exectuion of this function the header_ip can be 
	//overwriten in kernel ringbuffer if the ringbuffer is small and thus header_ip->saddr can have different value 
	iphdr2 *header_ip_orig = (iphdr2*)new FILE_LINE(0) u_char[header_ip->get_hdr_size()];
	memcpy(header_ip_orig, header_ip, header_ip->get_hdr_size());

	// get queue from ip_frag_stream based on source ip address and ip->id identificator (2-dimensional map array)
	ip_frag_queue *queue = ipfrag_data->ip_frag_stream[header_ip_orig->get_saddr()][header_ip_orig->get_frag_id()];
	if(!queue) {
		// queue does not exists yet - create it and assign to map 
		queue = new FILE_LINE(26016) ip_frag_queue;
		ipfrag_data->ip_frag_stream[header_ip_orig->get_saddr()][header_ip_orig->get_frag_id()] = queue;
	}
	int res = header_packet ?
		   ipfrag_add(queue,
			      header_packet, 
			      (u_char*)header_ip - HPP(*header_packet), header_ip_orig->get_tot_len(),
			      pushToStack_queue_index) :
		   ipfrag_add(queue,
			      header_packet_pqout, 
			      (u_char*)header_ip - header_packet_pqout->packet, header_ip_orig->get_tot_len());
	if(res > 0) {
		// packet was created from all pieces - delete queue and remove it from map
		ipfrag_data->ip_frag_stream[header_ip_orig->get_saddr()].erase(header_ip_orig->get_frag_id());
		delete queue;
	};
	
	delete header_ip_orig;
	
	return res;
}

int handle_defrag(iphdr2 *header_ip, sHeaderPacket **header_packet, ipfrag_data_s *ipfrag_data,
		  int pushToStack_queue_index) {
	return(_handle_defrag(header_ip, header_packet, NULL, ipfrag_data,
			      pushToStack_queue_index));
}

int handle_defrag(iphdr2 *header_ip, void *header_packet_pqout, ipfrag_data_s *ipfrag_data) {
	return(_handle_defrag(header_ip, NULL, (sHeaderPacketPQout*)header_packet_pqout, ipfrag_data,
			      -1));
}

void ipfrag_prune(unsigned int tv_sec, bool all, ipfrag_data_s *ipfrag_data,
		  int pushToStack_queue_index, int prune_limit) {
 
	if(prune_limit < 0) {
		prune_limit = 30;
	}
	ip_frag_queue *queue;
	for (ipfrag_data->ip_frag_streamIT = ipfrag_data->ip_frag_stream.begin(); ipfrag_data->ip_frag_streamIT != ipfrag_data->ip_frag_stream.end(); ipfrag_data->ip_frag_streamIT++) {
		for (ipfrag_data->ip_frag_streamITinner = (*ipfrag_data->ip_frag_streamIT).second.begin(); ipfrag_data->ip_frag_streamITinner != (*ipfrag_data->ip_frag_streamIT).second.end();) {
			queue = ipfrag_data->ip_frag_streamITinner->second;
			if(!queue->size()) {
				ipfrag_data->ip_frag_streamIT->second.erase(ipfrag_data->ip_frag_streamITinner++);
				delete queue;
				continue;
			}
			if(all or ((tv_sec - queue->begin()->second->ts) > prune_limit)) {
				for (ip_frag_queue_it_t it = queue->begin(); it != queue->end(); ++it) {
					ip_frag_s *node = it->second;
					ipfrag_delete_node(node, pushToStack_queue_index);
				}
				ipfrag_data->ip_frag_streamIT->second.erase(ipfrag_data->ip_frag_streamITinner++);
				delete queue;
				continue;
			}
			ipfrag_data->ip_frag_streamITinner++;
		}
	}
}

bool open_global_pcap_handle(const char *pcap, string *error) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap == string("/dev/stdin")) {
		global_pcap_handle = pcap_open_offline("-", errbuf);
	} else {
		global_pcap_handle = pcap_open_offline_zip(pcap, errbuf);
	}
	if(global_pcap_handle == NULL) {
		if(error) {
			*error = errbuf;
		}
		return(false);
	}
	global_pcap_handle_index = register_pcap_handle(global_pcap_handle);
	global_pcap_dlink = pcap_datalink(global_pcap_handle);
	if(error) {
		*error = "";
	}
	return(true);
}

bool process_pcap(const char *pcap_source, const char *pcap_destination, int process_pcap_type, string *error) {
	if(!pcap_destination || !*pcap_destination) {
		string _error = "missing destination filename";
		if(error) {
			*error = _error;
		}
		fprintf(stderr, "Parameters are not complete: %s\n", _error.c_str());
		return(false);
	}
	if(error) {
		*error = "";
	}
	string pcap_error;
	if(!open_global_pcap_handle(pcap_source, &pcap_error)) {
		if(error) {
			*error = pcap_error;
		}
		fprintf(stderr, "Couldn't open source pcap file '%s': %s\n", pcap_source, pcap_error.c_str());
		return(false);
	}
	PcapDumper *destination = new PcapDumper;
	if(!destination->open(tsf_na, pcap_destination, global_pcap_handle, global_pcap_dlink, &pcap_error)) {
		if(error) {
			*error = pcap_error;
		}
		fprintf(stderr, "Couldn't open destination pcap file '%s': %s\n", pcap_source, pcap_error.c_str());
		delete destination;
		return(false);
	}
	readdump_libpcap(global_pcap_handle, global_pcap_handle_index, global_pcap_dlink, destination, process_pcap_type);
	destination->close();
	delete destination;
	return(true);
}

void readdump_libpcap(pcap_t *handle, u_int16_t handle_index, int handle_dlt, PcapDumper *destination, int process_pcap_type) {
	if(verbosity > 2) {
		syslog(LOG_NOTICE, "DLT: %i", handle_dlt);
	}

	if(process_pcap_type & _pp_process_calls) {
		init_hash();
	}

	pcap_dumper_t *tmppcap = NULL;
	if(opt_pcapdump) {
		char pname[2048];
		snprintf(pname, sizeof(pname), "%s/dump-%u.pcap", getPcapdumpDir(), (unsigned int)time(NULL));
		tmppcap = pcap_dump_open(handle, pname);
	}

	if(!(process_pcap_type & _pp_read_file) && (process_pcap_type & _pp_process_calls)) {
		manager_parse_command_enable();
		if(!sverb.pcap_stat_period) {
			sverb.pcap_stat_period = verbosityE > 0 ? 1 : 10;
		}
	}
	
	pcapProcessData ppd;
	u_int64_t packet_counter = 0;
	unsigned long lastStatTimeMS = 0;
	sHeaderPacket *header_packet = NULL;
	int ppf_params = (process_pcap_type & _pp_process_calls) ? ppf_all :
			 (process_pcap_type & _pp_dedup) ? (ppf_dedup | ppf_calcMD5) :
			 (process_pcap_type & _pp_anonymize_ip) ? ppf_na :
			 ppf_na;
			 
	while(!is_terminating()) {
		pcap_pkthdr *pcap_next_ex_header;
		const u_char *pcap_next_ex_packet;
		int res = pcap_next_ex(handle, &pcap_next_ex_header, &pcap_next_ex_packet);
		if(res == -2) {
			//packets are being read from a ``savefile'', and there are no more packets to read from the savefile.
			if(opt_fork) printf("End of pcap file, exiting\n");
			break;
		} else if(!pcap_next_ex_packet || res <= 0) {
			if(!pcap_next_ex_packet) {
				if(verbosity > 2) {
					syslog(LOG_NOTICE, "NULL PACKET, pcap response is %d",res);
				}
			} else if(res == -1) {
				// error returned, sometimes it returs error 
				if(verbosity > 2) {
					syslog(LOG_NOTICE, "Error reading packets\n");
				}
			} else if(res == 0) {
				//continue on timeout when reading live packets
			}
			continue;
		}
		 
		if(header_packet && header_packet->packet_alloc_size != 0xFFFF) {
			DESTROY_HP(&header_packet);
		}
		if(header_packet) {
			header_packet->clearPcapProcessData();
		} else {
			header_packet = CREATE_HP(MAX(0xFFFF, get_pcap_snaplen()));
		}
		
		if(sverb.dump_packets_via_wireshark) {
			extern void ws_dissect_packet(pcap_pkthdr* header, const u_char* packet, int dlt, string *rslt);
			string dissect_rslt;
			ws_dissect_packet(pcap_next_ex_header, pcap_next_ex_packet, handle_dlt, &dissect_rslt);
			if(!dissect_rslt.empty()) {
				cout << dissect_rslt << endl;
			}
		}
		
		if(pcap_next_ex_header->caplen > get_pcap_snaplen()) {
			pcap_next_ex_header->caplen = get_pcap_snaplen();
		}
		if(pcap_next_ex_header->caplen > pcap_next_ex_header->len) {
			pcap_next_ex_header->caplen = pcap_next_ex_header->len;
		}
		
		memcpy_heapsafe(HPH(header_packet), header_packet,
				pcap_next_ex_header, NULL,
				sizeof(pcap_pkthdr));
		memcpy_heapsafe(HPP(header_packet), header_packet,
				pcap_next_ex_packet, NULL,
				pcap_next_ex_header->caplen);
		
		++packet_counter;
		
		if(!(process_pcap_type & _pp_read_file) && (process_pcap_type & _pp_process_calls)) {
			unsigned long timeMS = getTimeMS(HPH(header_packet));
			if(lastStatTimeMS) {
				if(timeMS > lastStatTimeMS &&
				   timeMS - lastStatTimeMS > (unsigned)(sverb.pcap_stat_period * 1000)) {
					if(rtp_threads) {
						extern int num_threads_max;
						for(int i = 0; i < num_threads_max; i++) {
							if(rtp_threads[i].threadId) {
								rtp_threads[i].push_batch();
							}
						}
					}
					void _process_packet__cleanup_calls(timeval *ts, const char *file, int line);
					_process_packet__cleanup_calls(&HPH(header_packet)->ts, __FILE__, __LINE__);
					ostringstream outStr;
					outStr << fixed;
					outStr << "calls[" << calltable->getCountCalls() << ",r:" << calltable->registers_listMAP.size() << "]"
					       << "[" << calls_counter << ",r:" << registers_counter << "]";
					syslog(LOG_NOTICE, "%s", outStr.str().c_str());
					lastStatTimeMS = timeMS;
				}
			} else {
				lastStatTimeMS = timeMS;
			}
		}

		if(!pcapProcess(&header_packet, -1,
				NULL, 0,
				ppf_params,
				&ppd, handle_dlt, tmppcap, ifname)) {
			continue;
		}
		
		if(process_pcap_type & _pp_dedup) {
			destination->dump(HPH(header_packet), HPP(header_packet), handle_dlt);
			continue;
		} else if(process_pcap_type & _pp_anonymize_ip) {
			pcap_pkthdr *header_new = NULL;
			u_char *packet_new = NULL;
			extern cConfigItem_net_map::t_net_map opt_anonymize_ip_map;
			extern cConfigItem_domain_map::t_domain_map opt_anonymize_domain_map;
			convertAnonymousInPacket(header_packet, &ppd, &header_new, &packet_new, &opt_anonymize_ip_map, &opt_anonymize_domain_map);
			if(header_new && packet_new) {
				destination->dump(header_new, packet_new, handle_dlt);
				delete header_new;
				delete [] packet_new;
			} else {
				destination->dump(HPH(header_packet), HPP(header_packet), handle_dlt);
			}
			continue;
		}
		
		if(opt_mirrorall || (opt_mirrorip && (sipportmatrix[ppd.header_udp->get_source()] || sipportmatrix[ppd.header_udp->get_dest()]))) {
			mirrorip->send((char *)ppd.header_ip, (int)(HPH(header_packet)->caplen - ((u_char*)ppd.header_ip - HPP(header_packet))));
		}
		if(!opt_mirroronly) {
			pcap_pkthdr *header = new FILE_LINE(26017) pcap_pkthdr;
			*header = *HPH(header_packet);
			u_char *packet = new FILE_LINE(26018) u_char[header->caplen];
			memcpy(packet, HPP(header_packet), header->caplen);
			unsigned dataoffset = (u_char*)ppd.data - HPP(header_packet);
			if(opt_enable_ssl && 
			   ppd.header_ip && ppd.header_ip->get_protocol() == IPPROTO_TCP &&
			   (isSslIpPort(ppd.header_ip->get_saddr(), ppd.header_udp->get_source()) ||
			    isSslIpPort(ppd.header_ip->get_daddr(), ppd.header_udp->get_dest()))) {
				tcpReassemblySsl->push_tcp(header, (iphdr2*)(packet + ppd.header_ip_offset), packet, true,
							   NULL, 0, false,
							   0, handle_dlt, opt_id_sensor, 0, ppd.pid);
			} else {
				bool ssl_client_random = false;
				extern bool ssl_client_random_enable;
				extern char *ssl_client_random_portmatrix;
				extern bool ssl_client_random_portmatrix_set;
				extern vector<vmIP> ssl_client_random_ip;
				extern vector<vmIPmask> ssl_client_random_net;
				if(ppd.header_ip && ppd.header_ip->get_protocol() == IPPROTO_UDP &&
				   ssl_client_random_enable &&
				   (!ssl_client_random_portmatrix_set || 
				    ssl_client_random_portmatrix[ppd.header_udp->get_dest()]) &&
				   ((!ssl_client_random_ip.size() && !ssl_client_random_net.size()) ||
				    check_ip_in(ppd.header_ip->get_daddr(), &ssl_client_random_ip, &ssl_client_random_net, true)) &&
				   ppd.datalen && ppd.data[0] == '{' && ppd.data[ppd.datalen - 1] == '}') {
					if(ssl_parse_client_random((u_char*)ppd.data, ppd.datalen)) {
						ssl_client_random = true;
					}
				} 
				if(!ssl_client_random) {
					preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
						#if USE_PACKET_NUMBER
						packet_counter,
						#endif
						ppd.header_ip ? ppd.header_ip->get_saddr() : 0, 
						ppd.header_ip ? ppd.header_udp->get_source() : vmPort(), 
						ppd.header_ip ? ppd.header_ip->get_daddr() : 0, 
						ppd.header_ip ? ppd.header_udp->get_dest() : vmPort(), 
						ppd.datalen, dataoffset, 
						handle_index, header, packet, true,
						ppd.flags, (iphdr2*)(packet + ppd.header_ip_encaps_offset), (iphdr2*)(packet + ppd.header_ip_offset),
						NULL, 0, handle_dlt, opt_id_sensor, 0, ppd.pid);
				} else {
					delete header;
					delete [] packet;
				}
			}
		}
	}
	
	if(header_packet) {
		DESTROY_HP(&header_packet);
	}
	
	if(!(process_pcap_type & _pp_read_file) && (process_pcap_type & _pp_process_calls)) {
		manager_parse_command_disable();
	}

	if(opt_pcapdump) {
		pcap_dump_close(tmppcap);
	}
}

int rtp_stream_analysis(const char *pcap, bool onlyRtp) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	if(!(handle = pcap_open_offline_zip(pcap, errbuf))) {
		fprintf(stderr, "Couldn't open pcap file '%s': %s\n", pcap, errbuf);
		return(2);
	}
	int dlink = pcap_datalink(handle);
	pcap_pkthdr *pcap_next_ex_header;
	const u_char *pcap_next_ex_packet;
	sHeaderPacket *header_packet = NULL;
	pcapProcessData ppd;
	packet_s *packetS = NULL;
	Call *call = NULL;
	int res;
	while((res = pcap_next_ex(handle, &pcap_next_ex_header, &pcap_next_ex_packet)) > 0) {
		if(header_packet && header_packet->packet_alloc_size != 0xFFFF) {
			DESTROY_HP(&header_packet);
		}
		if(header_packet) {
			header_packet->clearPcapProcessData();
		} else {
			header_packet = CREATE_HP(0xFFFF);
		}
		memcpy_heapsafe(HPH(header_packet), header_packet,
				pcap_next_ex_header, NULL,
				sizeof(pcap_pkthdr));
		memcpy_heapsafe(HPP(header_packet), header_packet,
				pcap_next_ex_packet, NULL,
				pcap_next_ex_header->caplen);
		if(!pcapProcess(&header_packet, -1,
				NULL, 0,
				ppf_all,
				&ppd, dlink, NULL, NULL)) {
			continue;
		}
		pcap_pkthdr *header = new FILE_LINE(0) pcap_pkthdr;
		*header = *HPH(header_packet);
		u_char *packet = new FILE_LINE(26018) u_char[header->caplen];
		memcpy(packet, HPP(header_packet), header->caplen);
		unsigned dataoffset = (u_char*)ppd.data - HPP(header_packet);
		if(onlyRtp) {
			if(!packetS) {
				 packetS = new packet_s;
				 #if __GNUC__ >= 8
				 #pragma GCC diagnostic push
				 #pragma GCC diagnostic ignored "-Wclass-memaccess"
				 #endif
				 memset(packetS, 0, sizeof(packet_s));
				 #if __GNUC__ >= 8
				 #pragma GCC diagnostic pop
				 #endif
			}
			if(!call) {
				call = new FILE_LINE(0) Call(INVITE, (char*)"", 0, NULL, 0);
			}
			packetS->_saddr = ppd.header_ip->get_saddr();
			packetS->_source = ppd.header_udp->get_source();
			packetS->_daddr = ppd.header_ip->get_daddr(); 
			packetS->_dest = ppd.header_udp->get_dest();
			packetS->_datalen = ppd.datalen; 
			packetS->_datalen_set = 0; 
			packetS->_dataoffset = dataoffset;
			packetS->header_pt = header;
			packetS->packet = packet; 
			packetS->header_ip_offset = (u_char*)ppd.header_ip - packet; 
			packetS->dlt = dlink; 
			call->read_rtp(packetS, 1, true, false, s_sdp_flags_base(), false, (char*)"file");
			delete header;
			delete [] packet;
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				packet_counter,
				#endif
				ppd.header_ip ? ppd.header_ip->get_saddr() : 0, 
				ppd.header_ip ? ppd.header_udp->get_source() : vmPort(), 
				ppd.header_ip ? ppd.header_ip->get_daddr() : 0, 
				ppd.header_ip ? ppd.header_udp->get_dest() : vmPort(), 
				ppd.datalen, dataoffset, 
				0, header, packet, true,
				ppd.flags, (iphdr2*)(packet + ppd.header_ip_encaps_offset), (iphdr2*)(packet + ppd.header_ip_offset),
				NULL, 0, global_pcap_dlink, opt_id_sensor, 0, ppd.pid);
		}
	}
	if(packetS) {
		delete packetS;
	}
	if(call) {
		delete call;
	}
	if(header_packet) {
		DESTROY_HP(&header_packet);
	}
	pcap_close(handle);
	return(0);
}

void logPacketSipMethodCall(u_int64_t packet_number, int sip_method, int lastSIPresponseNum, timeval ts, 
			    vmIP saddr, vmPort source, vmIP daddr, vmPort dest,
			    Call *call, const char *descr) {
	static timeval firstPacketTime;
	if(!firstPacketTime.tv_sec) {
		firstPacketTime = ts;
	}
 
	if(!sip_method ||
	   (!is_read_from_file_simple() && descr && strstr(descr, "we are not interested"))) {
		return;
	}
	
	ostringstream outStr;

	outStr << "--- ";
	outStr << setw(5) << packet_number << " ";
	// ts
	outStr << "abstime: "
	       << setw(10)
	       << sqlDateTimeString(ts.tv_sec) << " "
	       << ts.tv_sec << "."
	       << setw(6)
	       << ts.tv_usec << "  ";
	outStr << "reltime: "
	       << setw(4) 
	       << TIME_US_TO_S(getTimeUS(ts) - getTimeUS(firstPacketTime)) << "."
	       << setw(6) << setfill('0')
	       << TIME_US_TO_DEC_US(getTimeUS(ts) - getTimeUS(firstPacketTime)) 
	       << setfill(' ')
	       << "  ";
	// ip / port
	outStr << "ip / port: "
	       << setw(15) << saddr.getString()
	       << " / "
	       << setw(5) << source
	       << " -> "
	       << setw(15) << daddr.getString()
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
	       << (call ? sqlDateTimeString(call->calltime_s()) : "") << "  ";
	// duration
	outStr << "duration: "
	       << setw(5);
	if(call)
		outStr << call->duration_s() << "s";
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
	       << (call ? call->called() : "") << "  ";
	// lastSIPresponseNum
	outStr << "last response num: "
	       << setw(3)
	       << lastSIPresponseNum 
	       << "/"
	       << setw(3)
	       << (call ? call->lastSIPresponseNum : 0) << "  ";
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
	
	if(is_read_from_file_simple()) {
		cout << outStr.str() << endl;
	} else {
		syslog(LOG_NOTICE, "%s", outStr.str().c_str());
	}
}


void _process_packet__cleanup_calls(timeval *ts, const char *file, int line) {
	process_packet__cleanup_calls(ts, file, line);
	if(ts->tv_sec - process_packet__last_destroy_calls >= (unsigned)opt_destroy_calls_period) {
		calltable->destroyCallsIfPcapsClosed();
		process_packet__last_destroy_calls = ts->tv_sec;
	}
}

void _process_packet__cleanup_calls(const char *file, int line) {
	process_packet__cleanup_calls(NULL, file, line);
	u_int32_t timeS = getTimeS_rdtsc();
	if(timeS - process_packet__last_destroy_calls >= (unsigned)opt_destroy_calls_period) {
		calltable->destroyCallsIfPcapsClosed();
		process_packet__last_destroy_calls = timeS;
	}
}

void _process_packet__cleanup_registers() {
	process_packet__cleanup_registers(NULL);
	u_int32_t timeS = getTimeS_rdtsc();
	if(timeS - process_packet__last_destroy_registers >= 2) {
		calltable->destroyRegistersIfPcapsClosed();
		process_packet__last_destroy_registers = timeS;
	}
}

void _process_packet__cleanup_ss7() {
	process_packet__cleanup_ss7(NULL);
}


TcpReassemblySip::TcpReassemblySip() {
	last_cleanup = 0;
}

void TcpReassemblySip::processPacket(packet_s_process **packetS_ref, bool isSip, PreProcessPacket *processPacket) {
	packet_s_process *packetS = *packetS_ref;
	extern int opt_sip_tcp_reassembly_clean_period;
	if(packetS->getTime_s() - last_cleanup > opt_sip_tcp_reassembly_clean_period) {
		this->clean(packetS->getTime_s());
		last_cleanup = packetS->getTime_s();
	}
	if(packetS->datalen_() < 2) {
		PACKET_S_PROCESS_DESTROY(&packetS);
		return;
	}
 
	/*
	if(!((saddr.getString() == "31.47.138.44" &&
	      daddr.getString() == "81.88.86.11") ||
	     (daddr.getString() == "31.47.138.44" &&
	      saddr.getString() == "81.88.86.11"))) {
		 return;
	}
	*/
 
	bool usePacketS = false;
	tcphdr2 *header_tcp = (tcphdr2*)((char*)packetS->header_ip_() + packetS->header_ip_()->get_hdr_size());
	u_int32_t seq = htonl(header_tcp->seq);
	u_int32_t ack_seq = htonl(header_tcp->ack_seq);
	tcp_stream_id rev_id(packetS->daddr_(), packetS->dest_(), packetS->saddr_(), packetS->source_());
	map<tcp_stream_id, tcp_stream>::iterator rev_it = tcp_streams.find(rev_id);
	if(rev_it != tcp_streams.end()) {
		if(rev_it->second.packets) {
			if(isCompleteStream(&rev_it->second)) {
				if(sverb.reassembly_sip) {
					cout << " + call complete (reverse stream)" << endl;
				}
				complete(&rev_it->second, rev_id, processPacket);
			} else {
				if(sverb.reassembly_sip) {
					cout << " + clean (reverse stream)" << endl;
				}
				cleanStream(&rev_it->second);
			}
		}
		if(rev_it->second.last_seq || rev_it->second.last_ack_seq) {
			if(sverb.reassembly_sip) {
				cout << " - reset last seq & ack (reverse stream)" << endl;
			}
			rev_it->second.last_seq = 0;
			rev_it->second.last_ack_seq = 0;
			rev_it->second.last_time_us = 0;
		}
	}
	tcp_stream_id id(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
	map<tcp_stream_id, tcp_stream>::iterator it = tcp_streams.find(id);
	if(it != tcp_streams.end()) {
		if(it->second.packets && it->second.last_ack_seq &&
		   it->second.last_ack_seq != ack_seq) {
			if(isCompleteStream(&it->second)) {
				if(sverb.reassembly_sip) {
					cout << " + call complete (diff ack)" << endl;
				}
				complete(&it->second, id, processPacket);
			} else {
				if(sverb.reassembly_sip) {
					cout << " + clean (diff ack)" << endl;
				}
				cleanStream(&it->second);
			}
		}
		if(it->second.packets && isSip) {
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
					complete(&it->second, id, processPacket);
				} else {
					if(sverb.reassembly_sip) {
						cout << " + clean (next packet issip)" << endl;
					}
					cleanStream(&it->second);
				}
			}
		}
		if(it->second.packets || isSip) {
			if(addPacket(&it->second, &packetS, processPacket)) {
				usePacketS = true;
				if(isCompleteStream(&it->second)) {
					if(sverb.reassembly_sip) {
						cout << " + call complete (check complete after add 1)" << endl;
					}
					complete(&it->second, id, processPacket);
				} else if(it->second.complete_data && it->second.complete_data->size() > 65535) {
					cleanStream(&it->second);
				}
			}
		}
	} else {
		if(isSip) {
			tcp_stream *stream = &tcp_streams[id];
			if(addPacket(stream, &packetS, processPacket)) {
				usePacketS = true;
				if(isCompleteStream(stream)) {
					if(sverb.reassembly_sip) {
						cout << " + call complete (check complete after add 2)" << endl;
					}
					complete(stream, id, processPacket);
				}
			}
		}
	}
	if(!usePacketS) {
		PACKET_S_PROCESS_DESTROY(&packetS);
	}
}

void TcpReassemblySip::clean(time_t ts) {
	extern int opt_sip_tcp_reassembly_stream_timeout;
	map<tcp_stream_id, tcp_stream>::iterator it;
	for(it = tcp_streams.begin(); it != tcp_streams.end();) {
		if(!ts || (ts - TIME_US_TO_S(it->second.last_time_us)) > (unsigned)opt_sip_tcp_reassembly_stream_timeout) {
			cleanStream(&it->second, true);
			tcp_streams.erase(it++);
		} else {
			++it;
		}
	}
}

bool TcpReassemblySip::addPacket(tcp_stream *stream, packet_s_process **packetS_ref, PreProcessPacket */*processPacket*/) {
	packet_s_process *packetS = *packetS_ref;
	if(!packetS->datalen_()) {
		return(false);
	}
	if(sverb.reassembly_sip) {
		cout << sqlDateTimeString(packetS->getTime_s()) << " "
		     << setw(6) << setfill('0') << packetS->getTime_us() << setfill(' ') << " / "
		     << string(packetS->data_(), MIN(string(packetS->data_(), packetS->datalen_()).find(CR_STR), MIN(packetS->datalen_(), 100))) << endl;
	}
	tcphdr2 *header_tcp = (tcphdr2*)((char*)packetS->header_ip_() + packetS->header_ip_()->get_hdr_size());
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
		if((seq || header_tcp->check) && // check if not save by createSimpleTcpDataPacket
		   seq == stream->last_seq && 
		   ack_seq == stream->last_ack_seq &&
		   packetS->getTimeUS() != stream->last_time_us) {
			if(sverb.reassembly_sip) {
				cout << " - skip previous completed seq & ack (if different time)" << endl;
			}
			return(false);
		}
	}
	
	tcp_stream_packet *lastPacket = stream->packets ? getLastStreamPacket(stream) : NULL;
	
	tcp_stream_packet *newPacket = new FILE_LINE(26019) tcp_stream_packet;
	newPacket->packetS = packetS;
	newPacket->next = NULL;
	newPacket->ts = packetS->getTime_s();

	newPacket->lastpsh = header_tcp->psh;
	newPacket->seq = seq;
	newPacket->ack_seq = ack_seq;
	newPacket->next_seq = newPacket->seq + (unsigned long int)packetS->header_pt->caplen - ((unsigned long int)header_tcp - (unsigned long int)packetS->packet + header_tcp->doff * 4);

	// append new created node at the end of list of TCP packets within this TCP connection
	if(lastPacket) {
		lastPacket->next = newPacket;
	}

	if(stream->packets) {
		if(stream->complete_data) {
			stream->complete_data->add(packetS->data_(), packetS->datalen_());
		} else {
			stream->complete_data =  new FILE_LINE(26020) SimpleBuffer(10000);
			stream->complete_data->add(stream->packets->packetS->data_(), stream->packets->packetS->datalen_());
			stream->complete_data->add(packetS->data_(), packetS->datalen_());
		}
	} else {
		stream->packets = newPacket;
	}
	stream->last_seq = seq;
	stream->last_ack_seq = ack_seq;
	stream->last_time_us = packetS->getTimeUS();
	
	return(true);
}

void TcpReassemblySip::complete(tcp_stream *stream, tcp_stream_id /*id*/, PreProcessPacket *processPacket) {
	if(!stream->packets) {
		return;
	}
	packet_s_process *completePacketS;
	if(stream->complete_data == NULL) {
		completePacketS = stream->packets->packetS;
		stream->packets->packetS = NULL;
	} else {
		completePacketS = PreProcessPacket::clonePacketS(stream->complete_data->data(), stream->complete_data->size(), stream->packets->packetS);
	}
	completePacketS->pflags.tcp = 2;
	if(sverb.reassembly_sip || sverb.reassembly_sip_output) {
		if(sverb.reassembly_sip) {
			cout << " * COMPLETE ";
		}
		cout << sqlDateTimeString(completePacketS->getTime_s()) << " "
		     << setw(6) << setfill('0') << completePacketS->getTime_us() << setfill(' ') << " / "
		     << setw(15) << completePacketS->saddr_().getString() << " : "
		     << setw(5) << completePacketS->source_() << " / "
		     << setw(15) << completePacketS->daddr_().getString() << " : "
		     << setw(5) << completePacketS->dest_() << " / "
		     << setw(9) << stream->last_ack_seq << " / "
		     << string((char*)completePacketS->data_(), MIN(string((char*)completePacketS->data_(), completePacketS->datalen_()).find(CR_STR), MIN(completePacketS->datalen_(), 100))) << endl;
	}
	if(processPacket) {
		processPacket->process_parseSipData(&completePacketS, NULL);
	} else {
		preProcessPacket[PreProcessPacket::ppt_extend]->push_packet(completePacketS);
	}
	cleanStream(stream);
}

void TcpReassemblySip::cleanStream(tcp_stream* stream, bool /*callFromClean*/) {
	if(stream->packets) {
		tcp_stream_packet *packet = stream->packets;
		while(packet) {
			if(packet->packetS) {
				PACKET_S_PROCESS_DESTROY(&packet->packetS);
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


/* no need ?
ReassemblyWebsocket::websocket_stream::~websocket_stream() {
	clear();
}

void ReassemblyWebsocket::websocket_stream::add(packet_s_process *packet) {
	packets.push_back(packet);
}

u_char *ReassemblyWebsocket::websocket_stream::complete(unsigned *length) {
	if(packets.size()) {
		*length = this->length();
		if(*length) {
			unsigned pos = 0;
			u_char *compl_data = new FILE_LINE(0) u_char(*length);
			for(list<packet_s_process*>::iterator iter = packets.begin(); iter != packets.end(); iter++) {
				memcpy(compl_data + pos, (*iter)->data, (*iter)->datalen);
				pos += (*iter)->datalen;
			}
			return(compl_data);
		}
	} else {
		*length = 0;
	}
	return(NULL);
}

unsigned ReassemblyWebsocket::websocket_stream::length() {
	unsigned length = 0;
	for(list<packet_s_process*>::iterator iter = packets.begin(); iter != packets.end(); iter++) {
		length += (*iter)->datalen;
	}
	return(length);
}

void ReassemblyWebsocket::websocket_stream::clear() {
	while(packets.size()) {
		packet_s_process *packet = packets.front();
		PACKET_S_PROCESS_DESTROY(&packet);
		packets.pop_front();
	}
}

ReassemblyWebsocket::ReassemblyWebsocket() {
}

ReassemblyWebsocket::~ReassemblyWebsocket() {
	for(map<sStreamId, websocket_stream*>::iterator iter = streams.begin(); iter != streams.end(); iter++) {
		delete iter->second;
	}
}

int ReassemblyWebsocket::processPacket(packet_s_process **packetS_ref, bool createStream) {
	packet_s_process *packetS = *packetS_ref;
	websocket_stream *stream = NULL;
	sStreamId id(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
	map<sStreamId, websocket_stream*>::iterator iter = streams.find(id);
	if(iter == streams.end()) {
		if(!createStream) {
			return(-1);
		}
		stream = new FILE_LINE(0) websocket_stream;
		streams[id] = stream;
	} else {
		stream = iter->second;
		if(createStream) {
			stream->clear();
		}
	}
	stream->add(packetS);
	unsigned compl_data_length;
	u_char *compl_data = stream->complete(&compl_data_length);
	if(compl_data) {
		if(check_websocket(compl_data, compl_data_length)) {
			return(1);
		}
		delete compl_data;
	}
	return(0);
}

bool ReassemblyWebsocket::existsStream(packet_s_process **packetS_ref) {
	if(!streams.size()) {
		return(false);
	}
	packet_s_process *packetS = *packetS_ref;
	sStreamId id(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_());
	return(streams.find(id) != streams.end());
}
*/


ReassemblyBuffer::ReassemblyBuffer() {
	minTimeInStreams = 0;
}

ReassemblyBuffer::~ReassemblyBuffer() {
	for(map<sStreamId, sData>::iterator iter = streams.begin(); iter != streams.end(); iter++) {
		delete iter->second.ethHeader;
		delete iter->second.buffer;
	}
}

void ReassemblyBuffer::processPacket(u_char *ethHeader, unsigned ethHeaderLength,
				     vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, 
				     ReassemblyBuffer::eType type, u_char *data, unsigned length, bool createStream,
				     timeval time, u_int32_t ack, u_int32_t seq,
				     u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
				     list<sDataRslt> *dataRslt) {
	sStreamId id(saddr, sport, daddr, dport);
	map<sStreamId, sData>::iterator iter = streams.find(id);
	sData *b_data;
	bool b_data_update = false;
	if(iter == streams.end()) {
		if(!createStream) {
			return;
		}
		b_data = &streams[id];
		b_data->ethHeader = new FILE_LINE(0) SimpleBuffer;
		b_data->ethHeader->add(ethHeader, ethHeaderLength);
		b_data->buffer = new FILE_LINE(0) SimpleBuffer;
		b_data->type = (eType)(type & _type_mask);
		b_data_update = true;
	} else {
		b_data = &iter->second;
		if(createStream || 
		   (b_data->type == _sip && ack != b_data->ack)) {
			if(b_data->buffer->size() && b_data->time.tv_sec > time.tv_sec - 10) {
				dataRslt->push_back(complete(&id, b_data));
			}
			b_data->ethHeader->clear();
			b_data->ethHeader->add(ethHeader, ethHeaderLength);
			b_data->buffer->clear();
			if(type & _type_mask) {
				b_data->type = (eType)(type & _type_mask);
			}
			b_data_update = true;
		}
	}
	if(b_data_update) {
		b_data->time = time;
		b_data->ack = ack;
		b_data->seq = seq;
		b_data->handle_index = handle_index;
		b_data->dlt = dlt;
		b_data->sensor_id = sensor_id;
		b_data->sensor_ip = sensor_ip;
		b_data->pid = pid;
	}
	b_data->buffer->add(data, length);
	if(!createStream &&
	   ((b_data->type == _websocket && check_websocket(b_data->buffer->data(), b_data->buffer->size())) ||
	    (b_data->type == _sip && TcpReassemblySip::_checkSip(b_data->buffer->data(), b_data->buffer->size(), false)))) {
		dataRslt->push_back(complete(&id, b_data));
		delete b_data->buffer;
		delete b_data->ethHeader;
		streams.erase(iter);
	} else {
		if(!minTimeInStreams ||
		   getTimeUS(time) < minTimeInStreams) {
			minTimeInStreams = getTimeUS(time);
		}
	}
}

bool ReassemblyBuffer::existsStream(vmIP saddr, vmPort sport, vmIP daddr, vmPort dport) {
	if(streams.size()) {
		sStreamId id(saddr, sport, daddr, dport);
		if(streams.find(id) != streams.end()) {
			return(true);
		}
	}
	return(false);
}

void ReassemblyBuffer::cleanup(timeval time, list<sDataRslt> *dataRslt) {
	if(minTimeInStreams && minTimeInStreams < getTimeUS(time) - 500000ull) {
		minTimeInStreams = 0;
		for(map<sStreamId, sData>::iterator iter = streams.begin(); iter != streams.end(); ) {
			if(getTimeUS(iter->second.time) < getTimeUS(time) - 500000ull) {
				dataRslt->push_back(complete((sStreamId*)&iter->first, &iter->second));
				delete iter->second.ethHeader;
				delete iter->second.buffer;
				streams.erase(iter++);
			} else {
				if(!minTimeInStreams ||
				   getTimeUS(iter->second.time) < minTimeInStreams) {
					minTimeInStreams = getTimeUS(iter->second.time);
				}
				iter++;
			}
		}
	}
}

ReassemblyBuffer::sDataRslt ReassemblyBuffer::complete(sStreamId *streamId, sData *b_data) {
	sDataRslt dataRslt;
	*(sData_base*)&dataRslt = *(sData_base*)(b_data);
	dataRslt.ethHeaderLength = b_data->ethHeader->size();
	dataRslt.ethHeader = new FILE_LINE(0) u_char[dataRslt.ethHeaderLength];
	memcpy(dataRslt.ethHeader, b_data->ethHeader->data(), dataRslt.ethHeaderLength);
	dataRslt.ethHeaderAlloc = true;
	dataRslt.dataLength = b_data->buffer->size();
	dataRslt.data = new FILE_LINE(0) u_char[dataRslt.dataLength];
	memcpy(dataRslt.data, b_data->buffer->data(), dataRslt.dataLength);
	dataRslt.dataAlloc = true;
	dataRslt.saddr = streamId->s.ip;
	dataRslt.sport = streamId->s.port;
	dataRslt.daddr = streamId->c.ip;
	dataRslt.dport = streamId->c.port;
	return(dataRslt);
}


unsigned packet_s_process_calls_info::__size_of;
unsigned packet_s_process_0::__size_of;


inline void *_PreProcessPacket_outThreadFunction(void *arg) {
	return(((PreProcessPacket*)arg)->outThreadFunction());
}

inline void *_PreProcessPacket_nextThreadFunction(void *arg) {
	PreProcessPacket::arg_next_thread *_arg = (PreProcessPacket::arg_next_thread*)arg;
	void *rsltThread = _arg->preProcessPacket->nextThreadFunction(_arg->next_thread_id);
	delete _arg;
	return(rsltThread);
}

PreProcessPacket::PreProcessPacket(eTypePreProcessThread typePreProcessThread, unsigned idPreProcessThread) {
	this->typePreProcessThread = typePreProcessThread;
	this->idPreProcessThread = idPreProcessThread;
	this->qring_batch_item_length = opt_preprocess_packets_qring_item_length ?
					 opt_preprocess_packets_qring_item_length :
					 min(opt_preprocess_packets_qring_length / 10, 1000u);
	this->qring_length = opt_preprocess_packets_qring_item_length ?
			      opt_preprocess_packets_qring_length :
			      opt_preprocess_packets_qring_length / this->qring_batch_item_length;
	this->readit = 0;
	this->writeit = 0;
	if(typePreProcessThread == ppt_detach) {
		this->qring_detach = new FILE_LINE(26022) batch_packet_s*[this->qring_length];
		for(unsigned int i = 0; i < this->qring_length; i++) {
			this->qring_detach[i] = new FILE_LINE(26023) batch_packet_s(this->qring_batch_item_length);
			this->qring_detach[i]->used = 0;
		}
		this->qring = NULL;
	} else {
		this->qring = new FILE_LINE(26024) batch_packet_s_process*[this->qring_length];
		for(unsigned int i = 0; i < this->qring_length; i++) {
			this->qring[i] = new FILE_LINE(26025) batch_packet_s_process(this->qring_batch_item_length);
			this->qring[i]->used = 0;
		}
		this->qring_detach = NULL;
	}
	this->items_flag = new FILE_LINE(0) volatile int[this->qring_batch_item_length];
	this->qring_push_index = 0;
	this->qring_push_index_count = 0;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->qringPushCounter = 0;
	this->qringPushCounter_full = 0;
	this->outThreadId = 0;
	this->_sync_push = 0;
	this->_sync_count = 0;
	this->term_preProcess = false;
	for(int i = 0; i < MAX_PRE_PROCESS_PACKET_NEXT_THREADS; i++) {
		this->nextThreadId[i] = 0;
		this->next_thread_handle[i] = 0;
		this->next_thread_data[i].null();
	}
	if(typePreProcessThread == ppt_detach) {
		this->stackSip = new FILE_LINE(26026) cHeapItemsPointerStack(opt_preprocess_packets_qring_item_length ?
									      opt_preprocess_packets_qring_item_length * opt_preprocess_packets_qring_length :
									      opt_preprocess_packets_qring_length, 
									     1, 200);
		this->stackRtp = new FILE_LINE(26027) cHeapItemsPointerStack((opt_preprocess_packets_qring_item_length ?
									       opt_preprocess_packets_qring_item_length * opt_preprocess_packets_qring_length :
									       opt_preprocess_packets_qring_length) * 10, 
									     1, 200);
		this->stackOther = new FILE_LINE(0) cHeapItemsPointerStack(opt_preprocess_packets_qring_item_length ?
									    opt_preprocess_packets_qring_item_length * opt_preprocess_packets_qring_length :
									    opt_preprocess_packets_qring_length, 
									   1, 200);
	} else {
		this->stackSip = NULL;
		this->stackRtp = NULL;
		this->stackOther = NULL;
	}
	this->outThreadState = 0;
	allocCounter[0] = allocCounter[1] = 0;
	allocStackCounter[0] = allocStackCounter[1] = 0;
	getCpuUsagePerc_counter = 0;
	getCpuUsagePerc_counter_at_start_out_thread = 0;
	this->next_threads = opt_t2_boost && (typePreProcessThread == ppt_detach || typePreProcessThread == ppt_sip) ? 
			      opt_pre_process_packets_next_thread : 
			      0;
	for(int i = 0; i < min(opt_pre_process_packets_next_thread_max, MAX_PRE_PROCESS_PACKET_NEXT_THREADS); i++) {
		this->nextThreadId[i] = 0;
		this->next_thread_handle[i] = 0;
		this->next_thread_data[i].null();
		if(i < this->next_threads) {
			for(int j = 0; j < 2; j++) {
				sem_init(&sem_sync_next_thread[i][j], 0, 0);
			}
			arg_next_thread *arg = new FILE_LINE(0) arg_next_thread;
			arg->preProcessPacket = this;
			arg->next_thread_id = i + 1;
			vm_pthread_create(("pre process next - " + getNameTypeThread()).c_str(),
					  &this->next_thread_handle[i], NULL, _PreProcessPacket_nextThreadFunction, arg, __FILE__, __LINE__);
		}
	}
}

PreProcessPacket::~PreProcessPacket() {
	terminate();
	if(this->qring_detach) {
		for(unsigned int i = 0; i < this->qring_length; i++) {
			delete this->qring_detach[i];
		}
		delete [] this->qring_detach;
	}
	if(this->qring) {
		for(unsigned int i = 0; i < this->qring_length; i++) {
			delete this->qring[i];
		}
		delete [] this->qring;
	}
	delete [] this->items_flag;
	if(this->stackSip) {
		delete this->stackSip;
	}
	if(this->stackRtp) {
		delete this->stackRtp;
	}
	if(this->stackOther) {
		delete this->stackOther;
	}
}

void PreProcessPacket::runOutThread() {
	if(!this->outThreadState) {
		this->outThreadState = 2;
		getCpuUsagePerc_counter_at_start_out_thread = getCpuUsagePerc_counter;
		vm_pthread_create_autodestroy(("t2 sip preprocess " + getNameTypeThread()).c_str(),
					      &this->out_thread_handle, NULL, _PreProcessPacket_outThreadFunction, this, __FILE__, __LINE__);
	}
}

void PreProcessPacket::endOutThread(bool force) {
	if(isActiveOutThread() &&
	   (force || getCpuUsagePerc_counter > getCpuUsagePerc_counter_at_start_out_thread + 10)) {
		outThreadState = 1;
	}
}

void *PreProcessPacket::nextThreadFunction(int next_thread_index_plus) {
	this->nextThreadId[next_thread_index_plus - 1] = get_unix_tid();
	syslog(LOG_NOTICE, "start PreProcessPacket next thread %s/%i", this->getNameTypeThread().c_str(), this->nextThreadId[next_thread_index_plus - 1]);
	int usleepUseconds = 20;
	unsigned int usleepCounter = 0;
	while(!this->term_preProcess) {
		sem_wait(&sem_sync_next_thread[next_thread_index_plus - 1][0]);
		if(this->term_preProcess) {
			break;
		}
		s_next_thread_data *next_thread_data = &this->next_thread_data[next_thread_index_plus - 1];
		if(next_thread_data->batch) {
			unsigned batch_index_start = next_thread_data->start;
			unsigned batch_index_end = next_thread_data->end;
			unsigned batch_index_skip = next_thread_data->skip;
			switch(this->typePreProcessThread) {
			case ppt_detach: {
				packet_s_plus_pointer **batch = (packet_s_plus_pointer**)next_thread_data->batch;
				for(unsigned batch_index = batch_index_start; 
				    batch_index < batch_index_end; 
				    batch_index += batch_index_skip) {
					this->process_DETACH_plus(batch[batch_index], false);
					this->items_flag[batch_index] = 1;
				} }
				break;
			case ppt_sip: {
				packet_s_process **batch = (packet_s_process**)next_thread_data->batch;
				for(unsigned batch_index = batch_index_start; 
				    batch_index < batch_index_end; 
				    batch_index += batch_index_skip) {
					this->process_SIP(batch[batch_index], true);
					this->items_flag[batch_index] = 1;
				} }
				break;
			default:
				break;
			}
			next_thread_data->processing = 0;
			usleepCounter = 0;
			sem_post(&sem_sync_next_thread[next_thread_index_plus - 1][1]);
		} else {
			USLEEP_C(usleepUseconds, usleepCounter++);
		}
	}
	return(NULL);
}

void *PreProcessPacket::outThreadFunction() {
	if(this->typePreProcessThread == ppt_detach ||
	   this->typePreProcessThread == ppt_sip ||
	   this->typePreProcessThread == ppt_extend) {
		 pthread_t thId = pthread_self();
		 pthread_attr_t thAttr;
		 int policy = 0;
		 int max_prio_for_policy = 0;
		 pthread_attr_init(&thAttr);
		 pthread_attr_getschedpolicy(&thAttr, &policy);
		 max_prio_for_policy = sched_get_priority_max(policy);
		 #ifndef FREEBSD
		 pthread_setschedprio(thId, max_prio_for_policy);
		 #else
		 pthread_setprio(thId, max_prio_for_policy);
		 #endif
		 pthread_attr_destroy(&thAttr);
	}
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start PreProcessPacket out thread %s/%i", this->getNameTypeThread().c_str(), this->outThreadId);
	packet_s_process *packetS;
	batch_packet_s *batch_detach;
	batch_packet_s_process *batch;
	unsigned int usleepCounter = 0;
	u_int64_t usleepSumTimeForPushBatch = 0;
	while(!this->term_preProcess) {
		if(this->typePreProcessThread == ppt_detach ?
		    (this->qring_detach[this->readit]->used == 1) :
		    (this->qring[this->readit]->used == 1)) {
			if(this->typePreProcessThread == ppt_detach) {
				batch_detach = this->qring_detach[this->readit];
				if(this->next_thread_handle[0]) {
					__SYNC_LOCK(this->_sync_count);
					unsigned count = batch_detach->count;
					__SYNC_UNLOCK(this->_sync_count);
					unsigned completed = 0;
					int _next_threads = this->next_threads;
					bool _process_only_in_next_threads = _next_threads > 1;
					for(unsigned batch_index = 0; batch_index < count; batch_index++) {
						this->items_flag[batch_index] = 0;
					}
					for(int i = 0; i < _next_threads; i++) {
						if(_process_only_in_next_threads) {
							this->next_thread_data[i].start = i;
							this->next_thread_data[i].end = count;
							this->next_thread_data[i].skip = _next_threads;
						} else {
							this->next_thread_data[i].start = count / (_next_threads + 1) * (i + 1);
							this->next_thread_data[i].end = i == (_next_threads - 1) ? count : count / (_next_threads + 1) * (i + 2);
							this->next_thread_data[i].skip = 1;
						}
						this->next_thread_data[i].batch = batch_detach->batch;
						this->next_thread_data[i].processing = 1;
						sem_post(&sem_sync_next_thread[i][0]);
					}
					if(_process_only_in_next_threads) {
						while(this->next_thread_data[0].processing || this->next_thread_data[1].processing ||
						      (_next_threads > 2 && this->isNextThreadsGt2Processing(_next_threads))) {
							if(completed < count &&
							   this->items_flag[completed] != 0) {
								preProcessPacket[ppt_sip]->push_packet((packet_s_process*)(batch_detach->batch[completed]->pointer[0]));
								++completed;
							} else {
								USLEEP(20);
							}
						}
					} else {
						for(unsigned batch_index = 0; 
						    batch_index < count / (_next_threads + 1); 
						    batch_index++) {
							this->process_DETACH_plus(batch_detach->batch[batch_index], false);
						}
					}
					for(int i = 0; i < _next_threads; i++) {
						sem_wait(&sem_sync_next_thread[i][1]);
					}
					for(unsigned batch_index = completed; batch_index < batch_detach->count; batch_index++) {
						preProcessPacket[ppt_sip]->push_packet((packet_s_process*)(batch_detach->batch[batch_index]->pointer[0]));
					}
				} else {
					for(unsigned batch_index = 0; batch_index < batch_detach->count; batch_index++) {
						this->process_DETACH_plus(batch_detach->batch[batch_index]);
						batch_detach->batch[batch_index]->_packet_alloc = false;
					}
				}
				#if RQUEUE_SAFE
					__SYNC_NULL(batch_detach->count);
					__SYNC_NULL(batch_detach->used);
				#else
					batch_detach->count = 0;
					batch_detach->used = 0;
				#endif
			} else if(this->typePreProcessThread == ppt_sip && this->next_thread_handle[0]) {
				batch = this->qring[this->readit];
				__SYNC_LOCK(this->_sync_count);
				unsigned count = batch->count;
				__SYNC_UNLOCK(this->_sync_count);
				unsigned completed = 0;
				int _next_threads = this->next_threads;
				bool _process_only_in_next_threads = _next_threads > 1;
				for(unsigned batch_index = 0; batch_index < count; batch_index++) {
					this->items_flag[batch_index] = 0;
				}
				for(int i = 0; i < _next_threads; i++) {
					if(_process_only_in_next_threads) {
						this->next_thread_data[i].start = i;
						this->next_thread_data[i].end = count;
						this->next_thread_data[i].skip = _next_threads;
					} else {
						this->next_thread_data[i].start = count / (_next_threads + 1) * (i + 1);
						this->next_thread_data[i].end = i == (_next_threads - 1) ? count : count / (_next_threads + 1) * (i + 2);
						this->next_thread_data[i].skip = 1;
					}
					this->next_thread_data[i].batch = batch->batch;
					this->next_thread_data[i].processing = 1;
					sem_post(&sem_sync_next_thread[i][0]);
				}
				if(_process_only_in_next_threads) {
					while(this->next_thread_data[0].processing || this->next_thread_data[1].processing ||
					      (_next_threads > 2 && this->isNextThreadsGt2Processing(_next_threads))) {
						if(completed < count &&
						   this->items_flag[completed] != 0) {
							processNextAction(batch->batch[completed]);
							++completed;
						} else {
							USLEEP(20);
						}
					}
				} else {
					for(unsigned batch_index = 0; 
					    batch_index < count / (_next_threads + 1); 
					    batch_index++) {
						this->process_SIP(batch->batch[batch_index], true);
					}
				}
				for(int i = 0; i < _next_threads; i++) {
					sem_wait(&sem_sync_next_thread[i][1]);
				}
				for(unsigned batch_index = completed; batch_index < count; batch_index++) {
					processNextAction(batch->batch[batch_index]);
					batch->batch[batch_index] = NULL;
				}
				if(opt_preprocess_packets_qring_force_push) {
					preProcessPacket[ppt_extend]->push_batch();
					if(opt_t2_boost) {
						preProcessPacket[ppt_pp_rtp]->push_batch();
					}
				}
				#if RQUEUE_SAFE
					__SYNC_NULL(batch->count);
					__SYNC_NULL(batch->used);
				#else
					batch->count = 0;
					batch->used = 0;
				#endif
			} else {
				batch = this->qring[this->readit];
				__SYNC_LOCK(this->_sync_count);
				unsigned count = batch->count;
				__SYNC_UNLOCK(this->_sync_count);
				for(unsigned batch_index = 0; batch_index < count; batch_index++) {
					packetS = batch->batch[batch_index];
					batch->batch[batch_index] = NULL;
					if(is_terminating()) {
						PACKET_S_PROCESS_DESTROY(&packetS);
					} else {
						switch(this->typePreProcessThread) {
						case ppt_detach:
							break;
						case ppt_sip:
							this->process_SIP(packetS);
							if(opt_preprocess_packets_qring_force_push &&
							   batch_index == count - 1) {
								preProcessPacket[ppt_extend]->push_batch();
								if(opt_t2_boost) {
									preProcessPacket[ppt_pp_rtp]->push_batch();
								}
							}
							break;
						case ppt_extend:
							this->process_SIP_EXTEND(packetS);
							if(opt_preprocess_packets_qring_force_push &&
							   batch_index == count - 1) {
								preProcessPacket[ppt_pp_call]->push_batch();
								preProcessPacket[ppt_pp_register]->push_batch();
								preProcessPacket[ppt_pp_sip_other]->push_batch();
								if(!opt_t2_boost) {
									preProcessPacket[ppt_pp_rtp]->push_batch();
								}
							}
							break;
						case ppt_pp_call:
							this->process_CALL(packetS);
							break;
						case ppt_pp_callx:
							this->process_CALLX(packetS);
							break;
						case ppt_pp_callfindx:
							this->process_CallFindX(packetS);
							break;
						case ppt_pp_register:
							this->process_REGISTER(packetS);
							break;
						case ppt_pp_sip_other:
							this->process_SIP_OTHER(packetS);
							break;
						case ppt_pp_rtp:
							this->process_RTP(packetS);
							break;
						case ppt_pp_other:
							this->process_OTHER(packetS);
							break;
						case ppt_end_base:
							break;
						}
					}
				}
				#if RQUEUE_SAFE
					__SYNC_NULL(batch->count);
					__SYNC_NULL(batch->used);
				#else
					batch->count = 0;
					batch->used = 0;
				#endif
			}
			#if RQUEUE_SAFE
				__SYNC_INCR(this->readit, this->qring_length);
			#else
				if((this->readit + 1) == this->qring_length) {
					this->readit = 0;
				} else {
					this->readit++;
				}
			#endif
			usleepCounter = 0;
			usleepSumTimeForPushBatch = 0;
		} else {
			if(this->outThreadState == 1) {
				break;
			}
			if(usleepSumTimeForPushBatch > 500000ull) {
				switch(this->typePreProcessThread) {
				case ppt_detach:
					preProcessPacket[ppt_sip]->push_batch();
					break;
				case ppt_sip:
					preProcessPacket[ppt_extend]->push_batch();
					if(opt_t2_boost) {
						preProcessPacket[ppt_pp_rtp]->push_batch();
					}
					preProcessPacket[ppt_pp_other]->push_batch();
					break;
				case ppt_extend:
					preProcessPacket[ppt_pp_call]->push_batch();
					preProcessPacket[ppt_pp_register]->push_batch();
					preProcessPacket[ppt_pp_sip_other]->push_batch();
					if(!opt_t2_boost) {
						preProcessPacket[ppt_pp_rtp]->push_batch();
					}
					if(opt_t2_boost && preProcessPacketCallX_state == PreProcessPacket::callx_find && 
					   preProcessPacketCallFindX[0]->isActiveOutThread()) {
						for(int i = 0; i < preProcessPacketCallX_count; i++) {
							preProcessPacketCallFindX[i]->push_batch();
						}
					}
					break;
				case ppt_pp_call:
					if(opt_t2_boost && preProcessPacketCallX_state == PreProcessPacket::callx_process && 
					   preProcessPacketCallX[0]->isActiveOutThread()) {
						for(int i = 0; i < preProcessPacketCallX_count; i++) {
							preProcessPacketCallX[i]->push_batch();
						}
					}
					if(!opt_t2_boost || preProcessPacketCallX_state == PreProcessPacket::callx_na) {
						_process_packet__cleanup_calls(__FILE__, __LINE__);
					}
					break;
				case ppt_pp_callx:
					if(opt_t2_boost && preProcessPacketCallX_state != PreProcessPacket::callx_na &&
					   preProcessPacketCallX[0]->isActiveOutThread() &&
					   (int)idPreProcessThread == preProcessPacketCallX_count) {
						_process_packet__cleanup_calls(__FILE__, __LINE__);
					}
					break;
				case ppt_pp_callfindx:
					preProcessPacketCallX[idPreProcessThread]->push_batch();
					break;
				case ppt_pp_register:
					_process_packet__cleanup_registers();
					break;
				case ppt_pp_sip_other:
					break;
				case ppt_pp_rtp:
					if(processRtpPacketHash) {
						processRtpPacketHash->push_batch();
					} else if(!opt_t2_boost) {
						if(rtp_threads) {
							extern int num_threads_max;
							for(int i = 0; i < num_threads_max; i++) {
								if(rtp_threads[i].threadId) {
									rtp_threads[i].push_batch();
								}
							}
						}
					}
					break;
				case ppt_pp_other:
					_process_packet__cleanup_ss7();
					break;
				case ppt_end_base:
					break;
				}
				usleepSumTimeForPushBatch = 0;
			}
			usleepSumTimeForPushBatch += USLEEP_C(opt_preprocess_packets_qring_usleep, usleepCounter++);
		}
	}
	this->outThreadState = 0;
	syslog(LOG_NOTICE, "stop PreProcessPacket out thread %s/%i", this->getNameTypeThread().c_str(), this->outThreadId);
	return(NULL);
}

void PreProcessPacket::processNextAction(packet_s_process *packetS) {
	switch(packetS->next_action) {
	case _ppna_push_to_extend:
		preProcessPacket[ppt_extend]->push_packet(packetS);
		break;
	case _ppna_push_to_rtp:
		preProcessPacket[ppt_pp_rtp]->push_packet(packetS);
		break;
	case _ppna_push_to_other:
		preProcessPacket[ppt_pp_other]->push_packet(packetS);
		break;
	}
	if(packetS->__type == _t_packet_s_process && packetS->child_packets) {
		if(packetS->child_packets_type == packet_s_process::_tchp_packet) {
			processNextAction((packet_s_process*)packetS->child_packets);
		} else {
			for(list<packet_s_process*>::iterator iter = ((list<packet_s_process*>*)packetS->child_packets)->begin(); 
			    iter != ((list<packet_s_process*>*)packetS->child_packets)->end(); 
			    iter++) {
				processNextAction(*iter);
			}
		}
	}
	if(packetS->next_action == _ppna_destroy) {
		PACKET_S_PROCESS_DESTROY(&packetS);
	}
}

void PreProcessPacket::push_batch_nothread() {
	switch(this->typePreProcessThread) {
	case ppt_detach:
		if(!preProcessPacket[ppt_sip]->outThreadState) {
			preProcessPacket[ppt_sip]->push_batch();
		}
		break;
	case ppt_sip:
		if(!preProcessPacket[ppt_extend]->outThreadState) {
			preProcessPacket[ppt_extend]->push_batch();
		}
		if(opt_t2_boost) {
			if(!preProcessPacket[ppt_pp_rtp]->outThreadState) {
				preProcessPacket[ppt_pp_rtp]->push_batch();
			}
		}
		if(!preProcessPacket[ppt_pp_other]->outThreadState) {
			preProcessPacket[ppt_pp_other]->push_batch();
		}
		break;
	case ppt_extend:
		if(!preProcessPacket[ppt_pp_call]->outThreadState) {
			preProcessPacket[ppt_pp_call]->push_batch();
		}
		if(!preProcessPacket[ppt_pp_register]->outThreadState) {
			preProcessPacket[ppt_pp_register]->push_batch();
		}
		if(!preProcessPacket[ppt_pp_sip_other]->outThreadState) {
			preProcessPacket[ppt_pp_sip_other]->push_batch();
		}
		if(!opt_t2_boost) {
			if(!preProcessPacket[ppt_pp_rtp]->outThreadState) {
				preProcessPacket[ppt_pp_rtp]->push_batch();
			}
		}
		if(opt_t2_boost && preProcessPacketCallX_state == PreProcessPacket::callx_find) {
			for(int i = 0; i < preProcessPacketCallX_count; i++) {
				if(!preProcessPacketCallFindX[i]->outThreadState) {
					preProcessPacketCallFindX[i]->push_batch();
				}
			}
		}
		break;
	case ppt_pp_call:
		if(opt_t2_boost && preProcessPacketCallX_state == PreProcessPacket::callx_process) {
			for(int i = 0; i < preProcessPacketCallX_count; i++) {
				if(!preProcessPacketCallX[i]->outThreadState) {
					preProcessPacketCallX[i]->push_batch();
				}
			}
		}
		if(!opt_t2_boost || preProcessPacketCallX_state == PreProcessPacket::callx_na) {
			_process_packet__cleanup_calls(__FILE__, __LINE__);
		}
		break;
	case ppt_pp_callx:
		if(opt_t2_boost && 
		   (int)idPreProcessThread == preProcessPacketCallX_count) {
			_process_packet__cleanup_calls(__FILE__, __LINE__);
		}
		break;
	case ppt_pp_callfindx:
		if(!preProcessPacketCallX[idPreProcessThread]->outThreadState) {
			preProcessPacketCallX[idPreProcessThread]->push_batch();
		}
		break;
	case ppt_pp_register:
		_process_packet__cleanup_registers();
		break;
	case ppt_pp_sip_other:
		break;
	case ppt_pp_rtp:
		if(processRtpPacketHash) {
			processRtpPacketHash->push_batch();
		} else if(!opt_t2_boost) {
			if(rtp_threads) {
				extern int num_threads_max;
				for(int i = 0; i < num_threads_max; i++) {
					if(rtp_threads[i].threadId) {
						rtp_threads[i].push_batch();
					}
				}
			}
		}
	case ppt_pp_other:
		_process_packet__cleanup_ss7();
		break;
	case ppt_end_base:
		break;
	}
}

void PreProcessPacket::preparePstatData(int nextThreadIndexPlus) {
	if(nextThreadIndexPlus ? this->nextThreadId[nextThreadIndexPlus - 1] : this->outThreadId) {
		if(this->threadPstatData[nextThreadIndexPlus][0].cpu_total_time) {
			this->threadPstatData[nextThreadIndexPlus][1] = this->threadPstatData[nextThreadIndexPlus][0];
		}
		pstat_get_data(nextThreadIndexPlus ? this->nextThreadId[nextThreadIndexPlus - 1] : this->outThreadId, this->threadPstatData[nextThreadIndexPlus]);
	}
}

double PreProcessPacket::getCpuUsagePerc(bool preparePstatData, int nextThreadIndexPlus, double *percFullQring) {
	++getCpuUsagePerc_counter;
	if(this->isActiveOutThread()) {
		if(preparePstatData) {
			this->preparePstatData(nextThreadIndexPlus);
		}
		if(this->outThreadId) {
			if(nextThreadIndexPlus ? this->nextThreadId[nextThreadIndexPlus - 1] : this->outThreadId) {
				double ucpu_usage, scpu_usage;
				if(this->threadPstatData[nextThreadIndexPlus][0].cpu_total_time && this->threadPstatData[nextThreadIndexPlus][1].cpu_total_time) {
					pstat_calc_cpu_usage_pct(
						&this->threadPstatData[nextThreadIndexPlus][0], &this->threadPstatData[nextThreadIndexPlus][1],
						&ucpu_usage, &scpu_usage);
					if(percFullQring) {
						*percFullQring = qringPushCounter ? 100. * qringPushCounter_full / qringPushCounter : -1;
						qringPushCounter = 0;
						qringPushCounter_full = 0;
					}
					return(ucpu_usage + scpu_usage);
				}
			}
		}
	}
	if(percFullQring) {
		*percFullQring = -1;
		qringPushCounter = 0;
		qringPushCounter_full = 0;
	}
	return(-1);
}

void PreProcessPacket::terminate() {
	this->term_preProcess = true;
	unsigned int usleepCounter = 0;
	while(this->outThreadState) {
		USLEEP_C(10, usleepCounter++);
	}
	this->out_thread_handle = 0;
	for(int i = 0; i < this->next_threads; i++) {
		if(this->next_thread_handle[i]) {
			sem_post(&this->sem_sync_next_thread[i][0]);
			pthread_join(this->next_thread_handle[i], NULL);
			this->next_thread_handle[i] = 0;
			for(int j = 0; j < 2; j++) {
				sem_destroy(&sem_sync_next_thread[i][j]);
			}
		}
	}
}

void PreProcessPacket::addNextThread() {
	if(opt_t2_boost &&
	   (this->typePreProcessThread == ppt_detach || this->typePreProcessThread == ppt_sip) &&
	   this->next_threads < min(opt_pre_process_packets_next_thread_max, MAX_PRE_PROCESS_PACKET_NEXT_THREADS)) {
		for(int j = 0; j < 2; j++) {
			sem_init(&sem_sync_next_thread[this->next_threads][j], 0, 0);
		}
		arg_next_thread *arg = new FILE_LINE(0) arg_next_thread;
		arg->preProcessPacket = this;
		arg->next_thread_id = this->next_threads + 1;
		vm_pthread_create(("pre process next - " + getNameTypeThread()).c_str(),
				  &this->next_thread_handle[this->next_threads], NULL, _PreProcessPacket_nextThreadFunction, arg, __FILE__, __LINE__);
		++this->next_threads;
	}
}

void PreProcessPacket::process_SIP(packet_s_process *packetS, bool parallel_threads) {
	++counter_all_packets;
	bool isSip = false;
	bool isMgcp = false;
	bool rtp = false;
	bool other = false;
	packetS->blockstore_addflag(11 /*pb lock flag*/);
	if(packetS->need_sip_process) {
		packetS->init2();
		packetS->next_action = parallel_threads ? _ppna_set : _ppna_na;
		if(check_sip20(packetS->data_(), packetS->datalen_(), NULL, packetS->pflags.tcp)) {
			packetS->blockstore_addflag(12 /*pb lock flag*/);
			isSip = true;
		} else if(packetS->pflags.mgcp && check_mgcp(packetS->data_(), packetS->datalen_())) {
			//packetS->blockstore_addflag(12 /*pb lock flag*/);
			isMgcp = true;
		}
		if(packetS->pflags.tcp) {
			packetS->blockstore_addflag(13 /*pb lock flag*/);
			if(packetS->pflags.skinny) {
				// call process_skinny before tcp reassembly - TODO !
				this->process_skinny(&packetS);
			} else if(packetS->pflags.mgcp && isMgcp) {
				// call process_mgcp before tcp reassembly - TODO !
				this->process_mgcp(&packetS);
			} else if(no_sip_reassembly() || packetS->pflags.ssl) {
				if(isSip) {
					this->process_parseSipData(&packetS, NULL);
				} else {
					if(packetS->next_action == _ppna_set) {
						packetS->next_action = _ppna_destroy;
					} else {
						PACKET_S_PROCESS_DESTROY(&packetS);
					}
				}
			} else {
				bool possibleWebSocketSip = false;
				if(!isSip && check_websocket(packetS->data_(), packetS->datalen_(), cWebSocketHeader::_chdst_na)) {
					cWebSocketHeader ws(packetS->data_(), packetS->datalen_());
					if(packetS->datalen_() - ws.getHeaderLength() < 11) {
						possibleWebSocketSip = true;
					}
				}
				extern bool opt_sip_tcp_reassembly_ext;
				extern TcpReassembly *tcpReassemblySipExt;
				if(opt_sip_tcp_reassembly_ext && tcpReassemblySipExt) {
					tcpReassemblySipExt->push_tcp(packetS->header_pt, packetS->header_ip_(), (u_char*)packetS->packet, packetS->_packet_alloc,
								      packetS->block_store, packetS->block_store_index, packetS->_blockstore_lock,
								      packetS->handle_index, packetS->dlt, packetS->sensor_id_(), packetS->sensor_ip, packetS->pid,
								      this, packetS, isSip || possibleWebSocketSip);
					packetS->_packet_alloc = false;
					packetS->_blockstore_lock = false;
					if(packetS->next_action == _ppna_set) {
						packetS->next_action = _ppna_destroy;
					} else {
						PACKET_S_PROCESS_DESTROY(&packetS);
					}
				} else {
					tcpReassemblySip.processPacket(&packetS, isSip || possibleWebSocketSip, this);
				}
			}
		} else if(isSip) {
			packetS->blockstore_addflag(14 /*pb lock flag*/);
			this->process_parseSipData(&packetS, NULL);
		} else if(isMgcp) {
			//packetS->blockstore_addflag(14 /*pb lock flag*/);
			this->process_mgcp(&packetS);
		} else {
			packetS->blockstore_addflag(15 /*pb lock flag*/);
			rtp = true;
		}
	} else if(packetS->pflags.mrcp) {
		rtp = true;
	} else if(!packetS->pflags.other_processing()) {
		packetS->blockstore_addflag(16 /*pb lock flag*/);
		rtp = true;
	} else {
		other = true;
	}
	if(rtp) {
		packetS->blockstore_addflag(17 /*pb lock flag*/);
		if(opt_t2_boost) {
			if(parallel_threads) {
				packetS->next_action = _ppna_push_to_rtp;
			} else {
				preProcessPacket[ppt_pp_rtp]->push_packet(packetS);
			}
		} else {
			packetS->type_content = _pptc_na;
			if(parallel_threads) {
				packetS->next_action = _ppna_push_to_extend;
			} else {
				preProcessPacket[ppt_extend]->push_packet(packetS);
			}
		}
	}
	if(other) {
		if(parallel_threads) {
			packetS->next_action = _ppna_push_to_other;
		} else {
			preProcessPacket[ppt_pp_other]->push_packet(packetS);
		}
	}
}

void PreProcessPacket::process_SIP_EXTEND(packet_s_process *packetS) {
	glob_last_packet_time = packetS->getTime_s();
	if(packetS->typeContentIsSip()) {
		packetS->blockstore_addflag(101 /*pb lock flag*/);
		bool pushed = false;
		if(!packetS->is_register()) {
			if(opt_t2_boost && preProcessPacketCallX_state == PreProcessPacket::callx_find &&
			   preProcessPacketCallFindX[0]->isActiveOutThread()) {
				preProcessPacketCallFindX[packetS->get_callid_sipextx_index()]->push_packet(packetS);
				pushed = true;
			} else {
				this->process_findCall(&packetS);
				this->process_createCall(&packetS);
				if((packetS->_findCall && packetS->call) ||
				   (packetS->_createCall && packetS->call_created)) {
					preProcessPacket[ppt_pp_call]->push_packet(packetS);
					pushed = true;
				}
			}
		} else if(opt_sip_register) {
			preProcessPacket[ppt_pp_register]->push_packet(packetS);
			pushed = true;
		}
		if(!pushed) {
			if((packetS->is_options() && !opt_sip_options && !livesnifferfilterUseSipTypes.u_options) ||
			   (packetS->is_subscribe() && !opt_sip_subscribe && !livesnifferfilterUseSipTypes.u_subscribe) ||
			   (packetS->is_notify() && !opt_sip_notify && !livesnifferfilterUseSipTypes.u_notify)) {
				PACKET_S_PROCESS_DESTROY(&packetS);
			} else {
				preProcessPacket[ppt_pp_sip_other]->push_packet(packetS);
			}
		}
	} else if(packetS->typeContentIsSkinny()) {
		packetS->blockstore_addflag(102 /*pb lock flag*/);
		preProcessPacket[ppt_pp_call]->push_packet(packetS);
	} else if(packetS->typeContentIsMgcp()) {
		//packetS->blockstore_addflag(102 /*pb lock flag*/);
		preProcessPacket[ppt_pp_call]->push_packet(packetS);
	} else if(!opt_t2_boost) {
		packetS->blockstore_addflag(103 /*pb lock flag*/);
		preProcessPacket[ppt_pp_rtp]->push_packet(packetS);
	}
}

void PreProcessPacket::process_CALL(packet_s_process *packetS) {
	if(packetS->typeContentIsSip() && !packetS->is_register()) {
		if(opt_ipaccount && packetS->block_store) {
			packetS->block_store->setVoipPacket(packetS->block_store_index);
		}
		if(opt_detect_alone_bye &&
		   ((packetS->_findCall && packetS->call && packetS->call->typeIs(BYE)) ||
		    (packetS->_createCall && packetS->call_created && packetS->call_created->typeIs(BYE)))) {
			process_packet_sip_alone_bye(packetS);
		} else {
			if(opt_t2_boost && preProcessPacketCallX_state == PreProcessPacket::callx_process &&
			   preProcessPacketCallX[0]->isActiveOutThread()) {
				Call *call = packetS->call ? packetS->call : packetS->call_created;
				preProcessPacketCallX[call ? call->counter % preProcessPacketCallX_count : 0]->push_packet(packetS);
				return;
			} else {
				process_packet_sip_call(packetS);
			}
		}
		if(opt_quick_save_cdr != 2) {
			_process_packet__cleanup_calls(packetS->getTimeval_pt(), __FILE__, __LINE__);
		}
		if(packetS->_findCall && packetS->call) {
			__sync_sub_and_fetch(&packetS->call->in_preprocess_queue_before_process_packet, 1);
		}
		if(packetS->_createCall && packetS->call_created) {
			__sync_sub_and_fetch(&packetS->call_created->in_preprocess_queue_before_process_packet, 1);
		}
		if(opt_quick_save_cdr == 2) {
			_process_packet__cleanup_calls(packetS->getTimeval_pt(), __FILE__, __LINE__);
		}
	} else if(packetS->typeContentIsSkinny()) {
		if(opt_ipaccount && packetS->block_store) {
			packetS->block_store->setVoipPacket(packetS->block_store_index);
		}
		_process_packet__cleanup_calls(packetS->getTimeval_pt(), __FILE__, __LINE__);
		handle_skinny(packetS->header_pt, packetS->packet, packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), packetS->data_(), packetS->datalen_(), packetS->dataoffset_(),
			      get_pcap_handle(packetS->handle_index), packetS->dlt, packetS->sensor_id_(), packetS->sensor_ip);
	} else if(packetS->typeContentIsMgcp()) {
		if(opt_ipaccount && packetS->block_store) {
			packetS->block_store->setVoipPacket(packetS->block_store_index);
		}
		_process_packet__cleanup_calls(packetS->getTimeval_pt(), __FILE__, __LINE__);
		handle_mgcp(packetS);
	}
	PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 0);
}

void PreProcessPacket::process_CALLX(packet_s_process *packetS) {
	process_packet_sip_call(packetS);
	if(idPreProcessThread == 0) {
		_process_packet__cleanup_calls(packetS->getTimeval_pt(), __FILE__, __LINE__);
	}
	if(packetS->_findCall && packetS->call) {
		__sync_sub_and_fetch(&packetS->call->in_preprocess_queue_before_process_packet, 1);
	}
	if(packetS->_createCall && packetS->call_created) {
		__sync_sub_and_fetch(&packetS->call_created->in_preprocess_queue_before_process_packet, 1);
	}
	PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 10 + idPreProcessThread);
}

void PreProcessPacket::process_CallFindX(packet_s_process *packetS) {
	packetS->call = calltable->find_by_call_id_x(idPreProcessThread, packetS->get_callid(), 0, packetS->getTime_s());
	packetS->_findCall = true;
	if(!packetS->call &&
	   (packetS->sip_method == INVITE || packetS->sip_method == MESSAGE ||
	    (opt_detect_alone_bye && packetS->sip_method == BYE))) {
		packetS->call_created = new_invite_register(packetS, packetS->sip_method, packetS->get_callid(), idPreProcessThread);
		packetS->_createCall = true;
	}
	if(packetS->call || packetS->call_created) {
		preProcessPacketCallX[idPreProcessThread]->push_packet(packetS);
	} else {
		PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 20 + idPreProcessThread);
	}
}

void PreProcessPacket::process_REGISTER(packet_s_process *packetS) {
	if(packetS->typeContentIsSip() && packetS->is_register()) {
		if(opt_ipaccount && packetS->block_store) {
			packetS->block_store->setVoipPacket(packetS->block_store_index);
		}
		process_packet_sip_register(packetS);
	}
	PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 1);
}

void PreProcessPacket::process_SIP_OTHER(packet_s_process *packetS) {
	if(packetS->typeContentIsSip()) {
		if(opt_ipaccount && packetS->block_store) {
			packetS->block_store->setVoipPacket(packetS->block_store_index);
		}
		process_packet_sip_other(packetS);
	}
	PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 2);
}

void PreProcessPacket::process_RTP(packet_s_process_0 *packetS) {
	if(processing_limitations.suppressRtpAllProcessing() ||
	   !process_packet_rtp(packetS)) {
		PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 3);
	}
}

void PreProcessPacket::process_OTHER(packet_s_stack *packetS) {
	if(packetS->pflags.other_processing()) {
		process_packet_other(packetS);
	}
	PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 4);
}

void PreProcessPacket::process_parseSipDataExt(packet_s_process **packetS_ref, packet_s_process *packetS_orig) {
	if(packetS_orig && packetS_orig->next_action) {
		packetS_orig->register_child_packet(*packetS_ref);
		(*packetS_ref)->next_action = _ppna_set;
	}
	this->process_parseSipData(packetS_ref, packetS_orig);
}

void PreProcessPacket::process_parseSipData(packet_s_process **packetS_ref, packet_s_process *packetS_orig) {
	packet_s_process *packetS = *packetS_ref;
	if(!packetS_orig) {
		packetS_orig = packetS;
	}
	if(check_websocket(packetS->data_(), packetS->datalen_())) {
		this->process_websocket(&packetS, packetS_orig);
		return;
	}
	if(packetS->pflags.skinny) {
		this->process_skinny(&packetS);
		return;
	}
	if(packetS->pflags.mgcp) {
		this->process_mgcp(&packetS);
		return;
	}
	bool isSip = false;
	bool multipleSip = false;
	do {
		packetS->sipDataLen = packetS->parseContents.parse(packetS->data_()+ packetS->sipDataOffset, 
								   packetS->datalen_() - packetS->sipDataOffset, true);
		if(packetS->parseContents.isSip()) {
			packetS->type_content = _pptc_sip;
			isSip = true;
			bool nextSip = false;
			u_int32_t nextSipDataOffset = 0;
			if((packetS->sipDataOffset + packetS->sipDataLen + 11) < packetS->datalen_()) {
				if(check_sip20(packetS->data_()+ packetS->sipDataOffset + packetS->sipDataLen,
					       packetS->datalen_() - packetS->sipDataOffset - packetS->sipDataLen,
					       NULL, packetS->pflags.tcp)) {
					nextSip = true;
					multipleSip = true;
				} else {
					char *pointToDoubleEndLine = NULL;
					unsigned doubleEndLineSize = 0;
					for(int pass_line_separator = 0; pass_line_separator < 2 && !pointToDoubleEndLine; pass_line_separator++) {
						pointToDoubleEndLine = (char*)memmem(packetS->data_()+ packetS->sipDataOffset + packetS->sipDataLen, 
										     packetS->datalen_() - (packetS->sipDataOffset + packetS->sipDataLen), 
										     SIP_DBLLINE_SEPARATOR(pass_line_separator == 1), 
										     SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1));
						if(doubleEndLineSize) {
							doubleEndLineSize = SIP_DBLLINE_SEPARATOR_SIZE(pass_line_separator == 1);
						}
					}
					if(pointToDoubleEndLine) {
						u_int32_t offsetAfterDoubleEndLine = pointToDoubleEndLine - packetS->data_() + doubleEndLineSize;
						if(offsetAfterDoubleEndLine < (unsigned)packetS->datalen_() - 11) {
							if(check_sip20(packetS->data_()+ offsetAfterDoubleEndLine, 
								       packetS->datalen_() - offsetAfterDoubleEndLine, 
								       NULL, packetS->pflags.tcp)) {
								nextSip = true;
								multipleSip = true;
								nextSipDataOffset = offsetAfterDoubleEndLine;
							}
						}
					}
				}
			}
			if(multipleSip) {
				packet_s_process *partPacketS = PACKET_S_PROCESS_SIP_CREATE();
				*partPacketS = *packetS;
				partPacketS->stack = NULL;
				partPacketS->blockstore_relock(18 /*pb lock flag*/);
				if(partPacketS->_packet_alloc) {
					partPacketS->new_alloc_packet_header();
				}
				if(packetS_orig && packetS_orig->next_action) {
					packetS_orig->register_child_packet(partPacketS);
					partPacketS->next_action = _ppna_set;
				}
				this->process_sip(&partPacketS);
			} else {
				this->process_sip(&packetS);
			}
			if(nextSip) {
				if(nextSipDataOffset) {
					packetS->sipDataOffset = nextSipDataOffset;
				} else {
					packetS->sipDataOffset += packetS->sipDataLen;
				}
			} else {
				break;
			}
		} else {
			break;
		}
		
	} while(true);
	if(isSip) {
		++counter_sip_packets[0];
		if(multipleSip) {
			if(packetS->next_action == _ppna_set) {
				packetS->next_action = _ppna_destroy;
			} else {
				PACKET_S_PROCESS_DESTROY(&packetS);
			}
		}
	} else if(packetS) {
		if(packetS->next_action == _ppna_set) {
			packetS->next_action = _ppna_push_to_rtp;
		} else {
			preProcessPacket[ppt_pp_rtp]->push_packet(packetS);
		}
	}
}

void PreProcessPacket::process_sip(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	extern vmIP opt_kamailio_dstip;
	extern vmIP opt_kamailio_srcip;
	extern unsigned opt_kamailio_port;
	if(opt_kamailio_dstip.isSet() && opt_kamailio_dstip == packetS->daddr_() &&
	   (!opt_kamailio_srcip.isSet() || opt_kamailio_srcip == packetS->saddr_()) &&
	   (!opt_kamailio_port || opt_kamailio_port == packetS->dest_().port)) {
		unsigned long from_ip_l;
		char *from_ip = gettag_sip(packetS, "\nX-Siptrace-Fromip:", &from_ip_l);
		if(from_ip) {
			unsigned long to_ip_l;
			char *to_ip = gettag_sip(packetS, "\nX-Siptrace-Toip:", &to_ip_l);
			if(to_ip) {
				bool is_tcp[2] = { false, false };
				vmIP n_ip[2];
				unsigned n_port[2] = { 0, 0 };
				bool ok_ip[2] = { false, false };
				for(int i = 0; i < 2; i++) {
					char *ip = i == 0 ? from_ip : to_ip;
					unsigned long l = i == 0 ? from_ip_l : to_ip_l;
					char *p_sep_ip = strnchr(ip, ':', l);
					if(p_sep_ip) {
						char *p_sep_port = strnchr(p_sep_ip + 1, ':', l - (p_sep_ip - ip));
						if(p_sep_port) {
							is_tcp[i] = ip[0] == 't' || ip[0] == 'T';
							string str_ip = string(p_sep_ip + 1, p_sep_port - p_sep_ip - 1);
							n_port[i] = atoi(p_sep_port + 1);
							if(n_ip[i].setFromString(str_ip.c_str()) && 
							   n_port[i] > 0 && n_port[i] <= 0xFFFF) {
								ok_ip[i] = true;
								// cout << (is_tcp[i] ? 'T' : 'U') << " : " << n_ip[i].getString() << " : " << n_port[i] << endl;
							} else {
								break;
							}
						}
					}
				}
				if(ok_ip[0] && ok_ip[1]) {
					packet_s_kamailio_subst *kamailio_subst = new FILE_LINE(0) packet_s_kamailio_subst;
					kamailio_subst->is_tcp = is_tcp[0] || is_tcp[1];
					kamailio_subst->saddr = n_ip[0];
					kamailio_subst->daddr = n_ip[1];
					kamailio_subst->source = n_port[0];
					kamailio_subst->dest = n_port[1];
					unsigned long time_l;
					char *time = gettag_sip(packetS, "\nX-Siptrace-Time:", &time_l);
					bool time_ok = false;
					if(time) {
						char *p_sep_us = strnchr(time, ' ', time_l) ;
						if(p_sep_us) {
							kamailio_subst->ts.tv_sec = atol(time);
							kamailio_subst->ts.tv_usec = atol(p_sep_us + 1);
							extern char opt_pb_read_from_file[256];
							extern int opt_pb_read_from_file_acttime;
							extern u_int64_t opt_pb_read_from_file_acttime_diff;
							if(opt_pb_read_from_file[0]) {
								if(opt_pb_read_from_file_acttime) {
									u_int64_t packetTime = getTimeUS(kamailio_subst->ts);
									packetTime += opt_pb_read_from_file_acttime_diff;
									kamailio_subst->ts.tv_sec = TIME_US_TO_S(packetTime);
									kamailio_subst->ts.tv_usec = TIME_US_TO_DEC_US(packetTime);
								}
							}
							time_ok = true;
						}
					}
					if(!time_ok) {
						kamailio_subst->ts.tv_sec = 0;
						kamailio_subst->ts.tv_usec = 0;
					}
					packetS->kamailio_subst = kamailio_subst;
				}
			}
		}
	}
	packetS->_getCallID = true;
	if(!this->process_getCallID(&packetS)) {
		if(packetS->next_action == _ppna_set) {
			packetS->next_action = _ppna_destroy;
		} else {
			PACKET_S_PROCESS_DESTROY(&packetS);
		}
		return;
	}
	this->process_getSipMethod(&packetS);
	if(packetS->is_register() && !opt_sip_register && !livesnifferfilterUseSipTypes.u_register) {
		if(packetS->next_action == _ppna_set) {
			packetS->next_action = _ppna_destroy;
		} else {
			PACKET_S_PROCESS_DESTROY(&packetS);
		}
		return;
	}
	if(!this->process_getCallID_publish(&packetS)) {
		if(packetS->next_action == _ppna_set) {
			packetS->next_action = _ppna_destroy;
		} else {
			PACKET_S_PROCESS_DESTROY(&packetS);
		}
		return;
	}
	this->process_getLastSipResponse(&packetS);
	++counter_sip_packets[1];
	if(packetS) {
		if(packetS->next_action == _ppna_set) {
			packetS->next_action = _ppna_push_to_extend;
		} else {
			preProcessPacket[ppt_extend]->push_packet(packetS);
		}
	}
}

void PreProcessPacket::process_skinny(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	packetS->type_content = _pptc_skinny;
	++counter_sip_packets[1];
	if(packetS->next_action == _ppna_set) {
		packetS->next_action = _ppna_push_to_extend;
	} else {
		preProcessPacket[ppt_extend]->push_packet(packetS);
	}
}

void PreProcessPacket::process_mgcp(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	packetS->type_content = _pptc_mgcp;
	++counter_sip_packets[1];
	if(packetS->next_action == _ppna_set) {
		packetS->next_action = _ppna_push_to_extend;
	} else {
		preProcessPacket[ppt_extend]->push_packet(packetS);
	}
}

void PreProcessPacket::process_websocket(packet_s_process **packetS_ref, packet_s_process *packetS_orig) {
	packet_s_process *packetS = *packetS_ref;
	if(!packetS_orig) {
		packetS_orig = packetS;
	}
	cWebSocketHeader ws(packetS->data_(), packetS->datalen_());
	bool allocWsData;
	u_char *ws_data = ws.decodeData(&allocWsData);
	packet_s_process *newPacketS = clonePacketS(ws_data, ws.getDataLength(), packetS);
	if(allocWsData) {
		delete [] ws_data;
	}
	if(packetS_orig && packetS_orig->next_action) {
		packetS_orig->register_child_packet(newPacketS);
		newPacketS->next_action = _ppna_set;
	}
	if(packetS->next_action == _ppna_set) {
		packetS->next_action = _ppna_destroy;
	} else {
		PACKET_S_PROCESS_DESTROY(&packetS);
	}
	this->process_parseSipData(&newPacketS, packetS);
}

bool PreProcessPacket::process_getCallID(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	bool exists_callid = false;
	char *s;
	unsigned long l;
	s = gettag_sip(packetS, "\nCall-ID:", "\ni:", &l);
	if(s && l <= 1023) {
		packetS->set_callid(s, l);
		exists_callid = true;
	}
	if(opt_call_id_alternative[0]) {
		for(unsigned i = 0; i < opt_call_id_alternative_v.size(); i++) {
			s = gettag_sip(packetS, ("\n" + opt_call_id_alternative_v[i]).c_str(), &l);
			if(s && l <= 1023) {
				packetS->set_callid_alternative(s, l);
				exists_callid = true;
			}
		}
	}
	return(exists_callid);
}

bool PreProcessPacket::process_getCallID_publish(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	if(packetS->sip_method == PUBLISH) {
		char *s;
		unsigned long l;
		s = gettag_sip(packetS, "\nContent-Type:", "\nc:", &l);
		if(s && l <= 1023 &&
		   strncasestr(s, "application/vq-rtcpxr", l)) {
			s = gettag_sip(packetS, "\nCallID:", &l);
			if(s && l <= 1023) {
				packetS->set_callid(s, l);
			} else {
				return(false);
			}
		}
	}
	return(true);
}

void PreProcessPacket::process_getSipMethod(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	packetS->sip_method = process_packet__parse_sip_method(packetS, &packetS->sip_response);
	process_packet__parse_cseq(&packetS->cseq, packetS);
	packetS->_getSipMethod = true;
}

void PreProcessPacket::process_getLastSipResponse(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	packetS->lastSIPresponseNum = parse_packet__last_sip_response(packetS, packetS->sip_method, packetS->sip_response,
								      packetS->lastSIPresponse, &packetS->call_cancel_lsr487);
	packetS->_getLastSipResponse = true;
}

void PreProcessPacket::process_findCall(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	packetS->call = calltable->find_by_call_id(packetS->get_callid(), 0, packetS->callid_alternative, packetS->getTime_s());
	if(packetS->call) {
		if(pcap_drop_flag) {
			packetS->call->pcap_drop = pcap_drop_flag;
		}
		if(packetS->call_cancel_lsr487) {
			packetS->call->cancel_lsr487 = true;
		}
	} else if(opt_callidmerge_header[0] != '\0') {
		packetS->call = process_packet__merge(packetS, packetS->get_callid(), &packetS->merged, true);
	}
	packetS->_findCall = true;
}

void PreProcessPacket::process_createCall(packet_s_process **packetS_ref) {
	packet_s_process *packetS = *packetS_ref;
	if(packetS->_findCall && !packetS->call &&
	   (packetS->sip_method == INVITE || packetS->sip_method == MESSAGE ||
	    (opt_detect_alone_bye && packetS->sip_method == BYE))) {
		packetS->call_created = new_invite_register(packetS, packetS->sip_method, packetS->get_callid());
		packetS->_createCall = true;
	}
}

void PreProcessPacket::autoStartNextLevelPreProcessPacket() {
	int i = 0;
	for(; i < PreProcessPacket::ppt_end_base && preProcessPacket[i]->isActiveOutThread(); i++);
	if(!opt_sip_register && preProcessPacket[i]->getTypePreProcessThread() == PreProcessPacket::PreProcessPacket::ppt_pp_register) {
		++i;
	}
	if(i < PreProcessPacket::ppt_end_base) {
		preProcessPacket[i]->startOutThread();
		autoStartNextLevelPreProcessPacket_last_time_s = getTimeS();
	}
}

void PreProcessPacket::autoStartCallX_PreProcessPacket() {
	if(opt_t2_boost) {
		for(int i = 0; i < preProcessPacketCallX_count + 1; i++) {
			if(!preProcessPacketCallX[i]->outThreadState) {
				preProcessPacketCallX[i]->startOutThread();
			}
		}
		if(calltable->enableCallFindX()) {
			for(int i = 0; i < preProcessPacketCallX_count; i++) {
				if(!preProcessPacketCallFindX[i]->outThreadState) {
					preProcessPacketCallFindX[i]->startOutThread();
				}
			}
			preProcessPacketCallX_state = PreProcessPacket::callx_find;
		} else {
			preProcessPacketCallX_state = PreProcessPacket::callx_process;
		}
	}
}

void PreProcessPacket::autoStopLastLevelPreProcessPacket(bool force) {
	if(autoStartNextLevelPreProcessPacket_last_time_s &&
	   getTimeS() < autoStartNextLevelPreProcessPacket_last_time_s + 30 * 60) {
		cout << "suppress stop t2 thread" << endl;
		return;
	}
	int i = 0;
	for(i = PreProcessPacket::ppt_end_base - 1; i > 0 && !preProcessPacket[i]->isActiveOutThread(); i--);
	if(i > 0 && preProcessPacket[i]->isActiveOutThread()) {
		preProcessPacket[i]->stopOutThread(force);
	}
}

packet_s_process *PreProcessPacket::clonePacketS(u_char *newData, unsigned newDataLength, packet_s_process *packetS) {
	packet_s_process *newPacketS = PACKET_S_PROCESS_SIP_CREATE();
	*newPacketS = *packetS;
	newPacketS->blockstore_clear();
	long newLen = newDataLength + newPacketS->dataoffset_();
	pcap_pkthdr *new_header = new FILE_LINE(0) pcap_pkthdr;
	*new_header = *newPacketS->header_pt;
	new_header->caplen = newLen;
	new_header->len = newLen;
	u_char *new_packet = new FILE_LINE(0) u_char[newLen];
	memcpy(new_packet, newPacketS->packet, newPacketS->dataoffset_());
	memcpy(new_packet + newPacketS->dataoffset_(), newData, newDataLength);
	//u_char *newDataInNewPacket = new_packet + newPacketS->dataoffset_();
	iphdr2 *newHeaderIpInNewPacket = (iphdr2*)(new_packet + newPacketS->header_ip_offset);
	newHeaderIpInNewPacket->set_tot_len(newLen - newPacketS->header_ip_offset);
	//newPacketS->data = (char*)newDataInNewPacket;
	newPacketS->_datalen = newDataLength;
	newPacketS->_datalen_set = 0;
	newPacketS->header_pt = new_header;
	newPacketS->packet = new_packet;
	//newPacketS->header_ip = newHeaderIpInNewPacket;
	newPacketS->_packet_alloc = true;
	return(newPacketS);
}

u_long PreProcessPacket::autoStartNextLevelPreProcessPacket_last_time_s = 0;

inline void *_ProcessRtpPacket_outThreadFunction(void *arg) {
	return(((ProcessRtpPacket*)arg)->outThreadFunction());
}

inline void *_ProcessRtpPacket_nextThreadFunction(void *arg) {
	ProcessRtpPacket::arg_next_thread *_arg = (ProcessRtpPacket::arg_next_thread*)arg;
	void *rsltThread = _arg->processRtpPacket->nextThreadFunction(_arg->next_thread_id);
	delete _arg;
	return(rsltThread);
}

ProcessRtpPacket::ProcessRtpPacket(eType type, int indexThread) {
	this->type = type;
	this->indexThread = indexThread;
	this->qring_batch_item_length = opt_process_rtp_packets_qring_item_length ?
					 opt_process_rtp_packets_qring_item_length :
					 min(opt_process_rtp_packets_qring_length / 5, 1000u);
	this->qring_length = opt_process_rtp_packets_qring_item_length ?
			      opt_process_rtp_packets_qring_length :
			      opt_process_rtp_packets_qring_length / this->qring_batch_item_length;
	this->readit = 0;
	this->writeit = 0;
	this->qring = new FILE_LINE(26028) batch_packet_s_process*[this->qring_length];
	for(unsigned int i = 0; i < this->qring_length; i++) {
		this->qring[i] = new FILE_LINE(26029) batch_packet_s_process(this->qring_batch_item_length);
		this->qring[i]->used = 0;
	}
	this->hash_find_flag = new FILE_LINE(26030) volatile int[this->qring_batch_item_length];
	this->qring_push_index = 0;
	this->qring_push_index_count = 0;
	this->qring_active_push_item = NULL;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->qringPushCounter = 0;
	this->qringPushCounter_full = 0;
	this->outThreadId = 0;
	this->term_processRtp = false;
	for(int i = 0; i < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS; i++) {
		this->nextThreadId[i] = 0;
		this->next_thread_handle[i] = 0;
		this->hash_thread_data[i].null();
	}
	this->_sync_count = 0;
	vm_pthread_create((string("t2 rtp preprocess ") + (type == hash ? "hash" : "distribute")).c_str(),
			  &this->out_thread_handle, NULL, _ProcessRtpPacket_outThreadFunction, this, __FILE__, __LINE__);
	this->process_rtp_packets_hash_next_threads = opt_process_rtp_packets_hash_next_thread;
	if(type == hash && this->process_rtp_packets_hash_next_threads) {
		for(int i = 0; i < this->process_rtp_packets_hash_next_threads; i++) {
			for(int j = 0; j < opt_process_rtp_packets_hash_next_thread_sem_sync; j++) {
				sem_init(&sem_sync_next_thread[i][j], 0, 0);
			}
			arg_next_thread *arg = new FILE_LINE(26031) arg_next_thread;
			arg->processRtpPacket = this;
			arg->next_thread_id = i + 1;
			vm_pthread_create("hash next",
					  &this->next_thread_handle[i], NULL, _ProcessRtpPacket_nextThreadFunction, arg, __FILE__, __LINE__);
		}
	}
}

ProcessRtpPacket::~ProcessRtpPacket() {
	terminate();
	for(unsigned int i = 0; i < this->qring_length; i++) {
		delete this->qring[i];
	}
	delete [] this->qring;
	delete [] this->hash_find_flag;
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
		 #ifndef FREEBSD
		 pthread_setschedprio(thId, max_prio_for_policy);
		 #else
		 pthread_setprio(thId, max_prio_for_policy);
		 #endif
		 pthread_attr_destroy(&thAttr);
	}
	this->outThreadId = get_unix_tid();
	syslog(LOG_NOTICE, "start ProcessRtpPacket out thread %s/%i", this->type == hash ? "hash" : "distribute", this->outThreadId);
	unsigned int usleepCounter = 0;
	u_int64_t usleepSumTimeForPushBatch = 0;
	while(!this->term_processRtp) {
		if(this->qring[this->readit]->used == 1) {
			batch_packet_s_process *batch = this->qring[this->readit];
			__SYNC_LOCK(this->_sync_count);
			unsigned count = batch->count;
			__SYNC_UNLOCK(this->_sync_count);
			if(is_terminating()) {
				for(unsigned batch_index = 0; batch_index < count; batch_index++) {
					packet_s_process_0 *packetS = batch->batch[batch_index];
					batch->batch[batch_index] = NULL;
					PACKET_S_PROCESS_DESTROY(&packetS);
				}
			} else {
				this->rtp_batch(batch, count);
			}
			#if RQUEUE_SAFE
				__SYNC_NULL(batch->count);
				__SYNC_NULL(batch->used);
				__SYNC_INCR(this->readit, this->qring_length);
			#else
				batch->count = 0;
				batch->used = 0;
				if((this->readit + 1) == this->qring_length) {
					this->readit = 0;
				} else {
					this->readit++;
				}
			#endif
			usleepCounter = 0;
			usleepSumTimeForPushBatch = 0;
		} else {
			if(usleepSumTimeForPushBatch > 500000ull && !is_terminating()) {
				switch(this->type) {
				case hash:
					for(int i = 0; i < process_rtp_packets_distribute_threads_use; i++) {
						processRtpPacketDistribute[i]->push_batch();
					}
					break;
				case distribute:
					if(rtp_threads) {
						extern int num_threads_max;
						if(!opt_t2_boost) {
							for(int i = 0; i < num_threads_max; i++) {
								if(rtp_threads[i].threadId) {
									rtp_threads[i].push_batch();
								}
							}
						} else {
							for(int i = 0; i < num_threads_max; i++) {
								if(rtp_threads[i].threadId) {
									rtp_threads[i].push_thread_buffer(indexThread);
								}
							}
						}
					}
					break;
				}
				usleepSumTimeForPushBatch = 0;
			}
			usleepSumTimeForPushBatch += USLEEP_C(opt_process_rtp_packets_qring_usleep, usleepCounter++);
		}
	}
	return(NULL);
}

void *ProcessRtpPacket::nextThreadFunction(int next_thread_index_plus) {
	this->nextThreadId[next_thread_index_plus - 1] = get_unix_tid();
	syslog(LOG_NOTICE, "start ProcessRtpPacket next thread %s/%i", this->type == hash ? "hash" : "distribute", this->nextThreadId[next_thread_index_plus - 1]);
	int usleepUseconds = 20;
	unsigned int usleepCounter = 0;
	while(!this->term_processRtp) {
		if(opt_process_rtp_packets_hash_next_thread_sem_sync) {
			sem_wait(&sem_sync_next_thread[next_thread_index_plus - 1][0]);
		}
		if(this->term_processRtp) {
			break;
		}
		s_hash_thread_data *hash_thread_data = &this->hash_thread_data[next_thread_index_plus - 1];
		if(hash_thread_data->batch) {
			unsigned batch_index_start = hash_thread_data->start;
			unsigned batch_index_end = hash_thread_data->end;
			unsigned batch_index_skip = hash_thread_data->skip;
			for(unsigned batch_index = batch_index_start; 
			    batch_index < batch_index_end; 
			    batch_index += batch_index_skip) {
				packet_s_process_0 *packetS = hash_thread_data->batch->batch[batch_index];
				packetS->init2_rtp();
				this->find_hash(packetS, false);
				if(packetS->call_info.length > 0) {
					this->hash_find_flag[batch_index] = 1;
				} else {
					PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 30 + next_thread_index_plus - 1);
					this->hash_find_flag[batch_index] = -1;
				}
			}
			hash_thread_data->processing = 0;
			usleepCounter = 0;
			if(opt_process_rtp_packets_hash_next_thread_sem_sync == 2) {
				sem_post(&sem_sync_next_thread[next_thread_index_plus - 1][1]);
			}
		} else {
			USLEEP_C(usleepUseconds, usleepCounter++);
		}
	}
	return(NULL);
}

void ProcessRtpPacket::rtp_batch(batch_packet_s_process *batch, unsigned count) {
	if(type == hash) {
		int _process_rtp_packets_hash_next_threads = this->process_rtp_packets_hash_next_threads;
		int _process_rtp_packets_distribute_threads_use = process_rtp_packets_distribute_threads_use;
		int _find_hash_only_in_next_threads = opt_process_rtp_packets_hash_next_thread_sem_sync == 1 && _process_rtp_packets_hash_next_threads > 1;
		unsigned batch_index_distribute = 0;
		for(unsigned batch_index = 0; batch_index < count; batch_index++) {
			this->hash_find_flag[batch_index] = 0;
		}
		calltable->lock_calls_hash();
		if(this->next_thread_handle[0]) {
			for(int i = 0; i < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS; i++) {
				this->hash_thread_data[i].null();
			}
			for(int i = 0; i < _process_rtp_packets_hash_next_threads; i++) {
				if(_find_hash_only_in_next_threads) {
					this->hash_thread_data[i].start = i;
					this->hash_thread_data[i].end = count;
					this->hash_thread_data[i].skip = _process_rtp_packets_hash_next_threads;
				} else {
					this->hash_thread_data[i].start = count / (_process_rtp_packets_hash_next_threads + 1) * (i + 1);
					this->hash_thread_data[i].end = i == (_process_rtp_packets_hash_next_threads - 1) ? 
									 count : 
									 count / (_process_rtp_packets_hash_next_threads + 1) * (i + 2);
					this->hash_thread_data[i].skip = 1;
				}
				this->hash_thread_data[i].batch = batch;
				this->hash_thread_data[i].processing = 1;
				if(opt_process_rtp_packets_hash_next_thread_sem_sync) {
					sem_post(&sem_sync_next_thread[i][0]);
				}
			}
			if(_find_hash_only_in_next_threads) {
				while(this->hash_thread_data[0].processing || this->hash_thread_data[1].processing ||
				      (_process_rtp_packets_hash_next_threads > 2 && this->isNextThreadsGt2Processing(_process_rtp_packets_hash_next_threads))) {
					if(batch_index_distribute < count &&
					   this->hash_find_flag[batch_index_distribute] != 0) {
						packet_s_process_0 *packetS = batch->batch[batch_index_distribute];
						batch->batch[batch_index_distribute] = NULL;
						if(this->hash_find_flag[batch_index_distribute] == 1) {
							this->rtp_packet_distr(packetS, _process_rtp_packets_distribute_threads_use);
						}
						++batch_index_distribute;
					} else {
						USLEEP(20);
					}
				}
			} else {
				for(unsigned batch_index = 0; 
				    batch_index < count / (_process_rtp_packets_hash_next_threads + 1); 
				    batch_index++) {
					packet_s_process_0 *packetS = batch->batch[batch_index];
					packetS->init2_rtp();
					this->find_hash(packetS, false);
					if(packetS->call_info.length > 0) {
						this->hash_find_flag[batch_index] = 1;
					} else {
						PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 5);
						this->hash_find_flag[batch_index] = -1;
					}
				}
				for(int i = 0; i < _process_rtp_packets_hash_next_threads; i++) {
					if(opt_process_rtp_packets_hash_next_thread_sem_sync == 2) {
						sem_wait(&sem_sync_next_thread[i][1]);
					} else {
						while(this->hash_thread_data[i].processing) { 
							USLEEP(20); 
						}
					}
				}
			}
		} else {
			for(unsigned batch_index = 0; batch_index < count; batch_index++) {
				packet_s_process_0 *packetS = batch->batch[batch_index];
				packetS->init2_rtp();
				this->find_hash(packetS, false);
				if(packetS->call_info.length > 0) {
					this->hash_find_flag[batch_index] = 1;
				} else {
					PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 5);
					this->hash_find_flag[batch_index] = -1;
				}
			}
		}
		calltable->unlock_calls_hash();
		for(;batch_index_distribute < count; batch_index_distribute++) {
			packet_s_process_0 *packetS = batch->batch[batch_index_distribute];
			batch->batch[batch_index_distribute] = NULL;
			if(this->hash_find_flag[batch_index_distribute] == 1) {
				this->rtp_packet_distr(packetS, _process_rtp_packets_distribute_threads_use);
			}
		}
	} else {
		for(unsigned batch_index = 0; batch_index < count; batch_index++) {
			packet_s_process_0 *packetS = batch->batch[batch_index];
			batch->batch[batch_index] = NULL;
			if(packetS->call_info.length < 0) {
				this->find_hash(packetS);
			}
			if(packetS->call_info.length) {
				process_packet__rtp_call_info(&packetS->call_info, packetS, 
							      true,
							      opt_t2_boost ? indexThread + 1 : 0,
							      indexThread + 1);
			} else {
				if(opt_rtpnosip) {
					process_packet__rtp_nosip(packetS->saddr_(), packetS->source_(), packetS->daddr_(), packetS->dest_(), 
								  packetS->data_(), packetS->datalen_(), packetS->dataoffset_(),
								  packetS->header_pt, packetS->packet, packetS->pflags.tcp, packetS->header_ip_(),
								  packetS->block_store, packetS->block_store_index, packetS->dlt, packetS->sensor_id_(), packetS->sensor_ip,
								  get_pcap_handle(packetS->handle_index));
				}
				PACKET_S_PROCESS_PUSH_TO_STACK(&packetS, 40 + indexThread);
			}
		}
	}
}

inline void ProcessRtpPacket::rtp_packet_distr(packet_s_process_0 *packetS, int _process_rtp_packets_distribute_threads_use) {
	packetS->blockstore_addflag(41 /*pb lock flag*/);
	if(opt_t2_boost) {
		if(packetS->call_info.length == 1) {
			packetS->blockstore_addflag(42 /*pb lock flag*/);
			processRtpPacketDistribute[packetS->call_info.calls[0].call->thread_num_rd]->push_packet(packetS);
		} else {
			int threads_rd[MAX_PROCESS_RTP_PACKET_THREADS];
			threads_rd[0] = packetS->call_info.calls[0].call->thread_num_rd;
			int threads_rd_count = 1;
			for(unsigned i = 1; i < packetS->call_info.length; i++) {
				int thread_rd = packetS->call_info.calls[i].call->thread_num_rd;
				if(thread_rd != threads_rd[0]) {
					bool exists = false;
					for(int j = 1; j < threads_rd_count; j++) {
						if(threads_rd[j] == thread_rd) {
							exists = true;
							break;
						}
					}
					if(!exists) {
						threads_rd[threads_rd_count++] = thread_rd;
					}
				}
			}
			packetS->set_use_reuse_counter();
			packetS->reuse_counter_inc_sync(packetS->call_info.length);
			for(int i = 0; i < threads_rd_count; i++) {
				packetS->blockstore_addflag(46 /*pb lock flag*/);
				processRtpPacketDistribute[threads_rd[i]]->push_packet(packetS);
			}
		}
	} else {
		if(packetS->call_info.length > 1) {
			packetS->set_use_reuse_counter();
			packetS->reuse_counter_inc_sync(packetS->call_info.length);
		}
		ProcessRtpPacket *_processRtpPacket = processRtpPacketDistribute[1] ?
						       processRtpPacketDistribute[min(packetS->source_().getPort(), packetS->dest_().getPort()) / 2 % _process_rtp_packets_distribute_threads_use] :
						       processRtpPacketDistribute[0];
		_processRtpPacket->push_packet(packetS);
	}
}

void ProcessRtpPacket::find_hash(packet_s_process_0 *packetS, bool lock) {
	packetS->blockstore_addflag(31 /*pb lock flag*/);
	packetS->call_info.length = 0;
	packetS->call_info.find_by_dest = false;
	if(lock) {
		calltable->lock_calls_hash();
	}
	node_call_rtp *n_call = NULL;
	if((n_call = calltable->hashfind_by_ip_port(packetS->daddr_(), packetS->dest_(), false))) {
		packetS->call_info.find_by_dest = true;
		packetS->blockstore_addflag(32 /*pb lock flag*/);
	} else {
		n_call = calltable->hashfind_by_ip_port(packetS->saddr_(), packetS->source_(), false);
		packetS->blockstore_addflag(33 /*pb lock flag*/);
	}
	packetS->call_info.length = 0;
	#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
	if(n_call && !n_call->empty()) {
	#else
	if(n_call) {
	#endif
		++counter_rtp_packets[0];
		#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
		for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end(); iter++) {
			call_rtp *call_rtp = *iter;
		#else
		for (; n_call != NULL; n_call = n_call->next) {
			call_rtp *call_rtp = n_call;
		#endif
			Call *call = call_rtp->call;
			if(call_confirmation_for_rtp_processing(call, &packetS->call_info, packetS)) {
				++counter_rtp_packets[1];
				packetS->blockstore_addflag(34 /*pb lock flag*/);
				packetS->call_info.calls[packetS->call_info.length].call = call;
				packetS->call_info.calls[packetS->call_info.length].iscaller = call_rtp->iscaller;
				packetS->call_info.calls[packetS->call_info.length].is_rtcp = call_rtp->is_rtcp;
				packetS->call_info.calls[packetS->call_info.length].sdp_flags = call_rtp->sdp_flags;
				if(call->use_rtcp_mux && !packetS->call_info.calls[packetS->call_info.length].sdp_flags.rtcp_mux) {
					s_sdp_flags *sdp_flags_other_side = packetS->call_info.find_by_dest ?
									     calltable->get_sdp_flags_in_hashfind_by_ip_port(call, packetS->saddr_(), packetS->source_(), false) :
									     calltable->get_sdp_flags_in_hashfind_by_ip_port(call, packetS->daddr_(), packetS->dest_(), false);
					if(sdp_flags_other_side && sdp_flags_other_side->rtcp_mux) {
						packetS->call_info.calls[packetS->call_info.length].sdp_flags.rtcp_mux = true;
					}
				}
				packetS->call_info.calls[packetS->call_info.length].use_sync = false;
				packetS->call_info.calls[packetS->call_info.length].multiple_calls = false;
				__sync_add_and_fetch(&call->rtppacketsinqueue, 1);
				++packetS->call_info.length;
				if(packetS->call_info.length >= packet_s_process_calls_info::max_calls()) {
					break;
				}
			}
		}
		if(packetS->call_info.length > 1 && !packetS->audiocodes) {
			for(unsigned i = 0; i < packetS->call_info.length; i++) {
				packetS->call_info.calls[i].multiple_calls = true;
			}
		}
	}
	if(lock) {
		calltable->unlock_calls_hash();
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

double ProcessRtpPacket::getCpuUsagePerc(bool preparePstatData, int nextThreadIndexPlus, double *percFullQring) {
	if(preparePstatData) {
		this->preparePstatData(nextThreadIndexPlus);
	}
	if(nextThreadIndexPlus ? this->nextThreadId[nextThreadIndexPlus - 1] : this->outThreadId) {
		double ucpu_usage, scpu_usage;
		if(this->threadPstatData[nextThreadIndexPlus][0].cpu_total_time && this->threadPstatData[nextThreadIndexPlus][1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&this->threadPstatData[nextThreadIndexPlus][0], &this->threadPstatData[nextThreadIndexPlus][1],
				&ucpu_usage, &scpu_usage);
			if(percFullQring) {
				*percFullQring = qringPushCounter ? 100. * qringPushCounter_full / qringPushCounter : -1;
				qringPushCounter = 0;
				qringPushCounter_full = 0;
			}
			return(ucpu_usage + scpu_usage);
		}
	}
	if(percFullQring) {
		*percFullQring = -1;
		qringPushCounter = 0;
		qringPushCounter_full = 0;
	}
	return(-1);
}

void ProcessRtpPacket::terminate() {
	this->term_processRtp = true;
	if(this->out_thread_handle) {
		pthread_join(this->out_thread_handle, NULL);
		this->out_thread_handle = 0;
	}
	for(int i = 0; i < this->process_rtp_packets_hash_next_threads; i++) {
		if(this->next_thread_handle[i]) {
			if(opt_process_rtp_packets_hash_next_thread_sem_sync) {
				sem_post(&this->sem_sync_next_thread[i][0]);
			}
			pthread_join(this->next_thread_handle[i], NULL);
			this->next_thread_handle[i] = 0;
			for(int j = 0; j < opt_process_rtp_packets_hash_next_thread_sem_sync; j++) {
				sem_destroy(&sem_sync_next_thread[i][j]);
			}
		}
	}
}

void ProcessRtpPacket::autoStartProcessRtpPacket() {
	if(!processRtpPacketHash &&
	   opt_enable_process_rtp_packet && enable_pcap_split &&
	   !is_read_from_file_simple()) {
		process_rtp_packets_distribute_threads_use = opt_enable_process_rtp_packet;
		ProcessRtpPacket *_processRtpPacketHash = new FILE_LINE(26032) ProcessRtpPacket(ProcessRtpPacket::hash, 0);
		for(int i = 0; i < opt_enable_process_rtp_packet; i++) {
			processRtpPacketDistribute[i] = new FILE_LINE(26033) ProcessRtpPacket(ProcessRtpPacket::distribute, i);
		}
		processRtpPacketHash = _processRtpPacketHash;
	}
}

void ProcessRtpPacket::addRtpRhThread() {
	if(this->process_rtp_packets_hash_next_threads < MAX_PROCESS_RTP_PACKET_HASH_NEXT_THREADS) {
		for(int j = 0; j < opt_process_rtp_packets_hash_next_thread_sem_sync; j++) {
			sem_init(&sem_sync_next_thread[this->process_rtp_packets_hash_next_threads][j], 0, 0);
		}
		arg_next_thread *arg = new FILE_LINE(26034) arg_next_thread;
		arg->processRtpPacket = this;
		arg->next_thread_id = this->process_rtp_packets_hash_next_threads + 1;
		vm_pthread_create("hash next",
				  &this->next_thread_handle[this->process_rtp_packets_hash_next_threads], NULL, _ProcessRtpPacket_nextThreadFunction, arg, __FILE__, __LINE__);
		++this->process_rtp_packets_hash_next_threads;
	}
}

void ProcessRtpPacket::addRtpRdThread() {
	if(process_rtp_packets_distribute_threads_use < MAX_PROCESS_RTP_PACKET_THREADS &&
	   !processRtpPacketDistribute[process_rtp_packets_distribute_threads_use]) {
		ProcessRtpPacket *_processRtpPacketDistribute = new FILE_LINE(26035) ProcessRtpPacket(ProcessRtpPacket::distribute, process_rtp_packets_distribute_threads_use);
		processRtpPacketDistribute[process_rtp_packets_distribute_threads_use] = _processRtpPacketDistribute;
		++process_rtp_packets_distribute_threads_use;
	}
}

void rtp_read_thread::init(int threadNum, size_t qring_length) {
	this->threadId = 0;
	this->threadNum = threadNum;
	memset(this->threadPstatData, 0, sizeof(this->threadPstatData));
	this->remove_flag = 0;
	this->last_use_time_s = 0;
	this->calls = 0;
	this->push_lock_sync = 0;
	this->count_lock_sync = 0;
	this->init_qring(qring_length);
	this->init_thread_buffer();
}

void rtp_read_thread::init_qring(size_t qring_length) {
	this->qring_batch_item_length = rtp_qring_batch_length;
	this->qring_length = qring_length / this->qring_batch_item_length;
	this->readit = 0;
	this->writeit = 0;
	this->qring = NULL;
	this->qring_push_index = 0;
	this->qring_push_index_count = 0;
}

void rtp_read_thread::alloc_qring() {
	if(!this->qring) {
		this->qring = new FILE_LINE(26036) batch_packet_rtp*[this->qring_length];
		for(unsigned int i = 0; i < this->qring_length; i++) {
			this->qring[i] = new FILE_LINE(26037) batch_packet_rtp(this->qring_batch_item_length);
			this->qring[i]->used = 0;
		}
	}
}

void rtp_read_thread::init_thread_buffer() {
	thread_buffer_length = 10;
	this->thread_buffer = new FILE_LINE(26038) batch_packet_rtp_thread_buffer*[thread_buffer_length];
	for(unsigned int i = 0; i < thread_buffer_length; i++) {
		this->thread_buffer[i] = new FILE_LINE(26039) batch_packet_rtp_thread_buffer(this->qring_batch_item_length);
	}
	#if DEBUG_QUEUE_RTP_THREAD
	tdd = new FILE_LINE(26040) thread_debug_data[thread_buffer_length];
	memset(tdd, 0, thread_buffer_length * sizeof(thread_debug_data));
	#endif
}

void rtp_read_thread::term() {
	this->term_qring();
	this->term_thread_buffer();
}

void rtp_read_thread::term_qring() {
	if(this->qring) {
		for(unsigned int i = 0; i < this->qring_length; i++) {
			delete this->qring[i];
		}
		delete [] this->qring;
		this->qring = NULL;
	}
}

void rtp_read_thread::term_thread_buffer() {
	for(unsigned int i = 0; i < thread_buffer_length; i++) {
		delete this->thread_buffer[i];
	}
	delete [] this->thread_buffer;
	#if DEBUG_QUEUE_RTP_THREAD
	delete tdd;
	#endif
}

size_t rtp_read_thread::qring_size() {
	return(writeit >= readit ? writeit - readit : writeit + this->qring_length - readit);
}


void trace_call(u_char *packet, unsigned caplen, int pcapLinkHeaderType,
		u_int16_t header_ip_offset, u_int64_t packet_time, 
		u_char *data, unsigned datalen,
		const char *file, unsigned line, const char *function, const char *descr) {
	if(!sverb.trace_call) {
		return;
	}
	if(!data) {
		if(!header_ip_offset) {
			sll_header *header_sll;
			ether_header *header_eth;
			u_int16_t protocol;
			u_int16_t vlan;
			if(!parseEtherHeader(pcapLinkHeaderType, packet,
					     header_sll, header_eth, NULL,
					     header_ip_offset, protocol, vlan)) {
				return;
			}
		}
		iphdr2 *header_ip = (iphdr2*)(packet + header_ip_offset);
		if(header_ip->get_protocol() == IPPROTO_UDP) {
			udphdr2 *header_udp = (udphdr2*)((char*)header_ip + header_ip->get_hdr_size());
			datalen = get_udp_data_len(header_ip, header_udp, (char**)&data, packet, caplen);
		} else if(header_ip->get_protocol() == IPPROTO_TCP) {
			tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
			datalen = get_tcp_data_len(header_ip, header_tcp, (char**)&data, packet, caplen);
		}
		if(!data) {
			return;
		}
	}
	if(datalen > 6 && !strncasecmp((char*)data, "INVITE", 6)) {
		unsigned long callid_length; 
		unsigned long gettagLimitLen = 0;
		char *callid = gettag_ext(data, datalen, NULL,
					  "\nCall-ID:", &callid_length, &gettagLimitLen);
		if(callid && callid_length > 0) {
			ostringstream str;
			str << fixed;
			str << string(callid, callid_length) << " / "
			    << sqlDateString(packet_time / 1000000) << "." 
			    << setw(6) << (packet_time % 1000000) << " / "
			    << (getTimeUS() - packet_time) / 1e3 << " / "
			    << file << ":" << line << " / "
			    << function;
			if(descr) {
				str << " / " << descr;
			}
			static volatile int _sync = 0;
			__SYNC_LOCK(_sync);
			FILE *out_file = fopen(sverb.trace_call, "a");
			if(out_file) {
				fputs((str.str() + "\n").c_str(), out_file);
				fclose(out_file);
			}
			__SYNC_UNLOCK(_sync);
		}
	}
}

void *checkSizeOfLivepacketTables(void */*arg*/) {
	extern int opt_livesniffer_tablesize_max_mb;
	if(!opt_livesniffer_tablesize_max_mb) {
		usersniffer_checksize_sync = 0;
		return(NULL);
	}
	vector<unsigned int> uids;
	while(__sync_lock_test_and_set(&usersniffer_sync, 1)) {};
	for(map<unsigned int, livesnifferfilter_s*>::iterator iter = usersniffer.begin(); iter != usersniffer.end(); iter++) {
		uids.push_back(iter->first);
	}
	__sync_lock_release(&usersniffer_sync);
	if(uids.size()) {
		SqlDb *sqlDb = createSqlObject();
		sqlDb->setDisableLogError(true);
		sqlDb->setMaxQueryPass(1);
		cLogSensor *log = NULL;
		for(unsigned i = 0; i < uids.size(); i++) {
			string livepacketTableName = "livepacket_" + intToString(uids[i]);
			int64_t size = sqlDb->sizeOfTable(livepacketTableName);
			if(size > 0) {
				size /= (1024 * 1024);
				if(size > opt_livesniffer_tablesize_max_mb) {
					while(__sync_lock_test_and_set(&usersniffer_sync, 1)) {};
					if(usersniffer.find(uids[i]) != usersniffer.end()) {
						string kill_reason = "table size limit (in sniffer configuration - " + intToString(opt_livesniffer_tablesize_max_mb) + "MB)";
						if(!log) {
							log = cLogSensor::begin(cLogSensor::notice, "live sniffer", "table size limit - terminate");
						}
						log->log(NULL, "uid: %u, state: %s, reason: %s", uids[i], usersniffer[uids[i]]->getStringState().c_str(), kill_reason.c_str());
						delete usersniffer[uids[i]];
						usersniffer.erase(uids[i]);
						if(!usersniffer.size()) {
							global_livesniffer = 0;
						}
						usersniffer_kill_reason[uids[i]] = kill_reason;
					}
					__sync_lock_release(&usersniffer_sync);
				}
			}
		}
		if(log) {
			log->end();
		}
		delete sqlDb;
	}
	usersniffer_checksize_sync = 0;
	return(NULL);
}
