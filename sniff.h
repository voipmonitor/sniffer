/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#ifndef SNIFF_H
#define SNIFF_H

#include <queue>
#include <map>
#include <semaphore.h>

#include "rqueue.h"
#include "voipmonitor.h"
#include "calltable.h"
#include "pcap_queue_block.h"

#ifdef FREEBSD
#include <machine/endian.h>
#else
#include "asm/byteorder.h"
#endif

#define RTP_FIXED_HEADERLEN 12

#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

struct iphdr2 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl:4;
	unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif 
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
	/*The options start here. */
#ifdef PACKED
} __attribute__((packed));
#else
};
#endif

void *rtp_read_thread_func(void *arg);

void readdump_libnids(pcap_t *handle);
void readdump_libpcap(pcap_t *handle);
void save_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet, 
		 unsigned int saddr, int source, unsigned int daddr, int dest, 
		 int istcp, iphdr2 *header_ip, char *data, unsigned int datalen, unsigned int dataoffset, int type, 
		 int forceSip, int dlt, int sensor_id);


typedef std::map<in_addr_t, in_addr_t> nat_aliases_t; //!< 


/* this is copied from libpcap sll.h header file, which is not included in debian distribution */
#define SLL_ADDRLEN       8               /* length of address field */
struct sll_header {
	u_int16_t sll_pkttype;          /* packet type */
	u_int16_t sll_hatype;           /* link-layer address type */
	u_int16_t sll_halen;            /* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
	u_int16_t sll_protocol;         /* protocol */
};

struct udphdr2 {
        uint16_t        source;
        uint16_t        dest;
        uint16_t        len;
        uint16_t        check;
};

typedef struct {
	Call *call;
	u_int32_t saddr;
	u_int32_t daddr;
	unsigned short sport;
	unsigned short dport;
	char iscaller;
	char is_rtcp;
	int dlt;
	int sensor_id;
	char save_packet;
	const u_char *packet;
	char istcp;
	u_char *data;
	int datalen;
	int dataoffset;
	struct pcap_pkthdr header;
	pcap_block_store *block_store;
	int block_store_index;
} rtp_packet_pcap_queue;

struct rtp_read_thread {
	rtp_read_thread()  {
		this->rtpp_queue = NULL;
		this->rtpp_queue_quick = NULL;
		this->rtpp_queue_quick_boost = NULL;
	}
	pthread_t thread;	       // ID of worker storing CDR thread 
	rqueue<rtp_packet_pcap_queue> *rtpp_queue;
	rqueue_quick<rtp_packet_pcap_queue> *rtpp_queue_quick;
	rqueue_quick_boost<rtp_packet_pcap_queue> *rtpp_queue_quick_boost;
};

#define MAXLIVEFILTERS 10
#define MAXLIVEFILTERSCHARS 32

typedef struct livesnifferfilter_s {
	struct state_s {
		bool all_saddr;
		bool all_daddr;
		bool all_bothaddr;
		bool all_addr;
		bool all_srcnum;
		bool all_dstnum;
		bool all_bothnum;
		bool all_num;
		bool all_siptypes;
		bool all_all;
	};
        unsigned int lv_saddr[MAXLIVEFILTERS];
        unsigned int lv_daddr[MAXLIVEFILTERS];
	unsigned int lv_bothaddr[MAXLIVEFILTERS];
        char lv_srcnum[MAXLIVEFILTERS][MAXLIVEFILTERSCHARS];
        char lv_dstnum[MAXLIVEFILTERS][MAXLIVEFILTERSCHARS];
	char lv_bothnum[MAXLIVEFILTERS][MAXLIVEFILTERSCHARS];
	unsigned char lv_siptypes[MAXLIVEFILTERS];
        int uid;
        time_t created_at;
	state_s state;
	void updateState();
	string getStringState();
} livesnifferfilter_t;

struct livesnifferfilter_use_siptypes_s {
	bool u_invite;
	bool u_register;
	bool u_options;
	bool u_subscribe;
	bool u_message;
	bool u_notify;
};

struct gre_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
#ifdef FREEBSD
        u_int16_t rec:3,
#else
        __u16   rec:3,
#endif
                srr:1,
                seq:1,
                key:1,
                routing:1,
                csum:1,
                version:3,
                reserved:4,
                ack:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
#ifdef FREEBSD
        u_int16_t   csum:1,
#else
	__u16   csum:1,
#endif
                routing:1,
                key:1,
                seq:1,
                srr:1,
                rec:3,
                ack:1,
                reserved:4,
                version:3;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
#ifdef FREEBSD
        u_int16_t  protocol;
#else
	__be16	protocol;
#endif
};


#define MAX_TCPSTREAMS 1024

class TcpReassemblySip {
public:
	struct tcp_stream_packet {
		u_int64_t packet_number;
		u_int32_t saddr;
		u_int16_t source; 
		u_int32_t daddr;
		u_int16_t dest;
		char *data;
		int datalen;
		int dataoffset;
		pcap_pkthdr header;
		u_char *packet;
		iphdr2 *header_ip;
		pcap_t *handle;
		int dlt; 
		int sensor_id;
		time_t ts;
		u_int32_t seq;
		u_int32_t next_seq;
		u_int32_t ack_seq;
		tcp_stream_packet *next;
		int lastpsh;
	};
	struct tcp_stream {
		tcp_stream() {
			packets = NULL;
			complete_data = NULL;
			last_ts = 0;
			last_seq = 0;
			last_ack_seq = 0;
		}
		tcp_stream_packet* packets;
		SimpleBuffer* complete_data;
		time_t last_ts;
		u_int32_t last_seq;
		u_int32_t last_ack_seq;
	};
	struct tcp_stream_id {
		tcp_stream_id(u_int32_t saddr = 0, u_int16_t source = 0, 
			      u_int32_t daddr = 0, u_int16_t dest = 0) {
			this->saddr = saddr;
			this->source = source;
			this->daddr = daddr; 
			this->dest = dest;
		}
		u_int32_t saddr;
		u_int16_t source;
		u_int32_t daddr;
		u_int16_t dest;
		bool operator < (const tcp_stream_id& other) const {
			return((this->saddr < other.saddr) ? 1 : (this->saddr > other.saddr) ? 0 :
			       (this->source < other.source) ? 1 : (this->source > other.source) ? 0 :
			       (this->daddr < other.daddr) ? 1 : (this->daddr > other.daddr) ? 0 :
			       (this->dest < other.dest));
		}
	};
public:
	void processPacket(
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id,
		bool issip);
	void clean(time_t ts = 0);
private:
	bool addPacket(
		tcp_stream *stream,
		u_int64_t packet_number,
		unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen, int dataoffset,
		pcap_t *handle, pcap_pkthdr header, const u_char *packet, struct iphdr2 *header_ip,
		int dlt, int sensor_id);
	void complete(
		tcp_stream *stream, tcp_stream_id id);
	tcp_stream_packet *getLastStreamPacket(tcp_stream *stream) {
		if(!stream->packets) {
			return(NULL);
		}
		tcp_stream_packet *packet = stream->packets;
		while(packet->next) {
			packet = packet->next;
		}
		return(packet);
	}
	bool isCompleteStream(tcp_stream *stream) {
		if(!stream->packets) {
			return(false);
		}
		int data_len;
		u_char *data;
		if(stream->complete_data) {
			data_len = stream->complete_data->size();
			data = stream->complete_data->data();
		} else {
			data_len = stream->packets->datalen;
			data = (u_char*)stream->packets->data;
		}
		while(data_len > 0) {
			u_char *endHeaderSepPos = (u_char*)memmem(data, data_len, "\r\n\r\n", 4);
			if(endHeaderSepPos) {
				*endHeaderSepPos = 0;
				char *contentLengthPos = strcasestr((char*)data, "Content-Length: ");
				*endHeaderSepPos = '\r';
				unsigned int contentLength = 0;
				if(contentLengthPos) {
					contentLength = atol(contentLengthPos + 16);
				}
				int sipDataLen = (endHeaderSepPos - data) + 4 + contentLength;
				extern int check_sip20(char *data, unsigned long len);
				if(sipDataLen == data_len) {
					return(true);
				} else if(sipDataLen < data_len) {
					if(!check_sip20((char*)(data + sipDataLen), data_len - sipDataLen)) {
						return(true);
					} else {
						data += sipDataLen;
						data_len -= sipDataLen;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		}
		return(false);
	}
	void cleanStream(tcp_stream *stream, bool deletePackets);
private:
	map<tcp_stream_id, tcp_stream> tcp_streams;
};


class PreProcessPacket {
public:
	enum eTypePreProcessThread {
		ppt_detach,
		ppt_sip
	};
	struct packet_s {
		u_int64_t packet_number;
		unsigned int saddr;
		int source; 
		unsigned int daddr; 
		int dest;
		char *data; 
		int datalen; 
		int dataoffset;
		pcap_t *handle; 
		pcap_pkthdr header; 
		const u_char *packet; 
		int istcp; 
		struct iphdr2 *header_ip; 
		pcap_block_store *block_store; 
		int block_store_index; 
		int dlt; 
		int sensor_id;
		bool is_ssl;
	};
	struct packet_parse_s {
		packet_parse_s() {
			init();
		}
		void init() {
			sip_method = -1;
			sip_response = false;
			lastSIPresponseNum = -1;
			call_cancel_lsr487 = false;
			call = NULL;
			call_created = NULL;
			detectUserAgent = false;
			_getCallID_reassembly = false;
			_getSipMethod = false;
			_getLastSipResponse = false;
			_findCall = false;
			_createCall = false;
		}
		packet_s packet;
		bool packetDelete;
		int forceSip;
		ParsePacket parse;
		u_int32_t sipDataLen;
		bool isSip;
		string callid;
		int sip_method;
		bool sip_response;
		int lastSIPresponseNum;
		string lastSIPresponse;
		bool call_cancel_lsr487;
		Call *call;
		Call *call_created;
		bool detectUserAgent;
		bool _getCallID_reassembly;
		bool _getSipMethod;
		bool _getLastSipResponse;
		bool _findCall;
		bool _createCall;
		unsigned int hash[2];
		volatile int used;
	};
public:
	PreProcessPacket(eTypePreProcessThread typePreProcessThread);
	~PreProcessPacket();
	void push(bool is_ssl, u_int64_t packet_number,
		  unsigned int saddr, int source, unsigned int daddr, int dest, 
		  char *data, int datalen, int dataoffset,
		  pcap_t *handle, pcap_pkthdr *header, const u_char *packet, bool packetDelete,
		  int istcp, struct iphdr2 *header_ip, int forceSip,
		  pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
		  bool disableLock = false);
	void push(packet_s *packetS, bool packetDelete = false, int forceSip = 0, bool disableLock = false);
	void preparePstatData();
	double getCpuUsagePerc(bool preparePstatData);
	void terminate();
private:
	bool sipProcess(packet_parse_s *parse_packet);
	bool sipProcess_getCallID(packet_parse_s *parse_packet);
	bool sipProcess_reassembly(packet_parse_s *parse_packet);
	void sipProcess_getSipMethod(packet_parse_s *parse_packet);
	void sipProcess_getLastSipResponse(packet_parse_s *parse_packet);
	void sipProcess_findCall(packet_parse_s *parse_packet);
	void sipProcess_createCall(packet_parse_s *parse_packet);
	void *outThreadFunction();
	void lock_push() {
		while(__sync_lock_test_and_set(&this->_sync_push, 1)) {
			usleep(10);
		}
	}
	void unlock_push() {
		__sync_lock_release(&this->_sync_push);
	}
private:
	eTypePreProcessThread typePreProcessThread;
	packet_parse_s **qring;
	unsigned int qringmax;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pstat_data threadPstatData[2];
	int outThreadId;
	volatile int _sync_push;
	bool term_preProcess;
friend inline void *_PreProcessPacket_outThreadFunction(void *arg);
};


class ProcessRtpPacket {
public:
	enum eType {
		hash,
		distribute
	};
public:
	struct rtp_call_info {
		Call *call;
		bool iscaller;
		bool is_rtcp;
		s_sdp_flags sdp_flags;
		bool use_sync;
	};
	struct packet_s {
		unsigned int saddr;
		int source; 
		unsigned int daddr; 
		int dest;
		char *data; 
		int datalen; 
		int dataoffset;
		pcap_t *handle;
		pcap_pkthdr header; 
		const u_char *packet; 
		int istcp;
		struct iphdr2 *header_ip; 
		pcap_block_store *block_store; 
		int block_store_index; 
		int dlt; 
		int sensor_id;
		unsigned int hash_s;
		unsigned int hash_d;
		rtp_call_info call_info[20];
		int call_info_length;
		bool call_info_find_by_dest;
		volatile int used;
	};
public:
	ProcessRtpPacket(eType type, int indexThread);
	~ProcessRtpPacket();
	void push(unsigned int saddr, int source, unsigned int daddr, int dest, 
		  char *data, int datalen, int dataoffset,
		  pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int istcp, struct iphdr2 *header_ip,
		  pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id,
		  unsigned int hash_s, unsigned int hash_d);
	void push(packet_s *_packet);
	void preparePstatData(bool nextThread = false);
	double getCpuUsagePerc(bool preparePstatData, bool nextThread = false);
	void terminate();
	static void autoStartProcessRtpPacket();
private:
	void *outThreadFunction();
	void *nextThreadFunction();
	void rtp(packet_s *_packet);
	void find_hash(packet_s *_packet, bool lock = true);
	packet_s *qring_item(size_t index) {
		index += this->readit;
		if(index >= qringmax) {
			index -= qringmax;
		}
		return(&qring[index]);
	}
	size_t qring_size() {
		unsigned int _writeit = writeit;
		unsigned int _readit = readit;
		return(_writeit > _readit ?
			_writeit - _readit: 
		       _writeit < _readit ?
			_writeit - 1 + qringmax - _readit :
			(qring[_readit].used ? qringmax : 0));
	}
	
public:
	#if RTP_PROF
	volatile unsigned long long __prof__ProcessRtpPacket_outThreadFunction_begin;
	volatile unsigned long long __prof__ProcessRtpPacket_outThreadFunction;
	volatile unsigned long long __prof__ProcessRtpPacket_outThreadFunction__usleep;
	volatile unsigned long long __prof__ProcessRtpPacket_rtp;
	volatile unsigned long long __prof__ProcessRtpPacket_rtp__hashfind;
	volatile unsigned long long __prof__ProcessRtpPacket_rtp__fill_call_array;
	volatile unsigned long long __prof__process_packet__rtp;
	volatile unsigned long long __prof__add_to_rtp_thread_queue;
	#endif
	eType type;
	int indexThread;
	int outThreadId;
	int nextThreadId;
private:
	packet_s *qring;
	unsigned int qringmax;
	unsigned int hash_blob_limit;
	volatile unsigned int readit;
	volatile unsigned int writeit;
	pthread_t out_thread_handle;
	pthread_t next_thread_handle;
	pstat_data threadPstatData[2][2];
	bool term_processRtp;
	volatile int hash_buffer_next_thread_process;
	volatile unsigned int hash_blob_size;
	sem_t sem_sync_next_thread[2];
friend inline void *_ProcessRtpPacket_outThreadFunction(void *arg);
friend inline void *_ProcessRtpPacket_nextThreadFunction(void *arg);
};


Call *process_packet(bool is_ssl, u_int64_t packet_number,
		     unsigned int saddr, int source, unsigned int daddr, int dest, 
		     char *data, int datalen, int dataoffset,
		     pcap_t *handle, pcap_pkthdr *header, const u_char *packet, 
		     int istcp, int *was_rtp, struct iphdr2 *header_ip, int *voippacket, int forceSip,
		     pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id, 
		     bool mainProcess = true, int sipOffset = 0,
		     PreProcessPacket::packet_parse_s *parsePacket = NULL);
Call *process_packet(PreProcessPacket::packet_s *packetS,
		     int *was_rtp, int *voippacket, int forceSip = 0,
		     bool mainProcess = true, int sipOffset = 0,
		     PreProcessPacket::packet_parse_s *parsePacket = NULL);


#define enable_save_sip(call)		(call->flags & FLAG_SAVESIP)
#define enable_save_register(call)	(call->flags & FLAG_SAVEREGISTER)
#define enable_save_rtcp(call)		((call->flags & (FLAG_SAVERTP | FLAG_SAVERTPHEADER)) || (call->isfax && opt_saveudptl))
#define enable_save_rtp(call)		((call->flags & (FLAG_SAVERTP | FLAG_SAVERTPHEADER)) || (call->isfax && opt_saveudptl) || opt_saverfc2833)
#define enable_save_sip_rtp(call)	(enable_save_sip(call) || enable_save_rtp(call))
#define enable_save_packet(call)	(enable_save_sip(call) || enable_save_register(call) || enable_save_rtp(call))
#define enable_save_audio(call)		((call->flags & FLAG_SAVEAUDIO) || opt_savewav_force)
#define enable_save_sip_rtp_audio(call)	(enable_save_sip_rtp(call) || enable_save_audio(call))
#define enable_save_any(call)		(enable_save_packet(call) || enable_save_audio(call))


#endif
