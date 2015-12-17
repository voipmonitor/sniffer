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
#include "fraud.h"

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
void save_packet(Call *call, packet_s *packetS, ParsePacket *parsePacket, int type,  int forceSip);


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

typedef struct {
	Call *call;
	packet_s packet;
	char iscaller;
	char is_rtcp;
	char save_packet;
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


Call *process_packet(struct packet_s *packetS, void *parsePacketPreproc,
		     int *was_rtp, int *voippacket, int forceSip = 0,
		     bool mainProcess = true, int sipOffset = 0);
inline Call *process_packet(bool is_ssl, u_int64_t packet_number,
			    unsigned int saddr, int source, unsigned int daddr, int dest, 
			    char *data, int datalen, int dataoffset,
			    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, void *parsePacketPreproc,
			    int istcp, int *was_rtp, struct iphdr2 *header_ip, int *voippacket, int forceSip,
			    pcap_block_store *block_store, int block_store_index, int dlt, int sensor_id, 
			    bool mainProcess = true, int sipOffset = 0) {
	packet_s packetS;
	packetS.packet_number = packet_number;
	packetS.saddr = saddr;
	packetS.source = source;
	packetS.daddr = daddr; 
	packetS.dest = dest;
	packetS.data = data; 
	packetS.datalen = datalen; 
	packetS.dataoffset = dataoffset;
	packetS.handle = handle; 
	packetS.header = *header; 
	packetS.packet = packet; 
	packetS.istcp = istcp; 
	packetS.header_ip = header_ip; 
	packetS.block_store = block_store; 
	packetS.block_store_index =  block_store_index; 
	packetS.dlt = dlt; 
	packetS.sensor_id = sensor_id;
	packetS.is_ssl = is_ssl;
	return(process_packet(&packetS, parsePacketPreproc,
			      was_rtp, voippacket, forceSip,
			      mainProcess, sipOffset));
}


#define enable_save_sip(call)		(call->flags & FLAG_SAVESIP)
#define enable_save_register(call)	(call->flags & FLAG_SAVEREGISTER)
#define enable_save_rtcp(call)		((call->flags & FLAG_SAVERTCP) || (call->isfax && opt_saveudptl))
#define enable_save_rtp(call)		((call->flags & (FLAG_SAVERTP | FLAG_SAVERTPHEADER)) || (call->isfax && opt_saveudptl) || opt_saverfc2833)
#define enable_save_sip_rtp(call)	(enable_save_sip(call) || enable_save_rtp(call))
#define enable_save_packet(call)	(enable_save_sip(call) || enable_save_register(call) || enable_save_rtp(call))
#define enable_save_audio(call)		((call->flags & FLAG_SAVEAUDIO) || opt_savewav_force)
#define enable_save_sip_rtp_audio(call)	(enable_save_sip_rtp(call) || enable_save_audio(call))
#define enable_save_any(call)		(enable_save_packet(call) || enable_save_audio(call))


#endif
