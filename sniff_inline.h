#ifndef SNIFF_INLINE_H
#define SNIFF_INLINE_H

#include "pcap_queue.h"
#include "voipmonitor.h"

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_udp_header_len(udphdr2 *header_udp);

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_udp_data_len(iphdr2 *header_ip, udphdr2 *header_udp, char** data, u_char *packet, unsigned caplen);

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_tcp_header_len(tcphdr2 *header_tcp);

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_tcp_data_len(iphdr2 *header_ip, tcphdr2 *header_tcp, char** data, u_char *packet, unsigned caplen);

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_sctp_data_len(iphdr2 *header_ip, char** data, u_char *packet, unsigned caplen);
 
#if SNIFFER_INLINE_FUNCTIONS
inline
#endif
iphdr2 *convertHeaderIP_GRE(iphdr2 *header_ip, unsigned max_len);

#if SNIFFER_INLINE_FUNCTIONS
inline
#endif
bool parseEtherHeader(int pcapLinklayerHeaderType, u_char* packet,
		      sll_header *&header_sll, ether_header *&header_eth, u_char **header_ppp_o_e,
		      u_int16_t &header_ip_offset, u_int16_t &protocol, u_int16_t &vlan);

#if SNIFFER_INLINE_FUNCTIONS
inline
#endif
int findNextHeaderIp(iphdr2 *header_ip, unsigned header_ip_offset, u_char *packet, unsigned caplen, u_int8_t *flags = NULL);

enum pcapProcessFlags {
	ppf_na = 0,
	ppf_defrag = 1, 
	ppf_calcMD5 = 2, 
	ppf_dedup = 4, 
	ppf_dump = 8,
	ppf_returnZeroInCheckData = 16,
	ppf_all = 31,
	ppf_defragInPQout = 32
};

#if SNIFFER_INLINE_FUNCTIONS
inline
#endif
int pcapProcess(sHeaderPacket **header_packet, int pushToStack_queue_index,
		pcap_block_store *block_store, int block_store_index,
		int ppf, 
		pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t *pcapDumpHandle, const char *interfaceName);

#if SNIFFER_INLINE_FUNCTIONS
#include "sniff_inline.cpp"
#endif

#endif

