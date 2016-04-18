#ifndef SNIFF_INLINE_H
#define SNIFF_INLINE_H

#include "pcap_queue.h"
#include "voipmonitor.h"

#if SNIFFER_INLINE_FUNCTIONS
inline
#endif
iphdr2 *convertHeaderIP_GRE(iphdr2 *header_ip);

#if SNIFFER_INLINE_FUNCTIONS
inline
#endif
bool parseEtherHeader(int pcapLinklayerHeaderType, u_char* packet,
		      sll_header *&header_sll, ether_header *&header_eth, u_int &header_ip_offset, int &protocol, int *vlan = NULL);

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

