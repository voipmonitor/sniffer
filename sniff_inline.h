#ifndef SNIFF_INLINE_H
#define SNIFF_INLINE_H


#include "pcap_queue.h"

#if SNIFFER_INLINE_FUNCTIONS
#include "sniff_inline.cpp"
#else
iphdr2 *convertHeaderIP_GRE(iphdr2 *header_ip);
int pcapProcess(pcap_pkthdr** header, u_char** packet, bool *destroy,
		bool enableDefrag, bool enableCalcMD5, bool enableDedup, bool enableDump,
		pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t *pcapDumpHandle, const char *interfaceName);
#endif


#endif