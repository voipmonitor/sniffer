#ifndef SNIFF_INLINE_C
#define SNIFF_INLINE_C

#include <syslog.h>
#include <net/ethernet.h>

#include "tcpreassembly.h"
#include "sniff.h"
#include "sniff_inline.h"


#ifndef DEBUG_ALL_PACKETS
#define DEBUG_ALL_PACKETS false
#endif

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif


extern int opt_udpfrag;
extern int opt_ipaccount;
extern int opt_skinny;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern TcpReassembly *tcpReassemblyHttp;
extern TcpReassembly *tcpReassemblyWebrtc;
extern unsigned int duplicate_counter;


#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
iphdr2 *convertHeaderIP_GRE(iphdr2 *header_ip) {
	char gre[8];
	uint16_t a, b;
	// if anyone know how to make network to hostbyte nicely, redesign this
	a = ntohs(*(uint16_t*)((char*)header_ip + sizeof(iphdr2)));
	b = ntohs(*(uint16_t*)((char*)header_ip + sizeof(iphdr2) + 2));
	memcpy(gre, &a, 2);
	memcpy(gre + 2, &b, 2);
	struct gre_hdr *grehdr = (struct gre_hdr *)gre;			
	if(grehdr->version == 0 and grehdr->protocol == 0x6558) {
		struct ether_header *header_eth = (struct ether_header *)((char*)header_ip + sizeof(iphdr2) + 8);
		unsigned int vlanoffset;
		int protocol = 0;
		if(header_eth->ether_type == 129) {
			// VLAN tag
			vlanoffset = 4;
			//XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
			protocol = *((char*)header_eth + 2);
		} else {
			vlanoffset = 0;
			protocol = header_eth->ether_type;
		}
		if(protocol == 8) {
			header_ip = (struct iphdr2 *) ((char*)header_eth + sizeof(ether_header) + vlanoffset);
		} else {
			return(NULL);
		}
	} else if(grehdr->version == 0 and grehdr->protocol == 0x800) {
		header_ip = (struct iphdr2 *) ((char*)header_ip + sizeof(iphdr2) + 4);
	} else {
		return(NULL);
	}
	return(header_ip);
}

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
int pcapProcess(pcap_pkthdr** header, u_char** packet, bool *destroy,
		       bool enableDefrag, bool enableCalcMD5, bool enableDedup, bool enableDump,
		       pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t *pcapDumpHandle, const char *interfaceName) {
	*destroy = false;
	switch(pcapLinklayerHeaderType) {
		case DLT_LINUX_SLL:
			ppd->header_sll = (sll_header*)*packet;
			if(ppd->header_sll->sll_protocol == 129) {
				// VLAN tag
				ppd->protocol = htons(*(u_int16_t*)(*packet + sizeof(sll_header) + 2));
				ppd->header_ip_offset = 4;
			} else {
				ppd->header_ip_offset = 0;
				ppd->protocol = htons(ppd->header_sll->sll_protocol);
			}
			ppd->header_ip_offset += sizeof(sll_header);
			break;
		case DLT_EN10MB:
			ppd->header_eth = (ether_header *)*packet;
			if(ppd->header_eth->ether_type == 129) {
				// VLAN tag
				ppd->header_ip_offset = 4;
				//XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
				ppd->protocol = htons(*(u_int16_t*)(*packet + sizeof(ether_header) + 2));
			} else {
				ppd->header_ip_offset = 0;
				ppd->protocol = htons(ppd->header_eth->ether_type);
			}
			ppd->header_ip_offset += sizeof(ether_header);
			break;
		case DLT_RAW:
			ppd->header_ip_offset = 0;
			ppd->protocol = ETHERTYPE_IP;
			break;
		case DLT_IEEE802_11_RADIO:
			ppd->header_ip_offset = 52;
			ppd->protocol = ETHERTYPE_IP;
			break;
		case DLT_NULL:
			ppd->header_ip_offset = 4;
			ppd->protocol = ETHERTYPE_IP;
			break;
		default:
			syslog(LOG_ERR, "BAD DATALINK %s: datalink number [%d] is not supported", interfaceName, pcapLinklayerHeaderType);
			return(0);
	}
	
	if(ppd->protocol != ETHERTYPE_IP) {
		#if TCPREPLAY_WORKARROUND
		if(ppd->protocol == 0) {
			ppd->header_ip_offset += 2;
			ppd->protocol = ETHERTYPE_IP;
		} else 
		#endif
		{
			// not ipv4 
			return(0);
		}
	}
	
	ppd->header_ip = (iphdr2*)(*packet + ppd->header_ip_offset);

	extern BogusDumper *bogusDumper;
	static u_long lastTimeLogErrBadIpHeader = 0;
	if(ppd->header_ip->version != 4) {
		if(bogusDumper) {
			bogusDumper->dump(*header, *packet, pcapLinklayerHeaderType, interfaceName);
		}
		u_long actTime = getTimeMS(*header);
		if(actTime - 1000 > lastTimeLogErrBadIpHeader) {
			syslog(LOG_ERR, "BAD HEADER_IP: %s: bogus ip header version %i", interfaceName, ppd->header_ip->version);
			lastTimeLogErrBadIpHeader = actTime;
		}
		return(0);
	}
	if(htons(ppd->header_ip->tot_len) + ppd->header_ip_offset > (*header)->len) {
		if(bogusDumper) {
			bogusDumper->dump(*header, *packet, pcapLinklayerHeaderType, interfaceName);
		}
		u_long actTime = getTimeMS(*header);
		if(actTime - 1000 > lastTimeLogErrBadIpHeader) {
			syslog(LOG_ERR, "BAD HEADER_IP: %s: bogus ip header length %i, len %i", interfaceName, htons(ppd->header_ip->tot_len), (*header)->len);
			lastTimeLogErrBadIpHeader = actTime;
		}
		return(0);
	}
	
	if(enableDefrag) {
		//if UDP defrag is enabled process only UDP packets and only SIP packets
		if(opt_udpfrag && (ppd->header_ip->protocol == IPPROTO_UDP || ppd->header_ip->protocol == 4)) {
			int foffset = ntohs(ppd->header_ip->frag_off);
			if ((foffset & IP_MF) || ((foffset & IP_OFFSET) > 0)) {
				if(htons(ppd->header_ip->tot_len) + ppd->header_ip_offset > (*header)->caplen) {
					if(bogusDumper) {
						bogusDumper->dump(*header, *packet, pcapLinklayerHeaderType, interfaceName);
					}
					u_long actTime = getTimeMS(*header);
					if(actTime - 1000 > lastTimeLogErrBadIpHeader) {
						syslog(LOG_ERR, "BAD FRAGMENTED HEADER_IP: %s: bogus ip header length %i, caplen %i", interfaceName, htons(ppd->header_ip->tot_len), (*header)->caplen);
						lastTimeLogErrBadIpHeader = actTime;
					}
					return(0);
				}
				// packet is fragmented
				if(handle_defrag(ppd->header_ip, header, packet, 0, &ppd->ipfrag_data)) {
					// packets are reassembled
					ppd->header_ip = (iphdr2*)(*packet + ppd->header_ip_offset);
					*destroy = true;
				} else {
					return(0);
				}
			}
		}
	}
	
	bool nextPass;
	do {
		nextPass = false;
		if(ppd->header_ip->protocol == IPPROTO_IPIP) {
			// ip in ip protocol
			ppd->header_ip = (iphdr2*)((char*)ppd->header_ip + sizeof(iphdr2));
			
			if(enableDefrag) {
				//if UDP defrag is enabled process only UDP packets and only SIP packets
				if(opt_udpfrag && ppd->header_ip->protocol == IPPROTO_UDP) {
					int foffset = ntohs(ppd->header_ip->frag_off);
					if ((foffset & IP_MF) || ((foffset & IP_OFFSET) > 0)) {
						// packet is fragmented
						pcap_pkthdr* header_old = *header;
						u_char* packet_old = *packet;
						if(handle_defrag(ppd->header_ip, header, packet, 0, &ppd->ipfrag_data)) {
							// packet was returned
							iphdr2 *header_ip_1 = (iphdr2*)(*packet + ppd->header_ip_offset);

							// turn off frag flag in the first IP header
							header_ip_1->frag_off = 0;

							// turn off frag flag in the second IP header
							ppd->header_ip = (iphdr2*)((char*)header_ip_1 + sizeof(iphdr2));
							ppd->header_ip->frag_off = 0;

							// update lenght of the first ip header to the len of the second IP header since it can be changed due to reassemble
							header_ip_1->tot_len = htons((ntohs(ppd->header_ip->tot_len)) + sizeof(iphdr2));

							if(*destroy) {
								free(header_old);
								free(packet_old);
							}
							*destroy = true;
						} else {
							return(0);
						}
					}
				}
			}
			
		} else if(ppd->header_ip->protocol == IPPROTO_GRE) {
			// gre protocol
			iphdr2 *header_ip = convertHeaderIP_GRE(ppd->header_ip);
			ppd->header_ip_offset = (u_char*)header_ip - *packet;
			if(header_ip) {
				ppd->header_ip = header_ip;
				nextPass = true;
			} else {
				if(opt_ipaccount == 0) {
					return(0);
				}
			}
		}
	} while(nextPass);
                                               
	if(enableDefrag) {
		// if IP defrag is enabled, run each 10 seconds cleaning 
		if(opt_udpfrag && (ppd->ipfrag_lastprune + 10) < (*header)->ts.tv_sec) {
			ipfrag_prune((*header)->ts.tv_sec, 0, &ppd->ipfrag_data);
			ppd->ipfrag_lastprune = (*header)->ts.tv_sec;
			//TODO it would be good to still pass fragmented packets even it does not contain the last semant, the ipgrad_prune just wipes all unfinished frags
		}
	}

	ppd->header_udp = &ppd->header_udp_tmp;
	if (ppd->header_ip->protocol == IPPROTO_UDP) {
		// prepare packet pointers 
		ppd->header_udp = (udphdr2*) ((char*) ppd->header_ip + sizeof(*ppd->header_ip));
		ppd->data = (char*) ppd->header_udp + sizeof(*ppd->header_udp);
		ppd->datalen = (int)((*header)->caplen - ((unsigned long) ppd->data - (unsigned long) *packet)); 
		ppd->traillen = (int)((*header)->caplen - ((unsigned long) ppd->header_ip - (unsigned long) *packet)) - ntohs(ppd->header_ip->tot_len);
		ppd->istcp = 0;
	} else if (ppd->header_ip->protocol == IPPROTO_TCP) {
		ppd->istcp = 1;
		// prepare packet pointers 
		ppd->header_tcp = (tcphdr2*) ((char*) ppd->header_ip + sizeof(*ppd->header_ip));
		ppd->data = (char*) ppd->header_tcp + (ppd->header_tcp->doff * 4);
		ppd->datalen = (int)((*header)->caplen - ((unsigned long) ppd->data - (unsigned long) *packet)); 
		if (!(sipportmatrix[htons(ppd->header_tcp->source)] || sipportmatrix[htons(ppd->header_tcp->dest)]) &&
		    !(opt_enable_http && (httpportmatrix[htons(ppd->header_tcp->source)] || httpportmatrix[htons(ppd->header_tcp->dest)]) &&
		      (tcpReassemblyHttp->check_ip(htonl(ppd->header_ip->saddr)) || tcpReassemblyHttp->check_ip(htonl(ppd->header_ip->daddr)))) &&
		    !(opt_enable_webrtc && (webrtcportmatrix[htons(ppd->header_tcp->source)] || webrtcportmatrix[htons(ppd->header_tcp->dest)]) &&
		      (tcpReassemblyWebrtc->check_ip(htonl(ppd->header_ip->saddr)) || tcpReassemblyWebrtc->check_ip(htonl(ppd->header_ip->daddr)))) &&
		    !(opt_skinny && (htons(ppd->header_tcp->source) == 2000 || htons(ppd->header_tcp->dest) == 2000))) {
			// not interested in TCP packet other than SIP port
			if(opt_ipaccount == 0 && !DEBUG_ALL_PACKETS) {
				return(0);
			}
		}

		ppd->header_udp->source = ppd->header_tcp->source;
		ppd->header_udp->dest = ppd->header_tcp->dest;
	} else {
		//packet is not UDP and is not TCP, we are not interested, go to the next packet (but if ipaccount is enabled, do not skip IP
		if(opt_ipaccount == 0 && !DEBUG_ALL_PACKETS) {
			return(0);
		}
	}

	if(ppd->datalen < 0) {
		return(0);
	}

	if(enableCalcMD5 || enableDedup) {
		/* check for duplicate packets (md5 is expensive operation - enable only if you really need it */
		if(ppd->datalen > 0 && opt_dup_check && ppd->prevmd5s != NULL && (ppd->traillen < ppd->datalen) &&
		   !(ppd->istcp && opt_enable_http && (httpportmatrix[htons(ppd->header_tcp->source)] || httpportmatrix[htons(ppd->header_tcp->dest)])) &&
		   !(ppd->istcp && opt_enable_webrtc && (webrtcportmatrix[htons(ppd->header_tcp->source)] || webrtcportmatrix[htons(ppd->header_tcp->dest)]))) {
			if(enableCalcMD5) {
				MD5_Init(&ppd->ctx);
				if(opt_dup_check_ipheader) {
					// check duplicates based on full ip header and data 
					MD5_Update(&ppd->ctx, ppd->header_ip, MIN(ppd->datalen - ((char*)ppd->header_ip - ppd->data), ntohs(ppd->header_ip->tot_len)));
				} else {
					// check duplicates based only on data (without ip header and without UDP/TCP header). Duplicate packets 
					// will be matched regardless on IP 
					MD5_Update(&ppd->ctx, ppd->data, MAX(0, (unsigned long)ppd->datalen - ppd->traillen));
				}
				MD5_Final((unsigned char*)ppd->md5, &ppd->ctx);
			}
			if(enableDedup && ppd->md5[0]) {
				if(memcmp(ppd->md5, ppd->prevmd5s + (*ppd->md5 * MD5_DIGEST_LENGTH), MD5_DIGEST_LENGTH) == 0) {
					//printf("dropping duplicate md5[%s]\n", md5);
					duplicate_counter++;
					return(0);
				}
				memcpy(ppd->prevmd5s+(*ppd->md5 * MD5_DIGEST_LENGTH), ppd->md5, MD5_DIGEST_LENGTH);
			}
		}
	}
	
	if(enableDump) {
		if(pcapDumpHandle) {
			pcap_dump((u_char*)pcapDumpHandle, *header, *packet);
		}
	}
	
	return(1);
}

#endif
