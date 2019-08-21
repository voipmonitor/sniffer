#ifndef SNIFF_INLINE_C
#define SNIFF_INLINE_C

#include "voipmonitor.h"

#ifdef FREEBSD
#include <sys/types.h>
#endif

#include <syslog.h>
#include <net/ethernet.h>
#include <iomanip>

#include "tcpreassembly.h"
#include "sniff.h"
#include "sniff_inline.h"
#include "audiocodes.h"


#ifndef DEBUG_ALL_PACKETS
#define DEBUG_ALL_PACKETS false
#endif

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif


extern bool isSslIpPort(vmIP ip, vmPort port);


extern int opt_udpfrag;
extern int opt_ipaccount;
extern int opt_skinny;
extern int opt_mgcp;
extern unsigned opt_tcp_port_mgcp_gateway;
extern unsigned opt_udp_port_mgcp_gateway;
extern unsigned opt_tcp_port_mgcp_callagent;
extern unsigned opt_udp_port_mgcp_callagent;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern int opt_dup_check_ipheader_ignore_ttl;
extern char *sipportmatrix;
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern char *skinnyportmatrix;
extern TcpReassembly *tcpReassemblyHttp;
extern TcpReassembly *tcpReassemblyWebrtc;
extern unsigned int defrag_counter;
extern unsigned int duplicate_counter;


#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_udp_data_len(iphdr2 *header_ip, udphdr2 *header_udp, char** data, u_char *packet, unsigned caplen) {
	*data = (char*)header_udp + sizeof(udphdr2);
	return(MIN((unsigned)(header_ip->get_tot_len() - header_ip->get_hdr_size() - sizeof(udphdr2)), 
	       MIN((unsigned)(htons(header_udp->len) - sizeof(udphdr2)),
		   (unsigned)(caplen - ((u_char*)*data - packet)))));
}

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_tcp_data_len(iphdr2 *header_ip, tcphdr2 *header_tcp, char** data, u_char *packet, unsigned caplen) {
	*data = (char*)header_tcp + (header_tcp->doff * 4);
	return(MIN((unsigned)(header_ip->get_tot_len() - header_ip->get_hdr_size() - header_tcp->doff * 4), 
		   (unsigned)(caplen - ((u_char*)*data - packet))));
}

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
unsigned get_sctp_data_len(iphdr2 *header_ip, char** data, u_char *packet, unsigned caplen) {
	unsigned sizeOfSctpHeader = 12;
	*data = (char*)header_ip + header_ip->get_hdr_size() + sizeOfSctpHeader;
	return(MIN((unsigned)(header_ip->get_tot_len() - header_ip->get_hdr_size() - sizeOfSctpHeader), 
		   (unsigned)(caplen - ((u_char*)*data - packet))));
}

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
iphdr2 *convertHeaderIP_GRE(iphdr2 *header_ip) {
	gre_hdr *grehdr = (gre_hdr*)((char*)header_ip + header_ip->get_hdr_size());
	u_int16_t grehdr_protocol = ntohs(grehdr->protocol);
	if(grehdr->version == 0 && (grehdr_protocol == 0x6558 || grehdr_protocol == 0x88BE)) {
		// 0x6558 - GRE          - header size 8 bytes
		// 0x88BE - GRE & ERSPAN - headers size 4 bytes (GRE ERSPAN) 
		//                         + 4 (if seq - sequence number) 
		//                         + 4 (if key - key) 
		//                         + 8 (if seq - Encapsulated Remote Switch Packet ANalysis)
		struct ether_header *header_eth = (struct ether_header *)((char*)header_ip + header_ip->get_hdr_size() + 
						  (grehdr_protocol == 0x6558 ? 8 :
						   grehdr_protocol == 0x88BE ? (4 + 
										(grehdr->seq ? 4 : 0) + 
										(grehdr->key ? 4 : 0) + 
										(grehdr->seq ? 8 : 0)) :
									       8));
		unsigned int vlanoffset;
		u_int16_t protocol = 0;
		if(header_eth->ether_type == 129) {
			// VLAN tag
			vlanoffset = 0;
			do {
				protocol = *(u_int16_t*)((char*)header_eth + sizeof(ether_header) + vlanoffset + 2);
				vlanoffset += 4;
			} while(protocol == 129);
			//XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
		} else {
			vlanoffset = 0;
			protocol = header_eth->ether_type;
		}
		if(protocol == 8) {
			header_ip = (struct iphdr2 *) ((char*)header_eth + sizeof(ether_header) + vlanoffset);
		} else {
			return(NULL);
		}
	} else if(grehdr->version == 0 and grehdr_protocol == 0x800) {
		header_ip = (struct iphdr2 *) ((char*)header_ip + header_ip->get_hdr_size() + 4);
	} else if(grehdr->version == 0 and grehdr_protocol == 0x8847) {
		// 0x88BE - GRE & MPLS - + 4 bytes (GRE) + N * 4 bytes (MPLS)
		u_int header_ip_offset = header_ip->get_hdr_size() + 4;
		u_int8_t mpls_bottomOfLabelStackFlag;
		do {
			mpls_bottomOfLabelStackFlag = *((u_int8_t*)header_ip + header_ip_offset + 2) & 1;
			header_ip_offset += 4;
		} while(mpls_bottomOfLabelStackFlag == 0);
		header_ip = (struct iphdr2 *) ((char*)header_ip + header_ip_offset);
	} else {
		return(NULL);
	}
	return(header_ip);
}

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
bool parseEtherHeader(int pcapLinklayerHeaderType, u_char* packet,
		      sll_header *&header_sll, ether_header *&header_eth, u_char **header_ppp_o_e,
		      u_int &header_ip_offset, int &protocol, u_int16_t &vlan) {
	vlan = VLAN_NOSET;
	bool exists_vlan = false;
	u_int16_t ether_type;
	switch(pcapLinklayerHeaderType) {
		case DLT_LINUX_SLL:
			header_sll = (sll_header*)packet;
			if(htons(header_sll->sll_protocol) == 0x8100) {
				// VLAN tag
				header_ip_offset = 0;
				exists_vlan = true;
			} else {
				header_ip_offset = 0;
				protocol = htons(header_sll->sll_protocol);
			}
			if(exists_vlan) {
				u_int16_t _protocol;
				do {
					vlan = htons(*(u_int16_t*)(packet + sizeof(sll_header) + header_ip_offset)) & 0xFFF;
					_protocol = htons(*(u_int16_t*)(packet + sizeof(sll_header) + header_ip_offset + 2));
					header_ip_offset += 4;
				} while(_protocol == 0x8100);
				protocol = _protocol;
			}
			header_ip_offset += sizeof(sll_header);
			break;
		case DLT_EN10MB:
			header_eth = (ether_header*)packet;
			ether_type = htons(header_eth->ether_type);
			switch(ether_type) {
			case 0x8100:
				// VLAN tag
				header_ip_offset = 0;
				exists_vlan = true;
				//XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
				break;
			case 0x88A8:
				// IEEE 8021ad
				header_ip_offset = 4;
				protocol = htons(*(u_int16_t*)(packet + sizeof(ether_header) + 2));
				if(protocol == 0x8100) {
					// VLAN tag
					exists_vlan = true;
				}
				break;
			case 0x8864:
				// PPPoE
				if(htons(*(u_int16_t*)(packet + sizeof(ether_header) + 6)) == 0x0021) { // Point To Point protocol IPv4
					if(header_ppp_o_e) {
						*header_ppp_o_e = packet + sizeof(ether_header);
					}
					header_ip_offset = 8;
					protocol = ETHERTYPE_IP;
				} else {
					header_ip_offset = 0;
					protocol = 0;
				}
				break;
			case 0x8847:
				// MPLS
				header_ip_offset = 0;
				u_int8_t mpls_bottomOfLabelStackFlag;
				do {
					mpls_bottomOfLabelStackFlag = *((u_int8_t*)packet + sizeof(ether_header) + header_ip_offset + 2) & 1;
					header_ip_offset += 4;
				} while(mpls_bottomOfLabelStackFlag == 0);
				protocol = ETHERTYPE_IP;
				break;
			default:
				header_ip_offset = 0;
				protocol = ether_type;
			}
			if(exists_vlan) {
				u_int16_t _protocol;
				do {
					vlan = htons(*(u_int16_t*)(packet + sizeof(ether_header) + header_ip_offset)) & 0xFFF;
					_protocol = htons(*(u_int16_t*)(packet + sizeof(ether_header) + header_ip_offset + 2));
					header_ip_offset += 4;
				} while(_protocol == 0x8100);
				if(_protocol == 0x8864 && // PPPoE
				   htons(*(u_int16_t*)(packet + sizeof(ether_header) + header_ip_offset + 6)) == 0x0021) { // Point To Point protocol IPv4
					if(header_ppp_o_e) {
						*header_ppp_o_e = packet + header_ip_offset + sizeof(ether_header);
					}
					header_ip_offset += 8;
					protocol = ETHERTYPE_IP;
				} else {
					protocol = _protocol;
				}
			}
			header_ip_offset += sizeof(ether_header);
			break;
		case DLT_RAW:
			header_ip_offset = 0;
			protocol = ETHERTYPE_IP;
			break;
		case DLT_IEEE802_11_RADIO:
			header_ip_offset = 52;
			protocol = ETHERTYPE_IP;
			break;
		case DLT_MTP2_WITH_PHDR:
		case DLT_MTP2:
			header_ip_offset = 0xFFFFFFFF;
			protocol = 0;
			break;
		case DLT_NULL:
			header_ip_offset = 4;
			protocol = ETHERTYPE_IP;
			break;
		default:
			return(false);
	}
	return(true);
}

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
int findNextHeaderIp(iphdr2 *header_ip, unsigned header_ip_offset, u_char *packet, unsigned caplen, u_int8_t *flags) {
	extern unsigned opt_udp_port_l2tp;
	extern unsigned opt_udp_port_tzsp;
	extern bool opt_audiocodes;
	extern unsigned opt_udp_port_audiocodes;
	extern unsigned opt_tcp_port_audiocodes;
	if(header_ip->get_protocol() == IPPROTO_IPIP) {
		// ip in ip protocol
		return(header_ip->get_hdr_size());
	} else if(header_ip->get_protocol() == IPPROTO_GRE) {
		// gre protocol
		iphdr2 *header_ip_next = convertHeaderIP_GRE(header_ip);
		if(header_ip_next) {
			return((u_char*)header_ip_next - (u_char*)header_ip);
		} else {
			return(-1);
		}
	} else if(header_ip->get_protocol() == IPPROTO_UDP &&
		  header_ip->get_tot_len() + header_ip_offset == caplen &&
		  header_ip->get_tot_len() > header_ip->get_hdr_size() + sizeof(udphdr2) &&
		  IS_RTP((char*)header_ip + header_ip->get_hdr_size() + sizeof(udphdr2), header_ip->get_tot_len() - header_ip->get_hdr_size() - sizeof(udphdr2))) {
		return(0);
	} else if(opt_udp_port_l2tp &&
		  header_ip->get_protocol() == IPPROTO_UDP &&									// Layer 2 Tunelling protocol / UDP
		  (unsigned)((udphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->get_dest() == opt_udp_port_l2tp &&	// check destination port (default 1701)
		  (unsigned)((udphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->get_source() == opt_udp_port_l2tp &&	// check source port (default 1701)
		  htons(((udphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->len) > (sizeof(udphdr2) + 10)) {		// check minimal length
		unsigned int l2tp_length = 6;	// flags (2) + tunel id (2) + session id (2)
		unsigned int ptp_length = 4;	// address (1) + control (1) + protocol (2)
		unsigned int l2tp_offset = header_ip->get_hdr_size() + sizeof(udphdr2);
		u_int16_t l2tp_flags = htons(*(u_int16_t*)((unsigned char*)header_ip + l2tp_offset));
		if(l2tp_flags & 0x4000) {	// length bit - length field is present
			l2tp_length += 2;
		}
		unsigned int ptp_offset = l2tp_offset + l2tp_length;
		unsigned int next_header_ip_offset = 0;
		if(*((unsigned char*)header_ip + ptp_offset + 1) == 0x03 &&				// check control (0x03)
		   htons(*(u_int16_t*)((unsigned char*)header_ip + ptp_offset + 2)) == 0x0021) {	// check ptp protocol IPv4 (0x0021)
			next_header_ip_offset = ptp_offset + ptp_length;
		}
		return(next_header_ip_offset);
	} else if(opt_udp_port_tzsp &&
		  header_ip->get_protocol() == IPPROTO_UDP &&									// TZSP
		  ((unsigned)((udphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->get_dest() == opt_udp_port_tzsp ||	// check destination port (default 0x9090)
		   (unsigned)((udphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->get_source() == opt_udp_port_tzsp) &&	// check source port (default 0x9090)
		  htons(((udphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->len) > 
							 (sizeof(udphdr2) + 5 + sizeof(ether_header))) {	// check minimal length
		unsigned int tzsp_length = 5;									// version (1) + type (1) + protocol (2) + ... + end (1)
		unsigned int tzsp_offset = header_ip->get_hdr_size() + sizeof(udphdr2);
		unsigned int next_header_ip_offset = 0;
		if(*((unsigned char*)header_ip + tzsp_offset) == 1 &&						// check version (1)
		   htons(*(u_int16_t*)((unsigned char*)header_ip + tzsp_offset + 2)) == 1) {			// check ethernet protocol (1)
			while(*((unsigned char*)header_ip + tzsp_offset + tzsp_length - 1) != 1 &&		// find end (1)
			      tzsp_length < 10) {
				if(header_ip_offset + tzsp_offset + tzsp_length + sizeof(ether_header) < caplen) {
					++tzsp_length;
				} else {
					break;
				}
			}
			if(*((unsigned char*)header_ip + tzsp_offset + tzsp_length - 1) == 1) {			// check find end (1)
				next_header_ip_offset = tzsp_offset + tzsp_length + sizeof(ether_header);
			}
		}
		return(next_header_ip_offset);
	} else if(opt_audiocodes &&
		  ((opt_udp_port_audiocodes &&
		    header_ip->get_protocol() == IPPROTO_UDP &&
		    (unsigned)((udphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->get_dest() == opt_udp_port_audiocodes) ||
		   (opt_tcp_port_audiocodes &&
		    header_ip->get_protocol() == IPPROTO_TCP &&
		    (unsigned)((tcphdr2*)((char*)header_ip + header_ip->get_hdr_size()))->get_dest() == opt_tcp_port_audiocodes))) {
		u_char *data;
		unsigned datalen;
		unsigned udp_tcp_header_length;
		if(header_ip->get_protocol() == IPPROTO_UDP) {
			udphdr2 *header_udp = (udphdr2*)((char*)header_ip + header_ip->get_hdr_size());
			datalen =  get_udp_data_len(header_ip, header_udp,
						    (char**)&data, packet, caplen);
			udp_tcp_header_length = sizeof(udphdr2); 
		} else {
			tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
			datalen =  get_tcp_data_len(header_ip, header_tcp,
						    (char**)&data, packet, caplen);
			udp_tcp_header_length = header_tcp->doff * 4; 
		}
		sAudiocodes audiocodes;
		audiocodes.parse(data, datalen);
		if(audiocodes.ip_protocol_type == IPPROTO_UDP ||
		   audiocodes.ip_protocol_type == IPPROTO_TCP) {
			if(flags) {
				*flags |= FLAG_AUDIOCODES;
			}
			return(header_ip->get_hdr_size() + udp_tcp_header_length + audiocodes.header_length_total);
		}
	}
	return(0);
}

enum error_type {
	_na,
	bad_datalink,
	bad_eth_protocol,
	bad_ip_version,
	bad_ip_length
};

void pcapProcessEvalError(error_type error, pcap_pkthdr header, u_char *packet,
			  pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t *pcapDumpHandle, const char *interfaceName);
void pcapProcessEvalError(error_type error, pcap_pkthdr_plus2 *header, u_char *packet,
			  pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t *pcapDumpHandle, const char *interfaceName);

#if SNIFFER_INLINE_FUNCTIONS
inline 
#endif
int pcapProcess(sHeaderPacket **header_packet, int pushToStack_queue_index,
		pcap_block_store *block_store, int block_store_index,
		int ppf,
		pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t *pcapDumpHandle, const char *interfaceName) {
	pcap_pkthdr_plus2 *pcap_header_plus2 = NULL;
	u_char *packet = NULL;
	if(header_packet) {
		if((*header_packet)->detect_headers & 0x01) {
			ppd->header_ip_offset = (*header_packet)->header_ip_first_offset;
			ppd->protocol = (*header_packet)->eth_protocol;
			ppd->header_ip = (iphdr2*)(HPP(*header_packet) + ppd->header_ip_offset);
			ppd->pid = (*header_packet)->pid;
		} else if(parseEtherHeader(pcapLinklayerHeaderType, HPP(*header_packet),
					   ppd->header_sll, ppd->header_eth, NULL,
					   ppd->header_ip_offset, ppd->protocol, ppd->pid.vlan)) {
			(*header_packet)->detect_headers |= 0x01;
			(*header_packet)->header_ip_first_offset = ppd->header_ip_offset;
			(*header_packet)->eth_protocol = ppd->protocol;
			(*header_packet)->pid = ppd->pid;
			(*header_packet)->pid.flags = 0;
			if(!(ppd->protocol == ETHERTYPE_IP ||
			     (VM_IPV6_B && ppd->protocol == ETHERTYPE_IPV6) ||
			     ppd->header_ip_offset == 0xFFFFFFFF)) {
				if(sverb.tcpreplay) {
					if(ppd->protocol == 0) {
						ppd->header_ip_offset += 2;
						ppd->protocol = ETHERTYPE_IP;
					} else {
						return(0);
					}
				} else {
					pcapProcessEvalError(bad_eth_protocol, *HPH(*header_packet), HPP(*header_packet),
							     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
					return(0);
				}
			}
			if(ppd->header_ip_offset == 0xFFFFFFFF) {
				ppd->header_ip = NULL;
			} else {
				ppd->header_ip = (iphdr2*)(HPP(*header_packet) + ppd->header_ip_offset);
				if(!(((iphdr2*)ppd->header_ip)->version == 4 ||
				     (VM_IPV6_B && ((iphdr2*)ppd->header_ip)->version == 6))) {
					pcapProcessEvalError(bad_ip_version, *HPH(*header_packet), HPP(*header_packet),
							     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
					return(0);
				}
				if((ppd->header_ip->get_tot_len() + ppd->header_ip_offset > HPH(*header_packet)->len) && !sverb.process_rtp_header)  {
					pcapProcessEvalError(bad_ip_length, *HPH(*header_packet), HPP(*header_packet),
							     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
					return(0);
				}
			}
		} else {
			pcapProcessEvalError(bad_datalink, *HPH(*header_packet), HPP(*header_packet),
					     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
			return(0);
		}
	} else {
		pcap_header_plus2 = (pcap_pkthdr_plus2*)block_store->get_header(block_store_index);
		packet = block_store->get_packet(block_store_index);
		if(pcap_header_plus2->detect_headers & 0x01) {
			ppd->header_ip_offset = pcap_header_plus2->header_ip_first_offset;
			ppd->protocol = pcap_header_plus2->eth_protocol;
			ppd->header_ip = (iphdr2*)(packet + ppd->header_ip_offset);
			ppd->pid = pcap_header_plus2->pid;
		} else if(parseEtherHeader(pcapLinklayerHeaderType, packet,
					   ppd->header_sll, ppd->header_eth, NULL,
					   ppd->header_ip_offset, ppd->protocol, ppd->pid.vlan)) {
			pcap_header_plus2->detect_headers |= 0x01;
			pcap_header_plus2->header_ip_first_offset = ppd->header_ip_offset;
			pcap_header_plus2->eth_protocol = ppd->protocol;
			pcap_header_plus2->pid = ppd->pid;
			pcap_header_plus2->pid.flags = 0;
			if(!(ppd->protocol == ETHERTYPE_IP ||
			     (VM_IPV6_B && ppd->protocol == ETHERTYPE_IPV6) ||
			     ppd->header_ip_offset == 0xFFFFFFFF)) {
				if(sverb.tcpreplay) {
					if(ppd->protocol == 0) {
						ppd->header_ip_offset += 2;
						ppd->protocol = ETHERTYPE_IP;
					} else {
						pcap_header_plus2->ignore = true;
						return(0);
					}
				} else {
					pcapProcessEvalError(bad_eth_protocol, pcap_header_plus2, packet,
							     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
					pcap_header_plus2->ignore = true;
					return(0);
				}
			}
			if(ppd->header_ip_offset == 0xFFFFFFFF) {
				ppd->header_ip = NULL;
			} else {
				ppd->header_ip = (iphdr2*)(packet + ppd->header_ip_offset);
				if(!(((iphdr2*)ppd->header_ip)->version == 4 ||
				     (VM_IPV6_B && ((iphdr2*)ppd->header_ip)->version == 6))) {
					pcapProcessEvalError(bad_ip_version, pcap_header_plus2, packet,
							     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
					pcap_header_plus2->ignore = true;
					return(0);
				}
				if(ppd->header_ip->get_tot_len() + ppd->header_ip_offset > pcap_header_plus2->get_len()) {
					pcapProcessEvalError(bad_ip_length, pcap_header_plus2, packet,
							     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
					pcap_header_plus2->ignore = true;
					return(0);
				}
			}
		} else {
			pcapProcessEvalError(bad_datalink, pcap_header_plus2, packet,
					     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
			pcap_header_plus2->ignore = true;
			return(0);
		}
	}
	
	int is_ip_frag = 0;
	if(ppd->header_ip) {
		u_int16_t frag_data = ppd->header_ip->get_frag_data();
		if(ppd->header_ip->is_more_frag(frag_data) || ppd->header_ip->get_frag_offset(frag_data)) {
			is_ip_frag = 1;
			if((ppf & ppf_defrag) && opt_udpfrag) {
				if(ppd->header_ip->get_tot_len() + ppd->header_ip_offset > HPH(*header_packet)->caplen) {
					if(interfaceName) {
						extern BogusDumper *bogusDumper;
						static u_int64_t lastTimeLogErrBadIpHeader = 0;
						if(bogusDumper) {
							bogusDumper->dump(HPH(*header_packet), HPP(*header_packet), pcapLinklayerHeaderType, interfaceName);
						}
						u_int64_t actTime = getTimeMS(HPH(*header_packet));
						if(actTime - 1000 > lastTimeLogErrBadIpHeader) {
							syslog(LOG_ERR, "BAD FRAGMENTED HEADER_IP: %s: bogus ip header length %i, caplen %i", interfaceName, ppd->header_ip->get_tot_len(), HPH(*header_packet)->caplen);
							lastTimeLogErrBadIpHeader = actTime;
						}
					}
					//cout << "pcapProcess exit 001" << endl;
					return(0);
				}
				// packet is fragmented
				if(handle_defrag(ppd->header_ip, header_packet, &ppd->ipfrag_data, pushToStack_queue_index) > 0) {
					// packets are reassembled
					ppd->header_ip = (iphdr2*)(HPP(*header_packet) + ppd->header_ip_offset);
					if(sverb.defrag) {
						defrag_counter++;
						cout << "*** DEFRAG 1 " << defrag_counter << endl;
					}
					is_ip_frag = 2;
				} else {
					//cout << "pcapProcess exit 002" << endl;
					return(0);
				}
			}
		}
		unsigned headers_ip_counter = 0;
		unsigned headers_ip_offset[20];
		while(headers_ip_counter < sizeof(headers_ip_offset) / sizeof(headers_ip_offset[0]) - 1) {
			headers_ip_offset[headers_ip_counter] = ppd->header_ip_offset;
			++headers_ip_counter;
			int next_header_ip_offset = findNextHeaderIp(ppd->header_ip, ppd->header_ip_offset,
								     header_packet ? HPP(*header_packet) : packet,
								     header_packet ? HPH(*header_packet)->caplen : pcap_header_plus2->get_caplen(),
								     &ppd->pid.flags);
			if(next_header_ip_offset == 0) {
				break;
			} else if(next_header_ip_offset < 0) {
				if(ppf & ppf_returnZeroInCheckData) {
					//cout << "pcapProcess exit 004" << endl;
					if(pcap_header_plus2) {
						pcap_header_plus2->ignore = true;
					}
					return(0);
				}
			} else {
				ppd->header_ip = (iphdr2*)((u_char*)ppd->header_ip + next_header_ip_offset);
				ppd->header_ip_offset += next_header_ip_offset;
			}
			if(ppd->header_ip->get_protocol() == IPPROTO_UDP) {
				u_int16_t frag_data = ppd->header_ip->get_frag_data();
				if(ppd->header_ip->is_more_frag(frag_data) || ppd->header_ip->get_frag_offset(frag_data)) {
					is_ip_frag = 1;
					if((ppf & ppf_defrag) && opt_udpfrag) {
						if(handle_defrag(ppd->header_ip, header_packet, &ppd->ipfrag_data, pushToStack_queue_index) > 0) {
							ppd->header_ip = (iphdr2*)(HPP(*header_packet) + ppd->header_ip_offset);
							ppd->header_ip->clear_frag_data();
							for(unsigned i = 0; i < headers_ip_counter; i++) {
								iphdr2 *header_ip_prev = (iphdr2*)(HPP(*header_packet) + headers_ip_offset[i]);
								header_ip_prev->set_tot_len(ppd->header_ip->get_tot_len() + (ppd->header_ip_offset - headers_ip_offset[i]));
								header_ip_prev->clear_frag_data();
							}
							if(sverb.defrag) {
								defrag_counter++;
								cout << "*** DEFRAG 2 " << defrag_counter << endl;
							}
							is_ip_frag = 2;
						} else {
							//cout << "pcapProcess exit 003" << endl;
							return(0);
						}
					}
				}
			}
		}
	}
	
	if(header_packet) {
		(*header_packet)->header_ip_offset = ppd->header_ip_offset;
		(*header_packet)->pid.flags = ppd->pid.flags;
	} else {
		pcap_header_plus2->header_ip_offset = ppd->header_ip_offset;
		pcap_header_plus2->pid.flags = ppd->pid.flags;
	}
	
	if((ppf & ppf_defrag) && ppd->header_ip) {
		// if IP defrag is enabled, run each 10 seconds cleaning 
		if(opt_udpfrag && (ppd->ipfrag_lastprune + 10) < HPH(*header_packet)->ts.tv_sec) {
			ipfrag_prune(HPH(*header_packet)->ts.tv_sec, false, &ppd->ipfrag_data, pushToStack_queue_index, -1);
			ppd->ipfrag_lastprune = HPH(*header_packet)->ts.tv_sec;
			//TODO it would be good to still pass fragmented packets even it does not contain the last semant, the ipgrad_prune just wipes all unfinished frags
		}
	}
	
	if(!((ppf & ppf_defragInPQout) && is_ip_frag == 1)) {
		u_int32_t caplen;
		if(header_packet) {
			caplen = HPH(*header_packet)->caplen;
			packet = HPP(*header_packet);
		} else {
			caplen = pcap_header_plus2->get_caplen();
		}
		if(ppd->header_ip) {
			ppd->header_udp = &ppd->header_udp_tmp;
			if (ppd->header_ip->get_protocol() == IPPROTO_UDP) {
				// prepare packet pointers 
				ppd->header_udp = (udphdr2*) ((char*) ppd->header_ip + ppd->header_ip->get_hdr_size());
				ppd->datalen = get_udp_data_len(ppd->header_ip, ppd->header_udp, &ppd->data, packet, caplen);
				ppd->istcp = 0;
				ppd->isother = 0;
			} else if (ppd->header_ip->get_protocol() == IPPROTO_TCP) {
				ppd->istcp = 1;
				ppd->isother = 0;
				// prepare packet pointers 
				ppd->header_tcp = (tcphdr2*) ((char*) ppd->header_ip + ppd->header_ip->get_hdr_size());
				ppd->datalen = get_tcp_data_len(ppd->header_ip, ppd->header_tcp, &ppd->data, packet, caplen);
				if (!(sipportmatrix[ppd->header_tcp->get_source()] || sipportmatrix[ppd->header_tcp->get_dest()]) &&
				    !(opt_enable_http && (httpportmatrix[ppd->header_tcp->get_source()] || httpportmatrix[ppd->header_tcp->get_dest()]) &&
				      (tcpReassemblyHttp->check_ip(ppd->header_ip->get_saddr()) || tcpReassemblyHttp->check_ip(ppd->header_ip->get_daddr()))) &&
				    !(opt_enable_webrtc && (webrtcportmatrix[ppd->header_tcp->get_source()] || webrtcportmatrix[ppd->header_tcp->get_dest()]) &&
				      (tcpReassemblyWebrtc->check_ip(ppd->header_ip->get_saddr()) || tcpReassemblyWebrtc->check_ip(ppd->header_ip->get_daddr()))) &&
				    !(opt_enable_ssl && 
				      (isSslIpPort(ppd->header_ip->get_saddr(), ppd->header_tcp->get_source()) ||
				       isSslIpPort(ppd->header_ip->get_daddr(), ppd->header_tcp->get_dest()))) &&
				    !(opt_skinny && (skinnyportmatrix[ppd->header_tcp->get_source()] || skinnyportmatrix[ppd->header_tcp->get_dest()])) &&
				    !(opt_mgcp && 
				      ((unsigned)ppd->header_tcp->get_source() == opt_tcp_port_mgcp_gateway || (unsigned)ppd->header_tcp->get_dest() == opt_tcp_port_mgcp_gateway ||
				       (unsigned)ppd->header_tcp->get_source() == opt_tcp_port_mgcp_callagent || (unsigned)ppd->header_tcp->get_dest() == opt_tcp_port_mgcp_callagent))) {
					// not interested in TCP packet other than SIP port
					if(!opt_ipaccount && !DEBUG_ALL_PACKETS && (ppf & ppf_returnZeroInCheckData)) {
						//cout << "pcapProcess exit 005" << endl;
						if(pcap_header_plus2) {
							pcap_header_plus2->ignore = true;
						}
						return(0);
					}
				}
				ppd->header_udp->_source = ppd->header_tcp->_source;
				ppd->header_udp->_dest = ppd->header_tcp->_dest;
			} else if (opt_enable_ss7 && ppd->header_ip->get_protocol() == IPPROTO_SCTP) {
				ppd->istcp = 0;
				ppd->isother = 1;
				ppd->datalen = get_sctp_data_len(ppd->header_ip, &ppd->data, packet, caplen);
			} else {
				//packet is not UDP and is not TCP, we are not interested, go to the next packet (but if ipaccount is enabled, do not skip IP
				ppd->datalen = 0;
				if(!opt_ipaccount && !DEBUG_ALL_PACKETS && (ppf & ppf_returnZeroInCheckData)) {
					//cout << "pcapProcess exit 006 / protocol: " << (int)ppd->header_ip->protocol << endl;
					if(pcap_header_plus2) {
						pcap_header_plus2->ignore = true;
					}
					return(0);
				}
			}
			if(ppd->datalen < 0 && (ppf & ppf_returnZeroInCheckData)) {
				//cout << "pcapProcess exit 007" << endl;
				if(pcap_header_plus2) {
					pcap_header_plus2->ignore = true;
				}
				return(0);
			}
			ppd->traillen = (int)(caplen - ((u_char*)ppd->header_ip - packet)) - ppd->header_ip->get_tot_len();
		} else if(opt_enable_ss7) {
			ppd->istcp = 0;
			ppd->isother = 1;
			ppd->data = (char*)packet;
			ppd->datalen = caplen;
		}
	} else {
		ppd->data = NULL;
		ppd->datalen = 0;
	}

	#ifdef DEDUP_DEBUG
	static long counter = 0;
	cout << "packet " << (++counter) << " " << HPH(*header_packet)->ts.tv_sec << "." << setw(6) << setfill('0') << HPH(*header_packet)->ts.tv_usec;
	#endif
	if(((ppf & ppf_calcMD5) || (ppf & ppf_dedup)) && ppd->header_ip) {
		// check for duplicate packets (md5 is expensive operation - enable only if you really need it
		if(opt_dup_check && 
		   ppd->prevmd5s != NULL && 
		   (((ppf & ppf_defragInPQout) && is_ip_frag == 1) ||
		    (ppd->datalen > 0 && (opt_dup_check_ipheader || ppd->traillen < ppd->datalen))) &&
		   !(ppd->istcp && opt_enable_http && (httpportmatrix[ppd->header_tcp->get_source()] || httpportmatrix[ppd->header_tcp->get_dest()])) &&
		   !(ppd->istcp && opt_enable_webrtc && (webrtcportmatrix[ppd->header_tcp->get_source()] || webrtcportmatrix[ppd->header_tcp->get_dest()])) &&
		   !(ppd->istcp && opt_enable_ssl && (isSslIpPort(ppd->header_ip->get_saddr(), ppd->header_tcp->get_source()) || isSslIpPort(ppd->header_ip->get_daddr(), ppd->header_tcp->get_dest())))) {
			uint16_t *_md5 = header_packet ? (*header_packet)->md5 : pcap_header_plus2->md5;
			if(ppf & ppf_calcMD5) {
				bool header_ip_set_orig = false;
				u_int8_t header_ip_ttl_orig;
				u_int8_t header_ip_check_orig;
				if(opt_dup_check_ipheader_ignore_ttl &&
				   (((ppf & ppf_defragInPQout) && is_ip_frag == 1) ||
				    opt_dup_check_ipheader)) {
					header_ip_ttl_orig = ppd->header_ip->get_ttl();
					header_ip_check_orig = ppd->header_ip->get_check();
					ppd->header_ip->set_ttl(0);
					ppd->header_ip->set_check(0);
					header_ip_set_orig = true;
				}
				MD5_Init(&ppd->ctx);
				if((ppf & ppf_defragInPQout) && is_ip_frag == 1) {
					u_int32_t caplen = header_packet ? HPH(*header_packet)->caplen : pcap_header_plus2->get_caplen();
					MD5_Update(&ppd->ctx, ppd->header_ip, MIN(caplen - ppd->header_ip_offset, ppd->header_ip->get_tot_len()));
				} else if(opt_dup_check_ipheader) {
					MD5_Update(&ppd->ctx, ppd->header_ip, MIN(ppd->datalen + (ppd->data - (char*)ppd->header_ip), ppd->header_ip->get_tot_len()));
				} else {
					// check duplicates based only on data (without ip header and without UDP/TCP header). Duplicate packets 
					// will be matched regardless on IP 
					MD5_Update(&ppd->ctx, ppd->data, MAX(0, (unsigned long)ppd->datalen - ppd->traillen));
				}
				MD5_Final((unsigned char*)_md5, &ppd->ctx);
				if(header_ip_set_orig) {
					ppd->header_ip->set_ttl(header_ip_ttl_orig);
					ppd->header_ip->set_check(header_ip_check_orig);
				}
				#ifdef DEDUP_DEBUG
				cout << " " << MD5_String((unsigned char*)_md5);
				#endif
			}
			if((ppf & ppf_dedup) && _md5[0]) {
				if(memcmp(_md5, ppd->prevmd5s + (_md5[0] * MD5_DIGEST_LENGTH), MD5_DIGEST_LENGTH) == 0) {
					//printf("dropping duplicate md5[%s]\n", md5);
					duplicate_counter++;
					if(sverb.dedup) {
						cout << "*** DEDUP " << duplicate_counter << endl;
					}
					if(pcap_header_plus2) {
						pcap_header_plus2->ignore = true;
					}
					#ifdef DEDUP_DEBUG
					cout << " DUPL" << endl;
					#endif
					return(0);
				}
				memcpy(ppd->prevmd5s + (_md5[0] * MD5_DIGEST_LENGTH), _md5, MD5_DIGEST_LENGTH);
			}
		}
	}
	#ifdef DEDUP_DEBUG
	cout << endl;
	#endif
	
	if((ppf & ppf_dump) && ppd->header_ip) {
		if(pcapDumpHandle) {
			if(header_packet) {
				pcap_dump((u_char*)pcapDumpHandle, HPH(*header_packet), HPP(*header_packet));
			} else {
				pcap_pkthdr header = pcap_header_plus2->getStdHeader();
				pcap_dump((u_char*)pcapDumpHandle, &header, packet);
			}
		}
	}
	
	return(1);
}

void pcapProcessEvalError(error_type error, pcap_pkthdr header, u_char *packet, 
			  pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t */*pcapDumpHandle*/, const char *interfaceName) {
	switch(error) {
	case bad_eth_protocol: {
		static int info_tcpreplay = 0;
		if(ppd->protocol == 0 && !info_tcpreplay && interfaceName && !strcmp(interfaceName, "lo")) {
			syslog(LOG_ERR, "BAD PROTOCOL (not ipv4) IN %s (dlt %d) - TRY VERBOSE OPTION tcpreplay", interfaceName, pcapLinklayerHeaderType);
			info_tcpreplay = 1;
		}
		}
		break;
	case bad_ip_version:
		if(interfaceName) {
			extern BogusDumper *bogusDumper;
			static u_int64_t lastTimeLogErrBadIpHeader = 0;
			if(bogusDumper) {
				bogusDumper->dump(&header, packet, pcapLinklayerHeaderType, interfaceName);
			}
			u_int64_t actTime = getTimeMS(&header);
			if(actTime - 1000 > lastTimeLogErrBadIpHeader) {
				syslog(LOG_ERR, "BAD HEADER_IP: %s: bogus ip header version %i", interfaceName, ppd->header_ip->version);
				lastTimeLogErrBadIpHeader = actTime;
			}
		}
		break;
	case bad_ip_length:
		if(interfaceName) {
			extern BogusDumper *bogusDumper;
			static u_int64_t lastTimeLogErrBadIpHeader = 0;
			if(bogusDumper) {
				bogusDumper->dump(&header, packet, pcapLinklayerHeaderType, interfaceName);
			}
			u_int64_t actTime = getTimeMS(&header);
			if(actTime - 1000 > lastTimeLogErrBadIpHeader) {
				syslog(LOG_ERR, "BAD HEADER_IP: %s: bogus ip header length %i, len %i", interfaceName, ppd->header_ip->get_tot_len(), header.len);
				lastTimeLogErrBadIpHeader = actTime;
			}
		}
		break;
	case bad_datalink:
		syslog(LOG_ERR, "BAD DATALINK %s: datalink number [%d] is not supported", interfaceName ? interfaceName : "---", pcapLinklayerHeaderType);
		break;
	default:
		break;
	}
}

void pcapProcessEvalError(error_type error, pcap_pkthdr_plus2 *header, u_char *packet,
			  pcapProcessData *ppd, int pcapLinklayerHeaderType, pcap_dumper_t *pcapDumpHandle, const char *interfaceName) {
	pcapProcessEvalError(error, header->getStdHeader(), packet,
			     ppd, pcapLinklayerHeaderType, pcapDumpHandle, interfaceName);
}


#endif
