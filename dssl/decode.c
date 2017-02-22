/*
** This file is a part of DSSL library.
**
** Copyright (C) 2005-2009, Atomic Labs, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#include "stdinc.h"
#include "decode.h"

#ifdef HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif

#ifdef _WIN32
struct ip6_hdr
{
	union
	{
		struct ip6_hdrctl
		{
			uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
										20 bits flow-ID */
			uint16_t ip6_un1_plen;   /* payload length */
			uint8_t  ip6_un1_nxt;    /* next header */
			uint8_t  ip6_un1_hlim;   /* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
	} ip6_ctlun;
	struct in6_addr ip6_src;      /* source address */
	struct in6_addr ip6_dst;      /* destination address */
};
#endif
#if defined(OLD_IPV6) || defined(_WIN32)
/* Generic extension header.  */
struct ip6_ext
{
	uint8_t  ip6e_nxt;		/* next header.  */
	uint8_t  ip6e_len;		/* length in units of 8 octets.  */
};
#endif

void DecodeTcpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int tcp_hdr_len;

	/* Check the packet length */
	if( len < sizeof(struct tcphdr) )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than minimal TCP header size", len );
		return;
	}

	pkt->tcp_header = (struct tcphdr*) data;

	tcp_hdr_len = NM_TCP_HDR_LEN( pkt->tcp_header );

	if( len < tcp_hdr_len )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than TCP header size specified (%d)", 
			len, tcp_hdr_len );
		return;
	}

	pkt->data_len = (uint16_t)( len - tcp_hdr_len );

	CapEnvProcessPacket( env, pkt );
}


void DecodeUdpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int hdr_len = sizeof(struct udphdr);

	/* Check the packet length */
	if( len < hdr_len )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than minimal UDP header size", len );
		return;
	}

	pkt->udp_header = (struct udphdr*) data;

	pkt->data_len = (uint16_t)( len - hdr_len );

	CapEnvProcessDatagram( env, data + hdr_len, pkt->data_len, pkt );
}


static int TranslateIPv6Address(struct in6_addr *in6, uint32_t *ip)
{
	const uint32_t local_host = (uint32_t)htonl(INADDR_LOOPBACK);
	
	if (IN6_IS_ADDR_LOOPBACK(in6)) {
		*ip = local_host;
	} 
	else if(IN6_IS_ADDR_V4MAPPED(in6)) {
#ifdef _WIN32
		*ip = *(uint32_t*)&in6->s6_addr[12];
#elif defined(__sparc__) ||  defined(__sparc) || defined(__SunOS_5_8) || defined(__SunOS_5_9) || defined(__SunOS_5_10) || ( defined(__GNUC__) && defined(__sun__) )
		*ip = in6->_S6_un._S6_u32[3];
#else
		*ip = in6->s6_addr32[3];
#endif
	}
	else {
		*ip = 0;
		return 0;
	}
	
	return 1;
}

void DecodeIpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int ip_pkt_len, ip_hdrlen;
	struct ip6_hdr *ip6 = (struct ip6_hdr*) data;
	uint32_t src, dst;
	struct ip6_ext *ip6ext;
	uint8_t nxt;
	int more_headers = 1;

	pkt->ip_header = (struct ip*) data;
	pkt->ip_header_allocated = 0;

	if( len < sizeof(struct ip) )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Invalid IP header length!" );
		return;
	}

	switch( IP_V(pkt->ip_header) )
	{
		case 4:
			ip_pkt_len = ntohs(pkt->ip_header->ip_len);
			ip_hdrlen = IP_HL(pkt->ip_header) << 2;
			
			if( ip_hdrlen < sizeof(struct ip) )
			{
				nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Bogus IP header!" );
				return;
			}
			break;
		case 6:
			/* length includes all the extra ipv6 headers */
			ip_pkt_len = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
			ip_hdrlen = sizeof(struct ip6_hdr);
			
			/* check if addresses are IPv4 mapped or LOCALHOST */
			if ((0 == TranslateIPv6Address(&ip6->ip6_src, &src)) || (0 == TranslateIPv6Address(&ip6->ip6_dst, &dst))) {
				nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Unsupported IPv6 address!" );
				return;
			}
			
			/* skip all extra headers */
			nxt = ip6->ip6_nxt;
			ip6ext = (struct ip6_ext*)(data + ip_hdrlen);
			while (more_headers) {
				switch (nxt) {
					case IPPROTO_HOPOPTS:
					case IPPROTO_ROUTING:
					case IPPROTO_FRAGMENT:
					case IPPROTO_ICMPV6:
					case IPPROTO_DSTOPTS:
#ifdef IPPROTO_MH
					case IPPROTO_MH:
#endif
						/* skip IPv6 extension header */
						ip_hdrlen += (ip6ext->ip6e_len + 1) * 8;
						nxt = ip6ext->ip6e_nxt;
						ip6ext = (struct ip6_ext*)(data + ip_hdrlen);
						break;
					case IPPROTO_NONE:
						/* no more IPv6 extension headers and no more headers at all */
						return;
						break;
					default:
						/* no more IPv6 extension headers */
						more_headers = 0;
						break;
				}
			}
			/* create an artificial IPv4 header */
			pkt->ip_header = malloc( sizeof( struct ip ) );
			pkt->ip_header_allocated = 1;
			/* only set the minimum needed fields */
#ifdef _WIN32
			pkt->ip_header->ip_vhl = 0x45;
#else
			pkt->ip_header->ip_v = 4;
			pkt->ip_header->ip_hl = 5;
#endif
			pkt->ip_header->ip_len = htons(20 + (ip_pkt_len - ip_hdrlen));
			pkt->ip_header->ip_dst.s_addr = dst;
			pkt->ip_header->ip_src.s_addr = src;
			pkt->ip_header->ip_p = nxt;
			break;
		default:
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Unsupported IP version: %d",
				(int)IP_V(pkt->ip_header) );
		return;
	}

	/*TODO: reassemble fragmented packets*/

	if( pkt->ip_header->ip_p == IPPROTO_TCP )
	{
		DecodeTcpPacket( env, pkt, data + ip_hdrlen, ip_pkt_len - ip_hdrlen );
	}
	else if( pkt->ip_header->ip_p == IPPROTO_UDP && env->datagram_callback != NULL )
	{
		DecodeUdpPacket( env, pkt, data + ip_hdrlen, ip_pkt_len - ip_hdrlen );
	}
	
	if ( pkt->ip_header_allocated )
	{
		free( pkt->ip_header );
		pkt->ip_header_allocated = 0;
	}
}
