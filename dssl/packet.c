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
#include <string.h>
#include "stdinc.h"
#include "packet.h"

uint32_t PktNextTcpSeqExpected( const DSSL_Pkt* pkt )
{
	uint32_t th_seq;
	th_seq = ntohl( pkt->tcp_header->th_seq );

	if( (pkt->tcp_header->th_flags & TH_SYN) || (pkt->tcp_header->th_flags & TH_FIN) )
		return th_seq + pkt->data_len + 1;
	else
		return th_seq + pkt->data_len;
}


DSSL_Pkt* PktClone( const DSSL_Pkt* src )
{
	DSSL_Pkt* pClone;

	pClone = malloc( sizeof( DSSL_Pkt ) + src->pcap_header.caplen );
	memcpy( &pClone->pcap_header, &src->pcap_header, sizeof( struct pcap_pkthdr ) );
	memcpy( (u_char*)pClone + sizeof(*pClone), src->pcap_ptr, src->pcap_header.caplen );

	pClone->data_len = src->data_len;
	pClone->pcap_ptr = (u_char*) pClone + sizeof(*pClone);
	pClone->session = src->session;
	pClone->link_type = src->link_type;
	pClone->ip_header_allocated = src->ip_header_allocated;
	
	pClone->ether_header = (struct ether_header*)
			( pClone->pcap_ptr + ((u_char*)src->ether_header - src->pcap_ptr ) );
	if (src->ip_header_allocated) {
		pClone->ip_header = malloc( sizeof( struct ip ) );
		memcpy( pClone->ip_header, src->ip_header, sizeof( struct ip ) );
	} else
		pClone->ip_header = (struct ip*) 
			( pClone->pcap_ptr + ((u_char*) src->ip_header - src->pcap_ptr ) );
	pClone->tcp_header = (struct tcphdr*)
			( pClone->pcap_ptr + ((u_char*) src->tcp_header - src->pcap_ptr ) );

	pClone->udp_header = (struct udphdr*)
			( pClone->pcap_ptr + ((u_char*) src->udp_header - src->pcap_ptr ) );

	pClone->prev = pClone->next = NULL;
	pClone->ack_time = src->ack_time;
	pClone->flags = src->flags;

	return pClone;
}

int PktCloneChunk(const DSSL_Pkt* src, int tail_len, DSSL_Pkt** rc)
{
	DSSL_Pkt* pClone = NULL;
	uint32_t newSeq = 0;
	u_char* d1 = NULL;
	u_char* d2 = NULL;
	int hdr_len = 0;

	_ASSERT(rc);
	_ASSERT(src);

	if(tail_len <= 0 || tail_len > (int)src->data_len )
	{
		return NM_ERROR(DSSL_E_INVALID_PARAMETER);
	}

	d1 = PKT_TCP_PAYLOAD(src);
	d2 = d1 + src->data_len - tail_len;
	hdr_len = d1 - src->pcap_ptr;

	_ASSERT(d2 <= d1);
	_ASSERT(d2 + tail_len <= d1 + src->data_len);
	_ASSERT(d2 + tail_len <= src->pcap_ptr + src->pcap_header.caplen);

	pClone = malloc( sizeof( DSSL_Pkt ) + src->pcap_header.caplen );
	memcpy( &pClone->pcap_header, &src->pcap_header, sizeof( struct pcap_pkthdr ) );
	/*copy the header data */
	memcpy( (u_char*)pClone + sizeof(*pClone), src->pcap_ptr, hdr_len);
	/* copy only the tail_len last bytes */
	memcpy( (u_char*)pClone + sizeof(*pClone) + hdr_len, d2, tail_len);

	pClone->data_len = (uint16_t) tail_len;
	pClone->pcap_ptr = (u_char*) pClone + sizeof(*pClone);
	pClone->session = src->session;
	pClone->link_type = src->link_type;
	pClone->ip_header_allocated = src->ip_header_allocated;
	
	pClone->ether_header = (struct ether_header*)
			( pClone->pcap_ptr + ((u_char*)src->ether_header - src->pcap_ptr ) );
	if (src->ip_header_allocated) {
		pClone->ip_header = malloc( sizeof( struct ip ) );
		memcpy( pClone->ip_header, src->ip_header, sizeof( struct ip ) );
	} else
		pClone->ip_header = (struct ip*) 
			( pClone->pcap_ptr + ((u_char*) src->ip_header - src->pcap_ptr ) );
	pClone->tcp_header = (struct tcphdr*)
			( pClone->pcap_ptr + ((u_char*) src->tcp_header - src->pcap_ptr ) );

	pClone->udp_header = (struct udphdr*)
			( pClone->pcap_ptr + ((u_char*) src->udp_header - src->pcap_ptr ) );

	pClone->prev = pClone->next = NULL;
	pClone->ack_time = src->ack_time;
	pClone->flags = src->flags;

	/* shift the sequence forward so the seq+len will be the same as in the original packet */
	newSeq = PKT_TCP_SEQ(src) + src->data_len - tail_len;
	pClone->tcp_header->th_seq = htonl(newSeq);

	/* assign the retval param*/
	(*rc) = pClone;

	return DSSL_RC_OK;
}

void PktFree( DSSL_Pkt* pkt )
{
	if ( pkt->ip_header_allocated ) {
		free( pkt->ip_header );
	}
	free( pkt );
}

int PktCompareTimes( const DSSL_Pkt* pkt1, const DSSL_Pkt* pkt2 )
{
	if( pkt1->pcap_header.ts.tv_sec > pkt2->pcap_header.ts.tv_sec )
		return 1;
	else if ( pkt1->pcap_header.ts.tv_sec < pkt2->pcap_header.ts.tv_sec )
		return -1;
	else return pkt1->pcap_header.ts.tv_usec - pkt2->pcap_header.ts.tv_usec;
}
