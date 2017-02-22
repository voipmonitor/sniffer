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
#ifndef __DSSL_STREAM_H__
#define __DSSL_STREAM_H__

#include "packet.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define DSSL_TCPSTREAM_SENT_SYN		1
#define DSSL_TCPSTREAM_SENT_FIN		2
#define DSSL_TCPSTREAM_SENT_RST		4

/* maximum number of out-of-order packets */
#define DSSL_STREAM_MAX_REASSEMBLY_DEPTH	1024

/*number of ack packet times stored per stream*/
#define DSSL_ACK_TIME_BUFFER_SIZE			2

typedef struct _PktAckTime
{
	uint32_t			seq;
	struct timeval		ack_time;
} PktAckTime;

/*!TcpStreamStats - packet statistics for TCP stream */
typedef struct _TcpStreamStats
{
	/*! data packets count */
	uint32_t	data_pkt_count;
	/*! ACK-only (no data) packets count */
	uint32_t	ack_pkt_count;
	/*! number of packet retransmissions */
	uint32_t	retrans_pkt_count;
} TcpStreamStats;


struct _TcpStream
{
	uint32_t		ip_addr;
	uint16_t		port;
	/*! DSSL_TCPSTREAM_ bitmask */
	uint16_t		flags;
	/*! head of the reassembly queue */
    DSSL_Pkt*		pktHead;
	/*! tail of the reassembly queue */
    DSSL_Pkt*		pktTail;
	/*! sequence number of the next packet in the stream */
	uint32_t		nextSeqExpected;
	/*! latest and greatest ACK sequence */
	uint32_t		lastPacketAck;
	/*! latest and greatest ACK time */
	struct timeval	lastPacketAckTime;
	/*! parent TCP session object */
	TcpSession*		session;
	/*! size of the reassembly queue*/
	uint32_t		queue_size;
	/* initial TCP sequence */
	uint32_t		initial_seq;
	/*! timestamp of a SYN or SYN+ACK packet that started this stream */
	struct timeval	syn_time; 
	/*! timestamp of peer's packet that ACKs the SYN or SYN+ACK packet of this stream */
	struct timeval	first_ack_time; 

	/* circular buffer to store timestamps of ACK packets with correspondinf ACK sequence number */
	PktAckTime		acks[DSSL_ACK_TIME_BUFFER_SIZE];
	int				ack_idx;

	TcpStreamStats	stats;
};


/* Initialization / destruction */
void StreamInit( TcpStream* stream, TcpSession* sess, uint32_t ip, uint16_t port );
void StreamFreeData( TcpStream* stream );

/* Main packet processing function */
int StreamProcessPacket( TcpStream* stream, DSSL_Pkt* pkt, int* new_ack );

TcpStream* StreamGetPeer( const TcpStream* stream );
int StreamConsumeHead( TcpStream* stream, int* new_ack );

/* check any previoulsy enqueued out-of-order packets are ready to be processed */
int StreamPollPackets( TcpStream* stream, int* new_ack );


#ifdef  __cplusplus
}
#endif

#endif
