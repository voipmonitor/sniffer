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
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#include <string.h>
#include "stdinc.h"
#include "stream.h"
#include "session.h"
#include "capenv.h"

#define STREAM_PKT_NOT_ACKED( pkt ) ((pkt)->ack_time.tv_sec == 0 && (pkt)->ack_time.tv_usec == 0)

TcpStream* StreamGetPeer( const TcpStream* stream );
static int IsNextPacket( const TcpStream* stream, const DSSL_Pkt* pkt );
static void StreamDiscardHead(TcpStream* stream);

/* update memory usage when the packet is added to the cache*/
static void CountPktIn( TcpStream* stream, const DSSL_Pkt* pkt)
{
	_ASSERT(stream);
	_ASSERT(pkt);
	++stream->queue_size;

	/* update the memory statistics */
	if( stream->session && stream->session->env )
	{
		dssl_SessionTable* tbl = stream->session->env->sessions;
		_ASSERT(tbl);
		++tbl->packet_cache_count;
		tbl->packet_cache_mem += pkt->data_len;
#ifdef NM_TRACE_MEMORY_USAGE
		DEBUG_TRACE2("\n:: ++ %d bytes, %ld now", pkt->data_len, tbl->packet_cache_mem);
#endif
	}
}

/* update memory usage when the packet is removed from the cache*/
static void CountPktOut(TcpStream* stream, const DSSL_Pkt* pkt)
{
	_ASSERT(stream);
	_ASSERT(pkt);
	--stream->queue_size;

	/* update the memory statistics */
	if( stream->session && stream->session->env )
	{
		dssl_SessionTable* tbl = stream->session->env->sessions;
		_ASSERT(tbl);
		--tbl->packet_cache_count;
		tbl->packet_cache_mem -= pkt->data_len;
#ifdef NM_TRACE_MEMORY_USAGE
		DEBUG_TRACE2("\n:: -- %d bytes, %ld left", pkt->data_len, tbl->packet_cache_mem);
#endif
	}
}


#ifdef NM_TRACE_TCP_STREAMS

/* 
warning: this is a diagnostic funtion for debugging purposes only;
it is not reentrable and not thread-safe
*/
static const char* StreamToString( const TcpStream* str )
{
	static char buff[512];
	char addr1[32], addr2[32];

	addr1[0] = 0;
	addr2[0] = 0;

	AddressToString( str->ip_addr, str->port, addr1 );
	AddressToString( StreamGetPeer(str)->ip_addr, StreamGetPeer(str)->port, addr2 );

	sprintf( buff, "%s->%s", addr1, addr2 );

	return buff;
}
#endif

void StreamInit( TcpStream* stream, TcpSession* sess, uint32_t ip, uint16_t port )
{
	_ASSERT( stream );

	memset(stream, 0, sizeof(*stream) );

	stream->ip_addr = ip;
	stream->port = port;
	stream->pktHead = NULL;
	stream->pktTail = NULL;
	stream->nextSeqExpected = 0;
	stream->session = sess;
	stream->queue_size = 0;
}

/*
static int StreamGetPacketCount( TcpStream* stream )
{
	int cnt = 0;
	DSSL_Pkt* pkt = stream->pktHead;

	while( pkt )
	{
		cnt++;
		pkt = pkt->next;
	}

	return cnt;
}
*/


void StreamFreeData( TcpStream* stream )
{
	DSSL_Pkt* pkt = stream->pktHead;

#ifdef NM_TRACE_TCP_STREAMS
	DEBUG_TRACE2( "\nFreeStreamData: stream %s; %d packets freed",
		StreamToString(stream), StreamGetPacketCount( stream ) );
#endif

	while( pkt ) 
	{
		DSSL_Pkt* t = pkt->next;
		CountPktOut(stream, pkt);
		PktFree( pkt );
		pkt = t;
	}

	stream->pktTail = stream->pktHead = NULL;
	stream->nextSeqExpected = 0;
	_ASSERT(stream->queue_size == 0);
}


static void StreamInsertAfter( TcpStream* stream, DSSL_Pkt* pktInsert, DSSL_Pkt* pktAfter )
{
	if( pktAfter->next && PKT_TCP_SEQ(pktAfter->next) < PktNextTcpSeqExpected(pktInsert) )
	{
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Overlapping packet seq:%u, len %d", StreamToString(stream), 
			PKT_TCP_SEQ( pktInsert ) - stream->initial_seq, pktInsert->data_len );
		DEBUG_TRACE2( " between seq:%u, len %d", PKT_TCP_SEQ(pktAfter)- stream->initial_seq, pktAfter->data_len );
		DEBUG_TRACE2( " and seq:%u, len %d", PKT_TCP_SEQ(pktAfter->next)- stream->initial_seq, pktAfter->next->data_len );
#endif
		return;
	}

	/* clone packet because it can be allocated on stack and we 
	   want it to live in a queue */
	pktInsert = PktClone( pktInsert );

#ifdef NM_TRACE_TCP_STREAMS
	{
		uint32_t seq = PKT_TCP_SEQ( pktInsert );
		uint32_t seq_after = PKT_TCP_SEQ( pktAfter );
		DEBUG_TRACE3( "\n%s: Insert seq:%u  after: %u", StreamToString(stream), (unsigned int) seq - stream->initial_seq, 
			(unsigned int) seq_after - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
	}
#endif

	pktInsert->prev = pktAfter;
	pktInsert->next = pktAfter->next;
	pktAfter->next = pktInsert;

	if( pktInsert->next ) { pktInsert->next->prev = pktInsert; }
	if( pktAfter == stream->pktTail ) { stream->pktTail = pktInsert; }
	CountPktIn(stream, pktInsert);
}


static void StreamInsertBefore( TcpStream* stream, DSSL_Pkt* pktInsert, DSSL_Pkt* pktBefore )
{
	_ASSERT( pktBefore && pktInsert && stream );

	if(pktBefore->prev && PktNextTcpSeqExpected(pktBefore->prev) > PKT_TCP_SEQ(pktInsert) )
	{
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Overlapping packet seq:%u, len %d", StreamToString(stream), 
			PKT_TCP_SEQ( pktInsert ) - stream->initial_seq, pktInsert->data_len );
		DEBUG_TRACE2( " between seq:%u, len %d", PKT_TCP_SEQ(pktBefore->prev)- stream->initial_seq, pktBefore->prev->data_len );
		DEBUG_TRACE2( " and seq:%u, len %d", PKT_TCP_SEQ(pktBefore)- stream->initial_seq, pktBefore->data_len );
#endif
		return;
	}

	/* clone packet because it can be allocated on stack and we 
	   want it to live in a queue */
	pktInsert = PktClone( pktInsert );

#ifdef NM_TRACE_TCP_STREAMS
	{
		uint32_t seq = PKT_TCP_SEQ( pktInsert );
		uint32_t seq_before = PKT_TCP_SEQ( pktBefore );
		DEBUG_TRACE3( "\n%s: Insert seq:%u  before: %u", StreamToString(stream),
			(unsigned int)seq- stream->initial_seq,
			(unsigned int)seq_before - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
	}
#endif

	pktInsert->prev = pktBefore->prev;

	if( pktBefore->prev )
	{
		_ASSERT( pktBefore->prev->next == pktBefore );
		pktBefore->prev->next = pktInsert;
	}
	else
	{
		_ASSERT( pktBefore == stream->pktHead );
		stream->pktHead = pktInsert;
	}

	pktBefore->prev = pktInsert;
	pktInsert->next = pktBefore;

	CountPktIn(stream, pktInsert);
}


TcpStream* StreamGetPeer( const TcpStream* stream )
{
	if( stream == &stream->session->clientStream)
		return &stream->session->serverStream;
	else if( stream == &stream->session->serverStream )
		return &stream->session->clientStream;
	else
	{
		_ASSERT(0);
		return NULL;
	}
}

int FindPacketAckTime( const TcpStream* stream, DSSL_Pkt* pkt)
{
		uint32_t pkt_seq = PktNextTcpSeqExpected(pkt);
	TcpStream* peer_stream = StreamGetPeer( stream );
	if( !peer_stream || !(peer_stream->flags & DSSL_TCPSTREAM_SENT_SYN) ) return 0;

	/* if the packet ACK time hasn't been set explicitly, use peer stream's ACK pool to figure out*/
	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt) )
	{
		TcpStream* peer = StreamGetPeer(stream);
		int i = 0;

		_ASSERT(peer);
		for(i = 0; i < DSSL_ACK_TIME_BUFFER_SIZE; ++i)
		{
			int idx = ( peer->ack_idx + i ) % DSSL_ACK_TIME_BUFFER_SIZE;
			if( peer->acks[idx].seq >= pkt_seq )
			{
				pkt->ack_time = peer->acks[idx].ack_time;
				return 1;
			}
		}
	}

	/* if still not ACK'ed, try peeking at the peer stream's reassembly queue */
	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt) )
	{
		TcpStream* peer = StreamGetPeer(stream);
		DSSL_Pkt* peer_pkt = peer->pktHead;

		while( peer_pkt )
		{
			if( PKT_TCP_ACK( peer_pkt ) >= pkt_seq )
			{
				pkt->ack_time = peer_pkt->pcap_header.ts;
				return 1;
			}

			peer_pkt = peer_pkt->next;
		}
	}

	return 0;
}

/* return the index of packet in the queue that acknowledges the given sequence (seq) */
static int GetAcknowledgingPacketIndex( const DSSL_Pkt* queue_head, uint32_t seq)
{
	int ack_idx = -1;
	int idx = 0;
	const DSSL_Pkt* pkt = queue_head;
	while( pkt && ack_idx == -1) {
		if(PKT_HAS_TCP_ACK(pkt)) {
			if(PKT_TCP_ACK(pkt) >= seq) 
				ack_idx = idx;
		}
		pkt = pkt->next;
		idx++;
	}

	return ack_idx;
}

static int IsDeadlocked( const TcpStream* stream )
{
	/*return 0;*/
	const TcpStream* peer = NULL;
	if(!stream)	{
		_ASSERT(stream != NULL);
		return 0;
	}

	peer = StreamGetPeer( stream );
	if( peer == NULL) {
		_ASSERT( peer != NULL );
		return 0;
	}

	/* 
	streams are "deadlocked" only if more than one packet is queued
	and the first packets in the queue is acknowledged by 2-nd or higher packet 
	in the peer stream's queue 
	*/
	if(peer->queue_size < 2 || stream->queue_size < 2) 
		return 0;

	if(peer->nextSeqExpected != PKT_TCP_SEQ(peer->pktHead) || stream->nextSeqExpected != PKT_TCP_SEQ(stream->pktHead) )
		return 0;

	if(IsNextPacket(peer, peer->pktHead))
		return 0;

	/* Tcp reassembly is deadlocked if both streams in the session has packets in front of the reassembly
	queue waiting for acknowledgement, while blocking each other's acknowledging packets.
	This is a symmetrical condition, so we favor the stream that has the earlier packet in
	front of the reassembly queue */
	return GetAcknowledgingPacketIndex(peer->pktHead, PktNextTcpSeqExpected(stream->pktHead)) > 0 &&
		GetAcknowledgingPacketIndex(stream->pktHead, PktNextTcpSeqExpected(peer->pktHead)) > 0 &&
		PktCompareTimes(stream->pktHead, peer->pktHead) < 0;
}

int IsPacketAcknowledged( const TcpStream* stream, const DSSL_Pkt* pkt )
{
	TcpStream* peer_stream = StreamGetPeer( stream );
	_ASSERT(peer_stream);

	if(PktNextTcpSeqExpected(pkt) <= peer_stream->lastPacketAck)
		return 1;
	/* check if the first packet in peer stream's queue acks this one */
	if( peer_stream->pktHead )
	{
		int acked = PKT_TCP_ACK(peer_stream->pktHead) >= PktNextTcpSeqExpected(pkt);
		return acked && PktCompareTimes( pkt, peer_stream->pktHead ) < 0;
	}
	return 0;
}

static int IsNextPacket( const TcpStream* stream, const DSSL_Pkt* pkt )
{
	uint32_t seq = PKT_TCP_SEQ( pkt );
	TcpStream* peer_stream = StreamGetPeer( stream );
	
	if( !peer_stream || !(peer_stream->flags & DSSL_TCPSTREAM_SENT_SYN) ) return 0;
	if( (stream->nextSeqExpected == seq ) && IsPacketAcknowledged(stream, pkt) )
	{
		if( PKT_HAS_TCP_ACK(pkt) && pkt->data_len != 0 )
		{
			uint32_t ack = PKT_TCP_ACK(pkt);
			if( ack <= peer_stream->nextSeqExpected )
				return 1;
			else
				return 0;
		}
		else
			return 1;
	}
	else
	{
		return 0;
	}
}

#define PREPROC_ACTION_CLOSE			1

static uint32_t PreProcessPacket( DSSL_Pkt* pkt )
{
	int dir;
	TcpStream* sender, *receiver;
	int th_pkt_flags;
	//uint32_t th_seq;
	TcpSession* sess = pkt->session;

	dir = SessionGetPacketDirection( sess, pkt );
	if( dir == ePacketDirInvalid ) {
		_ASSERT( dir != ePacketDirInvalid );
		return PREPROC_ACTION_CLOSE;
	}

	if( dir == ePacketDirFromClient ) {
		sender = &sess->clientStream;
		receiver = &sess->serverStream;
	} else if( dir == ePacketDirFromServer ) {
		sender = &sess->serverStream;
		receiver = &sess->clientStream;
	} else {
		_ASSERT( FALSE );
		return PREPROC_ACTION_CLOSE;
	}

	th_pkt_flags = pkt->tcp_header->th_flags;
	//th_seq = ntohl( pkt->tcp_header->th_seq );

	if( th_pkt_flags & TH_RST ) {
		sender->flags |= DSSL_TCPSTREAM_SENT_RST; 
		return PREPROC_ACTION_CLOSE;
	}

	if( th_pkt_flags & TH_SYN ) {
		sender->flags |= DSSL_TCPSTREAM_SENT_SYN; 
	}
	if( th_pkt_flags & TH_FIN ) {
		sender->flags |= DSSL_TCPSTREAM_SENT_FIN;
	}
	if( (sender->flags & DSSL_TCPSTREAM_SENT_FIN) && (receiver->flags & DSSL_TCPSTREAM_SENT_FIN) ) {
		return PREPROC_ACTION_CLOSE;
	}

	return 0;
}

static void StreamUpdateACK( TcpStream* stream, uint32_t new_ack, struct timeval* ack_time )
{
	TcpStream* peer = StreamGetPeer( stream );
	stream->lastPacketAck = new_ack;
	stream->lastPacketAckTime = (*ack_time);
	_ASSERT(ack_time);

	/* store ack packet time in the buffer */
	stream->acks[stream->ack_idx].seq = new_ack;
	stream->acks[stream->ack_idx].ack_time = (*ack_time);
	++ stream->ack_idx; if( stream->ack_idx == DSSL_ACK_TIME_BUFFER_SIZE ) stream->ack_idx = 0;

	/* check if this is the first ACK packet and set the peer's first_ack_time accordingly */
	if(peer && (peer->flags & DSSL_TCPSTREAM_SENT_SYN) && peer->initial_seq + 1 == new_ack)
	{
		peer->first_ack_time = *ack_time;
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Stream's first ACK time set: %ld:%ld", StreamToString(peer), 
			ack_time->tv_sec, ack_time->tv_usec );
#endif
	}

	/* update the ACK timestamp of any packet that is now acked */
	if( peer ) 
	{
		DSSL_Pkt* pkt = peer->pktHead;
		while( pkt )
		{
			if( PktNextTcpSeqExpected(pkt) <= new_ack )
			{
				if(pkt->ack_time.tv_sec == 0  && pkt->ack_time.tv_usec == 0)
					pkt->ack_time = *ack_time;
				if(PktNextTcpSeqExpected(pkt) == new_ack)
					pkt->flags |= DSSL_PKT_ACK_MATCH; /* exact ACK match found */
			}
			else
			{
				break;
			}
			pkt = pkt->next;
		}
	}
}

static int StreamConsumePacket( TcpStream* stream, DSSL_Pkt* pkt, int* new_ack )
{	
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Consuming seq:%u, len: %d", StreamToString(stream), 
			PKT_TCP_SEQ( pkt )- stream->initial_seq, pkt->data_len );
		DEBUG_TRACE2( " q size=%u ack=%u", stream->queue_size, (uint32_t)PKT_TCP_ACK(pkt) - StreamGetPeer(stream)->initial_seq);
#endif
	_ASSERT( new_ack );

	/* pre-process packet (TCP state change, session closure) */
	if( PreProcessPacket(pkt) == PREPROC_ACTION_CLOSE)
	{
		stream->session->closing = 1;
	}

	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt) )
	{
		FindPacketAckTime( stream, pkt );
	}

#ifdef NM_TRACE_TCP_STREAMS
	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt))
	{
		DEBUG_TRACE0(" not acked ");
	}
#endif

	/* update packet statistics */
	if( pkt->data_len )
	{
		++ stream->stats.data_pkt_count;
	}
	else if( PKT_HAS_TCP_ACK(pkt) ) 
	{
		++ stream->stats.ack_pkt_count;
	}

	stream->nextSeqExpected = PktNextTcpSeqExpected(pkt);
	stream->session->packet_time = pkt->pcap_header.ts;
	if( PKT_HAS_TCP_ACK(pkt) ) 
	{
		uint32_t pkt_ack = PKT_TCP_ACK(pkt);
		if( stream->lastPacketAck != pkt_ack ) 
		{ 
			(*new_ack) = 1;
		}
		if(stream->lastPacketAck < pkt_ack ) 
		{ 
			StreamUpdateACK(stream, pkt_ack, &pkt->pcap_header.ts);
		}
#ifdef NM_TRACE_TCP_STREAMS
		else if(stream->lastPacketAck > pkt_ack)
		{
			DEBUG_TRACE2( " ===> OLD ACK %u, already know: %u", PKT_TCP_ACK(pkt) - StreamGetPeer(stream)->initial_seq,
				stream->lastPacketAck - StreamGetPeer(stream)->initial_seq);
		}
#endif
	}

#ifdef NM_TRACE_TCP_STREAMS
	if( *new_ack ) { DEBUG_TRACE0( " New ACK" ); }
#endif

	/* if packet has data, invoke the callback routine */
	if( pkt->data_len )
	{
		return stream->session->OnNewPacket( stream, pkt );
	}
	else
	{
		return DSSL_RC_OK;
	}
}

static int StreamEnqueue( TcpStream* stream, DSSL_Pkt* pkt )
{
	DSSL_Pkt* p = NULL;
	uint32_t seq = PKT_TCP_SEQ( pkt );
	int processed = 0;

	/* check if reassembly queue limit is reached for this session */
	if( stream->queue_size + 1 >= DSSL_STREAM_MAX_REASSEMBLY_DEPTH )
	{
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE1( "\n%s: Error: reassembly queue limit reached, dropping the session", StreamToString(stream));
#endif
		pkt->session->closing = 1;
		return NM_ERROR( DSSL_E_TCP_REASSEMBLY_QUEUE_FULL );
	}

	/* check if global reassembly queue limit is reached */
	if( stream->session && stream->session->env)
	{
		dssl_SessionTable* tbl = stream->session->env->sessions;
		_ASSERT(tbl);
		if( tbl->maxCachedPacketCount > 0 && tbl->packet_cache_count >= tbl->maxCachedPacketCount)
		{
			pkt->session->closing = 1;
			return NM_ERROR( DSSL_E_TCP_GLOBAL_REASSEMBLY_QUEUE_LIMIT );
		}
	}

	if( seq < stream->nextSeqExpected )
	{
		/* update packet statistics */
		++ stream->stats.retrans_pkt_count;
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Dropping a packet (retransmission), seq:%u, next_seq: %u",
			StreamToString(stream), seq- stream->initial_seq, stream->nextSeqExpected - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
#endif
		return DSSL_RC_OK;
	}

	if( seq == stream->nextSeqExpected && stream->lastPacketAck < PKT_TCP_ACK(pkt))
	{
		stream->lastPacketAck = PKT_TCP_ACK(pkt);
		stream->lastPacketAckTime = pkt->pcap_header.ts;
	}

	/* simple case - first packet in the list */
	if( stream->pktHead == NULL )
	{
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE2( "\n%s: Adding the head at seq:%u", StreamToString(stream), seq - stream->initial_seq);
#endif
		_ASSERT( stream->pktTail == NULL);
		
		p = PktClone( pkt );
		p->next = p->prev = NULL;
		stream->pktHead = stream->pktTail = p;
		processed = 1;
		_ASSERT( !stream->queue_size ); 
		CountPktIn(stream, p);
	}
	else if( seq == PktNextTcpSeqExpected( stream->pktTail ) )
	{
		/* special case - packet right next to the current tail */
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE2( "\n%s: Adding to the tail at seq:%u", StreamToString(stream), seq - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
#endif
		StreamInsertAfter( stream, pkt, stream->pktTail );
		processed = 1;
	}
	else
	{
		p = stream->pktHead;
		/* find where this packet fits */
		while( p && !processed )
		{
			uint32_t seq_p = PKT_TCP_SEQ( p );
			if( seq_p <= seq && seq_p + p->data_len >= seq )
			{
				if( p->data_len != 0 )
				{
					/* multiple data packets at this seq number, probably retransmission */
				#ifdef NM_TRACE_TCP_STREAMS
					DEBUG_TRACE3( "\n%s: Dropping retransmission, seq:%u, len: %d", 
						StreamToString(stream), seq - stream->initial_seq, (int) pkt->data_len );
					DEBUG_TRACE1( " q size=%u", stream->queue_size);
				#endif
					/* update packet statistics */
					++ stream->stats.retrans_pkt_count;
				}
				else
				{
					/* this is an ACK packet, insert the data packet after it */
					StreamInsertAfter( stream, pkt, p );
				}
				processed = 1;
			}
			else if( seq_p > seq )
			{
				/* Insert in front*/
				StreamInsertBefore( stream, pkt, p );
				processed = 1;
			}
			else
			{
				p = p->next;
			}
		}

		/* add to the tail */
		if( !processed )
		{
			StreamInsertAfter( stream, pkt, stream->pktTail );
			processed = 1;
		}
	}

	_ASSERT( processed );
	return DSSL_RC_OK;
}


static DSSL_Pkt* StreamDequeue( TcpStream* stream )
{
	DSSL_Pkt* retval = stream->pktHead;
	
	if( stream->pktHead ) { stream->pktHead = stream->pktHead->next; }
	if( stream->pktHead ) {
		stream->pktHead->prev = NULL;
	} else {
		stream->pktTail = NULL;
	}


	if(retval) 
	{
		_ASSERT( stream->queue_size ); 
		CountPktOut(stream, retval);
	}
	else
	{
		_ASSERT( !stream->queue_size ); 
	}

	return retval;
}


static NM_PacketDir StreamGetPacketDirection( TcpStream* stream )
{
	if( stream == &stream->session->clientStream )
		return ePacketDirFromClient;
	else if( stream == &stream->session->serverStream )
		return ePacketDirFromServer;
	else {
		_ASSERT( FALSE );
		return ePacketDirInvalid;
	}
}


int IsPacketTimeout(TcpStream* stream, DSSL_Pkt* pkt, struct timeval *tv)
{
	TcpSession* s = stream->session;
	_ASSERT(s);

	if( s->missing_packet_timeout && pkt->pcap_header.ts.tv_sec - tv->tv_sec 
		> s->missing_packet_timeout )
		return 1;
	
	return 0;
}


int StreamHasMissingPacket(TcpStream* stream, DSSL_Pkt* pkt)
{
	TcpSession* s = stream->session;
	_ASSERT(s);

	if( s->type != eSessionTypeTcp && s->type != eSessionTypeTBD) return 0;
	if( s->missing_callback == NULL ) return 0;
	if( stream->pktHead == NULL ) {
		if( s->type == eSessionTypeTBD &&
			( (stream->flags & DSSL_TCPSTREAM_SENT_SYN) ) &&
			IsPacketTimeout(stream, pkt, &stream->syn_time) )
			return 1;
		/* if we sent a FIN/RST and nothing came back */
		if( s->type == eSessionTypeTcp && 
			( (stream->flags & (DSSL_TCPSTREAM_SENT_FIN | DSSL_TCPSTREAM_SENT_RST)) ) &&
			IsPacketTimeout(stream, pkt, &stream->lastPacketAckTime) )
			return 1;
		return 0;
	}
	if( IsPacketTimeout(stream, pkt, &stream->pktHead->pcap_header.ts) )
		return 1;
	if( PKT_TCP_SEQ(stream->pktHead) == stream->nextSeqExpected) return 0;
	if( s->missing_packet_count && stream->queue_size >= s->missing_packet_count ) 
		return 1;

	return 0;
}


int StreamConsumeHeadOverlap( TcpStream* stream, int* new_ack, int data_to_proc )
{
	int rc = DSSL_RC_OK;
	DSSL_Pkt* p = NULL;
	DSSL_Pkt* pClone = NULL;
	
	/* safety check - max possible tcp segment*/
	if(data_to_proc > 65535) {
		return NM_ERROR(DSSL_E_INVALID_PARAMETER);
	}

	p = StreamDequeue( stream );

#ifdef NM_TRACE_TCP_STREAMS
	DEBUG_TRACE4( "\n  %s:Processing the last %d bytes from a packet seq:%u", StreamToString(stream), 
		data_to_proc, PKT_TCP_SEQ( p )- stream->initial_seq, p->data_len );
#endif

	rc = PktCloneChunk(p, data_to_proc, &pClone);
	if(rc != DSSL_RC_OK) return rc;

	/* packets are cloned when they are put into the queue, 
		so they should be freed after been done with */
	PktFree(p); p = NULL;
	if(pClone == NULL) {
		return NM_ERROR(DSSL_E_OUT_OF_MEMORY);
	}

	rc = StreamConsumePacket( stream, pClone, new_ack );
	/* free the clone too */
	PktFree(pClone);
	return rc;
}

int StreamConsumeHead( TcpStream* stream, int* new_ack )
{
	int rc = DSSL_RC_OK;
	DSSL_Pkt* p = StreamDequeue( stream );

#ifdef NM_TRACE_TCP_STREAMS
	DEBUG_TRACE3( "\n  %s:Processing a packet seq:%u, len: %d", StreamToString(stream), 
		PKT_TCP_SEQ( p )- stream->initial_seq, p->data_len );
#endif

	rc = StreamConsumePacket( stream, p, new_ack );
	/* 
		packets are cloned when they are put into the queue, 
		so they should be freed here 
	*/
	PktFree(p); 
	return rc;
}

/*
========================================================
	StreamProcessPacket: Main packet processing routine 
========================================================
*/
int StreamProcessPacket( TcpStream* stream, DSSL_Pkt* pkt, int* new_ack )
{
	int rc = DSSL_RC_OK;
	
	/* SYN packet - process right away */
	if( pkt->tcp_header->th_flags & TH_SYN )
	{
		_ASSERT( stream->initial_seq == 0 || stream->initial_seq == PKT_TCP_SEQ(pkt));
		_ASSERT( pkt->data_len == 0 );
		/* set initial stream metrics */
		stream->initial_seq = PKT_TCP_SEQ(pkt);
		stream->syn_time = pkt->pcap_header.ts;

		/* check if this is SYN+ACK packet and SYN packet was missing */
		if(pkt->tcp_header->th_flags & TH_ACK && StreamGetPeer(stream))
		{
			TcpStream* peer = StreamGetPeer(stream);
			if(peer->initial_seq == 0 && !(peer->flags & DSSL_TCPSTREAM_SENT_SYN))
			{
				#ifdef NM_TRACE_TCP_STREAMS
					DEBUG_TRACE1("\n%s: missing or out-of-order SYN detected", StreamToString(peer));
				#endif
				peer->initial_seq = PKT_TCP_ACK(pkt);
				peer->nextSeqExpected = peer->initial_seq;
				peer->flags |= DSSL_TCPSTREAM_SENT_SYN;
			}
		}
		return StreamConsumePacket( stream, pkt, new_ack );
	}

	/* check for missing SYN,ACK packet */
	if(stream->initial_seq == 0)
	{
		const TcpStream* peer = StreamGetPeer( stream );
		/*check if this packet ACKs peer stream's initial TCP sequence */
		if(peer && (peer->flags & DSSL_TCPSTREAM_SENT_SYN) && peer->pktHead)
		{
			DSSL_Pkt* ph = peer->pktHead;
			_ASSERT( PKT_TCP_SEQ(ph) == peer->initial_seq + 1 ); /*must be the first ACK packet*/
		#ifdef NM_TRACE_TCP_STREAMS
			DEBUG_TRACE1("\n%s: missing SYN+ACK detected", StreamToString(stream));
		#endif
			stream->initial_seq = PKT_TCP_ACK(ph);
			stream->nextSeqExpected = stream->initial_seq;
			stream->flags |= DSSL_TCPSTREAM_SENT_SYN;
		}
	}

	/* is this the next packet in sequence? */
	if( IsNextPacket( stream, pkt ) )
	{
		rc = StreamConsumePacket( stream, pkt, new_ack );
	}
	else
	{
		_ASSERT( !(pkt->tcp_header->th_flags & TH_SYN) );
		rc = StreamEnqueue( stream, pkt );

		if( rc == DSSL_RC_OK && StreamHasMissingPacket(stream, pkt) )
		{
			uint32_t len = 0; int retcode = 0;
			/* must be at least one packet in the queue */
			_ASSERT( stream->pktHead );

			if ((PKT_TCP_SEQ( stream->pktHead ) > stream->nextSeqExpected) || IsPacketTimeout(stream, pkt, &stream->pktHead->pcap_header.ts)) {
				len = PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected;
				
				#ifdef NM_TRACE_TCP_STREAMS
				DEBUG_TRACE3("\n%s: missing packet found at seq: %u, len = %u", StreamToString(stream), 
					PKT_TCP_SEQ(stream->pktHead), len );
				#endif
				
				retcode = stream->session->missing_callback( StreamGetPacketDirection(stream),
					stream->session->user_data, PKT_TCP_SEQ( stream->pktHead ), len );
				if( retcode ) {
					rc = StreamConsumeHead( stream, new_ack );
				} else {
					pkt->session->closing = 1;
					rc = NM_ERROR( DSSL_E_TCP_MISSING_PACKET_DETECTED );
				}
			} else {
				/* a packet on top of the reassembly queue 
				 has lower SEQ number than the next expected packet SEQ */
				int headNextSeq = PktNextTcpSeqExpected(stream->pktHead);

				if(headNextSeq <= (int)stream->nextSeqExpected) {
					/* this is a retranmission packet, dump it */
					StreamDiscardHead(stream);
				} else {
					int dataToProc = PKT_TCP_SEQ(stream->pktHead) + 
						stream->pktHead->data_len - stream->nextSeqExpected;
					if(dataToProc > 0) {
						rc = StreamConsumeHeadOverlap(stream, new_ack, dataToProc);
					}
				}
			}
		}
	}

	if( rc == DSSL_RC_OK ) rc = StreamPollPackets( stream, new_ack );

	return rc;
}

int StreamPollPackets( TcpStream* stream, int* new_ack )
{
	int rc = DSSL_RC_OK;
	int hit = 0;
	while( rc == DSSL_RC_OK && stream->pktHead && IsNextPacket( stream, stream->pktHead ) )
	{
		rc = StreamConsumeHead( stream, new_ack );
#ifdef NM_TRACE_TCP_STREAMS
		hit = 1;
#endif
	}

#ifdef NM_TRACE_TCP_STREAMS
	{
		uint32_t headSeq = stream->pktHead ? PKT_TCP_SEQ( stream->pktHead ) : stream->initial_seq;
		uint32_t peerInitSec = StreamGetPeer(stream)->initial_seq;
		uint32_t headAck = stream->pktHead ? PKT_TCP_ACK( stream->pktHead ) - peerInitSec : 0;
		if(!hit)  DEBUG_TRACE1("\n   %s no packets dequeued", StreamToString(stream));
		DEBUG_TRACE3( "|| Next seq: %u, head: (s:%u ack:%u)", stream->nextSeqExpected - stream->initial_seq, 
			headSeq - stream->initial_seq, headAck);
	}
#endif
	
	if(rc == DSSL_RC_OK && !hit && IsDeadlocked(stream)) {
#ifdef NM_TRACE_TCP_STREAMS
		DEBUG_TRACE1("\n %s - deadlock detected, processing the front of the queue", StreamToString(stream) );
#endif
		rc = StreamConsumeHead(stream, new_ack );
		/* force processing of other half of the TCP stream as well */
		if( rc == DSSL_RC_OK ) *new_ack = 1;
	}

	return rc;
}

static void StreamDiscardHead(TcpStream* stream)
{
	DSSL_Pkt* p = StreamDequeue( stream );

#ifdef NM_TRACE_TCP_STREAMS
	DEBUG_TRACE3( "\n  %s:Dumping a packet seq:%u, len: %d", StreamToString(stream), 
		PKT_TCP_SEQ( p )- stream->initial_seq, p->data_len );
#endif

	/* 
		packets are cloned when they are put into the queue, 
		so they should be freed here 
	*/
	PktFree(p); 
}

