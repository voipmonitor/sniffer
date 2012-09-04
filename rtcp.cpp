#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>

#include "calltable.h"
#include "rtp.h"

int debug_rtcp = 0;

//#include "rtcp.h"

/*
 * Static part of RTCP header
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|    RC   |       PT      |             length            | header
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

typedef struct rtcp_header {
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t version:2,
		 padding:1,
		 rc_sc:5;
#else
	u_int8_t rc_sc:5,
		 padding:1,
		 version:2;
#endif
	u_int8_t	packet_type;
	u_int16_t length;
} rtcp_header_t;


/*
 * RTCP SR packet type sender info portion
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         SSRC of sender                        |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * |              NTP timestamp, most significant word             | sender
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ info
 * |             NTP timestamp, least significant word             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         RTP timestamp                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     sender's packet count                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      sender's octet count                     |
 * +---------------------------------------------------------------+
 */

typedef struct rtcp_sr_senderinfo
{
	u_int32_t sender_ssrc;
	u_int32_t timestamp_MSW;
	u_int32_t timestamp_LSW;
	u_int32_t timestamp_RTP;
	u_int32_t sender_pkt_cnt;
	u_int32_t sender_octet_cnt;
} rtcp_sr_senderinfo_t;

/*
 * RTCP SR report block
 *
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * |                 SSRC_1 (SSRC of first source)                 | 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 * | fraction lost |       cumulative number of packets lost       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           extended highest sequence number received           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      interarrival jitter                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         last SR (LSR)                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   delay since last SR (DLSR)                  |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 */

typedef struct rtcp_sr_reportblock
{
	u_int32_t ssrc;
	u_int8_t	frac_lost;
	u_int8_t	packets_lost[3];
	u_int32_t ext_seqno_recvd;
	u_int32_t jitter;
	u_int32_t lsr;
	u_int32_t delay_since_lsr;
} rtcp_sr_reportblock_t;


/* 
 * RTCP packet type definitions 
 */

#define RTCP_PACKETTYPE_SR	200
#define RTCP_PACKETTYPE_RR	201
#define RTCP_PACKETTYPE_SDES	202
#define RTCP_PACKETTYPE_BYE	203
#define RTCP_PACKETTYPE_APP	204

/*
 * RTCP payload type map
 */
#if 0
typedef struct strmap {
	u_int32_t number;
	char * string;
} strmap_t;

strmap_t rtcp_packettype_map[] =
{
	{ RTCP_PACKETTYPE_SR,				"sender report" },
	{ RTCP_PACKETTYPE_RR,				"receiver report" },
	{ RTCP_PACKETTYPE_SDES,			"source description" },
	{ RTCP_PACKETTYPE_BYE,			 "bye" },
	{ RTCP_PACKETTYPE_APP,			 "application" },
	{ 0, ""}
};
#endif

extern struct arg_t * my_args;

/*----------------------------------------------------------------------------
**
** dump_rtcp_sr()
**
** Parse RTCP sender report fields
**
**----------------------------------------------------------------------------
*/

char *dump_rtcp_sr(char *data, unsigned int datalen, int count, Call *call)
{
	char *pkt = data;
	rtcp_sr_senderinfo_t *senderinfo;
	rtcp_sr_reportblock_t *reportblock;
	int reports_seen;

	/* Get the sender info */
	if((pkt + sizeof(rtcp_sr_senderinfo_t)) < (data + datalen)){
		senderinfo = (rtcp_sr_senderinfo_t *)pkt;
		pkt += sizeof(rtcp_sr_senderinfo_t);
	} else {
		return pkt;
	}

	/* Conversions */
	senderinfo->sender_ssrc = ntohl(senderinfo->sender_ssrc);
	senderinfo->timestamp_MSW = ntohl(senderinfo->timestamp_MSW);
	senderinfo->timestamp_LSW = ntohl(senderinfo->timestamp_LSW);
	senderinfo->timestamp_RTP = ntohl(senderinfo->timestamp_RTP);
	senderinfo->sender_pkt_cnt = ntohl(senderinfo->sender_pkt_cnt);
	senderinfo->sender_octet_cnt = ntohl(senderinfo->sender_octet_cnt);
	
	if(debug_rtcp) {
		printf("Sender SSRC [%x]\n", senderinfo->sender_ssrc);
		printf("Timestamp MSW [%u]\n", senderinfo->timestamp_MSW);
		printf("Timestamp LSW [%u]\n", senderinfo->timestamp_LSW);
		printf("RTP timestamp [%u]\n", senderinfo->timestamp_RTP);
		printf("Sender packet count [%u]\n", senderinfo->sender_pkt_cnt);
		printf("Sender octet count [%u]\n", senderinfo->sender_octet_cnt);
	}
	
	/* Loop over report blocks */
	reports_seen = 0;
	while(reports_seen < count) {
		/* Get the report block */
		if((pkt + sizeof(rtcp_sr_reportblock_t)) < (data + datalen)){
			reportblock = (rtcp_sr_reportblock_t *)pkt;
			pkt += sizeof(rtcp_sr_reportblock_t);
		} else {
			break;
		}
			
		/* Conversions */
		reportblock->ssrc = ntohl(reportblock->ssrc);
		reportblock->ext_seqno_recvd = ntohl(reportblock->ext_seqno_recvd);
		reportblock->jitter = ntohl(reportblock->jitter);
		reportblock->lsr = ntohl(reportblock->lsr);
		reportblock->delay_since_lsr = ntohl(reportblock->delay_since_lsr);

		RTP *rtp = NULL;

		for(int i = 0; i < call->ssrc_n; i++) {
			if(call->rtp[i]->ssrc == reportblock->ssrc) {
				// found 
				rtp = call->rtp[i];
			}
		}
	
	
		int loss = ((int)reportblock->packets_lost[2]) << 16;
		loss |= ((int)reportblock->packets_lost[1]) << 8;
		loss |= (int)reportblock->packets_lost[0];

		if(rtp) {
			rtp->rtcp.counter++;
			rtp->rtcp.loss = loss;
			rtp->rtcp.maxfr = (rtp->rtcp.maxfr < reportblock->frac_lost) ? reportblock->frac_lost : rtp->rtcp.maxfr;
			rtp->rtcp.avgfr = (rtp->rtcp.avgfr * (rtp->rtcp.counter - 1) + reportblock->frac_lost) / rtp->rtcp.counter;
			rtp->rtcp.maxjitter = (rtp->rtcp.maxjitter < reportblock->jitter) ? reportblock->jitter : rtp->rtcp.maxjitter;
			rtp->rtcp.avgjitter = (rtp->rtcp.avgjitter * (rtp->rtcp.counter - 1) + reportblock->jitter) / rtp->rtcp.counter;
		} 

		if(debug_rtcp) {
			printf("sSSRC [%x]", reportblock->ssrc);
			printf("	Fraction lost [%u]\n", reportblock->frac_lost);
			printf("	Packets lost [%d]\n", loss);
			printf("	Highest seqno received [%d]\n", reportblock->ext_seqno_recvd);
			printf("	Jitter [%u]\n", reportblock->jitter);
			printf("	Last SR [%u]\n", reportblock->lsr);
			printf("	Delay since last SR [%u]\n", reportblock->delay_since_lsr);
		}

		reports_seen++;
	}
	return pkt;
}

/*----------------------------------------------------------------------------
**
** dump_rtcp_rr()
**
** Parse RTCP receiver report fields
**
**----------------------------------------------------------------------------
*/

char *dump_rtcp_rr(char *data, int datalen, int count, Call *call)
{
	char *pkt = data;
	rtcp_sr_reportblock_t *reportblock;
	int	reports_seen;
	u_int32_t *ssrc;

	/* Get the SSRC */
	if((pkt + sizeof(u_int32_t)) < (data + datalen)){
		ssrc = (u_int32_t*)pkt;
		pkt += sizeof(u_int32_t);
	} else {
		return pkt;
	}

	/* Conversions */
	*ssrc = ntohl(*ssrc);

	if(debug_rtcp) {
		printf("SSRC [%u]\n", *ssrc);
	}

	/* Loop over report blocks */
	reports_seen = 0;
	while(reports_seen < count) {
		/* Get the report block */
		if((pkt + sizeof(rtcp_sr_reportblock_t)) < (data + datalen)){
			reportblock = (rtcp_sr_reportblock_t *)pkt;
			pkt += sizeof(rtcp_sr_reportblock_t);
		} else {
			break;
		}

		/* Conversions */
		reportblock->ssrc = ntohl(reportblock->ssrc);
		reportblock->ext_seqno_recvd = ntohl(reportblock->ext_seqno_recvd);
		reportblock->jitter = ntohl(reportblock->jitter);
		reportblock->lsr = ntohl(reportblock->lsr);
		reportblock->delay_since_lsr = ntohl(reportblock->delay_since_lsr);

		RTP *rtp = NULL;

		for(int i = 0; i < call->ssrc_n; i++) {
			if(call->rtp[i]->ssrc == reportblock->ssrc) {
				// found 
				rtp = call->rtp[i];
			}
		}
	

		int loss = ((int)reportblock->packets_lost[2]) << 16;
		loss |= ((int)reportblock->packets_lost[1]) << 8;
		loss |= (int)reportblock->packets_lost[0];

		if(rtp) {
			rtp->rtcp.counter++;
			rtp->rtcp.loss = loss;
			rtp->rtcp.maxfr = (rtp->rtcp.maxfr < rtp->rtcp.maxfr) ? reportblock->frac_lost : rtp->rtcp.maxfr;
			rtp->rtcp.avgfr = (rtp->rtcp.avgfr * (rtp->rtcp.counter - 1) + reportblock->frac_lost) / rtp->rtcp.counter;
			rtp->rtcp.maxjitter = (rtp->rtcp.maxjitter < rtp->rtcp.maxjitter) ? reportblock->jitter : rtp->rtcp.maxjitter;
			rtp->rtcp.avgjitter = (rtp->rtcp.avgjitter * (rtp->rtcp.counter - 1) + reportblock->jitter) / rtp->rtcp.counter;
		} 

		if(debug_rtcp) {
			printf("rSSRC [%x]", reportblock->ssrc);
			printf("	Fraction lost [%u]\n", reportblock->frac_lost);
			printf("	Packets lost [%d]\n", loss);
			printf("	Highest seqno received [%u]\n", reportblock->ext_seqno_recvd);
			printf("	Jitter [%u]\n", reportblock->jitter);
			printf("	Last SR [%u]\n", reportblock->lsr);
			printf("	Delay since last SR [%u]\n", reportblock->delay_since_lsr);
		}

		reports_seen++;
	}
	return pkt;
}

/*----------------------------------------------------------------------------
**
** dump_rtcp_sdes()
**
** Parse RTCP source description fields
**
**----------------------------------------------------------------------------
*/

void dump_rtcp_sdes(char *data, unsigned int datalen, int count)
{
	char *pkt = data;
	u_int32_t	*ssrc;
	u_int8_t	 type;
	u_int8_t	 length;
	u_int8_t * string;
	int				chunks_read;
	int				pad_len;

	chunks_read = 0;
	while((pkt < (data + datalen)) && chunks_read < count) {
		/* Get the ssrc, type and length */
		if((pkt + sizeof(u_int32_t)) < (data + datalen)){
			ssrc = (u_int32_t*)pkt;
			pkt += sizeof(u_int32_t);
		} else {
			break;
		}
		*ssrc = ntohl(*ssrc);
		if(debug_rtcp) {
			printf("SSRC/CSRC [%u]\n", *ssrc);
		}
		/* Loop through items */
		while (1) {
			if((pkt + sizeof(u_int8_t)) < (data + datalen)){
				type = (u_int8_t)*pkt;
				pkt += sizeof(u_int8_t);
			} else {
				break;
			}
			if((pkt + sizeof(u_int8_t)) < (data + datalen)){
				length = (u_int8_t)*pkt;
				pkt += sizeof(u_int8_t);
			} else {
				break;
			}
			
			/* Allocate memory for the string then get it */
			string = (u_int8_t*)malloc(length + 1);
			if((pkt + length) < (data + datalen)){
				memcpy(string, pkt, length);
				pkt += length;
			} else {
				free(string);
				break;
			}
			string[length] = '\0';
			
			if(debug_rtcp) {
				printf("	Type [%u]\n", type);
				printf("	Length [%u]\n", length);
				printf("	SDES [%s]", string);
			}

			/* Free string memory */
			free(string);
			
			/* Look for a null terminator */
//			if (look_packet_bytes((u_int8_t *) &byte, pkt, 1) == 0)
//				break;
			if((pkt) < (data + datalen)) {
				pkt++;
				if (*pkt == 0) {
					break;
				}
			} else {
				break;
			}
		}

		/* Figure out the pad and skip by it */
		pad_len = 4 - (length + 2) % 4;
		pkt += pad_len;
			
		chunks_read ++;
	}
}

/*----------------------------------------------------------------------------
**
** dump_rtcp()
**
** Parse RTCP packet and dump fields
**
**----------------------------------------------------------------------------
*/

void parse_rtcp(char *data, int datalen, Call* call)
{
	char *pkt = data;
	rtcp_header_t *rtcp;
	u_int8_t			packet_type;
	u_int8_t			padding;
	u_int8_t			version;
	u_int8_t			count;
	u_int16_t		 bytes_remaining;

	while(1){
		/* Get the fixed RTCP header */
		if((pkt + sizeof(rtcp_header_t)) < (data + datalen)){
			rtcp = (rtcp_header_t*)pkt;
			pkt += sizeof(rtcp_header_t);
		} else {
			break;
		}

		/* Conversions */
		packet_type = rtcp->packet_type;
		padding = rtcp->padding;
		version = rtcp->version;
		count = rtcp->rc_sc;
		rtcp->length = ntohs(rtcp->length);
		
		/* Set the number of bytes remaining */
		bytes_remaining = 4 * rtcp->length;
		
		if(debug_rtcp) {
			printf("\nRTCP Header\n");
			printf("Version %d\n", version);
			printf("Padding %d\n", padding);
			printf("Report/source count [%d]\n", count);
			printf("Packet type [%d]\n", packet_type);
			printf("Length [%d]\n", rtcp->length);
		}
			
		switch(packet_type) {
		case RTCP_PACKETTYPE_SR:
			pkt = dump_rtcp_sr(pkt, data + datalen - pkt + 1, count, call);
			break;

		case RTCP_PACKETTYPE_RR:
			pkt = dump_rtcp_rr(pkt, data + datalen - pkt + 1, count, call);
			break;
		case RTCP_PACKETTYPE_SDES:
			dump_rtcp_sdes(pkt, data + datalen - pkt + 1, count);
			break;
		default:
			return;
		}
	}
}
