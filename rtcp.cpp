#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>

#include "calltable.h"
#include "rtp.h"

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
#define RTCP_PACKETTYPE_RTPFB	205
#define RTCP_PACKETTYPE_PSFB	206
#define RTCP_PACKETTYPE_XR	207

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


/*
 * RTCP XR report block type
 */
typedef enum rtcp_xr_report_type_t_ {
    RTCP_XR_LOSS_RLE = 1,  /* Loss RLE report */
    RTCP_XR_DUP_RLE,       /* Duplicate RLE report */
    RTCP_XR_RTCP_TIMES,    /* Packet receipt times report */
    RTCP_XR_RCVR_RTT,      /* Receiver reference time report */
    RTCP_XR_DLRR,          /* DLRR report */
    RTCP_XR_STAT_SUMMARY,  /* Statistics summary report */
    RTCP_XR_VOIP_METRICS,  /* VoIP metrics report */
    RTCP_XR_BT_XNQ,        /* BT's eXtended Network Quality report */
    RTCP_XR_TI_XVQ,        /* TI eXtended VoIP Quality report */
    RTCP_XR_POST_RPR_LOSS_RLE,  /* Post ER Loss RLE report */
    RTCP_XR_MA = 200,           /* Media Acquisition report (avoid */
    RTCP_XR_DC,                 /* Diagnostic Counters report (TBD) */
    NOT_AN_XR_REPORT       /* this MUST always be LAST */
} rtcp_xr_report_type_t;


typedef struct rtcp_xr_header {
	rtcp_header_t ch;
	uint32_t ssrc;
} rtcp_xr_header_t;

/*
 * generic XR report definition
 */
typedef struct rtcp_xr_gen_t_ {
    uint8_t  bt;                /* Report Block Type */
    uint8_t  type_specific;     /* Report Type Specific */
    uint16_t length;            /* Report Length */
} rtcp_xr_gen_t;

typedef struct rtcp_xr_voip_metrics_report_block {
	uint32_t ssrc;
	uint8_t loss_rate;
	uint8_t discard_rate;
	uint8_t burst_density;
	uint8_t gap_density;
	uint16_t burst_duration;
	uint16_t gap_duration;
	uint16_t round_trip_delay;
	uint16_t end_system_delay;
	int8_t signal_level;
	int8_t noise_level;
	uint8_t rerl;
	uint8_t gmin;
	uint8_t r_factor;
	uint8_t ext_r_factor;
	uint8_t mos_lq;
	uint8_t mos_cq;
	uint8_t rx_config;
	uint8_t reserved2;
	uint16_t jb_nominal;
	uint16_t jb_maximum;
	uint16_t jb_abs_max;
} rtcp_xr_voip_metrics_report_block_t;

extern struct arg_t * my_args;
extern unsigned int opt_ignoreRTCPjitter;

/*----------------------------------------------------------------------------
**
** dump_rtcp_sr()
**
** Parse RTCP sender report fields
**
**----------------------------------------------------------------------------
*/

char *dump_rtcp_sr(char *data, unsigned int datalen, int count, Call *call, struct timeval *ts)
{
	char *pkt = data;
	rtcp_sr_senderinfo_t senderinfo;
	rtcp_sr_reportblock_t reportblock;
	int reports_seen;

	/* Get the sender info */
	if((pkt + sizeof(rtcp_sr_senderinfo_t)) < (data + datalen)){
		memcpy(&senderinfo, pkt, sizeof(rtcp_sr_senderinfo_t));
		pkt += sizeof(rtcp_sr_senderinfo_t);
	} else {
		return pkt;
	}

	/* Conversions */
	senderinfo.sender_ssrc = ntohl(senderinfo.sender_ssrc);
	senderinfo.timestamp_MSW = ntohl(senderinfo.timestamp_MSW);
	senderinfo.timestamp_LSW = ntohl(senderinfo.timestamp_LSW);
	senderinfo.timestamp_RTP = ntohl(senderinfo.timestamp_RTP);
	senderinfo.sender_pkt_cnt = ntohl(senderinfo.sender_pkt_cnt);
	senderinfo.sender_octet_cnt = ntohl(senderinfo.sender_octet_cnt);

	u_int32_t cur_lsr = ((senderinfo.timestamp_MSW & 0xffff) << 16) | ((senderinfo.timestamp_LSW & 0xffff0000) >> 16);
	u_int32_t last_lsr = 0;
	u_int32_t last_lsr_delay = 0;
	RTP *rtp_sender = NULL;
	for(int i = 0; i < call->rtp_size(); i++) { RTP *rtp_i = call->rtp_stream_by_index(i);
		if(rtp_i->ssrc == senderinfo.sender_ssrc) {
			rtp_sender = rtp_i;
			rtp_sender->rtcp.lsr4compare = cur_lsr;
			last_lsr = rtp_sender->rtcp.last_lsr;
			last_lsr_delay = rtp_sender->rtcp.last_lsr_delay;
			rtp_sender->rtcp.sniff_ts.tv_sec = ts->tv_sec;
			rtp_sender->rtcp.sniff_ts.tv_usec = ts->tv_usec;
			break;
		}
	}

	if(sverb.debug_rtcp) {
		printf("Sender SSRC [%x]\n", senderinfo.sender_ssrc);
		printf("Timestamp MSW [%u]\n", senderinfo.timestamp_MSW);
		printf("Timestamp LSW [%u]\n", senderinfo.timestamp_LSW);
		printf("RTP timestamp [%u]\n", senderinfo.timestamp_RTP);
		printf("Sender packet count [%u]\n", senderinfo.sender_pkt_cnt);
		printf("Sender octet count [%u]\n", senderinfo.sender_octet_cnt);
	}
	
	/* Loop over report blocks */
	reports_seen = 0;
	while(reports_seen < count) {
		/* Get the report block */
		if((pkt + sizeof(rtcp_sr_reportblock_t)) < (data + datalen)){
			memcpy(&reportblock, pkt, sizeof(rtcp_sr_reportblock_t));
			pkt += sizeof(rtcp_sr_reportblock_t);
		} else {
			break;
		}
			
		/* Conversions */
		reportblock.ssrc = ntohl(reportblock.ssrc);
		reportblock.ext_seqno_recvd = ntohl(reportblock.ext_seqno_recvd);
		reportblock.jitter = ntohl(reportblock.jitter);
		reportblock.lsr = ntohl(reportblock.lsr);
		reportblock.delay_since_lsr = ntohl(reportblock.delay_since_lsr);

		RTP *rtp = NULL;
		for(int i = 0; i < call->rtp_size(); i++) { RTP *rtp_i = call->rtp_stream_by_index(i);
			if(rtp_i->ssrc == reportblock.ssrc) {
				// found 
				rtp = rtp_i;
			}
		}
	
		int32_t loss = ((int32_t)reportblock.packets_lost[2]) << 16;
		loss |= ((int32_t)reportblock.packets_lost[1]) << 8;
		loss |= (int32_t)reportblock.packets_lost[0];
		loss = loss & 0x800000 ? 0xff000000 | loss : loss;

		if(rtp) {
			rtp->rtcp.counter++;
			rtp->rtcp.loss = loss;
			if (reportblock.frac_lost)
				rtp->rtcp.fraclost_pkt_counter++;
			rtp->rtcp.maxfr = (rtp->rtcp.maxfr < reportblock.frac_lost) ? reportblock.frac_lost : rtp->rtcp.maxfr;
			rtp->rtcp.avgfr = (rtp->rtcp.avgfr * (rtp->rtcp.counter - 1) + reportblock.frac_lost) / rtp->rtcp.counter;
			if (opt_ignoreRTCPjitter == 0 or reportblock.jitter < opt_ignoreRTCPjitter) {
				rtp->rtcp.jitt_counter++;
				rtp->rtcp.maxjitter = (rtp->rtcp.maxjitter < reportblock.jitter) ? reportblock.jitter : rtp->rtcp.maxjitter;
				rtp->rtcp.avgjitter = (rtp->rtcp.avgjitter * (rtp->rtcp.jitt_counter - 1) + reportblock.jitter) / rtp->rtcp.jitt_counter;
			}
			// calculate rtcp round trip delay
			if (reportblock.lsr && reportblock.delay_since_lsr && rtp->rtcp.lsr4compare == reportblock.lsr) {
				if (last_lsr && last_lsr_delay && rtp_sender) {
					int tmpdiff = cur_lsr - last_lsr - last_lsr_delay - reportblock.delay_since_lsr;
					if (tmpdiff > 0) {
						rtp_sender->rtcp.rtd_sum += tmpdiff;
						rtp_sender->rtcp.rtd_count++;
						if (rtp_sender->rtcp.rtd_max < (uint)tmpdiff) {
							rtp_sender->rtcp.rtd_max = tmpdiff;
						}
					}
				}
				if (timerisset(&rtp->rtcp.sniff_ts)) {
					struct timeval tmpts;
					timersub(ts, &rtp->rtcp.sniff_ts, &tmpts);
					unsigned int ms = tmpts.tv_sec * 1000 + tmpts.tv_usec / 1000 - reportblock.delay_since_lsr *1000 / 65536;
					if (ms > 0) {
						rtp->rtcp.rtd_w_count++;
						rtp->rtcp.rtd_w_sum += ms;
						if (rtp->rtcp.rtd_w_max < ms) {
							rtp->rtcp.rtd_w_max = ms;
						}
					}
				}
			}
			rtp->rtcp.last_lsr = reportblock.lsr;
			rtp->rtcp.last_lsr_delay = reportblock.delay_since_lsr;

			if(sverb.debug_rtcp) {
				printf("sSSRC [%x]\n", reportblock.ssrc);
				printf("	Fraction lost [%u]\n", reportblock.frac_lost);
				printf("	Packets lost [%d]\n", loss);
				printf("	Highest seqno received [%d]\n", reportblock.ext_seqno_recvd);
				printf("	Jitter [%u]\n", reportblock.jitter);
				printf("	Last SR [%u]\n", reportblock.lsr);
				printf("	Delay since last SR [%u]\n", reportblock.delay_since_lsr);
			}
		} else {
			if(sverb.debug_rtcp) {
				printf("sSSRC [%x] skipped (no rtp stream with this ssrc)\n", reportblock.ssrc);
			}
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

char *dump_rtcp_rr(char *data, int datalen, int count, Call *call, struct timeval *ts)
{
	char *pkt = data;
	rtcp_sr_reportblock_t reportblock;
	int	reports_seen;
	u_int32_t ssrc;

	/* Get the SSRC */
	if((pkt + sizeof(u_int32_t)) < (data + datalen)){
		ssrc = *pkt;
		pkt += sizeof(u_int32_t);
	} else {
		return pkt;
	}

	/* Conversions */
	ssrc = ntohl(ssrc);

	if(sverb.debug_rtcp) {
		printf("SSRC [%u]\n", ssrc);
	}

	/* Loop over report blocks */
	reports_seen = 0;
	while(reports_seen < count) {
		/* Get the report block */
		if((pkt + sizeof(rtcp_sr_reportblock_t)) < (data + datalen)){
			memcpy(&reportblock, pkt, sizeof(rtcp_sr_reportblock_t));
			pkt += sizeof(rtcp_sr_reportblock_t);
		} else {
			break;
		}

		/* Conversions */
		reportblock.ssrc = ntohl(reportblock.ssrc);
		reportblock.ext_seqno_recvd = ntohl(reportblock.ext_seqno_recvd);
		reportblock.jitter = ntohl(reportblock.jitter);
		reportblock.lsr = ntohl(reportblock.lsr);
		reportblock.delay_since_lsr = ntohl(reportblock.delay_since_lsr);

		RTP *rtp = NULL;
		for(int i = 0; i < call->rtp_size(); i++) { RTP *rtp_i = call->rtp_stream_by_index(i);
			if(rtp_i->ssrc == reportblock.ssrc) {
				// found 
				rtp = rtp_i;
			}
		}

		int32_t loss = ((int32_t)reportblock.packets_lost[2]) << 16;
		loss |= ((int32_t)reportblock.packets_lost[1]) << 8;
		loss |= (int32_t)reportblock.packets_lost[0];
		loss = loss & 0x800000 ? 0xff000000 | loss : loss;

		if(rtp) {
			rtp->rtcp.counter++;
			rtp->rtcp.loss = loss;
			if (reportblock.frac_lost)
				rtp->rtcp.fraclost_pkt_counter++;
			rtp->rtcp.maxfr = (rtp->rtcp.maxfr < reportblock.frac_lost) ? reportblock.frac_lost : rtp->rtcp.maxfr;
			rtp->rtcp.avgfr = (rtp->rtcp.avgfr * (rtp->rtcp.counter - 1) + reportblock.frac_lost) / rtp->rtcp.counter;
			if (opt_ignoreRTCPjitter == 0 or reportblock.jitter < opt_ignoreRTCPjitter) {
				rtp->rtcp.jitt_counter++;
				rtp->rtcp.maxjitter = (rtp->rtcp.maxjitter < reportblock.jitter) ? reportblock.jitter : rtp->rtcp.maxjitter;
				rtp->rtcp.avgjitter = (rtp->rtcp.avgjitter * (rtp->rtcp.jitt_counter - 1) + reportblock.jitter) / rtp->rtcp.jitt_counter;
			}
			// calculate rtcp round trip delay
			if (reportblock.lsr && reportblock.delay_since_lsr && rtp->rtcp.lsr4compare == reportblock.lsr) {
				if (timerisset(&rtp->rtcp.sniff_ts)) {
					struct timeval tmpts;
					timersub(ts, &rtp->rtcp.sniff_ts, &tmpts);
					unsigned int ms = tmpts.tv_sec * 1000 + tmpts.tv_usec / 1000 - reportblock.delay_since_lsr * 1000 / 65536;
					if (ms > 0) {
						rtp->rtcp.rtd_w_count++;
						rtp->rtcp.rtd_w_sum += ms;
						if (rtp->rtcp.rtd_w_max < ms) {
							rtp->rtcp.rtd_w_max = ms;
						}
					}
				}
			}
			if(sverb.debug_rtcp) {
				printf("rSSRC [%x]\n", reportblock.ssrc);
				printf("	Fraction lost [%u]\n", reportblock.frac_lost);
				printf("	Packets lost [%d]\n", loss);
				printf("	Highest seqno received [%u]\n", reportblock.ext_seqno_recvd);
				printf("	Jitter [%u]\n", reportblock.jitter);
				printf("	Last SR [%u]\n", reportblock.lsr);
				printf("	Delay since last SR [%u]\n", reportblock.delay_since_lsr);
			}
		} else {
			if(sverb.debug_rtcp) {
				printf("rSSRC [%x] skipped (no rtp stream with this ssrc)\n", reportblock.ssrc);
			}
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

char *dump_rtcp_sdes(char *data, unsigned int datalen, int count)
{
	char *pkt = data;
	u_int32_t	ssrc;
	u_int8_t	type;
	u_int8_t	length = 0;
	u_int8_t * string;
	int				chunks_read;
	int				pad_len;

	chunks_read = 0;
	while(chunks_read < count) {
		/* Get the ssrc, type and length */
		if((pkt + sizeof(u_int32_t)) < (data + datalen)){
			ssrc = *pkt;
			pkt += sizeof(u_int32_t);
		} else {
			break;
		}
		ssrc = ntohl(ssrc);
		if(sverb.debug_rtcp) {
			printf("SSRC/CSRC [%x]\n", ssrc);
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
			string = new FILE_LINE(23001) u_int8_t[length + 1];
			if((pkt + length) < (data + datalen)){
				memcpy(string, pkt, length);
				pkt += length;
			} else {
				delete [] string;
				break;
			}
			string[length] = '\0';
			
			if(sverb.debug_rtcp) {
				printf("	Type [%u]\n", type);
				printf("	Length [%u]\n", length);
				printf("	SDES [%s]\n", string);
			}

			/* Free string memory */
			delete [] string;
			
			/* Look for a null terminator */
//			if (look_packet_bytes((u_int8_t *) &byte, pkt, 1) == 0)
//				break;
			if((pkt + 1) < (data + datalen)) {
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
	return pkt;
}

/*----------------------------------------------------------------------------
**
** dump_rtcp_xr()
**
** Parse RTCP extended report fields
**
**----------------------------------------------------------------------------
*/

void dump_rtcp_xr(char *data, unsigned int datalen, int all_block_size, Call *call)
{
	char *pkt = data;
	int reports_seen;

	rtcp_xr_header_t *header = (rtcp_xr_header_t*)pkt;

	if(sverb.debug_rtcp) {
		printf("sender SSRC [%x]\n", ntohl(header->ssrc));
	}

	pkt += sizeof(rtcp_xr_header_t);
	all_block_size -= sizeof(rtcp_xr_header_t);
	
	/* Loop over report blocks */
	reports_seen = 0;
	while(all_block_size > (int)sizeof(rtcp_xr_gen_t)) {

		if(pkt + sizeof(rtcp_xr_gen_t) > (data + datalen)) {
			break;
		}

		rtcp_xr_gen_t *block = (rtcp_xr_gen_t*)pkt;
		unsigned block_size = sizeof(rtcp_xr_gen_t) + ntohs(block->length) * 4;
		all_block_size -= block_size;

		if((rtcp_xr_report_type_t_)block->bt != RTCP_XR_VOIP_METRICS) {
			pkt += block_size;
			continue;
		}

		pkt += sizeof(rtcp_xr_gen_t);
		rtcp_xr_voip_metrics_report_block_t *xr = (rtcp_xr_voip_metrics_report_block_t*)pkt;
	
		unsigned count_use_rtp = 0;
		for(int i = 0; i < call->rtp_size(); i++) { RTP *rtp_i = call->rtp_stream_by_index(i);
			if(rtp_i->ssrc == ntohl(xr->ssrc)) {
				RTP *rtp = rtp_i;
				rtp->rtcp_xr.counter_fr++;
				rtp->rtcp_xr.maxfr = (rtp->rtcp_xr.maxfr < xr->loss_rate) ? xr->loss_rate : rtp->rtcp_xr.maxfr;
				rtp->rtcp_xr.avgfr = (rtp->rtcp_xr.avgfr * (rtp->rtcp_xr.counter_fr - 1) + xr->loss_rate) / rtp->rtcp_xr.counter_fr;
				if(xr->mos_lq != 0x7F) {
					rtp->rtcp_xr.counter_mos++;
					rtp->rtcp_xr.minmos = (rtp->rtcp_xr.minmos > xr->mos_lq) ? xr->mos_lq : rtp->rtcp_xr.minmos;
					rtp->rtcp_xr.avgmos = (rtp->rtcp_xr.avgmos * (rtp->rtcp_xr.counter_mos - 1) + xr->mos_lq) / rtp->rtcp_xr.counter_mos;
				}
				if(sverb.debug_rtcp) {
					printf("identifier [%x]\n", ntohl(xr->ssrc));
					printf("	Fraction lost [%u]\n", xr->loss_rate);
					printf("	Fraction discarded [%d]\n", xr->discard_rate);
					printf("	Burst density [%d]\n", xr->burst_density);
					printf("	Gap density[%d]\n", xr->gap_density);
					printf("	Burst duration[%d]\n", ntohs(xr->burst_duration));
					printf("	Gap duration[%d]\n", ntohs(xr->gap_duration));
					printf("	Round trip delay[%d]\n", ntohs(xr->round_trip_delay));
					printf("	End system delay[%d]\n", ntohs(xr->end_system_delay));
					printf("	Signal Level[%d]\n", xr->signal_level);
					printf("	Noise level[%d]\n", xr->noise_level);
					printf("	Residual echo return loss[%d]\n", xr->rerl);
					printf("	Gmin[%d]\n", xr->gmin);
					printf("	R Factor[%d]\n", xr->r_factor);
					printf("	External R Factor[%d]\n", xr->ext_r_factor);
					printf("	MOS Listening Quality[%d]\n", xr->mos_lq);
					printf("	MOS Conversational Quality[%d]\n", xr->mos_cq);
					printf("	rx_config[%d]\n", xr->rx_config);
					printf("	Nominal jitter buffer size[%d]\n", ntohs(xr->jb_nominal));
					printf("	Maximum jitter buffer size[%d]\n", ntohs(xr->jb_maximum));
					printf("	Absolute maximum jitter buffer size[%d]\n", ntohs(xr->jb_abs_max));
				}
				++count_use_rtp;
			}
		}
		if(!count_use_rtp) {
			if(sverb.debug_rtcp) {
				printf("identifier [%x] skipped (no rtp stream with this ssrc)\n", ntohl(xr->ssrc));
			}
		}

		pkt += ntohs(block->length) * 4;
		reports_seen++;
	}
	return;
}

/*----------------------------------------------------------------------------
**
** dump_rtcp()
**
** Parse RTCP packet and dump fields
**
**----------------------------------------------------------------------------
*/

void parse_rtcp(char *data, int datalen, timeval *ts, Call* call)
{
	char *pkt = data;
	rtcp_header_t *rtcp;
	
	if(sverb.debug_rtcp) {
		printf("\nRTCP PACKET - ts %lu.%06lu\n", ts->tv_sec, ts->tv_usec);
	}

	while(1){
		/* Get the fixed RTCP header */
		if((pkt + sizeof(rtcp_header_t)) < (data + datalen)){
			rtcp = (rtcp_header_t*)pkt;
		} else {
			break;
		}

		int rtcp_size = ntohs(rtcp->length) * 4 + sizeof(rtcp_header_t);

		if(rtcp->version != 2) {
			if(sverb.debug_rtcp) {
				printf("\n[%s] Malformed RTCP header (version != 2)\n", call->fbasename);
			}
			pkt += rtcp_size;
			break;
		}
	
		if((pkt + rtcp_size) > (data + datalen)){
			if(sverb.debug_rtcp) {
				printf("\n[%s] Malformed RTCP header (overflow rtcp length)\n", call->fbasename);
			}
			//rtcp too big 
			break;
		}

		char *rtcp_data = pkt + sizeof(rtcp_header_t);
	
		if(sverb.debug_rtcp) {
			printf("\nRTCP Header\n");
			printf("Version %d\n", rtcp->version);
			printf("Padding %d\n", rtcp->padding);
			printf("Report/source count [%d]\n", rtcp->rc_sc);
			printf("Packet type [%d]\n", rtcp->packet_type);
			printf("Length [%d]\n", ntohs(rtcp->length));
		}
			
		switch(rtcp->packet_type) {
		case RTCP_PACKETTYPE_SR:
			dump_rtcp_sr(rtcp_data, data + datalen - rtcp_data, rtcp->rc_sc, call, ts);
			break;
		case RTCP_PACKETTYPE_RR:
			dump_rtcp_rr(rtcp_data, data + datalen - rtcp_data, rtcp->rc_sc, call, ts);
			break;
		case RTCP_PACKETTYPE_SDES:
			// we do not need to parse it
			//dump_rtcp_sdes(rtcp_data, data + datalen - rtcp_data, rtcp->rc_sc);
			break;
		case RTCP_PACKETTYPE_XR:
			dump_rtcp_xr(pkt, data + datalen - rtcp_data, rtcp_size, call);
			break;
		default:
			break;
		}

		pkt += rtcp_size;
	}
}
