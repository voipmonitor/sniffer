/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#ifndef RTP_H
#define RTP_H
#include <netinet/in.h>
#include <fstream>
#include <iostream>

#include "tools.h"
#include "dsp.h"
#include "codecs.h"
#include "calltable_base.h"

//#include "jitterbuffer/asterisk/channel.h"
#include "jitterbuffer/asterisk/abstract_jb.h"

#define MAX_RTPMAP 40


using namespace std;

int get_ticks_bycodec(int);

void burstr_calculate(struct ast_channel *chan, u_int32_t received, double *burstr, double *lossr, int lastinterval);
int calculate_mos_fromrtp(RTP *rtp, int jittertype, int lastinterval);
double calculate_mos_g711(double ppl, double burstr, int version);
double calculate_mos(double ppl, double burstr, int codec, unsigned int received, bool call_is_connected);


/*

http://www.ietf.org/rfc/rfc3550.txt

The RTP header has the following format:

    0		   1		   2		   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number	 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |			   timestamp			   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |	   synchronization source (SSRC) identifier	    |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |	    contributing source (CSRC) identifiers	     |
   |			     ....			      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/*
   version (V): 2 bits
      This field identifies the version of RTP.  The version defined by
      this specification is two (2).  (The value 1 is used by the first
      draft version of RTP and the value 0 is used by the protocol
      initially implemented in the "vat" audio tool.)
*/

/*
   padding (P): 1 bit
      If the padding bit is set, the packet contains one or more
      additional padding octets at the end which are not part of the
      payload.  The last octet of the padding contains a count of how
      many padding octets should be ignored, including itself.  Padding
      may be needed by some encryption algorithms with fixed block sizes
      or for carrying several RTP packets in a lower-layer protocol data
      unit.
*/

/*
   extension (X): 1 bit
      If the extension bit is set, the fixed header MUST be followed by
      exactly one header extension, with a format defined in Section
      5.3.1.
*/

/*
   CSRC count (CC): 4 bits
      The CSRC count contains the number of CSRC identifiers that follow
      the fixed header.
*/
 
/*
   marker (M): 1 bit
      The interpretation of the marker is defined by a profile.  It is
      intended to allow significant events such as frame boundaries to
      be marked in the packet stream.  A profile MAY define additional
      marker bits or specify that there is no marker bit by changing the
      number of bits in the payload type field (see Section 5.3).
*/

/*
   payload type (PT): 7 bits
      This field identifies the format of the RTP payload and determines
      its interpretation by the application.  A profile MAY specify a
      default static mapping of payload type codes to payload formats.
      Additional payload type codes MAY be defined dynamically through
      non-RTP means (see Section 3).  A set of default mappings for
      audio and video is specified in the companion RFC 3551 [1].  An
      RTP source MAY change the payload type during a session, but this
      field SHOULD NOT be used for multiplexing separate media streams
      (see Section 5.2).

      A receiver MUST ignore packets with payload types that it does not
      understand.
*/

#define RTP_VERSION    2	//!< current protocol version 

#define RTP_SEQ_MOD (1<<16)
#define RTP_MAX_SDES 255	//!< maximum text length for SDES 

#define MIN_SEQUENTIAL 2
#define MAX_MISORDER 100
#define MAX_DROPOUT 3000

#define ROT_SEQ(seq) ((seq) & (RTP_SEQ_MOD - 1))

#define FIRST_RTCP_CONFLICT_PAYLOAD_TYPE 72
#define LAST_RTCP_CONFLICT_PAYLOAD_TYPE  76


struct RTPFixedHeader {
#if     __BYTE_ORDER == __BIG_ENDIAN
	// For big endian boxes
	unsigned char version:2;	// Version, currently 2
	unsigned char padding:1;	// Padding bit
	unsigned char extension:1;      // Extension bit
	unsigned char cc:4;	     // CSRC count
	unsigned char marker:1;	 // Marker bit
	unsigned char payload:7;	// Payload type
#else
	// For little endian boxes
	unsigned char cc:4;	     // CSRC count
	unsigned char extension:1;      // Extension bit
	unsigned char padding:1;	// Padding bit
	unsigned char version:2;	// Version, currently 2
	unsigned char payload:7;	// Payload type
	unsigned char marker:1;	 // Marker bit
#endif
	u_int16_t sequence;     // sequence number
	u_int32_t timestamp;    // timestamp
	u_int32_t sources[1];   // contributing sources
#ifdef PACKED
} __attribute__((packed));
#else
};
#endif

struct UDPTLFixedHeader {
	u_int16_t sequence;
	u_int8_t size;
#if     __BYTE_ORDER == __BIG_ENDIAN
	// For big endian boxes
	unsigned char data_field:1;
	unsigned char type:1;
	unsigned char t30_indicator:5;
	unsigned char _fill:1;
#else
	// For little endian boxes
	unsigned char _fill:1;
	unsigned char t30_indicator:5;
	unsigned char type:1;
	unsigned char data_field:1;
#endif
#ifdef PACKED
} __attribute__((packed));
#else
};
#endif


struct RTPMAP {
	inline RTPMAP() {
		clear();
	}
	inline bool is_set() const {
		return(payload || codec);
	}
	inline void clear() {
		payload = 0;
		codec = 0;
		frame_size = 0;
		bit_rate = 0;
	}
	u_int16_t payload;
	u_int16_t codec;
	u_int16_t frame_size;
	u_int16_t bit_rate;
};


enum eRtpMarkType {
	_mark_rtp = 1,
	_forcemark_diff_seq = 2,
	_forcemark_sip_sdp = 3
};


/**
 * This class implements operations on RTP strem
 */

#if EXPERIMENTAL_LITE_RTP_MOD

class RTP {
public:
	struct s_id {
		u_int32_t ssrc;
		vmIP saddr;
		vmIP daddr;
		vmPort sport;
		vmPort dport;
		u_int8_t iscaller;
		class Call *call_owner;
	} id;
	struct s_media {
		int32_t codec;
		bool had_audio;
	} media;
	struct s_timing {
		u_int64_t first_packet_time_us;
		u_int64_t last_packet_time_us;
	} timing;
	struct stats_t {
		u_int32_t received;
	} stats;
	struct s_sdp {
		u_int16_t ssrc_index;
		bool skip;
	} sdp;
	struct s_silence {
		u_int8_t tailedframes;
	} silence;

	inline void init(class Call *call) {
		media.codec = -1;
		stats.received = 0;
		sdp.skip = false;
		media.had_audio = true;
		silence.tailedframes = 0;
		id.call_owner = call;
	}
	inline unsigned received_() {
		return(stats.received);
	}
	inline void set_received_(u_int32_t r) {
		stats.received = r;
	}
	inline unsigned lost_() {
		return(0);
	}
	inline void set_lost_(u_int32_t l) {
		//
	}
	inline double lost_perc_() {
		unsigned lost = lost_();
		unsigned received = received_();
		return(lost ?
			(received ? (double)lost/(lost + received) * 100 : 100) :
			0);
	}
	inline double lost_ratio_() {
		unsigned lost = lost_();
		unsigned received = received_();
		return(lost ?
			(received ? (double)lost/received : 1e10) :
			0);
	}
	inline int first_codec_() {
		return(media.codec);
	}
	inline void set_first_codec_(int c) {
		media.codec = c;
	}
	inline bool ok_other_ip_side_by_sip_() {
		return(false);
	}
	inline bool eqAddrPort(vmIP saddr, vmIP daddr, vmPort sport, vmPort dport) {
		return(id.sport == sport && id.dport == dport &&
		       id.saddr == saddr && id.daddr == daddr);
	}
	inline bool eqAddrPort(RTP *rtp) {
		return(eqAddrPort(rtp->id.saddr, rtp->id.daddr, rtp->id.sport, rtp->id.dport));
	}
	inline bool allowed_for_ab() {
		return(true);
	}
	static inline RTPFixedHeader* getHeader(void *data) { 
		return reinterpret_cast<RTPFixedHeader*>(data); 
	}
	static inline const int getPayload(void *data) { 
		return getHeader(data)->payload; 
	}
	static inline const bool isSetMarkerInHeader(void *data) { 
		return getHeader(data)->marker;
	};
	static inline const bool isRTCP_enforce(void *data) { 
		if(isSetMarkerInHeader(data)) {
			int payload = getPayload(data);
			return(payload >= FIRST_RTCP_CONFLICT_PAYLOAD_TYPE && payload <= LAST_RTCP_CONFLICT_PAYLOAD_TYPE);
		}
		return(false);
	};
};

#else

class RTP {
       /* extension header */
	typedef struct {
		u_int16_t profdef;
		u_int16_t length; // length of extension in 32bits, this header exluded.
	} extension_hdr_t;
	struct sRSA {
		sRSA() {
			first_packet_time_us = 0;
			last_packet_time_us = 0;
			jitter = 0;
			counter = 0;
			first_timestamp = 0;
			last_timestamp = 0;
			prev_seq = 0;
		}
		u_int64_t first_packet_time_us;
		u_int64_t last_packet_time_us;
		double jitter;
		u_int32_t counter;
		u_int32_t first_timestamp;
		u_int32_t last_timestamp;
		u_int16_t prev_seq;
	};
	class cDuplCheckSeq {
	public:
		cDuplCheckSeq() {
			memset(circ_buffer, 0, sizeof(circ_buffer));
			circ_buffer_pos = 0;
			exists_dupl = false;
		}
		inline void push(u_int16_t seq) {
			circ_buffer[circ_buffer_pos] = seq;
			if(++circ_buffer_pos == (sizeof(circ_buffer) / sizeof(circ_buffer[0]))) {
				circ_buffer_pos = 0;
			}
		}
		inline bool check(u_int16_t seq) {
			if(seq) {
				for(u_int16_t i = 0; i < (sizeof(circ_buffer) / sizeof(circ_buffer[0])); i++) {
					if(seq == circ_buffer[i]) {
						return(true);
					}
				}
			}
			return(false);
		}
	private:
		u_int16_t circ_buffer[20];
		u_int16_t circ_buffer_pos;
	public:
		bool exists_dupl;
	};
public:
	// =========================================================================
	// ZONE 1: HOT per-packet substructures (L1/L2 cache resident, CL 0..13)
	// =========================================================================

	/* Stream identity, 5-tuple, direction and Call owner (64B = CL 0) */
	struct s_id {
		void init() {
			ssrc = 0;
			ssrc2 = 0;
			saddr.clear();
			daddr.clear();
			sport.clear();
			dport.clear();
			iscaller = 0;
			call_owner = NULL;
		}
		u_int32_t ssrc;		//!< ssrc of this RTP class
		u_int32_t ssrc2;	//!< matched ssrc of this RTP class
		vmIP saddr;		//!< last source IP address
		vmIP daddr;		//!< last destination IP address
		vmPort sport;
		vmPort dport;
		int iscaller;		//!< flag which indicates if RTP stream is part of caller or callee
		void *call_owner;	//!< which Call owns us
	} id;

	/* Current packet pointers, timestamp and sequence cursor (64B = CL 1) */
	struct s_pkt {
		void init() {
			memset(this, 0, sizeof(*this));
			last_seq = -1;
		}
		unsigned char *data;		//!< pointer to UDP payload
		iphdr2 *header_ip;
		unsigned char *payload_data;	//!< pointer to RTP payload
		struct timeval header_ts;	//!< pcap timestamp of current packet
		int len;			//!< length of UDP payload
		int payload_len;		//!< length of RTP payload
		int last_seq;			//!< last packet sequence number
		u_int32_t last_ts;		//!< last RTP timestamp
		u_int16_t seq;			//!< current sequence number
		u_int16_t prev_payload_len;	//!< previous length of RTP payload
		uint8_t padding_len;		//!< length of RTP padding
		char ignore;
		bool last_markbit;
		bool resetgraph;
	} pkt;

	/* Jitterbuffer channels, frame and DSP instances (64B = CL 2) */
	struct s_jb {
		void init() {
			#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
			channel_fix1 = NULL;
			channel_fix2 = NULL;
			channel_adapt = NULL;
			channel_record = NULL;
			frame = NULL;
			#endif
			DSP = NULL;
			DSP_ivr = NULL;
			lastframetype = 0;
			pinformed = 0;
		}
		#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
		struct ast_channel *channel_fix1;
		struct ast_channel *channel_fix2;
		struct ast_channel *channel_adapt;
		struct ast_channel *channel_record;
		struct ast_frame *frame;
		#endif
		struct dsp *DSP;
		struct dsp *DSP_ivr;	//!< own DSP for ivrdetect (early media), the shared DSP state stays untouched
		int lastframetype;
		int pinformed;
	} jb;

	/* Codec, payload, packetization and media flags (64B = CL 3) */
	struct s_media {
		void init() {
			codec = -1;
			prev_payload = -1;
			prev_codec = -1;
			payload2 = -1;
			first_codec = -1;
			packetization = 0;
			last_packetization = 0;
			packetization_iterator = 0;
			default_packetization = 0;
			samplerate = 8000;
			sid = false;
			prev_sid = false;
			avg_ptime = 0;
			avg_ptime_count = 0;
			change_packetization_iterator = 0;
			lastcng = 0;
			had_audio = false;
			defer_codec_change = false;
			codecchanged = false;
			changing_codec = false;
			sdp_flags = s_sdp_flags_base();
			stopped_jb_due_to_high_ooo = false;
		}
		int codec;
		int prev_payload;
		int prev_codec;
		int payload2;
		int first_codec;
		int packetization;		//!< packetization in milliseconds
		int last_packetization;		//!< last packetization in milliseconds
		int packetization_iterator;
		int default_packetization;
		unsigned int samplerate;
		int sid;
		int prev_sid;
		float avg_ptime;
		u_int32_t avg_ptime_count;
		uint8_t change_packetization_iterator;
		char lastcng;
		bool had_audio;
		bool defer_codec_change;
		bool codecchanged;
		bool changing_codec;
		s_sdp_flags_base sdp_flags;
		bool stopped_jb_due_to_high_ooo;
	} media;

	/* Packet timing, voice frame timestamps and instantaneous jitter (72B) */
	struct s_timing {
		void init() {
			memset(this, 0, sizeof(*this));
		}
		u_int64_t first_packet_time_us;
		u_int64_t last_packet_time_us;
		u_int64_t next_save_mos_graph_us;
		timeval _last_ts;
		timeval last_voice_frame_ts;
		double jitter;
		uint32_t last_voice_frame_timestamp;
		char save_mos_graph_wait;
		bool pcap_header_ts_bad_time;
	} timing;

	/* IP TTL running statistics (16B) */
	struct s_ttl {
		void init() {
			sum = 0;
			count = 0;
			min = -1;
			max = -1;
		}
		u_int64_t sum;
		u_int32_t count;
		int16_t min;
		int16_t max;
	} ttl;

	/* Forced marker state (8B) */
	struct s_forcemark {
		void init() {
			owner_used = 0;
			mark = 0;
			mark2 = 0;
			by_owner = false;
			by_owner_set = false;
		}
		unsigned owner_used;
		u_int8_t mark;
		u_int8_t mark2;
		bool by_owner;
		bool by_owner_set;
	} forcemark;

private:
	/* Call / CallBranch stream linkage (32B, kept hot with CL 5) */
	struct s_call_link {
		void init() {
			c_branch_created = NULL;
			index_call_ip_port = -1;
			index_call_ip_port_other_side = -1;
			call_ipport_n_orig = 0;
			leg_index = -1;
			leg_view_index = -1;
			index_call_ip_port_by_dest = false;
			stopReadProcessing = false;
			stream_in_multiple_calls = false;
		}
		class CallBranch *c_branch_created;
		int index_call_ip_port;
		int index_call_ip_port_other_side;
		int call_ipport_n_orig;
		int leg_index;
		int leg_view_index;
		bool index_call_ip_port_by_dest;
		bool stopReadProcessing;
		bool stream_in_multiple_calls;
	} link;

public:
	/* Per-packet loss, delay and jitter statistics (112B, starts on CL 6) */
	struct stats_t {
		void init() {
			memset(this, 0, sizeof(*this));
		}
		// Hot per-packet fields in first cache line
		double		avgjitter;
		double		maxjitter;
		u_int32_t	received;		//!< overall received packets
		u_int32_t	lost;			//!< overall lost packets (real)
		u_int32_t	lost_with_reinvite_gaps;
		u_int32_t	reordered;
		int		last_lost;		//!< last overall lost packets

		// Delay & serial-loss histograms (only touched on delay >= 50ms or loss)
		u_int32_t	d50;			//!< delay from 0 to 50
		u_int32_t	d70;
		u_int32_t	d90;
		u_int32_t	d120;
		u_int32_t	d150;
		u_int32_t	d200;
		u_int32_t	d300;
		u_int32_t	slost[11];		//!< lost counts
	} stats;

	/* RFC 3550 per-source sequence & delay state (120B, embedded directly) */
	struct source {
		void init() {
			memset(this, 0, sizeof(*this));
			first = true;
		}
		int64_t cycles;			//!< shifted count of seq. number cycles
		double fdelay;
		double prevjitter;
		double avgdelay;
		struct timeval lastTimeRec;	//!< last received time from pcap packet header
		struct timeval lastTimeRecJ;	//!< last received time from pcap packet header for jitterbuffer
		u_int32_t base_seq;		//!< base seq number
		u_int32_t bad_seq;		//!< last 'bad' seq number + 1
		u_int32_t probation;		//!< sequ. packets till source is valid
		u_int32_t received;		//!< packets received
		u_int32_t lastTimeStamp;	//!< last received timestamp from RTP header
		u_int32_t lastTimeStampJ;	//!< last received timestamp from RTP header for jitterbuffer
		u_int32_t expected_prior;	//!< packet expected at last interval
		u_int32_t received_prior;	//!< packet received at last interval
		u_int32_t transit;		//!< relative trans time for prev pkt
		u_int32_t jitter;		//!< estimated jitter
		u_int32_t lost;			//!< lost packets
		int delay;
		u_int16_t max_seq;		//!< highest seq. number seen
		bool first;
	};

	source s;

	/* Sliding 30-packet delay average window (128B) */
	struct s_delay_win {
		void init() {
			counter = 0;
			idx = 0;
		}
		float avgdelays[30];
		uint32_t counter;
		uint8_t idx;
	} delay_win;

private:
	/* SRTP decryption state (40B; hot decrypt/is_srtp checked per packet in first 16B) */
	struct s_srtp {
		void init() {
			decrypt = NULL;
			auth_tag_size = 0;
			is_srtp = false;
			probably_unencrypted_payload = false;
			decrypt_local = false;
			tag_verified = false;
			decrypt_index_call_ip_port = -1;
			decrypt_rtp_attempt[0] = 0;
			decrypt_rtp_attempt[1] = 0;
			decrypt_ok = 0;
			decrypt_failed = 0;
		}
		class RTPsecure *decrypt;
		unsigned auth_tag_size;
		bool is_srtp;
		bool probably_unencrypted_payload;
		bool decrypt_local;
		bool tag_verified;
		int decrypt_index_call_ip_port;
		unsigned decrypt_rtp_attempt[2];
		unsigned decrypt_ok;
		unsigned decrypt_failed;
	} srtp;

	cDuplCheckSeq dupl_check_seq;	//!< per-packet seq duplicate ringbuffer (44B, CL 12)
	int nintervals;			//!< graph delimiter packet interval counter (4B, CL 12)

public:
	RtpGraphSaver graph;		//!< per-packet when FLAG_SAVEGRAPH is active (64B, CL 13)

	// =========================================================================
	// ZONE 2: WARM / COLD substructures (periodic / RTCP / setup / recording)
	// =========================================================================

	/* Periodic (10s) MOS & interval loss statistics (64B = 1 CL) */
	struct s_mos {
		void init() {
			last_save_graph_ms = 0;
			last_call_save_graph_ms = 0;
			time_ms = 0;
			last_stat_loss_perc_mult10 = 0;
			f1_avg = 0;
			f2_avg = 0;
			AD_avg = 0;
			Silence_avg = 0;
			last_stat_lost = 0;
			last_stat_received = 0;
			f1_min = 45;
			f2_min = 45;
			AD_min = 45;
			Silence_min = (uint8_t)-1;
			last_interval_f1 = 45;
			last_interval_f2 = 45;
			last_interval_AD = 45;
			last_interval_Silence = 45;
		}
		u_int64_t last_save_graph_ms;
		u_int64_t last_call_save_graph_ms;
		uint64_t time_ms;
		double last_stat_loss_perc_mult10;
		float f1_avg;
		float f2_avg;
		float AD_avg;
		float Silence_avg;
		uint32_t last_stat_lost;
		uint32_t last_stat_received;
		uint8_t f1_min;
		uint8_t f2_min;
		uint8_t AD_min;
		uint8_t Silence_min;
		unsigned char last_interval_f1;
		unsigned char last_interval_f2;
		unsigned char last_interval_AD;
		unsigned char last_interval_Silence;
	} mos;

	/* SDP negotiation metadata, DSCP, skip & port-change flags (32B) */
	struct s_sdp {
		void init() {
			frame_size = 0;
			bit_rate = 0;
			rtpmap_call_index = -1;
			rtpmap_other_side_call_index = -1;
			ssrc_index = 0;
			ptime = 0;
			dscp = 0;
			skip = false;
			change_src_port = false;
			change_dst_port = false;
			find_by_dest = false;
			ok_other_ip_side_by_sip = false;
			confirm_both_sides_by_sdp = false;
		}
		int frame_size;
		int bit_rate;
		int rtpmap_call_index;
		int rtpmap_other_side_call_index;
		int ssrc_index;		//!< index
		u_int16_t ptime;
		uint8_t dscp;
		bool skip;
		bool change_src_port;
		bool change_dst_port;
		bool find_by_dest;
		bool ok_other_ip_side_by_sip;
		bool confirm_both_sides_by_sdp;
	} sdp;

	/* RFC 2833 DTMF state (8B) */
	struct s_dtmf_state {
		void init() {
			last_end_timestamp = 0;
			lastdtmf = 0;
		}
		unsigned int last_end_timestamp;
		char lastdtmf;
	} dtmf;

	/* Silence detection & jitterbuffer tail counters (12B) */
	struct s_silence {
		void init() {
			tailedframes = 0;
			sum_changes = 0;
			last_was_silence = false;
		}
		uint32_t tailedframes;
		uint32_t sum_changes;
		bool last_was_silence;
	} silence;

	/* RTCP data (64B = 1 CL) */
	struct rtcp_t {
		void init() {
			memset(this, 0, sizeof(*this));
		}
		double avgfr;
		double avgjitter;
		int loss;
		unsigned int maxfr;
		unsigned int maxjitter;
		unsigned int counter;
		unsigned int jitt_counter;
		unsigned int fraclost_pkt_counter;
		unsigned int rtd_rfc_sum;	/* roundtrip delay */
		unsigned int rtd_rfc_count;
		unsigned int rtd_rfc_max;
		unsigned int rtd_ws_sum;	/* roundtrip delay by wireshark */
		unsigned int rtd_ws_count;
		unsigned int rtd_ws_max;
	} rtcp;

	/* RTCP XR data (32B) */
	struct rtcp_xr_t {
		void init() {
			memset(this, 0, sizeof(*this));
			minmos = 45;
		}
		double avgfr;
		double avgmos;
		unsigned int counter_fr;
		unsigned int counter_mos;
		uint8_t maxfr;
		uint8_t minmos;
	} rtcp_xr;

	/* RAW audio recording state & deduplication ringbuffer */
	struct s_raw {
		void init() {
			#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
			gfile = NULL;
			gfile_buffer = NULL;
			gfile_lock = 0;
			iterator = 0;
			init_done = false;
			need_init_for_channel_record = false;
			#endif
			memset(seq_ringbuffer, 0, sizeof(seq_ringbuffer));
			seq_ringbuffer_pos = 0;
		}
		#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
		FILE *gfile;			//!< file for storing RTP payload in RAW format
		char *gfile_buffer;
		volatile int gfile_lock;
		int iterator;			//!< iterator for raw file name
		bool init_done;
		bool need_init_for_channel_record;
		#endif
		u_int16_t seq_ringbuffer[50];
		u_int16_t seq_ringbuffer_pos;
	} raw;

	/* Output filename buffers (2048B) */
	struct s_files {
		void init() {
			#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
			basefilename[0] = '\0';
			#endif
			gfilename[0] = '\0';
		}
		#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
		char basefilename[1024];
		#endif
		char gfilename[1024];		//!< file name of graph file
	} files;

	/* Dynamic payload RTPMAP tables (640B) */
	struct s_rtpmap {
		void init() {
			memset((void*)local, 0, sizeof(local));
			memset((void*)other_side, 0, sizeof(other_side));
		}
		RTPMAP local[MAX_RTPMAP];
		RTPMAP other_side[MAX_RTPMAP];
	} rtpmap;

	/**
	* constructor which allocates and zeroing stats structure
	*
	*/
	RTP(int sensor_id, vmIP sensor_ip);

	/**
	* destructor
	*
	*/
	~RTP();
	
	void setSRtpDecrypt(class RTPsecure *srtp_decrypt, int index_call_ip_port, bool local = false);

	/**
	 * @brief simulate jitter buffer
	 *
	 * Put packet to jitterbuffer associated to channel structure
	 *
	 * @param channel pointer to the channel structure which holds statistics and jitterbuffer data
	 *
	*/
	void jitterbuffer(struct ast_channel *channel, bool save_audio, bool energylevels, bool mos_lqo);
	void jitterbuffer_mos_all();

	void process_dtmf_rfc2833();

	/**
	 * @brief read RTP packet
	 *
	 * Used for reading RTP packet
	 *
	 * @param data pointer to the packet buffer
	 * @param header header structure of the packet
	 * @param saddr source IP adress of the packet
	 *
	*/
	bool read(class CallBranch *c_branch,
		  unsigned char* data, iphdr2 *header_ip, unsigned *len, struct pcap_pkthdr *header, vmIP saddr, vmIP daddr, vmPort sport, vmPort dport,
		  int sensor_id, vmIP sensor_ip, char *ifname = NULL, bool *decrypt_ok = NULL, volatile int8_t *decrypt_sync = NULL);

	/**
	 * @brief fill RTP packet into structures
	 *
	 * Used for temporary operations on RTP packet
	 *
	 * @param data pointer to the data packet buffer
	 * @param len data length
	 *
	*/
	void fill_data(unsigned char* data, int len);

	/**
	 * @brief get version
	 *
	 * this function gets version from rtp header
	 *
	 * @return padding RTP version
	*/
	const unsigned char getVersion() { return getHeader()->version; };
	static const unsigned char getVersion(void *data) { return getHeader(data)->version; };
	
	/**
	 * @brief get sequence sumber
	 *
	 * this function gets sequence number from header of RTP packet
	 *
	 * @return sequence number
	*/
	const u_int16_t getSeqNum() { return htons(getHeader()->sequence); };

	/**
	 * @brief get timestamp 
	 *
	 * this function gets timestamp from header of RTP packet
	 *
	 * @return number of seocnds since UNIX epoch
	*/
	const u_int32_t getTimestamp() { return htonl(getHeader()->timestamp); };
	
	/**
	 * @brief get SSRC
	 *
	 * this function gets SSRC from header of RTP packet
	 *
	 * @return SSRC
	*/
	const u_int32_t getSSRC() { return htonl(getHeader()->sources[0]); };
	static const u_int32_t getSSRC(void *data) { return htonl(getHeader(data)->sources[0]); };

	/**
	 * @brief get Payload 
	 *
	 * this function gets Payload from header of RTP packet
	 *
	 * @return SSRC
	*/
	inline const int getPayload() { return getHeader()->payload; };
	static inline const int getPayload(void *data) { return getHeader(data)->payload; };
	/**
	 * @brief get Received
	 *
	 * this function gets number of received packets
	 *
	 * @return received packets
	*/
	const u_int32_t getReceived() { return s.received; };

	inline const int getMarker() { return getHeader()->marker ? 1 : forcemark.mark; };
	
	inline const bool isSetMarkerInHeader() { return getHeader()->marker; };
	static inline const bool isSetMarkerInHeader(void *data) { return getHeader(data)->marker; };
	
	static inline const bool isRTCP_enforce(void *data) { 
		if(isSetMarkerInHeader(data)) {
			int payload = getPayload(data);
			return(payload >= FIRST_RTCP_CONFLICT_PAYLOAD_TYPE && payload <= LAST_RTCP_CONFLICT_PAYLOAD_TYPE);
		}
		return(false);
	};

	/**
	 * @brief get padding
	 *
	 * this function gets padding bit from rtp header
	 *
	 * @return padding bit
	*/
	const unsigned char getPadding() { return getHeader()->padding; };
 
	 /**
	 * @brief get cc
	 *
	 * this function gets the number of CSRC identifiers that follow the fixed header.
	 *
	 * @return 4bits number (integer)
	*/
	const int getCC() { return getHeader()->cc; };
 
	 /**
	 * @brief get extension
	 *
	 * this function gets X, Extension. 1 bit.
	 *
	 * @return 1bit
	*/
	const int getExtension() { return getHeader()->extension; };
 
	 /**
	 * @brief get payload length
	 *
	 * this function gets length of payload 
	 *
	 * @return number of bytes of payload
	*/
	const int get_payload_len();
	inline const int get_payload_len_fast() {
		if(__builtin_expect(pkt.data[0] == 0x80, 1)) {
			pkt.payload_data = pkt.data + sizeof(RTPFixedHeader);
			pkt.payload_len = pkt.len - sizeof(RTPFixedHeader);
			return pkt.payload_len;
		}
		return get_payload_len();
	}

	 /**

	 * @brief flushes frames from jitterbuffer
	 *
	 * this function flushes all frames from jitterbuffer fixed implementation and writes it to raw files
	*/
	void jitterbuffer_fixed_flush(struct ast_channel *channel);

	 /**

	 * @brief adds empty frames from last packet in jitterbuffer to time in header packet
	 *
	 * add silence to RTP stream from last packet time to current time which is in header->ts 
	*/
	void jt_tail(struct pcap_pkthdr *header);

	 /**

	 * @brief prints debug informations
	 *
	 * this function prints statistics data on stdout 
	 *
	*/
	void dump();

	/**
	 * @brief get total lost packets
	 *
	 * this function gets total lost packets within live of RTP stream
	 *
	 * @return count of lost packets
	*/
	u_int32_t getLost() { return s.probation ? 0 : ((s.cycles + s.max_seq) - s.base_seq + 1) - s.received; };

	void save_mos_graph(bool delimiter);
	
	inline void clearAudioBuff(class Call *call, ast_channel *channel);
	
	bool eqAddrPort(vmIP saddr, vmIP daddr, vmPort sport, vmPort dport) {
		return(id.sport == sport && id.dport == dport &&
		       id.saddr == saddr && id.daddr == daddr);
	}
	bool eqAddrPort(RTP *rtp) {
		return(eqAddrPort(rtp->id.saddr, rtp->id.daddr, rtp->id.sport, rtp->id.dport));
	}
	
	bool checkDuplChannelRecordSeq(u_int16_t seq) {
		extern int opt_saveaudio_dedup_seq;
		if(opt_saveaudio_dedup_seq) {
			unsigned ringbuffer_length = sizeof(raw.seq_ringbuffer) / sizeof(raw.seq_ringbuffer[0]);
			for(unsigned i = 0; i < ringbuffer_length; i++) {
				if(seq == raw.seq_ringbuffer[i]) {
					return(false);
				}
			}
			raw.seq_ringbuffer[raw.seq_ringbuffer_pos] = seq;
			++raw.seq_ringbuffer_pos;
			if(raw.seq_ringbuffer_pos >= ringbuffer_length) {
				raw.seq_ringbuffer_pos = 0;
			}
		}
		return(true);
	}

	void rtp_stream_analysis_output();
	
	int mos_min_mult10_from_avg(bool prefer_f2 = false);
	int mos_min_mult10_from_min(bool prefer_f2 = false);
	double mos_min_from_avg(bool *null, bool prefer_f2 = false);
	double mos_min_from_min(bool *null, bool prefer_f2 = false);
	double mos_xr_min(bool *null);
	double mos_xr_avg(bool *null);
	double mos_silence_min(bool *null);
	double mos_silence_avg(bool *null);
	double packet_loss(bool *null);
	double jitter_avg(bool *null);
	double jitter_max(bool *null);
	double delay_sum(bool *null);
	double delay_cnt(bool *null);
	double jitter_rtcp_avg(bool *null);
	double jitter_rtcp_max(bool *null);
	double fr_rtcp_avg(bool *null);
	double fr_rtcp_max(bool *null);
	
	void addEnergyLevel(u_int16_t energyLevel, u_int16_t seq);
	void addEnergyLevel(void *data, int datalen, int codec);
	
	bool is_video() {
		return(media.sdp_flags.is_mt_video());
	}
	bool allowed_for_ab() {
		return(!is_video());
	}

	inline unsigned received_() {
		return(stats.received);
	}
	inline void set_received_(u_int32_t r) {
		stats.received = r;
	}
	inline unsigned lost_() {
		return(stats.lost);
	}
	inline void set_lost_(u_int32_t l) {
		stats.lost = l;
	}
	inline double lost_perc_() {
		unsigned lost = lost_();
		unsigned received = received_();
		return(lost ?
			(received ? (double)lost/(lost + received) * 100 : 100) :
			0);
	}
	inline double lost_ratio_() {
		unsigned lost = lost_();
		unsigned received = received_();
		return(lost ?
			(received ? (double)lost/received : 1e10) :
			0);
	}
	inline int first_codec_() {
		return(media.first_codec);
	}
	inline void set_first_codec_(int c) {
		media.first_codec = c;
	}
	inline bool ok_other_ip_side_by_sip_() {
		return(sdp.ok_other_ip_side_by_sip);
	}
	
	RTPMAP *get_rtpmap(class Call *call, class CallBranch *c_branch, bool other_side = false);
	
	bool is_unencrypted_payload(u_char *data, unsigned datalen);
	
	bool channel_is_adaptive(struct ast_channel *channel);
	bool channel_record_is_adaptive() {
		#if not EXPERIMENTAL_SUPPRESS_AST_CHANNELS
		return(channel_is_adaptive(jb.channel_record));
		#else
		return(false);
		#endif
	}
	
	string getJson();
	
private: 
	inline RTPFixedHeader* getHeader() const { return reinterpret_cast<RTPFixedHeader*>(pkt.data); }
	static inline RTPFixedHeader* getHeader(void *data) { return reinterpret_cast<RTPFixedHeader*>(data); }
	
	void update_stats();
	void update_graph_silence();

	void init_seq(u_int16_t seq);
	int update_seq(u_int16_t seq);

	// ===== Cold private substructures =====

	/* Energy levels recording state (16B) */
	struct s_energy {
		void init() {
			buf = NULL;
			counter = 0;
			last_seq = 0;
			via_jb = false;
		}
		SimpleChunkBuffer *buf;
		u_int32_t counter;
		u_int16_t last_seq;
		bool via_jb;
	} energy;

	sRSA rsa;

	/* Sensor metadata, syslog throttling and debug counters (56B) */
	struct s_diag {
		void init(int sensor_id_, vmIP sensor_ip_) {
			lastTimeSyslog = 0;
			sensor_ip = sensor_ip_;
			sensor_id = sensor_id_;
			_last_sensor_id = 0;
			read_rtp_counter = 0;
			_last_ifname[0] = '\0';
		}
		u_int64_t lastTimeSyslog;
		vmIP sensor_ip;
		int sensor_id;
		int _last_sensor_id;
		unsigned read_rtp_counter;
		char _last_ifname[10];
	} diag;

friend class Call;
friend class RTPsecure;
};

#endif // EXPERIMENTAL_LITE_RTP_MOD


class RTPstat {
	typedef struct {
		uint32_t 	time;		// seconds since unix epoch of the last update 
		uint8_t 	mosf1_min;
		float 		mosf1_avg;
		uint8_t 	mosf2_min;
		float 		mosf2_avg;
		uint8_t 	mosAD_min;
		float 		mosAD_avg;
		uint16_t 	jitter_max;
		float 		jitter_avg;
		float	 	loss_max;
		float	 	loss_avg;
		uint32_t	counter;	// will be reset with every update 
		uint32_t	refcount;	// reference count to RTP class for cleaning purpose 
	} node_t;
public:
	RTPstat() {
		lasttime1 = lasttime2 = 0;
		pthread_mutex_init(&mlock, NULL);
		mod = 10;
		maps[0] = &saddr_map[0];
		maps[1] = &saddr_map[1];
	}
	~RTPstat() {
		pthread_mutex_destroy(&mlock);
	}
	void lock() {
		pthread_mutex_lock(&mlock);
	}
	void unlock() {
		pthread_mutex_unlock(&mlock);
	}
	void update(vmIP saddr, uint32_t time, uint8_t mosf1, uint8_t mosf2, uint8_t mosAD, uint16_t jitter, double loss);
	void flush_and_clean(map<vmIP, node_t> *map, bool needLock = true);
	void flush();

private:
	map<vmIP, node_t> saddr_map[2];
	map<vmIP, node_t> *maps[2];
	int mod;
	pthread_mutex_t mlock;
	uint32_t lasttime1;
	uint32_t lasttime2;
};


struct sStreamAnalysisData {
	~sStreamAnalysisData() {
		clear();
	}
	struct sStreamAnalysisRow {
		sStreamAnalysisRow() {
			memset(this, 0, sizeof(*this));
		}
		u_int32_t counter;
		int64_t time_real_us;
		int64_t time_rtp_us;
		u_int16_t seq;
		int64_t delta_real_us;
		int64_t delta_rtp_us;
		int64_t transit;
		int64_t skew;
		double jitter;
		double jitter_rsa;
		bool marker;
		bool bad_seq;
		unsigned payload_len;
		int codec;
		bool set_energylevel;
		u_int16_t energylevel;
	};
	struct sStreamAnalysisRowMos {
		sStreamAnalysisRowMos() {
			memset(this, 0, sizeof(*this));
		}
		unsigned f1;
		unsigned f2;
		unsigned adapt;
		unsigned silence;
	};
	vector<sStreamAnalysisRow*> rows;
	map<u_int64_t, sStreamAnalysisRowMos*> mos;
	void exportCsvHeader();
	void exportCsvRow(sStreamAnalysisRow *row, sStreamAnalysisRowMos *row_mos);
	void exportCsvMos(sStreamAnalysisRowMos *row);
	void exportCsvRows(bool all = false);
	void clear();
};


u_int16_t get_energylevel(u_char *data, int datalen, int codec);


#endif
