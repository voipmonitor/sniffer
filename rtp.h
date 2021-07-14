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
	inline bool is_set() {
		return(payload || codec);
	}
	inline void clear() {
		payload = 0;
		codec = 0;
		frame_size = 0;
	}
	u_int16_t payload;
	u_int16_t codec;
	u_int16_t frame_size;
};


enum eRtpMarkType {
	_mark_rtp = 1,
	_forcemark_diff_seq = 2,
	_forcemark_sip_sdp = 3
};


/**
 * This class implements operations on RTP strem
 */
class RTP {
       /* extension header */
	typedef struct {
		u_int16_t profdef;
		u_int16_t length; // length of extension in 32bits, this header exluded.
	} extension_hdr_t;
	struct sRSA {
		sRSA() {
			counter = 0;
			first_packet_time_us = 0;
			last_packet_time_us = 0;
			first_timestamp = 0;
			last_timestamp = 0;
			jitter = 0;
			prev_seq = 0;
		}
		u_int32_t counter;
		u_int64_t first_packet_time_us;
		u_int64_t last_packet_time_us;
		u_int32_t first_timestamp;
		u_int32_t last_timestamp;
		u_int16_t prev_seq;
		double jitter;
	};
public: 
	u_int32_t ssrc;		//!< ssrc of this RTP class
	u_int32_t ssrc2;	//!< ssrc of this RTP class
	vmIP saddr;	//!< last source IP adress 
	vmIP daddr;	//!< last source IP adress 
	vmPort sport;
	vmPort dport;
	vmPort prev_sport;
	vmPort prev_dport;
	bool change_src_port;
	bool find_by_dest;
	bool ok_other_ip_side_by_sip;
	u_int16_t avg_ptime;
	u_int32_t avg_ptime_count;
	RtpGraphSaver graph;
	FILE *gfileRAW;	 //!< file for storing RTP payload in RAW format
	bool initRAW;
	bool needInitRawForChannelRecord;
	char *gfileRAW_buffer;
	char gfilename[1024];	//!< file name of this file 
	char basefilename[1024];
	int rawiterator;	//!< iterator for raw file name 
	struct ast_channel *channel_fix1;
	struct ast_channel *channel_fix2;
	struct ast_channel *channel_adapt;
	struct ast_channel *channel_record;
	struct ast_frame *frame;
	int lastframetype;		//!< last packet sequence number
	char lastcng;		//!< last packet sequence number
	u_int16_t seq;		//!< current sequence number
	int last_seq;		//!< last packet sequence number
	u_int16_t channel_record_seq_ringbuffer[50];
	u_int16_t channel_record_seq_ringbuffer_pos;
	int packetization;	//!< packetization in millisenocds
	int last_packetization;	//!< last packetization in millisenocds
	int last_ts;		//!< last timestamp 
	u_int64_t last_pcap_header_us;
	bool pcap_header_ts_bad_time;
	int packetization_iterator;	
	int prev_payload;
	int prev_codec;
	int payload2;
	int first_codec;
	int codec;
	s_sdp_flags_base sdp_flags;
	int frame_size;
	RTPMAP rtpmap[MAX_RTPMAP];
	RTPMAP rtpmap_other_side[MAX_RTPMAP];
	unsigned char* data;    //!< pointer to UDP payload
	iphdr2 *header_ip;
	int len;		//!< lenght of UDP payload
	unsigned char* payload_data;    //!< pointer to RTP payload
	int payload_len;	//!< lenght of RTP payload
	uint8_t padding_len;	//!< lenght of RTP payload
	u_int16_t prev_payload_len;	//!< lenght of RTP payload
	int ssrc_index;		//!< index 
	int iscaller;		//!< flag which indicates if RTP stream is part of caller or callee
	void *call_owner;	//!< which Call owns us
	int default_packetization;
	int sid;
	int prev_sid;
	int pinformed;
	u_int64_t first_packet_time_us;
	u_int64_t last_packet_time_us;
	unsigned int last_end_timestamp;
	char lastdtmf;
	u_int8_t forcemark;
	u_int8_t forcemark2;
	bool forcemark_by_owner;
	bool forcemark_by_owner_set;
	unsigned forcemark_owner_used;
	char ignore;
	uint8_t dscp;
	bool skip;
	unsigned int last_mos_time;
	uint8_t	mosf1_min;
	uint8_t	mosf2_min;
	uint8_t	mosAD_min;
	uint8_t	mosSilence_min;
	float	mosf1_avg;
	float	mosf2_avg;
	float	mosAD_avg;
	float	mosSilence_avg;
	uint32_t	mos_counter;
	char save_mos_graph_wait;
	timeval _last_ts;
	timeval last_voice_frame_ts;
	uint32_t last_voice_frame_timestamp;
	bool	resetgraph;
	bool	mos_processed;
	double	jitter;
	uint32_t last_stat_lost;
	uint32_t last_stat_received;
	double last_stat_loss_perc_mult10;
	bool codecchanged;
	uint32_t counter;
	bool had_audio;
	bool defer_codec_change;
	bool stream_in_multiple_calls;
	uint32_t tailedframes;
	uint8_t change_packetization_iterator;
	bool last_was_silence;
	uint32_t sum_silence_changes;
	bool confirm_both_sides_by_sdp;

	/* RTCP data */
	struct rtcp_t {
		int loss;
		unsigned int maxfr;
		double avgfr;
		unsigned int maxjitter;
		double avgjitter;
		unsigned int counter;
		unsigned int jitt_counter;
		unsigned int fraclost_pkt_counter;
		u_int32_t lsr4compare;
		u_int32_t last_lsr;
		u_int32_t last_lsr_delay;
		struct timeval sniff_ts;
		unsigned int rtd_sum;	/* roundtrip delay */
		unsigned int rtd_count;
		unsigned int rtd_max;
		unsigned int rtd_w_sum;	/* roundtrip delay by wireshark*/
		unsigned int rtd_w_count;
		unsigned int rtd_w_max;
	} rtcp;

	struct rtcp_xr_t {
		uint8_t 	maxfr;
		double 		avgfr;
		uint8_t		minmos;
		double 		avgmos;
		unsigned int counter_fr;
		unsigned int counter_mos;
	} rtcp_xr;

	unsigned int samplerate;

	struct stats_t {
		u_int32_t	d50;	//!< delay from 0 to 50
		u_int32_t	d70;
		u_int32_t	d90;
		u_int32_t	d120; 
		u_int32_t	d150; 
		u_int32_t	d200; 
		u_int32_t	d300;

		u_int32_t	slost[11];	//!< lost counts
		
		u_int32_t	received;	//!< overall received packets
		u_int32_t	lost;		//!< overall lost packets (real)
		u_int32_t	lost2;		//!< overall lost packets
		int		last_lost;	//!< last overall lost packepts
		long double 	avgjitter;
		long double 	maxjitter;
	} stats;

	typedef struct {
		u_int16_t max_seq;		//!< highest seq. number seen 
		int64_t cycles;			//!< shifted count of seq. number cycles
		u_int32_t base_seq;		//!< base seq number
		u_int32_t bad_seq;		//!< last 'bad' seq number + 1
		u_int32_t probation;		//!< sequ. packets till source is valid
		u_int32_t received;		//!< packets received
		u_int32_t expected_prior;	//!< packet expected at last interval
		u_int32_t received_prior;	//!< packet received at last interval
		u_int32_t transit;		//!< relative trans time for prev pkt
		u_int32_t jitter;		//!< estimated jitter
		u_int32_t lost;			//!< lost packets
		struct timeval lastTimeRec;	//!< last received time from pcap packet header
		struct timeval lastTimeRecJ;	//!< last received time from pcap packet header for jitterbuffer
		u_int32_t lastTimeStamp;	//!< last received timestamp from RTP header
		u_int32_t lastTimeStampJ;	//!< last received timestamp from RTP header for jitterbuffer
		int delay;
		long double fdelay;
		double prevjitter;
		double avgdelay;
	} source;

	float avgdelays[30];

	bool last_markbit;
	unsigned char last_interval_mosf1;
	unsigned char last_interval_mosf2;
	unsigned char last_interval_mosAD;
	unsigned char last_interval_mosSilence;

	struct dsp *DSP;

	source *s;

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
	
	void setSRtpDecrypt(class RTPsecure *srtp_decrypt);

	/**
	 * @brief simulate jitter buffer
	 *
	 * Put packet to jitterbuffer associated to channel structure
	 *
	 * @param channel pointer to the channel structure which holds statistics and jitterbuffer data
	 *
	*/
	void jitterbuffer(struct ast_channel *channel, bool save_audio, bool energylevels, bool mos_lqo);

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
	bool read(unsigned char* data, iphdr2 *header_ip, unsigned *len, struct pcap_pkthdr *header, vmIP saddr, vmIP daddr, vmPort sport, vmPort dport,
		  int sensor_id, vmIP sensor_ip, char *ifname = NULL);


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
	const u_int32_t getReceived() { return s->received; };

	inline const int getMarker() { return getHeader()->marker ? 1 : forcemark; };
	
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
	u_int32_t getLost() { return s->probation ? 0 : ((s->cycles + s->max_seq) - s->base_seq + 1) - s->received; };

	void save_mos_graph(bool delimiter);
	
	inline void clearAudioBuff(class Call *call, ast_channel *channel);
	
	bool eqAddrPort(vmIP saddr, vmIP daddr, vmPort sport, vmPort dport) {
		return(this->saddr == saddr && this->daddr == daddr &&
		       this->sport == sport && this->dport == dport);
	}
	bool eqAddrPort(RTP *rtp) {
		return(eqAddrPort(rtp->saddr, rtp->daddr, rtp->sport, rtp->dport));
	}
	
	bool checkDuplChannelRecordSeq(u_int16_t seq) {
		extern int opt_saveaudio_dedup_seq;
		if(opt_saveaudio_dedup_seq) {
			unsigned ringbuffer_length = sizeof(channel_record_seq_ringbuffer) / sizeof(channel_record_seq_ringbuffer[0]);
			for(unsigned i = 0; i < ringbuffer_length; i++) {
				if(seq == channel_record_seq_ringbuffer[i]) {
					return(false);
				}
			}
			channel_record_seq_ringbuffer[channel_record_seq_ringbuffer_pos] = seq;
			++channel_record_seq_ringbuffer_pos;
			if(channel_record_seq_ringbuffer_pos >= ringbuffer_length) {
				channel_record_seq_ringbuffer_pos = 0;
			}
		}
		return(true);
	}

	void rtp_stream_analysis_output();
	
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
		return(sdp_flags.is_video());
	}
	bool allowed_for_ab() {
		return(!is_video());
	}

private: 
	/*
	* Per-source state information
	*/

	struct timeval header_ts;
	bool first;
	int nintervals;

	inline RTPFixedHeader* getHeader() const { return reinterpret_cast<RTPFixedHeader*>(data); }
	static inline RTPFixedHeader* getHeader(void *data) { return reinterpret_cast<RTPFixedHeader*>(data); }
	
	void update_stats();
	void update_graph_silence();

	void init_seq(u_int16_t seq);
	int update_seq(u_int16_t seq);

	int sensor_id;
	vmIP sensor_ip;
	int index_call_ip_port;
	bool index_call_ip_port_by_dest;
	
	int _last_sensor_id;
	char _last_ifname[10];
	
	u_int64_t lastTimeSyslog;
	
	bool stopReadProcessing;
	
	class RTPsecure *srtp_decrypt;
	
	sRSA rsa;
	
	SimpleChunkBuffer *energylevels;
	u_int16_t energylevels_last_seq;
	bool energylevels_via_jb;
	u_int32_t energylevels_counter;
	
friend class Call;
};


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


u_int16_t get_energylevel(u_char *data, int datalen, int codec);


#endif
