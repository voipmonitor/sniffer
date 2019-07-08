#ifndef AUDIOCODES_H
#define AUDIOCODES_H


#include "ip.h"


struct sAudiocodes {
	enum eMediaTypes {
		ac_mt_DSP_AC49X =0,
		ac_mt_RTP		=1,
		ac_mt_RTCP	=2,
		ac_mt_T38		=3,
		ac_mt_Event	=4,
		ac_mt_Info	=5,
		ac_mt_ATMAAL1	=6,
		ac_mt_ATMAAL2	=7,
		ac_mt_AAL2	=8,
		ac_mt_ATMAAL5	=9,
		ac_mt_SIP		=10,
		ac_mt_MEGACO	=11,
		ac_mt_MGCP	=12,
		ac_mt_TPNCP	=13,
		ac_mt_Control =14,
		ac_mt_PCM		=15,
		ac_mt_NP_CONTROL	= 16,
		ac_mt_NP_DATA		= 17,
		ac_mt_DSP_AC48X =18,
		ac_mt_DSP_AC45X =19,
		ac_mt_RESERVED_FOR_INTERNAL_USE_20 = 20,
		ac_mt_RESERVED_FOR_INTERNAL_USE_21 = 21,
		ac_mt_RESERVED_FOR_INTERNAL_USE_22 = 22,
		ac_mt_HA = 23,
		ac_mt_CAS = 24,
		ac_mt_NET_BRICKS = 25,
		ac_mt_COMMAND = 26,
		ac_mt_VIDEORTP	= 27,
		ac_mt_VIDEORTCP	= 28,
		ac_mt_PCIIF_COMMAND = 29,
		ac_mt_GWAPPSYSLOG = 30,
		ac_mt_V1501 = 31,
		ac_mt_DSP_AC5X =32,
		ac_mt_TLS = 33,
		ac_mt_TLSPeek = 34,
		ac_mt_DSP_AC5X_MII = 35,
		ac_mt_NATIVE = 36,
		ac_mt_SIGNALING = 37,
		ac_mt_FRAGMENTED = 38,
		ac_mt_RESERVED_FOR_INTERNAL_USE_39 = 39,
		ac_mt_RESERVED_FOR_INTERNAL_USE_40 = 40,
		ac_mt_RESERVED_FOR_INTERNAL_USE_41 = 41,
		ac_mt_QOE_CDR = 42,
		ac_mt_QOE_MDR = 43,
		ac_mt_QOE_EVENT = 44,
		ac_mt_RESERVED_FOR_INTERNAL_USE_45 = 45,
		ac_mt_RESERVED_FOR_INTERNAL_USE_46 = 46,
		ac_mt_DSP_TDM_PLAYBACK = 47,
		ac_mt_DSP_NET_PLAYBACK = 48,
		ac_mt_DSP_DATA_RELAY = 49,
		ac_mt_DSP_SNIFFER = 50,
		ac_mt_RTP_AMR = 51,
		ac_mt_RTP_EVRC= 52,
		ac_mt_RTP_RFC2198 = 53,
		ac_mt_RTP_RFC2833 = 54,
		ac_mt_T38_OVER_RTP = 55,
		ac_mt_RTP_FEC = 56,
		ac_mt_RTP_FAX_BYPASS = 57,
		ac_mt_RTP_MODEM_BYPASS = 58,
		ac_mt_RTP_NSE = 59,
		ac_mt_RTP_NO_OP = 60,
		ac_mt_DTLS = 61
	};
	enum eTracePoints {
		ac_tp_Net2Dsp			=0,
		ac_tp_Dsp2Net			=1,
		ac_tp_Dsp2Host		=2,
		ac_tp_Host2Dsp		=3,
		ac_tp_Net2Host		=4,
		ac_tp_Host2Net		=5,
		ac_tp_System			=6,
		ac_tp_Dsp2Dsp			=7,
		ac_tp_Net2Net			=8,
		ac_tp_Dsp2Tdm			=9,
		ac_tp_Tdm2Dsp			=10,
		ac_tp_Np2Dsp			=11,
		ac_tp_Dsp2Np			=12,
		ac_tp_Host2Np			=13,
		ac_tp_Np2Host			=14,
		ac_tp_acUnknown		=15,
		ac_tp_Net				=16,
		ac_tp_P2P				=17,
		ac_tp_DspDecoder		=18,
		ac_tp_DspEncoder		=19,
		ac_tp_VoipDecoder		=20,
		ac_tp_VoipEncoder		=21,
		ac_tp_NetEncoder		=22,
		ac_tp_P2PDecoder		=23,
		ac_tp_P2PEncoder		=24,
		ac_tp_Host2Pstn		=25,
		ac_tp_Pstn2Host		=26,
		ac_tp_Net2DspPing		=27,
		ac_tp_Dsp2NetPing		=28,
		ac_tp_Src2Dest		=29,
		ac_tp_Addr2Addr		=30,
		ac_tp_GeneralSystem	=31,
		ac_tp_AllMedia		=32,
		ac_tp_DspIncoming		=33,
		ac_tp_DspOutgoing		=34,
		ac_tp_AfterSrtpDecoder=35
	};
	void init();
	bool parse(u_char *ac_header, unsigned length);
	void set_ip(vmIP *ip, u_char *data, bool ipv6 = false);
	void set_port(vmPort *port, u_char *data);
	iphdr2* get_iphdr(u_char *ac_header);
	udphdr2* get_udphdr(u_char *ac_header);
	tcphdr2* get_tcphdr(u_char *ac_header);
	u_char* get_data(u_char *ac_header);
	unsigned get_data_offset(u_char *ac_header);
	u_int8_t version;
	u_int8_t header_length;
	u_int8_t header_length_extension;
	u_int8_t header_length_total;
	u_int64_t timestamp;
	u_int16_t sequence_number;
	u_int32_t source_id;
	u_int32_t dest_id;
	u_int8_t extra_data;
	u_int8_t trace_point;
	u_int8_t media_type;
	u_int8_t payload_offset;
	u_char session_id[9];
	u_int8_t session_id_length;
	vmIP packet_source_ip;
	vmIP packet_dest_ip;
	vmPort packet_source_port;
	vmPort packet_dest_port;
	u_int8_t ip_type_of_service;
	u_int8_t ip_protocol_type;
	u_int8_t packet_direction;
	u_int8_t payload_type;
};


#endif
