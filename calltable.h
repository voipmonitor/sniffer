/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/* Calls are stored into indexed array. 
 * Into one calltable is stored SIP call-id and IP-port of SDP session
 */

#ifndef CALLTABLE_H
#define CALLTABLE_H


// experimental modes:
#define NEW_RTP_FIND__NODES 0
#define NEW_RTP_FIND__PORT_NODES 0
#define NEW_RTP_FIND__MAP_LIST 0
#define NEW_RTP_FIND__NODES__PORT_MODE 1
#define NEW_RTP_FIND__NODES__LIST 0
#define HASH_RTP_FIND__LIST 0


#include <queue>
#include <map>
#include <list>
#include <set>
#include <deque>
#include <vector>

#include <arpa/inet.h>
#include <time.h>
#include <limits.h>
#include <semaphore.h>

#include <pcap.h>

#include <string>

#include "mgcp.h"
#include "rtp.h"
#include "tools.h"
#include "sql_db.h"
#include "voipmonitor.h"
#include "tools_fifo_buffer.h"
#include "record_array.h"
#include "calltable_base.h"
#include "dtls.h"
#include "ipfix.h"


#define MAX_IP_PER_CALL 40	//!< total maxumum of SDP sessions for one call-id
#define MAX_SSRC_PER_CALL_FIX 40	//!< total maxumum of SDP sessions for one call-id
#if CALL_RTP_DYNAMIC_ARRAY
typedef vector<RTP*> CALL_RTP_DYNAMIC_ARRAY_TYPE;
#endif
#define MAX_FNAME 256		//!< max len of stored call-id
#define MAX_RTPMAP 40          //!< max rtpmap records
#define MAXNODE 150000
#define MAX_SIPCALLERDIP 8
#define MAXLEN_SDP_SESSID 30
#define MAXLEN_SDP_LABEL 20

#define INVITE 1
#define REINVITE 1000
#define BYE 2
#define CANCEL 3
#define RES10X 100
#define RES18X 180
#define RES182 182
#define RES2XX 200
#define RES2XX_INVITE 200001
#define RES300 300
#define RES3XX 399
#define RES401 401
#define RES403 403
#define RES404 404
#define RES4XX 400
#define RES5XX 500
#define RES6XX 600
#define REGISTER 4
#define MESSAGE 5
#define INFO 6
#define SUBSCRIBE 7
#define OPTIONS 8
#define NOTIFY 9
#define ACK 10
#define PRACK 11
#define PUBLISH 12
#define REFER 13
#define UPDATE 14
#define SKINNY_NEW 100
#define SS7 200
#define MGCP 300

#define IS_SIP_RES18X(sip_method) (sip_method == RES18X || sip_method == RES182)
#define IS_SIP_RES3XX(sip_method) (sip_method == RES300 || sip_method == RES3XX)
#define IS_SIP_RES4XX(sip_method) (sip_method == RES401 || sip_method == RES403 || sip_method == RES404 || sip_method == RES4XX)
#define IS_SIP_RESXXX(sip_method) (sip_method == RES10X || sip_method == RES18X || sip_method == RES182 || sip_method == RES2XX || IS_SIP_RES3XX(sip_method) || IS_SIP_RES4XX(sip_method) || sip_method == RES5XX || sip_method == RES6XX)

enum eCallBitFlag {
	 _CALL_BIT_SAVESIP,
	 _CALL_BIT_SAVERTP,
	 _CALL_BIT_SAVERTPHEADER,
	 _CALL_BIT_SAVERTP_VIDEO,
	 _CALL_BIT_SAVERTP_VIDEO_HEADER,
	 _CALL_BIT_PROCESSING_RTP_VIDEO,
	 _CALL_BIT_SAVEMRCP,
	 _CALL_BIT_SAVERTCP,
	 _CALL_BIT_SAVEREGISTERDB,
	 _CALL_BIT_SAVEREGISTERPCAP,
	 _CALL_BIT_SAVEAUDIO,
	 _CALL_BIT_FORMATAUDIO_WAV,
	 _CALL_BIT_FORMATAUDIO_OGG,
	 _CALL_BIT_FORMATAUDIO_MP3,
	 _CALL_BIT_AUDIOTRANSCRIBE,
	 _CALL_BIT_SAVEGRAPH,
	 _CALL_BIT_SAVEAUDIOGRAPH,
	 _CALL_BIT_SKIPCDR,
	 _CALL_BIT_RUNSCRIPT,
	 _CALL_BIT_RUNAMOSLQO,
	 _CALL_BIT_RUNBMOSLQO,
	 _CALL_BIT_HIDEMESSAGE,
	 _CALL_BIT_USE_SPOOL_2,
	 _CALL_BIT_SAVEDTMFDB,
	 _CALL_BIT_SAVEDTMFPCAP,
	 _CALL_BIT_SAVEOPTIONSDB,
	 _CALL_BIT_SAVEOPTIONSPCAP,
	 _CALL_BIT_SAVENOTIFYDB,
	 _CALL_BIT_SAVENOTIFYPCAP,
	 _CALL_BIT_SAVESUBSCRIBEDB,
	 _CALL_BIT_SAVESUBSCRIBEPCAP
};

#define CALL_FLAG(bit) (((u_int64_t)1) << (bit))

#define FLAG_SAVESIP			CALL_FLAG(_CALL_BIT_SAVESIP)
#define FLAG_SAVERTP			CALL_FLAG(_CALL_BIT_SAVERTP)
#define FLAG_SAVERTPHEADER		CALL_FLAG(_CALL_BIT_SAVERTPHEADER)
#define FLAG_SAVERTP_VIDEO		CALL_FLAG(_CALL_BIT_SAVERTP_VIDEO)
#define FLAG_SAVERTP_VIDEO_HEADER	CALL_FLAG(_CALL_BIT_SAVERTP_VIDEO_HEADER)
#define FLAG_PROCESSING_RTP_VIDEO	CALL_FLAG(_CALL_BIT_PROCESSING_RTP_VIDEO)
#define FLAG_SAVEMRCP			CALL_FLAG(_CALL_BIT_SAVEMRCP)
#define FLAG_SAVERTCP			CALL_FLAG(_CALL_BIT_SAVERTCP)
#define FLAG_SAVEREGISTERDB		CALL_FLAG(_CALL_BIT_SAVEREGISTERDB)
#define FLAG_SAVEREGISTERPCAP		CALL_FLAG(_CALL_BIT_SAVEREGISTERPCAP)
#define FLAG_SAVEAUDIO			CALL_FLAG(_CALL_BIT_SAVEAUDIO)
#define FLAG_FORMATAUDIO_WAV		CALL_FLAG(_CALL_BIT_FORMATAUDIO_WAV)
#define FLAG_FORMATAUDIO_OGG		CALL_FLAG(_CALL_BIT_FORMATAUDIO_OGG)
#define FLAG_FORMATAUDIO_MP3		CALL_FLAG(_CALL_BIT_FORMATAUDIO_MP3)
#define FLAG_SAVEAUDIO_WAV		(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_WAV)
#define FLAG_SAVEAUDIO_OGG		(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_OGG)
#define FLAG_SAVEAUDIO_MP3		(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_MP3)
#define FLAG_AUDIOTRANSCRIBE		CALL_FLAG(_CALL_BIT_AUDIOTRANSCRIBE)
#define FLAG_SAVEGRAPH			CALL_FLAG(_CALL_BIT_SAVEGRAPH)
#define FLAG_SAVEAUDIOGRAPH		CALL_FLAG(_CALL_BIT_SAVEAUDIOGRAPH)
#define FLAG_SKIPCDR			CALL_FLAG(_CALL_BIT_SKIPCDR)
#define FLAG_RUNSCRIPT			CALL_FLAG(_CALL_BIT_RUNSCRIPT)
#define FLAG_RUNAMOSLQO			CALL_FLAG(_CALL_BIT_RUNAMOSLQO)
#define FLAG_RUNBMOSLQO			CALL_FLAG(_CALL_BIT_RUNBMOSLQO)
#define FLAG_HIDEMESSAGE		CALL_FLAG(_CALL_BIT_HIDEMESSAGE)
#define FLAG_USE_SPOOL_2		CALL_FLAG(_CALL_BIT_USE_SPOOL_2)
#define FLAG_SAVEDTMFDB			CALL_FLAG(_CALL_BIT_SAVEDTMFDB)
#define FLAG_SAVEDTMFPCAP		CALL_FLAG(_CALL_BIT_SAVEDTMFPCAP)
#define FLAG_SAVEOPTIONSDB		CALL_FLAG(_CALL_BIT_SAVEOPTIONSDB)
#define FLAG_SAVEOPTIONSPCAP		CALL_FLAG(_CALL_BIT_SAVEOPTIONSPCAP)
#define FLAG_SAVENOTIFYDB		CALL_FLAG(_CALL_BIT_SAVENOTIFYDB)
#define FLAG_SAVENOTIFYPCAP		CALL_FLAG(_CALL_BIT_SAVENOTIFYPCAP)
#define FLAG_SAVESUBSCRIBEDB		CALL_FLAG(_CALL_BIT_SAVESUBSCRIBEDB)
#define FLAG_SAVESUBSCRIBEPCAP		CALL_FLAG(_CALL_BIT_SAVESUBSCRIBEPCAP)

#define CDR_FLAG(bit) (((u_int64_t)1) << (bit))

enum eCdrBitFlag {
	_CDR_BIT_CHANGE_SRC_PORT_CALLER,
	_CDR_BIT_CHANGE_SRC_PORT_CALLED,
	_CDR_BIT_UNCONFIRMED_BYE,
	_CDR_BIT_ALONE_UNCONFIRMED_BYE,
	_CDR_BIT_SRTP_WITHOUT_KEY,
	_CDR_BIT_FAS_DETECTED,
	_CDR_BIT_ZEROSSRC_DETECTED,
	_CDR_BIT_SIPALG_DETECTED,
	_CDR_BIT_TELEVENT_EXISTS_REQUEST,
	_CDR_BIT_TELEVENT_EXISTS_RESPONSE,
	_CDR_BIT_SIP_FRAGMENTED,
	_CDR_BIT_RTP_FRAGMENTED,
	_CDR_BIT_SDP_EXISTS_MEDIA_TYPE_AUDIO,
	_CDR_BIT_SDP_EXISTS_MEDIA_TYPE_IMAGE,
	_CDR_BIT_SDP_EXISTS_MEDIA_TYPE_VIDEO,
	_CDR_BIT_PROCLIM_SUPPRESS_RTP_READ,
	_CDR_BIT_PROCLIM_SUPPRESS_RTP_PROC,
	_CDR_BIT_RTCP_EXISTS,
	_CDR_BIT_PCAP_IN_SAFESPOOLDIR,
	_CDR_BIT_PCAP_DUMP_ERROR_DTL,
	_CDR_BIT_PCAP_DUMP_ERROR_MAXPCAPSIZE,
	_CDR_BIT_PCAP_DUMP_ERROR_CAPLEN,
	_CDR_BIT_RTP_DUPL_SEQ,
	_CDR_BIT_SAVE_FLAGS,
	_CDR_BIT_SAVE_SIP_PCAP,
	_CDR_BIT_SAVE_RTP_PCAP,
	_CDR_BIT_SAVE_RTP_PAYLOAD_PCAP,
	_CDR_BIT_SAVE_RTCP_PCAP,
	_CDR_BIT_SAVE_RTP_GRAPH,
	_CDR_BIT_SAVE_AUDIO,
	_CDR_BIT_SAVE_AUDIOGRAPH,
	_CDR_BIT_PROTO_TCP,
	_CDR_BIT_PROTO_UDP,
	_CDR_BIT_PROTO_TLS,
	_CDR_BIT_STOPPED_JB_DUE_TO_HIGH_OOO,
	_CDR_BIT_CHANGING_CODEC_IN_STREAM
};

#define CDR_CHANGE_SRC_PORT_CALLER		CDR_FLAG(_CDR_BIT_CHANGE_SRC_PORT_CALLER)
#define CDR_CHANGE_SRC_PORT_CALLED		CDR_FLAG(_CDR_BIT_CHANGE_SRC_PORT_CALLED)
#define CDR_UNCONFIRMED_BYE			CDR_FLAG(_CDR_BIT_UNCONFIRMED_BYE)
#define CDR_ALONE_UNCONFIRMED_BYE		CDR_FLAG(_CDR_BIT_ALONE_UNCONFIRMED_BYE)
#define CDR_SRTP_WITHOUT_KEY			CDR_FLAG(_CDR_BIT_SRTP_WITHOUT_KEY)
#define CDR_FAS_DETECTED			CDR_FLAG(_CDR_BIT_FAS_DETECTED)
#define CDR_ZEROSSRC_DETECTED			CDR_FLAG(_CDR_BIT_ZEROSSRC_DETECTED)
#define CDR_SIPALG_DETECTED			CDR_FLAG(_CDR_BIT_SIPALG_DETECTED)
#define CDR_TELEVENT_EXISTS_REQUEST		CDR_FLAG(_CDR_BIT_TELEVENT_EXISTS_REQUEST)
#define CDR_TELEVENT_EXISTS_RESPONSE		CDR_FLAG(_CDR_BIT_TELEVENT_EXISTS_RESPONSE)
#define CDR_SIP_FRAGMENTED			CDR_FLAG(_CDR_BIT_SIP_FRAGMENTED)
#define CDR_RTP_FRAGMENTED			CDR_FLAG(_CDR_BIT_RTP_FRAGMENTED)
#define CDR_SDP_EXISTS_MEDIA_TYPE_AUDIO		CDR_FLAG(_CDR_BIT_SDP_EXISTS_MEDIA_TYPE_AUDIO)
#define CDR_SDP_EXISTS_MEDIA_TYPE_IMAGE		CDR_FLAG(_CDR_BIT_SDP_EXISTS_MEDIA_TYPE_IMAGE)
#define CDR_SDP_EXISTS_MEDIA_TYPE_VIDEO		CDR_FLAG(_CDR_BIT_SDP_EXISTS_MEDIA_TYPE_VIDEO)
#define CDR_PROCLIM_SUPPRESS_RTP_READ		CDR_FLAG(_CDR_BIT_PROCLIM_SUPPRESS_RTP_READ)
#define CDR_PROCLIM_SUPPRESS_RTP_PROC		CDR_FLAG(_CDR_BIT_PROCLIM_SUPPRESS_RTP_PROC)
#define CDR_RTCP_EXISTS				CDR_FLAG(_CDR_BIT_RTCP_EXISTS)
#define CDR_PCAP_IN_SAFESPOOLDIR		CDR_FLAG(_CDR_BIT_PCAP_IN_SAFESPOOLDIR)
#define CDR_PCAP_DUMP_ERROR_DTL			CDR_FLAG(_CDR_BIT_PCAP_DUMP_ERROR_DTL)
#define CDR_PCAP_DUMP_ERROR_MAXPCAPSIZE		CDR_FLAG(_CDR_BIT_PCAP_DUMP_ERROR_MAXPCAPSIZE)
#define CDR_PCAP_DUMP_ERROR_CAPLEN		CDR_FLAG(_CDR_BIT_PCAP_DUMP_ERROR_CAPLEN)
#define CDR_RTP_DUPL_SEQ			CDR_FLAG(_CDR_BIT_RTP_DUPL_SEQ)
#define CDR_STOPPED_JB_DUE_TO_HIGH_OOO		CDR_FLAG(_CDR_BIT_STOPPED_JB_DUE_TO_HIGH_OOO)
#define CDR_CHANGING_CODEC_IN_STREAM		CDR_FLAG(_CDR_BIT_CHANGING_CODEC_IN_STREAM)

#define CDR_SAVE_FLAGS				CDR_FLAG(_CDR_BIT_SAVE_FLAGS)
#define CDR_SAVE_SIP_PCAP			CDR_FLAG(_CDR_BIT_SAVE_SIP_PCAP)
#define CDR_SAVE_RTP_PCAP			CDR_FLAG(_CDR_BIT_SAVE_RTP_PCAP)
#define CDR_SAVE_RTP_PAYLOAD_PCAP		CDR_FLAG(_CDR_BIT_SAVE_RTP_PAYLOAD_PCAP)
#define CDR_SAVE_RTCP_PCAP			CDR_FLAG(_CDR_BIT_SAVE_RTCP_PCAP)
#define CDR_SAVE_RTP_GRAPH			CDR_FLAG(_CDR_BIT_SAVE_RTP_GRAPH)
#define CDR_SAVE_AUDIO				CDR_FLAG(_CDR_BIT_SAVE_AUDIO)
#define CDR_SAVE_AUDIOGRAPH			CDR_FLAG(_CDR_BIT_SAVE_AUDIOGRAPH)

#define CDR_PROTO_TCP				CDR_FLAG(_CDR_BIT_PROTO_TCP)
#define CDR_PROTO_UDP				CDR_FLAG(_CDR_BIT_PROTO_UDP)
#define CDR_PROTO_TLS				CDR_FLAG(_CDR_BIT_PROTO_TLS)

#define CDR_RTP_STREAM_IN_MULTIPLE_CALLS	(1 << 0)
#define CDR_RTP_STREAM_IS_AB			(1 << 1)
#define CDR_RTP_STREAM_IS_CALLER		(1 << 2)
#define CDR_RTP_STREAM_IS_CALLED		(1 << 3)
#define CDR_RTP_STREAM_IS_SRTP			(1 << 4)
#define CDR_RTP_STOPPED_JB_DUE_TO_HIGH_OOO	(1 << 5)
#define CDR_RTP_CHANGING_CODEC			(1 << 6)

#define SS7_IAM 1
#define SS7_SAM 2
#define SS7_ACM 6
#define SS7_CPG 44
#define SS7_ANM 9
#define SS7_REL 12
#define SS7_RLC 16

#define SS7_FLAG_SONUS (1 << 0)
#define SS7_FLAG_RUDP (1 << 1)

#define NOFAX	0
#define T38FAX	1
#define T30FAX	2

#define iscaller_is_set(iscaller) (iscaller >= 0)
#define iscaller_index(iscaller) (iscaller > 0 ? 1 : 0)
#define iscaller_inv_index(iscaller) (iscaller > 0 ? 0 : 1)
#define iscaller_description(iscaller) (iscaller > 0 ? "caller" : (iscaller == 0 ? "called" : "unknown"))
#define iscaller_inv_description(iscaller) (iscaller > 0 ? "called" : (iscaller == 0 ? "caller" : "unknown"))

#define enable_save_dtmf_db		(flags & FLAG_SAVEDTMFDB)
#define enable_save_dtmf_pcap(call)	(call->flags & FLAG_SAVEDTMFPCAP)


struct s_dtmf {
	enum e_type {
		sip_info,
		inband,
		rfc2833
	};
	e_type type;
	double ts;
	char dtmf;
	vmIP saddr;
	vmIP daddr;
};


enum e_sdp_protocol {
	sdp_proto_na,
	sdp_proto_rtp,
	sdp_proto_srtp,
	sdp_proto_t38,
	sdp_proto_msrp,
	sdp_proto_sprt,
	sdp_proto_tcp_mrcpv2
};

struct s_sdp_flags : public s_sdp_flags_base {
	s_sdp_flags() {
		protocol = sdp_proto_na;
	}
	inline int operator != (const s_sdp_flags &other) {
		return(*(s_sdp_flags_base*)this != other);
	}
	int8_t protocol;
};

struct call_rtp {
	class CallBranch *c_branch;
	int8_t iscaller;
	u_int16_t is_rtcp;
	s_sdp_flags sdp_flags;
};

#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
struct node_call_rtp : public list<call_rtp*> {
};
#else
struct node_call_rtp : public call_rtp {
	node_call_rtp *next;
};
#endif

struct node_call_rtp_ip_port {
	node_call_rtp_ip_port *next;
	#if HASH_RTP_FIND__LIST
	node_call_rtp calls;
	#else
	node_call_rtp *calls;
	#endif
	vmIP addr;
	vmPort port;
};

struct node_call_rtp_ports {
	node_call_rtp_ports() {
		#if NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST
	 
		#else
		memset(ports, 0, sizeof(ports));
		#endif
	}
	#if NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST
		#if NEW_RTP_FIND__NODES__PORT_MODE == 1
		node_call_rtp ports[256];
		#else
		node_call_rtp ports[256*256];
		#endif
	#else
		#if NEW_RTP_FIND__NODES__PORT_MODE == 1
		node_call_rtp *ports[256];
		#else
		node_call_rtp *ports[256*256];
		#endif
	#endif
};

struct ip_port_call_info_rtp {
	vmIP saddr;
	vmPort sport;
	vmIP daddr;
	vmPort dport;
	time_t last_packet_time;
};

struct srtp_crypto_config {
	unsigned tag;
	string suite;
	string key;
	u_int64_t from_time_us;
};

struct s_sdp_media_data {
	s_sdp_media_data() {
		ip.clear();
		port.clear();
		label[0] = 0;
		inactive_ip0 = 0;
		srtp_crypto_config_list = NULL;
		srtp_fingerprint = NULL;
		exists_payload_televent = false;
		ptime = 0;
	}
	vmIP ip;
	vmPort port;
	char label[MAXLEN_SDP_LABEL];
	s_sdp_flags sdp_flags;
	int8_t inactive_ip0;
	list<srtp_crypto_config> *srtp_crypto_config_list;
	string *srtp_fingerprint;
	RTPMAP rtpmap[MAX_RTPMAP];
	bool exists_payload_televent;
	u_int16_t ptime;
};

struct s_sdp_store_data {
	vmIPport ip_port;
	bool is_caller;
	u_int16_t ptime;
	inline const bool operator == (const s_sdp_store_data &other) {
		return(this->ip_port == other.ip_port &&
		       this->is_caller == other.is_caller);
	}
};

struct ip_port_call_info {
	ip_port_call_info() {
		srtp = false;
		srtp_crypto_config_list = NULL;
		srtp_fingerprint = NULL;
		canceled = false;
	}
	~ip_port_call_info() {
		if(srtp_crypto_config_list) {
			delete srtp_crypto_config_list;
		}
		if(srtp_fingerprint) {
			delete srtp_fingerprint;
		}
	}
	void setSrtp() {
		srtp = true;
	}
	void setSrtpCryptoConfig(list<srtp_crypto_config> *srtp_crypto_config_list, u_int64_t from_time_us) {
		if(srtp_crypto_config_list && srtp_crypto_config_list->size()) {
			if(!this->srtp_crypto_config_list) {
				this->srtp_crypto_config_list = new FILE_LINE(0) list<srtp_crypto_config>;
				for(list<srtp_crypto_config>::iterator iter = srtp_crypto_config_list->begin(); iter != srtp_crypto_config_list->end(); iter++) {
					iter->from_time_us = from_time_us;
					this->srtp_crypto_config_list->push_back(*iter);
				}
			} else {
				for(list<srtp_crypto_config>::iterator iter = srtp_crypto_config_list->begin(); iter != srtp_crypto_config_list->end(); iter++) {
					bool exists = false;
					for(list<srtp_crypto_config>::iterator iter2 = this->srtp_crypto_config_list->begin(); iter2 != this->srtp_crypto_config_list->end(); iter2++) {
						if(iter->suite == iter2->suite && iter->key == iter2->key) {
							exists = true;
							break;
						}
					}
					if(!exists) {
						iter->from_time_us = from_time_us;
						this->srtp_crypto_config_list->push_back(*iter);
					}
				}
			}
		}
	}
	void setSrtpFingerprint(string *srtp_fingerprint) {
		if(srtp_fingerprint) {
			if(!this->srtp_fingerprint) {
				this->srtp_fingerprint = new FILE_LINE(0) string;
			}
			*this->srtp_fingerprint = *srtp_fingerprint;
		}
	}
	enum eTypeAddr {
		_ta_base,
		_ta_natalias,
		_ta_sdp_reverse_ipport
	};
	vmIP addr;
	u_int8_t type_addr;
	vmPort port;
	int8_t iscaller;
	string sessid;
	string sdp_label;
	bool srtp;
	list<srtp_crypto_config> *srtp_crypto_config_list;
	string *srtp_fingerprint;
	string to;
	string to_uri;
	string domain_to;
	string domain_to_uri;
	string branch;
	vmIP sip_src_addr;
	s_sdp_flags sdp_flags;
	u_int16_t ptime;
	ip_port_call_info_rtp rtp[2];
	bool canceled;
};

struct sCseq {
	inline void null() {
		method = -1;
		number = 0;
	}
	inline bool is_set() {
		return(method > 0);
	}
	inline const bool operator == (const sCseq &cseq_other) {
		return(this->method == cseq_other.method &&
		       this->number == cseq_other.number);
	}
	inline const bool operator != (const sCseq &cseq_other) {
		return(this->method != cseq_other.method ||
		       this->number != cseq_other.number);
	}
	int method;
	u_int32_t number;
};

class CallStructs {
public:
	struct sInviteCseqData {
		sInviteCseqData(u_int64_t time_us = 0) {
			this->time_us = time_us;
			first_response_100_time_us = 0;
			first_response_200_time_us = 0;
			first_response_xxx_time_us = 0;
		}
		u_int64_t time_us;
		u_int64_t first_response_100_time_us;
		u_int64_t first_response_200_time_us;
		u_int64_t first_response_xxx_time_us;
	};
	struct sInviteSD_Addr {
		sInviteSD_Addr() {
			confirmed = false;
			counter = 0;
			counter_reverse = 0;
		}
		vmIP saddr;
		vmIP daddr;
		vmIP saddr_first;
		vmIP daddr_first;
		u_int8_t saddr_first_protocol;
		u_int8_t daddr_first_protocol;
		vmPort sport;
		vmPort dport;
		bool confirmed;
		unsigned counter;
		unsigned counter_reverse;
		map<u_int32_t, u_int32_t> counter_by_cseq;
		map<u_int32_t, u_int32_t> counter_reverse_by_cseq;
		map<u_int32_t, sInviteCseqData> cseq_data;
		string caller;
		string called;
		string called_invite;
		string branch;
	};
	struct sInviteSD_OrderItem {
		inline sInviteSD_OrderItem(unsigned order, u_int64_t ts) {
			this->order = order;
			this->ts = ts;
		}
		unsigned order;
		u_int64_t ts;
	};
	struct sSipResponse {
		sSipResponse(const char *SIPresponse = NULL, int SIPresponseNum = 0) {
			if(SIPresponse) {
				this->SIPresponse = SIPresponse;
			}
			this->SIPresponseNum = SIPresponseNum;
		}
		string SIPresponse;
		int SIPresponseNum;
	};
	struct sSipHistory {
		sSipHistory(u_int64_t time_us = 0,
			    const char *SIPrequest = NULL,
			    const char *SIPresponse = NULL, int SIPresponseNum = 0) {
			this->time_us = time_us;
			if(SIPrequest && SIPrequest[0]) {
				this->SIPrequest = SIPrequest;
			}
			if(SIPresponse && SIPresponse[0]) {
				this->SIPresponse = SIPresponse;
			}
			this->SIPresponseNum = SIPresponseNum;
		}
		u_int64_t time_us;
		string SIPrequest;
		string SIPresponse;
		int SIPresponseNum;
	};
	struct sSipPacketInfo {
		u_int64_t time_us;
		vmIPport src;
		vmIPport dst;
		string sip_first_line;
		u_int32_t sip_length;
		u_int32_t packet_length;
		sCseq cseq;
		string getJson();
	};
	struct sSipcalleRD_IP {
		sSipcalleRD_IP() {
			for(unsigned i = 0; i < MAX_SIPCALLERDIP; i++) {
				sipcallerip[i].clear();
				sipcalledip[i].clear();
				sipcalledip_mod.clear();
				sipcallerport[i].clear();
				sipcalledport[i].clear();
				sipcalledport_mod.clear();
			}
		}
		vmIP sipcallerip[MAX_SIPCALLERDIP];
		vmIP sipcalledip[MAX_SIPCALLERDIP];
		vmIP sipcalledip_mod;
		vmPort sipcallerport[MAX_SIPCALLERDIP];
		vmPort sipcalledport[MAX_SIPCALLERDIP];
		vmPort sipcalledport_mod;
	};
	struct sMergeLegInfo {
		sMergeLegInfo() {
			seenbye = false;
			seenbye_time_usec = 0;
			seenokbye = false;
			seenokbye_time_usec = 0;
			seenbye_and_ok = false;
			seenbye_and_ok_time_usec = 0;
			seencancel = false;
			seencancel_time_usec = 0;
			seencancel_and_ok = false;
			seencancel_and_ok_time_usec = 0;
			seenauthfailed = false;
			seenauthfailed_time_usec = 0;
		}
		bool seenbye;
		u_int64_t seenbye_time_usec;
		bool seenokbye;
		u_int64_t seenokbye_time_usec;
		bool seenbye_and_ok;
		u_int64_t seenbye_and_ok_time_usec;
		bool seencancel;
		u_int64_t seencancel_time_usec;
		bool seencancel_and_ok;
		u_int64_t seencancel_and_ok_time_usec;
		bool seenauthfailed;
		u_int64_t seenauthfailed_time_usec;
	};
	struct sCalledInviteBranchItem {
		string to;
		string to_uri;
		string domain_to;
		string domain_to_uri;
	};
};

class CallBranch : public CallStructs {
public:
	CallBranch(Call *call = NULL, unsigned branch_id = 0);
	virtual ~CallBranch();
	inline void invite_list_lock() {
		__SYNC_LOCK_USLEEP(_invite_list_lock, 50);
	}
	inline void invite_list_unlock() {
		__SYNC_UNLOCK(_invite_list_lock);
	}
	inline bool is_closed() {
		return(seenbye ||
		       seencancel ||
		       ignore_rtp_after_response_time_usec ||
		       (lastSIPresponseNum / 100 == 4 && !(lastSIPresponseNum == 401 || lastSIPresponseNum == 407 || lastSIPresponseNum == 491)) ||
		       lastSIPresponseNum / 100 == 5 ||
		       lastSIPresponseNum / 100 == 6);
	}
	void proxy_add(vmIP ip, vmPort port) {
		if(ip.isSet()) {
			proxies_lock();
			proxies.push_back(vmIPport(ip, port));
			proxies_unlock();
		}
	}
	bool in_proxy(vmIP ip, vmPort port) {
		proxies_lock();
		bool rslt = find(proxies.begin(), proxies.end(), vmIPport(ip, port)) != proxies.end();
		proxies_unlock();
		return(rslt);
	}
	void proxies_undup(set<vmIP> *proxies_undup, list<vmIPport> *proxies = NULL, vmIPport *exclude = NULL);
	void proxies_lock() {
		__SYNC_LOCK(this->_proxies_lock);
	}
	void proxies_unlock() {
		__SYNC_UNLOCK(this->_proxies_lock);
	}
	int64_t get_min_response_100_time_us();
	int64_t get_min_response_xxx_time_us();
	string get_sip_packets_info_json();
public:

	Call *call;
	unsigned branch_id;
	string branch_call_id;
	string branch_fbasename;

	vector<sInviteSD_Addr> invite_sdaddr;
	map<vmIPportLink, unsigned> invite_sdaddr_map;
	vector<sInviteSD_Addr> rinvite_sdaddr;
	map<vmIPportLink, unsigned> rinvite_sdaddr_map;
	vector<sInviteSD_OrderItem> invite_sdaddr_order;
	u_int64_t invite_sdaddr_last_ts;
	int8_t invite_sdaddr_all_confirmed;
	bool invite_sdaddr_bad_order;
	
	vmIP saddr;
	vmPort sport;
	vmIP daddr;
	vmPort dport;
	
	sCseq invitecseq;
	list<sCseq> invitecseq_next;
	deque<sCseq> invitecseq_in_dialog;
	sCseq byecseq[2];
	sCseq messagecseq;
	sCseq cancelcseq;		
	sCseq updatecseq;
	
	string callername;
	string caller;
	string caller_domain;
	string called_to;
	string called_uri;
	string called_final;
	string called_domain_to;
	string called_domain_uri;
	string called_domain_final;
	string caller_tag;
	string called_tag_to;
	
	string contact_num;
	string contact_domain;
	string digest_username;
	string digest_realm;
	
	string custom_header1;
	string match_header;
 
	vmIP sipcallerip[MAX_SIPCALLERDIP];	//!< SIP signalling source IP address
	vmIP sipcalledip[MAX_SIPCALLERDIP];	//!< SIP signalling destination IP address
	vmIP sipcalledip_mod;
	vmIP sipcallerip_encaps;
	vmIP sipcalledip_encaps;
	u_int8_t sipcallerip_encaps_prot;
	u_int8_t sipcalledip_encaps_prot;
	vmIP sipcallerip_rslt;
	vmIP sipcalledip_rslt;
	vmIP sipcallerip_encaps_rslt;
	vmIP sipcalledip_encaps_rslt;
	u_int8_t sipcallerip_encaps_prot_rslt;
	u_int8_t sipcalledip_encaps_prot_rslt;
	vmPort sipcallerport[MAX_SIPCALLERDIP];
	vmPort sipcalledport[MAX_SIPCALLERDIP];
	vmPort sipcalledport_mod;
	vmPort sipcallerport_rslt;
	vmPort sipcalledport_rslt;
	bool sipcallerdip_reverse;
	
	volatile int _proxies_lock;
	list<vmIPport> proxies;
	
	int whohanged;
	char oneway;
	vmIP lastsrcip;
	vmIP lastdstip;
	vmIP lastsipcallerip;
	vmPort lastsrcport;
	
	map<string, sSipcalleRD_IP> map_sipcallerdip;
	map<string, sCalledInviteBranchItem> called_invite_branch_map;

	string lastSIPresponse;
	int lastSIPresponseNum;
	list<sSipResponse> SIPresponse;
	list<sSipHistory> SIPhistory;
	list<sSipPacketInfo*> SIPpacketInfoList;
	bool new_invite_after_lsr487;
	bool cancel_lsr487;
	
	int reason_sip_cause;
	string reason_sip_text;
	int reason_q850_cause;
	string reason_q850_text;
	
	string a_ua;
	string b_ua;
	
	bool seeninvite;
	bool seeninviteok;
	bool seenmessage;
	bool seenmessageok;
	bool seenbye;
	u_int64_t seenbye_time_usec;
	bool seenokbye;
	u_int64_t seenokbye_time_usec;
	bool seenbye_and_ok;
	bool seenbye_and_ok_permanent;
	u_int64_t seenbye_and_ok_time_usec;
	bool seencancel;
	u_int64_t seencancel_time_usec;
	bool seencancel_and_ok;
	u_int64_t seencancel_and_ok_time_usec;
	bool seenauthfailed;
	u_int64_t seenauthfailed_time_usec;
	u_int64_t ignore_rtp_after_response_time_usec;
	bool unconfirmed_bye;
	bool seenRES2XX;
	bool seenRES2XX_no_BYE;
	bool seenRES18X;
	
	u_int16_t vlan;
	bool is_sipalg_detected;
	
	ip_port_call_info ip_port[MAX_IP_PER_CALL];
	int ipport_n;
	bool logged_max_ip_per_call;

	volatile int end_call_rtp;
	volatile int end_call_hash_removed;
	
	RTPMAP rtpmap[MAX_IP_PER_CALL][MAX_RTPMAP];
	bool rtpmap_used_flags[MAX_IP_PER_CALL];
	
	volatile int rtp_ip_port_counter;
	#if CHECK_HASHTABLE_FOR_ALL_CALLS
	volatile int rtp_ip_port_counter_add;
	#endif
	
	volatile int _invite_list_lock;

	bool updateDstnumOnAnswer;
	bool updateDstnumFromMessage;
	
	string last_via_branch;
	
};

struct raws_t {
	int ssrc_index;
	int rawiterator;
	int codec;
	int frame_size;
	int bit_rate;
	struct timeval tv;
	string filename;
	class RTP *rtp;
};

enum eCallField {
	cf_na,
	cf_callreference,
	cf_callid,
	cf_calldate,
	cf_calldate_num,
	cf_lastpackettime,
	cf_duration,
	cf_connect_duration,
	cf_caller,
	cf_called,
	cf_caller_country,
	cf_called_country,
	cf_caller_international,
	cf_called_international,
	cf_callername,
	cf_callerdomain,
	cf_calleddomain,
	cf_calleragent,
	cf_calledagent,
	cf_callerip,
	cf_calledip,
	cf_callerip_country,
	cf_calledip_country,
	cf_callerip_encaps,
	cf_calledip_encaps,
	cf_callerip_encaps_prot,
	cf_calledip_encaps_prot,
	cf_sipproxies,
	cf_lastSIPresponseNum,
	cf_rtp_src,
	cf_rtp_dst,
	cf_rtp_src_country,
	cf_rtp_dst_country,
	cf_callercodec,
	cf_calledcodec,
	cf_src_mosf1,
	cf_src_mosf1_avg,
	cf_src_mosf1_min,
	cf_src_mosf2,
	cf_src_mosf2_avg,
	cf_src_mosf2_min,
	cf_src_mosAD,
	cf_src_mosAD_avg,
	cf_src_mosAD_min,
	cf_dst_mosf1,
	cf_dst_mosf1_avg,
	cf_dst_mosf1_min,
	cf_dst_mosf2,
	cf_dst_mosf2_avg,
	cf_dst_mosf2_min,
	cf_dst_mosAD,
	cf_dst_mosAD_avg,
	cf_dst_mosAD_min,
	cf_src_jitter,
	cf_src_jitter_avg,
	cf_src_jitter_max,
	cf_dst_jitter,
	cf_dst_jitter_avg,
	cf_dst_jitter_max,
	cf_src_received,
	cf_dst_received,
	cf_src_loss_abs,
	cf_dst_loss_abs,
	cf_src_loss,
	cf_dst_loss,
	cf_src_loss_last10sec,
	cf_dst_loss_last10sec,
	cf_id_sensor,
	cf_vlan,
	cf_custom_header,
	cf__max
};

struct sCallField {
	eCallField fieldType;
	const char *fieldName;
};

#define P_FLAGS_IMAX 10
#define P_FLAGS_MAX 200

class Call_abstract {
public:
	enum ePFlags {
		_p_flag_na,
		_p_flag_dumper_open,			//  1
		_p_flag_dumper_open_ok,			//  2
		_p_flag_dumper_dump,			//  3
		_p_flag_dumper_dump_end,		//  4
		_p_flag_dumper_dump_close,		//  5
		_p_flag_dumper_dump_close_2,		//  6
		_p_flag_dumper_dump_close_3,		//  7
		_p_flag_dumper_dump_close_4,		//  8
		_p_flag_dumper_dump_close_5,		//  9
		_p_flag_dumper_dump_close_end,		// 10
		_p_flag_dumper_dump_close_not_async,	// 11
		_p_flag_dumper_set_state_close,		// 12
		_p_flag_init_tar_buffer,		// 13
		_p_flag_init_tar_buffer_end,		// 14
		_p_flag_fzh_close,			// 15
		_p_flag_fzh_flushbuffer_1,		// 16
		_p_flag_fzh_flushbuffer_2,		// 17
		_p_flag_fzh_flushbuffer_3,		// 18
		_p_flag_fzh_flushtar_1,			// 19
		_p_flag_fzh_flushtar_2,			// 20
		_p_flag_fzh_flushtar_3,			// 21
		_p_flag_fzh_write_1,			// 22
		_p_flag_fzh_write_2,			// 23
		_p_flag_fzh_compress_ev_1,		// 24
		_p_flag_fzh_compress_ev_2,		// 25
		_p_flag_chb_add_tar_pos,		// 26
		_p_flag_destroy_tar_buffer,		// 27
		_p_flag_inc_chunk_buffer,		// 28
		_p_flag_dec_chunk_buffer		// 29
	};
	struct sChbIndex {
		inline sChbIndex(void *chb, const char *name) {
			this->chb = chb;
			this->name = name;
		}
		void *chb;
		string name;
		friend inline const bool operator < (const sChbIndex &i1, const sChbIndex &i2) {
			return(i1.chb < i2.chb ? 1 : i1.chb > i2.chb ? 0 :
			       i1.name < i2.name);
		}
	};
public:
	Call_abstract(int call_type, u_int64_t time_us);
	virtual ~Call_abstract() {
		alloc_flag = 0;
		if(nat_aliases) {
			delete nat_aliases;
		}
	}
	int getTypeBase() { return(type_base); }
	bool typeIs(int type) { return(type_base == type || (type_next && type_next == type)); }
	bool typeIsOnly(int type) { return(type_base == type && type_next == 0); }
	bool typeIsNot(int type) { return(!typeIs(type)); }
	bool addNextType(int type);
	u_int32_t calltime_s() { return TIME_US_TO_S(first_packet_time_us); };
	u_int64_t calltime_us() { return first_packet_time_us; };
	struct timeval *get_calltime_tv(struct timeval *ts) {
		ts->tv_sec = TIME_US_TO_S(first_packet_time_us);
		ts->tv_usec = TIME_US_TO_DEC_US(first_packet_time_us);
		return(ts);
	}
	string get_sensordir();
	string get_pathname(eTypeSpoolFile typeSpoolFile, const char *substSpoolDir = NULL);
	string get_filename(eTypeSpoolFile typeSpoolFile, const char *fileExtension = NULL);
	string get_pathfilename(eTypeSpoolFile typeSpoolFile, const char *fileExtension = NULL);
	string dirnamesqlfiles();
	char *get_fbasename_safe();
	const char *getSpoolDir(eTypeSpoolFile typeSpoolFile) {
		return(::getSpoolDir(typeSpoolFile, getSpoolIndex()));
	}
	int getSpoolIndex() {
		extern sExistsColumns existsColumns;
		return((flags & FLAG_USE_SPOOL_2) && isSetSpoolDir2() &&
			((typeIs(INVITE) && existsColumns.cdr_next_spool_index) ||
			 (typeIs(MESSAGE) && existsColumns.message_spool_index) ||
			 (typeIs(REGISTER) && existsColumns.register_state_spool_index && existsColumns.register_failed_spool_index)) ?
			1 : 
			0);
	}
	#if DEBUG_ASYNC_TAR_WRITE
	bool isEmptyChunkBuffersCount() {
		__SYNC_LOCK(chunkBuffersCount_sync);
		bool rslt = chunkBuffersMap.size() == 0;
		__SYNC_UNLOCK(chunkBuffersCount_sync);
		return(rslt);
	}
	int getChunkBuffersCount() {
		__SYNC_LOCK(chunkBuffersCount_sync);
		int rslt = chunkBuffersMap.size();
		__SYNC_UNLOCK(chunkBuffersCount_sync);
		return(rslt);
	}
	bool incChunkBuffers(u_char index, void *chb, const char *name) {
		bool rslt = false;
		__SYNC_LOCK(chunkBuffersCount_sync);
		this->addPFlag(index, _p_flag_inc_chunk_buffer);
		map<sChbIndex, bool>::iterator iter = chunkBuffersMap.find(sChbIndex(chb, name));
		if(iter == chunkBuffersMap.end()) {
			chunkBuffersMap[sChbIndex(chb, name)] = true;
			rslt = true;
		}
		__SYNC_UNLOCK(chunkBuffersCount_sync);
		return(rslt);
	}
	bool decChunkBuffers(u_char index, void *chb, const char *name) {
		bool rslt = false;
		__SYNC_LOCK(chunkBuffersCount_sync);
		this->addPFlag(index, _p_flag_dec_chunk_buffer);
		map<sChbIndex, bool>::iterator iter = chunkBuffersMap.find(sChbIndex(chb, name));
		if(iter != chunkBuffersMap.end()) {
			chunkBuffersMap.erase(iter);
			rslt = true;
		}
		__SYNC_UNLOCK(chunkBuffersCount_sync);
		return(rslt);
	}
	void addPFlag(u_char index, u_char pflag) {
		if(index >= 0 && index < P_FLAGS_IMAX && isAllocFlagOK() && p_flags_count[index] < P_FLAGS_MAX - 1) {
			p_flags[index][p_flags_count[index]++] = pflag;
		}
	}
	bool isChunkBuffersCountSyncOK() {
		return(chunkBuffersCount_sync == 0 || chunkBuffersCount_sync == 1);
	}
	bool isChunkBuffersCountSyncOK_wait() {
		if(isChunkBuffersCountSyncOK()) {
			return(true);
		}
		for(unsigned i = 0; i < 3; i++) {
			USLEEP(10);
			if(isChunkBuffersCountSyncOK()) {
				return(true);
			}
		}
		return(false);
	}
	#else
	bool isEmptyChunkBuffersCount() {
		return(chunkBuffersCount == 0);
	}
	int getChunkBuffersCount() {
		return(chunkBuffersCount);
	}
	void incChunkBuffers() {
		__SYNC_INC(chunkBuffersCount);
	}
	void decChunkBuffers() {
		if(chunkBuffersCount == 0) {
			syslog(LOG_NOTICE, "invalid zero sync in decChunkBuffers in call %s", fbasename);
		}
		__SYNC_DEC(chunkBuffersCount);
	}
	#endif
	void addTarPos(u_int64_t pos, int type);
	bool isAllocFlagOK() {
		return(alloc_flag == 1);
	}
	bool isAllocFlagSetAsFree() {
		return(alloc_flag == 0);
	}
	inline void updateTimeShift(u_int64_t time_us) {
		if(time_us > 1000000000ull * 1000000ull) {
			time_shift_ms = (int64_t)getTimeMS_rdtsc() - (int64_t)(time_us / 1000);
		}
	}
	inline u_int64_t unshiftCallTime_ms(u_int64_t time_ms) {
		return(time_ms ? (time_ms + time_shift_ms) : 0);
	}
	inline u_int64_t unshiftCallTime_s(u_int64_t time_s) {
		return(time_s ? (time_s + time_shift_ms / 1000) : 0);
	}
	inline u_int64_t unshiftSystemTime_ms(u_int64_t time_ms) {
		return(time_ms ? (time_ms - time_shift_ms) : 0);
	}
	inline u_int64_t unshiftSystemTime_s(u_int64_t time_s) {
		return(time_s ? (time_s - time_shift_ms / 1000) : 0);
	}
	inline u_int64_t getRelTime(struct timeval *ts) {
		return(getTimeUS(ts) > first_packet_time_us ? getTimeUS(ts) - first_packet_time_us : 0);
	}
	inline u_int64_t get_created_at() { 
		return(created_at);
	}
	inline void setClosed() { 
		closed = true;
	}
	inline bool isClosed() { 
		return(closed);
	}
public:
	volatile uint8_t alloc_flag;
	int type_base;
	int type_next;
	u_int64_t first_packet_time_us;
	int64_t time_shift_ms;
	char fbasename[MAX_FNAME];
	char fbasename_safe[MAX_FNAME];
	u_int64_t fname_register;
	int useSensorId;
	int useDlt;
	pcap_t *useHandle;
	string force_spool_path;
	volatile unsigned long int flags;
	map<vmIP, vmIP> *nat_aliases;
	void *user_data;
	int user_data_type;
protected:
	list<u_int64_t> tarPosSip;
	list<u_int64_t> tarPosRtp;
	list<u_int64_t> tarPosGraph;
private:
	#if DEBUG_ASYNC_TAR_WRITE
	map<sChbIndex, bool> chunkBuffersMap;
	volatile int chunkBuffersCount_sync;
	u_char p_flags[P_FLAGS_IMAX][P_FLAGS_MAX];
	u_char p_flags_count[P_FLAGS_IMAX];
	#else
	volatile int chunkBuffersCount;
	#endif
	u_int64_t created_at;
	bool closed;
friend class cDestroyCallsInfo;
friend class ChunkBuffer;
friend class cSeparateProcessing;
};

struct sChartsCacheCallData {
	map<u_int32_t, cEvalFormula::sValue> value_map;
};

/**
  * This class implements operations on call
*/
class Call : public CallStructs, public Call_abstract {
public:
	enum eStoreFlags {
		_sf_db = 1,
		_sf_charts_cache = 2
	};
	enum eRtcpDataItemType {
		_rtcp_data_type_na,
		_rtcp_data_type_publish,
		_rtcp_data_type_rtcp_xr,
		_rtcp_data_type_rtcp_sr_rr
	};
	struct sRtcpDataItem_data {
		sRtcpDataItem_data() {
			memset(this, 0, sizeof(*this));
		}
		u_int32_t ssrc[2];
		timeval tv;
		bool mos_lq_set : 1;
		bool fr_lost_set : 1;
		bool loss_set : 1;
		bool jitter_set : 1;
		u_int8_t mos_lq;
		u_int8_t fr_lost;
		int32_t loss;
		u_int32_t jitter;
	};
	struct sRtcpDataItem : public sRtcpDataItem_data {
		sRtcpDataItem() {
			type = _rtcp_data_type_na;
			branch_id = 0;
		}
		eRtcpDataItemType type;
		u_int16_t branch_id;
		vmIPport ip_port_src;
		vmIPport ip_port_dst;
		void dump() {
			cout << ip_port_src.getString() << " -> " << ip_port_dst.getString()
			     << " ssrc: " << hex << ssrc[0] << "/" << ssrc[1] << dec
			     << " type: " << type;
			if(mos_lq_set) cout << " mos_lq: " << (int)mos_lq;
			if(fr_lost_set) cout << " fr_lost: " << (int)fr_lost;
			if(loss_set) cout << " loss: " << loss;
			if(jitter_set) cout << " jitter: " << jitter;
		}
	};
	struct sRtcpData : public list<sRtcpDataItem> {
		void add_publish(u_int16_t branch_id, vmIPport ip_port_src, vmIPport ip_port_dst, u_int32_t ssrc[], 
				 timeval tv, bool mos_lq_set, u_int8_t mos_lq, bool fr_lost_set, u_int8_t fr_lost) {
			sRtcpDataItem dataItem;
			dataItem.type = _rtcp_data_type_publish;
			dataItem.branch_id = branch_id;
			dataItem.ip_port_src = ip_port_src;
			dataItem.ip_port_dst = ip_port_dst;
			dataItem.ssrc[0] = ssrc[0];
			dataItem.ssrc[1] = ssrc[1];
			dataItem.tv = tv;
			dataItem.mos_lq_set = mos_lq_set;
			dataItem.mos_lq = mos_lq;
			dataItem.fr_lost_set = fr_lost_set;
			dataItem.fr_lost = fr_lost;
			this->push_back(dataItem);
		}
		void add_rtcp_xr(u_int16_t branch_id, vmIPport ip_port_src, vmIPport ip_port_dst, u_int32_t ssrc,
				 timeval tv, bool mos_lq_set, u_int8_t mos_lq, bool fr_lost_set, u_int8_t fr_lost) {
			sRtcpDataItem dataItem;
			dataItem.type = _rtcp_data_type_rtcp_xr;
			dataItem.branch_id = branch_id;
			dataItem.ip_port_src = ip_port_src;
			dataItem.ip_port_dst = ip_port_dst;
			dataItem.ssrc[0] = ssrc;
			dataItem.tv = tv;
			dataItem.mos_lq_set = mos_lq_set;
			dataItem.mos_lq = mos_lq;
			dataItem.fr_lost_set = fr_lost_set;
			dataItem.fr_lost = fr_lost;
			this->push_back(dataItem);
		}
		void add_rtcp_sr_rr(u_int16_t branch_id, vmIPport ip_port_src, vmIPport ip_port_dst, u_int32_t ssrc,
				    timeval tv, bool loss_set, int32_t loss, bool jitter_set, u_int32_t jitter, bool fr_lost_set, u_int8_t fr_lost) {
			sRtcpDataItem dataItem;
			dataItem.type = _rtcp_data_type_rtcp_sr_rr;
			dataItem.branch_id = branch_id;
			dataItem.ip_port_src = ip_port_src;
			dataItem.ip_port_dst = ip_port_dst;
			dataItem.ssrc[0] = ssrc;
			dataItem.tv = tv;
			dataItem.loss_set = loss_set;
			dataItem.loss = loss;
			dataItem.jitter_set = jitter_set;
			dataItem.jitter = jitter;
			dataItem.fr_lost_set = fr_lost_set;
			dataItem.fr_lost = fr_lost;
			this->push_back(dataItem);
		}
	};
	struct sRtcpStreamIndex {
		sRtcpStreamIndex(vmIPport ip_port_src, vmIPport ip_port_dst, u_int32_t ssrc[]) {
			this->ip_port_src = ip_port_src;
			this->ip_port_dst = ip_port_dst;
			this->ssrc[0] = ssrc[0];
			this->ssrc[1] = ssrc[1];
		}
		bool operator == (const sRtcpStreamIndex& other) const { 
			return(this->ip_port_src == other.ip_port_src &&
			       this->ip_port_dst == other.ip_port_dst &&
			       this->ssrc[0] == other.ssrc[0] &&
			       this->ssrc[1] == other.ssrc[1]); 
		}
		bool operator < (const sRtcpStreamIndex& other) const { 
			return(this->ip_port_src < other.ip_port_src ? true : !(this->ip_port_src == other.ip_port_src) ? false :
			       this->ip_port_dst < other.ip_port_dst ? true : !(this->ip_port_dst == other.ip_port_dst) ? false :
			       this->ssrc[0] < other.ssrc[0] ? true : this->ssrc[0] != other.ssrc[0] ? false :
			       this->ssrc[1] < other.ssrc[1]);
		}
		void dump() {
			cout << ip_port_src.getString() << " -> " << ip_port_dst.getString()
			     << " ssrc: "<< hex << ssrc[0] << "/" << ssrc[1] << dec;
		}
		vmIPport ip_port_src;
		vmIPport ip_port_dst;
		u_int32_t ssrc[2];
	};
	struct sRtcpXrStreamData {
		sRtcpXrStreamData() {
			ssrc[0] = 0;
			ssrc[1] = 0;
			ok_by_sdp = false;
			iscaller = -1;
			rtcp_mux = false;
			counter = 0;
			mos_lq_min = 45;
			mos_lq_avg = 0;
			mos_lq_counter = 0;
			fr_lost_max = 0;
			fr_lost_avg = 0;
			fr_lost_counter = 0;
			loss = 0;
			loss_counter = 0;
			jitter_max = 0;
			jitter_avg = 0;
			jitter_counter = 0;
			ticks_bycodec = 0;
		}
		void add_mos_lq(int16_t mos_lq);
		void add_fr_lost(int16_t fr_lost);
		void add_loss(int32_t loss);
		void add_jitter(u_int32_t jitter);
		vmIPport ip_port_src_orig;
		vmIPport ip_port_dst_orig;
		vmIPport ip_port_src;
		vmIPport ip_port_dst;
		u_int32_t ssrc[2];
		eRtcpDataItemType type;
		bool ok_by_sdp;
		int8_t iscaller;
		bool rtcp_mux;
		unsigned counter;
		uint8_t mos_lq_min;
		double mos_lq_avg;
		unsigned mos_lq_counter;
		uint8_t fr_lost_max;
		double fr_lost_avg;
		unsigned fr_lost_counter;
		int32_t loss;
		unsigned loss_counter;
		u_int32_t jitter_max;
		double jitter_avg;
		unsigned jitter_counter;
		u_int8_t ticks_bycodec;
	};
	struct sRtcpXrStreamDataByType {
		map<eRtcpDataItemType, sRtcpXrStreamData> data;
	};
	struct sRtcpXrStreams {
		void findAB(sRtcpXrStreamData *ab[]);
		sRtcpXrStreamData *getOtherType(sRtcpXrStreamData *stream);
		map<sRtcpStreamIndex, sRtcpXrStreamDataByType> by_type;
	};
	struct sIPFixStreamData : public vector<sIPFixQosStreamStat> {
		void findAB(sIPFixQosStreamStat *ab[]);
	};
	struct sUdptlDumper {
		sUdptlDumper() {
			dumper = NULL;
			last_seq = 0;
		}
		~sUdptlDumper() {
			if(dumper) {
				delete dumper;
			}
		}
		PcapDumper *dumper;
		unsigned last_seq;
	};
	enum eVoicemail {
		voicemail_na,
		voicemail_active,
		voicemail_inactive
	};
	struct sAudioBufferData {
		sAudioBufferData() {
			audiobuffer = NULL;
			clearLast();
		}
		void set(void **destBuffer, int seqno, u_int32_t ssrc, struct timeval *ts) {
			if(audiobuffer && audiobuffer->is_enable()) {
				u_int64_t actTimeMS = getTimeMS(ts);
				if(!last_seq || !last_ssrc ||
				   (last_ssrc == ssrc ?
				     (last_seq < seqno || (last_seq - seqno) > 30000) :
				     last_ssrc_time_ms < actTimeMS - 200)) {
					*destBuffer = audiobuffer;
					last_seq = seqno;
					last_ssrc = ssrc;
					last_ssrc_time_ms = actTimeMS;
				}
			}
		}
		void clearLast() {
			last_seq = 0;
			last_ssrc = 0;
			last_ssrc_time_ms = 0;
		}
		FifoBuffer *audiobuffer;
		int last_seq;
		u_int32_t last_ssrc;
		u_int64_t last_ssrc_time_ms;
	};
	struct sReg {
		sReg() {
			registercseq.null();
			msgcount = 0;
			regcount = 0;
			regcount_after_4xx = 0;
			reg401count = 0;
			reg401count_all = 0;
			reg403count = 0;
			reg404count = 0;
			reg200count = 0;
			regstate = 0;
			regresponse = false;
			regrrddiff = -1;
			//regsrcmac = 0;
			reg_tcp_seq = NULL;
			last_sip_method = 0;
			register_expires = -1;
		}
		sCseq registercseq;
		int msgcount;
		int regcount;
		int regcount_after_4xx;
		int reg401count;
		int reg401count_all;
		list<d_item2<vmIP, u_int16_t> > reg401count_sipcallerip_vlan;
		int reg403count;
		int reg404count;
		int reg200count;
		int regstate;
		bool regresponse;
		int register_expires;
		timeval regrrdstart;		// time of first REGISTER
		int regrrddiff;			// RRD diff time REGISTER<->OK in [ms]- RFC6076
		//uint64_t regsrcmac;		// mac if ether layer present in REGISTER
		list<u_int32_t> *reg_tcp_seq;
		int last_sip_method;
	};
	enum eTxtType {
		txt_type_na,
		txt_type_sdp_xml
	};
	struct sTxt {
		u_int64_t time;
		eTxtType type;
		string txt;
	};
	struct sConferenceLegId {
		string user_entity;
		string endpoint_entity;
		bool operator == (const sConferenceLegId& other) const { 
			return(this->user_entity == other.user_entity &&
			       this->endpoint_entity == other.endpoint_entity); 
		}
		bool operator < (const sConferenceLegId& other) const { 
			return(this->user_entity < other.user_entity ||
			       (this->user_entity == other.user_entity && this->endpoint_entity < other.endpoint_entity)); 
		}
	};
	struct sConferenceLeg {
		sConferenceLeg() {
			connect_time = 0;
			disconnect_time = 0;
		}
		string user_entity;
		string endpoint_entity;
		u_int64_t connect_time;
		u_int64_t disconnect_time;
	};
	struct sConferenceLegs {
		vector<sConferenceLeg*> legs;
		~sConferenceLegs() {
			for(vector<sConferenceLeg*>::iterator iter = legs.begin(); iter != legs.end(); iter++) {
				delete (*iter);
			}
		}
		void addLeg(const char *user_entity, const char *endpoint_entity, u_int64_t connect_time) {
			sConferenceLeg *leg = new FILE_LINE(0) sConferenceLeg;
			leg->user_entity = user_entity;
			leg->endpoint_entity = endpoint_entity;
			leg->connect_time = connect_time;
			legs.push_back(leg);
		}
		void setDisconnectTime(u_int64_t disconnect_time) {
			if(isConnect()) {
				legs.back()->disconnect_time = disconnect_time;
			}
		}
		bool isConnect() {
			return(legs.size() &&
			       !legs.back()->disconnect_time);
		}
	};
	struct cBranchInfo {
		vmIP sip_src_addr;
		string to;
		string branch;
		bool operator == (const cBranchInfo& other) const { 
			return(this->sip_src_addr == other.sip_src_addr &&
			       this->to == other.to &&
			       this->branch == other.branch); 
		}
		bool operator < (const cBranchInfo& other) const { 
			return(this->sip_src_addr < other.sip_src_addr ? true : this->sip_src_addr > other.sip_src_addr ? false :
			       this->to < other.to ? true : this->to > other.to ? false :
			       this->branch < other.branch);
		}
	};
	enum eSrvccFlag {
		_srvcc_na,
		_srvcc_post,
		_srvcc_pre
	};
	enum eMoMtLegFlag {
		_momt_na,
		_momt_mt,
		_momt_mo
	};
public:
	bool is_ssl;			//!< call was decrypted
	#if not EXPERIMENTAL_SUPPRESS_AUDIOCODES
	bool is_audiocodes;
	#endif
	#if EXPERIMENTAL_LITE_RTP_MOD
	RTP rtp_fix[MAX_SSRC_PER_CALL_FIX];	//!< array of RTP streams
	#else
	RTP *rtp_fix[MAX_SSRC_PER_CALL_FIX];	//!< array of RTP streams
	#if CALL_RTP_DYNAMIC_ARRAY
	vector<RTP*> *rtp_dynamic;
	#endif
	#endif
	int ssrc_n;				//!< last index of rtp array
	bool rtcp_exists;
	list<RTP*> *rtp_canceled;
	volatile bool rtp_remove_flag;
	RTP *rtpab[2];
	map<int, class RTPsecure*> rtp_secure_map;
	cDtls *dtls;
	bool dtls_exists;
	volatile unsigned dtls_queue_move;
	volatile int dtls_queue_sync;
	vector<cDtlsLink::sSrtpKeys*> dtls_keys;
	volatile int dtls_keys_sync;
	volatile int rtplock_sync;
	unsigned long call_id_len;	//!< length of call-id 	
	string call_id;	//!< call-id from SIP session
	map<string, bool> *call_id_alternative;
	volatile int _call_id_alternative_lock;
	
	inline const char *get_called(CallBranch *c_branch) {
		extern int opt_destination_number_mode;
		if(is_multiple_to_branch(c_branch)) {
			if(!c_branch->called_final.empty()) {
				if(to_is_canceled(c_branch, c_branch->called_final.c_str())) {
					const char *rslt = opt_destination_number_mode == 2 ? get_to_uri_not_canceled(c_branch) : get_to_not_canceled(c_branch);
					if(rslt && rslt[0]) {
						return(rslt);
					}
				}
				return(c_branch->called_final.c_str());
			} else {
				if(opt_destination_number_mode == 2) {
					const char *rslt = get_called_uri(c_branch, true);
					if(rslt && rslt[0]) {
						return(rslt);
					}
				}
				return(get_called_to(c_branch, true));
			}
		}
		return(!c_branch->called_final.empty() ? c_branch->called_final.c_str() :
		       !c_branch->called_uri.empty() && opt_destination_number_mode == 2 ? c_branch->called_uri.c_str() : c_branch->called_to.c_str());
	}
	inline const char *get_called_to(CallBranch *c_branch, int8_t _is_multiple_to_branch = -1) {
		if(_is_multiple_to_branch >= 0 ? _is_multiple_to_branch : is_multiple_to_branch(c_branch)) {
			if(to_is_canceled(c_branch, c_branch->called_to.c_str())) {
				const char *rslt = get_to_not_canceled(c_branch);
				if(rslt && rslt[0]) {
					return(rslt);
				}
			}
		}
		return(c_branch->called_to.c_str());
	}
	inline const char *get_called_uri(CallBranch *c_branch, int8_t _is_multiple_to_branch = -1) {
		if(_is_multiple_to_branch >= 0 ? _is_multiple_to_branch : is_multiple_to_branch(c_branch)) {
			if(to_is_canceled(c_branch, c_branch->called_to.c_str())) {
				const char *rslt = get_to_uri_not_canceled(c_branch);
				if(rslt && rslt[0]) {
					return(rslt);
				}
			} else if(!c_branch->called_uri.empty()) {
				return(c_branch->called_uri.c_str());
			}
			return(get_called_to(c_branch));
		}
		return(!c_branch->called_uri.empty() ? c_branch->called_uri.c_str() : c_branch->called_to.c_str());
	}
	inline const char *get_called_domain(CallBranch *c_branch) {
		extern int opt_destination_number_mode;
		if(is_multiple_to_branch(c_branch)) {
			if(!c_branch->called_final.empty()) {
				if(to_is_canceled(c_branch, c_branch->called_final.c_str())) {
					const char *rslt = opt_destination_number_mode == 2 ? get_domain_to_uri_not_canceled(c_branch) : get_domain_to_not_canceled(c_branch);
					if(rslt && rslt[0]) {
						return(rslt);
					}
				}
				return(c_branch->called_domain_final.c_str());
			} else {
				if(opt_destination_number_mode == 2) {
					const char *rslt = get_called_domain_uri(c_branch, true);
					if(rslt && rslt[0]) {
						return(rslt);
					}
				}
				return(get_called_domain_to(c_branch, true));
			}
		}
		return(!c_branch->called_domain_final.empty() ? c_branch->called_domain_final.c_str() :
		       !c_branch->called_domain_uri.empty() && opt_destination_number_mode == 2 ? c_branch->called_domain_uri.c_str() : c_branch->called_domain_to.c_str());
	}
	inline const char *get_called_domain_to(CallBranch *c_branch, int8_t _is_multiple_to_branch = -1) {
		if(_is_multiple_to_branch >= 0 ? _is_multiple_to_branch : is_multiple_to_branch(c_branch)) {
			if(to_is_canceled(c_branch, c_branch->called_to.c_str())) {
				const char *rslt = get_domain_to_not_canceled(c_branch);
				if(rslt && rslt[0]) {
					return(rslt);
				}
			}
		}
		return(c_branch->called_domain_to.c_str());
	}
	inline const char *get_called_domain_uri(CallBranch *c_branch, int8_t _is_multiple_to_branch = -1) {
		if(_is_multiple_to_branch >= 0 ? _is_multiple_to_branch : is_multiple_to_branch(c_branch)) {
			if(to_is_canceled(c_branch, c_branch->called_to.c_str())) {
				const char *rslt = get_domain_to_uri_not_canceled(c_branch);
				if(rslt && rslt[0]) {
					return(rslt);
				}
			} else if(!c_branch->called_domain_uri.empty()) {
				return(c_branch->called_domain_uri.c_str());
			}
			return(get_called_domain_to(c_branch));
		}
		return(!c_branch->called_domain_uri.empty() ? c_branch->called_domain_uri.c_str() : c_branch->called_domain_to.c_str());
	}
	
	inline bool is_fax() {
		return(isfax || (seenudptl && exists_udptl_data));
	}
	inline bool is_fax_packet(struct packet_s_process_0 *packetS);
	
	bool sighup;			//!< true if call is saving during sighup
	
	RTP *lastcallerrtp;		//!< last RTP stream from caller
	RTP *lastcalledrtp;		//!< last RTP stream from called
	RTP *lastactivecallerrtp;
	RTP *lastactivecalledrtp;
	
	int recordstopped;		//!< flag holding if call was stopped to avoid double free
	int dtmfflag;			//!< used for holding dtmf states 
	unsigned int dtmfflag2[2];	//!< used for holding dtmf states 
	double lastdtmf_time;		//!< used for holding time of last dtmf

	string hold_times;		//!< used for record hold times
	bool hold_status;		//!< hold status var
	bool is_fas_detected;		//!< detected FAS (False Answer Supervision)
	bool is_zerossrc_detected;	//!< detected zero SSRC

	bool protocol_is_tcp;
	bool protocol_is_udp;
	
	int silencerecording;
	int recordingpausedby182;
	bool save_energylevels;
	
	sReg reg;
	
	volatile int rtppacketsinqueue;
	
	volatile int push_call_to_calls_queue;
	volatile int push_register_to_registers_queue;
	volatile int push_call_to_storing_cdr_queue;
	unsigned int ps_drop;
	unsigned int ps_ifdrop;
	vector<u_int64_t> forcemark_time;
	volatile u_int32_t forcemark_time_size;
	volatile int _forcemark_lock;
	int first_codec;
	bool	has_second_merged_leg;

	float a_mos_lqo;
	float b_mos_lqo;

	u_int64_t progress_time_us;	//!< time in u_seconds of 18X response
	u_int64_t first_rtp_time_us;	//!< time in u_seconds of first RTP packet
	u_int64_t connect_time_us;	//!< time in u_seconds of 200 OK
	u_int64_t last_signal_packet_time_us;
	u_int64_t last_rtp_packet_time_us;
	u_int64_t last_rtcp_packet_time_us;
	u_int64_t last_rtp_a_packet_time_us;
	u_int64_t last_rtp_b_packet_time_us;
	time_t destroy_call_at;
	time_t destroy_call_at_bye;
	time_t destroy_call_at_bye_confirmed;
	
	std::queue <s_dtmf> dtmf_history;
	volatile int dtmf_sync;
	
	u_int64_t first_invite_time_us;
	u_int64_t first_response_100_time_us;
	u_int64_t first_response_xxx_time_us;
	u_int64_t first_message_time_us;
	u_int64_t first_response_200_time_us;

	uint8_t	caller_sipdscp;
	uint8_t	called_sipdscp;

	int isfax;
	char seenudptl;
	bool exists_udptl_data;
	bool not_acceptable;
	
	bool sip_fragmented;
	bool rtp_fragmented;

	void *rtp_cur[2];		//!< last RTP structure in direction 0 and 1 (iscaller = 1)
	void *rtp_prev[2];		//!< previouse RTP structure in direction 0 and 1 (iscaller = 1)

	char *contenttype;
	char *message;
	char *message_info;
	int content_length;
	
	unsigned int dcs;
	eVoicemail voicemail;

	int last_callercodec;		//!< Last caller codec 
	int last_calledcodec;		//!< Last called codec 

	int codec_caller;
	int codec_called;
	
	unsigned max_length_sip_data;
	unsigned max_length_sip_packet;

	sAudioBufferData audioBufferData[2];

	unsigned int skinny_partyid;

	int *listening_worker_run;
	pthread_mutex_t listening_worker_run_lock;

	int thread_num;
	int thread_num_rd;

	char absolute_timeout_exceeded;
	char zombie_timeout_exceeded;
	char bye_timeout_exceeded;
	char rtp_timeout_exceeded;
	char sipwithoutrtp_timeout_exceeded;
	char oneway_timeout_exceeded;
	char max_sip_packets_exceeded;
	char max_invite_packets_exceeded;
	char force_terminate;
	char pcap_drop;
	
	void *listening_worker_args;
	
	RTP *lastraw[2];

	string geoposition;

	/* obsolete
	map<string, string> custom_headers;
	*/
	map<int, map<int, dstring> > custom_headers_content_cdr;
	map<int, map<int, dstring> > custom_headers_content_message;
	volatile int _custom_headers_content_sync;
	map<int, map<int, int> > first_custom_header_search;

	u_int16_t onInvite_counter;
	u_int16_t onCall_2XX_counter;
	u_int16_t onCall_18X_counter;
	u_int16_t onHangup_counter;
	
	bool force_close;

	unsigned int caller_silence;
	unsigned int called_silence;
	unsigned int caller_noise;
	unsigned int called_noise;
	unsigned int caller_lastsilence;
	unsigned int called_lastsilence;

	unsigned int caller_clipping_8k;
	unsigned int called_clipping_8k;
	
	unsigned int lastcallerssrc;
	unsigned int lastcalledssrc;

	map<string, sMergeLegInfo> mergecalls;
	volatile int _mergecalls_lock;

	bool rtp_zeropackets_stored;
	
	sRtcpData rtcpData;
	sIPFixStreamData ipfixData;
	
	map<d_item<vmIPport>, unsigned> last_udptl_seq;

	u_int32_t iscaller_consecutive[2];
	
	string mgcp_callid;
	list<u_int32_t> mgcp_transactions;
	map<u_int32_t, sMgcpRequest> mgcp_requests;
	map<u_int32_t, sMgcpResponse> mgcp_responses;
	u_int64_t last_mgcp_connect_packet_time_us;
	
	u_int64_t counter;
	static u_int64_t counter_s;
	
	bool syslog_sdp_multiplication;
	
	list<sTxt> txt;
	volatile int _txt_lock;
	
	bool televent_exists_request;
	bool televent_exists_response;
	
	bool exclude_from_active_calls;
	
	bool conference_is_main_leg;
	bool conference_is_leg;
	string conference_referred_by;
	sCseq conference_referred_by_cseq;
	u_int64_t conference_referred_by_ok_time;
	#if CONFERENCE_LEGS_MOD_WITHOUT_TABLE_CDR_CONFERENCE
	string main_conference_call_id;
	string conference_user_entity;
	u_int64_t conference_connect_time;
	u_int64_t conference_disconnect_time;
	volatile int conference_active;
	map<string, Call*> conference_legs;
	#else
	map<sConferenceLegId, sConferenceLegs*> conference_legs;
	#endif
	volatile int conference_legs_sync;
	eSrvccFlag srvcc_flag;
	string srvcc_call_id;
	
	/**
	 * constructor
	 *
	 * @param call_id unique identification of call parsed from packet
	 * @param call_id_len lenght of the call_id buffer
	 * @param time time of the first packet
	 * 
	*/
	Call(int call_type, char *call_id, unsigned long call_id_len, vector<string> *call_id_alternative, u_int64_t time_us);

	/**
	 * destructor
	 * 
	*/
	~Call();

	int get_index_by_ip_port(CallBranch *c_branch, vmIP addr, vmPort port, bool use_sip_src_addr = false, bool rtcp = false, bool *rtcp_mux = NULL);
	inline int get_index_by_ip_port_by_src(CallBranch *c_branch, vmIP addr, vmPort port, int iscaller, bool rtcp = false) {
		int index_call_ip_port_by_src = get_index_by_ip_port(c_branch, addr, port, false, rtcp);
		if(index_call_ip_port_by_src < 0) {
			index_call_ip_port_by_src = get_index_by_ip_port(c_branch, addr, port, true, rtcp);
		}
		if(index_call_ip_port_by_src < 0 && iscaller_is_set(iscaller)) {
			index_call_ip_port_by_src = get_index_by_iscaller(c_branch, iscaller_inv_index(iscaller));
		}
		return(index_call_ip_port_by_src);
	}
	int get_index_by_sessid_to(CallBranch *c_branch, const char *sessid, const char *to, vmIP sip_src_addr, ip_port_call_info::eTypeAddr type_addr);
	int get_index_by_iscaller(CallBranch *c_branch, int iscaller);
	
	bool is_multiple_to_branch(CallBranch *c_branch);
	bool all_invite_is_multibranch(CallBranch *c_branch, vmIP saddr, vmPort sport, bool use_lock = true);
	bool to_is_canceled(CallBranch *c_branch, const char *to);
	bool all_branches_is_canceled(CallBranch *c_branch, bool check_ip);
	const char *get_to_not_canceled(CallBranch *c_branch, bool uri = false);
	const char *get_to_uri_not_canceled(CallBranch *c_branch) {
		return(get_to_not_canceled(c_branch, true));
	}
	const char *get_domain_to_not_canceled(CallBranch *c_branch, bool uri = false);
	const char *get_domain_to_uri_not_canceled(CallBranch *c_branch) {
		return(get_domain_to_not_canceled(c_branch, true));
	}

	/**
	 * @brief close all rtp[].gfileRAW
	 *
	 * close all RTP[].gfileRAW to flush writes 
	 * 
	*/
	void closeRawFiles();
	
	/**
	 * @brief read RTP packet 
	 *
	 * Used for reading RTP packet 
	 * 
	*/
	bool read_rtp(CallBranch *c_branch, struct packet_s_process_0 *packetS, int iscaller, bool find_by_dest, bool stream_in_multiple_calls, s_sdp_flags_base sdp_flags, char enable_save_packet, char *ifname = NULL);
	inline void _read_rtp_srtp(CallBranch *c_branch, packet_s_process_0 *packetS, RTP *rtp, int iscaller, bool new_rtp);
	inline bool _read_rtp(CallBranch *c_branch, packet_s_process_0 *packetS, int iscaller, s_sdp_flags_base sdp_flags, bool find_by_dest, bool stream_in_multiple_calls, char *ifname, bool *record_dtmf, bool *disable_save);
	inline void _save_rtp(packet_s_process_0 *packetS, s_sdp_flags_base sdp_flags, char enable_save_packet, bool record_dtmf, u_int8_t forceVirtualUdp = false);

	/**
	 * @brief read RTCP packet 
	 *
	 * Used for reading RTCP packet 
	 * 
	*/
	bool read_rtcp(CallBranch *c_branch, packet_s_process_0 *packetS, int iscaller, char enable_save_packet);
	
	void read_dtls(packet_s_process_0 *packetS);

	/**
	 * @brief adds RTP stream to the this Call 
	 *
	 * Adds RTP stream to the this Call which is identified by IP address and port number
	 *
	 * @param addr IP address of the RTP stream
	 * @param port port number of the RTP stream
	 * 
	 * @return return 0 on success, 1 if IP and port is duplicated and -1 on failure
	*/
	
	int add_ip_port(CallBranch *c_branch,
			vmIP sip_src_addr, vmIP addr, ip_port_call_info::eTypeAddr type_addr, vmPort port, struct timeval *ts, 
			char *sessid, char *sdp_label, 
			list<srtp_crypto_config> *srtp_crypto_config_list, string *srtp_fingerprint,
			char *to, char *to_uri, char *domain_to, char *domain_to_uri, char *branch,
			int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags, u_int16_t ptime);
	bool refresh_data_ip_port(CallBranch *c_branch,
				  vmIP addr, vmPort port, struct timeval *ts, 
				  list<srtp_crypto_config> *srtp_crypto_config_list, string *rtp_fingerprint,
				  int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags, u_int16_t ptime);
	void add_ip_port_hash(CallBranch *c_branch,
			      vmIP sip_src_addr, vmIP addr, ip_port_call_info::eTypeAddr type_addr, vmPort port, struct timeval *ts, 
			      char *sessid, char *sdp_label, bool multipleSdpMedia, 
			      list<srtp_crypto_config> *srtp_crypto_config_list, string *rtp_fingerprint,
			      char *to, char *to_uri, char *domain_to, char *domain_to_uri, char *branch,
			      int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags, u_int16_t ptime);
	void cancel_ip_port_hash(CallBranch *c_branch, vmIP sip_src_addr, char *to, char *branch);
	
	/**
	 * @brief get pointer to PcapDumper of the writing pcap file  
	 *
	 * @return pointer to PcapDumper
	*/
	PcapDumper *getPcap() { return(&this->pcap); }
	PcapDumper *getPcapSip() { return(&this->pcapSip); }
	PcapDumper *getPcapRtp() { return(&this->pcapRtp); }
	
	/**
	 * @brief get time of the last seen packet which belongs to this call
	 *
	 * @return time of the last packet in seconds from UNIX epoch
	*/
	u_int64_t get_last_packet_time_us() { return max(last_signal_packet_time_us, max(last_rtp_packet_time_us, last_rtcp_packet_time_us)); };
	u_int32_t get_last_packet_time_s() { return TIME_US_TO_S(get_last_packet_time_us()); };

	/**
	 * @brief get time of the last seen rtp packet which belongs to this call
	 *
	 * @return time of the last rtp packet in seconds from UNIX epoch
	*/
	u_int64_t get_last_rtp_packet_time_us() { return max(last_rtp_a_packet_time_us, last_rtp_b_packet_time_us); };

	/**
	 * @brief set time of the last seen packet which belongs to this call
	 *
	 * this time is used for calculating lenght of the call
	 *
	*/
	void set_last_signal_packet_time_us(u_int64_t time_us) { if(time_us > last_signal_packet_time_us) last_signal_packet_time_us = time_us; };
	void set_last_rtp_packet_time_us(u_int64_t time_us) { if(time_us > last_rtp_packet_time_us) last_rtp_packet_time_us = time_us; };
	void set_last_rtcp_packet_time_us(u_int64_t time_us) { if(time_us > last_rtcp_packet_time_us) last_rtcp_packet_time_us = time_us; };
	void set_last_mgcp_connect_packet_time_us(u_int64_t time_us) { if(time_us > last_mgcp_connect_packet_time_us) last_mgcp_connect_packet_time_us = time_us; };

	/**
	 * @brief get first time of the the packet which belongs to this call
	 *
	 * this time is used as start of the call in CDR record
	 *
	 * @return time of the first packet in seconds from UNIX epoch
	*/
	time_t get_first_packet_time_s() { return TIME_US_TO_S(first_packet_time_us); };

	/**
	 * @brief set first time of the the packet which belongs to this call
	 *
	*/
	void set_first_packet_time_us(u_int64_t time_us) { first_packet_time_us = time_us; };

	u_int64_t get_last_time_us() {
		if(typeIs(MGCP)) {
			return(last_mgcp_connect_packet_time_us);
		} else {
			extern bool opt_ignore_duration_after_bye_confirmed;
			if(opt_ignore_duration_after_bye_confirmed) {
				CallBranch *c_branch = this->branch_main();
				if(c_branch->seenbye_and_ok_time_usec && c_branch->seenbye_and_ok_time_usec > first_packet_time_us) {
					return(c_branch->seenbye_and_ok_time_usec);
				}
			}
		}
		return(get_last_packet_time_us());
	}
	
	u_int32_t get_last_time_s() { return TIME_US_TO_S(get_last_time_us()); }
	
	/**
	 * handle hold times
	 *
	*/
	void HandleHold(bool sdp_sendonly, bool sdp_sendrecv);
	/**
	 * @brief convert raw files to one WAV
	 *
	*/
	int convertRawToWav(void **transcribe_call, int thread_index);
	
	void selectRtpAB();
 
	/**
	 * @brief save call to database
	 *
	*/
	int saveToDb(bool enableBatchIfPossible = true);
	void prepareDbRow_cdr_next_branches(SqlDb_row &next_branch_row, CallBranch *n_branch, int indexRow, string &table, bool batch, string *query_str);
	int saveAloneByeToDb(bool enableBatchIfPossible = true);

	/**
	 * @brief save register msgs to database
	 *
	*/
	int saveRegisterToDb(bool enableBatchIfPossible = true);

	/**
	 * @brief save sip MSSAGE to database
	 *
	*/
	int saveMessageToDb(bool enableBatchIfPossible = true);

	/**
	 * @brief calculate duration of the call
	 *
	 * @return lenght of the call in seconds
	*/
	u_int64_t duration_us() {
		return(get_last_time_us() - first_packet_time_us);
	};
	double duration_sf() { return(TIME_US_TO_SF(duration_us())); };
	u_int32_t duration_s() { return(TIME_US_TO_S(duration_us())); };
	u_int64_t connect_duration_us() { return(connect_time_us ? duration_us() - (connect_time_us - first_packet_time_us) : 0); };
	u_int32_t connect_duration_s() { return(TIME_US_TO_S(connect_duration_us())); };
	u_int64_t callend_us() { return calltime_us() + duration_us(); };
	u_int32_t callend_s() { return TIME_US_TO_S(callend_us()); };
	
	u_int64_t duration_active_us() { return(unshiftSystemTime_ms(getTimeMS_rdtsc()) * 1000 - first_packet_time_us); };
	u_int32_t duration_active_s() { return(TIME_US_TO_S(duration_active_us())); };
	u_int64_t connect_duration_active_us() { return(connect_time_us ? duration_active_us() - (connect_time_us - first_packet_time_us) : 0); };
	u_int32_t connect_duration_active_s() { return(TIME_US_TO_S(connect_duration_active_us())); };
	
	/**
	 * @brief remove call from hash table
	 *
	*/
	void hashRemove(CallBranch *c_branch, bool useHashQueueCounter = false);
	
	void skinnyTablesRemove();

	void removeFindTables(CallBranch *c_branch, bool set_end_call = false, bool destroy = false, bool callFromAllBranch = false);
	
	void destroyCall();

	/**
	 * @brief remove all RTP 
	 *
	*/
	void setFlagForRemoveRTP();
	inline void removeRTP_ifSetFlag() {
		if(rtp_remove_flag) {
			_removeRTP();
		}
	}
	void _removeRTP();

	/**
	 * @brief stop recording packets to pcap file
	 *
	*/
	void stoprecording();

	/**
	 * @brief save call to register tables and remove from calltable 
	 *
	*/
	void saveregister(struct timeval *currtime);

	/**
	 * @brief print debug information for the call to stdout
	 *
	*/

	void evProcessRtpStream(CallBranch *c_branch, int index_ip_port, bool by_dest, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time) {
		if(index_ip_port < c_branch->ipport_n) {
			if(!c_branch->ip_port[index_ip_port].rtp[by_dest].saddr.isSet()) {
				c_branch->ip_port[index_ip_port].rtp[by_dest].saddr = saddr;
				c_branch->ip_port[index_ip_port].rtp[by_dest].sport = sport;
				c_branch->ip_port[index_ip_port].rtp[by_dest].daddr = daddr;
				c_branch->ip_port[index_ip_port].rtp[by_dest].dport = dport;
				this->evStartRtpStream(c_branch, index_ip_port, saddr, sport, daddr, dport, time);
			}
			c_branch->ip_port[index_ip_port].rtp[by_dest].last_packet_time = time;
		}
	}
	void evDestroyIpPortRtpStream(CallBranch *c_branch, int index_ip_port) {
		if(index_ip_port < c_branch->ipport_n) {
			for(int i = 0; i < 2; i++) {
				if(c_branch->ip_port[index_ip_port].rtp[i].saddr.isSet()) {
					this->evEndRtpStream(c_branch, index_ip_port, 
							     c_branch->ip_port[index_ip_port].rtp[i].saddr,
							     c_branch->ip_port[index_ip_port].rtp[i].sport,
							     c_branch->ip_port[index_ip_port].rtp[i].daddr,
							     c_branch->ip_port[index_ip_port].rtp[i].dport,
							     c_branch->ip_port[index_ip_port].rtp[i].last_packet_time);
				}
			}
			this->nullIpPortInfoRtpStream(c_branch, index_ip_port);
		}
	}
	void nullIpPortInfoRtpStream(CallBranch *c_branch, int index_ip_port) {
		if(index_ip_port < c_branch->ipport_n) {
			for(int i = 0; i < 2; i++) {
				c_branch->ip_port[index_ip_port].rtp[i].saddr.clear();
				c_branch->ip_port[index_ip_port].rtp[i].sport.clear();
				c_branch->ip_port[index_ip_port].rtp[i].daddr.clear();
				c_branch->ip_port[index_ip_port].rtp[i].dport.clear();
				c_branch->ip_port[index_ip_port].rtp[i].last_packet_time = 0;
			}
		}
	}
	
	void evStartRtpStream(CallBranch *c_branch, int index_ip_port, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time);
	void evEndRtpStream(CallBranch *c_branch, int index_ip_port, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time);
	
	void addtocachequeue(string file);
	static void _addtocachequeue(string file);

	void addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, long long writeBytes);
	static void _addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, string dirnamesqlfiles, long long writeBytes, int spoolIndex);

	float mos_lqo(char *deg, int samplerate);

	void handle_dtmf(char dtmf, double dtmf_time, vmIP saddr, vmIP daddr, s_dtmf::e_type dtmf_type);
	
	void handle_dscp(struct iphdr2 *header_ip, bool iscaller);
	
	bool check_is_caller_called(CallBranch *c_branch,
				    const char *call_id, int sip_method, int cseq_method,
				    vmIP saddr, vmIP daddr, 
				    vmIP saddr_first, vmIP daddr_first, u_int8_t first_protocol,
				    vmPort sport, vmPort dport,  
				    int *iscaller, int *iscalled = NULL, bool enableSetSipcallerdip = false);
	
	bool is_sipcaller(CallBranch *c_branch, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport);
	bool is_sipcalled(CallBranch *c_branch, vmIP daddr, vmPort dport, vmIP saddr, vmPort sport);
	
	bool use_both_side_for_check_direction() {
		extern bool opt_both_side_for_check_direction;
		return(opt_both_side_for_check_direction);
	}
	
	void check_reset_oneway(CallBranch *c_branch, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport) {
		if(c_branch->oneway &&
		   (c_branch->lastsrcip != saddr ||
		    (c_branch->lastsrcip == c_branch->lastdstip &&
		     c_branch->lastsrcport != sport))) {
			c_branch->invite_list_lock();
			for(vector<sInviteSD_Addr>::iterator iter = c_branch->invite_sdaddr.begin(); iter != c_branch->invite_sdaddr.end(); iter++) {
				if(sport == iter->sport && dport == iter->dport &&
				   saddr == iter->saddr && daddr == iter->daddr) {
					c_branch->invite_list_unlock();
					return;
				}
			}
			c_branch->invite_list_unlock();
			c_branch->oneway = 0;
		}
	}

	void dump();

	bool isFillRtpMap(CallBranch *c_branch, int index) {
		for(int i = 0; i < MAX_RTPMAP; i++) {
			if(c_branch->rtpmap[index][i].is_set()) {
				return(true);
			}
		}
		return(false);
	}
	int getTicksByCodecIfEq(CallBranch *c_branch, int index) {
		int ticks = 0;
		for(int i = 0; i < MAX_RTPMAP; i++) {
			if(c_branch->rtpmap[index][i].is_set()) {
				int ticks_codec = get_ticks_bycodec(c_branch->rtpmap[index][i].codec);
				if(!ticks) {
					ticks = ticks_codec;
				} else if(ticks != ticks_codec) {
					return(0);
				}
			}
		}
		return(ticks);
	}
	int getFillRtpMapByCallerd(CallBranch *c_branch, bool iscaller) {
		for(int i = c_branch->ipport_n - 1; i >= 0; i--) {
			if(c_branch->ip_port[i].iscaller == iscaller &&
			   isFillRtpMap(c_branch, i)) {
				return(i);
			}
		}
		return(-1);
	}

	void atFinish();
	
	bool isPcapsClose() {
		return(pcap.isClose() &&
		       pcapSip.isClose() &&
		       pcapRtp.isClose());
	}
	bool isGraphsClose() {
		#if not EXPERIMENTAL_LITE_RTP_MOD
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(rtp_i && !rtp_i->graph.isClose()) {
				return(false);
			}
		}
		#endif
		return(true);
	}
	bool closePcaps() {
		bool callClose = false;
		if(!pcap.isClose()) {
			pcap.close();
			callClose = true;
		}
		if(!pcapSip.isClose()) {
			pcapSip.close();
			callClose = true;
		}
		if(!pcapRtp.isClose()) {
			pcapRtp.close();
			callClose = true;
		}
		return(callClose);
	}
	bool closeGraphs() {
		bool callClose = false;
		#if not EXPERIMENTAL_LITE_RTP_MOD
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(rtp_i && !rtp_i->graph.isClose()) {
				rtp_i->graph.close();
				callClose = true;
			}
		}
		#endif
		return(callClose);
	}
	bool isReadyForWriteCdr() {
		return(isPcapsClose() && isGraphsClose() &&
		       isEmptyChunkBuffersCount());
	}
	
	u_int32_t getAllReceivedRtpPackets();
	
	void call_id_alternative_lock() {
		__SYNC_LOCK(this->_call_id_alternative_lock);
	}
	void call_id_alternative_unlock() {
		__SYNC_UNLOCK(this->_call_id_alternative_lock);
	}
	
	void custom_headers_content_lock() {
		__SYNC_LOCK(this->_custom_headers_content_sync);
	}
	void custom_headers_content_unlock() {
		__SYNC_UNLOCK(this->_custom_headers_content_sync);
	}
	
	void forcemark_lock() {
		__SYNC_LOCK(this->_forcemark_lock);
	}
	void forcemark_unlock() {
		__SYNC_UNLOCK(this->_forcemark_lock);
	}

	bool is_enable_set_destroy_call_at_for_call(CallBranch *c_branch, sCseq *cseq, int merged) {
		return((!cseq || !c_branch->invitecseq_in_dialog.size() || find(c_branch->invitecseq_in_dialog.begin(),c_branch->invitecseq_in_dialog.end(), *cseq) == c_branch->invitecseq_in_dialog.end()) &&
		       (!this->has_second_merged_leg || (this->has_second_merged_leg && merged)));
	}
	
	bool is_closed_other_branches(CallBranch *c_branch) {
		if(is_multibranch()) {
			if(first_branch.branch_id != c_branch->branch_id &&
			   !first_branch.is_closed()) {
				return(false);
			}
			bool ok = true;
			branches_lock();
			for(unsigned i = 0; i < next_branches.size(); i++) {
				if(next_branches[i]->branch_id != c_branch->branch_id &&
				   !next_branches[i]->is_closed()) {
					ok = false;
					break;
				}
			}
			branches_unlock();
			return(ok);
		}
		return(true);
	}
	
	void set_destroy_call_at(u_int32_t time_s, u_int32_t shift_s) {
		extern int opt_t2_boost;
		if(!typeIs(REGISTER) && opt_t2_boost) {
			extern int opt_t2_boost_direct_rtp;
			extern int opt_t2_boost_rtp_delay_queue_ms;
			extern int opt_t2_boost_rtp_max_queue_length_ms;
			extern int opt_t2_boost_direct_rtp_delay_queue_ms;
			extern int opt_t2_boost_direct_rtp_max_queue_length_ms;
			int delay_ms = opt_t2_boost_direct_rtp ?
					opt_t2_boost_direct_rtp_delay_queue_ms :
					opt_t2_boost_rtp_delay_queue_ms;
			int max_length_ms = opt_t2_boost_direct_rtp ?
					     opt_t2_boost_direct_rtp_max_queue_length_ms :
					     opt_t2_boost_rtp_max_queue_length_ms;
			if(delay_ms > 0 || max_length_ms > 0) {
				int max_delay = max(delay_ms, max_length_ms);
				if(shift_s < ceil(max_delay * 1.5 / 1000.)) {
					shift_s = ceil(max_delay * 1.5 / 1000.);
				}
			}
		}
		this->destroy_call_at = time_s + shift_s;
	}
	void shift_destroy_call_at(CallBranch *c_branch, u_int32_t time_s, int lastSIPresponseNum = 0) {
		extern int opt_quick_save_cdr;
		if(this->destroy_call_at > 0) {
			extern int opt_register_timeout;
			time_t new_destroy_call_at = 
				typeIs(REGISTER) ?
					time_s + opt_register_timeout :
					(c_branch->seenbye_and_ok ?
						time_s + (opt_quick_save_cdr == 2 ? 0 :
							 (opt_quick_save_cdr ? 1 : 5)) :
					 c_branch->seenbye ?
						time_s + 60 :
						time_s + (lastSIPresponseNum == 487 || c_branch->lastSIPresponseNum == 487 ? 15 : 5));
			if(new_destroy_call_at > this->destroy_call_at) {
				this->destroy_call_at = new_destroy_call_at;
			}
		}
	}
	
	void applyRtcpXrDataToRtp();
	void prepareRtcpXrData(sRtcpXrStreams *streams, bool checkOK);
	
	void adjustUA(CallBranch *c_branch);
	void adjustReason(CallBranch *c_branch);
	
	void createListeningBuffers();
	void destroyListeningBuffers();
	void disableListeningBuffers();
	
	bool checkKnownIP_inSipCallerdIP(CallBranch *c_branch, vmIP ip) {
		if(!c_branch) {
			if(checkKnownIP_inSipCallerdIP(&first_branch, ip)) {
				return(true);
			}
			bool rslt = false;
			if(next_branches.size()) {
				for(unsigned i = 0; i < next_branches.size(); i++) {
					if(checkKnownIP_inSipCallerdIP(next_branches[i], ip)) {
						rslt = true;
						break;
					}
				}
			}
			return(rslt);
		}
		for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
			if(ip == c_branch->sipcallerip[i] ||
			   ip == c_branch->sipcalledip[i]) {
				return(true);
			}
		}
		return(false);
	}
	
	bool isAllInviteConfirmed(CallBranch *c_branch) {
		if(c_branch->invite_sdaddr_all_confirmed == -1) {
			bool all_confirmed = true;
			c_branch->invite_list_lock();
			for(vector<sInviteSD_Addr>::iterator iter = c_branch->invite_sdaddr.begin(); iter != c_branch->invite_sdaddr.end(); iter++) {
				if(!iter->confirmed) {
					all_confirmed = false;
					break;
				}
			}
			c_branch->invite_sdaddr_all_confirmed = all_confirmed;
			c_branch->invite_list_unlock();
		}
		return(c_branch->invite_sdaddr_all_confirmed);
	}
	
	vmIP getSipcalleripFromInviteList(CallBranch *c_branch, vmPort *sport = NULL, vmIP *saddr_encaps = NULL, u_int8_t *saddr_encaps_protocol = NULL, 
					  bool onlyConfirmed = false, bool onlyFirst = false, u_int8_t only_ipv = 0);
	vmIP getSipcalledipFromInviteList(CallBranch *c_branch, vmPort *dport = NULL, vmIP *daddr_encaps = NULL, u_int8_t *daddr_encaps_protocol = NULL, list<vmIPport> *proxies = NULL, 
					  bool onlyConfirmed = false, bool onlyFirst = false, u_int8_t only_ipv = 0);
	void prepareSipIpForSave(CallBranch *c_branch, set<vmIP> *proxies_undup);
	
	unsigned getMaxRetransmissionInvite(CallBranch *c_branch);
	
	void calls_counter_inc() {
		extern volatile int calls_counter;
		if(typeIs(INVITE) || typeIs(MESSAGE) || typeIs(MGCP) || typeIs(SKINNY_NEW)) {
			__SYNC_INC(calls_counter);
			set_call_counter = true;
		}
	}
	void calls_counter_dec() {
		extern volatile int calls_counter;
		if(typeIs(INVITE) || typeIs(MESSAGE) || typeIs(MGCP) || typeIs(SKINNY_NEW)) {
			__SYNC_DEC(calls_counter);
			set_call_counter = false;
		}
	}
	void registers_counter_inc() {
		extern volatile int registers_counter;
		__SYNC_INC(registers_counter);
		set_register_counter = true;
	}
	void registers_counter_dec() {
		extern volatile int registers_counter;
		__SYNC_DEC(registers_counter);
		set_register_counter = false;
	}
	
	bool selectRtpStreams();
	bool selectRtpStreams_bySipcallerip();
	bool selectRtpStreams_byMaxLengthInLink();
	u_int64_t getLengthStreams_us(list<int> *streams_i);
	u_int64_t getLengthStreams_us();
	void setSkipConcurenceStreams(int caller);
	u_int64_t getFirstTimeInRtpStreams_us(int caller, bool selected);
	void printSelectedRtpStreams(int caller, bool selected);
	bool existsConcurenceInSelectedRtpStream(int caller, unsigned tolerance_ms);
	bool existsBothDirectionsInSelectedRtpStream();
	
	bool isSetCallidMergeHeader(bool checkForceSeparateBranches = false) {
		extern char opt_callidmerge_header[128];
		extern bool opt_call_branches;
		extern bool opt_callidmerge_force_separate_branches;
		return((typeIs(INVITE) || typeIs(MESSAGE)) &&
		       opt_callidmerge_header[0] != '\0' &&
		       !(checkForceSeparateBranches && opt_call_branches && opt_callidmerge_force_separate_branches));
	}
	void removeCallIdMap();
	void removeMergeCalls();
	void mergecalls_lock() {
		__SYNC_LOCK(this->_mergecalls_lock);
	}
	void mergecalls_unlock() {
		__SYNC_UNLOCK(this->_mergecalls_lock);
	}
	
	inline void setSipcallerip(CallBranch *c_branch, vmIP ip, vmIP ip_encaps, u_int8_t ip_encaps_prot, vmPort port, const char *call_id = NULL) {
		c_branch->sipcallerip[0] = ip;
		c_branch->sipcallerip_encaps = ip_encaps;
		c_branch->sipcallerip_encaps_prot = ip_encaps_prot;
		c_branch->sipcallerport[0] = port;
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			c_branch->map_sipcallerdip[call_id].sipcallerip[0] = ip;
			c_branch->map_sipcallerdip[call_id].sipcallerport[0] = port;
		}
	}
	inline void setSipcalledip(CallBranch *c_branch, vmIP ip, vmIP ip_encaps, u_int8_t ip_encaps_prot, vmPort port, const char *call_id = NULL) {
		if(c_branch->sipcalledip[0].isSet()) {
			c_branch->sipcalledip_mod = ip;
			c_branch->sipcalledport_mod = port;
		} else {
			c_branch->sipcalledip[0] = ip;
			c_branch->sipcalledport[0] = port;
		}
		c_branch->sipcalledip_encaps = ip_encaps;
		c_branch->sipcalledip_encaps_prot = ip_encaps_prot;
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			if(c_branch->map_sipcallerdip[call_id].sipcalledip[0].isSet()) {
				c_branch->map_sipcallerdip[call_id].sipcalledip_mod = ip;
				c_branch->map_sipcallerdip[call_id].sipcalledport_mod = port;
			} else {
				c_branch->map_sipcallerdip[call_id].sipcalledip[0] = ip;
				c_branch->map_sipcallerdip[call_id].sipcalledport[0] = port;
			}
		}
	}
	vmIP getSipcallerip(CallBranch *c_branch, bool correction_via_invite_list_if_need = false) {
		if(correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order) {
			vmIP sipcallerip_correction = getSipcalleripFromInviteList(c_branch);
			if(sipcallerip_correction.isSet()) {
				return(sipcallerip_correction);
			}
		}
		return(c_branch->sipcallerip[0]);
	}
	vmIP getSipcallerip_encaps(CallBranch *c_branch, bool correction_via_invite_list_if_need = false) {
		if(correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order) {
			vmIP sipcallerip_encaps_correction;
			u_int8_t sipcallerip_encaps_prot_correction;
			getSipcalleripFromInviteList(c_branch, NULL, &sipcallerip_encaps_correction, &sipcallerip_encaps_prot_correction);
			if(sipcallerip_encaps_correction.isSet()) {
				return(sipcallerip_encaps_correction);
			}
		}
		return(c_branch->sipcallerip_encaps);
	}
	u_int8_t getSipcallerip_encaps_prot(CallBranch *c_branch, bool correction_via_invite_list_if_need = false) {
		if(correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order) {
			vmIP sipcallerip_encaps_correction;
			u_int8_t sipcallerip_encaps_prot_correction;
			getSipcalleripFromInviteList(c_branch, NULL, &sipcallerip_encaps_correction, &sipcallerip_encaps_prot_correction);
			if(sipcallerip_encaps_correction.isSet()) {
				return(sipcallerip_encaps_prot_correction);
			}
		}
		return(c_branch->sipcallerip_encaps_prot);
	}
	vmIP getSipcalledip(CallBranch *c_branch, bool correction_via_invite_list_if_need = false, bool confirm_via_invite_list = false, vmPort *port = NULL, std::set<vmIP> *proxies = NULL) {
		bool need_correction = correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order;
		bool need_confirmed = confirm_via_invite_list && !isAllInviteConfirmed(c_branch);
		if(need_correction || need_confirmed) {
			vmPort sipcalledport_correction;
			list<vmIPport> proxies_correction;
			vmIP sipcalledip_correction;
			for(int i = 0; i < (need_correction && need_confirmed ? 2 : 1); i++) {
				sipcalledip_correction = getSipcalledipFromInviteList(c_branch, &sipcalledport_correction, NULL, NULL, proxies ? &proxies_correction : NULL, need_confirmed && i == 0);
				if(sipcalledip_correction.isSet()) {
					if(port) {
						*port = sipcalledport_correction;
					}
					if(proxies && proxies_correction.size()) {
						vmIPport proxy_exclude(sipcalledip_correction, sipcalledport_correction);
						c_branch->proxies_undup(proxies, &proxies_correction, &proxy_exclude);
					}
					return(sipcalledip_correction);
				}
			}
		}
		if(port) {
			*port = c_branch->sipcalledport_mod.isSet() ? c_branch->sipcalledport_mod : c_branch->sipcalledport[0];
		}
		if(proxies && c_branch->proxies.size()) {
			vmIPport proxy_exclude(c_branch->sipcalledip_mod.isSet() ? c_branch->sipcalledip_mod : c_branch->sipcalledip[0], 
					       c_branch->sipcalledport_mod.isSet() ? c_branch->sipcalledport_mod : c_branch->sipcalledport[0]);
			c_branch->proxies_undup(proxies, NULL, &proxy_exclude);
		}
		return(c_branch->sipcalledip_mod.isSet() ? c_branch->sipcalledip_mod : c_branch->sipcalledip[0]);
	}
	vmIP getSipcalledip_encaps(CallBranch *c_branch, bool correction_via_invite_list_if_need = false, bool confirm_via_invite_list = false) {
		bool need_correction = correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order;
		bool need_confirmed = confirm_via_invite_list && !isAllInviteConfirmed(c_branch);
		if(need_correction || need_confirmed) {
			vmIP sipcalledip_encaps_correction;
			u_int8_t sipcalledip_encaps_prot_correction;
			for(int i = 0; i < (need_correction && need_confirmed ? 2 : 1); i++) {
				getSipcalledipFromInviteList(c_branch, NULL, &sipcalledip_encaps_correction, &sipcalledip_encaps_prot_correction, NULL, need_confirmed && i == 0);
				if(sipcalledip_encaps_correction.isSet()) {
					return(sipcalledip_encaps_correction);
				}
			}
		}
		return(c_branch->sipcalledip_encaps);
	}
	u_int8_t getSipcalledip_encaps_prot(CallBranch *c_branch, bool correction_via_invite_list_if_need = false, bool confirm_via_invite_list = false) {
		bool need_correction = correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order;
		bool need_confirmed = confirm_via_invite_list && !isAllInviteConfirmed(c_branch);
		if(need_correction || need_confirmed) {
			vmIP sipcalledip_encaps_correction;
			u_int8_t sipcalledip_encaps_prot_correction;
			for(int i = 0; i < (need_correction && need_confirmed ? 2 : 1); i++) {
				getSipcalledipFromInviteList(c_branch, NULL, &sipcalledip_encaps_correction, &sipcalledip_encaps_prot_correction, NULL, need_confirmed && i == 0);
				if(sipcalledip_encaps_correction.isSet()) {
					return(sipcalledip_encaps_prot_correction);
				}
			}
		}
		return(c_branch->sipcalledip_encaps_prot);
	}
	vmPort getSipcallerport(CallBranch *c_branch, bool correction_via_invite_list_if_need = false) {
		if(correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order) {
			vmPort sipcallerport_correction;
			getSipcalleripFromInviteList(c_branch, &sipcallerport_correction);
			if(sipcallerport_correction.isSet()) {
				return(sipcallerport_correction);
			}
		}
		return(c_branch->sipcallerport[0]);
	}
	vmPort getSipcalledport(CallBranch *c_branch, bool correction_via_invite_list_if_need = false, bool confirm_via_invite_list = false) {
		bool need_correction = correction_via_invite_list_if_need && c_branch->invite_sdaddr_bad_order;
		bool need_confirmed = confirm_via_invite_list && !isAllInviteConfirmed(c_branch);
		if(need_correction || need_confirmed) {
			vmPort sipcalledport_correction;
			for(int i = 0; i < (need_correction && need_confirmed ? 2 : 1); i++) {
				getSipcalledipFromInviteList(c_branch, &sipcalledport_correction, NULL, NULL, NULL, need_confirmed && i == 0);
				if(sipcalledport_correction.isSet()) {
					return(sipcalledport_correction);
				}
			}
		}
		return(c_branch->sipcalledport_mod.isSet() ? c_branch->sipcalledport_mod : c_branch->sipcalledport[0]);
	}
	void getProxies(CallBranch *c_branch, std::set<vmIP> *proxies = NULL, bool correction_via_invite_list_if_need = false, bool confirm_via_invite_list = false) {
		getSipcalledip(c_branch, correction_via_invite_list_if_need, confirm_via_invite_list, NULL, proxies);
	}
	string getProxies_str(CallBranch *c_branch, bool correction_via_invite_list_if_need = false, bool confirm_via_invite_list = false) {
		string rslt;
		std::set<vmIP> proxies;
		getProxies(c_branch, &proxies, correction_via_invite_list_if_need, confirm_via_invite_list);
		for(set<vmIP>::iterator iter = proxies.begin(); iter != proxies.end(); iter++) {
			if(!rslt.empty()) {
				rslt += ",";
			}
			rslt += iter->getString();
		}
		return(rslt);
	}
	
	void setSeenBye(CallBranch *c_branch, bool seenbye, u_int64_t seenbye_time_usec, const char *call_id) {
		c_branch->seenbye = seenbye;
		if(!c_branch->seenbye_time_usec || (!seenbye && !seenbye_time_usec)) {
			c_branch->seenbye_time_usec = seenbye_time_usec;
		}
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seenbye = seenbye;
				if(!mergecalls[call_id].seenbye_time_usec || (!seenbye && !seenbye_time_usec)) {
					mergecalls[call_id].seenbye_time_usec = seenbye_time_usec;
				}
			}
			mergecalls_unlock();
		}
	}
	void setSeenOkBye(CallBranch *c_branch, bool seenokbye, u_int64_t seenokbye_time_usec, const char *call_id) {
		c_branch->seenokbye = seenokbye;
		if(!c_branch->seenokbye_time_usec || (!seenokbye && !seenokbye_time_usec)) {
			c_branch->seenokbye_time_usec = seenokbye_time_usec;
		}
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seenokbye = seenokbye;
				if(!mergecalls[call_id].seenokbye_time_usec || (!seenokbye && !seenokbye_time_usec)) {
					mergecalls[call_id].seenokbye_time_usec = seenokbye_time_usec;
				}
			}
			mergecalls_unlock();
		}
	}
	void setSeenByeAndOk(CallBranch *c_branch, bool seenbye_and_ok, u_int64_t seenbye_and_ok_time_usec, const char *call_id) {
		c_branch->seenbye_and_ok = seenbye_and_ok;
		if(seenbye_and_ok) {
			c_branch->seenbye_and_ok_permanent = true;
		}
		if(!c_branch->seenbye_and_ok_time_usec || (!seenbye_and_ok && !seenbye_and_ok_time_usec)) {
			c_branch->seenbye_and_ok_time_usec = seenbye_and_ok_time_usec;
		}
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seenbye_and_ok = seenbye_and_ok;
				if(!mergecalls[call_id].seenbye_and_ok_time_usec || (!seenbye_and_ok && !seenbye_and_ok_time_usec)) {
					mergecalls[call_id].seenbye_and_ok_time_usec = seenbye_and_ok_time_usec;
				}
			}
			mergecalls_unlock();
		}
	}
	void setSeenCancel(CallBranch *c_branch, bool seencancel, u_int64_t seencancel_time_usec, const char *call_id) {
		c_branch->seencancel = seencancel;
		if(!c_branch->seencancel_time_usec || (!seencancel && !seencancel_time_usec)) {
			c_branch->seencancel_time_usec = seencancel_time_usec;
		}
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seencancel = seencancel;
				if(!mergecalls[call_id].seencancel_time_usec || (!seencancel && !seencancel_time_usec)) {
					mergecalls[call_id].seencancel_time_usec = seencancel_time_usec;
				}
			}
			mergecalls_unlock();
		}
	}
	void setSeenCancelAndOk(CallBranch *c_branch, bool seencancel_and_ok, u_int64_t seencancel_and_ok_time_usec, const char *call_id) {
		c_branch->seencancel_and_ok = seencancel_and_ok;
		if(!c_branch->seencancel_and_ok_time_usec || (!seencancel_and_ok && !seencancel_and_ok_time_usec)) {
			c_branch->seencancel_and_ok_time_usec = seencancel_and_ok_time_usec;
		}
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seencancel_and_ok = seencancel_and_ok;
				if(!mergecalls[call_id].seencancel_and_ok_time_usec || (!seencancel_and_ok && !seencancel_and_ok_time_usec)) {
					mergecalls[call_id].seencancel_and_ok_time_usec = seencancel_and_ok_time_usec;
				}
			}
			mergecalls_unlock();
		}

	}
	void setSeenAuthFailed(CallBranch *c_branch, bool seenauthfailed, u_int64_t seenauthfailed_time_usec, const char *call_id) {
		c_branch->seenauthfailed = seenauthfailed;
		if(!c_branch->seenauthfailed_time_usec || (!seenauthfailed && !seenauthfailed_time_usec)) {
			c_branch->seenauthfailed_time_usec = seenauthfailed_time_usec;
		}
		if(isSetCallidMergeHeader(true) &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seenauthfailed = seenauthfailed;
				if(!mergecalls[call_id].seenauthfailed_time_usec || (!seenauthfailed && !seenauthfailed_time_usec)) {
					mergecalls[call_id].seenauthfailed_time_usec = seenauthfailed_time_usec;
				}
			}
			mergecalls_unlock();
		}
	}
	u_int64_t getSeenByeTimeUS(CallBranch *c_branch) {
		if(isSetCallidMergeHeader(true)) {
			u_int64_t seenbye_time_usec = 0;
			mergecalls_lock();
			for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
				if(!it->second.seenbye || !it->second.seenbye_time_usec) {
					mergecalls_unlock();
					return(0);
				}
				if(seenbye_time_usec < it->second.seenbye_time_usec) {
					seenbye_time_usec = it->second.seenbye_time_usec;
				}
			}
			mergecalls_unlock();
			return(seenbye_time_usec);
		}
		return(c_branch->seenbye ? c_branch->seenbye_time_usec : 0);
	}
	u_int64_t getSeenByeAndOkTimeUS(CallBranch *c_branch) {
		if(isSetCallidMergeHeader(true)) {
			u_int64_t seenbye_and_ok_time_usec = 0;
			mergecalls_lock();
			for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
				if(!it->second.seenbye_and_ok || !it->second.seenbye_and_ok_time_usec) {
					mergecalls_unlock();
					return(0);
				}
				if(seenbye_and_ok_time_usec < it->second.seenbye_and_ok_time_usec) {
					seenbye_and_ok_time_usec = it->second.seenbye_and_ok_time_usec;
				}
			}
			mergecalls_unlock();
			return(seenbye_and_ok_time_usec);
		}
		return(c_branch->seenbye_and_ok ? c_branch->seenbye_and_ok_time_usec : 0);
	}
	u_int64_t getSeenCancelTimeUS(CallBranch *c_branch) {
		if(isSetCallidMergeHeader(true)) {
			u_int64_t seencancel_time_usec = 0;
			mergecalls_lock();
			for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
				if(!it->second.seencancel || !it->second.seencancel_time_usec) {
					mergecalls_unlock();
					return(0);
				}
				if(seencancel_time_usec < it->second.seencancel_time_usec) {
					seencancel_time_usec = it->second.seencancel_time_usec;
				}
			}
			mergecalls_unlock();
			return(seencancel_time_usec);
		}
		return(c_branch->seencancel ? c_branch->seencancel_time_usec : 0);
	}
	u_int64_t getSeenCancelAndOkTimeUS(CallBranch *c_branch) {
		if(isSetCallidMergeHeader(true)) {
			u_int64_t seencancel_and_ok_time_usec = 0;
			mergecalls_lock();
			for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
				if(!it->second.seencancel_and_ok || !it->second.seencancel_and_ok_time_usec) {
					mergecalls_unlock();
					return(0);
				}
				if(seencancel_and_ok_time_usec < it->second.seencancel_and_ok_time_usec) {
					seencancel_and_ok_time_usec = it->second.seencancel_and_ok_time_usec;
				}
			}
			mergecalls_unlock();
			return(seencancel_and_ok_time_usec);
		}
		return(c_branch->seencancel_and_ok ? c_branch->seencancel_and_ok_time_usec : 0);
	}
	u_int64_t getSeenAuthFailedTimeUS(CallBranch *c_branch) {
		if(isSetCallidMergeHeader(true)) {
			u_int64_t seenauthfailed_time_usec = 0;
			mergecalls_lock();
			for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
				if(!it->second.seenauthfailed || !it->second.seenauthfailed_time_usec) {
					mergecalls_unlock();
					return(0);
				}
				if(seenauthfailed_time_usec < it->second.seenauthfailed_time_usec) {
					seenauthfailed_time_usec = it->second.seenauthfailed_time_usec;
				}
			}
			mergecalls_unlock();
			return(seenauthfailed_time_usec);
		}
		return(c_branch->seenauthfailed ? c_branch->seenauthfailed_time_usec : 0);
	}
	int setByeCseq(CallBranch *c_branch, sCseq *cseq) {
		unsigned index;
		unsigned size_byecseq = sizeof(c_branch->byecseq) / sizeof(c_branch->byecseq[0]);
		for(index = 0; index < size_byecseq; index++) {
			if(!c_branch->byecseq[index].is_set()) {
				break;
			} else if(c_branch->byecseq[index] == *cseq) {
				return(index);
			}
		}
		if(index == size_byecseq) {
			index = size_byecseq - 1;
		}
		c_branch->byecseq[index] = *cseq;
		return(index);
	}
	int existsByeCseq(CallBranch *c_branch, sCseq *cseq) {
		for(unsigned index = 0; index < (sizeof(c_branch->byecseq) / sizeof(c_branch->byecseq[0])); index++) {
			if(c_branch->byecseq[index].is_set() &&
			   c_branch->byecseq[index] == *cseq) {
				return(index + 1);
			}
		}
		return(0);
	}
	
	void getValue(eCallField field, RecordArrayField *rfield);
	static string getJsonHeader();
	static void getJsonHeader(vector<string> *header);
	void getRecordData(RecordArray *rec);
	string getJsonData();
	void setRtpThreadNum();
	
	void hash_add_lock() {
		__SYNC_LOCK(this->_hash_add_lock);
	}
	void hash_add_unlock() {
		__SYNC_UNLOCK(this->_hash_add_lock);
	}
	
	void add_txt(u_int64_t time, eTxtType type, const char *txt, unsigned txt_length);
	int detectCallerdByLabelInXml(const char *label);
	void txt_lock() {
		__SYNC_LOCK(this->_txt_lock);
	}
	void txt_unlock() {
		__SYNC_UNLOCK(this->_txt_lock);
	}
	
	void getChartCacheValue(int type, double *value, string *value_str, bool *null, class cCharts *chartsCache);
	static void getChartCacheValue(cDbTablesContent *tablesContent,
				       int type, double *value, string *value_str, bool *null, class cCharts *chartsCache);
	bool sqlFormulaOperandReplace(cEvalFormula::sValue *value, string *table, string *column, void *callData, 
				      string *child_table, unsigned child_index, cEvalFormula::sOperandReplaceData *ord);
	static bool sqlFormulaOperandReplace(cDbTablesContent *tablesContent,
					     cEvalFormula::sValue *value, string *table, string *column, void *callData, 
					     string *child_table, unsigned child_index, cEvalFormula::sOperandReplaceData *ord);
	int sqlChildTableSize(string *child_table, void *callData);
	
	bool isEmptyCdrRow() {
		return(cdr.isEmpty());
	}
	
	void addRegTcpSeq(u_int32_t seq) {
		if(seq) {
			if(!reg.reg_tcp_seq) {
				reg.reg_tcp_seq = new list<u_int32_t>;
			}
			reg.reg_tcp_seq->push_back(seq);
		}
	}
	
	eMoMtLegFlag momt_get();
	
	void srvcc_check_post(CallBranch *c_branch);
	void srvcc_check_pre(CallBranch *c_branch);
	
	#if not EXPERIMENTAL_LITE_RTP_MOD
	inline void add_rtp_stream(RTP *rtp) {
		#if CALL_RTP_DYNAMIC_ARRAY
		if(ssrc_n < MAX_SSRC_PER_CALL_FIX) {
			rtp_fix[ssrc_n] = rtp;
		} else {
			if(!rtp_dynamic) {
				rtp_dynamic = new FILE_LINE(0) CALL_RTP_DYNAMIC_ARRAY_TYPE;
			}
			rtp_dynamic->push_back(rtp);
		}
		#else
		rtp_fix[ssrc_n] = rtp;
		#endif
		++ssrc_n;
	}
	#endif
	inline RTP *rtp_stream_by_index(unsigned index) {
		#if not EXPERIMENTAL_LITE_RTP_MOD
		#if CALL_RTP_DYNAMIC_ARRAY
		if(index < MAX_SSRC_PER_CALL_FIX) {
			return(rtp_fix[index]);
		} else {
			return((*rtp_dynamic)[index - MAX_SSRC_PER_CALL_FIX]);
		}
		#else
		return(rtp_fix[index]);
		#endif
		#else
		return(&rtp_fix[index]);
		#endif
	}
	inline int rtp_size() {
		return(ssrc_n);
	}
	string get_rtp_streams_info_json();
	
	inline bool existsSrtp() {
		return(exists_srtp);
	}
	inline bool existsSrtpCryptoConfig() {
		return(exists_srtp_crypto_config);
	}
	inline bool existsSrtpFingerprint() {
		return(exists_srtp_fingerprint);
	}
	inline bool isSrtpInIpPort(CallBranch *c_branch, int indexIpPort) {
		return(c_branch->ip_port[indexIpPort].srtp);
	}
	
	void dtls_keys_add(cDtlsLink::sSrtpKeys* keys_item);
	unsigned dtls_keys_count();
	cDtlsLink::sSrtpKeys* dtls_keys_get(unsigned index);
	void dtls_keys_clear();
	void dtls_keys_lock();
	void dtls_keys_unlock();

public:	
	CallBranch first_branch;
	vector<CallBranch*> next_branches;
	map<string, int> branches_to_map;
	map<string, int> branches_tag_map;
	volatile unsigned branch_main_id;
	volatile int _branches_lock;
	inline bool is_multibranch() {
		return(next_branches.size() > 0);
	}
	inline CallBranch *branch_main() {
		return(branch(branch_main_id));
	}
	inline CallBranch *branch(unsigned branch_id) {
		if(branch_id == 0) {
			return(&first_branch);
		} else {
			CallBranch *branch;
			branches_lock();
			branch = next_branches[branch_id - 1];
			branches_unlock();
			return(branch);
		}
	}
	void branches_lock() {
		__SYNC_LOCK(_branches_lock);
	}
	void branches_unlock() {
		__SYNC_UNLOCK(_branches_lock);
	}
	void dtls_queue_lock() {
		__SYNC_LOCK(dtls_queue_sync);
	}
	void dtls_queue_unlock() {
		__SYNC_UNLOCK(dtls_queue_sync);
	}
	void setDiameterFromSip(const char *from_sip);
	void setDiameterToSip(const char *to_sip);
	void getDiameterFromSip(list<string> *from_sip);
	void getDiameterToSip(list<string> *to_sip);
	void clearDiameterFromSip();
	void clearDiameterToSip();
	void moveDiameterPacketsToPcap(bool enableSave = true);
	void set_pcap_dump_error(int pcap_dump_error) {
		this->pcap_dump_error |= pcap_dump_error;
	}
	inline void set_callerd_confirm_rtp_by_both_sides_sdp(int8_t iscaller) {
		__SYNC_SET(callerd_confirm_rtp_by_both_sides_sdp[iscaller]);
	}
	inline int8_t get_callerd_confirm_rtp_by_both_sides_sdp(int8_t iscaller) {
		return(ATOMIC_LOAD(callerd_confirm_rtp_by_both_sides_sdp[iscaller]) > 0);
	}
	
private:
	
	volatile int8_t callerd_confirm_rtp_by_both_sides_sdp[2];
	bool exists_srtp;
	bool exists_srtp_crypto_config;
	bool exists_srtp_fingerprint;
	bool log_srtp_callid;
	PcapDumper pcap;
	PcapDumper pcapSip;
	PcapDumper pcapRtp;
	int pcap_dump_error;
	map<sStreamId, sUdptlDumper*> udptlDumpers;
	volatile int _hash_add_lock;
	int payload_rslt;
	map<string, bool> diameter_from_sip;
	map<string, bool> diameter_to_sip;
public:
	list<vmPort> sdp_ip0_ports[2];
	bool error_negative_payload_length;
	#if NEW_RTP_FIND__NODES
	list<vmIPport> rtp_ip_port_list;
	#endif
	volatile int hash_queue_counter;
	volatile int attemptsClose;
	volatile bool stopProcessing;
	u_int32_t stopProcessingAt_s;
	bool bad_flags_warning[2];
	volatile int useInListCalls;
	bool use_rtcp_mux;
	bool use_sdp_sendonly;
	bool rtp_from_multiple_sensors;
	bool sdp_exists_media_type_audio;
	bool sdp_exists_media_type_image;
	bool sdp_exists_media_type_video;
	bool sdp_exists_media_type_application;
	bool siprec;
	#if not PROCESS_PACKETS_INDIC_MOD_1
	volatile int in_preprocess_queue_before_process_packet;
	volatile u_int32_t in_preprocess_queue_before_process_packet_at[2];
	#endif
	bool suppress_rtp_read_due_to_insufficient_hw_performance;
	bool suppress_rtp_proc_due_to_insufficient_hw_performance;
	bool stopped_jb_due_to_high_ooo;
	bool changing_codec_in_stream;
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	volatile bool sp_sent_close_call;
	volatile bool sp_arrived_rtp_streams;
	volatile u_int32_t sp_stop_rtp_processing_at;
	volatile u_int32_t sp_do_destroy_call_at;
	set<vmIPport> sp_rtp_ipport;
	#endif
	unsigned sip_packets_counter;
	unsigned invite_packets_counter;
	unsigned process_rtp_counter;
	#if CALL_DEBUG_RTP
	volatile int8_t debug_rtp;
	#endif
	bool save_sip_pcap : 1;
	bool save_rtp_pcap : 1;
	bool save_rtp_payload_pcap : 1;
	bool save_rtcp_pcap : 1;
	bool save_rtp_graph : 1;
	unsigned rslt_save_cdr_bye;
	u_int64_t rslt_save_cdr_flags;
private:
	SqlDb_row cdr;
	SqlDb_row cdr_next;
	SqlDb_row cdr_next_ch[CDR_NEXT_MAX];
	SqlDb_row cdr_country_code;
	#if CALL_RTP_DYNAMIC_ARRAY
	map<unsigned, unsigned> rtp_rows_indexes;
	#else
	unsigned rtp_rows_indexes[MAX_SSRC_PER_CALL_FIX];
	#endif
	unsigned rtp_rows_count;
	vector<s_sdp_store_data> sdp_rows_list;
	bool set_call_counter;
	bool set_register_counter;
	double price_customer;
	double price_operator;
friend class RTP;
friend class RTPsecure;
};


void adjustSipResponse(string &sipResponse);
void adjustReason(string &reason);
void adjustUA(string &ua);

inline unsigned int tuplehash(u_int32_t addr, u_int16_t port) {
	unsigned int key;

	key = (unsigned int)(addr * port);
	key += ~(key << 15);
	key ^=  (key >> 10);
	key +=  (key << 3);
	key ^=  (key >> 6);
	key += ~(key << 11);
	key ^=  (key >> 16);
	return key % MAXNODE;
}


class Ss7 : public Call_abstract {
public:
	enum eState {
		call_setup,
		in_call,
		completed,
		rejected,
		canceled
	};
	enum eMessageType {
		iam,
		acm,
		cpg,
		anm,
		rel,
		rlc
	};
	struct sParseData {
		sParseData() {
			isup_message_type = 0;
			isup_cic = 0;
			isup_satellite_indicator = 0;
			isup_echo_control_device_indicator = 0;
			isup_calling_partys_category = 0;
			isup_calling_party_nature_of_address_indicator = 0;
			isup_ni_indicator = 0;
			isup_address_presentation_restricted_indicator = 0;
			isup_screening_indicator = 0;
			isup_transmission_medium_requirement = 0;
			isup_called_party_nature_of_address_indicator = 0;
			isup_inn_indicator = 0;
			m3ua_protocol_data_opc = 0;
			m3ua_protocol_data_dpc = 0;
			mtp3_opc = 0;
			mtp3_dpc = 0;
			isup_cause_indicator = 0;
		}
		bool parse(struct packet_s_stack *packetS, const char *dissect_rslt = NULL);
		string ss7_id() {
			if(!isOk()) {
				return("");
			}
			unsigned opc = isset_unsigned(m3ua_protocol_data_opc) ? m3ua_protocol_data_opc : mtp3_opc;
			unsigned dpc = isset_unsigned(m3ua_protocol_data_dpc) ? m3ua_protocol_data_dpc : mtp3_dpc;
			unsigned low_point = min(opc, dpc);
			unsigned high_point = max(opc, dpc);
			extern int opt_ss7_type_callid;
			return(opt_ss7_type_callid == 2 ?
				intToString(isup_cic) :
				intToString(isup_cic) + "-" + intToString(low_point) + "-" + intToString(high_point));
		}
		string filename() {
			if(!isOk()) {
				return("");
			}
			unsigned opc = isset_unsigned(m3ua_protocol_data_opc) ? m3ua_protocol_data_opc : mtp3_opc;
			unsigned dpc = isset_unsigned(m3ua_protocol_data_dpc) ? m3ua_protocol_data_dpc : mtp3_dpc;
			return(intToString(isup_cic) + "-" + intToString(opc) + "-" + intToString(dpc) + "-" +
			       e164_calling_party_number_digits + "-" + e164_called_party_number_digits);
		}
		bool isOk() {
			return(isset_unsigned(isup_cic) &&
			       (isset_unsigned(m3ua_protocol_data_opc) || isset_unsigned(mtp3_opc)) &&
			       (isset_unsigned(m3ua_protocol_data_dpc) || isset_unsigned(mtp3_dpc)));
		}
		bool isset_unsigned(unsigned value) {
			return(value != UINT_MAX);
		}
		void debugOutput();
		unsigned isup_message_type;
		unsigned isup_cic;
		unsigned isup_satellite_indicator;
		unsigned isup_echo_control_device_indicator;
		unsigned isup_calling_partys_category;
		unsigned isup_calling_party_nature_of_address_indicator;
		unsigned isup_ni_indicator;
		unsigned isup_address_presentation_restricted_indicator;
		unsigned isup_screening_indicator;
		unsigned isup_transmission_medium_requirement;
		unsigned isup_called_party_nature_of_address_indicator;
		unsigned isup_inn_indicator;
		unsigned m3ua_protocol_data_opc;
		unsigned m3ua_protocol_data_dpc;
		unsigned mtp3_opc;
		unsigned mtp3_dpc;
		string e164_called_party_number_digits;
		string e164_calling_party_number_digits;
		string isup_subsequent_number;
		unsigned isup_cause_indicator;
	};
public:
	Ss7(u_int64_t time_us);
	void processData(packet_s_stack *packetS, sParseData *data);
	void pushToQueue(string *ss7_id = NULL);
	int saveToDb(bool enableBatchIfPossible = true);
	string ss7_id() {
		return(iam_data.ss7_id());
	}
	string filename() {
		return(intToString(iam_time_us) + "-" + iam_data.filename());
	}
	eState getState() {
		return(rel_time_us ?
			(anm_time_us ? 
			  completed :
			(rel_cause_indicator == 16 ? 
			  canceled : 
			  rejected)) :
			(anm_time_us ? 
			  in_call : 
			  call_setup));
	}
	string getStateToString() {
		eState state = getState();
		return(state == call_setup ? "call_setup" :
		       state == in_call ? "in_call" :
		       state == completed ? "completed" :
		       state == rejected ? "rejected" :
		       state == canceled ? "canceled" : "");
	}
	string lastMessageTypeToString() {
		return(last_message_type == iam ? "iam" :
		       last_message_type == acm ? "acm" :
		       last_message_type == cpg ? "cpg" :
		       last_message_type == anm ? "anm" :
		       last_message_type == rel ? "rel" :
		       last_message_type == rlc ? "rlc" : "");
	}
	bool isset_unsigned(unsigned value) {
		return(value != UINT_MAX);
	}
private:
	void init();
public:
	eMessageType last_message_type;
	// IAM (Initial Address)
	sParseData iam_data;
	sParseData sam_data;
	vmIP iam_src_ip;
	vmIP iam_dst_ip;
	u_int64_t iam_time_us;
	// ACM (Address Complete)
	u_int64_t acm_time_us;
	// CPG (Call Progress)
	u_int64_t cpg_time_us;
	// ANM (Answer)
	u_int64_t anm_time_us;
	// REL (Reelease)
	u_int64_t rel_time_us;
	// RLC (Release complete)
	u_int64_t rlc_time_us;
	u_int64_t last_time_us;
	unsigned rel_cause_indicator;
	u_int32_t destroy_at_s;
	bool sonus : 1;
	bool rudp : 1;
	PcapDumper pcap;
private:
	struct timeval last_dump_ts;
};


struct sChartsCallData {
	enum eType {
		_call,
		_tables_content,
		_csv
	};
	eType type;
	void *data;
	sChartsCallData(eType type, void *data) {
		this->type = type;
		this->data = data;
	}
	inline Call* call() { return((Call*)data); }
	inline CallBranch* branch_main() { return(((Call*)data)->branch_main()); }
	inline cDbTablesContent* tables_content() { return((cDbTablesContent*)data); }
};


/**
  * This class implements operations on Call list
*/

class Calltable {
private:
	struct sAudioQueueThread {
		sAudioQueueThread(int thread_index) {
			thread_handle = 0;
			thread_id = 0;
			this->thread_index = thread_index;
		}
		pthread_t thread_handle;
		int thread_id;
		int thread_index;
	};
	enum eHashModifyOper {
		hmo_add,
		hmo_remove,
		hmo_remove_call
	};
	struct sHashModifyData {
		eHashModifyOper oper;
		vmIP addr;
		vmPort port;
		u_int32_t time_s;
		CallBranch *c_branch;
		int8_t iscaller;
		int8_t is_rtcp;
		int8_t ignore_rtcp_check;
		s_sdp_flags sdp_flags;
		bool use_hash_queue_counter;
	};
	struct sChcThreadData {
		pthread_t thread;
		int tid;
		pstat_data pstat[2][2];
		sem_t sem[2];
		bool init;
		list<sChartsCallData> *calls;
		class cFiltersCache *cache;
	};
	struct sSrvccPostCall {
		inline sSrvccPostCall(const char *call_id = NULL, u_int64_t first_packet_time_us = 0) {
			this->call_id = call_id ? call_id : "";
			this->first_packet_time_us = first_packet_time_us;
		}
		string call_id;
		u_int64_t first_packet_time_us;
	};
	struct sSrvccPostCalls {
		list<sSrvccPostCall*> calls;
	};
	class cSrvccCalls {
	public:
		cSrvccCalls() {
			_sync_calls = 0;
			cleanup_last_time_s = getTimeS_rdtsc();
			cleanup_period_s = 60;
		}
		void set(const char *number, const char *call_id, u_int64_t first_packet_time_us) {
			extern int opt_srvcc_compare_number_length;
			string number_str = number;
			if(opt_srvcc_compare_number_length > 0 && number_str.length() > (unsigned)opt_srvcc_compare_number_length) {
				number_str = number_str.substr(number_str.length() - opt_srvcc_compare_number_length);
			}
			__SYNC_LOCK(_sync_calls);
			sSrvccPostCalls *post_calls = NULL;
			map<string, sSrvccPostCalls*>::iterator iter = calls.find(number_str);
			if(iter != calls.end()) {
				post_calls = iter->second;
			} else {
				post_calls = new FILE_LINE(0) sSrvccPostCalls;
				calls[number_str] = post_calls;
			}
			post_calls->calls.push_back(new FILE_LINE(0) sSrvccPostCall(call_id, first_packet_time_us));
			__SYNC_UNLOCK(_sync_calls);
			cleanup();
		}
		string get(const char *number, u_int64_t first_packet_time_us, u_int64_t last_packet_time_us) {
			string call_id;
			extern int opt_srvcc_compare_number_length;
			string number_str = number;
			if(opt_srvcc_compare_number_length > 0 && number_str.length() > (unsigned)opt_srvcc_compare_number_length) {
				number_str = number_str.substr(number_str.length() - opt_srvcc_compare_number_length);
			}
			__SYNC_LOCK(_sync_calls);
			map<string, sSrvccPostCalls*>::iterator iter = calls.find(number_str);
			if(iter != calls.end()) {
				sSrvccPostCalls *post_calls = iter->second;
				for(list<sSrvccPostCall*>::iterator iter_2 = post_calls->calls.begin(); iter_2 != post_calls->calls.end(); iter_2++) {
					if(first_packet_time_us <= (*iter_2)->first_packet_time_us &&
					   last_packet_time_us >= (*iter_2)->first_packet_time_us) {
						sSrvccPostCall *post_call = *iter_2;
						call_id = post_call->call_id;
						break;
					}
				}
			}
			__SYNC_UNLOCK(_sync_calls);
			return(call_id);
		}
	private:
		void cleanup();
	private:
		map<string, sSrvccPostCalls*> calls;
		volatile int _sync_calls;
		u_int32_t cleanup_last_time_s;
		u_int32_t cleanup_period_s;
	};
public:
	deque<Call*> calls_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	deque<Call*> audio_queue; //!< this queue is used for asynchronous audio convert by the worker thread
	deque<Call*> calls_deletequeue; //!< this queue is used for asynchronous storing CDR by the worker thread
	deque<sChartsCallData> calls_charts_cache_queue;
	deque<Call*> registers_queue;
	deque<Call*> registers_deletequeue;
	deque<Ss7*> ss7_queue;
	queue<string> files_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	queue<string> files_sqlqueue; //!< this queue is used for asynchronous storing CDR by the worker thread
	list<Call*> calls_list;
	map<string, Call*> calls_listMAP;
	map<sStreamIds2, Call*> calls_by_stream_callid_listMAP;
	map<sStreamId2, Call*> calls_by_stream_id2_listMAP;
	map<sStreamId, Call*> calls_by_stream_listMAP;
	map<string, Call*> calls_mergeMAP;
	map<string, Call*> calls_diameter_from_sip_listMAP;
	map<string, Call*> calls_diameter_to_sip_listMAP;
	map<string, Call*> conference_calls_map;
	map<string, Call*> registers_listMAP;
	map<d_item<vmIP>, Call*> skinny_ipTuples;
	map<unsigned int, Call*> skinny_partyID;
	map<string, Ss7*> ss7_listMAP;
	cSrvccCalls srvcc_calls;

	/**
	 * @brief constructor
	 *
	*/
	Calltable(SqlDb *sqlDb = NULL);
	/*
	Calltable() { 
		pthread_mutex_init(&qlock, NULL); 
		printf("SS:%d\n", sizeof(calls_hash));
		printf("SS:%s\n", 1);
		memset(calls_hash, 0x0, sizeof(calls_hash) * MAXNODE);
	};
	*/

	/**
	 * destructor
	 * 
	*/
	~Calltable();

	/**
	 * @brief lock calls_queue structure 
	 *
	*/
	void lock_calls_queue() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_queue, opt_lock_calls_usleep); 
		/*pthread_mutex_lock(&qlock);*/
	}
	void lock_calls_audioqueue() { 
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_audioqueue, opt_lock_calls_usleep); 
		/*pthread_mutex_lock(&qaudiolock);*/
	}
	void lock_calls_charts_cache_queue() { 
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_charts_cache_queue, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&qaudiolock);*/
	}
	void lock_calls_deletequeue() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_deletequeue, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&qdellock);*/
	}
	void lock_registers_queue() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_registers_queue, opt_lock_calls_usleep);
	}
	void lock_registers_deletequeue() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_registers_deletequeue, opt_lock_calls_usleep);
	}
	void lock_files_queue() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_files_queue, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&flock);*/
	}
	void lock_calls_listMAP() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_listMAP, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&calls_listMAPlock);*/
	}
	void lock_calls_mergeMAP() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_mergeMAP, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&calls_mergeMAPlock);*/
	}
	void lock_calls_diameter_from_sip_listMAP() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_diameter_from_sip_listMAP, opt_lock_calls_usleep);
	}
	void lock_calls_diameter_to_sip_listMAP() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_calls_diameter_to_sip_listMAP, opt_lock_calls_usleep);
	}
	#if CONFERENCE_LEGS_MOD_WITHOUT_TABLE_CDR_CONFERENCE
	void lock_conference_calls_map() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_conference_calls_map, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&calls_listMAPlock);*/
	}
	#endif
	void lock_registers_listMAP() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_registers_listMAP, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&registers_listMAPlock);*/
	}
	void lock_skinny_maps() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_skinny_maps, opt_lock_calls_usleep);
		/*pthread_mutex_lock(&registers_listMAPlock);*/
	}
	void lock_ss7_listMAP() { 
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_ss7_listMAP, opt_lock_calls_usleep);
	}
	void lock_process_ss7_listmap() { 
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_process_ss7_listmap, opt_lock_calls_usleep);
	}
	void lock_process_ss7_queue() {
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_process_ss7_queue, opt_lock_calls_usleep);
	}
	void lock_hash_modify_queue() { 
		extern unsigned int opt_lock_calls_usleep;
		__SYNC_LOCK_USLEEP(this->_sync_lock_hash_modify_queue, opt_lock_calls_usleep);
	}

	/**
	 * @brief unlock calls_queue structure 
	 *
	*/
	void unlock_calls_queue() { __SYNC_UNLOCK(this->_sync_lock_calls_queue); /*pthread_mutex_unlock(&qlock);*/ }
	void unlock_calls_audioqueue() { __SYNC_UNLOCK(this->_sync_lock_calls_audioqueue); /*pthread_mutex_unlock(&qaudiolock);*/ }
	void unlock_calls_charts_cache_queue() { __SYNC_UNLOCK(this->_sync_lock_calls_charts_cache_queue); /*pthread_mutex_unlock(&qcharts_chache_lock);*/ }
	void unlock_calls_deletequeue() { __SYNC_UNLOCK(this->_sync_lock_calls_deletequeue); /*pthread_mutex_unlock(&qdellock);*/ }
	void unlock_registers_queue() { __SYNC_UNLOCK(this->_sync_lock_registers_queue); }
	void unlock_registers_deletequeue() { __SYNC_UNLOCK(this->_sync_lock_registers_deletequeue); }
	void unlock_files_queue() { __SYNC_UNLOCK(this->_sync_lock_files_queue); /*pthread_mutex_unlock(&flock);*/ }
	void unlock_calls_listMAP() { __SYNC_UNLOCK(this->_sync_lock_calls_listMAP); /*pthread_mutex_unlock(&calls_listMAPlock);*/ }
	void unlock_calls_mergeMAP() { __SYNC_UNLOCK(this->_sync_lock_calls_mergeMAP); /*pthread_mutex_unlock(&calls_mergeMAPlock);*/ }
	void unlock_calls_diameter_from_sip_listMAP() { __SYNC_UNLOCK(this->_sync_lock_calls_diameter_from_sip_listMAP); }
	void unlock_calls_diameter_to_sip_listMAP() { __SYNC_UNLOCK(this->_sync_lock_calls_diameter_to_sip_listMAP); }
	#if CONFERENCE_LEGS_MOD_WITHOUT_TABLE_CDR_CONFERENCE
	void unlock_conference_calls_map() { __SYNC_UNLOCK(this->_sync_lock_conference_calls_map); /*pthread_mutex_unlock(&calls_mergeMAPlock);*/ }
	#endif
	void unlock_registers_listMAP() { __SYNC_UNLOCK(this->_sync_lock_registers_listMAP); /*pthread_mutex_unlock(&registers_listMAPlock);*/ }
	void unlock_skinny_maps() { __SYNC_UNLOCK(this->_sync_lock_skinny_maps); }
	void unlock_ss7_listMAP() { __SYNC_UNLOCK(this->_sync_lock_ss7_listMAP); }
	void unlock_process_ss7_listmap() { __SYNC_UNLOCK(this->_sync_lock_process_ss7_listmap); }
	void unlock_process_ss7_queue() { __SYNC_UNLOCK(this->_sync_lock_process_ss7_queue); }
	void unlock_hash_modify_queue() { __SYNC_UNLOCK(this->_sync_lock_hash_modify_queue); }

	/**
	 * @brief add Call to Calltable
	 *
	 * @param call_id unique identifier of the Call which is parsed from the SIP packets
	 * @param call_id_len lenght of the call_id buffer
	 * @param time timestamp of arrivel packet in seconds from UNIX epoch
	 *
	 * @return reference of the new Call class
	*/
	Call *add(int call_type, char *call_id, unsigned long call_id_len, vector<string> *call_id_alternative,
		  u_int64_t time_us, vmIP saddr, vmPort port, 
		  pcap_t *handle, int dlt, int sensorId, int8_t ci = -1, map<string, Call*> *map_calls = NULL);
	Ss7 *add_ss7(packet_s_stack *packetS, Ss7::sParseData *data);
	Call *add_mgcp(sMgcpRequest *request, u_int64_t time_us, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport,
		       pcap_t *handle, int dlt, int sensorId);
	
	size_t getCountCalls();
	
	/**
	 * @brief find Call by call_id
	 *
	 * @param call_id unique identifier of the Call which is parsed from the SIP packets
	 * @param call_id_len lenght of the call_id buffer
	 *
	 * @return reference of the Call if found, otherwise return NULL
	*/
	Call *find_by_call_id(char *call_id, unsigned long call_id_len, vector<string> *call_id_alternative, time_t time) {
		extern char opt_call_id_alternative[256];
		Call *rslt_call = NULL;
		string call_idS = call_id_len ? string(call_id, call_id_len) : string(call_id);
		lock_calls_listMAP();
		map<string, Call*>::iterator callMAPIT = calls_listMAP.find(call_idS);
		if(opt_call_id_alternative[0]) {
			if(callMAPIT == calls_listMAP.end() && call_id_alternative) {
				for(unsigned i = 0; i < call_id_alternative->size(); i++) {
					callMAPIT = calls_listMAP.find((*call_id_alternative)[i]);
					if(callMAPIT != calls_listMAP.end()) {
						break;
					}
				}
			}
		}
		if(callMAPIT != calls_listMAP.end()) {
			rslt_call = callMAPIT->second;
			if(opt_call_id_alternative[0]) {
				rslt_call->call_id_alternative_lock();
				if(call_idS != rslt_call->call_id) {
					calls_listMAP[call_idS] = rslt_call;
					(*rslt_call->call_id_alternative)[call_idS] = true;
				}
				if(call_id_alternative) {
					for(unsigned i = 0; i < call_id_alternative->size(); i++) {
						if((*call_id_alternative)[i] != rslt_call->call_id) {
							calls_listMAP[(*call_id_alternative)[i]] = rslt_call;
							(*rslt_call->call_id_alternative)[(*call_id_alternative)[i]] = true;
						}
					}
				}
				rslt_call->call_id_alternative_unlock();
			}
			#if not PROCESS_PACKETS_INDIC_MOD_1
			if(time && !rslt_call->stopProcessing) {
				__SYNC_INC(rslt_call->in_preprocess_queue_before_process_packet);
				#if DEBUG_PREPROCESS_QUEUE
					cout << " *** ++ in_preprocess_queue_before_process_packet (1) : "
					     << rslt_call->call_id << " : "
					     << rslt_call->in_preprocess_queue_before_process_packet << endl;
				#endif
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
			#endif
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_call_id_simple(char *call_id, unsigned long call_id_len, time_t time) {
		Call *rslt_call = NULL;
		string call_idS = call_id_len ? string(call_id, call_id_len) : string(call_id);
		map<string, Call*>::iterator callMAPIT = calls_listMAP.find(call_idS);
		if(callMAPIT != calls_listMAP.end()) {
			rslt_call = callMAPIT->second;
			#if not PROCESS_PACKETS_INDIC_MOD_1
			if(time && !rslt_call->stopProcessing) {
				__SYNC_INC(rslt_call->in_preprocess_queue_before_process_packet);
				#if DEBUG_PREPROCESS_QUEUE
					cout << " *** ++ in_preprocess_queue_before_process_packet (1) : "
					     << rslt_call->call_id << " : "
					     << rslt_call->in_preprocess_queue_before_process_packet << endl;
				#endif
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
			#endif
		}
		return(rslt_call);
	}
	Call *find_by_call_id_alter_map(char *call_id, unsigned long call_id_len, time_t time, map<string, Call*> *map_calls) {
		Call *rslt_call = NULL;
		string call_idS = call_id_len ? string(call_id, call_id_len) : string(call_id);
		map<string, Call*>::iterator callMAPIT = map_calls->find(call_idS);
		if(callMAPIT != map_calls->end()) {
			rslt_call = callMAPIT->second;
			#if not PROCESS_PACKETS_INDIC_MOD_1
			if(time && !rslt_call->stopProcessing) {
				__SYNC_INC(rslt_call->in_preprocess_queue_before_process_packet);
				#if DEBUG_PREPROCESS_QUEUE
					cout << " *** ++ in_preprocess_queue_before_process_packet (1) : "
					     << rslt_call->call_id << " : "
					     << rslt_call->in_preprocess_queue_before_process_packet << endl;
				#endif
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
			#endif
		}
		return(rslt_call);
	}
	Call *find_by_stream_callid(vmIP sip, vmPort sport, vmIP dip, vmPort dport, const char *callid) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		map<sStreamIds2, Call*>::iterator callMAPIT = calls_by_stream_callid_listMAP.find(sStreamIds2(sip, sport, dip, dport, callid, true));
		if(callMAPIT != calls_by_stream_callid_listMAP.end()) {
			rslt_call = callMAPIT->second;
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_stream_id2(vmIP sip, vmPort sport, vmIP dip, vmPort dport, u_int64_t id) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		map<sStreamId2, Call*>::iterator callMAPIT = calls_by_stream_id2_listMAP.find(sStreamId2(sip, sport, dip, dport, id, true));
		if(callMAPIT != calls_by_stream_id2_listMAP.end()) {
			rslt_call = callMAPIT->second;
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_stream(vmIP sip, vmPort sport, vmIP dip, vmPort dport) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		map<sStreamId, Call*>::iterator callMAPIT = calls_by_stream_listMAP.find(sStreamId(sip, sport, dip, dport, true));
		if(callMAPIT != calls_by_stream_listMAP.end()) {
			rslt_call = callMAPIT->second;
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_mergecall_id(char *call_id, unsigned long call_id_len, time_t time) {
		Call *rslt_call = NULL;
		string call_idS = call_id_len ? string(call_id, call_id_len) : string(call_id);
		lock_calls_listMAP();
		lock_calls_mergeMAP();
		map<string, Call*>::iterator mergeMAPIT = calls_mergeMAP.find(call_idS);
		if(mergeMAPIT != calls_mergeMAP.end()) {
			rslt_call = mergeMAPIT->second;
			#if not PROCESS_PACKETS_INDIC_MOD_1
			if(time) {
				__SYNC_INC(rslt_call->in_preprocess_queue_before_process_packet);
				#if DEBUG_PREPROCESS_QUEUE
					cout << " *** ++ in_preprocess_queue_before_process_packet (3) : "
					     << rslt_call->call_id << " : "
					     << rslt_call->in_preprocess_queue_before_process_packet << endl;
				#endif
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
			#endif
		}
		unlock_calls_mergeMAP();
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_register_id(char *register_id, unsigned long register_id_len) {
		Call *rslt_register = NULL;
		string register_idS = register_id_len ? string(register_id, register_id_len) : string(register_id);
		lock_registers_listMAP();
		map<string, Call*>::iterator registerMAPIT = registers_listMAP.find(register_idS);
		if(registerMAPIT != registers_listMAP.end()) {
			rslt_register = registerMAPIT->second;
		}
		unlock_registers_listMAP();
		return(rslt_register);
	}
	Call *find_by_reference(long long callreference, bool lock) {
		Call *rslt_call = NULL;
		if(lock) lock_calls_listMAP();
		extern char opt_call_id_alternative[256];
		if(opt_call_id_alternative[0]) {
			for(list<Call*>::iterator iter = calls_list.begin(); iter != calls_list.end(); iter++) {
				if((long long)*iter == callreference) {
					rslt_call = *iter;
					break;
				}
			}
		} else {
			for(map<string, Call*>::iterator iter = calls_listMAP.begin(); iter != calls_listMAP.end(); iter++) {
				if((long long)(iter->second) == callreference) {
					rslt_call = iter->second;
					break;
				}
			}
		}
		if(lock) unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_skinny_partyid(unsigned int partyid) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		lock_skinny_maps();
		map<unsigned int, Call*>::iterator skinny_partyIDIT = skinny_partyID.find(partyid);
		if(skinny_partyIDIT != skinny_partyID.end()) {
			rslt_call = skinny_partyIDIT->second;
		}
		unlock_skinny_maps();
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_skinny_ipTuples(vmIP saddr, vmIP daddr) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		lock_skinny_maps();
		d_item<vmIP> ip2;
		ip2.items[0] = min(saddr, daddr);
		ip2.items[1] = max(saddr, daddr);
		map<d_item<vmIP>, Call*>::iterator skinny_ipTuplesIT = skinny_ipTuples.find(ip2);
		if(skinny_ipTuplesIT != skinny_ipTuples.end()) {
			rslt_call = skinny_ipTuplesIT->second;
		}
		unlock_skinny_maps();
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_diameter_from_sip(const char *from_sip) {
		Call *rslt_call = NULL;
		lock_calls_diameter_from_sip_listMAP();
		map<string, Call*>::iterator iter = calls_diameter_from_sip_listMAP.find(from_sip);
		if(iter != calls_diameter_from_sip_listMAP.end()) {
			rslt_call = iter->second;
		}
		unlock_calls_diameter_from_sip_listMAP();
		return(rslt_call);
	}
	Call *find_by_diameter_to_sip(const char *to_sip) {
		Call *rslt_call = NULL;
		lock_calls_diameter_to_sip_listMAP();
		map<string, Call*>::iterator iter = calls_diameter_to_sip_listMAP.find(to_sip);
		if(iter != calls_diameter_to_sip_listMAP.end()) {
			rslt_call = iter->second;
		}
		unlock_calls_diameter_to_sip_listMAP();
		return(rslt_call);
	}
	Ss7 *find_by_ss7_id(string *ss7_id) {
		Ss7 *rslt_ss7 = NULL;
		lock_ss7_listMAP();
		map<string, Ss7*>::iterator ss7MAPIT = ss7_listMAP.find(*ss7_id);
		if(ss7MAPIT != ss7_listMAP.end()) {
			rslt_ss7 = ss7MAPIT->second;
		}
		unlock_ss7_listMAP();
		return(rslt_ss7);
	}

	/**
	 * @brief Save inactive calls to MySQL and delete it from list
	 *
	 *
	 * walk this list of Calls and if any of the call is inactive more
	 * than 5 minutes, save it to MySQL and delete it from the list
	 *
	 * @param currtime current time
	 *
	 * @return reference of the Call if found, otherwise return NULL
	*/
	int cleanup_calls(bool closeAll, u_int32_t packet_time_s = 0, const char *file = NULL, int line = 0);
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	void cleanup_calls_separate_processing_rtp();
	#endif
	int cleanup_registers(bool closeAll, u_int32_t packet_time_s = 0);
	int cleanup_ss7(bool closeAll, u_int32_t packet_time_s = 0);

	/**
	 * @brief add call to hash table
	 *
	*/
	void hashAdd(vmIP addr, vmPort port, u_int64_t time_us, CallBranch *c_branch, int iscaller, int isrtcp, s_sdp_flags sdp_flags);
	inline void _hashAdd(vmIP addr, vmPort port, long int time_s, CallBranch *c_branch, int iscaller, int isrtcp, s_sdp_flags sdp_flags, bool use_lock = true);
	void _hashAddExt(vmIP addr, vmPort port, long int time_s, CallBranch *c_branch, int iscaller, int isrtcp, s_sdp_flags sdp_flags, bool use_lock = true);

	/**
	 * @brief find call
	 *
	*/
	inline node_call_rtp *hashfind_by_ip_port(vmIP addr, vmPort port, bool lock = true) {
		node_call_rtp *rslt = NULL;
		#if NEW_RTP_FIND__NODES
			if(lock) {
				lock_calls_hash();
			}
			node_call_rtp_ports *ports;
			if(addr.is_v6()) {
				ports = calls_ipv6_port->find((u_char*)addr.getPointerToIP(), 16
							      #if NEW_RTP_FIND__NODES__PORT_MODE == 1
							      ,(u_char*)&port.port + 1, 1
							      #endif
							      );
			} else {
				ports = calls_ip_port->find((u_char*)addr.getPointerToIP(), 4
							    #if NEW_RTP_FIND__NODES__PORT_MODE == 1
							    ,(u_char*)&port.port + 1, 1
							    #endif
							    );
			}
			if(ports) {
				rslt = 
				       #if NEW_RTP_FIND__NODES__LIST
				       &
				       #endif
				       ports->ports[
						    #if NEW_RTP_FIND__NODES__PORT_MODE == 1
						    *((u_char*)&port.port + 0)
						    #else
						    port.port
						    #endif
						    ];
			}
			if(lock) {
				unlock_calls_hash();
			}
		#elif NEW_RTP_FIND__PORT_NODES
			if(lock) {
				lock_calls_hash();
			}
			if(addr.is_v6()) {
				rslt = (node_call_rtp*)calls_ipv6_port[port.port]._find((u_char*)addr.getPointerToIP(), 16);
			} else {
				rslt = (node_call_rtp*)calls_ip_port[port.port]._find((u_char*)addr.getPointerToIP(), 4);
			}
			if(lock) {
				unlock_calls_hash();
			}
		#elif NEW_RTP_FIND__MAP_LIST
			if(lock) {
				lock_calls_hash();
			}
			u_int64_t ip_port = addr.ip.v4.n;
			ip_port = (ip_port << 32) + port.port;
			map<u_int64_t, node_call_rtp*>::iterator iter = calls_ip_port.find(ip_port);
			if(iter != calls_ip_port.end()) {
				rslt = iter->second;
			}
			if(lock) {
				unlock_calls_hash();
			}
		#else
			u_int32_t h = tuplehash(addr.getHashNumber(), port);
			if(lock) {
				lock_calls_hash();
			}
			for(node_call_rtp_ip_port *node = calls_hash[h]; node != NULL; node = node->next) {
				if((node->port == port) && (node->addr == addr)) {
					rslt = 
					       #if HASH_RTP_FIND__LIST
					       &
					       #endif
					       node->calls;
					break;
				}
			}
			if(lock) {
				unlock_calls_hash();
			}
		#endif
		return rslt;
	}
	inline node_call_rtp *hashfind_by_ip_port(vmIP *addr, vmPort port, bool lock = true) {
		node_call_rtp *rslt = NULL;
		u_int32_t h = tuplehash(addr->getHashNumber(), port);
		if(lock) {
			lock_calls_hash();
		}
		for(node_call_rtp_ip_port *node = calls_hash[h]; node != NULL; node = node->next) {
			if((node->port == port) && (node->addr == *addr)) {
				rslt = 
				       #if HASH_RTP_FIND__LIST
				       &
				       #endif
				       node->calls;
				break;
			}
		}
		if(lock) {
			unlock_calls_hash();
		}
		return rslt;
	}
	inline node_call_rtp *hashfind_by_ip_port(u_int32_t h, vmIP *addr, vmPort port, bool lock = true) {
		node_call_rtp *rslt = NULL;
		if(lock) {
			lock_calls_hash();
		}
		for(node_call_rtp_ip_port *node = calls_hash[h]; node != NULL; node = node->next) {
			if((node->port == port) && (node->addr == *addr)) {
				rslt = 
				       #if HASH_RTP_FIND__LIST
				       &
				       #endif
				       node->calls;
				break;
			}
		}
		if(lock) {
			unlock_calls_hash();
		}
		return rslt;
	}
	inline bool check_call_in_hashfind_by_ip_port(Call *call, CallBranch *c_branch, vmIP addr, vmPort port, bool lock = true) {
		bool rslt = false;
		if(lock) {
			lock_calls_hash();
		}
		node_call_rtp *n_call = this->hashfind_by_ip_port(addr, port, false);
		if(n_call) {
			#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
			for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end(); iter++) {
				if((*iter)->call == call) {
					rslt = true;
					break;
				}
			}
			#else
			if(n_call) {
				for(; n_call; n_call = n_call->next) {
					if(n_call->c_branch == c_branch) {
						rslt = true;
						break;
					}
				}
			}
			#endif
		}
		if(lock) {
			unlock_calls_hash();
		}
		return rslt;
	}
	inline s_sdp_flags *get_sdp_flags_in_hashfind_by_ip_port(Call *call, CallBranch *c_branch, vmIP addr, vmPort port, bool lock = true) {
		s_sdp_flags *sdp_flags = NULL;
		if(lock) {
			lock_calls_hash();
		}
		node_call_rtp *n_call = this->hashfind_by_ip_port(addr, port, false);
		if(n_call) {
			#if (NEW_RTP_FIND__NODES && NEW_RTP_FIND__NODES__LIST) || HASH_RTP_FIND__LIST || NEW_RTP_FIND__MAP_LIST
			for(list<call_rtp*>::iterator iter = n_call->begin(); iter != n_call->end(); iter++) {
				if((*iter)->call == call) {
					sdp_flags = &(*iter)->sdp_flags;
					break;
				}
			}
			#else
			if(n_call) {
				for(; n_call; n_call = n_call->next) {
					if(n_call->c_branch == c_branch) {
						sdp_flags = &n_call->sdp_flags;
						break;
					}
				}
			}
			#endif
		}
		if(lock) {
			unlock_calls_hash();
		}
		return sdp_flags;
	}

	/**
	 * @brief remove call from hash
	 *
	*/
	void hashRemove(CallBranch *c_branch, vmIP addr, vmPort port, bool rtcp = false, bool ignore_rtcp_check = false, bool useHashQueueCounter = true);
	inline int _hashRemove(CallBranch *c_branch, vmIP addr, vmPort port, bool rtcp = false, bool ignore_rtcp_check = false, bool use_lock = true);
	int _hashRemoveExt(CallBranch *c_branch, vmIP addr, vmPort port, bool rtcp = false, bool ignore_rtcp_check = false, bool use_lock = true);
	int hashRemove(CallBranch *c_branch, bool useHashQueueCounter = true);
	int hashRemoveForce(CallBranch *c_branch);
	inline int _hashRemove(CallBranch *c_branch, bool use_lock = true);
	void applyHashModifyQueue(bool setBegin, bool use_lock_calls_hash = true);
	inline void _applyHashModifyQueue(bool setBegin, bool use_lock_calls_hash = true);
	string getHashStats();
	
	void processCallsInAudioQueue(bool lock = true);
	static void *processAudioQueueThread(void *);
	size_t getCountActiveAudioQueueThreads(bool lock = true);
	void setAudioQueueTerminating() {
		audioQueueTerminating = 1;
	}
	
	void processCallsInChartsCache_start();
	void processCallsInChartsCache_stop();
	void processCallsInChartsCache_thread(int threadIndex);
	static void *_processCallsInChartsCache_thread(void *_threadIndex);
	void processCallsInChartsCache_thread_add();
	void processCallsInChartsCache_thread_remove();
	string processCallsInChartsCache_cpuUsagePerc(double *avg, int pstatDataIndex);

	void destroyCallsIfPcapsClosed();
	void destroyRegistersIfPcapsClosed();
	
	void mgcpCleanupTransactions(Call *call);
	void mgcpCleanupStream(Call *call);
	
	string getCallTableJson(char *params, bool *zip = NULL);
	
	void lock_calls_hash() {
		extern unsigned int opt_lock_calls_hash_usleep;
		unsigned int usleepCounter = 0;
		__SYNC_LOCK_WHILE(this->_sync_lock_calls_hash) {
			if(opt_lock_calls_hash_usleep) {
				USLEEP_C(opt_lock_calls_hash_usleep, usleepCounter++);
			} else {
				__ASM_PAUSE;
			}
		}
	}
	void unlock_calls_hash() {
		__SYNC_UNLOCK(this->_sync_lock_calls_hash);
	}
	
	void addSystemCommand(const char *command);
	
	unsigned int getAudioQueueThreadsMax() {
		return(audioQueueThreadsMax);
	}
	
private:
	/*
	pthread_mutex_t qlock;		//!< mutex locking calls_queue
	pthread_mutex_t qaudiolock;	//!< mutex locking calls_audioqueue
	pthread_mutex_t qcharts_chache_lock;
	pthread_mutex_t qdellock;	//!< mutex locking calls_deletequeue
	pthread_mutex_t flock;		//!< mutex locking calls_queue
	pthread_mutex_t calls_listMAPlock;
	pthread_mutex_t calls_mergeMAPlock;
	pthread_mutex_t registers_listMAPlock;
	*/

	#if NEW_RTP_FIND__NODES
	cNodeData<node_call_rtp_ports> *calls_ip_port;
	cNodeData<node_call_rtp_ports> *calls_ipv6_port;
	#elif NEW_RTP_FIND__PORT_NODES
	cNodeData<node_call_rtp> calls_ip_port[65536];
	cNodeData<node_call_rtp> calls_ipv6_port[65536];
	#elif NEW_RTP_FIND__MAP_LIST
	map<u_int64_t, node_call_rtp*> calls_ip_port;
	#else
	node_call_rtp_ip_port **calls_hash;
	#endif
	volatile int _sync_lock_calls_hash;
	volatile int _sync_lock_calls_listMAP;
	volatile int _sync_lock_calls_mergeMAP;
	volatile int _sync_lock_calls_diameter_from_sip_listMAP;
	volatile int _sync_lock_calls_diameter_to_sip_listMAP;
	#if CONFERENCE_LEGS_MOD_WITHOUT_TABLE_CDR_CONFERENCE
	volatile int _sync_lock_conference_calls_map;
	#endif
	volatile int _sync_lock_registers_listMAP;
	volatile int _sync_lock_calls_queue;
	volatile int _sync_lock_calls_audioqueue;
	volatile int _sync_lock_calls_charts_cache_queue;
	volatile int _sync_lock_calls_deletequeue;
	volatile int _sync_lock_registers_queue;
	volatile int _sync_lock_registers_deletequeue;
	volatile int _sync_lock_skinny_maps;
	volatile int _sync_lock_files_queue;
	volatile int _sync_lock_ss7_listMAP;
	volatile int _sync_lock_process_ss7_listmap;
	volatile int _sync_lock_process_ss7_queue;
	
	vector<sAudioQueueThread*> audioQueueThreads;
	unsigned int audioQueueThreadsMax;
	int audioQueueTerminating;
	
	cSqlDbCodebook *cb_ua;
	cSqlDbCodebook *cb_sip_response;
	cSqlDbCodebook *cb_sip_request;
	cSqlDbCodebook *cb_reason_sip;
	cSqlDbCodebook *cb_reason_q850;
	cSqlDbCodebook *cb_contenttype;
	cSqlDbCodebooks *cb;
	
	class AsyncSystemCommand *asyncSystemCommand;
	
	list<sHashModifyData> hash_modify_queue;
	u_int64_t hash_modify_queue_begin_ms;
	volatile int _sync_lock_hash_modify_queue;
	
	sChcThreadData *chc_threads;
	volatile int chc_threads_count;
	volatile int chc_threads_count_mod;
	volatile int chc_threads_count_mod_request;
	volatile int chc_threads_count_sync;
	unsigned chc_threads_count_last_change;
	
	Call **active_calls_cache;
	u_int32_t active_calls_cache_size;
	u_int32_t active_calls_cache_count;
	u_int64_t active_calls_cache_fill_at_ms;
	map<string, d_item2<u_int32_t, string> > active_calls_cache_map;
	volatile int active_calls_cache_sync;
};


class CustomHeaders {
public:
	enum eType {
		cdr,
		message,
		sip_msg
	};
	enum eSpecialType {
		st_na,
		max_length_sip_data,
		max_length_sip_packet,
		gsm_dcs,
		gsm_voicemail,
		max_retransmission_invite,
		digest_username
	};
	enum eReqRespDirection {
		dir_na,
		dir_request  = 1,
		dir_response = 2,
		dir_both     = 3
	};
	enum eSelectOccurence {
		so_sensor_setting = 0,
		so_first_value = 1,
		so_last_value = 2
	};
	struct sCustomHeaderData {
		sCustomHeaderData() {
			specialType = st_na;
			doNotAddColon = false;
			db_id = 0;
			screenPopupField = false;
			reqRespDirection = dir_na;
			useLastValue = false;
			allowMissingHeader = false;
		}
		inline string first_header() {
			return(header.size() ? header[0] : "");
		}
		inline string first_header_find() {
			return(header_find.size() ? header_find[0] : "");
		}
		void setHeaderFindSuffix() {
			for(unsigned i = 0; i < header_find.size(); i++) {
				if(header_find[i][header_find[i].length() - 1] != ':' &&
				   header_find[i][header_find[i].length() - 1] != '=' &&
				   strcasecmp(header_find[i].c_str(), "invite")) {
					header_find[i].append(":");
				}
			}
		}
		string dump(const char *prefix);
		eSpecialType specialType;
		vector<string> header;
		vector<string> header_find;
		string name;
		bool doNotAddColon;
		unsigned db_id;
		string leftBorder;
		string rightBorder;
		string regularExpression;
		string regularExpressionReplacePattern;
		bool screenPopupField;
		eReqRespDirection reqRespDirection;
		bool useLastValue;
		bool allowMissingHeader;
		std::vector<int> cseqMethod;
		std::vector<pair<int, int> > sipResponseCodeInfo;
	};
	struct sCustomHeaderDataPlus : public sCustomHeaderData {
		string type;
		int dynamic_table;
		int dynamic_column;
	};
	typedef map<int, map<int, dstring> > tCH_Content;
public:
	CustomHeaders(eType type, SqlDb *sqlDb = NULL);
	void load(SqlDb *sqlDb = NULL, bool enableCreatePartitions = true, bool lock = true);
	void clear(bool lock = true);
	void refresh(SqlDb *sqlDb = NULL, bool enableCreatePartitions = true);
	void prepareCustomNodes(ParsePacket *parsePacket);
	void parse(Call *call, int type, tCH_Content *ch_content, packet_s_process *packetS, eReqRespDirection reqRespDirection = dir_na);
	void setCustomHeaderContent(Call *call, int type, tCH_Content *ch_content, int pos1, int pos2, dstring *content, bool useLastValue);
	void prepareSaveRows(Call *call, int type, tCH_Content *ch_content, u_int64_t time_us, class SqlDb_row *cdr_next, class SqlDb_row cdr_next_ch[], char *cdr_next_ch_name[]);
	string getScreenPopupFieldsString(Call *call, int type);
	string getDeleteQuery(const char *id, const char *prefix, const char *suffix);
	list<string> getAllNextTables() {
		return(allNextTables);
	}
	list<string> *getAllNextTablesPointer() {
		return(&allNextTables);
	}
	void createMysqlPartitions(class SqlDb *sqlDb);
	void createMysqlPartitions(class SqlDb *sqlDb, char type, int next_day);
	void createMysqlPartitions(class SqlDb *sqlDb, const char *tableName, char type, int next_day);
	inline unsigned long getLoadTime() {
		return(loadTime);
	}
	string getQueryForSaveUseInfo(Call *call, int type, tCH_Content *ch_content);
	string getQueryForSaveUseInfo(u_int64_t time_us, tCH_Content *ch_content);
	void createTablesIfNotExists(SqlDb *sqlDb = NULL, bool enableOldPartition = false);
	void createTableIfNotExists(const char *tableName, SqlDb *sqlDb = NULL, bool enableOldPartition = false);
	void checkTablesColumns(SqlDb *sqlDb = NULL, bool checkColumnsSilentLog = false);
	void checkTableColumns(const char *tableName, int tableIndex, SqlDb *sqlDb = NULL, bool checkColumnsSilentLog = false);
	void createColumnsForFixedHeaders(SqlDb *sqlDb = NULL);
	bool getPosForDbId(unsigned db_id, d_u_int32_t *pos);
	static tCH_Content *getCustomHeadersCallContent(Call *call, int type);
	void getHeaders(list<string> *rslt);
	void getValues(Call *call, int type, list<string> *rslt);
	void getHeaderValues(Call *call, int type, map<string, string> *rslt);
	void getNameValues(Call *call, int type, map<string, string> *rslt);
	string getValue(Call *call, int type, const char *header);
	static string tCH_Content_value(tCH_Content *ch_content, int i1, int i2);
	unsigned getSize();
	int getCustomHeaderMaxSize();
	string dump();
private:
	void lock_custom_headers() {
		__SYNC_LOCK(this->_sync_custom_headers);
	}
	void unlock_custom_headers() {
		__SYNC_UNLOCK(this->_sync_custom_headers);
	}
private:
	eType type;
	string configTable;
	string mainTable;
	string nextTablePrefix;
	string fixedTable;
	string relIdColumn;
	string relTimeColumn;
	map<int, map<int, sCustomHeaderData> > custom_headers;
	list<string> allNextTables;
	map<int, bool> calldate_ms;
	unsigned long loadTime;
	unsigned lastTimeSaveUseInfo;
	volatile int _sync_custom_headers;
};


class NoHashMessageRule {
public:
	NoHashMessageRule();
	~NoHashMessageRule();
	bool checkNoHash(Call *call);
	void load(const char *name, 
		  unsigned customHeader_db_id, const char *customHeader, 
		  const char *header_regexp, const char *content_regexp);
	void clean_list_regexp();
private:
	string name;
	unsigned customHeader_db_id;
	string customHeader_name;
	d_u_int32_t customHeader_pos;
	bool customHeader_ok;
	list<cRegExp*> header_regexp;
	list<cRegExp*> content_regexp;
};

class NoHashMessageRules {
public:
	NoHashMessageRules(SqlDb *sqlDb = NULL);
	~NoHashMessageRules();
	bool checkNoHash(Call *call);
	void load(SqlDb *sqlDb = NULL, bool lock = true);
	void clear(bool lock = true);
	void refresh(SqlDb *sqlDb = NULL);
private:
	void lock_no_hash() {
		__SYNC_LOCK(this->_sync_no_hash);
	}
	void unlock_no_hash() {
		__SYNC_UNLOCK(this->_sync_no_hash);
	}
private:
	list<NoHashMessageRule*> rules;
	unsigned int loadTime;
	volatile int _sync_no_hash;
};


class NoStoreCdrRule {
public:
	NoStoreCdrRule();
	~NoStoreCdrRule();
	bool check(Call *call, CallBranch *c_branch);
	void set(const char*);
	bool isSet();
private:
	bool check_number(const char *number);
	bool check_name(const char *name);
	bool check_lsr(const char *lsr);
private:
	int lastResponseNum;
	int lastResponseNumLength;
	vmIP ip;
	unsigned ip_mask_length;
	string number;
	CheckString *number_check;
	cRegExp *number_regexp;
	string name;
	CheckString *name_check;
	cRegExp *name_regexp;
	string lsr;
	CheckString *lsr_check;
	cRegExp *lsr_regexp;
};

class NoStoreCdrRules {
public:
	~NoStoreCdrRules();
	bool check(Call *call, CallBranch *c_branch);
	void set(const char*);
	bool isSet();
private:
	list<NoStoreCdrRule*> rules;
};


class AsyncSystemCommand {
public:
	AsyncSystemCommand();
	~AsyncSystemCommand();
	void stopPopSystemCommandThread();
	void addSystemCommand(const char *command);
private:
	void initPopSystemCommandThread();
	void popSystemCommandThread();
	static void *popSystemCommandThread(void *arg);
private:
	SafeAsyncQueue<string> systemCommandQueue;
	pthread_t threadPopSystemCommand;
	volatile bool termPopSystemCommand;
};


int sip_request_name_to_int(const char *requestName, bool withResponse = false);
const char *sip_request_int_to_name(int requestCode, bool withResponse = false);

string printCallFlags(unsigned long int flags);
eCallField convCallFieldToFieldId(const char *field);
int convCallFieldToFieldIndex(eCallField field);
int convCallFieldToFieldIndex(const char *field);

void reset_counters();


#if DEBUG_ASYNC_TAR_WRITE
class cDestroyCallsInfo {
public:
	struct sCallInfo {
		sCallInfo(Call *call) {
			pointer_to_call = call;
			fbasename = call->fbasename;
			destroy_time = getTimeUS();
			tid = get_unix_tid();
			chunk_buffers_count = call->getChunkBuffersCount();
			dump_sip_state = call->getPcapSip()->getState();
			for(unsigned i = 0; i < P_FLAGS_IMAX; i++) {
				p_flags_count[i] = call->p_flags_count[i];
				memcpy(p_flags[i], call->p_flags[i], P_FLAGS_MAX);
			}
		}
		void *pointer_to_call;
		string fbasename;
		u_int64_t destroy_time;
		u_int32_t tid;
		u_int16_t chunk_buffers_count;
		u_int16_t dump_sip_state;
		u_char p_flags[P_FLAGS_IMAX][P_FLAGS_MAX];
		u_char p_flags_count[P_FLAGS_IMAX];
	};
public:
	cDestroyCallsInfo(unsigned limit) {
		this->limit = limit;
		_sync = 0;
	}
	~cDestroyCallsInfo();
	void add(Call *call);
	string find(string fbasename, int index = 0);
private:
	void lock() {
		__SYNC_LOCK(_sync);
	}
	void unlock() {
		__SYNC_UNLOCK(_sync);
	}
private:
	unsigned limit;
	deque<sCallInfo*> queue;
	map<string, sCallInfo*> q_map;
	volatile int _sync;
};
#endif


#endif
