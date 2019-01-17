/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/* Calls are stored into indexed array. 
 * Into one calltable is stored SIP call-id and IP-port of SDP session
 */

#ifndef CALLTABLE_H
#define CALLTABLE_H

#include <queue>
#include <map>
#include <list>
#include <set>

#include <arpa/inet.h>
#include <time.h>
#include <limits.h>

#include <pcap.h>

#include <string>

#include "mgcp.h"
#include "rtp.h"
#include "tools.h"
#include "sql_db.h"
#include "voipmonitor.h"
#include "tools_fifo_buffer.h"
#include "record_array.h"

#define MAX_IP_PER_CALL 40	//!< total maxumum of SDP sessions for one call-id
#define MAX_SSRC_PER_CALL 40	//!< total maxumum of SDP sessions for one call-id
#define MAX_FNAME 256		//!< max len of stored call-id
#define MAX_RTPMAP 40          //!< max rtpmap records
#define MAXNODE 150000
#define MAX_SIPCALLERDIP 8
#define MAXLEN_SDP_SESSID 30

#define INVITE 1
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

#define FLAG_SAVERTP		(1 << 0)
#define FLAG_SAVERTCP		(1 << 1)
#define FLAG_SAVESIP		(1 << 2)
#define FLAG_SAVEREGISTER	(1 << 3)
#define FLAG_SAVEAUDIO		(1 << 4)
#define FLAG_FORMATAUDIO_WAV	(1 << 5)
#define FLAG_FORMATAUDIO_OGG	(1 << 6)
#define FLAG_SAVEAUDIO_WAV	(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_WAV)
#define FLAG_SAVEAUDIO_OGG	(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_OGG)
#define FLAG_SAVEGRAPH		(1 << 7)
#define FLAG_SAVERTPHEADER	(1 << 8)
#define FLAG_SKIPCDR		(1 << 9)
#define FLAG_RUNSCRIPT		(1 << 10)
#define FLAG_RUNAMOSLQO		(1 << 11)
#define FLAG_RUNBMOSLQO		(1 << 12)
#define FLAG_HIDEMESSAGE	(1 << 13)
#define FLAG_USE_SPOOL_2	(1 << 14)
#define FLAG_SAVEDTMF		(1 << 15)

#define CDR_NEXT_MAX 10

#define CDR_CHANGE_SRC_PORT_CALLER	(1 << 0)
#define CDR_CHANGE_SRC_PORT_CALLED	(1 << 1)
#define CDR_UNCONFIRMED_BYE		(1 << 2)
#define CDR_ALONE_UNCONFIRMED_BYE	(1 << 3)
#define CDR_SRTP_WITHOUT_KEY		(1 << 4)
#define CDR_FAS_DETECTED		(1 << 5)
#define CDR_ZEROSSRC_DETECTED		(1 << 6)
#define CDR_SIPALG_DETECTED		(1 << 7)

#define SS7_IAM 1
#define SS7_ACM 6
#define SS7_CPG 44
#define SS7_ANM 9
#define SS7_REL 12
#define SS7_RLC 16

#define NOFAX	0
#define T38FAX	1
#define T30FAX	2

#define iscaller_is_set(iscaller) (iscaller >= 0)
#define iscaller_index(iscaller) (iscaller > 0 ? 1 : 0)
#define iscaller_inv_index(iscaller) (iscaller > 0 ? 0 : 1)
#define iscaller_description(iscaller) (iscaller > 0 ? "caller" : (iscaller == 0 ? "called" : "unknown"))
#define iscaller_inv_description(iscaller) (iscaller > 0 ? "called" : (iscaller == 0 ? "caller" : "unknown"))

#define enable_save_dtmf	(flags & FLAG_SAVEDTMF)

struct s_dtmf {
	enum e_type {
		sip_info,
		inband,
		rfc2833
	};
	e_type type;
	double ts;
	char dtmf;
	unsigned int saddr;
	unsigned int daddr;
};

enum e_sdp_protocol {
	sdp_proto_na,
	sdp_proto_rtp,
	sdp_proto_srtp,
	sdp_proto_t38,
	sdp_proto_msrp,
	sdp_proto_sprt
};

struct s_sdp_flags {
	s_sdp_flags() {
		is_fax = 0;
		rtcp_mux = 0;
		protocol = sdp_proto_na;
	}
	int operator != (const s_sdp_flags &other) {
		return(is_fax != other.is_fax ||
		       rtcp_mux != other.rtcp_mux);
	}
	int8_t is_fax;
	int8_t rtcp_mux;
	int8_t protocol;
};

struct hash_node_call {
	hash_node_call *next;
	Call *call;
	int8_t iscaller;
	u_int16_t is_rtcp;
	s_sdp_flags sdp_flags;
};

struct hash_node {
	hash_node *next;
	hash_node_call *calls;
	u_int32_t addr;
	u_int16_t port;
};

struct ip_port_call_info_rtp {
	volatile u_int32_t saddr;
	volatile u_int16_t sport;
	volatile u_int32_t daddr;
	volatile u_int16_t dport;
	volatile time_t last_packet_time;
};

struct rtp_crypto_config {
	unsigned tag;
	string suite;
	string key;
	u_int64_t from_time_us;
};

struct ip_port_call_info {
	ip_port_call_info() {
		rtp_crypto_config_list = NULL;
		canceled = false;
		for(int i = 0; i < 2; i++) {
			callerd_confirm_sdp[i] = false;
		}
	}
	~ip_port_call_info() {
		if(rtp_crypto_config_list) {
			delete rtp_crypto_config_list;
		}
	}
	void setSdpCryptoList(list<rtp_crypto_config> *rtp_crypto_config_list, u_int64_t from_time_us) {
		if(rtp_crypto_config_list && rtp_crypto_config_list->size()) {
			if(!this->rtp_crypto_config_list) {
				this->rtp_crypto_config_list = new FILE_LINE(0) list<rtp_crypto_config>;
				for(list<rtp_crypto_config>::iterator iter = rtp_crypto_config_list->begin(); iter != rtp_crypto_config_list->end(); iter++) {
					iter->from_time_us = from_time_us;
					this->rtp_crypto_config_list->push_back(*iter);
				}
			} else {
				for(list<rtp_crypto_config>::iterator iter = rtp_crypto_config_list->begin(); iter != rtp_crypto_config_list->end(); iter++) {
					bool exists = false;
					for(list<rtp_crypto_config>::iterator iter2 = this->rtp_crypto_config_list->begin(); iter2 != this->rtp_crypto_config_list->end(); iter2++) {
						if(iter->suite == iter2->suite && iter->key == iter2->key) {
							exists = true;
							break;
						}
					}
					if(!exists) {
						iter->from_time_us = from_time_us;
						this->rtp_crypto_config_list->push_back(*iter);
					}
				}
			}
		}
	}
	enum eTypeAddr {
		_ta_base,
		_ta_natalias,
		_ta_sdp_reverse_ipport
	};
	u_int32_t addr;
	u_int8_t type_addr;
	u_int16_t port;
	int8_t iscaller;
	string sessid;
	list<rtp_crypto_config> *rtp_crypto_config_list;
	string to;
	string branch;
	u_int32_t sip_src_addr;
	s_sdp_flags sdp_flags;
	ip_port_call_info_rtp rtp[2];
	bool canceled;
	int8_t callerd_confirm_sdp[2];
};

struct raws_t {
	int ssrc_index;
	int rawiterator;
	int codec;
	int frame_size;
	struct timeval tv;
	string filename;
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
	cf_sipproxies,
	cf_lastSIPresponseNum,
	cf_rtp_src,
	cf_rtp_dst,
	cf_rtp_src_country,
	cf_rtp_dst_country,
	cf_callercodec,
	cf_calledcodec,
	cf_src_mosf1,
	cf_src_mosf2,
	cf_src_mosAD,
	cf_dst_mosf1,
	cf_dst_mosf2,
	cf_dst_mosAD,
	cf_src_jitter,
	cf_dst_jitter,
	cf_src_loss,
	cf_dst_loss,
	cf_src_loss_last10sec,
	cf_dst_loss_last10sec,
	cf_id_sensor,
	cf__max
};

struct sCallField {
	eCallField fieldType;
	const char *fieldName;
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

class Call_abstract {
public:
	Call_abstract(int call_type, time_t time);
	~Call_abstract() {
		alloc_flag = 0;
	}
	int getTypeBase() { return(type_base); }
	bool typeIs(int type) { return(type_base == type || (type_next && type_next == type)); }
	bool typeIsOnly(int type) { return(type_base == type && type_next == 0); }
	bool typeIsNot(int type) { return(!typeIs(type)); }
	bool addNextType(int type);
	int calltime() { return first_packet_time; };
	struct timeval *get_calltime(struct timeval *ts) {
		ts->tv_sec = first_packet_time;
		ts->tv_usec = 0;
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
	bool isEmptyChunkBuffersCount() {
		return(!chunkBuffersCount);
	}
	void incChunkBuffers() {
		__sync_add_and_fetch(&chunkBuffersCount, 1);
	}
	void decChunkBuffers() {
		__sync_sub_and_fetch(&chunkBuffersCount, 1);
	}
	void addTarPos(u_int64_t pos, int type);
	bool isAllocFlagOK() {
		return(alloc_flag);
	}
public:
	uint16_t alloc_flag;
	int type_base;
	int type_next;
	time_t first_packet_time;
	char fbasename[MAX_FNAME];
	char fbasename_safe[MAX_FNAME];
	u_int64_t fname_register;
	int useSensorId;
	int useDlt;
	pcap_t *useHandle;
	string force_spool_path;
	volatile unsigned int flags;
	void *user_data;
	int user_data_type;
protected:
	list<u_int64_t> tarPosSip;
	list<u_int64_t> tarPosRtp;
	list<u_int64_t> tarPosGraph;
private:
	volatile u_int16_t chunkBuffersCount;
};

/**
  * This class implements operations on call
*/
class Call : public Call_abstract {
public:
	struct sSipcalleRD_IP {
		sSipcalleRD_IP() {
			for(unsigned i = 0; i < MAX_SIPCALLERDIP; i++) {
				sipcallerip[i] = 0;
				sipcalledip[i] = 0;
				sipcalledip_mod = 0;
				sipcallerport[i] = 0;
				sipcalledport[i] = 0;
				sipcalledport_mod = 0;
			}
		}
		u_int32_t sipcallerip[MAX_SIPCALLERDIP];
		u_int32_t sipcalledip[MAX_SIPCALLERDIP];
		u_int32_t sipcalledip_mod;
		u_int16_t sipcallerport[MAX_SIPCALLERDIP];
		u_int16_t sipcalledport[MAX_SIPCALLERDIP];
		u_int16_t sipcalledport_mod;
	};
	struct sMergeLegInfo {
		sMergeLegInfo() {
			seenbye = false;
			seenbye_time_usec = 0;
			seenbyeandok = false;
			seenbyeandok_time_usec = 0;
			seencancelandok = false;
			seencancelandok_time_usec = 0;
		}
		bool seenbye;
		u_int64_t seenbye_time_usec;
		bool seenbyeandok;
		u_int64_t seenbyeandok_time_usec;
		bool seencancelandok;
		u_int64_t seencancelandok_time_usec;
	};
	struct sInviteSD_Addr {
		sInviteSD_Addr() {
			confirmed = false;
			counter = 0;
			counter_reverse = 0;
		}
		u_int32_t saddr;
		u_int32_t daddr;
		u_int16_t sport;
		u_int16_t dport;
		bool confirmed;
		unsigned counter;
		unsigned counter_reverse;
		string caller;
		string called;
		string called_invite;
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
		sSipHistory(u_int64_t time = 0,
			    const char *SIPrequest = NULL,
			    const char *SIPresponse = NULL, int SIPresponseNum = 0) {
			this->time = time;
			if(SIPrequest && SIPrequest[0]) {
				this->SIPrequest = SIPrequest;
			}
			if(SIPresponse && SIPresponse[0]) {
				this->SIPresponse = SIPresponse;
			}
			this->SIPresponseNum = SIPresponseNum;
		}
		u_int64_t time;
		string SIPrequest;
		string SIPresponse;
		int SIPresponseNum;
	};
	struct sRtcpXrDataItem {
		timeval tv;
		int16_t moslq;
		int16_t nlr;
	};
	struct sRtcpXrDataSsrc : public list<sRtcpXrDataItem> {
		void add(timeval tv, int16_t moslq, int16_t nlr) {
			sRtcpXrDataItem dataItem;
			dataItem.tv = tv;
			dataItem.moslq = moslq;
			dataItem.nlr = nlr;
			this->push_back(dataItem);
		}
	};
	struct sRtcpXrData : public map<u_int32_t, sRtcpXrDataSsrc> {
		void add(u_int32_t ssrc, timeval tv, int16_t moslq, int16_t nlr) {
			(*this)[ssrc].add(tv, moslq, nlr);
		}
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
				u_long actTimeMS = getTimeMS(ts);
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
		u_long last_ssrc_time_ms;
	};
public:
	bool is_ssl;			//!< call was decrypted
	RTP *rtp[MAX_SSRC_PER_CALL];		//!< array of RTP streams
	map<int, class RTPsecure*> rtp_secure_map;
	volatile int rtplock;
	unsigned long call_id_len;	//!< length of call-id 	
	string call_id;	//!< call-id from SIP session
	char callername[256];		//!< callerid name from SIP header
	char caller[256];		//!< From: xxx 
	char caller_domain[256];	//!< From: xxx 
	char called[256];		//!< To: xxx
	map<string, string> called_invite_branch_map;
	char called_domain[256];	//!< To: xxx
	char contact_num[64];		//!< 
	char contact_domain[128];	//!< 
	char digest_username[64];	//!< 
	char digest_realm[64];		//!< 
	int register_expires;	
	sCseq byecseq[2];		
	sCseq invitecseq;		
	list<sCseq> invitecseq_next;
	list<sCseq> invitecseq_in_dialog;
	sCseq messagecseq;
	sCseq registercseq;
	sCseq cancelcseq;		
	sCseq updatecseq;		
	char custom_header1[256];	//!< Custom SIP header
	char match_header[128];	//!< Custom SIP header
	bool seeninvite;		//!< true if we see SIP INVITE within the Call
	bool seeninviteok;			//!< true if we see SIP INVITE within the Call
	bool seenmessage;
	bool seenmessageok;
	bool seenbye;			//!< true if we see SIP BYE within the Call
	u_int64_t seenbye_time_usec;
	bool seenbyeandok;		//!< true if we see SIP OK TO BYE within the Call
	u_int64_t seenbyeandok_time_usec;
	bool seencancelandok;		//!< true if we see SIP OK TO CANCEL within the Call
	u_int64_t seencancelandok_time_usec;
	bool unconfirmed_bye;
	bool seenRES2XX;
	bool seenRES2XX_no_BYE;
	bool seenRES18X;
	bool sighup;			//!< true if call is saving during sighup
	char a_ua[1024];		//!< caller user agent 
	char b_ua[1024];		//!< callee user agent 
	RTPMAP rtpmap[MAX_IP_PER_CALL][MAX_RTPMAP]; //!< rtpmap for every rtp stream
	RTP tmprtp;			//!< temporary structure used to decode information from frame
	RTP *lastcallerrtp;		//!< last RTP stream from caller
	RTP *lastcalledrtp;		//!< last RTP stream from called
	u_int32_t saddr;		//!< source IP address of first INVITE
	unsigned short sport;		//!< source port of first INVITE
	u_int32_t daddr;
	unsigned short dport;
	int whohanged;			//!< who hanged up. 0 -> caller, 1-> callee, -1 -> unknown
	int recordstopped;		//!< flag holding if call was stopped to avoid double free
	int dtmfflag;			//!< used for holding dtmf states 
	unsigned int dtmfflag2[2];	//!< used for holding dtmf states 
	double lastdtmf_time;		//!< used for holding time of last dtmf

	string hold_times;		//!< used for record hold times
	bool hold_status;		//!< hold status var
	bool is_fas_detected;		//!< detected FAS (False Answer Supervision)
	bool is_zerossrc_detected;	//!< detected zero SSRC
	bool is_sipalg_detected;	//!< detected sip-alg

	int silencerecording;
	int recordingpausedby182;
	int msgcount;
	int regcount;
	int reg401count;
	int reg401count_distinct;
	u_int32_t reg401count_sipcallerip[MAX_SIPCALLERDIP];
	int reg403count;
	int reg403count_distinct;
	u_int32_t reg403count_sipcallerip[MAX_SIPCALLERDIP];
	int reg200count;
	int regstate;
	bool regresponse;
	timeval regrrdstart;		// time of first REGISTER
	int regrrddiff;			// RRD diff time REGISTER<->OK in [ms]- RFC6076
	uint64_t regsrcmac;		// mac if ether layer present in REGISTER
	volatile unsigned int rtppacketsinqueue;
	volatile int end_call_rtp;
	volatile int end_call_hash_removed;
	volatile int push_call_to_calls_queue;
	volatile int push_register_to_registers_queue;
	unsigned int ps_drop;
	unsigned int ps_ifdrop;
	vector<u_int64_t> forcemark_time;
	volatile int _forcemark_lock;
	int first_codec;
	bool	has_second_merged_leg;

	float a_mos_lqo;
	float b_mos_lqo;

	time_t progress_time;		//!< time in seconds of 18X response
	time_t first_rtp_time;		//!< time in seconds of first RTP packet
	unsigned int first_rtp_time_usec;
	time_t connect_time;		//!< time in seconds of 200 OK
	unsigned int connect_time_usec;
	time_t last_packet_time;	
	time_t last_rtp_a_packet_time;	
	time_t last_rtp_b_packet_time;	
	unsigned int first_packet_usec;
	time_t destroy_call_at;
	time_t destroy_call_at_bye;
	time_t destroy_call_at_bye_confirmed;
	std::queue <s_dtmf> dtmf_history;
	
	u_int64_t first_invite_time_usec;
	u_int64_t first_response_100_time_usec;
	u_int64_t first_response_xxx_time_usec;
	u_int64_t first_message_time_usec;
	u_int64_t first_response_200_time_usec;

	uint8_t	caller_sipdscp;
	uint8_t	called_sipdscp;

	int isfax;
	char seenudptl;
	bool exists_udptl_data;
	bool not_acceptable;

	void *rtp_cur[2];		//!< last RTP structure in direction 0 and 1 (iscaller = 1)
	void *rtp_prev[2];		//!< previouse RTP structure in direction 0 and 1 (iscaller = 1)

	u_int32_t sipcallerip[MAX_SIPCALLERDIP];	//!< SIP signalling source IP address
	u_int32_t sipcalledip[MAX_SIPCALLERDIP];	//!< SIP signalling destination IP address
	u_int32_t sipcalledip_mod;
	u_int16_t sipcallerport[MAX_SIPCALLERDIP];
	u_int16_t sipcalledport[MAX_SIPCALLERDIP];
	u_int16_t sipcalledport_mod;
	map<string, sSipcalleRD_IP> map_sipcallerdip;
	u_int32_t lastsipcallerip;
	bool sipcallerdip_reverse;
	
	list<sInviteSD_Addr> invite_sdaddr;
	list<sInviteSD_Addr> rinvite_sdaddr;

	char lastSIPresponse[128];
	int lastSIPresponseNum;
	list<sSipResponse> SIPresponse;
	list<sSipHistory> SIPhistory;
	bool new_invite_after_lsr487;
	bool cancel_lsr487;
	
	int reason_sip_cause;
	string reason_sip_text;
	int reason_q850_cause;
	string reason_q850_text;

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

	char oneway;
	char absolute_timeout_exceeded;
	char zombie_timeout_exceeded;
	char bye_timeout_exceeded;
	char rtp_timeout_exceeded;
	char sipwithoutrtp_timeout_exceeded;
	char oneway_timeout_exceeded;
	char force_terminate;
	char pcap_drop;
	unsigned int lastsrcip;
	unsigned int lastdstip;
	unsigned int lastsrcport;

	void *listening_worker_args;
	
	int ssrc_n;				//!< last index of rtp array
	int ipport_n;				//!< last index of addr and port array 

	RTP *lastraw[2];

	string geoposition;

	/* obsolete
	map<string, string> custom_headers;
	*/
	map<int, map<int, dstring> > custom_headers_content_cdr;
	map<int, map<int, dstring> > custom_headers_content_message;

	volatile int _proxies_lock;
	list<unsigned int> proxies;
	
	bool onInvite;
	bool onCall_2XX;
	bool onCall_18X;
	bool updateDstnumOnAnswer;
	bool updateDstnumFromMessage;
	
	bool force_close;

	unsigned int caller_silence;
	unsigned int called_silence;
	unsigned int caller_noise;
	unsigned int called_noise;
	unsigned int caller_lastsilence;
	unsigned int called_lastsilence;

	unsigned int caller_clipping_8k;
	unsigned int called_clipping_8k;
	
	int vlan;

	unsigned int lastcallerssrc;
	unsigned int lastcalledssrc;

	map<string, sMergeLegInfo> mergecalls;
	volatile int _mergecalls_lock;

	bool rtp_zeropackets_stored;
	
	sRtcpXrData rtcpXrData;
	
	unsigned last_udptl_seq;

	u_int32_t iscaller_consecutive[2];
	
	string mgcp_callid;
	list<u_int32_t> mgcp_transactions;
	map<u_int32_t, sMgcpRequest> mgcp_requests;
	map<u_int32_t, sMgcpResponse> mgcp_responses;
	time_t last_mgcp_connect_packet_time;
	
	/**
	 * constructor
	 *
	 * @param call_id unique identification of call parsed from packet
	 * @param call_id_len lenght of the call_id buffer
	 * @param time time of the first packet
	 * 
	*/
	Call(int call_type, char *call_id, unsigned long call_id_len, time_t time);

	/**
	 * destructor
	 * 
	*/
	~Call();

	int get_index_by_ip_port(in_addr_t addr, unsigned short port, bool use_sip_src_addr = false);
	int get_index_by_sessid_to(char *sessid, char *to, in_addr_t sip_src_addr, ip_port_call_info::eTypeAddr type_addr);
	int get_index_by_iscaller(int iscaller);
	
	bool is_multiple_to_branch();
	bool to_is_canceled(char *to);
	string get_to_not_canceled();

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
	bool read_rtp(struct packet_s *packetS, int iscaller, bool find_by_dest, bool stream_in_multiple_calls, char is_fax, char enable_save_packet, char *ifname = NULL);
	inline bool _read_rtp(struct packet_s *packetS, int iscaller, bool find_by_dest, bool stream_in_multiple_calls, char *ifname, bool *record_dtmf, bool *disable_save);
	inline void _save_rtp(packet_s *packetS, char is_fax, char enable_save_packet, bool record_dtmf, bool forceVirtualUdp = false);

	/**
	 * @brief read RTCP packet 
	 *
	 * Used for reading RTCP packet 
	 * 
	*/
	bool read_rtcp(struct packet_s *packetS, int iscaller, char enable_save_packet);
	
	void read_dtls(struct packet_s *packetS);

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
	int add_ip_port(in_addr_t sip_src_addr, in_addr_t addr, ip_port_call_info::eTypeAddr type_addr, unsigned short port, pcap_pkthdr *header, 
			char *sessid, list<rtp_crypto_config> *rtp_crypto_config_list, char *to, char *branch, int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags);
	
	bool refresh_data_ip_port(in_addr_t addr, unsigned short port, pcap_pkthdr *header, 
				  list<rtp_crypto_config> *rtp_crypto_config_list, int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags);
	
	void add_ip_port_hash(in_addr_t sip_src_addr, in_addr_t addr, ip_port_call_info::eTypeAddr type_addr, unsigned short port, pcap_pkthdr *header, 
			      char *sessid, list<rtp_crypto_config> *rtp_crypto_config_list, char *to, char *branch, int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags);

	void cancel_ip_port_hash(in_addr_t sip_src_addr, char *to, char *branch, struct timeval *ts);
	
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
	time_t get_last_packet_time() { return last_packet_time; };

	/**
	 * @brief get time of the last seen rtp packet which belongs to this call
	 *
	 * @return time of the last rtp packet in seconds from UNIX epoch
	*/
	time_t get_last_rtp_packet_time() { return max(last_rtp_a_packet_time, last_rtp_b_packet_time); };

	/**
	 * @brief set time of the last seen packet which belongs to this call
	 *
	 * this time is used for calculating lenght of the call
	 *
	*/
	void set_last_packet_time(time_t mtime) { if(mtime > last_packet_time) last_packet_time = mtime; };
	void set_last_mgcp_connect_packet_time(time_t mtime) { if(mtime > last_mgcp_connect_packet_time) last_mgcp_connect_packet_time = mtime; };

	/**
	 * @brief get first time of the the packet which belongs to this call
	 *
	 * this time is used as start of the call in CDR record
	 *
	 * @return time of the first packet in seconds from UNIX epoch
	*/
	time_t get_first_packet_time() { return first_packet_time; };

	/**
	 * @brief set first time of the the packet which belongs to this call
	 *
	*/
	void set_first_packet_time(time_t mtime, unsigned int usec) { first_packet_time = mtime; first_packet_usec = usec;};

	/**
	 * handle hold times
	 *
	*/
	void HandleHold(bool sdp_sendonly, bool sdp_sendrecv);
	/**
	 * @brief convert raw files to one WAV
	 *
	*/
	int convertRawToWav();
 
	/**
	 * @brief save call to database
	 *
	*/
	int saveToDb(bool enableBatchIfPossible = true);
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
	int duration() { return (typeIs(MGCP) ? last_mgcp_connect_packet_time : last_packet_time) - first_packet_time; };
	int connect_duration() { return(connect_time ? duration() - (connect_time - first_packet_time) : 0); };
	
	int duration_active() { return(getGlobalPacketTimeS() - first_packet_time); };
	int connect_duration_active() { return(connect_time ? duration_active() - (connect_time - first_packet_time) : 0); };
	
	/**
	 * @brief remove call from hash table
	 *
	*/
	void hashRemove(struct timeval *ts, bool useHashQueueCounter = false);
	
	void skinnyTablesRemove();
	
	void removeFindTables(struct timeval *ts, bool set_end_call = false, bool destroy = false);

	/**
	 * @brief remove all RTP 
	 *
	*/
	void removeRTP();

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

	void evProcessRtpStream(int index_ip_port, bool by_dest, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, time_t time) {
		if(index_ip_port < ipport_n) {
			if(!ip_port[index_ip_port].rtp[by_dest].saddr) {
				ip_port[index_ip_port].rtp[by_dest].saddr = saddr;
				ip_port[index_ip_port].rtp[by_dest].sport = sport;
				ip_port[index_ip_port].rtp[by_dest].daddr = daddr;
				ip_port[index_ip_port].rtp[by_dest].dport = dport;
				this->evStartRtpStream(index_ip_port, saddr, sport, daddr, dport, time);
			}
			ip_port[index_ip_port].rtp[by_dest].last_packet_time = time;
		}
	}
	void evDestroyIpPortRtpStream(int index_ip_port) {
		if(index_ip_port < ipport_n) {
			for(int i = 0; i < 2; i++) {
				if(ip_port[index_ip_port].rtp[i].saddr) {
					this->evEndRtpStream(index_ip_port, 
							     ip_port[index_ip_port].rtp[i].saddr,
							     ip_port[index_ip_port].rtp[i].sport,
							     ip_port[index_ip_port].rtp[i].daddr,
							     ip_port[index_ip_port].rtp[i].dport,
							     ip_port[index_ip_port].rtp[i].last_packet_time);
				}
			}
			this->nullIpPortInfoRtpStream(index_ip_port);
		}
	}
	void nullIpPortInfoRtpStream(int index_ip_port) {
		if(index_ip_port < ipport_n) {
			for(int i = 0; i < 2; i++) {
				ip_port[index_ip_port].rtp[i].saddr = 0;
				ip_port[index_ip_port].rtp[i].sport = 0;
				ip_port[index_ip_port].rtp[i].daddr = 0;
				ip_port[index_ip_port].rtp[i].dport = 0;
				ip_port[index_ip_port].rtp[i].last_packet_time = 0;
			}
		}
	}
	void evStartRtpStream(int index_ip_port, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, time_t time);
	void evEndRtpStream(int index_ip_port, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, time_t time);
	
	void addtocachequeue(string file);
	static void _addtocachequeue(string file);

	void addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, long long writeBytes);
	static void _addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, string dirnamesqlfiles, long long writeBytes, int spoolIndex);

	float mos_lqo(char *deg, int samplerate);

	void handle_dtmf(char dtmf, double dtmf_time, unsigned int saddr, unsigned int daddr, s_dtmf::e_type dtmf_type);
	
	void handle_dscp(struct iphdr2 *header_ip, bool iscaller);
	
	bool check_is_caller_called(const char *call_id, int sip_method, int cseq_method,
				    unsigned int saddr, unsigned int daddr, unsigned int sport, unsigned int dport,  
				    int *iscaller, int *iscalled = NULL, bool enableSetSipcallerdip = false);
	bool is_sipcaller(unsigned int saddr, unsigned int sport, unsigned int daddr, unsigned int dport);
	bool is_sipcalled(unsigned int daddr, unsigned int dport, unsigned int saddr, unsigned int sport);
	bool use_both_side_for_check_direction() {
		extern bool opt_both_side_for_check_direction;
		return(opt_both_side_for_check_direction);
	}
	bool use_port_for_check_direction(unsigned int /*addr*/) {
		return(true /*ip_is_localhost(htonl(addr))*/);
	}
	void check_reset_oneway(unsigned int saddr, unsigned int source) {
		if(lastsrcip != saddr ||
		   (lastsrcip == lastdstip &&
		    use_port_for_check_direction(saddr) && 
		    lastsrcport != source)) {
			oneway = 0;
		}
	}

	void dump();

	bool isFillRtpMap(int index) {
		for(int i = 0; i < MAX_RTPMAP; i++) {
			if(rtpmap[index][i].is_set()) {
				return(true);
			}
		}
		return(false);
	}

	int getFillRtpMapByCallerd(bool iscaller) {
		for(int i = ipport_n - 1; i >= 0; i--) {
			if(ip_port[i].iscaller == iscaller &&
			   isFillRtpMap(i)) {
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
		for(int i = 0; i < MAX_SSRC_PER_CALL; i++) {
			if(rtp[i] && !rtp[i]->graph.isClose()) {
				return(false);
			}
		}
		return(true);
	}
	bool isReadyForWriteCdr() {
		return(isPcapsClose() && isGraphsClose() &&
		       isEmptyChunkBuffersCount());
	}
	
	u_int32_t getAllReceivedRtpPackets();
	
	void forcemark_lock() {
		while(__sync_lock_test_and_set(&this->_forcemark_lock, 1));
	}
	void forcemark_unlock() {
		__sync_lock_release(&this->_forcemark_lock);
	}

	void proxies_lock() {
		while(__sync_lock_test_and_set(&this->_proxies_lock, 1));
	}
	void proxies_unlock() {
		__sync_lock_release(&this->_proxies_lock);
	}
	
	bool is_enable_set_destroy_call_at_for_call(sCseq *cseq, int merged) {
		return((!cseq || !this->invitecseq_in_dialog.size() || find(this->invitecseq_in_dialog.begin(),this->invitecseq_in_dialog.end(), *cseq) == this->invitecseq_in_dialog.end()) &&
		       (!this->has_second_merged_leg || (this->has_second_merged_leg && merged)));
	}
	
	void shift_destroy_call_at(pcap_pkthdr *header, int lastSIPresponseNum = 0) {
		extern int opt_quick_save_cdr;
		if(this->destroy_call_at > 0) {
			extern int opt_register_timeout;
			time_t new_destroy_call_at = 
				typeIs(REGISTER) ?
					header->ts.tv_sec + opt_register_timeout :
					(this->seenbyeandok ?
						header->ts.tv_sec + (opt_quick_save_cdr == 2 ? 0 :
								    (opt_quick_save_cdr ? 1 : 5)) :
					 this->seenbye ?
						header->ts.tv_sec + 60 :
						header->ts.tv_sec + (lastSIPresponseNum == 487 || this->lastSIPresponseNum == 487 ? 15 : 5));
			if(new_destroy_call_at > this->destroy_call_at) {
				this->destroy_call_at = new_destroy_call_at;
			}
		}
	}
	
	void applyRtcpXrDataToRtp();
	
	void adjustUA();
	
	bool is_set_proxies();
	void proxies_undup(set<unsigned int> *proxies_undup);
	string get_proxies_str();

	void proxy_add(u_int32_t sipproxyip);
	
	void createListeningBuffers();
	void destroyListeningBuffers();
	void disableListeningBuffers();
	
	bool checkKnownIP_inSipCallerdIP(u_int32_t ip) {
		for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
			if(ip == sipcallerip[i] ||
			   ip == sipcalledip[i]) {
				return(true);
			}
		}
		return(false);
	}
	
	u_int32_t getSipcalledipConfirmed(u_int16_t *dport);
	unsigned getMaxRetransmissionInvite();
	
	void calls_counter_inc() {
		extern volatile int calls_counter;
		if(typeIs(INVITE) || typeIs(MESSAGE) || typeIs(MGCP)) {
			++calls_counter;
		}
	}
	void calls_counter_dec() {
		extern volatile int calls_counter;
		if(typeIs(INVITE) || typeIs(MESSAGE) || typeIs(MGCP)) {
			--calls_counter;
		}
	}
	
	bool selectRtpStreams();
	bool selectRtpStreams_bySipcallerip();
	bool selectRtpStreams_byMaxLengthInLink();
	u_int64_t getLengthStreams(list<int> *streams_i);
	u_int64_t getLengthStreams();
	void setSkipConcurenceStreams(int caller);
	u_int64_t getFirstTimeInRtpStreams(int caller, bool selected);
	void printSelectedRtpStreams(int caller, bool selected);
	bool existsConcurenceInSelectedRtpStream(int caller, unsigned tolerance_ms);
	bool existsBothDirectionsInSelectedRtpStream();
	
	bool isSetCallidMergeHeader() {
		extern char opt_callidmerge_header[128];
		return((typeIs(INVITE) || typeIs(MESSAGE)) &&
		       opt_callidmerge_header[0] != '\0');
	}
	void removeMergeCalls();
	void mergecalls_lock() {
		while(__sync_lock_test_and_set(&this->_mergecalls_lock, 1));
	}
	void mergecalls_unlock() {
		__sync_lock_release(&this->_mergecalls_lock);
	}
	
	void setSipcallerip(u_int32_t ip, u_int16_t port, const char *call_id = NULL) {
		sipcallerip[0] = ip;
		sipcallerport[0] = port;
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			map_sipcallerdip[call_id].sipcallerip[0] = ip;
			map_sipcallerdip[call_id].sipcallerport[0] = port;
		}
	}
	void setSipcalledip(u_int32_t ip, u_int16_t port, const char *call_id = NULL) {
		if(sipcalledip[0]) {
			sipcalledip_mod = ip;
			sipcalledport_mod = port;
		} else {
			sipcalledip[0] = ip;
			sipcalledport[0] = port;
		}
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			if(map_sipcallerdip[call_id].sipcalledip[0]) {
				map_sipcallerdip[call_id].sipcalledip_mod = ip;
				map_sipcallerdip[call_id].sipcalledport_mod = port;
			} else {
				map_sipcallerdip[call_id].sipcalledip[0] = ip;
				map_sipcallerdip[call_id].sipcalledport[0] = port;
			}
		}
	}
	u_int32_t getSipcallerip() {
		return(sipcallerip[0]);
	}
	u_int32_t getSipcalledip() {
		return(sipcalledip_mod ? sipcalledip_mod : sipcalledip[0]);
	}
	u_int16_t getSipcallerport() {
		return(sipcallerport[0]);
	}
	u_int16_t getSipcalledport() {
		return(sipcalledport_mod ? sipcalledport_mod : sipcalledport[0]);
	}
	void setSeenbye(bool seenbye, u_int64_t seenbye_time_usec, const char *call_id) {
		this->seenbye = seenbye;
		this->seenbye_time_usec = seenbye_time_usec;
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seenbye = seenbye;
				mergecalls[call_id].seenbye_time_usec = seenbye_time_usec;
			}
			mergecalls_unlock();
		}
	}
	void setSeenbyeAndOk(bool seenbyeandok, u_int64_t seenbyeandok_time_usec, const char *call_id) {
		this->seenbyeandok = seenbyeandok;
		this->seenbyeandok_time_usec = seenbyeandok_time_usec;
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seenbyeandok = seenbyeandok;
				mergecalls[call_id].seenbyeandok_time_usec = seenbyeandok_time_usec;
			}
			mergecalls_unlock();
		}
	}
	void setSeencancelAndOk(bool seencancelandok, u_int64_t seencancelandok_time_usec, const char *call_id) {
		this->seencancelandok = seencancelandok;
		this->seencancelandok_time_usec = seencancelandok_time_usec;
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seencancelandok = seencancelandok;
				mergecalls[call_id].seencancelandok_time_usec = seencancelandok_time_usec;
			}
			mergecalls_unlock();
		}
	}
	u_int64_t getSeenbyeTimeUS() {
		if(isSetCallidMergeHeader()) {
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
		return(seenbye ? seenbye_time_usec : 0);
	}
	u_int64_t getSeenbyeAndOkTimeUS() {
		if(isSetCallidMergeHeader()) {
			u_int64_t seenbyeandok_time_usec = 0;
			mergecalls_lock();
			for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
				if(!it->second.seenbyeandok || !it->second.seenbyeandok_time_usec) {
					mergecalls_unlock();
					return(0);
				}
				if(seenbyeandok_time_usec < it->second.seenbyeandok_time_usec) {
					seenbyeandok_time_usec = it->second.seenbyeandok_time_usec;
				}
			}
			mergecalls_unlock();
			return(seenbyeandok_time_usec);
		}
		return(seenbyeandok ? seenbyeandok_time_usec : 0);
	}
	int setByeCseq(sCseq *cseq) {
		unsigned index;
		unsigned size_byecseq = sizeof(byecseq) / sizeof(byecseq[0]);
		for(index = 0; index < size_byecseq; index++) {
			if(!byecseq[index].is_set()) {
				break;
			} else if(byecseq[index] == *cseq) {
				return(index);
			}
		}
		if(index == size_byecseq) {
			index = size_byecseq - 1;
		}
		byecseq[index] = *cseq;
		return(index);
	}
	int existsByeCseq(sCseq *cseq) {
		for(unsigned index = 0; index < (sizeof(byecseq) / sizeof(byecseq[0])); index++) {
			if(byecseq[index].is_set() &&
			   byecseq[index] == *cseq) {
				return(index + 1);
			}
		}
		return(0);
	}
	
	void getValue(eCallField field, RecordArrayField *rfield);
	static string getJsonHeader();
	void getRecordData(RecordArray *rec);
	string getJsonData();
	void setRtpThreadNum();
	
	void hash_add_lock() {
		while(__sync_lock_test_and_set(&this->_hash_add_lock, 1));
	}
	void hash_add_unlock() {
		__sync_lock_release(&this->_hash_add_lock);
	}

private:
	ip_port_call_info ip_port[MAX_IP_PER_CALL];
	bool exists_crypto_suite_key;
	bool log_srtp_callid;
	PcapDumper pcap;
	PcapDumper pcapSip;
	PcapDumper pcapRtp;
	map<sStreamId, sUdptlDumper*> udptlDumpers;
	volatile int _hash_add_lock;
public:
	list<u_int16_t> sdp_ip0_ports[2];
	bool error_negative_payload_length;
	bool use_removeRtp;
	volatile int hash_counter;
	volatile int hash_queue_counter;
	int attemptsClose;
	bool use_rtcp_mux;
	bool use_sdp_sendonly;
	bool rtp_from_multiple_sensors;
	volatile int in_preprocess_queue_before_process_packet;
	volatile u_int32_t in_preprocess_queue_before_process_packet_at[2];
friend class RTPsecure;
};


void adjustUA(string *ua);
const char *adjustUA(char *ua, unsigned ua_size);

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
			return(intToString(isup_cic) + "-" + intToString(low_point) + "-" + intToString(high_point));
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
		unsigned isup_cause_indicator;
	};
public:
	Ss7(time_t time);
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
	u_int32_t iam_src_ip;
	u_int32_t iam_dst_ip;
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
	PcapDumper pcap;
private:
	struct timeval last_dump_ts;
};


/**
  * This class implements operations on Call list
*/
class Calltable {
private:
	struct sAudioQueueThread {
		sAudioQueueThread() {
			thread_handle = 0;
			thread_id = 0;
		}
		pthread_t thread_handle;
		int thread_id;
	};
	enum eHashModifyOper {
		hmo_add,
		hmo_remove,
		hmo_remove_call
	};
	struct sHashModifyData {
		eHashModifyOper oper;
		u_int32_t addr;
		u_int16_t port;
		u_int32_t time_s;
		Call* call;
		int8_t iscaller;
		int8_t is_rtcp;
		s_sdp_flags sdp_flags;
		bool use_hash_queue_counter;
	};
public:
	deque<Call*> calls_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	deque<Call*> audio_queue; //!< this queue is used for asynchronous audio convert by the worker thread
	deque<Call*> calls_deletequeue; //!< this queue is used for asynchronous storing CDR by the worker thread
	deque<Call*> registers_queue;
	deque<Call*> registers_deletequeue;
	deque<Ss7*> ss7_queue;
	queue<string> files_queue; //!< this queue is used for asynchronous storing CDR by the worker thread
	queue<string> files_sqlqueue; //!< this queue is used for asynchronous storing CDR by the worker thread
	map<string, Call*> calls_listMAP;
	map<sStreamIds2, Call*> calls_by_stream_callid_listMAP;
	map<sStreamId2, Call*> calls_by_stream_id2_listMAP;
	map<sStreamId, Call*> calls_by_stream_listMAP;
	map<string, Call*> calls_mergeMAP;
	map<string, Call*> registers_listMAP;
	map<string, Call*> skinny_ipTuples;
	map<unsigned int, Call*> skinny_partyID;
	map<string, Ss7*> ss7_listMAP;

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
	void lock_calls_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_queue, 1)) usleep(10); /*pthread_mutex_lock(&qlock);*/ };
	void lock_calls_audioqueue() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_audioqueue, 1)) usleep(10); /*pthread_mutex_lock(&qaudiolock);*/ };
	void lock_calls_deletequeue() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_deletequeue, 1)) usleep(10); /*pthread_mutex_lock(&qdellock);*/ };
	void lock_registers_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_registers_queue, 1)) usleep(10); };
	void lock_registers_deletequeue() { while(__sync_lock_test_and_set(&this->_sync_lock_registers_deletequeue, 1)) usleep(10); };
	void lock_files_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_files_queue, 1)) usleep(10); /*pthread_mutex_lock(&flock);*/ };
	void lock_calls_listMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_listMAP, 1)) usleep(10); /*pthread_mutex_lock(&calls_listMAPlock);*/ };
	void lock_calls_mergeMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_mergeMAP, 1)) usleep(10); /*pthread_mutex_lock(&calls_mergeMAPlock);*/ };
	void lock_registers_listMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_registers_listMAP, 1)) usleep(10); /*pthread_mutex_lock(&registers_listMAPlock);*/ };
	void lock_skinny_maps() { while(__sync_lock_test_and_set(&this->_sync_lock_skinny_maps, 1)) usleep(10); /*pthread_mutex_lock(&registers_listMAPlock);*/ };
	void lock_ss7_listMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_ss7_listMAP, 1)) usleep(10); }
	void lock_process_ss7_listmap() { while(__sync_lock_test_and_set(&this->_sync_lock_process_ss7_listmap, 1)) usleep(10); }
	void lock_process_ss7_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_process_ss7_queue, 1)) usleep(10); }
	void lock_hash_modify_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_hash_modify_queue, 1)) usleep(10); }

	/**
	 * @brief unlock calls_queue structure 
	 *
	*/
	void unlock_calls_queue() { __sync_lock_release(&this->_sync_lock_calls_queue); /*pthread_mutex_unlock(&qlock);*/ };
	void unlock_calls_audioqueue() { __sync_lock_release(&this->_sync_lock_calls_audioqueue); /*pthread_mutex_unlock(&qaudiolock);*/ };
	void unlock_calls_deletequeue() { __sync_lock_release(&this->_sync_lock_calls_deletequeue); /*pthread_mutex_unlock(&qdellock);*/ };
	void unlock_registers_queue() { __sync_lock_release(&this->_sync_lock_registers_queue); };
	void unlock_registers_deletequeue() { __sync_lock_release(&this->_sync_lock_registers_deletequeue); };
	void unlock_files_queue() { __sync_lock_release(&this->_sync_lock_files_queue); /*pthread_mutex_unlock(&flock);*/ };
	void unlock_calls_listMAP() { __sync_lock_release(&this->_sync_lock_calls_listMAP); /*pthread_mutex_unlock(&calls_listMAPlock);*/ };
	void unlock_calls_mergeMAP() { __sync_lock_release(&this->_sync_lock_calls_mergeMAP); /*pthread_mutex_unlock(&calls_mergeMAPlock);*/ };
	void unlock_registers_listMAP() { __sync_lock_release(&this->_sync_lock_registers_listMAP); /*pthread_mutex_unlock(&registers_listMAPlock);*/ };
	void unlock_skinny_maps() { __sync_lock_release(&this->_sync_lock_skinny_maps); };
	void unlock_ss7_listMAP() { __sync_lock_release(&this->_sync_lock_ss7_listMAP); };
	void unlock_process_ss7_listmap() { __sync_lock_release(&this->_sync_lock_process_ss7_listmap); };
	void unlock_process_ss7_queue() { __sync_lock_release(&this->_sync_lock_process_ss7_queue); };
	void unlock_hash_modify_queue() { __sync_lock_release(&this->_sync_lock_hash_modify_queue); };

	/**
	 * @brief add Call to Calltable
	 *
	 * @param call_id unique identifier of the Call which is parsed from the SIP packets
	 * @param call_id_len lenght of the call_id buffer
	 * @param time timestamp of arrivel packet in seconds from UNIX epoch
	 *
	 * @return reference of the new Call class
	*/
	Call *add(int call_type, char *call_id, unsigned long call_id_len, time_t time, u_int32_t saddr, unsigned short port, 
		  pcap_t *handle, int dlt, int sensorId);
	Ss7 *add_ss7(packet_s_stack *packetS, Ss7::sParseData *data);
	Call *add_mgcp(sMgcpRequest *request, time_t time, u_int32_t saddr, unsigned short sport, u_int32_t daddr, unsigned short dport,
		       pcap_t *handle, int dlt, int sensorId);

	/**
	 * @brief find Call by call_id
	 *
	 * @param call_id unique identifier of the Call which is parsed from the SIP packets
	 * @param call_id_len lenght of the call_id buffer
	 *
	 * @return reference of the Call if found, otherwise return NULL
	*/
	Call *find_by_call_id(char *call_id, unsigned long call_id_len, time_t time) {
		Call *rslt_call = NULL;
		string call_idS = call_id_len ? string(call_id, call_id_len) : string(call_id);
		lock_calls_listMAP();
		map<string, Call*>::iterator callMAPIT = calls_listMAP.find(call_idS);
		if(callMAPIT != calls_listMAP.end()) {
			rslt_call = callMAPIT->second;
			if(time) {
				__sync_add_and_fetch(&rslt_call->in_preprocess_queue_before_process_packet, 1);
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_stream_callid(u_int32_t sip, u_int16_t sport, u_int32_t dip, u_int16_t dport, const char *callid) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		map<sStreamIds2, Call*>::iterator callMAPIT = calls_by_stream_callid_listMAP.find(sStreamIds2(sip, sport, dip, dport, callid, true));
		if(callMAPIT != calls_by_stream_callid_listMAP.end()) {
			rslt_call = callMAPIT->second;
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_stream_id2(u_int32_t sip, u_int16_t sport, u_int32_t dip, u_int16_t dport, u_int64_t id) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		map<sStreamId2, Call*>::iterator callMAPIT = calls_by_stream_id2_listMAP.find(sStreamId2(sip, sport, dip, dport, id, true));
		if(callMAPIT != calls_by_stream_id2_listMAP.end()) {
			rslt_call = callMAPIT->second;
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_stream(u_int32_t sip, u_int16_t sport, u_int32_t dip, u_int16_t dport) {
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
			if(time) {
				__sync_add_and_fetch(&rslt_call->in_preprocess_queue_before_process_packet, 1);
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
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
		for(map<string, Call*>::iterator iter = calls_listMAP.begin(); iter != calls_listMAP.end(); iter++) {
			if((long long)(iter->second) == callreference) {
				rslt_call = iter->second;
				break;
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
	Call *find_by_skinny_ipTuples(unsigned int saddr, unsigned int daddr) {
		Call *rslt_call = NULL;
		lock_calls_listMAP();
		lock_skinny_maps();
		string ip2 = intToString(min(saddr, daddr)) + '|' + intToString(max(saddr, daddr));
		map<string, Call*>::iterator skinny_ipTuplesIT = skinny_ipTuples.find(ip2);
		if(skinny_ipTuplesIT != skinny_ipTuples.end()) {
			rslt_call = skinny_ipTuplesIT->second;
		}
		unlock_skinny_maps();
		unlock_calls_listMAP();
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
	int cleanup_calls( struct timeval *currtime, bool forceClose = false );
	int cleanup_registers( struct timeval *currtime);
	int cleanup_ss7( struct timeval *currtime );

	/**
	 * @brief add call to hash table
	 *
	*/
	void hashAdd(in_addr_t addr, unsigned short port, struct timeval *ts, Call* call, int iscaller, int isrtcp, s_sdp_flags sdp_flags);
	inline void _hashAdd(in_addr_t addr, unsigned short port, long int time_s, Call* call, int iscaller, int isrtcp, s_sdp_flags sdp_flags, bool use_lock = true);

	/**
	 * @brief find call
	 *
	*/
	inline hash_node_call *hashfind_by_ip_port(in_addr_t addr, unsigned short port, bool lock = true) {
		hash_node *node = NULL;
		u_int32_t h = tuplehash(addr, port);
		if(lock) {
			lock_calls_hash();
		}
		hash_node_call *rslt = NULL;
		for (node = (hash_node *)calls_hash[h]; node != NULL; node = node->next) {
			if ((node->addr == addr) && (node->port == port)) {
				rslt = node->calls;
			}
		}
		if(lock) {
			unlock_calls_hash();
		}
		return rslt;
	}
	inline bool check_call_in_hashfind_by_ip_port(Call *call, in_addr_t addr, unsigned short port, bool lock = true) {
		bool rslt = false;
		if(lock) {
			lock_calls_hash();
		}
		hash_node_call *calls = this->hashfind_by_ip_port(addr, port, false);
		if(calls) {
			for(hash_node_call *node_call = (hash_node_call *)calls; node_call != NULL; node_call = node_call->next) {
				if(node_call->call == call) {
					rslt = true;
					break;
				}
			}
		}
		if(lock) {
			unlock_calls_hash();
		}
		return rslt;
	}

	/**
	 * @brief remove call from hash
	 *
	*/
	void hashRemove(Call *call, in_addr_t addr, unsigned short port, struct timeval *ts, bool rtcp = false, bool useHashQueueCounter = true);
	inline void _hashRemove(Call *call, in_addr_t addr, unsigned short port, bool rtcp = false, bool use_lock = true);
	int hashRemove(Call *call, struct timeval *ts, bool useHashQueueCounter = true);
	int hashRemoveForce(Call *call);
	inline int _hashRemove(Call *call, bool use_lock = true);
	void applyHashModifyQueue(struct timeval *ts, bool setBegin, bool use_lock_calls_hash = true);
	inline void _applyHashModifyQueue(struct timeval *ts, bool setBegin, bool use_lock_calls_hash = true);
	
	void processCallsInAudioQueue(bool lock = true);
	static void *processAudioQueueThread(void *);
	size_t getCountAudioQueueThreads() {
		return(audioQueueThreads.size());
	}
	void setAudioQueueTerminating() {
		audioQueueTerminating = 1;
	}

	void destroyCallsIfPcapsClosed();
	void destroyRegistersIfPcapsClosed();
	
	void mgcpCleanupTransactions(Call *call);
	void mgcpCleanupStream(Call *call);
	
	string getCallTableJson(char *params, bool *zip = NULL);
	
	void lock_calls_hash() {
		unsigned usleepCounter = 0;
		while(__sync_lock_test_and_set(&this->_sync_lock_calls_hash, 1)) {
			usleep(10 *
			       (usleepCounter > 10 ? 50 :
				usleepCounter > 5 ? 10 :
				usleepCounter > 2 ? 5 : 1));
			++usleepCounter;
		}
	}
	void unlock_calls_hash() {
		__sync_lock_release(&this->_sync_lock_calls_hash);
	}
	
	void cbInit(SqlDb *sqlDb = NULL);
	void cbLoad(SqlDb *sqlDb = NULL);
	void cbTerm();
	unsigned cb_ua_getId(const char *ua, bool enableInsert, bool enableAutoLoad = false);
	unsigned cb_sip_response_getId(const char *response, bool enableInsert, bool enableAutoLoad = false);
	unsigned cb_sip_request_getId(const char *request, bool enableInsert, bool enableAutoLoad = false);
	unsigned cb_reason_sip_getId(const char *reason, bool enableInsert, bool enableAutoLoad = false);
	unsigned cb_reason_q850_getId(const char *reason, bool enableInsert, bool enableAutoLoad = false);
	unsigned cb_contenttype_getId(const char *content, bool enableInsert, bool enableAutoLoad = false);
	
	void addSystemCommand(const char *command);
	
private:
	/*
	pthread_mutex_t qlock;		//!< mutex locking calls_queue
	pthread_mutex_t qaudiolock;	//!< mutex locking calls_audioqueue
	pthread_mutex_t qdellock;	//!< mutex locking calls_deletequeue
	pthread_mutex_t flock;		//!< mutex locking calls_queue
	pthread_mutex_t calls_listMAPlock;
	pthread_mutex_t calls_mergeMAPlock;
	pthread_mutex_t registers_listMAPlock;
	*/

	void *calls_hash[MAXNODE];
	volatile int _sync_lock_calls_hash;
	volatile int _sync_lock_calls_listMAP;
	volatile int _sync_lock_calls_mergeMAP;
	volatile int _sync_lock_registers_listMAP;
	volatile int _sync_lock_calls_queue;
	volatile int _sync_lock_calls_audioqueue;
	volatile int _sync_lock_calls_deletequeue;
	volatile int _sync_lock_registers_queue;
	volatile int _sync_lock_registers_deletequeue;
	volatile int _sync_lock_skinny_maps;
	volatile int _sync_lock_files_queue;
	volatile int _sync_lock_ss7_listMAP;
	volatile int _sync_lock_process_ss7_listmap;
	volatile int _sync_lock_process_ss7_queue;
	
	list<sAudioQueueThread*> audioQueueThreads;
	unsigned int audioQueueThreadsMax;
	int audioQueueTerminating;
	
	cSqlDbCodebook *cb_ua;
	cSqlDbCodebook *cb_sip_response;
	cSqlDbCodebook *cb_sip_request;
	cSqlDbCodebook *cb_reason_sip;
	cSqlDbCodebook *cb_reason_q850;
	cSqlDbCodebook *cb_contenttype;
	
	class AsyncSystemCommand *asyncSystemCommand;
	
	list<sHashModifyData> hash_modify_queue;
	u_int64_t hash_modify_queue_begin_ms;
	volatile int _sync_lock_hash_modify_queue;
	
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
		max_retransmission_invite
	};
	enum eReqRespDirection {
		dir_na,
		dir_request  = 1,
		dir_response = 2,
		dir_both     = 3
	};
	struct sCustomHeaderData {
		eSpecialType specialType;
		string header;
		unsigned db_id;
		string leftBorder;
		string rightBorder;
		string regularExpression;
		bool screenPopupField;
		eReqRespDirection reqRespDirection;
		bool selectOccurrence;
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
	void addToStdParse(ParsePacket *parsePacket);
	void parse(Call *call, int type, tCH_Content *ch_content, packet_s_process *packetS, eReqRespDirection reqRespDirection = dir_na);
	void setCustomHeaderContent(Call *call, int type, tCH_Content *ch_content, int pos1, int pos2, dstring *content, bool useLastValue);
	void prepareSaveRows(Call *call, int type, tCH_Content *ch_content, unsigned time_s, class SqlDb_row *cdr_next, class SqlDb_row cdr_next_ch[], char *cdr_next_ch_name[]);
	string getScreenPopupFieldsString(Call *call, int type);
	string getDeleteQuery(const char *id, const char *prefix, const char *suffix);
	list<string> getAllNextTables() {
		return(allNextTables);
	}
	list<string> *getAllNextTablesPointer() {
		return(&allNextTables);
	}
	void createMysqlPartitions(class SqlDb *sqlDb);
	void createMysqlPartitions(class SqlDb *sqlDb, int day);
	unsigned long getLoadTime() {
		return(loadTime);
	}
	string getQueryForSaveUseInfo(Call *call, int type, tCH_Content *ch_content);
	string getQueryForSaveUseInfo(unsigned time, tCH_Content *ch_content);
	void createTablesIfNotExists(SqlDb *sqlDb = NULL, bool enableOldPartition = false);
	void createTableIfNotExists(const char *tableName, SqlDb *sqlDb = NULL, bool enableOldPartition = false);
	void createColumnsForFixedHeaders(SqlDb *sqlDb = NULL);
	bool getPosForDbId(unsigned db_id, d_u_int32_t *pos);
	static tCH_Content *getCustomHeadersCallContent(Call *call, int type);
private:
	void lock_custom_headers() {
		while(__sync_lock_test_and_set(&this->_sync_custom_headers, 1));
	}
	void unlock_custom_headers() {
		__sync_lock_release(&this->_sync_custom_headers);
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
	unsigned loadTime;
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
		while(__sync_lock_test_and_set(&this->_sync_no_hash, 1));
	}
	void unlock_no_hash() {
		__sync_lock_release(&this->_sync_no_hash);
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
	bool check(Call *call);
	void set(const char*);
	bool isSet();
private:
	bool check_number(const char *number);
	bool check_name(const char *name);
private:
	int lastResponseNum;
	int lastResponseNumLength;
	u_int32_t ip;
	unsigned ip_mask_length;
	string number;
	CheckString *number_check;
	cRegExp *number_regexp;
	string name;
	CheckString *name_check;
	cRegExp *name_regexp;
 
};

class NoStoreCdrRules {
public:
	~NoStoreCdrRules();
	bool check(Call *call);
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

string printCallFlags(unsigned int flags);
eCallField convCallFieldToFieldId(const char *field);
int convCallFieldToFieldIndex(eCallField field);


#endif
