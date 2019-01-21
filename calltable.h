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

#define FLAG_SAVESIP			(1 << 1)
#define FLAG_SAVERTP			(1 << 2)
#define FLAG_SAVERTPHEADER		(1 << 3)
#define FLAG_SAVERTP_VIDEO		(1 << 4)
#define FLAG_SAVERTP_VIDEO_HEADER	(1 << 5)
#define FLAG_PROCESSING_RTP_VIDEO	(1 << 6)
#define FLAG_SAVEMRCP			(1 << 7)
#define FLAG_SAVERTCP			(1 << 8)
#define FLAG_SAVEREGISTER		(1 << 9)
#define FLAG_SAVEAUDIO			(1 << 10)
#define FLAG_FORMATAUDIO_WAV		(1 << 11)
#define FLAG_FORMATAUDIO_OGG		(1 << 12)
#define FLAG_SAVEAUDIO_WAV		(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_WAV)
#define FLAG_SAVEAUDIO_OGG		(FLAG_SAVEAUDIO|FLAG_FORMATAUDIO_OGG)
#define FLAG_SAVEGRAPH			(1 << 13)
#define FLAG_SKIPCDR			(1 << 14)
#define FLAG_RUNSCRIPT			(1 << 15)
#define FLAG_RUNAMOSLQO			(1 << 16)
#define FLAG_RUNBMOSLQO			(1 << 17)
#define FLAG_HIDEMESSAGE		(1 << 18)
#define FLAG_USE_SPOOL_2		(1 << 19)
#define FLAG_SAVEDTMFDB			(1 << 20)
#define FLAG_SAVEDTMFPCAP		(1 << 21)
#define FLAG_SAVEOPTIONSDB		(1 << 22)
#define FLAG_SAVEOPTIONSPCAP		(1 << 23)
#define FLAG_SAVENOTIFYDB		(1 << 24)
#define FLAG_SAVENOTIFYPCAP		(1 << 25)
#define FLAG_SAVESUBSCRIBEDB		(1 << 26)
#define FLAG_SAVESUBSCRIBEPCAP		(1 << 27)

#define CDR_NEXT_MAX 10

#define CDR_CHANGE_SRC_PORT_CALLER	(1 << 0)
#define CDR_CHANGE_SRC_PORT_CALLED	(1 << 1)
#define CDR_UNCONFIRMED_BYE		(1 << 2)
#define CDR_ALONE_UNCONFIRMED_BYE	(1 << 3)
#define CDR_SRTP_WITHOUT_KEY		(1 << 4)
#define CDR_FAS_DETECTED		(1 << 5)
#define CDR_ZEROSSRC_DETECTED		(1 << 6)
#define CDR_SIPALG_DETECTED		(1 << 7)
#define CDR_TELEVENT_EXISTS_REQUEST	(1 << 8)
#define CDR_TELEVENT_EXISTS_RESPONSE	(1 << 9)
#define CDR_SIP_FRAGMENTED		(1 << 10)
#define CDR_RTP_FRAGMENTED		(1 << 11)
#define CDR_SDP_EXISTS_MEDIA_TYPE_AUDIO	(1 << 12)
#define CDR_SDP_EXISTS_MEDIA_TYPE_IMAGE	(1 << 13)
#define CDR_SDP_EXISTS_MEDIA_TYPE_VIDEO	(1 << 14)
#define CDR_PROCLIM_SUPPRESS_RTP_READ   (1 << 15)
#define CDR_PROCLIM_SUPPRESS_RTP_PROC   (1 << 16)

#define CDR_RTP_STREAM_IN_MULTIPLE_CALLS	(1 << 0)
#define CDR_RTP_STREAM_IS_AB			(1 << 1)
#define CDR_RTP_STREAM_IS_CALLER		(1 << 2)
#define CDR_RTP_STREAM_IS_CALLED		(1 << 3)

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
	Call *call;
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
		_ta_sdp_reverse_ipport,
		_ta_base_video,
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
	string branch;
	vmIP sip_src_addr;
	s_sdp_flags sdp_flags;
	ip_port_call_info_rtp rtp[2];
	bool canceled;
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
	cf_vlan,
	cf_custom_header,
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
			usleep(10);
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
public:
	volatile uint8_t alloc_flag;
	int type_base;
	int type_next;
	u_int64_t first_packet_time_us;
	char fbasename[MAX_FNAME];
	char fbasename_safe[MAX_FNAME];
	u_int64_t fname_register;
	int useSensorId;
	int useDlt;
	pcap_t *useHandle;
	string force_spool_path;
	volatile unsigned long int flags;
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
friend class cDestroyCallsInfo;
friend class ChunkBuffer;
};

struct sChartsCacheCallData {
	map<u_int32_t, cEvalFormula::sValue> value_map;
};

/**
  * This class implements operations on call
*/
class Call : public Call_abstract {
public:
	enum eTable {
		_t_cdr = 1,
		_t_cdr_next = 2,
		_t_cdr_next_end = 20,
		_t_cdr_country_code = 21,
		_t_cdr_proxy,
		_t_cdr_sipresp,
		_t_cdr_siphistory,
		_t_cdr_rtp,
		_t_cdr_sdp
	};
	enum eStoreFlags {
		_sf_db = 1,
		_sf_charts_cache = 2
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
			seenbyeandok = false;
			seenbyeandok_time_usec = 0;
			seencancelandok = false;
			seencancelandok_time_usec = 0;
			seenauthfailed = false;
			seenauthfailed_time_usec = 0;
		}
		bool seenbye;
		u_int64_t seenbye_time_usec;
		bool seenbyeandok;
		u_int64_t seenbyeandok_time_usec;
		bool seencancelandok;
		u_int64_t seencancelandok_time_usec;
		bool seenauthfailed;
		u_int64_t seenauthfailed_time_usec;
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
		string caller;
		string called;
		string called_invite;
		string branch;
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
	struct sRtcpXrDataItem {
		timeval tv;
		int16_t moslq;
		int16_t nlr;
		vmIP ip_local;
		vmIP ip_remote;
	};
	struct sRtcpXrDataSsrc : public list<sRtcpXrDataItem> {
		void add(timeval tv, int16_t moslq, int16_t nlr, vmIP ip_local, vmIP ip_remote) {
			sRtcpXrDataItem dataItem;
			dataItem.tv = tv;
			dataItem.moslq = moslq;
			dataItem.nlr = nlr;
			dataItem.ip_local = ip_local;
			dataItem.ip_remote = ip_remote;
			this->push_back(dataItem);
		}
	};
	struct sRtcpXrData : public map<u_int32_t, sRtcpXrDataSsrc> {
		void add(u_int32_t ssrc, timeval tv, int16_t moslq, int16_t nlr, vmIP ip_local, vmIP ip_remote) {
			(*this)[ssrc].add(tv, moslq, nlr, ip_local, ip_remote);
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
	enum eTxtType {
		txt_type_na,
		txt_type_sdp_xml
	};
	struct sTxt {
		u_int64_t time;
		eTxtType type;
		string txt;
	};
public:
	bool is_ssl;			//!< call was decrypted
	RTP *rtp_fix[MAX_SSRC_PER_CALL_FIX];	//!< array of RTP streams
	int ssrc_n;				//!< last index of rtp array
	#if CALL_RTP_DYNAMIC_ARRAY
	vector<RTP*> *rtp_dynamic;
	#endif
	list<RTP*> *rtp_canceled;
	volatile bool rtp_remove_flag;
	RTP *rtpab[2];
	map<int, class RTPsecure*> rtp_secure_map;
	cDtls *dtls;
	volatile int rtplock_sync;
	unsigned long call_id_len;	//!< length of call-id 	
	string call_id;	//!< call-id from SIP session
	map<string, bool> *call_id_alternative;
	volatile int _call_id_alternative_lock;
	char callername[256];		//!< callerid name from SIP header
	char caller[256];		//!< From: xxx 
	char caller_domain[256];	//!< From: xxx 
	char called_to[256];		//!< To: xxx
	char called_uri[256];
	char called_final[256];
	inline char *called() {
		extern int opt_destination_number_mode;
		return(called_final[0] ? called_final :
		       called_uri[0] && opt_destination_number_mode == 2 ? called_uri : called_to);
	}
	map<string, dstring> called_invite_branch_map;
	char called_domain_to[256];	//!< To: xxx
	char called_domain_uri[256];
	inline char *called_domain() {
		extern int opt_destination_number_mode;
		return(called_domain_uri[0] && opt_destination_number_mode == 2 ? called_domain_uri : called_domain_to);
	}
	char contact_num[64];		//!< 
	char contact_domain[128];	//!< 
	char digest_username[64];	//!< 
	char digest_realm[64];		//!< 
	int register_expires;	
	sCseq byecseq[2];		
	sCseq invitecseq;		
	list<sCseq> invitecseq_next;
	deque<sCseq> invitecseq_in_dialog;
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
	bool seenbyeandok_permanent;
	u_int64_t seenbyeandok_time_usec;
	bool seencancelandok;		//!< true if we see SIP OK TO CANCEL within the Call
	u_int64_t seencancelandok_time_usec;
	bool seenauthfailed;
	u_int64_t seenauthfailed_time_usec;
	bool unconfirmed_bye;
	bool seenRES2XX;
	bool seenRES2XX_no_BYE;
	bool seenRES18X;
	bool sighup;			//!< true if call is saving during sighup
	char a_ua[1024];		//!< caller user agent 
	char b_ua[1024];		//!< callee user agent 
	RTPMAP rtpmap[MAX_IP_PER_CALL][MAX_RTPMAP]; //!< rtpmap for every rtp stream
	bool rtpmap_used_flags[MAX_IP_PER_CALL];
	RTP *lastcallerrtp;		//!< last RTP stream from caller
	RTP *lastcalledrtp;		//!< last RTP stream from called
	vmIP saddr;		//!< source IP address of first INVITE
	vmPort sport;		//!< source port of first INVITE
	vmIP daddr;
	vmPort dport;
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
	bool save_energylevels;
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
	timeval regrrdstart;		// time of first REGISTER
	int regrrddiff;			// RRD diff time REGISTER<->OK in [ms]- RFC6076
	//uint64_t regsrcmac;		// mac if ether layer present in REGISTER
	list<u_int32_t> *reg_tcp_seq;
	
	int last_sip_method;
	volatile unsigned int rtppacketsinqueue;
	volatile int end_call_rtp;
	volatile int end_call_hash_removed;
	volatile int push_call_to_calls_queue;
	volatile int push_register_to_registers_queue;
	volatile int push_call_to_storing_cdr_queue;
	unsigned int ps_drop;
	unsigned int ps_ifdrop;
	vector<u_int64_t> forcemark_time;
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

	vmIP sipcallerip[MAX_SIPCALLERDIP];	//!< SIP signalling source IP address
	vmIP sipcalledip[MAX_SIPCALLERDIP];	//!< SIP signalling destination IP address
	vmIP sipcalledip_mod;
	vmIP sipcallerip_encaps;
	vmIP sipcalledip_encaps;
	u_int8_t sipcallerip_encaps_prot;
	u_int8_t sipcalledip_encaps_prot;
	vmIP sipcalledip_rslt;
	vmIP sipcalledip_encaps_rslt;
	u_int8_t sipcalledip_encaps_prot_rslt;
	vmPort sipcallerport[MAX_SIPCALLERDIP];
	vmPort sipcalledport[MAX_SIPCALLERDIP];
	vmPort sipcalledport_mod;
	vmPort sipcalledport_rslt;
	map<string, sSipcalleRD_IP> map_sipcallerdip;
	vmIP lastsipcallerip;
	bool sipcallerdip_reverse;
	
	list<sInviteSD_Addr> invite_sdaddr;
	list<sInviteSD_Addr> rinvite_sdaddr;
	list<unsigned> invite_sdaddr_order;

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
	vmIP lastsrcip;
	vmIP lastdstip;
	vmPort lastsrcport;

	void *listening_worker_args;
	
	int ipport_n;				//!< last index of addr and port array 

	RTP *lastraw[2];

	string geoposition;

	/* obsolete
	map<string, string> custom_headers;
	*/
	map<int, map<int, dstring> > custom_headers_content_cdr;
	map<int, map<int, dstring> > custom_headers_content_message;
	volatile int _custom_headers_content_sync;

	volatile int _proxies_lock;
	list<vmIP> proxies;
	
	bool onInvite;
	bool onCall_2XX;
	bool onCall_18X;
	bool onHangup;
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
	
	u_int16_t vlan;

	unsigned int lastcallerssrc;
	unsigned int lastcalledssrc;

	map<string, sMergeLegInfo> mergecalls;
	volatile int _mergecalls_lock;

	bool rtp_zeropackets_stored;
	
	sRtcpXrData rtcpXrData;
	
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

	int get_index_by_ip_port(vmIP addr, vmPort port, bool use_sip_src_addr = false, bool rtcp = false);
	int get_index_by_sessid_to(char *sessid, char *to, vmIP sip_src_addr, ip_port_call_info::eTypeAddr type_addr);
	int get_index_by_iscaller(int iscaller);
	
	bool is_multiple_to_branch();
	bool all_invite_is_multibranch(vmIP saddr);
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
	bool read_rtp(struct packet_s *packetS, int iscaller, bool find_by_dest, bool stream_in_multiple_calls, s_sdp_flags_base sdp_flags, char enable_save_packet, char *ifname = NULL);
	inline bool _read_rtp(struct packet_s *packetS, int iscaller, s_sdp_flags_base sdp_flags, bool find_by_dest, bool stream_in_multiple_calls, char *ifname, bool *record_dtmf, bool *disable_save);
	inline void _save_rtp(packet_s *packetS, s_sdp_flags_base sdp_flags, char enable_save_packet, bool record_dtmf, u_int8_t forceVirtualUdp = false);

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
	int add_ip_port(vmIP sip_src_addr, vmIP addr, ip_port_call_info::eTypeAddr type_addr, vmPort port, struct timeval *ts, 
			char *sessid, char *sdp_label, 
			list<srtp_crypto_config> *srtp_crypto_config_list, string *srtp_fingerprint,
			char *to, char *branch, int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags);
	
	bool refresh_data_ip_port(vmIP addr, vmPort port, struct timeval *ts, 
				  list<srtp_crypto_config> *srtp_crypto_config_list, string *rtp_fingerprint,
				  int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags);
	
	void add_ip_port_hash(vmIP sip_src_addr, vmIP addr, ip_port_call_info::eTypeAddr type_addr, vmPort port, struct timeval *ts, 
			      char *sessid, char *sdp_label, bool multipleSdpMedia, 
			      list<srtp_crypto_config> *srtp_crypto_config_list, string *rtp_fingerprint,
			      char *to, char *branch, int iscaller, RTPMAP *rtpmap, s_sdp_flags sdp_flags);

	void cancel_ip_port_hash(vmIP sip_src_addr, char *to, char *branch, struct timeval *ts);
	
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
	
	void selectRtpAB();
 
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
	u_int64_t duration_us() { return((typeIs(MGCP) ? last_mgcp_connect_packet_time_us : get_last_packet_time_us()) - first_packet_time_us); };
	double duration_sf() { return(TIME_US_TO_SF(duration_us())); };
	u_int32_t duration_s() { return(TIME_US_TO_S(duration_us())); };
	u_int64_t connect_duration_us() { return(connect_time_us ? duration_us() - (connect_time_us - first_packet_time_us) : 0); };
	u_int32_t connect_duration_s() { return(TIME_US_TO_S(connect_duration_us())); };
	u_int64_t callend_us() { return calltime_us() + duration_us(); };
	u_int32_t callend_s() { return TIME_US_TO_S(callend_us()); };
	
	u_int32_t duration_active_s() { return(getGlobalPacketTimeS() - TIME_US_TO_S(first_packet_time_us)); };
	u_int32_t connect_duration_active_s() { return(connect_time_us ? duration_active_s() - TIME_US_TO_S(connect_time_us - first_packet_time_us) : 0); };
	
	/**
	 * @brief remove call from hash table
	 *
	*/
	void hashRemove(struct timeval *ts, bool useHashQueueCounter = false);
	
	void skinnyTablesRemove();
	
	void removeFindTables(struct timeval *ts, bool set_end_call = false, bool destroy = false);
	
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

	void evProcessRtpStream(int index_ip_port, bool by_dest, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time) {
		if(index_ip_port < ipport_n) {
			if(!ip_port[index_ip_port].rtp[by_dest].saddr.isSet()) {
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
				if(ip_port[index_ip_port].rtp[i].saddr.isSet()) {
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
				ip_port[index_ip_port].rtp[i].saddr.clear();
				ip_port[index_ip_port].rtp[i].sport.clear();
				ip_port[index_ip_port].rtp[i].daddr.clear();
				ip_port[index_ip_port].rtp[i].dport.clear();
				ip_port[index_ip_port].rtp[i].last_packet_time = 0;
			}
		}
	}
	void evStartRtpStream(int index_ip_port, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time);
	void evEndRtpStream(int index_ip_port, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport, time_t time);
	
	void addtocachequeue(string file);
	static void _addtocachequeue(string file);

	void addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, long long writeBytes);
	static void _addtofilesqueue(eTypeSpoolFile typeSpoolFile, string file, string dirnamesqlfiles, long long writeBytes, int spoolIndex);

	float mos_lqo(char *deg, int samplerate);

	void handle_dtmf(char dtmf, double dtmf_time, vmIP saddr, vmIP daddr, s_dtmf::e_type dtmf_type);
	
	void handle_dscp(struct iphdr2 *header_ip, bool iscaller);
	
	bool check_is_caller_called(const char *call_id, int sip_method, int cseq_method,
				    vmIP saddr, vmIP daddr, 
				    vmIP saddr_first, vmIP daddr_first, u_int8_t first_protocol,
				    vmPort sport, vmPort dport,  
				    int *iscaller, int *iscalled = NULL, bool enableSetSipcallerdip = false);
	bool is_sipcaller(vmIP saddr, vmPort sport, vmIP daddr, vmPort dport);
	bool is_sipcalled(vmIP daddr, vmPort dport, vmIP saddr, vmPort sport);
	bool use_both_side_for_check_direction() {
		extern bool opt_both_side_for_check_direction;
		return(opt_both_side_for_check_direction);
	}
	bool use_port_for_check_direction(vmIP /*addr*/) {
		return(true /*ip_is_localhost(addr)*/);
	}
	void check_reset_oneway(vmIP saddr, vmPort sport, vmIP daddr, vmPort dport) {
		if(oneway &&
		   (lastsrcip != saddr ||
		    (lastsrcip == lastdstip &&
		     use_port_for_check_direction(saddr) && 
		     lastsrcport != sport))) {
			for(list<sInviteSD_Addr>::iterator iter = invite_sdaddr.begin(); iter != invite_sdaddr.end(); iter++) {
				if(saddr == iter->saddr && daddr == iter->daddr &&
				   (!use_port_for_check_direction(saddr) ||
				    (sport == iter->sport && dport == iter->dport))) {
					return;
				}
			}
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
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(rtp_i && !rtp_i->graph.isClose()) {
				return(false);
			}
		}
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
		for(int i = 0; i < rtp_size(); i++) { RTP *rtp_i = rtp_stream_by_index(i);
			if(rtp_i && !rtp_i->graph.isClose()) {
				rtp_i->graph.close();
				callClose = true;
			}
		}
		return(callClose);
	}
	bool isReadyForWriteCdr() {
		return(isPcapsClose() && isGraphsClose() &&
		       isEmptyChunkBuffersCount());
	}
	
	u_int32_t getAllReceivedRtpPackets();
	
	void call_id_alternative_lock() {
		while(__sync_lock_test_and_set(&this->_call_id_alternative_lock, 1));
	}
	void call_id_alternative_unlock() {
		__sync_lock_release(&this->_call_id_alternative_lock);
	}
	
	void custom_headers_content_lock() {
		while(__sync_lock_test_and_set(&this->_custom_headers_content_sync, 1));
	}
	void custom_headers_content_unlock() {
		__sync_lock_release(&this->_custom_headers_content_sync);
	}
	
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
	
	void shift_destroy_call_at(u_int32_t time_s, int lastSIPresponseNum = 0) {
		extern int opt_quick_save_cdr;
		if(this->destroy_call_at > 0) {
			extern int opt_register_timeout;
			time_t new_destroy_call_at = 
				typeIs(REGISTER) ?
					time_s + opt_register_timeout :
					(this->seenbyeandok ?
						time_s + (opt_quick_save_cdr == 2 ? 0 :
							 (opt_quick_save_cdr ? 1 : 5)) :
					 this->seenbye ?
						time_s + 60 :
						time_s + (lastSIPresponseNum == 487 || this->lastSIPresponseNum == 487 ? 15 : 5));
			if(new_destroy_call_at > this->destroy_call_at) {
				this->destroy_call_at = new_destroy_call_at;
			}
		}
	}
	
	void applyRtcpXrDataToRtp();
	
	void adjustUA();
	
	bool is_set_proxies();
	void proxies_undup(set<vmIP> *proxies_undup);
	string get_proxies_str();

	void proxy_add(vmIP sipproxyip) {
		if(sipproxyip.isSet()) {
			proxies_lock();
			proxies.push_back(sipproxyip);
			proxies_unlock();
		}
	}
	bool in_proxy(vmIP ip) {
		proxies_lock();
		bool rslt = find(proxies.begin(), proxies.end(), ip) != proxies.end();
		proxies_unlock();
		return(rslt);
	}
	
	void createListeningBuffers();
	void destroyListeningBuffers();
	void disableListeningBuffers();
	
	bool checkKnownIP_inSipCallerdIP(vmIP ip) {
		for(int i = 0; i < MAX_SIPCALLERDIP; i++) {
			if(ip == sipcallerip[i] ||
			   ip == sipcalledip[i]) {
				return(true);
			}
		}
		return(false);
	}
	
	vmIP getSipcalledipConfirmed(vmPort *dport = NULL, vmIP *daddr_first = NULL, u_int8_t *daddr_first_protocol = NULL);
	unsigned getMaxRetransmissionInvite();
	
	void calls_counter_inc() {
		extern volatile int calls_counter;
		if(typeIs(INVITE) || typeIs(MESSAGE) || typeIs(MGCP)) {
			__sync_add_and_fetch(&calls_counter, 1);
			set_call_counter = true;
		}
	}
	void calls_counter_dec() {
		extern volatile int calls_counter;
		if(typeIs(INVITE) || typeIs(MESSAGE) || typeIs(MGCP)) {
			__sync_sub_and_fetch(&calls_counter, 1);
			set_call_counter = false;
		}
	}
	void registers_counter_inc() {
		extern volatile int registers_counter;
		__sync_add_and_fetch(&registers_counter, 1);
		set_register_counter = true;
	}
	void registers_counter_dec() {
		extern volatile int registers_counter;
		__sync_sub_and_fetch(&registers_counter, 1);
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
	
	bool isSetCallidMergeHeader() {
		extern char opt_callidmerge_header[128];
		return((typeIs(INVITE) || typeIs(MESSAGE)) &&
		       opt_callidmerge_header[0] != '\0');
	}
	void removeCallIdMap();
	void removeMergeCalls();
	void mergecalls_lock() {
		while(__sync_lock_test_and_set(&this->_mergecalls_lock, 1));
	}
	void mergecalls_unlock() {
		__sync_lock_release(&this->_mergecalls_lock);
	}
	
	inline void setSipcallerip(vmIP ip, vmIP ip_encaps, u_int8_t ip_encaps_prot, vmPort port, const char *call_id = NULL) {
		sipcallerip[0] = ip;
		sipcallerip_encaps = ip_encaps;
		sipcallerip_encaps_prot = ip_encaps_prot;
		sipcallerport[0] = port;
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			map_sipcallerdip[call_id].sipcallerip[0] = ip;
			map_sipcallerdip[call_id].sipcallerport[0] = port;
		}
	}
	inline void setSipcalledip(vmIP ip, vmIP ip_encaps, u_int8_t ip_encaps_prot, vmPort port, const char *call_id = NULL) {
		if(sipcalledip[0].isSet()) {
			sipcalledip_mod = ip;
			sipcalledport_mod = port;
		} else {
			sipcalledip[0] = ip;
			sipcalledport[0] = port;
		}
		sipcalledip_encaps = ip_encaps;
		sipcalledip_encaps_prot = ip_encaps_prot;
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			if(map_sipcallerdip[call_id].sipcalledip[0].isSet()) {
				map_sipcallerdip[call_id].sipcalledip_mod = ip;
				map_sipcallerdip[call_id].sipcalledport_mod = port;
			} else {
				map_sipcallerdip[call_id].sipcalledip[0] = ip;
				map_sipcallerdip[call_id].sipcalledport[0] = port;
			}
		}
	}
	vmIP getSipcallerip() {
		return(sipcallerip[0]);
	}
	vmIP getSipcallerip_encaps() {
		return(sipcallerip_encaps);
	}
	u_int8_t getSipcallerip_encaps_prot() {
		return(sipcallerip_encaps_prot);
	}
	vmIP getSipcalledip() {
		return(sipcalledip_mod.isSet() ? sipcalledip_mod : sipcalledip[0]);
	}
	vmIP getSipcalledip_encaps() {
		return(sipcalledip_encaps);
	}
	u_int8_t getSipcalledip_encaps_prot() {
		return(sipcalledip_encaps_prot);
	}
	vmPort getSipcallerport() {
		return(sipcallerport[0]);
	}
	vmPort getSipcalledport() {
		return(sipcalledport_mod.isSet() ? sipcalledport_mod : sipcalledport[0]);
	}
	void setSeenBye(bool seenbye, u_int64_t seenbye_time_usec, const char *call_id) {
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
	void setSeenByeAndOk(bool seenbyeandok, u_int64_t seenbyeandok_time_usec, const char *call_id) {
		this->seenbyeandok = seenbyeandok;
		if(seenbyeandok) {
			this->seenbyeandok_permanent = true;
		}
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
	void setSeenCancelAndOk(bool seencancelandok, u_int64_t seencancelandok_time_usec, const char *call_id) {
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
	void setSeenAuthFailed(bool seenauthfailed, u_int64_t seenauthfailed_time_usec, const char *call_id) {
		this->seenauthfailed = seenauthfailed;
		this->seenauthfailed_time_usec = seenauthfailed_time_usec;
		if(isSetCallidMergeHeader() &&
		   call_id && *call_id) {
			mergecalls_lock();
			if(mergecalls.find(call_id) != mergecalls.end()) {
				mergecalls[call_id].seenauthfailed = seenauthfailed;
				mergecalls[call_id].seenauthfailed_time_usec = seenauthfailed_time_usec;
			}
			mergecalls_unlock();
		}
	}
	u_int64_t getSeenByeTimeUS() {
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
	u_int64_t getSeenByeAndOkTimeUS() {
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
	u_int64_t getSeenCancelAndOkTimeUS() {
		if(isSetCallidMergeHeader()) {
			u_int64_t seencancelandok_time_usec = 0;
			mergecalls_lock();
			for(map<string, sMergeLegInfo>::iterator it = mergecalls.begin(); it != mergecalls.end(); ++it) {
				if(!it->second.seencancelandok || !it->second.seencancelandok_time_usec) {
					mergecalls_unlock();
					return(0);
				}
				if(seencancelandok_time_usec < it->second.seencancelandok_time_usec) {
					seencancelandok_time_usec = it->second.seencancelandok_time_usec;
				}
			}
			mergecalls_unlock();
			return(seencancelandok_time_usec);
		}
		return(seencancelandok ? seencancelandok_time_usec : 0);
	}
	u_int64_t getSeenAuthFailedTimeUS() {
		if(isSetCallidMergeHeader()) {
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
		return(seenauthfailed ? seenauthfailed_time_usec : 0);
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
	
	void add_txt(u_int64_t time, eTxtType type, const char *txt, unsigned txt_length);
	int detectCallerdByLabelInXml(const char *label);
	void txt_lock() {
		while(__sync_lock_test_and_set(&this->_txt_lock, 1));
	}
	void txt_unlock() {
		__sync_lock_release(&this->_txt_lock);
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
	
	static int getTableEnumIndex(string *table);
	
	bool isEmptyCdrRow() {
		return(cdr.isEmpty());
	}
	
	void addRegTcpSeq(u_int32_t seq) {
		if(seq) {
			if(!reg_tcp_seq) {
				reg_tcp_seq = new list<u_int32_t>;
			}
			reg_tcp_seq->push_back(seq);
		}
	}
	
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
	inline RTP *rtp_stream_by_index(unsigned index) {
		#if CALL_RTP_DYNAMIC_ARRAY
		if(index < MAX_SSRC_PER_CALL_FIX) {
			return(rtp_fix[index]);
		} else {
			return((*rtp_dynamic)[index - MAX_SSRC_PER_CALL_FIX]);
		}
		#else
		return(rtp_fix[index]);
		#endif
	}
	inline int rtp_size() {
		return(ssrc_n);
	}

private:
	ip_port_call_info ip_port[MAX_IP_PER_CALL];
	bool callerd_confirm_rtp_by_both_sides_sdp[2];
	bool exists_srtp;
	bool exists_srtp_crypto_config;
	bool exists_srtp_fingerprint;
	bool log_srtp_callid;
	PcapDumper pcap;
	PcapDumper pcapSip;
	PcapDumper pcapRtp;
	map<sStreamId, sUdptlDumper*> udptlDumpers;
	volatile int _hash_add_lock;
	int payload_rslt;
public:
	list<vmPort> sdp_ip0_ports[2];
	bool error_negative_payload_length;
	volatile int rtp_ip_port_counter;
	#if NEW_RTP_FIND__NODES
	list<vmIPport> rtp_ip_port_list;
	#endif
	volatile int hash_queue_counter;
	volatile int attemptsClose;
	volatile int useInListCalls;
	bool use_rtcp_mux;
	bool use_sdp_sendonly;
	bool rtp_from_multiple_sensors;
	bool sdp_exists_media_type_audio;
	bool sdp_exists_media_type_image;
	bool sdp_exists_media_type_video;
	bool sdp_exists_media_type_application;
	volatile int in_preprocess_queue_before_process_packet;
	volatile u_int32_t in_preprocess_queue_before_process_packet_at[2];
	bool suppress_rtp_read_due_to_insufficient_hw_performance;
	bool suppress_rtp_proc_due_to_insufficient_hw_performance;
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
	vector<d_item2<vmIPport, bool> > sdp_rows_list;
	bool set_call_counter;
	bool set_register_counter;
friend class RTP;
friend class RTPsecure;
};


void adjustSipResponse(string *sipResponse);
const char *adjustSipResponse(char *sipResponse, unsigned sipResponse_size, bool *adjustLength = NULL);
void adjustUA(string *ua);
const char *adjustUA(char *ua, unsigned ua_size, bool *adjustLength = NULL);

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
	inline cDbTablesContent* tables_content() { return((cDbTablesContent*)data); }
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
		vmIP addr;
		vmPort port;
		u_int32_t time_s;
		Call* call;
		int8_t iscaller;
		int8_t is_rtcp;
		s_sdp_flags sdp_flags;
		bool use_hash_queue_counter;
	};
	struct sChcThreadData {
		pthread_t thread;
		int tid;
		pstat_data pstat[2];
		sem_t sem[2];
		bool init;
		list<sChartsCallData> *calls;
		class cFiltersCache *cache;
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
	map<string, Call*> *calls_listMAP_X;
	map<sStreamIds2, Call*> calls_by_stream_callid_listMAP;
	map<sStreamId2, Call*> calls_by_stream_id2_listMAP;
	map<sStreamId, Call*> calls_by_stream_listMAP;
	map<string, Call*> calls_mergeMAP;
	map<string, Call*> registers_listMAP;
	map<d_item<vmIP>, Call*> skinny_ipTuples;
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
	void lock_calls_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_queue, 1)) USLEEP(10); /*pthread_mutex_lock(&qlock);*/ };
	void lock_calls_audioqueue() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_audioqueue, 1)) USLEEP(10); /*pthread_mutex_lock(&qaudiolock);*/ };
	void lock_calls_charts_cache_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_charts_cache_queue, 1)) USLEEP(10); /*pthread_mutex_lock(&qaudiolock);*/ };
	void lock_calls_deletequeue() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_deletequeue, 1)) USLEEP(10); /*pthread_mutex_lock(&qdellock);*/ };
	void lock_registers_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_registers_queue, 1)) USLEEP(10); };
	void lock_registers_deletequeue() { while(__sync_lock_test_and_set(&this->_sync_lock_registers_deletequeue, 1)) USLEEP(10); };
	void lock_files_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_files_queue, 1)) USLEEP(10); /*pthread_mutex_lock(&flock);*/ };
	void lock_calls_listMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_listMAP, 1)) USLEEP(10); /*pthread_mutex_lock(&calls_listMAPlock);*/ };
	void lock_calls_listMAP_X(u_int8_t ci) { while(__sync_lock_test_and_set(&this->_sync_lock_calls_listMAP_X[ci], 1)) USLEEP(10); };
	void lock_calls_mergeMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_calls_mergeMAP, 1)) USLEEP(10); /*pthread_mutex_lock(&calls_mergeMAPlock);*/ };
	void lock_registers_listMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_registers_listMAP, 1)) USLEEP(10); /*pthread_mutex_lock(&registers_listMAPlock);*/ };
	void lock_skinny_maps() { while(__sync_lock_test_and_set(&this->_sync_lock_skinny_maps, 1)) USLEEP(10); /*pthread_mutex_lock(&registers_listMAPlock);*/ };
	void lock_ss7_listMAP() { while(__sync_lock_test_and_set(&this->_sync_lock_ss7_listMAP, 1)) USLEEP(10); }
	void lock_process_ss7_listmap() { while(__sync_lock_test_and_set(&this->_sync_lock_process_ss7_listmap, 1)) USLEEP(10); }
	void lock_process_ss7_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_process_ss7_queue, 1)) USLEEP(10); }
	void lock_hash_modify_queue() { while(__sync_lock_test_and_set(&this->_sync_lock_hash_modify_queue, 1)) USLEEP(10); }

	/**
	 * @brief unlock calls_queue structure 
	 *
	*/
	void unlock_calls_queue() { __sync_lock_release(&this->_sync_lock_calls_queue); /*pthread_mutex_unlock(&qlock);*/ };
	void unlock_calls_audioqueue() { __sync_lock_release(&this->_sync_lock_calls_audioqueue); /*pthread_mutex_unlock(&qaudiolock);*/ };
	void unlock_calls_charts_cache_queue() { __sync_lock_release(&this->_sync_lock_calls_charts_cache_queue); /*pthread_mutex_unlock(&qcharts_chache_lock);*/ };
	void unlock_calls_deletequeue() { __sync_lock_release(&this->_sync_lock_calls_deletequeue); /*pthread_mutex_unlock(&qdellock);*/ };
	void unlock_registers_queue() { __sync_lock_release(&this->_sync_lock_registers_queue); };
	void unlock_registers_deletequeue() { __sync_lock_release(&this->_sync_lock_registers_deletequeue); };
	void unlock_files_queue() { __sync_lock_release(&this->_sync_lock_files_queue); /*pthread_mutex_unlock(&flock);*/ };
	void unlock_calls_listMAP() { __sync_lock_release(&this->_sync_lock_calls_listMAP); /*pthread_mutex_unlock(&calls_listMAPlock);*/ };
	void unlock_calls_listMAP_X(u_int8_t ci) { __sync_lock_release(&this->_sync_lock_calls_listMAP_X[ci]); };
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
	Call *add(int call_type, char *call_id, unsigned long call_id_len, vector<string> *call_id_alternative,
		  u_int64_t time_us, vmIP saddr, vmPort port, 
		  pcap_t *handle, int dlt, int sensorId, int8_t ci = -1);
	Ss7 *add_ss7(packet_s_stack *packetS, Ss7::sParseData *data);
	Call *add_mgcp(sMgcpRequest *request, time_t time, vmIP saddr, vmPort sport, vmIP daddr, vmPort dport,
		       pcap_t *handle, int dlt, int sensorId);
	
	size_t getCountCalls();
	bool enableCallX();
	bool useCallX();
	bool enableCallFindX();
	bool useCallFindX();

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
			if(time) {
				__sync_add_and_fetch(&rslt_call->in_preprocess_queue_before_process_packet, 1);
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
		}
		unlock_calls_listMAP();
		return(rslt_call);
	}
	Call *find_by_call_id_x(u_int8_t ci, char *call_id, unsigned long call_id_len, time_t time) {
		Call *rslt_call = NULL;
		string call_idS = call_id_len ? string(call_id, call_id_len) : string(call_id);
		lock_calls_listMAP_X(ci);
		map<string, Call*>::iterator callMAPIT = calls_listMAP_X[ci].find(call_idS);
		if(callMAPIT != calls_listMAP_X[ci].end()) {
			rslt_call = callMAPIT->second;
			if(time) {
				__sync_add_and_fetch(&rslt_call->in_preprocess_queue_before_process_packet, 1);
				rslt_call->in_preprocess_queue_before_process_packet_at[0] = time;
				rslt_call->in_preprocess_queue_before_process_packet_at[1] = getTimeMS_rdtsc() / 1000;
			}
		}
		unlock_calls_listMAP_X(ci);
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
			if(!rslt_call && useCallFindX()) {
				extern int preProcessPacketCallX_count;
				for(int i = 0; i < preProcessPacketCallX_count && !rslt_call; i++) {
					if(lock) lock_calls_listMAP_X(i);
					for(map<string, Call*>::iterator iter = calls_listMAP_X[i].begin(); iter != calls_listMAP_X[i].end(); iter++) {
						if((long long)(iter->second) == callreference) {
							rslt_call = iter->second;
							break;
						}
					}
					if(lock) unlock_calls_listMAP_X(i);
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
	int cleanup_calls( struct timeval *currtime, bool forceClose = false, const char *file = NULL, int line = 0);
	int cleanup_registers( struct timeval *currtime);
	int cleanup_ss7( struct timeval *currtime );

	/**
	 * @brief add call to hash table
	 *
	*/
	void hashAdd(vmIP addr, vmPort port, struct timeval *ts, Call* call, int iscaller, int isrtcp, s_sdp_flags sdp_flags);
	inline void _hashAdd(vmIP addr, vmPort port, long int time_s, Call* call, int iscaller, int isrtcp, s_sdp_flags sdp_flags, bool use_lock = true);

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
				if ((node->addr == addr) && (node->port == port)) {
					rslt = 
					       #if HASH_RTP_FIND__LIST
					       &
					       #endif
					       node->calls;
				}
			}
			if(lock) {
				unlock_calls_hash();
			}
		#endif
		return rslt;
	}
	inline bool check_call_in_hashfind_by_ip_port(Call *call, vmIP addr, vmPort port, bool lock = true) {
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
					if(n_call->call == call) {
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
	inline s_sdp_flags *get_sdp_flags_in_hashfind_by_ip_port(Call *call, vmIP addr, vmPort port, bool lock = true) {
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
					if(n_call->call == call) {
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
	void hashRemove(Call *call, vmIP addr, vmPort port, struct timeval *ts, bool rtcp = false, bool useHashQueueCounter = true);
	inline int _hashRemove(Call *call, vmIP addr, vmPort port, bool rtcp = false, bool use_lock = true);
	int hashRemove(Call *call, struct timeval *ts, bool useHashQueueCounter = true);
	int hashRemoveForce(Call *call);
	inline int _hashRemove(Call *call, bool use_lock = true);
	void applyHashModifyQueue(struct timeval *ts, bool setBegin, bool use_lock_calls_hash = true);
	inline void _applyHashModifyQueue(struct timeval *ts, bool setBegin, bool use_lock_calls_hash = true);
	string getHashStats();
	
	void processCallsInAudioQueue(bool lock = true);
	static void *processAudioQueueThread(void *);
	size_t getCountAudioQueueThreads() {
		return(audioQueueThreads.size());
	}
	void setAudioQueueTerminating() {
		audioQueueTerminating = 1;
	}
	
	void processCallsInChartsCache_start();
	void processCallsInChartsCache_stop();
	void processCallsInChartsCache_thread(int threadIndex);
	static void *_processCallsInChartsCache_thread(void *_threadIndex);
	void processCallsInChartsCache_thread_add();
	void processCallsInChartsCache_thread_remove();
	string processCallsInChartsCache_cpuUsagePerc(double *avg);

	void destroyCallsIfPcapsClosed();
	void destroyRegistersIfPcapsClosed();
	
	void mgcpCleanupTransactions(Call *call);
	void mgcpCleanupStream(Call *call);
	
	string getCallTableJson(char *params, bool *zip = NULL);
	
	void lock_calls_hash() {
		unsigned int usleepCounter = 0;
		while(__sync_lock_test_and_set(&this->_sync_lock_calls_hash, 1)) {
			USLEEP_C(10, usleepCounter++);
		}
	}
	void unlock_calls_hash() {
		__sync_lock_release(&this->_sync_lock_calls_hash);
	}
	
	void addSystemCommand(const char *command);
	
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
	node_call_rtp_ip_port *calls_hash[MAXNODE];
	#endif
	volatile int _sync_lock_calls_hash;
	volatile int _sync_lock_calls_listMAP;
	volatile int *_sync_lock_calls_listMAP_X;
	volatile int _sync_lock_calls_mergeMAP;
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
	
	list<sAudioQueueThread*> audioQueueThreads;
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
		bool doNotAddColon;
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
	unsigned long getLoadTime() {
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
	string getValue(Call *call, int type, const char *header);
	static string tCH_Content_value(tCH_Content *ch_content, int i1, int i2);
	unsigned getSize();
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
	map<int, bool> calldate_ms;
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

string printCallFlags(unsigned long int flags);
eCallField convCallFieldToFieldId(const char *field);
int convCallFieldToFieldIndex(eCallField field);

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
