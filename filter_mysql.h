#ifndef FILTER_MYSQL_H
#define FILTER_MYSQL_H


#include <cstdlib>
#include <iostream>
#include <string>
#include <cmath>
#include <map>
#include <vector>
#include <deque>
#include <deque>

#include "calltable.h"
#include "sniff.h"

enum eCaptBitFlag {
	_CAPT_BIT_RTP_ALL,
	_CAPT_BIT_RTP_HEADER,
	_CAPT_BIT_NORTP,
	_CAPT_BIT_RTP_VIDEO_ALL,
	_CAPT_BIT_RTP_VIDEO_HEADER,
	_CAPT_BIT_RTP_VIDEO_CDR_ONLY,
	_CAPT_BIT_NORTP_VIDEO,
	_CAPT_BIT_MRCP,
	_CAPT_BIT_NOMRCP,
	_CAPT_BIT_RTCP,
	_CAPT_BIT_NORTCP,
	_CAPT_BIT_SIP,
	_CAPT_BIT_NOSIP,
	_CAPT_BIT_REGISTER_DB,
	_CAPT_BIT_NOREGISTER_DB,
	_CAPT_BIT_REGISTER_PCAP,
	_CAPT_BIT_NOREGISTER_PCAP,
	_CAPT_BIT_GRAPH,
	_CAPT_BIT_NOGRAPH,
	_CAPT_BIT_AUDIO,
	_CAPT_BIT_AUDIO_WAV,
	_CAPT_BIT_AUDIO_OGG,
	_CAPT_BIT_AUDIO_MP3,
	_CAPT_BIT_NOWAV,
	_CAPT_BIT_AUDIO_TRANSCRIBE,
	_CAPT_BIT_NO_AUDIO_TRANSCRIBE,
	_CAPT_BIT_AUDIOGRAPH,
	_CAPT_BIT_NO_AUDIOGRAPH,
	_CAPT_BIT_SKIP,
	_CAPT_BIT_NOSKIP,
	_CAPT_BIT_SCRIPT,
	_CAPT_BIT_NOSCRIPT,
	_CAPT_BIT_AMOSLQO,
	_CAPT_BIT_BMOSLQO,
	_CAPT_BIT_ABMOSLQO,
	_CAPT_BIT_NOMOSLQO,
	_CAPT_BIT_HIDEMSG,
	_CAPT_BIT_SHOWMSG,
	_CAPT_BIT_SPOOL_2_SET,
	_CAPT_BIT_SPOOL_2_UNSET,
	_CAPT_BIT_DTMF_DB,
	_CAPT_BIT_NODTMF_DB,
	_CAPT_BIT_DTMF_PCAP,
	_CAPT_BIT_NODTMF_PCAP,
	_CAPT_BIT_OPTIONS_DB,
	_CAPT_BIT_NOOPTIONS_DB,
	_CAPT_BIT_OPTIONS_PCAP,
	_CAPT_BIT_NOOPTIONS_PCAP,
	_CAPT_BIT_NOTIFY_DB,
	_CAPT_BIT_NONOTIFY_DB,
	_CAPT_BIT_NOTIFY_PCAP,
	_CAPT_BIT_NONOTIFY_PCAP,
	_CAPT_BIT_SUBSCRIBE_DB,
	_CAPT_BIT_NOSUBSCRIBE_DB,
	_CAPT_BIT_SUBSCRIBE_PCAP,
	_CAPT_BIT_NOSUBSCRIBE_PCAP
};

#define CAPT_FLAG(bit) (((u_int64_t)1) << (bit))

#define MAX_PREFIX 64

struct filter_db_row_base {
	filter_db_row_base() {
		direction = 0;
		rtp = 0;
		rtp_video = 0;
		mrcp = 0;
		rtcp = 0;
		sip = 0;
		reg = 0;
		graph = 0;
		wav = 0;
		audio_transcribe = 0;
		audiograph = 0;
		skip = 0;
		mos_lqo = 0;
		script = 0;
		hide_message = 0;
		spool_2 = 0;
		dtmf = 0;
		options = 0;
		notify = 0;
		subscribe = 0;
	}
	int direction;
	int rtp;
	int rtp_video;
	int mrcp;
	int rtcp;
	int sip;
	int reg;
	int graph;
	int wav;
	int audio_transcribe;
	int audiograph;
	int skip;
	int mos_lqo;
	int script;
	int hide_message;
	int spool_2;
	int dtmf;
	int options;
	int notify;
	int subscribe;
	string natalias;
	bool natalias_inheritance;
};

class filter_base {
protected:
	string _string(SqlDb_row *sqlRow, map<string, string> *row, const char *column);
	bool _value_is_null(SqlDb_row *sqlRow, map<string, string> *row, const char *column);
	int _value(SqlDb_row *sqlRow, map<string, string> *row, const char *column);
	void _loadBaseDataRow(SqlDb_row *sqlRow, map<string, string> *row, filter_db_row_base *baseRow);
	void loadBaseDataRow(SqlDb_row *sqlRow, filter_db_row_base *baseRow);
	void loadBaseDataRow(map<string, string> *row, filter_db_row_base *baseRow);
	u_int64_t getFlagsFromBaseData(filter_db_row_base *baseRow, u_int32_t *global_flags);
	void parseNatAliases(filter_db_row_base *baseRow, nat_aliases_t **nat_aliases);
	void setCallFlagsFromFilterFlags(volatile unsigned long int *callFlags, u_int64_t filterFlags, bool reconfigure = false);
};

class IPfilter : public filter_base {
private:
	struct db_row : filter_db_row_base {
		db_row() {
			ip.clear();
			mask = 0;
		}
		vmIP ip;
		int mask;
	};
        struct t_node {
		t_node() {
			mask = 0;
			direction = 0;
			flags = 0;
			nat_aliases = NULL;
			nat_aliases_inheritance = false;
			next = NULL;
		}
		~t_node() {
			if(nat_aliases) {
				delete nat_aliases;
			}
		}
		vmIP network;
		int mask;
		int direction;
		u_int64_t flags;
		nat_aliases_t *nat_aliases;
		bool nat_aliases_inheritance;
                t_node *next;
        };
        t_node *first_node;
public: 
        IPfilter();
        ~IPfilter();
        void load(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	int _add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, vmIP saddr, vmIP daddr, bool reconfigure = false);
        static void dump2man(ostringstream &oss);
	static int add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, vmIP saddr, vmIP daddr, bool reconfigure = false);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static void lock() {
		__SYNC_LOCK(_sync);
	}
	static void unlock() {
		__SYNC_UNLOCK(_sync);
	}
	static void lock_reload() {
		__SYNC_LOCK(_sync_reload);
	}
	static void unlock_reload() {
		__SYNC_UNLOCK(_sync_reload);
	}
private:
	int count;
	static IPfilter *filter_active;
	static IPfilter *filter_reload;
	static volatile bool reload_do;
	static volatile int _sync;
	static volatile int _sync_reload;
};

class TELNUMfilter : public filter_base {
private:
	struct db_row : filter_db_row_base {
		db_row() {
			memset(prefix, 0, sizeof(prefix));
		}
		char prefix[MAX_PREFIX];
	};
	struct t_payload {
		t_payload() {
			direction = 0;
			flags = 0;
			nat_aliases = NULL;
		}
		~t_payload() {
			if(nat_aliases) {
				delete nat_aliases;
			}
		}
		char prefix[MAX_PREFIX];
		int direction;
		u_int64_t flags;
		nat_aliases_t *nat_aliases;
	};
        struct t_node_tel {
                t_node_tel *nodes[256];
                t_payload *payload;
        };
        t_node_tel *first_node;
public: 
        TELNUMfilter();
        ~TELNUMfilter();
        void load(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	void loadFile(u_int32_t *global_flags);
	void add_payload(t_payload *payload);
	int _add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *telnum_src, const char *telnum_dst, bool reconfigure = false);
        static void dump2man(ostringstream &oss, t_node_tel *node = NULL);
	static int add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *telnum_src, const char *telnum_dst, bool reconfigure = false);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static void lock() {
		__SYNC_LOCK(_sync);
	}
	static void unlock() {
		__SYNC_UNLOCK(_sync);
	}
	static void lock_reload() {
		__SYNC_LOCK(_sync_reload);
	}
	static void unlock_reload() {
		__SYNC_UNLOCK(_sync_reload);
	}
private:
	int count;
	static TELNUMfilter *filter_active;
	static TELNUMfilter *filter_reload;
	static volatile bool reload_do;
	static volatile int _sync;
	static volatile int _sync_reload;
};

class DOMAINfilter : public filter_base {
private:
	struct db_row : filter_db_row_base{
		db_row() {
		}
		std::string domain;
	};
        struct t_node {
		t_node() {
			direction = 0;
			flags = 0;
			nat_aliases = NULL;
			next = NULL;
		}
		~t_node() {
			if(nat_aliases) {
				delete nat_aliases;
			}
		}
		std::string domain;
		int direction;
		u_int64_t flags;
		nat_aliases_t *nat_aliases;
		t_node *next;
	};
	t_node *first_node;
public: 
	DOMAINfilter();
	~DOMAINfilter();
	void load(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	int _add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *domain_src, const char *domain_dst, bool reconfigure = false);
        static void dump2man(ostringstream &oss);
	static int add_call_flags(volatile unsigned long int *flags, nat_aliases_t **nat_aliases, const char *domain_src, const char *domain_dst, bool reconfigure = false);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static void lock() {
		__SYNC_LOCK(_sync);
	}
	static void unlock() {
		__SYNC_UNLOCK(_sync);
	}
	static void lock_reload() {
		__SYNC_LOCK(_sync_reload);
	}
	static void unlock_reload() {
		__SYNC_UNLOCK(_sync_reload);
	}
private:
	int count;
	static DOMAINfilter *filter_active;
	static DOMAINfilter *filter_reload;
	static volatile bool reload_do;
	static volatile int _sync;
	static volatile int _sync_reload;
};

class SIP_HEADERfilter : public filter_base {
private:
	struct db_row : filter_db_row_base{
		db_row() {
		}
		std::string header;
		std::string content;
		bool prefix;
		bool regexp;
	};
        struct item_data {
		item_data() {
			direction = 0;
			prefix = false;
			regexp = false;
			flags = 0;
			nat_aliases = NULL;
		}
		~item_data() {
			if(nat_aliases) {
				delete nat_aliases;
			}
		}
		int direction;
		bool prefix;
		bool regexp;
		u_int64_t flags;
		nat_aliases_t *nat_aliases;
	};
	struct header_data {
		void clean() {
			for(map<std::string, item_data*>::iterator iter = strict_prefix.begin(); iter != strict_prefix.end(); iter++) {
				delete iter->second;
			}
			for(map<std::string, item_data*>::iterator iter = regexp.begin(); iter != regexp.end(); iter++) {
				delete iter->second;
			}
		}
		std::map<std::string, item_data*> strict_prefix;
		std::map<std::string, item_data*> regexp;
	};
	std::map<std::string, header_data> data;
public: 
	SIP_HEADERfilter();
	~SIP_HEADERfilter();
	void load(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	void loadFile(u_int32_t *global_flags);
	int _add_call_flags(struct ParsePacket::ppContentsX *parseContents, volatile unsigned long int *flags, nat_aliases_t **nat_aliases, bool reconfigure = false);
        static void dump2man(ostringstream &oss);
	void _prepareCustomNodes(ParsePacket *parsePacket);
	static int add_call_flags(struct ParsePacket::ppContentsX *parseContents, volatile unsigned long int *flags, nat_aliases_t **nat_aliases, bool reconfigure = false);
	static void prepareCustomNodes(ParsePacket *parsePacket);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static inline unsigned long getLoadTime() {
		return(loadTime);
	}
	static void lock() {
		__SYNC_LOCK(_sync);
	}
	static void unlock() {
		__SYNC_UNLOCK(_sync);
	}
	static void lock_reload() {
		__SYNC_LOCK(_sync_reload);
	}
	static void unlock_reload() {
		__SYNC_UNLOCK(_sync_reload);
	}
private:
	int count;
	static SIP_HEADERfilter *filter_active;
	static SIP_HEADERfilter *filter_reload;
	static volatile bool reload_do;
	static volatile unsigned long loadTime;
	static volatile int _sync;
	static volatile int _sync_reload;
};

class cFilters {
public:
	enum eGlobalFlags {
		_gf_mrcp = 1 << 0
	};
public:
	static void loadActive(SqlDb *sqlDb = NULL);
	static void prepareReload(SqlDb *sqlDb = NULL);
	static void applyReload();
	static void freeActive();
	static void lock_reload() {
		__SYNC_LOCK(_sync_reload);
	}
	static void unlock_reload() {
		__SYNC_UNLOCK(_sync_reload);
	}
	static inline u_int32_t getGlobalFlags() {
		return(global_flags);
	}
	static inline bool saveMrcp() {
		extern int opt_saveMRCP;
		return(opt_saveMRCP ||
		       (getGlobalFlags() & _gf_mrcp));
	}
public:
	static u_int32_t global_flags;
	static u_int32_t reload_global_flags;
	static volatile bool reload_do;
	static volatile int _sync_reload;
};

inline void set_global_flags(volatile unsigned long int &flags) {
	extern int opt_saveSIP;
	extern int opt_saveRTP;
	extern int opt_onlyRTPheader;
	extern int opt_saveRTPvideo;
	extern int opt_saveRTPvideo_only_header;
	extern int opt_processingRTPvideo;
	extern int opt_saveMRCP;
	extern int opt_saveRTCP;
	extern int opt_saveWAV;
	extern int opt_save_audiograph;
	extern int opt_audio_transcribe;
	extern int opt_audio_format;
	extern int opt_saveGRAPH;
	extern int opt_skipdefault;
	extern int opt_hide_message_content;
	extern int opt_dbdtmf;
	extern int opt_pcapdtmf;
	extern bool opt_sip_register_save_all;
	extern int opt_sip_options;
	extern int opt_sip_subscribe;
	extern int opt_sip_notify;
	extern int opt_save_sip_options;
	extern int opt_save_sip_subscribe;
	extern int opt_save_sip_notify;
	extern int opt_save_sip_register;
	extern int opt_sip_register;

	if(opt_saveSIP) {
		flags |= FLAG_SAVESIP;
	}
	if(opt_saveRTP) {
		flags |= FLAG_SAVERTP;
	}
	if(opt_onlyRTPheader) {
		flags |= FLAG_SAVERTPHEADER;
	}
	if(opt_saveRTPvideo) {
		flags |= FLAG_SAVERTP_VIDEO | FLAG_PROCESSING_RTP_VIDEO;
	}
	if(opt_saveRTPvideo_only_header) {
		flags |= FLAG_SAVERTP_VIDEO_HEADER | FLAG_PROCESSING_RTP_VIDEO;
	}
	if(opt_processingRTPvideo) {
		flags |= FLAG_PROCESSING_RTP_VIDEO;
	}
	if(opt_saveMRCP) {
		flags |= FLAG_SAVEMRCP;
	}
	if(opt_saveRTCP) {
		flags |= FLAG_SAVERTCP;
	}
	if(opt_saveWAV) {
		flags |= (opt_audio_format == FORMAT_OGG ? FLAG_SAVEAUDIO_OGG : 
			  opt_audio_format == FORMAT_MP3 ? 
							   #if HAVE_LIBLAME && HAVE_LIBMPG123
							   FLAG_SAVEAUDIO_MP3
							   #else
							   FLAG_SAVEAUDIO_OGG
							   #endif
			  : FLAG_SAVEAUDIO_WAV);
	}
	if(opt_save_audiograph) {
		flags |= FLAG_SAVEAUDIOGRAPH;
	}
	if(opt_audio_transcribe) {
		flags |= FLAG_AUDIOTRANSCRIBE;
	}
	if(opt_saveGRAPH) {
		flags |= FLAG_SAVEGRAPH;
	}
	if(opt_skipdefault) {
		flags |= FLAG_SKIPCDR;
	}
	if(opt_hide_message_content) {
		flags |= FLAG_HIDEMESSAGE;
	}
	if (opt_dbdtmf) {
		flags |= FLAG_SAVEDTMFDB;
	}
	if (opt_pcapdtmf) {
		flags |= FLAG_SAVEDTMFPCAP;
	}
	if (opt_sip_register == 1) {
		flags |= FLAG_SAVEREGISTERDB;
	}
	if (opt_sip_register && opt_save_sip_register) {
		flags |= FLAG_SAVEREGISTERPCAP;
	}
	if(opt_sip_register_save_all) {
		flags |=  FLAG_SAVEREGISTERDB | FLAG_SAVEREGISTERPCAP;
	}
	if (opt_sip_options == 1) {
		flags |= FLAG_SAVEOPTIONSDB;
	}
	if (opt_sip_options && opt_save_sip_options) {
		flags |= FLAG_SAVEOPTIONSPCAP;
	}
	if (opt_sip_notify == 1) {
		flags |= FLAG_SAVENOTIFYDB;
	}
	if (opt_sip_notify && opt_save_sip_notify) {
		flags |= FLAG_SAVENOTIFYPCAP;
	}
	if (opt_sip_subscribe == 1) {
		flags |= FLAG_SAVESUBSCRIBEDB;
	}
	if (opt_sip_subscribe && opt_save_sip_subscribe) {
		flags |= FLAG_SAVESUBSCRIBEPCAP;
	}
}


inline void comb_nat_aliases(nat_aliases_t *src, nat_aliases_t **dst) {
	if(!src || !dst) {
		return;
	}
	if(!*dst) {
		*dst = new FILE_LINE(0) nat_aliases_t;
	}
	for(nat_aliases_t::iterator iter = src->begin(); iter != src->end(); iter++) {
		(**dst)[iter->first] = iter->second;
	}
}


#endif //FILTER_MYSQL_H
