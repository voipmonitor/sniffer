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

#define _FLAG_RTP_ALL			(((u_int64_t)1) << 0)
#define _FLAG_RTP_HEADER		(((u_int64_t)1) << 1)
#define _FLAG_NORTP      		(((u_int64_t)1) << 2)
#define _FLAG_RTP_VIDEO_ALL		(((u_int64_t)1) << 3)
#define _FLAG_RTP_VIDEO_HEADER		(((u_int64_t)1) << 4)
#define _FLAG_RTP_VIDEO_CDR_ONLY	(((u_int64_t)1) << 5)
#define _FLAG_NORTP_VIDEO      		(((u_int64_t)1) << 6)
#define _FLAG_MRCP			(((u_int64_t)1) << 7)
#define _FLAG_NOMRCP     		(((u_int64_t)1) << 8)
#define _FLAG_RTCP			(((u_int64_t)1) << 9)
#define _FLAG_NORTCP     		(((u_int64_t)1) << 10)
#define _FLAG_SIP			(((u_int64_t)1) << 11)
#define _FLAG_NOSIP      		(((u_int64_t)1) << 12)
#define _FLAG_REGISTER			(((u_int64_t)1) << 13)
#define _FLAG_NOREGISTER		(((u_int64_t)1) << 14)
#define _FLAG_GRAPH			(((u_int64_t)1) << 15)
#define _FLAG_NOGRAPH    		(((u_int64_t)1) << 16)
#define _FLAG_AUDIO			(((u_int64_t)1) << 17)
#define _FLAG_AUDIO_WAV			(((u_int64_t)1) << 18)
#define _FLAG_AUDIO_OGG			(((u_int64_t)1) << 19)
#define _FLAG_NOWAV      		(((u_int64_t)1) << 20)
#define _FLAG_SKIP       		(((u_int64_t)1) << 21)
#define _FLAG_NOSKIP     		(((u_int64_t)1) << 22)
#define _FLAG_SCRIPT     		(((u_int64_t)1) << 23)
#define _FLAG_NOSCRIPT   		(((u_int64_t)1) << 24)
#define _FLAG_AMOSLQO    		(((u_int64_t)1) << 25)
#define _FLAG_BMOSLQO    		(((u_int64_t)1) << 26)
#define _FLAG_ABMOSLQO   		(((u_int64_t)1) << 27)
#define _FLAG_NOMOSLQO   		(((u_int64_t)1) << 28)
#define _FLAG_HIDEMSG			(((u_int64_t)1) << 29)
#define _FLAG_SHOWMSG			(((u_int64_t)1) << 30)
#define _FLAG_SPOOL_2_SET		(((u_int64_t)1) << 31)
#define _FLAG_SPOOL_2_UNSET		(((u_int64_t)1) << 32)
#define _FLAG_DTMF_DB			(((u_int64_t)1) << 33)
#define _FLAG_NODTMF_DB			(((u_int64_t)1) << 34)
#define _FLAG_DTMF_PCAP			(((u_int64_t)1) << 35)
#define _FLAG_NODTMF_PCAP		(((u_int64_t)1) << 36)
#define _FLAG_OPTIONS_DB		(((u_int64_t)1) << 37)
#define _FLAG_NOOPTIONS_DB		(((u_int64_t)1) << 38)
#define _FLAG_OPTIONS_PCAP		(((u_int64_t)1) << 39)
#define _FLAG_NOOPTIONS_PCAP		(((u_int64_t)1) << 40)
#define _FLAG_NOTIFY_DB			(((u_int64_t)1) << 41)
#define _FLAG_NONOTIFY_DB		(((u_int64_t)1) << 42)
#define _FLAG_NOTIFY_PCAP		(((u_int64_t)1) << 43)
#define _FLAG_NONOTIFY_PCAP		(((u_int64_t)1) << 44)
#define _FLAG_SUBSCRIBE_DB		(((u_int64_t)1) << 45)
#define _FLAG_NOSUBSCRIBE_DB		(((u_int64_t)1) << 46)
#define _FLAG_SUBSCRIBE_PCAP		(((u_int64_t)1) << 47)
#define _FLAG_NOSUBSCRIBE_PCAP		(((u_int64_t)1) << 48)

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
	int skip;
	int mos_lqo;
	int script;
	int hide_message;
	int spool_2;
	int dtmf;
	int options;
	int notify;
	int subscribe;
};

class filter_base {
protected:
	bool _value_is_null(SqlDb_row *sqlRow, map<string, string> *row, const char *column);
	int _value(SqlDb_row *sqlRow, map<string, string> *row, const char *column);
	void _loadBaseDataRow(SqlDb_row *sqlRow, map<string, string> *row, filter_db_row_base *baseRow);
	void loadBaseDataRow(SqlDb_row *sqlRow, filter_db_row_base *baseRow);
	void loadBaseDataRow(map<string, string> *row, filter_db_row_base *baseRow);
	u_int64_t getFlagsFromBaseData(filter_db_row_base *baseRow, u_int32_t *global_flags);
	void setCallFlagsFromFilterFlags(volatile unsigned long int *callFlags, u_int64_t filterFlags);
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
		vmIP network;
		int mask;
		int direction;
		u_int64_t flags;
                t_node *next;
        };
        t_node *first_node;
public: 
        IPfilter();
        ~IPfilter();
        void load(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	int _add_call_flags(volatile unsigned long int *flags, vmIP saddr, vmIP daddr);
        static void dump2man(ostringstream &oss);
	static int add_call_flags(volatile unsigned long int *flags, vmIP saddr, vmIP daddr);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	static void unlock() {
		__sync_lock_release(&_sync);
	}
	static void lock_reload() {
		while(__sync_lock_test_and_set(&_sync_reload, 1));
	}
	static void unlock_reload() {
		__sync_lock_release(&_sync_reload);
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
		char prefix[MAX_PREFIX];
		int direction;
		unsigned int ip;
		int mask;
		u_int64_t flags;
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
	int _add_call_flags(volatile unsigned long int *flags, const char *telnum_src, const char *telnum_dst);
        static void dump2man(ostringstream &oss, t_node_tel *node = NULL);
	static int add_call_flags(volatile unsigned long int *flags, const char *telnum_src, const char *telnum_dst);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	static void unlock() {
		__sync_lock_release(&_sync);
	}
	static void lock_reload() {
		while(__sync_lock_test_and_set(&_sync_reload, 1));
	}
	static void unlock_reload() {
		__sync_lock_release(&_sync_reload);
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
		std::string domain;
		int direction;
		u_int64_t flags;
		t_node *next;
	};
	t_node *first_node;
public: 
	DOMAINfilter();
	~DOMAINfilter();
	void load(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	int _add_call_flags(volatile unsigned long int *flags, const char *domain_src, const char *domain_dst);
        static void dump2man(ostringstream &oss);
	static int add_call_flags(volatile unsigned long int *flags, const char *domain_src, const char *domain_dst);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	static void unlock() {
		__sync_lock_release(&_sync);
	}
	static void lock_reload() {
		while(__sync_lock_test_and_set(&_sync_reload, 1));
	}
	static void unlock_reload() {
		__sync_lock_release(&_sync_reload);
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
		int direction;
		bool prefix;
		bool regexp;
		u_int64_t flags;
	};
	struct header_data {
		std::map<std::string, item_data> strict_prefix;
		std::map<std::string, item_data> regexp;
	};
	std::map<std::string, header_data> data;
public: 
	SIP_HEADERfilter();
	~SIP_HEADERfilter();
	void load(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	void loadFile(u_int32_t *global_flags);
	int _add_call_flags(struct ParsePacket::ppContentsX *parseContents, volatile unsigned long int *flags);
        static void dump2man(ostringstream &oss);
	void _addNodes(ParsePacket *parsePacket);
	static int add_call_flags(struct ParsePacket::ppContentsX *parseContents, volatile unsigned long int *flags);
	static void addNodes(ParsePacket *parsePacket);
	static void loadActive(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void freeActive();
	static void prepareReload(u_int32_t *global_flags, SqlDb *sqlDb = NULL);
	static void applyReload();
	static unsigned long getLoadTime() {
		return(loadTime);
	}
	static void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	static void unlock() {
		__sync_lock_release(&_sync);
	}
	static void lock_reload() {
		while(__sync_lock_test_and_set(&_sync_reload, 1));
	}
	static void unlock_reload() {
		__sync_lock_release(&_sync_reload);
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
		while(__sync_lock_test_and_set(&_sync_reload, 1));
	}
	static void unlock_reload() {
		__sync_lock_release(&_sync_reload);
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
		flags |= (opt_audio_format == FORMAT_OGG ? FLAG_SAVEAUDIO_OGG : FLAG_SAVEAUDIO_WAV);
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
	if(opt_sip_register_save_all) {
		flags |= FLAG_SAVEREGISTER;
	}
	if (opt_dbdtmf) {
		flags |= FLAG_SAVEDTMFDB;
	}
	if (opt_pcapdtmf) {
		flags |= FLAG_SAVEDTMFPCAP;
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


#endif //FILTER_MYSQL_H
