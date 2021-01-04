#ifndef OPTIONS_H
#define OPTIONS_H


#include <string>
#include <vector>
#include <string.h>
#include <sys/types.h>
#include <list>
#include <deque>
#include <map>

#include "record_array.h"
#include "tools.h"
#include "calltable.h"
#include "sniff.h"


enum eSipMsgType {
	smt_options = OPTIONS,
	smt_subscribe = SUBSCRIBE,
	smt_notify = NOTIFY
};

enum eSipMsgField {
	smf_id = 0,
	smf_id_sensor,
	smf_type,
	smf_ip_src,
	smf_ip_dst,
	smf_port_src,
	smf_port_dst,
	smf_number_src,
	smf_number_dst,
	smf_domain_src,
	smf_domain_dst,
	smf_callername,
	smf_callid,
	smf_cseq,
	smf_ua_src,
	smf_ua_dst,
	smf_request_time,
	smf_request_time_us,
	smf_request_first_time,
	smf_request_first_time_us_compl,
	smf_response_time,
	smf_response_time_us,
	smf_response_duration_ms,
	smf_response_number,
	smf_response_string,
	smf_qualify_ok,
	smf_exists_pcap,
	smf_vlan,
	smf__max
};


class cSipMsgItem_base {
public:
	cSipMsgItem_base() {
		type = 0;
		id_sensor = 0;
		ip_src.clear();
		ip_dst.clear();
		port_src.clear();
		port_dst.clear();
		vlan = VLAN_UNSET;
	}
	bool operator == (const cSipMsgItem_base& other) const;
	void debug_out();
public:
	int16_t type;
	int16_t id_sensor;
	vmIP ip_src;
	vmIP ip_dst;
	vmPort port_src;
	vmPort port_dst;
	u_int16_t vlan;
	string number_src;
	string number_dst;
	string domain_src;
	string domain_dst;
};


class cSipMsgItem : public cSipMsgItem_base {
public:
	cSipMsgItem() {
		time_us = 0;
		response = false;
		cseq_number = 0;
		response_number = 0;
		content_length = 0;
	}
	bool operator == (const cSipMsgItem& other) const;
	void parseContent(packet_s_process *packetS);
	void debug_out();
public:
	u_int64_t time_us;
	bool response;
	string callid;
	u_int32_t cseq_number;
	string callername;
	string ua;
	int response_number;
	string response_string;
	string content_type;
	unsigned content_length;
	string content;
};


class cSipMsgRelationId : public cSipMsgItem_base {
public:
	cSipMsgRelationId(cSipMsgItem_base *sipMsg);
	inline bool operator == (const cSipMsgRelationId& other) const;
	inline bool operator < (const cSipMsgRelationId& other) const;
public:
	cSipMsgItem_base *sipMsg;
};


struct sCallDataPcap {
	sCallDataPcap() {
		call_data = NULL;
		pcap = NULL;
		pcap_save = false;
		pcap_closed = false;
	}
	inline bool isSet() {
		return(call_data || pcap);
	}
	inline bool isOpenPcap() {
		return(pcap && pcap->isOpen());
	}
	inline bool isClosePcap() {
		return(pcap && pcap->isClose());
	}
	inline void _closePcap() {
		if(isOpenPcap()) {
			pcap->close();
			pcap_closed = true;
		}
	}
	inline void destroy() {
		if(call_data) {
			delete call_data;
			call_data = NULL;
		}
		if(pcap) {
			delete pcap;
			pcap = NULL;
		}
	}
	inline bool pcapIsSave() {
		return(isSet() || pcap_save);
	}
	inline bool pcapIsSaved() {
		return(isClosePcap() && pcap_closed &&
		       call_data->isEmptyChunkBuffersCount());
	}
	Call_abstract *call_data;
	PcapDumper *pcap;
	volatile bool pcap_save;
	volatile bool pcap_closed;
};


class cSipMsgRequestResponse {
public:
	cSipMsgRequestResponse(u_int64_t time_us);
	~cSipMsgRequestResponse();
	void openPcap(packet_s_process *packetS, int type);
	void closePcap(class cSipMsgRelations *relations);
	bool isOpenPcap() {
		return(cdp.isOpenPcap());
	}
	bool isSetCdp() {
		return(cdp.isSet());
	}
	bool pcapIsSave() {
		return(cdp.pcapIsSave());
	}
	bool pcapIsSaved() {
		return(cdp.pcapIsSaved());
	}
	bool isSavedToDb() {
		return(saved_to_db);
	}
	void destroyCdp() {
		cdp.destroy();
	}
	void savePacket(packet_s_process *packetS);
	void saveToDb(cSipMsgRelations *relations);
	bool needSavePcap(cSipMsgRelations *relations, class cSipMsgRelation *relation);
	bool needSaveToDb(cSipMsgRelations *relations, class cSipMsgRelation *relation);
	u_int64_t getFirstRequestTime();
	u_int64_t getLastRequestTime();
	u_int64_t getLastResponseTime();
	u_int64_t getLastTime();
	string getPcapFileName();
	void destroy(cSipMsgRelations *relations, class cSipMsgRelation *relation);
	void parseCustomHeaders(packet_s_process *packetS, CustomHeaders::eReqRespDirection reqRespDirection);
public:
	u_int64_t time_us;
	cSipMsgItem *request;
	cSipMsgItem *response;
	list<u_int64_t> next_requests_time_us;
	sCallDataPcap cdp;
	volatile bool saved_to_db;
	CustomHeaders::tCH_Content custom_headers_content;
};


class cSipMsgRelation : public cSipMsgItem_base {
public:
	struct sHistoryData {
		inline sHistoryData() {
			clear();
		}
		inline void clear() {
			request_time_us = 0;
			cseq_number = 0;
			ua_src_id = 0;
			exists_pcap = false;
			clearResponse();
		}
		inline void clearResponse() {
			response_time_us = 0;
			response_number = 0;
			response_string_id = 0;
			ua_dst_id = 0;
		}
		inline u_int64_t getResponseDuration() {
			return(response_time_us ? response_time_us - request_time_us : -1);
		}
		u_int64_t getFirstRequestTime();
		u_int64_t getLastRequestTime();
		u_int64_t getLastResponseTime();
		u_int64_t getLastTime();
		string getJson(cStringCache *responseStringCache, int qualifyOk);
		u_int64_t request_time_us;
		list<u_int64_t> next_requests_time_us;
		u_int64_t response_time_us;
		int response_number;
		u_int32_t response_string_id;
		string callid;
		u_int32_t cseq_number;
		string callername;
		u_int32_t ua_src_id;
		u_int32_t ua_dst_id;
		bool exists_pcap;
	};
public:
	cSipMsgRelation(cSipMsgItem *item);
	~cSipMsgRelation();
	void addSipMsg(cSipMsgItem *item, packet_s_process *packetS,
		       cSipMsgRelations *relations);
	bool getDataRow(RecordArray *rec, u_int64_t limit_time_us, 
			cSipMsgRelations *relations);
	u_int64_t getLastTime();
	bool getLastHistoryData(u_int64_t limit_time_us, 
				cSipMsgRequestResponse **reqResp, sHistoryData **historyData,
				bool useLock = true);
	bool getHistoryData(list<sHistoryData> *historyData, u_int64_t limit_time_us, unsigned maxItems,
			    cSipMsgRelations *relations,
			    bool useLock = true);
	void debug_out(cSipMsgRelations *relations);
private:
	void convRequestResponseToHistoryData(cSipMsgRequestResponse *itemResponse, sHistoryData *historyData, bool useResponse,
					      cSipMsgRelations *relations,
					      bool useLock = true);
	cSipMsgRequestResponse *findItemForResponse(cSipMsgItem *item);
	void clear();
	void cleanup_item_response_by_limit_time(u_int64_t limit_time_us, cSipMsgRelations *relations);
	void cleanup_item_response_by_max_items(unsigned max_items, cSipMsgRelations *relations);
	void cleanup_history_by_limit_time(u_int64_t limit_time_us);
	void cleanup_history_by_max_items(unsigned max_items);
	void close_pcaps_by_limit_time(u_int64_t limit_time_us, cSipMsgRelations *relations);
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
	void lock_id() {
		while(__sync_lock_test_and_set(&_sync_id, 1));
	}
	void unlock_id() {
		__sync_lock_release(&_sync_id);
	}
private:
	u_int64_t id;
	deque<cSipMsgRequestResponse*> queue_req_resp;
	deque<sHistoryData> history;
	int id_sensor;
	unsigned long int flags;
	volatile int _sync;
	static volatile u_int64_t _id;
	static volatile int _sync_id;
friend class cSipMsgRelations;
};


class cSipMsgRelations {
public:
	enum eDbFlags {
		dbf_pcap_save = 1
	};
	struct sParamsBase {
		inline sParamsBase() {
			qualifyLimit = 0;
		}
		inline bool isSet() {
			return(qualifyLimit > 0);
		}
		inline void clear() {
			qualifyLimit = 0;
			okResponses.clear();
		}
		inline bool isQualifyOk(int64_t response_duration_us, int response_number) {
			if(response_duration_us > qualifyLimit * 1000) {
				return(false);
			}
			if(response_number == 200) {
				return(true);
			}
			return(okResponses.size() &&
			       std::find(okResponses.begin(), okResponses.end(), response_number) != okResponses.end());
		}
		int qualifyLimit;
		list<int> okResponses;
	};
	struct sParamsCondition {
		inline bool isSet() {
			return(!(ip_src.is_empty() &&
				 ip_dst.is_empty() &&
				 number_src.is_empty() &&
				 number_dst.is_empty() &&
				 domain_src.is_empty() &&
				 domain_dst.is_empty()));
		}
		inline bool okCond(cSipMsgItem_base *item) {
			return(((options && item->type == smt_options) ||
				(subscribe && item->type == smt_subscribe) ||
				(notify && item->type == smt_notify)) &&
			       (ip_src.is_empty() || ip_src.checkIP(item->ip_src)) &&
			       (ip_dst.is_empty() || ip_dst.checkIP(item->ip_dst)) &&
			       (number_src.is_empty() || number_src.checkNumber(item->number_src.c_str())) &&
			       (number_dst.is_empty() || number_dst.checkNumber(item->number_dst.c_str())) &&
			       (domain_src.is_empty() || domain_src.check(item->domain_src.c_str())) &&
			       (domain_dst.is_empty() || domain_dst.check(item->domain_dst.c_str())));
		}
		bool options;
		bool subscribe;
		bool notify;
		ListIP ip_src;
		ListIP ip_dst;
		ListPhoneNumber number_src;
		ListPhoneNumber number_dst;
		ListCheckString domain_src;
		ListCheckString domain_dst;
	};
	struct sParamsRecord : public sParamsCondition, public sParamsBase {
		string name;
	};
	struct sParams {
		inline void clear() {
			defaultParams.clear();
			recordsParams.clear();
		}
		inline sParamsBase *findParamsBase(cSipMsgItem_base *item) {
			if(recordsParams.size() > 0) {
				sParamsRecord *paramRecord = findRecordByCond(item);
				if(paramRecord) {
					return(paramRecord);
				}
			} else if(defaultParams.isSet()) {
				return(&defaultParams);
			}
			return(NULL);
		}
		inline sParamsRecord *findRecordByCond(cSipMsgItem_base *item) {
			for(list<sParamsRecord>::iterator iter = recordsParams.begin(); iter != recordsParams.end(); iter++) {
				if(iter->okCond(item)) {
					return(&(*iter));
				}
			}
			return(NULL);
		}
		inline int isQualifyOk(cSipMsgItem_base *item, int64_t response_duration_us, int response_number) {
			if(response_duration_us <= 0 || !response_number) {
				return(-1);
			}
			sParamsBase *paramsBase = findParamsBase(item);
			if(paramsBase) {
				return(paramsBase->isQualifyOk(response_duration_us, response_number));
			}
			return(-1);
		}
		sParamsBase defaultParams;
		list<sParamsRecord> recordsParams;
	};
public:
	cSipMsgRelations();
	~cSipMsgRelations();
	void addSipMsg(cSipMsgItem *item, packet_s_process *packetS);
	string getDataTableJson(char *params, bool *zip);
	string getHistoryDataJson(char *params, bool *zip);
	string getHistoryDataJson(u_int64_t id);
	void debug_out();
	void clear();
	void loadParams();
	void loadParamsInBackground();
	int isQualifyOk(cSipMsgItem_base *item, int64_t response_duration_us, int response_number) {
		lock_params();
		int rslt = params.isQualifyOk(item, response_duration_us, response_number);
		unlock_params();
		return(rslt);
	}
	void closePcap(sCallDataPcap *cdp);
	void saveToDb(cSipMsgRequestResponse *itemResponse);
	void _saveToDb(cSipMsgRequestResponse *itemResponse, bool enableBatchIfPossible = true);
	bool needSavePcap(cSipMsgRequestResponse *itemResponse, cSipMsgRelation *relation);
	bool needSaveToDb(cSipMsgRequestResponse *itemResponse, cSipMsgRelation *relation);
	void pushToCdpQueue(sCallDataPcap *cdp);
	void runInternalThread();
private:
	void cleanup_item_response_by_limit_time(u_int64_t limit_time_us);
	void cleanup_history_by_limit_time(u_int64_t limit_time_us);
	void cleanup_relations(u_int64_t limit_time_us);
	void close_pcaps_by_limit_time(u_int64_t limit_time_us);
	void do_cleanup_relations(u_int64_t act_time_ms, bool force = false);
	void do_close_pcaps_by_limit_time(u_int64_t act_time_ms, bool force = false, bool all = false);
	void do_cleanup_cdq();
	bool existsParamsTables();
	void loadParams(sParams *params);
	static void *_loadParamsInBackground(void *arg);
	void internalThread();
	static void *internalThread(void *arg);
	void lock_relations() {
		while(__sync_lock_test_and_set(&_sync_relations, 1));
	}
	void unlock_relations() {
		__sync_lock_release(&_sync_relations);
	}
	void lock_params() {
		while(__sync_lock_test_and_set(&_sync_params, 1));
	}
	void unlock_params() {
		__sync_lock_release(&_sync_params);
	}
	void lock_params_load() {
		while(__sync_lock_test_and_set(&_sync_params_load, 1));
	}
	void unlock_params_load() {
		__sync_lock_release(&_sync_params_load);
	}
	void lock_cdp_queue() {
		while(__sync_lock_test_and_set(&_sync_cdp_queue, 1));
	}
	void unlock_cdp_queue() {
		__sync_lock_release(&_sync_cdp_queue);
	}
	void lock_close_pcap() {
		while(__sync_lock_test_and_set(&_sync_close_pcap, 1));
	}
	void unlock_close_pcap() {
		__sync_lock_release(&_sync_close_pcap);
	}
	void lock_save_to_db() {
		while(__sync_lock_test_and_set(&_sync_save_to_db, 1));
	}
	void unlock_save_to_db() {
		__sync_lock_release(&_sync_save_to_db);
	}
public:
	map<cSipMsgRelationId, cSipMsgRelation*> relations;
private:
	cStringCache responseStringCache;
	cStringCache uaStringCache;
	sParams params;
	deque<sCallDataPcap> cdpQueue;
	volatile int _sync_relations;
	volatile int _sync_delete_relation;
	volatile int _sync_params;
	volatile int _sync_params_load;
	volatile int _sync_cdp_queue;
	volatile int _sync_close_pcap;
	volatile int _sync_save_to_db;
	u_int64_t lastCleanupRelations_ms;
	u_int64_t lastClosePcaps_ms;
	pthread_t internalThread_id;
	volatile bool terminate;
friend class cSipMsgRelation;
};


eSipMsgField convSipMsgFieldToFieldId(const char *field);


void initSipMsg();
void termSipMsg();


#endif //OPTIONS_H
