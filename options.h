#ifndef OPTIONS_H
#define OPTIONS_H


#include <string>
#include <vector>
#include <string.h>
#include <bits/types.h>
#include <list>
#include <deque>
#include <map>

#include "record_array.h"
#include "tools.h"


enum eOptionsField {
	of_id = 0,
	of_id_sensor,
	of_ip_src,
	of_ip_dst,
	of_port_src,
	of_port_dst,
	of_number_src,
	of_number_dst,
	of_domain_src,
	of_domain_dst,
	of_ua_src,
	of_ua_dst,
	of_last_options_time,
	of_last_options_time_us,
	of_last_response_time,
	of_last_response_time_us,
	of_response_time_ms,
	of_last_response_number,
	of_last_response_string,
	of_qualify_ok,
	of_history,
	of__max
};


class cOptionsItem_base {
public:
	cOptionsItem_base() {
		ip_src = 0;
		ip_dst = 0;
		port_src = 0;
		port_dst = 0;
	}
	bool operator == (const cOptionsItem_base& other) const;
	void debug_out();
public:
	u_int32_t ip_src;
	u_int32_t ip_dst;
	u_int16_t port_src;
	u_int16_t port_dst;
	string number_src;
	string number_dst;
	string domain_src;
	string domain_dst;
};


class cOptionsItem : public cOptionsItem_base {
public:
	cOptionsItem() {
		time_us = 0;
		id_sensor = 0;
		response = false;
		cseq_number = 0;
		response_number = 0;
	}
	bool operator == (const cOptionsItem& other) const;
	void debug_out();
public:
	u_int64_t time_us;
	int id_sensor;
	bool response;
	string callid;
	u_int32_t cseq_number;
	string callername;
	string ua;
	int response_number;
	string response_string;
};


class cOptionsRelationId : public cOptionsItem_base {
public:
	cOptionsRelationId(cOptionsItem_base *options);
	inline bool operator == (const cOptionsRelationId& other) const;
	inline bool operator < (const cOptionsRelationId& other) const;
public:
	cOptionsItem_base *options;
};


class cOptionsItemResponse {
public:
	cOptionsItemResponse() {
		item = NULL;
		response = NULL;
	}
	~cOptionsItemResponse();
	u_int64_t getLastOptionsTime();
	u_int64_t getLastResponseTime();
	u_int64_t getLastTime();
public:
	cOptionsItem *item;
	cOptionsItem *response;
	list<u_int64_t> prev_time_us;
};


class cOptionsRelation : public cOptionsItem_base {
public:
	struct sHistoryData {
		inline sHistoryData() {
			clear();
		}
		inline void clear() {
			options_time_us = 0;
			clearResponse();
		}
		inline void clearResponse() {
			response_time_us = 0;
			response_number = 0;
			response_string_id = 0;
		}
		inline u_int64_t getResponseTime() {
			return(response_time_us ? response_time_us - options_time_us : -1);
		}
		string getJson(cStringCache *responseStringCache, int qualifyOk);
		u_int64_t options_time_us;
		u_int64_t response_time_us;
		int response_number;
		u_int32_t response_string_id;
	};
public:
	cOptionsRelation(cOptionsItem *item);
	~cOptionsRelation();
	void addOptions(cOptionsItem *item, 
			class cOptionsRelations *relations);
	bool getDataRow(RecordArray *rec, u_int64_t limit_options_time_us, 
			cOptionsRelations *relations);
	u_int64_t getLastOptionsTime();
	u_int64_t getLastResponseTime();
	u_int64_t getLastTime();
	bool getLastHistoryData(sHistoryData *data, u_int64_t limit_options_time_us, 
				cOptionsRelations *relations,
				bool useLock = true);
	int32_t getLastResponseTime(u_int64_t limit_options_time_us, 
				    u_int64_t *options_time_us, u_int64_t *response_time_us,
				    int *response_number, string *response_string,
				    cOptionsRelations *relations,
				    bool useLock = true);
	bool getHistoryData(list<sHistoryData> *historyData, u_int64_t limit_options_time_us, unsigned maxItems,
			    cOptionsRelations *relations,
			    bool useLock = true);
	bool getHistoryDataJson(string *historyData, u_int64_t limit_options_time_us, bool withResponseString, unsigned maxItems,
				cOptionsRelations *relations,
				bool useLock = true);
	void debug_out(cOptionsRelations *relations);
private:
	void convItemResponseToHistoryData(cOptionsItemResponse *itemResponse, sHistoryData *historyData, 
					   cOptionsRelations *relations,
					   bool useLock = true);
	cOptionsItemResponse *findItemForResponse(cOptionsItem *item);
	void clear();
	void cleanup_item_response_by_limit_time(u_int64_t limit_time_us, cOptionsRelations *relations);
	void cleanup_item_response_by_max_items(unsigned max_items, cOptionsRelations *relations);
	void cleanup_history_by_limit_time(u_int64_t limit_time_us);
	void cleanup_history_by_max_items(unsigned max_items);
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
	deque<cOptionsItemResponse*> queue_items;
	deque<sHistoryData> history;
	int id_sensor;
	string ua_src;
	string ua_dst;
	volatile int _sync;
	static volatile u_int64_t _id;
	static volatile int _sync_id;
friend class cOptionsRelations;
};


class cOptionsRelations {
public:
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
		inline bool isQualifyOk(int response_time, int response_number) {
			if(response_time > qualifyLimit * 1000) {
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
		inline bool okCond(cOptionsItem_base *item) {
			return((ip_src.is_empty() || ip_src.checkIP(ntohl(item->ip_src))) &&
			       (ip_dst.is_empty() || ip_dst.checkIP(ntohl(item->ip_src))) &&
			       (number_src.is_empty() || number_src.checkNumber(item->number_src.c_str())) &&
			       (number_dst.is_empty() || number_dst.checkNumber(item->number_dst.c_str())) &&
			       (domain_src.is_empty() || domain_src.check(item->domain_src.c_str())) &&
			       (domain_dst.is_empty() || domain_dst.check(item->domain_dst.c_str())));
		}
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
		inline bool isSet() {
			return(defaultParams.isSet() ||
			       recordsParams.size() > 0);
		}
		inline bool checkProcess(cOptionsItem_base *item) {
			if(defaultParams.isSet()) {
				return(true);
			}
			return(findRecordByCond(item));
		}
		inline sParamsBase *findParamsBase(cOptionsItem_base *item) {
			sParamsRecord *paramRecord = findRecordByCond(item);
			if(paramRecord) {
				return(paramRecord);
			}
			if(defaultParams.isSet()) {
				return(&defaultParams);
			}
			return(NULL);
		}
		inline sParamsRecord *findRecordByCond(cOptionsItem_base *item) {
			for(list<sParamsRecord>::iterator iter = recordsParams.begin(); iter != recordsParams.end(); iter++) {
				if(iter->okCond(item)) {
					return(&(*iter));
				}
			}
			return(NULL);
		}
		inline int isQualifyOk(cOptionsItem_base *item, int response_time, int response_number) {
			if(response_time <= 0 || !response_number) {
				return(-1);
			}
			sParamsBase *paramsBase = findParamsBase(item);
			if(paramsBase) {
				return(paramsBase->isQualifyOk(response_time, response_number));
			}
			return(-1);
		}
		sParamsBase defaultParams;
		list<sParamsRecord> recordsParams;
	};
public:
	cOptionsRelations();
	~cOptionsRelations();
	void addOptions(cOptionsItem *item);
	string getDataTableJson(char *params, bool *zip);
	string getHistoryDataJson(char *params, bool *zip);
	string getHistoryDataJson(u_int64_t id);
	void debug_out();
	void clear();
	void loadParams();
	void loadParamsInBackground();
	bool isSetParams() {
		lock_params();
		bool rslt = params.isSet();
		unlock_params();
		return(rslt);
	}
	bool checkProcess(cOptionsItem_base *item) {
		lock_params();
		bool rslt = params.checkProcess(item);
		unlock_params();
		return(rslt);
	}
	int isQualifyOk(cOptionsItem_base *item, int response_time, int response_number) {
		lock_params();
		int rslt = params.isQualifyOk(item, response_time, response_number);
		unlock_params();
		return(rslt);
	}
private:
	void cleanup_item_response_by_limit_time(u_int64_t limit_time_us);
	void cleanup_history_by_limit_time(u_int64_t limit_time_us);
	void cleanup_relations(u_int64_t limit_time_us);
	bool existsParamsTables();
	bool loadParams(sParams *params);
	static void *_loadParamsInBackground(void *arg);
	void lock_relations() {
		while(__sync_lock_test_and_set(&_sync_relations, 1));
	}
	void unlock_relations() {
		__sync_lock_release(&_sync_relations);
	}
	void lock_delete_relation() {
		while(__sync_lock_test_and_set(&_sync_delete_relation, 1));
	}
	void unlock_delete_relation() {
		__sync_lock_release(&_sync_delete_relation);
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
public:
	map<cOptionsRelationId, cOptionsRelation*> relations;
private:
	cStringCache responseStringCache;
	sParams params;
	volatile int _sync_relations;
	volatile int _sync_delete_relation;
	volatile int _sync_params;
	volatile int _sync_params_load;
	u_long lastCleanupRelations;
friend class cOptionsRelation;
};


eOptionsField convOptionsFieldToFieldId(const char *field);


#endif //OPTIONS_H
