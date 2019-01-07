#ifndef FILTER_CALL_H
#define FILTER_CALL_H


#include "filter_record.h"
#include "calltable.h"
#include "country_detect.h"


class cRecordFilterItem_CallProxy : public cRecordFilterItem_IP {
public:
	cRecordFilterItem_CallProxy(cRecordFilter *parent)
	 : cRecordFilterItem_IP(parent, 0) {
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(findInBlackList) {
			*findInBlackList = false;
		}
		Call *call = (Call*)rec;
		if(call->is_set_proxies()) {
			set<unsigned int> proxies;
			call->proxies_undup(&proxies);
			for(set<unsigned int>::iterator iter = proxies.begin(); iter != proxies.end(); iter++) {
				bool _findInBlackList = false;
				if(check_ip(htonl(*iter), &_findInBlackList)) {
					return(true);
				} else if(_findInBlackList) {
					if(findInBlackList) {
						*findInBlackList = _findInBlackList;
					}
					return(false);
				}
			}
		}
		return(false);
	}
};


class cCallFilter : public cRecordFilter {
public:
	cCallFilter(const char *filter);
	void setFilter(const char *filter);
	int64_t getField_int(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_calldate:
			return(((Call*)rec)->calltime());
		case cf_callerip:
			return(htonl(((Call*)rec)->getSipcallerip()));
		case cf_calledip:
			return(htonl(((Call*)rec)->getSipcalledip()));
		case cf_id_sensor:
			return(((Call*)rec)->useSensorId);
		case cf_connect_duration:
			return(((Call*)rec)->connect_duration_active());
		case cf_called_international:
			return(!isLocalByPhoneNumber(((Call*)rec)->called));
		}
		return(0);
	}
	const char *getField_string(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_caller:
			return(((Call*)rec)->caller);
		case cf_called:
			return(((Call*)rec)->called);
		case cf_callerdomain:
			return(((Call*)rec)->caller_domain);
		case cf_calleddomain:
			return(((Call*)rec)->called_domain);
		case cf_calleragent:
			return(((Call*)rec)->a_ua);
		case cf_calledagent:
			return(((Call*)rec)->b_ua);
		case cf_callid:
			return(((Call*)rec)->fbasename);
		}
		return("");
	}
};


#endif
