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
			set<vmIP> proxies;
			call->proxies_undup(&proxies);
			for(set<vmIP>::iterator iter = proxies.begin(); iter != proxies.end(); iter++) {
				bool _findInBlackList = false;
				if(check_ip(*iter, &_findInBlackList)) {
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


class cRecordFilterItem_CustomHeader : public cRecordFilterItem_CheckString {
public:
	cRecordFilterItem_CustomHeader(cRecordFilter *parent, const char *customHeader)
	 : cRecordFilterItem_CheckString(parent, 0) {
		this->customHeader = customHeader;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	string customHeader;
};


class cRecordFilterItem_Call : public cRecordFilterItem_rec {
public:
	cRecordFilterItem_Call(cRecordFilter *parent, const char *filter)
	 : cRecordFilterItem_rec(parent) {
		this->filter = filter;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	string filter;
};


class cCallFilter : public cRecordFilter {
public:
	cCallFilter(const char *filter);
	void setFilter(const char *filter);
	int64_t getField_int(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_calldate:
			return(((Call*)rec)->calltime_s());
		case cf_id_sensor:
			return(((Call*)rec)->useSensorId);
		case cf_connect_duration:
			return(((Call*)rec)->connect_duration_active_s());
		case cf_called_international:
			return(!isLocalByPhoneNumber(((Call*)rec)->called()));
		case cf_vlan:
			return(((Call*)rec)->vlan);
		}
		return(0);
	}
	vmIP getField_ip(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_callerip:
			return(((Call*)rec)->getSipcallerip());
		case cf_calledip:
			return(((Call*)rec)->getSipcalledip());
		case cf_callerip_encaps:
			return(((Call*)rec)->getSipcallerip_encaps());
		case cf_calledip_encaps:
			return(((Call*)rec)->getSipcalledip_encaps());
		}
		return(0);
	}
	const char *getField_string(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_caller:
			return(((Call*)rec)->caller);
		case cf_called:
			return(((Call*)rec)->called());
		case cf_callerdomain:
			return(((Call*)rec)->caller_domain);
		case cf_calleddomain:
			return(((Call*)rec)->called_domain());
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


class cUserRestriction {
public:
	enum eTypeSrc {
		_ts_cdr,
		_ts_message,
		_ts_other
	};
	enum eCombCond {
		_cc_and,
		_cc_or
	};
public:
	cUserRestriction();
	~cUserRestriction();
	void load(unsigned uid, bool *useCustomHeaders, SqlDb *sqlDb = NULL);
	void apply();
	void clear();
	bool check(eTypeSrc type_src,
		   vmIP *ip_src, vmIP *ip_dst,
		   const char *number_src, const char *number_dst, const char *number_contact,
		   const char *domain_src, const char *domain_dst, const char *domain_contact,
		   u_int16_t vlan,
		   map<string, string> *ch);
private:
	unsigned uid;
	string src_ip;
	string src_number;
	string src_domain;
	string src_vlan;
	string src_ch_cdr;
	string src_ch_message;
	ListIP *cond_ip;
	ListPhoneNumber *cond_number;
	ListCheckString *cond_domain;
	list<u_int16_t> *cond_vlan;
	class cLogicHierarchyAndOr *cond_ch_cdr;
	cLogicHierarchyAndOr *cond_ch_message;
	eCombCond comb_cond;
};


class cLogicHierarchyAndOr {
public:
	class cItem {
	public:
		cItem(int level) {
			this->level = level;
		}
		virtual ~cItem() {}
	protected:
		virtual bool eval(void */*data*/) {
			return(true);
		}
	protected:
		int level;
	friend class cLogicHierarchyAndOr;
	};
public:
	cLogicHierarchyAndOr();
	virtual ~cLogicHierarchyAndOr();
	void set(const char *src);
	bool eval(void *data);
protected:
	virtual cItem *createItem(int level, const char *data);
private:
	bool eval(unsigned *index, void *data);
	void clear();
private:
	vector<cItem*> items;
};


class cLogicHierarchyAndOr_custom_header : public cLogicHierarchyAndOr {
public:
	class cItemCustomHeader : public cItem {
	public:
		cItemCustomHeader(int level, const char *custom_header, const char *pattern) : cItem(level) {
			this->custom_header = custom_header;
			this->pattern = pattern;
		}
	protected:
		virtual bool eval(void *data);
	protected:
		string custom_header;
		string pattern;
	};
protected:
	virtual cItem *createItem(int level, const char *data);
};


#endif
