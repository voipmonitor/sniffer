#ifndef FILTER_CALL_H
#define FILTER_CALL_H


#include <math.h>

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
		set<vmIP> proxies;
		getProxies(call, &proxies);
		for(set<vmIP>::iterator iter = proxies.begin(); iter != proxies.end(); iter++) {
			if(check_ip(*iter)) {
				return(true);
			}
		}
		return(false);
	}
	void checkWhiteBlack(void *rec, bool *white, bool *black) {
		*white = false;
		*black = false;
		Call *call = (Call*)rec;
		set<vmIP> proxies;
		getProxies(call, &proxies);
		for(set<vmIP>::iterator iter = proxies.begin(); iter != proxies.end(); iter++) {
			bool proxy_white;
			bool proxy_black;
			checkWhiteBlack_ip(*iter, &proxy_white, &proxy_black);
			if(proxy_white) {
				*white = true;
			}
			if(proxy_black) {
				*black = true;
			}
		}
	}
private:
	void getProxies(Call *call, set<vmIP> *proxies) {
		if(call->saved_data) {
			*proxies = call->saved_data->proxies;
		} else {
			call->getProxies(call->branch_main(), proxies);
		}
	}
};


class cRecordFilterItem_Fixed : public cRecordFilterItem_base {
public:
	cRecordFilterItem_Fixed(cRecordFilter *parent, bool rslt)
	 : cRecordFilterItem_base(parent, 0) {
		this->rslt = rslt;
	}
	bool check(void */*rec*/, bool *findInBlackList = NULL) {
		if(findInBlackList) {
			*findInBlackList = false;
		}
		return(rslt);
	}
private:
	bool rslt;
};


class cRecordFilterItem_CheckStringOr : public cRecordFilterItem_base {
public:
	struct sItem {
		sItem() {
			_not = false;
		}
		ListCheckString pattern;
		bool _not;
	};
public:
	cRecordFilterItem_CheckStringOr(cRecordFilter *parent, unsigned recordFieldIndex, const char *filter, const char *separators, const char *separatorsSeparator, bool enableNull = false);
	void setEmptyAsNull() {
		emptyAsNull = true;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(unsigned i = 0; i < items.size(); i++) {
			items[i].pattern.setNoLock();
		}
	}
protected:
	bool checkValue(const char *value);
protected:
	vector<sItem> items;
	bool null;
	bool emptyAsNull;
};


class cRecordFilterItem_CustomHeader : public cRecordFilterItem_CheckStringOr {
public:
	cRecordFilterItem_CustomHeader(cRecordFilter *parent, const char *customHeader, const char *filter, const char *separators, const char *separatorsSeparator, bool enableNull = false)
	 : cRecordFilterItem_CheckStringOr(parent, 0, filter, separators, separatorsSeparator, enableNull) {
		this->customHeader = customHeader;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	string customHeader;
};


class cRecordFilterItem_CustomHeaderNum : public cRecordFilterItem_rec {
public:
	cRecordFilterItem_CustomHeaderNum(cRecordFilter *parent, const char *customHeader, cRecordFilterItem_base::eCmpCond cond, double value)
	 : cRecordFilterItem_rec(parent) {
		this->customHeader = customHeader;
		this->cond = cond;
		this->value = value;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	string customHeader;
	cRecordFilterItem_base::eCmpCond cond;
	double value;
};


class cRecordFilterItem_SipResponseNum : public cRecordFilterItem_base {
public:
	struct sRange {
		int from;
		int to;
	};
public:
	cRecordFilterItem_SipResponseNum(cRecordFilter *parent, unsigned recordFieldIndex, const char *filter);
	bool check(void *rec, bool *findInBlackList = NULL);
	static bool isNumFilter(const char *filter);
private:
	static string trimNumSuffix(string item);
	static sRange parseRange(string item);
	static bool inRanges(vector<sRange> *ranges, int num);
private:
	vector<sRange> ranges;
	vector<sRange> ranges_not;
};


class cRecordFilterItem_SipResponse : public cRecordFilterItem_rec {
public:
	struct sItem {
		sItem() {
			num = NULL;
			_not = false;
		}
		cRecordFilterItem_SipResponseNum *num;
		ListCheckString pattern;
		bool _not;
	};
public:
	cRecordFilterItem_SipResponse(cRecordFilter *parent, const char *filter);
	~cRecordFilterItem_SipResponse();
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(unsigned i = 0; i < items.size(); i++) {
			items[i].pattern.setNoLock();
		}
	}
private:
	cRecordFilterItem_SipResponse(const cRecordFilterItem_SipResponse &other);
	cRecordFilterItem_SipResponse &operator = (const cRecordFilterItem_SipResponse &other);
private:
	vector<sItem> items;
	bool positive_never;
};


class cRecordFilterItem_SipResponseAll : public cRecordFilterItem_rec {
public:
	struct sItem {
		sItem() {
			num = -1;
		}
		int num;
		ListCheckString pattern;
	};
public:
	cRecordFilterItem_SipResponseAll(cRecordFilter *parent, const char *filter);
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(unsigned i = 0; i < items.size(); i++) {
			items[i].pattern.setNoLock();
		}
		for(unsigned i = 0; i < items_not.size(); i++) {
			items_not[i].pattern.setNoLock();
		}
	}
private:
	static bool checkItem(CallBranch *c_branch, sItem *item);
private:
	vector<sItem> items;
	vector<sItem> items_not;
};


class cRecordFilterItem_SipRequestHist : public cRecordFilterItem_rec {
public:
	struct sItem {
		sItem() {
			count = 0;
			_not = false;
		}
		ListCheckString pattern;
		unsigned count;
		bool _not;
	};
public:
	cRecordFilterItem_SipRequestHist(cRecordFilter *parent, const char *filter);
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(unsigned i = 0; i < items.size(); i++) {
			items[i].pattern.setNoLock();
		}
	}
private:
	vector<sItem> items;
};


class cRecordFilterItem_Reason : public cRecordFilterItem_rec {
public:
	enum eTypeReason {
		_sip,
		_q850
	};
	struct sItem {
		sItem() {
			null = false;
			num = -1;
			_not = false;
		}
		bool null;
		int num;
		bool _not;
		ListCheckString pattern;
	};
public:
	cRecordFilterItem_Reason(cRecordFilter *parent, eTypeReason typeReason, const char *filter);
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(unsigned i = 0; i < items.size(); i++) {
			items[i].pattern.setNoLock();
		}
	}
private:
	eTypeReason typeReason;
	vector<sItem> items;
	bool positive_never;
};


class cRecordFilterItem_CdrField : public cRecordFilterItem_rec {
public:
	enum eCond {
		_ge,
		_gt,
		_lt,
		_eq,
		_mos
	};
public:
	cRecordFilterItem_CdrField(cRecordFilter *parent, const char *columns, double divisor, eCond cond, double value);
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	vector<string> columns;
	double divisor;
	eCond cond;
	double value;
};


class cRecordFilterItem_CdrFieldsSum : public cRecordFilterItem_rec {
public:
	struct sColumn {
		string column;
		double multiplier;
	};
public:
	cRecordFilterItem_CdrFieldsSum(cRecordFilter *parent, double value)
	 : cRecordFilterItem_rec(parent) {
		this->value = value;
	}
	void addColumn(string column, double multiplier) {
		sColumn c;
		c.column = column;
		c.multiplier = multiplier;
		columns.push_back(c);
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	vector<sColumn> columns;
	double value;
};


class cCallFilter;

class cRecordFilterItem_CallSubFilter : public cRecordFilterItem_rec {
public:
	cRecordFilterItem_CallSubFilter(cRecordFilter *parent, cCallFilter *subFilter, bool negative)
	 : cRecordFilterItem_rec(parent) {
		this->subFilter = subFilter;
		this->negative = negative;
	}
	~cRecordFilterItem_CallSubFilter();
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	cCallFilter *subFilter;
	bool negative;
};


class cRecordFilterItem_CallStream : public cRecordFilterItem_rec {
public:
	enum eField {
		_sf_count,
		_sf_received,
		_sf_rtp_ptime,
		_sf_diff_rtp_sdp_ptime,
		_sf_sdp_row_ptime,
		_sf_in_multiple_calls
	};
	enum eSide {
		_any,
		_caller,
		_called
	};
public:
	cRecordFilterItem_CallStream(cRecordFilter *parent, eField field, eSide side = _any)
	 : cRecordFilterItem_rec(parent) {
		this->field = field;
		this->side = side;
		this->ge_set = false;
		this->lt_set = false;
		this->le_set = false;
		this->ge = 0;
		this->lt = 0;
		this->le = 0;
	}
	void setGe(double ge) {
		this->ge = ge;
		this->ge_set = true;
	}
	void setLt(double lt) {
		this->lt = lt;
		this->lt_set = true;
	}
	void setLe(double le) {
		this->le = le;
		this->le_set = true;
	}
	bool isSet() {
		return(ge_set || lt_set || le_set);
	}
	bool check(void *rec, bool *findInBlackList = NULL);
	static unsigned rtpStreamsSize(Call *call);
	static bool rtpStream(Call *call, unsigned index, Call::sSavedData::sRtpStream *stream);
	static unsigned sdpRowsSize(Call *call);
	static bool sdpRow(Call *call, unsigned index, s_sdp_store_data *sdp_row);
	static bool matchSide(eSide side, bool is_caller, bool caller_flag_value) {
		return(side == _any ||
		       (side == _caller ? is_caller == caller_flag_value : is_caller != caller_flag_value));
	}
private:
	bool cmpValue(double streamValue) {
		return((!ge_set || streamValue >= ge) &&
		       (!lt_set || streamValue < lt) &&
		       (!le_set || streamValue <= le));
	}
	bool getStreamValue(Call *call, unsigned index, double *streamValue);
	bool getSdpRowValue(Call *call, unsigned index, double *streamValue);
private:
	eField field;
	eSide side;
	bool ge_set;
	bool lt_set;
	bool le_set;
	double ge;
	double lt;
	double le;
};


class cRecordFilterItem_CallStreamIpPort : public cRecordFilterItem_rec {
public:
	enum eTarget {
		_t_rtp_src,
		_t_rtp_dst,
		_t_sdp
	};
public:
	cRecordFilterItem_CallStreamIpPort(cRecordFilter *parent, eTarget target,
					   cRecordFilterItem_CallStream::eSide side = cRecordFilterItem_CallStream::_any,
					   bool negative = false)
	 : cRecordFilterItem_rec(parent) {
		this->target = target;
		this->side = side;
		this->negative = negative;
	}
	void addEntries(const char *value, bool negative_entries);
	void addPortRange(unsigned port_min, unsigned port_max) {
		sEntry entry;
		entry.ip_set = false;
		entry.port_set = true;
		entry.port_min = port_min;
		entry.port_max = port_max;
		entries.push_back(entry);
	}
	bool isSet() {
		return(entries.size() > 0);
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	struct sEntry {
		bool ip_set;
		vmIP ip_min;
		vmIP ip_max;
		bool port_set;
		unsigned port_min;
		unsigned port_max;
	};
	bool parseEntry(const char *value, sEntry *entry, bool *entry_negative);
	bool matchEntries(vmIPport *ip_port);
private:
	eTarget target;
	cRecordFilterItem_CallStream::eSide side;
	bool negative;
	vector<sEntry> entries;
};


class cRecordFilterItem_Dscp : public cRecordFilterItem_base {
public:
	cRecordFilterItem_Dscp(cRecordFilter *parent, unsigned recordFieldIndex)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		eq = -1;
		ge = -1;
		lt = -1;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
public:
	int eq;
	int ge;
	int lt;
};


class cRecordFilterItem_Dtmf : public cRecordFilterItem_rec {
public:
	struct sItem {
		sItem() {
			_not = false;
		}
		ListCheckString pattern;
		bool _not;
	};
	struct sStream {
		sStream(vmIP saddr, vmIP daddr) {
			this->saddr = saddr;
			this->daddr = daddr;
		}
		bool operator < (const sStream &other) const {
			return(saddr < other.saddr ? true : saddr > other.saddr ? false : daddr < other.daddr);
		}
		vmIP saddr;
		vmIP daddr;
	};
public:
	cRecordFilterItem_Dtmf(cRecordFilter *parent, const char *filter);
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(unsigned i = 0; i < items.size(); i++) {
			items[i].pattern.setNoLock();
		}
	}
private:
	string chars;
	vector<sItem> items;
};


class cRecordFilterItem_DtmfCount : public cRecordFilterItem_rec {
public:
	cRecordFilterItem_DtmfCount(cRecordFilter *parent, unsigned count_ge, unsigned count_lt)
	 : cRecordFilterItem_rec(parent) {
		this->count_ge = count_ge;
		this->count_lt = count_lt;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	unsigned count_ge;
	unsigned count_lt;
};


class cRecordFilterItem_CountryCode : public cRecordFilterItem_base {
public:
	cRecordFilterItem_CountryCode(cRecordFilter *parent, unsigned recordFieldIndex, const char *filter);
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	set<string> codes;
	bool all;
};


class cRecordFilterItem_Trunk : public cRecordFilterItem_rec {
public:
	cRecordFilterItem_Trunk(cRecordFilter *parent, int trunk, vector<string> *ips);
	~cRecordFilterItem_Trunk();
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(unsigned i = 0; i < groups.size(); i++) {
			groups[i]->setNoLock();
		}
	}
private:
	cRecordFilterItem_Trunk(const cRecordFilterItem_Trunk &other);
	cRecordFilterItem_Trunk &operator = (const cRecordFilterItem_Trunk &other);
private:
	int trunk;
	vector<ListIP_wb*> groups;
};


class cRecordFilterItem_AB : public cRecordFilterItem_rec {
public:
	enum eComb {
		_comb_values,
		_comb_sides_or,
		_comb_sides_and
	};
public:
	cRecordFilterItem_AB(cRecordFilter *parent, eComb comb)
	 : cRecordFilterItem_rec(parent) {
		this->comb = comb;
		for(int i = 0; i < 2; i++) {
			items[i] = NULL;
			proxies[i] = NULL;
		}
	}
	~cRecordFilterItem_AB() {
		for(int i = 0; i < 2; i++) {
			if(items[i]) {
				delete items[i];
			}
			if(proxies[i]) {
				delete proxies[i];
			}
		}
	}
	bool check(void *rec, bool *findInBlackList = NULL);
	void setNoLock() {
		for(int i = 0; i < 2; i++) {
			if(items[i]) {
				items[i]->setNoLock();
			}
			if(proxies[i]) {
				proxies[i]->setNoLock();
			}
		}
	}
public:
	eComb comb;
	cRecordFilterItem_base *items[2];
	cRecordFilterItem_base *proxies[2];
};


class cRecordFilterItem_Call : public cRecordFilterItem_rec {
public:
	enum eTypeFilter {
		_tf_codec,
		_tf_codec_exclude,
		_tf_codec_ab_eq,
		_tf_codec_ab_diff,
		_tf_custom_headers_cond,
		_tf_flags,
		_tf_bye,
		_tf_who_hangup,
		_tf_one_way,
		_tf_missing_rtp,
		_tf_flags_eq,
		_tf_rtp_state,
		_tf_country_compare_numbers,
		_tf_country_compare_ips
	};
	struct sCodecData {
		int payload_ab[2];
		int mos_f2_ab[2];
		int payload;
		bool payload_null;
		bool rtp_rows_match;
	};
public:
	cRecordFilterItem_Call(cRecordFilter *parent, eTypeFilter typeFilter, const char *filter);
	cRecordFilterItem_Call(cRecordFilter *parent, eTypeFilter typeFilter, u_int64_t filter_num, u_int64_t filter_num2 = 0);
	void setCodecAllStreams(bool codec_all_streams) {
		this->codec_all_streams = codec_all_streams;
	}
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	bool codecMatch(int codec) {
		return(codec >= 0 && filter_int.find(codec) != filter_int.end());
	}
	void getSaddrExists(Call *call, bool *a_saddr, bool *b_saddr) {
		if(call->saved_data) {
			*a_saddr = call->saved_data->saddr_exists[0];
			*b_saddr = call->saved_data->saddr_exists[1];
		} else {
			*a_saddr = call->lastactivecallerrtp != NULL;
			*b_saddr = call->lastactivecalledrtp != NULL;
		}
	}
	void getCodecData(Call *call, sCodecData *codecData);
	int rtpMosF2Mult10(RTP *rtp);
	int sqlAnd(int cond1, int cond2) {
		return(cond1 == 0 || cond2 == 0 ? 0 :
		       cond1 < 0 || cond2 < 0 ? -1 : 1);
	}
	int sqlOr(int cond1, int cond2) {
		return(cond1 > 0 || cond2 > 0 ? 1 :
		       cond1 < 0 || cond2 < 0 ? -1 : 0);
	}
private:
	eTypeFilter typeFilter;
	string filter;
	set<int> filter_int;
	u_int64_t filter_num;
	u_int64_t filter_num2;
	bool codec_all_streams;
};


class cCallFilter : public cRecordFilter {
public:
	enum eAbItemType {
		_ab_ip,
		_ab_phone_number,
		_ab_check_string,
		_ab_country_code,
		_ab_num_list,
		_ab_cdr_mos,
		_ab_cdr_ge
	};
	struct sAbDef {
		sAbDef(eAbItemType itemType, unsigned field1, unsigned field2) {
			this->itemType = itemType;
			this->field1 = field1;
			this->field2 = field2;
			column1 = NULL;
			column2 = NULL;
			codebook_table = NULL;
			codebook_column = NULL;
			phoneNumberType = PhoneNumber::_tn_norm;
			splitSeparators = NULL;
			splitSeparatorsSeparator = NULL;
			proxyName = NULL;
			sideCombination = false;
			revertNegation = false;
			zeroIsValue = false;
			enableNull = false;
			emptyAsNull = false;
			divisor = 1;
			value_mult = 1;
			value_offset = 0;
		}
		sAbDef(eAbItemType itemType, const char *column1, const char *column2) {
			this->itemType = itemType;
			field1 = 0;
			field2 = 0;
			this->column1 = column1;
			this->column2 = column2;
			codebook_table = NULL;
			codebook_column = NULL;
			phoneNumberType = PhoneNumber::_tn_norm;
			splitSeparators = NULL;
			splitSeparatorsSeparator = NULL;
			proxyName = NULL;
			sideCombination = false;
			revertNegation = false;
			zeroIsValue = false;
			enableNull = false;
			emptyAsNull = false;
			divisor = 1;
			value_mult = 1;
			value_offset = 0;
		}
		sAbDef &codebook(const char *table, const char *column) {
			codebook_table = table;
			codebook_column = column;
			return(*this);
		}
		sAbDef &phoneType(PhoneNumber::eTypeNumber type) {
			phoneNumberType = type;
			return(*this);
		}
		sAbDef &splitBy(const char *separators, const char *separatorsSeparator) {
			splitSeparators = separators;
			splitSeparatorsSeparator = separatorsSeparator;
			return(*this);
		}
		sAbDef &proxy(const char *name) {
			proxyName = name;
			return(*this);
		}
		sAbDef &sideComb() {
			sideCombination = true;
			return(*this);
		}
		sAbDef &revertNeg() {
			revertNegation = true;
			return(*this);
		}
		sAbDef &zeroValue() {
			zeroIsValue = true;
			return(*this);
		}
		sAbDef &nullValue() {
			enableNull = true;
			return(*this);
		}
		sAbDef &emptyNull() {
			emptyAsNull = true;
			return(*this);
		}
		sAbDef &cdrValue(double divisor, double value_mult = 1, double value_offset = 0) {
			this->divisor = divisor;
			this->value_mult = value_mult;
			this->value_offset = value_offset;
			return(*this);
		}
		eAbItemType itemType;
		unsigned field1;
		unsigned field2;
		const char *column1;
		const char *column2;
		const char *codebook_table;
		const char *codebook_column;
		PhoneNumber::eTypeNumber phoneNumberType;
		const char *splitSeparators;
		const char *splitSeparatorsSeparator;
		const char *proxyName;
		bool sideCombination;
		bool revertNegation;
		bool zeroIsValue;
		bool enableNull;
		bool emptyAsNull;
		double divisor;
		double value_mult;
		double value_offset;
	};
	class cFilterData {
	public:
		struct sItem {
			sItem() {
				used = false;
			}
			string name;
			string value;
			bool used;
		};
	public:
		void add(const string &key, const string &name, const string &value) {
			sItem *item = &data[key];
			item->name = name;
			item->value = value;
		}
		void setUsed(const char *key) {
			if(key) {
				data[key].used = true;
			}
		}
		void setUnused(const char *key) {
			if(key) {
				data[key].used = false;
			}
		}
		string &operator [] (const string &key) {
			sItem *item = &data[key];
			item->used = true;
			return(item->value);
		}
		string getUnusedKeys(const char *ignoreKeys) {
			string rslt;
			for(map<string, sItem>::iterator iter = data.begin(); iter != data.end(); iter++) {
				if(!iter->second.used && !iter->second.value.empty() &&
				   !existsKeyInList(iter->first, ignoreKeys) &&
				   !existsKeyInList(iter->second.name, ignoreKeys)) {
					rslt += (rslt.empty() ? "" : ",") + iter->second.name;
				}
			}
			return(rslt);
		}
	private:
		bool existsKeyInList(const string &key, const char *keyList) {
			string keyDelim = "," + key + ",";
			return(strstr(keyList, keyDelim.c_str()) != NULL);
		}
	private:
		map<string, sItem> data;
	};
public:
	cCallFilter(const char *filter, const char *keyPrefix = NULL, bool nested = false);
	void setFilter(const char *filter, const char *keyPrefix = NULL, bool nested = false);
	bool existsUnsupportedKeys() {
		return(!unsupportedKeys.empty());
	}
	string getUnsupportedKeys() {
		return(unsupportedKeys);
	}
	int64_t getField_int(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_calldate:
			return(((Call*)rec)->calltime_s());
		case cf_id_sensor:
			return(((Call*)rec)->useSensorId);
		case cf_lastSIPresponseNum:
			return(((Call*)rec)->branch_main()->lastSIPresponseNum);
		case cf_callerport:
			return(((Call*)rec)->isClosed() ?
				((Call*)rec)->branch_main()->sipcallerport_rslt.getPort() :
				((Call*)rec)->getSipcallerport(((Call*)rec)->branch_main()).getPort());
		case cf_calledport:
			return(((Call*)rec)->isClosed() ?
				((Call*)rec)->branch_main()->sipcalledport_rslt.getPort() :
				((Call*)rec)->getSipcalledport(((Call*)rec)->branch_main()).getPort());
		case cf_called_international:
			return(!isLocalByPhoneNumber(((Call*)rec)->get_called(((Call*)rec)->branch_main()), ((Call*)rec)->getSipcalledip_corrected(((Call*)rec)->branch_main())));
		case cf_vlan:
			return(((Call*)rec)->branch_main()->getVlan());
		}
		return(0);
	}
	double getField_float(void *rec, unsigned registerFieldIndex, bool *null);
	vmIP getField_ip(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_callerip:
			return(((Call*)rec)->isClosed() ?
				((Call*)rec)->branch_main()->sipcallerip_rslt :
				((Call*)rec)->getSipcallerip_corrected(((Call*)rec)->branch_main()));
		case cf_calledip:
			return(((Call*)rec)->isClosed() ?
				((Call*)rec)->branch_main()->sipcalledip_rslt :
				((Call*)rec)->getSipcalledip_corrected(((Call*)rec)->branch_main()));
		case cf_callerip_encaps:
			return(((Call*)rec)->isClosed() ?
				((Call*)rec)->branch_main()->sipcallerip_encaps_rslt :
				((Call*)rec)->getSipcallerip_encaps(((Call*)rec)->branch_main(), true));
		case cf_calledip_encaps:
			return(((Call*)rec)->isClosed() ?
				((Call*)rec)->branch_main()->sipcalledip_encaps_rslt :
				((Call*)rec)->getSipcalledip_encaps(((Call*)rec)->branch_main(), true, true));
		case cf_rtp_src:
		case cf_rtp_dst: {
			int side = registerFieldIndex == cf_rtp_src ? 0 : 1;
			if(((Call*)rec)->saved_data) {
				if(((Call*)rec)->saved_data->saddr_exists[side]) {
					return(((Call*)rec)->saved_data->saddr[side]);
				}
				return(0);
			}
			RTP *rtp = side == 0 ? ((Call*)rec)->lastactivecallerrtp : ((Call*)rec)->lastactivecalledrtp;
			if(rtp) {
				return(rtp->saddr);
			}
			return(0);
			}
		}
		return(0);
	}
	string getField_string(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case cf_caller:
			return(((Call*)rec)->saved_data ?
				((Call*)rec)->saved_data->caller :
				((Call*)rec)->branch_main()->caller);
		case cf_called:
			return(((Call*)rec)->saved_data ?
				((Call*)rec)->saved_data->called :
				((Call*)rec)->get_called(((Call*)rec)->branch_main()));
		case cf_callerdomain:
			return(((Call*)rec)->branch_main()->caller_domain);
		case cf_calleddomain:
			return(((Call*)rec)->saved_data ?
				((Call*)rec)->saved_data->called_domain :
				((Call*)rec)->get_called_domain(((Call*)rec)->branch_main()));
		case cf_calleragent:
			return(((Call*)rec)->saved_data ?
				((Call*)rec)->saved_data->a_ua :
				((Call*)rec)->get_a_ua(((Call*)rec)->branch_main()));
		case cf_calledagent:
			return(((Call*)rec)->saved_data ?
				((Call*)rec)->saved_data->b_ua :
				((Call*)rec)->get_b_ua(((Call*)rec)->branch_main()));
		case cf_callid:
			return(((Call*)rec)->fbasename);
		case cf_callername:
			return(((Call*)rec)->saved_data ?
				((Call*)rec)->saved_data->callername :
				((Call*)rec)->branch_main()->callername);
		case cf_digest_username:
			return(((Call*)rec)->branch_main()->digest_username);
		case cf_lastSIPresponse:
			return(((Call*)rec)->branch_main()->lastSIPresponse);
		case cf_caller_country:
		case cf_callerip_country:
			{
			if(((Call*)rec)->saved_data) {
				if(!((Call*)rec)->saved_data->countries_set) {
					return("");
				}
				return(registerFieldIndex == cf_caller_country ?
					((Call*)rec)->saved_data->caller_country :
					((Call*)rec)->saved_data->callerip_country);
			}
			vmIP ip = ((Call*)rec)->isClosed() ?
				  ((Call*)rec)->getSipcallerip(((Call*)rec)->branch_main()) :
				  ((Call*)rec)->getSipcallerip_corrected(((Call*)rec)->branch_main());
			return(registerFieldIndex == cf_caller_country ?
				getCountryByPhoneNumber(((Call*)rec)->branch_main()->caller.c_str(), ip, true) :
				getCountryByIP(ip, true));
			}
		case cf_called_country:
		case cf_calledip_country:
			{
			if(((Call*)rec)->saved_data) {
				if(!((Call*)rec)->saved_data->countries_set) {
					return("");
				}
				return(registerFieldIndex == cf_called_country ?
					((Call*)rec)->saved_data->called_country :
					((Call*)rec)->saved_data->calledip_country);
			}
			vmIP ip = getField_ip(rec, cf_calledip);
			return(registerFieldIndex == cf_called_country ?
				getCountryByPhoneNumber(((Call*)rec)->get_called(((Call*)rec)->branch_main()), ip, true) :
				getCountryByIP(ip, true));
			}
		}
		return("");
	}
private:
	void addFilterAB(cFilterData &filterData, const char *name1, const char *name2, const char *typeName, sAbDef def);
	void addFilterNumInterval(cFilterData &filterData, const char *name, unsigned field, cRecordFilterItem_base::eCmpCond cond, bool zeroIsEmpty = false, bool mysqlConversion = false);
	void addFilterCdrMetric(cFilterData &filterData, const char *name, const char *columns_a, const char *columns_b, double divisor);
	void addFilterStreamMetric(cFilterData &filterData, const char *name, cRecordFilterItem_CallStream::eField field);
	void addFilterStreams(cFilterData &filterData);
	struct sCombRow {
		int logic_level;
		bool negative;
		bool unresolved;
		string filter_cfg;
	};
	void addFilterCombination(cFilterData &filterData);
	void buildCombinationGroup(vector<sCombRow> *rows, unsigned *index, cRecordFilterItems *group);
	cRecordFilterItem_base *createCombinationLeaf(sCombRow *row);
	void addFilterStreamPorts(cFilterData &filterData);
	void addFilterStreamIpPorts(cFilterData &filterData, const char *nameSource, const char *nameDest, const char *nameType,
				    cRecordFilterItem_CallStreamIpPort::eTarget target, bool sdp);
	void addFilterDataNotAvailable(cFilterData &filterData, const char *name);
	void addFilterCdrDelay(cFilterData &filterData);
	void addFilterCdrLoss(cFilterData &filterData);
	void addFilterCdrLastRtpFromEnd(cFilterData &filterData);
	cRecordFilterItem_base *createAbItem(sAbDef *def, int side, const char *value);
	cRecordFilterItem_CallProxy *createAbProxyItem(sAbDef *def, const char *value);
	bool isEmptyOrZero(const string &value) {
		return(value.empty() || value == "0");
	}
	double durationValue(u_int64_t duration_us, bool use_ms) {
		return(use_ms ? round(TIME_US_TO_SF(duration_us) * 1000) / 1000 : TIME_US_TO_S(duration_us));
	}
private:
	string unsupportedKeys;
	string unsupportedKeysComb;
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
