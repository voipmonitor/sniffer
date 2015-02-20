#ifndef FRAUD_H
#define FRAUD_H


#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "voipmonitor.h"

#include "tools.h"
#include "sql_db.h"


#define fraud_alert_rcc 21
#define fraud_alert_chc 22
#define fraud_alert_chcr 23
#define fraud_alert_d 24
#define fraud_alert_spc 25
#define fraud_alert_rc 26

extern timeval t;
class TimePeriod {
public:
	TimePeriod(SqlDb_row *dbRow = NULL);
	bool checkTime(const char *time) {
		return(checkTime(getDateTime(time)));
	}
	bool checkTime(u_int64_t time) {
		return(checkTime(getDateTime(time)));
	}
	bool checkTime(time_t time) {
		return(checkTime(getDateTime(time)));
	}
	bool checkTime(struct tm time) {
		bool rslt = true;
		if(is_hourmin) {
			if(from_hour * 100 + from_minute > to_hour * 100 + to_minute) {
				if(time.tm_hour * 100 + time.tm_min < from_hour * 100 + from_minute &&
				   time.tm_hour * 100 + time.tm_min > to_hour * 100 + to_minute) {
					rslt = false;
				}
			} else {
				if(time.tm_hour * 100 + time.tm_min < from_hour * 100 + from_minute ||
				   time.tm_hour * 100 + time.tm_min > to_hour * 100 + to_minute) {
					rslt = false;
				}
			}
		}
		if(is_weekday && rslt) {
			if(from_weekday > to_weekday) {
				if(time.tm_wday + 1 < from_weekday &&
				   time.tm_wday + 1 > to_weekday) {
					rslt = false;
				}
			} else {
				if(time.tm_wday + 1 < from_weekday ||
				   time.tm_wday + 1 > to_weekday) {
					rslt = false;
				}
			}
		}
		if(is_monthday && rslt) {
			if(from_monthday > to_monthday) {
				if(time.tm_mday < from_monthday &&
				   time.tm_mday > to_monthday) {
					rslt = false;
				}
			} else {
				if(time.tm_mday < from_monthday ||
				   time.tm_mday > to_monthday) {
					rslt = false;
				}
			}
		}
		if(is_month && rslt) {
			if(from_month > to_month) {
				if(time.tm_mon + 1 < from_month &&
				   time.tm_mon + 1 > to_month) {
					rslt = false;
				}
			} else {
				if(time.tm_mon + 1 < from_month ||
				   time.tm_mon + 1 > to_month) {
					rslt = false;
				}
			}
		}
		return(rslt);
	}
private:
	string descr;
	bool is_hourmin;
	int from_hour;
	int from_minute;
	int to_hour;
	int to_minute;
	bool is_weekday;
	int from_weekday;
	int to_weekday;
	bool is_monthday;
	int from_monthday;
	int to_monthday;
	bool is_month;
	int from_month;
	int to_month;
};


class CountryCodes {
public:
	CountryCodes();
	void load();
	bool isCountry(const char *code);
	string getNameCountry(const char *code);
	string getNameContinent(const char *code);
	string getName(const char *code);
	string getContinent(const char *code);
	bool isLocationIn(const char *location, vector<string> *in, bool continent = false);
private:
	map<string, string> continents;
	map<string, string> countries;
	map<string, vector<string> > continentCountry;
	map<string, string> countryContinent;
};

class CheckInternational {
public:
	CheckInternational();
	void setPrefixes(const char *prefixes);
	void setInternationalMinLength(int internationalMinLength);
	void load(SqlDb_row *dbRow);
	bool isInternational(const char *number, const char **prefix = NULL) {
		if(prefix) {
			*prefix = NULL;
		}
		int numberLength = strlen(number);
		for(size_t i = 0; i < prefixes.size(); i++) {
			if(numberLength > (int)prefixes[i].size() &&
			   !strncmp(number, prefixes[i].c_str(), prefixes[i].size())) {
				if(prefix) {
					*prefix = prefixes[i].c_str();
				}
				return(true);
			}
		}
		while(*number == '0') {
			--numberLength;
			++number;
		}
		if(internationalMinLength &&
		   numberLength >= internationalMinLength) {
			return(true);
		}
		return(false);
	}
	string normalize(const char *number, bool *international) {
		if(international) {
			*international = false;
		}
		const char *prefix;
		if(isInternational(number, &prefix)) {
			if(international) {
				*international = true;
			}
			if(prefix) {
				number += strlen(prefix);
			}
			while(*number == '0') {
				++number;
			}
		}
		return(number);
	}
	const char *getLocalCountry() {
		extern char opt_local_country_code[10];
		return(!countryCodeForLocalNumbers.empty() ? 
			countryCodeForLocalNumbers.c_str() :
			opt_local_country_code);
	}
	bool countryCodeIsLocal(const char *countryCode) {
		extern char opt_local_country_code[10];
		return(!countryCodeForLocalNumbers.empty() ?
			!strcmp(countryCodeForLocalNumbers.c_str(), countryCode) :
		       opt_local_country_code[0] ?
			!strcmp(opt_local_country_code, countryCode) :
			false);
	}
private:
	vector<string> prefixes;
	int internationalMinLength;
	string countryCodeForLocalNumbers;
};

class CountryPrefixes {
public:
	struct CountryPrefix_rec {
		CountryPrefix_rec(const char *number = NULL, const char *country_code = NULL, const char *descr  = NULL) {
			if(number) {
				this->number = number;
			}
			if(country_code) {
				this->country_code = country_code;
			}
			if(descr) {
				this->descr = descr;
			}
		}
		bool operator < (const CountryPrefix_rec& other) const { 
			return(this->number < other.number); 
		}
		string number;
		string country_code;
		string descr;
	};
public:
	CountryPrefixes();
	void load();
	string getCountry(const char *number, vector<string> *countries,
			  CheckInternational *checkInternational) {
		if(countries) {
			countries->clear();
		}
		bool isInternational;
		string normalizeNumber = checkInternational->normalize(number, &isInternational);
		if(!isInternational) {
			string country = checkInternational->getLocalCountry();
			countries->push_back(country);
			return(country);
		}
		number = normalizeNumber.c_str();
		vector<CountryPrefix_rec>::iterator findRecIt;
		findRecIt = std::lower_bound(data.begin(), data.end(), number);
		if(findRecIt == data.end()) {
			--findRecIt;
		}
		int _redukSizeFindNumber = 0;
		while(strncmp(findRecIt->number.c_str(), number, findRecIt->number.length())) {
			if(findRecIt->number[0] < number[0]) {
				return("");
			}
			if((!_redukSizeFindNumber || _redukSizeFindNumber > 1) &&
			   atol(findRecIt->number.c_str()) < atol(normalizeNumber.substr(0, findRecIt->number.length()).c_str())) {
				if(_redukSizeFindNumber) {
					--_redukSizeFindNumber;
				} else {
					_redukSizeFindNumber = findRecIt->number.length() - 1;
				}
				findRecIt = std::lower_bound(data.begin(), data.end(), string(number).substr(0, _redukSizeFindNumber).c_str());
				if(findRecIt == data.end()) {
					--findRecIt;
				}
			} else {
				if(findRecIt == data.begin()) {
					return("");
				} else {
					--findRecIt;
				}
			}
		}
		if(!strncmp(findRecIt->number.c_str(), number, findRecIt->number.length())) {
			string rslt = findRecIt->country_code;
			string rsltNumber = findRecIt->number;
			if(countries) {
				countries->push_back(rslt);
				while(findRecIt != data.begin()) {
					--findRecIt;
					if(rsltNumber == findRecIt->number) {
						countries->push_back(findRecIt->country_code);
					} else {
						break;
					}
				}
			}
			return(rslt);
		}
		return("");
	}
	bool isLocal(const char *number,
		     CheckInternational *checkInternational) {
		if(!checkInternational->isInternational(number)) {
			return(true);
		}
		vector<string> countries;
		getCountry(number, &countries, checkInternational);
		for(size_t i = 0; i < countries.size(); i++) {
			if(checkInternational->countryCodeIsLocal(countries[i].c_str())) {
				return(true); 
			}
		}
		return(false);
	}
private:
	vector<CountryPrefix_rec> data;
};


class GeoIP_country {
public:
	struct GeoIP_country_rec {
		GeoIP_country_rec(unsigned int ip_from = 0, unsigned int ip_to = 0, const char *country_code = NULL) {
			this->ip_from = ip_from;
			this->ip_to = ip_to;
			if(country_code) {
				this->country_code = country_code;
			}
		}
		bool operator < (const GeoIP_country_rec& other) const { 
			return(this->ip_from < other.ip_from); 
		}
		unsigned int ip_from;
		unsigned int ip_to;
		string country_code;
	};
public:
	GeoIP_country();
	void load();
	string getCountry(unsigned int ip) {
		vector<GeoIP_country_rec>::iterator findRecIt;
		findRecIt = std::lower_bound(data.begin(), data.end(), ip);
		if(findRecIt == data.end()) {
			--findRecIt;
		}
		for(int i = 0; i < 2; i++) {
			if(findRecIt->ip_from <= ip && findRecIt->ip_to >= ip) {
				return(findRecIt->country_code);
			}
			if(findRecIt == data.begin()) {
				break;
			}
			--findRecIt;
		}
		return("");
	}
	string getCountry(const char *ip) {
		in_addr ips;
		inet_aton(ip, &ips);
		return(getCountry(htonl(ips.s_addr)));
	}
	bool isLocal(unsigned int ip,
		     CheckInternational *checkInternational) {
		string countryCode = getCountry(ip);
		return(checkInternational->countryCodeIsLocal(countryCode.c_str()));
	}
	bool isLocal(const char *ip,
		     CheckInternational *checkInternational) {
		in_addr ips;
		inet_aton(ip, &ips);
		return(isLocal(htonl(ips.s_addr), checkInternational));
	}
private:
	vector<GeoIP_country_rec> data;
};

class CacheNumber_location {
public:
	struct sNumber {
		sNumber(const char *number = NULL, u_int32_t ip = 0) {
			if(number) {
				this->number = number;
			}
			this->ip = ip;
		}
		string number;
		u_int32_t ip;
		bool operator == (const sNumber& other) const { 
			return(this->number == other.number &&
			       this->ip == other.ip); 
		}
		bool operator < (const sNumber& other) const { 
			return(this->number < other.number ||
			       (this->number == other.number &&
				this->ip < other.ip)); 
		}
	};
	struct sIpRec {
		sIpRec() {
			ip = 0;
			at = 0;
			old_ip = 0;
			old_at = 0;
			fresh_at = 0;
		}
		u_int32_t ip;
		string country_code;
		string continent_code;
		u_int64_t at;
		u_int32_t old_ip;
		string old_country_code;
		string old_continent_code;
		u_int64_t old_at;
		u_int64_t fresh_at;
	};
	CacheNumber_location();
	~CacheNumber_location();
	bool checkNumber(const char *number, u_int32_t number_ip,
			 u_int32_t ip, u_int64_t at,
			 bool *diffCountry = NULL, bool *diffContinent = NULL,
			 u_int32_t *oldIp = NULL, string *oldCountry = NULL, string *oldContinent = NULL,
			 const char *ip_country = NULL, const char *ip_continent = NULL);
	bool loadNumber(const char *number, u_int32_t number_ip, u_int64_t at);
	void saveNumber(const char *number, u_int32_t number_ip, sIpRec *ipRec, bool update = false);
	void updateAt(const char *number, u_int32_t number_ip, u_int64_t at);
	void cleanup(u_int64_t at);
private:
	SqlDb *sqlDb;
	map<sNumber, sIpRec> cache;
	u_int64_t last_cleanup_at;
};

struct sFraudCallInfo {
	enum eTypeCallInfo {
		typeCallInfo_beginCall,
		typeCallInfo_connectCall,
		typeCallInfo_seenByeCall,
		typeCallInfo_endCall
	};
	sFraudCallInfo() {
		typeCallInfo = (eTypeCallInfo)0;
		call_type = 0;
		caller_ip = 0;
		called_ip = 0;
		at_begin = 0;
		at_connect = 0;
		at_seen_bye = 0;
		at_end = 0;
		at_last = 0;
		local_called_number = true;
		local_called_ip = true;
	}
	eTypeCallInfo typeCallInfo;
	int call_type;
	string callid;
	string caller_number;
	string called_number;
	u_int32_t caller_ip;
	u_int32_t called_ip;
	string country_code_caller_number;
	string country2_code_caller_number;
	string country_code_called_number;
	string country2_code_called_number;
	string continent_code_caller_number;
	string continent2_code_caller_number;
	string continent_code_called_number;
	string continent2_code_called_number;
	string country_code_caller_ip;
	string country_code_called_ip;
	string continent_code_caller_ip;
	string continent_code_called_ip;
	bool local_called_number;
	bool local_called_ip;
	u_int64_t at_begin;
	u_int64_t at_connect;
	u_int64_t at_seen_bye;
	u_int64_t at_end;
	u_int64_t at_last;
};

struct sFraudEventInfo {
	enum eTypeEventInfo {
		typeEventInfo_sipPacket,
		typeEventInfo_register,
		typeEventInfo_registerResponse
	};
	sFraudEventInfo() {
		typeEventInfo = (eTypeEventInfo)0;
		src_ip = 0;
		at = 0;
	}
	eTypeEventInfo typeEventInfo;
	u_int32_t src_ip;
	u_int64_t at;
};

class FraudAlertInfo {
public:
	FraudAlertInfo(class FraudAlert *alert);
	virtual ~FraudAlertInfo() {}
	string getAlertTypeString();
	string getAlertDescr();
	unsigned int getAlertDbId();
	virtual string getString() { return(""); }
	virtual string getJson() { return("{}"); }
protected:
	void setAlertJsonBase(JsonExport *json);
protected:
	FraudAlert *alert;
};

class FraudAlert {
public:
	enum eFraudAlertType {
		_rcc =	fraud_alert_rcc,
		_chc =	fraud_alert_chc,
		_chcr =	fraud_alert_chcr,
		_d =	fraud_alert_d,
		_spc =	fraud_alert_spc,
		_rc =	fraud_alert_rc
	};
	enum eTypeLocation {
		_typeLocation_NA,
		_typeLocation_country,
		_typeLocation_continent
	};
	enum eLocalInternational {
		_li_local,
		_li_international,
		_li_booth
	};
	FraudAlert(eFraudAlertType type, unsigned int dbId);
	virtual ~FraudAlert();
	void loadAlert();
	void loadFraudDef();
	eFraudAlertType getType() {
		return(type);
	}
	string getTypeString();
	string getDescr() {
		return(descr);
	}
	unsigned int getDbId() {
		return(dbId);
	}
	virtual void evCall(sFraudCallInfo *callInfo) {}
	virtual void evEvent(sFraudEventInfo *eventInfo) {}
	virtual bool okFilter(sFraudCallInfo *callInfo);
	virtual bool okFilter(sFraudEventInfo *eventInfo);
	virtual void evAlert(FraudAlertInfo *alertInfo);
protected:
	virtual void loadAlertVirt(SqlDb_row *row) {}
	virtual void addFraudDef(SqlDb_row *row) {}
	virtual bool defFilterIp() { return(false); }
	virtual bool defFilterNumber() { return(false); }
	virtual bool defFraudDef() { return(false); }
	virtual bool defConcuretCallsLimit() { return(false); }
	virtual bool defTypeChangeLocation() { return(false); }
	virtual bool defChangeLocationOk() { return(false); }
	virtual bool defDestLocation() { return(false); }
	virtual bool defInterval() { return(false); }
	virtual bool defSuppressRepeatingAlerts() { return(false); }
protected:
	eFraudAlertType type;
	unsigned int dbId;
	SqlDb_row dbRow;
	string descr;
	ListIP_wb ipFilter;
	ListPhoneNumber_wb phoneNumberFilter;
	unsigned int concurentCallsLimitLocal;
	unsigned int concurentCallsLimitInternational;
	unsigned int concurentCallsLimitBoth;
	eTypeLocation typeChangeLocation;
	vector<string> changeLocationOk;
	vector<string> destLocation;
	u_int32_t intervalLength;
	u_int32_t intervalLimit;
	CheckInternational checkInternational;
	bool suppressRepeatingAlerts;
	int alertOncePerHours;
friend class FraudAlerts;
friend class FraudAlert_rcc_base;
};

class FraudAlert_rcc_callInfo {
public:
	FraudAlert_rcc_callInfo();
	void addLocal(const char *callid, u_int64_t at) {
		calls_local[callid] = at;
	}
	void addInternational(const char *callid, u_int64_t at) {
		calls_international[callid] = at;
	}
private:
	map<string, u_int64_t> calls_local;
	map<string, u_int64_t> calls_international;
	u_int64_t last_alert_info_local;
	u_int64_t last_alert_info_international;
	u_int64_t last_alert_info_li;
friend class FraudAlert_rcc_base;
friend class FraudAlert_rcc_timePeriods;
friend class FraudAlert_rcc;
};

class FraudAlert_rcc_base {
private:
	struct sAlertInfo {
		sAlertInfo(size_t concurentCalls = 0, u_int64_t at = 0) {
			this->concurentCalls = concurentCalls;
			this->at = at;
		}
		size_t concurentCalls;
		u_int64_t at;
	};
public:
	void evCall_rcc(sFraudCallInfo *callInfo, class FraudAlert_rcc *alert, bool timeperiod);
protected:
	virtual bool checkTime(u_int64_t time) { return(true); }
	virtual string getDescr() { return(""); }
private:
	bool checkOkAlert(u_int32_t ip, size_t concurentCalls, u_int64_t at,
			  FraudAlert::eLocalInternational li,
			  FraudAlert_rcc *alert);
protected:
	unsigned int concurentCallsLimitLocal_tp;
	unsigned int concurentCallsLimitInternational_tp;
	unsigned int concurentCallsLimitBoth_tp;
	map<u_int32_t, FraudAlert_rcc_callInfo*> calls;
private:
	map<u_int32_t, sAlertInfo> alerts_local;
	map<u_int32_t, sAlertInfo> alerts_international;
	map<u_int32_t, sAlertInfo> alerts_booth;
};

class FraudAlert_rcc_timePeriods : public FraudAlert_rcc_base {
private:
	struct sAlertInfo {
		sAlertInfo() {
			concurentCallsLimitLocal = 0;
			concurentCallsLimitInternational = 0;
			concurentCallsLimitBoth = 0;
			at = 0;
		}
		unsigned int concurentCallsLimitLocal;
		unsigned int concurentCallsLimitInternational;
		unsigned int concurentCallsLimitBoth;
		u_int64_t at;
	};
public:
	FraudAlert_rcc_timePeriods(const char *descr, 
				   int concurentCallsLimitLocal, 
				   int concurentCallsLimitInternational, 
				   int concurentCallsLimitBoth,
				   unsigned int dbId);
	~FraudAlert_rcc_timePeriods();
	void loadTimePeriods();
protected: 
	bool checkTime(u_int64_t time) {
		vector<TimePeriod>::iterator iter = timePeriods.begin();
		while(iter != timePeriods.end()) {
			if((*iter).checkTime(time)) {
				return(true);
			}
			++iter;
		}
		return(false);
	}
	string getDescr() {
		return(descr);
	}
private:
	string descr;
	unsigned int dbId;
	vector<TimePeriod> timePeriods;
	map<u_int32_t, sAlertInfo> alerts;
};

class FraudAlertInfo_rcc : public FraudAlertInfo {
public:
	FraudAlertInfo_rcc(FraudAlert *alert);
	void set(FraudAlert::eLocalInternational localInternational,
		 const char *timeperiod_name,
		 u_int32_t ip, const char *ip_location_code,
		 unsigned int concurentCalls);
	string getString();
	string getJson();
private:
	FraudAlert::eLocalInternational localInternational;
	string timeperiod_name;
	u_int32_t ip;
	string ip_location_code;
	unsigned int concurentCalls;
};

class FraudAlert_rcc : public FraudAlert, FraudAlert_rcc_base {
public:
	FraudAlert_rcc(unsigned int dbId);
	~FraudAlert_rcc();
	void evCall(sFraudCallInfo *callInfo);
protected:
	void addFraudDef(SqlDb_row *row);
	bool defFilterIp() { return(true); }
	bool defFilterNumber() { return(true); }
	bool defFraudDef() { return(true); }
	bool defConcuretCallsLimit() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	vector<FraudAlert_rcc_timePeriods> timePeriods;
};

class FraudAlertInfo_chc : public FraudAlertInfo {
public:
	FraudAlertInfo_chc(FraudAlert *alert);
	void set(const char *number,
		 FraudAlert::eTypeLocation typeLocation,
		 u_int32_t ip,
		 const char *location_code,
		 u_int32_t ip_old,
		 const char *location_code_old);
	string getString();
	string getJson();
private:
	string number;
	FraudAlert::eTypeLocation typeLocation;
	u_int32_t ip;
	u_int32_t ip_old;
	string location_code;
	string location_code_old;
};

class FraudAlert_chc : public FraudAlert {
public:
	FraudAlert_chc(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
protected:
	bool defFilterNumber() { return(true); }
	bool defTypeChangeLocation() { return(true); }
	bool defChangeLocationOk() { return(true); }
};

class FraudAlert_chcr : public FraudAlert {
public:
	FraudAlert_chcr(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
protected:
	bool defFilterNumber() { return(true); }
	bool defTypeChangeLocation() { return(true); }
	bool defChangeLocationOk() { return(true); }
};

class FraudAlertInfo_d : public FraudAlertInfo {
public:
	FraudAlertInfo_d(FraudAlert *alert);
	void set(const char *src_number, 
		 const char *dst_number,
		 const char *country_code, 
		 const char *continent_code);
	string getString();
	string getJson();
private:
	string src_number;
	string dst_number;
	string country_code;
	string continent_code;
};

class FraudAlert_d : public FraudAlert {
private:
	struct sAlertInfo {
		sAlertInfo(const char *country_code = NULL, u_int64_t at = 0) {
			if(country_code) {
				this->country_code = country_code;
			}
			this->at = at;
		}
		string country_code;
		u_int64_t at;
	};
public:
	FraudAlert_d(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
protected:
	bool defFilterIp() { return(true); }
	bool defFilterNumber() { return(true); }
	bool defDestLocation() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	bool checkOkAlert(const char *src_number, const char *dst_number,
			  const char *country_code, u_int64_t at);
private:
	map<dstring, sAlertInfo> alerts;
};

class FraudAlertInfo_spc : public FraudAlertInfo {
public:
	FraudAlertInfo_spc(FraudAlert *alert);
	void set(unsigned int ip, 
		 unsigned int count);
	string getString();
	string getJson();
private:
	unsigned int ip;
	unsigned int count;
};

class FraudAlert_spc : public FraudAlert {
private:
	struct sCountItem {
		sCountItem(u_int64_t count = 0) {
			this->count = count;
		}
		u_int64_t count;
	};
	struct sAlertInfo {
		sAlertInfo(u_int64_t count = 0, u_int64_t at = 0) {
			this->count = count;
			this->at = at;
		}
		u_int64_t count;
		u_int64_t at;
	};
public:
	FraudAlert_spc(unsigned int dbId);
	void evEvent(sFraudEventInfo *eventInfo);
protected:
	bool defFilterIp() { return(true); }
	bool defInterval() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	bool checkOkAlert(u_int32_t ip, u_int64_t count, u_int64_t at);
private:
	map<u_int32_t, sCountItem> count;
	u_int64_t start_interval;
	map<u_int32_t, sAlertInfo> alerts;
};

class FraudAlert_rc : public FraudAlert {
private:
	struct sCountItem {
		sCountItem(u_int64_t count = 0) {
			this->count = count;
		}
		u_int64_t count;
	};
	struct sAlertInfo {
		sAlertInfo(u_int64_t count = 0, u_int64_t at = 0) {
			this->count = count;
			this->at = at;
		}
		u_int64_t count;
		u_int64_t at;
	};
public:
	FraudAlert_rc(unsigned int dbId);
	void evEvent(sFraudEventInfo *eventInfo);
protected:
	bool defFilterIp() { return(true); }
	bool defInterval() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	void loadAlertVirt(SqlDb_row *row);
	bool checkOkAlert(u_int32_t ip, u_int64_t count, u_int64_t at);
private:
	bool withResponse;
	map<u_int32_t, sCountItem> count;
	u_int64_t start_interval;
	map<u_int32_t, sAlertInfo> alerts;
};


class FraudAlerts {
public:
	FraudAlerts();
	~FraudAlerts();
	void loadAlerts();
	void clear();
	void beginCall(Call *call, u_int64_t at);
	void connectCall(Call *call, u_int64_t at);
	void seenByeCall(Call *call, u_int64_t at);
	void endCall(Call *call, u_int64_t at);
	void evSipPacket(u_int32_t ip, u_int64_t at);
	void evRegister(u_int32_t ip, u_int64_t at);
	void evRegisterResponse(u_int32_t ip, u_int64_t at);
	void stopPopCallInfoThread(bool wait = false);
	void refresh();
private:
	void initPopCallInfoThread();
	void popCallInfoThread();
	void getCallInfoFromCall(sFraudCallInfo *callInfo, Call *call, 
				 sFraudCallInfo::eTypeCallInfo typeCallInfo, u_int64_t at);
	void completeCallInfo_country_code(sFraudCallInfo *callInfo, CheckInternational *checkInternational);
	void lock_alerts() {
		while(__sync_lock_test_and_set(&this->_sync_alerts, 1));
	}
	void unlock_alerts() {
		__sync_lock_release(&this->_sync_alerts);
	}
private:
	vector<FraudAlert*> alerts;
	SafeAsyncQueue<sFraudCallInfo> callQueue;
	SafeAsyncQueue<sFraudEventInfo> eventQueue;
	pthread_t threadPopCallInfo;
	bool runPopCallInfoThread;
	bool termPopCallInfoThread;
	volatile int _sync_alerts;
friend void *_FraudAlerts_popCallInfoThread(void *arg);
};


void initFraud();
bool checkFraudTables();
void termFraud();
void refreshFraud();
void fraudBeginCall(Call *call, struct timeval tv);
void fraudConnectCall(Call *call, struct timeval tv);
void fraudSeenByeCall(Call *call, struct timeval tv);
void fraudEndCall(Call *call, struct timeval tv);
void fraudSipPacket(u_int32_t ip, timeval tv);
void fraudRegister(u_int32_t ip, timeval tv);
void fraudRegisterResponse(u_int32_t ip, u_int64_t at);
bool isExistsFraudAlerts();


#endif
