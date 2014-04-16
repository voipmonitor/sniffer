#ifndef FRAUD_H
#define FRAUD_H


#include <string>
#include <vector>
#include <map>
#include "voipmonitor.h"

#include "tools.h"
#include "sql_db.h"


#define fraud_alert_rcc 21
#define fraud_alert_chc 22
#define fraud_alert_chcr 23
#define fraud_alert_d 24

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
	string getCountry(const char *number, vector<string> *countries) {
		if(countries) {
			countries->clear();
		}
		size_t numberLen = strlen(number);
		if(numberLen > 1 && number[0] == '+') {
			number += 1;
		} else if(numberLen > 2 && number[0] == '0' && number[0] == '1') {
			number += 2;
		} else {
			extern char opt_local_country_code[10];
			if(countries) {
				countries->push_back(opt_local_country_code);
			}
			return(opt_local_country_code);
		}
		string _findNumber = number;
		vector<CountryPrefix_rec>::iterator findRecIt;
		findRecIt = std::lower_bound(data.begin(), data.end(), number);
		if(findRecIt == data.end()) {
			--findRecIt;
		}
		int _redukSizeFindNumber = 0;
		while(strncmp(findRecIt->number.c_str(), number, findRecIt->number.length())) {
			if(findRecIt->number[0] != number[0]) {
				return("");
			} 
			if((!_redukSizeFindNumber || _redukSizeFindNumber > 1) &&
			   atol(findRecIt->number.c_str()) < atol(_findNumber.substr(0, findRecIt->number.length()).c_str())) {
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
				--findRecIt;
			}
		}
		if(!strncmp(findRecIt->number.c_str(), number, findRecIt->number.length())) {
			string rslt = findRecIt->country_code;
			string rsltNumber = findRecIt->number;
			if(countries) {
				countries->push_back(rslt);
				do {
					--findRecIt;
					if(rsltNumber == findRecIt->number) {
						countries->push_back(findRecIt->country_code);
					} else {
						break;
					}
				} while(findRecIt != data.begin());
			}
			return(rslt);
		}
		return("");
	}
	bool isLocal(const char *number) {
		size_t numberLen = strlen(number);
		if(numberLen > 1 && number[0] == '+') {
			number += 1;
		} else if(numberLen > 2 && number[0] == '0' && number[0] == '1') {
			number += 2;
		} else {
			return(true);
		}
		vector<string> countries;
		getCountry(number, &countries);
		for(size_t i = 0; i < countries.size(); i++) {
			extern char opt_local_country_code[10];
			if(countries[i] == opt_local_country_code) {
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
		return(getCountry(ips.s_addr));
	}
	bool isLocal(unsigned int ip) {
		extern char opt_local_country_code[10];
		return(getCountry(ip) == opt_local_country_code);
	}
	bool isLocal(const char *ip) {
		in_addr ips;
		inet_aton(ip, &ips);
		return(isLocal(ips.s_addr));
	}
private:
	vector<GeoIP_country_rec> data;
};

class CacheNumber_location {
public:
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
	bool checkNumber(const char *number, u_int32_t ip, u_int64_t at,
			 bool *diffCountry = NULL, bool *diffContinent = NULL,
			 string *oldCountry = NULL, string *oldContinent = NULL,
			 const char *ip_country = NULL, const char *ip_continent = NULL);
	bool loadNumber(const char *number, u_int64_t at);
	void saveNumber(const char *number, sIpRec *ipRec, bool update = false);
	void updateAt(const char *number, u_int64_t at);
private:
	SqlDb *sqlDb;
	map<string, sIpRec> cache;
};

struct sFraudCallInfo {
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
	enum eTypeCallInfo {
		typeCallInfo_beginCall,
		typeCallInfo_connectCall,
		typeCallInfo_seenByeCall,
		typeCallInfo_endCall
	};
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
		_d =	fraud_alert_d
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
	virtual bool okFilter(sFraudCallInfo *callInfo);
	virtual void evAlert(FraudAlertInfo *alertInfo);
protected:
	virtual void addFraudDef(SqlDb_row *row) {}
	virtual bool defFilterIp() { return(false); }
	virtual bool defFilterNumber() { return(false); }
	virtual bool defFraudDef() { return(false); }
	virtual bool defConcuretCallsLimit() { return(false); }
	virtual bool defTypeChangeLocation() { return(false); }
	virtual bool defChangeLocationOk() { return(false); }
	virtual bool defDestLocation() { return(false); }
protected:
	eFraudAlertType type;
	unsigned int dbId;
	SqlDb_row dbRow;
	string descr;
	ListIP_wb ipFilter;
	ListPhoneNumber_wb phoneNumberFilter;
	unsigned int concurentCallsLimit;
	eTypeLocation typeChangeLocation;
	vector<string> changeLocationOk;
	vector<string> destLocation;
};

class FraudAlert_rcc_timePeriods {
public:
	FraudAlert_rcc_timePeriods(const char *descr, int concurentCallsLimit, unsigned int dbId);
	void loadTimePeriods();
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
	void evCall(sFraudCallInfo *callInfo, class FraudAlert_rcc *alert);
private:
	string descr;
	unsigned int concurentCallsLimit;
	unsigned int dbId;
	vector<TimePeriod> timePeriods;
	map<string, u_int64_t> calls_local;
	map<string, u_int64_t> calls_international;
	u_int64_t last_alert_info_local;
	u_int64_t last_alert_info_international;
	u_int64_t last_alert_info_li;
};

class FraudAlertInfo_rcc : public FraudAlertInfo {
public:
	FraudAlertInfo_rcc(FraudAlert *alert);
	void set(FraudAlert::eLocalInternational localInternational,
		 const char *timeperiod_name,
		 unsigned int concurentCalls);
	string getString();
	string getJson();
private:
	FraudAlert::eLocalInternational localInternational;
	string timeperiod_name;
	unsigned int concurentCalls;
};

class FraudAlert_rcc : public FraudAlert {
public:
	FraudAlert_rcc(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
protected:
	void addFraudDef(SqlDb_row *row);
	bool defFilterIp() { return(true); }
	bool defFilterNumber() { return(true); }
	bool defFraudDef() { return(true); }
	bool defConcuretCallsLimit() { return(true); }
private:
	vector<FraudAlert_rcc_timePeriods> timePeriods;
	map<string, u_int64_t> calls_local;
	map<string, u_int64_t> calls_international;
	u_int64_t last_alert_info_local;
	u_int64_t last_alert_info_international;
	u_int64_t last_alert_info_li;
};

class FraudAlertInfo_chc : public FraudAlertInfo {
public:
	FraudAlertInfo_chc(FraudAlert *alert);
	void set(const char *number,
		 FraudAlert::eTypeLocation typeLocation,
		 const char *location_code,
		 const char *location_code_old);
	string getString();
	string getJson();
private:
	string number;
	FraudAlert::eTypeLocation typeLocation;
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
public:
	FraudAlert_d(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
protected:
	bool defDestLocation() { return(true); }
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
	void stopPopCallInfoThread(bool wait = false);
private:
	void initPopCallInfoThread();
	void popCallInfoThread();
	void getCallInfoFromCall(sFraudCallInfo *callInfo, Call *call, 
				 sFraudCallInfo::eTypeCallInfo typeCallInfo, u_int64_t at);
	void completeCallInfo_country_code(sFraudCallInfo *callInfo);
private:
	vector<FraudAlert*> alerts;
	SafeAsyncQueue<sFraudCallInfo> callQueue;
	pthread_t threadPopCallInfo;
	bool runPopCallInfoThread;
	bool terminatingPopCallInfoThread;
friend void *_FraudAlerts_popCallInfoThread(void *arg);
};


void initFraud();
bool checkFraudTables();
void termFraud();
void fraudBeginCall(Call *call, struct timeval tv);
void fraudConnectCall(Call *call, struct timeval tv);
void fraudSeenByeCall(Call *call, struct timeval tv);
void fraudEndCall(Call *call, struct timeval tv);


#endif
