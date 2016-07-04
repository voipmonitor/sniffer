#ifndef FRAUD_H
#define FRAUD_H


#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "voipmonitor.h"

#include "tools.h"
#include "sql_db.h"
#include "register.h"
#include "filter_register.h"


#define fraud_alert_rcc 21
#define fraud_alert_chc 22
#define fraud_alert_chcr 23
#define fraud_alert_d 24
#define fraud_alert_spc 25
#define fraud_alert_rc 26
#define fraud_alert_seq 27
#define fraud_alert_reg_ua 43
#define fraud_alert_reg_short 44
#define fraud_alert_reg_expire 46


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
	void setInternationalPrefixes(const char *prefixes);
	void setSkipPrefixes(const char *prefixes);
	void setInternationalMinLength(int internationalMinLength);
	void load(SqlDb_row *dbRow);
	bool isInternational(const char *number, const char **prefix = NULL) {
		if(prefix) {
			*prefix = NULL;
		}
		int numberLength = strlen(number);
		bool existsSkipPrefix = false;
		do {
			existsSkipPrefix = false;
			for(size_t i = 0; i < skipPrefixes.size(); i++) {
				if(numberLength > (int)skipPrefixes[i].size() &&
				   !strncmp(number, skipPrefixes[i].c_str(), skipPrefixes[i].size())) {
					number += skipPrefixes[i].size();
					while(*number == ' ') ++number;
					numberLength = strlen(number);
					existsSkipPrefix = true;
				}
			}
		} while(existsSkipPrefix);
		for(size_t i = 0; i < internationalPrefixes.size(); i++) {
			if(numberLength > (int)internationalPrefixes[i].size() &&
			   !strncmp(number, internationalPrefixes[i].c_str(), internationalPrefixes[i].size())) {
				if(prefix) {
					*prefix = internationalPrefixes[i].c_str();
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
	vector<string> internationalPrefixes;
	int internationalMinLength;
	string countryCodeForLocalNumbers;
	vector<string> skipPrefixes;
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

struct sFraudNumberInfo {
	sFraudNumberInfo() {
		local_called_number = true;
	}
	string caller_number;
	string called_number;
	string country_code_caller_number;
	string country2_code_caller_number;
	string country_code_called_number;
	string country2_code_called_number;
	string continent_code_caller_number;
	string continent2_code_caller_number;
	string continent_code_called_number;
	string continent2_code_called_number;
	bool local_called_number;
};

struct sFraudCallInfo : public sFraudNumberInfo {
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
		local_called_ip = true;
	}
	eTypeCallInfo typeCallInfo;
	int call_type;
	string callid;
	u_int32_t caller_ip;
	u_int32_t called_ip;
	string country_code_caller_ip;
	string country_code_called_ip;
	string continent_code_caller_ip;
	string continent_code_called_ip;
	bool local_called_ip;
	u_int64_t at_begin;
	u_int64_t at_connect;
	u_int64_t at_seen_bye;
	u_int64_t at_end;
	u_int64_t at_last;
};

struct sFraudRtpStreamInfo : public sFraudNumberInfo {
	enum eTypeRtpStreamInfo {
		typeRtpStreamInfo_beginStream,
		typeRtpStreamInfo_endStream
	};
	sFraudRtpStreamInfo() {
		rtp_src_ip = 0;
		rtp_src_ip_group = 0;
		rtp_src_port = 0;
		rtp_dst_ip = 0;
		rtp_dst_ip_group = 0;
		rtp_dst_port = 0;
		local_called_number = true;
		at = 0;
	}
	eTypeRtpStreamInfo typeRtpStreamInfo;
	string callid;
	u_int32_t rtp_src_ip;
	u_int32_t rtp_src_ip_group;
	u_int16_t rtp_src_port;
	u_int32_t rtp_dst_ip;
	u_int32_t rtp_dst_ip_group;
	u_int16_t rtp_dst_port;
	string country_code_rtp_src_ip;
	string country_code_rtp_dst_ip;
	string continent_code_rtp_src_ip;
	string continent_code_rtp_dst_ip;
	u_int64_t at;
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
		sip_method = 0;
		at = 0;
	}
	eTypeEventInfo typeEventInfo;
	u_int32_t src_ip;
	unsigned sip_method;
	u_int64_t at;
	string ua;
};

struct sFraudRegisterInfo_id {
	u_int32_t sipcallerip;
	u_int32_t sipcalledip;
	string to_num;
	string to_domain;
	string contact_num;
	string contact_domain;
	string digest_username;
	bool operator == (const sFraudRegisterInfo_id& other) const {
		return(this->sipcallerip == other.sipcallerip &&
		       this->sipcalledip == other.sipcalledip &&
		       this->to_num == other.to_num &&
		       this->to_domain == other.to_domain &&
		       this->contact_num == other.contact_num &&
		       this->contact_domain == other.contact_domain &&
		       this->digest_username == other.digest_username);
	}
	bool operator < (const sFraudRegisterInfo_id& other) const { 
		int rslt_cmp_to_num;
		int rslt_cmp_to_domain;
		int rslt_cmp_contact_num;
		int rslt_cmp_contact_domain;
		int rslt_cmp_digest_username;
		return((this->sipcallerip < other.sipcallerip) ? 1 : (this->sipcallerip > other.sipcallerip) ? 0 :
		       (this->sipcalledip < other.sipcalledip) ? 1 : (this->sipcalledip > other.sipcalledip) ? 0 :
		       ((rslt_cmp_to_num = strcasecmp(this->to_num.c_str(), other.to_num.c_str())) < 0) ? 1 : (rslt_cmp_to_num > 0) ? 0 :
		       ((rslt_cmp_to_domain = strcasecmp(this->to_domain.c_str(), other.to_domain.c_str())) < 0) ? 1 : (rslt_cmp_to_domain > 0) ? 0 :
		       ((rslt_cmp_contact_num = strcasecmp(this->contact_num.c_str(), other.contact_num.c_str())) < 0) ? 1 : (rslt_cmp_contact_num > 0) ? 0 :
		       ((rslt_cmp_contact_domain = strcasecmp(this->contact_domain.c_str(), other.contact_domain.c_str())) < 0) ? 1 : (rslt_cmp_contact_domain > 0) ? 0 :
		       ((rslt_cmp_digest_username = strcasecmp(this->digest_username.c_str(), other.digest_username.c_str())) < 0));
	}
};

struct sFraudRegisterInfo_data {
	string from_num;
	string from_name;
	string from_domain;
	string digest_realm;
	string ua;
	eRegisterState state;
	eRegisterState prev_state;
	u_int64_t at;
	u_int64_t prev_state_at;
	u_int32_t time_from_prev_state;
};

struct sFraudRegisterInfo : public sFraudRegisterInfo_id, public sFraudRegisterInfo_data {
};

class FraudAlertInfo {
public:
	FraudAlertInfo(class FraudAlert *alert);
	virtual ~FraudAlertInfo() {}
	string getAlertTypeString();
	string getAlertDescr();
	unsigned int getAlertDbId();
	virtual string getJson() { return("{}"); }
protected:
	void setAlertJsonBase(JsonExport *json);
protected:
	FraudAlert *alert;
};

class FraudAlert {
public:
	enum eFraudAlertType {
		_rcc =		fraud_alert_rcc,
		_chc =		fraud_alert_chc,
		_chcr =		fraud_alert_chcr,
		_d =		fraud_alert_d,
		_spc =		fraud_alert_spc,
		_rc =		fraud_alert_rc,
		_seq =		fraud_alert_seq,
		_reg_ua =	fraud_alert_reg_ua,
		_reg_short =	fraud_alert_reg_short,
		_reg_expire =	fraud_alert_reg_expire
	};
	enum eTypeLocation {
		_typeLocation_NA,
		_typeLocation_country,
		_typeLocation_continent
	};
	enum eTypeBy {
		_typeBy_NA,
		_typeBy_source_ip,
		_typeBy_source_number,
		_typeBy_rtp_stream_ip,
		_typeBy_rtp_stream_ip_group
	};
	enum eLocalInternational {
		_li_local,
		_li_international,
		_li_booth
	};
	FraudAlert(eFraudAlertType type, unsigned int dbId);
	virtual ~FraudAlert();
	bool isReg();
	bool loadAlert();
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
	virtual void evRtpStream(sFraudRtpStreamInfo *rtpStreamInfo) {}
	virtual void evEvent(sFraudEventInfo *eventInfo) {}
	virtual void evRegister(sFraudRegisterInfo *registerInfo) {}
	virtual bool okFilter(sFraudCallInfo *callInfo);
	virtual bool okFilter(sFraudRtpStreamInfo *rtpStreamInfo);
	virtual bool okFilter(sFraudEventInfo *eventInfo);
	virtual bool okFilter(sFraudRegisterInfo *registerInfo);
	virtual bool okDayHour(sFraudCallInfo *callInfo) {
		if(!callInfo->at_last) {
			return(true);
		}
		return(this->okDayHour(callInfo->at_last / 1000000ull));
	}
	virtual bool okDayHour(sFraudRtpStreamInfo *rtpStreamInfo) {
		if(!rtpStreamInfo->at) {
			return(true);
		}
		return(this->okDayHour(rtpStreamInfo->at / 1000000ull));
	}
	virtual bool okDayHour(sFraudEventInfo *eventInfo) {
		if(!eventInfo->at) {
			return(true);
		}
		return(this->okDayHour(eventInfo->at / 1000000ull));
	}
	virtual bool okDayHour(time_t at);
	virtual void evAlert(FraudAlertInfo *alertInfo);
protected:
	virtual void loadAlertVirt() {}
	virtual void addFraudDef(SqlDb_row *row) {}
	virtual bool defFilterIp() { return(false); }
	virtual bool defFilterIp2() { return(false); }
	virtual bool defStreamFilterIp() { return(false); }
	virtual bool defFilterNumber() { return(false); }
	virtual bool defFilterNumber2() { return(false); }
	virtual bool defFilterUA() { return(false); }
	virtual bool defFraudDef() { return(false); }
	virtual bool defConcuretCallsLimit() { return(false); }
	virtual bool defTypeBy() { return(false); }
	virtual bool defTypeChangeLocation() { return(false); }
	virtual bool defChangeLocationOk() { return(false); }
	virtual bool defDestLocation() { return(false); }
	virtual bool defInterval() { return(false); }
	virtual bool defOnlyConnected() { return(false); }
	virtual bool defSuppressRepeatingAlerts() { return(false); }
protected:
	eFraudAlertType type;
	unsigned int dbId;
	SqlDb_row dbRow;
	string descr;
	ListIP_wb ipFilter;
	ListIP_wb ipFilter2;
	ListPhoneNumber_wb phoneNumberFilter;
	ListPhoneNumber_wb phoneNumberFilter2;
	ListUA_wb uaFilter;
	unsigned int concurentCallsLimitLocal;
	unsigned int concurentCallsLimitInternational;
	unsigned int concurentCallsLimitBoth;
	eTypeBy typeBy;
	eTypeLocation typeChangeLocation;
	vector<string> changeLocationOk;
	vector<string> destLocation;
	u_int32_t intervalLength;
	u_int32_t intervalLimit;
	CheckInternational checkInternational;
	bool onlyConnected;
	bool suppressRepeatingAlerts;
	int alertOncePerHours;
	int hour_from;
	int hour_to;
	bool day_of_week[7];
	bool day_of_week_set;
friend class FraudAlerts;
friend class FraudAlert_rcc_base;
friend class FraudAlert_rcc_timePeriods;
};

class FraudAlertReg_filter {
public:
	FraudAlertReg_filter(class FraudAlertReg *parent);
	~FraudAlertReg_filter();
	void setFilter(const char *description, const char *filter_str);
protected:
	void evRegister(sFraudRegisterInfo *registerInfo);
	bool okFilter(sFraudRegisterInfo *registerInfo);
protected:
	string description;
	string filter_str;
	cRegisterFilter *filter;
	u_int64_t ev_counter;
	map<sFraudRegisterInfo_id, sFraudRegisterInfo_data> ev_map;
	u_int64_t start_interval;
	FraudAlertReg *parent;
friend class FraudAlertReg;
};

class FraudAlertReg : public FraudAlert {
public:
	FraudAlertReg(eFraudAlertType type, unsigned int dbId);
	~FraudAlertReg();
protected:
	void evRegister(sFraudRegisterInfo *registerInfo);
	bool checkUA(const char *ua);
	bool checkRegisterTimeSecLe(sFraudRegisterInfo *registerInfo);
private:
	void loadAlertVirt();
	void loadFilters();
protected:
	map<u_int32_t, FraudAlertReg_filter*> filters;
	u_int32_t intervalLength;
	u_int32_t intervalLimit;
	vector<cRegExp*> ua_regex;
	u_int32_t registerTimeSecLe;
friend class FraudAlertReg_filter;
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
};

class FraudAlert_rcc_rtpStreamInfo {
public: 
	struct str_dipn_port {
		str_dipn_port(string str, u_int32_t ip1, u_int16_t port1, u_int32_t ip2, u_int16_t port2) {
			this->str = str;
			this->dipn_port = d_item<ipn_port>(ipn_port(ip1, port1), ipn_port(ip2, port2));
		}
		bool operator == (const str_dipn_port& other) const { 
			return(this->str == other.str &&
			       this->dipn_port == other.dipn_port); 
		}
		bool operator < (const str_dipn_port& other) const { 
			return(this->str < other.str ||
			       (this->str == other.str && this->dipn_port < other.dipn_port)); 
		}
		string str;
		d_item<ipn_port> dipn_port;
	};
public:
	FraudAlert_rcc_rtpStreamInfo();
	void addLocal(const char *callid, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, u_int64_t at) {
		calls_local[str_dipn_port(callid, saddr, sport, daddr, dport)] = at;
	}
	void removeLocal(const char *callid, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport) {
		calls_local.erase(str_dipn_port(callid, saddr, sport, daddr, dport));
	}
	void addInternational(const char *callid, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, u_int64_t at) {
		calls_international[str_dipn_port(callid, saddr, sport, daddr, dport)] = at;
	}
	void removeInternational(const char *callid, u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport) {
		calls_international.erase(str_dipn_port(callid, saddr, sport, daddr, dport));
	}
private:
	map<str_dipn_port, u_int64_t> calls_local;
	map<str_dipn_port, u_int64_t> calls_international;
	u_int64_t last_alert_info_local;
	u_int64_t last_alert_info_international;
	u_int64_t last_alert_info_li;
friend class FraudAlert_rcc_base;
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
	struct sIdAlert {
		sIdAlert(u_int32_t ip = 0) {
			this->ip = ip;
		}
		sIdAlert(const char *number) {
			this->number = number;
			this->ip = 0;
		}
		sIdAlert(d_u_int32_t rtp_stream) {
			this->rtp_stream = rtp_stream;
			this->ip = 0;
		}
		bool operator == (const sIdAlert& other) const { 
			return(this->ip ?
				this->ip == other.ip :
			       !this->number.empty() ?
				this->number == other.number : 
				this->rtp_stream == other.rtp_stream); 
		}
		bool operator < (const sIdAlert& other) const { 
			return(this->ip ?
				this->ip < other.ip :
			       !this->number.empty() ?
				this->number < other.number : 
				this->rtp_stream < other.rtp_stream); 
		}
		u_int32_t ip;
		string number;
		d_u_int32_t rtp_stream;
	};
public:
	FraudAlert_rcc_base(class FraudAlert_rcc *parent);
	~FraudAlert_rcc_base();
	void evCall_rcc(sFraudCallInfo *callInfo, class FraudAlert_rcc *alert, bool timeperiod);
	void evRtpStream_rcc(sFraudRtpStreamInfo *rtpStreamInfo, class FraudAlert_rcc *alert, bool timeperiod);
protected:
	virtual bool checkTime(u_int64_t time) { return(true); }
	virtual string getDescr() { return(""); }
	FraudAlert::eTypeBy getTypeBy();
private:
	bool checkOkAlert(sIdAlert idAlert, size_t concurentCalls, u_int64_t at,
			  FraudAlert::eLocalInternational li,
			  FraudAlert_rcc *alert);
protected:
	unsigned int concurentCallsLimitLocal_tp;
	unsigned int concurentCallsLimitInternational_tp;
	unsigned int concurentCallsLimitBoth_tp;
	map<u_int32_t, FraudAlert_rcc_callInfo*> calls_by_ip;
	map<string, FraudAlert_rcc_callInfo*> calls_by_number;
	map<d_u_int32_t, FraudAlert_rcc_rtpStreamInfo*> calls_by_rtp_stream;
private:
	map<sIdAlert, sAlertInfo> alerts_local;
	map<sIdAlert, sAlertInfo> alerts_international;
	map<sIdAlert, sAlertInfo> alerts_booth;
	FraudAlert_rcc *parent;
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
				   unsigned int dbId,
				   class FraudAlert_rcc *parent);
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
	FraudAlert_rcc *parent;
};

class FraudAlertInfo_rcc : public FraudAlertInfo {
public:
	FraudAlertInfo_rcc(FraudAlert *alert);
	void set_ip(FraudAlert::eLocalInternational localInternational,
		    const char *timeperiod_name,
		    u_int32_t ip, const char *ip_location_code,
		    unsigned int concurentCalls);
	void set_number(FraudAlert::eLocalInternational localInternational,
			const char *timeperiod_name,
			string number, const char *number_location_code,
			unsigned int concurentCalls);
	void set_rtp_stream(FraudAlert::eLocalInternational localInternational,
			    const char *timeperiod_name,
			    FraudAlert::eTypeBy type_by, d_u_int32_t rtp_stream,
			    unsigned int concurentCalls);
	string getJson();
private:
	FraudAlert::eLocalInternational localInternational;
	string timeperiod_name;
	FraudAlert::eTypeBy type_by;
	u_int32_t ip;
	string ip_location_code;
	string number;
	string number_location_code;
	d_u_int32_t rtp_stream;
	unsigned int concurentCalls;
};

class FraudAlert_rcc : public FraudAlert, FraudAlert_rcc_base {
public:
	FraudAlert_rcc(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
	void evRtpStream(sFraudRtpStreamInfo *rtpStreamInfo);
protected:
	void addFraudDef(SqlDb_row *row);
	bool defFilterIp() { return(getTypeBy() == FraudAlert::_typeBy_source_ip || 
				    getTypeBy() == FraudAlert::_typeBy_source_number); }
	bool defFilterIp2() { return(getTypeBy() == FraudAlert::_typeBy_source_ip || 
				     getTypeBy() == FraudAlert::_typeBy_source_number); }
	bool defStreamFilterIp() { return(getTypeBy() == FraudAlert::FraudAlert::_typeBy_rtp_stream_ip || 
					  getTypeBy() == FraudAlert::_typeBy_rtp_stream_ip_group); }
	bool defFilterNumber() { return(true); }
	bool defFilterNumber2() { return(true); }
	bool defFraudDef() { return(true); }
	bool defConcuretCallsLimit() { return(true); }
	bool defTypeBy() { return(true); }
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
	bool defOnlyConnected() { return(true); }
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
	bool defOnlyConnected() { return(true); }
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
		 unsigned int count,
		 unsigned int count_invite = 0,
		 unsigned int count_message = 0,
		 unsigned int count_register = 0);
	string getJson();
private:
	unsigned int ip;
	unsigned int count;
	unsigned int count_invite;
	unsigned int count_message;
	unsigned int count_register;
};

class FraudAlert_spc : public FraudAlert {
private:
	struct sCounts {
		u_int64_t count;
		u_int64_t count_invite;
		u_int64_t count_message;
		u_int64_t count_register;
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
	bool defFilterUA() { return(true); }
	bool defInterval() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	bool checkOkAlert(u_int32_t ip, u_int64_t count, u_int64_t at);
private:
	map<u_int32_t, sCounts> count;
	u_int64_t start_interval;
	map<u_int32_t, sAlertInfo> alerts;
};

class FraudAlert_rc : public FraudAlert {
private:
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
	bool defFilterUA() { return(true); }
	bool defInterval() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	void loadAlertVirt();
	bool checkOkAlert(u_int32_t ip, u_int64_t count, u_int64_t at);
private:
	bool withResponse;
	map<u_int32_t, u_int64_t> count;
	u_int64_t start_interval;
	map<u_int32_t, sAlertInfo> alerts;
};

class FraudAlertInfo_seq : public FraudAlertInfo {
public:
	FraudAlertInfo_seq(FraudAlert *alert);
	void set(unsigned int ip,
		 const char *number,
		 unsigned int count,
		 const char *country_code_ip,
		 const char *country_code_number);
	string getJson();
private:
	unsigned int ip;
	string number;
	unsigned int count;
	string country_code_ip;
	string country_code_number;
};

class FraudAlert_seq : public FraudAlert {
private:
	struct sIpNumber {
		sIpNumber(u_int32_t ip = 0, const char *number = NULL) {
			this->ip = ip;
			this->number = number ? number : "";
		}
		bool operator < (const sIpNumber& other) const { 
			return(this->ip != other.ip ? this->ip < other.ip :
			       this->number < other.number); 
		}
		u_int32_t ip;
		string number;
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
	FraudAlert_seq(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
protected:
	bool defFilterIp() { return(true); }
	bool defFilterNumber() { return(true); }
	bool defInterval() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	bool checkOkAlert(sIpNumber ipNumber, u_int64_t count, u_int64_t at);
private:
	map<sIpNumber, u_int64_t> count;
	u_int64_t start_interval;
	map<sIpNumber, sAlertInfo> alerts;
};

class FraudAlertInfo_reg : public FraudAlertInfo {
public:
	FraudAlertInfo_reg(FraudAlert *alert);
	void set(const char *filter_descr,
		 unsigned int count,
		 map<sFraudRegisterInfo_id, sFraudRegisterInfo_data> *reg_map);
	string getJson();
private:
	string filter_descr;
	unsigned int count;
	map<sFraudRegisterInfo_id, sFraudRegisterInfo_data> *reg_map;
};

class FraudAlert_reg_ua : public FraudAlertReg {
public:
	FraudAlert_reg_ua(unsigned int dbId);
protected:
	bool okFilter(sFraudRegisterInfo *registerInfo);
};

class FraudAlert_reg_short : public FraudAlertReg {
public:
	FraudAlert_reg_short(unsigned int dbId);
protected:
	bool okFilter(sFraudRegisterInfo *registerInfo);
};

class FraudAlert_reg_expire : public FraudAlertReg {
public:
	FraudAlert_reg_expire(unsigned int dbId);
protected:
	bool okFilter(sFraudRegisterInfo *registerInfo);
};


class FraudAlerts {
public:
	FraudAlerts();
	~FraudAlerts();
	void loadAlerts(bool lock = true);
	void loadData(bool lock = true);
	void clear(bool lock = true);
	void beginCall(Call *call, u_int64_t at);
	void connectCall(Call *call, u_int64_t at);
	void seenByeCall(Call *call, u_int64_t at);
	void endCall(Call *call, u_int64_t at);
	void beginRtpStream(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
			    Call *call, u_int64_t at);
	void endRtpStream(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
			  Call *call, u_int64_t at);
	void evSipPacket(u_int32_t ip, unsigned sip_method, u_int64_t at, const char *ua, int ua_len);
	void evRegister(u_int32_t ip, u_int64_t at, const char *ua, int ua_len);
	void evRegisterResponse(u_int32_t ip, u_int64_t at, const char *ua, int ua_len);
	void evRegister(Call *call, eRegisterState state, eRegisterState prev_state = rs_na, time_t prev_state_at = 0);
	void stopPopCallInfoThread(bool wait = false);
	void refresh();
	const char *getGuiTimezone() {
		if(gui_timezone.empty()) {
			return(NULL);
		}
		return(gui_timezone.c_str());
	}
	string getGroupName(unsigned idGroup) {
		return(groupsIP.getGroupName(idGroup));
	}
private:
	void initPopCallInfoThread();
	void popCallInfoThread();
	void completeCallInfo(sFraudCallInfo *callInfo, Call *call, 
			      sFraudCallInfo::eTypeCallInfo typeCallInfo, u_int64_t at);
	void completeRtpStreamInfo(sFraudRtpStreamInfo *rtpStreamInfo, Call *call);
	void completeNumberInfo_country_code(sFraudNumberInfo *numberInfo, CheckInternational *checkInternational);
	void completeCallInfoAfterPop(sFraudCallInfo *callInfo, CheckInternational *checkInternational);
	void completeRtpStreamInfoAfterPop(sFraudRtpStreamInfo *rtpStreamInfo, CheckInternational *checkInternational);
	void completeRegisterInfo(sFraudRegisterInfo *registerInfo, Call *call);
	void lock_alerts() {
		while(__sync_lock_test_and_set(&this->_sync_alerts, 1));
	}
	void unlock_alerts() {
		__sync_lock_release(&this->_sync_alerts);
	}
private:
	vector<FraudAlert*> alerts;
	SafeAsyncQueue<sFraudCallInfo> callQueue;
	SafeAsyncQueue<sFraudRtpStreamInfo> rtpStreamQueue;
	SafeAsyncQueue<sFraudEventInfo> eventQueue;
	SafeAsyncQueue<sFraudRegisterInfo> registerQueue;
	GroupsIP groupsIP;
	pthread_t threadPopCallInfo;
	bool runPopCallInfoThread;
	bool termPopCallInfoThread;
	string gui_timezone;
	volatile int _sync_alerts;
friend void *_FraudAlerts_popCallInfoThread(void *arg);
};


class cRegisterFilterFraud : public cRegisterFilter {
public:
	cRegisterFilterFraud(char *filter) 
	 : cRegisterFilter(filter) {
	}
	u_int64_t getField_int(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case rf_sipcallerip:
			return(((sFraudRegisterInfo*)rec)->sipcallerip);
		case rf_sipcalledip:
			return(((sFraudRegisterInfo*)rec)->sipcalledip);
		}
		return(0);
	}
	const char *getField_string(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case rf_to_num:
			return(((sFraudRegisterInfo*)rec)->to_num.c_str());
		case rf_to_domain:
			return(((sFraudRegisterInfo*)rec)->to_domain.c_str());
		case rf_contact_num:
			return(((sFraudRegisterInfo*)rec)->contact_num.c_str());
		case rf_contact_domain:
			return(((sFraudRegisterInfo*)rec)->contact_domain.c_str());
		case rf_digestusername:
			return(((sFraudRegisterInfo*)rec)->digest_username.c_str());
		case rf_from_num:
			return(((sFraudRegisterInfo*)rec)->from_num.c_str());
		case rf_from_name:
			return(((sFraudRegisterInfo*)rec)->from_name.c_str());
		case rf_from_domain:
			return(((sFraudRegisterInfo*)rec)->from_domain.c_str());
		case rf_digestrealm:
			return(((sFraudRegisterInfo*)rec)->digest_realm.c_str());
		case rf_ua:
			return(((sFraudRegisterInfo*)rec)->ua.c_str());
		}
		return("");
	}
public:
	list<cRegisterFilterItems> fItems;
};


void initFraud();
bool checkFraudTables();
void termFraud();
void refreshFraud();
void fraudBeginCall(Call *call, struct timeval tv);
void fraudConnectCall(Call *call, struct timeval tv);
void fraudSeenByeCall(Call *call, struct timeval tv);
void fraudEndCall(Call *call, struct timeval tv);
void fraudBeginRtpStream(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
			 Call *call, time_t time);
void fraudEndRtpStream(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
		       Call *call, time_t time);
void fraudSipPacket(u_int32_t ip, unsigned sip_method, timeval tv, const char *ua, int ua_len);
void fraudRegister(u_int32_t ip, timeval tv, const char *ua, int ua_len);
void fraudRegisterResponse(u_int32_t ip, u_int64_t at, const char *ua, int ua_len);
void fraudRegister(Call *call, eRegisterState state, eRegisterState prev_state = rs_na, time_t prev_state_at = 0);
bool isExistsFraudAlerts();

inline bool isFraudReady() {
	extern FraudAlerts *fraudAlerts;
        extern volatile int _fraudAlerts_ready;
	return(fraudAlerts && _fraudAlerts_ready);
}


#endif
