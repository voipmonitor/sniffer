#ifndef FRAUD_H
#define FRAUD_H


#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "voipmonitor.h"

#include "country_detect.h"
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

class CacheNumber_location {
public:
	struct sNumber {
		sNumber(const char *number = NULL, u_int32_t ip = 0, const char *domain = NULL) {
			if(number) {
				this->number = number;
			}
			this->ip = ip;
			if(domain) {
				this->domain = domain;
			}
		}
		string number;
		u_int32_t ip;
		string domain;
		bool operator == (const sNumber& other) const { 
			return(this->number == other.number &&
			       this->ip == other.ip &&
			       this->domain == other.domain); 
		}
		bool operator < (const sNumber& other) const { 
			return(this->number < other.number ? 1 : this->number > other.number ? 0 :
			       this->ip < other.ip ? 1 : this->ip > other.ip ? 0 :
			       this->domain < other.domain); 
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
	bool checkNumber(const char *number, u_int32_t number_ip, const char *domain,
			 u_int32_t ip, u_int64_t at,
			 bool *diffCountry = NULL, bool *diffContinent = NULL,
			 u_int32_t *oldIp = NULL, string *oldCountry = NULL, string *oldContinent = NULL,
			 const char *ip_country = NULL, const char *ip_continent = NULL);
	bool loadNumber(const char *number, u_int32_t number_ip, const char *domain, u_int64_t at);
	void saveNumber(const char *number, u_int32_t number_ip, const char *domain, sIpRec *ipRec, bool update = false);
	void cleanup(u_int64_t at);
private:
	string getTable(const char *domain);
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
	string country_prefix_caller;
	string country_prefix_called;
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
	string caller_domain;
	string called_domain;
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
		dst_ip = 0;
		sip_method = 0;
		at = 0;
		block_store = NULL;
		block_store_index = 0; 
		dlt = 0;
	}
	eTypeEventInfo typeEventInfo;
	u_int32_t src_ip;
	u_int32_t dst_ip;
	unsigned sip_method;
	u_int64_t at;
	string ua;
	struct pcap_block_store *block_store;
	u_int32_t block_store_index; 
	u_int16_t dlt;
};

struct sFraudRegisterInfo_id {
	u_int32_t sipcallerip;
	u_int32_t sipcalledip;
	string to_num;
	string to_domain;
	string digest_username;
	bool operator == (const sFraudRegisterInfo_id& other) const {
		return(this->sipcallerip == other.sipcallerip &&
		       this->sipcalledip == other.sipcalledip &&
		       this->to_num == other.to_num &&
		       this->to_domain == other.to_domain &&
		       this->digest_username == other.digest_username);
	}
	bool operator < (const sFraudRegisterInfo_id& other) const { 
		int rslt_cmp_to_num;
		int rslt_cmp_to_domain;
		int rslt_cmp_digest_username;
		return((this->sipcallerip < other.sipcallerip) ? 1 : (this->sipcallerip > other.sipcallerip) ? 0 :
		       (this->sipcalledip < other.sipcalledip) ? 1 : (this->sipcalledip > other.sipcalledip) ? 0 :
		       ((rslt_cmp_to_num = strcasecmp(this->to_num.c_str(), other.to_num.c_str())) < 0) ? 1 : (rslt_cmp_to_num > 0) ? 0 :
		       ((rslt_cmp_to_domain = strcasecmp(this->to_domain.c_str(), other.to_domain.c_str())) < 0) ? 1 : (rslt_cmp_to_domain > 0) ? 0 :
		       ((rslt_cmp_digest_username = strcasecmp(this->digest_username.c_str(), other.digest_username.c_str())) < 0));
	}
};

struct sFraudRegisterInfo_data {
	string from_num;
	string from_name;
	string from_domain;
	string contact_num;
	string contact_domain;
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
		_typeBy_destination_ip,
		_typeBy_source_number,
		_typeBy_rtp_stream_ip,
		_typeBy_rtp_stream_ip_group,
		_typeBy_summary
	};
	enum eLocalInternational {
		_li_local,
		_li_international,
		_li_booth
	};
	enum eCondition12 {
		_cond12_and,
		_cond12_or,
		_cond12_both_directions
	};
	FraudAlert(eFraudAlertType type, unsigned int dbId);
	virtual ~FraudAlert();
	bool isReg();
	bool loadAlert(SqlDb *sqlDb = NULL);
	void loadFraudDef(SqlDb *sqlDb = NULL);
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
	bool openVerbLog();
	virtual void evCall(sFraudCallInfo */*callInfo*/) {}
	virtual void evRtpStream(sFraudRtpStreamInfo */*rtpStreamInfo*/) {}
	virtual void evEvent(sFraudEventInfo */*eventInfo*/) {}
	virtual void evRegister(sFraudRegisterInfo */*registerInfo*/) {}
	virtual bool okFilterIp(u_int32_t ip, u_int32_t ip2);
	virtual bool okFilterPhoneNumber(const char *numb, const char *numb2);
	virtual bool okFilterDomain(const char *domain);
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
	virtual void loadAlertVirt(SqlDb */*sqlDb*/ = NULL) {}
	virtual void addFraudDef(SqlDb_row */*row*/, SqlDb */*sqlDb*/ = NULL) {}
	virtual bool defFilterIp() { return(false); }
	virtual bool defFilterIp2() { return(false); }
	virtual bool defFilterIpCondition12() { return(false); }
	virtual bool defFilterNumber() { return(false); }
	virtual bool defFilterNumber2() { return(false); }
	virtual bool defFilterNumberCondition12() { return(false); }
	virtual bool defFilterUA() { return(false); }
	virtual bool defUseDomain() { return(false); }
	virtual bool defFilterDomain() { return(false); }
	virtual bool defFraudDef() { return(false); }
	virtual bool defConcuretCallsLimit() { return(false); }
	virtual bool defTypeBy() { return(false); }
	virtual bool defTypeChangeLocation() { return(false); }
	virtual bool defChangeLocationOk() { return(false); }
	virtual bool defDestLocation() { return(false); }
	virtual bool defDestPrefixes() { return(false); }
	virtual bool defInterval() { return(false); }
	virtual bool defFilterInternational() { return(false); }
	virtual bool defOnlyConnected() { return(false); }
	virtual bool defSuppressRepeatingAlerts() { return(false); }
	virtual bool defStorePcaps() { return(false); }
	virtual bool supportVerbLog() { return(false); }
protected:
	eFraudAlertType type;
	unsigned int dbId;
	SqlDb_row dbRow;
	string descr;
	ListIP_wb ipFilter;
	ListIP_wb ipFilter2;
	eCondition12 ipFilterCondition12;
	ListPhoneNumber_wb phoneNumberFilter;
	ListPhoneNumber_wb phoneNumberFilter2;
	eCondition12 phoneNumberFilterCondition12;
	ListUA_wb uaFilter;
	bool useDomain;
	ListCheckString domainFilter;
	unsigned int concurentCallsLimitLocal;
	unsigned int concurentCallsLimitInternational;
	unsigned int concurentCallsLimitBoth;
	eTypeBy typeBy;
	eTypeLocation typeChangeLocation;
	vector<string> changeLocationOk;
	vector<string> destLocation;
	vector<string> destPrefixes;
	u_int32_t intervalLength;
	u_int32_t intervalLimit;
	bool filterInternational;
	CheckInternational checkInternational;
	bool onlyConnected;
	bool suppressRepeatingAlerts;
	int alertOncePerHours;
	int hour_from;
	int hour_to;
	bool day_of_week[7];
	bool day_of_week_set;
	bool storePcaps;
	string storePcapsToPaths;
	FILE *verbLog;
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
	void loadAlertVirt(SqlDb *sqlDb = NULL);
	void loadFilters(SqlDb *sqlDb = NULL);
protected:
	map<u_int32_t, FraudAlertReg_filter*> filters;
	u_int32_t intervalLength;
	u_int32_t intervalLimit;
	vector<cRegExp*> ua_regex;
	bool ua_reg_neg;
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
	virtual bool checkTime(u_int64_t /*time*/) { return(true); }
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
	FraudAlert_rcc_callInfo calls_summary;
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
				   class FraudAlert_rcc *parent,
				   SqlDb *sqlDb = NULL);
	void loadTimePeriods(SqlDb *sqlDb = NULL);
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
	void set_summary(FraudAlert::eLocalInternational localInternational,
			 const char *timeperiod_name,
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
	void addFraudDef(SqlDb_row *row, SqlDb *sqlDb = NULL);
	bool defFilterIp() { return(true); }
	bool defFilterIp2() { return(true); }
	bool defFilterIpCondition12() { return(true); }
	bool defFilterNumber() { return(true); }
	bool defFilterNumber2() { return(true); }
	bool defFilterNumberCondition12() { return(true); }
	bool defFraudDef() { return(true); }
	bool defConcuretCallsLimit() { return(true); }
	bool defDestPrefixes() { return(true); }
	bool defTypeBy() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
	bool supportVerbLog() { return(true); }
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
		 const char *location_code_old,
		 u_int32_t ip_dst);
	string getJson();
private:
	string number;
	FraudAlert::eTypeLocation typeLocation;
	u_int32_t ip;
	u_int32_t ip_old;
	u_int32_t ip_dst;
	string location_code;
	string location_code_old;
};

class FraudAlert_chc : public FraudAlert {
public:
	FraudAlert_chc(unsigned int dbId);
	void evCall(sFraudCallInfo *callInfo);
protected:
	bool defFilterIp() { return(true); }
	bool defFilterIp2() { return(true); }
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
	bool defFilterIp() { return(true); }
	bool defFilterIp2() { return(true); }
	bool defFilterNumber() { return(true); }
	bool defUseDomain() { return(true); }
	bool defFilterDomain() { return(true); }
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
	~FraudAlert_rc();
	void evEvent(sFraudEventInfo *eventInfo);
protected:
	bool defFilterIp() { return(true); }
	bool defFilterUA() { return(true); }
	bool defInterval() { return(true); }
	bool defTypeBy() { return(true); }
	bool defStorePcaps() { return(true); }
	bool defSuppressRepeatingAlerts() { return(true); }
private:
	void loadAlertVirt(SqlDb *sqlDb = NULL);
	bool checkOkAlert(u_int32_t ip, u_int64_t count, u_int64_t at);
	string getDumpName(u_int32_t ip, u_int64_t at);
private:
	bool withResponse;
	map<u_int32_t, u_int64_t> count;
	map<u_int32_t, PcapDumper*> dumpers;
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
	bool defFilterInternational() { return(true); }
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
	void loadAlerts(bool lock = true, SqlDb *sqlDb = NULL);
	void loadData(bool lock = true, SqlDb *sqlDb = NULL);
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
	void evRegister(u_int32_t src_ip, u_int32_t dst_ip, u_int64_t at, const char *ua, int ua_len,
			pcap_block_store *block_store, u_int32_t block_store_index, u_int16_t dlt);
	void evRegisterResponse(u_int32_t src_ip, u_int32_t dst_ip, u_int64_t at, const char *ua, int ua_len);
	void evRegister(Call *call, eRegisterState state, eRegisterState prev_state = rs_na, time_t prev_state_at = 0);
	void evRegister(class Register *reg, class RegisterState *regState, eRegisterState state, eRegisterState prev_state = rs_na, time_t prev_state_at = 0);
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
	void completeRegisterInfo(sFraudRegisterInfo *registerInfo, Register *reg, RegisterState *regState);
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
		setUseRecordArray(false);
	}
	int64_t getField_int(void *rec, unsigned registerFieldIndex) {
		switch(registerFieldIndex) {
		case rf_sipcallerip:
			return(htonl(((sFraudRegisterInfo*)rec)->sipcallerip));
		case rf_sipcalledip:
			return(htonl(((sFraudRegisterInfo*)rec)->sipcalledip));
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
};


void initFraud(SqlDb *sqlDb = NULL);
bool checkFraudTables(SqlDb *sqlDb = NULL);
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
void fraudRegister(u_int32_t src_ip, u_int32_t dst_ip, timeval tv, const char *ua, int ua_len,
		   struct packet_s *packetS);
void fraudRegisterResponse(u_int32_t src_ip, u_int32_t dst_ip, u_int64_t at, const char *ua, int ua_len);
void fraudRegister(Call *call, eRegisterState state, eRegisterState prev_state = rs_na, time_t prev_state_at = 0);
void fraudRegister(Register *reg, RegisterState *regState, eRegisterState state, eRegisterState prev_state = rs_na, time_t prev_state_at = 0);
string whereCondFraudAlerts();
bool isExistsFraudAlerts(bool *storePcaps = NULL, SqlDb *sqlDb = NULL);
bool selectSensorsContainSensorId(string select_sensors);

inline bool isFraudReady() {
	extern FraudAlerts *fraudAlerts;
        extern volatile int _fraudAlerts_ready;
	return(fraudAlerts && _fraudAlerts_ready);
}


#endif
