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
		string _findNumber = number;
		if(countries) {
			countries->clear();
		}
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
				_redukSizeFindNumber = _redukSizeFindNumber ?
							--_redukSizeFindNumber :
							findRecIt->number.length() - 1;
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
			--findRecIt;
		}
		return("");
	}
	string getCountry(const char *ip) {
		in_addr ips;
		inet_aton(ip, &ips);
		return(getCountry(ips.s_addr));
	}
private:
	vector<GeoIP_country_rec> data;
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
	FraudAlert(eFraudAlertType type, unsigned int dbId);
	virtual ~FraudAlert();
	void loadAlert();
	void loadFraudDef();
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
	std::string descr;
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
private:
	string descr;
	unsigned int concurentCallsLimit;
	unsigned int dbId;
	vector<TimePeriod> timePeriods;
};

class FraudAlert_rcc : public FraudAlert {
public:
	FraudAlert_rcc(unsigned int dbId);
protected:
	void addFraudDef(SqlDb_row *row);
	bool defFilterIp() { return(true); }
	bool defFilterNumber() { return(true); }
	bool defFraudDef() { return(true); }
	bool defConcuretCallsLimit() { return(true); }
private:
	vector<FraudAlert_rcc_timePeriods> timePeriods;
};

class FraudAlert_chc : public FraudAlert {
public:
	FraudAlert_chc(unsigned int dbId);
protected:
	bool defFilterNumber() { return(true); }
	bool defTypeChangeLocation() { return(true); }
	bool defChangeLocationOk() { return(true); }
};

class FraudAlert_chcr : public FraudAlert {
public:
	FraudAlert_chcr(unsigned int dbId);
protected:
	bool defFilterNumber() { return(true); }
	bool defTypeChangeLocation() { return(true); }
	bool defChangeLocationOk() { return(true); }
};

class FraudAlert_d : public FraudAlert {
public:
	FraudAlert_d(unsigned int dbId);
protected:
	bool defDestLocation() { return(true); }
};


class FraudAlerts {
public:
	~FraudAlerts();
	void loadAlerts();
	void clear();
private:
	vector<FraudAlert*> alerts;
};


#endif
