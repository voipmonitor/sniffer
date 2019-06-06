#ifndef COUNTRY_DETECT_H
#define COUNTRY_DETECT_H


#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <math.h>

#include "sql_db.h"


using namespace std;


class CountryDetect_base_table {
public:
	enum eTableType {
		_country_code,
		_country_code_prefix,
		_geoip_country,
		_geoipv6_country
	};
public:
	CountryDetect_base_table();
	bool checkTable(eTableType tableType, string &tableName, SqlDb *sqlDb = NULL);
	string getTableName(eTableType tableType);
public:
	bool loadOK;
};

class CountryCodes : public CountryDetect_base_table {
public:
	CountryCodes();
	bool load(SqlDb *sqlDb = NULL);
	bool isCountry(const char *code);
	string getNameCountry(const char *code);
	unsigned getIdCountry(const char *code);
	string getNameContinent(const char *code);
	unsigned getIdContinent(const char *code);
	string getName(const char *code);
	string getContinent(const char *code);
	bool isLocationIn(const char *location, vector<string> *in, bool continent = false);
private:
	map<string, d_item2<string, unsigned> > continents;
	map<string, d_item2<string, unsigned> > countries;
	map<string, vector<string> > continentCountry;
	map<string, string> countryContinent;
};

class CheckInternational : public CountryDetect_base_table {
public:
	struct CountryPrefix_recAdv {
		CountryPrefix_recAdv() {
			number_regexp_cond = NULL;
			number_length_from = -1;
			number_length_to = -1;
			trim_prefix_length = -1;
			is_international= false;
		}
		~CountryPrefix_recAdv() {
			if(number_regexp_cond) {
				delete number_regexp_cond;
			}
			for(unsigned i = 0; i < trim_prefixes_regexp.size(); i++) {
				delete trim_prefixes_regexp[i];
			}
		}
		cRegExp *number_regexp_cond;
		int number_length_from;
		int number_length_to;
		vector<string> trim_prefixes_string;
		vector<cRegExp*> trim_prefixes_regexp;
		int trim_prefix_length;
		bool is_international;
		string country_code;
		string descr;
	};
public:
	CheckInternational();
	~CheckInternational();
	void setInternationalPrefixes(const char *prefixes, vector<string> *separators = NULL);
	void setSkipPrefixes(const char *prefixes, vector<string> *separators = NULL);
	void setInternationalMinLength(int internationalMinLength, bool internationalMinLengthPrefixesStrict);
	void setEnableCheckNapaWithoutPrefix(bool enableCheckNapaWithoutPrefix, int minLengthNapaWithoutPrefix);
	bool isSet(SqlDb_row *dbRow);
	bool load(SqlDb_row *dbRow, SqlDb *sqlDb = NULL);
	bool load(SqlDb *sqlDb = NULL);
	void _load(SqlDb_row *dbRow);
	bool loadCustomerPrefixAdv(SqlDb *sqlDb = NULL);
	void clearInternationalPrefixes();
	void clearSkipPrefixes();
	void clearCustomerPrefixAdv();
	bool isInternationalViaLength(string *numberNormalized) {
		return((!internationalMinLengthPrefixesStrict ||
			(!internationalPrefixes_string.size() && !internationalPrefixes_regexp.size())) &&
		       internationalMinLength &&
		       (int)numberNormalized->length() >= internationalMinLength);
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
	bool processCustomerDataAdvanced(const char *number, 
					 bool *isInternational, string *country, string *numberWithoutPrefix = NULL);
	bool skipPrefixes(const char *number, vector<string> *prefixes_string, vector<cRegExp*> *prefixes_regexp, bool recurse,
			  string *numberWithoutPrefix = NULL, string *skipPrefix = NULL, unsigned *skipPrefixLength = NULL, vector<string> *skipPrefixes = NULL,
			  bool isInternationalPrefixes = false);
	bool skipInternationalPrefixes(const char *number,
				       string *numberWithoutPrefix = NULL, string *skipPrefix = NULL, unsigned *skipPrefixLength = NULL, vector<string> *skipPrefixes = NULL) {
		return(this->skipPrefixes(number, &internationalPrefixes_string, &internationalPrefixes_regexp, false,
					  numberWithoutPrefix, skipPrefix, skipPrefixLength, skipPrefixes,
					  true));
	}
	bool skipSkipPrefixes(const char *number,
			      string *numberWithoutPrefix = NULL, string *skipPrefix = NULL, unsigned *skipPrefixLength = NULL, vector<string> *skipPrefixes = NULL) {
		return(this->skipPrefixes(number, &skipPrefixes_string, &skipPrefixes_regexp, true,
					  numberWithoutPrefix, skipPrefix, skipPrefixLength, skipPrefixes));
	}
	string numberNormalized(const char *number, class CountryPrefixes *countryPrefixes);
private:
	vector<string> internationalPrefixes_string;
	vector<cRegExp*> internationalPrefixes_regexp;
	int internationalMinLength;
	bool internationalMinLengthPrefixesStrict;
	string countryCodeForLocalNumbers;
	bool enableCheckNapaWithoutPrefix;
	int minLengthNapaWithoutPrefix;
	vector<string> skipPrefixes_string;
	vector<cRegExp*> skipPrefixes_regexp;
	vector<CountryPrefix_recAdv*> customer_data_advanced;
friend class CountryPrefixes;
};

class CountryPrefixes : public CountryDetect_base_table {
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
	~CountryPrefixes();
	bool load(SqlDb *sqlDb = NULL);
	void clear();
	string getCountry(const char *number, vector<string> *countries, string *country_prefix,
			  CheckInternational *checkInternational, string *rsltNumberNormalized = NULL);
	string _getCountry(const char *number, vector<string> *countries, string *country_prefix);
	bool isLocal(const char *number,
		     CheckInternational *checkInternational) {
		vector<string> countries;
		getCountry(number, &countries, NULL, checkInternational);
		for(size_t i = 0; i < countries.size(); i++) {
			if(checkInternational->countryCodeIsLocal(countries[i].c_str())) {
				return(true); 
			}
		}
		return(false);
	}
	bool countryIsNapa(string country) {
		return(countryIsNapa(country.c_str()));
	}
	bool countryIsNapa(const char *country) {
		for(int pass = 0; pass < 2; pass++) {
			if(pass == 1 || !customer_data_simple.empty()) {
				vector<CountryPrefix_rec> *data = pass == 0 ? &this->customer_data_simple : &this->data;
				for(vector<CountryPrefix_rec>::iterator iter = data->begin(); iter != data->end(); iter++) {
					if(iter->country_code == country &&
					   iter->number.length() == 4 &&
					   iter->number[0] == '1') {
						return(true);
					}
				}
			}
		}
		return(false);
	}
	string getPrefixNumber(const char *country) {
		for(int pass = 0; pass < 2; pass++) {
			if(pass == 1 || !customer_data_simple.empty()) {
				vector<CountryPrefix_rec> *data = pass == 0 ? &this->customer_data_simple : &this->data;
				for(vector<CountryPrefix_rec>::iterator iter = data->begin(); iter != data->end(); iter++) {
					if(iter->country_code == country) {
						return(iter->number);
					}
				}
			}
		}
		return("");
	}
private:
	vector<CountryPrefix_rec> data;
	vector<CountryPrefix_rec> customer_data_simple;
};


class GeoIP_country : public CountryDetect_base_table {
public:
	struct GeoIP_country_rec {
		GeoIP_country_rec(vmIP ip_from = 0, vmIP ip_to = 0, const char *country_code = NULL) {
			this->ip_from = ip_from;
			this->ip_to = ip_to;
			if(country_code) {
				this->country_code = country_code;
			}
		}
		GeoIP_country_rec(const char *ip, unsigned int mask, const char *country_code) {
			vmIP vm_ip;
			vm_ip.setFromString(ip);
			this->ip_from = vm_ip.network(mask);
			this->ip_to = vm_ip.broadcast(mask);
			if(country_code) {
				this->country_code = country_code;
			}
		}
		bool operator < (const GeoIP_country_rec& other) const { 
			return(this->ip_from < other.ip_from); 
		}
		vmIP ip_from;
		vmIP ip_to;
		string country_code;
	};
public:
	GeoIP_country();
	bool load(SqlDb *sqlDb = NULL);
	string getCountry(vmIP ip) {
		for(unsigned pass = 0; pass < 2; pass++) {
			vector<GeoIP_country_rec> *data = pass == 0 ? 
							   &this->customer_data : 
							   (VM_IPV6_B && ip.is_v6() ? &this->data_v6 : &this->data);
			if(data->size()) {
				vector<GeoIP_country_rec>::iterator findRecIt;
				findRecIt = std::lower_bound(data->begin(), data->end(), ip);
				if(findRecIt == data->end()) {
					--findRecIt;
				}
				for(int i = 0; i < 2; i++) {
					if(findRecIt->ip_from <= ip && findRecIt->ip_to >= ip) {
						return(findRecIt->country_code);
					}
					if(findRecIt == data->begin()) {
						break;
					}
					--findRecIt;
				}
			}
		}
		return("");
	}
	string getCountry(const char *ip) {
		return(getCountry(str_2_vmIP(ip)));
	}
	bool isLocal(vmIP ip,
		     CheckInternational *checkInternational) {
		string countryCode = getCountry(ip);
		return(checkInternational->countryCodeIsLocal(countryCode.c_str()));
	}
	bool isLocal(const char *ip,
		     CheckInternational *checkInternational) {
		return(isLocal(str_2_vmIP(ip), checkInternational));
	}
private:
	vector<GeoIP_country_rec> data;
	vector<GeoIP_country_rec> data_v6;
	vector<GeoIP_country_rec> customer_data;
};


class CountryDetect {
public:
	CountryDetect();
	~CountryDetect();
	void load(SqlDb *sqlDb = NULL);
	string getCountryByPhoneNumber(const char *phoneNumber);
	unsigned getCountryIdByPhoneNumber(const char *phoneNumber);
	bool isLocalByPhoneNumber(const char *phoneNumber);
	string getCountryByIP(vmIP ip);
	unsigned getCountryIdByIP(vmIP ip);
	bool isLocalByIP(vmIP ip);
	string getContinentByCountry(const char *country);
	void prepareReload();
	void applyReload();
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
	void lock_reload() {
		while(__sync_lock_test_and_set(&_sync_reload, 1));
	}
	void unlock_reload() {
		__sync_lock_release(&_sync_reload);
	}
private:
	CountryCodes *countryCodes;
	CountryPrefixes *countryPrefixes;
	GeoIP_country *geoIP_country;
	CheckInternational *checkInternational;
	CountryCodes *countryCodes_reload;
	CountryPrefixes *countryPrefixes_reload;
	GeoIP_country *geoIP_country_reload;
	CheckInternational *checkInternational_reload;
	volatile bool reload_do;
	volatile int _sync;
	volatile int _sync_reload;
};


void CountryDetectInit(SqlDb *sqlDb = NULL);
void CountryDetectTerm();
string getCountryByPhoneNumber(const char *phoneNumber, bool suppressStringLocal = false);
unsigned getCountryIdByPhoneNumber(const char *phoneNumber);
bool isLocalByPhoneNumber(const char *phoneNumber);
string getCountryByIP(vmIP ip, bool suppressStringLocal = false);
unsigned getCountryIdByIP(vmIP ip);
string getContinentByCountry(const char *country);
void CountryDetectPrepareReload();
void CountryDetectApplyReload();


#endif //COUNTRY_DETECT_H
