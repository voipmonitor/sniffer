#ifndef COUNTRY_DETECT_H
#define COUNTRY_DETECT_H


#include <string.h>
#include <string>
#include <vector>
#include <map>

#include "sql_db.h"


using namespace std;


class CountryDetect_base_table {
public:
	enum eTableType {
		_country_code,
		_international_rules,
		_country_code_prefix,
		_geoip_country
	};
public:
	CountryDetect_base_table();
	bool checkTable(eTableType tableType, string &tableName);
	string getTableName(eTableType tableType);
public:
	bool loadOK;
};

class CountryCodes : public CountryDetect_base_table {
public:
	CountryCodes();
	bool load();
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

class CheckInternational : public CountryDetect_base_table {
public:
	CheckInternational();
	void setInternationalPrefixes(const char *prefixes);
	void setSkipPrefixes(const char *prefixes);
	void setInternationalMinLength(int internationalMinLength, bool internationalMinLengthPrefixesStrict);
	void setEnableCheckNapaWithoutPrefix(bool enableCheckNapaWithoutPrefix);
	void load(SqlDb_row *dbRow);
	bool load();
	bool isInternational(const char *number, const char **prefix = NULL, int *skippfxsize = 0) {
		if(prefix) {
			*prefix = NULL;
		}
		int numberLength = strlen(number);
		*skippfxsize = numberLength;
		bool existsSkipPrefix = false;
		do {
			existsSkipPrefix = false;
			for(size_t i = 0; i < skipPrefixes.size(); i++) {
				if (skipPrefixes[i][0] == '^') {
					vector<string> found;
					if (reg_match(number, skipPrefixes[i].c_str(), &found, true, __FILE__, __LINE__)) {
						number += found[0].size();
						numberLength = strlen(number);
					}
				} else {
					if(numberLength > (int)skipPrefixes[i].size() &&
					   !strncmp(number, skipPrefixes[i].c_str(), skipPrefixes[i].size())) {

						number += skipPrefixes[i].size();
						while(*number == ' ') ++number;
						numberLength = strlen(number);
						existsSkipPrefix = true;
					}
				}
			}
		} while(existsSkipPrefix);
		*skippfxsize -= numberLength;
		for(size_t i = 0; i < internationalPrefixes.size(); i++) {
			if(numberLength > (int)internationalPrefixes[i].size() &&
			   !strncmp(number, internationalPrefixes[i].c_str(), internationalPrefixes[i].size()) && 
			   (!internationalMinLengthPrefixesStrict ||
			    !internationalMinLength ||
			    numberLength >= (int)(internationalMinLength + internationalPrefixes[i].size()))) {
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
		if((!internationalMinLengthPrefixesStrict ||
		    !internationalPrefixes.size()) &&
		   internationalMinLength &&
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
		int skippfxsize;
		int isInt = isInternational(number, &prefix, &skippfxsize);

		if (skippfxsize)
			number += skippfxsize;

		if(isInt) {
			if(international) {
				*international = true;
			}
			if(prefix) {
				number += strlen(prefix);
			}
			while(*number == '0' || (!prefix && *number == '+')) {
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
	bool internationalMinLengthPrefixesStrict;
	string countryCodeForLocalNumbers;
	bool enableCheckNapaWithoutPrefix;
	vector<string> skipPrefixes;
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
	bool load();
	string getCountry(const char *number, vector<string> *countries, string *country_prefix,
			  CheckInternational *checkInternational, bool disableCheckNapaWithoutPrefix = false) {
		if(countries) {
			countries->clear();
		}
		if(country_prefix) {
			*country_prefix = "";
		}
		bool isInternational;
		string normalizeNumber = checkInternational->normalize(number, &isInternational);
		if(!isInternational) {
			string local_country = checkInternational->getLocalCountry();
			if(checkInternational->enableCheckNapaWithoutPrefix && !disableCheckNapaWithoutPrefix && 
			   countryIsNapa(local_country)) {
				string number2 = number;
				if(number[0] != '1') {
					number2 = "1" + number2;
				}
				if(checkInternational->internationalPrefixes.size() && 
				   (checkInternational->internationalMinLengthPrefixesStrict ||
				    (checkInternational->internationalMinLength &&
				     number2.length() < (unsigned)checkInternational->internationalMinLength))) {
					number2 = checkInternational->internationalPrefixes[0] + number2;
				}
				string country = this->getCountry(number2.c_str(), countries, country_prefix,
								  checkInternational, true);
				if((!countries || countries->size() == 1) && countryIsNapa(local_country)) {
					return(country);
				} else {
					if(countries) {
						countries->clear();
					}
				}
			}
			if(countries) {
				countries->push_back(local_country);
			}
			return(local_country);
		}
		number = normalizeNumber.c_str();
		vector<CountryPrefix_rec>::iterator findRecIt;
		for(int pass = 0; pass < 2; pass++) {
			if(pass == 1 || !customer_data.empty()) {
				vector<CountryPrefix_rec> *data = pass == 0 ? &this->customer_data : &this->data;
				findRecIt = std::lower_bound(data->begin(), data->end(), number);
				if(findRecIt == data->end()) {
					--findRecIt;
				}
				int _redukSizeFindNumber = 0;
				bool okFind = true;
				while(strncmp(findRecIt->number.c_str(), number, findRecIt->number.length())) {
					if(findRecIt->number[0] < number[0]) {
						okFind = false;
						break;
					}
					if((!_redukSizeFindNumber || _redukSizeFindNumber > 1) &&
					   atol(findRecIt->number.c_str()) < atol(normalizeNumber.substr(0, findRecIt->number.length()).c_str())) {
						if(_redukSizeFindNumber) {
							--_redukSizeFindNumber;
						} else {
							_redukSizeFindNumber = findRecIt->number.length() - 1;
						}
						findRecIt = std::lower_bound(data->begin(), data->end(), string(number).substr(0, _redukSizeFindNumber).c_str());
						if(findRecIt == data->end()) {
							--findRecIt;
						}
					} else {
						if(findRecIt == data->begin()) {
							okFind = false;
							break;
						} else {
							--findRecIt;
						}
					}
				}
				if(okFind &&
				   !strncmp(findRecIt->number.c_str(), number, findRecIt->number.length())) {
					string rslt = findRecIt->country_code;
					string rsltNumber = findRecIt->number;
					if(country_prefix) {
						*country_prefix = findRecIt->number;
					}
					if(countries) {
						countries->push_back(rslt);
						while(findRecIt != data->begin()) {
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
			}
		}
		return("");
	}
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
			if(pass == 1 || !customer_data.empty()) {
				vector<CountryPrefix_rec> *data = pass == 0 ? &this->customer_data : &this->data;
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
private:
	vector<CountryPrefix_rec> data;
	vector<CountryPrefix_rec> customer_data;
};


class GeoIP_country : public CountryDetect_base_table {
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
	bool load();
	string getCountry(unsigned int ip) {
		if(data.size()) {
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


class CountryDetect {
public:
	CountryDetect();
	~CountryDetect();
	void load();
	string getCountryByPhoneNumber(const char *phoneNumber);
	bool isLocalByPhoneNumber(const char *phoneNumber);
	string getCountryByIP(u_int32_t ip);
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


void CountryDetectInit();
void CountryDetectTerm();
string getCountryByPhoneNumber(const char *phoneNumber, bool suppressStringLocal = false);
bool isLocalByPhoneNumber(const char *phoneNumber);
string getCountryByIP(u_int32_t ip, bool suppressStringLocal = false);
string getContinentByCountry(const char *country);
void CountryDetectPrepareReload();
void CountryDetectApplyReload();


#endif //COUNTRY_DETECT_H
