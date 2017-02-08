#include "voipmonitor.h"
#include "country_detect.h"


CountryDetect *countryDetect;

extern int opt_nocdr;
extern char cloud_host[256];


CountryCodes::CountryCodes() {
}

void CountryCodes::load() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query(string("select * ") + 
		     "from " + (cloud_host[0] ? "cloudshare." : "") + "country_code\
		      where parent_id is null");
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		continents[row["code"]] = row["name"];
	}
	sqlDb->query(string("select country.*, continent.code as continent ") + 
		     "from " + (cloud_host[0] ? "cloudshare." : "") + "country_code country\
		      join " + (cloud_host[0] ? "cloudshare." : "") + "country_code continent on (continent.id = country.parent_id)\
		      where country.parent_id is not null");
	while((row = sqlDb->fetchRow())) {
		countries[row["code"]] = row["name"];
		countryContinent[row["code"]] = row["continent"];
		continentCountry[row["continent"]].push_back(row["code"]);
	}
	delete sqlDb;
}

bool CountryCodes::isCountry(const char *code) {
	map<string, string>::iterator iter;
	iter = countries.find(code);
	return(iter != countries.end());
}

string CountryCodes::getNameCountry(const char *code) {
	map<string, string>::iterator iter;
	iter = countries.find(code);
	return(iter != countries.end() ? iter->second : "");
}

string CountryCodes::getNameContinent(const char *code) {
	map<string, string>::iterator iter;
	iter = continents.find(code);
	return(iter != continents.end() ? iter->second : "");
}

string CountryCodes::getName(const char *code) {
	return(isCountry(code) ? getNameCountry(code) : getNameContinent(code));
}

string CountryCodes::getContinent(const char *code) {
	map<string, string>::iterator iter;
	iter = countryContinent.find(code);
	return(iter != countryContinent.end() ? iter->second : "");
}

bool CountryCodes::isLocationIn(const char *location, vector<string> *in, bool continent) {
	string location_s = continent ? string("c_") + location : location;
	vector<string>::iterator iter = in->begin();
	while(iter != in->end()) {
		if(location_s == *iter) {
			return(true);
		}
		++iter;
	}
	return(false);
}


CheckInternational::CheckInternational() {
	internationalPrefixes = split("+, 00", ",", true);
	internationalMinLength = 0;
	internationalMinLengthPrefixesStrict = false;
}

void CheckInternational::setInternationalPrefixes(const char *prefixes) {
	this->internationalPrefixes = split(prefixes, ",", true);
}

void CheckInternational::setSkipPrefixes(const char *prefixes) {
	this->skipPrefixes = split(prefixes, ",", true);
}

void CheckInternational::setInternationalMinLength(int internationalMinLength, bool internationalMinLengthPrefixesStrict) {
	this->internationalMinLength = internationalMinLength;
	this->internationalMinLengthPrefixesStrict = internationalMinLengthPrefixesStrict;
}

void CheckInternational::load(SqlDb_row *dbRow) {
	string _prefixes = (*dbRow)["international_prefixes"];
	if(!_prefixes.empty()) {
		internationalPrefixes = split(_prefixes.c_str(), split(",|;", "|"), true);
	} else {
		internationalPrefixes.clear();
	}
	internationalMinLength = atoi((*dbRow)["international_number_min_length"].c_str());
	internationalMinLengthPrefixesStrict = atoi((*dbRow)["international_number_min_length_prefixes_strict"].c_str());
	countryCodeForLocalNumbers = (*dbRow)["country_code_for_local_numbers"];
	_prefixes = (*dbRow)["skip_prefixes"];
	if(!_prefixes.empty()) {
		skipPrefixes = split(_prefixes.c_str(), split(",|;", "|"), true);
	}
}

void CheckInternational::load() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("show tables like 'international_rules'");
	if(sqlDb->fetchRow()) {
		sqlDb->query("select * from international_rules");
		SqlDb_row row;
		while((row = sqlDb->fetchRow())) {
			this->load(&row);
		}
	}
	delete sqlDb;
}


CountryPrefixes::CountryPrefixes() {
}

void CountryPrefixes::load() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query(string("select * ") + 
		     "from " + (cloud_host[0] ? "cloudshare." : "") + "country_code_prefix\
		      order by prefix");
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		data.push_back(CountryPrefix_rec(
			row["prefix"].c_str(),
			row["country_code"].c_str(),
			row["descr"].c_str()));
	}
	std::sort(data.begin(), data.end());
	delete sqlDb;
}


GeoIP_country::GeoIP_country() {
}

void GeoIP_country::load() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query(string("select * ") + 
		     "from " + (cloud_host[0] ? "cloudshare." : "") + "geoip_country\
		      order by ip_from");
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		data.push_back(GeoIP_country_rec(
			atol(row["ip_from"].c_str()),
			atol(row["ip_to"].c_str()),
			row["country"].c_str()));
	}
	std::sort(data.begin(), data.end());
	delete sqlDb;
}


CountryDetect::CountryDetect() {
	countryCodes = new FILE_LINE(0) CountryCodes;
	countryPrefixes = new FILE_LINE(0) CountryPrefixes;
	geoIP_country = new FILE_LINE(0) GeoIP_country;
	checkInternational = new FILE_LINE(0) CheckInternational;
	countryCodes_reload = NULL;
	countryPrefixes_reload = NULL;
	geoIP_country_reload = NULL;
	checkInternational_reload = NULL;
	reload_do = false;
	_sync = 0;
	_sync_reload = 0;
}

CountryDetect::~CountryDetect() {
	delete countryCodes;
	delete countryPrefixes;
	delete geoIP_country;
	delete checkInternational;
}

void CountryDetect::load() {
	countryCodes->load();
	countryPrefixes->load();
	geoIP_country->load();
	checkInternational->load();
}

string CountryDetect::getCountryByPhoneNumber(const char *phoneNumber) {
	lock();
	string rslt = countryPrefixes->getCountry(phoneNumber, NULL, NULL, checkInternational);
	unlock();
	return(rslt);
}

string CountryDetect::getCountryByIP(u_int32_t ip) {
	lock();
	string rslt = geoIP_country->getCountry(ip);
	unlock();
	return(rslt);
}

string CountryDetect::getContinentByCountry(const char *country) {
	lock();
	string rslt = countryCodes->getContinent(country);
	unlock();
	return(rslt);
}

void CountryDetect::prepareReload() {
	if(opt_nocdr) {
		return;
	}
	reload_do = false;
	lock_reload();
	if(countryCodes_reload) {
		delete countryCodes_reload;
	}
	if(countryPrefixes_reload) {
		delete countryPrefixes_reload;
	}
	if(geoIP_country_reload) {
		delete geoIP_country_reload;
	}
	if(checkInternational_reload) {
		delete checkInternational_reload;
	}
	countryCodes_reload = new FILE_LINE(0) CountryCodes;
	countryPrefixes_reload = new FILE_LINE(0) CountryPrefixes;
	geoIP_country_reload = new FILE_LINE(0) GeoIP_country;
	checkInternational_reload = new FILE_LINE(0) CheckInternational;
	countryCodes_reload->load();
	countryPrefixes_reload->load();
	geoIP_country_reload->load();
	checkInternational_reload->load();
	reload_do = true;
	syslog(LOG_NOTICE, "CountryDetect::prepareReload");
	unlock_reload();
}

void CountryDetect::applyReload() {
	if(reload_do) {
		lock_reload();
		lock();
		delete countryCodes;
		delete countryPrefixes;
		delete geoIP_country;
		delete checkInternational;
		countryCodes = countryCodes_reload;
		countryPrefixes = countryPrefixes_reload;
		geoIP_country = geoIP_country_reload;
		checkInternational = checkInternational_reload;
		unlock();
		countryCodes_reload = NULL;
		countryPrefixes_reload = NULL;
		geoIP_country_reload = NULL;
		checkInternational_reload = NULL;
		reload_do = false;
		syslog(LOG_NOTICE, "CountryDetect::applyReload");
		unlock_reload();
	}
}


void CountryDetectInit() {
	if(!opt_nocdr) {
		countryDetect = new FILE_LINE(0) CountryDetect;
		countryDetect->load();
	}
}

void CountryDetectTerm() {
	if(countryDetect) {
		delete countryDetect; 
	}
}

string getCountryByPhoneNumber(const char *phoneNumber) {
	if(countryDetect) {
		return(countryDetect->getCountryByPhoneNumber(phoneNumber));
	}
	return("");
}

string getCountryByIP(u_int32_t ip) {
	if(countryDetect) {
		return(countryDetect->getCountryByIP(ip));
	}
	return("");
}

string getContinentByCountry(const char *country) {
	if(countryDetect) {
		return(countryDetect->getContinentByCountry(country));
	}
	return("");
}

void CountryDetectPrepareReload() {
	if(countryDetect) {
		return(countryDetect->prepareReload());
	}
}

void CountryDetectApplyReload() {
	if(countryDetect) {
		return(countryDetect->applyReload());
	}
}
