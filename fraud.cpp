#include <sstream>
#include <syslog.h>

#include "fraud.h"
#include "calltable.h"


extern int opt_enable_fraud;
extern int opt_nocdr;
extern MySqlStore *sqlStore;
extern char cloud_host[256];

FraudAlerts *fraudAlerts = NULL;
volatile int _fraudAlerts_ready = 0;
volatile int _fraudAlerts_lock = 0;
int fraudDebug = 1;

CountryCodes *countryCodes = NULL;
CountryPrefixes *countryPrefixes = NULL;
GeoIP_country *geoIP_country = NULL;
CacheNumber_location *cacheNumber_location = NULL;

SqlDb *sqlDbFraud = NULL;


static void fraudAlerts_lock() {
	while(__sync_lock_test_and_set(&_fraudAlerts_lock, 1));
}
static void fraudAlerts_unlock() {
	__sync_lock_release(&_fraudAlerts_lock);
}


TimePeriod::TimePeriod(SqlDb_row *dbRow) {
	if(dbRow) {
		is_hourmin = atoi((*dbRow)["is_hourmin"].c_str());
		from_hour = atoi((*dbRow)["from_hour"].c_str());
		from_minute = atoi((*dbRow)["from_minute"].c_str());
		to_hour = atoi((*dbRow)["to_hour"].c_str());
		to_minute = atoi((*dbRow)["to_minute"].c_str());
		is_weekday = atoi((*dbRow)["is_weekday"].c_str());
		from_weekday = atoi((*dbRow)["from_weekday"].c_str());
		to_weekday = atoi((*dbRow)["to_weekday"].c_str());
		is_monthday = atoi((*dbRow)["is_monthday"].c_str());
		from_monthday = atoi((*dbRow)["from_monthday"].c_str());
		to_monthday = atoi((*dbRow)["to_monthday"].c_str());
		is_month = atoi((*dbRow)["is_month"].c_str());
		from_month = atoi((*dbRow)["from_month"].c_str());
		to_month = atoi((*dbRow)["to_month"].c_str());
	} else {
		is_hourmin = false;
		from_hour = 0;
		from_minute = 0;
		to_hour = 0;
		to_minute = 0;
		is_weekday = false;
		from_weekday = 0;
		to_weekday = 0;
		is_monthday = false;
		from_monthday = 0;
		to_monthday = 0;
		is_month = false;
		from_month = 0;
		to_month = 0;
	}
}


CountryCodes::CountryCodes() {
}

void CountryCodes::load() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query(string("select * ") + 
		     "from " + (cloud_host[0] ? "cloudshare." : "") + "country_code\
		      where parent_id is null");
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		continents[row["code"]] = row["name"];
	}
	sqlDb->query(string("select country.*, continent.code as continent ") + 
		     "from " + (cloud_host[0] ? "cloudshare." : "") + "country_code country\
		      join " + (cloud_host[0] ? "cloudshare." : "") + "country_code continent on (continent.id = country.parent_id)\
		      where country.parent_id is not null");
	while(row = sqlDb->fetchRow()) {
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
}

void CheckInternational::setInternationalPrefixes(const char *prefixes) {
	this->internationalPrefixes = split(prefixes, ",", true);
}

void CheckInternational::setSkipPrefixes(const char *prefixes) {
	this->skipPrefixes = split(prefixes, ",", true);
}

void CheckInternational::setInternationalMinLength(int internationalMinLength) {
	this->internationalMinLength = internationalMinLength;
}

void CheckInternational::load(SqlDb_row *dbRow) {
	string _prefixes = (*dbRow)["international_prefixes"];
	if(!_prefixes.empty()) {
		internationalPrefixes = split(_prefixes.c_str(), split(",|;", "|"), true);
	}
	internationalMinLength = atoi((*dbRow)["international_number_min_length"].c_str());
	countryCodeForLocalNumbers = (*dbRow)["country_code_for_local_numbers"];
	_prefixes = (*dbRow)["skip_prefixes"];
	if(!_prefixes.empty()) {
		skipPrefixes = split(_prefixes.c_str(), split(",|;", "|"), true);
	}
}


CountryPrefixes::CountryPrefixes() {
}

void CountryPrefixes::load() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query(string("select * ") + 
		     "from " + (cloud_host[0] ? "cloudshare." : "") + "country_code_prefix\
		      order by prefix");
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
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
	while(row = sqlDb->fetchRow()) {
		data.push_back(GeoIP_country_rec(
			atol(row["ip_from"].c_str()),
			atol(row["ip_to"].c_str()),
			row["country"].c_str()));
	}
	std::sort(data.begin(), data.end());
	delete sqlDb;
}


CacheNumber_location::CacheNumber_location() {
	if(!countryCodes) {
		countryCodes = new FILE_LINE CountryCodes();
		countryCodes->load();
	}
	if(!geoIP_country) {
		geoIP_country = new FILE_LINE GeoIP_country();
		geoIP_country->load();
	}
	sqlDb = createSqlObject();
	last_cleanup_at = 0;
}

CacheNumber_location::~CacheNumber_location() {
	delete sqlDb;
}

bool CacheNumber_location::checkNumber(const char *number, u_int32_t number_ip,
				       u_int32_t ip, u_int64_t at,
				       bool *diffCountry, bool *diffContinent,
				       u_int32_t *oldIp, string *oldCountry, string *oldContinent,
				       const char *ip_country, const char *ip_continent) {
	if(!last_cleanup_at) {
		last_cleanup_at = at;
	}
	if(at > last_cleanup_at + 600 * 1000000ull) {
		this->cleanup(at);
	}
	if(diffCountry) {
		*diffCountry = false;
	}
	if(diffContinent) {
		*diffContinent = false;
	}
	if(oldIp) {
		*oldIp = 0;
	}
	if(oldCountry) {
		*oldCountry = "";
	}
	if(oldContinent) {
		*oldContinent = "";
	}
	if(!strcasecmp(number, "anonymous") ||
	   !strcasecmp(number, "restricted") ||
	   !strcasecmp(number, "unknown")) {
		return(true);
	}
	sNumber numberIp(number, number_ip);
	map<sNumber, sIpRec>::iterator iterCache;
	for(int pass = 0; pass < 2; pass++) {
		iterCache = cache.find(numberIp);
		if(iterCache != cache.end()) {
			break;
		}
		if(pass == 0) {
			if(!this->loadNumber(number, number_ip, at)) {
				break;
			}
		}
	}
	string country_code = ip_country ? ip_country : geoIP_country->getCountry(ip);
	string continent_code = ip_continent ? ip_continent : countryCodes->getContinent(country_code.c_str());
	if(iterCache == cache.end()) {
		sIpRec ipRec;
		ipRec.ip = ip;
		ipRec.country_code = country_code;
		ipRec.continent_code = continent_code;
		ipRec.at = at;
		ipRec.fresh_at = at;
		cache[numberIp] = ipRec;
		this->saveNumber(number, number_ip, &ipRec);
		return(true);
	}
	iterCache = cache.find(numberIp);
	if(iterCache->second.old_at &&
	   iterCache->second.old_at <= at &&
	   iterCache->second.at >= at &&
	   iterCache->second.country_code == country_code) {
		if(iterCache->second.country_code != iterCache->second.old_country_code) {
			if(diffCountry) {
				*diffCountry = true;
			}
			if(oldIp) {
				*oldIp = iterCache->second.old_ip;
			}
			if(oldCountry) {
				*oldCountry = iterCache->second.old_country_code;
			}
		}
		if(iterCache->second.continent_code != iterCache->second.old_continent_code) {
			if(diffContinent) {
				*diffContinent = true;
			}
			if(oldIp) {
				*oldIp = iterCache->second.old_ip;
			}
			if(oldContinent) {
				*oldContinent = iterCache->second.old_continent_code;
			}
		}
		iterCache->second.fresh_at = at;
		return(false);
	}
	if(iterCache->second.country_code != country_code) {
		if(country_code != iterCache->second.country_code) {
			if(diffCountry) {
				*diffCountry = true;
			}
			if(oldIp) {
				*oldIp = iterCache->second.ip;
			}
			if(oldCountry) {
				*oldCountry = iterCache->second.country_code;
			}
		}
		if(continent_code != iterCache->second.continent_code) {
			if(diffContinent) {
				 *diffContinent = true;
			}
			if(oldIp) {
				*oldIp = iterCache->second.ip;
			}
			if(oldContinent) {
				*oldContinent = iterCache->second.continent_code;
			}
		}
		iterCache->second.old_ip = iterCache->second.ip;
		iterCache->second.old_country_code = iterCache->second.country_code;
		iterCache->second.old_continent_code = iterCache->second.continent_code;
		iterCache->second.old_at = iterCache->second.at;
		iterCache->second.ip = ip;
		iterCache->second.country_code = country_code;
		iterCache->second.continent_code = continent_code;
		iterCache->second.at = at;
		iterCache->second.fresh_at = at;
		this->saveNumber(number, number_ip, &cache[numberIp], true);
		return(false);
	} else if(at > iterCache->second.at &&
		  at - iterCache->second.at > 300 * 1000000ull) {
		this->updateAt(number, number_ip, at);
	}
	iterCache->second.fresh_at = at;
	return(true);
}

bool CacheNumber_location::loadNumber(const char *number, u_int32_t number_ip, u_int64_t at) {
	char number_ip_string[20];
	sprintf(number_ip_string, "%u", number_ip);
	sqlDb->query(string("select * from cache_number_location where number=") +
		     sqlEscapeStringBorder(number) +
		     " and number_ip=" +
		     number_ip_string);
	SqlDb_row row = sqlDb->fetchRow();
	if(row) {
		sIpRec ipRec;
		ipRec.ip = atoll(row["ip"].c_str());
		ipRec.country_code = row["country_code"];
		ipRec.continent_code = row["continent_code"];
		ipRec.at = atoll(row["at"].c_str());
		ipRec.old_ip = atoll(row["old_ip"].c_str());
		ipRec.old_country_code = row["old_country_code"];
		ipRec.old_continent_code = row["old_continent_code"];
		ipRec.old_at = atoll(row["old_at"].c_str());
		ipRec.fresh_at = at;
		cache[sNumber(number, number_ip)] = ipRec;
		return(true);
	}
	return(false);
}

void CacheNumber_location::saveNumber(const char *number, u_int32_t number_ip, sIpRec *ipRec, bool update) {
	if(update) {
		ostringstream outStr;
		outStr << "update cache_number_location set "
		       << "ip = "
		       << ipRec->ip << ","
		       << "country_code = "
		       << sqlEscapeStringBorder(ipRec->country_code) << ","
		       << "continent_code = "
		       << sqlEscapeStringBorder(ipRec->continent_code) << ","
		       << "at = "
		       << ipRec->at << ","
		       << "old_ip = "
		       << ipRec->old_ip << ","
		       << "old_country_code = "
		       << sqlEscapeStringBorder(ipRec->old_country_code) << ","
		       << "old_continent_code = "
		       << sqlEscapeStringBorder(ipRec->old_continent_code) << ","
		       << "old_at = "
		       << ipRec->old_at 
		       << " where number = "
		       << sqlEscapeStringBorder(number) 
		       << " and number_ip = "
		       << number_ip;
		sqlStore->query_lock(outStr.str().c_str(), STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS);
	} else {
		SqlDb_row row;
		row.add(number, "number");
		row.add(number_ip, "number_ip");
		row.add(ipRec->ip, "ip");
		row.add(ipRec->country_code, "country_code");
		row.add(ipRec->continent_code, "continent_code");
		row.add(ipRec->at, "at");
		row.add(ipRec->old_ip, "old_ip");
		row.add(ipRec->old_country_code, "old_country_code");
		row.add(ipRec->old_continent_code, "old_continent_code");
		row.add(ipRec->old_at, "old_at");
		sqlStore->query_lock(sqlDb->insertQuery("cache_number_location", row).c_str(), STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS);
	}
}

void CacheNumber_location::updateAt(const char *number, u_int32_t number_ip, u_int64_t at) {
	ostringstream outStr;
	outStr << "update cache_number_location\
		   set at = "
	       << at
	       << " where number = "
	       << sqlEscapeStringBorder(number)
	       << " and number_ip = "
	       << number_ip;
	sqlStore->query_lock(outStr.str().c_str(), STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS);
}

void CacheNumber_location::cleanup(u_int64_t at) {
	map<sNumber, sIpRec>::iterator iterCache;
	for(iterCache = cache.begin(); iterCache != cache.end();) {
		if(at > iterCache->second.fresh_at + 600 * 1000000ull) {
			cache.erase(iterCache++);
		} else {
			++iterCache;
		}
	}
	last_cleanup_at = at;
}


FraudAlertInfo::FraudAlertInfo(FraudAlert *alert) {
	this->alert = alert;
}

string FraudAlertInfo::getAlertTypeString() {
	return(alert->getTypeString());
}

string FraudAlertInfo::getAlertDescr() {
	return(alert->getDescr());
}

unsigned int FraudAlertInfo::getAlertDbId() {
	return(alert->getDbId());
}

void FraudAlertInfo::setAlertJsonBase(JsonExport *json) {
	json->add("alert_type", this->getAlertTypeString().c_str());
	json->add("alert_descr", this->getAlertDescr().c_str());
}

FraudAlert::FraudAlert(eFraudAlertType type, unsigned int dbId) {
	this->type = type;
	this->dbId = dbId;
	concurentCallsLimitLocal = 0;
	concurentCallsLimitInternational = 0;
	concurentCallsLimitBoth = 0;
	typeChangeLocation = _typeLocation_NA;
	intervalLength = 0;
	intervalLimit = 0;
	onlyConnected = false;
	suppressRepeatingAlerts = false;
	alertOncePerHours = 0;
	hour_from = -1;
	hour_to = -1;
	for(int i = 0; i < 7; i++) {
		day_of_week[i] = false;
	}
	day_of_week_set = false;
}

FraudAlert::~FraudAlert() {
}

bool FraudAlert::loadAlert() {
	SqlDb *sqlDb = createSqlObject();
	char dbIdStr[10];
	sprintf(dbIdStr, "%u", dbId);
	sqlDb->query(string(
		"select alerts.*,\
		 (select group_concat(number) \
		  from alerts_groups ag\
		  join cb_number_groups g on (g.id=ag.number_group_id)\
		  where ag.type = 'number_whitelist' and ag.alerts_id = alerts.id) as fraud_whitelist_number_g,\
		 (select group_concat(number)\
		  from alerts_groups ag\
		  join cb_number_groups g on (g.id=ag.number_group_id)\
		  where ag.type = 'number_blacklist' and ag.alerts_id = alerts.id) as fraud_blacklist_number_g,\
		 (select group_concat(number) \
		  from alerts_groups ag\
		  join cb_number_groups g on (g.id=ag.number_group_id)\
		  where ag.type = 'number_whitelist_2' and ag.alerts_id = alerts.id) as fraud_whitelist_number_2_g,\
		 (select group_concat(number)\
		  from alerts_groups ag\
		  join cb_number_groups g on (g.id=ag.number_group_id)\
		  where ag.type = 'number_blacklist_2' and ag.alerts_id = alerts.id) as fraud_blacklist_number_2_g,\
		 (select group_concat(ip)\
		  from alerts_groups ag\
		  join cb_ip_groups g on (g.id=ag.ip_group_id)\
		  where ag.type = 'ip_whitelist' and ag.alerts_id = alerts.id) as fraud_whitelist_ip_g,\
		 (select group_concat(ip)\
		  from alerts_groups ag\
		  join cb_ip_groups g on (g.id=ag.ip_group_id)\
		  where ag.type = 'ip_blacklist' and ag.alerts_id = alerts.id) as fraud_blacklist_ip_g,\
		 (select group_concat(ip)\
		  from alerts_groups ag\
		  join cb_ip_groups g on (g.id=ag.ip_group_id)\
		  where ag.type = 'ip_whitelist_2' and ag.alerts_id = alerts.id) as fraud_whitelist_ip_2_g,\
		 (select group_concat(ip)\
		  from alerts_groups ag\
		  join cb_ip_groups g on (g.id=ag.ip_group_id)\
		  where ag.type = 'ip_blacklist_2' and ag.alerts_id = alerts.id) as fraud_blacklist_ip_2_g,\
		 (select group_concat(ua)\
		  from alerts_groups ag\
		  join cb_ua_groups g on (g.id=ag.ua_group_id)\
		  where ag.type = 'ua_whitelist' and ag.alerts_id = alerts.id) as fraud_whitelist_ua_g\
		 from alerts\
		 where id = ") + dbIdStr);
	dbRow = sqlDb->fetchRow();
	if(!dbRow) {
		delete sqlDb;
		return(false);
	}
	descr = dbRow["descr"];
	if(defFilterIp()) {
		ipFilter.addWhite(dbRow["fraud_whitelist_ip"].c_str());
		ipFilter.addWhite(dbRow["fraud_whitelist_ip_g"].c_str());
		ipFilter.addBlack(dbRow["fraud_blacklist_ip"].c_str());
		ipFilter.addBlack(dbRow["fraud_blacklist_ip_g"].c_str());
	}
	if(defFilterIp2()) {
		ipFilter2.addWhite(dbRow["fraud_whitelist_ip_2"].c_str());
		ipFilter2.addWhite(dbRow["fraud_whitelist_ip_2_g"].c_str());
		ipFilter2.addBlack(dbRow["fraud_blacklist_ip_2"].c_str());
		ipFilter2.addBlack(dbRow["fraud_blacklist_ip_2_g"].c_str());
	}
	if(defFilterNumber()) {
		phoneNumberFilter.addWhite(dbRow["fraud_whitelist_number"].c_str());
		phoneNumberFilter.addWhite(dbRow["fraud_whitelist_number_g"].c_str());
		phoneNumberFilter.addBlack(dbRow["fraud_blacklist_number"].c_str());
		phoneNumberFilter.addBlack(dbRow["fraud_blacklist_number_g"].c_str());
	}
	if(defFilterNumber2()) {
		phoneNumberFilter2.addWhite(dbRow["fraud_whitelist_number_2"].c_str());
		phoneNumberFilter2.addWhite(dbRow["fraud_whitelist_number_2_g"].c_str());
		phoneNumberFilter2.addBlack(dbRow["fraud_blacklist_number_2"].c_str());
		phoneNumberFilter2.addBlack(dbRow["fraud_blacklist_number_2_g"].c_str());
	}
	if(defFilterUA()) {
		uaFilter.addWhite(dbRow["fraud_whitelist_ua"].c_str());
		uaFilter.addWhite(dbRow["fraud_whitelist_ua_g"].c_str());
	}
	if(defFraudDef()) {
		loadFraudDef();
	}
	if(defConcuretCallsLimit()) {
		concurentCallsLimitLocal = atoi(dbRow["fraud_concurent_calls_limit_local"].c_str());
		concurentCallsLimitInternational = atoi(dbRow["fraud_concurent_calls_limit_international"].c_str());
		concurentCallsLimitBoth = atoi(dbRow["fraud_concurent_calls_limit"].c_str());
	}
	if(defTypeChangeLocation()) {
		typeChangeLocation = dbRow["fraud_type_change_location"] == "country" ? _typeLocation_country :
				     dbRow["fraud_type_change_location"] == "continent" ? _typeLocation_continent :
						_typeLocation_NA;
	}
	if(defChangeLocationOk()) {
		changeLocationOk = split(dbRow["fraud_change_location_ok"].c_str(), ",", true);
	}
	if(defDestLocation()) {
		destLocation = split(dbRow["fraud_dest_location"].c_str(), ",", true);
	}
	if(defInterval()) {
		intervalLength = atol(dbRow["fraud_interval_length"].c_str());
		intervalLimit = atol(dbRow["fraud_interval_limit"].c_str());
	}
	if(defOnlyConnected()) {
		onlyConnected = atoi(dbRow["only_connected"].c_str());
	}
	if(defSuppressRepeatingAlerts()) {
		suppressRepeatingAlerts = atoi(dbRow["fraud_suppress_repeating_alerts"].c_str());
		if(suppressRepeatingAlerts) {
			alertOncePerHours = atoi(dbRow["fraud_alert_once_per_hours"].c_str());
		}
	}
	checkInternational.load(&dbRow);
	hour_from = -1;
	hour_to = -1;
	for(int i = 0; i < 7; i++) {
		day_of_week[i] = false;
	}
	day_of_week_set = false;
	if(!dbRow.isNull("at_hour_of_day_from")) {
		int _hour_from = atoi(dbRow["at_hour_of_day_from"].c_str());
		if(_hour_from >= 0 && _hour_from <= 23) {
			hour_from = _hour_from;
		}
	}
	if(!dbRow.isNull("at_hour_of_day_to")) {
		int _hour_to = atoi(dbRow["at_hour_of_day_to"].c_str());
		if(_hour_to >= 0 && _hour_to <= 23) {
			hour_to = _hour_to;
		}
	}
	if(hour_from >= 0 || hour_to >= 0) {
		if(hour_from < 0) hour_from = 0;
		if(hour_to < 0) hour_to = 23;
	}
	if(!dbRow.isNull("at_day_of_week")) {
		vector<string> dw = split(dbRow["at_day_of_week"].c_str(), ",", true);
		for(size_t i = 0; i < dw.size(); i++) {
			int day = atoi(dw[i].c_str());
			if(day >= 1 and day <= 7) {
				day_of_week[day - 1] = true;
				day_of_week_set = true;
			}
		}
	}
	delete sqlDb;
	return(true);
}

void FraudAlert::loadFraudDef() {
	SqlDb *sqlDb = createSqlObject();
	char dbIdStr[10];
	sprintf(dbIdStr, "%u", dbId);
	sqlDb->query(string(
		"select *\
		 from alerts_fraud\
		 where alerts_id = ") + dbIdStr);
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		if(fraudDebug) {
			syslog(LOG_NOTICE, "add fraud def %s", row["descr"].c_str());
		}
		addFraudDef(&row);
	}
	delete sqlDb;
}

string FraudAlert::getTypeString() {
	switch(type) {
	case _rcc: return("rcc");
	case _chc: return("chc");
	case _chcr: return("chcr");
	case _d: return("d");
	case _spc: return("spc");
	case _rc: return("rc");
	case _seq: return("seq");
	}
	return("");
}

bool FraudAlert::okFilter(sFraudCallInfo *callInfo) {
	if(this->defFilterIp() && !this->ipFilter.checkIP(callInfo->caller_ip)) {
		return(false);
	}
	if(this->defFilterIp2() && !this->ipFilter2.checkIP(callInfo->called_ip)) {
		return(false);
	}
	if(this->defFilterNumber() && !this->phoneNumberFilter.checkNumber(callInfo->caller_number.c_str())) {
		return(false);
	}
	if(this->defFilterNumber2() && !this->phoneNumberFilter2.checkNumber(callInfo->called_number.c_str())) {
		return(false);
	}
	return(true);
}

bool FraudAlert::okFilter(sFraudEventInfo *eventInfo) {
	if(this->defFilterIp() && !this->ipFilter.checkIP(eventInfo->src_ip)) {
		return(false);
	}
	if(this->defFilterUA() && !this->uaFilter.checkUA(eventInfo->ua.c_str())) {
		return(false);
	}
	return(true);
}

bool FraudAlert::okDayHour(time_t at) {
	if((hour_from >= 0 && hour_to >= 0) ||
	   day_of_week_set) {
		tm attm = localtime_r(&at);
		if(hour_from >= 0 && hour_to >= 0) {
			if(hour_from <= hour_to) {
				if(attm.tm_hour < hour_from || attm.tm_hour > hour_to) {
					return(false);
				}
			} else {
				if(attm.tm_hour < hour_from && attm.tm_hour > hour_to) {
					return(false);
				}
			}
		}
		if(day_of_week_set) {
			if(!day_of_week[attm.tm_wday]) {
				return(false);
			}
		}
	}
	return(true);
}

void FraudAlert::evAlert(FraudAlertInfo *alertInfo) {
	if(sverb.fraud) {
		cout << "FRAUD ALERT INFO: " 
		     << alertInfo->getAlertTypeString() << " // "
		     << alertInfo->getAlertDescr() << " // "
		     << alertInfo->getJson()
		     << endl
		     << flush;
	}
	if(!sqlDbFraud) {
		sqlDbFraud = createSqlObject();
	}
	SqlDb_row row;
	row.add(alertInfo->getAlertDbId(), "alert_id");
	time_t now;
	time(&now);
	row.add(sqlDateTimeString(now), "at");
	row.add(alertInfo->getJson(), "alert_info");
	sqlStore->query_lock(sqlDbFraud->insertQuery("fraud_alert_info", row).c_str(), STORE_PROC_ID_FRAUD_ALERT_INFO);
	delete alertInfo;
}

FraudAlert_rcc_callInfo::FraudAlert_rcc_callInfo() {
	this->last_alert_info_local = 0;
	this->last_alert_info_international = 0;
	this->last_alert_info_li = 0;
}

FraudAlert_rcc_timePeriods::FraudAlert_rcc_timePeriods(const char *descr, 
						       int concurentCallsLimitLocal, 
						       int concurentCallsLimitInternational, 
						       int concurentCallsLimitBoth, 
						       unsigned int dbId) {
	this->descr = descr;
	this->concurentCallsLimitLocal_tp = concurentCallsLimitLocal;
	this->concurentCallsLimitInternational_tp = concurentCallsLimitInternational;
	this->concurentCallsLimitBoth_tp = concurentCallsLimitBoth;
	this->dbId = dbId;
	this->loadTimePeriods();
}

FraudAlert_rcc_timePeriods::~FraudAlert_rcc_timePeriods() {
	map<u_int32_t, FraudAlert_rcc_callInfo*>::iterator callsIter;
	for(callsIter = calls.begin(); callsIter != calls.end(); ++callsIter) {
		delete callsIter->second;
	}
}

void FraudAlert_rcc_timePeriods::loadTimePeriods() {
	SqlDb *sqlDb = createSqlObject();
	char dbIdStr[10];
	sprintf(dbIdStr, "%u", dbId);
	sqlDb->query(string(
		"select *\
		 from alerts_fraud_timeperiod\
		 join cb_timeperiod on (cb_timeperiod.id = alerts_fraud_timeperiod.timeperiod_id)\
		 where alerts_fraud_id = ") + dbIdStr);
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		timePeriods.push_back(TimePeriod(&row));
	}
	delete sqlDb;
}

void FraudAlert_rcc_base::evCall_rcc(sFraudCallInfo *callInfo, FraudAlert_rcc *alert, bool timeperiod) {
	FraudAlert_rcc_callInfo *call;
	map<u_int32_t, FraudAlert_rcc_callInfo*>::iterator callsIter;
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_connectCall:
		if(this->checkTime(callInfo->at_connect)) {
			callsIter = calls.find(callInfo->caller_ip);
			if(callsIter != calls.end()) {
				call = callsIter->second;
			} else {
				call = new FraudAlert_rcc_callInfo;
				calls[callInfo->caller_ip] = call;
			}
			if(callInfo->local_called_number) {
				call->addLocal(callInfo->callid.c_str(), callInfo->at_connect);
				if(sverb.fraud) {
					syslog(LOG_NOTICE, "fraud local rcc ++ %s / %s / %lu", 
					       inet_ntostring(callInfo->caller_ip).c_str(), 
					       callInfo->callid.c_str(),
					       call->calls_local.size());
				}
			} else {
				call->addInternational(callInfo->callid.c_str(), callInfo->at_connect);
				if(sverb.fraud) {
					syslog(LOG_NOTICE, "fraud international rcc ++ %s / %s / %lu", 
					       inet_ntostring(callInfo->caller_ip).c_str(), 
					       callInfo->callid.c_str(),
					       call->calls_international.size());
				}
			}
			unsigned int concurentCallsLimitLocal = timeperiod ? this->concurentCallsLimitLocal_tp : alert->concurentCallsLimitLocal;
			unsigned int concurentCallsLimitInternational = timeperiod ? this->concurentCallsLimitInternational_tp : alert->concurentCallsLimitInternational;
			unsigned int concurentCallsLimitBoth = timeperiod ? this->concurentCallsLimitBoth_tp : alert->concurentCallsLimitBoth;
			if(concurentCallsLimitLocal &&
			   call->calls_local.size() >= concurentCallsLimitLocal &&
			   callInfo->at_connect > call->last_alert_info_local + 1000000ull &&
			   this->checkOkAlert(callInfo->caller_ip, call->calls_local.size(), callInfo->at_connect,
					      FraudAlert::_li_local, alert)) {
				FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc(alert);
				alertInfo->set(FraudAlert::_li_local, this->getDescr().c_str(), 
					       callInfo->caller_ip, callInfo->country_code_caller_ip.c_str(),
					       call->calls_local.size()); 
				alert->evAlert(alertInfo);
				call->last_alert_info_local = callInfo->at_connect;
			}
			if(concurentCallsLimitInternational &&
			   call->calls_international.size() >= concurentCallsLimitInternational &&
			   callInfo->at_connect > call->last_alert_info_international + 1000000ull &&
			   this->checkOkAlert(callInfo->caller_ip, call->calls_international.size(), callInfo->at_connect,
					      FraudAlert::_li_international, alert)) {
				FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc(alert);
				alertInfo->set(FraudAlert::_li_international, this->getDescr().c_str(), 
					       callInfo->caller_ip, callInfo->country_code_caller_ip.c_str(),
					       call->calls_international.size()); 
				alert->evAlert(alertInfo);
				call->last_alert_info_international = callInfo->at_connect;
			}
			if(concurentCallsLimitBoth &&
			   call->calls_local.size() + call->calls_international.size() >= concurentCallsLimitBoth &&
			   callInfo->at_connect > call->last_alert_info_li + 1000000ull &&
			   this->checkOkAlert(callInfo->caller_ip, call->calls_local.size() + call->calls_international.size(), callInfo->at_connect,
					      FraudAlert::_li_booth, alert)) {
				FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc(alert);
				alertInfo->set(FraudAlert::_li_booth, this->getDescr().c_str(), 
					       callInfo->caller_ip, callInfo->country_code_caller_ip.c_str(),
					       call->calls_local.size() + call->calls_international.size()); 
				alert->evAlert(alertInfo);
				call->last_alert_info_li = callInfo->at_connect;
			}
		}
		break;
	case sFraudCallInfo::typeCallInfo_seenByeCall:
	case sFraudCallInfo::typeCallInfo_endCall:
		callsIter = calls.find(callInfo->caller_ip);
		if(callsIter != calls.end()) {
			call = callsIter->second;
			if(callInfo->local_called_number) {
				call->calls_local.erase(callInfo->callid);
				if(sverb.fraud) {
					syslog(LOG_NOTICE, "fraud local rcc -- %s / %s / %lu", 
					       inet_ntostring(callInfo->caller_ip).c_str(), 
					       callInfo->callid.c_str(),
					       call->calls_local.size());
				}
			} else {
				call->calls_international.erase(callInfo->callid);
				if(sverb.fraud) {
					syslog(LOG_NOTICE, "fraud international rcc -- %s / %s / %lu", 
					       inet_ntostring(callInfo->caller_ip).c_str(), 
					       callInfo->callid.c_str(),
					       call->calls_international.size());
				}
			}
		}
		break;
	default:
		break;
	}
}

bool FraudAlert_rcc_base::checkOkAlert(u_int32_t ip, size_t concurentCalls, u_int64_t at,
				       FraudAlert::eLocalInternational li,
				       FraudAlert_rcc *alert) {
	if(!alert->alertOncePerHours) {
		return(true);
	}
	map<u_int32_t, sAlertInfo> *alerts = li == FraudAlert::_li_local ?
					      &this->alerts_local :
					     li == FraudAlert::_li_international ?
					      &this->alerts_international :
					      &this->alerts_booth;
	map<u_int32_t, sAlertInfo>::iterator iter = alerts->find(ip);
	if(iter == alerts->end()) {
		(*alerts)[ip] = sAlertInfo(concurentCalls, at);
		return(true);
	} else {
		if(iter->second.at + alert->alertOncePerHours * 3600 * 1000000ull < at/* ||
		   iter->second.concurentCalls * 1.5 < concurentCalls*/) {
			(*alerts)[ip] = sAlertInfo(concurentCalls, at);
		} else {
			return(false);
		}
	}
	return(true);
}

FraudAlertInfo_rcc::FraudAlertInfo_rcc(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_rcc::set(FraudAlert::eLocalInternational localInternational,
			     const char *timeperiod_name,
			     u_int32_t ip, const char *ip_location_code,
			     unsigned int concurentCalls) {
	this->localInternational = localInternational;
	if(timeperiod_name) {
		this->timeperiod_name = timeperiod_name;
	}
	this->ip = ip;
	this->ip_location_code = ip_location_code;
	this->concurentCalls = concurentCalls;
}

string FraudAlertInfo_rcc::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("local_international", 
		 (localInternational == FraudAlert::_li_local ? "local" :
		  localInternational == FraudAlert::_li_international ? "international" : "local & international"));
	if(!timeperiod_name.empty()) {
		json.add("timeperiod_name", timeperiod_name);
	}
	json.add("ip", inet_ntostring(ip));
	json.add("ip_location_code", ip_location_code);
	json.add("ip_country", countryCodes->getNameCountry(ip_location_code.c_str()));
	json.add("ip_continent", countryCodes->getNameContinent(ip_location_code.c_str()));
	json.add("concurent_calls", concurentCalls);
	return(json.getJson());
}

void FraudAlert_rcc::addFraudDef(SqlDb_row *row) {
	timePeriods.push_back(FraudAlert_rcc_timePeriods(
				(*row)["descr"].c_str(),
				atoi((*row)["concurent_calls_limit_local"].c_str()),
				atoi((*row)["concurent_calls_limit_international"].c_str()),
				atoi((*row)["concurent_calls_limit"].c_str()),
				atol((*row)["id"].c_str())));
}

FraudAlert_rcc::FraudAlert_rcc(unsigned int dbId)
 : FraudAlert(_rcc, dbId) {
}

FraudAlert_rcc::~FraudAlert_rcc() {
	map<u_int32_t, FraudAlert_rcc_callInfo*>::iterator callsIter;
	for(callsIter = calls.begin(); callsIter != calls.end(); ++callsIter) {
		delete callsIter->second;
	}
}

void FraudAlert_rcc::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type == REGISTER ||
	   !this->okFilter(callInfo) ||
	   !this->okDayHour(callInfo)) {
		return;
	}
	this->evCall_rcc(callInfo, this, false);
	for(size_t i = 0; i < timePeriods.size(); i++) {
		timePeriods[i].evCall_rcc(callInfo, this, true);
	}
}

FraudAlertInfo_chc::FraudAlertInfo_chc(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_chc::set(const char *number,
			     FraudAlert::eTypeLocation typeLocation,
			     u_int32_t ip,
			     const char *location_code,
			     u_int32_t ip_old,
			     const char *location_code_old) {
	this->number = number;
	this->typeLocation = typeLocation;
	this->ip = ip;
	this->location_code = location_code;
	this->ip_old = ip_old;
	this->location_code_old = location_code_old;
}

string FraudAlertInfo_chc::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("number", number);
	json.add("type_location", 
		 typeLocation == FraudAlert::_typeLocation_country ? 
		  "country" : 
		  "continent");
	json.add("ip", inet_ntostring(ip));
	json.add("location_code", location_code);
	json.add("location_name",
		 typeLocation == FraudAlert::_typeLocation_country ?
		  countryCodes->getNameCountry(location_code.c_str()) :
		  countryCodes->getNameContinent(location_code.c_str()));
	json.add("ip_old", inet_ntostring(ip_old));
	json.add("location_code_old", location_code_old);
	json.add("location_name_old",
		 typeLocation == FraudAlert::_typeLocation_country ?
		  countryCodes->getNameCountry(location_code_old.c_str()) :
		  countryCodes->getNameContinent(location_code_old.c_str()));
	return(json.getJson());
}

FraudAlert_chc::FraudAlert_chc(unsigned int dbId)
 : FraudAlert(_chc, dbId) {
}

void FraudAlert_chc::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type == REGISTER ||
	   !this->okFilter(callInfo) ||
	   !this->okDayHour(callInfo)) {
		return;
	}
	if(callInfo->typeCallInfo == (this->onlyConnected ? sFraudCallInfo::typeCallInfo_connectCall : sFraudCallInfo::typeCallInfo_beginCall)) {
		if(isLocalIP(callInfo->caller_ip) ||
		   (this->changeLocationOk.size() &&
		    (countryCodes->isLocationIn(callInfo->country_code_caller_ip.c_str(), &this->changeLocationOk) ||
		     countryCodes->isLocationIn(callInfo->continent_code_caller_ip.c_str(), &this->changeLocationOk, true)))) {
			return;
		}
		bool diffCountry = false;
		bool diffContinent = false;
		u_int32_t oldIp;
		string oldCountry;
		string oldContinent;
		if(!cacheNumber_location->checkNumber(callInfo->caller_number.c_str(), callInfo->called_ip,
						      callInfo->caller_ip, callInfo->at_begin,
						      &diffCountry, &diffContinent, &oldIp, &oldCountry, &oldContinent,
						      callInfo->country_code_caller_ip.c_str(), callInfo->continent_code_caller_ip.c_str())) {
			if(this->typeChangeLocation == _typeLocation_country && diffCountry) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_country,
					       callInfo->caller_ip,
					       callInfo->country_code_caller_ip.c_str(),
					       oldIp,
					       oldCountry.c_str());
				this->evAlert(alertInfo);
			}
			if(this->typeChangeLocation == _typeLocation_continent && diffContinent) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_continent,
					       callInfo->caller_ip,
					       callInfo->continent_code_caller_ip.c_str(),
					       oldIp,
					       oldContinent.c_str());
				this->evAlert(alertInfo);
			}
		}
	}
}

FraudAlert_chcr::FraudAlert_chcr(unsigned int dbId)
 : FraudAlert(_chcr, dbId) {
}

void FraudAlert_chcr::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type != REGISTER ||
	   !this->okFilter(callInfo) ||
	   !this->okDayHour(callInfo)) {
		return;
	}
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_connectCall:
		{
		if(isLocalIP(callInfo->caller_ip) ||
		   (this->changeLocationOk.size() &&
		    (countryCodes->isLocationIn(callInfo->country_code_caller_ip.c_str(), &this->changeLocationOk) ||
		     countryCodes->isLocationIn(callInfo->continent_code_caller_ip.c_str(), &this->changeLocationOk, true)))) {
			return;
		}
		bool diffCountry = false;
		bool diffContinent = false;
		u_int32_t oldIp;
		string oldCountry;
		string oldContinent;
		if(!cacheNumber_location->checkNumber(callInfo->caller_number.c_str(), callInfo->called_ip,
						      callInfo->caller_ip, callInfo->at_begin,
						      &diffCountry, &diffContinent, &oldIp, &oldCountry, &oldContinent,
						      callInfo->country_code_caller_ip.c_str(), callInfo->continent_code_caller_ip.c_str())) {
			if(this->typeChangeLocation == _typeLocation_country && diffCountry) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_country,
					       callInfo->caller_ip,
					       callInfo->country_code_caller_ip.c_str(),
					       oldIp,
					       oldCountry.c_str());
				this->evAlert(alertInfo);
			}
			if(this->typeChangeLocation == _typeLocation_continent && diffContinent) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_continent,
					       callInfo->caller_ip,
					       callInfo->continent_code_caller_ip.c_str(),
					       oldIp,
					       oldContinent.c_str());
				this->evAlert(alertInfo);
			}
		} 
		}
		break;
	default:
		break;
	}
}

FraudAlertInfo_d::FraudAlertInfo_d(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_d::set(const char *src_number, 
			   const char *dst_number, 
			   const char *country_code, 
			   const char *continent_code) {
	this->src_number = src_number;
	this->dst_number = dst_number;
	this->country_code = country_code;
	this->continent_code = continent_code;
}

string FraudAlertInfo_d::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("src_number", src_number);
	json.add("dst_number", dst_number);
	if(!country_code.empty()) {
		json.add("country_code", country_code);
		json.add("country_name", countryCodes->getNameCountry(country_code.c_str()));
	}
	if(!continent_code.empty()) {
		json.add("continent_code", continent_code);
		json.add("continent_name", countryCodes->getNameContinent(continent_code.c_str()));
	}
	return(json.getJson());
}

FraudAlert_d::FraudAlert_d(unsigned int dbId)
 : FraudAlert(_d, dbId) {
}

void FraudAlert_d::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type == REGISTER ||
	   !this->okFilter(callInfo) ||
	   !this->okDayHour(callInfo)) {
		return;
	}
	if(callInfo->typeCallInfo == (this->onlyConnected ? sFraudCallInfo::typeCallInfo_connectCall : sFraudCallInfo::typeCallInfo_beginCall)) {
		if(this->destLocation.size() &&
		   (countryCodes->isLocationIn(callInfo->country_code_called_number.c_str(), &this->destLocation) ||
		    countryCodes->isLocationIn(callInfo->continent_code_called_number.c_str(), &this->destLocation, true)) &&
		   this->checkOkAlert(callInfo->caller_number.c_str(), callInfo->called_number.c_str(),
				      callInfo->country_code_called_number.c_str(), callInfo->at_begin)) {
			FraudAlertInfo_d *alertInfo = new FraudAlertInfo_d(this);
			alertInfo->set(callInfo->caller_number.c_str(),
				       callInfo->called_number.c_str(),
				       callInfo->country_code_called_number.c_str(),
				       callInfo->continent_code_called_number.c_str());
			this->evAlert(alertInfo);
		}
	}
}

bool FraudAlert_d::checkOkAlert(const char *src_number, const char *dst_number,
				const char *country_code, u_int64_t at) {
	if(!this->alertOncePerHours) {
		return(true);
	}
	dstring src_dst_number(src_number, dst_number);
	map<dstring, sAlertInfo>::iterator iter = alerts.find(src_dst_number);
	if(iter == alerts.end()) {
		alerts[src_dst_number] = sAlertInfo(country_code, at);
		return(true);
	} else {
		if(iter->second.at + this->alertOncePerHours * 3600 * 1000000ull < at ||
		   iter->second.country_code != country_code) {
			alerts[src_dst_number] = sAlertInfo(country_code, at);
		} else {
			return(false);
		}
	}
	return(true);
}

FraudAlertInfo_spc::FraudAlertInfo_spc(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_spc::set(unsigned int ip, 
			     unsigned int count) {
	this->ip = ip;
	this->count = count;
}

string FraudAlertInfo_spc::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("ip", inet_ntostring(ip));
	json.add("count", count);
	string country_code = geoIP_country->getCountry(ip);
	if(!country_code.empty()) {
		json.add("country_code", country_code);
		json.add("country_name", countryCodes->getNameCountry(country_code.c_str()));
	}
	return(json.getJson());
}

FraudAlert_spc::FraudAlert_spc(unsigned int dbId)
 : FraudAlert(_spc, dbId) {
	start_interval = 0;
}

void FraudAlert_spc::evEvent(sFraudEventInfo *eventInfo) {
	if(eventInfo->typeEventInfo == sFraudEventInfo::typeEventInfo_sipPacket &&
	   this->okFilter(eventInfo) &&
	   this->okDayHour(eventInfo)) {
		map<u_int32_t, u_int64_t>::iterator iter = count.find(eventInfo->src_ip);
		if(iter == count.end()) {
			count[eventInfo->src_ip] = 1;
		} else {
			++count[eventInfo->src_ip];
		}
	}
	if(!start_interval) {
		start_interval = eventInfo->at;
	} else if(eventInfo->at - start_interval > intervalLength * 1000000ull) {
		map<u_int32_t, u_int64_t>::iterator iter;
		for(iter = count.begin(); iter != count.end(); iter++) {
			if(iter->second >= intervalLimit &&
			   this->checkOkAlert(iter->first, iter->second, eventInfo->at)) {
				FraudAlertInfo_spc *alertInfo = new FraudAlertInfo_spc(this);
				alertInfo->set(iter->first,
					       iter->second);
				this->evAlert(alertInfo);
			}
		}
		count.clear();
		start_interval = eventInfo->at;
	}
}

bool FraudAlert_spc::checkOkAlert(u_int32_t ip, u_int64_t count, u_int64_t at) {
	if(!this->alertOncePerHours) {
		return(true);
	}
	map<u_int32_t, sAlertInfo>::iterator iter = alerts.find(ip);
	if(iter == alerts.end()) {
		alerts[ip] = sAlertInfo(count, at);
		return(true);
	} else {
		if(iter->second.at + this->alertOncePerHours * 3600 * 1000000ull < at/* ||
		   iter->second.count * 1.5 < count*/) {
			alerts[ip] = sAlertInfo(count, at);
		} else {
			return(false);
		}
	}
	return(true);
}

FraudAlert_rc::FraudAlert_rc(unsigned int dbId)
 : FraudAlert(_rc, dbId) {
	withResponse = false;
	start_interval = 0;
}

void FraudAlert_rc::evEvent(sFraudEventInfo *eventInfo) {
	if((withResponse ?
	     eventInfo->typeEventInfo == sFraudEventInfo::typeEventInfo_registerResponse :
	     eventInfo->typeEventInfo == sFraudEventInfo::typeEventInfo_register) &&
	   this->okFilter(eventInfo) &&
	   this->okDayHour(eventInfo)) {
		map<u_int32_t, u_int64_t>::iterator iter = count.find(eventInfo->src_ip);
		if(iter == count.end()) {
			count[eventInfo->src_ip] = 1;
		} else {
			++count[eventInfo->src_ip];
		}
	}
	if(!start_interval) {
		start_interval = eventInfo->at;
	} else if(eventInfo->at - start_interval > intervalLength * 1000000ull) {
		map<u_int32_t, u_int64_t>::iterator iter;
		for(iter = count.begin(); iter != count.end(); iter++) {
			if(iter->second >= intervalLimit &&
			   this->checkOkAlert(iter->first, iter->second, eventInfo->at)) {
				FraudAlertInfo_spc *alertInfo = new FraudAlertInfo_spc(this);
				alertInfo->set(iter->first,
					       iter->second);
				this->evAlert(alertInfo);
			}
		}
		count.clear();
		start_interval = eventInfo->at;
	}
}

void FraudAlert_rc::loadAlertVirt(SqlDb_row *row) {
	withResponse = atoi((*row)["fraud_register_only_with_response"].c_str());
}

bool FraudAlert_rc::checkOkAlert(u_int32_t ip, u_int64_t count, u_int64_t at) {
	if(!this->alertOncePerHours) {
		return(true);
	}
	map<u_int32_t, sAlertInfo>::iterator iter = alerts.find(ip);
	if(iter == alerts.end()) {
		alerts[ip] = sAlertInfo(count, at);
		return(true);
	} else {
		if(iter->second.at + this->alertOncePerHours * 3600 * 1000000ull < at/* ||
		   iter->second.count * 1.5 < count*/) {
			alerts[ip] = sAlertInfo(count, at);
		} else {
			return(false);
		}
	}
	return(true);
}

FraudAlertInfo_seq::FraudAlertInfo_seq(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_seq::set(unsigned int ip, 
			     const char *number,
			     unsigned int count,
			     const char *country_code_ip,
			     const char *country_code_number) {
	this->ip = ip;
	this->number = number ? number : "";
	this->count = count;
	this->country_code_number = country_code_number ? country_code_number : "";
	this->country_code_ip = country_code_ip ? country_code_ip : "";
}

string FraudAlertInfo_seq::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("ip", inet_ntostring(ip));
	json.add("number", number);
	json.add("count", count);
	if(!country_code_ip.empty()) {
		json.add("country_code_ip", country_code_ip);
		json.add("country_name_ip", countryCodes->getNameCountry(country_code_ip.c_str()));
	}
	if(!country_code_number.empty()) {
		json.add("country_code_number", country_code_number);
		json.add("country_name_number", countryCodes->getNameCountry(country_code_number.c_str()));
	}
	return(json.getJson());
}

FraudAlert_seq::FraudAlert_seq(unsigned int dbId)
 : FraudAlert(_seq, dbId) {
	start_interval = 0;
}

void FraudAlert_seq::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type != REGISTER &&
	   callInfo->typeCallInfo == sFraudCallInfo::typeCallInfo_connectCall &&
	   this->okFilter(callInfo) &&
	   this->okDayHour(callInfo)) {
		sIpNumber ipNumber(callInfo->caller_ip, callInfo->called_number.c_str());
		map<sIpNumber, u_int64_t>::iterator iter = count.find(ipNumber);
		if(iter == count.end()) {
			count[ipNumber] = 1;
		} else {
			++count[ipNumber];
		}
	}
	if(!start_interval) {
		start_interval = callInfo->at_last;
	} else if(callInfo->at_last - start_interval > intervalLength * 1000000ull) {
		map<sIpNumber, u_int64_t>::iterator iter;
		for(iter = count.begin(); iter != count.end(); iter++) {
			if(iter->second >= intervalLimit &&
			   this->checkOkAlert(iter->first, iter->second, callInfo->at_last)) {
				FraudAlertInfo_seq *alertInfo = new FraudAlertInfo_seq(this);
				alertInfo->set(iter->first.ip,
					       iter->first.number.c_str(),
					       iter->second,
					       callInfo->country_code_caller_ip.c_str(),
					       callInfo->country_code_called_number.c_str());
				this->evAlert(alertInfo);
			}
		}
		count.clear();
		start_interval = callInfo->at_last;
	}
}

bool FraudAlert_seq::checkOkAlert(sIpNumber ipNumber, u_int64_t count, u_int64_t at) {
	if(!this->alertOncePerHours) {
		return(true);
	}
	map<sIpNumber, sAlertInfo>::iterator iter = alerts.find(ipNumber);
	if(iter == alerts.end()) {
		alerts[ipNumber] = sAlertInfo(count, at);
		return(true);
	} else {
		if(iter->second.at + this->alertOncePerHours * 3600 * 1000000ull < at/* ||
		   iter->second.count * 1.5 < count*/) {
			alerts[ipNumber] = sAlertInfo(count, at);
		} else {
			return(false);
		}
	}
	return(true);
}


FraudAlerts::FraudAlerts() {
	threadPopCallInfo = 0;
	runPopCallInfoThread = false;
	termPopCallInfoThread = false;
	_sync_alerts = 0;
	initPopCallInfoThread();
}

FraudAlerts::~FraudAlerts() {
	clear();
}

void FraudAlerts::loadAlerts(bool lock) {
	if(lock) lock_alerts();
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select id, alert_type, descr from alerts\
		      where alert_type > 20 and\
			    alert_type < 30 and\
			    (disable is null or not disable)");
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		if(fraudDebug) {
			syslog(LOG_NOTICE, "load fraud alert %s", row["descr"].c_str());
		}
		FraudAlert *alert = NULL;
		unsigned int dbId = atol(row["id"].c_str());
		switch(atoi(row["alert_type"].c_str())) {
		case FraudAlert::_rcc:
			alert = new FraudAlert_rcc(dbId);
			break;
		case FraudAlert::_chc:
			alert = new FraudAlert_chc(dbId);
			break;
		case FraudAlert::_chcr:
			alert = new FraudAlert_chcr(dbId);
			break;
		case FraudAlert::_d:
			alert = new FraudAlert_d(dbId);
			break;
		case FraudAlert::_spc:
			alert = new FraudAlert_spc(dbId);
			break;
		case FraudAlert::_rc:
			alert = new FraudAlert_rc(dbId);
			break;
		case FraudAlert::_seq:
			alert = new FraudAlert_seq(dbId);
			break;
		}
		if(alert && alert->loadAlert()) {
			alerts.push_back(alert);
		}
	}
	delete sqlDb;
	if(lock) unlock_alerts();
}

void FraudAlerts::clear(bool lock) {
	if(lock) lock_alerts();
	for(size_t i = 0; i < alerts.size(); i++) {
		delete alerts[i];
	}
	alerts.clear();
	if(lock) unlock_alerts();
}

void FraudAlerts::beginCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_beginCall, at);
	callQueue.push(callInfo);
}

void FraudAlerts::connectCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_connectCall, at);
	callQueue.push(callInfo);
}

void FraudAlerts::seenByeCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_seenByeCall, at);
	callQueue.push(callInfo);
}

void FraudAlerts::endCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_endCall, at);
	callQueue.push(callInfo);
}

void FraudAlerts::evSipPacket(u_int32_t ip, u_int64_t at, const char *ua, int ua_len) {
	sFraudEventInfo eventInfo;
	eventInfo.typeEventInfo = sFraudEventInfo::typeEventInfo_sipPacket;
	eventInfo.src_ip = htonl(ip);
	eventInfo.at = at;
	if(ua && ua_len) {
		eventInfo.ua = ua_len == -1 ? ua : string(ua, ua_len);
	}
	eventQueue.push(eventInfo);
}

void FraudAlerts::evRegister(u_int32_t ip, u_int64_t at, const char *ua, int ua_len) {
	sFraudEventInfo eventInfo;
	eventInfo.typeEventInfo = sFraudEventInfo::typeEventInfo_register;
	eventInfo.src_ip = htonl(ip);
	eventInfo.at = at;
	if(ua && ua_len) {
		eventInfo.ua = ua_len == -1 ? ua : string(ua, ua_len);
	}
	eventQueue.push(eventInfo);
}

void FraudAlerts::evRegisterResponse(u_int32_t ip, u_int64_t at, const char *ua, int ua_len) {
	sFraudEventInfo eventInfo;
	eventInfo.typeEventInfo = sFraudEventInfo::typeEventInfo_registerResponse;
	eventInfo.src_ip = htonl(ip);
	eventInfo.at = at;
	if(ua && ua_len) {
		eventInfo.ua = ua_len == -1 ? ua : string(ua, ua_len);
	}
	eventQueue.push(eventInfo);
}

void FraudAlerts::stopPopCallInfoThread(bool wait) {
	termPopCallInfoThread = true;
	while(wait && runPopCallInfoThread) {
		usleep(1000);
	}
}

void *_FraudAlerts_popCallInfoThread(void *arg) {
	((FraudAlerts*)arg)->popCallInfoThread();
	return(NULL);
}
void FraudAlerts::initPopCallInfoThread() {
	pthread_create(&this->threadPopCallInfo, NULL, _FraudAlerts_popCallInfoThread, this);
}

void FraudAlerts::popCallInfoThread() {
	runPopCallInfoThread = true;
	sFraudCallInfo callInfo;
	sFraudEventInfo eventInfo;
	while(!is_terminating() && !termPopCallInfoThread) {
		bool okPop = false;
		if(callQueue.pop(&callInfo)) {
			lock_alerts();
			vector<FraudAlert*>::iterator iter;
			for(iter = alerts.begin(); iter != alerts.end(); iter++) {
				this->completeCallInfo_country_code(&callInfo, &(*iter)->checkInternational);
				(*iter)->evCall(&callInfo);
			}
			unlock_alerts();
			okPop = true;
		}
		if(eventQueue.pop(&eventInfo)) {
			lock_alerts();
			vector<FraudAlert*>::iterator iter;
			for(iter = alerts.begin(); iter != alerts.end(); iter++) {
				(*iter)->evEvent(&eventInfo);
			}
			unlock_alerts();
			okPop = true;
		}
		if(!okPop) {
			usleep(1000);
		}
	}
	runPopCallInfoThread = false;
}

void FraudAlerts::getCallInfoFromCall(sFraudCallInfo *callInfo, Call *call, 
				      sFraudCallInfo::eTypeCallInfo typeCallInfo, u_int64_t at) {
	callInfo->typeCallInfo = typeCallInfo;
	callInfo->call_type = call->type;
	callInfo->callid = call->call_id;
	callInfo->caller_number = call->caller;
	callInfo->called_number = call->called;
	callInfo->caller_ip = htonl(call->sipcallerip[0]);
	callInfo->called_ip = htonl(call->sipcalledip[0]);
	switch(typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_beginCall:
		callInfo->at_begin = at;
		break;
	case sFraudCallInfo::typeCallInfo_connectCall:
		callInfo->at_connect = at;
		break;
	case sFraudCallInfo::typeCallInfo_seenByeCall:
		callInfo->at_seen_bye = at;
		break;
	case sFraudCallInfo::typeCallInfo_endCall:
		callInfo->at_end = at;
		break;
	}
	callInfo->at_last = at;
}

void FraudAlerts::completeCallInfo_country_code(sFraudCallInfo *callInfo, CheckInternational *checkInternational) {
	for(int i = 0; i < 2; i++) {
		string *number = i == 0 ? &callInfo->caller_number : &callInfo->called_number;
		string *rslt_country_code = i == 0 ? &callInfo->country_code_caller_number : &callInfo->country_code_called_number;
		string *rslt_continent_code = i == 0 ? &callInfo->continent_code_caller_number : &callInfo->continent_code_called_number;
		string *rslt_country2_code = i == 0 ? &callInfo->country2_code_caller_number : &callInfo->country2_code_called_number;
		string *rslt_continent2_code = i == 0 ? &callInfo->continent2_code_caller_number : &callInfo->continent2_code_called_number;
		vector<string> countries;
		if(countryPrefixes->getCountry(number->c_str(), &countries, checkInternational) != "" &&
		   countries.size()) {
			*rslt_country_code = countries[0];
			*rslt_continent_code = countryCodes->getContinent(countries[0].c_str());
			if(countries.size() > 1) {
				*rslt_country2_code = countries[1];
				*rslt_continent2_code = countryCodes->getContinent(countries[1].c_str());
			}
		}
	}
	for(int i = 0; i < 2; i++) {
		u_int32_t *ip = i == 0 ? &callInfo->caller_ip : &callInfo->called_ip;
		string *rslt_country_code = i == 0 ? &callInfo->country_code_caller_ip : &callInfo->country_code_called_ip;
		string *rslt_continent_code = i == 0 ? &callInfo->continent_code_caller_ip : &callInfo->continent_code_called_ip;
		string country = geoIP_country->getCountry(*ip);
		if(country != "") {
			*rslt_country_code = country;
			*rslt_continent_code = countryCodes->getContinent(country.c_str());
		}
	}
	callInfo->local_called_number = countryPrefixes->isLocal(callInfo->called_number.c_str(), checkInternational);
	callInfo->local_called_ip = geoIP_country->isLocal(callInfo->called_ip, checkInternational);
}

void FraudAlerts::refresh() {
	lock_alerts();
	clear(false);
	loadAlerts(false);
	unlock_alerts();
}


void initFraud() {
	if(!opt_enable_fraud) {
		return;
	}
	if(opt_nocdr) {
		opt_enable_fraud = false;
		return;
	}
	if(!isExistsFraudAlerts() ||
	   !checkFraudTables()) {
		return;
	}
	if(!countryCodes) {
		countryCodes = new FILE_LINE CountryCodes();
		countryCodes->load();
	}
	if(!countryPrefixes) {
		countryPrefixes = new FILE_LINE CountryPrefixes();
		countryPrefixes->load();
	}
	if(!geoIP_country) {
		geoIP_country = new FILE_LINE GeoIP_country();
		geoIP_country->load();
	}
	if(!cacheNumber_location) {
		cacheNumber_location = new FILE_LINE CacheNumber_location();
	}
	if(fraudAlerts) {
		return;
	}
	fraudAlerts_lock();
	fraudAlerts = new FraudAlerts();
	fraudAlerts->loadAlerts();
	fraudAlerts_unlock();
	_fraudAlerts_ready = 1;
}

void termFraud() {
	if(fraudAlerts) {
		_fraudAlerts_ready = 0;
		fraudAlerts_lock();
		fraudAlerts->stopPopCallInfoThread(true);
		delete fraudAlerts;
		fraudAlerts = NULL;
		fraudAlerts_unlock();
	}
	if(countryCodes) {
		delete countryCodes;
		countryCodes = NULL;
	}
	if(countryPrefixes) {
		delete countryPrefixes;
		countryPrefixes = NULL;
	}
	if(geoIP_country) {
		delete geoIP_country;
		geoIP_country = NULL;
	}
	if(cacheNumber_location) {
		delete cacheNumber_location;
		cacheNumber_location = NULL;
	}
	if(sqlDbFraud) {
		delete sqlDbFraud;
		sqlDbFraud = NULL;
	}
}

bool checkFraudTables() {
	SqlDb *sqlDb = createSqlObject();
	struct checkTable {
		const char *table;
		const char *help;
		const char *emptyHelp;
	};
	const char *help_gui_loginAdmin = 
		"Login into web gui as admin. Login process create missing table.";
	checkTable checkTables[] = {
		{"alerts", help_gui_loginAdmin, NULL},
		{"alerts_fraud", help_gui_loginAdmin, NULL},
		{cloud_host[0]?"cloudshare.country_code":"country_code", help_gui_loginAdmin, help_gui_loginAdmin},
		{cloud_host[0]?"cloudshare.country_code_prefix":"country_code_prefix", help_gui_loginAdmin, help_gui_loginAdmin},
		{cloud_host[0]?"cloudshare.geoip_country":"geoip_country", help_gui_loginAdmin, help_gui_loginAdmin}
	};
	for(size_t i = 0; i < sizeof(checkTables) / sizeof(checkTables[0]); i++) {
		sqlDb->query((string("show tables like '") + checkTables[i].table + "'").c_str());
		if(!sqlDb->fetchRow()) {
			syslog(LOG_ERR, "missing table %s - fraud disabled", checkTables[i].table);
			if(checkTables[i].help) {
				syslog(LOG_NOTICE, "try: %s", checkTables[i].help);
			}
			delete sqlDb;
			return(false);
		} else if(checkTables[i].emptyHelp) {
			sqlDb->query((string("select count(*) as cnt from ") + checkTables[i].table).c_str());
			SqlDb_row row = sqlDb->fetchRow();
			if(!row || !atol(row["cnt"].c_str())) {
				syslog(LOG_ERR, "table %s is empty - fraud disabled", checkTables[i].table);
				if(checkTables[i].emptyHelp) {
					syslog(LOG_NOTICE, "try: %s", checkTables[i].emptyHelp);
				}
				delete sqlDb;
				return(false);
			}
		}
	}
	delete sqlDb;
	return(true);
}

void refreshFraud() {
	if(opt_enable_fraud) {
		if(isExistsFraudAlerts()) {
			if(!fraudAlerts) {
				initFraud();
			} else {
				fraudAlerts->refresh();
			}
		} else {
			if(fraudAlerts) {
				termFraud();
			}
		}
	}
}

void fraudBeginCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->beginCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
		fraudAlerts_unlock();
	}
}

void fraudConnectCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->connectCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
		fraudAlerts_unlock();
	}
}

void fraudSeenByeCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->seenByeCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
		fraudAlerts_unlock();
	}
}

void fraudEndCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->endCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
		fraudAlerts_unlock();
	}
}

void fraudSipPacket(u_int32_t ip, timeval tv, const char *ua, int ua_len) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evSipPacket(ip, tv.tv_sec * 1000000ull + tv.tv_usec, ua, ua_len);
		fraudAlerts_unlock();
	}
}

void fraudRegister(u_int32_t ip, timeval tv, const char *ua, int ua_len) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evRegister(ip, tv.tv_sec * 1000000ull + tv.tv_usec, ua, ua_len);
		fraudAlerts_unlock();
	}
}

void fraudRegisterResponse(u_int32_t ip, u_int64_t at, const char *ua, int ua_len) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evRegisterResponse(ip, at, ua, ua_len);
		fraudAlerts_unlock();
	}
}

bool isExistsFraudAlerts() {
	if(opt_nocdr) {
		return(false);
	}
	bool rslt = false;
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("show tables like 'alerts'");
	if(sqlDb->fetchRow()) {
		sqlDb->createTable("fraud_alert_info");
		sqlDb->query("select id, alert_type, descr from alerts\
			      where alert_type > 20 and\
				    (disable is null or not disable)\
				    limit 1");
		rslt = sqlDb->fetchRow();
	}
	delete sqlDb;
	return(rslt);
}
