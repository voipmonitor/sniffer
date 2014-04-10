#include <algorithm>
#include <sstream>

#include "fraud.h"
#include "calltable.h"


extern int opt_enable_fraud;
extern int terminating;
extern MySqlStore *sqlStore;

FraudAlerts *fraudAlerts = NULL;
int fraudDebug = 1;

CountryCodes *countryCodes = NULL;
CountryPrefixes *countryPrefixes = NULL;
GeoIP_country *geoIP_country = NULL;
CacheNumber_location *cacheNumber_location = NULL;


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
	sqlDb->query("select *\
		      from country_code\
		      where parent_id is null");
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		continents[row["code"]] = row["name"];
	}
	sqlDb->query("select country.*,\
			     continent.code as continent\
		      from country_code country\
		      join country_code continent on (continent.id = country.parent_id)\
		      where country.parent_id is not null;");
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
	return(iter != continents.end() ? iter->second : "");
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


CountryPrefixes::CountryPrefixes() {
}

void CountryPrefixes::load() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select * from country_code_prefix order by prefix");
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
	sqlDb->query("select * from geoip_country order by ip_from");
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
		countryCodes = new CountryCodes();
		countryCodes->load();
	}
	if(!geoIP_country) {
		geoIP_country = new GeoIP_country();
		geoIP_country->load();
	}
	sqlDb = createSqlObject();
}

CacheNumber_location::~CacheNumber_location() {
	delete sqlDb;
}

bool CacheNumber_location::checkNumber(const char *number, u_int32_t ip, u_int64_t at,
				       bool *diffCountry, bool *diffContinent,
				       const char *ip_country, const char *ip_continent) {
	if(diffCountry) {
		*diffCountry = false;
	}
	if(diffContinent) {
		*diffContinent = false;
	}
	map<string, sIpRec>::iterator iterCache;
	for(int pass = 0; pass < 2; pass++) {
		iterCache = cache.find(number);
		if(iterCache != cache.end()) {
			break;
		}
		if(pass == 0) {
			if(!this->loadNumber(number, at)) {
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
		cache[number] = ipRec;
		this->saveNumber(number, &ipRec);
		return(true);
	}
	if(cache[number].old_at &&
	   cache[number].old_at <= at &&
	   cache[number].at >= at &&
	   cache[number].country_code == country_code) {
		if(diffCountry && cache[number].country_code != cache[number].old_country_code) {
			*diffCountry = true;
		}
		if(diffContinent && cache[number].continent_code != cache[number].old_continent_code) {
			*diffContinent = true;
		}
		cache[number].fresh_at = at;
		return(false);
	}
	if(cache[number].country_code != country_code) {
		if(diffCountry && country_code != cache[number].country_code) {
			*diffCountry = true;
		}
		if(diffContinent && continent_code != cache[number].continent_code) {
			*diffCountry = true;
		}
		cache[number].old_ip = cache[number].ip;
		cache[number].old_country_code = cache[number].country_code;
		cache[number].old_continent_code = cache[number].continent_code;
		cache[number].old_at = cache[number].at;
		cache[number].ip = cache[number].ip;
		cache[number].country_code = country_code;
		cache[number].continent_code = continent_code;
		cache[number].at = at;
		cache[number].fresh_at = at;
		this->saveNumber(number, &cache[number], true);
		return(false);
	}
	return(true);
}

bool CacheNumber_location::loadNumber(const char *number, u_int64_t at) {
	sqlDb->query(string("select * from cache_number_location where number=") +
		     sqlEscapeStringBorder(number));
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
		cache[row["number"]] = ipRec;
		return(true);
	}
	return(false);
}

void CacheNumber_location::saveNumber(const char *number, sIpRec *ipRec, bool update) {
	if(update) {
		ostringstream outStr;
		outStr << "update cache_number_location\
			   (ip, country_code, continent_code, at,\
			    old_ip, old_country_code, old_continent_code, old_at)\
			   values ("
		       << ipRec->ip << ","
		       << sqlEscapeStringBorder(ipRec->country_code) << ","
		       << sqlEscapeStringBorder(ipRec->continent_code) << ","
		       << ipRec->at << ","
		       << ipRec->old_ip << ","
		       << sqlEscapeStringBorder(ipRec->old_country_code) << ","
		       << sqlEscapeStringBorder(ipRec->old_continent_code) << ","
		       << ipRec->old_at << ")";
		sqlStore->query_lock(outStr.str().c_str(), STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS);
	} else {
		SqlDb_row row;
		row.add(number, "number");
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


FraudAlert::FraudAlert(eFraudAlertType type, unsigned int dbId) {
	this->type = type;
	this->dbId = dbId;
	concurentCallsLimit = 0;
	typeChangeLocation = _typeLocation_NA;
}

FraudAlert::~FraudAlert() {
}

void FraudAlert::loadAlert() {
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
		 (select group_concat(ip)\
		  from alerts_groups ag\
		  join cb_ip_groups g on (g.id=ag.ip_group_id)\
		  where ag.type = 'ip_whitelist' and ag.alerts_id = alerts.id) as fraud_whitelist_ip_g,\
		 (select group_concat(ip)\
		  from alerts_groups ag\
		  join cb_ip_groups g on (g.id=ag.ip_group_id)\
		  where ag.type = 'ip_blacklist' and ag.alerts_id = alerts.id) as fraud_blacklist_ip_g\
		 from alerts\
		 where id = ") + dbIdStr);
	dbRow = sqlDb->fetchRow();
	if(defFilterIp()) {
		ipFilter.addWhite(dbRow["fraud_whitelist_ip"].c_str());
		ipFilter.addWhite(dbRow["fraud_whitelist_ip_g"].c_str());
		ipFilter.addBlack(dbRow["fraud_blacklist_ip"].c_str());
		ipFilter.addBlack(dbRow["fraud_blacklist_ip_g"].c_str());
	}
	if(defFilterNumber()) {
		phoneNumberFilter.addWhite(dbRow["fraud_whitelist_number"].c_str());
		phoneNumberFilter.addWhite(dbRow["fraud_whitelist_number_g"].c_str());
		phoneNumberFilter.addBlack(dbRow["fraud_blacklist_number"].c_str());
		phoneNumberFilter.addBlack(dbRow["fraud_blacklist_number_g"].c_str());
	}
	if(defFraudDef()) {
		loadFraudDef();
	}
	if(defConcuretCallsLimit()) {
		concurentCallsLimit = atoi(dbRow["fraud_concurent_calls_limit"].c_str());
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
	delete sqlDb;
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
			cout << "add fraud def " << row["descr"] << endl;
		}
		addFraudDef(&row);
	}
	delete sqlDb;
}

bool FraudAlert::okFilter(sFraudCallInfo *callInfo) {
	if(this->defFilterIp() && !this->ipFilter.checkIP(callInfo->caller_ip)) {
		return(false);
	}
	if(this->defFilterNumber() && !this->phoneNumberFilter.checkNumber(callInfo->caller_number.c_str())) {
		return(false);
	}
	return(true);
}

void FraudAlert::evAlert(FraudAlertInfo *alertInfo) {
}

FraudAlert_rcc_timePeriods::FraudAlert_rcc_timePeriods(const char *descr, int concurentCallsLimit, unsigned int dbId) {
	this->descr = descr;
	this->concurentCallsLimit = concurentCallsLimit;
	this->dbId = dbId;
	this->loadTimePeriods();
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

void FraudAlert_rcc_timePeriods::evCall(sFraudCallInfo *callInfo, FraudAlert_rcc *alert) {
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_connectCall:
		if(this->checkTime(callInfo->at_connect)) {
			if(callInfo->local_called_number) {
				this->calls_local[callInfo->callid] = callInfo->at_connect;
			} else {
				this->calls_international[callInfo->callid] = callInfo->at_connect;
			}
			if(this->calls_local.size() > this->concurentCallsLimit) {
				FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc;
				alertInfo->set(FraudAlert::_li_local, this->descr.c_str(), this->calls_local.size()); 
				alert->evAlert(alertInfo);
			}
			if(this->calls_international.size() > this->concurentCallsLimit) {
				FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc;
				alertInfo->set(FraudAlert::_li_international, this->descr.c_str(), this->calls_international.size()); 
				alert->evAlert(alertInfo);
			}
			if(this->calls_local.size() + this->calls_international.size() > this->concurentCallsLimit) {
				FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc;
				alertInfo->set(FraudAlert::_li_booth, this->descr.c_str(), this->calls_local.size() + this->calls_international.size()); 
				alert->evAlert(alertInfo);
			}
		}
		break;
	case sFraudCallInfo::typeCallInfo_seenByeCall:
	case sFraudCallInfo::typeCallInfo_endCall:
		if(callInfo->local_called_number) {
			this->calls_local.erase(callInfo->callid);
		} else {
			this->calls_international.erase(callInfo->callid);
		}
		break;
	default:
		break;
	}
}

void FraudAlertInfo_rcc::set(FraudAlert::eLocalInternational localInternational,
			     const char *timeperiod_name,
			     unsigned int concurentCalls) {
	this->localInternational = localInternational;
	if(timeperiod_name) {
		this->timeperiod_name = timeperiod_name;
	}
	this->concurentCalls = concurentCalls;
}

void FraudAlert_rcc::addFraudDef(SqlDb_row *row) {
	timePeriods.push_back(FraudAlert_rcc_timePeriods(
				(*row)["descr"].c_str(),
				atoi((*row)["concurent_calls_limit"].c_str()),
				atol((*row)["id"].c_str())));
}

FraudAlert_rcc::FraudAlert_rcc(unsigned int dbId)
 : FraudAlert(_rcc, dbId) {
}

void FraudAlert_rcc::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type == REGISTER ||
	   !this->okFilter(callInfo)) {
		return;
	}
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_connectCall:
		if(callInfo->local_called_number) {
			this->calls_local[callInfo->callid] = callInfo->at_connect;
		} else {
			this->calls_international[callInfo->callid] = callInfo->at_connect;
		}
		if(this->calls_local.size() > this->concurentCallsLimit) {
			FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc;
			alertInfo->set(FraudAlert::_li_local, NULL, this->calls_local.size()); 
			this->evAlert(alertInfo);
		}
		if(this->calls_international.size() > this->concurentCallsLimit) {
			FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc;
			alertInfo->set(FraudAlert::_li_international, NULL, this->calls_international.size()); 
			this->evAlert(alertInfo);
		}
		if(this->calls_local.size() + this->calls_international.size() > this->concurentCallsLimit) {
			FraudAlertInfo_rcc *alertInfo = new FraudAlertInfo_rcc;
			alertInfo->set(FraudAlert::_li_booth, NULL, this->calls_local.size() + this->calls_international.size()); 
			this->evAlert(alertInfo);
		}
		break;
	case sFraudCallInfo::typeCallInfo_seenByeCall:
	case sFraudCallInfo::typeCallInfo_endCall:
		if(callInfo->local_called_number) {
			this->calls_local.erase(callInfo->callid);
		} else {
			this->calls_international.erase(callInfo->callid);
		}
		break;
	default:
		break;
	}
	vector<FraudAlert_rcc_timePeriods>::iterator iter = timePeriods.begin();
	while(iter != timePeriods.end()) {
		(*iter).evCall(callInfo, this);
		++iter;
	}
}

void FraudAlertInfo_chc::set(const char *number,
			     FraudAlert::eTypeLocation typeLocation,
			     const char *location_code) {
	this->number = number;
	this->typeLocation = typeLocation;
	this->location_code = location_code;
}

FraudAlert_chc::FraudAlert_chc(unsigned int dbId)
 : FraudAlert(_chc, dbId) {
}

void FraudAlert_chc::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type == REGISTER ||
	   !this->okFilter(callInfo)) {
		return;
	}
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_beginCall:
		{
		if(this->changeLocationOk.size() &&
		   (countryCodes->isLocationIn(callInfo->country_code_caller_ip.c_str(), &this->changeLocationOk) ||
		    countryCodes->isLocationIn(callInfo->continent_code_caller_ip.c_str(), &this->changeLocationOk, true))) {
			return;
		}
		bool diffCountry = false;
		bool diffContinent = false;
		if(!cacheNumber_location->checkNumber(callInfo->caller_number.c_str(), callInfo->caller_ip, callInfo->at_begin,
						      &diffCountry, &diffContinent,
						      callInfo->country_code_caller_ip.c_str(), callInfo->continent_code_caller_ip.c_str())) {
			if(this->typeChangeLocation == _typeLocation_country && diffCountry) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc;
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_country,
					       callInfo->country_code_caller_ip.c_str());
				this->evAlert(alertInfo);
			}
			if(this->typeChangeLocation == _typeLocation_continent && diffContinent) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc;
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_continent,
					       callInfo->continent_code_caller_ip.c_str());
				this->evAlert(alertInfo);
			}
		} 
		}
		break;
	default:
		break;
	}
}

FraudAlert_chcr::FraudAlert_chcr(unsigned int dbId)
 : FraudAlert(_chcr, dbId) {
}

void FraudAlert_chcr::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type != REGISTER ||
	   !this->okFilter(callInfo)) {
		return;
	}
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_beginCall:
		{
		if(this->changeLocationOk.size() &&
		   (countryCodes->isLocationIn(callInfo->country_code_caller_ip.c_str(), &this->changeLocationOk) ||
		    countryCodes->isLocationIn(callInfo->continent_code_caller_ip.c_str(), &this->changeLocationOk, true))) {
			return;
		}
		bool diffCountry = false;
		bool diffContinent = false;
		if(!cacheNumber_location->checkNumber(callInfo->caller_number.c_str(), callInfo->caller_ip, callInfo->at_begin,
						      &diffCountry, &diffContinent,
						      callInfo->country_code_caller_ip.c_str(), callInfo->continent_code_caller_ip.c_str())) {
			if(this->typeChangeLocation == _typeLocation_country && diffCountry) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc;
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_country,
					       callInfo->country_code_caller_ip.c_str());
				this->evAlert(alertInfo);
			}
			if(this->typeChangeLocation == _typeLocation_continent && diffContinent) {
				FraudAlertInfo_chc *alertInfo = new FraudAlertInfo_chc;
				alertInfo->set(callInfo->caller_number.c_str(),
					       _typeLocation_continent,
					       callInfo->continent_code_caller_ip.c_str());
				this->evAlert(alertInfo);
			}
		} 
		}
		break;
	default:
		break;
	}
}

void FraudAlertInfo_d::set(const char *number, 
			   const char *country_code, 
			   const char *continent_code) {
	this->number = number;
	this->country_code = country_code;
	this->continent_code = continent_code;
}

FraudAlert_d::FraudAlert_d(unsigned int dbId)
 : FraudAlert(_d, dbId) {
}

void FraudAlert_d::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type == REGISTER ||
	   !this->okFilter(callInfo)) {
		return;
	}
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_beginCall:
		{
		if(this->destLocation.size() &&
		   (countryCodes->isLocationIn(callInfo->country_code_called_number.c_str(), &this->changeLocationOk) ||
		    countryCodes->isLocationIn(callInfo->continent_code_called_number.c_str(), &this->changeLocationOk, true))) {
			FraudAlertInfo_d *alertInfo = new FraudAlertInfo_d;
			alertInfo->set(callInfo->called_number.c_str(),
				       callInfo->country_code_called_number.c_str(),
				       callInfo->continent_code_called_number.c_str());
			this->evAlert(alertInfo);
		}
		}
		break;
	default:
		break;
	}
}


FraudAlerts::FraudAlerts() {
	threadPopCallInfo = 0;
	initPopCallInfoThread();
}

FraudAlerts::~FraudAlerts() {
	clear();
}

void FraudAlerts::loadAlerts() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select id, alert_type, descr from alerts\
		      where alert_type > 20 and\
			    (disable is null or not disable)");
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		if(fraudDebug) {
			cout << "load alert " << row["descr"] << endl;
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
		}
		if(alert) {
			alert->loadAlert();
			alerts.push_back(alert);
		}
	}
	delete sqlDb;
}

void FraudAlerts::clear() {
	for(size_t i = 0; i < alerts.size(); i++) {
		delete alerts[i];
	}
	alerts.clear();
}

void FraudAlerts::beginCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_beginCall, at);
	this->completeCallInfo_country_code(&callInfo);
	callQueue.push(callInfo);
}

void FraudAlerts::connectCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_connectCall, at);
	this->completeCallInfo_country_code(&callInfo);
	callQueue.push(callInfo);
}

void FraudAlerts::seenByeCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_seenByeCall, at);
	this->completeCallInfo_country_code(&callInfo);
	callQueue.push(callInfo);
}

void FraudAlerts::endCall(Call *call, u_int64_t at) {
	sFraudCallInfo callInfo;
	this->getCallInfoFromCall(&callInfo, call, sFraudCallInfo::typeCallInfo_endCall, at);
	this->completeCallInfo_country_code(&callInfo);
	callQueue.push(callInfo);
}

void *_FraudAlerts_popCallInfoThread(void *arg) {
	((FraudAlerts*)arg)->popCallInfoThread();
	return(NULL);
}
void FraudAlerts::initPopCallInfoThread() {
	pthread_create(&this->threadPopCallInfo, NULL, _FraudAlerts_popCallInfoThread, this);
}

void FraudAlerts::popCallInfoThread() {
	while(!terminating || true) {
		sFraudCallInfo callInfo;
		if(callQueue.pop(&callInfo)) {
			vector<FraudAlert*>::iterator iter;
			for(iter = alerts.begin(); iter != alerts.end(); iter++) {
				(*iter)->evCall(&callInfo);
			}
		} else {
			usleep(1000);
		}
	}
}

void FraudAlerts::getCallInfoFromCall(sFraudCallInfo *callInfo, Call *call, 
				      sFraudCallInfo::eTypeCallInfo typeCallInfo, u_int64_t at) {
	callInfo->typeCallInfo = typeCallInfo;
	callInfo->call_type = call->type;
	callInfo->callid = call->call_id;
	callInfo->caller_number = call->caller;
	callInfo->called_number = call->called;
	callInfo->caller_ip = htonl(call->sipcallerip);
	callInfo->called_ip = htonl(call->sipcalledip);
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

void FraudAlerts::completeCallInfo_country_code(sFraudCallInfo *callInfo) {
	for(int i = 0; i < 2; i++) {
		string *number = i == 0 ? &callInfo->caller_number : &callInfo->called_number;
		string *rslt_country_code = i == 0 ? &callInfo->country_code_caller_number : &callInfo->country_code_called_number;
		string *rslt_continent_code = i == 0 ? &callInfo->continent_code_caller_number : &callInfo->continent_code_called_number;
		string *rslt_country2_code = i == 0 ? &callInfo->country2_code_caller_number : &callInfo->country2_code_called_number;
		string *rslt_continent2_code = i == 0 ? &callInfo->continent2_code_caller_number : &callInfo->continent2_code_called_number;
		vector<string> countries;
		if(countryPrefixes->getCountry(number->c_str(), &countries) != "" &&
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
	callInfo->local_called_number = countryPrefixes->isLocal(callInfo->called_number.c_str());
	callInfo->local_called_ip = geoIP_country->isLocal(callInfo->called_ip);
}


void initFraud() {
	if(!opt_enable_fraud) {
		return;
	}
	if(!countryCodes) {
		countryCodes = new CountryCodes();
		countryCodes->load();
	}
	if(!countryPrefixes) {
		countryPrefixes = new CountryPrefixes();
		countryPrefixes->load();
	}
	if(!geoIP_country) {
		geoIP_country = new GeoIP_country();
		geoIP_country->load();
	}
	if(!cacheNumber_location) {
		cacheNumber_location = new CacheNumber_location();
	}
	if(fraudAlerts) {
		return;
	}
	fraudAlerts = new FraudAlerts();
	fraudAlerts->loadAlerts();
}

void fraudBeginCall(Call *call, timeval tv) {
	if(fraudAlerts) {
		fraudAlerts->beginCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
	}
}

void fraudConnectCall(Call *call, timeval tv) {
	if(fraudAlerts) {
		fraudAlerts->connectCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
	}
}

void fraudSeenByeCall(Call *call, timeval tv) {
	if(fraudAlerts) {
		fraudAlerts->seenByeCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
	}
}

void fraudEndCall(Call *call, timeval tv) {
	if(fraudAlerts) {
		fraudAlerts->endCall(call, tv.tv_sec * 1000000ull + tv.tv_usec);
	}
}
