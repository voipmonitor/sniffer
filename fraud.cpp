#include <sstream>
#include <syslog.h>

#include "fraud.h"
#include "calltable.h"
#include "sniff.h"
#include "pcap_queue_block.h"
#include "filter_call.h"


extern int opt_id_sensor;
extern int opt_enable_fraud;
extern int opt_nocdr;
extern MySqlStore *sqlStore;
extern CountryDetect *countryDetect;

FraudAlerts *fraudAlerts = NULL;
volatile int _fraudAlerts_ready = 0;
volatile int _fraudAlerts_lock = 0;
int fraudDebug = 1;

CountryCodes *countryCodes = NULL;
CountryPrefixes *countryPrefixes = NULL;
GeoIP_country *geoIP_country = NULL;
CacheNumber_location *cacheNumber_location = NULL;

SqlDb *sqlDbFraud = NULL;

static bool opt_enable_fraud_store_pcaps;


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


CacheNumber_location::CacheNumber_location() {
	if(!countryCodes) {
		countryCodes = new FILE_LINE(7001) CountryCodes();
		countryCodes->load();
	}
	if(!geoIP_country && !countryDetect) {
		geoIP_country = new FILE_LINE(7002) GeoIP_country();
		geoIP_country->load();
	}
	sqlDb = createSqlObject();
	last_cleanup_at = 0;
}

CacheNumber_location::~CacheNumber_location() {
	delete sqlDb;
}

bool CacheNumber_location::checkNumber(const char *number, vmIP number_ip, const char *domain,
				       vmIP ip, u_int64_t at,
				       bool *diffCountry, bool *diffContinent,
				       vmIP *oldIp, string *oldCountry, string *oldContinent,
				       const char *ip_country, const char *ip_continent) {
	if(!last_cleanup_at) {
		last_cleanup_at = at;
	}
	if(at > last_cleanup_at + TIME_S_TO_US(600)) {
		this->cleanup(at);
	}
	if(diffCountry) {
		*diffCountry = false;
	}
	if(diffContinent) {
		*diffContinent = false;
	}
	if(oldIp) {
		oldIp->clear();
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
	sNumber numberIp(number, number_ip, domain);
	map<sNumber, sIpRec>::iterator iterCache;
	for(int pass = 0; pass < 2; pass++) {
		iterCache = cache.find(numberIp);
		if(iterCache != cache.end()) {
			break;
		}
		if(pass == 0) {
			if(!this->loadNumber(number, number_ip, domain, at)) {
				break;
			}
		}
	}
	string country_code = ip_country ? 
			       ip_country : 
			       (countryDetect ? 
				 countryDetect->getCountryByIP(ip) : 
				 geoIP_country->getCountry(ip));
	string continent_code = ip_continent ? ip_continent : countryCodes->getContinent(country_code.c_str());
	if(iterCache == cache.end()) {
		sIpRec ipRec;
		ipRec.ip = ip;
		ipRec.country_code = country_code;
		ipRec.continent_code = continent_code;
		ipRec.at = at;
		ipRec.fresh_at = at;
		cache[numberIp] = ipRec;
		this->saveNumber(number, number_ip, domain, &ipRec);
		return(true);
	}
	if(iterCache->second.country_code != country_code &&
	   at > iterCache->second.at) {
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
		this->saveNumber(number, number_ip, domain, &cache[numberIp], true);
		return(false);
	}
	iterCache->second.fresh_at = at;
	if(iterCache->second.country_code == country_code &&
	   at <= iterCache->second.at &&
	   iterCache->second.old_at &&
	   at >= iterCache->second.old_at) {
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
		return(false);
	}
	return(true);
}

bool CacheNumber_location::loadNumber(const char *number, vmIP number_ip, const char *domain, u_int64_t at) {
	SqlDb_row cond;
	cond.add(string_size(number, 30), "number");
	cond.add(number_ip, "number_ip", false, sqlDb, getTable(domain).c_str());
	if(domain && *domain) {
		cond.add(string_size(domain, 100), "domain");
	}
	sqlDb->query("select * from " + getTable(domain) + " where " +
		     cond.implodeFieldContent(" and ", "`", "\"", false, true));
	SqlDb_row row = sqlDb->fetchRow();
	if(row) {
		sIpRec ipRec;
		ipRec.ip.setIP(&row, "ip");
		ipRec.country_code = row["country_code"];
		ipRec.continent_code = row["continent_code"];
		ipRec.at = atoll(row["at"].c_str());
		ipRec.old_ip.setIP(&row, "old_ip");
		ipRec.old_country_code = row["old_country_code"];
		ipRec.old_continent_code = row["old_continent_code"];
		ipRec.old_at = atoll(row["old_at"].c_str());
		ipRec.fresh_at = at;
		cache[sNumber(number, number_ip, domain)] = ipRec;
		return(true);
	}
	return(false);
}

void CacheNumber_location::saveNumber(const char *number, vmIP number_ip, const char *domain, sIpRec *ipRec, bool update) {
	SqlDb_row row;
	row.add(ipRec->ip, "ip", false, sqlDb, getTable(domain).c_str());
	row.add(ipRec->country_code, "country_code");
	row.add(ipRec->continent_code, "continent_code");
	row.add(ipRec->at, "at");
	row.add(ipRec->old_ip, "old_ip", false, sqlDb, getTable(domain).c_str());
	row.add(ipRec->old_country_code, "old_country_code");
	row.add(ipRec->old_continent_code, "old_continent_code");
	row.add(ipRec->old_at, "old_at");
	if(update) {
		SqlDb_row cond;
		cond.add(string_size(number, 30), "number");
		cond.add(number_ip, "number_ip", false, sqlDb, getTable(domain).c_str());
		if(domain && *domain) {
			cond.add(string_size(domain, 100), "domain");
		}
		sqlStore->query_lock(MYSQL_ADD_QUERY_END(
				     sqlDb->updateQuery(getTable(domain), row, cond, false, true)),
				     STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS, 0);
	} else {
		row.add(string_size(number, 30), "number");
		row.add(number_ip, "number_ip", false, sqlDb, getTable(domain).c_str());
		if(domain && *domain) {
			row.add(string_size(domain, 100), "domain");
		}
		sqlStore->query_lock(MYSQL_ADD_QUERY_END(
				     sqlDb->insertQuery(getTable(domain), row, false, true, true)),
				     STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS, 0);
	}
}

void CacheNumber_location::cleanup(u_int64_t at) {
	map<sNumber, sIpRec>::iterator iterCache;
	for(iterCache = cache.begin(); iterCache != cache.end();) {
		if(at > iterCache->second.fresh_at + TIME_S_TO_US(600)) {
			cache.erase(iterCache++);
		} else {
			++iterCache;
		}
	}
	last_cleanup_at = at;
}

string CacheNumber_location::getTable(const char *domain) {
	return(domain && *domain ? "cache_number_domain_location" : "cache_number_location");
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
	ipFilterCondition12 = _cond12_and;
	phoneNumberFilterCondition12 = _cond12_and;
	useDomain = false;
	concurentCallsLimitLocal = 0;
	concurentCallsLimitInternational = 0;
	concurentCallsLimitBoth = 0;
	typeBy = _typeBy_NA;
	typeByIP = _typeByIP_NA;
	typeChangeLocation = _typeLocation_NA;
	intervalLength = 0;
	intervalLimit = 0;
	filterInternational = false;
	includeSessionCanceled = false;
	onlyConnected = false;
	suppressRepeatingAlerts = false;
	alertOncePerHours = 0;
	hour_from = -1;
	hour_to = -1;
	for(int i = 0; i < 7; i++) {
		day_of_week[i] = false;
	}
	day_of_week_set = false;
	owner_uid = 0;
	is_private = false;
	use_user_restriction = false;
	userRestriction = NULL;
	storePcaps = false;
	verbLog = NULL;
}

FraudAlert::~FraudAlert() {
	if(userRestriction) {
		delete userRestriction;
	}
	if(verbLog) {
		fclose(verbLog);
	}
}

bool FraudAlert::isReg() {
	return(type == _reg_ua ||
	       type == _reg_short ||
	       type == _reg_expire);
}

bool FraudAlert::loadAlert(bool *useUserRestriction, bool *useUserRestriction_custom_headers, SqlDb *sqlDb) {
	*useUserRestriction = false;
	*useUserRestriction_custom_headers = false;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
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
		 where id = ") + intToString(dbId));
	dbRow = sqlDb->fetchRow();
	dbRow.clearSqlDb();
	if(!dbRow) {
		if(_createSqlObject) {
			delete sqlDb;
		}
		return(false);
	}
	descr = dbRow["descr"];
	if(defTypeBy()) {
		typeBy = dbRow["fraud_rcc_by"] == "source_ip" ? _typeBy_source_ip :
			 dbRow["fraud_rcc_by"] == "destination_ip" ? _typeBy_destination_ip :
			 dbRow["fraud_rcc_by"] == "source_number" ? _typeBy_source_number :
			 dbRow["fraud_rcc_by"] == "rtp_stream_ip" ? _typeBy_rtp_stream_ip :
			 dbRow["fraud_rcc_by"] == "rtp_stream_ip_group" ? _typeBy_rtp_stream_ip_group :
			 dbRow["fraud_rcc_by"] == "summary" ? _typeBy_summary :
				_typeBy_source_ip;
	}
	if(defByIP()) {
		typeByIP = dbRow["fraud_by_ip"] == "src" ? _typeByIP_src :
			   dbRow["fraud_by_ip"] == "dst" ? _typeByIP_dst :
			   dbRow["fraud_by_ip"] == "both" ? _typeByIP_both :
				_typeByIP_NA;
	}
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
	if(defFilterIpCondition12()) {
		ipFilterCondition12 = dbRow["fraud_ip_condition_12"] == "and" ? _cond12_and :
				      dbRow["fraud_ip_condition_12"] == "or" ? _cond12_or :
				      dbRow["fraud_ip_condition_12"] == "both_directions" ? _cond12_both_directions :
				      typeBy == _typeBy_rtp_stream_ip || typeBy == _typeBy_rtp_stream_ip_group ? 
				       _cond12_both_directions : 
				       _cond12_and;
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
	if(defFilterNumberCondition12()) {
		phoneNumberFilterCondition12 = dbRow["fraud_number_condition_12"] == "and" ? _cond12_and :
					       dbRow["fraud_number_condition_12"] == "or" ? _cond12_or :
					       dbRow["fraud_number_condition_12"] == "both_directions" ? _cond12_both_directions :
					       typeBy == _typeBy_rtp_stream_ip || typeBy == _typeBy_rtp_stream_ip_group ? 
						_cond12_both_directions :
						_cond12_and;
	}
	if(defFilterUA()) {
		uaFilter.addWhite(dbRow["fraud_whitelist_ua"].c_str());
		uaFilter.addWhite(dbRow["fraud_whitelist_ua_g"].c_str());
	}
	if(defUseDomain()) {
		useDomain = atoi(dbRow["fraud_use_domain"].c_str());
	}
	if(defFilterDomain()) {
		domainFilter.addComb(dbRow["fraud_whitelist_domain"].c_str());
	}
	if(defFraudDef()) {
		loadFraudDef(sqlDb);
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
	if(defDestPrefixes()) {
		destPrefixes = split(dbRow["fraud_dest_prefixes"].c_str(), ",", true);
		for(unsigned i = 0; i < destPrefixes.size(); i++) {
			size_t posCountryCodeSeparator = destPrefixes[i].find('/');
			if(posCountryCodeSeparator != string::npos) {
				destPrefixes[i].resize(posCountryCodeSeparator);
			}
		}
	}
	if(defInterval()) {
		intervalLength = atol(dbRow["fraud_interval_length"].c_str());
		intervalLimit = atol(dbRow["fraud_interval_limit"].c_str());
	}
	if(defFilterInternational()) {
		filterInternational = atoi(dbRow["fraud_filter_international"].c_str());
	}
	if(defIncludeSessionCanceled()) {
		includeSessionCanceled = atoi(dbRow["fraud_include_session_canceled"].c_str());
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
	checkInternational.load(&dbRow, sqlDb);
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
	owner_uid = atol(dbRow["owner_uid"].c_str());
	is_private = atoi(dbRow["private"].c_str()) > 0;
	use_user_restriction = atoi(dbRow["use_user_restriction"].c_str()) > 0;
	if(owner_uid && use_user_restriction) {
		*useUserRestriction = true;
		userRestriction = new FILE_LINE(0) cUserRestriction;
		bool _useCustomHeaders = false;
		userRestriction->load(owner_uid, &_useCustomHeaders);
		if(_useCustomHeaders) {
			*useUserRestriction_custom_headers = true;
		}
	}
	if(defStorePcaps()) {
		storePcaps = atoi(dbRow["fraud_store_pcaps"].c_str());
		storePcapsToPaths = dbRow["fraud_store_pcaps_to_path"];
	}
	loadAlertVirt();
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
}

void FraudAlert::loadFraudDef(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query(string(
		"select *\
		 from alerts_fraud\
		 where alerts_id = ") + intToString(dbId));
	
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		if(fraudDebug) {
			syslog(LOG_NOTICE, "add fraud def %s", row["descr"].c_str());
		}
		addFraudDef(&row, sqlDb);
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
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
	case _reg_ua: return("reg_ua");
	case _reg_short: return("reg_short");
	case _reg_expire: return("reg_expire");
	case _ccd: return("ccd");
	}
	return("");
}

bool FraudAlert::openVerbLog() {
	string verbLogFileName = string(getSpoolDir(tsf_main, 0)) + "/fraud_log_" + intToString(this->dbId);
	verbLog = fopen(verbLogFileName.c_str(), "a");
	if(verbLog) {
		setbuf(verbLog, NULL);
		fprintf(verbLog, "start %s %s\n", this->getDescr().c_str(), sqlDateTimeString(time(NULL)).c_str());
		return(true);
	}
	return(false);
}

bool FraudAlert::okFilterIp(vmIP ip, vmIP ip2) {
	if((!this->defFilterIp() || this->ipFilter.is_empty()) && 
	   (!this->defFilterIp2() || this->ipFilter2.is_empty())) {
		return(true);
	}
	switch(ipFilterCondition12) {
	case _cond12_and:
		return((!this->defFilterIp() || this->ipFilter.checkIP(ip)) &&
		       (!this->defFilterIp2() || this->ipFilter2.checkIP(ip2)));
	case _cond12_or:
		return((!this->defFilterIp() || (!this->ipFilter.is_empty() && this->ipFilter.checkIP(ip))) ||
		       (!this->defFilterIp2() || (!this->ipFilter2.is_empty() && this->ipFilter2.checkIP(ip2))));
	case _cond12_both_directions:
		return(((!this->defFilterIp() || this->ipFilter.checkIP(ip)) &&
			(!this->defFilterIp2() || this->ipFilter2.checkIP(ip2))) ||
		       ((!this->defFilterIp() || this->ipFilter.checkIP(ip2)) &&
			(!this->defFilterIp2() || this->ipFilter2.checkIP(ip))));
	default:
		return(true);
	}
	return(false);
}

bool FraudAlert::okFilterPhoneNumber(const char *numb, const char *numb2) {
	if((!this->defFilterNumber() || this->phoneNumberFilter.is_empty()) && 
	   (!this->defFilterNumber2() || this->phoneNumberFilter2.is_empty())) {
		return(true);
	}
	switch(phoneNumberFilterCondition12) {
	case _cond12_and:
		return((!this->defFilterNumber() || this->phoneNumberFilter.checkNumber(numb)) &&
		       (!this->defFilterNumber2() || this->phoneNumberFilter2.checkNumber(numb2)));
	case _cond12_or:
		return((!this->defFilterNumber() || (!this->phoneNumberFilter.is_empty() && this->phoneNumberFilter.checkNumber(numb))) ||
		       (!this->defFilterNumber2() || (!this->phoneNumberFilter2.is_empty() && this->phoneNumberFilter2.checkNumber(numb2))));
	case _cond12_both_directions:
		return(((!this->defFilterNumber() || this->phoneNumberFilter.checkNumber(numb)) &&
			(!this->defFilterNumber2() || this->phoneNumberFilter2.checkNumber(numb2))) ||
		       ((!this->defFilterNumber() || this->phoneNumberFilter.checkNumber(numb2)) &&
			(!this->defFilterNumber2() || this->phoneNumberFilter2.checkNumber(numb))));
	default:
		return(true);
	}
	return(false);
}

bool FraudAlert::okFilterDomain(const char *domain) {
	if(!this->defFilterDomain() || this->domainFilter.is_empty()) {
		return(true);
	}
	return(this->domainFilter.check(domain));
}

bool FraudAlert::okFilter(sFraudCallInfo *callInfo) {
	if(userRestriction && !userRestriction->check(cUserRestriction::_ts_cdr,
						      &callInfo->caller_ip, &callInfo->called_ip,
						      callInfo->caller_number.c_str(), callInfo->called_number.c_str(), NULL,
						      callInfo->caller_domain.c_str(), callInfo->called_domain.c_str(), NULL,
						      callInfo->vlan,
						      callInfo->custom_headers)) {
		return(false);
	}
	if(!this->okFilterIp(callInfo->caller_ip, callInfo->called_ip)) {
		return(false);
	}
	if(!this->okFilterPhoneNumber(callInfo->caller_number.c_str(), callInfo->called_number.c_str())) {
		return(false);
	}
	if(!this->okFilterDomain(callInfo->caller_domain.c_str())) {
		return(false);
	}
	if(this->defDestPrefixes() && this->destPrefixes.size()) {
		if(!callInfo->country_prefix_called.length()) {
			return(false);
		}
		bool ok = false;
		for(unsigned i = 0; i < this->destPrefixes.size(); i++) {
			if(this->destPrefixes[i] == callInfo->country_prefix_called) {
				ok = true;
				break;
			}
		}
		if(!ok) {
			return(false);
		}
	}
	return(true);
}

bool FraudAlert::okFilter(sFraudRtpStreamInfo *rtpStreamInfo) {
	if(userRestriction && !userRestriction->check(cUserRestriction::_ts_other,
						      &rtpStreamInfo->rtp_src_ip, &rtpStreamInfo->rtp_dst_ip,
						      NULL, NULL, NULL,
						      NULL, NULL, NULL,
						      VLAN_UNSET,
						      NULL)) {
		return(false);
	}
	if(!this->okFilterIp(rtpStreamInfo->rtp_src_ip, rtpStreamInfo->rtp_dst_ip)) {
		return(false);
	}
	if(!this->okFilterPhoneNumber(rtpStreamInfo->caller_number.c_str(), rtpStreamInfo->called_number.c_str())) {
		return(false);
	}
	return(true);
}

bool FraudAlert::okFilter(sFraudEventInfo *eventInfo) {
	if(userRestriction && !userRestriction->check(cUserRestriction::_ts_other,
						      &eventInfo->src_ip, &eventInfo->dst_ip,
						      NULL, NULL, NULL,
						      NULL, NULL, NULL,
						      VLAN_UNSET,
						      NULL)) {
		return(false);
	}
	if(!this->okFilterIp(eventInfo->src_ip, eventInfo->dst_ip)) {
		return(false);
	}
	if(this->defFilterUA() && !this->uaFilter.checkUA(eventInfo->ua.c_str())) {
		return(false);
	}
	return(true);
}

bool FraudAlert::okFilter(sFraudRegisterInfo *registerInfo) {
	if(userRestriction && !userRestriction->check(cUserRestriction::_ts_other,
						      &registerInfo->sipcallerip, &registerInfo->sipcalledip,
						      registerInfo->from_num.c_str(), registerInfo->to_num.c_str(), registerInfo->contact_num.c_str(),
						      registerInfo->from_domain.c_str(), registerInfo->to_domain.c_str(), registerInfo->contact_domain.c_str(),
						      VLAN_UNSET,
						      NULL)) {
		return(false);
	}
	return(true);
}

bool FraudAlert::okDayHour(time_t at) {
	if((hour_from >= 0 && hour_to >= 0) ||
	   day_of_week_set) {
		tm attm = time_r(&at, fraudAlerts->getGuiTimezone());
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
	row.add(sqlEscapeString(alertInfo->getJson()), "alert_info");
	row.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
	sqlStore->query_lock(MYSQL_ADD_QUERY_END(
			     sqlDbFraud->insertQuery("fraud_alert_info", row)), 
			     STORE_PROC_ID_FRAUD_ALERT_INFO, 0);
	delete alertInfo;
}

FraudAlertReg_filter::FraudAlertReg_filter(FraudAlertReg *parent) {
	filter = NULL;
	ev_counter = 0;
	start_interval = 0;
	this->parent = parent;
}

FraudAlertReg_filter::~FraudAlertReg_filter() {
	if(filter) {
		delete filter;
	}
}

void FraudAlertReg_filter::evRegister(sFraudRegisterInfo *registerInfo) {
	if(!okFilter(registerInfo)) {
		return;
	}
	++ev_counter;
	ev_map[*(sFraudRegisterInfo_id*)registerInfo] = *(sFraudRegisterInfo_data*)registerInfo;
	ev_map[*(sFraudRegisterInfo_id*)registerInfo].time_from_prev_state =
		registerInfo->at > registerInfo->prev_state_at ? TIME_US_TO_S(registerInfo->at - registerInfo->prev_state_at) : 0;
	if(!start_interval) {
		start_interval = registerInfo->at;
	}
	if(parent->intervalLength ?
	    registerInfo->at - start_interval > TIME_S_TO_US(parent->intervalLength) :
    	    ev_counter >= parent->intervalLimit) {
		if(ev_counter >= parent->intervalLimit) {
			FraudAlertInfo_reg *alertInfo = new FILE_LINE(7003) FraudAlertInfo_reg(parent);
			alertInfo->set(description.c_str(), ev_counter, &ev_map);
			parent->evAlert(alertInfo);
		}
		ev_counter = 0;
		ev_map.clear();
		start_interval = registerInfo->at;
	}
}

bool FraudAlertReg_filter::okFilter(sFraudRegisterInfo *registerInfo) {
	if(!parent->okFilter(registerInfo)) {
		return(false);
	}
	if(filter && !filter->check(registerInfo)) {
		return(false);
	}
	return(true);
}

void FraudAlertReg_filter::setFilter(const char *description, const char *filter_str) {
	this->description = description;
	this->filter_str = filter_str;
	if(!this->filter_str.empty()) {
		filter = new FILE_LINE(0) cRegisterFilterFraud((char*)this->filter_str.c_str());
	}
}

FraudAlertReg::FraudAlertReg(FraudAlert::eFraudAlertType type, unsigned int dbId) 
 : FraudAlert(type, dbId) {
}

FraudAlertReg::~FraudAlertReg() {
	map<u_int32_t, FraudAlertReg_filter*>::iterator iter;
	for(iter = filters.begin(); iter != filters.end(); iter++) {
		delete iter->second;
	}
	for(unsigned i = 0; i < ua_regex.size(); i++) {
		delete ua_regex[i];
	}
}

void FraudAlertReg::evRegister(sFraudRegisterInfo *registerInfo) {
	map<u_int32_t, FraudAlertReg_filter*>::iterator iter;
	for(iter = filters.begin(); iter != filters.end(); iter++) {
		iter->second->evRegister(registerInfo);
	}
}

bool FraudAlertReg::checkUA(const char *ua) {
	if(!ua_regex.size()) {
		return(true);
	}
	if(ua && *ua) {
		for(unsigned i = 0; i < ua_regex.size(); i++) {
			if(ua_regex[i]->match(ua) > 0) {
				return(ua_reg_neg ? false : true);
			}
		}
	}
	return(ua_reg_neg ? true : false);
}

bool FraudAlertReg::checkRegisterTimeSecLe(sFraudRegisterInfo *registerInfo) {
	return((registerInfo->state != rs_OK && registerInfo->state != rs_UnknownMessageOK) &&
	       (registerInfo->prev_state == rs_OK || registerInfo->prev_state == rs_UnknownMessageOK) &&
	       registerInfo->at > registerInfo->prev_state_at &&
	       registerInfo->at - registerInfo->prev_state_at <= TIME_S_TO_US(registerTimeSecLe));
}

void FraudAlertReg::loadAlertVirt(SqlDb *sqlDb) {
	intervalLength = atol(dbRow["reg_interval_length_sec"].c_str());
	intervalLimit = atol(dbRow["reg_interval_limit"].c_str());
	vector<string> ua_split = split(dbRow["reg_ua"].c_str(), split(",|;|\r|\n", "|"), true);
	for(unsigned i = 0; i < ua_split.size(); i ++) {
		string ua = ua_split[i];
		if(ua[0] == '%') {
			ua = ".*" + ua.substr(1);
		}
		if(ua[ua.length() - 1] == '%') {
			ua = ua.substr(0, ua.length() - 1) + ".*";
		}
		cRegExp *regExp = new FILE_LINE(0) cRegExp(ua.c_str());
		if(regExp->isOK()) {
			ua_regex.push_back(regExp);
		} else {
			delete regExp;
		}
	}
	ua_reg_neg = atoi(dbRow["reg_ua_neg"].c_str());
	registerTimeSecLe = atol(dbRow["reg_register_time_sec_le"].c_str());
	loadFilters(sqlDb);
}

void FraudAlertReg::loadFilters(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query(string(
		"select *\
		 from alerts_reg_filters\
		 where alerts_id = ") + intToString(dbId));
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		FraudAlertReg_filter *filter = new FraudAlertReg_filter(this);
		filter->setFilter(row["descr"].c_str(), row["config_filter_register"].c_str());
		filters[atoi(row["id"].c_str())] = filter;
	}
	if(filters.size() == 0) {
		FraudAlertReg_filter *filter = new FraudAlertReg_filter(this);
		filter->setFilter("main", dbRow["config_filter_register"].c_str());
		filters[0] = filter;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

FraudAlert_rcc_callInfo::FraudAlert_rcc_callInfo() {
	this->last_alert_info_local = 0;
	this->last_alert_info_international = 0;
	this->last_alert_info_li = 0;
}

FraudAlert_rcc_rtpStreamInfo::FraudAlert_rcc_rtpStreamInfo() {
	this->last_alert_info_local = 0;
	this->last_alert_info_international = 0;
	this->last_alert_info_li = 0;
}

FraudAlert_rcc_timePeriods::FraudAlert_rcc_timePeriods(const char *descr, 
						       int concurentCallsLimitLocal, 
						       int concurentCallsLimitInternational, 
						       int concurentCallsLimitBoth, 
						       unsigned int dbId,
						       FraudAlert_rcc *parent,
						       SqlDb *sqlDb)
 : FraudAlert_rcc_base(parent) {
	this->descr = descr;
	this->concurentCallsLimitLocal_tp = concurentCallsLimitLocal;
	this->concurentCallsLimitInternational_tp = concurentCallsLimitInternational;
	this->concurentCallsLimitBoth_tp = concurentCallsLimitBoth;
	this->dbId = dbId;
	this->parent = parent;
	this->loadTimePeriods(sqlDb);
}

void FraudAlert_rcc_timePeriods::loadTimePeriods(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query(string(
		"select *\
		 from alerts_fraud_timeperiod\
		 join cb_timeperiod on (cb_timeperiod.id = alerts_fraud_timeperiod.timeperiod_id)\
		 where alerts_fraud_id = ") + intToString(dbId));
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		timePeriods.push_back(TimePeriod(&row));
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

FraudAlert_rcc_base::FraudAlert_rcc_base(FraudAlert_rcc *parent) {
	this->parent = parent;
}

FraudAlert_rcc_base::~FraudAlert_rcc_base() {
	map<vmIP, FraudAlert_rcc_callInfo*>::iterator callsIter_by_ip;
	for(callsIter_by_ip = calls_by_ip.begin(); callsIter_by_ip != calls_by_ip.end(); ++callsIter_by_ip) {
		delete callsIter_by_ip->second;
	}
	map<string, FraudAlert_rcc_callInfo*>::iterator callsIter_by_number;
	for(callsIter_by_number = calls_by_number.begin(); callsIter_by_number != calls_by_number.end(); ++callsIter_by_number) {
		delete callsIter_by_number->second;
	}
	map<d_item<vmIP>, FraudAlert_rcc_rtpStreamInfo*>::iterator callsIter_by_rtp_stream_ip;
	for(callsIter_by_rtp_stream_ip = calls_by_rtp_stream_ip.begin(); callsIter_by_rtp_stream_ip != calls_by_rtp_stream_ip.end(); ++callsIter_by_rtp_stream_ip) {
		delete callsIter_by_rtp_stream_ip->second;
	}
	map<d_u_int32_t, FraudAlert_rcc_rtpStreamInfo*>::iterator callsIter_by_rtp_stream_id;
	for(callsIter_by_rtp_stream_id = calls_by_rtp_stream_id.begin(); callsIter_by_rtp_stream_id != calls_by_rtp_stream_id.end(); ++callsIter_by_rtp_stream_id) {
		delete callsIter_by_rtp_stream_id->second;
	}
}

void FraudAlert_rcc_base::evCall_rcc(sFraudCallInfo *callInfo, FraudAlert_rcc *alert, bool timeperiod) {
	if(parent->typeBy == FraudAlert::_typeBy_rtp_stream_ip ||
	   parent->typeBy == FraudAlert::_typeBy_rtp_stream_ip_group) {
		return;
	}
	FraudAlert_rcc_callInfo *call = NULL;
	map<vmIP, FraudAlert_rcc_callInfo*>::iterator callsIter_by_ip;
	map<string, FraudAlert_rcc_callInfo*>::iterator callsIter_by_number;
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_connectCall:
		if(this->checkTime(callInfo->at_connect)) {
			sIdAlert idAlert;
			switch(parent->typeBy) {
			case FraudAlert::_typeBy_source_ip:
				idAlert.ips = (alert->typeByIP != FraudAlert::_typeByIP_dst) ? callInfo->caller_ip : 0;
				idAlert.ipd = (alert->typeByIP == FraudAlert::_typeByIP_dst || alert->typeByIP == FraudAlert::_typeByIP_both) ? callInfo->called_ip : 0;
				callsIter_by_ip = calls_by_ip.find(callInfo->caller_ip);
				if(callsIter_by_ip != calls_by_ip.end()) {
					call = callsIter_by_ip->second;
				} else {
					call = new FILE_LINE(7004) FraudAlert_rcc_callInfo;
					calls_by_ip[callInfo->caller_ip] = call;
				}
				break;
			case FraudAlert::_typeBy_source_number:
				idAlert.number = callInfo->caller_number;
				callsIter_by_number = calls_by_number.find(callInfo->caller_number);
				if(callsIter_by_number != calls_by_number.end()) {
					call = callsIter_by_number->second;
				} else {
					call = new FILE_LINE(7005) FraudAlert_rcc_callInfo;
					calls_by_number[callInfo->caller_number] = call;
				}
				break;
			case FraudAlert::_typeBy_summary:
				call = &this->calls_summary;
				break;
			default:
				break;
			}
			if(call) {
				if(callInfo->local_called_number) {
					call->addLocal(callInfo->callid.c_str(), callInfo->at_connect);
				} else {
					call->addInternational(callInfo->callid.c_str(), callInfo->at_connect);
				}
				if(sverb.fraud) {
					syslog(LOG_NOTICE, "fraud %s / %s rcc ++ %s / %s / %zd", 
					       alert->FraudAlert::getDescr().c_str(),
					       callInfo->local_called_number ? "local" : "international",
					       parent->typeBy == FraudAlert::_typeBy_source_ip ? callInfo->caller_ip.getString().c_str() :
					       parent->typeBy == FraudAlert::_typeBy_source_number ? callInfo->caller_number.c_str() : "",
					       callInfo->callid.c_str(),
					       callInfo->local_called_number ? call->calls_local.size() : call->calls_international.size());
				}
				if(sverb.fraud_file_log && parent->verbLog) {
					fprintf(parent->verbLog, 
						"%s|%i|+|%s|%s|%s|%zd\n",
						sqlDateTimeString(time(NULL)).c_str(),
						callInfo->typeCallInfo,
						callInfo->local_called_number ? "local" : "international",
						parent->typeBy == FraudAlert::_typeBy_source_ip ? callInfo->caller_ip.getString().c_str() :
						parent->typeBy == FraudAlert::_typeBy_source_number ? callInfo->caller_number.c_str() : "",
						callInfo->callid.c_str(),
						callInfo->local_called_number ? call->calls_local.size() : call->calls_international.size());
				}
				unsigned int concurentCallsLimitLocal = timeperiod ? this->concurentCallsLimitLocal_tp : alert->concurentCallsLimitLocal;
				unsigned int concurentCallsLimitInternational = timeperiod ? this->concurentCallsLimitInternational_tp : alert->concurentCallsLimitInternational;
				unsigned int concurentCallsLimitBoth = timeperiod ? this->concurentCallsLimitBoth_tp : alert->concurentCallsLimitBoth;
				for(int pass = 0; pass < 3; pass++) {
					FraudAlert::eLocalInternational _li = pass == 0 ? FraudAlert::_li_local :
									      pass == 1 ? FraudAlert::_li_international :
											  FraudAlert::_li_booth;
					unsigned int _concurentCallsLimit = pass == 0 ? concurentCallsLimitLocal :
									    pass == 1 ? concurentCallsLimitInternational :
											concurentCallsLimitBoth;
					unsigned int _actCalls = pass == 0 ? call->calls_local.size() :
								 pass == 1 ? call->calls_international.size() :
									     call->calls_local.size() + call->calls_international.size();
					if(_concurentCallsLimit &&
					   _actCalls >= _concurentCallsLimit &&
					   callInfo->at_connect > call->last_alert_info_local + TIME_S_TO_US(1) &&
					   this->checkOkAlert(idAlert, _actCalls, callInfo->at_connect,
							      _li, alert)) {
						FraudAlertInfo_rcc *alertInfo = new FILE_LINE(7006) FraudAlertInfo_rcc(alert);
						if(parent->typeBy == FraudAlert::_typeBy_source_ip) {
							alertInfo->set_ip(_li, this->getDescr().c_str(), 
									  idAlert.ips, idAlert.ipd,
									  callInfo->country_code_caller_ip.c_str(), callInfo->country_code_called_ip.c_str(),
									  _actCalls); 
						} else if(parent->typeBy == FraudAlert::_typeBy_source_number) {
							alertInfo->set_number(_li, this->getDescr().c_str(), 
									      callInfo->caller_number, callInfo->country_code_caller_number.c_str(),
									      _actCalls); 
						} else {
							alertInfo->set_summary(_li, this->getDescr().c_str(),
									       _actCalls);
						}
						alert->evAlert(alertInfo);
						switch(_li) {
						case FraudAlert::_li_local:
							call->last_alert_info_local = callInfo->at_connect;
							break;
						case FraudAlert::_li_international:
							call->last_alert_info_international = callInfo->at_connect;
							break;
						case FraudAlert::_li_booth:
							call->last_alert_info_li = callInfo->at_connect;
							break;
						}
					}
				}
			}
		}
		break;
	case sFraudCallInfo::typeCallInfo_seenByeCall:
	case sFraudCallInfo::typeCallInfo_endCall:
		switch(parent->typeBy) {
		case FraudAlert::_typeBy_source_ip:
			callsIter_by_ip = calls_by_ip.find(callInfo->caller_ip);
			if(callsIter_by_ip != calls_by_ip.end()) {
				call = callsIter_by_ip->second;
			}
			break;
		case FraudAlert::_typeBy_source_number:
			callsIter_by_number = calls_by_number.find(callInfo->caller_number);
			if(callsIter_by_number != calls_by_number.end()) {
				call = callsIter_by_number->second;
			}
			break;
		case FraudAlert::_typeBy_summary:
			call = &this->calls_summary;
			break;
		default:
			break;
		}
		if(call) {
			if(callInfo->local_called_number) {
				call->calls_local.erase(callInfo->callid);
			} else {
				call->calls_international.erase(callInfo->callid);
			}
			if(sverb.fraud) {
				syslog(LOG_NOTICE, "fraud %s / %s rcc -- %s / %s / %zd", 
				       alert->FraudAlert::getDescr().c_str(),
				       callInfo->local_called_number ? "local" : "international",
				       parent->typeBy == FraudAlert::_typeBy_source_ip ? callInfo->caller_ip.getString().c_str() :
				       parent->typeBy == FraudAlert::_typeBy_source_number ? callInfo->caller_number.c_str() : "", 
				       callInfo->callid.c_str(),
				       callInfo->local_called_number ? call->calls_local.size() : call->calls_international.size());
			}
			if(sverb.fraud_file_log && parent->verbLog) {
				fprintf(parent->verbLog, 
					"%s|%i|-|%s|%s|%s|%zd\n",
					sqlDateTimeString(time(NULL)).c_str(),
					callInfo->typeCallInfo,
					callInfo->local_called_number ? "local" : "international",
					parent->typeBy == FraudAlert::_typeBy_source_ip ? callInfo->caller_ip.getString().c_str() :
					parent->typeBy == FraudAlert::_typeBy_source_number ? callInfo->caller_number.c_str() : "",
					callInfo->callid.c_str(),
					callInfo->local_called_number ? call->calls_local.size() : call->calls_international.size());
			}
		}
		break;
	default:
		break;
	}
}

void FraudAlert_rcc_base::evRtpStream_rcc(sFraudRtpStreamInfo *rtpStreamInfo, class FraudAlert_rcc *alert, bool timeperiod) {
	if(parent->typeBy == FraudAlert::_typeBy_source_ip ||
	   parent->typeBy == FraudAlert::_typeBy_source_number) {
		return;
	}
	vmIP rtpStreamIP[2];
	u_int32_t rtpStreamId[2] = { 0, 0 };
	switch(parent->typeBy) {
	case FraudAlert::_typeBy_rtp_stream_ip:
		rtpStreamIP[0] = rtpStreamInfo->rtp_src_ip;
		rtpStreamIP[1] = rtpStreamInfo->rtp_dst_ip;
		if(!rtpStreamIP[0].isSet() || !rtpStreamIP[1].isSet()) {
			return;
		}
		break;
	case FraudAlert::_typeBy_rtp_stream_ip_group:
		rtpStreamId[0] = rtpStreamInfo->rtp_src_ip_group;
		rtpStreamId[1] = rtpStreamInfo->rtp_dst_ip_group;
		if(!rtpStreamId[0] || !rtpStreamId[1]) {
			return;
		}
		break;
	default:
		break;
	}
	d_item<vmIP> rtp_stream_ip(min(rtpStreamIP[0], rtpStreamIP[1]), max(rtpStreamIP[0], rtpStreamIP[1]));
	d_u_int32_t rtp_stream_id(min(rtpStreamId[0], rtpStreamId[1]), max(rtpStreamId[0], rtpStreamId[1]));
	FraudAlert_rcc_rtpStreamInfo *call = NULL;
	map<d_item<vmIP>, FraudAlert_rcc_rtpStreamInfo*>::iterator callsIter_by_rtp_stream_ip;
	map<d_u_int32_t, FraudAlert_rcc_rtpStreamInfo*>::iterator callsIter_by_rtp_stream_id;
	sIdAlert idAlert;
	switch(rtpStreamInfo->typeRtpStreamInfo) {
	case sFraudRtpStreamInfo::typeRtpStreamInfo_beginStream:
		if(this->checkTime(rtpStreamInfo->at)) {
			switch(parent->typeBy) {
			case FraudAlert::_typeBy_rtp_stream_ip:
				idAlert.rtp_stream_ip = rtp_stream_ip;
				callsIter_by_rtp_stream_ip = calls_by_rtp_stream_ip.find(rtp_stream_ip);
				if(callsIter_by_rtp_stream_ip != calls_by_rtp_stream_ip.end()) {
					call = callsIter_by_rtp_stream_ip->second;
				} else {
					call = new FILE_LINE(0) FraudAlert_rcc_rtpStreamInfo;
					calls_by_rtp_stream_ip[rtp_stream_ip] = call;
				}
				break;
			case FraudAlert::_typeBy_rtp_stream_ip_group:
				idAlert.rtp_stream_id = rtp_stream_id;
				callsIter_by_rtp_stream_id = calls_by_rtp_stream_id.find(rtp_stream_id);
				if(callsIter_by_rtp_stream_id != calls_by_rtp_stream_id.end()) {
					call = callsIter_by_rtp_stream_id->second;
				} else {
					call = new FILE_LINE(0) FraudAlert_rcc_rtpStreamInfo;
					calls_by_rtp_stream_id[rtp_stream_id] = call;
				}
				break;
			default:
				break;
			}
			if(call) {
				if(rtpStreamInfo->local_called_number) {
					call->addLocal(rtpStreamInfo->callid.c_str(), 
						       rtpStreamInfo->rtp_src_ip, rtpStreamInfo->rtp_src_port, rtpStreamInfo->rtp_dst_ip, rtpStreamInfo->rtp_dst_port,
						       rtpStreamInfo->at);
				} else {
					call->addInternational(rtpStreamInfo->callid.c_str(), 
							       rtpStreamInfo->rtp_src_ip, rtpStreamInfo->rtp_src_port, rtpStreamInfo->rtp_dst_ip, rtpStreamInfo->rtp_dst_port,
							       rtpStreamInfo->at);
				}
				if(sverb.fraud) {
					syslog(LOG_NOTICE, "fraud %s / %s rcc rtp stream ++ %s : %u ->  %s : %u / %s / %zd", 
					       alert->FraudAlert::getDescr().c_str(),
					       rtpStreamInfo->local_called_number ? "local" : "international",
					       parent->typeBy == FraudAlert::_typeBy_rtp_stream_ip ?
						rtpStreamInfo->rtp_src_ip.getString().c_str() :
						fraudAlerts->getGroupName(rtpStreamInfo->rtp_src_ip_group).c_str(),
					       rtpStreamInfo->rtp_src_port.getPort(),
					       parent->typeBy == FraudAlert::_typeBy_rtp_stream_ip ?
						rtpStreamInfo->rtp_dst_ip.getString().c_str() :
						fraudAlerts->getGroupName(rtpStreamInfo->rtp_dst_ip_group).c_str(),
					       rtpStreamInfo->rtp_dst_port.getPort(),
					       rtpStreamInfo->callid.c_str(),
					       rtpStreamInfo->local_called_number ? call->calls_local.size() : call->calls_international.size());
				}
				unsigned int concurentCallsLimitLocal = timeperiod ? this->concurentCallsLimitLocal_tp : alert->concurentCallsLimitLocal;
				unsigned int concurentCallsLimitInternational = timeperiod ? this->concurentCallsLimitInternational_tp : alert->concurentCallsLimitInternational;
				unsigned int concurentCallsLimitBoth = timeperiod ? this->concurentCallsLimitBoth_tp : alert->concurentCallsLimitBoth;
				for(int pass = 0; pass < 3; pass++) {
					FraudAlert::eLocalInternational _li = pass == 0 ? FraudAlert::_li_local :
									      pass == 1 ? FraudAlert::_li_international :
											  FraudAlert::_li_booth;
					unsigned int _concurentCallsLimit = pass == 0 ? concurentCallsLimitLocal :
									    pass == 1 ? concurentCallsLimitInternational :
											concurentCallsLimitBoth;
					unsigned int _actCalls = pass == 0 ? call->calls_local.size() :
								 pass == 1 ? call->calls_international.size() :
									     call->calls_local.size() + call->calls_international.size();
					if(_concurentCallsLimit &&
					   _actCalls >= _concurentCallsLimit &&
					   rtpStreamInfo->at > call->last_alert_info_local + TIME_S_TO_US(1) &&
					   this->checkOkAlert(idAlert, _actCalls, rtpStreamInfo->at,
							      FraudAlert::_li_local, alert)) {
						FraudAlertInfo_rcc *alertInfo = new FILE_LINE(7008) FraudAlertInfo_rcc(alert);
						switch(parent->typeBy) {
						case FraudAlert::_typeBy_rtp_stream_ip:
							alertInfo->set_rtp_stream(_li, this->getDescr().c_str(), 
										  parent->typeBy, rtp_stream_ip,
										  _actCalls);
							break;
						case FraudAlert::_typeBy_rtp_stream_ip_group:
							alertInfo->set_rtp_stream(_li, this->getDescr().c_str(), 
										  parent->typeBy, rtp_stream_id,
										  _actCalls);
							break;
						default:
							break;
						}
						alert->evAlert(alertInfo);
						switch(_li) {
						case FraudAlert::_li_local:
							call->last_alert_info_local = rtpStreamInfo->at;
							break;
						case FraudAlert::_li_international:
							call->last_alert_info_international = rtpStreamInfo->at;
							break;
						case FraudAlert::_li_booth:
							call->last_alert_info_li = rtpStreamInfo->at;
							break;
						}
					}
				}
			}
		}
		break;
	case sFraudRtpStreamInfo::typeRtpStreamInfo_endStream:
		switch(parent->typeBy) {
		case FraudAlert::_typeBy_rtp_stream_ip:
			callsIter_by_rtp_stream_ip = calls_by_rtp_stream_ip.find(rtp_stream_ip);
			if(callsIter_by_rtp_stream_ip != calls_by_rtp_stream_ip.end()) {
				call = callsIter_by_rtp_stream_ip->second;
			}
			break;
		case FraudAlert::_typeBy_rtp_stream_ip_group:
			callsIter_by_rtp_stream_id = calls_by_rtp_stream_id.find(rtp_stream_id);
			if(callsIter_by_rtp_stream_id != calls_by_rtp_stream_id.end()) {
				call = callsIter_by_rtp_stream_id->second;
			}
			break;
		default:
			break;
		}
		if(call) {
			if(rtpStreamInfo->local_called_number) {
				call->removeLocal(rtpStreamInfo->callid.c_str(), 
						  rtpStreamInfo->rtp_src_ip, rtpStreamInfo->rtp_src_port, rtpStreamInfo->rtp_dst_ip, rtpStreamInfo->rtp_dst_port);
			} else {
				call->removeInternational(rtpStreamInfo->callid.c_str(), 
							  rtpStreamInfo->rtp_src_ip, rtpStreamInfo->rtp_src_port, rtpStreamInfo->rtp_dst_ip, rtpStreamInfo->rtp_dst_port);
			}
			if(sverb.fraud) {
				syslog(LOG_NOTICE, "fraud %s / %s rcc rtp stream -- %s : %u ->  %s : %u / %s / %zd", 
				       alert->FraudAlert::getDescr().c_str(),
				       rtpStreamInfo->local_called_number ? "local" : "international",
				       parent->typeBy == FraudAlert::_typeBy_rtp_stream_ip ?
					rtpStreamInfo->rtp_src_ip.getString().c_str() :
					fraudAlerts->getGroupName(rtpStreamInfo->rtp_src_ip_group).c_str(),
				       rtpStreamInfo->rtp_src_port.getPort(),
				       parent->typeBy == FraudAlert::_typeBy_rtp_stream_ip ?
					rtpStreamInfo->rtp_dst_ip.getString().c_str() :
					fraudAlerts->getGroupName(rtpStreamInfo->rtp_dst_ip_group).c_str(),
				       rtpStreamInfo->rtp_dst_port.getPort(),
				       rtpStreamInfo->callid.c_str(),
				       rtpStreamInfo->local_called_number ? call->calls_local.size() : call->calls_international.size());
			}
		}
		break;
	}
}

FraudAlert::eTypeBy FraudAlert_rcc_base::getTypeBy() { 
	return(parent->typeBy); 
}

bool FraudAlert_rcc_base::checkOkAlert(sIdAlert idAlert, size_t concurentCalls, u_int64_t at,
				       FraudAlert::eLocalInternational li,
				       FraudAlert_rcc *alert) {
	if(!alert->alertOncePerHours) {
		return(true);
	}
	map<sIdAlert, sAlertInfo> *alerts = li == FraudAlert::_li_local ?
					     &this->alerts_local :
					    li == FraudAlert::_li_international ?
					     &this->alerts_international :
					     &this->alerts_booth;
	map<sIdAlert, sAlertInfo>::iterator iter = alerts->find(idAlert);
	if(iter == alerts->end()) {
		(*alerts)[idAlert] = sAlertInfo(concurentCalls, at);
		return(true);
	} else {
		if(iter->second.at + TIME_S_TO_US(alert->alertOncePerHours * 3600) < at/* ||
		   iter->second.concurentCalls * 1.5 < concurentCalls*/) {
			(*alerts)[idAlert] = sAlertInfo(concurentCalls, at);
		} else {
			return(false);
		}
	}
	return(true);
}

FraudAlertInfo_rcc::FraudAlertInfo_rcc(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_rcc::set_ip(FraudAlert::eLocalInternational localInternational,
				const char *timeperiod_name,
				vmIP ips, vmIP ipd, const char *ips_location_code, const char *ipd_location_code,
				unsigned int concurentCalls) {
	this->localInternational = localInternational;
	if(timeperiod_name) {
		this->timeperiod_name = timeperiod_name;
	}
	this->type_by = FraudAlert::_typeBy_source_ip;
	this->ips = ips;
	this->ipd = ipd;
	this->ips_location_code = ips_location_code;
	this->ipd_location_code = ipd_location_code;
	this->concurentCalls = concurentCalls;
}

void FraudAlertInfo_rcc::set_number(FraudAlert::eLocalInternational localInternational,
				    const char *timeperiod_name,
				    string number, const char *number_location_code,
				    unsigned int concurentCalls) {
	this->localInternational = localInternational;
	if(timeperiod_name) {
		this->timeperiod_name = timeperiod_name;
	}
	this->type_by = FraudAlert::_typeBy_source_number;
	this->number = number;
	this->number_location_code = number_location_code;
	this->concurentCalls = concurentCalls;
}

void FraudAlertInfo_rcc::set_rtp_stream(FraudAlert::eLocalInternational localInternational,
					const char *timeperiod_name,
					FraudAlert::eTypeBy type_by, d_item<vmIP> rtp_stream_ip,
					unsigned int concurentCalls) {
	this->localInternational = localInternational;
	if(timeperiod_name) {
		this->timeperiod_name = timeperiod_name;
	}
	this->type_by = type_by;
	this->rtp_stream_ip = rtp_stream_ip;
	this->concurentCalls = concurentCalls;
}

void FraudAlertInfo_rcc::set_rtp_stream(FraudAlert::eLocalInternational localInternational,
					const char *timeperiod_name,
					FraudAlert::eTypeBy type_by, d_u_int32_t rtp_stream_id,
					unsigned int concurentCalls) {
	this->localInternational = localInternational;
	if(timeperiod_name) {
		this->timeperiod_name = timeperiod_name;
	}
	this->type_by = type_by;
	this->rtp_stream_id = rtp_stream_id;
	this->concurentCalls = concurentCalls;
}

void FraudAlertInfo_rcc::set_summary(FraudAlert::eLocalInternational localInternational,
				     const char *timeperiod_name,
				     unsigned int concurentCalls) {
	this->localInternational = localInternational;
	if(timeperiod_name) {
		this->timeperiod_name = timeperiod_name;
	}
	this->type_by = FraudAlert::_typeBy_summary;
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
	switch(type_by) {
	case FraudAlert::_typeBy_source_ip:
		if(ips.isSet() && ipd.isSet()) {
			json.add("ips", ips.getString());
			json.add("ipd", ipd.getString());
			if (!ips_location_code.empty()) {
				json.add("ips_location_code", ips_location_code);
				json.add("ips_country", countryCodes->getNameCountry(ips_location_code.c_str()));
				json.add("ips_continent", countryCodes->getNameContinent(ips_location_code.c_str()));
			}
			if (!ipd_location_code.empty()) {
				json.add("ipd_location_code", ipd_location_code);
				json.add("ipd_country", countryCodes->getNameCountry(ipd_location_code.c_str()));
				json.add("ipd_continent", countryCodes->getNameContinent(ipd_location_code.c_str()));
			}
		} else {
			vmIP ip = ipd.isSet() ? ipd : ips;
			string ip_location_code = ipd.isSet() ? ipd_location_code : ips_location_code;
			json.add("ip", ip.getString());
			json.add("ip_location_code", ip_location_code);
			json.add("ip_country", countryCodes->getNameCountry(ip_location_code.c_str()));
			json.add("ip_continent", countryCodes->getNameContinent(ip_location_code.c_str()));
		}
		break;
	case FraudAlert::_typeBy_source_number:
		json.add("number", number);
		json.add("number_location_code", number_location_code);
		json.add("number_country", countryCodes->getNameCountry(number_location_code.c_str()));
		json.add("number_continent", countryCodes->getNameContinent(number_location_code.c_str()));
		break;
	case FraudAlert::_typeBy_rtp_stream_ip:
		json.add("rtp_stream_ip1", rtp_stream_ip.items[0].getString());
		json.add("rtp_stream_ip2", rtp_stream_ip.items[1].getString());
		break;
	case FraudAlert::_typeBy_rtp_stream_ip_group:
		json.add("rtp_stream_ip_group1", rtp_stream_id[0]);
		json.add("rtp_stream_ip_group2", rtp_stream_id[1]);
		break;
	default:
		break;
	}
	json.add("concurent_calls", concurentCalls);
	return(json.getJson());
}

void FraudAlert_rcc::addFraudDef(SqlDb_row *row, SqlDb *sqlDb) {
	timePeriods.push_back(FraudAlert_rcc_timePeriods(
				(*row)["descr"].c_str(),
				atoi((*row)["concurent_calls_limit_local"].c_str()),
				atoi((*row)["concurent_calls_limit_international"].c_str()),
				atoi((*row)["concurent_calls_limit"].c_str()),
				atol((*row)["id"].c_str()),
				this,
				sqlDb));
}

FraudAlert_rcc::FraudAlert_rcc(unsigned int dbId)
 : FraudAlert(_rcc, dbId), FraudAlert_rcc_base(this) {
}

void FraudAlert_rcc::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type != INVITE ||
	   !this->okFilter(callInfo) ||
	   !this->okDayHour(callInfo)) {
		return;
	}
	this->evCall_rcc(callInfo, this, false);
	for(size_t i = 0; i < timePeriods.size(); i++) {
		timePeriods[i].evCall_rcc(callInfo, this, true);
	}
}

void FraudAlert_rcc::evRtpStream(sFraudRtpStreamInfo *rtpStreamInfo) {
	if(!this->okFilter(rtpStreamInfo) ||
	   !this->okDayHour(rtpStreamInfo)) {
		return;
	}
	this->evRtpStream_rcc(rtpStreamInfo, this, false);
	for(size_t i = 0; i < timePeriods.size(); i++) {
		timePeriods[i].evRtpStream_rcc(rtpStreamInfo, this, true);
	}
}

FraudAlertInfo_chc::FraudAlertInfo_chc(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_chc::set(const char *number,
			     const char *domain,
			     FraudAlert::eTypeLocation typeLocation,
			     vmIP ip,
			     const char *location_code,
			     vmIP ip_old,
			     const char *location_code_old,
			     vmIP ip_dst) {
	this->number = number;
	if(domain) this->domain = domain;
	this->typeLocation = typeLocation;
	this->ip = ip;
	this->location_code = location_code;
	this->ip_old = ip_old;
	this->location_code_old = location_code_old;
	this->ip_dst = ip_dst;
}

string FraudAlertInfo_chc::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("number", number);
	json.add("domain", domain);
	json.add("type_location", 
		 typeLocation == FraudAlert::_typeLocation_country ? 
		  "country" : 
		  "continent");
	json.add("ip", ip.getString());
	json.add("location_code", location_code);
	json.add("location_name",
		 typeLocation == FraudAlert::_typeLocation_country ?
		  countryCodes->getNameCountry(location_code.c_str()) :
		  countryCodes->getNameContinent(location_code.c_str()));
	json.add("ip_old", ip_old.getString());
	json.add("location_code_old", location_code_old);
	json.add("location_name_old",
		 typeLocation == FraudAlert::_typeLocation_country ?
		  countryCodes->getNameCountry(location_code_old.c_str()) :
		  countryCodes->getNameContinent(location_code_old.c_str()));
	if(ip_dst.isSet()) {
		json.add("ip_dst", ip_dst.getString());
	}
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
		if(callInfo->caller_ip.isLocalIP() ||
		   (this->changeLocationOk.size() &&
		    (countryCodes->isLocationIn(callInfo->country_code_caller_ip.c_str(), &this->changeLocationOk) ||
		     countryCodes->isLocationIn(callInfo->continent_code_caller_ip.c_str(), &this->changeLocationOk, true)))) {
			return;
		}
		bool diffCountry = false;
		bool diffContinent = false;
		vmIP oldIp;
		string oldCountry;
		string oldContinent;
		if(!cacheNumber_location->checkNumber(callInfo->caller_number.c_str(), callInfo->called_ip,
						      useDomain ? callInfo->caller_domain.c_str() : NULL,
						      callInfo->caller_ip, this->onlyConnected ? callInfo->at_connect : callInfo->at_begin,
						      &diffCountry, &diffContinent, &oldIp, &oldCountry, &oldContinent,
						      callInfo->country_code_caller_ip.c_str(), callInfo->continent_code_caller_ip.c_str())) {
			if(this->typeChangeLocation == _typeLocation_country && diffCountry) {
				FraudAlertInfo_chc *alertInfo = new FILE_LINE(7009) FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       useDomain ? callInfo->caller_domain.c_str() : NULL,
					       _typeLocation_country,
					       callInfo->caller_ip,
					       callInfo->country_code_caller_ip.c_str(),
					       oldIp,
					       oldCountry.c_str(),
					       0);
				this->evAlert(alertInfo);
			}
			if(this->typeChangeLocation == _typeLocation_continent && diffContinent) {
				FraudAlertInfo_chc *alertInfo = new FILE_LINE(7010) FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       useDomain ? callInfo->caller_domain.c_str() : NULL,
					       _typeLocation_continent,
					       callInfo->caller_ip,
					       callInfo->continent_code_caller_ip.c_str(),
					       oldIp,
					       oldContinent.c_str(),
					       0);
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
		if(callInfo->caller_ip.isLocalIP() ||
		   (this->changeLocationOk.size() &&
		    (countryCodes->isLocationIn(callInfo->country_code_caller_ip.c_str(), &this->changeLocationOk) ||
		     countryCodes->isLocationIn(callInfo->continent_code_caller_ip.c_str(), &this->changeLocationOk, true)))) {
			return;
		}
		bool diffCountry = false;
		bool diffContinent = false;
		vmIP oldIp;
		string oldCountry;
		string oldContinent;
		if(!cacheNumber_location->checkNumber(callInfo->caller_number.c_str(), callInfo->called_ip, 
						      useDomain ? callInfo->caller_domain.c_str() : NULL,
						      callInfo->caller_ip, callInfo->at_connect,
						      &diffCountry, &diffContinent, &oldIp, &oldCountry, &oldContinent,
						      callInfo->country_code_caller_ip.c_str(), callInfo->continent_code_caller_ip.c_str())) {
			if(this->typeChangeLocation == _typeLocation_country && diffCountry) {
				FraudAlertInfo_chc *alertInfo = new FILE_LINE(7011) FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       useDomain ? callInfo->caller_domain.c_str() : NULL,
					       _typeLocation_country,
					       callInfo->caller_ip,
					       callInfo->country_code_caller_ip.c_str(),
					       oldIp,
					       oldCountry.c_str(),
					       callInfo->called_ip);
				this->evAlert(alertInfo);
			}
			if(this->typeChangeLocation == _typeLocation_continent && diffContinent) {
				FraudAlertInfo_chc *alertInfo = new FILE_LINE(7012) FraudAlertInfo_chc(this);
				alertInfo->set(callInfo->caller_number.c_str(),
					       useDomain ? callInfo->caller_domain.c_str() : NULL,
					       _typeLocation_continent,
					       callInfo->caller_ip,
					       callInfo->continent_code_caller_ip.c_str(),
					       oldIp,
					       oldContinent.c_str(),
					       callInfo->called_ip);
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
				      callInfo->country_code_called_number.c_str(), this->onlyConnected ? callInfo->at_connect : callInfo->at_begin)) {
			FraudAlertInfo_d *alertInfo = new FILE_LINE(7013) FraudAlertInfo_d(this);
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
		if(iter->second.at + TIME_S_TO_US(this->alertOncePerHours * 3600) < at ||
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

void FraudAlertInfo_spc::set(vmIP ip, 
			     unsigned int count,
			     unsigned int count_invite,
			     unsigned int count_message,
			     unsigned int count_register) {
	this->ip = ip;
	this->count = count;
	this->count_invite = count_invite;
	this->count_message = count_message;
	this->count_register = count_register;
}

string FraudAlertInfo_spc::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("ip", ip.getString());
	json.add("count", count);
	json.add("count_invite", count_invite);
	json.add("count_message", count_message);
	json.add("count_register", count_register);
	string country_code = countryDetect ?
			       countryDetect->getCountryByIP(ip) :
			       geoIP_country->getCountry(ip);
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
		map<vmIP, sCounts>::iterator iter = count.find(eventInfo->src_ip);
		if(iter == count.end()) {
			count[eventInfo->src_ip].count = 1;
		} else {
			++count[eventInfo->src_ip].count;
		}
		switch(eventInfo->sip_method) {
		case INVITE:
			++count[eventInfo->src_ip].count_invite;
			break;
		case MESSAGE:
			++count[eventInfo->src_ip].count_message;
			break;
		case REGISTER:
			++count[eventInfo->src_ip].count_register;
			break;
		}
	}
	if(!start_interval) {
		start_interval = eventInfo->at;
	} else if(eventInfo->at - start_interval > TIME_S_TO_US(intervalLength)) {
		map<vmIP, sCounts>::iterator iter;
		for(iter = count.begin(); iter != count.end(); iter++) {
			if(iter->second.count >= intervalLimit &&
			   this->checkOkAlert(iter->first, iter->second.count, eventInfo->at)) {
				FraudAlertInfo_spc *alertInfo = new FILE_LINE(7014) FraudAlertInfo_spc(this);
				alertInfo->set(iter->first,
					       iter->second.count,
					       iter->second.count_invite,
					       iter->second.count_message,
					       iter->second.count_register);
				this->evAlert(alertInfo);
			}
		}
		count.clear();
		start_interval = eventInfo->at;
	}
}

bool FraudAlert_spc::checkOkAlert(vmIP ip, u_int64_t count, u_int64_t at) {
	if(!this->alertOncePerHours) {
		return(true);
	}
	map<vmIP, sAlertInfo>::iterator iter = alerts.find(ip);
	if(iter == alerts.end()) {
		alerts[ip] = sAlertInfo(count, at);
		return(true);
	} else {
		if(iter->second.at + TIME_S_TO_US(this->alertOncePerHours * 3600) < at/* ||
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

FraudAlert_rc::~FraudAlert_rc() {
	while(this->dumpers.size()) {
		map<vmIP, PcapDumper*>::iterator iter_dumper = this->dumpers.begin();
		if(iter_dumper->second && iter_dumper->second != (PcapDumper*)1) {
			delete iter_dumper->second;
		}
		this->dumpers.erase(iter_dumper);
	}
}

void FraudAlert_rc::evEvent(sFraudEventInfo *eventInfo) {
	vmIP ip = typeBy == _typeBy_source_ip ? eventInfo->src_ip : eventInfo->dst_ip;
	if((withResponse ?
	     eventInfo->typeEventInfo == sFraudEventInfo::typeEventInfo_registerResponse :
	     eventInfo->typeEventInfo == sFraudEventInfo::typeEventInfo_register) &&
	   this->okFilter(eventInfo) &&
	   this->okDayHour(eventInfo)) {
		map<vmIP, u_int64_t>::iterator iter = count.find(ip);
		if(iter == count.end()) {
			count[ip] = 1;
		} else {
			++count[ip];
		}
	}
	bool enable_store_pcap = this->storePcaps;
	bool enable_dump = eventInfo->block_store != NULL;
	if(!start_interval) {
		start_interval = eventInfo->at;
	} else if(eventInfo->at - start_interval > TIME_S_TO_US(intervalLength)) {
		map<vmIP, u_int64_t>::iterator iter;
		for(iter = count.begin(); iter != count.end(); iter++) {
			if(iter->second >= intervalLimit) {
				if(this->checkOkAlert(iter->first, iter->second, eventInfo->at)) {
					FraudAlertInfo_spc *alertInfo = new FILE_LINE(7015) FraudAlertInfo_spc(this);
					alertInfo->set(iter->first,
						       iter->second);
					this->evAlert(alertInfo);
				}
				if(enable_store_pcap) {
					map<vmIP, PcapDumper*>::iterator iter_dumper = this->dumpers.find(iter->first);
					if(iter_dumper == this->dumpers.end()) {
						this->dumpers[iter->first] = (PcapDumper*)1;
					}
				}
			} else if(enable_store_pcap) {
				map<vmIP, PcapDumper*>::iterator iter_dumper = this->dumpers.find(iter->first);
				if(iter_dumper != this->dumpers.end()) {
					if(iter_dumper->second && iter_dumper->second != (PcapDumper*)1) {
						delete iter_dumper->second;
					}
					this->dumpers.erase(iter_dumper);
				}
			}
		}
		count.clear();
		start_interval = eventInfo->at;
	}
	if(enable_store_pcap && enable_dump) {
		map<vmIP, PcapDumper*>::iterator iter_dumper = this->dumpers.find(ip);
		if(iter_dumper != this->dumpers.end()) {
			if(iter_dumper->second == (PcapDumper*)1) {
				PcapDumper *dumper = new FILE_LINE(7016) PcapDumper(PcapDumper::na, NULL);
				dumper->setEnableAsyncWrite(false);
				dumper->setTypeCompress(FileZipHandler::gzip);
				if(dumper->open(tsf_na, getDumpName(ip, eventInfo->at).c_str(), eventInfo->dlt)) {
					iter_dumper->second = dumper;
				} else {
					iter_dumper->second = NULL;
				}
			}
			if(iter_dumper->second) {
				#if __GNUC__ >= 8
				#pragma GCC diagnostic push
				#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
				#endif
				iter_dumper->second->dump(&(*eventInfo->block_store)[eventInfo->block_store_index].header->header_std,
							  (*eventInfo->block_store)[eventInfo->block_store_index].packet,
							  eventInfo->dlt);
				#if __GNUC__ >= 8
				#pragma GCC diagnostic pop
				#endif
			}
		}
	}
}

void FraudAlert_rc::loadAlertVirt(SqlDb */*sqlDb*/) {
	withResponse = atoi(dbRow["fraud_register_only_with_response"].c_str());
}

bool FraudAlert_rc::checkOkAlert(vmIP ip, u_int64_t count, u_int64_t at) {
	if(!this->alertOncePerHours) {
		return(true);
	}
	map<vmIP, sAlertInfo>::iterator iter = alerts.find(ip);
	if(iter == alerts.end()) {
		alerts[ip] = sAlertInfo(count, at);
		return(true);
	} else {
		if(iter->second.at + TIME_S_TO_US(this->alertOncePerHours * 3600) < at/* ||
		   iter->second.count * 1.5 < count*/) {
			alerts[ip] = sAlertInfo(count, at);
		} else {
			return(false);
		}
	}
	return(true);
}

string FraudAlert_rc::getDumpName(vmIP ip, u_int64_t at) {
	string path = storePcapsToPaths.empty() ? getStorePcaps() : storePcapsToPaths;
	string name = this->descr + '_' + ip.getString() + '_' + sqlDateTimeString(TIME_US_TO_S(at)) + ".pcap";
	prepare_string_to_filename(&name);
	string path_name = path + '/' + name;
	return(path_name);
}

FraudAlertInfo_seq::FraudAlertInfo_seq(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_seq::set(vmIP ips, vmIP ipd,  
			     const char *number,
			     unsigned int count,
			     const char *country_code_ips,
			     const char *country_code_ipd,
			     const char *country_code_number) {
	this->ips = ips;
	this->ipd = ipd;
	this->number = number ? number : "";
	this->count = count;
	this->country_code_number = country_code_number ? country_code_number : "";
	this->country_code_ips = country_code_ips ? country_code_ips : "";
	this->country_code_ipd = country_code_ipd ? country_code_ipd : "";
}

string FraudAlertInfo_seq::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	if(ips.isSet() && ipd.isSet()) {
		json.add("ips", ips.getString());
		json.add("ipd", ipd.getString());
		if(!country_code_ips.empty()) {
			json.add("country_code_ips", country_code_ips);
			json.add("country_name_ips", countryCodes->getNameCountry(country_code_ips.c_str()));
		}
		if(!country_code_ipd.empty()) {
			json.add("country_code_ipd", country_code_ipd);
			json.add("country_name_ipd", countryCodes->getNameCountry(country_code_ipd.c_str()));
		}
	} else {
		vmIP ip = ipd.isSet() ? ipd : ips;
		string country_code_ip = ipd.isSet() ? country_code_ipd : country_code_ips;
		json.add("ip", ip.getString());
		if(!country_code_ip.empty()) {
			json.add("country_code_ip", country_code_ip);
			json.add("country_name_ip", countryCodes->getNameCountry(country_code_ip.c_str()));
		}
	}
	json.add("number", number);
	if(!country_code_number.empty()) {
		json.add("country_code_number", country_code_number);
		json.add("country_name_number", countryCodes->getNameCountry(country_code_number.c_str()));
	}
	json.add("count", count);
	return(json.getJson());
}

FraudAlert_seq::FraudAlert_seq(unsigned int dbId)
 : FraudAlert(_seq, dbId) {
	start_interval = 0;
}

void FraudAlert_seq::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type != REGISTER &&
	   (callInfo->typeCallInfo == sFraudCallInfo::typeCallInfo_connectCall ||
	    (includeSessionCanceled && callInfo->typeCallInfo == sFraudCallInfo::typeCallInfo_sessionCanceledCall)) &&
	   (!filterInternational || !callInfo->local_called_number) &&
	   this->okFilter(callInfo) &&
	   this->okDayHour(callInfo)) {
		sIpNumber ipNumber(typeByIP != _typeByIP_dst ? callInfo->caller_ip : 0,
				   typeByIP == _typeByIP_dst || typeByIP == _typeByIP_both ? callInfo->called_ip : 0,
				   callInfo->called_number.c_str());
		map<sIpNumber, u_int64_t>::iterator iter = count.find(ipNumber);
		if(iter == count.end()) {
			count[ipNumber] = 1;
		} else {
			++count[ipNumber];
		}
	}
	if(!start_interval) {
		start_interval = callInfo->at_last;
	} else if(callInfo->at_last - start_interval > TIME_S_TO_US(intervalLength)) {
		map<sIpNumber, u_int64_t>::iterator iter;
		for(iter = count.begin(); iter != count.end(); iter++) {
			if(iter->second >= intervalLimit &&
			   this->checkOkAlert(iter->first, iter->second, callInfo->at_last)) {
				FraudAlertInfo_seq *alertInfo = new FILE_LINE(7017) FraudAlertInfo_seq(this);
				alertInfo->set(iter->first.ips,
					       iter->first.ipd,
					       iter->first.number.c_str(),
					       iter->second,
					       callInfo->country_code_caller_ip.c_str(),
					       callInfo->country_code_called_ip.c_str(),
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
		if(iter->second.at + TIME_S_TO_US(this->alertOncePerHours * 3600) < at/* ||
		   iter->second.count * 1.5 < count*/) {
			alerts[ipNumber] = sAlertInfo(count, at);
		} else {
			return(false);
		}
	}
	return(true);
}

FraudAlertInfo_reg::FraudAlertInfo_reg(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

void FraudAlertInfo_reg::set(const char *filter_descr,
			     unsigned int count, map<sFraudRegisterInfo_id, sFraudRegisterInfo_data> *reg_map) {
	this->filter_descr = filter_descr;
	this->count = count;
	this->reg_map = reg_map;
}

string FraudAlertInfo_reg::getJson() {
	JsonExport json;
	this->setAlertJsonBase(&json);
	json.add("filter_descr", filter_descr);
	json.add("count", count);
	JsonExport *incidents = json.addArray("incidents");
	map<sFraudRegisterInfo_id, sFraudRegisterInfo_data>::iterator iter;
	for(iter = reg_map->begin(); iter != reg_map->end(); iter++) {
		JsonExport *incident = incidents->addObject("");
		incident->add("sipcallerip", iter->first.sipcallerip.getString());
		incident->add("sipcalledip", iter->first.sipcalledip.getString());
		incident->add("to_num", iter->first.to_num);
		incident->add("to_domain", iter->first.to_domain);
		incident->add("contact_num", iter->second.contact_num);
		incident->add("contact_domain", iter->second.contact_domain);
		incident->add("digestusername", iter->first.digest_username);
		incident->add("from_num", iter->second.from_num);
		incident->add("from_name", iter->second.from_name);
		incident->add("from_domain", iter->second.from_domain);
		incident->add("digestrealm", iter->second.digest_realm);
		incident->add("ua", iter->second.ua);
		incident->add("state", iter->second.state);
		incident->add("prev_state", iter->second.prev_state);
		incident->add("at", sqlDateTimeString(TIME_US_TO_S(iter->second.at)));
		incident->add("prev_state_at", sqlDateTimeString(TIME_US_TO_S(iter->second.prev_state_at)));
		incident->add("time_from_prev_state", iter->second.time_from_prev_state);
	}
	return(json.getJson());
}

FraudAlert_reg_ua::FraudAlert_reg_ua(unsigned int dbId)
 : FraudAlertReg(_reg_ua, dbId) {
}

bool FraudAlert_reg_ua::okFilter(sFraudRegisterInfo *registerInfo) {
	return(checkUA(registerInfo->ua.c_str()));
}

FraudAlert_reg_short::FraudAlert_reg_short(unsigned int dbId)
 : FraudAlertReg(_reg_short, dbId) {
}

bool FraudAlert_reg_short::okFilter(sFraudRegisterInfo *registerInfo) {
	return(checkRegisterTimeSecLe(registerInfo));
}

FraudAlert_reg_expire::FraudAlert_reg_expire(unsigned int dbId)
 : FraudAlertReg(_reg_expire, dbId) {
}

bool FraudAlert_reg_expire::okFilter(sFraudRegisterInfo *registerInfo) {
	return(registerInfo->state == rs_Expired);
}

FraudAlertInfo_ccd::FraudAlertInfo_ccd(FraudAlert *alert) 
 : FraudAlertInfo(alert) {
}

string FraudAlertInfo_ccd::getJson() {
	JsonExport json;
	json.add("time", sqlDateTimeString(time));
	json.add("count", count);
	json.add("avgFrom", sqlDateTimeString(avgFrom));
	json.add("avgTo", sqlDateTimeString(avgTo));
	json.add("avg", avg);
	return(json.getJson());
}

FraudAlert_ccd::FraudAlert_ccd(unsigned int dbId)
: FraudAlert(_seq, dbId) {
	count_max = 0;
	_sync_calls = 0;
}

void FraudAlert_ccd::evCall(sFraudCallInfo *callInfo) {
	if(callInfo->call_type != INVITE ||
	   !this->okFilter(callInfo) ||
	   !this->okDayHour(callInfo)) {
		return;
	}
	lock_calls();
	switch(callInfo->typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_connectCall:
		calls[callInfo->callid] = callInfo->at_connect;
		break;
	case sFraudCallInfo::typeCallInfo_seenByeCall:
	case sFraudCallInfo::typeCallInfo_endCall:
		calls.erase(callInfo->callid);
		break;
	default:
		break;
	}
	int count = calls.size();
	if(count > count_max) {
		count_max = count;
	}
	unlock_calls();
}

void FraudAlert_ccd::evTimer(u_int32_t time_s) {
	lock_calls();
	int count = count_max;
	count_max = calls.size();
	unlock_calls();
	int sum = 0;
	if((int)queue.size() >= check_interval_minutes) {
		for(unsigned i = 0; i < queue.size(); i++) {
			sum += queue[i].count;
		}
		int avg = sum / queue.size();
		if(count < avg &&
		   (!ignore_if_cc_lt || avg >= ignore_if_cc_lt)) {
			int diff = avg - count;
			double diff_perc = ((double)diff / avg * 100 * 10) / 10;
			unsigned count_cond = 0;
			unsigned count_cond_ok = 0;
			if(perc_drop_limit > 0) {
				++count_cond;
				if(diff_perc >= perc_drop_limit) {
					++count_cond_ok;
				}
			}
			if(abs_drop_limit > 0) {
				++count_cond;
				if(diff >= abs_drop_limit) {
					++count_cond_ok;
				}
			}
			if(count_cond_ok > 0 && (drop_limit_cond != _cond12_and || count_cond_ok == count_cond)) {
				FraudAlertInfo_ccd *alertInfo = new FILE_LINE(0) FraudAlertInfo_ccd(this);
				alertInfo->time = time_s;
				alertInfo->count = count;
				alertInfo->avgFrom = queue[0].time_s;
				alertInfo->avgTo = queue[queue.size() - 1].time_s;
				alertInfo->avg = avg;
				evAlert(alertInfo);
			}
		}
	}
	sTimeCount timeCount;
	timeCount.time_s = time_s;
	timeCount.count = count;
	queue.push_back(timeCount);
	while((int)queue.size() > check_interval_minutes) {
		queue.pop_front();
	}
}

void FraudAlert_ccd::loadAlertVirt(SqlDb *sqlDb) {
	check_interval_minutes = atoi(dbRow["ccd_check_interval_minutes"].c_str());
	perc_drop_limit = atoi(dbRow["ccd_perc_drop_limit"].c_str());
	abs_drop_limit = atoi(dbRow["ccd_abs_drop_limit"].c_str());
	drop_limit_cond = dbRow["ccd_drop_limit_cond"] == "and" ? _cond12_and : _cond12_or;
	ignore_if_cc_lt = atoi(dbRow["ccd_ignore_if_cc_lt"].c_str());
}


FraudAlerts::FraudAlerts() {
	threadPopCallInfo = 0;
	runPopCallInfoThread = false;
	termPopCallInfoThread = false;
	useUserRestriction = false;
	useUserRestriction_custom_headers = false;
	_sync_alerts = 0;
	initPopCallInfoThread();
	lastTimeCallsIsFull = 0;
	lastTimeRtpStreamsIsFull = 0;
	lastTimeEventsIsFull = 0;
	lastTimeRegistersIsFull = 0;
	maxLengthAsyncQueue = 100000;
	timer_thread = 0;
	timer_thread_terminating = false;
	timer_thread_last_time_us = 0;
	timer_thread_last_time_s = 0;
	timer_thread_last_time_m = 0;
}

FraudAlerts::~FraudAlerts() {
	stopTimerThread();
	clear();
}

void FraudAlerts::loadAlerts(bool lock, SqlDb *sqlDb) {
	useUserRestriction = false;
	useUserRestriction_custom_headers = false;
	if(lock) lock_alerts();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	this->gui_timezone = ::getGuiTimezone(sqlDb);
	bool existsColumnSelectSensors = sqlDb->existsColumn("alerts", "select_sensors");
	sqlDb->query(string("select id, alert_type, descr") + 
		     (existsColumnSelectSensors ? ", select_sensors" : "") + 
		     "\
		      from alerts\
		      where " + whereCondFraudAlerts());
	SqlDb_rows alert_rows;
	sqlDb->fetchRows(&alert_rows);
	SqlDb_row alert_row;
	while((alert_row = alert_rows.fetchRow())) {
		if(!selectSensorsContainSensorId(alert_row["select_sensors"])) {
			continue;
		}
		if(fraudDebug) {
			syslog(LOG_NOTICE, "load fraud alert %s", alert_row["descr"].c_str());
		}
		FraudAlert *alert = NULL;
		unsigned int dbId = atol(alert_row["id"].c_str());
		switch(atoi(alert_row["alert_type"].c_str())) {
		case FraudAlert::_rcc:
			alert = new FILE_LINE(7018) FraudAlert_rcc(dbId);
			break;
		case FraudAlert::_chc:
			alert = new FILE_LINE(7019) FraudAlert_chc(dbId);
			break;
		case FraudAlert::_chcr:
			alert = new FILE_LINE(7020) FraudAlert_chcr(dbId);
			break;
		case FraudAlert::_d:
			alert = new FILE_LINE(7021) FraudAlert_d(dbId);
			break;
		case FraudAlert::_spc:
			alert = new FILE_LINE(7022) FraudAlert_spc(dbId);
			break;
		case FraudAlert::_rc:
			alert = new FILE_LINE(7023) FraudAlert_rc(dbId);
			break;
		case FraudAlert::_seq:
			alert = new FILE_LINE(7024) FraudAlert_seq(dbId);
			break;
		case FraudAlert::_reg_ua:
			alert = new FILE_LINE(7025) FraudAlert_reg_ua(dbId);
			break;
		case FraudAlert::_reg_short:
			alert = new FILE_LINE(7026) FraudAlert_reg_short(dbId);
			break;
		case FraudAlert::_reg_expire:
			alert = new FILE_LINE(7027) FraudAlert_reg_expire(dbId);
			break;
		case FraudAlert::_ccd:
			alert = new FILE_LINE(0) FraudAlert_ccd(dbId);
			break;
		}
		bool _useUserRestriction = false;
		bool _useUserRestriction_custom_headers = false;
		if(alert && alert->loadAlert(&_useUserRestriction, &_useUserRestriction_custom_headers, sqlDb)) {
			if(sverb.fraud_file_log  && alert->supportVerbLog()) {
				alert->openVerbLog();
			}
			alerts.push_back(alert);
			if(_useUserRestriction) {
				useUserRestriction = true;
			}
			if(_useUserRestriction_custom_headers) {
				useUserRestriction_custom_headers = true;
			}
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	if(lock) unlock_alerts();
	craeteTimerThread(lock, true);
}

void FraudAlerts::loadData(bool lock, SqlDb *sqlDb) {
	if(lock) lock_alerts();
	this->groupsIP.load(sqlDb);
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
	if(!checkIfCallQueueIsFull()) {
		sFraudCallInfo *callInfo = new FILE_LINE(0) sFraudCallInfo;
		this->completeCallInfo(callInfo, call, sFraudCallInfo::typeCallInfo_beginCall, at);
		pushToCallQueue(callInfo);
	}
}

void FraudAlerts::connectCall(Call *call, u_int64_t at) {
	if(!checkIfCallQueueIsFull()) {
		sFraudCallInfo *callInfo = new FILE_LINE(0) sFraudCallInfo;
		this->completeCallInfo(callInfo, call, sFraudCallInfo::typeCallInfo_connectCall, at);
		pushToCallQueue(callInfo);
	}
}

void FraudAlerts::sessionCanceledCall(Call *call, u_int64_t at) {
	if(!checkIfCallQueueIsFull()) {
		sFraudCallInfo *callInfo = new FILE_LINE(0) sFraudCallInfo;
		this->completeCallInfo(callInfo, call, sFraudCallInfo::typeCallInfo_sessionCanceledCall, at);
		pushToCallQueue(callInfo);
	}
}

void FraudAlerts::seenByeCall(Call *call, u_int64_t at) {
	if(!checkIfCallQueueIsFull()) {
		sFraudCallInfo *callInfo = new FILE_LINE(0) sFraudCallInfo;
		this->completeCallInfo(callInfo, call, sFraudCallInfo::typeCallInfo_seenByeCall, at);
		pushToCallQueue(callInfo);
	}
}

void FraudAlerts::endCall(Call *call, u_int64_t at) {
	if(!checkIfCallQueueIsFull()) {
		sFraudCallInfo *callInfo = new FILE_LINE(0) sFraudCallInfo;
		this->completeCallInfo(callInfo, call, sFraudCallInfo::typeCallInfo_endCall, at);
		pushToCallQueue(callInfo);
	}
}

void FraudAlerts::beginRtpStream(vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
				 Call *call, u_int64_t at) {
	if(!checkIfRtpStreamQueueIsFull()) {
		sFraudRtpStreamInfo *rtpStreamInfo = new FILE_LINE(0) sFraudRtpStreamInfo;
		rtpStreamInfo->typeRtpStreamInfo = sFraudRtpStreamInfo::typeRtpStreamInfo_beginStream;
		rtpStreamInfo->rtp_src_ip = src_ip;
		rtpStreamInfo->rtp_src_port = src_port;
		rtpStreamInfo->rtp_dst_ip = dst_ip;
		rtpStreamInfo->rtp_dst_port = dst_port;
		rtpStreamInfo->at = at;
		this->completeRtpStreamInfo(rtpStreamInfo, call);
		pushToRtpStreamQueue(rtpStreamInfo);
	}
}

void FraudAlerts::endRtpStream(vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
			       Call *call, u_int64_t at) {
	if(!checkIfRtpStreamQueueIsFull()) {
		sFraudRtpStreamInfo *rtpStreamInfo = new FILE_LINE(0) sFraudRtpStreamInfo;
		rtpStreamInfo->typeRtpStreamInfo = sFraudRtpStreamInfo::typeRtpStreamInfo_endStream;
		rtpStreamInfo->rtp_src_ip = src_ip;
		rtpStreamInfo->rtp_src_port = src_port;
		rtpStreamInfo->rtp_dst_ip = dst_ip;
		rtpStreamInfo->rtp_dst_port = dst_port;
		rtpStreamInfo->at = at;
		this->completeRtpStreamInfo(rtpStreamInfo, call);
		pushToRtpStreamQueue(rtpStreamInfo);
	}
}

void FraudAlerts::evSipPacket(vmIP ip, unsigned sip_method, u_int64_t at, const char *ua, int ua_len) {
	if(!checkIfEventQueueIsFull()) {
		sFraudEventInfo *eventInfo = new FILE_LINE(0) sFraudEventInfo;
		eventInfo->typeEventInfo = sFraudEventInfo::typeEventInfo_sipPacket;
		eventInfo->src_ip = ip;
		eventInfo->sip_method = sip_method;
		eventInfo->at = at;
		if(ua && ua_len) {
			eventInfo->ua = ua_len == -1 ? ua : string(ua, ua_len);
		}
		pushToEventQueue(eventInfo);
	}
}

void FraudAlerts::evRegister(vmIP src_ip, vmIP dst_ip, u_int64_t at, const char *ua, int ua_len,
			     pcap_block_store *block_store, u_int32_t block_store_index, u_int16_t dlt) {
	if(!checkIfEventQueueIsFull()) {
		bool lock_packet = opt_enable_fraud_store_pcaps && block_store;
		if(lock_packet) {
			block_store->lock_packet(block_store_index, 0);
		}
		sFraudEventInfo *eventInfo = new FILE_LINE(0) sFraudEventInfo;
		eventInfo->typeEventInfo = sFraudEventInfo::typeEventInfo_register;
		eventInfo->src_ip = src_ip;
		eventInfo->src_ip = dst_ip;
		eventInfo->at = at;
		eventInfo->block_store = block_store;
		eventInfo->block_store_index = block_store_index;
		eventInfo->dlt = dlt;
		eventInfo->lock_packet = lock_packet;
		if(ua && ua_len) {
			eventInfo->ua = ua_len == -1 ? ua : string(ua, ua_len);
		}
		pushToEventQueue(eventInfo);
	}
}

void FraudAlerts::evRegisterResponse(vmIP src_ip, vmIP dst_ip, u_int64_t at, const char *ua, int ua_len) {
	if(!checkIfEventQueueIsFull()) {
		sFraudEventInfo *eventInfo = new FILE_LINE(0) sFraudEventInfo;
		eventInfo->typeEventInfo = sFraudEventInfo::typeEventInfo_registerResponse;
		eventInfo->src_ip = src_ip;
		eventInfo->dst_ip = dst_ip;
		eventInfo->at = at;
		if(ua && ua_len) {
			eventInfo->ua = ua_len == -1 ? ua : string(ua, ua_len);
		}
		pushToEventQueue(eventInfo);
	}
}

void FraudAlerts::evRegister(Call *call, eRegisterState state, eRegisterState prev_state, u_int64_t prev_state_at) {
	if(!checkIfRegisterQueueIsFull()) {
		sFraudRegisterInfo *registerInfo = new FILE_LINE(0) sFraudRegisterInfo;
		this->completeRegisterInfo(registerInfo, call);
		registerInfo->state = state;
		registerInfo->prev_state = prev_state;
		registerInfo->prev_state_at = prev_state_at;
		pushToRegisterQueue(registerInfo);
	}
}

void FraudAlerts::evRegister(Register *reg, RegisterState *regState, eRegisterState state, eRegisterState prev_state, u_int64_t prev_state_at) {
	if(!checkIfRegisterQueueIsFull()) {
		sFraudRegisterInfo *registerInfo = new FILE_LINE(0) sFraudRegisterInfo;
		this->completeRegisterInfo(registerInfo, reg, regState);
		registerInfo->state = state;
		registerInfo->prev_state = prev_state;
		registerInfo->prev_state_at = prev_state_at;
		pushToRegisterQueue(registerInfo);
	}
}

void FraudAlerts::stopPopCallInfoThread(bool wait) {
	termPopCallInfoThread = true;
	while(wait && runPopCallInfoThread) {
		USLEEP(1000);
	}
}

void FraudAlerts::waitForEmptyQueues(int timeout) {
	u_int32_t start = getTimeS(); 
	while(callQueue.getSize() > 0 ||
	      rtpStreamQueue.getSize() > 0 ||
	      eventQueue.getSize() > 0 ||
	      registerQueue.getSize() > 0) {
		usleep(100000);
		if(timeout > 0) {
			u_int32_t time = getTimeS();
			if(time > start && time - start > timeout) {
				break;
			}
		}
	}
}

void FraudAlerts::pushToCallQueue(sFraudCallInfo *callInfo) {
	callQueue.push(callInfo);
}

void FraudAlerts::pushToRtpStreamQueue(sFraudRtpStreamInfo *streamInfo) {
	rtpStreamQueue.push(streamInfo);
}

void FraudAlerts::pushToEventQueue(sFraudEventInfo *eventInfo) {
	eventQueue.push(eventInfo);
}

void FraudAlerts::pushToRegisterQueue(sFraudRegisterInfo *registerInfo) {
	registerQueue.push(registerInfo);
}

bool FraudAlerts::checkIfCallQueueIsFull(bool log) {
	if(callQueue.getSize() >= maxLengthAsyncQueue) {
		if(log) {
			u_int64_t actTime = getTimeMS_rdtsc();
			if(actTime > lastTimeCallsIsFull + 5000) {
				syslog(LOG_NOTICE, "Fraud queue for CallInfo is full");
				lastTimeCallsIsFull = actTime;
			}
		}
		return(true);
	}
	return(false);
}

bool FraudAlerts::checkIfRtpStreamQueueIsFull(bool log) {
	if(rtpStreamQueue.getSize() >= maxLengthAsyncQueue) {
		if(log) {
			u_int64_t actTime = getTimeMS_rdtsc();
			if(actTime > lastTimeRtpStreamsIsFull + 5000) {
				syslog(LOG_NOTICE, "Fraud queue for RtpStreamInfo is full");
				lastTimeRtpStreamsIsFull = actTime;
			}
		}
		return(true);
	}
	return(false);
}

bool FraudAlerts::checkIfEventQueueIsFull(bool log) {
	if(eventQueue.getSize() >= maxLengthAsyncQueue) {
		if(log) {
			u_int64_t actTime = getTimeMS_rdtsc();
			if(actTime > lastTimeEventsIsFull + 5000) {
				syslog(LOG_NOTICE, "Fraud queue for EventInfo is full");
				lastTimeEventsIsFull = actTime;
			}
		}
		return(true);
	}
	return(false);
}

bool FraudAlerts::checkIfRegisterQueueIsFull(bool log) {
	if(registerQueue.getSize() >= maxLengthAsyncQueue) {
		if(log) {
			u_int64_t actTime = getTimeMS_rdtsc();
			if(actTime > lastTimeRegistersIsFull + 5000) {
				syslog(LOG_NOTICE, "Fraud queue for RegisterInfo is full");
				lastTimeRegistersIsFull = actTime;
			}
		}
		return(true);
	}
	return(false);
}

void *_FraudAlerts_popCallInfoThread(void *arg) {
	((FraudAlerts*)arg)->popCallInfoThread();
	return(NULL);
}
void FraudAlerts::initPopCallInfoThread() {
	vm_pthread_create("fraud",
			  &this->threadPopCallInfo, NULL, _FraudAlerts_popCallInfoThread, this, __FILE__, __LINE__);
}

void FraudAlerts::popCallInfoThread() {
	runPopCallInfoThread = true;
	sFraudCallInfo *callInfo;
	sFraudRtpStreamInfo *rtpStreamInfo;
	sFraudEventInfo *eventInfo;
	sFraudRegisterInfo *registerInfo;
	while(!is_terminating() && !termPopCallInfoThread) {
		bool okPop = false;
		if(callQueue.pop(&callInfo)) {
			if(_fraudAlerts_ready) {
				lock_alerts();
				vector<FraudAlert*>::iterator iter;
				for(iter = alerts.begin(); iter != alerts.end(); iter++) {
					this->completeCallInfoAfterPop(callInfo, &(*iter)->checkInternational);
					(*iter)->evCall(callInfo);
				}
				unlock_alerts();
			}
			delete callInfo;
			okPop = true;
		}
		if(rtpStreamQueue.pop(&rtpStreamInfo)) {
			if(_fraudAlerts_ready) {
				lock_alerts();
				vector<FraudAlert*>::iterator iter;
				for(iter = alerts.begin(); iter != alerts.end(); iter++) {
					this->completeRtpStreamInfoAfterPop(rtpStreamInfo, &(*iter)->checkInternational);
					(*iter)->evRtpStream(rtpStreamInfo);
				}
				unlock_alerts();
			}
			delete rtpStreamInfo;
			okPop = true;
		}
		if(eventQueue.pop(&eventInfo)) {
			if(_fraudAlerts_ready) {
				lock_alerts();
				vector<FraudAlert*>::iterator iter;
				for(iter = alerts.begin(); iter != alerts.end(); iter++) {
					(*iter)->evEvent(eventInfo);
				}
				unlock_alerts();
			}
			if(eventInfo->lock_packet && eventInfo->block_store) {
				eventInfo->block_store->unlock_packet(eventInfo->block_store_index);
			}
			delete eventInfo;
			okPop = true;
		}
		if(registerQueue.pop(&registerInfo)) {
			if(_fraudAlerts_ready) {
				lock_alerts();
				vector<FraudAlert*>::iterator iter;
				for(iter = alerts.begin(); iter != alerts.end(); iter++) {
					(*iter)->evRegister(registerInfo);
				}
				unlock_alerts();
			}
			delete registerInfo;
			okPop = true;
		}
		if(!okPop) {
			USLEEP(1000);
		}
	}
	runPopCallInfoThread = false;
}

void FraudAlerts::completeCallInfo(sFraudCallInfo *callInfo, Call *call, 
				   sFraudCallInfo::eTypeCallInfo typeCallInfo, u_int64_t at) {
	callInfo->typeCallInfo = typeCallInfo;
	callInfo->call_type = call->typeIs(INVITE) ? INVITE : call->getTypeBase();
	callInfo->callid = call->call_id;
	callInfo->caller_number = call->caller;
	callInfo->called_number = call->called();
	callInfo->caller_ip = call->sipcallerip[0];
	callInfo->called_ip = call->sipcalledip[0];
	callInfo->caller_domain = call->caller_domain;
	callInfo->called_domain = call->called_domain();
	callInfo->vlan = call->vlan;
	if(useUserRestriction_custom_headers) {
		extern CustomHeaders *custom_headers_cdr;
		callInfo->custom_headers = new FILE_LINE(0) map<string, string>;
		custom_headers_cdr->getHeaderValues(call, INVITE, callInfo->custom_headers);
	}
	switch(typeCallInfo) {
	case sFraudCallInfo::typeCallInfo_beginCall:
		callInfo->at_begin = at;
		break;
	case sFraudCallInfo::typeCallInfo_connectCall:
		callInfo->at_connect = at;
		break;
	case sFraudCallInfo::typeCallInfo_sessionCanceledCall:
		callInfo->at_session_canceled = at;
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

void FraudAlerts::completeRtpStreamInfo(sFraudRtpStreamInfo *rtpStreamInfo, Call *call) {
	rtpStreamInfo->caller_number = call->caller;
	rtpStreamInfo->called_number = call->called();
	rtpStreamInfo->callid = call->call_id;
}

void FraudAlerts::completeNumberInfo_country_code(sFraudNumberInfo *numberInfo, CheckInternational *checkInternational) {
	for(int i = 0; i < 2; i++) {
		string *number = i == 0 ? &numberInfo->caller_number : &numberInfo->called_number;
		string *rslt_country_code = i == 0 ? &numberInfo->country_code_caller_number : &numberInfo->country_code_called_number;
		string *rslt_continent_code = i == 0 ? &numberInfo->continent_code_caller_number : &numberInfo->continent_code_called_number;
		string *rslt_country2_code = i == 0 ? &numberInfo->country2_code_caller_number : &numberInfo->country2_code_called_number;
		string *rslt_continent2_code = i == 0 ? &numberInfo->continent2_code_caller_number : &numberInfo->continent2_code_called_number;
		string *rslt_country_prefix = i == 0 ? &numberInfo->country_prefix_caller : &numberInfo->country_prefix_called;
		vector<string> countries;
		if(countryPrefixes->getCountry(number->c_str(), &countries, rslt_country_prefix, checkInternational) != "" &&
		   countries.size()) {
			*rslt_country_code = countries[0];
			*rslt_continent_code = countryCodes->getContinent(countries[0].c_str());
			if(countries.size() > 1) {
				*rslt_country2_code = countries[1];
				*rslt_continent2_code = countryCodes->getContinent(countries[1].c_str());
			}
		}
	}
	numberInfo->local_called_number = countryPrefixes->isLocal(numberInfo->called_number.c_str(), checkInternational);
}

void FraudAlerts::completeCallInfoAfterPop(sFraudCallInfo *callInfo, CheckInternational *checkInternational) {
	this->completeNumberInfo_country_code(callInfo, checkInternational);
	for(int i = 0; i < 2; i++) {
		vmIP *ip = i == 0 ? &callInfo->caller_ip : &callInfo->called_ip;
		string *rslt_country_code = i == 0 ? &callInfo->country_code_caller_ip : &callInfo->country_code_called_ip;
		string *rslt_continent_code = i == 0 ? &callInfo->continent_code_caller_ip : &callInfo->continent_code_called_ip;
		string country = countryDetect ?
				  countryDetect->getCountryByIP(*ip) :
				  geoIP_country->getCountry(*ip);
		if(country != "") {
			*rslt_country_code = country;
			*rslt_continent_code = countryCodes->getContinent(country.c_str());
		}
	}
	callInfo->local_called_ip = countryDetect ?
				     countryDetect->isLocalByIP(callInfo->called_ip) :
				     geoIP_country->isLocal(callInfo->called_ip, checkInternational);
}

void FraudAlerts::completeRtpStreamInfoAfterPop(sFraudRtpStreamInfo *rtpStreamInfo, CheckInternational *checkInternational) {
	rtpStreamInfo->rtp_src_ip_group = this->groupsIP.getGroupId(rtpStreamInfo->rtp_src_ip);
	rtpStreamInfo->rtp_dst_ip_group = this->groupsIP.getGroupId(rtpStreamInfo->rtp_dst_ip);
	this->completeNumberInfo_country_code(rtpStreamInfo, checkInternational);
}

void FraudAlerts::completeRegisterInfo(sFraudRegisterInfo *registerInfo, Call *call) {
	registerInfo->sipcallerip = call->sipcallerip[0];
	registerInfo->sipcalledip = call->sipcalledip[0];
	registerInfo->to_num = call->called();
	registerInfo->to_domain = call->called_domain();
	registerInfo->contact_num = call->contact_num;
	registerInfo->contact_domain = call->contact_domain;
	registerInfo->digest_username = call->digest_username;
	registerInfo->from_num = call->caller;
	registerInfo->from_name = call->callername;
	registerInfo->from_domain = call->caller_domain;
	registerInfo->digest_realm = call->digest_realm;
	registerInfo->ua = call->a_ua;
	registerInfo->at = call->calltime_us();
}

void FraudAlerts::completeRegisterInfo(sFraudRegisterInfo *registerInfo, Register *reg, RegisterState *regState) {
	registerInfo->sipcallerip = reg->sipcallerip;
	registerInfo->sipcalledip = reg->sipcalledip;
	registerInfo->to_num = REG_CONV_STR(reg->to_num);
	registerInfo->to_domain = REG_CONV_STR(reg->to_domain);
	registerInfo->contact_num = REG_CONV_STR(regState->contact_num == EQ_REG ? reg->contact_num : regState->contact_num);
	registerInfo->contact_domain = REG_CONV_STR(regState->contact_domain == EQ_REG ? reg->contact_domain : regState->contact_domain);
	registerInfo->digest_username = REG_CONV_STR(reg->digest_username);
	registerInfo->from_num = REG_CONV_STR(regState->from_num == EQ_REG ? reg->from_num : regState->from_num);
	registerInfo->from_name = REG_CONV_STR(regState->from_name == EQ_REG ? reg->from_name : regState->from_name);
	registerInfo->from_domain = REG_CONV_STR(regState->from_domain == EQ_REG ? reg->from_domain : regState->from_domain);
	registerInfo->digest_realm = REG_CONV_STR(regState->digest_realm == EQ_REG ? reg->digest_realm : regState->digest_realm);
	registerInfo->ua = REG_CONV_STR(regState->ua == EQ_REG ? reg->ua : regState->ua);
	registerInfo->at = regState->state_from_us;
}

void FraudAlerts::refresh() {
	lock_alerts();
	clear(false);
	loadData(false);
	loadAlerts(false);
	unlock_alerts();
}

int FraudAlerts::craeteTimerThread(bool lock, bool ifNeed) {
	if(timer_thread) {
		return(-1);
	}
	if(ifNeed) {
		bool need = false;;
		if(lock) lock_alerts();
		for(vector<FraudAlert*>::iterator iter = alerts.begin(); iter != alerts.end(); iter++) {
			if((*iter)->needTimer()) {
				need = true;
			}
		}
		if(lock) unlock_alerts();
		if(!need) {
			return(0);
		}
	}
	timer_thread_terminating = false;
	vm_pthread_create("fraud timer", &timer_thread, NULL, FraudAlerts::_timerFce, this, __FILE__, __LINE__);
	return(1);
}

void FraudAlerts::stopTimerThread() {
	if(timer_thread) {
		timer_thread_terminating = true;
		pthread_join(timer_thread, NULL);
		timer_thread = 0;
		timer_thread_terminating = false;
	}
}

void *FraudAlerts::_timerFce(void *arg) {
	((FraudAlerts*)arg)->timerFce();
	return(NULL);
}

void FraudAlerts::timerFce() {
	timer_thread_last_time_us = 0;
	timer_thread_last_time_s = 0;
	timer_thread_last_time_m = 0;
	while(!timer_thread_terminating) {
		u_int64_t time_us = getTimeUS();
		u_int32_t time_s = time_us / 1000000;
		u_int32_t time_m = time_s / 60;
		if(timer_thread_last_time_us) {
			int typeChangeTime = 0;
			if(time_s > timer_thread_last_time_s) {
				typeChangeTime |= FraudAlert::_tt_sec;
				timer_thread_last_time_s = time_s;
				if(time_m > timer_thread_last_time_m) {
					typeChangeTime |= FraudAlert::_tt_min;
					timer_thread_last_time_m = time_m;
				}
			}
			if(typeChangeTime) {
				lock_alerts();
				for(vector<FraudAlert*>::iterator iter = alerts.begin(); iter != alerts.end(); iter++) {
					if((*iter)->needTimer() & typeChangeTime) {
						(*iter)->evTimer(time_s);
					}
				}
				unlock_alerts();
			}
		} else {
			timer_thread_last_time_s = time_s;
			timer_thread_last_time_m = time_m;
		}
		timer_thread_last_time_us = time_us;
		usleep(min((int)(1000000 - time_us % 1000000), 10000));
	}
}


void initFraud(SqlDb *sqlDb) {
	if(!opt_enable_fraud) {
		return;
	}
	if(opt_nocdr) {
		opt_enable_fraud = false;
		return;
	}
	if(!isExistsFraudAlerts(&opt_enable_fraud_store_pcaps, sqlDb) ||
	   !checkFraudTables(sqlDb)) {
		return;
	}
	if(!countryCodes) {
		countryCodes = new FILE_LINE(7028) CountryCodes();
		countryCodes->load(sqlDb);
	}
	if(!countryPrefixes) {
		countryPrefixes = new FILE_LINE(7029) CountryPrefixes();
		countryPrefixes->load(sqlDb);
	}
	if(!geoIP_country && !countryDetect) {
		geoIP_country = new FILE_LINE(7030) GeoIP_country();
		geoIP_country->load();
	}
	if(!cacheNumber_location) {
		cacheNumber_location = new FILE_LINE(7031) CacheNumber_location();
	}
	if(fraudAlerts) {
		return;
	}
	fraudAlerts_lock();
	fraudAlerts = new FILE_LINE(7032) FraudAlerts();
	fraudAlerts->loadData(true, sqlDb);
	fraudAlerts->loadAlerts(true, sqlDb);
	fraudAlerts_unlock();
	_fraudAlerts_ready = 1;
}

void termFraud() {
	if(fraudAlerts) {
		_fraudAlerts_ready = 0;
		fraudAlerts->waitForEmptyQueues();
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

bool checkFraudTables(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
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
		{isCloud()?"cloudshare.country_code":"country_code", help_gui_loginAdmin, help_gui_loginAdmin},
		{isCloud()?"cloudshare.country_code_prefix":"country_code_prefix", help_gui_loginAdmin, help_gui_loginAdmin},
		{isCloud()?"cloudshare.geoip_country":"geoip_country", help_gui_loginAdmin, help_gui_loginAdmin}
	};
	for(size_t i = 0; i < sizeof(checkTables) / sizeof(checkTables[0]); i++) {
		if(!sqlDb->existsTable(checkTables[i].table)) {
			syslog(LOG_ERR, "missing table %s - fraud disabled", checkTables[i].table);
			if(checkTables[i].help) {
				syslog(LOG_NOTICE, "try: %s", checkTables[i].help);
			}
			if(_createSqlObject) {
				delete sqlDb;
			}
			return(false);
		} else if(checkTables[i].emptyHelp) {
			sqlDb->query((string("select count(*) as cnt from ") + checkTables[i].table).c_str());
			SqlDb_row row = sqlDb->fetchRow();
			if(!row || !atol(row["cnt"].c_str())) {
				syslog(LOG_ERR, "table %s is empty - fraud disabled", checkTables[i].table);
				if(checkTables[i].emptyHelp) {
					syslog(LOG_NOTICE, "try: %s", checkTables[i].emptyHelp);
				}
				if(_createSqlObject) {
					delete sqlDb;
				}
				return(false);
			}
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
}

void refreshFraud() {
	if(opt_enable_fraud) {
		_fraudAlerts_ready = 0;
		bool enable_fraud_store_pcaps;
		if(isExistsFraudAlerts(&enable_fraud_store_pcaps)) {
			if(!fraudAlerts) {
				opt_enable_fraud_store_pcaps =  enable_fraud_store_pcaps;
				initFraud();
			} else {
				fraudAlerts->waitForEmptyQueues();
				opt_enable_fraud_store_pcaps =  enable_fraud_store_pcaps;
				fraudAlerts->refresh();
				_fraudAlerts_ready = 1;
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
		fraudAlerts->beginCall(call, getTimeUS(tv));
		fraudAlerts_unlock();
	}
}

void fraudConnectCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->connectCall(call, getTimeUS(tv));
		fraudAlerts_unlock();
	}
}

void fraudSessionCanceledCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->sessionCanceledCall(call, getTimeUS(tv));
		fraudAlerts_unlock();
	}
}

void fraudSeenByeCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->seenByeCall(call, getTimeUS(tv));
		fraudAlerts_unlock();
	}
}

void fraudEndCall(Call *call, timeval tv) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->endCall(call, getTimeUS(tv));
		fraudAlerts_unlock();
	}
}

void fraudBeginRtpStream(vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
			 Call *call, time_t time) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->beginRtpStream(src_ip, src_port, dst_ip, dst_port,
					    call, TIME_S_TO_US(time));
		fraudAlerts_unlock();
	}
}

void fraudEndRtpStream(vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
		       Call *call, time_t time) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->endRtpStream(src_ip, src_port, dst_ip, dst_port,
					  call, TIME_S_TO_US(time));
		fraudAlerts_unlock();
	}
}

void fraudSipPacket(vmIP ip, unsigned sip_method, timeval tv, const char *ua, int ua_len) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evSipPacket(ip, sip_method, getTimeUS(tv), ua, ua_len);
		fraudAlerts_unlock();
	}
}

void fraudRegister(vmIP src_ip, vmIP dst_ip, timeval tv, const char *ua, int ua_len,
		   packet_s *packetS) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evRegister(src_ip, dst_ip, getTimeUS(tv), ua, ua_len,
					packetS ? packetS->block_store : NULL, packetS ? packetS->block_store_index : 0, packetS ? packetS->dlt : 0);
		fraudAlerts_unlock();
	}
}

void fraudRegisterResponse(vmIP src_ip, vmIP dst_ip, u_int64_t at, const char *ua, int ua_len) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evRegisterResponse(src_ip, dst_ip, at, ua, ua_len);
		fraudAlerts_unlock();
	}
}

void fraudRegister(Call *call, eRegisterState state, eRegisterState prev_state, u_int64_t prev_state_at) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evRegister(call, state, prev_state, prev_state_at);
		fraudAlerts_unlock();
	}
}

void fraudRegister(Register *reg, RegisterState *regState, eRegisterState state, eRegisterState prev_state, u_int64_t prev_state_at) {
	if(isFraudReady()) {
		fraudAlerts_lock();
		fraudAlerts->evRegister(reg, regState, state, prev_state, prev_state_at);
		fraudAlerts_unlock();
	}
}

string whereCondFraudAlerts() {
	return("((alert_type > 20 and alert_type < 30) or\
		 alert_type in (43, 44, 46, 51)) and\
		(disable is null or not disable)");
}

bool isExistsFraudAlerts(bool *storePcaps, SqlDb *sqlDb) {
	if(storePcaps) {
		*storePcaps = false;
	}
	if(opt_nocdr) {
		return(false);
	}
	bool rslt = false;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("alerts")) {
		sqlDb->createTable("fraud_alert_info");
		bool existsColumnSelectSensors = sqlDb->existsColumn("alerts", "select_sensors");
		bool existsColumnFraudStorePcaps = sqlDb->existsColumn("alerts", "fraud_store_pcaps");
		sqlDb->query(string("select id, alert_type, descr") +
			     (existsColumnSelectSensors ? ", select_sensors" : "") + 
			     (existsColumnFraudStorePcaps ? ", fraud_store_pcaps" : "") + 
			     "\
			      from alerts\
			      where " + whereCondFraudAlerts());
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			if(selectSensorsContainSensorId(row["select_sensors"])) {
				rslt = true;
				if(storePcaps) {
					if(atoi(row["fraud_store_pcaps"].c_str())) {
						*storePcaps = true;
					}
				} else {
					break;
				}
			}
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(rslt);
}

bool selectSensorsContainSensorId(string select_sensors) {
	if(select_sensors.empty() || select_sensors == "-1") {
		return(true);
	}
	vector<string> sensors = split(select_sensors, ',');
	for(unsigned i = 0; i < sensors.size(); i++) {
		extern SensorsMap sensorsMap;
		if(atoi(sensors[i].c_str()) == sensorsMap.getSensorTableId(opt_id_sensor > 0 ? opt_id_sensor : -2)) {
			return(true);
		}
	}
	return(false);
}
