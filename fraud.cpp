#include <algorithm>

#include "fraud.h"


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
	delete sqlDb;
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
		addFraudDef(&row);
	}
	delete sqlDb;
}

FraudAlert_rcc_timePeriods::FraudAlert_rcc_timePeriods(const char *descr, int concurentCallsLimit, unsigned int dbId) {
	this->descr = descr;
	this->concurentCallsLimit = concurentCallsLimit;
	this->dbId = dbId;
}

void FraudAlert_rcc_timePeriods::loadTimePeriods() {
	SqlDb *sqlDb = createSqlObject();
	char dbIdStr[10];
	sprintf(dbIdStr, "%u", dbId);
	sqlDb->query(string(
		"select *\
		 from alerts_fraud_timeperiod\
		 where alerts_fraud_id = ") + dbIdStr);
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		timePeriods.push_back(TimePeriod(&row));
	}
	delete sqlDb;
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

FraudAlert_chc::FraudAlert_chc(unsigned int dbId)
 : FraudAlert(_chc, dbId) {
}

FraudAlert_chcr::FraudAlert_chcr(unsigned int dbId)
 : FraudAlert(_chcr, dbId) {
}

FraudAlert_d::FraudAlert_d(unsigned int dbId)
 : FraudAlert(_d, dbId) {
}


FraudAlerts::~FraudAlerts() {
	clear();
}

void FraudAlerts::loadAlerts() {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select id, alert_type from alerts\
		      where alert_type > 20 and\
			    (disable is null or not disable)");
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		FraudAlert *alert;
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
		alerts.push_back(alert);
	}
	delete sqlDb;
}

void FraudAlerts::clear() {
	for(size_t i = 0; i < alerts.size(); i++) {
		delete alerts[i];
	}
	alerts.clear();
}
