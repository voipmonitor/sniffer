#include "voipmonitor.h"
#include "country_detect.h"


CountryDetect *countryDetect;

extern int opt_id_sensor;
extern int opt_nocdr;


CountryDetect_base_table::CountryDetect_base_table() {
	loadOK = false;
}

bool CountryDetect_base_table::checkTable(eTableType tableType, string &tableName, SqlDb *sqlDb) {
	tableName = getTableName(tableType);
	if(tableName.empty()) {
		loadOK = false;
		return(false);
	}
	bool rslt = true;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(!sqlDb->existsTable(tableName)) {
		syslog(LOG_WARNING, "missing table %s - table is created from gui", tableName.c_str());
		rslt = false;
	} else if(sqlDb->emptyTable(tableName)) {
		syslog(LOG_WARNING, "table %s is empty - table is filled from gui", tableName.c_str());
		rslt = false;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	loadOK = rslt;
	return(rslt);
}

string CountryDetect_base_table::getTableName(eTableType tableType) {
	string tableName;
	bool useCloudShare = false;
	switch(tableType) {
	case _country_code:
		tableName = "country_code";
		useCloudShare = true;
		break;
	case _country_code_prefix:
		tableName = "country_code_prefix";
		useCloudShare = true;
		break;
	case _geoip_country:
		tableName = "geoip_country";
		useCloudShare = true;
		break;
	case _geoipv6_country:
		tableName = "geoipv6_country";
		useCloudShare = true;
		break;
	}
	if(!tableName.empty() && isCloud() && useCloudShare && !sverb.disable_cloudshare) {
		tableName =  "cloudshare." + tableName;
	}
	return(tableName);
}


CountryCodes::CountryCodes() {
}

bool CountryCodes::load(SqlDb *sqlDb) {
	string tableName;
	if(!checkTable(_country_code, tableName, sqlDb)) {
		return(false);
	}
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("select * \
		      from " + tableName + " \
		      where parent_id is null");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		continents[row["code"]] = d_item2<string, unsigned>(row["name"], atoi(row["id"].c_str()));
	}
	sqlDb->query("select country.*, continent.code as continent \
		      from " + tableName + " country \
		      join " + tableName + " continent on (continent.id = country.parent_id) \
		      where country.parent_id is not null");
	sqlDb->fetchRows(&rows);
	while((row = rows.fetchRow())) {
		countries[row["code"]] = d_item2<string, unsigned>(row["name"], atoi(row["id"].c_str()));
		countryContinent[row["code"]] = row["continent"];
		continentCountry[row["continent"]].push_back(row["code"]);
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
}

bool CountryCodes::isCountry(const char *code) {
	map<string, d_item2<string, unsigned> >::iterator iter;
	iter = countries.find(code);
	return(iter != countries.end());
}

string CountryCodes::getNameCountry(const char *code) {
	map<string, d_item2<string, unsigned> >::iterator iter;
	iter = countries.find(code);
	return(iter != countries.end() ? iter->second.item1 : "");
}

unsigned CountryCodes::getIdCountry(const char *code) {
	map<string, d_item2<string, unsigned> >::iterator iter;
	iter = countries.find(code);
	return(iter != countries.end() ? iter->second.item2 : 0);
}

string CountryCodes::getNameContinent(const char *code) {
	map<string, d_item2<string, unsigned> >::iterator iter;
	iter = continents.find(code);
	return(iter != continents.end() ? iter->second.item1 : "");
}

unsigned CountryCodes::getIdContinent(const char *code) {
	map<string, d_item2<string, unsigned> >::iterator iter;
	iter = continents.find(code);
	return(iter != continents.end() ? iter->second.item2 : 0);
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
	internationalPrefixes_string = split("+, 00", ",", true);
	internationalMinLength = 0;
	internationalMinLengthPrefixesStrict = false;
	enableCheckNapaWithoutPrefix = false;
	minLengthNapaWithoutPrefix = 0;
	skipPrefixesOnlyOne = false;
}

CheckInternational::~CheckInternational() {
	clearInternationalPrefixes();
	clearSkipPrefixes();
	clearCustomerPrefixAdv();
}

void CheckInternational::setInternationalPrefixes(const char *prefixes, vector<string> *separators) {
	clearInternationalPrefixes();
	vector<string> internationalPrefixes = separators ? 
						split(prefixes, *separators, true) :
						split(prefixes, ",", true);
	for(unsigned i = 0; i < internationalPrefixes.size(); i++) {
		if(internationalPrefixes[i].length()) {
			if(internationalPrefixes[i][0] == '^') {
				this->internationalPrefixes_regexp.push_back(new FILE_LINE(0) cRegExp(internationalPrefixes[i].c_str(), cRegExp::_regexp_icase_matches));
			} else {
				this->internationalPrefixes_string.push_back(internationalPrefixes[i]);
			}
		}
	}
}

void CheckInternational::setSkipPrefixes(const char *prefixes, vector<string> *separators, bool onlyOne) {
	clearSkipPrefixes();
	vector<string> skipPrefixes = separators ?
				       split(prefixes, *separators, true) :
				       split(prefixes, ",", true);
	for(unsigned i = 0; i < skipPrefixes.size(); i++) {
		if(skipPrefixes[i].length()) {
			if(skipPrefixes[i][0] == '^') {
				this->skipPrefixes_regexp.push_back(new FILE_LINE(0) cRegExp(skipPrefixes[i].c_str(), cRegExp::_regexp_icase_matches));
			} else {
				this->skipPrefixes_string.push_back(skipPrefixes[i]);
			}
		}
	}
	this->skipPrefixesOnlyOne = onlyOne;
}

void CheckInternational::setInternationalMinLength(int internationalMinLength, bool internationalMinLengthPrefixesStrict) {
	this->internationalMinLength = internationalMinLength;
	this->internationalMinLengthPrefixesStrict = internationalMinLengthPrefixesStrict;
}

void CheckInternational::setEnableCheckNapaWithoutPrefix(bool enableCheckNapaWithoutPrefix, int minLengthNapaWithoutPrefix) {
	this->enableCheckNapaWithoutPrefix = enableCheckNapaWithoutPrefix;
	this->minLengthNapaWithoutPrefix = minLengthNapaWithoutPrefix;
}

bool CheckInternational::isSet(SqlDb_row *dbRow) {
	return((*dbRow)["international_prefixes"].length() ||
	       atoi((*dbRow)["international_number_min_length"].c_str()) ||
	       (*dbRow)["country_code_for_local_numbers"].length());
}

bool CheckInternational::load(SqlDb_row *dbRow, SqlDb *sqlDb) {
	if(isSet(dbRow)) {
		_load(dbRow);
		loadCustomerPrefixAdv(sqlDb);
		return(true);
	} else {
		return(load(sqlDb));
	}
}

bool CheckInternational::load(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool loadFromSensors = false;
	if(opt_id_sensor > 0) {
		sqlDb->query("select * from sensors where id_sensor = " + intToString(opt_id_sensor));
		SqlDb_row row;
		if((row = sqlDb->fetchRow()) &&
		   atoi(row["override_international_rules"].c_str()) &&
		   isSet(&row)) {
			this->_load(&row);
			loadFromSensors = true;
		}
	}
	if(!loadFromSensors && sqlDb->existsTable("international_rules")) {
		sqlDb->query("select * from international_rules");
		SqlDb_row row;
		if((row = sqlDb->fetchRow())) {
			this->_load(&row);
		}
	}
	loadCustomerPrefixAdv(sqlDb);
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
}

void CheckInternational::_load(SqlDb_row *dbRow) {
	vector<string> prefixesSeparators = split(",|;| ", "|");
	setInternationalPrefixes((*dbRow)["international_prefixes"].c_str(), &prefixesSeparators);
	internationalMinLength = atoi((*dbRow)["international_number_min_length"].c_str());
	internationalMinLengthPrefixesStrict = atoi((*dbRow)["international_number_min_length_prefixes_strict"].c_str());
	countryCodeForLocalNumbers = (*dbRow)["country_code_for_local_numbers"];
	enableCheckNapaWithoutPrefix = atoi((*dbRow)["enable_check_napa_without_prefix"].c_str());
	minLengthNapaWithoutPrefix = atoi((*dbRow)["min_length_napa_without_prefix"].c_str());
	setSkipPrefixes((*dbRow)["skip_prefixes"].c_str(), &prefixesSeparators, atoi((*dbRow)["skip_prefixes_only_one"].c_str()));
}

bool CheckInternational::loadCustomerPrefixAdv(SqlDb *sqlDb) {
	unsigned countRecords = 0;
	clearCustomerPrefixAdv();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	for(int pass = 0; pass < 2; pass++) {
		bool okTable = false;
		if(pass == 0) {
			if(opt_id_sensor > 0 &&
			   sqlDb->existsTable("sensors") &&
			   sqlDb->existsTable("customer_country_prefix_sensors")) {
				bool existsIpsColumns = sqlDb->existsColumn("customer_country_prefix_sensors", "ips");
				sqlDb->query("select * from sensors where id_sensor = " + intToString(opt_id_sensor));
				SqlDb_row row;
				if((row = sqlDb->fetchRow()) &&
				   atoi(row["override_country_prefixes"].c_str())) {
					string ipsGroupCols = existsIpsColumns ?
						",(select group_concat(cb_ip_groups.ip) from customer_country_prefix_sensors_groups \
						   left join cb_ip_groups on customer_country_prefix_sensors_groups.ip_group_id = cb_ip_groups.id \
						   where customer_country_prefix_sensors_id = customer_country_prefix_sensors.id and type = 'ip_src') as ips_group " : "";
					okTable = true;
					sqlDb->query("select *" + ipsGroupCols + " \
						      from customer_country_prefix_sensors \
						      where advanced_mode and \
							    sensor_id = " + row["id"]);
				}
			}
		} else {
			if(sqlDb->existsTable("customer_country_prefix") &&
			   !sqlDb->emptyTable("customer_country_prefix") &&
			   sqlDb->existsColumn("customer_country_prefix", "advanced_mode")) {
				bool existsIpsColumns = sqlDb->existsColumn("customer_country_prefix", "ips");
				string ipsGroupCols = existsIpsColumns ?
					",(select group_concat(cb_ip_groups.ip) from customer_country_prefix_groups \
					   left join cb_ip_groups on customer_country_prefix_groups.ip_group_id = cb_ip_groups.id \
					   where customer_country_prefix_id = customer_country_prefix.id and type = 'ip_src') as ips_group " : "";
				okTable = true;
				sqlDb->query("select *" + ipsGroupCols + " \
					      from customer_country_prefix \
					      where advanced_mode");
			}
		}
		if(okTable) {
			SqlDb_rows rows;
			sqlDb->fetchRows(&rows);
			SqlDb_row row;
			while((row = rows.fetchRow())) {
				CountryPrefix_recAdv *recAdv = new FILE_LINE(0) CountryPrefix_recAdv;
				if(row["number_regexp_cond"].length()) {
					recAdv->number_regexp_cond = new FILE_LINE(0) cRegExp(row["number_regexp_cond"].c_str());
				}
				if(row["number_length_from"].length()) {
					recAdv->number_length_from = atoi(row["number_length_from"].c_str());
				}
				if(row["number_length_to"].length()) {
					recAdv->number_length_to = atoi(row["number_length_to"].c_str());
				}
				vector<string> trim_prefixes = split(row["trim_prefixes"].c_str(), split(",|;| ", "|"), true);
				for(unsigned i = 0; i < trim_prefixes.size(); i++) {
					if(trim_prefixes[i].length()) {
						if(trim_prefixes[i][0] == '^') {
							recAdv->trim_prefixes_regexp.push_back(new FILE_LINE(0) cRegExp(trim_prefixes[i].c_str(), cRegExp::_regexp_icase_matches));
						} else {
							recAdv->trim_prefixes_string.push_back(trim_prefixes[i]);
						}
					}
				}
				recAdv->trim_prefixes_only_one = atoi(row["trim_prefixes_only_one"].c_str());
				if(row["trim_prefix_length"].length()) {
					recAdv->trim_prefix_length = atoi(row["trim_prefix_length"].c_str());
				}
				if (row["ips"].length()) {
					recAdv->ipFilter.addWhite(row["ips"].c_str());
				}
				if (row["ips_group"].length()) {
					recAdv->ipFilter.addWhite(row["ips_group"].c_str());
				}
				recAdv->is_international = row["international_local"] == "international";
				recAdv->country_code = row["country_code"];
				recAdv->descr = row["description"];
				customer_data_advanced.push_back(recAdv);
				++countRecords;
			}
			break;
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(countRecords > 0);
}

void CheckInternational::clearInternationalPrefixes() {
	internationalPrefixes_string.clear();
	for(unsigned i = 0; i < internationalPrefixes_regexp.size(); i++) {
		delete internationalPrefixes_regexp[i];
	}
	internationalPrefixes_regexp.clear();
}

void CheckInternational::clearSkipPrefixes() {
	skipPrefixes_string.clear();
	for(unsigned i = 0; i < skipPrefixes_regexp.size(); i++) {
		delete skipPrefixes_regexp[i];
	}
	skipPrefixes_regexp.clear();
}

void CheckInternational::clearCustomerPrefixAdv() {
	for(unsigned i = 0; i < customer_data_advanced.size(); i++) {
		delete customer_data_advanced[i];
	}
	customer_data_advanced.clear();
}

bool CheckInternational::processCustomerDataAdvanced(const char *number, vmIP ip,
						     bool *isInternational, string *country, string *numberWithoutPrefix) {
	if(!this->customer_data_advanced.size()) {
		return(false);
	}
	for(unsigned i = 0; i < this->customer_data_advanced.size(); i++) {
		CountryPrefix_recAdv *recAdv = this->customer_data_advanced[i];
		bool tmpFlag = false;
		int number_length = strlen(number);
		if(recAdv->number_regexp_cond &&
		   recAdv->number_regexp_cond->match(number) &&
		   (recAdv->number_length_from == -1 || number_length >= recAdv->number_length_from) &&
		   (recAdv->number_length_to == -1 || number_length <= recAdv->number_length_to) &&
		   (!ip.isSet() || recAdv->ipFilter.is_empty() || (!recAdv->ipFilter.is_empty() && recAdv->ipFilter.checkIP(ip)))) {
			tmpFlag = true;
		} else if (!recAdv->ipFilter.is_empty() && recAdv->ipFilter.checkIP(ip)) {
			tmpFlag = true;
		}
		if (tmpFlag) {
			if(isInternational) {
				*isInternational = recAdv->is_international;
			}
			if(country) {
				if(recAdv->is_international && recAdv->country_code.length()) {
					*country = recAdv->country_code;
				} else {
					country->resize(0);
				}
			}
			if(numberWithoutPrefix) {
				if(recAdv->trim_prefixes_string.size() || recAdv->trim_prefixes_regexp.size()) {
					this->skipPrefixes(number, &recAdv->trim_prefixes_string, &recAdv->trim_prefixes_regexp, !recAdv->trim_prefixes_only_one, !recAdv->trim_prefixes_only_one, numberWithoutPrefix);
				} else if(recAdv->trim_prefix_length > 0 && recAdv->trim_prefix_length < (int)strlen(number)) {
					*numberWithoutPrefix = number + recAdv->trim_prefix_length;
				} else {
					*numberWithoutPrefix = number;
				}
			}
			return(true);
		}
	}
	return(false);
}

bool CheckInternational::skipPrefixes(const char *number, vector<string> *prefixes_string, vector<cRegExp*> *prefixes_regexp, bool prefixes_all, bool prefixes_recurse,
				      string *numberWithoutPrefix, string *skipPrefix, unsigned *skipPrefixLength, vector<string> *skipPrefixes,
				      bool isInternationalPrefixes) {
	unsigned _skipPrefixLength = 0;
	if(!skipPrefixLength) {
		skipPrefixLength = &_skipPrefixLength;
	}
	*skipPrefixLength = 0;
	vector<string> _skipPrefixes;
	if(!skipPrefixes) {
		skipPrefixes = &_skipPrefixes;
	}
	skipPrefixes->clear();
	unsigned number_length = strlen(number);
	unsigned prefixes_count = prefixes_string->size() + prefixes_regexp->size();
	sPrefixPointer prefixes[prefixes_count];
	unsigned prefixes_i = 0;
	for(unsigned i = 0; i < prefixes_string->size(); i++) {
		prefixes[prefixes_i].prefix = &(*prefixes_string)[i];
		prefixes[prefixes_i].is_regexp = false;
		++prefixes_i;
	}
	for(unsigned i = 0; i < prefixes_regexp->size(); i++) {
		prefixes[prefixes_i].prefix = (*prefixes_regexp)[i];
		prefixes[prefixes_i].is_regexp = true;
		++prefixes_i;
	}
	do {
		unsigned use = false;
		for(unsigned prefixes_i = 0; prefixes_i < prefixes_count; prefixes_i++) {
			prefixes[prefixes_i].use = false;
		}
		do {
			unsigned prefixes_i_maxlength = 0;
			unsigned prefixes_maxlength = 0;
			for(unsigned prefixes_i = 0; prefixes_i < prefixes_count; prefixes_i++) {
				if(!prefixes[prefixes_i].use) {
					if(prefixes[prefixes_i].is_regexp) {
						cRegExp *prefix_regexp = (cRegExp*)prefixes[prefixes_i].prefix;
						vector<string> matches;
						if(prefix_regexp->match(number + *skipPrefixLength, &matches) &&
						   matches.size() &&
						   (number_length - *skipPrefixLength) > matches[0].length() &&
						   (!isInternationalPrefixes ||
						    !internationalMinLengthPrefixesStrict ||
						    !internationalMinLength ||
						    (number_length - *skipPrefixLength) >= (internationalMinLength + matches[0].length()))) {
							prefixes[prefixes_i].regexp_match = matches[0];
							prefixes[prefixes_i].match_length = matches[0].length();
							if(prefixes[prefixes_i].match_length > prefixes_maxlength) {
								prefixes_maxlength = prefixes[prefixes_i].match_length;
								prefixes_i_maxlength = prefixes_i;
							}
						}
					} else {
						string *prefix_string = (string*)prefixes[prefixes_i].prefix;
						if((number_length - *skipPrefixLength) > prefix_string->length() &&
						   !strncmp(number + *skipPrefixLength, prefix_string->c_str(), prefix_string->length()) &&
						   (!isInternationalPrefixes ||
						    !internationalMinLengthPrefixesStrict ||
						    !internationalMinLength ||
						    (number_length - *skipPrefixLength) >= (internationalMinLength + prefix_string->length()))) {
							prefixes[prefixes_i].match_length = prefix_string->length();
							if(prefixes[prefixes_i].match_length > prefixes_maxlength) {
								prefixes_maxlength = prefixes[prefixes_i].match_length;
								prefixes_i_maxlength = prefixes_i;
							}
						}
					}
				}
			}
			if(prefixes_maxlength > 0) {
				*skipPrefixLength += prefixes[prefixes_i_maxlength].match_length;
				skipPrefixes->push_back(*prefixes[prefixes_i_maxlength].match());
				prefixes[prefixes_i_maxlength].use = true;
				use = true;
			} else {
				break;
			}
		} while(prefixes_all);
		if(!use) {
			break;
		}
	} while(prefixes_recurse);
	if(*skipPrefixLength) {
		if(numberWithoutPrefix) {
			*numberWithoutPrefix = number + *skipPrefixLength;
		}
		if(skipPrefix) {
			*skipPrefix = string(number, *skipPrefixLength);
		}
		return(true);
	}
	if(numberWithoutPrefix) {
		*numberWithoutPrefix = number;
	}
	if(skipPrefix) {
		skipPrefix->resize(0);
	}
	return(false);
}

string CheckInternational::numberNormalized(const char *number, vmIP ip, CountryPrefixes *countryPrefixes) {
	if(countryPrefixes->loadOK) {
		string numberNormalized;
		countryPrefixes->getCountry(number, ip, NULL, NULL,
					    this, &numberNormalized);
		return(numberNormalized);
	} else {
		return(number);
	}
}


CountryPrefixes::CountryPrefixes() {
}

CountryPrefixes::~CountryPrefixes() {
	clear();
}

bool CountryPrefixes::load(SqlDb *sqlDb) {
	clear();
	string tableName;
	if(!checkTable(_country_code_prefix, tableName, sqlDb)) {
		return(false);
	}
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->query("select * \
		      from " + tableName + " \
		      order by prefix");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		data.push_back(CountryPrefix_rec(
			row["prefix"].c_str(),
			row["country_code"].c_str(),
			row["descr"].c_str(),
			NULL,
			NULL));
	}
	std::sort(data.begin(), data.end());
	bool existsIpsColumns = sqlDb->existsColumn("customer_country_prefix", "ips");
	for(int pass = 0; pass < 2; pass++) {
		bool okTable = false;
		if(pass == 0) {
			if(opt_id_sensor > 0 &&
			   sqlDb->existsTable("sensors") &&
			   sqlDb->existsTable("customer_country_prefix_sensors")) {
				sqlDb->query("select * from sensors where id_sensor = " + intToString(opt_id_sensor));
				SqlDb_row row;
				if((row = sqlDb->fetchRow()) &&
				   atoi(row["override_country_prefixes"].c_str())) {
					string ipsGroupCols = existsIpsColumns ?
						",(select group_concat(cb_ip_groups.ip) from customer_country_prefix_sensors_groups \
						   left join cb_ip_groups on customer_country_prefix_sensors_groups.ip_group_id = cb_ip_groups.id \
						   where customer_country_prefix_sensors_id = customer_country_prefix_sensors.id and type = 'ip_src') as ips_group " : "";
					okTable = true;
					sqlDb->query("select *" + ipsGroupCols + " \
						      from customer_country_prefix_sensors \
						      where advanced_mode is null or not advanced_mode and \
							    sensor_id = " + row["id"] + " \
						      order by prefix");
				}
			}
		} else {
			if(sqlDb->existsTable("customer_country_prefix") &&
			   !sqlDb->emptyTable("customer_country_prefix")) {
				okTable = true;
				bool existsColumnAdvancedMode = sqlDb->existsColumn("customer_country_prefix", "advanced_mode");
				string ipsGroupCols = existsIpsColumns ?
					",(select group_concat(cb_ip_groups.ip) from customer_country_prefix_groups \
					   left join cb_ip_groups on customer_country_prefix_groups.ip_group_id = cb_ip_groups.id \
					   where customer_country_prefix_id = customer_country_prefix.id and type = 'ip_src') as ips_group " : "";
				sqlDb->query(existsColumnAdvancedMode ?
					      "select *" + ipsGroupCols + " \
					       from customer_country_prefix \
					       where advanced_mode is null or not advanced_mode \
					       order by prefix" :
					      "select *" + ipsGroupCols + " \
					       from customer_country_prefix \
					       order by prefix");
			}
		}
		if(okTable) {
			SqlDb_rows rows;
			sqlDb->fetchRows(&rows);
			SqlDb_row row;
			while((row = rows.fetchRow())) {
				customer_data_simple.push_back(CountryPrefix_rec(
					row["prefix"].c_str(),
					row["country_code"].c_str(),
					row["descr"].c_str(),
					row["ips"].c_str(),
					row["ips_group"].c_str()));
			}
			std::sort(customer_data_simple.begin(), customer_data_simple.end());
			break;
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
}

void CountryPrefixes::clear() {
	data.clear();
	customer_data_simple.clear();
}

string CountryPrefixes::getCountry(const char *number, vmIP ip, vector<string> *countries, string *country_prefix,
				   CheckInternational *checkInternational, string *rsltNumberNormalized) {
	if(countries) {
		countries->clear();
	}
	if(country_prefix) {
		*country_prefix = "";
	}
	if(rsltNumberNormalized) {
		*rsltNumberNormalized = "";
	}
	string numberOrig = number;
	bool _isInternational;
	string _country;
	string _numberWithoutPrefix;
	if(checkInternational->processCustomerDataAdvanced(numberOrig.c_str(), ip,
							    &_isInternational, &_country,  &_numberWithoutPrefix)) {
		if(rsltNumberNormalized) {
			*rsltNumberNormalized = _numberWithoutPrefix;
		}
		if(_country.length()) {
			if(countries) {
				countries->push_back(_country);
			}
			return(_country);
		}
		if(_isInternational) {
			string country = this->_getCountry(_numberWithoutPrefix.c_str(), ip, countries, country_prefix);
			return(country);
		} else {
			string local_country = checkInternational->getLocalCountry();
			if(countries) {
				countries->push_back(local_country);
			}
			if(rsltNumberNormalized) {
				*rsltNumberNormalized = this->getPrefixNumber(local_country.c_str()) + *rsltNumberNormalized;
			}
			return(local_country);
		}
	}
	string numberWithoutSkipPrefix;
	string skipPrefix;
	checkInternational->skipSkipPrefixes(numberOrig.c_str(), &numberWithoutSkipPrefix, &skipPrefix);
	string numberWithoutInternationalPrefix;
	string internationalPrefix;
	checkInternational->skipInternationalPrefixes(numberWithoutSkipPrefix.c_str(), &numberWithoutInternationalPrefix, &internationalPrefix);
	string numberNormalized = numberWithoutInternationalPrefix;
	while(!numberNormalized.empty() && 
	      (numberNormalized[0] == '0' ||
	       (!internationalPrefix.length() && numberNormalized[0] == '+'))) {
		numberNormalized = numberNormalized.substr(1);
	}
	bool isInternational = internationalPrefix.length() ||
			       checkInternational->isInternationalViaLength(&numberNormalized);
	if(!isInternational) {
		string local_country = checkInternational->getLocalCountry();
		if(checkInternational->enableCheckNapaWithoutPrefix && countryIsNapa(local_country)) {
			bool okLengthForUS_CA = (numberNormalized.length() == 10 && numberNormalized[0] != '1') ||
						(numberNormalized.length() == 11 && numberNormalized[0] == '1');
			bool okLengthForOther = checkInternational->minLengthNapaWithoutPrefix > 0 ?
						 (((int)numberNormalized.length() >= checkInternational->minLengthNapaWithoutPrefix && numberNormalized[0] != '1') ||
						  ((int)numberNormalized.length() >= (checkInternational->minLengthNapaWithoutPrefix + 1) && numberNormalized[0] == '1')) :
						 true;
			string numberNormalizedNapa = numberNormalized;
			if(numberNormalizedNapa[0] != '1') {
				numberNormalizedNapa = "1" + numberNormalizedNapa;
			}
			string country = this->_getCountry(numberNormalizedNapa.c_str(), ip, countries, country_prefix);
			if((!countries || countries->size() == 1) && countryIsNapa(country) &&
			   (country == "US" || country == "CA" ? okLengthForUS_CA : okLengthForOther)) {
				if(rsltNumberNormalized) {
					*rsltNumberNormalized = numberNormalizedNapa;
				}
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
		if(country_prefix) {
			*country_prefix = this->getPrefixNumber(local_country.c_str());
		}
		if(rsltNumberNormalized) {
			*rsltNumberNormalized = this->getPrefixNumber(local_country.c_str()) + numberNormalized;
		}
		return(local_country);
	}
	string country = this->_getCountry(numberNormalized.c_str(), ip, countries, country_prefix);
	if(rsltNumberNormalized) {
		*rsltNumberNormalized = numberNormalized;
	}
	return(country);
}

string CountryPrefixes::_getCountry(const char *number, vmIP ip, vector<string> *countries, string *country_prefix) {
	if(countries) {
		countries->clear();
	}
	if(country_prefix) {
		*country_prefix = "";
	}
	vector<CountryPrefix_rec>::iterator findRecIt;
	for(int pass = 0; pass < 2; pass++) {
		vector<CountryPrefix_rec> *data = pass == 0 ? &this->customer_data_simple : &this->data;
		if(data->size()) {
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
				   atol(findRecIt->number.c_str()) < atol(string(number, min(strlen(number), findRecIt->number.length())).c_str())) {
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
				string rslt, rsltNumber;
				if (!findRecIt->ipFilter.is_empty()) {
					if (ip.isSet() && findRecIt->ipFilter.checkIP(ip)) {
						rslt = findRecIt->country_code;
						rsltNumber = findRecIt->number;
					}
				} else {
					rslt = findRecIt->country_code;
					rsltNumber = findRecIt->number;
				}
				if (!rslt.empty()) {
					if(country_prefix) {
						*country_prefix = findRecIt->number;
					}
					if(countries) {
						countries->push_back(rslt);
						while(findRecIt != data->begin()) {
							--findRecIt;
							if(rsltNumber == findRecIt->number) {
								if (!findRecIt->ipFilter.is_empty()) {
									if (ip.isSet() && findRecIt->ipFilter.checkIP(ip)) {
										countries->push_back(findRecIt->country_code);
									} else {
										break;
									}
								} else {
									countries->push_back(findRecIt->country_code);
								}
							} else {
								break;
							}
						}
					}
					return(rslt);
				}
			}
		}
		if (pass == 0 && ip.isSet()) {
			for (vector<CountryPrefix_rec>::iterator it = this->customer_data_simple.begin(); it != this->customer_data_simple.end(); it++) {
				if (it->number.empty() && !it->ipFilter.is_empty() && it->ipFilter.checkIP(ip)) {
					if (countries) {
						countries->push_back(it->country_code);
					}
					return(it->country_code);
				}
			}
		}
	}
	return("");
}


GeoIP_country::GeoIP_country() {
}

bool GeoIP_country::load(SqlDb *sqlDb) {
	string tableName;
	string tableNameV6;
	if(!checkTable(_geoip_country, tableName, sqlDb) ||
	   (VM_IPV6_B && !checkTable(_geoipv6_country, tableNameV6, sqlDb))) {
		return(false);
	}
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	for(int pass = 0; pass < (VM_IPV6_B ? 2 : 1); pass++) {
		sqlDb->setCsvInRemoteResult(true);
		sqlDb->query("select * \
			      from " + (pass ? tableNameV6 : tableName) + " \
			      order by ip_from");
		sqlDb->setCsvInRemoteResult(false);
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		vector<GeoIP_country_rec> *_data = pass ? &data_v6 : &data;
		while((row = rows.fetchRow())) {
			vmIP ip_from;
			vmIP ip_to;
			ip_from.setIP(&row, "ip_from");
			ip_to.setIP(&row, "ip_to");
			_data->push_back(GeoIP_country_rec(ip_from, ip_to, row["country"].c_str()));
		}
		std::sort(_data->begin(), _data->end());
	}
	if(sqlDb->existsTable("geoip_customer_type") &&
	   sqlDb->existsColumn("geoip_customer_type", "country_code") &&
	   !sqlDb->emptyTable("geoip_customer_type") &&
	   sqlDb->existsTable("geoip_customer") &&
	   sqlDb->existsColumn("geoip_customer", "country_code") &&
	   !sqlDb->emptyTable("geoip_customer")) {
		sqlDb->query("select ip, mask, \
				     coalesce(geoip_customer.country_code, geoip_customer_type.country_code) as country \
			      from geoip_customer \
			      join geoip_customer_type on (geoip_customer_type.id = geoip_customer.type_id) \
			      where (geoip_customer.country_code is not null and geoip_customer.country_code <> '') or \
				    (geoip_customer_type.country_code is not null and geoip_customer_type.country_code <> '')");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			customer_data.push_back(GeoIP_country_rec(
				row["ip"].c_str(),
				atoi(row["mask"].c_str()),
				row["country"].c_str()));
		}
		std::sort(customer_data.begin(), customer_data.end());
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
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

void CountryDetect::load(SqlDb *sqlDb) {
	countryCodes->load(sqlDb);
	countryPrefixes->load(sqlDb);
	geoIP_country->load(sqlDb);
	checkInternational->load(sqlDb);
}

string CountryDetect::getCountryByPhoneNumber(const char *phoneNumber, vmIP ip) {
	string rslt;
	lock();
	if(countryPrefixes->loadOK) {
		rslt = countryPrefixes->getCountry(phoneNumber, ip, NULL, NULL, checkInternational);
	}
	unlock();
	return(rslt);
}

unsigned CountryDetect::getCountryIdByPhoneNumber(const char *phoneNumber, vmIP ip) {
	unsigned rslt = 0;
	lock();
	if(countryPrefixes->loadOK) {
		string rslt_str = countryPrefixes->getCountry(phoneNumber, ip, NULL, NULL, checkInternational);
		if(!rslt_str.empty()) {
			rslt = countryCodes->getIdCountry(rslt_str.c_str());
		}
	}
	unlock();
	return(rslt);
}

bool CountryDetect::isLocalByPhoneNumber(const char *phoneNumber, vmIP ip) {
	bool rslt = false;
	lock();
	if(countryPrefixes->loadOK) {
		rslt = countryPrefixes->isLocal(phoneNumber, ip, checkInternational);
	}
	unlock();
	return(rslt);
}

string CountryDetect::getCountryByIP(vmIP ip) {
	string rslt;
	lock();
	if(geoIP_country->loadOK) {
		rslt = geoIP_country->getCountry(ip);
	}
	unlock();
	return(rslt);
}

unsigned CountryDetect::getCountryIdByIP(vmIP ip) {
	unsigned rslt = 0;
	lock();
	if(geoIP_country->loadOK) {
		string rslt_str = geoIP_country->getCountry(ip);
		if(!rslt_str.empty()) {
			rslt = countryCodes->getIdCountry(rslt_str.c_str());
		}
	}
	unlock();
	return(rslt);
}

bool CountryDetect::isLocalByIP(vmIP ip) {
	bool rslt = false;
	lock();
	if(geoIP_country->loadOK) {
		rslt = geoIP_country->isLocal(ip, checkInternational);
	}
	unlock();
	return(rslt);
}

string CountryDetect::getContinentByCountry(const char *country) {
	string rslt;
	lock();
	if(countryCodes->loadOK) {
		rslt = countryCodes->getContinent(country);
	}
	unlock();
	return(rslt);
}

void CountryDetect::prepareReload() {
	if(opt_nocdr) {
		return;
	}
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
		if(reload_do) {
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
		}
		unlock_reload();
	}
}


void CountryDetectInit(SqlDb *sqlDb) {
	if(!opt_nocdr) {
		countryDetect = new FILE_LINE(0) CountryDetect;
		countryDetect->load(sqlDb);
	}
}

void CountryDetectTerm() {
	if(countryDetect) {
		delete countryDetect; 
	}
}

string getCountryByPhoneNumber(const char *phoneNumber, vmIP ip, bool suppressStringLocal) {
	if(countryDetect) {
		string country = countryDetect->getCountryByPhoneNumber(phoneNumber, ip);
		if(suppressStringLocal && country == "local") {
			country = "";
		}
		return(country);
	}
	return("");
}

unsigned getCountryIdByPhoneNumber(const char *phoneNumber, vmIP ip) {
	if(countryDetect) {
		return(countryDetect->getCountryIdByPhoneNumber(phoneNumber, ip));
	}
	return(0);
}

bool isLocalByPhoneNumber(const char *phoneNumber, vmIP ip) {
	if(countryDetect) {
		return(countryDetect->isLocalByPhoneNumber(phoneNumber, ip));
	}
	return(false);
}

string getCountryByIP(vmIP ip, bool suppressStringLocal) {
	if(countryDetect) {
		string country = countryDetect->getCountryByIP(ip);
		if(suppressStringLocal && country == "local") {
			country = "";
		}
		return(country);
	}
	return("");
}

unsigned int getCountryIdByIP(vmIP ip)
{
	if(countryDetect) {
		return(countryDetect->getCountryIdByIP(ip));
	}
	return(0);
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


void reassignCountries(const char *params) {
	JsonItem jsonData;
	jsonData.parse(params);
	bool by_src_number = atoi(jsonData.getValue("by_src_number").c_str());
	bool by_dst_number = atoi(jsonData.getValue("by_dst_number").c_str());
	bool by_src_ip = atoi(jsonData.getValue("by_src_ip").c_str());
	bool by_dst_ip = atoi(jsonData.getValue("by_dst_ip").c_str());
	reassignCountriesLoop(by_src_number, by_dst_number, by_src_ip, by_dst_ip);
}

void reassignCountriesLoop(bool by_src_number, bool by_dst_number, bool by_src_ip, bool by_dst_ip) {
	CountryDetectInit();
	cout << "reassign_countries - "
	     << "by_src_number: " << by_src_number << ", "
	     << "by_dst_number: " << by_dst_number << ", "
	     << "by_src_ip: " << by_src_ip << ", "
	     << "by_dst_ip: " << by_dst_ip << endl;
	cout << "ready\n" << flush;
	SqlDb *sqlDb = createSqlObject();
	char gets_buffer[1000*20];
	bool existsColumnCdrCalldate = sqlDb->existsColumn("cdr", "calldate");
	bool existsColumnCdrCountryCodeCalldate = sqlDb->existsColumn("cdr_country_code", "calldate");
	while(fgets(gets_buffer, sizeof(gets_buffer) - 1, stdin)) {
		int gets_buffer_length = strlen(gets_buffer);
		while(gets_buffer[gets_buffer_length - 1] == '\n') {
			gets_buffer[gets_buffer_length - 1] = 0;
			--gets_buffer_length;
		}
		if(!strncmp(gets_buffer, "ids:", 4)) {
			vector<int> ids = split2int(gets_buffer + 4, ',');
			if(ids.size()) {
				string queryStr = string(
						  "select cdr.id, cdr.sipcallerip, cdr.sipcalledip, cdr.caller, cdr.called,\
							  cdr_country_code.* from cdr\
						   left join cdr_country_code on (cdr_country_code.cdr_id = cdr.id") + 
						  (existsColumnCdrCalldate && existsColumnCdrCountryCodeCalldate ? " && cdr_country_code.calldate = cdr.calldate" : "") + 
						  ")\
						   where id in(" + implode(ids, ",") + ")";
				sqlDb->query(queryStr);
				SqlDb_rows rows;
				sqlDb->fetchRows(&rows);
				SqlDb_row row;
				while((row = rows.fetchRow())) {
					vmIP ip_src;
					vmIP ip_dst;
					ip_src.setIP(&row, "sipcallerip");
					ip_dst.setIP(&row, "sipcalledip");
					string number_src = row["caller"];
					string number_dst = row["called"];
					u_int64_t id = atoll(row["id"].c_str());
					string sipcallerip_country_code;
					string sipcalledip_country_code;
					string caller_number_country_code;
					string called_number_country_code;
					string sipcallerip_country_code_new;
					string sipcalledip_country_code_new;
					string caller_number_country_code_new;
					string called_number_country_code_new;
					unsigned int sipcallerip_country_code_id = 0;
					unsigned int sipcalledip_country_code_id = 0;
					unsigned int caller_number_country_code_id = 0;
					unsigned int called_number_country_code_id = 0;
					unsigned int sipcallerip_country_code_id_new = 0;
					unsigned int sipcalledip_country_code_id_new = 0;
					unsigned int caller_number_country_code_id_new = 0;
					unsigned int called_number_country_code_id_new = 0;
					SqlDb_row row_update;
					extern int opt_cdr_country_code;
					if(opt_cdr_country_code == 2) {
						sipcallerip_country_code_id = atol(row["sipcallerip_country_code"].c_str());
						sipcalledip_country_code_id = atol(row["sipcalledip_country_code"].c_str());
						caller_number_country_code_id = atol(row["caller_number_country_code"].c_str());
						called_number_country_code_id = atol(row["called_number_country_code"].c_str());
						if(by_src_ip) {
							sipcallerip_country_code_id_new = getCountryIdByIP(ip_src);
							if(sipcallerip_country_code_id_new != sipcallerip_country_code_id) {
								row_update.add(sipcallerip_country_code_id_new, "sipcallerip_country_code", !sipcallerip_country_code_id_new);
							}
						}
						if(by_dst_ip) {
							sipcalledip_country_code_id_new = getCountryIdByIP(ip_dst);
							if(sipcalledip_country_code_id_new != sipcalledip_country_code_id) {
								row_update.add(sipcalledip_country_code_id_new, "sipcalledip_country_code", !sipcalledip_country_code_id_new);
							}
						}
						if(by_src_number) {
							caller_number_country_code_id_new = getCountryIdByPhoneNumber(number_src.c_str(), ip_src);
							if(caller_number_country_code_id_new != caller_number_country_code_id) {
								row_update.add(caller_number_country_code_id_new, "caller_number_country_code", !caller_number_country_code_id_new);
							}
						}
						if(by_dst_number) {
							called_number_country_code_id_new = getCountryIdByPhoneNumber(number_dst.c_str(), ip_dst);
							if(called_number_country_code_id_new != called_number_country_code_id) {
								row_update.add(called_number_country_code_id_new, "called_number_country_code", !called_number_country_code_id_new);
							}
						}
						cout << "reassign countries cdr.id: " << id << " - "
						     << ip_src.getString() << ": " << sipcallerip_country_code_id_new << ", "
						     << ip_dst.getString() << ": " << sipcalledip_country_code_id_new << ", "
						     << number_src << ": " << caller_number_country_code_id_new << ", "
						     << number_dst << ": " << called_number_country_code_id_new << endl;
					} else {
						sipcallerip_country_code = row["sipcallerip_country_code"];
						sipcalledip_country_code = row["sipcalledip_country_code"];
						caller_number_country_code = row["caller_number_country_code"];
						called_number_country_code = row["called_number_country_code"];
						if(by_src_ip) {
							sipcallerip_country_code_new = getCountryByIP(ip_src, true);
							if(sipcallerip_country_code_new != sipcallerip_country_code) {
								row_update.add(sipcallerip_country_code_new, "sipcallerip_country_code", sipcallerip_country_code_new.empty());
							}
						}
						if(by_dst_ip) {
							sipcalledip_country_code_new = getCountryByIP(ip_dst, true);
							if(sipcalledip_country_code_new != sipcalledip_country_code) {
								row_update.add(sipcalledip_country_code_new, "sipcalledip_country_code", sipcalledip_country_code_new.empty());
							}
						}
						if(by_src_number) {
							caller_number_country_code_new = getCountryByPhoneNumber(number_src.c_str(), ip_src, true);
							if(caller_number_country_code_new != caller_number_country_code) {
								row_update.add(caller_number_country_code_new, "caller_number_country_code", caller_number_country_code_new.empty());
							}
						}
						if(by_dst_number) {
							called_number_country_code_new = getCountryByPhoneNumber(number_dst.c_str(), ip_dst, true);
							if(called_number_country_code_new != called_number_country_code) {
								row_update.add(called_number_country_code_new, "called_number_country_code", called_number_country_code_new.empty());
							}
						}
						cout << "reassign countries cdr.id: " << id << " - "
						     << ip_src.getString() << ": " << sipcallerip_country_code_new << ", "
						     << ip_dst.getString() << ": " << sipcalledip_country_code_new << ", "
						     << number_src << ": " << caller_number_country_code_new << ", "
						     << number_dst << ": " << called_number_country_code_new << endl;
					}
					if(!row_update.isEmpty()) {
						SqlDb_row row_cond;
						row_cond.add(id, "cdr_id");
						if(existsColumnCdrCountryCodeCalldate) {
							row_cond.add(row["calldate"], "calldate");
						}
						sqlDb->update("cdr_country_code", row_update, row_cond);
					}
				}
			}
		} else if(!strncmp(gets_buffer, "end", 3)) {
			break;
		}
		cout << "ready\n" << flush;
	}
	delete sqlDb;
}
