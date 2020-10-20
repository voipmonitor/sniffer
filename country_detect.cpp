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

void CheckInternational::setSkipPrefixes(const char *prefixes, vector<string> *separators) {
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
	setSkipPrefixes((*dbRow)["skip_prefixes"].c_str(), &prefixesSeparators);
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
				sqlDb->query("select * from sensors where id_sensor = " + intToString(opt_id_sensor));
				SqlDb_row row;
				if((row = sqlDb->fetchRow()) &&
				   atoi(row["override_country_prefixes"].c_str())) {
					okTable = true;
					sqlDb->query("select * \
						      from customer_country_prefix_sensors \
						      where advanced_mode and \
							    sensor_id = " + row["id"]);
				}
			}
		} else {
			if(sqlDb->existsTable("customer_country_prefix") &&
			   !sqlDb->emptyTable("customer_country_prefix") &&
			   sqlDb->existsColumn("customer_country_prefix", "advanced_mode")) {
				okTable = true;
				sqlDb->query("select * \
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
				if(row["trim_prefix_length"].length()) {
					recAdv->trim_prefix_length = atoi(row["trim_prefix_length"].c_str());
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

bool CheckInternational::processCustomerDataAdvanced(const char *number, 
						     bool *isInternational, string *country, string *numberWithoutPrefix) {
	if(!this->customer_data_advanced.size()) {
		return(false);
	}
	for(unsigned i = 0; i < this->customer_data_advanced.size(); i++) {
		CountryPrefix_recAdv *recAdv = this->customer_data_advanced[i];
		int number_length = strlen(number);
		if(recAdv->number_regexp_cond &&
		   recAdv->number_regexp_cond->match(number) &&
		   (recAdv->number_length_from == -1 || number_length >= recAdv->number_length_from) &&
		   (recAdv->number_length_to == -1 || number_length <= recAdv->number_length_to)) {
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
					this->skipPrefixes(number, &recAdv->trim_prefixes_string, &recAdv->trim_prefixes_regexp, true, numberWithoutPrefix);
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

bool CheckInternational::skipPrefixes(const char *number, vector<string> *prefixes_string, vector<cRegExp*> *prefixes_regexp, bool recurse,
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
	bool existsPrefix = false;
	do {
		existsPrefix = false;
		if(prefixes_string) {
			for(unsigned i = 0; i < prefixes_string->size(); i++) {
				if((number_length - *skipPrefixLength) > (*prefixes_string)[i].length() &&
				   !strncmp(number + *skipPrefixLength, (*prefixes_string)[i].c_str(), (*prefixes_string)[i].length()) &&
				   (!isInternationalPrefixes ||
				    !internationalMinLengthPrefixesStrict ||
				    !internationalMinLength ||
				    (number_length - *skipPrefixLength) >= (internationalMinLength + (*prefixes_string)[i].length()))) {
					existsPrefix = true;
					*skipPrefixLength += (*prefixes_string)[i].length();
					skipPrefixes->push_back((*prefixes_string)[i]);
				}
			}
		}
		if(!existsPrefix && prefixes_regexp) {
			for(unsigned i = 0; i < prefixes_regexp->size(); i++) {
				vector<string> matches;
				if((*prefixes_regexp)[i]->match(number + *skipPrefixLength, &matches) &&
				   matches.size() &&
				   (number_length - *skipPrefixLength) > matches[0].length() &&
				   (!isInternationalPrefixes ||
				    !internationalMinLengthPrefixesStrict ||
				    !internationalMinLength ||
				    (number_length - *skipPrefixLength) >= (internationalMinLength + matches[0].length()))) {
					existsPrefix = true;
					*skipPrefixLength += matches[0].length();
					skipPrefixes->push_back(matches[0]);
				}
			}
		}
	} while(existsPrefix && recurse);
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

string CheckInternational::numberNormalized(const char *number, CountryPrefixes *countryPrefixes) {
	if(countryPrefixes->loadOK) {
		string numberNormalized;
		countryPrefixes->getCountry(number, NULL, NULL,
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
			row["descr"].c_str()));
	}
	std::sort(data.begin(), data.end());
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
					okTable = true;
					sqlDb->query("select * \
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
				sqlDb->query(existsColumnAdvancedMode ?
					      "select * \
					       from customer_country_prefix \
					       where advanced_mode is null or not advanced_mode \
					       order by prefix" :
					      "select * \
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
					row["descr"].c_str()));
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

string CountryPrefixes::getCountry(const char *number, vector<string> *countries, string *country_prefix,
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
	if(checkInternational->processCustomerDataAdvanced(numberOrig.c_str(), 
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
			string country = this->_getCountry(_numberWithoutPrefix.c_str(), countries, country_prefix);
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
	while(numberNormalized[0] == '0' || 
	      (!internationalPrefix.length() && numberNormalized[0] == '+')) {
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
			string country = this->_getCountry(numberNormalizedNapa.c_str(), countries, country_prefix);
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
	string country = this->_getCountry(numberNormalized.c_str(), countries, country_prefix);
	if(rsltNumberNormalized) {
		*rsltNumberNormalized = numberNormalized;
	}
	return(country);
}

string CountryPrefixes::_getCountry(const char *number, vector<string> *countries, string *country_prefix) {
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

string CountryDetect::getCountryByPhoneNumber(const char *phoneNumber) {
	string rslt;
	lock();
	if(countryPrefixes->loadOK) {
		rslt = countryPrefixes->getCountry(phoneNumber, NULL, NULL, checkInternational);
	}
	unlock();
	return(rslt);
}

unsigned CountryDetect::getCountryIdByPhoneNumber(const char *phoneNumber) {
	unsigned rslt = 0;
	lock();
	if(countryPrefixes->loadOK) {
		string rslt_str = countryPrefixes->getCountry(phoneNumber, NULL, NULL, checkInternational);
		if(!rslt_str.empty()) {
			rslt = countryCodes->getIdCountry(rslt_str.c_str());
		}
	}
	unlock();
	return(rslt);
}

bool CountryDetect::isLocalByPhoneNumber(const char *phoneNumber) {
	bool rslt = false;
	lock();
	if(countryPrefixes->loadOK) {
		rslt = countryPrefixes->isLocal(phoneNumber, checkInternational);
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

string getCountryByPhoneNumber(const char *phoneNumber, bool suppressStringLocal) {
	if(countryDetect) {
		string country = countryDetect->getCountryByPhoneNumber(phoneNumber);
		if(suppressStringLocal && country == "local") {
			country = "";
		}
		return(country);
	}
	return("");
}

unsigned getCountryIdByPhoneNumber(const char *phoneNumber) {
	if(countryDetect) {
		return(countryDetect->getCountryIdByPhoneNumber(phoneNumber));
	}
	return(0);
}

bool isLocalByPhoneNumber(const char *phoneNumber) {
	if(countryDetect) {
		return(countryDetect->isLocalByPhoneNumber(phoneNumber));
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
