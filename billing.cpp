#include <math.h>

#include "voipmonitor.h"
#include "billing.h"


#define UNSET_STRING string("unset")


extern int opt_id_sensor;
extern int opt_nocdr;


cBillingAssignment::cBillingAssignment(eBilingTypeAssignment typeAssignment) {
	this->typeAssignment = typeAssignment;
}

void cBillingAssignment::load(SqlDb_row *row, SqlDb *sqlDb) {
	id = atol((*row)["id"].c_str());
	billing_rule_id = atol((*row)["id_billing"].c_str());
	name = (*row)["name"];
	limitation_for_sensors = atol((*row)["limitation_for_sensors"].c_str());
	checkInternational.load(row, sqlDb);
}

bool cBillingAssignment::isSensorOk(SqlDb *sqlDb) {
	if(!limitation_for_sensors || opt_id_sensor <= 0) {
		return(true);
	}
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	bool rslt = false;
	if(sqlDb->existsTable(typeAssignment == _billing_ta_operator ? 
			       "billing_operator_assignment_sensors" :
			       "billing_customer_assignment_sensors")) {
		sqlDb->query((typeAssignment == _billing_ta_operator ?
			       "select sensors.id_sensor \
				from billing_operator_assignment_sensors \
				join sensors on (sensors.id = billing_operator_assignment_sensors.id_sensor) \
				where id_operator_assignment = " :
			       "select sensors.id_sensor \
				from billing_customer_assignment_sensors \
				join sensors on (sensors.id = billing_customer_assignment_sensors.id_sensor) \
				where id_customer_assignment = ") + intToString(id));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			if(atoi(row["id_sensor"].c_str()) == opt_id_sensor) {
				rslt = true;
				break;
			}
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(rslt);
}

void cBillingAssignment::loadCond(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable(typeAssignment == _billing_ta_operator ? 
			       "billing_operator_assignment_addresses" :
			       "billing_customer_assignment_addresses")) {
		sqlDb->query((typeAssignment == _billing_ta_operator ?
			       "select * \
				from billing_operator_assignment_addresses \
				where id_operator_assignment = " :
			       "select * \
				from billing_customer_assignment_addresses \
				where id_customer_assignment = ") + intToString(id));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			list_ip.add(mysql_ip_2_vmIP(&row, "ip"), atoi(row["mask"].c_str()));
		}
	}
	if(sqlDb->existsTable(typeAssignment == _billing_ta_operator ?
			       "billing_operator_assignment_numbers" :
			       "billing_customer_assignment_numbers")) {
		sqlDb->query((typeAssignment == _billing_ta_operator ?
			       "select * \
				from billing_operator_assignment_numbers \
				where id_operator_assignment = " :
			       "select * \
				from billing_customer_assignment_numbers \
				where id_customer_assignment = ") + intToString(id));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			list_number.add(row["number"].c_str(), !atoi(row["fixed"].c_str()));
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

bool cBillingAssignment::checkIP(vmIP ip) {
	return(list_ip.checkIP(ip));
}

bool cBillingAssignment::checkNumber(const char *number) {
	return(list_number.checkNumber(number));
}


cBillingAssignments::cBillingAssignments() {
       _sync = 0;
}

cBillingAssignments::~cBillingAssignments() {
       clear();
}

void cBillingAssignments::load(SqlDb *sqlDb) {
	lock();
	clear(false);
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("billing_operator_assignment")) {
		sqlDb->query("select * \
			      from billing_operator_assignment");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			cBillingAssignment *assignment = new FILE_LINE(0) cBillingAssignment(_billing_ta_operator);
			assignment->load(&row, sqlDb);
			operators[assignment->id] = assignment;
		}
	}
	if(sqlDb->existsTable("billing_customer_assignment")) {
		sqlDb->query("select * \
			      from billing_customer_assignment");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			cBillingAssignment *assignment = new FILE_LINE(0) cBillingAssignment(_billing_ta_customer);
			assignment->load(&row, sqlDb);
			customers[assignment->id] = assignment;
		}
	}
	for(map<unsigned, cBillingAssignment*>::iterator iter = operators.begin(); iter != operators.end();) {
		if(iter->second->isSensorOk(sqlDb)) {
			iter->second->loadCond(sqlDb);
			iter++;
		} else {
			delete iter->second;
			operators.erase(iter++);
		}
	}
	for(map<unsigned, cBillingAssignment*>::iterator iter = customers.begin(); iter != customers.end();) {
		if(iter->second->isSensorOk(sqlDb)) {
			iter->second->loadCond(sqlDb);
			iter++;
		} else {
			delete iter->second;
			customers.erase(iter++);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	unlock();
}

void cBillingAssignments::clear(bool useLock) {
	if(useLock) {
		lock();
	}
	for(map<unsigned, cBillingAssignment*>::iterator iter = operators.begin(); iter != operators.end(); iter++) {
		delete iter->second;
	}
	operators.clear();
	for(map<unsigned, cBillingAssignment*>::iterator iter = customers.begin(); iter != customers.end(); iter++) {
		delete iter->second;
	}
	customers.clear();
	if(useLock) {
		unlock();
	}
}

unsigned cBillingAssignments::findBillingRuleIdForIP(vmIP ip, eBilingTypeAssignment typeAssignment,
						     unsigned *assignment_id) {
	unsigned rslt = 0;
	*assignment_id = 0;
	lock();
	map<unsigned, cBillingAssignment*> *assignments = typeAssignment == _billing_ta_operator ? &operators : &customers;
	for(map<unsigned, cBillingAssignment*>::iterator iter = assignments->begin(); iter != assignments->end(); iter++) {
		if(iter->second->checkIP(ip)) {
			rslt = iter->second->billing_rule_id;
			*assignment_id = iter->first;
			break;
		}
	}
	unlock();
	return(rslt);
}

unsigned cBillingAssignments::findBillingRuleIdForNumber(const char *number, eBilingTypeAssignment typeAssignment,
							 unsigned *assignment_id, CountryPrefixes *countryPrefixes) {
	unsigned rslt = 0;
	*assignment_id = 0;
	lock();
	map<unsigned, cBillingAssignment*> *assignments = typeAssignment == _billing_ta_operator ? &operators : &customers;
	for(map<unsigned, cBillingAssignment*>::iterator iter = assignments->begin(); iter != assignments->end(); iter++) {
		if(countryPrefixes) {
			string numberNormalized = iter->second->checkInternational.numberNormalized(number, countryPrefixes);
			if(iter->second->checkNumber(numberNormalized.c_str())) {
				rslt = iter->second->billing_rule_id;
				*assignment_id = iter->first;
				break;
			}
		} else {
			if(iter->second->checkNumber(number)) {
				rslt = iter->second->billing_rule_id;
				*assignment_id = iter->first;
				break;
			}
		}
	}
	unlock();
	return(rslt);
}


cBillingExclude::cBillingExclude(bool agregation) {
	this->agregation = agregation;
	_sync = 0;
}

void cBillingExclude::load(SqlDb *sqlDb) {
	lock();
	list_ip_src.clear();
	list_ip_dst.clear();
	list_number_src.clear();
	list_number_dst.clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable(agregation ? "billing_agregation_exclude_addresses" : "billing_exclude_addresses")) {
		sqlDb->query(string(
			     "select * \
			      from ") + (agregation ? "billing_agregation_exclude_addresses" : "billing_exclude_addresses"));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			if(row["side"] == "src" || row["side"] == "both") {
				list_ip_src.add(mysql_ip_2_vmIP(&row, "ip"), atoi(row["mask"].c_str()));
			}
			if(row["side"] == "dst" || row["side"] == "both") {
				list_ip_dst.add(mysql_ip_2_vmIP(&row, "ip"), atoi(row["mask"].c_str()));
			}
		}
	}
	if(sqlDb->existsTable(agregation ? "billing_agregation_exclude_numbers" : "billing_exclude_numbers")) {
		sqlDb->query(string(
			     "select * \
			      from ") + (agregation ? "billing_agregation_exclude_numbers" : "billing_exclude_numbers"));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			if(row["side"] == "src" || row["side"] == "both") {
				list_number_src.add(row["number"].c_str(), !atoi(row["fixed"].c_str()));
			}
			if(row["side"] == "dst" || row["side"] == "both") {
				list_number_dst.add(row["number"].c_str(), !atoi(row["fixed"].c_str()));
			}
		}
	}
	if(sqlDb->existsTable(agregation ? "billing_agregation_exclude_domains" : "billing_exclude_domains")) {
		sqlDb->query(string(
			     "select * \
			      from ") + (agregation ? "billing_agregation_exclude_domains" : "billing_exclude_domains"));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			if(row["side"] == "src" || row["side"] == "both") {
				list_domain_src.add(row["domain"].c_str());
			}
			if(row["side"] == "dst" || row["side"] == "both") {
				list_domain_dst.add(row["domain"].c_str());
			}
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	unlock();
}

bool cBillingExclude::checkIP(vmIP ip, eBilingSide side) {
	lock();
	bool rslt = side == _billing_side_src ? 
		     list_ip_src.checkIP(ip) :
		     list_ip_dst.checkIP(ip);
	unlock();
	return(rslt);
}

bool cBillingExclude::checkNumber(const char *number, eBilingSide side) {
	lock();
	bool rslt = side == _billing_side_src ? 
		     list_number_src.checkNumber(number) :
		     list_number_dst.checkNumber(number);
	unlock();
	return(rslt);
}

bool cBillingExclude::checkDomain(const char *domain, eBilingSide side) {
	if(!domain) {
		return(false);
	}
	lock();
	bool rslt = side == _billing_side_src ? 
		     list_domain_src.check(domain) :
		     list_domain_dst.check(domain);
	unlock();
	return(rslt);
}


void cStateHolidays::sHoliday::load(SqlDb_row *row) {
	type = (*row)["type_holiday"] == "fixed" ?         _billing_holiday_fixed :
	       (*row)["type_holiday"] == "movable" ?       _billing_holiday_movable :
	       (*row)["type_holiday"] == "easter_monday" ? _billing_holiday_easter_monday :
	       (*row)["type_holiday"] == "easter_friday" ? _billing_holiday_easter_friday :
						           _billing_holiday_na;
	switch(type) {
	case _billing_holiday_fixed:
		day.tm_mday = atoi((*row)["month_day"].c_str());
		day.tm_mon = atoi((*row)["month"].c_str());
		if(day.tm_mday && day.tm_mon) {
			day.tm_mon -= 1;
		} else {
			type = _billing_holiday_na;
			day.tm_mday = 0;
			day.tm_mon = 0;
		}
		break;
	case _billing_holiday_movable:
		day = stringToTm((*row)["date"].c_str());
		break;
	case _billing_holiday_easter_monday:
	case _billing_holiday_easter_friday:
	case _billing_holiday_na:
		break;
	}
}

bool cStateHolidays::sHoliday::isHoliday(tm &day, const char *timezone) {
	switch(type) {
	case _billing_holiday_fixed:
		return(this->day.tm_mon == day.tm_mon &&
		       this->day.tm_mday == day.tm_mday);
	case _billing_holiday_movable:
		return(this->day.tm_year == day.tm_year &&
		       this->day.tm_mon == day.tm_mon &&
		       this->day.tm_mday == day.tm_mday);
	case _billing_holiday_easter_monday:
		return(isEasterMondayDate(day, 0, timezone));
	case _billing_holiday_easter_friday:
		return(isEasterMondayDate(day, 3, timezone));
	case _billing_holiday_na:
		break;
	}
	return(false);
}


void cStateHolidays::load(SqlDb_row *row) {
	id = atol((*row)["id"].c_str());
	name = (*row)["name"];
	country_code = (*row)["country_code"];
}

void cStateHolidays::loadHolidays(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("holiday_state_date")) {
		sqlDb->query("select * \
			      from holiday_state_date \
			      where id_holiday_state = " + intToString(id));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			sHoliday holiday;
			holiday.load(&row);
			holidays.push_back(holiday);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

bool cStateHolidays::isHoliday(tm &day, const char *timezone) {
	for(list<sHoliday>::iterator iter = holidays.begin(); iter != holidays.end(); iter++) {
		if(iter->isHoliday(day, timezone)) {
			return(true);
		}
	}
	return(false);
}


cStatesHolidays::cStatesHolidays() {
	_sync = 0;
}

void cStatesHolidays::load(SqlDb *sqlDb) {
	lock();
	holidays.clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("holiday_state")) {
		sqlDb->query("select * \
			      from holiday_state");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			cStateHolidays stateHolidays;
			stateHolidays.load(&row);
			holidays[stateHolidays.id] = stateHolidays;
		}
	}
	for(map<unsigned, cStateHolidays>::iterator iter = holidays.begin(); iter != holidays.end(); iter++) {
		iter->second.loadHolidays(sqlDb);
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	unlock();
}

bool cStatesHolidays::isHoliday(unsigned id, tm &day, const char *timezone) {
	bool rslt = false;
	lock();
	if(holidays.find(id) != holidays.end()) {
		rslt = holidays[id].isHoliday(day, timezone);
	}
	unlock();
	return(rslt);
}


cPeakDefinition::cPeakDefinition() {
	enable = false;
}

void cPeakDefinition::load(SqlDb_row *row, const char *fieldNamePrefix) {
	string _fieldNamePrefix = fieldNamePrefix ? fieldNamePrefix : "";
	peak_starts_hour = atoi((*row)[_fieldNamePrefix + "peak_starts_hour"].c_str());
	peak_starts_minute = atoi((*row)[_fieldNamePrefix + "peak_starts_minute"].c_str());
	peak_ends_hour = atoi((*row)[_fieldNamePrefix + "peak_ends_hour"].c_str());
	peak_ends_minute = atoi((*row)[_fieldNamePrefix + "peak_ends_minute"].c_str());
	weekend_start = atoi((*row)[_fieldNamePrefix + "weekend_start"].c_str());
}

bool cPeakDefinition::peakCheck(tm &time, cStateHolidays *holidays, tm *toTime, const char *timezone) {
	tm _toTime;
	if(!toTime) {
		toTime = &_toTime;
	}
	*toTime = getNextBeginDate(time, timezone);
	if(!enable) {
		return(false);
	}
	int week_day_1 = weekend_start ? weekend_start : 7;
	int week_day_2 = week_day_1 == 7 ? 1 : week_day_1 + 1;
	if(time.tm_wday == week_day_1 - 1 ||
	   time.tm_wday == week_day_2 - 1) {
		return(false);
	}
	if(holidays && holidays->isHoliday(time, timezone)) {
		return(false);
	}
	if(peak_starts_hour || peak_ends_hour) {
		if((peak_ends_hour * 60 + peak_ends_minute) > (peak_starts_hour * 60 + peak_starts_minute)) {
			if((time.tm_hour * 60 + time.tm_min) < (int)(peak_starts_hour * 60 + peak_starts_minute)) {
				*toTime = time;
				toTime->tm_hour = peak_starts_hour;
				toTime->tm_min = peak_starts_minute;
			} else if((time.tm_hour * 60 + time.tm_min) < (int)(peak_ends_hour * 60 + peak_ends_minute)) {
				*toTime = time;
				toTime->tm_hour = peak_ends_hour;
				toTime->tm_min = peak_ends_minute;
				return(true);
			}
		} else if((peak_ends_hour * 60 + peak_ends_minute) < (peak_starts_hour * 60 + peak_starts_minute)) {
			if((time.tm_hour * 60 + time.tm_min) < (int)(peak_ends_hour * 60 + peak_ends_minute)) {
				*toTime = time;
				toTime->tm_hour = peak_ends_hour;
				toTime->tm_min = peak_ends_minute;
				return(true);
			} else if((time.tm_hour * 60 + time.tm_min) < (int)(peak_starts_hour * 60 + peak_starts_minute)) {
				*toTime = time;
				toTime->tm_hour = peak_starts_hour;
				toTime->tm_min = peak_starts_minute;
			} else {
				return(true);
			}
		}
	}
	return(false);
}


cBillingRuleNumber::cBillingRuleNumber() {
	regexp = NULL;
}

cBillingRuleNumber::~cBillingRuleNumber() {
	if(regexp) {
		delete regexp;
	}
}

void cBillingRuleNumber::load(SqlDb_row *row) {
	name = (*row)["name"];
	number_prefix = (*row)["prefix_number"];
	number_fixed = (*row)["fixed_number"];
	number_regex = (*row)["regex_number"];
	peak_definition.enable = atoi((*row)["override_default_peak_offpeak"].c_str());
	peak_definition.load(row);
	price = atof((*row)["price"].c_str());
	price_peak = atof((*row)["price_peak"].c_str());
	t1 = atoi((*row)["t1"].c_str());
	t2 = atoi((*row)["t2"].c_str());
	use_for_number_format = numberFormatEnum((*row)["use_for_number_format"].c_str());
	use_for_number_type = numberTypeEnum((*row)["use_for_number_type"].c_str());
}

void cBillingRuleNumber::regexp_create() {
	if(regexp) {
		delete regexp;
		regexp = NULL;
	}
	if(number_regex.length()) {
		regexp = new FILE_LINE(0) cRegExp(number_regex.c_str(), cRegExp::_regexp_icase_matches);
	}
}

cBillingRuleNumber::eNumberFormat cBillingRuleNumber::numberFormatEnum(const char *str) {
	return(!strcasecmp(str, "original") ? 
		_number_format_original :
	       !strcasecmp(str, "normalized") ? 
		 _number_format_normalized : 
	       !strcasecmp(str, "both") ? 
		_number_format_both :
		_number_format_na);
}

cBillingRuleNumber::eNumberType cBillingRuleNumber::numberTypeEnum(const char *str) {
	return(!strcasecmp(str, "local") ? 
		_number_type_local : 
	       !strcasecmp(str, "international") ? 
		_number_type_international :
	       !strcasecmp(str, "both") ? 
		_number_type_both :
		_number_type_na);
}

string cBillingRuleNumber::numberFormatString(eNumberFormat numbFormat) {
	return(numbFormat == _number_format_na ? "na" :
	       numbFormat == _number_format_original ? "original" :
	       numbFormat == _number_format_normalized ? "normalized" :
	       numbFormat == _number_format_both ? "original or normalized" : "unknown");
}

string cBillingRuleNumber::numberTypeString(eNumberType numbType) {
	return(numbType == _number_type_na ? "na" :
	       numbType == _number_type_local ? "local" :
	       numbType == _number_type_international ? "international" :
	       numbType == _number_type_both ? "local or international" : "unknown");
}


cBillingRule::~cBillingRule() {
	freeNumbers();
}

void cBillingRule::load(SqlDb_row *row) {
	id = atol((*row)["id"].c_str());
	name = (*row)["name"];
	holiday_id = atol((*row)["id_holiday_state"].c_str());
	peak_definition.enable = atoi((*row)["peak_offpeak"].c_str());
	peak_definition.load(row, "default_");
	price = atof((*row)["default_price"].c_str());
	price_peak = atof((*row)["default_price_peak"].c_str());
	t1 = atoi((*row)["default_t1"].c_str());
	t2 = atoi((*row)["default_t2"].c_str());
	use_for_number_format = cBillingRuleNumber::numberFormatEnum((*row)["default_use_for_number_format"].c_str());
	use_for_number_type = cBillingRuleNumber::numberTypeEnum((*row)["default_use_for_number_type"].c_str());
	default_customer = atoi((*row)["default_customer_billing"].c_str());
	currency_code = (*row)["currency_code"];
	currency_id = atoi((*row)["currency_id"].c_str());
	timezone_name = (*row)["timezone_name"];
}

void cBillingRule::loadNumbers(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	freeNumbers();
	if(sqlDb->existsTable("billing_rule")) {
		sqlDb->query("select * \
			      from billing_rule \
			      where id_billing = " + intToString(id));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			cBillingRuleNumber *number = new FILE_LINE(0) cBillingRuleNumber;
			number->load(&row);
			numbers.push_back(number);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cBillingRule::freeNumbers() {
	for(list<cBillingRuleNumber*>::iterator iter = numbers.begin(); iter != numbers.end(); iter++) {
		delete *iter;
	}
	numbers.clear();
}

double cBillingRule::billing(time_t time, unsigned duration, const char *number, const char *number_normalized,
			     bool isLocalNumber, cStateHolidays *holidays, const char *timezone,
			     vector<string> *debug) {
	tm time_tm = time_r(&time, timezone_name.length() ? timezone_name.c_str() : timezone);
	if(!duration) {
		duration = 1;
	}
	double price = this->price;
	double price_peak = this->price_peak;
	unsigned t1 = this->t1;
	unsigned t2 = this->t2;
	cBillingRuleNumber::eNumberFormat number_format_default = this->use_for_number_format == cBillingRuleNumber::_number_format_na ?
								   cBillingRuleNumber::_number_format_both : this->use_for_number_format;
	cBillingRuleNumber::eNumberType number_type_default = this->use_for_number_type == cBillingRuleNumber::_number_type_na ?
							       cBillingRuleNumber::_number_type_both : this->use_for_number_type;
	cPeakDefinition peak_definition = this->peak_definition;
	bool findNumber = false;
	string findNumberDebugStr;
	struct {
		int pattern_type;
		string pattern_name;
		string pattern;
		string number;
		cBillingRuleNumber::eNumberFormat number_format;
		cBillingRuleNumber::eNumberType number_type;
	} findNumberDebugData;
	if(numbers.size()) {
		unsigned useRegexMatchLength = 0;
		unsigned useNumberPrefixLength = 0;
		for(unsigned pass = 0; pass < 3 && !findNumber; pass++) {
			for(list<cBillingRuleNumber*>::iterator iter = numbers.begin(); iter != numbers.end(); iter++) {
				cBillingRuleNumber::eNumberFormat number_format = (*iter)->use_for_number_format == cBillingRuleNumber::_number_format_na ?
										   number_format_default : (*iter)->use_for_number_format;
				cBillingRuleNumber::eNumberType number_type = (*iter)->use_for_number_type == cBillingRuleNumber::_number_type_na ?
									       number_type_default : (*iter)->use_for_number_type;
				if(!(number_type == cBillingRuleNumber::_number_type_both ||
				     number_type == (isLocalNumber ? cBillingRuleNumber::_number_type_local : cBillingRuleNumber::_number_type_international))) {
					continue;
				}
				bool ok = false;
				unsigned regex_match_length = 0;
				if(debug) {
					findNumberDebugData.pattern_type = pass;
					findNumberDebugData.pattern_name = (*iter)->name;
					findNumberDebugData.number_type = isLocalNumber ? cBillingRuleNumber::_number_type_local : cBillingRuleNumber::_number_type_international;
				}
				switch(pass) {
				case 0:
					if((*iter)->number_fixed.length()) {
						if((number_format == cBillingRuleNumber::_number_format_original || 
						    number_format == cBillingRuleNumber::_number_format_both) &&
						   (*iter)->number_fixed == number) {
							ok = true;
							if(debug) {
								findNumberDebugData.pattern = (*iter)->number_fixed;
								findNumberDebugData.number = (*number ? number : UNSET_STRING);
								findNumberDebugData.number_format = cBillingRuleNumber::_number_format_original;
							}
						}
						if(number_normalized &&
						   (number_format == cBillingRuleNumber::_number_format_normalized || 
						    number_format == cBillingRuleNumber::_number_format_both) &&
						   (*iter)->number_fixed == number_normalized) {
							ok = true;
							if(debug) {
								findNumberDebugData.pattern = (*iter)->number_fixed;
								findNumberDebugData.number = (*number_normalized ? number_normalized : UNSET_STRING);
								findNumberDebugData.number_format = cBillingRuleNumber::_number_format_normalized;
							}
						}
					}
					break;
				case 1:
					if((*iter)->number_regex.length()) {
						if(!(*iter)->regexp) {
							(*iter)->regexp_create();
						}
						if((*iter)->regexp->isOK()) {
							if(number_format == cBillingRuleNumber::_number_format_original || 
							   number_format == cBillingRuleNumber::_number_format_both) {
								vector<string> matches;
								if((*iter)->regexp->match(number, &matches) > 0) {
									for(unsigned i = 0; i < matches.size(); i++) {
										if(matches[i].length() > regex_match_length) {
											regex_match_length = matches[i].length();
											if(debug) {
												findNumberDebugData.pattern = (*iter)->number_regex;
												findNumberDebugData.number = (*number ? number : UNSET_STRING);
												findNumberDebugData.number_format = cBillingRuleNumber::_number_format_original;
											}
										}
									}
								}
							}
							if(number_normalized &&
							   (number_format == cBillingRuleNumber::_number_format_normalized || 
							    number_format == cBillingRuleNumber::_number_format_both)) {
								vector<string> matches;
								if((*iter)->regexp->match(number_normalized, &matches) > 0) {
									for(unsigned i = 0; i < matches.size(); i++) {
										if(matches[i].length() > regex_match_length) {
											regex_match_length = matches[i].length();
											if(debug) {
												findNumberDebugData.pattern = (*iter)->number_regex;
												findNumberDebugData.number = (*number_normalized ? number_normalized : UNSET_STRING);
												findNumberDebugData.number_format = cBillingRuleNumber::_number_format_normalized;
											}
										}
									}
								}
							}
							if(regex_match_length > 0 &&
							   (!useRegexMatchLength || regex_match_length > useRegexMatchLength)) {
								ok = true;
							}
						}
					}
					break;
				case 2:
					if((*iter)->number_prefix.length()) {
						if((number_format == cBillingRuleNumber::_number_format_original || 
						    number_format == cBillingRuleNumber::_number_format_both) &&
						   (*iter)->number_prefix == string(number, min(strlen(number), (*iter)->number_prefix.length())) &&
						   (!useNumberPrefixLength || (*iter)->number_prefix.length() > useNumberPrefixLength)) {
							ok = true;
							if(debug) {
								findNumberDebugData.pattern = (*iter)->number_prefix;
								findNumberDebugData.number = (*number ? number : UNSET_STRING);
								findNumberDebugData.number_format = cBillingRuleNumber::_number_format_original;
							}
						}
						if(number_normalized &&
						   (number_format == cBillingRuleNumber::_number_format_normalized || 
						    number_format == cBillingRuleNumber::_number_format_both) &&
						   (*iter)->number_prefix == string(number_normalized, min(strlen(number_normalized), (*iter)->number_prefix.length())) &&
						   (!useNumberPrefixLength || (*iter)->number_prefix.length() > useNumberPrefixLength)) {
							ok = true;
							if(debug) {
								findNumberDebugData.pattern = (*iter)->number_prefix;
								findNumberDebugData.number = (*number_normalized ? number_normalized : UNSET_STRING);
								findNumberDebugData.number_format = cBillingRuleNumber::_number_format_normalized;
							}
						}
					}
					break;
				}
				if(ok) {
					if((*iter)->price) {
						price = (*iter)->price;
					}
					if((*iter)->price_peak) {
						price_peak = (*iter)->price_peak;
					}
					if((*iter)->t1) {
						t1 = (*iter)->t1;
					}
					if((*iter)->t2) {
						t2 = (*iter)->t2;
					}
					if((*iter)->peak_definition.enable) {
						peak_definition = (*iter)->peak_definition;
					}
					findNumber = true;
					if(debug) {
						findNumberDebugStr = "number '" + findNumberDebugData.number + "' " +
								     "matched with pattern named '" + findNumberDebugData.pattern_name + "' "
								     " - pattern type: '" + (findNumberDebugData.pattern_type == 0 ? "fixed length pattern" :
											     findNumberDebugData.pattern_type == 1 ? "regexp pattern" :
																     "prefix pattern") + "', " + 
								     "pattern: '" + findNumberDebugData.pattern + "', " + 
								     "format: '" + cBillingRuleNumber::numberFormatString(findNumberDebugData.number_format) + "', " + 
								     "area: '" + cBillingRuleNumber::numberTypeString(findNumberDebugData.number_type) + "'";
					}
					if(pass == 0) {
						break;
					} else if(pass == 1) {
						useRegexMatchLength = regex_match_length;
					} else if(pass == 2) {
						useNumberPrefixLength = (*iter)->number_prefix.length();
					}
				}
			}
		}
	}
	if(!t1 || !t2 ||
	   !price ||
	   (peak_definition.enable && !price_peak)) {
		return(0);
	}
	if(findNumber) {
		if(debug && !findNumberDebugStr.empty()) {
			debug->push_back(findNumberDebugStr);
		}
	} else {
		if(debug) {
			debug->push_back((numbers.size() ? 
					   "number '" + (*number ? number : UNSET_STRING) + "' (normalized to '" + (*number_normalized ? number_normalized : UNSET_STRING) + "') " + 
					   "does not match with any pattern in billing table '" + name + "'" :
					   "not exists patterns for number '" + (*number ? number : UNSET_STRING) + "' (normalized to '" + (*number_normalized ? number_normalized : UNSET_STRING) + "') in billing table '" + name + "'") + 
					 " - using default price which is set in table '" + name + "'");
		}
	}
	if(debug) {
		debug->push_back("selected tarification: " + 
				 (peak_definition.enable ?
				   "peak price = " + floatToString(price_peak, 6, true) + ", offpeak price = " + floatToString(price, 6, true) :
				   "price = " + floatToString(price, 6, true)) + ", " + 
				 "t1 = " + intToString(t1) + ", t2 = " + intToString(t2));
	}
	double rslt_price = 0;
	int duration_rest = duration;
	tm time_iter = time_tm;
	unsigned count_iter = 0;
	while(duration_rest > 0) {
		unsigned duration_iter = count_iter == 0 && t1 != t2 ?
					  t1 :
					  duration_rest;
		bool peak = false;
		if(peak_definition.enable) {
			tm time_iter_to;
			peak = peak_definition.peakCheck(time_iter, holidays, &time_iter_to, timezone);
			unsigned max_duration_iter = diffTime(time_iter_to, time_iter, timezone);
			if(max_duration_iter < duration_iter && count_iter > 0) {
				duration_iter = max_duration_iter;
			}
		}
		unsigned t = count_iter == 0 ? t1 : t2;
		duration_iter = (duration_iter / t + (duration_iter % t ? 1 : 0)) * t;
		double price_iter = (duration_iter / t) *
				    (peak ? price_peak : price) * t / 60;
		rslt_price += price_iter;
		time_iter = dateTimeAdd(time_iter, duration_iter, timezone);
		duration_rest -= duration_iter;
		if(debug) {
			debug->push_back("price calculation: " + 
					 (peak_definition.enable ? 
					   string("is_peak: ") + (peak ? "yes" : "no") + ", " : 
					   "") +
					 "tarification: " + floatToString(peak ? price_peak : price, 6, true) + " " + intToString(t1) + "/" + intToString(t2) + ", " +
					 "duration: " + intToString(duration_iter) + ", " +
					 "price: " + floatToString(price_iter, 6, true)); 
		}
		++count_iter;
	}
	return(rslt_price);
}


cBillingRules::cBillingRules() {
	_sync = 0;
}

cBillingRules::~cBillingRules() {
	clear();
}

void cBillingRules::load(SqlDb *sqlDb) {
	lock();
	clear(false);
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("billing")) {
		sqlDb->query(sqlDb->existsTable("currency") ?
			      "select billing.*, \
				      currency.id as currency_id \
			       from billing \
			       left join currency on (currency.code = billing.currency_code)" :
			      "select * \
			       from billing");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			cBillingRule *rule = new FILE_LINE(0) cBillingRule;
			rule->load(&row);
			rules[rule->id] = rule;
		}
	}
	for(map<unsigned, cBillingRule*>::iterator iter = rules.begin(); iter != rules.end(); iter++) {
		iter->second->loadNumbers(sqlDb);
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	unlock();
}

void cBillingRules::clear(bool useLock) {
	if(useLock) {
		lock();
	}
	for(map<unsigned, cBillingRule*>::iterator iter = rules.begin(); iter != rules.end(); iter++) {
		delete iter->second;
	}
	rules.clear();
	if(useLock) {
		unlock();
	}
}

unsigned cBillingRules::getDefaultCustomerBillingId() {
	for(map<unsigned, cBillingRule*>::iterator iter = rules.begin(); iter != rules.end(); iter++) {
		if(iter->second->default_customer) {
			return(iter->first);
		}
	}
	return(0);
}


cBillingAgregationSettings::cBillingAgregationSettings() {
	clear();
}

void cBillingAgregationSettings::load(SqlDb *sqlDb) {
	clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("billing_agregation_settings")) {
		sqlDb->query("select * \
			      from billing_agregation_settings");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			settings.enable_by_ip = atoi(row["enable_by_ip"].c_str());
			settings.enable_by_number = atoi(row["enable_by_number"].c_str());
			settings.enable_by_domain = atoi(row["enable_by_domain"].c_str());
			settings.week_start = atoi(row["week_start"].c_str());
			settings.hours_history_in_days = atoi(row["hours_history_in_days"].c_str());
			settings.days_history_in_weeks = atoi(row["days_history_in_weeks"].c_str());
			settings.weeks_history_in_months = atoi(row["weeks_history_in_months"].c_str());
			settings.months_history_in_years = atoi(row["months_history_in_years"].c_str());
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cBillingAgregationSettings::clear() {
	settings.enable_by_ip = false;
	settings.enable_by_number = false;
	settings.enable_by_domain = false;
	settings.week_start = 2;
	settings.hours_history_in_days = 7;
	settings.days_history_in_weeks = 4;
	settings.weeks_history_in_months = 6;
	settings.months_history_in_years = 4;
}


cCurrency::cCurrency() {
	_sync = 0;
}

void cCurrency::load(SqlDb *sqlDb) {
	lock();
	clear(false);
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("currency")) {
		sqlDb->query("select * \
			      from currency");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			sCurrencyItem item;
			item.id = atoi(row["id"].c_str());
			item.code = row["code"];
			item.name = row["name"];
			item.country_code = row["country_code"];
			item.main_currency = atoi(row["main_currency"].c_str());
			item.exchange_rate = atof(row["exchange_rate"].c_str());
			items.push_back(item);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	unlock();
}

void cCurrency::clear(bool useLock) {
	if(useLock) {
		lock();
	}
	items.clear();
	if(useLock) {
		unlock();
	}
}

double cCurrency::getExchangeRateToMainCurency(unsigned from_id) {
	double exchangeRate = 1;
	lock();
	for(list<sCurrencyItem>::iterator iter = items.begin(); iter != items.end(); iter++) {
		if(iter->id == from_id && iter->exchange_rate) {
			exchangeRate = iter->main_currency ? 1 : iter->exchange_rate;
			break;
		}
	}
	unlock();
	return(exchangeRate);
}

string cCurrency::getCurrencyCode(unsigned id) {
	string code;
	if(id) {
		lock();
		for(list<sCurrencyItem>::iterator iter = items.begin(); iter != items.end(); iter++) {
			if(iter->id == id) {
				code = iter->code;
				break;
			}
		}
		unlock();
	}
	return(code);
}


cBilling::cBilling() {
	_sync = 0;
	set = false;
	rules = new FILE_LINE(0) cBillingRules;
	assignments = new FILE_LINE(0) cBillingAssignments;
	exclude = new FILE_LINE(0) cBillingExclude;
	holidays = new FILE_LINE(0) cStatesHolidays;
	countryPrefixes = new FILE_LINE(0) CountryPrefixes;
	checkInternational = new FILE_LINE(0) CheckInternational;
	agreg_exclude = new FILE_LINE(0) cBillingExclude(true);
	agreg_settings = new FILE_LINE(0) cBillingAgregationSettings;
	currency = new FILE_LINE(0) cCurrency;
}

cBilling::~cBilling() {
	delete rules;
	delete assignments;
	delete exclude;
	delete holidays;
	delete countryPrefixes;
	delete checkInternational;
	delete agreg_exclude;
	delete agreg_settings;
	delete currency;
}

void cBilling::load(SqlDb *sqlDb) {
	if(sverb.disable_billing) {
		return;
	}
	lock();
	rules->load(sqlDb);
	assignments->load(sqlDb);
	exclude->load(sqlDb);
	holidays->load(sqlDb);
	countryPrefixes->load(sqlDb);
	checkInternational->load(sqlDb);
	agreg_exclude->load(sqlDb);
	agreg_settings->load(sqlDb);
	currency->load(sqlDb);
	gui_timezone = getGuiTimezone(sqlDb);
	set = rules->rules.size() > 0;
	unlock();
	createMysqlPartitionsBillingAgregation(sqlDb);
}

bool cBilling::billing(time_t time, unsigned duration,
		       vmIP ip_src, vmIP ip_dst,
		       const char *number_src, const char *number_dst,
		       const char *domain_src, const char *domain_dst,
		       double *operator_price, double *customer_price,
		       unsigned *operator_currency_id, unsigned *customer_currency_id,
		       unsigned *operator_id, unsigned *customer_id,
		       unsigned force_operator_id, unsigned force_customer_id,
		       bool use_exclude_rules,
		       vector<string> *operator_debug, vector<string> *customer_debug) {
	bool rslt = false;
	*operator_price = 0;
	*customer_price = 0;
	*operator_currency_id = 0;
	*customer_currency_id = 0;
	*operator_id = 0;
	*customer_id = 0;
	lock();
	string number_src_normalized = checkInternational->numberNormalized(number_src, countryPrefixes);
	string number_dst_normalized = checkInternational->numberNormalized(number_dst, countryPrefixes);
	if(!use_exclude_rules ||
	   (!exclude->checkIP(ip_src, _billing_side_src) &&
	    !exclude->checkIP(ip_dst, _billing_side_dst) &&
	    !exclude->checkNumber(number_src_normalized.c_str(), _billing_side_src) &&
	    !exclude->checkNumber(number_dst_normalized.c_str(), _billing_side_dst) &&
	    !exclude->checkDomain(domain_src, _billing_side_src) &&
	    !exclude->checkDomain(domain_dst, _billing_side_dst))) {
		unsigned operator_assignment_id = 0;
		unsigned customer_assignment_id = 0;
		if(force_operator_id) {
			if(rules->rules.find(force_operator_id) != rules->rules.end()) {
				*operator_id = force_operator_id;
			} else {
				*operator_id = 0;
			}
		} else {
			*operator_id = assignments->findBillingRuleIdForIP(ip_dst, _billing_ta_operator,
									   &operator_assignment_id);
			if(*operator_id) {
				if(operator_debug) {
					operator_debug->push_back(string("assigned operator for called ip ") + 
								  "'" + (ip_dst.isSet() ? ip_dst.getString() : UNSET_STRING) + "': " + 
								  "'" + assignments->operators[operator_assignment_id]->name + "'");
					operator_debug->push_back("billing table '" + rules->rules[*operator_id]->name + "' selected");
				}
			} else {
				*operator_id = assignments->findBillingRuleIdForNumber(number_dst, _billing_ta_operator,
										       &operator_assignment_id, countryPrefixes);
				if(*operator_id && operator_debug) {
					operator_debug->push_back(string("assigned operator for called number ") + 
								  "'" + (*number_dst ? number_dst : UNSET_STRING) + "': " + 
								  "'" + assignments->operators[operator_assignment_id]->name + "'");
					operator_debug->push_back("billing table '" + rules->rules[*operator_id]->name + "' selected");
				}
			}
			if(!*operator_id) {
				if(operator_debug) {
					operator_debug->push_back(string("called ip ") + 
								  "'" + (ip_dst.isSet() ? ip_dst.getString() : UNSET_STRING) + "'" + 
								  " and called number " + 
								  "'" + (*number_dst ? number_dst : UNSET_STRING) + "' " +
								  "does not match with any operator in assign table");
				}
			}
		}
		if(force_customer_id) {
			if(rules->rules.find(force_customer_id) != rules->rules.end()) {
				*customer_id = force_customer_id;
			} else {
				*customer_id = 0;
			}
		} else {
			*customer_id = assignments->findBillingRuleIdForIP(ip_src, _billing_ta_customer,
									   &customer_assignment_id);
			if(*customer_id) {
				if(customer_debug) {
					customer_debug->push_back(string("assigned customer for caller ip ") + 
								  "'" + (ip_src.isSet() ? ip_src.getString() : UNSET_STRING) + "': " + 
								  "'" + assignments->customers[customer_assignment_id]->name + "'");
					customer_debug->push_back("billing table '" + rules->rules[*customer_id]->name + "' selected");
				}
			} else {
				*customer_id = assignments->findBillingRuleIdForNumber(number_src, _billing_ta_customer,
										       &customer_assignment_id, countryPrefixes);
				if(*customer_id && customer_debug) {
					customer_debug->push_back(string("assigned customer for caller number ") + 
								  "'" + (*number_src ? number_src : UNSET_STRING) + "': " + 
								  "'" + assignments->customers[customer_assignment_id]->name + "'");
					customer_debug->push_back("billing table '" + rules->rules[*customer_id]->name + "' selected");
				}
			}
			if(!*customer_id) {
				if(customer_debug) {
					customer_debug->push_back(string("caller ip ") + 
								  "'" + (ip_src.isSet() ? ip_src.getString() : UNSET_STRING) + "'" +
								  " and caller number " + 
								  "'" + (*number_src ? number_src : UNSET_STRING) + "' " + 
								  "does not match with any customer in assign table");
				}
				*customer_id = rules->getDefaultCustomerBillingId();
				if(*customer_id && customer_debug) {
					customer_debug->push_back("default billing table '" + rules->rules[*customer_id]->name + "' selected");
				}
			}
		}
		if(*operator_id) {
			rslt = true;
			string number_dst_normalized_billing = operator_assignment_id ?
								assignments->operators[operator_assignment_id]->checkInternational.numberNormalized(number_dst, countryPrefixes) :
								number_dst_normalized;
			if(operator_debug) {
				if(number_dst_normalized_billing != number_dst) {
					operator_debug->push_back("called number '" + (*number_dst ? number_dst : UNSET_STRING) + "' " + 
								  "normalized to: '" + number_dst_normalized_billing + "'");
				}
			}
			cStateHolidays *holidays = rules->rules[*operator_id]->holiday_id ?
						     &this->holidays->holidays[rules->rules[*operator_id]->holiday_id] :
						     NULL;
			CheckInternational *_checkInternational = operator_assignment_id ?
								   &assignments->operators[operator_assignment_id]->checkInternational :
								   checkInternational;
			bool isLocalNumber = countryPrefixes->isLocal(number_dst, _checkInternational);
			if(operator_debug) {
				operator_debug->push_back("called number '" + (*number_dst ? number_dst : UNSET_STRING) + "' " + 
							  "detected as: " + (isLocalNumber ? "local" : "international"));
			}
			*operator_price = rules->rules[*operator_id]->billing(time, duration, number_dst, number_dst_normalized_billing.c_str(),
									      isLocalNumber, holidays, gui_timezone.c_str(),
									      operator_debug);
			*operator_currency_id = rules->rules[*operator_id]->currency_id;
		}
		if(*customer_id) {
			rslt = true;
			string number_dst_normalized_billing = customer_assignment_id ?
								assignments->customers[customer_assignment_id]->checkInternational.numberNormalized(number_dst, countryPrefixes) :
								number_dst_normalized;
			if(customer_debug) {
				if(number_dst_normalized_billing != number_dst) {
					customer_debug->push_back("called number '" + (*number_dst ? number_dst : UNSET_STRING) + "' " + 
								  "normalized to: '" + number_dst_normalized_billing + "'");
				}
			}
			cStateHolidays *holidays = rules->rules[*customer_id]->holiday_id ?
						     &this->holidays->holidays[rules->rules[*customer_id]->holiday_id] :
						     NULL;
			CheckInternational *_checkInternational = customer_assignment_id ?
								   &assignments->customers[customer_assignment_id]->checkInternational :
								   checkInternational;
			bool isLocalNumber = countryPrefixes->isLocal(number_dst, _checkInternational);
			if(customer_debug) {
				customer_debug->push_back("called number '" + (*number_dst ? number_dst : UNSET_STRING) + "' " + 
							  "detected as: " + (isLocalNumber ? "local" : "international"));
			}
			*customer_price = rules->rules[*customer_id]->billing(time, duration, number_dst, number_dst_normalized_billing.c_str(),
									      isLocalNumber, holidays, gui_timezone.c_str(),
									      customer_debug);
			*customer_currency_id = rules->rules[*customer_id]->currency_id;
		}
	}
	unlock();
	return(rslt);
}

bool cBilling::saveAggregation(time_t time,
			       vmIP ip_src, vmIP ip_dst,
			       const char *number_src, const char *number_dst,
			       const char *domain_src, const char *domain_dst,
			       double operator_price, double customer_price,
			       unsigned operator_currency_id, unsigned customer_currency_id,
			       list<string> *inserts) {
	lock();
	sBillingAgregationSettings agregSettings = this->getAgregSettings();
	if(!agregSettings.enable_by_ip && 
	   !agregSettings.enable_by_number &&
	   !agregSettings.enable_by_domain) {
		unlock();
		return(false);
	}
	string number_src_normalized = checkInternational->numberNormalized(number_src, countryPrefixes);
	string number_dst_normalized = checkInternational->numberNormalized(number_dst, countryPrefixes);
	if(agreg_exclude->checkIP(ip_src, _billing_side_src) ||
	   agreg_exclude->checkIP(ip_dst, _billing_side_dst) ||
	   agreg_exclude->checkNumber(number_src_normalized.c_str(), _billing_side_src) ||
	   agreg_exclude->checkNumber(number_dst_normalized.c_str(), _billing_side_dst) ||
	   agreg_exclude->checkDomain(domain_src, _billing_side_src) ||
	   agreg_exclude->checkDomain(domain_dst, _billing_side_dst)) {
		unlock();
		return(false);
	}
	tm time_tm = time_r(&time, gui_timezone.c_str());
	int week_day = time_tm.tm_wday - (agregSettings.week_start - 1);
	if(week_day < 0) {
		week_day = week_day + 7;
	}
	tm week_start_time_tm = time_tm;
	for(int i = 0; i < week_day; i++) {
		week_start_time_tm = getPrevBeginDate(week_start_time_tm, gui_timezone.c_str());
	}
	vector<cBilling::sAgregationTypePart> typeParts = cBilling::getAgregTypeParts(&agregSettings);
	for(unsigned i = 0; i < typeParts.size(); i++) {
		char partName[20];
		char partTime[20];
		if(typeParts[i].type == "hour") {
			strftime(partName, sizeof(partName), "%Y%m%d", &time_tm);
			strftime(partTime, sizeof(partName), "%Y%m%d%H", &time_tm);
		} else if(typeParts[i].type == "day") {
			strftime(partName, sizeof(partName), "%Y%m%d", &week_start_time_tm);
			strftime(partTime, sizeof(partName), "%Y%m%d", &time_tm);
		} else if(typeParts[i].type == "week") {
			strftime(partName, sizeof(partName), "%Y%m", &time_tm);
			strftime(partTime, sizeof(partName), "%Y%m%d", &week_start_time_tm);
		} else if(typeParts[i].type == "month") {
			strftime(partName, sizeof(partName), "%Y", &time_tm);
			strftime(partTime, sizeof(partName), "%Y%m", &time_tm);
		}
		for(unsigned j = 0; j < 3; j++) {
			if(!((j == 0 && agregSettings.enable_by_ip && ip_src.isSet()) ||
			     (j == 1 && agregSettings.enable_by_number && *number_src) ||
			     (j == 2 && agregSettings.enable_by_domain && *domain_src))) {
				continue;
			}
			string type = typeParts[i].type;
			string type2 = (j == 0 ? "addresses" : 
				       (j == 1 ? "numbers" :
						 "domains"));
			string table = "billing_agregation_" + type + '_' + type2;
			string operator_price_str = intToString((int64_t)round(operator_price * 100000ll * 
									       currency->getExchangeRateToMainCurency(operator_currency_id)));
			string customer_price_str = intToString((int64_t)round(customer_price * 100000ll * 
									       currency->getExchangeRateToMainCurency(customer_currency_id)));
			string insert = 
				"insert ignore into " + table + " " +
				"values(" + partName + ", " + 
					    partTime + ", " +
					    (j == 0 ? 
					      ip_src.getStringForMysqlIpColumn(table.c_str(), "ip") : 
					    (j == 1 ? 
					      sqlEscapeStringBorder(string(number_src, min((int)strlen(number_src), 20))) :
					      sqlEscapeStringBorder(string(domain_src, min((int)strlen(domain_src), 32))))) + ", " +
					    (operator_price > 0 ? operator_price_str : "0") + ", " +
					    (customer_price > 0 ? customer_price_str : "0") + ") " + 
				"on duplicate key update " +
				"price_operator_mult100000 = price_operator_mult100000 + " + operator_price_str + ", " +
				"price_customer_mult100000 = price_customer_mult100000 + " + customer_price_str;
			inserts->push_back(insert);
		}
	}
	unlock();
	return(true);
}

vector<cBilling::sAgregationTypePart> cBilling::getAgregTypeParts(sBillingAgregationSettings *settings) {
	sAgregationTypePart typeParts[] = {
		{ "hour", "day_int", false, settings->hours_history_in_days + 2 },
		{ "day", "week_int", true, settings->days_history_in_weeks + 1 },
		{ "week", "month_int", false, settings->weeks_history_in_months + 1 },
		{ "month", "year_int", false, settings->months_history_in_years + 1 }
	};
	vector<cBilling::sAgregationTypePart> rslt;
	for(unsigned i = 0; i < sizeof(typeParts) / sizeof(typeParts[0]); i++) {
		rslt.push_back(typeParts[i]);
	}
	return(rslt);
}

string cBilling::getCurrencyCode(unsigned id) {
	string code;
	lock();
	if(isSet() && currency) {
		code = currency->getCurrencyCode(id);
	}
	unlock();
	return(code);
}

string cBilling::test(string calls_string, bool json_rslt) {
	vector<string> calls;
	vector<string> rslts;
	if(file_exists(calls_string)) {
		FILE *file = fopen(calls_string.c_str(), "r");
		calls_string = "";
		if(file) {
			char line[1000];
			while(fgets(line, sizeof(line), file)) {
				char *lf = strchr(line, '\n');
				if(lf) {
					*lf = 0;
				}
				if(*line) {
					if(!calls_string.empty()) {
						calls_string += ';';
					}
					calls_string += line;
				}
			}
			fclose(file);
		}
	}
	if(!calls_string.empty()) {
		if(calls_string[0] == '{' && calls_string[calls_string.length() - 1] == '}') {
			calls_string = '[' + calls_string + ']';
		}
		if(calls_string[0] == '[' && calls_string[calls_string.length() - 1] == ']') {
			JsonItem jsonCalls;
			jsonCalls.parse(calls_string);
			for(unsigned int i = 0; i < jsonCalls.getLocalCount(); i++) {
				JsonItem *jsonCall = jsonCalls.getLocalItem(i);
				string id = jsonCall->getValue("id");
				string sensor_id = jsonCall->getValue("sensor_id");
				string time = jsonCall->getValue("time");
				string duration = jsonCall->getValue("duration");
				string ip_src = jsonCall->getValue("ip_src");
				string ip_dst = jsonCall->getValue("ip_dst");
				string number_src = jsonCall->getValue("number_src");
				string number_dst = jsonCall->getValue("number_dst");
				string domain_src = jsonCall->getValue("domain_src");
				string domain_dst = jsonCall->getValue("domain_dst");
				string rslt = test(id.c_str(), time.c_str(), duration.c_str(),
						   ip_src.c_str(), ip_dst.c_str(),
						   number_src.c_str(), number_dst.c_str(),
						   domain_src.c_str(), domain_dst.c_str(),
						   sensor_id.c_str(),
						   NULL, NULL,
						   json_rslt);
				if(!rslt.empty()) {
					rslts.push_back(rslt);
				}
			}
		} else {
			calls = split(calls_string, ';');
			for(unsigned i = 0; i < calls.size(); i++) {
				vector<string> call = split(calls[i], ',');
				if(call.size() >= 6) {
					const char *time = call[0].c_str();
					const char *duration = call[1].c_str();
					const char *number_src = call[2].c_str();
					const char *number_dst = call[3].c_str();
					const char *ip_src = call[4].c_str();
					const char *ip_dst = call[5].c_str();
					const char *verify_operator_price = call.size() >= 7 ? call[6].c_str() : NULL;
					const char *verify_customer_price =  call.size() >= 8 ? call[7].c_str() : NULL;
					const char *domain_src = call.size() >= 9 ? call[8].c_str() : NULL;
					const char *domain_dst = call.size() >= 10 ? call[9].c_str() : NULL;
					const char *sensor_id = call.size() >= 11 ? call[10].c_str() : NULL;
					string rslt = test(NULL, time, duration,
							   ip_src, ip_dst,
							   number_src, number_dst,
							   domain_src, domain_dst,
							   sensor_id,
							   verify_operator_price, verify_customer_price,
							   json_rslt);
					if(!rslt.empty()) {
						rslts.push_back(rslt);
					}
				}
			}
		}
		if(rslts.size()) {
			if(json_rslt) {
				if(rslts.size() == 1) {
					return(rslts[0]);
				}
				string rslt = "[";
				for(unsigned i = 0; i < rslts.size(); i++) {
					if(i) {
						rslt += ",";
					}
					rslt += rslts[i];
				}
				rslt += "]";
				return(rslt);
			} else {
				string rslt;
				for(unsigned i = 0; i < rslts.size(); i++) {
					if(i) {
						rslt += "---\n";
					}
					rslt += rslts[i];
				}
				return(rslt);
			}
		}
	}
	return("");
}

string cBilling::test(const char *id, const char *time, const char *duration,
		      const char *ip_src, const char *ip_dst,
		      const char *number_src, const char *number_dst,
		      const char *domain_src, const char *domain_dst,
		      const char *sensor_id,
		      const char *verify_operator_price, const char *verify_customer_price,
		      bool json_rslt) {
	double operator_price; 
	double customer_price;
	unsigned operator_currency_id;
	unsigned customer_currency_id;
	unsigned operator_id;
	unsigned customer_id;
	vector<string> operator_debug, customer_debug;
	billing(stringToTime(time), atoi(duration),
		 str_2_vmIP(ip_src), str_2_vmIP(ip_dst),
		 number_src, number_dst,
		 domain_src, domain_dst,
		 &operator_price, &customer_price,
		 &operator_currency_id, &customer_currency_id,
		 &operator_id, &customer_id, 
		 0, 0,
		 false,
		 &operator_debug, &customer_debug);
	if(json_rslt) {
		JsonExport call;
		if(id) {
			call.add("id", id);
		}
		call.add("calldate", time);
		call.add("duration", duration);
		call.add("ip_src", ip_src);
		call.add("ip_dst", ip_dst);
		call.add("number_src", number_src);
		call.add("number_dst", number_dst);
		if(domain_src) {
			call.add("domain_src", domain_src);
		}
		if(domain_dst) {
			call.add("domain_dst", domain_dst);
		}
		call.add("operator_price", floatToString(operator_price, 6, true), JsonExport::_number);
		call.add("operator_currency_id", operator_currency_id);
		call.add("operator_currency_code", getCurrencyCode(operator_currency_id));
		call.add("operator_id", operator_id);
		call.add("customer_price", floatToString(customer_price, 6, true), JsonExport::_number);
		call.add("customer_currency_id", customer_currency_id);
		call.add("customer_currency_code", getCurrencyCode(customer_currency_id));
		call.add("customer_id", customer_id);
		JsonExport *call_operator_debug = call.addArray("operator_debug");
		for(unsigned i = 0; i < operator_debug.size(); i++) {
			call_operator_debug->add(NULL, operator_debug[i]);
		}
		JsonExport *call_customer_debug = call.addArray("customer_debug");
		for(unsigned i = 0; i < customer_debug.size(); i++) {
			call_customer_debug->add(NULL, customer_debug[i]);
		}
		return(call.getJson());
	} else {
		ostringstream out;
		unsigned labelWidth = 30;
		out << fixed;
		out << setw(labelWidth) << left << "calldate, duration:" << time << ", " << duration << endl;
		out << setw(labelWidth) << left << "numbers:" << number_src << " -> " << number_dst << endl;
		out << setw(labelWidth) << left << "IP:" << ip_src << " -> " << ip_dst << endl;
		out << setw(labelWidth) << left << "rslt operator price:" << operator_price;
		if(verify_operator_price && *verify_operator_price) {
			double _verify_operator_price = atof(verify_operator_price);
			if(round(_verify_operator_price * 1e6) == round(operator_price * 1e6)) {
				out << " (OK)";
			} else {
				out << " (errror - " << _verify_operator_price << ")";
			}
		}
		out << " / currency id: " << operator_currency_id << " / operator id: " << operator_id << endl;
		for(unsigned i = 0; i < operator_debug.size(); i++) {
			out << " - " << operator_debug[i] << endl;
		}
		out << setw(labelWidth) << left << "rslt customer price:" << customer_price;
		if(verify_customer_price && *verify_customer_price) {
			double test_customer_price = atof(verify_customer_price);
			if(round(test_customer_price * 1e6) == round(customer_price * 1e6)) {
				out << " (OK)";
			} else {
				out << " (errror - " << test_customer_price << ")";
			}
		}
		out << " / currency id: " << customer_currency_id << " / customer id: " << customer_id << endl;
		for(unsigned i = 0; i < customer_debug.size(); i++) {
			out << " - " << customer_debug[i] << endl;
		}
		return(out.str());
	}
	return("");
}

void cBilling::revaluationBilling(list<u_int64_t> *ids,
				  unsigned force_operator_id, unsigned force_customer_id,
				  bool use_exclude_rules) {
	SqlDb *sqlDb = createSqlObject();
	string queryStr = "select * from cdr where id in(" + implode(ids, ",") + ")";
	sqlDb->query(queryStr);
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	revaluationBilling(&rows, sqlDb, force_operator_id, force_customer_id, use_exclude_rules);
	delete sqlDb;
}

void cBilling::revaluationBilling(SqlDb_rows *rows, SqlDb *sqlDb,
				  unsigned force_operator_id, unsigned force_customer_id,
				  bool use_exclude_rules) {
	SqlDb_row row;
	string timezone = getGuiTimezone();
	while((row = rows->fetchRow())) {
		cout << "revaluation cdr.id: " << row["ID"] << endl;
		double connect_duration = atof(row["connect_duration"].c_str());
		if(!connect_duration) {
			continue;
		}
		u_int32_t calldate_s = mktime(row["calldate"].c_str(), timezone.c_str());
		vmIP ip_src;
		vmIP ip_dst;
		ip_src.setIP(&row, "sipcallerip");
		ip_dst.setIP(&row, "sipcalledip");
		string number_src = row["caller"];
		string number_dst = row["called"];
		string domain_src = row["caller_domain"];
		string domain_dst = row["called_domain"];
		bool extPrecisionOperator = row.getIndexField("price_operator_mult1000000") >= 0;
		bool extPrecisionCustomer = row.getIndexField("price_customer_mult1000000") >= 0;
		double operator_price_old = 0;
		double customer_price_old = 0;
		bool operator_price_old_set = false;
		bool customer_price_old_set = false;
		unsigned operator_currency_id_old = 0;
		unsigned customer_currency_id_old = 0;
		string priceOperatorField = extPrecisionOperator ? "price_operator_mult1000000" : "price_operator_mult100";
		string priceCustomerField = extPrecisionCustomer ? "price_customer_mult1000000" : "price_customer_mult100";
		double priceOperatorMult = extPrecisionOperator ? 1e6 : 1e2;
		double priceCustomerMult = extPrecisionCustomer ? 1e6 : 1e2;
		if(!row.isNull(priceOperatorField)) {
			operator_price_old_set = true;
			operator_price_old = atoll(row[priceOperatorField].c_str()) / priceOperatorMult;
		}
		operator_currency_id_old = atol(row["price_operator_currency_id"].c_str());
		if(!row.isNull(priceCustomerField)) {
			customer_price_old_set = true;
			customer_price_old = atoll(row[priceCustomerField].c_str()) / priceCustomerMult;
		}
		customer_currency_id_old = atol(row["price_customer_currency_id"].c_str());
		double operator_price = 0;
		double customer_price = 0;
		bool operator_price_set = false;
		bool customer_price_set = false;
		unsigned operator_currency_id = 0;
		unsigned customer_currency_id = 0;
		unsigned operator_id = 0;
		unsigned customer_id = 0;
		if(billing(calldate_s, connect_duration,
			   ip_src, ip_dst,
			   number_src.c_str(), number_dst.c_str(),
			   domain_src.c_str(), domain_dst.c_str(),
			   &operator_price, &customer_price,
			   &operator_currency_id, &customer_currency_id,
			   &operator_id, &customer_id,
			   force_operator_id, force_customer_id,
			   use_exclude_rules)) {
			if(operator_id) {
				operator_price_set = true;
			}
			if(customer_id) {
				customer_price_set = true;
			}
		}
		if(operator_price_set != operator_price_old_set ||
		   fabs(operator_price - operator_price_old) > 5e-7 ||
		   operator_currency_id != operator_currency_id_old ||
		   customer_price_set != customer_price_old_set ||
		   fabs(customer_price - customer_price_old) > 5e-7 ||
		   customer_currency_id != customer_currency_id_old) {
			bool set = false;
			SqlDb_row row_update;
			if(operator_price_set != operator_price_old_set ||
			   fabs(operator_price - operator_price_old_set) > 1e-7 ||
			   operator_currency_id != operator_currency_id_old) {
				if(operator_price_set) {
					row_update.add(round(operator_price * priceOperatorMult), priceOperatorField);
					row_update.add(operator_currency_id, "price_operator_currency_id", true);
					set = true;
				} else {
					row_update.add(0, priceOperatorField, true);
					row_update.add(0, "price_operator_currency_id", true);
					set = true;
				}
			}
			if(customer_price_set != customer_price_old_set ||
			   fabs(customer_price - customer_price_old_set) > 1e-7 ||
			   customer_currency_id != customer_currency_id_old) {
				if(customer_price_set) {
					row_update.add(round(customer_price * priceCustomerMult), priceCustomerField);
					row_update.add(customer_currency_id, "price_customer_currency_id", true);
					set = true;
				} else {
					row_update.add(0, priceCustomerField, true);
					row_update.add(0, "price_customer_currency_id", true);
					set = true;
				}
			}
			if(set) {
				SqlDb_row row_cond;
				row_cond.add(row["id"], "id");
				sqlDb->update("cdr", row_update, row_cond);
				if(fabs(operator_price - operator_price_old) > 5e-7 ||
				   fabs(customer_price - customer_price_old) > 5e-7) {
					list<string> aggregation_inserts;
					saveAggregation(calldate_s,
							ip_src, ip_dst,
							number_src.c_str(), number_dst.c_str(),
							domain_src.c_str(), domain_dst.c_str(),
							operator_price - operator_price_old,
							customer_price - customer_price_old,
							operator_currency_id,
							customer_currency_id,
							&aggregation_inserts);
					if(aggregation_inserts.size()) {
						bool disableLogErrorOld = sqlDb->getDisableLogError();
						unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
						sqlDb->setDisableLogError(true);
						sqlDb->setMaxQueryPass(1);
						for(list<string>::iterator iter = aggregation_inserts.begin(); iter != aggregation_inserts.end(); iter++) {
							sqlDb->query(*iter);
						}
						sqlDb->setMaxQueryPass(maxQueryPassOld);
						sqlDb->setDisableLogError(disableLogErrorOld);
					}
				}
			}
		}
	}
}


extern int opt_enable_billing;

cBilling *billing;


void initBilling(SqlDb *sqlDb) {
	if(opt_nocdr || !opt_enable_billing) {
		return;
	}
	if(!billing) {
		cBilling *_billing = new FILE_LINE(0) cBilling();
		billing = _billing;
		billing->load(sqlDb);
	}
}

void termBilling() {
	if(billing) {
		cBilling *_billing = billing;
		billing = NULL;
		delete _billing;
	}
}

void refreshBilling() {
	if(billing) {
		billing->load();
	}
}

void revaluationBilling(const char *params) {
	JsonItem jsonData;
	jsonData.parse(params);
	JsonItem *json_ids = jsonData.getItem("ids");
	if(!json_ids || !json_ids->getLocalCount()) {
		return;
	}
	list<u_int64_t> ids;
	for(unsigned i = 0; i < json_ids->getLocalCount(); i++) {
		JsonItem *json_id = json_ids->getLocalItem(i);
		if(json_id) {
			u_int64_t id = atoll(json_id->getLocalValue().c_str());
			if(id) {
				ids.push_back(id);
			}
		}
	}
	if(!ids.size()) {
		return;
	}
	unsigned force_operator_id = atol(jsonData.getValue("operator").c_str());
	unsigned force_customer_id = atol(jsonData.getValue("customer").c_str());
	bool use_exclude_rules = atoi(jsonData.getValue("use_exclude_rules").c_str()) > 0;
	revaluationBilling(&ids,
			   force_operator_id, force_customer_id,
			   use_exclude_rules);
}

void revaluationBilling(list<u_int64_t> *ids,
			unsigned force_operator_id, unsigned force_customer_id,
			bool use_exclude_rules) {
	map<int, SqlDb_rows*> sensor_rows;
	SqlDb *sqlDb = createSqlObject();
	string queryStr = "select * from cdr where id in(" + implode(ids, ",") + ")";
	sqlDb->query(queryStr);
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		int id_sensor = row.isNull("id_sensor") ? -1 : atoi(row["id_sensor"].c_str());
		map<int, SqlDb_rows*>::iterator iter = sensor_rows.find(id_sensor);
		if(iter == sensor_rows.end()) {
			sensor_rows[id_sensor] = new FILE_LINE(0) SqlDb_rows;
		}
		sensor_rows[id_sensor]->push(&row);
	}
	for(map<int, SqlDb_rows*>::iterator iter = sensor_rows.begin(); iter != sensor_rows.end(); iter++) {
		opt_enable_billing = true;
		opt_id_sensor = iter->first;
		cBilling *billing = new FILE_LINE(0) cBilling();
		billing->load(sqlDb);
		billing->revaluationBilling(iter->second, sqlDb, force_operator_id, force_customer_id, use_exclude_rules);
		delete billing;
	}
	delete sqlDb;
}

/*
		SqlDb *sqlDb = createSqlObject();
		initBilling(sqlDb);
*/
