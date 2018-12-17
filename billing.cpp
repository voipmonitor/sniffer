#include <math.h>

#include "voipmonitor.h"
#include "billing.h"


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
			list_ip.add(atol(row["ip"].c_str()), atoi(row["mask"].c_str()));
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

bool cBillingAssignment::checkIP(u_int32_t ip) {
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

unsigned cBillingAssignments::findBillingRuleIdForIP(u_int32_t ip, eBilingTypeAssignment typeAssignment,
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
				list_ip_src.add(atol(row["ip"].c_str()), atoi(row["mask"].c_str()));
			}
			if(row["side"] == "dst" || row["side"] == "both") {
				list_ip_dst.add(atol(row["ip"].c_str()), atoi(row["mask"].c_str()));
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
	if(_createSqlObject) {
		delete sqlDb;
	}
	unlock();
}

bool cBillingExclude::checkIP(u_int32_t ip, eBilingSide side) {
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


void cBillingRuleNumber::load(SqlDb_row *row) {
	name = (*row)["name"];
	number_prefix = (*row)["prefix_number"];
	number_fixed = (*row)["fixed_number"];
	peak_definition.enable = atoi((*row)["override_default_peak_offpeak"].c_str());
	peak_definition.load(row);
	price = atof((*row)["price"].c_str());
	price_peak = atof((*row)["price_peak"].c_str());
	t1 = atoi((*row)["t1"].c_str());
	t2 = atoi((*row)["t2"].c_str());
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
	if(sqlDb->existsTable("billing_rule")) {
		sqlDb->query("select * \
			      from billing_rule \
			      where id_billing = " + intToString(id));
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			cBillingRuleNumber number;
			number.load(&row);
			numbers.push_back(number);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

double cBillingRule::billing(time_t time, unsigned duration, const char *number, const char *number_normalized,
			     cStateHolidays *holidays, const char *timezone) {
	tm time_tm = time_r(&time, timezone_name.length() ? timezone_name.c_str() : timezone);
	if(!duration) {
		duration = 1;
	}
	double price = this->price;
	double price_peak = this->price_peak;
	unsigned t1 = this->t1;
	unsigned t2 = this->t2;
	cPeakDefinition peak_definition = this->peak_definition;
	if(numbers.size()) {
		bool findNumber = false;
		unsigned useNumberPrefixLength = 0;
		for(unsigned pass = 0; pass < 2 && !findNumber; pass++) {
			for(list<cBillingRuleNumber>::iterator iter = numbers.begin(); iter != numbers.end(); iter++) {
				if(pass == 0 ?
				    iter->number_fixed.length() &&
				    (iter->number_fixed == number ||
				     (number_normalized && iter->number_fixed == number_normalized)) :
				    iter->number_prefix.length() &&
				    (iter->number_prefix == string(number, min(strlen(number), iter->number_prefix.length())) ||
				     (number_normalized && iter->number_prefix == string(number_normalized, min(strlen(number_normalized), iter->number_prefix.length())))) &&
				    (!useNumberPrefixLength || iter->number_prefix.length() > useNumberPrefixLength)) {
					if(iter->price) {
						price = iter->price;
					}
					if(iter->price_peak) {
						price_peak = iter->price_peak;
					}
					if(iter->t1) {
						t1 = iter->t1;
					}
					if(iter->t2) {
						t2 = iter->t2;
					}
					if(iter->peak_definition.enable) {
						peak_definition = iter->peak_definition;
					}
					findNumber = true;
					if(pass == 0) {
						break;
					} else {
						useNumberPrefixLength = iter->number_prefix.length();
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
		rslt_price += (duration_iter / t) *
			      (peak ? price_peak : price) * t / 60;
		time_iter = dateTimeAdd(time_iter, duration_iter, timezone);
		duration_rest -= duration_iter;
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


cBilling::cBilling() {
	_sync = 0;
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
	unlock();
	createMysqlPartitionsBillingAgregation(sqlDb);
}

bool cBilling::billing(time_t time, unsigned duration,
		       u_int32_t ip_src, u_int32_t ip_dst,
		       const char *number_src, const char *number_dst,
		       double *operator_price, double *customer_price,
		       unsigned *operator_currency_id, unsigned *customer_currency_id,
		       unsigned *operator_id, unsigned *customer_id) {
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
	if(!exclude->checkIP(ip_src, _billing_side_src) &&
	   !exclude->checkIP(ip_dst, _billing_side_dst) &&
	   !exclude->checkNumber(number_src_normalized.c_str(), _billing_side_src) &&
	   !exclude->checkNumber(number_dst_normalized.c_str(), _billing_side_dst)) {
		unsigned operator_assignment_id = 0;
		unsigned customer_assignment_id = 0;
		*operator_id = assignments->findBillingRuleIdForIP(ip_dst, _billing_ta_operator,
								   &operator_assignment_id);
		if(!*operator_id) {
			*operator_id = assignments->findBillingRuleIdForNumber(number_dst, _billing_ta_operator,
									       &operator_assignment_id, countryPrefixes);
		}
		*customer_id = assignments->findBillingRuleIdForIP(ip_src, _billing_ta_customer,
								   &customer_assignment_id);
		if(!*customer_id) {
			*customer_id = assignments->findBillingRuleIdForNumber(number_src, _billing_ta_customer,
									       &customer_assignment_id, countryPrefixes);
		}
		if(!*customer_id) {
			*customer_id = rules->getDefaultCustomerBillingId();
		}
		if(*operator_id) {
			rslt = true;
			string number_dst_normalized_billing = assignments->operators[operator_assignment_id]->checkInternational.numberNormalized(number_dst, countryPrefixes);
			cStateHolidays *holidays = rules->rules[*operator_id]->holiday_id ?
						     &this->holidays->holidays[rules->rules[*operator_id]->holiday_id] :
						     NULL;
			*operator_price = rules->rules[*operator_id]->billing(time, duration, number_dst, number_dst_normalized.c_str(),
									      holidays, gui_timezone.c_str());
			*operator_currency_id = rules->rules[*operator_id]->currency_id;
		}
		if(*customer_id) {
			rslt = true;
			string number_dst_normalized_billing = customer_assignment_id ?
								assignments->customers[customer_assignment_id]->checkInternational.numberNormalized(number_dst, countryPrefixes) :
								number_dst_normalized;
			cStateHolidays *holidays = rules->rules[*customer_id]->holiday_id ?
						     &this->holidays->holidays[rules->rules[*customer_id]->holiday_id] :
						     NULL;
			*customer_price = rules->rules[*customer_id]->billing(time, duration, number_dst, number_dst_normalized.c_str(),
									      holidays, gui_timezone.c_str());
			*customer_currency_id = rules->rules[*customer_id]->currency_id;
		}
	}
	unlock();
	return(rslt);
}

list<string> cBilling::saveAgregation(time_t time,
				      u_int32_t ip_src, u_int32_t ip_dst,
				      const char *number_src, const char *number_dst,
				      double operator_price, double customer_price,
				      unsigned operator_currency_id, unsigned customer_currency_id) {
	list<string> inserts;
	lock();
	sBillingAgregationSettings agregSettings = this->getAgregSettings();
	if(!agregSettings.enable_by_ip && !agregSettings.enable_by_number) {
		unlock();
		return(inserts);
	}
	string number_src_normalized = checkInternational->numberNormalized(number_src, countryPrefixes);
	string number_dst_normalized = checkInternational->numberNormalized(number_dst, countryPrefixes);
	if(exclude->checkIP(ip_src, _billing_side_src) ||
	   exclude->checkIP(ip_dst, _billing_side_dst) ||
	   exclude->checkNumber(number_src_normalized.c_str(), _billing_side_src) ||
	   exclude->checkNumber(number_dst_normalized.c_str(), _billing_side_dst)) {
		unlock();
		return(inserts);
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
		for(unsigned j = 0; j < 2; j++) {
			if(!((j == 0 && agregSettings.enable_by_ip && ip_src) ||
			     (j == 1 && agregSettings.enable_by_number && *number_src))) {
				continue;
			}
			string type = typeParts[i].type;
			string type2 = (j == 0 ? "addresses" : "numbers");
			string table = "billing_agregation_" + type + '_' + type2;
			string operator_price_str = intToString((u_int64_t)round(operator_price * 100000ll * 
										 currency->getExchangeRateToMainCurency(operator_currency_id)));
			string customer_price_str = intToString((u_int64_t)round(customer_price * 100000ll * 
										 currency->getExchangeRateToMainCurency(customer_currency_id)));
			string insert = 
				"insert ignore into " + table + " " +
				"values(" + partName + ", " + 
					    partTime + ", " +
					    (j == 0 ? 
					      intToString(ip_src) : 
					      sqlEscapeStringBorder(string(number_src, min((int)strlen(number_src), 20)))) + ", " +
					    operator_price_str + ", " +
					    customer_price_str + ") " + 
				"on duplicate key update " +
				"price_operator_mult100000 = price_operator_mult100000 + " + operator_price_str + ", " +
				"price_customer_mult100000 = price_customer_mult100000 + " + customer_price_str;
			inserts.push_back(insert);
		}
	}
	unlock();
	return(inserts);
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
