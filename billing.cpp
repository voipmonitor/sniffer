#include "voipmonitor.h"
#include "billing.h"


cBillingAssignment::cBillingAssignment(eBilingTypeAssignment typeAssignment) {
	this->typeAssignment = typeAssignment;
}

void cBillingAssignment::load(SqlDb_row *row) {
	id = atol((*row)["id"].c_str());
	billing_rule_id = atol((*row)["id_billing"].c_str());
	name = (*row)["name"];
	checkInternational.load(row);
}

void cBillingAssignment::loadCond(SqlDb *sqlDb) {
	bool initSqlDb = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		initSqlDb = true;
	}
	sqlDb->query((typeAssignment == _billing_ta_operator ?
		       "select * \
			from billing_operator_assignment_addresses \
			where id_operator_assignment = " :
		       "select * \
			from billing_customer_assignment_addresses \
			where id_customer_assignment = ") + intToString(id));
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		list_ip.add(atol(row["ip"].c_str()), atoi(row["mask"].c_str()));
	}
	sqlDb->query((typeAssignment == _billing_ta_operator ?
		       "select * \
			from billing_operator_assignment_numbers \
			where id_operator_assignment = " :
		       "select * \
			from billing_customer_assignment_numbers \
			where id_customer_assignment = ") + intToString(id));
	while((row = sqlDb->fetchRow())) {
		list_number.add(row["number"].c_str(), !atoi(row["fixed"].c_str()));
	}
	if(initSqlDb) {
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
	bool initSqlDb = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		initSqlDb = true;
	}
	sqlDb->query("select * \
		      from billing_operator_assignment");
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		cBillingAssignment *assignment = new FILE_LINE(0) cBillingAssignment(_billing_ta_operator);
		assignment->load(&row);
		operators[assignment->id] = assignment;
	}
	sqlDb->query("select * \
		      from billing_customer_assignment");
	while((row = sqlDb->fetchRow())) {
		cBillingAssignment *assignment = new FILE_LINE(0) cBillingAssignment(_billing_ta_customer);
		assignment->load(&row);
		customers[assignment->id] = assignment;
	}
	for(map<unsigned, cBillingAssignment*>::iterator iter = operators.begin(); iter != operators.end(); iter++) {
		iter->second->loadCond(sqlDb);
	}
	for(map<unsigned, cBillingAssignment*>::iterator iter = customers.begin(); iter != customers.end(); iter++) {
		iter->second->loadCond(sqlDb);
	}
	if(initSqlDb) {
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


cBillingExclude::cBillingExclude() {
	_sync = 0;
}

void cBillingExclude::load(SqlDb *sqlDb) {
	lock();
	list_ip_src.clear();
	list_ip_dst.clear();
	list_number_src.clear();
	list_number_dst.clear();
	bool initSqlDb = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		initSqlDb = true;
	}
	sqlDb->query("select * \
		      from billing_exclude_addresses");
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		if(row["side"] == "src" || row["side"] == "both") {
			list_ip_src.add(atol(row["ip"].c_str()), atoi(row["mask"].c_str()));
		}
		if(row["side"] == "dst" || row["side"] == "both") {
			list_ip_dst.add(atol(row["ip"].c_str()), atoi(row["mask"].c_str()));
		}
	}
	sqlDb->query("select * \
		      from billing_exclude_numbers");
	while((row = sqlDb->fetchRow())) {
		if(row["side"] == "src" || row["side"] == "both") {
			list_number_src.add(row["number"].c_str(), !atoi(row["fixed"].c_str()));
		}
		if(row["side"] == "dst" || row["side"] == "both") {
			list_number_dst.add(row["number"].c_str(), !atoi(row["fixed"].c_str()));
		}
	}
	if(initSqlDb) {
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

bool cStateHolidays::sHoliday::isHoliday(tm &day) {
	switch(type) {
	case _billing_holiday_fixed:
		return(this->day.tm_mon == day.tm_mon &&
		       this->day.tm_mday == day.tm_mday);
	case _billing_holiday_movable:
		return(this->day.tm_year == day.tm_year &&
		       this->day.tm_mon == day.tm_mon &&
		       this->day.tm_mday == day.tm_mday);
	case _billing_holiday_easter_monday:
		return(isEasterMondayDate(day));
	case _billing_holiday_easter_friday:
		return(isEasterMondayDate(day, 3));
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
	bool initSqlDb = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		initSqlDb = true;
	}
	sqlDb->query("select * \
		      from holiday_state_date \
		      where id_holiday_state = " + intToString(id));
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		sHoliday holiday;
		holiday.load(&row);
		holidays.push_back(holiday);
	}
	if(initSqlDb) {
		delete sqlDb;
	}
}

bool cStateHolidays::isHoliday(tm &day) {
	for(list<sHoliday>::iterator iter = holidays.begin(); iter != holidays.end(); iter++) {
		if(iter->isHoliday(day)) {
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
	bool initSqlDb = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		initSqlDb = true;
	}
	sqlDb->query("select * \
		      from holiday_state");
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		cStateHolidays stateHolidays;
		stateHolidays.load(&row);
		holidays[stateHolidays.id] = stateHolidays;
	}
	for(map<unsigned, cStateHolidays>::iterator iter = holidays.begin(); iter != holidays.end(); iter++) {
		iter->second.loadHolidays(sqlDb);
	}
	if(initSqlDb) {
		delete sqlDb;
	}
	unlock();
}

bool cStatesHolidays::isHoliday(unsigned id, tm &day) {
	bool rslt = false;
	lock();
	if(holidays.find(id) != holidays.end()) {
		rslt = holidays[id].isHoliday(day);
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

bool cPeakDefinition::peakCheck(tm &time, cStateHolidays *holidays, tm *toTime) {
	tm _toTime;
	if(!toTime) {
		toTime = &_toTime;
	}
	*toTime = getNextBeginDate(time);
	if(!enable) {
		return(false);
	}
	int week_day_1 = weekend_start ? weekend_start : 7;
	int week_day_2 = week_day_1 == 7 ? 1 : week_day_1 + 1;
	if(time.tm_wday == week_day_1 - 1 ||
	   time.tm_wday == week_day_2 - 1) {
		return(false);
	}
	if(holidays && holidays->isHoliday(time)) {
		return(false);
	}
	if((peak_starts_hour || peak_ends_hour) &&
	   (peak_ends_hour * 60 + peak_ends_minute) > (peak_starts_hour * 60 + peak_starts_minute)) {
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
}

void cBillingRule::loadNumbers(SqlDb *sqlDb) {
	bool initSqlDb = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		initSqlDb = true;
	}
	sqlDb->query("select * \
		      from billing_rule \
		      where id_billing = " + intToString(id));
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		cBillingRuleNumber number;
		number.load(&row);
		numbers.push_back(number);
	}
	if(initSqlDb) {
		delete sqlDb;
	}
}

double cBillingRule::billing(tm &time, unsigned duration, const char *number, const char *number_normalized,
			     cStateHolidays *holidays) {
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
		for(unsigned pass = 0; pass < 2 && !findNumber; pass++) {
			for(list<cBillingRuleNumber>::iterator iter = numbers.begin(); iter != numbers.end(); iter++) {
				if(pass == 0 ?
				    iter->number_fixed.length() &&
				    (iter->number_fixed == number ||
				     (number_normalized && iter->number_fixed == number_normalized)) :
				    iter->number_prefix.length() &&
				    (iter->number_prefix == string(number, iter->number_prefix.length()) ||
				     (number_normalized && iter->number_prefix == string(number_normalized, iter->number_prefix.length())))) {
					price = iter->price;
					price_peak = iter->price_peak;
					t1 = iter->t1;
					t2 = iter->t2;
					if(iter->peak_definition.enable) {
						peak_definition = iter->peak_definition;
					}
					findNumber = true;
					break;
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
	tm time_iter = time;
	unsigned count_iter = 0;
	while(duration_rest > 0) {
		unsigned duration_iter = count_iter == 0 && t1 != t2 ?
					  t1 :
					  duration_rest;
		bool peak = false;
		if(peak_definition.enable) {
			tm time_iter_to;
			peak = peak_definition.peakCheck(time_iter, holidays, &time_iter_to);
			unsigned max_duration_iter = difftime(mktime(&time_iter_to), mktime(&time_iter));
			if(max_duration_iter < duration_iter && count_iter > 0) {
				duration_iter = max_duration_iter;
			}
		}
		unsigned t = count_iter == 0 ? t1 : t2;
		duration_iter = (duration_iter / t + (duration_iter % t ? 1 : 0)) * t;
		rslt_price += (duration_iter / t) *
			      (peak ? price_peak : price) * t / 60;
		time_iter = dateTimeAdd(time_iter, duration_iter);
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
	bool initSqlDb = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		initSqlDb = true;
	}
	sqlDb->query("select * \
		      from billing");
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		cBillingRule *rule = new FILE_LINE(0) cBillingRule;
		rule->load(&row);
		rules[rule->id] = rule;
	}
	for(map<unsigned, cBillingRule*>::iterator iter = rules.begin(); iter != rules.end(); iter++) {
		iter->second->loadNumbers(sqlDb);
	}
	if(initSqlDb) {
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


cBilling::cBilling() {
	_sync = 0;
	rules = new FILE_LINE(0) cBillingRules;
	assignments = new FILE_LINE(0) cBillingAssignments;
	exclude = new FILE_LINE(0) cBillingExclude;
	holidays = new FILE_LINE(0) cStatesHolidays;
	countryPrefixes = new FILE_LINE(0) CountryPrefixes;
	checkInternational = new FILE_LINE(0) CheckInternational;
}

cBilling::~cBilling() {
	delete rules;
	delete assignments;
	delete exclude;
	delete holidays;
	delete countryPrefixes;
	delete checkInternational;
}

void cBilling::load() {
	lock();
	rules->load();
	assignments->load();
	exclude->load();
	holidays->load();
	countryPrefixes->load();
	checkInternational->load();
	unlock();
}

bool cBilling::billing(tm &time, unsigned duration,
		       u_int32_t ip_src, u_int32_t ip_dst,
		       const char *number_src, const char *number_dst,
		       double *operator_price, double *customer_price,
		       unsigned *operator_id, unsigned *customer_id) {
	bool rslt = false;
	*operator_price = 0;
	*customer_price = 0;
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
									      holidays);
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
									      holidays);
		}
	}
	unlock();
	return(rslt);
}

bool cBilling::billing(time_t time, unsigned duration,
		       u_int32_t ip_src, u_int32_t ip_dst,
		       const char *number_src, const char *number_dst,
		       double *operator_price, double *customer_price,
		       unsigned *operator_id, unsigned *customer_id) {
	tm time_tm = time_r(&time);
	return(billing(time_tm, duration,
		       ip_src, ip_dst,
		       number_src, number_dst,
		       operator_price, customer_price,
		       operator_id, customer_id ));
}
