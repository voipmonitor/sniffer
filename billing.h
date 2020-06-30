#ifndef BILLING_H
#define BILLING_H


#include "tools.h"
#include "sql_db.h"
#include "country_detect.h"


enum eBilingSide {
	_billing_side_src,
	_billing_side_dst
};

enum eBilingTypeAssignment {
	_billing_ta_operator,
	_billing_ta_customer
};

enum eBillingHolidayType {
	_billing_holiday_na,
	_billing_holiday_fixed,
	_billing_holiday_movable,
	_billing_holiday_easter_monday,
	_billing_holiday_easter_friday
};


class cBillingAssignment {
public:
	cBillingAssignment(eBilingTypeAssignment typeAssignment);
	void load(SqlDb_row *row, SqlDb *sqlDb = NULL);
	bool isSensorOk(SqlDb *sqlDb = NULL);
	void loadCond(SqlDb *sqlDb = NULL);
	bool checkIP(vmIP ip);
	bool checkNumber(const char *number);
private:
	eBilingTypeAssignment typeAssignment;
	unsigned id;
	unsigned billing_rule_id;
	string name;
	bool limitation_for_sensors;
	CheckInternational checkInternational;
	ListIP list_ip;
	ListPhoneNumber list_number;
friend class cBillingAssignments;
friend class cBilling;
};

class cBillingAssignments {
public:
	cBillingAssignments();
	~cBillingAssignments();
	void load(SqlDb *sqlDb = NULL);
	void clear(bool useLock = true);
	unsigned findBillingRuleIdForIP(vmIP ip, eBilingTypeAssignment typeAssignment,
					unsigned *assignment_id);
	unsigned findBillingRuleIdForNumber(const char *number, eBilingTypeAssignment typeAssignment, 
					    unsigned *assignment_id, CountryPrefixes *countryPrefixes);
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	map<unsigned, cBillingAssignment*> operators;
	map<unsigned, cBillingAssignment*> customers;
	volatile int _sync;
friend class cBilling;
};


class cBillingExclude {
public:
	cBillingExclude(bool agregation = false);
	void load(SqlDb *sqlDb = NULL);
	bool checkIP(vmIP ip, eBilingSide side);
	bool checkNumber(const char *number, eBilingSide side);
	bool checkDomain(const char *domain, eBilingSide side);
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	bool agregation;
	ListIP list_ip_src;
	ListIP list_ip_dst;
	ListPhoneNumber list_number_src;
	ListPhoneNumber list_number_dst;
	ListCheckString list_domain_src;
	ListCheckString list_domain_dst;
	volatile int _sync;
};


class cStateHolidays {
public:
	struct sHoliday {
		sHoliday() {
			type = _billing_holiday_fixed;
			memset(&day, 0, sizeof(day));
		}
		void load(SqlDb_row *row);
		bool isHoliday(tm &day, const char *timezone);
		eBillingHolidayType type;
		tm day;
	};
public:
	void load(SqlDb_row *row);
	void loadHolidays(SqlDb *sqlDb = NULL);
	bool isHoliday(tm &day, const char *timezone);
private:
	unsigned id;
	string name;
	string country_code;
	list<sHoliday> holidays;
friend class cStatesHolidays;
};

class cStatesHolidays {
public:
	cStatesHolidays();
	void load(SqlDb *sqlDb = NULL);
	bool isHoliday(unsigned id, tm &day, const char *timezone);
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	map<unsigned, cStateHolidays> holidays;
	volatile int _sync;
friend class cBilling;
};

class cPeakDefinition {
public:
	cPeakDefinition();
	void load(SqlDb_row *row, const char *fieldNamePrefix = NULL);
	bool peakCheck(tm &time, cStateHolidays *holidays, tm *toTime, const char *timezone);
private: 
	bool enable;
	unsigned peak_starts_hour;
	unsigned peak_starts_minute;
	unsigned peak_ends_hour;
	unsigned peak_ends_minute;
	unsigned weekend_start;
friend class cBillingRuleNumber;
friend class cBillingRule;
};

class cBillingRuleNumber {
public:
	enum eNumberFormat {
		_number_format_na,
		_number_format_original,
		_number_format_normalized,
		_number_format_both
	};
	enum eNumberType {
		_number_type_na,
		_number_type_local,
		_number_type_international,
		_number_type_both
	};
public:
	cBillingRuleNumber();
	~cBillingRuleNumber();
	void load(SqlDb_row *row);
	void regexp_create();
	static eNumberFormat numberFormatEnum(const char *str);
	static eNumberType numberTypeEnum(const char *str);
	static string numberFormatString(eNumberFormat numbFormat);
	static string numberTypeString(eNumberType numbType);
private:
	string name;
	string number_prefix;
	string number_fixed;
	string number_regex;
	cPeakDefinition peak_definition;
	double price;
	double price_peak;
	unsigned t1;
	unsigned t2;
	eNumberFormat use_for_number_format;
	eNumberType use_for_number_type;
	cRegExp *regexp;
friend class cBillingRule;
};

class cBillingRule {
public:
	~cBillingRule();
	void load(SqlDb_row *row);
	void loadNumbers(SqlDb *sqlDb = NULL);
	void freeNumbers();
	double billing(time_t time, unsigned duration, const char *number, const char *number_normalized,
		       bool isLocalNumber, cStateHolidays *holidays, const char *timezone,
		       vector<string> *debug = NULL);
private:
	unsigned id;
	string name;
	unsigned holiday_id;
	cPeakDefinition peak_definition;
	double price;
	double price_peak;
	unsigned t1;
	unsigned t2;
	cBillingRuleNumber::eNumberFormat use_for_number_format;
	cBillingRuleNumber::eNumberType use_for_number_type;
	bool default_customer;
	string currency_code;
	unsigned currency_id;
	string timezone_name;
	list<cBillingRuleNumber*> numbers;
friend class cBillingRules;
friend class cBilling;
};

class cBillingRules {
public:
	cBillingRules();
	~cBillingRules();
	void load(SqlDb *sqlDb = NULL);
	void clear(bool useLock = true);
	unsigned getDefaultCustomerBillingId();
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	map<unsigned, cBillingRule*> rules;
	volatile int _sync;
friend class cBilling;
};

struct sBillingAgregationSettings {
	bool enable_by_ip;
	bool enable_by_number;
	bool enable_by_domain;
	unsigned week_start;
	unsigned hours_history_in_days;
	unsigned days_history_in_weeks;
	unsigned weeks_history_in_months;
	unsigned months_history_in_years;
};

class cBillingAgregationSettings {
public:
	cBillingAgregationSettings();
	void load(SqlDb *sqlDb = NULL);
	void clear();
	sBillingAgregationSettings getAgregSettings() {
		return(settings);
	}
private:
	sBillingAgregationSettings settings;
friend class cBilling;
};

class cCurrency {
public:
	struct sCurrencyItem {
		unsigned id;
		string code;
		string name;
		string country_code;
		bool main_currency;
		double exchange_rate;
	};
public:
	cCurrency();
	void load(SqlDb *sqlDb = NULL);
	void clear(bool useLock = true);
	double getExchangeRateToMainCurency(unsigned from_id);
	string getCurrencyCode(unsigned id);
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	list<sCurrencyItem> items;
	volatile int _sync;
};

class cBilling {
public:
	struct sAgregationTypePart {
		string type;
		string type_part;
		bool week;
		unsigned limit;
	};
public:
	cBilling();
	~cBilling();
	void load(SqlDb *sqlDb = NULL);
	bool isSet() {
		return(set);
	}
	bool billing(time_t time, unsigned duration,
		     vmIP ip_src, vmIP ip_dst,
		     const char *number_src, const char *number_dst,
		     const char *domain_src, const char *domain_dst,
		     double *operator_price, double *customer_price,
		     unsigned *operator_currency_id, unsigned *customer_currency_id,
		     unsigned *operator_id, unsigned *customer_id,
		     unsigned force_operator_id = 0, unsigned force_customer_id = 0,
		     bool use_exclude_rules = true,
		     vector<string> *operator_debug = NULL, vector<string> *customer_debug = NULL);
	bool saveAggregation(time_t time,
			     vmIP ip_src, vmIP ip_dst,
			     const char *number_src, const char *number_dst,
			     const char *domain_src, const char *domain_dst,
			     double operator_price, double customer_price,
			     unsigned operator_currency_id, unsigned customer_currency_id,
			     list<string> *inserts);
	sBillingAgregationSettings getAgregSettings() {
		return(agreg_settings->settings);
	}
	static vector<sAgregationTypePart> getAgregTypeParts(sBillingAgregationSettings *settings);
	string getCurrencyCode(unsigned id);
	string test(string calls_string, bool json_rslt);
	string test(const char *id, const char *time, const char *duration,
		    const char *ip_src, const char *ip_dst,
		    const char *number_src, const char *number_dst,
		    const char *domain_src, const char *domain_dst,
		    const char *sensor_id,
		    const char *verify_operator_price, const char *verify_customer_price,
		    bool json_rslt);
	void revaluationBilling(list<u_int64_t> *ids,
				unsigned force_operator_id = 0, unsigned force_customer_id = 0,
				bool use_exclude_rules = true);
	void revaluationBilling(SqlDb_rows *rows, SqlDb *sqlDb,
				unsigned force_operator_id = 0, unsigned force_customer_id = 0,
				bool use_exclude_rules = true);
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	bool set;
	cBillingRules *rules;
	cBillingAssignments *assignments;
	cBillingExclude *exclude;
	cStatesHolidays *holidays;
	CountryPrefixes *countryPrefixes;
	CheckInternational *checkInternational;
	cBillingExclude *agreg_exclude;
	cBillingAgregationSettings *agreg_settings;
	cCurrency *currency;
	string gui_timezone;
	volatile int _sync;
};


void initBilling(SqlDb *sqlDb);
void termBilling();
void refreshBilling();

void revaluationBilling(const char *params);
void revaluationBilling(list<u_int64_t> *ids,
			unsigned force_operator_id = 0, unsigned force_customer_id = 0,
			bool use_exclude_rules = true);


#endif //BILLING_H
