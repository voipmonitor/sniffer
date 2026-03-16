#ifndef FILTER_REGISTER_H
#define FILTER_REGISTER_H


#include "filter_record.h"


class cRecordFilterItem_Register : public cRecordFilterItem_rec {
public:
	enum eTypeFilter {
		_tf_ip_country_eq = 0,
		_tf_ip_country_diff,
		_tf_ip_country_national,
		_tf_ip_country_international,
		_tf_num_country_eq,
		_tf_num_country_diff,
		_tf_num_country_national,
		_tf_num_country_international
	};
public:
	cRecordFilterItem_Register(cRecordFilter *parent, eTypeFilter typeFilter);
	bool check(void *rec, bool *findInBlackList = NULL);
private:
	eTypeFilter typeFilter;
};


class cRegisterFilter : public cRecordFilter {
public:
	cRegisterFilter(const char *filter = NULL);
	void setFilter(const char *filter);
};


#endif
