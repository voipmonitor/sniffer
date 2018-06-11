#ifndef FILTER_OPTIONS_H
#define FILTER_OPTIONS_H


#include "filter_record.h"


class cOptionsFilter : public cRecordFilter {
public:
	cOptionsFilter(const char *filter);
	void setFilter(const char *filter);
};


#endif
