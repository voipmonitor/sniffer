#ifndef FILTER_REGISTER_H
#define FILTER_REGISTER_H


#include "filter_record.h"


class cRegisterFilter : public cRecordFilter {
public:
	cRegisterFilter(const char *filter = NULL);
	void setFilter(const char *filter);
};


#endif
