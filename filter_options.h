#ifndef FILTER_OPTIONS_H
#define FILTER_OPTIONS_H


#include "filter_record.h"


class cSipMsgFilter : public cRecordFilter {
public:
	cSipMsgFilter(const char *filter);
	void setFilter(const char *filter);
};


#endif
