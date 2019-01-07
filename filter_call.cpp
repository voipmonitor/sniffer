#include "filter_call.h"
#include "calltable.h"


cCallFilter::cCallFilter(const char *filter) {
	setUseRecordArray(false);
	setFilter(filter);
}

void cCallFilter::setFilter(const char *filter) {
	JsonItem jsonData;
	jsonData.parse(filter);
	map<string, string> filterData;
	for(unsigned int i = 0; i < jsonData.getLocalCount(); i++) {
		JsonItem *item = jsonData.getLocalItem(i);
		string filterTypeName = item->getLocalName();
		string filterValue = item->getLocalValue();
		if(filterValue.empty()) {
			continue;
		}
		filterData[filterTypeName] = filterValue;
	}
	if(!filterData["calldate"].empty()) {
		cRecordFilterItem_calldate *filter = new cRecordFilterItem_calldate(this, cf_calldate, atol(filterData["calldate"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["sipcallerip"].empty() &&
	   filterData["sipcallerdip_type"] == "0") {
		cRecordFilterItem_IP *filter1 =  new cRecordFilterItem_IP(this, cf_callerip);
		filter1->addWhite(filterData["sipcallerip"].c_str());
		cRecordFilterItem_IP *filter2 = new cRecordFilterItem_IP(this, cf_calledip);
		filter2->addWhite(filterData["sipcallerip"].c_str());
		cRecordFilterItem_CallProxy *filter3 = new cRecordFilterItem_CallProxy(this);
		filter3->addWhite(filterData["sipcallerip"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["sipcallerip"].empty()) {
			cRecordFilterItem_IP *filter = new cRecordFilterItem_IP(this, cf_callerip);
			filter->addWhite(filterData["sipcallerip"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["sipcalledip"].empty()) {
			cRecordFilterItem_IP *filter = new cRecordFilterItem_IP(this, cf_calledip);
			filter->addWhite(filterData["sipcalledip"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["caller"].empty() &&
	   filterData["callerd_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 =  new cRecordFilterItem_CheckString(this, cf_caller);
		filter1->addWhite(filterData["caller"].c_str());
		cRecordFilterItem_CheckString *filter2 = new cRecordFilterItem_CheckString(this, cf_called);
		filter2->addWhite(filterData["caller"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["caller"].empty()) {
			cRecordFilterItem_CheckString *filter = new cRecordFilterItem_CheckString(this, cf_caller);
			filter->addWhite(filterData["caller"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["called"].empty()) {
			cRecordFilterItem_CheckString *filter = new cRecordFilterItem_CheckString(this, cf_called);
			filter->addWhite(filterData["called"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["caller_domain"].empty() &&
	   filterData["callerd_domain_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 =  new cRecordFilterItem_CheckString(this, cf_callerdomain);
		filter1->addWhite(filterData["caller_domain"].c_str());
		cRecordFilterItem_CheckString *filter2 = new cRecordFilterItem_CheckString(this, cf_calleddomain);
		filter2->addWhite(filterData["caller_domain"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["caller_domain"].empty()) {
			cRecordFilterItem_CheckString *filter = new cRecordFilterItem_CheckString(this, cf_callerdomain);
			filter->addWhite(filterData["caller_domain"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["called_domain"].empty()) {
			cRecordFilterItem_CheckString *filter = new cRecordFilterItem_CheckString(this, cf_calleddomain);
			filter->addWhite(filterData["called_domain"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["caller_agent"].empty() &&
	   filterData["callerd_agent_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 =  new cRecordFilterItem_CheckString(this, cf_calleragent);
		filter1->addWhite(filterData["caller_agent"].c_str());
		cRecordFilterItem_CheckString *filter2 = new cRecordFilterItem_CheckString(this, cf_calledagent);
		filter2->addWhite(filterData["caller_agent"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["caller_agent"].empty()) {
			cRecordFilterItem_CheckString *filter = new cRecordFilterItem_CheckString(this, cf_calleragent);
			filter->addWhite(filterData["caller_agent"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["called_agent"].empty()) {
			cRecordFilterItem_CheckString *filter = new cRecordFilterItem_CheckString(this, cf_calledagent);
			filter->addWhite(filterData["called_agent"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["callid"].empty()) {
		cRecordFilterItem_CheckString *filter = new cRecordFilterItem_CheckString(this, cf_callid);
		filter->addWhite(filterData["callid"].c_str());
		addFilter(filter);
	}
	if(!filterData["sensor_id"].empty()) {
		cRecordFilterItem_numList *filter = new cRecordFilterItem_numList(this, cf_id_sensor);
		filter->addNum(atol(filterData["sensor_id"].c_str()));
		addFilter(filter);
	}
	if(!filterData["connected"].empty() && atoi(filterData["connected"].c_str())) {
		cRecordFilterItem_numInterval *filter = new cRecordFilterItem_numInterval(this, cf_connect_duration, 0, cRecordFilterItem_base::_gt);
		addFilter(filter);
	}
	if(!filterData["international"].empty()) {
		cRecordFilterItem_numList *filter = new cRecordFilterItem_numList(this, cf_called_international);
		filter->addNum(atoi(filterData["international"].c_str()));
		addFilter(filter);
	}
	if(!filterData["OR"].empty() && atoi(filterData["OR"].c_str())) {
		setCond(cRecordFilter::_or);
	}
}
