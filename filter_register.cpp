#include "filter_register.h"
#include "register.h"


cRegisterFilter::cRegisterFilter(const char *filter) {
	if(filter) {
		setFilter(filter);
	}
}

void cRegisterFilter::setFilter(const char *filter) {
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
	if(!filterData["calldate_from"].empty()) {
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, rf_calldate, atol(filterData["calldate_from"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["calldate_to"].empty()) {
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, rf_calldate, atol(filterData["calldate_to"].c_str()), cRecordFilterItem_base::_lt);
		addFilter(filter);
	}
	if(!filterData["sipcallerip"].empty() &&
	   filterData["sipcallerdip_type"] == "0") {
		cRecordFilterItem_IP *filter1 =  new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcallerip);
		filter1->addWhite(filterData["sipcallerip"].c_str());
		cRecordFilterItem_IP *filter2 = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcalledip);
		filter2->addWhite(filterData["sipcallerip"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["sipcallerip"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcallerip);
			filter->addWhite(filterData["sipcallerip"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["sipcalledip"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcalledip);
			filter->addWhite(filterData["sipcalledip"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["sipcallerip_encaps"].empty() &&
	   filterData["sipcallerdip_encaps_type"] == "0") {
		cRecordFilterItem_IP *filter1 =  new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcallerip_encaps);
		filter1->addWhite(filterData["sipcallerip_encaps"].c_str());
		cRecordFilterItem_IP *filter2 = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcalledip_encaps);
		filter2->addWhite(filterData["sipcallerip_encaps"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["sipcallerip_encaps"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcallerip_encaps);
			filter->addWhite(filterData["sipcallerip_encaps"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["sipcalledip_encaps"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcalledip_encaps);
			filter->addWhite(filterData["sipcalledip_encaps"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["from_num"].empty() &&
	   filterData["numFTC_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_num);
		filter1->addWhite(filterData["from_num"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_num);
		filter2->addWhite(filterData["from_num"].c_str());
		cRecordFilterItem_CheckString *filter3 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_num);
		filter3->addWhite(filterData["from_num"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["from_num"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_num);
			filter->addWhite(filterData["from_num"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["to_num"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_num);
			filter->addWhite(filterData["to_num"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["contact_num"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_num);
			filter->addWhite(filterData["contact_num"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["from_name"].empty()) {
		cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_name);
		filter->addWhite(filterData["from_name"].c_str());
		addFilter(filter);
	}
	if(!filterData["from_domain"].empty() &&
	   filterData["domainFTC_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_domain);
		filter1->addWhite(filterData["from_domain"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_domain);
		filter2->addWhite(filterData["from_domain"].c_str());
		cRecordFilterItem_CheckString *filter3 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_domain);
		filter3->addWhite(filterData["from_domain"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["from_domain"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_domain);
			filter->addWhite(filterData["from_domain"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["to_domain"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_domain);
			filter->addWhite(filterData["to_domain"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["contact_domain"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_domain);
			filter->addWhite(filterData["contact_domain"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["from_domain_group_id"].empty() &&
	   filterData["domainFTC_group_id_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_domain);
		filter1->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_domain);
		filter2->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		cRecordFilterItem_CheckString *filter3 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_domain);
		filter3->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_domain_group_id"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_domain_group_id"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["to_domain_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_domain_group_id"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["contact_domain_group_id"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["digestusername"].empty()) {
		cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_digestusername);
		filter->addWhite(filterData["digestusername"].c_str());
		addFilter(filter);
	}
	if(!filterData["digestrealm"].empty()) {
		cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_digestrealm);
		filter->addWhite(filterData["digestrealm"].c_str());
		addFilter(filter);
	}
	if(!filterData["rrd_avg_ge"].empty()) {
		cRecordFilterItem_numInterval *filter = new FILE_LINE(0) cRecordFilterItem_numInterval(this, rf_rrd_avg, atol(filterData["rrd_avg_ge"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["rrd_avg_lt"].empty()) {
		cRecordFilterItem_numInterval *filter = new FILE_LINE(0) cRecordFilterItem_numInterval(this, rf_rrd_avg, atol(filterData["rrd_avg_lt"].c_str()), cRecordFilterItem_base::_lt);
		addFilter(filter);
	}
	if(!filterData["expires_ge"].empty()) {
		cRecordFilterItem_numInterval *filter = new FILE_LINE(0) cRecordFilterItem_numInterval(this, rf_expires, atol(filterData["expires_ge"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["expires_lt"].empty()) {
		cRecordFilterItem_numInterval *filter = new FILE_LINE(0) cRecordFilterItem_numInterval(this, rf_expires, atol(filterData["expires_lt"].c_str()), cRecordFilterItem_base::_lt);
		addFilter(filter);
	}
	if(!filterData["expires_at_from"].empty()) {
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, rf_expires_at, atol(filterData["expires_at_from"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["expires_at_to"].empty()) {
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, rf_expires_at, atol(filterData["expires_at_to"].c_str()), cRecordFilterItem_base::_lt);
		addFilter(filter);
	}
	if(!filterData["ua"].empty()) {
		cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_ua, false);
		filter->addWhite(filterData["ua"].c_str());
		addFilter(filter);
	}
	if(!filterData["ua_group_id"].empty()) {
		cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_ua, false);
		filter->addWhite("cb_ua_groups", "ua", filterData["ua_group_id"].c_str());
		addFilter(filter);
	}
	if(!filterData["sensor_id"].empty()) {
		vector<string> filter_sensor_ids = split(filterData["sensor_id"].c_str(), ",", true);
		if(filter_sensor_ids.size()) {
			cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, rf_id_sensor);
			for(unsigned i = 0; i < filter_sensor_ids.size(); i++) {
				filter->addNum(atoi(filter_sensor_ids[i].c_str()) >= 0 ? atoi(filter_sensor_ids[i].c_str()) : -1);
			}
			addFilter(filter);
		}
	}
	if(!filterData["is_sipalg_detected"].empty()) {
		cRecordFilterItem_bool *filter = new FILE_LINE(0) cRecordFilterItem_bool(this, rf_is_sipalg_detected, filterData["is_sipalg_detected"].c_str());
		addFilter(filter);
	}
}
