#include "filter_register.h"
#include "register.h"
#include "country_detect.h"


cRecordFilterItem_Register::cRecordFilterItem_Register(cRecordFilter *parent, eTypeFilter typeFilter)
 : cRecordFilterItem_rec(parent) {
	this->typeFilter = typeFilter;
}

bool cRecordFilterItem_Register::check(void *rec, bool */*findInBlackList*/) {
	string country1, country2;
	if(typeFilter == _tf_ip_country_eq || typeFilter == _tf_ip_country_diff ||
	   typeFilter == _tf_ip_country_national || typeFilter == _tf_ip_country_international) {
		country1 = parent->getField_string(rec, rf_sipcallerip_country_code);
		country2 = parent->getField_string(rec, rf_sipcalledip_country_code);
	} else {
		country1 = parent->getField_string(rec, rf_from_num_country_code);
		country2 = parent->getField_string(rec, rf_to_num_country_code);
	}
	switch(typeFilter) {
	case _tf_ip_country_eq:
	case _tf_num_country_eq:
		return(country1 == country2);
	case _tf_ip_country_diff:
	case _tf_num_country_diff:
		if(country1.empty() || country2.empty()) {
			return(false);
		}
		return(country1 != country2);
	case _tf_ip_country_national:
	case _tf_num_country_national: {
		extern CountryDetect *countryDetect;
		if(!countryDetect) {
			return(country1 == country2);
		}
		return((country1.empty() || countryDetect->countryCodeIsLocal(country1.c_str())) &&
		       (country2.empty() || countryDetect->countryCodeIsLocal(country2.c_str())));
		}
	case _tf_ip_country_international:
	case _tf_num_country_international: {
		extern CountryDetect *countryDetect;
		if(!countryDetect) {
			if(country1.empty() || country2.empty()) {
				return(false);
			}
			return(country1 != country2);
		}
		return((!country1.empty() && !countryDetect->countryCodeIsLocal(country1.c_str())) ||
		       (!country2.empty() && !countryDetect->countryCodeIsLocal(country2.c_str())));
		}
	}
	return(false);
}


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
	if(!filterData["sipcallerip_group_id"].empty() &&
	   filterData["sipcallerdip_group_id_type"] == "0") {
		cRecordFilterItem_IP *filter1 =  new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcallerip);
		filter1->addWhite("cb_ip_groups", "ip", filterData["sipcallerip_group_id"].c_str());
		cRecordFilterItem_IP *filter2 = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcalledip);
		filter2->addWhite("cb_ip_groups", "ip", filterData["sipcallerip_group_id"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["sipcallerip_group_id"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcallerip);
			filter->addWhite("cb_ip_groups", "ip", filterData["sipcallerip_group_id"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["sipcalledip_group_id"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, rf_sipcalledip);
			filter->addWhite("cb_ip_groups", "ip", filterData["sipcalledip_group_id"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["sipcallerport"].empty() &&
	   filterData["sipcallerdport_type"] == "0") {
		cRecordFilterItem_Port *filter1 = new FILE_LINE(0) cRecordFilterItem_Port(this, rf_sipcallerport, atoi(filterData["sipcallerport"].c_str()));
		cRecordFilterItem_Port *filter2 = new FILE_LINE(0) cRecordFilterItem_Port(this, rf_sipcalledport, atoi(filterData["sipcallerport"].c_str()));
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["sipcallerport"].empty()) {
			cRecordFilterItem_Port *filter = new FILE_LINE(0) cRecordFilterItem_Port(this, rf_sipcallerport, atoi(filterData["sipcallerport"].c_str()));
			gItems.addFilter(filter);
		}
		if(!filterData["sipcalledport"].empty()) {
			cRecordFilterItem_Port *filter = new FILE_LINE(0) cRecordFilterItem_Port(this, rf_sipcalledport, atoi(filterData["sipcalledport"].c_str()));
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
	if(!filterData["from_num_group_id"].empty() &&
	   filterData["numFTC_group_id_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_num);
		filter1->addWhite("cb_number_groups", "number", filterData["from_num_group_id"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_num);
		filter2->addWhite("cb_number_groups", "number", filterData["from_num_group_id"].c_str());
		cRecordFilterItem_CheckString *filter3 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_num);
		filter3->addWhite("cb_number_groups", "number", filterData["from_num_group_id"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_num_group_id"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_num);
			filter->addWhite("cb_number_groups", "number", filterData["from_num_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_num_group_id"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_num);
			filter->addWhite("cb_number_groups", "number", filterData["to_num_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_num_group_id"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_contact_num);
			filter->addWhite("cb_number_groups", "number", filterData["contact_num_group_id"].c_str());
			addFilter(filter);
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
	if(!filterData["country_code_sipcallerip"].empty() &&
	   filterData["country_code_sipcallerdip_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_sipcallerip_country_code);
		filter1->addWhite(filterData["country_code_sipcallerip"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_sipcalledip_country_code);
		filter2->addWhite(filterData["country_code_sipcallerip"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["country_code_sipcallerip"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_sipcallerip_country_code);
			filter->addWhite(filterData["country_code_sipcallerip"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["country_code_sipcalledip"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_sipcalledip_country_code);
			filter->addWhite(filterData["country_code_sipcalledip"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["country_code_from_num"].empty() &&
	   filterData["country_code_numFT_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_num_country_code);
		filter1->addWhite(filterData["country_code_from_num"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_num_country_code);
		filter2->addWhite(filterData["country_code_from_num"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["country_code_from_num"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_from_num_country_code);
			filter->addWhite(filterData["country_code_from_num"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["country_code_to_num"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, rf_to_num_country_code);
			filter->addWhite(filterData["country_code_to_num"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["country_compare_ips"].empty()) {
		int val = atoi(filterData["country_compare_ips"].c_str());
		if(val >= 1 && val <= 4) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Register(this, (cRecordFilterItem_Register::eTypeFilter)(cRecordFilterItem_Register::_tf_ip_country_eq + val - 1)));
		}
	}
	if(!filterData["country_compare_numbers"].empty()) {
		int val = atoi(filterData["country_compare_numbers"].c_str());
		if(val >= 1 && val <= 4) {
			addFilter(new FILE_LINE(0) cRecordFilterItem_Register(this, (cRecordFilterItem_Register::eTypeFilter)(cRecordFilterItem_Register::_tf_num_country_eq + val - 1)));
		}
	}
}
