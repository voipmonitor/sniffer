#include "filter_register.h"
#include "sql_db.h"
#include "register.h"


void cRegisterFilterItem_base::setCodebook(const char *table, const char *column) {
	codebook_table = table;
	codebook_column = column;
}

string cRegisterFilterItem_base::getCodebookValue(u_int32_t id) {
	/*
	if(opt_nocdr) {
		return("");
	}
	*/
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select " + codebook_column + " as value from " + codebook_table + " where id = " + intToString(id));
	SqlDb_row row = sqlDb->fetchRow();
	string rslt;
	if(row) {
		rslt = row["value"];
	}
	delete sqlDb;
	return(rslt);
}

void cRegisterFilterItems::addFilter(cRegisterFilterItem_base *filter) {
	fItems.push_back(filter);
}

void cRegisterFilterItems::free() {
	list<cRegisterFilterItem_base*>::iterator iter;
	for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
		delete *iter;
	}
}

cRegisterFilter::cRegisterFilter(const char *filter) {
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
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(this, rf_calldate, atol(filterData["calldate_from"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["calldate_to"].empty()) {
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(this, rf_calldate, atol(filterData["calldate_to"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["sipcallerip"].empty() &&
	   filterData["sipcallerdip_type"] == "0") {
		cRegisterFilterItem_IP *filter1 =  new cRegisterFilterItem_IP(this, rf_sipcallerip);
		filter1->addWhite(filterData["sipcallerip"].c_str());
		cRegisterFilterItem_IP *filter2 = new cRegisterFilterItem_IP(this, rf_sipcalledip);
		filter2->addWhite(filterData["sipcallerip"].c_str());
		addFilter(filter1, filter2);
	} else {
		if(!filterData["sipcallerip"].empty()) {
			cRegisterFilterItem_IP *filter = new cRegisterFilterItem_IP(this, rf_sipcallerip);
			filter->addWhite(filterData["sipcallerip"].c_str());
			addFilter(filter);
		}
		if(!filterData["sipcalledip"].empty()) {
			cRegisterFilterItem_IP *filter = new cRegisterFilterItem_IP(this, rf_sipcalledip);
			filter->addWhite(filterData["sipcalledip"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["from_num"].empty() &&
	   filterData["numFTC_type"] == "0") {
		cRegisterFilterItem_CheckString *filter1 = new cRegisterFilterItem_CheckString(this, rf_from_num);
		filter1->addWhite(filterData["from_num"].c_str());
		cRegisterFilterItem_CheckString *filter2 = new cRegisterFilterItem_CheckString(this, rf_to_num);
		filter2->addWhite(filterData["from_num"].c_str());
		cRegisterFilterItem_CheckString *filter3 = new cRegisterFilterItem_CheckString(this, rf_contact_num);
		filter3->addWhite(filterData["from_num"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_num"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_from_num);
			filter->addWhite(filterData["from_num"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_num"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_to_num);
			filter->addWhite(filterData["to_num"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_num"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_contact_num);
			filter->addWhite(filterData["contact_num"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["from_name"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_from_name);
		filter->addWhite(filterData["from_name"].c_str());
		addFilter(filter);
	}
	if(!filterData["from_domain"].empty() &&
	   filterData["domainFTC_type"] == "0") {
		cRegisterFilterItem_CheckString *filter1 = new cRegisterFilterItem_CheckString(this, rf_from_domain);
		filter1->addWhite(filterData["from_domain"].c_str());
		cRegisterFilterItem_CheckString *filter2 = new cRegisterFilterItem_CheckString(this, rf_to_domain);
		filter2->addWhite(filterData["from_domain"].c_str());
		cRegisterFilterItem_CheckString *filter3 = new cRegisterFilterItem_CheckString(this, rf_contact_domain);
		filter3->addWhite(filterData["from_domain"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_domain"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_from_domain);
			filter->addWhite(filterData["from_domain"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_domain"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_to_domain);
			filter->addWhite(filterData["to_domain"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_domain"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_contact_domain);
			filter->addWhite(filterData["contact_domain"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["from_domain_group_id"].empty() &&
	   filterData["domainFTC_group_id_type"] == "0") {
		cRegisterFilterItem_CheckString *filter1 = new cRegisterFilterItem_CheckString(this, rf_from_domain);
		filter1->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		cRegisterFilterItem_CheckString *filter2 = new cRegisterFilterItem_CheckString(this, rf_to_domain);
		filter2->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		cRegisterFilterItem_CheckString *filter3 = new cRegisterFilterItem_CheckString(this, rf_contact_domain);
		filter3->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		if(!filterData["from_domain_group_id"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_from_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["from_domain_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["to_domain_group_id"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_to_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["to_domain_group_id"].c_str());
			addFilter(filter);
		}
		if(!filterData["contact_domain_group_id"].empty()) {
			cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_contact_domain);
			filter->addWhite("cb_domain_groups", "domain", filterData["contact_domain_group_id"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["digestusername"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_digestusername);
		filter->addWhite(filterData["digestusername"].c_str());
		addFilter(filter);
	}
	if(!filterData["digest_realm"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_digestrealm);
		filter->addWhite(filterData["digest_realm"].c_str());
		addFilter(filter);
	}
	if(!filterData["rrd_avg_ge"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(this, rf_rrd_avg, atol(filterData["rrd_avg_ge"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["rrd_avg_lt"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(this, rf_rrd_avg, atol(filterData["rrd_avg_lt"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["expires_ge"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(this, rf_expires, atol(filterData["expires_ge"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["expires_lt"].empty()) {
		cRegisterFilterItem_numInterval *filter = new cRegisterFilterItem_numInterval(this, rf_expires, atol(filterData["expires_lt"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["expires_at_from"].empty()) {
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(this, rf_expires_at, atol(filterData["expires_at_from"].c_str()), true);
		addFilter(filter);
	}
	if(!filterData["expires_at_to"].empty()) {
		cRegisterFilterItem_calldate *filter = new cRegisterFilterItem_calldate(this, rf_expires_at, atol(filterData["expires_at_to"].c_str()), false);
		addFilter(filter);
	}
	if(!filterData["ua"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_ua);
		filter->addWhite(filterData["ua"].c_str());
		addFilter(filter);
	}
	if(!filterData["ua_group_id"].empty()) {
		cRegisterFilterItem_CheckString *filter = new cRegisterFilterItem_CheckString(this, rf_ua);
		filter->addWhite("cb_ua_groups", "ua", filterData["ua_group_id"].c_str());
		addFilter(filter);
	}
	if(!filterData["sensor_id"].empty()) {
		cRegisterFilterItem_numList *filter = new cRegisterFilterItem_numList(this, rf_id_sensor);
		filter->addNum(atol(filterData["sensor_id"].c_str()));
		addFilter(filter);
	}
}

cRegisterFilter::~cRegisterFilter() {
	list<cRegisterFilterItems>::iterator iter;
	for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
		iter->free();
	}
}

void cRegisterFilter::addFilter(cRegisterFilterItem_base *filter1, cRegisterFilterItem_base *filter2, cRegisterFilterItem_base *filter3) {
	cRegisterFilterItems fSubItems;
	fSubItems.addFilter(filter1);
	if(filter2) {
		fSubItems.addFilter(filter2);
	}
	if(filter3) {
		fSubItems.addFilter(filter3);
	}
	fItems.push_back(fSubItems);
}
