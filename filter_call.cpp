#include "filter_call.h"
#include "calltable.h"
#include "header_packet.h"


extern CustomHeaders *custom_headers_cdr;


bool cRecordFilterItem_CustomHeader::check(void *rec, bool *findInBlackList) {
	if(custom_headers_cdr) {
		string customHeaderContent = custom_headers_cdr->getValue((Call*)rec, INVITE, customHeader.c_str());
		if(customHeaderContent.empty() ||
		   !checkStringData.check(customHeaderContent.c_str(), findInBlackList)) {
			return(false);
		}
	}
	return(true);
}


bool cRecordFilterItem_Call::check(void *rec, bool */*findInBlackList*/) {
	if(custom_headers_cdr) {
		map<string, string> custom_headers;
		custom_headers_cdr->getHeaderValues((Call*)rec, INVITE, &custom_headers);
		string filter_data = filter;
		size_t pos[2];
		while((pos[0] = filter_data.find("{{")) != string::npos &&
		      (pos[1] = filter_data.find("}}", pos[0])) != string::npos) {
			string field = filter_data.substr(pos[0] + 2, pos[1] - pos[0] - 2);
			map<string, string>::iterator iter = custom_headers.find(field);
			string value = iter != custom_headers.end() ? iter->second : "";
			filter_data = filter_data.substr(0, pos[0]) + "'" + value + "'" + filter_data.substr(pos[1] + 2);
		}
		cEvalFormula f(cEvalFormula::_est_na);
		return(f.e(filter_data.c_str()).getBool());
	}
	return(true);
}


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
		cRecordFilterItem_calldate *filter = new FILE_LINE(0) cRecordFilterItem_calldate(this, cf_calldate, atol(filterData["calldate"].c_str()), cRecordFilterItem_base::_ge);
		addFilter(filter);
	}
	if(!filterData["sipcallerip"].empty() &&
	   filterData["sipcallerdip_type"] == "0") {
		cRecordFilterItem_IP *filter1 =  new FILE_LINE(0) cRecordFilterItem_IP(this, cf_callerip);
		filter1->addWhite(filterData["sipcallerip"].c_str());
		cRecordFilterItem_IP *filter2 = new FILE_LINE(0) cRecordFilterItem_IP(this, cf_calledip);
		filter2->addWhite(filterData["sipcallerip"].c_str());
		cRecordFilterItem_CallProxy *filter3 = new FILE_LINE(0) cRecordFilterItem_CallProxy(this);
		filter3->addWhite(filterData["sipcallerip"].c_str());
		addFilter(filter1, filter2, filter3);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["sipcallerip"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, cf_callerip);
			filter->addWhite(filterData["sipcallerip"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["sipcalledip"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, cf_calledip);
			filter->addWhite(filterData["sipcalledip"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["sipcallerip_encaps"].empty() &&
	   filterData["sipcallerdip_encaps_type"] == "0") {
		cRecordFilterItem_IP *filter1 =  new FILE_LINE(0) cRecordFilterItem_IP(this, cf_callerip_encaps);
		filter1->addWhite(filterData["sipcallerip_encaps"].c_str());
		cRecordFilterItem_IP *filter2 = new FILE_LINE(0) cRecordFilterItem_IP(this, cf_calledip_encaps);
		filter2->addWhite(filterData["sipcallerip_encaps"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["sipcallerip_encaps"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, cf_callerip_encaps);
			filter->addWhite(filterData["sipcallerip_encaps"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["sipcalledip_encaps"].empty()) {
			cRecordFilterItem_IP *filter = new FILE_LINE(0) cRecordFilterItem_IP(this, cf_calledip_encaps);
			filter->addWhite(filterData["sipcalledip_encaps"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["caller"].empty() &&
	   filterData["callerd_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 =  new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_caller);
		filter1->addWhite(filterData["caller"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_called);
		filter2->addWhite(filterData["caller"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["caller"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_caller);
			filter->addWhite(filterData["caller"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["called"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_called);
			filter->addWhite(filterData["called"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["caller_domain"].empty() &&
	   filterData["callerd_domain_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 =  new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_callerdomain);
		filter1->addWhite(filterData["caller_domain"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_calleddomain);
		filter2->addWhite(filterData["caller_domain"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["caller_domain"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_callerdomain);
			filter->addWhite(filterData["caller_domain"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["called_domain"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_calleddomain);
			filter->addWhite(filterData["called_domain"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["caller_agent"].empty() &&
	   filterData["callerd_agent_type"] == "0") {
		cRecordFilterItem_CheckString *filter1 =  new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_calleragent);
		filter1->addWhite(filterData["caller_agent"].c_str());
		cRecordFilterItem_CheckString *filter2 = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_calledagent);
		filter2->addWhite(filterData["caller_agent"].c_str());
		addFilter(filter1, filter2);
	} else {
		cRecordFilterItems gItems(cRecordFilterItems::_and);
		if(!filterData["caller_agent"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_calleragent);
			filter->addWhite(filterData["caller_agent"].c_str());
			gItems.addFilter(filter);
		}
		if(!filterData["called_agent"].empty()) {
			cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_calledagent);
			filter->addWhite(filterData["called_agent"].c_str());
			gItems.addFilter(filter);
		}
		if(gItems.isSet()) {
			addFilter(&gItems);
		}
	}
	if(!filterData["callid"].empty()) {
		cRecordFilterItem_CheckString *filter = new FILE_LINE(0) cRecordFilterItem_CheckString(this, cf_callid);
		filter->addWhite(filterData["callid"].c_str());
		addFilter(filter);
	}
	if(!filterData["sensor_id"].empty()) {
		cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, cf_id_sensor);
		filter->addNum(atol(filterData["sensor_id"].c_str()));
		addFilter(filter);
	}
	if(!filterData["vlan"].empty()) {
		cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, cf_vlan);
		filter->addNum(atoi(filterData["vlan"].c_str()));
		addFilter(filter);
	}
	if(!filterData["connected"].empty() && atoi(filterData["connected"].c_str())) {
		cRecordFilterItem_numInterval *filter = new FILE_LINE(0) cRecordFilterItem_numInterval(this, cf_connect_duration, 0, cRecordFilterItem_base::_gt);
		addFilter(filter);
	}
	if(!filterData["international"].empty()) {
		cRecordFilterItem_numList *filter = new FILE_LINE(0) cRecordFilterItem_numList(this, cf_called_international);
		filter->addNum(atoi(filterData["international"].c_str()));
		addFilter(filter);
	}
	if(custom_headers_cdr) {
		list<string> customHeaders;
		custom_headers_cdr->getHeaders(&customHeaders);
		for(list<string>::iterator iter = customHeaders.begin(); iter != customHeaders.end(); iter++) {
			if(!filterData[*iter].empty()) {
				cRecordFilterItem_CustomHeader *filter = new FILE_LINE(0) cRecordFilterItem_CustomHeader(this, iter->c_str());
				filter->addWhite(filterData[*iter].c_str());
				addFilter(filter);
			}
		}
		if(!filterData["custom_headers_cdr_cond"].empty()) {
			cRecordFilterItem_Call *filter = new FILE_LINE(0) cRecordFilterItem_Call(this, filterData["custom_headers_cdr_cond"].c_str());
			addFilter(filter);
		}
	}
	if(!filterData["OR"].empty() && atoi(filterData["OR"].c_str())) {
		setCond(cRecordFilter::_or);
	}
}


cUserRestriction::cUserRestriction() {
	cond_ip = NULL;
	cond_number = NULL;
	cond_domain = NULL;
	cond_vlan = NULL;
	cond_ch_cdr = NULL;
	cond_ch_message = NULL;
	clear();
}

cUserRestriction::~cUserRestriction() {
	clear();
}

void cUserRestriction::load(unsigned uid, bool *useCustomHeaders, SqlDb *sqlDb) {
	*useCustomHeaders = false;
	this->uid = uid;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	list<SqlDb_condField> cond;
	cond.push_back(SqlDb_condField("id", intToString(uid)));
	sqlDb->select("users", NULL, &cond);
	SqlDb_row row = sqlDb->fetchRow();
	if(row) {
		src_ip = row["ip"];
		src_number = row["number"];
		src_domain = row["domain"];
		src_vlan = row["vlan"];
		src_ch_cdr =  row["custom_headers_cdr"];
		src_ch_message = row["custom_headers_message"];
		comb_cond = atoi(row["ip_number_domain_or"].c_str()) > 0 ? _cc_or : _cc_and;
		if(!src_ch_cdr.empty() || !src_ch_message.empty()) {
			*useCustomHeaders = true;
		}
		apply();
	} else {
		clear();
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cUserRestriction::apply() {
	if(!src_ip.empty()) {
		cond_ip = new FILE_LINE(0) ListIP;
		cond_ip->add(src_ip.c_str());
	}
	if(!src_number.empty()) {
		cond_number = new FILE_LINE(0) ListPhoneNumber;
		cond_number->add(src_number.c_str());
	}
	if(!src_domain.empty()) {
		cond_domain = new FILE_LINE(0) ListCheckString;
		cond_domain->add(src_domain.c_str());
	}
	if(!src_vlan.empty()) {
		vector<int> vlans = split2int(src_vlan, split(",|;|\n", '|'), true);
		if(vlans.size()) {
			cond_vlan = new FILE_LINE(0) list<u_int16_t>;
			for(unsigned i = 0; i < vlans.size(); i++) {
				cond_vlan->push_back(vlans[i]);
			}
			cond_vlan->sort();
		}
	}
	if(!src_ch_cdr.empty()) {
		cond_ch_cdr = new FILE_LINE(0) cLogicHierarchyAndOr_custom_header();
		cond_ch_cdr->set(src_ch_cdr.c_str());
	}
	if(!src_ch_message.empty()) {
		cond_ch_message = new FILE_LINE(0) cLogicHierarchyAndOr_custom_header();
		cond_ch_message->set(src_ch_message.c_str());
	}
}

void cUserRestriction::clear() {
	uid = 0;
	src_ip = "";
	src_number = "";
	src_domain = "";
	src_vlan = "";
	src_ch_cdr = "";
	src_ch_message = "";
	comb_cond = _cc_and;
	if(cond_ip) {
		delete cond_ip;
		cond_ip = NULL;
	}
	if(cond_number) {
		delete cond_number;
		cond_number = NULL;
	}
	if(cond_domain) {
		delete cond_domain;
		cond_domain = NULL;
	}
	if(cond_vlan) {
		delete cond_vlan;
		cond_vlan = NULL;
	}
	if(cond_ch_cdr) {
		delete cond_ch_cdr;
		cond_ch_cdr = NULL;
	}
	if(cond_ch_message) {
		delete cond_ch_message;
		cond_ch_message = NULL;
	}
}

bool cUserRestriction::check(eTypeSrc type_src,
			     vmIP *ip_src, vmIP *ip_dst,
			     const char *number_src, const char *number_dst, const char *number_contact,
			     const char *domain_src, const char *domain_dst, const char *domain_contact,
			     u_int16_t vlan,
			     map<string, string> *ch) {
	unsigned count_used_cond = 0;
	if(cond_ip) {
		bool rslt_any = false;
		for(unsigned i = 0; i < 2; i++) {
			if(i == 0 ? ip_src : ip_dst) {
				bool rslt = cond_ip->checkIP(*(i == 0 ? ip_src : ip_dst));
				if(rslt) {
					if(comb_cond == _cc_or) return(true); 
					rslt_any = true;
					break;
				}
			}
		}
		if(!rslt_any && comb_cond == _cc_and) return(false);
		++count_used_cond;
	}
	if(cond_number) {
		bool rslt_any = false;
		for(unsigned i = 0; i < 3; i++) {
			if(i == 0 ? number_src : 
			   i == 1 ? number_dst : number_contact) {
				bool rslt = cond_number->checkNumber(i == 0 ? number_src : 
								     i == 1 ? number_dst : number_contact);
				if(rslt) {
					if(comb_cond == _cc_or) return(true); 
					rslt_any = true;
					break;
				}
			}
		}
		if(!rslt_any && comb_cond == _cc_and) return(false);
		++count_used_cond;
	}
	if(cond_domain) {
		bool rslt_any = false;
		for(unsigned i = 0; i < 3; i++) {
			if(i == 0 ? domain_src : 
			   i == 1 ? domain_dst : domain_contact) {
				bool rslt = cond_domain->check(i == 0 ? domain_src : 
							       i == 1 ? domain_dst : domain_contact);
				if(rslt) {
					if(comb_cond == _cc_or) return(true); 
					rslt_any = true;
					break;
				}
			}
		}
		if(!rslt_any && comb_cond == _cc_and) return(false);
		++count_used_cond;
	}
	if(cond_vlan && vlan != VLAN_UNSET) {
		list<u_int16_t>::iterator iter = std::lower_bound(cond_vlan->begin(), cond_vlan->end(), vlan);
		bool rslt = iter != cond_vlan->end() && *iter == vlan;
		if(comb_cond == _cc_or) {
			if(rslt) return(true); 
		} else {
			if(!rslt) return(false); 
		}
		++count_used_cond;
	}
	if(type_src == _ts_cdr && cond_ch_cdr && ch) {
		bool rslt = cond_ch_cdr->eval(ch);
		if(comb_cond == _cc_or) {
			if(rslt) return(true); 
		} else {
			if(!rslt) return(false); 
		}
		++count_used_cond;
	}
	if(type_src == _ts_message && cond_ch_message && ch) {
		bool rslt = cond_ch_message->eval(ch);
		if(comb_cond == _cc_or) {
			if(rslt) return(true); 
		} else {
			if(!rslt) return(false); 
		}
		++count_used_cond;
	}
	return(comb_cond == _cc_or ?
		count_used_cond == 0 :
		true);
}

cLogicHierarchyAndOr::cLogicHierarchyAndOr() {
}

cLogicHierarchyAndOr::~cLogicHierarchyAndOr() {
	clear();
}

bool cLogicHierarchyAndOr::eval(void *data) {
	unsigned index = 0;
	return(eval(&index, data));
}

void cLogicHierarchyAndOr::set(const char *src) {
	vector<string> src_v = split(src, '\n');
	for(unsigned i = 0; i < src_v.size(); i++) {
		if(src_v[i][0] == '[' && src_v[i][src_v[i].length() - 1] == ']') {
			size_t delim_pos = src_v[i].find(',');
			if(delim_pos != string::npos) {
				string a = src_v[i].substr(1, delim_pos - 1);
				string b = src_v[i].substr(delim_pos + 1, src_v[i].length() - delim_pos - 2);
				if(b.length() > 2 && b[0] == '"' && b[b.length() - 1] == '"') {
					b = b.substr(1, b.length() - 2);
				}
				if(!a.empty() && !b.empty()) {
					cItem *item = createItem(atoi(a.c_str()), b.c_str()); 
					if(item) {
						items.push_back(item);
					}
				}
			}
		}
	}
}

bool cLogicHierarchyAndOr::eval(unsigned *index, void *data) {
	int level = items[*index]->level;
	vector<bool> rslts;
	while(*index < items.size()) {
		if(items[*index]->level < level) {
			break;
		} else if(items[*index]->level > level) {
			bool rslt = eval(index, data);
			rslts[rslts.size() - 1] = rslts[rslts.size() - 1] & rslt;
		} else {
			bool rslt = items[*index]->eval(data);
			rslts.push_back(rslt);
			++*index;
		}
	}
	for(unsigned i = 0; i < rslts.size(); i++) {
		if(rslts[i]) {
			return(true);
		}
	}
	return(false);
}

cLogicHierarchyAndOr::cItem *cLogicHierarchyAndOr::createItem(int level, const char *data) {
	cItem *item = new FILE_LINE(0) cItem(level);
	return(item);
}


void cLogicHierarchyAndOr::clear() {
	for(unsigned i = 0; i < items.size(); i++) {
		delete items[i];
	}
	items.clear();
}

bool cLogicHierarchyAndOr_custom_header::cItemCustomHeader::eval(void *data) {
	map<string, string> *ch = (map<string, string>*)data;
	map<string, string>::iterator iter = ch->find(custom_header);
	if(iter != ch->end()) {
		return(str_like(iter->second.c_str(), pattern.c_str()));
	} else {
		return(false);
	}
}

cLogicHierarchyAndOr::cItem *cLogicHierarchyAndOr_custom_header::createItem(int level, const char *data) {
	const char *data_separator = strchr(data, ':');
	if(data_separator) {
		string custom_header = string(data).substr(0, data_separator - data);
		string value = string(data_separator + 1);
		cItemCustomHeader *item = new FILE_LINE(0) cItemCustomHeader(level, custom_header.c_str(), value.c_str());
		return(item);
	}
	return(NULL);
}
