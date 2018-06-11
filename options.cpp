#include <iostream>
#include <iomanip>
#include <math.h>

#include "voipmonitor.h"
#include "options.h"
#include "filter_options.h"
#include "tools.h"
#include "sql_db.h"


extern int opt_nocdr;

cOptionsRelations optionsRelations;


struct OptionsFields {
	eOptionsField filedType;
	const char *fieldName;
} optionsFields[] = {
	{ of_id, "ID" },
	{ of_id_sensor, "id_sensor" },
	{ of_ip_src, "ip_src" },
	{ of_ip_dst, "ip_dst" },
	{ of_port_src, "port_src" },
	{ of_port_dst, "port_dst" },
	{ of_number_src, "number_src" },
	{ of_number_dst, "number_dst" },
	{ of_domain_src, "domain_src" },
	{ of_domain_dst, "domain_dst" },
	{ of_ua_src, "ua_src" },
	{ of_ua_dst, "ua_dst" },
	{ of_last_options_time, "last_options_time" },
	{ of_last_options_time_us, "last_options_time_us" },
	{ of_last_response_time, "last_response_time" },
	{ of_last_response_time_us, "last_response_time_us" },
	{ of_response_time_ms, "response_time" },
	{ of_last_response_number, "last_response_number" },
	{ of_last_response_string, "last_response_string" },
	{ of_qualify_ok, "qualify_ok" },
	{ of_history, "history" }
};


bool opt_sip_options_compare_ip_src = true;
bool opt_sip_options_compare_ip_dst = true;
bool opt_sip_options_compare_port_src = true;
bool opt_sip_options_compare_port_dst = false;
bool opt_sip_options_compare_number_src = true;
bool opt_sip_options_compare_number_dst = true;
bool opt_sip_options_compare_domain_src = true;
bool opt_sip_options_compare_domain_dst = true;

unsigned opt_cleanup_item_response_by_max_items = 5;
unsigned opt_cleanup_history_by_max_items = 500;
unsigned opt_cleanup_relations_limit_time = 3600;
unsigned opt_cleanup_relations_period = 60;
unsigned opt_datarow_limit_time = 5;


bool cOptionsItem_base:: operator == (const cOptionsItem_base& other) const {
	return(this->ip_src == other.ip_src &&
	       this->ip_dst == other.ip_dst &&
	       this->port_src == other.port_src &&
	       this->port_dst == other.port_dst &&
	       this->number_src == other.number_src &&
	       this->number_dst == other.number_dst &&
	       this->domain_src == other.domain_src &&
	       this->domain_dst == other.domain_dst);
}

void cOptionsItem_base::debug_out() {
	cout << inet_ntostring(ip_src) << ':' << port_src << " -> " << inet_ntostring(ip_dst) << ':' << port_dst <<  endl
	     << number_src << '@' << domain_src << " -> " << number_dst << '@' << domain_dst << endl;
}

bool cOptionsItem:: operator == (const cOptionsItem& other) const {
	return(*(const cOptionsItem_base*)this == *(const cOptionsItem_base*)&other &&
	       this->response == other.response &&
	       this->callid == other.callid &&
	       this->cseq_number == other.cseq_number &&
	       this->callername == other.callername &&
	       this->ua == other.ua && 
	       this->response_number == other.response_number &&
	       this->response_string == other.response_string);
}

void cOptionsItem::debug_out() {
	cout << (time_us/1000000) << '.' << setw(6) << setfill('0') << (time_us%1000000) << endl;
	cOptionsItem_base::debug_out();
	cout << callid << " / " << cseq_number << endl;
	if(response) {
		cout << response_number << " / " << response_string << endl;
	}
}


cOptionsRelationId::cOptionsRelationId(cOptionsItem_base *options) {
	this->options = options;
}

bool cOptionsRelationId:: operator == (const cOptionsRelationId& other) const {
	return((!opt_sip_options_compare_ip_src || this->options->ip_src == other.options->ip_src) &&
	       (!opt_sip_options_compare_ip_dst || this->options->ip_dst == other.options->ip_dst) &&
	       (!opt_sip_options_compare_port_src || this->options->port_src == other.options->port_src) &&
	       (!opt_sip_options_compare_port_dst || this->options->port_dst == other.options->port_dst) &&
	       (!opt_sip_options_compare_number_src || this->options->number_src == other.options->number_src) &&
	       (!opt_sip_options_compare_number_dst || this->options->number_dst == other.options->number_dst) &&
	       (!opt_sip_options_compare_domain_src || this->options->domain_src == other.options->domain_src) &&
	       (!opt_sip_options_compare_domain_dst || this->options->domain_dst == other.options->domain_dst));
}

bool cOptionsRelationId:: operator < (const cOptionsRelationId& other) const { 
	return((opt_sip_options_compare_ip_src && this->options->ip_src < other.options->ip_src) ? 1 : (opt_sip_options_compare_ip_src && this->options->ip_src > other.options->ip_src) ? 0 :
	       (opt_sip_options_compare_ip_dst && this->options->ip_dst < other.options->ip_dst) ? 1 : (opt_sip_options_compare_ip_dst && this->options->ip_dst > other.options->ip_dst) ? 0 :
	       (opt_sip_options_compare_port_src && this->options->port_src < other.options->port_src) ? 1 : (opt_sip_options_compare_port_src && this->options->port_src > other.options->port_src) ? 0 :
	       (opt_sip_options_compare_port_dst && this->options->port_dst < other.options->port_dst) ? 1 : (opt_sip_options_compare_port_dst && this->options->port_dst > other.options->port_dst) ? 0 :
	       (opt_sip_options_compare_number_src && this->options->number_src < other.options->number_src) ? 1 : (opt_sip_options_compare_number_src && this->options->number_src > other.options->number_src) ? 0 :
	       (opt_sip_options_compare_number_dst && this->options->number_dst < other.options->number_dst) ? 1 : (opt_sip_options_compare_number_dst && this->options->number_dst > other.options->number_dst) ? 0 :
	       (opt_sip_options_compare_domain_src && this->options->domain_src < other.options->domain_src) ? 1 : (opt_sip_options_compare_domain_src && this->options->domain_src < other.options->domain_src) ? 0 :
	       (opt_sip_options_compare_domain_dst && this->options->domain_dst < other.options->domain_dst) ? 1 : (opt_sip_options_compare_domain_src && this->options->domain_src < other.options->domain_src) ? 0 : 0);
}


cOptionsItemResponse::~cOptionsItemResponse() {
	if(item) {
		delete item;
	}
	if(response) {
		delete response;
	}
}

u_int64_t cOptionsItemResponse::getLastOptionsTime() {
	return(item ? item->time_us : 0);
}

u_int64_t cOptionsItemResponse::getLastResponseTime() {
	return(response ? response->time_us : 0);
}

u_int64_t cOptionsItemResponse::getLastTime() {
	return(max(getLastOptionsTime(), getLastResponseTime()));
}

string cOptionsRelation::sHistoryData::getJson(cStringCache *responseStringCache, int qualifyOk) {
	string json = "[";
	json += '"' + json_encode(sqlDateTimeString(options_time_us / 1000000)) + '"';
	json += ',';
	json += intToString(options_time_us % 1000000);
	if(response_time_us) {
		json += ',';
		json += intToString((long long)round((response_time_us - options_time_us) / 1000.));
		json += ',';
		json += intToString(response_number);
		if(responseStringCache) {
			json += ',';
			json += '"' + json_encode(responseStringCache->getString(response_string_id)) + '"';
		}
		json += ',';
		json += intToString(qualifyOk);
	}
	json += ']';
	return(json);
}

cOptionsRelation::cOptionsRelation(cOptionsItem *item) {
	_sync = 0;
	lock_id();
	id = ++_id;
	unlock_id();
	id_sensor = 0;
	*(cOptionsItem_base*)this = *item;
}

cOptionsRelation::~cOptionsRelation() {
	clear();
}

void cOptionsRelation::addOptions(cOptionsItem *item, cOptionsRelations *relations) {
	lock();
	this->id_sensor = item->id_sensor;
	if(item->response) {
		this->ua_dst = item->ua;
		if(queue_items.size()) {
			deque<cOptionsItemResponse*>::iterator iter;
			for(iter = queue_items.begin(); iter != queue_items.end(); iter++) {
				if(!(*iter)->response && 
				   (*iter)->item->callid == item->callid &&
				   (*iter)->item->cseq_number == item->cseq_number) {
					(*iter)->response = item;
					item = NULL;
					break;
				}
			}
		}
		if(item) {
			delete item;
		}
	} else {
		this->ua_src = item->ua;
		cOptionsItemResponse *itemResponse = NULL;
		if(queue_items.size()) {
			deque<cOptionsItemResponse*>::iterator iter;
			for(iter = queue_items.begin(); iter != queue_items.end(); iter++) {
				if(!(*iter)->response && *(*iter)->item == *item) {
					itemResponse = *iter;
					break;
				}
			}
		}
		if(itemResponse) {
			itemResponse->prev_time_us.push_back(itemResponse->item->time_us);
			itemResponse->item->time_us = item->time_us;
			delete item;
		} else {
			itemResponse = new FILE_LINE(0) cOptionsItemResponse;
			itemResponse->item = item;
			queue_items.push_back(itemResponse);
		}
	}
	unlock();
	cleanup_item_response_by_max_items(opt_cleanup_item_response_by_max_items, relations);
	cleanup_history_by_max_items(opt_cleanup_history_by_max_items);
}

bool cOptionsRelation::getDataRow(RecordArray *rec, u_int64_t limit_options_time_us, cOptionsRelations *relations) {
	lock();
	rec->fields[of_id].set(id);
	rec->fields[of_id_sensor].set(id_sensor);
	rec->fields[of_ip_src].set(htonl(ip_src));
	rec->fields[of_ip_dst].set(htonl(ip_dst));
	rec->fields[of_port_src].set(port_src);
	rec->fields[of_port_dst].set(port_dst);
	rec->fields[of_number_src].set(number_src.c_str());
	rec->fields[of_number_dst].set(number_dst.c_str());
	rec->fields[of_domain_src].set(domain_src.c_str());
	rec->fields[of_domain_dst].set(domain_dst.c_str());
	rec->fields[of_ua_src].set(ua_src.c_str());
	rec->fields[of_ua_dst].set(ua_dst.c_str());
	u_int64_t options_time_us;
	u_int64_t response_time_us;
	int response_number;
	string response_string;
	int response_time = getLastResponseTime(limit_options_time_us, 
						&options_time_us, &response_time_us,
						&response_number, &response_string,
						relations,
						false);
	if(options_time_us) {
		rec->fields[of_last_options_time].set(options_time_us / 1000000, RecordArrayField::tf_time);
		rec->fields[of_last_options_time_us].set(options_time_us % 1000000);
	}
	if(response_time_us) {
		rec->fields[of_last_response_time].set(response_time_us / 1000000, RecordArrayField::tf_time);
		rec->fields[of_last_response_time_us].set(response_time_us % 1000000);
	}
	rec->fields[of_response_time_ms].set(response_time < 0 ? response_time : round(response_time / 1000.));
	rec->fields[of_last_response_number].set(response_number);
	rec->fields[of_last_response_string].set(response_string.c_str());
	rec->fields[of_qualify_ok].set(relations->isQualifyOk(this, response_time, response_number));
	string historyDataJson;
	if(getHistoryDataJson(&historyDataJson, limit_options_time_us, false, 10, relations, false)) {
		rec->fields[of_history].set(historyDataJson.c_str(), RecordArrayField::tf_json);
	}
	unlock();
	return(true);
}

u_int64_t cOptionsRelation::getLastOptionsTime() {
	u_int64_t rslt = 0;
	lock();
	if(queue_items.size()) {
		rslt = queue_items.back()->getLastOptionsTime();
	} else if(history.size()) {
		rslt = history.back().options_time_us;
	}
	unlock();
	return(rslt);
}

u_int64_t cOptionsRelation::getLastResponseTime() {
	u_int64_t rslt = 0;
	lock();
	if(queue_items.size()) {
		for(int i = queue_items.size() - 1; i >= 0; i--) {
			u_int64_t resp_time = queue_items[i]->getLastResponseTime();
			if(resp_time) {
				rslt = resp_time;
				break;
			}
		}
	}
	if(!rslt && history.size()) {
		for(int i = history.size() - 1; i >= 0; i--) {
			u_int64_t resp_time = history[i].response_time_us;
			if(resp_time) {
				rslt = resp_time;
				break;
			}
		}
	}
	unlock();
	return(rslt);
}

u_int64_t cOptionsRelation::getLastTime() {
	u_int64_t rslt = 0;
	lock();
	if(queue_items.size()) {
		rslt = queue_items.back()->getLastTime();
	} else if(history.size()) {
		rslt = max(history.back().options_time_us, history.back().response_time_us);
	}
	unlock();
	return(rslt);
}

bool cOptionsRelation::getLastHistoryData(sHistoryData *data, u_int64_t limit_options_time_us, 
					  cOptionsRelations *relations,
					  bool useLock) {
	bool rslt = false;
	if(useLock) {
		lock();
	}
	if(queue_items.size()) {
		for(int i = queue_items.size() - 1; i >= 0; i--) {
			if(queue_items[i]->getLastOptionsTime() < limit_options_time_us) {
				convItemResponseToHistoryData(queue_items[i], data, relations, false);
				rslt = true;
				break;
			}
		}
	}
	if(!rslt && history.size()) {
		for(int i = history.size() - 1; i >= 0; i--) {
			if(history[i].options_time_us < limit_options_time_us) {
				*data = history[i];
				rslt = true;
				break;
			}
		}
	}
	if(useLock) {
		unlock();
	}
	if(!rslt) {
		data->clear();
	}
	return(rslt);
}

int32_t cOptionsRelation::getLastResponseTime(u_int64_t limit_options_time_us, 
					      u_int64_t *options_time_us, u_int64_t *response_time_us,
					      int *response_number, string *response_string,
					      cOptionsRelations *relations,
					      bool useLock) {
	sHistoryData historyData;
	getLastHistoryData(&historyData, limit_options_time_us, relations, useLock);
	*options_time_us = historyData.options_time_us;
	*response_time_us = historyData.response_time_us;
	*response_number = historyData.response_number;
	*response_string = relations->responseStringCache.getString(historyData.response_string_id);
	return(historyData.response_time_us ? historyData.response_time_us - historyData.options_time_us : -1);
}

bool cOptionsRelation::getHistoryData(list<sHistoryData> *historyData, u_int64_t limit_options_time_us, unsigned maxItems,
				      cOptionsRelations *relations,
				      bool useLock) {
	bool rslt = false;
	if(useLock) {
		lock();
	}
	if(queue_items.size()) {
		sHistoryData historyDataItem;
		for(int i = queue_items.size() - 1; i >= 0; i--) {
			if(queue_items[i]->getLastOptionsTime() < limit_options_time_us) {
				convItemResponseToHistoryData(queue_items[i], &historyDataItem, relations, false);
				historyData->push_back(historyDataItem);
				rslt = true;
				if(queue_items[i]->prev_time_us.size() &&
				   !(maxItems && historyData->size() >= maxItems)) {
					list<u_int64_t>::iterator iter = queue_items[i]->prev_time_us.end();
					while(iter != queue_items[i]->prev_time_us.begin()) {
						--iter;
						historyDataItem.clear();
						historyDataItem.options_time_us = *iter;
						historyData->push_back(historyDataItem);
						if(maxItems && historyData->size() >= maxItems) {
							break;
						}
					}
				}
				if(maxItems && historyData->size() >= maxItems) {
					break;
				}
			}
		}
	}
	if(history.size() && (!maxItems || historyData->size() < maxItems)) {
		for(int i = history.size() - 1; i >= 0; i--) {
			if(history[i].options_time_us < limit_options_time_us) {
				historyData->push_back(history[i]);
				rslt = true;
				if(maxItems && historyData->size() >= maxItems) {
					break;
				}
			}
		}
	}
	if(useLock) {
		unlock();
	}
	if(!rslt) {
		historyData->clear();
	}
	return(rslt);
}

bool cOptionsRelation::getHistoryDataJson(string *historyData, u_int64_t limit_options_time_us, bool withResponseString, unsigned maxItems,
					  cOptionsRelations *relations,
					  bool useLock) {
	*historyData = "";
	list<sHistoryData> historyDataList;
	if(getHistoryData(&historyDataList, limit_options_time_us, maxItems, relations, useLock)) {
		*historyData += '[';
		unsigned counter = 0;
		for(list<sHistoryData>::iterator iter = historyDataList.begin(); iter != historyDataList.end(); iter++) {
			if(counter) {
				*historyData += ',';
			}
			*historyData += iter->getJson(withResponseString ? &relations->responseStringCache : NULL,
						      relations->isQualifyOk(this, iter->getResponseTime(), iter->response_number));
			++counter;
		}
		*historyData += ']';
		return(true);
	} else {
		return(false);
	}
}

void cOptionsRelation::debug_out(cOptionsRelations *relations) {
	lock();
	cout << "*** RELATION" << endl;
	((cOptionsItem_base*)this)->debug_out();
	deque<cOptionsItemResponse*>::iterator iter_ir;
	for(iter_ir = queue_items.begin(); iter_ir != queue_items.end(); iter_ir++) {
		if((*iter_ir)->item) {
			cout << " * options" << endl;
			(*iter_ir)->item->debug_out();
		}
		if((*iter_ir)->prev_time_us.size()) {
			list<u_int64_t>::iterator iter;
			for(iter = (*iter_ir)->prev_time_us.begin(); iter != (*iter_ir)->prev_time_us.end(); iter++) {
				cout << "   prev " << ((*iter)/1000000) << '.' << setw(6) << setfill('0') << ((*iter)%1000000) << endl;
			}
		}
		if((*iter_ir)->response) {
			cout << " * response" << endl;
			(*iter_ir)->response->debug_out();
		}
	}
	if(history.size()) {
		deque<sHistoryData>::iterator iter_h;
		for(iter_h = history.begin(); iter_h != history.end(); iter_h++) {
			cout << "   history " << ((iter_h->options_time_us)/1000000) << '.' << setw(6) << setfill('0') << ((iter_h->options_time_us)%1000000);
			if(iter_h->response_time_us) {
				cout << " resp " << ((iter_h->response_time_us)/1000000) << '.' << setw(6) << setfill('0') << ((iter_h->response_time_us)%1000000);
				cout << " " << iter_h->response_number << " / " << relations->responseStringCache.getStr(iter_h->response_string_id);
			}
			cout << endl;
		}
	}
	cout << endl;
	unlock();
}

void cOptionsRelation::convItemResponseToHistoryData(cOptionsItemResponse *itemResponse, sHistoryData *historyData, 
						     cOptionsRelations *relations,
						     bool useLock) {
	if(useLock) {
		lock();
	}
	historyData->options_time_us = itemResponse->item->time_us;
	if(itemResponse->response) {
		historyData->response_time_us = itemResponse->response->time_us;
		historyData->response_number = itemResponse->response->response_number;
		historyData->response_string_id = relations->responseStringCache.getId(itemResponse->response->response_string.c_str());
	} else {
		historyData->clearResponse();
	}
	if(useLock) {
		unlock();
	}
}

void cOptionsRelation::clear() {
	lock();
	deque<cOptionsItemResponse*>::iterator iter;
	for(iter = queue_items.begin(); iter != queue_items.end(); iter++) {
		delete *iter;
	}
	queue_items.clear();
	unlock();
}

void cOptionsRelation::cleanup_item_response_by_limit_time(u_int64_t limit_time_us, cOptionsRelations *relations) {
	lock();
	while(queue_items.size() &&
	      (!limit_time_us || queue_items.front()->getLastTime() < limit_time_us)) {
		cOptionsItemResponse *itemResponse = queue_items.front();
		if(itemResponse->prev_time_us.size()) {
			list<u_int64_t>::iterator iter;
			for(iter = itemResponse->prev_time_us.begin(); iter != itemResponse->prev_time_us.end(); iter++) {
				sHistoryData historyItem;
				historyItem.options_time_us = *iter;
				history.push_back(historyItem);
			}
		}
		if(itemResponse->item) {
			sHistoryData historyItem;
			historyItem.options_time_us = itemResponse->item->time_us;
			if(itemResponse->response) {
				historyItem.response_time_us = itemResponse->response->time_us;
				historyItem.response_number = itemResponse->response->response_number;
				historyItem.response_string_id = relations->responseStringCache.getId(itemResponse->response->response_string.c_str());
			}
			history.push_back(historyItem);
		}
		queue_items.pop_front();
		delete itemResponse;
	}
	unlock();
}

void cOptionsRelation::cleanup_item_response_by_max_items(unsigned max_items, cOptionsRelations *relations) {
	lock();
	while(queue_items.size() > max_items) {
		cOptionsItemResponse *itemResponse = queue_items.front();
		if(itemResponse->prev_time_us.size()) {
			list<u_int64_t>::iterator iter;
			for(iter = itemResponse->prev_time_us.begin(); iter != itemResponse->prev_time_us.end(); iter++) {
				sHistoryData historyItem;
				historyItem.options_time_us = *iter;
				history.push_back(historyItem);
			}
		}
		if(itemResponse->item) {
			sHistoryData historyItem;
			historyItem.options_time_us = itemResponse->item->time_us;
			if(itemResponse->response) {
				historyItem.response_time_us = itemResponse->response->time_us;
				historyItem.response_number = itemResponse->response->response_number;
				historyItem.response_string_id = relations->responseStringCache.getId(itemResponse->response->response_string.c_str());
			}
			history.push_back(historyItem);
		}
		queue_items.pop_front();
		delete itemResponse;
	}
	unlock();
}

void cOptionsRelation::cleanup_history_by_limit_time(u_int64_t limit_time_us) {
	lock();
	while(history.size() &&
	      (!limit_time_us || history.front().options_time_us < limit_time_us)) {
		history.pop_front();
	}
	unlock();
}

void cOptionsRelation::cleanup_history_by_max_items(unsigned max_items) {
	lock();
	while(history.size() > max_items) {
		history.pop_front();
	}
	unlock();
}

volatile u_int64_t cOptionsRelation::_id = 0;
volatile int cOptionsRelation::_sync_id = 0;


cOptionsRelations::cOptionsRelations() {
	_sync_relations = 0;
	_sync_delete_relation = 0;
	_sync_params = 0;
	_sync_params_load = 0;
	lastCleanupRelations = getTimeMS_rdtsc();
}

cOptionsRelations::~cOptionsRelations() {
	clear();
}

void cOptionsRelations::addOptions(cOptionsItem *item) {
 
	/*
	item->debug_out();
	cout << endl;
	*/
 
	if(!checkProcess(item)) {
		delete item;
		return;
	}
	cOptionsRelation *relation = NULL;
	map<cOptionsRelationId, cOptionsRelation*>::iterator iter;
	iter = relations.find(item);
	if(iter != relations.end()) {
		relation = iter->second;
	}
	if(!relation) {
		if(item->response) {
			delete item;
			return;
		}
		relation = new FILE_LINE(0) cOptionsRelation(item);
		relations[relation] = relation;
	}
	relation->addOptions(item, this);
	u_long time_ms = getTimeMS_rdtsc();
	if(lastCleanupRelations < time_ms - opt_cleanup_relations_period * 1000) {
		cleanup_relations(((u_int64_t)time_ms - opt_cleanup_relations_limit_time * 1000) * 1000);
		lastCleanupRelations = time_ms;
	}
}

void cOptionsRelations::clear() {
 
	/*
	debug_out();
	cleanup_item_response_by_limit_time(0);
	cout << "-------------------------------" << endl;
	debug_out();
	*/
 
	map<cOptionsRelationId, cOptionsRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		delete iter->second;
	}
	relations.clear();
}

void cOptionsRelations::loadParams() {
	sParams paramsNew;
	if(loadParams(&paramsNew)) {
		lock_params();
		params = paramsNew;
		unlock_params();
	}
}

void cOptionsRelations::loadParamsInBackground() {
	lock_params_load();
	pthread_t thread;
	vm_pthread_create_autodestroy("cOptionsRelations::loadParams",
				      &thread, NULL, cOptionsRelations::_loadParamsInBackground, this, __FILE__, __LINE__);
}

void cOptionsRelations::cleanup_item_response_by_limit_time(u_int64_t limit_time_us) {
	map<cOptionsRelationId, cOptionsRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		iter->second->cleanup_item_response_by_limit_time(limit_time_us, this);
	}
}

void cOptionsRelations::cleanup_history_by_limit_time(u_int64_t limit_time_us) {
	map<cOptionsRelationId, cOptionsRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		iter->second->cleanup_history_by_limit_time(limit_time_us);
	}
}

void cOptionsRelations::cleanup_relations(u_int64_t limit_time_us) {
	map<cOptionsRelationId, cOptionsRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); ) {
		if(iter->second->getLastTime() < limit_time_us) {
			lock_delete_relation();
			delete iter->second;
			relations.erase(iter++);
			unlock_delete_relation();
		} else {
			iter++;
		}
	}
}

bool cOptionsRelations::existsParamsTables() {
	if(opt_nocdr) {
		return(false);
	}
	SqlDb *sqlDb = createSqlObject();
	bool rslt = sqlDb->existsTable("options_qualify_settings") &&
		    sqlDb->existsTable("options_qualify") &&
		    sqlDb->existsTable("options_qualify_groups");
	delete sqlDb;
	return(rslt);
}

bool cOptionsRelations::loadParams(sParams *params) {
	params->clear();
	if(!existsParamsTables()) {
		return(false);
	}
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select * from options_qualify_settings limit 1");
	SqlDb_row dbRow = sqlDb->fetchRow();
	if(dbRow) {
		int qualifyLimit = atoi(dbRow["ok_qualify_limit"].c_str());
		if(qualifyLimit > 0) {
			params->defaultParams.qualifyLimit = qualifyLimit;
			vector<string> ok_responses = split(dbRow["ok_responses"].c_str(), split(",|;|\r|\n", "|"), true);
			for(unsigned i = 0; i < ok_responses.size(); i++) {
				int ok_response = atoi(ok_responses[i].c_str());
				if(ok_response > 0) {
					params->defaultParams.okResponses.push_back(ok_response);
				}
			}
		}
	}
	sqlDb->query("select options_qualify.*, \
		      (select group_concat(ip_group_id) from options_qualify_groups \
		       where options_qualify_id = options_qualify.id and type = 'ip_src') as ip_src_group, \
		      (select group_concat(ip_group_id) from options_qualify_groups \
		       where options_qualify_id = options_qualify.id and type = 'ip_dst') as ip_dst_group, \
		      (select group_concat(number_group_id) from options_qualify_groups \
		       where options_qualify_id = options_qualify.id and type = 'number_src') as number_src_group, \
		      (select group_concat(number_group_id) from options_qualify_groups \
		       where options_qualify_id = options_qualify.id and type = 'number_dst') as number_dst_group, \
		      (select group_concat(domain_group_id) from options_qualify_groups \
		       where options_qualify_id = options_qualify.id and type = 'domain_src') as domain_src_group, \
		      (select group_concat(domain_group_id) from options_qualify_groups \
		       where options_qualify_id = options_qualify.id and type = 'domain_dst') as domain_dst_group \
		      from options_qualify");
	while((dbRow = sqlDb->fetchRow())) {
		int qualifyLimit = atoi(dbRow["ok_qualify_limit"].c_str());
		if(qualifyLimit > 0) {
			sParamsRecord recordParams;
			recordParams.name = dbRow["name"];
			recordParams.qualifyLimit =  qualifyLimit;
			vector<string> ok_responses = split(dbRow["ok_responses"].c_str(), split(",|;|\r|\n", "|"), true);
			for(unsigned i = 0; i < ok_responses.size(); i++) {
				int ok_response = atoi(ok_responses[i].c_str());
				if(ok_response > 0) {
					recordParams.okResponses.push_back(ok_response);
				}
			}
			recordParams.ip_src.addComb(dbRow["ip_src"].c_str());
			recordParams.ip_src.addComb(dbRow["ip_src_group"].c_str());
			recordParams.ip_dst.addComb(dbRow["ip_dst"].c_str());
			recordParams.ip_dst.addComb(dbRow["ip_dst_group"].c_str());
			recordParams.number_src.addComb(dbRow["number_src"].c_str());
			recordParams.number_src.addComb(dbRow["number_src_group"].c_str());
			recordParams.number_dst.addComb(dbRow["number_dst"].c_str());
			recordParams.number_dst.addComb(dbRow["number_dst_group"].c_str());
			recordParams.domain_src.addComb(dbRow["domain_src"].c_str());
			recordParams.domain_src.addComb(dbRow["domain_src_group"].c_str());
			recordParams.domain_dst.addComb(dbRow["domain_dst"].c_str());
			recordParams.domain_dst.addComb(dbRow["domain_dst_group"].c_str());
			params->recordsParams.push_back(recordParams);
		}
	}
	delete sqlDb;
	return(params->isSet());
}

void *cOptionsRelations::_loadParamsInBackground(void *arg) {
	cOptionsRelations *me = (cOptionsRelations*)arg;
	me->loadParams();
	me->unlock_params_load();
	return(NULL);
}

string cOptionsRelations::getDataTableJson(char *params, bool *zip) {
 
	JsonItem jsonParams;
	jsonParams.parse(params);

	u_int32_t limit = atol(jsonParams.getValue("limit").c_str());
	string sortBy = jsonParams.getValue("sort_field");
	eOptionsField sortById = convOptionsFieldToFieldId(sortBy.c_str());
	string sortDir = jsonParams.getValue("sort_dir");
	std::transform(sortDir.begin(), sortDir.end(), sortDir.begin(), ::tolower);
	bool sortDesc = sortDir.substr(0, 4) == "desc";
	
	if(zip) {
		string zipParam = jsonParams.getValue("zip");
		std::transform(zipParam.begin(), zipParam.end(), zipParam.begin(), ::tolower);
		*zip = zipParam == "yes";
	}
	
	lock_delete_relation();
	lock_relations();
	
	u_int32_t list_options_size = relations.size();
	u_int32_t list_options_count = 0;
	cOptionsRelation **list_options = new FILE_LINE(0) cOptionsRelation*[list_options_size];
	
	for(map<cOptionsRelationId, cOptionsRelation*>::iterator iter_opt = relations.begin(); iter_opt != relations.end(); iter_opt++) {
		list_options[list_options_count++] = iter_opt->second;
	}
	
	unlock_relations();
	
	list<RecordArray> records;
	for(unsigned i = 0; i < list_options_count; i++) {
		RecordArray rec(of__max);
		if(list_options[i]->getDataRow(&rec, ((u_int64_t)getTimeMS_rdtsc() - opt_datarow_limit_time * 1000) * 1000, this)) {
			rec.sortBy = sortById;
			rec.sortBy2 = of_id;
			records.push_back(rec);
		}
	}
	delete [] list_options;
	
	unlock_delete_relation();

	string table;
	string header = "[";
	for(unsigned i = 0; i < sizeof(optionsFields) / sizeof(optionsFields[0]); i++) {
		if(i) {
			header += ",";
		}
		header += '"' + string(optionsFields[i].fieldName) + '"';
	}
	header += "]";
	table = "[" + header;
	if(records.size()) {
		string filter = jsonParams.getValue("filter");
		if(!filter.empty()) {
			//cout << "FILTER: " << filter << endl;
			cOptionsFilter *optFilter = new cOptionsFilter(filter.c_str());
			for(list<RecordArray>::iterator iter_rec = records.begin(); iter_rec != records.end(); ) {
				if(!optFilter->check(&(*iter_rec))) {
					iter_rec->free();
					records.erase(iter_rec++);
				} else {
					iter_rec++;
				}
			}
			delete optFilter;
		}
	}
	if(records.size()) {
		table += string(", [{\"total\": ") + intToString(records.size()) + "}]";
		if(sortById) {
			records.sort();
		}
		list<RecordArray>::iterator iter_rec = sortDesc ? records.end() : records.begin();
		if(sortDesc) {
			iter_rec--;
		}
		u_int32_t counter = 0;
		while(counter < records.size() && iter_rec != records.end()) {
			table += "," + iter_rec->getJson();
			if(sortDesc) {
				if(iter_rec != records.begin()) {
					iter_rec--;
				} else {
					break;
				}
			} else {
				iter_rec++;
			}
			++counter;
			if(limit && counter >= limit) {
				break;
			}
		}
		for(iter_rec = records.begin(); iter_rec != records.end(); iter_rec++) {
			iter_rec->free();
		}
	}
	table += "]";
	return(table);
}

string cOptionsRelations::getHistoryDataJson(char *params, bool *zip) {
	JsonItem jsonParams;
	jsonParams.parse(params);
	u_int64_t id = atoll(jsonParams.getValue("id").c_str());
	if(zip) {
		string zipParam = jsonParams.getValue("zip");
		std::transform(zipParam.begin(), zipParam.end(), zipParam.begin(), ::tolower);
		*zip = zipParam == "yes";
	}
	return(getHistoryDataJson(id));
}

string cOptionsRelations::getHistoryDataJson(u_int64_t id) {
	cOptionsRelation *relation = NULL;
	lock_delete_relation();
	lock_relations();
	for(map<cOptionsRelationId, cOptionsRelation*>::iterator iter = relations.begin(); iter != relations.end(); iter++) {
		if(iter->second->id == id) {
			relation = iter->second;
		}
	}
	unlock_relations();
	list<cOptionsRelation::sHistoryData> historyData;
	if(relation) {
		relation->getHistoryData(&historyData, ((u_int64_t)getTimeMS_rdtsc() - opt_datarow_limit_time * 1000) * 1000, 0, this);
	}
	unlock_delete_relation();
	string historyDataJson;
	if(historyData.size()) {
		historyDataJson += '[';
		unsigned counter = 0;
		for(list<cOptionsRelation::sHistoryData>::iterator iter = historyData.begin(); iter != historyData.end(); iter++) {
			if(counter) {
				historyDataJson += ',';
			}
			historyDataJson += iter->getJson(&responseStringCache,
							 this->isQualifyOk(relation, iter->getResponseTime(), iter->response_number));
			++counter;
		}
		historyDataJson += ']';
	}
	return(historyDataJson);
}

void cOptionsRelations::debug_out() {
	map<cOptionsRelationId, cOptionsRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		iter->second->debug_out(this);
	}
}


eOptionsField convOptionsFieldToFieldId(const char *field) {
	for(unsigned i = 0; i < sizeof(optionsFields) / sizeof(optionsFields[0]); i++) {
		if(!strcmp(field, optionsFields[i].fieldName)) {
			return(optionsFields[i].filedType);
		}
	}
	return((eOptionsField)0);
}
