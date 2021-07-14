#include <iostream>
#include <iomanip>
#include <math.h>

#include "voipmonitor.h"
#include "options.h"
#include "filter_options.h"
#include "tools.h"
#include "sql_db.h"
#include "pcap_queue.h"
#include "sniff.h"
#include "filter_mysql.h"


extern char * gettag_sip_ext(packet_s_process *packetS,
			     const char *tag, unsigned long *gettaglen);
extern char * gettag_sip_ext(packet_s_process *packetS,
			     const char *tag, const char *tag2, unsigned long *gettaglen);

extern MySqlStore *sqlStore;
extern Calltable *calltable;
extern int opt_mysqlstore_max_threads_message;
extern int opt_nocdr;
extern CustomHeaders *custom_headers_sip_msg;
extern int opt_sip_options;
extern int opt_sip_subscribe;
extern int opt_sip_notify;
extern int opt_save_sip_options;
extern int opt_save_sip_subscribe;
extern int opt_save_sip_notify;
extern cSqlDbData *dbData;
extern bool opt_time_precision_in_ms;

cSipMsgRelations *sipMsgRelations;

SqlDb *sqlDbSaveSipMsg = NULL;

extern sExistsColumns existsColumns;

struct SipMsgFields {
	eSipMsgField filedType;
	const char *fieldName;
} sipMsgFields[] = {
	{ smf_id, "ID" },
	{ smf_id_sensor, "id_sensor" },
	{ smf_type, "type" },
	{ smf_ip_src, "ip_src" },
	{ smf_ip_dst, "ip_dst" },
	{ smf_port_src, "port_src" },
	{ smf_port_dst, "port_dst" },
	{ smf_number_src, "number_src" },
	{ smf_number_dst, "number_dst" },
	{ smf_domain_src, "domain_src" },
	{ smf_domain_dst, "domain_dst" },
	{ smf_callername, "callername" },
	{ smf_callid, "callid" },
	{ smf_cseq, "cseq" },
	{ smf_ua_src, "ua_src" },
	{ smf_ua_dst, "ua_dst" },
	{ smf_request_time, "request_time" },
	{ smf_request_time_us, "request_time_us" },
	{ smf_request_first_time, "request_first_time" },
	{ smf_request_first_time_us_compl, "request_first_time_us_compl" },
	{ smf_response_time, "response_time" },
	{ smf_response_time_us, "response_time_us" },
	{ smf_response_duration_ms, "response_duration_ms" },
	{ smf_response_number, "response_number" },
	{ smf_response_string, "response_string" },
	{ smf_qualify_ok, "qualify_ok" },
	{ smf_exists_pcap, "exists_pcap" },
	{ smf_vlan, "vlan" }
};


extern bool opt_sip_msg_compare_ip_src;
extern bool opt_sip_msg_compare_ip_dst;
extern bool opt_sip_msg_compare_port_src;
extern bool opt_sip_msg_compare_port_dst;
extern bool opt_sip_msg_compare_number_src;
extern bool opt_sip_msg_compare_number_dst;
extern bool opt_sip_msg_compare_domain_src;
extern bool opt_sip_msg_compare_domain_dst;
extern bool opt_sip_msg_compare_vlan;

unsigned opt_default_qualify_limit = 2000;
unsigned opt_cleanup_item_response_by_max_items = 5;
unsigned opt_cleanup_history_by_max_items = 50;
unsigned opt_cleanup_relations_limit_time = 300;
unsigned opt_cleanup_relations_period = 60;
unsigned opt_close_pcap_limit_time = 5;
unsigned opt_close_pcaps_period = 10;
unsigned opt_datarow_limit_time = 5;


bool cSipMsgItem_base:: operator == (const cSipMsgItem_base& other) const {
	return(this->id_sensor == other.id_sensor &&
	       this->ip_src == other.ip_src &&
	       this->ip_dst == other.ip_dst &&
	       this->port_src == other.port_src &&
	       this->port_dst == other.port_dst &&
	       this->number_src == other.number_src &&
	       this->number_dst == other.number_dst &&
	       this->domain_src == other.domain_src &&
	       this->domain_dst == other.domain_dst &&
	       this->vlan == other.vlan);
}

void cSipMsgItem_base::debug_out() {
	cout << ip_src.getString() << ':' << port_src << " -> " << ip_dst.getString() << ':' << port_dst <<  endl
	     << number_src << '@' << domain_src << " -> " << number_dst << '@' << domain_dst << endl;
}

bool cSipMsgItem:: operator == (const cSipMsgItem& other) const {
	return(*(const cSipMsgItem_base*)this == *(const cSipMsgItem_base*)&other &&
	       this->response == other.response &&
	       this->callid == other.callid &&
	       this->cseq_number == other.cseq_number &&
	       this->callername == other.callername &&
	       this->ua == other.ua && 
	       this->response_number == other.response_number &&
	       this->response_string == other.response_string);
}

void cSipMsgItem::parseContent(packet_s_process *packetS) {
	bool strictCheckLength = true;
	unsigned long l;
	char *s = gettag_sip_ext(packetS, "\nContent-Type:", "\nc:", &l);
	if(s && l <= 1023) {
		content_type = string(s, l);
	}
	s = gettag_sip_ext(packetS, "\nContent-Length:", &l);
	if(s && l <= 10) {
		content_length = atoi(string(s, l).c_str());
	}
	if(content_length > 0 && content_length < packetS->sipDataLen) {
		char *data = packetS->data_() + packetS->sipDataOffset;
		unsigned int datalen = packetS->sipDataLen;
		char endCharData = data[datalen - 1];
		data[datalen - 1] = 0;
		char *endHeader = strstr(data, "\r\n\r\n");;
		data[datalen - 1] = endCharData;
		if(endHeader) {
			int tryDecContentLength = 0;
			char *contentBegin = endHeader + 4;
			char *contentEnd = strncasestr(contentBegin, "\n\nContent-Length:", datalen - (contentBegin - data));
			if(!contentEnd) {
				contentEnd = strnstr(contentBegin, "\r\n", datalen - (contentBegin - data));
				if(contentEnd) {
					tryDecContentLength = data + datalen - contentEnd;
				}
			}
			if(!contentEnd) {
				contentEnd = data + datalen;
			}
			if(!strictCheckLength || 
			   (contentEnd - contentBegin) == content_length ||
			   (tryDecContentLength > 0 && (contentEnd - contentBegin) == content_length - tryDecContentLength)) {
				content = string(contentBegin, contentEnd - contentBegin);
			}
		}
	}
}

void cSipMsgItem::debug_out() {
	cout << (time_us/1000000) << '.' << setw(6) << setfill('0') << (time_us%1000000) << endl;
	cSipMsgItem_base::debug_out();
	cout << callid << " / " << cseq_number << endl;
	if(response) {
		cout << response_number << " / " << response_string << endl;
	}
}


cSipMsgRelationId::cSipMsgRelationId(cSipMsgItem_base *sipMsg) {
	this->sipMsg = sipMsg;
}

bool cSipMsgRelationId:: operator == (const cSipMsgRelationId& other) const {
	return((!opt_sip_msg_compare_ip_src || this->sipMsg->ip_src == other.sipMsg->ip_src) &&
	       (!opt_sip_msg_compare_ip_dst || this->sipMsg->ip_dst == other.sipMsg->ip_dst) &&
	       (!opt_sip_msg_compare_port_src || this->sipMsg->port_src == other.sipMsg->port_src) &&
	       (!opt_sip_msg_compare_port_dst || this->sipMsg->port_dst == other.sipMsg->port_dst) &&
	       (!opt_sip_msg_compare_number_src || this->sipMsg->number_src == other.sipMsg->number_src) &&
	       (!opt_sip_msg_compare_number_dst || this->sipMsg->number_dst == other.sipMsg->number_dst) &&
	       (!opt_sip_msg_compare_domain_src || this->sipMsg->domain_src == other.sipMsg->domain_src) &&
	       (!opt_sip_msg_compare_domain_dst || this->sipMsg->domain_dst == other.sipMsg->domain_dst) &&
	       (!opt_sip_msg_compare_vlan || this->sipMsg->vlan == other.sipMsg->vlan));
}

bool cSipMsgRelationId:: operator < (const cSipMsgRelationId& other) const { 
	return((opt_sip_msg_compare_ip_src && this->sipMsg->ip_src < other.sipMsg->ip_src) ? 1 : (opt_sip_msg_compare_ip_src && this->sipMsg->ip_src > other.sipMsg->ip_src) ? 0 :
	       (opt_sip_msg_compare_ip_dst && this->sipMsg->ip_dst < other.sipMsg->ip_dst) ? 1 : (opt_sip_msg_compare_ip_dst && this->sipMsg->ip_dst > other.sipMsg->ip_dst) ? 0 :
	       (opt_sip_msg_compare_port_src && this->sipMsg->port_src < other.sipMsg->port_src) ? 1 : (opt_sip_msg_compare_port_src && this->sipMsg->port_src > other.sipMsg->port_src) ? 0 :
	       (opt_sip_msg_compare_port_dst && this->sipMsg->port_dst < other.sipMsg->port_dst) ? 1 : (opt_sip_msg_compare_port_dst && this->sipMsg->port_dst > other.sipMsg->port_dst) ? 0 :
	       (opt_sip_msg_compare_number_src && this->sipMsg->number_src < other.sipMsg->number_src) ? 1 : (opt_sip_msg_compare_number_src && this->sipMsg->number_src > other.sipMsg->number_src) ? 0 :
	       (opt_sip_msg_compare_number_dst && this->sipMsg->number_dst < other.sipMsg->number_dst) ? 1 : (opt_sip_msg_compare_number_dst && this->sipMsg->number_dst > other.sipMsg->number_dst) ? 0 :
	       (opt_sip_msg_compare_domain_src && this->sipMsg->domain_src < other.sipMsg->domain_src) ? 1 : (opt_sip_msg_compare_domain_src && this->sipMsg->domain_src > other.sipMsg->domain_src) ? 0 :
	       (opt_sip_msg_compare_domain_dst && this->sipMsg->domain_dst < other.sipMsg->domain_dst) ? 1 : (opt_sip_msg_compare_domain_dst && this->sipMsg->domain_dst > other.sipMsg->domain_dst) ? 0 :
	       (opt_sip_msg_compare_vlan && this->sipMsg->vlan < other.sipMsg->vlan) ? 1 : (opt_sip_msg_compare_vlan && this->sipMsg->vlan > other.sipMsg->vlan) ? 0 : 0);
}


cSipMsgRequestResponse::cSipMsgRequestResponse(u_int64_t time_us) {
	this->time_us = time_us;
	request = NULL;
	response = NULL;
	saved_to_db = false;
}

cSipMsgRequestResponse::~cSipMsgRequestResponse() {
	if(request) {
		delete request;
	}
	if(response) {
		delete response;
	}
}

void cSipMsgRequestResponse::openPcap(packet_s_process *packetS, int type) {
	if(sverb.disable_save_packet) {
		return;
	}
	cdp.call_data = new FILE_LINE(0) Call_abstract(type, time_us);
	cdp.call_data->useHandle = get_pcap_handle(packetS->handle_index);
	cdp.call_data->useDlt = packetS->dlt;
	cdp.call_data->useSensorId = packetS->sensor_id_();
	cdp.call_data->user_data = this;
	cdp.call_data->user_data_type = type;
	cdp.pcap = new FILE_LINE(0) PcapDumper(PcapDumper::sip, cdp.call_data);
	string pathfilename = cdp.call_data->get_pathfilename(tsf_sip);
	cdp.pcap->open(tsf_sip, pathfilename.c_str(), cdp.call_data->useHandle, cdp.call_data->useDlt);
	cdp.pcap_save = true;
	//cout << "open " << cdp.pcap->getFileName() << endl;
}

void cSipMsgRequestResponse::closePcap(cSipMsgRelations *relations) {
	if(isOpenPcap()) {
		relations->closePcap(&cdp);
		//cout << "close " << cdp.pcap->getFileName() << endl;
	}
}

void cSipMsgRequestResponse::savePacket(packet_s_process *packetS) {
	if(isOpenPcap()) {
		pcap_pkthdr *header = packetS->header_pt;
		u_char *packet = (u_char*)packetS->packet;
		cdp.pcap->dump(header, packet, packetS->dlt, false, 
			       (u_char*)packetS->data_() + packetS->sipDataOffset, packetS->sipDataLen,
			       packetS->saddr_(), packetS->daddr_(), packetS->source_(), packetS->dest_(), packetS->pflags.tcp);
	}
}

void cSipMsgRequestResponse::saveToDb(cSipMsgRelations *relations) {
	relations->saveToDb(this);
}

bool cSipMsgRequestResponse::needSavePcap(cSipMsgRelations *relations, cSipMsgRelation *relation) {
	return(relations->needSavePcap(this, relation));
}

bool cSipMsgRequestResponse::needSaveToDb(cSipMsgRelations *relations, cSipMsgRelation *relation) {
	return(relations->needSaveToDb(this, relation));
}

u_int64_t cSipMsgRequestResponse::getFirstRequestTime() {
	return(request ? request->time_us : 0);
}

u_int64_t cSipMsgRequestResponse::getLastRequestTime() {
	return(request ? 
		(next_requests_time_us.size() ? next_requests_time_us.back() : request->time_us) : 
		0);
}

u_int64_t cSipMsgRequestResponse::getLastResponseTime() {
	return(response ? response->time_us : 0);
}

u_int64_t cSipMsgRequestResponse::getLastTime() {
	return(max(getLastRequestTime(), getLastResponseTime()));
}

string cSipMsgRequestResponse::getPcapFileName() {
	string filename = string(request->type == smt_options ? "OPT" :
				 request->type == smt_subscribe ? "SUB" :
				 request->type == smt_notify ? "NTF" : "") + "_" +
			  request->callid + '_' + intToString(request->cseq_number) + '_' + intToString(time_us);
	prepare_string_to_filename((char*)filename.c_str());
	return(filename);
}

void cSipMsgRequestResponse::destroy(cSipMsgRelations *relations, cSipMsgRelation *relation) {
	if(needSaveToDb(relations, relation)) {
		saveToDb(relations);
	}
	if(isSetCdp()) {
		if(isOpenPcap()) {
			closePcap(relations);
		}
		relations->pushToCdpQueue(&cdp);
	}
	delete this;
}

void cSipMsgRequestResponse::parseCustomHeaders(packet_s_process *packetS, CustomHeaders::eReqRespDirection reqRespDirection) {
	if(custom_headers_sip_msg) {
		custom_headers_sip_msg->parse(NULL, 0, &custom_headers_content, packetS, reqRespDirection);
	}
}

u_int64_t cSipMsgRelation::sHistoryData::getFirstRequestTime() {
	return(request_time_us);
}

u_int64_t cSipMsgRelation::sHistoryData::getLastRequestTime() {
	return(next_requests_time_us.size() ? next_requests_time_us.back() : request_time_us);
}

u_int64_t cSipMsgRelation::sHistoryData::getLastResponseTime() {
	return(response_time_us);
}

u_int64_t cSipMsgRelation::sHistoryData::getLastTime() {
	return(max(getLastRequestTime(), getLastResponseTime()));
}

string cSipMsgRelation::sHistoryData::getJson(cStringCache *responseStringCache, int qualifyOk) {
	JsonExport json;
	json.setTypeItem(JsonExport::_array);
	json.add(NULL, 
		 opt_time_precision_in_ms ?
		  sqlDateTimeString_us2ms(request_time_us) :
		  sqlDateTimeString(TIME_US_TO_S(request_time_us)));
	json.add(NULL, request_time_us);
	if(response_time_us) {
		json.add(NULL, (long long)round((response_time_us - request_time_us) / 1000.));
		json.add(NULL, response_number);
		json.add(NULL,responseStringCache->getString(response_string_id));
		json.add(NULL, qualifyOk);
	} else {
		for(int i = 0; i < 4; i++) {
			json.add(NULL);
		}
	}
	json.add(NULL, callid);
	json.add(NULL, cseq_number);
	json.add(NULL, exists_pcap);
	return(json.getJson());
}

cSipMsgRelation::cSipMsgRelation(cSipMsgItem *item) {
	_sync = 0;
	lock_id();
	id = ++_id;
	unlock_id();
	id_sensor = 0;
	flags = 0;
	*(cSipMsgItem_base*)this = *item;
}

cSipMsgRelation::~cSipMsgRelation() {
	clear();
}

void cSipMsgRelation::addSipMsg(cSipMsgItem *item, packet_s_process *packetS, cSipMsgRelations *relations) {
	lock();
	this->id_sensor = item->id_sensor;
	if(item->response) {
		if(queue_req_resp.size()) {
			deque<cSipMsgRequestResponse*>::iterator iter;
			for(iter = queue_req_resp.begin(); iter != queue_req_resp.end(); iter++) {
				if(!(*iter)->response && 
				   (*iter)->request->callid == item->callid &&
				   (*iter)->request->cseq_number == item->cseq_number) {
					(*iter)->response = item;
					(*iter)->response->parseContent(packetS);
					(*iter)->parseCustomHeaders(packetS, CustomHeaders::dir_response);
					(*iter)->savePacket(packetS);
					item = NULL;
					break;
				}
			}
		}
		if(item) {
			delete item;
		}
	} else {
		cSipMsgRequestResponse *requestResponse = NULL;
		if(queue_req_resp.size()) {
			deque<cSipMsgRequestResponse*>::iterator iter;
			for(iter = queue_req_resp.begin(); iter != queue_req_resp.end(); iter++) {
				if(!(*iter)->response && *(*iter)->request == *item) {
					requestResponse = *iter;
					break;
				}
			}
		}
		if(requestResponse) {
			requestResponse->next_requests_time_us.push_back(getTimeUS(packetS->header_pt));
			delete item;
		} else {
			requestResponse = new FILE_LINE(0) cSipMsgRequestResponse(item->time_us);
			requestResponse->request = item;
			requestResponse->request->parseContent(packetS);
			requestResponse->parseCustomHeaders(packetS, CustomHeaders::dir_request);
			if(requestResponse->needSavePcap(relations, this)) {
				requestResponse->openPcap(packetS, item->type);
			}
			queue_req_resp.push_back(requestResponse);
		}
		requestResponse->savePacket(packetS);
	}
	unlock();
	cleanup_item_response_by_max_items(opt_cleanup_item_response_by_max_items, relations);
	cleanup_history_by_max_items(opt_cleanup_history_by_max_items);
}

bool cSipMsgRelation::getDataRow(RecordArray *rec, u_int64_t limit_time_us, cSipMsgRelations *relations) {
	lock();
	cSipMsgRequestResponse *reqResp = NULL;
	sHistoryData *historyData = NULL;
	if(!getLastHistoryData(limit_time_us, &reqResp, &historyData, false)) {
		unlock();
		return(false);
	}
	u_int64_t request_time_us = 0;
	u_int64_t request_first_time_us = 0;
	u_int64_t response_time_us = 0;
	int64_t response_duration = -1;
	int response_number = 0;
	string response_string;
	if(reqResp) {
		if(reqResp->request) {
			request_time_us = reqResp->getLastRequestTime();
			request_first_time_us = reqResp->getFirstRequestTime();
		}
		if(reqResp->response) {
			response_time_us = reqResp->response->time_us;
			response_number = reqResp->response->response_number;
			response_string = reqResp->response->response_string;
		}
	} else if(historyData) {
		request_time_us = historyData->getLastRequestTime();
		request_first_time_us = historyData->getFirstRequestTime();
		if(historyData->response_time_us) {
			response_time_us = historyData->response_time_us;
			response_number = historyData->response_number;
			response_string = relations->responseStringCache.getString(historyData->response_string_id);
		}
	}
	if(request_time_us && response_time_us && request_time_us < response_time_us) {
		response_duration = response_time_us - request_time_us;
	}
	rec->fields[smf_id].set(id);
	rec->fields[smf_id_sensor].set(id_sensor);
	rec->fields[smf_type].set(type);
	rec->fields[smf_ip_src].set(ip_src, RecordArrayField::tf_ip_n4);
	rec->fields[smf_ip_dst].set(ip_dst, RecordArrayField::tf_ip_n4);
	rec->fields[smf_port_src].set(port_src.getPort());
	rec->fields[smf_port_dst].set(port_dst.getPort());
	rec->fields[smf_number_src].set(number_src.c_str());
	rec->fields[smf_number_dst].set(number_dst.c_str());
	rec->fields[smf_domain_src].set(domain_src.c_str());
	rec->fields[smf_domain_dst].set(domain_dst.c_str());
	if(VLAN_IS_SET(vlan)) {
		rec->fields[smf_vlan].set(vlan);
	}
	if(reqResp) {
		if(reqResp->request) {
			rec->fields[smf_callername].set(reqResp->request->callername.c_str());
			rec->fields[smf_callid].set(reqResp->request->callid.c_str());
			rec->fields[smf_cseq].set(reqResp->request->cseq_number);
			rec->fields[smf_ua_src].set(reqResp->request->ua.c_str());
			rec->fields[smf_exists_pcap].set(reqResp->pcapIsSave());
		}
		if(reqResp->response) {
			rec->fields[smf_ua_dst].set(reqResp->response->ua.c_str());
		}
	} else if(historyData) {
		rec->fields[smf_callername].set(historyData->callername.c_str());
		rec->fields[smf_callid].set(historyData->callid.c_str());
		rec->fields[smf_cseq].set(historyData->cseq_number);
		rec->fields[smf_ua_src].set(relations->uaStringCache.getString(historyData->ua_src_id).c_str());
		rec->fields[smf_exists_pcap].set(historyData->exists_pcap);
		if(historyData->ua_dst_id) {
			rec->fields[smf_ua_dst].set(relations->uaStringCache.getString(historyData->ua_dst_id).c_str());
		}
	}
	if(opt_time_precision_in_ms) {
		rec->fields[smf_request_time].set(request_time_us, RecordArrayField::tf_time_ms);
	} else {
		rec->fields[smf_request_time].set(TIME_US_TO_S(request_time_us), RecordArrayField::tf_time);
	}
	rec->fields[smf_request_time_us].set(TIME_US_TO_DEC_US(request_time_us));
	if(opt_time_precision_in_ms) {
		rec->fields[smf_request_first_time].set(request_first_time_us, RecordArrayField::tf_time_ms);
	} else {
		rec->fields[smf_request_first_time].set(TIME_US_TO_S(request_first_time_us), RecordArrayField::tf_time);
	}
	rec->fields[smf_request_first_time_us_compl].set(request_first_time_us);
	if(response_time_us) {
		if(opt_time_precision_in_ms) {
			rec->fields[smf_response_time].set(response_time_us, RecordArrayField::tf_time_ms);
		} else {
			rec->fields[smf_response_time].set(TIME_US_TO_S(response_time_us), RecordArrayField::tf_time);
		}
		rec->fields[smf_response_time_us].set(TIME_US_TO_DEC_US(response_time_us));
	}
	rec->fields[smf_response_duration_ms].set(response_duration < 0 ? response_duration : round(response_duration / 1000.));
	rec->fields[smf_response_number].set(response_number);
	rec->fields[smf_response_string].set(response_string.c_str());
	rec->fields[smf_qualify_ok].set(relations->isQualifyOk(this, response_duration, response_number));
	unlock();
	return(true);
}

u_int64_t cSipMsgRelation::getLastTime() {
	u_int64_t rslt = 0;
	lock();
	if(queue_req_resp.size()) {
		rslt = queue_req_resp.back()->getLastTime();
	} else if(history.size()) {
		rslt = history.back().getLastTime();
	}
	unlock();
	return(rslt);
}

bool cSipMsgRelation::getLastHistoryData(u_int64_t limit_time_us, 
					 cSipMsgRequestResponse **reqResp, sHistoryData **historyData,
					 bool useLock) {
	bool rslt = false;
	if(useLock) {
		lock();
	}
	if(reqResp) {
		*reqResp = NULL;
	}
	if(historyData) {
		*historyData = NULL;
	}
	if(queue_req_resp.size()) {
		for(int i = queue_req_resp.size() - 1; i >= 0; i--) {
			if(queue_req_resp[i]->getFirstRequestTime() < limit_time_us) {
				if(reqResp) {
					*reqResp = queue_req_resp[i];
				}
				rslt = true;
				break;
			}
		}
	}
	if(!rslt && history.size()) {
		for(int i = history.size() - 1; i >= 0; i--) {
			if(history[i].getFirstRequestTime() < limit_time_us) {
				if(historyData) {
					*historyData = &history[i];
				}
				rslt = true;
				break;
			}
		}
	}
	if(useLock) {
		unlock();
	}
	return(rslt);
}

bool cSipMsgRelation::getHistoryData(list<sHistoryData> *historyData, u_int64_t limit_time_us, unsigned maxItems,
				     cSipMsgRelations *relations,
				     bool useLock) {
	bool rslt = false;
	if(useLock) {
		lock();
	}
	if(queue_req_resp.size()) {
		for(int i = queue_req_resp.size() - 1; i >= 0 && (!maxItems || historyData->size() < maxItems); i--) {
			if(queue_req_resp[i]->next_requests_time_us.size()) {
				list<u_int64_t>::iterator iter = queue_req_resp[i]->next_requests_time_us.end();
				while((!maxItems || historyData->size() < maxItems) &&
				      iter != queue_req_resp[i]->next_requests_time_us.begin()) {
					--iter;
					if(*iter < limit_time_us) {
						sHistoryData historyDataItem;
						convRequestResponseToHistoryData(queue_req_resp[i], &historyDataItem, false, relations, false);
						historyDataItem.request_time_us = *iter;
						historyDataItem.next_requests_time_us.clear();
						historyDataItem.exists_pcap = false;
						historyData->push_back(historyDataItem);
						rslt = true;
					}
				}
			}
			if((!maxItems || historyData->size() < maxItems) &&
			   queue_req_resp[i]->getFirstRequestTime() < limit_time_us) {
				sHistoryData historyDataItem;
				convRequestResponseToHistoryData(queue_req_resp[i], &historyDataItem, true, relations, false);
				historyDataItem.next_requests_time_us.clear();
				historyData->push_back(historyDataItem);
				rslt = true;
			}
		}
	}
	if(history.size()) {
		for(int i = history.size() - 1; i >= 0 && (!maxItems || historyData->size() < maxItems); i--) {
			if(history[i].next_requests_time_us.size()) {
				list<u_int64_t>::iterator iter = history[i].next_requests_time_us.end();
				while((!maxItems || historyData->size() < maxItems) &&
				      iter != history[i].next_requests_time_us.begin()) {
					--iter;
					if(*iter < limit_time_us) {
						sHistoryData historyDataItem = history[i];
						historyDataItem.request_time_us = *iter;
						historyDataItem.clearResponse();
						historyDataItem.next_requests_time_us.clear();
						historyDataItem.exists_pcap = false;
						historyData->push_back(historyDataItem);
						rslt = true;
					}
				}
			}
			if((!maxItems || historyData->size() < maxItems) &&
			   history[i].getFirstRequestTime() < limit_time_us) {
				sHistoryData historyDataItem = history[i];
				historyDataItem.next_requests_time_us.clear();
				historyData->push_back(historyDataItem);
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

void cSipMsgRelation::debug_out(cSipMsgRelations *relations) {
	lock();
	cout << "*** RELATION" << endl;
	((cSipMsgItem_base*)this)->debug_out();
	deque<cSipMsgRequestResponse*>::iterator iter_ir;
	for(iter_ir = queue_req_resp.begin(); iter_ir != queue_req_resp.end(); iter_ir++) {
		if((*iter_ir)->request) {
			cout << " * request" << endl;
			(*iter_ir)->request->debug_out();
		}
		if((*iter_ir)->next_requests_time_us.size()) {
			list<u_int64_t>::iterator iter;
			for(iter = (*iter_ir)->next_requests_time_us.begin(); iter != (*iter_ir)->next_requests_time_us.end(); iter++) {
				cout << "   next " << ((*iter)/1000000) << '.' << setw(6) << setfill('0') << ((*iter)%1000000) << endl;
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
			cout << "   history " << ((iter_h->request_time_us)/1000000) << '.' << setw(6) << setfill('0') << ((iter_h->request_time_us)%1000000);
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

void cSipMsgRelation::convRequestResponseToHistoryData(cSipMsgRequestResponse *requestResponse, sHistoryData *historyData, bool useResponse,
						       cSipMsgRelations *relations,
						       bool useLock) {
	if(useLock) {
		lock();
	}
	historyData->request_time_us = requestResponse->request->time_us;
	historyData->next_requests_time_us = requestResponse->next_requests_time_us;
	historyData->callid = requestResponse->request->callid;
	historyData->cseq_number = requestResponse->request->cseq_number;
	historyData->callername = requestResponse->request->callername;
	historyData->ua_src_id = relations->uaStringCache.getId(requestResponse->request->ua.c_str());
	if(requestResponse->response && useResponse) {
		historyData->response_time_us = requestResponse->response->time_us;
		historyData->response_number = requestResponse->response->response_number;
		historyData->response_string_id = relations->responseStringCache.getId(requestResponse->response->response_string.c_str());
		historyData->ua_dst_id = relations->uaStringCache.getId(requestResponse->response->ua.c_str());
	} else {
		historyData->clearResponse();
	}
	historyData->exists_pcap = requestResponse->pcapIsSave();
	if(useLock) {
		unlock();
	}
}

void cSipMsgRelation::clear() {
	lock();
	deque<cSipMsgRequestResponse*>::iterator iter;
	for(iter = queue_req_resp.begin(); iter != queue_req_resp.end(); iter++) {
		delete *iter;
	}
	queue_req_resp.clear();
	unlock();
}

void cSipMsgRelation::cleanup_item_response_by_limit_time(u_int64_t limit_time_us, cSipMsgRelations *relations) {
	lock();
	while(queue_req_resp.size() &&
	      (!limit_time_us || queue_req_resp.front()->getLastTime() < limit_time_us)) {
		cSipMsgRequestResponse *requestResponse = queue_req_resp.front();
		sHistoryData historyItem;
		convRequestResponseToHistoryData(requestResponse, &historyItem, true, relations, false);
		history.push_back(historyItem);
		queue_req_resp.pop_front();
		requestResponse->destroy(relations, this);
	}
	unlock();
}

void cSipMsgRelation::cleanup_item_response_by_max_items(unsigned max_items, cSipMsgRelations *relations) {
	lock();
	while(queue_req_resp.size() > max_items) {
		cSipMsgRequestResponse *requestResponse = queue_req_resp.front();
		sHistoryData historyItem;
		convRequestResponseToHistoryData(requestResponse, &historyItem, true, relations, false);
		history.push_back(historyItem);
		queue_req_resp.pop_front();
		requestResponse->destroy(relations, this);
	}
	unlock();
}

void cSipMsgRelation::cleanup_history_by_limit_time(u_int64_t limit_time_us) {
	lock();
	while(history.size() &&
	      (!limit_time_us || history.front().request_time_us < limit_time_us)) {
		history.pop_front();
	}
	unlock();
}

void cSipMsgRelation::cleanup_history_by_max_items(unsigned max_items) {
	lock();
	while(history.size() > max_items) {
		history.pop_front();
	}
	unlock();
}

void cSipMsgRelation::close_pcaps_by_limit_time(u_int64_t limit_time_us, cSipMsgRelations *relations) {
	lock();
	deque<cSipMsgRequestResponse*>::iterator iter;
	for(iter = queue_req_resp.begin(); iter != queue_req_resp.end(); iter++) {
		if((*iter)->getLastTime() < limit_time_us && 
		   (!is_read_from_file_by_pb_acttime() || (*iter)->response)) {
			if((*iter)->needSaveToDb(relations, this)) {
				(*iter)->saveToDb(relations);
			}
			if((*iter)->isOpenPcap()) {
				(*iter)->closePcap(relations);
			}
		}
		if((*iter)->pcapIsSaved()) {
			(*iter)->destroyCdp();
		}
	}
	unlock();
}

volatile u_int64_t cSipMsgRelation::_id = 0;
volatile int cSipMsgRelation::_sync_id = 0;


cSipMsgRelations::cSipMsgRelations() {
	_sync_relations = 0;
	_sync_delete_relation = 0;
	_sync_params = 0;
	_sync_params_load = 0;
	_sync_cdp_queue = 0;
	_sync_close_pcap = 0;
	_sync_save_to_db = 0;
	lastCleanupRelations_ms = 
	lastClosePcaps_ms = getTimeMS_rdtsc();
	internalThread_id = 0;
	terminate = false;
}

cSipMsgRelations::~cSipMsgRelations() {
	clear();
	terminate = true;
	if(internalThread_id) {
		pthread_join(internalThread_id, NULL);
	}
}

void cSipMsgRelations::addSipMsg(cSipMsgItem *item, packet_s_process *packetS) {
 
	/*
	item->debug_out();
	cout << endl;
	*/
 
	cSipMsgRelation *relation = NULL;
	map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter;
	lock_relations();
	iter = relations.find(item);
	if(iter != relations.end()) {
		relation = iter->second;
	}
	if(!relation) {
		if(item->response) {
			delete item;
			unlock_relations();
			return;
		}
		relation = new FILE_LINE(0) cSipMsgRelation(item);
		relations[relation] = relation;

		unsigned long int flags = 0;
		set_global_flags(flags);
		if(sverb.dump_call_flags) {
			cout << "flags init cSipMsgRelation " 
			     << (item->type == smt_options ? "options" :
				 item->type == smt_subscribe ? "subscribe" :
				 item->type == smt_notify ? "notify" : "unknown type") 
			     << " : " << printCallFlags(flags) << endl;
		}
		relation->flags = setCallFlags(flags,
				item->ip_src, item->ip_dst,
				const_cast<char*>(item->number_src.c_str()), const_cast<char*>(item->number_dst.c_str()),
				const_cast<char*>(item->domain_src.c_str()), const_cast<char*>(item->domain_dst.c_str()),
				&packetS->parseContents);

	}
	relation->addSipMsg(item, packetS, this);
	unlock_relations();
	do_cleanup_relations(getTimeMS(&packetS->header_pt->ts));
	do_close_pcaps_by_limit_time(getTimeMS(&packetS->header_pt->ts));
}

void cSipMsgRelations::clear() {
 
	/*
	debug_out();
	cleanup_item_response_by_limit_time(0);
	cout << "-------------------------------" << endl;
	debug_out();
	*/
 
	lock_relations();
	map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		delete iter->second;
	}
	relations.clear();
	unlock_relations();
}

void cSipMsgRelations::loadParams() {
	sParams paramsNew;
	loadParams(&paramsNew);
	lock_params();
	params = paramsNew;
	unlock_params();
}

void cSipMsgRelations::loadParamsInBackground() {
	lock_params_load();
	pthread_t thread;
	vm_pthread_create_autodestroy("cSipMsgRelations::loadParams",
				      &thread, NULL, cSipMsgRelations::_loadParamsInBackground, this, __FILE__, __LINE__);
}

void cSipMsgRelations::closePcap(sCallDataPcap *cdp) {
	lock_close_pcap();
	if(cdp->isOpenPcap()) {
		cdp->_closePcap();
	}
	unlock_close_pcap();
}

void cSipMsgRelations::saveToDb(cSipMsgRequestResponse *requestResponse) {
	lock_save_to_db();
	if(!requestResponse->saved_to_db) {
		_saveToDb(requestResponse);
		requestResponse->saved_to_db = true;
	}
	unlock_save_to_db();
}

void cSipMsgRelations::_saveToDb(cSipMsgRequestResponse *requestResponse, bool enableBatchIfPossible) {
 
	/*
	cout << "save to db " 
	     << requestResponse->request->flags << ' '
	     << requestResponse->response->flags << ' '
	     << requestResponse->request->type << ' '
	     << requestResponse->request->callid << ' '
	     << requestResponse->time_us 
	     << endl;
	*/
	     
	if(opt_nocdr || sverb.disable_save_sip_msg) {
		return;
	}
	if(!sqlDbSaveSipMsg) {
		sqlDbSaveSipMsg = createSqlObject();
		sqlDbSaveSipMsg->setEnableSqlStringInContent(true);
	}
	unsigned flags = 0;
	string adj_ua_src, adj_ua_dst;
	adj_ua_src = requestResponse->request->ua;
	if(!adj_ua_src.empty()) {
		adjustUA(&adj_ua_src);
	}
	if(requestResponse->response) {
		adj_ua_dst = requestResponse->response->ua;
		if(!adj_ua_dst.empty()) {
			adjustUA(&adj_ua_dst);
		}
	}
	SqlDb_row rec,
		  next_ch[CDR_NEXT_MAX];
	char _next_ch_name[CDR_NEXT_MAX][100];
	char *next_ch_name[CDR_NEXT_MAX];
	for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
		_next_ch_name[i][0] = 0;
		next_ch_name[i] = _next_ch_name[i];
	}
	string table = "sip_msg";
	rec.add_calldate(requestResponse->time_us, "time", existsColumns.sip_msg_time_ms);
	rec.add(requestResponse->request->type, "type");
	rec.add(requestResponse->request->ip_src, "ip_src", false, sqlDbSaveSipMsg, table.c_str());
	rec.add(requestResponse->request->ip_dst, "ip_dst", false, sqlDbSaveSipMsg, table.c_str());
	rec.add(requestResponse->request->port_src.getPort(), "port_src");
	rec.add(requestResponse->request->port_dst.getPort(), "port_dst");
	if(existsColumns.sip_msg_vlan && VLAN_IS_SET(requestResponse->request->vlan)) {
		rec.add(requestResponse->request->vlan, "vlan");
	}
	rec.add(sqlEscapeString(requestResponse->request->number_src), "number_src");
	rec.add(sqlEscapeString(requestResponse->request->number_dst), "number_dst");
	rec.add(sqlEscapeString(requestResponse->request->domain_src), "domain_src");
	rec.add(sqlEscapeString(requestResponse->request->domain_dst), "domain_dst");
	rec.add(sqlEscapeString(requestResponse->request->callername), "callername");
	rec.add(sqlEscapeString(requestResponse->request->callid), "callid");
	rec.add(requestResponse->request->cseq_number, "cseq");
	for(int i = 0; i < 2; i++) {
		cSipMsgItem *item = i == 0 ? requestResponse->request : requestResponse->response;
		if(item) {
			if(item->content_length > 0) {
				string field_content_length = i == 0 ? "request_content_length" : "response_content_length";
				rec.add(item->content_length, field_content_length);
			}
			if(!item->content.empty()) {
				string field_content = i == 0 ? "request_content" : "response_content";
				rec.add(sqlEscapeString(item->content), field_content);
			}
		}
	}
	if(requestResponse->response) {
		rec.add(requestResponse->response->response_number, "response_number");
	}
	rec.add(requestResponse->time_us, "time_us");
	rec.add(requestResponse->next_requests_time_us.size(), "request_repetition");
	rec.add_calldate(requestResponse->request->time_us, "request_time", existsColumns.sip_msg_request_time_ms);
	rec.add(TIME_US_TO_DEC_US(requestResponse->request->time_us), "request_time_us");
	if(requestResponse->response) {
		rec.add_calldate(requestResponse->response->time_us, "response_time", existsColumns.sip_msg_response_time_ms);
		rec.add(TIME_US_TO_DEC_US(requestResponse->response->time_us), "response_time_us");
		int64_t response_duration = requestResponse->response->time_us - requestResponse->request->time_us;
		if(response_duration >= 0) {
			rec.add(round(response_duration / 1000.), "response_duration_ms");
		}
		rec.add(isQualifyOk(requestResponse->request, response_duration, requestResponse->response->response_number), "qualify_ok");
	}
	if(requestResponse->request->id_sensor > -1) {
		rec.add(requestResponse->request->id_sensor, "id_sensor");
	}
	if(requestResponse->cdp.pcap_save) {
		flags |= dbf_pcap_save;
	}
	if(flags) {
		rec.add(flags, "flags");
	}
	if(enableBatchIfPossible && isSqlDriver("mysql")) {
		string query_str;
		for(int i = 0; i < 2; i++) {
			string &adj_ua = i == 0 ? adj_ua_src : adj_ua_dst;
			if(!adj_ua.empty()) {
				string field = i == 0 ? "ua_src_id" : "ua_dst_id";
				if(useSetId()) {
					rec.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_ua, adj_ua), field);
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_ua, adj_ua.c_str(), false, true);
					if(_cb_id) {
						rec.add(_cb_id, field);
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @" + field + " = ") +  
							     "getIdOrInsertUA(" + sqlEscapeStringBorder(adj_ua) + ")");
						rec.add(MYSQL_VAR_PREFIX + "@" + field, field);
					}
				}
			}
		}
		if(requestResponse->response && !requestResponse->response->response_string.empty()) {
			if(useSetId()) {
				rec.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_sip_response, requestResponse->response->response_string), "response_id");
			} else {
				unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, requestResponse->response->response_string.c_str(), false, true);
				if(_cb_id) {
					rec.add(_cb_id, "response_id");
				} else {
					query_str += MYSQL_ADD_QUERY_END(string("set @response_id = ") + 
						     "getIdOrInsertSIPRES(" + sqlEscapeStringBorder(requestResponse->response->response_string) + ")");
					rec.add(MYSQL_VAR_PREFIX + "@response_id", "response_id");
				}
			}
		}
		for(int i = 0; i < 2; i++) {
			cSipMsgItem *item = i == 0 ? requestResponse->request : requestResponse->response;
			if(item && !item->content_type.empty()) {
				string field_content_type = i == 0 ? "request_id_content_type" : "response_id_content_type";
				if(useSetId()) {
					rec.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_contenttype, item->content_type), field_content_type);
				} else {
					unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_contenttype, item->content_type.c_str(), false, true);
					if(_cb_id) {
						rec.add(_cb_id, field_content_type);
					} else {
						query_str += MYSQL_ADD_QUERY_END(string("set @" + field_content_type + " = ") + 
							     "getIdOrInsertCONTENTTYPE(" + sqlEscapeStringBorder(item->content_type) + ")");
						rec.add(MYSQL_VAR_PREFIX + "@" + field_content_type, field_content_type);
					}
				}
			}
		}
		if(useNewStore()) {
			if(useSetId()) {
				rec.add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "ID");
			} else {
				query_str += MYSQL_GET_MAIN_INSERT_ID_OLD;
			}
		}
		query_str += MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT + 
			     sqlDbSaveSipMsg->insertQuery(table.c_str(), rec, false, false));
		if(useNewStore()) {
			if(!useSetId()) {
				query_str += MYSQL_GET_MAIN_INSERT_ID + 
					     MYSQL_IF_MAIN_INSERT_ID;
			}
		} else {
			query_str += "if row_count() > 0 then\n" +
				     MYSQL_GET_MAIN_INSERT_ID;
		}
		if(custom_headers_sip_msg) {
			custom_headers_sip_msg->prepareSaveRows(NULL, 0, &requestResponse->custom_headers_content, requestResponse->time_us, NULL, next_ch, next_ch_name);
			bool existsNextCh = false;
			for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
				if(next_ch_name[i][0]) {
					next_ch[i].add(MYSQL_VAR_PREFIX + MYSQL_MAIN_INSERT_ID, "sip_msg_ID");
					query_str += MYSQL_ADD_QUERY_END(MYSQL_NEXT_INSERT_GROUP + 
						     sqlDbSaveSipMsg->insertQuery(next_ch_name[i], next_ch[i]));
					existsNextCh = true;
				}
			}
			if(existsNextCh) {
				string queryForSaveUseInfo = custom_headers_sip_msg->getQueryForSaveUseInfo(requestResponse->time_us, &requestResponse->custom_headers_content);
				if(!queryForSaveUseInfo.empty()) {
					vector<string> queryForSaveUseInfo_vect = split(queryForSaveUseInfo.c_str(), ";");
					for(unsigned i = 0; i < queryForSaveUseInfo_vect.size(); i++) {
						query_str += MYSQL_ADD_QUERY_END(queryForSaveUseInfo_vect[i]);
					}
				}
			}
		}
		if(useNewStore()) {
			if(!useSetId()) {
				query_str += MYSQL_ENDIF_QE;
			}
		} else {
			query_str += "end if";
		}
		static unsigned int counterSqlStore = 0;
		sqlStore->query_lock(query_str.c_str(),
				     STORE_PROC_ID_MESSAGE, 
				     opt_mysqlstore_max_threads_message > 1 &&
				     sqlStore->getSize(STORE_PROC_ID_MESSAGE, 0) > 1000 ? 
				      counterSqlStore % opt_mysqlstore_max_threads_message : 
				      0);
		++counterSqlStore;
	} else {
		for(int i = 0; i < 2; i++) {
			string &adj_ua = i == 0 ? adj_ua_src : adj_ua_dst;
			if(!adj_ua.empty()) {
				string field = i == 0 ? "ua_src_id" : "ua_dst_id";
				rec.add(dbData->getCbId(cSqlDbCodebook::_cb_ua, adj_ua.c_str(), true), field);
			}
		}
		if(requestResponse->response && !requestResponse->response->response_string.empty()) {
			rec.add(dbData->getCbId(cSqlDbCodebook::_cb_sip_response, requestResponse->response->response_string.c_str(), true), "response_id");
		}
		for(int i = 0; i < 2; i++) {
			cSipMsgItem *item = i == 0 ? requestResponse->request : requestResponse->response;
			if(item && !item->content_type.empty()) {
				string field_content_type = i == 0 ? "request_id_content_type" : "response_id_content_type";
				rec.add(dbData->getCbId(cSqlDbCodebook::_cb_contenttype, item->content_type.c_str(), true), field_content_type);
			}
		}
		int64_t sipMsgID = sqlDbSaveSipMsg->insert(table, rec);
		if(sipMsgID > 0)
		for(unsigned i = 0; i < CDR_NEXT_MAX; i++) {
			if(next_ch_name[i][0]) {
				next_ch[i].add(sipMsgID, "sip_msg_ID");
				sqlDbSaveSipMsg->insert(next_ch_name[i], next_ch[i]);
			}
		}
	}
}

bool cSipMsgRelations::needSavePcap(cSipMsgRequestResponse *requestResponse, cSipMsgRelation *relation) {
	if(requestResponse->request) {
		return((requestResponse->request->type == smt_options && (relation->flags & FLAG_SAVEOPTIONSPCAP)) ||
		       (requestResponse->request->type == smt_subscribe && (relation->flags & FLAG_SAVESUBSCRIBEPCAP)) ||
		       (requestResponse->request->type == smt_notify && (relation->flags & FLAG_SAVENOTIFYPCAP)));
	}
	return(false);
}

bool cSipMsgRelations::needSaveToDb(cSipMsgRequestResponse *requestResponse, cSipMsgRelation *relation) {
	if(!requestResponse->saved_to_db && requestResponse->request) {
		return((requestResponse->request->type == smt_options && (relation->flags & FLAG_SAVEOPTIONSDB)) ||
		       (requestResponse->request->type == smt_subscribe && (relation->flags & FLAG_SAVESUBSCRIBEDB)) ||
		       (requestResponse->request->type == smt_notify && (relation->flags & FLAG_SAVENOTIFYDB)));
	}
	return(false);
}

void cSipMsgRelations::pushToCdpQueue(sCallDataPcap *cdp) {
	lock_cdp_queue();
	cdpQueue.push_back(*cdp);
	unlock_cdp_queue();
}

void cSipMsgRelations::runInternalThread() {
	vm_pthread_create("cSipMsgRelations::internalThread",
			  &internalThread_id, NULL, cSipMsgRelations::internalThread, this, __FILE__, __LINE__);
}

void cSipMsgRelations::cleanup_item_response_by_limit_time(u_int64_t limit_time_us) {
	lock_relations();
	map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		iter->second->cleanup_item_response_by_limit_time(limit_time_us, this);
	}
	unlock_relations();
}

void cSipMsgRelations::cleanup_history_by_limit_time(u_int64_t limit_time_us) {
	lock_relations();
	map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		iter->second->cleanup_history_by_limit_time(limit_time_us);
	}
	unlock_relations();
}

void cSipMsgRelations::cleanup_relations(u_int64_t limit_time_us) {
	lock_relations();
	map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); ) {
		if(iter->second->getLastTime() < limit_time_us) {
			delete iter->second;
			relations.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock_relations();
}

void cSipMsgRelations::close_pcaps_by_limit_time(u_int64_t limit_time_us) {
	lock_relations();
	map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		iter->second->close_pcaps_by_limit_time(limit_time_us, this);
	}
	unlock_relations();
}

void cSipMsgRelations::do_cleanup_relations(u_int64_t act_time_ms, bool force) {
	if(!act_time_ms) {
		act_time_ms = getTimeMS_rdtsc();
	}
	if(force ||
	   lastCleanupRelations_ms < act_time_ms - opt_cleanup_relations_period * 1000) {
		cleanup_relations(((u_int64_t)act_time_ms - opt_cleanup_relations_limit_time * 1000) * 1000);
		lastCleanupRelations_ms = act_time_ms;
	}
}

void cSipMsgRelations::do_close_pcaps_by_limit_time(u_int64_t act_time_ms, bool force, bool all) {
	if(!act_time_ms) {
		act_time_ms = getTimeMS_rdtsc();
	}
	if(force ||
	   lastClosePcaps_ms < act_time_ms - opt_close_pcaps_period * 1000) {
		close_pcaps_by_limit_time(((u_int64_t)act_time_ms - opt_close_pcap_limit_time * 1000) * 1000);
		lastClosePcaps_ms = act_time_ms;
	}
}

void cSipMsgRelations::do_cleanup_cdq() {
	while(!terminate) {
		sCallDataPcap cdp;
		lock_cdp_queue();
		if(cdpQueue.size()) {
			sCallDataPcap &_cdp = cdpQueue.front();
			if(_cdp.isOpenPcap()) {
				closePcap(&_cdp);
			} else if(_cdp.pcapIsSaved()) {
				cdp = _cdp;
				cdpQueue.pop_front();
			}
		}
		unlock_cdp_queue();
		if(cdp.isSet()) {
			cdp.destroy();
		} else {
			break;
		}
	}
}

bool cSipMsgRelations::existsParamsTables() {
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

void cSipMsgRelations::loadParams(sParams *params) {
	params->clear();
	if(!existsParamsTables()) {
		params->defaultParams.qualifyLimit = opt_default_qualify_limit;
		return;
	}
	SqlDb *sqlDb = createSqlObject();
	bool existsColumnType = sqlDb->existsColumn("options_qualify", "type");
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
	} else {
		params->defaultParams.qualifyLimit = opt_default_qualify_limit;
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
	SqlDb_rows dbRows;
	sqlDb->fetchRows(&dbRows);
	while((dbRow = dbRows.fetchRow())) {
		int qualifyLimit = atoi(dbRow["ok_qualify_limit"].c_str());
		if(qualifyLimit > 0) {
			sParamsRecord recordParams;
			recordParams.name = dbRow["name"];
			if(existsColumnType) {
				recordParams.options = dbRow["type"].find("options") != string::npos;
				recordParams.subscribe = dbRow["type"].find("subscribe") != string::npos;
				recordParams.notify = dbRow["type"].find("notify") != string::npos;
			} else {
				recordParams.options = true;
			}
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
}

void *cSipMsgRelations::_loadParamsInBackground(void *arg) {
	cSipMsgRelations *me = (cSipMsgRelations*)arg;
	me->loadParams();
	me->unlock_params_load();
	return(NULL);
}

void cSipMsgRelations::internalThread() {
	while(!terminate) {
		do_close_pcaps_by_limit_time(getTimeMS_rdtsc());
		if(!is_read_from_file()) {
			do_cleanup_relations(getTimeMS_rdtsc());
		}
		do_cleanup_cdq();
		for(int i = 0; i < 5 * 100 && !terminate; i++) {
			USLEEP(10000);
		}
	}
}

void *cSipMsgRelations::internalThread(void *arg) {
	cSipMsgRelations *me = (cSipMsgRelations*)arg;
	me->internalThread();
	return(NULL);
}

string cSipMsgRelations::getDataTableJson(char *params, bool *zip) {
 
	JsonItem jsonParams;
	jsonParams.parse(params);

	u_int32_t limit = atol(jsonParams.getValue("limit").c_str());
	string sortBy = jsonParams.getValue("sort_field");
	eSipMsgField sortById = convSipMsgFieldToFieldId(sortBy.c_str());
	string sortDir = jsonParams.getValue("sort_dir");
	std::transform(sortDir.begin(), sortDir.end(), sortDir.begin(), ::tolower);
	bool sortDesc = sortDir.substr(0, 4) == "desc";
	
	if(zip) {
		string zipParam = jsonParams.getValue("zip");
		std::transform(zipParam.begin(), zipParam.end(), zipParam.begin(), ::tolower);
		*zip = zipParam == "yes";
	}
	
	lock_relations();
	
	u_int32_t list_sip_msg_size = relations.size();
	u_int32_t list_sip_msg_count = 0;
	cSipMsgRelation **list_sip_msg = new FILE_LINE(0) cSipMsgRelation*[list_sip_msg_size];
	
	for(map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter_opt = relations.begin(); iter_opt != relations.end(); iter_opt++) {
		list_sip_msg[list_sip_msg_count++] = iter_opt->second;
	}
	
	list<RecordArray> records;
	for(unsigned i = 0; i < list_sip_msg_count; i++) {
		RecordArray rec(smf__max);
		if(list_sip_msg[i]->getDataRow(&rec, ((u_int64_t)getTimeMS_rdtsc() - opt_datarow_limit_time * 1000) * 1000, this)) {
			rec.sortBy = sortById;
			rec.sortBy2 = smf_id;
			records.push_back(rec);
		} else {
			rec.free();
		}
	}
	delete [] list_sip_msg;
	
	unlock_relations();

	string table;
	string header = "[";
	for(unsigned i = 0; i < sizeof(sipMsgFields) / sizeof(sipMsgFields[0]); i++) {
		if(i) {
			header += ",";
		}
		header += '"' + string(sipMsgFields[i].fieldName) + '"';
	}
	header += "]";
	table = "[" + header;
	if(records.size()) {
		string filter = jsonParams.getValue("filter");
		if(!filter.empty()) {
			//cout << "FILTER: " << filter << endl;
			cSipMsgFilter *optFilter = new FILE_LINE(0) cSipMsgFilter(filter.c_str());
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

string cSipMsgRelations::getHistoryDataJson(char *params, bool *zip) {
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

string cSipMsgRelations::getHistoryDataJson(u_int64_t id) {
	cSipMsgRelation *relation = NULL;
	lock_relations();
	for(map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter = relations.begin(); iter != relations.end(); iter++) {
		if(iter->second->id == id) {
			relation = iter->second;
			break;
		}
	}
	if(!relation) {
		unlock_relations();
		return("");
	}
	list<cSipMsgRelation::sHistoryData> historyData;
	relation->getHistoryData(&historyData, ((u_int64_t)getTimeMS_rdtsc() - opt_datarow_limit_time * 1000) * 1000, 0, this);
	unlock_relations();
	string historyDataJson;
	if(historyData.size()) {
		historyDataJson += '[';
		JsonExport json;
		json.setTypeItem(JsonExport::_array);
		const char *headers[] = {
			"time",
			"time_us_compl",
			"response_duration_ms",
			"response_number",
			"response_string",
			"qualify_ok",
			"callid",
			"cseq",
			"exists_pcap"
		};
		for(unsigned i = 0; i < sizeof(headers) / sizeof(headers[i]); i++) {
			json.add(NULL, headers[i]);
		}
		historyDataJson += json.getJson();
		for(list<cSipMsgRelation::sHistoryData>::iterator iter = historyData.begin(); iter != historyData.end(); iter++) {
			historyDataJson += ',';
			historyDataJson += iter->getJson(&responseStringCache,
							 this->isQualifyOk(relation, iter->getResponseDuration(), iter->response_number));
		}
		historyDataJson += ']';
	}
	return(historyDataJson);
}

void cSipMsgRelations::debug_out() {
	lock_relations();
	map<cSipMsgRelationId, cSipMsgRelation*>::iterator iter;
	for(iter = relations.begin(); iter != relations.end(); iter++) {
		iter->second->debug_out(this);
	}
	unlock_relations();
}


eSipMsgField convSipMsgFieldToFieldId(const char *field) {
	for(unsigned i = 0; i < sizeof(sipMsgFields) / sizeof(sipMsgFields[0]); i++) {
		if(!strcmp(field, sipMsgFields[i].fieldName)) {
			return(sipMsgFields[i].filedType);
		}
	}
	return((eSipMsgField)0);
}


void initSipMsg() {
	sipMsgRelations = new FILE_LINE(0) cSipMsgRelations;
	sipMsgRelations->loadParams();
	sipMsgRelations->runInternalThread();
}

void termSipMsg() {
	if(sipMsgRelations) {
		delete sipMsgRelations;
		sipMsgRelations = NULL;
	}
}
