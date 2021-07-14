#include "send_call_info.h"
#include "calltable.h"


extern int opt_nocdr;

SendCallInfo *sendCallInfo = NULL;
volatile int _sendCallInfo_ready = 0;
volatile int _sendCallInfo_lock = 0;


static void sendCallInfo_lock() {
	while(__sync_lock_test_and_set(&_sendCallInfo_lock, 1));
}
static void sendCallInfo_unlock() {
	__sync_lock_release(&_sendCallInfo_lock);
}


SendCallInfoItem::SendCallInfoItem(unsigned int dbId) {
	this->dbId = dbId;
	infoOn = sci_18X | sci_200;
	requestType = rt_get;
	suppressParametersEncoding = false;
	calledNumberSrc = cs_default;
	calledDomainSrc = cs_default;
}

bool SendCallInfoItem::load(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	char dbIdStr[10];
	snprintf(dbIdStr, sizeof(dbIdStr), "%u", dbId);
	sqlDb->query(string(
		"select send_call_info.*,\
		 (select group_concat(number) \
		  from send_call_info_groups scig\
		  join cb_number_groups g on (g.id=scig.number_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'number_caller_whitelist') as whitelist_number_caller_group,\
		 (select group_concat(number) \
		  from send_call_info_groups scig\
		  join cb_number_groups g on (g.id=scig.number_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'number_caller_blacklist') as blacklist_number_caller_group,\
		 (select group_concat(number) \
		  from send_call_info_groups scig\
		  join cb_number_groups g on (g.id=scig.number_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'number_called_whitelist') as whitelist_number_called_group,\
		 (select group_concat(number) \
		  from send_call_info_groups scig\
		  join cb_number_groups g on (g.id=scig.number_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'number_called_blacklist') as blacklist_number_called_group,\
		 (select group_concat(ip)\
		  from send_call_info_groups scig\
		  join cb_ip_groups g on (g.id=scig.ip_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'ip_caller_whitelist') as whitelist_ip_caller_group,\
		 (select group_concat(ip)\
		  from send_call_info_groups scig\
		  join cb_ip_groups g on (g.id=scig.ip_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'ip_caller_blacklist') as blacklist_ip_caller_group,\
		 (select group_concat(ip)\
		  from send_call_info_groups scig\
		  join cb_ip_groups g on (g.id=scig.ip_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'ip_called_whitelist') as whitelist_ip_called_group,\
		 (select group_concat(ip)\
		  from send_call_info_groups scig\
		  join cb_ip_groups g on (g.id=scig.ip_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'ip_called_blacklist') as blacklist_ip_called_group\
		 ") + (sqlDb->existsColumn("send_call_info_groups", "domain_group_id") ? ",\
		 (select group_concat(domain)\
		  from send_call_info_groups scig\
		  join cb_domain_groups g on (g.id=scig.domain_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'domain_caller_whitelist') as whitelist_domain_caller_group,\
		 (select group_concat(domain)\
		  from send_call_info_groups scig\
		  join cb_domain_groups g on (g.id=scig.domain_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'domain_caller_blacklist') as blacklist_domain_caller_group,\
		 (select group_concat(domain)\
		  from send_call_info_groups scig\
		  join cb_domain_groups g on (g.id=scig.domain_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'domain_called_whitelist') as whitelist_domain_called_group,\
		 (select group_concat(domain)\
		  from send_call_info_groups scig\
		  join cb_domain_groups g on (g.id=scig.domain_group_id)\
		  where send_call_info_id = send_call_info.id and type = 'domain_called_blacklist') as blacklist_domain_called_group" : "") + 
		"\
		 from send_call_info\
		 where id = " + dbIdStr);
	dbRow = sqlDb->fetchRow();
	if(!dbRow) {
		if(_createSqlObject) {
			delete sqlDb;
		}
		return(false);
	}
	dbRow.clearSqlDb();
	name = dbRow["descr"].empty() ? dbRow["name"] : dbRow["descr"];
	infoOn = 0;
	if(!dbRow["info_on_set"].empty()) {
		vector<string> info_on_set = explode(dbRow["info_on_set"].c_str(), ',');
		for(unsigned i = 0; i < info_on_set.size(); i++) {
			infoOn |= info_on_set[i] == "183/180" ? sci_18X :
				  info_on_set[i] == "200" ? sci_200 :
				  info_on_set[i] == "INVITE" ? sci_invite :
				  info_on_set[i] == "HANGUP" ? sci_hangup : 0;
		}
	} else if(!dbRow["info_on"].empty()) {
		infoOn = dbRow["info_on"] == "183/180" ? sci_18X :
			 dbRow["info_on"] == "200" ? sci_200 : 
			 dbRow["info_on"] == "183/180_200" ? sci_18X | sci_200 :
			 dbRow["info_on"] == "INVITE" ? sci_invite : 
			 0;
	}
	requestUrl = dbRow["request_url"];
	requestType = dbRow["request_type"] == "get" ? rt_get : rt_post;
	suppressParametersEncoding = atoi(dbRow["suppress_parameters_encoding"].c_str());
	calledNumberSrc = dbRow["called_number_src"] == "to" ? cs_to :
			  dbRow["called_number_src"] == "uri" ? cs_uri : cs_default;
	calledDomainSrc = dbRow["called_domain_src"] == "to" ? cs_to :
			  dbRow["called_domain_src"] == "uri" ? cs_uri : cs_default;
	jsonOutput = atoi(dbRow["json_output"].c_str());
	authUser = dbRow["auth_user"];
	authPassword = dbRow["auth_password"];
	for(unsigned i = 0; i < 2; i++) {
		vector<dstring> *dst = i == 0 ? &headers : &fields;
		vector<string> src = explode(dbRow[i == 0 ? "headers" : "fields"], '\n');
		if(src.size()) {
			for(unsigned j = 0; j < src.size(); j++) {
				string src_i = src[j];
				while(src_i.length() && (src_i[0] == ' ' || src_i[0] == '\r')) {
					src_i = src_i.substr(1);
				}
				while(src_i.length() && (src_i[src_i.length() - 1] == ' ' || src_i[src_i.length() - 1 ] == '\r')) {
					src_i = src_i.substr(0, src_i.length() - 1);
				}
				if(src_i.length()) {
					vector<string> src_ie = explode(src_i.c_str(), ':');
					if(src_ie.size()) {
						dstring dst_i;
						dst_i.str[0] = src_ie[0];
						dst_i.str[1] = src_ie.size() > 1 ? src_ie[1] : "";
						dst->push_back(dst_i);
					}
				}
			}
		}
	}
	phoneNumberCallerFilter.addWhite(dbRow["whitelist_number_caller"].c_str());
	phoneNumberCallerFilter.addWhite(dbRow["whitelist_number_caller_group"].c_str());
	phoneNumberCallerFilter.addBlack(dbRow["blacklist_number_caller"].c_str());
	phoneNumberCallerFilter.addBlack(dbRow["blacklist_number_caller_group"].c_str());
	phoneNumberCalledFilter.addWhite(dbRow["whitelist_number_called"].c_str());
	phoneNumberCalledFilter.addWhite(dbRow["whitelist_number_called_group"].c_str());
	phoneNumberCalledFilter.addBlack(dbRow["blacklist_number_called"].c_str());
	phoneNumberCalledFilter.addBlack(dbRow["blacklist_number_called_group"].c_str());
	ipCallerFilter.addWhite(dbRow["whitelist_ip_caller"].c_str());
	ipCallerFilter.addWhite(dbRow["whitelist_ip_caller_group"].c_str());
	ipCallerFilter.addBlack(dbRow["blacklist_ip_caller"].c_str());
	ipCallerFilter.addBlack(dbRow["blacklist_ip_caller_group"].c_str());
	ipCalledFilter.addWhite(dbRow["whitelist_ip_called"].c_str());
	ipCalledFilter.addWhite(dbRow["whitelist_ip_called_group"].c_str());
	ipCalledFilter.addBlack(dbRow["blacklist_ip_called"].c_str());
	ipCalledFilter.addBlack(dbRow["blacklist_ip_called_group"].c_str());
	domainCallerFilter.addWhite(dbRow["whitelist_domain_caller"].c_str());
	domainCallerFilter.addWhite(dbRow["whitelist_domain_caller_group"].c_str());
	domainCallerFilter.addBlack(dbRow["blacklist_domain_caller"].c_str());
	domainCallerFilter.addBlack(dbRow["blacklist_domain_caller_group"].c_str());
	domainCalledFilter.addWhite(dbRow["whitelist_domain_called"].c_str());
	domainCalledFilter.addWhite(dbRow["whitelist_domain_called_group"].c_str());
	domainCalledFilter.addBlack(dbRow["blacklist_domain_called"].c_str());
	domainCalledFilter.addBlack(dbRow["blacklist_domain_called_group"].c_str());
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
}

void SendCallInfoItem::evSci(sSciInfo *sci) {
	if((sci->typeSci & infoOn) &&
	   phoneNumberCallerFilter.checkNumber(sci->caller_number.c_str()) &&
	   phoneNumberCalledFilter.checkNumber(called_number(sci).c_str()) &&
	   ipCallerFilter.checkIP(sci->caller_ip) &&
	   ipCalledFilter.checkIP(sci->called_ip) &&
	   domainCallerFilter.check(sci->caller_domain.c_str()) &&
	   domainCalledFilter.check(called_domain(sci).c_str())) {
		vector<dstring> postData;
		postData.push_back(dstring("rule", name));
		postData.push_back(dstring("type", sci->typeSci == sci_18X ? "18X" : 
						   sci->typeSci == sci_200 ? "200" :
						   sci->typeSci == sci_invite ? "INVITE" : 
						   sci->typeSci == sci_hangup ? "HANGUP" : 
						   ""));
		postData.push_back(dstring("caller", sci->caller_number));
		postData.push_back(dstring("called", called_number(sci)));
		postData.push_back(dstring("callername", sci->callername));
		postData.push_back(dstring("caller_domain", sci->caller_domain));
		postData.push_back(dstring("called_domain", called_domain(sci)));
		postData.push_back(dstring("ip_src", sci->caller_ip.getString()));
		postData.push_back(dstring("ip_dst", sci->called_ip.getString()));
		postData.push_back(dstring("callid", sci->callid));
		if(fields.size()) {
			for(unsigned i = 0; i < fields.size(); i++) {
				postData.push_back(fields[i]);
			}
		}
		if(jsonOutput) {
			JsonExport jsonExport;
			for(vector<dstring>::iterator it = postData.begin(); it != postData.end(); it++) {
				jsonExport.add((*it)[0].c_str(), (*it)[1]);
			}
			postData.clear();
			postData.push_back(dstring("json", jsonExport.getJson()));
		}
		string getParams;
		if(requestType == rt_get && postData.size()) {
			for(vector<dstring>::iterator it = postData.begin(); it != postData.end(); it++) {
				getParams.append(getParams.empty() ? "?" : "&");
				getParams.append((*it)[0]);
				getParams.append("=");
				getParams.append(suppressParametersEncoding ? (*it)[1] : url_encode((*it)[1]));
			}
		}
		SimpleBuffer responseBuffer;
		string error;
		s_get_url_response_params curl_params;
		if(!authUser.empty() || !authPassword.empty()) {
			curl_params.auth_user = &authUser;
			curl_params.auth_password = &authPassword;
		}
		if(headers.size()) {
			curl_params.headers = &headers;
		}
		if(suppressParametersEncoding) {
			curl_params.suppress_parameters_encoding = true;
		}
		get_url_response((requestUrl + getParams).c_str(), &responseBuffer, requestType == rt_get ? NULL : &postData, &error, &curl_params);
		if(error.empty()) {
			if(sverb.send_call_info) {
				cout << "send call info response: " << (char*)responseBuffer << endl;
			}
		}
	}
}


SendCallInfo::SendCallInfo() {
	threadPopCallInfo = 0;
	runPopCallInfoThread = false;
	termPopCallInfoThread = false;
	_sync = 0;
	initPopCallInfoThread();
}

SendCallInfo::~SendCallInfo() {
	clear();
}

void SendCallInfo::load(bool lock) {
	if(lock) this->lock();
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select id, name from send_call_info");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		if(sverb.send_call_info) {
			syslog(LOG_NOTICE, "load send_call_info %s", row["name"].c_str());
		}
		SendCallInfoItem *sci = new FILE_LINE(25001) SendCallInfoItem(atol(row["id"].c_str()));
		if(sci->load()) {
			listSci.push_back(sci);
		}
	}
	delete sqlDb;
	if(lock) this->unlock();
}

void SendCallInfo::clear(bool lock) {
	if(lock) this->lock();
	for(list<SendCallInfoItem*>::iterator it = listSci.begin(); it != listSci.end(); it++) {
		delete *it;
	}
	listSci.clear();
	if(lock) this->unlock();
}

void SendCallInfo::refresh() {
	lock();
	clear(false);
	load(false);
	unlock();
}

void SendCallInfo::stopPopCallInfoThread(bool wait) {
	termPopCallInfoThread = true;
	while(wait && runPopCallInfoThread) {
		USLEEP(1000);
	}
}

void SendCallInfo::evCall(Call *call, eTypeSci typeSci, u_int64_t at) {
	sSciInfo sci;
	this->getSciFromCall(&sci, call, typeSci, at);
	sciQueue.push(sci);
}

void *_SendCallInfo_popCallInfoThread(void *arg) {
	((SendCallInfo*)arg)->popCallInfoThread();
	return(NULL);
}
void SendCallInfo::initPopCallInfoThread() {
	vm_pthread_create("send call info",
			  &this->threadPopCallInfo, NULL, _SendCallInfo_popCallInfoThread, this, __FILE__, __LINE__);
}

void SendCallInfo::popCallInfoThread() {
	runPopCallInfoThread = true;
	sSciInfo sci;
	while(!is_terminating() && !termPopCallInfoThread) {
		bool okPop = false;
		if(sciQueue.pop(&sci)) {
			lock();
			for(list<SendCallInfoItem*>::iterator it = listSci.begin(); it != listSci.end(); it++) {
				(*it)->evSci(&sci);
			}
			unlock();
			okPop = true;
		}
		if(!okPop) {
			USLEEP(1000);
		}
	}
	runPopCallInfoThread = false;
}

void SendCallInfo::getSciFromCall(sSciInfo *sci, Call *call, 
				  eTypeSci typeSci, u_int64_t at) {
	sci->callid = call->call_id;
	sci->caller_number = call->caller;
	sci->called_number_to = call->called_to;
	sci->called_number_uri = call->called_uri;
	sci->called_number_final = call->called();
	sci->callername = call->callername;
	sci->caller_domain = call->caller_domain;
	sci->called_domain_to = call->called_domain_to;
	sci->called_domain_uri = call->called_domain_uri;
	sci->called_domain_final = call->called_domain();
	sci->caller_ip = call->getSipcallerip();
	sci->called_ip = call->getSipcalledip();
	sci->typeSci = typeSci;
	sci->at = at;
}


void initSendCallInfo(SqlDb *sqlDb) {
	if(!isExistsSendCallInfo(sqlDb)) {
		return;
	}
	if(sendCallInfo) {
		return;
	}
	sendCallInfo_lock();
	sendCallInfo = new FILE_LINE(25002) SendCallInfo();
	sendCallInfo->load(sqlDb);
	sendCallInfo_unlock();
	_sendCallInfo_ready = 1;
}

void termSendCallInfo() {
	if(sendCallInfo) {
		_sendCallInfo_ready = 0;
		sendCallInfo_lock();
		sendCallInfo->stopPopCallInfoThread(true);
		delete sendCallInfo;
		sendCallInfo = NULL;
		sendCallInfo_unlock();
	}
}

void refreshSendCallInfo() {
	if(isExistsSendCallInfo()) {
		if(!sendCallInfo) {
			initSendCallInfo();
		} else {
			sendCallInfo->refresh();
		}
	} else {
		if(sendCallInfo) {
			termSendCallInfo();
		}
	}
}

void sendCallInfoEvCall(Call *call, eTypeSci typeSci, struct timeval tv) {
	if(sendCallInfo && _sendCallInfo_ready) {
		sendCallInfo_lock();
		sendCallInfo->evCall(call, typeSci, getTimeUS(tv));
		sendCallInfo_unlock();
	}
}

bool isExistsSendCallInfo(SqlDb *sqlDb) {
	if(opt_nocdr) {
		return(false);
	}
	bool rslt = false;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("send_call_info")) {
		sqlDb->query("select * from send_call_info limit 1");
		rslt = sqlDb->fetchRow();
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(rslt);
}
