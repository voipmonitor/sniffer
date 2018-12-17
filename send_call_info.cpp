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
	infoOn = infoOn_183_180_200;
	requestType = rt_get;
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
		 from send_call_info\
		 where id = ") + dbIdStr);
	dbRow = sqlDb->fetchRow();
	if(!dbRow) {
		if(_createSqlObject) {
			delete sqlDb;
		}
		return(false);
	}
	dbRow.clearSqlDb();
	name = dbRow["descr"].empty() ? dbRow["name"] : dbRow["descr"];
	infoOn = dbRow["info_on"] == "183/180" ? infoOn_183_180 :
		 dbRow["info_on"] == "200" ? infoOn_200 : 
		 dbRow["info_on"] == "183/180_200" ? infoOn_183_180_200 :
		 dbRow["info_on"] == "INVITE" ? infoOn_invite : 
		 (eInfoOn)-1;
	requestUrl = dbRow["request_url"];
	requestType = dbRow["request_type"] == "get" ? rt_get : rt_post;
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
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(true);
}

void SendCallInfoItem::evSci(sSciInfo *sci) {
	if(((infoOn == infoOn_183_180_200 && (sci->typeSci == sSciInfo::sci_18X || sci->typeSci == sSciInfo::sci_200)) ||
	    (infoOn == infoOn_183_180 && sci->typeSci == sSciInfo::sci_18X) ||
	    (infoOn == infoOn_200 && sci->typeSci == sSciInfo::sci_200) ||
	    (infoOn == infoOn_invite && sci->typeSci == sSciInfo::sci_invite)) &&
	   phoneNumberCallerFilter.checkNumber(sci->caller_number.c_str()) &&
	   phoneNumberCalledFilter.checkNumber(sci->called_number.c_str()) &&
	   ipCallerFilter.checkIP(sci->caller_ip) &&
	   ipCalledFilter.checkIP(sci->called_ip)) {
		vector<dstring> postData;
		postData.push_back(dstring("rule", name));
		postData.push_back(dstring("type", sci->typeSci == sSciInfo::sci_18X ? "18X" : 
						   sci->typeSci == sSciInfo::sci_200 ? "200" :
						   sci->typeSci == sSciInfo::sci_invite ? "INVITE" : 
						   ""));
		postData.push_back(dstring("caller", sci->caller_number));
		postData.push_back(dstring("called", sci->called_number));
		postData.push_back(dstring("ip_src", inet_ntostring(sci->caller_ip)));
		postData.push_back(dstring("ip_dst", inet_ntostring(sci->called_ip)));
		postData.push_back(dstring("callid", sci->callid));
		string getParams;
		if(requestType == rt_get && postData.size()) {
			for(vector<dstring>::iterator it = postData.begin(); it != postData.end(); it++) {
				getParams.append(getParams.empty() ? "?" : "&");
				getParams.append((*it)[0]);
				getParams.append("=");
				getParams.append(url_encode((*it)[1]));
			}
		}
		SimpleBuffer responseBuffer;
		string error;
		get_url_response((requestUrl + getParams).c_str(), &responseBuffer, requestType == rt_get ? NULL : &postData, &error);
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
		usleep(1000);
	}
}

void SendCallInfo::evCall(Call *call, sSciInfo::eTypeSci typeSci, u_int64_t at) {
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
			usleep(1000);
		}
	}
	runPopCallInfoThread = false;
}

void SendCallInfo::getSciFromCall(sSciInfo *sci, Call *call, 
				  sSciInfo::eTypeSci typeSci, u_int64_t at) {
	sci->callid = call->call_id;
	sci->caller_number = call->caller;
	sci->called_number = call->called;
	sci->caller_ip = htonl(call->getSipcallerip());
	sci->called_ip = htonl(call->getSipcalledip());
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

void sendCallInfoEvCall(Call *call, sSciInfo::eTypeSci typeSci, struct timeval tv) {
	if(sendCallInfo && _sendCallInfo_ready) {
		sendCallInfo_lock();
		sendCallInfo->evCall(call, typeSci, tv.tv_sec * 1000000ull + tv.tv_usec);
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
