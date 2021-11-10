#include <iostream>
#include <sstream>
#include <net/ethernet.h>

#include "http.h"
#include "sql_db.h"
#include "voipmonitor.h"


using namespace std;

extern int opt_id_sensor;
extern MySqlStore *sqlStore;
extern MySqlStore *sqlStore_2;
extern int opt_mysqlstore_max_threads_http;

SqlDb *sqlDbSaveHttp = NULL;


HttpData::HttpData() {
	this->counterProcessData = 0;
	this->counterSaveData = 0;
}

HttpData::~HttpData() {
	cout << "save HttpData: " << this->counterSaveData << endl;
}

void HttpData::processData(vmIP ip_src, vmIP ip_dst,
			   vmPort port_src, vmPort port_dst,
			   TcpReassemblyData *data,
			   u_char */*ethHeader*/, u_int32_t /*ethHeaderLength*/,
			   u_int16_t /*handle_index*/, int /*dlt*/, int /*sensor_id*/, vmIP /*sensor_ip*/, sPacketInfoData /*pid*/,
			   void */*uData*/, void */*uData2*/, void */*uData2_last*/, TcpReassemblyLink */*reassemblyLink*/,
			   std::ostream *debugStream) {
 
	++this->counterProcessData;

	if(!sqlDbSaveHttp) {
		sqlDbSaveHttp = createSqlObject();
	}

	string request;
	string response;
	string expectContinue;
	/*
	for(size_t i = 0; i < data->request.size(); i++) {
		if(i) {
			request += "\r\n\r\n---\r\n\r\n";
		}
		request += (char*)data->request[i].data;
	}
	for(size_t i = 0; i < data->response.size(); i++) {
		if(i) {
			response += "\r\n\r\n---\r\n\r\n";
		}
		response += (char*)data->response[i].data;
	}
	for(size_t i = 0; i < data->expectContinue.size(); i++) {
		if(i) {
			expectContinue += "\r\n\r\n---\r\n\r\n";
		}
		expectContinue += (char*)data->expectContinue[i].data;
	}
	*/
	TcpReassemblyDataItem *request_data = NULL;
	TcpReassemblyDataItem *response_data = NULL;
	
	string uri;
	string http;
	string body;
	size_t contentLength;
	
	bool ok = false;
	for(size_t i_request = 0; 
	    i_request < /*(data->expectContinue.size() ? */data->request.size() /*: 1)*/; 
	    i_request++) {
	
	/*
	if(strstr(request.c_str(), "POST /jj-api/public/v1/sessions/0-2BLJ4pLJ0KKW18bglZ4-3D_503a622c-a3bb-4222-8424-b45431d8284e/dispatchAction/?ccid=0-2BLJ4pLJ0KKW18bglZ4-3D HTTP/1.1")) {
		cout << " -- ***** -- ";
	}
	*/
	if(!data->expectContinue.size() &&
	   strcasestr(request.c_str(), "Expect: 100-continue") &&
	   data->request.size() > i_request) {
		request += data->request[i_request].getDataString();
	} else {
		request_data = &data->request[i_request];
		request = request_data->getDataString();
	}
	
	uri = this->getUri(request);
	if(!uri.length()) {
		continue;
		/*delete data;
		return;*/
	}
	contentLength = atol(this->getTag(request, "Content-Length").c_str());
	//if(!contentLength) {
	//	continue;
		/*delete data;
		return;*/
	//}
	response_data = NULL;
	if(data->response.size()) {
		response_data = &data->response[0];
		response = response_data->getDataString();
	}
	if(data->expectContinue.size()) {
		expectContinue = (char*)data->expectContinue[0].getData();
		if(data->expectContinueResponse.size()) {
			response_data = &data->expectContinueResponse[0];
			response = response_data->getDataString();
		}
	}
	
	if(expectContinue.length() && !data->forceAppendExpectContinue) {
		body = expectContinue;
	} else if(contentLength) {
		if(data->forceAppendExpectContinue) {
			request += expectContinue;
		}
		char *pointToBeginBody = (char*)strstr(request.c_str(), "\r\n\r\n");
		if(pointToBeginBody) {
			char oldEndChar = *pointToBeginBody;
			*pointToBeginBody = 0;
			http = request.c_str();
			*pointToBeginBody = oldEndChar;
			if(strlen(pointToBeginBody) > 4) {
				body = pointToBeginBody + 4;
			}
		}
	}
	if(//!body.length() ||
	   contentLength != body.length()) {
		if(body.length() == contentLength - 1 &&
		   body[0] == '{' && body[body.length() - 1] != '}') {
			body += "}";
		} else if(body.length() == contentLength + 1 &&
			body[0] == '{' && body[body.length()] == '}') {
			// OK
		} else {
			continue;
			/*delete data;
			return;*/
		}
	}
	ok = true;
	break;
	
	}
	if(!ok) {
		delete data;
		return;
	}
	
	
	if(!http.length()) {
		http = request;
	}
	string externalTransactionId = this->getTag(request, "External-Transaction-Id");
	if(externalTransactionId.empty() && body.length()) {
		externalTransactionId = this->getXmlValue(body, "correlation-id");
	}
	string sessionid = this->getUriValue(uri, "jajahsessionid");
	if(!sessionid.length() && body.length()) {
		sessionid = this->getJsonValue(body, "variable_jjSessionId");
	}
	if(!sessionid.length()) {
		sessionid = this->getUriPathValue(uri, "sessions");
	}
	string callid;
	if(body.length()) { 
		callid = this->getJsonValue(body, "variable_sip_call_id");
	}
	if(externalTransactionId.length() || sessionid.length() || callid.length()) {
		++this->counterSaveData;
		static int saveCounter;
		if(debugStream) {
			(*debugStream)
				<< "SAVE " << (++saveCounter) << " time: " << sqlDateTimeString(request_data->getTime().tv_sec) 
				<< (response.length() ? " with response" : "")
				<< endl;
		}
		this->cache.addRequest(getTimeUS(request_data->getTime()),
				       ip_src, ip_dst,
				       port_src, port_dst,
				       uri.c_str(), http.c_str(), body.c_str(),
				       callid.c_str(), sessionid.c_str(), externalTransactionId.c_str());
		if(response.length()) {
			size_t responseContentLength = atol(this->getTag(response, "Content-Length").c_str());
			string responseHttp;
			string responseBody;
			if(responseContentLength) {
				char *pointToBeginBody = (char*)strstr(response.c_str(), "\r\n\r\n");
				if(pointToBeginBody) {
					char oldEndChar = *pointToBeginBody;
					*pointToBeginBody = 0;
					responseHttp = response.c_str();
					*pointToBeginBody = oldEndChar;
					if(strlen(pointToBeginBody) > 4) {
						responseBody = pointToBeginBody + 4;
					}
				}
			}
			if(!responseHttp.length()) {
				responseHttp = response;
			}
			this->cache.addResponse(getTimeUS(response_data->getTime()),
						ip_dst, ip_src,
						port_dst, port_src,
						responseHttp.c_str(), responseBody.c_str(),
						uri.c_str(), http.c_str(), body.c_str());
		}
	}
	delete data;
	this->cache.writeToDb();
}

void HttpData::writeToDb(bool all) {
	this->cache.writeToDb(all, true);
}

string HttpData::getUri(string &request) {
	const char *requestTypes[] = { "POST", "GET", "HEADER" };
	int requestTypeIndex = -1;
	for(int i = 0; i < (int)(sizeof(requestTypes) / sizeof(requestTypes[0])); i++) {
		if(!strncmp(request.c_str(), requestTypes[i], strlen(requestTypes[i])) &&
		   request.c_str()[strlen(requestTypes[i])] == ' ') {
			requestTypeIndex = i;
			break;
		}
	}
	if(requestTypeIndex >= 0) {
		char *pointToBeginUri = (char*)(request.c_str() + strlen(requestTypes[requestTypeIndex]) + 1);
		char *pointToEndUri = strstr(pointToBeginUri, "\r\n");
		if(pointToEndUri) {
			char *pointToBeginHttpType = strstr(pointToBeginUri, " HTTP");
			if(pointToBeginHttpType && pointToBeginHttpType < pointToEndUri) {
				pointToEndUri = pointToBeginHttpType;
			}
			char oldEndChar = *pointToEndUri;
			*pointToEndUri = 0;
			string rslt = pointToBeginUri;
			*pointToEndUri = oldEndChar;
			return(rslt);
		}
	}
	return("");
}

string HttpData::getUriValue(string &uri, const char *valueName) {
	char *pointToBeginName = (char*)strcasestr(uri.c_str(), valueName);
	if(pointToBeginName) {
		char *pointToBeginValue = pointToBeginName + strlen(valueName);
		if(*pointToBeginValue == '=') {
			++pointToBeginValue;
		}
		char *pointToEndValue = (char*)(uri.c_str() + uri.length());
		char *pointToEndValue2 = strchr(pointToBeginValue, '&');
		if(pointToEndValue2) {
			pointToEndValue = pointToEndValue2;
		}
		if(pointToEndValue > pointToBeginValue) {
			char oldEndChar = *pointToEndValue;
			*pointToEndValue = 0;
			string rslt = pointToBeginValue;
			*pointToEndValue = oldEndChar;
			return(rslt);
		}
	}
	return("");
}

string HttpData::getUriPathValue(string &uri, const char *valueName) {
	char *pointToBeginName = (char*)strcasestr(uri.c_str(), valueName);
	if(pointToBeginName) {
		char *pointToBeginValue = pointToBeginName + strlen(valueName);
		while(*pointToBeginValue == '/') {
			++pointToBeginValue;
		}
		char *pointToEndValue = (char*)(uri.c_str() + uri.length());
		char *pointToEndValue2 = strchr(pointToBeginValue, '/');
		if(pointToEndValue2) {
			pointToEndValue = pointToEndValue2;
		}
		if(pointToEndValue > pointToBeginValue) {
			char oldEndChar = *pointToEndValue;
			*pointToEndValue = 0;
			string rslt = pointToBeginValue;
			*pointToEndValue = oldEndChar;
			return(rslt);
		}
	}
	return("");
}

string HttpData::getTag(string &data, const char *tag) {
	char *pointToBeginTag = (char*)strcasestr(data.c_str(), tag);
	if(pointToBeginTag) {
		char *pointToEndValue = strstr(pointToBeginTag, "\r\n");
		if(pointToEndValue) {
			char *pointToBeginValue = pointToBeginTag + strlen(tag);
			while(pointToBeginValue < pointToEndValue &&
			      (*pointToBeginValue == ':' || *pointToBeginValue == ' ')) {
				++pointToBeginValue;
			}
			while(pointToEndValue > pointToBeginValue &&
			      *pointToEndValue == ' ') {
				--pointToEndValue;
			}
			if(pointToEndValue > pointToBeginValue) {
				char oldEndChar = *pointToEndValue;
				*pointToEndValue = 0;
				string rslt = pointToBeginValue;
				*pointToEndValue = oldEndChar;
				return(rslt);
			}
		}
	}
	return("");
}

string HttpData::getJsonValue(string &data, const char *valueName) {
	string valueNameWithQuot = string("\"") + valueName + "\"";
	char *pointToBeginName = (char*)strcasestr(data.c_str(), valueNameWithQuot.c_str());
	if(pointToBeginName) {
		char *pointToBeginValue = pointToBeginName + strlen(valueName) + 2;
		while(*pointToBeginValue == ' ' || *pointToBeginValue == '\t' || 
		      *pointToBeginValue == ':' || *pointToBeginValue == '"') {
			++pointToBeginValue;
		}
		char *pointToEndValue = strchr(pointToBeginValue, '"');
		if(pointToEndValue && pointToEndValue > pointToBeginValue) {
			char oldEndChar = *pointToEndValue;
			*pointToEndValue = 0;
			string rslt = pointToBeginValue;
			*pointToEndValue = oldEndChar;
			return(rslt);
		}
	}
	return("");
}

string HttpData::getXmlValue(string &data, const char *valueName) {
	string valueNameWithEq = valueName + string("=");
	char *pointToBeginName = (char*)strcasestr(data.c_str(), valueNameWithEq.c_str());
	if(pointToBeginName) {
		char *pointToBeginValue = pointToBeginName + strlen(valueName) + 1;
		while(*pointToBeginValue == ' ' || *pointToBeginValue == '\t' || 
		      *pointToBeginValue == '\'') {
			++pointToBeginValue;
		}
		char *pointToEndValue = strchr(pointToBeginValue, '\'');
		if(pointToEndValue && pointToEndValue > pointToBeginValue) {
			char oldEndChar = *pointToEndValue;
			*pointToEndValue = 0;
			string rslt = pointToBeginValue;
			*pointToEndValue = oldEndChar;
			return(rslt);
		}
	}
	return("");
}

void HttpData::printContentSummary() {
	/*
	cout << "HTTP CACHE: " << this->cache.getSize() << endl;
	this->cache.cleanup(true);
	*/
}


HttpDataCache_relation::HttpDataCache_relation() {
	last_timestamp_response = 0;
}

HttpDataCache_relation::~HttpDataCache_relation() {
	delete request;
	while(responses.size()) {
		map<u_int64_t, HttpDataCache_data*>::iterator iter = responses.begin();
		delete iter->second;
		responses.erase(iter);
	}
}

void HttpDataCache_relation::addResponse(u_int64_t timestamp, const char *http, const char *body) {
	string http_md5 = http ? GetStringMD5(http) : "";
	string body_md5 = body ? GetStringMD5(body) : "";
	if(checkExistsResponse(http_md5.c_str(), body_md5.c_str())) {
		return;
	}
	this->responses[timestamp] = new FILE_LINE(11001) HttpDataCache_data(
						NULL, NULL,
						http, http_md5.c_str(),
						body, body_md5.c_str(),
						NULL, NULL, NULL);
	last_timestamp_response = timestamp;
}

bool HttpDataCache_relation::checkExistsResponse(const char *http_md5, const char *body_md5) {
	for(map<u_int64_t, HttpDataCache_data*>::iterator iter = responses.begin(); iter != responses.end(); iter++) {
		if(iter->second->http_md5 == http_md5 && 
		   iter->second->body_md5 == body_md5) {
			return(true);
		}
	}
	return(false);
}

HttpDataCache_link::~HttpDataCache_link() {
	while(relations.size()) {
		map<u_int64_t, HttpDataCache_relation*>::iterator iter = relations.begin();
		delete iter->second;
		relations.erase(iter);
	}
}

void HttpDataCache_link::addRequest(u_int64_t timestamp,
				    const char *url, const char *http, const char *body,
				    const char *callid, const char *sessionid, const char *external_transaction_id) {
	string url_md5 = url ? GetStringMD5(url) : "";
	string http_md5 = http ? GetStringMD5(http) : "";
	string body_md5 = body ? GetStringMD5(body) : "";
	string relations_map_id = getRelationsMapId(url_md5.c_str(), http_md5.c_str(), body_md5.c_str());
	if(relations_map.find(relations_map_id) != relations_map.end()) {
		return;
	}
	HttpDataCache_relation *new_relation = new FILE_LINE(11002) HttpDataCache_relation();
	new_relation->request = new FILE_LINE(11003) HttpDataCache_data(
					url, url_md5.c_str(),
					http, http_md5.c_str(),
					body, body_md5.c_str(),
					callid, sessionid, external_transaction_id);
	relations[timestamp] = new_relation;
	relations_map[relations_map_id] = new_relation;
}

void HttpDataCache_link::addResponse(u_int64_t timestamp,
				     const char *http, const char *body,
				     const char *url_master, const char *http_master, const char *body_master) {
	string url_master_md5 = url_master ? GetStringMD5(url_master) : "";
	string http_master_md5 = http_master ? GetStringMD5(http_master) : "";
	string body_master_md5 = body_master ? GetStringMD5(body_master) : "";
	string relations_map_id = getRelationsMapId(url_master_md5.c_str(), http_master_md5.c_str(), body_master_md5.c_str());
	map<string, HttpDataCache_relation*>::iterator iter = relations_map.find(relations_map_id);
	if(iter == relations_map.end()) {
		return;
	}
	iter->second->addResponse(timestamp, http, body);
}

bool HttpDataCache_link::checkExistsRequest(const char *url_md5, const char *http_md5, const char *body_md5) {
	map<string, HttpDataCache_relation*>::iterator iter = relations_map.find(getRelationsMapId(url_md5, http_md5, body_md5));
	return(iter != relations_map.end());
}

void HttpDataCache_link::writeToDb(const HttpDataCache_id *id, bool all, u_int64_t time) {
	u_int64_t actTimeMS = getTimeMS_rdtsc();
	for(map<u_int64_t, HttpDataCache_relation*>::iterator iter_rel = relations.begin(); iter_rel != relations.end(); ) {
		if(all || 
		   iter_rel->first < time - 10000000ull ||
		   iter_rel->first < actTimeMS * 1000ull - 30000000ull) {
			if(all || 
			   iter_rel->second->last_timestamp_response < time - 10000000ull ||
			   iter_rel->second->last_timestamp_response < actTimeMS * 1000ull - 30000000ull) {
				queryInsert = "";
				this->writeDataToDb(false, iter_rel->first, id, iter_rel->second->request);
				for(map<u_int64_t, HttpDataCache_data*>::iterator iter_resp = iter_rel->second->responses.begin(); iter_resp != iter_rel->second->responses.end(); iter_resp++) {
					this->writeDataToDb(true, iter_resp->first, id, iter_resp->second);
				}
				writeQueryInsertToDb();
				this->relations_map.erase(getRelationsMapId(iter_rel->second->request->url_md5, iter_rel->second->request->http_md5, iter_rel->second->request->body_md5));
				delete iter_rel->second;
				this->relations.erase(iter_rel++);
			} else {
				++iter_rel;
			}
		} else {
			break;
		}
	}
}

void HttpDataCache_link::writeDataToDb(bool response, u_int64_t timestamp, const HttpDataCache_id *id, HttpDataCache_data *data) {
	string http_jj_table = "http_jj";
	if(!response) {
		SqlDb_row rowRequest;
		rowRequest.add(sqlDateTimeString(TIME_US_TO_S(timestamp)), "timestamp");
		rowRequest.add(TIME_US_TO_DEC_US(timestamp), "usec");
		rowRequest.add(id->ip_src, "srcip", false, sqlDbSaveHttp, http_jj_table.c_str());
		rowRequest.add(id->ip_dst, "dstip", false, sqlDbSaveHttp, http_jj_table.c_str());
		rowRequest.add(id->port_src.getPort(), "srcport"); 
		rowRequest.add(id->port_dst.getPort(), "dstport"); 
		rowRequest.add(sqlEscapeString(data->url), "url");
		rowRequest.add((const char*)NULL, "type"); 
		rowRequest.add(sqlEscapeString(data->http), "http");
		rowRequest.add(sqlEscapeString(data->body).c_str(), "body");
		rowRequest.add(sqlEscapeString(data->callid).c_str(), "callid");
		rowRequest.add(sqlEscapeString(data->sessionid).c_str(), "sessid");
		rowRequest.add(sqlEscapeString(data->external_transaction_id).c_str(), "external_transaction_id");
		rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
		queryInsert += MYSQL_ADD_QUERY_END(
			       sqlDbSaveHttp->insertQuery(http_jj_table, rowRequest));
		queryInsert += MYSQL_ADD_QUERY_END(string(
			       "set @http_jj_request_id = last_insert_id()"));
		lastRequest_http_md5 = data->http_md5;
		lastRequest_body_md5 = data->body_md5;
	} else {
		SqlDb_row rowResponse;
		rowResponse.add(MYSQL_VAR_PREFIX + "@http_jj_request_id", "master_id");
		rowResponse.add(sqlDateTimeString(TIME_US_TO_S(timestamp)), "timestamp");
		rowResponse.add(TIME_US_TO_DEC_US(timestamp), "usec");
		rowResponse.add(id->ip_dst, "srcip", false, sqlDbSaveHttp, http_jj_table.c_str()); 
		rowResponse.add(id->ip_src, "dstip", false, sqlDbSaveHttp, http_jj_table.c_str()); 
		rowResponse.add(id->port_dst.getPort(), "srcport"); 
		rowResponse.add(id->port_src.getPort(), "dstport"); 
		rowResponse.add("", "url");
		rowResponse.add("http_ok", "type"); 
		rowResponse.add(sqlEscapeString(data->http), "http");
		rowResponse.add(sqlEscapeString(data->body).c_str(), "body");
		rowResponse.add("", "callid");
		rowResponse.add("", "sessid");
		rowResponse.add("", "external_transaction_id");
		rowResponse.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
		queryInsert += MYSQL_ADD_QUERY_END(
			       sqlDbSaveHttp->insertQuery(http_jj_table, rowResponse, true));
	}
}

void HttpDataCache_link::writeQueryInsertToDb() {
	if(queryInsert.empty()) {
		return;
	}
	extern bool opt_save_query_to_files;
	MySqlStore *sqlStore_http = use_mysql_2_http() && !opt_save_query_to_files ? sqlStore_2 : sqlStore;
	sqlStore_http->query_lock(queryInsert.c_str(),
				  STORE_PROC_ID_HTTP,
				  opt_mysqlstore_max_threads_http > 1 &&
				  sqlStore_http->getSize(STORE_PROC_ID_HTTP, 0) > 1000 ? 
				   writeToDb_counter % opt_mysqlstore_max_threads_http : 
				   0);
	++writeToDb_counter;
}

u_int32_t HttpDataCache_link::writeToDb_counter = 0;

HttpDataCache::HttpDataCache() {
	last_timestamp = 0;
	init_at = getTimeMS_rdtsc();
	last_write_at = 0;
	_sync = 0;
}

void HttpDataCache::addRequest(u_int64_t timestamp,
			       vmIP ip_src, vmIP ip_dst,
			       vmPort port_src, vmPort port_dst,
			       const char *url, const char *http, const char *body,
			       const char *callid, const char *sessionid, const char *external_transaction_id) {
	lock();
	HttpDataCache_id id(ip_src, ip_dst, port_src, port_dst);
	data[id].addRequest(timestamp,
			    url, http, body,
			    callid, sessionid, external_transaction_id);
	unlock();
	last_timestamp = timestamp;
}

void HttpDataCache::addResponse(u_int64_t timestamp,
				vmIP ip_src, vmIP ip_dst,
				vmPort port_src, vmPort port_dst,
				const char *http, const char *body,
				const char *url_master, const char *http_master, const char *body_master) {
	lock();
	HttpDataCache_id id(ip_dst, ip_src, port_dst, port_src);
	map<HttpDataCache_id, HttpDataCache_link>::iterator iter = data.find(id);
	if(iter == data.end()) {
		return;
	}
	iter->second.addResponse(timestamp,
				 http, body,
				 url_master, http_master, body_master);
	unlock();
	last_timestamp = timestamp;
}

void HttpDataCache::writeToDb(bool all, bool ifExpiration) {
	if(!last_timestamp) {
		return;
	}
	u_int64_t actTimeMS = getTimeMS_rdtsc();
	if(!all && ifExpiration &&
	   (last_write_at ? last_write_at : init_at) < actTimeMS - 10000) {
		return;
	}
	last_write_at = actTimeMS;
	lock();
	for(map<HttpDataCache_id, HttpDataCache_link>::iterator iter = data.begin(); iter != data.end(); ) {
		iter->second.writeToDb(&iter->first, all, last_timestamp);
		if(iter->second.relations.size()) {
			++iter;
		} else {
			data.erase(iter++);
		}
	}
	unlock();
}


HttpPacketsDumper::HttpPacketsDumper() {
	this->pcapDumper = NULL;
	this->unlinkPcap = false;
	this->selfOpenPcapDumper = false;
}

HttpPacketsDumper::~HttpPacketsDumper() {
	if(this->pcapDumper) {
		this->closePcapDumper();
	}
	if(this->unlinkPcap) {
		unlink(this->pcapName.c_str());
	}
}

void HttpPacketsDumper::setPcapName(const char *pcapName) {
	if(pcapName) {
		this->pcapName = pcapName;
	}
}

void HttpPacketsDumper::setTemplatePcapName() {
	this->pcapName = tmpnam();
}

void HttpPacketsDumper::setPcapDumper(PcapDumper *pcapDumper) {
	this->pcapDumper = pcapDumper;
}

void HttpPacketsDumper::dumpData(const char *timestamp_from, const char *timestamp_to, const char *ids) {
	SqlDb *sqlDb = createSqlObject(use_mysql_2_http() ? 1 : 0);
	SqlDb_row row;
	sqlDb->query(string("") +
		"select http_jj.*, \
			unix_timestamp(http_jj.timestamp) as sec \
		 from http_jj \
		 where timestamp >= '" + timestamp_from + "' and \
		       timestamp <= '" + timestamp_to + "' and \
		       id in (" + ids + ") \
		 order by sec, usec");
	while((row = sqlDb->fetchRow())) {
		timeval time;
		time.tv_sec = atoll(row["sec"].c_str());
		time.tv_usec = atoll(row["usec"].c_str());
		this->dumpDataItem(
			row.isNull("master_id") ? HttpPacketsDumper::request : HttpPacketsDumper::response,
			row["http"].c_str(),
			row["body"].c_str(),
			time,
			mysql_ip_2_vmIP(&row, "srcip"),
			mysql_ip_2_vmIP(&row, "dstip"),
			atoi(row["srcport"].c_str()),
			atoi(row["dstport"].c_str()));
	}
	delete sqlDb;
}

void HttpPacketsDumper::dumpDataItem(eReqResp /*reqResp*/, string header, string body,
				     timeval time,
				     vmIP ip_src, vmIP ip_dst,
				     vmPort port_src, vmPort port_dst) {
	if(!this->pcapDumper) {
		this->openPcapDumper();
	}
	
	HttpLink_id link_id = HttpLink_id(ip_src, ip_dst, port_src, port_dst);
	if(links.find(link_id) == links.end()) {
		links[link_id] = HttpLink(ip_src, ip_dst, port_src, port_dst);
	}
	
	int linkDirectionIndex = ip_src == links[link_id].ip1 && port_src == links[link_id].port1 ? 0 : 1;
	int linkDirectionNegIndex = linkDirectionIndex ? 0 : 1;
	
	string data = header + "\r\n\r\n" + body;
	
	ether_header eth_header;
	iphdr2 ip_header;
	tcphdr2 tcp_header;
	
	u_int32_t maxDataLengthInPacket = 0xFFFFul - (sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header));
	u_int32_t dataOffset = 0;
	
	while(dataOffset < data.length()) {
	 
		u_int32_t dataLength = min((unsigned)data.length() - dataOffset, maxDataLengthInPacket);
		bool lastPart = data.length() - dataOffset <= maxDataLengthInPacket;
	
		memset(&eth_header, 0, sizeof(eth_header));
		memset(&ip_header, 0, sizeof(ip_header));
		memset(&tcp_header, 0, sizeof(tcp_header));
		
		eth_header.ether_type = htons(ETHERTYPE_IP);
		
		ip_header.version = 4;
		ip_header._ihl = 5;
		ip_header._protocol = IPPROTO_TCP;
		ip_header.set_saddr(ip_src);
		ip_header.set_daddr(ip_dst);
		ip_header.set_tot_len(sizeof(ip_header) + sizeof(tcp_header) + dataLength);
		ip_header._ttl = 50;
		
		tcp_header.set_source(port_src);
		tcp_header.set_dest(port_dst);
		tcp_header.doff = 5;
		tcp_header.window = 0xFFFF;
		tcp_header.seq = htonl(links[link_id].seq[linkDirectionIndex]);
		tcp_header.ack_seq = htonl(links[link_id].seq[linkDirectionNegIndex]);
		tcp_header.psh = lastPart;
		tcp_header.ack = 1;
		
		links[link_id].seq[linkDirectionIndex] += dataLength;
		
		u_int32_t packetLen = sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header) + dataLength;
		u_char *packet = new FILE_LINE(11004) u_char[packetLen];
		
		memcpy(packet, 
		       &eth_header, sizeof(eth_header));
		memcpy(packet + sizeof(eth_header), 
		       &ip_header, sizeof(ip_header));
		memcpy(packet + sizeof(eth_header) + sizeof(ip_header), 
		       &tcp_header, sizeof(tcp_header));
		memcpy(packet + sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header), 
		       data.c_str() + dataOffset, dataLength);
		
		pcap_pkthdr pcap_header;
		memset(&pcap_header, 0, sizeof(pcap_header));
		pcap_header.ts = time;
		pcap_header.caplen = packetLen;
		pcap_header.len = packetLen; 
		
		this->pcapDumper->dump(&pcap_header, packet, DLT_EN10MB);
		
		delete [] packet;
		
		dataOffset += dataLength;
	}
}

void HttpPacketsDumper::setUnlinkPcap() {
	this->unlinkPcap = true;
}

string HttpPacketsDumper::getPcapName() {
	return(this->pcapName);
}

void HttpPacketsDumper::openPcapDumper() {
	if(!this->pcapDumper && !this->pcapName.empty()) {
		this->pcapDumper = new FILE_LINE(11005) PcapDumper();
		this->pcapDumper->open(tsf_na, this->pcapName.c_str(), DLT_EN10MB);
		this->selfOpenPcapDumper = true;
	}
}

void HttpPacketsDumper::closePcapDumper(bool force) {
	if((force || this->selfOpenPcapDumper) &&
	   this->pcapDumper) {
		this->pcapDumper->close();
		delete this->pcapDumper;
		this->pcapDumper = NULL;
	}
}

