#include <iostream>

#include "http.h"
#include "sql_db.h"


using namespace std;

extern int opt_id_sensor;
extern SqlDb *sqlDb;
extern MySqlStore *sqlStore;


void HttpData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			   u_int16_t port_src, u_int16_t port_dst,
			   TcpReassemblyData *data) {
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
	TcpReassemblyDataItem *request_data;
	TcpReassemblyDataItem *response_data;
	
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
		request += (char*)data->request[i_request].data;
	} else {
		request_data = &data->request[i_request];
		request = (char*)request_data->data;
	}
	
	uri = this->getUri(request);
	if(!uri.length()) {
		continue;
		/*delete data;
		return;*/
	}
	contentLength = atol(this->getTag(request, "Content-Length").c_str());
	if(!contentLength) {
		continue;
		/*delete data;
		return;*/
	}
	response_data = NULL;
	if(data->response.size()) {
		response_data = &data->response[0];
		response = (char*)response_data->data;
	}
	if(data->expectContinue.size()) {
		expectContinue = (char*)data->expectContinue[0].data;
		if(data->expectContinueResponse.size()) {
			response_data = &data->expectContinueResponse[0];
			response = (char*)response_data->data;
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
	if(!body.length() ||
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
		string queryInsert;
		static int saveCounter;
		cout << "SAVE " << (++saveCounter) << " time: " << sqlDateTimeString(request_data->time.tv_sec) 
		     << (response.length() ? " with response" : "")
		     << endl;
		SqlDb_row rowRequest;
		rowRequest.add(sqlDateTimeString(request_data->time.tv_sec), "timestamp");
		rowRequest.add(request_data->time.tv_usec, "usec");
		rowRequest.add(htonl(ip_src), "srcip"); 
		rowRequest.add(htonl(ip_dst), "dstip"); 
		rowRequest.add(sqlEscapeString(uri), "url");
		rowRequest.add((const char*)NULL, "type"); 
		rowRequest.add(sqlEscapeString(http), "http");
		rowRequest.add(sqlEscapeString(body).c_str(), "body");
		rowRequest.add(sqlEscapeString(callid).c_str(), "callid");
		rowRequest.add(sqlEscapeString(sessionid).c_str(), "sessid");
		rowRequest.add(sqlEscapeString(externalTransactionId).c_str(), "external_transaction_id");
		rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
		queryInsert = sqlDb->insertQuery("http_jj", rowRequest);
		if(response.length()) {
			queryInsert += ";\n";
			queryInsert += "set @http_jj_id = last_insert_id();\n";
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
			SqlDb_row rowRequest;
			rowRequest.add("_\\_'SQL'_\\_:@http_jj_id", "master_id");
			rowRequest.add(sqlDateTimeString(response_data->time.tv_sec), "timestamp");
			rowRequest.add(response_data->time.tv_usec, "usec");
			rowRequest.add(htonl(ip_dst), "srcip"); 
			rowRequest.add(htonl(ip_src), "dstip"); 
			rowRequest.add("", "url");
			rowRequest.add("http_ok", "type"); 
			rowRequest.add(sqlEscapeString(responseHttp), "http");
			rowRequest.add(sqlEscapeString(responseBody).c_str(), "body");
			rowRequest.add("", "callid");
			rowRequest.add("", "sessid");
			rowRequest.add("", "external_transaction_id");
			rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
			queryInsert += sqlDb->insertQuery("http_jj", rowRequest, true);
		}
		sqlStore->lock(STORE_PROC_ID_HTTP);
		sqlStore->query(queryInsert.c_str(), STORE_PROC_ID_HTTP);
		sqlStore->unlock(STORE_PROC_ID_HTTP);
	}
	delete data;
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