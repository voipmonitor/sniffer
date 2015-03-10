#include <iostream>
#include <sstream>
#include <net/ethernet.h>

#include "http.h"
#include "sql_db.h"
#include "voipmonitor.h"


using namespace std;

extern int opt_id_sensor;
extern MySqlStore *sqlStore;
extern int opt_mysqlstore_max_threads_http;

SqlDb *sqlDbSaveHttp = NULL;


HttpData::HttpData() {
	this->counterProcessData = 0;
}

HttpData::~HttpData() {
	this->cache.clear();
}

void HttpData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			   u_int16_t port_src, u_int16_t port_dst,
			   TcpReassemblyData *data,
			   u_char *ethHeader, u_int32_t ethHeaderLength,
			   pcap_t *handle, int dlt, int sensor_id,
			   TcpReassemblyLink *reassemblyLink,
			   bool debugSave) {
 
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
		if(debugSave) {
			cout << "SAVE " << (++saveCounter) << " time: " << sqlDateTimeString(request_data->getTime().tv_sec) 
			     << (response.length() ? " with response" : "")
			     << endl;
		}
		HttpDataCache requestDataFromCache = this->cache.get(ip_src, ip_dst, port_src, port_dst,
								     &http, &body);
		if(!requestDataFromCache.timestamp) {
			SqlDb_row rowRequest;
			rowRequest.add(sqlDateTimeString(request_data->getTime().tv_sec), "timestamp");
			rowRequest.add(request_data->getTime().tv_usec, "usec");
			rowRequest.add(htonl(ip_src), "srcip");
			rowRequest.add(htonl(ip_dst), "dstip");
			rowRequest.add(port_src, "srcport"); 
			rowRequest.add(port_dst, "dstport"); 
			rowRequest.add(sqlEscapeString(uri), "url");
			rowRequest.add((const char*)NULL, "type"); 
			rowRequest.add(sqlEscapeString(http), "http");
			rowRequest.add(sqlEscapeString(body).c_str(), "body");
			rowRequest.add(sqlEscapeString(callid).c_str(), "callid");
			rowRequest.add(sqlEscapeString(sessionid).c_str(), "sessid");
			rowRequest.add(sqlEscapeString(externalTransactionId).c_str(), "external_transaction_id");
			rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
			queryInsert = sqlDbSaveHttp->insertQuery("http_jj", rowRequest);
			this->cache.add(ip_src, ip_dst, port_src, port_dst,
					&http, &body, NULL, NULL,
					1, request_data->getTime().tv_sec);
		}
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
			HttpDataCache responseDataFromCache = this->cache.get(ip_src, ip_dst, port_src, port_dst,
									      &http, &body, &responseHttp, &responseBody);
			if(!responseDataFromCache.timestamp) {
				if(requestDataFromCache.timestamp) {
					ostringstream queryFindMasterId;
					queryFindMasterId << "set @http_jj_id = (select id from http_jj where"
							  << " srcip = " << htonl(ip_src)
							  << " and dstip = " << htonl(ip_dst)
							  << " and srcport = " << port_src
							  << " and dstport = " << port_dst
							  << " and http = '" << sqlEscapeString(http) << "'"
							  << " and body = '" << sqlEscapeString(body) << "'"
							  << " and timestamp = '" << sqlDateTimeString(requestDataFromCache.timestamp) << "'" 
							  << " limit 1);" << endl
							  << "if @http_jj_id then" << endl;
					queryInsert += queryFindMasterId.str();
				} else {
					queryInsert += ";\n";
					queryInsert += "set @http_jj_id = last_insert_id();\n";
				}
				SqlDb_row rowRequest;
				rowRequest.add("_\\_'SQL'_\\_:@http_jj_id", "master_id");
				rowRequest.add(sqlDateTimeString(response_data->getTime().tv_sec), "timestamp");
				rowRequest.add(response_data->getTime().tv_usec, "usec");
				rowRequest.add(htonl(ip_dst), "srcip"); 
				rowRequest.add(htonl(ip_src), "dstip"); 
				rowRequest.add(port_dst, "srcport"); 
				rowRequest.add(port_src, "dstport"); 
				rowRequest.add("", "url");
				rowRequest.add("http_ok", "type"); 
				rowRequest.add(sqlEscapeString(responseHttp), "http");
				rowRequest.add(sqlEscapeString(responseBody).c_str(), "body");
				rowRequest.add("", "callid");
				rowRequest.add("", "sessid");
				rowRequest.add("", "external_transaction_id");
				rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
				queryInsert += sqlDbSaveHttp->insertQuery("http_jj", rowRequest, true);
				if(requestDataFromCache.timestamp) {
					queryInsert += ";\n";
					queryInsert += "end if";
				}
				this->cache.add(ip_src, ip_dst, port_src, port_dst,
						&http, &body, &responseHttp, &responseBody,
						1, response_data->getTime().tv_sec);
			}
		}
		if(queryInsert.length()) {
			int storeId = STORE_PROC_ID_HTTP_1 + 
				      (opt_mysqlstore_max_threads_http > 1 &&
				       sqlStore->getSize(STORE_PROC_ID_HTTP_1) > 1000 ? 
					counterProcessData % opt_mysqlstore_max_threads_http : 
					0);
			sqlStore->query_lock(queryInsert.c_str(), storeId);
		}
	}
	delete data;
	this->cache.cleanup(false);
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

void HttpData::printContentSummary() {
	cout << "HTTP CACHE: " << this->cache.getSize() << endl;
	this->cache.cleanup(true);
}


HttpCache::HttpCache() {
	this->cleanupCounter = 0;
	this->lastAddTimestamp = 0;	
}

HttpDataCache HttpCache::get(u_int32_t ip_src, u_int32_t ip_dst,
			     u_int16_t port_src, u_int16_t port_dst,
			     string *http, string *body,
			     string *http_master, string *body_master) {
	HttpDataCache_id idc(ip_src, ip_dst, port_src, port_dst, http, body, http_master, body_master);
	map<HttpDataCache_id, HttpDataCache>::iterator iter = this->cache.find(idc);
	if(iter == this->cache.end()) {
		return(HttpDataCache());
	} else {
		return(iter->second);
	}
}

void HttpCache::add(u_int32_t ip_src, u_int32_t ip_dst,
		    u_int16_t port_src, u_int16_t port_dst,
		    string *http, string *body,
		    string *http_master, string *body_master,
		    u_int32_t id, u_int64_t timestamp) {
	HttpDataCache_id idc(ip_src, ip_dst, port_src, port_dst, http, body, http_master, body_master);
	this->cache[idc] = HttpDataCache(id, timestamp);
	this->lastAddTimestamp = timestamp;
}

void HttpCache::cleanup(bool force) {
	++this->cleanupCounter;
	if(force ||
	   !(this->cleanupCounter % 100)) {
		u_int64_t clock = getTimeMS()/1000;
		map<HttpDataCache_id, HttpDataCache>::iterator iter;
		for(iter = this->cache.begin(); iter != this->cache.end(); ) {
			if(iter->second.timestamp < this->lastAddTimestamp - 120 ||
			   iter->second.timestamp_clock < clock - 120) {
				this->cache.erase(iter++);
			} else {
				++iter;
			}
		}
	}
}

void HttpCache::clear() {
	this->cache.clear();
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
	char tempFileName[L_tmpnam+1];
	tmpnam(tempFileName);
	this->pcapName = tempFileName;
}

void HttpPacketsDumper::setPcapDumper(PcapDumper *pcapDumper) {
	this->pcapDumper = pcapDumper;
}

void HttpPacketsDumper::dumpData(const char *timestamp_from, const char *timestamp_to, const char *ids) {
	SqlDb *sqlDb = createSqlObject();
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
			atoll(row["srcip"].c_str()),
			atoll(row["dstip"].c_str()),
			atol(row["srcport"].c_str()),
			atol(row["dstport"].c_str()));
	}
}

void HttpPacketsDumper::dumpDataItem(eReqResp reqResp, string header, string body,
				     timeval time,
				     u_int32_t ip_src, u_int32_t ip_dst,
				     u_int16_t port_src, u_int16_t port_dst) {
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
		ip_header.ihl = 5;
		ip_header.protocol = IPPROTO_TCP;
		ip_header.saddr = htonl(ip_src);
		ip_header.daddr = htonl(ip_dst);
		ip_header.tot_len = htons(sizeof(ip_header) + sizeof(tcp_header) + dataLength);
		ip_header.ttl = 50;
		
		tcp_header.source = htons(port_src);
		tcp_header.dest = htons(port_dst);
		tcp_header.doff = 5;
		tcp_header.window = 0xFFFF;
		tcp_header.seq = htonl(links[link_id].seq[linkDirectionIndex]);
		tcp_header.ack_seq = htonl(links[link_id].seq[linkDirectionNegIndex]);
		tcp_header.psh = lastPart;
		tcp_header.ack = 1;
		
		links[link_id].seq[linkDirectionIndex] += dataLength;
		
		u_int32_t packetLen = sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header) + dataLength;
		u_char *packet = new u_char[packetLen];
		
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
		this->pcapDumper = new PcapDumper();
		this->pcapDumper->open(this->pcapName.c_str(), DLT_EN10MB);
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

