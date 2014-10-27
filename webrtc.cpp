#include <iomanip>

#include "webrtc.h"
#include "sql_db.h"


using namespace std;

extern int opt_id_sensor;
extern MySqlStore *sqlStore;
extern int opt_mysqlstore_max_threads_webrtc;

SqlDb *sqlDbSaveWebrtc = NULL;


WebrtcData::WebrtcData() {
	this->counterProcessData = 0;
}

WebrtcData::~WebrtcData() {
	this->cache.clear();
}

void WebrtcData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			     u_int16_t port_src, u_int16_t port_dst,
			     TcpReassemblyData *data,
			     bool debugSave) {
	++this->counterProcessData;
	if(!sqlDbSaveWebrtc) {
		sqlDbSaveWebrtc = createSqlObject();
	}
	WebrtcDataItem webrtcDataItemRequest;
	string deviceIdRequest;
	string commCorrelationIdRequest;
	string bodyRequest;
	string queryInsert;
	WebrtcDataCache requestDataFromCache;
	for(int direction = TcpReassemblyStream::DIRECTION_TO_DEST;
	    direction <= TcpReassemblyStream::DIRECTION_TO_SOURCE;
	    direction++) {
		vector<TcpReassemblyDataItem> *dataItems = direction == TcpReassemblyStream::DIRECTION_TO_DEST ? 
							    &data->request :
							    &data->response;
		for(size_t i_data = 0; i_data < dataItems->size(); i_data++) {
			TcpReassemblyDataItem *dataItem = &(*dataItems)[i_data];
			if(debugSave) {
				cout << fixed
				     << setw(15) << inet_ntostring(ip_src)
				     << " / "
				     << setw(5) << port_src
				     << (direction == TcpReassemblyStream::DIRECTION_TO_DEST ? " -> " : " <- ")
				     << setw(15) << inet_ntostring(ip_dst)
				     << " / "
				     << setw(5) << port_dst
				     << "  len: " << setw(4) << dataItem->getDatalen() 
				     << endl;
			}
			WebrtcDecodeData webrtcDD;
			bool webrtcDD_ok;
			if(dataItem->getDatalen() > 4 &&
			   (!strncmp((char*)dataItem->getData(), "POST", 4) ||
			    !strncmp((char*)dataItem->getData(), "GET", 3) ||
			    !strncmp((char*)dataItem->getData(), "HTTP", 4))) {
				if(debugSave) {
					cout << "HTTP DATA: " << dataItem->getData() << endl;
				}
			} else {
				if(webrtcDD.decode(dataItem->getData(), dataItem->getDatalen())) {
					if(webrtcDD.method == "hb") {
						break;
					}
					if(debugSave) {
						switch(webrtcDD.opcode) {
						case opcode_textData:
							cout << "WEBRTC DATA";
							if(webrtcDD.data) {
								cout << ": (len: " << strlen((char*)webrtcDD.data)
								     << " payload len: " << webrtcDD.payload_length << ") "
								     << webrtcDD.data;
							}
							cout << endl;
							if(!webrtcDD.method.empty()) {
								cout << "   method: " << webrtcDD.method << endl;
							}
							if(!webrtcDD.deviceId.empty()) {
								cout << "   deviceId: " << webrtcDD.deviceId << endl;
							}
							if(!webrtcDD.commCorrelationId.empty()) {
								cout << "   commCorrelationId: " << webrtcDD.commCorrelationId << endl;
							}
							break;
						case opcode_binaryData:
							cout << "WEBRTC BINARY DATA" << endl;
							break;
						case opcode_terminatesConnection:
							cout << "WEBRTC TERMINATES CONNECTION" << endl;
							break;
						default:
							cout << "WEBRTC OTHER OPCODE" << endl;
							break;
						}
					}
					if(webrtcDD.opcode == opcode_textData && webrtcDD.data) {
						webrtcDD_ok = true;
					}
				}
			}
			if(webrtcDD_ok) {
				WebrtcDataItem webrtcDataItem(webrtcDD.opcode, webrtcDD.data);
				if(direction == TcpReassemblyStream::DIRECTION_TO_DEST) {
					if(i_data == 0) {
						webrtcDataItemRequest = webrtcDataItem;
						deviceIdRequest = webrtcDD.deviceId;
						commCorrelationIdRequest = webrtcDD.commCorrelationId;
						bodyRequest = (char*)webrtcDD.data;
					}
					requestDataFromCache = this->cache.get(ip_src, ip_dst, port_src, port_dst, &webrtcDataItem);
					if(!requestDataFromCache.timestamp) {
						SqlDb_row rowRequest;
						rowRequest.add(sqlDateTimeString(dataItem->getTime().tv_sec), "timestamp");
						rowRequest.add(dataItem->getTime().tv_usec, "usec");
						rowRequest.add(htonl(ip_src), "srcip");
						rowRequest.add(htonl(ip_dst), "dstip");
						rowRequest.add(port_src, "srcport"); 
						rowRequest.add(port_dst, "dstport"); 
						rowRequest.add("websocket", "type");
						rowRequest.add(webrtcDD.method, "method"); 
						rowRequest.add(sqlEscapeString((char*)webrtcDD.data).c_str(), "body");
						rowRequest.add(sqlEscapeString(!webrtcDD.deviceId.empty() ? 
										 webrtcDD.deviceId :
										 webrtcDD.commCorrelationId).c_str(), 
							       "external_transaction_id");
						rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
						queryInsert = sqlDbSaveWebrtc->insertQuery("webrtc", rowRequest);
						this->cache.add(ip_src, ip_dst, port_src, port_dst,
								&webrtcDataItem, NULL,
								dataItem->getTime().tv_sec);
					}
				} else {
					WebrtcDataCache responseDataFromCache = this->cache.get(ip_src, ip_dst, port_src, port_dst,
												&webrtcDataItem, &webrtcDataItemRequest);
					if(!responseDataFromCache.timestamp) {
						if(requestDataFromCache.timestamp) {
							ostringstream queryFindMasterId;
							queryFindMasterId << "set @webrtc_id = (select id from webrtc where"
									  << " srcip = " << htonl(ip_src)
									  << " and dstip = " << htonl(ip_dst)
									  << " and srcport = " << port_src
									  << " and dstport = " << port_dst
									  << " and body = '" << sqlEscapeString(bodyRequest) << "'"
									  << " and timestamp = '" << sqlDateTimeString(requestDataFromCache.timestamp) << "'" 
									  << " limit 1);" << endl
									  << "if @webrtc_id then" << endl;
							queryInsert += queryFindMasterId.str();
						} else {
							queryInsert += ";\n";
							queryInsert += "set @webrtc_id = last_insert_id();\n";
						}
						SqlDb_row rowRequest;
						rowRequest.add("_\\_'SQL'_\\_:@webrtc_id", "master_id");
						rowRequest.add(sqlDateTimeString(dataItem->getTime().tv_sec), "timestamp");
						rowRequest.add(dataItem->getTime().tv_usec, "usec");
						rowRequest.add(htonl(ip_dst), "srcip"); 
						rowRequest.add(htonl(ip_src), "dstip"); 
						rowRequest.add(port_dst, "srcport"); 
						rowRequest.add(port_src, "dstport"); 
						rowRequest.add("websocket_resp", "type");
						rowRequest.add(webrtcDD.method, "method"); 
						rowRequest.add(sqlEscapeString((char*)webrtcDD.data).c_str(), "body");
						rowRequest.add(sqlEscapeString(!webrtcDD.deviceId.empty() ? 
										 webrtcDD.deviceId :
									       !webrtcDD.commCorrelationId.empty() ? 
										 webrtcDD.commCorrelationId :
									       !deviceIdRequest.empty() ?
										 deviceIdRequest :
										 commCorrelationIdRequest),
							       "external_transaction_id");
						rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
						queryInsert += sqlDbSaveWebrtc->insertQuery("webrtc", rowRequest, true);
						if(requestDataFromCache.timestamp) {
							queryInsert += ";\n";
							queryInsert += "end if";
						}
						this->cache.add(ip_src, ip_dst, port_src, port_dst,
								&webrtcDataItem, &webrtcDataItemRequest,
								dataItem->getTime().tv_sec);
					}
				}
			}
		}
	}
	if(queryInsert.length()) {
		int storeId = STORE_PROC_ID_WEBRTC_1 + 
			      (opt_mysqlstore_max_threads_webrtc > 1 &&
			       sqlStore->getSize(STORE_PROC_ID_WEBRTC_1) > 1000 ? 
				counterProcessData % opt_mysqlstore_max_threads_webrtc : 
				0);
		sqlStore->query_lock(queryInsert.c_str(), storeId);
	}
	delete data;
	this->cache.cleanup(false);
}
 
void WebrtcData::printContentSummary() {
	cout << "WEBRTC CACHE: " << this->cache.getSize() << endl;
	this->cache.cleanup(true);
}

unsigned int WebrtcData::WebrtcDecodeData::decode(u_char *data, unsigned int data_length) {
	u_int16_t headerLength = 2;
	if(data_length <= headerLength) {
		return(0);
	}
	WebrtcHeader *header = (WebrtcHeader*)data;
	opcode = (eWebrtcOpcode)header->opcode;
	switch(opcode) {
	case opcode_continuePayload:
	case opcode_textData:
	case opcode_binaryData:
	case opcode_terminatesConnection:
	case opcode_ping:
	case opcode_pong:
		break;
	default:
		clear();
		return(0);
	}
	if(header->payload_length >= 126) {
		headerLength += 2;
		if(data_length <= headerLength) {
			clear();
			return(0);
		}
		payload_length = htons(*(u_int16_t*)(data + headerLength - 2));
	} else {
		payload_length = header->payload_length;
	}
	if(header->mask) {
		headerLength += 4;
		if(data_length <= headerLength) {
			switch(opcode) {
			case opcode_terminatesConnection:
			case opcode_ping:
			case opcode_pong:
				return(headerLength - 4);
				break;
			default:
				clear();
				return(0);
			}
		}
		masking_key = htonl(*(u_int32_t*)(data + headerLength - 4));
	}
	if(data_length < headerLength + payload_length) {
		clear();
		return(0);
	}
	if(payload_length) {
		u_int32_t dataLength = payload_length / 4 * 4 + (payload_length % 4 ? 4 : 0);
		this->data = new u_char[dataLength + 1];
		memcpy(this->data, data + headerLength, payload_length);
		if(masking_key) {
			for(u_int32_t i = 0; i < dataLength; i += 4) {
				*(u_int32_t*)(this->data + i) = htonl(htonl(*(u_int32_t*)(this->data + i)) ^ masking_key);
			}
		}
		for(u_int32_t i = payload_length; i < dataLength + 1; i++) {
			this->data[i] = 0;
		}
		if(opcode == opcode_textData) {
			this->method = reg_replace((char*)this->data, "\"method\":\"([^\"]+)\"", "$1");
			this->deviceId = reg_replace((char*)this->data, "\"deviceId\":\"([^\"]+)\"", "$1");
			this->commCorrelationId = reg_replace((char*)this->data, "\"Comm-Correlation-ID\":\"([^\"]+)\"", "$1");
		}
	}
	return(headerLength + payload_length);
}


WebrtcCache::WebrtcCache() {
	this->cleanupCounter = 0;
	this->lastAddTimestamp = 0;	
}

WebrtcDataCache WebrtcCache::get(u_int32_t ip_src, u_int32_t ip_dst,
				 u_int16_t port_src, u_int16_t port_dst,
				 WebrtcDataItem *data,
				 WebrtcDataItem *data_master) {
	WebrtcDataCache_id idc(ip_src, ip_dst, port_src, port_dst, data, data_master);
	map<WebrtcDataCache_id, WebrtcDataCache>::iterator iter = this->cache.find(idc);
	if(iter == this->cache.end()) {
		return(WebrtcDataCache());
	} else {
		return(iter->second);
	}
}

void WebrtcCache::add(u_int32_t ip_src, u_int32_t ip_dst,
		      u_int16_t port_src, u_int16_t port_dst,
		      WebrtcDataItem *data,
		      WebrtcDataItem *data_master,
		      u_int64_t timestamp) {
	WebrtcDataCache_id idc(ip_src, ip_dst, port_src, port_dst, data, data_master);
	this->cache[idc] = WebrtcDataCache(timestamp);
	this->lastAddTimestamp = timestamp;
}

void WebrtcCache::cleanup(bool force) {
	++this->cleanupCounter;
	if(force ||
	   !(this->cleanupCounter % 100)) {
		u_int64_t clock = getTimeMS()/1000;
		map<WebrtcDataCache_id, WebrtcDataCache>::iterator iter;
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

void WebrtcCache::clear() {
	this->cache.clear();
}
