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

void WebrtcData::processData(vmIP ip_src, vmIP ip_dst,
			     vmPort port_src, vmPort port_dst,
			     TcpReassemblyData *data,
			     u_char */*ethHeader*/, u_int32_t /*ethHeaderLength*/,
			     u_int16_t /*handle_index*/, int /*dlt*/, int /*sensor_id*/, vmIP /*sensor_ip*/, sPacketInfoData /*pid*/,
			     void */*uData*/, void */*uData2*/, void */*uData2_last*/, TcpReassemblyLink */*reassemblyLink*/,
			     std::ostream *debugStream) {
	++this->counterProcessData;
	if(debugStream) {
		(*debugStream) << "### WebrtcData::processData " << this->counterProcessData << endl;
	}
	if(!sqlDbSaveWebrtc) {
		sqlDbSaveWebrtc = createSqlObject();
	}
	for(size_t i_data = 0; i_data < data->data.size(); i_data++) {
		TcpReassemblyDataItem *dataItem = &data->data[i_data];
		if(!dataItem->getData()) {
			continue;
		}
		if(debugStream) {
			(*debugStream)
				<< fixed
				<< setw(15) << ip_src.getString()
				<< " / "
				<< setw(5) << port_src
				<< (dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? " --> " : " <-- ")
				<< setw(15) << ip_dst.getString()
				<< " / "
				<< setw(5) << port_dst
				<< "  len: " << setw(4) << dataItem->getDatalen();
			u_int32_t ack = dataItem->getAck();
			if(ack) {
				(*debugStream) << "  ack: " << setw(5) << ack;
			}
			(*debugStream) << endl;
		}
		WebrtcDecodeData webrtcDD;
		if(dataItem->getDatalen() > 4 &&
		   (!strncmp((char*)dataItem->getData(), "POST", 4) ||
		    !strncmp((char*)dataItem->getData(), "GET", 3) ||
		    !strncmp((char*)dataItem->getData(), "HTTP", 4))) {
			if(debugStream) {
				(*debugStream) << "  HTTP DATA: " << dataItem->getData() << endl;
			}
			continue;
		} else {
			unsigned int rsltDecode = webrtcDD.decode(dataItem->getData(), dataItem->getDatalen());
			if(rsltDecode) {
				if(webrtcDD.method == "hb") {
					if(debugStream) {
						(*debugStream) << "   method: hb - skip" << endl;
					}
					continue;
				}
				if(debugStream) {
					switch(webrtcDD.opcode) {
					case opcode_textData:
						(*debugStream) << "  WEBRTC " << webrtcDD.type << " DATA";
						if(webrtcDD.data) {
							(*debugStream)
								<< ": (len: " << strlen((char*)webrtcDD.data)
								<< " payload len: " << webrtcDD.payload_length << ") "
								<< webrtcDD.data;
						}
						(*debugStream) << endl;
						if(!webrtcDD.method.empty()) {
							(*debugStream) << "   method: " << webrtcDD.method << endl;
						}
						if(!webrtcDD.type.empty()) {
							(*debugStream) << "   type: " << webrtcDD.type << endl;
						}
						if(!webrtcDD.deviceId.empty()) {
							(*debugStream) << "   deviceId: " << webrtcDD.deviceId << endl;
						}
						if(!webrtcDD.commCorrelationId.empty()) {
							(*debugStream) << "   commCorrelationId: " << webrtcDD.commCorrelationId << endl;
						}
						break;
					case opcode_binaryData:
						(*debugStream) << "  WEBRTC BINARY DATA" << endl;
						break;
					case opcode_terminatesConnection:
						(*debugStream) << "  WEBRTC TERMINATES CONNECTION" << endl;
						break;
					default:
						(*debugStream) << "  WEBRTC OTHER OPCODE" << endl;
						break;
					}
				}
				if(rsltDecode != dataItem->getDatalen()) {
					if(debugStream) {
						(*debugStream) << "  WARNING - BAD LENGTH WEBRTC DATA" << endl;
					}
				}
				if(webrtcDD.opcode != opcode_textData) {
					continue;
				}
			} else {
				if(debugStream) {
					(*debugStream) << "  BAD WEBRTC DATA: " << endl;
				}
				continue;
			}
		}
		if((webrtcDD.opcode == opcode_textData && webrtcDD.data) &&
		   (webrtcDD.type == "req" || webrtcDD.type == "rsp") &&
		   ((webrtcDD.method == "login" && !webrtcDD.deviceId.empty()) || 
		    (webrtcDD.method == "msg" && !webrtcDD.commCorrelationId.empty()))) {
			string data_md5 = GetDataMD5(webrtcDD.data, webrtcDD.payload_length);
			vmIP _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
			vmIP _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
			vmPort _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
			vmPort _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
			WebrtcDataCache requestDataFromCache = this->cache.get(_ip_src, _ip_dst, _port_src, _port_dst, data_md5);
			if(requestDataFromCache.timestamp) {
				if(debugStream) {
					(*debugStream) << "DUPL" << endl;
				}
			} else {
				SqlDb_row rowRequest;
				string webrtc_table = "webrtc";
				rowRequest.add(sqlDateTimeString(dataItem->getTime().tv_sec), "timestamp");
				rowRequest.add(dataItem->getTime().tv_usec, "usec");
				rowRequest.add(_ip_src, "srcip", false, sqlDbSaveWebrtc, webrtc_table.c_str());
				rowRequest.add(_ip_dst, "dstip", false, sqlDbSaveWebrtc, webrtc_table.c_str());
				rowRequest.add(_port_src.getPort(), "srcport"); 
				rowRequest.add(_port_dst.getPort(), "dstport"); 
				rowRequest.add(webrtcDD.type == "req" ? "websocket" : "websocket_resp", "type");
				rowRequest.add(webrtcDD.method, "method"); 
				rowRequest.add(sqlEscapeString((char*)webrtcDD.data).c_str(), "body");
				rowRequest.add(sqlEscapeString(!webrtcDD.deviceId.empty() ? 
								 webrtcDD.deviceId :
								 webrtcDD.commCorrelationId).c_str(), 
					       "external_transaction_id");
				rowRequest.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "id_sensor", opt_id_sensor <= 0);
				string queryInsert = MYSQL_ADD_QUERY_END(sqlDbSaveWebrtc->insertQuery("webrtc", rowRequest));
				sqlStore->query_lock(queryInsert.c_str(),
						     STORE_PROC_ID_WEBRTC,
						     opt_mysqlstore_max_threads_webrtc > 1 &&
						     sqlStore->getSize(STORE_PROC_ID_WEBRTC, 0) > 1000 ? 
						      counterProcessData % opt_mysqlstore_max_threads_webrtc : 
						      0);
				if(debugStream) {
					(*debugStream) << "SAVE" << endl;
				}
				this->cache.add(_ip_src, _ip_dst, _port_src, _port_dst, data_md5,
						dataItem->getTime().tv_sec);
			}
		} else {
			if(debugStream) {
				(*debugStream) << "  UNCOMPLETE WEBRTC DATA: " << endl;
			}
		}
	}
	delete data;
	this->cache.cleanup(false);
}
 
void WebrtcData::printContentSummary() {
	cout << "WEBRTC CACHE: " << this->cache.getSize() << endl;
	this->cache.cleanup(true);
}

unsigned int WebrtcData::WebrtcDecodeData::decode(u_char *data, unsigned int data_length, bool checkOkOnly) {
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
	if(payload_length && !checkOkOnly) {
		u_int32_t dataLength = payload_length / 4 * 4 + (payload_length % 4 ? 4 : 0);
		this->data = new FILE_LINE(43001) u_char[dataLength + 1];
		memcpy_heapsafe(this->data, this->data,
				data + headerLength, data,
				payload_length,
				__FILE__, __LINE__);
		if(masking_key) {
			for(u_int32_t i = 0; i < dataLength; i += 4) {
				*(u_int32_t*)(this->data + i) = htonl(htonl(*(u_int32_t*)(this->data + i)) ^ masking_key);
			}
		}
		for(u_int32_t i = payload_length; i < dataLength + 1; i++) {
			this->data[i] = 0;
		}
		if(opcode == opcode_textData) {
			this->method = reg_replace((char*)this->data, "\"method\":\"([^\"]+)\"", "$1", __FILE__, __LINE__);
			this->type = reg_replace((char*)this->data, "\"type\":\"([^\"]+)\"", "$1", __FILE__, __LINE__);
			this->deviceId = reg_replace((char*)this->data, "\"deviceId\":\"([^\"]+)\"", "$1", __FILE__, __LINE__);
			this->commCorrelationId = reg_replace((char*)this->data, "\"Comm-Correlation-ID\":\"([^\"]+)\"", "$1", __FILE__, __LINE__);
			if(this->commCorrelationId.empty()) {
				this->commCorrelationId = reg_replace((char*)this->data, "\"comm-correlation-id\":\"([^\"]+)\"", "$1", __FILE__, __LINE__);
			}
		}
	}
	return(headerLength + payload_length);
}


WebrtcCache::WebrtcCache() {
	this->cleanupCounter = 0;
	this->lastAddTimestamp = 0;	
}

WebrtcDataCache WebrtcCache::get(vmIP ip_src, vmIP ip_dst,
				 vmPort port_src, vmPort port_dst,
				 string data_md5) {
	WebrtcDataCache_id idc(ip_src, ip_dst, port_src, port_dst, data_md5);
	map<WebrtcDataCache_id, WebrtcDataCache>::iterator iter = this->cache.find(idc);
	if(iter == this->cache.end()) {
		return(WebrtcDataCache());
	} else {
		return(iter->second);
	}
}

void WebrtcCache::add(vmIP ip_src, vmIP ip_dst,
		      vmPort port_src, vmPort port_dst,
		      string data_md5,
		      u_int64_t timestamp) {
	WebrtcDataCache_id idc(ip_src, ip_dst, port_src, port_dst, data_md5);
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


bool checkOkWebrtcHttpData(u_char *data, u_int32_t datalen) {
	return(data && datalen > 4 &&
	       (!strncmp((char*)data, "POST", 4) ||
		!strncmp((char*)data, "GET", 3) ||
		!strncmp((char*)data, "HTTP", 4)));
}

bool checkOkWebrtcData(u_char *data, u_int32_t datalen) {
	if(!data) {
		return(false);
	}
	WebrtcData::WebrtcDecodeData webrtcDD;
	return(webrtcDD.decode(data, datalen, true) > 0);
}
