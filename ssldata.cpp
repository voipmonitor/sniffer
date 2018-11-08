#include <iomanip>

#include "ssldata.h"
#include "sniff_proc_class.h"
#include "sql_db.h"
#include "ssl_dssl.h"
#include "websocket.h"

#ifdef FREEBSD
#include <sys/socket.h>
#endif


using namespace std;

extern int opt_enable_ssl;

extern int check_sip20(char *data, unsigned long len, ParsePacket::ppContentsX *parseContents, bool isTcp);

#ifdef HAVE_LIBGNUTLS
extern void decrypt_ssl(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport);
#endif

extern map<d_u_int32_t, string> ssl_ipport;
extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];


SslData::SslData() {
	this->counterProcessData = 0;
}

SslData::~SslData() {
}

void SslData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			  u_int16_t port_src, u_int16_t port_dst,
			  TcpReassemblyData *data,
			  u_char *ethHeader, u_int32_t ethHeaderLength,
			  u_int16_t handle_index, int dlt, int sensor_id, u_int32_t sensor_ip,
			  void */*uData*/, TcpReassemblyLink *reassemblyLink,
			  std::ostream *debugStream) {
	++this->counterProcessData;
	if(debugStream) {
		(*debugStream) << "### SslData::processData " << this->counterProcessData << endl;
	}
	for(size_t i_data = 0; i_data < data->data.size(); i_data++) {
		TcpReassemblyDataItem *dataItem = &data->data[i_data];
		if(!dataItem->getData()) {
			continue;
		}
		u_int32_t _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
		u_int32_t _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
		u_int16_t _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
		u_int16_t _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
		if(reassemblyLink->checkDuplicitySeq(dataItem->getSeq())) {
			if(debugStream) {
				(*debugStream) << "SKIP SEQ " << dataItem->getSeq() << endl;
			}
			continue;
		}
		if(debugStream) {
			(*debugStream)
				<< "###"
				<< fixed
				<< setw(15) << inet_ntostring(htonl(ip_src))
				<< " / "
				<< setw(5) << port_src
				<< (dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? " --> " : " <-- ")
				<< setw(15) << inet_ntostring(htonl(ip_dst))
				<< " / "
				<< setw(5) << port_dst
				<< "  len: " << setw(4) << dataItem->getDatalen();
			u_int32_t ack = dataItem->getAck();
			if(ack) {
				(*debugStream) << "  ack: " << setw(5) << ack;
			}
			(*debugStream) << endl;
		}
		vector<string> rslt_decrypt;
		for(int pass = 0; pass < 2; pass++) {
			u_char *ssl_data;
			u_int32_t ssl_datalen;
			bool alloc_ssl_data = false;
			if(reassemblyLink->getRemainData(dataItem->getDirection())) {
				ssl_datalen = reassemblyLink->getRemainDataLength(dataItem->getDirection()) + dataItem->getDatalen();
				ssl_data = new FILE_LINE(33001) u_char[ssl_datalen];
				memcpy(ssl_data, reassemblyLink->getRemainData(dataItem->getDirection()), reassemblyLink->getRemainDataLength(dataItem->getDirection()));
				memcpy(ssl_data + reassemblyLink->getRemainDataLength(dataItem->getDirection()), dataItem->getData(), dataItem->getDatalen());
				alloc_ssl_data = true;
			} else {
				ssl_data = dataItem->getData();
				ssl_datalen = dataItem->getDatalen();
			}
			u_int32_t ssl_data_offset = 0;
			while(ssl_data_offset < ssl_datalen &&
			      ssl_datalen - ssl_data_offset >= 5) {
				SslHeader header(ssl_data + ssl_data_offset, ssl_datalen - ssl_data_offset);
				if(header.isOk() && header.length && (u_int32_t)header.length + header.getDataOffsetLength() <= ssl_datalen - ssl_data_offset) {
					if(debugStream) {
						(*debugStream)
							<< "SSL HEADER "
							<< "content type: " << (int)header.content_type << " / "
							<< "version: " << hex << header.version << dec << " / "
							<< "length: " << header.length
							<< endl;
					}
					vector<string> rslt_decrypt_part;
					if(opt_enable_ssl == 10) {
						#ifdef HAVE_LIBGNUTLS
						decrypt_ssl(&rslt_decrypt_part, (char*)(ssl_data + ssl_data_offset), header.length + header.getDataOffsetLength(), htonl(_ip_src), htonl(_ip_dst), _port_src, _port_dst);
						#endif
					} else {
						decrypt_ssl_dssl(&rslt_decrypt_part, (char*)(ssl_data + ssl_data_offset), header.length + header.getDataOffsetLength(), htonl(_ip_src), htonl(_ip_dst), _port_src, _port_dst, dataItem->getTime());
					}
					if(rslt_decrypt_part.size()) {
						for(size_t i = 0; i < rslt_decrypt_part.size(); i++) {
							rslt_decrypt.push_back(rslt_decrypt_part[i]);
						}
					}
					ssl_data_offset += header.length + header.getDataOffsetLength();
				} else {
					break;
				}
			}
			if(pass == 0) {
				bool ok = false;
				if(reassemblyLink->getRemainDataLength(dataItem->getDirection()) &&
				   !ssl_data_offset &&
				   _checkOkSslData(dataItem->getData(), dataItem->getDatalen())) {
					// next pass with ignore remainData
					reassemblyLink->clearRemainData(dataItem->getDirection());
					if(debugStream) {
						(*debugStream) << "SKIP REMAIN DATA" << endl;
					}
				} else {
					if(ssl_data_offset < ssl_datalen) {
						reassemblyLink->setRemainData(ssl_data + ssl_data_offset, ssl_datalen - ssl_data_offset, dataItem->getDirection());
						if(debugStream) {
							(*debugStream) << "REMAIN DATA LENGTH: " << ssl_datalen - ssl_data_offset << endl;
						}
					} else {
						reassemblyLink->clearRemainData(dataItem->getDirection());
					}
					ok = true;
				}
				if(alloc_ssl_data) {
					delete [] ssl_data;
				}
				if(ok) {
					break;
				}
			}
		}
		for(size_t i = 0; i < rslt_decrypt.size(); i++) {
			if(debugStream) {
				string out(rslt_decrypt[i], 0,100);
				std::replace( out.begin(), out.end(), '\n', ' ');
				std::replace( out.begin(), out.end(), '\r', ' ');
				unsigned long s_addr = _ip_src;
				unsigned long d_addr = _ip_dst;
				char src[INET_ADDRSTRLEN];
				char dst[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &s_addr, src, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &d_addr, dst, INET_ADDRSTRLEN);
				if(out.length()) {
					(*debugStream) << "TS: " << dataItem->getTime().tv_sec << "." << dataItem->getTime().tv_usec << " " << src << " -> " << dst << " SIP " << rslt_decrypt[i].length() << " " << out << endl;
				}
				(*debugStream) << "DECRYPT DATA: " << rslt_decrypt[i] << endl;
			}
			if(!ethHeader || !ethHeaderLength) {
				continue;
			}
			string dataComb;
			bool dataCombUse = false;
			if(i < rslt_decrypt.size() - 1 && rslt_decrypt[i].length() == 1) {
				dataComb = rslt_decrypt[i] + rslt_decrypt[i + 1];
				if(check_sip20((char*)dataComb.c_str(), dataComb.length(), NULL, true) ||
				   check_websocket((char*)dataComb.c_str(), dataComb.length(), false)) {
					dataCombUse = true;
				}
			}
			u_char *data;
			unsigned dataLength;
			if(dataCombUse) {
				data = (u_char*)dataComb.c_str();
				dataLength = dataComb.size();
				++i;
			} else {
				data = (u_char*)rslt_decrypt[i].c_str();
				dataLength = rslt_decrypt[i].size();
			}
			bool allocData = false;
			bool tcp = false;
			if(check_websocket(data, dataLength)) {
				tcp = true;
				if(sverb.ssldecode) {
					hexdump(data, dataLength);
					cout << "---" << endl;
					cWebSocketHeader ws(data, dataLength);
					bool allocWsData;
					u_char *ws_data = ws.decodeData(&allocWsData);
					cout << string((char*)ws_data, ws.getDataLength()) << endl;
					if(allocWsData) {
						delete [] ws_data;
					}
					cout << "------" << endl;
				}
			} else if(check_websocket(data, dataLength, false) || 
				  (dataLength < websocket_header_length((char*)data, dataLength) && check_websocket_first_byte(data, dataLength))) {
				reassemblyWebsocketBuffer.processPacket(_ip_src, _ip_dst, _port_src, _port_dst,
									data, dataLength, true, NULL);
				data = NULL;
			} else if(reassemblyWebsocketBuffer.existsStream(_ip_src, _ip_dst, _port_src, _port_dst)) {
				tcp = true;
				data = reassemblyWebsocketBuffer.processPacket(_ip_src, _ip_dst, _port_src, _port_dst,
									       data, dataLength, false, &dataLength);
				if(data) {
					allocData = true;
					if(sverb.ssldecode) {
						hexdump(data, dataLength);
						cout << "---" << endl;
						cWebSocketHeader ws(data, dataLength);
						bool allocWsData;
						u_char *ws_data = ws.decodeData(&allocWsData);
						cout << string((char*)ws_data, ws.getDataLength()) << endl;
						if(allocWsData) {
							delete [] ws_data;
						}
						cout << "------" << endl;
					}
				}
			} else {
				if(sverb.ssldecode) {
					hexdump(data, dataLength);
					cout << "---" << endl;
					cout << string((char*)data, dataLength) << endl;
				}
			}
			if(data) {
				if(tcp) {
					pcap_pkthdr *tcpHeader;
					u_char *tcpPacket;
					createSimpleTcpDataPacket(ethHeaderLength, &tcpHeader,  &tcpPacket,
								  ethHeader, data, dataLength,
								  _ip_src, _ip_dst, _port_src, _port_dst,
								  dataItem->getSeq(), dataItem->getAck(), 
								  dataItem->getTime().tv_sec, dataItem->getTime().tv_usec, dlt);
					unsigned dataOffset = ethHeaderLength + sizeof(iphdr2) + ((tcphdr2*)(tcpPacket + ethHeaderLength + sizeof(iphdr2)))->doff * 4;
					preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
						true, 
						#if USE_PACKET_NUMBER
						0, 
						#endif
						_ip_src, _port_src, _ip_dst, _port_dst, 
						dataLength, dataOffset,
						handle_index, tcpHeader, tcpPacket, true, 
						2, false, (iphdr2*)(tcpPacket + ethHeaderLength),
						NULL, 0, dlt, sensor_id, sensor_ip,
						false);
				} else {
					pcap_pkthdr *udpHeader;
					u_char *udpPacket;
					createSimpleUdpDataPacket(ethHeaderLength, &udpHeader,  &udpPacket,
								  ethHeader, data, dataLength,
								  _ip_src, _ip_dst, _port_src, _port_dst,
								  dataItem->getTime().tv_sec, dataItem->getTime().tv_usec);
					preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
						true, 
						#if USE_PACKET_NUMBER
						0,
						#endif
						_ip_src, _port_src, _ip_dst, _port_dst, 
						dataLength, ethHeaderLength + sizeof(iphdr2) + sizeof(udphdr2),
						handle_index, udpHeader, udpPacket, true, 
						false, false, (iphdr2*)(udpPacket + ethHeaderLength),
						NULL, 0, dlt, sensor_id, sensor_ip,
						false);
				}
				if(allocData) {
					delete [] data;
				}
			}
		}
	}
	delete data;
}
 
void SslData::printContentSummary() {
}


bool checkOkSslData(u_char *data, u_int32_t datalen) {
	if(!data) {
		return(false);
	}
	u_int32_t offset = 0;
	u_int32_t len;
	while(offset < datalen &&
	      datalen - offset >= 5 &&
	      (len = _checkOkSslData(data + offset, datalen - offset)) > 0) {
		offset += len;
		if(offset == datalen) {
			return(true);
		}
	}
	return(false);
}

u_int32_t _checkOkSslData(u_char *data, u_int32_t datalen) {
	if(!data) {
		return(false);
	}
	SslData::SslHeader header(data, datalen);
	return(header.length && (u_int32_t)header.length + header.getDataOffsetLength() <= datalen ? header.length + header.getDataOffsetLength() : 0);
}

bool checkOkSslHeader(u_char *data, u_int32_t datalen) {
	if(!data || datalen < 5) {
		return(false);
	}
	SslData::SslHeader header(data, datalen);
	return(header.isOk());
}


bool isSslIpPort(u_int32_t ip, u_int16_t port) {
	map<d_u_int32_t, string>::iterator iter = ssl_ipport.find(d_u_int32_t(ip, port));
	return(iter != ssl_ipport.end());
}
