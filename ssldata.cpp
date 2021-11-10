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

#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)
extern void decrypt_ssl(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport);
#endif

extern map<vmIPport, string> ssl_ipport;
extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];


SslData::SslData() {
	this->counterProcessData = 0;
	this->counterDecryptData = 0;
}

SslData::~SslData() {
}

void SslData::processData(vmIP ip_src, vmIP ip_dst,
			  vmPort port_src, vmPort port_dst,
			  TcpReassemblyData *data,
			  u_char *ethHeader, u_int32_t ethHeaderLength,
			  u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			  void */*uData*/, void */*uData2*/, void */*uData2_last*/, TcpReassemblyLink *reassemblyLink,
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
		vmIP _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
		vmIP _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
		vmPort _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
		vmPort _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
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
				<< setw(15) << ip_src.getString()
				<< " / "
				<< setw(5) << port_src
				<< (dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? " --> " : " <-- ")
				<< setw(15) << ip_dst.getString()
				<< " / "
				<< setw(5) << port_dst
				<< "  len: " << setw(4) << dataItem->getDatalen();
			u_int32_t ack = dataItem->getAck();
			u_int32_t seq = dataItem->getSeq();
			if(ack) {
				(*debugStream) << "  ack: " << setw(5) << ack;
			}
			if(seq) {
				(*debugStream) << "  seq: " << setw(5) << seq;
			}
			(*debugStream) << endl;
		}
		vector<string> rslt_decrypt;
		bool ok_first_ssl_header = false;
		u_char *ssl_data;
		u_int32_t ssl_datalen;
		bool alloc_ssl_data = false;
		bool exists_remain_data = reassemblyLink->existsRemainData(dataItem->getDirection());
		bool ignore_remain_data = false;
		if(exists_remain_data) {
			u_int32_t remain_data_items = reassemblyLink->getRemainDataItems(dataItem->getDirection());
			for(u_int32_t skip_first_remain_data_items = 0; skip_first_remain_data_items < remain_data_items; skip_first_remain_data_items++) {
				if(alloc_ssl_data) {
					delete [] ssl_data;
					alloc_ssl_data = false;
				}
				u_int32_t remain_data_length = reassemblyLink->getRemainDataLength(dataItem->getDirection(), skip_first_remain_data_items);
				ssl_datalen = remain_data_length + dataItem->getDatalen();
				ssl_data = reassemblyLink->completeRemainData(dataItem->getDirection(), &ssl_datalen, dataItem->getAck(), dataItem->getSeq(), dataItem->getData(), dataItem->getDatalen(), skip_first_remain_data_items);
				alloc_ssl_data = true;
				SslHeader header(ssl_data, ssl_datalen);
				if(header.isOk() && header.length && (u_int32_t)header.length + header.getDataOffsetLength() <= ssl_datalen) {
					ok_first_ssl_header = true;
					if(debugStream) {
						(*debugStream) << "APPLY PREVIOUS REMAIN DATA: " << remain_data_length << endl;
					}
					break;
				}
			}
		}
		if(!ok_first_ssl_header) {
			if(alloc_ssl_data) {
				delete [] ssl_data;
				alloc_ssl_data = false;
			}
			ssl_data = dataItem->getData();
			ssl_datalen = dataItem->getDatalen();
			SslHeader header(ssl_data, ssl_datalen);
			if(header.isOk() && header.length && (u_int32_t)header.length + header.getDataOffsetLength() <= ssl_datalen) {
				ok_first_ssl_header = true;
				if(exists_remain_data) {
					ignore_remain_data = true;
				}
			}
		}
		if(ok_first_ssl_header) {
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
						#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)
						decrypt_ssl(&rslt_decrypt_part, (char*)(ssl_data + ssl_data_offset), header.length + header.getDataOffsetLength(), htonl(_ip_src), htonl(_ip_dst), _port_src, _port_dst);
						#endif
					} else {
						decrypt_ssl_dssl(&rslt_decrypt_part, (char*)(ssl_data + ssl_data_offset), header.length + header.getDataOffsetLength(), _ip_src, _ip_dst, _port_src, _port_dst, dataItem->getTime(), ignore_remain_data);
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
			if(exists_remain_data) {
				reassemblyLink->clearRemainData(dataItem->getDirection());
				if(debugStream) {
					(*debugStream) << "CLEAR REMAIN DATA" << endl;
				}
			}
			if(ssl_data_offset < ssl_datalen) {
				reassemblyLink->addRemainData(dataItem->getDirection(), dataItem->getAck(), dataItem->getSeq(), ssl_data + ssl_data_offset, ssl_datalen - ssl_data_offset);
				if(debugStream) {
					(*debugStream) << "SET REMAIN DATA: " << (ssl_datalen - ssl_data_offset) << endl;
				}
			}
		} else {
			reassemblyLink->addRemainData(dataItem->getDirection(), dataItem->getAck(), dataItem->getSeq(), ssl_data, ssl_datalen);
			if(debugStream) {
				(*debugStream) << (exists_remain_data ? "ADD" : "SET") << " REMAIN DATA: " << ssl_datalen << endl;
			}
		}
		if(alloc_ssl_data) {
			delete [] ssl_data;
		}
		/* old version
		for(int pass = 0; pass < 2; pass++) {
			u_char *ssl_data;
			u_int32_t ssl_datalen;
			bool alloc_ssl_data = false;
			if(reassemblyLink->existsRemainData(dataItem->getDirection())) {
				ssl_datalen = reassemblyLink->getRemainDataLength(dataItem->getDirection()) + dataItem->getDatalen();
				ssl_data = reassemblyLink->completeRemainData(dataItem->getDirection(), &ssl_datalen, dataItem->getAck(), dataItem->getSeq(), dataItem->getData(), dataItem->getDatalen());
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
						#if defined(HAVE_LIBGNUTLS) and defined(HAVE_SSL_WS)
						decrypt_ssl(&rslt_decrypt_part, (char*)(ssl_data + ssl_data_offset), header.length + header.getDataOffsetLength(), htonl(_ip_src), htonl(_ip_dst), _port_src, _port_dst);
						#endif
					} else {
						decrypt_ssl_dssl(&rslt_decrypt_part, (char*)(ssl_data + ssl_data_offset), header.length + header.getDataOffsetLength(), _ip_src, _ip_dst, _port_src, _port_dst, dataItem->getTime(),
								 pass == 1);
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
				if(reassemblyLink->existsRemainData(dataItem->getDirection()) &&
				   !ssl_data_offset &&
				   (!checkOkSslHeader(dataItem->getData(), dataItem->getDatalen()) || 
				    _checkOkSslData(dataItem->getData(), dataItem->getDatalen()))) {
					// next pass with ignore remainData
					reassemblyLink->clearRemainData(dataItem->getDirection());
					if(debugStream) {
						(*debugStream) << "SKIP REMAIN DATA" << endl;
					}
				} else {
					if(ssl_data_offset < ssl_datalen) {
						reassemblyLink->clearRemainData(dataItem->getDirection());
						reassemblyLink->addRemainData(dataItem->getDirection(), dataItem->getAck(), dataItem->getSeq(), ssl_data + ssl_data_offset, ssl_datalen - ssl_data_offset);
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
		*/
		for(size_t i = 0; i < rslt_decrypt.size(); i++) {
			if(debugStream) {
				string out(rslt_decrypt[i], 0,100);
				std::replace(out.begin(), out.end(), '\n', ' ');
				std::replace(out.begin(), out.end(), '\r', ' ');
				if(out.length()) {
					(*debugStream) << "TS: " << dataItem->getTime().tv_sec << "." << dataItem->getTime().tv_usec << " " << _ip_src.getString() << " -> " << _ip_dst.getString() << " SIP " << rslt_decrypt[i].length() << " " << out << endl;
				}
				++this->counterDecryptData;
				(*debugStream) << "DECRYPT DATA " << this->counterDecryptData << " : " << rslt_decrypt[i] << endl;
			}
			if(!ethHeader || !ethHeaderLength) {
				continue;
			}
			string dataComb;
			bool dataCombUse = false;
			if(i < rslt_decrypt.size() - 1 && rslt_decrypt[i].length() == 1) {
				dataComb = rslt_decrypt[i] + rslt_decrypt[i + 1];
				if(check_sip20((char*)dataComb.c_str(), dataComb.length(), NULL, true) ||
				   check_websocket((char*)dataComb.c_str(), dataComb.length(), cWebSocketHeader::_chdst_na)) {
					dataCombUse = true;
				}
			}
			u_char *data = NULL;
			unsigned dataLength = 0;
			ReassemblyBuffer::eType dataType = ReassemblyBuffer::_na;
			if(dataCombUse) {
				data = (u_char*)dataComb.c_str();
				dataLength = dataComb.size();
				++i;
			} else {
				data = (u_char*)rslt_decrypt[i].c_str();
				dataLength = rslt_decrypt[i].size();
			}
			/* diagnosis of bad length websocket data
			if(check_websocket(data, dataLength, cWebSocketHeader::_chdst_na) &&
			   !check_websocket(data, dataLength, cWebSocketHeader::_chdst_strict)) {
				print_websocket_check((char*)data, dataLength);
			}
			*/
			if(check_websocket(data, dataLength)) {
				dataType = ReassemblyBuffer::_websocket;
			} else if(check_websocket(data, dataLength, cWebSocketHeader::_chdst_na) || 
				  (dataLength < websocket_header_length((char*)data, dataLength) && check_websocket_first_byte(data, dataLength))) {
				dataType = ReassemblyBuffer::_websocket_incomplete;
			} else if(check_sip20((char*)data, dataLength, NULL, false)) {
				if(TcpReassemblySip::_checkSip(data, dataLength, false)) {
					dataType = ReassemblyBuffer::_sip;
				} else {
					dataType = ReassemblyBuffer::_sip_incomplete;
				}
			}
			list<ReassemblyBuffer::sDataRslt> dataRslt;
			reassemblyBuffer.cleanup(dataItem->getTime(), &dataRslt);
			bool doProcessPacket = false;
			bool createStream = false;
			if(reassemblyBuffer.existsStream(_ip_src, _port_src, _ip_dst, _port_dst)) {
				doProcessPacket = true;
				createStream = false;
			} else {
				if(dataType == ReassemblyBuffer::_websocket_incomplete ||
				   dataType == ReassemblyBuffer::_sip_incomplete) {
					doProcessPacket = true;
					createStream = true;
				}
			}
			if(doProcessPacket) {
				reassemblyBuffer.processPacket(ethHeader, ethHeaderLength,
							       _ip_src, _port_src, _ip_dst, _port_dst,
							       dataType, data, dataLength, createStream, 
							       dataItem->getTime(), dataItem->getAck(), dataItem->getSeq(),
							       handle_index, dlt, sensor_id, sensor_ip, pid,
							       &dataRslt);
			}
			if(dataRslt.size()) {
				for(list<ReassemblyBuffer::sDataRslt>::iterator iter = dataRslt.begin(); iter != dataRslt.end(); iter++) {
					processPacket(&(*iter));
				}
			}
			if(!doProcessPacket) {
				processPacket(ethHeader, ethHeaderLength, false,
					      data, dataLength, dataType, false,
					      _ip_src, _ip_dst, _port_src, _port_dst,
					      dataItem->getTime(), dataItem->getAck(), dataItem->getSeq(),
					      handle_index, dlt, sensor_id, sensor_ip, pid);
			}
		}
	}
	delete data;
}
 
void SslData::printContentSummary() {
}

void SslData::processPacket(u_char *ethHeader, unsigned ethHeaderLength, bool ethHeaderAlloc,
			    u_char *data, unsigned dataLength, ReassemblyBuffer::eType dataType, bool dataAlloc,
			    vmIP ip_src, vmIP ip_dst, vmPort port_src, vmPort port_dst,
			    timeval time, u_int32_t ack, u_int32_t seq,
			    u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid) {
	if(sverb.ssldecode) {
		hexdump(data, dataLength);
		cout << "---" << endl;
		if(dataType == ReassemblyBuffer::_websocket) {
			cWebSocketHeader ws(data, dataLength);
			bool allocWsData;
			u_char *ws_data = ws.decodeData(&allocWsData);
			cout << string((char*)ws_data, ws.getDataLength()) << endl;
			if(allocWsData) {
				delete [] ws_data;
			}
		} else {
			cout << string((char*)data, dataLength) << endl;
		}
		cout << "------" << endl;
	}
	if(dataType == ReassemblyBuffer::_websocket) {
		pcap_pkthdr *tcpHeader;
		u_char *tcpPacket;
		createSimpleTcpDataPacket(ethHeaderLength, &tcpHeader,  &tcpPacket,
					  ethHeader, data, dataLength,
					  ip_src, ip_dst, port_src, port_dst,
					  seq, ack, 
					  time.tv_sec, time.tv_usec, dlt);
		unsigned iphdrSize = ((iphdr2*)(tcpPacket + ethHeaderLength))->get_hdr_size();
		unsigned dataOffset = ethHeaderLength + 
				      iphdrSize +
				      ((tcphdr2*)(tcpPacket + ethHeaderLength + iphdrSize))->doff * 4;
		packet_flags pflags;
		pflags.init();
		pflags.tcp = 2;
		pflags.ssl = true;
		preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
			#if USE_PACKET_NUMBER
			0, 
			#endif
			ip_src, port_src, ip_dst, port_dst, 
			dataLength, dataOffset,
			handle_index, tcpHeader, tcpPacket, true, 
			pflags, (iphdr2*)(tcpPacket + ethHeaderLength), (iphdr2*)(tcpPacket + ethHeaderLength),
			NULL, 0, dlt, sensor_id, sensor_ip, pid,
			false);
	} else {
		pcap_pkthdr *udpHeader;
		u_char *udpPacket;
		createSimpleUdpDataPacket(ethHeaderLength, &udpHeader,  &udpPacket,
					  ethHeader, data, dataLength,
					  ip_src, ip_dst, port_src, port_dst,
					  time.tv_sec, time.tv_usec);
		unsigned iphdrSize = ((iphdr2*)(udpPacket + ethHeaderLength))->get_hdr_size();
		unsigned dataOffset = ethHeaderLength + 
				      iphdrSize + 
				      sizeof(udphdr2);
		packet_flags pflags;
		pflags.init();
		pflags.ssl = true;
		preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
			#if USE_PACKET_NUMBER
			0,
			#endif
			ip_src, port_src, ip_dst, port_dst, 
			dataLength, dataOffset,
			handle_index, udpHeader, udpPacket, true, 
			pflags, (iphdr2*)(udpPacket + ethHeaderLength), (iphdr2*)(udpPacket + ethHeaderLength),
			NULL, 0, dlt, sensor_id, sensor_ip, pid,
			false);
	}
	if(ethHeaderAlloc) {
		delete [] ethHeader;
	}
	if(dataAlloc) {
		delete [] data;
	}
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


bool isSslIpPort(vmIP ip, vmPort port) {
	map<vmIPport, string>::iterator iter = ssl_ipport.find(vmIPport(ip, port));
	return(iter != ssl_ipport.end());
}
