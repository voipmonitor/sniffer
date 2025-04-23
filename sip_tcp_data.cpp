#include <iomanip>

#include "sip_tcp_data.h"
#include "sniff_proc_class.h"
#include "sql_db.h"


using namespace std;


extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];


SipTcpData::SipTcpData() {
	this->counterProcessData = 0;
	this->last_cache_time_cleanup = 0;
	this->_sync_cache = 0;
}

SipTcpData::~SipTcpData() {
	map<Cache_id, Cache_data*>::iterator iter;
	for(iter = cache.begin(); iter != cache.end(); iter++) {
		delete iter->second;
	}
}

void SipTcpData::processData(vmIP ip_src, vmIP ip_dst,
			     vmPort port_src, vmPort port_dst,
			     TcpReassemblyData *data,
			     u_char *ethHeader, u_int32_t ethHeaderLength,
			     u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			     void *uData, void *uData2, void *uData2_last, TcpReassemblyLink *reassemblyLink,
			     std::ostream *debugStream) {
	++this->counterProcessData;
	if(debugStream) {
		(*debugStream) << "### SipData::processData " << this->counterProcessData << endl;
	}
	u_int64_t cache_time = 0;
	for(size_t i_data = 0; i_data < data->data.size(); i_data++) {
		TcpReassemblyDataItem *dataItem = &data->data[i_data];
		list<d_u_int32_t> sip_offsets;
		if(!dataItem->getData()) {
			continue;
		}
		for(list<d_u_int32_t>::iterator iter_sip_offset = reassemblyLink->getSipOffsets()->begin(); iter_sip_offset != reassemblyLink->getSipOffsets()->end(); iter_sip_offset++) {
			if((*iter_sip_offset)[0] + (*iter_sip_offset)[1] > dataItem->getDatalen()) {
				break;
			}
			cache_time = dataItem->getTimeMS();
			string md5_data = GetDataMD5(dataItem->getData() + (*iter_sip_offset)[0], (*iter_sip_offset)[1]);
			Cache_id cache_id(ip_src, ip_dst, port_src, port_dst, dataItem->getAck(), dataItem->getSeq());
			lock_cache();
			map<Cache_id, Cache_data*>::iterator cache_iterator = cache.find(cache_id);
			if(cache_iterator != cache.end()) {
				Cache_data *cache_data = cache_iterator->second;
				map<string, u_int64_t>::iterator cache_data_iterator = cache_data->data.find(md5_data);
				if(cache_data_iterator != cache_data->data.end()) {
					if(cache_data_iterator->second + 100 > (u_int64_t)cache_time) {
						cache_data_iterator->second = cache_time;
						unlock_cache();
						continue;
					}
				} else {
					cache_data->data[md5_data] = cache_time;
				}
			} else {
				Cache_data *cache_data = new FILE_LINE(0) Cache_data;
				cache_data->data[md5_data] = cache_time;
				cache[cache_id] = cache_data;
			}
			unlock_cache();
			if(debugStream) {
				(*debugStream)
					<< "### "
					<< fixed
					<< setw(15) << ip_src.getString()
					<< " / "
					<< setw(5) << port_src
					<< (dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? " --> " : " <-- ")
					<< setw(15) << ip_dst.getString()
					<< " / "
					<< setw(5) << port_dst
					<< "  len: " << setw(4) << (*iter_sip_offset)[1];
				u_int32_t ack = dataItem->getAck();
				if(ack) {
					(*debugStream) << "  ack: " << setw(5) << ack;
				}
				(*debugStream) << endl;
				string _data;
				char  *_data_src = (char*)(dataItem->getData() + (*iter_sip_offset)[0]);
				unsigned _datalen = (*iter_sip_offset)[1];
				if(_datalen) {
					char *__data = new FILE_LINE(0) char[_datalen + 1];
					memcpy_heapsafe(__data, __data,
							_data_src, NULL,
							_datalen, 
							__FILE__, __LINE__);
					__data[_datalen] = 0;
					_data = __data;
					delete [] __data;
					_data = _data.substr(0, 5000);
					for(size_t i = 0; i < _data.length(); i++) {
						if(_data[i] == 13 || _data[i] == 10) {
							_data[i] = '\\';
						}
						if(_data[i] < 32) {
							_data.resize(i);
						}
					}
				}
				(*debugStream)
					<< "### " << _data << endl;
			}
			pcap_pkthdr *tcpHeader;
			u_char *tcpPacket;
			vmIP _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
			vmIP _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
			vmPort _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
			vmPort _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
			u_char *_data = dataItem->getData() + (*iter_sip_offset)[0];
			unsigned int _datalen = (*iter_sip_offset)[1];
			while(_datalen >= 1 && (_data[0] == '\r' || _data[0] == '\n')) {
				_data += 1;
				_datalen -= 1;
			}
			if(_datalen > 0) {
				#if DEBUG_PACKET_COUNT
				extern void __ftcp_sip(const char *callid, const char *req, const char *stat);
				extern char * gettag_ext(const void *ptr, unsigned long len, ParsePacket::ppContentsX *parseContents,
							 const char *tag, unsigned long *gettaglen, unsigned long *limitLen);
				unsigned long callid_length;
				char *callid = gettag_ext(_data, _datalen, NULL,
							  "\nCall-ID:", &callid_length, NULL);
				unsigned long cseq_length;
				char *cseq = gettag_ext(_data, _datalen, NULL,
							"\nCSeq:", &cseq_length, NULL);
				if(callid && cseq) {
					const char *first_cr = strnchr((char*)_data, '\r', _datalen);
					if(first_cr) {
						string req_stat = string((char*)_data, (u_char*)first_cr - _data);
						__ftcp_sip(string(callid, callid_length).c_str(), 
							   req_stat.substr(0, 3) == "SIP" ? "" : req_stat.c_str(), 
							   req_stat.substr(0, 3) == "SIP" ? req_stat.c_str() : "");
						extern cWsCalls *ws_calls;
						if(ws_calls) {
							ws_calls->setConfirm(string(callid, callid_length).c_str(),
									     req_stat.substr(0, 3) != "SIP",
									     req_stat.c_str(),
									     string(cseq, cseq_length).c_str());
						}
					}
				}
				#endif
				createSimpleTcpDataPacket(ethHeaderLength, &tcpHeader,  &tcpPacket,
							  ethHeader, _data, _datalen, 0,
							  _ip_src, _ip_dst, _port_src, _port_dst,
							  dataItem->getSeq(), dataItem->getAck(), 0,
							  dataItem->getTime().tv_sec, dataItem->getTime().tv_usec, dlt);
				unsigned iphdrSize = ((iphdr2*)(tcpPacket + ethHeaderLength))->get_hdr_size();
				unsigned dataOffset = ethHeaderLength + 
						      iphdrSize +
						      ((tcphdr2*)(tcpPacket + ethHeaderLength + iphdrSize))->doff * 4;
				if(uData) {
					packet_s_process *packetS = PACKET_S_PROCESS_SIP_CREATE();
					#if USE_PACKET_NUMBER
					packetS->packet_number = 0;
					#endif
					#if not EXPERIMENTAL_PACKETS_WITHOUT_IP
					packetS->_saddr = _ip_src;
					packetS->_daddr = _ip_dst; 
					#endif
					packetS->_source = _port_src;
					packetS->_dest = _port_dst;
					packetS->_datalen = _datalen; 
					packetS->_datalen_set = 0; 
					packetS->_dataoffset = dataOffset;
					packetS->handle_index = handle_index; 
					packetS->header_pt = tcpHeader;
					packetS->packet = tcpPacket; 
					packetS->_packet_alloc_type = _t_packet_alloc_header_std; 
					packetS->pflags.init();
					packetS->pflags.set_tcp(2);
					packetS->header_ip_offset = ethHeaderLength; 
					#if not NOT_USE_SEPARATE_TIME_US
					packetS->time_us = ::getTimeUS(tcpHeader);
					#endif
					packetS->block_store = NULL; 
					packetS->block_store_index =  0; 
					packetS->dlt = dlt; 
					packetS->sensor_id_u = (u_int16_t)sensor_id;
					packetS->sensor_ip = sensor_ip;
					packetS->pid = pid;
					extern int opt_skinny;
					extern char *sipportmatrix;
					extern char *skinnyportmatrix;
					packetS->pflags.set_skinny(opt_skinny && (skinnyportmatrix[_port_src] || skinnyportmatrix[_port_dst]));
					extern int opt_mgcp;
					extern char *mgcp_gateway_tcp_portmatrix;
					extern char *mgcp_callagent_tcp_portmatrix;
					extern bool opt_enable_diameter;
					extern char *diameter_tcp_portmatrix;
					packetS->pflags.set_mgcp(opt_mgcp && (mgcp_gateway_tcp_portmatrix[_port_src] || mgcp_gateway_tcp_portmatrix[_port_dst] ||
									      mgcp_callagent_tcp_portmatrix[_port_src] || mgcp_callagent_tcp_portmatrix[_port_dst]));
					packetS->pflags.set_diameter(opt_enable_diameter && (diameter_tcp_portmatrix[_port_src] || diameter_tcp_portmatrix[_port_dst]));
					packetS->need_sip_process = !packetS->pflags.other_processing() &&
								    (sipportmatrix[_port_src] || sipportmatrix[_port_dst] ||
								     packetS->pflags.is_skinny() ||
								     packetS->pflags.is_mgcp() ||
								     packetS->pflags.is_diameter());
					packetS->init2();
					((PreProcessPacket*)uData)->process_parseSipDataExt(&packetS, (packet_s_process*)uData2_last);
					
					#if DEBUG_PACKET_COUNT
					extern volatile int __xc_reassembly[10];
					__SYNC_INC(__xc_reassembly[1]);
					#endif
					
				} else {
					packet_flags pflags;
					pflags.init();
					pflags.set_tcp(2);
					if(opt_t2_boost_direct_rtp) {
						sHeaderPacketPQout hp(tcpHeader, tcpPacket,
								      dlt, sensor_id, sensor_ip);
						preProcessPacket[PreProcessPacket::ppt_detach_x]->push_packet(
								ethHeaderLength, 0xFFFF,
								dataOffset, _datalen,
								_port_src, _port_dst,
								pflags,
								&hp,
								handle_index);
					} else {
						preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
								#if USE_PACKET_NUMBER
								0, 
								#endif
								_ip_src, _port_src, _ip_dst, _port_dst, 
								_datalen, dataOffset,
								handle_index, tcpHeader, tcpPacket, _t_packet_alloc_header_std, 
								pflags, (iphdr2*)(tcpPacket + ethHeaderLength), NULL,
								NULL, 0, dlt, sensor_id, sensor_ip, pid,
								false);
					}
				}
			}
		}
	}
	delete data;
	cleanupCache(cache_time);
}

void SipTcpData::cleanupCache(u_int64_t cache_time) {
	if(!last_cache_time_cleanup) {
		last_cache_time_cleanup = cache_time;
		return;
	}
	if(cache_time > last_cache_time_cleanup + 10000) {
		lock_cache();
		map<Cache_id, Cache_data*>::iterator cache_iterator;
		for(cache_iterator = cache.begin(); cache_iterator != cache.end(); ) {
			Cache_data *cache_data = cache_iterator->second;
			map<string, u_int64_t>::iterator cache_data_iterator;
			for(cache_data_iterator = cache_data->data.begin(); cache_data_iterator != cache_data->data.end(); ) {
				if(cache_data_iterator->second < cache_time - 5000) {
					cache_data->data.erase(cache_data_iterator++);
				} else {
					cache_data_iterator++;
				}
			}
			if(cache_data->data.size() == 0) {
				delete cache_data;
				cache.erase(cache_iterator++);
			} else {
				cache_iterator++;
			}
		}
		unlock_cache();
		last_cache_time_cleanup = cache_time;
	}
}
 
void SipTcpData::printContentSummary() {
}


int checkOkSipData(u_char *data, u_int32_t datalen, int8_t strict_mode, list<d_u_int32_t> *offsets, u_int32_t *datalen_used) {
	int _datalen_used;
	int rslt = TcpReassemblySip::checkSip(data, datalen, strict_mode, offsets, &_datalen_used);
	if(datalen_used) {
		while(_datalen_used < (int)datalen &&
		      (data[_datalen_used] == LF_CHAR ||
		       data[_datalen_used] == CR_CHAR)) {
			++_datalen_used;
		}
		*datalen_used = _datalen_used;
	}
	return(rslt);
}
