#include <iomanip>

#include "sip_tcp_data.h"
#include "sniff_proc_class.h"
#include "sql_db.h"


using namespace std;


extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];


SipTcpData::SipTcpData() {
	this->counterProcessData = 0;
	this->last_cache_time_cleanup = 0;
}

SipTcpData::~SipTcpData() {
	map<Cache_id, Cache_data*>::iterator iter;
	for(iter = cache.begin(); iter != cache.end(); iter++) {
		delete iter->second;
	}
}

void SipTcpData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			     u_int16_t port_src, u_int16_t port_dst,
			     TcpReassemblyData *data,
			     u_char *ethHeader, u_int32_t ethHeaderLength,
			     u_int16_t handle_index, int dlt, int sensor_id, u_int32_t sensor_ip,
			     void *uData, TcpReassemblyLink *reassemblyLink,
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
			cache_time = dataItem->getTime().tv_sec * 1000 + dataItem->getTime().tv_usec / 1000;
			string md5_data = GetDataMD5(dataItem->getData() + (*iter_sip_offset)[0], (*iter_sip_offset)[1]);
			Cache_id cache_id(ip_src, ip_dst, port_src, port_dst);
			map<Cache_id, Cache_data*>::iterator cache_iterator = cache.find(cache_id);
			if(cache_iterator != cache.end()) {
				Cache_data *cache_data = cache_iterator->second;
				map<string, u_int64_t>::iterator cache_data_iterator = cache_data->data.find(md5_data);
				if(cache_data_iterator != cache_data->data.end()) {
					if(cache_data_iterator->second + 100 > (u_int64_t)cache_time) {
						cache_data_iterator->second = cache_time;
						continue;
					}
				} else {
					cache_data->data[md5_data] = cache_time;
				}
			} else {
				Cache_data *cache_data = new Cache_data;
				cache_data->data[md5_data] = cache_time;
				cache[cache_id] = cache_data;
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
					<< "  len: " << setw(4) << (*iter_sip_offset)[1];
				u_int32_t ack = dataItem->getAck();
				if(ack) {
					(*debugStream) << "  ack: " << setw(5) << ack;
				}
				(*debugStream) << endl;
			}
			pcap_pkthdr *tcpHeader;
			u_char *tcpPacket;
			u_int32_t _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
			u_int32_t _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
			u_int16_t _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
			u_int16_t _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
			u_char *_data = dataItem->getData() + (*iter_sip_offset)[0];
			unsigned int _datalen = (*iter_sip_offset)[1];
			while(_datalen >= 2 && _data[0] == '\r' && _data[1] == '\n') {
				_data += 2;
				_datalen -= 2;
			}
			if(_datalen > 0) {
				createSimpleTcpDataPacket(ethHeaderLength, &tcpHeader,  &tcpPacket,
							  ethHeader, _data, _datalen,
							  _ip_src, _ip_dst, _port_src, _port_dst,
							  dataItem->getSeq(), dataItem->getAck(), 
							  dataItem->getTime().tv_sec, dataItem->getTime().tv_usec, dlt);
				unsigned dataOffset = ethHeaderLength + sizeof(iphdr2) + ((tcphdr2*)(tcpPacket + ethHeaderLength + sizeof(iphdr2)))->doff * 4;
				if(uData) {
					packet_s_process *packetS = PACKET_S_PROCESS_SIP_CREATE();
					#if USE_PACKET_NUMBER
					packetS->packet_number = 0;
					#endif
					packetS->saddr = _ip_src;
					packetS->source = _port_src;
					packetS->daddr = _ip_dst; 
					packetS->dest = _port_dst;
					packetS->datalen = _datalen; 
					packetS->dataoffset = dataOffset;
					packetS->handle_index = handle_index; 
					packetS->header_pt = tcpHeader;
					packetS->packet = tcpPacket; 
					packetS->_packet_alloc = true; 
					packetS->istcp = 2;
					packetS->isother = 0;
					packetS->header_ip_offset = ethHeaderLength; 
					packetS->block_store = NULL; 
					packetS->block_store_index =  0; 
					packetS->dlt = dlt; 
					packetS->sensor_id_u = (u_int16_t)sensor_id;
					packetS->sensor_ip = sensor_ip;
					packetS->is_ssl = false;
					extern int opt_skinny;
					extern char *sipportmatrix;
					extern char *skinnyportmatrix;
					packetS->is_skinny = opt_skinny && (skinnyportmatrix[_port_src] || skinnyportmatrix[_port_dst]);
					extern int opt_mgcp;
					extern unsigned opt_tcp_port_mgcp_gateway;
					extern unsigned opt_tcp_port_mgcp_callagent;
					packetS->is_mgcp = opt_mgcp && (_port_src == opt_tcp_port_mgcp_gateway || _port_dst == opt_tcp_port_mgcp_gateway ||
									_port_src == opt_tcp_port_mgcp_callagent || _port_dst == opt_tcp_port_mgcp_callagent);
					packetS->is_need_sip_process = !packetS->isother &&
								       (sipportmatrix[_port_src] || sipportmatrix[_port_dst] ||
									packetS->is_skinny ||
									packetS->is_mgcp);
					packetS->init2();
					((PreProcessPacket*)uData)->process_parseSipDataExt(&packetS);
				} else {
					preProcessPacket[PreProcessPacket::ppt_extend]->push_packet(
							true, 
							#if USE_PACKET_NUMBER
							0, 
							#endif
							_ip_src, _port_src, _ip_dst, _port_dst, 
							_datalen, dataOffset,
							handle_index, tcpHeader, tcpPacket, true, 
							2, false, (iphdr2*)(tcpPacket + ethHeaderLength),
							NULL, 0, dlt, sensor_id, sensor_ip,
							false);
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
		last_cache_time_cleanup = cache_time;
	}
}
 
void SipTcpData::printContentSummary() {
}


bool checkOkSipData(u_char *data, u_int32_t datalen, bool strict, list<d_u_int32_t> *offsets) {
	return(TcpReassemblySip::checkSip(data, datalen, strict, offsets));
}
