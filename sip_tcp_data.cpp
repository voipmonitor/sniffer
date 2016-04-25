#include <iomanip>

#include "sip_tcp_data.h"
#include "sniff_proc_class.h"
#include "sql_db.h"


using namespace std;


extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end];


SipTcpData::SipTcpData() {
	this->counterProcessData = 0;
}

SipTcpData::~SipTcpData() {
}

void SipTcpData::processData(u_int32_t ip_src, u_int32_t ip_dst,
			     u_int16_t port_src, u_int16_t port_dst,
			     TcpReassemblyData *data,
			     u_char *ethHeader, u_int32_t ethHeaderLength,
			     u_int16_t handle_index, int dlt, int sensor_id, u_int32_t sensor_ip,
			     void *uData, TcpReassemblyLink *reassemblyLink,
			     bool debugSave) {
	++this->counterProcessData;
	if(debugSave) {
		cout << "### SipData::processData " << this->counterProcessData << endl;
	}
	for(size_t i_data = 0; i_data < data->data.size(); i_data++) {
		TcpReassemblyDataItem *dataItem = &data->data[i_data];
		if(!dataItem->getData()) {
			continue;
		}
		if(debugSave) {
			cout << "###"
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
				cout << "  ack: " << setw(5) << ack;
			}
			cout << endl;
		}
		pcap_pkthdr *tcpHeader;
		u_char *tcpPacket;
		u_int32_t _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
		u_int32_t _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
		u_int16_t _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
		u_int16_t _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
		ethHeaderLength = sizeof(ether_header);
		createSimpleTcpDataPacket(ethHeaderLength, &tcpHeader,  &tcpPacket,
					  ethHeader, dataItem->getData(), dataItem->getDatalen(),
					  _ip_src, _ip_dst, _port_src, _port_dst,
					  dataItem->getAck(), dataItem->getTime().tv_sec, dataItem->getTime().tv_usec);
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
			packetS->datalen = dataItem->getDatalen(); 
			packetS->dataoffset = dataOffset;
			packetS->handle_index = handle_index; 
			packetS->header_pt = tcpHeader;
			packetS->packet = tcpPacket; 
			packetS->_packet_alloc = true; 
			packetS->istcp = 2;
			packetS->header_ip_offset = ethHeaderLength; 
			packetS->block_store = NULL; 
			packetS->block_store_index =  0; 
			packetS->dlt = dlt; 
			packetS->sensor_id_u = (u_int16_t)sensor_id;
			packetS->sensor_ip = sensor_ip;
			packetS->is_ssl = false;
			extern int opt_skinny;
			extern char *sipportmatrix;
			packetS->is_skinny = opt_skinny && (_port_src == 2000 || _port_dst == 2000);
			packetS->is_need_sip_process = sipportmatrix[_port_src] || sipportmatrix[_port_dst] ||
						       packetS->is_skinny;
			packetS->init2();
			((PreProcessPacket*)uData)->process_parseSipDataExt(&packetS);
		} else {
			preProcessPacket[PreProcessPacket::ppt_extend]->push_packet(
					true, 0, _ip_src, _port_src, _ip_dst, _port_dst, 
					(char*)(tcpPacket + dataOffset), dataItem->getDatalen(), dataOffset,
					handle_index, tcpHeader, tcpPacket, true, 
					2, (iphdr2*)(tcpPacket + ethHeaderLength),
					NULL, 0, dlt, sensor_id, sensor_ip,
					false);
		}
	}
	delete data;
}
 
void SipTcpData::printContentSummary() {
}


bool checkOkSipData(u_char *data, u_int32_t datalen, bool strict) {
	return(TcpReassemblySip::checkSip(data, datalen, strict));
}
