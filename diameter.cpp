#include "diameter.h"

#include "sniff_proc_class.h"


DiameterTcpData::DiameterTcpData() {
}

DiameterTcpData::~DiameterTcpData() {
}

void DiameterTcpData::processData(vmIP ip_src, vmIP ip_dst,
				  vmPort port_src, vmPort port_dst,
				  TcpReassemblyData *data,
				  u_char *ethHeader, u_int32_t ethHeaderLength,
				  u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
				  void *uData, void */*uData2*/, void *uData2_last, TcpReassemblyLink */*reassemblyLink*/,
				  std::ostream */*debugStream*/) {
	for(size_t i_data = 0; i_data < data->data.size(); i_data++) {
		TcpReassemblyDataItem *dataItem = &data->data[i_data];
		if(!dataItem->getData()) {
			continue;
		}
		vmIP _ip_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_src : ip_dst;
		vmIP _ip_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? ip_dst : ip_src;
		vmPort _port_src = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_src : port_dst;
		vmPort _port_dst = dataItem->getDirection() == TcpReassemblyDataItem::DIRECTION_TO_DEST ? port_dst : port_src;
		pcap_pkthdr *tcpHeader;
		u_char *tcpPacket;
		createSimpleTcpDataPacket(ethHeaderLength, &tcpHeader,  &tcpPacket,
					  ethHeader, dataItem->getData(), dataItem->getDatalen(), 0,
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
			packetS->_datalen = dataItem->getDatalen(); 
			packetS->_datalen_set = 0; 
			packetS->_dataoffset = dataOffset;
			packetS->handle_index = handle_index; 
			packetS->header_pt = tcpHeader;
			packetS->packet = tcpPacket; 
			packetS->_packet_alloc = true; 
			packetS->pflags.init();
			packetS->pflags.tcp = 2;
			packetS->header_ip_offset = ethHeaderLength; 
			packetS->block_store = NULL; 
			packetS->block_store_index =  0; 
			packetS->dlt = dlt; 
			packetS->sensor_id_u = (u_int16_t)sensor_id;
			packetS->sensor_ip = sensor_ip;
			packetS->pid = pid;
			packetS->pflags.diameter = true;
			packetS->need_sip_process = true;
			packetS->init2();
			((PreProcessPacket*)uData)->process_diameterExt(&packetS, (packet_s_process*)uData2_last);
		}
	}
	delete data;
}

bool checkOkDiameter(u_char *data, u_int32_t datalen) {
	if(datalen > 0 &&data[0] == DIAMETER_VERSION_1) {
		 cDiameter diameter(data, datalen);
		 return(diameter.versionIsOk() &&
			diameter.headerLengthIsOk() &&
			diameter.lengthIsOk());
	}
	return(false);
}

cDiameterAvpDataItem::cDiameterAvpDataItem() {
	code = 0;
	length = 0;
	payload = NULL;
}

cDiameterAvpDataItem::~cDiameterAvpDataItem() {
	if(payload) {
		delete payload;
	}
}

cDiameterAvpDataItems::cDiameterAvpDataItems() {
}

cDiameterAvpDataItems::~cDiameterAvpDataItems() {
	for(list<cDiameterAvpDataItem*>::iterator iter = items.begin(); iter != items.end(); iter++) {
		delete *iter;
	}
}

void cDiameterAvpDataItems::push(cDiameterAvpDataItem *dataItem) {
	items.push_back(dataItem);
}

void cDiameterAvpDataItems::print() {
	for(list<cDiameterAvpDataItem*>::iterator iter = items.begin(); iter != items.end(); iter++) {
		cDiameterAvpDataItem *dataItem = *iter;
		cout << " * " << dataItem->code << " " << dataItem->length << endl;
		hexdump(dataItem->payload->data(), dataItem->payload->size());
	}
}

cDiameterAvp::cDiameterAvp(u_char *data, unsigned datalen) {
	this->data = data;
	this->datalen = datalen;
}

void cDiameterAvp::parse(cDiameterAvpDataItems *dataItems) {
	if(isGroup()) {
		u_int32_t group_payload_len = this->payload_len();
		if(group_payload_len > 0) {
			u_char *group_payload = this->payload();
			u_int32_t offset = 0;
			while(offset < group_payload_len && (group_payload_len - offset) > sizeof(cDiameterAvp::sHeader)) {
				cDiameterAvp avp(group_payload + offset, group_payload_len - offset);
				if(avp.lengthIsOk()) {
					avp.parse(dataItems);
					offset += avp.real_length();
				} else {
					break;
				}
			}
		}
	} else {
		u_int32_t payload_len = this->payload_len();
		if(payload_len > 0) {
			u_char *payload = this->payload();
			cDiameterAvpDataItem *dataItem = new FILE_LINE(0) cDiameterAvpDataItem;
			dataItem->code = code(); 
			dataItem->length = payload_len;
			dataItem->payload = new FILE_LINE(0) SimpleBuffer(payload, payload_len);
			dataItems->push(dataItem);
		}
	}
}

u_int32_t cDiameterAvp::code() {
	return(ntohl(((sHeader*)data)->code));
}

u_int8_t cDiameterAvp::flags() {
	return(((sHeader*)data)->flags);
}

u_int32_t cDiameterAvp::header_length() {
	return(sizeof(sHeader) + ((flags() & _flag_vendor) ? sizeof(u_int32_t) : 0));
}

u_int32_t cDiameterAvp::length() {
	u_int32_t length = ((sHeader*)data)->length << 8;
	return(ntohl(length));
}

u_int32_t cDiameterAvp::real_length() {
	u_int32_t length = this->length();
	return(length / 4 * 4 + (length % 4 ? 4 : 0));
}

u_int32_t cDiameterAvp::vendor_id() {
	if(flags() & _flag_vendor) {
		return(ntohl(*(u_int32_t*)data + sizeof(sHeader)));
	}
	return(0);
}

u_char *cDiameterAvp::payload() {
	return(data + header_length());
}

u_int32_t cDiameterAvp::payload_len() {
	u_int32_t length = this->length();
	u_int32_t header_length = this->header_length();
	return(length > header_length ? length - header_length : 0);
}

bool cDiameterAvp::isGroup() {
	u_int32_t code = this->code();
	return(code == 651 || code == 700);
}

bool cDiameterAvp::headerLengthIsOk() {
	return(datalen >= sizeof(sHeader) && datalen >= header_length());
}

bool cDiameterAvp::lengthIsOk() {
	return(headerLengthIsOk() &&
	       real_length() <= datalen);
}

cDiameter::cDiameter(u_char *data, unsigned datalen) {
	this->data = data;
	this->datalen = datalen;
}

string cDiameter::getPublicIdentity(cDiameterAvpDataItems *dataItems) {
	string rslt;
	bool allocDataItems = false;
	if(!dataItems) {
		allocDataItems = true;
		dataItems = new FILE_LINE(0) cDiameterAvpDataItems;
		parse(dataItems);
	}
	for(list<cDiameterAvpDataItem*>::iterator iter = dataItems->items.begin(); iter != dataItems->items.end(); iter++) {
		if((*iter)->code == 601 && (*iter)->length > 0) {
			rslt = (char*)(*((*iter)->payload));
			break;
		}
	}
	if(allocDataItems) {
		delete dataItems;
	}
	return(rslt);
}

void cDiameter::parse(cDiameterAvpDataItems *dataItems) {
	u_char *payload = this->payload();
	u_int32_t payload_len = this->payload_len();
	u_int32_t offset = 0;
	while(offset < payload_len && (payload_len - offset) > sizeof(cDiameterAvp::sHeader)) {
		cDiameterAvp avp(payload + offset, payload_len - offset);
		if(avp.lengthIsOk()) {
			avp.parse(dataItems);
			offset += avp.real_length();
		} else {
			break;
		}
	}
}

u_int8_t cDiameter::version() {
	return(((sHeader*)data)->version);
}

u_int32_t cDiameter::length() {
	u_int32_t length = ((sHeader*)data)->length << 8;
	return(ntohl(length));
}

u_int8_t cDiameter::flags() {
	return(((sHeader*)data)->flags);
}

u_int32_t cDiameter::command_code() {
	u_int32_t command_code = ((sHeader*)data)->command_code << 8;
	return(ntohl(command_code));
}

u_int32_t cDiameter::application_id() {
	return(ntohl(((sHeader*)data)->application_id));
}

u_int32_t cDiameter::hop_by_hop_id() {
	return(ntohl(((sHeader*)data)->hop_by_hop_id));
}

u_int32_t cDiameter::end_to_end_id() {
	return(ntohl(((sHeader*)data)->end_to_end_id));
}

u_char *cDiameter::payload() {
	return(data + sizeof(sHeader));
}

u_int32_t cDiameter::payload_len() {
	return(length() - sizeof(sHeader));
}

bool cDiameter::isRequest() {
	return(flags() & _flag_request);
}

bool cDiameter::versionIsOk() {
	return(datalen > 0 && data[0] == DIAMETER_VERSION_1);
}

bool cDiameter::headerLengthIsOk() {
	return(datalen >= sizeof(sHeader));
}

bool cDiameter::lengthIsOk() {
	return(headerLengthIsOk() &&
	       length() <= datalen);
}


void cDiameterPacketStack::sPacket::destroy_packet() {
	packet_s_process *packetS = (packet_s_process*)packet;
	PACKET_S_PROCESS_DESTROY(&packetS);
}

cDiameterPacketStack::cQueuePackets::cQueuePackets() {
	confirmed = false;
}

void cDiameterPacketStack::cQueuePackets::add(void *packet, bool is_request, u_int32_t hbh_id, u_int64_t time_us) {
	sPacket packet_q;
	packet_q.packet = packet;
	packet_q.is_request = is_request;
	packet_q.hbh_id = hbh_id;
	packet_q.time_us = time_us;
	packets.push_back(packet_q);
}

unsigned cDiameterPacketStack::cQueuePackets::age_s(u_int64_t time_us) {
	return(packets.size() && packets.begin()->time_us < time_us ?
		TIME_US_TO_S(time_us - packets.begin()->time_us) :
		0);
}

void cDiameterPacketStack::cQueuePackets::destroy_packets() {
	for(list<sPacket>::iterator iter = packets.begin(); iter != packets.end(); iter++) {
		iter->destroy_packet();
	}
}

cDiameterPacketStack::cDiameterPacketStack() {
	age_expiration_s = 60;
	cleanup_period_s = 120;
	last_cleanup_s = 0;
	_sync_lock = 0;
}

cDiameterPacketStack::~cDiameterPacketStack() {
	for(map<string, cQueuePackets*>::iterator iter_qp = packet_stack.begin(); iter_qp != packet_stack.end(); iter_qp++) {
		cQueuePackets *qp = iter_qp->second;
		qp->destroy_packets();
		delete qp;
	}
}

bool cDiameterPacketStack::add(void *packet, bool is_request, u_int32_t hbh_id, const char *public_identity, u_int64_t time_us) {
	bool rslt = false;
	lock();
	cQueuePackets *qp = NULL;
	if(is_request) {
		hbh_id_to_public_identity[hbh_id] = public_identity;
		map<string, cQueuePackets*>::iterator iter_qp = packet_stack.find(public_identity);
		if(iter_qp != packet_stack.end()) {
			qp = iter_qp->second;
		} else {
			qp = new FILE_LINE(0) cQueuePackets;
			qp->public_identity = public_identity;
			packet_stack[public_identity] = qp;
		}
	} else {
		map<u_int32_t, string>::iterator iter_hbh = hbh_id_to_public_identity.find(hbh_id);
		if(iter_hbh != hbh_id_to_public_identity.end()) {
			map<string, cQueuePackets*>::iterator iter_qp = packet_stack.find(iter_hbh->second);
			if(iter_qp != packet_stack.end()) {
				qp = iter_qp->second;
			}
		}
	}
	if(qp) {
		qp->add(packet, is_request, hbh_id, time_us);
		rslt = true;
	}
	unlock();
	if(!last_cleanup_s) {
		last_cleanup_s = TIME_US_TO_S(time_us);
	} else if(TIME_US_TO_S(time_us) > last_cleanup_s && (TIME_US_TO_S(time_us) - last_cleanup_s) > cleanup_period_s) {
		cleanup(time_us);
		last_cleanup_s = TIME_US_TO_S(time_us);
	}
	return(rslt);
}

bool cDiameterPacketStack::retrieve(const char *public_identity, list<sPacket> *packets) {
	bool rslt = false;
	lock();
	map<string, cQueuePackets*>::iterator iter_qp = packet_stack.find(public_identity);
	if(iter_qp != packet_stack.end()) {
		rslt = true;
		cQueuePackets *qp = iter_qp->second;
		for(list<sPacket>::iterator iter = qp->packets.begin(); iter != qp->packets.end(); iter++) {
			packets->push_back(*iter);
			hbh_id_to_public_identity.erase(iter->hbh_id);
		}
		packet_stack.erase(iter_qp);
		delete qp;
	}
	unlock();
	return(rslt);
}

bool cDiameterPacketStack::retrieve(list<string> *public_identity, list<sPacket> *packets) {
	int rslt = 0;
	for(list<string>::iterator iter = public_identity->begin(); iter != public_identity->end(); iter++) {
		if(retrieve(iter->c_str(), packets)) {
			++rslt;
		}
	}
	if(rslt > 1) {
		packets->sort();
	}
	return(rslt > 0);
}

bool cDiameterPacketStack::retrieve(list<string> *public_identity, cQueuePackets *packets) {
	return(retrieve(public_identity, &packets->packets));
}

void cDiameterPacketStack::cleanup(u_int64_t time_us) {
	if(!time_us) {
		time_us = getTimeUS();
	}
	lock();
	for(map<string, cQueuePackets*>::iterator iter_qp = packet_stack.begin(); iter_qp != packet_stack.end(); ) {
		bool destroy = false;
		unsigned age_s = iter_qp->second->age_s(time_us);
		extern int absolute_timeout;
		if(age_s > age_expiration_s) {
			if(!iter_qp->second->confirmed) {
				if(confirm_public_identity(iter_qp->first.c_str())) {
					iter_qp->second->confirmed = true;
				} else {
					destroy = true;
				}
			}
		} else if(age_s > (unsigned)absolute_timeout + 120) {
			destroy = true;
		}
		if(destroy) {
			cQueuePackets *qp = iter_qp->second;
			for(list<sPacket>::iterator iter = qp->packets.begin(); iter != qp->packets.end(); iter++) {
				hbh_id_to_public_identity.erase(iter->hbh_id);
			}
			qp->destroy_packets();
			delete qp;
			packet_stack.erase(iter_qp++);
			continue;
		} else {
			iter_qp++;
		}
	}
	unlock();
}

bool cDiameterPacketStack::confirm_public_identity(const char *public_identity) {
	extern Calltable *calltable;
	return(calltable->find_by_diameter_to_sip(public_identity) != NULL);
}
