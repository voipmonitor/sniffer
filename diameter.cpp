#include "diameter.h"

#include "sniff_proc_class.h"


extern bool opt_diameter_ignore_domain;
extern bool opt_diameter_ignore_prefix;
extern int opt_diameter_time_overlap;


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
			packetS->_packet_alloc_type = _t_packet_alloc_header_std; 
			packetS->pflags.init();
			packetS->pflags.tcp = 2;
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
		if(payload_len > 0 && payload_len < 16 * 1024) {
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
	return(code == 456 || code == 651 || code == 700 || code == 873 || code == 876);
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
	string publicIdentity = getValue(601, dataItems);
	if(!publicIdentity.empty()) {
		if(opt_diameter_ignore_domain) {
			size_t domainSeparatorPos = publicIdentity.find('@');
			if(domainSeparatorPos != string::npos && domainSeparatorPos > 0) {
				publicIdentity = publicIdentity.substr(0, domainSeparatorPos);
			}
		}
		if(opt_diameter_ignore_prefix) {
			size_t prefixSeparatorPos = publicIdentity.find(':');
			if(prefixSeparatorPos != string::npos && prefixSeparatorPos < publicIdentity.length() - 1) {
				publicIdentity = publicIdentity.substr(prefixSeparatorPos + 1);
			}
		}
		return(publicIdentity);
	}
	return("");
}

string cDiameter::getSessionId(cDiameterAvpDataItems *dataItems) {
	string sessionId = getValue(263, dataItems);
	if(!sessionId.empty()) {
		size_t lastSemicolonPos = sessionId.rfind(';');
		if(lastSemicolonPos != string::npos) {
			sessionId = sessionId.substr(lastSemicolonPos + 1);
		}
		if(opt_diameter_ignore_domain) {
			size_t domainSeparatorPos = sessionId.find('@');
			if(domainSeparatorPos != string::npos && domainSeparatorPos > 0) {
				sessionId = sessionId.substr(0, domainSeparatorPos);
			}
		}
		if(opt_diameter_ignore_prefix) {
			size_t prefixSeparatorPos = sessionId.find(':');
			if(prefixSeparatorPos != string::npos && prefixSeparatorPos < sessionId.length() - 1) {
				sessionId = sessionId.substr(prefixSeparatorPos + 1);
			}
		}
		if(!strncasecmp(sessionId.c_str(), "sip:", 4) ||
		   !strncasecmp(sessionId.c_str(), "tel:", 4)) {
			return(sessionId);
		}
	}
	return("");
}

string cDiameter::getCallingPartyAddress(cDiameterAvpDataItems *dataItems) {
	string callingPartyAddress = getValue(831, dataItems);
	if(!callingPartyAddress.empty()) {
		size_t firstSemicolonPos = callingPartyAddress.find(';');
		if(firstSemicolonPos != string::npos) {
			callingPartyAddress = callingPartyAddress.substr(0, firstSemicolonPos);
		}
		if(opt_diameter_ignore_domain) {
			size_t domainSeparatorPos = callingPartyAddress.find('@');
			if(domainSeparatorPos != string::npos && domainSeparatorPos > 0) {
				callingPartyAddress = callingPartyAddress.substr(0, domainSeparatorPos);
			}
		}
		if(opt_diameter_ignore_prefix) {
			size_t prefixSeparatorPos = callingPartyAddress.find(':');
			if(prefixSeparatorPos != string::npos && prefixSeparatorPos < callingPartyAddress.length() - 1) {
				callingPartyAddress = callingPartyAddress.substr(prefixSeparatorPos + 1);
			}
		}
		return(callingPartyAddress);
	}
	return("");
}

string cDiameter::getValue(unsigned code, cDiameterAvpDataItems *dataItems) {
	string rslt;
	bool allocDataItems = false;
	if(!dataItems) {
		allocDataItems = true;
		dataItems = new FILE_LINE(0) cDiameterAvpDataItems;
		parse(dataItems);
	}
	for(list<cDiameterAvpDataItem*>::iterator iter = dataItems->items.begin(); iter != dataItems->items.end(); iter++) {
		if((*iter)->code == code && (*iter)->length > 0) {
			rslt = (char*)(*((*iter)->payload));
			break;
		}
	}
	if(allocDataItems) {
		delete dataItems;
	}
	return(rslt);
}

int cDiameter::getValues(unsigned code, list<string> *values, cDiameterAvpDataItems *dataItems) {
	values->clear();
	bool allocDataItems = false;
	if(!dataItems) {
		allocDataItems = true;
		dataItems = new FILE_LINE(0) cDiameterAvpDataItems;
		parse(dataItems);
	}
	for(list<cDiameterAvpDataItem*>::iterator iter = dataItems->items.begin(); iter != dataItems->items.end(); iter++) {
		if((*iter)->code == code && (*iter)->length > 0) {
			string value = (char*)(*((*iter)->payload));
			if(std::find(values->begin(), values->end(), value) == values->end()) {
				values->push_back(value);
			}
		}
	}
	if(allocDataItems) {
		delete dataItems;
	}
	return(values->size());
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

void cDiameterPacketStack::sQueuePacketsId::set(cDiameterAvpDataItems *dataItems) {
	cDiameter diameter(NULL, 0);
	public_identity = diameter.getPublicIdentity(dataItems);
	session_id = diameter.getSessionId(dataItems);
	calling_party_address = diameter.getCallingPartyAddress(dataItems);
}

string cDiameterPacketStack::sQueuePacketsId::print(void *_packets) const {
	ostringstream out_str;
	vector<string> filter_items_values;
	if(!public_identity.empty()) {
		out_str << "PI: " << public_identity << " ";
		if(std::find(filter_items_values.begin(), filter_items_values.end(), public_identity) == filter_items_values.end()) {
			filter_items_values.push_back(public_identity);
		}
	}
	if(!session_id.empty()) {
		out_str << "SI: " << session_id << " ";
		if(std::find(filter_items_values.begin(), filter_items_values.end(), session_id) == filter_items_values.end()) {
			filter_items_values.push_back(session_id);
		}
	}
	if(!calling_party_address.empty()) {
		out_str << "CA: " << calling_party_address << " ";
		if(std::find(filter_items_values.begin(), filter_items_values.end(), calling_party_address) == filter_items_values.end()) {
			filter_items_values.push_back(calling_party_address);
		}
	}
	cDiameterPacketStack::cQueuePackets *packets = (cDiameterPacketStack::cQueuePackets*)_packets;
	if(packets->packets.size()) {
		out_str << "C: " << packets->packets.size() << " "
			<< packets->hbh_str() << " ";
	}
	vector<string> filter_items;
	for(unsigned i = 0; i < filter_items_values.size(); i++) {
		filter_items.push_back("frame contains \"" + filter_items_values[i] + "\"");
	}
	out_str << "FILTER: "
		<< "(diameter and " << "(" << implode(filter_items, " and ") << "))"
		<< " or "
		<< "(sip and (sip.Method == \"INVITE\" or sip.Method == \"REGISTER\") and " << "(" << implode(filter_items, " or ") << "))";
	return(out_str.str());
}

cDiameterPacketStack::cQueuePackets::cQueuePackets() {
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
	return(packets.size() ? packets.begin()->age_s(time_us) : 0);
}

void cDiameterPacketStack::cQueuePackets::destroy_packets() {
	for(list<sPacket>::iterator iter = packets.begin(); iter != packets.end(); iter++) {
		iter->destroy_packet();
	}
}

string cDiameterPacketStack::cQueuePackets::hbh_str() {
	ostringstream out_str;
	int c = 0;
	for(list<sPacket>::iterator iter = packets.begin(); iter != packets.end(); iter++) {
		++c;
		sPacket *packet = &(*iter);
		if(c > 1) {
			out_str << ",";
		}
		out_str << (packet->is_request ? "R_" : "A_");
		out_str << hex << packet->hbh_id << dec;
	}
	return(out_str.str());
}

cDiameterPacketStack::cDiameterPacketStack() {
	age_expiration_s = 60;
	cleanup_period_s = 120;
	last_cleanup_s = 0;
	_sync_lock = 0;
}

cDiameterPacketStack::~cDiameterPacketStack() {
	for(map<sQueuePacketsId, cQueuePackets*>::iterator iter_qp = packet_stack.begin(); iter_qp != packet_stack.end(); iter_qp++) {
		cQueuePackets *qp = iter_qp->second;
		qp->destroy_packets();
		eraseFindIndexes(qp);
		delete qp;
	}
}

bool cDiameterPacketStack::add(void *packet, bool is_request, u_int32_t hbh_id, sQueuePacketsId *queue_packets_id, u_int64_t time_us) {
	bool rslt = false;
	lock();
	cQueuePackets *qp = NULL;
	if(is_request) {
		map<sQueuePacketsId, cQueuePackets*>::iterator iter_qp = packet_stack.find(*queue_packets_id);
		if(iter_qp != packet_stack.end()) {
			qp = iter_qp->second;
		}
		if(!qp) {
			qp = new FILE_LINE(0) cQueuePackets;
			qp->id = *queue_packets_id;
			packet_stack[*queue_packets_id] = qp;
			addFindIndexes(qp);
		}
		hbh_id_to_queue_packets_id[hbh_id] = qp;
	} else {
		map<u_int32_t, cQueuePackets*>::iterator iter_hbh = hbh_id_to_queue_packets_id.find(hbh_id);
		if(iter_hbh != hbh_id_to_queue_packets_id.end()) {
			qp = iter_hbh->second;
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

bool cDiameterPacketStack::retrieve(eTypeRetrieve type_retrieve, const char *identity, list<sPacket> *packets, u_int64_t from_time, u_int64_t to_time) {
	bool rslt = false;
	lock();
	list<cQueuePackets*> qpl;
	map<string, list<cQueuePackets*> >::iterator iter;
	if(type_retrieve == _tr_from) {
		if((iter = packet_stack_by_from.find(identity)) != packet_stack_by_from.end()) {
			qpl = iter->second;
		}
	} else {
		if((iter = packet_stack_by_to.find(identity)) != packet_stack_by_to.end()) {
			qpl = iter->second;
		}
	}
	if(qpl.size()) {
		for(list<cQueuePackets*>::iterator iter_qpl = qpl.begin(); iter_qpl != qpl.end(); iter_qpl++) {
			cQueuePackets *qp = *iter_qpl;
			for(list<sPacket>::iterator iter_packet = qp->packets.begin(); iter_packet != qp->packets.end(); ) {
				if(iter_packet->time_us >= from_time - TIME_S_TO_US(opt_diameter_time_overlap) &&
				   iter_packet->time_us <= to_time + TIME_S_TO_US(opt_diameter_time_overlap)) {
					rslt = true;
					packets->push_back(*iter_packet);
					hbh_id_to_queue_packets_id.erase(iter_packet->hbh_id);
					qp->packets.erase(iter_packet++);
				} else {
					iter_packet++;
				}
			}
			if(!qp->packets.size()) {
				packet_stack.erase(qp->id);
				eraseFindIndexes(qp);
				delete qp;
			}
		}
	}
	/* obsolete
	for(map<sQueuePacketsId, cQueuePackets*>::iterator iter_qp = packet_stack.begin(); iter_qp != packet_stack.end();) {
		if(type_retrieve == _tr_from ?
		    iter_qp->first.session_id == identity || iter_qp->first.calling_party_address == identity :
		    iter_qp->first.public_identity == identity) {
			rslt = true;
			cQueuePackets *qp = iter_qp->second;
			for(list<sPacket>::iterator iter = qp->packets.begin(); iter != qp->packets.end(); iter++) {
				packets->push_back(*iter);
				hbh_id_to_queue_packets_id.erase(iter->hbh_id);
			}
			eraseFindIndexes(qp);
			delete qp;
			packet_stack.erase(iter_qp++);
		} else {
			iter_qp++;
		}
	}
	*/
	unlock();
	return(rslt);
}

bool cDiameterPacketStack::retrieve(eTypeRetrieve type_retrieve, list<string> *identity, list<sPacket> *packets, u_int64_t from_time, u_int64_t to_time) {
	int rslt = 0;
	for(list<string>::iterator iter = identity->begin(); iter != identity->end(); iter++) {
		if(retrieve(type_retrieve, iter->c_str(), packets, from_time, to_time)) {
			++rslt;
		}
	}
	if(rslt > 1) {
		packets->sort();
	}
	return(rslt > 0);
}

bool cDiameterPacketStack::retrieve(eTypeRetrieve type_retrieve, list<string> *identity, cQueuePackets *packets, u_int64_t from_time, u_int64_t to_time) {
	return(retrieve(type_retrieve, identity, &packets->packets, from_time, to_time));
}

bool cDiameterPacketStack::retrieve_from_sip(list<string> *from_sip, cQueuePackets *packets, u_int64_t from_time, u_int64_t to_time) {
	return(retrieve(_tr_from, from_sip, packets, from_time, to_time));
}

bool cDiameterPacketStack::retrieve_to_sip(list<string> *to_sip, cQueuePackets *packets, u_int64_t from_time, u_int64_t to_time) {
	return(retrieve(_tr_to, to_sip, packets, from_time, to_time));
}

void cDiameterPacketStack::cleanup(u_int64_t time_us) {
	if(!time_us) {
		time_us = getTimeUS();
	}
	lock();
	for(map<sQueuePacketsId, cQueuePackets*>::iterator iter_qp = packet_stack.begin(); iter_qp != packet_stack.end(); ) {
		extern int absolute_timeout;
		unsigned age_s = iter_qp->second->age_s(time_us);
		bool do_cleanup = false;
		if(age_s > (unsigned)absolute_timeout + 120) {
			do_cleanup = true;
		} else if(age_s > age_expiration_s) {
			if(!check_used(&iter_qp->first)) {
				do_cleanup = true;
			}
		}
		if(do_cleanup) {
			cQueuePackets *qp = iter_qp->second;
			while(qp->packets.size() && qp->packets.begin()->age_s(time_us) > age_expiration_s) {
				list<sPacket>::iterator iter = qp->packets.begin();
				hbh_id_to_queue_packets_id.erase(iter->hbh_id);
				iter->destroy_packet();
				qp->packets.erase(iter);
			}
			if(!qp->packets.size()) {
				eraseFindIndexes(qp);
				delete qp;
				packet_stack.erase(iter_qp++);
			} else {
				iter_qp++;
			}
		} else {
			iter_qp++;
		}
	}
	unlock();
}

string cDiameterPacketStack::print_packets_stack() {
	ostringstream out_str;
	lock();
	if(packet_stack.size()) {
		out_str << " * packet_stack size: " << packet_stack.size() << endl;
		int counter = 0;
		for(map<sQueuePacketsId, cQueuePackets*>::iterator iter = packet_stack.begin(); iter != packet_stack.end(); iter++) {
			out_str << " - " << (++counter) << " " << iter->first.print((cQueuePackets*)iter->second) << endl;
		}
	}
	if(packet_stack_by_from.size()) {
		out_str << " * packet_stack_by_from size: " << packet_stack_by_from.size() << endl;
		int counter = 0;
		for(map<string, list<cQueuePackets*> >::iterator iter = packet_stack_by_from.begin(); iter != packet_stack_by_from.end(); iter++) {
			out_str << " - " << (++counter) << " " << iter->first << endl;
		}
	}
	if(packet_stack_by_to.size()) {
		out_str << " * packet_stack_by_to size: " << packet_stack_by_to.size() << endl;
		int counter = 0;
		for(map<string, list<cQueuePackets*> >::iterator iter = packet_stack_by_to.begin(); iter != packet_stack_by_to.end(); iter++) {
			out_str << " - " << (++counter) << " " << iter->first << endl;
		}
	}
	if(hbh_id_to_queue_packets_id.size()) {
		out_str << " * hbh_id_to_queue_packets_id size: " << hbh_id_to_queue_packets_id.size() << endl;
	}
	unlock();
	return(out_str.str());
}

bool cDiameterPacketStack::check_used(const sQueuePacketsId *queue_packets_id) {
	extern Calltable *calltable;
	return((!queue_packets_id->public_identity.empty() && 
		(calltable->find_by_diameter_to_sip(queue_packets_id->public_identity.c_str()) != NULL ||
		 calltable->find_by_diameter_from_sip(queue_packets_id->public_identity.c_str()) != NULL)) ||
	       (!queue_packets_id->session_id.empty() && 
		(calltable->find_by_diameter_to_sip(queue_packets_id->session_id.c_str()) != NULL || 
		 calltable->find_by_diameter_from_sip(queue_packets_id->session_id.c_str()) != NULL)) ||
	       (!queue_packets_id->calling_party_address.empty() && 
		calltable->find_by_diameter_from_sip(queue_packets_id->calling_party_address.c_str()) != NULL));
}

void cDiameterPacketStack::addFindIndexes(cQueuePackets *queue_packets) {
	if(!queue_packets->id.public_identity.empty()) {
		addFindIndex(queue_packets, &packet_stack_by_to, queue_packets->id.public_identity.c_str());
		addFindIndex(queue_packets, &packet_stack_by_from, queue_packets->id.public_identity.c_str());
	}
	if(!queue_packets->id.session_id.empty()) {
		addFindIndex(queue_packets, &packet_stack_by_to, queue_packets->id.session_id.c_str());
		addFindIndex(queue_packets, &packet_stack_by_from, queue_packets->id.session_id.c_str());
	}
	if(!queue_packets->id.calling_party_address.empty()) {
		addFindIndex(queue_packets, &packet_stack_by_from, queue_packets->id.calling_party_address.c_str());
	}
}

void cDiameterPacketStack::addFindIndex(cQueuePackets *queue_packets, map<string, list<cQueuePackets*> > *dia_map, const char *index) {
	if(std::find((*dia_map)[index].begin(), (*dia_map)[index].end(), queue_packets) == (*dia_map)[index].end()) {
		(*dia_map)[index].push_back(queue_packets);
	}
}

void cDiameterPacketStack::eraseFindIndexes(cQueuePackets *queue_packets) {
	map<string, cQueuePackets*>::iterator iter;
	if(!queue_packets->id.public_identity.empty()) {
		eraseFindIndex(queue_packets, &packet_stack_by_to, queue_packets->id.public_identity.c_str());
		eraseFindIndex(queue_packets, &packet_stack_by_from, queue_packets->id.public_identity.c_str());
	}
	if(!queue_packets->id.session_id.empty()) {
		eraseFindIndex(queue_packets, &packet_stack_by_to, queue_packets->id.session_id.c_str());
		eraseFindIndex(queue_packets, &packet_stack_by_from, queue_packets->id.session_id.c_str());
	}
	if(!queue_packets->id.calling_party_address.empty()) {
		eraseFindIndex(queue_packets, &packet_stack_by_from, queue_packets->id.calling_party_address.c_str());
	}
}

void cDiameterPacketStack::eraseFindIndex(cQueuePackets *queue_packets, map<string, list<cQueuePackets*> > *dia_map, const char *index) {
	for(list<cQueuePackets*>::iterator iter = (*dia_map)[index].begin(); iter != (*dia_map)[index].end(); iter++) {
		if(*iter == queue_packets) {
			(*dia_map)[index].erase(iter);
			break;
		}
	}
	if((*dia_map)[index].size() == 0) {
		dia_map->erase(index);
	}
}
