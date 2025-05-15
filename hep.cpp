#include "voipmonitor.h"

#include "hep.h"
#include "tools.h"
#include "header_packet.h"
#include "sniff_inline.h"
#include "sniff_proc_class.h"

#include <pcap.h>


extern bool opt_hep_kamailio_protocol_id_fix;
extern bool opt_hep_counter_log;
extern bool opt_hep_via_pb;
extern int opt_t2_boost;

cHepCounter hep_counter;

static cHEP_Server *HEP_Server;


cHEP_ProcessData::cHEP_ProcessData() 
 : cTimer(NULL) {
	block_store = NULL;
	block_store_sync = 0;
	if(opt_t2_boost && opt_hep_via_pb) {
		setEveryMS(100);
		start();
	}
}

void cHEP_ProcessData::processData(u_char *data, size_t dataLen, vmIP ip) {
	/*
	cout << " *** " << (isBeginHep(data, dataLen) ? "BEGIN" : "not begin") << endl;
	cout << " *** " << dataLen << endl;
	if(isBeginHep(data, dataLen)) {
		cout << " *** " << hepLength(data, dataLen) << endl;
		cout << " *** " << (isCompleteHep(data, dataLen) ? "COMPLETE" : "not complete") << endl;
	}
	*/
	if(isBeginHep(data, dataLen)) {
		hep_buffer.clear();
		if(isCompleteHep(data, dataLen)) {
			unsigned processed = processHeps(data, dataLen, ip);
			if(processed < dataLen) {
				hep_buffer.add(data + processed, dataLen - processed);
			}
		} else {
			hep_buffer.add(data, dataLen);
		}
	} else if(!hep_buffer.empty()) {
		hep_buffer.add(data, dataLen);
		if(isCompleteHep(hep_buffer.data(), hep_buffer.data_len())) {
			unsigned processed = processHeps(hep_buffer.data(), hep_buffer.data_len(), ip);
			if(processed == hep_buffer.data_len()) {
				hep_buffer.clear();
			} else if(processed < dataLen) {
				hep_buffer.removeDataFromLeft(processed);
			}
		}
		if(hep_buffer.size() > 1024 * 1024) {
			hep_buffer.clear();
			syslog(LOG_NOTICE, "HEP data exceeded the limit of 1MB. Check the HEP data sent.");
		}
	}
}

bool cHEP_ProcessData::isCompleteHep(u_char *data, size_t dataLen) {
	return(isBeginHep(data, dataLen) &&
	       hepLength(data, dataLen) <= dataLen);
}

bool cHEP_ProcessData::isBeginHep(u_char *data, size_t dataLen) {
	return(dataLen >= 4 &&
	       data[0] == 0x48 && data[1] == 0x45 && data[2] == 0x50 && data[3] == 0x33);
}

u_int16_t cHEP_ProcessData::hepLength(u_char *data, size_t dataLen) {
	return(dataLen >= 6 ? ntohs(*(u_int32_t*)(data + 4)) : 0);
}

unsigned cHEP_ProcessData::processHeps(u_char *data, size_t dataLen, vmIP ip) {
	unsigned processed = 0;
	while(processed < dataLen - 6) {
		if(!isBeginHep(data + processed, dataLen - processed)) {
			break;
		}
		unsigned hep_length = hepLength(data + processed, dataLen - processed);
		if(hep_length > dataLen - processed) {
			break;
		}
		processHep(data + processed, hep_length, ip);
		processed += hep_length;
	}
	return(processed);
}

void cHEP_ProcessData::processHep(u_char *data, size_t dataLen, vmIP ip) {
	if(opt_hep_counter_log && ip.isSet()) {
		 hep_counter.inc(ip);
	}
	sHEP_Data hepData;
	processChunks(data + 6, dataLen - 6, &hepData);
	if(sverb.hep3) {
		cout << " * HEP3 * " << endl
		     << hepData.dump() << endl;
	}
	if((hepData.ip_protocol_family == PF_INET || hepData.ip_protocol_family == PF_INET6) &&
	   (hepData.ip_protocol_id == IPPROTO_UDP || hepData.ip_protocol_id == IPPROTO_TCP || hepData.ip_protocol_id == IPPROTO_ESP)) {
		int dlink = PcapDumper::get_global_pcap_dlink_en10();
		int pcap_handle_index = PcapDumper::get_global_handle_index_en10();
		ether_header header_eth;
		memset(&header_eth, 0, sizeof(header_eth));
		header_eth.ether_type = htons(hepData.ip_protocol_family == PF_INET6 ? ETHERTYPE_IPV6 : ETHERTYPE_IP);
		string payload_str;
		SimpleBuffer payload_buf;
		u_char *payload_data = hepData.captured_packet_payload.data();
		unsigned payload_len = hepData.captured_packet_payload.data_len();
		if(hepData.protocol_type == _hep_prot_SIP && 
		   payload_len > 0 && payload_data[0] == '{' && payload_data[payload_len - 1] == '}') {
			JsonItem jsonData;
			jsonData.parse((char*)payload_data);
			string payload_value = jsonData.getValue("payload");
			if(!payload_value.empty()) {
				payload_str = payload_value;
				payload_data = (u_char*)payload_str.c_str();
				payload_len = payload_str.length();
			}
		} else if(hepData.protocol_type == _hep_prot_RTCP_JSON && 
			  payload_len > 0 && payload_data[0] == '{' && payload_data[payload_len - 1] == '}') {
			extern bool createRtcpPayloadFromJson(const char *json, SimpleBuffer *buffer);
			if(createRtcpPayloadFromJson((const char*)payload_data, &payload_buf)) {
				payload_data = payload_buf.data();
				payload_len = payload_buf.size();
			}
		}
		if(hepData.ip_protocol_id == IPPROTO_TCP || hepData.ip_protocol_id == IPPROTO_ESP) {
			pcap_pkthdr *tcpHeader;
			u_char *tcpPacket;
			createSimpleTcpDataPacket(sizeof(header_eth), &tcpHeader,  &tcpPacket,
						  (u_char*)&header_eth, payload_data, payload_len, 0,
						  hepData.ip_source_address, hepData.ip_destination_address, hepData.protocol_source_port, hepData.protocol_destination_port,
						  0, 0, (hepData.set_flags & (1ull << _hep_chunk_tcp_flag)) ? hepData.tcp_flag : 0,
						  hepData.timestamp_seconds, hepData.timestamp_microseconds, dlink);
			pushPacket(&hepData, tcpHeader, tcpPacket, payload_len, true,
				   dlink, pcap_handle_index);
		} else if(hepData.ip_protocol_id == IPPROTO_UDP) {
			pcap_pkthdr *udpHeader;
			u_char *udpPacket;
			createSimpleUdpDataPacket(sizeof(header_eth), &udpHeader,  &udpPacket,
						  (u_char*)&header_eth, payload_data, payload_len, 0,
						  hepData.ip_source_address, hepData.ip_destination_address, hepData.protocol_source_port, hepData.protocol_destination_port,
						  hepData.timestamp_seconds, hepData.timestamp_microseconds);
			pushPacket(&hepData, udpHeader, udpPacket, payload_len, false,
				   dlink, pcap_handle_index);
		}
	}
}

u_int16_t cHEP_ProcessData::chunkVendor(u_char *data, size_t dataLen) {
	return(dataLen >= 2 ? ntohs(*(u_int32_t*)(data + 0)) : 0);
}

u_int16_t cHEP_ProcessData::chunkType(u_char *data, size_t dataLen) {
	return(dataLen >= 4 ? ntohs(*(u_int32_t*)(data + 2)) : 0);
}

u_int16_t cHEP_ProcessData::chunkLength(u_char *data, size_t dataLen) {
	return(dataLen >= 6 ? ntohs(*(u_int32_t*)(data + 4)) : 0);
}

void cHEP_ProcessData::processChunks(u_char *data, size_t dataLen, sHEP_Data *hepData) {
	unsigned offset = 0;
	while(offset < dataLen - 6) {
		unsigned chunk_length = chunkLength(data + offset, dataLen - offset);
		if(!chunk_length || chunk_length > dataLen - offset) {
			break;
		}
		processChunk(data + offset, chunk_length, hepData);
		offset += chunk_length;
	}
}

void cHEP_ProcessData::processChunk(u_char *data, size_t dataLen, sHEP_Data *hepData) {
	unsigned chunk_type = chunkType(data, dataLen);
	unsigned payloadLen = dataLen - 6;
	u_char *payload = data + 6;
	bool ok = false;
	SimpleBuffer *bin = NULL;
	switch(chunk_type) {
	case _hep_chunk_ip_protocol_family:
		if(payloadLen == 1) {
			hepData->ip_protocol_family = *(u_int8_t*)payload;
			ok = true;
		}
		break;
	case _hep_chunk_ip_protocol_id:
		if(payloadLen == 1) {
			hepData->ip_protocol_id = *(u_int8_t*)payload;
			if(hepData->ip_protocol_id == IPPROTO_IDP && opt_hep_kamailio_protocol_id_fix) {
				hepData->ip_protocol_id = IPPROTO_UDP;
			}
			ok = true;
		}
		break;
	case _hep_chunk_ip_source_address_v4:
		if(payloadLen == 4) {
			hepData->ip_source_address.setIPv4(*(u_int32_t*)payload, true);
			ok = true;
		}
		break;
	case _hep_chunk_ip_source_address_v6:
		if(payloadLen == 16) {
			hepData->ip_source_address.setIPv6(*(in6_addr*)payload, true);
			ok = true;
		}
		break;
	case _hep_chunk_ip_destination_address_v4:
		if(payloadLen == 4) {
			hepData->ip_destination_address.setIPv4(*(u_int32_t*)payload, true);
			ok = true;
		}
		break;
	case _hep_chunk_ip_destination_address_v6:
		if(payloadLen == 16) {
			hepData->ip_destination_address.setIPv6(*(in6_addr*)payload, true);
			ok = true;
		}
		break;
	case _hep_chunk_protocol_source_port:
		if(payloadLen == 2) {
			hepData->protocol_source_port.setPort(*(u_int16_t*)payload, true);
			ok = true;
		}
		break;
	case _hep_chunk_protocol_destination_port:
		if(payloadLen == 2) {
			hepData->protocol_destination_port.setPort(*(u_int16_t*)payload, true);
			ok = true;
		}
		break;
	case _hep_chunk_timestamp_seconds:
		if(payloadLen == 4) {
			hepData->timestamp_seconds = ntohl(*(u_int32_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_timestamp_microseconds:
		if(payloadLen == 4) {
			hepData->timestamp_microseconds = ntohl(*(u_int32_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_protocol_type:
		if(payloadLen == 1) {
			hepData->protocol_type = *(u_int8_t*)payload;
			ok = true;
		}
		break;
	case _hep_chunk_capture_agent_id:
		if(payloadLen == 4) {
			hepData->capture_agent_id = ntohl(*(u_int32_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_keep_alive_timer:
		if(payloadLen == 2) {
			hepData->keep_alive_timer = ntohs(*(u_int16_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_authenticate_key:
		bin = &hepData->authenticate_key;
		break;
	case _hep_chunk_captured_packet_payload:
		hepData->captured_packet_payload.add(payload, payloadLen);
		ok = true;
		break;
	case _hep_chunk_captured_packet_payload_compressed:
		{
		cGzip gzipDecompress;
		if(gzipDecompress.isCompress(payload, payloadLen)) {
			u_char *dbuffer;
			size_t dbufferLength;
			if(gzipDecompress.decompress(payload, payloadLen, &dbuffer, &dbufferLength)) {
				hepData->captured_packet_payload.add(dbuffer, dbufferLength);
				delete [] dbuffer;
			}
		}
		}
		break;
	case _hep_chunk_internal_correlation_id:
		bin = &hepData->internal_correlation_id;
		break;
	case _hep_chunk_vlan_id:
		if(payloadLen == 2) {
			hepData->vlan_id = ntohs(*(u_int16_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_group_id:
		bin = &hepData->group_id;
		break;
	case _hep_chunk_source_mac:
		if(payloadLen == 8) {
			hepData->source_mac = be64toh(*(u_int64_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_destination_mac:
		if(payloadLen == 8) {
			hepData->destination_mac = be64toh(*(u_int64_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_ethernet_type:
		if(payloadLen == 2) {
			hepData->ethernet_type = ntohs(*(u_int16_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_tcp_flag:
		if(payloadLen == 1) {
			hepData->tcp_flag = *(u_int8_t*)payload;
			ok = true;
		}
		break;
	case _hep_chunk_ip_tos:
		if(payloadLen == 1) {
			hepData->ip_tos = *(u_int8_t*)payload;
			ok = true;
		}
		break;
	case _hep_chunk_mos_value:
		if(payloadLen == 2) {
			hepData->mos_value = ntohs(*(u_int16_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_r_factor:
		if(payloadLen == 2) {
			hepData->r_factor = ntohs(*(u_int16_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_geo_location:
		bin = &hepData->geo_location;
		break;
	case _hep_chunk_jitter:
		if(payloadLen == 4) {
			hepData->jitter = ntohl(*(u_int32_t*)payload);
			ok = true;
		}
		break;
	case _hep_chunk_transaction_type:
		bin = &hepData->transaction_type;
		break;
	case _hep_chunk_payload_json_keys:
		bin = &hepData->payload_json_keys;
		break;
	case _hep_chunk_tags_values:
		bin = &hepData->tags_values;
		break;
	case _hep_chunk_tag_type:
		if(payloadLen == 2) {
			hepData->tag_type = ntohs(*(u_int16_t*)payload);
			ok = true;
		}
		break;
	}
	if(bin) {
		bin->add(payload, payloadLen);
		ok = true;
	}
	if(ok) {
		hepData->set_flags |= (1ull << chunk_type);
	}
}

void cHEP_ProcessData::pushPacket(sHEP_Data *hepData, pcap_pkthdr *header, u_char *packet, unsigned payload_len, bool tcp,
				  int dlink, int pcap_handle_index) {
	if(opt_t2_boost && opt_hep_via_pb) {
		block_store_lock();
		if(!block_store) {
			block_store = new FILE_LINE(0) pcap_block_store;
		}
		pcap_pkthdr_plus header_plus;
		header_plus.convertFromStdHeader(header);
		header_plus.header_ip_encaps_offset = 0xFFFF;
		header_plus.header_ip_offset = sizeof(ether_header);
		header_plus.dlink = dlink;
		header_plus.pid.clear();
		if(!block_store->add_hp_ext(&header_plus, packet)) {
			extern PcapQueue_readFromFifo *pcapQueueQ;
			pcapQueueQ->addBlockStoreToPcapStoreQueue_ext(block_store);
			block_store = new FILE_LINE(0) pcap_block_store;
			block_store->add_hp_ext(&header_plus, packet);
		}
		delete header;
		delete [] packet;
		block_store_unlock();
	} else {
		unsigned iphdrSize = ((iphdr2*)(packet + sizeof(ether_header)))->get_hdr_size();
		unsigned dataOffset = sizeof(ether_header) + iphdrSize + 
				      (tcp ?
					((tcphdr2*)(packet + sizeof(ether_header) + iphdrSize))->doff * 4 :
					sizeof(udphdr2));
		packet_flags pflags;
		pflags.init();
		if(tcp) {
			pflags.set_tcp(2);
		}
		sPacketInfoData pid;
		pid.clear();
		extern int opt_id_sensor;
		extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
		if(opt_t2_boost_direct_rtp) {
			sHeaderPacketPQout hp(header, packet,
					      dlink, opt_id_sensor, vmIP());
			preProcessPacket[PreProcessPacket::ppt_detach_x]->push_packet(
				sizeof(ether_header), 0xFFFF,
				dataOffset, payload_len,
				hepData->protocol_source_port, hepData->protocol_destination_port,
				pflags,
				&hp,
				pcap_handle_index);
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				0, 
				#endif
				hepData->ip_source_address, hepData->protocol_source_port, hepData->ip_destination_address, hepData->protocol_destination_port, 
				payload_len, dataOffset,
				pcap_handle_index, header, packet, _t_packet_alloc_header_std, 
				pflags, (iphdr2*)(packet + sizeof(ether_header)), (iphdr2*)(packet + sizeof(ether_header)),
				NULL, 0, dlink, opt_id_sensor, vmIP(), pid,
				false);
		}
	}
}

void cHEP_ProcessData::evTimer(u_int32_t /*time_s*/, int /*typeTimer*/, void */*data*/) {
	block_store_lock();
	if(block_store && block_store->isFull_checkTimeout_ext(100)) {
		extern PcapQueue_readFromFifo *pcapQueueQ;
		pcapQueueQ->addBlockStoreToPcapStoreQueue_ext(block_store);
		block_store = NULL;
	}
	block_store_unlock();
}


string sHEP_Data::dump() {
	ostringstream out;
	if(set_flags & (1ull << _hep_chunk_ip_protocol_family)) {
		out << "ip_protocol_family: " << (int)ip_protocol_family << endl;
	}
	if(set_flags & (1ull << _hep_chunk_ip_protocol_id)) {
		out << "ip_protocol_id: " << (int)ip_protocol_id << endl;
	}
	if(set_flags & (1ull << _hep_chunk_ip_source_address_v4) ||
	   set_flags & (1ull << _hep_chunk_ip_source_address_v6)) {
		out << "ip_source_address: " << ip_source_address.getString() << endl;
	}
	if(set_flags & (1ull << _hep_chunk_ip_destination_address_v4) ||
	   set_flags & (1ull << _hep_chunk_ip_destination_address_v6)) {
		out << "ip_destination_address: " << ip_destination_address.getString() << endl;
	}
	if(set_flags & (1ull << _hep_chunk_protocol_source_port)) {
		out << "protocol_source_port: " << protocol_source_port.getString() << endl;
	}
	if(set_flags & (1ull << _hep_chunk_protocol_destination_port)) {
		out << "protocol_destination_port: " << protocol_destination_port.getString() << endl;
	}
	if(set_flags & (1ull << _hep_chunk_timestamp_seconds)) {
		out << "timestamp_seconds: " << timestamp_seconds << endl;
	}
	if(set_flags & (1ull << _hep_chunk_timestamp_microseconds)) {
		out << "timestamp_microseconds: " << timestamp_microseconds << endl;
	}
	if(set_flags & (1ull << _hep_chunk_protocol_type)) {
		out << "protocol_type: " << (int)protocol_type << endl;
	}
	if(set_flags & (1ull << _hep_chunk_capture_agent_id)) {
		out << "capture_agent_id: " << capture_agent_id << endl;
	}
	if(set_flags & (1ull << _hep_chunk_keep_alive_timer)) {
		out << "keep_alive_timer: " << keep_alive_timer << endl;
	}
	if(set_flags & (1ull << _hep_chunk_authenticate_key)) {
		out << "authenticate_key: " << hexdump_to_string(&authenticate_key) << endl;
	}
	if(set_flags & (1ull << _hep_chunk_captured_packet_payload) ||
	   set_flags & (1ull << _hep_chunk_captured_packet_payload_compressed)) {
		string dump_payload((char*)captured_packet_payload);
		find_and_replace(dump_payload, "\r", "\\r");
		find_and_replace(dump_payload, "\n", "\\n");
		out << "captured_packet_payload: " << dump_payload << endl;
	}
	if(set_flags & (1ull << _hep_chunk_internal_correlation_id)) {
		out << "internal_correlation_id: " << hexdump_to_string(&internal_correlation_id) << endl;
	}
	if(set_flags & (1ull << _hep_chunk_vlan_id)) {
		out << "vlan_id: " << vlan_id << endl;
	}
	if(set_flags & (1ull << _hep_chunk_group_id)) {
		out << "group_id: " << hexdump_to_string(&group_id) << endl;
	}
	if(set_flags & (1ull << _hep_chunk_source_mac)) {
		out << "source_mac: " << hex << source_mac << dec << endl;
	}
	if(set_flags & (1ull << _hep_chunk_destination_mac)) {
		out << "destination_mac: " << hex << destination_mac << dec << endl;
	}
	if(set_flags & (1ull << _hep_chunk_ethernet_type)) {
		out << "ethernet_type: " << ethernet_type << endl;
	}
	if(set_flags & (1ull << _hep_chunk_tcp_flag)) {
		out << "tcp_flag: " << hex << (int)tcp_flag << dec << endl;
	}
	if(set_flags & (1ull << _hep_chunk_ip_tos)) {
		out << "ip_tos: " << (int)ip_tos << endl;
	}
	if(set_flags & (1ull << _hep_chunk_mos_value)) {
		out << "mos_value: " << mos_value << endl;
	}
	if(set_flags & (1ull << _hep_chunk_r_factor)) {
		out << "r_factor: " << r_factor << endl;
	}
	if(set_flags & (1ull << _hep_chunk_geo_location)) {
		out << "geo_location: " << hexdump_to_string(&geo_location) << endl;
	}
	if(set_flags & (1ull << _hep_chunk_jitter)) {
		out << "jitter: " << jitter << endl;
	}
	if(set_flags & (1ull << _hep_chunk_transaction_type)) {
		out << "transaction_type: " << hexdump_to_string(&transaction_type) << endl;
	}
	if(set_flags & (1ull << _hep_chunk_payload_json_keys)) {
		out << "payload_json_keys: " << hexdump_to_string(&payload_json_keys) << endl;
	}
	if(set_flags & (1ull << _hep_chunk_tags_values)) {
		out << "tags_values: " << hexdump_to_string(&tags_values) << endl;
	}
	if(set_flags & (1ull << _hep_chunk_tag_type)) {
		out << "tag_type: " << tag_type << endl;
	}
	return(out.str());
}


cHEP_Server::cHEP_Server(bool udp) 
 : cServer(udp, true) {
}

cHEP_Server::~cHEP_Server() {
}

void cHEP_Server::createConnection(cSocket *socket) {
	if(is_terminating()) {
		return;
	}
	cHEP_Connection *connection = new FILE_LINE(0) cHEP_Connection(socket);
	connection->connection_start();
}

void cHEP_Server::evData(u_char *data, size_t dataLen, vmIP ip) {
	processData(data, dataLen, ip);
}


cHEP_Connection::cHEP_Connection(cSocket *socket) 
 : cServerConnection(socket, true) {
}

cHEP_Connection::~cHEP_Connection() {
}

void cHEP_Connection::evData(u_char *data, size_t dataLen) {
	processData(data, dataLen, socket->getIPL());
}

void cHEP_Connection::connection_process() {
	cServerConnection::connection_process();
	delete this;
}


string cHepCounter::get_ip_counter() {
	string rslt;
	lock();
	for(map<vmIP, u_int64_t>::iterator iter = ip_counter.begin(); iter != ip_counter.end(); iter++) {
		if(!rslt.empty()) {
			rslt += ";";
		}
		rslt += iter->first.getString() + ":" + intToString(iter->second);
	}
	unlock();
	return(rslt);
}

u_int64_t cHepCounter::get_sum_counter() {
	u_int64_t sum = 0;
	lock();
	for(map<vmIP, u_int64_t>::iterator iter = ip_counter.begin(); iter != ip_counter.end(); iter++) {
		sum += iter->second;
	}
	unlock();
	return(sum);
}


void HEP_ServerStart(const char *host, int port, bool udp) {
	if(HEP_Server) {
		delete HEP_Server;
	}
	HEP_Server =  new FILE_LINE(0) cHEP_Server(udp);
	HEP_Server->setStartVerbString("START HEP LISTEN");
	HEP_Server->listen_start("hep_server", host, port);
}

void HEP_ServerStop() {
	if(HEP_Server) {
		delete HEP_Server;
		HEP_Server = NULL;
	}
}


void HEP_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port, bool udp) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	if(!(handle = pcap_open_offline_zip(pcap, errbuf))) {
		fprintf(stderr, "Couldn't open pcap file '%s': %s\n", pcap, errbuf);
		return;
	}
	set_all_ports_for_tcp();
	int dlink = pcap_datalink(handle);
	pcap_pkthdr *pcap_next_ex_header;
	const u_char *pcap_next_ex_packet;
	sHeaderPacket *header_packet = NULL;
	pcapProcessData ppd;
	int res;
	cSocket socket("x");
	if(udp) {
		socket.setUdp(true);
	}
	socket.setHostPort(destination_ip.getString(), destination_port);
	if(!socket.connect()) {
		return;
	} else {
		cout << "ok connect" << endl;
	}
	while((res = pcap_next_ex(handle, &pcap_next_ex_header, &pcap_next_ex_packet)) > 0) {
		if(header_packet && header_packet->packet_alloc_size != 0xFFFF) {
			DESTROY_HP(&header_packet);
		}
		if(header_packet) {
			header_packet->clearPcapProcessData();
		} else {
			header_packet = CREATE_HP(0xFFFF);
		}
		memcpy_heapsafe(HPH(header_packet), header_packet,
				pcap_next_ex_header, NULL,
				sizeof(pcap_pkthdr));
		memcpy_heapsafe(HPP(header_packet), header_packet,
				pcap_next_ex_packet, NULL,
				pcap_next_ex_header->caplen);
		ppd.header_udp = NULL;
		ppd.header_tcp = NULL;
		ppd.datalen = 0;
		if(!pcapProcess(&header_packet, -1,
				NULL, 0,
				ppf_all,
				&ppd, dlink, NULL, NULL)) {
			continue;
		}
		u_int32_t caplen = HPH(header_packet)->caplen;
		u_char *packet = HPP(header_packet);
		if(ppd.header_ip) {
			if(ppd.header_ip->get_protocol() == IPPROTO_UDP) {
				ppd.header_udp = (udphdr2*)((char*)ppd.header_ip + ppd.header_ip->get_hdr_size());
				ppd.datalen = get_udp_data_len(ppd.header_ip, ppd.header_udp, &ppd.data, packet, caplen);
			} else if(ppd.header_ip->get_protocol() == IPPROTO_TCP) {
				ppd.header_tcp = (tcphdr2*) ((char*) ppd.header_ip + ppd.header_ip->get_hdr_size());
				ppd.datalen = get_tcp_data_len(ppd.header_ip, ppd.header_tcp, &ppd.data, packet, caplen);
			}
			if(ppd.datalen) {
				if(ppd.header_ip->get_saddr() == client_ip && ppd.header_ip->get_daddr() == server_ip) {
					cout << " -> " << flush;
					if(socket.write((u_char*)ppd.data, ppd.datalen)) {
						cout << "ok write " << ppd.datalen << endl;
					}
				}
			}
		}
	}
	if(header_packet) {
		DESTROY_HP(&header_packet);
	}
	pcap_close(handle);
}
