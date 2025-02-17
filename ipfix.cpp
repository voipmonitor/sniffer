#include "voipmonitor.h"

#include "ipfix.h"
#include "tools.h"
#include "header_packet.h"
#include "sniff_inline.h"
#include "sniff_proc_class.h"

#include <pcap.h>


#define IPFIX_VERSION_DEFAULT 10


cIpFixCounter ipfix_counter;


cIPFixServer::cIPFixServer() {
}

cIPFixServer::~cIPFixServer() {
}

void cIPFixServer::createConnection(cSocket *socket) {
	if(is_terminating()) {
		return;
	}
	cIPFixConnection *connection = new FILE_LINE(0) cIPFixConnection(socket);
	connection->connection_start();
}

cIPFixConnection::cIPFixConnection(cSocket *socket)
: cServerConnection(socket) {
}

cIPFixConnection::~cIPFixConnection() {
}

void cIPFixConnection::connection_process() {
	SimpleBuffer read_buffer;
	while((socket && !socket->isError() && !socket->isTerminate()) && !is_terminating())  {
		u_char buffer[10000];
		size_t buffer_length = sizeof(buffer);
		if(socket->read(buffer, &buffer_length) && buffer_length > 0) {
			read_buffer.add(buffer, buffer_length);
			bool rslt_check = check(&read_buffer);
			if(rslt_check) {
				process(&read_buffer);
			}
		} else if(read_buffer.size() > 1024 * 1024) {
			read_buffer.clear();
			syslog(LOG_NOTICE, "IPFIX data exceeded the limit of 1MB. Check the IPFIX data sent.");
		}
	}
	delete this;
}

int cIPFixConnection::check(SimpleBuffer *data) {
	return(checkIPFixData(data, false));
}

int cIPFixConnection::process(SimpleBuffer *data) {
	if(data->size() < sizeof(sIPFixHeader)) {
		return(false);
	}
	unsigned offset = 0;
	unsigned counter = 0;
	do {
		sIPFixHeader *header = (sIPFixHeader*)(data->data() + offset);
		if(!checkIPFixVersion(ntohs(header->Version))) {
			++offset;
			continue;
		}
		u_int16_t length = ntohs(header->Length);
		if(length > data->size() - offset) {
			break;
		}
		if(length < sizeof(sIPFixHeader)) {
			offset += sizeof(sIPFixHeader);
			continue;
		}
		process_ipfix(header);
		offset += length;
		++counter;
	} while(offset < data->size() &&
		data->size() - offset > sizeof(sIPFixHeader));
	if(offset == data->size()) {
		data->clear();
	} else {
		data->removeDataFromLeft(offset);
	}
	return(counter);
}

void cIPFixConnection::process_ipfix(sIPFixHeader *header) {
	// cout << htons(header->SetID) << endl;
	if(sverb.ipfix_counter) {
		 ipfix_counter.inc(socket->getIPL());
	}
	switch(htons(header->SetID)) {
	case _ipfix_HandShake:
		process_ipfix_HandShake(header);
		break;
	case _ipfix_SipIn:
		process_ipfix_SipIn(header);
		break;
	case _ipfix_SipOut:
		process_ipfix_SipOut(header);
		break;
	case _ipfix_SipInTCP:
		process_ipfix_SipInTcp(header);
		break;
	case _ipfix_SipOutTCP:
		process_ipfix_SipOutTcp(header);
		break;
	}
}

void cIPFixConnection::process_ipfix_HandShake(sIPFixHeader *header) {
	// sIPFixHandShake *data = (sIPFixHandShake*)((u_char*)header + sizeof(sIPFixHeader));
	// cout << "Hostname: " << data->Hostname() << " |" << endl;
	header->SetID = ntohs(_ipfix_HandShake_Response);
	socket->write((u_char*)header, htons(header->Length));
}

void cIPFixConnection::process_ipfix_SipIn(sIPFixHeader *header) {
	sIPFixSipIn *data = (sIPFixSipIn*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	push_packet(header, sip_data, false, data->GetTime(), data->GetSrc(), data->GetDst());
}

void cIPFixConnection::process_ipfix_SipOut(sIPFixHeader *header) {
	sIPFixSipOut *data = (sIPFixSipOut*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	push_packet(header, sip_data, false, data->GetTime(), data->GetSrc(), data->GetDst());
}

void cIPFixConnection::process_ipfix_SipInTcp(sIPFixHeader *header) {
	sIPFixSipInTCP *data = (sIPFixSipInTCP*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	push_packet(header, sip_data, true, data->GetTime(), data->GetSrc(), data->GetDst());
}

void cIPFixConnection::process_ipfix_SipOutTcp(sIPFixHeader *header) {
	sIPFixSipOutTCP *data = (sIPFixSipOutTCP*)((u_char*)header + sizeof(sIPFixHeader));
	string sip_data = data->SipMsg(header);
	push_packet(header, sip_data, true, data->GetTime(), data->GetSrc(), data->GetDst());
}

void cIPFixConnection::push_packet(sIPFixHeader *header, string &data, bool tcp, timeval time, vmIPport src, vmIPport dst) {
	/*
	cout << "************************************************************" << endl;
	cout << ntohs(header->SetID) << " / " << ntohl(header->SeqNum) << endl;
	cout << time.tv_sec << "." << setw(6) << time.tv_usec << endl;
	cout << src.getString() << " -> " << dst.getString() << endl;
	cout << data << endl;
	*/
	//
	/*
	u_int64_t time_us = getTimeUS();
	time.tv_sec = time_us / 1000000ull;
	time.tv_usec = time_us % 1000000ull;
	*/
	//
	extern int opt_id_sensor;
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	int dlink = PcapDumper::get_global_pcap_dlink_en10();
	int pcap_handle_index = PcapDumper::get_global_handle_index_en10();
	ether_header header_eth;
	memset(&header_eth, 0, sizeof(header_eth));
	header_eth.ether_type = htons(ETHERTYPE_IP);
	if(tcp) {
		pcap_pkthdr *tcpHeader;
		u_char *tcpPacket;
		createSimpleTcpDataPacket(sizeof(header_eth), &tcpHeader,  &tcpPacket,
					  (u_char*)&header_eth, (u_char*)data.c_str(), data.length(), 0,
					  src.ip, dst.ip, src.port, dst.port,
					  0, 0, 0,
					  time.tv_sec, time.tv_usec, dlink);
		unsigned iphdrSize = ((iphdr2*)(tcpPacket + sizeof(header_eth)))->get_hdr_size();
		unsigned dataOffset = sizeof(header_eth) + 
				      iphdrSize +
				      ((tcphdr2*)(tcpPacket + sizeof(header_eth) + iphdrSize))->doff * 4;
		packet_flags pflags;
		pflags.init();
		pflags.set_tcp(2);
		pflags.set_ssl(true);
		sPacketInfoData pid;
		pid.clear();
		if(opt_t2_boost_direct_rtp) {
			sHeaderPacketPQout hp(tcpHeader, tcpPacket,
					      dlink, opt_id_sensor, vmIP());
			preProcessPacket[PreProcessPacket::ppt_detach_x]->push_packet(
				sizeof(header_eth), 0xFFFF,
				dataOffset, data.length(),
				src.port, dst.port,
				pflags,
				&hp,
				pcap_handle_index);
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				0, 
				#endif
				src.ip, src.port, dst.ip, dst.port, 
				data.length(), dataOffset,
				pcap_handle_index, tcpHeader, tcpPacket, _t_packet_alloc_header_std, 
				pflags, (iphdr2*)(tcpPacket + sizeof(header_eth)), (iphdr2*)(tcpPacket + sizeof(header_eth)),
				NULL, 0, dlink, opt_id_sensor, vmIP(), pid,
				false);
		}
	} else {
		pcap_pkthdr *udpHeader;
		u_char *udpPacket;
		createSimpleUdpDataPacket(sizeof(header_eth), &udpHeader,  &udpPacket,
					  (u_char*)&header_eth, (u_char*)data.c_str(), data.length(), 0,
					  src.ip, dst.ip, src.port, dst.port,
					  time.tv_sec, time.tv_usec);
		unsigned iphdrSize = ((iphdr2*)(udpPacket + sizeof(header_eth)))->get_hdr_size();
		unsigned dataOffset = sizeof(header_eth) + 
				      iphdrSize + 
				      sizeof(udphdr2);
		packet_flags pflags;
		pflags.init();
		pflags.set_ssl(true);
		sPacketInfoData pid;
		pid.clear();
		if(opt_t2_boost_direct_rtp) {
			sHeaderPacketPQout hp(udpHeader, udpPacket,
					      dlink, opt_id_sensor, vmIP());
			preProcessPacket[PreProcessPacket::ppt_detach_x]->push_packet(
				sizeof(header_eth), 0xFFFF,
				dataOffset, data.length(),
				src.port, dst.port,
				pflags,
				&hp,
				pcap_handle_index);
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				0,
				#endif
				src.ip, src.port, dst.ip, dst.port, 
				data.length(), dataOffset,
				pcap_handle_index, udpHeader, udpPacket, _t_packet_alloc_header_std, 
				pflags, (iphdr2*)(udpPacket + sizeof(header_eth)), (iphdr2*)(udpPacket + sizeof(header_eth)),
				NULL, 0, dlink, opt_id_sensor, vmIP(), pid,
				false);
		}
	}
}


string cIpFixCounter::get_ip_counter() {
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

u_int64_t cIpFixCounter::get_sum_counter() {
	u_int64_t sum = 0;
	lock();
	for(map<vmIP, u_int64_t>::iterator iter = ip_counter.begin(); iter != ip_counter.end(); iter++) {
		sum += iter->second;
	}
	unlock();
	return(sum);
}


int checkIPFixData(SimpleBuffer *data, bool strict) {
	if(data->size() < sizeof(sIPFixHeader)) {
		return(false);
	}
	unsigned offset = 0;
	unsigned counter = 0;
	do {
		sIPFixHeader *header = (sIPFixHeader*)(data->data() + offset);
		if(!checkIPFixVersion(ntohs(header->Version))) {
			if(strict) {
				break;
			}
			++offset;
			continue;
		}
		u_int16_t length = ntohs(header->Length);
		if(length > data->size() - offset) {
			break;
		}
		if(length < sizeof(sIPFixHeader)) {
			if(strict) {
				break;
			}
			offset += sizeof(sIPFixHeader); 
			continue;
		}
		offset += length;
		++counter;
	} while(offset < data->size() &&
		data->size() - offset > sizeof(sIPFixHeader));
	return(strict ? offset == data->size() : counter > 0);
}

bool checkIPFixVersion(u_int16_t version) {
	extern vector<int> opt_ipfix_version;
	if(opt_ipfix_version.size()) {
		for(unsigned i = 0; i < opt_ipfix_version.size(); i++) {
			if(opt_ipfix_version[i] == version) {
				return(true);
			}
		}
	} else {
		return(version == IPFIX_VERSION_DEFAULT);
	}
	return(false);
}


void IPFix_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port) {
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
						cout << "ok write" << endl;
					}
				} else if(ppd.header_ip->get_saddr() == server_ip && ppd.header_ip->get_daddr() == client_ip) {
					cout << " <- " << flush;
					SimpleBuffer read_buffer;
					do {
						u_char buffer[10000];
						size_t read_length = sizeof(buffer);
						if(socket.read(buffer, &read_length)) {
							read_buffer.add(buffer, read_length);
						}
						if(checkIPFixData(&read_buffer, true)) {
							cout << "ok read" << endl;
							break;
						}
					} while(!socket.isError());
				}
			}
		}
	}
	if(header_packet) {
		DESTROY_HP(&header_packet);
	}
	pcap_close(handle);
}


static cIPFixServer *IPFixServer;

void IPFixServerStart(const char *host, int port) {
	if(IPFixServer) {
		delete IPFixServer;
	}
	IPFixServer =  new FILE_LINE(0) cIPFixServer;
	IPFixServer->setStartVerbString("START IPFIX LISTEN");
	IPFixServer->listen_start("ipfix_server", host, port);
}

void IPFixServerStop() {
	if(IPFixServer) {
		delete IPFixServer;
		IPFixServer = NULL;
	}
}
