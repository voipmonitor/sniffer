#include "voipmonitor.h"

#include "ribbonsbc.h"
#include "tools.h"
#include "header_packet.h"
#include "sniff_inline.h"
#include "sniff_proc_class.h"

#include <pcap.h>


extern string opt_ribbonsbc_bind_ip;
extern unsigned opt_ribbonsbc_bind_port;
extern bool opt_ribbonsbc_bind_udp;
extern bool opt_ribbonsbc_counter_log;
extern bool opt_ribbonsbc_via_pb;
extern bool opt_ribbonsbc_size_header;
extern bool opt_ribbonsbc_strict_check;
extern int opt_t2_boost;

cRibbonSbcCounter ribbonsbc_counter;

static cRibbonSbc_Server *RibbonSbc_Server;


cRibbonSbc_ProcessData::cRibbonSbc_ProcessData() 
 : cTimer(NULL) {
	data_buffer_add_counter = 0;
	block_store = NULL;
	block_store_sync = 0;
	if(opt_t2_boost && opt_ribbonsbc_via_pb) {
		setEveryMS(100);
		start();
	}
}

void cRibbonSbc_ProcessData::processData(u_char *data, size_t dataLen, vmIP ip, vmPort port) {
	if(opt_ribbonsbc_counter_log && ip.isSet()) {
		 ribbonsbc_counter.inc(ip);
	}
	if(opt_ribbonsbc_size_header) {
		data_buffer.add(data, dataLen);
		++data_buffer_add_counter;
		if(opt_ribbonsbc_strict_check) {
			if(checkCompleteData(data_buffer.data(), data_buffer.size())) {
				u_char *_data = data_buffer.data();
				size_t _dataLen = data_buffer.size();
				while(_dataLen > 2 &&
				      ntohs(*(u_int16_t*)_data) + 2u <= _dataLen) {
					size_t _dataSegmentLen = ntohs(*(u_int16_t*)_data);
					createPacket(_data + 2, _dataSegmentLen, 
						     ip, port, RibbonSbc_Server->getListenSocketIP(), RibbonSbc_Server->getListenSocketPort());
					_data += _dataSegmentLen + 2;
					_dataLen -= _dataSegmentLen + 2;
				}
				data_buffer.clear();
				data_buffer_add_counter = 0;
			} else if(data_buffer_add_counter > 10) {
				data_buffer.clear();
				data_buffer_add_counter = 0;
				syslog(LOG_NOTICE, "RIBBONSBC: Unable to verify data completeness - discarding data on length %u", data_buffer.size());
			}
		} else {
			while(data_buffer.size() > 2 &&
			      ntohs(*(u_int16_t*)data_buffer.data()) + 2u <= data_buffer.size()) {
				size_t _dataSegmentLen = ntohs(*(u_int16_t*)data_buffer.data());
				createPacket(data_buffer.data() + 2, _dataSegmentLen,
					     ip, port, RibbonSbc_Server->getListenSocketIP(), RibbonSbc_Server->getListenSocketPort());
				data_buffer.removeDataFromLeft(_dataSegmentLen + 2);
			}
			if(!data_buffer.size()) {
				data_buffer_add_counter = 0;
			}
			if(data_buffer.size() > 1024 * 1024) {
				data_buffer.clear();
				data_buffer_add_counter = 0;
				syslog(LOG_NOTICE, "RIBBONSBC data exceeded the limit of 1MB. Check the HEP data sent.");
			}
		}
	} else {
		createPacket(data, dataLen,
			     ip, port, RibbonSbc_Server->getListenSocketIP(), RibbonSbc_Server->getListenSocketPort());
	}
}

bool cRibbonSbc_ProcessData::checkCompleteData(u_char *data, size_t dataLen) {
	u_char *_data = data;
	size_t _dataLen = dataLen;
	while(_dataLen > 2 &&
	      ntohs(*(u_int16_t*)_data) + 2u <= _dataLen) {
		size_t _dataSegmentLen = ntohs(*(u_int16_t*)_data);
		_data += _dataSegmentLen + 2;
		_dataLen -= _dataSegmentLen + 2;
	}
	return(_dataLen == 0);
}

void cRibbonSbc_ProcessData::createPacket(u_char *data, size_t dataLen,
					  vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port) {
	const char *src_ip_port_str = strncasestr((char*)data, "srcip:", dataLen);
	if(src_ip_port_str) {
		vmIPport src_ip_port;
		if(src_ip_port.setFromString(src_ip_port_str + 6)) {
			src_ip = src_ip_port.ip;
			src_port = src_ip_port.port;
		}
	}
	const char *dst_ip_port_str = strncasestr((char*)data, "dstip:", dataLen);
	if(dst_ip_port_str) {
		vmIPport dst_ip_port;
		if(dst_ip_port.setFromString(dst_ip_port_str + 6)) {
			dst_ip = dst_ip_port.ip;
			dst_port = dst_ip_port.port;
		}
	}
	int dlink = PcapDumper::get_global_pcap_dlink_en10();
	int pcap_handle_index = PcapDumper::get_global_handle_index_en10();
	ether_header header_eth;
	memset(&header_eth, 0, sizeof(header_eth));
	header_eth.ether_type = htons(src_ip.is_v6() ? ETHERTYPE_IPV6 : ETHERTYPE_IP);
	timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	pcap_pkthdr *udpHeader;
	u_char *udpPacket;
	createSimpleUdpDataPacket(sizeof(header_eth), &udpHeader,  &udpPacket,
				  (u_char*)&header_eth, data, dataLen, 0,
				  src_ip, dst_ip, src_port, dst_port,
				  time.tv_sec, time.tv_nsec / 1000);
	pushPacket(udpHeader, udpPacket, dataLen, false,
		   src_ip, src_port, dst_ip, dst_port,
		   dlink, pcap_handle_index);
}

void cRibbonSbc_ProcessData::pushPacket(pcap_pkthdr *header, u_char *packet, unsigned dataLen, bool tcp,
					vmIP src_ip, vmPort src_port, vmIP dst_ip, vmPort dst_port,
					int dlink, int pcap_handle_index) {
	if(opt_t2_boost && opt_ribbonsbc_via_pb) {
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
				dataOffset, dataLen,
				src_port, dst_port,
				pflags,
				&hp,
				pcap_handle_index);
		} else {
			preProcessPacket[PreProcessPacket::ppt_detach]->push_packet(
				#if USE_PACKET_NUMBER
				0, 
				#endif
				src_ip, src_port, dst_ip, dst_port, 
				dataLen, dataOffset,
				pcap_handle_index, header, packet, _t_packet_alloc_header_std, 
				pflags, (iphdr2*)(packet + sizeof(ether_header)), (iphdr2*)(packet + sizeof(ether_header)),
				NULL, 0, dlink, opt_id_sensor, vmIP(), pid,
				false);
		}
	}
}

void cRibbonSbc_ProcessData::evTimer(u_int32_t /*time_s*/, int /*typeTimer*/, void */*data*/) {
	block_store_lock();
	if(block_store && block_store->isFull_checkTimeout_ext(100)) {
		extern PcapQueue_readFromFifo *pcapQueueQ;
		pcapQueueQ->addBlockStoreToPcapStoreQueue_ext(block_store);
		block_store = NULL;
	}
	block_store_unlock();
}


cRibbonSbc_Server::cRibbonSbc_Server(bool udp) 
 : cServer(udp, true) {
}

cRibbonSbc_Server::~cRibbonSbc_Server() {
}

void cRibbonSbc_Server::createConnection(cSocket *socket) {
	if(is_terminating()) {
		return;
	}
	cRibbonSbc_Connection *connection = new FILE_LINE(0) cRibbonSbc_Connection(socket);
	connection->connection_start();
}

void cRibbonSbc_Server::evData(u_char *data, size_t dataLen, vmIP ip, vmPort port, vmIP local_ip, vmPort local_port, cSocket *socket) {
	processData(data, dataLen, ip);
}


cRibbonSbc_Connection::cRibbonSbc_Connection(cSocket *socket) 
 : cServerConnection(socket, true) {
}

cRibbonSbc_Connection::~cRibbonSbc_Connection() {
}

void cRibbonSbc_Connection::evData(u_char *data, size_t dataLen) {
	processData(data, dataLen, socket->getIPL(), socket->getPort());
}

void cRibbonSbc_Connection::connection_process() {
	cServerConnection::connection_process();
	delete this;
}


string cRibbonSbcCounter::get_ip_counter() {
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

u_int64_t cRibbonSbcCounter::get_sum_counter() {
	u_int64_t sum = 0;
	lock();
	for(map<vmIP, u_int64_t>::iterator iter = ip_counter.begin(); iter != ip_counter.end(); iter++) {
		sum += iter->second;
	}
	unlock();
	return(sum);
}


void RibbonSbc_ServerStart(const char *host, int port, bool udp) {
	if(RibbonSbc_Server) {
		delete RibbonSbc_Server;
	}
	RibbonSbc_Server =  new FILE_LINE(0) cRibbonSbc_Server(udp);
	RibbonSbc_Server->setStartVerbString("START RIBBONSBC LISTEN");
	RibbonSbc_Server->listen_start("ribbonsbc_server", host, port);
}

void RibbonSbc_ServerStop() {
	if(RibbonSbc_Server) {
		delete RibbonSbc_Server;
		RibbonSbc_Server = NULL;
	}
}


void RibbonSbc_client_emulation(const char *pcap, vmIP client_ip, vmIP server_ip, vmIP destination_ip, vmPort destination_port, bool udp) {
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
	cSocket socket("RibbonSbc_client_emulation");
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
				} else {
					cout << "unknown ip: " << ppd.header_ip->get_saddr().getString() << " -> " <<ppd.header_ip->get_daddr().getString() << endl;
				}
			}
		}
	}
	if(header_packet) {
		DESTROY_HP(&header_packet);
	}
	pcap_close(handle);
}
