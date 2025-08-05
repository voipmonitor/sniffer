#include <net/ethernet.h> 

#include "rtp.h"

#include "sipgen.h"


#define SIPGEN_DEBUG 0
#define SUPPRESS_DUMP 0
#define PACKETS_COUNTER 1


static sgParams sg_params;


void sgParams::parse(const char *params) {
	if(!params) {
		cout << "need params in json notation" << endl
		     << "example: voipmonitor --sipgen='{\"interface\":\"eth1\"}'" << endl << endl;
		printParams();
		exit(1);
	}
	JsonItem jsonData;
	jsonData.parse(params);
	if(jsonData.getItem("pcap")) pcap = jsonData.getValue("pcap");
	if(jsonData.getItem("interface")) interface = jsonData.getValue("interface");
	if(jsonData.getItem("calls")) calls = atoi(jsonData.getValue("calls").c_str());
	if(jsonData.getItem("rtp")) rtp = yesno(jsonData.getValue("rtp").c_str());
	if(jsonData.getItem("threads")) threads = atoi(jsonData.getValue("threads").c_str());
	if(jsonData.getItem("max_time")) max_time = atoi(jsonData.getValue("max_time").c_str());
	if(jsonData.getItem("dur_rtp_min")) dur_rtp_min = atoi(jsonData.getValue("dur_rtp_min").c_str());
	if(jsonData.getItem("dur_rtp_max")) dur_rtp_max = atoi(jsonData.getValue("dur_rtp_max").c_str());
	if(jsonData.getItem("time_183_ms_min")) time_183_ms_min = atoi(jsonData.getValue("time_183_ms_min").c_str());
	if(jsonData.getItem("time_183_ms_max")) time_183_ms_max = atoi(jsonData.getValue("time_183_ms_max").c_str());
	if(jsonData.getItem("time_200_ms_min")) time_200_ms_min = atoi(jsonData.getValue("time_200_ms_min").c_str());
	if(jsonData.getItem("time_200_ms_max")) time_200_ms_max = atoi(jsonData.getValue("time_200_ms_max").c_str());
	if(jsonData.getItem("log_period")) log_period = atoi(jsonData.getValue("log_period").c_str());
}

void sgParams::check() {
	if(pcap.empty() && interface.empty()) {
		cout << "need set pcap or interface" << endl
		     << "example: voipmonitor --sipgen='{\"interface\":\"eth1\"}'" << endl << endl;
		printParams();
		exit(1);
	}
	if(threads < 1) {
		cout << "this is wrong: threads < 1 !!!" << endl;
		exit(1);
	}
	if(dur_rtp_min > dur_rtp_max) {
		cout << "this is wrong: dur_rtp_min > dur_rtp_max !!!" << endl;
		exit(1);
	}
	if(time_183_ms_min > time_183_ms_max) {
		cout << "this is wrong: time_183_ms_min > time_183_ms_max !!!" << endl;
		exit(1);
	}
	if(time_200_ms_min > time_200_ms_max) {
		cout << "this is wrong: time_200_ms_min > time_200_ms_max !!!" << endl;
		exit(1);
	}
}

void sgParams::printParams() {
	cout
	<< "params:" << endl
	<< " - pcap" << endl
	<< " - interface" << endl
	<< " - calls (default 80)" << endl
	<< " - rtp (yes/no - default yes)" << endl
	<< " - threads (default 4)" << endl
	<< " - max_time (default 0)" << endl
	<< " - dur_rtp_min (default 2s)" << endl
	<< " - dur_rtp_max (default 30s)" << endl
	<< " - time_183_ms_min (default 50ms)" << endl
	<< " - time_183_ms_max (default 1000ms)" << endl
	<< " - time_200_ms_min (default 100ms)" << endl
	<< " - time_200_ms_max (default 5000ms)" << endl
	<< " - log_period (default 2s)" << endl;
}

sgPackets::sgPackets() {
	max_time = TIME_MS_TO_US(100);
	pos = 0;
	first_time = 0;
	full = false;
}

sgPackets::~sgPackets() {
	for(vector<u_char*>::iterator iter = packets.begin(); iter != packets.end(); iter++) {
		delete [] *iter;
	}
}

sgPacketsQueue::sgPacketsQueue() {
	packets_in = NULL;
	sync = 0;
}

sgPacketsQueue::~sgPacketsQueue() {
	for(list<sgPackets*>::iterator iter = queue.begin(); iter != queue.end(); iter++) {
		delete *iter;
	}
}

void sgPacketsQueue::push(sgPackets *packets) {
	__SYNC_LOCK(sync);
	queue.push_back(packets);
	__SYNC_UNLOCK(sync);
}

sgPackets *sgPacketsQueue::pop() {
	sgPackets *rslt = NULL;
	__SYNC_LOCK(sync);
	if(queue.size()) {
		rslt = queue.front();
		queue.pop_front();
	}
	__SYNC_UNLOCK(sync);
	return(rslt);
}

sgPacketsDestroyQueue::sgPacketsDestroyQueue() {
	sync = 0;
}

sgPacketsDestroyQueue::~sgPacketsDestroyQueue() {
	destroy();
}

void sgPacketsDestroyQueue::push(sgPackets *packets) {
	__SYNC_LOCK(sync);
	queue.push_back(packets);
	__SYNC_UNLOCK(sync);
}

bool sgPacketsDestroyQueue::destroy() {
	bool rslt = false;
	__SYNC_LOCK(sync);
	if(queue.size()) {
		delete queue.front();
		queue.pop_front();
		rslt = true;
	}
	__SYNC_UNLOCK(sync);
	return(rslt);
}

sgMaster::sgMaster(unsigned count_calls_instances) 
 : count_calls_instances(count_calls_instances) {
	calls_instances = new FILE_LINE(0) sgCalls*[count_calls_instances];
	for(unsigned i = 0; i < count_calls_instances; i++) {
		calls_instances[i] = new FILE_LINE(0) sgCalls(
			this, i,
			("test_" + intToString(i + 1)).c_str(),
			str_2_vmIP(("192.168." + intToString(i + 1) + ".12").c_str()),
			str_2_vmIP(("192.168." + intToString(i + 1) + ".13").c_str()),
			str_2_vmIP(("192.168." + intToString(i + 1) + ".14").c_str()),
			str_2_vmIP(("192.168." + intToString(i + 1) + ".15").c_str()),
			5060 + i);
	}
	stats = new FILE_LINE(0) sStat[count_calls_instances];
	print_stat_last_at = 0;
	packets_pool = new FILE_LINE(0) sgPacketsPool(count_calls_instances * 2);
	time_delay = TIME_MS_TO_US(500);
	max_calls = 10;
	max_time = 10;
	dumper = NULL;
	end = false;
	terminating = false;
}

sgMaster::~sgMaster() {
	for(unsigned i = 0; i < count_calls_instances; i++) {
		delete calls_instances[i];
	}
	delete [] calls_instances;
	delete [] stats;
	delete packets_pool;
}

void sgMaster::set_start_params(unsigned max_calls, unsigned max_time) {
	this->max_calls = max_calls;
	this->max_time = max_time;
}

void sgMaster::set_dst_pcap(const char *pcap_filename) {
	this->pcap_filename = pcap_filename;
}

void sgMaster::set_interface(const char *interface) {
	this->interface = interface;
}

void sgMaster::start() {
	vm_pthread_create("destroy queue", &destroy_queue_thread, NULL, sgMaster::start_destroy_thread, this, __FILE__, __LINE__, false);
	vm_pthread_create("stat", &stat_thread, NULL, sgMaster::start_stat_thread, this, __FILE__, __LINE__, false);
	process();
}

void sgMaster::process() {
	if(!pcap_filename.empty()) {
		dumper = new FILE_LINE(0) PcapDumper(PcapDumper::na, NULL);
		dumper->setEnableAsyncWrite(false);
		dumper->setTypeCompress(FileZipHandler::compress_na);
		if(!dumper->open(tsf_na, pcap_filename.c_str(), DLT_EN10MB)) {
			cerr << "failed open " << pcap_filename << endl;
			exit(1);
		}
	}
	if(!interface.empty()) {
		for(unsigned i = 0; i < count_calls_instances; i++) {
			calls_instances[i]->set_interface(interface.c_str());
		}
	}
	for(unsigned i = 0; i < count_calls_instances; i++) {
		calls_instances[i]->start(max_calls, max_time, true);
	}
	bool empty = false;
	int last_ci_index = -1;
	do {
		empty = false;
		unsigned ci_index = (last_ci_index + 1) % count_calls_instances;
		sgPackets *packets = calls_instances[ci_index]->packets_queue.pop();
		if(!packets) {
			if(count_calls_instances > 1) {
				for(unsigned i = 0; i < count_calls_instances - 1; i++) {
					unsigned j = (ci_index + i) % count_calls_instances;
					packets = calls_instances[j]->packets_queue.pop();
					if(packets) {
						ci_index = j;
						break;
					}
				}
			}
		}
		if(packets) {
			int new_item_index = packets_pool->new_item();
			packets_pool->set(new_item_index, packets);
			sgPacketsPool::sMinHeapData minHeapData(new_item_index);
			packets_pool->minHeap->insert(minHeapData);
			last_ci_index = ci_index;
		} else {
			empty = true;
			usleep(100);
		}
		while(packets_pool->is_full() || (empty && end)) {
			int min_block_info_index = packets_pool->minHeap->getMin();
			if(min_block_info_index < 0) {
				break;
			}
			sgPackets *packets = packets_pool->items[min_block_info_index].packets;
			u_char *packet;
			u_int16_t size;
			u_int64_t time;
			packet = packets->get_packet(size, time);
			if(packet) {
				process_packet(packet, size, time);
			}
			if(packets->completed()) {
				packets_pool->free_item(min_block_info_index);
				packets_pool->minHeap->extractMin();
				destroy_queue.push(packets);
			} else {
				packets_pool->minHeap->doHeapify();
			}
		}
	} while(!empty || !end);
	if(dumper) {
		delete dumper;
	}
	terminating = true;
	pthread_join(destroy_queue_thread, NULL);
	pthread_join(stat_thread, NULL);
}

void sgMaster::process_packet(u_char *packet, u_int16_t size, u_int64_t time) {
	if(dumper) {
		pcap_pkthdr *header = sgCalls::create_pcap_pkthdr(time, size);
		#if not SUPPRESS_DUMP
		dumper->dump(header, packet, DLT_EN10MB);
		#endif
		delete header;
	}
}

void sgMaster::evEnd() {
	checkEnd();
}

void sgMaster::evStat(unsigned index, unsigned calls, unsigned packets_per_sec) {
	stats[index].calls = calls;
	stats[index].packets_per_sec = packets_per_sec;
}

void sgMaster::printStat() {
	bool data_completed = true;
	for(unsigned i = 0; i < count_calls_instances; i++) {
		if(!stats[i].calls) {
			data_completed =false;
			break;
		}
	}
	if(!data_completed) return;
	for(unsigned i = 0; i < count_calls_instances; i++) {
		if(i) cout << "; ";
		cout << "T" << (i + 1) << ": ";
		cout << stats[i].calls << " calls / " << stats[i].packets_per_sec << " p/s";
	}
	cout << endl;
}

void sgMaster::checkEnd() {
	unsigned count_end = 0;
	for(unsigned i = 0; i < count_calls_instances; i++) {
		if(calls_instances[i]->end) {
			++count_end;
		}
	}
	if(count_end == count_calls_instances) {
		end = true;
	}
}

void *sgMaster::start_destroy_thread(void *arg) {
	sgMaster *me = (sgMaster*)arg;
	me->destroy_thread();
	return(NULL);
}

void sgMaster::destroy_thread() {
	while(!terminating) {
		if(!destroy_queue.destroy()) {
			usleep(100);
		}
	}
}

void *sgMaster::start_stat_thread(void *arg) {
	sgMaster *me = (sgMaster*)arg;
	me->stat_thread_proc();
	return(NULL);
}

void sgMaster::stat_thread_proc() {
	while(!terminating) {
		u_int64_t time = TIME_MS_TO_US(getTimeMS_rdtsc());
		if(!print_stat_last_at) {
			print_stat_last_at = time;
		} else if(time >= print_stat_last_at + TIME_S_TO_US(sg_params.log_period)) {
			printStat();
			print_stat_last_at = time;
		}
		usleep(1000);
	}
}

sgCalls::sgCalls(sgMaster *master, unsigned master_index,
		 const char *callid_prefix,
		 vmIP sip_src_ip,
		 vmIP sip_dst_ip,
		 vmIP rtp_src_ip,
		 vmIP rtp_dst_ip,
		 vmPort sip_dst_port) 
 : master(master),
   master_index(master_index),
   callid_prefix(callid_prefix),
   sip_src_ip(sip_src_ip),
   sip_dst_ip(sip_dst_ip),
   rtp_src_ip(rtp_src_ip),
   rtp_dst_ip(rtp_dst_ip),
   sip_dst_port(sip_dst_port),
   sip_src_port_used(65535, 10000),
   rtp_src_port_used(65535 / 2, 10000 / 2),
   rtp_dst_port_used(65535 / 2, 10000 / 2) {
	dumper = NULL;
	pcap = NULL;
	end = false;
	packets_counter = 0;
	packets_counter_last_time = 0;
}

sgCalls::~sgCalls() {
	for(map<string, sgCall*>::iterator iter = calls.begin(); iter != calls.end(); iter++) {
		delete iter->second;
	}
}

void sgCalls::start(unsigned max_calls, unsigned max_time, bool run_in_thread) {
	this->max_calls = max_calls;
	this->max_time = max_time;
	if(run_in_thread) {
		vm_pthread_create("sgCalls process", &thread, NULL, sgCalls::start_process, this, __FILE__, __LINE__, true);
	} else {
		process();
	}
}

void *sgCalls::start_process(void *arg) {
	sgCalls *calls = (sgCalls*)arg;
	calls->process();
	return(NULL);
}

void sgCalls::process() {
	if(!pcap_filename.empty()) {
		dumper = new FILE_LINE(0) PcapDumper(PcapDumper::na, NULL);
		dumper->setEnableAsyncWrite(false);
		dumper->setTypeCompress(FileZipHandler::compress_na);
		if(!dumper->open(tsf_na, pcap_filename.c_str(), DLT_EN10MB)) {
			cerr << "failed open: " << pcap_filename << endl;
			exit(1);
		}
	} else if(!interface.empty()) {
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap = pcap_open_live(interface.c_str(), 65536, 0, 0, errbuf);
		if (!pcap) {
			cerr << "failed open: " << interface << endl;
			exit(1);
		}
	}
	u_int64_t begin_time = TIME_MS_TO_US(getTimeMS_rdtsc());
	while(true) {
		if(calls.size() < max_calls) {
			newCall();
		}
		u_int64_t time = TIME_MS_TO_US(getTimeMS_rdtsc());
		bool exists_process = false;
		for(map<string, sgCall*>::iterator iter = calls.begin(); iter != calls.end();) {
			u_int16_t packets = 0;
			sgCall::eRsltProcess rslt = iter->second->process_state(time, packets);
			if(rslt != sgCall::rslt_end) {
				if(rslt != sgCall::rslt_na) {
					exists_process = true;
					#if PACKETS_COUNTER
					packets_counter += packets;
					if(!packets_counter_last_time) {
						packets_counter_last_time = time;
					} else if(time >= packets_counter_last_time + TIME_S_TO_US(1)) {
						if(master) {
							master->evStat(master_index, calls.size(), packets_counter);
						} else {
							cout << "calls: " << calls.size() << " / p/s: " << packets_counter << endl;
						}
						packets_counter = 0;
						packets_counter_last_time = time;
					}
					#endif
				}
				iter++;
			} else {
				delete iter->second;
				calls.erase(iter++);
			}
		}
		if(!exists_process) {
			usleep(100);
		}
		if((max_time && time > begin_time + TIME_S_TO_US(max_time)) ||
		   is_terminating()) {
			break;
		}
	}
	if(dumper) {
		delete dumper;
	} else if(pcap) {
		pcap_close(pcap);
	} else {
		packets_queue.force_push();
	}
	end = true;
	if(master) {
		master->evEnd();
	}
}

void sgCalls::set_dst_pcap(const char *pcap_filename) {
	this->pcap_filename = pcap_filename;
}

void sgCalls::set_interface(const char *interface) {
	this->interface = interface;
}

u_char *sgCalls::create_udp_packet(u_char *data, unsigned int data_len,
				   vmIPport *src, vmIPport *dst,
				   unsigned *packet_len) {
	unsigned iphdr_size = 
		#if VM_IPV6
		src->ip.is_v6() ? 
		 sizeof(ip6hdr2) : 
		#endif
		 sizeof(iphdr2);
	*packet_len = sizeof(ether_header) + iphdr_size + sizeof(udphdr2) + data_len;
	u_char *packet = new FILE_LINE(38022) u_char[*packet_len];
	ether_header *header_eth = (ether_header*)packet;
	memset(header_eth, 0, sizeof(ether_header));
	
	#if VM_IPV6
	if(src->ip.is_v6()) {
		header_eth->ether_type = htons(ETHERTYPE_IPV6);
		ip6hdr2 *iphdr = (ip6hdr2*)(packet + sizeof(ether_header)); 
		memset(iphdr, 0, iphdr_size);
		iphdr->version = 6;
		iphdr->nxt = IPPROTO_UDP;
		iphdr->set_saddr(src->ip);
		iphdr->set_daddr(dst->ip);
		iphdr->set_tot_len(iphdr_size + sizeof(udphdr2) + data_len);
	} else  {
	#endif
		header_eth->ether_type = htons(ETHERTYPE_IP);
		iphdr2 *iphdr = (iphdr2*)(packet + sizeof(ether_header)); 
		memset(iphdr, 0, iphdr_size);
		iphdr->version = 4;
		iphdr->_ihl = 5;
		iphdr->_protocol = IPPROTO_UDP;
		iphdr->set_saddr(src->ip);
		iphdr->set_daddr(dst->ip);
		iphdr->set_tot_len(iphdr_size + sizeof(udphdr2) + data_len);
		iphdr->_ttl = 50;
	#if VM_IPV6
	}
	#endif
	udphdr2 *udphdr = (udphdr2*)(packet + sizeof(ether_header) + iphdr_size);
	memset(udphdr, 0, sizeof(udphdr2));
	udphdr->set_source(src->port);
	udphdr->set_dest(dst->port);
	udphdr->len = htons(sizeof(udphdr2) + data_len);
	memcpy(packet + sizeof(ether_header) + iphdr_size + sizeof(udphdr2), data, data_len);
	return(packet);
}

pcap_pkthdr *sgCalls::create_pcap_pkthdr(u_int64_t time, unsigned packet_len) {
	pcap_pkthdr *header = new FILE_LINE(0) pcap_pkthdr;
	header->ts.tv_sec = time / 1000000;
	header->ts.tv_usec = time % 1000000;
	header->caplen = packet_len;
	header->len = packet_len;
	return(header);
}

void sgCalls::newCall() {
	sgCall *call = new FILE_LINE(0) sgCall(this);
	calls[call->callid] = call;
}

void sgCalls::sendPacket(u_char *data, unsigned data_len,
			 vmIPport *src, vmIPport *dst, u_int64_t time) {
	unsigned packet_len;
	u_char *packet = create_udp_packet(data, data_len,
					   src, dst,
					   &packet_len);
	if(dumper) {
		pcap_pkthdr *header = create_pcap_pkthdr(time, packet_len);
		#if not SUPPRESS_DUMP
		dumper->dump(header, packet, DLT_EN10MB);
		#endif
		delete [] packet;
		delete header;
	} else if(pcap) {
		if(pcap_sendpacket(pcap, packet, packet_len) != 0) {
			cerr << "failed pcap_sendpacket: " << pcap_geterr(pcap) << endl;
		}
		packets_queue.add(packet, packet_len, time);
	} else {
		packets_queue.add(packet, packet_len, time);
	}
}

sgCall::sgCall(sgCalls *calls)
 : calls(calls) {
	do {
		callid = create_callid();
	} while(calls->calls.find(callid) != calls->calls.end());
	from = create_number();
	from_domain = create_domain();
	from_tag = create_tag();
	to = create_number();
	to_domain = create_domain();
	to_tag = create_tag();
	ua_src = "Linphone";
	cseq_invite = 1 + rand() % 1000;
	cseq_bye = 1 + rand() % 1000;
	sip_src = vmIPport(calls->sip_src_ip, calls->sip_src_port_used.get());
	sip_dst = vmIPport(calls->sip_dst_ip, calls->sip_dst_port);
	rtp_src = vmIPport(calls->rtp_src_ip, calls->rtp_src_port_used.get() * 2);
	rtp_dst = vmIPport(calls->rtp_dst_ip, calls->rtp_dst_port_used.get() * 2);
	stream_a = new sgStream(this, 0);
	stream_b = new sgStream(this, 1);
	state = state_na;
	last_state_at = 0;
	next_state = state_invite;
	next_state_at = 0;
	invite_at = 0;
	begin_streams_at = 0;
	streams_duration = TIME_S_TO_US(sg_params.dur_rtp_min + rand() % (sg_params.dur_rtp_max - sg_params.dur_rtp_min + 1));
}

sgCall::~sgCall() {
	calls->sip_src_port_used.free(sip_src.port);
	calls->rtp_src_port_used.free(rtp_src.port / 2);
	calls->rtp_dst_port_used.free(rtp_dst.port / 2);
	delete stream_a;
	delete stream_b;
}

string sgCall::create_callid() {
	const char charset[] = "abcdefghijklmnopqrstuvwxyz"
			       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			       "0123456789";
	return(calls->callid_prefix + "_" + rand_str(charset, sizeof(charset) - 1, 10, 20));
}

string sgCall::create_number() {
	const char charset[] = "0123456789";
	return(rand_str(charset, sizeof(charset) - 1, 6, 12));
}

string sgCall::create_domain() {
	const char charset[] = "abcdefghijklmnopqrstuvwxyz";
	return("sip." + rand_str(charset, sizeof(charset) - 1, 4, 10) + ".net");
}

string sgCall::create_tag() {
	const char charset[] = "abcdefghijklmnopqrstuvwxyz"
			       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			       "0123456789";
	return(rand_str(charset, sizeof(charset) - 1, 10, 20));
}

sgCall::eRsltProcess sgCall::process_state(u_int64_t time, u_int16_t &packets) {
	if(next_state == state_end) {
		return(rslt_end);
	}
	if(!(state == state_na || (next_state_at && time >= next_state_at))) {
		return(rslt_na);
	}
	eRsltProcess rslt = rslt_na;
	state = next_state;
	last_state_at = time;
	if(state == state_streams) {
		if(!begin_streams_at) {
			begin_streams_at = time;
		}
		if(sg_params.rtp) {
			create_rtp_packets(time);
			packets = 2;
			rslt = rslt_rtp;
		} else {
			rslt = rslt_rtp_skip;
		}
	} else {
		create_sip_packet(time);
		packets = 1;
		rslt = rslt_sip;
	}
	set_next_state();
	return(rslt);
}

void sgCall::set_next_state() {
	switch(state) {
	case state_na:
		last_state_at = TIME_MS_TO_US(getTimeMS_rdtsc());
		next_state = state_invite;
		next_state_at = last_state_at;
		break;
	case state_invite:
		next_state = state_100;
		next_state_at = last_state_at + TIME_MS_TO_US(10 + rand() % 10);
		break;
	case state_100:
		next_state = state_183;
		next_state_at = last_state_at + TIME_MS_TO_US(250 + rand() % 250);
		break;
	case state_183:
		next_state = state_invite_ok;
		next_state_at = last_state_at + TIME_MS_TO_US(sg_params.time_183_ms_min + rand() % (sg_params.time_183_ms_max - sg_params.time_183_ms_min + 1));
		break;
	case state_invite_ok:
		next_state = state_ack;
		next_state_at = last_state_at + TIME_MS_TO_US(sg_params.time_200_ms_min + rand() % (sg_params.time_200_ms_max - sg_params.time_200_ms_min + 1));
		break;
	case state_ack:
		next_state = state_streams;
		next_state_at = last_state_at + TIME_MS_TO_US(20 + rand() % 20);
		break;
	case state_streams:
		next_state = last_state_at > begin_streams_at && last_state_at - begin_streams_at > streams_duration ?
			      state_bye :
			      state_streams;
		next_state_at = last_state_at + TIME_MS_TO_US(20);
		break;
	case state_bye:
		next_state = state_bye_ok;
		next_state_at = last_state_at + TIME_MS_TO_US(20 + rand() % 20);
		break;
	case state_bye_ok:
		next_state = state_end;
		next_state_at = 0;
		break;
	case state_end:
	default:
		break;
	}
	if(next_state_at) {
		next_state_at = ((next_state_at + 5000 - 1) / 5000) * 5000;
	}
}

void sgCall::create_sip_packet(u_int64_t time) {
	string sip = create_sip(state);
	u_int8_t dir = direction(state);
	calls->sendPacket((u_char*)sip.c_str(), sip.length(),
			  dir ? &sip_dst : &sip_src,
			  dir ? &sip_src : &sip_dst,
			  time);
	#if SIPGEN_DEBUG
	cout << sip << endl;
	#endif
}

void sgCall::create_rtp_packets(u_int64_t time) {
	stream_a->create_rtp_packet(time);
	stream_b->create_rtp_packet(time);
}

string sgCall::create_sip_invite() {
	string content =
string("v=0\r\n") +
"o=" + from + " 1477 2440 IN IP4 " + rtp_src.ip.getString() + "\r\n" +
"s=Talk\r\n" +
"c=IN IP4 " + rtp_src.ip.getString() + "\r\n" +
"t=0 0\r\n" +
"m=audio " + rtp_src.port.getString() + " RTP/AVP 125 112 111 110 96 3 0 8 101\r\n" +
"a=rtpmap:125 opus/48000\r\n" +
"a=fmtp:125 useinbandfec=1; usedtx=1\r\n" +
"a=rtpmap:112 speex/32000\r\n" +
"a=fmtp:112 vbr=on\r\n" +
"a=rtpmap:111 speex/16000\r\n" +
"a=fmtp:111 vbr=on\r\n" +
"a=rtpmap:110 speex/8000\r\n" +
"a=fmtp:110 vbr=on\r\n" +
"a=rtpmap:96 GSM/11025\r\n" +
"a=rtpmap:101 telephone-event/8000\r\n" +
"a=fmtp:101 0-11\r\n" +
"m=video 9078 RTP/AVP 103\r\n" +
"a=rtpmap:103 VP8/90000\r\n";
	return(
"INVITE sip:" + to + "@" + to_domain + " SIP/2.0\r\n" +
//Via: SIP/2.0/UDP 192.168.1.12:5061;rport;branch=z9hG4bK1610895315
"From: <sip:" + from + "@" + from_domain + ">;tag=" + from_tag + "\r\n" +
"To: <sip:" + to + "@" + to_domain + ">\r\n" +
"Call-ID: " + callid + "\r\n" +
"CSeq: " + intToString(cseq_invite) + " INVITE\r\n" +
"Contact: <sip:" + from + "@" + from_domain + ">\r\n" +
//Proxy-Authorization: Digest username="706912", realm="sip.odorik.cz", nonce="VRqjSFUaohz+9rYdM3y1ZKoD3WSgG8mZ", uri="sip:800123456@sip.odorik.cz", response="e87b11be6e9f700476b233b14c23c2c2", algorithm=MD5
"Content-Type: application/sdp\r\n" + 
"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n" + 
"Max-Forwards: 70\r\n" + 
"User-Agent: " + ua_src + "\r\n" + 
"Subject: Phone call\r\n" + 
"Content-Length: " + intToString(content.size()) + "\r\n" + 
"\r\n" + 
content);
}

string sgCall::create_sip_100() {
	return(
string("SIP/2.0 100 Trying\r\n") +
//Via: SIP/2.0/UDP 192.168.1.12:5061;rport=5061;branch=z9hG4bK1610895315;received=93.91.52.46
"From: <sip:" + from + "@" + from_domain + ">;tag=" + from_tag + "\r\n" +
"To: <sip:" + to + "@" + to_domain + ">\r\n" +
"Call-ID: " + callid + "\r\n" +
"CSeq: " + intToString(cseq_invite) + " INVITE\r\n" +
"Content-Length: 0\r\n" +
"\r\n");
}

string sgCall::create_sip_183() {
	return(
string("SIP/2.0 183 Session Progress\r\n") +
//Via: SIP/2.0/UDP 192.168.1.12:5061;received=93.91.52.46;rport=5061;branch=z9hG4bK1610895315
//Record-Route: <sip:800123456@81.31.45.51;lr=on;ftag=1645803335;did=ea91.2b2f;nat=yes>
"From: <sip:" + from + "@" + from_domain + ">;tag=" + from_tag + "\r\n" +
"To: <sip:" + to + "@" + to_domain + ">;tag=" + to_tag + "\r\n" +
"Call-ID: " + callid + "\r\n" +
"CSeq: " + intToString(cseq_invite) + " INVITE\r\n" +
"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\n" +
"Supported: replaces\r\n" +
"Contact: <sip:" + to + "@" + to_domain + ">\r\n" +
"Content-Length: 0\r\n" +
"\r\n");
}

string sgCall::create_sip_invite_ok() {
	string content =
string("v=0\r\n") +
"o=root 1314528731 1314528732 IN IP4 " + rtp_dst.ip.getString() + "\r\n" +
//s=Odorik_UAC
"c=IN IP4 " + rtp_dst.ip.getString() + "\r\n" +
"t=0 0\r\n" +
"m=audio " + rtp_dst.port.getString() + " RTP/AVP 8 110 3 101\r\n" +
"a=rtpmap:8 PCMA/8000\r\n" +
"a=rtpmap:110 speex/8000\r\n" +
"a=rtpmap:3 GSM/8000\r\n" +
"a=rtpmap:101 telephone-event/8000\r\n" +
"a=fmtp:101 0-16\r\n" +
"a=silenceSupp:off - - - -\r\n" +
"a=ptime:20\r\n" +
"a=sendrecv\r\n";
	return(
string("SIP/2.0 200 OK\r\n") + 
//Via: SIP/2.0/UDP 192.168.1.12:5061;received=93.91.52.46;rport=5061;branch=z9hG4bK1610895315
//Record-Route: <sip:800123456@81.31.45.51;lr=on;ftag=1645803335;did=ea91.2b2f;nat=yes>
"From: <sip:" + from + "@" + from_domain + ">;tag=" + from_tag + "\r\n" +
"To: <sip:" + to + "@" + to_domain + ">;tag=" + to_tag + "\r\n" +
"Call-ID: " + callid + "\r\n" +
"CSeq: " + intToString(cseq_invite) + " INVITE\r\n" +
//Server: Odorik_UAC
"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\n" +
"Supported: replaces\r\n" +
"Contact: <sip:" + to + "@" + to_domain + ">\r\n" +
"Content-Type: application/sdp\r\n" +
"Content-Length: " + intToString(content.size()) + "\r\n" + 
"\r\n" + 
content);
}

string sgCall::create_sip_ack() {
	return(
"ACK sip:" + to + "@" + to_domain + " SIP/2.0\r\n" +
//Via: SIP/2.0/UDP 192.168.1.12:5061;rport;branch=z9hG4bK349703257
//Route: <sip:800123456@81.31.45.51;lr=on;ftag=1645803335;did=ea91.2b2f;nat=yes>
"From: <sip:" + from + "@" + from_domain + ">;tag=" + from_tag + "\r\n" +
"To: <sip:" + to + "@" + to_domain + ">;tag=" + to_tag + "\r\n" +
"Call-ID: " + callid + "\r\n" +
"CSeq: " + intToString(cseq_invite) + " INVITE\r\n" +
"Contact: <sip:" + from + "@" + from_domain + ">\r\n" +
//Proxy-Authorization: Digest username="706912", realm="sip.odorik.cz", nonce="VRqjSFUaohz+9rYdM3y1ZKoD3WSgG8mZ", uri="sip:800123456@sip.odorik.cz", response="e87b11be6e9f700476b233b14c23c2c2", algorithm=MD5
"Max-Forwards: 70\r\n" +
"User-Agent: " + ua_src + "\r\n" +
"Content-Length: 0\r\n" +
"\r\n");
}

string sgCall::create_sip_bye() {
	return(
"BYE sip:" + to + "@" + to_domain + " SIP/2.0\r\n" +
//Via: SIP/2.0/UDP 192.168.1.12:5061;rport;branch=z9hG4bK1228041609
//Route: <sip:800123456@81.31.45.51;lr=on;ftag=1645803335;did=ea91.2b2f;nat=yes>
"From: <sip:" + from + "@" + from_domain + ">;tag=" + from_tag + "\r\n" +
"To: <sip:" + to + "@" + to_domain + ">;tag=" + to_tag + "\r\n" +
"Call-ID: " + callid + "\r\n" +
"CSeq: " + intToString(cseq_bye) + " BYE\r\n" +
"Contact: <sip:" + from + "@" + from_domain + ">\r\n" +
//Proxy-Authorization: Digest username="706912", realm="sip.odorik.cz", nonce="VRqjSFUaohz+9rYdM3y1ZKoD3WSgG8mZ", uri="sip:00420800123456@81.31.45.56:5060;alias=81.31.45.56~5060~1", response="e16a1f557905e2e318d1b683dc7b251d", algorithm=MD5
"Max-Forwards: 70\r\n" +
"User-Agent: " + ua_src + "\r\n" +
"Content-Length: 0\r\n" +
"\r\n");
}

string sgCall::create_sip_bye_ok() {
	return(
string("SIP/2.0 200 OK\r\n") +
//Via: SIP/2.0/UDP 192.168.1.12:5061;received=93.91.52.46;rport=5061;branch=z9hG4bK1228041609
"From: <sip:" + from + "@" + from_domain + ">;tag=" + from_tag + "\r\n" +
"To: <sip:" + to + "@" + to_domain + ">;tag=" + to_tag + "\r\n" +
"Call-ID: " + callid + "\r\n" +
"CSeq: " + intToString(cseq_bye) + " BYE\r\n" +
//Server: Odorik_UAC
"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH\r\n" +
"Supported: replaces\r\n" +
"Content-Length: 0\r\n" +
"\r\n");
}

string sgCall::create_sip(eState state) {
	switch(state) {
	case state_invite:
		return(create_sip_invite());
	case state_100:
		return(create_sip_100());
	case state_183:
		return(create_sip_183());
	case state_invite_ok:
		return(create_sip_invite_ok());
	case state_ack:
		return(create_sip_ack());
	case state_bye:
		return(create_sip_bye());
	case state_bye_ok:
		return(create_sip_bye_ok());
	default:
		break;
	}
	return("");
}

u_int8_t sgCall::direction(eState state) {
	switch(state) {
	case state_100:
	case state_183:
	case state_invite_ok:
	case state_bye_ok:
		return(1);
	default:
		break;
	}
	return(0);
}

sgStream::sgStream(sgCall *call, u_int8_t direction) 
 : call(call),
   direction(direction) {
	do {
		ssrc = ((u_int32_t)(rand() & 0xFFFF) << 16) | (u_int32_t)(rand() & 0xFFFF);
	} while(call->calls->ssrc_used.find(ssrc) != call->calls->ssrc_used.end());
	call->calls->ssrc_used.insert(ssrc);
	seq = 1;
	ts = 0;
}

sgStream::~sgStream() {
	call->calls->ssrc_used.erase(ssrc);
}

void sgStream::create_rtp_packet(u_int64_t time) {
	u_char rtp_data[sizeof(RTPFixedHeader) + 160];
	RTPFixedHeader *header = (RTPFixedHeader*)rtp_data;
	memset(header, 0, sizeof(RTPFixedHeader));
	header->version = 2;
	header->payload = 8;
	header->sequence = htons(seq);
	header->timestamp = htonl(ts);
	header->sources[0] = htonl(ssrc);
	call->calls->sendPacket(rtp_data, sizeof(rtp_data),
				direction ? &call->rtp_dst : &call->rtp_src,
				direction ? &call->rtp_src : &call->rtp_dst,
				time);
	#if SIPGEN_DEBUG
	cout << "RTP" 
	     << " ssrc:" << hex << ssrc << dec
	     << " seq:" << seq 
	     << " ts:" << ts
	     << endl;
	#endif     
	++seq;
	ts += 160;
}

void sg(const char *params) {
	sg_params.parse(params);
	sg_params.check();
	sverb.thread_create = true;
	sgMaster *sg_master = new FILE_LINE(0) sgMaster(sg_params.threads);
	if(!sg_params.pcap.empty()) {
		sg_master->set_dst_pcap(sg_params.pcap.c_str());
	} else if(!sg_params.interface.empty()) {
		sg_master->set_interface(sg_params.interface.c_str());
	}
	sg_master->set_start_params(sg_params.calls / sg_params.threads, sg_params.max_time);
	sg_master->start();
	delete sg_master;
}

void sg_test() {
	sverb.thread_create = true;
	bool single_process = false;
	if(single_process) {
		sgCalls *sgc = new FILE_LINE(0) sgCalls(
			NULL, 0,
			"test01",
			str_2_vmIP("192.168.1.12"),
			str_2_vmIP("192.168.1.13"),
			str_2_vmIP("192.168.1.14"),
			str_2_vmIP("192.168.1.15"),
			5060);
		//sgc->set_dst_pcap("/home/jumbox/Plocha/test01.pcap");
		sgc->set_interface("eth1");
		sgc->start(5000, 300, false);
		delete sgc;
	} else {
		sgMaster *sg_master = new FILE_LINE(0) sgMaster(6);
		//sg_master->set_dst_pcap("/home/jumbox/Plocha/test01.pcap");
		sg_master->set_interface("eth1");
		sg_master->set_start_params(2000, 300);
		sg_master->start();
		delete sg_master;
	}
}
