#include "voipmonitor.h"

#include "ip_frag.h"

#include "sniff_inline.h"


#if not DEFRAG_MOD_OLDVER

cIpFrag::cIpFrag(unsigned fdata_threads_split) {
	this->fdata_threads_split = fdata_threads_split > 1 ? fdata_threads_split : 1;
	fdata = new sDefrag[this->fdata_threads_split];
}

cIpFrag::~cIpFrag() {
	cleanup(0, true, -1, 0);
	delete [] fdata;
}

void cIpFrag::cleanup(unsigned int tv_sec, bool all,
		      int pushToStack_queue_index, int cleanup_limit) {
	if(cleanup_limit < 0) {
		cleanup_limit = 30;
	}
	for(unsigned fdata_thread_index = 0; fdata_thread_index < fdata_threads_split; fdata_thread_index++) {
		for(map<pair<vmIP, u_int32_t>, sFrags*>::iterator it_d = fdata[fdata_thread_index].begin(); it_d != fdata[fdata_thread_index].end(); ) {
			sFrags *frags = it_d->second;
			if(frags->size() &&
			   (all ||
			    ((tv_sec - frags->begin()->second->ts) > cleanup_limit))) {
				for(map<u_int16_t, sFrag*>::iterator it_s = frags->begin(); it_s != frags->end(); it_s++) {
					#if INVITE_COUNTERS
					if(it_s->second->header_packet) {
						u_char *packet = HPP(it_s->second->header_packet);
						unsigned header_ip_offset = it_s->second->header_packet->header_ip_offset;
						unsigned caplen = HPH(it_s->second->header_packet)->caplen;
						iphdr2 *header_ip = (iphdr2*)(it_s->second->header_packet->packet + header_ip_offset);
						extern vmIP invite_counters_ip_src;
						extern vmIP invite_counters_ip_dst;
						extern volatile u_int64_t counter_12_defrag_error_2;
						if(header_ip &&
						   (!invite_counters_ip_src.isSet() || invite_counters_ip_src == header_ip->get_saddr()) &&
						   (!invite_counters_ip_dst.isSet() || invite_counters_ip_dst == header_ip->get_daddr())) {
							char *data = NULL;
							int datalen = 0;
							u_int8_t header_ip_protocol = 0;
							header_ip_protocol = header_ip->get_protocol(caplen - header_ip_offset);
							if(header_ip_protocol == IPPROTO_UDP) {
								udphdr2 *header_udp = (udphdr2*)((char*) header_ip + header_ip->get_hdr_size());
								datalen = get_udp_data_len(header_ip, header_udp, &data, packet, caplen);
							} else if(header_ip_protocol == IPPROTO_TCP) {
								tcphdr2 *header_tcp = (tcphdr2*)((char*)header_ip + header_ip->get_hdr_size());
								datalen = get_tcp_data_len(header_ip, header_tcp, &data, packet, caplen);
							}
							if(datalen > 6 && !strncasecmp(data, "INVITE", 6)) {
								ATOMIC_INC_RELAXED(counter_12_defrag_error_2);
							}
						}
					}
					#endif
					it_s->second->destroy(pushToStack_queue_index);
				}
				frags->clear();
			}
			if(!frags->size()) {
				fdata[fdata_thread_index].erase(it_d++);
				delete frags;
			} else {
				it_d++;
			}
		}
	}
}

#endif
