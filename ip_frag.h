#ifndef IP_FRAG_H
#define IP_FRAG_H

#include <net/ethernet.h>

#include "header_packet.h"

struct ip_frag_s {
	sHeaderPacket *header_packet;
	void *header_packet_pqout;
	unsigned int header_ip_offset;
	time_t ts;
	u_int32_t offset;
	u_int32_t len;
	u_int16_t iphdr_len;
};

typedef map<unsigned int, ip_frag_s*> ip_frag_queue_t;
typedef map<unsigned int, ip_frag_s*>::iterator ip_frag_queue_it_t;

struct ip_frag_queue : ip_frag_queue_t {
	ip_frag_queue() {
		has_last = false;
	}
	bool has_last;
};

struct ipfrag_data_s {
	map<vmIP, map<unsigned int, ip_frag_queue*> > ip_frag_stream;
	map<vmIP, map<unsigned int, ip_frag_queue*> >::iterator ip_frag_streamIT;
	map<unsigned int, ip_frag_queue*>::iterator ip_frag_streamITinner;
};

void ipfrag_prune(unsigned int tv_sec, bool all, ipfrag_data_s *ipfrag_data,
		  int pushToStack_queue_index, int prune_limit);
int handle_defrag(iphdr2 *header_ip, sHeaderPacket **header_packet, ipfrag_data_s *ipfrag_data,
		  int pushToStack_queue_index);
int handle_defrag(iphdr2 *header_ip, void *header_packet_pqout, ipfrag_data_s *ipfrag_data);

#endif
