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
	char has_last;
};

typedef map<unsigned int, ip_frag_s*> ip_frag_queue_t;
typedef map<unsigned int, ip_frag_s*>::iterator ip_frag_queue_it_t;

struct ipfrag_data_s {
	map<unsigned int, map<unsigned int, ip_frag_queue_t*> > ip_frag_stream;
	map<unsigned int, map<unsigned int, ip_frag_queue_t*> >::iterator ip_frag_streamIT;
	map<unsigned int, ip_frag_queue_t*>::iterator ip_frag_streamITinner;
};

void ipfrag_prune(unsigned int tv_sec, bool all, ipfrag_data_s *ipfrag_data,
		  int pushToStack_queue_index, int prune_limit);
int handle_defrag(iphdr2 *header_ip, sHeaderPacket **header_packet, ipfrag_data_s *ipfrag_data,
		  int pushToStack_queue_index);
int handle_defrag(iphdr2 *header_ip, void *header_packet_pqout, ipfrag_data_s *ipfrag_data);

#endif
