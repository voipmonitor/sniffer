#ifndef IP_FRAG_H
#define IP_FRAG_H

#include <net/ethernet.h>

#include "pcap_queue_block.h"
#include "header_packet.h"


#if DEFRAG_MOD_OLDVER

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


#if not DEFRAG_MOD_OLDVER

#define DEFRAG_THREADS_SPLIT 16

class cIpFrag {
public:
	struct sFrag {
		void destroy(int pushToStack_queue_index) {
			if(header_packet) {
				PUSH_HP(&header_packet, pushToStack_queue_index);
			}
			if(header_packet_pqout) {
				((sHeaderPacketPQout*)header_packet_pqout)->destroy_or_unlock_blockstore();
				delete ((sHeaderPacketPQout*)header_packet_pqout);
			}
			delete this;
		}
		sHeaderPacket *header_packet;
		void *header_packet_pqout;
		unsigned int header_ip_offset;
		time_t ts;
		u_int32_t offset;
		u_int32_t len;
		u_int16_t iphdr_len;
	};
	struct sFrags : map<u_int16_t, sFrag*> {
		sFrags() {
			has_last = false;
		}
		bool has_last;
	};
	struct sDefrag : map<pair<vmIP, u_int32_t>, sFrags*> {
	};
public:
	cIpFrag(unsigned fdata_threads_split = 0);
	~cIpFrag();
	void cleanup(unsigned int tv_sec, bool all,
		     int pushToStack_queue_index, int cleanup_limit);
	inline int defrag(iphdr2 *header_ip, sHeaderPacket **header_packet, sHeaderPacketPQout *header_packet_pqout, 
			  int fdata_thread_index, int pushToStack_queue_index) {
 
		if(fdata_thread_index < 0) {
			fdata_thread_index = fdata_threads_split > 1 ?
					      (header_ip->get_saddr().getHashNumber() % fdata_threads_split) :
					      0;
		}
	 
		#if DEFRAG_HEADER_IP_COPY
		//copy header ip to tmp beacuse it can happen that during exectuion of this function the header_ip can be 
		//overwriten in kernel ringbuffer if the ringbuffer is small and thus header_ip->saddr can have different value 
		iphdr2 *header_ip_orig = (iphdr2*)new FILE_LINE(0) u_char[header_ip->get_hdr_size()];
		memcpy(header_ip_orig, header_ip, header_ip->get_hdr_size());
		#else
		iphdr2 *header_ip_orig = header_ip;
		#endif
		
		pair<vmIP, u_int32_t> frags_index(header_ip_orig->get_saddr(), header_ip_orig->get_frag_id());
		sFrags *frags = fdata[fdata_thread_index][frags_index];

		// get queue from ip_frag_stream based on source ip address and ip->id identificator (2-dimensional map array)
		if(!frags) {
			// queue does not exists yet - create it and assign to map 
			frags = new FILE_LINE(0) sFrags;
			fdata[fdata_thread_index][frags_index] = frags;
		}
		
		int res = header_packet ?
			   add(frags, header_packet, NULL,
			       (u_char*)header_ip - HPP(*header_packet), header_ip_orig->get_tot_len(),
			       pushToStack_queue_index) :
			   add(frags, NULL, header_packet_pqout, 
			       (u_char*)header_ip - header_packet_pqout->packet, header_ip_orig->get_tot_len(),
			       -1);
		if(res > 0) {
			// packet was created from all pieces - delete queue and remove it from map
			fdata[fdata_thread_index].erase(frags_index);
			delete frags;
		}
		
		#if DEFRAG_HEADER_IP_COPY
		delete [] header_ip_orig;
		#endif
		
		return res;
	}
private:
	inline int add(sFrags *frags, sHeaderPacket **header_packet, sHeaderPacketPQout *header_packet_pqout,
		       unsigned int header_ip_offset, unsigned int len,
		       int pushToStack_queue_index) {
	 
		iphdr2 *header_ip = header_packet ?
				     (iphdr2*)((HPP(*header_packet)) + header_ip_offset) :
				     (iphdr2*)(header_packet_pqout->packet + header_ip_offset);

		u_int16_t frag_data = header_ip->get_frag_data();
		unsigned int offset_d = header_ip->get_frag_offset(frag_data);

		if(!header_ip->is_more_frag(frag_data) && offset_d) {
			// this packet do not set more fragment indicator but contains offset which means that it is the last packet
			frags->has_last = true;
		}

		if(frags->find(offset_d) == frags->end()) {
			// this offset number is not yet in the queue - add packet to queue which automatically sort it into right position

			// create node
			sFrag *frag = new FILE_LINE(0) sFrag;

			if(header_packet) {
				frag->ts = HPH(*header_packet)->ts.tv_sec;
				frag->header_packet = *header_packet;
				frag->header_packet_pqout = NULL;
				*header_packet = NULL;
			} else {
				frag->ts = header_packet_pqout->header->get_tv_sec();
				frag->header_packet_pqout = new FILE_LINE(26015) sHeaderPacketPQout;
				frag->header_packet = NULL;
				*(sHeaderPacketPQout*)frag->header_packet_pqout = *header_packet_pqout;
				((sHeaderPacketPQout*)frag->header_packet_pqout)->alloc_and_copy_blockstore();
			}
			
			frag->header_ip_offset = header_ip_offset;
			frag->len = len;
			frag->offset = offset_d;
			frag->iphdr_len = header_ip->get_hdr_size() - 
					  (header_ip->_get_protocol() == IPPROTO_ESP ? IPPROTO_ESP_HEADER_SIZE : 0);

			// add to queue (which will sort it automatically
			(*frags)[offset_d] = frag;
		} else {
			// node with that offset already exists - discard
			return -1;
		}

		// now check if packets in queue are complete - if yes - defragment - if not, do nithing
		int ok = true;
		unsigned int lastoffset = 0;
		if(frags->has_last and frags->begin()->second->offset == 0) {
			// queue has first and last packet - check if there are all middle fragments
			for(map<u_int16_t, sFrag*>::iterator it = frags->begin(); it != frags->end(); ++it) {
				sFrag *frag = it->second;
				if((frag->offset != lastoffset)) {
					ok = false;
					break;
				}
				lastoffset += frag->len - frag->iphdr_len;
			}
		} else {
			// queue does not contain a last packet and does not contain a first packet
			ok = false;
		}

		if(ok) {
			// all packets -> defragment 
		 
			dequeue(frags, header_packet, header_packet_pqout, pushToStack_queue_index);
			
			return 1;
		} else {
			return 0;
		}
	}
	inline int dequeue(sFrags *frags, 
			   sHeaderPacket **header_packet, sHeaderPacketPQout *header_packet_pqout,
			   int pushToStack_queue_index) {
		//walk queue

		if(!frags) return 1;
		if(!frags->size()) return 1;

		// prepare newpacket structure and header structure
		u_int32_t totallen = frags->begin()->second->header_ip_offset;
		unsigned i = 0;
		for(map<u_int16_t, sFrag*>::iterator it = frags->begin(); it != frags->end(); ++it) {
			totallen += it->second->len;
			if(i) {
				totallen -= it->second->iphdr_len;
			}
			i++;
		}
		if(totallen > 0xFFFF + frags->begin()->second->header_ip_offset) {
			if(sverb.defrag_overflow) {
				map<u_int16_t, sFrag*>::iterator it = frags->begin();
				if(it != frags->end()) {
					sFrag *frag = it->second;
					iphdr2 *iph = (iphdr2*)((u_char*)HPP(frag->header_packet) + frag->header_ip_offset);
					syslog(LOG_NOTICE, "ipfrag overflow: %i src ip: %s dst ip: %s", totallen, iph->get_saddr().getString().c_str(), iph->get_daddr().getString().c_str());
				}
			}
			totallen = 0xFFFF + frags->begin()->second->header_ip_offset;
		}
		
		unsigned int additionallen = 0;
		iphdr2 *iphdr = NULL;
		i = 0;
		unsigned int len = 0;
		
		if(header_packet) {
			*header_packet = CREATE_HP(totallen);
			sPacketInfoData pid;
			for(map<u_int16_t, sFrag*>::iterator it = frags->begin(); it != frags->end(); ++it) {
				sFrag *frag = it->second;
				if(i == 0) {
					// for first packet copy ethernet header and ip header
					if(frag->header_ip_offset) {
						memcpy_heapsafe(HPP(*header_packet), *header_packet,
								HPP(frag->header_packet), frag->header_packet,
								frag->header_ip_offset);
						len += frag->header_ip_offset;
						iphdr = (iphdr2*)(HPP(*header_packet) + len);
					}
					memcpy_heapsafe(HPP(*header_packet) + len, *header_packet,
							HPP(frag->header_packet) + frag->header_ip_offset, frag->header_packet,
							frag->len);
					len += frag->len;
					pid = frag->header_packet->pid;
				} else {
					if(len < totallen) {
						unsigned cpy_len = min((unsigned)(frag->len - frag->iphdr_len), totallen - len);
						memcpy_heapsafe(HPP(*header_packet) + len, *header_packet,
								HPP(frag->header_packet) + frag->header_ip_offset + frag->iphdr_len, frag->header_packet,
								cpy_len);
						len += cpy_len;
						additionallen += cpy_len;
					}
				}
				if(i == frags->size() - 1) {
					memcpy_heapsafe(HPH(*header_packet), *header_packet, 
							HPH(frag->header_packet), frag->header_packet,
							sizeof(struct pcap_pkthdr));
					HPH(*header_packet)->len = totallen;
					HPH(*header_packet)->caplen = totallen;
					(*header_packet)->pid = pid;
				}
				frag->destroy(pushToStack_queue_index);
				i++;
			}
		} else {
			header_packet_pqout->header = new FILE_LINE(26012) pcap_pkthdr_plus;
			header_packet_pqout->packet = new FILE_LINE(26013) u_char[totallen];
			header_packet_pqout->block_store = NULL;
			header_packet_pqout->block_store_index = 0;
			header_packet_pqout->block_store_locked = false;
			header_packet_pqout->header_ip_last_offset = 0xFFFF;
			sPacketInfoData pid;
			for(map<u_int16_t, sFrag*>::iterator it = frags->begin(); it != frags->end(); ++it) {
				sFrag *frag = it->second;
				if(i == 0) {
					// for first packet copy ethernet header and ip header
					if(frag->header_ip_offset) {
						memcpy_heapsafe(header_packet_pqout->packet, header_packet_pqout->packet,
								((sHeaderPacketPQout*)frag->header_packet_pqout)->packet, 
								((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store ?
								 ((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store->block :
								 ((sHeaderPacketPQout*)frag->header_packet_pqout)->packet,
								frag->header_ip_offset);
						len += frag->header_ip_offset;
						iphdr = (iphdr2*)(header_packet_pqout->packet + len);
					}
					memcpy_heapsafe(header_packet_pqout->packet + len, header_packet_pqout->packet,
							((sHeaderPacketPQout*)frag->header_packet_pqout)->packet + frag->header_ip_offset, 
							((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store ?
							 ((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store->block :
							 ((sHeaderPacketPQout*)frag->header_packet_pqout)->packet,
							frag->len);
					len += frag->len;
					pid = ((sHeaderPacketPQout*)frag->header_packet_pqout)->header->pid;
				} else {
					// for rest of a packets append only data 
					if(len < totallen) {
						unsigned cpy_len = min((unsigned)(frag->len - frag->iphdr_len), totallen - len);
						memcpy_heapsafe(header_packet_pqout->packet + len, header_packet_pqout->packet,
								((sHeaderPacketPQout*)frag->header_packet_pqout)->packet + frag->header_ip_offset + frag->iphdr_len, 
								((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store ?
								 ((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store->block :
								 ((sHeaderPacketPQout*)frag->header_packet_pqout)->packet,
								cpy_len);
						len += cpy_len;
						additionallen += cpy_len;
					}
				}
				if(i == frags->size() - 1) {
					memcpy_heapsafe(header_packet_pqout->header, header_packet_pqout->header,
							((sHeaderPacketPQout*)frag->header_packet_pqout)->header,
							((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store ?
							 ((sHeaderPacketPQout*)frag->header_packet_pqout)->block_store->block :
							 (u_char*)((sHeaderPacketPQout*)frag->header_packet_pqout)->header,
							sizeof(pcap_pkthdr_plus));
					header_packet_pqout->header->set_len(totallen);
					header_packet_pqout->header->set_caplen(totallen);
					header_packet_pqout->header->pid = pid;
				}
				frag->destroy(0);
				i++;
			}
		}
		if(iphdr) {
			//increase IP header length 
			iphdr->set_tot_len(iphdr->get_tot_len() + additionallen);
			// reset checksum
			iphdr->set_check(0);
			// reset fragment flag to 0
			iphdr->clear_frag_data();
		}
		
		return 1;
	}
private:
	sDefrag *fdata;
	unsigned fdata_threads_split;
};

#endif


#endif
