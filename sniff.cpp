/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/*
This unit reads and parse packets from network interface or file 
and insert them into Call class. 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <syslog.h>

#include <pcap.h>
//#include <pcap/sll.h>

#include "codecs.h"
#include "calltable.h"
#include "sniff.h"
#include "voipmonitor.h"

using namespace std;

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

Calltable *calltable;
extern int opt_saveSIP;	  	// save SIP packets to pcap file?
extern int opt_saveRTP;	 	// save RTP packets to pcap file?
extern int opt_saveRAW;	 	
extern int opt_saveWAV;	 	
extern int opt_packetbuffered;	  // Make .pcap files writing ‘‘packet-buffered’’
extern int verbosity;
extern int terminating;
extern int opt_rtp_firstleg;
extern int opt_sip_register;

/* save packet into file */
void save_packet(Call *call, struct pcap_pkthdr *header, const u_char *packet) {
	if (call->get_f_pcap() != NULL){
		call->set_last_packet_time(header->ts.tv_sec);
		pcap_dump((u_char *) call->get_f_pcap(), header, packet);
		if (opt_packetbuffered) 
			pcap_dump_flush(call->get_f_pcap());
	}
}

/* get SIP tag from memory pointed to *ptr length of len */
char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen){
	unsigned long register r, l, tl;
	char *rc;

	tl = strlen(tag);
	r = (unsigned long)memmem(ptr, len, tag, tl);
	if(r == 0){
		l = 0;
	} else {
		r += tl;
		l = (unsigned long)memmem((void *)r, len - (r - (unsigned long)ptr), "\r\n", 2);
		if (l > 0){
			l -= r;
		} else {
			l = 0;
		}
	}
	rc = (char*)r;
	if (rc) {
		while (rc[0] == ' '){
			rc++;
			l--;
		}
	}
	*gettaglen = l;
	return rc;
}

int get_sip_peercnam(char *data, int data_len, const char *tag, char *peername, int peername_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, tag, &peername_tag_len);
	if(!peername_tag_len) {
		goto fail_exit;
	}
	if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "\"", 1)) == 0){
		goto fail_exit;
	}
	r += 1;
	if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, "\" <", 3)) == 0){
		goto fail_exit;
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)peername_len) ){
		goto fail_exit;
	}
	memcpy(peername, (void*)r, r2 - r);
	peername[r2 - r] = '\0';
	return 0;
fail_exit:
	strcpy(peername, "empty");
	return 1;
}


int get_sip_peername(char *data, int data_len, char *tag, char *peername, int peername_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, tag, &peername_tag_len);
	if(!peername_tag_len) {
		goto fail_exit;
	}
	if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "sip:", 4)) == 0){
		goto fail_exit;
	}
	r += 4;
	if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, "@", 1)) == 0){
		goto fail_exit;
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)peername_len)  ){
		goto fail_exit;
	}
	memcpy(peername, (void*)r, r2 - r);
	peername[r2 - r] = '\0';
	return 0;
fail_exit:
	strcpy(peername, "empty");
	return 1;
}

int get_sip_branch(char *data, int data_len, char *tag, char *branch, int branch_len){
	unsigned long r, r2, branch_tag_len;
	char *branch_tag = gettag(data, data_len, tag, &branch_tag_len);
	if ((r = (unsigned long)memmem(branch_tag, branch_tag_len, "branch=", 7)) == 0){
		goto fail_exit;
	}
	r += 7;
	if ((r2 = (unsigned long)memmem(branch_tag, branch_tag_len, ";", 1)) == 0){
		goto fail_exit;
	}
	if (r2 <= r){
		goto fail_exit;
	}
	memcpy(branch, (void*)r, r2 - r);
	memset(branch + (r2 - r), 0, 1);
	return 0;
fail_exit:
	strcpy(branch, "");
	return 1;
}


int get_ip_port_from_sdp(char *sdp_text, in_addr_t *addr, unsigned short *port){
	unsigned long l;
	char *s;
	char s1[20];
	s=gettag(sdp_text,strlen(sdp_text), "c=IN IP4 ", &l);
	memset(s1, '\0', sizeof(s1));
	memcpy(s1, s, MIN(l, 19));
	if ((long)(*addr = inet_addr(s1)) == -1){
		*addr = 0;
		*port = 0;
		return 1;
	}
	s=gettag(sdp_text, strlen(sdp_text), "m=audio ", &l);
	if (l == 0 || (*port = atoi(s)) == 0){
		*port = 0;
		return 1;
	}
	return 0;
}

int mimeSubtypeToInt(char *mimeSubtype) {
       if(strcmp(mimeSubtype,"G729") == 0)
	       return PAYLOAD_G729;
       else if(strcmp(mimeSubtype,"GSM") == 0)
	       return PAYLOAD_GSM;
       else if(strcmp(mimeSubtype,"G723") == 0)
	       return PAYLOAD_G723;
       else if(strcmp(mimeSubtype,"PCMA") == 0)
	       return PAYLOAD_PCMA;
       else if(strcmp(mimeSubtype,"PCMU") == 0)
	       return PAYLOAD_PCMU;
       else if(strcmp(mimeSubtype,"iLBC") == 0)
	       return PAYLOAD_ILBC;
       else if(strcmp(mimeSubtype,"speex") == 0)
	       return PAYLOAD_SPEEX;
       else if(strcmp(mimeSubtype,"SPEEX") == 0)
	       return PAYLOAD_SPEEX;
       else
	       return 0;
}

int get_rtpmap_from_sdp(char *sdp_text, unsigned long len, int *rtpmap){
	 unsigned long l = 0;
	 char *s, *z;
	 int codec;
	 char mimeSubtype[128];
	 int i = 0;

	 s = gettag(sdp_text, len, "m=audio ", &l);
	 if(!l) {
		 return 0;
	 }
	 do {
		 s = gettag(s, len - (s - sdp_text), "a=rtpmap:", &l);
		 if(l && (z = strchr(s, '\r'))) {
			 *z = '\0';
		 } else {
			 break;
		 }
		 if (sscanf(s, "%30u %[^/]/", &codec, mimeSubtype) == 2) {
			 // store payload type and its codec into one integer with 1000 offset
			 rtpmap[i] = mimeSubtypeToInt(mimeSubtype) + 1000*codec;
			 //printf("PAYLOAD: rtpmap:%d codec:%d, mimeSubtype [%d] [%s]\n", rtpmap[i], codec, mimeSubtypeToInt(mimeSubtype), mimeSubtype);
		 }
		 // return '\r' into sdp_text
		*z = '\r';
		i++;
	 } while(l);
	 rtpmap[i] = 0; //terminate rtpmap field
	 return 0;
}


void readdump(pcap_t *handle) {
	struct pcap_pkthdr *header;	// The header that pcap gives us
	const u_char *packet = NULL;		// The actual packet 
	unsigned long last_cleanup = 0;	// Last cleaning time
	struct ether_header *header_eth;
	struct sll_header *header_sll;
	struct iphdr *header_ip;
	struct udphdr *header_udp;
	char *data;
	unsigned long datalen;
	char *s;
	unsigned long l;
	char str1[1024],str2[1024];
	int sip_method = 0;
	int res;
	int protocol;
	int iscaller;
	unsigned int offset;
	Call *call;
	struct pcap_stat ps;
	unsigned int lostpacket = 0;
	unsigned int lostpacketif = 0;
	int pcapstatres = 0;
	char lastSIPresponse[128];
	int lastSIPresponseNum;

	while (!terminating) {
		res = pcap_next_ex(handle, &header, &packet);

		if(!packet and res != -2) {
			if(verbosity > 2) {
				syslog(LOG_NOTICE,"NULL PACKET, pcap response is %d",res);
			}
			continue;
		}

		if(res == -1) {
			// error returned, sometimes it returs error 
			if(verbosity > 2) {
				syslog(LOG_NOTICE,"Error reading packets\n");
			}
			continue;
		} else if(res == -2) {
			//packets are being read from a ``savefile'', and there are no more packets to read from the savefile.
			syslog(LOG_NOTICE,"End of pcap file, exiting\n");
			break;
		} else if(res == 0) {
			//continue on timeout when reading live packets
			continue;
		}


		// checking and cleaning calltable every 15 seconds (if some packet arrive) 
		if (header->ts.tv_sec - last_cleanup > 15){
			if(verbosity > 0) printf("Total calls [%d] calls in queue[%d]\n", calltable->calls_list.size(), calltable->calls_queue.size());
			if (last_cleanup >= 0){
				calltable->cleanup(header->ts.tv_sec);
			}
			/* also do every 15 seconds pcap statistics */
			pcapstatres = pcap_stats(handle, &ps);
			if (pcapstatres == 0 && (lostpacket < ps.ps_drop || lostpacketif < ps.ps_ifdrop)) {
				syslog(LOG_ERR, "error: libpcap or interface dropped some packets! rx:%i drop:%i ifdrop:%i increase --ring-buffer (kernel >= 2.6.31 needed)\n", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
				lostpacket = ps.ps_drop;
				lostpacketif = ps.ps_ifdrop;
			}
			last_cleanup = header->ts.tv_sec;
		}
	
                switch(pcap_datalink(handle)) {
                        case DLT_LINUX_SLL:
                                header_sll = (struct sll_header *) (char*)packet;
                                protocol = header_sll->sll_protocol;
                                offset = sizeof(struct sll_header);
                                break;
                        case DLT_EN10MB:
				header_eth = (struct ether_header *) (char*)(packet);
                                if(header_eth->ether_type == 129) {
                                        // VLAN tag
                                        offset = 4;
                                        //XXX: this is very ugly hack, please do it right! (it will work for "08 00" which is IPV4 but not for others! (find vlan_header or something)
                                        protocol = *(packet + sizeof(struct ether_header) + 2);
                                } else {
                                        offset = 0;
                                        protocol = header_eth->ether_type;
                                }
                                offset += sizeof(struct ether_header);
                                break;
                }

                if(protocol != 8) {
                        // not ipv4 
                        continue;
                }

		header_ip = (struct iphdr *) ((char*)packet + offset);

		if (header_ip->protocol != IPPROTO_UDP) {
			//packet is not UDP, we are not interested, go to the next packet
			continue;
		}


		// prepare packet pointers 
		header_udp = (struct udphdr *) ((char *) header_ip + sizeof(*header_ip));
		data = (char *) header_udp + sizeof(*header_udp);
		datalen = header->len - ((unsigned long) data - (unsigned long) packet); 
		// TODO: remove if hash will be stable
		//if ((call = calltable->find_by_ip_port(header_ip->daddr, htons(header_udp->dest), &iscaller))){	
		if ((call = calltable->hashfind_by_ip_port(header_ip->daddr, htons(header_udp->dest), &iscaller))){	
			// packet (RTP) by destination:port is already part of some stored call 
			call->read_rtp((unsigned char*) data, datalen, header, header_ip->saddr, htons(header_udp->source), iscaller);
			call->set_last_packet_time(header->ts.tv_sec);
			if(opt_saveRTP) {
				save_packet(call, header, packet);
			}
		// TODO: remove if hash will be stable
		//} else if ((call = calltable->find_by_ip_port(header_ip->saddr, htons(header_udp->source), &iscaller))){	
		} else if ((call = calltable->hashfind_by_ip_port(header_ip->saddr, htons(header_udp->source), &iscaller))){
			// packet (RTP) by source:port is already part of some stored call 
			// as we are searching by source address and find some call, revert iscaller 
			call->read_rtp((unsigned char*) data, datalen, header, header_ip->saddr, htons(header_udp->source), !iscaller);
			call->set_last_packet_time(header->ts.tv_sec);
			if(opt_saveRTP) {
				save_packet(call, header, packet);
			}
		} else if (htons(header_udp->source) == 5060 || htons(header_udp->dest) == 5060) {
			// packet is from or to port 5060 
			data[datalen]=0;
			/* No, this isn't the phone number of the caller. It uniquely represents 
			   the whole call, or dialog, between the two user agents. All related SIP 
			   messages use the same Call-ID. For example, when a user agent receives a 
			   BYE message, it knows which call to hang up based on the Call-ID.
			*/
			s = gettag(data,datalen,"Call-ID:", &l);
			if(l <= 0 || l > 1023) {
				// try also compact header
				s = gettag(data,datalen,"i:", &l);
				if(l <= 0 || l > 1023) {
					continue;
				}
			}

			memcpy(str1,s,l);
			str1[l] = '\0';

			// parse SIP method 
			if ((datalen > 5) && !(memmem(data, 6, "INVITE", 6) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: INVITE\n");
				sip_method = INVITE;
			} else if ((datalen > 7) && !(memmem(data, 8, "REGISTER", 8) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: REGISTER\n");
				sip_method = REGISTER;
			} else if ((datalen > 2) && !(memmem(data, 3, "BYE", 3) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: BYE\n");
				sip_method = BYE;
			} else if ((datalen > 5) && !(memmem(data, 6, "CANCEL", 6) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: CANCEL\n");
				sip_method = CANCEL;
			} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 2", 9) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 2XX\n");
				sip_method = RES2XX;
			} else if ((datalen > 9) && !(memmem(data, 10, "SIP/2.0 18", 10) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 18X\n");
				sip_method = RES18X;
			} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 3", 9) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 3XX\n");
				sip_method = RES3XX;
			} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 4", 9) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 4XX\n");
				sip_method = RES4XX;
			} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 5", 9) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 5XX\n");
				sip_method = RES5XX;
			} else if ((datalen > 8) && !(memmem(data, 9, "SIP/2.0 6", 9) == 0)) {
				if(verbosity > 2) 
					 syslog(LOG_NOTICE,"SIP msg: 6XX\n");
				sip_method = RES6XX;
			} else {
				if(verbosity > 2) {
					char a[100];
					strncpy(a, data, 20);
					a[20] = '\0';
					 syslog(LOG_NOTICE,"SIP msg: 1XX or Unknown msg %s\n", a);
				}
				sip_method = 0;
			}
			lastSIPresponse[0] = '\0';
			lastSIPresponseNum = 0;
			if(sip_method > 0 && sip_method != INVITE && sip_method != REGISTER && sip_method != CANCEL) {
				char *tmp = strstr(data, "\r");
				if(tmp) {
					// 8 is len of [SIP/2.0 ], 128 is max buffer size
					strncpy(lastSIPresponse, data + 8, (datalen > 128) ? 128 : datalen);
					lastSIPresponse[tmp - data - 8] = '\0';
					char num[4];
					strncpy(num, data + 8, 3);
					num[3] = '\0';
					lastSIPresponseNum = atoi(num);
					if(lastSIPresponseNum == 0) {
						if(verbosity > 0) syslog(LOG_NOTICE, "lastSIPresponseNum = 0 [%s]\n", lastSIPresponse);
					}
				} 
			}

			// find call */
			if (!(call = calltable->find_by_call_id(s, l))){
				// packet does not belongs to any call yet
				if (sip_method == INVITE || (opt_sip_register && sip_method == REGISTER)) {
					// store this call only if it starts with invite
					call = calltable->add(s, l, header->ts.tv_sec, header_ip->saddr, htons(header_udp->source));
					call->set_first_packet_time(header->ts.tv_sec);
					call->sipcallerip = header_ip->saddr;
					call->sipcalledip = header_ip->daddr;
					call->type = sip_method;
					strcpy(call->fbasename, str1);

					// opening dump file
					if(opt_saveSIP or opt_saveRTP or opt_saveRAW or opt_saveWAV) {
						mkdir(call->dirname(), 0777);
					}
					if(opt_saveSIP or opt_saveRTP) {
						sprintf(str2, "%s/%s.pcap", call->dirname(), str1);
						call->set_f_pcap(pcap_dump_open(handle, str2));
					}

					//check and save CSeq for later to compare with OK 
					s = gettag(data, datalen, "CSeq:", &l);
					if(l && l < 32) {
						memcpy(call->invitecseq, s, l);
						call->invitecseq[l] = '\0';
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Seen invite, CSeq: %s\n", call->invitecseq);
					}
				} else {
					// SIP packet does not belong to any call and it is not INVITE 
					continue;
				}
			/* check if SIP packet belongs to the first leg */
			} else if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
				(call->saddr == header_ip->saddr && call->sport == htons(header_udp->source)) || 
				(call->saddr == header_ip->daddr && call->sport == htons(header_udp->dest))))

				{
				// packet is already part of call
				call->set_last_packet_time(header->ts.tv_sec);
				if(lastSIPresponse[0] != '\0') {
					strncpy(call->lastSIPresponse, lastSIPresponse, 128);
					call->lastSIPresponseNum = lastSIPresponseNum;
				}

				// check if it is BYE or OK(RES2XX)
				if(sip_method == INVITE) {
					//check and save CSeq for later to compare with OK 
					s = gettag(data, datalen, "CSeq:", &l);
					if(l && l < 32) {
						memcpy(call->invitecseq, s, l);
						call->invitecseq[l] = '\0';
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Seen invite, CSeq: %s\n", call->invitecseq);
					}
				} else if(sip_method == BYE || sip_method == CANCEL) {
					//check and save CSeq for later to compare with OK 
					s = gettag(data, datalen, "CSeq:", &l);
					if(l && l < 32) {
						memcpy(call->byecseq, s, l);
						call->byecseq[l] = '\0';
						call->seenbye = true;
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Seen bye\n");
							
					}
				} else if(sip_method == RES2XX) {

					if(!call->connect_time) {
						call->connect_time = header->ts.tv_sec;
					}

					// if it is OK check for BYE
					s = gettag(data, datalen, "CSeq:", &l);
					if(l) {
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Cseq: %s\n", data);
						if(strncmp(s, call->byecseq, l) == 0) {
							// terminate successfully acked call, put it into mysql CDR queue and remove it from calltable 
							call->seenbyeandok = true;
							if(opt_saveSIP) {
								save_packet(call, header, packet);
							}
							if (call->get_f_pcap() != NULL){
								pcap_dump_flush(call->get_f_pcap());
								pcap_dump_close(call->get_f_pcap());
								call->set_f_pcap(NULL);
							}
							calltable->lock_calls_queue();
							calltable->calls_queue.push(call);	// push it to CDR queue at the end of queue
							calltable->unlock_calls_queue();
							calltable->calls_list.remove(call);
							if(verbosity > 2)
								syslog(LOG_NOTICE, "Call closed\n");
							continue;
						} else if(strncmp(s, call->invitecseq, l) == 0) {
							call->seeninviteok = true;
							if(verbosity > 2)
								syslog(LOG_NOTICE, "Call answered\n");
						}
					}
				} else if(sip_method == RES18X) {
					call->progress_time = header->ts.tv_sec;
				}
				/*
				} else if(sip_method == RES3XX || sip_method == RES4XX || sip_method == RES5XX || sip_method == RES6XX) {
						call->seenbye = true;
						call->seenbyeandok = true;
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Call closed2\n");
				}
				*/
			}
			
			/* this logic updates call on the first INVITES */
			if (sip_method == INVITE && !call->seeninvite) {
				get_sip_peercnam(data,datalen,"From:", call->callername, sizeof(call->callername));
				get_sip_peername(data,datalen,"From:", call->caller, sizeof(call->caller));
				get_sip_peername(data,datalen,"To:", call->called, sizeof(call->called));
				call->seeninvite = true;
			}
			// SDP examination only in case it is SIP msg belongs to first leg

			if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
				(call->saddr == header_ip->saddr && call->sport == htons(header_udp->source)) || 
				(call->saddr == header_ip->daddr && call->sport == htons(header_udp->dest)))) 
				{

				s = gettag(data,datalen,"Content-Type:",&l);
				if(l <= 0 || l > 1023) {
					//try compact header
					s = gettag(data,datalen,"c:",&l);
				}
				char *tmp = strstr(data, "\r\n\r\n");;
				if(l > 0 && strncasecmp(s, "application/sdp", l) == 0 && tmp != NULL){
					// we have found SDP, add IP and port to the table
					in_addr_t tmp_addr;
					unsigned short tmp_port;
					int rtpmap[MAX_RTPMAP];
					memset(&rtpmap, 0, sizeof(int) * MAX_RTPMAP);
					if (!get_ip_port_from_sdp(tmp + 1, &tmp_addr, &tmp_port)){
						// prepare User-Agent
						s = gettag(data,datalen,"User-Agent:", &l);
						// store RTP stream
						get_rtpmap_from_sdp(tmp + 1, datalen - (tmp + 1 - data), rtpmap);
						call->add_ip_port(tmp_addr, tmp_port, s, l, call->sipcallerip == header_ip->saddr, rtpmap);
						calltable->hashAdd(tmp_addr, tmp_port, call, call->sipcallerip == header_ip->saddr);
#ifdef NAT
						call->add_ip_port(header_ip->saddr, tmp_port, s, l, call->sipcallerip == header_ip->saddr, rtpmap);
						calltable->hashAdd(header_ip->saddr, tmp_port, call, call->sipcallerip == header_ip->saddr);
#endif
		
					} else {
						if(verbosity >= 2){
							syslog(LOG_ERR, "Can't get ip/port from SDP:\n%s\n\n", tmp + 1);
						}
					}
				}
			}
			if(opt_saveSIP) {
				save_packet(call, header, packet);
			}
		} else {
			// we are not interested in this packet
			if (verbosity >= 6){
				char st1[16];
				char st2[16];
				struct in_addr in;

				in.s_addr = header_ip->saddr;
				strcpy(st1, inet_ntoa(in));
				in.s_addr = header_ip->daddr;
				strcpy(st2, inet_ntoa(in));
				syslog(LOG_ERR, "Skipping udp packet %s:%d->%s:%d\n",
							st1, htons(header_udp->source), st2, htons(header_udp->dest));
			}

		}
	}
}
