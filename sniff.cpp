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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <semaphore.h>

#include <pcap.h>
//#include <pcap/sll.h>

#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)&x))
#define MAX_TCPSTREAMS 1024
#define RTP_FIXED_HEADERLEN 12

//#define HAS_NIDS 1
#ifdef HAS_NIDS
#include <nids.h>
#endif

#include "codecs.h"
#include "calltable.h"
#include "sniff.h"
#include "voipmonitor.h"
#include "filter_mysql.h"
#include "hash.h"
#include "rtp.h"
#include "rtcp.h"

extern "C" {
#include "liblfds.6/inc/liblfds.h"
}

using namespace std;

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#ifdef	MUTEX_THREAD
queue<pcap_packet*> readpacket_thread_queue;
extern pthread_mutex_t readpacket_thread_queue_lock;
#endif

Calltable *calltable;
extern int calls;
extern int opt_saveSIP;	  	// save SIP packets to pcap file?
extern int opt_saveRTP;	 	// save RTP packets to pcap file?
extern int opt_saveRTCP;	// save RTCP packets to pcap file?
extern int opt_saveRAW;	 	
extern int opt_saveWAV;	 	
extern int opt_packetbuffered;	  // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_rtcp;		  // Make .pcap files writing ‘‘packet-buffered’’
extern int verbosity;
extern int terminating;
extern int opt_rtp_firstleg;
extern int opt_sip_register;
extern int opt_norecord_header;
extern char *sipportmatrix;
extern pcap_t *handle;
extern read_thread *threads;
extern int opt_norecord_dtmf;
extern int opt_onlyRTPheader;
extern int opt_sipoverlap;

extern IPfilter *ipfilter;
extern IPfilter *ipfilter_reload;
extern int ipfilter_reload_do;

extern TELNUMfilter *telnumfilter;
extern TELNUMfilter *telnumfilter_reload;
extern int telnumfilter_reload_do;

extern int rtp_threaded;
extern int opt_pcap_threaded;

extern int opt_rtpnosip;
extern char opt_cachedir[1024];

extern int opt_savewav_force;
extern int opt_saveudptl;

extern nat_aliases_t nat_aliases;

#ifdef QUEUE_MUTEX
extern sem_t readpacket_thread_semaphore;
#endif

struct tcp_stream2 {
	char *data;
	int datalen;
	pcap_pkthdr header;
	u_char *packet;
	u_int next_seq;
	u_int hash;
	time_t ts;
	tcp_stream2 *next;
};

tcp_stream2 *tcp_streams_hashed[MAX_TCPSTREAMS];
list<tcp_stream2*> tcp_streams_list;

extern struct queue_state *qs_readpacket_thread_queue;

// return IP from nat_aliases[ip] or 0 if not found
in_addr_t match_nat_aliases(in_addr_t ip) {
	nat_aliases_t::iterator iter;
        iter = nat_aliases.find(ip);
        if(iter == nat_aliases.end()) {
                // not found
                return 0;
        } else {
                return iter->second;
        }
	
}

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
	char *tmp;
	char tmp2;
	tmp = (char*)ptr;

	// put '\0' at the end of the packet so it can be used with string functions. then restore the character
	tmp2 = tmp[len - 1];
	tmp[len - 1] = '\0';

	tl = strlen(tag);
	//r = (unsigned long)memmem(ptr, len, tag, tl); memmem cannot be used because SIP headers are case insensitive
	r = (unsigned long)strcasestr(tmp, tag);
	tmp[len - 1] = tmp2;
	if(r == 0){
		// tag did not match
		l = 0;
	} else {
		//tag matches move r pointer behind the tag name
		r += tl;
		l = (unsigned long)memmem((void *)r, len - (r - (unsigned long)ptr), "\r\n", 2);
		if (l > 0){
			// remove trailing \r\n and set l to length of the tag
			l -= r;
		} else {
			// trailing \r\n not found
			l = 0;
		}
	}
	// left trim spacees
	if(l > 0) {
		rc = (char*)r;
		if (rc) {
			while (((char *)ptr + len) > rc && rc[0] == ' '){
				rc++;
				l--;
			}
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

/* three types of URI
 1)     "A. G. Bell" <sip:agb@bell-telephone.com> ;tag=a48s
 2)     Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8
 3)     sip:+12125551212@server.phone2net.com;tag=887s
*/
	if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "\"", 1)) == 0){
		// try without ""
		if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "<", 1)) == 0){
			goto fail_exit;
		} else {
			// found case 2)     Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8
			r = (unsigned long)peername_tag;
		}
	} else {
		// found case 1) "A. G. Bell" <sip:agb@bell-telephone.com> ;tag=a48s
		r += 1;
	}
	if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, "\" <", 3)) == 0){
		// try without space ' '
		if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, "\"<", 2)) == 0){
			// try without quotes
			if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, " <", 2)) == 0){
				goto fail_exit;
			}
		}
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)peername_len) ){
		goto fail_exit;
	}
	memcpy(peername, (void*)r, r2 - r);
	peername[r2 - r] = '\0';
	return 0;
fail_exit:
	strcpy(peername, "");
	return 1;
}


int get_sip_peername(char *data, int data_len, const char *tag, char *peername, int peername_len){
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
	strcpy(peername, "");
	return 1;
}

int get_sip_domain(char *data, int data_len, const char *tag, char *domain, int domain_len){
	unsigned long r, r2, peername_tag_len;
	char *peername_tag = gettag(data, data_len, tag, &peername_tag_len);
	char *c;
	if(!peername_tag_len) {
		goto fail_exit;
	}
	if ((r = (unsigned long)memmem(peername_tag, peername_tag_len, "@", 1)) == 0){
		goto fail_exit;
	}
	r += 1;
	if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len, ">", 1)) == 0){
		if ((r2 = (unsigned long)memmem(peername_tag, peername_tag_len + 1, "\r", 1)) == 0){
			goto fail_exit;
		}
	}
	if (r2 <= r || ((r2 - r) > (unsigned long)domain_len)  ){
		goto fail_exit;
	}
	memcpy(domain, (void*)r, r2 - r);
	domain[r2 - r] = '\0';

	// check if there is ; in the string (for example sip:<123@domain;user=phone>
	c = strchr(domain, ';');
	if(c != NULL)
		*c = '\0';

	return 0;
fail_exit:
	strcpy(domain, "");
	return 1;
}


int get_sip_branch(char *data, int data_len, const char *tag, char *branch, int branch_len){
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


int get_ip_port_from_sdp(char *sdp_text, in_addr_t *addr, unsigned short *port, int *fax){
	unsigned long l;
	char *s;
	char s1[20];

	*fax = 0;
	s = gettag(sdp_text,strlen(sdp_text), "c=IN IP4 ", &l);
	if(l == 0) return 1;
	memset(s1, '\0', sizeof(s1));
	memcpy(s1, s, MIN(l, 19));
//	printf("---------- [%s]\n", s1);
	if ((int32_t)(*addr = inet_addr(s1)) == -1){
		*addr = 0;
		*port = 0;
		return 1;
	}
	s = gettag(sdp_text, strlen(sdp_text), "m=audio ", &l);
	if (l == 0 || (*port = atoi(s)) == 0){
		s = gettag(sdp_text, strlen(sdp_text), "m=image ", &l);
		if (l == 0 || (*port = atoi(s)) == 0){
			*port = 0;
			return 1;
		} else {
			*fax = 1;
		}
	}
	return 0;
}

int get_value_stringkeyval2(const char *data, unsigned int data_len, const char *key, char *value, int len) {
	unsigned long r, tag_len;
	char *tmp = gettag(data, data_len, key, &tag_len);
	//gettag removes \r\n but we need it
	if(!tag_len) {
		goto fail_exit;
	} else {
		//gettag remove trailing \r but we need it 
		tag_len++;
	}
	if ((r = (unsigned long)memmem(tmp, tag_len, ";", 1)) == 0){
		if ((r = (unsigned long)memmem(tmp, tag_len, "\r", 1)) == 0){
			goto fail_exit;
		}
	}
	memcpy(value, (void*)tmp, r - (unsigned long)tmp);
	value[r - (unsigned long)tmp] = '\0';
	return 0;
fail_exit:
	strcpy(value, "");
	return 1;
}

int get_expires_from_contact(char *data, int datalen, int *expires){
	char *s;
	unsigned long l;

	if(datalen < 8) return 1;

	s = gettag(data, datalen, "\nContact:", &l);
	if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
		char tmp[128];
		int res = get_value_stringkeyval2(s, l + 2, "expires=", tmp, sizeof(tmp));
		if(res) {
			// not found, try again in case there is more Contact headers
			return get_expires_from_contact(s, datalen - (s - data), expires);
		} else {
			*expires = atoi(tmp);
			return 0;
		}
	} else {
		return 1;
	}
}

int get_value_stringkeyval(const char *data, unsigned int data_len, const char *key, char *value, int len) {
	unsigned long r, tag_len;
	char *tmp = gettag(data, data_len, key, &tag_len);
	if(!tag_len) {
		goto fail_exit;
	}
	if ((r = (unsigned long)memmem(tmp, tag_len, "\"", 1)) == 0){
		goto fail_exit;
	}
	memcpy(value, (void*)tmp, r - (unsigned long)tmp);
	value[r - (unsigned long)tmp] = '\0';
	return 0;
fail_exit:
	strcpy(value, "");
	return 1;
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

void add_to_rtp_thread_queue(Call *call, unsigned char *data, int datalen, struct pcap_pkthdr *header,  u_int32_t saddr, unsigned short port, int iscaller) {
	rtp_packet *rtpp = (rtp_packet*)malloc(sizeof(rtp_packet));
	rtpp->call = call;
	rtpp->data = (unsigned char *)malloc(sizeof(unsigned char) * datalen);
	rtpp->datalen = datalen;
	rtpp->saddr = saddr;
	rtpp->port = port;
	rtpp->iscaller = iscaller;

	memcpy(&rtpp->header, header, sizeof(struct pcap_pkthdr));
	memcpy(rtpp->data, data, datalen);

#ifdef QUEUE_MUTEX
	pthread_mutex_lock(&(threads[call->thread_num].qlock));
	threads[call->thread_num].pqueue.push(rtpp);
	pthread_mutex_unlock(&(threads[call->thread_num].qlock));
	sem_post(&threads[call->thread_num].semaphore);
#endif

#ifdef QUEUE_NONBLOCK
	if(queue_enqueue(threads[call->thread_num].pqueue, (void*)rtpp) == 0) {
		// enqueue failed, try to raise queue
		if(queue_guaranteed_enqueue(threads[call->thread_num].pqueue, (void*)rtpp) == 0) {
			syslog(LOG_ERR, "error: add_to_rtp_thread_queue cannot allocate memory");
		}
	}
#endif
}


void *rtp_read_thread_func(void *arg) {
	rtp_packet *rtpp;
	read_thread *params = (read_thread*)arg;
	while(1) {

#ifdef QUEUE_MUTEX
		sem_wait(&params->semaphore);

		pthread_mutex_lock(&(params->qlock));
		rtpp = params->pqueue.front();
		params->pqueue.pop();
		pthread_mutex_unlock(&(params->qlock));
#endif
		
#ifdef QUEUE_NONBLOCK
		if(queue_dequeue(params->pqueue, (void **)&rtpp) != 1) {
			// queue is empty
			usleep(10000);
			continue;
		};
#endif 
		rtpp->call->read_rtp(rtpp->data, rtpp->datalen, &rtpp->header, rtpp->saddr, rtpp->port, rtpp->iscaller);
		rtpp->call->set_last_packet_time(rtpp->header.ts.tv_sec);

		free(rtpp->data);
		free(rtpp);
	}

	return NULL;
}

Call *new_invite_register(int sip_method, char *data, int datalen, struct pcap_pkthdr *header, char *callidstr, u_int32_t saddr, u_int32_t daddr, int source, char *s, long unsigned int l){
	static char str2[1024];
	// store this call only if it starts with invite
	Call *call = calltable->add(s, l, header->ts.tv_sec, saddr, source);
	call->set_first_packet_time(header->ts.tv_sec);
	call->sipcallerip = saddr;
	call->sipcalledip = daddr;
	call->type = sip_method;
	ipfilter->add_call_flags(&(call->flags), ntohl(saddr), ntohl(daddr));
	strcpy(call->fbasename, callidstr);

	/* this logic updates call on the first INVITES */
	if (sip_method == INVITE or sip_method == REGISTER) {
		int res;
		// callername
		res = get_sip_peercnam(data,datalen,"\nFrom:", call->callername, sizeof(call->callername));
		if(res) {
			// try compact header
			get_sip_peercnam(data,datalen,"\nf:", call->callername, sizeof(call->callername));
		}

		// caller number
		res = get_sip_peername(data,datalen,"\nFrom:", call->caller, sizeof(call->caller));
		if(res) {
			// try compact header
			get_sip_peername(data,datalen,"\nf:", call->caller, sizeof(call->caller));
		}

		// caller number
		res = get_sip_peername(data,datalen,"\nTo:", call->called, sizeof(call->called));
		if(res) {
			// try compact header
			get_sip_peername(data,datalen,"\nt:", call->called, sizeof(call->called));
		}

		// caller domain 
		res = get_sip_domain(data,datalen,"\nFrom:", call->caller_domain, sizeof(call->caller_domain));
		if(res) {
			// try compact header
			get_sip_domain(data,datalen,"\nf:", call->caller_domain, sizeof(call->caller_domain));
		}

		// called domain 
		res = get_sip_domain(data,datalen,"\nTo:", call->called_domain, sizeof(call->called_domain));
		if(res) {
			// try compact header
			get_sip_domain(data,datalen,"\nt:", call->called_domain, sizeof(call->called_domain));
		}

		if(sip_method == REGISTER) {	
			// copy contact num <sip:num@domain>

			s = gettag(data, datalen, "\nUser-Agent:", &l);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				memcpy(call->a_ua, s, l);
				call->a_ua[l] = '\0';
			}

			res = get_sip_peername(data,datalen,"\nContact:", call->contact_num, sizeof(call->contact_num));
			if(res) {
				// try compact header
				get_sip_peername(data,datalen,"\nm:", call->contact_num, sizeof(call->contact_num));
			}
			// copy contact domain <sip:num@domain>
			res = get_sip_domain(data,datalen,"\nContact:", call->contact_domain, sizeof(call->contact_domain));
			if(res) {
				// try compact header
				get_sip_domain(data,datalen,"\nm:", call->contact_domain, sizeof(call->contact_domain));
			}

			// copy Authorization
			s = gettag(data, datalen, "\nAuthorization:", &l);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				get_value_stringkeyval(s, datalen - (s - data), "username=\"", call->digest_username, sizeof(call->digest_username));
				get_value_stringkeyval(s, datalen - (s - data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
			}
			// get expires header
			s = gettag(data, datalen, "\nExpires:", &l);
			if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
				char c = s[l];
				s[l] = '\0';
				call->register_expires = atoi(s);
				s[l] = c;
			}
			// the expire can be also in contact header Contact: 79438652 <sip:6600006@192.168.10.202:1026>;expires=240
			get_expires_from_contact(data, datalen, &call->register_expires);
/*
			syslog(LOG_NOTICE, "contact_num[%s] contact_domain[%s] from_num[%s] from_name[%s] from_domain[%s] digest_username[%s] digest_realm[%s] expires[%d]\n", 
				call->contact_num, call->contact_domain, call->caller, call->callername, call->caller_domain, 
				call->digest_username, call->digest_realm, call->register_expires);
*/
		}

		if(sip_method == INVITE) {
			call->seeninvite = true;
			telnumfilter->add_call_flags(&(call->flags), call->caller, call->called);
#ifdef DEBUG_INVITE
			syslog(LOG_NOTICE, "New call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s] Call-ID[%s]\n", 
				call->sipcallerip, call->sipcalledip, call->caller, call->called, call->fbasename);
#endif
		}
	}

	if(opt_norecord_header) {
		s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l);
		if(l && l < 33) {
			// do 
			call->stoprecording();
		}
	}

	// opening dump file
	if(call->type != REGISTER && (call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP | FLAG_SAVEWAV) || opt_savewav_force)) {
		if(opt_cachedir[0] != '\0') {
			sprintf(str2, "%s/%s", opt_cachedir, call->dirname());
			mkdir(str2, 0777);
		}
		mkdir(call->dirname(), 0777);
	}
	if(call->type != REGISTER && ((call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP)) || (call->isfax && opt_saveudptl))) {
		if(opt_cachedir[0] != '\0') {
			sprintf(str2, "%s/%s/%s.pcap", opt_cachedir, call->dirname(), call->get_fbasename_safe());
		} else {
			sprintf(str2, "%s/%s.pcap", call->dirname(), call->get_fbasename_safe());
		}
		sprintf(call->pcapfilename, "%s/%s.pcap", call->dirname(), call->get_fbasename_safe());
		call->set_f_pcap(pcap_dump_open(handle, str2));
		if(call->get_f_pcap() == NULL) {
			syslog(LOG_NOTICE,"pcap [%s] cannot be opened: %s\n", str2, pcap_geterr(handle));
		}
		if(verbosity > 3) {
			syslog(LOG_NOTICE,"pcap_filename: [%s]\n",str2);
		}
	}

	//check and save CSeq for later to compare with OK 
	s = gettag(data, datalen, "\nCSeq:", &l);
	if(l && l < 32) {
		memcpy(call->invitecseq, s, l);
		call->invitecseq[l] = '\0';
		if(verbosity > 2)
			syslog(LOG_NOTICE, "Seen invite, CSeq: %s\n", call->invitecseq);
	}
	
	// check if we have X-VoipMonitor-Custom1
	s = gettag(data, datalen, "\nX-VoipMonitor-Custom1:", &l);
	if(l && l < 255) {
		memcpy(call->custom_header1, s, l);
		call->custom_header1[l] = '\0';
		if(verbosity > 2)
			syslog(LOG_NOTICE, "Seen X-VoipMonitor-Custom1: %s\n", call->custom_header1);
	}
	return call;
}

Call *process_packet(unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen,
	pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int istcp, int dontsave, int can_thread, int *was_rtp) {

	static Call *call;
	static int iscaller;
	static int is_rtcp = 0;
	static unsigned long last_cleanup = 0;	// Last cleaning time
	static char *s;
	static unsigned long l;
	static char callidstr[1024],str2[1024];
	static int sip_method = 0;
	static char lastSIPresponse[128];
	static int lastSIPresponseNum;
	static int pcapstatres = 0;
	static int pcapstatresCount = 0;
	static struct pcap_stat ps;
	static unsigned int lostpacket = 0;
	static unsigned int lostpacketif = 0;
	unsigned int tmp_u32 = 0;

	*was_rtp = 0;

	// checking and cleaning stuff every 10 seconds (if some packet arrive) 
	if (header->ts.tv_sec - last_cleanup > 10){
		if(verbosity > 0) printf("Total calls [%d] calls in queue[%d]\n", (int)calltable->calls_listMAP.size(), (int)calltable->calls_queue.size());
		if (last_cleanup >= 0){
			calltable->cleanup(header->ts.tv_sec);
		}
		/* also do every 10 seconds pcap statistics */
		pcapstatres = pcap_stats(handle, &ps);
		if (pcapstatres == 0 && (lostpacket < ps.ps_drop || lostpacketif < ps.ps_ifdrop)) {
			if(pcapstatresCount) {
				syslog(LOG_ERR, "error: libpcap or interface dropped some packets! rx:%i pcapdrop:%i ifdrop:%i increase --ring-buffer (kernel >= 2.6.31 needed and libpcap >= 1.0.0) or use --pcap-thread\n", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
			} else {
				// do not show first error, it is normal on startup. 
				pcapstatresCount++;
			}
			lostpacket = ps.ps_drop;
			lostpacketif = ps.ps_ifdrop;
		}
		last_cleanup = header->ts.tv_sec;
		/* delete all calls */
		calltable->lock_calls_deletequeue();
		while (calltable->calls_deletequeue.size() > 0) {
			call = calltable->calls_deletequeue.front();
			calltable->calls_deletequeue.pop();
			call->hashRemove();
			delete call;
			calls--;
		}
		calltable->unlock_calls_deletequeue();

		// clean tcp_streams_list
		list<tcp_stream2*>::iterator stream;
		for (stream = tcp_streams_list.begin(); stream != tcp_streams_list.end();) {
			if((header->ts.tv_sec - (*stream)->ts) > (10 * 60)) {
				// remove tcp stream after 10 minutes
				tcp_stream2 *next, *tmpstream;
				tmpstream = tcp_streams_hashed[(*stream)->hash];
				tcp_streams_hashed[(*stream)->hash] = NULL;
				while(tmpstream) {
					free(tmpstream->data);
					free(tmpstream->packet);
					next = tmpstream->next;
					free(tmpstream);
					tmpstream = next;
				}
				tcp_streams_list.erase(stream++);
			} else {
				++stream;
			}
		}
	}

	// check if the packet is SIP ports 	
	if(sipportmatrix[source] || sipportmatrix[dest]) {

#if 0
		/* ugly and dirty hack to detect two SIP messages in one TCP packet. */
		tmp = strstr(data, "SIP/2.0 ");
		if(tmp) {
			tmp = strstr(tmp + 8, "SIP/2.0 ");
			if(tmp) {
				// second SIP message in one packet. Skip the first packet for now. TODO: process both packets
				datalen -= tmp - data;
				data = tmp;
			}
		}
#endif

		/* note that Call-ID isn't the phone number of the caller. It uniquely represents 
		   the whole call, or dialog, between the two user agents. All related SIP 
		   messages use the same Call-ID. For example, when a user agent receives a 
		   BYE message, it knows which call to hang up based on the Call-ID.
		*/
		s = gettag(data,datalen,"\nCall-ID:", &l);
		if(l <= 0 || l > 1023) {
			// try also compact header
			s = gettag(data,datalen,"\ni:", &l);
			if(l <= 0 || l > 1023) {
				// no Call-ID found in packet
				// if packet is tcp, check if belongs to some TCP stream for reassemling 
				u_int hash = mkhash(saddr, source, daddr, dest) % MAX_TCPSTREAMS;
				if(istcp && tcp_streams_hashed[hash] != NULL) {
					// it belongs, append to end

					// create stream node
					tcp_stream2 *stream = (tcp_stream2*)malloc(sizeof(tcp_stream2));
					tcp_stream2 *tmpstream;
					stream->next = NULL;
					stream->ts = header->ts.tv_sec;
					stream->hash = hash;
					// XXX: packet belongs to some list of stream, do not append to list of root nodes! tcp_streams_list.push_back(stream);

					// append new created node at the end of list of TCP packets within this TCP connection
					for(tmpstream = tcp_streams_hashed[hash]; tmpstream->next; tmpstream = tmpstream->next) {};
					tmpstream->next = stream;

					//copy data
					stream->data = (char*)malloc(sizeof(char) * datalen);
					memcpy(stream->data, data, datalen);
					stream->datalen = datalen;

					//copy header
					memcpy((void*)(&stream->header), header, sizeof(pcap_pkthdr));

					//copy packet
					stream->packet = (u_char*)malloc(sizeof(u_char) * header->len);
					memcpy(stream->packet, packet, header->len);

					// check if this TCP packet was the last packet 
					if(data[datalen - 2] == 0x0d && data[datalen - 1] == 0x0a) {
						tcp_streams_list.remove(tcp_streams_hashed[hash]);
						int newlen = 0;
						// get SIP packet length from all TCP packets
						for(tmpstream = tcp_streams_hashed[hash]; tmpstream->next; tmpstream = tmpstream->next) {
							newlen += tmpstream->datalen;
						};
						// allocate structure for whole SIP packet
						u_char *newdata = (u_char*)malloc(sizeof(u_char) * newlen);
						int len2 = 0;
						// concatenate all TCP packets to one SIP packet
						for(tmpstream = tcp_streams_hashed[hash]; tmpstream->next; tmpstream = tmpstream->next) {
							memcpy(newdata + len2, tmpstream->data, tmpstream->datalen);
							len2 += tmpstream->datalen;
						};
						// process SIP packet but disable to process by thread because we are freeing newdata and need to guarantee right order
						int tmp_was_rtp;
						Call *call = process_packet(saddr, source, daddr, dest, (char*)newdata, newlen, handle, header, packet, 0, 1, 0, &tmp_was_rtp);
						// remove TCP stream
						free(newdata);
						tcp_stream2 *next;
						tmpstream = tcp_streams_hashed[hash];
						while(tmpstream) {
							if(call) {
								// if packet belongs to (or created) call, save each packets to pcap and destroy TCP stream
								save_packet(call, &tmpstream->header, (const u_char*)tmpstream->packet);
							}
							free(tmpstream->data);
							free(tmpstream->packet);
							next = tmpstream->next;
							free(tmpstream);
							tmpstream = next;
						}
						tcp_streams_hashed[hash] = NULL;
					}
					return NULL;
				} else {
					// no call-id and it belongs to no stream, skip 
					return NULL;
				}
			}
		}

		memcpy(callidstr, s, l);
		callidstr[l] = '\0';

		// Call-ID is present
		if(istcp) {
			u_int hash = mkhash(saddr, source, daddr, dest) % MAX_TCPSTREAMS;
			// check if TCP packet contains the whole SIP message
			if(!(data[datalen - 2] == 0x0d && data[datalen - 1] == 0x0a)) {
				// SIP message is not complete, save packet 
				if(tcp_streams_hashed[hash]) {
					// there is already stream 
					if ((datalen > 5) && !(memmem(data, 6, "NOTIFY", 6) == 0)) {
						/* NOTIFY can have content-length > 0 which will not end with 0x0d 0x0a
						Content-Type: application/dialog-info+xml
						Content-Length: 527

						<?xml version="1.0"?>
						*/
					} else {
						syslog(LOG_NOTICE,"DEBUG: this TCP stream with Call-ID[%s] should not happen! fix voipmonitor", callidstr);
					}
				} else {
					// create stream node
					tcp_stream2 *stream = (tcp_stream2*)malloc(sizeof(tcp_stream2));
					tcp_streams_list.push_back(stream);
					stream->next = NULL;
					stream->ts = header->ts.tv_sec;
					stream->hash = hash;
					tcp_streams_hashed[hash] = stream;

					//copy data
					stream->data = (char*)malloc(sizeof(char) * datalen);
					stream->datalen = datalen;
					memcpy(stream->data, data, datalen);

					//copy header
					memcpy((void*)(&stream->header), header, sizeof(pcap_pkthdr));

					//copy packet
					stream->packet = (u_char*)malloc(sizeof(u_char) * header->len);
					memcpy(stream->packet, packet, header->len);
					return NULL;
				}
			} else if(tcp_streams_hashed[hash]) {
				// SIP packet is complete and part of TCP stream
				//syslog(LOG_NOTICE,"TCP packet contains Call-ID[%s] and is already part of TCP stream which should not happen. fix voipmonitor", callidstr);
			}
		}



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
		} else if ((datalen > 10) && !(memmem(data, 11, "SIP/2.0 401", 11) == 0)) {
			if(verbosity > 2) 
				 syslog(LOG_NOTICE,"SIP msg: 401\n");
			sip_method = RES401;
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
				syslog(LOG_NOTICE,"SIP msg: 1XX or Unknown msg \n");
			}
			sip_method = 0;
		}
		lastSIPresponse[0] = '\0';
		lastSIPresponseNum = 0;
		if(sip_method > 0 && sip_method != INVITE && sip_method != REGISTER && sip_method != CANCEL && sip_method != BYE) {
			char a = data[datalen - 1];
			data[datalen - 1] = 0;
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
			data[datalen - 1] = a;
/* XXX: remove it once tested
		} else if(sip_method == CANCEL) {
			lastSIPresponseNum = 487;
			strcpy(lastSIPresponse, "487 Request Terminated CANCEL");
*/
		} else if(sip_method == BYE) {
			strcpy(lastSIPresponse, "BYE");
			lastSIPresponseNum = 0;
		}

		// find call */
		if (!(call = calltable->find_by_call_id(s, l))){
			// packet does not belongs to any call yet
			if (sip_method == INVITE || (opt_sip_register && sip_method == REGISTER)) {
				call = new_invite_register(sip_method, data, datalen, header, callidstr, saddr, daddr, source, s, l);
			} else {
				// SIP packet does not belong to any call and it is not INVITE 
				return NULL;
			}
		// check if the SIP msg is part of earlier REGISTER
		} else if(call->type == REGISTER) {
			call->msgcount++;
			if(sip_method == REGISTER) {
				call->regcount++;
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER Call-ID[%s] regcount[%d]", call->call_id, call->regcount);

				// update Authorization
				s = gettag(data, datalen, "\nAuthorization:", &l);
				if(l && ((unsigned int)l < ((unsigned int)datalen - (s - data)))) {
					get_value_stringkeyval(s, datalen - (s - data), "username=\"", call->digest_username, sizeof(call->digest_username));
					get_value_stringkeyval(s, datalen - (s - data), "realm=\"", call->digest_realm, sizeof(call->digest_realm));
				}

				if(call->regcount > 4) {
					// to much register attempts without OK or 401 responses
					call->regstate = 4;
					call->saveregister();
					call = new_invite_register(sip_method, data, datalen, header, callidstr, saddr, daddr, source, call->call_id, strlen(call->call_id));
					return call;
				}
				s = gettag(data, datalen, "\nCSeq:", &l);
				if(l && l < 32) {
					memcpy(call->invitecseq, s, l);
					call->invitecseq[l] = '\0';
				}
			} else if(sip_method == RES2XX) {
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER OK Call-ID[%s]", call->call_id);
                                s = gettag(data, datalen, "\nCSeq:", &l);
                                if(l && strncmp(s, call->invitecseq, l) == 0) {
					// registration OK 
					call->regstate = 1;
					call->saveregister();
					return NULL;
				} else {
					call->regstate = 3;
					call->saveregister();
					return NULL;
					// OK to unknown msg close the call
				}
			} else if(sip_method == RES401) {
				call->reg401count++;
				if(verbosity > 3) syslog(LOG_DEBUG, "REGISTER 401 Call-ID[%s] reg401count[%d]", call->call_id, call->reg401count);
				if(call->reg401count > 1) {
					// registration failed
					call->regstate = 2;
					call->saveregister();
					return NULL;
				}
			}
			if(call->msgcount > 20) {
				// to many REGISTER messages within the same callid
				call->regstate = 4;
				call->saveregister();
				return NULL;
			}
		// packet is already part of call
		// check if SIP packet belongs to the first leg 
		} else if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
			((call->saddr == saddr && call->sport == source) || 
			(call->saddr == daddr && call->sport == dest))))

			{

			if(opt_norecord_header) {
				s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l);
				if(l && l < 33) {
					// do 
					call->stoprecording();
				}
			}

			// we have packet, extend pending destroy requests
			if(call->destroy_call_at > 0) {
				call->destroy_call_at += 5; 
			}

			call->set_last_packet_time(header->ts.tv_sec);
			// save lastSIPresponseNum but only if previouse was not 487 (CANCEL) TODO: check if this is still neccessery to check != 487
			if(lastSIPresponse[0] != '\0' && call->lastSIPresponseNum != 487) {
				strncpy(call->lastSIPresponse, lastSIPresponse, 128);
				call->lastSIPresponseNum = lastSIPresponseNum;
			}

			// check if it is BYE or OK(RES2XX)
			if(sip_method == INVITE) {
				//update called number for each invite due to overlap-dialling
				if (opt_sipoverlap && saddr == call->sipcallerip) {
					int res = get_sip_peername(data,datalen,"\nTo:", call->called, sizeof(call->called));
					if(res) {
						// try compact header
						get_sip_peername(data,datalen,"\nt:", call->called, sizeof(call->called));
					}
				}

				//check and save CSeq for later to compare with OK 
				s = gettag(data, datalen, "\nCSeq:", &l);
				if(l && l < 32) {
					memcpy(call->invitecseq, s, l);
					call->invitecseq[l] = '\0';
					if(verbosity > 2)
						syslog(LOG_NOTICE, "Seen invite, CSeq: %s\n", call->invitecseq);
				}
			} else if(sip_method == BYE) {
				//check and save CSeq for later to compare with OK 
				s = gettag(data, datalen, "\nCSeq:", &l);
				if(l && l < 32) {
					memcpy(call->byecseq, s, l);
					call->byecseq[l] = '\0';
					call->seenbye = true;
					if(call->listening_worker_run) {
						*(call->listening_worker_run) = 0;
					}
					if(verbosity > 2)
						syslog(LOG_NOTICE, "Seen bye\n");
						
				}
				// save who hanged up 
				call->whohanged = (call->sipcallerip == saddr) ? 0 : 1;
			} else if(sip_method == CANCEL) {
				// CANCEL continues with Status: 200 canceling; 200 OK; 487 Req. terminated; ACK. Lets wait max 10 seconds and destroy call
				call->destroy_call_at = header->ts.tv_sec + 10;
			} else if(sip_method == RES2XX) {
				// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
				if(call->progress_time == 0) {
					call->progress_time = header->ts.tv_sec;
				}

				// if it is OK check for BYE
				s = gettag(data, datalen, "\nCSeq:", &l);
				if(l) {
					if(verbosity > 2) {
						char a = data[datalen - 1];
						data[datalen - 1] = 0;
						syslog(LOG_NOTICE, "Cseq: %s\n", data);
						data[datalen - 1] = a;
					}
					if(strncmp(s, call->byecseq, l) == 0) {
						// terminate successfully acked call, put it into mysql CDR queue and remove it from calltable 

						call->seenbyeandok = true;
						if(!dontsave && call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER)) {
							save_packet(call, header, packet);
						}
/*
	Whan voipmonitor listens for both SIP legs (with the same Call-ID it sees both BYE and should save both 200 OK after BYE so closing call after the 
	first 200 OK will not save the second 200 OK. So rather wait for 5 seconds for some more messages instead of closing the call. 
*/
						// destroy call after 5 seonds from now 
						call->destroy_call_at = header->ts.tv_sec + 5;
/*
						if (call->get_f_pcap() != NULL){
							pcap_dump_flush(call->get_f_pcap());
							pcap_dump_close(call->get_f_pcap());
							call->set_f_pcap(NULL);
						}
						// we have to close all raw files as there can be data in buffers 
						call->closeRawFiles();
						calltable->lock_calls_queue();
						calltable->calls_queue.push(call);	// push it to CDR queue at the end of queue
						calltable->unlock_calls_queue();
						calltable->calls_list.remove(call);
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Call closed\n");
*/
						return call;
					} else if(strncmp(s, call->invitecseq, l) == 0) {
						call->seeninviteok = true;
						if(!call->connect_time) {
							call->connect_time = header->ts.tv_sec;
						}
						if(verbosity > 2)
							syslog(LOG_NOTICE, "Call answered\n");
					}
				}
			} else if(sip_method == RES18X) {
				if(call->progress_time == 0) {
					call->progress_time = header->ts.tv_sec;
				}
			}

			// if the call ends with some of SIP [456]XX response code, we can shorten timeout when the call will be closed 
			if( ((call->saddr == saddr && call->sport == source) || (call->saddr == daddr && call->sport == dest))
				&&
			    (sip_method == RES3XX || sip_method == RES4XX || sip_method == RES5XX || sip_method == RES6XX) && lastSIPresponseNum != 401 && lastSIPresponseNum != 407 ) {
					// if the progress time was not set yet set it here so PDD (Post Dial Delay) is accurate if no ringing is present
					if(call->progress_time == 0) {
						call->progress_time = header->ts.tv_sec;
					}
					// save packet 
					if(!dontsave && opt_saveSIP) {
						save_packet(call, header, packet);
					}
					call->destroy_call_at = header->ts.tv_sec + 5;

/*
					// we have to close all raw files as there can be data in buffers 
					call->closeRawFiles();
					calltable->lock_calls_queue();
					calltable->calls_queue.push(call);	// push it to CDR queue at the end of queue
					calltable->unlock_calls_queue();
					calltable->calls_list.remove(call);
					if(verbosity > 2)
						syslog(LOG_NOTICE, "Call closed [%d]\n", lastSIPresponseNum);
*/
					return call;
			}
		}

		if(opt_norecord_header) {
			s = gettag(data, datalen, "\nX-VoipMonitor-norecord:", &l);
			if(l && l < 33) {
				// do 
				call->stoprecording();
			}
		}

		if(opt_norecord_dtmf) {
			s = gettag(data, datalen, "\nSignal:", &l);
			if(l && l < 33) {
				char *tmp = s + 1;
				tmp[l - 1] = '\0';
				if(call->dtmfflag == 0) {
					if(tmp[0] == '*') {
						// received ftmf '*', set flag so if next dtmf will be '0' stop recording
						call->dtmfflag = 1;
					}
				} else {
					if(tmp[0] == '0') {
						// we have complete *0 sequence
						call->stoprecording();
						call->dtmfflag = 0;
					} else {
						// reset flag because we did not received '0' after '*'
						call->dtmfflag = 0;
					}
				}
			}
		}
		
		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at += 5; 
		}

		// SDP examination only in case it is SIP msg belongs to first leg
		if(opt_rtp_firstleg == 0 || (opt_rtp_firstleg &&
			((call->saddr == saddr && call->sport == source) || 
			(call->saddr == daddr && call->sport == dest))))
			{

			s = gettag(data,datalen,"\nContent-Type:",&l);
			if(l <= 0 || l > 1023) {
				//try compact header
				s = gettag(data,datalen,"\nc:",&l);
			}
			char a = data[datalen - 1];
			data[datalen - 1] = 0;
			char *tmp = strstr(data, "\r\n\r\n");;
			if(l > 0 && strncasecmp(s, "application/sdp", l) == 0 && tmp != NULL){
				// we have found SDP, add IP and port to the table
				in_addr_t tmp_addr;
				unsigned short tmp_port;
				int rtpmap[MAX_RTPMAP];
				memset(&rtpmap, 0, sizeof(int) * MAX_RTPMAP);
				int fax;
				if (!get_ip_port_from_sdp(tmp + 1, &tmp_addr, &tmp_port, &fax)){
					if(fax) { 
						if(verbosity >= 1){
							syslog(LOG_ERR, "[%s] T38 detected", call->fbasename);
						}
						call->isfax = 1;
					}
					// prepare User-Agent
					s = gettag(data,datalen,"\nUser-Agent:", &l);
					// store RTP stream
					get_rtpmap_from_sdp(tmp + 1, datalen - (tmp + 1 - data), rtpmap);

					call->add_ip_port(tmp_addr, tmp_port, s, l, call->sipcallerip != saddr, rtpmap);
					calltable->hashAdd(tmp_addr, tmp_port, call, call->sipcallerip != saddr, 0);
					//calltable->mapAdd(tmp_addr, tmp_port, call, call->sipcallerip != saddr, 0);
					if(opt_rtcp) {
						calltable->hashAdd(tmp_addr, tmp_port + 1, call, call->sipcallerip != saddr, 1); //add rtcp
						//calltable->mapAdd(tmp_addr, tmp_port + 1, call, call->sipcallerip != saddr, 1); //add rtcp
					}
					
					// check if the IP address is listed in nat_aliases
					in_addr_t alias = 0;
					if((alias = match_nat_aliases(tmp_addr)) != 0) {
						call->add_ip_port(alias, tmp_port, s, l, call->sipcallerip != saddr, rtpmap);
						calltable->hashAdd(alias, tmp_port, call, call->sipcallerip != saddr, 0);
						//calltable->mapAdd(alias, tmp_port, call, call->sipcallerip != saddr, 0);
						if(opt_rtcp) {
							calltable->hashAdd(alias, tmp_port + 1, call, call->sipcallerip != saddr, 1); //add rtcp
							//calltable->mapAdd(alias, tmp_port + 1, call, call->sipcallerip != saddr, 1); //add rtcp
						}
					}

#ifdef NAT
					call->add_ip_port(saddr, tmp_port, s, l, call->sipcallerip != saddr, rtpmap);
					calltable->hashAdd(saddr, tmp_port, call, call->sipcallerip != saddr, 0);
					//calltable->mapAdd(saddr, tmp_port, call, call->sipcallerip != saddr, 0);
					if(opt_rtcp) {
						calltable->hashAdd(saddr, tmp_port + 1, call, call->sipcallerip != saddr, 1);
						//calltable->mapAdd(saddr, tmp_port + 1, call, call->sipcallerip != saddr, 1);
					}
#endif

				} else {
					if(verbosity >= 2){
						syslog(LOG_ERR, "Can't get ip/port from SDP:\n%s\n\n", tmp + 1);
					}
				}
			}
			data[datalen - 1] = a;
		}
		if(!dontsave && call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER)) {
			save_packet(call, header, packet);
		}

		return call;
	} else if ((call = calltable->hashfind_by_ip_port(daddr, dest, &iscaller, &is_rtcp))){
	//} else if ((call = calltable->mapfind_by_ip_port(daddr, dest, &iscaller, &is_rtcp))){
	// TODO: remove if hash will be stable
	//if ((call = calltable->find_by_ip_port(daddr, dest, &iscaller)))
		// packet (RTP) by destination:port is already part of some stored call 

		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at += 5; 
		}

		if(is_rtcp) {
			call->read_rtcp((unsigned char*) data, datalen, header, saddr, source, iscaller);
			if(!dontsave && (opt_saveRTP || opt_saveRTCP)) {
				save_packet(call, header, packet);
			}
			return call;
		}

		if(rtp_threaded && can_thread) {
			add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, source, iscaller);
			*was_rtp = 1;
		} else {
			call->read_rtp((unsigned char*) data, datalen, header, saddr, source, iscaller);
			call->set_last_packet_time(header->ts.tv_sec);
		}
		if(!dontsave && ((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl))) {
			if(opt_onlyRTPheader && !call->isfax) {
				tmp_u32 = header->caplen;
				header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
				save_packet(call, header, packet);
				header->caplen = tmp_u32;
			} else {
				save_packet(call, header, packet);
			}

		}
	} else if ((call = calltable->hashfind_by_ip_port(saddr, source, &iscaller, &is_rtcp))){
	//} else if ((call = calltable->mapfind_by_ip_port(saddr, source, &iscaller, &is_rtcp))){
	// TODO: remove if hash will be stable
	// else if ((call = calltable->find_by_ip_port(saddr, source, &iscaller)))
		// packet (RTP[C]) by source:port is already part of some stored call 

		// we have packet, extend pending destroy requests
		if(call->destroy_call_at > 0) {
			call->destroy_call_at += 5; 
		}

		if(is_rtcp) {
			call->read_rtcp((unsigned char*) data, datalen, header, saddr, source, iscaller);
			if(!dontsave && (opt_saveRTP || opt_saveRTCP)) {
				save_packet(call, header, packet);
			}
			return call;
		}

		// as we are searching by source address and find some call, revert iscaller 
		if(rtp_threaded && can_thread) {
			add_to_rtp_thread_queue(call, (unsigned char*) data, datalen, header, saddr, source, !iscaller);
			*was_rtp = 1;
		} else {
			call->read_rtp((unsigned char*) data, datalen, header, saddr, source, !iscaller);
			call->set_last_packet_time(header->ts.tv_sec);
		}
		if(!dontsave && ((call->flags & FLAG_SAVERTP) || (call->isfax && opt_saveudptl))) {
			if(opt_onlyRTPheader && !call->isfax) {
				tmp_u32 = header->caplen;
				header->caplen = header->caplen - (datalen - RTP_FIXED_HEADERLEN);
				save_packet(call, header, packet);
				header->caplen = tmp_u32;
			} else {
				save_packet(call, header, packet);
			}
		}
	// packet does not belongs to established call, check if it is on SIP port
	} else {
		if(opt_rtpnosip) {
			// decoding RTP without SIP signaling is enabled. Check if it is port >= 1024 and if RTP version is == 2
			char s[256];
			RTP rtp;
			int rtpmap[MAX_RTPMAP];
			memset(&rtpmap, 0, sizeof(int) * MAX_RTPMAP);

			rtp.read((unsigned char*)data, datalen, header, saddr, 0);

			if(rtp.getVersion() != 2 && rtp.getPayload() > 18) {
				return NULL;
			}
			snprintf(s, 4092, "%u-%x", (unsigned int)time(NULL), rtp.getSSRC());

			printf("ssrc [%x] ver[%d] src[%u] dst[%u]\n", rtp.getSSRC(), rtp.getVersion(), source, dest);

			call = calltable->add(s, strlen(s), header->ts.tv_sec, saddr, source);
			call->set_first_packet_time(header->ts.tv_sec);
			call->sipcallerip = saddr;
			call->sipcalledip = daddr;
			call->type = INVITE;
			ipfilter->add_call_flags(&(call->flags), ntohl(saddr), ntohl(daddr));
			strcpy(call->fbasename, s);
			call->seeninvite = true;
			strcpy(call->callername, "RTP");
			strcpy(call->caller, "RTP");
			strcpy(call->called, "RTP");

#ifdef DEBUG_INVITE
			syslog(LOG_NOTICE, "New RTP call: srcip INET_NTOA[%u] dstip INET_NTOA[%u] From[%s] To[%s]\n", call->sipcallerip, call->sipcalledip, call->caller, call->called);
#endif

			// opening dump file
			if((call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP | FLAG_SAVEWAV) || opt_savewav_force ) || (call->isfax && opt_saveudptl)) {
				mkdir(call->dirname(), 0777);
			}
			if((call->flags & (FLAG_SAVESIP | FLAG_SAVEREGISTER | FLAG_SAVERTP)) || (call->isfax && opt_saveudptl)) {
				sprintf(str2, "%s/%s.pcap", call->dirname(), s);
				call->set_f_pcap(pcap_dump_open(handle, str2));
				sprintf(call->pcapfilename, "%s/%s.pcap", call->dirname(), s);
			}

			if(verbosity > 3) {
				syslog(LOG_NOTICE,"pcap_filename: [%s]\n",str2);
			}

			call->add_ip_port(daddr, dest, s, l, 1, rtpmap);
			//calltable->hashAdd(daddr, dest, call, 1, 0);
			calltable->mapAdd(daddr, dest, call, 1, 0);

			call->add_ip_port(saddr, source, s, l, 0, rtpmap);
			//calltable->hashAdd(saddr, source, call, 0, 0);
			calltable->mapAdd(saddr, source, call, 0, 0);
			
		}
		// we are not interested in this packet
		if (verbosity >= 6){
			char st1[16];
			char st2[16];
			struct in_addr in;

			in.s_addr = saddr;
			strcpy(st1, inet_ntoa(in));
			in.s_addr = daddr;
			strcpy(st2, inet_ntoa(in));
			syslog(LOG_ERR, "Skipping udp packet %s:%d->%s:%d\n", st1, source, st2, dest);
		}
		return NULL;
	}

	return NULL;
}

#ifdef HAS_NIDS
void
libnids_tcp_callback(struct tcp_stream *a_tcp, void **this_time_not_needed) {
	char buf[1024];
//	return;
//	strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
	if (a_tcp->nids_state == NIDS_JUST_EST) {
		// connection described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
		a_tcp->client.collect++; // we want data received by a client
		a_tcp->server.collect++; // and by a server, too
		a_tcp->server.collect_urg++; // we want urgent data received by a
		 // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
		a_tcp->client.collect_urg++; // if we don't increase this value,
				 // we won't be notified of urgent data
				 // arrival
#endif
		fprintf (stderr, "%s established\n", buf);
		return;
		}
	if (a_tcp->nids_state == NIDS_CLOSE) {
		// connection has been closed normally
		fprintf (stderr, "%s closing\n", buf);
		return;
	}
	if (a_tcp->nids_state == NIDS_RESET) {
		// connection has been closed by RST
		fprintf (stderr, "%s reset\n", buf);
		return;
	}
	if (a_tcp->nids_state == NIDS_DATA){
		printf("[%d] [%d]\n", a_tcp->client.count_new, a_tcp->server.count_new);
		// new data has arrived; gotta determine in what direction
		// and if it's urgent or not

		struct half_stream *hlf;

		if (a_tcp->server.count_new_urg) {
			// new byte of urgent data has arrived
			strcat(buf,"(urgent->)");
			buf[strlen(buf)+1]=0;
			buf[strlen(buf)]=a_tcp->server.urgdata;
			write(1,buf,strlen(buf));
			return;
		}
		// We don't have to check if urgent data to client has arrived,
		// because we haven't increased a_tcp->client.collect_urg variable.
		// So, we have some normal data to take care of.
		if (a_tcp->client.count_new) {
			printf("CLIENT !!! \n");
			// new data for the client
			hlf = &a_tcp->client; // from now on, we will deal with hlf var,
					// which will point to client side of conn
			strcat (buf, "(<-)"); // symbolic direction of data
		} else {
			printf("SERVER !!! \n");
			hlf = &a_tcp->server; // analogical
			strcat (buf, "(->)");
		}
		fprintf(stderr,"%s",buf); // we print the connection parameters
						// (saddr, daddr, sport, dport) accompanied
						// by data flow direction (-> or <-)

		 write(2,hlf->data,hlf->count_new); // we print the newly arrived data

	}
	return;
}
#endif


#ifdef HAS_NIDS
void
libnids_udp_callback(struct tuple4 *addr, u_char *data, int len, struct ip *pkt) {
	int was_rtp;
	process_packet(addr->saddr, addr->source, addr->daddr, addr->dest, (char*)data, len, handle, nids_last_pcap_header, nids_last_pcap_data, 0, 0, 1, &was_rtp);
	return;
}

void readdump_libnids(pcap_t *handle) {
	struct pcap_pkthdr *header;	// The header that pcap gives us
	const u_char *packet = NULL;		// The actual packet 
	static struct nids_chksum_ctl ctl;
	int res;

	nids_params.pcap_desc = handle;
	if (!nids_init ()) {
	    fprintf (stderr, "%s\n", nids_errbuf);
	    exit (1);
	}

	/* turn off TCP checksums */
	ctl.netaddr = inet_addr("0.0.0.0");
	ctl.mask = inet_addr("0.0.0.0");
	ctl.action = NIDS_DONT_CHKSUM;
	nids_register_chksum_ctl(&ctl, 1);

	/* register tcp and udp handlers */
//	nids_register_tcp((void*)libnids_tcp_callback);
	nids_register_udp((void*)libnids_udp_callback);

	/* read packets from libpcap in a loop */
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
		nids_pcap_handler(NULL, header, (u_char*)packet);
	}
}
#endif

void *pcap_read_thread_func(void *arg) {
	pcap_packet *pp;
	struct iphdr *header_ip;
	struct udphdr *header_udp;
	struct udphdr header_udp_tmp;
	struct tcphdr *header_tcp;
	char *data;
	int datalen;
	int istcp = 0;
	int res;
	int was_rtp;
	while(1) {

#ifdef QUEUE_MUTEX
		res = sem_wait(&readpacket_thread_semaphore);
		if(res != 0) {
			printf("Error pcap_read_thread_func sem_wait returns != 0\n");
		}

		pthread_mutex_lock(&readpacket_thread_queue_lock);
		pp = readpacket_thread_queue.front();
		readpacket_thread_queue.pop();
		pthread_mutex_unlock(&readpacket_thread_queue_lock);
#endif

#ifdef QUEUE_NONBLOCK
		if((res = queue_dequeue(qs_readpacket_thread_queue, (void **)&pp)) != 1) {
			// queue is empty
			usleep(10000);
			continue;
		};
#endif

		header_ip = (struct iphdr *) ((char*)pp->packet + pp->offset);
		header_udp = &header_udp_tmp;
		if (header_ip->protocol == IPPROTO_UDP) {
			// prepare packet pointers 
			header_udp = (struct udphdr *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_udp + sizeof(*header_udp);
			datalen = (int)(pp->header.len - ((unsigned long) data - (unsigned long) pp->packet)); 
			istcp = 0;
		} else if (header_ip->protocol == IPPROTO_TCP) {
			istcp = 1;
			// prepare packet pointers 
			header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_tcp + (header_tcp->doff * 4);
			datalen = (int)(pp->header.len - ((unsigned long) data - (unsigned long) pp->packet)); 

			header_udp->source = header_tcp->source;
			header_udp->dest = header_tcp->dest;
		} else {
			//packet is not UDP and is not TCP, we are not interested, go to the next packet
			continue;
		}

		process_packet(header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
			    data, datalen, handle, &pp->header, pp->packet, istcp, 0, 1, &was_rtp);

		free(pp->packet);
		free(pp);
	}

	return NULL;
}

void readdump_libpcap(pcap_t *handle) {
	struct pcap_pkthdr *header;	// The header that pcap gives us
	const u_char *packet = NULL;		// The actual packet 
	struct ether_header *header_eth;
	struct sll_header *header_sll;
	struct iphdr *header_ip;
	struct udphdr *header_udp;
	struct udphdr header_udp_tmp;
	struct tcphdr *header_tcp;
	char *data;
	int datalen;
	int res;
	int protocol = 0;
	unsigned int offset;
	int pcap_dlink = pcap_datalink(handle);
	int istcp = 0;
	int was_rtp;

	init_hash();
	memset(tcp_streams_hashed, 0, sizeof(tcp_stream2*) * MAX_TCPSTREAMS);

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

		// check, if ipfilter should be reloaded. Reloading is done in this section to avoid mutex locking around ipfilter structure
		if(ipfilter_reload_do) {
			delete ipfilter;
			ipfilter = ipfilter_reload;
			ipfilter_reload = NULL;
			ipfilter_reload_do = 0; 
		}

		if(telnumfilter_reload_do) {
			delete telnumfilter;
			telnumfilter = telnumfilter_reload;
			telnumfilter_reload = NULL;
			telnumfilter_reload_do = 0; 
		}

		switch(pcap_dlink) {
			case DLT_LINUX_SLL:
				header_sll = (struct sll_header *) (char*)packet;
				protocol = header_sll->sll_protocol;
				if(header_sll->sll_protocol == 129) {
					// VLAN tag
					protocol = *(short *)((char*)packet + 16 + 2);
					offset = 4;
				} else {
					offset = 0;
					protocol = header_sll->sll_protocol;
				}
				offset += sizeof(struct sll_header);
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
			case DLT_RAW:
				offset = 0;
				protocol = 8;
				break;
			default:
				printf("This datalink number [%d] is not supported yet. For more information write to support@voipmonitor.org\n", pcap_dlink);
		}

		if(protocol != 8) {
			// not ipv4 
			continue;
		}

		header_ip = (struct iphdr *) ((char*)packet + offset);
		if(header_ip->protocol == 4) {
			header_ip = (struct iphdr *) ((char*)header_ip + sizeof(iphdr));
		}

		header_udp = &header_udp_tmp;
		if (header_ip->protocol == IPPROTO_UDP) {
			// prepare packet pointers 
			header_udp = (struct udphdr *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_udp + sizeof(*header_udp);
			datalen = (int)(header->len - ((unsigned long) data - (unsigned long) packet)); 
			istcp = 0;
		} else if (header_ip->protocol == IPPROTO_TCP) {
			istcp = 1;
			// prepare packet pointers 
			header_tcp = (struct tcphdr *) ((char *) header_ip + sizeof(*header_ip));
			data = (char *) header_tcp + (header_tcp->doff * 4);
			datalen = (int)(header->len - ((unsigned long) data - (unsigned long) packet)); 
			if (datalen == 0 || !(sipportmatrix[htons(header_tcp->source)] || sipportmatrix[htons(header_tcp->dest)])) {
				// not interested in TCP packet other than SIP port
				continue;
			}
#if 0
			char tmp = data[datalen-1];
			data[datalen-1] = '\0';
			printf("tcp packet datalen[%d] [%s]!!!\n", datalen, data);
			data[datalen-1] = tmp;
#endif

			header_udp->source = header_tcp->source;
			header_udp->dest = header_tcp->dest;
		} else {
			//packet is not UDP and is not TCP, we are not interested, go to the next packet
			continue;
		}

		if(datalen < 0) {
			continue;
		}

		if(opt_pcap_threaded) {
			//add packet to queue
			pcap_packet *pp = (pcap_packet*)malloc(sizeof(pcap_packet));
			pp->packet = (u_char*)malloc(sizeof(u_char) * header->len);
			pp->offset = offset;
			memcpy(&pp->header, header, sizeof(struct pcap_pkthdr));
			memcpy(pp->packet, packet, header->len);
			if(header->caplen > header->len) {
				syslog(LOG_ERR, "error: header->caplen > header->len FIX!");
			}

#ifdef QUEUE_MUTEX
			pthread_mutex_lock(&readpacket_thread_queue_lock);
			readpacket_thread_queue.push(pp);
			pthread_mutex_unlock(&readpacket_thread_queue_lock);
#endif

#ifdef QUEUE_NONBLOCK
			if(queue_enqueue(qs_readpacket_thread_queue, (void*)pp) == 0) {
				// enqueue failed, try to raise queue
				if(queue_guaranteed_enqueue(qs_readpacket_thread_queue, (void*)pp) == 0) {
					syslog(LOG_ERR, "error: readpacket_queue cannot allocate memory");
				}
			}
#endif 

			//sem_post(&readpacket_thread_semaphore);
			continue;
		}

		process_packet(header_ip->saddr, htons(header_udp->source), header_ip->daddr, htons(header_udp->dest), 
			    data, datalen, handle, header, packet, istcp, 0, 1, &was_rtp);
	}
}
