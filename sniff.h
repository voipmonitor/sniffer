/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#include <queue>
#include <map>
#include "voipmonitor.h"

#define MAXPACKETLENQRING 1600

#ifdef QUEUE_NONBLOCK
extern "C" {
#include "liblfds.6/inc/liblfds.h"
}
#endif

#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

void *rtp_read_thread_func(void *arg);
void *pcap_read_thread_func(void *arg);

void process_packet(unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen,
                    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int can_thread, int *was_rtp);
void readdump_libnids(pcap_t *handle);
void readdump_libpcap(pcap_t *handle);

typedef std::map<in_addr_t, in_addr_t> nat_aliases_t; //!< 

void clean_tcpstreams();
void ipfrag_prune(unsigned int tv_sec, int all);


/* this is copied from libpcap sll.h header file, which is not included in debian distribution */
#define SLL_ADDRLEN       8               /* length of address field */
struct sll_header {
	u_int16_t sll_pkttype;          /* packet type */
	u_int16_t sll_hatype;           /* link-layer address type */
	u_int16_t sll_halen;            /* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
	u_int16_t sll_protocol;         /* protocol */
};

struct udphdr2 {
        uint16_t        source;
        uint16_t        dest;
        uint16_t        len;
        uint16_t        check;
};

typedef struct {
	Call *call;
#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
	unsigned char *data;
#endif
#ifdef QUEUE_NONBLOCK2
	unsigned char data[MAXPACKETLENQRING];
#endif
	int datalen;
	u_int32_t saddr;
	unsigned short port;
	char iscaller;
	char is_rtcp;
	struct pcap_pkthdr header;
	volatile char free;
} rtp_packet;

typedef struct {
	pthread_t thread;	       // ID of worker storing CDR thread 
#ifdef QUEUE_MUTEX
	queue<rtp_packet*> pqueue;
	pthread_mutex_t qlock;
	sem_t semaphore;
#endif
#ifdef QUEUE_NONBLOCK
	struct queue_state *pqueue;
#endif
#ifdef QUEUE_NONBLOCK2
	rtp_packet *vmbuffer;
	int vmbuffermax;
	volatile int readit;
	volatile int writeit;
#endif
} read_thread;

#if defined(QUEUE_MUTEX) || defined(QUEUE_NONBLOCK)
typedef struct {
	struct pcap_pkthdr header;
	u_char *packet;
	int offset;
} pcap_packet;
#endif


#if defined(QUEUE_NONBLOCK2)
typedef struct {
	struct pcap_pkthdr header;
	u_char packet[MAXPACKETLENQRING];
	u_char *packet2;
	int offset;
	volatile char free;
} pcap_packet;
#endif

#define MAXLIVEFILTERS 10
#define MAXLIVEFILTERSCHARS 32

typedef struct livesnifferfilter_s {
        unsigned int lv_saddr[MAXLIVEFILTERS];
        unsigned int lv_daddr[MAXLIVEFILTERS];
        unsigned int lv_bothaddr[MAXLIVEFILTERS];
        char lv_srcnum[MAXLIVEFILTERS][MAXLIVEFILTERSCHARS];
        char lv_dstnum[MAXLIVEFILTERS][MAXLIVEFILTERSCHARS];
        char lv_bothnum[MAXLIVEFILTERS][MAXLIVEFILTERSCHARS];
        int uid;
        time_t created_at;
	int all;
} livesnifferfilter_t;

