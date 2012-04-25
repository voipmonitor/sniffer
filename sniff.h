/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#include <queue>
#include "voipmonitor.h"

#ifdef QUEUE_NONBLOCK
extern "C" {
#include "liblfds.6/inc/liblfds.h"
}
#endif

void *rtp_read_thread_func(void *arg);
void *pcap_read_thread_func(void *arg);

void process_packet(unsigned int saddr, int source, unsigned int daddr, int dest, char *data, int datalen,
                    pcap_t *handle, pcap_pkthdr *header, const u_char *packet, int can_thread, int *was_rtp);
void readdump_libnids(pcap_t *handle);
void readdump_libpcap(pcap_t *handle);

/* this is copied from libpcap sll.h header file, which is not included in debian distribution */
#define SLL_ADDRLEN       8               /* length of address field */
struct sll_header {
	u_int16_t sll_pkttype;          /* packet type */
	u_int16_t sll_hatype;           /* link-layer address type */
	u_int16_t sll_halen;            /* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
	u_int16_t sll_protocol;         /* protocol */
};

struct udphdr {
        uint16_t        source;
        uint16_t        dest;
        uint16_t        len;
        uint16_t        check;
};

typedef struct {
	Call *call;
	unsigned char *data;
	int datalen;
	u_int32_t saddr;
	unsigned short port;
	int iscaller;
	struct pcap_pkthdr header;
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
} read_thread;

typedef struct {
	struct pcap_pkthdr header;
	u_char *packet;
	int offset;
} pcap_packet;
