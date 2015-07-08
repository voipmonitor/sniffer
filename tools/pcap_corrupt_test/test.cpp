#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>


struct iphdr2 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl:4;
	unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif 
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
	/*The options start here. */
#ifdef PACKED
} __attribute__((packed));
#else
};
#endif


int main(int argc, char *argv[]) {
 
	if(argc < 2) {
		printf("missing ifname as parameter 1\n");
		return(1);
	}
 
	char ifname[10];
	strcpy(ifname, argv[1]);
 
	bpf_u_int32 net;
	bpf_u_int32 mask;
	
	char errbuf[PCAP_ERRBUF_SIZE];
 
	if (pcap_lookupnet(ifname, &net, &mask, errbuf) == -1) {
		mask = PCAP_NETMASK_UNKNOWN;
	}
	printf("pcap_lookupnet OK\n");
	
	pcap_t *pcap_handle;
 
	if((pcap_handle = pcap_create(ifname, errbuf)) == NULL) {
		printf("pcap_create failed on iface '%s': %s\n", ifname, errbuf);
		return(1);
	}
	printf("pcap_create OK\n");
	
	int status;
	
	if((status = pcap_set_snaplen(pcap_handle, 3200)) != 0) {
		printf("error pcap_set_snaplen\n");
		return(1);
	}
	printf("pcap_set_snaplen OK\n");
	
	int opt_promisc = 1;
	
	if((status = pcap_set_promisc(pcap_handle, opt_promisc)) != 0) {
		printf("error pcap_set_promisc\n");
		return(1);
	}
	printf("pcap_set_promisc OK\n");
	
	if((status = pcap_set_timeout(pcap_handle, 1000)) != 0) {
		printf("error pcap_set_timeout\n");
		return(1);
	}
	printf("pcap_set_timeout OK\n");

	int opt_ringbuffer = 1000;
	
	if((status = pcap_set_buffer_size(pcap_handle, opt_ringbuffer * 1024ul * 1024ul)) != 0) {
		printf("error pcap_set_buffer_size\n");
		return(1);
	}
	printf("pcap_set_buffer_size OK\n");

	if((status = pcap_activate(pcap_handle)) != 0) {
		printf("libpcap error: [%s]\n", pcap_geterr(pcap_handle));
		return(1);
	}
	printf("pcap_activate OK\n");
	
	pcap_pkthdr* header;
	const u_char* packet;

	while(pcap_next_ex(pcap_handle, &header, &packet)) {
		printf("%lx\n", (long)packet);
		unsigned int tl = ((iphdr2*)(packet+14))->tot_len;
		sleep(1);
		if(tl != ((iphdr2*)(packet+14))->tot_len) {
			printf("bad len tl[%u] != [%u] header caplen: %u\n", htons(tl), htons(((iphdr2*)(packet+14))->tot_len), header->caplen);
		}
	}
	
	return(0);
}
