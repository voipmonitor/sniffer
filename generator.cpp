/*Writing some small packet generator
 */

#include "generator.h"
#include "sniff.h"


void 
*gensiprtp(void */*params*/) {
	Generator *gen = new FILE_LINE(8001) Generator("1.1.1.1", "2.2.2.2");
	//send test data 
	struct udphdr2 udph;
	udph.set_dest(5060);
	udph.len = 8;
	udph.set_source(5060);
	udph.check = 0;

	//char buf[4092];

	gen->send((char*)&udph, 8);
	
	return NULL;
}

void 
Generator::socket_broadcast(int sd)
{
	const int one = 1;
 
	if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST,(char *)&one, sizeof(one)) == -1)
	{
		syslog(LOG_ERR, "[socket_broadcast] can't set SO_BROADCAST option\n");
		/* non fatal error */
	}
}
 
void 
Generator::socket_iphdrincl(int sd)
{
	const int one = 1;
 
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL,(char *)&one, sizeof(one)) == -1)
	{
		syslog(LOG_ERR, "[socket_broadcast] can't set IP_HDRINCL option\n");
		/* non fatal error */
	}
}
 
Generator::Generator(const char *src, const char *dst) {

	sockraw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	 
	socket_broadcast(sockraw);
	// set SO_IPHDRINCL option
	socket_iphdrincl(sockraw);

 
	socket_set_saddr(&src_addr, str_2_vmIP(src), 9095);
	socket_set_saddr(&dest_addr, str_2_vmIP(dst), 9095);
	if(::bind(sockraw, (struct sockaddr *)&src_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		//return -1;
	}
	//return 0;
}

int
Generator::send(char *data, int datalen) {

	struct iphdr2 *iphdr;
	unsigned ip_hdr_size = sizeof(iphdr2);

	iphdr = (iphdr2*)generator_packet;
	memset(iphdr, 0, ip_hdr_size);
	iphdr->version = 4;
	iphdr->_id = htons(100);
	iphdr->_ttl = 120;
	iphdr->_protocol = 17;
	iphdr->set_tot_len(ip_hdr_size + datalen);
	iphdr->_ihl = 5;
	iphdr->_set_saddr(src_addr.sin_addr.s_addr);
	iphdr->_set_daddr(dest_addr.sin_addr.s_addr);
	memcpy(generator_packet + ip_hdr_size, data, datalen);

	int res;
	if((res = sendto(sockraw, generator_packet, datalen + ip_hdr_size, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr))) == -1)
	{
		printf("msglen[%u]\n", datalen + ip_hdr_size);
		perror("sendto");
	}
	return res;
}
