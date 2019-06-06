/*Writing some small packet generator
 */

#include "voipmonitor.h"
#include "mirrorip.h"
#include "sniff.h"

void 
MirrorIP::socket_broadcast(int sd)
{
	const int one = 1;
 
	if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST,(char *)&one, sizeof(one)) == -1)
	{
		syslog(LOG_ERR, "[socket_broadcast] can't set SO_BROADCAST option\n");
		/* non fatal error */
	}
}
 
void 
MirrorIP::socket_iphdrincl(int sd)
{
	const int one = 1;
 
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL,(char *)&one, sizeof(one)) == -1)
	{
		syslog(LOG_ERR, "[socket_broadcast] can't set IP_HDRINCL option\n");
		/* non fatal error */
	}
}
 
MirrorIP::MirrorIP(const char *src, const char *dst) {
 
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
MirrorIP::send(char *data, int datalen) {

	iphdr2 *ip_hdr;
	unsigned ip_hdr_size = sizeof(iphdr2);

	ip_hdr = (iphdr2*)mirror_packet;
	memset(ip_hdr, 0, ip_hdr_size);
	ip_hdr->version = 4;
	ip_hdr->_id = htons(100);
	ip_hdr->_ttl = 120;
	ip_hdr->_protocol = 4;
	ip_hdr->set_tot_len(ip_hdr_size + datalen);
	ip_hdr->_ihl = 5;
	ip_hdr->_set_saddr(src_addr.sin_addr.s_addr);
	ip_hdr->_set_daddr(dest_addr.sin_addr.s_addr);
	memcpy(mirror_packet + ip_hdr_size, data, datalen);

	int res;
	if((res = sendto(sockraw, mirror_packet, datalen + ip_hdr_size, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr))) == -1)
	{
		printf("msglen[%u]\n", datalen + ip_hdr_size);
		perror("sendto");
	}
	return res;
}
