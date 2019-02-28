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
	/* set SO_IPHDRINCL option */
	socket_iphdrincl(sockraw);
 
	src_addr.sin_family = AF_INET;
	src_addr.sin_addr.s_addr = inet_addr(src);
	src_addr.sin_port = htons(9095);
	memset(&src_addr.sin_zero, '\0', 8);
 
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_addr.s_addr = inet_addr(dst);
	dest_addr.sin_port = htons(9095);
	memset(&dest_addr.sin_zero, '\0', 8);
    
	if(::bind(sockraw, (struct sockaddr *)&src_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		//return -1;
	}
	//return 0;
}

int
MirrorIP::send(char *data, int datalen) {

	struct iphdr2 *ip_hdr;

	ip_hdr = (struct iphdr2 *)mirror_packet;
	memset(ip_hdr, 0, sizeof(struct iphdr2));
	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->id = htons(100);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 120;
	ip_hdr->protocol = 4;
	ip_hdr->check = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr2) + datalen);
	ip_hdr->ihl = 5;
	ip_hdr->check = 0;
	ip_hdr->saddr = src_addr.sin_addr.s_addr;
	ip_hdr->daddr = dest_addr.sin_addr.s_addr;
	memcpy(mirror_packet + sizeof(struct iphdr2), data, datalen);

	int res;
	if((res = sendto(sockraw, mirror_packet, datalen + sizeof(struct iphdr2), 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr))) == -1)
	{
		printf("msglen[%lu]\n", datalen + sizeof(struct iphdr2));
		perror("sendto");
	}
	return res;
}
