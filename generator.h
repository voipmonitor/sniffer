#ifndef GENERATOR_H
#define GENERATOR_H

#include "voipmonitor.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef FREEBSD
#include <netinet/ether.h>
#endif

#include <sys/times.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <netinet/ip.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#ifndef FREEBSD
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif
#endif

using namespace std;

void *gensiprtp(void *);

class Generator {
public: 
	Generator(const char*, const char*);
	int send(char *, int);
	
private:
	int sockraw;
	char generator_packet[4092];
	struct sockaddr_in src_addr;
	struct sockaddr_in dest_addr;

	void socket_broadcast(int);
	void socket_iphdrincl(int);
};

#endif
