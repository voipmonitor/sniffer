/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#include <queue>

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
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pcap.h>

#include "calltable.h"
#include "voipmonitor.h"
#include "sniff.h"

using namespace std;

/* global variables */

extern Calltable *calltable;
int opt_packetbuffered = 0;	// Make .pcap files writing ‘‘packet-buffered’’ 
				// more slow method, but you can use partitialy 
				// writen file anytime, it will be consistent.
					
int opt_fork = 1;		// fork or run foreground 
int opt_saveSIP = 0;		// save SIP packets to pcap file?
int opt_saveRTP = 0;		// save RTP packets to pcap file?
int opt_saveGRAPH = 0;		// save GRAPH data to *.graph file? 
int verbosity = 0;		// debug level

char mysql_host[256] = "localhost";
char mysql_database[256] = "voipmonitor";
char mysql_user[256] = "root";
char mysql_password[256] = "";


pthread_t call_thread;		// ID of worker thread (storing CDR)
int terminating;		// if set to 1, worker thread will terminate


/* handler for INTERRUPT signal */
void sigint_handler(int param)
{
	syslog(LOG_ERR, "SIGINT received, terminating\n");
	calltable->cleanup(0);
	terminating = 1;
	pthread_join(call_thread, NULL);
	exit(1);
}

/* handler for TERMINATE signal */
void sigterm_handler(int param)
{
	syslog(LOG_ERR, "SIGTERM received, terminating\n");
	calltable->cleanup(0);
	terminating = 1;
	pthread_join(call_thread, NULL);
	exit(1);
}

/* cycle calls_queue and save it to MySQL */
void *storing_cdr( void *dummy ) {
	Call *call;
	while(1) {
		while (calltable->calls_queue.size() > 0) {
			calltable->lock_calls_queue();
			call = calltable->calls_queue.front();
			calltable->unlock_calls_queue();
			
			call->saveToMysql();
			
			calltable->lock_calls_queue();
			calltable->calls_queue.pop();
			calltable->unlock_calls_queue();
			delete call;
		}
		if(terminating) {
			break;
		}
		
		/* sleep one second but only if running as daemon */
		if(opt_fork)
			sleep(1);
	}
	return NULL;
}

static void daemonize(void)
{
	pid_t pid;

	pid = fork();
	if (pid) {
		// parent
		exit(0);
	} else {
		// child
		setsid();
		// close std descriptors (otherwise problems detaching ssh)
		close(0); open("/dev/null", O_RDONLY);
		close(1); open("/dev/null", O_WRONLY);
		close(2); open("/dev/null", O_WRONLY);
	}
}

int main(int argc, char *argv[]) {

	/* parse arguments */

	char *fname = NULL;	// pcap file to read on 
	char *ifname = NULL;	// Specifies the name of the network device to use for 
				// the network lookup, for example, eth0
	int opt_promisc = 1;	// put interface to promisc mode?
	char user_filter[2048] = "";
	
	char *opt_chdir = "/var/spool/voipmonitor";

	terminating = 0;

	umask(0000);

	openlog("voipmonitor", LOG_CONS | LOG_PERROR, LOG_DAEMON);

	while(1) {
		char c;
		c = getopt_long(argc, argv, "f:i:r:d:v:h:b:u:p:knUSRG", NULL, NULL);
		//"i:r:d:v:h:b:u:p:fnU", NULL, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 'i':
				ifname = optarg;
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
			case 'r':
				fname = optarg;
				break;
			case 'd':
				opt_chdir = optarg;
				break;
			case 'k':
				opt_fork = 0;
				break;
			case 'n':
				opt_promisc = 0;
				break;
			case 'U':
				opt_packetbuffered=1;
				break;
			case 'h':
				strncpy(mysql_host, optarg, sizeof(mysql_host));
				break;
			case 'b':
				strncpy(mysql_database, optarg, sizeof(mysql_database));
				break;
			case 'u':
				strncpy(mysql_user, optarg, sizeof(mysql_user));
				break;
			case 'p':
				strncpy(mysql_password, optarg, sizeof(mysql_password));
				break;
			case 'f':
				strncpy(user_filter, optarg, sizeof(user_filter));
				break;
			case 'S':
				opt_saveSIP = 1;
				break;
			case 'R':
				opt_saveRTP = 1;
				break;
			case 'G':
				opt_saveGRAPH = 1;
				break;
		}
	}
	if ((fname == NULL) && (ifname == NULL)){
		printf( "voipmonitor version %s\n"
				"Usage: voipmonitor [-knUSRG] [-i <interface>] [-f <pcap filter>] [-r <file>] [-d <pcap dump directory>] [-v level]\n"
				"                 [-h <mysql server>] [-b <mysql database] [-u <mysql username>] [-p <mysql password>]\n"
				"                 [-f <pcap filter>]\n"
				" -S   save SIP packets to pcap file. Default is disabled.\n"
				" -R   save RTP packets to pcap file. Default is disabled.\n"
				" -G   save GRAPH data to graph file. Default is disabled.\n"
				" -r   read packets from file.\n"
				" -f   additional pcap filter. Builint filter is always udp (udp and (<pcap filter>)).Maximum size is 2040 chars\n"
				" -d   where to store pcap files - default /var/spool/voipmonitor\n"
				" -k   Do not fork or detach from controlling terminal.\n"
				" -n   Do not put the interface into promiscuous mode.\n"
				" -U   make .pcap files writing ‘‘packet-buffered’’ - more slow method,\n"
				"	  but you can use partitialy writen file anytime, it will be consistent.\n"
				" -h   mysql server - default localhost\n"
				" -b   mysql database - default voipmonitor\n"
				" -u   mysql username - default root\n"
				" -p   mysql password - default is empty\n"
				" -v   set verbosity level (higher number is more verbose).\n"
				, RTPSENSOR_VERSION);
		return 1;
	}

	signal(SIGINT,sigint_handler);
	signal(SIGTERM,sigterm_handler);
	
	calltable = new Calltable;

	// preparing pcap reading and pcap filters 
	
	bpf_u_int32 net;		// Holds the network address for the device.
	bpf_u_int32 mask;		// Holds the subnet mask associated with device.
	char errbuf[PCAP_ERRBUF_SIZE];	// Returns error text and is only set when the pcap_lookupnet subroutine fails.
	pcap_t *handle;			// pcap handler 

	if (ifname){
		printf("Capturing on interface: %s\n", ifname);
		// Find the properties for interface 
		if (pcap_lookupnet(ifname, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for interface %s: %s\n", ifname, errbuf);
			net = 0;
			mask = 0;
		}
		handle = pcap_open_live(ifname, 1600, opt_promisc, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open inteface '%s': %s\n", ifname, errbuf);
			return(2);
		}
	}else{
		printf("Reading file: %s\n", fname);
		net = 0;
		mask = 0;
		handle = pcap_open_offline(fname, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open pcap file '%s': %s\n", ifname, errbuf);
			return(2);
		}
	}

	chdir(opt_chdir);

	char filter_exp[2048] = "udp";		// The filter expression
	struct bpf_program fp;		// The compiled filter 

	if(*user_filter != '\0') {
		snprintf(filter_exp, sizeof(filter_exp), "udp and (%s)", user_filter);
	}

	// Compile and apply the filter
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	// filters are ok, we can daemonize 
	if (opt_fork){
		daemonize();
	}

	// start thread processing queued cdr 
	pthread_create(&call_thread, NULL, storing_cdr, NULL);
	
	// start reading packets
	readdump(handle);

	// here we go when readdump finished. When reading from interface, do nothing, because cleanups is done in sigint_* functions
	if(!ifname) {
		calltable->cleanup(0);
		terminating = 1;
		pthread_join(call_thread, NULL);
	}
}
