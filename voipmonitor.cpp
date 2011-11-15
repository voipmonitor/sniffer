/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#include <queue>
#include <climits>

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
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/resource.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pcap.h>

#include "calltable.h"
#include "voipmonitor.h"
#include "sniff.h"
#include "simpleini/SimpleIni.h"
#include "manager.h"
#include "filter_mysql.h"

using namespace std;

/* global variables */

extern Calltable *calltable;
extern int calls;
int opt_packetbuffered = 0;	// Make .pcap files writing ‘‘packet-buffered’’ 
				// more slow method, but you can use partitialy 
				// writen file anytime, it will be consistent.
					
int opt_fork = 1;		// fork or run foreground 
int opt_saveSIP = 0;		// save SIP packets to pcap file?
int opt_saveRTP = 0;		// save RTP packets to pcap file?
int opt_saveRTCP = 0;		// save RTCP packets to pcap file?
int opt_saveRAW = 0;		// save RTP packets to pcap file?
int opt_saveWAV = 0;		// save RTP packets to pcap file?
int opt_saveGRAPH = 0;		// save GRAPH data to *.graph file? 
int opt_gzipGRAPH = 0;		// compress GRAPH data ? 
int opt_rtcp = 1;		// pair RTP+1 port to RTCP and save it. 
int opt_nocdr = 0;		// do not save cdr?
int opt_gzipPCAP = 0;		// compress PCAP data ? 
int verbosity = 0;		// cebug level
int opt_rtp_firstleg = 0;		// if == 1 then save RTP stream only for first INVITE leg in case you are 
				// sniffing on SIP proxy where voipmonitor see both SIP leg. 
int opt_sip_register = 0;	// if == 1 save REGISTER messages
int opt_ringbuffer = 10;	// ring buffer in MB 
int opt_audio_format = FORMAT_WAV;	// define format for audio writing (if -W option)
int opt_manager_port = 5029;	// manager api TCP port

char configfile[1024] = "";	// config file name
char mysql_host[256] = "localhost";
char mysql_database[256] = "voipmonitor";
char mysql_table[256] = "cdr";
char mysql_user[256] = "root";
char mysql_password[256] = "";
char opt_pidfile[] = "/var/run/voipmonitor.pid";
char user_filter[2048] = "";
char ifname[1024];	// Specifies the name of the network device to use for 
			// the network lookup, for example, eth0
int opt_promisc = 1;	// put interface to promisc mode?

char opt_chdir[1024];

IPfilter *ipfilter = NULL;		// IP filter based on MYSQL 
IPfilter *ipfilter_reload = NULL;	// IP filter based on MYSQL for reload purpose
int ipfilter_reload_do = 0;	// for reload in main thread

TELNUMfilter *telnumfilter = NULL;		// IP filter based on MYSQL 
TELNUMfilter *telnumfilter_reload = NULL;	// IP filter based on MYSQL for reload purpose
int telnumfilter_reload_do = 0;	// for reload in main thread

pthread_t call_thread;		// ID of worker storing CDR thread 
pthread_t manager_thread;	// ID of worker manager thread 
int terminating;		// if set to 1, worker thread will terminate
char *sipportmatrix;		// matrix of sip ports to monitor

pcap_t *handle = NULL;		// pcap handler 

void terminate2() {
	terminating = 1;
}

/* handler for INTERRUPT signal */
void sigint_handler(int param)
{
	syslog(LOG_ERR, "SIGINT received, terminating\n");
	terminate2();
}

/* handler for TERMINATE signal */
void sigterm_handler(int param)
{
	syslog(LOG_ERR, "SIGTERM received, terminating\n");
	terminate2();
}

/* cycle calls_queue and save it to MySQL */
void *storing_cdr( void *dummy ) {
	Call *call;
	while(1) {
		if(verbosity > 0) syslog(LOG_ERR,"calls[%d]\n", calls);
		while (1) {
			calltable->lock_calls_queue();
			if(calltable->calls_queue.size() == 0) {
				calltable->unlock_calls_queue();
				break;
			}
			call = calltable->calls_queue.front();
			calltable->unlock_calls_queue();
	

			if(!opt_nocdr) {
				if(verbosity > 0) printf("storing to MySQL. Queue[%d]\n", (int)calltable->calls_queue.size());
				if(call->type == INVITE) {
					call->saveToMysql();
				} else if(call->type == REGISTER){
					call->saveRegisterToMysql();
				}
			}

			if((call->flags & FLAG_SAVEWAV) && call->type == INVITE) {
				if(verbosity > 0) printf("converting RAW file to WAV Queue[%d]\n", (int)calltable->calls_queue.size());
				call->convertRawToWav();
			}

			calltable->lock_calls_queue();
			calltable->calls_queue.pop();
			calltable->unlock_calls_queue();

			/* if we delete call here directly, destructors and another cleaning functions can be
			 * called in the middle of working with call or another structures inside main thread
			 * so put it in deletequeue and delete it in the main thread. Another way can be locking
			 * call structure for every case in main thread but it can slow down thinks for each 
			 * processing packet.
			*/
			calltable->lock_calls_deletequeue();
			calltable->calls_deletequeue.push(call);
			calltable->unlock_calls_deletequeue();
		}
		if(terminating) {
			break;
		}
	
		//TODO: it would be nice if this can be EVENT driven instead of sleeping
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
		FILE* f;
		pid_t vmon_pid;

		setsid();

		// write pid file to opt_pidfile
		vmon_pid = getpid();
		f = fopen(opt_pidfile, "w");
		if (f) {
		       fprintf(f, "%ld\n", (long)vmon_pid);
		       fclose(f);
		} else {
		       syslog(LOG_ERR,"Error occurs while writing pid file to %s\n", opt_pidfile);
		}

		// close std descriptors (otherwise problems detaching ssh)
		close(0); open("/dev/null", O_RDONLY);
		close(1); open("/dev/null", O_WRONLY);
		close(2); open("/dev/null", O_WRONLY);
	}
}

bool FileExists(char *strFilename) { 
	struct stat stFileInfo; 
	int intStat; 

	// Attempt to get the file attributes 
	intStat = stat(strFilename, &stFileInfo); 
	if(intStat == 0) { 
		// We were able to get the file attributes 
		// so the file obviously exists. 
		return true; 
	} else { 
		// We were not able to get the file attributes. 
		// This may mean that we don't have permission to 
		// access the folder which contains this file. If you 
		// need to do that level of checking, lookup the 
		// return values of stat which will give you 
		// more details on why stat failed. 
		return false; 
	} 
}

int yesno(const char *arg) {
	if(arg[0] == 'y' or arg[0] == 1) 
		return 1;
	else
		return 0;
}

int load_config(char *fname) {
	if(!FileExists(fname)) {
		return 1;
	}

	printf("Loading configuration from file %s\n", fname);

	CSimpleIniA ini;
	ini.SetUnicode();
	ini.SetMultiKey(true);
	ini.LoadFile(fname);
	const char *value;
	CSimpleIniA::TNamesDepend values;

	// sip ports
	if (ini.GetAllValues("general", "sipport", values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		// reset default port 
		sipportmatrix[5060] = 0;
		for (; i != values.end(); ++i) {
			sipportmatrix[atoi(i->pItem)] = 1;
		}
	}

	if((value = ini.GetValue("general", "interface", NULL))) {
		strncpy(ifname, value, sizeof(ifname));
	}
	if((value = ini.GetValue("general", "ringbuffer", NULL))) {
		opt_ringbuffer = atoi(value);
	}
	if((value = ini.GetValue("general", "rtp-firstleg", NULL))) {
		opt_rtp_firstleg = yesno(value);
	}
	if((value = ini.GetValue("general", "sip-register", NULL))) {
		opt_sip_register = yesno(value);
	}
	if((value = ini.GetValue("general", "nocdr", NULL))) {
		opt_nocdr = yesno(value);
	}
	if((value = ini.GetValue("general", "savesip", NULL))) {
		opt_saveSIP = yesno(value);
	}
	if((value = ini.GetValue("general", "savertp", NULL))) {
		opt_saveRTP = yesno(value);
	}
	if((value = ini.GetValue("general", "manager-port", NULL))) {
		opt_manager_port = atoi(value);
	}
	if((value = ini.GetValue("general", "savertcp", NULL))) {
		opt_saveRTCP = yesno(value);
	}
	if((value = ini.GetValue("general", "saveaudio", NULL))) {
		switch(value[0]) {
		case 'y':
		case '1':
		case 'w':
			opt_saveWAV = 1;
			opt_audio_format = FORMAT_WAV;
			break;
		case 'o':
			opt_saveWAV = 1;
			opt_audio_format = FORMAT_OGG;
			break;
		}
	}
	if((value = ini.GetValue("general", "savegraph", NULL))) {
		switch(value[0]) {
		case 'y':
		case '1':
		case 'p':
			opt_saveGRAPH = 1;
			break;
		case 'g':
			opt_saveGRAPH = 1;
			opt_gzipGRAPH = 1;
			break;
		}
	}
	if((value = ini.GetValue("general", "filter", NULL))) {
		strncpy(user_filter, value, sizeof(user_filter));
	}
	if((value = ini.GetValue("general", "spooldir", NULL))) {
		strncpy(opt_chdir, value, sizeof(opt_chdir));
	}

	if((value = ini.GetValue("general", "promisc", NULL))) {
		opt_promisc = yesno(value);
	}
	if((value = ini.GetValue("general", "mysqlhost", NULL))) {
		strncpy(mysql_host, value, sizeof(mysql_host));
	}
	if((value = ini.GetValue("general", "myqslhost", NULL))) {
		printf("You have old version of config file! there were typo in myqslhost instead of mysqlhost! Fix your config! exiting...\n");
		syslog(LOG_ERR, "You have old version of config file! there were typo in myqslhost instead of mysqlhost! Fix your config! exiting...\n");
		exit(1);
	}
	if((value = ini.GetValue("general", "mysqldb", NULL))) {
		strncpy(mysql_database, value, sizeof(mysql_database));
	}
	if((value = ini.GetValue("general", "mysqltable", NULL))) {
		strncpy(mysql_table, value, sizeof(mysql_table));
	}
	if((value = ini.GetValue("general", "mysqlusername", NULL))) {
		strncpy(mysql_user, value, sizeof(mysql_user));
	}
	if((value = ini.GetValue("general", "mysqlpassword", NULL))) {
		strncpy(mysql_password, value, sizeof(mysql_password));
	}
	return 0;
}

void reload_config() {
	load_config(configfile);

	if(ipfilter_reload)
		delete ipfilter_reload;

	ipfilter_reload = new IPfilter;
	ipfilter_reload->load();
	ipfilter_reload_do = 1;

	if(telnumfilter_reload)
		delete telnumfilter_reload;

	telnumfilter_reload = new TELNUMfilter;
	telnumfilter_reload->load();
	telnumfilter_reload_do = 1;
}

int main(int argc, char *argv[]) {

	/* parse arguments */

	char *fname = NULL;	// pcap file to read on 
	ifname[0] = '\0';
	strcpy(opt_chdir, "/var/spool/voipmonitor");
	sipportmatrix = (char*)calloc(1, sizeof(char) * 65537);
	// set default SIP port to 5060
	sipportmatrix[5060] = 1;

	int option_index = 0;
	static struct option long_options[] = {
	    {"gzip-graph", 0, 0, '1'},
	    {"gzip-pcap", 0, 0, '2'},
	    {"save-sip", 0, 0, 'S'},
	    {"save-rtp", 0, 0, 'R'},
	    {"save-rtcp", 0, 0, '9'},
	    {"save-raw", 0, 0, 'A'},
	    {"save-audio", 0, 0, 'W'},
	    {"no-cdr", 0, 0, 'c'},
	    {"save-graph", 2, 0, 'G'},
	    {"mysql-server", 1, 0, 'h'},
	    {"mysql-database", 1, 0, 'b'},
	    {"mysql-username", 1, 0, 'u'},
	    {"mysql-password", 1, 0, 'p'},
	    {"pid-file", 1, 0, 'P'},
	    {"rtp-firstleg", 0, 0, '3'},
	    {"sip-register", 0, 0, '4'},
	    {"audio-format", 1, 0, '5'},
	    {"ring-buffer", 1, 0, '6'},
	    {"config-file", 1, 0, '7'},
	    {"manager-port", 1, 0, '8'},
	    {0, 0, 0, 0}
	};

	terminating = 0;

	umask(0000);

	openlog("voipmonitor", LOG_CONS | LOG_PERROR, LOG_DAEMON);

	/* command line arguments overrides configuration in voipmonitor.conf file */
	while(1) {
		int c;
		c = getopt_long(argc, argv, "f:i:r:d:v:h:b:t:u:p:P:kncUSRAWG", long_options, &option_index);
		//"i:r:d:v:h:b:u:p:fnU", NULL, NULL);
		if (c == -1)
			break;

		switch (c) {
			/*
			case 0:
				printf ("option %s\n", long_options[option_index].name);
				break;
			*/
			case '1':
				opt_gzipGRAPH = 1;
				break;
			case '2':
				opt_gzipPCAP = 1;
				break;
			case '3':
				opt_rtp_firstleg = 1;
				break;
			case '4':
				opt_sip_register = 1;
				break;
			case '5':
				if(optarg[0] == 'o') {
					opt_audio_format = FORMAT_OGG;
				} else {
					opt_audio_format = FORMAT_WAV;
				}
				break;
			case '6':
				printf("ring buf\n");
				opt_ringbuffer = atoi(optarg);
				break;
			case '7':
				strncpy(configfile, optarg, sizeof(configfile));
				load_config(configfile);
				break;
			case '8':
				opt_manager_port = atoi(optarg);
				break;
			case '9':
				opt_saveRTCP = 1;
				break;
			case 'i':
				strncpy(ifname, optarg, sizeof(ifname));
				break;
			case 'v':
				verbosity = atoi(optarg);
				break;
			case 'r':
				fname = optarg;
				break;
			case 'c':
				opt_nocdr = 1;
				break;
			case 'd':
				strncpy(opt_chdir, optarg, sizeof(opt_chdir));
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
			case 't':
				strncpy(mysql_table, optarg, sizeof(mysql_table));
				break;
			case 'u':
				strncpy(mysql_user, optarg, sizeof(mysql_user));
				break;
			case 'p':
				strncpy(mysql_password, optarg, sizeof(mysql_password));
				break;
			case 'P':
				strncpy(opt_pidfile, optarg, sizeof(opt_pidfile));
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
			case 'A':
				opt_saveRAW = 1;
				break;
			case 'W':
				opt_saveWAV = 1;
				break;
			case 'G':
				opt_saveGRAPH = 1;
				if(optarg && optarg[0] == 'g') {
					opt_gzipGRAPH = 1;
				}
				break;
		}
	}
	if ((fname == NULL) && (ifname[0] == '\0')){
		printf( "voipmonitor version %s\n"
				"Usage: voipmonitor [--config-file /etc/voipmonitor.conf] [-kncUSRAWG] [-i <interface>] [-f <pcap filter>]\n"
				"       [-r <file>] [-d <pcap dump directory>] [-v level] [-h <mysql server>] [-b <mysql database]\n"
				"       [-u <mysql username>] [-p <mysql password>] [-f <pcap filter>] [--rtp-firstleg]\n"
				"       [--ring-buffer <n>] [--manager-port <n>]\n"
				"\n"
				" -S, --save-sip\n"
				"      save SIP packets to pcap file. Default is disabled.\n"
				"\n"
				" -R, --save-rtp\n"
   				"      save RTP packets to pcap file. Default is disabled. Whan enabled RTCP packets will be saved too.\n"
				"\n"
				" --save-rtcp\n"
   				"      save RTCP packets to pcap file. You can enable SIP signalization + only RTCP packets and not RTP packets.\n"
				"\n"
				" --sip-register\n"
   				"      save SIP register requests to cdr.register table and to pcap file.\n"
				"\n"
				" --rtp-firstleg\n"
				"      this is important option if voipmonitor is sniffing on SIP proxy and see both RTP leg of CALL.\n"
				"      in that case use this option. It will analyze RTP only for the first LEG and not each 4 RTP\n"
				"      streams which will confuse voipmonitor. Drawback of this switch is that voipmonitor will analyze\n"
				"      SDP only for SIP packets which have the same IP and port of the first INVITE source IP\n"
				"      and port. It means it will not work in case where phone sends INVITE from a.b.c.d:1024 and\n"
				"      SIP proxy replies to a.b.c.d:5060. If you have better idea how to solve this problem better\n"
				"      please contact support@voipmonitor.org\n"
				"\n"
				" -W, --save-audio\n"
				"      save RTP packets and covert it to one WAV file. Default is disabled.\n"
				"\n"
				" --audio-format <wav|ogg>\n"
				"      Save to WAV or OGG audio format. Default is WAV.\n"
				"\n"
				" --sip-messages\n"
				"      save REGISTER messages\n"
				"\n"
				" --ring-buffer\n"
				"      Set ring buffer in MB (feature of newer >= 2.6.31 kernels). If you see voipmonitor dropping packets in syslog\n"
				"      upgrade to newer kernel and increase --ring-buffer to higher MB. It is buffer between pcap library and voipmonitor.\n"
				"      The most reason why voipmonitor drops packets is waiting for I/O operations (switching to ext4 from ext3 also helps.\n"
				"\n"
				" -c, --no-cdr\n"
				"      do no save CDR to MySQL database.\n"
				"\n"
				" -A, --save-raw\n"
				"      save RTP payload to RAW format. Default is disabled.\n"
				"\n"
				" -G, --save-graph=[gzip|plain]\n"
				"      save GRAPH data to graph file. Default is disabled. Default format is plain. For gzip format use --save-graph=gzip\n"
				"\n"
				" -r <file>\n"
				"      read packets from <file>.\n"
				"\n"
				" -f <filter>\n"
				"      Pcap filter. If you will use only UDP, put here udp. Warning: If you set protocol to 'udp' pcap discards VLAN packets. Maximum size is 2040 chars\n"
				"\n"
				" -d <dir>\n"
				"      where to store pcap files - default /var/spool/voipmonitor\n"
				"\n"
				" -k   Do not fork or detach from controlling terminal.\n"
				"\n"
				" -n   Do not put the interface into promiscuous mode.\n"
				"\n"
				" -U   make .pcap files writing ‘‘packet-buffered’’ - more slow method,\n"
				"	  but you can use partialy writen file anytime, it will be consistent.\n"
				"\n"
				" -h <hostname>, --mysql-server=<hostname>\n"
				"      mysql server - default localhost\n"
				"\n"
				" -b <database>, --mysql-database\n"
				"      mysql database, default voipmonitor\n"
				"\n"
				" -t <table>, --mysql-table=<table>\n"
				"      mysql table, default cdr\n"
				"\n"
				" -u <username>, --mysql-username=<username>\n"
				"      mysql username, default root\n"
				"\n"
				" -p <password>, --mysql-password=<password>\n"
				"      mysql password, default is empty\n"
				"\n"
				" -P <pid file>, --pid-file=<pid file>\n"
				"      pid file, default /var/run/voipmonitor.pid\n"
				"\n"
				" --manager-port <port number>\n"
				"      to which TCP port should manager interface bind. Defaults to 5029.\n\n"
				"You have to provide <-i interfce> or <-r pcap_file> or set interface in configuration file\n\n"
				"\n"
				" -v <level number>\n"
				"      set verbosity level (higher number is more verbose).\n\n"
				"You have to provide <-i interfce> or <-r pcap_file> or set interface in configuration file\n\n"
				, RTPSENSOR_VERSION);
		return 1;
	}

	signal(SIGINT,sigint_handler);
	signal(SIGTERM,sigterm_handler);
	
	calltable = new Calltable;

	// preparing pcap reading and pcap filters 
	
	bpf_u_int32 mask;		// Holds the subnet mask associated with device.
	char errbuf[PCAP_ERRBUF_SIZE];	// Returns error text and is only set when the pcap_lookupnet subroutine fails.

	if (fname == NULL && ifname[0] != '\0'){
		bpf_u_int32 net;

		printf("Capturing on interface: %s\n", ifname);
		// Find the properties for interface 
		if (pcap_lookupnet(ifname, &net, &mask, errbuf) == -1) {
			// if not available, use default
			mask = PCAP_NETMASK_UNKNOWN;
		}
/*
		handle = pcap_open_live(ifname, 1600, opt_promisc, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open inteface '%s': %s\n", ifname, errbuf);
			return(2);
		}
*/

		/* to set own pcap_set_buffer_size it must be this way and not useing pcap_lookupnet */

		int status = 0;
		if((handle = pcap_create(ifname, errbuf)) == NULL) {
			fprintf(stderr, "pcap_create failed on iface '%s': %s\n", ifname, errbuf);
			return(2);
		}
		if((status = pcap_set_snaplen(handle, 3200)) != 0) {
			fprintf(stderr, "error pcap_set_snaplen\n");
			return(2);
		}
		if((status = pcap_set_promisc(handle, opt_promisc)) != 0) {
			fprintf(stderr, "error pcap_set_promisc\n");
			return(2);
		}
		if((status = pcap_set_timeout(handle, 1000)) != 0) {
			fprintf(stderr, "error pcap_set_timeout\n");
			return(2);
		}

		/* this is not possible for libpcap older than 1.0.0 so now voipmonitor requires libpcap > 1.0.0
			set ring buffer size to 5M to prevent packet drops whan CPU goes high or on very high traffic 
			- default is 2MB for libpcap > 1.0.0
			- for libpcap < 1.0.0 it is controled by /proc/sys/net/core/rmem_default which is very low 
		*/
		if((status = pcap_set_buffer_size(handle, opt_ringbuffer * 1024 * 1024)) != 0) {
			fprintf(stderr, "error pcap_set_buffer_size\n");
			return(2);
		}

		if((status = pcap_activate(handle)) != 0) {
			fprintf(stderr, "error pcap_activate\n");
			return(2);
		}
	} else {
		printf("Reading file: %s\n", fname);
		mask = PCAP_NETMASK_UNKNOWN;
		handle = pcap_open_offline(fname, errbuf);
		if(handle == NULL) {
			fprintf(stderr, "Couldn't open pcap file '%s': %s\n", ifname, errbuf);
			return(2);
		}
	}

	chdir(opt_chdir);

	char filter_exp[2048] = "";		// The filter expression
	struct bpf_program fp;		// The compiled filter 

	if(*user_filter != '\0') {
		snprintf(filter_exp, sizeof(filter_exp), "%s", user_filter);

		// Compile and apply the filter
		if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
	}

	// set maximum open files 
	struct rlimit rlp;
	rlp.rlim_cur = 65535;
	rlp.rlim_max = 65535;
	setrlimit(RLIMIT_NOFILE, &rlp);
	getrlimit(RLIMIT_NOFILE, &rlp);
	if(rlp.rlim_cur != 65535) {
		printf("Warning, max open files is: %d consider raise this to 65535 with ulimit -n 65535\n", (int)rlp.rlim_cur);
	}
	// set core file dump to unlimited size
	rlp.rlim_cur = UINT_MAX;
	rlp.rlim_max = UINT_MAX;
	setrlimit(RLIMIT_CORE, &rlp);

	ipfilter = new IPfilter;
	ipfilter->load();
//	ipfilter->dump();

	telnumfilter = new TELNUMfilter;
	telnumfilter->load();

	// filters are ok, we can daemonize 
	if (opt_fork){
		daemonize();
	}
	
	// start thread processing queued cdr 
	pthread_create(&call_thread, NULL, storing_cdr, NULL);

	// start manager thread 	
	pthread_create(&manager_thread, NULL, manager_server, NULL);
	// start reading packets
//	readdump_libnids(handle);
	readdump_libpcap(handle);

	// close handler
	pcap_close(handle);

	// flush all queues
	Call *call;
	calltable->cleanup(0);
	terminating = 1;
	pthread_join(call_thread, NULL);
	while(calltable->calls_queue.size() != 0) {
			call = calltable->calls_queue.front();
			calltable->calls_queue.pop();
			delete call;
			calls--;
	}
	while(calltable->calls_deletequeue.size() != 0) {
			call = calltable->calls_deletequeue.front();
			calltable->calls_deletequeue.pop();
			delete call;
			calls--;
	}

	delete calltable;
	free(sipportmatrix);
	unlink(opt_pidfile);
}
