#include "config.h"
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <string>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <netdb.h>
#include <resolv.h>
#include <vorbis/codec.h>
#include <vorbis/vorbisenc.h>
#include <pcap.h>
#include <malloc.h>

#ifdef HAVE_LIBSSH
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#endif 

#include <openssl/crypto.h>  

#include <sstream>

#include "ipaccount.h"
#include "voipmonitor.h"
#include "calltable.h"
#include "sniff.h"
#include "format_slinear.h"
#include "codec_alaw.h"
#include "codec_ulaw.h"
#include "tools.h"
#include "calltable.h"
#include "format_ogg.h"
#include "cleanspool.h"
#include "pcap_queue.h"
#include "manager.h"
#include "fraud.h"
#include "rrd.h"
#include "tar.h"
#include "http.h"
#include "send_call_info.h"
#include "config_param.h"

//#define BUFSIZE 1024
//define BUFSIZE 20480
#define BUFSIZE 4096		//block size?

extern Calltable *calltable;
extern int opt_manager_port;
extern char opt_manager_ip[32];
extern int opt_manager_nonblock_mode;
extern volatile int calls_counter;
extern char opt_clientmanager[1024];
extern int opt_clientmanagerport;
extern char mac[32];
extern int verbosity;
extern char opt_chdir[1024];
extern char opt_php_path[1024];
extern int terminating;
extern int manager_socket_server;
extern int opt_nocdr;
extern int global_livesniffer;
extern map<unsigned int, octects_live_t*> ipacc_live;

extern map<unsigned int, livesnifferfilter_t*> usersniffer;
extern volatile int usersniffer_sync;

extern char ssh_host[1024];
extern int ssh_port;
extern char ssh_username[256];
extern char ssh_password[256];
extern char ssh_remote_listenhost[1024];
extern unsigned int ssh_remote_listenport;
extern int enable_bad_packet_order_warning;
extern ip_port opt_pcap_queue_send_to_ip_port;

extern cConfig CONFIG;
extern bool useNewCONFIG;

int opt_blocktarwrite = 0;
int opt_blockasyncprocess = 0;
int opt_blockprocesspacket = 0;
int opt_blockqfile = 0;

using namespace std;

struct listening_worker_arg {
	Call *call;
};

static void updateLivesnifferfilters();
static bool cmpCallBy_destroy_call_at(Call* a, Call* b);
static bool cmpCallBy_first_packet_time(Call* a, Call* b);
static int sendFile(const char *fileName, int client, ssh_channel sshchannel, bool zip);

livesnifferfilter_use_siptypes_s livesnifferfilterUseSipTypes;

ManagerClientThreads ClientThreads;

volatile int ssh_threads;
volatile int ssh_threads_break; 

class c_getfile_in_tar_completed {
public:
	c_getfile_in_tar_completed() {
		_sync = 0;
	}
	void add(const char *tar, const char *file, const char *key) {
		lock();
		data[string(tar) + "/" + file + "/" + key] = getTimeMS();
		unlock();
	}
	bool check(const char *tar, const char *file, const char *key) {
		lock();
		map<string, u_long>::iterator iter = data.find(string(tar) + "/" + file + "/" + key);
		bool rslt =  iter != data.end();
		unlock();
		cleanup();
		return(rslt);
	}
	void cleanup() {
		lock();
		u_long actTime = getTimeMS();
		map<string, u_long>::iterator iter = data.begin();
		while(iter != data.end()) {
			if(actTime - iter->second > 10000ul) {
				data.erase(iter++);
			} else {
				++iter;
			}
		}
		unlock();
	}
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
private:
	map<string, u_long> data;
	volatile int _sync;
} getfile_in_tar_completed;

/* 
 * this function runs as thread. It reads RTP audio data from call
 * and write it to output buffer 
 *
 * input parameter is structure where call 
 *
*/
void *listening_worker(void *arguments) {
	struct listening_worker_arg *args = (struct listening_worker_arg*)arguments;

        unsigned char read1[1024];
        unsigned char read2[1024];
        struct timeval tv;

	getUpdDifTime(&tv);
	alaw_init();
	ulaw_init();

        struct timeval tvwait;

	short int r1;
	short int r2;
	int len1,len2;

	// if call is hanged hup it will set listening_worker_run in its destructor to 0
	int listening_worker_run = 1;
	args->call->listening_worker_run = &listening_worker_run;
	pthread_mutex_lock(&args->call->listening_worker_run_lock);

	FILE *out = NULL;
	if(sverb.call_listening) {
		out = fopen("/tmp/test.raw", "w");
	}

//	vorbis_desc ogg;
//	ogg_header(out, &ogg);
//	fclose(out);
//	pthread_mutex_lock(&args->call->buflock);
//	ogg_header_live(&args->call->spybufferchar, &ogg);
//	pthread_mutex_unlock(&args->call->buflock);

	timespec tS;
	timespec tS2;

	tS.tv_sec = 0;
	tS.tv_nsec = 0;
	tS2.tv_sec = 0;
	tS2.tv_nsec = 0;

	long int udiff;

        while(listening_worker_run) {

		if(tS.tv_nsec > tS2.tv_nsec) {
			udiff = (1000 * 1000 * 1000 - (tS.tv_nsec - tS2.tv_nsec)) / 1000;
		} else {
			udiff = (tS2.tv_nsec - tS.tv_nsec) / 1000;
		}

		tvwait.tv_sec = 0;
		tvwait.tv_usec = 1000*20 - udiff; //20 ms
//		long int usec = tvwait.tv_usec;
		select(0, NULL, NULL, NULL, &tvwait);

		clock_gettime(CLOCK_REALTIME, &tS);
		char *s16char;

		//usleep(tvwait.tv_usec);
		pthread_mutex_lock(&args->call->buflock);
		len1 = circbuf_read(args->call->audiobuffer1, (char*)read1, 160);
		len2 = circbuf_read(args->call->audiobuffer2, (char*)read2, 160);
//		printf("codec_caller[%d] codec_called[%d] len1[%d] len2[%d] outbc[%d] outbchar[%d] wait[%u]\n", args->call->codec_caller, args->call->codec_called, len1, len2, (int)args->call->spybuffer.size(), (int)args->call->spybufferchar.size(), usec);
		if(len1 == 160 and len2 == 160) {
			for(int i = 0; i < len1; i++) {
				switch(args->call->codec_caller) {
				case 0:
					r1 = ULAW(read1[i]);
					break;
				case 8:
					r1 = ALAW(read1[i]);
					break;
				}
					
				switch(args->call->codec_caller) {
				case 0:
					r2 = ULAW(read2[i]);
					break;
				case 8:
					r2 = ALAW(read2[i]);
					break;
				}
				s16char = (char *)&r1;
				slinear_saturated_add((short int*)&r1, (short int*)&r2);
				if(sverb.call_listening) {
					fwrite(&r1, 1, 2, out);
				}
				args->call->spybufferchar.push(s16char[0]);
				args->call->spybufferchar.push(s16char[1]);
//				ogg_write_live(&ogg, &args->call->spybufferchar, (short int*)&r1);
			}
		} else if(len2 == 160) {
			for(int i = 0; i < len2; i++) {
				switch(args->call->codec_caller) {
				case 0:
					r2 = ULAW(read2[i]);
					break;
				case 8:
					r2 = ALAW(read2[i]);
					break;
				}
				if(sverb.call_listening) {
					fwrite(&r2, 1, 2, out);
				}
				s16char = (char *)&r2;
				args->call->spybufferchar.push(s16char[0]);
				args->call->spybufferchar.push(s16char[1]);
//				ogg_write_live(&ogg, &args->call->spybufferchar, (short int*)&r2);
			}
		} else if(len1 == 160) {
			for(int i = 0; i < len1; i++) {
				switch(args->call->codec_caller) {
				case 0:
					r1 = ULAW(read1[i]);
					break;
				case 8:
					r1 = ALAW(read1[i]);
					break;
				}
				if(sverb.call_listening) {
					fwrite(&r1, 1, 2, out);
				}
				s16char = (char *)&r1;
				args->call->spybufferchar.push(s16char[0]);
				args->call->spybufferchar.push(s16char[1]);
//				ogg_write_live(&ogg, &args->call->spybufferchar, (short int*)&r1);
			}
		} else {
			// write 20ms silence 
			int16_t s = 0;
			//unsigned char sa = 255;
			for(int i = 0; i < 160; i++) {
				if(sverb.call_listening) {
					fwrite(&s, 1, 2, out);
				}
				s16char = (char *)&s;
				args->call->spybufferchar.push(s16char[0]);
				args->call->spybufferchar.push(s16char[1]);
//				ogg_write_live(&ogg, &args->call->spybufferchar, (short int*)&s);
			}
		}
		pthread_mutex_unlock(&args->call->buflock);
		clock_gettime(CLOCK_REALTIME, &tS2);
        }

	// reset pointer to NULL as we are leaving the stack here
	args->call->listening_worker_run = NULL;
	pthread_mutex_unlock(&args->call->listening_worker_run_lock);

	if(sverb.call_listening) {
		fclose(out);
	}
	
	//clean ogg
/*
        ogg_stream_clear(&ogg.os);
        vorbis_block_clear(&ogg.vb);
        vorbis_dsp_clear(&ogg.vd);
        vorbis_comment_clear(&ogg.vc);
        vorbis_info_clear(&ogg.vi);
*/

	delete args;
	return 0;
}

#ifdef HAVE_LIBSSH
int sendssh(ssh_channel channel, const char *buf, int len) {
	int wr, i;
	wr = 0;
	do {   
		i = ssh_channel_write(channel, buf, len);
		if (i < 0) {
			fprintf(stderr, "libssh_channel_write: %d\n", i);
			return -1;
		}
		wr += i;
	} while(i > 0 && wr < len);
	return wr;
}
#else 
int sendssh(ssh_channel channel, const char *buf, int len) {
	return 0;
}
#endif

int sendvm(int socket, ssh_channel channel, const char *buf, size_t len, int mode) {
	int res;
	if(channel) {
		res = sendssh(channel, buf, len);
	} else {
		res = send(socket, buf, len, 0);
	}
	return res;
}

int _sendvm(int socket, void *channel, const char *buf, size_t len, int mode) {
	return(sendvm(socket, (ssh_channel)channel, buf, len, mode));
}

int sendvm_from_stdout_of_command(char *command, int socket, ssh_channel channel, char *buf, size_t len, int mode) {
	SimpleBuffer out;
	if(vm_pexec(command, &out) && out.size()) {
		if(sendvm(socket, channel, (const char*)out.data(), out.size(), 0) == -1) {
			if (verbosity > 0) syslog(LOG_NOTICE, "sendvm_from_stdout_of_command: sending data problem");
			return -1;
		}
	}
	return 0;
	
	/* obsolete
 
//using pipe for reading from stdout of given command;
    int retch;
    long total = 0;

    FILE *inpipe;
    
    cout << command << endl;
    
    inpipe = popen(command, "r");

    if (!inpipe) {
        syslog(LOG_ERR, "sendvm_from_stdout_of_command: couldn't open pipe for command %s", command);
        return -1;
    }

//     while (retch = fread(buf, sizeof(char), len, inpipe) > 0) {
// 		total += retch;
// 		syslog(LOG_ERR, "CTU: buflen:%d nacetl jsem %li create command",buflen, total);
// 
// 		if (sendvm(socket, channel, buf, retch, 0) == -1) {
// 			if (verbosity > 1) syslog(LOG_NOTICE, "Pipe RET %li bytes, problem sending using sendvm", total);
// 			return -1;
// 		}
//     }

	int filler = 0;		//'offset' buf pointer
	retch = 0;

	//read char by char from a pipe
    while ((retch = fread(buf + filler, 1, 1, inpipe)) > 0) {
		total ++;
		filler ++;

		if (filler == BUFSIZE) {
			filler = 0;
			if (sendvm(socket, channel, buf, BUFSIZE, 0) == -1) 
			{
				if (verbosity > 0) syslog(LOG_NOTICE, "sendvm_from_stdout_of_command: Pipe RET %li bytes, but problem sending using sendvm1", total);
				return -1;
			}
		}
    }
	if (filler > 0) {
		if (sendvm(socket, channel, buf, filler, 0) == -1) {
			if (verbosity > 0) syslog(LOG_NOTICE, "sendvm_from_stdout_of_command: Pipe RET %li bytes, but problem sending using sendvm2", total);
			return -1;
		}
	}

	if (verbosity > 1) syslog(LOG_NOTICE, "sendvm_from_stdout_of_command: Read total %li chars.", total);
    pclose(inpipe);
    return 0; 
	*/
}

int parse_command(char *buf, int size, int client, int eof, const char *buf_long, ManagerClientThread **managerClientThread = NULL, ssh_channel sshchannel = NULL) {
 
	char *pointerToEndSeparator = strstr(buf, "\r\n");
	if(pointerToEndSeparator) {
		*pointerToEndSeparator = 0;
	}
	if(sverb.manager) {
		cout << "manager command: " << buf << "|END" << endl;
	}
 
	char sendbuf[BUFSIZE];
	u_int32_t uid = 0;

	if(strstr(buf, "getversion") != NULL) {
		if ((size = sendvm(client, sshchannel, RTPSENSOR_VERSION, strlen(RTPSENSOR_VERSION), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "creategraph") != NULL) {
		checkRrdVersion(true);
		extern int vm_rrd_version;
		if(!vm_rrd_version) {
			if ((size = sendvm(client, sshchannel, "missing rrdtool", 15, 0)) == -1){
				cerr << "Error sending data to client" << endl;
				return -1;
			}
			return 0;
		}
	 
		extern pthread_mutex_t vm_rrd_lock;
		pthread_mutex_lock(&vm_rrd_lock);
		
		int res = 0;
		int manager_argc;
		char *manager_cmd_line = NULL;	//command line passed to voipmonitor manager
		char **manager_args = NULL;		//cuted voipmonitor manager commandline to separate arguments
	
		sendbuf[0] = 0;			//for reseting sendbuf

		if (( manager_argc = vm_rrd_countArgs(buf)) < 6) {	//few arguments passed
			if (verbosity > 0) syslog(LOG_NOTICE, "parse_command creategraph too few arguments, passed%d need at least 6!\n", manager_argc);
			snprintf(sendbuf, BUFSIZE, "Syntax: creategraph graph_type linuxTS_from linuxTS_to size_x_pixels size_y_pixels  [ slope-mode  [ icon-mode  [ color  [ dstfile ]]]]\n");
			if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
				cerr << "Error sending data to client 1" << endl;
			}
			pthread_mutex_unlock(&vm_rrd_lock);
			return -1;
		}
		if ((manager_cmd_line = new FILE_LINE char[strlen(buf) + 1]) == NULL) {
			syslog(LOG_ERR, "parse_command creategraph malloc error\n");
			pthread_mutex_unlock(&vm_rrd_lock);
			return -1;
		}
		if ((manager_args = new FILE_LINE char*[manager_argc + 1]) == NULL) {
			delete [] manager_cmd_line;
			syslog(LOG_ERR, "parse_command creategraph malloc error2\n");
			pthread_mutex_unlock(&vm_rrd_lock);
			return -1;
		}
		
		memcpy(manager_cmd_line, buf, strlen(buf));
		manager_cmd_line[strlen(buf)] = '\0';

		syslog(LOG_NOTICE, "creategraph VERBOSE ALL: %s", manager_cmd_line);
		if ((manager_argc = vm_rrd_createArgs(manager_cmd_line, manager_args))) {
			//Arguments:
			//0-creategraphs
			//1-graph type
			//2-at-style time from
			//3-at-style time to
			//4-total size x
			//5-total size y
			//[6-zaobleni hran(slope-mode)]
			//[7-discard graphs legend (for sizes bellow 600x240)]
			//[8-color]
			//[9-dstfile (if not defined PNG goes to stdout)]
			if (sverb.rrd_info) {
				syslog(LOG_NOTICE, "%d arguments detected. Showing them:\n", manager_argc);
				for (int i = 0; i < manager_argc; i++) {
					syslog (LOG_NOTICE, "%d.arg:%s",i, manager_args[i]);
				}
			}
		
			char *fromat, *toat;
			char filename[1000];
			int resx, resy;
			short slope, icon;
			char *dstfile;
			char *color;

			fromat = manager_args[2];
			toat = manager_args[3];
			resx = atoi(manager_args[4]);
			resy = atoi(manager_args[5]);
			if ((manager_argc > 6) && (manager_args[6][0] == '1')) slope = 1; else slope = 0;
			if ((manager_argc > 7) && (manager_args[7][0] == '1')) icon = 1; else icon = 0;
			if ((manager_argc > 8) && (manager_args[8][0] != '-')) color = manager_args[8]; else  color = NULL;
			if (manager_argc > 9) dstfile = manager_args[9]; else dstfile = NULL;			//set dstfile == NULL if not specified

			//limits check discarding graph's legend and axis/grid
			if ((resx < 400) or (resy < 200)) icon = 1;
			//Possible graph types: #PS,PSC,PSS,PSSM,PSSR,PSR,PSA,SQLq,SQLf,tCPU,drop,speed,heap,calls,tacCPU,RSSVSSZ


			char sendcommand[2048];			//buffer for send command string;
			if (!strncmp(manager_args[1], "PSA",4 )) {
				sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
				rrd_vm_create_graph_PSA_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "PSR", 4)) {
				sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
				rrd_vm_create_graph_PSR_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "PSSR", 5)) {
				sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
				rrd_vm_create_graph_PSSR_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "PSSM", 5)) {
				sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
				rrd_vm_create_graph_PSSM_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "PSS", 4)) {
				sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
				rrd_vm_create_graph_PSS_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "PSC", 4)) {
				sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
				rrd_vm_create_graph_PSC_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "PS", 3)) {
				sprintf(filename, "%s/rrd/2db-PS.rrd", opt_chdir);
				rrd_vm_create_graph_PS_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "SQLq", 5)) {
				sprintf(filename, "%s/rrd/db-SQL.rrd", opt_chdir);
				rrd_vm_create_graph_SQLq_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "SQLf", 5)) {
				sprintf(filename, "%s/rrd/db-SQL.rrd", opt_chdir);
				rrd_vm_create_graph_SQLf_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "tCPU", 5)) {
				sprintf(filename, "%s/rrd/db-tCPU.rrd", opt_chdir);
				rrd_vm_create_graph_tCPU_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "drop", 5)) {
				sprintf(filename, "%s/rrd/db-drop.rrd", opt_chdir);
				rrd_vm_create_graph_drop_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "speed", 5)) {
				sprintf(filename, "%s/rrd/db-speedmbs.rrd", opt_chdir);
				rrd_vm_create_graph_speed_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "heap", 5)) {
				sprintf(filename, "%s/rrd/db-heap.rrd", opt_chdir);
				rrd_vm_create_graph_heap_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "calls", 6)) {
				sprintf(filename, "%s/rrd/db-callscounter.rrd", opt_chdir);
				rrd_vm_create_graph_calls_command(filename, fromat, toat, color, resx ,resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "tacCPU", 7)) {
				sprintf(filename, "%s/rrd/db-tacCPU.rrd", opt_chdir);
				rrd_vm_create_graph_tacCPU_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else if (!strncmp(manager_args[1], "RSSVSZ", 7)) {
				sprintf(filename, "%s/rrd/db-RSSVSZ.rrd", opt_chdir);
				rrd_vm_create_graph_RSSVSZ_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
			} else {
				snprintf(sendbuf, BUFSIZE, "Error: Graph type %s isn't known\n\tGraph types: PS PSC PSS PSSM PSSR PSR PSA SQLq SQLf tCPU drop speed heap calls tacCPU RSSVSZ\n", manager_args[1]);	
				if (verbosity > 0) {
					syslog(LOG_NOTICE, "creategraph Error: Unrecognized graph type %s", manager_args[1]);
					syslog(LOG_NOTICE, "    Graph types: PS PSC PSS PSSM PSSR PSR PSA SQLq SQLf tCPU drop speed heap calls tacCPU RSSVSZ");
				}
				res = -1;
			}
			if ((dstfile == NULL) && (res == 0)) {		//send from stdout of a command (binary data)
				if (sverb.rrd_info) syslog(LOG_NOTICE, "COMMAND for system pipe:%s", sendcommand);
				if (sendvm_from_stdout_of_command(sendcommand, client, sshchannel, sendbuf, sizeof(sendbuf), 0) == -1 ){
					cerr << "Error sending data to client 2" << endl;
					delete [] manager_cmd_line;
					delete [] manager_args;
					pthread_mutex_unlock(&vm_rrd_lock);
					return -1;
				}
			} else {									//send string data (text data or error response)
				if (sverb.rrd_info) syslog(LOG_NOTICE, "COMMAND for system:%s", sendcommand);
				res = system(sendcommand);
				if ((verbosity > 0) && (res > 0)) snprintf(sendbuf, BUFSIZE, "ERROR while creating graph of type %s from:%s to:%s resx:%i resy:%i slopemode=%s, iconmode=%s\n", manager_args[1], fromat, toat, resx, resy, slope?"yes":"no", icon?"yes":"no");
				if ((verbosity > 0) && (res == 0)) snprintf(sendbuf, BUFSIZE, "Created graph of type %s from:%s to:%s resx:%i resy:%i slopemode=%s, iconmode=%s in file %s\n", manager_args[1], fromat, toat, resx, resy, slope?"yes":"no", icon?"yes":"no", dstfile);
				if (strlen(sendbuf)) {
					if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
						cerr << "Error sending data to client 3" << endl;
						delete [] manager_cmd_line;
						delete [] manager_args;
						pthread_mutex_unlock(&vm_rrd_lock);
						return -1;
					}
				}
			}
		}
		delete [] manager_cmd_line;
		delete [] manager_args;
		pthread_mutex_unlock(&vm_rrd_lock);
		return res;

	} else if(strstr(buf, "reindexfiles") != NULL) {
		char date[21];
		int hour;
		bool badParams = false;
		if(strstr(buf, "reindexfiles_datehour")) {
			if(sscanf(buf + strlen("reindexfiles_datehour") + 1, "%20s %i", date, &hour) != 2) {
				badParams = true;
			}
		} else if(strstr(buf, "reindexfiles_date")) {
			if(sscanf(buf + strlen("reindexfiles_date") + 1, "%20s", date) != 1) {
				badParams = true;
			}
		}
		if(badParams) {
			snprintf(sendbuf, BUFSIZE, "bad parameters");
			if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
				cerr << "Error sending data to client" << endl;
			}
			return -1;
		}
		snprintf(sendbuf, BUFSIZE, "starting reindexing please wait...");
		if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		if(strstr(buf, "reindexfiles_datehour")) {
			reindex_date_hour(date, hour);
		} else if(strstr(buf, "reindexfiles_date")) {
			reindex_date(date);
		} else {
			convert_filesindex();
		}
		snprintf(sendbuf, BUFSIZE, "done\r\n");
		if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "check_filesindex") != NULL) {
		snprintf(sendbuf, BUFSIZE, "starting checking indexing please wait...");
		if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		check_filesindex();
		snprintf(sendbuf, BUFSIZE, "done\r\n");
		if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "totalcalls") != NULL) {
		snprintf(sendbuf, BUFSIZE, "%d", calls_counter);
		if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "disablecdr") != NULL) {
		opt_nocdr = 1;
		if ((size = sendvm(client, sshchannel, "disabled", 8, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "enablecdr") != NULL) {
		opt_nocdr = 0;
		if ((size = sendvm(client, sshchannel, "enabled", 7, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "listcalls") != NULL) {
		//list<Call*>::iterator call;
		map<string, Call*>::iterator callMAPIT;
		Call *call;
		char outbuf[2048];
		char *resbuf = new FILE_LINE char[32 * 1024];
		unsigned int resbufalloc = 32 * 1024, outbuflen = 0, resbuflen = 0;
		if(outbuf == NULL) {
			syslog(LOG_ERR, "Cannot allocate memory\n");
			return -1;
		}
		/* headers */
		outbuflen = sprintf(outbuf, 
				    "[[\"callreference\", "
				    "\"callid\", "
				    "\"callercodec\", "
				    "\"calledcodec\", "
				    "\"caller\", "
				    "\"callername\", "
				    "\"callerdomain\", "
				    "\"called\", "
				    "\"calleddomain\", "
				    "\"calldate\", "
				    "\"duration\", "
				    "\"connect_duration\", "
				    "\"callerip\", "
				    "\"calledip\", "
				    "\"lastpackettime\", "
				    "\"lastSIPresponseNum\"]");
		memcpy(resbuf + resbuflen, outbuf, outbuflen);
		resbuflen += outbuflen;
		calltable->lock_calls_listMAP();
		for (callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
			call = (*callMAPIT).second;
			if(call->type == REGISTER or call->type == MESSAGE or call->destroy_call_at > 0 or call->destroy_call_at_bye > 0) {
				// skip register or message or calls which are scheduled to be closed
				continue;
			}
			/* 
			 * caller 
			 * callername
			 * called
			 * calldate
			 * duration
			 * callerip htonl(sipcallerip)
			 * sipcalledip htonl(sipcalledip)
			*/
			//XXX: escape " or replace it to '
			outbuflen = sprintf(outbuf, 
					    ",[\"%p\", "
					    "\"%s\", "
					    "\"%d\", "
					    "\"%d\", "
					    "\"%s\", "
					    "\"%s\", "
					    "\"%s\", "
					    "\"%s\", "
					    "\"%s\", "
					    "\"%s\", "
					    "\"%d\", "
					    "\"%d\", "
					    "\"%u\", "
					    "\"%u\", "
					    "\"%u\", "
					    "\"%d\"]",
					    call, 
					    call->call_id.c_str(), 
					    call->last_callercodec, 
					    call->last_callercodec, 
					    call->caller, 
					    call->callername, 
					    call->caller_domain,
					    call->called, 
					    call->called_domain,
					    sqlDateTimeString(call->calltime()).c_str(), 
					    call->duration_active(), 
					    call->connect_duration_active(), 
					    htonl(call->sipcallerip[0]), 
					    htonl(call->sipcalledip[0]), 
					    (unsigned int)call->get_last_packet_time(), 
					    call->lastSIPresponseNum);
			if((resbuflen + outbuflen) > resbufalloc) {
				char *resbufnew = new FILE_LINE char[resbufalloc + 32 * 1024];
				memcpy(resbufnew, resbuf, resbufalloc);
				delete [] resbuf;
				resbuf = resbufnew;
				resbufalloc += 32 * 1024;
			}
			memcpy(resbuf + resbuflen, outbuf, outbuflen);
			resbuflen += outbuflen;
		}
		calltable->unlock_calls_listMAP();
		if((resbuflen + 1) > resbufalloc) {
			char *resbufnew = new FILE_LINE char[resbufalloc + 32 * 1024];
			memcpy(resbufnew, resbuf, resbufalloc);
			delete [] resbuf;
			resbuf = resbufnew;
			resbufalloc += 32 * 1024;
		}
		resbuf[resbuflen] = ']';
		resbuflen++;
		if ((size = sendvm(client, sshchannel, resbuf, resbuflen, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		delete [] resbuf;
		return 0;
	} else if(strstr(buf, "d_lc_for_destroy") != NULL) {
		ostringstream outStr;
		if(calltable->calls_queue.size()) {
			Call *call;
			vector<Call*> vectCall;
			calltable->lock_calls_queue();
			for(size_t i = 0; i < calltable->calls_queue.size(); ++i) {
				call = calltable->calls_queue[i];
				if(call->type != REGISTER && call->destroy_call_at) {
					vectCall.push_back(call);
				}
			}
			if(vectCall.size()) { 
				std::sort(vectCall.begin(), vectCall.end(), cmpCallBy_destroy_call_at);
				for(size_t i = 0; i < vectCall.size(); i++) {
					call = vectCall[i];
					outStr.width(15);
					outStr << call->caller << " -> ";
					outStr.width(15);
					outStr << call->called << "  "
					<< sqlDateTimeString(call->calltime()) << "  ";
					outStr.width(6);
					outStr << call->duration() << "s  "
					<< sqlDateTimeString(call->destroy_call_at) << "  "
					<< call->fbasename;
					outStr << endl;
				}
			}
			calltable->unlock_calls_queue();
		}
		outStr << "-----------" << endl;
		if ((size = sendvm(client, sshchannel, outStr.str().c_str(), outStr.str().length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "d_lc_bye") != NULL) {
		ostringstream outStr;
		map<string, Call*>::iterator callMAPIT;
		Call *call;
		vector<Call*> vectCall;
		calltable->lock_calls_listMAP();
		for (callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
			call = (*callMAPIT).second;
			if(call->type != REGISTER && call->seenbye) {
				vectCall.push_back(call);
			}
		}
		if(vectCall.size()) { 
			std::sort(vectCall.begin(), vectCall.end(), cmpCallBy_destroy_call_at);
			for(size_t i = 0; i < vectCall.size(); i++) {
				call = vectCall[i];
				outStr.width(15);
				outStr << call->caller << " -> ";
				outStr.width(15);
				outStr << call->called << "  "
				<< sqlDateTimeString(call->calltime()) << "  ";
				outStr.width(6);
				outStr << call->duration() << "s  "
				<< (call->destroy_call_at ? sqlDateTimeString(call->destroy_call_at) : "    -  -     :  :  ")  << "  "
				<< call->fbasename;
				outStr << endl;
			}
		}
		calltable->unlock_calls_listMAP();
		outStr << "-----------" << endl;
		if ((size = sendvm(client, sshchannel, outStr.str().c_str(), outStr.str().length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "d_lc_all") != NULL) {
		ostringstream outStr;
		map<string, Call*>::iterator callMAPIT;
		Call *call;
		vector<Call*> vectCall;
		calltable->lock_calls_listMAP();
		for (callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
			vectCall.push_back((*callMAPIT).second);
		}
		if(vectCall.size()) { 
			std::sort(vectCall.begin(), vectCall.end(), cmpCallBy_first_packet_time);
			for(size_t i = 0; i < vectCall.size(); i++) {
				call = vectCall[i];
				outStr.width(15);
				outStr << call->caller << " -> ";
				outStr.width(15);
				outStr << call->called << "  "
				<< sqlDateTimeString(call->calltime()) << "  ";
				outStr.width(6);
				outStr << call->duration() << "s  "
				<< (call->destroy_call_at ? sqlDateTimeString(call->destroy_call_at) : "    -  -     :  :  ")  << "  ";
				outStr.width(3);
				outStr << call->lastSIPresponseNum << "  "
				<< call->fbasename;
				outStr << endl;
			}
		}
		calltable->unlock_calls_listMAP();
		outStr << "-----------" << endl;
		if ((size = sendvm(client, sshchannel, outStr.str().c_str(), outStr.str().length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "d_close_call") != NULL) {
		char fbasename[100];
		sscanf(buf, "d_close_call %s", fbasename);
		string rslt = fbasename + string(" missing");
		map<string, Call*>::iterator callMAPIT;
		calltable->lock_calls_listMAP();
		for (callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
			if(!strcmp((*callMAPIT).second->fbasename, fbasename)) {
				(*callMAPIT).second->force_close = true;
				rslt = fbasename + string(" close");
				break;
			}
		}
		calltable->unlock_calls_listMAP();
		if ((size = sendvm(client, sshchannel, (rslt + "\n").c_str(), rslt.length() + 1, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "cleanup_calls") != NULL) {
		calltable->cleanup(0);
		if ((size = sendvm(client, sshchannel, "ok", 2, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "getipaccount") != NULL) {
		sscanf(buf, "getipaccount %u", &uid);
		map<unsigned int, octects_live_t*>::iterator it = ipacc_live.find(uid);
		if(it != ipacc_live.end()) {
			snprintf(sendbuf, BUFSIZE, "%d", 1);
		} else {
			snprintf(sendbuf, BUFSIZE, "%d", 0);
		}
		if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "ipaccountfilter set") != NULL) {
		
		string ipfilter;
		if(buf_long) {
			buf = (char*)buf_long;
		}
		u_int32_t id = atol(buf + strlen("ipaccountfilter set "));
		char *pointToSeparatorBefereIpfilter = strchr(buf + strlen("ipaccountfilter set "), ' ');
		if(pointToSeparatorBefereIpfilter) {
			ipfilter = pointToSeparatorBefereIpfilter + 1;
		}
		if(!ipfilter.length() || ipfilter.find("ALL") != string::npos) {
			map<unsigned int, octects_live_t*>::iterator it = ipacc_live.find(id);
			octects_live_t* filter;
			if(it != ipacc_live.end()) {
				filter = it->second;
			} else {
				filter = new FILE_LINE octects_live_t;
				memset(filter, 0, sizeof(octects_live_t));
				filter->all = 1;
				filter->fetch_timestamp = time(NULL);
				ipacc_live[id] = filter;
				if(verbosity > 0) {
					cout << "START LIVE IPACC " << "id: " << id << " ipfilter: " << "ALL" << endl;
				}
			}
			return 0;
		} else {
			octects_live_t* filter;
			filter = new FILE_LINE octects_live_t;
			memset(filter, 0, sizeof(octects_live_t));
			filter->setFilter(ipfilter.c_str());
			filter->fetch_timestamp = time(NULL);
			ipacc_live[id] = filter;
			if(verbosity > 0) {
				cout << "START LIVE IPACC " << "id: " << id << " ipfilter: " << ipfilter << endl;
			}
		}
		return(0);
	} else if(strstr(buf, "stopipaccount")) {
		u_int32_t id = 0;
		sscanf(buf, "stopipaccount %u", &id);
		map<unsigned int, octects_live_t*>::iterator it = ipacc_live.find(id);
		if(it != ipacc_live.end()) {
			delete it->second;
			ipacc_live.erase(it);
			if(verbosity > 0) {
				cout << "STOP LIVE IPACC " << "id:" << id << endl;
			}
		}
		return 0;
	} else if(strstr(buf, "fetchipaccount")) {
		u_int32_t id = 0;
		sscanf(buf, "fetchipaccount %u", &id);
		map<unsigned int, octects_live_t*>::iterator it = ipacc_live.find(id);
		char sendbuf[1024];
		if(it == ipacc_live.end()) {
			strcpy(sendbuf, "stopped");
		} else {
			octects_live_t *data = it->second;
			snprintf(sendbuf, 1024, "%u;%llu;%u;%llu;%u;%llu;%u;%llu;%u;%llu;%u;%llu;%u", 
				(unsigned int)time(NULL),
				data->dst_octects, data->dst_numpackets, 
				data->src_octects, data->src_numpackets, 
				data->voipdst_octects, data->voipdst_numpackets, 
				data->voipsrc_octects, data->voipsrc_numpackets, 
				data->all_octects, data->all_numpackets,
				data->voipall_octects, data->voipall_numpackets);
			data->fetch_timestamp = time(NULL);
		}
		if((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1) {
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
///////////////////////////////////////////////////////////////
	} else if(strstr(buf, "getactivesniffers")) {
		while(__sync_lock_test_and_set(&usersniffer_sync, 1));
		string jsonResult = "[";
		map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT;
		int counter = 0;
		for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); usersnifferIT++) {
			if(counter) {
				jsonResult += ",";
			}
			char uid_str[10];
			sprintf(uid_str, "%i", usersnifferIT->first);
			jsonResult += "{\"uid\": \"" + string(uid_str) + "\"," +
					"\"state\":\"" + usersnifferIT->second->getStringState() + "\"}";
			++counter;
		}
		jsonResult += "]";
		__sync_lock_release(&usersniffer_sync);
		if((size = sendvm(client, sshchannel, jsonResult.c_str(), jsonResult.length(), 0)) == -1) {
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
        } else if(strstr(buf, "stoplivesniffer")) {
                sscanf(buf, "stoplivesniffer %u", &uid);
		while(__sync_lock_test_and_set(&usersniffer_sync, 1));
                map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT = usersniffer.find(uid);
                if(usersnifferIT != usersniffer.end()) {
                        delete usersnifferIT->second;
                        usersniffer.erase(usersnifferIT);
			if(!usersniffer.size()) {
				global_livesniffer = 0;
			}
			updateLivesnifferfilters();
			if(verbosity > 0) {
				 syslog(LOG_NOTICE, "stop livesniffer - uid: %u", uid);
			}
                }
                __sync_lock_release(&usersniffer_sync);
                return 0;
	} else if(strstr(buf, "getlivesniffer") != NULL) {
		sscanf(buf, "getlivesniffer %u", &uid);
		while(__sync_lock_test_and_set(&usersniffer_sync, 1));
		map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT = usersniffer.find(uid);
		if(usersnifferIT != usersniffer.end()) {
			snprintf(sendbuf, BUFSIZE, "%d", 1);
		} else {
			snprintf(sendbuf, BUFSIZE, "%d", 0);
		}
		__sync_lock_release(&usersniffer_sync);
		if ((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "livefilter set") != NULL) {
		char search[1024] = "";
		char value[1024] = "";

		sscanf(buf, "livefilter set %u %s %[^\n\r]", &uid, search, value);
		if(verbosity > 0) {
			syslog(LOG_NOTICE, "set livesniffer - uid: %u search: %s value: %s", uid, search, value);
		}
		
		while(__sync_lock_test_and_set(&usersniffer_sync, 1));

		if(memmem(search, sizeof(search), "all", 3)) {
			global_livesniffer = 1;
			map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT = usersniffer.find(uid);
			livesnifferfilter_t* filter;
			if(usersnifferIT != usersniffer.end()) {
				filter = usersnifferIT->second;
			} else {
				filter = new FILE_LINE livesnifferfilter_t;
				memset(filter, 0, sizeof(livesnifferfilter_t));
				usersniffer[uid] = filter;
			}
			updateLivesnifferfilters();
			__sync_lock_release(&usersniffer_sync);
			return 0;
		}

		map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT = usersniffer.find(uid);
		livesnifferfilter_t* filter;
		if(usersnifferIT != usersniffer.end()) {
			filter = usersnifferIT->second;
		} else {
			filter = new FILE_LINE livesnifferfilter_t;
			memset(filter, 0, sizeof(livesnifferfilter_t));
			usersniffer[uid] = filter;
		}
		
		if(strstr(search, "srcaddr")) {
			int i = 0;
			//reset filters 
			for(i = 0; i < MAXLIVEFILTERS; i++) {
				filter->lv_saddr[i] = 0;
			}
			stringstream  data(value);
			string val;
			// read all argumens lkivefilter set saddr 123 345 244
			i = 0;
			while(i < MAXLIVEFILTERS and getline(data, val,' ')){
				global_livesniffer = 1;
				//convert doted ip to unsigned int
				filter->lv_saddr[i] = ntohl((unsigned int)inet_addr(val.c_str()));
				i++;
			}
			updateLivesnifferfilters();
		} else if(strstr(search, "dstaddr")) {
			int i = 0;
			//reset filters 
			for(i = 0; i < MAXLIVEFILTERS; i++) {
				filter->lv_daddr[i] = 0;
			}
			stringstream  data(value);
			string val;
			i = 0;
			// read all argumens livefilter set daddr 123 345 244
			while(i < MAXLIVEFILTERS and getline(data, val,' ')){
				global_livesniffer = 1;
				//convert doted ip to unsigned int
				filter->lv_daddr[i] = ntohl((unsigned int)inet_addr(val.c_str()));
				i++;
			}
			updateLivesnifferfilters();
		} else if(strstr(search, "bothaddr")) {
			int i = 0;
			//reset filters 
			for(i = 0; i < MAXLIVEFILTERS; i++) {
				filter->lv_bothaddr[i] = 0;
			}
			stringstream  data(value);
			string val;
			i = 0;
			// read all argumens livefilter set bothaddr 123 345 244
			while(i < MAXLIVEFILTERS and getline(data, val,' ')){
				global_livesniffer = 1;
				//convert doted ip to unsigned int
				filter->lv_bothaddr[i] = ntohl((unsigned int)inet_addr(val.c_str()));
				i++;
			}
			updateLivesnifferfilters();
		} else if(strstr(search, "srcnum")) {
			int i = 0;
			//reset filters 
			for(i = 0; i < MAXLIVEFILTERS; i++) {
				filter->lv_srcnum[i][0] = '\0';
			}
			stringstream  data(value);
			string val;
			i = 0;
			// read all argumens livefilter set srcaddr 123 345 244
			while(i < MAXLIVEFILTERS and getline(data, val,' ')){
				global_livesniffer = 1;
				stringstream tmp;
				tmp << val;
				tmp >> filter->lv_srcnum[i];
				//cout << filter->lv_srcnum[i] << "\n";
				i++;
			}
			updateLivesnifferfilters();
		} else if(strstr(search, "dstnum")) {
			int i = 0;
			//reset filters 
			for(i = 0; i < MAXLIVEFILTERS; i++) {
				filter->lv_dstnum[i][0] = '\0';
			}
			stringstream  data(value);
			string val;
			i = 0;
			// read all argumens livefilter set dstaddr 123 345 244
			while(i < MAXLIVEFILTERS and getline(data, val,' ')){
				global_livesniffer = 1;
				stringstream tmp;
				tmp << val;
				tmp >> filter->lv_dstnum[i];
				//cout << filter->lv_dstnum[i] << "\n";
				i++;
			}
			updateLivesnifferfilters();
		} else if(strstr(search, "bothnum")) {
			int i = 0;
			//reset filters 
			for(i = 0; i < MAXLIVEFILTERS; i++) {
				filter->lv_bothnum[i][0] = '\0';
			}
			stringstream  data(value);
			string val;
			i = 0;
			// read all argumens livefilter set bothaddr 123 345 244
			while(i < MAXLIVEFILTERS and getline(data, val,' ')){
				global_livesniffer = 1;
				stringstream tmp;
				tmp << val;
				tmp >> filter->lv_bothnum[i];
				//cout << filter->lv_bothnum[i] << "\n";
				i++;
			}
			updateLivesnifferfilters();
		} else if(strstr(search, "siptypes")) {
			//cout << "siptypes: " << value << "\n";
			for(size_t i = 0; i < strlen(value) && i < MAXLIVEFILTERS; i++) {
				filter->lv_siptypes[i] = value[i] == 'I' ? INVITE :
							 value[i] == 'R' ? REGISTER :
							 value[i] == 'O' ? OPTIONS :
							 value[i] == 'S' ? SUBSCRIBE :
							 value[i] == 'M' ? MESSAGE :
							 value[i] == 'N' ? NOTIFY :
									   0;
			}
			updateLivesnifferfilters();
		}
		
		__sync_lock_release(&usersniffer_sync);
		
		if ((size = sendvm(client, sshchannel, "ok", 2, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "listen") != NULL) {
		long long callreference;

		intptr_t tmp1,tmp2;

		sscanf(buf, "listen %llu", &callreference);
		if(!callreference) {
			sscanf(buf, "listen %llxu", &callreference);
		}

		tmp1 = callreference;
	
		map<string, Call*>::iterator callMAPIT;
		Call *call;
		calltable->lock_calls_listMAP();
		for (callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
			call = (*callMAPIT).second;
			tmp2 = (intptr_t)call;

			//printf("call[%p] == [%li] [%d] [%li] [%li]\n", call, callreference, (long int)call == (long int)callreference, (long int)call, (long int)callreference);
				
			//if((long long)call == (long long)callreference) {
			if(tmp1 == tmp2) {
				if(call->listening_worker_run) {
					// the thread is already running. 
					if ((size = sendvm(client, sshchannel, "call already listening", 22, 0)) == -1){
						cerr << "Error sending data to client" << endl;
						return -1;
					}
					calltable->unlock_calls_listMAP();
					return 0;
				} else {
					struct listening_worker_arg *args = new FILE_LINE listening_worker_arg;
					args->call = call;
					call->audiobuffer1 = new FILE_LINE pvt_circbuf;
					call->audiobuffer2 = new FILE_LINE pvt_circbuf;
					circbuf_init(call->audiobuffer1, 20000);
					circbuf_init(call->audiobuffer2, 20000);

					pthread_t call_thread;
					pthread_create(&call_thread, NULL, listening_worker, (void *)args);
					calltable->unlock_calls_listMAP();
					if ((size = sendvm(client, sshchannel, "success", 7, 0)) == -1){
						cerr << "Error sending data to client" << endl;
						return -1;
					}
					return 0;
				}
			}
		}
		calltable->unlock_calls_listMAP();
		if ((size = sendvm(client, sshchannel, "call not found", 14, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "readaudio") != NULL) {
		long long callreference;

		sscanf(buf, "readaudio %llu", &callreference);
		if(!callreference) {
			sscanf(buf, "readaudio %llxu", &callreference);
		}
	
		map<string, Call*>::iterator callMAPIT;
		Call *call;
		int i;
		calltable->lock_calls_listMAP();
		for (callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
			call = (*callMAPIT).second;
			if((long int)call == (long int)callreference) {
				pthread_mutex_lock(&call->buflock);
				size_t bsize = call->spybufferchar.size();
				char *buff = new FILE_LINE char[bsize];
				for(i = 0; i < (int)bsize; i++) {
					buff[i] = call->spybufferchar.front();
					call->spybufferchar.pop();
				}
				pthread_mutex_unlock(&call->buflock);
				if ((size = sendvm(client, sshchannel, buff, bsize, 0)) == -1){
					delete [] buff;
					calltable->unlock_calls_listMAP();
					cerr << "Error sending data to client" << endl;
					return -1;
				}
				delete [] buff;
			}
		}
		calltable->unlock_calls_listMAP();
		return 0;
	} else if(strstr(buf, "reload") != NULL) {
		reload_config();
		if ((size = sendvm(client, sshchannel, "reload ok", 9, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "hot_restart") != NULL) {
		hot_restart();
		if ((size = sendvm(client, sshchannel, "hot restart ok", 9, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "get_json_config") != NULL) {
		string rslt = useNewCONFIG ? CONFIG.getJson() : "not supported";
		if ((size = sendvm(client, sshchannel, rslt.c_str(), rslt.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "set_json_config ") != NULL) {
		string rslt;
		if(useNewCONFIG) {
			hot_restart_with_json_config(buf + 16);
			rslt = "ok";
		} else {
			rslt = "not supported";
		}
		if ((size = sendvm(client, sshchannel, rslt.c_str(), rslt.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "fraud_refresh") != NULL) {
		refreshFraud();
		if ((size = sendvm(client, sshchannel, "reload ok", 9, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "send_call_info_refresh") != NULL) {
		refreshSendCallInfo();
		if ((size = sendvm(client, sshchannel, "reload ok", 9, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "custom_headers_refresh") != NULL) {
		extern CustomHeaders *custom_headers_cdr;
		extern CustomHeaders *custom_headers_message;
		if(custom_headers_cdr) {
			custom_headers_cdr->refresh();
		}
		if(custom_headers_message) {
			custom_headers_message->refresh();
		}
		if ((size = sendvm(client, sshchannel, "reload ok", 9, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "getfile_is_zip_support") != NULL) {
		if ((size = sendvm(client, sshchannel, "OK", 2, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "getfile_in_tar_check_complete") != NULL) {
		char tar_filename[2048];
		char filename[2048];
		char dateTimeKey[2048];
		
		sscanf(buf, "getfile_in_tar_check_complete %s %s %s", tar_filename, filename, dateTimeKey);
		
		const char *rslt = getfile_in_tar_completed.check(tar_filename, filename, dateTimeKey) ? "OK" : "uncomplete";
		
		if ((size = sendvm(client, sshchannel, rslt, strlen(rslt), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "getfile_in_tar") != NULL) {
		bool zip = strstr(buf, "getfile_in_tar_zip");
	 
		char tar_filename[2048];
		char filename[2048];
		char dateTimeKey[2048];
		u_int32_t recordId = 0;
		char tableType[100] = "";
		char *tarPosI = new char[100000];
		*tarPosI = 0;

		sscanf(buf, zip ? "getfile_in_tar_zip %s %s %s %u %s %s" : "getfile_in_tar %s %s %s %u %s %s", tar_filename, filename, dateTimeKey, &recordId, tableType, tarPosI);
		
		Tar tar;
		if(!tar.tar_open(tar_filename, O_RDONLY)) {
			tar.tar_read_send_parameters(client, sshchannel, zip);
			tar.tar_read((string(filename) + ".*").c_str(), filename, recordId, tableType, tarPosI);
			if(tar.isReadEnd()) {
				getfile_in_tar_completed.add(tar_filename, filename, dateTimeKey);
			}
		} else {
			sprintf(buf, "error: cannot open file [%s]", tar_filename);
			if ((size = sendvm(client, sshchannel, buf, strlen(buf), 0)) == -1){
				cerr << "Error sending data to client" << endl;
			}
			delete [] tarPosI;
			return -1;
		}
		delete [] tarPosI;
		return 0;
	} else if(strstr(buf, "getfile") != NULL) {
		bool zip = strstr(buf, "getfile_zip");
		
		char filename[2048];
		sscanf(buf, zip ? "getfile_zip %s" : "getfile %s", filename);

		return(sendFile(filename, client, sshchannel, zip));
	} else if(strstr(buf, "file_exists") != NULL) {
		if(opt_pcap_queue_send_to_ip_port) {
			sendvm(client, sshchannel, "mirror", 6, 0);
			return 0;
		}
	 
		char filename[2048];
		unsigned int size;
		string rslt;

		sscanf(buf, "file_exists %s", filename);
		if(FileExists(filename)) {
			size = file_exists(filename);
			char size_str[20];
			sprintf(size_str, "%d", size);
			rslt = size_str;
			if(size > 0 && strstr(filename, "tar")) {
				for(int i = 1; i <= 5; i++) {
					char nextfilename[2048];
					strcpy(nextfilename, filename);
					sprintf(nextfilename + strlen(nextfilename), ".%i", i);
					unsigned int nextsize = file_exists(nextfilename);
					if(nextsize > 0) {
						char nextsize_str[20];
						sprintf(nextsize_str, "%d", nextsize);
						rslt.append(string(";") + nextfilename + ":" + nextsize_str);
					} else {
						break;
					}
				}
			}
		} else {
			rslt = "not_exists";
		}
		sendvm(client, sshchannel, rslt.c_str(), rslt.length(), 0);
		return 0;
	} else if(strstr(buf, "fileexists") != NULL) {
		char filename[2048];
		unsigned int size;

		sscanf(buf, "fileexists %s", filename);
		size = file_exists(filename);
		sprintf(buf, "%d", size);
		sendvm(client, sshchannel, buf, strlen(buf), 0);
		return 0;
	} else if(strstr(buf, "flush_tar") != NULL) {
		char filename[2048];
		sscanf(buf, "flush_tar %s", filename);
		flushTar(filename);
		sendvm(client, sshchannel, "OK", 2, 0);
		return 0;
	} else if(strstr(buf, "genwav") != NULL) {
		char filename[2048];
		unsigned int size;
		char wavfile[2048];
		char pcapfile[2048];
		char cmd[4092];
		int secondrun = 0;

		sscanf(buf, "genwav %s", filename);

		sprintf(pcapfile, "%s.pcap", filename);
		sprintf(wavfile, "%s.wav", filename);

getwav2:
		size = file_exists(wavfile);
		if(size) {
			sprintf(buf, "%d", size);
			sendvm(client, sshchannel, buf, strlen(buf), 0);
			return 0;
		}
		if(secondrun > 0) {
			// wav does not exist 
			sendvm(client, sshchannel, "0", 1, 0);
			return -1;
		}

		// wav does not exists, check if exists pcap and try to create wav
		size = file_exists(pcapfile);
		if(!size) {
			sendvm(client, sshchannel, "0", 1, 0);
			return -1;
		}
		sprintf(cmd, "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin voipmonitor --rtp-firstleg -k -WRc -r \"%s.pcap\" -y -d %s 2>/dev/null >/dev/null", filename, opt_chdir);
		system(cmd);
		secondrun = 1;
		goto getwav2;
	} else if(strstr(buf, "getwav") != NULL) {
		char filename[2048];
		int fd;
		unsigned int size;
		char wavfile[2048];
		char pcapfile[2048];
		char cmd[4092];
		char rbuf[4096];
		int res;
		ssize_t nread;
		int secondrun = 0;

		sscanf(buf, "getwav %s", filename);

		sprintf(pcapfile, "%s.pcap", filename);
		sprintf(wavfile, "%s.wav", filename);

getwav:
		size = file_exists(wavfile);
		if(size) {
			fd = open(wavfile, O_RDONLY);
			if(fd < 0) {
				sprintf(buf, "error: cannot open file [%s]", wavfile);
				if ((res = sendvm(client, sshchannel, buf, strlen(buf), 0)) == -1){
					cerr << "Error sending data to client" << endl;
				}
				return -1;
			}
			while(nread = read(fd, rbuf, sizeof rbuf), nread > 0) {
				if ((res = sendvm(client, sshchannel, rbuf, nread, 0)) == -1){
					close(fd);
					return -1;
				}
			}
			if(eof) {
				if ((res = sendvm(client, sshchannel, "EOF", 3, 0)) == -1){
					close(fd);
					return -1;
				}
			}
			close(fd);
			return 0;
		}
		if(secondrun > 0) {
			// wav does not exist 
			sendvm(client, sshchannel, "0", 1, 0);
			return -1;
		}

		// wav does not exists, check if exists pcap and try to create wav
		size = file_exists(pcapfile);
		if(!size) {
			sendvm(client, sshchannel, "0", 1, 0);
			return -1;
		}
		sprintf(cmd, "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin voipmonitor --rtp-firstleg -k -WRc -r \"%s.pcap\" -y 2>/dev/null >/dev/null", filename);
		system(cmd);
		secondrun = 1;
		goto getwav;
	} else if(strstr(buf, "getsiptshark") != NULL) {
		char filename[2048];
		int fd;
		unsigned int size;
		char tsharkfile[2048];
		char pcapfile[2048];
		char cmd[4092];
		char rbuf[4096];
		int res;
		ssize_t nread;

		sscanf(buf, "getsiptshark %s", filename);

		sprintf(tsharkfile, "%s.pcap2txt", filename);
		sprintf(pcapfile, "%s.pcap", filename);


		size = file_exists(tsharkfile);
		if(size) {
			fd = open(tsharkfile, O_RDONLY);
			if(fd < 0) {
				sprintf(buf, "error: cannot open file [%s]", tsharkfile);
				if ((res = sendvm(client, sshchannel, buf, strlen(buf), 0)) == -1){
					cerr << "Error sending data to client" << endl;
				}
				return -1;
			}
			while(nread = read(fd, rbuf, sizeof rbuf), nread > 0) {
				if ((res = sendvm(client, sshchannel, rbuf, nread, 0)) == -1){
					close(fd);
					return -1;
				}
			}
			if(eof) {
				if ((res = sendvm(client, sshchannel, "EOF", 3, 0)) == -1){
					close(fd);
					return -1;
				}
			}
			close(fd);
			return 0;
		}

		size = file_exists(pcapfile);
		if(!size) {
			sendvm(client, sshchannel, "0", 1, 0);
			return -1;
		}
	
		sprintf(cmd, "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin tshark -r \"%s.pcap\" -R sip > \"%s.pcap2txt\" 2>/dev/null", filename, filename);
		system(cmd);
		sprintf(cmd, "echo ==== >> \"%s.pcap2txt\"", filename);
		system(cmd);
		sprintf(cmd, "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin tshark -r \"%s.pcap\" -V -R sip >> \"%s.pcap2txt\" 2>/dev/null", filename, filename);
		system(cmd);

		size = file_exists(tsharkfile);
		if(size) {
			fd = open(tsharkfile, O_RDONLY);
			if(fd < 0) {
				sprintf(buf, "error: cannot open file [%s]", filename);
				return -1;
			}
			while(nread = read(fd, rbuf, sizeof rbuf), nread > 0) {
				if ((res = sendvm(client, sshchannel, rbuf, nread, 0)) == -1){
					close(fd);
					return -1;
				}
			}
			if(eof) {
				if ((res = sendvm(client, sshchannel, "EOF", 3, 0)) == -1){
					close(fd);
					return -1;
				}
			}
			close(fd);
			return 0;
		}
		return 0;
	} else if(strstr(buf, "genhttppcap") != NULL) {
		char timestamp_from[100]; 
		char timestamp_to[100]; 
		char ids[10000];
		sscanf(buf, "genhttppcap %19[T0-9--: ] %19[T0-9--: ] %s", timestamp_from, timestamp_to, ids);
		/*
		cout << timestamp_from << endl
		     << timestamp_to << endl
		     << ids << endl;
		*/
		HttpPacketsDumper dumper;
		dumper.setTemplatePcapName();
		dumper.setUnlinkPcap();
		dumper.dumpData(timestamp_from, timestamp_to, ids);
		dumper.closePcapDumper();
		
		if(!dumper.getPcapName().empty() &&
		   file_exists(dumper.getPcapName()) > 0) {
			return(sendFile(dumper.getPcapName().c_str(), client, sshchannel, false));
		} else {
			sendvm(client, sshchannel, "null", 4, 0);
			return(0);
		}
	} else if(strstr(buf, "quit") != NULL) {
		return 0;
	} else if(strstr(buf, "terminating") != NULL) {
		vm_terminate();
	} else if(strstr(buf, "coutstr") != NULL) {
		char *pointToSpaceSeparator = strchr(buf, ' ');
		if(pointToSpaceSeparator) {
			cout << (pointToSpaceSeparator + 1) << flush;
		}
	} else if(strstr(buf, "syslogstr") != NULL) {
		char *pointToSpaceSeparator = strchr(buf, ' ');
		if(pointToSpaceSeparator) {
			syslog(LOG_NOTICE, "%s", pointToSpaceSeparator + 1);
		}
	} else if(strstr(buf, "custipcache_get_cust_id") != NULL) {
		char ip[20];
		sscanf(buf, "custipcache_get_cust_id %s", ip);
		CustIpCache *custIpCache = getCustIpCache();
		if(custIpCache) {
			unsigned int cust_id = custIpCache->getCustByIp(inet_addr(ip));
			snprintf(sendbuf, BUFSIZE, "cust_id: %u\n", cust_id);
			if((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1) {
				cerr << "Error sending data to client" << endl;
				return -1;
			}
		}
		return 0;
	} else if(strstr(buf, "custipcache_refresh") != NULL) {
		int rslt = refreshCustIpCache();
		snprintf(sendbuf, BUFSIZE, "rslt: %i\n", rslt);
		if((size = sendvm(client, sshchannel, sendbuf, strlen(sendbuf), 0)) == -1) {
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "custipcache_vect_print") != NULL) {
		CustIpCache *custIpCache = getCustIpCache();
		if(custIpCache) {
			string rslt = custIpCache->printVect();
			if((size = sendvm(client, sshchannel, rslt.c_str(), rslt.length(), 0)) == -1) {
				cerr << "Error sending data to client" << endl;
				return -1;
			}
		}
		return 0;
	} else if(strstr(buf, "restart") != NULL ||
		  strstr(buf, "upgrade") != NULL) {
		bool upgrade = false;
		string version;
		string url;
		string md5_32;
		string md5_64;
		string rsltForSend;
		if(strstr(buf, "upgrade") != NULL) {
			extern bool opt_upgrade_by_git;
			if(opt_upgrade_by_git) {
				rsltForSend = "upgrade from official binary source disabled - upgrade by git!";
			} else {
				upgrade = true;
				string command = buf;
				size_t pos = command.find("to: [");
				if(pos != string::npos) {
					size_t posEnd = command.find("]", pos);
					if(posEnd != string::npos) {
						version = command.substr(pos + 5, posEnd - pos - 5);
					}
				}
				if(pos != string::npos) {
					pos = command.find("url: [", pos);
					if(pos != string::npos) {
						size_t posEnd = command.find("]", pos);
						if(posEnd != string::npos) {
							url = command.substr(pos + 6, posEnd - pos - 6);
						}
					}
				}
				if(pos != string::npos) {
					pos = command.find("md5: [", pos);
					if(pos != string::npos) {
						size_t posEnd = command.find("]", pos);
						if(posEnd != string::npos) {
							md5_32 = command.substr(pos + 6, posEnd - pos - 6);
						}
						pos = command.find(" / [", pos);
						if(pos != string::npos) {
							size_t posEnd = command.find("]", pos);
							if(posEnd != string::npos) {
								md5_64 = command.substr(pos + 4, posEnd - pos - 4);
							}
						}
					}
				}
				if(!version.length()) {
					rsltForSend = "missing version in command line";
				} else if(!url.length()) {
					rsltForSend = "missing url in command line";
				} else if(!md5_32.length() || !md5_64.length()) {
					rsltForSend = "missing md5 in command line";
				}
			}
		}
		bool ok = false;
		RestartUpgrade restart(upgrade, version.c_str(), url.c_str(), md5_32.c_str(), md5_64.c_str());
		if(!rsltForSend.length()) {
			if(restart.createRestartScript()) {
				if((!upgrade || restart.runUpgrade()) &&
				   restart.checkReadyRestart() &&
				   restart.isOk()) {
					ok = true;
				}
			}
			rsltForSend = restart.getRsltString();
		}
		if ((size = sendvm(client, sshchannel, rsltForSend.c_str(), rsltForSend.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		if(ok) {
			restart.runRestart(client, manager_socket_server);
		}
		return 0;
	} else if(strstr(buf, "gitUpgrade") != NULL) {
		char cmd[100];
		sscanf(buf, "gitUpgrade %s", cmd);
		RestartUpgrade upgrade;
		bool rslt = upgrade.runGitUpgrade(cmd);
		string rsltString;
		if(rslt) {
			rsltString = "OK";
		} else {
			rsltString = upgrade.getErrorString();
		}
		rsltString.append("\n");
		if ((size = sendvm(client, sshchannel, rsltString.c_str(), rsltString.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "sniffer_stat") != NULL) {
		extern vm_atomic<string> storingCdrLastWriteAt;
		extern vm_atomic<string> pbStatString;
		extern vm_atomic<u_long> pbCountPacketDrop;
		extern bool opt_upgrade_by_git;
		ostringstream outStrStat;
		extern int vm_rrd_version;
		checkRrdVersion(true);
		while(__sync_lock_test_and_set(&usersniffer_sync, 1));
		size_t countLiveSniffers = usersniffer.size();
		__sync_lock_release(&usersniffer_sync);
		outStrStat << "{"
			   << "\"version\": \"" << RTPSENSOR_VERSION << "\","
			   << "\"rrd_version\": \"" << vm_rrd_version << "\","
			   << "\"storingCdrLastWriteAt\": \"" << storingCdrLastWriteAt << "\","
			   << "\"pbStatString\": \"" << pbStatString << "\","
			   << "\"pbCountPacketDrop\": \"" << pbCountPacketDrop << "\","
			   << "\"uptime\": \"" << getUptime() << "\","
			   << "\"count_live_sniffers\": \"" << countLiveSniffers << "\","
			   << "\"upgrade_by_git\": \"" << opt_upgrade_by_git << "\""
			   << "}";
		outStrStat << endl;
		string outStrStatStr = outStrStat.str();
		if ((size = sendvm(client, sshchannel, outStrStatStr.c_str(), outStrStatStr.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return 0;
	} else if(strstr(buf, "pcapstat") != NULL) {
		extern PcapQueue *pcapQueueStatInterface;
		string rslt;
		if(pcapQueueStatInterface) {
			rslt = pcapQueueStatInterface->pcapDropCountStat();
			if(!rslt.length()) {
				rslt = "ok";
			}
		} else {
			rslt = "no PcapQueue mode";
		}
		if ((size = sendvm(client, sshchannel, rslt.c_str(), rslt.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		return(0);
	} else if(strstr(buf, "login_screen_popup") != NULL) {
		*managerClientThread =  new FILE_LINE ManagerClientThread_screen_popup(client, buf);
	} else if(strstr(buf, "ac_add_thread") != NULL) {
		extern AsyncClose *asyncClose;
		asyncClose->addThread();
		if ((size = sendvm(client, sshchannel, "ok\n", 3, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "ac_remove_thread") != NULL) {
		extern AsyncClose *asyncClose;
		asyncClose->removeThread();
		if ((size = sendvm(client, sshchannel, "ok\n", 3, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
		
	} else if(strstr(buf, "enable_bad_packet_order_warning") != NULL) {
		enable_bad_packet_order_warning = 1;
		if ((size = sendvm(client, sshchannel, "ok\n", 3, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "sipports") != NULL) {
		ostringstream outStrSipPorts;
		extern char *sipportmatrix;
		for(int i = 0; i < 65537; i++) {
			if(sipportmatrix[i]) {
				outStrSipPorts << i << ',';
			}
		}
		outStrSipPorts << endl;
		string strSipPorts = outStrSipPorts.str();
		if ((size = sendvm(client, sshchannel, strSipPorts.c_str(), strSipPorts.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "sqlexport") != NULL ||
		  strstr(buf, "sqlvmexport") != NULL) {
		bool sqlFormat = strstr(buf, "sqlexport") != NULL;
		extern MySqlStore *sqlStore;
		string rslt = sqlStore->exportToFile(NULL, "auto", sqlFormat, strstr(buf, "clean") != NULL);
		if ((size = sendvm(client, sshchannel, rslt.c_str(), rslt.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "memory_stat") != NULL) {
		string rsltMemoryStat = getMemoryStat();
		if ((size = sendvm(client, sshchannel, rsltMemoryStat.c_str(), rsltMemoryStat.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(strstr(buf, "jemalloc_stat") != NULL) {
		string jeMallocStat(bool full);
		string rsltMemoryStat = jeMallocStat(strstr(buf, "full"));
		if ((size = sendvm(client, sshchannel, rsltMemoryStat.c_str(), rsltMemoryStat.length(), 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	} else if(buf[0] == 'b' and strstr(buf, "blocktar") != NULL) {
		opt_blocktarwrite = 1;
	} else if(buf[0] == 'u' and strstr(buf, "unblocktar") != NULL) {
		opt_blocktarwrite = 0;
	} else if(buf[0] == 'b' and strstr(buf, "blockasync") != NULL) {
		opt_blockasyncprocess = 1;
	} else if(buf[0] == 'u' and strstr(buf, "unblockasync") != NULL) {
		opt_blockasyncprocess = 0;
	} else if(buf[0] == 'b' and strstr(buf, "blockprocesspacket") != NULL) {
		opt_blockprocesspacket = 1;
	} else if(buf[0] == 'u' and strstr(buf, "unblockprocesspacket") != NULL) {
		opt_blockprocesspacket = 0;
	} else if(buf[0] == 'b' and strstr(buf, "blockqfile") != NULL) {
		opt_blockqfile = 1;
	} else if(buf[0] == 'u' and strstr(buf, "unblockqfile") != NULL) {
		opt_blockqfile = 0;
	} else if(strstr(buf, "malloc_trim") != NULL) {
		malloc_trim(0);
	} else if(strstr(buf, "memcrash_test_1") != NULL) {
		char *test = new char[10];
		test[10] = 1;
	} else {
		if ((size = sendvm(client, sshchannel, "command not found\n", 18, 0)) == -1){
			cerr << "Error sending data to client" << endl;
			return -1;
		}
	}
	return 1;
}


void *manager_client(void *dummy) {
	struct hostent* host;
	struct sockaddr_in addr;
	int res;
	int client = 0;
	char buf[BUFSIZE];
	char sendbuf[BUFSIZE];
	int size;
	

	while(1) {
		host = gethostbyname(opt_clientmanager);
		if (!host) { //Report lookup failure  
			syslog(LOG_ERR, "Cannot resolv: %s: host [%s] trying again...\n",  hstrerror(h_errno),  opt_clientmanager);  
			sleep(1);
			continue;  
		} 
		break;
	}
connect:
	client = socket(PF_INET, SOCK_STREAM, 0); /* create socket */
	memset(&addr, 0, sizeof(addr));    /* create & zero struct */
	addr.sin_family = AF_INET;    /* select internet protocol */
	addr.sin_port = htons(opt_clientmanagerport);         /* set the port # */
	addr.sin_addr.s_addr = *(long*)host->h_addr_list[0]; /* set the addr */
	syslog(LOG_NOTICE, "Connecting to manager server [%s]\n", inet_ntoa( *(struct in_addr *) host->h_addr_list[0]));
	while(1) {
		res = connect(client, (struct sockaddr *)&addr, sizeof(addr));         /* connect! */
		if(res == -1) {
			syslog(LOG_NOTICE, "Failed to connect to server [%s] error:[%s] trying again...\n", inet_ntoa( *(struct in_addr *) host->h_addr_list[0]), strerror(errno));
			sleep(1);
			continue;
		}
		break;
	}

	// send login
	snprintf(sendbuf, BUFSIZE, "login %s", mac);
	if ((size = send(client, sendbuf, strlen(sendbuf), 0)) == -1){
		perror("send()");
		sleep(1);
		goto connect;
	}

	// catch the reply
	size = recv(client, buf, BUFSIZE - 1, 0);
	buf[size] = '\0';

	while(1) {

		string buf_long;
		//cout << "New manager connect from: " << inet_ntoa((in_addr)clientInfo.sin_addr) << endl;
		size = recv(client, buf, BUFSIZE - 1, 0);
		if (size == -1 or size == 0) {
			//cerr << "Error in receiving data" << endl;
			perror("recv()");
			close(client);
			sleep(1);
			goto connect;
		}
		buf[size] = '\0';
//		if(verbosity > 0) syslog(LOG_NOTICE, "recv[%s]\n", buf);
		//res = parse_command(buf, size, client, 1, buf_long.c_str());
		res = parse_command(buf, size, client, 1, NULL);
	
#if 0	
		//cout << "New manager connect from: " << inet_ntoa((in_addr)clientInfo.sin_addr) << endl;
		size = recv(client, buf, BUFSIZE - 1, 0);
		if (size == -1 or size == 0) {
			//cerr << "Error in receiving data" << endl;
			perror("recv()");
			close(client);
			sleep(1);
			goto connect;
		} else {
			buf[size] = '\0';
			buf_long = buf;
			char buf_next[BUFSIZE];
			while((size = recv(client, buf_next, BUFSIZE - 1, 0)) > 0) {
				buf_next[size] = '\0';
				buf_long += buf_next;
			}
		}
		buf[size] = '\0';
		if(verbosity > 0) syslog(LOG_NOTICE, "recv[%s]\n", buf);
		res = parse_command(buf, size, client, 1, buf_long.c_str());
#endif
	}

	return 0;
}

void *manager_read_thread(void * arg) {

	char buf[BUFSIZE];
	string buf_long;
	int size;
	unsigned int    client;
	client = *(unsigned int *)arg;
	delete (unsigned int*)arg;

	//cout << "New manager connect from: " << inet_ntoa((in_addr)clientInfo.sin_addr) << endl;
	if ((size = recv(client, buf, BUFSIZE - 1, 0)) == -1) {
		cerr << "Error in receiving data" << endl;
		close(client);
		return 0;
	} else {
		buf[size] = '\0';
		buf_long = buf;
		////cout << "DATA: " << buf << endl;
		if(size == BUFSIZE - 1 && !strstr(buf, "\r\n\r\n")) {
			char buf_next[BUFSIZE];
			////cout << "NEXT_RECV start" << endl;
			while((size = recv(client, buf_next, BUFSIZE - 1, 0)) > 0) {
				buf_next[size] = '\0';
				buf_long += buf_next;
				////cout << "NEXT DATA: " << buf_next << endl;
				////cout << "NEXT_RECV read" << endl;
				if(buf_long.find("\r\n\r\n") != string::npos) {
					break;
				}
			}
			////cout << "NEXT_RECV stop" << endl;
			size_t posEnd;
			if((posEnd = buf_long.find("\r\n\r\n")) != string::npos) {
				buf_long.resize(posEnd);
			}
		}
	}
	ManagerClientThread *managerClientThread = NULL;
	parse_command(buf, size, client, 0, buf_long.c_str(), &managerClientThread);
	if(managerClientThread) {
		if(managerClientThread->parseCommand()) {
			ClientThreads.add(managerClientThread);
			managerClientThread->run();
		} else {
			delete managerClientThread;
			close(client);
		}
	} else {
		close(client);
	}

	return 0;
}

void perror_syslog(const char *msg) {
	char buf[1024];
	strerror_r(errno, buf, 1024);
	syslog(LOG_ERR, "%s:%s\n", msg, buf);
}

#ifdef HAVE_LIBSSH
void *manager_ssh_(void) {
	ssh_session session;
	int rc;
	// Open session and set options
	list<ssh_channel> ssh_chans;
	list<ssh_channel>::iterator it1;
	char buf[1024*1024]; 
	int len;
	session = ssh_new();
	if (session == NULL)
		exit(-1);
	ssh_options_set(session, SSH_OPTIONS_HOST, ssh_host);
	ssh_options_set(session, SSH_OPTIONS_PORT, &ssh_port);
	ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");
	ssh_options_set(session, SSH_OPTIONS_SSH_DIR, "/tmp");
	ssh_options_set(session, SSH_OPTIONS_USER, "root");
	// Connect to server
	rc = ssh_connect(session);
	if (rc != SSH_OK) {
		syslog(LOG_ERR, "Error connecting to %s: %s\n", ssh_host, ssh_get_error(session));
		ssh_free(session);
		return 0;
	}
/*
	// Verify the server's identity
	// For the source code of verify_knowhost(), check previous example
	if (verify_knownhost(session) < 0)
	{
		ssh_disconnect(session);
		ssh_free(session);
		exit(-1);
	}
*/
	// Authenticate ourselves
	rc = ssh_userauth_password(session, ssh_username, ssh_password);
	if (rc != SSH_AUTH_SUCCESS) {
		syslog(LOG_ERR, "Error authenticating with password: %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		goto ssh_disconnect;
	}
	syslog(LOG_NOTICE, "Connected to ssh\n");

	int remote_listenport;
	rc = ssh_forward_listen(session, ssh_remote_listenhost, ssh_remote_listenport, &remote_listenport);
	if (rc != SSH_OK) {
		syslog(LOG_ERR, "Error opening remote port: %s\n", ssh_get_error(session));
		goto ssh_disconnect;
	}
	syslog(LOG_NOTICE, "connection established\n");

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	/* set the thread detach state */
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	while(1) {
		ssh_channel channel;
		//int port;
		//channel = ssh_channel_accept_forward(session, 0, &port);
		channel = ssh_forward_accept(session, 0);
		usleep(10000);
		if (channel == NULL) {
			if(!ssh_is_connected(session)) {
				break;
			}
		} else {
			ssh_chans.push_back(channel);
		}
		for (it1 = ssh_chans.begin(); it1 != ssh_chans.end();) {
			ssh_channel channel = *it1;
			if(ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
				len = ssh_channel_read_nonblocking(channel, buf, sizeof(buf), 0);
				if(len == SSH_ERROR) {
					// read error 
					ssh_channel_free(channel);
					ssh_chans.erase(it1++);
					continue;
				}
				if (len <= 0) {
					++it1;
					continue;
				}
				buf[len] = '\0';
				parse_command(buf, len, 0, 0, NULL, NULL, channel);
				ssh_channel_send_eof(channel);
				ssh_channel_free(channel);
				ssh_chans.erase(it1++);
			} else {
				// channel is closed already, remove it
				ssh_channel_free(channel);
				ssh_chans.erase(it1++);
			}
		}
	}
ssh_disconnect:
	ssh_disconnect(session);
	ssh_free(session);
	return 0;
}
#endif

#ifdef HAVE_LIBSSH
void *manager_ssh(void *arg) {
	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();
//	ssh_set_log_level(SSH_LOG_WARNING | SSH_LOG_PROTOCOL | SSH_LOG_PACKET | SSH_LOG_FUNCTIONS);
	while(1 && terminating == 0) {
		syslog(LOG_NOTICE, "Starting reverse SSH connection service\n");
		manager_ssh_();
		syslog(LOG_NOTICE, "SSH service stopped.\n");
		sleep(1);
	}
	return 0;
}
#endif


void *manager_server(void *dummy) {
	sockaddr_in sockName;
	sockaddr_in clientInfo;
	socklen_t addrlen;

	// Vytvorime soket - viz minuly dil
	if ((manager_socket_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		cerr << "Cannot create manager tcp socket" << endl;
		return 0;
	}
	sockName.sin_family = AF_INET;
	sockName.sin_port = htons(opt_manager_port);
	//sockName.sin_addr.s_addr = INADDR_ANY;
	sockName.sin_addr.s_addr = inet_addr(opt_manager_ip);
	int on = 1;
	setsockopt(manager_socket_server, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if(opt_manager_nonblock_mode) {
		int flags = fcntl(manager_socket_server, F_GETFL, 0);
		if(flags >= 0) {
			fcntl(manager_socket_server, F_SETFL, flags | O_NONBLOCK);
		}
	}
tryagain:
	if (bind(manager_socket_server, (sockaddr *)&sockName, sizeof(sockName)) == -1) {
		syslog(LOG_ERR, "Cannot bind to port [%d] trying again after 5 seconds intervals\n", opt_manager_port);
		sleep(5);
		goto tryagain;
	}
	// create queue with 100 connections max 
	if (listen(manager_socket_server, 100) == -1) {
		cerr << "Cannot create manager queue" << endl;
		return 0;
	}
	pthread_t threads;
	pthread_attr_t attr;
	fd_set rfds;
	struct timeval tv;
	while(terminating == 0) {
		FD_ZERO(&rfds);
		FD_SET(manager_socket_server, &rfds);
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		if(!opt_manager_nonblock_mode ||
		   select(manager_socket_server + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
			addrlen = sizeof(clientInfo);
			int client = accept(manager_socket_server, (sockaddr*)&clientInfo, &addrlen);
			if(terminating == 1) {
				close(client);
				close(manager_socket_server);
				return 0;
			}
			if (client == -1) {
				//cerr << "Problem with accept client" <<endl;
				close(client);
				continue;
			}

			pthread_attr_init(&attr);
			unsigned int *_ids = new FILE_LINE unsigned int;
			*_ids = client;
			int rslt = pthread_create (		/* Create a child thread        */
				       &threads,		/* Thread ID (system assigned)  */    
				       &attr,			/* Default thread attributes    */
				       manager_read_thread,	/* Thread routine               */
				       _ids);			/* Arguments to be passed       */
			pthread_detach(threads);
			pthread_attr_destroy(&attr);
			if(rslt != 0) {
				syslog(LOG_ERR, "manager pthread_create failed with rslt code %i", rslt);
			}
		}
	}
	close(manager_socket_server);
	return 0;
}

void livesnifferfilter_s::updateState() {
	state_s new_state; 
	new_state.all_saddr = true;
	new_state.all_daddr = true;
	new_state.all_bothaddr = true;
	new_state.all_srcnum = true;
	new_state.all_dstnum = true;
	new_state.all_bothnum = true;
	new_state.all_siptypes = true;
	for(int i = 0; i < MAXLIVEFILTERS; i++) {
		if(this->lv_saddr[i]) {
			new_state.all_saddr = false;
		}
		if(this->lv_daddr[i]) {
			new_state.all_daddr = false;
		}
		if(this->lv_bothaddr[i]) {
			new_state.all_bothaddr = false;
		}
		if(this->lv_srcnum[i][0]) {
			new_state.all_srcnum = false;
		}
		if(this->lv_dstnum[i][0]) {
			new_state.all_dstnum = false;
		}
		if(this->lv_bothnum[i][0]) {
			new_state.all_bothnum = false;
		}
		if(this->lv_siptypes[i]) {
			new_state.all_siptypes = false;
		}
	}
	new_state.all_addr = new_state.all_saddr && new_state.all_daddr && new_state.all_bothaddr;
	new_state.all_num = new_state.all_srcnum && new_state.all_dstnum && new_state.all_bothnum;
	new_state.all_all = new_state.all_addr && new_state.all_num && new_state.all_siptypes;
	this->state = new_state;
}

string livesnifferfilter_s::getStringState() {
	ostringstream outStr;
	outStr << "sip type: ";
	if(this->state.all_siptypes) {
		outStr << "all";
	} else {
		int counter = 0;
		for(int i = 0; i < MAXLIVEFILTERS; i++) {
			if(this->lv_siptypes[i]) {
				if(counter) {
					outStr << ",";
				}
				outStr << (this->lv_siptypes[i] == INVITE ? 'I' :
					   this->lv_siptypes[i] == REGISTER ? 'R' :
					   this->lv_siptypes[i] == OPTIONS ? 'O' :
					   this->lv_siptypes[i] == SUBSCRIBE ? 'S' :
					   this->lv_siptypes[i] == MESSAGE ? 'M' :
					   this->lv_siptypes[i] == NOTIFY ? 'N' : '-');
				++counter;
			}
		}
	}
	outStr << " ;   ";
	for(int pass = 1; pass <= 3; pass++) {
		if(!(pass == 1 ? this->state.all_saddr :
		     pass == 2 ? this->state.all_daddr :
				 this->state.all_bothaddr)) {
			unsigned int *addr = pass == 1 ? this->lv_saddr :
					     pass == 2 ? this->lv_daddr :
							 this->lv_bothaddr;
			int counter = 0;
			for(int i = 0; i < MAXLIVEFILTERS; i++) {
				if(addr[i]) {
					if(counter) {
						outStr << ", ";
					} else {
						outStr << (pass == 1 ? "source address" :
							   pass == 2 ? "dest. address" :
							   pass == 3 ? "address" : 
								       "")
						       << ": ";
					}
					outStr << inet_ntostring(addr[i]);
					++counter;
				}
			}
			if(counter) {
				outStr << " ;   ";
			}
		}
	}
	for(int pass = 1; pass <= 3; pass++) {
		if(!(pass == 1 ? this->state.all_srcnum :
		     pass == 2 ? this->state.all_dstnum :
				 this->state.all_bothnum)) {
			char (*num)[MAXLIVEFILTERSCHARS] = pass == 1 ? this->lv_srcnum :
							   pass == 2 ? this->lv_dstnum :
								       this->lv_bothnum;
			int counter = 0;
			for(int i = 0; i < MAXLIVEFILTERS; i++) {
				if(num[i][0]) {
					if(counter) {
						outStr << ", ";
					} else {
						outStr << (pass == 1 ? "source number" :
							   pass == 2 ? "dest. number" :
							   pass == 3 ? "number" : 
								       "")
						       << ": ";
					}
					outStr << num[i];
					++counter;
				}
			}
			if(counter) {
				outStr << " ;   ";
			}
		}
	}
	return(outStr.str());
}

void updateLivesnifferfilters() {
	livesnifferfilter_use_siptypes_s new_livesnifferfilterUseSipTypes;
	memset(&new_livesnifferfilterUseSipTypes, 0, sizeof(new_livesnifferfilterUseSipTypes));
	if(usersniffer.size()) {
		global_livesniffer = 1;
		map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT;
		for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); ++usersnifferIT) {
			usersnifferIT->second->updateState();
			if(usersnifferIT->second->state.all_siptypes) {
				new_livesnifferfilterUseSipTypes.u_invite = true;
				new_livesnifferfilterUseSipTypes.u_register = true;
				new_livesnifferfilterUseSipTypes.u_options = true;
				new_livesnifferfilterUseSipTypes.u_subscribe = true;
				new_livesnifferfilterUseSipTypes.u_message = true;
				new_livesnifferfilterUseSipTypes.u_notify = true;
			} else {
				for(int i = 0; i < MAXLIVEFILTERS; i++) {
					if(usersnifferIT->second->lv_siptypes[i]) {
						switch(usersnifferIT->second->lv_siptypes[i]) {
						case INVITE:
							new_livesnifferfilterUseSipTypes.u_invite = true;
							break;
						case REGISTER:
							new_livesnifferfilterUseSipTypes.u_register = true;
							break;
						case OPTIONS:
							new_livesnifferfilterUseSipTypes.u_options = true;
							break;
						case SUBSCRIBE:
							new_livesnifferfilterUseSipTypes.u_subscribe = true;
							break;
						case MESSAGE:
							new_livesnifferfilterUseSipTypes.u_message = true;
							break;
						case NOTIFY:
							new_livesnifferfilterUseSipTypes.u_notify = true;
							break;
						}
					}
				}
			}
		}
	} else {
		global_livesniffer = 0;
	}
	livesnifferfilterUseSipTypes = new_livesnifferfilterUseSipTypes;
	/*
	cout << "livesnifferfilterUseSipTypes" << endl;
	if(livesnifferfilterUseSipTypes.u_invite) cout << "INVITE" << endl;
	if(livesnifferfilterUseSipTypes.u_register) cout << "REGISTER" << endl;
	if(livesnifferfilterUseSipTypes.u_options) cout << "OPTIONS" << endl;
	if(livesnifferfilterUseSipTypes.u_subscribe) cout << "SUBSCRIBE" << endl;
	if(livesnifferfilterUseSipTypes.u_message) cout << "MESSAGE" << endl;
	if(livesnifferfilterUseSipTypes.u_notify) cout << "NOTIFY" << endl;
	*/
}

bool cmpCallBy_destroy_call_at(Call* a, Call* b) {
	return(a->destroy_call_at < b->destroy_call_at);   
}
bool cmpCallBy_first_packet_time(Call* a, Call* b) {
	return(a->first_packet_time < b->first_packet_time);   
}


ManagerClientThread::ManagerClientThread(int client, const char *type, const char *command, int commandLength) {
	this->client = client;
	this->type = type;
	if(commandLength) {
		this->command = string(command, commandLength);
	} else {
		this->command = command;
	}
	this->finished = false;
	this->_sync_responses = 0;
}

void ManagerClientThread::run() {
	unsigned int counter = 0;
	bool disconnect = false;
	int flag = 0;
	setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	int flushBuffLength = 1000;
	char *flushBuff = new FILE_LINE char[flushBuffLength];
	memset(flushBuff, '_', flushBuffLength - 1);
	flushBuff[flushBuffLength - 1] = '\n';
	while(true && !terminating && !disconnect) {
		string rsltString;
		this->lock_responses();
		if(this->responses.size()) {
			rsltString = this->responses.front();
			this->responses.pop();
		}
		this->unlock_responses();
		if(!rsltString.empty()) {
			if(send(client, rsltString.c_str(), rsltString.length(), 0) == -1) {
				disconnect = true;
			} else {
				send(client, flushBuff, flushBuffLength, 0);
			}
		}
		++counter;
		if((counter % 5) == 0 && !disconnect) {
			if(send(client, "ping\n", 5, 0) == -1) {
				disconnect = true;
			}
		}
		usleep(100000);
	}
	close(client);
	finished = true;
	delete [] flushBuff;
}

ManagerClientThread_screen_popup::ManagerClientThread_screen_popup(int client, const char *command, int commandLength) 
 : ManagerClientThread(client, "screen_popup", command, commandLength) {
	auto_popup = false;
	non_numeric_caller_id = false;
}

bool ManagerClientThread_screen_popup::parseCommand() {
	ClientThreads.cleanup();
	return(this->parseUserPassword());
}

void ManagerClientThread_screen_popup::onCall(int sipResponseNum, const char *callerName, const char *callerNum, const char *calledNum,
					      unsigned int sipSaddr, unsigned int sipDaddr) {
	/*
	cout << "** call 01" << endl;
	cout << "** - called num : " << calledNum << endl;
	struct in_addr _in;
	_in.s_addr = sipSaddr;
	cout << "** - src ip : " << inet_ntoa(_in) << endl;
	cout << "** - reg_match : " << reg_match(calledNum, this->dest_number.empty() ? this->username.c_str() : this->dest_number.c_str(), __FILE__, __LINE__) << endl;
	cout << "** - check ip : " << this->src_ip.checkIP(htonl(sipSaddr)) << endl;
	*/
	if(!(reg_match(calledNum, this->dest_number.empty() ? this->username.c_str() : this->dest_number.c_str(), __FILE__, __LINE__) &&
	     (this->non_numeric_caller_id ||
	      this->isNumericId(calledNum)) &&
	     this->src_ip.checkIP(htonl(sipSaddr)))) {
		return;
	}
	if(this->regex_check_calling_number.size()) {
		bool callerNumOk = false;
		for(size_t i = 0; i < this->regex_check_calling_number.size(); i++) {
			if(reg_match(callerNum, this->regex_check_calling_number[i].c_str(), __FILE__, __LINE__)) {
				callerNumOk = true;
				break;
			}
		}
		if(!callerNumOk) {
			return;
		}
	}
	char rsltString[4096];
	char sipSaddrIP[18];
	char sipDaddrIP[18];
	struct in_addr in;
	in.s_addr = sipSaddr;
	strcpy(sipSaddrIP, inet_ntoa(in));
	in.s_addr = sipDaddr;
	strcpy(sipDaddrIP, inet_ntoa(in));
	string callerNumStr = callerNum;
	for(size_t i = 0; i < this->regex_replace_calling_number.size(); i++) {
		string temp = reg_replace(callerNumStr.c_str(), 
					  this->regex_replace_calling_number[i].pattern.c_str(), 
					  this->regex_replace_calling_number[i].replace.c_str(),
					  __FILE__, __LINE__);
		if(!temp.empty()) {
			callerNumStr = temp;
		}
	}
	sprintf(rsltString,
		"call_data: "
		"sipresponse:[[%i]] "
		"callername:[[%s]] "
		"caller:[[%s]] "
		"called:[[%s]] "
		"sipcallerip:[[%s]] "
		"sipcalledip:[[%s]]\n",
		sipResponseNum,
		callerName,
		callerNumStr.c_str(),
		calledNum,
		sipSaddrIP,
		sipDaddrIP);
	this->lock_responses();
	this->responses.push(rsltString);
	this->unlock_responses();
}

bool ManagerClientThread_screen_popup::parseUserPassword() {
	char user[128];
	char password[128];
	char key[128];
	sscanf(command.c_str(), "login_screen_popup %s %s %s", user, password, key);
	string password_md5 = GetStringMD5(password);
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query(
		string(
		"select u.username,\
			u.name,\
			u.dest_number,\
			u.allow_change_settings,\
			p.name as profile_name,\
			p.auto_popup,\
			p.show_ip,\
			p.popup_on,\
			p.non_numeric_caller_id,\
			p.regex_calling_number,\
			p.src_ip_whitelist,\
			p.src_ip_blacklist,\
			p.app_launch,\
			p.app_launch_args_or_url,\
			p.popup_title\
		 from screen_popup_users u\
		 join screen_popup_profile p on (p.id=u.profile_id)\
		 where username=") +
		sqlEscapeStringBorder(user) +
		" and password=" + 
		sqlEscapeStringBorder(password_md5));
	SqlDb_row row = sqlDb->fetchRow();
	char rsltString[4096];
	bool rslt;
	if(row) {
		rslt = true;
		username = row["username"];
		name = row["name"];
		dest_number = row["dest_number"];
		allow_change_settings = atoi(row["allow_change_settings"].c_str());
		profile_name = row["profile_name"];
		auto_popup = atoi(row["auto_popup"].c_str());
		show_ip = atoi(row["show_ip"].c_str());
		popup_on = row["popup_on"];
		non_numeric_caller_id = atoi(row["non_numeric_caller_id"].c_str());
		if(!row["regex_calling_number"].empty()) {
			vector<string> items = split(row["regex_calling_number"].c_str(), split("\r|\n", "|"), true);
			for(size_t i = 0; i < items.size(); i++) {
				vector<string> itemItems = split(items[i].c_str(), "|", true);
				if(itemItems.size() == 2) {
					this->regex_replace_calling_number.push_back(RegexReplace(itemItems[0].c_str(), itemItems[1].c_str()));
				} else {
					this->regex_check_calling_number.push_back(itemItems[0]);
				}
			}
		}
		src_ip.addWhite(row["src_ip_whitelist"].c_str());
		src_ip.addBlack(row["src_ip_blacklist"].c_str());
		app_launch = row["app_launch"];
		app_launch_args_or_url = row["app_launch_args_or_url"];
		popup_title = row["popup_title"];
		if(!opt_php_path[0]) {
			rslt = false;
			strcpy(rsltString, "login_failed error:[[Please set php_path parameter in voipmonitor.conf.]]\n");
		} else {
			string cmd = string("php ") + opt_php_path + "/php/run.php checkScreenPopupLicense -k " + key;
			FILE *fp = popen(cmd.c_str(), "r");
			if(fp == NULL) {
				rslt = false;
				strcpy(rsltString, "login_failed error:[[Failed to run php checkScreenPopupLicense.]]\n");
			} else {
				char rsltFromPhp[1024];
				if(!fgets(rsltFromPhp, sizeof(rsltFromPhp) - 1, fp)) {
					rslt = false;
					strcpy(rsltString, "login_failed error:[[License check failed please contact support.]]\n");
				} else if(!strncmp(rsltFromPhp, "error: ", 7)) {
					rslt = false;
					strcpy(rsltString, (string("login_failed error:[[") + (rsltFromPhp + 7) + "]]\n").c_str());
				} else {
					char key[1024];
					int maxClients;
					if(sscanf(rsltFromPhp, "key: %s max_clients: %i", key, &maxClients) == 2) {
						if(maxClients && ClientThreads.getCount() >= maxClients) {
							rslt = false;
							strcpy(rsltString, "login_failed error:[[Maximum connection limit reached.]]\n");
						} else {
							sprintf(rsltString, 
								"login_ok "
								"auto_popup:[[%i]] "
								"popup_on_200:[[%i]] "
								"popup_on_18:[[%i]] "
								"show_ip:[[%i]] "
								"app_launch:[[%s]] "
								"args_or_url:[[%s]] "
								"key:[[%s]] "
								"allow_change_settings:[[%i]] "
								"popup_title:[[%s]]\n", 
								auto_popup, 
								popup_on == "200" || popup_on == "183/180_200",
								popup_on == "183/180" || popup_on == "183/180_200",
								show_ip, 
								app_launch.c_str(), 
								app_launch_args_or_url.c_str(), 
								key, 
								allow_change_settings,
								popup_title.c_str());
						}
					} else {
						rslt = false;
							strcpy(rsltString, "login_failed error:[[License is invalid.]]\n");
					}
				}
				pclose(fp);
			}
		}
	} else {
		rslt = false;
		strcpy(rsltString, "login_failed error:[[Invalid user or password.]]\n");
	}
	delete sqlDb;
	send(client, rsltString, strlen(rsltString), 0);
	return(rslt);
}

bool ManagerClientThread_screen_popup::isNumericId(const char *id) {
	while(*id) {
		if(!isdigit(*id) &&
		   *id != ' ' &&
		   *id != '+') {
			return(false);
		}
		++id;
	}
	return(true);
}

ManagerClientThreads::ManagerClientThreads() {
	_sync_client_threads = 0;
}
	
void ManagerClientThreads::add(ManagerClientThread *clientThread) {
	this->lock_client_threads();
	clientThreads.push_back(clientThread);
	this->unlock_client_threads();
	this->cleanup();
}

void ManagerClientThreads::onCall(int sipResponseNum, const char *callerName, const char *callerNum, const char *calledNum,
				  unsigned int sipSaddr, unsigned int sipDaddr) {
	this->lock_client_threads();
	vector<ManagerClientThread*>::iterator iter;
	for(iter = this->clientThreads.begin(); iter != this->clientThreads.end(); ++iter) {
		(*iter)->onCall(sipResponseNum, callerName, callerNum, calledNum, sipSaddr, sipDaddr);
	}
	this->unlock_client_threads();
}

void ManagerClientThreads::cleanup() {
	this->lock_client_threads();
	for(int i = this->clientThreads.size() - 1; i >=0; i--) {
		ManagerClientThread *ct = this->clientThreads[i];
		if(ct->isFinished()) {
			delete ct;
			this->clientThreads.erase(this->clientThreads.begin() + i);
			
		}
	}
	this->unlock_client_threads();
}

int ManagerClientThreads::getCount() {
	this->lock_client_threads();
	int count = this->clientThreads.size();
	this->unlock_client_threads();
	return(count);
}

int sendFile(const char *fileName, int client, ssh_channel sshchannel, bool zip) {
	int fd = open(fileName, O_RDONLY);
	if(fd < 0) {
		char buf[1000];
		sprintf(buf, "error: cannot open file [%s]", fileName);
		if(sendvm(client, sshchannel, buf, strlen(buf), 0) == -1){
			cerr << "Error sending data to client" << endl;
		}
		return -1;
	}
	CompressStream *compressStream = NULL;
	if(zip) {
		compressStream = new FILE_LINE CompressStream(CompressStream::gzip, 1024, 0);
		compressStream->setSendParameters(client, sshchannel);
	}
	ssize_t nread;
	size_t read_size = 0;
	char rbuf[4096];
	while(nread = read(fd, rbuf, sizeof rbuf), nread > 0) {
		if(!read_size && compressStream &&
		   (unsigned char)rbuf[0] == 0x1f &&
		   (nread == 1 || (unsigned char)rbuf[1] == 0x8b)) {
			delete compressStream;
			compressStream = NULL;
		}
		read_size += nread;
		if(compressStream) {
			compressStream->compress(rbuf, nread, false, compressStream);
			if(compressStream->isError()) {
				close(fd);
				return -1;
			}
		} else {
			if(sendvm(client, sshchannel, rbuf, nread, 0) == -1){
				close(fd);
				return -1;
			}
		}
	}
	if(compressStream) {
		compressStream->compress(rbuf, 0, true, compressStream);
		delete compressStream;
	}
	close(fd);
	
	return(0);
}
