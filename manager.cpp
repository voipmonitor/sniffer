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
#include <math.h>
#include <time.h>

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
#include "country_detect.h"
#include "fraud.h"
#include "billing.h"
#include "rrd.h"
#include "tar.h"
#include "http.h"
#include "send_call_info.h"
#include "config_param.h"
#include "sniff_proc_class.h"
#include "register.h"
#include "options.h"
#include "server.h"
#include "filter_mysql.h"

#ifndef FREEBSD
#include <malloc.h>
#endif

//#define BUFSIZE 1024
//define BUFSIZE 20480
#define BUFSIZE 4096		//block size?

extern Calltable *calltable;
extern int terminating;
extern int opt_manager_port;
extern char opt_manager_ip[32];
extern int opt_manager_nonblock_mode;
extern volatile int calls_counter;
extern volatile int registers_counter;
extern char mac[32];
extern int verbosity;
extern char opt_php_path[1024];
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
extern bool opt_socket_use_poll;

extern cConfig CONFIG;
extern bool useNewCONFIG;
extern volatile bool cloud_activecheck_sshclose;

int opt_blocktarwrite = 0;
int opt_blockasyncprocess = 0;
int opt_blockprocesspacket = 0;
int opt_blockcleanupcalls = 0;
int opt_sleepprocesspacket = 0;
int opt_blockqfile = 0;
int opt_block_alloc_stack = 0;

using namespace std;

int sendvm(int socket, ssh_channel channel, cClient *c_client, const char *buf, size_t len, int /*mode*/);

std::map<string, int> MgmtCmdsRegTable;
std::map<string, string> MgmtHelpTable;

int Mgmt_params::registerCommand(const char *str, const char *help) {
	string h(help, strlen(help));
	string s(str, strlen(str));
	MgmtCmdsRegTable[s] = index;
	MgmtHelpTable[s] = h;
	return(0);
}

int Mgmt_params::registerCommand(commandAndHelp *cmdHelp) {
	while (cmdHelp->command) {
		registerCommand(cmdHelp->command, cmdHelp->help);
		cmdHelp++;
	}
	return(0);
}

int Mgmt_params::sendString(const char *str) {
	string tstr = str;
	return(sendString(&tstr));
}

int Mgmt_params::sendString(const char *str, ssize_t size) {
	if(sendvm(client, sshchannel, c_client, str, size, 0) == -1){
		cerr << "Error sending data to client" << endl;
		return -1;
	}
	return(0);
}

int Mgmt_params::sendString(ostringstream *str) {
	string tstr = str->str();
	return(sendString(&tstr));
}

int Mgmt_params::sendString(int value) {
	std::stringstream s;
	s << value;
	string tstr = s.str();
	return(sendString(&tstr));
}

int Mgmt_params::sendString(string *str) {
	if(str->empty()) {
		return(0);
	}
	CompressStream *compressStream = NULL;
	if(zip &&
	   ((*str)[0] != 0x1f || (str->length() > 1 && (unsigned char)(*str)[1] != 0x8b))) {
		compressStream = new FILE_LINE(13021) CompressStream(CompressStream::gzip, 1024, 0);
		compressStream->setSendParameters(client, sshchannel, c_client);
	}
	unsigned chunkLength = 4096;
	unsigned processedLength = 0;
	while(processedLength < str->length()) {
		unsigned processLength = MIN(chunkLength, str->length() - processedLength);
		if(compressStream) {
			compressStream->compress((char*)str->c_str() + processedLength, processLength, false, compressStream);
			if(compressStream->isError()) {
				cerr << "Error compress stream" << endl;
			return -1;
			}
		} else {
			if(sendvm(client, sshchannel, c_client, (char*)str->c_str() + processedLength, processLength, 0) == -1){
				cerr << "Error sending data to client" << endl;
				return -1;
			}
		}
		processedLength += processLength;
	}
	if(compressStream) {
		compressStream->compress(NULL, 0, true, compressStream);
		delete compressStream;
	}
	return(0);
}

int Mgmt_params::sendFile(const char *fileName) {
	int fd = open(fileName, O_RDONLY);
	if(fd < 0) {
		string str = "error: cannot open file " + string(fileName);
		sendString(&str);
		return -1;
	}
	RecompressStream *recompressStream = new FILE_LINE(0) RecompressStream(RecompressStream::compress_na, zip ? RecompressStream::gzip : RecompressStream::compress_na);
	recompressStream->setSendParameters(client, sshchannel, c_client);
	ssize_t nread;
	size_t read_size = 0;
	char rbuf[4096];
	while(nread = read(fd, rbuf, sizeof(rbuf)), nread > 0) {
		if(!read_size) {
			if(nread >= 2 &&
			   (unsigned char)rbuf[0] == 0x1f &&
			   (unsigned char)rbuf[1] == 0x8b) {
				if(zip) {
					recompressStream->setTypeCompress(RecompressStream::compress_na);
					recompressStream->setTypeDecompress(RecompressStream::compress_na);
				}
			} else if(nread >= 3 &&
				  rbuf[0] == 'L' && rbuf[1] == 'Z' && rbuf[2] == 'O') {
				recompressStream->setTypeDecompress(RecompressStream::lzo, true);
			}
		}
		read_size += nread;
		recompressStream->processData(rbuf, nread);
		if(recompressStream->isError()) {
			close(fd);
			return -1;
		}
	}
	close(fd);
	delete recompressStream;
	return(0);
}


Mgmt_params::Mgmt_params(char *ibuf, int isize, int iclient, ssh_channel isshchannel, cClient *ic_client, ManagerClientThread **imanagerClientThread) {
	buf = ibuf;
	size = isize;
	client = iclient;
	sshchannel = isshchannel;
	c_client = ic_client;
	managerClientThread = imanagerClientThread;
	index = 0;
	zip = false;
	task = mgmt_task_na;
}

int Mgmt_help(Mgmt_params *params);
int Mgmt_getversion(Mgmt_params *params);
int Mgmt_listcalls(Mgmt_params *params);
int Mgmt_reindexfiles(Mgmt_params *params);
int Mgmt_offon(Mgmt_params *params);
int Mgmt_check_filesindex(Mgmt_params *params);
int Mgmt_reindexspool(Mgmt_params *params);
int Mgmt_printspool(Mgmt_params *params);
int Mgmt_totalcalls(Mgmt_params *params);
int Mgmt_totalregisters(Mgmt_params *params);
int Mgmt_creategraph(Mgmt_params *params);
int Mgmt_is_register_new(Mgmt_params *params);
int Mgmt_listregisters(Mgmt_params *params);
int Mgmt_list_sip_msg(Mgmt_params *params);
int Mgmt_list_history_sip_msg(Mgmt_params *params);
int Mgmt_cleanupregisters(Mgmt_params *params);
int Mgmt_d_close_call(Mgmt_params *params);
int Mgmt_d_pointer_to_call(Mgmt_params *params);
int Mgmt_d_lc_all(Mgmt_params *params);
int Mgmt_d_lc_bye(Mgmt_params *params);
int Mgmt_d_lc_for_destroy(Mgmt_params *params);
int Mgmt_destroy_close_calls(Mgmt_params *params);
int Mgmt_cleanup_tcpreassembly(Mgmt_params *params);
int Mgmt_expire_registers(Mgmt_params *params);
int Mgmt_cleanup_registers(Mgmt_params *params);
int Mgmt_cleanup_calls(Mgmt_params *params);
int Mgmt_getipaccount(Mgmt_params *params);
int Mgmt_ipaccountfilter(Mgmt_params *params);
int Mgmt_stopipaccount(Mgmt_params *params);
int Mgmt_fetchipaccount(Mgmt_params *params);
int Mgmt_livefilter(Mgmt_params *params);
int Mgmt_startlivesniffer(Mgmt_params *params);
int Mgmt_getlivesniffer(Mgmt_params *params);
int Mgmt_stoplivesniffer(Mgmt_params *params);
int Mgmt_getactivesniffers(Mgmt_params *params);
int Mgmt_readaudio(Mgmt_params *params);
int Mgmt_listen(Mgmt_params *params);
int Mgmt_listen_stop(Mgmt_params *params);
int Mgmt_options_qualify_refresh(Mgmt_params *params);
int Mgmt_send_call_info_refresh(Mgmt_params *params);
int Mgmt_fraud_refresh(Mgmt_params *params);
int Mgmt_set_json_config(Mgmt_params *params);
int Mgmt_get_json_config(Mgmt_params *params);
int Mgmt_hot_restart(Mgmt_params *params);
int Mgmt_crules_print(Mgmt_params *params);
int Mgmt_reload(Mgmt_params *params);
int Mgmt_custom_headers_refresh(Mgmt_params *params);
int Mgmt_no_hash_message_rules_refresh(Mgmt_params *params);
int Mgmt_billing_refresh(Mgmt_params *params);
int Mgmt_country_detect_refresh(Mgmt_params *params);
int Mgmt_flush_tar(Mgmt_params *params);
int Mgmt_fileexists(Mgmt_params *params);
int Mgmt_file_exists(Mgmt_params *params);
int Mgmt_getfile(Mgmt_params *params);
int Mgmt_getfile_in_tar(Mgmt_params *params);
int Mgmt_getfile_in_tar_check_complete(Mgmt_params *params);
int Mgmt_getfile_is_zip_support(Mgmt_params *params);
int Mgmt_getwav(Mgmt_params *params);
int Mgmt_genwav(Mgmt_params *params);
int Mgmt_genhttppcap(Mgmt_params *params);
int Mgmt_getsiptshark(Mgmt_params *params);
int Mgmt_upgrade_restart(Mgmt_params *params);
int Mgmt_custipcache_vect_print(Mgmt_params *params);
int Mgmt_custipcache_refresh(Mgmt_params *params);
int Mgmt_custipcache_get_cust_id(Mgmt_params *params);
int Mgmt_syslogstr(Mgmt_params *params);
int Mgmt_coutstr(Mgmt_params *params);
int Mgmt_terminating(Mgmt_params *params);
int Mgmt_quit(Mgmt_params *params);
int Mgmt_pcapstat(Mgmt_params *params);
int Mgmt_sniffer_threads(Mgmt_params *params);
int Mgmt_sniffer_stat(Mgmt_params *params);
int Mgmt_gitUpgrade(Mgmt_params *params);
int Mgmt_login_screen_popup(Mgmt_params *params);
int Mgmt_ac_add_thread(Mgmt_params *params);
int Mgmt_ac_remove_thread(Mgmt_params *params);
int Mgmt_t2sip_add_thread(Mgmt_params *params);
int Mgmt_t2sip_remove_thread(Mgmt_params *params);
int Mgmt_rtpread_add_thread(Mgmt_params *params);
int Mgmt_rtpread_remove_thread(Mgmt_params *params);
int Mgmt_enable_bad_packet_order_warning(Mgmt_params *params);
int Mgmt_sipports(Mgmt_params *params);
int Mgmt_skinnyports(Mgmt_params *params);
int Mgmt_ignore_rtcp_jitter(Mgmt_params *params);
int Mgmt_convertchars(Mgmt_params *params);
int Mgmt_natalias(Mgmt_params *params);
int Mgmt_cloud_activecheck(Mgmt_params *params);
int Mgmt_jemalloc_stat(Mgmt_params *params);
int Mgmt_list_active_clients(Mgmt_params *params);
int Mgmt_memory_stat(Mgmt_params *params);
int Mgmt_sqlexport(Mgmt_params *params);
int Mgmt_sql_time_information(Mgmt_params *params);
int Mgmt_pausecall(Mgmt_params *params);
int Mgmt_unpausecall(Mgmt_params *params);
int Mgmt_setverbparam(Mgmt_params *params);
int Mgmt_set_pcap_stat_period(Mgmt_params *params);
int Mgmt_memcrash_test(Mgmt_params *params);
int Mgmt_malloc_trim(Mgmt_params *params);


int (* MgmtFuncArray[])(Mgmt_params *params) = {
	Mgmt_help,
	Mgmt_getversion,
	Mgmt_listcalls,
	Mgmt_reindexfiles,
	Mgmt_offon,
	Mgmt_check_filesindex,
	Mgmt_reindexspool,
	Mgmt_printspool,
	Mgmt_totalcalls,
	Mgmt_totalregisters,
	Mgmt_creategraph,
	Mgmt_is_register_new,
	Mgmt_listregisters,
	Mgmt_list_sip_msg,
	Mgmt_list_history_sip_msg,
	Mgmt_cleanupregisters,
	Mgmt_d_close_call,
	Mgmt_d_pointer_to_call,
	Mgmt_d_lc_all,
	Mgmt_d_lc_bye,
	Mgmt_d_lc_for_destroy,
	Mgmt_destroy_close_calls,
	Mgmt_cleanup_tcpreassembly,
	Mgmt_expire_registers,
	Mgmt_cleanup_registers,
	Mgmt_cleanup_calls,
	Mgmt_getipaccount,
	Mgmt_ipaccountfilter,
	Mgmt_stopipaccount,
	Mgmt_fetchipaccount,
	Mgmt_livefilter,
	Mgmt_startlivesniffer,
	Mgmt_getlivesniffer,
	Mgmt_stoplivesniffer,
	Mgmt_getactivesniffers,
	Mgmt_readaudio,
	Mgmt_listen,
	Mgmt_listen_stop,
	Mgmt_options_qualify_refresh,
	Mgmt_send_call_info_refresh,
	Mgmt_fraud_refresh,
	Mgmt_set_json_config,
	Mgmt_get_json_config,
	Mgmt_hot_restart,
	Mgmt_crules_print,
	Mgmt_reload,
	Mgmt_custom_headers_refresh,
	Mgmt_no_hash_message_rules_refresh,
	Mgmt_billing_refresh,
	Mgmt_country_detect_refresh,
	Mgmt_flush_tar,
	Mgmt_fileexists,
	Mgmt_file_exists,
	Mgmt_getfile,
	Mgmt_getfile_in_tar,
	Mgmt_getfile_in_tar_check_complete,
	Mgmt_getfile_is_zip_support,
	Mgmt_getwav,
	Mgmt_genwav,
	Mgmt_genhttppcap,
	Mgmt_getsiptshark,
	Mgmt_upgrade_restart,
	Mgmt_custipcache_vect_print,
	Mgmt_custipcache_refresh,
	Mgmt_custipcache_get_cust_id,
	Mgmt_syslogstr,
	Mgmt_coutstr,
	Mgmt_terminating,
	Mgmt_quit,
	Mgmt_pcapstat,
	Mgmt_sniffer_threads,
	Mgmt_sniffer_stat,
	Mgmt_gitUpgrade,
	Mgmt_login_screen_popup,
	Mgmt_ac_add_thread,
	Mgmt_ac_remove_thread,
	Mgmt_t2sip_add_thread,
	Mgmt_t2sip_remove_thread,
	Mgmt_rtpread_add_thread,
	Mgmt_rtpread_remove_thread,
	Mgmt_enable_bad_packet_order_warning,
	Mgmt_sipports,
	Mgmt_skinnyports,
	Mgmt_ignore_rtcp_jitter,
	Mgmt_convertchars,
	Mgmt_natalias,
	Mgmt_cloud_activecheck,
	Mgmt_jemalloc_stat,
	Mgmt_list_active_clients,
	Mgmt_memory_stat,
	Mgmt_sqlexport,
	Mgmt_sql_time_information,
	Mgmt_pausecall,
	Mgmt_unpausecall,
	Mgmt_setverbparam,
	Mgmt_set_pcap_stat_period,
	Mgmt_memcrash_test,
	Mgmt_malloc_trim,
	NULL
};

struct listening_worker_arg {
	Call *call;
};

static void updateLivesnifferfilters();
static bool cmpCallBy_destroy_call_at(Call* a, Call* b);
static bool cmpCallBy_first_packet_time(Call* a, Call* b);

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

class c_listening_clients {
public:
	struct s_client {
		s_client(const char *id, Call *call) {
			this->id = id;
			this->call = call;
			last_activity_time = getTimeS();
			spybuffer_start_pos = 0;
			spybuffer_last_send_pos = 0;
		}
		string id;
		Call *call;
		u_int32_t last_activity_time;
		u_int64_t spybuffer_start_pos;
		u_int64_t spybuffer_last_send_pos;
	};
public:
	c_listening_clients() {
		_sync = 0;
		_sync_map = 0;
	}
	~c_listening_clients() {
		lock_map();
		while(clients.size()) {
			map<string, s_client*>::iterator iter = clients.begin();
			delete iter->second;
			clients.erase(iter++);
		}
		unlock_map();
	}
	s_client *add(const char *id, Call *call) {
		s_client *client = new FILE_LINE(13001) s_client(id, call);
		string cid = string(id) + '/' + intToString((long long)call);
		lock_map();
		clients[cid] = client;
		unlock_map();
		return(client);
	}
	s_client *get(const char *id, Call *call) {
		string cid = string(id) + '/' + intToString((long long)call);
		lock_map();
		map<string, s_client*>::iterator iter = clients.find(cid);
		if(iter != clients.end()) {
			unlock_map();
			return(iter->second);
		} else {
			unlock_map();
			return(NULL);
		}
	}
	void remove(const char *id, Call *call) {
		string cid = string(id) + '/' + intToString((long long)call);
		lock_map();
		map<string, s_client*>::iterator iter = clients.find(cid);
		if(iter != clients.end()) {
			delete iter->second;
			clients.erase(iter);
		}
		unlock_map();
	}
	void remove(s_client *client) {
		remove(client->id.c_str(), client->call);
	}
	void cleanup() {
		lock_map();
		u_int64_t actTime = getTimeS();
		for(map<string, s_client*>::iterator iter = clients.begin(); iter != clients.end(); ) {
			if(iter->second->last_activity_time < actTime - 10) {
				delete iter->second;
				clients.erase(iter++);
			} else {
				iter++;
			}
		}
		unlock_map();
	}
	bool exists(Call *call) {
		bool exists = false;
		for(map<string, s_client*>::iterator iter = clients.begin(); iter != clients.end(); iter++) {
			if(iter->second->call == call) {
				exists = true;
				break;
			}
		}
		return(exists);
	}
	u_int64_t get_min_use_spybuffer_pos(Call *call) {
		u_int64_t min_pos = (u_int64_t)-1;
		lock_map();
		for(map<string, s_client*>::iterator iter = clients.begin(); iter != clients.end(); iter++) {
			if(iter->second->call == call &&
			   max(iter->second->spybuffer_start_pos, iter->second->spybuffer_last_send_pos) < min_pos) {
				min_pos = max(iter->second->spybuffer_start_pos, iter->second->spybuffer_last_send_pos);
			}
		}
		unlock_map();
		return(min_pos == (u_int64_t)-1 ? 0 : min_pos);
	}
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
	void lock_map() {
		while(__sync_lock_test_and_set(&_sync_map, 1));
	}
	void unlock_map() {
		__sync_lock_release(&_sync_map);
	}
private:
	map<string, s_client*> clients;
	volatile int _sync;
	volatile int _sync_map;
} listening_clients;

class c_listening_workers {
public:
	struct s_worker {
		s_worker(Call *call) {
			this->call = call;
			spybuffer = new FILE_LINE(13002) FifoBuffer((string("spybuffer for call ") + call->call_id).c_str());
			spybuffer->setMinItemBufferLength(1000);
			spybuffer->setMaxSize(10000000);
			thread = 0;
			running = false;
			stop = false;
		}
		~s_worker() {
			if(spybuffer) {
				delete spybuffer;
			}
		}
		Call *call;
		FifoBuffer *spybuffer;
		pthread_t thread;
		volatile bool running;
		volatile bool stop;
	};
	c_listening_workers() {
		_sync = 0;
		_sync_map = 0;
	}
	~c_listening_workers() {
		lock_map();
		while(workers.size()) {
			map<Call*, s_worker*>::iterator iter = workers.begin();
			delete iter->second;
			workers.erase(iter++);
		}
		unlock_map();
	}
	s_worker *add(Call *call) {
		s_worker *worker = new FILE_LINE(13003) s_worker(call);
		lock_map();
		workers[call] = worker;
		unlock_map();
		return(worker);
	}
	s_worker *get(Call *call) {
		lock_map();
		map<Call*, s_worker*>::iterator iter = workers.find(call);
		if(iter != workers.end()) {
			unlock_map();
			return(iter->second);
		} else {
			unlock_map();
			return(NULL);
		}
	}
	void remove(Call *call) {
		lock_map();
		map<Call*, s_worker*>::iterator iter = workers.find(call);
		if(iter != workers.end()) {
			iter->second->call->disableListeningBuffers();
			delete iter->second;
			workers.erase(iter);
		}
		unlock_map();
	}
	void remove(s_worker *worker) {
		remove(worker->call);
	}
	void run(s_worker *worker) {
		worker->call->createListeningBuffers();
		worker->running = true;
		worker->stop = false;
		vm_pthread_create_autodestroy("manager - listening worker",
					      &worker->thread, NULL, worker_thread_function, (void*)worker, __FILE__, __LINE__);
	}
	void stop(s_worker *worker) {
		worker->stop = true;
	}
	static void *worker_thread_function(void *arguments);
	void cleanup() {
		for(map<Call*, s_worker*>::iterator iter = workers.begin(); iter != workers.end(); ) {
			if(!listening_clients.exists(iter->second->call)) {
				stop(iter->second);
				while(iter->second->running) {
					usleep(100);
				}
			}
			if(!iter->second->running) {
				iter->second->call->disableListeningBuffers();
				delete iter->second;
				workers.erase(iter++);
			} else {
				iter++;
			}
		}
	}
	void lock() {
		while(__sync_lock_test_and_set(&_sync, 1));
	}
	void unlock() {
		__sync_lock_release(&_sync);
	}
	void lock_map() {
		while(__sync_lock_test_and_set(&_sync_map, 1));
	}
	void unlock_map() {
		__sync_lock_release(&_sync_map);
	}
private:
	map<Call*, s_worker*> workers;
	volatile int _sync;
	volatile int _sync_map;
} listening_workers;

/* 
 * this function runs as thread. It reads RTP audio data from call
 * and write it to output buffer 
 *
 * input parameter is structure where call 
 *
*/
void* c_listening_workers::worker_thread_function(void *arguments) {
 
	c_listening_workers::s_worker *worker = (c_listening_workers::s_worker*)arguments;
	Call *call = worker->call;
	worker->running = true;

	alaw_init();
	ulaw_init();

	// if call is hanged hup it will set listening_worker_run in its destructor to 0
	int listening_worker_run = 1;
	call->listening_worker_run = &listening_worker_run;
	pthread_mutex_lock(&call->listening_worker_run_lock);

	FILE *out = NULL;
	if(sverb.call_listening) {
		out = fopen("/tmp/test.raw", "w");
	}

	/*
	vorbis_desc ogg;
	ogg_header(out, &ogg);
	fclose(out);
	pthread_mutex_lock(&args->call->buflock);
	(&args->call->spybufferchar, &ogg);
	pthread_mutex_unlock(&args->call->buflock);
	*/

	unsigned long long begin_time_us = 0;
	unsigned long long end_time_us = 0;
	unsigned long long prev_process_time_us = 0;
        struct timeval tvwait;

	
	unsigned int period_msec = 50;
	unsigned int period_samples = 8000 * period_msec / 1000;
	u_char *spybufferchunk = new FILE_LINE(13004) u_char[period_samples * 2];
	u_int32_t len1, len2;
	short int r1, r2;
	char *s16char;
	
        while(listening_worker_run && !worker->stop) {

		/*
		while(max(call->audiobuffer1->size_get(), call->audiobuffer2->size_get()) < period_msec * 2) {
			usleep(period_msec * 1000);
		}
		*/
	 
		prev_process_time_us = end_time_us - begin_time_us;

		tvwait.tv_sec = 0;
		tvwait.tv_usec = 1000 * period_msec - prev_process_time_us;
		select(0, NULL, NULL, NULL, &tvwait);

		begin_time_us = getTimeUS();
		
		len1 = call->audioBufferData[0].audiobuffer->size_get();
		len2 = call->audioBufferData[1].audiobuffer->size_get();

		/*
		printf("codec_caller[%d] codec_called[%d] len1[%d] len2[%d]\n", 
		       worker->call->codec_caller, 
		       worker->call->codec_called,
		       len1, len2);
		*/
		
		if(len1 >= period_samples || len2 >= period_samples) {
			if(len1 >= period_samples && len2 >= period_samples) {
				len1 = period_samples;
				len2 = period_samples;
				unsigned char *read1 = call->audioBufferData[0].audiobuffer->pop(&len1);
				unsigned char *read2 = call->audioBufferData[1].audiobuffer->pop(&len2);
				for(unsigned int i = 0; i < len1; i++) {
					switch(call->codec_caller) {
					case 0:
						r1 = ULAW(read1[i]);
						break;
					case 8:
						r1 = ALAW(read1[i]);
						break;
					}
					switch(call->codec_caller) {
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
					spybufferchunk[i * 2] = s16char[0];
					spybufferchunk[i * 2 + 1] = s16char[1];
				}
				delete [] read1;
				delete [] read2;
			} else if(len2 >= period_samples) {
				len2 = period_samples;
				unsigned char *read2 = call->audioBufferData[1].audiobuffer->pop(&len2);
				for(unsigned int i = 0; i < len2; i++) {
					switch(call->codec_caller) {
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
					spybufferchunk[i * 2] = s16char[0];
					spybufferchunk[i * 2 + 1] = s16char[1];
				}
				delete [] read2;
			} else if(len1 >= period_samples) {
				len1 = period_samples;
				unsigned char *read1 = call->audioBufferData[0].audiobuffer->pop(&len1);
				for(unsigned int i = 0; i < len1; i++) {
					switch(call->codec_caller) {
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
					spybufferchunk[i * 2] = s16char[0];
					spybufferchunk[i * 2 + 1] = s16char[1];
				}
				delete [] read1;
			}
			worker->spybuffer->lock_master();
			worker->spybuffer->push(spybufferchunk, period_samples * 2);
			worker->spybuffer->unlock_master();
		}
		
		end_time_us = getTimeUS();
        }

	if(sverb.call_listening) {
		fclose(out);
	}
	
	/*
	//clean ogg
        ogg_stream_clear(&ogg.os);
        vorbis_block_clear(&ogg.vb);
        vorbis_dsp_clear(&ogg.vd);
        vorbis_comment_clear(&ogg.vc);
        vorbis_info_clear(&ogg.vi);
        */

	delete [] spybufferchunk;

	// reset pointer to NULL as we are leaving the stack here
	call->listening_worker_run = NULL;
	pthread_mutex_unlock(&call->listening_worker_run_lock);
	
	worker->running = false;
	
	return 0;
}

void listening_master_lock() {
	calltable->lock_calls_listMAP();
	listening_workers.lock();
	listening_clients.lock();
}

void listening_master_unlock() {
	listening_clients.unlock();
	listening_workers.unlock();
	calltable->unlock_calls_listMAP();
}

void listening_cleanup() {
	listening_master_lock();
	listening_clients.cleanup();
	listening_workers.cleanup();
	listening_master_unlock();
}

void listening_remove_worker(Call *call) {
	listening_master_lock();
	listening_workers.remove(call);
	listening_master_unlock();
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

int sendvm(int socket, ssh_channel channel, cClient *c_client, const char *buf, size_t len, int /*mode*/) {
	int res = 0;
	if(c_client) {
		extern cCR_Receiver_service *cloud_receiver;
		extern cSnifferClientService *snifferClientService;
		string aes_ckey, aes_ivec;
		if(cloud_receiver) {
			cloud_receiver->get_aes_keys(&aes_ckey, &aes_ivec);
		} else if(snifferClientService) {
			snifferClientService->get_aes_keys(&aes_ckey, &aes_ivec);
		}
		c_client->writeAesEnc((u_char*)buf, len, aes_ckey.c_str(), aes_ivec.c_str());
	} else if(channel) {
		res = sendssh(channel, buf, len);
	} else {
		res = send(socket, buf, len, 0);
	}
	return res;
}

int _sendvm(int socket, void *channel, void *c_client, const char *buf, size_t len, int mode) {
	return(sendvm(socket, (ssh_channel)channel, (cClient*)c_client, buf, len, mode));
}

int sendvm_from_stdout_of_command(char *command, int socket, ssh_channel channel, cClient *c_client, char */*buf*/, size_t /*len*/, int /*mode*/) {
	SimpleBuffer out;
	if(vm_pexec(command, &out) && out.size()) {
		if(sendvm(socket, channel, c_client, (const char*)out.data(), out.size(), 0) == -1) {
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

void try_ip_mask(uint &addr, uint &mask, string &ipstr) {
	stringstream data2(ipstr);
	string prefix, bits;
	uint tmpmask = ~0;
	getline(data2, prefix, '/');
	getline(data2, bits, '/');
	mask = ~(tmpmask >> atoi(bits.c_str()));
	addr = ntohl((unsigned int)inet_addr(prefix.c_str())) & mask;
}

static volatile bool enable_parse_command = false;

void manager_parse_command_enable() {
	enable_parse_command = true;
}

void manager_parse_command_disable() {
	enable_parse_command = false;
}

static int _parse_command(char *buf, int size, int client, ssh_channel sshchannel, cClient *c_client, ManagerClientThread **managerClientThread);

int parse_command(string cmd, int client, cClient *c_client) {
	ManagerClientThread *managerClientThread = NULL;
	int rslt = _parse_command((char*)cmd.c_str(), cmd.length(), client, NULL, c_client, &managerClientThread);
	if(managerClientThread) {
		if(managerClientThread->parseCommand()) {
			ClientThreads.add(managerClientThread);
			managerClientThread->run();
		} else {
			delete managerClientThread;
			if(client) {
				close(client);
			}
		}
	} else {
		if(client) {
			close(client);
		}
	}
	return(rslt);
}

int _parse_command(char *buf, int size, int client, ssh_channel sshchannel, cClient *c_client, ManagerClientThread **managerClientThread) {
	if(!enable_parse_command) {
		return(0);
	}

	char *pointerToEndSeparator = strstr(buf, "\r\n");
	if(pointerToEndSeparator) {
		*pointerToEndSeparator = 0;
	}
	if(sverb.manager) {
		cout << "manager command: " << buf << "|END" << endl;
	}
	
	int MgmtFuncIndex = -1;
	string MgmtCommand;
	char *pointerToSeparatorInCmd = strpbrk(buf, " \r\n\t");
	std::map<string, int>::iterator MgmtItem = MgmtCmdsRegTable.find(pointerToSeparatorInCmd ? string(buf, pointerToSeparatorInCmd) : buf);
	if (MgmtItem != MgmtCmdsRegTable.end()) {
		MgmtFuncIndex = MgmtItem->second;
		MgmtCommand = MgmtItem->first;
	}
	if(MgmtFuncIndex < 0) {
		std::map<string, int>::iterator MgmtItem;
		for(MgmtItem = MgmtCmdsRegTable.begin(); MgmtItem != MgmtCmdsRegTable.end(); MgmtItem++) {
			if(strstr(buf, MgmtItem->first.c_str())) {
				MgmtFuncIndex = MgmtItem->second;
				MgmtCommand = MgmtItem->first;
				break;
			}
		}
	}
	Mgmt_params* mparams = new FILE_LINE(0) Mgmt_params(buf, size, client, sshchannel, c_client, managerClientThread);
	if(MgmtFuncIndex >= 0) {
		mparams->command = MgmtCommand;
		int ret = MgmtFuncArray[MgmtFuncIndex](mparams);
		delete mparams;
		return(ret);
	} else {
		mparams->sendString("command not found\n");
		delete mparams;
		string error = string("Can't determine the command '") + buf + "'";
		syslog(LOG_ERR, "%s", error.c_str());
		return(-1);
	}
}

int Handle_pause_call(long long callref, int val ) {
	int retval = 1;

	if (calltable) {
		calltable->lock_calls_listMAP();
		Call *call = calltable->find_by_reference(callref, false);

		if (call)
			call->silencerecording = val;
		else
			retval = -1;

		calltable->unlock_calls_listMAP();
	}
	return(retval);
}


/*
struct svi {
	volatile char command_type[100];
	volatile int i;
};
volatile svi vi[500];
extern pthread_mutex_t commmand_type_counter_sync;

bool _strncmp_v(volatile char a[], const char *b, unsigned length) {
	for(unsigned i = 0; i < length; i++) {
		if(a[i] != b[i]) {
			return(true);
		}
		if(!a[i] || !b[i]) {
			break;
		}
	}
	return(false);
}

bool _strncpy_v(volatile char dst[], const char *src, unsigned length) {
	for(unsigned i = 0; i < length; i++) {
		dst[i] = src[i];
		if(!src[i]) {
			break;
		}
	}
}

static bool addCommandType(string command_type) {
	bool rslt = false;
	pthread_mutex_lock(&commmand_type_counter_sync);
	for(unsigned i = 0; i < sizeof(vi) / sizeof(svi); i++) {
		if(!_strncmp_v(vi[i].command_type, command_type.c_str(), sizeof(vi[i].command_type))) {
			if(vi[i].i < 20) {
				++vi[i].i;
				rslt = true;
			}
			break;
		} else if(!vi[i].command_type[0]) {
			_strncpy_v(vi[i].command_type, command_type.c_str(), sizeof(vi[i].command_type));
			vi[i].i = 1;
			rslt = true;
			break;
		}
	}
	
// 	map<string, vi*>::iterator iter = commmand_type_counter.find(command_type);
// 	if(iter == commmand_type_counter.end()) {
// 		vi *_i = new vi;
// 		_i->i = 1;
// 		commmand_type_counter[command_type] = _i;
// 		rslt = true;
// 	} else {
// 		if(commmand_type_counter[command_type]->i < 20) {
// 			__sync_add_and_fetch(&commmand_type_counter[command_type]->i, 1);
// 			rslt = true;
// 		}
// 	}
	
	pthread_mutex_unlock(&commmand_type_counter_sync);
	return(rslt);
}

static void subCommandType(string command_type) {
	pthread_mutex_lock(&commmand_type_counter_sync);
	for(unsigned i = 0; i < sizeof(vi) / sizeof(svi); i++) {
		if(!_strncmp_v(vi[i].command_type, command_type.c_str(), sizeof(vi[i].command_type))) {
			if(vi[i].i > 0) {
				--vi[i].i;
			}
			break;
		}
	}
	
// 	if(commmand_type_counter[command_type]->i > 0) {
// 		__sync_sub_and_fetch(&commmand_type_counter[command_type]->i, 1);
// 	}
	
	pthread_mutex_unlock(&commmand_type_counter_sync);
}
*/

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
		bool debugRecv = verbosity >= 2;
		if(debugRecv) {
			cout << "DATA: " << buf << endl;
		}
		if(!strstr(buf, "\r\n\r\n")) {
			char buf_next[BUFSIZE];
			if(debugRecv) {
				cout << "NEXT_RECV start" << endl;
			}
			while(true) {
				bool doRead = false;
				int timeout_ms = 500;
				if(opt_socket_use_poll) {
					pollfd fds[2];
					memset(fds, 0 , sizeof(fds));
					fds[0].fd = client;
					fds[0].events = POLLIN;
					int rsltPool = poll(fds, 1, timeout_ms);
					if(rsltPool > 0 && fds[0].revents) {
						doRead = true;
					}
				} else {
					fd_set rfds;
					struct timeval tv;
					FD_ZERO(&rfds);
					FD_SET(client, &rfds);
					tv.tv_sec = 0;
					tv.tv_usec = timeout_ms * 1000;
					int rsltSelect = select(client + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
					if(rsltSelect > 0 && FD_ISSET(client, &rfds)) {
						doRead = true;
					}
				}
				if(doRead &&
				   (size = recv(client, buf_next, BUFSIZE - 1, 0)) > 0) {
					buf_next[size] = '\0';
					buf_long += buf_next;
					if(debugRecv) {
						cout << "NEXT DATA: " << buf_next << endl;
					}
					if(buf_long.find("\r\n\r\n") != string::npos) {
						break;
					}
				} else {
					break;
				}
			}
			if(debugRecv) {
				cout << "NEXT_RECV stop" << endl;
			}
			size_t posEnd;
			if((posEnd = buf_long.find("\r\n\r\n")) != string::npos) {
				buf_long.resize(posEnd);
			}
		}
	}
	
	parse_command(buf_long, client, NULL);

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

	cloud_activecheck_sshclose = false; //alow active checking operations from now
	/* set the thread detach state */
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	while(1) {
		if (cloud_activecheck_sshclose) goto ssh_disconnect;
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
				_parse_command(buf, len, 0, channel, NULL, NULL);
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
void *manager_ssh(void */*arg*/) {
	while (ssh_host[0] == '\0') {	//wait until register.php POST done
		sleep(1);
	}

	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();
//	ssh_set_log_level(SSH_LOG_WARNING | SSH_LOG_PROTOCOL | SSH_LOG_PACKET | SSH_LOG_FUNCTIONS);
	while(!is_terminating()) {
		syslog(LOG_NOTICE, "Starting reverse SSH connection service\n");
		manager_ssh_();
		syslog(LOG_NOTICE, "SSH service stopped.\n");
		sleep(1);
	}
	return 0;
}
#endif


void *manager_server(void */*dummy*/) {
 
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
	while(!is_terminating_without_error()) {
		bool doAccept = false;
		int timeout = 10;
		if(!opt_manager_nonblock_mode) {
			doAccept = true;
		} else {
			if(opt_socket_use_poll) {
				pollfd fds[2];
				memset(fds, 0 , sizeof(fds));
				fds[0].fd = manager_socket_server;
				fds[0].events = POLLIN;
				if(poll(fds, 1, timeout * 1000) > 0) {
					doAccept = true;
				}
			} else {
				FD_ZERO(&rfds);
				FD_SET(manager_socket_server, &rfds);
				tv.tv_sec = timeout;
				tv.tv_usec = 0;
				if(select(manager_socket_server + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
					doAccept = true;
				}
			}
		}
		if(doAccept) {
			addrlen = sizeof(clientInfo);
			int client = accept(manager_socket_server, (sockaddr*)&clientInfo, &addrlen);
			if(is_terminating_without_error()) {
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
			unsigned int *_ids = new FILE_LINE(13018) unsigned int;
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
	new_state.all_bothport = true;
	new_state.all_srcnum = true;
	new_state.all_dstnum = true;
	new_state.all_bothnum = true;
	new_state.all_fromhstr = true;
	new_state.all_tohstr = true;
	new_state.all_bothhstr = true;
	new_state.all_vlan = true;
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
		if(this->lv_bothport[i]) {
			new_state.all_bothport = false;
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
		if(this->lv_fromhstr[i][0]) {
			new_state.all_fromhstr = false;
		}
		if(this->lv_tohstr[i][0]) {
			new_state.all_tohstr = false;
		}
		if(this->lv_bothhstr[i][0]) {
			new_state.all_bothhstr = false;
		}
		if(this->lv_vlan_set[i]) {
			new_state.all_vlan = false;
		}
		if(this->lv_siptypes[i]) {
			new_state.all_siptypes = false;
		}
	}
	new_state.all_addr = new_state.all_saddr && new_state.all_daddr && new_state.all_bothaddr;
	new_state.all_num = new_state.all_srcnum && new_state.all_dstnum && new_state.all_bothnum;
	new_state.all_hstr = new_state.all_fromhstr && new_state.all_tohstr && new_state.all_bothhstr;
	new_state.all_all = new_state.all_addr && new_state.all_bothport && new_state.all_num && new_state.all_hstr && new_state.all_vlan && new_state.all_siptypes;
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
	for(int pass = 1; pass <= 3; pass++) {
		if(!(pass == 1 ? this->state.all_fromhstr :
		     pass == 2 ? this->state.all_tohstr :
				 this->state.all_bothhstr)) {
			char (*hstr)[MAXLIVEFILTERSCHARS] = pass == 1 ? this->lv_fromhstr :
							    pass == 2 ? this->lv_tohstr :
									this->lv_bothhstr;
			int counter = 0;
			for(int i = 0; i < MAXLIVEFILTERS; i++) {
				if(hstr[i][0]) {
					if(counter) {
						outStr << ", ";
					} else {
						outStr << (pass == 1 ? "from header" :
							   pass == 2 ? "to header" :
							   pass == 3 ? "from/to header" :
								       "")
						       << ": ";
					}
					outStr << hstr[i];
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
	char *flushBuff = new FILE_LINE(13019) char[flushBuffLength];
	memset(flushBuff, '_', flushBuffLength - 1);
	flushBuff[flushBuffLength - 1] = '\n';
	while(true && !is_terminating_without_error() && !disconnect) {
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
					      unsigned int sipSaddr, unsigned int sipDaddr,
					      const char *screenPopupFieldsString) {
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
	snprintf(rsltString, sizeof(rsltString),
		"call_data: "
		"sipresponse:[[%i]] "
		"callername:[[%s]] "
		"caller:[[%s]] "
		"called:[[%s]] "
		"sipcallerip:[[%s]] "
		"sipcalledip:[[%s]] "
		"fields:[[%s]]\n",
		sipResponseNum,
		callerName,
		callerNumStr.c_str(),
		calledNum,
		sipSaddrIP,
		sipDaddrIP,
		screenPopupFieldsString);
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
							snprintf(rsltString, sizeof(rsltString),
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
				  unsigned int sipSaddr, unsigned int sipDaddr,
				  const char *screenPopupFieldsString) {
	this->lock_client_threads();
	vector<ManagerClientThread*>::iterator iter;
	for(iter = this->clientThreads.begin(); iter != this->clientThreads.end(); ++iter) {
		(*iter)->onCall(sipResponseNum, callerName, callerNum, calledNum, 
				sipSaddr, sipDaddr, 
				screenPopupFieldsString);
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

int Mgmt_getversion(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getversion", "return the version of the sniffer");
		return(0);
	}
	return(params->sendString(RTPSENSOR_VERSION));
}

int Mgmt_cleanup_calls(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("cleanup_calls", "clean calls");
		return(0);
	}
	calltable->cleanup_calls(NULL);
	return(params->sendString("ok"));
}

int Mgmt_cleanup_registers(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("cleanup_registers", "clean registers");
		return(0);
	}
	calltable->cleanup_registers(NULL);
	return(params->sendString("ok"));
}

int Mgmt_expire_registers(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("expire_registers", "expire registers");
		return(0);
	}
	extern int opt_sip_register;
	if(opt_sip_register == 1) {
		extern Registers registers;
		struct timeval act_ts;
		act_ts.tv_sec = time(NULL);
		act_ts.tv_usec = 0;
		registers.cleanup(&act_ts, true);
	}
	return(params->sendString("ok"));
}

int Mgmt_cleanup_tcpreassembly(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("cleanup_tcpreassembly", "clean tcpreassembly");
		return(0);
	}
	extern TcpReassemblySip tcpReassemblySip;
	tcpReassemblySip.clean();
	return(params->sendString("ok"));
}

int Mgmt_destroy_close_calls(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("destroy_close_calls", "destroy close calls");
		return(0);
	}
	calltable->destroyCallsIfPcapsClosed();
	return(params->sendString("ok"));
}

int Mgmt_is_register_new(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("is_register_new", "return status of the sip registration");
		return(0);
	}
	extern int opt_sip_register;
	return(params->sendString(opt_sip_register == 2 ? "no" : "ok"));
}

int Mgmt_totalcalls(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("totalcalls", "return the number of total calls");
		return(0);
	}
	return(params->sendString(calls_counter));
}

int Mgmt_totalregisters(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("totalregisters", "return the number of total registers");
		return(0);
	}
	extern Registers registers;
	return(params->sendString(registers.getCount()));
}

int Mgmt_listregisters(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("listregisters", "return the list of registers. Possible params:");
		return(0);
	}
	string rslt_data;
	char *pointer;
	if((pointer = strchr(params->buf, '\n')) != NULL) {
		*pointer = 0;
	}
	extern Registers registers;
	rslt_data = registers.getDataTableJson(params->buf + params->command.length() + 1, &params->zip);
	return(params->sendString(&rslt_data));
}

int Mgmt_list_sip_msg(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("list_sip_msg", "return the list of options. Possible params:");
		return(0);
	}
	string rslt_data;
	char *pointer;
	if((pointer = strchr(params->buf, '\n')) != NULL) {
		*pointer = 0;
	}
	extern cSipMsgRelations *sipMsgRelations;
	if(sipMsgRelations) {
		rslt_data = sipMsgRelations->getDataTableJson(params->buf + params->command.length() + 1, &params->zip);
		return(params->sendString(&rslt_data));
	}
	return(0);
}

int Mgmt_list_history_sip_msg(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("list_history_sip_msg", "return the list of history options. Possible params:");
		return(0);
	}
	string rslt_data;
	char *pointer;
	if((pointer = strchr(params->buf, '\n')) != NULL) {
		*pointer = 0;
	}
	extern cSipMsgRelations *sipMsgRelations;
	if(sipMsgRelations) {
		rslt_data = sipMsgRelations->getHistoryDataJson(params->buf + params->command.length() + 1, &params->zip);
		return(params->sendString(&rslt_data));
	}
	return(0);
}

int Mgmt_cleanupregisters(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("cleanupregisters", "clean registers. Possible params:");
		return(0);
	}
	char *pointer;
	if((pointer = strchr(params->buf, '\n')) != NULL) {
		*pointer = 0;
	}
	extern Registers registers;
	registers.cleanupByJson(params->buf + strlen("cleanupregisters") + 1);
	return(params->sendString("ok"));
}

int Mgmt_help(Mgmt_params* params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("help", "print command's help");
		return(0);
	}
	std::map<string, string>::iterator MgmtItem;
	char *startOfParam = strpbrk(params->buf, " ");
	stringstream sendBuff;
	if (startOfParam) {
		startOfParam++;
		char *endOfParam = strpbrk(startOfParam, " \r\n\t");
		if (!endOfParam) {
			syslog(LOG_ERR, "Can't determine the param's end.");
			cerr << "Can't determine the param's end." << endl;
			return(-1);
		}
		string cmdStr (startOfParam, endOfParam);
		MgmtItem = MgmtHelpTable.find(cmdStr);
		if (MgmtItem != MgmtHelpTable.end()) {
			if (MgmtItem->second.length()) {
				sendBuff << MgmtItem->first << " ... " << MgmtItem->second << "." << endl << endl;
			}
		} else {
			sendBuff << "Command " << cmdStr << " not found." << endl << endl;
		}
	} else {
		sendBuff << "List of commands:" << endl << endl;
		for (MgmtItem = MgmtHelpTable.begin(); MgmtItem != MgmtHelpTable.end(); MgmtItem++) {
			if (MgmtItem->second.length()) {
				sendBuff << MgmtItem->first << " ... " << MgmtItem->second << "." << endl << endl;
			}
		}
	}
	string sendbuff = sendBuff.str();
	return(params->sendString(&sendbuff));
}

int Mgmt_check_filesindex(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("check_filesindex", "check files indexing");
		return(0);
	}
	char sendbuf[BUFSIZE];
	if(is_enable_cleanspool()) {
		snprintf(sendbuf, BUFSIZE, "starting checking indexing please wait...");
		params->sendString(sendbuf);
		CleanSpool::run_check_filesindex();
		snprintf(sendbuf, BUFSIZE, "done\r\n");
	} else {
		strcpy(sendbuf, "cleanspool is disable\r\n");
	}
	return(params->sendString(sendbuf));
}

int Mgmt_reindexspool(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("reindexspool", "reindex spool directory");
		return(0);
	}
	string rslt;
	if(is_enable_cleanspool()) {
		CleanSpool::run_reindex_spool();
		rslt = "done\r\n";
	} else {
		rslt = "cleanspool is disable\r\n";
	}
	return(params->sendString(&rslt));
}

int Mgmt_printspool(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("printspool", "print info about spool directory");
		return(0);
	}
	string rslt;
	if(is_enable_cleanspool()) {
		rslt = CleanSpool::run_print_spool();
	} else {
		rslt = "cleanspool is disable\r\n";
	}
	return(params->sendString(&rslt));
}

int Mgmt_reindexfiles(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		commandAndHelp ch[] = {
			{"reindexfiles", "starts the reindexing of the spool's files. 'reindexfiles' runs standard reindex"},
			{"reindexfiles_date", "runs reindex for entered DATE"},
			{"reindexfiles_datehour", "runs reindex for entered DATE HOUR"},
			{NULL, NULL}
		};
		params->registerCommand(ch);
		return(0);
	}
	char sendbuf[BUFSIZE];
	if(is_enable_cleanspool()) {
		char date[21];
		int hour;
		bool badParams = false;
		if(strstr(params->buf, "reindexfiles_datehour")) {
			if(sscanf(params->buf + strlen("reindexfiles_datehour") + 1, "%20s %i", date, &hour) != 2) {
				badParams = true;
			}
		} else if(strstr(params->buf, "reindexfiles_date")) {
			if(sscanf(params->buf + strlen("reindexfiles_date") + 1, "%20s", date) != 1) {
				badParams = true;
			}
		}
		if(badParams) {
			snprintf(sendbuf, BUFSIZE, "bad parameters");
			params->sendString(sendbuf);
			return -1;
		}
		snprintf(sendbuf, BUFSIZE, "starting reindexing please wait...");
		params->sendString(sendbuf);
		if(strstr(params->buf, "reindexfiles_datehour")) {
			CleanSpool::run_reindex_date_hour(date, hour);
		} else if(strstr(params->buf, "reindexfiles_date")) {
			CleanSpool::run_reindex_date(date);
		} else {
			CleanSpool::run_reindex_all("call from manager");
		}
		snprintf(sendbuf, BUFSIZE, "done\r\n");
	} else {
		strcpy(sendbuf, "cleanspool is disable\r\n");
	}
	return(params->sendString(sendbuf));
}

int Mgmt_listcalls(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("listcalls", "lists active calls");
		return(0);
	}
	if(calltable) {
		string rslt_data;
		char *pointer;
		if((pointer = strchr(params->buf, '\n')) != NULL) {
			*pointer = 0;
		}
		params->zip = false;
		char *jsonParams = params->buf + strlen("listcalls");
		while(*jsonParams == ' ') {
			++jsonParams;
		}
		rslt_data = calltable->getCallTableJson(jsonParams, &params->zip);
		return(params->sendString(&rslt_data));
	}
	return 0;
}

typedef struct {
	int *setVar;
	int setValue;
	const char *helpText;
} cmdData;

int Mgmt_offon(Mgmt_params *params) {
	static std::map<string, cmdData> cmdsDataTable;
	if (params->task == params->mgmt_task_DoInit) {
		cmdsDataTable["unblocktar"] = {&opt_blocktarwrite, 0, "unblock tar files"};
		cmdsDataTable["blocktar"] = {&opt_blocktarwrite, 1, "block tar files"};
		cmdsDataTable["unblockasync"] = {&opt_blockasyncprocess, 0, "unblock async processing"};
		cmdsDataTable["blockasync"] = {&opt_blockasyncprocess, 1, "block async processing"};
		cmdsDataTable["unblockprocesspacket"] = {&opt_blockprocesspacket, 0, "unblock packet processing"};
		cmdsDataTable["blockprocesspacket"] = {&opt_blockprocesspacket, 1, "block packet processing"};
		cmdsDataTable["unblockcleanupcalls"] = {&opt_blockcleanupcalls, 0, "unblock cleanup calls"};
		cmdsDataTable["blockcleanupcalls"] = {&opt_blockcleanupcalls, 1, "block cleanup calls"};
		cmdsDataTable["unsleepprocesspacket"] = {&opt_sleepprocesspacket, 0, "unsleep packet processing"};
		cmdsDataTable["sleepprocesspacket"] = {&opt_sleepprocesspacket, 1, "sleep packet processing"};
		cmdsDataTable["unblockqfile"] = {&opt_blockqfile, 0, "unblock qfiles"};
		cmdsDataTable["blockqfile"] = {&opt_blockqfile, 1, "block qfiles"};
		cmdsDataTable["unblock_alloc_stack"] = {&opt_block_alloc_stack, 0, "unblock stack allocation"};
		cmdsDataTable["block_alloc_stack"] = {&opt_block_alloc_stack, 1, "block stack allocation"};
		cmdsDataTable["disablecdr"] = {&opt_nocdr, 1, "disable cdr creation"};
		cmdsDataTable["enablecdr"] = {&opt_nocdr, 0, "enable cdr creation"};

		std::map<string, cmdData>::iterator cmdItem;
		for (cmdItem = cmdsDataTable.begin(); cmdItem != cmdsDataTable.end(); cmdItem++) {
			params->registerCommand(cmdItem->first.c_str(), cmdItem->second.helpText);
		}
		return(0);
	}
	char *endOfCmd = strpbrk(params->buf, " \r\n\t");
	if (!endOfCmd) {
		return(-1);
	}
	string cmdStr (params->buf, endOfCmd);
	std::map<string, cmdData>::iterator cmdItem = cmdsDataTable.find(cmdStr);
	if (cmdItem != cmdsDataTable.end()) {
		* cmdItem->second.setVar = cmdItem->second.setValue;
	}
	return(0);
}

int Mgmt_creategraph(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("creategraph", "creates graphs");
		return(0);
	}

	checkRrdVersion(true);
	extern int vm_rrd_version;
	if(!vm_rrd_version)
		return(params->sendString("missing rrdtool"));

	extern pthread_mutex_t vm_rrd_lock;
	pthread_mutex_lock(&vm_rrd_lock);

	int res = 0;
	int manager_argc;
	char *manager_cmd_line = NULL;	//command line passed to voipmonitor manager
	char **manager_args = NULL;		//cuted voipmonitor manager commandline to separate arguments

	char sendbuf[BUFSIZE];
	sendbuf[0] = 0;			//for reseting sendbuf

	if (( manager_argc = vm_rrd_countArgs(params->buf)) < 6) {	//few arguments passed
		if (verbosity > 0) syslog(LOG_NOTICE, "parse_command creategraph too few arguments, passed%d need at least 6!\n", manager_argc);
		snprintf(sendbuf, BUFSIZE, "Syntax: creategraph graph_type linuxTS_from linuxTS_to size_x_pixels size_y_pixels  [ slope-mode  [ icon-mode  [ color  [ dstfile ]]]]\n");
		if (params->sendString(sendbuf) == -1) {
			cerr << "Error sending data to client 1" << endl;
		}
		pthread_mutex_unlock(&vm_rrd_lock);
		return -1;
	}
	if ((manager_cmd_line = new FILE_LINE(13005) char[strlen(params->buf) + 1]) == NULL) {
		syslog(LOG_ERR, "parse_command creategraph malloc error\n");
		pthread_mutex_unlock(&vm_rrd_lock);
		return -1;
	}
	if ((manager_args = new FILE_LINE(13006) char*[manager_argc + 1]) == NULL) {
		delete [] manager_cmd_line;
		syslog(LOG_ERR, "parse_command creategraph malloc error2\n");
		pthread_mutex_unlock(&vm_rrd_lock);
		return -1;
	}

	memcpy(manager_cmd_line, params->buf, strlen(params->buf));
	manager_cmd_line[strlen(params->buf)] = '\0';

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
		//Possible graph types: #PS,PSC,PSS,PSSM,PSSR,PSR,PSA,SQLq,SQLf,tCPU,drop,speed,heap,calls,tacCPU,loadadvg


		char sendcommand[2048];			//buffer for send command string;
		if (!strncmp(manager_args[1], "PSA",4 )) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-PS.rrd", getRrdDir());
			rrd_vm_create_graph_PSA_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "PSR", 4)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-PS.rrd", getRrdDir());
			rrd_vm_create_graph_PSR_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "PSSR", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-PS.rrd", getRrdDir());
			rrd_vm_create_graph_PSSR_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "PSSM", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-PS.rrd", getRrdDir());
			rrd_vm_create_graph_PSSM_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "PSS", 4)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-PS.rrd", getRrdDir());
			rrd_vm_create_graph_PSS_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "PSC", 4)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-PS.rrd", getRrdDir());
			rrd_vm_create_graph_PSC_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "PS", 3)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-PS.rrd", getRrdDir());
			rrd_vm_create_graph_PS_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "SQLq", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/3db-SQL.rrd", getRrdDir());
			rrd_vm_create_graph_SQLq_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "SQLf", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/3db-SQL.rrd", getRrdDir());
			rrd_vm_create_graph_SQLf_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "tCPU", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-tCPU.rrd", getRrdDir());
			rrd_vm_create_graph_tCPU_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "drop", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-drop.rrd", getRrdDir());
			rrd_vm_create_graph_drop_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "speed", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-speedmbs.rrd", getRrdDir());
			rrd_vm_create_graph_speed_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "heap", 5)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-heap.rrd", getRrdDir());
			rrd_vm_create_graph_heap_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "calls", 6)) {
			snprintf(filename, sizeof(filename), "%s/rrd/3db-callscounter.rrd", getRrdDir());
			rrd_vm_create_graph_calls_command(filename, fromat, toat, color, resx ,resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "tacCPU", 7)) {
			snprintf(filename, sizeof(filename), "%s/rrd/2db-tacCPU.rrd", getRrdDir());
			rrd_vm_create_graph_tacCPU_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "memusage", 7)) {
			snprintf(filename, sizeof(filename), "%s/rrd/db-memusage.rrd", getRrdDir());
			rrd_vm_create_graph_memusage_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else if (!strncmp(manager_args[1], "loadavg", 7)) {
			snprintf(filename, sizeof(filename), "%s/rrd/db-LA.rrd", getRrdDir());
			rrd_vm_create_graph_LA_command(filename, fromat, toat, color, resx, resy, slope, icon, dstfile, sendcommand, sizeof(sendcommand));
		} else {
			snprintf(sendbuf, BUFSIZE, "Error: Graph type %s isn't known\n\tGraph types: PS PSC PSS PSSM PSSR PSR PSA SQLq SQLf tCPU drop speed heap calls tacCPU memusage\n", manager_args[1]);
			if (verbosity > 0) {
				syslog(LOG_NOTICE, "creategraph Error: Unrecognized graph type %s", manager_args[1]);
				syslog(LOG_NOTICE, "    Graph types: PS PSC PSS PSSM PSSR PSR PSA SQLq SQLf tCPU drop speed heap calls tacCPU memusage loadavg");
			}
			res = -1;
		}
		if ((dstfile == NULL) && (res == 0)) {		//send from stdout of a command (binary data)
			if (sverb.rrd_info) syslog(LOG_NOTICE, "COMMAND for system pipe:%s", sendcommand);
			if (sendvm_from_stdout_of_command(sendcommand, params->client, params->sshchannel, params->c_client, sendbuf, sizeof(sendbuf), 0) == -1 ){
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
				if (params->sendString(sendbuf) == -1) {
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
}

int Mgmt_d_lc_for_destroy(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("d_lc_for_destroy", "d_lc_for_destroy");
		return(0);
	}

	ostringstream outStr;
	if(!calltable && !terminating) {
		outStr << "sniffer not initialized yet" << endl;
		return(params->sendString(&outStr));
	}
	if(calltable->calls_queue.size()) {
		Call *call;
		vector<Call*> vectCall;
		calltable->lock_calls_queue();
		for(size_t i = 0; i < calltable->calls_queue.size(); ++i) {
			call = calltable->calls_queue[i];
			if(call->typeIsNot(REGISTER) && call->destroy_call_at) {
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
	return(params->sendString(&outStr));
}
int Mgmt_d_lc_bye(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("d_lc_bye", "d_lc_bye");
		return(0);
	}

	ostringstream outStr;
	if(!calltable && !terminating) {
		outStr << "sniffer not initialized yet" << endl;
		return(params->sendString(&outStr));
	}
	map<string, Call*>::iterator callMAPIT;
	Call *call;
	vector<Call*> vectCall;
	calltable->lock_calls_listMAP();
	for (callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
		call = (*callMAPIT).second;
		if(call->typeIsNot(REGISTER) && call->seenbye) {
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
	return(params->sendString(&outStr));
}

int Mgmt_d_lc_all(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("d_lc_all", "d_lc_all");
		return(0);
	}

	ostringstream outStr;
	if(!calltable && !terminating) {
		outStr << "sniffer not initialized yet" << endl;
		return(params->sendString(&outStr));
	}
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
	return(params->sendString(&outStr));
}

int Mgmt_d_pointer_to_call(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("d_pointer_to_call", "d_pointer_to_call");
		return(0);
	}
	char fbasename[256];
	sscanf(params->buf, "d_pointer_to_call %s", fbasename);
	ostringstream outStr;
	calltable->lock_calls_listMAP();
	for(map<string, Call*>::iterator callMAPIT = calltable->calls_listMAP.begin(); callMAPIT != calltable->calls_listMAP.end(); ++callMAPIT) {
		if(!strcmp((*callMAPIT).second->fbasename, fbasename)) {
			outStr << "find in calltable->calls_listMAP " << hex << (*callMAPIT).second << endl;
		}
	}
	calltable->unlock_calls_listMAP();
	calltable->lock_calls_queue();
	for(deque<Call*>::iterator callIT = calltable->calls_queue.begin(); callIT != calltable->calls_queue.end(); ++callIT) {
		if(!strcmp((*callIT)->fbasename, fbasename)) {
			outStr << "find in calltable->calls_queue " << hex << (*callIT) << endl;
		}
	}
	calltable->unlock_calls_queue();
	return(params->sendString(&outStr));
}

int Mgmt_d_close_call(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("d_close_call", "d_close_call");
		return(0);
	}
	char fbasename[100];
	sscanf(params->buf, "d_close_call %s", fbasename);
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
	rslt += "\n";
	return(params->sendString(&rslt));
}

int Mgmt_getipaccount(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getipaccount", "getipaccount");
		return(0);
	}
	char sendbuf[BUFSIZE];
	u_int32_t uid = 0;
	sscanf(params->buf, "getipaccount %u", &uid);
	map<unsigned int, octects_live_t*>::iterator it = ipacc_live.find(uid);
	if(it != ipacc_live.end()) {
		snprintf(sendbuf, BUFSIZE, "%d", 1);
	} else {
		snprintf(sendbuf, BUFSIZE, "%d", 0);
	}
	return(params->sendString(sendbuf));
}

int Mgmt_ipaccountfilter(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("ipaccountfilter", "ipaccountfilter set");
		return(0);
	}

	string ipfilter;
	u_int32_t id = atol(params->buf + strlen("ipaccountfilter set "));
	char *pointToSeparatorBefereIpfilter = strchr(params->buf + strlen("ipaccountfilter set "), ' ');
	if(pointToSeparatorBefereIpfilter) {
		ipfilter = pointToSeparatorBefereIpfilter + 1;
	}
	if(!ipfilter.length() || ipfilter.find("ALL") != string::npos) {
		map<unsigned int, octects_live_t*>::iterator it = ipacc_live.find(id);
		octects_live_t* filter;
		if(it != ipacc_live.end()) {
			filter = it->second;
		} else {
			filter = new FILE_LINE(13007) octects_live_t;
			memset(CAST_OBJ_TO_VOID(filter), 0, sizeof(octects_live_t));
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
		filter = new FILE_LINE(13008) octects_live_t;
		memset(CAST_OBJ_TO_VOID(filter), 0, sizeof(octects_live_t));
		filter->setFilter(ipfilter.c_str());
		filter->fetch_timestamp = time(NULL);
		ipacc_live[id] = filter;
		if(verbosity > 0) {
			cout << "START LIVE IPACC " << "id: " << id << " ipfilter: " << ipfilter << endl;
		}
	}
	return(0);
}

int Mgmt_stopipaccount(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("stopipaccount", "stopipaccount");
		return(0);
	}
	u_int32_t id = 0;
	sscanf(params->buf, "stopipaccount %u", &id);
	map<unsigned int, octects_live_t*>::iterator it = ipacc_live.find(id);
	if(it != ipacc_live.end()) {
		delete it->second;
		ipacc_live.erase(it);
		if(verbosity > 0) {
			cout << "STOP LIVE IPACC " << "id:" << id << endl;
		}
	}
	return 0;
}

int Mgmt_fetchipaccount(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("fetchipaccount", "fetchipaccount");
		return(0);
	}
	u_int32_t id = 0;
	sscanf(params->buf, "fetchipaccount %u", &id);
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
	return(params->sendString(sendbuf));
}

int Mgmt_getactivesniffers(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getactivesniffers", "returns active sniffers");
		return(0);
	}
	while(__sync_lock_test_and_set(&usersniffer_sync, 1));
	string jsonResult = "[";
	map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT;
	int counter = 0;
	for(usersnifferIT = usersniffer.begin(); usersnifferIT != usersniffer.end(); usersnifferIT++) {
		if(counter) {
			jsonResult += ",";
		}
		char uid_str[10];
		snprintf(uid_str, sizeof(uid_str), "%i", usersnifferIT->first);
		jsonResult += "{\"uid\": \"" + string(uid_str) + "\"," +
			"\"state\":\"" + usersnifferIT->second->getStringState() + "\"}";
		++counter;
	}
	jsonResult += "]";
	__sync_lock_release(&usersniffer_sync);
	return(params->sendString(&jsonResult));
}

int Mgmt_stoplivesniffer(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("stoplivesniffer", "stop live sniffer");
		return(0);
	}
	u_int32_t uid = 0;
	sscanf(params->buf, "stoplivesniffer %u", &uid);
	while(__sync_lock_test_and_set(&usersniffer_sync, 1)) {};
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
}

int Mgmt_getlivesniffer(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getlivesniffer", "returns running live sniffers");
		return(0);
	}
	char sendbuf[BUFSIZE];
	u_int32_t uid = 0;
	sscanf(params->buf, "getlivesniffer %u", &uid);
	while(__sync_lock_test_and_set(&usersniffer_sync, 1));
	map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT = usersniffer.find(uid);
	if(usersnifferIT != usersniffer.end()) {
		snprintf(sendbuf, BUFSIZE, "%d %s", 1, (char*)usersnifferIT->second->parameters);
	} else {
		snprintf(sendbuf, BUFSIZE, "%d", 0);
	}
	__sync_lock_release(&usersniffer_sync);
	return(params->sendString(sendbuf));
}

int Mgmt_startlivesniffer(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("startlivesniffer", "starts live sniffing");
		return(0);
	}

	char parameters[10000] = "";
	sscanf(params->buf, "startlivesniffer %[^\n\r]", parameters);
	if(verbosity > 0) {
		syslog(LOG_NOTICE, "start livesniffer - parameters: %s", parameters);
	}
	JsonItem jsonParameters;
	jsonParameters.parse(parameters);
	while(__sync_lock_test_and_set(&usersniffer_sync, 1));
	unsigned int uid = atol(jsonParameters.getValue("uid").c_str());
	map<unsigned int, livesnifferfilter_t*>::iterator usersnifferIT = usersniffer.find(uid);
	livesnifferfilter_t* filter;
	if(usersnifferIT != usersniffer.end()) {
		filter = usersnifferIT->second;
	} else {
		filter = new FILE_LINE(0) livesnifferfilter_t;
		memset(CAST_OBJ_TO_VOID(filter), 0, sizeof(livesnifferfilter_t));
		filter->parameters.add(parameters);
		usersniffer[uid] = filter;
	}
	string filter_sensor_id = jsonParameters.getValue("filter_sensor_id");
	if(filter_sensor_id.length()) {
		filter->sensor_id = atoi(filter_sensor_id.c_str());
		filter->sensor_id_set = true;
	}
	string filter_ip = jsonParameters.getValue("filter_ip");
	if(filter_ip.length()) {
		vector<string> ip = split(filter_ip.c_str(), split(",|;| ", "|"), true);
		for(unsigned i = 0; i < ip.size() && i < MAXLIVEFILTERS; i++) {
			filter->lv_bothaddr[i] = ntohl((unsigned int)inet_addr(ip[i].c_str()));
			if((int)filter->lv_bothaddr[i] == -1 && strchr(ip[i].c_str(), '/')) {
				try_ip_mask(filter->lv_bothaddr[i], filter->lv_bothmask[i], ip[i]);
			} else {
				filter->lv_bothmask[i] = ~0;
			}
		}
	}
	string filter_port = jsonParameters.getValue("filter_port");
	if(filter_port.length()) {
		vector<string> port = split(filter_port.c_str(), split(",|;| ", "|"), true);
		for(unsigned i = 0; i < port.size() && i < MAXLIVEFILTERS; i++) {
			filter->lv_bothport[i] = ntohs(atoi(port[i].c_str()));
		}
	}
	string filter_number = jsonParameters.getValue("filter_number");
	if(filter_number.length()) {
		vector<string> number = split(filter_number.c_str(), split(",|;| ", "|"), true);
		for(unsigned i = 0; i < number.size() && i < MAXLIVEFILTERS; i++) {
			strcpy_null_term(filter->lv_bothnum[i], number[i].c_str());
		}
	}
	string filter_vlan = jsonParameters.getValue("filter_vlan");
	if(filter_vlan.length()) {
		vector<string> vlan = split(filter_vlan.c_str(), split(",|;| ", "|"), true);
		for(unsigned i = 0; i < vlan.size() && i < MAXLIVEFILTERS; i++) {
			filter->lv_vlan[i] = atoi(vlan[i].c_str());
			filter->lv_vlan_set[i] = true;
		}
	}
	string filter_header_type = jsonParameters.getValue("filter_header_type");
	string filter_header = jsonParameters.getValue("filter_header");
	if(filter_header_type.length() && filter_header.length()) {
		vector<string> header_type = split(filter_header_type.c_str(), split(",|;| ", "|"), true);
		bool from = false;
		bool to = false;
		for(unsigned i = 0; i < header_type.size(); i++) {
			if(header_type[i] == "F") {
				from = true;
			} else if(header_type[i] == "T") {
				to = true;
			}
		}
		if(from || to) {
			vector<string> header = split(filter_header.c_str(), split(",|;| ", "|"), true);
			for(unsigned i = 0; i < header.size() && i < MAXLIVEFILTERS; i++) {
				if(from && to) {
					strcpy_null_term(filter->lv_bothhstr[i], header[i].c_str());
				} else if(from) {
					strcpy_null_term(filter->lv_fromhstr[i], header[i].c_str());
				} else if(to) {
					strcpy_null_term(filter->lv_tohstr[i], header[i].c_str());
				}
			}
		}
	}
	string filter_sip_type = jsonParameters.getValue("filter_sip_type");
	if(filter_sip_type.length()) {
		vector<string> sip_type = split(filter_sip_type.c_str(), split(",|;| ", "|"), true);
		for(unsigned i = 0, j = 0; i < sip_type.size(); i++) {
			int sip_type_i = sip_type[i] == "I" ? INVITE :
				sip_type[i] == "R" ? REGISTER :
				sip_type[i] == "O" ? OPTIONS :
				sip_type[i] == "S" ? SUBSCRIBE :
				sip_type[i] == "M" ? MESSAGE :
				sip_type[i] == "N" ? NOTIFY :
				0;
			if(sip_type_i) {
				filter->lv_siptypes[j++] = sip_type_i;
			}
		}
	}
	updateLivesnifferfilters();
	global_livesniffer = 1;
	__sync_lock_release(&usersniffer_sync);
	return(0);
}

int Mgmt_livefilter(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("livefilter", "set live filter. Syntax livefilter set PARAMS");
		return(0);
	}

	char search[1024] = "";
	char value[1024] = "";
	u_int32_t uid = 0;
	sscanf(params->buf, "livefilter set %u %s %[^\n\r]", &uid, search, value);
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
			filter = new FILE_LINE(13009) livesnifferfilter_t;
			memset(CAST_OBJ_TO_VOID(filter), 0, sizeof(livesnifferfilter_t));
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
		filter = new FILE_LINE(13010) livesnifferfilter_t;
		memset(CAST_OBJ_TO_VOID(filter), 0, sizeof(livesnifferfilter_t));
		usersniffer[uid] = filter;
	}

	if(strstr(search, "srcaddr")) {
		int i = 0;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_saddr[i] = 0;
			filter->lv_smask[i] = ~0;
		}
		stringstream  data(value);
		string val;
		// read all argumens lkivefilter set saddr 123 345 244
		i = 0;
		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			//convert doted ip to unsigned int
			filter->lv_saddr[i] = ntohl((unsigned int)inet_addr(val.c_str()));

			// bad ip (signed -1) -> try prefix
			if ((int)filter->lv_saddr[i] == -1 && strchr(val.c_str(), '/'))
				try_ip_mask(filter->lv_saddr[i], filter->lv_smask[i], val);

			i++;
		}
		updateLivesnifferfilters();
	} else if(strstr(search, "dstaddr")) {
		int i = 0;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_daddr[i] = 0;
			filter->lv_dmask[i] = ~0;
		}
		stringstream  data(value);
		string val;
		i = 0;
		// read all argumens livefilter set daddr 123 345 244
		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			//convert doted ip to unsigned int
			filter->lv_daddr[i] = ntohl((unsigned int)inet_addr(val.c_str()));

			// bad ip (signed -1) -> try prefix
			if ((int)filter->lv_daddr[i] == -1 && strchr(val.c_str(), '/'))
				try_ip_mask(filter->lv_daddr[i], filter->lv_dmask[i], val);

			i++;
		}
		updateLivesnifferfilters();
	} else if(strstr(search, "bothaddr")) {
		int i = 0;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_bothaddr[i] = 0;
			filter->lv_bothmask[i] = ~0;
		}
		stringstream  data(value);
		string val;
		i = 0;
		// read all argumens livefilter set bothaddr 123 345 244
		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			//convert doted ip to unsigned int
			filter->lv_bothaddr[i] = ntohl((unsigned int)inet_addr(val.c_str()));

			// bad ip (signed -1) -> try prefix
			if ((int)filter->lv_bothaddr[i] == -1 && strchr(val.c_str(), '/'))
				try_ip_mask(filter->lv_bothaddr[i], filter->lv_bothmask[i], val);

			i++;
		}
		updateLivesnifferfilters();
	} else if(strstr(search, "bothport")) {
		int i;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_bothport[i] = 0;
		}
		stringstream  data(value);
		string val;
		i = 0;

		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			filter->lv_bothport[i] = ntohs(atoi(val.c_str()));
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
	} else if(strstr(search, "fromhstr")) {
		int i = 0;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_fromhstr[i][0] = '\0';
		}
		stringstream  data(value);
		string val;
		i = 0;
		// read all argumens livefilter set fromhstr 123 345 244
		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			stringstream tmp;
			tmp << val;
			tmp >> filter->lv_fromhstr[i];
			//cout << filter->lv_fromhstr[i] << "\n";
			i++;
		}
		updateLivesnifferfilters();
	} else if(strstr(search, "tohstr")) {
		int i = 0;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_tohstr[i][0] = '\0';
		}
		stringstream  data(value);
		string val;
		i = 0;
		// read all argumens livefilter set tohstr 123 345 244
		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			stringstream tmp;
			tmp << val;
			tmp >> filter->lv_tohstr[i];
			//cout << filter->lv_tohstr[i] << "\n";
			i++;
		}
		updateLivesnifferfilters();
	} else if(strstr(search, "bothhstr")) {
		int i = 0;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_bothhstr[i][0] = '\0';
		}
		stringstream  data(value);
		string val;
		i = 0;
		// read all argumens livefilter set bothhstr 123 345 244
		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			stringstream tmp;
			tmp << val;
			tmp >> filter->lv_bothhstr[i];
			//cout << filter->lv_bothhstr[i] << "\n";
			i++;
		}
		updateLivesnifferfilters();
	} else if(strstr(search, "vlan")) {
		int i = 0;
		//reset filters
		for(i = 0; i < MAXLIVEFILTERS; i++) {
			filter->lv_vlan[i] = 0;
			filter->lv_vlan_set[i] = false;
		}
		stringstream  data(value);
		string val;
		i = 0;
		// read all argumens livefilter set bothhstr 123 345 244
		while(i < MAXLIVEFILTERS and getline(data, val,' ')){
			global_livesniffer = 1;
			filter->lv_vlan[i] = atoi(val.c_str());
			filter->lv_vlan_set[i] = true;
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
	return(params->sendString("ok"));
}

int Mgmt_listen_stop(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("listen_stop", "stop listen");
		return(0);
	}

	if(!calltable) {
		return(-1);
	}
	long long callreference = 0;
	char listen_id[20] = "";
	string error;
	sscanf(params->buf, "listen_stop %llu %s", &callreference, listen_id);
	if(!callreference) {
		listen_id[0] = 0;
		sscanf(params->buf, "listen_stop %llx %s", &callreference, listen_id);
	}
	listening_master_lock();
	c_listening_clients::s_client *l_client = listening_clients.get(listen_id, (Call*)callreference);
	if(l_client) {
		listening_clients.remove(l_client);
	}
	c_listening_workers::s_worker *l_worker = listening_workers.get((Call*)callreference);
	if(l_worker && !listening_clients.exists(l_worker->call)) {
		listening_workers.stop(l_worker);
		while(l_worker->running) {
			usleep(100);
		}
		listening_workers.remove(l_worker);
	}
	listening_master_unlock();
	return(0);
}

int Mgmt_listen(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("listen", "start listen");
		return(0);
	}

	if(!calltable) {
		return(-1);
	}
	int rslt = 0;
	string error;
	extern int opt_liveaudio;
	if(opt_liveaudio) {
		long long callreference = 0;
		char listen_id[20] = "";
		sscanf(params->buf, "listen %llu %s", &callreference, listen_id);
		if(!callreference) {
			listen_id[0] = 0;
			sscanf(params->buf, "listen %llx %s", &callreference, listen_id);
		}
		listening_master_lock();
		Call *call = calltable->find_by_reference(callreference, false);
		if(call) {
			bool newWorker = false;
			string rslt_str = "success";
			c_listening_workers::s_worker *l_worker = listening_workers.get(call);
			if(l_worker) {
				rslt_str = "call already listening";
			} else {
				l_worker = listening_workers.add(call);
				listening_workers.run(l_worker);
				newWorker = true;
			}
			c_listening_clients::s_client *l_client = listening_clients.add(listen_id, call);
			if(!newWorker) {
				l_client->spybuffer_start_pos = l_worker->spybuffer->size_all_with_freed_pos();
			}
			if(params->sendString(&rslt_str) == -1) {
				rslt = -1;
			}
		} else {
			error = "call not found";
		}
		listening_master_unlock();
	} else {
		error = "liveaudio is disabled";
	}
	if(!error.empty()) {
		if(params->sendString(&error) == -1) {
			rslt = -1;
		}
	}
	return(rslt);
}

int Mgmt_readaudio(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("readaudio", "start read audio");
		return(0);
	}

	if(!calltable) {
		return(-1);
	}
	long long callreference = 0;
	char listen_id[20] = "";
	string error;
	string information;
	int rslt = 0;
	sscanf(params->buf, "readaudio %llu %s", &callreference, listen_id);
	if(!callreference) {
		listen_id[0] = 0;
		sscanf(params->buf, "readaudio %llx %s", &callreference, listen_id);
	}
	listening_master_lock();
	Call *call = calltable->find_by_reference(callreference, false);
	if(call) {
		c_listening_workers::s_worker *l_worker = listening_workers.get(call);
		if(l_worker) {
			c_listening_clients::s_client *l_client = listening_clients.get(listen_id, call);
			if(l_client) {
				u_int32_t bsize = 0;
				u_int32_t from_pos = max(l_client->spybuffer_start_pos, l_client->spybuffer_last_send_pos);
				//cout << "pos: " << from_pos << " / " << l_worker->spybuffer->size_all_with_freed_pos() << endl;
				l_worker->spybuffer->lock_master();
				u_char *buff = l_worker->spybuffer->get_from_pos(&bsize, from_pos);
				if(buff) {
					//cout << "bsize: " << bsize << endl;
					l_client->spybuffer_last_send_pos = from_pos + bsize;
					u_int64_t min_use_spybuffer_sample = listening_clients.get_min_use_spybuffer_pos(l_client->call);
					if(min_use_spybuffer_sample) {
						l_worker->spybuffer->free_pos(min_use_spybuffer_sample);
					}
					l_worker->spybuffer->unlock_master();
					if(params->sendString((char*)buff, bsize) == -1) {
						rslt = -1;
					}
					delete [] buff;
				} else {
					l_worker->spybuffer->unlock_master();
					information = "wait for data";
				}
				l_client->last_activity_time = getTimeS();
			} else {
				error = "client of worker not found";
			}
		} else {
			error = "worker not found";
		}
	} else {
		error = "call not found";
	}
	listening_master_unlock();
	if(!error.empty() || !information.empty()) {
		string data = !error.empty() ?
			"error: " + error :
			"information: " + information;
		if(params->sendString(&data) == -1) {
			rslt = -1;
		}
	}
	return(rslt);
}

int Mgmt_reload(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("reload", "voipmonitor reload");
		return(0);
	}
	reload_capture_rules();
	return(params->sendString("reload ok"));
}

int Mgmt_crules_print(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("crules_print", "debug print of the capture rules");
		return(0);
	}
	ostringstream oss;
	oss << "IPfilter" << endl;
	IPfilter::dump2man(oss);
	oss << "TELNUMfilter" << endl;
	TELNUMfilter::dump2man(oss, NULL);
	oss << "DOMAINfilter" << endl;
	DOMAINfilter::dump2man(oss);
	oss << "SIP_HEADERfilter" << endl;
	SIP_HEADERfilter::dump2man(oss);
	string txt = oss.str();
	return(params->sendString(&txt));
}

int Mgmt_hot_restart(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("hot_restart", "do hot restart");
		return(0);
	}
	hot_restart();
	return(params->sendString("hot restart ok"));
}

int Mgmt_get_json_config(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("get_json_config", "export JSON config");
		return(0);
	}
	string rslt = useNewCONFIG ? CONFIG.getJson() : "not supported";
	return(params->sendString(&rslt));
}

int Mgmt_set_json_config(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("set_json_config", "set JSON config");
		return(0);
	}
	string rslt;
	if(useNewCONFIG) {
		hot_restart_with_json_config(params->buf + 16);
		rslt = "ok";
	} else {
		rslt = "not supported";
	}
	return(params->sendString(&rslt));
}

int Mgmt_fraud_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("fraud_refresh", "refresh fraud");
		return(0);
	}
	refreshFraud();
	return(params->sendString("reload ok"));
}

int Mgmt_send_call_info_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("send_call_info_refresh", "send call info refresh");
		return(0);
	}
	refreshSendCallInfo();
	return(params->sendString("reload ok"));
}

int Mgmt_options_qualify_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("options_qualify_refresh", "refresh options qualify");
		return(0);
	}
	extern cSipMsgRelations *sipMsgRelations;
	sipMsgRelations->loadParamsInBackground();
	return(params->sendString("reload ok"));
}

int Mgmt_custom_headers_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("custom_headers_refresh", "refresh custom headers");
		return(0);
	}
	extern CustomHeaders *custom_headers_cdr;
	extern CustomHeaders *custom_headers_message;
	extern NoHashMessageRules *no_hash_message_rules;
	if(custom_headers_cdr) {
		custom_headers_cdr->refresh();
	}
	if(custom_headers_message) {
		custom_headers_message->refresh();
	}
	if(no_hash_message_rules) {
		no_hash_message_rules->refresh();
	}
	return(params->sendString("reload ok"));
}

int Mgmt_no_hash_message_rules_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("no_hash_message_rules_refresh", "refresh no hash message rules");
		return(0);
	}
	extern NoHashMessageRules *no_hash_message_rules;
	if(no_hash_message_rules) {
		no_hash_message_rules->refresh();
	}
	return(params->sendString("reload ok"));
}

int Mgmt_billing_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("billing_refresh", "refresh billing");
		return(0);
	}
	refreshBilling();
	return(params->sendString("reload ok"));
}

int Mgmt_country_detect_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("country_detect_refresh", "refresh country detect");
		return(0);
	}
	refreshBilling();
	CountryDetectPrepareReload();
	return(params->sendString("reload ok"));
}

int Mgmt_getfile_is_zip_support(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getfile_is_zip_support", "check getfile zip support");
		return(0);
	}
	return(params->sendString("OK"));
}

int Mgmt_getfile_in_tar_check_complete(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getfile_in_tar_check_complete", "getfile in tar check complete");
		return(0);
	}
	char tar_filename[2048];
	char filename[2048];
	char dateTimeKey[2048];

	sscanf(params->buf, "getfile_in_tar_check_complete %s %s %s", tar_filename, filename, dateTimeKey);

	const char *rslt = getfile_in_tar_completed.check(tar_filename, filename, dateTimeKey) ? "OK" : "uncomplete";

	return(params->sendString(rslt));
}

int Mgmt_getfile_in_tar(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		commandAndHelp ch[] = {
			{"getfile_in_tar", "get file(s) in tar"},
			{"getfile_in_tar_zip", "get file(s) in zipped tar"},
			{NULL, NULL}
		};
		params->registerCommand(ch);
		return(0);
	}

	bool zip = strstr(params->buf, "getfile_in_tar_zip");

	char tar_filename[2048];
	char filename[2048];
	char dateTimeKey[2048];
	u_int32_t recordId = 0;
	char tableType[100] = "";
	char *tarPosI = new FILE_LINE(13011) char[1000000];
	unsigned spool_index = 0;
	int type_spool_file = (int)tsf_na;
	*tarPosI = 0;
	char buf_output[1024];

	sscanf(params->buf, zip ? "getfile_in_tar_zip %s %s %s %u %s %s %u %i" : "getfile_in_tar %s %s %s %u %s %s %u %i", tar_filename, filename, dateTimeKey, &recordId, tableType, tarPosI, &spool_index, &type_spool_file);
	if(type_spool_file == tsf_na) {
		type_spool_file = findTypeSpoolFile(spool_index, tar_filename);
	}

	Tar tar;
	if(!tar.tar_open(string(getSpoolDir((eTypeSpoolFile)type_spool_file, spool_index)) + '/' + tar_filename, O_RDONLY)) {
		string filename_conv = filename;
		prepare_string_to_filename((char*)filename_conv.c_str());
		tar.tar_read_send_parameters(params->client, params->sshchannel, params->c_client, zip);
		tar.tar_read((filename_conv + ".*").c_str(), filename, recordId, tableType, tarPosI);
		if(tar.isReadEnd()) {
			getfile_in_tar_completed.add(tar_filename, filename, dateTimeKey);
		}
	} else {
		snprintf(buf_output, sizeof(buf_output), "error: cannot open file [%s]", tar_filename);
		params->sendString(buf_output);
		delete [] tarPosI;
		return -1;
	}
	delete [] tarPosI;
	return 0;
}

int Mgmt_getfile(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		commandAndHelp ch[] = {
			{"getfile", "get file"},
			{"getfile_zip", "get zipped file"},
			{NULL, NULL}
		};
		params->registerCommand(ch);
		return(0);
	}
	params->zip = strstr(params->buf, "getfile_zip");

	char filename[2048];
	unsigned spool_index = 0;
	int type_spool_file = (int)tsf_na;

	sscanf(params->buf, params->zip ? "getfile_zip %s %u %i" : "getfile %s %u %i", filename, &spool_index, &type_spool_file);
	if(type_spool_file == tsf_na) {
		type_spool_file = findTypeSpoolFile(spool_index, filename);
	}
	return(params->sendFile((string(getSpoolDir((eTypeSpoolFile)type_spool_file, spool_index)) + '/' + filename).c_str()));
}

int Mgmt_file_exists(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("file_exists", "file exists");
		return(0);
	}

	if(is_sender()) {
		return(params->sendString("mirror"));
	}

	char filename[2048];
	unsigned spool_index = 0;
	int type_spool_file = (int)tsf_na;
	u_int64_t size;
	string rslt;

	sscanf(params->buf, "file_exists %s %u %i", filename, &spool_index, &type_spool_file);
	if(type_spool_file == tsf_na) {
		type_spool_file = findTypeSpoolFile(spool_index, filename);
	}

	int error_code;
	if(file_exists(string(getSpoolDir((eTypeSpoolFile)type_spool_file, spool_index)) + '/' + filename, &error_code)) {
		size = file_size(string(getSpoolDir((eTypeSpoolFile)type_spool_file, spool_index)) + '/' + filename);
		rslt = intToString(size);
		if(size > 0 && strstr(filename, "tar")) {
			for(int i = 1; i <= 5; i++) {
				string nextfilename = filename;
				nextfilename += "." + intToString(i);
				u_int64_t nextsize = file_size(string(getSpoolDir((eTypeSpoolFile)type_spool_file, spool_index)) + '/' + nextfilename);
				if(nextsize > 0) {
					rslt += ";" + nextfilename + ":" + intToString(nextsize);
				} else {
					break;
				}
			}
		}
	} else {
		rslt = error_code == EACCES ? "permission_denied" : "not_exists";
	}
	return(params->sendString(&rslt));
}

int Mgmt_fileexists(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("fileexists", "file exists 2");
		return(0);
	}
	char filename[2048];
	unsigned int size;
	char buf_output[1024];

	sscanf(params->buf, "fileexists %s", filename);
	size = file_size(filename);
	snprintf(buf_output, sizeof(buf_output), "%d", size);
	return(params->sendString(buf_output));
}

int Mgmt_flush_tar(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("flush_tar", "flush_tar");
		return(0);
	}
	char filename[2048];
	sscanf(params->buf, "flush_tar %s", filename);
	flushTar(filename);
	return(params->sendString("OK"));
}

int Mgmt_genwav(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("genwav", "generates wav");
		return(0);
	}

	char filename[2048];
	unsigned int size;
	char wavfile[2048];
	char pcapfile[2048];
	char cmd[4092];
	int secondrun = 0;
	char buf_output[1024];

	sscanf(params->buf, "genwav %s", filename);

	snprintf(pcapfile, sizeof(pcapfile), "%s.pcap", filename);
	snprintf(wavfile, sizeof(wavfile), "%s.wav", filename);

getwav2:
	size = file_size(wavfile);
	if(size) {
		snprintf(buf_output, sizeof(buf_output), "%d", size);
		params->sendString(buf_output);
		return 0;
	}
	if(secondrun > 0) {
		// wav does not exist
		params->sendString("0");
		return -1;
	}

	// wav does not exists, check if exists pcap and try to create wav
	size = file_size(pcapfile);
	if(!size) {
		params->sendString("0");
		return -1;
	}
	snprintf(cmd, sizeof(cmd), "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin voipmonitor --rtp-firstleg -k -WRc -r \"%s.pcap\" -y -d %s 2>/dev/null >/dev/null", filename, getSpoolDir(tsf_main, 0));
	system(cmd);
	secondrun = 1;
	goto getwav2;
}

int Mgmt_getwav(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getwav", "gets wav");
		return(0);
	}

	char filename[2048];
	int fd;
	unsigned int size;
	char wavfile[2048];
	char pcapfile[2048];
	char cmd[4092];
	char rbuf[4096];
	ssize_t nread;
	int secondrun = 0;
	char buf_output[1024];

	sscanf(params->buf, "getwav %s", filename);

	snprintf(pcapfile, sizeof(pcapfile), "%s.pcap", filename);
	snprintf(wavfile, sizeof(wavfile), "%s.wav", filename);

getwav:
	size = file_size(wavfile);
	if(size) {
		fd = open(wavfile, O_RDONLY);
		if(fd < 0) {
			snprintf(buf_output, sizeof(buf_output), "error: cannot open file [%s]", wavfile);
			params->sendString(buf_output);
			return -1;
		}
		while(nread = read(fd, rbuf, sizeof rbuf), nread > 0) {
			if (params->sendString(rbuf, nread) == -1){
				close(fd);
				return -1;
			}
		}
		if(true /*eof*/) { // obsolete parameter eof
			if (params->sendString("EOF") == -1){
				close(fd);
				return -1;
			}
		}
		close(fd);
		return 0;
	}
	if(secondrun > 0) {
		// wav does not exist
		params->sendString("0");
		return -1;
	}

	// wav does not exists, check if exists pcap and try to create wav
	size = file_size(pcapfile);
	if(!size) {
		params->sendString("0");
		return -1;
	}
	snprintf(cmd, sizeof(cmd), "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/bin voipmonitor --rtp-firstleg -k -WRc -r \"%s.pcap\" -y 2>/dev/null >/dev/null", filename);
	system(cmd);
	secondrun = 1;
	goto getwav;
}

int Mgmt_getsiptshark(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("getsiptshark", "get sip tshark");
		return(0);
	}

	char filename[2048];
	int fd;
	unsigned int size;
	char tsharkfile[2048];
	char pcapfile[2048];
	char cmd[4092];
	char rbuf[4096];
	ssize_t nread;
	char buf_output[1024];

	sscanf(params->buf, "getsiptshark %s", filename);

	snprintf(tsharkfile, sizeof(tsharkfile), "%s.pcap2txt", filename);
	snprintf(pcapfile, sizeof(pcapfile), "%s.pcap", filename);

	size = file_size(tsharkfile);
	if(size) {
		fd = open(tsharkfile, O_RDONLY);
		if(fd < 0) {
			snprintf(buf_output, sizeof(buf_output), "error: cannot open file [%s]", tsharkfile);
			params->sendString(buf_output);
			return -1;
		}
		while(nread = read(fd, rbuf, sizeof rbuf), nread > 0) {
			if (params->sendString(rbuf, nread) == -1){
				close(fd);
				return -1;
			}
		}
		if(true /*eof*/) { // obsolete parameter eof
			if (params->sendString("EOF") == -1){
				close(fd);
				return -1;
			}
		}
		close(fd);
		return 0;
	}

	size = file_size(pcapfile);
	if(!size) {
		params->sendString("0");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin tshark -r \"%s.pcap\" -R sip > \"%s.pcap2txt\" 2>/dev/null", filename, filename);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "echo ==== >> \"%s.pcap2txt\"", filename);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin tshark -r \"%s.pcap\" -V -R sip >> \"%s.pcap2txt\" 2>/dev/null", filename, filename);
	system(cmd);

	size = file_size(tsharkfile);
	if(size) {
		fd = open(tsharkfile, O_RDONLY);
		if(fd < 0) {
			snprintf(buf_output, sizeof(buf_output), "error: cannot open file [%s]", filename);
			params->sendString(buf_output);
			return -1;
		}
		while(nread = read(fd, rbuf, sizeof rbuf), nread > 0) {
			if (params->sendString(rbuf, nread) == -1){
				close(fd);
				return -1;
			}
		}
		if(true /*eof*/) { // obsolete parameter eof
			if (params->sendString("EOF") == -1){
				close(fd);
				return -1;
			}
		}
		close(fd);
	}
	return(0);
}

int Mgmt_genhttppcap(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("genhttppcap", "get http pcap");
		return(0);
	}

	char timestamp_from[100];
	char timestamp_to[100];
	char *ids = new FILE_LINE(13012) char [1000000];
	sscanf(params->buf, "genhttppcap %19[T0-9--: ] %19[T0-9--: ] %s", timestamp_from, timestamp_to, ids);
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

	delete [] ids;

	if(!dumper.getPcapName().empty() && file_exists(dumper.getPcapName()) > 0) {
		return(params->sendFile(dumper.getPcapName().c_str()));
	} else {
		params->sendString("null");
		return(0);
	}
}

int Mgmt_quit(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("quit", "quit");
		return(0);
	}
	return(0);
}

int Mgmt_terminating(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("terminating", "terminates sensor");
		return(0);
	}
	vm_terminate();
	return(0);
}

int Mgmt_coutstr(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("coutstr", "echo string to the standart output");
		return(0);
	}
	char *pointToSpaceSeparator = strchr(params->buf, ' ');
	if(pointToSpaceSeparator) {
		cout << (pointToSpaceSeparator + 1) << flush;
	}
	return(0);
}

int Mgmt_syslogstr(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("syslogstr", "sends string to the syslog");
		return(0);
	}
	char *pointToSpaceSeparator = strchr(params->buf, ' ');
	if(pointToSpaceSeparator) {
		syslog(LOG_NOTICE, "%s", pointToSpaceSeparator + 1);
	}
	return(0);
}

int Mgmt_custipcache_get_cust_id(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("custipcache_get_cust_id", "custipcache_get_cust_id");
		return(0);
	}
	char ip[20];
	sscanf(params->buf, "custipcache_get_cust_id %s", ip);
	CustIpCache *custIpCache = getCustIpCache();
	if(custIpCache) {
		unsigned int cust_id = custIpCache->getCustByIp(inet_addr(ip));
		char sendbuf[BUFSIZE];
		snprintf(sendbuf, BUFSIZE, "cust_id: %u\n", cust_id);
		return(params->sendString(sendbuf));
	}
	return(0);
}

int Mgmt_custipcache_refresh(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("custipcache_refresh", "custipcache_refresh");
		return(0);
	}
	char sendbuf[BUFSIZE];
	int rslt = refreshCustIpCache();
	snprintf(sendbuf, BUFSIZE, "rslt: %i\n", rslt);
	return(params->sendString(sendbuf));
}

int Mgmt_custipcache_vect_print(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("custipcache_vect_print", "custipcache_vect_print");
		return(0);
	}
	CustIpCache *custIpCache = getCustIpCache();
	if(custIpCache) {
		string rslt = custIpCache->printVect();
		return(params->sendString(&rslt));
	}
	return(0);
}

int Mgmt_upgrade_restart(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		commandAndHelp ch[] = {
			{"upgrade", "upgrades senso"},
			{"restart", "restarts sensor"},
			{NULL, NULL}
		};
		params->registerCommand(ch);
		return(0);
	}

	bool upgrade = false;
	string version;
	string url;
	string md5_32;
	string md5_64;
	string md5_arm;
	string md5_64_ws;
	string rsltForSend;

	if(strstr(params->buf, "upgrade") != NULL) {
		extern void dns_lookup_common_hostnames();
		dns_lookup_common_hostnames();

		extern bool opt_upgrade_by_git;
		if(opt_upgrade_by_git) {
			rsltForSend = "upgrade from official binary source disabled - upgrade by git!";
		} else {
			upgrade = true;
			string command = params->buf;
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
					for(int i = 0; i < 3; i++) {
						pos = command.find(" / [", pos);
						if(pos != string::npos) {
							size_t posEnd = command.find("]", pos);
							if(posEnd != string::npos) {
								string md5 = command.substr(pos + 4, posEnd - pos - 4);
								switch(i) {
									case 0: md5_64 = md5; break;
									case 1: md5_arm = md5; break;
									case 2: md5_64_ws = md5; break;
								}
								pos = posEnd;
							} else {
								break;
							}
						} else {
							break;
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
	RestartUpgrade restart(upgrade, version.c_str(), url.c_str(), md5_32.c_str(), md5_64.c_str(), md5_arm.c_str(), md5_64_ws.c_str());
	if(!rsltForSend.length()) {
		if(restart.createRestartScript() && restart.createSafeRunScript()) {
			if((!upgrade || restart.runUpgrade()) &&
					restart.checkReadyRestart() &&
					restart.isOk()) {
				ok = true;
			}
		}
		rsltForSend = restart.getRsltString();
	}
	if (params->sendString(&rsltForSend) == -1){
		return -1;
	}
	if(ok) {
		restart.runRestart(params->client, manager_socket_server, params->c_client);
	}
	return 0;
}

int Mgmt_gitUpgrade(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("gitUpgrade", "do upgrade from git");
		return(0);
	}
	char cmd[100];
	sscanf(params->buf, "gitUpgrade %s", cmd);
	RestartUpgrade upgrade;
	bool rslt = upgrade.runGitUpgrade(cmd);
	string rsltString;
	if(rslt) {
		rsltString = "OK";
	} else {
		rsltString = upgrade.getErrorString();
	}
	rsltString.append("\n");
	return(params->sendString(&rsltString));
}

int Mgmt_sniffer_stat(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("sniffer_stat", "return sniffer's statistics");
		return(0);
	}

	extern vm_atomic<string> storingCdrLastWriteAt;
	extern vm_atomic<string> storingRegisterLastWriteAt;
	extern vm_atomic<string> pbStatString;
	extern vm_atomic<u_long> pbCountPacketDrop;
	extern bool opt_upgrade_by_git;
	extern bool packetbuffer_memory_is_full;
	extern vm_atomic<string> terminating_error;
	ostringstream outStrStat;
	extern int vm_rrd_version;
	checkRrdVersion(true);
	while(__sync_lock_test_and_set(&usersniffer_sync, 1));
	size_t countLiveSniffers = usersniffer.size();
	__sync_lock_release(&usersniffer_sync);
	outStrStat << "{";
	outStrStat << "\"version\": \"" << RTPSENSOR_VERSION << "\",";
	outStrStat << "\"rrd_version\": \"" << vm_rrd_version << "\",";
	outStrStat << "\"storingCdrLastWriteAt\": \"" << storingCdrLastWriteAt << "\",";
	outStrStat << "\"pbStatString\": \"" << pbStatString << "\",";
	outStrStat << "\"pbCountPacketDrop\": \"" << pbCountPacketDrop << "\",";
	outStrStat << "\"uptime\": \"" << getUptime() << "\",";
	outStrStat << "\"memory_is_full\": \"" << packetbuffer_memory_is_full << "\",";
	outStrStat << "\"count_live_sniffers\": \"" << countLiveSniffers << "\",";
	outStrStat << "\"upgrade_by_git\": \"" << opt_upgrade_by_git << "\",";
	outStrStat << "\"use_new_config\": \"" << useNewCONFIG << "\",";
	outStrStat << "\"terminating_error\": \"" << terminating_error << "\"";
	outStrStat << "}";
	outStrStat << endl;
	string outStrStatStr = outStrStat.str();
	return(params->sendString(&outStrStatStr));
}

int Mgmt_sniffer_threads(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("sniffer_threads", "return sniffer's thread statistics");
		return(0);
	}
	extern cThreadMonitor threadMonitor;
	string threads = threadMonitor.output();
	return(params->sendString(&threads));
}

int Mgmt_pcapstat(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("pcapstat", "return pcap's statistics");
		return(0);
	}
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
	return(params->sendString(&rslt));
}

int Mgmt_login_screen_popup(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("login_screen_popup", "login_screen_popup");
		return(0);
	}
	*params->managerClientThread =  new FILE_LINE(13013) ManagerClientThread_screen_popup(params->client, params->buf);
	return(0);
}

int Mgmt_ac_add_thread(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("ac_add_thread", "ac_add_thread");
		return(0);
	}
	extern AsyncClose *asyncClose;
	asyncClose->addThread();
	return(params->sendString("ok\n"));
}

int Mgmt_ac_remove_thread(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("ac_remove_thread", "ac_remove_thread");
		return(0);
	}
	extern AsyncClose *asyncClose;
	asyncClose->removeThread();
	return(params->sendString("ok\n"));
}

int Mgmt_t2sip_add_thread(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("t2sip_add_thread", "t2sip_add_thread");
		return(0);
	}
	PreProcessPacket::autoStartNextLevelPreProcessPacket();
	return(params->sendString("ok\n"));
}

int Mgmt_t2sip_remove_thread(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("t2sip_remove_thread", "t2sip_remove_thread");
		return(0);
	}
	PreProcessPacket::autoStopLastLevelPreProcessPacket(true);
	return(params->sendString("ok\n"));
}

int Mgmt_rtpread_add_thread(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("rtpread_add_thread", "rtpread_add_thread");
		return(0);
	}
	add_rtp_read_thread();
	return(params->sendString("ok\n"));
}

int Mgmt_rtpread_remove_thread(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("rtpread_remove_thread", "rtpread_remove_thread");
		return(0);
	}
	set_remove_rtp_read_thread();
	return(params->sendString("ok\n"));
}

int Mgmt_enable_bad_packet_order_warning(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("enable_bad_packet_order_warning", "enable_bad_packet_order_warning");
		return(0);
	}
	enable_bad_packet_order_warning = 1;
	return(params->sendString("ok\n"));
}

int Mgmt_sipports(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("sipports", "return list of used sip ports");
		return(0);
	}
	ostringstream outStrSipPorts;
	extern char *sipportmatrix;
	for(int i = 0; i < 65537; i++) {
		if(sipportmatrix[i]) {
			outStrSipPorts << i << ',';
		}
	}
	outStrSipPorts << endl;
	string strSipPorts = outStrSipPorts.str();
	return(params->sendString(&strSipPorts));
}

int Mgmt_skinnyports(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("skinnyports", "return list of used skinny ports");
		return(0);
	}

	ostringstream outStrSkinnyPorts;
	extern char *skinnyportmatrix;
	extern int opt_skinny;
	if (opt_skinny) {
		for(int i = 0; i < 65537; i++) {
			if(skinnyportmatrix[i]) {
				outStrSkinnyPorts << i << ',';
			}
		}
	}
	outStrSkinnyPorts << endl;
	string strSkinnyPorts = outStrSkinnyPorts.str();
	return(params->sendString(&strSkinnyPorts));
}

int Mgmt_ignore_rtcp_jitter(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("ignore_rtcp_jitter", "return ignore rtcp jitter value");
		return(0);
	}
	extern unsigned int opt_ignoreRTCPjitter;
	ostringstream outStrIgnoreJitter;
	outStrIgnoreJitter << opt_ignoreRTCPjitter << endl;
	string ignoreJitterVal = outStrIgnoreJitter.str();
	return(params->sendString(&ignoreJitterVal));
}

int Mgmt_convertchars(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("convertchars", "convertchars");
		return(0);
	}
	ostringstream outStrConvertchar;
	extern char opt_convert_char[64];
	for(unsigned int i = 0; i < sizeof(opt_convert_char) && opt_convert_char[i]; i++) {
		outStrConvertchar << opt_convert_char[i] << ',';
	}
	outStrConvertchar << endl;
	string strConvertchar = outStrConvertchar.str();
	return(params->sendString(&strConvertchar));
}

int Mgmt_natalias(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("natalias", "natalias");
		return(0);
	}
	extern nat_aliases_t nat_aliases;
	string strNatAliases;
	if(nat_aliases.size()) {
		ostringstream outStrNatAliases;
		for(nat_aliases_t::iterator iter = nat_aliases.begin(); iter != nat_aliases.end(); iter++) {
			outStrNatAliases << inet_ntostring(htonl(iter->first)) << ':' << inet_ntostring(htonl(iter->second)) << ',';
		}
		strNatAliases = outStrNatAliases.str();
	} else {
		strNatAliases = "none";
	}
	return(params->sendString(&strNatAliases));
}

int Mgmt_sql_time_information(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("sql_time_information", "sql_time_information");
		return(0);
	}

	string timezone_name = "UTC";
	long timezone_offset = 0;
	extern bool opt_sql_time_utc;
	char sendbuf[BUFSIZE];
	if(!opt_sql_time_utc && !isCloud()) {
		time_t t = time(NULL);
		struct tm lt;
		::localtime_r(&t, &lt);
		timezone_name = getSystemTimezone();
		if(timezone_name.empty()) {
			timezone_name = lt.tm_zone;
		}
		timezone_offset = lt.tm_gmtoff;
	}
	snprintf(sendbuf, BUFSIZE, "%s,%li,%s",
			timezone_name.c_str(),
			timezone_offset,
			sqlDateTimeString(time(NULL)).c_str());
	return(params->sendString(sendbuf));
}

int Mgmt_sqlexport(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		commandAndHelp ch[] = {
			{"sqlexport", "sqlexport"},
			{"sqlvmexport", "sqlvmexport"},
			{NULL, NULL}
		};
		params->registerCommand(ch);
		return(0);
	}
	bool sqlFormat = strstr(params->buf, "sqlexport") != NULL;
	extern MySqlStore *sqlStore;
	string rslt = sqlStore->exportToFile(NULL, "auto", sqlFormat, strstr(params->buf, "clean") != NULL);
	return(params->sendString(&rslt));
}

int Mgmt_memory_stat(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("memory_stat", "return a memory statistics");
		return(0);
	}
	string rsltMemoryStat = getMemoryStat();
	return(params->sendString(&rsltMemoryStat));
}

int Mgmt_list_active_clients(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("list_active_clients", "list of active clients");
		return(0);
	}
	extern sSnifferServerServices snifferServerServices;
	string rslt = snifferServerServices.listJsonServices();
	return(params->sendString(&rslt));
}

int Mgmt_jemalloc_stat(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("jemalloc_stat", "return jemalloc statistics");
		return(0);
	}
	string jeMallocStat(bool full);
	string rsltMemoryStat = jeMallocStat(strstr(params->buf, "full"));
	return(params->sendString(&rsltMemoryStat));
}

int Mgmt_cloud_activecheck(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("cloud_activecheck", "cloud_activecheck");
		return(0);
	}
	cloud_activecheck_success();
	return(0);
}

#ifndef FREEBSD
int Mgmt_malloc_trim(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("malloc_trim", "malloc_trim");
		return(0);
	}
	malloc_trim(0);
	return(0);
}
#endif

int Mgmt_memcrash_test(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		commandAndHelp ch[] = {
			{"memcrash_test_1", ""},
			{"memcrash_test_2", ""},
			{"memcrash_test_3", ""},
			{"memcrash_test_4", ""},
			{"memcrash_test_5", ""},
			{NULL, NULL}
		};
		params->registerCommand(ch);
		return(0);
	}

	if(strstr(params->buf, "memcrash_test_1") != NULL) {
		char *test = new FILE_LINE(13014) char[10];
		test[10] = 1;
	} else if(strstr(params->buf, "memcrash_test_2") != NULL) {
		char *test = new FILE_LINE(13015) char[10];
		delete [] test;
		delete [] test;
	} else if(strstr(params->buf, "memcrash_test_3") != NULL) {
		char *test = new FILE_LINE(13016) char[10];
		delete [] test;
		test[0] = 1;
	} else if(strstr(params->buf, "memcrash_test_4") != NULL) {
		char *test[10];
		for(int i = 0; i < 10; i++) {
			test[i] = new FILE_LINE(13017) char[10];
		}
		memset(test[4] + 10, 0, 40);
	} else if(strstr(params->buf, "memcrash_test_5") != NULL) {
		char *test = NULL;
		*test = 0;
	}
	return(0);
}

int Mgmt_set_pcap_stat_period(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("set_pcap_stat_period", "set_pcap_stat_period");
		return(0);
	}
	int new_pcap_stat_period = atoi(params->buf + 21);
	if(new_pcap_stat_period > 0 && new_pcap_stat_period < 600) {
		sverb.pcap_stat_period = new_pcap_stat_period;
	}
	return(0);
}

int Mgmt_setverbparam(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("setverbparam", "setverbparam");
		return(0);
	}

	extern void parse_verb_param(string verbParam);
	string verbparam = params->buf + 13;
	size_t posEndLine = verbparam.find("\n");
	if(posEndLine != string::npos) {
		verbparam.resize(posEndLine);
	}
	parse_verb_param(verbparam);
	return(0);
}

int Mgmt_unpausecall(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("unpausecall", "unpause call's processing");
		return(0);
	}

	long long callref = 0;
	sscanf(params->buf, "unpausecall 0x%llx", &callref);
	if (!callref) {
		return(params->sendString("Bad/missing Call id\n"));
	} else if (Handle_pause_call(callref, 0) == -1) {
		return(params->sendString("Call id not found\n"));
	}
	return(0);
}

int Mgmt_pausecall(Mgmt_params *params) {
	if (params->task == params->mgmt_task_DoInit) {
		params->registerCommand("pausecall", "pause call's processing");
		return(0);
	}

	long long callref = 0;
	sscanf(params->buf, "pausecall 0x%llx", &callref);
	if (!callref) {
		return(params->sendString("Bad/missing Call id\n"));
	} else if (Handle_pause_call(callref, 1) == -1) {
		return(params->sendString("Call id not found\n"));
	}
	return(0);
}

void init_management_functions(void) {
	int i;
	Mgmt_params params(NULL, 0, 0, NULL, NULL, NULL);
	params.task = params.mgmt_task_DoInit;

	for (i = 0;; i++) {
		params.index = i;
		if (!MgmtFuncArray[i])
			break;

		MgmtFuncArray[i](&params);
	}
}
