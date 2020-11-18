#ifndef SERVER_H
#define SERVER_H


#include <string.h>
#include <queue>
#include <list>

#include "cloud_router/cloud_router_base.h"


using namespace std;


struct sSnifferServerVerbose {
	sSnifferServerVerbose() {
		memset(this, 0, sizeof(*this));
		start_server = true;
		start_client = true;
		connect_command = true;
		connect_info = true;
	}
	bool start_server;
	bool start_client;
	bool socket_connect;
	bool connect_command;
	bool connect_info;
	bool connect_info_ext;
};


enum eServerClientTypeCompress {
	_cs_compress_na,
	_cs_compress_gzip,
	_cs_compress_lzo
};

struct sSnifferServerOptions {
	sSnifferServerOptions() {
		port = 60024;
		mysql_queue_limit = 0;
		mysql_redirect_queue_limit = 0;
		mysql_concat_limit = 1000;
		type_compress = _cs_compress_gzip;
	}
	bool isEnable() {
		return(!host.empty() && port);
	}
	string host;
	unsigned port;
	unsigned mysql_queue_limit;
	unsigned mysql_redirect_queue_limit;
	unsigned mysql_concat_limit;
	eServerClientTypeCompress type_compress;
};


struct sSnifferClientOptions {
	sSnifferClientOptions() {
		port = 60024;
		remote_query = true;
		remote_store = true;
		packetbuffer_sender = false;
		mysql_new_store = 0;
		mysql_set_id = false;
		mysql_concat_limit = 0; // set only from server due compatibility client/server with different versions
		csv_store_format = false;
		charts_cache_store = false;
		type_compress = _cs_compress_gzip;
		remote_chart_server = false;
	}
	bool isEnable() {
		return(!host.empty() && port);
	}
	bool isEnableRemoteQuery() {
		return(isEnable() && remote_query);
	}
	bool isEnableRemoteStore() {
		return(isEnable() && remote_store);
	}
	bool isEnablePacketBufferSender() {
		return(isEnable() && packetbuffer_sender);
	}
	bool isRemoteChartServer() {
		return(isEnable() && remote_chart_server);
	}
	bool isSetHostPort() {
		return(!host.empty() && port);
	}
	string host;
	unsigned port;
	bool remote_query;
	bool remote_store;
	bool packetbuffer_sender;
	int mysql_new_store;
	bool mysql_set_id;
	unsigned mysql_concat_limit;
	bool csv_store_format;
	bool charts_cache_store;
	bool remote_chart_server;
	eServerClientTypeCompress type_compress;
};


struct sSnifferServerClientOptions {
	string password;
};


struct sSnifferServerGuiTask {
	enum eTaskState {
		_na,
		_receive,
		_service,
		_result,
		_complete
	};
	sSnifferServerGuiTask() {
		state = _receive;
		sensor_id = 0;
		time_us = 0;
		gui_connection = NULL;
	}
	void setTimeId() {
		static volatile u_int64_t _id_counter;
		u_int64_t _id = ++_id_counter;
		if(!_id) {
			_id = ++_id_counter;
		}
		time_us = getTimeUS();
		id = intToString(time_us) + ":" + intToString(_id);
	}
	eTaskState state;
	int32_t sensor_id;
	string command;
	u_int64_t time_us;
	string id;
	class cSnifferServerConnection *gui_connection;
};


class sSnifferServerGuiTasks {
public:
	sSnifferServerGuiTasks();
	void add(sSnifferServerGuiTask *task);
	void remove(sSnifferServerGuiTask *task);
	void remove(string id);
	sSnifferServerGuiTask getTask(string id);
	class cSnifferServerConnection *getGuiConnection(string id);
	int32_t getSensorId(string id);
	sSnifferServerGuiTask::eTaskState getTaskState(string id);
	void setTaskState(string id, sSnifferServerGuiTask::eTaskState state);
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync_lock, 1)) {
			if(SYNC_LOCK_USLEEP) {
				USLEEP(SYNC_LOCK_USLEEP);
			}
		}
	}
	void unlock() {
		__sync_lock_release(&_sync_lock);
	}
public:
	map<string, sSnifferServerGuiTask> tasks;
	volatile int _sync_lock;
};


struct sSnifferServerService {
	sSnifferServerService() {
		connect_ip.clear();
		connect_port = 0;
		sensor_id = 0;
		service_connection = NULL;
		remote_chart_server = false;
	}
	vmIP connect_ip;
	u_int16_t connect_port;
	int32_t sensor_id;
	string sensor_string;
	class cSnifferServerConnection *service_connection;
	string aes_ckey;
	string aes_ivec;
	bool remote_chart_server;
};


class sSnifferServerServices {
public:
	sSnifferServerServices();
	void add(sSnifferServerService *service);
	void remove(sSnifferServerService *service);
	string getIdService(int32_t sensor_id, const char *sensor_string);
	bool existsService(int32_t sensor_id, const char *sensor_string);
	sSnifferServerService getService(int32_t sensor_id, const char *sensor_string);
	class cSnifferServerConnection *getServiceConnection(int32_t sensor_id, const char *sensor_string);
	bool getAesKeys(int32_t sensor_id, const char *sensor_string, string *ckey, string *ivec);
	string listJsonServices();
	bool add_rchs_query(const char *query, bool checkMaxSize);
	bool add_rchs_query(string *query, bool checkMaxSize);
	string *get_rchs_query();
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync_lock, 1)) {
			if(SYNC_LOCK_USLEEP) {
				USLEEP(SYNC_LOCK_USLEEP);
			}
		}
	}
	void unlock() {
		__sync_lock_release(&_sync_lock);
	}
	void lock_rchs() {
		while(__sync_lock_test_and_set(&_sync_rchs, 1)) {
			if(SYNC_LOCK_USLEEP) {
				USLEEP(SYNC_LOCK_USLEEP);
			}
		}
	}
	void unlock_rchs() {
		__sync_lock_release(&_sync_rchs);
	}
public:
	map<string, sSnifferServerService> services;
	volatile int _sync_lock;
	volatile int remote_chart_server;
	queue<string*> rchs_query_queue;
	unsigned rchs_query_queue_max_size; 
	volatile int _sync_rchs;
};


class cSnifferServer : public cServer {
public:
	cSnifferServer();
	~cSnifferServer();
	void setSqlStore(class MySqlStore *sqlStore);
	void sql_query_lock(const char *query_str, int id_main, int id_2);
	void sql_query_lock(list<string> *query_str, int id_main, int id_2);
	int findMinStoreId2(int id_main);
	unsigned int sql_queue_size(bool redirect);
	bool isSetSqlStore() {
		return(sqlStore != NULL);
	}
	virtual void createConnection(cSocket *socket);
	void registerConnectionThread(class cSnifferServerConnection *connectionThread);
	void unregisterConnectionThread(class cSnifferServerConnection *connectionThread);
	bool existConnectionThread();
	void terminateSocketInConnectionThreads();
	void cancelConnectionThreads();
	bool isTerminate() {
		return(terminate);
	}
	void lock_connection_threads() {
		while(__sync_lock_test_and_set(&connection_threads_sync, 1));
	}
	void unlock_connection_threads() {
		__sync_lock_release(&connection_threads_sync);
	}
private:
	MySqlStore *sqlStore;
	volatile bool terminate;
	map<class cSnifferServerConnection*, bool> connection_threads;
	volatile int connection_threads_sync;
	volatile size_t sql_queue_size_size[2];
	volatile u_int64_t sql_queue_size_time_ms[2];
};


class cSnifferServerConnection : public cServerConnection {
public:
	enum eTypeConnection {
		_tc_na,
		_tc_gui_command,
		_tc_service,
		_tc_response,
		_tc_responses,
		_tc_query,
		_tc_store,
		_tc_packetbuffer_block,
		_tc_manager_command
	};
public:
	cSnifferServerConnection(cSocket *socket, cSnifferServer *server);
	~cSnifferServerConnection();
	virtual void connection_process();
	virtual void evData(u_char *data, size_t dataLen);
	void addTask(sSnifferServerGuiTask task);
	sSnifferServerGuiTask getTask();
	void doTerminate() {
		terminate = true;
	}
	void setOrphan() {
		orphan = true;
	}
protected:
	bool checkPassword(string password, string *rsltStr);
	void cp_gui_command(int32_t sensor_id, string command);
	void cp_service();
	void cp_respone(string gui_task_id, u_char *remainder, size_t remainder_length);
	void cp_responses();
	void cp_query();
	void cp_store();
	bool cp_store_check();
	void cp_packetbuffer_block();
	void cp_manager_command(string command);
private:
	bool rsaAesInit(bool writeRsltOK = true);
	eTypeConnection convTypeConnection(string typeConnection);
	void updateSensorState(int32_t sensor_id);
	void lock_tasks() {
		while(__sync_lock_test_and_set(&_sync_tasks, 1)) {
			if(SYNC_LOCK_USLEEP) {
				USLEEP(SYNC_LOCK_USLEEP);
			}
		}
	}
	void unlock_tasks() {
		__sync_lock_release(&_sync_tasks);
	}
	string getTypeConnectionStr();
protected: 
	queue<sSnifferServerGuiTask> tasks;
	volatile int _sync_tasks;
	volatile bool terminate;
	volatile bool orphan;
	cSnifferServer *server;
private:
	eTypeConnection typeConnection;
};


class cSnifferClientService : public cReceiver {
public:
	cSnifferClientService(int32_t sensor_id, const char *sensor_string, unsigned sensor_version);
	~cSnifferClientService();
	void setClientOptions(sSnifferClientOptions *client_options);
	void createResponseSender();
	void stopResponseSender();
	bool start(string host, u_int16_t port);
	virtual bool receive_process_loop_begin();
	virtual void evData(u_char *data, size_t dataLen);
protected:
	int32_t sensor_id;
	string sensor_string;
	unsigned sensor_version;
	string host;
	u_int16_t port;
	bool connection_ok;
	string connect_from;
	sSnifferClientOptions *client_options;
	class cSnifferClientResponseSender *response_sender;
};


class cSnifferClientResponse : public cClient {
public:
	cSnifferClientResponse(string gui_task_id, string command, cSnifferClientResponseSender *response_sender = NULL);
	bool start(string host, u_int16_t port);
	virtual void client_process();
protected:
	string gui_task_id;
	string command;
	cSnifferClientResponseSender *response_sender;
};


class cSnifferClientResponseSender {
private:
	struct sDataForSend {
		string task_id;
		SimpleBuffer *buffer;
	};
public:
	cSnifferClientResponseSender();
	~cSnifferClientResponseSender();
	void add(string task_id, SimpleBuffer *buffer);
	void start(string host, u_int16_t port);
	void stop();
	static void *sendProcess(void*);
	void sendProcess();
private:
	void lock_data() {
		while(__sync_lock_test_and_set(&_sync_data, 1)) {
			USLEEP(10);
		}
	}
	void unlock_data() {
		__sync_lock_release(&_sync_data);
	}
private:
	string host;
	u_int16_t port;
	volatile bool terminate;
	cSocketBlock *socket;
	pthread_t send_process_thread;
	queue<sDataForSend> data_for_send;
	volatile int _sync_data;
};


void snifferServerStart();
void snifferServerStop();
void snifferServerSetSqlStore(MySqlStore *sqlStore);
cSnifferClientService *snifferClientStart(sSnifferClientOptions *clientOptions, 
					  const char *sensorString = NULL,
					  cSnifferClientService *snifferClientServiceOld = NULL);
void snifferClientStop(cSnifferClientService *snifferClientService);
bool existsRemoteChartServer();
size_t getRemoteChartServerQueueSize();
bool add_rchs_query(const char *query, bool checkMaxSize);
bool add_rchs_query(string *query, bool checkMaxSize);


#endif //SERVER_H
