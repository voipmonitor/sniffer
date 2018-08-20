#ifndef SERVER_H
#define SERVER_H


#include <string.h>

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


struct sSnifferServerOptions {
	sSnifferServerOptions() {
		port = 60024;
	}
	bool isEnable() {
		return(!host.empty() && port);
	}
	string host;
	unsigned port;
};


struct sSnifferClientOptions {
	sSnifferClientOptions() {
		port = 60024;
		remote_query = true;
		remote_store = true;
		packetbuffer_sender = false;
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
	string host;
	unsigned port;
	bool remote_query;
	bool remote_store;
	bool packetbuffer_sender;
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
				usleep(SYNC_LOCK_USLEEP);
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
		connect_ipl = 0;
		connect_port = 0;
		sensor_id = 0;
		service_connection = NULL;
	}
	u_int32_t connect_ipl;
	u_int16_t connect_port;
	int32_t sensor_id;
	class cSnifferServerConnection *service_connection;
	string aes_ckey;
	string aes_ivec;
};


class sSnifferServerServices {
public:
	sSnifferServerServices();
	void add(sSnifferServerService *service);
	void remove(sSnifferServerService *service);
	bool existsService(int32_t sensor_id);
	sSnifferServerService getService(int32_t sensor_id);
	class cSnifferServerConnection *getServiceConnection(int32_t sensor_id);
	bool getAesKeys(int32_t sensor_id, string *ckey, string *ivec);
	string listJsonServices();
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync_lock, 1)) {
			if(SYNC_LOCK_USLEEP) {
				usleep(SYNC_LOCK_USLEEP);
			}
		}
	}
	void unlock() {
		__sync_lock_release(&_sync_lock);
	}
public:
	map<int32_t, sSnifferServerService> services;
	volatile int _sync_lock;
};


class cSnifferServer : public cServer {
public:
	cSnifferServer();
	~cSnifferServer();
	void setSqlStore(class MySqlStore *sqlStore);
	void sql_query_lock(const char *query_str, int id);
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
};


class cSnifferServerConnection : public cServerConnection {
public:
	enum eTypeConnection {
		_tc_na,
		_tc_gui_command,
		_tc_service,
		_tc_response,
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
	void cp_query();
	void cp_store();
	void cp_packetbuffer_block();
	void cp_manager_command(string command);
private:
	bool rsaAesInit();
	eTypeConnection convTypeConnection(string typeConnection);
	void updateSensorState(int32_t sensor_id);
	void lock_tasks() {
		while(__sync_lock_test_and_set(&_sync_tasks, 1)) {
			if(SYNC_LOCK_USLEEP) {
				usleep(SYNC_LOCK_USLEEP);
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
	cSnifferClientService(int32_t sensor_id);
	bool start(string host, u_int16_t port);
	virtual bool receive_process_loop_begin();
	virtual void evData(u_char *data, size_t dataLen);
protected:
	int32_t sensor_id;
	string host;
	u_int16_t port;
	bool connection_ok;
	string connect_from;
};


class cSnifferClientResponse : public cClient {
public:
	cSnifferClientResponse(string gui_task_id, string command);
	bool start(string host, u_int16_t port);
	virtual void client_process();
protected:
	string gui_task_id;
	string command;
};


void snifferServerStart();
void snifferServerStop();
void snifferServerSetSqlStore(MySqlStore *sqlStore);
void snifferClientStart();
void snifferClientStop();


#endif //SERVER_H
