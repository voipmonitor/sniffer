#include <mysqld_error.h>

#include "voipmonitor.h"

#include "server.h"
#include "sql_db.h"
#include "pcap_queue.h"


extern int opt_id_sensor;
extern Calltable *calltable;

sSnifferServerOptions snifferServerOptions;
sSnifferServerClientOptions snifferServerClientOptions;
sSnifferServerGuiTasks snifferServerGuiTasks;
sSnifferServerServices snifferServerServices;
cSnifferServer *snifferServer;

static bool opt_enable_responses_sender;


sSnifferServerVerbose SS_VERBOSE() {
	sSnifferServerVerbose v;
	return(v);
}


sSnifferServerGuiTasks::sSnifferServerGuiTasks() {
	_sync_lock = 0;
}

void sSnifferServerGuiTasks::add(sSnifferServerGuiTask *task) {
	lock();
	tasks[task->id] = *task;
	unlock();
}

void sSnifferServerGuiTasks::remove(sSnifferServerGuiTask *task) {
	remove(task->id);
}

void sSnifferServerGuiTasks::remove(string id) {
	lock();
	map<string, sSnifferServerGuiTask>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		tasks.erase(iter);
	}
	unlock();
}

sSnifferServerGuiTask sSnifferServerGuiTasks::getTask(string id) {
	sSnifferServerGuiTask task;
	lock();
	map<string, sSnifferServerGuiTask>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		task = iter->second;
	}
	unlock();
	return(task);
}

cSnifferServerConnection *sSnifferServerGuiTasks::getGuiConnection(string id) {
	return(getTask(id).gui_connection);
}

int32_t sSnifferServerGuiTasks::getSensorId(string id) {
	return(getTask(id).sensor_id);
}

sSnifferServerGuiTask::eTaskState sSnifferServerGuiTasks::getTaskState(string id) {
	sSnifferServerGuiTask task = getTask(id);
	return(task.id.empty() ? sSnifferServerGuiTask::_na : task.state);
}

void sSnifferServerGuiTasks::setTaskState(string id, sSnifferServerGuiTask::eTaskState state) {
	lock();
	map<string, sSnifferServerGuiTask>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		iter->second.state = state;
	}
	unlock();
}


sSnifferServerServices::sSnifferServerServices() {
	_sync_lock = 0;
	remote_chart_server = 0;
	_sync_rchs = 0;
	extern int opt_charts_cache_remote_queue_limit;
	rchs_query_queue_max_size = opt_charts_cache_remote_queue_limit;
}

void sSnifferServerServices::add(sSnifferServerService *service) {
	lock();
	string id = getIdService(service->sensor_id, service->sensor_string.c_str());
	map<string, sSnifferServerService>::iterator iter = services.find(id);
	if(iter != services.end()) {
		iter->second.service_connection->setOrphan();
		iter->second.service_connection->doTerminate();
	}
	services[id] = *service;
	if(service->remote_chart_server) {
		__SYNC_INC(remote_chart_server);
	}
	unlock();
}

void sSnifferServerServices::remove(sSnifferServerService *service) {
	lock();
	string id = getIdService(service->sensor_id, service->sensor_string.c_str());
	map<string, sSnifferServerService>::iterator iter = services.find(id);
	if(iter != services.end()) {
		if(iter->second.remote_chart_server) {
			__SYNC_DEC(remote_chart_server);
		}
		services.erase(iter);
	}
	unlock();
}

string sSnifferServerServices::getIdService(int32_t sensor_id, const char *sensor_string) {
	return(intToString(sensor_id) + 
	       (sensor_string && *sensor_string ? string("/") + sensor_string : ""));
}

bool sSnifferServerServices::existsService(int32_t sensor_id, const char *sensor_string) {
	lock();
	string id = getIdService(sensor_id, sensor_string);
	map<string, sSnifferServerService>::iterator iter = services.find(id);
	bool exists = iter != services.end();
	unlock();
	return(exists);
}

sSnifferServerService sSnifferServerServices::getService(int32_t sensor_id, const char *sensor_string) {
	sSnifferServerService service;
	lock();
	string id = getIdService(sensor_id, sensor_string);
	map<string, sSnifferServerService>::iterator iter = services.find(id);
	if(iter != services.end()) {
		service = iter->second;
	}
	unlock();
	return(service);
}

cSnifferServerConnection *sSnifferServerServices::getServiceConnection(int32_t sensor_id, const char *sensor_string) {
	return(getService(sensor_id, sensor_string).service_connection);
}

bool sSnifferServerServices::getAesKeys(int32_t sensor_id, const char *sensor_string, string *ckey, string *ivec) {
	sSnifferServerService service = getService(sensor_id, sensor_string);
	if(!service.aes_ckey.empty() && !service.aes_ivec.empty()) {
		*ckey = service.aes_ckey;
		*ivec = service.aes_ivec;
		return(true);
	} else {
		return(false);
	}
}

string sSnifferServerServices::listJsonServices() {
	JsonExport expServices;
	lock();
	expServices.add("count", services.size());
	JsonExport *expAr = NULL;
	if(services.size()) {
		expAr = expServices.addArray("services");
	}
	for(map<string, sSnifferServerService>::iterator iter = services.begin(); iter != services.end(); iter++) {
		sSnifferServerService *service = &(iter->second);
		JsonExport *expSer = expAr->addObject(NULL);
		expSer->add("ip", service->connect_ip.getString());
		expSer->add("port", service->connect_port);
		expSer->add("sensor_id", service->sensor_id);
	}
	unlock();
	return(expServices.getJson());
}

bool sSnifferServerServices::add_rchs_query(const char *query, bool checkMaxSize) {
	bool rslt;
	string *query_string = new FILE_LINE(0) string(query);
	lock_rchs();
	if(checkMaxSize && rchs_query_queue.size() >= rchs_query_queue_max_size) {
		rslt = false;
	} else {
		rchs_query_queue.push(query_string);
		rslt = true;
	}
	unlock_rchs();
	if(!rslt) {
		delete query_string;
	}
	return(rslt);
}

bool sSnifferServerServices::add_rchs_query(string *query, bool checkMaxSize) {
	bool rslt;
	lock_rchs();
	if(checkMaxSize && rchs_query_queue.size() >= rchs_query_queue_max_size) {
		rslt = false;
	} else {
		rchs_query_queue.push(query);
		rslt = true;
	}
	unlock_rchs();
	return(rslt);
}

string *sSnifferServerServices::get_rchs_query() {
	string *query_string = NULL;
	if(rchs_query_queue.size()) {
		lock();
		if(rchs_query_queue.size()) {
			query_string = rchs_query_queue.front();
			if(query_string) {
				rchs_query_queue.pop();
			}
		}
		unlock();
	}
	return(query_string);
}


cSnifferServer::cSnifferServer() {
	sqlStore = NULL;
	terminate = false;
	connection_threads_sync = 0;
	for(int i = 0; i < 2; i++) {
		sql_queue_size_size[i] = 0;
		sql_queue_size_time_ms[i] = 0;
	}
}

cSnifferServer::~cSnifferServer() {
	terminate = true;
	terminateSocketInConnectionThreads();
	unsigned counter = 0;
	while(existConnectionThread() && counter < 100 && is_terminating() < 2) {
		USLEEP(100000);
		++counter;
	}
	cancelConnectionThreads();
}

void cSnifferServer::setSqlStore(MySqlStore *sqlStore) {
	this->sqlStore = sqlStore;
}

void cSnifferServer::sql_query_lock(const char *query_str, int id_main, int id_2) {
	sqlStore->query_lock(query_str, id_main, id_2);
}

void cSnifferServer::sql_query_lock(list<string> *query_str, int id_main, int id_2) {
	sqlStore->query_lock(query_str, id_main, id_2);
}

int cSnifferServer::findMinStoreId2(int id_main) {
	return(sqlStore->findMinId2(id_main, false));
}

unsigned int cSnifferServer::sql_queue_size(bool redirect) {
	while(!sqlStore) {
		if(is_terminating()) {
			return(0);
		}
		USLEEP(1000);
	}
	u_int64_t act_time_ms = getTimeMS_rdtsc();
	int size_index = redirect ? 1 : 0;
	if(act_time_ms > sql_queue_size_time_ms[size_index] + 200) {
		sql_queue_size_size[size_index] = redirect ?
						   sqlStore->getAllRedirectSize(false) :
						   sqlStore->getAllSize(false) + 
						   (calltable ? calltable->calls_charts_cache_queue.size() : 0);
		sql_queue_size_time_ms[size_index] = act_time_ms;
	}
	return(sql_queue_size_size[size_index]);
}
 
void cSnifferServer::createConnection(cSocket *socket) {
	if(is_terminating() || terminate) {
		return;
	}
	cSnifferServerConnection *connection = new FILE_LINE(0) cSnifferServerConnection(socket, this);
	connection->connection_start();
}

void cSnifferServer::registerConnectionThread(class cSnifferServerConnection *connectionThread) {
	lock_connection_threads();
	connection_threads[connectionThread] = true;
	unlock_connection_threads();
}

void cSnifferServer::unregisterConnectionThread(class cSnifferServerConnection *connectionThread) {
	lock_connection_threads();
	if(connection_threads.find(connectionThread) != connection_threads.end()) {
		connection_threads.erase(connectionThread);
	}
	unlock_connection_threads();
}

bool cSnifferServer::existConnectionThread() {
	bool exists = false;
	lock_connection_threads();
	if(connection_threads.size() > 0) {
		exists = true;
	}
	unlock_connection_threads();
	return(exists);
}

void cSnifferServer::cancelConnectionThreads() {
	lock_connection_threads();
	for(map<cSnifferServerConnection*, bool>::iterator iter = connection_threads.begin(); iter != connection_threads.end(); iter++) {
		pthread_cancel(iter->first->getThread());
	}
	unlock_connection_threads();
}

void cSnifferServer::terminateSocketInConnectionThreads() {
	lock_connection_threads();
	for(map<cSnifferServerConnection*, bool>::iterator iter = connection_threads.begin(); iter != connection_threads.end(); iter++) {
		iter->first->setTerminateSocket();
	}
	unlock_connection_threads();
}


cSnifferServerConnection::cSnifferServerConnection(cSocket *socket, cSnifferServer *server) 
 : cServerConnection(socket) {
	_sync_tasks = 0;
	terminate = false;
	orphan = false;
	typeConnection = _tc_na;
	this->server = server;
}

cSnifferServerConnection::~cSnifferServerConnection() {
	server->unregisterConnectionThread(this);
	syslog(LOG_NOTICE, "close connection from %s:%i, socket: %i, type connection: %s", 
	       socket->getIP().c_str(), socket->getPort(), socket->getHandle(),
	       getTypeConnectionStr().c_str());
}

void cSnifferServerConnection::connection_process() {
	server->registerConnectionThread(this);
	JsonItem jsonData;
	u_char *remainder = NULL;
	size_t remainder_length = 0;
	string str = socket->readLine(&remainder, &remainder_length);
	if(!str.empty()) {
		jsonData.parse(str.c_str());
		typeConnection = convTypeConnection(jsonData.getValue("type_connection"));
	}
	if(SS_VERBOSE().connect_command) {
		ostringstream verbstr;
		verbstr << "CONNECTION PROCESS CMD: " << str;
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	if(typeConnection != _tc_response && remainder) {
		delete [] remainder;
	}
	switch(typeConnection) {
	case _tc_gui_command:
		cp_gui_command(atol(jsonData.getValue("sensor_id").c_str()), jsonData.getValue("command"));
		break;
	case _tc_service:
		cp_service();
		break;
	case _tc_response:
		cp_respone(jsonData.getValue("gui_task_id"), remainder, remainder_length);
		break;
	case _tc_responses:
		cp_responses();
		break;
	case _tc_query:
		cp_query();
		break;
	case _tc_store:
		cp_store();
		break;
	case _tc_packetbuffer_block:
		cp_packetbuffer_block();
		break;
	case _tc_manager_command:
		cp_manager_command(jsonData.getValue("command"));
		break;
	default:
		delete this;
		return;
	}
}

void cSnifferServerConnection::evData(u_char */*data*/, size_t /*dataLen*/) {
}

void cSnifferServerConnection::addTask(sSnifferServerGuiTask task) {
	lock_tasks();
	tasks.push(task);
	unlock_tasks();
}

sSnifferServerGuiTask cSnifferServerConnection::getTask() {
	sSnifferServerGuiTask task;
	lock_tasks();
	if(tasks.size()) {
		task = tasks.front();
		tasks.pop();
	}
	unlock_tasks();
	return(task);
}

bool cSnifferServerConnection::checkPassword(string password, string *rsltStr) {
	if(password == snifferServerClientOptions.password) {
		*rsltStr = "";
		return(true);
	} else {
		*rsltStr = "bad password";
		return(false);
	}
}

void cSnifferServerConnection::cp_gui_command(int32_t sensor_id, string command) {
	if(SS_VERBOSE().connect_info) {
		ostringstream verbstr;
		verbstr << "GUI COMAND: "
			<< "sensor_id: " << sensor_id << ", "
			<< "command: " << command;
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	cSnifferServerConnection *service_connection = snifferServerServices.getServiceConnection(sensor_id, NULL);
	if(!service_connection) {
		socket->write("missing sniffer service - connect sensor?");
		delete this;
		return;
	}
	if(SS_VERBOSE().connect_info_ext) {
		ostringstream verbstr;
		verbstr << "FIND SERVICE CONNECTION: "
			<< "addr: " << service_connection;
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	sSnifferServerGuiTask task;
	task.sensor_id = sensor_id;
	task.command = command;
	task.setTimeId();
	task.gui_connection = this;
	snifferServerGuiTasks.add(&task);
	service_connection->addTask(task);
	u_int64_t startTime = getTimeUS();
	while(snifferServerGuiTasks.getTaskState(task.id) != sSnifferServerGuiTask::_complete && !is_terminating()) {
		USLEEP(1000);
		if(getTimeUS() > startTime + 5 * 60 * 1000000ull) {
			socket->write("timeout");
			break;
		}
	}
	snifferServerGuiTasks.remove(&task);
	delete this;
}

void cSnifferServerConnection::cp_service() {
	socket->generate_rsa_keys(4096);
	JsonExport json_rsa_key;
	json_rsa_key.add("rsa_key", socket->get_rsa_pub_key());
	if(!socket->writeBlock(json_rsa_key.getJson())) {
		socket->setError("failed send rsa key");
		delete this;
		return;
	}
	string rsltPasswordAesKeys;
	if(!socket->readBlock(&rsltPasswordAesKeys, cSocket::_te_rsa) || rsltPasswordAesKeys.find("password") == string::npos) {
		socket->setError("failed read password & aes keys");
		delete this;
		return;
	}
	JsonItem jsonPasswordAesKeys;
	jsonPasswordAesKeys.parse(rsltPasswordAesKeys);
	string password = jsonPasswordAesKeys.getValue("password");
	int32_t sensor_id = atol(jsonPasswordAesKeys.getValue("sensor_id").c_str());
	string sensor_string = jsonPasswordAesKeys.getValue("sensor_string");
	string aes_ckey = jsonPasswordAesKeys.getValue("aes_ckey");
	string aes_ivec = jsonPasswordAesKeys.getValue("aes_ivec");
	unsigned int sensor_version = atol(jsonPasswordAesKeys.getValue("sensor_version").c_str());
	if((useNewStore() || useSetId()) &&
	   sensor_version < 23007000) {
		string error = "need upgrade sensor!!!";
		socket->writeBlock(error);
		socket->setError(error.c_str());
		delete this;
		return;
	}
	string checkPasswordRsltStr;
	if(!checkPassword(password, &checkPasswordRsltStr)) {
		socket->writeBlock(checkPasswordRsltStr);
		socket->setError(checkPasswordRsltStr.c_str());
		delete this;
		return;
	}
	if(sensor_id == max(opt_id_sensor, 0) && sensor_string.empty()) {
		string error = "client sensor_id must be different from receiver sensor_id";
		socket->writeBlock(error);
		socket->setError(error.c_str());
		delete this;
		return;
	}
	if(jsonPasswordAesKeys.getValue("restore").empty() &&
	   snifferServerServices.existsService(sensor_id, sensor_string.c_str())) {
		string error = "client with sensor_id " + intToString(sensor_id) + " is already connected, refusing connection";
		socket->writeBlock(error);
		socket->setError(error.c_str());
		delete this;
		return;
	}
	bool checkPingResponse = atoi(jsonPasswordAesKeys.getValue("check_ping_response").c_str()) > 0;
	bool autoParameters = atoi(jsonPasswordAesKeys.getValue("auto_parameters").c_str()) > 0;
	bool remote_chart_server = atoi(jsonPasswordAesKeys.getValue("remote_chart_server").c_str()) > 0; 
	bool use_encode_data = atoi(jsonPasswordAesKeys.getValue("use_encode_data").c_str()) > 0;
	if(use_encode_data) {
		socket->set_aes_keys(aes_ckey, aes_ivec);
	}
	string okAndParameters;
	if(autoParameters) {
		JsonExport ok_parameters;
		ok_parameters.add("result", "OK");
		extern int opt_pcap_queue_use_blocks;
		extern int opt_dup_check;
		if(opt_pcap_queue_use_blocks) {
			ok_parameters.add("use_blocks_pb", true);
		}
		if(opt_dup_check) {
			ok_parameters.add("deduplicate", true);
		}
		if(useNewStore()) {
			ok_parameters.add("mysql_new_store", useNewStore());
		}
		if(useSetId()) {
			ok_parameters.add("mysql_set_id", useSetId());
		}
		if(snifferServerOptions.mysql_concat_limit) {
			ok_parameters.add("mysql_concat_limit", snifferServerOptions.mysql_concat_limit);
		}
		if(useCsvStoreFormat()) {
			ok_parameters.add("csv_store_format", useCsvStoreFormat());
		}
		extern bool opt_charts_cache_store;
		if(opt_charts_cache_store) {
			ok_parameters.add("charts_cache_store", true);
		}
		ok_parameters.add("type_compress", snifferServerOptions.type_compress);
		ok_parameters.add("enable_responses_sender", true);
		okAndParameters = ok_parameters.getJson();
	} else {
		okAndParameters = "OK";
	}
	if(!socket->writeBlock(okAndParameters)) {
		socket->setError("failed send ok");
		delete this;
		return;
	}
	if(SS_VERBOSE().connect_info) {
		ostringstream verbstr;
		verbstr << "SERVER SERVICE START: "
			<< "sensor_id: " << sensor_id;
		if(!sensor_string.empty()) {
			verbstr << ", " << "sensor_string: " << sensor_string;
		}
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	if(!is_read_from_file_simple() && !is_load_pcap_via_client(sensor_string.c_str())) {
		updateSensorState(sensor_id);
	}
	sSnifferServerService service;
	service.connect_ip = socket->getIPL();
	service.connect_port = socket->getPort();
	service.sensor_id = sensor_id;
	service.sensor_string = sensor_string;
	service.service_connection = this;
	service.aes_ckey = aes_ckey;
	service.aes_ivec = aes_ivec;
	service.remote_chart_server = remote_chart_server;
	snifferServerServices.add(&service);
	u_int64_t lastWriteTimeUS = 0;
	u_int64_t wait_remote_chart_server_processing_to_time_ms = 0;
	unsigned errors_counter = 0;
	while(!server->isTerminate() &&
	      !terminate) {
		u_int64_t time_us = getTimeUS();
		if(!socket->checkHandleRead()) {
			if(SS_VERBOSE().connect_info) {
				ostringstream verbstr;
				verbstr << "SNIFFER SERVICE STOP: "
					<< "sensor_id: " << sensor_id;
				if(!sensor_string.empty()) {
					verbstr << ", " << "sensor_string: " << sensor_string;
				}
				syslog(LOG_INFO, "%s", verbstr.str().c_str());
			}
			break;
		}
		if(errors_counter > 100) {
			ostringstream verbstr;
			verbstr << "SNIFFER SERVICE STOP (because too many errors): "
				<< "sensor_id: " << sensor_id;
			if(!sensor_string.empty()) {
				verbstr << ", " << "sensor_string: " << sensor_string;
			}
			syslog(LOG_INFO, "%s", verbstr.str().c_str());
			break;
		}
		sSnifferServerGuiTask task = getTask();
		if(!task.id.empty()) {
			string idCommand = task.id + "/" + task.command;
			socket->writeBlock(idCommand, use_encode_data ? cSocket::_te_aes : cSocket::_te_na);
			lastWriteTimeUS = time_us;
			continue;
		}
		if(remote_chart_server &&
		   (!wait_remote_chart_server_processing_to_time_ms ||
		    getTimeMS() > wait_remote_chart_server_processing_to_time_ms)) {
			wait_remote_chart_server_processing_to_time_ms = 0;
			string *rchs_query = snifferServerServices.get_rchs_query();
			if(rchs_query) {
				bool okSend = true;
				if(snifferServerOptions.type_compress == _cs_compress_gzip) {
					cGzip gzipCompressQuery;
					u_char *queryGzip;
					size_t queryGzipLength;
					if(gzipCompressQuery.compressString(*rchs_query, &queryGzip, &queryGzipLength)) {
						if(!socket->writeBlock((u_char*)("rch:" + string((char*)queryGzip, queryGzipLength)).c_str(), queryGzipLength + 4, 
								       use_encode_data ? cSocket::_te_aes : cSocket::_te_na)) {
							okSend = false;
						}
						delete [] queryGzip;
					}
				} else if(snifferServerOptions.type_compress == _cs_compress_lzo) {
					cLzo lzoCompressQuery;
					u_char *queryLzo;
					size_t queryLzoLength;
					if(lzoCompressQuery.compress((u_char*)rchs_query->c_str(), rchs_query->length(), &queryLzo, &queryLzoLength)) {
						if(!socket->writeBlock((u_char*)("rch:" + string((char*)queryLzo, queryLzoLength)).c_str(), queryLzoLength + 4, 
								       use_encode_data ? cSocket::_te_aes : cSocket::_te_na)) {
							okSend = false;
						}
						delete [] queryLzo;
					}
				} else {
					if(!socket->writeBlock(("rch:" + *rchs_query).c_str(), use_encode_data ? cSocket::_te_aes : cSocket::_te_na)) {
						okSend = false;
					}
				}
				if(!okSend) {
					add_rchs_query(rchs_query, false);
					syslog(LOG_NOTICE, "failed send data to remote chart client - try again after 1s");
					wait_remote_chart_server_processing_to_time_ms = getTimeMS() + 1000;
					++errors_counter;
					continue;
				}
				string response;
				if(socket->readBlockTimeout(&response, 30) &&
				   response == "OK") {
					delete rchs_query;
					errors_counter = 0;
				} else {
					add_rchs_query(rchs_query, false);
					if(response.empty()) {
						syslog(LOG_NOTICE, "failed receive confirmation from remote chart client - try again after 1s");
						wait_remote_chart_server_processing_to_time_ms = getTimeMS() + 1000;
					} else {
						syslog(LOG_NOTICE, "remote chart client sent error '%s' - try again after 1s", response.c_str());
						wait_remote_chart_server_processing_to_time_ms = getTimeMS() + 1000;
					}
					++errors_counter;
				}
				continue;
			}
		}
		if(time_us > lastWriteTimeUS + 5000000ull) {
			socket->writeBlock("ping", use_encode_data ? cSocket::_te_aes : cSocket::_te_na);
			if(checkPingResponse) {
				string pingResponse;
				if(!socket->readBlockTimeout(&pingResponse, 5) ||
				   pingResponse != "pong") {
					if(SS_VERBOSE().connect_info) {
						ostringstream verbstr;
						verbstr << "SNIFFER SERVICE DISCONNECT: "
							<< "sensor_id: " << sensor_id;
						if(!sensor_string.empty()) {
							verbstr << ", " << "sensor_string: " << sensor_string;
						}
						syslog(LOG_INFO, "%s", verbstr.str().c_str());
					}
					break;
				}
			}
			lastWriteTimeUS = time_us;
		}
		USLEEP(1000);
	}
	if(!orphan) {
		snifferServerServices.remove(&service);
	}
	delete this;
}

void cSnifferServerConnection::cp_respone(string gui_task_id, u_char *remainder, size_t remainder_length) {
	cSnifferServerConnection *gui_connection = snifferServerGuiTasks.getGuiConnection(gui_task_id);
	if(SS_VERBOSE().connect_info) {
		ostringstream verbstr;
		verbstr << "RESPONSE: "
			<< "gui_task_id: " << gui_task_id << ", "
			<< "gui_connection: " << gui_connection;
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	if(!gui_connection) {
		if(remainder) {
			delete [] remainder;
		}
		delete this;
		return;
	}
	int32_t sensor_id = snifferServerGuiTasks.getSensorId(gui_task_id);
	string aes_ckey, aes_ivec;
	snifferServerServices.getAesKeys(sensor_id, NULL, &aes_ckey, &aes_ivec);
	if(aes_ckey.empty() || aes_ivec.empty()) {
		if(remainder) {
			delete [] remainder;
		}
		delete this;
		return;
	}
	socket->set_aes_keys(aes_ckey, aes_ivec);
	socket->readDecodeAesAndResendTo(gui_connection->socket, remainder, remainder_length);
	snifferServerGuiTasks.setTaskState(gui_task_id, sSnifferServerGuiTask::_complete);
	delete this;
}

void cSnifferServerConnection::cp_responses() {
	if(!rsaAesInit()) {
		delete this;
		return;
	}
	if(SS_VERBOSE().connect_info_ext) {
		ostringstream verbstr;
		verbstr << "RESPONSES";
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	u_char *response;
	size_t responseLength;
	unsigned counter = 0;
	while(!server->isTerminate() &&
	      (response = socket->readBlock(&responseLength, cSocket::_te_aes, "", counter > 0, 0, 1024 * 1024)) != NULL) {
		u_char response_last_char = response[responseLength - 1];
		response[responseLength - 1] = 0;
		u_char *response_task_id_separator = (u_char*)strchr((char*)response, '#');
		response[responseLength - 1] = response_last_char;
		if(!response_task_id_separator) {
			socket->writeBlock("missing gui task id", cSocket::_te_aes);
			continue;
		}
		string gui_task_id = string((char*)response, response_task_id_separator - response);
		cSnifferServerConnection *gui_connection = snifferServerGuiTasks.getGuiConnection(gui_task_id);
		if(!gui_connection) {
			socket->writeBlock("unknown gui task id", cSocket::_te_aes);
			continue;
		}
		if(gui_connection->socket->write(response_task_id_separator + 1,
						 responseLength - (response_task_id_separator - response) - 1)) {
			if(socket->writeBlock("OK", cSocket::_te_aes)) {
				snifferServerGuiTasks.setTaskState(gui_task_id, sSnifferServerGuiTask::_complete);
			}
		}
	}
	delete this;
}

void cSnifferServerConnection::cp_query() {
	if(!rsaAesInit()) {
		delete this;
		return;
	}
	if(SS_VERBOSE().connect_info_ext) {
		ostringstream verbstr;
		verbstr << "SQL QUERY";
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	SqlDb *sqlDb = createSqlObject();
	u_char *query;
	size_t queryLength;
	unsigned counter = 0;
	while(!server->isTerminate() &&
	      (query = socket->readBlock(&queryLength, cSocket::_te_aes, "", counter > 0, 0, 1024 * 1024)) != NULL) {
		string queryStr;
		cGzip gzipDecompressQuery;
		if(gzipDecompressQuery.isCompress(query, queryLength)) {
			queryStr = gzipDecompressQuery.decompressString(query, queryLength);
		} else {
			queryStr = string((char*)query, queryLength);
		}
		if(!queryStr.empty()) {
			sqlDb->setMaxQueryPass(1);
			bool useCsvRslt = false;
			if(queryStr.substr(0, 4) == "CSV:") {
				queryStr = queryStr.substr(4);
				useCsvRslt = true;
			}
			if(sqlDb->query(queryStr)) {
				string rsltQuery = useCsvRslt ? sqlDb->getCsvResult() : sqlDb->getJsonResult();
				if(rsltQuery.length() > 100) {
					u_char *rsltQueryGzip;
					size_t rsltQueryGzipLength;
					cGzip gzipCompressResult;
					if(gzipCompressResult.compressString(rsltQuery, &rsltQueryGzip, &rsltQueryGzipLength)) {
						socket->writeBlock(rsltQueryGzip, rsltQueryGzipLength, cSocket::_te_aes);
						delete [] rsltQueryGzip;
					}
				} else {
					socket->writeBlock(rsltQuery, cSocket::_te_aes);
				}
			} else {
				if(sqlDb->getLastError() == ER_SP_ALREADY_EXISTS &&
				   queryStr.find("create procedure ") == 0 &&
				   queryStr.find("(") != string::npos) {
					string procedureName = queryStr.substr(17, queryStr.find("(") - 17);
					sqlDb->query("repair table mysql.proc");
					sqlDb->query("drop procedure if exists " + procedureName);
				}
				string rsltError = sqlDb->getJsonError();
				socket->writeBlock(rsltError, cSocket::_te_aes);
			}
		}
		++counter;
	}
	delete sqlDb;
	delete this;
}

void cSnifferServerConnection::cp_store() {
	while(!dbDataIsSet()) {
		if(is_terminating()) {
			delete this;
			return;
		}
		USLEEP(1000);
	}
	if(!rsaAesInit(false)) {
		delete this;
		return;
	}
	JsonExport json_ok;
	json_ok.add("rslt", "OK");
	json_ok.add("check_store", 1);
	json_ok.add("check_time", 1);
	if(!socket->writeBlock(json_ok.getJson())) {
		socket->setError("failed send ok");
		delete this;
		return;
	}
	u_char *query;
	size_t queryLength;
	unsigned counter = 0;
	while(!server->isTerminate() &&
	      (query = socket->readBlock(&queryLength, cSocket::_te_aes, "", counter > 0, 0, 1024 * 1024)) != NULL) {
		if(queryLength == 5 && !strncmp((char*)query, "check", 5)) {
			if(cp_store_check()) {
				socket->writeBlock("OK", cSocket::_te_aes);
			}
			continue;
		}
		if(cp_store_check()) {
			string queryStr;
			cGzip gzipDecompressQuery;
			cLzo lzoDecompressQuery;
			if(gzipDecompressQuery.isCompress(query, queryLength)) {
				queryStr = gzipDecompressQuery.decompressString(query, queryLength);
			} else if(lzoDecompressQuery.isCompress(query, queryLength)) {
				queryStr = lzoDecompressQuery.decompressString(query, queryLength);
			} else {
				queryStr = string((char*)query, queryLength);
			}
			if(!queryStr.empty()) {
				size_t posStoreIdSeparator = queryStr.find('|');
				if(posStoreIdSeparator != string::npos) {
					int storeIdMain = atoi(queryStr.c_str());
					while(!server->isSetSqlStore()) {
						if(is_terminating()) {
							delete this;
							return;
						}
						USLEEP(1000);
					}
					size_t posBeginQuery = posStoreIdSeparator + 1;
					if(queryStr[posBeginQuery] == 'T' && isdigit(queryStr[posBeginQuery + 1])) {
						size_t posTimeSeparator = queryStr.find('|', posBeginQuery);
						if(posTimeSeparator != string::npos && posTimeSeparator - posBeginQuery <= 20) {
							string query_time_str = queryStr.substr(posBeginQuery + 1, posTimeSeparator - posBeginQuery - 1);
							time_t query_time = stringToTime(query_time_str.c_str());
							time_t act_time = time(NULL);
							if(query_time > act_time && query_time - act_time > 24 * 60 * 60) {
								static uint64_t lastTimeSyslog =0;
								u_int64_t actTime = getTimeMS();
								if(actTime - 30000 > lastTimeSyslog) {
									cLogSensor::log(cLogSensor::error, "client/server problem", "client time of %s is too greater than server time", socket->getHost().c_str());
									lastTimeSyslog = actTime;
								}
								JsonExport exp;
								exp.add("error", "client time is too greater than server time");
								exp.add("next_attempt", false);
								socket->writeBlock(exp.getJson(), cSocket::_te_aes);
								delete this;
								return;
							}
							posBeginQuery = posTimeSeparator + 1;
						}
					}
					int storeId2 = server->findMinStoreId2(storeIdMain);
					if(queryStr[posBeginQuery] == 'L' && isdigit(queryStr[posBeginQuery + 1])) {
						list<string> queriesStr;
						size_t pos = posBeginQuery;
						do {
							if(queryStr[pos] != 'L') {
								syslog(LOG_ERR, "cSnifferServerConnection::cp_store: missing 'L' separator");
								break;
							}
							unsigned length = atoi(queryStr.c_str() + pos + 1);
							size_t pos_sep = queryStr.find(':', pos);
							if(pos_sep == string::npos) {
								syslog(LOG_ERR, "cSnifferServerConnection::cp_store: missing ':' separator");
								break;
							}
							pos = pos_sep + 1;
							queriesStr.push_back(queryStr.substr(pos, length));
							pos += length + 1;
						} while(pos < queryStr.length());
						if(!sverb.suppress_server_store) {
							server->sql_query_lock(&queriesStr, storeIdMain, storeId2);
						}
					} else {
						if(!sverb.suppress_server_store) {
							server->sql_query_lock(queryStr.substr(posBeginQuery).c_str(), storeIdMain, storeId2);
						}
					}
					socket->writeBlock("OK", cSocket::_te_aes);
				}
			}
		}
		++counter;
	}
	delete this;
}

bool cSnifferServerConnection::cp_store_check() {
	if((snifferServerOptions.mysql_queue_limit &&
	    server->sql_queue_size(false) > snifferServerOptions.mysql_queue_limit) ||
	   (snifferServerOptions.mysql_redirect_queue_limit &&
	    server->sql_queue_size(true) > snifferServerOptions.mysql_redirect_queue_limit)) {
		extern int opt_client_server_sleep_ms_if_queue_is_full;
		JsonExport exp;
		exp.add("error", "sql queue is full");
		exp.add("next_attempt", true);
		exp.add("usleep", opt_client_server_sleep_ms_if_queue_is_full * (300 + (rand() % 100)) / 400 * 1000ul);
		exp.add("quietly", true);
		exp.add("keep_connect", true);
		socket->writeBlock(exp.getJson(), cSocket::_te_aes);
		return(false);
	}
	return(true);
}

void cSnifferServerConnection::cp_packetbuffer_block() {
	syslog(LOG_NOTICE, "accept new connection from %s:%i, socket: %i", 
	       socket->getIP().c_str(), socket->getPort(), socket->getHandle());
	extern PcapQueue_readFromFifo *pcapQueueQ;
	while(!pcapQueueQ || !pcapQueueQ->threadInitIsOk()) {
		USLEEP(10000);
	}
	if(!rsaAesInit()) {
		delete this;
		return;
	}
	u_char *block;
	size_t blockLength;
	unsigned counter = 0;
	u_int32_t block_counter = 0;
	while(!server->isTerminate() &&
	      (block = socket->readBlock(&blockLength, cSocket::_te_aes, "", counter > 0, 0, 1024 * 1024)) != NULL) {
		if(is_readend() || !pcapQueueQ) {
			break;
		}
		string errorAddBlock;
		string warningAddBlock;
		bool require_confirmation = true;
		bool rsltAddBlock = pcapQueueQ->addBlockStoreToPcapStoreQueue(block, blockLength, &errorAddBlock, &warningAddBlock, &block_counter, &require_confirmation);
		if(require_confirmation) {
			if(rsltAddBlock) {
				socket->writeBlock("OK", cSocket::_te_aes);
			} else {
				socket->writeBlock(errorAddBlock, cSocket::_te_aes);
			}
		}
		++counter;
		if(!errorAddBlock.empty()) {
			cLogSensor::log(cLogSensor::error, 
					"error in receiving packets from client",
					"connection from %s, error: %s", 
					socket->getIP().c_str(),
					errorAddBlock.c_str());
		}
		if(!warningAddBlock.empty()) {
			cLogSensor::log(cLogSensor::warning, 
					"warning in receiving packets from client",
					"connection from %s, warning: %s", 
					socket->getIP().c_str(),
					warningAddBlock.c_str());
		}
	}
	delete this;
}

void cSnifferServerConnection::cp_manager_command(string command) {
	if(SS_VERBOSE().connect_info) {
		ostringstream verbstr;
		verbstr << "MANAGER COMAND: "
			<< "command: " << command;
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	string rslt;
	if(command == "active") {
		rslt = snifferServerServices.listJsonServices();
	} else {
		rslt = "unknown command: " + command;
	}
	socket->write(rslt);
	delete this;
}

bool cSnifferServerConnection::rsaAesInit(bool writeRsltOK) {
	socket->generate_rsa_keys();
	JsonExport json_rsa_key;
	json_rsa_key.add("rsa_key", socket->get_rsa_pub_key());
	if(!socket->writeBlock(json_rsa_key.getJson())) {
		socket->setError("failed send rsa key");
		return(false);
	}
	string rsltTokenAesKeys;
	if(!socket->readBlock(&rsltTokenAesKeys, cSocket::_te_rsa) || rsltTokenAesKeys.find("password") == string::npos) {
		socket->setError("failed read password & aes keys");
		return(false);
	}
	JsonItem jsonTokenAesKeys;
	jsonTokenAesKeys.parse(rsltTokenAesKeys);
	string password = jsonTokenAesKeys.getValue("password");
	string aes_ckey = jsonTokenAesKeys.getValue("aes_ckey");
	string aes_ivec = jsonTokenAesKeys.getValue("aes_ivec");
	socket->set_aes_keys(aes_ckey, aes_ivec);
	string checkPasswordRsltStr;
	if(!checkPassword(password, &checkPasswordRsltStr)) {
		socket->writeBlock(checkPasswordRsltStr);
		return(false);
	}
	if(typeConnection == _tc_packetbuffer_block) {
		int sensorId = atoi(jsonTokenAesKeys.getValue("sensor_id").c_str());
		string sensorName = jsonTokenAesKeys.getValue("sensor_name");
		if(sensorId > 0 && sensorName.length()) {
			extern SensorsMap sensorsMap;
			sensorsMap.setSensorName(sensorId, sensorName.c_str());
			syslog(LOG_NOTICE, "detect sensor name: '%s' for sensor id: %i", sensorName.c_str(), sensorId);
		}
		string sensorTime = jsonTokenAesKeys.getValue("time");
		if(sensorTime.length()) {
			syslog(LOG_NOTICE, "reported sensor time: %s for sensor id: %i", sensorTime.c_str(), sensorId);
			time_t actualTimeSec = time(NULL);
			time_t sensorTimeSec = stringToTime(sensorTime.c_str(), true);
			extern int opt_client_server_connect_maximum_time_diff_s;
			int timeDiff = abs((int64_t)actualTimeSec - (int64_t)sensorTimeSec) % (3600/2);
			if(timeDiff > opt_client_server_connect_maximum_time_diff_s) {
				cLogSensor::log(cLogSensor::error,  
						"sensor is not allowed to connect because of different time",
						"Time difference between server and client (id_sensor:%i) is too big (%is). Please synchronise time on both server and client. Or increase configuration parameter client_server_connect_maximum_time_diff_s on server.",
						sensorId,
						timeDiff);
				socket->writeBlock("bad time");
				return(false);
			}
		}
	}
	if(writeRsltOK) {
		if(!socket->writeBlock("OK")) {
			socket->setError("failed send ok");
			return(false);
		}
	}
	return(true);
}

cSnifferServerConnection::eTypeConnection cSnifferServerConnection::convTypeConnection(string typeConnection) {
	if(typeConnection == "gui_command") {
		return(_tc_gui_command);
	} else if(typeConnection == "service") {
		return(_tc_service);
	} else if(typeConnection == "response") {
		return(_tc_response);
	} else if(typeConnection == "responses") {
		return(_tc_responses);
	} else if(typeConnection == "query") {
		return(_tc_query);
	} else if(typeConnection == "store") {
		return(_tc_store);
	} else if(typeConnection == "packetbuffer block") {
		return(_tc_packetbuffer_block);
	} else if(typeConnection == "manager_command") {
		return(_tc_manager_command);
	} else {
		return(_tc_na);
	}
}

void cSnifferServerConnection::updateSensorState(int32_t sensor_id) {
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select * from `sensors` where id_sensor=" + intToString(sensor_id));
	bool existsRowSensor = sqlDb->fetchRow();
	if(existsRowSensor) {
		SqlDb_row rowU;
		rowU.add(socket->getIP(), "host");
		sqlDb->update("sensors", rowU, ("id_sensor=" + intToString(sensor_id)).c_str());
	} else {
		SqlDb_row rowI;
		rowI.add(sensor_id, "id_sensor");
		rowI.add("auto insert id " + intToString(sensor_id), "name");
		rowI.add(socket->getIP(), "host");
		sqlDb->insert("sensors", rowI);
	}
	delete sqlDb;
}

string cSnifferServerConnection::getTypeConnectionStr() {
	switch(typeConnection) {
	case _tc_na: return("na");
	case _tc_gui_command: return("gui_command");
	case _tc_service: return("service");
	case _tc_response: return("response");
	case _tc_responses: return("responses");
	case _tc_query: return("query");
	case _tc_store: return("store");
	case _tc_packetbuffer_block: return("packetbuffer_block");
	case _tc_manager_command: return("manager_command");
	}
	return("");
}


cSnifferClientService::cSnifferClientService(int32_t sensor_id, const char *sensor_string, unsigned sensor_version) {
	this->sensor_id = sensor_id;
	this->sensor_string = sensor_string ? sensor_string : "";
	this->sensor_version = sensor_version;
	port = 0;
	connection_ok = false;
	client_options = NULL;
	response_sender = NULL;
}

cSnifferClientService::~cSnifferClientService() {
	if(response_sender) {
		 delete response_sender;
	}
}

void cSnifferClientService::setClientOptions(sSnifferClientOptions *client_options) {
	this->client_options = client_options;
	if(client_options->remote_chart_server) {
		use_encode_data = true;
	}
}

void cSnifferClientService::createResponseSender() {
	response_sender = new FILE_LINE(0) cSnifferClientResponseSender();
	response_sender->start(client_options->host, client_options->port);
}

void cSnifferClientService::stopResponseSender() {
	if(response_sender) {
		response_sender->stop();
	}
}

bool cSnifferClientService::start(string host, u_int16_t port) {
	this->host = host;
	this->port = port;
	_receive_start();
	return(true);
}

bool cSnifferClientService::receive_process_loop_begin() {
	if(connection_ok) {
		if(receive_socket->isError()) {
			_close();
			connection_ok = false;
		} else {
			return(true);
		}
	}
	if(!receive_socket) {
		_connect(host, port, 5);
	}
	if(!receive_socket) {
		return(false);
	}
	string connectCmd = "{\"type_connection\":\"service\"}\r\n";
	if(!receive_socket->write(connectCmd)) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed send command service");
		}
		_close();
		return(false);
	}
	string rsltRsaKeyIP;
	if(!receive_socket->readBlock(&rsltRsaKeyIP) || rsltRsaKeyIP.find("rsa_key") == string::npos) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed read rsa key");
		}
		_close();
		return(false);
	}
	JsonItem jsonRsaKey;
	jsonRsaKey.parse(rsltRsaKeyIP);
	string rsa_key = jsonRsaKey.getValue("rsa_key");
	connect_from = jsonRsaKey.getValue("ip");
	receive_socket->set_rsa_pub_key(rsa_key);
	receive_socket->generate_aes_keys();
	JsonExport json_keys;
	json_keys.add("sensor_id", sensor_id);
	if(!sensor_string.empty()) {
		json_keys.add("sensor_string", sensor_string);
	}
	json_keys.add("password", snifferServerClientOptions.password);
	string aes_ckey, aes_ivec;
	receive_socket->get_aes_keys(&aes_ckey, &aes_ivec);
	json_keys.add("aes_ckey", aes_ckey);
	json_keys.add("aes_ivec", aes_ivec);
	json_keys.add("sensor_version", sensor_version);
	if(start_ok) {
		json_keys.add("restore", true);
	}
	json_keys.add("check_ping_response", true);
	json_keys.add("auto_parameters", true);
	if(client_options->remote_chart_server) {
		json_keys.add("remote_chart_server", client_options->remote_chart_server);
	}
	if(use_encode_data) {
		json_keys.add("use_encode_data", use_encode_data);
	}
	if(!receive_socket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed send sensor_id & aes keys");
		}
		_close();
		return(false);
	}
	string rsltConnectData;
	bool rsltConnectData_okRead = false;
	if(!receive_socket->readBlock(&rsltConnectData)) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed read ok");
		}
	} else {
		if(rsltConnectData == "OK") {
			rsltConnectData_okRead = true;
		} else {
			if(rsltConnectData.empty() || rsltConnectData[0] != '{') {
				if(!receive_socket->isError()) {
					receive_socket->setError(rsltConnectData.empty() ? "failed read ok" : rsltConnectData.c_str());
				}
			} else {
				JsonItem rsltConnectData_json;
				rsltConnectData_json.parse(rsltConnectData);
				if(rsltConnectData_json.getValue("result") == "OK") {
					rsltConnectData_okRead = true;
					if(is_client_packetbuffer_sender()) {
						extern int opt_pcap_queue_use_blocks;
						extern int opt_dup_check;
						bool change_config = false;
						if(!rsltConnectData_json.getValue("use_blocks_pb").empty() &&
						   !opt_pcap_queue_use_blocks) {
							opt_pcap_queue_use_blocks = true;
							syslog(LOG_NOTICE, "enabling pcap_queue_use_blocks because it is enabled on server");
							change_config = true;
						}
						if(!rsltConnectData_json.getValue("deduplicate").empty() &&
						   !opt_dup_check) {
							opt_dup_check = true;
							syslog(LOG_NOTICE, "enabling deduplicate because it is enabled on server");
							change_config = true;
						}
						if(change_config) {
							extern void set_context_config();
							set_context_config();
						}
					} else {
						client_options->mysql_new_store = !rsltConnectData_json.getValue("mysql_new_store").empty() ?
										   atoi(rsltConnectData_json.getValue("mysql_new_store").c_str()) :
										   0;
						client_options->mysql_set_id = !rsltConnectData_json.getValue("mysql_set_id").empty() &&
									       atoi(rsltConnectData_json.getValue("mysql_set_id").c_str());
						if(!rsltConnectData_json.getValue("mysql_concat_limit").empty()) {
							client_options->mysql_concat_limit = atoi(rsltConnectData_json.getValue("mysql_concat_limit").c_str());
						}
						client_options->csv_store_format = !rsltConnectData_json.getValue("csv_store_format").empty() &&
										   atoi(rsltConnectData_json.getValue("csv_store_format").c_str());
						client_options->charts_cache_store = !rsltConnectData_json.getValue("charts_cache_store").empty() &&
										     atoi(rsltConnectData_json.getValue("charts_cache_store").c_str());
						if(!rsltConnectData_json.getValue("type_compress").empty()) {
							client_options->type_compress = (eServerClientTypeCompress)atoi(rsltConnectData_json.getValue("type_compress").c_str());
						}
					}
					opt_enable_responses_sender = !rsltConnectData_json.getValue("enable_responses_sender").empty();
				} else {
					if(!receive_socket->isError()) {
						receive_socket->setError(rsltConnectData.c_str());
					}
				}
			}
		}
	}
	if(!rsltConnectData_okRead) {
		if(!start_ok) {
			set_terminating();
		}
		_close();
		return(false);
	}
	connection_ok = true;
	if(SS_VERBOSE().start_client) {
		ostringstream verbstr;
		verbstr << "START SNIFFER SERVICE";
		vector<string> params;
		if(client_options->remote_query) {
			params.push_back("remote_query: yes");
		}
		if(client_options->remote_store) {
			params.push_back("remote_store: yes");
		}
		if(client_options->packetbuffer_sender) {
			params.push_back("packetbuffer_sender: yes");
		}
		if(client_options->mysql_new_store) {
			params.push_back("mysql_new_store(s): yes");
		}
		if(client_options->mysql_set_id) {
			params.push_back("mysql_set_id(s): yes");
		}
		if(client_options->mysql_concat_limit) {
			params.push_back("mysql_concat_limit(s): " + intToString(client_options->mysql_concat_limit));
		}
		if(client_options->csv_store_format) {
			params.push_back("csv_store_format(s): yes");
		}
		if(client_options->charts_cache_store) {
			params.push_back("charts_cache_store(s): yes");
		}
		if(params.size()) {
			verbstr << ' ' << implode(params, ", ");
		}
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	return(true);
}

void cSnifferClientService::evData(u_char *data, size_t dataLen) {
	if(dataLen > 4 && !strncmp((char*)data, "rch:", 4)) {
		if(!calltable) {
			while(!calltable) {
				USLEEP(100000);
			}
			USLEEP(100000);
		}
		extern int opt_charts_cache_queue_limit;
		if(calltable->calls_charts_cache_queue.size() > (unsigned)opt_charts_cache_queue_limit) {
			receive_socket->writeBlock("queue is full");
			return;
		}
		string queryStr;
		cGzip gzipDecompressQuery;
		cLzo lzoDecompressQuery;
		if(gzipDecompressQuery.isCompress(data + 4, dataLen - 4)) {
			queryStr = gzipDecompressQuery.decompressString(data + 4, dataLen - 4);
			if(queryStr.empty()) {
				receive_socket->writeBlock("error in decompress zip");
				return;
			}
		} else if(lzoDecompressQuery.isCompress(data + 4, dataLen - 4)) {
			queryStr = lzoDecompressQuery.decompressString(data + 4, dataLen - 4);
			if(queryStr.empty()) {
				receive_socket->writeBlock("error in decompress lzo");
				return;
			}
		} else {
			queryStr = string((char*)data + 4, dataLen - 4);
		}
		if(!receive_socket->writeBlock("OK")) {
			return;
		}
		list<string*> csv_list;
		if(queryStr[0] == 'L' && isdigit(queryStr[1])) {
			size_t pos = 0;
			do {
				if(queryStr[pos] != 'L') {
					syslog(LOG_ERR, "cSnifferClientService::evData: missing 'L' separator");
					break;
				}
				unsigned length = atoi(queryStr.c_str() + pos + 1);
				size_t pos_sep = queryStr.find(':', pos);
				if(pos_sep == string::npos) {
					syslog(LOG_ERR, "cSnifferClientService::evData: missing ':' separator");
					break;
				}
				pos = pos_sep + 1;
				csv_list.push_back(new FILE_LINE(0) string(queryStr.substr(pos, length)));
				pos += length + 1;
			} while(pos < queryStr.length());
		} else {
			csv_list.push_back(new FILE_LINE(0) string(queryStr));
		}
		calltable->lock_calls_charts_cache_queue();
		for(list<string*>::iterator iter = csv_list.begin(); iter != csv_list.end(); iter++) {
			calltable->calls_charts_cache_queue.push_back(sChartsCallData(sChartsCallData::_csv, *iter));
		}
		calltable->unlock_calls_charts_cache_queue();
	} else {
		string idCommand = string((char*)data, dataLen);
		size_t idCommandSeparatorPos = idCommand.find('/'); 
		if(idCommandSeparatorPos != string::npos) {
			cSnifferClientResponse *response = new FILE_LINE(0) cSnifferClientResponse(
					idCommand.substr(0, idCommandSeparatorPos), 
					idCommand.substr(idCommandSeparatorPos + 1),
					opt_enable_responses_sender ? response_sender : NULL);
			response->start(receive_socket->getHost(), receive_socket->getPort());
		}
	}
}


cSnifferClientResponse::cSnifferClientResponse(string gui_task_id, string command, cSnifferClientResponseSender *response_sender) {
	this->gui_task_id = gui_task_id;
	this->command = command;
	if(command.find("file_exists") != string::npos ||
	   command.find("fileexists") != string::npos) {
		this->response_sender = response_sender;
	} else {
		this->response_sender = NULL;
	}
}

bool cSnifferClientResponse::start(string host, u_int16_t port) {
	if(response_sender) {
		this->writeToBuffer();
	} else {
		if(!_connect(host, port)) {
			return(false);
		}
	}
	if(!response_sender) {
		string connectCmd = "{\"type_connection\":\"response\",\"gui_task_id\":\"" + gui_task_id + "\"}\r\n";
		if(!client_socket->write(connectCmd)) {
			delete client_socket;
			client_socket = NULL;
			return(false);
		}
	}
	_client_start();
	return(true);
}

void cSnifferClientResponse::client_process() {
	extern int parse_command(string cmd, sClientInfo client, cClient *c_client);
	parse_command(command, 0, this);
	if(response_sender) {
		response_sender->add(gui_task_id, buffer);
		buffer = NULL;
	} else {
		client_socket->writeAesEnc(NULL, 0, true);
	}
	delete this;
}


cSnifferClientResponseSender::cSnifferClientResponseSender() {
	terminate = false;
	socket = NULL;
	send_process_thread = 0;
	_sync_data = 0;
}

cSnifferClientResponseSender::~cSnifferClientResponseSender() {
	stop();
}

void cSnifferClientResponseSender::add(string task_id, SimpleBuffer *buffer) {
	lock_data();
	sDataForSend data;
	data.task_id = task_id;
	data.buffer = buffer;
	data_for_send.push(data);
	unlock_data();
}

void cSnifferClientResponseSender::start(string host, u_int16_t port) {
	this->host = host;
	this->port = port;
	vm_pthread_create("cSnifferClientResponseSender::start", &send_process_thread, NULL, cSnifferClientResponseSender::sendProcess, this, __FILE__, __LINE__);
}

void cSnifferClientResponseSender::stop() {
	terminate = true;
	if(send_process_thread) {
		pthread_join(send_process_thread, NULL);
		send_process_thread = 0;
	}
}

void *cSnifferClientResponseSender::sendProcess(void *arg) {
	((cSnifferClientResponseSender*)arg)->sendProcess();
	return(NULL);
}

void cSnifferClientResponseSender::sendProcess() {
	while(!terminate) {
		lock_data();
		unsigned data_for_send_size = data_for_send.size();
		unlock_data();
		if(!data_for_send_size) {
			USLEEP(100000);
			continue;
		}
		if(!socket) {
			socket = new FILE_LINE(0) cSocketBlock("responses", true);
			socket->setHostPort(host, port);
			if(!socket->connect()) {
				delete socket;
				socket = NULL;
				// log "failed connect"
				sleep(5);
				continue;
			}
			string cmd = "{\"type_connection\":\"responses\"}\r\n";
			if(!socket->write(cmd)) {
				delete socket;
				socket = NULL;
				// log "failed send command"
				sleep(1);
				continue;
			}
			string rsltRsaKey;
			if(!socket->readBlock(&rsltRsaKey) || rsltRsaKey.find("key") == string::npos) {
				delete socket;
				socket = NULL;
				// log "failed read rsa key"
				sleep(1);
				continue;
			}
			JsonItem jsonRsaKey;
			jsonRsaKey.parse(rsltRsaKey);
			string rsa_key = jsonRsaKey.getValue("rsa_key");
			socket->set_rsa_pub_key(rsa_key);
			socket->generate_aes_keys();
			JsonExport json_keys;
			json_keys.add("password", snifferServerClientOptions.password);
			string aes_ckey, aes_ivec;
			socket->get_aes_keys(&aes_ckey, &aes_ivec);
			json_keys.add("aes_ckey", aes_ckey);
			json_keys.add("aes_ivec", aes_ivec);
			if(!socket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
				delete socket;
				socket = NULL;
				// log "failed send password & aes keys"
				sleep(1);
				continue;
			}
			string connectResponse;
			if(!socket->readBlock(&connectResponse) || connectResponse != "OK") {
				delete socket;
				socket = NULL;
				// log "failed read response after send password & aes keys"
				sleep(1);
				continue;
			}
		}
		sDataForSend data;
		lock_data();
		data = data_for_send.front();
		unlock_data();
		unsigned data_buffer_size = data.task_id.length() + 1 + data.buffer->size();
		u_char *data_buffer = new u_char[data_buffer_size];
		memcpy(data_buffer, data.task_id.c_str(), data.task_id.length());
		memcpy(data_buffer + data.task_id.length(), "#", 1);
		memcpy(data_buffer + data.task_id.length() + 1, data.buffer->data(), data.buffer->size());
		if(!socket->writeBlock(data_buffer,data_buffer_size, cSocket::_te_aes)) {
			delete [] data_buffer;
			delete socket;
			socket = NULL;
			// log "failed write response"
			continue;
		}
		string dataResponse;
		if(!socket->readBlock(&dataResponse, cSocket::_te_aes, "", true) || dataResponse != "OK") {
			if(dataResponse.find("missing gui task id") != string::npos || 
			   dataResponse.find("unknown gui task id") != string::npos) {
				lock_data();
				data_for_send.pop();
				unlock_data();
			}
			delete [] data_buffer;
			delete socket;
			socket = NULL;
			// log "failed read response after send data"
			continue;
		}
		delete data.buffer;
		delete [] data_buffer;
		lock_data();
		data_for_send.pop();
		unlock_data();
	}
	if(socket) {
		delete socket;
		socket = NULL;
	}
}


void snifferServerStart() {
	if(snifferServer) {
		delete snifferServer;
	}
	snifferServer =  new FILE_LINE(0) cSnifferServer;
	snifferServer->listen_start("sniffer_server", snifferServerOptions.host, snifferServerOptions.port);
}


void snifferServerStop() {
	if(snifferServer) {
		delete snifferServer;
		snifferServer = NULL;
	}
}


void snifferServerSetSqlStore(MySqlStore *sqlStore) {
	if(snifferServer) {
		snifferServer->setSqlStore(sqlStore);
	}
}


cSnifferClientService *snifferClientStart(sSnifferClientOptions *clientOptions, 
					  const char *sensorString,
					  cSnifferClientService *snifferClientServiceOld) {
	if(snifferClientServiceOld) {
		snifferClientStop(snifferClientServiceOld);
	}
	extern char opt_sensor_string[128];
	cSnifferClientService *snifferClientService = new FILE_LINE(0) cSnifferClientService(opt_id_sensor > 0 ? opt_id_sensor : 0, 
											     sensorString ? sensorString : opt_sensor_string, 
											     RTPSENSOR_VERSION_INT());
	snifferClientService->setClientOptions(clientOptions);
	snifferClientService->createResponseSender();
	snifferClientService->setErrorTypeString(cSocket::_se_loss_connection, "connection to the server has been lost - trying again");
	snifferClientService->start(clientOptions->host, clientOptions->port);
	while(!snifferClientService->isStartOk() && !is_terminating()) {
		USLEEP(100000);
	}
	return(snifferClientService);
}


void snifferClientStop(cSnifferClientService *snifferClientService) {
	snifferClientService->stopResponseSender();
	if(snifferClientService) {
		delete snifferClientService;
	}
}


bool existsRemoteChartServer() {
	return(snifferServerServices.remote_chart_server);
}


size_t getRemoteChartServerQueueSize() {
	return(snifferServerServices.rchs_query_queue.size());
}


bool add_rchs_query(const char *query, bool checkMaxSize) {
	return(snifferServerServices.add_rchs_query(query, checkMaxSize));
}

bool add_rchs_query(string *query, bool checkMaxSize) {
	return(snifferServerServices.add_rchs_query(query, checkMaxSize));
}
