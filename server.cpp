#include <mysqld_error.h>

#include "voipmonitor.h"

#include "server.h"
#include "sql_db.h"
#include "pcap_queue.h"


extern int opt_id_sensor;

sSnifferServerOptions snifferServerOptions;
sSnifferClientOptions snifferClientOptions;
sSnifferServerClientOptions snifferServerClientOptions;
sSnifferServerGuiTasks snifferServerGuiTasks;
sSnifferServerServices snifferServerServices;
cSnifferServer *snifferServer;
cSnifferClientService *snifferClientService;


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
}

void sSnifferServerServices::add(sSnifferServerService *service) {
	lock();
	map<int32_t, sSnifferServerService>::iterator iter = services.find(service->sensor_id);
	if(iter != services.end()) {
		iter->second.service_connection->setOrphan();
		iter->second.service_connection->doTerminate();
	}
	services[service->sensor_id] = *service;
	unlock();
}

void sSnifferServerServices::remove(sSnifferServerService *service) {
	lock();
	map<int32_t, sSnifferServerService>::iterator iter = services.find(service->sensor_id);
	if(iter != services.end()) {
		services.erase(iter);
	}
	unlock();
}

bool sSnifferServerServices::existsService(int32_t sensor_id) {
	lock();
	map<int32_t, sSnifferServerService>::iterator iter = services.find(sensor_id);
	bool exists = iter != services.end();
	unlock();
	return(exists);
}

sSnifferServerService sSnifferServerServices::getService(int32_t sensor_id) {
	sSnifferServerService service;
	lock();
	map<int32_t, sSnifferServerService>::iterator iter = services.find(sensor_id);
	if(iter != services.end()) {
		service = iter->second;
	}
	unlock();
	return(service);
}

cSnifferServerConnection *sSnifferServerServices::getServiceConnection(int32_t sensor_id) {
	return(getService(sensor_id).service_connection);
}

bool sSnifferServerServices::getAesKeys(int32_t sensor_id, string *ckey, string *ivec) {
	sSnifferServerService service = getService(sensor_id);
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
	for(map<int32_t, sSnifferServerService>::iterator iter = services.begin(); iter != services.end(); iter++) {
		sSnifferServerService *service = &(iter->second);
		JsonExport *expSer = expAr->addObject(NULL);
		expSer->add("ip", inet_ntostring(htonl(service->connect_ipl)));
		expSer->add("port", service->connect_port);
		expSer->add("sensor_id", service->sensor_id);
	}
	unlock();
	return(expServices.getJson());
}


cSnifferServer::cSnifferServer() {
	sqlStore = NULL;
	terminate = false;
	connection_threads_sync = 0;
}

cSnifferServer::~cSnifferServer() {
	terminate = true;
	terminateSocketInConnectionThreads();
	unsigned counter = 0;
	while(existConnectionThread() && counter < 100 && is_terminating() < 2) {
		usleep(100000);
		++counter;
	}
	cancelConnectionThreads();
}

void cSnifferServer::setSqlStore(MySqlStore *sqlStore) {
	this->sqlStore = sqlStore;
}

void cSnifferServer::sql_query_lock(const char *query_str, int id) {
	while(!sqlStore) {
		if(is_terminating()) {
			return;
		}
		usleep(1000);
	}
	sqlStore->query_lock(query_str, sqlStore->convStoreId(id));
}
 
void cSnifferServer::createConnection(cSocket *socket) {
	if(is_terminating() || terminate) {
		return;
	}
	cSnifferServerConnection *connection = new cSnifferServerConnection(socket, this);
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
	cSnifferServerConnection *service_connection = snifferServerServices.getServiceConnection(sensor_id);
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
		usleep(1000);
		if(getTimeUS() > startTime + 5 * 60 * 1000000ull) {
			socket->write("timeout");
			break;
		}
	}
	snifferServerGuiTasks.remove(&task);
	delete this;
}

void cSnifferServerConnection::cp_service() {
	socket->generate_rsa_keys();
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
	string aes_ckey = jsonPasswordAesKeys.getValue("aes_ckey");
	string aes_ivec = jsonPasswordAesKeys.getValue("aes_ivec");
	string checkPasswordRsltStr;
	if(!checkPassword(password, &checkPasswordRsltStr)) {
		socket->writeBlock(checkPasswordRsltStr);
		socket->setError(checkPasswordRsltStr.c_str());
		delete this;
		return;
	}
	if(sensor_id == max(opt_id_sensor, 0)) {
		string error = "client sensor_id must be different from receiver sensor_id";
		socket->writeBlock(error);
		socket->setError(error.c_str());
		delete this;
		return;
	}
	if(jsonPasswordAesKeys.getValue("restore").empty() &&
	   snifferServerServices.existsService(sensor_id)) {
		string error = "client with sensor_id " + intToString(sensor_id) + " is already connected, refusing connection";
		socket->writeBlock(error);
		socket->setError(error.c_str());
		delete this;
		return;
	}
	bool checkPingResponse = !jsonPasswordAesKeys.getValue("check_ping_response").empty();
	bool autoParameters = !jsonPasswordAesKeys.getValue("auto_parameters").empty();
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
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	updateSensorState(sensor_id);
	sSnifferServerService service;
	service.connect_ipl = socket->getIPL();
	service.connect_port = socket->getPort();
	service.sensor_id = sensor_id;
	service.service_connection = this;
	service.aes_ckey = aes_ckey;
	service.aes_ivec = aes_ivec;
	snifferServerServices.add(&service);
	u_int64_t lastWriteTimeUS = 0;
	while(!server->isTerminate() &&
	      !terminate) {
		u_int64_t time_us = getTimeUS();
		if(!socket->checkHandleRead()) {
			if(SS_VERBOSE().connect_info) {
				ostringstream verbstr;
				verbstr << "SNIFFER SERVICE STOP: "
					<< "sensor_id: " << sensor_id;
				syslog(LOG_INFO, "%s", verbstr.str().c_str());
			}
			break;
		}
		sSnifferServerGuiTask task = getTask();
		if(!task.id.empty()) {
			string idCommand = task.id + "/" + task.command;
			socket->writeBlock(idCommand);
			lastWriteTimeUS = time_us;
		} else {
			if(time_us > lastWriteTimeUS + 5000000ull) {
				socket->writeBlock("ping");
				if(checkPingResponse) {
					string pingResponse;
					if(!socket->readBlockTimeout(&pingResponse, 5) ||
					   pingResponse != "pong") {
						if(SS_VERBOSE().connect_info) {
							ostringstream verbstr;
							verbstr << "SNIFFER SERVICE DISCONNECT: "
								<< "sensor_id: " << sensor_id;
							syslog(LOG_INFO, "%s", verbstr.str().c_str());
						}
						break;
					}
				}
				lastWriteTimeUS = time_us;
			}
			usleep(1000);
		}
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
	snifferServerServices.getAesKeys(sensor_id, &aes_ckey, &aes_ivec);
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
	      (query = socket->readBlock(&queryLength, cSocket::_te_aes, "", counter > 0)) != NULL) {
		string queryStr;
		cGzip gzipDecompressQuery;
		if(gzipDecompressQuery.isCompress(query, queryLength)) {
			queryStr = gzipDecompressQuery.decompressString(query, queryLength);
		} else {
			queryStr = string((char*)query, queryLength);
		}
		if(!queryStr.empty()) {
			sqlDb->setMaxQueryPass(1);
			if(sqlDb->query(queryStr)) {
				string rsltQuery = sqlDb->getJsonResult();
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
	if(!rsaAesInit()) {
		delete this;
		return;
	}
	u_char *query;
	size_t queryLength;
	unsigned counter = 0;
	while(!server->isTerminate() &&
	      (query = socket->readBlock(&queryLength, cSocket::_te_aes, "", counter > 0)) != NULL) {
		string queryStr;
		cGzip gzipDecompressQuery;
		if(gzipDecompressQuery.isCompress(query, queryLength)) {
			queryStr = gzipDecompressQuery.decompressString(query, queryLength);
		} else {
			queryStr = string((char*)query, queryLength);
		}
		if(!queryStr.empty()) {
			size_t posStoreIdSeparator = queryStr.find('|');
			if(posStoreIdSeparator != string::npos) {
				server->sql_query_lock(queryStr.substr(posStoreIdSeparator + 1).c_str(), 
						       atoi(queryStr.c_str()));
				socket->writeBlock("OK", cSocket::_te_aes);
			}
		}
		++counter;
	}
	delete this;
}

void cSnifferServerConnection::cp_packetbuffer_block() {
	syslog(LOG_NOTICE, "accept new connection from %s:%i, socket: %i", 
	       socket->getIP().c_str(), socket->getPort(), socket->getHandle());
	extern PcapQueue_readFromFifo *pcapQueueQ;
	while(!pcapQueueQ || !pcapQueueQ->threadInitIsOk()) {
		usleep(10000);
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
	      (block = socket->readBlock(&blockLength, cSocket::_te_aes, "", counter > 0)) != NULL) {
		if(is_readend() || !pcapQueueQ) {
			break;
		}
		string errorAddBlock;
		string warningAddBlock;
		bool rsltAddBlock = pcapQueueQ->addBlockStoreToPcapStoreQueue(block, blockLength, &errorAddBlock, &warningAddBlock, &block_counter);
		if(rsltAddBlock) {
			socket->writeBlock("OK", cSocket::_te_aes);
		} else {
			socket->writeBlock(errorAddBlock, cSocket::_te_aes);
		}
		++counter;
		if(!warningAddBlock.empty()) {
			syslog(LOG_WARNING, "%s in connection from %s:%i, socket: %i", 
			       warningAddBlock.c_str(),
			       socket->getIP().c_str(), socket->getPort(), socket->getHandle());
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

bool cSnifferServerConnection::rsaAesInit() {
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
			time_t sensorTimeSec = stringToTime(sensorTime.c_str());
			if(abs(actualTimeSec % 3600 - sensorTimeSec % 3600) > 2) {
				cLogSensor::log(cLogSensor::error,  
						"sensor is not allowed to connect because of different time",
						"between receiver (%s) and sensor %i (%s) - please synchronize clocks on both server ",
						sqlDateTimeString(actualTimeSec).c_str(),
						sensorId,
						sensorTime.c_str());
				socket->writeBlock("bad time");
			}
		}
	}
	if(!socket->writeBlock("OK")) {
		socket->setError("failed send ok");
		return(false);
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
	case _tc_query: return("query");
	case _tc_store: return("store");
	case _tc_packetbuffer_block: return("packetbuffer_block");
	case _tc_manager_command: return("manager_command");
	}
	return("");
}


cSnifferClientService::cSnifferClientService(int32_t sensor_id) {
	this->sensor_id = sensor_id;
	port = 0;
	connection_ok = false;
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
	json_keys.add("password", snifferServerClientOptions.password);
	string aes_ckey, aes_ivec;
	receive_socket->get_aes_keys(&aes_ckey, &aes_ivec);
	json_keys.add("aes_ckey", aes_ckey);
	json_keys.add("aes_ivec", aes_ivec);
	if(start_ok) {
		json_keys.add("restore", true);
	}
	json_keys.add("check_ping_response", true);
	json_keys.add("auto_parameters", true);
	if(!receive_socket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
		if(!receive_socket->isError()) {
			receive_socket->setError("failed send sesnor_id & aes keys");
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
					}
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
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	return(true);
}

void cSnifferClientService::evData(u_char *data, size_t dataLen) {
	receive_socket->writeBlock("OK");
	string idCommand = string((char*)data, dataLen);
	size_t idCommandSeparatorPos = idCommand.find('/'); 
	if(idCommandSeparatorPos != string::npos) {
		cSnifferClientResponse *response = new cSnifferClientResponse(idCommand.substr(0, idCommandSeparatorPos), idCommand.substr(idCommandSeparatorPos + 1));
		response->start(receive_socket->getHost(), receive_socket->getPort());
	}
}


cSnifferClientResponse::cSnifferClientResponse(string gui_task_id, string command) {
	this->gui_task_id = gui_task_id;
	this->command = command;	
}

bool cSnifferClientResponse::start(string host, u_int16_t port) {
	if(!_connect(host, port)) {
		return(false);
	}
	string connectCmd = "{\"type_connection\":\"response\",\"gui_task_id\":\"" + gui_task_id + "\"}\r\n";
	if(!client_socket->write(connectCmd)) {
		delete client_socket;
		client_socket = NULL;
		return(false);
	}
	_client_start();
	return(true);
}

void cSnifferClientResponse::client_process() {
	extern int parse_command(string cmd, int client, cClient *c_client);
	parse_command(command, 0, this);
	client_socket->writeAesEnc(NULL, 0, true);
	delete this;
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


void snifferClientStart() {
	if(snifferClientService) {
		delete snifferClientService;
	}
	snifferClientService = new FILE_LINE(0) cSnifferClientService(opt_id_sensor > 0 ? opt_id_sensor : 0);
	snifferClientService->setErrorTypeString(cSocket::_se_loss_connection, "connection to the server has been lost - trying again");
	snifferClientService->start(snifferClientOptions.host, snifferClientOptions.port);
	while(!snifferClientService->isStartOk() && !is_terminating()) {
		usleep(100000);
	}
}


void snifferClientStop() {
	if(snifferClientService) {
		delete snifferClientService;
		snifferClientService = NULL;
	}
}
