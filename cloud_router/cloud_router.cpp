#include <getopt.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <syslog.h>
#include <mysql.h>
#include <mysqld_error.h>

#include "cloud_router.h"


#define VERBOSE 1

#define MYSQL_HOST "localhost"
#define MYSQL_USER "root"
#define MYSQL_PASSWORD ""
#define MYSQL_DATABASE "voipmonitor"


static void parse_command_line_arguments(int argc, char *argv[]);
 

sOptions options;
cResolver resolver;
sCR_gui_tasks gui_tasks;
sCR_sniffer_services sniffer_services;
bool TERMINATE = false;


int main(int argc, char *argv[]) {

	/*
	cCloudMysqlServer *mysql = new cCloudMysqlServer();
	cout <<mysql->query("select content from `system` where type='timezone_info_local_sensor'") << endl;
	delete mysql;
	return(0);
	*/
 
	openlog("cloud_router", LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);
	parse_command_line_arguments(argc, argv);
	if(options.server) {
		cCR_Server *cr_server =  new cCR_Server;
		cr_server->listen_start("server", options.host, options.port);
	}
	if(options.client) {
		cCR_Receiver_service *receiverService =  new cCR_Receiver_service("abcd", 1);
		receiverService->start(options.host, options.port);
	}
	while(!TERMINATE) {
		usleep(1000);
	}
	return(0);
}


void parse_command_line_arguments(int argc, char *argv[]) {
	option long_options[] = {
		{"server", 1, 0, 'S'},
		{"client", 1, 0, 'C'},
		{0, 0, 0, 0}
	};
	string argOptions;
	string noArgOptions;
	for(unsigned i = 0; long_options[i].name; i++) {
		if(long_options[i].val >= '0' && long_options[i].val <= 'z') {
			if(long_options[i].has_arg == 1) {
				argOptions += (char)long_options[i].val;
				argOptions += ':';
			} else {
				noArgOptions += (char)long_options[i].val;
			}
		}
	}
	int option_index = 0;
	int option_character = 0;
	while((option_character = getopt_long(argc, argv, (argOptions + noArgOptions).c_str(), long_options, &option_index)) != -1) {
		switch(option_character) {
		case 'S':
			options.server = true;
			break;
		case 'C':
			options.client = true;
			break;
		}
		switch(option_character) {
		case 'S':
		case 'C':
			if(optarg && *optarg) {
				const char *hostPortSeparator = strchr(optarg, ':');
				if(hostPortSeparator) {
					options.host = string(optarg, hostPortSeparator - optarg);
					options.port = atol(hostPortSeparator + 1);
				}
			}
		}
		
	}
}


cResolver::cResolver() {
	use_lock = true;
	res_timeout = 120;
	_sync_lock = 0;
}

u_int32_t cResolver::resolve(const char *host) {
	if(use_lock) {
		lock();
	}
	u_int32_t ipl = 0;
	time_t now = time(NULL);
	map<string, sIP_time>::iterator iter_find = res_table.find(host);
	if(iter_find != res_table.end() &&
	   iter_find->second.at + 120 > now) {
		ipl = iter_find->second.ipl;
	}
	if(!ipl) {
		hostent *rslt_hostent = gethostbyname(host);
		if(rslt_hostent) {
			ipl = ((in_addr*)rslt_hostent->h_addr)->s_addr;
			if(ipl) {
				res_table[host].ipl = ipl;
				res_table[host].at = now;
			}
		}
	}
	if(use_lock) {
		unlock();
	}
	return(ipl);
}


cSocket::cSocket(const char *name, bool autoClose) {
	if(name) {
		this->name = name;
	}
	this->autoClose = autoClose;
	port = 0;
	ipl = 0;
	handle = -1;
	enableWriteReconnect = false;
	terminate = false;
	error = _se_na;
	writeEncPos = 0;
	readDecPos = 0;
}

cSocket::~cSocket() {
	if(autoClose) {
		close();
	}
}

void cSocket::setHostPort(string host, u_int16_t port) {
	this->host = host;
	this->port = port;
}

void cSocket::setKey(string key) {
	this->key = key;
}

bool cSocket::connect(unsigned loopSleepS) {
	if(VERBOSE) {
		cout << "connect (" << name << ")"
		     << " - " << getHostPort() << endl;
	}
	bool rslt = true;
	unsigned passCounter = 0;
	do {
		++passCounter;
		if(passCounter > 1 && loopSleepS) {
			logError();
			sleep(loopSleepS);
		}
		rslt = true;
		clearError();
		if(!ipl) {
			ipl = resolver.resolve(host);
			if(!ipl) {
				setError("failed resolve host name %s", host.c_str());
				rslt = false;
				continue;
			}
		}
		if((handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
			setError("cannot create socket");
			rslt = false;
			continue;
		}
		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = ipl;
		if(::connect(handle, (sockaddr*)&addr, sizeof(addr)) == -1) {
			setError("failed to connect to server [%s] error:[%s]", host.c_str(), strerror(errno));
			close();
			rslt = false;
			continue;
		}
		int on = 1;
		setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int));
		int flags = fcntl(handle, F_GETFL, 0);
		if(flags >= 0) {
			fcntl(handle, F_SETFL, flags | O_NONBLOCK);
		}
	} while(!rslt && loopSleepS && !(terminate || TERMINATE));
	if(!rslt) {
		logError();
	}
	return(true);
}

bool cSocket::listen() {
	if(!ipl) {
		ipl = resolver.resolve(host);
		if(!ipl) {
			setError("failed resolve host name %s", host);
			return(false);
		}
	}
	if((handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		setError("cannot create socket");
		return(false);
	}
	int flags = fcntl(handle, F_GETFL, 0);
	if(flags >= 0) {
		fcntl(handle, F_SETFL, flags | O_NONBLOCK);
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ipl;
	int on = 1;
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	int rsltListen;
	do {
		while(bind(handle, (sockaddr*)&addr, sizeof(addr)) == -1 && !terminate) {
			setError("cannot bind to port [%d] - trying again after 5 seconds", port);
			sleep(5);
		}
		if(terminate) {
			return(false);
		}
		rsltListen = ::listen(handle, 5);
		if(rsltListen == -1) {
			setError("listen failed - trying again after 5 seconds");
			sleep(5);
		}
	} while(rsltListen == -1);
	return(true);
}

void cSocket::close() {
	if(okHandle()) {
		if(VERBOSE) {
			cout << "close (" << name << ")"
			     << " - " << getHostPort() << endl;
		}
		::close(handle);
		handle = -1;
	}
}

bool cSocket::await(cSocket **clientSocket) {
	if(isError() || !okHandle()) {
		setError(_se_bad_connection);
		return(false);
	}
	int clientHandle = -1;
	if(clientSocket) {
		*clientSocket = NULL;
	}
	sockaddr_in clientInfo;
	socklen_t clientInfoLen = sizeof(sockaddr_in);
	while(clientHandle < 0 && !terminate) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(handle, &rfds);
		struct timeval tv;
		tv.tv_sec = timeouts.await;
		tv.tv_usec = 0;
		if(select(handle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
			clientHandle = accept(handle, (sockaddr*)&clientInfo, &clientInfoLen);
			int flags = fcntl(clientHandle, F_GETFL, 0);
			if(flags >= 0) {
				fcntl(clientHandle, F_SETFL, flags | O_NONBLOCK);
			}
			if(clientSocket) {
				*clientSocket = new cSocket("client/await");
				(*clientSocket)->host = inet_ntoa(clientInfo.sin_addr);
				(*clientSocket)->port = htons(clientInfo.sin_port);
				(*clientSocket)->ipl = clientInfo.sin_addr.s_addr;
				(*clientSocket)->handle = clientHandle;
			}
		}
	}
	return(clientHandle >= 0);
}

bool cSocket::write(u_char *data, size_t dataLen) {
	if(isError() || !okHandle()) {
		setError(_se_bad_connection);
		return(false);
	}
	size_t dataLenWrited = 0;
	while(dataLenWrited < dataLen && !terminate) {
		size_t _dataLen = dataLen - dataLenWrited;
		if(!_write(data + dataLenWrited, &_dataLen)) {
			if(enableWriteReconnect) {
				close();
				while(!terminate && !connect()) {
					sleep(1);
				}
			} else {
				return(false);
			}
		} else {
			dataLenWrited += _dataLen;
		}
	}
	return(true);
}

bool cSocket::write(const char *data) {
	return(write((u_char*)data, strlen(data)));
}

bool cSocket::write(string &data) {
	return(write((u_char*)data.c_str(), data.length()));
}

bool cSocket::_write(u_char *data, size_t *dataLen) {
	if(isError() || !okHandle()) {
		*dataLen = 0;
		setError(_se_bad_connection);
		return(false);
	}
	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(handle, &wfds);
	struct timeval tv;
	tv.tv_sec = timeouts.write;
	tv.tv_usec = 0;
	int rsltSelect = select(handle + 1, (fd_set *) 0, &wfds, (fd_set *) 0, &tv);
	if(rsltSelect < 0) {
		*dataLen = 0;
		return(false);
	}
	if(rsltSelect > 0 && FD_ISSET(handle, &wfds)) {
		ssize_t sendLen = send(handle, data, *dataLen, 0);
		if(sendLen > 0) {
			*dataLen = sendLen;
		} else {
			*dataLen = 0;
			return(false);
		}
	} else {
		*dataLen = 0;
	}
	return(true);
}

bool cSocket::read(u_char *data, size_t *dataLen) {
	if(isError() || !okHandle()) {
		*dataLen = 0;
		setError(_se_bad_connection);
		return(false);
	}
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(handle, &rfds);
	struct timeval tv;
	tv.tv_sec = timeouts.read;
	tv.tv_usec = 0;
	int rsltSelect = select(handle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
	if(rsltSelect < 0) {
		*dataLen = 0;
		setError(_se_bad_connection);
		return(false);
	}
	if(rsltSelect > 0 && FD_ISSET(handle, &rfds)) {
		ssize_t recvLen = recv(handle, data, *dataLen, 0);
		if(recvLen > 0) {
			*dataLen = recvLen;
		} else {
			*dataLen = 0;
			if(errno != EWOULDBLOCK) {
				setError(_se_bad_connection);
				return(false);
			}
		}
	} else {
		*dataLen = 0;
	}
	return(true);
}

bool cSocket::writeEnc(u_char *data, size_t dataLen) {
	u_char *dataEnc = new u_char[dataLen];
	memcpy(dataEnc, data, dataLen);
	encodeWriteBuffer(dataEnc, dataLen);
	bool rsltWrite = write(dataEnc, dataLen);
	delete [] dataEnc;
	if(rsltWrite) {
		writeEncPos += dataLen;
	}
	return(rsltWrite);
}

bool cSocket::readDec(u_char *data, size_t *dataLen) {
	bool rsltRead = read(data, dataLen);
	if(rsltRead && *dataLen) {
		decodeReadBuffer(data, *dataLen);
	}
	return(rsltRead);
}

void cSocket::encodeWriteBuffer(u_char *data, size_t dataLen) {
	xorData(data, dataLen, key.c_str(), key.length(), writeEncPos);
}

void cSocket::decodeReadBuffer(u_char *data, size_t dataLen) {
	xorData(data, dataLen, key.c_str(), key.length(), readDecPos);
	readDecPos += dataLen;
}

bool cSocket::checkHandleRead() {
	if(!okHandle()) {
		return(false);
	}
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(handle, &rfds);
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	int rsltSelect = select(handle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
	if(rsltSelect < 0) {
		return(false);
	}
	if(rsltSelect > 0 && FD_ISSET(handle, &rfds)) {
		u_char buffer[10];
		ssize_t recvLen = recv(handle, buffer, 10, 0);
		if(!recvLen && errno != EWOULDBLOCK) {
			return(false);
		}
	}
	return(true);
	
}

bool cSocket::checkHandleWrite() {
	if(!okHandle()) {
		return(false);
	}
	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(handle, &wfds);
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1000;
	int rsltSelect = select(handle + 1, (fd_set *) 0, &wfds, (fd_set *) 0, &tv);
	if(rsltSelect < 0) {
		return(false);
	}
	return(true);
	
}

void cSocket::logError() {
	if(isError()) {
		syslog(LOG_ERR, "%s%s%s", 
		       name.c_str(),
		       name.empty() ? "" : " - ",
		       getError().c_str());
	}
}

void cSocket::setError(eSocketError error) {
	if(isError()) {
		return;
	}
	this->error = error;
}

void cSocket::setError(const char *formatError, ...) {
	if(isError()) {
		return;
	}
	error = _se_error_str;
	unsigned error_buffer_length = 1024*1024;
	char *error_buffer = new char[error_buffer_length];
	va_list args;
	va_start(args, formatError);
	vsnprintf(error_buffer, error_buffer_length, formatError, args);
	va_end(args);
	error_str = error_buffer;
	delete [] error_buffer;
}

void cSocket::clearError() {
	error = _se_na;
	error_str.resize(0);
}

void cSocket::sleep(int s) {
	int sx10 = s * 10;
	while(sx10 > 0 && !terminate) {
		usleep(100000);
		sx10 -= 1;
	}
}


cSocketBlock::cSocketBlock(const char *name, bool autoClose)
 : cSocket(name, autoClose) {
       
}

bool cSocketBlock::writeBlock(u_char *data, size_t dataLen, string key) {
	u_char *block = new u_char[sizeof(sBlockHeader) + dataLen];
	((sBlockHeader*)block)->init();
	((sBlockHeader*)block)->length = dataLen;
	((sBlockHeader*)block)->sum = dataSum(data, dataLen);
	memcpy(block + sizeof(sBlockHeader), data, dataLen);
	if(!key.empty()) {
		xorData(block + sizeof(sBlockHeader), dataLen, key.c_str(), key.length(), 0);
	}
	bool rsltWrite = write(block, sizeof(sBlockHeader) + dataLen);
	delete [] block;
	return(rsltWrite);
}

bool cSocketBlock::writeBlock(string str, string key) {
	return(writeBlock((u_char*)str.c_str(), str.length(), key));
}

u_char *cSocketBlock::readBlock(size_t *dataLen, string key) {
	size_t bufferLength = 10 * 1024;
	u_char *buffer = new u_char[bufferLength];
	bool rsltRead = true;
	readBuffer.clear();
	size_t readLength = bufferLength;
	bool blockHeaderOK = false;
	while((rsltRead = read(buffer, &readLength))) {
		if(readLength) {
			readBuffer.add(buffer, readLength);
			if(!blockHeaderOK) {
				if(readBuffer.length >= sizeof(sBlockHeader)) {
					if(readBuffer.okBlockHeader()) {
						blockHeaderOK = true;
					} else {
						rsltRead = false;
						break;
					}
				}
			}
			if(blockHeaderOK) {
				if(readBuffer.length >= readBuffer.lengthBlockHeader(true)) {
					if(!key.empty()) {
						xorData(readBuffer.buffer + sizeof(sBlockHeader), readBuffer.lengthBlockHeader(), key.c_str(), key.length(), 0);
					}
					if(!checkSumReadBuffer()) {
						rsltRead = false;
					}
					break;
				}
			}
		} else {
			usleep(1000);
		}
		readLength = bufferLength;
	}
	delete [] buffer;
	if(rsltRead) {
		*dataLen = readBuffer.lengthBlockHeader();
		return(readBuffer.buffer + sizeof(sBlockHeader));
	} else {
		*dataLen = 0;
		return(NULL);
	}
}

bool cSocketBlock::readBlock(string *str, string key) {
	u_char *data;
	size_t dataLen;
	data = readBlock(&dataLen, key);
	if(data && !isError()) {
		*str = string((char*)data, dataLen);
		return(true);
	} else {
		return(false);
	}
}

string cSocketBlock::readLine(u_char **remainder, size_t *remainder_length) {
	string line;
	size_t bufferLength = 10 * 1024;
	u_char *buffer = new u_char[bufferLength];
	bool rsltRead = true;
	readBuffer.clear();
	size_t readLength = bufferLength;
	while((rsltRead = read(buffer, &readLength))) {
		if(readLength) {
			size_t endLinePos = 0;
			for(size_t i = 0; i < readLength; i++) {
				if(buffer[i] == '\r' || buffer[i] == '\n') {
					endLinePos = i;
					break;
				}
			}
			if(endLinePos) {
				if(remainder) {
					size_t pos = endLinePos;
					while(pos < readLength && 
					      (buffer[pos] == '\r' || buffer[pos] == '\n')) {
						++pos;
					}
					if(pos < readLength) {
						size_t _remainder_length = readLength - pos;
						*remainder = new u_char[_remainder_length];
						memcpy(*remainder, buffer + pos, _remainder_length);
						if(remainder_length) {
							*remainder_length = _remainder_length;
						}
					}
				}
			}
			line += string((char*)buffer, endLinePos ? endLinePos : readLength);
			if(endLinePos) {
				break;
			}
			
		} else {
			usleep(1000);
		}
		readLength = bufferLength;
	}
	delete [] buffer;
	return(line);
}

bool cSocketBlock::checkSumReadBuffer() {
	return(readBuffer.sumBlockHeader() ==
	       dataSum(readBuffer.buffer + sizeof(sBlockHeader), readBuffer.length - sizeof(sBlockHeader)));
}

u_int32_t cSocketBlock::dataSum(u_char *data, size_t dataLen) {
	u_int32_t sum = 0;
	for(size_t i = 0; i < dataLen; i++) {
		sum += data[i];
	}
	return(sum);
}


cServer::cServer() {
	listen_socket = NULL;
}

cServer::~cServer() {
	if(listen_socket) {
		listen_socket->close();
		delete listen_socket;
		listen_socket = NULL;
	}
}

bool cServer::listen_start(const char *name, string host, u_int16_t port) {
	listen_socket = new cSocketBlock(name);
	listen_socket->setHostPort(host, port);
	if(!listen_socket->listen()) {
		delete listen_socket;
		listen_socket = NULL;
		return(false);
	}
	vm_pthread_create_autodestroy("cServer::listen_start", &listen_thread, NULL, cServer::listen_process, this, __FILE__, __LINE__);
	return(true);
}

void *cServer::listen_process(void *arg) {
	if(VERBOSE) {
		cout << "START SERVER LISTEN" << endl;
	}
	((cServer*)arg)->listen_process();
	return(NULL);
}

void cServer::listen_process() {
	cSocket *clientSocket;
	while(!((listen_socket && listen_socket->isTerminate()) || TERMINATE)) {
		if(listen_socket->await(&clientSocket)) {
			if(VERBOSE) {
				cout << "NEW CONNECTION FROM: " 
				     << clientSocket->getIP() << " : " << clientSocket->getPort()
				     << endl;
			}
			createConnection(clientSocket);
		}
	}
}

void cServer::createConnection(cSocket *socket) {
	cServerConnection *connection = new cServerConnection(socket);
	connection->connection_start();
}


cServerConnection::cServerConnection(cSocket *socket) {
	this->socket = new cSocketBlock(NULL);
	*(cSocket*)this->socket = *socket;
	delete socket;
}

cServerConnection::~cServerConnection() {
	if(socket) {
		socket->close();
		delete socket;
	}
}

bool cServerConnection::connection_start() {
	vm_pthread_create_autodestroy("cServerConnection::connection_start", &thread, NULL, cServerConnection::connection_process, this, __FILE__, __LINE__);
	return(true);
}

void *cServerConnection::connection_process(void *arg) {
	((cServerConnection*)arg)->connection_process();
	return(NULL);
}

void cServerConnection::connection_process() {
	while(!((socket && socket->isTerminate()) || TERMINATE)) {
		u_char *data;
		size_t dataLen;
		data = socket->readBlock(&dataLen);
		if(data) {
			evData(data, dataLen);
		} else {
			usleep(1000);
		}
	}
}

void cServerConnection::evData(u_char *data, size_t dataLen) {
}


cReceiver::cReceiver() {
	receive_socket = NULL;
}

cReceiver::~cReceiver() {
	if(receive_socket) {
		receive_socket->close();
		delete receive_socket;
		receive_socket = NULL;
	}
}

bool cReceiver::receive_start(string host, u_int16_t port) {
	if(!_connect(host, port, 5)) {
		return(false);
	}
	_receive_start();
	return(true);
}

bool cReceiver::_connect(string host, u_int16_t port, unsigned loopSleepS) {
	if(!receive_socket) {
		receive_socket = new cSocketBlock("receiver");
		receive_socket->setHostPort(host, port);
		if(!receive_socket->connect(loopSleepS)) {
			_close();
			return(false);
		}
	}
	return(true);
}

void cReceiver::_close() {
	if(receive_socket) {
		delete receive_socket;
		receive_socket = NULL;
	}
}

void cReceiver::_receive_start() {
	vm_pthread_create_autodestroy("cReceiver::receive_start", &receive_thread, NULL, cReceiver::receive_process, this, __FILE__, __LINE__);
}

void *cReceiver::receive_process(void *arg) {
	((cReceiver*)arg)->receive_process();
	return(NULL);
}

void cReceiver::receive_process() {
	while(!((receive_socket && receive_socket->isTerminate()) || TERMINATE)) {
		if(receive_process_loop_begin()) {
			u_char *data;
			size_t dataLen;
			data = receive_socket->readBlock(&dataLen);
			if(data) {
				evData(data, dataLen);
			}
		} else {
			sleep(1);
		}
	}
}

bool cReceiver::receive_process_loop_begin() {
	return(true);
}

void cReceiver::evData(u_char *data, size_t dataLen) {
}


cClient::cClient() {
	client_socket = NULL;
}

cClient::~cClient() {
	if(client_socket) {
		client_socket->close();
		delete client_socket;
		client_socket = NULL;
	}
}

bool cClient::client_start(string host, u_int16_t port) {
	if(!_connect(host, port)) {
		return(false);
	}
	_client_start();
	return(true);
}

bool cClient::_connect(string host, u_int16_t port) {
	if(!client_socket) {
		client_socket = new cSocketBlock("client");
		client_socket->setHostPort(host, port);
		if(!client_socket->connect()) {
			delete client_socket;
			client_socket = NULL;
			return(false);
		}
	}
	return(true);
}

void cClient::_client_start() {
	vm_pthread_create_autodestroy("cClient::client_start", &client_thread, NULL, cClient::client_process, this, __FILE__, __LINE__);
}

void *cClient::client_process(void *arg) {
	((cClient*)arg)->client_process();
	return(NULL);
}

void cClient::client_process() {
}


//-------------------------------------


sCR_gui_tasks::sCR_gui_tasks() {
	_sync_lock = 0;
}

void sCR_gui_tasks::add(sCR_gui_task *task) {
	lock();
	tasks[task->id] = *task;
	unlock();
}

void sCR_gui_tasks::remove(sCR_gui_task *task) {
	remove(task->id);
}

void sCR_gui_tasks::remove(u_int64_t id) {
	lock();
	map<u_int64_t, sCR_gui_task>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		tasks.erase(iter);
	}
	unlock();
}

cCR_ServerConnection *sCR_gui_tasks::getGuiConnection(u_int64_t id) {
	cCR_ServerConnection *connection = NULL;
	lock();
	map<u_int64_t, sCR_gui_task>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		connection = iter->second.gui_connection;
	}
	unlock();
	return(connection);
}

string sCR_gui_tasks::getToken(u_int64_t id) {
	string token;
	lock();
	map<u_int64_t, sCR_gui_task>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		token = iter->second.token;
	}
	unlock();
	return(token);
}

sCR_gui_task::eTaskState sCR_gui_tasks::getTaskState(u_int64_t id) {
	sCR_gui_task::eTaskState state = sCR_gui_task::_na;
	lock();
	map<u_int64_t, sCR_gui_task>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		state = iter->second.state;
	}
	unlock();
	return(state);
}

void sCR_gui_tasks::setTaskState(u_int64_t id, sCR_gui_task::eTaskState state) {
	lock();
	map<u_int64_t, sCR_gui_task>::iterator iter = tasks.find(id);
	if(iter != tasks.end()) {
		iter->second.state = state;
	}
	unlock();
}


sCR_sniffer_services::sCR_sniffer_services() {
	_sync_lock = 0;
}

void sCR_sniffer_services::add(sCR_sniffer_service *service) {
	lock();
	string idService = getIdService(service);
	map<string, sCR_sniffer_service>::iterator iter = services.find(idService);
	if(iter != services.end()) {
		delete iter->second.service_connection;
	}
	services[idService] = *service;
	unlock();
}

void sCR_sniffer_services::remove(sCR_sniffer_service *service) {
	lock();
	string idService = getIdService(service);
	map<string, sCR_sniffer_service>::iterator iter = services.find(idService);
	if(iter != services.end()) {
		services.erase(iter);
	}
	unlock();
}

string sCR_sniffer_services::getIdService(sCR_sniffer_service *service) {
	return(getIdService(service->token, service->sensor_id));
}

string sCR_sniffer_services::getIdService(string token, int32_t sensor_id) {
	return(token + "/" + intToString(sensor_id));
}

cCR_ServerConnection *sCR_sniffer_services::getServiceConnection(string token, int32_t sensor_id) {
	cCR_ServerConnection *connection = NULL;
	lock();
	map<string, sCR_sniffer_service>::iterator iter = services.find(getIdService(token, sensor_id));
	if(iter != services.end()) {
		connection = iter->second.service_connection;
	}
	unlock();
	return(connection);
}


void cCR_Server::createConnection(cSocket *socket) {
	cCR_ServerConnection *connection = new cCR_ServerConnection(socket);
	connection->connection_start();
}


cCR_ServerConnection::cCR_ServerConnection(cSocket *socket) 
 : cServerConnection(socket) {
	typeConnection = _tc_na;
	sensor_id = 0;
	gui_task_id = 0;
	_sync_tasks = 0;
}

void cCR_ServerConnection::connection_process() {
	JsonItem jsonData;
	u_char *remainder = NULL;
	size_t remainder_length = 0;
	if(typeConnection == _tc_na) {
		string str = socket->readLine(&remainder, &remainder_length);
		if(!str.empty()) {
			jsonData.parse(str.c_str());
			typeConnection = convTypeConnection(jsonData.getValue("type_connection"));
		}
		if(VERBOSE) {
			cout << "CONNECTION PROCESS CMD: "
			     << str 
			     << endl;
		}
	}
	if(typeConnection != _tc_sniffer_response && remainder) {
		delete [] remainder;
	}
	switch(typeConnection) {
	case _tc_gui_command:
		token = jsonData.getValue("token");
		sensor_id = atol(jsonData.getValue("sensor_id").c_str());
		cp_gui_command(jsonData.getValue("command"));
		break;
	case _tc_sniffer_service:
		cp_sniffer_service();
		break;
	case _tc_sniffer_response:
		gui_task_id = atol(jsonData.getValue("gui_task_id").c_str());
		cp_sniffer_respone(remainder, remainder_length);
		break;
	case _tc_sniffer_sql_query:
		token = jsonData.getValue("token");
		cp_sniffer_sql_query();
		break;
	default:
		delete this;
		break;
	}
}

void cCR_ServerConnection::evData(u_char *data, size_t dataLen) {
}

void cCR_ServerConnection::addTask(sCR_gui_task task) {
	lock_tasks();
	tasks.push(task);
	unlock_tasks();
}

sCR_gui_task cCR_ServerConnection::getTask() {
	sCR_gui_task task;
	lock_tasks();
	if(tasks.size()) {
		task = tasks.front();
		tasks.pop();
	}
	unlock_tasks();
	return(task);
}

void cCR_ServerConnection::cp_gui_command(string command) {
	// TODO: check token
	if(VERBOSE) {
		cout << "GUI COMAND: "
		     << "token: " << token << ", "
		     << "sensor_id: " << sensor_id << ", "
		     << "command: " << command << ", "
		     << endl;
	}
	cCR_ServerConnection *service_connection = sniffer_services.getServiceConnection(token, sensor_id);
	if(!service_connection) {
		socket->write("missing sniffer service - connect sensor?");
		delete this;
		return;
	}
	if(VERBOSE) {
		cout << "FIND SERVICE CONNECTION: "
		     << "addr: " << service_connection
		     << endl;
	}
	sCR_gui_task task;
	task.token = token;
	task.sensor_id = sensor_id;
	task.command = command;
	task.setIdTime();
	task.gui_connection = this;
	gui_tasks.add(&task);
	service_connection->addTask(task);
	u_int64_t startTime = getTimeUS();
	while(gui_tasks.getTaskState(task.id) != sCR_gui_task::_complete) {
		usleep(1000);
		if(getTimeUS() > startTime + 5 * 60 * 1000000ull) {
			socket->write("timeout");
			break;
		}
	}
	gui_tasks.remove(&task);
	delete this;
}

void cCR_ServerConnection::cp_sniffer_service() {
	if(!socket->writeBlock("OK")) {
		socket->setError("failed send command ok");
		delete this;
		return;
	}
	string connectData;
	if(!socket->readBlock(&connectData)) {
		socket->setError("failed read connection data");
		delete this;
		return;
	}
	if(!socket->writeBlock("OK")) {
		socket->setError("failed send connection data ok");
		delete this;
		return;
	}
	// TODO: decrypt token
	JsonItem jsonData;
	jsonData.parse(connectData);
	token = jsonData.getValue("token");
	sensor_id = atol(jsonData.getValue("sensor_id").c_str());
	// TODO: check token
	if(VERBOSE) {
		cout << "SNIFFER SERVICE START: "
		     << "token: " << token << ", "
		     << "sensor_id: " << sensor_id << ", "
		     << endl;
	}
	sCR_sniffer_service service;
	service.token = token;
	service.sensor_id = sensor_id;
	service.service_connection = this;
	sniffer_services.add(&service);
	while(true) {
		if(!socket->checkHandleRead()) {
			if(VERBOSE) {
				cout << "SNIFFER SERVICE STOP: "
				     << "token: " << token << ", "
				     << "sensor_id: " << sensor_id << ", "
				     << endl;
			}
			break;
		}
		usleep(1000);
		sCR_gui_task task = getTask();
		if(task.id) {
			string idCommand = intToString(task.id) + "/" + task.command;
			socket->writeBlock(idCommand);
		}
	}
	sniffer_services.remove(&service);
	delete this;
}

void cCR_ServerConnection::cp_sniffer_respone(u_char *remainder, size_t remainder_length) {
	cCR_ServerConnection *gui_connection = gui_tasks.getGuiConnection(gui_task_id);
	if(VERBOSE) {
		cout << "SNIFFER RESPONSE: "
		     << "gui_task_id: " << gui_task_id << ", "
		     << "gui_connection: " << gui_connection << ", "
		     << endl;
	}
	if(!gui_connection) {
		if(remainder) {
			delete [] remainder;
		}
		delete this;
		return;
	}
	string key = gui_tasks.getToken(gui_task_id);
	socket->setKey(key);
	if(remainder) {
		socket->decodeReadBuffer(remainder, remainder_length);
		gui_connection->socket->write(remainder, remainder_length);
	}
	size_t bufferLen = 1000;
	u_char *buffer = new u_char[bufferLen];
	while(true) {
		size_t len = bufferLen;
		if(socket->readDec(buffer, &len)) {
			if(len) {
				gui_connection->socket->write(buffer, len);
			}
		} else {
			gui_tasks.setTaskState(gui_task_id, sCR_gui_task::_complete);
			break;
		}
	}
	delete [] buffer;
	if(remainder) {
		delete [] remainder;
	}
	delete this;
}

void cCR_ServerConnection::cp_sniffer_sql_query() {
	if(!socket->writeBlock("OK")) {
		socket->setError("failed send command ok");
		delete this;
		return;
	}
	string connectData;
	if(!socket->readBlock(&connectData)) {
		socket->setError("failed read connection data");
		delete this;
		return;
	}
	if(!socket->writeBlock("OK")) {
		socket->setError("failed send connection data ok");
		delete this;
		return;
	}
	// TODO: decrypt token
	JsonItem jsonData;
	jsonData.parse(connectData);
	token = jsonData.getValue("token");
	// TODO: check token
	if(VERBOSE) {
		cout << "SQL QUERY: "
		     << "token: " << token << ", "
		     << endl;
	}
	// TODO: find database via token
	cCloudMysqlServer *mysql = new cCloudMysqlServer(MYSQL_DATABASE);
	string query;
	while(socket->readBlock(&query, token)) {
		if(!query.empty()) {
			string rsltQuery = mysql->query(query);
			socket->writeBlock(rsltQuery, token);
		}
	}
	delete mysql;
	delete this;
}

cCR_ServerConnection::cCR_TypeConnection cCR_ServerConnection::convTypeConnection(string typeConnection) {
	if(typeConnection == "gui_command") {
		return(_tc_gui_command);
	} else if(typeConnection == "sniffer_service") {
		return(_tc_sniffer_service);
	} else if(typeConnection == "sniffer_response") {
		return(_tc_sniffer_response);
	} else if(typeConnection == "sniffer_sql_query") {
		return(_tc_sniffer_sql_query);
	} else {
		return(_tc_na);
	}
}


cCR_Receiver_service::cCR_Receiver_service(const char *token, int32_t sensor_id) {
	this->token = token;
	this->sensor_id = sensor_id;
	port = 0;
	connection_ok = false;
}

bool cCR_Receiver_service::start(string host, u_int16_t port) {
	this->host = host;
	this->port = port;
	_receive_start();
	return(true);
}

bool cCR_Receiver_service::receive_process_loop_begin() {
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
	string connectCmd = "{\"type_connection\":\"sniffer_service\"}\r\n";
	if(!receive_socket->write(connectCmd)) {
		if(receive_socket->isError()) {
			receive_socket->logError();
		} else {
			receive_socket->setError("failed send command sniffer_service");
		}
		_close();
		return(false);
	}
	string rsltConnectCmd;
	if(!receive_socket->readBlock(&rsltConnectCmd) || rsltConnectCmd != "OK") {
		if(receive_socket->isError()) {
			receive_socket->logError();
		} else {
			receive_socket->setError("failed read command ok");
		}
		_close();
		return(false);
	}
	// TODO: encrypt token
	string connectData = "{\"token\":\"" + token + "\",\"sensor_id\":" + intToString(sensor_id) + "}";
	if(!receive_socket->writeBlock(connectData)) {
		if(receive_socket->isError()) {
			receive_socket->logError();
		} else {
			receive_socket->setError("failed send connection data");
		}
		_close();
		return(false);
	}
	string rsltConnectData;
	if(!receive_socket->readBlock(&rsltConnectData) || rsltConnectData != "OK") {
		if(receive_socket->isError()) {
			receive_socket->logError();
		} else {
			receive_socket->setError("failed read connection data ok");
		}
		_close();
		return(false);
	}
	connection_ok = true;
	if(VERBOSE) {
		cout << "START SNIFFER SERVICE" << endl;
	}
	return(true);
}

void cCR_Receiver_service::evData(u_char *data, size_t dataLen) {
	receive_socket->writeBlock("OK");
	string idCommand = string((char*)data, dataLen);
	size_t idCommandSeparatorPos = idCommand.find('/'); 
	if(idCommandSeparatorPos != string::npos) {
		cCR_Client_response *response = new cCR_Client_response(idCommand.c_str() + idCommandSeparatorPos + 1, atoll(idCommand.c_str()));
		response->start(receive_socket->getHost(), receive_socket->getPort());
	}
}


cCR_Client_response::cCR_Client_response(const char *command, u_int64_t gui_task_id) {
	this->command = command;
	this->gui_task_id = gui_task_id;
}

bool cCR_Client_response::start(string host, u_int16_t port) {
	if(!_connect(host, port)) {
		return(false);
	}
	string connectCmd = "{\"type_connection\":\"sniffer_response\",\"gui_task_id\":" + intToString(gui_task_id) + "}\r\n";
	if(!client_socket->write(connectCmd)) {
		delete client_socket;
		client_socket = NULL;
		return(false);
	}
	
	_client_start();
	
	return(true);
	
}

void cCR_Client_response::client_process() {
	extern int parse_command(string cmd, int client, cCR_Client_response *cr_client);
	parse_command(command, 0, this);
	delete this;
}

bool cCR_Client_response::write(u_char *data, size_t dataLen) {
	return(client_socket->write(data, dataLen));
}

bool cCR_Client_response::writeEnc(u_char *data, size_t dataLen, const char *key) {
	client_socket->setKey(key);
	return(client_socket->writeEnc(data, dataLen));
}


cCloudMysqlServer::cCloudMysqlServer(string database) {
	this->database = database;
	hMysql = NULL;
	hMysqlConn = NULL;
	errorCode = 0;
}

cCloudMysqlServer::~cCloudMysqlServer() {
	disconnect();
}

bool cCloudMysqlServer::connect() {
	hMysql = mysql_init(NULL);
	if(!hMysql) {
		errorCode = 0;
		errorStr = "mysql_init failed - insufficient memory ?";
		disconnect();
		return(false);
	}
	hMysqlConn = mysql_real_connect(hMysql, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, NULL,
					3306,
					NULL, 0);
	if(!hMysqlConn) {
		errorCode = mysql_errno(hMysql);
		errorStr = mysql_error(hMysql);
		disconnect();
		return(false);
	}
	if(mysql_query(hMysqlConn, "SET NAMES UTF8") ||
	   mysql_query(hMysqlConn, "SET sql_mode = ''") ||
	   mysql_query(hMysqlConn, (string("USE ") + database).c_str())) {
		errorCode = mysql_errno(hMysqlConn);
		errorStr = mysql_error(hMysqlConn);
		disconnect();
		return(false);
	}
	return(true);
}

void cCloudMysqlServer::disconnect() {
	if(hMysqlConn) {
		mysql_close(hMysqlConn);
		hMysqlConn = NULL;
	}
	hMysql = NULL;
}

string cCloudMysqlServer::query(string query) {
	clearError();
	vector<string> rslt_fields;
	map<string, string> rslt_row;
	vector<map<string, string>> rslt_rows;
	if(!hMysql) {
		connect();
	}
	if(hMysql) {
		if(!mysql_query(hMysqlConn, query.c_str())) {
			MYSQL_RES *hMysqlRes = mysql_use_result(hMysqlConn);
			if(hMysqlRes) {
				MYSQL_FIELD *field;
				for(int i = 0; (field = mysql_fetch_field(hMysqlRes)); i++) {
					rslt_fields.push_back(field->name);
				}
				MYSQL_ROW mysqlRow;
				while((mysqlRow = mysql_fetch_row(hMysqlRes))) {
					unsigned int numFields = mysql_num_fields(hMysqlRes);
					for(unsigned int i = 0; i < numFields; i++) {
						rslt_row[rslt_fields[i]] = mysqlRow[i] ? mysqlRow[i] : "NULL";
					}
					rslt_rows.push_back(rslt_row);
				}
				mysql_free_result(hMysqlRes);
			}
		} else {
			errorCode = mysql_errno(hMysql);
			errorStr = mysql_error(hMysql);
			disconnect();
		}
	}
	JsonExport exp;
	if(!errorCode && errorStr.empty()) {
		exp.add("result", "OK");
		if(rslt_rows.size()) {
			exp.add("data_rows", rslt_rows.size());
			JsonExport *expData = exp.addArray("data");
			for(size_t i = 0; i < rslt_rows.size(); i++) {
				if(i == 0) {
					JsonExport *desc = expData->addArray(NULL);
					for(size_t j = 0; j < rslt_fields.size(); j++) {
						desc->add(NULL, rslt_fields[j]);
					}
				}
				JsonExport *row = expData->addArray(NULL);
				for(size_t j = 0; j < min(rslt_rows[i].size(), rslt_fields.size()); j++) {
					row->add(NULL, rslt_rows[i][rslt_fields[j]]);
				}
			}
		}
	} else {
		exp.add("result", intToString(errorCode) + "|" + 
				  intToString((u_int16_t)(errorCode == ER_PARSE_ERROR ? 0 : 1)) + "|" + 
				  errorStr);
	}
	return(exp.getJson());
}

void cCloudMysqlServer::clearError() {
	errorCode = 0;
	errorStr = "";
}
