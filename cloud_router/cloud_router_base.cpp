#include "cloud_router_base.h"

#include <netdb.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <iostream>
#include <sstream>
#include <syslog.h>
#include <stdarg.h>


extern cResolver *CR_RESOLVER();
extern bool CR_TERMINATE();
extern sCloudRouterVerbose CR_VERBOSE();


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
	if(CR_VERBOSE().socket_connect) {
		ostringstream verbstr;
		verbstr << "connect (" << name << ")"
			<< " - " << getHostPort();
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
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
			ipl = CR_RESOLVER()->resolve(host);
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
	} while(!rslt && loopSleepS && !(terminate || CR_TERMINATE()));
	if(!rslt) {
		logError();
	}
	return(true);
}

bool cSocket::listen() {
	if(!ipl) {
		ipl = CR_RESOLVER()->resolve(host);
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
		if(CR_VERBOSE().socket_connect) {
			ostringstream verbstr;
			verbstr << "close (" << name << ")"
				<< " - " << getHostPort();
			syslog(LOG_INFO, "%s", verbstr.str().c_str());
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
	if(CR_VERBOSE().start_server) {
		ostringstream verbstr;
		verbstr << "START SERVER LISTEN";
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	((cServer*)arg)->listen_process();
	return(NULL);
}

void cServer::listen_process() {
	cSocket *clientSocket;
	while(!((listen_socket && listen_socket->isTerminate()) || CR_TERMINATE())) {
		if(listen_socket->await(&clientSocket)) {
			if(CR_VERBOSE().connect_info) {
				ostringstream verbstr;
				verbstr << "NEW CONNECTION FROM: " 
					<< clientSocket->getIP() << " : " << clientSocket->getPort();
				syslog(LOG_INFO, "%s", verbstr.str().c_str());
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
	while(!((socket && socket->isTerminate()) || CR_TERMINATE())) {
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
	while(!((receive_socket && receive_socket->isTerminate()) || CR_TERMINATE())) {
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
