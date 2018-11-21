#include "cloud_router_base.h"

#include <netdb.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <iostream>
#include <sstream>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/poll.h>


extern bool CR_TERMINATE();
extern void CR_SET_TERMINATE();
extern sCloudRouterVerbose& CR_VERBOSE();
extern bool opt_socket_use_poll;
extern cResolver resolver;


cRsa::cRsa() {
	priv_rsa = NULL;
	pub_rsa = NULL;
	padding = RSA_PKCS1_PADDING;
}

cRsa::~cRsa() {
	if(priv_rsa) {
		RSA_free(priv_rsa);
	}
	if(pub_rsa) {
		RSA_free(pub_rsa);
	}
}

void cRsa::generate_keys() {
	RSA *rsa = RSA_generate_key(2048, RSA_F4, 0, 0);
	// priv key
	BIO *priv_key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(priv_key_bio, rsa, NULL, NULL, 0, NULL, NULL);
	int priv_key_length = BIO_pending(priv_key_bio);
	char *priv_key_buffer = new char[priv_key_length];
	BIO_read(priv_key_bio, priv_key_buffer, priv_key_length);
	priv_key = string(priv_key_buffer, priv_key_length);
	delete [] priv_key_buffer;
	BIO_free_all(priv_key_bio);
	// pub key
	BIO *pub_key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSA_PUBKEY(pub_key_bio, rsa);
	int pub_key_length = BIO_pending(pub_key_bio);
	char *pub_key_buffer = new char[pub_key_length];
	BIO_read(pub_key_bio, pub_key_buffer, pub_key_length);
	pub_key_gener = string(pub_key_buffer, pub_key_length);
	pub_key = pub_key_gener;
	delete [] pub_key_buffer;
	BIO_free_all(pub_key_bio);
	//
	RSA_free(rsa);
}

RSA *cRsa::create_rsa(const char *key, eTypeKey typeKey) {
	BIO *key_bio = BIO_new_mem_buf((void*)key, -1);
	if(!key_bio) {
		return(NULL);
	}
	RSA *rsa = NULL;
	if(typeKey == _private) {
		rsa = PEM_read_bio_RSAPrivateKey(key_bio, &rsa, NULL, NULL);
	} else {
		rsa = PEM_read_bio_RSA_PUBKEY(key_bio, &rsa, NULL, NULL);
	}
	BIO_free_all(key_bio);
	return(rsa);
}

RSA *cRsa::create_rsa(eTypeKey typeKey) {
	RSA *rsa = create_rsa(typeKey == _private ? priv_key.c_str() : pub_key.c_str(), typeKey);
	if(rsa) {
		if(typeKey == _private) {
			priv_rsa = rsa;
		} else {
			pub_rsa = rsa;
		}
	}
	return(rsa);
}

bool cRsa::public_encrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	if(!pub_rsa) {
		if(!create_rsa(_public)) {
			return(false);
		}
	}
	u_char *data_enc = new u_char[*datalen * 2 + 1000];
	int data_enc_len = RSA_public_encrypt(*datalen, *data, data_enc, pub_rsa, padding);
	if(data_enc_len <= 0) {
		return(false);
	}
	if(destroyOldData) {
		delete [] *data;
	}
	*data  = data_enc;
	*datalen = data_enc_len;
	return(true);
}

bool cRsa::private_decrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	if(!priv_rsa) {
		if(!create_rsa(_private)) {
			return(false);
		}
	}
	u_char *data_dec = new u_char[*datalen * 2 + 1000];
	int data_dec_len = RSA_private_decrypt(*datalen, *data, data_dec, priv_rsa, padding);
	if(data_dec_len <= 0) {
		return(false);
	}
	if(destroyOldData) {
		delete [] *data;
	}
	*data  = data_dec;
	*datalen = data_dec_len;
	return(true);
}
 
bool cRsa::private_encrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	if(!priv_rsa) {
		if(!create_rsa(_private)) {
			return(false);
		}
	}
	u_char *data_enc = new u_char[*datalen * 2 + 1000];
	int data_enc_len = RSA_private_encrypt(*datalen, *data, data_enc, priv_rsa, padding);
	if(data_enc_len <= 0) {
		return(false);
	}
	if(destroyOldData) {
		delete [] *data;
	}
	*data  = data_enc;
	*datalen = data_enc_len;
	return(true);
}

bool cRsa::public_decrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	if(!pub_rsa) {
		if(!create_rsa(_public)) {
			return(false);
		}
	}
	u_char *data_dec = new u_char[*datalen * 2 + 1000];
	int data_dec_len = RSA_public_decrypt(*datalen, *data, data_dec, pub_rsa, padding);
	if(data_dec_len <= 0) {
		return(false);
	}
	if(destroyOldData) {
		delete [] *data;
	}
	*data  = data_dec;
	*datalen = data_dec_len;
	return(true);
}

string cRsa::getError() {
	char *error_buffer = new char[1000];;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), error_buffer);
	string error = error_buffer;
	delete [] error_buffer;
	return(error);
}


cAes::cAes() {
	ctx_enc = NULL;
	ctx_dec = NULL;
}

cAes::~cAes() {
	destroyCtxEnc();
	destroyCtxDec();
}

void cAes::generate_keys() {
	srand(getTimeUS());
	ckey.resize(0);
	for(int i = 0; i < 32; i++) {
		char ch = (char)((double)rand() * ('z' - '0') / RAND_MAX + '0');
		ckey.append(1, ch);
	}
	ivec.resize(0);
	for(int i = 0; i < 16; i++) {
		char ch = (char)((double)rand() * ('z' - '0') / RAND_MAX + '0');
		ivec.append(1, ch);
	}
}

bool cAes::encrypt(u_char *data, size_t datalen, u_char **data_enc, size_t *datalen_enc, bool final) {
	*data_enc = NULL;
	*datalen_enc = 0;
	if(!ctx_enc) {
		if(!data && final) {
			return(true);
		}
		ctx_enc = EVP_CIPHER_CTX_new();
		if(!EVP_EncryptInit(ctx_enc, EVP_aes_128_cbc(), (u_char*)ckey.c_str(), (u_char*)ivec.c_str())) {
			EVP_CIPHER_CTX_free(ctx_enc);
			ctx_enc = NULL;
			return(false);
		}
	}
	*data_enc = new u_char[datalen * 2 + 1000];
	int datalen_enc_part1 = 0;
	int datalen_enc_part2 = 0;
	if(datalen) {
		if(!EVP_EncryptUpdate(ctx_enc, *data_enc, &datalen_enc_part1, data, datalen)) {
			destroyCtxEnc();
			return(false);
		}
	}
	if(final) {
		if(!EVP_EncryptFinal(ctx_enc, *data_enc + datalen_enc_part1, &datalen_enc_part2)) {
			destroyCtxEnc();
			return(false);
		}
		destroyCtxEnc();
	}
	*datalen_enc = datalen_enc_part1 + datalen_enc_part2;
	if(!*datalen_enc) {
		delete [] *data_enc;
		*data_enc = NULL;
	}
	return(true);
}

bool cAes::decrypt(u_char *data, size_t datalen, u_char **data_dec, size_t *datalen_dec, bool final) {
	*data_dec = NULL;
	*datalen_dec = 0;
	if(!ctx_dec) {
		if(!data && final) {
			return(true);
		}
		ctx_dec = EVP_CIPHER_CTX_new();
		if(!EVP_DecryptInit(ctx_dec, EVP_aes_128_cbc(), (u_char*)ckey.c_str(), (u_char*)ivec.c_str())) {
			EVP_CIPHER_CTX_free(ctx_dec);
			ctx_dec = NULL;
			return(false);
		}
	}
	*data_dec = new u_char[datalen + 1000];
	int datalen_dec_part1 = 0;
	int datalen_dec_part2 = 0;
	if(datalen) {
		if(!EVP_DecryptUpdate(ctx_dec, *data_dec, &datalen_dec_part1, data, datalen)) {
			destroyCtxDec();
			return(false);
		}
	}
	if(final) {
		if(!EVP_DecryptFinal(ctx_dec, *data_dec + datalen_dec_part1, &datalen_dec_part2)) {
			destroyCtxDec();
			return(false);
		}
		destroyCtxDec();
	}
	*datalen_dec = datalen_dec_part1 + datalen_dec_part2;
	if(!*datalen_dec) {
		delete [] *data_dec;
		*data_dec = NULL;
	}
	return(true);
}

string cAes::getError() {
	char *error_buffer = new char[1000];;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), error_buffer);
	string error = error_buffer;
	delete [] error_buffer;
	return(error);
}

void cAes::destroyCtxEnc() {
	if(ctx_enc) {
		EVP_CIPHER_CTX_cleanup(ctx_enc);
		EVP_CIPHER_CTX_free(ctx_enc);
		ctx_enc = NULL;
	}
}

void cAes::destroyCtxDec() {
	if(ctx_dec) {
		EVP_CIPHER_CTX_cleanup(ctx_dec);
		EVP_CIPHER_CTX_free(ctx_dec);
		ctx_dec = NULL;
	}
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
	lastTimeOkRead = 0;
	lastTimeOkWrite = 0;
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

void cSocket::setXorKey(string xor_key) {
	this->xor_key = xor_key;
}

bool cSocket::connect(unsigned loopSleepS) {
	if(CR_VERBOSE().socket_connect) {
		ostringstream verbstr;
		verbstr << "try connect (" << name << ")"
			<< " - " << getHostPort();
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	bool rslt = true;
	unsigned passCounter = 0;
	do {
		++passCounter;
		if(passCounter > 1 && loopSleepS) {
			sleep(loopSleepS);
		}
		rslt = true;
		clearError();
		ipl = resolver.resolve(host);
		if(!ipl) {
			setError("failed resolve host name %s", host.c_str());
			rslt = false;
			continue;
		}
		int pass_call_socket = 0;
		do {
			handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			++pass_call_socket;
		} while(handle == 0 && pass_call_socket < 5);
		if(handle == -1) {
			setError("cannot create socket");
			rslt = false;
			continue;
		}
		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
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
		if(rslt) {
			if(CR_VERBOSE().socket_connect) {
				ostringstream verbstr;
				verbstr << "OK connect (" << name << ")"
					<< " - " << getHostPort()
					<< " handle " << handle;
				syslog(LOG_INFO, "%s", verbstr.str().c_str());
			}
		}
		
	} while(!rslt && loopSleepS && !(terminate || CR_TERMINATE()));
	return(true);
}

bool cSocket::listen() {
	if(!ipl && !host.empty()) {
		ipl = resolver.resolve(host);
		if(!ipl && host != "0.0.0.0") {
			setError("failed resolve host name %s", host.c_str());
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
	memset(&addr, 0, sizeof(addr));
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
				<< " - " << getHostPort()
				<< " handle " << handle;
			syslog(LOG_INFO, "%s", verbstr.str().c_str());
		}
		::close(handle);
		handle = -1;
	}
}

bool cSocket::await(cSocket **clientSocket) {
	if(isError() || !okHandle()) {
		setError(_se_bad_connection, "await");
		return(false);
	}
	int clientHandle = -1;
	if(clientSocket) {
		*clientSocket = NULL;
	}
	sockaddr_in clientInfo;
	socklen_t clientInfoLen = sizeof(sockaddr_in);
	while(clientHandle < 0 && !terminate) {
		bool doAccept = false;
		if(opt_socket_use_poll) {
			pollfd fds[2];
			memset(fds, 0 , sizeof(fds));
			fds[0].fd = handle;
			fds[0].events = POLLIN;
			if(poll(fds, 1, timeouts.await * 1000) > 0) {
				doAccept = true;
			}
		} else {
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(handle, &rfds);
			struct timeval tv;
			tv.tv_sec = timeouts.await;
			tv.tv_usec = 0;
			if(select(handle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
				doAccept = true;
			}
		}
		if(doAccept) {
			clientHandle = accept(handle, (sockaddr*)&clientInfo, &clientInfoLen);
			if(clientHandle >= 0) {
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
	}
	return(clientHandle >= 0);
}

bool cSocket::write(u_char *data, size_t dataLen) {
	if(isError() || !okHandle()) {
		setError(_se_bad_connection, "write");
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
	lastTimeOkWrite = getTimeUS();
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
		setError(_se_bad_connection, "_write");
		return(false);
	}
	bool doWrite = false;
	if(opt_socket_use_poll) {
		pollfd fds[2];
		memset(fds, 0 , sizeof(fds));
		fds[0].fd = handle;
		fds[0].events = POLLOUT;
		int rsltPool = poll(fds, 1, timeouts.write * 1000);
		if(rsltPool < 0) {
			*dataLen = 0;
			setError(_se_loss_connection, "failed poll()");
			perror("poll()");
			return(false);
		}
		if(rsltPool > 0 && fds[0].revents) {
			doWrite = true;
		}
	} else {
		fd_set wfds;
		FD_ZERO(&wfds);
		FD_SET(handle, &wfds);
		struct timeval tv;
		tv.tv_sec = timeouts.write;
		tv.tv_usec = 0;
		int rsltSelect = select(handle + 1, (fd_set *) 0, &wfds, (fd_set *) 0, &tv);
		if(rsltSelect < 0) {
			*dataLen = 0;
			setError(_se_loss_connection, "failed select()");
			perror("select()");
			return(false);
		}
		if(rsltSelect > 0 && FD_ISSET(handle, &wfds)) {
			doWrite = true;
		}
	}
	if(doWrite) {
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

bool cSocket::read(u_char *data, size_t *dataLen, bool quietEwouldblock) {
	if(isError() || !okHandle()) {
		*dataLen = 0;
		setError(_se_bad_connection, "read");
		return(false);
	}
	bool doRead = false;
	if(opt_socket_use_poll) {
		pollfd fds[2];
		memset(fds, 0 , sizeof(fds));
		fds[0].fd = handle;
		fds[0].events = POLLIN;
		int rsltPool = poll(fds, 1, timeouts.read * 1000);
		if(rsltPool < 0) {
			*dataLen = 0;
			setError(_se_loss_connection, "failed poll()");
			perror("poll()");
			return(false);
		}
		if(rsltPool > 0 && fds[0].revents) {
			doRead = true;
		}
	} else {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(handle, &rfds);
		struct timeval tv;
		tv.tv_sec = timeouts.read;
		tv.tv_usec = 0;
		int rsltSelect = select(handle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
		if(rsltSelect < 0) {
			*dataLen = 0;
			setError(_se_loss_connection, "failed select()");
			perror("select()");
			return(false);
		}
		if(rsltSelect > 0 && FD_ISSET(handle, &rfds)) {
			doRead = true;
		}
	}
	if(doRead) {
		ssize_t recvLen = recv(handle, data, *dataLen, 0);
		if(recvLen > 0) {
			*dataLen = recvLen;
		} else {
			*dataLen = 0;
			if(errno != EWOULDBLOCK) {
				if(!quietEwouldblock) {
					setError(_se_loss_connection, "failed read()");
				}
				return(false);
			}
		}
	} else {
		*dataLen = 0;
	}
	lastTimeOkRead = getTimeUS();
	return(true);
}

bool cSocket::writeXorKeyEnc(u_char *data, size_t dataLen) {
	u_char *dataEnc = new u_char[dataLen];
	memcpy(dataEnc, data, dataLen);
	encodeXorKeyWriteBuffer(dataEnc, dataLen);
	bool rsltWrite = write(dataEnc, dataLen);
	delete [] dataEnc;
	if(rsltWrite) {
		writeEncPos += dataLen;
	}
	return(rsltWrite);
}

bool cSocket::readXorKeyDec(u_char *data, size_t *dataLen) {
	bool rsltRead = read(data, dataLen);
	if(rsltRead && *dataLen) {
		decodeXorKeyReadBuffer(data, *dataLen);
	}
	return(rsltRead);
}

bool cSocket::writeAesEnc(u_char *data, size_t dataLen, bool final) {
	u_char *data_enc;
	size_t data_enc_len;
	if(!encodeAesWriteBuffer(data, dataLen, &data_enc, &data_enc_len, final)) {
		return(false);
	}
	bool rsltWrite = true;
	if(data_enc_len) {
		rsltWrite = write(data_enc, data_enc_len);
		delete [] data_enc;
	}
	return(rsltWrite);
}

void cSocket::encodeXorKeyWriteBuffer(u_char *data, size_t dataLen) {
	xorData(data, dataLen, xor_key.c_str(), xor_key.length(), writeEncPos);
}

void cSocket::decodeXorKeyReadBuffer(u_char *data, size_t dataLen) {
	xorData(data, dataLen, xor_key.c_str(), xor_key.length(), readDecPos);
	readDecPos += dataLen;
}

bool cSocket::encodeAesWriteBuffer(u_char *data, size_t dataLen, u_char **data_enc, size_t *dataLenEnc, bool final) {
	return(aes.encrypt(data, dataLen, data_enc, dataLenEnc, final));
}

bool cSocket::decodeAesReadBuffer(u_char *data, size_t dataLen, u_char **data_dec, size_t *dataLenDec, bool final) {
	return(aes.decrypt(data, dataLen, data_dec, dataLenDec, final));
}

bool cSocket::checkHandleRead() {
	if(!okHandle()) {
		return(false);
	}
	bool doRead = false;
	if(opt_socket_use_poll) {
		pollfd fds[2];
		memset(fds, 0 , sizeof(fds));
		fds[0].fd = handle;
		fds[0].events = POLLIN;
		int rsltPool = poll(fds, 1, 100);
		if(rsltPool < 0) {
			return(false);
		}
		if(rsltPool > 0 && fds[0].revents) {
			doRead = true;
		}
	} else {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(handle, &rfds);
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 100000;
		int rsltSelect = select(handle + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
		if(rsltSelect < 0) {
			return(false);
		}
		if(rsltSelect > 0 && FD_ISSET(handle, &rfds)) {
			doRead = true;
		}
	}
	if(doRead) {
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

void cSocket::setError(eSocketError error, const char *descr) {
	if(isError()) {
		return;
	}
	this->error = error;
	this->error_descr = descr ? descr : "";
	logError();
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
	logError();
}

void cSocket::logError() {
	if(isError()) {
		string logStr;
		if((error == _se_bad_connection || error == _se_loss_connection) &&
		   !errorTypeStrings[error].empty()) {
			logStr = errorTypeStrings[error];
		} else {
			if(!name.empty()) {
				logStr += name + " - ";
			}
			logStr += getHostPort() + " - ";
			logStr += getError();
		}
		syslog(LOG_ERR, "%s", logStr.c_str());
	}
}

void cSocket::clearError() {
	error = _se_na;
	error_str.resize(0);
	error_descr.resize(0);
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

bool cSocketBlock::writeBlock(u_char *data, size_t dataLen, eTypeEncode typeEncode, string xor_key) {
	unsigned int data_sum = dataSum(data, dataLen);
	u_char *xor_key_data = NULL;
	u_char *rsa_data = NULL;
	u_char *aes_data = NULL;
	if(typeEncode == _te_xor && !xor_key.empty()) {
		xor_key_data = new u_char[dataLen];
		memcpy(xor_key_data, data, dataLen);
		xorData(xor_key_data, dataLen, xor_key.c_str(), xor_key.length(), 0);
		data = xor_key_data;
	} else if(typeEncode == _te_rsa && rsa.isSetPubKey()) {
		rsa_data = data;
		size_t rsa_data_len = dataLen;
		if(rsa.public_encrypt(&rsa_data, &rsa_data_len, false)) {
			data = rsa_data;
			dataLen = rsa_data_len;
		} else {
			return(false);
		}
	} else if(typeEncode == _te_aes) {
		size_t aes_data_len;
		if(aes.encrypt(data, dataLen, &aes_data, &aes_data_len, true)) {
			data = aes_data;
			dataLen = aes_data_len;
		} else {
			return(false);
		}
	}
	u_char *block = new u_char[sizeof(sBlockHeader) + dataLen];
	((sBlockHeader*)block)->init();
	((sBlockHeader*)block)->length = dataLen;
	((sBlockHeader*)block)->sum = data_sum;
	memcpy(block + sizeof(sBlockHeader), data, dataLen);
	if(xor_key_data) {
		delete xor_key_data;
	}
	if(rsa_data) {
		delete [] rsa_data;
	}
	if(aes_data) {
		delete [] aes_data;
	}
	bool rsltWrite = write(block, sizeof(sBlockHeader) + dataLen);
	delete [] block;
	return(rsltWrite);
}

bool cSocketBlock::writeBlock(string str, eTypeEncode typeEncode, string xor_key) {
	return(writeBlock((u_char*)str.c_str(), str.length(), typeEncode, xor_key));
}

u_char *cSocketBlock::readBlock(size_t *dataLen, eTypeEncode typeEncode, string xor_key, bool quietEwouldblock, u_int16_t timeout) {
	if(!timeout) {
		timeout = timeouts.readblock;
	}
	size_t bufferLength = 10 * 1024;
	u_char *buffer = new u_char[bufferLength];
	bool rsltRead = true;
	readBuffer.clear();
	size_t readLength = sizeof(sBlockHeader);
	bool blockHeaderOK = false;
	u_int64_t startTime = getTimeUS();
	while((rsltRead = read(buffer, &readLength, quietEwouldblock))) {
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
					if(typeEncode == _te_xor && !xor_key.empty()) {
						xorData(readBuffer.buffer + sizeof(sBlockHeader), readBuffer.lengthBlockHeader(), xor_key.c_str(), xor_key.length(), 0);
					} else if(typeEncode == _te_rsa && rsa.isSetPrivKey()) {
						u_char *rsa_data = readBuffer.buffer + sizeof(sBlockHeader);
						size_t rsa_data_len = readBuffer.lengthBlockHeader();
						if(rsa.private_decrypt(&rsa_data, &rsa_data_len, false)) {
							size_t new_buffer_length = rsa_data_len + sizeof(sBlockHeader);
							u_char *new_buffer = new u_char[new_buffer_length];
							memcpy(new_buffer, readBuffer.buffer, sizeof(sBlockHeader));
							((sBlockHeader*)new_buffer)->length = rsa_data_len;
							memcpy(new_buffer + sizeof(sBlockHeader), rsa_data, rsa_data_len);
							readBuffer.set(new_buffer, new_buffer_length);
							delete [] rsa_data;
						} else {
							rsltRead = false;
						}
					} else if(typeEncode == _te_aes) {
						u_char *aes_data;
						size_t aes_data_len;
						if(aes.decrypt(readBuffer.buffer + sizeof(sBlockHeader), readBuffer.lengthBlockHeader(), &aes_data, &aes_data_len, true)) {
							size_t new_buffer_length = aes_data_len + sizeof(sBlockHeader);
							u_char *new_buffer = new u_char[new_buffer_length];
							memcpy(new_buffer, readBuffer.buffer, sizeof(sBlockHeader));
							((sBlockHeader*)new_buffer)->length = aes_data_len;
							memcpy(new_buffer + sizeof(sBlockHeader), aes_data, aes_data_len);
							readBuffer.set(new_buffer, new_buffer_length);
							delete [] aes_data;
						} else  {
							rsltRead = false;
						}
					}
					if(rsltRead && !checkSumReadBuffer()) {
						rsltRead = false;
					}
					break;
				}
			}
		} else {
			usleep(1000);
			if((timeout && getTimeUS() > startTime + timeout * 1000000ull) || terminate) {
				rsltRead = false;
				break;
			}
		}
		readLength = blockHeaderOK ?
			      min(bufferLength, readBuffer.lengthBlockHeader(true) - readBuffer.length) :
			      min(bufferLength, sizeof(sBlockHeader) - readBuffer.length);
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

bool cSocketBlock::readBlock(string *str, eTypeEncode typeEncode, string xor_key, bool quietEwouldblock, u_int16_t timeout) {
	u_char *data;
	size_t dataLen;
	data = readBlock(&dataLen, typeEncode, xor_key, quietEwouldblock, timeout);
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

void cSocketBlock::readDecodeAesAndResendTo(cSocketBlock *dest, u_char *remainder, size_t remainder_length, u_int16_t timeout) {
	string verb_str;
	if(!timeout) {
		timeout = timeouts.readblock;
	}
	u_int64_t startTime = getTimeUS();
	if(remainder) {
		u_char *data_dec;
		size_t data_dec_len;
		this->decodeAesReadBuffer(remainder, remainder_length, &data_dec, &data_dec_len, false);
		if(data_dec_len) {
			dest->write(data_dec, data_dec_len);
		}
		if(data_dec) {
			delete [] data_dec;
		}
		if(CR_VERBOSE().socket_decode) {
			verb_str += "header: " + intToString(remainder_length) + "/d:" + intToString(data_dec_len) + "; ";
		}
	}
	size_t bufferLen = 1000;
	u_char *buffer = new u_char[bufferLen];
	unsigned counter = 0;
	while(!CR_TERMINATE()) {
		size_t len = bufferLen;
		if(this->read(buffer, &len, counter > 0 || remainder)) {
			if(len) {
				u_char *data_dec;
				size_t data_dec_len;
				this->decodeAesReadBuffer(buffer, len, &data_dec, &data_dec_len, false);
				if(data_dec_len) {
					dest->write(data_dec, data_dec_len);
				}
				if(data_dec) {
					delete [] data_dec;
				}
				if(CR_VERBOSE().socket_decode) {
					verb_str += "data: " + intToString(len) + "/d:" + intToString(data_dec_len) + "; ";
				}
			}
		} else {
			u_char *data_dec;
			size_t data_dec_len;
			this->decodeAesReadBuffer(NULL, 0, &data_dec, &data_dec_len, true);
			if(data_dec_len) {
				dest->write(data_dec, data_dec_len);
			}
			if(data_dec) {
				delete [] data_dec;
			}
			if(CR_VERBOSE().socket_decode) {
				verb_str += "rest: d:" + intToString(data_dec_len) + "; ";
			}
			break;
		}
		++counter;
		if(timeout && getTimeUS() > startTime + timeout * 1000000ull) {
			break;
		}
	}
	delete [] buffer;
	if(remainder) {
		delete [] remainder;
	}
	if(CR_VERBOSE().socket_decode) {
		syslog(LOG_INFO, "decode %s", verb_str.c_str());
	}
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
	listen_thread = 0;
}

cServer::~cServer() {
	listen_stop();
}

bool cServer::listen_start(const char *name, string host, u_int16_t port) {
	listen_socket = new cSocketBlock(name);
	listen_socket->setHostPort(host, port);
	if(!listen_socket->listen()) {
		delete listen_socket;
		listen_socket = NULL;
		return(false);
	}
	vm_pthread_create("cServer::listen_start", &listen_thread, NULL, cServer::listen_process, this, __FILE__, __LINE__);
	return(true);
}

void cServer::listen_stop() {
	if(listen_socket) {
		listen_socket->close();
		listen_socket->setTerminate();
		if(listen_thread) {
			pthread_join(listen_thread, NULL);
			listen_thread = 0;
		}
		delete listen_socket;
		listen_socket = NULL;
	}
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
			if(!CR_TERMINATE()) {
				if(CR_VERBOSE().connect_info) {
					ostringstream verbstr;
					verbstr << "NEW CONNECTION FROM: " 
						<< clientSocket->getIP() << " : " << clientSocket->getPort();
					syslog(LOG_INFO, "%s", verbstr.str().c_str());
				}
				createConnection(clientSocket);
			} else {
				delete clientSocket;
			}
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

void cServerConnection::setTerminateSocket() {
	if(socket) {
		socket->setTerminate();
	}
}


cReceiver::cReceiver() {
	receive_socket = NULL;
	receive_thread = 0;
	start_ok = false;
}

cReceiver::~cReceiver() {
	receive_stop();
}

bool cReceiver::receive_start(string host, u_int16_t port) {
	if(!_connect(host, port, 5)) {
		return(false);
	}
	_receive_start();
	return(true);
}

void cReceiver::receive_stop() {
	if(receive_socket) {
		receive_socket->close();
		receive_socket->setTerminate();
		if(receive_thread) {
			pthread_join(receive_thread, NULL);
			receive_thread = 0;
		}
		delete receive_socket;
		receive_socket = NULL;
	}
}

bool cReceiver::_connect(string host, u_int16_t port, unsigned loopSleepS) {
	if(!receive_socket) {
		receive_socket = new cSocketBlock("receiver");
		for(map<cSocket::eSocketError, string>::iterator iter = errorTypeStrings.begin(); iter != errorTypeStrings.end(); iter++) {
			receive_socket->setErrorTypeString(iter->first, iter->second.c_str());
		}
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
	vm_pthread_create("cReceiver::receive_start", &receive_thread, NULL, cReceiver::receive_process, this, __FILE__, __LINE__);
}

void *cReceiver::receive_process(void *arg) {
	((cReceiver*)arg)->receive_process();
	return(NULL);
}

void cReceiver::receive_process() {
	while(!((receive_socket && receive_socket->isTerminate()) || CR_TERMINATE())) {
		if(receive_process_loop_begin()) {
			start_ok = true;
			u_char *data;
			size_t dataLen;
			data = receive_socket->readBlockTimeout(&dataLen, 30);
			if(data) {
				if(string((char*)data, dataLen) != "ping") {
					evData(data, dataLen);
				} else {
					receive_socket->writeBlock("pong");
				}
			} else {
				receive_socket->setError("timeout");
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

bool cClient::write(u_char *data, size_t dataLen) {
	return(client_socket->write(data, dataLen));
}

bool cClient::writeXorKeyEnc(u_char *data, size_t dataLen, const char *key) {
	client_socket->setXorKey(key);
	return(client_socket->writeXorKeyEnc(data, dataLen));
}

bool cClient::writeAesEnc(u_char *data, size_t dataLen, const char *ckey, const char *ivec) {
	client_socket->set_aes_keys(ckey, ivec);
	return(client_socket->writeAesEnc(data, dataLen, false));
}

bool cClient::writeFinal() {
	return(client_socket->writeAesEnc(NULL, 0, true));
}
