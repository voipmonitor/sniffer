#include "cloud_router_base.h"

#include <netdb.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <iostream>
#include <sstream>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>


extern bool CR_TERMINATE();
extern void CR_SET_TERMINATE();
extern sCloudRouterVerbose& CR_VERBOSE();
extern bool opt_socket_use_poll;
extern cResolver resolver;

cRsa::cRsa() {
	#ifdef HAVE_OPENSSL
	priv_rsa = NULL;
	pub_rsa = NULL;
	padding = RSA_PKCS1_PADDING;
	#endif
}

cRsa::~cRsa() {
	#ifdef HAVE_OPENSSL
	if(priv_rsa) {
		RSA_free(priv_rsa);
	}
	if(pub_rsa) {
		RSA_free(pub_rsa);
	}
	#endif
}

void cRsa::generate_keys(unsigned keylen) {
	#ifdef HAVE_OPENSSL
	#if __GNUC__ >= 8
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	#endif
	RSA *rsa = RSA_generate_key(keylen, RSA_F4, 0, 0);
	#if __GNUC__ >= 8
	#pragma GCC diagnostic pop
	#endif
	// priv key
	BIO *priv_key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(priv_key_bio, rsa, NULL, NULL, 0, NULL, NULL);
	int priv_key_length = BIO_pending(priv_key_bio);
	char *priv_key_buffer = new FILE_LINE(0) char[priv_key_length];
	BIO_read(priv_key_bio, priv_key_buffer, priv_key_length);
	priv_key = string(priv_key_buffer, priv_key_length);
	delete [] priv_key_buffer;
	BIO_free_all(priv_key_bio);
	// pub key
	BIO *pub_key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSA_PUBKEY(pub_key_bio, rsa);
	int pub_key_length = BIO_pending(pub_key_bio);
	char *pub_key_buffer = new FILE_LINE(0) char[pub_key_length];
	BIO_read(pub_key_bio, pub_key_buffer, pub_key_length);
	pub_key_gener = string(pub_key_buffer, pub_key_length);
	pub_key = pub_key_gener;
	delete [] pub_key_buffer;
	BIO_free_all(pub_key_bio);
	//
	RSA_free(rsa);
	#endif
}

RSA *cRsa::create_rsa(const char *key, eTypeKey typeKey) {
	#ifdef HAVE_OPENSSL
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
	#else
	return(NULL);
	#endif
}

RSA *cRsa::create_rsa(eTypeKey typeKey) {
	#ifdef HAVE_OPENSSL
	RSA *rsa = create_rsa(typeKey == _private ? priv_key.c_str() : pub_key.c_str(), typeKey);
	if(rsa) {
		if(typeKey == _private) {
			priv_rsa = rsa;
		} else {
			pub_rsa = rsa;
		}
	}
	return(rsa);
	#else
	return(NULL);
	#endif
}

bool cRsa::public_encrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	#ifdef HAVE_OPENSSL
	if(!pub_rsa) {
		if(!create_rsa(_public)) {
			return(false);
		}
	}
	u_char *data_enc = new FILE_LINE(0) u_char[*datalen * 2 + 1000];
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
	#else
	return(false);
	#endif
}

bool cRsa::private_decrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	#ifdef HAVE_OPENSSL
	if(!priv_rsa) {
		if(!create_rsa(_private)) {
			return(false);
		}
	}
	u_char *data_dec = new FILE_LINE(0) u_char[*datalen * 2 + 1000];
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
	#else
	return(false);
	#endif
}
 
bool cRsa::private_encrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	#ifdef HAVE_OPENSSL
	if(!priv_rsa) {
		if(!create_rsa(_private)) {
			return(false);
		}
	}
	u_char *data_enc = new FILE_LINE(0) u_char[*datalen * 2 + 1000];
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
	#else
	return(false);
	#endif
}

bool cRsa::public_decrypt(u_char **data, size_t *datalen, bool destroyOldData) {
	#ifdef HAVE_OPENSSL
	if(!pub_rsa) {
		if(!create_rsa(_public)) {
			return(false);
		}
	}
	u_char *data_dec = new FILE_LINE(0) u_char[*datalen * 2 + 1000];
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
	#else
	return(false);
	#endif
}

string cRsa::getError() {
	#ifdef HAVE_OPENSSL
	char *error_buffer = new FILE_LINE(0) char[1000];;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), error_buffer);
	string error = error_buffer;
	delete [] error_buffer;
	return(error);
	#else
	return("openssl library is not present");
	#endif
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
	#ifdef HAVE_OPENSSL
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
	*data_enc = new FILE_LINE(0) u_char[datalen * 2 + 1000];
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
	#else
	return(false);
	#endif
}

bool cAes::decrypt(u_char *data, size_t datalen, u_char **data_dec, size_t *datalen_dec, bool final) {
	#ifdef HAVE_OPENSSL
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
	*data_dec = new FILE_LINE(0) u_char[datalen + 1000];
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
	#else
	return(false);
	#endif
}

string cAes::getError() {
	#ifdef HAVE_OPENSSL
	char *error_buffer = new FILE_LINE(0) char[1000];
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), error_buffer);
	string error = error_buffer;
	delete [] error_buffer;
	return(error);
	#else
	return("openssl library is not present");
	#endif
}

void cAes::destroyCtxEnc() {
	#ifdef HAVE_OPENSSL
	if(ctx_enc) {
		EVP_CIPHER_CTX_cleanup(ctx_enc);
		EVP_CIPHER_CTX_free(ctx_enc);
		ctx_enc = NULL;
	}
	#endif
}

void cAes::destroyCtxDec() {
	#ifdef HAVE_OPENSSL
	if(ctx_dec) {
		EVP_CIPHER_CTX_cleanup(ctx_dec);
		EVP_CIPHER_CTX_free(ctx_dec);
		ctx_dec = NULL;
	}
	#endif
}


cSocket::cSocket(const char *name, bool autoClose) {
	if(name) {
		this->name = name;
	}
	this->autoClose = autoClose;
	port = 0;
	ip.clear();
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
	this->host = host.find('/') != string::npos ? host.substr(0, host.find('/')) : host;
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
		std::vector<vmIP> ips;
		resolver.resolve(host.c_str(), &ips);
		if(!ips.size()) {
			setError("failed resolve host name %s", host.c_str());
			rslt = false;
			continue;
		}
		bool ok_connect = false;
		for(uint i = 0; i < ips.size() && !ok_connect; i++) {
			clearError();
			ip = ips[i];
			int pass_call_socket_create = 0;
			do {
				handle = socket_create(ip, SOCK_STREAM, IPPROTO_TCP);
				++pass_call_socket_create;
			} while(handle == 0 && pass_call_socket_create < 5);
			if(handle == -1) {
				if(CR_VERBOSE().socket_connect) {
					ostringstream verbstr;
					verbstr << "cannot create socket (" << name << ")";
					syslog(LOG_ERR, "%s", verbstr.str().c_str());
				}
			} else if(socket_connect(handle, ip, port) == -1) {
				if(CR_VERBOSE().socket_connect) {
					ostringstream verbstr;
					verbstr << "failed to connect to server [" << host << "] resolved to ip "
						<< ip.getString() << " error:[" << strerror(errno) << "] (" << name << ")";
					syslog(LOG_ERR, "%s", verbstr.str().c_str());
				}
				close();
			} else {
				ok_connect = true;
			}
		}
		if(ok_connect) {
			int on = 1;
			setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int));
			int flags = fcntl(handle, F_GETFL, 0);
			if(flags >= 0) {
				fcntl(handle, F_SETFL, flags | O_NONBLOCK);
			}
			if(CR_VERBOSE().socket_connect) {
				ostringstream verbstr;
				verbstr << "OK connect (" << name << ")"
					<< " - " << getHostPort()
					<< " handle " << handle;
				syslog(LOG_INFO, "%s", verbstr.str().c_str());
			}
			rslt = true;
		} else {
			string ips_str;
			for(uint i = 0; i < ips.size(); i++) {
				if(i > 0) {
					ips_str += ",";
				}
				ips_str += ips[i].getString();
			}
			setError("failed connection to %s (%s) of the server %s : last error:[%s]", 
				 ips.size() > 1 ? "all possible ips" : "ip",
				 ips_str.c_str(), host.c_str(), 
				 strerror(errno));
			rslt = false;
		}
	} while(!rslt && loopSleepS && !(terminate || CR_TERMINATE()));
	return(rslt);
}

bool cSocket::listen() {
	if(!ip.isSet() && !host.empty()) {
		ip = resolver.resolve(host);
		if(!ip.isSet() && 
		   !(ip.is_v6() ? host == "::" : host == "0.0.0.0")) {
			setError("failed resolve host name %s", host.c_str());
			return(false);
		}
	}
	if((handle = socket_create(ip, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		setError("cannot create socket");
		return(false);
	}
	int flags = fcntl(handle, F_GETFL, 0);
	if(flags >= 0) {
		fcntl(handle, F_SETFL, flags | O_NONBLOCK);
	}
	int on = 1;
	setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	int rsltListen;
	do {
		while(socket_bind(handle, ip, port) == -1 && !terminate && !CR_TERMINATE()) {
			clearError();
			setError("cannot bind to port [%d] - trying again after 5 seconds", port);
			sleep(5);
		}
		if(terminate || CR_TERMINATE()) {
			return(false);
		}
		rsltListen = ::listen(handle, 512);
		if(rsltListen == -1) {
			clearError();
			setError("listen failed - trying again after 5 seconds");
			sleep(5);
		}
	} while(rsltListen == -1);
	clearError();
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
			vmIP clientIP;
			vmPort clientPort;
			clientHandle = socket_accept(handle, &clientIP, &clientPort);
			if(clientHandle >= 0) {
				int flags = fcntl(clientHandle, F_GETFL, 0);
				if(flags >= 0) {
					fcntl(clientHandle, F_SETFL, flags | O_NONBLOCK);
				}
				if(clientSocket) {
					*clientSocket = new FILE_LINE(0) cSocket("client/await");
					(*clientSocket)->host = clientIP.getString();
					(*clientSocket)->port = clientPort;
					(*clientSocket)->ip = clientIP;
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
				if(!quietEwouldblock && !(isTerminate() || CR_TERMINATE())) {
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
	u_char *dataEnc = new FILE_LINE(0) u_char[dataLen];
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
	char *error_buffer = new FILE_LINE(0) char[error_buffer_length];
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
		USLEEP(100000);
		sx10 -= 1;
	}
}


cSocketBlock::cSocketBlock(const char *name, bool autoClose)
 : cSocket(name, autoClose) {
	block_header_string = NULL;
}

cSocketBlock::~cSocketBlock() {
	if(block_header_string) {
		delete [] block_header_string;
	}
}

void cSocketBlock::setBlockHeaderString(const char *block_header_string) {
	if(this->block_header_string) {
		delete [] this->block_header_string;
		this->block_header_string = NULL;
	}
	if(block_header_string) {
		this->block_header_string = new FILE_LINE(0) char[strlen(block_header_string) + 1];
		strcpy(this->block_header_string, block_header_string);
	}
}

bool cSocketBlock::writeBlock(u_char *data, size_t dataLen, eTypeEncode typeEncode, string xor_key) {
	unsigned int data_sum = dataSum(data, dataLen);
	u_char *xor_key_data = NULL;
	u_char *rsa_data = NULL;
	u_char *aes_data = NULL;
	if(typeEncode == _te_xor && !xor_key.empty()) {
		xor_key_data = new FILE_LINE(0) u_char[dataLen];
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
	u_char *block = new FILE_LINE(0) u_char[sizeof(sBlockHeader) + dataLen];
	((sBlockHeader*)block)->init(block_header_string);
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

u_char *cSocketBlock::readBlock(size_t *dataLen, eTypeEncode typeEncode, string xor_key, bool quietEwouldblock, u_int16_t timeout, size_t bufferIncLength) {
	if(!timeout) {
		timeout = timeouts.readblock;
	}
	size_t maxReadLength = 10 * 1024;
	bool rsltRead = true;
	readBuffer.clear();
	size_t readLength = sizeof(sBlockHeader);
	bool blockHeaderOK = false;
	u_int64_t startTime = getTimeUS();
	do {
		readBuffer.needFreeSize(readLength, bufferIncLength);
		rsltRead = read(readBuffer.buffer + readBuffer.length, &readLength, quietEwouldblock);
		if(rsltRead) {
			if(readLength) {
				readBuffer.incLength(readLength);
				if(!blockHeaderOK) {
					if(readBuffer.length >= sizeof(sBlockHeader)) {
						if(readBuffer.okBlockHeader(block_header_string)) {
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
								u_char *new_buffer = new FILE_LINE(0) u_char[new_buffer_length];
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
								u_char *new_buffer = new FILE_LINE(0) u_char[new_buffer_length];
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
				USLEEP(1000);
				if((timeout && getTimeUS() > startTime + timeout * 1000000ull) || terminate) {
					rsltRead = false;
					break;
				}
			}
			readLength = blockHeaderOK ?
				      min(maxReadLength, readBuffer.lengthBlockHeader(true) - readBuffer.length) :
				      min(maxReadLength, sizeof(sBlockHeader) - readBuffer.length);
		}
	} while(rsltRead);
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
	u_char *buffer = new FILE_LINE(0) u_char[bufferLength];
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
						*remainder = new FILE_LINE(0) u_char[_remainder_length];
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
			USLEEP(1000);
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
	u_char *buffer = new FILE_LINE(0) u_char[bufferLen];
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
	for(unsigned i = 0; i < MAX_LISTEN_SOCKETS; i++) {
		listen_socket[i] = NULL;
		listen_thread[i] = 0;
	}
}

cServer::~cServer() {
	listen_stop();
}

bool cServer::listen_start(const char *name, string host, u_int16_t port, unsigned index) {
	listen_socket[index] = new FILE_LINE(0) cSocketBlock(name);
	listen_socket[index]->setHostPort(host, port);
	if(!listen_socket[index]->listen()) {
		delete listen_socket[index];
		listen_socket[index] = NULL;
		return(false);
	}
	sListenParams *listenParams = new sListenParams;
	listenParams->server = this;
	listenParams->index = index;
	vm_pthread_create("cServer::listen_start", &listen_thread[index], NULL, cServer::listen_process, listenParams, __FILE__, __LINE__);
	return(true);
}

void cServer::listen_stop(unsigned index) {
	if(listen_socket[index]) {
		listen_socket[index]->setTerminate();
		listen_socket[index]->close();
		if(listen_thread[index]) {
			pthread_join(listen_thread[index], NULL);
			listen_thread[index] = 0;
		}
		delete listen_socket[index];
		listen_socket[index] = NULL;
	}
}

void *cServer::listen_process(void *arg) {
	if(CR_VERBOSE().start_server) {
		ostringstream verbstr;
		verbstr << (((sListenParams*)arg)->server->startVerbString.empty() ? 
			     "START SERVER LISTEN" : 
			     ((sListenParams*)arg)->server->startVerbString);
		syslog(LOG_INFO, "%s", verbstr.str().c_str());
	}
	((sListenParams*)arg)->server->listen_process(((sListenParams*)arg)->index);
	delete (sListenParams*)arg;
	return(NULL);
}

void cServer::listen_process(int index) {
	cSocket *clientSocket;
	while(!((listen_socket[index] && listen_socket[index]->isTerminate()) || CR_TERMINATE())) {
		if(listen_socket[index]->await(&clientSocket)) {
			#ifdef CLOUD_ROUTER_SERVER
			extern cBlockIP blockIP;
			if(blockIP.isBlocked(clientSocket->getIPL())) {
				clientSocket->close();
				delete clientSocket;
			} else 
			#endif
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
	cServerConnection *connection = new FILE_LINE(0) cServerConnection(socket);
	connection->connection_start();
}

void cServer::setStartVerbString(const char *startVerbString) {
	this->startVerbString = startVerbString ? startVerbString : "";
}


cServerConnection::cServerConnection(cSocket *socket) {
	this->socket = new FILE_LINE(0) cSocketBlock(NULL);
	*(cSocket*)this->socket = *socket;
	delete socket;
	begin_time_ms = getTimeMS();
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
			USLEEP(1000);
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
	use_encode_data = false;
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
		receive_socket->setTerminate();
		receive_socket->close();
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
		receive_socket = new FILE_LINE(0) cSocketBlock("receiver");
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
		receive_socket->close();
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
			data = receive_socket->readBlockTimeout(&dataLen, 30, use_encode_data ? cSocket::_te_aes : cSocket::_te_na, "", false, 1024 * 1024);
			if(data) {
				if(string((char*)data, dataLen) != "ping") {
					evData(data, dataLen);
				} else {
					receive_socket->writeBlock("pong");
				}
			} else if(!((receive_socket && receive_socket->isTerminate()) || CR_TERMINATE())) {
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
	buffer = NULL;
}

cClient::~cClient() {
	if(client_socket) {
		client_socket->close();
		delete client_socket;
		client_socket = NULL;
	}
	if(buffer) {
		delete buffer;
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
		client_socket = new FILE_LINE(0) cSocketBlock("client");
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
	if(buffer) {
		buffer->add(data, dataLen);
		return(true);
	} else {
		return(client_socket->write(data, dataLen));
	}
}

bool cClient::writeXorKeyEnc(u_char *data, size_t dataLen, const char *key) {
	if(buffer) {
		buffer->add(data, dataLen);
		return(true);
	} else {
		client_socket->setXorKey(key);
		return(client_socket->writeXorKeyEnc(data, dataLen));
	}
}

bool cClient::writeAesEnc(u_char *data, size_t dataLen, const char *ckey, const char *ivec) {
	if(buffer) {
		buffer->add(data, dataLen);
		return(true);
	} else {
		client_socket->set_aes_keys(ckey, ivec);
		return(client_socket->writeAesEnc(data, dataLen, false));
	}
}

bool cClient::writeFinal() {
	if(buffer) {
		return(true);
	} else {
		return(client_socket->writeAesEnc(NULL, 0, true));
	}
}

void cClient::writeToBuffer() {
	buffer = new SimpleBuffer;
}
