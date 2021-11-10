#ifndef CLOUD_ROUTER_BASE_H
#define CLOUD_ROUTER_BASE_H


#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <map>
#include <string>
#include <arpa/inet.h>

#include "cloud_router.h"

#ifdef CLOUD_ROUTER_CLIENT
#include "../tools_global.h"
#include "../config.h"
#else
#include "tools_global.h"
#define HAVE_OPENSSL
#endif

#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#else
typedef u_char RSA;
typedef u_char EVP_CIPHER_CTX;
#endif


using namespace std;


#define SYNC_LOCK_USLEEP 100
#define MAX_LISTEN_SOCKETS 2


struct sCloudRouterVerbose {
	sCloudRouterVerbose() {
		memset(this, 0, sizeof(*this));
		start_server = true;
		start_client = true;
		connect_command = true;
		connect_info = true;
		socket_decode = false;
		sql_query = false;
		sql_error = true;
	}
	bool start_server;
	bool start_client;
	bool socket_connect;
	bool connect_command;
	bool connect_info;
	bool create_thread;
	bool socket_decode;
	bool sql_query;
	bool sql_error;
};


class cRsa {
public:
	enum eTypeKey {
		_private,
		_public
	};
public:
	cRsa();
	~cRsa();
	void generate_keys(unsigned keylen = 2048);
	RSA *create_rsa(const char *key, eTypeKey typeKey);
	RSA *create_rsa(eTypeKey typeKey);
	bool public_encrypt(u_char **data, size_t *datalen, bool destroyOldData);
	bool private_decrypt(u_char **data, size_t *datalen, bool destroyOldData);
	bool private_encrypt(u_char **data, size_t *datalen, bool destroyOldData);
	bool public_decrypt(u_char **data, size_t *datalen, bool destroyOldData);
	void setPubKey(string pub_key) {
		this->pub_key = pub_key;
	}
	string getPrivKey() {
		return(this->priv_key);
	}
	string getPubKey() {
		return(this->pub_key);
	}
	string getError();
	bool isSetPrivKey() {
		return(!priv_key.empty());
	}
	bool isSetPubKey() {
		return(!pub_key.empty());
	}
	bool isSetKeys() {
		return(!priv_key.empty() && !pub_key.empty());
	}
private:
	string priv_key;
	string pub_key_gener;
	string pub_key;
	RSA *priv_rsa;
	RSA *pub_rsa;
	int padding;
};


class cAes {
public:
	cAes();
	~cAes();
	void generate_keys();
	void setKeys(string ckey, string ivec) {
		this->ckey = ckey;
		this->ivec = ivec;
	}
	bool getKeys(string *ckey, string *ivec) {
		if(!this->ckey.empty() && !this->ivec.empty()) {
			*ckey = this->ckey;
			*ivec = this->ivec;
			return(true);
		} else {
			return(false);
		}
	}
	bool encrypt(u_char *data, size_t datalen, u_char **data_enc, size_t *datalen_enc, bool final);
	bool decrypt(u_char *data, size_t datalen, u_char **data_dec, size_t *datalen_dec, bool final);
	string getError();
	bool isSetKeys() {
		return(!ckey.empty() && !ivec.empty());
	}
private:
	void destroyCtxEnc();
	void destroyCtxDec();
private:
	EVP_CIPHER_CTX *ctx_enc;
	EVP_CIPHER_CTX *ctx_dec;
	string ckey;
	string ivec;
};


class cBlockIP {
public:
	void setBlock(vmIP ip, unsigned expirationS) {
		block_ip_time[ip] = getTimeMS_rdtsc() + expirationS * 1000;
	}
	bool isBlocked(vmIP ip) {
		map<vmIP, u_int64_t>::iterator iter = block_ip_time.find(ip);
		return(iter != block_ip_time.end() &&
		       block_ip_time[ip] > getTimeMS_rdtsc());
	}
private:
	map<vmIP, u_int64_t> block_ip_time;
};


class cCounterIP {
public:
        cCounterIP() {
                _sync_lock = 0;
        }
        u_int32_t inc(vmIP ip, int inc = 1) {
                u_int32_t rslt = 0;
                lock();
                map<vmIP, u_int32_t>::iterator iter = ip_counter.find(ip);
                if(iter != ip_counter.end()) {
                        if(inc >= 0) {
                                iter->second += inc;
                        } else {
                                if(iter->second <= (unsigned)-inc) {
                                        iter->second = 0;
                                } else {
                                        iter->second += inc;
                                }
                        }
                        rslt = iter->second;
                } else {
                        if(inc > 0) {
                                ip_counter[ip] = inc;
                                rslt = inc;
                        }
                }
                unlock();
                return(rslt);
        }
        u_int32_t dec(vmIP ip) {
                return(inc(ip, -1));
        }
        u_int32_t get(vmIP ip) {
                u_int32_t rslt = 0;
                lock();
                map<vmIP, u_int32_t>::iterator iter = ip_counter.find(ip);
                if(iter != ip_counter.end()) {
                        rslt = iter->second;
                }
                unlock();
                return(rslt);
        }
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
private:
        map<vmIP, u_int32_t> ip_counter;
        volatile int _sync_lock;
};


class cSocket {
public:
	enum eTypeEncode {
		_te_na,
		_te_xor,
		_te_rsa,
		_te_aes
	};
	enum eSocketError {
		_se_na,
		_se_bad_connection,
		_se_loss_connection,
		_se_error_str
	};
	struct sTimeouts {
		sTimeouts() {
			await = 1;
			read = 1;
			write = 1;
			readblock = 300;
		}
		int await;
		int read;
		int write;
		int readblock;
	};
public:
	cSocket(const char *name, bool autoClose = false);
	virtual ~cSocket();
	void setHostPort(string host, u_int16_t port);
	void setXorKey(string xor_key);
	bool connect(unsigned loopSleepS = 0);
	bool listen();
	void close();
	bool await(cSocket **clientSocket);
	bool write(u_char *data, size_t dataLen);
	bool write(const char *data);
	bool write(string &data);
	bool _write(u_char *data, size_t *dataLen);
	bool read(u_char *data, size_t *dataLen, bool quietEwouldblock = false);
	bool writeXorKeyEnc(u_char *data, size_t dataLen);
	bool readXorKeyDec(u_char *data, size_t *dataLen);
	bool writeAesEnc(u_char *data, size_t dataLen, bool final);
	void encodeXorKeyWriteBuffer(u_char *data, size_t dataLen);
	void decodeXorKeyReadBuffer(u_char *data, size_t dataLen);
	bool encodeAesWriteBuffer(u_char *data, size_t dataLen, u_char **data_enc, size_t *dataLenEnc, bool final);
	bool decodeAesReadBuffer(u_char *data, size_t dataLen, u_char **data_dec, size_t *dataLenDec, bool final);
	bool checkHandleRead();
	bool checkHandleWrite();
	bool okHandle() {
		return(handle >= 0);
	}
	bool isError() {
		return(error != _se_na || !error_str.empty());
	}
	string getError() {
		return(error == _se_error_str ?
			(!error_str.empty() ? error_str : "unknown error") :
		       error == _se_bad_connection ?
			("bad connection" + (!error_descr.empty() ? " - " + error_descr : "")) :
		       error == _se_loss_connection ?
			("loss connection" + (!error_descr.empty() ? " - " + error_descr : "")) :
		       error == _se_na ?
		        "" :
		        "unknown error");
	}
	string getHost() {
		return(host.empty() ? getIP() : host);
	}
	string getIP() {
		return(ip.getString());
	}
	vmIP getIPL() {
		return(ip);
	}
	u_int16_t getPort() {
		return(port);
	}
	string getHostPort() {
		return(getHost() + " : " + intToString(port));
	}
	int getHandle() {
		return(handle);
	}
	void setTerminate() {
		terminate = true;
	}
	bool isTerminate() {
		return(terminate);
	}
	void setError(eSocketError error, const char *descr);
	void setError(const char *formatError, ...);
	void logError();
	void generate_aes_keys() {
		aes.generate_keys();
	}
	void set_aes_keys(string ckey, string ivec) {
		aes.setKeys(ckey, ivec);
	}
	bool get_aes_keys(string *ckey, string *ivec) {
		return(aes.getKeys(ckey, ivec));
	}
	void setErrorTypeString(eSocketError errorType, const char *errorString) {
		errorTypeStrings[errorType] = errorString ? errorString : "";
	}
	u_int64_t getLastTimeOkRead() {
		return(lastTimeOkRead);
	}
	u_int64_t getLastTimeOkWrite() {
		return(lastTimeOkWrite);
	}
protected:
	void clearError();
	void sleep(int s);
protected:
	string name;
	bool autoClose;
	string host;
	u_int16_t port;
	vmIP ip;
	sTimeouts timeouts;
	int handle;
	bool enableWriteReconnect;
	volatile bool terminate;
	eSocketError error;
	string error_str;
	string error_descr;
	string xor_key;
	cAes aes;
	u_int64_t writeEncPos;
	u_int64_t readDecPos;
	u_int64_t lastTimeOkRead;
	u_int64_t lastTimeOkWrite;
	map<eSocketError, string> errorTypeStrings;
};


class cSocketBlock : public cSocket {
public:
	struct sBlockHeader {
		sBlockHeader(const char *header_string) {
			init(header_string);
		}
		void init(const char *header_string) {
			memset(this, 0, sizeof(sBlockHeader));
			strncpy(header, get_header_string(header_string), sizeof(header));
		}
		bool okHeader(const char *header_string) {
			const char *_header_string = get_header_string(header_string);
			return(!strncmp(header, _header_string, min(sizeof(header), strlen(_header_string))));
		}
		const char *get_header_string(const char *header_string) {
			return(header_string ? header_string : "vm_cloud_router_block_header");
		}
		char header[30];
		u_int32_t length;
		u_int32_t sum;
	};
	struct sReadBuffer {
		sReadBuffer() {
			init();
		}
		~sReadBuffer() {
			clear();
		}
		void add(u_char *data, size_t dataLen, size_t inc = 0) {
			if(!data || !dataLen) {
				return;
			}
			if(!buffer || capacity < length + dataLen) {
				if(!buffer) {
					capacity = max(dataLen * 2, inc);
					buffer = new FILE_LINE(0) u_char[capacity];
				} else {
					capacity = length + max(dataLen * 2, inc);
					u_char *buffer_new = new FILE_LINE(0) u_char[capacity];
					memcpy(buffer_new, buffer, length);
					delete [] buffer;
					buffer = buffer_new;
				}
			}
			memcpy(buffer + length, data, dataLen);
			length += dataLen;
		}
		void needFreeSize(size_t size, size_t inc = 0) {
			if(!buffer || capacity - length < size) {
				if(!buffer) {
					capacity = max(size * 2, inc);
					buffer = new FILE_LINE(0) u_char[capacity];
				} else {
					capacity = length + max(size * 2, inc);
					u_char *buffer_new = new FILE_LINE(0) u_char[capacity];
					memcpy(buffer_new, buffer, length);
					delete [] buffer;
					buffer = buffer_new;
				}
			}
		}
		void incLength(size_t size) {
			length += size;
		}
		void set(u_char *buffer, size_t length) {
			if(this->buffer) {
				delete [] this->buffer;
			}
			this->buffer = buffer;
			this->length = length;
			this->capacity = length;
		}
		void clear() {
			if(buffer) {
				delete [] buffer;
			}
			init();
		}
		void init() {
			buffer = NULL;
			length = 0;
			capacity = 0;
		}
		bool okBlockHeader(const char *header_string) {
			return(length >= sizeof(sBlockHeader) &&
			       ((sBlockHeader*)buffer)->okHeader(header_string));
		}
		u_int32_t lengthBlockHeader(bool addHeaderSize = false) {
			return(length >= sizeof(sBlockHeader) ?
				((sBlockHeader*)buffer)->length + (addHeaderSize ? sizeof(sBlockHeader) : 0) :
				0);
		}
		u_int32_t sumBlockHeader() {
			return(length >= sizeof(sBlockHeader) ?
				((sBlockHeader*)buffer)->sum :
				0);
		}
		u_char *buffer;
		size_t length;
		size_t capacity;
	};
public:
	cSocketBlock(const char *name, bool autoClose = false);
	~cSocketBlock();
	void setBlockHeaderString(const char *block_header_string);
	bool writeBlock(u_char *data, size_t dataLen, eTypeEncode typeEncode = _te_na, string xor_key = "");
	bool writeBlock(string str, eTypeEncode typeCode = _te_na, string xor_key = "");
	u_char *readBlock(size_t *dataLen, eTypeEncode typeCode = _te_na, string xor_key = "", bool quietEwouldblock = false, u_int16_t timeout = 0, size_t bufferIncLength = 0);
	bool readBlock(string *str, eTypeEncode typeCode = _te_na, string xor_key = "", bool quietEwouldblock = false, u_int16_t timeout = 0);
	u_char *readBlockTimeout(size_t *dataLen, u_int16_t timeout, eTypeEncode typeCode = _te_na, string xor_key = "", bool quietEwouldblock = false, size_t bufferIncLength = 0) {
		return(readBlock(dataLen, typeCode, xor_key, quietEwouldblock, timeout, bufferIncLength));
	}
	bool readBlockTimeout(string *str, u_int16_t timeout, eTypeEncode typeCode = _te_na, string xor_key = "", bool quietEwouldblock = false) {
		return(readBlock(str, typeCode, xor_key, quietEwouldblock, timeout));
	}
	string readLine(u_char **remainder = NULL, size_t *remainder_length = NULL);
	void readDecodeAesAndResendTo(cSocketBlock *dest, u_char *remainder = NULL, size_t remainder_length = 0, u_int16_t timeout = 0);
	void generate_rsa_keys(unsigned keylen = 2048) {
		rsa.generate_keys(keylen);
	}
	string get_rsa_pub_key() {
		return(rsa.getPubKey());
	}
	void set_rsa_pub_key(string key) {
		return(rsa.setPubKey(key));
	}
protected:
	bool checkSumReadBuffer();
	u_int32_t dataSum(u_char *data, size_t dataLen);
protected:
	sReadBuffer readBuffer;
	cRsa rsa;
private:
	char *block_header_string;
};


class cServer {
private:
	struct sListenParams {
		cServer *server;
		unsigned index;
	};
public:
	 cServer();
	 virtual ~cServer();
	 bool listen_start(const char *name, string host, u_int16_t port, unsigned index = 0);
	 void listen_stop(unsigned index = 0);
	 static void *listen_process(void *arg);
	 void listen_process(int index);
	 virtual void createConnection(cSocket *socket);
	 void setStartVerbString(const char *startVerbString);
protected:
	 cSocketBlock *listen_socket[MAX_LISTEN_SOCKETS];
	 pthread_t listen_thread[MAX_LISTEN_SOCKETS];
	 string startVerbString;
};


class cServerConnection {
public:
	cServerConnection(cSocket *socket);
	virtual ~cServerConnection();
	bool connection_start();
	static void *connection_process(void *arg);
	virtual void connection_process();
	virtual void evData(u_char *data, size_t dataLen);
	void setTerminateSocket();
	pthread_t getThread() {
		return(thread);
	}
protected:
	cSocketBlock *socket;
	pthread_t thread;
	u_int64_t begin_time_ms;
};


class cReceiver {
public:
	cReceiver();
	virtual ~cReceiver();
	bool receive_start(string host, u_int16_t port);
	void receive_stop();
	bool _connect(string host, u_int16_t port, unsigned loopSleepS);
	void _close();
	void _receive_start();
	static void *receive_process(void *arg);
	virtual void receive_process();
	virtual bool receive_process_loop_begin();
	virtual void evData(u_char *data, size_t dataLen);
	bool get_aes_keys(string *ckey, string *ivec) {
		return(receive_socket->get_aes_keys(ckey, ivec));
	}
	bool isStartOk() {
		return(start_ok);
	}
	void setErrorTypeString(cSocket::eSocketError errorType, const char *errorString) {
		errorTypeStrings[errorType] = errorString ? errorString : "";
	}
protected:
	cSocketBlock *receive_socket;
	pthread_t receive_thread;
	bool start_ok;
	bool use_encode_data;
	map<cSocket::eSocketError, string> errorTypeStrings;
};


class cClient {
public:
	cClient();
	virtual ~cClient();
	bool client_start(string host, u_int16_t port);
	bool _connect(string host, u_int16_t port);
	void _client_start();
	static void *client_process(void *arg);
	virtual void client_process();
	bool write(u_char *data, size_t dataLen);
	bool writeXorKeyEnc(u_char *data, size_t dataLen, const char *key);
	bool writeAesEnc(u_char *data, size_t dataLen, const char *ckey, const char *ivec);
	bool writeFinal();
	void writeToBuffer();
protected:
	cSocketBlock *client_socket;
	pthread_t client_thread;
	SimpleBuffer *buffer;
};


#endif //CLOUD_ROUTER_BASE_H
