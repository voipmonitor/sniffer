#ifndef SSL_DSSL_H
#define SSL_DSSL_H


#include "config.h"
#include "sql_db.h"

#include <map>
#include <string>
#include <vector>


#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)


#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "tools.h"

#include "dssl/dssl_defs.h"
#include "dssl/errors.h"
#include "dssl/packet.h"
#include "dssl/ssl_session.h"
#include "dssl/ssl_decode_hs.h"

extern "C" {
#include "dssl/tls-ext.h"
}


using namespace std;


class cSslDsslSession {
public:
	enum eServerErrors {
		_se_na,
		_se_ok,
		_se_keyfile_not_exists,
		_se_load_key_failed
	};
public:
	cSslDsslSession(vmIP ip, vmPort port, string keyfile, string password = "");
	~cSslDsslSession();
	void setClientIpPort(vmIP ipc, vmPort portc);
	void init();
	void term();
	bool initServer();
	bool initSession();
	void termServer();
	void termSession();
	void processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, 
			 vmIP saddr, vmIP daddr, vmPort sport, vmPort dport, 
			 struct timeval ts, bool init, class cSslDsslSessions *sessions,
			 bool forceTryIfExistsError = false);
	bool isClientHello(char *data, unsigned int datalen, NM_PacketDir dir);
private:
	NM_PacketDir getDirection(vmIP sip, vmPort sport, vmIP dip, vmPort dport);
	static void dataCallback(NM_PacketDir dir, void* user_data, u_char* data, uint32_t len, DSSL_Pkt* pkt);
	static void errorCallback(void* user_data, int error_code);
	static int password_calback_direct(char *buf, int size, int rwflag, void *userdata);
	static int get_keys(u_char *client_random, DSSL_Session_get_keys_data *get_keys_data, DSSL_Session *session);
	string get_session_data(struct timeval ts);
	bool restore_session_data(const char *data);
	void store_session(class cSslDsslSessions *sessions, struct timeval ts);
private:
	vmIP ip;
	vmPort port;
	string keyfile;
	string password;
	vmIP ipc;
	vmPort portc;
	EVP_PKEY *pkey;
	DSSL_ServerInfo* server_info;
	DSSL_Session* session;
	eServerErrors server_error;
	unsigned process_data_counter;
	bool process_error;
	int process_error_code;
	vector<string> *decrypted_data;
	bool get_keys_ok;
	u_long stored_at;
	bool restored;
	u_int64_t lastTimeSyslog;
friend class cSslDsslSessions;
};


class cSslDsslSessionKeys {
public:
	enum eSessionKeyType {
		_skt_na,
		_skt_client_random,
		_skt_client_handshake_traffic_secret,
		_skt_server_handshake_traffic_secret,
		_skt_exporter_secret,
		_skt_client_traffic_secret_0,
		_skt_server_traffic_secret_0
	};
	struct sSessionKeyType {
		const char *str;
		eSessionKeyType type;
		unsigned length;
	};
	class cSslDsslSessionKeyIndex {
	public:
		cSslDsslSessionKeyIndex(u_char *client_random = NULL);
		bool operator == (const cSslDsslSessionKeyIndex& other) const { 
			return(!memcmp(this->client_random, other.client_random, SSL3_RANDOM_SIZE)); 
		}
		bool operator < (const cSslDsslSessionKeyIndex& other) const { 
			return(memcmp(this->client_random, other.client_random, SSL3_RANDOM_SIZE) < 0); 
		}
	public:
		u_char client_random[SSL3_RANDOM_SIZE];
	};
	class cSslDsslSessionKeyItem {
	public:
		cSslDsslSessionKeyItem(u_char *key = NULL, unsigned key_length = 0);
	public:
		u_char key[SSL3_MASTER_SECRET_SIZE];
		unsigned key_length;
		u_int32_t set_at;
	};
public:
	cSslDsslSessionKeys();
	~cSslDsslSessionKeys();
	void set(const char *type, u_char *client_random, u_char *key, unsigned key_length);
	void set(eSessionKeyType type, u_char *client_random, u_char *key, unsigned key_length);
	bool get(u_char *client_random, eSessionKeyType type, u_char *key, unsigned *key_length, struct timeval ts, bool use_wait = true);
	bool get(u_char *client_random, DSSL_Session_get_keys_data *keys, struct timeval ts, bool use_wait = true);
	void erase(u_char *client_random);
	void cleanup();
	void clear();
	eSessionKeyType strToEnumType(const char *type);
	const char *enumToStrType(eSessionKeyType type);
private:
	void lock_map() {
		while(__sync_lock_test_and_set(&this->_sync_map, 1));
	}
	void unlock_map() {
		__sync_lock_release(&this->_sync_map);
	}
private:
	map<cSslDsslSessionKeyIndex, map<eSessionKeyType, cSslDsslSessionKeyItem*> > keys;
	volatile int _sync_map;
	u_int32_t last_cleanup_at;
public:
	static sSessionKeyType session_key_types[];
};

class cSslDsslSessions {
public:
	struct sSessionData {
		string data;
	};
public:
	cSslDsslSessions();
	~cSslDsslSessions();
public:
	void processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, vmIP saddr, vmIP daddr, vmPort sport, vmPort dport, struct timeval ts,
			 bool forceTryIfExistsError = false);
	void destroySession(vmIP saddr, vmIP daddr, vmPort sport, vmPort dport);
	void keySet(const char *type, u_char *client_random, u_char *key, unsigned key_length);
	bool keyGet(u_char *client_random, cSslDsslSessionKeys::eSessionKeyType type, u_char *key, unsigned *key_length, struct timeval ts, bool use_wait = true);
	bool keysGet(u_char *client_random, DSSL_Session_get_keys_data *get_keys_data, struct timeval ts, bool use_wait = true);
	void keyErase(u_char *client_random);
	void keysCleanup();
private:
	cSslDsslSession *addSession(vmIP ip, vmPort port);
	NM_PacketDir checkIpPort(vmIP sip, vmPort sport, vmIP dip, vmPort dport);
	void init();
	void term();
	void loadSessions();
	void deleteOldSessions(struct timeval ts);
	string storeSessionsTableName();
	void lock_sessions() {
		while(__sync_lock_test_and_set(&this->_sync_sessions, 1));
	}
	void unlock_sessions() {
		__sync_lock_release(&this->_sync_sessions);
	}
	void lock_sessions_db() {
		while(__sync_lock_test_and_set(&this->_sync_sessions_db, 1));
	}
	void unlock_sessions_db() {
		__sync_lock_release(&this->_sync_sessions_db);
	}
private:
	map<sStreamId, cSslDsslSession*> sessions;
	map<sStreamId, sSessionData> sessions_db;
	volatile int _sync_sessions;
	volatile int _sync_sessions_db;
	cSslDsslSessionKeys session_keys;
	SqlDb *sqlDb;
	u_long last_delete_old_sessions_at;
	bool exists_sessions_table;
friend class cSslDsslSession;
};

class cClientRandomServer : public cServer {
public:
	cClientRandomServer();
	~cClientRandomServer();
	virtual void createConnection(cSocket *socket);
};

class cClientRandomConnection : public cServerConnection {
public:
	cClientRandomConnection(cSocket *socket);
	~cClientRandomConnection();
	virtual void connection_process();
	virtual void evData(u_char *data, size_t dataLen);
};


#endif //HAVE_OPENSSL101 && HAVE_LIBGNUTLS


void ssl_dssl_init();
void ssl_dssl_clean();
void decrypt_ssl_dssl(vector<string> *rslt_decrypt, char *data, unsigned int datalen, vmIP saddr, vmIP daddr, vmPort sport, vmPort dport, struct timeval ts,
		      bool forceTryIfExistsError = false);
void end_decrypt_ssl_dssl(vmIP saddr, vmIP daddr, vmPort sport, vmPort dport);
bool string_looks_like_client_random(u_char *data, unsigned datalen);
bool ssl_parse_client_random(u_char *data, unsigned datalen);
void ssl_parse_client_random(const char *fileName);

void clientRandomServerStart(const char *host, int port);
void clientRandomServerStop();

bool find_master_secret(u_char *client_random, u_char *key, unsigned *key_length);
void erase_client_random(u_char *client_random);


#endif //SSL_DSSL_H
