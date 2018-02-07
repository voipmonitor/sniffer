#ifndef SSL_DSSL_H
#define SSL_DSSL_H


#include "config.h"

#include <map>
#include <string>
#include <vector>


#ifdef HAVE_OPENSSL101


#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "tools.h"

#include "dssl/dssl_defs.h"
#include "dssl/errors.h"
#include "dssl/packet.h"
#include "dssl/ssl_session.h"
#include "dssl/ssl_decode_hs.h"


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
	cSslDsslSession(u_int32_t ip, u_int16_t port, string keyfile, string password = "");
	~cSslDsslSession();
	void setClientIpPort(u_int32_t ipc, u_int16_t portc);
	void init();
	void term();
	bool initServer();
	bool initSession();
	void termServer();
	void termSession();
	void processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport, struct timeval ts);
private:
	NM_PacketDir getDirection(u_int32_t sip, u_int16_t sport, u_int32_t dip, u_int16_t dport);
	static void dataCallback(NM_PacketDir dir, void* user_data, u_char* data, uint32_t len, DSSL_Pkt* pkt);
	static void errorCallback(void* user_data, int error_code);
	static int password_calback_direct(char *buf, int size, int rwflag, void *userdata);
	static int gener_master_secret(u_char *client_random, u_char *master_secret, DSSL_Session *session);
private:
	u_int32_t ip;
	u_int16_t port;
	string keyfile;
	string password;
	u_int32_t ipc;
	u_int16_t portc;
	EVP_PKEY *pkey;
	DSSL_ServerInfo* server_info;
	DSSL_Session* session;
	eServerErrors server_error;
	bool process_error;
	int process_error_code;
	vector<string> *decrypted_data;
	unsigned process_counter;
	bool client_random_master_secret;
friend class cSslDsslSessions;
};


class cSslDsslClientRandomItems {
public:
	class cSslDsslClientRandomIndex {
	public:
		cSslDsslClientRandomIndex(u_char *client_random = NULL);
		bool operator == (const cSslDsslClientRandomIndex& other) const { 
			return(!memcmp(this->client_random, other.client_random, SSL3_RANDOM_SIZE)); 
		}
		bool operator < (const cSslDsslClientRandomIndex& other) const { 
			return(memcmp(this->client_random, other.client_random, SSL3_RANDOM_SIZE) < 0); 
		}
	public:
		u_char client_random[SSL3_RANDOM_SIZE];
	};
	class cSslDsslClientRandomItem {
	public:
		cSslDsslClientRandomItem(u_char *master_secret = NULL);
	public:
		u_char master_secret[SSL3_MASTER_SECRET_SIZE];
		u_int32_t set_at;
	};
public:
	cSslDsslClientRandomItems();
	~cSslDsslClientRandomItems();
	void set(u_char *client_random, u_char *master_secret);
	bool get(u_char *client_random, u_char *master_secret);
	void erase(u_char *client_random);
	void cleanup();
	void clear();
private:
	void lock_map() {
		while(__sync_lock_test_and_set(&this->_sync_map, 1));
	}
	void unlock_map() {
		__sync_lock_release(&this->_sync_map);
	}
private:
	map<cSslDsslClientRandomIndex, cSslDsslClientRandomItem*> map_client_random;
	volatile int _sync_map;
	u_int32_t last_cleanup_at;
};

class cSslDsslSessions {
public:
	cSslDsslSessions();
	~cSslDsslSessions();
public:
	void processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport, struct timeval ts);
	void destroySession(unsigned int saddr, unsigned int daddr, int sport, int dport);
	void clientRandomSet(u_char *client_random, u_char *master_secret);
	bool clientRandomGet(u_char *client_random, u_char *master_secret);
	void clientRandomErase(u_char *client_random);
	void clientRandomCleanup();
private:
	cSslDsslSession *addSession(u_int32_t ip, u_int16_t port);
	NM_PacketDir checkIpPort(u_int32_t sip, u_int16_t sport, u_int32_t dip, u_int16_t dport);
	void init();
	void term();
	void lock_sessions() {
		while(__sync_lock_test_and_set(&this->_sync_sessions, 1));
	}
	void unlock_sessions() {
		__sync_lock_release(&this->_sync_sessions);
	}
private:
	map<sStreamId, cSslDsslSession*> sessions;
	volatile int _sync_sessions;
	cSslDsslClientRandomItems client_random;
};


#endif //HAVE_OPENSSL101


void ssl_dssl_init();
void ssl_dssl_clean();
void decrypt_ssl_dssl(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport, struct timeval ts);
void end_decrypt_ssl_dssl(unsigned int saddr, unsigned int daddr, int sport, int dport);
bool ssl_parse_client_random(u_char *data, unsigned datalen);


#endif //SSL_DSSL_H
