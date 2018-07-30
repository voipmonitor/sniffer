#include "voipmonitor.h"
#include "pcap_queue.h"

#if defined HAVE_OPENSSL101 and defined HAVE_LIBGNUTLS
#include <gcrypt.h>
#endif //HAVE_OPENSSL101 and HAVE_LIBGNUTLS

#include "ssl_dssl.h"


#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)


extern map<d_u_int32_t, string> ssl_ipport;

static cSslDsslSessions *SslDsslSessions;


cSslDsslSession::cSslDsslSession(u_int32_t ip, u_int16_t port, string keyfile, string password) {
	this->ip = ip;
	this->port = port;
	this->keyfile = keyfile;
	this->password = password;
	ipc = 0;
	portc = 0;
	pkey = NULL;
	server_info = NULL;
	session = NULL;
	server_error = _se_na;
	process_error = false;
	process_error_code = 0;
	process_counter = 0;
	client_random_master_secret = false;
	init();
}

cSslDsslSession::~cSslDsslSession() {
	term();
}

void cSslDsslSession::setClientIpPort(u_int32_t ipc, u_int16_t portc) {
	this->ipc = ipc;
	this->portc = portc;
}

void cSslDsslSession::init() {
	if(initServer()) {
		initSession();
	}
}

void cSslDsslSession::term() {
	termSession();
	termServer();
}

bool cSslDsslSession::initServer() {
	EVP_PKEY *pkey = NULL;
	if(keyfile.length()) {
		FILE* file_keyfile = fopen(keyfile.c_str(), "r");
		if(!file_keyfile) {
			server_error = _se_keyfile_not_exists;
			return(false);
		}
		if(!PEM_read_PrivateKey(file_keyfile, &pkey, cSslDsslSession::password_calback_direct, (void*)password.c_str())) {
			fclose(file_keyfile);
			server_error = _se_load_key_failed;
			return(false);
		}
		fclose(file_keyfile);
	}
	this->server_info = new FILE_LINE(0) DSSL_ServerInfo;
	this->server_info->server_ip = *(in_addr*)&ip;
	this->server_info->port = port;
	this->server_info->pkey = pkey;
	server_error = _se_ok;
	return(true);
}

bool cSslDsslSession::initSession() {
	session = new FILE_LINE(0) DSSL_Session;
	DSSL_SessionInit(NULL, session, server_info);
	session->env = DSSL_EnvCreate(100 /*sessionTableSize*/, 3600 /*key_timeout_interval*/);
	session->last_packet = new FILE_LINE(0) DSSL_Pkt;
	session->gener_master_secret = this->gener_master_secret;
	session->gener_master_secret_data[0] = this;
	session->gener_master_secret_data[1] = SslDsslSessions;
	extern bool opt_ssl_ignore_error_invalid_mac;
	session->ignore_error_invalid_mac = opt_ssl_ignore_error_invalid_mac;
	memset(session->last_packet, 0, sizeof(*session->last_packet));
	DSSL_SessionSetCallback(session, cSslDsslSession::dataCallback, cSslDsslSession::errorCallback, this);
	return(true);
}

void cSslDsslSession::termServer() {
	if(server_info) {
		EVP_PKEY_free(server_info->pkey);
		server_info->pkey = NULL;
		delete server_info;
		server_info = NULL;
	}
	server_error = _se_na;
}

void cSslDsslSession::termSession() {
	if(session) {
		DSSL_EnvDestroy(session->env);
		session->env = NULL;
		delete session->last_packet;
		session->last_packet = NULL;
		DSSL_SessionDeInit(session);
		delete session;
		session = NULL;
	}
	process_error = false;
	process_counter = 0;
}

void cSslDsslSession::processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport, struct timeval ts) {
	rslt_decrypt->clear();
	if(!session) {
		return;
	}
	NM_PacketDir dir = this->getDirection(saddr, sport, daddr, dport);
	if(dir != ePacketDirInvalid) {
		bool maybeNextClientHello = false;
		if(process_counter && dir == ePacketDirFromClient) {
			NM_ERROR_DISABLE_LOG;
			uint16_t ver = 0;
			if(!ssl_detect_client_hello_version((u_char*)data, datalen, &ver) && ver) {
				maybeNextClientHello = true;
			}
			NM_ERROR_ENABLE_LOG;
		}
		if(this->process_error) {
			if(maybeNextClientHello) {
				term();
				init();
				this->process_error = false;
			} else {
				return;
			}
		}
		for(unsigned pass = 1; pass <= (maybeNextClientHello ? 2 : 1); pass++) {
			if(pass == 2) {
				term();
				init();
				rslt_decrypt->clear();
			}
			session->last_packet->pcap_header.ts = ts;
			this->decrypted_data = rslt_decrypt;
			int rc = DSSL_SessionProcessData(session, dir, (u_char*)data, datalen);
			if(rc == DSSL_RC_OK) {
				break;
			}
		}
		++process_counter;
	}
}

NM_PacketDir cSslDsslSession::getDirection(u_int32_t sip, u_int16_t sport, u_int32_t dip, u_int16_t dport) {
	return(dip == ip && dport == port ?
		ePacketDirFromClient :
	       sip == ip && sport == port ?
		ePacketDirFromServer :
		ePacketDirInvalid);
}

void cSslDsslSession::dataCallback(NM_PacketDir /*dir*/, void* user_data, u_char* data, uint32_t len, DSSL_Pkt* /*pkt*/) {
	cSslDsslSession *me = (cSslDsslSession*)user_data;
	me->decrypted_data->push_back(string((char*)data, len));
}

void cSslDsslSession::errorCallback(void* user_data, int error_code) {
	cSslDsslSession *me = (cSslDsslSession*)user_data;
	if(!me->process_error) {
		extern bool opt_ssl_log_errors;
		if(opt_ssl_log_errors) {
			syslog(LOG_ERR, "SSL decode failed: err code %i, connection %s:%u -> %s:%u", 
			       error_code,
			       inet_ntostring(me->ipc).c_str(),
			       me->portc,
			       inet_ntostring(me->ip).c_str(),
			       me->port);
		}
		me->process_error = true;
	}
	me->process_error_code = error_code;
}

int cSslDsslSession::password_calback_direct(char *buf, int size, int /*rwflag*/, void *userdata) {
	char* password = (char*)userdata;
	int length = strlen(password);
	strncpy(buf, password, size);
	return(length);
}

int cSslDsslSession::gener_master_secret(u_char *client_random, u_char *master_secret, DSSL_Session *session) {
	if(((cSslDsslSessions*)session->gener_master_secret_data[1])->clientRandomGet(client_random, master_secret, session->last_packet->pcap_header.ts)) {
		((cSslDsslSession*)session->gener_master_secret_data[0])->client_random_master_secret = true;
		return(1);
	}
	return(0);
}


cSslDsslClientRandomItems::cSslDsslClientRandomIndex::cSslDsslClientRandomIndex(u_char *client_random) {
	if(client_random) {
		memcpy(this->client_random, client_random, SSL3_RANDOM_SIZE);
	}
}

cSslDsslClientRandomItems::cSslDsslClientRandomItem::cSslDsslClientRandomItem(u_char *master_secret) {
	if(master_secret) {
		memcpy(this->master_secret, master_secret, SSL3_MASTER_SECRET_SIZE);
		set_at = getTimeS();
	}
}

cSslDsslClientRandomItems::cSslDsslClientRandomItems() {
	_sync_map = 0;
	last_cleanup_at = 0;
}

cSslDsslClientRandomItems::~cSslDsslClientRandomItems() {
	clear();
}

void cSslDsslClientRandomItems::set(u_char *client_random, u_char *master_secret) {
	cSslDsslClientRandomIndex index(client_random);
	cSslDsslClientRandomItem *item = new FILE_LINE(0) cSslDsslClientRandomItem(master_secret);
	lock_map();
	if(map_client_random[index]) {
		delete map_client_random[index];
	}
	map_client_random[index] = item;
	unlock_map();
}

bool cSslDsslClientRandomItems::get(u_char *client_random, u_char *master_secret, struct timeval ts) {
	if(sverb.ssl_sessionkey) {
		cout << "find clientrandom" << endl;
		hexdump(client_random, 32);
	}
	bool rslt = false;
	cSslDsslClientRandomIndex index(client_random);
	int64_t waitUS = -1;
	extern int ssl_client_random_maxwait_ms;
	if(ssl_client_random_maxwait_ms > 0) {
		extern PcapQueue_readFromFifo *pcapQueueQ;
		if(pcapQueueQ) {
			waitUS = pcapQueueQ->getLastUS() - getTimeUS(ts);
		}
	}
	do {
		lock_map();
		map<cSslDsslClientRandomIndex, cSslDsslClientRandomItem*>::iterator iter = map_client_random.find(index);
		if(iter != map_client_random.end()) {
			memcpy(master_secret, iter->second->master_secret, SSL3_MASTER_SECRET_SIZE);
			rslt = true;
		}
		unlock_map();
		if(!rslt) {
			if(waitUS >= 0 && waitUS < ssl_client_random_maxwait_ms * 1000ll) {
				usleep(1000);
				waitUS += 1000;
			} else {
				break;
			}
		}
	} while(!rslt && waitUS >= 0);
	return(rslt);
}

void cSslDsslClientRandomItems::erase(u_char *client_random) {
	cSslDsslClientRandomIndex index(client_random);
	lock_map();
	map<cSslDsslClientRandomIndex, cSslDsslClientRandomItem*>::iterator iter = map_client_random.find(index);
	if(iter != map_client_random.end()) {
		delete iter->second;
		map_client_random.erase(iter);
	}
	unlock_map();
}

void cSslDsslClientRandomItems::cleanup() {
	u_int32_t now = getTimeS();
	if(!last_cleanup_at || last_cleanup_at + 600 < now) {
		lock_map();
		for(map<cSslDsslClientRandomIndex, cSslDsslClientRandomItem*>::iterator iter = map_client_random.begin(); iter != map_client_random.end();) {
			if(iter->second->set_at + 3600 < now) {
				delete iter->second;
				map_client_random.erase(iter++);
			} else {
				iter++;
			}
		}
		unlock_map();
		last_cleanup_at = now;
	}
}

void cSslDsslClientRandomItems::clear() {
	lock_map();
	for(map<cSslDsslClientRandomIndex, cSslDsslClientRandomItem*>::iterator iter = map_client_random.begin(); iter != map_client_random.end(); iter++) {
		delete iter->second;
	}
	map_client_random.clear();
	unlock_map();
}


cSslDsslSessions::cSslDsslSessions() {
	_sync_sessions = 0;
	init();
}

cSslDsslSessions::~cSslDsslSessions() {
	term();
}

void cSslDsslSessions::processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport, struct timeval ts) {
	lock_sessions();
	NM_PacketDir dir = checkIpPort(saddr, sport, daddr, dport);
	if(dir == ePacketDirInvalid) {
		rslt_decrypt->clear();
		unlock_sessions();
		return;
	}
	cSslDsslSession *session = NULL;
	sStreamId sid(dir == ePacketDirFromClient ? daddr : saddr,
		      dir == ePacketDirFromClient ? dport : sport,
		      dir == ePacketDirFromClient ? saddr : daddr,
		      dir == ePacketDirFromClient ? sport : dport);
	map<sStreamId, cSslDsslSession*>::iterator iter_session;
	iter_session = sessions.find(sid);
	if(iter_session != sessions.end()) {
		session = iter_session->second;
	}
	if(!session && dir == ePacketDirFromClient) {
		session = addSession(daddr, dport);
		session->setClientIpPort(saddr, sport);
		sessions[sid] = session;
	}
	if(session) {
		session->processData(rslt_decrypt, data, datalen, saddr, daddr, sport, dport, ts);
	}
	unlock_sessions();
}

void cSslDsslSessions::destroySession(unsigned int saddr, unsigned int daddr, int sport, int dport) {
	lock_sessions();
	NM_PacketDir dir = checkIpPort(saddr, sport, daddr, dport);
	if(dir == ePacketDirInvalid) {
		unlock_sessions();
		return;
	}
	sStreamId sid(dir == ePacketDirFromClient ? daddr : saddr,
		      dir == ePacketDirFromClient ? dport : sport,
		      dir == ePacketDirFromClient ? saddr : daddr,
		      dir == ePacketDirFromClient ? sport : dport);
	map<sStreamId, cSslDsslSession*>::iterator iter_session;
	iter_session = sessions.find(sid);
	if(iter_session != sessions.end()) {
		if(iter_session->second->client_random_master_secret) {
			clientRandomErase(iter_session->second->session->client_random);
		}
		delete iter_session->second;
		sessions.erase(iter_session);
	}
	unlock_sessions();
}

void cSslDsslSessions::clientRandomSet(u_char *client_random, u_char *master_secret) {
	this->client_random.set(client_random, master_secret);
}

bool cSslDsslSessions::clientRandomGet(u_char *client_random, u_char *master_secret, struct timeval ts) {
	return(this->client_random.get(client_random, master_secret, ts));
}

void cSslDsslSessions::clientRandomErase(u_char *client_random) {
	this->client_random.erase(client_random);
}

void cSslDsslSessions::clientRandomCleanup() {
	this->client_random.cleanup();
}

cSslDsslSession *cSslDsslSessions::addSession(u_int32_t ip, u_int16_t port) {
	cSslDsslSession *session = new FILE_LINE(0) cSslDsslSession(ip, port, ssl_ipport[d_u_int32_t(ip, port)]);
	return(session);
}

NM_PacketDir cSslDsslSessions::checkIpPort(u_int32_t sip, u_int16_t sport, u_int32_t dip, u_int16_t dport) {
	map<d_u_int32_t, string>::iterator iter_ssl_ipport;
	iter_ssl_ipport = ssl_ipport.find(d_u_int32_t(dip, dport));
	if(iter_ssl_ipport != ssl_ipport.end()) {
		return(ePacketDirFromClient);
	}
	iter_ssl_ipport = ssl_ipport.find(d_u_int32_t(sip, sport));
	if(iter_ssl_ipport != ssl_ipport.end()) {
		return(ePacketDirFromServer);
	}
	return(ePacketDirInvalid);
}

void cSslDsslSessions::init() {
	SSL_library_init();	
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
}

void cSslDsslSessions::term() {
	map<sStreamId, cSslDsslSession*>::iterator iter_session;
	for(iter_session = sessions.begin(); iter_session != sessions.end();) {
		delete iter_session->second;
		sessions.erase(iter_session++);
	}
}


#endif //HAVE_OPENSSL101 && HAVE_LIBGNUTLS


void ssl_dssl_init() {
	#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)
	SslDsslSessions = new FILE_LINE(0) cSslDsslSessions;
	extern bool init_lib_gcrypt();
	init_lib_gcrypt();
	#endif //HAVE_OPENSSL101 && HAVE_LIBGNUTLS
}

void ssl_dssl_clean() {
	#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)
	if(SslDsslSessions) {
		delete SslDsslSessions;
		SslDsslSessions = NULL;
	}
	#endif //HAVE_OPENSSL101 && HAVE_LIBGNUTLS
}


void decrypt_ssl_dssl(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport, struct timeval ts) {
	#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)
	SslDsslSessions->processData(rslt_decrypt, data, datalen, saddr, daddr, sport, dport, ts);
	#endif //HAVE_OPENSSL101 && HAVE_LIBGNUTLS
}

void end_decrypt_ssl_dssl(unsigned int saddr, unsigned int daddr, int sport, int dport) {
	#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)
	SslDsslSessions->destroySession(saddr, daddr, sport, dport);
	SslDsslSessions->clientRandomCleanup();
	#endif //HAVE_OPENSSL101 && HAVE_LIBGNUTLS
}

bool ssl_parse_client_random(u_char *data, unsigned datalen) {
	#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)
	if(!SslDsslSessions) {
		return(false);
	}
	JsonItem jsonData;
	jsonData.parse(string((char*)data, datalen).c_str());
	string sessionid = jsonData.getValue("sessionid");
	string mastersecret = jsonData.getValue("mastersecret");
	if(sessionid.length() == SSL3_RANDOM_SIZE * 2 &&
	   mastersecret.length() == SSL3_MASTER_SECRET_SIZE * 2) {
		u_char client_random[SSL3_RANDOM_SIZE];
		u_char master_secret[SSL3_MASTER_SECRET_SIZE];
		hexdecode(client_random, sessionid.c_str(), SSL3_RANDOM_SIZE);
		hexdecode(master_secret, mastersecret.c_str(), SSL3_MASTER_SECRET_SIZE);
		SslDsslSessions->clientRandomSet(client_random, master_secret);
		if(sverb.ssl_sessionkey) {
			cout << "set clientrandom" << endl;
			hexdump(client_random, 32);
		}
		return(true);
	}
	#endif //HAVE_OPENSSL101 && HAVE_LIBGNUTLS
	return(false);
}
