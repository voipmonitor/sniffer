#include "voipmonitor.h"
#include "pcap_queue.h"

#if defined HAVE_OPENSSL101 and defined HAVE_LIBGNUTLS
#include <gcrypt.h>
#endif //HAVE_OPENSSL101 and HAVE_LIBGNUTLS

#include "ssl_dssl.h"


#if defined(HAVE_OPENSSL101) and defined(HAVE_LIBGNUTLS)


extern map<d_u_int32_t, string> ssl_ipport;
extern int opt_ssl_store_sessions;
extern MySqlStore *sqlStore;
extern int opt_id_sensor;
extern int opt_nocdr;

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
	process_data_counter = 0;
	process_error = false;
	process_error_code = 0;
	client_random_master_secret = false;
	stored_at = 0;
	restored = false;
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
	process_data_counter = 0;
	process_error = false;
	process_error_code = 0;
	stored_at = 0;
	restored = false;
}

void cSslDsslSession::processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, 
				  unsigned int saddr, unsigned int daddr, int sport, int dport, 
				  struct timeval ts, bool init, class cSslDsslSessions *sessions) {
	rslt_decrypt->clear();
	if(!session) {
		return;
	}
	NM_PacketDir dir = this->getDirection(saddr, sport, daddr, dport);
	if(dir != ePacketDirInvalid) {
		bool reinit = false;
		if(!init && (process_error || restored)) {
			if(this->isClientHello(data, datalen, dir)) {
				this->term();
				this->init();
				reinit = true;
			} else if(process_error) {
				return;
			}
		}
		for(unsigned pass = 1; pass <= (init || reinit ? 1 : 2); pass++) {
			if(pass == 2) {
				if(this->isClientHello(data, datalen, dir)) {
					this->term();
					this->init();
					rslt_decrypt->clear();
				} else {
					break;
				}
			}
			session->last_packet->pcap_header.ts = ts;
			this->decrypted_data = rslt_decrypt;
			int rc = DSSL_SessionProcessData(session, dir, (u_char*)data, datalen);
			if(rc == DSSL_RC_OK) {
				if(opt_ssl_store_sessions && !opt_nocdr && !init) {
					this->store_session(sessions, ts);
				}
				break;
			}
		}
	}
}

bool cSslDsslSession::isClientHello(char *data, unsigned int datalen, NM_PacketDir dir) {
	bool isClientHello = false;
	if(dir == ePacketDirFromClient) {
		NM_ERROR_DISABLE_LOG;
		uint16_t ver = 0;
		if(!ssl_detect_client_hello_version((u_char*)data, datalen, &ver) && ver) {
			isClientHello = true;
		}
		NM_ERROR_ENABLE_LOG;
	}
	return(isClientHello);
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
	++me->process_data_counter;
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

string cSslDsslSession::get_session_data(struct timeval ts) {
	JsonExport json;
	json.add("version", session->version);
	json.add("cipher_suite", session->cipher_suite);
	json.add("compression_method", session->compression_method);
	json.add("client_random", hexencode(session->client_random, sizeof(session->client_random)));
	json.add("server_random", hexencode(session->server_random, sizeof(session->server_random)));
	json.add("master_secret", hexencode(session->master_secret, sizeof(session->master_secret)));
	json.add("c_dec_version", session->c_dec.version);
	json.add("s_dec_version", session->s_dec.version);
	json.add("stored_at", ts.tv_sec);
	return(json.getJson());
}

bool cSslDsslSession::restore_session_data(const char *data) {
	JsonItem jsonData;
	jsonData.parse(data);
	session->version = atoi(jsonData.getValue("version").c_str());
	session->cipher_suite = atoi(jsonData.getValue("cipher_suite").c_str());
	session->compression_method = atoi(jsonData.getValue("compression_method").c_str());
	hexdecode(session->client_random, jsonData.getValue("client_random").c_str(), sizeof(session->client_random));
	hexdecode(session->server_random, jsonData.getValue("server_random").c_str(), sizeof(session->server_random));
	hexdecode(session->master_secret, jsonData.getValue("master_secret").c_str(), sizeof(session->master_secret));
	if(ssls_generate_keys(session) != DSSL_RC_OK ||
	   ssls_set_session_version(session, session->version) != DSSL_RC_OK ||
	   dssl_decoder_stack_flip_cipher(&session->c_dec) != DSSL_RC_OK ||
	   dssl_decoder_stack_flip_cipher(&session->s_dec) != DSSL_RC_OK) {
		return(false);
	}
	session->c_dec.sess = session;
	session->s_dec.sess = session;
	if(dssl_decoder_stack_set(&session->c_dec, session, atoi(jsonData.getValue("c_dec_version").c_str())) == DSSL_RC_OK &&
	   dssl_decoder_stack_set(&session->s_dec, session, atoi(jsonData.getValue("s_dec_version").c_str())) == DSSL_RC_OK) {
		restored = true;
		stored_at = atol(jsonData.getValue("stored_at").c_str());
		return(true);
	}
	return(false);
}

void cSslDsslSession::store_session(cSslDsslSessions *sessions, struct timeval ts) {
	if(opt_ssl_store_sessions && !opt_nocdr &&
	   this->process_data_counter > 0 &&
	   this->session->c_dec.version && this->session->s_dec.version &&
	   (!this->stored_at || this->stored_at < (u_long)(ts.tv_sec - 3600))) {
		string session_data = get_session_data(ts);
		SqlDb_row session_row_insert;
		session_row_insert.add(opt_id_sensor, "id_sensor");
		session_row_insert.add(ip, "serverip");
		session_row_insert.add(port, "serverport");
		session_row_insert.add(ipc, "clientip");
		session_row_insert.add(portc, "clientport");
		session_row_insert.add(sqlDateTimeString(ts.tv_sec), "stored_at");
		session_row_insert.add(session_data, "session");
		SqlDb_row session_row_update;
		session_row_update.add(sqlDateTimeString(ts.tv_sec), "stored_at");
		session_row_update.add(session_data, "session");
		if(!sessions->sqlDb) {
			sessions->sqlDb = createSqlObject();
		}
		sqlStore->query_lock(sessions->sqlDb->insertOrUpdateQuery(sessions->storeSessionsTableName(), session_row_insert, session_row_update, false, true).c_str(),
				     STORE_PROC_ID_OTHER);
		this->stored_at = ts.tv_sec;
		sessions->deleteOldSessions(ts);
	}
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
	_sync_sessions_db = 0;
	sqlDb = NULL;
	last_delete_old_sessions_at = 0;
	loadSessions();
	init();
}

cSslDsslSessions::~cSslDsslSessions() {
	if(sqlDb) {
		delete sqlDb;
	}
	term();
}

void cSslDsslSessions::processData(vector<string> *rslt_decrypt, char *data, unsigned int datalen, unsigned int saddr, unsigned int daddr, int sport, int dport, struct timeval ts) {
	/*
	if(!(sport == 50404 || dport == 50404)) {
		return;
	}
	if(ts.tv_sec < 1533040717) {
		return;
	}
	if(getTimeUS(ts) < 1487014991237727ull) {
		return;
	}
	*/
	lock_sessions();
	NM_PacketDir dir = checkIpPort(saddr, sport, daddr, dport);
	if(dir == ePacketDirInvalid) {
		rslt_decrypt->clear();
		unlock_sessions();
		return;
	}
	unsigned int server_addr, client_addr;
	int server_port, client_port;
	server_addr = dir == ePacketDirFromClient ? daddr : saddr;
	server_port = dir == ePacketDirFromClient ? dport : sport;
	client_addr = dir == ePacketDirFromClient ? saddr : daddr;
	client_port = dir == ePacketDirFromClient ? sport : dport;
	cSslDsslSession *session = NULL;
	sStreamId sid(server_addr, server_port, client_addr, client_port);
	map<sStreamId, cSslDsslSession*>::iterator iter_session;
	iter_session = sessions.find(sid);
	if(iter_session != sessions.end()) {
		session = iter_session->second;
	}
	bool init_client_hello = false;
	bool init_store_session = false;
	if(!session && dir == ePacketDirFromClient) {
		NM_ERROR_DISABLE_LOG;
		uint16_t ver = 0;
		if(!ssl_detect_client_hello_version((u_char*)data, datalen, &ver) && ver) {
			init_client_hello = true;
		}
		NM_ERROR_ENABLE_LOG;
		if(init_client_hello) {
			session = addSession(server_addr, server_port);
			session->setClientIpPort(client_addr, client_port);
			sessions[sid] = session;
			lock_sessions_db();
			if(sessions_db.find(sid) != sessions_db.end()) {
				sessions_db.erase(sid);
			}
			unlock_sessions_db();
		}
	}
	if(!session) {
		sSessionData session_data;
		lock_sessions_db();
		map<sStreamId, sSessionData>::iterator iter_session_db = sessions_db.find(sid);
		if(iter_session_db != sessions_db.end()) {
			session_data = iter_session_db->second;
		}
		unlock_sessions_db();
		if(!session_data.data.empty()) {
			session = addSession(server_addr, server_port);
			session->setClientIpPort(client_addr, client_port);
			if(session->restore_session_data(session_data.data.c_str())) {
				sessions[sid] = session;
				init_store_session = true;
				lock_sessions_db();
				sessions_db.erase(sid);
				unlock_sessions_db();
			} else {
				delete session;
				session = NULL;
			}
		}
	}
	if(session) {
		session->processData(rslt_decrypt, data, datalen, 
				     saddr, daddr, sport, dport, 
				     ts, init_client_hello || init_store_session, this);
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

void cSslDsslSessions::loadSessions() {
	if(!opt_ssl_store_sessions || opt_nocdr) {
		return;
	}
	if(!sqlDb) {
		sqlDb = createSqlObject();
	}
	if(!sqlDb->existsTable(storeSessionsTableName())) {
		return;
	}
	list<SqlDb_condField> cond;
	cond.push_back(SqlDb_condField("id_sensor", intToString(opt_id_sensor)));
	cond.push_back(SqlDb_condField("stored_at", sqlDateTimeString(getTimeS() - 12 * 3600)).setOper(">"));
	sqlDb->select(storeSessionsTableName(), NULL, &cond);
	SqlDb_row row;
	while((row = sqlDb->fetchRow())) {
		sStreamId sid(atol(row["serverip"].c_str()), atoi(row["serverport"].c_str()), 
			      atol(row["clientip"].c_str()), atoi(row["clientport"].c_str()));
		sSessionData session_data;
		session_data.data = row["session"];
		lock_sessions_db();
		sessions_db[sid] = session_data;
		unlock_sessions_db();
	}
}

void cSslDsslSessions::deleteOldSessions(struct timeval ts) {
	if(!opt_ssl_store_sessions || opt_nocdr) {
		return;
	}
	if(!last_delete_old_sessions_at || last_delete_old_sessions_at < (u_long)(ts.tv_sec - 3600)) {
		if(!sqlDb) {
			sqlDb = createSqlObject();
		}
		if(!sqlDb->existsTable(storeSessionsTableName())) {
			return;
		}
		list<SqlDb_condField> cond;
		cond.push_back(SqlDb_condField("id_sensor", intToString(opt_id_sensor)));
		cond.push_back(SqlDb_condField("stored_at", sqlDateTimeString(ts.tv_sec - 12 * 3600)).setOper("<"));
		sqlStore->query_lock("delete from " + storeSessionsTableName() + " where " + sqlDb->getCondStr(&cond),
				     STORE_PROC_ID_OTHER);
		last_delete_old_sessions_at = ts.tv_sec;
	}
}

string cSslDsslSessions::storeSessionsTableName() {
	return(opt_ssl_store_sessions == 1 ? "ssl_sessions_mem" :
	       opt_ssl_store_sessions == 2 ? "ssl_sessions" : "");
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
