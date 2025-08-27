#include <stdio.h>
#include <iostream>
#include <syslog.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sstream>
#include <stdarg.h>
#include <netdb.h>
#include <mysqld_error.h>
#include <errmsg.h>
#include <dirent.h>
#include <math.h>
#include <signal.h>
#include <cstdarg>

#include "voipmonitor.h"

#ifndef FREEBSD
#include <sys/inotify.h>
#endif

#include "tools.h"

#include "sql_db.h"
#include "fraud.h"
#include "billing.h"
#include "calltable.h"
#include "cleanspool.h"
#include "server.h"
#include "charts.h"
#include "config_param.h"

#define QFILE_PREFIX "qoq"

extern int verbosity;
extern int opt_mysql_port;
extern char opt_match_header[128];
extern int opt_ipaccount;
extern int opt_id_sensor;
extern bool opt_cdr_partition;
extern bool opt_cdr_partition_by_hours;
extern bool opt_cdr_force_primary_index_in_all_tables;
extern bool opt_cdr_sipport;
extern bool opt_last_rtp_from_end;
extern bool opt_cdr_rtpport;
extern bool opt_cdr_rtpsrcport;
extern int opt_cdr_stat_values;
extern bool opt_cdr_stat_sources;
extern int opt_cdr_problems;
extern bool opt_cdr_problems_by_ip;
extern bool opt_cdr_problems_by_number;
extern bool opt_cdr_problems_by_comb;
extern int opt_create_old_partitions;
extern bool opt_disable_partition_operations;
extern vector<dstring> opt_custom_headers_cdr;
extern vector<dstring> opt_custom_headers_message;
extern char get_customers_pn_query[1024];
extern int opt_dscp;
extern int opt_enable_http_enum_tables;
extern int opt_enable_webrtc_table;
extern int opt_mysqlcompress;
extern char opt_mysqlcompress_type[256];
extern int opt_mysql_enable_transactions;
extern pthread_mutex_t mysqlconnect_lock;      
extern int opt_mos_lqo;
extern int opt_enable_fraud;
extern bool _save_sip_history;
extern bool opt_sql_time_utc;
extern int opt_enable_ss7;
extern int opt_ssl_store_sessions;
extern int opt_cdr_country_code;
extern int opt_message_country_code;
extern int opt_mysql_enable_multiple_rows_insert;
extern bool opt_time_precision_in_ms;
extern bool opt_save_energylevels;
extern int opt_save_ip_from_encaps_ipheader;
extern int opt_sip_register;

extern char sql_driver[256];

extern char mysql_host[256];
extern char mysql_database[256];
extern char mysql_user[256];
extern char mysql_password[256];
extern int opt_mysql_port;
extern char mysql_socket[256];
extern mysqlSSLOptions optMySsl;

extern char mysql_2_host[256];
extern char mysql_2_database[256];
extern char mysql_2_user[256];
extern char mysql_2_password[256];
extern int opt_mysql_2_port;
extern char mysql_2_socket[256];
extern mysqlSSLOptions optMySsl_2;

extern char opt_mysql_timezone[256];
extern int opt_mysql_client_compress;
extern int opt_skiprtpdata;

extern char odbc_dsn[256];
extern char odbc_user[256];
extern char odbc_password[256];
extern char odbc_driver[256];

extern int opt_nocdr;

extern CustomHeaders *custom_headers_cdr;
extern CustomHeaders *custom_headers_message;
extern CustomHeaders *custom_headers_sip_msg;

extern int opt_ptime;

extern bool cloud_db;
extern string cloud_db_version;

extern sSnifferClientOptions snifferClientOptions;
extern sSnifferClientOptions snifferClientOptions_charts_cache;
extern sSnifferServerClientOptions snifferServerClientOptions;

extern int opt_load_query_main_from_files;

extern bool opt_disable_cdr_fields_rtp;
extern bool opt_disable_cdr_indexes_rtp;
extern int opt_mysql_redirect_cdr_queue;


extern bool opt_sip_register_save_eq_states_time;

extern bool opt_conference_processing;
extern vector<string> opt_mo_mt_identification_prefix;
extern bool srvcc_set;
extern int opt_separate_storage_ipv6_ipv4_address;

extern bool opt_sql_log_all_errors;
extern string opt_sql_errors_log_file;
extern char opt_sql_errors_skip[1024];

int sql_noerror = 0;
int sql_disable_next_attempt_if_error = 0;
bool opt_cdr_partition_oldver = false;
bool opt_ss7_partition_oldver;
bool opt_cdr_stat_values_partition_oldver[2] = { false, false };
bool opt_cdr_stat_sources_partition_oldver[2] = { false, false };
bool opt_cdr_problems_partition_oldver[3] = { false, false, false };
bool opt_rtp_stat_partition_oldver = false;
bool opt_log_sensor_partition_oldver = false;
sExistsColumns existsColumns;
SqlDb::eSupportPartitions supportPartitions = SqlDb::_supportPartitions_ok;

cSqlDbData *dbData;
cDbCalls *dbCalls;

volatile int partitionsServiceIsInProgress = 0;


#if DEBUG_STORE_COUNT
map<int, u_int64_t> _store_cnt;
map<int, u_int64_t> _store_old_cnt;
map<int, u_int64_t> _query_lock_cnt;
map<int, u_int64_t> _query_to_file_cnt;
map<int, u_int64_t> _loadFromQFile_cnt;
map<int, u_int64_t> _charts_cache_cnt;
#endif


string SqlDb_row::SqlDb_rowField::getContentForCsv() {
	switch(ifv.type) {
	case _ift_ip:
		return(ifv.v_ip.getString());
	case _ift_calldate:
		return(intToString(ifv.v._int_u));
	default:
		break;
	}
	return(content);
}

string SqlDb_row::operator [] (const char *fieldName) {
	int indexField = this->getIndexField(fieldName);
	if(indexField >= 0 && (unsigned)indexField < row.size()) {
		return(row[indexField].content);
	}
	return("");
}

string SqlDb_row::operator [] (string fieldName) {
	return((*this)[fieldName.c_str()]);
}

string SqlDb_row::operator [] (int indexField) {
	return(row[indexField].content);
}

SqlDb_row::operator int() {
	return(!this->isEmpty());
}

bool SqlDb_row::setContent(const char *fieldName, const char *newContent) {
	int indexField = this->getIndexField(fieldName);
	if(indexField >= 0 && (unsigned)indexField < row.size()) {
		row[indexField].content = newContent;
		return(true);
	}
	return(false);
}

void SqlDb_row::add(vmIP content, string fieldName, bool null, SqlDb *sqlDb, const char *table) {
	if(!content.isSet() && null) {
		this->add((const char*)NULL, fieldName, 0, 0, _ift_ip)
		    ->ifv.v_ip = content;
	} else {
		if(VM_IPV6_B) {
			if(sqlDb->isIPv6Column(table, fieldName)) {
				this->add(string(MYSQL_VAR_PREFIX) + content._getStringForMysqlIpColumn(6), fieldName, false, _ift_ip)
				    ->ifv.v_ip = content;
				return;
			}
		}
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%u", content.getIPv4());
		this->add(str_content, fieldName, 0, 0, _ift_ip)
		    ->ifv.v_ip = content;
	}
}

void SqlDb_row::add_calldate(u_int64_t calldate_us, string fieldName, bool use_ms) {
	char dateTimeBuffer[50];
	if(use_ms) {
		sqlDateTimeString_us2ms(dateTimeBuffer, calldate_us);
		add(dateTimeBuffer, fieldName, 0, 0, _ift_calldate)
		    ->ifv.v._int_u = (u_int64_t)round(calldate_us / 1000.) * 1000ull;
	} else {
		sqlDateTimeString(dateTimeBuffer, TIME_US_TO_S(calldate_us));
		add(dateTimeBuffer, fieldName, 0, 0, _ift_calldate)
		    ->ifv.v._int_u = TIME_US_TO_S(calldate_us) * 1000000ull;
	}
}

void SqlDb_row::add_duration(u_int64_t duration_us, string fieldName, bool use_ms, bool round_s, u_int64_t limit) {
	if((int64_t)duration_us >= 0) {
		if(use_ms) {
			double duration = TIME_US_TO_SF(duration_us);
			if(limit && duration > limit) {
				duration = limit;
			}
			add(duration, fieldName);
		} else {
			unsigned duration = round_s ? (unsigned)round(TIME_US_TO_SF(duration_us)) : TIME_US_TO_S(duration_us);
			if(limit && duration > limit) {
				duration = limit;
			}
			add(duration, fieldName);
		}
	}
}

void SqlDb_row::add_duration(int64_t duration_us, string fieldName, bool use_ms, bool round_s, int64_t limit) {
	if(use_ms) {
		double duration = TIME_US_TO_SF(duration_us);
		if(limit) {
			if(duration > limit) {
				duration = limit;
			} else if(duration < -limit) {
				duration = -limit;
			}
		}
		add(duration, fieldName);
	} else {
		int duration = round_s ? (int)round(TIME_US_TO_SF(duration_us)) : TIME_US_TO_S_signed(duration_us);
		if(limit) {
			if(duration > limit) {
				duration = limit;
			} else if(duration < -limit) {
				duration = -limit;
			}
		}
		add(duration, fieldName);
	}
}

void SqlDb_row::add_cb_string(string content, string fieldName, int cb_type) {
	this->add(content, fieldName, false, _ift_cb_string)
	    ->ifv.cb_type = cb_type;
}

int SqlDb_row::_getIndexField(string fieldName) {
	return(this->sqlDb->getIndexField(fieldName));
}

string SqlDb_row::_getNameField(int indexField) {
	return(this->sqlDb->getNameField(indexField));
}

string SqlDb_row::implodeFields(string separator, string border) {
	string rslt;
	rslt.reserve(this->row.size() * 20);
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		rslt += border;
		rslt += this->row[i].fieldName;
		rslt += border;
	}
	return(rslt);
}

string SqlDb_row::implodeFieldsToCsv() {
	return(implodeFields(",", "\""));
}

string SqlDb_row::implodeContent(string separator, string border, bool enableSqlString, bool escapeAll) {
	string rslt;
	rslt.reserve(this->row.size() * 100);
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		if(this->row[i].null) {
			rslt += "NULL";
		} else if(enableSqlString && this->row[i].content.substr(0, 12) == MYSQL_VAR_PREFIX) {
			rslt += this->row[i].content.substr(12);
		} else if(this->row[i].content.substr(0, 14) == MYSQL_CODEBOOK_ID_PREFIX) {
			rslt += this->row[i].content;
		} else if(this->row[i].ifv.type == _ift_cb_string){
			string nameValue = dbData->getCbNameForType((cSqlDbCodebook::eTypeCodebook)this->row[i].ifv.cb_type) + ";" + this->row[i].content;
			string fieldContent = MYSQL_CODEBOOK_ID_PREFIX + intToString(nameValue.length()) + ":" + nameValue;
			rslt += fieldContent;
		} else {
			rslt += border;
			rslt += escapeAll ? sqlEscapeString(this->row[i].content) : this->row[i].content;
			rslt += border;
		}
	}
	return(rslt);
}

string SqlDb_row::implodeFieldContent(string separator, string fieldBorder, string contentBorder, bool enableSqlString, bool escapeAll) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		rslt += fieldBorder + /*'`' +*/ this->row[i].fieldName + /*'`' +*/ fieldBorder;
		rslt += " = ";
		if(this->row[i].null) {
			rslt += "NULL";
		} else if(enableSqlString && this->row[i].content.substr(0, 12) == MYSQL_VAR_PREFIX) {
			rslt += this->row[i].content.substr(12);
		} else if(this->row[i].content.substr(0, 14) == MYSQL_CODEBOOK_ID_PREFIX) {
			rslt += this->row[i].content;
		} else if(this->row[i].ifv.type == _ift_cb_string){
			string nameValue = dbData->getCbNameForType((cSqlDbCodebook::eTypeCodebook)this->row[i].ifv.cb_type) + ";" + this->row[i].content;
			string fieldContent = MYSQL_CODEBOOK_ID_PREFIX + intToString(nameValue.length()) + ":" + nameValue;
			rslt += fieldContent;
		} else {
			rslt += contentBorder + 
				(escapeAll ? sqlEscapeString(this->row[i].content) : this->row[i].content) + 
				contentBorder;
		}
	}
	return(rslt);
}

string SqlDb_row::implodeContentTypeToCsv(bool enableSqlString) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += ","; }
		if(this->row[i].null) {
			rslt += string(1, '0' + _ift_null);
		} else if(enableSqlString && this->row[i].content.substr(0, 12) == MYSQL_VAR_PREFIX) {
			rslt += '"' + 
				string(1, '0' + _ift_sql) + ':' +
				this->row[i].content.substr(12) +
				'"';
		} else if(this->row[i].content.substr(0, 14) == MYSQL_CODEBOOK_ID_PREFIX) {
			rslt += '"' + 
				string(1, '0' + _ift_cb_old) + ':' +
				this->row[i].content + 
				'"';
		} else if(this->row[i].ifv.type == _ift_cb_string) {
			rslt += '"' + 
				string(1, '0' + this->row[i].ifv.type + this->row[i].ifv.cb_type) + ':';
			if(this->row[i].content.find("\",") != string::npos) {
				const char *content_src = this->row[i].content.c_str();
				unsigned content_src_length = this->row[i].content.length();
				string content_esc;
				for(unsigned i = 0; i < content_src_length; i++) {
					if(i < content_src_length  - 1 &&
					   content_src[i] == '"' && content_src[i + 1] == ',' &&
					   (i == 0 || content_src[i - 1] != '\\')) {
						content_esc += "\\\",";
						++i;
					} else {
						content_esc += content_src[i];
					}
				}
				rslt += content_esc;
			} else {
				rslt += this->row[i].content;
			}
			rslt += '"';
		} else {
			rslt += '"' + 
				string(1, '0' + this->row[i].ifv.type) + ':' +
				this->row[i].getContentForCsv() + 
				'"';
		}
	}
	return(rslt);
}

string SqlDb_row::keyvalList(string separator) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(this->row[i].null) {
			rslt += this->row[i].fieldName + ":NULL\n";
		} else {
			rslt += this->row[i].fieldName + separator + this->row[i].content + "\n";
		}
	}
	return(rslt);
}

size_t SqlDb_row::getCountFields() {
	return(row.size());
}

void SqlDb_row::removeFieldsIfNotContainIn(map<string, int> *fields) {
	for(size_t i = row.size(); i > 0; i--) {
		if(!(*fields)[row[i - 1].fieldName]) {
			row.erase(row.begin() + i - 1);
		}
	}
}

void SqlDb_row::clearSqlDb() {
	this->sqlDb = NULL;
}


SqlDb_rows::SqlDb_rows() {
	iter_rows = NULL;
}

SqlDb_rows::~SqlDb_rows() {
	if(iter_rows) {
		delete iter_rows;
	}
}

void SqlDb_rows::push(SqlDb_row *row) {
	row->clearSqlDb();
	rows.push_back(*row);
}

SqlDb_row& SqlDb_rows::fetchRow() {
	static SqlDb_row row_empty;
	if(!iter_rows) {
		if(!rows.size()) {
			return(row_empty);
		}
		iter_rows = new list<SqlDb_row>::iterator;
		*iter_rows = rows.begin();
	} else {
		(*iter_rows)++;
	}
	if(*iter_rows == rows.end()) {
		delete iter_rows;
		iter_rows = NULL;
	} else {
		return(*(*iter_rows));
	}
	return(row_empty);
}

void SqlDb_rows::initFetch() {
	if(iter_rows) {
		delete iter_rows;
	}
}

unsigned SqlDb_rows::countRow() {
	return(rows.size());
}

SqlDb_rows::operator unsigned() {
	return(rows.size());
}

void SqlDb_rows::clear() {
	if(iter_rows) {
		delete iter_rows;
	}
	rows.clear();
}


SqlDb::SqlDb() {
	this->clearLastError();
	this->conn_port = 0;
	this->conn_sslkey = NULL;
	this->conn_sslcert = NULL;
	this->conn_sslcacert = NULL;
	this->conn_sslcapath = NULL;
	this->conn_disable_secure_auth = false;
	this->cloud_router = false;
	this->conn_showversion = false;
	this->maxQueryPass = UINT_MAX;
	this->loginTimeout = (ulong)NULL;
	this->enableSqlStringInContent = false;
	this->disableNextAttemptIfError = false;
	this->disableLogError = false;
	this->silentConnect = false;
	this->connecting = false;
	this->response_data_rows = 0;
	this->response_data_index = 0;
	this->maxAllowedPacket = 1024*1024*100;
	this->lastError = 0;
	this->remote_socket = NULL;
	this->existsColumn_cache_enable = false;
	this->existsColumn_cache_suspend = false;
	this->existsColumn_cache_sync = 0;
	this->partitions_cache_sync = 0;
	this->useCsvInRemoteResult = false;
}

map<string, map<string, string> > SqlDb::typeColumn_cache;  
volatile int SqlDb::typeColumn_cache_sync = 0;

SqlDb::~SqlDb() {
	if(this->remote_socket) {
		this->remote_socket->sendEnd();
		delete this->remote_socket;
	}
}

void SqlDb::setConnectParameters(string server, string user, string password, string database, u_int16_t port, string socket, 
				 bool showversion, mysqlSSLOptions *sslOpt) {
	this->conn_server = server;
	this->conn_user = user;
	this->conn_password = password;
	this->conn_database = database;
	this->conn_port = port;
	this->conn_socket = socket;
	this->conn_showversion = showversion;
	if (sslOpt) {
		this->conn_sslkey = sslOpt->key;
		this->conn_sslcert = sslOpt->cert;
		this->conn_sslcacert = sslOpt->caCert;
		this->conn_sslcapath = sslOpt->caPath;
		this->conn_sslciphers = sslOpt->ciphers;
	} else {
		this->conn_sslkey = NULL;
		this->conn_sslcert = NULL;
		this->conn_sslcacert = NULL;
		this->conn_sslcapath = NULL;
	}
}

void SqlDb::setCloudParameters(string cloud_host, string cloud_token, bool cloud_router) {
	this->cloud_host = cloud_host;
	this->cloud_token = cloud_token;
	this->cloud_router = cloud_router;
}

void SqlDb::setLoginTimeout(ulong loginTimeout) {
	this->loginTimeout = loginTimeout;
}

void SqlDb::setDisableSecureAuth(bool disableSecureAuth) {
	this->conn_disable_secure_auth = disableSecureAuth;
}

bool SqlDb::reconnect() {
	if(this->connecting) {
		if(verbosity > 1) {
			syslog(LOG_NOTICE, "prevent recursion of connect to db");
		}
		return(false);
	}
	if(verbosity > 1) {
		syslog(LOG_INFO, "start reconnect");
	}
	this->disconnect();
	bool rslt = this->connect();
	if(verbosity > 1) {
		syslog(LOG_INFO, "reconnect rslt: %s", rslt ? "OK" : "FAIL");
	}
	return(rslt);
}

void SqlDb::setCsvInRemoteResult(bool useCsvInRemoteResult) {
	this->useCsvInRemoteResult = useCsvInRemoteResult;
}

bool SqlDb::queryByRemoteSocket(string query, bool callFromStoreProcessWithFixDeadlock, const char *dropProcQuery) {
	clearLastError();
	bool ok = false;
	unsigned int attempt = 0;
	unsigned int send_query_counter = 0;
	u_int64_t startTimeMS = getTimeMS();
	for(unsigned int pass = 0; pass < this->maxQueryPass; attempt++) {
		if(is_terminating() > 1 ||
		   (isCloud() && is_read_from_file_simple() && getTimeMS() > startTimeMS + 5 * 1000)) {
			break;
		}
		string preparedQuery = this->prepareQuery(query, !callFromStoreProcessWithFixDeadlock && send_query_counter > 1);
		if(attempt > 0) {
			if(this->remote_socket) {
				delete this->remote_socket;
				this->remote_socket = NULL;
			}
			sleep(min(1 + attempt * 2,  60u));
			syslog(LOG_INFO, "next attempt %u - query: %s", attempt, prepareQueryForPrintf(preparedQuery.c_str()).substr(0, 100).c_str());
		} else if(this->remote_socket && this->remote_socket->getLastTimeOkRead() && getTimeUS() > this->remote_socket->getLastTimeOkRead() + 10 * 1000000ull) {
			if(!this->remote_socket->checkHandleRead()) {
				delete this->remote_socket;
				this->remote_socket = NULL;
			}
		}
		if(!this->remote_socket) {
			this->remote_socket = new FILE_LINE(0) cSocketBlock("sql query", true);
			if(isCloud()) {
				extern unsigned cloud_router_port;
				this->remote_socket->setHostPort(cloud_host, cloud_router_port);
			} else {
				this->remote_socket->setHostsPort(snifferClientOptions.hosts, snifferClientOptions.port);
			}
			if(!this->remote_socket->connect()) {
				setLastError(0, string("failed connect to ") + (isCloud() ? "cloud router" : "server"), true);
				continue;
			}
			string cmd = isCloud() ?
				      "{\"type_connection\":\"sniffer_sql_query\",\"gzip\":1}\r\n" :
				      "{\"type_connection\":\"query\"}\r\n";
			if(!this->remote_socket->write(cmd)) {
				setLastError(0, "failed send command", true);
				continue;
			}
			string rsltRsaKey;
			if(!this->remote_socket->readBlock(&rsltRsaKey) || rsltRsaKey.find("key") == string::npos) {
				setLastError(0, "failed read rsa key", true);
				continue;
			}
			JsonItem jsonRsaKey;
			jsonRsaKey.parse(rsltRsaKey);
			string rsa_key = jsonRsaKey.getValue("rsa_key");
			this->remote_socket->set_rsa_pub_key(rsa_key);
			this->remote_socket->generate_aes_keys();
			JsonExport json_keys;
			if(isCloud()) {
				json_keys.add("token", cloud_token);
				extern int opt_cdr_check_exists_callid;
				json_keys.add("cdr_check_exists_callid", opt_cdr_check_exists_callid);
			} else {
				json_keys.add("password", snifferServerClientOptions.password);
			}
			string aes_ckey, aes_ivec;
			this->remote_socket->get_aes_keys(&aes_ckey, &aes_ivec);
			json_keys.add("aes_ckey", aes_ckey);
			json_keys.add("aes_ivec", aes_ivec);
			if(!this->remote_socket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
				setLastError(0, "failed send token & aes keys", true);
				continue;
			}
			string connectResponse;
			if(!this->remote_socket->readBlock(&connectResponse) || connectResponse != "OK") {
				if(!this->remote_socket->isError() && connectResponse != "OK") {
					setLastError(0, string("failed response from ") + (isCloud() ? "cloud router" : "server") + 
							" - " + connectResponse, true);
					delete this->remote_socket;
					this->remote_socket = NULL;
					continue;
				} else {
					setLastError(0, "failed read ok", true);
					continue;
				}
			}
		}
		if(this->useCsvInRemoteResult) {
			preparedQuery = "CSV:" + preparedQuery;
		}
		eQueryByRemoteSocketRslt rsltProcessResponse = _queryByRemoteSocket(preparedQuery);
		send_query_counter++;
		bool stop = false;
		switch(rsltProcessResponse) {
		case _qbrs_ok:
			ok = true;
			stop = true;
			++pass;
			break;
		case _qbrs_mysql_error:
			if(ignoreLastError() ||
			   (callFromStoreProcessWithFixDeadlock && getLastError() == ER_LOCK_DEADLOCK)) {
				stop = true;
			} else if(this->getLastError() == ER_SP_ALREADY_EXISTS && pass >= 2) {
				if(_queryByRemoteSocket("select table_name from information_schema.tables where table_schema = 'mysql' and table_name = 'proc'") == 1) {
					if(_queryByRemoteSocket("repair table mysql.proc") == 1) {
						syslog(LOG_NOTICE, "success call 'repair table mysql.proc'");
					} else {
						syslog(LOG_NOTICE, "failed call 'repair table mysql.proc' with error: %s", this->getLastErrorString().c_str());
					}
				}
				if(dropProcQuery) {
					if(_queryByRemoteSocket(dropProcQuery) == 1) {
						syslog(LOG_NOTICE, "success call '%s'", dropProcQuery);
					} else {
						syslog(LOG_NOTICE, "failed call '%s' with error: %s", dropProcQuery, this->getLastErrorString().c_str());
					}
				}
			}
			++pass;
			break;
		case _qbrs_mysql_error_disable_next_attempt:
			stop = true;
			++pass;
			break;
		case _qbrs_failed_connect:
			break;
		case _qbrs_na:
			++pass;
			break;
		}
		if(stop) {
			break;
		}
	}
	this->useCsvInRemoteResult = false;
	return(ok);
}

SqlDb::eQueryByRemoteSocketRslt SqlDb::_queryByRemoteSocket(string query) {
	bool okSendQuery = true;
	if(query.length() > 100) {
		cGzip gzipCompressQuery;
		u_char *queryGzip;
		size_t queryGzipLength;
		if(gzipCompressQuery.compressString(query, &queryGzip, &queryGzipLength)) {
			if(!this->remote_socket->writeBlock(queryGzip, queryGzipLength, cSocket::_te_aes)) {
				okSendQuery = false;
			}
			delete [] queryGzip;
		}
	} else {
		if(!this->remote_socket->writeBlock(query, cSocket::_te_aes)) {
			okSendQuery = false;
		}
	}
	if(!okSendQuery) {
		setLastError(0, "failed send query", true);
		return(_qbrs_failed_connect);
	}
	u_char *queryResponse;
	size_t queryResponseLength;
	queryResponse = this->remote_socket->readBlock(&queryResponseLength, cSocket::_te_aes);
	if(!queryResponse) {
		setLastError(0, "failed read query response", true);
		return(_qbrs_failed_connect);
	}
	string queryResponseStr;
	cGzip gzipDecompressResponse;
	if(gzipDecompressResponse.isCompress(queryResponse, queryResponseLength)) {
		queryResponseStr = gzipDecompressResponse.decompressString(queryResponse, queryResponseLength);
		if(queryResponseStr.empty()) {
			setLastError(0, "response is invalid (gunzip failed)", true);
			return(_qbrs_failed_connect);
		}
	} else {
		queryResponseStr = string((char*)queryResponse, queryResponseLength);
	}
	if(queryResponseStr.empty()) {
		setLastError(0, "response is empty", true);
		return(_qbrs_failed_connect);
	}
	if(isJsonObject(queryResponseStr)) {
		return(processResponseFromQueryBy(queryResponseStr.c_str(), query.c_str()));
	} else if(queryResponseStr.substr(0, 3) == "CSV") {
		return(processResponseFromCsv(queryResponseStr.c_str()));
	}
	return(_qbrs_na);
}

SqlDb::eQueryByRemoteSocketRslt SqlDb::processResponseFromQueryBy(const char *response, const char *query) {
	response_data_columns.clear();
	response_data_columns_types.clear();
	response_data.clear();
	response_data_rows = 0;
	response_data_index = 0;
	bool ok = false;
	JsonItem jsonData;
	jsonData.parse(response);
	string result = jsonData.getValue("result");
	trim(result);
	if(!strcasecmp(result.c_str(), "OK")) {
		ok = true;
	} else {
		unsigned int errorCode = atol(result.c_str());
		if(this->ignoreErrorCodes.size() &&
		   std::find(this->ignoreErrorCodes.begin(), this->ignoreErrorCodes.end(), errorCode) != this->ignoreErrorCodes.end()) {
			ok = true;
		} else { 
			bool tryNext = true;
			size_t posSeparator = result.find('|');
			string errorString;
			if(posSeparator != string::npos) {
				size_t posSeparator2 = result.find('|', posSeparator + 1);
				if(posSeparator2 != string::npos) {
					tryNext = atoi(result.substr(posSeparator + 1).c_str());
					errorString = result.substr(posSeparator2 + 1);
				} else {
					errorString = result.substr(posSeparator + 1);
				}
			} else {
				errorString = result;
			}
			if((!sql_noerror && !this->disableLogError) || opt_sql_log_all_errors) {
				if(query) {
					errorString = "sql response: [" + errorString + "] from query: [" + query + "]";
				}
				setLastError(errorCode, errorString.c_str(), true);
			}
			if(tryNext) {
				if(sql_disable_next_attempt_if_error || 
				   this->disableNextAttemptIfError ||
				   errorCode == ER_PARSE_ERROR) {
					return(_qbrs_mysql_error_disable_next_attempt);
				} else {
					return(_qbrs_mysql_error);
				}
			} else {
				return(_qbrs_mysql_error_disable_next_attempt);
			}
		}
	}
	if(ok) {
		JsonItem *dataJsonDataRows = jsonData.getItem("data_rows");
		if(dataJsonDataRows) {
			response_data_rows = atol(dataJsonDataRows->getLocalValue().c_str());
		}
		JsonItem *dataJsonItems = jsonData.getItem("data");
		if(dataJsonItems) {
			for(size_t i = 0; i < dataJsonItems->getLocalCount(); i++) {
				JsonItem *dataJsonItem = dataJsonItems->getLocalItem(i);
				for(size_t j = 0; j < dataJsonItem->getLocalCount(); j++) {
					string dataItem = dataJsonItem->getLocalItem(j)->getLocalValue();
					bool dataItemIsNull = dataJsonItem->getLocalItem(j)->localValueIsNull();
					if(i == 0) {
						size_t typeSeparator = dataItem.find(':');
						response_data_columns.push_back(typeSeparator != string::npos ? dataItem.substr(0, typeSeparator) : dataItem);
						response_data_columns_types.push_back(typeSeparator != string::npos ? atoi(dataItem.c_str() + typeSeparator + 1) : 0);
					} else {
						if(response_data.size() < i) {
							vector<string_null> row;
							response_data.push_back(row);
						}
						if(dataItemIsNull) {
							response_data[i-1].push_back(string_null(NULL, 0, true));
						} else {
							string_null strn;
							strn.in(dataItem.c_str());
							response_data[i-1].push_back(strn);
						}
					}
				}
			}
		}
		return(_qbrs_ok);
	}
	return(_qbrs_na);
}

SqlDb::eQueryByRemoteSocketRslt SqlDb::processResponseFromCsv(const char *response) {
	response_data_columns.clear();
	response_data_columns_types.clear();
	response_data.clear();
	response_data_rows = 0;
	response_data_index = 0;
	unsigned row_counter = 0;
	size_t pos = 4;
	while(true) {
		size_t posEndLine = 0;
		const char *pointEndLine = strchr(response + pos, '\n');
		if(pointEndLine) {
			posEndLine = pointEndLine - response;
			((char*)response)[posEndLine] = 0;
		}
		++row_counter;
		const char *line = response + pos;
		if(*line) {
			//cout << line << endl;
			unsigned column_counter = 0;
			size_t posLine = 0;
			while(true) {
				size_t posCommaInLine = 0;
				const char *pointCommaInLine = strchr(line + posLine, ',');
				if(pointCommaInLine) {
					posCommaInLine = pointCommaInLine - line;
					((char*)line)[posCommaInLine] = 0;
				}
				++column_counter;
				const char *column = line + posLine;
				//cout << column << endl;
				if(row_counter == 1) {
					const char *typeSeparator = strchr(column, ':');
					response_data_columns.push_back(typeSeparator ? string(column, typeSeparator - column).c_str() : column);
					response_data_columns_types.push_back(typeSeparator ? atoi(typeSeparator + 1) : 0);
				} else {
					if(column_counter == 1) {
						vector<string_null> row;
						response_data.push_back(row);
					}
					string_null strn;
					strn.in(column);
					response_data[row_counter - 2].push_back(strn);
				}
				if(posCommaInLine) {
					((char*)line)[posCommaInLine] = ',';
					posLine = posCommaInLine + 1;
				} else {
					break;
				}
			}
		}
		if(posEndLine) {
			((char*)response)[posEndLine] = '\n';
			pos = posEndLine + 1;
		} else {
			break;
		}
	}
	response_data_rows = row_counter > 1 ? row_counter - 1 : 0;
	return(_qbrs_ok);
}

string SqlDb::prepareQuery(string query, bool nextPass) {
	::prepareQuery(this->getSubtypeDb(), query, true, nextPass ? 2 : 1);
	return(query);
}

string SqlDb::fetchValue(int indexField) {
	SqlDb_row row = fetchRow();
	if(row) {
		return(row[indexField]);
	}
	return("");
}

string SqlDb::fetchValue(const char *nameField) {
	SqlDb_row row = fetchRow();
	if(row) {
		return(row[nameField]);
	}
	return("");
}

bool SqlDb::fetchValues(vector<string> *values, list<int> *indexFields) {
	values->clear();
	SqlDb_row row = fetchRow();
	if(row) {
		for(list<int>::iterator iter = indexFields->begin(); iter != indexFields->end(); iter++) {
			values->push_back(row[*iter]);
		}
		return(true);
	}
	return(false);
}

bool SqlDb::fetchValues(vector<string> *values, list<string> *nameFields) {
	values->clear();
	SqlDb_row row = fetchRow();
	if(row) {
		for(list<string>::iterator iter = nameFields->begin(); iter != nameFields->end(); iter++) {
			values->push_back(row[*iter]);
		}
		return(true);
	}
	return(false);
}

unsigned SqlDb::fetchRows(SqlDb_rows *rows) {
	rows->clear();
	SqlDb_row row;
	while((row = fetchRow())) {
		row.clearSqlDb();
		rows->rows.push_back(row);
	}
	return(*rows);
}

string SqlDb::getFieldsStr(list<SqlDb_field> *fields) {
	string fieldsStr;
	for(list<SqlDb_field>::iterator iter = fields->begin(); iter != fields->end(); iter++) {
		if(!fieldsStr.empty()) {
			fieldsStr += ", ";
		}
		fieldsStr += iter->needEscapeField ?
			      getFieldBorder() + iter->field + getFieldBorder() :
			      iter->field;
		if(!iter->alias.empty()) {
			fieldsStr += " as ";
			fieldsStr += getFieldBorder() + iter->alias + getFieldBorder();
		}
	}
	return(fieldsStr);
}

string SqlDb::getCondStr(list<SqlDb_condField> *cond, bool forceLatin1) {
	string condStr;
	for(list<SqlDb_condField>::iterator iter = cond->begin(); iter != cond->end(); iter++) {
		if(!condStr.empty()) {
			condStr += " and ";
		}
		condStr += iter->needEscapeField ?
			    getFieldBorder() + iter->field + getFieldBorder() :
			    iter->field;
		condStr += iter->oper.empty() ? " = " : " " + iter->oper + " ";
		condStr += iter->needEscapeValue ?
			    (forceLatin1 ? "convert(" : "") +
			    getContentBorder() + escape(iter->value.c_str()) + getContentBorder()  +
			    (forceLatin1 ? "using latin1)" : "") :
			    iter->value;
	}
	return(condStr);
}

string SqlDb::selectQuery(string table, list<SqlDb_field> *fields, list<SqlDb_condField> *cond, unsigned limit, bool forceLatin1) {
	string query = 
		"select " +
		(fields && fields->size() ? getFieldsStr(fields) : "*") + 
		" from " + escapeTableName(table);
	if(cond && cond->size()) {
		query += " where " + getCondStr(cond, forceLatin1);
	}
	if(limit) {
		query += " limit " + intToString(limit);
	}
	return(query);
}

string SqlDb::selectQuery(string table, const char *field, const char *condField, const char *condValue, unsigned limit, bool forceLatin1) {
	list<SqlDb_field> fields;
	if(field) {
		fields.push_back(field);
	}
	list<SqlDb_condField> cond;
	if(condField) {
		if(condValue) {
			cond.push_back(SqlDb_condField(condField, condValue));
		} else {
			cond.push_back(SqlDb_condField(condField, "NULL", true, false));
		}
	}
	return(selectQuery(table, &fields, &cond, limit));
}

string SqlDb::insertQuery(string table, SqlDb_row row, bool enableSqlStringInContent, bool escapeAll, bool insertIgnore, SqlDb_row *row_on_duplicate) {
	string query = 
		string("INSERT ") + (insertIgnore ? "IGNORE " : "") + "INTO " + escapeTableName(table) + " ( " + row.implodeFields(this->getFieldSeparator(), this->getFieldBorder()) + 
		" ) VALUES ( " + row.implodeContent(this->getContentSeparator(), this->getContentBorder(), enableSqlStringInContent || this->enableSqlStringInContent, escapeAll) + " )";
	if(row_on_duplicate) {
		query += 
			" ON DUPLICATE KEY UPDATE " +
			row_on_duplicate->implodeFieldContent(this->getFieldSeparator(), this->getFieldBorder(), this->getContentBorder(), enableSqlStringInContent || this->enableSqlStringInContent, escapeAll);
	}
	return(query);
}

string SqlDb::insertOrUpdateQuery(string table, SqlDb_row row, SqlDb_row row_on_duplicate, bool enableSqlStringInContent, bool escapeAll, bool insertIgnore) {
	return(insertQuery(table, row, enableSqlStringInContent, escapeAll, insertIgnore, &row_on_duplicate));
}

string SqlDb::insertQuery(string table, vector<SqlDb_row> *rows, bool enableSqlStringInContent, bool escapeAll, bool insertIgnore) {
	if(!rows->size()) {
		return("");
	}
	string values = "";
	for(size_t i = 0; i < rows->size(); i++) {
		values += "( " + (*rows)[i].implodeContent(this->getContentSeparator(), this->getContentBorder(), enableSqlStringInContent || this->enableSqlStringInContent, escapeAll) + " )";
		if(i < rows->size() - 1) {
			values += ",";
		}
	}
	string query = 
		string("INSERT ") + (insertIgnore ? "IGNORE " : "") + "INTO " + escapeTableName(table) + " ( " + (*rows)[0].implodeFields(this->getFieldSeparator(), this->getFieldBorder()) + 
		" ) VALUES " + values;
	return(query);
}

string SqlDb::insertQueryWithLimitMultiInsert(string table, vector<SqlDb_row> *rows, unsigned limitMultiInsert, const char *queriesSeparator, const char *queriesSeparatorSubst,
					      bool enableSqlStringInContent, bool escapeAll, bool insertIgnore) {
	if(!rows->size()) {
		return("");
	}
	string query = "";
	string values = "";
	for(size_t i = 0; i < rows->size(); i++) {
		values += "( " + (*rows)[i].implodeContent(this->getContentSeparator(), this->getContentBorder(), enableSqlStringInContent || this->enableSqlStringInContent, escapeAll) + " )";
		if(queriesSeparator && queriesSeparatorSubst && queriesSeparator != queriesSeparatorSubst) {
			values = find_and_replace(values, queriesSeparator, queriesSeparatorSubst);
		}
		if((limitMultiInsert && !((i + 1) % limitMultiInsert)) || i == (rows->size() - 1)) {
			if(!query.empty()) {
				query += queriesSeparator ? queriesSeparator : "; ";
			}
			query +=
				string("INSERT ") + (insertIgnore ? "IGNORE " : "") + "INTO " + escapeTableName(table) + " ( " + (*rows)[0].implodeFields(this->getFieldSeparator(), this->getFieldBorder()) + 
				" ) VALUES " + values;
			values = "";
		} else {
			values += ",";
		}
	}
	return(query);
}

string SqlDb::updateQuery(string table, SqlDb_row row, const char *whereCond, bool enableSqlStringInContent, bool escapeAll) {
	string query = 
		string("UPDATE ") + escapeTableName(table) + " set " + row.implodeFieldContent(this->getFieldSeparator(), this->getFieldBorder(), this->getContentBorder(), enableSqlStringInContent || this->enableSqlStringInContent, escapeAll);
	if(whereCond) {
		query += string(" WHERE ") + whereCond;
	}
	return(query);
}

string SqlDb::updateQuery(string table, SqlDb_row row, SqlDb_row whereCond, bool enableSqlStringInContent, bool escapeAll) {
	string cond = 
		whereCond.implodeFieldContent(" and ", this->getFieldBorder(), this->getContentBorder(), enableSqlStringInContent || this->enableSqlStringInContent, escapeAll);
	return(updateQuery(table, row, cond.c_str(), enableSqlStringInContent, escapeAll));
}

bool SqlDb::select(string table, list<SqlDb_field> *fields, list<SqlDb_condField> *cond, unsigned limit, bool forceLatin1) {
	string query = this->selectQuery(table, fields, cond, limit, forceLatin1);
	return(this->query(query));
}

bool SqlDb::select(string table, const char *field, const char *condField, const char *condValue, unsigned limit, bool forceLatin1) {
	string query = this->selectQuery(table, field, condField, condValue, limit, forceLatin1);
	return(this->query(query));
}

int64_t SqlDb::insert(string table, SqlDb_row row) {
	string query = this->insertQuery(table, row);
	if(this->query(query)) {
		return(this->getInsertId());
	}
	return(-1);
}

int64_t SqlDb::insert(string table, vector<SqlDb_row> *rows) {
	if(!rows->size()) {
		return(-1);
	}
	string query = this->insertQuery(table, rows);
	if(this->query(query)) {
		return(this->getInsertId());
	}
	return(-1);
}

bool SqlDb::update(string table, SqlDb_row row, const char *whereCond) {
	string query = this->updateQuery(table, row, whereCond);
	return(this->query(query));
}

bool SqlDb::update(string table, SqlDb_row row, SqlDb_row whereCond) {
	string query = this->updateQuery(table, row, whereCond);
	return(this->query(query));
}

int SqlDb::getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row, const char *uniqueField2) {
	string query = 
		"SELECT * FROM " + escapeTableName(table) + " WHERE " + uniqueField + " = " + 
		this->getContentBorder() + row[uniqueField] + this->getContentBorder();
	if(uniqueField2) {
		query = query + " AND " + uniqueField2 + " = " +
		this->getContentBorder() + row[uniqueField2] + this->getContentBorder();
	}
	if(this->query(query)) {
		SqlDb_row rsltRow = this->fetchRow();
		if(rsltRow) {
			return(atoi(rsltRow[idField].c_str()));
		}
	}
	return(this->insert(table, row));
}

string SqlDb::getQueryRsltStringValue(string query, int indexRslt) {
	if(this->query(query)) {
		SqlDb_row row;
		if((row = this->fetchRow())) {
			return(row[indexRslt]);
		}
	}
	return("");
}

int64_t SqlDb::getQueryRsltIntValue(string query, int indexRslt, int64_t failedResult) {
	if(this->query(query)) {
		SqlDb_row row;
		if((row = this->fetchRow())) {
			return(atoll(row[indexRslt].c_str()));
		}
	}
	return(failedResult);
}

bool SqlDb::existsMultipleColumns(const char *table, ...) {
	std::va_list args;
	va_start(args, table);
	const char *column;
	bool exists = true;
	while((column = va_arg(args, const char *))) {
		if(!existsColumn(table, column)) {
			exists = false;
			break;
		}
	}
	va_end(args);
	return(exists);
}

void SqlDb::startExistsColumnCache() {
	__SYNC_LOCK(existsColumn_cache_sync);
	this->existsColumn_cache.clear();
	this->existsColumn_cache_enable = true;
	this->existsColumn_cache_suspend = false;
	__SYNC_UNLOCK(existsColumn_cache_sync);
}

void SqlDb::stopExistsColumnCache() {
	__SYNC_LOCK(existsColumn_cache_sync);
	this->existsColumn_cache.clear();
	this->existsColumn_cache_enable = false;
	this->existsColumn_cache_suspend = false;
	__SYNC_UNLOCK(existsColumn_cache_sync);
}

void SqlDb::suspendExistsColumnCache() {
	__SYNC_LOCK(existsColumn_cache_sync);
	if(this->existsColumn_cache_enable) {
		this->existsColumn_cache_suspend = true;
	}
	__SYNC_UNLOCK(existsColumn_cache_sync);
}

void SqlDb::resumeExistsColumnCache() {
	__SYNC_LOCK(existsColumn_cache_sync);
	this->existsColumn_cache_suspend = false;
	__SYNC_UNLOCK(existsColumn_cache_sync);
}

bool SqlDb::isEnableExistColumnCache() {
	__SYNC_LOCK(existsColumn_cache_sync);
	bool rslt = this->existsColumn_cache_enable &&
		    !this->existsColumn_cache_suspend;
	__SYNC_UNLOCK(existsColumn_cache_sync);
	return(rslt);
}

int SqlDb::existsColumnInCache(const char *table, const char *column, string *type) {
	__SYNC_LOCK(existsColumn_cache_sync);
	map<string, map<string, string> >::iterator iter = this->existsColumn_cache.find(table);
	if(iter != this->existsColumn_cache.end()) {
		int rslt = 0;
		map<string, string>::iterator iter2 = iter->second.find(column);
		if(iter2 != iter->second.end()) {
			rslt = 1;
			if(type) {
				*type = iter2->second;
			}
		}
		__SYNC_UNLOCK(existsColumn_cache_sync);
		return(rslt);
	}
	__SYNC_UNLOCK(existsColumn_cache_sync);
	return(-1);
}

void SqlDb::addColumnToCache(const char *table, const char *column, const char *type) {
	__SYNC_LOCK(existsColumn_cache_sync);
	this->existsColumn_cache[table][column] = type;
	__SYNC_UNLOCK(existsColumn_cache_sync);
}

void SqlDb::removeTableFromColumnCache(const char *table) {
	__SYNC_LOCK(existsColumn_cache_sync);
	map<string, map<string, string> >::iterator iter = this->existsColumn_cache.find(table);
	if(iter != this->existsColumn_cache.end()) {
		this->existsColumn_cache.erase(iter);
	}
	__SYNC_UNLOCK(existsColumn_cache_sync);
}

bool SqlDb::isIPv6Column(string table, string column, bool useCache) {
	if(!VM_IPV6_B) {
		return(false);
	}
	string columnType = getTypeColumn(table, column, true, useCache);
	return(columnType.find("varbinary") != string::npos);
}

bool SqlDb::_isIPv6Column(string table, string column) {
	if(!VM_IPV6_B) {
		return(false);
	}
	bool isIPv6 = false;
	__SYNC_LOCK(typeColumn_cache_sync);
	if(typeColumn_cache.find(table) == typeColumn_cache.end()) {
		SqlDb *sqlDb = createSqlObject();
		sqlDb->query(string("show columns from ") + sqlDb->escapeTableName(table));
		SqlDb_row cdr_struct_row;
		while((cdr_struct_row = sqlDb->fetchRow())) {
			typeColumn_cache[table][cdr_struct_row["field"]] = cdr_struct_row["type"];
		}
		delete sqlDb;
	}
	if(typeColumn_cache.find(table) != typeColumn_cache.end() &&
	   typeColumn_cache[table].find(column) != typeColumn_cache[table].end()) {
		string type = typeColumn_cache[table][column];
		std::transform(type.begin(), type.end(), type.begin(), ::tolower);
		isIPv6 = type.find("varbinary") != string::npos;
	}
	__SYNC_UNLOCK(typeColumn_cache_sync);
	return(isIPv6);
}

int SqlDb::getPartitions(const char *table, vector<sPartition> *partitions, bool useCache) {
	list<sPartition> partitions_l;
	int rslt = getPartitions(table, &partitions_l, useCache);
	partitions->clear();
	for(list<sPartition>::iterator iter = partitions_l.begin(); iter != partitions_l.end(); iter++) {
		partitions->push_back(*iter);
	}
	return(rslt);
}

bool SqlDb::existsDayPartition(string table, unsigned addDaysToNow, bool useCache) {
	time_t now = time(NULL);
	tm tm = time_r(&now);
	while(addDaysToNow > 0) {
		tm = getNextBeginDate(tm);
		--addDaysToNow;
	}
	char partitionName[40];
	snprintf(partitionName, sizeof(partitionName), "p%02i%02i%02i", tm.tm_year - 100, tm.tm_mon + 1, tm.tm_mday);
	bool rslt = existsPartition(table, partitionName, useCache);
	/*
	if(rslt) {
		cout << "exists partition " << table << '.' << partitionName << endl;
	}
	*/
	return(rslt);
}

bool SqlDb::existsHourPartition(string table, unsigned addHoursToNow, bool checkDayPartition, bool useCache) {
	time_t now = time(NULL);
	tm tm = time_r(&now);
	while(addHoursToNow > 0) {
		tm = getNextBeginHour(tm);
		--addHoursToNow;
	}
	char partitionName[40];
	snprintf(partitionName, sizeof(partitionName), "p%02i%02i%02i%02i", tm.tm_year - 100, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	bool rslt = existsPartition(table, partitionName, useCache);
	/*
	if(rslt) {
		cout << "exists partition " << table << '.' << partitionName << endl;
	}
	*/
	if(!rslt && checkDayPartition) {
		snprintf(partitionName, sizeof(partitionName), "p%02i%02i%02i", tm.tm_year - 100, tm.tm_mon + 1, tm.tm_mday);
		rslt = existsPartition(table, partitionName, useCache);
		/*
		if(rslt) {
			cout << "exists partition " << table << '.' << partitionName << endl;
		}
		*/
	}
	return(rslt);
}

int SqlDb::getIndexField(string fieldName) {
	if(isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		for(size_t i = 0; i < this->response_data_columns.size(); i++) {
			if(!strcasecmp(this->response_data_columns[i].c_str(), fieldName.c_str())) {
				return(i);
			}
		}
	} else {
		for(size_t i = 0; i < this->fields.size(); i++) {
			if(!strcasecmp(this->fields[i].c_str(), fieldName.c_str())) {
				return(i);
			}
		}
	}
	return(-1);
}

string SqlDb::getNameField(int indexField) {
	if(isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		if((unsigned)indexField < this->response_data_columns.size()) {
			return(this->response_data_columns[indexField]);
		}
	} else {
		if((unsigned)indexField < this->fields.size()) {
			return(this->fields[indexField]);
		}
	}
	return("");
}

void SqlDb::setLastErrorString(string lastErrorString, bool sysLog) {
	this->lastErrorString = lastErrorString;
	if(sysLog && lastErrorString != "") {
		syslog(LOG_ERR, "%s", lastErrorString.c_str());
	}
}

bool SqlDb::ignoreLastError() {
	return(getLastError() == ER_PARSE_ERROR ||
	       getLastError() == ER_NO_REFERENCED_ROW_2 ||
	       getLastError() == ER_SAME_NAME_PARTITION ||
	       getLastError() == ER_SP_DOES_NOT_EXIST);
}

bool SqlDb::isSkipError() {
	if(!opt_sql_errors_skip[0]) {
		return(false);
	}
	int error = getLastError();
	if(!error) {
		return(false);
	}
	vector<string> skip_errors = split(opt_sql_errors_skip, split(",|;", '|'), true);
	for(unsigned i = 0; i < skip_errors.size(); i++) {
		if(atoi(skip_errors[i].c_str()) == error) {
			return(true);
		}
	}
	return(false);
}

string SqlDb::getDatadirTab(const char *datadir, const char *database) {
	string datadir_tab;
	if(datadir && *datadir) {
		datadir_tab = datadir;
	} else {
		datadir_tab = getDbDatadir();
		if(datadir_tab.empty()) {
			return("");
		}
		datadir_tab += (datadir_tab[datadir_tab.length() - 1] == '/' ? "" : "/") + string(database && *database ? database : conn_database);
	}
	if(!file_exists(datadir_tab)) {
		return("");
	}
	return(datadir_tab);
}

void SqlDb::setEnableSqlStringInContent(bool enableSqlStringInContent) {
	this->enableSqlStringInContent = enableSqlStringInContent;
}

void SqlDb::setDisableNextAttemptIfError() {
	this->disableNextAttemptIfError = true;
}

void SqlDb::setEnableNextAttemptIfError() {
	this->disableNextAttemptIfError = false;
}

void SqlDb::setDisableLogError() {
	this->disableLogError = true;
}

void SqlDb::setEnableLogError() {
	this->disableLogError = false;
}

void SqlDb::setDisableLogError(bool disableLogError) {
	this->disableLogError = disableLogError;
}

bool SqlDb::getDisableLogError() {
	return(this->disableLogError);
}

void SqlDb::setSilentConnect() {
	this->silentConnect = true;
}

void SqlDb::cleanFields() {
	this->fields.clear();
	this->fields_type.clear();
}

bool SqlDb::logNeedAlter(string table, string reason, string alter,
			 bool log, map<string, u_int64_t> *tableSize, bool *existsColumnFlag) {
	vector<string> alters;
	alters.push_back(alter);
	return(logNeedAlter(table, reason, alters,
			    log, tableSize, existsColumnFlag));
}

int SqlDb::checkNeedAlterAdd(string table, string reason, bool tryAlter,
			     bool log, map<string, u_int64_t> *tableSize, bool *existsColumnFlag,
			     ...) {
	if(existsColumnFlag) {
		*existsColumnFlag = false;
	}
	std::va_list args;
	va_start(args, existsColumnFlag);
	const char *column;
	const char *type;
	const char *key;
	vector<string> columns;
	vector<string> types;
	vector<string> keys;
	while((column = va_arg(args, const char *))) {
		type = va_arg(args, const char *);
		if(!type) {
			break;
		}
		key = va_arg(args, const char *);
		columns.push_back(column);
		types.push_back(type);
		keys.push_back(key ? key : "");
	}
	va_end(args);
	bool okAlter = false;
	for(int pass = 0; pass < 2; pass++) {
		bool exists = true;
		for(vector<string>::iterator iter = columns.begin(); iter != columns.end(); iter++) {
			if(!existsColumn(table, *iter)) {
				exists = false;
				break;
			}
		}
		if(exists) {
			if(existsColumnFlag) {
				*existsColumnFlag = true;
			}
			return(okAlter ? true: -1);
		} else if(!tryAlter) {
			return(-1);
		}
		if(pass == 0 && !exists) {
			vector<string> alter_add_columns;
			for(unsigned i = 0; i < columns.size(); i++) {
				if(!existsColumn(table, columns[i])) {
					alter_add_columns.push_back(string("ADD COLUMN ") + getFieldBorder() + columns[i] + getFieldBorder() + " " + types[i] + 
								    (!keys[i].empty() ? ", ADD KEY " + keys[i] : ""));
				}
			}
			if(alter_add_columns.size()) {
				vector<string> alters;
				alters.push_back("ALTER TABLE " + table + " " + implode(alter_add_columns, ", ") + ";");
				if(logNeedAlter(table, reason, alters,
						log, tableSize, existsColumnFlag)) {
					okAlter = true;
				} else {
					break;
				}
			}
		}
	}
	return(false);
}

bool SqlDb::logNeedAlter(string table, string reason, vector<string> alters,
			 bool log, map<string, u_int64_t> *tableSize, bool *existsColumnFlag) {
	bool okAlter = false;
	if(tableSize) {
		map<string, u_int64_t>::iterator iter = tableSize->find(table);
		if(iter == tableSize->end()) {
			(*tableSize)[table] = -1;
			if(this->query("show table status like '" + table + "'")) {
				SqlDb_row row = this->fetchRow();
				if(row) {
					(*tableSize)[table] = atoll(row["Rows"].c_str());
				}
			}
		}
		extern int opt_alter_rows_limit;
		if((*tableSize)[table] < (unsigned)opt_alter_rows_limit && !sverb.suppress_auto_alter) {
			int sql_disable_next_attempt_if_error_old = sql_disable_next_attempt_if_error;
			sql_disable_next_attempt_if_error = 1;
			unsigned okAlterCount = 0;
			bool error = false;
			for(unsigned i = 0; i < alters.size(); i++) {
				SqlDb_row dbAlterRow;
				extern long int runAt;
				if(opt_id_sensor > 0) {
					dbAlterRow.add(opt_id_sensor, "id_sensor");
				}
				dbAlterRow.add(sqlDateTimeString(runAt), "at");
				dbAlterRow.add(sqlEscapeString(table), "table");
				dbAlterRow.add(sqlEscapeString(reason), "reason");
				dbAlterRow.add(sqlEscapeString(alters[i]), "alter");
				if(error) {
					++okAlterCount;
					dbAlterRow.add("skip_prev_error", "result");
				} else  {
					syslog(LOG_NOTICE, "run alter: %s", alters[i].c_str());
					if(this->query(alters[i])) {
						++okAlterCount;
						dbAlterRow.add("ok", "result");
					} else {
						error = true;
						dbAlterRow.add("error", "result");
						dbAlterRow.add(sqlEscapeString(getLastErrorString()), "error");
					}
				}
				insert("db_alters", dbAlterRow);
			}
			if(okAlterCount == alters.size()) {
				okAlter = true;
				if(existsColumnFlag) {
					*existsColumnFlag = true;
				}
			}
			sql_disable_next_attempt_if_error = sql_disable_next_attempt_if_error_old;
		} else {
			for(unsigned i = 0; i < alters.size(); i++) {
				SqlDb_row dbAlterRow;
				extern long int runAt;
				if(opt_id_sensor > 0) {
					dbAlterRow.add(opt_id_sensor, "id_sensor");
				}
				dbAlterRow.add(sqlDateTimeString(runAt), "at");
				dbAlterRow.add(sqlEscapeString(table), "table");
				dbAlterRow.add(sqlEscapeString(reason), "reason");
				dbAlterRow.add(sqlEscapeString(alters[i]), "alter");
				dbAlterRow.add("skip_too_rows", "result");
				insert("db_alters", dbAlterRow);
			}
		}
	}
	if(log && !okAlter) {
		string msg = 
			"!!! New feature was added. If you want to use it then you need to alter " + table +
			" database table and add new columns to support " + reason + ". "
			"This operation can take hours based on ammount of data, CPU and I/O speed of your server. "
			"The alter table will prevent the database to insert new rows and will probably block other operations. "
			"It is recommended to alter the table in non working hours. "
			"Login to the mysql voipmonitor database (mysql -uroot voipmonitor) and run on the CLI> " +
			implode(alters, " ");
		syslog(LOG_WARNING, "%s", msg.c_str());
	}
	if(okAlter) {
		this->removeTableFromColumnCache(table.c_str());
	}
	return(okAlter);
}

volatile u_int64_t SqlDb::delayQuery_sum_ms[3] = { 0, 0, 0 };
volatile u_int32_t SqlDb::delayQuery_count[3] = { 0, 0, 0 };
volatile u_int32_t SqlDb::insert_count = 0;


SqlDb_mysql::SqlDb_mysql() {
	this->hMysql = NULL;
	this->hMysqlConn = NULL;
	this->hMysqlRes = NULL;
	this->mysqlThreadId = 0;
}

string SqlDb_mysql::dbVersion_static;
volatile int SqlDb_mysql::dbVersion_static_sync = 0;

SqlDb_mysql::~SqlDb_mysql() {
	this->clean();
}

bool SqlDb_mysql::connect(bool createDb, bool mainInit) {
	if(opt_nocdr || isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		return(true);
	}
	list<cLogSensor*> logs;
	this->connecting = true;
	pthread_mutex_lock(&mysqlconnect_lock);
	this->hMysql = mysql_init(NULL);
	if(this->hMysql) {
		string conn_server_ip = cResolver::resolve_str(this->conn_server);
		if(conn_server_ip.empty()) {
			this->setLastErrorString("mysql connect failed - " + this->conn_server + " is unavailable", true);
			pthread_mutex_unlock(&mysqlconnect_lock);
			this->connecting = false;
			return(false);
		}
		extern bool opt_mysql_reconnect;
		if(opt_mysql_reconnect) {
			bool reconnect = 1;
			mysql_options(this->hMysql, MYSQL_OPT_RECONNECT, &reconnect);
		}
		string connect_via_str;
		for(int connectPass = 0; connectPass < 2; connectPass++) {
			if(connectPass) {
				if(this->hMysqlRes) {
					while(mysql_fetch_row(this->hMysqlRes));
					mysql_free_result(this->hMysqlRes);
					this->hMysqlRes = NULL;
				}
				mysql_close(this->hMysqlConn);
			}
			this->hMysql = mysql_init(NULL);
			bool enabledSSL = false;
#ifdef MYSQL_WITHOUT_SSL_SUPPORT
			if ((this->conn_sslkey && strlen(this->conn_sslkey)) || 
			    (this->conn_sslcert && strlen(this->conn_sslcert)) || 
			    (this->conn_sslcacert && strlen(this->conn_sslcacert)) ||
			    (this->conn_sslcapath && strlen(this->conn_sslcapath)) || 
			    this->conn_sslciphers.length()) {
				syslog(LOG_WARNING, "Mysql SSL options was not recognized in the mysql library so SSL/TLS connection to the Mysql server will not work.");
			}
#else
			if (this->conn_sslkey && strlen(this->conn_sslkey) && 
			    this->conn_sslcert && strlen(this->conn_sslcert)) {
				mysql_options(this->hMysql, MYSQL_OPT_SSL_KEY, this->conn_sslkey);
				mysql_options(this->hMysql, MYSQL_OPT_SSL_CERT, this->conn_sslcert);
				enabledSSL = true;
			}
			if (this->conn_sslcacert && strlen(this->conn_sslcacert)) {
				mysql_options(this->hMysql, MYSQL_OPT_SSL_CA, this->conn_sslcacert);
				enabledSSL = true;
			}
			if (this->conn_sslcapath && strlen(this->conn_sslcapath)) {
				mysql_options(this->hMysql, MYSQL_OPT_SSL_CAPATH, this->conn_sslcapath);
				enabledSSL = true;
			}
			if (this->conn_sslciphers.length()) {
				mysql_options(this->hMysql, MYSQL_OPT_SSL_CIPHER, this->conn_sslciphers.c_str());
			}
			if (enabledSSL) {
				#if LIBMYSQL_VERSION_ID < 80000
				my_bool forceSSL = true;
				mysql_options(this->hMysql, MYSQL_OPT_SSL_ENFORCE, &forceSSL);
				#else
				unsigned int forceSSL = SSL_MODE_REQUIRED;
				mysql_options(this->hMysql, MYSQL_OPT_SSL_MODE, &forceSSL);
				#endif
				syslog(LOG_INFO, "Enabling SSL/TLS for mysql connection.");
			}
#endif
			#if LIBMYSQL_VERSION_ID < 80000
			if(!enabledSSL && this->conn_disable_secure_auth) {
				int arg = 0;
				mysql_options(this->hMysql, MYSQL_SECURE_AUTH, &arg);
			}
			#endif
			extern unsigned int opt_mysql_connect_timeout;
			if(opt_mysql_connect_timeout) {
				mysql_options(this->hMysql, MYSQL_OPT_CONNECT_TIMEOUT, &opt_mysql_connect_timeout);
			}
			bool isLocalhost = conn_server_ip == "localhost" || conn_server_ip == "127.0.0.1";
			for(int connectLocalhostPass = (isLocalhost ? (!this->conn_socket.empty() ? 0 : 1) : 2); connectLocalhostPass <= 2; ++connectLocalhostPass) {
				const char *_host = 
					connectLocalhostPass == 0 ? (const char*)NULL : 
					connectLocalhostPass == 1 ? "localhost" : 
								    (isLocalhost ? 
								      "127.0.0.1" : 
								      conn_server_ip.c_str());
				const char *_socket = 
					connectLocalhostPass == 0 ? this->conn_socket.c_str() : 
					connectLocalhostPass == 1 ? (const char*)NULL : 
								    (const char*)NULL;
				this->hMysqlConn = mysql_real_connect(
							this->hMysql,
							_host, 
							this->conn_user.c_str(),
							this->conn_password.c_str(),
							NULL,
							this->conn_port ? this->conn_port : opt_mysql_port,
							_socket, 
							CLIENT_MULTI_RESULTS | (opt_mysql_client_compress ? CLIENT_COMPRESS : 0));
				if(this->hMysqlConn) {
					connect_via_str = _socket ? 
							   "socket " + string(_socket) : 
							   _host;
					break;
				}
			}
			if(!this->hMysqlConn) {
				break;
			}
			sql_disable_next_attempt_if_error = 1;
			sql_noerror = !mainInit;
			if(getQueryRsltIntValue("show variables like 'max_allowed_packet'", 1, 0) < 1024*1024*100) {
				if(this->query("SET GLOBAL max_allowed_packet=1024*1024*100") &&
				   this->query("show variables like 'max_allowed_packet'")) {
					sql_disable_next_attempt_if_error = 0;
					sql_noerror = 0;
					SqlDb_row row;
					if((row = this->fetchRow())) {
						this->maxAllowedPacket = atoll(row[1].c_str());
						if(this->maxAllowedPacket >= 1024*1024*100) {
							break;
						} else if(connectPass) {
							if(mainInit) {
								logs.push_back(
								cLogSensor::begin(cLogSensor::error, 
										  "set max_allowed_packet failed",
										  "Max allowed packet size is only %lu. Concat query size is limited. "
										  "Please set max_allowed_packet to 100MB manually in your mysql configuration file.", 
										  this->maxAllowedPacket));
							}
						}
					} else {
						if(mainInit) {
							logs.push_back(
							cLogSensor::begin(cLogSensor::error, 
									  "set max_allowed_packet failed",
									  "Unknown max allowed packet size. Concat query size is limited. "
									  "Please set max_allowed_packet to 100MB manually in your mysql configuration file."));
						}
						break;
					}
				} else {
					sql_disable_next_attempt_if_error = 0;
					sql_noerror = 0;
					if(mainInit) {
						logs.push_back(
						cLogSensor::begin(cLogSensor::error, 
								  "set max_allowed_packet failed",
								  "Query for set / get max allowed packet size failed. Concat query size is limited. "
								  "Please set max_allowed_packet to 100MB manually in your mysql configuration file."));
					}
					break;
				}
			} else {
				sql_disable_next_attempt_if_error = 0;
				sql_noerror = 0;
				break;
			}
		}
		if(this->hMysqlConn) {
			bool rslt = true;
			this->mysqlThreadId = mysql_thread_id(this->hMysql);
			sql_disable_next_attempt_if_error = 1;
			if(!this->query("SET NAMES UTF8")) {
				rslt = false;
			}
			sql_noerror = 1;
			this->query("SET GLOBAL innodb_stats_on_metadata=0"); // this will speedup "Slow query on information_schema.tables"
			if(opt_mysql_timezone[0]) {
				this->query(string("SET time_zone = '") + opt_mysql_timezone + "'");
			}
			sql_noerror = 0;
			if(!this->query("SET sql_mode = ''") ||
			   !this->query("SET group_concat_max_len = 100000000")) {
				rslt = false;
			}
			char tmp[1024];
			if(createDb) {
				if(this->getDbMajorVersion() >= 5 and 
					!(this->getDbMajorVersion() == 5 and this->getDbMinorVersion() <= 1)) {
					this->query("SET GLOBAL innodb_file_per_table=1;");
				}
				snprintf(tmp, sizeof(tmp), "CREATE DATABASE IF NOT EXISTS `%s`", this->conn_database.c_str());
				if(!this->query(tmp)) {
					rslt = false;
				}
			}
			snprintf(tmp, sizeof(tmp), "USE `%s`", this->conn_database.c_str());
			bool disableLogErrorOld = false;
			if(silentConnect) {
				disableLogErrorOld = getDisableLogError();
				setDisableLogError(true);
			}
			if(!this->query(tmp)) {
				rslt = false;
			}
			if(silentConnect) {
				setDisableLogError(disableLogErrorOld);
			}
			if(mainInit) {
				if(!isCloud()) {
					this->query("SHOW VARIABLES LIKE \"version\"");
					SqlDb_row row;
					if((row = this->fetchRow())) {
						this->dbVersion = row[1];
					}
					while(this->fetchRow());
					if(this->conn_showversion) {
						syslog(LOG_INFO, "connect - db version %s (%i) %s / maximum partitions: %i / connect via %s", 
						       this->getDbVersionString().c_str(), 
						       this->getDbVersion(), 
						       this->getDbName().c_str(), 
						       this->getMaximumPartitions(),
						       connect_via_str.c_str());
					}
				} else if(!cloud_db_version.empty()) {
					this->dbVersion = cloud_db_version;
				}
			}
			sql_disable_next_attempt_if_error = 0;
			pthread_mutex_unlock(&mysqlconnect_lock);
			if(this->hMysqlRes) {
				mysql_free_result(this->hMysqlRes);
				this->hMysqlRes = NULL;
				this->cleanFields();
			}
			this->connecting = false;
			cLogSensor::end(logs);
			return(rslt);
		} else {
			if(!this->silentConnect) {
				this->checkLastError("MySQL connect error (" + this->conn_server + ")", true);
			}
		}
	} else {
		this->setLastErrorString("mysql_init failed - insufficient memory ?", true);
	}
	pthread_mutex_unlock(&mysqlconnect_lock);
	this->connecting = false;
	cLogSensor::end(logs);
	return(false);
}

int SqlDb_mysql::multi_on() {
	return isCloud() || snifferClientOptions.isEnableRemoteQuery() ? 
		true : 
		mysql_set_server_option(this->hMysql, MYSQL_OPTION_MULTI_STATEMENTS_ON);
}

int SqlDb_mysql::multi_off() {
	return isCloud() || snifferClientOptions.isEnableRemoteQuery() ? 
		true : 
		mysql_set_server_option(this->hMysql, MYSQL_OPTION_MULTI_STATEMENTS_OFF);
}

int SqlDb_mysql::getDbMajorVersion() {
	this->_getDbVersion();
	if(this->dbVersion.empty()) {
		if(!isCloud()) {
			this->query("SHOW VARIABLES LIKE \"version\"");
			SqlDb_row row = this->fetchRow();
			if(row) {
				this->dbVersion = row[1];
				__SYNC_LOCK(this->dbVersion_static_sync);
				this->dbVersion_static = this->dbVersion;
				__SYNC_UNLOCK(this->dbVersion_static_sync);
			}
		} else if(!cloud_db_version.empty()) {
			this->dbVersion = cloud_db_version;
			__SYNC_LOCK(this->dbVersion_static_sync);
			this->dbVersion_static = cloud_db_version;
			__SYNC_UNLOCK(this->dbVersion_static_sync);
		}
	}
	return(_getDbMajorVersion(this->dbVersion.c_str()));
}

int SqlDb_mysql::getDbMinorVersion(int minorLevel) {
	this->_getDbVersion();
	return(_getDbMinorVersion(this->dbVersion.c_str(), minorLevel));
}

string SqlDb_mysql::getDbName() {
	this->_getDbVersion();
	return(_getDbName(this->dbVersion.c_str()));
}

int SqlDb_mysql::getDbVersion_static() {
	int rslt = 0;
	__SYNC_LOCK(dbVersion_static_sync);
	if(!dbVersion_static.empty()) {
		rslt = _getDbMajorVersion(dbVersion_static.c_str()) * 10000 + 
		       _getDbMinorVersion(dbVersion_static.c_str()) * 100 + 
		       _getDbMinorVersion(dbVersion_static.c_str(), 1);
	}
	__SYNC_UNLOCK(dbVersion_static_sync);
	return(rslt);
}

int SqlDb_mysql::getDbMajorVersion_static() {
	int rslt = 0;
	__SYNC_LOCK(dbVersion_static_sync);
	if(!dbVersion_static.empty()) {
		rslt = _getDbMajorVersion(dbVersion_static.c_str());
	}
	__SYNC_UNLOCK(dbVersion_static_sync);
	return(rslt);
}

int SqlDb_mysql::getDbMinorVersion_static(int minorLevel) {
	int rslt = 0;
	__SYNC_LOCK(dbVersion_static_sync);
	if(!dbVersion_static.empty()) {
		rslt = _getDbMinorVersion(dbVersion_static.c_str(), minorLevel);
	}
	__SYNC_UNLOCK(dbVersion_static_sync);
	return(rslt);
}

string SqlDb_mysql::getDbName_static() {
	string rslt = "";
	__SYNC_LOCK(dbVersion_static_sync);
	if(!dbVersion_static.empty()) {
		rslt = _getDbName(dbVersion_static.c_str());
	}
	__SYNC_UNLOCK(dbVersion_static_sync);
	return(rslt);
}

int SqlDb_mysql::_getDbMajorVersion(const char *db_version) {
	int rslt = 0;
	if(*db_version) {
		rslt = atoi(db_version);
	}
	return(rslt);
}

int SqlDb_mysql::_getDbMinorVersion(const char *db_version, int minorLevel) {
	int rslt = 0;
	if(*db_version) {
		const char *pointToVersion = db_version;
		for(int i = 0; i < minorLevel + 1 && pointToVersion; i++) {
			const char *pointToSeparator = strchr(pointToVersion, '.');
			if(pointToSeparator) {
				pointToVersion = pointToSeparator + 1;
			}
		}
		if(pointToVersion) {
			rslt = atoi(pointToVersion);
		}
	}
	return(rslt);
}

string SqlDb_mysql::_getDbName(const char *db_version) {
	string rslt = "";
	if(*db_version) {
		rslt = strcasestr(db_version, "MariaDB") ? "mariadb" : "mysql";
	}
	return(rslt);
}

string SqlDb_mysql::getDbDatadir() {
	if(isCloud()) {
		return("");
	}
	if(this->dbDatadir.empty()) {
		this->query("SHOW VARIABLES LIKE \"datadir\"");
		SqlDb_row row = this->fetchRow();
		if(row) {
			this->dbDatadir = row[1];
		}
	}
	return(this->dbDatadir);
}

bool SqlDb_mysql::getDbDatadirStats(const char *datadir, const char *database, double *total_MB, double *free_MB, double *free_perc, double *files_sum_size_MB) {
	*total_MB = 0;
	*free_MB = 0;
	*free_perc = 0;
	*files_sum_size_MB = 0;
	string datadir_tab = getDatadirTab(datadir, database);
	if(datadir_tab.empty()) {
		return(false);
	}
	long long total = GetTotalDiskSpace(datadir_tab.c_str());
	if(total <= 0) {
		return(false);
	}
	*total_MB = (double)total / (1024 * 1024);
	long long free = GetFreeDiskSpace(datadir_tab.c_str());
	if(free < 0) {
		return(false);
	}
	*free_MB = (double)free / (1024 * 1024);
	*free_perc = (double)free / total * 100;
	u_int64_t files_sum_size = 0;
	DIR* dp = opendir(datadir_tab.c_str());
	if(dp) {
		dirent* de;
		while((de = readdir(dp)) != NULL) {
			if(string(de->d_name) == ".." or string(de->d_name) == "." || 
			   is_dir(de, datadir_tab.c_str())) {
				continue;
			}
			long long fs = GetFileSize(datadir_tab + '/' + de->d_name);
			if(fs < 0) {
				closedir(dp);
				return(false);
			}
			files_sum_size += fs;
		}
		closedir(dp);
	} else {
		return(false);
	}
	*files_sum_size_MB = (double)files_sum_size / (1024 * 1024);
	return(true);
}

int SqlDb_mysql::getMaximumPartitions() {
	return(getDbName() == "mariadb" ? 
		(getDbVersion() < 100004 ? 1024 : 8192) :
		(getDbVersion() < 50607 ? 1024 : 8192));
}

bool SqlDb_mysql::isSupportForDatetimeMs() {
	return(isCloud() ||
	       (getDbName() == "mariadb" ? 
		 (getDbVersion() > 50300) :
		 (getDbVersion() > 50500)));
}

bool SqlDb_mysql::_getDbVersion() {
	if(this->dbVersion.empty()) {
		if(!isCloud()) {
			this->query("SHOW VARIABLES LIKE \"version\"");
			SqlDb_row row = this->fetchRow();
			if(row) {
				this->dbVersion = row[1];
				__SYNC_LOCK(this->dbVersion_static_sync);
				this->dbVersion_static = this->dbVersion;
				__SYNC_UNLOCK(this->dbVersion_static_sync);
			}
		} else if(!cloud_db_version.empty()) {
			this->dbVersion = cloud_db_version;
			__SYNC_LOCK(this->dbVersion_static_sync);
			this->dbVersion_static = cloud_db_version;
			__SYNC_UNLOCK(this->dbVersion_static_sync);
		}
	}
	return(!this->dbVersion.empty());
}

bool SqlDb_mysql::createRoutine(string routine, string routineName, string routineParamsAndReturn, eRoutineType routineType, bool abortIfFailed) {
	bool missing = false;
	bool diff = false;
	if(this->isCloud()) {
		syslog(LOG_NOTICE, "check %s %s", (routineType == procedure ? "procedure" : "function"), routineName.c_str());
		bool rslt = this->query(string("create_routine||") + (routineType == procedure ? "procedure" : "function") + "||" + routineName + "||" + routineParamsAndReturn + "||" + routine);
		if(!rslt && abortIfFailed) {
			string errorString = string("create routine ") + routineName + " on cloud side failed";
			syslog(LOG_ERR, "%s", errorString.c_str());
			vm_terminate_error(errorString.c_str());
		}
		return(rslt);
	} else {
		this->query(string("select routine_definition from information_schema.routines where routine_schema='") + this->conn_database + 
			    "' and routine_name='" + routineName + 
			    "' and routine_type='" + (routineType == procedure ? "PROCEDURE" : "FUNCTION") + "'");
		SqlDb_row row = this->fetchRow();
		if(!row) {
			missing = true;
		} else if(row["routine_definition"] != routine) {
			size_t i = 0, j = 0;
			while(i < routine.length() &&
			      j < row["routine_definition"].length()) {
				if(routine[i] == '\\' && i < routine.length() - 1) {
					++i;
				}
				if(routine[i] != row["routine_definition"][j]) {
					diff = true;
					break;
				}
				++i;
				++j;
			}
			if(!diff && 
			   (i < routine.length() || j < row["routine_definition"].length())) {
				diff = true;
			}
		}
	}
	if(missing || diff) {
		syslog(LOG_NOTICE, "%s %s %s", diff ? "update" : "create",(routineType == procedure ? "procedure" : "function"), routineName.c_str());
		this->query(string("drop ") + (routineType == procedure ? "PROCEDURE" : "FUNCTION") +
			    " if exists " + routineName);
		extern bool opt_mysql_security_invoker_routines;
		bool rslt = this->query(string("create ") + (routineType == procedure ? "PROCEDURE" : "FUNCTION") + " " +
					routineName + routineParamsAndReturn + 
					(opt_mysql_security_invoker_routines ? " SQL SECURITY INVOKER " : " ") + 
					routine);
		if(!rslt && abortIfFailed) {
			string errorString1 = string("create routine ") + routineName + " failed";
			string errorString2 = "tip: SET GLOBAL log_bin_trust_function_creators = 1  or put it in my.cnf configuration or grant SUPER privileges to your voipmonitor mysql user.";
			cLogSensor::log(cLogSensor::error,
					errorString1.c_str(),
					errorString2.c_str());
			vm_terminate_error((errorString1 + "\n" + errorString2).c_str());
		}
		return(rslt);
	} else {
		return(true);
	}
}

void SqlDb_mysql::disconnect() {
	if(isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		return;
	}
	if(this->hMysqlRes) {
		while(mysql_fetch_row(this->hMysqlRes));
		mysql_free_result(this->hMysqlRes);
		this->hMysqlRes = NULL;
	}
	if(this->hMysqlConn) {
		mysql_close(this->hMysqlConn);
		this->hMysqlConn = NULL;
	}
	/* disable dealloc hMysql - is it shared variable ?
		this->hMysql = NULL;
	} 
	else if(this->hMysql) {
		mysql_close(this->hMysql);
		this->hMysql = NULL;
	}
	*/
}

bool SqlDb_mysql::connected() {
	return(isCloud() || snifferClientOptions.isEnableRemoteQuery() ? 
		true : 
		this->hMysqlConn != NULL);
}

bool SqlDb_mysql::query(string query, bool callFromStoreProcessWithFixDeadlock, const char *dropProcQuery) {
	if(isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		string preparedQuery = this->prepareQuery(query, false);
		if(verbosity > 1) {
			syslog(LOG_INFO, "%s", prepareQueryForPrintf(preparedQuery).c_str());
		}
		if(sverb.query_regex[0] && reg_match(prepareQueryForPrintf(preparedQuery).c_str(), sverb.query_regex)) {
			cout << prepareQueryForPrintf(preparedQuery) << endl;
		}
		return(this->queryByRemoteSocket(preparedQuery, callFromStoreProcessWithFixDeadlock, dropProcQuery));
	}
	if(opt_nocdr) {
		return(true);
	}
	u_int32_t startTimeMS = getTimeMS();
	if(this->hMysqlConn) {
		if(!this->hMysqlRes) {
			this->hMysqlRes = mysql_use_result(this->hMysqlConn);
		}
		if(this->hMysqlRes) {
			unsigned counter = 0;
			unsigned limitFetch = 10000;
			while(counter < limitFetch && mysql_fetch_row(this->hMysqlRes)) {
				++counter;
			}
			if(counter == limitFetch) {
				syslog(LOG_NOTICE, "unfetched records from query %s", this->prevQuery.c_str());
			}
			mysql_free_result(this->hMysqlRes);
		}
	}
	this->hMysqlRes = NULL;
	if(this->connected()) {
		if(mysql_ping(this->hMysql)) {
			if(verbosity > 1) {
				syslog(LOG_INFO, "mysql_ping failed -> force reconnect");
			}
			this->reconnect();
		} else if(this->mysqlThreadId && this->mysqlThreadId != mysql_thread_id(this->hMysql)) {
			if(verbosity > 1) {
				syslog(LOG_INFO, "diff thread_id -> force reconnect");
			}
			this->reconnect();
		}
	}
	bool rslt = false;
	this->cleanFields();
	unsigned int attempt = 1;
	for(unsigned int pass = 0; pass < this->maxQueryPass; pass++) {
		string preparedQuery = this->prepareQuery(query, !callFromStoreProcessWithFixDeadlock && attempt > 1);
		if(attempt == 1) {
			if(verbosity > 1) {
				syslog(LOG_INFO, "%s", prepareQueryForPrintf(preparedQuery).c_str());
			}
			if(sverb.query_regex[0] && reg_match(prepareQueryForPrintf(preparedQuery).c_str(), sverb.query_regex)) {
				cout << prepareQueryForPrintf(preparedQuery) << endl;
			}
		}
		if(pass > 0) {
			if(is_terminating()) {
				USLEEP(100000);
			} else {
				sleep(1);
			}
			if(!is_terminating() || !(attempt % 10)) {
				syslog(LOG_INFO, "next attempt %u - query: %s", attempt - 1, prepareQueryForPrintf(preparedQuery).substr(0, 100).c_str());
			}
		}
		if(!this->connected()) {
			this->connect();
		}
		if(this->connected()) {
			if(mysql_query(this->hMysqlConn, preparedQuery.c_str())) {
				if(this->ignoreErrorCodes.size() &&
				   std::find(this->ignoreErrorCodes.begin(), this->ignoreErrorCodes.end(), mysql_errno(this->hMysql)) != this->ignoreErrorCodes.end()) {
					break;
				}
				if(verbosity > 1) {
					syslog(LOG_NOTICE, "query error - query: %s", prepareQueryForPrintf(preparedQuery).c_str());
					syslog(LOG_NOTICE, "query error - error: %s", mysql_error(this->hMysql));
				}
				this->checkLastError("query error in [" + preparedQuery.substr(0,200) + (preparedQuery.size() > 200 ? "..." : "") + "]", 
						     (!sql_noerror && !this->disableLogError) || opt_sql_log_all_errors);
				if((!sql_noerror && !this->disableLogError) || opt_sql_log_all_errors) {
					if(verbosity > 1 || sverb.query_error) {
						cout << endl << "ERROR IN QUERY {" << this->getLastErrorString() << "}:"<< endl
						     << preparedQuery << endl;
					}
					if(!pass && (!opt_sql_errors_log_file.empty() || sverb.query_error_log[0])) {
						const char *error_log_file = !opt_sql_errors_log_file.empty() ?
									      opt_sql_errors_log_file.c_str() :
									      sverb.query_error_log;
						FILE *error_log = fopen(error_log_file, "a");
						if(error_log) {
							string dateTime = sqlDateTimeString(time(NULL));
							fprintf(error_log, "ERROR IN QUERY at %s {%s}:\n%s\n\n", 
								dateTime.c_str(), 
								this->getLastErrorString().c_str(),
								preparedQuery.c_str());
							fclose(error_log);
						}
					}
				}
				this->evError(pass);
				if(this->connecting) {
					break;
				} else {
					if(this->getLastError() == CR_SERVER_GONE_ERROR ||
					   this->getLastError() == ER_NO_PARTITION_FOR_GIVEN_VALUE) {
						if(pass < this->maxQueryPass - 1) {
							this->reconnect();
						}
					} else if(this->getLastError() == ER_TOO_BIG_ROWSIZE) {
						vector<string> matches;
						if(reg_match(query.c_str(), "ALTER TABLE ([a-z0-9_~]+)", &matches, true) && matches.size() >= 2) {
							bool alterOK = false;
							string table = matches[1];
							if(this->existsTable(table)) {
								if(!mysql_query(this->hMysqlConn, ("alter table " + table + " row_format=dynamic").c_str())) {
									syslog(LOG_NOTICE, "success change row_format to dynamic for table %s", table.c_str());
									MYSQL_RES *res = mysql_use_result(this->hMysqlConn);
									if(res) {
										while(mysql_fetch_row(res));
										mysql_free_result(res);
									}
									alterOK = true;
								} else {
									syslog(LOG_NOTICE, "failed change row_format to dynamic for table %s with error: %s", table.c_str(), mysql_error(this->hMysqlConn));
								}
								if(!alterOK) {
									break;
								}
							}
						} else {
							break;
						}
					} else if(sql_disable_next_attempt_if_error || 
						  this->disableNextAttemptIfError ||
						  this->ignoreLastError() ||
						  this->isSkipError() ||
						  (callFromStoreProcessWithFixDeadlock && this->getLastError() == ER_LOCK_DEADLOCK)) {
						break;
					} else if(useNewStore() == 2 && useSetId() && this->getLastError() == ER_DUP_ENTRY) {
						if(pass < this->maxQueryPass - 2) {
							pass = this->maxQueryPass - 2;
						}
					} else {
						if(this->getLastError() == ER_SP_ALREADY_EXISTS) {
							if(this->existsTable("mysql.proc")) {
								if(!mysql_query(this->hMysqlConn, "repair table mysql.proc")) {
									syslog(LOG_NOTICE, "success call 'repair table mysql.proc'");
									MYSQL_RES *res = mysql_use_result(this->hMysqlConn);
									if(res) {
										while(mysql_fetch_row(res));
										mysql_free_result(res);
									}
								} else {
									syslog(LOG_NOTICE, "failed call 'repair table mysql.proc' with error: %s", mysql_error(this->hMysqlConn));
								}
							}
							if(dropProcQuery) {
								if(!mysql_query(this->hMysqlConn, dropProcQuery)) {
									MYSQL_RES *res = mysql_use_result(this->hMysqlConn);
									if(res) {
										while(mysql_fetch_row(res));
										mysql_free_result(res);
									}
									syslog(LOG_NOTICE, "success call '%s'", dropProcQuery);
									++attempt;
									continue;
								} else  {
									syslog(LOG_NOTICE, "failed call '%s' with error: %s", dropProcQuery, mysql_error(this->hMysqlConn));
								}
							}
						}
						if(is_read_from_file() && pass < this->maxQueryPass - 10) {
							pass = this->maxQueryPass - 10;
						}
						if(pass < this->maxQueryPass - 1) {
							this->reconnect();
						}
					}
				}
			} else {
				if(verbosity > 1) {
					syslog(LOG_NOTICE, "query ok - %s", prepareQueryForPrintf(preparedQuery).c_str());
				}
				rslt = true;
				break;
			}
		}
		++attempt;
		if(is_terminating() && attempt >= 2) {
			break;
		}
	}
	SqlDb::addDelayQuery(getTimeMS() - startTimeMS);
	this->prevQuery = query;
	return(rslt);
}

SqlDb_row SqlDb_mysql::fetchRow() {
	SqlDb_row row(this);
	if(isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		if(response_data_index < response_data_rows &&
		   response_data_index < response_data.size()) {
			for(size_t i = 0; i < min(response_data[response_data_index].size(), response_data_columns.size()); i++) {
				row.add(response_data[response_data_index][i].is_null ?
					 NULL :
					 response_data[response_data_index][i].str.c_str(), 
					response_data_columns[i].c_str(), 
					response_data_columns_types[i],
					response_data[response_data_index][i].str.length());
			}
			++response_data_index;
		}
	} else if(this->hMysqlConn) {
		if(!this->hMysqlRes) {
			this->hMysqlRes = mysql_use_result(this->hMysqlConn);
			if(this->hMysqlRes) {
				MYSQL_FIELD *field;
				for(int i = 0; (field = mysql_fetch_field(this->hMysqlRes)); i++) {
					this->fields.push_back(field->name);
					this->fields_type.push_back(field->type);
				}
			} else {
				this->checkLastError("fetch row error in function mysql_use_result", true);
			}
		}
		if(this->hMysqlRes) {
			MYSQL_ROW mysqlRow = mysql_fetch_row(hMysqlRes);
			if(mysqlRow) {
				unsigned int numFields = mysql_num_fields(this->hMysqlRes);
				unsigned long *lengths = mysql_fetch_lengths(this->hMysqlRes);
				for(unsigned int i = 0; i < numFields; i++) {
					row.add(mysqlRow[i], this->fields[i], this->fields_type[i], lengths[i]);
				}
			} else {
				this->checkLastError("fetch row error", true);
			}
		}
	}
	return(row);
}

bool SqlDb_mysql::fetchQueryResult(vector<string> *fields, vector<int> *fields_types, vector<map<string, string_null> > *rows) {
	fields->clear();
	fields_types->clear();
	rows->clear();
	MYSQL_RES *hMysqlRes = mysql_use_result(this->hMysqlConn);
	if(hMysqlRes) {
		MYSQL_FIELD *field;
		for(int i = 0; (field = mysql_fetch_field(hMysqlRes)); i++) {
			fields->push_back(field->name);
			fields_types->push_back(field->type);
		}
		MYSQL_ROW mysqlRow;
		while((mysqlRow = mysql_fetch_row(hMysqlRes))) {
			map<string, string_null> rslt_row;
			unsigned int numFields = mysql_num_fields(hMysqlRes);
			unsigned long *lengths = mysql_fetch_lengths(hMysqlRes);
			for(unsigned int i = 0; i < numFields; i++) {
				rslt_row[(*fields)[i]] = string_null(mysqlRow[i], lengths[i], false);
			}
			rows->push_back(rslt_row);
		}
		mysql_free_result(hMysqlRes);
	}
	return(true);
	
}

string SqlDb_mysql::getJsonResult(vector<string> *fields, vector<int> *fields_types, vector<map<string, string_null> > *rows) {
	JsonExport exp;
	exp.add("result", "OK");
	string jsonData;
	if(rows->size()) {
		exp.add("data_rows", rows->size());
		exp.addArray("data");
		JsonExport expFields;
		expFields.setTypeItem(JsonExport::_array);
		for(size_t j = 0; j < fields->size(); j++) {
			expFields.add(NULL, (*fields)[j] + ':' + intToString((*fields_types)[j]));
		}
		jsonData = expFields.getJson();
		for(size_t i = 0; i < rows->size(); i++) {
			JsonExport expRow;
			expRow.setTypeItem(JsonExport::_array);
			for(size_t j = 0; j < min((*rows)[i].size(), fields->size()); j++) {
				if((*rows)[i][(*fields)[j]].is_null) {
					expRow.add(NULL);
				} else {
					expRow.add(NULL, (*rows)[i][(*fields)[j]].out());
				}
			}
			jsonData += "," + expRow.getJson();
		}
	}
	string jsonRslt = exp.getJson();
	if(!jsonData.empty()) {
		jsonRslt.resize(jsonRslt.length() - 2);
		jsonRslt += jsonData + "]}";
	}
	return(jsonRslt);
}

string SqlDb_mysql::getJsonResult() {
	vector<string> rslt_fields;
	vector<int> rslt_fields_types;
	vector<map<string, string_null> > rslt_rows;
	this->fetchQueryResult(&rslt_fields, &rslt_fields_types, &rslt_rows);
	return(this->getJsonResult(&rslt_fields, &rslt_fields_types, &rslt_rows));
}

string SqlDb_mysql::getCsvResult() {
	vector<string> rslt_fields;
	vector<int> rslt_fields_types;
	vector<map<string, string_null> > rslt_rows;
	this->fetchQueryResult(&rslt_fields, &rslt_fields_types, &rslt_rows);
	string rslt_csv = "CSV\n";
	for(size_t i = 0; i < rslt_fields.size(); i++) {
		if(i) {
			rslt_csv += ",";
		}
		rslt_csv += rslt_fields[i] + ':' + intToString(rslt_fields_types[i]);
	}
	for(size_t i = 0; i < rslt_rows.size(); i++) {
		rslt_csv += "\n";
		for(size_t j = 0; j < min(rslt_rows[i].size(), rslt_fields.size()); j++) {
			if(j) {
				rslt_csv += ",";
			}
			rslt_csv += rslt_rows[i][rslt_fields[j]].out();
		}
	}
	return(rslt_csv);
}

string SqlDb_mysql::getJsonError() {
	unsigned int errorCode = mysql_errno(hMysql);
	string errorStr = mysql_error(hMysql);
	JsonExport exp;
	exp.add("result", intToString(errorCode) + "|" + 
			  intToString((u_int16_t)(errorCode == ER_PARSE_ERROR ? 0 : 1)) + "|" + 
			  errorStr);
	return(exp.getJson());
}

int64_t SqlDb_mysql::getInsertId() {
	if(isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		if(this->query("select last_insert_id()")) {
			SqlDb_row row;
			if((row = this->fetchRow()) != 0) {
				return(atoll(row[0].c_str()));
			}
		}
	} else {
		if(this->hMysqlConn) {
			return(mysql_insert_id(this->hMysqlConn));
		}
	}
	return(-1);
}

bool SqlDb_mysql::existsTable(const char *table) {
	const char *db_table_separator;
	if((db_table_separator = strchr(table, '.')) != NULL) {
		string db = string(table, db_table_separator - table);
		this->query(string("select table_name from information_schema.tables where table_schema = '") + db + "' and table_name = '" + (db_table_separator + 1) + "'");
	} else {
		this->query(string("show tables like '") + table + "'");
	}
	int countRow = 0;
	while(this->fetchRow()) {
		++countRow;
	}
	return(countRow > 0);
}

list<string> SqlDb_mysql::getAllTables() {
	list<string> tables;
	this->query("show tables");
	SqlDb_row table_row;
	while((table_row = this->fetchRow())) {
		tables.push_back(table_row[0]);
	}
	return(tables);
}

bool SqlDb_mysql::existsDatabase() {
	if(cloud_db) {
		return(true);
	}
	this->query(string("show databases like '") + conn_database + "'");
	int countRow = 0;
	while(this->fetchRow()) {
		++countRow;
	}
	return(countRow > 0);
}

bool SqlDb_mysql::existsColumn(const char *table, const char *column, string *type) {
	if(isEnableExistColumnCache()) {
		int exists = this->existsColumnInCache(table, column, type);
		if(exists < 0) {
			this->query(string("show columns from ") + escapeTableName(table));
			SqlDb_row cdr_struct_row;
			while((cdr_struct_row = this->fetchRow())) {
				this->addColumnToCache(table, cdr_struct_row["field"].c_str(), cdr_struct_row["type"].c_str());
				if(cdr_struct_row["field"] == column) {
					exists = true;
					if(type) {
						*type = cdr_struct_row["type"];
					}
				}
			}
			return(exists > 0);
		} else {
			return(exists);
		}
	} else {
		this->query(string("show columns from ") + escapeTableName(table) + 
			    " where Field='" + column + "'");
		int countRow = 0;
		SqlDb_row cdr_struct_row;
		while((cdr_struct_row = this->fetchRow())) {
			++countRow;
			if(type) {
				*type = cdr_struct_row["type"];
			}
		}
		return(countRow > 0);
	}
}

string SqlDb_mysql::getTypeColumn(const char *table, const char *column, bool toLower, bool useCache) {
	if(useCache) {
		__SYNC_LOCK(typeColumn_cache_sync);
		if(!column ||
		   typeColumn_cache.find(table) == typeColumn_cache.end()) {
			this->query(string("show columns from ") + escapeTableName(table));
			SqlDb_row cdr_struct_row;
			while((cdr_struct_row = this->fetchRow())) {
				typeColumn_cache[table][cdr_struct_row["field"]] = cdr_struct_row["type"];
			}
		}
		string type;
		if(column) {
			if(typeColumn_cache.find(table) != typeColumn_cache.end() &&
			   typeColumn_cache[table].find(column) != typeColumn_cache[table].end()) {
				type = typeColumn_cache[table][column];
				if(toLower) {
					std::transform(type.begin(), type.end(), type.begin(), ::tolower);
				}
			}
		}
		__SYNC_UNLOCK(typeColumn_cache_sync);
		return(type);
	} else if(isEnableExistColumnCache()) {
		string type;
		existsColumn(table, column, &type);
		if(toLower) {
			std::transform(type.begin(), type.end(), type.begin(), ::tolower);
		}
		return(type);
	}
	this->query(string("show columns from ") + escapeTableName(table) + " like '" + column + "'");
	SqlDb_row cdr_struct_row = this->fetchRow();
	if(cdr_struct_row) {
		string type = cdr_struct_row["type"];
		if(toLower) {
			std::transform(type.begin(), type.end(), type.begin(), ::tolower);
		}
		return(type);
	}
	return("");
}

bool SqlDb_mysql::existsColumnInTypeCache(const char *table, const char *column) {
	return(existsColumnInTypeCache_static(table, column));
}

bool SqlDb_mysql::existsColumnInTypeCache_static(const char *table, const char *column) {
	bool rslt = false;
	__SYNC_LOCK(typeColumn_cache_sync);
	if(typeColumn_cache.find(table) != typeColumn_cache.end() &&
	   typeColumn_cache[table].find(column) != typeColumn_cache[table].end()) {
		rslt = true;
	}
	__SYNC_UNLOCK(typeColumn_cache_sync);
	return(rslt);
}

bool SqlDb_mysql::existsIndex(const char *table, const char *indexColumn, int seqInIndex) {
	this->query(string("show index from ") + escapeTableName(table) + 
		    " where (Column_name='" + indexColumn + "' or Key_name='" + indexColumn + "')" + 
		    (seqInIndex ? " and seq_in_index = " + intToString(seqInIndex) : ""));
	int countIndex = 0;
	SqlDb_row cdr_index_row;
	while((cdr_index_row = this->fetchRow())) {
		++countIndex;
	}
	return(countIndex > 0);
}

int SqlDb_mysql::getPartitions(const char *datadir, const char *database, const char *table, list<sPartition> *partitions, bool useCache) {
	if(useCache) {
		bool existsInCache = false;
		int sizeInCache = 0;
		__SYNC_LOCK(partitions_cache_sync);
		if(partitions_cache.find(table) != partitions_cache.end()) {
			if(partitions) {
				*partitions = partitions_cache[table];
			}
			sizeInCache = partitions_cache[table].size();
			existsInCache = true;
		}
		__SYNC_UNLOCK(partitions_cache_sync);
		if(existsInCache) {
			return(sizeInCache);
		}
	}
	list<sPartition> _partitions;
	int _size = 0;
	if(partitions) {
		partitions->clear();
	} else if(useCache) {
		partitions = &_partitions;
	}
	string query = 
		string("explain") + (getDbName() == "mysql" && getDbMajorVersion() >= 8 ? "" : " partitions") + " " +
		selectQuery(table);
	if(this->query(query)) {
		SqlDb_row row;
		if((row = this->fetchRow())) {
			vector<string> partitions_v = split(row["partitions"], ',');
			_size = partitions_v.size();
			if(partitions) {
				for(unsigned i = 0; i < partitions_v.size(); i++) {
					sPartition partition;
					fillPartitionData(&partition, datadir, database, table, partitions_v[i].c_str(), i == partitions_v.size() - 1);
					partitions->push_back(partition);
				}
			}
		}
	}
	if(useCache && partitions) {
		__SYNC_LOCK(partitions_cache_sync);
		partitions_cache[table] = *partitions;
		__SYNC_UNLOCK(partitions_cache_sync);
	}
	return(_size);
}

bool SqlDb_mysql::existsPartition(const char *table, const char *partition, bool useCache) {
	list<sPartition> partitions;
	if(getPartitions(NULL, NULL, table, &partitions, useCache) > 0) {
		for(list<sPartition>::iterator iter = partitions.begin(); iter != partitions.end(); iter++) {
			if(iter->name == partition) {
				return(true);
			}
		}
	}
	return(false);
}

bool SqlDb_mysql::emptyTable(const char *table, bool viaTableStatus) {
	return(rowsInTable(table, viaTableStatus) <= 0);
}

int64_t SqlDb_mysql::rowsInTable(const char *table, bool viaTableStatus) {
	list<SqlDb_field> fields;
	if(viaTableStatus) {
		this->query(string("show table status like '") + table + "'");
		SqlDb_row row = this->fetchRow();
		return(row ? atol(row["Rows"].c_str()) : -1);
	} else {
		fields.push_back(SqlDb_field("count(*)", "cnt", false));
		this->select(table, &fields);
		SqlDb_row row = this->fetchRow();
		return(row ? atol(row["cnt"].c_str()) : -1);
	}
}

int64_t SqlDb_mysql::sizeOfTable(const char *table) {
	this->query(string("show table status like '") + table + "'");
	SqlDb_row row = this->fetchRow();
	return(row ? atoll(row["Data_length"].c_str()) + atoll(row["Index_length"].c_str()) : -1);
}

bool SqlDb_mysql::isOldVerPartition(const char *table) {
	this->query(string("select partition_description from information_schema.partitions where table_schema='")  + mysql_database + 
			   "' and table_name like '" + table + "' and partition_description is not null and  partition_description regexp '^[0-9]+$' limit 1");
	return(this->fetchRow());
}

string SqlDb_mysql::escape(const char *inputString, int length) {
	return sqlEscapeString(inputString, length, this->getTypeDb().c_str());
}

string SqlDb_mysql::escapeTableName(string tableName) {
	if(isReservedWord(tableName) || tableName.find('-') != string::npos) {
		return("`" + tableName + "`");
	}
	return(tableName);
}

bool SqlDb_mysql::isReservedWord(string word) {
	const char* reservedWords[] = {
		"system",
		"group",
		"groups"
	};
	for(unsigned i = 0; i < sizeof(reservedWords) / sizeof(reservedWords[0]); i++) {
		if(!strcasecmp(reservedWords[i], word.c_str())) {
			return(true);
		}
	}
	return(false);
}

bool SqlDb_mysql::checkLastError(string prefixError, bool sysLog, bool clearLastError) {
	if(this->hMysql) {
		unsigned int errnoMysql = mysql_errno(this->hMysql);
		if(errnoMysql) {
			char errnoMysqlString[20];
			snprintf(errnoMysqlString, sizeof(errnoMysqlString), "%u", errnoMysql);
			this->setLastError(errnoMysql, (prefixError + ":  " + errnoMysqlString + " - " + mysql_error(this->hMysql)).c_str(), sysLog);
			return(true);
		} else if(clearLastError) {
			this->clearLastError();
		}
	}
	return(false);
}

void SqlDb_mysql::evError(int pass) {
	unsigned _errno = mysql_errno(this->hMysql);
	string _error = mysql_error(this->hMysql);
	switch(_errno) {
	case 1146:
		if(pass == 0) {
			string table = reg_replace(_error.c_str(), "'.+\\.([^']+)'", "$1", __FILE__, __LINE__);
			this->createTable(table.c_str());
		}
		break;
	}
}

void SqlDb_mysql::clean() {
	this->disconnect();
	this->cleanFields();
}

string SqlDb_mysql::getOptimalCompressType(bool memoryEngine, bool useCache) {
	extern int opt_mysqlcompress;
	extern char opt_mysqlcompress_type[256];
	if(!opt_mysqlcompress) {
		return("");
	}
	if(opt_mysqlcompress_type[0]) {
		return(opt_mysqlcompress_type);
	}
	string dbname = getDbName();
	if(dbname == "mysql") {
		return(getOptimalCompressType_mysql(memoryEngine, useCache));
	} else if(dbname == "mariadb") { 
		return(getOptimalCompressType_mariadb(memoryEngine, useCache));
	}
	return("");
}

string SqlDb_mysql::getOptimalCompressType_mysql(bool memoryEngine, bool useCache) {
	if(useCache) {
		if(memoryEngine) {
			if(!selectedCompressType_memoryEngine.empty()) {
				return(selectedCompressType_memoryEngine);
			}
		} else {
			if(!selectedCompressType.empty()) {
				return(selectedCompressType);
			}
		}
	}
	int dbVersion = getDbVersion();
	if(dbVersion >= 50708) {
		string compressType_test = "compression=\"lz4\"";
		if(testCreateTable(memoryEngine, compressType_test.c_str())) {
			setSelectedCompressType(memoryEngine, compressType_test.c_str());
			return(compressType_test);
		}
	}
	string compressType_test = MYSQL_ROW_FORMAT_COMPRESSED;
	if(testCreateTable(memoryEngine, compressType_test.c_str())) {
		setSelectedCompressType(memoryEngine, compressType_test.c_str());
		return(compressType_test);
	}
	setSelectedCompressType(memoryEngine, NULL);
	return("");
}

string SqlDb_mysql::getOptimalCompressType_mariadb(bool memoryEngine, bool useCache) {
	if(useCache) {
		if(memoryEngine) {
			if(!selectedCompressType_memoryEngine.empty()) {
				if(selectedCompressType_memoryEngine == MARIADB_PAGE_COMPRESSED) {
					if(getQueryRsltStringValue("show global variables like 'innodb_compression_algorithm'", 1) != selectedCompressSubtype_memoryEngine) {
						query("SET GLOBAL innodb_compression_algorithm='" + selectedCompressSubtype_memoryEngine + "'");
					}
				}
				return(selectedCompressType_memoryEngine);
			}
		} else {
			if(!selectedCompressType.empty()) {
				if(selectedCompressType == MARIADB_PAGE_COMPRESSED) {
					if(getQueryRsltStringValue("show global variables like 'innodb_compression_algorithm'", 1) != selectedCompressSubtype) {
						query("SET GLOBAL innodb_compression_algorithm='" + selectedCompressSubtype + "'");
					}
				}
				return(selectedCompressType);
			}
		}
	}
	int dbVersion = getDbVersion();
	if(dbVersion >= 100204 && !memoryEngine) {
		const char *try_compress_order[][2] = {
			{ "lz4", "Innodb_have_lz4" },
			{ "lzma", "Innodb_have_lzma" },
			{ "zlib", NULL },
			{ NULL, NULL }
		};
		vector<string> mariadb_compress_types;
		for(unsigned i = 0; try_compress_order[i][0]; i++) {
			if(try_compress_order[i][0] && try_compress_order[i][1]) {
				mariadb_compress_types.push_back(try_compress_order[i][1]);
			}
		}
		map<string, bool> mariadb_compress_enable_types;
		if(mariadb_compress_types.size()) {
			if(query("SHOW GLOBAL STATUS WHERE Variable_name IN ('" +
				 implode(mariadb_compress_types, "','") +
				 "')")) {
				SqlDb_row row;
				while((row = this->fetchRow())) {
					if(row[1] == "ON") {
						mariadb_compress_enable_types[row[0]] = true;
					}
				}
			}
		}
		for(unsigned i = 0; try_compress_order[i][0]; i++) {
			if(try_compress_order[i][0]) {
				if(!try_compress_order[i][1] || 
				   mariadb_compress_enable_types[try_compress_order[i][1]]) {
					if(getQueryRsltStringValue("show global variables like 'innodb_compression_algorithm'", 1) == try_compress_order[i][0] ||
					   query(string("SET GLOBAL innodb_compression_algorithm='") + try_compress_order[i][0] + "'")) {
						string compressType_test = MARIADB_PAGE_COMPRESSED;
						if(testCreateTable(memoryEngine, compressType_test.c_str())) {
							setSelectedCompressType(memoryEngine, compressType_test.c_str(), try_compress_order[i][0]);
							return(compressType_test);
						}
					}
				}
			}
		}
	}
	if(dbVersion < 100204) {
		string compressType_test = MYSQL_ROW_FORMAT_COMPRESSED;
		if(testCreateTable(memoryEngine, compressType_test.c_str())) {
			setSelectedCompressType(memoryEngine, compressType_test.c_str());
			return(compressType_test);
		}
	}
	setSelectedCompressType(memoryEngine, NULL);
	return("");
}

bool SqlDb_mysql::testCreateTable(bool memoryEngine, const char *compressType) {
	bool rslt = false;
	unsigned int maxQueryPassOld = getMaxQueryPass();
	setMaxQueryPass(1);
	string tableName = "_test_compress_type_" + intToString(rand() % 100000);
	if(existsTable(tableName)) {
		query("drop table `" + tableName + "`");
	}
	if(query("create table `" + tableName + "` ( `test_field` char(10) ) ENGINE=" + (memoryEngine ? "memory" : "InnoDB") + " " + compressType)) {
		if(existsTable(tableName)) {
			rslt = true;
			query("drop table `" + tableName + "`");
		}
	}
	setMaxQueryPass(maxQueryPassOld);
	return(rslt);
}

void SqlDb_mysql::setSelectedCompressType(bool memoryEngine, const char *type, const char *subtype) {
	if(memoryEngine) {
		selectedCompressType_memoryEngine = type ? type : "";
		selectedCompressSubtype_memoryEngine = subtype ? subtype : "";
	} else {
		selectedCompressType = type ? type : "";
		selectedCompressSubtype = subtype ? subtype : "";
	}
}


SqlDb_odbc_bindBufferItem::SqlDb_odbc_bindBufferItem(SQLUSMALLINT colNumber, string fieldName, SQLSMALLINT dataType, SQLULEN columnSize, SQLHSTMT hStatement) {
	this->colNumber = colNumber;
	this->fieldName = fieldName;
	this->dataType = dataType;
	this->columnSize = columnSize;
	this->buffer = new FILE_LINE(29001) char[this->columnSize + 100]; // 100 - reserve for convert binary to text
	memset(this->buffer, 0, this->columnSize + 100);
	if(hStatement) {
		this->bindCol(hStatement);
	}
}

SqlDb_odbc_bindBufferItem::~SqlDb_odbc_bindBufferItem() {
	if(this->buffer) {
		delete [] this->buffer;
	}
}

void SqlDb_odbc_bindBufferItem::bindCol(SQLHSTMT hStatement) {
	SQLBindCol(hStatement, this->colNumber, SQL_CHAR, this->buffer, this->columnSize, &this->ind);
}

string SqlDb_odbc_bindBufferItem::getContent() {
	return(string(this->buffer));
}

char* SqlDb_odbc_bindBufferItem::getBuffer() {
	return(this->buffer);
}


void SqlDb_odbc_bindBuffer::addItem(SQLUSMALLINT colNumber, string fieldName, SQLSMALLINT dataType, SQLULEN columnSize, SQLHSTMT hStatement) {
	this->push_back(new FILE_LINE(29002) SqlDb_odbc_bindBufferItem(colNumber, fieldName, dataType, columnSize, hStatement));
}

void SqlDb_odbc_bindBuffer::bindCols(SQLHSTMT hStatement) {
	SQLCHAR columnName[255];
	SQLSMALLINT nameLength;
	SQLSMALLINT dataType;
	SQLULEN columnSize;
	SQLSMALLINT decimalDigits;
	SQLSMALLINT nullable;
	unsigned int columnIndex = 0;
	while(!SQLDescribeCol(
			hStatement, columnIndex + 1, columnName, sizeof(columnName)/sizeof(SQLCHAR),
			&nameLength, &dataType, &columnSize, &decimalDigits, &nullable)) {
		this->addItem(columnIndex + 1, (const char*)columnName, dataType, columnSize + 1, hStatement);
		++columnIndex;
	}
}

string SqlDb_odbc_bindBuffer::getColContent(string fieldName) {
	int index = this->getIndexField(fieldName);
	if(index >= 0) {
		this->getColContent(index);
	}
	return("");
}

string SqlDb_odbc_bindBuffer::getColContent(unsigned int fieldIndex) {
	return(fieldIndex < this->size() ?
		(*this)[fieldIndex]->getContent() :
		"");
}

char* SqlDb_odbc_bindBuffer::getColBuffer(unsigned int fieldIndex) {
	return(fieldIndex < this->size() ?
		(*this)[fieldIndex]->getBuffer() :
		NULL);
}

int SqlDb_odbc_bindBuffer::getIndexField(string fieldName) {
	for(size_t i = 0; i < this->size(); i++) {
		if(!strcasecmp((*this)[i]->fieldName.c_str(), fieldName.c_str())) {
			return(i);
		}
	}
	return(-1);
}


SqlDb_odbc::SqlDb_odbc() {
	this->odbcVersion = (ulong)NULL;
	this->subtypeDb = "";
	this->hEnvironment = NULL;
	this->hConnection = NULL;
	this->hStatement = NULL;
}

SqlDb_odbc::~SqlDb_odbc() {
	this->clean();
}

void SqlDb_odbc::setOdbcVersion(ulong odbcVersion) {
	this->odbcVersion = odbcVersion;
}

void SqlDb_odbc::setSubtypeDb(string subtypeDb) {
	this->subtypeDb = subtypeDb;
}

bool SqlDb_odbc::connect(bool /*createDb*/, bool /*mainInit*/) {
	this->connecting = true;
	SQLRETURN rslt;
	this->clearLastError();
	if(!this->hEnvironment) {
		rslt = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &this->hEnvironment);
		if(!this->okRslt(rslt)) {
			this->setLastError(rslt, "odbc: error in allocate environment handle", true);
			this->disconnect();
			this->connecting = false;
			return(false);
		}
		if(this->odbcVersion) {
			rslt = SQLSetEnvAttr(this->hEnvironment, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)this->odbcVersion, 0); 
			if(!this->okRslt(rslt)) {
				this->setLastError(rslt, "odbc: error in set environment attributes");
				this->disconnect();
				this->connecting = false;
				return(false);
			}
		}
	}
	if(!this->hConnection) {
		rslt = SQLAllocHandle(SQL_HANDLE_DBC, this->hEnvironment, &this->hConnection); 
		if(!this->okRslt(rslt)) {
			this->setLastError(rslt, "odbc: error in allocate connection handle");
			this->disconnect();
			this->connecting = false;
			return(false);
		}
		if(this->loginTimeout) {
			SQLSetConnectAttr(this->hConnection, SQL_LOGIN_TIMEOUT, (SQLPOINTER *)this->loginTimeout, 0);
		}
		rslt = SQLConnect(this->hConnection, 
				  (SQLCHAR*)this->conn_server.c_str(), SQL_NTS,
				  (SQLCHAR*)this->conn_user.c_str(), SQL_NTS,
				  (SQLCHAR*)this->conn_password.c_str(), SQL_NTS);
		if(!this->okRslt(rslt)) {
			this->checkLastError("odbc: connect error (" + this->conn_server + ")", true);
			this->disconnect();
			this->connecting = false;
			return(false);
		}
	}
	this->connecting = false;
	return(true);
}

void SqlDb_odbc::disconnect() {
	if(this->hStatement) {
		SQLFreeHandle(SQL_HANDLE_STMT, this->hStatement);
		this->hStatement = NULL;
	}
	if(this->hConnection) {
		SQLDisconnect(this->hConnection);
		SQLFreeHandle(SQL_HANDLE_DBC, this->hConnection);
		this->hConnection = NULL;
	}
	if(this->hEnvironment) {
		SQLFreeHandle(SQL_HANDLE_ENV, this->hEnvironment);
		this->hEnvironment = NULL;
	}
}

bool SqlDb_odbc::connected() {
	return(this->hConnection != NULL);
}

bool SqlDb_odbc::query(string query, bool /*callFromStoreProcessWithFixDeadlock*/, const char */*dropProcQuery*/) {
	SQLRETURN rslt = SQL_NULL_DATA;
	if(this->hStatement) {
		SQLFreeHandle(SQL_HANDLE_STMT, this->hStatement);
		this->hStatement = NULL;
	}
	this->cleanFields();
	unsigned int attempt = 1;
	for(unsigned int pass = 0; pass < this->maxQueryPass; pass++) {
		string preparedQuery = this->prepareQuery(query, attempt > 1);
		if(attempt == 1 && verbosity > 1) { 
			syslog(LOG_INFO, "%s", prepareQueryForPrintf(preparedQuery).c_str());
		}
		if(pass > 0) {
			if(is_terminating()) {
				USLEEP(100000);
			} else {
				sleep(1);
			}
		}
		if(!this->connected()) {
			this->connect();
		}
		if(this->connected()) {
			rslt = SQLAllocHandle(SQL_HANDLE_STMT, hConnection, &hStatement);
			if(!this->okRslt(rslt)) {
				this->checkLastError("odbc: error in allocate statement handle", true);
				if(is_terminating()) {
					break;
				}
				this->reconnect();
				++attempt;
				continue;
			}
			rslt = SQLExecDirect(this->hStatement, (SQLCHAR*)preparedQuery.c_str(), SQL_NTS);   
			if(!this->okRslt(rslt) && rslt != SQL_NO_DATA) {
				if((!sql_noerror && !this->disableLogError) || opt_sql_log_all_errors) {
					this->checkLastError("odbc query error", true);
				}
				if(sql_disable_next_attempt_if_error || 
				   this->disableNextAttemptIfError) {
					break;
				}
				else if(rslt == SQL_ERROR || rslt == SQL_INVALID_HANDLE) {
					if(pass < this->maxQueryPass - 1) {
						this->reconnect();
					}
				} else {
					if(is_read_from_file() && pass < this->maxQueryPass - 10) {
						pass = this->maxQueryPass - 10;
					}
					if(pass < this->maxQueryPass - 1) {
						this->reconnect();
					}
				}
			} else {
				break;
			}
		}
		++attempt;
		if(is_terminating() && attempt >= 2) {
			break;
		}
	}
	return(this->okRslt(rslt) || rslt == SQL_NO_DATA);
}

SqlDb_row SqlDb_odbc::fetchRow() {
	SqlDb_row row(this);
	if(this->hConnection && this->hStatement) {
		if(!this->bindBuffer.size()) {
			this->bindBuffer.bindCols(this->hStatement);
		}
		SQLRETURN rslt = SQLFetch(hStatement);
		if(this->okRslt(rslt) || rslt == SQL_NO_DATA) {
			if(rslt != SQL_NO_DATA) {
				for(unsigned int i = 0; i < this->bindBuffer.size(); i++) {
					row.add(this->bindBuffer.getColBuffer(i), this->bindBuffer[i]->fieldName);
				}
			}
		} else {
			this->checkLastError("odbc fetch error", true);
		}
	}
	return(row);
}

int64_t SqlDb_odbc::getInsertId() {
	SqlDb_row row;
	if(this->query("select @@identity as last_insert_id") &&
	   (row = this->fetchRow()) != 0) {
		return(atoll(row["last_insert_id"].c_str()));
	}
	return(-1);
}

bool SqlDb_odbc::existsTable(const char */*table*/) {
	// TODO
	return(false);
}

bool SqlDb_odbc::existsDatabase() {
	// TODO
	return(false);
}

bool SqlDb_odbc::existsColumn(const char */*table*/, const char */*column*/, string */*type*/) {
	// TODO
	return(false);
}

string SqlDb_odbc::getTypeColumn(const char */*table*/, const char */*column*/, bool /*toLower*/, bool /*useCache*/) {
	// TODO
	return("");
}

bool SqlDb_odbc::existsColumnInTypeCache(const char */*table*/, const char */*column*/) {
	// TODO
	return(false);
}

bool SqlDb_odbc::existsIndex(const char */*table*/, const char */*indexColumn*/, int /*seqInIndex*/) {
	// TODO
	return(false);
}

int SqlDb_odbc::getPartitions(const char */*datadir*/, const char */*database*/, const char */*table*/, list<sPartition> */*partitions*/, bool /*useCache*/) {
	// TODO
	return(-1);
}

bool SqlDb_odbc::existsPartition(const char */*table*/, const char */*partition*/, bool /*useCache*/) {
	// TODO
	return(false);
}

bool SqlDb_odbc::emptyTable(const char *table, bool viaTableStatus) {
	return(rowsInTable(table, viaTableStatus));
}

int64_t SqlDb_odbc::rowsInTable(const char */*table*/, bool /*viaTableStatus*/) {
	// TODO
	return(-1);
}

int64_t SqlDb_odbc::sizeOfTable(const char */*table*/) {
	// TODO
	return(-1);
}

int SqlDb_odbc::getIndexField(string fieldName) {
	for(size_t i = 0; i < this->bindBuffer.size(); i++) {
		if(!strcasecmp(this->bindBuffer[i]->fieldName.c_str(), fieldName.c_str())) {
			return(i);
		}
	}
	return(-1);
}

string SqlDb_odbc::escape(const char *inputString, int length) {
	return sqlEscapeString(inputString, length, this->getTypeDb().c_str());
}

bool SqlDb_odbc::checkLastError(string prefixError, bool sysLog, bool /*clearLastError*/) {
	if(this->hConnection) {
		SQLCHAR sqlState[10];
		SQLINTEGER nativeError;
		SQLCHAR messageText[1000];
		SQLSMALLINT messageTextLength;
		SQLRETURN rslt = SQLGetDiagRec(
					this->hStatement ? SQL_HANDLE_STMT : SQL_HANDLE_DBC,
					this->hStatement ? this->hStatement : this->hConnection,
					1, sqlState, &nativeError, messageText, sizeof(messageText), &messageTextLength);
		if(this->okRslt(rslt)) {
			if(nativeError) {
				this->setLastError(nativeError, (prefixError + ":  " + string((char*)messageText)).c_str(), sysLog);
				return(true);
			} else {
				this->clearLastError();
			}
		}
	}
	return(false);
}

void SqlDb_odbc::evError(int /*pass*/) {
}

void SqlDb_odbc::cleanFields() {
	for(unsigned int i = 0; i < this->bindBuffer.size(); i++) {
		delete this->bindBuffer[i];
	}
	this->bindBuffer.clear();
}

void SqlDb_odbc::clean() {
	this->disconnect();
	this->cleanFields();
}

void *MySqlStore_process_storing(void *storeProcess_addr) {
	MySqlStore_process *storeProcess = (MySqlStore_process*)storeProcess_addr;
	storeProcess->store();
	return(NULL);
}
	
MySqlStore_process::MySqlStore_process(int id_main, int id_2, MySqlStore *parentStore,
				       const char *host, const char *user, const char *password, const char *database, u_int16_t port, const char *socket,
				       const char *cloud_host, const char *cloud_token, bool cloud_router, int concatLimit, mysqlSSLOptions *mySSLOpt) {
	this->id_main = id_main;
	this->id_2 = id_2;
	this->parentStore = parentStore;
	this->terminated = false;
	this->enableTerminatingDirectly = false;
	this->enableTerminatingIfEmpty = false;
	this->enableTerminatingIfSqlError = false;
	this->enableAutoDisconnect = false;
	this->concatLimit = concatLimit;
	this->enableTransaction = false;
	this->enableFixDeadlock = false;
	this->queryBuffLimit = 0;
	this->lastQueryTime = 0;
	this->queryCounter = 0;
	this->sqlDb = new FILE_LINE(29003) SqlDb_mysql();
	this->sqlDb->setConnectParameters(host, user, password, database, port, socket, true, mySSLOpt);
	if(cloud_host && *cloud_host) {
		this->sqlDb->setCloudParameters(cloud_host, cloud_token, cloud_router);
	}
	this->lock_sync = 0;
	this->thread = (pthread_t)NULL;
	this->threadRunningCounter = 0;
	this->lastThreadRunningCounterCheck = 0;
	this->lastThreadRunningTimeCheck = 0;
	this->remote_socket = NULL;
	this->check_store_supported = false;
	this->check_time_supported = false;
	this->last_store_iteration_time = 0;
}

MySqlStore_process::~MySqlStore_process() {
	this->waitForTerminate();
	if(this->sqlDb) {
		delete this->sqlDb;
	}
	if(this->remote_socket) {
		delete this->remote_socket;
	}
}

void MySqlStore_process::connect() {
	if(!this->sqlDb->connected()) {
		this->sqlDb->connect();
	}
}

void MySqlStore_process::disconnect() {
	if(this->sqlDb->connected()) {
		this->sqlDb->disconnect();
	}
}

bool MySqlStore_process::connected() {
	return(this->sqlDb->connected());
}

void MySqlStore_process::query(const char *query_str) {
	if(sverb.store_process_query) {
		cout << "store_process_query_" << this->id_main << "_" << this->id_2 << endl
		     << query_str << endl;
	}
	bool needCreateThread = false;
	if(!this->thread) {
		needCreateThread = true;
	} else if(!(queryCounter % 10)) {
		u_long act_time = getTimeS();
		if(!this->lastThreadRunningTimeCheck) {
			this->lastThreadRunningTimeCheck = act_time;
		} else if(act_time - this->lastThreadRunningTimeCheck > 60 && pthread_kill(this->thread, SIGCONT)) {
			if(this->threadRunningCounter == this->lastThreadRunningCounterCheck) {
				syslog(LOG_NOTICE, "resurrection sql store process %i_%i thread", this->id_main, this->id_2);
				needCreateThread = true;
			} else {
				this->lastThreadRunningCounterCheck = this->threadRunningCounter;
			}
			this->lastThreadRunningTimeCheck = act_time;
		}
	}
	if(needCreateThread) {
		this->threadRunningCounter = 0;
		this->lastThreadRunningCounterCheck = 0;
		vm_pthread_create_autodestroy(("sql store " + intToString(id_main) + "_" + intToString(id_2)).c_str(),
					      &this->thread, NULL, MySqlStore_process_storing, this, __FILE__, __LINE__);
	}
	this->query_buff.push_back(query_str);
	++queryCounter;
}

void MySqlStore_process::queryByRemoteSocket(const char *query_str) {
	unsigned maxPass = 100000;
	unsigned nextUsleepAfterError = 0;
	bool quietlyError = false;
	bool keepConnectAfterError = false;
	bool needCheckStore = false;
	sSnifferClientOptions *_snifferClientOptions = id_main == STORE_PROC_ID_CHARTS_CACHE && snifferClientOptions_charts_cache.isSetHostPort() ?
							&snifferClientOptions_charts_cache :
							&snifferClientOptions;
	for(unsigned int pass = 0; pass < maxPass; pass++) {
		if(is_terminating() > 1 && pass > 2) {
			break;
		}
		if(pass > 0) {
			if(!keepConnectAfterError && this->remote_socket) {
				delete this->remote_socket;
				this->remote_socket = NULL;
			}
			if(nextUsleepAfterError) {
				usleep(nextUsleepAfterError);
			} else {
				sleep(min(1 + pass * 2,  60u));
			}
			if(!quietlyError) {
				syslog(LOG_INFO, "next attempt %u - query: %s", pass, prepareQueryForPrintf(query_str).substr(0, 100).c_str());
			}
			nextUsleepAfterError = 0;
			quietlyError = false;
			keepConnectAfterError = false;
		}
		if(!this->remote_socket) {
			this->remote_socket = new FILE_LINE(0) cSocketBlock("sql store", true);
			this->remote_socket->setHostsPort(_snifferClientOptions->hosts, _snifferClientOptions->port);
			if(!this->remote_socket->connect()) {
				syslog(LOG_ERR, "send store query error: %s", (string("failed connect to ") + (isCloud() ? "cloud router" : "server")).c_str());
				continue;
			}
			string cmd = "{\"type_connection\":\"store\"}\r\n";
			if(!this->remote_socket->write(cmd)) {
				syslog(LOG_ERR, "send store query error: %s", "failed send command");
				continue;
			}
			string rsltRsaKey;
			if(!this->remote_socket->readBlock(&rsltRsaKey) || rsltRsaKey.find("key") == string::npos) {
				syslog(LOG_ERR, "send store query error: %s", "failed read rsa key");
				continue;
			}
			JsonItem jsonRsaKey;
			jsonRsaKey.parse(rsltRsaKey);
			string rsa_key = jsonRsaKey.getValue("rsa_key");
			this->remote_socket->set_rsa_pub_key(rsa_key);
			this->remote_socket->generate_aes_keys();
			JsonExport json_keys;
			json_keys.add("password", snifferServerClientOptions.password);
			string aes_ckey, aes_ivec;
			this->remote_socket->get_aes_keys(&aes_ckey, &aes_ivec);
			json_keys.add("aes_ckey", aes_ckey);
			json_keys.add("aes_ivec", aes_ivec);
			if(!this->remote_socket->writeBlock(json_keys.getJson(), cSocket::_te_rsa)) {
				syslog(LOG_ERR, "send store query error: %s", "failed send token & aes keys");
				continue;
			}
			string connectResponse;
			bool connectOK = false;
			string connectError;
			if(this->remote_socket->readBlock(&connectResponse)) {
				if(connectResponse == "OK") {
					connectOK = true;
					this->check_store_supported = false;
					this->check_time_supported = false;
				} else if(isJsonObject(connectResponse)) {
					JsonItem connectResponseData;
					connectResponseData.parse(connectResponse);
					if(connectResponseData.getValue("rslt") == "OK") {
						connectOK = true;
						this->check_store_supported = atoi(connectResponseData.getValue("check_store").c_str());
						this->check_time_supported = atoi(connectResponseData.getValue("check_time").c_str());
					} else {
						connectError = connectResponseData.getValue("error");
					}
				} else {
					connectError = connectResponse;
				}
			}
			if(!connectOK) {
				if(!this->remote_socket->isError()) {
					syslog(LOG_ERR, "send store query error: %s", 
					       (string("failed response from ") + (isCloud() ? "cloud router" : "server") + 
						" - " + (connectError.empty() ? "unknown error" : connectError)).c_str());
					delete this->remote_socket;
					this->remote_socket = NULL;
					continue;
				} else {
					syslog(LOG_ERR, "send store query error: %s", "failed read ok");
					continue;
				}
			}
		}
		string response;
		bool checkStoreOK = false;
		if(this->check_store_supported && needCheckStore) {
			if(!this->remote_socket->writeBlock("check", cSocket::_te_aes)) {
				syslog(LOG_ERR, "send store query error: %s", "failed send check store");
				continue;
			}
			if(this->remote_socket->readBlock(&response, cSocket::_te_aes)) {
				if(response == "OK") {
					checkStoreOK = true;
				}
			} else {
				syslog(LOG_ERR, "send store query error: %s", "failed read check store response");
				continue;
			}
		}
		if(!(this->check_store_supported && needCheckStore) || checkStoreOK) {
			string query_str_with_id = intToString(id_main) + '|' +
						   (this->check_time_supported ? 'T' + sqlDateTimeString(time(NULL)) + '|' : "") +
						   query_str;
			bool okSendQuery = true;
			if(query_str_with_id.length() > 100 && _snifferClientOptions->type_compress != _cs_compress_na) {
				if(_snifferClientOptions->type_compress == _cs_compress_gzip) {
					cGzip gzipCompressQuery;
					u_char *queryGzip;
					size_t queryGzipLength;
					if(gzipCompressQuery.compressString(query_str_with_id, &queryGzip, &queryGzipLength)) {
						if(!this->remote_socket->writeBlock(queryGzip, queryGzipLength, cSocket::_te_aes)) {
							okSendQuery = false;
						}
						delete [] queryGzip;
					}
				#ifdef HAVE_LIBZSTD
				} else if(_snifferClientOptions->type_compress == _cs_compress_zstd) {
					cZstd zstdCompressQuery;
					u_char *queryZstd;
					size_t queryZstdLength;
					if(zstdCompressQuery.compressString(query_str_with_id, &queryZstd, &queryZstdLength)) {
						if(!this->remote_socket->writeBlock(queryZstd, queryZstdLength, cSocket::_te_aes)) {
							okSendQuery = false;
						}
						delete [] queryZstd;
					}
				#endif
				#ifdef HAVE_LIBLZO
				} else if(_snifferClientOptions->type_compress == _cs_compress_lzo) {
					cLzo lzoCompressQuery;
					u_char *queryLzo;
					size_t queryLzoLength;
					if(lzoCompressQuery.compress((u_char*)query_str_with_id.c_str(), query_str_with_id.length(), &queryLzo, &queryLzoLength)) {
						if(!this->remote_socket->writeBlock(queryLzo, queryLzoLength, cSocket::_te_aes)) {
							okSendQuery = false;
						}
						delete [] queryLzo;
					}
				#endif
				}
			} else {
				if(!this->remote_socket->writeBlock(query_str_with_id, cSocket::_te_aes)) {
					okSendQuery = false;
				}
			}
			if(!okSendQuery) {
				syslog(LOG_ERR, "send store query error: %s", "failed send query");
				continue;
			}
			if(!this->remote_socket->readBlock(&response, cSocket::_te_aes)) {
				syslog(LOG_ERR, "send store query error: %s", "failed read query response");
				continue;
			}
		}
		if(response == "OK") {
			needCheckStore = false;
			break;
		} else {
			bool next_attempt = true;
			string error;
			if(response.empty()) {
				error = "response is empty";
			} else if(isJsonObject(response)) {
				JsonItem jsonResponse;
				jsonResponse.parse(response);
				error = jsonResponse.getValue("error");
				string next_attempt_str = jsonResponse.getValue("next_attempt");
				if(!next_attempt_str.empty()) {
					next_attempt = atoi(next_attempt_str.c_str());
				}
				string usleep_str = jsonResponse.getValue("usleep");
				if(!usleep_str.empty()) {
					nextUsleepAfterError = atoll(usleep_str.c_str());
				}
				string quietly_str = jsonResponse.getValue("quietly");
				if(!quietly_str.empty()) {
					quietlyError = atoi(quietly_str.c_str());
				}
				string keep_connect_str = jsonResponse.getValue("keep_connect");
				if(!keep_connect_str.empty()) {
					keepConnectAfterError = atoi(keep_connect_str.c_str());
				}
				needCheckStore = true;
			} else {
				error = response;
			}
			if(!quietlyError) {
				syslog(LOG_ERR, "send store query error: %s", error.c_str());
			}
			if(!next_attempt) {
				break;
			}
		}
	}
}

void MySqlStore_process::store() {
	string beginTransaction = "\nDECLARE EXIT HANDLER FOR SQLEXCEPTION\nBEGIN\nROLLBACK;\nEND;\nSTART TRANSACTION;\n";
	string endTransaction = "\nCOMMIT;\n";
	while(1) {
		list<string> queryqueue;
		unsigned queryqueue_length = 0;
		while(1) {
			++this->threadRunningCounter;
			if(id_main == STORE_PROC_ID_CHARTS_CACHE_REMOTE ||
			   snifferClientOptions.isEnableRemoteStore()) {
				extern int opt_charts_cache_remote_concat_limit;
				unsigned concat_limit = id_main == STORE_PROC_ID_CHARTS_CACHE_REMOTE ?
							 opt_charts_cache_remote_concat_limit :
							 snifferClientOptions.mysql_concat_limit;
				this->lock();
				if(this->query_buff.size() == 0) {
					this->unlock();
					break;
				}
				if(this->query_buff.size() == 1 || concat_limit <= 1) {
					string query = this->query_buff.front();
					this->query_buff.pop_front();
					#if DEBUG_STORE_COUNT
					++_store_cnt[id_main * 100 + id_2];
					#endif
					this->unlock();
					if(id_main == STORE_PROC_ID_CHARTS_CACHE_REMOTE) {
						while(!add_rchs_query(query.c_str(), true)) {
							USLEEP(1000);
						}
					} else {
						this->queryByRemoteSocket(query.c_str());
					}
				} else {
					string queries;
					for(unsigned i = 0; i < concat_limit; i++) {
						if(this->query_buff.size() == 0) {
							break;
						}
						string query = this->query_buff.front();
						queries += "L" + intToString(query.length()) + ":" + query + "\n";
						this->query_buff.pop_front();
						#if DEBUG_STORE_COUNT
						++_store_cnt[id_main * 100 + id_2];
						#endif
					}
					this->unlock();
					if(id_main == STORE_PROC_ID_CHARTS_CACHE_REMOTE) {
						while(!add_rchs_query(queries.c_str(), true)) {
							USLEEP(1000);
						}
					} else {
						this->queryByRemoteSocket(queries.c_str());
					}
				}
			} else if(id_main == STORE_PROC_ID_CDR_REDIRECT) {
				while((partitionsServiceIsInProgress || sCreatePartitions::in_progress) && !is_terminating()) {
					usleep(100000);
				}
				unsigned queries_max = 10;
				string queries[queries_max];
				unsigned queries_count = 0;
				this->lock();
				while(queries_count < queries_max) {
					if(this->query_buff.size()) {
						queries[queries_count++] = this->query_buff.front();
						this->query_buff.pop_front();
					} else {
						break;
					}
				}
				this->unlock();
				if(queries_count) {
					for(unsigned i = 0; i < queries_count; i++) {
						#if TEST_SERVER_STORE_SPEED
						SqlDb::addDelayQuery(10);
						#else
						u_int32_t startTimeMS = getTimeMS();
						this->sqlDb->query(queries[i]);
						SqlDb::addDelayQuery(getTimeMS() - startTimeMS, SqlDb::_tq_redirect);
						lastQueryTime = getTimeMS_rdtsc() / 1000;
						#endif
					}
				} else {
					break;
				}
			} else {
				string beginProcedure = "\nBEGIN\n" + (opt_mysql_enable_transactions || this->enableTransaction ? beginTransaction : "");
				string endProcedure = (opt_mysql_enable_transactions || this->enableTransaction ? endTransaction : "") + "\nEND";
				this->lock();
				if(this->query_buff.size() == 0) {
					this->unlock();
					if(queryqueue.size()) {
						this->_store(beginProcedure, endProcedure, &queryqueue);
						lastQueryTime = getTimeS();
						queryqueue.clear();
						queryqueue_length = 0;
						if(verbosity > 1) {
							syslog(LOG_INFO, "STORE id: %i_%i", this->id_main, this->id_2);
						}
					}
					break;
				}
				string query = this->query_buff.front();
				size_t query_len = query.length();
				while(query_len && query[query_len - 1] == ' ') {
					--query_len;
				}
				if(query_len < query.length()) {
					query.resize(query_len);
				}
				if(!((query_len && query[query_len - 1] == ';') ||
				     (query_len > 1 && query[query_len - 1] == '\n' && query[query_len - 2] == ';'))) {
					query.append("; ");
				}
				bool maxAllowedPacketIsFull = false;
				if(queryqueue.size() > 0 && queryqueue_length * 1.1 + query.length() > this->sqlDb->maxAllowedPacket) {
					maxAllowedPacketIsFull = true;
					this->unlock();
				} else {
					this->query_buff.pop_front();
					#if DEBUG_STORE_COUNT
					++_store_cnt[id_main * 100 + id_2];
					#endif
					this->unlock();
					queryqueue.push_back(query);
				}
				if((int)queryqueue.size() >= this->concatLimit || maxAllowedPacketIsFull) {
					this->_store(beginProcedure, endProcedure, &queryqueue);
					lastQueryTime = getTimeS();
					queryqueue.clear();
					queryqueue_length = 0;
					if(verbosity > 1) {
						syslog(LOG_INFO, "STORE id: %i_%i", this->id_main, this->id_2);
					}
				}
				if(is_terminating() && this->sqlDb->getLastError() && this->enableTerminatingIfSqlError) {
					break;
				}
				this->last_store_iteration_time = getTimeMS_rdtsc() / 1000;
			}
		}
		if(is_terminating() && 
		   (this->enableTerminatingDirectly ||
		    (this->enableTerminatingIfEmpty && this->query_buff.size() == 0) ||
		    (this->enableTerminatingIfSqlError && this->sqlDb->getLastError()))) {
			break;
		}
		if(this->enableAutoDisconnect && this->connected() &&
		   getTimeS() - lastQueryTime > 600) {
			this->disconnect();
		}
		if(id_main == STORE_PROC_ID_CDR_REDIRECT) {
			usleep(1000);
		} else {
			sleep(1);
		}
	}
	this->terminated = true;
	syslog(LOG_NOTICE, "terminated - sql store %i_%i", this->id_main, this->id_2);
}

void MySqlStore_process::_store(string beginProcedure, string endProcedure, list<string> *queries) {
	if(opt_nocdr) {
		return;
	}
	static unsigned counter;
	static unsigned sumTimeMS;
	unsigned long startTimeMS = getTimeMS();
	size_t queries_size = 0;
	if(sverb.store_process_query_compl_time) {
		queries_size = queries->size();
	}
	if(useNewStore() || opt_load_query_main_from_files || is_server()) {
		string queries_str_old_store;
		for(list<string>::iterator iter = queries->begin(); iter != queries->end(); ) {
			if(strncmp(iter->c_str(), "csv", 3) &&
			   iter->find(_MYSQL_QUERY_END_new) == string::npos) {
				queries_str_old_store += *iter;
				queries->erase(iter++);
				#if DEBUG_STORE_COUNT
				++_store_old_cnt[id_main * 100 + id_2];
				#endif
			} else {
				iter++;
			}
		}
		if(!queries_str_old_store.empty()) {
			__store(beginProcedure, endProcedure, queries_str_old_store);
		}
		if(queries->size()) {
			__store(queries);
		}
	} else {
		string queries_str;
		for(list<string>::iterator iter = queries->begin(); iter != queries->end(); iter++) {
			queries_str += *iter;
		}
		__store(beginProcedure, endProcedure, queries_str);
	}
	unsigned long endTimeMS = getTimeMS();
	SqlDb::addDelayQuery(endTimeMS - startTimeMS, SqlDb::_tq_store);
	if(sverb.store_process_query_compl_time) {
		sumTimeMS += (endTimeMS -startTimeMS);
		cout << "store_process_query_compl_" << this->id_main << "_" << this->id_2 << endl
		     << " * time " << (++counter) << " / " << (endTimeMS-startTimeMS)/1000. << " / " << sumTimeMS/1000. << " size: " << queries_size << endl;
	}
}

void MySqlStore_process::__store(list<string> *queries) {
	SqlDb::addCountInsert(queries->size());
	if(this->parentStore->isCloud() && useNewStore()) {
		string queries_str;
		for(list<string>::iterator iter = queries->begin(); iter != queries->end(); iter++) {
			queries_str += ":" + intToString(iter->length()) + ":";
			queries_str += *iter;
		}
		this->sqlDb->query("store"  + queries_str);
		return;
	}
	string queries_str;
	list<string> queries_list;
	list<string> ig;
	__store_prepare_queries(queries, dbData, dbCalls, NULL,
				&queries_str, &queries_list, NULL,
				useNewStore(), useSetId(), opt_mysql_enable_multiple_rows_insert,
				this->sqlDb->maxAllowedPacket);
	if(useNewStore() == 2) {
		if(sverb.store_process_query_compl) {
			cout << "store_process_query_compl_" << this->id_main << "_" << this->id_2 << endl;
		}
		if(id_main == STORE_PROC_ID_CDR && opt_mysql_redirect_cdr_queue) {
			extern MySqlStore *sqlStore;
			if(!sqlStore || opt_mysql_redirect_cdr_queue == 2) {
				parentStore->query_lock(&queries_list, STORE_PROC_ID_CDR_REDIRECT, 
							parentStore->findMinId2(STORE_PROC_ID_CDR_REDIRECT, false),
							100);
			} else {
				if(sqlStore->qfileConfigEnable(STORE_PROC_ID_CDR_REDIRECT)) {
					sqlStore->query_lock(&queries_list, STORE_PROC_ID_CDR_REDIRECT, 0);
				} else {
					sqlStore->query_lock(&queries_list, STORE_PROC_ID_CDR_REDIRECT, 
							     sqlStore->findMinId2(STORE_PROC_ID_CDR_REDIRECT, false),
							     100);
				}
			}
		} else {
			for(list<string>::iterator iter = queries_list.begin(); iter != queries_list.end(); iter++) {
				#if TEST_SERVER_STORE_SPEED
				SqlDb::addDelayQuery(10);
				#else
				this->sqlDb->query(*iter);
				#endif
			}
		}
	} else {
		if(sverb.store_process_query_compl) {
			cout << "store_process_query_compl_" << this->id_main << "_" << this->id_2 << endl
			     << queries_str << endl;
		}
		this->sqlDb->query(string("call store_001(\"") + 
				   queries_str + "\",\"" + 
				   _MYSQL_QUERY_END_new + "\"," + 
				   (opt_mysql_enable_transactions || this->enableTransaction ? "true" : "false") +
				   ")");
	}
}

void MySqlStore_process::__store(string beginProcedure, string endProcedure, string &queries) {
	string procedureName = this->getInsertFuncName();
	int maxPassComplete = this->enableFixDeadlock ? 10 : 1;
	for(int passComplete = 0; passComplete < maxPassComplete; passComplete++) {
		string dropProcQuery = string("drop procedure if exists ") + procedureName;
		this->sqlDb->query(dropProcQuery.c_str());
		string preparedQueries = queries;
		::prepareQuery(this->sqlDb->getSubtypeDb(), preparedQueries, false, passComplete ? 2 : 1);
		bool rsltQuery = false;
		unsigned maxPassIfMissingQuery = 10;
		unsigned counterPassIfMissingQuery = 0;
		do {
			if(counterPassIfMissingQuery) {
				sleep(1);
			}
			++counterPassIfMissingQuery;
			if(this->sqlDb->query(string("create procedure ") + procedureName + "()" + 
					      beginProcedure + 
					      preparedQueries + 
					      endProcedure,
					      false,
					      dropProcQuery.c_str())) {
				rsltQuery = this->sqlDb->query(string("call ") + procedureName + "();", this->enableFixDeadlock);
			} else {
				rsltQuery = false;
			}
		} while(!rsltQuery && this->sqlDb->getLastError() == ER_SP_DOES_NOT_EXIST &&
			counterPassIfMissingQuery < maxPassIfMissingQuery);
		/* deadlock debugging
		rsltQuery = false;
		this->sqlDb->setLastError(ER_LOCK_DEADLOCK, "deadlock");
		*/
		if(rsltQuery) {
			break;
		} else if(this->sqlDb->getLastError() == ER_LOCK_DEADLOCK) {
			if(passComplete < maxPassComplete - 1) {
				syslog(LOG_INFO, "DEADLOCK in store %i_%i - next attempt %u", this->id_main, this->id_2, passComplete + 1);
				USLEEP(500000);
			}
		} else {
			if(sverb.store_process_query) {
				cout << "store_process_query_" << this->id_main << "_" << this->id_2 << ": " << "ERROR" << endl 
				     << this->sqlDb->getLastErrorString() << endl;
			}
			break;
		}
	}
}

void MySqlStore_process::exportToFile(FILE *file, bool sqlFormat, bool cleanAfterExport) {
	this->lock();
	string queryqueue;
	int concatLimit = this->concatLimit;
	int size = 0;
	for(size_t index = 0; index < this->query_buff.size(); index++) {
		string query = this->query_buff[index];
		if(sqlFormat) {
			::prepareQuery(this->sqlDb->getSubtypeDb(), query, true, 2);
			queryqueue.append(query);
			size_t query_len = query.length();
			while(query_len && query[query_len - 1] == ' ') {
				--query_len;
			}
			if(query_len && query[query_len - 1] != ';') {
				queryqueue.append("; ");
			}
			++size;
			if(size > concatLimit) {
				this->_exportToFileSqlFormat(file, queryqueue);
				size = 0;
				queryqueue = "";
			}
		} else {
			find_and_replace(query, "__ENDL__", "__endl__");
			find_and_replace(query, "\n", "__ENDL__");
			fprintf(file, "%i:%s\n", this->id_main, query.c_str());
		}
	}
	if(size) {
		this->_exportToFileSqlFormat(file, queryqueue);
	}
	if(cleanAfterExport) {
		this->query_buff.clear();
	}
	this->unlock();
}

void MySqlStore_process::_exportToFileSqlFormat(FILE *file, string queries) {
	string procedureName = this->getInsertFuncName() + "_export";
	fprintf(file, "drop procedure if exists %s;\n", procedureName.c_str());
	fputs("delimiter ;;\n", file);
	fprintf(file, "create procedure %s()\n", procedureName.c_str());
	fputs("begin\n", file);
	fputs(queries.c_str(), file);
	fputs("\nend\n"
	      ";;\n"
	      "delimiter ;\n", file);
	fprintf(file, "call %s();\n", procedureName.c_str());
}

void MySqlStore_process::setEnableTerminatingDirectly(bool enableTerminatingDirectly) {
	this->enableTerminatingDirectly = enableTerminatingDirectly;
}

void MySqlStore_process::setEnableTerminatingIfEmpty(bool enableTerminatingIfEmpty) {
	this->enableTerminatingIfEmpty = enableTerminatingIfEmpty;
}

void MySqlStore_process::setEnableTerminatingIfSqlError(bool enableTerminatingIfSqlError) {
	this->enableTerminatingIfSqlError = enableTerminatingIfSqlError;
}

void MySqlStore_process::setEnableAutoDisconnect(bool enableAutoDisconnect) {
	this->enableAutoDisconnect = enableAutoDisconnect;
}

void MySqlStore_process::setConcatLimit(int concatLimit) {
	this->concatLimit = concatLimit;
}

int MySqlStore_process::getConcatLimit() {
	return(this->concatLimit);
}

void MySqlStore_process::setEnableTransaction(bool enableTransaction) {
	this->enableTransaction = enableTransaction;
}

void MySqlStore_process::setEnableFixDeadlock(bool enableFixDeadlock) {
	this->enableFixDeadlock = enableFixDeadlock;
}

void MySqlStore_process::setQueryBuffLimit(int queryBuffLimit) {
	this->queryBuffLimit = queryBuffLimit;
}

void MySqlStore_process::waitForTerminate() {
	if(this->thread) {
		while(!this->terminated) {
			if(is_terminating() > 1 &&
			   getTimeS() > (this->last_store_iteration_time + 60)) {
				syslog(LOG_NOTICE, "cancel store thread id (%i_%i)", id_main, id_2);
				pthread_cancel(this->thread);
				break;
			}
			USLEEP(100000);
		}
		this->thread = (pthread_t)NULL;
	}
}

void MySqlStore_process::waitForFullQueue() {
	if(this->queryBuffLimit > 0) {
		while(this->query_buff.size() > (unsigned)this->queryBuffLimit && !is_terminating()) {
			usleep(1000);
		}
	}
}

string MySqlStore_process::getInsertFuncName() {
	char insert_funcname[20];
	snprintf(insert_funcname, sizeof(insert_funcname), "__insert_%i_%i", this->id_main, this->id_2);
	if(opt_id_sensor > -1) {
		snprintf(insert_funcname + strlen(insert_funcname), sizeof(insert_funcname) - strlen(insert_funcname), "S%i", opt_id_sensor);
	}
	return(insert_funcname);
}

string MySqlStore::QFileConfig::getDirectory() {
	return(this->directory.empty() ? getQueryCacheDir() : this->directory);
}

MySqlStore::MySqlStore(const char *host, const char *user, const char *password, const char *database, u_int16_t port, const char *socket,
		       const char *cloud_host, const char *cloud_token, bool cloud_router, mysqlSSLOptions *mySSLOpt) {
	this->host = host;
	this->user = user;
	this->password = password;
	this->database = database;
	this->port = port;
	this->socket = socket;
	this->mySSLOptions = mySSLOpt;
	if(cloud_host) {
		this->cloud_host = cloud_host;
	}
	if(cloud_token) {
		this->cloud_token = cloud_token;
	}
	this->cloud_router = cloud_router;
	this->defaultConcatLimit = 400;
	this->_sync_processes = 0;
	this->enableTerminatingDirectly = false;
	this->enableTerminatingIfEmpty = false;
	this->enableTerminatingIfSqlError = false;
	this->_sync_qfiles = 0;
	this->qfilesCheckperiodThread = 0;
	this->qfilesINotifyThread = 0;
}

MySqlStore::~MySqlStore() {
	map<int, map<int, MySqlStore_process*> >::iterator iter1;
	map<int, MySqlStore_process*>::iterator iter2;
	for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
		for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
			iter2->second->setEnableTerminatingIfEmpty(true);
			iter2->second->waitForTerminate();
		}
	}
	if(!qfileConfig.enable && !loadFromQFileConfig.enable) {
		extern bool opt_autoload_from_sqlvmexport;
		if(opt_autoload_from_sqlvmexport &&
		   this->getAllSize() &&
		   !is_read_from_file()) {
			extern MySqlStore *sqlStore;
			sqlStore->exportToFile(NULL, "auto", false, true);
		}
	}
	for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
		for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
			delete iter2->second;
		}
	}
	if(qfileConfig.enableAny()) {
		if(this->qfilesCheckperiodThread) {
			pthread_join(this->qfilesCheckperiodThread, NULL);
		}
		closeAllQFiles();
		clearAllQFiles();
	}
	if(loadFromQFileConfig.enableAny()) {
		for(map<int, LoadFromQFilesThreadData>::iterator iter = loadFromQFilesThreadData.begin(); iter != loadFromQFilesThreadData.end(); iter++) {
			if(iter->second.thread) {
				pthread_join(iter->second.thread, NULL);
			}
		}
	}
}

void MySqlStore::queryToFiles(bool enable, const char *directory, int period, 
			      bool enable_charts, bool enable_charts_remote) {
	qfileConfig.enable = enable;
	qfileConfig.enable_charts = enable_charts;
	qfileConfig.enable_charts_remote = enable_charts_remote;
	if(directory) {
		qfileConfig.directory = directory;
	}
	if(period) {
		qfileConfig.period = period;
	}
}

void MySqlStore::queryToFilesTerminate() {
	if(qfileConfig.enableAny()) {
		qfileConfig.terminate = true;
		USLEEP(250000);
		closeAllQFiles();
		clearAllQFiles();
	}
}

void MySqlStore::queryToFiles_start() {
	if(qfileConfig.enableAny()) {
		vm_pthread_create("query cache - check",
				  &this->qfilesCheckperiodThread, NULL, this->threadQFilesCheckPeriod, this, __FILE__, __LINE__);
	}
}

void MySqlStore::loadFromQFiles(bool enable, const char *directory, int period,
				bool enable_charts, bool enable_charts_remote) {
	loadFromQFileConfig.enable = enable;
	loadFromQFileConfig.enable_charts = enable_charts;
	loadFromQFileConfig.enable_charts_remote = enable_charts_remote;
	if(directory) {
		loadFromQFileConfig.directory = directory;
	}
	if(period) {
		loadFromQFileConfig.period = period;
	}
}

void MySqlStore::loadFromQFiles_start() {
	extern bool opt_load_query_from_files_inotify;
	if(loadFromQFileConfig.enableAny()) {
		if(opt_load_query_from_files_inotify) {
			this->enableInotifyForLoadFromQFile();
		}
	}
	if(loadFromQFileConfig.enable) {
		if(!isCloud()) {
			extern MySqlStore *sqlStore_2;
			this->addLoadFromQFile(STORE_PROC_ID_CDR, "cdr");
			this->addLoadFromQFile(STORE_PROC_ID_CDR_REDIRECT, "cdr_redir");
			this->addLoadFromQFile(STORE_PROC_ID_MESSAGE, "message");
			this->addLoadFromQFile(STORE_PROC_ID_SIP_MSG, "sip_msg");
			this->addLoadFromQFile(STORE_PROC_ID_CLEANSPOOL, "cleanspool");
			this->addLoadFromQFile(STORE_PROC_ID_REGISTER, "register");
			//this->addLoadFromQFile(STORE_PROC_ID_SAVE_PACKET_SQL, "save_packet_sql"); // disable query_cache for live sniffer
			this->addLoadFromQFile(STORE_PROC_ID_HTTP, "http", 0, 0,
					       use_mysql_2_http() ? sqlStore_2 : NULL);
			this->addLoadFromQFile(STORE_PROC_ID_WEBRTC, "webrtc");
			this->addLoadFromQFile(STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS, "cache_numbers");
			this->addLoadFromQFile(STORE_PROC_ID_FRAUD_ALERT_INFO, "fraud_alert_info");
			this->addLoadFromQFile(STORE_PROC_ID_LOG_SENSOR, "log_sensor");
			this->addLoadFromQFile(STORE_PROC_ID_SS7, "ss7");
			this->addLoadFromQFile(STORE_PROC_ID_OTHER, "other");
			if(opt_ipaccount) {
				this->addLoadFromQFile(STORE_PROC_ID_IPACC, "ipacc");
				this->addLoadFromQFile(STORE_PROC_ID_IPACC_AGR_INTERVAL, "ipacc_agreg");
				this->addLoadFromQFile(STORE_PROC_ID_IPACC_AGR_HOUR, "ipacc_agreg_hour");
				this->addLoadFromQFile(STORE_PROC_ID_IPACC_AGR_DAY, "ipacc_agreg_day");
				this->addLoadFromQFile(STORE_PROC_ID_IPACC_AGR2_HOUR, "ipacc_agreg2");
			}
		} else {
			extern int opt_mysqlstore_concat_limit_cdr;
			this->addLoadFromQFile(1, "cloud", 1, opt_mysqlstore_concat_limit_cdr);
		}
	}
	if(loadFromQFileConfig.enable_charts) {
		if(!isCloud()) {
			this->addLoadFromQFile(STORE_PROC_ID_CHARTS_CACHE, "charts_cache");
		}
	}
	if(loadFromQFileConfig.enable_charts_remote) {
		if(!isCloud()) {
			this->addLoadFromQFile(STORE_PROC_ID_CHARTS_CACHE_REMOTE, "charts_cache_remote");
		}
	}
	if(loadFromQFileConfig.enableAny()) {
		if(opt_load_query_from_files_inotify) {
			this->setInotifyReadyForLoadFromQFile();
		}
	}
}

void MySqlStore::connect(int id_main, int id_2) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->connect();
}

void MySqlStore::query(const char *query_str, int id_main, int id_2) {
	if(!query_str || !*query_str) {
		return;
	}
	if(qfileConfigEnable(id_main)) {
		query_to_file(query_str, id_main);
	} else {
		MySqlStore_process* process = this->find(id_main, id_2);
		process->query(query_str);
	}
}

void MySqlStore::query(string query_str, int id_main, int id_2) {
	query(query_str.c_str(), id_main, id_2);
}

void MySqlStore::query_lock(const char *query_str, int id_main, int id_2) {
	if(!query_str || !*query_str) {
		return;
	}
	if(qfileConfigEnable(id_main)) {
		query_to_file(query_str, id_main);
	} else {
		MySqlStore_process* process = this->find(id_main, id_2);
		process->lock();
		#if DEBUG_STORE_COUNT
		++_query_lock_cnt[id_main * 100 + id_2];
		#endif
		for(int i = 0; i < max(sverb.multiple_store && id_main != 99 ? sverb.multiple_store : 0, 1); i++) {
			process->query(query_str);
		}
		process->unlock();
	}
}

void MySqlStore::query_lock(list<string> *query_str, int id_main, int id_2, int change_id_2_after) {
	if(!query_str->size()) {
		return;
	}
	if(qfileConfigEnable(id_main)) {
		for(list<string>::iterator iter = query_str->begin(); iter != query_str->end(); iter++) {
			query_to_file(iter->c_str(), id_main);
		}
	} else {
		MySqlStore_process* process = this->find(id_main, id_2);
		process->waitForFullQueue();
		process->lock();
		unsigned counter = 0;
		for(list<string>::iterator iter = query_str->begin(); iter != query_str->end(); iter++) {
			if(counter && change_id_2_after && !(counter % change_id_2_after)) {
				process->unlock();
				id_2 = findMinId2(id_main, false);
				process->lock();
			}
			for(int i = 0; i < max(sverb.multiple_store && id_main != 99 ? sverb.multiple_store : 0, 1); i++) {
				process->query(iter->c_str());
			}
			++counter;
		}
		process->unlock();
	}
}

void MySqlStore::query_lock(string query_str, int id_main, int id_2) {
	query_lock(query_str.c_str(), id_main, id_2);
}

void MySqlStore::query_to_file(const char *query_str, int id_main) {
	if(qfileConfig.terminate) {
		return;
	}
	int idc = !isCloud() ? id_main : 1;
	QFile *qfile;
	lock_qfiles();
	if(qfiles.find(idc) == qfiles.end()) {
		qfile = new FILE_LINE(29004) QFile;
		qfiles[idc] = qfile;
	} else {
		qfile = qfiles[idc];
	}
	unlock_qfiles();
	qfile->lock();
	#if DEBUG_STORE_COUNT
	++_query_to_file_cnt[id_main];
	#endif
	if(qfile->isOpen() &&
	   qfile->isExceedPeriod(qfileConfig.period)) {
		if(sverb.qfiles) {
			cout << "*** CLOSE QFILE " << qfile->filename 
			     << " - time: " << sqlDateTimeString(time(NULL)) 
			     << " / lines: " << qfile->_lines
			     << endl;
		}
		qfile->close();
	}
	if(!qfile->isOpen()) {
		u_int64_t actTime = getTimeMS();
		string qfilename = getQFilename(idc, actTime);
		qfile->_lines = 0;
		if(qfile->open(qfilename.c_str(), actTime)) {
			if(sverb.qfiles) {
				cout << "*** OPEN QFILE " << qfile->filename 
				     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
			}
		} else {
			syslog(LOG_ERR, "failed create file %s in function MySqlStore::getQFile", qfilename.c_str());
		}
	}
	if(qfile->fileZipHandler) {
		string query = query_str;
		find_and_replace(query, "__ENDL__", "__endl__");
		find_and_replace(query, "\n", "__ENDL__");
		unsigned int query_length = query.length();
		query.append("\n");
		char buffIdLength[100];
		snprintf(buffIdLength, sizeof(buffIdLength), "%i/%u:", id_main, query_length);
		qfile->fileZipHandler->write(buffIdLength, strlen(buffIdLength));
		qfile->fileZipHandler->write((char*)query.c_str(), query.length());
		u_int64_t actTimeMS = getTimeMS();
		if(max(qfile->flushAt, qfile->createAt) < actTimeMS - 1000) {
			qfile->fileZipHandler->flushBuffer();
			qfile->flushAt = actTimeMS;
		}
		++qfile->_lines;
	}
	qfile->unlock();
}

string MySqlStore::getQFilename(int idc, u_int64_t actTime) {
	char fileName[100];
	string dateTime = sqlDateTimeString(actTime / 1000).c_str();
	find_and_replace(dateTime, " ", "T");
	snprintf(fileName, sizeof(fileName), "%s-%i-%" int_64_format_prefix "lu-%s", QFILE_PREFIX, idc, actTime, dateTime.c_str());
	return(qfileConfig.getDirectory() + "/" + fileName);
}

bool MySqlStore::existFilenameInQFiles(const char *filename) {
	bool exists = false;
	lock_qfiles();
	for(map<int, QFile*>::iterator iter = qfiles.begin(); iter != qfiles.end(); iter++) {
		iter->second->lock();
		if(filename == iter->second->filename) {
			exists = true;
		}
		iter->second->unlock();
		if(exists) {
			break;
		}
	}
	unlock_qfiles();
	return(exists);
}

void MySqlStore::closeAllQFiles() {
	lock_qfiles();
	for(map<int, QFile*>::iterator iter = qfiles.begin(); iter != qfiles.end(); iter++) {
		iter->second->lock();
		if(iter->second->fileZipHandler) {
			if(sverb.qfiles) {
				cout << "*** CLOSE QFILE FROM FUNCTION MySqlStore::closeAllQFiles " << iter->second->filename
				     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
			}
			iter->second->close();
		}
		iter->second->unlock();
	}
	unlock_qfiles();
}

void MySqlStore::clearAllQFiles() {
	lock_qfiles();
	for(map<int, QFile*>::iterator iter = qfiles.begin(); iter != qfiles.end();) {
		iter->second->lock();
		delete iter->second;
		qfiles.erase(iter++);
	}
	unlock_qfiles();
}

void MySqlStore::enableInotifyForLoadFromQFile(bool enableINotify) {
#ifndef FREEBSD
	loadFromQFileConfig.inotify = enableINotify;
	if(loadFromQFileConfig.enableAny() && loadFromQFileConfig.inotify) {
		vm_pthread_create("query cache - inotify",
				  &this->qfilesINotifyThread, NULL, this->threadINotifyQFiles, this, __FILE__, __LINE__);
	}
#endif
}

void MySqlStore::setInotifyReadyForLoadFromQFile(bool iNotifyReady) {
	if(loadFromQFileConfig.enableAny() && loadFromQFileConfig.inotify) {
		loadFromQFileConfig.inotify_ready = iNotifyReady;
	}
}

void MySqlStore::addLoadFromQFile(int id_main, const char *name, 
				  int storeThreads, int storeConcatLimit,
				  MySqlStore *store) {
	LoadFromQFilesThreadData threadData;
	threadData.id_main = id_main;
	threadData.name = name;
	threadData.storeThreads = storeThreads > 0 ? storeThreads : getMaxThreadsForStoreId(id_main);
	threadData.storeThreadsSet = storeThreads > 0 ? true : isSetMaxThreadsForStoreId(id_main);
	threadData.storeConcatLimit = storeConcatLimit > 0 ? storeConcatLimit : getConcatLimitForStoreId(id_main);
	threadData.store = store;
	loadFromQFilesThreadData[id_main] = threadData;
	LoadFromQFilesThreadInfo *threadInfo = new FILE_LINE(29005) LoadFromQFilesThreadInfo;
	threadInfo->store = this;
	threadInfo->id_main = id_main;
	vm_pthread_create(("query cache - load " + intToString(id_main)).c_str(),
			  &loadFromQFilesThreadData[id_main].thread, NULL, this->threadLoadFromQFiles, threadInfo, __FILE__, __LINE__);
}

bool MySqlStore::fillQFiles(int id_main) {
	DIR* dp = opendir(loadFromQFileConfig.getDirectory().c_str());
	if(!dp) {
		return(false);
	}
	char prefix[10];
	snprintf(prefix, sizeof(prefix), "%s-%i-", QFILE_PREFIX, id_main);
	dirent* de;
	while((de = readdir(dp)) != NULL) {
		if(strncmp(de->d_name, prefix, strlen(prefix))) continue;
		QFileData qfileData = parseQFilename(de->d_name);
		if(qfileData.id_main) {
			loadFromQFilesThreadData[qfileData.id_main].addFile(qfileData.time, de->d_name);
		}
	}
	closedir(dp);
	return(true);
}

string MySqlStore::getMinQFile(int id_main) {
	if(loadFromQFileConfig.inotify) {
		string qfilename;
		loadFromQFilesThreadData[id_main].lock();
		map<u_int64_t, string>::iterator iter = loadFromQFilesThreadData[id_main].qfiles_load.begin();
		if(iter != loadFromQFilesThreadData[id_main].qfiles_load.end() &&
		   (getTimeMS() - iter->first) > (unsigned)loadFromQFileConfig.period * 2 * 1000) {
			qfilename = iter->second;
			loadFromQFilesThreadData[id_main].qfiles_load.erase(iter);
		}
		loadFromQFilesThreadData[id_main].unlock();
		if(!qfilename.empty()) {
			return(loadFromQFileConfig.getDirectory() + "/" + qfilename);
		}
	} else {
		DIR* dp = opendir(loadFromQFileConfig.getDirectory().c_str());
		if(!dp) {
			return("");
		}
		u_int64_t minTime = 0;
		string minTimeFileName;
		char prefix[10];
		snprintf(prefix, sizeof(prefix), "%s-%i-", QFILE_PREFIX, id_main);
		dirent* de;
		while((de = readdir(dp)) != NULL) {
			if(strncmp(de->d_name, prefix, strlen(prefix))) continue;
			u_int64_t time = atoll(de->d_name + strlen(prefix));
			if(!minTime || time < minTime) {
				minTime = time;
				minTimeFileName = de->d_name;
			}
		}
		closedir(dp);
		if(minTime &&
		   (getTimeMS() - minTime) > (unsigned)loadFromQFileConfig.period * 2 * 1000) {
			return(loadFromQFileConfig.getDirectory() + "/" + minTimeFileName);
		}
	}
	return("");
}

int MySqlStore::getCountQFiles(int id_main) {
	DIR* dp = opendir(loadFromQFileConfig.getDirectory().c_str());
	if(!dp) {
		return(-1);
	}
	char prefix[10];
	snprintf(prefix, sizeof(prefix), "%s-%i-", QFILE_PREFIX, id_main);
	dirent* de;
	int counter = 0;
	while((de = readdir(dp)) != NULL) {
		if(strncmp(de->d_name, prefix, strlen(prefix))) continue;
		++counter;
	}
	closedir(dp);
	return(counter);
}

bool MySqlStore::loadFromQFile(const char *filename, int id_main, bool onlyCheck) {
	bool ok = true;
	unsigned _lines = 0;
	if(sverb.qfiles) {
		cout << "*** START " << (onlyCheck ? "CHECK" : "PROCESS") << " FILE " << filename
		     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
	}
	#if TEST_SERVER_STORE_SPEED
	do {
	#endif
	FileZipHandler *fileZipHandler = new FILE_LINE(29006) FileZipHandler(8 * 1024, 0, isGunzip(filename) ? FileZipHandler::gzip : FileZipHandler::compress_na);
	fileZipHandler->open(tsf_na, filename);
	bool copyBadFileToTemp = false;
	while(!fileZipHandler->is_eof() && fileZipHandler->is_ok_decompress() && fileZipHandler->read(8 * 1024)) {
		string lineQuery;
		while(fileZipHandler->getLineFromReadBuffer(&lineQuery)) {
			char *buffLineQuery = (char*)lineQuery.c_str();
			unsigned int buffLineQueryLength = lineQuery.length();
			if(buffLineQuery[buffLineQueryLength - 1] == '\n') {
				buffLineQuery[buffLineQueryLength - 1] = 0;
			}
			int idQueryProcess;
			unsigned int queryLength;
			char *posSeparator = strchr(buffLineQuery, ':');
			if(!posSeparator ||
			   sscanf(buffLineQuery, "%i/%u:", &idQueryProcess, &queryLength) != 2 ||
			   !idQueryProcess ||
			   !queryLength) {
				if(sverb.qfiles) {
					syslog(LOG_ERR, "bad string in qfile %s: %s", filename, buffLineQuery);
				}
				ok = false;
				continue;
			}
			if(queryLength != strlen(posSeparator + 1)) {
				if(sverb.qfiles) {
					syslog(LOG_ERR, "bad query length in qfile %s: %s", filename, buffLineQuery);
				}
				if(sverb.qfiles && !copyBadFileToTemp) {
					char *baseFileName = (char*)strrchr(filename, '/');
					copy_file(filename, (string("/tmp") + baseFileName).c_str());
					copyBadFileToTemp = true;
				}
				ok = false;
				continue;
			}
			#if DEBUG_STORE_COUNT
			++_loadFromQFile_cnt[id_main];
			#endif
			++_lines;
			if(!onlyCheck) {
				string query = find_and_replace(posSeparator + 1, "__ENDL__", "\n");
				int first_thread_qtSize = 0;
				bool next_threads_exists = false;
				bool next_threads_filled = false;
				int next_threads_limit = 100;
				int id_2 = 0;
				ssize_t id_2_minSize = -1;
				for(int i = 0; i < loadFromQFilesThreadData[id_main].storeThreads; i++) {
					int qtSize = this->getSize(id_main, i);
					if(i == 0) {
						first_thread_qtSize = qtSize;
					} else {
						if(qtSize >= 0) {
							next_threads_exists = true;
							if(qtSize > 0) {
								next_threads_filled = true;
							}
						}
					}
					if(qtSize < 0) {
						qtSize = 0;
					}
					if(id_2_minSize == -1 || qtSize < id_2_minSize) {
						id_2 = i;
						id_2_minSize = qtSize;
					}
				}
				if(id_2 && !loadFromQFilesThreadData[id_main].storeThreadsSet &&
				   first_thread_qtSize < next_threads_limit && (!next_threads_exists || !next_threads_filled)) {
					id_2 = 0;
				}
				if(!check(id_main, id_2)) {
					find(id_main, id_2, loadFromQFilesThreadData[id_main].store);
					setEnableTerminatingIfEmpty(id_main, id_2, true);
					setEnableTerminatingIfSqlError(id_main, id_2, true);
					if(loadFromQFilesThreadData[id_main].storeConcatLimit) {
						setConcatLimit(id_main, id_2, loadFromQFilesThreadData[id_main].storeConcatLimit);
					}
				}
				/*if(sverb.qfiles) {
					cout << " ** send query id: " << id_main << " to thread: " << id_main << "_" << id_2 << " / " << getSize(id_main, id_2) << endl;
				}*/
				extern int opt_query_cache_check_utf;
				extern int opt_query_cache_max_mb_utf;
				if(opt_query_cache_check_utf || opt_query_cache_max_mb_utf) {
					extern cUtfConverter utfConverter;
					if(!utfConverter.check2(query.c_str())) {
						query = utfConverter.replace_exceeding_utf8_mb(query.c_str(), 1);
					} else if(opt_query_cache_max_mb_utf && utfConverter.get_max_mb(query.c_str()) > opt_query_cache_max_mb_utf) {
						query = utfConverter.replace_exceeding_utf8_mb(query.c_str(), opt_query_cache_max_mb_utf);
					}
				}
				query_lock(query.c_str(), id_main, id_2);
			}
		}
	}
	if(!fileZipHandler->is_ok_decompress()) {
		syslog(LOG_ERR, "decompress error in qfile: %s / lines: %u", filename, _lines);
	}
	fileZipHandler->close();
	delete fileZipHandler;
	#if TEST_SERVER_STORE_SPEED
	} while(true);
	#endif
	if(!onlyCheck) {
		if(!sverb.disable_unlink_qfile) {
			unlink(filename);
		}
		//rename(filename, find_and_replace(filename, "qoq", "_qoq").c_str());
	}
	if(sverb.qfiles) {
		cout << "*** END " << (onlyCheck ? "CHECK" : "PROCESS") << " FILE " << filename
		     << " - time: " << sqlDateTimeString(time(NULL)) 
		     << " / lines: " << _lines 
		     << endl;
	}
	return(ok);
}

void MySqlStore::addFileFromINotify(const char *filename) {
	while(!loadFromQFileConfig.inotify_ready) {
		USLEEP(100000);
	}
	QFileData qfileData = parseQFilename(filename);
	if(qfileData.id_main) {
		if(sverb.qfiles) {
			cout << "*** INOTIFY QFILE " << filename 
			     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
		}
		loadFromQFilesThreadData[qfileData.id_main].addFile(qfileData.time, qfileData.filename.c_str());
	}
}

MySqlStore::QFileData MySqlStore::parseQFilename(const char *filename) {
	QFileData qfileData;
	qfileData.id_main = 0;
	qfileData.time = 0;
	if(!strncmp(filename, QFILE_PREFIX, strlen(QFILE_PREFIX))) {
		int id_main;
		u_int64_t time;
		if(sscanf(filename + strlen(QFILE_PREFIX) , "-%i-%" int_64_format_prefix "lu", &id_main, &time) == 2) {
			qfileData.filename = filename;
			qfileData.id_main = id_main;
			qfileData.time = time;
		}
	}
	return(qfileData);
}

string MySqlStore::getLoadFromQFilesStat(bool processes) {
	ostringstream outStr;
	outStr << fixed;
	int counter = 0;
	if(!processes) {
		for(map<int, LoadFromQFilesThreadData>::iterator iter = loadFromQFilesThreadData.begin(); iter != loadFromQFilesThreadData.end(); iter++) {
			int countQFiles = getCountQFiles(iter->second.id_main);
			if(countQFiles > 0) {
				if(counter) {
					outStr << ", ";
				}
				outStr << iter->second.name << ": " << countQFiles;
				++counter;
			}
		}
	} else {
		map<int, map<int, MySqlStore_process*> >::iterator iter1;
		map<int, MySqlStore_process*>::iterator iter2;
		for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
			for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
				size_t size = iter2->second->getSize();
				if(size > 0) {
					if(counter) {
						outStr << ",";
					}
					outStr << iter1->first << "_" << iter2->first << ":" << size;
					++counter;
				}
			}
		}
	}
	return(outStr.str());
}

unsigned MySqlStore::getLoadFromQFilesCount() {
	unsigned count = 0;
	for(map<int, LoadFromQFilesThreadData>::iterator iter = loadFromQFilesThreadData.begin(); iter != loadFromQFilesThreadData.end(); iter++) {
		count += getCountQFiles(iter->second.id_main);
	}
	return(count);
}

void MySqlStore::lock(int id_main, int id_2) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->lock();
}

void MySqlStore::unlock(int id_main, int id_2) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->unlock();
}

void MySqlStore::setEnableTerminatingDirectly(int id_main, int id_2, bool enableTerminatingDirectly) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	if(id_main > 0) {
		MySqlStore_process* process = this->find(id_main, id_2);
		process->setEnableTerminatingDirectly(enableTerminatingDirectly);
	} else {
		this->lock_processes();
		map<int, map<int, MySqlStore_process*> >::iterator iter1;
		map<int, MySqlStore_process*>::iterator iter2;
		for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
			for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
				iter2->second->setEnableTerminatingDirectly(enableTerminatingDirectly);
			}
		}
		this->unlock_processes();
	}
}

void MySqlStore::setEnableTerminatingIfEmpty(int id_main, int id_2, bool enableTerminatingIfEmpty) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	if(id_main > 0) {
		MySqlStore_process* process = this->find(id_main, id_2);
		process->setEnableTerminatingIfEmpty(enableTerminatingIfEmpty);
	} else {
		this->lock_processes();
		map<int, map<int, MySqlStore_process*> >::iterator iter1;
		map<int, MySqlStore_process*>::iterator iter2;
		for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
			for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
				iter2->second->setEnableTerminatingIfEmpty(enableTerminatingIfEmpty);
			}
		}
		this->unlock_processes();
	}
}

void MySqlStore::setEnableTerminatingIfSqlError(int id_main, int id_2, bool enableTerminatingIfSqlError) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	if(id_main > 0) {
		MySqlStore_process* process = this->find(id_main, id_2);
		process->setEnableTerminatingIfSqlError(enableTerminatingIfSqlError);
	} else {
		this->lock_processes();
		map<int, map<int, MySqlStore_process*> >::iterator iter1;
		map<int, MySqlStore_process*>::iterator iter2;
		for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
			for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
				iter2->second->setEnableTerminatingIfSqlError(enableTerminatingIfSqlError);
			}
		}
		this->unlock_processes();
	}
}

void MySqlStore::setEnableAutoDisconnect(int id_main, int id_2, bool enableAutoDisconnect) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->setEnableAutoDisconnect(enableAutoDisconnect);
}

void MySqlStore::setConcatLimit(int id_main, int id_2, int concatLimit) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->setConcatLimit(concatLimit);
}

int MySqlStore::getConcatLimit(int id_main, int id_2) {
	MySqlStore_process* process = this->find(id_main, id_2);
	if(id_2 == -1 && !process) {
		return(0);
	}
	return(process->getConcatLimit());
}

void MySqlStore::setEnableTransaction(int id_main, int id_2, bool enableTransaction) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->setEnableTransaction(enableTransaction);
}

void MySqlStore::setEnableFixDeadlock(int id_main, int id_2, bool enableFixDeadlock) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->setEnableFixDeadlock(enableFixDeadlock);
}

void MySqlStore::setQueryBuffLimit(int id_main, int id_2, int queryBuffLimit) {
	if(qfileConfigEnable(id_main)) {
		return;
	}
	MySqlStore_process* process = this->find(id_main, id_2);
	process->setQueryBuffLimit(queryBuffLimit);
}

void MySqlStore::setDefaultConcatLimit(int defaultConcatLimit) {
	this->defaultConcatLimit = defaultConcatLimit;
}

MySqlStore_process *MySqlStore::find(int id_main, int id_2, MySqlStore *store) {
	if(isCloud()) {
		id_main = 1;
		if(id_2 >= 0) {
			id_2 = 0;
		}
	}
	this->lock_processes();
	if(id_2 == -1) {
		MySqlStore_process* process = NULL;
		map<int, map<int, MySqlStore_process*> >::iterator iter = this->processes.find(id_main);
		if(iter != this->processes.end()) {
			if(iter->second.begin() != iter->second.end()) {
				process = iter->second.begin()->second;
			}
		}
		this->unlock_processes();
		return(process);
	}
	MySqlStore_process* process = this->processes[id_main][id_2];
	if(process) {
		this->unlock_processes();
		return(process);
	}
	process = new FILE_LINE(29007) MySqlStore_process(
						id_main, id_2, store ? store : this,
						store ? store->host.c_str() : this->host.c_str(), 
						store ? store->user.c_str() : this->user.c_str(), 
						store ? store->password.c_str() : this->password.c_str(), 
						store ? store->database.c_str() : this->database.c_str(),
						store ? store->port : this->port,
						store ? store->socket.c_str() : this->socket.c_str(),
						this->isCloud() ? this->cloud_host.c_str() : NULL, this->cloud_token.c_str(), this->cloud_router,
						this->defaultConcatLimit,
						store ? store->mySSLOptions : this->mySSLOptions);
	process->setEnableTerminatingDirectly(this->enableTerminatingDirectly);
	process->setEnableTerminatingIfEmpty(this->enableTerminatingIfEmpty);
	process->setEnableTerminatingIfSqlError(this->enableTerminatingIfSqlError);
	this->processes[id_main][id_2] = process;
	this->unlock_processes();
	return(process);
}

MySqlStore_process *MySqlStore::check(int id_main, int id_2) {
	if(isCloud()) {
		id_main = 1;
		id_2 = 0;
	}
	this->lock_processes();
	map<int, map<int, MySqlStore_process*> >::iterator iter1 = this->processes.find(id_main);
	if(iter1 == this->processes.end()) {
		this->unlock_processes();
		return(NULL);
	}
	map<int, MySqlStore_process*>::iterator iter2 = iter1->second.find(id_2);
	if(iter2 == iter1->second.end()) {
		this->unlock_processes();
		return(NULL);
	}
	MySqlStore_process* process = iter2->second;
	this->unlock_processes();
	return(process);
}

size_t MySqlStore::getAllSize(bool lock, bool redirect) {
	size_t size = 0;
	map<int, MySqlStore_process*>::iterator iter;
	this->lock_processes();
	map<int, map<int, MySqlStore_process*> >::iterator iter1;
	map<int, MySqlStore_process*>::iterator iter2;
	for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
		if(!redirect || this->isRedirectStoreId(iter1->first)) {
			for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
				if(lock) {
					iter2->second->lock();
				}
				size += iter2->second->getSize();
				if(lock) {
					iter2->second->unlock();
				}
			}
		}
	}
	this->unlock_processes();
	return(size);
}

size_t MySqlStore::getAllRedirectSize(bool lock) {
	return(getAllSize(lock, true));
}

int MySqlStore::getSize(int id_main, int id_2, bool lock) {
	if(id_2 == -1) {
		int size = -1;
		if(lock) {
			this->lock_processes();
		}
		map<int, map<int, MySqlStore_process*> >::iterator iter1 = this->processes.find(id_main);
		if(iter1 != this->processes.end()) {
			size = 0;
			map<int, MySqlStore_process*>::iterator iter2;
			for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
				if(lock) {
					iter2->second->lock();
				}
				size += iter2->second->getSize();
				if(lock) {
					iter2->second->unlock();
				}
			}
		}
		if(lock) {
			this->unlock_processes();
		}
		return(size);
	} else {
		MySqlStore_process *process = this->check(id_main, id_2);
		if(process) {
			if(lock) {
				process->lock();
			}
			int size = process->getSize();
			if(lock) {
				process->unlock();
			}
			return(size);
		}
	}
	return(-1);
}

int MySqlStore::getCountActive(int id_main, bool lock) {
	int count_active = -1;
	if(lock) {
		this->lock_processes();
	}
	map<int, map<int, MySqlStore_process*> >::iterator iter1 = this->processes.find(id_main);
	if(iter1 != this->processes.end()) {
		count_active = 0;
		map<int, MySqlStore_process*>::iterator iter2;
		for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
			if(lock) {
				iter2->second->lock();
			}
			if(iter2->second->getSize() > 0) {
				++count_active;
			}
			if(lock) {
				iter2->second->unlock();
			}
		}
	}
	if(lock) {
		this->unlock_processes();
	}
	return(count_active);
}

void MySqlStore::fillSizeMap(map<int, int> *size_map, map<int, int> *size_map_by_id_2, bool lock) {
	if(lock) {
		this->lock_processes();
	}
	map<int, map<int, MySqlStore_process*> >::iterator iter1;
	map<int, MySqlStore_process*>::iterator iter2;
	for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
		for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
			size_t size = iter2->second->getSize();
			if(size > 0) {
				if(size_map) {
					(*size_map)[iter1->first] += size;
				}
				if(size_map_by_id_2) {
					(*size_map_by_id_2)[iter1->first * 100 + iter2->first] += size;
				}
			}
		}
	}
	if(lock) {
		this->unlock_processes();
	}
}

string MySqlStore::exportToFile(FILE *file, string fileName, bool sqlFormat, bool cleanAfterExport) {
	bool openFile = false;
	if(!file) {
		if(fileName == "auto") {
			fileName = getSqlVmExportDirectory() + "/" +
				   (sqlFormat ? "export_voipmonitor_sql-" : "export_voipmonitor_queries-") + sqlDateTimeString(time(NULL));
		}
		file = fopen(fileName.c_str(), "wt");
		openFile = true;
	}
	if(!openFile) {
		return("exportToFile : failed open file " + fileName);
	}
	fputs("SET NAMES UTF8;\n", file);
	fprintf(file, "USE %s;\n", mysql_database);
	this->lock_processes();
	map<int, map<int, MySqlStore_process*> >::iterator iter1;
	map<int, MySqlStore_process*>::iterator iter2;
	for(iter1 = this->processes.begin(); iter1 != this->processes.end(); ++iter1) {
		for(iter2 = iter1->second.begin(); iter2 != iter1->second.end(); ++iter2) {
			iter2->second->exportToFile(file, sqlFormat, cleanAfterExport);
		}
	}
	this->unlock_processes();
	if(openFile) {
		fclose(file);
	}
	return(openFile ? "ok write to " + fileName : "ok write");
}

void MySqlStore::autoloadFromSqlVmExport() {
	DIR* dirstream = opendir(getSqlVmExportDirectory().c_str());
	if(!dirstream) {
		return;
	}
	dirent* direntry;
	while((direntry = readdir(dirstream))) {
		const char *prefixSqlVmExport = "export_voipmonitor_queries-";
		if(strncmp(direntry->d_name, prefixSqlVmExport, strlen(prefixSqlVmExport))) {
			continue;
		}
		if(time(NULL) - stringToTime(direntry->d_name + strlen(prefixSqlVmExport)) < 3600) {
			syslog(LOG_NOTICE, "recovery queries from %s", direntry->d_name);
			FILE *file = fopen((getSqlVmExportDirectory() + "/" + direntry->d_name).c_str(), "rt");
			if(!file) {
				syslog(LOG_NOTICE, "failed open file %s", direntry->d_name);
				continue;
			}
			unsigned int counter = 0;
			unsigned int maxLengthQuery = 1000000;
			char *buffQuery = new FILE_LINE(29008) char[maxLengthQuery];
			while(fgets(buffQuery, maxLengthQuery, file)) {
				int idProcess = atoi(buffQuery);
				if(!idProcess) {
					continue;
				}
				char *posSeparator = strchr(buffQuery, ':');
				if(!posSeparator) {
					continue;
				}
				string query = find_and_replace(posSeparator + 1, "__ENDL__", "\n");
				this->query(query.c_str(), idProcess, 0);
				++counter;
			}
			delete [] buffQuery;
			fclose(file);
			unlink((getSqlVmExportDirectory() + "/" + direntry->d_name).c_str());
			syslog(LOG_NOTICE, "success recovery %u queries", counter);
		}
	}
	closedir(dirstream);
}

string MySqlStore::getSqlVmExportDirectory() {
	return(getSqlVmExportDir());
}

int MySqlStore::findMinId2(int id_main, bool lock) {
	int id_2 = 0;
	int maxThreads = getMaxThreadsForStoreId(id_main);
	if(maxThreads > 1) {
		ssize_t id_2_minSize = -1;
		for(int i = 0; i < maxThreads; i++) {
			int qtSize = this->getSize(id_main, i, lock);
			if(qtSize < 0) {
				qtSize = 0;
			}
			if(id_2_minSize == -1 || qtSize < id_2_minSize) {
				id_2 = i;
				id_2_minSize = qtSize;
			}
		}
	}
	return(id_2);
}

int MySqlStore::getMaxThreadsForStoreId(int id_main) {
	extern int opt_mysqlstore_max_threads_cdr;
	extern int opt_mysqlstore_max_threads_message;
	extern int opt_mysqlstore_max_threads_sip_msg;
	extern int opt_mysqlstore_max_threads_register;
	extern int opt_mysqlstore_max_threads_http;
	extern int opt_mysqlstore_max_threads_webrtc;
	extern int opt_mysqlstore_max_threads_ipacc_base;
	extern int opt_mysqlstore_max_threads_ipacc_agreg2;
	extern int opt_mysqlstore_max_threads_charts_cache;
	int maxThreads = 1;
	switch(id_main) {
	case STORE_PROC_ID_CDR:
		maxThreads = opt_mysqlstore_max_threads_cdr;
		break;
	case STORE_PROC_ID_CDR_REDIRECT:
		maxThreads = opt_mysqlstore_max_threads_cdr;
		break;
	case STORE_PROC_ID_MESSAGE:
		maxThreads = opt_mysqlstore_max_threads_message;
		break;
	case STORE_PROC_ID_SIP_MSG:
		maxThreads = opt_mysqlstore_max_threads_sip_msg;
		break;
	case STORE_PROC_ID_REGISTER:
		maxThreads = opt_mysqlstore_max_threads_register;
		break;
	case STORE_PROC_ID_HTTP:
		maxThreads = opt_mysqlstore_max_threads_http;
		break;
	case STORE_PROC_ID_WEBRTC:
		maxThreads = opt_mysqlstore_max_threads_webrtc;
		break;
	case STORE_PROC_ID_IPACC:
		maxThreads = opt_mysqlstore_max_threads_ipacc_base;
		break;
	case STORE_PROC_ID_IPACC_AGR_INTERVAL:
	case STORE_PROC_ID_IPACC_AGR2_HOUR:
		maxThreads = opt_mysqlstore_max_threads_ipacc_agreg2;
		break;
	case STORE_PROC_ID_CHARTS_CACHE:
	case STORE_PROC_ID_CHARTS_CACHE_REMOTE:
		maxThreads = opt_mysqlstore_max_threads_charts_cache;
		break;
	}
	return(maxThreads);
}

bool MySqlStore::isSetMaxThreadsForStoreId(int id_main) {
	extern bool opt_mysqlstore_max_threads_cdr_set;
	extern bool opt_mysqlstore_max_threads_message_set;
	extern bool opt_mysqlstore_max_threads_sip_msg_set;
	extern bool opt_mysqlstore_max_threads_register_set;
	extern bool opt_mysqlstore_max_threads_http_set;
	extern bool opt_mysqlstore_max_threads_webrtc_set;
	extern bool opt_mysqlstore_max_threads_ipacc_base_set;
	extern bool opt_mysqlstore_max_threads_ipacc_agreg2_set;
	extern bool opt_mysqlstore_max_threads_charts_cache_set;
	bool set = false;
	switch(id_main) {
	case STORE_PROC_ID_CDR:
		set = opt_mysqlstore_max_threads_cdr_set;
		break;
	case STORE_PROC_ID_CDR_REDIRECT:
		set = opt_mysqlstore_max_threads_cdr_set;
		break;
	case STORE_PROC_ID_MESSAGE:
		set = opt_mysqlstore_max_threads_message_set;
		break;
	case STORE_PROC_ID_SIP_MSG:
		set = opt_mysqlstore_max_threads_sip_msg_set;
		break;
	case STORE_PROC_ID_REGISTER:
		set = opt_mysqlstore_max_threads_register_set;
		break;
	case STORE_PROC_ID_HTTP:
		set = opt_mysqlstore_max_threads_http_set;
		break;
	case STORE_PROC_ID_WEBRTC:
		set = opt_mysqlstore_max_threads_webrtc_set;
		break;
	case STORE_PROC_ID_IPACC:
		set = opt_mysqlstore_max_threads_ipacc_base_set;
		break;
	case STORE_PROC_ID_IPACC_AGR_INTERVAL:
	case STORE_PROC_ID_IPACC_AGR2_HOUR:
		set = opt_mysqlstore_max_threads_ipacc_agreg2_set;
		break;
	case STORE_PROC_ID_CHARTS_CACHE:
	case STORE_PROC_ID_CHARTS_CACHE_REMOTE:
		set = opt_mysqlstore_max_threads_charts_cache_set;
		break;
	}
	return(set);
}

int MySqlStore::getConcatLimitForStoreId(int id_main) {
	extern int opt_mysqlstore_concat_limit_cdr;;
	extern int opt_mysqlstore_concat_limit_message;
	extern int opt_mysqlstore_concat_limit_sip_msg;
	extern int opt_mysqlstore_concat_limit_register;
	extern int opt_mysqlstore_concat_limit_http;
	extern int opt_mysqlstore_concat_limit_webrtc;
	extern int opt_mysqlstore_concat_limit_ipacc;
	extern int opt_mysqlstore_concat_limit;
	int concatLimit = 0;
	switch(id_main) {
	case STORE_PROC_ID_CDR:
		concatLimit = opt_mysqlstore_concat_limit_cdr;
		break;
	case STORE_PROC_ID_CDR_REDIRECT:
		concatLimit = opt_mysqlstore_concat_limit_cdr;
		break;
	case STORE_PROC_ID_MESSAGE:
		concatLimit = opt_mysqlstore_concat_limit_message;
		break;
	case STORE_PROC_ID_SIP_MSG:
		concatLimit = opt_mysqlstore_concat_limit_sip_msg;
		break;
	case STORE_PROC_ID_REGISTER:
		concatLimit = opt_mysqlstore_concat_limit_register;
		break;
	case STORE_PROC_ID_HTTP:
		concatLimit = opt_mysqlstore_concat_limit_http;
		break;
	case STORE_PROC_ID_WEBRTC:
		concatLimit = opt_mysqlstore_concat_limit_webrtc;
		break;
	case STORE_PROC_ID_IPACC:
	case STORE_PROC_ID_IPACC_AGR_INTERVAL:
	case STORE_PROC_ID_IPACC_AGR2_HOUR:
		concatLimit = opt_mysqlstore_concat_limit_ipacc;
		break;
	case STORE_PROC_ID_CHARTS_CACHE:
	case STORE_PROC_ID_CHARTS_CACHE_REMOTE:
		concatLimit = opt_mysqlstore_concat_limit;
		break;
	}
	return(concatLimit);
}

bool MySqlStore::isRedirectStoreId(int id_main) {
	return(id_main == STORE_PROC_ID_CDR_REDIRECT);
}

void *MySqlStore::threadQFilesCheckPeriod(void *arg) {
	MySqlStore *me = (MySqlStore*)arg;
	while(!is_terminating()) {
		me->lock_qfiles();
		for(map<int, QFile*>::iterator iter = me->qfiles.begin(); iter != me->qfiles.end(); iter++) {
			iter->second->lock();
			if(iter->second->isOpen() &&
			   iter->second->isExceedPeriod(me->qfileConfig.period)) {
				if(sverb.qfiles) {
					cout << "*** CLOSE FROM THREAD QFilesCheckPeriod " << iter->second->filename
					     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
				}
				iter->second->close();
			}
			iter->second->unlock();
		}
		me->unlock_qfiles();
		USLEEP(250000);
	}
	return(NULL);
}

void *MySqlStore::threadLoadFromQFiles(void *arg) {
	LoadFromQFilesThreadInfo *threadInfo = (LoadFromQFilesThreadInfo*)arg;
	int id_main = threadInfo->id_main;
	MySqlStore *me = threadInfo->store;
	delete threadInfo;
	if(me->loadFromQFileConfig.inotify) {
		me->fillQFiles(id_main);
	}
	while(!is_terminating()) {
		extern int opt_blockqfile;
		if(opt_blockqfile) {
			sleep(1);
			continue;
		}
		string minFile = me->getMinQFile(id_main);
		if(minFile.empty()) {
			USLEEP(250000);
		} else {
			extern int opt_query_cache_speed;
			while((me->isCloud() ?
				(me->getSize(id_main, -1) > me->getConcatLimit(id_main, -1)) :
			       opt_query_cache_speed ? 
			        (me->getCountActive(id_main) >= me->loadFromQFilesThreadData[id_main].storeThreads) :
			        (me->getSize(id_main, -1) > 0)) && 
			      !is_terminating()) {
				USLEEP(100000);
			}
			if(!is_terminating()) {
				if(me->existFilenameInQFiles(minFile.c_str()) ||
				   !me->loadFromQFile(minFile.c_str(), id_main)) {
					USLEEP(250000);
				}
			}
		}
	}
	return(NULL);
}

void *MySqlStore::threadINotifyQFiles(void *arg) {
#ifndef FREEBSD
	MySqlStore *me = (MySqlStore*)arg;
	int inotifyDescriptor = inotify_init();
	if(inotifyDescriptor < 0) {
		syslog(LOG_ERR, "inotify init failed");
		me->loadFromQFileConfig.inotify = false;
		return(NULL);
	}
	string directory = me->loadFromQFileConfig.getDirectory();
	int watchDescriptor = inotify_add_watch(inotifyDescriptor, directory.c_str(), IN_CLOSE_WRITE);
	if(watchDescriptor < 0) {
		syslog(LOG_ERR, "inotify watch %s failed", directory.c_str());
		close(inotifyDescriptor);
		me->loadFromQFileConfig.inotify = false;
		return(NULL);
	}
	ssize_t watchBuffMaxLen = 1024 * (sizeof(inotify_event) + 256);
	char *watchBuff =  new FILE_LINE(29009) char[watchBuffMaxLen];
	while(!is_terminating()) {
		ssize_t watchBuffLen = read(inotifyDescriptor, watchBuff, watchBuffMaxLen);
		if(watchBuffLen > (ssize_t)sizeof(inotify_event)) {
			if(watchBuffLen == watchBuffMaxLen) {
				syslog(LOG_NOTICE, "qfiles inotify events filled whole buffer");
			}
			ssize_t i = 0;
			while(i < watchBuffLen && !is_terminating()) {
				if(watchBuffLen - i < (ssize_t)sizeof(inotify_event)) {
					break;
				}
				inotify_event *event = (inotify_event*)(watchBuff + i);
				if(watchBuffLen - i < (ssize_t)sizeof(inotify_event) + event->len) {
					break;
				}
				i += sizeof(inotify_event) + event->len;
				if(event->mask & IN_CLOSE_WRITE) {
					me->addFileFromINotify(event->name);
				}
			}
		} else {
			usleep(1000);
		}
	}
	delete [] watchBuff;
	inotify_rm_watch(inotifyDescriptor, watchDescriptor);
#endif
	return(NULL);
}


SqlDb *createSqlObject(int connectId) {
	SqlDb *sqlDb = NULL;
	if(isSqlDriver("mysql")) {
		if(connectId) {
			if(!(connectId == 1 && use_mysql_2())) {
				return(NULL);
			}
		}
		sqlDb = new FILE_LINE(29010) SqlDb_mysql();
		if(connectId == 1) {
			sqlDb->setConnectParameters(mysql_2_host, mysql_2_user, mysql_2_password, mysql_2_database, opt_mysql_2_port, mysql_2_socket, true, &optMySsl_2);
		} else {
			sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket, true, &optMySsl);
			if(isCloud()) {
				extern char cloud_host[256];
				extern char cloud_token[256];
				extern bool cloud_router;
				sqlDb->setCloudParameters(cloud_host, cloud_token, cloud_router);
			}
		}
	} else if(isSqlDriver("odbc")) {
		SqlDb_odbc *sqlDb_odbc = new FILE_LINE(29011) SqlDb_odbc();
		sqlDb_odbc->setOdbcVersion(SQL_OV_ODBC3);
		sqlDb_odbc->setSubtypeDb(odbc_driver);
		sqlDb = sqlDb_odbc;
		sqlDb->setConnectParameters(odbc_dsn, odbc_user, odbc_password);
	}
	return(sqlDb);
}

string sqlDateTimeString(time_t unixTime, bool useGlobalTimeCache) {
	char dateTimeBuffer[50];
	sqlDateTimeString(dateTimeBuffer, unixTime, useGlobalTimeCache);
	return dateTimeBuffer;
}

#define sqlDateTimeString_cache_length 5

void sqlDateTimeString(char *rslt, time_t unixTime, bool useGlobalTimeCache) {
 
	#if not defined(__arm__)
	static __thread time_t _cache_time[sqlDateTimeString_cache_length];
	static __thread char _cache_rslt[sqlDateTimeString_cache_length][50];
	static __thread int _cache_pos = 0;
	#else
	static time_t _cache_time[sqlDateTimeString_cache_length];
	static char _cache_rslt[sqlDateTimeString_cache_length][50];
	static volatile int _cache_pos = 0;
	static volatile int _cache_sync = 0;
	#endif
	
	if(!useGlobalTimeCache) {
		#if defined(__arm__)
		__SYNC_LOCK(_cache_sync);
		#endif
		for(unsigned i = 0; i < sqlDateTimeString_cache_length; i++) {
			if(_cache_time[i] == unixTime) {
				strcpy(rslt, _cache_rslt[i]);
				#if defined(__arm__)
				__SYNC_UNLOCK(_cache_sync);
				#endif
				return;
			}
		}
		#if defined(__arm__)
		__SYNC_UNLOCK(_cache_sync);
		#endif
	}
 
	struct tm localTime = time_r(&unixTime, NULL, useGlobalTimeCache);
	strftime(rslt, 50, "%Y-%m-%d %H:%M:%S", &localTime);
	
	if(!useGlobalTimeCache) {
		#if defined(__arm__)
		__SYNC_LOCK(_cache_sync);
		#endif
		strcpy(_cache_rslt[_cache_pos], rslt);
		_cache_time[_cache_pos] = unixTime;
		_cache_pos = (_cache_pos + 1) % sqlDateTimeString_cache_length;
		#if defined(__arm__)
		__SYNC_UNLOCK(_cache_sync);
		#endif
	}
	
}

string sqlDateTimeString_us2ms(u_int64_t unixTime_us, bool useGlobalTimeCache) {
	char dateTimeBuffer[50];
	sqlDateTimeString_us2ms(dateTimeBuffer, unixTime_us, useGlobalTimeCache);
	return dateTimeBuffer;
}

void sqlDateTimeString_us2ms(char *rslt, u_int64_t unixTime_us, bool useGlobalTimeCache) {
 
	#if not defined(__arm__)
	static __thread u_int64_t _cache_time[sqlDateTimeString_cache_length];
	static __thread char _cache_rslt[sqlDateTimeString_cache_length][50];
	static __thread int _cache_pos = 0;
	#else
	static u_int64_t _cache_time[sqlDateTimeString_cache_length];
	static char _cache_rslt[sqlDateTimeString_cache_length][50];
	static volatile int _cache_pos = 0;
	static volatile int _cache_sync = 0;
	#endif
	
	if(!useGlobalTimeCache) {
		#if defined(__arm__)
		__SYNC_LOCK(_cache_sync);
		#endif
		for(unsigned i = 0; i < sqlDateTimeString_cache_length; i++) {
			if(_cache_time[i] == unixTime_us) {
				strcpy(rslt, _cache_rslt[i]);
				#if defined(__arm__)
				__SYNC_UNLOCK(_cache_sync);
				#endif
				return;
			}
		}
		#if defined(__arm__)
		__SYNC_UNLOCK(_cache_sync);
		#endif
	}

	time_t unixTime_s = TIME_US_TO_S(unixTime_us);
	unsigned unixTime_dec_ms = round(TIME_US_TO_DEC_US(unixTime_us) / 1000.);
	if(unixTime_dec_ms > 999) {
		++unixTime_s;
		unixTime_dec_ms = 0;
	}
	struct tm localTime = time_r(&unixTime_s, NULL, useGlobalTimeCache);
	strftime(rslt, 50, "%Y-%m-%d %H:%M:%S", &localTime);
	sprintf(rslt + strlen(rslt), ".%03i", unixTime_dec_ms);
	
	if(!useGlobalTimeCache) {
		#if defined(__arm__)
		__SYNC_LOCK(_cache_sync);
		#endif
		strcpy(_cache_rslt[_cache_pos], rslt);
		_cache_time[_cache_pos] = unixTime_us;
		_cache_pos = (_cache_pos + 1) % sqlDateTimeString_cache_length;
		#if defined(__arm__)
		__SYNC_UNLOCK(_cache_sync);
		#endif
	}
	
}

string sqlDateString(time_t unixTime, bool useGlobalTimeCache) {
	struct tm localTime = time_r(&unixTime, NULL, useGlobalTimeCache);
	char dateBuffer[50];
	strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d", &localTime);
	return string(dateBuffer);
}

string sqlDateTimeString(tm &time) {
	char dateTimeBuffer[50];
	strftime(dateTimeBuffer, sizeof(dateTimeBuffer), "%Y-%m-%d %H:%M:%S", &time);
	return string(dateTimeBuffer);
}

string sqlDateString(tm &time) {
	char dateBuffer[50];
	strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d", &time);
	return string(dateBuffer);
}

string reverseString(const char *str) {
	extern cUtfConverter utfConverter;
	return(utfConverter.reverse(str));
}

string prepareQueryForPrintf(const char *query) {
	string rslt;
	if(query) {
		int length = strlen(query);
		for(int i = 0; i < length; i++) {
			rslt += query[i];
			if(query[i] == '%') {
				rslt += '%';
			}
		}
	}
	return rslt;
}

void prepareQuery(string subtypeDb, string &query, bool base, int removeNextPassQuery) {
	size_t findPos;
	if(base) {
		if(subtypeDb == "mssql") {
			const char *substFce[][2] = { 
					{ "UNIX_TIMESTAMP", "dbo.unix_timestamp" },
					{ "NOW", "dbo.now" },
					{ "SUBTIME", "dbo.subtime" }
			};
			for(unsigned int i = 0; i < sizeof(substFce)/sizeof(substFce[0]); i++) {
				while((findPos  = query.find(substFce[i][0])) != string::npos) {
					query.replace(findPos, strlen(substFce[i][0]), substFce[i][1]);
				}
			}
		}
		while((findPos  = query.find("_LC_[")) != string::npos) {
			size_t findPosEnd = query.find("]", findPos);
			if(findPosEnd != string::npos) {
				string lc = query.substr(findPos + 5, findPosEnd - findPos - 5);
				if(subtypeDb == "mssql") {
					lc = "case when " + lc + " then 1 else 0 end";
				}
				query.replace(findPos, findPosEnd - findPos + 1, lc);
			}
		}
	}
	if(removeNextPassQuery) {
		while((findPos  = query.find("__NEXT_PASS_QUERY_BEGIN__")) != string::npos) {
			size_t findPosEnd = query.find("__NEXT_PASS_QUERY_END__", findPos);
			if(findPosEnd != string::npos) {
				if(removeNextPassQuery == 2) { 
					query.erase(findPosEnd, 23);
					query.erase(findPos, 25);
				} else {
					query.erase(findPos, findPosEnd - findPos + 23);
				}
			}
		}
	}
}

string prepareQueryForPrintf(string &query) {
	return(prepareQueryForPrintf(query.c_str()));
}


bool SqlDb_mysql::createSchema(int connectId) {
	if(connectId) {
		syslog(LOG_DEBUG, "creating and upgrading MySQL schema - connect %i...", connectId + 1);
	} else {
		syslog(LOG_DEBUG, "creating and upgrading MySQL schema...");
	}
	sql_disable_next_attempt_if_error = 1;
	this->multi_off();

	bool existsCdrTable = false;
	if(connectId == 0) {
		existsCdrTable = this->existsTable("cdr");
	}

	unsigned sniffer_version_num = 0;
	unsigned sniffer_version_num_save = 0;
	bool okSaveVersion = false;
	bool existsTableSystem = false;
	if(connectId == 0) {
		sniffer_version_num = RTPSENSOR_VERSION_INT();
		if(this->existsTable("system")) {
			existsTableSystem = true;
			this->select("system", "content", "type", "sniffer_db_version");
			SqlDb_row rslt = this->fetchRow();
			if(rslt) {
				sniffer_version_num_save = atol(rslt[0].c_str());
			}
		}
		if(sniffer_version_num_save && sniffer_version_num &&
		   sniffer_version_num_save >= sniffer_version_num) {
			okSaveVersion = true;
		}
	}

	extern bool opt_check_db;
	bool result = createSchema_tables_other(connectId) &&
		      createSchema_table_http_jj(connectId) &&
		      createSchema_table_webrtc(connectId) &&
		      ((!opt_check_db && okSaveVersion) || createSchema_alter_other(connectId)) &&
		      ((!opt_check_db && okSaveVersion) || createSchema_alter_http_jj(connectId)) &&
		      createSchema_procedure_partition(connectId) &&
		      createSchema_procedures_other(connectId) &&
		      (connectId != 0 || existsCdrTable ||
		       createSchema_init_cdr_partitions(connectId));

	sql_disable_next_attempt_if_error = 0;
	syslog(LOG_DEBUG, "done");
	
	if(connectId == 0 && result) {
		this->saveTimezoneInformation();
		if(sniffer_version_num > sniffer_version_num_save &&
		   existsTableSystem) {
			SqlDb_row row;
			row.add(sniffer_version_num, "content");
			if(sniffer_version_num_save) {
				this->update("system", row, "type = 'sniffer_db_version'");
			} else {
				row.add("sniffer_db_version", "type");
				this->insert("system", row);
			}
		}
	}
	
	return(result);
}

bool SqlDb_mysql::createSchema_tables_other(int connectId) {
	this->clearLastError();
	if(!(connectId == 0)) {
		return(true);
	}
	
	string compress = getOptimalCompressType();
	string limitDay;
	string partDayName;
	string limitMonth;
	string partMonthName;
	string limitHour;
	string partHourName;
	string limitHourNext;
	string partHourNextName;
	partDayName = this->getPartDayName(&limitDay, opt_create_old_partitions > 0 ? -opt_create_old_partitions : 0);
	partMonthName = this->getPartMonthName(&limitMonth);
	partHourName = this->getPartHourName(&limitHour);
	partHourNextName = this->getPartHourName(&limitHourNext, 1);
	
	bool okTableSensorConfig = false;
	if(this->existsTable("filter_ip")) {
		if(this->query("select * from filter_ip")) {
			okTableSensorConfig = true;
		} else {
			if(this->getLastError() == ER_NO_DB_ERROR ||
			   this->getLastError() == ER_DBACCESS_DENIED_ERROR) {
				return(false);
			}
		}
	}
	
	if(!okTableSensorConfig && this->getLastError()) {
		return(false);
	}
	
	this->query(
	"CREATE TABLE IF NOT EXISTS `db_alters` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned DEFAULT NULL,\
			`at` datetime,\
			`table` varchar(1024),\
			`reason` text,\
			`alter` text,\
			`result` enum('ok','error','skip_too_rows','skip_prev_error'),\
			`error` text,\
		PRIMARY KEY (`id`),\
		KEY `id_sensor` (`id_sensor`),\
		KEY `at` (`at`),\
		KEY `id_sensor_at` (`id_sensor`,`at`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `sensor_config` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned DEFAULT NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	this->query(
	"CREATE TABLE IF NOT EXISTS `sensor_running_config` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned DEFAULT NULL,\
			`start_at` datetime default NULL,\
			`stop_at` datetime default NULL,\
			`version` varchar(100) default NULL,\
			`config` mediumtext default NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `filter_ip` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`ip` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`mask` int DEFAULT NULL,\
			`direction` tinyint DEFAULT NULL,\
			`rtp` tinyint DEFAULT NULL,\
			`rtcp` tinyint default NULL,\
			`sip` tinyint DEFAULT NULL,\
			`register` tinyint DEFAULT NULL,\
			`dtmf` tinyint DEFAULT NULL,\
			`graph` tinyint DEFAULT NULL,\
			`wav` tinyint DEFAULT NULL,\
			`skip` tinyint DEFAULT NULL,\
			`script` tinyint DEFAULT NULL,\
			`mos_lqo` tinyint DEFAULT NULL,\
			`hide_message` tinyint DEFAULT NULL,\
			`note` text,\
			`remove_at` date default NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	this->query(
	"CREATE TABLE IF NOT EXISTS `filter_telnum` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`prefix` varchar(32) DEFAULT NULL,\
			`fixed_len` int unsigned DEFAULT '0',\
			`direction` tinyint DEFAULT NULL,\
			`rtp` tinyint DEFAULT NULL,\
			`rtcp` tinyint default NULL,\
			`sip` tinyint DEFAULT NULL,\
			`register` tinyint DEFAULT NULL,\
			`dtmf` tinyint DEFAULT NULL,\
			`graph` tinyint DEFAULT NULL,\
			`wav` tinyint DEFAULT NULL,\
			`skip` tinyint DEFAULT NULL,\
			`script` tinyint DEFAULT NULL,\
			`mos_lqo` tinyint DEFAULT NULL,\
			`hide_message` tinyint DEFAULT NULL,\
			`note` text,\
			`remove_at` date default NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `filter_domain` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`domain` char(128) DEFAULT NULL,\
			`direction` tinyint DEFAULT NULL,\
			`rtp` tinyint DEFAULT NULL,\
			`rtcp` tinyint default NULL,\
			`sip` tinyint DEFAULT NULL,\
			`register` tinyint DEFAULT NULL,\
			`dtmf` tinyint DEFAULT NULL,\
			`graph` tinyint DEFAULT NULL,\
			`wav` tinyint DEFAULT NULL,\
			`skip` tinyint DEFAULT NULL,\
			`script` tinyint DEFAULT NULL,\
			`mos_lqo` tinyint DEFAULT NULL,\
			`hide_message` tinyint DEFAULT NULL,\
			`note` text,\
			`remove_at` date default NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `filter_sip_header` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`header` char(128) default NULL,\
			`content` char(128) default NULL,\
			`content_type` enum('strict', 'prefix', 'regexp') default NULL,\
			`direction` tinyint DEFAULT NULL,\
			`rtp` tinyint DEFAULT NULL,\
			`rtcp` tinyint default NULL,\
			`sip` tinyint DEFAULT NULL,\
			`register` tinyint DEFAULT NULL,\
			`dtmf` tinyint DEFAULT NULL,\
			`graph` tinyint DEFAULT NULL,\
			`wav` tinyint DEFAULT NULL,\
			`skip` tinyint DEFAULT NULL,\
			`script` tinyint DEFAULT NULL,\
			`mos_lqo` tinyint DEFAULT NULL,\
			`hide_message` tinyint DEFAULT NULL,\
			`note` text,\
			`remove_at` date default NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `cdr_sip_response` (\
			`id` mediumint unsigned NOT NULL AUTO_INCREMENT,\
			`lastSIPresponse` varchar(255) DEFAULT NULL,\
		PRIMARY KEY (`id`),\
		UNIQUE KEY `lastSIPresponse` (`lastSIPresponse`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	if(_save_sip_history) {
		this->query(
		"CREATE TABLE IF NOT EXISTS `cdr_sip_request` (\
				`id` mediumint unsigned NOT NULL AUTO_INCREMENT,\
				`request` varchar(255) DEFAULT NULL,\
			PRIMARY KEY (`id`),\
			UNIQUE KEY `request` (`request`)\
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	}
	
	this->query(
	"CREATE TABLE IF NOT EXISTS `cdr_reason` (\
			`id` mediumint unsigned NOT NULL AUTO_INCREMENT,\
			`type` tinyint DEFAULT NULL,\
			`reason` varchar(255) DEFAULT NULL,\
		PRIMARY KEY (`id`),\
		UNIQUE KEY `type_reason` (`type`, `reason`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_ua` (\
			`id` int unsigned NOT NULL AUTO_INCREMENT,\
			`ua` varchar(512) DEFAULT NULL,\
		PRIMARY KEY (`id`),\
		UNIQUE KEY `ua` (`ua`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 ") + compress + ";");

	bool extPrecisionBilling = true;
	extern bool opt_database_backup;
	if(opt_database_backup) {
		extern char opt_database_backup_from_mysql_host[256];
		extern char opt_database_backup_from_mysql_database[256];
		extern char opt_database_backup_from_mysql_user[256];
		extern char opt_database_backup_from_mysql_password[256];
		extern unsigned int opt_database_backup_from_mysql_port;
		extern char opt_database_backup_from_mysql_socket[256];
		extern mysqlSSLOptions optMySSLBackup;
		SqlDb_mysql *sqlDbSrc = new FILE_LINE(29013) SqlDb_mysql();
		sqlDbSrc->setConnectParameters(opt_database_backup_from_mysql_host, 
					       opt_database_backup_from_mysql_user,
					       opt_database_backup_from_mysql_password,
					       opt_database_backup_from_mysql_database,
					       opt_database_backup_from_mysql_port,
					       opt_database_backup_from_mysql_socket,
					       true, &optMySSLBackup);
		if(sqlDbSrc->existsColumn("cdr", "price_operator_mult100") &&
		   sqlDbSrc->existsColumn("cdr", "price_customer_mult100")) {
			extPrecisionBilling = false;
		}
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`calldate` ") + column_type_datetime_ms() + " NOT NULL,\
			`callend` " + column_type_datetime_ms() + " NOT NULL,\
			`duration` " + column_type_duration_ms() + " unsigned DEFAULT NULL,\
			`connect_duration` " + column_type_duration_ms() + " unsigned DEFAULT NULL,\
			`progress_time` " + column_type_duration_ms() + " unsigned DEFAULT NULL,\
			`first_rtp_time` " + column_type_duration_ms() + " unsigned DEFAULT NULL,\
			`post_bye_delay` " + column_type_duration_ms(NULL, true) + " unsigned DEFAULT NULL,\
			`caller` varchar(255) DEFAULT NULL,\
			`caller_domain` varchar(255) DEFAULT NULL,\
			`caller_reverse` varchar(255) DEFAULT NULL,\
			`callername` varchar(255) DEFAULT NULL,\
			`callername_reverse` varchar(255) DEFAULT NULL,\
			`called` varchar(255) DEFAULT NULL,\
			`called_domain` varchar(255) DEFAULT NULL,\
			`called_reverse` varchar(255) DEFAULT NULL,\
			`sipcallerip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sipcallerport` smallint unsigned DEFAULT NULL,\
			`sipcalledip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sipcalledport` smallint unsigned DEFAULT NULL,\
			" + (opt_save_ip_from_encaps_ipheader ?
			      string(
			      "`sipcallerip_encaps` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledip_encaps` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			       `sipcalledip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			      " :
			      "") +
			    (opt_separate_storage_ipv6_ipv4_address ?
			      string(
			      "`sipcallerip_v4` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerport_v4` smallint unsigned DEFAULT NULL,\
			       `sipcalledip_v4` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledport_v4` smallint unsigned DEFAULT NULL,\
			       `sipcallerip_v6` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerport_v6` smallint unsigned DEFAULT NULL,\
			       `sipcalledip_v6` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledport_v6` smallint unsigned DEFAULT NULL,\
			      " :
			      "") +
			"`whohanged` enum('caller','callee') DEFAULT NULL,\
			`bye` tinyint unsigned DEFAULT NULL,\
			`lastSIPresponse_id` mediumint unsigned DEFAULT NULL,\
			`lastSIPresponseNum` smallint unsigned DEFAULT NULL,\
			`reason_sip_cause` smallint unsigned DEFAULT NULL,\
			`reason_sip_text_id` mediumint unsigned DEFAULT NULL,\
			`reason_q850_cause` smallint unsigned DEFAULT NULL,\
			`reason_q850_text_id` mediumint unsigned DEFAULT NULL,\
			`sighup` tinyint DEFAULT NULL,\
			`dscp` int unsigned DEFAULT NULL,\
			`a_index` tinyint DEFAULT NULL,\
			`b_index` tinyint DEFAULT NULL,\
			`a_payload` int DEFAULT NULL,\
			`b_payload` int DEFAULT NULL,\
			`a_saddr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`b_saddr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`a_received` mediumint unsigned DEFAULT NULL,\
			`b_received` mediumint unsigned DEFAULT NULL,\
			`a_lost` mediumint unsigned DEFAULT NULL,\
			`b_lost` mediumint unsigned DEFAULT NULL,\
			`a_ua_id` int unsigned DEFAULT NULL,\
			`b_ua_id` int unsigned DEFAULT NULL,\
		       " + (opt_disable_cdr_fields_rtp ? "" :
		       "`a_avgjitter_mult10` mediumint unsigned DEFAULT NULL,\
			`b_avgjitter_mult10` mediumint unsigned DEFAULT NULL,\
			`a_maxjitter` smallint unsigned DEFAULT NULL,\
			`b_maxjitter` smallint unsigned DEFAULT NULL,\
			`a_sl1` mediumint unsigned DEFAULT NULL,\
			`a_sl2` mediumint unsigned DEFAULT NULL,\
			`a_sl3` mediumint unsigned DEFAULT NULL,\
			`a_sl4` mediumint unsigned DEFAULT NULL,\
			`a_sl5` mediumint unsigned DEFAULT NULL,\
			`a_sl6` mediumint unsigned DEFAULT NULL,\
			`a_sl7` mediumint unsigned DEFAULT NULL,\
			`a_sl8` mediumint unsigned DEFAULT NULL,\
			`a_sl9` mediumint unsigned DEFAULT NULL,\
			`a_sl10` mediumint unsigned DEFAULT NULL,\
			`a_d50` mediumint unsigned DEFAULT NULL,\
			`a_d70` mediumint unsigned DEFAULT NULL,\
			`a_d90` mediumint unsigned DEFAULT NULL,\
			`a_d120` mediumint unsigned DEFAULT NULL,\
			`a_d150` mediumint unsigned DEFAULT NULL,\
			`a_d200` mediumint unsigned DEFAULT NULL,\
			`a_d300` mediumint unsigned DEFAULT NULL,\
			`b_sl1` mediumint unsigned DEFAULT NULL,\
			`b_sl2` mediumint unsigned DEFAULT NULL,\
			`b_sl3` mediumint unsigned DEFAULT NULL,\
			`b_sl4` mediumint unsigned DEFAULT NULL,\
			`b_sl5` mediumint unsigned DEFAULT NULL,\
			`b_sl6` mediumint unsigned DEFAULT NULL,\
			`b_sl7` mediumint unsigned DEFAULT NULL,\
			`b_sl8` mediumint unsigned DEFAULT NULL,\
			`b_sl9` mediumint unsigned DEFAULT NULL,\
			`b_sl10` mediumint unsigned DEFAULT NULL,\
			`b_d50` mediumint unsigned DEFAULT NULL,\
			`b_d70` mediumint unsigned DEFAULT NULL,\
			`b_d90` mediumint unsigned DEFAULT NULL,\
			`b_d120` mediumint unsigned DEFAULT NULL,\
			`b_d150` mediumint unsigned DEFAULT NULL,\
			`b_d200` mediumint unsigned DEFAULT NULL,\
			`b_d300` mediumint unsigned DEFAULT NULL,\
			`a_mos_lqo_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_lqo_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_f1_min_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_f2_min_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_adapt_min_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_xr_min_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_silence_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f1_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f2_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_adapt_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_xr_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_silence_min_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_f1_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_f2_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_adapt_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_xr_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_silence_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f1_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f2_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_adapt_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_xr_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_silence_mult10` tinyint unsigned DEFAULT NULL,\
			`a_rtcp_loss` mediumint DEFAULT NULL,\
			`a_rtcp_maxfr` smallint unsigned DEFAULT NULL,\
			`a_rtcp_avgfr_mult10` smallint unsigned DEFAULT NULL,\
			`a_rtcp_maxjitter` smallint unsigned DEFAULT NULL,\
			`a_rtcp_avgjitter_mult10` smallint unsigned DEFAULT NULL,\
			`a_rtcp_avgrtd_mult10` smallint unsigned DEFAULT NULL,\
			`a_rtcp_maxrtd_mult10` smallint unsigned DEFAULT NULL,\
			`a_rtcp_avgrtd_w` smallint unsigned DEFAULT NULL,\
			`a_rtcp_maxrtd_w` smallint unsigned DEFAULT NULL,\
			`b_rtcp_loss` mediumint DEFAULT NULL,\
			`b_rtcp_maxfr` smallint unsigned DEFAULT NULL,\
			`b_rtcp_avgfr_mult10` smallint unsigned DEFAULT NULL,\
			`b_rtcp_maxjitter` smallint unsigned DEFAULT NULL,\
			`b_rtcp_avgjitter_mult10` smallint unsigned DEFAULT NULL,\
			`b_rtcp_avgrtd_mult10` smallint unsigned DEFAULT NULL,\
			`b_rtcp_maxrtd_mult10` smallint unsigned DEFAULT NULL,\
			`b_rtcp_avgrtd_w` smallint unsigned DEFAULT NULL,\
			`b_rtcp_maxrtd_w` smallint unsigned DEFAULT NULL,\
		       ") + 
		       "`a_last_rtp_from_end` " + column_type_duration_ms("smallint") + " DEFAULT NULL,\
			`b_last_rtp_from_end` " + column_type_duration_ms("smallint") + " DEFAULT NULL,\
		       " + (opt_disable_cdr_fields_rtp ? "" :
		       "`a_rtcp_fraclost_pktcount` int unsigned DEFAULT NULL,\
			`b_rtcp_fraclost_pktcount` int unsigned DEFAULT NULL,\
		       ") +
		       "`a_rtp_ptime` tinyint unsigned DEFAULT NULL,\
			`b_rtp_ptime` tinyint unsigned DEFAULT NULL,\
			`payload` int DEFAULT NULL,\
		       " + (opt_disable_cdr_fields_rtp ? "" :
		       "`jitter_mult10` mediumint unsigned DEFAULT NULL,\
			`mos_min_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_min_mult10` tinyint unsigned DEFAULT NULL,\
			`packet_loss_perc_mult1000` mediumint unsigned DEFAULT NULL,\
			`a_packet_loss_perc_mult1000` mediumint unsigned DEFAULT NULL,\
			`b_packet_loss_perc_mult1000` mediumint unsigned DEFAULT NULL,\
			`delay_sum` mediumint unsigned DEFAULT NULL,\
			`a_delay_sum` mediumint unsigned DEFAULT NULL,\
			`b_delay_sum` mediumint unsigned DEFAULT NULL,\
			`delay_avg_mult100` mediumint unsigned DEFAULT NULL,\
			`a_delay_avg_mult100` mediumint unsigned DEFAULT NULL,\
			`b_delay_avg_mult100` mediumint unsigned DEFAULT NULL,\
			`delay_cnt` mediumint unsigned DEFAULT NULL,\
			`a_delay_cnt` mediumint unsigned DEFAULT NULL,\
			`b_delay_cnt` mediumint unsigned DEFAULT NULL,\
			`rtcp_avgfr_mult10` smallint unsigned DEFAULT NULL,\
			`rtcp_avgjitter_mult10` smallint unsigned DEFAULT NULL,\
		       ") + 
		       "`lost` mediumint unsigned DEFAULT NULL,\
		       " + (opt_disable_cdr_fields_rtp ? "" :
		       "`caller_clipping_div3` smallint unsigned DEFAULT NULL,\
			`called_clipping_div3` smallint unsigned DEFAULT NULL,\
			`caller_silence` tinyint unsigned DEFAULT NULL,\
			`called_silence` tinyint unsigned DEFAULT NULL,\
			`caller_silence_end` smallint unsigned DEFAULT NULL,\
			`called_silence_end` smallint unsigned DEFAULT NULL,\
		       ") +
		       "`response_time_100` smallint unsigned DEFAULT NULL,\
			`response_time_xxx` smallint unsigned DEFAULT NULL,\
			`max_retransmission_invite` tinyint unsigned DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,\
			`vlan` smallint DEFAULT NULL,\
			`id_sensor` smallint unsigned DEFAULT NULL," +
			(get_customers_pn_query[0] ?
				"`caller_customer_id` int DEFAULT NULL,\
				`caller_reseller_id` char(10) DEFAULT NULL,\
				`called_customer_id` int DEFAULT NULL,\
				`called_reseller_id` char(10) DEFAULT NULL," :
				"") +
			(extPrecisionBilling ?
				"`price_operator_mult1000000` bigint unsigned DEFAULT NULL,\
				 `price_operator_currency_id` tinyint unsigned DEFAULT NULL,\
				 `price_customer_mult1000000` bigint unsigned DEFAULT NULL,\
				 `price_customer_currency_id` tinyint unsigned DEFAULT NULL," :
				"`price_operator_mult100` int unsigned DEFAULT NULL,\
				 `price_operator_currency_id` tinyint unsigned DEFAULT NULL,\
				 `price_customer_mult100` int unsigned DEFAULT NULL,\
				 `price_customer_currency_id` tinyint unsigned DEFAULT NULL,") + 
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `calldate`)," :
			"PRIMARY KEY (`ID`),") + 
		"KEY `calldate` (`calldate`),\
		KEY `callend` (`callend`),\
		KEY `duration` (`duration`),\
		KEY `source` (`caller`),\
		KEY `source_reverse` (`caller_reverse`),\
		KEY `destination` (`called`),\
		KEY `destination_reverse` (`called_reverse`),\
		KEY `callername` (`callername`),\
		KEY `callername_reverse` (`callername_reverse`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`),\
		" + (opt_save_ip_from_encaps_ipheader ?
		      "KEY `sipcallerip_encaps` (`sipcallerip_encaps`),\
		       KEY `sipcalledip_encaps` (`sipcalledip_encaps`),\
		      " :
		      "") +
		    (opt_separate_storage_ipv6_ipv4_address ?
		      "KEY `sipcallerip_v4` (`sipcallerip_v4`),\
		       KEY `sipcalledip_v4` (`sipcalledip_v4`),\
		       KEY `sipcallerip_v6` (`sipcallerip_v6`),\
		       KEY `sipcalledip_v6` (`sipcalledip_v6`),\
		      " :
		      "") +
		"KEY `lastSIPresponseNum` (`lastSIPresponseNum`),\
		KEY `bye` (`bye`),\
		KEY `a_saddr` (`a_saddr`),\
		KEY `b_saddr` (`b_saddr`)," +
		(opt_disable_cdr_fields_rtp || opt_disable_cdr_indexes_rtp ? "" :
		"KEY `a_lost` (`a_lost`),\
		KEY `b_lost` (`b_lost`),\
		KEY `a_maxjitter` (`a_maxjitter`),\
		KEY `b_maxjitter` (`b_maxjitter`),\
		KEY `a_rtcp_loss` (`a_rtcp_loss`),\
		KEY `a_rtcp_maxfr` (`a_rtcp_maxfr`),\
		KEY `a_rtcp_maxjitter` (`a_rtcp_maxjitter`),\
		KEY `a_rtcp_maxrtd_mult10` (`a_rtcp_maxrtd_mult10`),\
		KEY `b_rtcp_maxrtd_mult10` (`b_rtcp_maxrtd_mult10`),\
		KEY `a_rtcp_maxrtd_w` (`a_rtcp_maxrtd_w`),\
		KEY `b_rtcp_maxrtd_w` (`b_rtcp_maxrtd_w`),\
		KEY `b_rtcp_loss` (`b_rtcp_loss`),\
		KEY `b_rtcp_maxfr` (`b_rtcp_maxfr`),\
		KEY `b_rtcp_maxjitter` (`b_rtcp_maxjitter`),") +
		"KEY `a_ua_id` (`a_ua_id`),\
		KEY `b_ua_id` (`b_ua_id`)," + 
		(opt_disable_cdr_fields_rtp || opt_disable_cdr_indexes_rtp ? "" :
		"KEY `a_avgjitter_mult10` (`a_avgjitter_mult10`),\
		KEY `b_avgjitter_mult10` (`b_avgjitter_mult10`),\
		KEY `a_rtcp_avgjitter_mult10` (`a_rtcp_avgjitter_mult10`),\
		KEY `b_rtcp_avgjitter_mult10` (`b_rtcp_avgjitter_mult10`),") +
		"KEY `lastSIPresponse_id` (`lastSIPresponse_id`),\
		KEY `reason_sip_text_id` (`reason_sip_text_id`),\
		KEY `reason_q850_text_id` (`reason_q850_text_id`),\
		KEY `payload` (`payload`),\
		KEY `vlan` (`vlan`),\
		KEY `id_sensor` (`id_sensor`)" + 
		(get_customers_pn_query[0] ?
				",KEY `caller_customer_id` (`caller_customer_id`),\
				KEY `caller_reseller_id` (`caller_reseller_id`),\
				KEY `called_customer_id` (`called_customer_id`),\
				KEY `called_reseller_id` (`called_reseller_id`)" :
				"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_ibfk_1` FOREIGN KEY (`lastSIPresponse_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `cdr_ibfk_2` FOREIGN KEY (`a_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `cdr_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `cdr_ibfk_4` FOREIGN KEY (`reason_sip_text_id`) REFERENCES `cdr_reason` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `cdr_ibfk_5` FOREIGN KEY (`reason_q850_text_id`) REFERENCES `cdr_reason` (`id`) ON UPDATE CASCADE"
		) +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(opt_cdr_partition) {
		bool tableIsExists = false;
		bool partitionIsExists = false;
		vector<string> cdrMainTables = this->getSourceTables(tt_main | tt_child, tt2_cdr);
		for(size_t i = 0; i < cdrMainTables.size(); i++) {
			if(existsTable(cdrMainTables[i].c_str())) {
				tableIsExists = true;
				if(getPartitions(NULL, NULL, cdrMainTables[i].c_str()) > 0) {
					partitionIsExists = true;
				}
			}
		}
		if(tableIsExists && !partitionIsExists) {
			syslog(LOG_INFO, "disable opt_cdr_partition (tables cdr... does not have partitions)");
			opt_cdr_partition = 0;
		}
	}
	
	string cdrIdType = "bigint";
	if(!opt_cdr_partition) {
		this->query("show columns from cdr like 'id'");
		SqlDb_row cdr_struct_row = this->fetchRow();
		if(cdr_struct_row) {
			string idType = cdr_struct_row["type"];
			std::transform(idType.begin(), idType.end(), idType.begin(), ::toupper);
			if(idType.find("BIG") == string::npos) {
				cdrIdType = "int";
			}
		}
	}
	
	#if VM_IPV6
	extern bool useIPv6;
	string cdrIP_type = this->getTypeColumn("cdr", "sipcallerip", true);;
	bool _useIPv6 = cdrIP_type.find("varbinary") != string::npos;
	if(useIPv6 && !_useIPv6) {
		syslog(LOG_NOTICE, "IPv6 support need varbinary columns for IP addresses!");
	}
	useIPv6 = _useIPv6;
	#endif

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_next` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`custom_header1` varchar(255) DEFAULT NULL,\
			`fbasename` varchar(255) DEFAULT NULL,\
			`digest_username` varchar(255) DEFAULT NULL,\
			`match_header` VARCHAR(128) DEFAULT NULL,\
			`GeoPosition` varchar(255) DEFAULT NULL, \
			`hold` varchar(1024) DEFAULT NULL, \
			`spool_index` tinyint unsigned DEFAULT NULL," +
			(opt_conference_processing ?
				"`conference_flag` enum('main','leg') DEFAULT NULL,\
				 `conference_referred_by` varchar(1024) DEFAULT NULL,\
				 `conference_referred_by_ok_time` " + column_type_datetime_ms() + " DEFAULT NULL," :
				"") +
			(opt_mo_mt_identification_prefix.size() ?
				"`leg_flag` enum('mo','mt') DEFAULT NULL," :
				"") +
			(srvcc_set ?
				"`srvcc_call_id` varchar(255) DEFAULT NULL,\
				 `srvcc_flag` enum('post_srvcc','pre_srvcc') DEFAULT NULL," :
				"") +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`cdr_ID`, `calldate`)," :
			"PRIMARY KEY (`cdr_ID`),") +
		"KEY `fbasename` (`fbasename`),\
		 KEY `digest_username` (`digest_username`),\
		 KEY `match_header` (`match_header`)" + 
		(opt_conference_processing ?
			",KEY `conference_referred_by` (`conference_referred_by`)" :
			"") +
		(srvcc_set ?
			",KEY `srvcc_call_id` (`srvcc_call_id`)\
			 ,KEY `srvcc_flag` (`srvcc_flag`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_next_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	sql_noerror = 1;
	for(size_t iCustHeaders = 0; iCustHeaders < opt_custom_headers_cdr.size(); iCustHeaders++) {
		this->query(string(
		"ALTER TABLE `cdr_next`\
			ADD COLUMN `") + opt_custom_headers_cdr[iCustHeaders][1] + "` VARCHAR(255);");
	}
	sql_noerror = 0;

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_proxy` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,\
			`calldate` " + column_type_datetime_child_ms() + " NOT NULL,\
			`dst` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY `cdr_ID` (`cdr_ID`),\
		KEY `calldate` (`calldate`),\
		KEY `dst` (`dst`)" + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_proxy_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress  + 
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_next_branches` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") +
			"`caller` varchar(255) DEFAULT NULL,\
			`caller_domain` varchar(255) DEFAULT NULL,\
			`caller_reverse` varchar(255) DEFAULT NULL,\
			`callername` varchar(255) DEFAULT NULL,\
			`callername_reverse` varchar(255) DEFAULT NULL,\
			`called` varchar(255) DEFAULT NULL,\
			`called_domain` varchar(255) DEFAULT NULL,\
			`called_reverse` varchar(255) DEFAULT NULL,\
			`sipcallerip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sipcallerport` smallint unsigned DEFAULT NULL,\
			`sipcalledip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sipcalledport` smallint unsigned DEFAULT NULL,\
			" + (opt_save_ip_from_encaps_ipheader ?
			      string(
			      "`sipcallerip_encaps` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledip_encaps` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			       `sipcalledip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			      " :
			      "") +
			    (opt_separate_storage_ipv6_ipv4_address ?
			      string(
			      "`sipcallerip_v4` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerport_v4` smallint unsigned DEFAULT NULL,\
			       `sipcalledip_v4` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledport_v4` smallint unsigned DEFAULT NULL,\
			       `sipcallerip_v6` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerport_v6` smallint unsigned DEFAULT NULL,\
			       `sipcalledip_v6` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledport_v6` smallint unsigned DEFAULT NULL,\
			      " :
			      "") +
			(opt_cdr_country_code == 2 ?
				"`sipcallerip_country_code` smallint,\
				`sipcalledip_country_code` smallint,\
				`caller_number_country_code` smallint,\
				`called_number_country_code` smallint," :
			(opt_cdr_country_code == 1 ?
				"`sipcallerip_country_code` varchar(5),\
				`sipcalledip_country_code` varchar(5),\
				`caller_number_country_code` varchar(5),\
				`called_number_country_code` varchar(5)," :
				"")) +
			"`proxyip_1` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`proxyip_2` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`proxyip_3` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`whohanged` enum('caller','callee') DEFAULT NULL,\
			`bye` tinyint unsigned DEFAULT NULL,\
			`lastSIPresponse_id` mediumint unsigned DEFAULT NULL,\
			`lastSIPresponseNum` smallint unsigned DEFAULT NULL,\
			`reason_sip_cause` smallint unsigned DEFAULT NULL,\
			`reason_sip_text_id` mediumint unsigned DEFAULT NULL,\
			`reason_q850_cause` smallint unsigned DEFAULT NULL,\
			`reason_q850_text_id` mediumint unsigned DEFAULT NULL,\
			`a_ua_id` int unsigned DEFAULT NULL,\
			`b_ua_id` int unsigned DEFAULT NULL,\
			`call_id` varchar(255) DEFAULT NULL,\
			`fbasename` varchar(255) DEFAULT NULL,\
			`custom_header1` varchar(255) DEFAULT NULL,\
			`match_header` VARCHAR(128) DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)," + 
		(opt_cdr_partition ? 
			"KEY (`calldate`)," :
			"") +
		"KEY `source` (`caller`),\
		KEY `source_reverse` (`caller_reverse`),\
		KEY `destination` (`called`),\
		KEY `destination_reverse` (`called_reverse`),\
		KEY `callername` (`callername`),\
		KEY `callername_reverse` (`callername_reverse`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`),\
		" + (opt_save_ip_from_encaps_ipheader ?
		      "KEY `sipcallerip_encaps` (`sipcallerip_encaps`),\
		       KEY `sipcalledip_encaps` (`sipcalledip_encaps`),\
		      " :
		      "") +
		    (opt_separate_storage_ipv6_ipv4_address ?
		      "KEY `sipcallerip_v4` (`sipcallerip_v4`),\
		       KEY `sipcalledip_v4` (`sipcalledip_v4`),\
		       KEY `sipcallerip_v6` (`sipcallerip_v6`),\
		       KEY `sipcalledip_v6` (`sipcalledip_v6`),\
		      " :
		      "") +
		    (opt_cdr_country_code ?
		      "KEY(`sipcallerip_country_code`),\
		       KEY(`sipcalledip_country_code`),\
		       KEY(`caller_number_country_code`),\
		       KEY(`called_number_country_code`),\
		      " :
		      "") +
		"KEY `lastSIPresponseNum` (`lastSIPresponseNum`),\
		 KEY `call_id` (`call_id`),\
		 KEY `fbasename` (`fbasename`)" +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_next_branches_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_rtp` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`saddr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sport` smallint unsigned DEFAULT NULL,\
			`daddr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`dport` smallint unsigned DEFAULT NULL,\
			`ssrc` int unsigned DEFAULT NULL,\
			`received` mediumint unsigned DEFAULT NULL,\
			`loss` mediumint unsigned DEFAULT NULL,\
			`firsttime` " + column_type_duration_ms("float") + " DEFAULT NULL,\
			`payload` smallint unsigned DEFAULT NULL,\
			`maxjitter_mult10` smallint unsigned DEFAULT NULL,\
			`index` tinyint unsigned DEFAULT NULL,\
			`sdp_ptime` tinyint unsigned DEFAULT NULL,\
			`rtp_ptime` tinyint unsigned DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,\
			`duration` " + column_type_duration_ms("float") + " DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_rtp_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(opt_save_energylevels) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_rtp_energylevels` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`index` tinyint unsigned DEFAULT NULL,\
			`energylevels` mediumblob,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_rtp_energylevels_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_dtmf` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`daddr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`saddr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`firsttime` " + column_type_duration_ms("float") + " DEFAULT NULL,\
			`dtmf` char DEFAULT NULL,\
			`type` tinyint unsigned DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_dtmf_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_sipresp` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`SIPresponse_id` mediumint unsigned DEFAULT NULL,\
			`SIPresponseNum` smallint unsigned DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" +
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_sipresp_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	if(_save_sip_history) {
		this->query(string(
		"CREATE TABLE IF NOT EXISTS `cdr_siphistory` (\
				" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
				`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
				(opt_cdr_partition ?
					"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
					"") + 
				"`time` bigint unsigned DEFAULT NULL,\
				`SIPrequest_id` mediumint unsigned DEFAULT NULL,\
				`SIPresponse_id` mediumint unsigned DEFAULT NULL,\
				`SIPresponseNum` smallint unsigned DEFAULT NULL,\
			" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
			KEY (`cdr_ID`)" + 
			(opt_cdr_partition ? 
				",KEY (`calldate`)" :
				"") +
			(opt_cdr_partition ?
				"" :
				",CONSTRAINT `cdr_siphistory_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
		") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
		(opt_cdr_partition ?
			(opt_cdr_partition_by_hours ?
				string(" PARTITION BY RANGE COLUMNS(calldate)(\
					 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
					 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
			 opt_cdr_partition_oldver ? 
				string(" PARTITION BY RANGE (to_days(calldate))(\
					 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
				string(" PARTITION BY RANGE COLUMNS(calldate)(\
					 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
			""));
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_tar_part` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`type` tinyint unsigned DEFAULT NULL,\
			`pos` bigint unsigned DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_tar_part_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_country_code` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			(opt_cdr_country_code == 2 ?
				"`sipcallerip_country_code` smallint,\
				`sipcalledip_country_code` smallint,\
				`caller_number_country_code` smallint,\
				`called_number_country_code` smallint," :
				"`sipcallerip_country_code` varchar(5),\
				`sipcalledip_country_code` varchar(5),\
				`caller_number_country_code` varchar(5),\
				`called_number_country_code` varchar(5),") +
		(opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`cdr_ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + 
		"KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
			",KEY(`sipcallerip_country_code`),\
			KEY(`sipcalledip_country_code`),\
			KEY(`caller_number_country_code`),\
			KEY(`called_number_country_code`)" +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_country_code_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_sdp` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`ip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`port` smallint unsigned DEFAULT NULL,\
			`is_caller` tinyint unsigned DEFAULT NULL,\
			`ptime` tinyint unsigned DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
			",KEY(`ip`),\
			KEY(`port`),\
			KEY(`is_caller`)" +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_sdp_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	if(opt_conference_processing) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_conference` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
		       "`user_entity` varchar(1024) DEFAULT NULL,\
			`endpoint_entity` varchar(1024) DEFAULT NULL,\
			`connect_time` " + column_type_datetime_ms() + " DEFAULT NULL,\
			`disconnect_time` " + column_type_datetime_ms() + " DEFAULT NULL," + 
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `calldate`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_conference_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	}
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_txt` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`time` bigint unsigned DEFAULT NULL,\
			`type` tinyint unsigned DEFAULT NULL,\
			`content` mediumtext DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_txt_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_flags` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + cdrIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`deleted` smallint unsigned DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_flags_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_audio_transcribe` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`calldate` " + column_type_datetime_child_ms() + " NOT NULL,\
			`fbasename` varchar(255) DEFAULT NULL,\
			`a_language` varchar(10) DEFAULT NULL,\
			`b_language` varchar(10) DEFAULT NULL,\
			`a_text` mediumtext DEFAULT NULL,\
			`b_text` mediumtext DEFAULT NULL,\
			`a_segments` mediumtext DEFAULT NULL,\
			`b_segments` mediumtext DEFAULT NULL,") +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `calldate`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY `fbasename` (`fbasename`)\
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(opt_cdr_stat_values) {
	for(int src_dst = 0; src_dst < 2; src_dst++) {
	if(cCdrStat::enableBySrcDst(src_dst)) {
	string cdr_stat_fields_str = cCdrStat::metrics_db_fields();
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_stat_values") + cCdrStat::tableNameSuffix(src_dst) + "` (\
			`from_time` datetime,\
			`addr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`sensor_id` int,\
			`created_at` datetime,\
			`updated_at` datetime,\
			`updated_counter` smallint unsigned,\
			" + cdr_stat_fields_str + "\
			" + (opt_cdr_force_primary_index_in_all_tables ? "PRIMARY KEY" : "UNIQUE KEY `comb_1`") + "(`from_time`,`addr`,`sensor_id`,`created_at`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(supportPartitions != _supportPartitions_na ?
		(opt_cdr_stat_values_partition_oldver[src_dst] ? 
			string(" PARTITION BY RANGE (to_days(`from_time`))(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN (to_days('" + limitMonth + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(`from_time`)(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN ('" + limitMonth + "') engine innodb)") :
		""));
	}}}
	if(opt_cdr_stat_sources) {
	for(int src_dst = 0; src_dst < 2; src_dst++) {
	if(cCdrStat::enableBySrcDst(src_dst)) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_stat_sources") + cCdrStat::tableNameSuffix(src_dst) + "` (\
			`from_time` datetime,\
			`addr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`series` int unsigned NOT NULL,\
			`sensor_id` int,\
			`created_at` datetime,\
			`updated_at` datetime,\
			`updated_counter` smallint unsigned,\
			`count_all` int unsigned,\
			`count_connected` int unsigned,\
			`data` mediumtext,\
			" + (opt_cdr_force_primary_index_in_all_tables ? "PRIMARY KEY" : "UNIQUE KEY `comb_1`") + "(`from_time`,`addr`,`series`,`sensor_id`,`created_at`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(supportPartitions != _supportPartitions_na ?
		(opt_cdr_stat_sources_partition_oldver[src_dst] ? 
			string(" PARTITION BY RANGE (to_days(`from_time`))(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN (to_days('" + limitMonth + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(`from_time`)(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN ('" + limitMonth + "') engine innodb)") :
		""));	 
	}}}
	
	if(opt_cdr_problems) {
	string cdr_problems_fields_str = cCdrProblems::db_fields();
	if(opt_cdr_problems_by_ip) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_problems_by_ip` (\
			`from_time` datetime,\
			`type` enum('from_own_clients','from_own_servers','from_public_trunks'),\
			`side` enum('src','dst'),\
			`addr` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sensor_id` int,\
			`created_at` datetime,\
			`updated_at` datetime,\
			`updated_counter` smallint unsigned,\
			" + cdr_problems_fields_str + "\
			" + (opt_cdr_force_primary_index_in_all_tables ? "PRIMARY KEY" : "UNIQUE KEY `comb_1`") + "(`from_time`,`type`,`side`,`addr`,`sensor_id`,`created_at`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(supportPartitions != _supportPartitions_na ?
		(opt_cdr_problems_partition_oldver[0] ? 
			string(" PARTITION BY RANGE (to_days(`from_time`))(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN (to_days('" + limitMonth + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(`from_time`)(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN ('" + limitMonth + "') engine innodb)") :
		""));
	}
	if(opt_cdr_problems_by_number) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_problems_by_number` (\
			`from_time` datetime,\
			`type` enum('from_own_clients','from_own_servers','from_public_trunks'),\
			`side` enum('src','dst'),\
			`number` varchar(255) DEFAULT NULL,\
			`sensor_id` int,\
			`created_at` datetime,\
			`updated_at` datetime,\
			`updated_counter` smallint unsigned,") + "\
			" + cdr_problems_fields_str + "\
			" + (opt_cdr_force_primary_index_in_all_tables ? "PRIMARY KEY" : "UNIQUE KEY `comb_1`") + "(`from_time`,`type`,`side`,`number`,`sensor_id`,`created_at`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(supportPartitions != _supportPartitions_na ?
		(opt_cdr_problems_partition_oldver[1] ? 
			string(" PARTITION BY RANGE (to_days(`from_time`))(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN (to_days('" + limitMonth + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(`from_time`)(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN ('" + limitMonth + "') engine innodb)") :
		""));
	}
	if(opt_cdr_problems_by_comb) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_problems_by_comb` (\
			`from_time` datetime,\
			`side` enum('src','dst'),\
			`type` enum('from_own_clients','from_own_servers','from_public_trunks'),\
			`addr` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`number` varchar(255) DEFAULT NULL,\
			`sensor_id` int,\
			`created_at` datetime,\
			`updated_at` datetime,\
			`updated_counter` smallint unsigned,\
			" + cdr_problems_fields_str + "\
			" + (opt_cdr_force_primary_index_in_all_tables ? "PRIMARY KEY" : "UNIQUE KEY `comb_1`") + "(`from_time`,`type`,`side`,`addr`,`number`,`sensor_id`,`created_at`),\
			KEY `comb_2` (`from_time`,`type`,`side`,`number`,`addr`,`sensor_id`),\
			KEY `comb_3` (`from_time`,`type`,`side`,`addr`,`sensor_id`),\
			KEY `comb_4` (`from_time`,`type`,`side`,`number`,`sensor_id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(supportPartitions != _supportPartitions_na ?
		(opt_cdr_problems_partition_oldver[2] ? 
			string(" PARTITION BY RANGE (to_days(`from_time`))(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN (to_days('" + limitMonth + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(`from_time`)(\
				 PARTITION ") + partMonthName + " VALUES LESS THAN ('" + limitMonth + "') engine innodb)") :
		""));
	}
	}
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `rtp_stat` (\
			`id_sensor` smallint unsigned NOT NULL,\
			`time` datetime NOT NULL,\
			`saddr` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`mosf1_min` tinyint unsigned NOT NULL,\
			`mosf1_avg` tinyint unsigned NOT NULL,\
			`mosf2_min` tinyint unsigned NOT NULL,\
			`mosf2_avg` tinyint unsigned NOT NULL,\
			`mosAD_min` tinyint unsigned NOT NULL,\
			`mosAD_avg` tinyint unsigned NOT NULL,\
			`jitter_max` smallint unsigned NOT NULL,\
			`jitter_avg` smallint unsigned NOT NULL,\
			`loss_max_mult10` smallint unsigned NOT NULL,\
			`loss_avg_mult10` smallint unsigned NOT NULL,\
			`counter` mediumint unsigned NOT NULL,\
			PRIMARY KEY (`time`, `saddr`, `id_sensor`),\
			KEY `time` (`time`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(supportPartitions != _supportPartitions_na ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(time)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_rtp_stat_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(`time`))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(`time`)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `contenttype` (\
			`id` int unsigned NOT NULL AUTO_INCREMENT,\
			`contenttype` varchar(255) DEFAULT NULL,\
		PRIMARY KEY (`id`),\
		KEY `contenttype` (`contenttype`)\
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 ") + compress + ";");

	if(opt_enable_ss7) {
		this->query(string(
		"CREATE TABLE IF NOT EXISTS `ss7` (\
				`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
				`time_iam` " + column_type_datetime_ms() + " NOT NULL,\
				`time_acm` " + column_type_datetime_ms() + ",\
				`time_cpg` " + column_type_datetime_ms() + ",\
				`time_anm` " + column_type_datetime_ms() + ",\
				`time_rel` " + column_type_datetime_ms() + ",\
				`time_rlc` " + column_type_datetime_ms() + ",\
				`duration` " + column_type_duration_ms() + " unsigned,\
				`connect_duration` " + column_type_duration_ms() + " unsigned,\
				`progress_time` " + column_type_duration_ms() + " unsigned,\
				`cic` int unsigned,\
				`satellite_indicator` int unsigned,\
				`echo_control_device_indicator` int unsigned,\
				`caller_partys_category` int unsigned,\
				`caller_party_nature_of_address_indicator` int unsigned,\
				`ni_indicator` int unsigned,\
				`address_presentation_restricted_indicator` int unsigned,\
				`screening_indicator` int unsigned,\
				`transmission_medium_requirement` int unsigned,\
				`called_party_nature_of_address_indicator` int unsigned,\
				`inn_indicator` int unsigned,\
				`m3ua_protocol_data_opc` int unsigned,\
				`m3ua_protocol_data_dpc` int unsigned,\
				`mtp3_opc` int unsigned,\
				`mtp3_dpc` int unsigned,\
				`opc` int unsigned,\
				`dpc` int unsigned,\
				`called_number` varchar(255),\
				`caller_number` varchar(255),\
				`called_number_reverse` varchar(255),\
				`caller_number_reverse` varchar(255),\
				`called_number_country_code` varchar(5),\
				`caller_number_country_code` varchar(5),\
				`rel_cause_indicator` int unsigned,\
				`state` enum('call_setup','in_call','completed','rejected','canceled'),\
				`last_message_type` enum('iam','acm','cpg','anm','rel','rlc'),\
				`src_ip` ") + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
				`dst_ip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
				`src_ip_country_code` varchar(5),\
				`dst_ip_country_code` varchar(5),\
				`ss7_id` varchar(255),\
				`pcap_filename` varchar(255),\
				`id_sensor` smallint unsigned,\
				`flags` bigint unsigned DEFAULT NULL," +
			(supportPartitions != _supportPartitions_na ?
				"PRIMARY KEY (`ID`, `time_iam`)," :
				"PRIMARY KEY (`ID`),") + 
			"KEY `time_iam` (`time_iam`)"\
		") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress + 
		(supportPartitions != _supportPartitions_na ?
			(opt_cdr_partition_by_hours ?
				string(" PARTITION BY RANGE COLUMNS(time_iam)(\
					 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
					 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
			 opt_ss7_partition_oldver ? 
				string(" PARTITION BY RANGE (to_days(time_iam))(\
					 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
				string(" PARTITION BY RANGE COLUMNS(time_iam)(\
					 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
			""));
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `message` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`id_contenttype` int unsigned NOT NULL,\
			`calldate`" ) + column_type_datetime_ms() + " NOT NULL,\
			`caller` varchar(255) DEFAULT NULL,\
			`caller_domain` varchar(255) DEFAULT NULL,\
			`caller_reverse` varchar(255) DEFAULT NULL,\
			`callername` varchar(255) DEFAULT NULL,\
			`callername_reverse` varchar(255) DEFAULT NULL,\
			`called` varchar(255) DEFAULT NULL,\
			`called_domain` varchar(255) DEFAULT NULL,\
			`called_reverse` varchar(255) DEFAULT NULL,\
			`sipcallerip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sipcalledip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`bye` tinyint unsigned DEFAULT NULL,\
			`lastSIPresponse_id` mediumint unsigned DEFAULT NULL,\
			`lastSIPresponseNum` smallint unsigned DEFAULT NULL,\
			`id_sensor` smallint unsigned DEFAULT NULL,\
			`vlan` smallint DEFAULT NULL,\
			`a_ua_id` int unsigned DEFAULT NULL,\
			`b_ua_id` int unsigned DEFAULT NULL,\
			`fbasename` varchar(255) DEFAULT NULL,\
			`message` MEDIUMTEXT CHARACTER SET utf8,\
			`content_length` MEDIUMINT DEFAULT NULL,\
			`response_time` SMALLINT UNSIGNED DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `calldate`)," :
			"PRIMARY KEY (`ID`),") + 
		"KEY `id_contenttype` (`id_contenttype`),\
		KEY `calldate` (`calldate`),\
		KEY `caller` (`caller`),\
		KEY `caller_domain` (`caller_domain`),\
		KEY `caller_reverse` (`caller_reverse`),\
		KEY `callername` (`callername`),\
		KEY `callername_reverse` (`callername_reverse`),\
		KEY `called` (`called`),\
		KEY `called_reverse` (`called_reverse`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`),\
		KEY `lastSIPresponseNum` (`lastSIPresponseNum`),\
		KEY `bye` (`bye`),\
		KEY `lastSIPresponse_id` (`lastSIPresponse_id`),\
		KEY `id_sensor` (`id_sensor`),\
		KEY `vlan` (`vlan`),\
		KEY `a_ua_id` (`a_ua_id`),\
		KEY `b_ua_id` (`b_ua_id`),\
		KEY `fbasename` (`fbasename`)" +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`lastSIPresponse_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`a_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `messages_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `messages_ibfk_4` FOREIGN KEY (`id_contenttype`) REFERENCES `contenttype` (`id`) ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress + 
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	sql_noerror = 1;
	for(size_t iCustHeaders = 0; iCustHeaders < opt_custom_headers_message.size(); iCustHeaders++) {
		this->query(string(
		"ALTER TABLE `message`\
			ADD COLUMN `") + opt_custom_headers_message[iCustHeaders][1] + "` VARCHAR(255);");
	}
	sql_noerror = 0;

	string messageIdType = "bigint";
	if(!opt_cdr_partition) {
		this->query("show columns from message like 'id'");
		SqlDb_row message_struct_row = this->fetchRow();
		if(message_struct_row) {
			string idType = message_struct_row["type"];
			std::transform(idType.begin(), idType.end(), idType.begin(), ::toupper);
			if(idType.find("BIG") == string::npos) {
				messageIdType = "int";
			}
		}
	}
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `message_proxy` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + messageIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`message_ID` " + messageIdType + " unsigned NOT NULL,\
			`calldate` " + column_type_datetime_child_ms() + " NOT NULL,\
			`dst` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY `message_ID` (`message_ID`),\
		KEY `calldate` (`calldate`),\
		KEY `dst` (`dst`)" + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `message_proxy_ibfk_1` FOREIGN KEY (`message_ID`) REFERENCES `message` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress  + 
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `message_country_code` (\
			`message_ID` " + messageIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			(opt_message_country_code == 2 ?
				"`sipcallerip_country_code` smallint,\
				`sipcalledip_country_code` smallint,\
				`caller_number_country_code` smallint,\
				`called_number_country_code` smallint," :
				"`sipcallerip_country_code` varchar(5),\
				`sipcalledip_country_code` varchar(5),\
				`caller_number_country_code` varchar(5),\
				`called_number_country_code` varchar(5),") +
		(opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`message_ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + 
		"KEY (`message_ID`)" +
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		",KEY(`sipcallerip_country_code`),\
		KEY(`sipcalledip_country_code`),\
		KEY(`caller_number_country_code`),\
		KEY(`called_number_country_code`)" +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `message_country_code_ibfk_1` FOREIGN KEY (`message_ID`) REFERENCES `message` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `message_flags` (\
			" + (opt_cdr_force_primary_index_in_all_tables ? "`ID` " + messageIdType + " unsigned NOT NULL AUTO_INCREMENT," : "") + "\
			`message_ID` " + messageIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`deleted` smallint unsigned DEFAULT NULL,\
		" + (opt_cdr_force_primary_index_in_all_tables ? string("PRIMARY KEY (`ID`") + (opt_cdr_partition ? ",`calldate`" : "") + ")," : "") + "\
		KEY (`message_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `message_flags_ibfk_1` FOREIGN KEY (`message_ID`) REFERENCES `message` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(opt_sip_register == 2) {
	string compress_memory = getOptimalCompressType(true);
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned NOT NULL,\
			`fname` BIGINT NULL default NULL,\
			`calldate` ") + column_type_datetime_ms() + " NOT NULL,\
			`sipcallerip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`sipcalledip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`from_num` varchar(255) NULL DEFAULT NULL,\
			`from_name` varchar(255) NULL DEFAULT NULL,\
			`from_domain` varchar(255) NULL DEFAULT NULL,\
			`to_num` varchar(255) NULL DEFAULT NULL,\
			`to_domain` varchar(255) NULL DEFAULT NULL,\
			`contact_num` varchar(255) NULL DEFAULT NULL,\
			`contact_domain` varchar(255) NULL DEFAULT NULL,\
			`digestusername` varchar(255) NULL DEFAULT NULL,\
			`digestrealm` varchar(255) NULL DEFAULT NULL,\
			`expires`     mediumint NULL DEFAULT NULL,\
			`expires_at`  datetime NULL DEFAULT NULL,\
			`state`  tinyint unsigned NULL DEFAULT NULL,\
			`ua_id` int unsigned DEFAULT NULL,\
			`rrd_avg` mediumint unsigned DEFAULT NULL,\
			`rrd_count` tinyint unsigned DEFAULT NULL,\
			`src_mac` bigint unsigned DEFAULT NULL,\
		PRIMARY KEY (`ID`),\
		KEY `calldate` (`calldate`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`),\
		KEY `from_num` (`from_num`),\
		KEY `digestusername` (`digestusername`),\
		KEY `rrd_avg` (`rrd_avg`),\
		KEY `src_mac` (`src_mac`)\
	) ENGINE=MEMORY DEFAULT CHARSET=latin1 " + compress + ";");
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register_state` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned NOT NULL,\
			`fname` BIGINT NULL default NULL,\
			") + (opt_sip_register_save_eq_states_time ? "`counter` int DEFAULT 0," : "") + 
			"`created_at` " + column_type_datetime_ms() + " NOT NULL,\
			`sipcallerip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`sipcalledip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			" + (opt_save_ip_from_encaps_ipheader ?
			      string(
			      "`sipcallerip_encaps` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledip_encaps` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			       `sipcalledip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			      " :
			      "") + 
			"`sipcallerport` smallint unsigned DEFAULT NULL,\
			`sipcalledport` smallint unsigned DEFAULT NULL,\
			`from_num` varchar(255) NULL DEFAULT NULL,\
			`to_num` varchar(255) NULL DEFAULT NULL,\
			`contact_num` varchar(255) NULL DEFAULT NULL,\
			`contact_domain` varchar(255) NULL DEFAULT NULL,\
			`digestusername` varchar(255) NULL DEFAULT NULL,\
			`digestrealm` varchar(255) NULL DEFAULT NULL,\
			`expires` mediumint NULL DEFAULT NULL,\
			`state` tinyint unsigned NULL DEFAULT NULL,\
			`ua_id` int unsigned DEFAULT NULL,\
			`to_domain` varchar(255) NULL DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,\
			`vlan` smallint DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `created_at`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY `created_at` (`created_at`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`),\
		" + (opt_save_ip_from_encaps_ipheader ?
		      "KEY `sipcallerip_encaps` (`sipcallerip_encaps`),\
		       KEY `sipcalledip_encaps` (`sipcalledip_encaps`),\
		      " :
		      "") +
		"KEY `vlan` (`vlan`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(created_at))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));

	if(opt_sip_register_save_eq_states_time) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register_state_eq_next` (\
			`register_state_ID` bigint unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`created_at` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`order` int DEFAULT NULL,\
			`next_at` " + column_type_datetime_child_ms() + " DEFAULT NULL,\
			`fname` BIGINT NULL default NULL,\
			`id_sensor` int unsigned NOT NULL,\
		KEY (`register_state_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`created_at`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `register_state_eq_next_ibfk_1` FOREIGN KEY (`register_state_ID`) REFERENCES `register_state` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(created_at))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register_failed` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned NOT NULL,\
			`fname` BIGINT NULL default NULL,\
			`counter` int DEFAULT 0,\
			`created_at` ") + column_type_datetime_ms() + " NOT NULL,\
			`sipcallerip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`sipcalledip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			" + (opt_save_ip_from_encaps_ipheader ?
			      string(
			      "`sipcallerip_encaps` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcalledip_encaps` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			       `sipcallerip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			       `sipcalledip_encaps_prot` tinyint unsigned DEFAULT NULL,\
			      " :
			      "") +
			"`sipcallerport` smallint unsigned DEFAULT NULL,\
			`sipcalledport` smallint unsigned DEFAULT NULL,\
			`from_num` varchar(255) NULL DEFAULT NULL,\
			`to_num` varchar(255) NULL DEFAULT NULL,\
			`contact_num` varchar(255) NULL DEFAULT NULL,\
			`contact_domain` varchar(255) NULL DEFAULT NULL,\
			`digestusername` varchar(255) NULL DEFAULT NULL,\
			`digestrealm` varchar(255) NULL DEFAULT NULL,\
			`ua_id` int unsigned DEFAULT NULL,\
			`to_domain` varchar(255) NULL DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,\
			`vlan` smallint DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `created_at`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY `created_at` (`created_at`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`),\
		" + (opt_save_ip_from_encaps_ipheader ?
		      "KEY `sipcallerip_encaps` (`sipcallerip_encaps`),\
		       KEY `sipcalledip_encaps` (`sipcalledip_encaps`),\
		      " :
		      "") +
		"KEY `vlan` (`vlan`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(created_at))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));
	
	if(opt_sip_register_save_eq_states_time) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register_failed_eq_next` (\
			`register_failed_ID` bigint unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`created_at` " + column_type_datetime_child_ms() + " NOT NULL," :
				"") + 
			"`order` int DEFAULT NULL,\
			`next_at` " + column_type_datetime_child_ms() + " DEFAULT NULL,\
			`fname` BIGINT NULL default NULL,\
			`id_sensor` int unsigned NOT NULL,\
		KEY (`register_failed_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`created_at`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `register_failed_eq_next_ibfk_1` FOREIGN KEY (`register_failed_ID`) REFERENCES `register_failed` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(created_at))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	}
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register_time_info` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`created_at` datetime NOT NULL,\
			`type_info` enum('failed','active'),\
			`id_sensor` int unsigned NOT NULL,\
			`sipcallerip` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`sipcalledip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`counter` int DEFAULT NULL,\
			`counter_2` int DEFAULT NULL," + 
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `created_at`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY `created_at` (`created_at`),\
		KEY `type_info` (`type_info`),\
		KEY `id_sensor` (`id_sensor`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(created_at))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `sip_msg` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`time` " + column_type_datetime_ms() + " NOT NULL,\
			`type` tinyint unsigned NOT NULL,\
			`ip_src` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`ip_dst` " + VM_IPV6_TYPE_MYSQL_COLUMN + " DEFAULT NULL,\
			`ip_src_country_code` varchar(5),\
			`ip_dst_country_code` varchar(5),\
			`port_src` smallint unsigned DEFAULT NULL,\
			`port_dst` smallint unsigned DEFAULT NULL,\
			`number_src` varchar(255) DEFAULT NULL,\
			`number_dst` varchar(255) DEFAULT NULL,\
			`number_src_country_code` varchar(5),\
			`number_dst_country_code` varchar(5),\
			`domain_src` varchar(255) DEFAULT NULL,\
			`domain_dst` varchar(255) DEFAULT NULL,\
			`ua_src_id` int unsigned DEFAULT NULL,\
			`ua_dst_id` int unsigned DEFAULT NULL,\
			`callername` varchar(255),\
			`callid` varchar(255),\
			`cseq` int unsigned DEFAULT NULL,\
			`request_id_content_type` mediumint unsigned DEFAULT NULL,\
			`request_content_length` mediumint unsigned DEFAULT NULL,\
			`request_content` mediumtext DEFAULT NULL,\
			`response_id_content_type` mediumint unsigned DEFAULT NULL,\
			`response_content_length` mediumint DEFAULT NULL,\
			`response_content` mediumtext DEFAULT NULL,\
			`response_number` smallint unsigned DEFAULT NULL,\
			`response_id` mediumint unsigned DEFAULT NULL,\
			`time_us` bigint unsigned DEFAULT NULL,\
			`request_repetition` smallint unsigned DEFAULT NULL,\
			`request_time` " + column_type_datetime_ms() + " DEFAULT NULL,\
			`request_time_us` int unsigned DEFAULT NULL,\
			`response_time` " + column_type_datetime_ms() + " DEFAULT NULL,\
			`response_time_us` int unsigned DEFAULT NULL,\
			`response_duration_ms` int unsigned DEFAULT NULL,\
			`qualify_ok` tinyint unsigned DEFAULT NULL,\
			`id_sensor` smallint unsigned DEFAULT NULL,\
			`vlan` smallint DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `time`)," :
			"PRIMARY KEY (`ID`),") + 
		"KEY `type` (`type`),\
		KEY `time` (`time`),\
		KEY `ip_src` (`ip_src`),\
		KEY `ip_dst` (`ip_dst`),\
		KEY `number_src` (`number_src`),\
		KEY `number_dst` (`number_dst`),\
		KEY `domain_src` (`number_src`),\
		KEY `domain_dst` (`number_dst`),\
		KEY `ua_src_id` (`ua_src_id`),\
		KEY `ua_dst_id` (`ua_dst_id`),\
		KEY `callername` (`callername`),\
		KEY `callid` (`callid`),\
		KEY `cseq` (`cseq`),\
		KEY `response_number` (`response_number`),\
		KEY `response_id` (`response_id`),\
		KEY `vlan` (`vlan`),\
		KEY `id_sensor` (`id_sensor`)" +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `sip_msg_ibfk_1` FOREIGN KEY (`response_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `sip_msg_ibfk_2` FOREIGN KEY (`ua_src_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `sip_msg_ibfk_3` FOREIGN KEY (`ua_dst_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress + 
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(time)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(time))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(time)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	this->query("CREATE TABLE IF NOT EXISTS `sensors` (\
			`id_sensor` int unsigned NOT NULL,\
			`name` varchar(256) NULL DEFAULT NULL,\
			`host` varchar(255) NULL DEFAULT NULL,\
			`port` int NULL DEFAULT NULL,\
			`timezone_name` varchar(64) NULL DEFAULT NULL,\
			`timezone_offset` int NULL DEFAULT NULL,\
			`timezone_save_at` datetime NULL DEFAULT NULL,\
		PRIMARY KEY (`id_sensor`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	this->query("CREATE TABLE IF NOT EXISTS `system` (\
			`id` int NOT NULL auto_increment,\
			`type` text default NULL,\
			`cdate` date default NULL,\
			`cdatetime` datetime default NULL,\
			`content` text default NULL,\
			PRIMARY KEY  (`id`)\
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	if(opt_ipaccount) {
	 
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `ipacc` (\
			`saddr` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`src_id_customer` int unsigned NOT NULL DEFAULT 0,\
			`daddr` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`dst_id_customer` int unsigned NOT NULL DEFAULT 0,\
			`port` smallint unsigned NOT NULL,\
			`proto` smallint unsigned NOT NULL,\
			`octects` int unsigned NOT NULL,\
			`numpackets` mediumint unsigned NOT NULL,\
			`interval_time` datetime NOT NULL,\
			`voip` tinyint unsigned NOT NULL DEFAULT 0,\
			`do_agr_trigger` tinyint NOT NULL DEFAULT 0,\
		KEY `saddr` (`saddr`),\
		KEY `src_id_customer` (`src_id_customer`),\
		KEY `daddr` (`daddr`),\
		KEY `dst_id_customer` (`dst_id_customer`),\
		KEY `port` (`port`),\
		KEY `proto` (`proto`),\
		KEY `interval_time` (`interval_time`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition_oldver ?
		string(" PARTITION BY RANGE (to_days(interval_time))(\
			 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
		string(" PARTITION BY RANGE COLUMNS(interval_time)(\
			 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)"));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS ipacc_agr_interval (\
			interval_time datetime,\
			addr ")  + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			customer_id int unsigned,\
			proto smallint unsigned,\
			port smallint unsigned,\
			traffic_in bigint,\
			traffic_out bigint,\
			traffic_sum bigint,\
			packets_in bigint,\
			packets_out bigint,\
			packets_sum bigint,\
			traffic_voip_in bigint,\
			traffic_voip_out bigint,\
			traffic_voip_sum bigint,\
			packets_voip_in bigint,\
			packets_voip_out bigint,\
			packets_voip_sum bigint,\
		primary key (interval_time, addr, customer_id, proto, port)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition_oldver ?
		string(" PARTITION BY RANGE (to_days(interval_time))(\
			 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
		string(" PARTITION BY RANGE COLUMNS(interval_time)(\
			 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)"));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS ipacc_agr_hour (\
			time_hour datetime,\
			addr ")  + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			customer_id int unsigned,\
			proto smallint unsigned,\
			port smallint unsigned,\
			traffic_in bigint,\
			traffic_out bigint,\
			traffic_sum bigint,\
			packets_in bigint,\
			packets_out bigint,\
			packets_sum bigint,\
			traffic_voip_in bigint,\
			traffic_voip_out bigint,\
			traffic_voip_sum bigint,\
			packets_voip_in bigint,\
			packets_voip_out bigint,\
			packets_voip_sum bigint,\
		primary key (time_hour, addr, customer_id, proto, port),\
		index idx_addr (addr),\
		index idx_cust (customer_id),\
		index idx_traffic_sum (traffic_sum),\
		index idx_traffic_voip_sum (traffic_voip_sum)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition_oldver ?
		string(" PARTITION BY RANGE (to_days(time_hour))(\
			 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
		string(" PARTITION BY RANGE COLUMNS(time_hour)(\
			 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)"));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS ipacc_agr2_hour (\
			time_hour datetime,\
			addr ")  + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			customer_id int unsigned,\
			addr2 "  + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			proto smallint unsigned,\
			port smallint unsigned,\
			traffic_in bigint,\
			traffic_out bigint,\
			traffic_sum bigint,\
			packets_in bigint,\
			packets_out bigint,\
			packets_sum bigint,\
			traffic_voip_in bigint,\
			traffic_voip_out bigint,\
			traffic_voip_sum bigint,\
			packets_voip_in bigint,\
			packets_voip_out bigint,\
			packets_voip_sum bigint,\
			primary key (time_hour, addr, customer_id, addr2, proto, port),\
		index idx_addr (addr),\
		index idx_cust (customer_id),\
		index idx_addr12 (addr, addr2),\
		index idx_cust_addr2 (customer_id, addr2),\
		index idx_traffic_sum (traffic_sum),\
		index idx_traffic_voip_sum (traffic_voip_sum)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition_oldver ?
		string(" PARTITION BY RANGE (to_days(time_hour))(\
			 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
		string(" PARTITION BY RANGE COLUMNS(time_hour)(\
			 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)"));
	 
	this->query(string(
	"CREATE TABLE IF NOT EXISTS ipacc_agr_day (\
			date_day date,\
			addr ")  + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			customer_id int unsigned,\
			proto smallint unsigned,\
			port smallint unsigned,\
			traffic_in bigint,\
			traffic_out bigint,\
			traffic_sum bigint,\
			packets_in bigint,\
			packets_out bigint,\
			packets_sum bigint,\
			traffic_voip_in bigint,\
			traffic_voip_out bigint,\
			traffic_voip_sum bigint,\
			packets_voip_in bigint,\
			packets_voip_out bigint,\
			packets_voip_sum bigint,\
			primary key (date_day, addr, customer_id, proto, port),\
			index idx_addr (addr),\
			index idx_cust (customer_id),\
			index idx_traffic_sum (traffic_sum),\
			index idx_traffic_voip_sum (traffic_voip_sum)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition_oldver ?
		string(" PARTITION BY RANGE (to_days(date_day))(\
			 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitMonth + "')) engine innodb)" :
		string(" PARTITION BY RANGE COLUMNS(date_day)(\
			 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitMonth + "') engine innodb)"));
	
	}

	this->query(
	"CREATE TABLE IF NOT EXISTS `files` (\
			`datehour` int NOT NULL,\
			`spool_index` int unsigned NOT NULL,\
			`id_sensor` int unsigned NOT NULL,\
			`sipsize` bigint unsigned DEFAULT 0,\
			`rtpsize` bigint unsigned DEFAULT 0,\
			`graphsize` bigint unsigned DEFAULT 0,\
			`audiosize` bigint unsigned DEFAULT 0,\
			`regsize` bigint unsigned DEFAULT 0,\
			`skinnysize` bigint unsigned DEFAULT 0,\
			`mgcpsize` bigint unsigned DEFAULT 0,\
			`ss7size` bigint unsigned DEFAULT 0,\
		PRIMARY KEY (`datehour`, `spool_index`, `id_sensor`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	if(opt_enable_fraud) {
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cache_number_location` (\
			`number` varchar(30) NOT NULL,\
			`number_ip` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`ip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			`country_code` varchar(5),\
			`continent_code` varchar(5),\
			`ua` varchar(512),\
			`at` bigint unsigned,\
			`old_ip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			`old_country_code` varchar(5),\
			`old_continent_code` varchar(5),\
			`old_ua` varchar(512),\
			`old_at` bigint unsigned,\
		PRIMARY KEY (`number`, `number_ip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress + ";");
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cache_number_domain_location` (\
			`number` varchar(30) NOT NULL,\
			`domain` varchar(100) NOT NULL,\
			`number_ip` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
			`ip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			`country_code` varchar(5),\
			`continent_code` varchar(5),\
			`ua` varchar(512),\
			`at` bigint unsigned,\
			`old_ip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
			`old_country_code` varchar(5),\
			`old_continent_code` varchar(5),\
			`old_ua` varchar(512),\
			`old_at` bigint unsigned,\
		PRIMARY KEY (`number`, `domain`, `number_ip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress + ";");
	this->createTable("fraud_alert_info");
	}
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `log_sensor` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`time` datetime NOT NULL,\
			`ID_parent` bigint unsigned,\
			`id_sensor` smallint unsigned DEFAULT NULL,\
			`type` enum('debug','info','notice','warning','error','critical','alert','emergency'),\
			`confirmed` bool,\
			`subject` text,\
			`message` text,") +
		(supportPartitions != _supportPartitions_na ? 
			"PRIMARY KEY (`ID`, `time`)," :
			"PRIMARY KEY (`ID`),") + 
		"KEY `time` (`time`),\
		KEY `ID_parent` (`ID_parent`),\
		KEY `id_sensor` (`id_sensor`)\
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 " + compress +  
	(supportPartitions != _supportPartitions_na ?
		(opt_log_sensor_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(`time`))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(`time`)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(opt_ssl_store_sessions) {
		this->createTable("ssl_sessions:auto");
	}

	return(true);
}

bool SqlDb_mysql::createSchema_tables_billing_agregation() {
	cBillingAgregationSettings agregSettingsInst;
	agregSettingsInst.load();
	sBillingAgregationSettings agregSettings = agregSettingsInst.getAgregSettings();
	if(!agregSettings.enable_by_ip &&
	   !agregSettings.enable_by_number &&
	   !agregSettings.enable_by_domain) {
		return(true);
	}
	this->clearLastError();
	string compress = getOptimalCompressType();
	vector<cBilling::sAgregationTypePart> typeParts = cBilling::getAgregTypeParts(&agregSettings);
	for(unsigned i = 0; i < typeParts.size(); i++) {
		this->query(string(
			"CREATE TABLE IF NOT EXISTS `billing_agregation_") + typeParts[i].type + "_addresses` (\
				`part` INT UNSIGNED,\
				`time` INT UNSIGNED,\
				`ip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
				`price_operator_mult100000` BIGINT UNSIGNED,\
				`price_customer_mult100000` BIGINT UNSIGNED,\
				PRIMARY KEY (`part`,`time`,`ip`))\
			ENGINE=InnoDB DEFAULT CHARSET=latin1\
			" + compress + "\
			PARTITION BY RANGE (`part`)(\
				PARTITION p0 VALUES LESS THAN (1) engine innodb)");
		this->query(string(
			"CREATE TABLE IF NOT EXISTS `billing_agregation_") + typeParts[i].type + "_numbers` (\
				`part` INT UNSIGNED,\
				`time` INT UNSIGNED,\
				`number` CHAR(20),\
				`price_operator_mult100000` BIGINT UNSIGNED,\
				`price_customer_mult100000` BIGINT UNSIGNED,\
				PRIMARY KEY (`part`,`time`,`number`))\
			ENGINE=InnoDB DEFAULT CHARSET=latin1\
			" + compress + "\
			PARTITION BY RANGE (`part`)(\
				PARTITION p0 VALUES LESS THAN (1) engine innodb)");
		this->query(string(
			"CREATE TABLE IF NOT EXISTS `billing_agregation_") + typeParts[i].type + "_domains` (\
				`part` INT UNSIGNED,\
				`time` INT UNSIGNED,\
				`domain` CHAR(32),\
				`price_operator_mult100000` BIGINT UNSIGNED,\
				`price_customer_mult100000` BIGINT UNSIGNED,\
				PRIMARY KEY (`part`,`time`,`domain`))\
			ENGINE=InnoDB DEFAULT CHARSET=latin1\
			" + compress + "\
			PARTITION BY RANGE (`part`)(\
				PARTITION p0 VALUES LESS THAN (1) engine innodb)");
	}
	return(true);
}

bool SqlDb_mysql::createSchema_table_http_jj(int connectId) {
	this->clearLastError();
	if(!((connectId == 0 && !use_mysql_2_http()) ||
	     (connectId == 1 && use_mysql_2_http())) ||
	   !opt_enable_http_enum_tables) {
		return(true);
	}
	
	string compress = getOptimalCompressType();
	string limitDay;
	string partDayName;
	string limitHour;
	string partHourName;
	string limitHourNext;
	string partHourNextName;
	if(opt_cdr_partition) {
		partDayName = this->getPartDayName(&limitDay, opt_create_old_partitions > 0 ? -opt_create_old_partitions : 0);
		if(opt_cdr_partition_by_hours) {
			partHourName = this->getPartHourName(&limitHour);
			partHourNextName = this->getPartHourName(&limitHourNext, 1);
		}
	}

	bool okTableHttpJj = false;
	if(this->existsTable("http_jj")) {
		if(this->query("select * from http_jj limit 1")) {
			okTableHttpJj = true;
		} else {
			if(this->getLastError() == ER_NO_DB_ERROR ||
			   this->getLastError() == ER_DBACCESS_DENIED_ERROR) {
				return(false);
			}
		}
	}
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `http_jj` (\
		`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\
		`master_id` BIGINT UNSIGNED,\
		`timestamp` DATETIME NOT NULL,\
		`usec` INT UNSIGNED NOT NULL,\
		`srcip` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
		`dstip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
		`srcport` SMALLINT UNSIGNED DEFAULT NULL,\
		`dstport` SMALLINT UNSIGNED DEFAULT NULL,\
		`url` TEXT NOT NULL,\
		`type` ENUM('http_ok') DEFAULT NULL,\
		`http` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,\
		`body` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,\
		`callid` VARCHAR( 255 ) NOT NULL,\
		`sessid` VARCHAR( 255 ) NOT NULL,\
		`external_transaction_id` varchar( 255 ) NOT NULL,\
		`id_sensor` smallint DEFAULT NULL," +
	(opt_cdr_partition ? 
		"PRIMARY KEY (`id`, `timestamp`)," :
		"PRIMARY KEY (`id`),") + 
	"KEY `timestamp` (`timestamp`),\
	KEY `callid` (`callid`),\
	KEY `sessid` (`sessid`),\
	KEY `external_transaction_id` (`external_transaction_id`)," +
	(opt_cdr_partition ? 
		"KEY `master_id` (`master_id`)" :
		"CONSTRAINT fk__http_jj__master_id\
			FOREIGN KEY (`master_id`) REFERENCES `http_jj` (`id`)\
			ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(timestamp)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(timestamp))(\
				PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(timestamp)(\
				PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(!okTableHttpJj && this->getLastError()) {
		return(false);
	}
	
	/* obsolete
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `enum_jj` (\
		`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\
		`dnsid` INT UNSIGNED NOT NULL,\
		`timestamp` DATETIME NOT NULL,\
		`usec` INT UNSIGNED NOT NULL,\
		`srcip` INT UNSIGNED NOT NULL,\
		`dstip` INT UNSIGNED NOT NULL,\
		`isresponse` TINYINT NOT NULL,\
		`recordtype` SMALLINT NOT NULL,\
		`queryname` VARCHAR(255) NOT NULL,\
		`responsename` VARCHAR(255) NOT NULL,\
		`data` BLOB NOT NULL,\
		`id_sensor` smallint DEFAULT NULL,") +
	(opt_cdr_partition ? 
		"PRIMARY KEY (`id`, `timestamp`)," :
		"PRIMARY KEY (`id`),") + 
	"KEY `timestamp` (`timestamp`),\
	KEY `dnsid` (`dnsid`),\
	KEY `queryname` (`queryname`),\
	KEY `responsename` (`responsename`)\
	) ENGINE=InnoDB " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(timestamp)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(timestamp))(\
				PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(timestamp)(\
				PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	*/
	
	return(true);
}

bool SqlDb_mysql::createSchema_table_webrtc(int connectId) {
	this->clearLastError();
	if(!(connectId == 0) ||
	   !opt_enable_webrtc_table) {
		return(true);
	}
	
	string compress = getOptimalCompressType();
	string limitDay;
	string partDayName;
	string limitHour;
	string partHourName;
	string limitHourNext;
	string partHourNextName;
	if(opt_cdr_partition) {
		partDayName = this->getPartDayName(&limitDay, opt_create_old_partitions > 0 ? -opt_create_old_partitions : 0);
		if(opt_cdr_partition_by_hours) {
			partHourName = this->getPartHourName(&limitHour);
			partHourNextName = this->getPartHourName(&limitHourNext, 1);
		}
	}

	bool okTableWebrtc = false;
	if(this->existsTable("webrtc")) {
		if(this->query("select * from webrtc limit 1")) {
			okTableWebrtc = true;
		} else {
			if(this->getLastError() == ER_NO_DB_ERROR ||
			   this->getLastError() == ER_DBACCESS_DENIED_ERROR) {
				return(false);
			}
		}
	}
 
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `webrtc` (\
		`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\
		`timestamp` DATETIME NOT NULL,\
		`usec` INT UNSIGNED NOT NULL,\
		`srcip` ") + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
		`dstip` " + VM_IPV6_TYPE_MYSQL_COLUMN + " NOT NULL,\
		`srcport` SMALLINT UNSIGNED DEFAULT NULL,\
		`dstport` SMALLINT UNSIGNED DEFAULT NULL,\
		`type` ENUM('http', 'http_resp', 'websocket', 'websocket_resp') DEFAULT NULL,\
		`method` VARCHAR(32) DEFAULT NULL,\
		`body` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,\
		`external_transaction_id` VARCHAR( 255 ) NOT NULL,\
		`id_sensor` smallint DEFAULT NULL," +
	(opt_cdr_partition ? 
		"PRIMARY KEY (`id`, `timestamp`)," :
		"PRIMARY KEY (`id`),") + 
	"KEY `timestamp` (`timestamp`),\
	KEY `external_transaction_id` (`external_transaction_id`)\
	) ENGINE=InnoDB " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_by_hours ?
			string(" PARTITION BY RANGE COLUMNS(timestamp)(\
				 PARTITION ") + partHourName + " VALUES LESS THAN ('" + limitHour + "') engine innodb,\
				 PARTITION " + partHourNextName + " VALUES LESS THAN ('" + limitHourNext + "') engine innodb)" :
		 opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(timestamp))(\
				PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(timestamp)(\
				PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	if(!okTableWebrtc && this->getLastError()) {
		return(false);
	}
	
	return(true);
}

bool SqlDb_mysql::createSchema_alter_other(int connectId) {
	this->clearLastError();
	if(!(connectId == 0)) {
		return(true);
	}
	
	char alter_funcname[20];
	snprintf(alter_funcname, sizeof(alter_funcname), "__alter");
	if(opt_id_sensor > -1) {
		snprintf(alter_funcname + strlen(alter_funcname), sizeof(alter_funcname) - strlen(alter_funcname),"_S%i", opt_id_sensor);
	}
	this->query(string("drop procedure if exists ") + alter_funcname);
	ostringstream outStrAlter;
	outStrAlter << "create procedure " << alter_funcname << "() begin" << endl
		    << "DECLARE CONTINUE HANDLER FOR SQLSTATE '42S21' BEGIN END;" << endl
		    << "DECLARE CONTINUE HANDLER FOR SQLSTATE '42000' BEGIN END;" << endl;
	
	//5.2 -> 5.3
	if(opt_match_header[0] != '\0') {
		outStrAlter << "ALTER TABLE cdr_next\
				ADD match_header VARCHAR(128),\
				ADD KEY `match_header` (`match_header`);" << endl;
	}
	//5.3 -> 5.4
	if(opt_sip_register == 2) {
	outStrAlter << "ALTER TABLE register\
			ADD KEY `to_domain` (`to_domain`),\
			ADD KEY `to_num` (`to_num`);" << endl;
	}
	outStrAlter << "ALTER TABLE register_state\
			ADD `to_domain` varchar(255) NULL DEFAULT NULL;" << endl;
	outStrAlter << "ALTER TABLE register_failed\
			ADD `to_domain` varchar(255) NULL DEFAULT NULL;" << endl;
	//5.4 -> 5.5
	outStrAlter << "ALTER TABLE register_state\
			ADD `sipcalledip` int unsigned,\
			ADD KEY `sipcalledip` (`sipcalledip`);" << endl;
	outStrAlter << "ALTER TABLE register_failed\
			ADD `sipcalledip` int unsigned,\
			ADD KEY `sipcalledip` (`sipcalledip`);" << endl;
	//6.0 -> 6.1
	outStrAlter << "ALTER TABLE message\
			ADD id_contenttype INT AFTER ID,\
			ADD KEY `id_contenttype` (`id_contenttype`);" << endl;
	
	//6.5RC2 ->
	outStrAlter << "ALTER TABLE message ADD GeoPosition varchar(255);" << endl;
	outStrAlter << "ALTER TABLE cdr_next ADD GeoPosition varchar(255);" << endl;
	if(opt_sip_register == 2) {
	outStrAlter << "ALTER TABLE register\
			ADD `fname` BIGINT NULL DEFAULT NULL;" << endl;
	}
	outStrAlter << "ALTER TABLE register_failed\
			ADD `fname` BIGINT NULL DEFAULT NULL;" << endl;
	outStrAlter << "ALTER TABLE register_state\
			ADD `fname` BIGINT NULL DEFAULT NULL;" << endl;
	if(opt_sip_register == 2) {
	outStrAlter << "ALTER TABLE register\
			ADD `id_sensor` INT NULL DEFAULT NULL;" << endl;
	}
	outStrAlter << "ALTER TABLE register_failed\
			ADD `id_sensor` INT NULL DEFAULT NULL;" << endl;
	outStrAlter << "ALTER TABLE register_state\
			ADD `id_sensor` INT NULL DEFAULT NULL;" << endl;

	outStrAlter << "ALTER TABLE filter_ip\
			ADD `skip` tinyint NULL;" << endl;
	outStrAlter << "ALTER TABLE filter_telnum\
			ADD `skip` tinyint NULL;" << endl;
	
	//8.2
	outStrAlter << "ALTER TABLE filter_ip\
			ADD `script` tinyint NULL;" << endl;
	outStrAlter << "ALTER TABLE filter_telnum\
			ADD `script` tinyint NULL;" << endl;

	outStrAlter << "ALTER TABLE filter_ip\
			ADD `mos_lqo` tinyint NULL;" << endl;
	outStrAlter << "ALTER TABLE filter_telnum\
			ADD `mos_lqo` tinyint NULL;" << endl;
	
	outStrAlter << "ALTER TABLE files\
			ADD `regsize` bigint unsigned DEFAULT 0;" << endl;

	/* obsolete
	//9.4
	outStrAlter << "ALTER TABLE sensor_conf ADD `sip-register-timeout` tinyint DEFAULT 5;" << endl;
	*/

	//
	outStrAlter << "ALTER TABLE filter_ip\
			ADD `hide_message` tinyint default NULL;" << endl;
	outStrAlter << "ALTER TABLE filter_telnum\
			ADD `hide_message` tinyint default NULL;" << endl;
	outStrAlter << "ALTER TABLE filter_ip\
			ADD `remove_at` date default NULL;" << endl;
	outStrAlter << "ALTER TABLE filter_telnum\
			ADD `remove_at` date default NULL;" << endl;

	//10.0.5
	if(opt_enable_fraud) {
	outStrAlter << "ALTER TABLE cache_number_location\
			ADD `number_ip` int unsigned DEFAULT NULL AFTER number,\
			DROP PRIMARY KEY,\
			ADD PRIMARY KEY (`number`, `number_ip`);" << endl;
	}
	
	//12.5
	if(opt_sip_register == 2) {
	outStrAlter << "ALTER TABLE register \
		ADD `rrd_avg` mediumint unsigned DEFAULT NULL;" <<endl;
	outStrAlter << "ALTER TABLE register \
		ADD `rrd_count` tinyint unsigned DEFAULT NULL;" <<endl;
	outStrAlter << "ALTER TABLE register \
		ADD KEY `rrd_avg` (`rrd_avg`);" << endl;
	}
	outStrAlter << "drop trigger if exists cdr_bi;" << endl;

	//15.1
	if(opt_sip_register == 2) {
	outStrAlter << "ALTER TABLE register \
		ADD `src_mac` bigint unsigned DEFAULT NULL;" <<endl;
	outStrAlter << "ALTER TABLE register \
		ADD KEY `src_mac` (`src_mac`);" << endl;
	}
	outStrAlter << "drop trigger if exists cdr_bi;" << endl;
	
	//17
	if(opt_enable_fraud) {
		if(this->existsTable("fraud_alert_info")) {
			outStrAlter << "ALTER TABLE fraud_alert_info\
					ADD `id_sensor` smallint unsigned;" << endl;
		}
	}

	//
	outStrAlter << "end;" << endl;

	/*
	cout << "alter procedure" << endl
	     << outStrAlter.str() << endl
	     << "---" << endl;
	*/

	// drop old cdr trigger
	this->query(outStrAlter.str());
	this->query(string("call ") + alter_funcname);
	this->query(string("drop procedure if exists ") + alter_funcname);
	
	return(true);
}

bool SqlDb_mysql::createSchema_alter_http_jj(int connectId) {
	this->clearLastError();
	if(!((connectId == 0 && !use_mysql_2_http()) ||
	     (connectId == 1 && use_mysql_2_http())) ||
	   !opt_enable_http_enum_tables) {
		return(true);
	}
	
	char alter_funcname[20];
	snprintf(alter_funcname, sizeof(alter_funcname), "__alter");
	if(opt_id_sensor > -1) {
		snprintf(alter_funcname + strlen(alter_funcname), sizeof(alter_funcname) - strlen(alter_funcname), "_S%i", opt_id_sensor);
	}
	this->query(string("drop procedure if exists ") + alter_funcname);
	ostringstream outStrAlter;
	outStrAlter << "create procedure " << alter_funcname << "() begin" << endl
		    << "DECLARE CONTINUE HANDLER FOR SQLSTATE '42S21' BEGIN END;" << endl
		    << "DECLARE CONTINUE HANDLER FOR SQLSTATE '42000' BEGIN END;" << endl;
	
	outStrAlter << "ALTER TABLE http_jj\
			ADD external_transaction_id varchar( 255 ) NOT NULL,\
			ADD KEY `external_transaction_id` (`external_transaction_id`);" << endl;
	outStrAlter << "ALTER TABLE http_jj ADD type ENUM('http_ok') DEFAULT NULL AFTER url;" << endl;
	outStrAlter << "ALTER TABLE http_jj ADD http TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL AFTER type;" << endl;
	outStrAlter << "ALTER TABLE http_jj ADD id_sensor SMALLINT DEFAULT NULL;" << endl;
	/* obsolete
	outStrAlter << "ALTER TABLE enum_jj ADD id_sensor SMALLINT DEFAULT NULL;" << endl;
	*/

	//
	outStrAlter << "end;" << endl;

	/*
	cout << "alter procedure" << endl
	     << outStrAlter.str() << endl
	     << "---" << endl;
	*/

	// drop old cdr trigger
	this->query(outStrAlter.str());
	this->query(string("call ") + alter_funcname);
	this->query(string("drop procedure if exists ") + alter_funcname);
	
	return(true);
}

bool SqlDb_mysql::createSchema_procedures_other(int connectId) {
	this->clearLastError();
	if(!(connectId == 0)) {
		return(true);
	}
	
	if(opt_ipaccount && !opt_disable_partition_operations) {
		if(isCloud()) {
			this->createProcedure(
			"begin\
			    call create_partition_v3('ipacc', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3('ipacc_agr_interval', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3('ipacc_agr_hour', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3('ipacc_agr2_hour', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3('ipacc_agr_day', 'month', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			 end",
			"create_partitions_ipacc", "(next_days int)", true);
			this->query(
			"call create_partitions_ipacc(0);");
			this->query(
			"call create_partitions_ipacc(1);");
			this->query(
			"drop event if exists ipacc_add_partition");
			this->query(
			"create event if not exists ipacc_add_partition\
			 on schedule every 1 hour do\
			 begin\
			    call create_partitions_ipacc(1);\
			 end");
		} else {
			this->createProcedure(
			"begin\
			    call create_partition_v3(database_name, 'ipacc', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3(database_name, 'ipacc_agr_interval', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3(database_name, 'ipacc_agr_hour', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3(database_name, 'ipacc_agr2_hour', 'day', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			    call create_partition_v3(database_name, 'ipacc_agr_day', 'month', next_days, " + string(opt_cdr_partition_oldver? "true" : "false") + ");\
			 end",
			"create_partitions_ipacc", "(database_name char(100), next_days int)", true);
			this->query(string(
			"call `") + mysql_database + "`.create_partitions_ipacc('" + mysql_database + "', 0);");
			this->query(string(
			"call `") + mysql_database + "`.create_partitions_ipacc('" + mysql_database + "', 1);");
			this->query(
			"drop event if exists ipacc_add_partition");
			this->query(string(
			"create event if not exists ipacc_add_partition\
			 on schedule every 1 hour do\
			 begin\
			    call `") + mysql_database + "`.create_partitions_ipacc('" + mysql_database + "', 1);\
			 end");
		}
		this->query("set global event_scheduler = 1");
	}
	this->createFunction( // double space after begin for invocation rebuild function if change parameter - createRoutine compare only body
	"BEGIN  \
		DECLARE _ID INT; \
		SET _ID = (SELECT id FROM cdr_ua WHERE ua = val); \
		IF ( _ID ) THEN \
			RETURN _ID; \
		ELSE  \
			INSERT INTO cdr_ua SET ua = val; \
			RETURN LAST_INSERT_ID(); \
		END IF; \
	END",
	"getIdOrInsertUA", "(val VARCHAR(255) CHARACTER SET latin1) RETURNS INT DETERMINISTIC", true);
	this->createFunction( // double space after begin for invocation rebuild function if change parameter - createRoutine compare only body
	"BEGIN  \
		DECLARE _ID INT; \
		SET _ID = (SELECT id FROM cdr_sip_response WHERE lastSIPresponse = val); \
		IF ( _ID ) THEN \
			RETURN _ID; \
		ELSE  \
			INSERT INTO cdr_sip_response SET lastSIPresponse = val; \
			RETURN LAST_INSERT_ID(); \
		END IF; \
	END",
	"getIdOrInsertSIPRES", "(val VARCHAR(255) CHARACTER SET latin1) RETURNS INT DETERMINISTIC", true);
	if(_save_sip_history) {
		this->createFunction( // double space after begin for invocation rebuild function if change parameter - createRoutine compare only body
		"BEGIN  \
			DECLARE _ID INT; \
			SET _ID = (SELECT id FROM cdr_sip_request WHERE request = val); \
			IF ( _ID ) THEN \
				RETURN _ID; \
			ELSE  \
				INSERT INTO cdr_sip_request SET request = val; \
				RETURN LAST_INSERT_ID(); \
			END IF; \
		END",
		"getIdOrInsertSIPREQUEST", "(val VARCHAR(255) CHARACTER SET latin1) RETURNS INT DETERMINISTIC", true);
	}
	this->createFunction(
	"BEGIN \
		DECLARE _ID INT; \
		SET _ID = (SELECT id FROM cdr_reason WHERE type = type_input and reason = val); \
		IF ( _ID ) THEN \
			RETURN _ID; \
		ELSE  \
			INSERT INTO cdr_reason SET type = type_input, reason = val; \
			RETURN LAST_INSERT_ID(); \
		END IF; \
	END",
	"getIdOrInsertREASON", "(type_input tinyint, val VARCHAR(255) CHARACTER SET latin1) RETURNS INT DETERMINISTIC", true);
	this->createFunction( // double space after begin for invocation rebuild function if change parameter - createRoutine compare only body
	"BEGIN  \
		DECLARE _ID INT; \
		SET _ID = (SELECT id FROM contenttype WHERE contenttype = val LIMIT 1); \
		IF ( _ID ) THEN \
			RETURN _ID; \
		ELSE  \
			INSERT INTO contenttype SET contenttype = val; \
			RETURN LAST_INSERT_ID(); \
		END IF; \
	END",
	"getIdOrInsertCONTENTTYPE", "(val VARCHAR(255) CHARACTER SET utf8) RETURNS INT DETERMINISTIC", true);
	this->createProcedure(
	"BEGIN \
		DECLARE _ID INT; \
		DECLARE _state INT; \
		DECLARE _expires_at DATETIME; \
		DECLARE _expired INT; \
		DECLARE _rrd_avg MEDIUMINT; \
		DECLARE _rrd_count TINYINT; \
		SELECT ID, \
		       state, \
		       expires_at, \
		       rrd_avg, \
		       rrd_count, \
		       (UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(calltime)) AS expired \
		INTO _ID, _state, _expires_at, _rrd_avg, _rrd_count, _expired FROM register \
		WHERE to_num = called AND to_domain = called_domain AND \
		      contact_num = contact_num_param AND contact_domain = contact_domain_param \
		ORDER BY ID DESC LIMIT 1; \
		IF ( _ID ) THEN \
			DELETE FROM register WHERE ID = _ID; \
			IF ( _expired > 5 ) THEN \
				INSERT INTO `register_state` \
					SET `id_sensor` = id_sensor, \
					    `fname` = fname, \
					    `created_at` = _expires_at, \
					    `sipcallerip` = sipcallerip, \
					    `sipcalledip` = sipcalledip, \
					    `from_num` = caller, \
					    `to_num` = called, \
					    `to_domain` = called_domain, \
					    `contact_num` = contact_num_param, \
					    `contact_domain` = contact_domain_param, \
					    `digestusername` = digest_username, \
					    `digestrealm` = digest_realm, \
					    `expires` = register_expires, \
					    state = 5, \
					    ua_id = getIdOrInsertUA(cdr_ua); \
			END IF; \
			IF ( _state <> regstate OR register_expires = 0) THEN \
				INSERT INTO `register_state` \
					SET `id_sensor` = id_sensor, \
					    `fname` = fname, \
					    `created_at` = calltime, \
					    `sipcallerip` = sipcallerip, \
					    `sipcalledip` = sipcalledip, \
					    `from_num` = caller, \
					    `to_num` = called, \
					    `to_domain` = called_domain, \
					    `contact_num` = contact_num_param, \
					    `contact_domain` = contact_domain_param, \
					    `digestusername` = digest_username, \
					    `digestrealm` = digest_realm, \
					    `expires` = register_expires, \
					    state = regstate, \
					    ua_id = getIdOrInsertUA(cdr_ua); \
			END IF; \
		ELSE \
			INSERT INTO `register_state` \
				SET `id_sensor` = id_sensor, \
				    `fname` = fname, \
				    `created_at` = calltime, \
				    `sipcallerip` = sipcallerip, \
				    `sipcalledip` = sipcalledip, \
				    `from_num` = caller, \
				    `to_num` = called, \
				    `to_domain` = called_domain, \
				    `contact_num` = contact_num_param, \
				    `contact_domain` = contact_domain_param, \
				    `digestusername` = digest_username, \
				    `digestrealm` = digest_realm, \
				    `expires` = register_expires, \
				    state = regstate, \
				    ua_id = getIdOrInsertUA(cdr_ua);\
		END IF; \
		IF ( register_expires > 0 ) THEN \
			IF ( _rrd_count IS NULL ) THEN \
				SET _rrd_count = 1; \
				SET _rrd_avg = regrrddiff; \
			ELSE \
				IF (_rrd_count < 10) THEN \
					SET _rrd_count = _rrd_count + 1; \
				END IF; \
				SET _rrd_avg = (_rrd_avg * (_rrd_count - 1) + regrrddiff) / _rrd_count; \
			END IF; \
			INSERT INTO `register` \
				SET `id_sensor` = id_sensor, \
				    `fname` = fname, \
				    `calldate` = calltime, \
				    `sipcallerip` = sipcallerip, \
				    `sipcalledip` = sipcalledip, \
				    `from_num` = caller, \
				    `from_name` = callername, \
				    `from_domain` = caller_domain, \
				    `to_num` = called, \
				    `to_domain` = called_domain, \
				    `contact_num` = contact_num_param, \
				    `contact_domain` = contact_domain_param, \
				    `digestusername` = digest_username, \
				    `digestrealm` = digest_realm, \
				    `expires` = register_expires, \
				    state = regstate, \
				    ua_id = getIdOrInsertUA(cdr_ua), \
				    `expires_at` = mexpires_at, \
				    `rrd_avg` = _rrd_avg, \
				    `rrd_count` = _rrd_count; \
		END IF; \
	END",
	"PROCESS_SIP_REGISTER", 
	"(IN calltime VARCHAR(32), \
	  IN caller VARCHAR(64), \
	  IN callername VARCHAR(64), \
	  IN caller_domain VARCHAR(64), \
	  IN called VARCHAR(64), \
	  IN called_domain VARCHAR(64), \
	  IN sipcallerip INT UNSIGNED, \
	  IN sipcalledip INT UNSIGNED, \
	  IN contact_num_param VARCHAR(64), \
	  IN contact_domain_param VARCHAR(64), \
	  IN digest_username VARCHAR(255), \
	  IN digest_realm VARCHAR(255), \
	  IN regstate INT, \
	  IN mexpires_at VARCHAR(128), \
	  IN register_expires INT, \
	  IN cdr_ua VARCHAR(255), \
	  IN fname BIGINT, \
	  IN id_sensor INT, \
	  IN regrrddiff MEDIUMINT)",true);
	if(useNewStore()) {
	this->createProcedure(
	"begin \
		declare str_sep_pos_length integer default 0; \
		declare str_sep_pos integer default 0; \
		declare str_sep_pos_next integer default 0; \
		declare str_sub longtext; \
		declare level integer default 1; \
		declare skip_levels_gt integer default 0; \
		declare colonAtBegin bool default false; \
		declare exit handler for sqlexception \
			begin \
				if(use_transaction) then \
					rollback; \
				end if; \
				" + string((getDbName() == "mariadb" ? 
					     (getDbVersion() > 50500) :
					     (getDbVersion() > 50500)) ? "resignal;" : "") + " \
			end; \
		if(use_transaction) then \
			start transaction; \
		end if; \
		set str_sep_pos_length = length(str_sep); \
		while (str_sep_pos >= 0) do \
			set str_sep_pos_next = locate(str_sep, str, str_sep_pos + 1); \
			set str_sub = substr(str, str_sep_pos + 1, if(str_sep_pos_next > 0, str_sep_pos_next - str_sep_pos - 1, 1e9)); \
			if(left(str_sub, 6) = ':ENDIF') then \
				set level = level - 1; \
			else \
				if(not(skip_levels_gt and level > skip_levels_gt)) then \
					if(left(str_sub, 3) = ':IF') then \
						set @query_str = concat('set @rslt_if = (', substr(str_sub, locate(':IF', str_sub) + 3), ')'); \
						PREPARE if_stmt FROM @query_str; \
						EXECUTE if_stmt; \
						DEALLOCATE PREPARE if_stmt; \
						if(@rslt_if is null or not(@rslt_if)) then \
							set skip_levels_gt = level; \
						end if; \
						set level = level + 1; \
					else \
						if(length(str_sub) > 0) then \
							set @query_str = str_sub; \
							PREPARE query_stmt FROM @query_str; \
							EXECUTE query_stmt; \
							DEALLOCATE PREPARE query_stmt; \
						end if; \
					end if; \
				end if; \
			end if; \
			set str_sep_pos = if(str_sep_pos_next > 0, str_sep_pos_next + str_sep_pos_length - 1, -1); \
		end while; \
		if(use_transaction) then \
			commit; \
		end if; \
	end",
	"store_001", "(str longtext, str_sep text, use_transaction bool)", true);
	}
	
	return(true);
}

bool SqlDb_mysql::createSchema_procedure_partition(int connectId, bool abortIfFailed) {
	this->clearLastError();
	if(!(connectId == 0 ||
	     (connectId == 1 && use_mysql_2_http())) ||
	   opt_disable_partition_operations) {
		return(true);
	}
	
	this->createProcedure(
	"begin\
	    declare part_start_time datetime;\
	    declare part_start_date date;\
	    declare part_start_hour datetime;\
	    declare part_limit date;\
	    declare part_limit_time datetime;\
	    declare part_limit_int int unsigned;\
	    declare part_name char(100);\
	    declare _week_start int;\
	    declare _week_day int;\
	    declare test_exists_any_part_query varchar(1000);\
	    declare test_exists_part_query varchar(1000);\
	    declare create_part_query varchar(1000);\
	    if(database_name is not null) then\
	       set test_exists_any_part_query = concat(\
		  'set @_exists_any_part = exists (select * from information_schema.partitions where table_schema=\\'',\
		  database_name,\
		  '\\' and table_name = \\'',\
		  table_name,\
		  '\\' and partition_name is not null)');\
	       set @_test_exists_any_part_query = test_exists_any_part_query;\
	       prepare stmt FROM @_test_exists_any_part_query;\
	       execute stmt;\
	       deallocate prepare stmt;\
	    end if;\
	    if(database_name is null or @_exists_any_part) then\
	       set part_start_time = date_add(now(), interval next_part day);\
	       set part_limit = NULL;\
	       set part_limit_time = NULL;\
	       set part_limit_int = NULL;\
	       if(type_part = 'year_int') then\
		  set part_start_date = date_format(part_start_time, '%Y-01-01');\
		  set part_limit_int = date_format(part_start_date + interval 1 year, '%Y%m');\
		  set part_name = concat('p', date_format(part_start_date, '%Y'));\
	       elseif(type_part = 'month_int') then\
		  set part_start_date = date_format(part_start_time, '%Y-%m-01');\
		  set part_limit_int = date_format(part_start_date + interval 1 month, '%Y%m%d');\
		  set part_name = concat('p', date_format(part_start_date, '%Y%m'));\
	       elseif(type_part like 'week_int%') then\
		  set _week_start = substring_index(type_part, ':', -1);\
		  set _week_start = if(_week_start = 1, 6, _week_start - 2);\
		  set _week_day = weekday(part_start_time) - _week_start;\
		  if(_week_day < 0) then\
		     set _week_day = _week_day + 7;\
		  end if;\
		  set part_start_date = date(part_start_time) - interval _week_day day;\
		  set part_limit_int = date_format(part_start_date + interval 1 week, '%Y%m%d');\
		  set part_name = concat('p', date_format(part_start_date, '%Y%m%d'));\
	       elseif(type_part = 'day_int') then\
		  set part_start_date =  date(part_start_time);\
		  set part_limit_int = date_format(date(part_start_date) + interval 1 day, '%Y%m%d00');\
		  set part_name = concat('p', date_format(part_start_date, '%Y%m%d'));\
	       elseif(type_part = 'month') then\
		  set part_start_date = date_add(date(part_start_time), interval -(day(date(part_start_time))-1) day);\
		  set part_limit = date_add(part_start_date, interval 1 month);\
		  if(old_ver_partition) then\
		     set part_limit_int = to_days(part_limit);\
		  end if;\
		  set part_name = concat('p', date_format(part_start_date, '%y%m'));\
	       elseif(type_part = 'hour') then\
		  set part_start_time = date_add(now(), interval next_part hour);\
		  set part_start_hour = date_format(part_start_time, '%Y-%m-%d %H');\
		  set part_limit_time = date_add(part_start_hour, interval 1 hour);\
		  set part_name = concat('p', date_format(part_start_hour, '%y%m%d%H'));\
	       else\
		  set part_start_date =  date(part_start_time);\
		  set part_limit = date_add(part_start_date, interval 1 day);\
		  if(old_ver_partition) then\
		     set part_limit_int = to_days(part_limit);\
		  end if;\
		  set part_name = concat('p', date_format(part_start_date, '%y%m%d'));\
	       end if;\
	       if(database_name is not null) then\
		  set test_exists_part_query = concat(\
		     'set @_exists_part = exists (select * from information_schema.partitions where table_schema=\\'',\
		     database_name,\
		     '\\' and table_name = \\'',\
		     table_name,\
		     '\\' and partition_name >= \\'',\
		     part_name,\
		     '\\')');\
		  set @_test_exists_part_query = test_exists_part_query;\
		  prepare stmt FROM @_test_exists_part_query;\
		  execute stmt;\
		  deallocate prepare stmt;\
	       end if;\
	       if(database_name is null or not @_exists_part) then\
		  set create_part_query = concat(\
		     'alter table ',\
		     if(database_name is not null, concat('`', database_name, '`.'), ''),\
		     '`',\
		     table_name,\
		     '` add partition (partition ',\
		     part_name,\
		     if(part_limit_int is not null,\
			' VALUES LESS THAN (',\
			' VALUES LESS THAN (\\''),\
		     if(part_limit_int is not null,\
			part_limit_int,\
			if(part_limit_time is not null, cast(part_limit_time as char),  cast(part_limit as char))),\
		     if(part_limit_int is not null,\
			'',\
			'\\''),\
		     '))'\
		     );\
		  set @_create_part_query = create_part_query;\
		  prepare stmt FROM @_create_part_query;\
		  execute stmt;\
		  deallocate prepare stmt;\
	       end if;\
	    end if;\
	 end",
	"create_partition_v3", "(database_name char(100), table_name char(100), type_part char(10), next_part int, old_ver_partition bool)", abortIfFailed);

	return(true);
}

bool SqlDb_mysql::createSchema_init_cdr_partitions(int connectId) {
	this->clearLastError();
	if(opt_cdr_partition && !opt_disable_partition_operations) {
		if(opt_create_old_partitions > 0) {
			for(int i = opt_create_old_partitions - 1; i > 0; i--) {
				_createMysqlPartitionsCdr('d', -i, connectId, this);
			}
		}
		for(int next_day = 0; next_day < LIMIT_DAY_PARTITIONS_INIT; next_day++) {
			_createMysqlPartitionsCdr(opt_cdr_partition_by_hours ? 'h' : 'd', next_day, connectId, this);
		}
	}
	return(true);
}

string SqlDb_mysql::getPartMonthName(string *limitMonth_str, int next) {
	char partMonthName[20] = "";
	char limitMonth[20] = "";
	if(supportPartitions != _supportPartitions_na) {
		time_t act_time = time(NULL);
		struct tm partTime = time_r(&act_time);
		if(next > 0) {
			for(int i = 0; i < next; i++) {
				partTime = getNextBeginMonth(partTime);
			}
		}
		strftime(partMonthName, sizeof(partMonthName), "p%y%m", &partTime);
		struct tm nextMonthTime = getNextBeginMonth(partTime);
		strftime(limitMonth, sizeof(limitMonth), "%Y-%m-01", &nextMonthTime);
	}
	if(limitMonth_str) {
		*limitMonth_str = limitMonth;
	}
	return(partMonthName);
}

string SqlDb_mysql::getPartDayName(string *limitDay_str, int next) {
	char partDayName[20] = "";
	char limitDay[20] = "";
	if(supportPartitions != _supportPartitions_na) {
		time_t act_time = time(NULL);
		struct tm partTime = time_r(&act_time);
		if(next < 0) {
			for(int i = 0; i < -next; i++) {
				partTime = getPrevBeginDate(partTime);
			}
		}
		if(next > 0) {
			for(int i = 0; i < next; i++) {
				partTime = getNextBeginDate(partTime);
			}
		}
		strftime(partDayName, sizeof(partDayName), "p%y%m%d", &partTime);
		struct tm nextDayTime = getNextBeginDate(partTime);
		strftime(limitDay, sizeof(limitDay), "%Y-%m-%d", &nextDayTime);
	}
	if(limitDay_str) {
		*limitDay_str = limitDay;
	}
	return(partDayName);
}

string SqlDb_mysql::getPartHourName(string *limitHour_str, int next) {
	char partHourName[20] = "";
	char limitHour[20] = "";
	if(supportPartitions != _supportPartitions_na) {
		time_t act_time = time(NULL);
		struct tm partTime = time_r(&act_time);
		if(next > 0) {
			for(int i = 0; i < next; i++) {
				partTime = getNextBeginHour(partTime);
			}
		}
		strftime(partHourName, sizeof(partHourName), "p%y%m%d%H", &partTime);
		struct tm nextHourTime = getNextBeginHour(partTime);
		strftime(limitHour, sizeof(limitHour), "%Y-%m-%d %H:00:00", &nextHourTime);
	}
	if(limitHour_str) {
		*limitHour_str = limitHour;
	}
	return(partHourName);
}

string SqlDb_mysql::getPartHourName(string *limitHour_str, int next_day, int hour) {
	char partHourName[20] = "";
	char limitHour[20] = "";
	if(supportPartitions != _supportPartitions_na) {
		time_t act_time = time(NULL);
		struct tm partTime = time_r(&act_time);
		if(!(next_day == 0 && hour < partTime.tm_hour)) {
			if(next_day > 0) {
				for(int i = 0; i < next_day; i++) {
					partTime = getNextBeginDate(partTime);
				}
			} else {
				partTime = getBeginDate(partTime);
			}
			for(int i = 0; i < hour; i++) {
				partTime = getNextBeginHour(partTime);
			}
			strftime(partHourName, sizeof(partHourName), "p%y%m%d%H", &partTime);
			char startHour[20] = "";
			strftime(startHour, sizeof(limitHour), "%Y-%m-%d %H:00:00", &partTime);
			struct tm nextHourTime = getNextBeginHour(partTime);
			strftime(limitHour, sizeof(limitHour), "%Y-%m-%d %H:00:00", &nextHourTime);
			if(string(startHour) >= string(limitHour)) {
				return("");
			}
		}
	}
	if(limitHour_str) {
		*limitHour_str = limitHour;
	}
	return(partHourName);
}

void SqlDb_mysql::fillPartitionData(sPartition *partition, const char *datadir, const char *database, const char *table, const char *partition_name, bool last) {
	partition->name = partition_name;
	partition->table = table;
	partition->file = getPartitionFile(datadir, database, table, partition_name);
	partition->file_size = !partition->file.empty() ? GetFileSize(partition->file) : -1;
	/*
	partition->part_size = getPartitionSize(database, table, partition_name);
	*/
	partition->type = getPartitionType(partition_name);
	partition->time = getPartitionTime(partition_name);
	string act_part_time;
	switch(partition->type) {
	case SqlDb::_tp_day:
		getPartDayName(&act_part_time);
		break;
	case SqlDb::_tp_hour:
		getPartHourName(&act_part_time);
		break;
	case SqlDb::_tp_month:
		getPartMonthName(&act_part_time);
		break;
	default:
		break;
	}
	if(!last && !act_part_time.empty() && partition->time < act_part_time) {
		partition->is_prev = true;
	}
}

string SqlDb_mysql::getPartitionFile(const char *datadir, const char *database, const char *table, const char *partition_name) {
	string datadir_tab = getDatadirTab(datadir, database);
	if(datadir_tab.empty()) {
		return("");
	}
	for(int i = 0; i < 2; i++) {
               string file = datadir_tab + "/" + table + (i == 0 ? "#p#" : "#P#") + partition_name + ".ibd";
               if(file_exists(file)) {
                       return(file);
               }
        }
	return("");
}

int64_t SqlDb_mysql::getPartitionSize(const char *database, const char *table, const char *partition_name) {
	int64_t rslt = -1;
	bool disableLogErrorOld = this->getDisableLogError();
	unsigned int maxQueryPassOld = this->getMaxQueryPass();
	this->setDisableLogError(true);
	this->setMaxQueryPass(1);
	if(this->query(string("select DATA_LENGTH + INDEX_LENGTH\
			       from information_schema.PARTITIONS\
			       where TABLE_SCHEMA = '") + (database ? database : conn_database) + 
			       "' and TABLE_NAME = '" + table + 
			       "' and PARTITION_NAME = '" + partition_name +  "'")) {
		SqlDb_row row = this->fetchRow();
		if(row) {
			rslt= atoll(row[0].c_str());
		}
	}
	this->setMaxQueryPass(maxQueryPassOld);
	this->setDisableLogError(disableLogErrorOld);
	return(rslt);
}

SqlDb::eTypePartition SqlDb_mysql::getPartitionType(const char *partition_name) {
	if(partition_name && partition_name[0] == 'p') {
		unsigned partition_name_length = strlen(partition_name);
		if(partition_name_length == 7) {
			return(_tp_day);
		} else if(partition_name_length == 9) {
			return(_tp_hour);
		} else if(partition_name_length == 5) {
			return(_tp_month);
		}
	}
	return(_tp_na);
}

string SqlDb_mysql::getPartitionTime(const char *partition_name) {
	unsigned partition_num = atoll(partition_name + 1);
	struct tm partition_time;
	memset(&partition_time, 0, sizeof(partition_time));
	const char *partition_time_format = NULL;
	switch(getPartitionType(partition_name)) {
	case _tp_day:
		partition_time.tm_year = 2000 + partition_num / ((unsigned)1e4) - 1900;
		partition_time.tm_mon = (partition_num % ((unsigned)1e4)) /  ((unsigned)1e2) - 1;
		partition_time.tm_mday = partition_num % ((unsigned)1e2);
		partition_time = getNextBeginDate(partition_time);
		partition_time_format = "%Y-%m-%d 00:00:00";
		break;
	case _tp_hour:
		partition_time.tm_year = 2000 + partition_num /  ((unsigned)1e6) - 1900;
		partition_time.tm_mon = (partition_num % ((unsigned)1e6)) / ((unsigned)1e4) - 1;
		partition_time.tm_mday = (partition_num % ((unsigned)1e4)) / ((unsigned)1e2);
		partition_time.tm_hour = partition_num % ((unsigned)1e2);
		partition_time = getNextBeginHour(partition_time);
		partition_time_format = "%Y-%m-%d %H:00:00";
		break;
	case _tp_month:
		partition_time.tm_year = 2000 + partition_num / ((unsigned)1e2) - 1900;
		partition_time.tm_mon = partition_num % ((unsigned)1e2) - 1;
		partition_time.tm_mday = 1;
		partition_time = getNextBeginMonth(partition_time);
		partition_time_format = "%Y-%m-01 00:00:00";
		break;
	default:
		break;
	}
	if(partition_time.tm_year && partition_time_format) {
		char partition_time_str[20] = "";
		strftime(partition_time_str, sizeof(partition_time_str), partition_time_format, &partition_time);
		return(partition_time_str);
	}
	return("");
}

void SqlDb_mysql::saveTimezoneInformation() {
	string timezone_name = "UTC";
	long timezone_offset = 0;
	if(!opt_sql_time_utc && !isCloud()) {
		time_t t = time(NULL);
		struct tm lt;
		::localtime_r(&t, &lt);
		timezone_name = getSystemTimezone();
		if(timezone_name.empty()) {
			timezone_name = lt.tm_zone;
		}
		timezone_offset = lt.tm_gmtoff;
	}
	if(opt_id_sensor <= 0) {
		if(!this->existsTable("system") ||
		   !this->existsColumn("system", "content") ||
		   !this->existsColumn("system", "type")) {
			return;
		}
		char timezoneInfo[100];
		snprintf(timezoneInfo, sizeof(timezoneInfo), "{\"name\":\"%s\",\"offset\":\"%li\",\"save_at\":\"%s\"}",
			 timezone_name.c_str(),
			 timezone_offset,
			 sqlDateTimeString(time(NULL)).c_str());
		this->select("system", "content", "type", "timezone_info_local_sensor");
		SqlDb_row row = this->fetchRow();
		if(row) {
			SqlDb_row rowU;
			rowU.add(sqlEscapeString(timezoneInfo), "content");
			this->update("system", rowU, "type='timezone_info_local_sensor'");
		} else {
			SqlDb_row rowI;
			rowI.add(sqlEscapeString(timezoneInfo), "content");
			rowI.add(sqlEscapeString("timezone_info_local_sensor"), "type");
			this->insert("system", rowI);
		}
	} else {
		if(!this->existsTable("sensors") ||
		   !this->existsColumn("sensors", "timezone_name") ||
		   !this->existsColumn("sensors", "timezone_offset")) {
			return;
		}
		SqlDb_row row;
		row.add(timezone_name, "timezone_name");
		row.add(timezone_offset, "timezone_offset");
		row.add(sqlDateTimeString(time(NULL)), "timezone_save_at");
		char whereCond[100];
		snprintf(whereCond, sizeof(whereCond), "id_sensor = %i", opt_id_sensor);
		this->update("sensors", row, whereCond);
	}
}

void SqlDb_mysql::checkDbMode() {
	sql_disable_next_attempt_if_error = 1;
	if(!opt_cdr_partition &&
	   (isCloud() ||
	    this->getDbMajorVersion() * 100 + this->getDbMinorVersion() > 500)) {
		if(this->existsTable("cdr") &&
		   this->getPartitions(NULL, NULL, "cdr") > 0) {
			syslog(LOG_INFO, "enable opt_cdr_partition (table cdr has partitions)");
			opt_cdr_partition = true;
		}
	}
	if(!isCloud()) {
		if(this->getDbMajorVersion() * 100 + this->getDbMinorVersion() <= 500) {
			supportPartitions = _supportPartitions_na;
			if(opt_cdr_partition) {
				opt_cdr_partition = false;
				syslog(LOG_NOTICE, "mysql <= 5.0 does not know partitions - we recommend to upgrade mysql");
			}
		} else { 
			if(this->getDbMajorVersion() * 100 + this->getDbMinorVersion() <= 501) {
				supportPartitions = _supportPartitions_oldver;
				if(opt_cdr_partition) {
					opt_cdr_partition_oldver = true;
					syslog(LOG_NOTICE, "mysql <= 5.1 - use old mode partitions");
					if(opt_cdr_partition_by_hours) {
						opt_cdr_partition_by_hours = false;
						syslog(LOG_NOTICE, "mysql <= 5.1 - hour partitions not supported with old mode");
					}
				}
				opt_ss7_partition_oldver = true;
				for(int src_dst = 0; src_dst < 2; src_dst++) {
					opt_cdr_stat_values_partition_oldver[src_dst] = true;
					opt_cdr_stat_sources_partition_oldver[src_dst] = true;
				}
				opt_rtp_stat_partition_oldver = true;
				opt_log_sensor_partition_oldver = true;
			} else {
				if(opt_cdr_partition) {
					if(this->isOldVerPartition("cdr%")) {
						opt_cdr_partition_oldver = true;
						syslog(LOG_NOTICE, "database contain old mode partitions");
						if(opt_cdr_partition_by_hours) {
							opt_cdr_partition_by_hours = false;
							syslog(LOG_NOTICE, "mysql <= 5.1 - hour partitions not supported with old mode");
						}
					}
				}
				if(this->isOldVerPartition("ss7")) {
					opt_ss7_partition_oldver = true;
					syslog(LOG_NOTICE, "table ss7 contain old mode partitions");
				}
				for(int src_dst = 0; src_dst < 2; src_dst++) {
					if(cCdrStat::enableBySrcDst(src_dst)) {
						if(this->isOldVerPartition(("cdr_stat_values" + cCdrStat::tableNameSuffix(src_dst)).c_str())) {
							opt_cdr_stat_values_partition_oldver[src_dst] = true;
							syslog(LOG_NOTICE, "table cdr_stat_values%s contain old mode partitions", cCdrStat::tableNameSuffix(src_dst).c_str());
						}
						if(opt_cdr_stat_sources && 
						   this->isOldVerPartition(("cdr_stat_sources" + cCdrStat::tableNameSuffix(src_dst)).c_str())) {
							opt_cdr_stat_sources_partition_oldver[src_dst] = true;
							syslog(LOG_NOTICE, "table cdr_stat_sources%s contain old mode partitions", cCdrStat::tableNameSuffix(src_dst).c_str());
						}
					}
				}
				for(int by_type = 0; by_type < 3; by_type++) {
					if(cCdrProblems::enableByType(by_type)) {
						if(this->isOldVerPartition(("cdr_problems" + cCdrProblems::tableNameSuffix(by_type)).c_str())) {
							opt_cdr_problems_partition_oldver[by_type] = true;
							syslog(LOG_NOTICE, "table cdr_problems%s contain old mode partitions", cCdrProblems::tableNameSuffix(by_type).c_str());
						}
					}
				}
				if(this->isOldVerPartition("rtp_stat")) {
					opt_rtp_stat_partition_oldver = true;
					syslog(LOG_NOTICE, "table rtp_stat contain old mode partitions");
				}
				if(this->isOldVerPartition("log_sensor")) {
					opt_log_sensor_partition_oldver = true;
					syslog(LOG_NOTICE, "table log_sensor contain old mode partitions");
				}
			}
		}
	}
	sql_disable_next_attempt_if_error = 0;
}

void SqlDb_mysql::createTable(const char *tableName) {
	if(!strcmp(tableName, "fraud_alert_info")) {
		if(this->existsTable("alerts")) {
			this->query(
			"CREATE TABLE IF NOT EXISTS `fraud_alert_info` (\
					`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\
					`alert_id` INT NOT NULL,\
					`at` DATETIME NOT NULL,\
					`alert_info` TEXT NOT NULL,\
					`id_sensor` smallint unsigned,\
					PRIMARY KEY (`ID`),\
					CONSTRAINT `fraud_alert_info_ibfk_1` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON UPDATE CASCADE ON DELETE CASCADE\
			) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
		}
	}
	if(!strcmp(tableName, "ssl_sessions:auto") ||
	   !strcmp(tableName, "ssl_sessions") ||
	   !strcmp(tableName, "ssl_sessions_mem")) {
		bool mem = (!strcmp(tableName, "ssl_sessions:auto") && opt_ssl_store_sessions == 1) ||
			   !strcmp(tableName, "ssl_sessions_mem");
		this->query(string(
		"CREATE TABLE IF NOT EXISTS `ssl_sessions") + (mem ? "_mem" : "") + "` (\
				`id_sensor` int,\
				`serverip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
				`serverport` smallint unsigned,\
				`clientip` " + VM_IPV6_TYPE_MYSQL_COLUMN + ",\
				`clientport` smallint unsigned,\
				`stored_at` datetime,\
				`session` varchar(1024),\
			PRIMARY KEY (`id_sensor`, `clientip`, `clientport`, `serverip`, `serverport`)\
		) ENGINE=" + (mem ? "MEMORY" : "InnoDB") + " DEFAULT CHARSET=latin1;");
	}
}

void SqlDb_mysql::checkSchema(int connectId, bool checkColumnsSilentLog) {
	this->clearLastError();
	if(!(connectId == 0)) {
		return;
	}
	
	sql_disable_next_attempt_if_error = 1;
	startExistsColumnCache();
	
	if(!opt_cdr_partition &&
	   (isCloud() ||
	    this->getDbMajorVersion() * 100 + this->getDbMinorVersion() > 500)) {
		if(this->getPartitions(NULL, NULL, "cdr") > 0) {
			syslog(LOG_INFO, "enable opt_cdr_partition (table cdr has partitions)");
			opt_cdr_partition = true;
		}
	}
	
	this->checkColumns_cdr(!checkColumnsSilentLog);
	this->checkColumns_cdr_next(!checkColumnsSilentLog);
	this->checkColumns_cdr_next_branches(!checkColumnsSilentLog);
	this->checkColumns_cdr_sdp(!checkColumnsSilentLog);
	this->checkColumns_cdr_rtp(!checkColumnsSilentLog);
	this->checkColumns_cdr_dtmf(!checkColumnsSilentLog);
	this->checkColumns_cdr_conference(!checkColumnsSilentLog);
	this->checkColumns_cdr_child(!checkColumnsSilentLog);
	this->checkColumns_cdr_stat(!checkColumnsSilentLog);
	this->checkColumns_cdr_problems(!checkColumnsSilentLog);
	this->checkColumns_ss7(!checkColumnsSilentLog);
	this->checkColumns_message(!checkColumnsSilentLog);
	this->checkColumns_message_child(!checkColumnsSilentLog);
	this->checkColumns_register(!checkColumnsSilentLog);
	this->checkColumns_sip_msg(!checkColumnsSilentLog);
	this->checkColumns_other(!checkColumnsSilentLog);
	
	stopExistsColumnCache();
	
	#if VM_IPV6
	extern bool useIPv6;
	string cdrIP_type = this->getTypeColumn("cdr", "sipcallerip", true);;
	bool _useIPv6 = cdrIP_type.find("varbinary") != string::npos;
	if(useIPv6 && !_useIPv6) {
		syslog(LOG_NOTICE, "IPv6 support need varbinary columns for IP addresses!");
	}
	useIPv6 = _useIPv6;
	#endif
	
	if(VM_IPV6_B) {
		list<string> allTables = this->getAllTables();
		for(list<string>::iterator iter = allTables.begin(); iter != allTables.end(); iter++) {
			this->getTypeColumn(iter->c_str(), NULL, true, true);
		}
	}

	sql_disable_next_attempt_if_error = 0;
}

void SqlDb_mysql::updateSensorState() {
	if(isCloud() && opt_id_sensor > 0) {
		this->query("select * from `sensors` where id_sensor=" + intToString(opt_id_sensor));
		bool existsRowSensor = this->fetchRow();
		bool existsColumnCloudRouter = this->existsColumn("sensors", "cloud_router");
		if(existsRowSensor) {
			SqlDb_row rowU;
			if(existsColumnCloudRouter) {
				rowU.add(true, "cloud_router");
			}
			extern cCR_Receiver_service *cloud_receiver;
			rowU.add(cloud_receiver->getConnectFrom(), "host");
			if(!rowU.isEmpty()) {
				this->update("sensors", rowU, ("id_sensor=" + intToString(opt_id_sensor)).c_str());
			}
		} else {
			SqlDb_row rowI;
			rowI.add(opt_id_sensor, "id_sensor");
			rowI.add("auto insert id " + intToString(opt_id_sensor), "name");
			if(existsColumnCloudRouter) {
				rowI.add(true, "cloud_router");
			}
			extern cCR_Receiver_service *cloud_receiver;
			rowI.add(cloud_receiver->getConnectFrom(), "host");
			rowI.add(5029, "port");
			this->insert("sensors", rowI);
		}
	}
}

void SqlDb_mysql::checkColumns_cdr(bool log) {
	map<string, u_int64_t> tableSize;
	this->checkNeedAlterAdd("cdr", "store post bye delay", true,
				log, &tableSize, &existsColumns.cdr_post_bye_delay,
				"post_bye_delay", string(column_type_duration_ms(NULL, true) + " unsigned default null").c_str(), NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	for(int pass = 0; pass < 2; pass++) {
		vector<string> alters_ms;
		if(!(existsColumns.cdr_calldate_ms = this->getTypeColumn("cdr", "calldate").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column calldate " + column_type_datetime_ms() + " not null");
		}
		if(!(existsColumns.cdr_callend_ms = this->getTypeColumn("cdr", "callend").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column callend " + column_type_datetime_ms() + " not null");
		}
		if(!(existsColumns.cdr_duration_ms = this->getTypeColumn("cdr", "duration").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column duration " + column_type_duration_ms() + " unsigned default null");
		}
		if(!(existsColumns.cdr_connect_duration_ms = this->getTypeColumn("cdr", "connect_duration").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column connect_duration " + column_type_duration_ms() + " unsigned default null");
		}
		if(!(existsColumns.cdr_progress_time_ms = this->getTypeColumn("cdr", "progress_time").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column progress_time " + column_type_duration_ms() + " unsigned default null");
		}
		if(!(existsColumns.cdr_first_rtp_time_ms = this->getTypeColumn("cdr", "first_rtp_time").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column first_rtp_time " + column_type_duration_ms() + " unsigned default null");
		}
		if(this->existsColumn("cdr", "post_bye_delay") &&
		   !(existsColumns.cdr_post_bye_delay_ms = this->getTypeColumn("cdr", "post_bye_delay").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column post_bye_delay " + column_type_duration_ms() + " unsigned default null");
		}
		if(this->existsColumn("cdr", "a_last_rtp_from_end") &&
		   !(existsColumns.cdr_a_last_rtp_from_end_time_ms = this->getTypeColumn("cdr", "a_last_rtp_from_end").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column a_last_rtp_from_end " + column_type_duration_ms() + " signed default null");
		}
		if(this->existsColumn("cdr", "a_last_rtp_from_end") &&
		   !(existsColumns.cdr_b_last_rtp_from_end_time_ms = this->getTypeColumn("cdr", "b_last_rtp_from_end").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column b_last_rtp_from_end " + column_type_duration_ms() + " signed default null");
		}
		if(pass == 0 && opt_time_precision_in_ms) {
			if(alters_ms.size()) {
				if(isSupportForDatetimeMs()) {
					if(this->logNeedAlter("cdr",
							      "time accuracy in milliseconds",
							      "ALTER TABLE cdr " + implode(alters_ms, ", ") + ";",
							      log, &tableSize, NULL)) {
						this->removeTableFromColumnCache("cdr");
					}
					continue;
				} else {
					cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
					opt_time_precision_in_ms = false;
				}
			}
		}
		break;
	}
	if(this->checkNeedAlterAdd("cdr", "store last rtp from end", opt_last_rtp_from_end,
				   log, &tableSize, &existsColumns.cdr_last_rtp_from_end,
				   "a_last_rtp_from_end", existsColumns.cdr_calldate_ms ? "decimal(9,3) signed default null" : "SMALLINT SIGNED DEFAULT NULL", NULL_CHAR_PTR,
				   "b_last_rtp_from_end", existsColumns.cdr_calldate_ms ? "decimal(9,3) signed default null" : "SMALLINT SIGNED DEFAULT NULL", NULL_CHAR_PTR,
				   NULL_CHAR_PTR) > 0) {
		existsColumns.cdr_a_last_rtp_from_end_time_ms = this->getTypeColumn("cdr", "a_last_rtp_from_end").find("decimal") != string::npos;
		existsColumns.cdr_b_last_rtp_from_end_time_ms = this->getTypeColumn("cdr", "b_last_rtp_from_end").find("decimal") != string::npos;
	}
	this->checkNeedAlterAdd("cdr", "store sip ports", opt_cdr_sipport,
				log, &tableSize, &existsColumns.cdr_sipport,
				"sipcallerport", "smallint unsigned DEFAULT NULL AFTER `sipcallerip`", NULL_CHAR_PTR,
				"sipcalledport", "smallint unsigned DEFAULT NULL AFTER `sipcalledip`", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	if(!opt_disable_cdr_fields_rtp) {
		extern int opt_silencedetect;
		this->checkNeedAlterAdd("cdr", "silencedetect", opt_silencedetect,
					log, &tableSize, &existsColumns.cdr_silencedetect,
					"caller_silence", "tinyint unsigned default NULL", NULL_CHAR_PTR,
					"called_silence", "tinyint unsigned default NULL", NULL_CHAR_PTR,
					"caller_silence_end", "smallint default NULL", NULL_CHAR_PTR,
					"called_silence_end", "smallint default NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	if(!opt_disable_cdr_fields_rtp) {
		extern int opt_clippingdetect;
		this->checkNeedAlterAdd("cdr", "clippingdetect", opt_clippingdetect,
					log, &tableSize, &existsColumns.cdr_clippingdetect,
					"caller_clipping_div3", "smallint unsigned default NULL", NULL_CHAR_PTR,
					"called_clipping_div3", "smallint unsigned default NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	if(!opt_disable_cdr_fields_rtp) {
		this->checkNeedAlterAdd("cdr", "rctp_fraclost_pktcount", true,
					log, &tableSize, &existsColumns.cdr_rtcp_fraclost_pktcount,
					"a_rtcp_fraclost_pktcount", "int unsigned default NULL", NULL_CHAR_PTR,
					"b_rtcp_fraclost_pktcount", "int unsigned default NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	this->checkNeedAlterAdd("cdr", "rtp ptime", true,
				log, &tableSize, &existsColumns.cdr_rtp_ptime,
				"a_rtp_ptime", "tinyint unsigned default NULL", NULL_CHAR_PTR,
				"b_rtp_ptime", "tinyint unsigned default NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr", "dscp", opt_dscp,
				log, &tableSize, &existsColumns.cdr_dscp,
				"dscp", "int unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr", "mos lqo", opt_mos_lqo,
				log, &tableSize, &existsColumns.cdr_mos_lqo,
				"a_mos_lqo_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"b_mos_lqo_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr", "flags", true,
				log, &tableSize, &existsColumns.cdr_flags,
				"flags", "bigint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr", "maximum retransmissions invite", true,
				log, &tableSize, &existsColumns.cdr_max_retransmission_invite,
				"max_retransmission_invite", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);

	if(this->existsTable("billing")) {
		if(!this->existsColumn("cdr", "price_operator_mult100") &&
		   !this->existsColumn("cdr", "price_operator_mult1000000")) {
			this->checkNeedAlterAdd("cdr", "billing feature", true,
						log, &tableSize, NULL,
						"price_operator_mult1000000", "BIGINT UNSIGNED", NULL_CHAR_PTR,
						"price_operator_currency_id", "TINYINT UNSIGNED", NULL_CHAR_PTR,
						"price_customer_mult1000000", "BIGINT UNSIGNED", NULL_CHAR_PTR,
						"price_customer_currency_id", "TINYINT UNSIGNED", NULL_CHAR_PTR,
						NULL_CHAR_PTR);
		} else if(this->existsExtPrecissionBilling() &&
			  this->existsColumn("cdr", "price_operator_mult100") &&
			  !this->existsColumn("cdr", "price_operator_mult1000000")) {
			vector<string> alters;
			alters.push_back(
				"ALTER TABLE cdr "
				"ADD COLUMN price_operator_mult1000000 BIGINT UNSIGNED, "
				"ADD COLUMN price_customer_mult1000000 BIGINT UNSIGNED;");
			alters.push_back(
				"UPDATE cdr "
				"set price_operator_mult1000000 = price_operator_mult100 * 10000 "
				"where price_operator_mult100 <> 0;");
			alters.push_back(
				"UPDATE cdr "
				"set price_customer_mult1000000 = price_customer_mult100 * 10000 "
				"where price_customer_mult100 <> 0;");
			if(this->logNeedAlter("cdr",
					      "billing feature - add extended price precision",
					      alters,
					      log, &tableSize, NULL)) {
				this->removeTableFromColumnCache("cdr");
			}
		}
	}
	existsColumns.cdr_price_operator_mult1000000 = this->existsColumn("cdr", "price_operator_mult1000000");
	existsColumns.cdr_price_operator_mult100 = this->existsColumn("cdr", "price_operator_mult100");
	existsColumns.cdr_price_operator_currency_id = this->existsColumn("cdr", "price_operator_currency_id");
	existsColumns.cdr_price_customer_mult1000000 = this->existsColumn("cdr", "price_customer_mult1000000");
	existsColumns.cdr_price_customer_mult100 = this->existsColumn("cdr", "price_customer_mult100");
	existsColumns.cdr_price_customer_currency_id = this->existsColumn("cdr", "price_customer_currency_id");
	
	this->checkNeedAlterAdd("cdr", "SIP header 'reason'", true,
				log, &tableSize, &existsColumns.cdr_reason,
				"reason_sip_cause", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"reason_sip_text_id", "mediumint unsigned DEFAULT NULL", "reason_sip_text_id (reason_sip_text_id)",
				"reason_q850_cause", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"reason_q850_text_id", "mediumint unsigned DEFAULT NULL", "reason_q850_text_id (reason_q850_text_id)",
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr", "SIP response time", true,
				log, &tableSize, &existsColumns.cdr_response_time_100,
				"response_time_100", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"response_time_xxx", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	existsColumns.cdr_response_time_100 = this->existsColumn("cdr", "response_time_100");
	existsColumns.cdr_response_time_xxx = this->existsColumn("cdr", "response_time_xxx");
	//14.0
	if(!opt_disable_cdr_fields_rtp) {
		this->checkNeedAlterAdd("cdr", "MOS min", true,
					log, &tableSize, &existsColumns.cdr_mos_min,
					"a_mos_f1_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"a_mos_f2_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"a_mos_adapt_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_mos_f1_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_mos_f2_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_mos_adapt_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	//14.3
	if(!opt_disable_cdr_fields_rtp) {
		this->checkNeedAlterAdd("cdr", "MOS RTCP XR", true,
					log, &tableSize, &existsColumns.cdr_mos_xr,
					"a_mos_xr_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_mos_xr_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"a_mos_xr_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_mos_xr_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
		this->checkNeedAlterAdd("cdr", "RTCP Roundtrip Delay", true,
					log, &tableSize, &existsColumns.cdr_rtcp_rtd,
					"a_rtcp_avgrtd_mult10", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_rtcp_avgrtd_mult10", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"a_rtcp_maxrtd_mult10", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_rtcp_maxrtd_mult10", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
		this->checkNeedAlterAdd("cdr", "RTCP Roundtrip Delay (wireshark version)", true,
					log, &tableSize, &existsColumns.cdr_rtcp_rtd_w,
					"a_rtcp_avgrtd_w", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_rtcp_avgrtd_w", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"a_rtcp_maxrtd_w", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_rtcp_maxrtd_w", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	//23.7
	if(!opt_disable_cdr_fields_rtp) {
		this->checkNeedAlterAdd("cdr", "Columns MOS Silence", true,
					log, &tableSize, &existsColumns.cdr_mos_silence,
					"a_mos_silence_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_mos_silence_min_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"a_mos_silence_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"b_mos_silence_mult10", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	this->checkNeedAlterAdd("cdr", "Vlan", true,
				log, &tableSize, &existsColumns.cdr_vlan,
				"vlan", "smallint DEFAULT NULL", "`vlan` (`vlan`)", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	//27.3
	this->checkNeedAlterAdd("cdr", "SIP IP from first IP header", opt_save_ip_from_encaps_ipheader,
				log, &tableSize, &existsColumns.cdr_sipcallerdip_encaps,
				"sipcallerip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_encaps` (`sipcallerip_encaps`)",
				"sipcalledip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcalledip_encaps` (`sipcalledip_encaps`)",
				"sipcallerip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"sipcalledip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	
	existsColumns.cdr_ab_rtcp_loss_is_smallint_type[0] = this->getTypeColumn("cdr", "a_rtcp_loss", true).find("smallint") != string::npos;
	existsColumns.cdr_ab_rtcp_loss_is_smallint_type[1] = this->getTypeColumn("cdr", "b_rtcp_loss", true).find("smallint") != string::npos;
	existsColumns.cdr_ab_rtcp_loss_is_signed_type[0] = this->getTypeColumn("cdr", "a_rtcp_loss", true).find("unsigned") == string::npos;
	existsColumns.cdr_ab_rtcp_loss_is_signed_type[1] = this->getTypeColumn("cdr", "b_rtcp_loss", true).find("unsigned") == string::npos;
	
	existsColumns.cdr_a_last_rtp_from_end_unsigned = this->getTypeColumn("cdr", "a_last_rtp_from_end").find("unsigned") != string::npos;
	existsColumns.cdr_b_last_rtp_from_end_unsigned = this->getTypeColumn("cdr", "b_last_rtp_from_end").find("unsigned") != string::npos;
	
	if(opt_separate_storage_ipv6_ipv4_address) {
		this->checkNeedAlterAdd("cdr", "separate storage IPv4 and IPv6 sip address", opt_separate_storage_ipv6_ipv4_address,
					log, &tableSize, &existsColumns.cdr_sipcallerdip_v6,
					"sipcallerip_v4", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_v4` (`sipcallerip_v4`)",
					"sipcallerport_v4", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"sipcalledip_v4", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcalledip_v4` (`sipcalledip_v4`)",
					"sipcalledport_v4", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"sipcallerip_v6", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_v6` (`sipcallerip_v6`)",
					"sipcallerport_v6", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"sipcalledip_v6", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcalledip_v6` (`sipcalledip_v6`)",
					"sipcalledport_v6", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	
	if(!this->existsIndex("sensors", "id_sensor", 1)) {
		bool dupl = false;
		if(this->query("select count(*) as cnt from sensors \
				group by id_sensor order by cnt desc limit 1")) {
			SqlDb_row row = this->fetchRow();
			if(row && atoi(row["cnt"].c_str()) > 1) {
				dupl = true;
			}
		}
		if(!dupl) {
			this->query("alter table sensors add unique(id_sensor)");
		}
	}
}

void SqlDb_mysql::checkColumns_cdr_next(bool log) {
	map<string, u_int64_t> tableSize;
	this->checkNeedAlterAdd("cdr_next", "cdr digest username (can be used by custom header)", true,
				log, &tableSize, &existsColumns.cdr_next_digest_username,
				"digest_username", "varchar(255) DEFAULT NULL", "digest_username (digest_username)",
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_next", "cdr spool index", true,
				log, &tableSize, &existsColumns.cdr_next_spool_index,
				"spool_index", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_next", "cdr hold", true,
				log, &tableSize, &existsColumns.cdr_next_hold,
				"hold", "varchar(1024) DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	if(opt_conference_processing) {
		this->checkNeedAlterAdd("cdr_next", "conference flag", true,
					log, &tableSize, &existsColumns.cdr_next_conference_flag,
					"conference_flag", "enum('main','leg') DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
		this->checkNeedAlterAdd("cdr_next", "conference referred_by", true,
					log, &tableSize, &existsColumns.cdr_next_conference_referred_by,
					"conference_referred_by", "varchar(1024) DEFAULT NULL", "`conference_referred_by` (`conference_referred_by`)",
					NULL_CHAR_PTR);
		this->checkNeedAlterAdd("cdr_next", "conference referred_by ok_time", true,
					log, &tableSize, &existsColumns.cdr_next_conference_referred_by_ok_time,
					"conference_referred_by_ok_time", (column_type_datetime_ms() + " DEFAULT NULL").c_str(), NULL_CHAR_PTR,
					NULL_CHAR_PTR);
		for(int pass = 0; pass < 2; pass++) {
			vector<string> alters_ms;
			if(!(existsColumns.cdr_next_conference_referred_by_ok_time_ms = this->getTypeColumn("cdr_next", "conference_referred_by_ok_time").find("(3)") != string::npos)) {
				alters_ms.push_back("modify column connect_time " + column_type_datetime_ms() + " not null");
			}
			if(pass == 0 && opt_time_precision_in_ms) {
				if(alters_ms.size()) {
					if(isSupportForDatetimeMs()) {
						if(this->logNeedAlter("cdr_next",
								      "time accuracy in milliseconds",
								      "ALTER TABLE cdr_next " + implode(alters_ms, ", ") + ";",
								      log, &tableSize, NULL)) {
							this->removeTableFromColumnCache("cdr_next");
						}
						continue;
					} else {
						cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
						opt_time_precision_in_ms = false;
					}
				}
			}
			break;
		}
	}
	if(opt_mo_mt_identification_prefix.size()) {
		this->checkNeedAlterAdd("cdr_next", "leg flag", true,
					log, &tableSize, &existsColumns.cdr_next_leg_flag,
					"srvcc_call_id", "enum('mo','mt') DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	if(srvcc_set) {
		this->checkNeedAlterAdd("cdr_next", "srvcc call id", true,
					log, &tableSize, &existsColumns.cdr_next_srvcc_call_id,
					"srvcc_call_id", "varchar(255) DEFAULT NULL", "srvcc_call_id (srvcc_call_id)",
					NULL_CHAR_PTR);
		this->checkNeedAlterAdd("cdr_next", "srvcc flag", true,
					log, &tableSize, &existsColumns.cdr_next_srvcc_flag,
					"srvcc_flag", "enum('post_srvcc','pre_srvcc') DEFAULT NULL", "srvcc_flag (srvcc_flag)",
					NULL_CHAR_PTR);
	}
}

void SqlDb_mysql::checkColumns_cdr_next_branches(bool log) {
	map<string, u_int64_t> tableSize;
	existsColumns.cdr_next_branches = this->existsTable("cdr_next_branches");
	this->checkNeedAlterAdd("cdr_next_branches", "store sip ports (next branches)", opt_cdr_sipport,
				log, &tableSize, &existsColumns.cdr_next_branches_sipport,
				"sipcallerport", "smallint unsigned DEFAULT NULL AFTER `sipcallerip`", NULL_CHAR_PTR,
				"sipcalledport", "smallint unsigned DEFAULT NULL AFTER `sipcalledip`", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_next_branches", "SIP IP from first IP header (next branches)", opt_save_ip_from_encaps_ipheader,
				log, &tableSize, &existsColumns.cdr_next_branches_sipcallerdip_encaps,
				"sipcallerip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_encaps` (`sipcallerip_encaps`)",
				"sipcalledip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcalledip_encaps` (`sipcalledip_encaps`)",
				"sipcallerip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"sipcalledip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	if(opt_separate_storage_ipv6_ipv4_address) {
		this->checkNeedAlterAdd("cdr_next_branches", "separate storage IPv4 and IPv6 sip address (next branches)", opt_separate_storage_ipv6_ipv4_address,
					log, &tableSize, &existsColumns.cdr_next_branches_sipcallerdip_v6,
					"sipcallerip_v4", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_v4` (`sipcallerip_v4`)",
					"sipcallerport_v4", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"sipcalledip_v4", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcalledip_v4` (`sipcalledip_v4`)",
					"sipcalledport_v4", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"sipcallerip_v6", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_v6` (`sipcallerip_v6`)",
					"sipcallerport_v6", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					"sipcalledip_v6", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcalledip_v6` (`sipcalledip_v6`)",
					"sipcalledport_v6", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
}

void SqlDb_mysql::checkColumns_cdr_sdp(bool log) {
	map<string, u_int64_t> tableSize;
	this->checkNeedAlterAdd("cdr_sdp", "sdp ptime", true,
				log, &tableSize, &existsColumns.cdr_sdp_ptime,
				"ptime", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
}
 
void SqlDb_mysql::checkColumns_cdr_rtp(bool log) {
	map<string, u_int64_t> tableSize;
	this->checkNeedAlterAdd("cdr_rtp", "rtp destination port", opt_cdr_rtpport,
				log, &tableSize, &existsColumns.cdr_rtp_dport,
				"dport", "smallint unsigned DEFAULT NULL AFTER `daddr`", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_rtp", "rtp source port", opt_cdr_rtpsrcport,
				log, &tableSize, &existsColumns.cdr_rtp_sport,
				"sport", "smallint unsigned DEFAULT NULL AFTER `saddr`", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_rtp", "rtp index of stream", true,
				log, &tableSize, &existsColumns.cdr_rtp_index,
				"index", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_rtp", "rtp & sdp ptime", true,
				log, &tableSize, &existsColumns.cdr_rtp_sdp_ptime,
				"sdp_ptime", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"rtp_ptime", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_rtp", "flags", true,
				log, &tableSize, &existsColumns.cdr_rtp_flags,
				"flags", "bigint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("cdr_rtp", "rtp duration", true,
				log, &tableSize, &existsColumns.cdr_rtp_duration,
				"duration", string(column_type_duration_ms("float") + " DEFAULT NULL").c_str(), NULL_CHAR_PTR,
				NULL_CHAR_PTR);
}

void SqlDb_mysql::checkColumns_cdr_dtmf(bool log) {
	extern int opt_dbdtmf;
	map<string, u_int64_t> tableSize;
	this->checkNeedAlterAdd("cdr_dtmf", "type", opt_dbdtmf,
				log, &tableSize, &existsColumns.cdr_dtmf_type,
				"type", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
}

void SqlDb_mysql::checkColumns_cdr_conference(bool log) {
	existsColumns.cdr_conference = this->existsTable("cdr_conference");
	if(!existsColumns.cdr_conference) {
		return;
	}
	map<string, u_int64_t> tableSize;
	for(int pass = 0; pass < 2; pass++) {
		vector<string> alters_ms;
		if(!(existsColumns.cdr_conference_connect_time_ms = this->getTypeColumn("cdr_conference", "connect_time").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column connect_time " + column_type_datetime_ms() + " not null");
		}
		if(!(existsColumns.cdr_conference_disconnect_time_ms = this->getTypeColumn("cdr_conference", "disconnect_time").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column disconnect_time " + column_type_datetime_ms() + " not null");
		}
		if(pass == 0 && opt_time_precision_in_ms) {
			if(alters_ms.size()) {
				if(isSupportForDatetimeMs()) {
					if(this->logNeedAlter("cdr_conference",
							      "time accuracy in milliseconds",
							      "ALTER TABLE cdr_conference " + implode(alters_ms, ", ") + ";",
							      log, &tableSize, NULL)) {
						this->removeTableFromColumnCache("cdr_conference");
					}
					continue;
				} else {
					cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
					opt_time_precision_in_ms = false;
				}
			}
		}
		break;
	}
}

void SqlDb_mysql::checkColumns_cdr_child(bool log) {
	existsColumns.cdr_next_calldate = this->existsColumn("cdr_next", "calldate");
	if(existsColumns.cdr_next_branches) {
		existsColumns.cdr_next_branches_calldate = this->existsColumn("cdr_next_branches", "calldate");
	}
	existsColumns.cdr_rtp_calldate = this->existsColumn("cdr_rtp", "calldate");
	if(opt_save_energylevels) {
		existsColumns.cdr_rtp_energylevels_calldate = this->existsColumn("cdr_rtp_energylevels", "calldate");
	}
	existsColumns.cdr_dtmf_calldate = this->existsColumn("cdr_dtmf", "calldate");
	existsColumns.cdr_sipresp_calldate = this->existsColumn("cdr_sipresp", "calldate");
	if(_save_sip_history) {
		existsColumns.cdr_siphistory_calldate = this->existsColumn("cdr_siphistory", "calldate");
	}
	existsColumns.cdr_tar_part_calldate = this->existsColumn("cdr_tar_part", "calldate");
	existsColumns.cdr_country_code_calldate = this->existsColumn("cdr_country_code", "calldate");
	existsColumns.cdr_sdp_calldate = this->existsColumn("cdr_sdp", "calldate");
	if(this->existsTable("cdr_conference")) {
		existsColumns.cdr_conference_calldate = this->existsColumn("cdr_conference", "calldate");
	}
	existsColumns.cdr_txt_calldate = this->existsColumn("cdr_txt", "calldate");
	map<string, u_int64_t> tableSize;
	vector<sTableCalldateMsIndik> childTablesCalldateMsIndik;
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_next_calldate_ms, "cdr_next"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_proxy_calldate_ms, "cdr_proxy"));
	if(existsColumns.cdr_next_branches) {
		childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_next_branches_calldate_ms, "cdr_next_branches"));
	}
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_rtp_calldate_ms, "cdr_rtp"));
	if(opt_save_energylevels) {
		childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_rtp_energylevels_calldate_ms, "cdr_rtp_energylevels"));
	}
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_dtmf_calldate_ms, "cdr_dtmf"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_sipresp_calldate_ms, "cdr_sipresp"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_siphistory_calldate_ms, "cdr_siphistory"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_tar_part_calldate_ms, "cdr_tar_part"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_country_code_calldate_ms, "cdr_country_code"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_sdp_calldate_ms, "cdr_sdp"));
	if(opt_conference_processing) {
		childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_conference_calldate_ms, "cdr_conference"));
	}
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_txt_calldate_ms, "cdr_txt"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_child_flags_calldate_ms, "cdr_flags"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.cdr_audio_transcribe_calldate_ms, "cdr_audio_transcribe"));
	for(unsigned i = 0; i < childTablesCalldateMsIndik.size(); i++) {
		for(int pass = 0; pass < 2; pass++) {
			string alter_ms;
			if(!(*(childTablesCalldateMsIndik[i].ms) = this->getTypeColumn(childTablesCalldateMsIndik[i].table.c_str(), childTablesCalldateMsIndik[i].calldate.c_str()).find("(3)") != string::npos)) {
				alter_ms = "modify column " + childTablesCalldateMsIndik[i].calldate + " " + column_type_datetime_child_ms() + " not null";
			}
			if(pass == 0 && opt_time_precision_in_ms) {
				if(!alter_ms.empty()) {
					if(isSupportForDatetimeMs()) {
						if(this->logNeedAlter(childTablesCalldateMsIndik[i].table,
								      "time accuracy in milliseconds",
								      "ALTER TABLE " + childTablesCalldateMsIndik[i].table + " " + alter_ms + ";",
								      log, &tableSize, NULL)) {
							this->removeTableFromColumnCache(childTablesCalldateMsIndik[i].table.c_str());
						}
						continue;
					} else {
						cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
						opt_time_precision_in_ms = false;
					}
				}
			}
			break;
		}
	}
}

void SqlDb_mysql::checkColumns_cdr_stat(bool log) {
	for(int src_dst = 0; src_dst < 2; src_dst++) {
		cCdrStat::exists_columns_clear(src_dst);
	}
	if(!opt_cdr_stat_values || (!this->existsTable("cdr_stat_values") && !this->existsTable("cdr_stat_values_dst"))) {
		return;
	}
	vector<dstring> cdr_stat_fields;
	cCdrStat::metrics_db_fields(&cdr_stat_fields);
	for(int src_dst = 0; src_dst < 2; src_dst++) {
		if(cCdrStat::enableBySrcDst(src_dst)) {
			map<string, u_int64_t> tableSize;
			for(unsigned i = 0; i < cdr_stat_fields.size(); i++) {
				bool existsColumn = false;
				this->checkNeedAlterAdd("cdr_stat_values" + cCdrStat::tableNameSuffix(src_dst), "field " + cdr_stat_fields[i].str[0], true,
							log, &tableSize, &existsColumn,
							cdr_stat_fields[i].str[0].c_str(), cdr_stat_fields[i].str[1].c_str(), NULL_CHAR_PTR,
							NULL_CHAR_PTR);
				if(existsColumn) {
					cCdrStat::exists_columns_add(cdr_stat_fields[i].str[0].c_str(), src_dst);
				}
			}
		}
	}
}

void SqlDb_mysql::checkColumns_cdr_problems(bool log) {
	for(int by_type = 0; by_type < 3; by_type++) {
		cCdrProblems::exists_columns_clear(by_type);
	}
	bool existsTable = false;
	for(int by_type = 0; by_type < 3; by_type++) {
		if(this->existsTable("cdr_problems" + cCdrProblems::tableNameSuffix(by_type))) {
			existsTable = true;
			break;
		}
	}
	if(!opt_cdr_problems || !existsTable) {
		return;
	}
	vector<dstring> cdr_problems_fields;
	cCdrProblems::db_fields(&cdr_problems_fields);
	for(int by_type = 0; by_type < 3; by_type++) {
		if(cCdrProblems::enableByType(by_type)) {
			map<string, u_int64_t> tableSize;
			for(unsigned i = 0; i < cdr_problems_fields.size(); i++) {
				bool existsColumn = false;
				this->checkNeedAlterAdd("cdr_problems" + cCdrProblems::tableNameSuffix(by_type), "field " + cdr_problems_fields[i].str[0], true,
							log, &tableSize, &existsColumn,
							cdr_problems_fields[i].str[0].c_str(), cdr_problems_fields[i].str[1].c_str(), NULL_CHAR_PTR,
							NULL_CHAR_PTR);
				if(existsColumn) {
					cCdrProblems::exists_columns_add(cdr_problems_fields[i].str[0].c_str(), by_type);
				}
			}
		}
	}
}

void SqlDb_mysql::checkColumns_ss7(bool log) {
	if(!this->existsTable("ss7")) {
		return;
	}
	map<string, u_int64_t> tableSize;
	this->checkNeedAlterAdd("ss7", "flags", true,
				log, &tableSize, &existsColumns.ss7_flags,
				"flags", "bigint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	for(int pass = 0; pass < 2; pass++) {
		vector<string> alters_ms;
		if(!(existsColumns.ss7_time_iam_ms = this->getTypeColumn("ss7", "time_iam").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column time_iam " + column_type_datetime_ms() + " not null");
		}
		if(!(existsColumns.ss7_time_acm_ms = this->getTypeColumn("ss7", "time_acm").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column time_acm " + column_type_datetime_ms());
		}
		if(!(existsColumns.ss7_time_cpg_ms = this->getTypeColumn("ss7", "time_cpg").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column time_cpg " + column_type_datetime_ms());
		}
		if(!(existsColumns.ss7_time_anm_ms = this->getTypeColumn("ss7", "time_anm").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column time_anm " + column_type_datetime_ms());
		}
		if(!(existsColumns.ss7_time_rel_ms = this->getTypeColumn("ss7", "time_rel").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column time_rel " + column_type_datetime_ms());
		}
		if(!(existsColumns.ss7_time_rlc_ms = this->getTypeColumn("ss7", "time_rlc").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column time_rlc " + column_type_datetime_ms());
		}
		if(!(existsColumns.ss7_duration_ms = this->getTypeColumn("ss7", "duration").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column duration " + column_type_duration_ms() + " unsigned");
		}
		if(!(existsColumns.ss7_connect_duration_ms = this->getTypeColumn("ss7", "connect_duration").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column connect_duration " + column_type_duration_ms() + " unsigned");
		}
		if(!(existsColumns.ss7_progress_time_ms = this->getTypeColumn("ss7", "progress_time").find("decimal") != string::npos)) {
			alters_ms.push_back("modify column progress_time " + column_type_duration_ms() + " unsigned");
		}
		if(pass == 0 && opt_time_precision_in_ms) {
			if(alters_ms.size()) {
				if(isSupportForDatetimeMs()) {
					if(this->logNeedAlter("ss7",
							      "time accuracy in milliseconds",
							      "ALTER TABLE ss7 " + implode(alters_ms, ", ") + ";",
							      log, &tableSize, NULL)) {
						this->removeTableFromColumnCache("ss7");
					}
					continue;
				} else {
					cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
					opt_time_precision_in_ms = false;
				}
			}
		}
		break;
	}
}

void SqlDb_mysql::checkColumns_message(bool log) {
	map<string, u_int64_t> tableSize;
	for(int pass = 0; pass < 2; pass++) {
		string alter_ms;
		if(!(existsColumns.message_calldate_ms = this->getTypeColumn("message", "calldate").find("(3)") != string::npos)) {
			alter_ms = "modify column calldate " + column_type_datetime_ms() + " not null";
		}
		if(pass == 0 && opt_time_precision_in_ms) {
			if(!alter_ms.empty()) {
				if(isSupportForDatetimeMs()) {
					if(this->logNeedAlter("message",
							      "time accuracy in milliseconds",
							      "ALTER TABLE message " + alter_ms + ";",
							      log, &tableSize, NULL)) {
						this->removeTableFromColumnCache("message");
					}
					continue;
				} else {
					cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
					opt_time_precision_in_ms = false;
				}
			}
		}
		break;
	}
	existsColumns.message_content_length = this->existsColumn("message", "content_length");
	this->checkNeedAlterAdd("message", "SIP response time", true,
				log, &tableSize, &existsColumns.message_response_time,
				"response_time", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("message", "message spool index", true,
				log, &tableSize, &existsColumns.message_spool_index,
				"spool_index", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("message", "Vlan", true,
				log, &tableSize, &existsColumns.message_vlan,
				"vlan", "smallint DEFAULT NULL", "`vlan` (`vlan`)",
				NULL_CHAR_PTR);
}

void SqlDb_mysql::checkColumns_message_child(bool log) {
	map<string, u_int64_t> tableSize;
	vector<sTableCalldateMsIndik> childTablesCalldateMsIndik;
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.message_child_proxy_calldate_ms, "message_proxy"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.message_child_country_code_calldate_ms, "message_country_code"));
	childTablesCalldateMsIndik.push_back(sTableCalldateMsIndik(&existsColumns.message_child_flags_calldate_ms, "message_flags"));
	for(unsigned i = 0; i < childTablesCalldateMsIndik.size(); i++) {
		for(int pass = 0; pass < 2; pass++) {
			string alter_ms;
			if(!(*(childTablesCalldateMsIndik[i].ms) = this->getTypeColumn(childTablesCalldateMsIndik[i].table.c_str(), childTablesCalldateMsIndik[i].calldate.c_str()).find("(3)") != string::npos)) {
				alter_ms = "modify column " + childTablesCalldateMsIndik[i].calldate + " " + column_type_datetime_child_ms() + " not null";
			}
			if(pass == 0 && opt_time_precision_in_ms) {
				if(!alter_ms.empty()) {
					if(isSupportForDatetimeMs()) {
						if(this->logNeedAlter(childTablesCalldateMsIndik[i].table,
								      "time accuracy in milliseconds",
								      "ALTER TABLE " + childTablesCalldateMsIndik[i].table + " " + alter_ms + ";",
								      log, &tableSize, NULL)) {
							this->removeTableFromColumnCache(childTablesCalldateMsIndik[i].table.c_str());
						}
						continue;
					} else {
						cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
						opt_time_precision_in_ms = false;
					}
				}
			}
			break;
		}
	}
}

void SqlDb_mysql::checkColumns_register(bool log) {
	map<string, u_int64_t> tableSize;
	for(int pass = 0; pass < 2; pass++) {
		vector<dstring> alters_ms;
		if(opt_sip_register == 2) {
			if(!(existsColumns.register_calldate_ms = this->getTypeColumn("register", "calldate").find("(3)") != string::npos)) {
				alters_ms.push_back(dstring("register", "modify column calldate " + column_type_datetime_ms() + " not null"));
			}
		}
		if(!(existsColumns.register_state_created_at_ms = this->getTypeColumn("register_state", "created_at").find("(3)") != string::npos)) {
			alters_ms.push_back(dstring("register_state", "modify column created_at " + column_type_datetime_ms() + " not null"));
		}
		if(!(existsColumns.register_failed_created_at_ms = this->getTypeColumn("register_failed", "created_at").find("(3)") != string::npos)) {
			alters_ms.push_back(dstring("register_failed", "modify column created_at " + column_type_datetime_ms() + " not null"));
		}
		if(pass == 0 && opt_time_precision_in_ms) {
			if(alters_ms.size()) {
				if(isSupportForDatetimeMs()) {
					for(unsigned i = 0; i < alters_ms.size(); i++) {
						if(this->logNeedAlter(alters_ms[i][0],
								      "time accuracy in milliseconds",
								      "ALTER TABLE " + alters_ms[i][0] + " " + alters_ms[i][1] + ";",
								      log, &tableSize, NULL)) {
							this->removeTableFromColumnCache(alters_ms[i][0].c_str());
						}
					}
					continue;
				} else {
					cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
					opt_time_precision_in_ms = false;
				}
			}
		}
		break;
	}
	if(enable_register_engine) {
		bool registerStateIdIsBig = true;
		bool registerStateIdIsAutoIncrement = true;
		this->query("show columns from register_state like 'id'");
		SqlDb_row register_state_struct_row = this->fetchRow();
		if(register_state_struct_row) {
			string idType = register_state_struct_row["type"];
			std::transform(idType.begin(), idType.end(), idType.begin(), ::toupper);
			if(idType.find("BIG") == string::npos) {
				registerStateIdIsBig = false;
			}
			string extra = register_state_struct_row["extra"];
			std::transform(extra.begin(), extra.end(), extra.begin(), ::toupper);
			if(extra.find("AUTO_INCREMENT") == string::npos) {
				registerStateIdIsAutoIncrement = false;
			}
		}
		if(!registerStateIdIsBig || !registerStateIdIsAutoIncrement) {
			this->logNeedAlter("register_state",
					   "register state",
					   "ALTER TABLE register_state "
					   "CHANGE COLUMN `ID` `ID` bigint unsigned NOT NULL AUTO_INCREMENT;",
					   log, &tableSize, NULL);
		}
		bool registerFailedIdIsBig = true;
		bool registerFailedIdIsAutoIncrement = true;
		this->query("show columns from register_failed like 'id'");
		SqlDb_row register_failed_struct_row = this->fetchRow();
		if(register_failed_struct_row) {
			string idType = register_failed_struct_row["type"];
			std::transform(idType.begin(), idType.end(), idType.begin(), ::toupper);
			if(idType.find("BIG") == string::npos) {
				registerFailedIdIsBig = false;
			}
			string extra = register_failed_struct_row["extra"];
			std::transform(extra.begin(), extra.end(), extra.begin(), ::toupper);
			if(extra.find("AUTO_INCREMENT") == string::npos) {
				registerFailedIdIsAutoIncrement = false;
			}
		}
		if(!registerFailedIdIsBig || !registerFailedIdIsAutoIncrement) {
			this->logNeedAlter("register_failed",
					   "register failed",
					   "ALTER TABLE register_failed "
					   "CHANGE COLUMN `ID` `ID` bigint unsigned NOT NULL AUTO_INCREMENT;",
					   log, &tableSize, NULL);
		}
	}
	if(this->existsTable("register_state_eq_next")) {
		existsColumns.register_state_eq_next_created_at = this->existsColumn("register_state_eq_next", "created_at");
		if(existsColumns.register_state_eq_next_created_at) {
			existsColumns.register_state_eq_next_created_at_ms = this->getTypeColumn("register_state_eq_next", "created_at").find("(3)") != string::npos;
		}
		existsColumns.register_state_eq_next_next_at_ms = this->getTypeColumn("register_state_eq_next", "next_at").find("(3)") != string::npos;
	}
	if(this->existsTable("register_failed_eq_next")) {
		existsColumns.register_failed_eq_next_created_at = this->existsColumn("register_failed_eq_next", "created_at");
		if(existsColumns.register_failed_eq_next_created_at) {
			existsColumns.register_failed_eq_next_created_at_ms = this->getTypeColumn("register_failed_eq_next", "created_at").find("(3)") != string::npos;
		}
		existsColumns.register_failed_eq_next_next_at_ms = this->getTypeColumn("register_failed_eq_next", "next_at").find("(3)") != string::npos;
	}
	if(opt_sip_register_save_eq_states_time) {
		this->checkNeedAlterAdd("register_state", "register_state counter", true,
					log, &tableSize, &existsColumns.register_state_counter,
					"counter", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
	this->checkNeedAlterAdd("register_state", "register_state spool index", true,
				log, &tableSize, &existsColumns.register_state_spool_index,
				"spool_index", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_state", "register_state flags", true,
				log, &tableSize, &existsColumns.register_state_flags,
				"flags", "bigint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_state", "register_state vlan", true,
				log, &tableSize, &existsColumns.register_state_vlan,
				"vlan", "smallint DEFAULT NULL", "`vlan` (`vlan`)",
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_state", "register_state digestrealm", true,
				log, &tableSize, &existsColumns.register_state_digestrealm,
				"digestrealm", "varchar(255) DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_state", "register_state sipcallerport", true,
				log, &tableSize, &existsColumns.register_state_sipcallerport,
				"sipcallerport", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_state", "register_state sipcalledport", true,
				log, &tableSize, &existsColumns.register_state_sipcalledport,
				"sipcalledport", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_failed", "register_failed sipcallerport", true,
				log, &tableSize, &existsColumns.register_failed_sipcallerport,
				"sipcallerport", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_failed", "register_failed sipcalledport", true,
				log, &tableSize, &existsColumns.register_failed_sipcalledport,
				"sipcalledport", "smallint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_failed", "register_failed spool index", true,
				log, &tableSize, &existsColumns.register_failed_spool_index,
				"spool_index", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_failed", "register_failed flags", true,
				log, &tableSize, &existsColumns.register_failed_flags,
				"flags", "bigint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_failed", "register_failed vlan", true,
				log, &tableSize, &existsColumns.register_failed_vlan,
				"vlan", "smallint DEFAULT NULL", "`vlan` (`vlan`)",
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_failed", "register_failed digestrealm", true,
				log, &tableSize, &existsColumns.register_failed_digestrealm,
				"digestrealm", "varchar(255) DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	//27.3
	this->checkNeedAlterAdd("register_state", "SIP IP from first IP header", opt_save_ip_from_encaps_ipheader,
				log, &tableSize, &existsColumns.register_state_sipcallerdip_encaps,
				"sipcallerip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_encaps` (`sipcallerip_encaps`)",
				"sipcalledip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), NULL_CHAR_PTR,
				"sipcallerip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"sipcalledip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	this->checkNeedAlterAdd("register_failed", "SIP IP from first IP header", opt_save_ip_from_encaps_ipheader,
				log, &tableSize, &existsColumns.register_failed_sipcallerdip_encaps,
				"sipcallerip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), "`sipcallerip_encaps` (`sipcallerip_encaps`)",
				"sipcalledip_encaps", (string(VM_IPV6_TYPE_MYSQL_COLUMN) + " DEFAULT NULL").c_str(), NULL_CHAR_PTR,
				"sipcallerip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				"sipcalledip_encaps_prot", "tinyint unsigned DEFAULT NULL", NULL_CHAR_PTR,
				NULL_CHAR_PTR);
	if(opt_sip_register == 2) {
		existsColumns.register_rrd_count = this->existsColumn("register", "rrd_count");
	}
}

void SqlDb_mysql::checkColumns_sip_msg(bool log) {
	map<string, u_int64_t> tableSize;
	for(int pass = 0; pass < 2; pass++) {
		vector<string> alters_ms;
		if(!(existsColumns.sip_msg_time_ms = this->getTypeColumn("sip_msg", "time").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column time " + column_type_datetime_ms() + " not null");
		}
		if(!(existsColumns.sip_msg_request_time_ms = this->getTypeColumn("sip_msg", "request_time").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column request_time " + column_type_datetime_ms() + " not null");
		}
		if(!(existsColumns.sip_msg_response_time_ms = this->getTypeColumn("sip_msg", "response_time").find("(3)") != string::npos)) {
			alters_ms.push_back("modify column response_time " + column_type_datetime_ms() + " not null");
		}
		if(pass == 0 && opt_time_precision_in_ms) {
			if(alters_ms.size()) {
				if(isSupportForDatetimeMs()) {
					if(this->logNeedAlter("sip_msg",
							      "time accuracy in milliseconds",
							      "ALTER TABLE sip_msg " + implode(alters_ms, ", ") + ";",
							      log, &tableSize, NULL)) {
						this->removeTableFromColumnCache("sip_msg");
					}
					continue;
				} else {
					cLogSensor::log(cLogSensor::error, "Your database version does not support time accuracy in milliseconds.");
					opt_time_precision_in_ms = false;
				}
			}
		}
		break;
	}
	this->checkNeedAlterAdd("sip_msg", "sip_msg vlan", true,
				log, &tableSize, &existsColumns.sip_msg_vlan,
				"vlan", "smallint DEFAULT NULL", "`vlan` (`vlan`)",
				NULL_CHAR_PTR);
}

void SqlDb_mysql::checkColumns_other(bool log) {
	if(!this->existsColumn("files", "spool_index")) {
		this->query(
			"ALTER TABLE `files`\
			 ADD COLUMN `spool_index` INT NOT NULL AFTER `id_sensor`,\
			 DROP PRIMARY KEY,\
			 ADD PRIMARY KEY (`datehour`, `id_sensor`, `spool_index`)");
	}
	if(!this->existsColumn("files", "skinnysize")) {
		this->query(
			"ALTER TABLE `files`\
			 ADD COLUMN `skinnysize` bigint unsigned DEFAULT 0");
	}
	if(!this->existsColumn("files", "mgcpsize")) {
		this->query(
			"ALTER TABLE `files`\
			 ADD COLUMN `mgcpsize` bigint unsigned DEFAULT 0");
	}
	if(!this->existsColumn("files", "ss7size")) {
		this->query(
			"ALTER TABLE `files`\
			 ADD COLUMN `ss7size` bigint unsigned DEFAULT 0");
	}
	if(!this->existsColumn("files", "audiographsize")) {
		this->query(
			"ALTER TABLE `files`\
			 ADD COLUMN `audiographsize` bigint unsigned DEFAULT 0");
	}
	if(opt_ssl_store_sessions) {
		string ssl_sessions_table = opt_ssl_store_sessions == 1 ? "ssl_sessions_mem" : "ssl_sessions";
		string ssl_sessions_id_type = this->getTypeColumn(ssl_sessions_table.c_str(), "id_sensor", true);
		existsColumns.ssl_sessions_id_sensor_is_unsigned = ssl_sessions_id_type.find("unsigned") != string::npos;
	}
	if(opt_enable_fraud) {
		map<string, u_int64_t> tableSize;
		this->checkNeedAlterAdd("cache_number_location", "ua column", true,
					log, &tableSize, &existsColumns.cache_number_location_ua,
					"ua", "varchar(512)", NULL_CHAR_PTR,
					"old_ua", "varchar(512)", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
		this->checkNeedAlterAdd("cache_number_domain_location", "ua column", true,
					log, &tableSize, &existsColumns.cache_number_domain_location_ua,
					"ua", "varchar(512)", NULL_CHAR_PTR,
					"old_ua", "varchar(512)", NULL_CHAR_PTR,
					NULL_CHAR_PTR);
	}
}

bool SqlDb_mysql::existsExtPrecissionBilling() {
	bool existsExtPrecisionBilling = false;
	for(int i = 0; i < 2 && !existsExtPrecisionBilling; i++) {
		string table = string("billing") + (i ? "_rule" : "");
		if(this->existsTable(table)) {
			this->select(table);
			SqlDb_row row;
			while((row = this->fetchRow())) {
				for(int j = 0; j < 2 && !existsExtPrecisionBilling; j++) {
					double price = atof(row[i ? (j ? "price_peak" : "price") :
								    (j ? "default_price_peak" : "default_price")].c_str());
					if(fabs(round(price * 100) - price * 100) >= 0.1) {
						existsExtPrecisionBilling = true;
					}
				}
			}
		}
	}
	return(existsExtPrecisionBilling);
}

string SqlDb_mysql::column_type_datetime_ms() {
	return(opt_time_precision_in_ms && isSupportForDatetimeMs() ?
		"datetime(3)" :
		"datetime");
}

string SqlDb_mysql::column_type_datetime_child_ms() {
	return(opt_time_precision_in_ms && isSupportForDatetimeMs() ?
		"datetime(3)" :
		"datetime");
}

string SqlDb_mysql::column_type_duration_ms(const char *base_type, bool force) {
	return((opt_time_precision_in_ms || force) && isSupportForDatetimeMs() ?
		"decimal(9,3)" :
		(base_type ? base_type : "mediumint"));
}

bool SqlDb_mysql::checkSourceTables() {
	bool ok = true;
	vector<string> sourceTables = this->getSourceTables(tt_main);
	sql_disable_next_attempt_if_error = 1;
	for(size_t i = 0; i < sourceTables.size(); i++) {
		if(!this->query("select * from " + sourceTables[i] + " limit 1")) {
			ok = false;
		} else {
			while(this->fetchRow());
		}
	}
	sql_disable_next_attempt_if_error = 0;
	return(ok);
}

void SqlDb_mysql::copyFromSourceTablesReftabs(SqlDb_mysql *sqlDbSrc,
					      cSqlDbCodebooks *cb_src, cSqlDbCodebooks *cb_dst) {
	vector<string> tablesMinor = getSourceTables(tt_reftabs);
	for(size_t i = 0; i < tablesMinor.size() && !is_terminating(); i++) {
		if(cb_src && cb_dst && tablesMinor[i] == "cdr_sip_response") {
			cSqlDbCodebook *cb_src_tab = cb_src->getCodebook(cSqlDbCodebook::_cb_sip_response);
			cSqlDbCodebook *cb_dst_tab = cb_dst->getCodebook(cSqlDbCodebook::_cb_sip_response);
			cb_src_tab->merge(cb_dst_tab, this, "cdr_sip_response");
		} else if(cb_src && cb_dst && tablesMinor[i] == "cdr_sip_request") {
			cSqlDbCodebook *cb_src_tab = cb_src->getCodebook(cSqlDbCodebook::_cb_sip_request);
			cSqlDbCodebook *cb_dst_tab = cb_dst->getCodebook(cSqlDbCodebook::_cb_sip_request);
			cb_src_tab->merge(cb_dst_tab, this, "cdr_sip_request");
		} else if(cb_src && cb_dst && tablesMinor[i] == "cdr_reason") {
			for(int i = 0; i < 2; i++) {
				cSqlDbCodebook *cb_src_tab = cb_src->getCodebook(i == 0 ? cSqlDbCodebook::_cb_reason_sip : cSqlDbCodebook::_cb_reason_q850);
				cSqlDbCodebook *cb_dst_tab = cb_dst->getCodebook(i == 0 ? cSqlDbCodebook::_cb_reason_sip : cSqlDbCodebook::_cb_reason_q850);
				cb_src_tab->merge(cb_dst_tab, this, i == 0 ? "cdr_reason - sip" : "cdr_reason - q850");
			}
		} else if(cb_src && cb_dst && tablesMinor[i] == "cdr_ua") {
			cSqlDbCodebook *cb_src_tab = cb_src->getCodebook(cSqlDbCodebook::_cb_ua);
			cSqlDbCodebook *cb_dst_tab = cb_dst->getCodebook(cSqlDbCodebook::_cb_ua);
			cb_src_tab->merge(cb_dst_tab, this, "cdr_ua");
		} else if(cb_src && cb_dst && tablesMinor[i] == "contenttype") {
			cSqlDbCodebook *cb_src_tab = cb_src->getCodebook(cSqlDbCodebook::_cb_contenttype);
			cSqlDbCodebook *cb_dst_tab = cb_dst->getCodebook(cSqlDbCodebook::_cb_contenttype);
			cb_src_tab->merge(cb_dst_tab, this, "contenttype");
		} else {
			this->copyFromSourceTable(sqlDbSrc, tablesMinor[i].c_str(), 10000);
		}
	}
}

void SqlDb_mysql::copyFromSourceTablesMain(SqlDb_mysql *sqlDbSrc,
					   unsigned long limit, bool descDir,
					   bool skipRegister,
					   bool skipMissingTables,
					   cSqlDbCodebooks *cb_src, cSqlDbCodebooks *cb_dst) {
	vector<string> tablesMain = getSourceTables(tt_main);
	for(size_t i = 0; i < tablesMain.size() && !is_terminating(); i++) {
		if((!skipMissingTables || sqlDbSrc->existsTable(tablesMain[i].c_str())) &&
		   (!skipRegister || !strstr(tablesMain[i].c_str(), "register"))) {
			this->copyFromSourceTable(sqlDbSrc, tablesMain[i].c_str(), limit ? limit : 10000, descDir,
						  cb_src, cb_dst);
		}
	}
}

void SqlDb_mysql::copyFromSourceTable(SqlDb_mysql *sqlDbSrc, 
				      const char *tableName, 
				      unsigned long limit, bool descDir,
				      cSqlDbCodebooks *cb_src, cSqlDbCodebooks *cb_dst) {
	if(!sqlDbSrc->existsTable(tableName)) {
		return;
	}
	map<string, cSqlDbCodebook::eTypeCodebook> reftable_map;
	if(cb_src && cb_dst) {
		getReferenceTablesMap(tableName, &reftable_map);
	}
	extern char opt_database_backup_from_date[20];
	extern char opt_database_backup_to_date[20];
	u_int64_t minIdSrc = 0;
	u_int64_t minIdSrc_time_limit = 0;
	string timeColumn = getTimeColumn(tableName);
	if(opt_database_backup_from_date[0] && !timeColumn.empty()) {
		sqlDbSrc->query(string("select min(id) as min_id from ") + tableName +
				" where " + timeColumn + " = " + 
				"(select min(" + timeColumn + ") from " + tableName + " where " + timeColumn + " > '" + opt_database_backup_from_date + "')");
		minIdSrc = atoll(sqlDbSrc->fetchRow()["min_id"].c_str());
		minIdSrc_time_limit = minIdSrc;
	} else {
		sqlDbSrc->query(string("select min(id) as min_id from ") + tableName);
		SqlDb_row row = sqlDbSrc->fetchRow();
		if(row) {
			minIdSrc = atoll(row["min_id"].c_str());
		}
	}
	if(!minIdSrc) {
		return;
	}
	u_int64_t maxIdSrc = 0;
	u_int64_t maxIdSrc_time_limit = 0;
	if(opt_database_backup_to_date[0] && !timeColumn.empty()) {
		sqlDbSrc->query(string("select max(id) as max_id from ") + tableName +
				" where " + timeColumn + " = " +
				"(select max(" + timeColumn + ") from " + tableName + " where " + timeColumn + " < '" + opt_database_backup_to_date + "')");
		maxIdSrc = atoll(sqlDbSrc->fetchRow()["max_id"].c_str());
		maxIdSrc_time_limit = maxIdSrc;
	} else {
		sqlDbSrc->query(string("select max(id) as max_id from ") + tableName);
		SqlDb_row row = sqlDbSrc->fetchRow();
		if(row) {
			maxIdSrc = atoll(row["max_id"].c_str());
		}
	}
	if(!maxIdSrc) {
		return;
	}
	SqlDb_row row;
	u_int64_t maxIdDst = 0;
	u_int64_t minIdDst = 0;
	u_int64_t useMaxIdInSrc = 0;
	u_int64_t useMinIdInSrc = 0;
	u_int64_t startIdSrc = 0;
	bool okStartIdSrc = true;
	if(!descDir) {
		startIdSrc = minIdSrc;
		this->query(string("select max(id) as max_id from ") + tableName);
		row = this->fetchRow();
		if(row) {
			maxIdDst = atoll(row["max_id"].c_str());
			if(maxIdDst && startIdSrc < maxIdDst + 1) {
				startIdSrc = maxIdDst + 1;
			}
		}
		if(startIdSrc > maxIdSrc) {
			okStartIdSrc = false;
		}
	} else {
		startIdSrc = maxIdSrc;
		this->query(string("select min(id) as min_id from ") + tableName);
		row = this->fetchRow();
		if(row) {
			minIdDst = atoll(row["min_id"].c_str());
			if(minIdDst && startIdSrc > minIdDst - 1) {
				startIdSrc = minIdDst - 1;
			}
		}
		if(startIdSrc < minIdSrc) {
			okStartIdSrc = false;
		}
	}
	if(okStartIdSrc) {
		map<string, int> columnsDest;
		this->query(string("show columns from ") + tableName);
		size_t i = 0;
		while((row = this->fetchRow())) {
			columnsDest[row["Field"]] = ++i;
		}
		vector<string> condSrc;
		if(!descDir) {
			if(startIdSrc) {
				condSrc.push_back(string("id >= ") + intToString(startIdSrc));
			}
			if(string(tableName) == "register_failed") {
				condSrc.push_back(string("created_at < '") + sqlDateTimeString(time(NULL) - 3600) + "'");
			}
		} else {
			condSrc.push_back(string("id <= ") + intToString(startIdSrc));
		}
		if(minIdSrc_time_limit) {
			condSrc.push_back(string("id >= ") + intToString(minIdSrc_time_limit));
		}
		if(maxIdSrc_time_limit) {
			condSrc.push_back(string("id <= ") + intToString(maxIdSrc_time_limit));
		}
		string orderSrc = "id";
		stringstream queryStr;
		queryStr << "select " << tableName << ".*"
			 << " from " << tableName;
		if(condSrc.size()) {
			queryStr << " where ";
			for(size_t i = 0; i < condSrc.size(); i++) {
				if(i) {
					queryStr << " and ";
				}
				queryStr << condSrc[i];
			}
		}
		queryStr << " order by " << orderSrc;
		if(descDir) {
			queryStr << " desc";
		}
		queryStr << " limit " << limit;
		syslog(LOG_NOTICE, "%s", ("select query: " + queryStr.str()).c_str());
		if(sqlDbSrc->query(queryStr.str())) {
			extern MySqlStore *sqlStore;
			SqlDb_row row;
			vector<SqlDb_row> rows;
			unsigned int counterInsert = 0;
			extern int opt_database_backup_insert_threads;
			unsigned int insertThreads = opt_database_backup_insert_threads > 1 ? opt_database_backup_insert_threads : 1;
			while(!is_terminating() && (row = sqlDbSrc->fetchRow())) {
				row.removeFieldsIfNotContainIn(&columnsDest);
				if(cb_src && cb_dst) {
					if(!convId(&row, tableName, cb_src, cb_dst, &reftable_map)) {
						syslog(LOG_NOTICE, "%s", "missing record in reference table - continue after next sync reference tables");
						break;
					}
				}
				if(!descDir) {
					if(!useMinIdInSrc) {
						useMinIdInSrc = atoll(row["id"].c_str());
					}
					useMaxIdInSrc = atoll(row["id"].c_str());
				} else {
					useMinIdInSrc = atoll(row["id"].c_str());
					if(!useMaxIdInSrc) {
						useMaxIdInSrc = atoll(row["id"].c_str());
					}
				}
				rows.push_back(row);
				if(rows.size() >= 100) {
					string insertQuery = this->insertQuery(tableName, &rows, false, true, true);
					sqlStore->query(insertQuery.c_str(), 
							insertThreads > 1 ? ((counterInsert++ % insertThreads) + 1) : 1, 0);
					rows.clear();
				}
				while(!is_terminating() && sqlStore->getAllSize() > 1000) {
					USLEEP(100000);
				}
			}
			if(is_terminating() < 2 && rows.size()) {
				string insertQuery = this->insertQuery(tableName, &rows, false, true, true);
				sqlStore->query(insertQuery.c_str(), 
						insertThreads > 1 ? ((counterInsert++ % insertThreads) + 1) : 1, 0);
				rows.clear();
			}
		}
	}
	vector<string> slaveTables;
	string slaveIdToMasterColumn;
	if(string(tableName) == "cdr") {
		slaveTables = this->getSourceTables(tt_child, tt2_cdr);
		slaveIdToMasterColumn = "cdr_id";
	}
	if(string(tableName) == "message") {
		slaveTables = this->getSourceTables(tt_child, tt2_message);
		slaveIdToMasterColumn = "message_id";
	}
	for(size_t i = 0; i < slaveTables.size() && !is_terminating(); i++) {
		if(sqlDbSrc->existsTable(slaveTables[i])) {
			if(!descDir) {
				this->copyFromSourceTableSlave(sqlDbSrc,
							       tableName, slaveTables[i].c_str(),
							       slaveIdToMasterColumn.c_str(), 
							       "calldate", "calldate",
							       minIdSrc, maxIdSrc,
							       minIdSrc_time_limit, maxIdSrc_time_limit,
							       useMinIdInSrc, useMaxIdInSrc,
							       limit * 100, false,
							       cb_src, cb_dst);
			} else {
				this->copyFromSourceTableSlave(sqlDbSrc,
							       tableName, slaveTables[i].c_str(),
							       slaveIdToMasterColumn.c_str(), 
							       "calldate", "calldate",
							       minIdSrc, maxIdSrc,
							       minIdSrc_time_limit, maxIdSrc_time_limit,
							       useMinIdInSrc, useMaxIdInSrc,
							       limit * 100, true,
							       cb_src, cb_dst);
			}
		}
	}
}

void SqlDb_mysql::copyFromSourceTableSlave(SqlDb_mysql *sqlDbSrc,
					   const char *masterTableName, const char *slaveTableName,
					   const char *slaveIdToMasterColumn, 
					   const char *masterCalldateColumn, const char *slaveCalldateColumn,
					   u_int64_t minIdSrc, u_int64_t maxIdSrc,
					   u_int64_t minIdSrc_time_limit, u_int64_t maxIdSrc_time_limit,
					   u_int64_t useMinIdMaster, u_int64_t useMaxIdMaster,
					   unsigned long limit, bool descDir, 
					   cSqlDbCodebooks *cb_src, cSqlDbCodebooks *cb_dst) {
	map<string, cSqlDbCodebook::eTypeCodebook> reftable_map;
	if(cb_src && cb_dst) {
		getReferenceTablesMap(slaveTableName, &reftable_map);
	}
	bool existsCalldateInSlaveTableSrc = false;
	bool existsCalldateInSlaveTableDst = false;
	if(slaveCalldateColumn) {
		if(sqlDbSrc->existsColumn(slaveTableName, slaveCalldateColumn)) {
			existsCalldateInSlaveTableSrc = true;
		}
		if(this->existsColumn(slaveTableName, slaveCalldateColumn)) {
			existsCalldateInSlaveTableDst = true;
		}
	}
	extern char opt_database_backup_from_date[20];
	extern char opt_database_backup_to_date[20];
	u_int64_t minIdToMasterInSlaveSrc = 0;
	if(opt_database_backup_from_date[0] && slaveCalldateColumn && existsCalldateInSlaveTableSrc) {
		sqlDbSrc->query(string("select min(") + slaveIdToMasterColumn + ") as min_id from " + slaveTableName +
				" where " + slaveCalldateColumn + " = " + 
				"(select min(" + slaveCalldateColumn + ") from " + slaveTableName + " where " + slaveCalldateColumn + " > '" + opt_database_backup_from_date + "')");
		minIdToMasterInSlaveSrc = atoll(sqlDbSrc->fetchRow()["min_id"].c_str());
	} else {
		sqlDbSrc->query(string("select min(") + slaveIdToMasterColumn + ") as min_id from " + slaveTableName);
		SqlDb_row row = sqlDbSrc->fetchRow();
		if(row) {
			minIdToMasterInSlaveSrc = atoll(row["min_id"].c_str());
		}
	}
	if(!minIdToMasterInSlaveSrc) {
		return;
	}
	u_int64_t maxIdToMasterInSlaveSrc = 0;
	if(opt_database_backup_to_date[0] && slaveCalldateColumn && existsCalldateInSlaveTableSrc) {
		sqlDbSrc->query(string("select max(") + slaveIdToMasterColumn + ") as max_id from " + slaveTableName +
				" where " + slaveCalldateColumn + " = " +
				"(select max(" + slaveCalldateColumn + ") from " + slaveTableName + " where " + slaveCalldateColumn + " < '" + opt_database_backup_to_date + "')");
		maxIdToMasterInSlaveSrc = atoll(sqlDbSrc->fetchRow()["max_id"].c_str());
	} else {
		sqlDbSrc->query(string("select max(") + slaveIdToMasterColumn + ") as max_id from " + slaveTableName);
		SqlDb_row row = sqlDbSrc->fetchRow();
		if(row) {
			maxIdToMasterInSlaveSrc = atoll(row["max_id"].c_str());
		}
	}
	if(!maxIdToMasterInSlaveSrc) {
		return;
	}
	SqlDb_row row;
	u_int64_t maxIdToMasterInSlaveDst = 0;
	u_int64_t minIdToMasterInSlaveDst = 0;
	u_int64_t startIdToMasterInSlaveSrc = 0;
	if(!descDir) {
		startIdToMasterInSlaveSrc = minIdSrc;
		if(minIdSrc_time_limit && startIdToMasterInSlaveSrc < minIdSrc_time_limit) {
			startIdToMasterInSlaveSrc = minIdSrc_time_limit;
		}
		this->query(string("select max(") + slaveIdToMasterColumn + ") as max_id from " + slaveTableName);
		row = this->fetchRow();
		if(row) {
			maxIdToMasterInSlaveDst = atoll(row["max_id"].c_str());
			if(maxIdToMasterInSlaveDst && startIdToMasterInSlaveSrc < maxIdToMasterInSlaveDst + 1) {
				startIdToMasterInSlaveSrc = maxIdToMasterInSlaveDst + 1;
			}
		}
		if(startIdToMasterInSlaveSrc >= maxIdToMasterInSlaveSrc ||
		   (maxIdSrc_time_limit && startIdToMasterInSlaveSrc >= maxIdSrc_time_limit)) {
			return;
		}
	} else {
		startIdToMasterInSlaveSrc = maxIdSrc;
		if(maxIdSrc_time_limit && startIdToMasterInSlaveSrc > maxIdSrc_time_limit) {
			startIdToMasterInSlaveSrc = maxIdSrc_time_limit;
		}
		this->query(string("select min(") + slaveIdToMasterColumn + ") as min_id from " + slaveTableName);
		row = this->fetchRow();
		if(row) {
			minIdToMasterInSlaveDst = atoll(row["min_id"].c_str());
			if(minIdToMasterInSlaveDst && startIdToMasterInSlaveSrc > minIdToMasterInSlaveDst - 1) {
				startIdToMasterInSlaveSrc = minIdToMasterInSlaveDst - 1;
			}
		}
		if(startIdToMasterInSlaveSrc <= minIdToMasterInSlaveSrc ||
		   (minIdSrc_time_limit && startIdToMasterInSlaveSrc <= minIdSrc_time_limit)) {
			return;
		}
	}
	map<string, int> columnsDest;
	this->query(string("show columns from ") + slaveTableName);
	size_t i = 0;
	while((row = this->fetchRow())) {
		columnsDest[row["Field"]] = ++i;
	}
	vector<string> condSrc;
	if(!descDir) {
		if(startIdToMasterInSlaveSrc) {
			condSrc.push_back(string(slaveIdToMasterColumn) + " >= " + intToString(startIdToMasterInSlaveSrc));
		}
		if(useMaxIdMaster) {
			extern int opt_database_backup_slave_record_safe_gap;
			unsigned gap = useMaxIdMaster > (unsigned)opt_database_backup_slave_record_safe_gap ? opt_database_backup_slave_record_safe_gap : 0;
			condSrc.push_back(string(slaveIdToMasterColumn) + " <= " + intToString(useMaxIdMaster - gap));
		}
	} else {
		if(startIdToMasterInSlaveSrc) {
			condSrc.push_back(string(slaveIdToMasterColumn) + " <= " + intToString(startIdToMasterInSlaveSrc));
		}
		if(useMinIdMaster) {
			condSrc.push_back(string(slaveIdToMasterColumn) + " >= " + intToString(useMinIdMaster));
		}
	}
	if(minIdSrc_time_limit) {
		condSrc.push_back(string(slaveIdToMasterColumn) + " >= " + intToString(minIdSrc_time_limit));
	}
	if(maxIdSrc_time_limit) {
		condSrc.push_back(string(slaveIdToMasterColumn) + " <= " + intToString(maxIdSrc_time_limit));
	}
	string orderSrc = slaveIdToMasterColumn;
	stringstream queryStr;
	queryStr << "select " << slaveTableName << ".*";
	if(existsCalldateInSlaveTableDst && !existsCalldateInSlaveTableSrc) {
		queryStr << "," << masterTableName << "." << masterCalldateColumn << " as " << slaveCalldateColumn;
	}
	queryStr << " from " << slaveTableName;
	if(existsCalldateInSlaveTableDst && !existsCalldateInSlaveTableSrc) {
		queryStr << " join " << masterTableName << " on (" << masterTableName << ".id = " << slaveTableName << "." << slaveIdToMasterColumn << ")";
	}
	if(condSrc.size()) {
		queryStr << " where ";
		for(size_t i = 0; i < condSrc.size(); i++) {
			if(i) {
				queryStr << " and ";
			}
			queryStr << condSrc[i];
		}
	}
	queryStr << " order by " << orderSrc;
	if(descDir) {
		queryStr << " desc";
	}
	queryStr << " limit " << limit;
	syslog(LOG_NOTICE, "%s", ("select query: " + queryStr.str()).c_str());
	if(sqlDbSrc->query(queryStr.str())) {
		extern MySqlStore *sqlStore;
		SqlDb_row row;
		u_int64_t lastMasterId = 0;
		vector<SqlDb_row> rowsMasterId;
		vector<SqlDb_row> rows;
		unsigned long counterInsert = 0;
		extern int opt_database_backup_insert_threads;
		unsigned int insertThreads = opt_database_backup_insert_threads > 1 ? opt_database_backup_insert_threads : 1;
		unsigned long counterRows = 0;
		while(!is_terminating() && (row = sqlDbSrc->fetchRow())) {
			row.removeFieldsIfNotContainIn(&columnsDest);
			if(cb_src && cb_dst) {
				if(!convId(&row, slaveTableName, cb_src, cb_dst, &reftable_map)) {
					syslog(LOG_NOTICE, "%s", "missing record in reference table - continue after next sync reference tables");
					break;
				}
			}
			++counterRows;
			u_int64_t readMasterId = atoll(row[slaveIdToMasterColumn].c_str());
			if(readMasterId != lastMasterId ||
			   (descDir && readMasterId == minIdToMasterInSlaveSrc)) {
				if(lastMasterId) {
					for(size_t i = 0; i < rowsMasterId.size(); i++) {
						rows.push_back(rowsMasterId[i]);
					}
					rowsMasterId.clear();
				}
				lastMasterId = readMasterId;
			}
			rowsMasterId.push_back(row);
			if(rows.size() >= 100) {
				string insertQuery = this->insertQuery(slaveTableName, &rows, false, true, true);
				sqlStore->query(insertQuery.c_str(), 
						insertThreads > 1 ? ((counterInsert++ % insertThreads) + 1) : 1, 0);
				rows.clear();
			}
			while(!is_terminating() && sqlStore->getAllSize() > 1000) {
				USLEEP(100000);
			}
		}
		if(is_terminating() < 2) {
			if(counterRows < limit) {
				for(size_t i = 0; i < rowsMasterId.size(); i++) {
					rows.push_back(rowsMasterId[i]);
				}
			}
			if(rows.size()) {
				string insertQuery = this->insertQuery(slaveTableName, &rows, false, true, true);
				sqlStore->query(insertQuery.c_str(), 
						insertThreads > 1 ? ((counterInsert++ % insertThreads) + 1) : 1, 0);
				rows.clear();
			}
		}
	}
}

vector<string> SqlDb_mysql::getSourceTables(int typeTables, int typeTables2) {
	vector<string> tables;
	if(typeTables & tt_reftabs) {
		tables.push_back("cdr_sip_response");
		if(_save_sip_history) {
			tables.push_back("cdr_sip_request");
		}
		tables.push_back("cdr_reason");
		tables.push_back("cdr_ua");
		tables.push_back("contenttype");
	}
	if(typeTables & (tt_main | tt_child)) {
		if(typeTables2 == tt2_na || typeTables2 & tt2_cdr_static) {
			if(typeTables & tt_main) {
				tables.push_back("cdr");
				tables.push_back("cdr_audio_transcribe");
			}
			if(typeTables & tt_child) {
				tables.push_back("cdr_next");
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_cdr_dynamic) {
			if(typeTables & tt_child) {
				if(custom_headers_cdr) {
					list<string> nextTables = custom_headers_cdr->getAllNextTables();
					for(list<string>::iterator it = nextTables.begin(); it != nextTables.end(); it++) {
						tables.push_back(it->c_str());
					}
				}
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_cdr_static) {
			if(typeTables & tt_child) {
				if(existsColumns.cdr_next_branches) {
					tables.push_back("cdr_next_branches");
				}
				tables.push_back("cdr_rtp");
				if(opt_save_energylevels) {
					tables.push_back("cdr_rtp_energylevels");
				}
				tables.push_back("cdr_dtmf");
				tables.push_back("cdr_sipresp");
				if(_save_sip_history) {
					tables.push_back("cdr_siphistory");
				}
				tables.push_back("cdr_proxy");
				tables.push_back("cdr_tar_part");
				tables.push_back("cdr_country_code");
				tables.push_back("cdr_sdp");
				if(opt_conference_processing) {
					tables.push_back("cdr_conference");
				}
				tables.push_back("cdr_txt");
				tables.push_back("cdr_flags");
			}
		}
		if(opt_enable_http_enum_tables && 
		   (typeTables2 == tt2_na || typeTables2 & tt2_http_enum)) {
			if(typeTables & tt_main) {
				tables.push_back("http_jj");
			}
		}
		if(opt_enable_http_enum_tables && 
		   (typeTables2 == tt2_na || typeTables2 & tt2_http_enum)) {
			if(typeTables & tt_main) {
				tables.push_back("enum_jj");
			}
		}
		if(opt_enable_webrtc_table && 
		   (typeTables2 == tt2_na || typeTables2 & tt2_webrtc)) {
			if(typeTables & tt_main) {
				tables.push_back("webrtc");
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_message_static) {
			if(typeTables & tt_main) {
				tables.push_back("message");
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_message_dynamic) {
			if(typeTables & tt_child) {
				if(custom_headers_message) {
					list<string> nextTables = custom_headers_message->getAllNextTables();
					for(list<string>::iterator it = nextTables.begin(); it != nextTables.end(); it++) {
						tables.push_back(it->c_str());
					}
				}
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_message_static) {
			if(typeTables & tt_child) {
				tables.push_back("message_proxy");
				tables.push_back("message_country_code");
				tables.push_back("message_flags");
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_register) {
			if(typeTables & tt_main) {
				tables.push_back("register_failed");
				tables.push_back("register_state");
				tables.push_back("register_time_info");
			}
		}
		if(opt_sip_register_save_eq_states_time) {
			if(typeTables2 == tt2_na || typeTables2 & tt2_register) {
				if(typeTables & tt_child) {
					if(existsTable("register_failed_eq_next")) {
						tables.push_back("register_failed_eq_next");
					}
					if(existsTable("register_state_eq_next")) {
						tables.push_back("register_state_eq_next");
					}
				}
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_sip_msg_static) {
			if(typeTables & tt_main) {
				tables.push_back("sip_msg");
			}
		}
		if(typeTables2 == tt2_na || typeTables2 & tt2_sip_msg_dynamic) {
			if(typeTables & tt_child) {
				if(custom_headers_sip_msg) {
					list<string> nextTables = custom_headers_sip_msg->getAllNextTables();
					for(list<string>::iterator it = nextTables.begin(); it != nextTables.end(); it++) {
						tables.push_back(it->c_str());
					}
				}
			}
		}
	}
	return(tables);
}

string SqlDb_mysql::getTimeColumn(string table) {
	return((table == "cdr" || table == "cdr_audio_transcribe" || table == "message") ? "calldate" : 
	       (table == "http_jj" || table == "enum_jj") ? "timestamp" : 
	       (table == "register_state" || table == "register_failed") ? "created_at" :
	       (table == "sip_msg") ? "time" :
	       "");
}

bool SqlDb_mysql::getReferenceTablesMap(const char *table, map<string, cSqlDbCodebook::eTypeCodebook> *reftable_map) {
	if(!strcmp(table, "cdr")) {
		(*reftable_map)["lastSIPresponse_id"] = cSqlDbCodebook::_cb_sip_response;
		(*reftable_map)["a_ua_id"] = cSqlDbCodebook::_cb_ua;
		(*reftable_map)["b_ua_id"] = cSqlDbCodebook::_cb_ua;
		(*reftable_map)["reason_sip_text_id"] = cSqlDbCodebook::_cb_reason_sip;
		(*reftable_map)["reason_q850_text_id"] = cSqlDbCodebook::_cb_reason_q850;
	} else if(!strcmp(table, "cdr_next_branches")) {
		(*reftable_map)["lastSIPresponse_id"] = cSqlDbCodebook::_cb_sip_response;
		(*reftable_map)["a_ua_id"] = cSqlDbCodebook::_cb_ua;
		(*reftable_map)["b_ua_id"] = cSqlDbCodebook::_cb_ua;
		(*reftable_map)["reason_sip_text_id"] = cSqlDbCodebook::_cb_reason_sip;
		(*reftable_map)["reason_q850_text_id"] = cSqlDbCodebook::_cb_reason_q850;
	} else if(!strcmp(table, "cdr_sipresp")) {
		(*reftable_map)["SIPresponse_id"] = cSqlDbCodebook::_cb_sip_response;
	} else if(!strcmp(table, "cdr_siphistory")) {
		(*reftable_map)["SIPresponse_id"] = cSqlDbCodebook::_cb_sip_response;
		(*reftable_map)["SIPrequest_id"] = cSqlDbCodebook::_cb_sip_request;
	} else if(!strcmp(table, "message")) {
		(*reftable_map)["lastSIPresponse_id"] = cSqlDbCodebook::_cb_sip_response;
		(*reftable_map)["a_ua_id"] = cSqlDbCodebook::_cb_ua;
		(*reftable_map)["b_ua_id"] = cSqlDbCodebook::_cb_ua;
	} else if(!strcmp(table, "register_state") || !strcmp(table, "register_failed")) {
		(*reftable_map)["ua_id"] = cSqlDbCodebook::_cb_ua;
	} else if(!strcmp(table, "sip_msg")) {
		(*reftable_map)["response_id"] = cSqlDbCodebook::_cb_sip_response;
		(*reftable_map)["ua_src_id"] = cSqlDbCodebook::_cb_ua;
		(*reftable_map)["ua_dst_id"] = cSqlDbCodebook::_cb_ua;
	}
	return(reftable_map->size() > 0);
}

bool SqlDb_mysql::convId(SqlDb_row *row, const char *table,
			 cSqlDbCodebooks *cb_src, cSqlDbCodebooks *cb_dst,
			 map<string, cSqlDbCodebook::eTypeCodebook> *reftable_map) {
	bool rslt = true;
	for(map<string, cSqlDbCodebook::eTypeCodebook>::iterator iter = reftable_map->begin(); iter != reftable_map->end(); iter++) {
		if(!convId(row, table, iter->first.c_str(),
			   iter->second, cb_src, cb_dst)) {
			rslt = false;
		}
	}
	return(rslt);
}

bool SqlDb_mysql::convId(SqlDb_row *row, const char *table, const char *column,
			 cSqlDbCodebook::eTypeCodebook cb_type, cSqlDbCodebooks *cb_src, cSqlDbCodebooks *cb_dst) {
	u_int64_t old_id = atoll((*row)[column].c_str());
	if(!old_id) {
		return(true);
	}
	cSqlDbCodebook *cb_src_tab = cb_src->getCodebook(cb_type);
	cSqlDbCodebook *cb_dst_tab = cb_dst->getCodebook(cb_type);
	u_int64_t new_id = convId(old_id, cb_src_tab, cb_dst_tab);
	if(!new_id) {
		return(false);
	}
	if(new_id != old_id) {
		row->setContent(column, intToString(new_id).c_str());
		/*
		cout << " *** " << table << " " << column << " " << (*row)["id"] << " " 
		     << old_id << "->" << new_id << endl;
		*/
	}
	return(true);
}

unsigned SqlDb_mysql::convId(unsigned id,
			      cSqlDbCodebook *cb_src, cSqlDbCodebook *cb_dst) {
	return(cb_src->convId(id, cb_dst));
}


bool SqlDb_odbc::createSchema(int /*connectId*/) {
	return(true);
}

void SqlDb_odbc::createTable(const char */*tableName*/) {
}

void SqlDb_odbc::checkDbMode() {
}

void SqlDb_odbc::checkSchema(int /*connectId*/, bool /*checkColumnsSilentLog*/) {
}

void SqlDb_odbc::updateSensorState() {
}


void createMysqlPartitionsCdr() {
	partitionsServiceIsInProgress = 1;
	syslog(LOG_NOTICE, "%s", "create cdr partitions - begin");
	for(int connectId = 0; connectId < (use_mysql_2() ? 2 : 1); connectId++) {
		SqlDb *sqlDb = createSqlObject(connectId);
		sqlDb->setIgnoreErrorCode(ER_SAME_NAME_PARTITION);
		sqlDb->setIgnoreErrorCode(ER_RANGE_NOT_INCREASING_ERROR);
		sqlDb->setIgnoreErrorCode(ER_NO_SUCH_TABLE);
		if(isCloud() && connectId == 0) {
			SqlDb_mysql *sqlDbMysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
			if(sqlDbMysql) {
				bool disableLogErrorOld = sqlDb->getDisableLogError();
				unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
				sqlDb->setDisableLogError(true);
				sqlDb->setMaxQueryPass(1);
				sqlDbMysql->createSchema_procedure_partition(0, false);
				sqlDb->setMaxQueryPass(maxQueryPassOld);
				sqlDb->setDisableLogError(disableLogErrorOld);
			}
		}
		for(int next_day = 0; next_day < LIMIT_DAY_PARTITIONS; next_day++) {
			_createMysqlPartitionsCdr(opt_cdr_partition_by_hours ? 'h' : 'd', next_day, connectId, sqlDb);
		}
		if(connectId == 0) {
			if(custom_headers_cdr) {
				custom_headers_cdr->createMysqlPartitions(sqlDb);
			}
			if(custom_headers_message) {
				custom_headers_message->createMysqlPartitions(sqlDb);
			}
			if(custom_headers_sip_msg) {
				custom_headers_sip_msg->createMysqlPartitions(sqlDb);
			}
		}
		delete sqlDb;
	}
	syslog(LOG_NOTICE, "%s", "create cdr partitions - end");
	partitionsServiceIsInProgress = 0;
}

void _createMysqlPartitionsCdr(char type, int next_day, int connectId, SqlDb *sqlDb) {
	SqlDb_mysql *sqlDbMysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
	if(!sqlDbMysql) {
		return;
	}
	vector<string> tablesForCreatePartitions = sqlDbMysql->getSourceTables(SqlDb_mysql::tt_main | SqlDb_mysql::tt_child, SqlDb_mysql::tt2_static);
	unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
	if((next_day <= 0 && type == 'd') ||
	   isCloud() || cloud_db) {
		sqlDb->setMaxQueryPass(1);
	}
	for(size_t i = 0; i < tablesForCreatePartitions.size(); i++) {
		if((connectId == 0 && (!use_mysql_2_http() || tablesForCreatePartitions[i] != "http_jj")) ||
		   (connectId == 1 && use_mysql_2_http() && tablesForCreatePartitions[i] == "http_jj")) {
			_createMysqlPartition(tablesForCreatePartitions[i], type, next_day, opt_cdr_partition_oldver, 
					      connectId == 0 ? mysql_database : mysql_2_database, sqlDb);
		}
	}
	sqlDb->setMaxQueryPass(maxQueryPassOld);
}

void createMysqlPartitionsSs7() {
	partitionsServiceIsInProgress = 1;
	createMysqlPartitionsTable("ss7", opt_ss7_partition_oldver);
	partitionsServiceIsInProgress = 0;
}

void createMysqlPartitionsCdrStat() {
	partitionsServiceIsInProgress = 1;
	if(opt_cdr_stat_values) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
			if(cCdrStat::enableBySrcDst(src_dst)) {
				createMysqlPartitionsTable(("cdr_stat_values" + cCdrStat::tableNameSuffix(src_dst)).c_str(), opt_cdr_stat_values_partition_oldver[src_dst], false, 'm');
			}
		}
	}
	if(opt_cdr_stat_sources) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
			if(cCdrStat::enableBySrcDst(src_dst)) {
				createMysqlPartitionsTable(("cdr_stat_sources" + cCdrStat::tableNameSuffix(src_dst)).c_str(), opt_cdr_stat_sources_partition_oldver[src_dst], false, 'm');
			}
		}
	}
	partitionsServiceIsInProgress = 0;
}

void createMysqlPartitionsCdrProblems() {
	partitionsServiceIsInProgress = 1;
	if(opt_cdr_problems) {
		for(int by_type = 0; by_type < 3; by_type++) {
			if(cCdrProblems::enableByType(by_type)) {
				createMysqlPartitionsTable(("cdr_problems" + cCdrProblems::tableNameSuffix(by_type)).c_str(), opt_cdr_problems_partition_oldver[by_type], false, 'm');
			}
		}
	}
	partitionsServiceIsInProgress = 0;
}

void createMysqlPartitionsRtpStat() {
	partitionsServiceIsInProgress = 1;
	createMysqlPartitionsTable("rtp_stat", opt_rtp_stat_partition_oldver);
	partitionsServiceIsInProgress = 0;
}

void createMysqlPartitionsLogSensor() {
	partitionsServiceIsInProgress = 1;
	createMysqlPartitionsTable("log_sensor", opt_log_sensor_partition_oldver, true);
	partitionsServiceIsInProgress = 0;
}

void createMysqlPartitionsBillingAgregation(SqlDb *sqlDb) {
	cBillingAgregationSettings agregSettingsInst;
	agregSettingsInst.load(sqlDb);
	sBillingAgregationSettings agregSettings = agregSettingsInst.getAgregSettings();
	if(!agregSettings.enable_by_ip &&
	   !agregSettings.enable_by_number &&
	   !agregSettings.enable_by_domain) {
		return;
	}
	partitionsServiceIsInProgress = 1;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	syslog(LOG_NOTICE, "%s", "create billing partitions - begin");
	vector<cBilling::sAgregationTypePart> typeParts = cBilling::getAgregTypeParts(&agregSettings);
	bool tablesExists = true;
	for(unsigned i = 0; i < typeParts.size() && tablesExists; i++) {
		for(unsigned j = 0; j < 3 && tablesExists; j++) {
			string type = typeParts[i].type;
			string type2 = (j == 0 ? "addresses" : 
				       (j == 1 ? "numbers" : 
						 "domains"));
			string table = "billing_agregation_" + type + '_' + type2;
			if(!sqlDb->existsTable(table)) {
				tablesExists = false;
			}
		}
	}
	if(!tablesExists) {
		SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
		if(sqlDb_mysql) {
			sqlDb_mysql->createSchema_tables_billing_agregation();
		}
	}
	unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
	for(int day = 0; day < 3; day++) {
		if(!day ||
		   isCloud() || cloud_db) {
			sqlDb->setMaxQueryPass(1);
		}
		for(unsigned i = 0; i < typeParts.size(); i++) {
			for(unsigned j = 0; j < 3; j++) {
				if(!((j == 0 && agregSettings.enable_by_ip) ||
				     (j == 1 && agregSettings.enable_by_number) ||
				     (j == 2 && agregSettings.enable_by_domain))) {
					continue;
				}
				string type = typeParts[i].type;
				string type_part = typeParts[i].type_part;
				string type2 = (j == 0 ? "addresses" : 
					       (j == 1 ? "numbers" :
							 "domains"));
				string table = "billing_agregation_" + type + '_' + type2;
				if(typeParts[i].week) {
					type_part += ':' + intToString(agregSettings.week_start);
				}
				sqlDb->query(
					string("call ") + (isCloud() ? "" : "`" + string(mysql_database) + "`.") + "create_partition_v3(" + 
					(isCloud() || cloud_db ? "NULL" : "'" + string(mysql_database) + "'") + ", " +
					"'" + table + "', " + 
					"'" + type_part + "', " + 
					intToString(day) + ", " + 
					"true" + ");");
			}
		}
		sqlDb->setMaxQueryPass(maxQueryPassOld);
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	syslog(LOG_NOTICE, "%s", "create billing partitions - end");
	partitionsServiceIsInProgress = 0;
}

void createMysqlPartitionsTable(const char* table, bool partition_oldver, bool disableHourPartitions, char type) {
	syslog(LOG_NOTICE, "%s", (string("create ") + table + " partitions - begin").c_str());
	SqlDb *sqlDb = createSqlObject();
	sqlDb->setIgnoreErrorCode(ER_SAME_NAME_PARTITION);
	sqlDb->setIgnoreErrorCode(ER_RANGE_NOT_INCREASING_ERROR);
	sqlDb->setIgnoreErrorCode(ER_NO_SUCH_TABLE);
	unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
	if(!type) {
		type = opt_cdr_partition_by_hours && !disableHourPartitions ? 'h' : 'd';
	}
	if(type == 'm') {
		for(int next_month = 0; next_month < 2; next_month++) {
			if(!next_month ||
			   isCloud() || cloud_db) {
				sqlDb->setMaxQueryPass(1);
			}
			_createMysqlPartition(table, type, next_month, partition_oldver, NULL, sqlDb);
			sqlDb->setMaxQueryPass(maxQueryPassOld);
		}
	} else {
		for(int next_day = 0; next_day < LIMIT_DAY_PARTITIONS; next_day++) {
			if((!next_day && type == 'd') ||
			   isCloud() || cloud_db) {
				sqlDb->setMaxQueryPass(1);
			}
			_createMysqlPartition(table, type, next_day, partition_oldver, NULL, sqlDb);
			sqlDb->setMaxQueryPass(maxQueryPassOld);
		}
	}
	delete sqlDb;
	syslog(LOG_NOTICE, "%s", (string("create ") + table + " partitions - end").c_str());
}

void createMysqlPartitionsIpacc() {
	partitionsServiceIsInProgress = 1;
	SqlDb *sqlDb = createSqlObject();
	syslog(LOG_NOTICE, "%s", "create ipacc partitions - begin");
	if(isCloud()) {
		sqlDb->setMaxQueryPass(1);
		sqlDb->query(
			"call create_partitions_ipacc(0);");
		sqlDb->query(
			"call create_partitions_ipacc(1);");
	} else {
		sqlDb->query(
			string("call `") + mysql_database + "`.create_partitions_ipacc('" + mysql_database + "', 0);");
		sqlDb->query(
			string("call `") + mysql_database + "`.create_partitions_ipacc('" + mysql_database + "', 1);");
	}
	delete sqlDb;
	syslog(LOG_NOTICE, "%s", "create ipacc partitions - end");
	partitionsServiceIsInProgress = 0;
}

struct sPartitionInfo {
	sPartitionInfo(char type, string name, string limit, int next, int hour_in_day) {
		this->type = type;
		this->name = name;
		this->limit = limit;
		this->next = next;
		this->hour_in_day = hour_in_day;
		this->hour = next * 24 + hour_in_day;
	}
	char type;
	string name;
	string limit;
	int next;
	int hour_in_day;
	int hour;
};

void _createMysqlPartition(string table, char type, int next, bool old_ver, const char *database, SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	SqlDb_mysql *sqlDb_mysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
	switch(type) {
	case 'm': {
		string partMonthName = sqlDb_mysql->getPartMonthName(NULL, next);
		if(sqlDb_mysql->existsPartition(table.c_str(), partMonthName.c_str())) {
			if(_createSqlObject) {
				delete sqlDb;
			}
			return;
		}}
		break;
	case 'd':
	case 'h': {
		string partDayName = sqlDb_mysql->getPartDayName(NULL, next);
		if(sqlDb_mysql->existsPartition(table.c_str(), partDayName.c_str())) {
			if(_createSqlObject) {
				delete sqlDb;
			}
			return;
		}}
		break;
	}
	vector<sPartitionInfo> partitions;
	switch(type) {
	case 'm': {
		string partLimit;
		string partName = sqlDb_mysql->getPartMonthName(&partLimit, next);
		partitions.push_back(sPartitionInfo(type, partName, partLimit, next, 0));
		}
		break;
	case 'd': {
		string partLimit;
		string partName = sqlDb_mysql->getPartDayName(&partLimit, next);
		partitions.push_back(sPartitionInfo(type, partName, partLimit, next, 0));
		}
		break;
	case 'h': {
		for(int h = 0; h < 24; h++) {
			string partLimit;
			string partName = sqlDb_mysql->getPartHourName(&partLimit, next, h);
			if(!partName.empty() &&
			   !sqlDb_mysql->existsPartition(table.c_str(), partName.c_str())) {
				partitions.push_back(sPartitionInfo(type, partName, partLimit, next, h));
			}
		}}
		break;
	}
	if(partitions.size()) {
		extern bool cloud_db;
		extern char mysql_database[256];
		if(!(isCloud() || cloud_db) && 
		   !(database && strcmp(database, mysql_database)) && !old_ver) {
			string partitions_create_str;
			string partitions_list_str;
			for(unsigned i = 0; i < partitions.size(); i++) {
				if(i > 0) {
					partitions_create_str += ", ";
					partitions_list_str += ",";
				}
				partitions_create_str += "partition `" + partitions[i].name + "` VALUES LESS THAN ('" + partitions[i].limit + "')";
				partitions_list_str += partitions[i].name;
			}
			syslog(LOG_NOTICE, "CREATE PARTITION %s : %s", table.c_str(), partitions_list_str.c_str());
			sqlDb->query(string("ALTER TABLE ") + sqlDb->escapeTableName(table) + " ADD PARTITION " + 
				     "(" + partitions_create_str + ")");
		} else {
			for(unsigned i = 0; i < partitions.size(); i++) {
				const char *_database = database ? database : mysql_database;
				sqlDb->query(
					string("call ") + (isCloud() ? "" : "`" + string(_database) + "`.") + "create_partition_v3(" + 
					(isCloud() || cloud_db ? "NULL" : "'" + string(_database) + "'") + ", " +
					"'" + table + "', " +
					"'" + (type == 'm' ? "month" : type == 'd' ? "day" : "hour") + "', " + 
					intToString(type == 'd' ? next : partitions[i].hour) + ", " +
					(old_ver ? "true" : "false") + ");");
			}
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void dropMysqlPartitionsCdr() {
	partitionsServiceIsInProgress = 1;
	extern int opt_cleandatabase_cdr;
	extern int opt_cleandatabase_cdr_rtp_energylevels;
	extern int opt_cleandatabase_http_enum;
	extern int opt_cleandatabase_webrtc;
	extern int opt_cleandatabase_register_state;
	extern int opt_cleandatabase_register_failed;
	extern int opt_cleandatabase_register_time_info;
	extern int opt_cleandatabase_sip_msg;
	syslog(LOG_NOTICE, "drop cdr old partitions - begin");
	SqlDb *sqlDb = createSqlObject();
	sqlDb->setDisableLogError();
	sqlDb->setDisableNextAttemptIfError();
	_dropMysqlPartitions("cdr", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_next", opt_cleandatabase_cdr, 0, sqlDb);
	if(existsColumns.cdr_next_branches) {
		_dropMysqlPartitions("cdr_next_branches", opt_cleandatabase_cdr, 0, sqlDb);
	}
	_dropMysqlPartitions("cdr_rtp", opt_cleandatabase_cdr, 0, sqlDb);
	if(opt_save_energylevels) {
		_dropMysqlPartitions("cdr_rtp_energylevels", opt_cleandatabase_cdr_rtp_energylevels ? opt_cleandatabase_cdr_rtp_energylevels : opt_cleandatabase_cdr, 0, sqlDb);
	}
	_dropMysqlPartitions("cdr_dtmf", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_sipresp", opt_cleandatabase_cdr, 0, sqlDb);
	if(_save_sip_history || sqlDb->existsTable("cdr_siphistory")) {
		_dropMysqlPartitions("cdr_siphistory", opt_cleandatabase_cdr, 0, sqlDb);
	}
	_dropMysqlPartitions("cdr_tar_part", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_country_code", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_sdp", opt_cleandatabase_cdr, 0, sqlDb);
	if(sqlDb->existsTable("cdr_conference")) {
		_dropMysqlPartitions("cdr_conference", opt_cleandatabase_cdr, 0, sqlDb);
	}
	_dropMysqlPartitions("cdr_txt", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_proxy", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_flags", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_audio_transcribe", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("message", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("message_proxy", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("message_country_code", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("message_flags", opt_cleandatabase_cdr, 0, sqlDb);
	if(custom_headers_cdr) {
		list<string> nextTables = custom_headers_cdr->getAllNextTables();
		for(list<string>::iterator iter = nextTables.begin(); iter != nextTables.end(); iter++) {
			_dropMysqlPartitions((*iter).c_str(), opt_cleandatabase_cdr, 0, sqlDb);
		}
	}
	if(custom_headers_message) {
		list<string> nextTables = custom_headers_message->getAllNextTables();
		for(list<string>::iterator iter = nextTables.begin(); iter != nextTables.end(); iter++) {
			_dropMysqlPartitions((*iter).c_str(), opt_cleandatabase_cdr, 0, sqlDb);
		}
	}
	if(opt_enable_http_enum_tables) {
		SqlDb *sqlDbHttp;
		if(use_mysql_2_http()) {
			sqlDbHttp = createSqlObject(1);
		} else {
			sqlDbHttp = sqlDb;
		}
		_dropMysqlPartitions("http_jj", opt_cleandatabase_http_enum, 0, sqlDbHttp);
		/* obsolete
		_dropMysqlPartitions("enum_jj", opt_cleandatabase_http_enum, 0, sqlDbHttp);
		*/
		if(use_mysql_2_http()) {
			delete sqlDbHttp;
		}
	}
	if(opt_enable_webrtc_table) {
		_dropMysqlPartitions("webrtc", opt_cleandatabase_webrtc, 0, sqlDb);
	}
	_dropMysqlPartitions("register_state", opt_cleandatabase_register_state, 0, sqlDb);
	_dropMysqlPartitions("register_failed", opt_cleandatabase_register_failed, 0, sqlDb);
	_dropMysqlPartitions("register_time_info", opt_cleandatabase_register_time_info, 0, sqlDb);
	if(opt_sip_register_save_eq_states_time) {
		if(sqlDb->existsTable("register_state_eq_next")) {
			_dropMysqlPartitions("register_state_eq_next", opt_cleandatabase_register_state, 0, sqlDb);
		}
		if(sqlDb->existsTable("register_failed_eq_next")) {
			_dropMysqlPartitions("register_failed_eq_next", opt_cleandatabase_register_failed, 0, sqlDb);
		}
	}
	_dropMysqlPartitions("sip_msg", opt_cleandatabase_sip_msg, 0, sqlDb);
	if(custom_headers_sip_msg) {
		list<string> nextTables = custom_headers_sip_msg->getAllNextTables();
		for(list<string>::iterator iter = nextTables.begin(); iter != nextTables.end(); iter++) {
			_dropMysqlPartitions((*iter).c_str(), opt_cleandatabase_sip_msg, 0, sqlDb);
		}
	}
	delete sqlDb;
	syslog(LOG_NOTICE, "drop cdr old partitions - end");
	partitionsServiceIsInProgress = 0;
}

void dropMysqlPartitionsSs7() {
	extern int opt_cleandatabase_ss7;
	dropMysqlPartitionsTable("ss7", opt_cleandatabase_ss7, 0);
}

void dropMysqlPartitionsCdrStat() {
	extern int opt_cleandatabase_cdr_stat;
	for(int src_dst = 0; src_dst < 2; src_dst++) {
		dropMysqlPartitionsTable(("cdr_stat_values" + cCdrStat::tableNameSuffix(src_dst)).c_str(), opt_cleandatabase_cdr_stat, 0, 'm');
	}
	for(int src_dst = 0; src_dst < 2; src_dst++) {
		dropMysqlPartitionsTable(("cdr_stat_sources" + cCdrStat::tableNameSuffix(src_dst)).c_str(), opt_cleandatabase_cdr_stat, 0, 'm');
	}
}

void dropMysqlPartitionsCdrProblems() {
	extern int opt_cleandatabase_cdr_problems;
	for(int by_type = 0; by_type < 3; by_type++) {
		dropMysqlPartitionsTable(("cdr_problems" + cCdrProblems::tableNameSuffix(by_type)).c_str(), opt_cleandatabase_cdr_problems, 0, 'm');
	}
}

void dropMysqlPartitionsRtpStat() {
	extern int opt_cleandatabase_rtp_stat;
	dropMysqlPartitionsTable("rtp_stat", opt_cleandatabase_rtp_stat, 0);
}

void dropMysqlPartitionsLogSensor() {
	extern int opt_cleandatabase_log_sensor;
	dropMysqlPartitionsTable("log_sensor", opt_cleandatabase_log_sensor, 0);
}

void dropMysqlPartitionsBillingAgregation() {
	cBillingAgregationSettings agregSettingsInst;
	agregSettingsInst.load();
	sBillingAgregationSettings agregSettings = agregSettingsInst.getAgregSettings();
	if(!agregSettings.enable_by_ip &&
	   !agregSettings.enable_by_number &&
	   !agregSettings.enable_by_domain) {
		return;
	}
	partitionsServiceIsInProgress = 1;
	SqlDb *sqlDb = createSqlObject();
	syslog(LOG_NOTICE, "%s", "drop billing old partitions - begin");
	vector<cBilling::sAgregationTypePart> typeParts = cBilling::getAgregTypeParts(&agregSettings);
		for(unsigned i = 0; i < typeParts.size(); i++) {
			for(unsigned j = 0; j < 3; j++) {
				if(!((j == 0 && agregSettings.enable_by_ip) ||
				     (j == 1 && agregSettings.enable_by_number) ||
				     (j == 2 && agregSettings.enable_by_domain))) {
					continue;
				}
				string type = typeParts[i].type;
				string type2 = (j == 0 ? "addresses" : 
					       (j == 1 ? "numbers" : 
							 "domains"));
				string table = "billing_agregation_" + type + '_' + type2;
				unsigned limit = typeParts[i].limit;
				_dropMysqlPartitions(table.c_str(), 0, limit, sqlDb);
			}
		}
	delete sqlDb;
	syslog(LOG_NOTICE, "%s", "drop billing old partitions - end");
	partitionsServiceIsInProgress = 0;
}

void dropMysqlPartitionsTable(const char *table, int cleanParam, unsigned maximumPartitions, char type) {
	SqlDb *sqlDb = createSqlObject();
	if(sqlDb->existsTable(table)) {
		syslog(LOG_NOTICE, "%s", (string("drop ") + table + " old partitions - begin").c_str());
		sqlDb->setDisableLogError();
		sqlDb->setDisableNextAttemptIfError();
		_dropMysqlPartitions(table, cleanParam, maximumPartitions, sqlDb, type);
		syslog(LOG_NOTICE, "%s", (string("drop ") + table + " old partitions - end").c_str());
	}
	delete sqlDb;
}

void _dropMysqlPartitions(const char *table, int cleanParam, unsigned maximumPartitions, SqlDb *sqlDb, char type) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		sqlDb->setDisableLogError();
		sqlDb->setDisableNextAttemptIfError();
		_createSqlObject = true;
	}
	string limitPartName;
	if(cleanParam > 0) {
		time_t act_time = time(NULL);
		time_t prev_day_time = act_time - cleanParam * 24 * 60 * 60;
		struct tm prevDayTime = time_r(&prev_day_time);
		char limitPartName_buff[20] = "";
		strftime(limitPartName_buff, sizeof(limitPartName_buff), type == 'm' ? "p%y%m" : "p%y%m%d", &prevDayTime);
		limitPartName = limitPartName_buff;
	}
	map<string, int> partitions;
	unsigned maximumDbPartitions = sqlDb->getMaximumPartitions();
	if(maximumDbPartitions) {
		if(maximumDbPartitions > 10) {
			maximumDbPartitions -= 10;
		}
		if(!maximumPartitions || maximumPartitions > maximumDbPartitions) {
			maximumPartitions = maximumDbPartitions;
		}
	}
	vector<SqlDb::sPartition> exists_partitions;
	if(sqlDb->getPartitions(table, &exists_partitions) > 0) {
		std::sort(exists_partitions.begin(), exists_partitions.end());
		if(maximumPartitions ) {
			if(exists_partitions.size() > maximumPartitions) {
				for(size_t i = 0; i < (exists_partitions.size() - maximumPartitions); i++) {
					partitions[exists_partitions[i].name] = 1;
				}
			}
		}
		if(cleanParam > 0) {
			for(size_t i = 0; i < exists_partitions.size() && exists_partitions[i].name.substr(0, limitPartName.length()) <= limitPartName; i++) {
				partitions[exists_partitions[i].name] = 1;
			}
		}
	}
	if(partitions.size()) {
		string partitions_list_str;
		for(map<string, int>::iterator iter = partitions.begin(); iter != partitions.end(); iter++) {
			if(!partitions_list_str.empty()) {
				partitions_list_str += ",";
			}
			partitions_list_str += iter->first;
		}
		syslog(LOG_NOTICE, "DROP PARTITION %s : %s", table, partitions_list_str.c_str());
		if(!sverb.suppress_drop_partitions) {
			sqlDb->query(string("ALTER TABLE ") + sqlDb->escapeTableName(table) + " DROP PARTITION " + partitions_list_str);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

static u_int64_t checkMysqlIdCdrChildTables_getAutoIncrement(string table, SqlDb *sqlDb);
static u_int64_t _checkMysqlIdCdrChildTables_getAutoIncrement(string table, SqlDb *sqlDb);
static u_int64_t _checkMysqlIdCdrChildTables_getAutoIncrement_v2(string table, SqlDb *sqlDb);
static bool checkMysqlIdCdrChildTables_setAutoIncrement(string table, u_int64_t autoIncrement, SqlDb *sqlDb);
static bool _checkMysqlIdCdrChildTables_setAutoIncrement(string table, u_int64_t autoIncrement, SqlDb *sqlDb);
static bool _checkMysqlIdCdrChildTables_setAutoIncrement_v2(string table, u_int64_t autoIncrement, SqlDb *sqlDb);

void checkMysqlIdCdrChildTables() {
	SqlDb *sqlDb = createSqlObject();
	SqlDb_mysql *sqlDbMysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
	if(!sqlDbMysql) {
		return;
	}
	vector<string> cdrTables = sqlDbMysql->getSourceTables(SqlDb_mysql::tt_main | SqlDb_mysql::tt_child, SqlDb_mysql::tt2_cdr);
	for(size_t i = 0; i < cdrTables.size(); i++) {
		if(!sqlDb->existsTable(cdrTables[i])) {
			continue;
		}
		// check id is bigint
		sqlDb->query("show columns from " + cdrTables[i] + " like 'id'");
		SqlDb_row row = sqlDb->fetchRow();
		if(!row) {
			continue;
		}
		string idType = row["type"];
		std::transform(idType.begin(), idType.end(), idType.begin(), ::toupper);
		bool idIsBig = idType.find("BIG") != string::npos;
		if(idIsBig) {
			continue;
		}
		// check max id
		if(!sqlDb->query("select max(id) from " + cdrTables[i]) ||
		   !(row = sqlDb->fetchRow())) {
			syslog(LOG_ERR, "failed get max id for table %s", cdrTables[i].c_str());
			continue;
		}
		u_int64_t maxId = atoll(row[0].c_str());
		if(maxId < 0xFFFFFFFF - 1e6) {
			continue;
		}
		// check auto increment
		u_int64_t autoIncrement = checkMysqlIdCdrChildTables_getAutoIncrement(cdrTables[i], sqlDb);
		if(autoIncrement < 0xFFFFFFFF - 1e6) {
			continue;
		}
		syslog(LOG_ERR, "critical value %" int_64_format_prefix "lu in column id / table %s", maxId, cdrTables[i].c_str());
		// check if main tables
		if(cdrTables[i] == "cdr" || 
		   reg_match(cdrTables[i].c_str(), "cdr_next", __FILE__, __LINE__)) {
			continue;
		}
		// check if exists calldate
		if(!sqlDb->existsColumn(cdrTables[i], "calldate")) {
			continue;
		}
		// check min id
		sqlDb->query("select min(id) from " + cdrTables[i]);
		row = sqlDb->fetchRow();
		u_int64_t minId = atoll(row[0].c_str());
		if(minId > 0xFFFFFFFF / 4) {
			bool rstlSetAutoIncrement = checkMysqlIdCdrChildTables_setAutoIncrement(cdrTables[i], 1, sqlDb);
			syslog(rstlSetAutoIncrement ? LOG_NOTICE : LOG_ERR, 
			       "switch auto_increment value to 1 in table %s: %s", 
			       cdrTables[i].c_str(),
			       rstlSetAutoIncrement ? "SUCCESS" : "FAILED");
		} else {
			continue;
		}
	}
	delete sqlDb;
}

u_int64_t checkMysqlIdCdrChildTables_getAutoIncrement(string table, SqlDb *sqlDb) {
	u_int64_t autoIncrement = _checkMysqlIdCdrChildTables_getAutoIncrement_v2(table, sqlDb);
	if(autoIncrement != (u_int64_t)-1) {
		return(autoIncrement);
	} else {
		return(_checkMysqlIdCdrChildTables_getAutoIncrement(table, sqlDb));
	}
}

u_int64_t _checkMysqlIdCdrChildTables_getAutoIncrement(string table, SqlDb *sqlDb) {
	SqlDb_row row;
	if(!sqlDb->query("show table status like '" + table + "'") ||
	   !(row = sqlDb->fetchRow())) {
		return((u_int64_t)-1);
	}
	return(atoll(row["auto_increment"].c_str()));
}

u_int64_t _checkMysqlIdCdrChildTables_getAutoIncrement_v2(string table, SqlDb *sqlDb) {
	if(!sqlDb->existsTable(table + "_auto_increment")) {
		return((u_int64_t)-1);
	}
	SqlDb_row row;
	if(!sqlDb->select(table + "_auto_increment", "auto_increment") ||
	   !(row = sqlDb->fetchRow())) {
		return((u_int64_t)-1);
	}
	return(atoll(row["auto_increment"].c_str()));
}

bool checkMysqlIdCdrChildTables_setAutoIncrement(string table, u_int64_t autoIncrement, SqlDb *sqlDb) {
	if(_checkMysqlIdCdrChildTables_setAutoIncrement(table, autoIncrement, sqlDb) &&
	   _checkMysqlIdCdrChildTables_getAutoIncrement(table, sqlDb) < autoIncrement + 1000) {
		return(true);
	} else {
		return(_checkMysqlIdCdrChildTables_setAutoIncrement_v2(table, autoIncrement, sqlDb));
	}
}

bool _checkMysqlIdCdrChildTables_setAutoIncrement(string table, u_int64_t autoIncrement, SqlDb *sqlDb) {
	return(sqlDb->query("alter table " + sqlDb->escapeTableName(table) + " auto_increment = " + intToString(autoIncrement)));
}

bool _checkMysqlIdCdrChildTables_setAutoIncrement_v2(string table, u_int64_t autoIncrement, SqlDb *sqlDb) {
	string lockName = table + "_auto_increment_lock";
	if(!sqlDb->existsTable(table + "_auto_increment")) {
		return(sqlDb->query("CREATE TABLE `" + table + "_auto_increment` (`auto_increment` BIGINT UNSIGNED NULL) ENGINE=InnoDB") &&
		       sqlDb->query("INSERT INTO `" + table + "_auto_increment` (`auto_increment`) VALUES (" + intToString(autoIncrement) + ");") &&
		       sqlDb->query("DROP TRIGGER IF EXISTS " + table + "_auto_increment_tr") &&
		       sqlDb->query("CREATE TRIGGER " + table + "_auto_increment_tr \
				     BEFORE INSERT ON " + table + " \
				     FOR EACH ROW \
					BEGIN \
					   declare auto_increment_value bigint; \
					   do get_lock('" + table + "_auto_increment', 60); \
					   set auto_increment_value = (select auto_increment from " + table + "_auto_increment); \
					   if not auto_increment_value then \
					      set auto_increment_value = 1; \
					   end if; \
					   update " + table + "_auto_increment set auto_increment = (auto_increment_value + 1); \
					   do release_lock('" + table + "_auto_increment'); \
					   set new.id = auto_increment_value; \
					END"));
	} else {
		return(sqlDb->query("UPDATE `" + table + "_auto_increment` set `auto_increment` = " + intToString(autoIncrement)));
	}
}


cLogSensor::cLogSensor() {
}

void cLogSensor::log(eType type, const char *subject, const char *formatMessage, ...) {
	cLogSensor *log = new FILE_LINE(0) cLogSensor;
	string message;
	if(formatMessage && *formatMessage) {
		unsigned message_buffer_length = 1024*1024;
		char *message_buffer = new FILE_LINE(0) char[message_buffer_length];
		va_list args;
		va_start(args, formatMessage);
		vsnprintf(message_buffer, message_buffer_length, formatMessage, args);
		va_end(args);
		message = message_buffer;
		delete [] message_buffer;
	}
	bool enableSaveToDb = false;
	__SYNC_LOCK(previous_logs_sync);
	string combSubjectMessage = string(subject) + " / " + message;
	map<string, u_int32_t>::iterator previous_logs_iter = previous_logs.find(combSubjectMessage);
	if(previous_logs_iter == previous_logs.end() ||
	   previous_logs_iter->second + 2 * 60 < getTimeS()) {
		enableSaveToDb = true;
		previous_logs[combSubjectMessage] = getTimeS();
	}
	__SYNC_UNLOCK(previous_logs_sync);
	log->_log(type, subject, message.c_str(), enableSaveToDb);
	log->_end();
	delete log;
}

cLogSensor *cLogSensor::begin(eType type, const char *subject, const char *formatMessage, ...) {
	cLogSensor *log = new FILE_LINE(0) cLogSensor;
	string message;
	if(formatMessage && *formatMessage) {
		unsigned message_buffer_length = 1024*1024;
		char *message_buffer = new FILE_LINE(0) char[message_buffer_length];
		va_list args;
		va_start(args, formatMessage);
		vsnprintf(message_buffer, message_buffer_length, formatMessage, args);
		va_end(args);
		message = message_buffer;
		delete [] message_buffer;
	}
	log->_log(type, subject, message.c_str());
	return(log);
}

void cLogSensor::log(cLogSensor *log, const char *subject, const char *formatMessage, ...) {
	string message;
	if(formatMessage && *formatMessage) {
		unsigned message_buffer_length = 1024*1024;
		char *message_buffer = new FILE_LINE(0) char[message_buffer_length];
		va_list args;
		va_start(args, formatMessage);
		vsnprintf(message_buffer, message_buffer_length, formatMessage, args);
		va_end(args);
		message = message_buffer;
		delete [] message_buffer;
	}
	log->_log(subject, message.c_str());
}

void cLogSensor::log(const char *subject, const char *formatMessage, ...) {
	string message;
	if(formatMessage && *formatMessage) {
		unsigned message_buffer_length = 1024*1024;
		char *message_buffer = new FILE_LINE(0) char[message_buffer_length];
		va_list args;
		va_start(args, formatMessage);
		vsnprintf(message_buffer, message_buffer_length, formatMessage, args);
		va_end(args);
		message = message_buffer;
		delete [] message_buffer;
	}
	this->_log(subject, message.c_str());
}

void cLogSensor::end(cLogSensor *log) {
	log->_end();
	delete log;
}

void cLogSensor::end(list<cLogSensor*> logs) {
	for(list<cLogSensor*>::iterator iter = logs.begin(); iter != logs.end(); iter++) {
		cLogSensor::end(*iter);
	}
}

void cLogSensor::_log(eType type, const char *subject, const char *message, bool enableSaveToDb) {
	sItem item;
	item.type = type;
	if(subject) {
		item.subject = subject;
	}
	if(message) {
		item.message = message;
	}
	item.enableSaveToDb = enableSaveToDb;
	items.push_back(item);
}

void cLogSensor::_log(const char *subject, const char *message) {
	_log(_na, subject, message);
}

void cLogSensor::_end() {
	_save();
}

void cLogSensor::_save() {
	if(!items.size()) {
		return;
	}
	extern MySqlStore *sqlStore;
	SqlDb *sqlDb = createSqlObject();
	sqlDb->setMaxQueryPass(1);
	sqlDb->setDisableLogError(true);
	sqlDb->setEnableSqlStringInContent(true);
	bool existsOkLogSensorTable = false;
	if(!sqlStore && !isCloud() && !opt_nocdr && sqlDb->connect()) {
		existsOkLogSensorTable = sqlDb->existsTable("log_sensor");
	}
	string query_str;
	sItem *firstItem = &(*items.begin());
	unsigned counter = 0;
	unsigned ID_parent = 0;
	for(list<sItem>::iterator iter = items.begin(); iter != items.end(); ++iter) {
		if(!opt_nocdr && iter->enableSaveToDb) {
			SqlDb_row logRow;
			logRow.add(sqlEscapeString(sqlDateTimeString(firstItem->time).c_str()), "time");
			if(firstItem->id_sensor > 0) {
				logRow.add(firstItem->id_sensor, "id_sensor");
			}
			logRow.add(firstItem->type, "type");
			logRow.add(sqlEscapeString(iter->subject), "subject");
			logRow.add(sqlEscapeString(iter->message), "message");
			if(sqlStore) {
				if(counter > 0) {
					logRow.add(MYSQL_VAR_PREFIX + "@group_id", "ID_parent");
				}
				query_str += MYSQL_ADD_QUERY_END(sqlDb->insertQuery("log_sensor", logRow));
				if(counter == 0 && items.size() > 1) {
					query_str += MYSQL_ADD_QUERY_END(string("set @group_id = last_insert_id()"));
				}
			} else if(existsOkLogSensorTable) {
				if(counter > 0) {
					logRow.add(ID_parent, "ID_parent");
				}
				sqlDb->insert("log_sensor", logRow);
				if(counter == 0 && items.size() > 1) {
					ID_parent = sqlDb->getInsertId();
				}
			}
		}
		syslog(firstItem->type == debug ? LOG_DEBUG :
		       firstItem->type == info ? LOG_INFO :
		       firstItem->type == notice ? LOG_NOTICE :
		       firstItem->type == warning ? LOG_WARNING :
		       firstItem->type == error ? LOG_ERR :
		       firstItem->type == critical ? LOG_CRIT :
		       firstItem->type == alert ? LOG_ALERT :
		       firstItem->type == emergency ? LOG_EMERG : LOG_INFO,
		       "%s%s%s",
		       iter->subject.c_str(),
		       !iter->subject.empty() && !iter->message.empty() ? " - " : "",
		       iter->message.c_str());
		++counter;
	}
	if(sqlStore && !query_str.empty()) {
		sqlStore->query_lock(query_str, STORE_PROC_ID_LOG_SENSOR, 0);
	}
	delete sqlDb;
}

map<string, u_int32_t> cLogSensor::previous_logs;
volatile int cLogSensor::previous_logs_sync = 0;


string MYSQL_CODEBOOK_ID(int type, string value) {
	string nameValue = dbData->getCbNameForType((cSqlDbCodebook::eTypeCodebook)type) + ";" + value;
	return(MYSQL_CODEBOOK_ID_PREFIX + intToString(nameValue.length()) + ":" + nameValue);
}

string MYSQL_ADD_QUERY_END(string query, bool enableSubstQueryEnd) {
	unsigned query_length = query.length();
	while(query_length && 
	      (query[query_length - 1] == '\n' ||
	       query[query_length - 1] == ';' ||
	       query[query_length - 1] == ' ')) {
		--query_length;
	}
	if(query_length < query.length()) {
		query.resize(query_length);
	}
	if(enableSubstQueryEnd && (useNewStore() || opt_load_query_main_from_files || is_server())) {
		find_and_replace(query, _MYSQL_QUERY_END_new, _MYSQL_QUERY_END_SUBST_new);
	}
	query += MYSQL_QUERY_END;
	return(query);
}


sCreatePartitions::sCreatePartitions() {
	init();
}

void sCreatePartitions::init() {
	createCdr = false;
	dropCdr = false;
	createSs7 = false;
	dropSs7 = false;
	createCdrStat = false;
	dropCdrStat = false;
	createCdrProblems = false;
	dropCdrProblems = false;
	createRtpStat = false;
	dropRtpStat = false;
	createLogSensor = false;
	dropLogSensor = false;
	createIpacc = false;
	createBilling = false;
	dropBilling = false;
	dropBySize = false;
	_runInThread = false;
}

bool sCreatePartitions::isSet() {
	return(createCdr || dropCdr || 
	       createSs7 || dropSs7 ||
	       createCdrStat || dropCdrStat ||
	       createCdrProblems || dropCdrProblems ||
	       createRtpStat || dropRtpStat ||
	       createLogSensor || dropLogSensor ||
	       createIpacc || 
	       createBilling || dropBilling ||
	       dropBySize);
}

void sCreatePartitions::createPartitions(bool inThread) {
	if(isSet()) {
		sCreatePartitions::in_progress = 1;
		bool successStartThread = false;
		if(inThread) {
			sCreatePartitions *createPartitionsData = new FILE_LINE(42004) sCreatePartitions;
			*createPartitionsData = *this;
			createPartitionsData->_runInThread = true;
			pthread_t thread;
			successStartThread = vm_pthread_create_autodestroy("create partitions",
									   &thread, NULL, _createPartitions, createPartitionsData, __FILE__, __LINE__) == 0;
		}
		if(!inThread || !successStartThread) {
			this->_runInThread = false;
			_createPartitions(this);
		}
	}
}

void *sCreatePartitions::_createPartitions(void *arg) {
	sCreatePartitions *createPartitionsData = (sCreatePartitions*)arg;
	if(!is_read_from_file_simple()) {
		createPartitionsData->setIndicPartitionOperations();
		sleep(10);
	}
	extern bool opt_partition_operations_drop_first;
	if(opt_partition_operations_drop_first) {
		createPartitionsData->doDropPartitions();
	}
	createPartitionsData->doCreatePartitions();
	if(!opt_partition_operations_drop_first) {
		createPartitionsData->doDropPartitions();
	}
	if(createPartitionsData->_runInThread) {
		delete createPartitionsData;
	}
	extern volatile int partitionsServiceIsInProgress;
	partitionsServiceIsInProgress = 0;
	sCreatePartitions::in_progress = 0;
	if(!is_read_from_file_simple()) {
		createPartitionsData->unsetIndicPartitionOperations();
	}
	return(NULL);
}

void sCreatePartitions::doCreatePartitions() {
	if(this->createCdr) {
		createMysqlPartitionsCdr();
	}
	if(this->createSs7) {
		createMysqlPartitionsSs7();
	}
	if(this->createCdrStat) {
		createMysqlPartitionsCdrStat();
	}
	if(this->createCdrProblems) {
		createMysqlPartitionsCdrProblems();
	}
	if(this->createRtpStat) {
		createMysqlPartitionsRtpStat();
	}
	if(this->createLogSensor) {
		createMysqlPartitionsLogSensor();
	}
	if(this->createIpacc) {
		createMysqlPartitionsIpacc();
	}
	if(this->createBilling) {
		createMysqlPartitionsBillingAgregation();
	}
}

void sCreatePartitions::doDropPartitions() {
	if(this->dropCdr) {
		dropMysqlPartitionsCdr();
	}
	if(this->dropSs7) {
		dropMysqlPartitionsSs7();
	}
	if(this->dropCdrStat) {
		dropMysqlPartitionsCdrStat();
	}
	if(this->dropCdrProblems) {
		dropMysqlPartitionsCdrProblems();
	}
	if(this->dropRtpStat) {
		dropMysqlPartitionsRtpStat();
	}
	if(this->dropLogSensor) {
		dropMysqlPartitionsLogSensor();
	}
	if(this->dropBilling) {
		dropMysqlPartitionsBillingAgregation();
	}
	if(this->dropBySize) {
		cPartitions p;
		p.cleanup_by_size();
	}
}

void sCreatePartitions::setIndicPartitionOperations(bool set) {
	SqlDb *sqlDb = createSqlObject();
	if(sqlDb->existsTable("system") && sqlDb->existsColumn("system", "cdatetime")) {
		sqlDb->select("system", "cdatetime", "type", "partitions_operations");
		SqlDb_row row = sqlDb->fetchRow();
		if(row) {
			SqlDb_row rowU;
			rowU.add(set ? sqlDateTimeString(time(NULL)) : "", "cdatetime", !set);
			sqlDb->update("system", rowU, "type='partitions_operations'");
		} else if(set) {
			SqlDb_row rowI;
			rowI.add(sqlDateTimeString(time(NULL)), "cdatetime");
			rowI.add(sqlEscapeString("partitions_operations"), "type");
			sqlDb->insert("system", rowI);
		}
	}
	delete sqlDb;
}

void sCreatePartitions::unsetIndicPartitionOperations() {
	setIndicPartitionOperations(false);
}

sCheckIdCdrChildTables::sCheckIdCdrChildTables() {
	init();
}

void sCheckIdCdrChildTables::init() {
	check = false;
}

bool sCheckIdCdrChildTables::isSet() {
	return(check);
}

void sCheckIdCdrChildTables::checkIdCdrChildTables(bool inThread) {
	if(isSet()) {
		if(inThread) {
			pthread_t thread;
			vm_pthread_create_autodestroy("check child cdr id",
						      &thread, NULL, _checkIdCdrChildTables, this, __FILE__, __LINE__);
		} else {
			_checkIdCdrChildTables(this);
		}
	}
}
	
void *sCheckIdCdrChildTables::_checkIdCdrChildTables(void *arg) {
	sCheckIdCdrChildTables::in_progress = 1;
	sCheckIdCdrChildTables *checkIdCdrChildTables = (sCheckIdCdrChildTables*)arg;
	if(checkIdCdrChildTables->check) {
		checkMysqlIdCdrChildTables();
	}
	sCheckIdCdrChildTables::in_progress = 0;
	return(NULL);
}

volatile int sCheckIdCdrChildTables::in_progress = 0;


cCreatePartitions::cCreatePartitions() {
	createPartitionCdrAt = 0;
	dropPartitionCdrAt = 0;
	createPartitionSs7At = 0;
	dropPartitionSs7At = 0;
	createPartitionCdrStatAt = 0;
	dropPartitionCdrStatAt = 0;
	createPartitionCdrProblemsAt = 0;
	dropPartitionCdrProblemsAt = 0;
	createPartitionRtpStatAt = 0;
	dropPartitionRtpStatAt = 0;
	createPartitionLogSensorAt = 0;
	dropPartitionLogSensorAt = 0;
	createPartitionIpaccAt = 0;
	createPartitionBillingAgregationAt = 0;
	dropPartitionBillingAgregationAt = 0;
	dropPartitionBySizeAt = 0;
	checkMysqlIdCdrChildTablesAt = 0;
	_sync_run = 0;
}


void cCreatePartitions::run(bool firstIter) {
	if(_sync_run) {
		return;
	}
	lock_run();
	extern int opt_partition_operations_enable_run_hour_from;
	extern int opt_partition_operations_enable_run_hour_to;
	this->firstIter = firstIter;
	setEnableFromTo = false;
	timeOk = false;
	if(opt_partition_operations_enable_run_hour_from >= 0 &&
	   opt_partition_operations_enable_run_hour_to >= 0) {
		setEnableFromTo = true;
		time_t now;
		time(&now);
		struct tm dateTime = time_r(&now);
		if(opt_partition_operations_enable_run_hour_to >= opt_partition_operations_enable_run_hour_from) {
			if(dateTime.tm_hour >= opt_partition_operations_enable_run_hour_from &&
			   dateTime.tm_hour <= opt_partition_operations_enable_run_hour_to) {
				timeOk = true;
			}
		} else {
			if((dateTime.tm_hour >= opt_partition_operations_enable_run_hour_from && dateTime.tm_hour < 24) ||
			   dateTime.tm_hour <= opt_partition_operations_enable_run_hour_to) {
				timeOk = true;
			}
		}
	}
	actTime = time(NULL);
	create_partitions.init();
	if(opt_cdr_partition) {
		if(check_time_partition_operation(createPartitionCdrAt)) {
			create_partitions.createCdr = true;
			createPartitionCdrAt = actTime;
		}
		if(check_time_partition_operation(dropPartitionCdrAt)) {
			create_partitions.dropCdr = true;
			dropPartitionCdrAt = actTime;
		}
	}
	if(opt_enable_ss7) {
		if(check_time_partition_operation(createPartitionSs7At)) {
			create_partitions.createSs7 = true;
			createPartitionSs7At = actTime;
		}
		if(check_time_partition_operation(dropPartitionSs7At)) {
			create_partitions.dropSs7 = true;
			dropPartitionSs7At = actTime;
		}
	}
	if(true /* cdr_stat */) {
		if(check_time_partition_operation(createPartitionCdrStatAt)) {
			create_partitions.createCdrStat = true;
			createPartitionCdrStatAt = actTime;
		}
		if(check_time_partition_operation(dropPartitionCdrStatAt)) {
			create_partitions.dropCdrStat = true;
			dropPartitionCdrStatAt = actTime;
		}
	}
	if(true /* cdr_problems */) {
		if(check_time_partition_operation(createPartitionCdrProblemsAt)) {
			create_partitions.createCdrProblems = true;
			createPartitionCdrProblemsAt = actTime;
		}
		if(check_time_partition_operation(dropPartitionCdrProblemsAt)) {
			create_partitions.dropCdrProblems = true;
			dropPartitionCdrProblemsAt = actTime;
		}
	}
	if(true /* rtp_stat */) {
		if(check_time_partition_operation(createPartitionRtpStatAt)) {
			create_partitions.createRtpStat = true;
			createPartitionRtpStatAt = actTime;
		}
		if(check_time_partition_operation(dropPartitionRtpStatAt)) {
			create_partitions.dropRtpStat = true;
			dropPartitionRtpStatAt = actTime;
		}
	}
	if(true /* log_sensor */) {
		if(check_time_partition_operation(createPartitionLogSensorAt)) {
			create_partitions.createLogSensor = true;
			createPartitionLogSensorAt = actTime;
		}
		if(check_time_partition_operation(dropPartitionLogSensorAt)) {
			create_partitions.dropLogSensor = true;
			dropPartitionLogSensorAt = actTime;
		}
	}
	if(opt_ipaccount) {
		if(check_time_partition_operation(createPartitionIpaccAt)) {
			create_partitions.createIpacc = true;
			createPartitionIpaccAt = actTime;
		}
	}
	if(true /* billing agregation */) {
		if(check_time_partition_operation(createPartitionBillingAgregationAt)) {
			create_partitions.createBilling = true;
			createPartitionBillingAgregationAt = actTime;
		}
		if(check_time_partition_operation(dropPartitionBillingAgregationAt)) {
			create_partitions.dropBilling = true;
			dropPartitionBillingAgregationAt = actTime;
		}
	}
	if(opt_cdr_partition && is_set_cleandatabase_by_size()) {
		if(check_time_partition_by_size_operation(dropPartitionBySizeAt)) {
			create_partitions.dropBySize = true;
			dropPartitionBySizeAt = actTime;
		}
	}
	if(create_partitions.isSet()) {
		extern bool opt_partition_operations_in_thread;
		create_partitions.createPartitions(!firstIter && opt_partition_operations_in_thread);
	}
	if(opt_cdr_partition && !sCheckIdCdrChildTables::in_progress) {
		actTime = time(NULL);
		check_id_cdr_child_tables.init();
		if(actTime - checkMysqlIdCdrChildTablesAt > 1 * 3600) {
			check_id_cdr_child_tables.check = true;
			checkMysqlIdCdrChildTablesAt = actTime;
		}
		if(check_id_cdr_child_tables.isSet()) {
			extern bool opt_partition_operations_in_thread;
			check_id_cdr_child_tables.checkIdCdrChildTables(!firstIter && opt_partition_operations_in_thread);
		}
	}
	unlock_run();
}

bool cCreatePartitions::check_time_partition_operation(time_t at) {
	return(firstIter ||
	       ((!setEnableFromTo || timeOk) && ((actTime - at) > (setEnableFromTo ? 1 : 12) * 3600)) ||
	       (actTime - at) > 24 * 3600);
}

bool cCreatePartitions::check_time_partition_by_size_operation(time_t at) {
	extern int opt_cleandatabase_size_period;
	return(firstIter ||
	       (actTime - at) > opt_cleandatabase_size_period);
}

void cCreatePartitions::lock_run() {
	__SYNC_LOCK_USLEEP(_sync_run, 100);
}

void cCreatePartitions::unlock_run() {
	__SYNC_UNLOCK(_sync_run);
}


void cPartitions::fill(SqlDb *sqlDb, const char *datadir, const char *database) {
	extern string mysql_datadir;
	if(!(datadir && *datadir) && !mysql_datadir.empty()) {
		datadir = mysql_datadir.c_str();
	}
	fillTables(sqlDb);
	fillPartitions(sqlDb, datadir, database);
}

void cPartitions::fillTables(SqlDb *sqlDb) {
	tables.clear();
	extern int opt_cleandatabase_cdr;
	extern int opt_cleandatabase_cdr_rtp_energylevels;
	// CDR
	addTable("cdr", "cdr");
	addTable("cdr", "cdr_next");
	if(existsColumns.cdr_next_branches) {
		addTable("cdr", "cdr_next_branches");
	}
	addTable("cdr", "cdr_rtp");
	if(opt_save_energylevels && (!opt_cleandatabase_cdr_rtp_energylevels || opt_cleandatabase_cdr_rtp_energylevels == opt_cleandatabase_cdr)) {
		addTable("cdr", "cdr_rtp_energylevels");
	}
	addTable("cdr", "cdr_dtmf");
	addTable("cdr", "cdr_sipresp");
	if(_save_sip_history || sqlDb->existsTable("cdr_siphistory")) {
		addTable("cdr", "cdr_siphistory");
	}
	addTable("cdr", "cdr_tar_part");
	addTable("cdr", "cdr_country_code");
	addTable("cdr", "cdr_sdp");
	if(sqlDb->existsTable("cdr_conference")) {
		addTable("cdr", "cdr_conference");
	}
	addTable("cdr", "cdr_txt");
	addTable("cdr", "cdr_proxy");
	addTable("cdr", "cdr_flags");
	addTable("cdr", "cdr_audio_transcribe");
	addTable("cdr", "message");
	addTable("cdr", "message_proxy");
	addTable("cdr", "message_country_code");
	addTable("cdr", "message_flags");
	if(custom_headers_cdr) {
		list<string> nextTables = custom_headers_cdr->getAllNextTables();
		for(list<string>::iterator iter = nextTables.begin(); iter != nextTables.end(); iter++) {
			addTable("cdr", (*iter).c_str());
		}
	}
	if(custom_headers_message) {
		list<string> nextTables = custom_headers_message->getAllNextTables();
		for(list<string>::iterator iter = nextTables.begin(); iter != nextTables.end(); iter++) {
			addTable("cdr", (*iter).c_str());
		}
	}
	//CDR_ENERGYLEVELS
	if(opt_save_energylevels && opt_cleandatabase_cdr_rtp_energylevels && opt_cleandatabase_cdr_rtp_energylevels != opt_cleandatabase_cdr) {
		addTable("cdr_energylevels", "cdr_rtp_energylevels");
	}
	// HTTP
	if(opt_enable_http_enum_tables) {
		addTable("http_enum", "http_jj");
		/* obsolete
		addTable("http_enum", "enum_jj");
		*/
	}
	// WEBRTC
	if(opt_enable_webrtc_table) {
		addTable("webrtc", "webrtc");
	}
	// REGISTER_STATE
	addTable("register_state", "register_state");
	if(opt_sip_register_save_eq_states_time && sqlDb->existsTable("register_state_eq_next")) {
		addTable("register_state", "register_state_eq_next");
	}
	// REGISTER_FAILED
	addTable("register_failed", "register_failed");
	if(opt_sip_register_save_eq_states_time && sqlDb->existsTable("register_failed_eq_next")) {
		addTable("register_failed", "register_failed_eq_next");
	}
	// REGISTER_TIME_INFO
	addTable("register_time_info", "register_time_info");
	// SIP_MSG
	addTable("sip_msg", "sip_msg");
	if(custom_headers_sip_msg) {
		list<string> nextTables = custom_headers_sip_msg->getAllNextTables();
		for(list<string>::iterator iter = nextTables.begin(); iter != nextTables.end(); iter++) {
			addTable("sip_msg", (*iter).c_str());
		}
	}
	// SS7
	addTable("ss7", "ss7");
	// CDR_STAT
	if(opt_cdr_stat_values) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
			if(cCdrStat::enableBySrcDst(src_dst)) {
				addTable("cdr_stat", ("cdr_stat_values" + cCdrStat::tableNameSuffix(src_dst)).c_str());
			}
		}
	}
	if(opt_cdr_stat_sources) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
			if(cCdrStat::enableBySrcDst(src_dst)) {
				addTable("cdr_stat", ("cdr_stat_sources" + cCdrStat::tableNameSuffix(src_dst)).c_str());
			}
		}
	}
	// CDR_PROBLEMS
	if(opt_cdr_problems) {
		for(int by_type = 0; by_type < 3; by_type++) {
			if(cCdrProblems::enableByType(by_type)) {
				addTable("cdr_problems", ("cdr_problems" + cCdrProblems::tableNameSuffix(by_type)).c_str());
			}
		}
	}
	// RTP_STAT
	addTable("rtp_stat", "rtp_stat");
	// LOG_SENSOR
	addTable("log_sensor", "log_sensor");
}

void cPartitions::fillPartitions(SqlDb *sqlDb, const char *datadir, const char *database) {
	partitions.clear();
	for(list<sTable>::iterator iter_tables = tables.begin(); iter_tables != tables.end(); iter_tables++) {
		list<SqlDb::sPartition> table_part;
		if(sqlDb->existsTable(iter_tables->table)) {
			sqlDb->getPartitions(datadir, database, iter_tables->table.c_str(), &table_part);
			for(list<SqlDb::sPartition>::iterator iter_part = table_part.begin(); iter_part != table_part.end(); iter_part++) {
				partitions[iter_tables->table].push_back(*iter_part);
			}
		}
	}
}

void cPartitions::sumByGroup(map<string, map<string, u_int64_t> > *sum, bool only_prev) {
	for(list<sTable>::iterator iter_tables = tables.begin(); iter_tables != tables.end(); iter_tables++) {
		map<string, list<SqlDb::sPartition> >::iterator iter_part = partitions.find(iter_tables->table);
		if(iter_part != partitions.end()) {
			for(list<SqlDb::sPartition>::iterator iter_part2 = partitions[iter_tables->table].begin(); iter_part2 != partitions[iter_tables->table].end(); iter_part2++) {
				if((only_prev && !iter_part2->is_prev) ||
				   iter_part2->file_size < 0) {
					continue;
				}
				(*sum)[iter_tables->group][iter_part2->time] += iter_part2->file_size;
			}
		}
	}
}

void cPartitions::sumByGroup(map<string, u_int64_t> *sum, bool only_prev) {
	map<string, map<string, u_int64_t> > _sum;
	sumByGroup(&_sum, only_prev);
	for(map<string, map<string, u_int64_t> >::iterator iter_sum = _sum.begin(); iter_sum != _sum.end(); iter_sum++) {
		for(map<string, u_int64_t>::iterator iter_sum2 = iter_sum->second.begin(); iter_sum2 != iter_sum->second.end(); iter_sum2++) {
			(*sum)[iter_sum->first] += iter_sum2->second;
		}
	}
}

u_int64_t cPartitions::sum(bool only_prev) {
	u_int64_t sum = 0;
	map<string, map<string, u_int64_t> > _sum;
	sumByGroup(&_sum, only_prev);
	for(map<string, map<string, u_int64_t> >::iterator iter_sum = _sum.begin(); iter_sum != _sum.end(); iter_sum++) {
		for(map<string, u_int64_t>::iterator iter_sum2 = iter_sum->second.begin(); iter_sum2 != iter_sum->second.end(); iter_sum2++) {
			sum += iter_sum2->second;
		}
	}
	return(sum);
}

void cPartitions::countByGroup(map<string, unsigned> *count, bool only_prev) {
	map<string, map<string, u_int64_t> > _sum;
	sumByGroup(&_sum, only_prev);
	for(map<string, map<string, u_int64_t> >::iterator iter_sum = _sum.begin(); iter_sum != _sum.end(); iter_sum++) {
		(*count)[iter_sum->first] += iter_sum->second.size();
	}
}

void cPartitions::lastSizeByGroup(map<string, u_int64_t> *size, bool only_prev) {
	map<string, map<string, u_int64_t> > sum;
	sumByGroup(&sum, only_prev);
	for(map<string, map<string, u_int64_t> >::iterator iter_sum = sum.begin(); iter_sum != sum.end(); iter_sum++) {
		(*size)[iter_sum->first] = iter_sum->second.begin()->second;
	}
}

void cPartitions::getGroups(vector<string> *groups) {
	string group_prev;
	for(list<sTable>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		if(iter->group != group_prev &&
		   find(groups->begin(), groups->end(), iter->group) == groups->end()) {
			groups->push_back(iter->group);
			group_prev = iter->group;
		}
	}
}

void cPartitions::getGroups(set<string> *groups) {
	for(list<sTable>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		groups->insert(iter->group);
	}
}

void cPartitions::getTablesInGroup(vector<string> *tables, const char *group) {
	for(list<sTable>::iterator iter = this->tables.begin(); iter != this->tables.end(); iter++) {
		if(!group || group == iter->group) {
			tables->push_back(iter->table);
		}
	}
}

void cPartitions::getTablesInGroup(set<string> *tables, const char *group) {
	for(list<sTable>::iterator iter = this->tables.begin(); iter != this->tables.end(); iter++) {
		if(!group || group == iter->group) {
			tables->insert(iter->table);
		}
	}
}

void cPartitions::getPartitionsTimes(vector<string> *times, bool only_prev, const char *group) {
	set<string> tablesInGroup;
	if(group) {
		getTablesInGroup(&tablesInGroup, group);
	}
	set<string> times_set;
	for(map<string, list<SqlDb::sPartition> >::iterator iter = partitions.begin(); iter != partitions.end(); iter++) {
		if(!group || tablesInGroup.find(iter->first) != tablesInGroup.end()) {
			for(list<SqlDb::sPartition>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
				if(!only_prev || iter2->is_prev) {
					times_set.insert(iter2->time);
				}
			}
		}
	}
	for(set<string>::iterator iter = times_set.begin(); iter != times_set.end(); iter++) {
		times->push_back(*iter);
	}
}

void cPartitions::getTablesPartsforTime(vector<pair<string, string> > *tables_parts, const char *time, bool only_prev, const char *group) {
	set<string> tablesInGroup;
	if(group) {
		getTablesInGroup(&tablesInGroup, group);
	}
	for(map<string, list<SqlDb::sPartition> >::iterator iter = partitions.begin(); iter != partitions.end(); iter++) {
		if(!group || tablesInGroup.find(iter->first) != tablesInGroup.end()) {
			for(list<SqlDb::sPartition>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
				if(iter2->time == time &&
				   (!only_prev || iter2->is_prev)) {
					tables_parts->push_back(make_pair(iter->first, iter2->name));
				}
			}
		}
	}
}

string cPartitions::dump(bool only_prev, const char *datadir, const char *database) {
	SqlDb *sqlDb = createSqlObject();
	extern string mysql_datadir;
	if(!(datadir && *datadir) && !mysql_datadir.empty()) {
		datadir = mysql_datadir.c_str();
	}
	ostringstream outStr;
	double total_MB, free_MB, free_perc, files_sum_size_MB;
	bool stat_rslt = sqlDb->getDbDatadirStats(datadir, database, &total_MB, &free_MB, &free_perc, &files_sum_size_MB);
	outStr << "DATADIR STAT : " << (stat_rslt ? "OK" : "failed") << endl;
	if(stat_rslt) {
		outStr << "total: " << dump_MB(total_MB * 1024 * 1024) << " MB" << endl
		       << "free: " << dump_MB(free_MB * 1024 * 1024) << " MB"
		       << " / " << free_perc << " %" << endl
		       << "files sum: " << dump_MB(files_sum_size_MB  * 1024 * 1024) << " MB" << endl;
		this->fill(sqlDb);
		vector<string> groups;
		getGroups(&groups);
		map<string, u_int64_t> groups_sum;
		map<string, unsigned> groups_count;
		map<string, u_int64_t> groups_last_size;
		sumByGroup(&groups_sum, only_prev);
		countByGroup(&groups_count, only_prev);
		lastSizeByGroup(&groups_last_size, only_prev);
		outStr << "GROUPS : size / count / last size" << endl;
		for(unsigned i = 0; i < groups.size(); i++) {
			outStr << groups[i] << " : "
			       << dump_MB(groups_sum[groups[i]])  << " MB / "
			       << groups_count[groups[i]] << " / "
			       << dump_MB(groups_last_size[groups[i]]) << " MB" << endl;
		}
		outStr << "SUM : " << dump_MB(sum(only_prev)) << " MB" << endl;
	}
	delete sqlDb;
	return(outStr.str());
}

bool cPartitions::cleanup_by_size(const char *datadir, const char *database) {
	SqlDb *sqlDb = createSqlObject();
	extern string mysql_datadir;
	if(!(datadir && *datadir) && !mysql_datadir.empty()) {
		datadir = mysql_datadir.c_str();
	}
	double total_MB, free_MB, free_perc, files_sum_size_MB;
	bool stat_rslt = sqlDb->getDbDatadirStats(datadir, database, &total_MB, &free_MB, &free_perc, &files_sum_size_MB);
	if(!stat_rslt) {
		delete sqlDb;
		return(false);
	}
	this->fill(sqlDb);
	extern int opt_cleandatabase_size;
	extern int opt_cleandatabase_min_free_size;
	extern int opt_cleandatabase_cdr_size;
	extern int opt_cleandatabase_cdr_rtp_energylevels_size;
	extern int opt_cleandatabase_ss7_size;
	extern int opt_cleandatabase_http_enum_size;
	extern int opt_cleandatabase_webrtc_size;
	extern int opt_cleandatabase_register_state_size;
	extern int opt_cleandatabase_register_failed_size;
	extern int opt_cleandatabase_register_time_info_size;
	extern int opt_cleandatabase_sip_msg_size;
	extern int opt_cleandatabase_cdr_stat_size;
	extern int opt_cleandatabase_cdr_problems_size;
	extern int opt_cleandatabase_rtp_stat_size;
	extern int opt_cleandatabase_log_sensor_size;
	if(opt_cleandatabase_size || opt_cleandatabase_min_free_size) {
		 cleanup_by_size(opt_cleandatabase_size, opt_cleandatabase_min_free_size, sqlDb, datadir, database);
	}
	if(opt_cleandatabase_cdr_size) {
		cleanup_group_by_size("cdr", opt_cleandatabase_cdr_size, sqlDb);
	}
	if(opt_cleandatabase_cdr_rtp_energylevels_size) {
		cleanup_group_by_size("cdr_energylevels", opt_cleandatabase_cdr_rtp_energylevels_size, sqlDb);
	}
	if(opt_cleandatabase_ss7_size) {
		cleanup_group_by_size("ss7", opt_cleandatabase_ss7_size, sqlDb);
	}
	if(opt_cleandatabase_http_enum_size) {
		cleanup_group_by_size("http_enum", opt_cleandatabase_http_enum_size, sqlDb);
	}
	if(opt_cleandatabase_webrtc_size) {
		cleanup_group_by_size("webrtc", opt_cleandatabase_webrtc_size, sqlDb);
	}
	if(opt_cleandatabase_register_state_size) {
		cleanup_group_by_size("register_state", opt_cleandatabase_register_state_size, sqlDb);
	}
	if(opt_cleandatabase_register_failed_size) {
		cleanup_group_by_size("register_failed", opt_cleandatabase_register_failed_size, sqlDb);
	}
	if(opt_cleandatabase_register_time_info_size) {
		cleanup_group_by_size("register_time_info", opt_cleandatabase_register_time_info_size, sqlDb);
	}
	if(opt_cleandatabase_sip_msg_size) {
		cleanup_group_by_size("sip_msg", opt_cleandatabase_sip_msg_size, sqlDb);
	}
	if(opt_cleandatabase_cdr_stat_size) {
		cleanup_group_by_size("cdr_stat", opt_cleandatabase_cdr_stat_size, sqlDb);
	}
	if(opt_cleandatabase_cdr_problems_size) {
		cleanup_group_by_size("cdr_problems", opt_cleandatabase_cdr_problems_size, sqlDb);
	}
	if(opt_cleandatabase_rtp_stat_size) {
		cleanup_group_by_size("rtp_stat", opt_cleandatabase_rtp_stat_size, sqlDb);
	}
	if(opt_cleandatabase_log_sensor_size) {
		cleanup_group_by_size("log_sensor", opt_cleandatabase_log_sensor_size, sqlDb);
	}
	delete sqlDb;
	return(true);
}

void cPartitions::cleanup_by_size(unsigned limit_sum_mb, unsigned limit_min_free_size, SqlDb *sqlDb, 
				  const char *datadir, const char *database) {
	double total_MB, free_MB, free_perc, files_sum_size_MB;
	bool stat_rslt = sqlDb->getDbDatadirStats(datadir, database, &total_MB, &free_MB, &free_perc, &files_sum_size_MB);
	if(!stat_rslt) {
		return;
	}
	unsigned oversize_mb = 0;
	if((limit_sum_mb && files_sum_size_MB > limit_sum_mb) || 
	   (limit_min_free_size && free_MB < limit_min_free_size)) {
		if(limit_sum_mb && files_sum_size_MB > limit_sum_mb) {
			oversize_mb = files_sum_size_MB - limit_sum_mb;
		}
		if(limit_min_free_size && free_MB < limit_min_free_size && 
		   (limit_min_free_size - free_MB) > oversize_mb) {
			oversize_mb = limit_min_free_size - free_MB;
		}
	}
	if(oversize_mb > 0) {
		u_int64_t cleanable_max_size = sum(true);
		if(cleanable_max_size > 0) {
			cleanup_by_oversize(oversize_mb, sqlDb);
		}
	}
}

void cPartitions::cleanup_by_oversize(unsigned oversize_mb, SqlDb *sqlDb) {
	u_int64_t oversize = (u_int64_t)oversize_mb * 1024 * 1024;
	u_int64_t sum = this->sum(true);
	u_int64_t sum_size_required = sum > oversize ? sum - oversize : 0;
	while(sum > sum_size_required) {
		map<string, u_int64_t> groups_sum;
		map<string, unsigned> groups_count;
		sumByGroup(&groups_sum, true);
		countByGroup(&groups_count, true);
		if(groups_sum["sip_msg"] > groups_sum["cdr"]) {
			syslog(LOG_NOTICE, "cleanup partitions by size - remove last partitions for group sip_msg");
			dropLastPartitionsInGroup("sip_msg", sqlDb);
		} else if(groups_sum["register_failed"] > groups_sum["cdr"]) {
			syslog(LOG_NOTICE, "cleanup partitions by size - remove last partitions for group register_failed");
			dropLastPartitionsInGroup("register_failed", sqlDb);
		} else if(groups_sum["cdr_stat"] > groups_sum["cdr"] && groups_count["cdr_stat"] > 1) {
			syslog(LOG_NOTICE, "cleanup partitions by size - remove last partitions for group cdr_stat");
			dropLastPartitionsInGroup("cdr_stat", sqlDb);
		} else if(groups_sum["rtp_stat"] > groups_sum["cdr"] && groups_count["rtp_stat"] > 1) {
			syslog(LOG_NOTICE, "cleanup partitions by size - remove last partitions for group rtp_stat");
			dropLastPartitionsInGroup("rtp_stat", sqlDb);
		} else {
			vector<string> times;
			getPartitionsTimes(&times, true);
			if(times.size()) {
				vector<pair<string, string> > tables_parts;
				getTablesPartsforTime(&tables_parts, times[0].c_str(), true);
				if(tables_parts.size()) {
					syslog(LOG_NOTICE, "cleanup partitions by size - remove partitions for time %s", times[0].c_str());
					bool _createSqlObject = false;
					if(!sqlDb) {
						sqlDb = createSqlObject();
						_createSqlObject = true;
					}
					for(vector<pair<string, string> >::iterator iter = tables_parts.begin(); iter != tables_parts.end(); iter++) {
						dropPartition(iter->first.c_str(), iter->second.c_str(), sqlDb);
					}
					if(_createSqlObject) {
						delete sqlDb;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		}
		sum = this->sum(true);
	}
}

void cPartitions::cleanup_group_by_size(const char *group, unsigned limit_mb, SqlDb *sqlDb) {
	while(true) {
		map<string, u_int64_t> groups_sum;
		map<string, unsigned> groups_count;
		sumByGroup(&groups_sum, false);
		countByGroup(&groups_count, true);
		if(groups_sum[group] > (u_int64_t)limit_mb * 1024ull * 1024 && groups_count[group] > 0) {
			syslog(LOG_NOTICE, "cleanup partitions by size for group %s", group);
			if(!dropLastPartitionsInGroup(group, sqlDb)) {
				break;
			}
		} else {
			break;
		}
	}
}

bool cPartitions::dropLastPartitionsInGroup(const char *group, SqlDb *sqlDb) {
	vector<string> times;
	getPartitionsTimes(&times, true, group);
	if(times.size()) {
		vector<pair<string, string> > tables_parts;
		getTablesPartsforTime(&tables_parts, times[0].c_str(), true, group);
		if(tables_parts.size()) {
			bool _createSqlObject = false;
			if(!sqlDb) {
				sqlDb = createSqlObject();
				_createSqlObject = true;
			}
			for(vector<pair<string, string> >::iterator iter = tables_parts.begin(); iter != tables_parts.end(); iter++) {
				dropPartition(iter->first.c_str(), iter->second.c_str(), sqlDb);
			}
			if(_createSqlObject) {
				delete sqlDb;
			}
			return(true);
		}
	}
	return(false);
}

bool cPartitions::dropPartition(const char *table, const char *partition, SqlDb *sqlDb) {
	map<string, list<SqlDb::sPartition> >::iterator iter = partitions.find(table);
	if(iter != partitions.end()) {
		for(list<SqlDb::sPartition>::iterator iter2 = iter->second.begin(); iter2 != iter->second.end(); iter2++) {
			if(iter2->name == partition) {
				iter->second.erase(iter2);
				syslog(LOG_NOTICE, "DROP PARTITION %s : %s", table, partition);
				sqlDb->setDisableLogError();
				sqlDb->setDisableNextAttemptIfError();
				if(!sverb.suppress_drop_partitions) {
					sqlDb->query(string("ALTER TABLE ") + sqlDb->escapeTableName(table) + " DROP PARTITION " + partition);
				}
				return(true);
			}
		}
	}
	return(false);
}

void cPartitions::addTable(const char *group, const char *table) {
	tables.push_back(sTable(group, table));
}


volatile int sCreatePartitions::in_progress = 0;


void dbDataInit(SqlDb *sqlDb) {
	cSqlDbData *_dbData = new FILE_LINE(0) cSqlDbData();
	extern unsigned opt_cdr_check_exists_callid_cache_max_size;
	extern int absolute_timeout;
	cDbCalls *_dbCalls = new FILE_LINE(0) cDbCalls(opt_cdr_check_exists_callid_cache_max_size, absolute_timeout + 10 * 60);
	if(!opt_nocdr) {
		_dbData->init(!isCloud() && !is_client() && !is_sender() && !is_read_from_file_simple(), 
			      is_server() ? 0 : 1000000, sqlDb);
	}
	dbData = _dbData;
	dbCalls = _dbCalls;
}

void dbDataTerm() {
	if(dbData) {
		delete dbData;
		dbData = NULL;
	}
	if(dbCalls) {
		delete dbCalls;
		dbCalls = NULL;
	}
}

bool dbDataIsSet() {
	return(dbData != NULL);
}


void storeRunningConfig(bool start) {
	string table_sensor_running_config = "sensor_running_config";
	SqlDb *sqlDb = createSqlObject();
	if(!sqlDb->existsTable(table_sensor_running_config)) {
		delete sqlDb;
		return;
	}
	sqlDb->setMaxQueryPass(1);
	sqlDb->setDisableLogError();
	if(!sqlDb->select(table_sensor_running_config, NULL, "id_sensor", intToString(opt_id_sensor).c_str())) {
		delete sqlDb;
		return;
	}
	SqlDb_row row = sqlDb->fetchRow();
	unsigned row_id = 0;
	if(row) {
		row_id = atoi(row["id"].c_str());
	}
	if(start) {
		SqlDb_row row;
		if(!row_id) {
			row.add(opt_id_sensor, "id_sensor");
		}
		row.add(sqlDateTimeString(time(NULL)), "start_at");
		row.add_null("stop_at");
		row.add(getVersionWithBuild(), "version");
		string config_json;
		extern cConfig CONFIG;
		if(CONFIG.isSet()) {
			config_json = CONFIG.getJson(true);
		} else {
			cConfig config;
			config.addConfigItems();
			config_json = config.getJson(true);
		}
		row.add(config_json, "config");
		if(row_id) {
			sqlDb->update(table_sensor_running_config, row, ("id = " + intToString(row_id)).c_str());
		} else {
			sqlDb->insert(table_sensor_running_config, row);
		}
	} else if(row_id) {
		SqlDb_row row;
		row.add(sqlDateTimeString(time(NULL)), "stop_at");
		sqlDb->update(table_sensor_running_config, row, ("id = " + intToString(row_id)).c_str());
	}
	delete sqlDb;
}


#if DEBUG_STORE_COUNT
void out_db_cnt() {
	cout << "* _query_to_file_cnt" << endl;
	int sum = 0;
	for(map<int, u_int64_t>::iterator iter = _query_to_file_cnt.begin(); iter != _query_to_file_cnt.end(); iter++) {
		sum += iter->second;
		cout << iter->first << " : " << iter->second << " s " << sum << endl;
	}
	cout << "* _loadFromQFile_cnt" << endl;
	sum = 0;
	for(map<int, u_int64_t>::iterator iter = _loadFromQFile_cnt.begin(); iter != _loadFromQFile_cnt.end(); iter++) {
		sum += iter->second;
		cout << iter->first << " : " << iter->second << " s " << sum << endl;
	}
	cout << "* _query_lock_cnt" << endl;
	sum = 0;
	for(map<int, u_int64_t>::iterator iter = _query_lock_cnt.begin(); iter != _query_lock_cnt.end(); iter++) {
		sum += iter->second;
		cout << iter->first << " : " << iter->second << " s " << sum << endl;
	}
	cout << "* _store_cnt" << endl;
	sum = 0;
	for(map<int, u_int64_t>::iterator iter = _store_cnt.begin(); iter != _store_cnt.end(); iter++) {
		sum += iter->second;
		cout << iter->first << " : " << iter->second << " s " << sum << endl;
	}
	cout << "* _store_old_cnt" << endl;
	sum = 0;
	for(map<int, u_int64_t>::iterator iter = _store_old_cnt.begin(); iter != _store_old_cnt.end(); iter++) {
		sum += iter->second;
		cout << iter->first << " : " << iter->second << " s " << sum << endl;
	}
	cout << "* _charts_cache_cnt" << endl;
	sum = 0;
	for(map<int, u_int64_t>::iterator iter = _charts_cache_cnt.begin(); iter != _charts_cache_cnt.end(); iter++) {
		sum += iter->second;
		cout << iter->first << " : " << iter->second << " s " << sum << endl;
	}
}
#endif
