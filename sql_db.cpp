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

#define QFILE_PREFIX "qoq"


extern int verbosity;
extern int opt_mysql_port;
extern char opt_match_header[128];
extern int opt_ipaccount;
extern int opt_id_sensor;
extern bool opt_cdr_partition;
extern bool opt_cdr_sipport;
extern bool opt_last_rtp_from_end;
extern bool opt_cdr_rtpport;
extern bool opt_cdr_rtpsrcport;
extern int opt_create_old_partitions;
extern bool opt_disable_partition_operations;
extern vector<dstring> opt_custom_headers_cdr;
extern vector<dstring> opt_custom_headers_message;
extern char get_customers_pn_query[1024];
extern int opt_dscp;
extern int opt_enable_http_enum_tables;
extern int opt_enable_webrtc_table;
extern int opt_mysqlcompress;
extern int opt_mysql_enable_transactions;
extern pthread_mutex_t mysqlconnect_lock;      
extern int opt_mos_lqo;
extern int opt_read_from_file;
extern char opt_pb_read_from_file[256];
extern int opt_enable_fraud;
extern bool _save_sip_history;
extern bool opt_sql_time_utc;
extern int opt_enable_ss7;
extern int opt_ssl_store_sessions;
extern int opt_cdr_country_code;
extern int opt_message_country_code;

extern char sql_driver[256];

extern char mysql_host[256];
extern char mysql_database[256];
extern char mysql_user[256];
extern char mysql_password[256];
extern int opt_mysql_port;

extern char mysql_2_host[256];
extern char mysql_2_database[256];
extern char mysql_2_user[256];
extern char mysql_2_password[256];
extern int opt_mysql_2_port;

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

extern sSnifferClientOptions snifferClientOptions;
extern sSnifferServerClientOptions snifferServerClientOptions;


int sql_noerror = 0;
int sql_disable_next_attempt_if_error = 0;
bool opt_cdr_partition_oldver = false;
bool opt_ss7_partition_oldver;
bool opt_rtp_stat_partition_oldver = false;
bool opt_log_sensor_partition_oldver = false;
sExistsColumns existsColumns;
SqlDb::eSupportPartitions supportPartitions = SqlDb::_supportPartitions_ok;

#define CONV_ID(id) (id < STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS || id >= STORE_PROC_ID_IPACC_1 ?  (id / 10) * 10 : id)
#define CONV_ID_FOR_QFILE(id) CONV_ID(id)
#define CONV_ID_FOR_REMOTE_STORE(id) CONV_ID(id)


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

void SqlDb_row::add(const char *content, string fieldName) {
	if(fieldName != "") {
		for(size_t i = 0; i < row.size(); i++) {
			if(row[i].fieldName == fieldName) {
				row[i] = SqlDb_rowField(content, fieldName);
				return;
			}
		}
	}
	this->row.push_back(SqlDb_rowField(content, fieldName));
}

void SqlDb_row::add(string content, string fieldName, bool null) {
	if(fieldName != "") {
		for(size_t i = 0; i < row.size(); i++) {
			if(row[i].fieldName == fieldName) {
				row[i] = SqlDb_rowField(content, fieldName, null);
				return;
			}
		}
	}
	this->row.push_back(SqlDb_rowField(content, fieldName, null));
}

void SqlDb_row::add(int content, string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%i", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(unsigned int content, string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%u", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(long int content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%li", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(unsigned long int content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%lu", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(long long int content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%lli", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(unsigned long long int content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%llu", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(double content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		snprintf(str_content, sizeof(str_content), "%lf", content);
		this->add(str_content, fieldName);
	}
}

int SqlDb_row::getIndexField(string fieldName) {
	for(size_t i = 0; i < row.size(); i++) {
		if(!strcasecmp(row[i].fieldName.c_str(), fieldName.c_str())) {
			return(i);
		}
	}
	if(this->sqlDb) {
		return(this->sqlDb->getIndexField(fieldName));
	}
	return(-1);
}

string SqlDb_row::getNameField(int indexField) {
	if((unsigned)indexField < row.size()) {
		if(!row[indexField].fieldName.empty()) {
			return(row[indexField].fieldName);
		}
		if(this->sqlDb) {
			return(this->sqlDb->getNameField(indexField));
		}
	}
	return("");
}

bool SqlDb_row::isEmpty() {
	return(!row.size());
}

bool SqlDb_row::isNull(string fieldName) {
	int indexField = this->getIndexField(fieldName);
	if(indexField >= 0) {
		return(row[indexField].null);
	}
	return(false);
}

string SqlDb_row::implodeFields(string separator, string border) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		rslt += border + /*'`' +*/ this->row[i].fieldName + /*'`' +*/ border;
	}
	return(rslt);
}

string SqlDb_row::implodeContent(string separator, string border, bool enableSqlString, bool escapeAll) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		if(this->row[i].null) {
			rslt += "NULL";
		} else if(enableSqlString && this->row[i].content.substr(0, 12) == "_\\_'SQL'_\\_:") {
			rslt += this->row[i].content.substr(12);
		} else {
			rslt += border + 
				(escapeAll ? sqlEscapeString(this->row[i].content) : this->row[i].content) + 
				border;
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
		} else if(enableSqlString && this->row[i].content.substr(0, 12) == "_\\_'SQL'_\\_:") {
			rslt += this->row[i].content.substr(12);
		} else {
			rslt += contentBorder + 
				(escapeAll ? sqlEscapeString(this->row[i].content) : this->row[i].content) + 
				contentBorder;
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
	this->conn_disable_secure_auth = false;
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
	this->existsColumnCache_enable = false;
	this->existsColumnCache_suspend = false;
}

SqlDb::~SqlDb() {
	if(this->remote_socket) {
		delete this->remote_socket;
	}
}

void SqlDb::setConnectParameters(string server, string user, string password, string database, u_int16_t port, bool showversion) {
	this->conn_server = server;
	this->conn_user = user;
	this->conn_password = password;
	this->conn_database = database;
	this->conn_port = port;
	this->conn_showversion = showversion;
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

bool SqlDb::queryByCurl(string query, bool callFromStoreProcessWithFixDeadlock) {
	clearLastError();
	bool ok = false;
	unsigned int attempt = 0;
	unsigned int send_query_counter = 0;
	for(unsigned int pass = 0; pass < this->maxQueryPass; pass++, attempt++) {
		string preparedQuery = this->prepareQuery(query, !callFromStoreProcessWithFixDeadlock && send_query_counter > 1);
		if(pass > 0) {
			sleep(1);
			syslog(LOG_INFO, "next attempt %u - query: %s", attempt, prepareQueryForPrintf(preparedQuery).c_str());
		}
		vector<dstring> postData;
		postData.push_back(dstring("query", preparedQuery.c_str()));
		postData.push_back(dstring("token", cloud_token));
		SimpleBuffer responseBuffer;
		string error;
		get_url_response(cloud_redirect.empty() ? cloud_host.c_str() : cloud_redirect.c_str(),
				 &responseBuffer, &postData, &error);
		if(!error.empty()) {
			setLastError(0, error.c_str(), true);
			continue;
		}
		if(responseBuffer.empty()) {
			setLastError(0, "response is empty", true);
			continue;
		}
		if(!responseBuffer.isJsonObject()) {
			setLastError(0, "bad response - " + string(responseBuffer), true);
			continue;
		}
		JsonItem jsonData;
		jsonData.parse((char*)responseBuffer);
		string result = jsonData.getValue("result");
		trim(result);
		if(!strncasecmp(result.c_str(), "REDIRECT TO", 11)) {
			cloud_redirect = result.substr(11);
			trim(cloud_redirect);
			if(cloud_redirect.empty()) {
				setLastError(0, "missing redirect ip / server", true);
			} else {
				pass = 0;
				continue;
			}
		}
		int rsltProcessResponse = processResponseFromQueryBy(responseBuffer, pass);
		send_query_counter++;
		if(rsltProcessResponse == 1) {
			ok = true;
			break;
		} else if(rsltProcessResponse == -1) {
			break;
		} else {
			if(callFromStoreProcessWithFixDeadlock && getLastError() == ER_LOCK_DEADLOCK) {
				break;
			}
		}
	}
	return(ok);
}

bool SqlDb::queryByRemoteSocket(string query, bool callFromStoreProcessWithFixDeadlock, const char *dropProcQuery) {
	clearLastError();
	bool ok = false;
	unsigned int attempt = 0;
	unsigned int send_query_counter = 0;
	for(unsigned int pass = 0; pass < this->maxQueryPass; pass++, attempt++) {
		if(is_terminating() > 1 && attempt > 2) {
			break;
		}
		string preparedQuery = this->prepareQuery(query, !callFromStoreProcessWithFixDeadlock && send_query_counter > 1);
		if(pass > 0) {
			if(this->remote_socket) {
				delete this->remote_socket;
				this->remote_socket = NULL;
			}
			if(is_terminating()) {
				usleep(100000);
			} else {
				sleep(1);
			}
			syslog(LOG_INFO, "next attempt %u - query: %s", attempt, prepareQueryForPrintf(preparedQuery.c_str()).c_str());
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
				this->remote_socket->setHostPort(snifferClientOptions.host, snifferClientOptions.port);
			}
			if(!this->remote_socket->connect()) {
				setLastError(0, "failed connect to cloud router", true);
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
					setLastError(0, "failed response from cloud router - " + connectResponse, true);
					delete this->remote_socket;
					this->remote_socket = NULL;
					break;
				} else {
					setLastError(0, "failed read ok", true);
					continue;
				}
			}
		}
		int rsltProcessResponse = _queryByRemoteSocket(preparedQuery, pass);
		send_query_counter++;
		if(rsltProcessResponse == 1) {
			ok = true;
			break;
		} else if(rsltProcessResponse == -1) {
			break;
		} else {
			if(callFromStoreProcessWithFixDeadlock && getLastError() == ER_LOCK_DEADLOCK) {
				break;
			}
			if(this->getLastError() == ER_SP_ALREADY_EXISTS && pass >= 2) {
				if(_queryByRemoteSocket("repair table mysql.proc", 0) == 1) {
					syslog(LOG_NOTICE, "success call 'repair table mysql.proc'");
				} else {
					syslog(LOG_NOTICE, "failed call 'repair table mysql.proc' with error: %s", this->getLastErrorString().c_str());
				}
				if(dropProcQuery) {
					if(_queryByRemoteSocket(dropProcQuery, 0) == 1) {
						syslog(LOG_NOTICE, "success call '%s'", dropProcQuery);
					} else {
						syslog(LOG_NOTICE, "failed call '%s' with error: %s", dropProcQuery, this->getLastErrorString().c_str());
					}
				}
			}
		}
	}
	return(ok);
}

int SqlDb::_queryByRemoteSocket(string query, unsigned int pass) {
	bool okSendQuery = true;
	if(query.length() > 100) {
		cGzip gzipCompressQuery;
		u_char *queryGzip;
		size_t queryGzipLength;
		if(gzipCompressQuery.compressString(query, &queryGzip, &queryGzipLength)) {
			if(!this->remote_socket->writeBlock(queryGzip, queryGzipLength, cSocket::_te_aes)) {
				okSendQuery = false;
			}
			delete queryGzip;
		}
	} else {
		if(!this->remote_socket->writeBlock(query, cSocket::_te_aes)) {
			okSendQuery = false;
		}
	}
	if(!okSendQuery) {
		setLastError(0, "failed send query", true);
		return(0);
	}
	u_char *queryResponse;
	size_t queryResponseLength;
	queryResponse = this->remote_socket->readBlock(&queryResponseLength, cSocket::_te_aes);
	if(!queryResponse) {
		setLastError(0, "failed read query response", true);
		return(0);
	}
	string queryResponseStr;
	cGzip gzipDecompressResponse;
	if(gzipDecompressResponse.isCompress(queryResponse, queryResponseLength)) {
		queryResponseStr = gzipDecompressResponse.decompressString(queryResponse, queryResponseLength);
		if(queryResponseStr.empty()) {
			setLastError(0, "response is invalid (gunzip failed)", true);
			return(0);
		}
	} else {
		queryResponseStr = string((char*)queryResponse, queryResponseLength);
	}
	if(queryResponseStr.empty()) {
		setLastError(0, "response is empty", true);
		return(0);
	}
	if(!isJsonObject(queryResponseStr)) {
		setLastError(0, "response is not json", true);
		return(0);
	}
	return(processResponseFromQueryBy(queryResponseStr.c_str(), pass));
}

int SqlDb::processResponseFromQueryBy(const char *response, unsigned pass) {
	response_data_columns.clear();
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
		bool tryNext = true;
		unsigned int errorCode = atol(result.c_str());
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
		if(!sql_noerror && !this->disableLogError) {
			setLastError(errorCode, errorString.c_str(), true);
		}
		if(tryNext) {
			if(sql_noerror || sql_disable_next_attempt_if_error || 
			   this->disableLogError || this->disableNextAttemptIfError ||
			   errorCode == ER_PARSE_ERROR) {
				return(-1);
			} else if(errorCode != CR_SERVER_GONE_ERROR &&
				  pass < this->maxQueryPass - 5) {
				pass = this->maxQueryPass - 5;
			}
		} else {
			return(-1);
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
						response_data_columns.push_back(dataItem);
					} else {
						if(response_data.size() < i) {
							vector<sCloudDataItem> row;
							response_data.push_back(row);
						}
						response_data[i-1].push_back(sCloudDataItem(dataItem.c_str(), dataItemIsNull));
					}
				}
			}
		}
		return(1);
	}
	return(0);
}

string SqlDb::prepareQuery(string query, bool nextPass) {
	::prepareQuery(this->getSubtypeDb(), query, true, nextPass ? 2 : 1);
	return(query);
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

string SqlDb::getCondStr(list<SqlDb_condField> *cond) {
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
			    getContentBorder() + escape(iter->value.c_str()) + getContentBorder() :
			    iter->value;
	}
	return(condStr);
}

string SqlDb::selectQuery(string table, list<SqlDb_field> *fields, list<SqlDb_condField> *cond, unsigned limit) {
	string query = 
		"select " +
		(fields && fields->size() ? getFieldsStr(fields) : "*") + 
		" from " + escapeTableName(table);
	if(cond && cond->size()) {
		query += " where " + getCondStr(cond);
	}
	if(limit) {
		query += " limit " + intToString(limit);
	}
	return(query);
}

string SqlDb::selectQuery(string table, const char *field, const char *condField, const char *condValue, unsigned limit) {
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

string SqlDb::insertQueryWithLimitMultiInsert(string table, vector<SqlDb_row> *rows, unsigned limitMultiInsert, const char *queriesSeparator,
					      bool enableSqlStringInContent, bool escapeAll, bool insertIgnore) {
	if(!rows->size()) {
		return("");
	}
	string query = "";
	string values = "";
	for(size_t i = 0; i < rows->size(); i++) {
		values += "( " + (*rows)[i].implodeContent(this->getContentSeparator(), this->getContentBorder(), enableSqlStringInContent || this->enableSqlStringInContent, escapeAll) + " )";
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

bool SqlDb::select(string table, list<SqlDb_field> *fields, list<SqlDb_condField> *cond, unsigned limit) {
	string query = this->selectQuery(table, fields, cond, limit);
	return(this->query(query));
}

bool SqlDb::select(string table, const char *field, const char *condField, const char *condValue, unsigned limit) {
	string query = this->selectQuery(table, field, condField, condValue, limit);
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

int64_t SqlDb::getQueryRsltIntValue(string query, int indexRslt, int64_t failedResult) {
	if(this->query(query)) {
		SqlDb_row row;
		if((row = this->fetchRow())) {
			return(atoll(row[indexRslt].c_str()));
		}
	}
	return(failedResult);
}

void SqlDb::startExistsColumnCache() {
	this->existsColumnCache.clear();
	this->existsColumnCache_enable = true;
	this->existsColumnCache_suspend = false;
}

void SqlDb::stopExistsColumnCache() {
	this->existsColumnCache.clear();
	this->existsColumnCache_enable = false;
	this->existsColumnCache_suspend = false;
}

void SqlDb::suspendExistsColumnCache() {
	if(this->existsColumnCache_enable) {
		this->existsColumnCache_suspend = true;
	}
}

void SqlDb::resumeExistsColumnCache() {
	this->existsColumnCache_suspend = false;
}

bool SqlDb::isEnableExistColumnCache() {
	return(this->existsColumnCache_enable &&
	       !this->existsColumnCache_suspend);
}

int SqlDb::existsColumnInCache(const char *table, const char *column) {
	map<string, list<string> >::iterator iter = this->existsColumnCache.find(table);
	if(iter != this->existsColumnCache.end()) {
		return(find(iter->second.begin(), iter->second.end(), column) != iter->second.end());
	}
	return(-1);
}

void SqlDb::addColumnToCache(const char *table, const char *column) {
	this->existsColumnCache[table].push_back(column);
}

int SqlDb::getPartitions(const char *table, vector<string> *partitions, bool useCache) {
	list<string> partitions_l;
	int rslt = getPartitions(table, &partitions_l, useCache);
	partitions->clear();
	for(list<string>::iterator iter = partitions_l.begin(); iter != partitions_l.end(); iter++) {
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
	char partitionName[10];
	snprintf(partitionName, sizeof(partitionName), "p%02i%02i%02i", tm.tm_year - 100, tm.tm_mon + 1, tm.tm_mday);
	bool rslt = existsPartition(table, partitionName, useCache);
	/*
	if(rslt) {
		cout << "exists partition " << table << '.' << partitionName << endl;
	}
	*/
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
	this->silentConnect = true;;
}

void SqlDb::cleanFields() {
	this->fields.clear();
}

void SqlDb::addDelayQuery(u_int32_t delay_ms) {
	delayQuery_sum_ms += delay_ms;
	++delayQuery_count;
}

u_int32_t SqlDb::getAvgDelayQuery() {
	u_int64_t _delayQuery_sum_ms = delayQuery_sum_ms;
	u_int32_t _delayQuery_count = delayQuery_count;
	return(_delayQuery_count ? _delayQuery_sum_ms / _delayQuery_count : 0);
}

void SqlDb::resetDelayQuery() {
	delayQuery_sum_ms = 0;
	delayQuery_count = 0;
}

void SqlDb::logNeedAlter(string table, string reason, string alter,
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
		if((*tableSize)[table] < 1000) {
			int sql_disable_next_attempt_if_error_old = sql_disable_next_attempt_if_error;
			sql_disable_next_attempt_if_error = 1;
			okAlter = this->query(alter);
			if(okAlter && existsColumnFlag) {
				*existsColumnFlag = true;
			}
			sql_disable_next_attempt_if_error = sql_disable_next_attempt_if_error_old;
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
			alter;
		syslog(LOG_WARNING, "%s", msg.c_str());
	}
}

volatile u_int64_t SqlDb::delayQuery_sum_ms = 0;
volatile u_int32_t SqlDb::delayQuery_count = 0;


SqlDb_mysql::SqlDb_mysql() {
	this->hMysql = NULL;
	this->hMysqlConn = NULL;
	this->hMysqlRes = NULL;
	this->mysqlThreadId = 0;
	this->partitions_cache_sync = 0;
}

SqlDb_mysql::~SqlDb_mysql() {
	this->clean();
}

bool SqlDb_mysql::connect(bool createDb, bool mainInit) {
	if(opt_nocdr || isCloud() || snifferClientOptions.isEnableRemoteQuery()) {
		return(true);
	}
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
		my_bool reconnect = 1;
		mysql_options(this->hMysql, MYSQL_OPT_RECONNECT, &reconnect);
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
			if(this->conn_disable_secure_auth) {
				int arg = 0;
				mysql_options(this->hMysql, MYSQL_SECURE_AUTH, &arg);
			}
			extern unsigned int opt_mysql_connect_timeout;
			if(opt_mysql_connect_timeout) {
				mysql_options(this->hMysql, MYSQL_OPT_CONNECT_TIMEOUT, &opt_mysql_connect_timeout);
			}
			this->hMysqlConn = mysql_real_connect(
						this->hMysql,
						conn_server_ip.c_str(), this->conn_user.c_str(), this->conn_password.c_str(), NULL,
						this->conn_port ? this->conn_port : opt_mysql_port,
						NULL, 
						CLIENT_MULTI_RESULTS | (opt_mysql_client_compress ? CLIENT_COMPRESS : 0));
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
								syslog(LOG_WARNING, "Max allowed packet size is only %lu. Concat query size is limited. "
										    "Please set max_allowed_packet to 100MB manually in your mysql configuration file.", 
								       this->maxAllowedPacket);
							}
						}
					} else {
						if(mainInit) {
							syslog(LOG_WARNING, "Unknown max allowed packet size. Concat query size is limited. "
									    "Please set max_allowed_packet to 100MB manually in your mysql configuration file.");
						}
						break;
					}
				} else {
					sql_disable_next_attempt_if_error = 0;
					sql_noerror = 0;
					if(mainInit) {
						syslog(LOG_WARNING, "Query for set / get max allowed packet size failed. Concat query size is limited. "
								    "Please set max_allowed_packet to 100MB manually in your mysql configuration file.");
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
			if(!this->existsDatabase() || !this->query(tmp)) {
				rslt = false;
			}
			if(mainInit && !isCloud()) {
				this->query("SHOW VARIABLES LIKE \"version\"");
				SqlDb_row row;
				if((row = this->fetchRow())) {
					this->dbVersion = row[1];
				}
				while(this->fetchRow());
				if(this->conn_showversion) {
					syslog(LOG_INFO, "connect - db version %s (%i) %s / maximum partitions: %i", 
					       this->getDbVersionString().c_str(), this->getDbVersion(), this->getDbName().c_str(), this->getMaximumPartitions());
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
	if(this->dbVersion.empty() && !isCloud()) {
		this->query("SHOW VARIABLES LIKE \"version\"");
		SqlDb_row row = this->fetchRow();
		if(row) {
			this->dbVersion = row[1];
		}
	}
	return(atoi(this->dbVersion.c_str()));
}

int SqlDb_mysql::getDbMinorVersion(int minorLevel) {
	this->_getDbVersion();
	const char *pointToVersion = this->dbVersion.c_str();
	for(int i = 0; i < minorLevel + 1 && pointToVersion; i++) {
		const char *pointToSeparator = strchr(pointToVersion, '.');
		if(pointToSeparator) {
			pointToVersion = pointToSeparator + 1;
		}
	}
	return(pointToVersion ? atoi(pointToVersion) : 0);
}

string SqlDb_mysql::getDbName() {
	this->_getDbVersion();
	return(strcasestr(this->dbVersion.c_str(), "MariaDB") ? "mariadb" : "mysql");
}

int SqlDb_mysql::getMaximumPartitions() {
	return(getDbName() == "mariadb" ? 
		(getDbVersion() < 100004 ? 1024 : 8192) :
		(getDbVersion() < 50607 ? 1024 : 8192));
}

bool SqlDb_mysql::_getDbVersion() {
	if(this->dbVersion.empty() && !isCloud()) {
		this->query("SHOW VARIABLES LIKE \"version\"");
		SqlDb_row row = this->fetchRow();
		if(row) {
			this->dbVersion = row[1];
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
		syslog(LOG_NOTICE, "create %s %s", (routineType == procedure ? "procedure" : "function"), routineName.c_str());
		this->query(string("drop ") + (routineType == procedure ? "PROCEDURE" : "FUNCTION") +
			    " if exists " + routineName);
		bool rslt = this->query(string("create ") + (routineType == procedure ? "PROCEDURE" : "FUNCTION") + " " +
					routineName + routineParamsAndReturn + " " + routine);
		if(!rslt && abortIfFailed) {
			string errorString = 
				string("create routine ") + routineName + " failed\n" +
				"tip: SET GLOBAL log_bin_trust_function_creators = 1  or put it in my.cnf configuration or grant SUPER privileges to your voipmonitor mysql user.";
			syslog(LOG_ERR, "%s", errorString.c_str());
			vm_terminate_error(errorString.c_str());
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
		if(isCloudSsh()) {
			return(this->queryByCurl(preparedQuery, callFromStoreProcessWithFixDeadlock));
		} else {
			return(this->queryByRemoteSocket(preparedQuery, callFromStoreProcessWithFixDeadlock, dropProcQuery));
		}
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
		if(attempt == 1 && verbosity > 1) {
			syslog(LOG_INFO, "%s", prepareQueryForPrintf(preparedQuery).c_str());
		}
		if(pass > 0) {
			if(is_terminating()) {
				usleep(100000);
			} else {
				sleep(1);
			}
			syslog(LOG_INFO, "next attempt %u - query: %s", attempt - 1, prepareQueryForPrintf(preparedQuery).c_str());
		}
		if(!this->connected()) {
			this->connect();
		}
		if(this->connected()) {
			if(mysql_query(this->hMysqlConn, preparedQuery.c_str())) {
				if(verbosity > 1) {
					syslog(LOG_NOTICE, "query error - query: %s", prepareQueryForPrintf(preparedQuery).c_str());
					syslog(LOG_NOTICE, "query error - error: %s", mysql_error(this->hMysql));
				}
				this->checkLastError("query error in [" + preparedQuery.substr(0,200) + (preparedQuery.size() > 200 ? "..." : "") + "]", !sql_noerror && !this->disableLogError);
				if(!sql_noerror && !this->disableLogError && (verbosity > 1 || sverb.query_error)) {
					cout << endl << "ERROR IN QUERY: " << endl
					     << preparedQuery << endl;
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
					} else if(sql_noerror || sql_disable_next_attempt_if_error || 
						  this->disableLogError || this->disableNextAttemptIfError ||
						  this->getLastError() == ER_PARSE_ERROR ||
						  this->getLastError() == ER_NO_REFERENCED_ROW_2 ||
						  this->getLastError() == ER_SAME_NAME_PARTITION ||
						  (callFromStoreProcessWithFixDeadlock && this->getLastError() == ER_LOCK_DEADLOCK)) {
						break;
					} else {
						if(this->getLastError() == ER_SP_ALREADY_EXISTS) {
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
						extern int opt_load_query_from_files;
						if(!opt_load_query_from_files && pass < this->maxQueryPass - 5) {
							pass = this->maxQueryPass - 5;
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
				row.add(response_data[response_data_index][i].str, response_data_columns[i], response_data[response_data_index][i].null);
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
				}
			} else {
				this->checkLastError("fetch row error in function mysql_use_result", true);
			}
		}
		if(this->hMysqlRes) {
			MYSQL_ROW mysqlRow = mysql_fetch_row(hMysqlRes);
			if(mysqlRow) {
				unsigned int numFields = mysql_num_fields(this->hMysqlRes);
				for(unsigned int i = 0; i < numFields; i++) {
					row.add(mysqlRow[i], this->fields[i]);
				}
			} else {
				this->checkLastError("fetch row error", true);
			}
		}
	}
	return(row);
}

bool SqlDb_mysql::fetchQueryResult(vector<string> *fields, vector<map<string, string_null> > *rows) {
	fields->clear();
	rows->clear();
	MYSQL_RES *hMysqlRes = mysql_use_result(this->hMysqlConn);
	if(hMysqlRes) {
		MYSQL_FIELD *field;
		for(int i = 0; (field = mysql_fetch_field(hMysqlRes)); i++) {
			fields->push_back(field->name);
		}
		MYSQL_ROW mysqlRow;
		while((mysqlRow = mysql_fetch_row(hMysqlRes))) {
			map<string, string_null> rslt_row;
			unsigned int numFields = mysql_num_fields(hMysqlRes);
			for(unsigned int i = 0; i < numFields; i++) {
				rslt_row[(*fields)[i]] = string_null(mysqlRow[i]);
			}
			rows->push_back(rslt_row);
		}
		mysql_free_result(hMysqlRes);
	}
	return(true);
	
}

string SqlDb_mysql::getJsonResult(vector<string> *fields, vector<map<string, string_null> > *rows) {
	JsonExport exp;
	exp.add("result", "OK");
	string jsonData;
	if(rows->size()) {
		exp.add("data_rows", rows->size());
		exp.addArray("data");
		JsonExport expFields;
		expFields.setTypeItem(JsonExport::_array);
		for(size_t j = 0; j < fields->size(); j++) {
			expFields.add(NULL, (*fields)[j]);
		}
		jsonData = expFields.getJson();
		for(size_t i = 0; i < rows->size(); i++) {
			JsonExport expRow;
			expRow.setTypeItem(JsonExport::_array);
			for(size_t j = 0; j < min((*rows)[i].size(), fields->size()); j++) {
				if((*rows)[i][(*fields)[j]].is_null) {
					expRow.add(NULL);
				} else {
					expRow.add(NULL, (*rows)[i][(*fields)[j]].str);
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
	vector<map<string, string_null> > rslt_rows;
	this->fetchQueryResult(&rslt_fields, &rslt_rows);
	return(this->getJsonResult(&rslt_fields, &rslt_rows));
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
	if(this->hMysqlConn) {
		return(mysql_insert_id(this->hMysqlConn));
	}
	return(-1);
}

bool SqlDb_mysql::existsTable(const char *table) {
	this->query(string("show tables like '") + table + "'");
	int countRow = 0;
	while(this->fetchRow()) {
		++countRow;
	}
	return(countRow > 0);
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

bool SqlDb_mysql::existsColumn(const char *table, const char *column) {
	if(isEnableExistColumnCache()) {
		int exists = this->existsColumnInCache(table, column);
		if(exists < 0) {
			this->query(string("show columns from ") + escapeTableName(table));
			SqlDb_row cdr_struct_row;
			while((cdr_struct_row = this->fetchRow())) {
				this->addColumnToCache(table, cdr_struct_row["field"].c_str());
				if(cdr_struct_row["field"] == column) {
					exists = true;
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
		while(this->fetchRow()) {
			++countRow;
		}
		return(countRow > 0);
	}
}

string SqlDb_mysql::getTypeColumn(const char *table, const char *column, bool toLower) {
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

int SqlDb_mysql::getPartitions(const char *table, list<string> *partitions, bool useCache) {
	if(useCache) {
		bool existsInCache = false;
		int sizeInCache = 0;
		while(__sync_lock_test_and_set(&partitions_cache_sync, 1));
		if(partitions_cache.find(table) != partitions_cache.end()) {
			if(partitions) {
				*partitions = partitions_cache[table];
			}
			sizeInCache = partitions_cache[table].size();
			existsInCache = true;
		}
		__sync_lock_release(&partitions_cache_sync);
		if(existsInCache) {
			return(sizeInCache);
		}
	}
	list<string> _partitions;
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
					partitions->push_back(partitions_v[i]);
				}
			}
		}
	}
	if(useCache && partitions) {
		while(__sync_lock_test_and_set(&partitions_cache_sync, 1));
		partitions_cache[table] = *partitions;
		__sync_lock_release(&partitions_cache_sync);
	}
	return(_size);
}

bool SqlDb_mysql::existsPartition(const char *table, const char *partition, bool useCache) {
	list<string> partitions;
	if(getPartitions(table, &partitions, useCache) > 0) {
		for(list<string>::iterator iter = partitions.begin(); iter != partitions.end(); iter++) {
			if(*iter == partition) {
				return(true);
			}
		}
	}
	return(false);
}

bool SqlDb_mysql::emptyTable(const char *table) {
	return(rowsInTable(table) <= 0);
}

int64_t SqlDb_mysql::rowsInTable(const char *table) {
	list<SqlDb_field> fields;
	fields.push_back(SqlDb_field("count(*)", "cnt", false));
	this->select(table, &fields);
	SqlDb_row row = this->fetchRow();
	return(row ? atol(row["cnt"].c_str()) : -1);
}

bool SqlDb_mysql::isOldVerPartition(const char *table) {
	this->query(string("select partition_description from information_schema.partitions where table_schema='")  + mysql_database + 
			   "' and table_name like '" + table + "' and partition_description is not null and  partition_description regexp '^[0-9]+$' limit 1");
	return(this->fetchRow());
}

string SqlDb_mysql::escape(const char *inputString, int length) {
	return sqlEscapeString(inputString, length, this->getTypeDb().c_str(), this);
}

string SqlDb_mysql::escapeTableName(string tableName) {
	if(isReservedWord(tableName)) {
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
				usleep(100000);
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
				if(!sql_noerror && !this->disableLogError) {
					this->checkLastError("odbc query error", true);
				}
				if(sql_noerror || sql_disable_next_attempt_if_error || 
				   this->disableLogError || this->disableNextAttemptIfError) {
					break;
				}
				else if(rslt == SQL_ERROR || rslt == SQL_INVALID_HANDLE) {
					if(pass < this->maxQueryPass - 1) {
						this->reconnect();
					}
				} else {
					if(pass < this->maxQueryPass - 5) {
						pass = this->maxQueryPass - 5;
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

bool SqlDb_odbc::existsColumn(const char */*table*/, const char */*column*/) {
	// TODO
	return(false);
}

string SqlDb_odbc::getTypeColumn(const char */*table*/, const char */*column*/, bool /*toLower*/) {
	// TODO
	return("");
}

int SqlDb_odbc::getPartitions(const char */*table*/, list<string> */*partitions*/, bool /*useCache*/) {
	// TODO
	return(-1);
}

bool SqlDb_odbc::existsPartition(const char */*table*/, const char */*partition*/, bool /*useCache*/) {
	// TODO
	return(false);
}

bool SqlDb_odbc::emptyTable(const char *table) {
	return(rowsInTable(table));
}

int64_t SqlDb_odbc::rowsInTable(const char */*table*/) {
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
	
MySqlStore_process::MySqlStore_process(int id, const char *host, const char *user, const char *password, const char *database, u_int16_t port,
				       const char *cloud_host, const char *cloud_token, bool cloud_router,
				       int concatLimit) {
	this->id = id;
	this->terminated = false;
	this->enableTerminatingDirectly = false;
	this->enableTerminatingIfEmpty = false;
	this->enableTerminatingIfSqlError = false;
	this->enableAutoDisconnect = false;
	this->concatLimit = concatLimit;
	this->enableTransaction = false;
	this->enableFixDeadlock = false;
	this->lastQueryTime = 0;
	this->queryCounter = 0;
	this->sqlDb = new FILE_LINE(29003) SqlDb_mysql();
	this->sqlDb->setConnectParameters(host, user, password, database, port);
	if(cloud_host && *cloud_host) {
		this->sqlDb->setCloudParameters(cloud_host, cloud_token, cloud_router);
	}
	pthread_mutex_init(&this->lock_mutex, NULL);
	this->thread = (pthread_t)NULL;
	this->threadRunningCounter = 0;
	this->lastThreadRunningCounterCheck = 0;
	this->lastThreadRunningTimeCheck = 0;
	this->remote_socket = NULL;
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
		cout << "store_process_query_" << this->id << ": " << query_str << endl;
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
				syslog(LOG_NOTICE, "resurrection sql store process %i thread", this->id);
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
		vm_pthread_create_autodestroy(("sql store " + intToString(id)).c_str(),
					      &this->thread, NULL, MySqlStore_process_storing, this, __FILE__, __LINE__);
	}
	this->query_buff.push_back(query_str);
	++queryCounter;
}

void MySqlStore_process::queryByRemoteSocket(const char *query_str) {
	unsigned maxPass = 100000;
	for(unsigned int pass = 0; pass < maxPass; pass++) {
		if(is_terminating() > 1 && pass > 2) {
			break;
		}
		if(pass > 0) {
			if(this->remote_socket) {
				delete this->remote_socket;
				this->remote_socket = NULL;
			}
			if(is_terminating()) {
				usleep(100000);
			} else {
				sleep(1);
			}
			syslog(LOG_INFO, "next attempt %u - query: %s", pass, prepareQueryForPrintf(query_str).c_str());
		}
		if(!this->remote_socket) {
			this->remote_socket = new FILE_LINE(0) cSocketBlock("sql store", true);
			this->remote_socket->setHostPort(snifferClientOptions.host, snifferClientOptions.port);
			if(!this->remote_socket->connect()) {
				syslog(LOG_ERR, "send store query error: %s", "failed connect to cloud router");
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
			if(!this->remote_socket->readBlock(&connectResponse) || connectResponse != "OK") {
				if(!this->remote_socket->isError() && connectResponse != "OK") {
					syslog(LOG_ERR, "send store query error: %s", ("failed response from cloud router - " + connectResponse).c_str());
					delete this->remote_socket;
					this->remote_socket = NULL;
					break;
				} else {
					syslog(LOG_ERR, "send store query error: %s", "failed read ok");
					continue;
				}
			}
		}
		string query_str_with_id = intToString(CONV_ID_FOR_REMOTE_STORE(id)) + '|' + query_str;
		bool okSendQuery = true;
		if(query_str_with_id.length() > 100) {
			cGzip gzipCompressQuery;
			u_char *queryGzip;
			size_t queryGzipLength;
			if(gzipCompressQuery.compressString(query_str_with_id, &queryGzip, &queryGzipLength)) {
				if(!this->remote_socket->writeBlock(queryGzip, queryGzipLength, cSocket::_te_aes)) {
					okSendQuery = false;
				}
				delete [] queryGzip;
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
		string response;
		if(!this->remote_socket->readBlock(&response, cSocket::_te_aes)) {
			syslog(LOG_ERR, "send store query error: %s", "failed read query response");
			continue;
		}
		if(response == "OK") {
			break;
		} else {
			syslog(LOG_ERR, "send store query error: %s", response.empty() ? "response is empty" : ("bad response - " + response).c_str());
		}
	}
}

void MySqlStore_process::store() {
	string beginTransaction = "\nDECLARE EXIT HANDLER FOR SQLEXCEPTION\nBEGIN\nROLLBACK;\nEND;\nSTART TRANSACTION;\n";
	string endTransaction = "\nCOMMIT;\n";
	while(1) {
		int size = 0;
		string queryqueue = "";
		while(1) {
			++this->threadRunningCounter;
			if(snifferClientOptions.isEnableRemoteStore()) {
				this->lock();
				if(this->query_buff.size() == 0) {
					this->unlock();
					break;
				}
				string query = this->query_buff.front();
				this->query_buff.pop_front();
				this->unlock();
				this->queryByRemoteSocket(query.c_str());
			} else {
				string beginProcedure = "\nBEGIN\n" + (opt_mysql_enable_transactions || this->enableTransaction ? beginTransaction : "");
				string endProcedure = (opt_mysql_enable_transactions || this->enableTransaction ? endTransaction : "") + "\nEND";
				this->lock();
				if(this->query_buff.size() == 0) {
					this->unlock();
					if(queryqueue != "") {
						this->_store(beginProcedure, endProcedure, queryqueue);
						lastQueryTime = getTimeS();
						queryqueue = "";
						if(verbosity > 1) {
							syslog(LOG_INFO, "STORE id: %i", this->id);
						}
					}
					break;
				}
				string query = this->query_buff.front();
				bool maxAllowedPacketIsFull = false;
				if(size > 0 && queryqueue.size() + query.size() + 100 > this->sqlDb->maxAllowedPacket) {
					maxAllowedPacketIsFull = true;
					this->unlock();
				} else {
					this->query_buff.pop_front();
					this->unlock();
					queryqueue.append(query);
					size_t query_len = query.length();
					while(query_len && query[query_len - 1] == ' ') {
						--query_len;
					}
					if(!((query_len && query[query_len - 1] == ';') ||
					     (query_len > 1 && query[query_len - 1] == '\n' && query[query_len - 2] == ';'))) {
						queryqueue.append("; ");
					}
				}
				if(size < this->concatLimit && !maxAllowedPacketIsFull) {
					size++;
				} else {
					this->_store(beginProcedure, endProcedure, queryqueue);
					lastQueryTime = getTimeS();
					queryqueue = "";
					size = 0;
					if(verbosity > 1) {
						syslog(LOG_INFO, "STORE id: %i", this->id);
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
		sleep(1);
	}
	this->terminated = true;
	syslog(LOG_NOTICE, "terminated - sql store %u", this->id);
}

void MySqlStore_process::_store(string beginProcedure, string endProcedure, string queries) {
	if(opt_nocdr) {
		return;
	}
	string procedureName = this->getInsertFuncName();
	int maxPassComplete = this->enableFixDeadlock ? 10 : 1;
	for(int passComplete = 0; passComplete < maxPassComplete; passComplete++) {
		string dropProcQuery = string("drop procedure if exists ") + procedureName;
		this->sqlDb->query(dropProcQuery.c_str());
		string preparedQueries = queries;
		::prepareQuery(this->sqlDb->getSubtypeDb(), preparedQueries, false, passComplete ? 2 : 1);
		if(!this->sqlDb->query(string("create procedure ") + procedureName + "()" + 
				       beginProcedure + 
				       preparedQueries + 
				       endProcedure,
				       false,
				       dropProcQuery.c_str())) {
			if(sverb.store_process_query) {
				cout << "store_process_query_" << this->id << ": " << "ERROR " << this->sqlDb->getLastErrorString() << endl;
			}
		}
		bool rsltQuery = this->sqlDb->query(string("call ") + procedureName + "();", this->enableFixDeadlock);
		/* deadlock debugging
		rsltQuery = false;
		this->sqlDb->setLastError(ER_LOCK_DEADLOCK, "deadlock");
		*/
		if(rsltQuery) {
			break;
		} else if(this->sqlDb->getLastError() == ER_LOCK_DEADLOCK) {
			if(passComplete < maxPassComplete - 1) {
				syslog(LOG_INFO, "DEADLOCK in store %u - next attempt %u", this->id, passComplete + 1);
				usleep(500000);
			}
		} else {
			if(sverb.store_process_query) {
				cout << "store_process_query_" << this->id << ": " << "ERROR " << this->sqlDb->getLastErrorString() << endl;
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
			fprintf(file, "%i:%s\n", this->id, query.c_str());
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

void MySqlStore_process::lock() {
	pthread_mutex_lock(&this->lock_mutex);
}

void MySqlStore_process::unlock() {
	pthread_mutex_unlock(&this->lock_mutex);
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

void MySqlStore_process::waitForTerminate() {
	if(this->thread) {
		while(!this->terminated) {
			if(is_terminating() > 1 &&
			   getTimeS() > (this->last_store_iteration_time + 60)) {
				syslog(LOG_NOTICE, "cancel store thread id (%i)", id);
				pthread_cancel(this->thread);
				break;
			}
			usleep(100000);
		}
		this->thread = (pthread_t)NULL;
	}
}

string MySqlStore_process::getInsertFuncName() {
	char insert_funcname[20];
	snprintf(insert_funcname, sizeof(insert_funcname), "__insert_%i", this->id);
	if(opt_id_sensor > -1) {
		snprintf(insert_funcname + strlen(insert_funcname), sizeof(insert_funcname) - strlen(insert_funcname), "S%i", opt_id_sensor);
	}
	return(insert_funcname);
}

string MySqlStore::QFileConfig::getDirectory() {
	return(this->directory.empty() ? getQueryCacheDir() : this->directory);
}

MySqlStore::MySqlStore(const char *host, const char *user, const char *password, const char *database, u_int16_t port,
		       const char *cloud_host, const char *cloud_token, bool cloud_router) {
	this->host = host;
	this->user = user;
	this->password = password;
	this->database = database;
	this->port = port;
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
	map<int, MySqlStore_process*>::iterator iter;
	for(iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
		iter->second->setEnableTerminatingIfEmpty(true);
		iter->second->waitForTerminate();
	}
	if(!qfileConfig.enable && !loadFromQFileConfig.enable) {
		extern bool opt_autoload_from_sqlvmexport;
		if(opt_autoload_from_sqlvmexport &&
		   this->getAllSize() &&
		   !opt_read_from_file && !opt_pb_read_from_file[0]) {
			extern MySqlStore *sqlStore;
			sqlStore->exportToFile(NULL, "auto", false, true);
		}
	}
	for(iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
		delete iter->second;
	}
	if(qfileConfig.enable) {
		if(this->qfilesCheckperiodThread) {
			pthread_join(this->qfilesCheckperiodThread, NULL);
		}
		closeAllQFiles();
		clearAllQFiles();
	}
	if(loadFromQFileConfig.enable) {
		for(map<int, LoadFromQFilesThreadData>::iterator iter = loadFromQFilesThreadData.begin(); iter != loadFromQFilesThreadData.end(); iter++) {
			pthread_join(iter->second.thread, NULL);
		}
	}
}

void MySqlStore::queryToFiles(bool enable, const char *directory, int period) {
	qfileConfig.enable = enable;
	if(directory) {
		qfileConfig.directory = directory;
	}
	if(period) {
		qfileConfig.period = period;
	}
}

void MySqlStore::queryToFilesTerminate() {
	if(qfileConfig.enable) {
		qfileConfig.terminate = true;
		usleep(250000);
		closeAllQFiles();
		clearAllQFiles();
	}
}

void MySqlStore::queryToFiles_start() {
	if(qfileConfig.enable) {
		vm_pthread_create("query cache - check",
				  &this->qfilesCheckperiodThread, NULL, this->threadQFilesCheckPeriod, this, __FILE__, __LINE__);
	}
}

void MySqlStore::loadFromQFiles(bool enable, const char *directory, int period) {
	loadFromQFileConfig.enable = enable;
	if(directory) {
		loadFromQFileConfig.directory = directory;
	}
	if(period) {
		loadFromQFileConfig.period = period;
	}
}

void MySqlStore::loadFromQFiles_start() {
	if(loadFromQFileConfig.enable) {
		extern bool opt_load_query_from_files_inotify;
		if(opt_load_query_from_files_inotify) {
			this->enableInotifyForLoadFromQFile();
		}
		if(!isCloud()) {
			extern MySqlStore *sqlStore_2;
			this->addLoadFromQFile((STORE_PROC_ID_CDR_1 / 10) * 10, "cdr");
			this->addLoadFromQFile((STORE_PROC_ID_MESSAGE_1 / 10) * 10, "message");
			this->addLoadFromQFile((STORE_PROC_ID_CLEANSPOOL / 10) * 10, "cleanspool");
			this->addLoadFromQFile((STORE_PROC_ID_REGISTER_1 / 10) * 10, "register");
			this->addLoadFromQFile((STORE_PROC_ID_SAVE_PACKET_SQL / 10) * 10, "save_packet_sql");
			this->addLoadFromQFile((STORE_PROC_ID_HTTP_1 / 10) * 10, "http", 0, 0,
					       use_mysql_2_http() ? sqlStore_2 : NULL);
			this->addLoadFromQFile((STORE_PROC_ID_WEBRTC_1 / 10) * 10, "webrtc");
			this->addLoadFromQFile(STORE_PROC_ID_CACHE_NUMBERS_LOCATIONS, "cache_numbers");
			this->addLoadFromQFile(STORE_PROC_ID_FRAUD_ALERT_INFO, "fraud_alert_info");
			this->addLoadFromQFile(STORE_PROC_ID_LOG_SENSOR, "log_sensor");
			if(opt_ipaccount) {
				this->addLoadFromQFile((STORE_PROC_ID_IPACC_1 / 10) * 10, "ipacc");
				this->addLoadFromQFile((STORE_PROC_ID_IPACC_AGR_INTERVAL / 10) * 10, "ipacc_agreg");
				this->addLoadFromQFile((STORE_PROC_ID_IPACC_AGR2_HOUR_1 / 10) * 10, "ipacc_agreg2");
			}
		} else {
			extern int opt_mysqlstore_concat_limit_cdr;
			this->addLoadFromQFile(1, "cloud", 1, opt_mysqlstore_concat_limit_cdr);
		}
		if(opt_load_query_from_files_inotify) {
			this->setInotifyReadyForLoadFromQFile();
		}
	}
}

void MySqlStore::connect(int id) {
	if(qfileConfig.enable) {
		return;
	}
	MySqlStore_process* process = this->find(id);
	process->connect();
}

void MySqlStore::query(const char *query_str, int id) {
	if(!query_str || !*query_str) {
		return;
	}
	if(qfileConfig.enable) {
		query_to_file(query_str, id);
	} else {
		MySqlStore_process* process = this->find(id);
		process->query(query_str);
	}
}

void MySqlStore::query(string query_str, int id) {
	query(query_str.c_str(), id);
}

void MySqlStore::query_lock(const char *query_str, int id) {
	if(!query_str || !*query_str) {
		return;
	}
	if(qfileConfig.enable) {
		query_to_file(query_str, id);
	} else {
		MySqlStore_process* process = this->find(id);
		process->lock();
		process->query(query_str);
		process->unlock();
	}
}

void MySqlStore::query_lock(string query_str, int id) {
	query_lock(query_str.c_str(), id);
}

void MySqlStore::query_to_file(const char *query_str, int id) {
	if(qfileConfig.terminate) {
		return;
	}
	int idc = !isCloud() ? convIdForQFile(id) : 1;
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
	if(qfile->isOpen() &&
	   qfile->isExceedPeriod(qfileConfig.period)) {
		if(sverb.qfiles) {
			cout << "*** CLOSE QFILE " << qfile->filename 
			     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
		}
		qfile->close();
	}
	if(!qfile->isOpen()) {
		u_long actTime = getTimeMS();
		string qfilename = getQFilename(idc, actTime);
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
		snprintf(buffIdLength, sizeof(buffIdLength), "%i/%u:", id, query_length);
		qfile->fileZipHandler->write(buffIdLength, strlen(buffIdLength));
		qfile->fileZipHandler->write((char*)query.c_str(), query.length());
		u_long actTimeMS = getTimeMS();
		if(max(qfile->flushAt, qfile->createAt) < actTimeMS - 1000) {
			qfile->fileZipHandler->flushBuffer();
			qfile->flushAt = actTimeMS;
		}
	}
	qfile->unlock();
}

string MySqlStore::getQFilename(int idc, u_long actTime) {
	char fileName[100];
	string dateTime = sqlDateTimeString(actTime / 1000).c_str();
	find_and_replace(dateTime, " ", "T");
	snprintf(fileName, sizeof(fileName), "%s-%i-%lu-%s", QFILE_PREFIX, idc, actTime, dateTime.c_str());
	return(qfileConfig.getDirectory() + "/" + fileName);
}

int MySqlStore::convIdForQFile(int id) {
	return(CONV_ID_FOR_QFILE(id));
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
	if(loadFromQFileConfig.enable && loadFromQFileConfig.inotify) {
		vm_pthread_create("query cache - inotify",
				  &this->qfilesINotifyThread, NULL, this->threadINotifyQFiles, this, __FILE__, __LINE__);
	}
#endif
}

void MySqlStore::setInotifyReadyForLoadFromQFile(bool iNotifyReady) {
	if(loadFromQFileConfig.enable && loadFromQFileConfig.inotify) {
		loadFromQFileConfig.inotify_ready = iNotifyReady;
	}
}

void MySqlStore::addLoadFromQFile(int id, const char *name, 
				  int storeThreads, int storeConcatLimit,
				  MySqlStore *store) {
	LoadFromQFilesThreadData threadData;
	threadData.id = id;
	threadData.name = name;
	threadData.storeThreads = storeThreads > 0 ? storeThreads : getMaxThreadsForStoreId(id);
	threadData.storeConcatLimit = storeConcatLimit > 0 ? storeConcatLimit : getConcatLimitForStoreId(id);
	threadData.store = store;
	loadFromQFilesThreadData[id] = threadData;
	LoadFromQFilesThreadInfo *threadInfo = new FILE_LINE(29005) LoadFromQFilesThreadInfo;
	threadInfo->store = this;
	threadInfo->id = id;
	vm_pthread_create("query cache - load",
			  &loadFromQFilesThreadData[id].thread, NULL, this->threadLoadFromQFiles, threadInfo, __FILE__, __LINE__);
}

bool MySqlStore::fillQFiles(int id) {
	DIR* dp = opendir(loadFromQFileConfig.getDirectory().c_str());
	if(!dp) {
		return(false);
	}
	char prefix[10];
	snprintf(prefix, sizeof(prefix), "%s-%i-", QFILE_PREFIX, id);
	dirent* de;
	while((de = readdir(dp)) != NULL) {
		if(strncmp(de->d_name, prefix, strlen(prefix))) continue;
		QFileData qfileData = parseQFilename(de->d_name);
		if(qfileData.id) {
			loadFromQFilesThreadData[qfileData.id].addFile(qfileData.time, de->d_name);
		}
	}
	closedir(dp);
	return(true);
}

string MySqlStore::getMinQFile(int id) {
	if(loadFromQFileConfig.inotify) {
		string qfilename;
		loadFromQFilesThreadData[id].lock();
		map<u_long, string>::iterator iter = loadFromQFilesThreadData[id].qfiles_load.begin();
		if(iter != loadFromQFilesThreadData[id].qfiles_load.end() &&
		   (getTimeMS() - iter->first) > (unsigned)loadFromQFileConfig.period * 2 * 1000) {
			qfilename = iter->second;
			loadFromQFilesThreadData[id].qfiles_load.erase(iter);
		}
		loadFromQFilesThreadData[id].unlock();
		if(!qfilename.empty()) {
			return(loadFromQFileConfig.getDirectory() + "/" + qfilename);
		}
	} else {
		DIR* dp = opendir(loadFromQFileConfig.getDirectory().c_str());
		if(!dp) {
			return("");
		}
		u_long minTime = 0;
		string minTimeFileName;
		char prefix[10];
		snprintf(prefix, sizeof(prefix), "%s-%i-", QFILE_PREFIX, id);
		dirent* de;
		while((de = readdir(dp)) != NULL) {
			if(strncmp(de->d_name, prefix, strlen(prefix))) continue;
			u_long time = atoll(de->d_name + strlen(prefix));
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

int MySqlStore::getCountQFiles(int id) {
	DIR* dp = opendir(loadFromQFileConfig.getDirectory().c_str());
	if(!dp) {
		return(-1);
	}
	char prefix[10];
	snprintf(prefix, sizeof(prefix), "%s-%i-", QFILE_PREFIX, id);
	dirent* de;
	int counter = 0;
	while((de = readdir(dp)) != NULL) {
		if(strncmp(de->d_name, prefix, strlen(prefix))) continue;
		++counter;
	}
	closedir(dp);
	return(counter);
}

bool MySqlStore::loadFromQFile(const char *filename, int id, bool onlyCheck) {
	bool ok = true;
	if(sverb.qfiles) {
		cout << "*** START " << (onlyCheck ? "CHECK" : "PROCESS") << " FILE " << filename
		     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
	}
	FileZipHandler *fileZipHandler = new FILE_LINE(29006) FileZipHandler(8 * 1024, 0, isGunzip(filename) ? FileZipHandler::gzip : FileZipHandler::compress_na);
	fileZipHandler->open(tsf_na, filename);
	unsigned int counter = 0;
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
				syslog(LOG_ERR, "bad string in qfile %s: %s", filename, buffLineQuery);
				ok = false;
				continue;
			}
			if(queryLength != strlen(posSeparator + 1)) {
				syslog(LOG_ERR, "bad query length in qfile %s: %s", filename, buffLineQuery);
				if(sverb.qfiles && !copyBadFileToTemp) {
					char *baseFileName = (char*)strrchr(filename, '/');
					copy_file(filename, (string("/tmp") + baseFileName).c_str());
					copyBadFileToTemp = true;
				}
				ok = false;
				continue;
			}
			if(!onlyCheck) {
				string query = find_and_replace(posSeparator + 1, "__ENDL__", "\n");
				int queryThreadId = id;
				ssize_t queryThreadMinSize = -1;
				for(int qtid = id; qtid < (id + loadFromQFilesThreadData[id].storeThreads); qtid++) {
					int qtSize = this->getSize(qtid);
					if(qtSize < 0) {
						qtSize = 0;
					}
					if(queryThreadMinSize == -1 ||
					   qtSize < queryThreadMinSize) {
						queryThreadId = qtid;
						queryThreadMinSize = qtSize;
					}
				}
				if(!check(queryThreadId)) {
					find(queryThreadId, loadFromQFilesThreadData[id].store);
					setEnableTerminatingIfEmpty(queryThreadId, true);
					setEnableTerminatingIfSqlError(queryThreadId, true);
					if(loadFromQFilesThreadData[id].storeConcatLimit) {
						setConcatLimit(queryThreadId, loadFromQFilesThreadData[id].storeConcatLimit);
					}
				}
				/*if(sverb.qfiles) {
					cout << " ** send query id: " << id << " to thread: " << queryThreadId << " / " << getSize(queryThreadId) << endl;
				}*/
				extern int opt_query_cache_check_utf;
				if(opt_query_cache_check_utf) {
					extern cUtfConverter utfConverter;
					if(!utfConverter.check(query.c_str())) {
						utfConverter._remove_no_ascii(query.c_str());
					}
				}
				query_lock(query.c_str(), queryThreadId);
			}
			++counter;
		}
	}
	if(!fileZipHandler->is_ok_decompress()) {
		syslog(LOG_ERR, "decompress error in qfile %s", filename);
	}
	fileZipHandler->close();
	delete fileZipHandler;
	if(!onlyCheck) {
		unlink(filename);
	}
	if(sverb.qfiles) {
		cout << "*** END " << (onlyCheck ? "CHECK" : "PROCESS") << " FILE " << filename
		     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
	}
	return(ok);
}

void MySqlStore::addFileFromINotify(const char *filename) {
	while(!loadFromQFileConfig.inotify_ready) {
		usleep(100000);
	}
	QFileData qfileData = parseQFilename(filename);
	if(qfileData.id) {
		if(sverb.qfiles) {
			cout << "*** INOTIFY QFILE " << filename 
			     << " - time: " << sqlDateTimeString(time(NULL)) << endl;
		}
		loadFromQFilesThreadData[qfileData.id].addFile(qfileData.time, qfileData.filename.c_str());
	}
}

MySqlStore::QFileData MySqlStore::parseQFilename(const char *filename) {
	QFileData qfileData;
	qfileData.id = 0;
	qfileData.time = 0;
	if(!strncmp(filename, QFILE_PREFIX, strlen(QFILE_PREFIX))) {
		int id;
		u_long time;
		if(sscanf(filename + strlen(QFILE_PREFIX) , "-%i-%lu", &id, &time) == 2) {
			qfileData.filename = filename;
			qfileData.id = id;
			qfileData.time = time;;
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
			int countQFiles = getCountQFiles(iter->second.id);
			if(countQFiles > 0) {
				if(counter) {
					outStr << ", ";
				}
				outStr << iter->second.name << ": " << countQFiles;
				++counter;
			}
		}
	} else {
		for(map<int, MySqlStore_process*>::iterator iter = this->processes.begin(); iter != this->processes.end(); iter++) {
			size_t size = iter->second->getSize();
			if(size > 0) {
				if(counter) {
					outStr << ",";
				}
				outStr << iter->first << ":" << size;
				++counter;
			}
		}
	}
	return(outStr.str());
}

unsigned MySqlStore::getLoadFromQFilesCount() {
	unsigned count = 0;
	for(map<int, LoadFromQFilesThreadData>::iterator iter = loadFromQFilesThreadData.begin(); iter != loadFromQFilesThreadData.end(); iter++) {
		count += getCountQFiles(iter->second.id);
	}
	return(count);
}

void MySqlStore::lock(int id) {
	if(qfileConfig.enable) {
		return;
	}
	MySqlStore_process* process = this->find(id);
	process->lock();
}

void MySqlStore::unlock(int id) {
	if(qfileConfig.enable) {
		return;
	}
	MySqlStore_process* process = this->find(id);
	process->unlock();
}

void MySqlStore::setEnableTerminatingDirectly(int id, bool enableTerminatingDirectly) {
	if(qfileConfig.enable) {
		return;
	}
	if(id > 0) {
		MySqlStore_process* process = this->find(id);
		process->setEnableTerminatingDirectly(enableTerminatingDirectly);
	} else {
		this->lock_processes();
		for(map<int, MySqlStore_process*>::iterator iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
			iter->second->setEnableTerminatingDirectly(enableTerminatingDirectly);
		}
		this->unlock_processes();
	}
}

void MySqlStore::setEnableTerminatingIfEmpty(int id, bool enableTerminatingIfEmpty) {
	if(qfileConfig.enable) {
		return;
	}
	if(id > 0) {
		MySqlStore_process* process = this->find(id);
		process->setEnableTerminatingIfEmpty(enableTerminatingIfEmpty);
	} else {
		this->lock_processes();
		for(map<int, MySqlStore_process*>::iterator iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
			iter->second->setEnableTerminatingIfEmpty(enableTerminatingIfEmpty);
		}
		this->unlock_processes();
	}
}

void MySqlStore::setEnableTerminatingIfSqlError(int id, bool enableTerminatingIfSqlError) {
	if(qfileConfig.enable) {
		return;
	}
	if(id > 0) {
		MySqlStore_process* process = this->find(id);
		process->setEnableTerminatingIfEmpty(enableTerminatingIfSqlError);
	} else {
		this->lock_processes();
		for(map<int, MySqlStore_process*>::iterator iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
			iter->second->setEnableTerminatingIfEmpty(enableTerminatingIfSqlError);
		}
		this->unlock_processes();
	}
}

void MySqlStore::setEnableAutoDisconnect(int id, bool enableAutoDisconnect) {
	if(qfileConfig.enable) {
		return;
	}
	MySqlStore_process* process = this->find(id);
	process->setEnableAutoDisconnect(enableAutoDisconnect);
}

void MySqlStore::setConcatLimit(int id, int concatLimit) {
	if(qfileConfig.enable) {
		return;
	}
	MySqlStore_process* process = this->find(id);
	process->setConcatLimit(concatLimit);
}

int MySqlStore::getConcatLimit(int id) {
	MySqlStore_process* process = this->find(id);
	return(process->getConcatLimit());
}

void MySqlStore::setEnableTransaction(int id, bool enableTransaction) {
	if(qfileConfig.enable) {
		return;
	}
	MySqlStore_process* process = this->find(id);
	process->setEnableTransaction(enableTransaction);
}

void MySqlStore::setEnableFixDeadlock(int id, bool enableFixDeadlock) {
	if(qfileConfig.enable) {
		return;
	}
	MySqlStore_process* process = this->find(id);
	process->setEnableFixDeadlock(enableFixDeadlock);
}

void MySqlStore::setDefaultConcatLimit(int defaultConcatLimit) {
	this->defaultConcatLimit = defaultConcatLimit;
}

MySqlStore_process *MySqlStore::find(int id, MySqlStore *store) {
	if(isCloud()) {
		id = 1;
	}
	this->lock_processes();
	MySqlStore_process* process = this->processes[id];
	if(process) {
		this->unlock_processes();
		return(process);
	}
	process = new FILE_LINE(29007) MySqlStore_process(id, 
						   store ? store->host.c_str() : this->host.c_str(), 
						   store ? store->user.c_str() : this->user.c_str(), 
						   store ? store->password.c_str() : this->password.c_str(), 
						   store ? store->database.c_str() : this->database.c_str(),
						   store ? store->port : this->port,
						   this->isCloud() ? this->cloud_host.c_str() : NULL, this->cloud_token.c_str(), this->cloud_router,
						   this->defaultConcatLimit);
	process->setEnableTerminatingDirectly(this->enableTerminatingDirectly);
	process->setEnableTerminatingIfEmpty(this->enableTerminatingIfEmpty);
	process->setEnableTerminatingIfSqlError(this->enableTerminatingIfSqlError);
	this->processes[id] = process;
	this->unlock_processes();
	return(process);
}

MySqlStore_process *MySqlStore::check(int id) {
	if(isCloud()) {
		id = 1;
	}
	this->lock_processes();
	map<int, MySqlStore_process*>::iterator iter = this->processes.find(id);
	if(iter == this->processes.end()) {
		this->unlock_processes();
		return(NULL);
	} else {
		MySqlStore_process* process = iter->second;
		this->unlock_processes();
		return(process);
	}
}

size_t MySqlStore::getAllSize(bool lock) {
	size_t size = 0;
	map<int, MySqlStore_process*>::iterator iter;
	this->lock_processes();
	for(iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
		if(lock) {
			iter->second->lock();
		}
		size += iter->second->getSize();
		if(lock) {
			iter->second->unlock();
		}
	}
	this->unlock_processes();
	return(size);
}

int MySqlStore::getSize(int id, bool lock) {
	MySqlStore_process *process = this->check(id);
	if(process) {
		if(lock) {
			process->lock();
		}
		int size = process->getSize();
		if(lock) {
			process->unlock();
		}
		return(size);
	} else {
		return(-1);
	}
}

int MySqlStore::getSizeMult(int n, ...) {
	int size = -1;
	va_list vl;
	va_start(vl, n);
	for(int i = 0; i < n; i++) {
		int id = va_arg(vl, int);
		int _size = this->getSize(id);
		if(_size >= 0) {
			if(size < 0) {
				size = 0;
			}
			size += _size;
		}
	}
	va_end(vl);
	return(size);
}

int MySqlStore::getSizeVect(int id1, int id2, bool /*lock*/) {
	int size = -1;
	for(int id = id1; id <= id2; id++) {
		int _size = this->getSize(id);
		if(_size >= 0) {
			if(size < 0) {
				size = 0;
			}
			size += _size;
		}
	}
	return(size);
}

int MySqlStore::getActiveIdsVect(int id1, int id2, bool /*lock*/) {
	int activeIds  = 0;
	for(int id = id1; id <= id2; id++) {
		int _size = this->getSize(id);
		if(_size > 0) {
			++activeIds;
		}
	}
	return(activeIds);
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
	map<int, MySqlStore_process*>::iterator iter;
	for(iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
		iter->second->exportToFile(file, sqlFormat, cleanAfterExport);
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
				this->query(query.c_str(), idProcess);
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

int MySqlStore::convStoreId(int id) {
	int threadId = id + (id % 10 ? 0 : 1);
	int maxThreads = getMaxThreadsForStoreId(id);
	if(maxThreads > 1) {
		ssize_t queryThreadMinSize = -1;
		for(int i = 0; i < maxThreads; i++) {
			int qtSize = this->getSize(id + i);
			if(qtSize < 0) {
				qtSize = 0;
			}
			if(queryThreadMinSize == -1 || qtSize < queryThreadMinSize) {
				threadId = id  + i + 1;
				queryThreadMinSize = qtSize;
			}
		}
	}
	return(threadId);
}

int MySqlStore::getMaxThreadsForStoreId(int id) {
	extern int opt_mysqlstore_max_threads_cdr;
	extern int opt_mysqlstore_max_threads_message;
	extern int opt_mysqlstore_max_threads_register;
	extern int opt_mysqlstore_max_threads_http;
	extern int opt_mysqlstore_max_threads_webrtc;
	extern int opt_mysqlstore_max_threads_ipacc_base;
	extern int opt_mysqlstore_max_threads_ipacc_agreg2;
	int maxThreads = 1;
	switch((id / 10) * 10) {
	case (STORE_PROC_ID_CDR_1 / 10) * 10:
		maxThreads = opt_mysqlstore_max_threads_cdr;
		break;
	case (STORE_PROC_ID_MESSAGE_1 / 10) * 10:
		maxThreads = opt_mysqlstore_max_threads_message;
		break;
	case (STORE_PROC_ID_REGISTER_1 / 10) * 10:
		maxThreads = opt_mysqlstore_max_threads_register;
		break;
	case (STORE_PROC_ID_HTTP_1 / 10) * 10:
		maxThreads = opt_mysqlstore_max_threads_http;
		break;
	case (STORE_PROC_ID_WEBRTC_1 / 10) * 10:
		maxThreads = opt_mysqlstore_max_threads_webrtc;
		break;
	case (STORE_PROC_ID_IPACC_1 / 10) * 10:
		maxThreads = opt_mysqlstore_max_threads_ipacc_base;
		break;
	case (STORE_PROC_ID_IPACC_AGR_INTERVAL / 10) * 10:
	case (STORE_PROC_ID_IPACC_AGR2_HOUR_1 / 10) * 10:
		maxThreads = opt_mysqlstore_max_threads_ipacc_agreg2;
		break;
	}
	return(maxThreads);
}

int MySqlStore::getConcatLimitForStoreId(int id) {
	extern int opt_mysqlstore_concat_limit_cdr;;
	extern int opt_mysqlstore_concat_limit_message;
	extern int opt_mysqlstore_concat_limit_register;
	extern int opt_mysqlstore_concat_limit_http;
	extern int opt_mysqlstore_concat_limit_webrtc;
	extern int opt_mysqlstore_concat_limit_ipacc;
	int concatLimit = 0;
	switch((id / 10) * 10) {
	case (STORE_PROC_ID_CDR_1 / 10) * 10:
		concatLimit = opt_mysqlstore_concat_limit_cdr;
		break;
	case (STORE_PROC_ID_MESSAGE_1 / 10) * 10:
		concatLimit = opt_mysqlstore_concat_limit_message;
		break;
	case (STORE_PROC_ID_REGISTER_1 / 10) * 10:
		concatLimit = opt_mysqlstore_concat_limit_register;
		break;
	case (STORE_PROC_ID_HTTP_1 / 10) * 10:
		concatLimit = opt_mysqlstore_concat_limit_http;
		break;
	case (STORE_PROC_ID_WEBRTC_1 / 10) * 10:
		concatLimit = opt_mysqlstore_concat_limit_webrtc;
		break;
	case (STORE_PROC_ID_IPACC_1 / 10) * 10:
	case (STORE_PROC_ID_IPACC_AGR_INTERVAL / 10) * 10:
	case (STORE_PROC_ID_IPACC_AGR2_HOUR_1 / 10) * 10:
		concatLimit = opt_mysqlstore_concat_limit_ipacc;
		break;
	}
	return(concatLimit);
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
		usleep(250000);
	}
	return(NULL);
}

void *MySqlStore::threadLoadFromQFiles(void *arg) {
	LoadFromQFilesThreadInfo *threadInfo = (LoadFromQFilesThreadInfo*)arg;
	int id = threadInfo->id;
	MySqlStore *me = threadInfo->store;
	delete threadInfo;
	if(me->loadFromQFileConfig.inotify) {
		me->fillQFiles(id);
	}
	while(!is_terminating()) {
		extern int opt_blockqfile;
		if(opt_blockqfile) {
			sleep(1);
			continue;
		}
		string minFile = me->getMinQFile(id);
		if(minFile.empty()) {
			usleep(250000);
		} else {
			extern int opt_query_cache_speed;
			while((me->isCloud() ?
				(me->getSize(id) > me->getConcatLimit(id)) :
			       opt_query_cache_speed ? 
			        (me->getActiveIdsVect(id, id + me->loadFromQFilesThreadData[id].storeThreads - 1) == me->loadFromQFilesThreadData[id].storeThreads) :
			        (me->getSizeVect(id, id + me->loadFromQFilesThreadData[id].storeThreads - 1) > 0)) && 
			      !is_terminating()) {
				usleep(100000);
			}
			if(!is_terminating()) {
				if(me->existFilenameInQFiles(minFile.c_str()) ||
				   !me->loadFromQFile(minFile.c_str(), id)) {
					usleep(250000);
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
	const char *directory = me->loadFromQFileConfig.getDirectory().c_str();
	int watchDescriptor = inotify_add_watch(inotifyDescriptor, directory, IN_CLOSE_WRITE);
	if(watchDescriptor < 0) {
		syslog(LOG_ERR, "inotify watch %s failed", directory);
		close(inotifyDescriptor);
		me->loadFromQFileConfig.inotify = false;
		return(NULL);
	}
	unsigned watchBuffMaxLen = 1024 * 20;
	char *watchBuff =  new FILE_LINE(29009) char[watchBuffMaxLen];
	while(!is_terminating()) {
		ssize_t watchBuffLen = read(inotifyDescriptor, watchBuff, watchBuffMaxLen);
		if(watchBuffLen == watchBuffMaxLen) {
			syslog(LOG_NOTICE, "qfiles inotify events filled whole buffer");
		}
		unsigned i = 0;
		while(i < watchBuffLen && !is_terminating()) {
			inotify_event *event = (inotify_event*)(watchBuff + i);
			i += sizeof(inotify_event) + event->len;
			if(event->mask & IN_CLOSE_WRITE) {
				me->addFileFromINotify(event->name);
			}
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
			sqlDb->setConnectParameters(mysql_2_host, mysql_2_user, mysql_2_password, mysql_2_database, opt_mysql_2_port);
		} else {
			sqlDb->setConnectParameters(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port);
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

string sqlDateTimeString(time_t unixTime) {
	struct tm localTime = time_r(&unixTime);
	char dateTimeBuffer[50];
	strftime(dateTimeBuffer, sizeof(dateTimeBuffer), "%Y-%m-%d %H:%M:%S", &localTime);
	return string(dateTimeBuffer);
}

string sqlDateString(time_t unixTime) {
	struct tm localTime = time_r(&unixTime);
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

string sqlEscapeString(string inputStr, const char *typeDb, SqlDb_mysql *sqlDbMysql) {
	return sqlEscapeString(inputStr.c_str(), 0, typeDb, sqlDbMysql);
}

SqlDb_mysql *sqlDbEscape = NULL; 

string sqlEscapeString(const char *inputStr, int length, const char *typeDb, SqlDb_mysql *sqlDbMysql) {
	if(!length) {
		length = strlen(inputStr);
	}
	/* disabled - use only offline varint - online variant can cause problems in connect to db
	if(isTypeDb("mysql", sqlDbMysql ? sqlDbMysql->getTypeDb().c_str() : typeDb) && !isCloud()) {
		bool okEscape = false;
		int sizeBuffer = length * 2 + 10;
		char *buffer = new FILE_LINE(29012) char[sizeBuffer];
		if(sqlDbMysql && sqlDbMysql->getH_Mysql()) {
			if(mysql_real_escape_string(sqlDbMysql->getH_Mysql(), buffer, inputStr, length) >= 0) {
				okEscape = true;
			}
		} else {
			if(!sqlDbEscape) {
				sqlDbEscape = (SqlDb_mysql*)createSqlObject();
				sqlDbEscape->connect();
			}
			if(sqlDbEscape->connected() &&
			   mysql_real_escape_string(sqlDbEscape->getH_Mysql(), buffer, inputStr, length) >= 0) {
				okEscape = true;
			}
		}
		string rslt = buffer;
		delete [] buffer;
		if(okEscape) {
			return(rslt);
		}
	}
	*/
	return _sqlEscapeString(inputStr, length, sqlDbMysql ? sqlDbMysql->getTypeDb().c_str() : typeDb);
}

struct escChar {
	char ch;
	char escCh;
};
static escChar escCharsMysql[] = {
	{ '\'', '\'' },
	{ '"' , '"' },
	{ '\\', '\\' },
	{ '\n', '\n' },		// new line feed
	{ '\r', '\r' },		// cariage return
	// remove after create function test_escape
	//{ '\t', '\t' }, 	// tab
	//{ '\v', '\v' }, 	// vertical tab
	//{ '\b', '\b' }, 	// backspace
	//{ '\f', '\f' }, 	// form feed
	//{ '\a', '\a' }, 	// alert (bell)
	//{ '\e', 0 }, 		// escape
	// add after create function test_escape
	{    0, '0' },
	{   26, 'Z' }
};
static unsigned char escTableMysql[256][2];
static escChar escCharsOdbc[] = { 
	{ '\'', 2 },
	{ '\v', 0 }, 		// vertical tab
	{ '\b', 0 }, 		// backspace
	{ '\f', 0 }, 		// form feed
	{ '\a', 0 }, 		// alert (bell)
	{ '\e', 0 }, 		// escape
};
static unsigned char escTableOdbc[256][2];

void fillEscTables() {
	for(unsigned i = 0; i < sizeof(escCharsMysql) / sizeof(escCharsMysql[0]); i++) {
		escTableMysql[(unsigned char)escCharsMysql[i].ch][0] = 1;
		escTableMysql[(unsigned char)escCharsMysql[i].ch][1] = (unsigned char)escCharsMysql[i].escCh;
	}
	for(unsigned i = 0; i < sizeof(escCharsOdbc) / sizeof(escCharsOdbc[0]); i++) {
		escTableOdbc[(unsigned char)escCharsOdbc[i].ch][0] = 1;
		escTableOdbc[(unsigned char)escCharsOdbc[i].ch][1] = (unsigned char)escCharsOdbc[i].escCh;
	}
}

string _sqlEscapeString(const char *inputStr, int length, const char *typeDb) {
	bool mysql = false;
	unsigned char (*escTable)[2] = NULL;
	if(!typeDb || isTypeDb("mysql", typeDb)) {
		mysql = true;
		escTable = escTableMysql;
	} else if(isTypeDb("odbc", typeDb)) {
		escTable = escTableOdbc;
	}
	if(!length) {
		length = strlen(inputStr);
	}
	if(!escTable) {
		return(string(inputStr, length));
	}
	string rsltString;
	for(int posInputString = 0; posInputString < length; posInputString++) {
		if(escTable[(unsigned char)inputStr[posInputString]][0]) {
			if(mysql) {
				if(escTable[(unsigned char)inputStr[posInputString]][1]) {
					rsltString += '\\';
					rsltString += (char)escTable[(unsigned char)inputStr[posInputString]][1];
				}
			} else {
				if(escTable[(unsigned char)inputStr[posInputString]][1] == 2) {
					rsltString += inputStr[posInputString];
					rsltString += inputStr[posInputString];
				}
			}
		} else {
			rsltString += inputStr[posInputString];
		}
	}
	extern cUtfConverter utfConverter;
	if(!utfConverter.check(rsltString.c_str())) {
		rsltString = utfConverter.remove_no_ascii(rsltString.c_str());
	}
	return(rsltString);
}

void _sqlEscapeString(const char *inputStr, int length, char *outputStr, const char *typeDb, bool checkUtf) {
	bool mysql = false;
	unsigned char (*escTable)[2] = NULL;
	if(!typeDb || isTypeDb("mysql", typeDb)) {
		mysql = true;
		escTable = escTableMysql;
	} else if(isTypeDb("odbc", typeDb)) {
		escTable = escTableOdbc;
	}
	if(!length) {
		length = strlen(inputStr);
	}
	if(!escTable) {
		strncpy(outputStr, inputStr, length);
		outputStr[length] = 0;
		return;
	}
	unsigned posOutputString = 0;
	for(int posInputString = 0; posInputString < length; posInputString++) {
		if(escTable[(unsigned char)inputStr[posInputString]][0]) {
			if(mysql) {
				if(escTable[(unsigned char)inputStr[posInputString]][1]) {
					outputStr[posOutputString++] = '\\';
					outputStr[posOutputString++] = (char)escTable[(unsigned char)inputStr[posInputString]][1];
				}
			} else {
				if(escTable[(unsigned char)inputStr[posInputString]][1] == 2) {
					outputStr[posOutputString++] = inputStr[posInputString];
					outputStr[posOutputString++] = inputStr[posInputString];
				}
			}
		} else {
			outputStr[posOutputString++] = inputStr[posInputString];
		}
	}
	outputStr[posOutputString] = 0;
	extern cUtfConverter utfConverter;
	if(checkUtf && !utfConverter.check(outputStr)) {
		utfConverter._remove_no_ascii(outputStr);
	}
}

string sqlEscapeStringBorder(string inputStr, char borderChar, const char *typeDb, SqlDb_mysql *sqlDbMysql) {
	return sqlEscapeStringBorder(inputStr.c_str(), borderChar, typeDb, sqlDbMysql);
}

string sqlEscapeStringBorder(const char *inputStr, char borderChar, const char *typeDb, SqlDb_mysql *sqlDbMysql) {
	string rsltString = sqlEscapeString(inputStr, 0, typeDb, sqlDbMysql);
	if(borderChar) {
		rsltString = borderChar + rsltString + borderChar;
	}
	return rsltString;
}

bool isSqlDriver(const char *sqlDriver, const char *checkSqlDriver) {
	return cmpStringIgnoreCase(checkSqlDriver ? checkSqlDriver : sql_driver, sqlDriver);
}

bool isTypeDb(const char *typeDb, const char *checkSqlDriver, const char *checkOdbcDriver) {
	return cmpStringIgnoreCase(checkSqlDriver ? checkSqlDriver : sql_driver, typeDb) ||
	       (cmpStringIgnoreCase(checkSqlDriver ? checkSqlDriver : sql_driver, "odbc") && 
	        cmpStringIgnoreCase(checkOdbcDriver ? checkOdbcDriver : odbc_driver, typeDb));
}

bool cmpStringIgnoreCase(const char* str1, const char* str2) {
	if(str1 == str2) {
		return true;
	}
	if(((str1 || str2) && !(str1 && str2)) ||
	   ((*str1 || *str2) && !(*str1 && *str2)) ||
	   strlen(str1) != strlen(str2)) {
		return false;
	}
	int length = strlen(str1);
	for(int i = 0; i < length; i++) {
		if(tolower(str1[i]) != tolower(str2[i])) {
			return false;
		}
	}
	return true;
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
		vector<string> sniffer_version_split = split(string(RTPSENSOR_VERSION), '.');
		if(sniffer_version_split.size()) {
			for(unsigned i = 0; i < min((unsigned)sniffer_version_split.size(), 3u); i++) {
				sniffer_version_num += atoi(sniffer_version_split[i].c_str()) * (i == 0 ? 1000000 : i == 1 ? 1000 : 1);
			}
		}
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
		      createSchema_table_http_jj(connectId) &
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
	
	string compress = opt_mysqlcompress ? "ROW_FORMAT=COMPRESSED" : "";
	string limitDay;
	string partDayName = this->getPartDayName(limitDay);
	
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
	"CREATE TABLE IF NOT EXISTS `sensor_config` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned DEFAULT NULL,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	
	this->query(
	"CREATE TABLE IF NOT EXISTS `filter_ip` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`ip` int unsigned DEFAULT NULL,\
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

	bool existsExtPrecisionBilling = false;
	extern bool opt_database_backup;
	if(opt_database_backup) {
		extern char opt_database_backup_from_mysql_host[256];
		extern char opt_database_backup_from_mysql_database[256];
		extern char opt_database_backup_from_mysql_user[256];
		extern char opt_database_backup_from_mysql_password[256];
		extern unsigned int opt_database_backup_from_mysql_port;
		SqlDb_mysql *sqlDbSrc = new FILE_LINE(29013) SqlDb_mysql();
		sqlDbSrc->setConnectParameters(opt_database_backup_from_mysql_host, 
					       opt_database_backup_from_mysql_user,
					       opt_database_backup_from_mysql_password,
					       opt_database_backup_from_mysql_database,
					       opt_database_backup_from_mysql_port);
		if(sqlDbSrc->existsColumn("cdr", "price_customer_mult1000000")) {
			existsExtPrecisionBilling = true;
		}
	} else {
		if(this->isExtPrecissionBilling()) {
			existsExtPrecisionBilling = true;
		}
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`calldate` datetime NOT NULL,\
			`callend` datetime NOT NULL,\
			`duration` mediumint unsigned DEFAULT NULL,\
			`connect_duration` mediumint unsigned DEFAULT NULL,\
			`progress_time` mediumint unsigned DEFAULT NULL,\
			`first_rtp_time` mediumint unsigned DEFAULT NULL,\
			`caller` varchar(255) DEFAULT NULL,\
			`caller_domain` varchar(255) DEFAULT NULL,\
			`caller_reverse` varchar(255) DEFAULT NULL,\
			`callername` varchar(255) DEFAULT NULL,\
			`callername_reverse` varchar(255) DEFAULT NULL,\
			`called` varchar(255) DEFAULT NULL,\
			`called_domain` varchar(255) DEFAULT NULL,\
			`called_reverse` varchar(255) DEFAULT NULL,\
			`sipcallerip` int unsigned DEFAULT NULL,\
			`sipcallerport` smallint unsigned DEFAULT NULL,\
			`sipcalledip` int unsigned DEFAULT NULL,\
			`sipcalledport` smallint unsigned DEFAULT NULL,\
			`whohanged` enum('caller','callee') DEFAULT NULL,\
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
			`a_saddr` int unsigned DEFAULT NULL,\
			`b_saddr` int unsigned DEFAULT NULL,\
			`a_received` mediumint unsigned DEFAULT NULL,\
			`b_received` mediumint unsigned DEFAULT NULL,\
			`a_lost` mediumint unsigned DEFAULT NULL,\
			`b_lost` mediumint unsigned DEFAULT NULL,\
			`a_ua_id` int unsigned DEFAULT NULL,\
			`b_ua_id` int unsigned DEFAULT NULL,\
			`a_avgjitter_mult10` mediumint unsigned DEFAULT NULL,\
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
			`b_mos_f1_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f2_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_adapt_min_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_xr_min_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_f1_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_f2_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_adapt_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_xr_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f1_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f2_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_adapt_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_xr_mult10` tinyint unsigned DEFAULT NULL,\
			`a_rtcp_loss` smallint unsigned DEFAULT NULL,\
			`a_rtcp_maxfr` smallint unsigned DEFAULT NULL,\
			`a_rtcp_avgfr_mult10` smallint unsigned DEFAULT NULL,\
			`a_rtcp_maxjitter` smallint unsigned DEFAULT NULL,\
			`a_rtcp_avgjitter_mult10` smallint unsigned DEFAULT NULL,\
			`b_rtcp_loss` smallint unsigned DEFAULT NULL,\
			`b_rtcp_maxfr` smallint unsigned DEFAULT NULL,\
			`b_rtcp_avgfr_mult10` smallint unsigned DEFAULT NULL,\
			`b_rtcp_maxjitter` smallint unsigned DEFAULT NULL,\
			`b_rtcp_avgjitter_mult10` smallint unsigned DEFAULT NULL,\
			`a_last_rtp_from_end` smallint unsigned DEFAULT NULL,\
			`b_last_rtp_from_end` smallint unsigned DEFAULT NULL,\
			`a_rtcp_fraclost_pktcount` int unsigned DEFAULT NULL,\
			`b_rtcp_fraclost_pktcount` int unsigned DEFAULT NULL,\
			`a_rtp_ptime` tinyint unsigned DEFAULT NULL,\
			`b_rtp_ptime` tinyint unsigned DEFAULT NULL,\
			`payload` int DEFAULT NULL,\
			`jitter_mult10` mediumint unsigned DEFAULT NULL,\
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
			`lost` mediumint unsigned DEFAULT NULL,\
			`caller_clipping_div3` smallint unsigned DEFAULT NULL,\
			`called_clipping_div3` smallint unsigned DEFAULT NULL,\
			`caller_silence` tinyint unsigned DEFAULT NULL,\
			`called_silence` tinyint unsigned DEFAULT NULL,\
			`caller_silence_end` smallint unsigned DEFAULT NULL,\
			`called_silence_end` smallint unsigned DEFAULT NULL,\
			`response_time_100` smallint unsigned DEFAULT NULL,\
			`response_time_xxx` smallint unsigned DEFAULT NULL,\
			`max_retransmission_invite` tinyint unsigned DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,\
			`id_sensor` smallint unsigned DEFAULT NULL,") + 
			(get_customers_pn_query[0] ?
				"`caller_customer_id` int DEFAULT NULL,\
				`caller_reseller_id` char(10) DEFAULT NULL,\
				`called_customer_id` int DEFAULT NULL,\
				`called_reseller_id` char(10) DEFAULT NULL," :
				"") +
			(existsExtPrecisionBilling ?
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
		KEY `lastSIPresponseNum` (`lastSIPresponseNum`),\
		KEY `bye` (`bye`),\
		KEY `a_saddr` (`a_saddr`),\
		KEY `b_saddr` (`b_saddr`),\
		KEY `a_lost` (`a_lost`),\
		KEY `b_lost` (`b_lost`),\
		KEY `a_maxjitter` (`a_maxjitter`),\
		KEY `b_maxjitter` (`b_maxjitter`),\
		KEY `a_rtcp_loss` (`a_rtcp_loss`),\
		KEY `a_rtcp_maxfr` (`a_rtcp_maxfr`),\
		KEY `a_rtcp_maxjitter` (`a_rtcp_maxjitter`),\
		KEY `b_rtcp_loss` (`b_rtcp_loss`),\
		KEY `b_rtcp_maxfr` (`b_rtcp_maxfr`),\
		KEY `b_rtcp_maxjitter` (`b_rtcp_maxjitter`),\
		KEY `a_ua_id` (`a_ua_id`),\
		KEY `b_ua_id` (`b_ua_id`),\
		KEY `a_avgjitter_mult10` (`a_avgjitter_mult10`),\
		KEY `b_avgjitter_mult10` (`b_avgjitter_mult10`),\
		KEY `a_rtcp_avgjitter_mult10` (`a_rtcp_avgjitter_mult10`),\
		KEY `b_rtcp_avgjitter_mult10` (`b_rtcp_avgjitter_mult10`),\
		KEY `lastSIPresponse_id` (`lastSIPresponse_id`),\
		KEY `reason_sip_text_id` (`reason_sip_text_id`),\
		KEY `reason_q850_text_id` (`reason_q850_text_id`),\
		KEY `payload` (`payload`),\
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
		(opt_cdr_partition_oldver ? 
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
				if(getPartitions(cdrMainTables[i].c_str()) > 0) {
					partitionIsExists = true;
				}
			}
		}
		if(tableIsExists && !partitionIsExists) {
			syslog(LOG_INFO, "disable opt_cdr_partition (tables cdr... does not have partitions)");
			opt_cdr_partition = 0;
		}
	}

	checkColumns_cdr(true);
	
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

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_next` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`custom_header1` varchar(255) DEFAULT NULL,\
			`fbasename` varchar(255) DEFAULT NULL,\
			`match_header` VARCHAR(128) DEFAULT NULL,\
			`GeoPosition` varchar(255) DEFAULT NULL, \
			`hold` varchar(1024) DEFAULT NULL, \
			`spool_index` tinyint unsigned DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`cdr_ID`, `calldate`)," :
			"PRIMARY KEY (`cdr_ID`),") +
		"KEY `fbasename` (`fbasename`),\
		 KEY `match_header` (`match_header`)" + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_next_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
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
	
	checkColumns_cdr_next(true);

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_proxy` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,\
			`calldate` datetime NOT NULL,\
			`src` int unsigned DEFAULT NULL,\
			`dst` varchar(255) DEFAULT NULL,\
		KEY `cdr_ID` (`cdr_ID`),\
		KEY `calldate` (`calldate`),\
		KEY `src` (`src`),\
		KEY `dst` (`dst`)") + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_proxy_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress  + 
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_rtp` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`saddr` int unsigned DEFAULT NULL,\
			`daddr` int unsigned DEFAULT NULL,\
			`ssrc` int unsigned DEFAULT NULL,\
			`received` mediumint unsigned DEFAULT NULL,\
			`loss` mediumint unsigned DEFAULT NULL,\
			`firsttime` float DEFAULT NULL,\
			`payload` smallint unsigned DEFAULT NULL,\
			`maxjitter_mult10` smallint unsigned DEFAULT NULL,\
			`index` tinyint unsigned DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_rtp_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	checkColumns_cdr_rtp(true);

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_dtmf` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`daddr` int unsigned DEFAULT NULL,\
			`saddr` int unsigned DEFAULT NULL,\
			`firsttime` float DEFAULT NULL,\
			`dtmf` char DEFAULT NULL,\
			`type` tinyint unsigned DEFAULT NULL,\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_dtmf_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	checkColumns_cdr_dtmf(true);

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_sipresp` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`SIPresponse_id` mediumint unsigned DEFAULT NULL,\
			`SIPresponseNum` smallint unsigned DEFAULT NULL,\
		KEY (`cdr_ID`)" +
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_sipresp_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	if(_save_sip_history) {
		this->query(string(
		"CREATE TABLE IF NOT EXISTS `cdr_siphistory` (\
				`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
				(opt_cdr_partition ?
					"`calldate` datetime NOT NULL," :
					"") + 
				"`time` bigint unsigned DEFAULT NULL,\
				`SIPrequest_id` mediumint unsigned DEFAULT NULL,\
				`SIPresponse_id` mediumint unsigned DEFAULT NULL,\
				`SIPresponseNum` smallint unsigned DEFAULT NULL,\
			KEY (`cdr_ID`)" + 
			(opt_cdr_partition ? 
				",KEY (`calldate`)" :
				"") +
			(opt_cdr_partition ?
				"" :
				",CONSTRAINT `cdr_siphistory_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
		") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
		(opt_cdr_partition ?
			(opt_cdr_partition_oldver ? 
				string(" PARTITION BY RANGE (to_days(calldate))(\
					 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
				string(" PARTITION BY RANGE COLUMNS(calldate)(\
					 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
			""));
	}

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_tar_part` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`type` tinyint unsigned DEFAULT NULL,\
			`pos` bigint unsigned DEFAULT NULL,\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_tar_part_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_country_code` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
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
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_sdp` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`ip` int unsigned DEFAULT NULL,\
			`port` smallint unsigned DEFAULT NULL,\
			`is_caller` tinyint unsigned DEFAULT NULL,\
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
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_flags` (\
			`cdr_ID` " + cdrIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`deleted` smallint unsigned DEFAULT NULL,\
		KEY (`cdr_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_flags_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `rtp_stat` (\
			`id_sensor` smallint unsigned NOT NULL,\
			`time` datetime NOT NULL,\
			`saddr` int unsigned NOT NULL,\
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
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 ") + compress +  
	(supportPartitions != _supportPartitions_na ?
		(opt_rtp_stat_partition_oldver ? 
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
				`time_iam` datetime NOT NULL,\
				`time_acm` datetime,\
				`time_cpg` datetime,\
				`time_anm` datetime,\
				`time_rel` datetime,\
				`time_rlc` datetime,\
				`duration` mediumint unsigned,\
				`connect_duration` mediumint unsigned,\
				`progress_time` mediumint unsigned,\
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
				`src_ip` int unsigned,\
				`dst_ip` int unsigned,\
				`src_ip_country_code` varchar(5),\
				`dst_ip_country_code` varchar(5),\
				`ss7_id` varchar(255),\
				`pcap_filename` varchar(255),\
				`id_sensor` smallint unsigned,") +
			(supportPartitions != _supportPartitions_na ?
				"PRIMARY KEY (`ID`, `time_iam`)," :
				"PRIMARY KEY (`ID`),") + 
			"KEY `time_iam` (`time_iam`)"\
		") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress + 
		(supportPartitions != _supportPartitions_na ?
			(opt_ss7_partition_oldver ? 
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
			`calldate` datetime NOT NULL,\
			`caller` varchar(255) DEFAULT NULL,\
			`caller_domain` varchar(255) DEFAULT NULL,\
			`caller_reverse` varchar(255) DEFAULT NULL,\
			`callername` varchar(255) DEFAULT NULL,\
			`callername_reverse` varchar(255) DEFAULT NULL,\
			`called` varchar(255) DEFAULT NULL,\
			`called_domain` varchar(255) DEFAULT NULL,\
			`called_reverse` varchar(255) DEFAULT NULL,\
			`sipcallerip` int unsigned DEFAULT NULL,\
			`sipcalledip` int unsigned DEFAULT NULL,\
			`bye` tinyint unsigned DEFAULT NULL,\
			`lastSIPresponse_id` mediumint unsigned DEFAULT NULL,\
			`lastSIPresponseNum` smallint unsigned DEFAULT NULL,\
			`id_sensor` smallint unsigned DEFAULT NULL,\
			`a_ua_id` int unsigned DEFAULT NULL,\
			`b_ua_id` int unsigned DEFAULT NULL,\
			`fbasename` varchar(255) DEFAULT NULL,\
			`message` MEDIUMTEXT CHARACTER SET utf8,\
			`content_length` MEDIUMINT DEFAULT NULL,\
			`response_time` SMALLINT UNSIGNED DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL,") +
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
		(opt_cdr_partition_oldver ? 
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
	
	checkColumns_message(true);

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
			`message_ID` " + messageIdType + " unsigned NOT NULL,\
			`calldate` datetime NOT NULL,\
			`src` int unsigned DEFAULT NULL,\
			`dst` varchar(255) DEFAULT NULL,\
		KEY `message_ID` (`message_ID`),\
		KEY `calldate` (`calldate`),\
		KEY `src` (`src`),\
		KEY `dst` (`dst`)") + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `message_proxy_ibfk_1` FOREIGN KEY (`message_ID`) REFERENCES `message` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress  + 
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `message_country_code` (\
			`message_ID` " + messageIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
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
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `message_flags` (\
			`message_ID` " + messageIdType + " unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`deleted` smallint unsigned DEFAULT NULL,\
		KEY (`message_ID`)" + 
		(opt_cdr_partition ? 
			",KEY (`calldate`)" :
			"") +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `message_flags_ibfk_1` FOREIGN KEY (`message_ID`) REFERENCES `message` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(calldate))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(calldate)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
		""));
	
	this->query(
	"CREATE TABLE IF NOT EXISTS `register` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned NOT NULL,\
			`fname` BIGINT NULL default NULL,\
			`calldate` datetime NOT NULL,\
			`sipcallerip` int unsigned NOT NULL,\
			`sipcalledip` int unsigned NOT NULL,\
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

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register_state` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned NOT NULL,\
			`fname` BIGINT NULL default NULL,\
			`created_at` datetime NOT NULL,\
			`sipcallerip` int unsigned NOT NULL,\
			`sipcalledip` int unsigned NOT NULL,\
			`from_num` varchar(255) NULL DEFAULT NULL,\
			`to_num` varchar(255) NULL DEFAULT NULL,\
			`contact_num` varchar(255) NULL DEFAULT NULL,\
			`contact_domain` varchar(255) NULL DEFAULT NULL,\
			`digestusername` varchar(255) NULL DEFAULT NULL,\
			`expires` mediumint NULL DEFAULT NULL,\
			`state` tinyint unsigned NULL DEFAULT NULL,\
			`ua_id` int unsigned DEFAULT NULL,\
			`to_domain` varchar(255) NULL DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL,") +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `created_at`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY `created_at` (`created_at`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(created_at))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `register_failed` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`id_sensor` int unsigned NOT NULL,\
			`fname` BIGINT NULL default NULL,\
			`counter` int DEFAULT 0,\
			`created_at` datetime NOT NULL,\
			`sipcallerip` int unsigned NOT NULL,\
			`sipcalledip` int unsigned NOT NULL,\
			`from_num` varchar(255) NULL DEFAULT NULL,\
			`to_num` varchar(255) NULL DEFAULT NULL,\
			`contact_num` varchar(255) NULL DEFAULT NULL,\
			`contact_domain` varchar(255) NULL DEFAULT NULL,\
			`digestusername` varchar(255) NULL DEFAULT NULL,\
			`ua_id` int unsigned DEFAULT NULL,\
			`to_domain` varchar(255) NULL DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL,") +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `created_at`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY `created_at` (`created_at`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress +  
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
			string(" PARTITION BY RANGE (to_days(created_at))(\
				 PARTITION ") + partDayName + " VALUES LESS THAN (to_days('" + limitDay + "')) engine innodb)" :
			string(" PARTITION BY RANGE COLUMNS(created_at)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)") :
	""));

	checkColumns_register(true);
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `sip_msg` (\
			`ID` bigint unsigned NOT NULL AUTO_INCREMENT,\
			`time` datetime NOT NULL,\
			`type` tinyint unsigned NOT NULL,\
			`ip_src` int unsigned DEFAULT NULL,\
			`ip_dst` int unsigned DEFAULT NULL,\
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
			`request_time` datetime DEFAULT NULL,\
			`request_time_us` int unsigned DEFAULT NULL,\
			`response_time` datetime DEFAULT NULL,\
			`response_time_us` int unsigned DEFAULT NULL,\
			`response_duration_ms` int unsigned DEFAULT NULL,\
			`qualify_ok` tinyint unsigned DEFAULT NULL,\
			`id_sensor` smallint unsigned DEFAULT NULL,\
			`spool_index` tinyint unsigned DEFAULT NULL,\
			`flags` bigint unsigned DEFAULT NULL,") +
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
		KEY `id_sensor` (`id_sensor`)" +
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `sip_msg_ibfk_1` FOREIGN KEY (`lastSIPresponse_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `sip_msg_ibfk_2` FOREIGN KEY (`a_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
			CONSTRAINT `sip_msg_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 " + compress + 
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
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
	this->query(
	"CREATE TABLE IF NOT EXISTS `ipacc` (\
			`saddr` int unsigned NOT NULL,\
			`src_id_customer` int unsigned NOT NULL DEFAULT 0,\
			`daddr` int unsigned NOT NULL,\
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
			string(" PARTITION BY RANGE COLUMNS(interval_time)(\
				 PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)");
	}

	this->query(
	"CREATE TABLE IF NOT EXISTS `livepacket` (\
			`id` INT UNSIGNED NOT NULL AUTO_INCREMENT ,\
			`id_sensor` INT DEFAULT NULL,\
			`sipcallerip` INT UNSIGNED NOT NULL ,\
			`sipcalledip` INT UNSIGNED NOT NULL ,\
			`sport` SMALLINT UNSIGNED NOT NULL ,\
			`dport` SMALLINT UNSIGNED NOT NULL ,\
			`istcp` TINYINT UNSIGNED NOT NULL ,\
			`created_at` TIMESTAMP NOT NULL ,\
			`microseconds` INT UNSIGNED NOT NULL ,\
			`callid` VARCHAR(255) NOT NULL ,\
			`description` VARCHAR(1024),\
			`data` VARBINARY(10000) NOT NULL ,\
		PRIMARY KEY ( `id` ) ,\
		INDEX (`created_at` , `microseconds`)\
	) ENGINE=MEMORY DEFAULT CHARSET=latin1 " + compress + ";");
	
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
	this->query(
	"CREATE TABLE IF NOT EXISTS `cache_number_location` (\
			`number` varchar(30) NOT NULL,\
			`number_ip` int unsigned NOT NULL,\
			`ip` int unsigned,\
			`country_code` varchar(5),\
			`continent_code` varchar(5),\
			`at` bigint unsigned,\
			`old_ip` int unsigned,\
			`old_country_code` varchar(5),\
			`old_continent_code` varchar(5),\
			`old_at` bigint unsigned,\
		PRIMARY KEY (`number`, `number_ip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
	this->query(
	"CREATE TABLE IF NOT EXISTS `cache_number_domain_location` (\
			`number` varchar(30) NOT NULL,\
			`domain` varchar(100) NOT NULL,\
			`number_ip` int unsigned NOT NULL,\
			`ip` int unsigned,\
			`country_code` varchar(5),\
			`continent_code` varchar(5),\
			`at` bigint unsigned,\
			`old_ip` int unsigned,\
			`old_country_code` varchar(5),\
			`old_continent_code` varchar(5),\
			`old_at` bigint unsigned,\
		PRIMARY KEY (`number`, `domain`, `number_ip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
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
	
	checkColumns_other(true);

	return(true);
}

bool SqlDb_mysql::createSchema_tables_billing_agregation() {
	cBillingAgregationSettings agregSettingsInst;
	agregSettingsInst.load();
	sBillingAgregationSettings agregSettings = agregSettingsInst.getAgregSettings();
	if(!agregSettings.enable_by_ip &&
	   !agregSettings.enable_by_number) {
		return(true);
	}
	this->clearLastError();
	string compress = opt_mysqlcompress ? "ROW_FORMAT=COMPRESSED" : "";
	vector<cBilling::sAgregationTypePart> typeParts = cBilling::getAgregTypeParts(&agregSettings);
	for(unsigned i = 0; i < typeParts.size(); i++) {
		this->query(string(
			"CREATE TABLE IF NOT EXISTS `billing_agregation_") + typeParts[i].type + "_addresses` (\
				`part` INT UNSIGNED,\
				`time` INT UNSIGNED,\
				`ip` INT UNSIGNED,\
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
	
	string compress = opt_mysqlcompress ? "ROW_FORMAT=COMPRESSED" : "";
	string limitDay;
	string partDayName = this->getPartDayName(limitDay);

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
		`srcip` INT UNSIGNED NOT NULL,\
		`dstip` INT UNSIGNED NOT NULL,\
		`srcport` SMALLINT UNSIGNED DEFAULT NULL,\
		`dstport` SMALLINT UNSIGNED DEFAULT NULL,\
		`url` TEXT NOT NULL,\
		`type` ENUM('http_ok') DEFAULT NULL,\
		`http` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,\
		`body` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,\
		`callid` VARCHAR( 255 ) NOT NULL,\
		`sessid` VARCHAR( 255 ) NOT NULL,\
		`external_transaction_id` varchar( 255 ) NOT NULL,\
		`id_sensor` smallint DEFAULT NULL,") +
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
		(opt_cdr_partition_oldver ? 
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
		(opt_cdr_partition_oldver ? 
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
	
	string compress = opt_mysqlcompress ? "ROW_FORMAT=COMPRESSED" : "";
	string limitDay;
	string partDayName = this->getPartDayName(limitDay);

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
		`srcip` INT UNSIGNED NOT NULL,\
		`dstip` INT UNSIGNED NOT NULL,\
		`srcport` SMALLINT UNSIGNED DEFAULT NULL,\
		`dstport` SMALLINT UNSIGNED DEFAULT NULL,\
		`type` ENUM('http', 'http_resp', 'websocket', 'websocket_resp') DEFAULT NULL,\
		`method` VARCHAR(32) DEFAULT NULL,\
		`body` TEXT CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,\
		`external_transaction_id` VARCHAR( 255 ) NOT NULL,\
		`id_sensor` smallint DEFAULT NULL,") +
	(opt_cdr_partition ? 
		"PRIMARY KEY (`id`, `timestamp`)," :
		"PRIMARY KEY (`id`),") + 
	"KEY `timestamp` (`timestamp`),\
	KEY `external_transaction_id` (`external_transaction_id`)\
	) ENGINE=InnoDB " + compress +
	(opt_cdr_partition ?
		(opt_cdr_partition_oldver ? 
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
	outStrAlter << "ALTER TABLE register\
			ADD KEY `to_domain` (`to_domain`),\
			ADD KEY `to_num` (`to_num`);" << endl;
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
	outStrAlter << "ALTER TABLE register\
			ADD `fname` BIGINT NULL DEFAULT NULL;" << endl;
	outStrAlter << "ALTER TABLE register_failed\
			ADD `fname` BIGINT NULL DEFAULT NULL;" << endl;
	outStrAlter << "ALTER TABLE register_state\
			ADD `fname` BIGINT NULL DEFAULT NULL;" << endl;
	outStrAlter << "ALTER TABLE register\
			ADD `id_sensor` INT NULL DEFAULT NULL;" << endl;
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
	outStrAlter << "ALTER TABLE register \
		ADD `rrd_avg` mediumint unsigned DEFAULT NULL;" <<endl;
	outStrAlter << "ALTER TABLE register \
		ADD `rrd_count` tinyint unsigned DEFAULT NULL;" <<endl;
	outStrAlter << "ALTER TABLE register \
		ADD KEY `rrd_avg` (`rrd_avg`);" << endl;
	outStrAlter << "drop trigger if exists cdr_bi;" << endl;

	//15.1
	outStrAlter << "ALTER TABLE register \
		ADD `src_mac` bigint unsigned DEFAULT NULL;" <<endl;
	outStrAlter << "ALTER TABLE register \
		ADD KEY `src_mac` (`src_mac`);" << endl;
	outStrAlter << "drop trigger if exists cdr_bi;" << endl;
	
	//17
	if(opt_enable_fraud) {
		if(this->existsTable("fraud_alert_info")) {
			outStrAlter << "ALTER TABLE fraud_alert_info\
					ADD `id_sensor` smallint unsigned;" << endl;
		}
	}

	//19.3
	outStrAlter << "ALTER TABLE sensors \
		ADD `cloud_router` tinyint;" << endl;
	
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
			    call create_partition('ipacc', 'day', next_days);\
			    call create_partition('ipacc_agr_interval', 'day', next_days);\
			    call create_partition('ipacc_agr_hour', 'day', next_days);\
			    call create_partition('ipacc_agr2_hour', 'day', next_days);\
			    call create_partition('ipacc_agr_day', 'month', next_days);\
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
			    call create_partition(database_name, 'ipacc', 'day', next_days);\
			    call create_partition(database_name, 'ipacc_agr_interval', 'day', next_days);\
			    call create_partition(database_name, 'ipacc_agr_hour', 'day', next_days);\
			    call create_partition(database_name, 'ipacc_agr2_hour', 'day', next_days);\
			    call create_partition(database_name, 'ipacc_agr_day', 'month', next_days);\
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
	    declare part_limit date;\
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
	       set part_start_time = date_add(now(), interval next_days day);\
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
			part_limit),\
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
	"create_partition_v3", "(database_name char(100), table_name char(100), type_part char(10), next_days int, old_ver_partition bool)", abortIfFailed);

	return(true);
}

bool SqlDb_mysql::createSchema_init_cdr_partitions(int connectId) {
	this->clearLastError();
	
	if(opt_cdr_partition && !opt_disable_partition_operations) {
		if(opt_create_old_partitions > 0) {
			for(int i = opt_create_old_partitions - 1; i > 0; i--) {
				_createMysqlPartitionsCdr(-i, connectId, this);
			}
		}
		_createMysqlPartitionsCdr(0, connectId, this);
		_createMysqlPartitionsCdr(1, connectId, this);
	}
	return(true);
}

string SqlDb_mysql::getPartDayName(string &limitDay_str, bool enableOldPartition) {
	char partDayName[20] = "";
	char limitDay[20] = "";
	if(supportPartitions != _supportPartitions_na) {
		time_t act_time = time(NULL);
		if(enableOldPartition && opt_create_old_partitions > 0) {
			act_time -= opt_create_old_partitions * 24 * 60 * 60;
		}
		struct tm actTime = time_r(&act_time);
		strftime(partDayName, sizeof(partDayName), "p%y%m%d", &actTime);
		time_t next_day_time = act_time + 24 * 60 * 60;
		struct tm nextDayTime = time_r(&next_day_time);
		strftime(limitDay, sizeof(partDayName), "%Y-%m-%d", &nextDayTime);
	}
	limitDay_str = limitDay;
	return(partDayName);
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
		   this->getPartitions("cdr") > 0) {
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
				}
				opt_ss7_partition_oldver = true;
				opt_rtp_stat_partition_oldver = true;
				opt_log_sensor_partition_oldver = true;
			} else {
				if(opt_cdr_partition) {
					if(this->isOldVerPartition("cdr%")) {
						opt_cdr_partition_oldver = true;
						syslog(LOG_NOTICE, "database contain old mode partitions");
					}
				}
				if(this->isOldVerPartition("ss7")) {
					opt_ss7_partition_oldver = true;
					syslog(LOG_NOTICE, "table ss7 contain old mode partitions");
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
				`id_sensor` smallint unsigned,\
				`serverip` int unsigned,\
				`serverport` smallint unsigned,\
				`clientip` int unsigned,\
				`clientport` smallint unsigned,\
				`stored_at` datetime,\
				`session` varchar(1024),\
			PRIMARY KEY (`id_sensor`, `clientip`, `clientport`, `serverip`, `serverport`)\
		) ENGINE=" + (mem ? "MEMORY" : "InnoDB") + " DEFAULT CHARSET=latin1;");
	}
}

void SqlDb_mysql::checkSchema(int connectId, bool checkColumns) {
	this->clearLastError();
	if(!(connectId == 0)) {
		return;
	}
	
	sql_disable_next_attempt_if_error = 1;
	startExistsColumnCache();
	
	existsColumns.cdr_next_calldate = this->existsColumn("cdr_next", "calldate");
	existsColumns.cdr_rtp_calldate = this->existsColumn("cdr_rtp", "calldate");
	existsColumns.cdr_dtmf_calldate = this->existsColumn("cdr_dtmf", "calldate");
	existsColumns.cdr_sipresp_calldate = this->existsColumn("cdr_sipresp", "calldate");
	if(_save_sip_history) {
		existsColumns.cdr_siphistory_calldate = this->existsColumn("cdr_siphistory", "calldate");
	}
	existsColumns.cdr_tar_part_calldate = this->existsColumn("cdr_tar_part", "calldate");
	existsColumns.cdr_country_code_calldate = this->existsColumn("cdr_country_code", "calldate");
	existsColumns.cdr_sdp_calldate = this->existsColumn("cdr_sdp", "calldate");
	if(!opt_cdr_partition &&
	   (isCloud() ||
	    this->getDbMajorVersion() * 100 + this->getDbMinorVersion() > 500)) {
		if(this->getPartitions("cdr") > 0) {
			syslog(LOG_INFO, "enable opt_cdr_partition (table cdr has partitions)");
			opt_cdr_partition = true;
		}
	}
	existsColumns.register_rrd_count = this->existsColumn("register", "rrd_count");
	
	if(checkColumns) {
		this->checkColumns_cdr();
		this->checkColumns_cdr_next();
		this->checkColumns_cdr_rtp();
		this->checkColumns_cdr_dtmf();
		this->checkColumns_message();
		this->checkColumns_register();
		this->checkColumns_other();
	}
	
	sql_disable_next_attempt_if_error = 0;
	stopExistsColumnCache();
}

void SqlDb_mysql::updateSensorState() {
	if(opt_id_sensor > 0) {
		this->query("select * from `sensors` where id_sensor=" + intToString(opt_id_sensor));
		bool existsRowSensor = this->fetchRow();
		if(isCloud()) {
			bool existsColumnCloudRouter = this->existsColumn("sensors", "cloud_router");
			if(existsRowSensor) {
				SqlDb_row rowU;
				if(existsColumnCloudRouter) {
					rowU.add(isCloudRouter(), "cloud_router");
				}
				if(isCloudRouter()) {
					extern cCR_Receiver_service *cloud_receiver;
					rowU.add(cloud_receiver->getConnectFrom(), "host");
				}
				if(!rowU.isEmpty()) {
					this->update("sensors", rowU, ("id_sensor=" + intToString(opt_id_sensor)).c_str());
				}
			} else if(isCloudRouter()) {
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
	} else {
		if(isCloud()) {
			this->query("select content from `system` where type='cloud_router_local_sensor'");
			SqlDb_row row = this->fetchRow();
			if(row) {
				SqlDb_row rowU;
				rowU.add(intToString(isCloudRouter()), "content");
				this->update("system", rowU, "type='cloud_router_local_sensor'");
			} else {
				SqlDb_row rowI;
				rowI.add(intToString(isCloudRouter()), "content");
				rowI.add("cloud_router_local_sensor", "type");
				this->insert("system", rowI);
			}
		}
	}
}

void SqlDb_mysql::checkColumns_cdr(bool log) {
	map<string, u_int64_t> tableSize;
	existsColumns.cdr_sipport = this->existsColumn("cdr", "sipcallerport");
	if(opt_cdr_sipport && !existsColumns.cdr_sipport) {
		this->logNeedAlter("cdr",
				   "store sip ports",
				   "ALTER TABLE cdr "
				   "ADD COLUMN `sipcallerport` smallint unsigned DEFAULT NULL AFTER `sipcallerip`, "
				   "ADD COLUMN `sipcalledport` smallint unsigned DEFAULT NULL AFTER `sipcalledip`;",
				   log, &tableSize, &existsColumns.cdr_sipport);
	}
	existsColumns.cdr_last_rtp_from_end = this->existsColumn("cdr", "a_last_rtp_from_end");
	if(opt_last_rtp_from_end && !existsColumns.cdr_last_rtp_from_end) {
		this->logNeedAlter("cdr",
				   "store last rtp from end",
				   "ALTER TABLE cdr "
				   "ADD COLUMN a_last_rtp_from_end SMALLINT UNSIGNED DEFAULT NULL, "
				   "ADD COLUMN b_last_rtp_from_end SMALLINT UNSIGNED DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_last_rtp_from_end);
	}
	existsColumns.cdr_silencedetect = this->existsColumn("cdr", "caller_silence");
	extern int opt_silencedetect;
	if(opt_silencedetect && !existsColumns.cdr_silencedetect) {
		this->logNeedAlter("cdr",
				   "silencedetect",
				   "ALTER TABLE cdr "
				   "ADD COLUMN caller_silence tinyint unsigned default NULL, "
				   "ADD COLUMN called_silence tinyint unsigned default NULL, "
				   "ADD COLUMN caller_silence_end smallint default NULL, "
				   "ADD COLUMN called_silence_end smallint default NULL;",
				   log, &tableSize, &existsColumns.cdr_silencedetect);
	}
	existsColumns.cdr_clippingdetect = this->existsColumn("cdr", "caller_clipping_div3");
	extern int opt_clippingdetect;
	if(opt_clippingdetect && !existsColumns.cdr_clippingdetect) {
		this->logNeedAlter("cdr",
				   "clippingdetect",
				   "ALTER TABLE cdr "
				   "ADD COLUMN caller_clipping_div3 smallint unsigned default NULL, "
				   "ADD COLUMN called_clipping_div3 smallint unsigned default NULL;",
				   log, &tableSize, &existsColumns.cdr_clippingdetect);
	}
	existsColumns.cdr_rtcp_fraclost_pktcount = this->existsColumn("cdr", "a_rtcp_fraclost_pktcount");
	if(!existsColumns.cdr_rtcp_fraclost_pktcount) {
		this->logNeedAlter("cdr",
				   "rctp_fraclost_pktcount",
				   "ALTER TABLE cdr "
				   "ADD COLUMN a_rtcp_fraclost_pktcount int unsigned default NULL, "
				   "ADD COLUMN b_rtcp_fraclost_pktcount int unsigned default NULL;",
				   log, &tableSize, &existsColumns.cdr_rtcp_fraclost_pktcount);
	}
	existsColumns.cdr_rtp_ptime = this->existsColumn("cdr", "a_rtp_ptime");
	if(!existsColumns.cdr_rtp_ptime) {
		this->logNeedAlter("cdr",
				   "rtp ptime",
				   "ALTER TABLE cdr "
				   "ADD COLUMN a_rtp_ptime tinyint unsigned default NULL, "
				   "ADD COLUMN b_rtp_ptime tinyint unsigned default NULL;",
				   log, &tableSize, &existsColumns.cdr_rtp_ptime);
	}
	existsColumns.cdr_dscp = this->existsColumn("cdr", "dscp");
	if(opt_dscp && !existsColumns.cdr_dscp) {
		this->logNeedAlter("cdr",
				   "dscp",
				   "ALTER TABLE cdr "
				   "ADD COLUMN dscp int unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_dscp);
	}
	existsColumns.cdr_mos_lqo = this->existsColumn("cdr", "a_mos_lqo_mult10");
	if(opt_mos_lqo && !existsColumns.cdr_mos_lqo) {
		this->logNeedAlter("cdr",
				   "mos lqo",
				   "ALTER TABLE cdr "
				   "ADD COLUMN `a_mos_lqo_mult10` tinyint unsigned DEFAULT NULL, "
				   "ADD COLUMN `b_mos_lqo_mult10` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_mos_lqo);
	}
	existsColumns.cdr_flags = this->existsColumn("cdr", "flags");
	if(!existsColumns.cdr_flags) {
		this->logNeedAlter("cdr",
				   "flags",
				   "ALTER TABLE cdr "
				   "ADD COLUMN `flags` bigint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_flags);
	}
	existsColumns.cdr_max_retransmission_invite = this->existsColumn("cdr", "max_retransmission_invite");
	if(!existsColumns.cdr_max_retransmission_invite) {
		this->logNeedAlter("cdr",
				   "maximum retransmissions invite",
				   "ALTER TABLE cdr "
				   "ADD COLUMN `max_retransmission_invite` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_max_retransmission_invite);
	}

	if(!this->existsColumn("cdr", "price_operator_mult100") &&
	   !this->existsColumn("cdr", "price_operator_mult1000000") &&
	   this->existsTable("billing")) {
		this->logNeedAlter("cdr",
				   "billing feature",
				   string("ALTER TABLE cdr ") +
				   (this->isExtPrecissionBilling() ?
					"ADD COLUMN price_operator_mult100 INT UNSIGNED, "
					"ADD COLUMN price_operator_currency_id TINYINT UNSIGNED, "
					"ADD COLUMN price_customer_mult100 INT UNSIGNED, "
					"ADD COLUMN price_customer_currency_id TINYINT UNSIGNED;" :
					"ADD COLUMN price_operator_mult1000000 BIGINT UNSIGNED, "
					"ADD COLUMN price_operator_currency_id TINYINT UNSIGNED, "
					"ADD COLUMN price_customer_mult1000000 BIGINT UNSIGNED, "
					"ADD COLUMN price_customer_currency_id TINYINT UNSIGNED;"),
				   log, &tableSize, NULL);
	}
	existsColumns.cdr_price_operator_mult100 = this->existsColumn("cdr", "price_operator_mult100");
	existsColumns.cdr_price_operator_mult1000000 = this->existsColumn("cdr", "price_operator_mult1000000");
	existsColumns.cdr_price_operator_currency_id = this->existsColumn("cdr", "price_operator_currency_id");
	existsColumns.cdr_price_customer_mult100 = this->existsColumn("cdr", "price_customer_mult100");
	existsColumns.cdr_price_customer_mult1000000 = this->existsColumn("cdr", "price_customer_mult1000000");
	existsColumns.cdr_price_customer_currency_id = this->existsColumn("cdr", "price_customer_currency_id");
	
	const char *cdrReasonColumns[] = {
		"reason_sip_cause",
		"reason_sip_text_id",
		"reason_q850_cause",
		"reason_q850_text_id"
	};
	bool missing_column_cdr_reason = false;
	for(unsigned int i = 0; i < sizeof(cdrReasonColumns) / sizeof(cdrReasonColumns[0]); i++) {
		if(!this->existsColumn("cdr", cdrReasonColumns[i])) {
			missing_column_cdr_reason = true;
		}
	}
	if(missing_column_cdr_reason) {
		this->logNeedAlter("cdr",
				   "SIP header 'reason'",
				   "ALTER TABLE cdr "
				   "ADD COLUMN reason_sip_cause smallint unsigned DEFAULT NULL, "
				   "ADD COLUMN reason_sip_text_id mediumint unsigned DEFAULT NULL, "
				   "ADD COLUMN reason_q850_cause smallint unsigned DEFAULT NULL, "
				   "ADD COLUMN reason_q850_text_id mediumint unsigned DEFAULT NULL, "
				   "ADD KEY reason_sip_text_id (reason_sip_text_id), "
				   "ADD KEY reason_q850_text_id (reason_q850_text_id);",
				   log, &tableSize, &existsColumns.cdr_reason);
	} else {
		existsColumns.cdr_reason = true;
	}
	
	const char *cdrResponseTime[] = {
		"response_time_100",
		"response_time_xxx"
	};
	bool missing_column_cdr_response_time = false;
	for(unsigned int i = 0; i < sizeof(cdrResponseTime) / sizeof(cdrResponseTime[0]); i++) {
		if(!this->existsColumn("cdr", cdrResponseTime[i])) {
			missing_column_cdr_response_time = true;
		}
	}
	if(missing_column_cdr_response_time) {
		this->logNeedAlter("cdr",
				   "SIP response time",
				   "ALTER TABLE cdr "
				   "ADD COLUMN response_time_100 smallint unsigned DEFAULT NULL, "
				   "ADD COLUMN response_time_xxx smallint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_response_time);
	} else {
		existsColumns.cdr_response_time = true;
	}

	//14.0
	existsColumns.cdr_mos_min = this->existsColumn("cdr", "a_mos_f1_min_mult10");
	if(!existsColumns.cdr_mos_min) {
		this->logNeedAlter("cdr",
				   "MOS min",
				   "ALTER TABLE cdr "
					"ADD COLUMN a_mos_f1_min_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN a_mos_f2_min_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN a_mos_adapt_min_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN b_mos_f1_min_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN b_mos_f2_min_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN b_mos_adapt_min_mult10 tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_mos_min);
	}
	//14.3
	existsColumns.cdr_mos_xr = this->existsColumn("cdr", "a_mos_xr_min_mult10");
	if(!existsColumns.cdr_mos_xr) {
		this->logNeedAlter("cdr",
				   "MOS RTPC XR",
				   "ALTER TABLE cdr "
					"ADD COLUMN a_mos_xr_min_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN b_mos_xr_min_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN a_mos_xr_mult10 tinyint unsigned DEFAULT NULL, "
					"ADD COLUMN b_mos_xr_mult10 tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_mos_xr);
	}
}

void SqlDb_mysql::checkColumns_cdr_next(bool log) {
	map<string, u_int64_t> tableSize;
	existsColumns.cdr_next_spool_index= this->existsColumn("cdr_next", "spool_index");
	if(!existsColumns.cdr_next_spool_index) {
		this->logNeedAlter("cdr_next",
				   "cdr spool index",
				   "ALTER TABLE cdr_next "
				   "ADD COLUMN `spool_index` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_next_spool_index);
	}
	existsColumns.cdr_next_hold = this->existsColumn("cdr_next", "hold");
	if(!existsColumns.cdr_next_hold) {
		this->logNeedAlter("cdr_next",
				   "cdr hold",
				   "ALTER TABLE cdr_next "
				   "ADD COLUMN `hold` varchar(1024) DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_next_hold);
	}
}

void SqlDb_mysql::checkColumns_cdr_rtp(bool log) {
	map<string, u_int64_t> tableSize;
	existsColumns.cdr_rtp_dport = this->existsColumn("cdr_rtp", "dport");
	if(opt_cdr_rtpport && !existsColumns.cdr_rtp_dport) {
		this->logNeedAlter("cdr_rtp",
				   "rtp destination port",
				   "ALTER TABLE cdr_rtp "
					"ADD COLUMN `dport` smallint unsigned DEFAULT NULL AFTER `daddr`;",
				   log, &tableSize, &existsColumns.cdr_rtp_dport);
	}
	existsColumns.cdr_rtp_sport = this->existsColumn("cdr_rtp", "sport");
	if(opt_cdr_rtpsrcport && !existsColumns.cdr_rtp_sport) {
		this->logNeedAlter("cdr_rtp",
				   "rtp source port",
				   "ALTER TABLE cdr_rtp "
					"ADD COLUMN `sport` smallint unsigned DEFAULT NULL AFTER `saddr`;",
				   log, &tableSize, &existsColumns.cdr_rtp_sport);
	}
	existsColumns.cdr_rtp_index = this->existsColumn("cdr_rtp", "index");
	if(!existsColumns.cdr_rtp_index) {
		this->logNeedAlter("cdr_rtp",
				   "rtp index of stream",
				   "ALTER TABLE cdr_rtp "
					"ADD COLUMN `index` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_rtp_index);
	}
	existsColumns.cdr_rtp_flags = this->existsColumn("cdr_rtp", "flags");
	if(!existsColumns.cdr_rtp_flags) {
		this->logNeedAlter("cdr_rtp",
				   "flags",
				   "ALTER TABLE cdr_rtp "
					"ADD COLUMN `flags` bigint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_rtp_flags);
	}
}

void SqlDb_mysql::checkColumns_cdr_dtmf(bool log) {
	extern int opt_dbdtmf;
	map<string, u_int64_t> tableSize;
	existsColumns.cdr_dtmf_type = this->existsColumn("cdr_dtmf", "type");
	if(opt_dbdtmf && !existsColumns.cdr_dtmf_type) {
		this->logNeedAlter("cdr_dtmf",
				   "type",
				   "ALTER TABLE cdr_dtmf "
					"ADD COLUMN `type` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.cdr_dtmf_type);
	}
}

void SqlDb_mysql::checkColumns_message(bool log) {
	map<string, u_int64_t> tableSize;
	existsColumns.message_content_length = this->existsColumn("message", "content_length");
	existsColumns.message_response_time = this->existsColumn("message", "response_time");
	if(!existsColumns.message_response_time) {
		this->logNeedAlter("message",
				   "SIP response time",
				   "ALTER TABLE message "
				   "ADD COLUMN response_time smallint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.message_response_time);
	}
	existsColumns.message_spool_index= this->existsColumn("message", "spool_index");
	if(!existsColumns.message_spool_index) {
		this->logNeedAlter("message",
				   "message spool index",
				   "ALTER TABLE message "
				   "ADD COLUMN `spool_index` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.message_spool_index);
	}
}

void SqlDb_mysql::checkColumns_register(bool log) {
	map<string, u_int64_t> tableSize;
	extern int opt_sip_register;
	if(opt_sip_register == 1) {
		bool registerFailedIdIsBig = true;
		this->query("show columns from register_failed like 'id'");
		SqlDb_row register_failed_struct_row = this->fetchRow();
		if(register_failed_struct_row) {
			string idType = register_failed_struct_row["type"];
			std::transform(idType.begin(), idType.end(), idType.begin(), ::toupper);
			if(idType.find("BIG") == string::npos) {
				registerFailedIdIsBig = false;
			}
		}
		if(!registerFailedIdIsBig) {
			this->logNeedAlter("register_failed",
					   "register failed",
					   "ALTER TABLE register_failed "
					   "CHANGE COLUMN `ID` `ID` bigint unsigned NOT NULL;",
					   log, &tableSize, NULL);
		}
	}
	existsColumns.register_state_spool_index= this->existsColumn("register_state", "spool_index");
	if(!existsColumns.register_state_spool_index) {
		this->logNeedAlter("register_state",
				   "register_state spool index",
				   "ALTER TABLE register_state "
				   "ADD COLUMN `spool_index` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.register_state_spool_index);
	}
	existsColumns.register_state_flags= this->existsColumn("register_state", "flags");
	if(!existsColumns.register_state_flags) {
		this->logNeedAlter("register_state",
				   "register_state flags",
				   "ALTER TABLE register_state "
				   "ADD COLUMN `flags` bigint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.register_state_flags);
	}
	existsColumns.register_failed_spool_index= this->existsColumn("register_failed", "spool_index");
	if(!existsColumns.register_failed_spool_index) {
		this->logNeedAlter("register_failed",
				   "register_failed spool index",
				   "ALTER TABLE register_failed "
				   "ADD COLUMN `spool_index` tinyint unsigned DEFAULT NULL;",
				   log, &tableSize, &existsColumns.register_failed_spool_index);
	}
}

void SqlDb_mysql::checkColumns_other(bool /*log*/) {
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
}

bool SqlDb_mysql::isExtPrecissionBilling() {
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

bool SqlDb_mysql::checkSourceTables() {
	bool ok = true;
	vector<string> sourceTables = this->getSourceTables();
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

void SqlDb_mysql::copyFromSourceTablesMinor(SqlDb_mysql *sqlDbSrc) {
	vector<string> tablesMinor = getSourceTables(tt_minor);
	for(size_t i = 0; i < tablesMinor.size() && !is_terminating(); i++) {
		this->copyFromSourceTable(sqlDbSrc, tablesMinor[i].c_str(), 10000);
	}
}

void SqlDb_mysql::copyFromSourceTablesMain(SqlDb_mysql *sqlDbSrc,
					   unsigned long limit, bool descDir,
					   bool skipRegister) {
	vector<string> tablesMain = getSourceTables(tt_main);
	for(size_t i = 0; i < tablesMain.size() && !is_terminating(); i++) {
		if(!skipRegister || !strstr(tablesMain[i].c_str(), "register")) {
			this->copyFromSourceTable(sqlDbSrc, tablesMain[i].c_str(), limit ? limit : 10000, descDir);
		}
	}
}

void SqlDb_mysql::copyFromSourceTable(SqlDb_mysql *sqlDbSrc, 
				      const char *tableName, 
				      unsigned long limit, bool descDir) {
	u_int64_t minIdSrc = 0;
	extern char opt_database_backup_from_date[20];
	if(opt_database_backup_from_date[0]) {
		string timeColumn = (string(tableName) == "cdr" || string(tableName) == "message") ? "calldate" : 
				    (string(tableName) == "http_jj" || string(tableName) == "enum_jj") ? "timestamp" : 
				    (string(tableName) == "register_state" || string(tableName) == "register_failed") ? "created_at" :
				    "";
		if(!timeColumn.empty()) {
			sqlDbSrc->query(string("select min(id) as min_id from ") + tableName +
					" where " + timeColumn + " = " + 
					"(select min(" + timeColumn + ") from " + tableName + " where " + timeColumn + " > '" + opt_database_backup_from_date + "')");
			minIdSrc = atoll(sqlDbSrc->fetchRow()["min_id"].c_str());
		}
	} else {
		sqlDbSrc->query(string("select min(id) as min_id from ") + tableName);
		SqlDb_row row = sqlDbSrc->fetchRow();
		if(row) {
			minIdSrc = atoll(row["min_id"].c_str());
		}
	}
	u_int64_t maxIdSrc = 0;
	sqlDbSrc->query(string("select max(id) as max_id from ") + tableName);
	SqlDb_row row = sqlDbSrc->fetchRow();
	if(row) {
		maxIdSrc = atoll(row["max_id"].c_str());
	}
	if(!maxIdSrc) {
		return;
	}
	u_int64_t maxIdDst = 0;
	u_int64_t minIdDst = 0;
	u_int64_t useMaxIdInSrc = 0;
	u_int64_t useMinIdInSrc = 0;
	u_int64_t startIdSrc = 0;
	bool okStartIdSrc = false;
	if(!descDir) {
		this->query(string("select max(id) as max_id from ") + tableName);
		row = this->fetchRow();
		if(row) {
			maxIdDst = atoll(row["max_id"].c_str());
		}
		startIdSrc = max(minIdSrc, maxIdDst + 1);
		okStartIdSrc = startIdSrc <= maxIdSrc;
	} else {
		this->query(string("select min(id) as min_id from ") + tableName);
		row = this->fetchRow();
		if(row) {
			minIdDst = atoll(row["min_id"].c_str());
		}
		startIdSrc = minIdDst ? min(maxIdSrc, minIdDst - 1) : maxIdSrc;
		okStartIdSrc = startIdSrc && startIdSrc >= minIdSrc;
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
				if(!descDir) {
					useMaxIdInSrc = atoll(row["id"].c_str());
				} else {
					useMinIdInSrc = atoll(row["id"].c_str());
				}
				rows.push_back(row);
				if(rows.size() >= 100) {
					string insertQuery = this->insertQuery(tableName, &rows, false, true, true);
					sqlStore->query(insertQuery.c_str(), 
							insertThreads > 1 ?
								((counterInsert++ % insertThreads) + 1) :
								1);
					rows.clear();
				}
				while(!is_terminating() && sqlStore->getAllSize() > 1000) {
					usleep(100000);
				}
			}
			if(is_terminating() < 2 && rows.size()) {
				string insertQuery = this->insertQuery(tableName, &rows, false, true, true);
				sqlStore->query(insertQuery.c_str(), 
						insertThreads > 1 ?
							((counterInsert++ % insertThreads) + 1) :
							1);
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
		if(!descDir) {
			this->copyFromSourceTableSlave(sqlDbSrc,
						       tableName, slaveTables[i].c_str(),
						       slaveIdToMasterColumn.c_str(), 
						       "calldate", "calldate",
						       minIdSrc, useMaxIdInSrc > 100 ? useMaxIdInSrc - 100 : 0,
						       limit * 10);
		} else {
			this->copyFromSourceTableSlave(sqlDbSrc,
						       tableName, slaveTables[i].c_str(),
						       slaveIdToMasterColumn.c_str(), 
						       "calldate", "calldate",
						       useMinIdInSrc, 0,
						       limit * 10, true);
		}
	}
}

void SqlDb_mysql::copyFromSourceTableSlave(SqlDb_mysql *sqlDbSrc,
					   const char *masterTableName, const char *slaveTableName,
					   const char *slaveIdToMasterColumn, 
					   const char *masterCalldateColumn, const char *slaveCalldateColumn,
					   u_int64_t useMinIdMaster, u_int64_t useMaxIdMaster,
					   unsigned long limit, bool descDir) {
	u_int64_t maxIdToMasterInSlaveSrc = 0;
	sqlDbSrc->query(string("select max(") + slaveIdToMasterColumn + ") as max_id from " + slaveTableName);
	SqlDb_row row = sqlDbSrc->fetchRow();
	if(row) {
		maxIdToMasterInSlaveSrc = atoll(row["max_id"].c_str());
	}
	if(!maxIdToMasterInSlaveSrc) {
		return;
	}
	u_int64_t minIdToMasterInSlaveSrc = 0;
	sqlDbSrc->query(string("select min(") + slaveIdToMasterColumn + ") as min_id from " + slaveTableName);
	row = sqlDbSrc->fetchRow();
	if(row) {
		minIdToMasterInSlaveSrc = atoll(row["min_id"].c_str());
	}
	u_int64_t maxIdToMasterInSlaveDst = 0;
	u_int64_t minIdToMasterInSlaveDst = 0;
	u_int64_t startIdToMasterSrc = 0;
	if(!descDir) {
		this->query(string("select max(") + slaveIdToMasterColumn + ") as max_id from " + slaveTableName);
		row = this->fetchRow();
		if(row) {
			maxIdToMasterInSlaveDst = atoll(row["max_id"].c_str());
		}
		startIdToMasterSrc = max(useMinIdMaster, maxIdToMasterInSlaveDst + 1);
		if(startIdToMasterSrc >= maxIdToMasterInSlaveSrc) {
			return;
		}
	} else {
		this->query(string("select min(") + slaveIdToMasterColumn + ") as min_id from " + slaveTableName);
		row = this->fetchRow();
		if(row) {
			minIdToMasterInSlaveDst = atoll(row["min_id"].c_str());
		}
		startIdToMasterSrc = minIdToMasterInSlaveDst ? minIdToMasterInSlaveDst - 1 : maxIdToMasterInSlaveSrc;
		if(startIdToMasterSrc < useMinIdMaster ||
		   startIdToMasterSrc <= minIdToMasterInSlaveSrc) {
			return;
		}
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
	map<string, int> columnsDest;
	this->query(string("show columns from ") + slaveTableName);
	size_t i = 0;
	while((row = this->fetchRow())) {
		columnsDest[row["Field"]] = ++i;
	}
	vector<string> condSrc;
	if(!descDir) {
		if(useMinIdMaster || maxIdToMasterInSlaveDst) {
			condSrc.push_back(string(slaveIdToMasterColumn) + " >= " + intToString(startIdToMasterSrc));
		}
		if(useMaxIdMaster) {
			condSrc.push_back(string(slaveIdToMasterColumn) + " <= " + intToString(useMaxIdMaster));
		}
	} else {
		condSrc.push_back(string(slaveIdToMasterColumn) + " <= " + intToString(startIdToMasterSrc));
		if(useMinIdMaster) {
			condSrc.push_back(string(slaveIdToMasterColumn) + " >= " + intToString(useMinIdMaster));
		}
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
			++counterRows;
			row.removeFieldsIfNotContainIn(&columnsDest);
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
						insertThreads > 1 ?
							((counterInsert++ % insertThreads) + 1) :
							1);
				rows.clear();
			}
			while(!is_terminating() && sqlStore->getAllSize() > 1000) {
				usleep(100000);
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
						insertThreads > 1 ?
							((counterInsert++ % insertThreads) + 1) :
							1);
				rows.clear();
			}
		}
	}
}

vector<string> SqlDb_mysql::getSourceTables(int typeTables, int typeTables2) {
	vector<string> tables;
	if(typeTables & tt_minor) {
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
				tables.push_back("cdr_rtp");
				tables.push_back("cdr_dtmf");
				tables.push_back("cdr_sipresp");
				if(_save_sip_history) {
					tables.push_back("cdr_siphistory");
				}
				tables.push_back("cdr_proxy");
				tables.push_back("cdr_tar_part");
				tables.push_back("cdr_country_code");
				tables.push_back("cdr_sdp");
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


bool SqlDb_odbc::createSchema(int /*connectId*/) {
	return(true);
}

void SqlDb_odbc::createTable(const char */*tableName*/) {
}

void SqlDb_odbc::checkDbMode() {
}

void SqlDb_odbc::checkSchema(int /*connectId*/, bool /*checkColumns*/) {
}

void SqlDb_odbc::updateSensorState() {
}


void createMysqlPartitionsCdr() {
	syslog(LOG_NOTICE, "%s", "create cdr partitions - begin");
	for(int connectId = 0; connectId < (use_mysql_2() ? 2 : 1); connectId++) {
		SqlDb *sqlDb = createSqlObject(connectId);
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
		for(int day = 0; day < 3; day++) {
			_createMysqlPartitionsCdr(day, connectId, sqlDb);
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
}

void _createMysqlPartitionsCdr(int day, int connectId, SqlDb *sqlDb) {
	SqlDb_mysql *sqlDbMysql = dynamic_cast<SqlDb_mysql*>(sqlDb);
	if(!sqlDbMysql) {
		return;
	}
	vector<string> tablesForCreatePartitions = sqlDbMysql->getSourceTables(SqlDb_mysql::tt_main | SqlDb_mysql::tt_child, SqlDb_mysql::tt2_static);
	unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
	if(day <= 0 ||
	   isCloud() || cloud_db) {
		sqlDb->setMaxQueryPass(1);
	}
	for(size_t i = 0; i < tablesForCreatePartitions.size(); i++) {
		if((isCloud() || cloud_db) &&
		   sqlDb->existsDayPartition(tablesForCreatePartitions[i], day)) {
			continue;
		}
		if((connectId == 0 && (!use_mysql_2_http() || tablesForCreatePartitions[i] != "http_jj")) ||
		   (connectId == 1 && use_mysql_2_http() && tablesForCreatePartitions[i] == "http_jj")) {
			string _mysql_database = connectId == 0 ? 
						  mysql_database : 
						  mysql_2_database;
			sqlDb->query(string("call ") + (isCloud() ? "" : "`" +_mysql_database + "`.") + "create_partition_v3(" + 
				     (isCloud() || cloud_db ? "NULL" : "'" + _mysql_database + "'") + ", "
				     "'" + tablesForCreatePartitions[i] + "', " + 
				     "'day', " + 
				     intToString(day) + ", " + 
				     (opt_cdr_partition_oldver ? "true" : "false") + ");");
		}
	}
	sqlDb->setMaxQueryPass(maxQueryPassOld);
}

void createMysqlPartitionsSs7() {
	createMysqlPartitionsTable("ss7", opt_ss7_partition_oldver);
}

void createMysqlPartitionsRtpStat() {
	createMysqlPartitionsTable("rtp_stat", opt_rtp_stat_partition_oldver);
}

void createMysqlPartitionsLogSensor() {
	createMysqlPartitionsTable("log_sensor", opt_log_sensor_partition_oldver);
}

void createMysqlPartitionsBillingAgregation(SqlDb *sqlDb) {
	cBillingAgregationSettings agregSettingsInst;
	agregSettingsInst.load(sqlDb);
	sBillingAgregationSettings agregSettings = agregSettingsInst.getAgregSettings();
	if(!agregSettings.enable_by_ip &&
	   !agregSettings.enable_by_number) {
		return;
	}
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	syslog(LOG_NOTICE, "%s", "create billing partitions - begin");
	vector<cBilling::sAgregationTypePart> typeParts = cBilling::getAgregTypeParts(&agregSettings);
	bool tablesExists = true;
	for(unsigned i = 0; i < typeParts.size() && tablesExists; i++) {
		for(unsigned j = 0; j < 2 && tablesExists; j++) {
			string type = typeParts[i].type;
			string type2 = (j == 0 ? "addresses" : "numbers");
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
			for(unsigned j = 0; j < 2; j++) {
				if(!((j == 0 && agregSettings.enable_by_ip) ||
				     (j == 1 && agregSettings.enable_by_number))) {
					continue;
				}
				string type = typeParts[i].type;
				string type_part = typeParts[i].type_part;
				string type2 = (j == 0 ? "addresses" : "numbers");
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
}

void createMysqlPartitionsTable(const char* table, bool partition_oldver) {
	syslog(LOG_NOTICE, "%s", (string("create ") + table + " partitions - begin").c_str());
	SqlDb *sqlDb = createSqlObject();
	unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
	for(int day = 0; day < 3; day++) {
		if(!day ||
		   isCloud() || cloud_db) {
			sqlDb->setMaxQueryPass(1);
		}
		if((isCloud() || cloud_db) &&
		   sqlDb->existsDayPartition(table, day)) {
			continue;
		}
		sqlDb->query(
			string("call ") + (isCloud() ? "" : "`" + string(mysql_database) + "`.") + "create_partition_v3(" + 
			(isCloud() || cloud_db ? "NULL" : "'" + string(mysql_database) + "'") + ", " +
			"'" + table + "', " + 
			"'day', " + 
			intToString(day) + ", " + 
			(partition_oldver ? "true" : "false") + ");");
		sqlDb->setMaxQueryPass(maxQueryPassOld);
	}
	delete sqlDb;
	syslog(LOG_NOTICE, "%s", (string("create ") + table + " partitions - end").c_str());
}

void createMysqlPartitionsIpacc() {
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
}

void dropMysqlPartitionsCdr() {
	extern int opt_cleandatabase_cdr;
	extern int opt_cleandatabase_http_enum;
	extern int opt_cleandatabase_webrtc;
	extern int opt_cleandatabase_register_state;
	extern int opt_cleandatabase_register_failed;
	syslog(LOG_NOTICE, "drop cdr old partitions - begin");
	SqlDb *sqlDb = createSqlObject();
	sqlDb->setDisableLogError();
	sqlDb->setDisableNextAttemptIfError();
	_dropMysqlPartitions("cdr", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_next", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_rtp", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_dtmf", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_sipresp", opt_cleandatabase_cdr, 0, sqlDb);
	if(_save_sip_history || sqlDb->existsTable("cdr_siphistory")) {
		_dropMysqlPartitions("cdr_siphistory", opt_cleandatabase_cdr, 0, sqlDb);
	}
	_dropMysqlPartitions("cdr_tar_part", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_country_code", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_sdp", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_proxy", opt_cleandatabase_cdr, 0, sqlDb);
	_dropMysqlPartitions("cdr_flags", opt_cleandatabase_cdr, 0, sqlDb);
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
	_dropMysqlPartitions("sip_msg", opt_cleandatabase_cdr, 0, sqlDb);
	if(custom_headers_sip_msg) {
		list<string> nextTables = custom_headers_sip_msg->getAllNextTables();
		for(list<string>::iterator iter = nextTables.begin(); iter != nextTables.end(); iter++) {
			_dropMysqlPartitions((*iter).c_str(), opt_cleandatabase_cdr, 0, sqlDb);
		}
	}
	delete sqlDb;
	syslog(LOG_NOTICE, "drop cdr old partitions - end");
}

void dropMysqlPartitionsSs7() {
	extern int opt_cleandatabase_ss7;
	dropMysqlPartitionsTable("ss7", opt_cleandatabase_ss7, 0);
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
	   !agregSettings.enable_by_number) {
		return;
	}
	SqlDb *sqlDb = createSqlObject();
	syslog(LOG_NOTICE, "%s", "drop billing old partitions - begin");
	vector<cBilling::sAgregationTypePart> typeParts = cBilling::getAgregTypeParts(&agregSettings);
		for(unsigned i = 0; i < typeParts.size(); i++) {
			for(unsigned j = 0; j < 2; j++) {
				if(!((j == 0 && agregSettings.enable_by_ip) ||
				     (j == 1 && agregSettings.enable_by_number))) {
					continue;
				}
				string type = typeParts[i].type;
				string type2 = (j == 0 ? "addresses" : "numbers");
				string table = "billing_agregation_" + type + '_' + type2;
				unsigned limit = typeParts[i].limit;
				_dropMysqlPartitions(table.c_str(), 0, limit, sqlDb);
			}
		}
	delete sqlDb;
	syslog(LOG_NOTICE, "%s", "drop billing old partitions - end");
}

void dropMysqlPartitionsTable(const char *table, int cleanParam, unsigned maximumPartitions) {
	syslog(LOG_NOTICE, "%s", (string("drop ") + table + " old partitions - begin").c_str());
	SqlDb *sqlDb = createSqlObject();
	sqlDb->setDisableLogError();
	sqlDb->setDisableNextAttemptIfError();
	_dropMysqlPartitions(table, cleanParam, maximumPartitions, sqlDb);
	delete sqlDb;
	syslog(LOG_NOTICE, "%s", (string("drop ") + table + " old partitions - end").c_str());
}

void _dropMysqlPartitions(const char *table, int cleanParam, unsigned maximumPartitions, SqlDb *sqlDb) {
	if(!sqlDb) {
		sqlDb = createSqlObject();
		sqlDb->setDisableLogError();
		sqlDb->setDisableNextAttemptIfError();
	}
	string limitPartName;
	if(cleanParam > 0) {
		time_t act_time = time(NULL);
		time_t prev_day_time = act_time - cleanParam * 24 * 60 * 60;
		struct tm prevDayTime = time_r(&prev_day_time);
		char limitPartName_buff[20] = "";
		strftime(limitPartName_buff, sizeof(limitPartName_buff), "p%y%m%d", &prevDayTime);
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
	vector<string> exists_partitions;
	if(sqlDb->getPartitions(table, &exists_partitions) > 0) {
		std::sort(exists_partitions.begin(), exists_partitions.end());
		if(maximumPartitions ) {
			if(exists_partitions.size() > maximumPartitions) {
				for(size_t i = 0; i < (exists_partitions.size() - maximumPartitions); i++) {
					partitions[exists_partitions[i]] = 1;
				}
			}
		}
		if(cleanParam > 0) {
			for(size_t i = 0; i < exists_partitions.size() && exists_partitions[i] <= limitPartName; i++) {
				partitions[exists_partitions[i]] = 1;
			}
		}
	}
	for(map<string, int>::iterator iter = partitions.begin(); iter != partitions.end(); iter++) {
		syslog(LOG_NOTICE, "DROP PARTITION %s : %s", table, iter->first.c_str());
		sqlDb->query(string("ALTER TABLE ") + sqlDb->escapeTableName(table) + " DROP PARTITION " + iter->first);
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
		syslog(LOG_ERR, "critical value %lu in column id / table %s", maxId, cdrTables[i].c_str());
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
	time_t actTime = time(NULL);
	bool enableSaveToDb = subject != last_subject_db ||
			      last_subject_db_at + 60 < actTime;
	log->_log(type, subject, message.c_str(), enableSaveToDb);
	if(enableSaveToDb) {
		last_subject_db = subject;
		last_subject_db_at = actTime;
	}
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
	if(!sqlStore && !isCloud() && !opt_nocdr) {
		existsOkLogSensorTable = sqlDb->existsDatabase() && sqlDb->existsTable("log_sensor");
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
					logRow.add("_\\_'SQL'_\\_:@group_id", "ID_parent");
				}
				query_str += sqlDb->insertQuery("log_sensor", logRow) + ";\n";
				if(counter == 0 && items.size() > 1) {
					query_str += "set @group_id = last_insert_id();\n";
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
		sqlStore->query_lock(query_str, STORE_PROC_ID_LOG_SENSOR);
	}
	delete sqlDb;
}

string cLogSensor::last_subject_db = "";
u_int32_t cLogSensor::last_subject_db_at = 0;


cSqlDbCodebook::cSqlDbCodebook(const char *table, const char *columnId, const char *columnStringValue, 
			       unsigned limitTableRows) {
	this->table = table;
	this->columnId = columnId;
	this->columnStringValue = columnStringValue;
	this->limitTableRows = limitTableRows;
	autoLoadPeriod = 0;
	data_overflow = false;
	_sync_data = 0;
	_sync_load = 0;
	lastBeginLoadTime = 0;
	lastEndLoadTime = 0;
}

void cSqlDbCodebook::addCond(const char *field, const char *value) {
	cond.push_back(SqlDb_condField(field, value));
}

void cSqlDbCodebook::setAutoLoadPeriod(unsigned autoLoadPeriod) {
	this->autoLoadPeriod = autoLoadPeriod;
}

unsigned cSqlDbCodebook::getId(const char *stringValue, bool enableInsert, bool enableAutoLoad) {
	if(data_overflow || sverb.disable_cb_cache) {
		return(0);
	}
	unsigned rslt = 0;
	lock_data();
	if(data.size()) {
		map<string, unsigned>::iterator iter = data.find(stringValue);
		if(iter != data.end()) {
			rslt = iter->second;
		}
	}
	if(!rslt && enableInsert) {
		SqlDb *sqlDb = createSqlObject();
		list<SqlDb_condField> cond = this->cond;
		cond.push_back(SqlDb_condField(columnStringValue, stringValue));
		if(sqlDb->select(table, NULL, &cond, 1)) {
			SqlDb_row row;
			if((row = sqlDb->fetchRow())) {
				rslt = atol(row[columnId].c_str());
			}
		}
		if(!rslt) {
			SqlDb_row row;
			row.add(stringValue, columnStringValue);
			for(list<SqlDb_condField>::iterator iter = this->cond.begin(); iter != this->cond.end(); iter++) {
				row.add(iter->value, iter->field);
			}
			int64_t rsltInsert = sqlDb->insert(table, row);
			if(rsltInsert > 0) {
				rslt = rsltInsert;
			}
		}
		delete sqlDb;
	}
	unlock_data();
	if(!rslt && enableAutoLoad && this->autoLoadPeriod && !_sync_load) {
		u_long actTime = getTimeS();
		if(lastBeginLoadTime + this->autoLoadPeriod < actTime &&
		   lastEndLoadTime + this->autoLoadPeriod < actTime) {
			loadInBackground();
		}
	}
	return(rslt);
}

void cSqlDbCodebook::load(SqlDb *sqlDb) {
	if(lock_load(1000000)) {
		_load(&data, &data_overflow, sqlDb);
		unlock_load();
	}
}

void cSqlDbCodebook::loadInBackground() {
	if(lock_load(1000000)) {
		pthread_t thread;
		vm_pthread_create_autodestroy("cSqlDbCodebook::loadInBackground",
					      &thread, NULL, cSqlDbCodebook::_loadInBackground, this, __FILE__, __LINE__);
	}
}

void cSqlDbCodebook::_load(map<string, unsigned> *data, bool *overflow, SqlDb *sqlDb) {
	lastBeginLoadTime = getTimeS();
	data->clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	sqlDb->setMaxQueryPass(2);
	if(sqlDb->rowsInTable(table) > this->limitTableRows) {
		*overflow = true;
	} else {
		if(sqlDb->select(table, NULL, &cond)) {
			SqlDb_rows rows;
			sqlDb->fetchRows(&rows);
			SqlDb_row row;
			while((row = rows.fetchRow())) {
				(*data)[row[columnStringValue]] = atol(row[columnId].c_str());
			}
		}
		*overflow = false;
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	lastEndLoadTime = getTimeS();
}

void *cSqlDbCodebook::_loadInBackground(void *arg) {
	cSqlDbCodebook *me = (cSqlDbCodebook*)arg;
	map<string, unsigned> data;
	bool data_overflow;
	me->_load(&data, &data_overflow);
	if(data.size() || data_overflow) {
		me->lock_data();
		me->data = data;
		me->data_overflow = data_overflow;
		me->unlock_data();
	}
	me->unlock_load();
	return(NULL);
}
