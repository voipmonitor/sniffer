#ifndef SQL_DB_H
#define SQL_DB_H

#include <stdlib.h>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <mysql.h>
#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>
#include <sys/file.h>

#include "tools.h"

#include "cloud_router/cloud_router_client.h"

#include "sql_db_global.h"


#define MYSQL_ROW_FORMAT_COMPRESSED "ROW_FORMAT=COMPRESSED"
#define MARIADB_PAGE_COMPRESSED "PAGE_COMPRESSED=1"

#define NULL_CHAR_PTR (const char*)NULL

#define LIMIT_DAY_PARTITIONS 3
#define LIMIT_DAY_PARTITIONS_INIT 2


using namespace std;


class SqlDb;

class SqlDb_row {
public:
	enum eInternalFieldType {
		_ift_na,
		_ift_string,
		_ift_int,
		_ift_int_u,
		_ift_double,
		_ift_ip,
		_ift_calldate,
		_ift_sql,
		_ift_cb_old,
		_ift_cb_string = 0x10,
		_ift_base      = 0x1F,
		_ift_null      = 0x20
	};
	struct sInternalFieldValue {
		int type;
		union {
			int64_t _int;
			u_int64_t _int_u;
			double _double;
		} v;
		vmIP v_ip;
		int cb_type;
	};
	struct SqlDb_rowField {
		SqlDb_rowField(const char *content, string fieldName = "", int type = 0, unsigned long length = 0, eInternalFieldType ift = _ift_na) {
			if(content) {
				if(type == MYSQL_TYPE_VAR_STRING) {
					this->content = string(content, length);
				} else {
					this->content = content;
				}
			}
			this->fieldName = fieldName;
			this->null = !content;
			this->type = type;
			this->ifv.type = ift | (!content ? _ift_null : 0);
			this->length = length;
		}
		SqlDb_rowField(string content, string fieldName = "", bool null = false, int type = 0, unsigned long length = 0, eInternalFieldType ift = _ift_na) {
			this->content = content;
			this->fieldName = fieldName;
			this->null = null;
			this->type = type;
			this->ifv.type = ift | (null ? _ift_null : 0);
			this->length = length;
		}
		string getContentForCsv();
		string content;
		string fieldName;
		bool null;
		int type;
		sInternalFieldValue ifv;
		unsigned long length;
	};
	SqlDb_row(SqlDb *sqlDb = NULL) {
		this->sqlDb = sqlDb;
		ignoreCheckExistsField = false;
	}
	void setIgnoreCheckExistsField(bool ignoreCheckExistsField = true) {
		this->ignoreCheckExistsField = ignoreCheckExistsField;
	}
	string operator [] (const char *fieldName);
	string operator [] (string fieldName);
	string operator [] (int indexField);
	operator int();
	SqlDb_rowField *add(const char *content, string fieldName = "", int type = 0, unsigned long length = 0, eInternalFieldType ift = _ift_string) {
		if(!ignoreCheckExistsField && fieldName != "") {
			for(size_t i = 0; i < row.size(); i++) {
				if(row[i].fieldName == fieldName) {
					row[i] = SqlDb_rowField(content, fieldName, type, length, ift);
					return(&row[i]);
				}
			}
		}
		row.push_back(SqlDb_rowField(content, fieldName, type, length, ift));
		return(&row[row.size() - 1]);
	}
	SqlDb_rowField *add(string content, string fieldName = "", bool null = false, eInternalFieldType ift = _ift_string) {
		if(!ignoreCheckExistsField && fieldName != "") {
			for(size_t i = 0; i < row.size(); i++) {
				if(row[i].fieldName == fieldName) {
					row[i] = SqlDb_rowField(content, fieldName, null, 0, 0, ift);
					return(&row[i]);
				}
			}
		}
		row.push_back(SqlDb_rowField(content, fieldName, null, 0, 0, ift));
		return(&row[row.size() - 1]);
	}
	SqlDb_rowField *add(int content, string fieldName, bool null = false) {
		SqlDb_rowField *f;
		if(!content && null) {
			f = this->add((const char*)NULL, fieldName, 0, 0, _ift_int);
			f->ifv.v._int = content;
		} else {
			char str_content[100];
			intToString(content, str_content);
			f = this->add(str_content, fieldName, 0, 0, _ift_int);
			f->ifv.v._int = content;
		}
		return(f);
	}
	SqlDb_rowField *add(unsigned int content, string fieldName, bool null = false) {
		SqlDb_rowField *f;
		if(!content && null) {
			f = this->add((const char*)NULL, fieldName, 0, 0, _ift_int_u);
			f->ifv.v._int_u = content;
		} else {
			char str_content[100];
			intToString(content, str_content);
			f = this->add(str_content, fieldName, 0, 0, _ift_int_u);
			f->ifv.v._int_u = content;
		}
		return(f);
	}
	void add(long int content, string fieldName, bool null = false) {
		if(!content && null) {
			this->add((const char*)NULL, fieldName, 0, 0, _ift_int)
			    ->ifv.v._int = content;
		} else {
			char str_content[100];
			intToString(content, str_content);
			this->add(str_content, fieldName, 0, 0, _ift_int)
			    ->ifv.v._int = content;
		}
	}
	void add(unsigned long int content, string fieldName, bool null = false) {
		if(!content && null) {
			this->add((const char*)NULL, fieldName, 0, 0, _ift_int_u)
			    ->ifv.v._int_u = content;
		} else {
			char str_content[100];
			intToString(content, str_content);
			this->add(str_content, fieldName, 0, 0, _ift_int_u)
			    ->ifv.v._int_u = content;
		}
	}
	void add(long long int content, string fieldName, bool null = false) {
		if(!content && null) {
			this->add((const char*)NULL, fieldName, 0, 0, _ift_int)
			    ->ifv.v._int = content;
		} else {
			char str_content[100];
			intToString(content, str_content);
			this->add(str_content, fieldName, 0, 0, _ift_int)
			    ->ifv.v._int = content;
		}
	}
	void add(unsigned long long int content, string fieldName, bool null = false) {
		if(!content && null) {
			this->add((const char*)NULL, fieldName, 0, 0, _ift_int_u)
			    ->ifv.v._int_u = content;
		} else {
			char str_content[100];
			intToString(content, str_content);
			this->add(str_content, fieldName, 0, 0, _ift_int_u)
			    ->ifv.v._int_u = content;
		}
	}
	void add(double content, string fieldName, bool null = false) {
		if(!content && null) {
			this->add((const char*)NULL, fieldName, 0, 0, _ift_double)
			     ->ifv.v._double = content;
		} else {
			char str_content[100];
			floatToString(content, str_content);
			this->add(str_content, fieldName, 0, 0, _ift_double)
			    ->ifv.v._double = content;
		}
	}
	void add(vmIP content, string fieldName, bool null, SqlDb *sqlDb, const char *table);
	void add_calldate(u_int64_t calldate_us, string fieldName, bool use_ms);
	void add_duration(u_int64_t duration_us, string fieldName, bool use_ms, bool round_s = false, u_int64_t limit = 0);
	void add_duration(int64_t duration_us, string fieldName, bool use_ms, bool round_s = false, int64_t limit = 0);
	void add_cb_string(string content, string fieldName, int cb_type);
	int getIndexField(string fieldName) {
		for(size_t i = 0; i < row.size(); i++) {
			if(!strcasecmp(row[i].fieldName.c_str(), fieldName.c_str())) {
				return(i);
			}
		}
		if(this->sqlDb) {
			return(_getIndexField(fieldName));
		}
		return(-1);
	}
	int _getIndexField(string fieldName);
	string getNameField(int indexField) {
		if((unsigned)indexField < row.size()) {
			if(!row[indexField].fieldName.empty()) {
				return(row[indexField].fieldName);
			}
			if(this->sqlDb) {
				return(_getNameField(indexField));
			}
		}
		return("");
	}
	string _getNameField(int indexField);
	unsigned long getLengthField(string fieldName) {
		int indexField = this->getIndexField(fieldName);
		if(indexField >= 0) {
			return(row[indexField].length);
		}
		return(0);
	}
	int getTypeField(string fieldName) {
		int indexField = this->getIndexField(fieldName);
		if(indexField >= 0) {
			return(row[indexField].type);
		}
		return(0);
	}
	SqlDb_rowField *getField(string fieldName, int *_indexField = NULL) {
		int indexField = this->getIndexField(fieldName);
		if(indexField >= 0) {
			if(_indexField) {
				*_indexField = indexField;
			}
			return(&row[indexField]);
		}
		return(NULL);
	}
	bool isEmpty() {
		return(!row.size());
	}
	bool isNull(string fieldName) {
		int indexField = this->getIndexField(fieldName);
		if(indexField >= 0) {
			return(row[indexField].null);
		}
		return(false);
	}
	string implodeFields(string separator = ",", string border = "");
	string implodeFieldsToCsv();
	string implodeContent(string separator = ",", string border = "'", bool enableSqlString = false, bool escapeAll = false);
	string implodeFieldContent(string separator = ",", string fieldBorder = "`", string contentBorder = "'", bool enableSqlString = false, bool escapeAll = false);
	string implodeContentTypeToCsv(bool enableSqlString = false);
	string keyvalList(string separator);
	size_t getCountFields();
	void removeFieldsIfNotContainIn(map<string, int> *fields);
	void clearSqlDb();
	void clear() {
		row.clear();
	}
private:
	SqlDb *sqlDb;
	vector<SqlDb_rowField> row;
	bool ignoreCheckExistsField;
};

class SqlDb_rows {
public:
	SqlDb_rows();
	~SqlDb_rows();
	void push(SqlDb_row *row);
	SqlDb_row &fetchRow();
	void initFetch();
	unsigned countRow();
	operator unsigned();
	void clear();
private:
	list<SqlDb_row> rows;
	list<SqlDb_row>::iterator *iter_rows;
friend class SqlDb;
};

class SqlDb {
public:
	enum eSupportPartitions {
		_supportPartitions_na,
		_supportPartitions_ok,
		_supportPartitions_oldver
	};
	enum eTypeQuery {
		_tq_std,
		_tq_store,
		_tq_redirect
	};
public:
	SqlDb();
	virtual ~SqlDb();
	void setConnectParameters(string server, string user, string password, string database = "", u_int16_t port = 0, string socket = "",
				  bool showversion = true, 
				  mysqlSSLOptions *sslOpt = NULL);
	void setCloudParameters(string cloud_host, string cloud_token, bool cloud_router);
	void setLoginTimeout(ulong loginTimeout);
	void setDisableSecureAuth(bool disableSecureAuth = true);
	virtual bool connect(bool craeteDb = false, bool mainInit = false) = 0;
	virtual void disconnect() = 0;
	virtual bool connected() = 0;
	bool reconnect();
	void setCsvInRemoteResult(bool useCsvInRemoteResult = true);
	virtual bool query(string query, bool callFromStoreProcessWithFixDeadlock = false, const char *dropProcQuery = NULL) = 0;
	bool queryByCurl(string query, bool callFromStoreProcessWithFixDeadlock = false);
	bool queryByRemoteSocket(string query, bool callFromStoreProcessWithFixDeadlock = false, const char *dropProcQuery = NULL);
	int _queryByRemoteSocket(string query, unsigned int pass);
	int processResponseFromQueryBy(const char *response, unsigned pass);
	int processResponseFromCsv(const char *response);
	virtual string prepareQuery(string query, bool nextPass);
	virtual SqlDb_row fetchRow() = 0;
	string fetchValue(int indexField = 0);
	string fetchValue(const char *nameField);
	bool fetchValues(vector<string> *values, list<int> *indexFields);
	bool fetchValues(vector<string> *values, list<string> *nameFields);
	unsigned fetchRows(SqlDb_rows *rows);
	virtual string getJsonResult() { return(""); }
	virtual string getCsvResult() { return(""); }
	virtual string getJsonError() { return(""); }
	virtual string getFieldsStr(list<SqlDb_field> *fields);
	virtual string getCondStr(list<SqlDb_condField> *cond, bool forceLatin1 = false);
	virtual string selectQuery(string table, list<SqlDb_field> *fields = NULL, list<SqlDb_condField> *cond = NULL, unsigned limit = 0, bool forceLatin1 = false);
	virtual string selectQuery(string table, const char *field, const char *condField = NULL, const char *condValue = NULL, unsigned limit = 0, bool forceLatin1 = false);
	virtual string insertQuery(string table, SqlDb_row row, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false, SqlDb_row *row_on_duplicate = NULL);
	virtual string insertOrUpdateQuery(string table, SqlDb_row row, SqlDb_row row_on_duplicate, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual string insertQuery(string table, vector<SqlDb_row> *rows, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual string insertQueryWithLimitMultiInsert(string table, vector<SqlDb_row> *rows, unsigned limitMultiInsert, const char *queriesSeparator = NULL, const char *queriesSeparatorSubst = NULL,
						       bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual string updateQuery(string table, SqlDb_row row, const char *whereCond, bool enableSqlStringInContent = false, bool escapeAll = false);
	virtual string updateQuery(string table, SqlDb_row row, SqlDb_row whereCond, bool enableSqlStringInContent = false, bool escapeAll = false);
	virtual bool select(string table, list<SqlDb_field> *fields = NULL, list<SqlDb_condField> *cond = NULL, unsigned limit = 0, bool forceLatin1 = false);
	virtual bool select(string table, const char *field, const char *condField = NULL, const char *condValue = NULL, unsigned limit = 0, bool forceLatin1 = false);
	virtual int64_t insert(string table, SqlDb_row row);
	virtual int64_t insert(string table, vector<SqlDb_row> *rows);
	virtual bool update(string table, SqlDb_row row, const char *whereCond);
	virtual bool update(string table, SqlDb_row row, SqlDb_row whereCond);
	virtual int getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row, const char *uniqueField2 = NULL);
	virtual int64_t getInsertId() = 0;
	int64_t getQueryRsltIntValue(string query, int indexRslt, int64_t failedResult);
	virtual bool existsDatabase() = 0;
	virtual bool existsTable(const char *table) = 0;
	bool existsTable(string table) { return(existsTable(table.c_str())); }
	virtual bool existsColumn(const char *table, const char *column, string *type = NULL) = 0;
	bool existsColumn(string table, string column, string *type = NULL) { return(existsColumn(table.c_str(), column.c_str(), type)); }
	bool existsMultipleColumns(const char *table, ...);
	void startExistsColumnCache();
	void stopExistsColumnCache();
	void suspendExistsColumnCache();
	void resumeExistsColumnCache();
	bool isEnableExistColumnCache();
	int existsColumnInCache(const char *table, const char *column, string *type = NULL);
	void addColumnToCache(const char *table, const char *column, const char *type);
	void removeTableFromColumnCache(const char *table);
	virtual string getTypeColumn(const char *table, const char *column, bool toLower = true, bool useCache = false) = 0;
	string getTypeColumn(string table, string column, bool toLower = true, bool useCache = false) { return(getTypeColumn(table.c_str(), column.c_str(), toLower, useCache)); }
	virtual bool existsColumnInTypeCache(const char *table, const char *column) = 0;
	bool existsColumnInTypeCache(string table, string column) {
		return(existsColumnInCache(table.c_str(), column.c_str()));
	}
	bool isIPv6Column(string table, string column, bool useCache = true);
	bool isIPv4Column(string table, string column, bool useCache = true) {
		return(!isIPv6Column(table, column, useCache));
	}
	static bool _isIPv6Column(string table, string column);
	static bool _isIPv4Column(string table, string column) {
		return(!_isIPv6Column(table, column));
	}
	virtual int getPartitions(const char *table, list<string> *partitions = NULL, bool useCache = true) = 0;
	int getPartitions(string table, list<string> *partitions, bool useCache) { return(getPartitions(table.c_str(), partitions, useCache)); }
	int getPartitions(const char *table, vector<string> *partitions, bool useCache = true);
	int getPartitions(string table, vector<string> *partitions, bool useCache) { return(getPartitions(table.c_str(), partitions, useCache)); }
	virtual bool existsPartition(const char *table, const char *partition, bool useCache = true) = 0;
	bool existsPartition(string table, string partition, bool useCache) { return(existsPartition(table.c_str(), partition.c_str(), useCache)); }
	bool existsDayPartition(string table, unsigned addDaysToNow, bool useCache = true);
	bool existsHourPartition(string table, unsigned addHoursToNow, bool checkDayPartition = true, bool useCache = true);
	virtual bool emptyTable(const char *table, bool viaTableStatus = false) = 0;
	bool emptyTable(string table, bool viaTableStatus = false) { return(emptyTable(table.c_str(), viaTableStatus)); }
	virtual int64_t rowsInTable(const char *table, bool viaTableStatus = false) = 0;
	int64_t rowsInTable(string table, bool viaTableStatus = false) { return(rowsInTable(table.c_str(), viaTableStatus)); }
	virtual int64_t sizeOfTable(const char *table) = 0;
	int64_t sizeOfTable(string table) { return(sizeOfTable(table.c_str())); }
	virtual bool isOldVerPartition(const char *table) { return(false); }
	bool isOldVerPartition(string table) { return(isOldVerPartition(table.c_str())); }
	virtual int getIndexField(string fieldName);
	virtual string getNameField(int indexField);
	virtual string escape(const char *inputString, int length = 0) = 0;
	virtual string getFieldBorder() {
		return("");
	} 
	virtual string getFieldSeparator() {
		return(",");
	} 
	virtual string getContentBorder() {
		return("'");
	} 
	virtual string getContentSeparator() {
		return(",");
	} 
	virtual string escapeTableName(string tableName) {
		return(tableName);
	}
	virtual bool checkLastError(string /*prefixError*/, bool /*sysLog*/ = false, bool /*clearLastError*/ = false) {
		return(false);
	}
	virtual void evError(int pass) {
	}
	void setLastError(unsigned int lastError, const char *lastErrorString, bool sysLog = false) {
		this->lastError = lastError;
		if(lastErrorString) {
			this->setLastErrorString(lastErrorString, sysLog);
		}
	}
	void setLastError(unsigned int lastError, string lastErrorString, bool sysLog = false) {
		this->setLastError(lastError, lastErrorString.c_str(), sysLog);
	}
	unsigned int getLastError() {
		return(this->lastError);
	}
	void setLastErrorString(string lastErrorString, bool sysLog = false);
	string getLastErrorString() {
		return(this->lastErrorString);
	}
	bool isError() {
		return(this->lastError ||
		       this->lastErrorString != "");
	}
	void clearLastError() {
		this->lastError = 0;
		this->lastErrorString = "";
	}
	bool ignoreLastError();
	void setMaxQueryPass(unsigned int maxQueryPass) {
		this->maxQueryPass = maxQueryPass;
	}
	unsigned int getMaxQueryPass() {
		return(this->maxQueryPass);
	}
	virtual void cleanFields();
	virtual void clean() = 0;
	virtual bool createSchema(int connectId = 0) = 0;
	virtual void createTable(const char *tableName) = 0;
	virtual void checkDbMode() = 0;
	virtual void checkSchema(int connectId = 0, bool checkColumnsSilentLog = false) = 0;
	virtual void updateSensorState() = 0;
	virtual string getTypeDb() = 0;
	virtual string getSubtypeDb() = 0;
	virtual int multi_on() {
		return(1);
	}
	virtual int multi_off() {
		return(1);
	}
	virtual int getDbVersion() {
		return(getDbMajorVersion() * 10000 + 
		       getDbMinorVersion() * 100 + 
		       getDbMinorVersion(1));
	}
	virtual string getDbVersionString() {
		return(intToString(getDbMajorVersion()) + "." +
		       intToString(getDbMinorVersion()) + "." +
		       intToString(getDbMinorVersion(1)));
	}
	virtual int getDbMajorVersion() {
		return(0);
	}
	virtual int getDbMinorVersion(int /*minorLevel*/  = 0) {
		return(0);
	}
	virtual string getDbName() {
		return("");
	}
	virtual int getMaximumPartitions() {
		return(0);
	}
	void setEnableSqlStringInContent(bool enableSqlStringInContent);
	void setDisableNextAttemptIfError();
	void setEnableNextAttemptIfError();
	void setDisableLogError();
	void setEnableLogError();
	void setDisableLogError(bool disableLogError);
	bool getDisableLogError();
	void setSilentConnect();
	bool isCloud() {
		return(cloud_host[0] && cloud_token[0] && cloud_router);
	}
	inline static void addDelayQuery(u_int32_t delay_ms, eTypeQuery typeQuery = _tq_std) {
		__SYNC_ADD(delayQuery_sum_ms[typeQuery], delay_ms);
		__SYNC_INC(delayQuery_count[typeQuery]);
	}
	inline static u_int32_t getAvgDelayQuery(eTypeQuery typeQuery = _tq_std) {
		return(delayQuery_count[typeQuery] ? delayQuery_sum_ms[typeQuery] / delayQuery_count[typeQuery] : 0);
	}
	inline static u_int32_t getCountQuery(eTypeQuery typeQuery = _tq_std) {
		return(delayQuery_count[typeQuery]);
	}
	inline static void resetDelayQuery(eTypeQuery typeQuery = _tq_std) {
		delayQuery_sum_ms[typeQuery] = 0;
		delayQuery_count[typeQuery] = 0;
	}
	inline static void addCountInsert(u_int32_t qc) {
		__SYNC_ADD(insert_count, qc);
	}
	inline static u_int32_t getCountInsert() {
		return(insert_count);
	}
	inline static void resetCountInsert() {
		insert_count = 0;
	}
	bool logNeedAlter(string table, string reason, string alter,
			  bool log, map<string, u_int64_t> *tableSize, bool *existsColumnFlag);
	int checkNeedAlterAdd(string table, string reason, bool tryAlter,
			      bool log, map<string, u_int64_t> *tableSize, bool *existsColumnFlag,
			      ...);
	bool logNeedAlter(string table, string reason, vector<string> alters,
			  bool log, map<string, u_int64_t> *tableSize, bool *existsColumnFlag);
protected:
	string conn_server;
	string conn_user;
	string conn_password;
	string conn_database;
	u_int16_t conn_port;
	string conn_socket;
	char *conn_sslkey;
	char *conn_sslcert;
	char *conn_sslcacert;
	char *conn_sslcapath;
	string conn_sslciphers;
	bool conn_disable_secure_auth;
	string cloud_host;
	string cloud_redirect;
	string cloud_token;
	bool cloud_router;
	bool conn_showversion;
	ulong loginTimeout;
	unsigned int maxQueryPass;
	vector<string> fields;
	vector<int> fields_type;
	bool enableSqlStringInContent;
	bool disableNextAttemptIfError;
	bool disableLogError;
	bool silentConnect;
	bool connecting;
	vector<string> response_data_columns;
	vector<int> response_data_columns_types;
	vector<vector<string_null> > response_data;
	size_t response_data_rows;
	size_t response_data_index;
	unsigned long maxAllowedPacket;
	string prevQuery;
	bool useCsvInRemoteResult;
	map<string, map<string, string> > existsColumn_cache;
	bool existsColumn_cache_enable;
	bool existsColumn_cache_suspend;
	volatile int existsColumn_cache_sync;
	static map<string, map<string, string> > typeColumn_cache;  
	static volatile int typeColumn_cache_sync;
	map<string, list<string> > partitions_cache;
	volatile int partitions_cache_sync;
private:
	unsigned int lastError;
	string lastErrorString;
	static volatile u_int64_t delayQuery_sum_ms[3];
	static volatile u_int32_t delayQuery_count[3];
	static volatile u_int32_t insert_count;
	cSocketBlock *remote_socket;
friend class MySqlStore_process;
};

class SqlDb_mysql : public SqlDb {
public:
	enum eRoutineType {
		procedure,
		function
	};
	enum eTypeTables {
		tt_minor = 1,
		tt_main  = 2,
		tt_child = 4,
		tt_all   = 7
	};
	enum eTypeTables2 {
		tt2_na			= 0,
		tt2_cdr_static		= 1 << 0,
		tt2_cdr_dynamic		= 1 << 1,
		tt2_cdr			= (1 << 0) | (1 << 1),
		tt2_message_static	= 1 << 2,
		tt2_message_dynamic	= 1 << 3,
		tt2_message		= (1 << 2) | (1 << 3),
		tt2_register		= 1 << 4,
		tt2_sip_msg_static	= 1 << 5,
		tt2_sip_msg_dynamic	= 1 << 6,
		tt2_sip_msg		= (1 << 5) | (1 << 6),
		tt2_http_enum		= (1 << 7),
		tt2_webrtc		= (1 << 8),
		tt2_static = tt2_cdr_static | 
			     tt2_message_static | 
			     tt2_register | 
			     tt2_sip_msg_static |
			     tt2_http_enum | 
			     tt2_webrtc
	};
public:
	SqlDb_mysql();
	~SqlDb_mysql();
	bool connect(bool craeteDb = false, bool mainInit = false);
	void disconnect();
	bool connected();
	bool query(string query, bool callFromStoreProcessWithFixDeadlock = false, const char *dropProcQuery = NULL);
	SqlDb_row fetchRow();
	bool fetchQueryResult(vector<string> *fields, vector<int> *fields_types, vector<map<string, string_null> > *rows);
	string getJsonResult(vector<string> *fields, vector<int> *fields_types, vector<map<string, string_null> > *rows);
	string getJsonResult();
	string getCsvResult();
	string getJsonError();
	int64_t getInsertId();
	bool existsDatabase();
	bool existsTable(const char *table);
	list<string> getAllTables();
	bool existsTable(string table) { return(existsTable(table.c_str())); }
	bool existsColumn(const char *table, const char *column, string *type = NULL);
	string getTypeColumn(const char *table, const char *column, bool toLower = true, bool useCache = false);
	bool existsColumnInTypeCache(const char *table, const char *column);
	static bool existsColumnInTypeCache_static(const char *table, const char *column);
	int getPartitions(const char *table, list<string> *partitions = NULL, bool useCache = true);
	bool existsPartition(const char *table, const char *partition, bool useCache = true);
	bool emptyTable(const char *table, bool viaTableStatus = false);
	int64_t rowsInTable(const char *table, bool viaTableStatus = false);
	int64_t sizeOfTable(const char *table);
	bool isOldVerPartition(const char *table);
	string escape(const char *inputString, int length = 0);
	string getFieldBorder() {
		return("`");
	}
	string escapeTableName(string tableName);
	bool isReservedWord(string word);
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void evError(int pass);
	void clean();
	bool createSchema(int connectId = 0);
	bool createSchema_tables_other(int connectId);
	bool createSchema_tables_billing_agregation();
	bool createSchema_table_http_jj(int connectId);
	bool createSchema_table_webrtc(int connectId);
	bool createSchema_alter_other(int connectId);
	bool createSchema_alter_http_jj(int connectId);
	bool createSchema_procedures_other(int connectId);
	bool createSchema_procedure_partition(int connectId, bool abortIfFailed = true);
	bool createSchema_init_cdr_partitions(int connectId);
	string getPartMonthName(string *limitDay_str, int next = 0);
	string getPartDayName(string *limitDay_str, int next = 0);
	string getPartHourName(string *limitHour_str, int next = 0);
	string getPartHourName(string *limitHour_str, int next_day, int hour);
	void saveTimezoneInformation();
	void createTable(const char *tableName);
	void checkDbMode();
	void checkSchema(int connectId = 0, bool checkColumnsSilentLog = false);
	void updateSensorState();
	void checkColumns_cdr(bool log = false);
	void checkColumns_cdr_next(bool log = false);
	void checkColumns_cdr_rtp(bool log = false);
	void checkColumns_cdr_dtmf(bool log = false);
	void checkColumns_cdr_child(bool log = false);
	void checkColumns_cdr_stat(bool log = false);
	void checkColumns_ss7(bool log = false);
	void checkColumns_message(bool log = false);
	void checkColumns_message_child(bool log = false);
	void checkColumns_register(bool log = false);
	void checkColumns_sip_msg(bool log = false);
	void checkColumns_other(bool log = false);
	bool existsExtPrecissionBilling();
	string column_type_datetime_ms();
	string column_type_datetime_child_ms();
	string column_type_duration_ms(const char *base_type = NULL);
	bool checkSourceTables();
	void copyFromSourceTablesMinor(SqlDb_mysql *sqlDbSrc);
	void copyFromSourceTablesMain(SqlDb_mysql *sqlDbSrc,
				      unsigned long limit = 0, bool descDir = false,
				      bool skipRegister = false);
	void copyFromSourceTable(SqlDb_mysql *sqlDbSrc, 
				 const char *tableName, 
				 unsigned long limit, bool descDir = false);
	void copyFromSourceTableSlave(SqlDb_mysql *sqlDbSrc,
				      const char *masterTableName, const char *slaveTableName,
				      const char *slaveIdToMasterColumn, 
				      const char *masterCalldateColumn, const char *slaveCalldateColumn,
				      u_int64_t useMinIdMaster, u_int64_t useMaxIdMaster,
				      unsigned long limit, bool descDir = false, u_int64_t limitMaxId = 0);
	vector<string> getSourceTables(int typeTables = tt_all, int typeTables2 = tt2_na);
	string getTypeDb() {
		return("mysql");
	}
	string getSubtypeDb() {
		return("");
	}
	int multi_on();
	int multi_off();
	int getDbMajorVersion();
	int getDbMinorVersion(int minorLevel  = 0);
	string getDbName();
	int getMaximumPartitions();
	bool isSupportForDatetimeMs();
	bool _getDbVersion();
	bool createRoutine(string routine, string routineName, string routineParamsAndReturn, eRoutineType routineType, bool abortIfFailed = false);
	bool createFunction(string routine, string routineName, string routineParamsAndReturn, bool abortIfFailed = false) {
		return(this->createRoutine(routine, routineName, routineParamsAndReturn, function, abortIfFailed));
	}
	bool createProcedure(string routine, string routineName, string routineParamsAndReturn, bool abortIfFailed = false) {
		return(this->createRoutine(routine, routineName, routineParamsAndReturn, procedure, abortIfFailed));
	}
	MYSQL *getH_Mysql() {
		return(this->hMysql);
	}
	string getOptimalCompressType(bool memoryEngine = false, bool useCache = true);
	string getOptimalCompressType_mysql(bool memoryEngine, bool useCache);
	string getOptimalCompressType_mariadb(bool memoryEngine, bool useCache);
	bool testCreateTable(bool memoryEngine, const char *compressType);
	void setSelectedCompressType(bool memoryEngine, const char *type, const char *subtype = NULL);
private:
	MYSQL *hMysql;
	MYSQL *hMysqlConn;
	MYSQL_RES *hMysqlRes;
	string dbVersion;
	unsigned long mysqlThreadId;
	string selectedCompressType;
	string selectedCompressSubtype;
	string selectedCompressType_memoryEngine;
	string selectedCompressSubtype_memoryEngine;
};

class SqlDb_odbc_bindBufferItem {
public:
	SqlDb_odbc_bindBufferItem(SQLUSMALLINT colNumber, string fieldName, SQLSMALLINT dataType, SQLULEN columnSize, SQLHSTMT hStatement = NULL);
	SqlDb_odbc_bindBufferItem(const SqlDb_odbc_bindBufferItem &other);
	~SqlDb_odbc_bindBufferItem();
	void bindCol(SQLHSTMT hStatement);
	string getContent();
	char *getBuffer();
private:
	SQLUSMALLINT colNumber;
	string fieldName;
	SQLSMALLINT dataType;
	SQLULEN columnSize;
	char *buffer;
	SQLLEN ind;
friend class SqlDb_odbc;
friend class SqlDb_odbc_bindBuffer;
};

class SqlDb_odbc_bindBuffer : public vector<SqlDb_odbc_bindBufferItem*> {
public:
	void addItem(SQLUSMALLINT colNumber, string fieldName, SQLSMALLINT dataType, SQLULEN columnSize, SQLHSTMT hStatement = NULL);
	void bindCols(SQLHSTMT hStatement);
	string getColContent(string fieldName);
	string getColContent(unsigned int fieldIndex);
	char *getColBuffer(unsigned int fieldIndex);
	int getIndexField(string fieldName);
};

class SqlDb_odbc : public SqlDb {
public:
	SqlDb_odbc();
	~SqlDb_odbc();
	void setOdbcVersion(ulong odbcVersion);
	void setSubtypeDb(string subtypeDb);
	bool connect(bool craeteDb = false, bool mainInit = false);
	void disconnect();
	bool connected();
	bool query(string query, bool callFromStoreProcessWithFixDeadlock = false, const char *dropProcQuery = NULL);
	SqlDb_row fetchRow();
	int64_t getInsertId();
	bool existsDatabase();
	bool existsTable(const char *table);
	bool existsColumn(const char *table, const char *column, string *type = NULL);
	string getTypeColumn(const char *table, const char *column, bool toLower = true, bool useCache = false);
	bool existsColumnInTypeCache(const char *table, const char *column);
	int getPartitions(const char *table, list<string> *partitions = NULL, bool useCache = true);
	bool existsPartition(const char *table, const char *partition, bool useCache = true);
	bool emptyTable(const char *table, bool viaTableStatus = false);
	int64_t rowsInTable(const char *table, bool viaTableStatus = false);
	int64_t sizeOfTable(const char *table);
	int getIndexField(string fieldName);
	string escape(const char *inputString, int length = 0);
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void evError(int pass);
	void cleanFields();
	void clean();
	bool createSchema(int connectId = 0);
	void createTable(const char *tableName);
	void checkDbMode();
	void checkSchema(int connectId = 0, bool checkColumnsSilentLog = false);
	void updateSensorState();
	string getTypeDb() {
		return("odbc");
	}
	string getSubtypeDb() {
		return(this->subtypeDb);
	}
private:
	bool okRslt(SQLRETURN rslt) { 
		return rslt == SQL_SUCCESS || rslt == SQL_SUCCESS_WITH_INFO; 
	}
private:
	ulong odbcVersion;
	string subtypeDb;
	SQLHANDLE hEnvironment;
	SQLHANDLE hConnection;
	SQLHANDLE hStatement;
	SqlDb_odbc_bindBuffer bindBuffer;
};

class MySqlStore_process {
public:
	MySqlStore_process(int id_main, int id_2, class MySqlStore *parentStore,
			   const char *host, const char *user, const char *password, const char *database, u_int16_t port, const char *socket,
			   const char *cloud_host, const char *cloud_token, bool cloud_router, int concatLimit, mysqlSSLOptions *mySSLOpt);
	~MySqlStore_process();
	void connect();
	void disconnect();
	bool connected();
	void query(const char *query_str);
	void queryByRemoteSocket(const char *query_str);
	void queryByServiceConnection(const char *query_str);
	void store();
	void _store(string beginProcedure, string endProcedure, list<string> *queries);
	void __store(list<string> *queries);
	void __store(string beginProcedure, string endProcedure, string &queries);
	void exportToFile(FILE *file, bool sqlFormat, bool cleanAfterExport);
	void _exportToFileSqlFormat(FILE *file, string queries);
	void lock() {
		__SYNC_LOCK_USLEEP(lock_sync, 10);
	}
	void unlock() {
		__SYNC_UNLOCK(lock_sync);
	}
	void setEnableTerminatingDirectly(bool enableTerminatingDirectly);
	void setEnableTerminatingIfEmpty(bool enableTerminatingIfEmpty);
	void setEnableTerminatingIfSqlError(bool enableTerminatingIfSqlError);
	void setEnableAutoDisconnect(bool enableAutoDisconnect = true);
	void setConcatLimit(int concatLimit);
	int getConcatLimit();
	void setEnableTransaction(bool enableTransaction = true);
	void setEnableFixDeadlock(bool enableFixDeadlock = true);
	int getIdMain() {
		return(this->id_main);
	}
	int getId2() {
		return(this->id_2);
	}
	size_t getSize() {
		return(this->query_buff.size());
	}
	void waitForTerminate();
private:
	string getInsertFuncName();
private:
	int id_main;
	int id_2;
	MySqlStore *parentStore;
	int concatLimit;
	bool enableTransaction;
	bool enableFixDeadlock;
	pthread_t thread;
	volatile u_int64_t threadRunningCounter;
	u_int64_t lastThreadRunningCounterCheck;
	u_long lastThreadRunningTimeCheck;
	volatile int lock_sync;
	SqlDb *sqlDb;
	deque<string> query_buff;
	bool terminated;
	bool enableTerminatingDirectly;
	bool enableTerminatingIfEmpty;
	bool enableTerminatingIfSqlError;
	bool enableAutoDisconnect;
	u_long lastQueryTime;
	u_long queryCounter;
	cSocketBlock *remote_socket;
	bool check_store_supported;
	bool check_time_supported;
	u_long last_store_iteration_time;
};

class MySqlStore {
private:
	class QFile {
	public:
		QFile() {
			fileZipHandler = NULL;
			createAt = 0;
			flushAt = 0;
			is_open = false;
			_sync = 0;
			_lines = 0;
		}
		bool open(const char *filename, u_int64_t createAt) {
			this->filename = filename;
			this->createAt = createAt;
			fileZipHandler =  new FILE_LINE(30001) FileZipHandler(8 * 1024, 0, FileZipHandler::gzip);
			fileZipHandler->open(tsf_na, this->filename.c_str());
			if(fileZipHandler->_open_write()) {
				is_open = true;
				return(true);
			} else {
				delete fileZipHandler;
				fileZipHandler = NULL;
				return(false);
			}
		}
		void close() {
			filename = "";
			createAt = 0;
			is_open = false;
			if(fileZipHandler) {
				fileZipHandler->close();
				delete fileZipHandler;
				fileZipHandler = NULL;
			}
		}
		bool isOpen() {
			return(is_open);
		}
		bool isExceedPeriod(int period, u_int64_t time = 0) {
			if(!time) {
				time = getTimeMS();
			}
			return(time - createAt > (unsigned)period * 1000);
		}
		void lock() {
			__SYNC_LOCK_USLEEP(_sync, 10);
		}
		void unlock() {
			__SYNC_UNLOCK(_sync);
		}
		string filename;
		FileZipHandler *fileZipHandler;
		u_int64_t createAt;
		u_int64_t flushAt;
		volatile bool is_open;
		volatile int _sync;
		unsigned _lines;
	};
	struct QFileConfig {
		QFileConfig() {
			enable = false;
			enable_charts = false;
			enable_charts_remote = false;
			terminate = false;
			period = 10;
			inotify = false;
			inotify_ready = false;
		}
		string getDirectory();
		bool enableAny() {
			return(enable || enable_charts || enable_charts_remote);
		}
		bool enable;
		bool enable_charts;
		bool enable_charts_remote;
		bool terminate;
		string directory;
		int period;
		bool inotify;
		bool inotify_ready;
	};
	struct LoadFromQFilesThreadData {
		LoadFromQFilesThreadData() {
			id_main = 0;
			storeThreads = 1;
			storeConcatLimit = 0;
			store = NULL;
			thread = 0;
			_sync = 0;
		}
		void addFile(u_int64_t time, const char *file) {
			lock();
			qfiles_load[time] = file;
			unlock();
		}
		void lock() {
			__SYNC_LOCK_USLEEP(_sync, 10);
		}
		void unlock() {
			__SYNC_UNLOCK(_sync);
		}
		int id_main;
		string name;
		int storeThreads;
		int storeConcatLimit;
		MySqlStore *store;
		pthread_t thread;
		map<u_int64_t, string> qfiles_load;
		volatile int _sync;
	};
	struct LoadFromQFilesThreadInfo {
		MySqlStore *store;
		int id_main;
	};
	struct QFileData {
		string filename;
		int id_main;
		u_int64_t time;
	};
public:
	MySqlStore(const char *host, const char *user, const char *password, const char *database, u_int16_t port, const char *socket,
		   const char *cloud_host = NULL, const char *cloud_token = NULL, bool cloud_router = true, mysqlSSLOptions *mySSLOpt = NULL);
	~MySqlStore();
	void queryToFiles(bool enable = true, const char *directory = NULL, int period = 0,
			  bool enable_charts = false, bool enable_charts_remote = false);
	void queryToFilesTerminate();
	void loadFromQFiles(bool enable = true, const char *directory = NULL, int period = 0);
	void queryToFiles_start();
	void loadFromQFiles_start();
	void connect(int id_main, int id_2);
	void query(const char *query_str, int id_main, int id_2);
	void query(string query_str, int id_main, int id_2);
	void query_lock(const char *query_str, int id_main, int id_2);
	void query_lock(list<string> *query_str, int id_main, int id_2, int change_id_2_after = 0);
	void query_lock(string query_str, int id_main, int id_2);
	// qfiles
	void query_to_file(const char *query_str, int id_main);
	string getQFilename(int idc, u_int64_t actTime);
	void closeAllQFiles();
	void clearAllQFiles();
	bool existFilenameInQFiles(const char *filename);
	void enableInotifyForLoadFromQFile(bool enableINotify = true);
	void setInotifyReadyForLoadFromQFile(bool iNotifyReady = true);
	void addLoadFromQFile(int id_main, const char *name, 
			      int storeThreads = 0, int storeConcatLimit = 0,
			      MySqlStore *store = NULL);
	bool fillQFiles(int id_main);
	string getMinQFile(int id_main);
	int getCountQFiles(int id_main);
	bool loadFromQFile(const char *filename, int id_main, bool onlyCheck = false);
	void addFileFromINotify(const char *filename);
	QFileData parseQFilename(const char *filename);
	string getLoadFromQFilesStat(bool processes = false);
	unsigned getLoadFromQFilesCount();
	//
	void lock(int id_main, int id_2);
	void unlock(int id_main, int id_2);
	void setEnableTerminatingDirectly(int id_main, int id_2, bool enableTerminatingDirectly);
	void setEnableTerminatingIfEmpty(int id_main, int id_2, bool enableTerminatingIfEmpty);
	void setEnableTerminatingIfSqlError(int id_main, int id_2, bool enableTerminatingIfSqlError);
	void setEnableAutoDisconnect(int id_main, int id_2, bool enableAutoDisconnect = true);
	void setDefaultConcatLimit(int defaultConcatLimit);
	void setConcatLimit(int id_main, int id_2, int concatLimit);
	int getConcatLimit(int id_main, int id_2);
	void setEnableTransaction(int id_main, int id_2, bool enableTransaction = true);
	void setEnableFixDeadlock(int id_main, int id_2, bool enableFixDeadlock = true);
	MySqlStore_process *find(int id_main, int id_2, MySqlStore *store = NULL);
	MySqlStore_process *check(int id_main, int id_2);
	size_t getAllSize(bool lock = true, bool redirect = false);
	size_t getAllRedirectSize(bool lock = true);
	int getSize(int id_main, int id_2, bool lock = true);
	int getCountActive(int id_main, bool lock = true);
	void fillSizeMap(map<int, int> *size_map, map<int, int> *size_map_by_id_2, bool lock = true);
	string exportToFile(FILE *file, string filename, bool sqlFormat, bool cleanAfterExport);
	void autoloadFromSqlVmExport();
	string getSqlVmExportDirectory();
	bool isCloud() {
		return(cloud_host[0] && cloud_token[0] && cloud_router);
	}
	int findMinId2(int id_main, bool lock = true);
	int getMaxThreadsForStoreId(int id_main);
	int getConcatLimitForStoreId(int id_main);
	bool isRedirectStoreId(int id_main);
private:
	static void *threadQFilesCheckPeriod(void *arg);
	static void *threadLoadFromQFiles(void *arg);
	static void *threadINotifyQFiles(void *arg);
	void lock_processes() {
		__SYNC_LOCK_USLEEP(this->_sync_processes, 10);
	}
	void unlock_processes() {
		__SYNC_UNLOCK(this->_sync_processes);
	}
	void lock_qfiles() {
		__SYNC_LOCK_USLEEP(this->_sync_qfiles, 10);
	}
	void unlock_qfiles() {
		__SYNC_UNLOCK(this->_sync_qfiles);
	}
	bool idIsNotCharts(int id) {
		return(!idIsCharts(id) && !idIsChartsRemote(id));
	}
	bool idIsCharts(int id) {
		return(id == STORE_PROC_ID_CHARTS_CACHE);
	}
	bool idIsChartsRemote(int id) {
		return(id == STORE_PROC_ID_CHARTS_CACHE_REMOTE);
	}
	bool qfileConfigEnable(int id) {
		return(idIsNotCharts(id) ? qfileConfig.enable :
		       idIsCharts(id) ? qfileConfig.enable_charts :
		       idIsChartsRemote(id) ? qfileConfig.enable_charts_remote : false);
	}
private:
	map<int, map<int, MySqlStore_process*> > processes;
	string host;
	string user;
	string password;
	string database;
	u_int16_t port;
	string socket;
	mysqlSSLOptions *mySSLOptions;
	string cloud_host;
	string cloud_token;
	bool cloud_router;
	int defaultConcatLimit;
	volatile int _sync_processes;
	bool enableTerminatingDirectly;
	bool enableTerminatingIfEmpty;
	bool enableTerminatingIfSqlError;
	QFileConfig qfileConfig;
	QFileConfig loadFromQFileConfig;
	map<int, QFile*> qfiles;
	volatile int _sync_qfiles;
	pthread_t qfilesCheckperiodThread;
	map<int, LoadFromQFilesThreadData> loadFromQFilesThreadData;
	pthread_t qfilesINotifyThread;
};

SqlDb *createSqlObject(int connectId = 0);
string sqlDateTimeString(time_t unixTime, bool useGlobalTimeCache = false);
inline void sqlDateTimeString(char *rslt, time_t unixTime, bool useGlobalTimeCache = false);
string sqlDateTimeString_us2ms(u_int64_t unixTime_us, bool useGlobalTimeCache = false);
inline void sqlDateTimeString_us2ms(char *rslt, u_int64_t unixTime_us, bool useGlobalTimeCache = false);
string sqlDateString(time_t unixTime, bool useGlobalTimeCache = false);
string sqlDateTimeString(tm &time);
string sqlDateString(tm &time);
string reverseString(const char *str);
void prepareQuery(string subtypeDb, string &query, bool base, int nextPassQuery);
string prepareQueryForPrintf(const char *query);
string prepareQueryForPrintf(string &query);

void createMysqlPartitionsCdr();
void _createMysqlPartitionsCdr(char type, int next_day, int connectId, SqlDb *sqlDb);
void createMysqlPartitionsSs7();
void createMysqlPartitionsCdrStat();
void createMysqlPartitionsRtpStat();
void createMysqlPartitionsLogSensor();
void createMysqlPartitionsBillingAgregation(SqlDb *sqlDb = NULL);
void createMysqlPartitionsTable(const char* table, bool partition_oldver, bool disableHourPartitions = false, char type = 0);
void createMysqlPartitionsIpacc();
void _createMysqlPartition(string table, char type, int next_day, bool old_ver, const char *database, SqlDb *sqlDb);
void dropMysqlPartitionsCdr();
void dropMysqlPartitionsSs7();
void dropMysqlPartitionsCdrStat();
void dropMysqlPartitionsRtpStat();
void dropMysqlPartitionsLogSensor();
void dropMysqlPartitionsBillingAgregation();
void dropMysqlPartitionsTable(const char *table, int cleanParam, unsigned maximumPartitions);
void _dropMysqlPartitions(const char *table, int cleanParam, unsigned maximumPartitions, SqlDb *sqlDb);
void checkMysqlIdCdrChildTables();


struct sExistsColumns {
	bool cdr_calldate_ms;
	bool cdr_child_next_calldate_ms;
	bool cdr_child_proxy_calldate_ms;
	bool cdr_child_rtp_calldate_ms;
	bool cdr_child_rtp_energylevels_calldate_ms;
	bool cdr_child_dtmf_calldate_ms;
	bool cdr_child_sipresp_calldate_ms;
	bool cdr_child_siphistory_calldate_ms;
	bool cdr_child_tar_part_calldate_ms;
	bool cdr_child_country_code_calldate_ms;
	bool cdr_child_sdp_calldate_ms;
	bool cdr_child_txt_calldate_ms;
	bool cdr_child_flags_calldate_ms;
	bool cdr_callend_ms;
	bool cdr_duration_ms;
	bool cdr_connect_duration_ms;
	bool cdr_progress_time_ms;
	bool cdr_first_rtp_time_ms;
	bool cdr_a_last_rtp_from_end_time_ms;
	bool cdr_b_last_rtp_from_end_time_ms;
	bool cdr_a_last_rtp_from_end_unsigned;
	bool cdr_b_last_rtp_from_end_unsigned;
	bool cdr_response_time_100;
	bool cdr_response_time_xxx;
	bool cdr_reason;
	bool cdr_sipport;
	bool cdr_last_rtp_from_end;
	bool cdr_silencedetect;
	bool cdr_clippingdetect;
	bool cdr_rtp_ptime;
	bool cdr_mos_min;
	bool cdr_mos_xr;
	bool cdr_mos_silence;
	bool cdr_dscp;
	bool cdr_mos_lqo;
	bool cdr_max_retransmission_invite;
	bool cdr_flags;
	bool cdr_price_operator_mult100;
	bool cdr_price_operator_mult1000000;
	bool cdr_price_operator_currency_id;
	bool cdr_price_customer_mult100;
	bool cdr_price_customer_mult1000000;
	bool cdr_price_customer_currency_id;
	bool cdr_sipcallerdip_encaps;
	bool cdr_next_calldate;
	bool cdr_next_spool_index;
	bool cdr_next_hold;
	bool cdr_rtp_calldate;
	bool cdr_rtp_energylevels_calldate;
	bool cdr_rtp_sport;
	bool cdr_rtp_dport;
	bool cdr_rtp_index;
	bool cdr_rtp_flags;
	bool cdr_rtp_duration;
	bool cdr_rtcp_fraclost_pktcount;
	bool cdr_rtcp_rtd;
	bool cdr_rtcp_rtd_w;
	bool cdr_dtmf_calldate;
	bool cdr_dtmf_type;
	bool cdr_sipresp_calldate;
	bool cdr_siphistory_calldate;
	bool cdr_tar_part_calldate;
	bool cdr_country_code_calldate;
	bool cdr_sdp_calldate;
	bool cdr_txt_calldate;
	bool cdr_rtcp_loss_is_smallint_type;
	bool cdr_vlan;
	bool ss7_flags;
	bool ss7_time_iam_ms;
	bool ss7_time_acm_ms;
	bool ss7_time_cpg_ms;
	bool ss7_time_anm_ms;
	bool ss7_time_rel_ms;
	bool ss7_time_rlc_ms;
	bool ss7_duration_ms;
	bool ss7_connect_duration_ms;
	bool ss7_progress_time_ms;
	bool message_calldate_ms;
	bool message_child_proxy_calldate_ms;
	bool message_child_country_code_calldate_ms;
	bool message_child_flags_calldate_ms;
	bool message_content_length;
	bool message_response_time;
	bool message_spool_index;
	bool message_vlan;
	bool register_calldate_ms;
	bool register_state_created_at_ms;
	bool register_failed_created_at_ms;
	bool register_rrd_count;
	bool register_state_spool_index;
	bool register_failed_spool_index;
	bool register_state_flags;
	bool register_state_vlan;
	bool register_failed_vlan;
	bool register_state_sipcallerdip_encaps;
	bool register_failed_sipcallerdip_encaps;
	bool register_state_digestrealm;
	bool register_failed_digestrealm;
	bool sip_msg_time_ms;
	bool sip_msg_request_time_ms;
	bool sip_msg_response_time_ms;
	bool sip_msg_vlan;
	bool ssl_sessions_id_sensor_is_unsigned;
};

struct sTableCalldateMsIndik {
	sTableCalldateMsIndik(bool *ms, const char *table, const char *calldate = "calldate") {
		this->ms = ms;
		this->table = table;
		this->calldate = calldate;
	}
	bool *ms;
	string table;
	string calldate;
};

class cLogSensor {
public: 
	enum eType {
	      _na,
	      debug,
	      info,
	      notice,
	      warning,
	      error,
	      critical,
	      alert,
	      emergency
	};
private:
	struct sItem {
		sItem() {
			extern int opt_id_sensor;
			time = getTimeS();
			id_sensor = opt_id_sensor;
			type = _na;
			enableSaveToDb = true;
		};
		u_int32_t time;
		int id_sensor;
		eType type;
		string subject;
		string message;
		bool enableSaveToDb;
	};
public:
	cLogSensor();
	static void log(eType type, const char *subject, const char *formatMessage = NULL, ...);
	static cLogSensor *begin(eType type, const char *subject, const char *formatMessage = NULL, ...);
	static void log(cLogSensor *log, const char *subject, const char *formatMessage = NULL, ...);
	void log(const char *subject, const char *formatMessage = NULL, ...);
	static void end(cLogSensor *log);
	static void end(list<cLogSensor*> logs);
	void end() {
		end(this);
	}
private:
	void _log(eType type, const char *subject, const char *message, bool enableSaveToDb = true);
	void _log(const char *subject, const char *message);
	void _end();
	void _save();
private:
	list<sItem> items;
	static map<string, u_int32_t> previous_logs;
	static volatile int previous_logs_sync;
};


class sCreatePartitions {
public:
	sCreatePartitions() {
		init();
	}
	void init() {
		createCdr = false;
		dropCdr = false;
		createSs7 = false;
		dropSs7 = false;
		createCdrStat = false;
		dropCdrStat = false;
		createRtpStat = false;
		dropRtpStat = false;
		createLogSensor = false;
		dropLogSensor = false;
		createIpacc = false;
		createBilling = false;
		dropBilling = false;
		_runInThread = false;
	}
	bool isSet() {
		return(createCdr || dropCdr || 
		       createSs7 || dropSs7 ||
		       createCdrStat || dropCdrStat ||
		       createRtpStat || dropRtpStat ||
		       createLogSensor || dropLogSensor ||
		       createIpacc || 
		       createBilling || dropBilling);
	}
	void createPartitions(bool inThread = false);
	static void *_createPartitions(void *arg);
	void doCreatePartitions();
	void doDropPartitions();
	void setIndicPartitionOperations(bool set = true);
	void unsetIndicPartitionOperations() {
		setIndicPartitionOperations(false);
	}
public:
	bool createCdr;
	bool dropCdr;
	bool createSs7;
	bool dropSs7;
	bool createCdrStat;
	bool createRtpStat;
	bool dropCdrStat;
	bool dropRtpStat;
	bool createLogSensor;
	bool dropLogSensor;
	bool createIpacc;
	bool createBilling;
	bool dropBilling;
	bool _runInThread;
	static volatile int in_progress;
};


void dbDataInit(SqlDb *sqlDb);
void dbDataTerm();
bool dbDataIsSet();


#endif
