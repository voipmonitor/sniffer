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


using namespace std;


class SqlDb;

class SqlDb_field {
public:
	SqlDb_field(const char *field, const char *alias = NULL, bool needEscapeField = true) {
		this->field = field;
		if(alias) {
			this->alias = alias;
		}
		this->needEscapeField = needEscapeField;
	}
	SqlDb_field(string field, string alias, bool needEscapeField = true) {
		this->field = field;
		this->alias = alias;
		this->needEscapeField = needEscapeField;
	}
public:
	string field;
	string alias;
	bool needEscapeField;
};

class SqlDb_condField {
public:
	SqlDb_condField(const char *field, const char *value, bool needEscapeField = true, bool needEscapeValue = true) {
		this->field = field;
		this->value = value;
		this->needEscapeField = needEscapeField;
		this->needEscapeValue = needEscapeValue;
	}
	SqlDb_condField(string field, string value, bool needEscapeField = true, bool needEscapeValue = true) {
		this->field = field;
		this->value = value;
		this->needEscapeField = needEscapeField;
		this->needEscapeValue = needEscapeValue;
	}
	SqlDb_condField &setOper(const char *oper) {
		this->oper = oper;
		return(*this);
	}
public:
	string field;
	string value;
	string oper;
	bool needEscapeField;
	bool needEscapeValue;
};

class SqlDb_row {
public:
	struct SqlDb_rowField {
		SqlDb_rowField(const char *content, string fieldName = "") {
			if(content) {
				this->content = content;
			}
			this->fieldName = fieldName;
			this->null = !content;
		}
		SqlDb_rowField(string content, string fieldName = "", bool null = false) {
			this->content = content;
			this->fieldName = fieldName;
			this->null = null;
		}
		string content;
		string fieldName;
		bool null;
	};
	SqlDb_row(SqlDb *sqlDb = NULL) {
		this->sqlDb = sqlDb;
	}
	string operator [] (const char *fieldName);
	string operator [] (string fieldName);
	string operator [] (int indexField);
	operator int();
	void add(const char *content, string fieldName = "");
	void add(string content, string fieldName = "", bool null = false);
	void add(int content, string fieldName, bool null = false);
	void add(unsigned int content, string fieldName, bool null = false);
	void add(long int content, string fieldName, bool null = false);
	void add(unsigned long int content, string fieldName, bool null = false);
	void add(long long int content, string fieldName, bool null = false);
	void add(unsigned long long int content, string fieldName, bool null = false);
	void add(double content,  string fieldName, bool null = false);
	int getIndexField(string fieldName);
	string getNameField(int indexField);
	bool isEmpty();
	bool isNull(string fieldName);
	string implodeFields(string separator = ",", string border = "");
	string implodeContent(string separator = ",", string border = "'", bool enableSqlString = false, bool escapeAll = false);
	string implodeFieldContent(string separator = ",", string fieldBorder = "`", string contentBorder = "'", bool enableSqlString = false, bool escapeAll = false);
	string keyvalList(string separator);
	size_t getCountFields();
	void removeFieldsIfNotContainIn(map<string, int> *fields);
	void clearSqlDb();
private:
	SqlDb *sqlDb;
	vector<SqlDb_rowField> row;
};

class SqlDb_rows {
public:
	SqlDb_rows();
	~SqlDb_rows();
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
	struct sCloudDataItem {
		sCloudDataItem(const char *str, bool null) {
			if(str) {
				this->str = str;
				this->null = null;
			} else {
				this->null = true;
			}
		}
		string str;
		bool null;
	};
public:
	SqlDb();
	virtual ~SqlDb();
	void setConnectParameters(string server, string user, string password, string database = "", u_int16_t port = 0, bool showversion = true);
	void setCloudParameters(string cloud_host, string cloud_token, bool cloud_router);
	void setLoginTimeout(ulong loginTimeout);
	void setDisableSecureAuth(bool disableSecureAuth = true);
	virtual bool connect(bool craeteDb = false, bool mainInit = false) = 0;
	virtual void disconnect() = 0;
	virtual bool connected() = 0;
	bool reconnect();
	virtual bool query(string query, bool callFromStoreProcessWithFixDeadlock = false, const char *dropProcQuery = NULL) = 0;
	bool queryByCurl(string query, bool callFromStoreProcessWithFixDeadlock = false);
	bool queryByRemoteSocket(string query, bool callFromStoreProcessWithFixDeadlock = false, const char *dropProcQuery = NULL);
	int _queryByRemoteSocket(string query, unsigned int pass);
	int processResponseFromQueryBy(const char *response, unsigned pass);
	virtual string prepareQuery(string query, bool nextPass);
	virtual SqlDb_row fetchRow() = 0;
	unsigned fetchRows(SqlDb_rows *rows);
	virtual string getJsonResult() { return(""); }
	virtual string getJsonError() { return(""); }
	virtual string getFieldsStr(list<SqlDb_field> *fields);
	virtual string getCondStr(list<SqlDb_condField> *cond);
	virtual string selectQuery(string table, list<SqlDb_field> *fields = NULL, list<SqlDb_condField> *cond = NULL, unsigned limit = 0);
	virtual string selectQuery(string table, const char *field, const char *condField = NULL, const char *condValue = NULL, unsigned limit = 0);
	virtual string insertQuery(string table, SqlDb_row row, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false, SqlDb_row *row_on_duplicate = NULL);
	virtual string insertOrUpdateQuery(string table, SqlDb_row row, SqlDb_row row_on_duplicate, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual string insertQuery(string table, vector<SqlDb_row> *rows, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual string insertQueryWithLimitMultiInsert(string table, vector<SqlDb_row> *rows, unsigned limitMultiInsert, const char *queriesSeparator = NULL,
						       bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual string updateQuery(string table, SqlDb_row row, const char *whereCond, bool enableSqlStringInContent = false, bool escapeAll = false);
	virtual string updateQuery(string table, SqlDb_row row, SqlDb_row whereCond, bool enableSqlStringInContent = false, bool escapeAll = false);
	virtual bool select(string table, list<SqlDb_field> *fields = NULL, list<SqlDb_condField> *cond = NULL, unsigned limit = 0);
	virtual bool select(string table, const char *field, const char *condField = NULL, const char *condValue = NULL, unsigned limit = 0);
	virtual int64_t insert(string table, SqlDb_row row);
	virtual int64_t insert(string table, vector<SqlDb_row> *rows);
	virtual bool update(string table, SqlDb_row row, const char *whereCond);
	virtual int getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row, const char *uniqueField2 = NULL);
	virtual int64_t getInsertId() = 0;
	int64_t getQueryRsltIntValue(string query, int indexRslt, int64_t failedResult);
	virtual bool existsDatabase() = 0;
	virtual bool existsTable(const char *table) = 0;
	bool existsTable(string table) { return(existsTable(table.c_str())); }
	virtual bool existsColumn(const char *table, const char *column) = 0;
	bool existsColumn(string table, string column) { return(existsColumn(table.c_str(), column.c_str())); }
	void startExistsColumnCache();
	void stopExistsColumnCache();
	void suspendExistsColumnCache();
	void resumeExistsColumnCache();
	bool isEnableExistColumnCache();
	int existsColumnInCache(const char *table, const char *column);
	void addColumnToCache(const char *table, const char *column);
	virtual string getTypeColumn(const char *table, const char *column, bool toLower = true) = 0;
	string getTypeColumn(string table, string column, bool toLower = true) { return(getTypeColumn(table.c_str(), column.c_str(), toLower)); }
	virtual int getPartitions(const char *table, list<string> *partitions = NULL, bool useCache = true) = 0;
	int getPartitions(string table, list<string> *partitions, bool useCache) { return(getPartitions(table.c_str(), partitions, useCache)); }
	int getPartitions(const char *table, vector<string> *partitions, bool useCache = true);
	int getPartitions(string table, vector<string> *partitions, bool useCache) { return(getPartitions(table.c_str(), partitions, useCache)); }
	virtual bool existsPartition(const char *table, const char *partition, bool useCache = true) = 0;
	bool existsPartition(string table, string partition, bool useCache) { return(existsPartition(table.c_str(), partition.c_str(), useCache)); }
	bool existsDayPartition(string table, unsigned addDaysToNow, bool useCache = true);
	virtual bool emptyTable(const char *table) = 0;
	bool emptyTable(string table) { return(emptyTable(table.c_str())); }
	virtual int64_t rowsInTable(const char *table) = 0;
	int64_t rowsInTable(string table) { return(rowsInTable(table.c_str())); }
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
	virtual void checkSchema(int connectId = 0, bool checkColumns = false) = 0;
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
		return(isCloudRouter() || isCloudSsh());
	}
	bool isCloudRouter() {
		return(cloud_host[0] && cloud_token[0] && cloud_router);
	}
	bool isCloudSsh() {
		return(cloud_host[0] && cloud_token[0] && !cloud_router);
	}
	static void addDelayQuery(u_int32_t delay_ms);
	static u_int32_t getAvgDelayQuery();
	static void resetDelayQuery();
	void logNeedAlter(string table, string reason, string alter,
			  bool log, map<string, u_int64_t> *tableSize, bool *existsColumnFlag);
protected:
	string conn_server;
	string conn_user;
	string conn_password;
	string conn_database;
	u_int16_t conn_port;
	bool conn_disable_secure_auth;
	string cloud_host;
	string cloud_redirect;
	string cloud_token;
	bool cloud_router;
	bool conn_showversion;
	ulong loginTimeout;
	unsigned int maxQueryPass;
	vector<string> fields;
	bool enableSqlStringInContent;
	bool disableNextAttemptIfError;
	bool disableLogError;
	bool silentConnect;
	bool connecting;
	vector<string> response_data_columns;
	vector<vector<sCloudDataItem> > response_data;
	size_t response_data_rows;
	size_t response_data_index;
	unsigned long maxAllowedPacket;
	string prevQuery;
private:
	unsigned int lastError;
	string lastErrorString;
	static volatile u_int64_t delayQuery_sum_ms;
	static volatile u_int32_t delayQuery_count;
	cSocketBlock *remote_socket;
	map<string, list<string> > existsColumnCache;
	bool existsColumnCache_enable;
	bool existsColumnCache_suspend;
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
	bool fetchQueryResult(vector<string> *fields, vector<map<string, string_null> > *rows);
	string getJsonResult(vector<string> *fields, vector<map<string, string_null> > *rows);
	string getJsonResult();
	string getJsonError();
	int64_t getInsertId();
	bool existsDatabase();
	bool existsTable(const char *table);
	bool existsTable(string table) { return(existsTable(table.c_str())); }
	bool existsColumn(const char *table, const char *column);
	string getTypeColumn(const char *table, const char *column, bool toLower = true);
	int getPartitions(const char *table, list<string> *partitions = NULL, bool useCache = true);
	bool existsPartition(const char *table, const char *partition, bool useCache = true);
	bool emptyTable(const char *table);
	int64_t rowsInTable(const char *table);
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
	string getPartDayName(string &limitDay_str, bool enableOldPartition = true);
	void saveTimezoneInformation();
	void createTable(const char *tableName);
	void checkDbMode();
	void checkSchema(int connectId = 0, bool checkColumns = false);
	void updateSensorState();
	void checkColumns_cdr(bool log = false);
	void checkColumns_cdr_next(bool log = false);
	void checkColumns_cdr_rtp(bool log = false);
	void checkColumns_cdr_dtmf(bool log = false);
	void checkColumns_message(bool log = false);
	void checkColumns_register(bool log = false);
	void checkColumns_other(bool log = false);
	bool isExtPrecissionBilling();
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
				      unsigned long limit, bool descDir = false);
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
private:
	MYSQL *hMysql;
	MYSQL *hMysqlConn;
	MYSQL_RES *hMysqlRes;
	string dbVersion;
	unsigned long mysqlThreadId;
	map<string, list<string> > partitions_cache;
	volatile int partitions_cache_sync;
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
	bool existsColumn(const char *table, const char *column);
	string getTypeColumn(const char *table, const char *column, bool toLower = true);
	int getPartitions(const char *table, list<string> *partitions = NULL, bool useCache = true);
	bool existsPartition(const char *table, const char *partition, bool useCache = true);
	bool emptyTable(const char *table);
	int64_t rowsInTable(const char *table);
	int getIndexField(string fieldName);
	string escape(const char *inputString, int length = 0);
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void evError(int pass);
	void cleanFields();
	void clean();
	bool createSchema(int connectId = 0);
	void createTable(const char *tableName);
	void checkDbMode();
	void checkSchema(int connectId = 0, bool checkColumns = false);
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
	MySqlStore_process(int id, const char *host, const char *user, const char *password, const char *database, u_int16_t port,
			   const char *cloud_host, const char *cloud_token, bool cloud_router,
			   int concatLimit);
	~MySqlStore_process();
	void connect();
	void disconnect();
	bool connected();
	void query(const char *query_str);
	void queryByRemoteSocket(const char *query_str);
	void store();
	void _store(string beginProcedure, string endProcedure, string queries);
	void exportToFile(FILE *file, bool sqlFormat, bool cleanAfterExport);
	void _exportToFileSqlFormat(FILE *file, string queries);
	void lock();
	void unlock();
	void setEnableTerminatingDirectly(bool enableTerminatingDirectly);
	void setEnableTerminatingIfEmpty(bool enableTerminatingIfEmpty);
	void setEnableTerminatingIfSqlError(bool enableTerminatingIfSqlError);
	void setEnableAutoDisconnect(bool enableAutoDisconnect = true);
	void setConcatLimit(int concatLimit);
	int getConcatLimit();
	void setEnableTransaction(bool enableTransaction = true);
	void setEnableFixDeadlock(bool enableFixDeadlock = true);
	int getId() {
		return(this->id);
	}
	size_t getSize() {
		return(this->query_buff.size());
	}
	bool operator < (const MySqlStore_process& other) const { 
		return(this->id < other.id); 
	}
	void waitForTerminate();
private:
	string getInsertFuncName();
private:
	int id;
	int concatLimit;
	bool enableTransaction;
	bool enableFixDeadlock;
	pthread_t thread;
	volatile u_int64_t threadRunningCounter;
	u_int64_t lastThreadRunningCounterCheck;
	u_long lastThreadRunningTimeCheck;
	pthread_mutex_t lock_mutex;
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
		}
		bool open(const char *filename, u_long createAt) {
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
		bool isExceedPeriod(int period, u_long time = 0) {
			if(!time) {
				time = getTimeMS();
			}
			return(time - createAt > (unsigned)period * 1000);
		}
		void lock() {
			while(__sync_lock_test_and_set(&_sync, 1));
		}
		void unlock() {
			__sync_lock_release(&_sync);
		}
		string filename;
		FileZipHandler *fileZipHandler;
		u_long createAt;
		u_long flushAt;
		volatile bool is_open;
		volatile int _sync;
	};
	struct QFileConfig {
		QFileConfig() {
			enable = false;
			terminate = false;
			period = 10;
			inotify = false;
			inotify_ready = false;
		}
		string getDirectory();
		bool enable;
		bool terminate;
		string directory;
		int period;
		bool inotify;
		bool inotify_ready;
	};
	struct LoadFromQFilesThreadData {
		LoadFromQFilesThreadData() {
			id = 0;
			storeThreads = 1;
			storeConcatLimit = 0;
			store = NULL;
			thread = 0;
			_sync = 0;
		}
		void addFile(u_long time, const char *file) {
			lock();
			qfiles_load[time] = file;
			unlock();
		}
		void lock() {
			while(__sync_lock_test_and_set(&_sync, 1));
		}
		void unlock() {
			__sync_lock_release(&_sync);
		}
		int id;
		string name;
		int storeThreads;
		int storeConcatLimit;
		MySqlStore *store;
		pthread_t thread;
		map<u_long, string> qfiles_load;
		volatile int _sync;
	};
	struct LoadFromQFilesThreadInfo {
		MySqlStore *store;
		int id;
	};
	struct QFileData {
		string filename;
		int id;
		u_long time;
	};
public:
	MySqlStore(const char *host, const char *user, const char *password, const char *database, u_int16_t port,
		   const char *cloud_host = NULL, const char *cloud_token = NULL, bool cloud_router = true);
	~MySqlStore();
	void queryToFiles(bool enable = true, const char *directory = NULL, int period = 0);
	void queryToFilesTerminate();
	void loadFromQFiles(bool enable = true, const char *directory = NULL, int period = 0);
	void queryToFiles_start();
	void loadFromQFiles_start();
	void connect(int id);
	void query(const char *query_str, int id);
	void query(string query_str, int id);
	void query_lock(const char *query_str, int id);
	void query_lock(string query_str, int id);
	// qfiles
	void query_to_file(const char *query_str, int id);
	string getQFilename(int idc, u_long actTime);
	int convIdForQFile(int id);
	void closeAllQFiles();
	void clearAllQFiles();
	bool existFilenameInQFiles(const char *filename);
	void enableInotifyForLoadFromQFile(bool enableINotify = true);
	void setInotifyReadyForLoadFromQFile(bool iNotifyReady = true);
	void addLoadFromQFile(int id, const char *name, 
			      int storeThreads = 0, int storeConcatLimit = 0,
			      MySqlStore *store = NULL);
	bool fillQFiles(int id);
	string getMinQFile(int id);
	int getCountQFiles(int id);
	bool loadFromQFile(const char *filename, int id, bool onlyCheck = false);
	void addFileFromINotify(const char *filename);
	QFileData parseQFilename(const char *filename);
	string getLoadFromQFilesStat(bool processes = false);
	unsigned getLoadFromQFilesCount();
	//
	void lock(int id);
	void unlock(int id);
	void setEnableTerminatingDirectly(int id, bool enableTerminatingDirectly);
	void setEnableTerminatingIfEmpty(int id, bool enableTerminatingIfEmpty);
	void setEnableTerminatingIfSqlError(int id, bool enableTerminatingIfSqlError);
	void setEnableAutoDisconnect(int id, bool enableAutoDisconnect = true);
	void setDefaultConcatLimit(int defaultConcatLimit);
	void setConcatLimit(int id, int concatLimit);
	int getConcatLimit(int id);
	void setEnableTransaction(int id, bool enableTransaction = true);
	void setEnableFixDeadlock(int id, bool enableFixDeadlock = true);
	MySqlStore_process *find(int id, MySqlStore *store = NULL);
	MySqlStore_process *check(int id);
	size_t getAllSize(bool lock = true);
	int getSize(int id, bool lock = true);
	int getSizeMult(int n, ...);
	int getSizeVect(int id1, int id2, bool lock = true);
	int getActiveIdsVect(int id1, int id2, bool lock = true);
	string exportToFile(FILE *file, string filename, bool sqlFormat, bool cleanAfterExport);
	void autoloadFromSqlVmExport();
	string getSqlVmExportDirectory();
	bool isCloud() {
		return(isCloudRouter() || isCloudSsh());
	}
	bool isCloudRouter() {
		return(cloud_host[0] && cloud_token[0] && cloud_router);
	}
	bool isCloudSsh() {
		return(cloud_host[0] && cloud_token[0] && !cloud_router);
	}
	int convStoreId(int id);
	int getMaxThreadsForStoreId(int id);
	int getConcatLimitForStoreId(int id);
private:
	static void *threadQFilesCheckPeriod(void *arg);
	static void *threadLoadFromQFiles(void *arg);
	static void *threadINotifyQFiles(void *arg);
	void lock_processes() {
		while(__sync_lock_test_and_set(&this->_sync_processes, 1));
	}
	void unlock_processes() {
		__sync_lock_release(&this->_sync_processes);
	}
	void lock_qfiles() {
		while(__sync_lock_test_and_set(&this->_sync_qfiles, 1));
	}
	void unlock_qfiles() {
		__sync_lock_release(&this->_sync_qfiles);
	}
private:
	map<int, MySqlStore_process*> processes;
	string host;
	string user;
	string password;
	string database;
	u_int16_t port;
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
string sqlDateTimeString(time_t unixTime);
string sqlDateString(time_t unixTime);
string sqlDateTimeString(tm &time);
string sqlDateString(tm &time);
string sqlEscapeString(string inputStr, const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
string sqlEscapeString(const char *inputStr, int length = 0, const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
void fillEscTables();
string _sqlEscapeString(const char *inputString, int length, const char *typeDb);
void _sqlEscapeString(const char *inputStr, int length, char *outputStr, const char *typeDb, bool checkUtf = false);
string sqlEscapeStringBorder(string inputStr, char borderChar = '\'', const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
string sqlEscapeStringBorder(const char *inputStr, char borderChar = '\'', const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
bool isSqlDriver(const char *sqlDriver, const char *checkSqlDriver = NULL);
bool isTypeDb(const char *typeDb, const char *checkSqlDriver = NULL, const char *checkOdbcDriver = NULL);
bool cmpStringIgnoreCase(const char* str1, const char* str2);
string reverseString(const char *str);
void prepareQuery(string subtypeDb, string &query, bool base, int nextPassQuery);
string prepareQueryForPrintf(const char *query);
string prepareQueryForPrintf(string &query);

void createMysqlPartitionsCdr();
void _createMysqlPartitionsCdr(int day, int connectId, SqlDb *sqlDb);
void createMysqlPartitionsSs7();
void createMysqlPartitionsRtpStat();
void createMysqlPartitionsLogSensor();
void createMysqlPartitionsBillingAgregation(SqlDb *sqlDb = NULL);
void createMysqlPartitionsTable(const char* table, bool partition_oldver);
void createMysqlPartitionsIpacc();
void dropMysqlPartitionsCdr();
void dropMysqlPartitionsSs7();
void dropMysqlPartitionsRtpStat();
void dropMysqlPartitionsLogSensor();
void dropMysqlPartitionsBillingAgregation();
void dropMysqlPartitionsTable(const char *table, int cleanParam, unsigned maximumPartitions);
void _dropMysqlPartitions(const char *table, int cleanParam, unsigned maximumPartitions, SqlDb *sqlDb);
void checkMysqlIdCdrChildTables();


struct sExistsColumns {
	bool cdr_response_time;
	bool cdr_reason;
	bool cdr_sipport;
	bool cdr_last_rtp_from_end;
	bool cdr_silencedetect;
	bool cdr_clippingdetect;
	bool cdr_rtp_ptime;
	bool cdr_mos_min;
	bool cdr_mos_xr;
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
	bool cdr_next_calldate;
	bool cdr_next_spool_index;
	bool cdr_next_hold;
	bool cdr_rtp_calldate;
	bool cdr_rtp_sport;
	bool cdr_rtp_dport;
	bool cdr_rtp_index;
	bool cdr_rtp_flags;
	bool cdr_rtcp_fraclost_pktcount;
	bool cdr_dtmf_calldate;
	bool cdr_dtmf_type;
	bool cdr_sipresp_calldate;
	bool cdr_siphistory_calldate;
	bool cdr_tar_part_calldate;
	bool cdr_country_code_calldate;
	bool cdr_sdp_calldate;
	bool message_content_length;
	bool message_response_time;
	bool message_spool_index;
	bool register_rrd_count;
	bool register_state_spool_index;
	bool register_failed_spool_index;
	bool register_state_flags;
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
	static string last_subject_db;
	static u_int32_t last_subject_db_at;
};


class cSqlDbCodebook {
public:
	cSqlDbCodebook(const char *table, const char *columnId, const char *columnStringValue, 
		       unsigned limitTableRows = 100000);
	void addCond(const char *field, const char *value);
	void setAutoLoadPeriod(unsigned autoLoadPeriod);
	unsigned getId(const char *stringValue, bool enableInsert = false, bool enableAutoLoad = false);
	void load(SqlDb *sqlDb = NULL);
	void loadInBackground();
private:
	void _load(map<string, unsigned> *data, bool *overflow, SqlDb *sqlDb = NULL);
	static void *_loadInBackground(void *arg);
	void lock_data() {
		while(__sync_lock_test_and_set(&_sync_data, 1));
	}
	void unlock_data() {
		__sync_lock_release(&_sync_data);
	}
	void lock_load() {
		while(__sync_lock_test_and_set(&_sync_load, 1));
	}
	bool lock_load(int timeout_us) {
		while(__sync_lock_test_and_set(&_sync_load, 1)) {
			timeout_us -= 100;
			if(timeout_us < 0) {
				return(false);
			}
			usleep(100);
		}
		return(true);
	}
	void unlock_load() {
		__sync_lock_release(&_sync_load);
	}
private:
	string table;
	string columnId;
	string columnStringValue;
	unsigned limitTableRows;
	list<SqlDb_condField> cond;
	unsigned autoLoadPeriod;
	map<string, unsigned> data;
	bool data_overflow;
	volatile int _sync_data;
	volatile int _sync_load;
	u_long lastBeginLoadTime;
	u_long lastEndLoadTime;
};


#endif
