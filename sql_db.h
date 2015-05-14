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


using namespace std;


class SqlDb;

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
		SqlDb_rowField(string content, string fieldName = "") {
			this->content = content;
			this->fieldName = fieldName;
			this->null = false;
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
	void add(string content, string fieldName = "");
	void add(int content, string fieldName, bool null = false);
	void add(unsigned int content, string fieldName, bool null = false);
	void add(long int content,  string fieldName, bool null = false);
	void add(double content,  string fieldName, bool null = false);
	void add(u_int64_t content,  string fieldName, bool null = false);
	int getIndexField(string fieldName);
	bool isEmpty();
	bool isNull(string fieldName);
	string implodeFields(string separator = ",", string border = "");
	string implodeContent(string separator = ",", string border = "'", bool enableSqlString = false, bool escapeAll = false);
	string keyvalList(string separator);
private:
	SqlDb *sqlDb;
	vector<SqlDb_rowField> row;
};

class SqlDb {
public:
	SqlDb();
	virtual ~SqlDb();
	void setConnectParameters(string server, string user, string password, string database = "", bool showversion = true);
	void setCloudParameters(string cloud_host, string cloud_token);
	void setLoginTimeout(ulong loginTimeout);
	virtual bool connect(bool craeteDb = false, bool mainInit = false) = 0;
	virtual void disconnect() = 0;
	virtual bool connected() = 0;
	bool reconnect();
	virtual bool query(string query, bool callFromStoreProcessWithFixDeadlock = false) = 0;
	bool queryByCurl(string query);
	virtual string prepareQuery(string query, bool nextPass);
	virtual SqlDb_row fetchRow(bool assoc = false) = 0;
	virtual string insertQuery(string table, SqlDb_row row, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual string insertQuery(string table, vector<SqlDb_row> *rows, bool enableSqlStringInContent = false, bool escapeAll = false, bool insertIgnore = false);
	virtual int insert(string table, SqlDb_row row);
	virtual int insert(string table, vector<SqlDb_row> *rows);
	virtual int getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row);
	virtual int getInsertId() = 0;
	virtual int getIndexField(string fieldName);
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
	virtual bool checkLastError(string prefixError, bool sysLog = false, bool clearLastError = false) {
		return(false);
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
	virtual void cleanFields();
	virtual void clean() = 0;
	virtual void createSchema(const char *host = NULL, const char *database = NULL, const char *user = NULL, const char *password = NULL) = 0;
	virtual void createTable(const char *tableName) = 0;
	virtual void checkDbMode() = 0;
	virtual void checkSchema() = 0;
	virtual string getTypeDb() = 0;
	virtual string getSubtypeDb() = 0;
	virtual int multi_on() {
		return(1);
	}
	virtual int multi_off() {
		return(1);
	}
	virtual int getDbMajorVersion() {
		return(0);
	}
	virtual int getDbMinorVersion(int minorLevel  = 0) {
		return(0);
	}
	void setEnableSqlStringInContent(bool enableSqlStringInContent);
	void setDisableNextAttemptIfError();
	void setEnableNextAttemptIfError();
	bool isCloud() {
		return(!cloud_host.empty());
	}
	unsigned int lastmysqlresolve;
protected:
	string conn_server;
	string conn_server_ip;
	string conn_user;
	string conn_password;
	string conn_database;
	string cloud_host;
	string cloud_redirect;
	string cloud_token;
	bool conn_showversion;
	ulong loginTimeout;
	unsigned int maxQueryPass;
	vector<string> fields;
	bool enableSqlStringInContent;
	bool disableNextAttemptIfError;
	bool connecting;
	vector<string> cloud_data_columns;
	vector<vector<string> > cloud_data;
	size_t cloud_data_rows;
	size_t cloud_data_index;
	unsigned long maxAllowedPacket;
private:
	unsigned int lastError;
	string lastErrorString;
friend class MySqlStore_process;
};

class SqlDb_mysql : public SqlDb {
public:
	enum eRoutineType {
		procedure,
		function
	};
public:
	SqlDb_mysql();
	~SqlDb_mysql();
	bool connect(bool craeteDb = false, bool mainInit = false);
	void disconnect();
	bool connected();
	bool query(string query, bool callFromStoreProcessWithFixDeadlock = false);
	SqlDb_row fetchRow(bool assoc = false);
	int getInsertId();
	string escape(const char *inputString, int length = 0);
	string getFieldBorder() {
		return("`");
	}
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void clean();
	void createSchema(const char *host = NULL, const char *database = NULL, const char *user = NULL, const char *password = NULL);
	void createTable(const char *tableName);
	void checkDbMode();
	void checkSchema();
	bool checkSourceTables();
	void copyFromSourceTables(SqlDb_mysql *sqlDbSrc);
	void copyFromSourceTable(SqlDb_mysql *sqlDbSrc, const char *tableName, const char *id = NULL, unsigned long maxDiffId = 0, 
				 unsigned long minIdInSrc = 1, unsigned long useMaxIdInSrc = 0);
	void copyFromSourceGuiTables(SqlDb_mysql *sqlDbSrc);
	void copyFromSourceGuiTable(SqlDb_mysql *sqlDbSrc, const char *tableName);
	vector<string> getSourceTables();
	bool checkFederatedTables();
	void copyFromFederatedTables();
	void copyFromFederatedTable(const char *tableName, const char *id = NULL, unsigned long maxDiffId = 0, 
				    unsigned long minIdInFederated = 1, unsigned long useMaxIdInFederated = 0);
	void dropFederatedTables();
	vector<string> getFederatedTables();
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
	bool query(string query, bool callFromStoreProcessWithFixDeadlock = false);
	SqlDb_row fetchRow(bool assoc = false);
	int getInsertId();
	int getIndexField(string fieldName);
	string escape(const char *inputString, int length = 0);
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void cleanFields();
	void clean();
	void createSchema(const char *host = NULL, const char *database = NULL, const char *user = NULL, const char *password = NULL);
	void createTable(const char *tableName);
	void checkDbMode();
	void checkSchema();
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
	MySqlStore_process(int id, const char *host, const char *user, const char *password, const char *database,
			   const char *cloud_host, const char *cloud_token,
			   int concatLimit);
	~MySqlStore_process();
	void connect();
	void disconnect();
	bool connected();
	void query(const char *query_str);
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
};

class MySqlStore {
private:
	class QFile {
	public:
		QFile(const char *filename = NULL) {
			if(filename) {
				this->filename = filename;
			}
			file = NULL;
			createAt = filename ? getTimeMS() : 0;
			_sync = 0;
		}
		bool open(const char *filename = NULL, u_long createAt = 0) {
			if(filename) {
				this->filename = filename;
				this->createAt = createAt ? createAt : getTimeMS();
			}
			if(!this->filename.length()) {
				return(false);
			}
			file = fopen(this->filename.c_str(), "wxt");
			if(file) {
				flock(fileno(file), LOCK_EX);
			}
			return(file != NULL);
		}
		void close() {
			if(file) {
				flock(fileno(file), LOCK_UN);
				fclose(file);
				file = NULL;
			}
			filename = "";
			createAt = 0;
		}
		bool isEmpty() {
			return(filename.empty());
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
		FILE *file;
		u_long createAt;
		volatile int _sync;
	};
	struct QFileConfig {
		QFileConfig() {
			enable = false;
			period = 10;
			inotify = false;
			inotify_ready = false;
		}
		bool enable;
		string directory;
		int period;
		bool inotify;
		bool inotify_ready;
	};
	struct LoadFromQFilesThreadData {
		LoadFromQFilesThreadData() {
			id = 0;
			maxStoreThreads = 1;
			storeConcatLimit = 0;
			thread = 0;
			useStoreThreads = 1;
			_sync = 0;
		}
		void addFile(u_long time, const char *file) {
			lock();
			qfiles[time] = file;
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
		int maxStoreThreads;
		int storeConcatLimit;
		pthread_t thread;
		int useStoreThreads;
		map<u_long, string> qfiles;
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
	MySqlStore(const char *host, const char *user, const char *password, const char *database, 
		   const char *cloud_host = NULL, const char *cloud_token = NULL);
	~MySqlStore();
	void queryToFiles(bool enable = true, const char *directory = NULL, int period = 0);
	void loadFromQFiles(bool enable = true, const char *directory = NULL, int period = 0);
	void queryToFiles_start();
	void loadFromQFiles_start();
	void connect(int id);
	void query(const char *query_str, int id);
	void query_lock(const char *query_str, int id);
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
			      int maxStoreThreads = 0, int storeConcatLimit = 0);
	bool fillQFiles(int id);
	string getMinQFile(int id);
	int getCountQFiles(int id);
	bool loadFromQFile(const char *filename, int id);
	void addFileFromINotify(const char *filename);
	QFileData parseQFilename(const char *filename);
	string getLoadFromQFilesStat();
	//
	void lock(int id);
	void unlock(int id);
	void setEnableTerminatingDirectly(int id, bool enableTerminatingDirectly);
	void setEnableTerminatingIfEmpty(int id, bool enableTerminatingIfEmpty);
	void setEnableTerminatingIfSqlError(int id, bool enableTerminatingIfSqlError);
	void setEnableAutoDisconnect(int id, bool enableAutoDisconnect = true);
	void setDefaultConcatLimit(int defaultConcatLimit);
	void setConcatLimit(int id, int concatLimit);
	void setEnableTransaction(int id, bool enableTransaction = true);
	void setEnableFixDeadlock(int id, bool enableFixDeadlock = true);
	MySqlStore_process *find(int id);
	MySqlStore_process *check(int id);
	size_t getAllSize(bool lock = true);
	int getSize(int id, bool lock = true);
	int getSizeMult(int n, ...);
	int getSizeVect(int id1, int id2, bool lock = true);
	string exportToFile(FILE *file, string filename, bool sqlFormat, bool cleanAfterExport);
	void autoloadFromSqlVmExport();
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
	string cloud_host;
	string cloud_token;
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

SqlDb *createSqlObject();
string sqlDateTimeString(time_t unixTime);
string sqlDateString(time_t unixTime);
string sqlEscapeString(string inputStr, const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
string sqlEscapeString(const char *inputStr, int length = 0, const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
string _sqlEscapeString(const char *inputString, int length, const char *typeDb);
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
void createMysqlPartitionsIpacc();
void createMysqlPartitionsBillingAgregation();
void dropMysqlPartitionsCdr();

#endif
