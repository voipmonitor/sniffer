#ifndef SQL_DB_H
#define SQL_DB_H

#include <stdlib.h>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <mysql/mysql.h>
#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>


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
	void setLoginTimeout(ulong loginTimeout);
	virtual bool connect(bool craeteDb = false, bool mainInit = false) = 0;
	virtual void disconnect() = 0;
	virtual bool connected() = 0;
	bool reconnect();
	virtual bool query(string query) = 0;
	virtual void prepareQuery(string *query);
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
protected:
	string conn_server;
	string conn_user;
	string conn_password;
	string conn_database;
	bool conn_showversion;
	ulong loginTimeout;
	unsigned int maxQueryPass;
	vector<string> fields;
	bool enableSqlStringInContent;
	bool disableNextAttemptIfError;
private:
	unsigned int lastError;
	string lastErrorString;
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
	bool query(string query);
	SqlDb_row fetchRow(bool assoc = false);
	int getInsertId();
	string escape(const char *inputString, int length = 0);
	string getFieldBorder() {
		return("`");
	}
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void clean();
	void createSchema(const char *host = NULL, const char *database = NULL, const char *user = NULL, const char *password = NULL);
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
	bool createRoutine(string routine, string routineName, string routineParamsAndReturn, eRoutineType routineType);
	bool createFunction(string routine, string routineName, string routineParamsAndReturn) {
		return(this->createRoutine(routine, routineName, routineParamsAndReturn, function));
	}
	bool createProcedure(string routine, string routineName, string routineParamsAndReturn) {
		return(this->createRoutine(routine, routineName, routineParamsAndReturn, procedure));
	}
	MYSQL *getH_Mysql() {
		return(this->hMysql);
	}
private:
	MYSQL *hMysql;
	MYSQL *hMysqlConn;
	MYSQL_RES *hMysqlRes;
	string dbVersion;
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
	bool query(string query);
	SqlDb_row fetchRow(bool assoc = false);
	int getInsertId();
	int getIndexField(string fieldName);
	string escape(const char *inputString, int length = 0);
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void cleanFields();
	void clean();
	void createSchema(const char *host = NULL, const char *database = NULL, const char *user = NULL, const char *password = NULL);
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
	MySqlStore_process(int id, const char *host, const char *user, const char *password, const char *database);
	~MySqlStore_process();
	void query(const char *query_str);
	void store();
	void lock();
	void unlock();
	void setIgnoreTerminating(bool ignoreTerminating);
	int getId() {
		return(this->id);
	}
	size_t getSize() {
		return(this->query_buff.size());
	}
	bool operator < (const MySqlStore_process& other) const { 
		return(this->id < other.id); 
	}
private:
	int id;
	pthread_t thread;
	pthread_mutex_t lock_mutex;
	SqlDb *sqlDb;
	queue<string> query_buff;
	bool terminated;
	bool ignoreTerminating;
};

class MySqlStore {
public:
	MySqlStore(const char *host, const char *user, const char *password, const char *database);
	~MySqlStore();
	void query(const char *query_str, int id);
	void lock(int id);
	void unlock(int id);
	void setIgnoreTerminating(int id, bool ignoreTerminating);
	MySqlStore_process *find(int id);
	size_t getSize();
private:
	map<int, MySqlStore_process*> processes;
	string host;
	string user;
	string password;
	string database;
};

SqlDb *createSqlObject();
string sqlDateTimeString(time_t unixTime);
string sqlDateString(time_t unixTime);
string sqlEscapeString(string inputStr, const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
string sqlEscapeString(const char *inputStr, int length = 0, const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
string _sqlEscapeString(const char *inputString, const char *typeDb);
string sqlEscapeStringBorder(string inputStr, char borderChar = '\'', const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
string sqlEscapeStringBorder(const char *inputStr, char borderChar = '\'', const char *typeDb = NULL, SqlDb_mysql *sqlDbMysql = NULL);
bool isSqlDriver(const char *sqlDriver, const char *checkSqlDriver = NULL);
bool isTypeDb(const char *typeDb, const char *checkSqlDriver = NULL, const char *checkOdbcDriver = NULL);
bool cmpStringIgnoreCase(const char* str1, const char* str2);
string reverseString(const char *str);

void createMysqlPartitionsCdr();
void createMysqlPartitionsIpacc();
void dropMysqlPartitionsCdr();

#endif
