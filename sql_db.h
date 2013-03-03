#ifndef SQL_DB_H
#define SQL_DB_H

#include <stdlib.h>
#include <string>
#include <vector>
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
	string implodeContent(string separator = ",", string border = "'", bool enableSqlString = false);
	string keyvalList(string separator);
private:
	SqlDb *sqlDb;
	vector<SqlDb_rowField> row;
};

class SqlDb {
public:
	SqlDb();
	virtual ~SqlDb();
	void setConnectParameters(string server, string user, string password, string database = "");
	void setLoginTimeout(ulong loginTimeout);
	void enableSysLog();
	virtual bool connect() = 0;
	virtual void disconnect() = 0;
	virtual bool connected() = 0;
	bool reconnect();
	virtual bool query(string query) = 0;
	virtual void prepareQuery(string *query);
	virtual SqlDb_row fetchRow() = 0;
	virtual string insertQuery(string table, SqlDb_row row);
	virtual int insert(string table, SqlDb_row row);
	virtual int getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row);
	virtual int getInsertId() = 0;
	virtual int getIndexField(string fieldName);
	virtual string escape(const char *inputString, int length = 0) = 0;
	string _escape(const char *inputString);
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
	virtual void createSchema() = 0;
	virtual string getTypeDb() = 0;
	virtual string getSubtypeDb() = 0;
	virtual int multi_on() {
		return(1);
	}
	virtual int multi_off() {
		return(1);
	}
	void setEnableSqlStringInContent(bool enableSqlStringInContent);
protected:
	string conn_server;
	string conn_user;
	string conn_password;
	string conn_database;
	ulong loginTimeout;
	bool sysLog;
	unsigned int maxQueryPass;
	vector<string> fields;
	bool enableSqlStringInContent;
private:
	unsigned int lastError;
	string lastErrorString;
};

class SqlDb_mysql : public SqlDb {
public:
	SqlDb_mysql();
	~SqlDb_mysql();
	bool connect();
	void disconnect();
	bool connected();
	bool query(string query);
	SqlDb_row fetchRow();
	int getInsertId();
	string escape(const char *inputString, int length = 0);
	string getFieldBorder() {
		return("`");
	}
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void clean();
	void createSchema();
	string getTypeDb() {
		return("mysql");
	}
	string getSubtypeDb() {
		return("");
	}
	int multi_on();
	int multi_off();
private:
	MYSQL *hMysql;
	MYSQL *hMysqlConn;
	MYSQL_RES *hMysqlRes;
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
	bool connect();
	void disconnect();
	bool connected();
	bool query(string query);
	SqlDb_row fetchRow();
	int getInsertId();
	int getIndexField(string fieldName);
	string escape(const char *inputString, int length = 0);
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
	void cleanFields();
	void clean();
	void createSchema();
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

string sqlDateTimeString(time_t unixTime);
string sqlDateString(time_t unixTime);
string sqlEscapeString(string inputStr);
string sqlEscapeString(const char *inputStr);
string sqlEscapeStringBorder(string inputStr, char borderChar = '\'');
string sqlEscapeStringBorder(const char *inputStr, char borderChar = '\'');
string _sqlEscapeString(const char *inputStr, char borderChar);
bool isSqlDriver(const char *sqlDriver);
bool isTypeDb(const char *typeDb);
bool cmpStringIgnoreCase(const char* str1, const char* str2);
string reverseString(const char *str);

#endif
