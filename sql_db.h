#ifndef SQL_DB_H
#define SQL_DB_H

#include <stdlib.h>
#include <string>
#include <vector>
#include <mysql/mysql.h>


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
	string implodeFields(string separator = ",", string border = "");
	string implodeContent(string separator = ",", string border = "'");
private:
	SqlDb *sqlDb;
	vector<SqlDb_rowField> row;
};

class SqlDb {
public:
	SqlDb();
	void setConnectParameters(string server, string user, string password, string database = "");
	void enableSysLog();
	virtual bool connect() = 0;
	virtual void disconnect() = 0;
	virtual bool connected() = 0;
	bool reconnect();
	virtual bool query(string query) = 0;
	virtual SqlDb_row fetchRow() = 0;
	virtual int insert(string table, SqlDb_row row, string contentBorder = "'");
	virtual int getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row, string contentBorder = "'");
	virtual int getInsertId() = 0;
	virtual int getIndexField(string fieldName) { 
		return(-1);
	}
	virtual string escape(const char *inputString) = 0;
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
protected:
	string conn_server;
	string conn_user;
	string conn_password;
	string conn_database;
	bool sysLog;
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
	int getIndexField(string fieldName);
	string escape(const char *inputString);
	bool checkLastError(string prefixError, bool sysLog = false,bool clearLastError = false);
private:
	MYSQL *hMysql;
	MYSQL *hMysqlConn;
	MYSQL_RES *hMysqlRes;
	vector<string> fields;
};

#endif
