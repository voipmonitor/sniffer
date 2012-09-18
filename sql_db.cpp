#include <stdio.h>
#include <iostream>
#include <syslog.h>
#include <string.h>

#include "sql_db.h"


extern int verbosity;


string SqlDb_row::operator [] (const char *fieldName) {
	int indexField = this->getIndexField(fieldName);
	if(indexField >= 0) {
		return(row[indexField].content);
	}
	return("");
}

string SqlDb_row::operator [] (string fieldName) {
	return((*this)[fieldName.c_str()]);
}

SqlDb_row::operator int() {
	return(!this->isEmpty());
}

void SqlDb_row::add(const char *content, string fieldName) {
	this->row.push_back(SqlDb_rowField(content, fieldName));
}

void SqlDb_row::add(string content, string fieldName) {
	this->row.push_back(SqlDb_rowField(content, fieldName));
}

void SqlDb_row::add(int content, string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%i", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(unsigned int content, string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%u", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(long int content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%li", content);
		this->add(str_content, fieldName);
	}
}

void SqlDb_row::add(double content,  string fieldName, bool null) {
	if(!content && null) {
		this->add((const char*)NULL, fieldName);
	} else {
		char str_content[100];
		sprintf(str_content, "%lf", content);
		this->add(str_content, fieldName);
	}
}

int SqlDb_row::getIndexField(string fieldName) {
	for(size_t i = 0; i < row.size(); i++) {
		if(row[i].fieldName == fieldName) {
			return(i);
		}
	}
	if(this->sqlDb) {
		return(this->sqlDb->getIndexField(fieldName));
	}
	return(-1);
}

bool SqlDb_row::isEmpty() {
	return(!row.size());
}

string SqlDb_row::implodeFields(string separator, string border) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		rslt += border + this->row[i].fieldName + border;
	}
	return(rslt);
}

string SqlDb_row::implodeContent(string separator, string border) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		if(this->row[i].null) {
			rslt += "NULL";
		} else {
			rslt += border + this->row[i].content + border;
		}
	}
	return(rslt);
}


SqlDb::SqlDb() {
	this->sysLog = false;
	this->clearLastError();
}

void SqlDb::setConnectParameters(string server, string user, string password, string database) {
	this->conn_server = server;
	this->conn_user = user;
	this->conn_password = password;
	this->conn_database = database;
}

void SqlDb::enableSysLog() {
	this->sysLog = true;
}

bool SqlDb::reconnect() {
	this->disconnect();
	return(this->connect());
}

int SqlDb::insert(string table, SqlDb_row row, string contentBorder) {
	string query = "INSERT INTO " + table + " ( " + row.implodeFields() + " ) VALUES ( " + row.implodeContent(",", "") + " )";
	if(this->query(query)) {
		return(this->getInsertId());
	}
	return(-1);
}

int SqlDb::getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row, string contentBorder) {
	string query = "SELECT * FROM " + table + " WHERE " + uniqueField + " = " + 
		       contentBorder + row[uniqueField] + contentBorder;
	if(this->query(query)) {
		SqlDb_row rsltRow = this->fetchRow();
		if(rsltRow) {
			return(atoi(rsltRow[idField].c_str()));
		}
	}
	return(this->insert(table, row, contentBorder));
}

void SqlDb::setLastErrorString(string lastErrorString, bool sysLog) {
	this->lastErrorString = lastErrorString;
	if(sysLog && lastErrorString != "" && this->sysLog) {
		syslog(LOG_ERR, lastErrorString.c_str());
	}
}


SqlDb_mysql::SqlDb_mysql() {
	this->hMysql = NULL;
	this->hMysqlConn = NULL;
	this->hMysqlRes = NULL;
}

SqlDb_mysql::~SqlDb_mysql() {
	this->disconnect();
}

bool SqlDb_mysql::connect() {
	this->hMysql = mysql_init(NULL);
	if(this->hMysql) {
		this->hMysqlConn = mysql_real_connect(
					this->hMysql,
					this->conn_server.c_str(), this->conn_user.c_str(), this->conn_password.c_str(), this->conn_database.c_str(),
					0, NULL, 0);
		if(this->hMysqlConn) {
			return(true);
		} else {
			this->checkLastError("connect error", true);
		}
	} else {
		this->setLastErrorString("mysql_init failed - insufficient memory ?", true);
	}
	return(false);
}

void SqlDb_mysql::disconnect() {
	if(this->hMysqlRes) {
		mysql_free_result(this->hMysqlRes);
		this->hMysqlRes = NULL;
	}
	if(this->hMysqlConn) {
		mysql_close(this->hMysqlConn);
		this->hMysqlConn = NULL;
		this->hMysql = NULL;
	} else if(this->hMysql) {
		mysql_close(this->hMysql);
		this->hMysql = NULL;
	}
}

bool SqlDb_mysql::connected() {
	return(this->hMysqlConn != NULL);
}

bool SqlDb_mysql::query(string query) {
	if(verbosity > 0) { 
		cout << query << endl;
	}
	bool rslt = false;
	if(this->hMysqlRes) {
		mysql_free_result(this->hMysqlRes);
		this->hMysqlRes = NULL;
	}
	for(int pass = 0; pass < 2 && !rslt; pass++) {
		if(!this->connected()) {
			this->connect();
		}
		if(this->connected()) {
			if(mysql_query(this->hMysqlConn, query.c_str())) {
				this->checkLastError("query error in [" + query + "]", true);
				if(this->getLastError() == 2006) { // MySQL server has gone away
					if(pass == 0) {
						this->reconnect();
					}
				} else {
					break;
				}
			} else {
				rslt = true;
			}
		}
	}
	return(rslt);
}

SqlDb_row SqlDb_mysql::fetchRow() {
	SqlDb_row row(this);
	if(this->hMysqlConn) {
		if(!this->hMysqlRes) {
			this->hMysqlRes = mysql_use_result(this->hMysqlConn);
			if(this->hMysqlRes) {
				fields.clear();
				MYSQL_FIELD *field;
				for(int i = 0; (field = mysql_fetch_field(this->hMysqlRes)); i++) {
					fields.push_back(field->name);
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
					row.add(mysqlRow[i]);
				}
			} else {
				this->checkLastError("fetch row error", true);
			}
		}
	}
	return(row);
}

int SqlDb_mysql::getInsertId() {
	if(this->hMysqlConn) {
		return(mysql_insert_id(this->hMysqlConn));
	}
	return(-1);
}

int SqlDb_mysql::getIndexField(string fieldName) {
	for(size_t i = 0; i < fields.size(); i++) {
		if(fields[i] == fieldName) {
			return(i);
		}
	}
	return(-1);
}

string SqlDb_mysql::escape(const char *inputString) {
	cout << "ESCAPE" << inputString << endl;
	if(inputString && inputString[0]) {
		int length = strlen(inputString);
		int sizeBuffer = length * 2 + 10;
		char *buffer = new char[sizeBuffer];
		mysql_real_escape_string(this->hMysqlConn, buffer, inputString, length);
		cout << "ESCAPED" << buffer << endl;
		string rslt = buffer;
		delete [] buffer;
		return(rslt);
	} else {
		return("");
	}
}

bool SqlDb_mysql::checkLastError(string prefixError, bool sysLog, bool clearLastError) {
	if(this->hMysql) {
		unsigned int errno = mysql_errno(this->hMysql);
		if(errno) {
			this->setLastError(errno, (prefixError + ":  " + mysql_error(this->hMysql)).c_str(), sysLog);
			return(true);
		} else if(clearLastError) {
			this->clearLastError();
		}
	}
	return(false);
}
