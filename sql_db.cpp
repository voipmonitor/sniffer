#include <stdio.h>
#include <iostream>
#include <syslog.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "sql_db.h"


extern int verbosity;
extern int opt_mysql_port;
extern char opt_match_header[128];
int sql_noerror = 0;


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

void SqlDb_row::add(string content, string fieldName) {
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

string SqlDb_row::implodeContent(string separator, string border, bool enableSqlString) {
	string rslt;
	for(size_t i = 0; i < this->row.size(); i++) {
		if(i) { rslt += separator; }
		if(this->row[i].null) {
			rslt += "NULL";
		} else if(enableSqlString && this->row[i].content.substr(0, 12) == "_\\_'SQL'_\\_:") {
			rslt += this->row[i].content.substr(12);
		} else {
			rslt += border + this->row[i].content + border;
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


SqlDb::SqlDb() {
	this->sysLog = false;
	this->clearLastError();
	this->maxQueryPass = UINT_MAX;
	this->loginTimeout = (ulong)NULL;
	this->enableSqlStringInContent = false;
}

SqlDb::~SqlDb() {
}

void SqlDb::setConnectParameters(string server, string user, string password, string database) {
	this->conn_server = server;
	this->conn_user = user;
	this->conn_password = password;
	this->conn_database = database;
}

void SqlDb::setLoginTimeout(ulong loginTimeout) {
	this->loginTimeout = loginTimeout;
}

void SqlDb::enableSysLog() {
	this->sysLog = true;
}

bool SqlDb::reconnect() {
	this->disconnect();
	return(this->connect());
}

string SqlDb::_escape(const char *inputString) {
	string rsltString;
	struct escChar {
		char ch;
		const char* escStr;
	} 
	escCharsMysql[] = 
				{
					{ '\'', "\\'" },
					{ '"' , "\\\"" },
					{ '\\', "\\\\" },
					{ '\n', "\\n" }, 	// new line feed
					{ '\r', "\\r" }, 	// cariage return
					{ '\t', "\\t" }, 	// tab
					{ '\v', "\\v" }, 	// vertical tab
					{ '\b', "\\b" }, 	// backspace
					{ '\f', "\\f" }, 	// form feed
					{ '\a', "\\a" }, 	// alert (bell)
					{ '\e', "" }, 		// escape
				},
	escCharsOdbc[] = 
				{ 
					{ '\'', "\'\'" },
					{ '\v', "" }, 		// vertical tab
					{ '\b', "" }, 		// backspace
					{ '\f', "" }, 		// form feed
					{ '\a', "" }, 		// alert (bell)
					{ '\e', "" }, 		// escape
				};
	escChar *escChars = NULL;
	int countEscChars = 0;
	if(this->getTypeDb() == "mysql") {
		escChars = escCharsMysql;
		countEscChars = sizeof(escCharsMysql)/sizeof(escChar);
	} else if(this->getTypeDb() == "odbc") {
		escChars = escCharsOdbc;
		countEscChars = sizeof(escCharsOdbc)/sizeof(escChar);
	}
	int lengthStr = strlen(inputString);
	for(int posInputString = 0; posInputString<lengthStr; posInputString++) {
		bool isEscChar = false;
		for(int i = 0; i<countEscChars; i++) {
			if(escChars[i].ch == inputString[posInputString]) {
				rsltString += escChars[i].escStr;
				isEscChar = true;
				break;
			}
		}
		if(!isEscChar) {
			rsltString += inputString[posInputString];
		}
	}
	return(inputString);
}

string SqlDb::insertQuery(string table, SqlDb_row row) {
	string query = 
		"INSERT INTO " + table + " ( " + row.implodeFields(this->getFieldSeparator(), this->getFieldBorder()) + 
		" ) VALUES ( " + row.implodeContent(this->getContentSeparator(), this->getContentBorder(), this->enableSqlStringInContent) + " )";
	return(query);
}

int SqlDb::insert(string table, SqlDb_row row) {
	string query = this->insertQuery(table, row);
	if(this->query(query)) {
		return(this->getInsertId());
	}
	return(-1);
}

int SqlDb::getIdOrInsert(string table, string idField, string uniqueField, SqlDb_row row) {
	string query = 
		"SELECT * FROM " + table + " WHERE " + uniqueField + " = " + 
		this->getContentBorder() + row[uniqueField] + this->getContentBorder();
	if(this->query(query)) {
		SqlDb_row rsltRow = this->fetchRow();
		if(rsltRow) {
			return(atoi(rsltRow[idField].c_str()));
		}
	}
	return(this->insert(table, row));
}

int SqlDb::getIndexField(string fieldName) {
	for(size_t i = 0; i < this->fields.size(); i++) {
		if(this->fields[i] == fieldName) {
			return(i);
		}
	}
	return(-1);
}

void SqlDb::setLastErrorString(string lastErrorString, bool sysLog) {
	this->lastErrorString = lastErrorString;
	if(sysLog && lastErrorString != "" && this->sysLog) {
		syslog(LOG_ERR, "%s", lastErrorString.c_str());
	}
}

void SqlDb::setEnableSqlStringInContent(bool enableSqlStringInContent) {
	this->enableSqlStringInContent = enableSqlStringInContent;
}
	
void SqlDb::cleanFields() {
	this->fields.clear();
}


SqlDb_mysql::SqlDb_mysql() {
	this->hMysql = NULL;
	this->hMysqlConn = NULL;
	this->hMysqlRes = NULL;
}

SqlDb_mysql::~SqlDb_mysql() {
	this->clean();
}

bool SqlDb_mysql::connect() {
	this->hMysql = mysql_init(NULL);
	if(this->hMysql) {
		this->hMysqlConn = mysql_real_connect(
					this->hMysql,
					this->conn_server.c_str(), this->conn_user.c_str(), this->conn_password.c_str(), this->conn_database.c_str(),
					//opt_mysql_port, NULL, CLIENT_MULTI_STATEMENTS);
					opt_mysql_port, NULL, 0);
		if(this->hMysqlConn) {
			this->query("SET NAMES UTF8");
			return(true);
		} else {
			this->checkLastError("connect error", true);
		}
	} else {
		this->setLastErrorString("mysql_init failed - insufficient memory ?", true);
	}
	return(false);
}

int SqlDb_mysql::multi_on() {
	return mysql_set_server_option(this->hMysql, MYSQL_OPTION_MULTI_STATEMENTS_ON);
}

int SqlDb_mysql::multi_off() {
	return mysql_set_server_option(this->hMysql, MYSQL_OPTION_MULTI_STATEMENTS_OFF);
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
	this->cleanFields();
	for(unsigned int pass = 0; pass < this->maxQueryPass; pass++) {
		if(pass > 0) {
			sleep(1);
		}
		if(!this->connected()) {
			this->connect();
		}
		if(this->connected()) {
			if(mysql_query(this->hMysqlConn, query.c_str())) {
				if(!sql_noerror)
					this->checkLastError("query error in [" + query + "]", true);
				if(this->getLastError() == 2006) { // MySQL server has gone away
					if(pass < this->maxQueryPass - 1) {
						this->reconnect();
					}
				} else {
					break;
				}
			} else {
				rslt = true;
				break;
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

string SqlDb_mysql::escape(const char *inputString, int length) {
	if(!(inputString && (inputString[0] || length))) {
		return(inputString ? inputString : "");
	}
	if(this->connected()) {
		if(!length) {
			length = strlen(inputString);
		}
		int sizeBuffer = length * 2 + 10;
		char *buffer = new char[sizeBuffer];
		mysql_real_escape_string(this->hMysqlConn, buffer, inputString, length);
		string rslt = buffer;
		delete [] buffer;
		return(rslt);
	}
	return(this->_escape(inputString));
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

void SqlDb_mysql::clean() {
	this->disconnect();
	this->cleanFields();
}


SqlDb_odbc_bindBufferItem::SqlDb_odbc_bindBufferItem(SQLUSMALLINT colNumber, string fieldName, SQLSMALLINT dataType, SQLULEN columnSize, SQLHSTMT hStatement) {
	this->colNumber = colNumber;
	this->fieldName = fieldName;
	this->dataType = dataType;
	this->columnSize = columnSize;
	this->buffer = new char[this->columnSize + 100]; // 100 - reserve for convert binary to text
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
	this->push_back(new SqlDb_odbc_bindBufferItem(colNumber, fieldName, dataType, columnSize, hStatement));
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
		this->addItem(columnIndex + 1, (const char*)columnName, dataType, columnSize, hStatement);
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
		if((*this)[i]->fieldName == fieldName) {
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

bool SqlDb_odbc::connect() {
	SQLRETURN rslt;
	this->clearLastError();
	if(!this->hEnvironment) {
		rslt = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &this->hEnvironment);
		if(!this->okRslt(rslt)) {
			this->setLastError(rslt, "odbc: error in allocate environment handle", true);
			this->disconnect();
			return(false);
		}
		if(this->odbcVersion) {
			rslt = SQLSetEnvAttr(this->hEnvironment, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)this->odbcVersion, 0); 
			if(!this->okRslt(rslt)) {
				this->setLastError(rslt, "odbc: error in set environment attributes");
				this->disconnect();
				return(false);
			}
		}
	}
	if(!this->hConnection) {
		rslt = SQLAllocHandle(SQL_HANDLE_DBC, this->hEnvironment, &this->hConnection); 
		if(!this->okRslt(rslt)) {
			this->setLastError(rslt, "odbc: error in allocate connection handle");
			this->disconnect();
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
			this->checkLastError("odbc: connect error", true);
			this->disconnect();
			return(false);
		}
	}
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

bool SqlDb_odbc::query(string query) {
	if(verbosity > 0) { 
		cout << query << endl;
	}
	SQLRETURN rslt = 0;
	if(this->hStatement) {
		SQLFreeHandle(SQL_HANDLE_STMT, this->hStatement);
		this->hStatement = NULL;
	}
	this->cleanFields();
	for(unsigned int pass = 0; pass < this->maxQueryPass; pass++) {
		if(pass > 0) {
			sleep(1);
		}
		if(!this->connected()) {
			this->connect();
		}
		rslt = SQLAllocHandle(SQL_HANDLE_STMT, hConnection, &hStatement);
		if(!this->okRslt(rslt)) {
			this->checkLastError("alloc statement", true);
			this->reconnect();
			continue;
		}
		rslt = SQLExecDirect(this->hStatement, (SQLCHAR*)query.c_str(), SQL_NTS);   
		if(!this->okRslt(rslt) && rslt != SQL_NO_DATA) {
			this->checkLastError("query error", true);
			if(rslt > 0) {
				if(pass < this->maxQueryPass - 1) {
					this->reconnect();
				}
			} else {
				break;
			}
		} else {
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
					row.add(this->bindBuffer.getColBuffer(i));
				}
			}
		} else {
			this->checkLastError("fetch error", true);
		}
	}
	return(row);
}

int SqlDb_odbc::getInsertId() {
	SqlDb_row row;
	if(this->query("select @@identity as last_insert_id") &&
	   (row = this->fetchRow()) != 0) {
		return(atol(row["last_insert_id"].c_str()));
	}
	return(-1);
}

int SqlDb_odbc::getIndexField(string fieldName) {
	for(size_t i = 0; i < this->bindBuffer.size(); i++) {
		if(this->bindBuffer[i]->fieldName == fieldName) {
			return(i);
		}
	}
	return(-1);
}

string SqlDb_odbc::escape(const char *inputString, int length) {
	if(!(inputString && (inputString[0] || length))) {
		return(inputString ? inputString : "");
	}
	return(this->_escape(inputString));
}

bool SqlDb_odbc::checkLastError(string prefixError, bool sysLog, bool clearLastError) {
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


string sqlDateTimeString(time_t unixTime) {
	struct tm * localTime = localtime(&unixTime);
	char dateTimeBuffer[50];
	strftime(dateTimeBuffer, sizeof(dateTimeBuffer), "%Y-%m-%d %H:%M:%S", localTime);
	return string(dateTimeBuffer);
}

string sqlEscapeString(string inputStr) {
	return _sqlEscapeString(inputStr.c_str(), 0);
}

string sqlEscapeString(const char *inputStr) {
	return _sqlEscapeString(inputStr, 0);
}

string sqlEscapeStringBorder(string inputStr, char borderChar) {
	return _sqlEscapeString(inputStr.c_str(), borderChar);
}

string sqlEscapeStringBorder(const char *inputStr, char borderChar) {
	return _sqlEscapeString(inputStr, borderChar);
}

extern SqlDb *sqlDb;
extern char sql_driver[256];
extern char odbc_driver[256];

string _sqlEscapeString(const char *inputStr, char borderChar) {
	if(!sqlDb) {
		return(inputStr);
	}
	string rsltString = sqlDb->escape(inputStr);
	if(borderChar) {
		rsltString = borderChar + rsltString + borderChar;
	}
	return rsltString;
}

bool isSqlDriver(const char *sqlDriver) {
	return sqlDb ?
		cmpStringIgnoreCase(sqlDb->getTypeDb().c_str(), sqlDriver) :
		cmpStringIgnoreCase(sql_driver, sqlDriver);
}

bool isTypeDb(const char *typeDb) {
	return sqlDb ?
		cmpStringIgnoreCase(sqlDb->getTypeDb().c_str(), typeDb) ||
		(cmpStringIgnoreCase(sqlDb->getTypeDb().c_str(), "odbc") && cmpStringIgnoreCase(sqlDb->getSubtypeDb().c_str(), typeDb)) :
		cmpStringIgnoreCase(sql_driver, typeDb) ||
		(cmpStringIgnoreCase(sql_driver, "odbc") && cmpStringIgnoreCase(odbc_driver, typeDb));
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
	string rslt;
	if(str) {
		int length = strlen(str);
		for(int i = length - 1; i >= 0; i--) {
			rslt += str[i];
		}
	}
	return rslt;
}


void SqlDb_mysql::createSchema() {

	this->multi_off();

	string query = "CREATE TABLE IF NOT EXISTS `filter_ip` (\
  `id` int(32) NOT NULL AUTO_INCREMENT,\
  `ip` int(32) unsigned DEFAULT NULL,\
  `mask` int(8) DEFAULT NULL,\
  `direction` tinyint(8) DEFAULT '0',\
  `rtp` tinyint(1) DEFAULT '0',\
  `sip` tinyint(1) DEFAULT '0',\
  `register` tinyint(1) DEFAULT '0',\
  `graph` tinyint(1) DEFAULT '0',\
  `wav` tinyint(1) DEFAULT '0',\
  `note` text,\
  PRIMARY KEY (`id`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";
	
	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `filter_telnum` (\
  `id` int(32) NOT NULL AUTO_INCREMENT,\
  `prefix` bigint(32) unsigned DEFAULT NULL,\
  `fixed_len` int(32) unsigned DEFAULT '0',\
  `direction` tinyint(8) DEFAULT '0',\
  `rtp` tinyint(1) DEFAULT '0',\
  `sip` tinyint(1) DEFAULT '0',\
  `register` tinyint(1) DEFAULT '0',\
  `graph` tinyint(1) DEFAULT '0',\
  `wav` tinyint(1) DEFAULT '0',\
  `note` text,\
  PRIMARY KEY (`id`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr_sip_response` (\
  `id` smallint(5) unsigned NOT NULL AUTO_INCREMENT,\
  `lastSIPresponse` varchar(255) DEFAULT NULL,\
  PRIMARY KEY (`id`),\
  UNIQUE KEY `lastSIPresponse` (`lastSIPresponse`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr_ua` (\
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,\
  `ua` varchar(512) DEFAULT NULL,\
  PRIMARY KEY (`id`),\
  UNIQUE KEY `ua` (`ua`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `calldate` datetime NOT NULL,\
  `callend` datetime NOT NULL,\
  `duration` mediumint(8) unsigned DEFAULT NULL,\
  `connect_duration` mediumint(8) unsigned DEFAULT NULL,\
  `progress_time` mediumint(8) unsigned DEFAULT NULL,\
  `first_rtp_time` mediumint(8) unsigned DEFAULT NULL,\
  `caller` varchar(255) DEFAULT NULL,\
  `caller_domain` varchar(255) DEFAULT NULL,\
  `caller_reverse` varchar(255) DEFAULT NULL,\
  `callername` varchar(255) DEFAULT NULL,\
  `callername_reverse` varchar(255) DEFAULT NULL,\
  `called` varchar(255) DEFAULT NULL,\
  `called_domain` varchar(255) DEFAULT NULL,\
  `called_reverse` varchar(255) DEFAULT NULL,\
  `sipcallerip` int(10) unsigned DEFAULT NULL,\
  `sipcalledip` int(10) unsigned DEFAULT NULL,\
  `whohanged` enum('caller','callee') DEFAULT NULL,\
  `bye` tinyint(3) unsigned DEFAULT NULL,\
  `lastSIPresponse_id` smallint(5) unsigned DEFAULT NULL,\
  `lastSIPresponseNum` smallint(5) unsigned DEFAULT NULL,\
  `sighup` tinyint(4) DEFAULT NULL,\
  `a_index` tinyint(4) DEFAULT NULL,\
  `b_index` tinyint(4) DEFAULT NULL,\
  `a_payload` int(11) DEFAULT NULL,\
  `b_payload` int(11) DEFAULT NULL,\
  `a_saddr` int(10) unsigned DEFAULT NULL,\
  `b_saddr` int(10) unsigned DEFAULT NULL,\
  `a_received` mediumint(8) unsigned DEFAULT NULL,\
  `b_received` mediumint(8) unsigned DEFAULT NULL,\
  `a_lost` mediumint(8) unsigned DEFAULT NULL,\
  `b_lost` mediumint(8) unsigned DEFAULT NULL,\
  `a_ua_id` int(10) unsigned DEFAULT NULL,\
  `b_ua_id` int(10) unsigned DEFAULT NULL,\
  `a_avgjitter_mult10` mediumint(8) unsigned DEFAULT NULL,\
  `b_avgjitter_mult10` mediumint(8) unsigned DEFAULT NULL,\
  `a_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `b_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `a_sl1` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl2` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl3` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl4` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl5` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl6` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl7` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl8` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl9` mediumint(8) unsigned DEFAULT NULL,\
  `a_sl10` mediumint(8) unsigned DEFAULT NULL,\
  `a_d50` mediumint(8) unsigned DEFAULT NULL,\
  `a_d70` mediumint(8) unsigned DEFAULT NULL,\
  `a_d90` mediumint(8) unsigned DEFAULT NULL,\
  `a_d120` mediumint(8) unsigned DEFAULT NULL,\
  `a_d150` mediumint(8) unsigned DEFAULT NULL,\
  `a_d200` mediumint(8) unsigned DEFAULT NULL,\
  `a_d300` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl1` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl2` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl3` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl4` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl5` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl6` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl7` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl8` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl9` mediumint(8) unsigned DEFAULT NULL,\
  `b_sl10` mediumint(8) unsigned DEFAULT NULL,\
  `b_d50` mediumint(8) unsigned DEFAULT NULL,\
  `b_d70` mediumint(8) unsigned DEFAULT NULL,\
  `b_d90` mediumint(8) unsigned DEFAULT NULL,\
  `b_d120` mediumint(8) unsigned DEFAULT NULL,\
  `b_d150` mediumint(8) unsigned DEFAULT NULL,\
  `b_d200` mediumint(8) unsigned DEFAULT NULL,\
  `b_d300` mediumint(8) unsigned DEFAULT NULL,\
  `a_mos_f1_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_mos_f2_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_mos_adapt_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_f1_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_f2_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_adapt_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_rtcp_loss` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_maxfr` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_avgfr_mult10` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `a_rtcp_avgjitter_mult10` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_loss` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_maxfr` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_avgfr_mult10` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_maxjitter` smallint(5) unsigned DEFAULT NULL,\
  `b_rtcp_avgjitter_mult10` smallint(5) unsigned DEFAULT NULL,\
  `payload` int(11) DEFAULT NULL,\
  `jitter_mult10` mediumint(8) unsigned DEFAULT NULL,\
  `mos_min_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `a_mos_min_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `b_mos_min_mult10` tinyint(3) unsigned DEFAULT NULL,\
  `packet_loss_perc_mult1000` mediumint(8) unsigned DEFAULT NULL,\
  `a_packet_loss_perc_mult1000` mediumint(8) unsigned DEFAULT NULL,\
  `b_packet_loss_perc_mult1000` mediumint(8) unsigned DEFAULT NULL,\
  `delay_sum` mediumint(8) unsigned DEFAULT NULL,\
  `a_delay_sum` mediumint(8) unsigned DEFAULT NULL,\
  `b_delay_sum` mediumint(8) unsigned DEFAULT NULL,\
  `delay_avg_mult100` mediumint(8) unsigned DEFAULT NULL,\
  `a_delay_avg_mult100` mediumint(8) unsigned DEFAULT NULL,\
  `b_delay_avg_mult100` mediumint(8) unsigned DEFAULT NULL,\
  `delay_cnt` mediumint(8) unsigned DEFAULT NULL,\
  `a_delay_cnt` mediumint(8) unsigned DEFAULT NULL,\
  `b_delay_cnt` mediumint(8) unsigned DEFAULT NULL,\
  `rtcp_avgfr_mult10` smallint(5) unsigned DEFAULT NULL,\
  `rtcp_avgjitter_mult10` smallint(5) unsigned DEFAULT NULL,\
  `lost` mediumint(8) unsigned DEFAULT NULL,\
  `id_sensor` smallint(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `calldate` (`calldate`),\
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
  KEY `payload` (`payload`),\
  KEY `id_sensor` (`id_sensor`),\
  CONSTRAINT `cdr_ibfk_1` FOREIGN KEY (`lastSIPresponse_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `cdr_ibfk_2` FOREIGN KEY (`a_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `cdr_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `contenttype` (\
  `id` int(16) unsigned NOT NULL AUTO_INCREMENT,\
  `contenttype` varchar(255) DEFAULT NULL,\
  PRIMARY KEY (`id`),\
  KEY `contenttype` (`contenttype`)\
) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=COMPRESSED;";
	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `message` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `id_contenttype` int(16) unsigned NOT NULL,\
  `calldate` datetime NOT NULL,\
  `caller` varchar(255) DEFAULT NULL,\
  `caller_domain` varchar(255) DEFAULT NULL,\
  `caller_reverse` varchar(255) DEFAULT NULL,\
  `callername` varchar(255) DEFAULT NULL,\
  `callername_reverse` varchar(255) DEFAULT NULL,\
  `called` varchar(255) DEFAULT NULL,\
  `called_domain` varchar(255) DEFAULT NULL,\
  `called_reverse` varchar(255) DEFAULT NULL,\
  `sipcallerip` int(10) unsigned DEFAULT NULL,\
  `sipcalledip` int(10) unsigned DEFAULT NULL,\
  `bye` tinyint(3) unsigned DEFAULT NULL,\
  `lastSIPresponse_id` smallint(5) unsigned DEFAULT NULL,\
  `lastSIPresponseNum` smallint(5) unsigned DEFAULT NULL,\
  `id_sensor` smallint(10) unsigned DEFAULT NULL,\
  `a_ua_id` int(10) unsigned DEFAULT NULL,\
  `b_ua_id` int(10) unsigned DEFAULT NULL,\
  `fbasename` varchar(255) DEFAULT NULL,\
  `message` TEXT CHARACTER SET utf8,\
  PRIMARY KEY (`ID`),\
  KEY `id_contenttype` (`id_contenttype`),\
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
  KEY `fbasename` (`fbasename`),\
  CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`lastSIPresponse_id`) REFERENCES `cdr_sip_response` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`a_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `messages_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE,\
  CONSTRAINT `messages_ibfk_4` FOREIGN KEY (`id_contenttype`) REFERENCES `contenttype` (`id`) ON UPDATE CASCADE\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";
	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `cdr_next` (\
  `cdr_ID` int(10) unsigned NOT NULL,\
  `custom_header1` varchar(255) DEFAULT NULL,\
  `fbasename` varchar(255) DEFAULT NULL,\
  PRIMARY KEY (`cdr_ID`),\
  KEY `fbasename` (`fbasename`),\
  CONSTRAINT `cdr_next_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `register` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `calldate` datetime NOT NULL,\
  `sipcallerip` int(32) unsigned NOT NULL,\
  `sipcalledip` int(32) unsigned NOT NULL,\
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
  `ua_id` int(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `calldate` (`calldate`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`),\
  KEY `from_num` (`from_num`),\
  KEY `digestusername` (`digestusername`)\
) ENGINE=MEMORY DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `register_state` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `created_at` datetime NOT NULL,\
  `sipcallerip` int(32) unsigned NOT NULL,\
  `sipcalledip` int(32) unsigned NOT NULL,\
  `from_num` varchar(255) NULL DEFAULT NULL,\
  `to_num` varchar(255) NULL DEFAULT NULL,\
  `contact_num` varchar(255) NULL DEFAULT NULL,\
  `contact_domain` varchar(255) NULL DEFAULT NULL,\
  `digestusername` varchar(255) NULL DEFAULT NULL,\
  `expires` mediumint NULL DEFAULT NULL,\
  `state` tinyint unsigned NULL DEFAULT NULL,\
  `ua_id` int(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `created_at` (`created_at`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `register_failed` (\
  `ID` int(32) unsigned NOT NULL AUTO_INCREMENT,\
  `counter` int DEFAULT 0,\
  `created_at` datetime NOT NULL,\
  `sipcallerip` int(32) unsigned NOT NULL,\
  `sipcalledip` int(32) unsigned NOT NULL,\
  `from_num` varchar(255) NULL DEFAULT NULL,\
  `to_num` varchar(255) NULL DEFAULT NULL,\
  `contact_num` varchar(255) NULL DEFAULT NULL,\
  `contact_domain` varchar(255) NULL DEFAULT NULL,\
  `digestusername` varchar(255) NULL DEFAULT NULL,\
  `ua_id` int(10) unsigned DEFAULT NULL,\
  PRIMARY KEY (`ID`),\
  KEY `created_at` (`created_at`),\
  KEY `sipcallerip` (`sipcallerip`),\
  KEY `sipcalledip` (`sipcalledip`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `sensors` (\
  `id_sensor` int(32) unsigned NOT NULL,\
  `host` varchar(255) NULL DEFAULT NULL,\
  `port` int(8) NULL DEFAULT NULL,\
  PRIMARY KEY (`id_sensor`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `ipacc` (\
  `saddr` int(32) unsigned NOT NULL,\
  `daddr` int(32) unsigned NOT NULL,\
  `port` smallint(4) unsigned NOT NULL,\
  `proto` smallint(4) unsigned NOT NULL,\
  `octects` int(32) unsigned NOT NULL,\
  `numpackets` mediumint(32) unsigned NOT NULL,\
  `interval` varchar(255) NULL DEFAULT NULL,\
  KEY `saddr` (`saddr`),\
  KEY `daddr` (`daddr`),\
  KEY `port` (`port`),\
  KEY `proto` (`proto`),\
  KEY `interval` (`interval`)\
) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";

	this->query(query);

	query = "CREATE TABLE IF NOT EXISTS `livepacket` (\
	`id` INT UNSIGNED NOT NULL AUTO_INCREMENT ,\
	`id_sensor` INT UNSIGNED DEFAULT NULL,\
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
	INDEX (  `created_at` ,  `microseconds` )\
	) ENGINE=MEMORY DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;";
	this->query(query);

	//5.2 -> 5.3
	sql_noerror = 1;
	if(opt_match_header[0] != '\0') {
		query = "ALTER TABLE cdr_next ADD match_header VARCHAR(128), ADD KEY `match_header` (`match_header`);";
		this->query(query);
	}
	//5.3 -> 5.4
	query = "ALTER TABLE register ADD KEY `to_domain` (`to_domain`), ADD KEY `to_num` (`to_num`);";
	this->query(query);
	query = "ALTER TABLE register_state ADD `to_domain` varchar(255) NULL DEFAULT NULL;";
	this->query(query);
	query = "ALTER TABLE register_failed ADD `to_domain` varchar(255) NULL DEFAULT NULL;";
	this->query(query);

	//5.4 -> 5.5
	query = "ALTER TABLE register_state ADD `sipcalledip` int(32) unsigned, ADD KEY `sipcalledip` (`sipcalledip`);";
	this->query(query);
	query = "ALTER TABLE register_failed ADD `sipcalledip` int(32) unsigned, ADD KEY `sipcalledip` (`sipcalledip`);";
	this->query(query);

	//6.0 -> 6.1
	query = "ALTER TABLE message ADD id_contenttype INT(16) AFTER ID, ADD KEY `id_contenttype` (`id_contenttype`);";
	this->query(query);

	sql_noerror = 0;

	query = "DROP FUNCTION IF EXISTS getIdOrInsertUA ;";
	this->query(query);
	query = "CREATE FUNCTION getIdOrInsertUA(val VARCHAR(255)) RETURNS INT DETERMINISTIC \
BEGIN \
DECLARE _ID INT; \
SET _ID = (SELECT id FROM cdr_ua WHERE ua = val); \
IF ( _ID ) \
THEN \
        RETURN _ID; \
ELSE  \
        INSERT INTO cdr_ua SET ua = val; \
        RETURN LAST_INSERT_ID(); \
END IF; \
END ; ";
	this->query(query);
	
	query = "DROP FUNCTION IF EXISTS getIdOrInsertSIPRES;";
	this->query(query);
	query = "CREATE FUNCTION getIdOrInsertSIPRES(val VARCHAR(255)) RETURNS INT DETERMINISTIC \
BEGIN \
DECLARE _ID INT; \
SET _ID = (SELECT id FROM cdr_sip_response WHERE lastSIPresponse = val); \
IF ( _ID ) \
THEN \
        RETURN _ID; \
ELSE  \
        INSERT INTO cdr_sip_response SET lastSIPresponse = val; \
        RETURN LAST_INSERT_ID(); \
END IF; \
END ; ";
	this->query(query);

	query = "DROP PROCEDURE IF EXISTS PROCESS_SIP_REGISTER ;";
	this->query(query);

	query = "CREATE PROCEDURE PROCESS_SIP_REGISTER(IN calltime VARCHAR(32), IN caller VARCHAR(64), IN callername VARCHAR(64), IN caller_domain VARCHAR(64), IN called VARCHAR(64), IN called_domain VARCHAR(64), IN sipcallerip INT UNSIGNED, sipcalledip INT UNSIGNED, contact_num VARCHAR(64), IN contact_domain VARCHAR(64), IN digest_username VARCHAR(255), IN digest_realm VARCHAR(255), IN regstate INT, mexpires_at VARCHAR(128), IN register_expires INT, IN cdr_ua VARCHAR(255)) \
BEGIN \
DECLARE _ID INT; \
DECLARE _state INT; \
DECLARE _expires_at INT UNSIGNED; \
DECLARE _expired INT; \
SELECT ID, state, expires_at, (UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(calltime)) AS expired INTO _ID, _state, _expires_at, _expired FROM register WHERE to_num = called AND to_domain = called_domain AND digestusername = digest_username ORDER BY ID DESC LIMIT 1; \
IF ( _ID ) \
THEN \
        SET sql_log_bin = 0; \
        DELETE FROM register WHERE ID = _ID; \
        SET sql_log_bin = 1; \
        IF ( _expired > 0 ) THEN \
                INSERT INTO `register_state` SET `created_at` = _expires_at, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `expires` = register_expires, state = 5, ua_id = getIdOrInsertUA(cdr_ua); \
        END IF; \
        IF ( _state <> regstate AND register_expires = 0) \
        THEN \
                INSERT INTO `register_state` SET `created_at` = calltime, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `expires` = register_expires, state = regstate, ua_id = getIdOrInsertUA(cdr_ua); \
        END IF; \
ELSE \
        INSERT INTO `register_state` SET `created_at` = calltime, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `expires` = register_expires, state = regstate, ua_id = getIdOrInsertUA(cdr_ua);\
END IF; \
IF ( register_expires > 0 ) \
THEN \
        INSERT INTO `register` SET `calldate` = calltime, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `from_name` = callername, `from_domain` = caller_domain, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `digestrealm` = digest_realm, `expires` = register_expires, state = regstate, ua_id = getIdOrInsertUA(cdr_ua), `expires_at` = mexpires_at; \
END IF; \
END ; ";

	this->query(query);

//	this->multi_on();
}


void SqlDb_odbc::createSchema() {
	string query;
	
	query = "IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr_sip_response') BEGIN\
  CREATE TABLE cdr_sip_response (\
  id smallint PRIMARY KEY IDENTITY,\
  lastSIPresponse varchar(255) DEFAULT NULL);\
  CREATE UNIQUE INDEX lastSIPresponse ON cdr_sip_response (lastSIPresponse);\
  END";

	this->query(query);

	
}
