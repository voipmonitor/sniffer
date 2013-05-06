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
extern int terminating;
extern int opt_id_sensor;
extern bool opt_cdr_partition;
extern char get_customers_pn_query[1024];
extern char mysql_database[256];

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
	this->existsColumnCalldateInCdrNext = false;
	this->existsColumnCalldateInCdrRtp = false;
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

void SqlDb::prepareQuery(string *query) {
	size_t findPos;
	if(this->getSubtypeDb() == "mssql") {
		const char *substFce[][2] = { 
				{ "UNIX_TIMESTAMP", "dbo.unix_timestamp" },
				{ "NOW", "dbo.now" },
				{ "SUBTIME", "dbo.subtime" }
		};
		for(unsigned int i = 0; i < sizeof(substFce)/sizeof(substFce[0]); i++) {
			while((findPos  = query->find(substFce[i][0])) != string::npos) {
				query->replace(findPos, strlen(substFce[i][0]), substFce[i][1]);
			}
		}
	}
	while((findPos  = query->find("_LC_[")) != string::npos) {
		size_t findPosEnd = query->find("]", findPos);
		if(findPosEnd != string::npos) {
			string lc = query->substr(findPos + 5, findPosEnd - findPos - 5);
			if(this->getSubtypeDb() == "mssql") {
				lc = "case when " + lc + " then 1 else 0 end";
			}
			query->replace(findPos, findPosEnd - findPos + 1, lc);
		}
	}
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
			this->query("SET sql_mode = ''");
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
	return(this->hMysqlConn != NULL);
}

bool SqlDb_mysql::query(string query) {
	this->prepareQuery(&query);
	if(verbosity > 1) { 
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
				if(!sql_noerror) {
					this->checkLastError("query error in [" + query + "]", true);
				}
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
		if(terminating) {
			break;
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
	this->prepareQuery(&query);
	if(verbosity > 1) { 
		cout << query << endl;
	}
	SQLRETURN rslt = SQL_NULL_DATA;
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
			this->checkLastError("odbc: error in allocate statement handle", true);
			this->reconnect();
			continue;
		}
		rslt = SQLExecDirect(this->hStatement, (SQLCHAR*)query.c_str(), SQL_NTS);   
		if(!this->okRslt(rslt) && rslt != SQL_NO_DATA) {
			if(!sql_noerror) {
				this->checkLastError("odbc query error", true);
			}
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
		if(terminating) {
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
			this->checkLastError("odbc fetch error", true);
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

void *MySqlStore_process_storing(void *storeProcess_addr) {
	MySqlStore_process *storeProcess = (MySqlStore_process*)storeProcess_addr;
	storeProcess->store();
	return(NULL);
}
	
MySqlStore_process::MySqlStore_process(int id, const char *host, const char *user, const char *password, const char *database) {
	this->id = id;
	this->terminated = false;
	this->sqlDb = new SqlDb_mysql();
	this->sqlDb->setConnectParameters(host, user, password, database);
	this->sqlDb->connect();
	this->sqlDb->enableSysLog();
	pthread_mutex_init(&this->lock_mutex, NULL);
	pthread_create(&this->thread, NULL, MySqlStore_process_storing, this);
}

MySqlStore_process::~MySqlStore_process() {
	while(!this->terminated) {
		usleep(100000);
	}
	pthread_detach(this->thread);
	if(this->sqlDb) {
		delete this->sqlDb;
	}
}

void MySqlStore_process::query(const char *query_str) {
	this->query_buff.push(query_str);
}

void MySqlStore_process::store() {
	char insert_funcname[20];
	sprintf(insert_funcname, "__insert_%i", this->id);
	if(opt_id_sensor > -1) {
		sprintf(insert_funcname + strlen(insert_funcname), "S%i", opt_id_sensor);
	}
	while(1) {
		int size = 0;
		int msgs = 50;
		string queryqueue = "";
		while(1) {
			this->lock();
			if(this->query_buff.size() == 0) {
				this->unlock();
				if(queryqueue != "") {
					this->sqlDb->query(string("drop procedure if exists ") + insert_funcname);
					this->sqlDb->query(string("create procedure ") + insert_funcname + "()\nbegin\n" + queryqueue + "\nend");
					this->sqlDb->query(string("call ") + insert_funcname + "();");
					queryqueue = "";
					if(verbosity > 1) {
						cout << "STORE id: " << this->id << endl;
					}
				}
				break;
			}
			string query = this->query_buff.front();
			this->query_buff.pop();
			this->unlock();
			queryqueue.append(query + "; ");
			if(size < msgs) {
				size++;
			} else {
				this->sqlDb->query(string("drop procedure if exists ") + insert_funcname);
				this->sqlDb->query(string("create procedure ") + insert_funcname + "()\nbegin\n" + queryqueue + "\nend");
				this->sqlDb->query(string("call ") + insert_funcname + "();");
				queryqueue = "";
				size = 0;
				if(verbosity > 1) {
					cout << "STORE id: " << this->id << endl;
				}
			}
		}
		if(terminating) {
			break;
		}
		sleep(1);
	}
	this->terminated = true;
}

void MySqlStore_process::lock() {
	pthread_mutex_lock(&this->lock_mutex);
}

void MySqlStore_process::unlock() {
	pthread_mutex_unlock(&this->lock_mutex);
}

MySqlStore::MySqlStore(const char *host, const char *user, const char *password, const char *database) {
	this->host = host;
	this->user = user;
	this->password = password;
	this->database = database;
}

MySqlStore::~MySqlStore() {
	map<int, MySqlStore_process*>::iterator iter;
	for(iter = this->processes.begin(); iter != this->processes.end(); ++iter) {
		delete iter->second;
	}
}

void MySqlStore::query(const char *query_str, int id) {
	MySqlStore_process* process = this->find(id);
	process->query(query_str);
}

void MySqlStore::lock(int id) {
	MySqlStore_process* process = this->find(id);
	process->lock();
}

void MySqlStore::unlock(int id) {
	MySqlStore_process* process = this->find(id);
	process->unlock();
}

MySqlStore_process *MySqlStore::find(int id) {
	MySqlStore_process* process = this->processes[id];
	if(process) {
		return(process);
	}
	process = new MySqlStore_process(id, this->host.c_str(), this->user.c_str(), this->password.c_str(), this->database.c_str());
	this->processes[id] = process;
	return(process);
}

string sqlDateTimeString(time_t unixTime) {
	struct tm * localTime = localtime(&unixTime);
	char dateTimeBuffer[50];
	strftime(dateTimeBuffer, sizeof(dateTimeBuffer), "%Y-%m-%d %H:%M:%S", localTime);
	return string(dateTimeBuffer);
}

string sqlDateString(time_t unixTime) {
	struct tm * localTime = localtime(&unixTime);
	char dateBuffer[50];
	strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d", localTime);
	return string(dateBuffer);
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

	syslog(LOG_DEBUG, "creating and upgrading MySQL schema...");
	this->multi_off();

	this->query(
	"CREATE TABLE IF NOT EXISTS `filter_ip` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`ip` int unsigned DEFAULT NULL,\
			`mask` int DEFAULT NULL,\
			`direction` tinyint DEFAULT '0',\
			`rtp` tinyint DEFAULT '0',\
			`sip` tinyint DEFAULT '0',\
			`register` tinyint DEFAULT '0',\
			`graph` tinyint DEFAULT '0',\
			`wav` tinyint DEFAULT '0',\
			`note` text,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `filter_telnum` (\
			`id` int NOT NULL AUTO_INCREMENT,\
			`prefix` bigint unsigned DEFAULT NULL,\
			`fixed_len` int unsigned DEFAULT '0',\
			`direction` tinyint DEFAULT '0',\
			`rtp` tinyint DEFAULT '0',\
			`sip` tinyint DEFAULT '0',\
			`register` tinyint DEFAULT '0',\
			`graph` tinyint DEFAULT '0',\
			`wav` tinyint DEFAULT '0',\
			`note` text,\
		PRIMARY KEY (`id`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `cdr_sip_response` (\
			`id` smallint unsigned NOT NULL AUTO_INCREMENT,\
			`lastSIPresponse` varchar(255) DEFAULT NULL,\
		PRIMARY KEY (`id`),\
		UNIQUE KEY `lastSIPresponse` (`lastSIPresponse`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `cdr_ua` (\
			`id` int unsigned NOT NULL AUTO_INCREMENT,\
			`ua` varchar(512) DEFAULT NULL,\
		PRIMARY KEY (`id`),\
		UNIQUE KEY `ua` (`ua`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;");

	char partDayName[20] = "";
	char limitDay[20] = "";
	if(opt_cdr_partition) {
		time_t act_time = time(NULL);
		struct tm *actTime = localtime(&act_time);
		strftime(partDayName, sizeof(partDayName), "p%y%m%d", actTime);
		time_t next_day_time = act_time + 24 * 60 * 60;
		struct tm *nextDayTime = localtime(&next_day_time);
		strftime(limitDay, sizeof(partDayName), "%Y-%m-%d", nextDayTime);
	}
	
	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr` (\
			`ID` int unsigned NOT NULL AUTO_INCREMENT,\
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
			`sipcalledip` int unsigned DEFAULT NULL,\
			`whohanged` enum('caller','callee') DEFAULT NULL,\
			`bye` tinyint unsigned DEFAULT NULL,\
			`lastSIPresponse_id` smallint unsigned DEFAULT NULL,\
			`lastSIPresponseNum` smallint unsigned DEFAULT NULL,\
			`sighup` tinyint DEFAULT NULL,\
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
			`a_mos_f1_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_f2_mult10` tinyint unsigned DEFAULT NULL,\
			`a_mos_adapt_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f1_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_f2_mult10` tinyint unsigned DEFAULT NULL,\
			`b_mos_adapt_mult10` tinyint unsigned DEFAULT NULL,\
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
			`id_sensor` smallint unsigned DEFAULT NULL,") + 
			(get_customers_pn_query[0] ?
				"`caller_customer_id` int DEFAULT NULL,\
				`caller_reseller_id` char(10) DEFAULT NULL,\
				`called_customer_id` int DEFAULT NULL,\
				`called_reseller_id` char(10) DEFAULT NULL," :
				"") +
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
			CONSTRAINT `cdr_ibfk_3` FOREIGN KEY (`b_ua_id`) REFERENCES `cdr_ua` (`id`) ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED" + 
	(opt_cdr_partition ?
		string(" PARTITION BY RANGE COLUMNS(calldate)(\
			PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)" :
		""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_next` (\
			`cdr_ID` int unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`custom_header1` varchar(255) DEFAULT NULL,\
			`fbasename` varchar(255) DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`cdr_ID`, `calldate`)," :
			"PRIMARY KEY (`cdr_ID`),") +
		"KEY `fbasename` (`fbasename`)" + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_next_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED" + 
	(opt_cdr_partition ?
		string(" PARTITION BY RANGE COLUMNS(calldate)(\
			PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)" :
		""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_rtp` (\
			`ID` int unsigned NOT NULL AUTO_INCREMENT,\
			`cdr_ID` int unsigned NOT NULL,") +
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
			`maxjitter_mult10` smallint unsigned DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `calldate`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY (`cdr_ID`)" + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_rtp_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED" + 
	(opt_cdr_partition ?
		string(" PARTITION BY RANGE COLUMNS(calldate)(\
			PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)" :
		""));

	this->query(string(
	"CREATE TABLE IF NOT EXISTS `cdr_dtmf` (\
			`ID` int unsigned NOT NULL AUTO_INCREMENT,\
			`cdr_ID` int unsigned NOT NULL,") +
			(opt_cdr_partition ?
				"`calldate` datetime NOT NULL," :
				"") + 
			"`daddr` int unsigned DEFAULT NULL,\
			`saddr` int unsigned DEFAULT NULL,\
			`firsttime` float DEFAULT NULL,\
			`dtmf` char DEFAULT NULL," +
		(opt_cdr_partition ? 
			"PRIMARY KEY (`ID`, `calldate`)," :
			"PRIMARY KEY (`ID`),") +
		"KEY (`cdr_ID`)" + 
		(opt_cdr_partition ?
			"" :
			",CONSTRAINT `cdr_dtmf_ibfk_1` FOREIGN KEY (`cdr_ID`) REFERENCES `cdr` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE") +
	") ENGINE=InnoDB DEFAULT CHARSET=latin1" + 
	(opt_cdr_partition ?
		string(" PARTITION BY RANGE COLUMNS(calldate)(\
			PARTITION ") + partDayName + " VALUES LESS THAN ('" + limitDay + "') engine innodb)" :
		""));

	this->query(
	"CREATE TABLE IF NOT EXISTS `contenttype` (\
			`id` int unsigned NOT NULL AUTO_INCREMENT,\
			`contenttype` varchar(255) DEFAULT NULL,\
		PRIMARY KEY (`id`),\
		KEY `contenttype` (`contenttype`)\
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 ROW_FORMAT=COMPRESSED;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `message` (\
			`ID` int unsigned NOT NULL AUTO_INCREMENT,\
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
			`lastSIPresponse_id` smallint unsigned DEFAULT NULL,\
			`lastSIPresponseNum` smallint unsigned DEFAULT NULL,\
			`id_sensor` smallint unsigned DEFAULT NULL,\
			`a_ua_id` int unsigned DEFAULT NULL,\
			`b_ua_id` int unsigned DEFAULT NULL,\
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
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;");


	this->query(
	"CREATE TABLE IF NOT EXISTS `register` (\
			`ID` int unsigned NOT NULL AUTO_INCREMENT,\
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
		PRIMARY KEY (`ID`),\
		KEY `calldate` (`calldate`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`),\
		KEY `from_num` (`from_num`),\
		KEY `digestusername` (`digestusername`)\
	) ENGINE=MEMORY DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `register_state` (\
			`ID` int unsigned NOT NULL AUTO_INCREMENT,\
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
		PRIMARY KEY (`ID`),\
		KEY `created_at` (`created_at`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;");

	this->query(
	"CREATE TABLE IF NOT EXISTS `register_failed` (\
			`ID` int unsigned NOT NULL AUTO_INCREMENT,\
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
		PRIMARY KEY (`ID`),\
		KEY `created_at` (`created_at`),\
		KEY `sipcallerip` (`sipcallerip`),\
		KEY `sipcalledip` (`sipcalledip`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;");

	this->query("CREATE TABLE IF NOT EXISTS `sensors` (\
			`id_sensor` int unsigned NOT NULL,\
			`host` varchar(255) NULL DEFAULT NULL,\
			`port` int NULL DEFAULT NULL,\
		PRIMARY KEY (`id_sensor`)\
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;");

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
	) ENGINE=InnoDB DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;");

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
	) ENGINE=MEMORY DEFAULT CHARSET=latin1 ROW_FORMAT=COMPRESSED;");
	
	sql_noerror = 1;
	
	if(opt_cdr_partition) {
		this->query(
		"create procedure create_partition(database_name char(100), table_name char(100), type_part char(10), next_days int)\
		 begin\
		    declare part_date date;\
		    declare part_limit date;\
		    declare part_name char(100);\
		    declare test_exists_part_query varchar(1000);\
		    declare create_part_query varchar(1000);\
		    set part_date =  date_add(date(now()), interval next_days day);\
		    if(type_part = 'month') then\
		       set part_date = date_add(part_date, interval -(day(part_date)-1) day);\
		       set part_limit = date_add(part_date, interval 1 month);\
		       set part_name = concat('p', date_format(part_date, '%y%m'));\
		    else\
		       set part_limit = date_add(part_date, interval 1 day);\
		       set part_name = concat('p', date_format(part_date, '%y%m%d'));\
		    end if;\
		    set test_exists_part_query = concat(\
		       'set @_exists_part = exists (select * from information_schema.partitions where table_schema=\'',\
		       database_name,\
		       '\' and table_name = \'',\
		       table_name,\
		       '\' and partition_name = \'',\
		       part_name,\
		       '\')');\
		    set @_test_exists_part_query = test_exists_part_query;\
		    prepare stmt FROM @_test_exists_part_query;\
		    execute stmt;\
		    deallocate prepare stmt;\
		    if(not @_exists_part) then\
		       set create_part_query = concat(\
			  'alter table ',\
			  if(database_name is not null, concat('`', database_name, '`.'), ''),\
			  '`',\
			  table_name,\
			  '` add partition (partition ',\
			  part_name,\
			  ' VALUES LESS THAN (\'',\
			  part_limit,\
			  '\'))');\
		       set @_create_part_query = create_part_query;\
		       prepare stmt FROM @_create_part_query;\
		       execute stmt;\
		       deallocate prepare stmt;\
		    end if;\
		 end");
		this->query(
		"create procedure create_partitions_cdr(database_name char(100), next_days int)\
		 begin\
		    call create_partition(database_name, 'cdr', 'day', next_days);\
		    call create_partition(database_name, 'cdr_next', 'day', next_days);\
		    call create_partition(database_name, 'cdr_rtp', 'day', next_days);\
		    call create_partition(database_name, 'cdr_dtmf', 'day', next_days);\
		 end");
		this->query(string(
		"create event if not exists cdr_add_partition\
		 on schedule every 1 hour do\
		 begin\
		    call ") + mysql_database + ".create_partitions_cdr('" + mysql_database + "', 1);\
		 end");
		this->query(string(
		"call ") + mysql_database + ".create_partitions_cdr('" + mysql_database + "', 0);");
		this->query(string(
		"call ") + mysql_database + ".create_partitions_cdr('" + mysql_database + "', 1);");
	}

	//5.2 -> 5.3
	if(opt_match_header[0] != '\0') {
		this->query("ALTER TABLE cdr_next\
				ADD match_header VARCHAR(128),\
				ADD KEY `match_header` (`match_header`);");
	}
	//5.3 -> 5.4
	this->query("ALTER TABLE register\
			ADD KEY `to_domain` (`to_domain`),\
			ADD KEY `to_num` (`to_num`);");
	this->query("ALTER TABLE register_state\
			ADD `to_domain` varchar(255) NULL DEFAULT NULL;");
	this->query("ALTER TABLE register_failed\
			ADD `to_domain` varchar(255) NULL DEFAULT NULL;");
	//5.4 -> 5.5
	this->query("ALTER TABLE register_state\
			ADD `sipcalledip` int unsigned,\
			ADD KEY `sipcalledip` (`sipcalledip`);");
	this->query("ALTER TABLE register_failed\
			ADD `sipcalledip` int unsigned,\
			ADD KEY `sipcalledip` (`sipcalledip`);");
	//6.0 -> 6.1
	this->query("ALTER TABLE message\
			ADD id_contenttype INT AFTER ID,\
			ADD KEY `id_contenttype` (`id_contenttype`);");

	sql_noerror = 0;

	this->query("DROP FUNCTION IF EXISTS getIdOrInsertUA;");
	this->query("CREATE FUNCTION getIdOrInsertUA(val VARCHAR(255)) RETURNS INT DETERMINISTIC \
			BEGIN \
				DECLARE _ID INT; \
				SET _ID = (SELECT id FROM cdr_ua WHERE ua = val); \
				IF ( _ID ) THEN \
					RETURN _ID; \
				ELSE  \
					INSERT INTO cdr_ua SET ua = val; \
					RETURN LAST_INSERT_ID(); \
				END IF; \
			END;");
	
	this->query("DROP FUNCTION IF EXISTS getIdOrInsertSIPRES;");
	this->query("CREATE FUNCTION getIdOrInsertSIPRES(val VARCHAR(255)) RETURNS INT DETERMINISTIC \
			BEGIN \
				DECLARE _ID INT; \
				SET _ID = (SELECT id FROM cdr_sip_response WHERE lastSIPresponse = val); \
				IF ( _ID ) THEN \
					RETURN _ID; \
				ELSE  \
					INSERT INTO cdr_sip_response SET lastSIPresponse = val; \
					RETURN LAST_INSERT_ID(); \
				END IF; \
			END;");

	this->query("DROP PROCEDURE IF EXISTS PROCESS_SIP_REGISTER;");
	this->query("CREATE PROCEDURE PROCESS_SIP_REGISTER(IN calltime VARCHAR(32), IN caller VARCHAR(64), IN callername VARCHAR(64), IN caller_domain VARCHAR(64), IN called VARCHAR(64), IN called_domain VARCHAR(64), IN sipcallerip INT UNSIGNED, sipcalledip INT UNSIGNED, contact_num VARCHAR(64), IN contact_domain VARCHAR(64), IN digest_username VARCHAR(255), IN digest_realm VARCHAR(255), IN regstate INT, mexpires_at VARCHAR(128), IN register_expires INT, IN cdr_ua VARCHAR(255), IN fname BIGINT, IN id_sensor INT) \
			BEGIN \
				DECLARE _ID INT; \
				DECLARE _state INT; \
				DECLARE _expires_at DATETIME; \
				DECLARE _expired INT; \
				SELECT ID, state, expires_at, (UNIX_TIMESTAMP(expires_at) < UNIX_TIMESTAMP(calltime)) AS expired INTO _ID, _state, _expires_at, _expired FROM register WHERE to_num = called AND to_domain = called_domain ORDER BY ID DESC LIMIT 1; \
				IF ( _ID ) THEN \
					SET sql_log_bin = 0; \
					DELETE FROM register WHERE ID = _ID; \
					SET sql_log_bin = 1; \
					IF ( _expired > 5 ) THEN \
						INSERT INTO `register_state` SET `id_sensor` = id_sensor, `fname` = fname, `created_at` = _expires_at, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `expires` = register_expires, state = 5, ua_id = getIdOrInsertUA(cdr_ua); \
					END IF; \
					IF ( _state <> regstate OR register_expires = 0) THEN \
						INSERT INTO `register_state` SET `id_sensor` = id_sensor, `fname` = fname, `created_at` = calltime, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `expires` = register_expires, state = regstate, ua_id = getIdOrInsertUA(cdr_ua); \
					END IF; \
				ELSE \
					INSERT INTO `register_state` SET `id_sensor` = id_sensor, `fname` = fname, `created_at` = calltime, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `expires` = register_expires, state = regstate, ua_id = getIdOrInsertUA(cdr_ua);\
				END IF; \
				IF ( register_expires > 0 ) THEN \
					INSERT INTO `register` SET `id_sensor` = id_sensor, `fname` = fname, `calldate` = calltime, `sipcallerip` = sipcallerip, `sipcalledip` = sipcalledip, `from_num` = caller, `from_name` = callername, `from_domain` = caller_domain, `to_num` = called, `to_domain` = called_domain, `contact_num` = contact_num, `contact_domain` = contact_domain, `digestusername` = digest_username, `digestrealm` = digest_realm, `expires` = register_expires, state = regstate, ua_id = getIdOrInsertUA(cdr_ua), `expires_at` = mexpires_at; \
				END IF; \
			END;");

	//this->multi_on();

	//6.5RC2 ->
	sql_noerror = 1;
	this->query("ALTER TABLE message ADD GeoPosition varchar(255)");
	this->query("ALTER TABLE cdr_next ADD GeoPosition varchar(255)");
	this->query("ALTER TABLE register\
			ADD `fname` BIGINT NULL DEFAULT NULL;");
	this->query("ALTER TABLE register_failed\
			ADD `fname` BIGINT NULL DEFAULT NULL;");
	this->query("ALTER TABLE register_state\
			ADD `fname` BIGINT NULL DEFAULT NULL;");
	this->query("ALTER TABLE register\
			ADD `id_sensor` INT NULL DEFAULT NULL;");
	this->query("ALTER TABLE register_failed\
			ADD `id_sensor` INT NULL DEFAULT NULL;");
	this->query("ALTER TABLE register_state\
			ADD `id_sensor` INT NULL DEFAULT NULL;");
	sql_noerror = 0;
	syslog(LOG_DEBUG, "done");
}

void SqlDb_mysql::checkSchema() {
	this->query("show columns from cdr_next where Field='calldate'");
	this->existsColumnCalldateInCdrNext = this->fetchRow();
	this->query("show columns from cdr_rtp where Field='calldate'");
	this->existsColumnCalldateInCdrRtp = this->fetchRow();
}


void SqlDb_odbc::createSchema() {
	
	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'filter_ip') BEGIN\
		CREATE TABLE filter_ip (\
			id int PRIMARY KEY IDENTITY,\
			ip bigint NULL,\
			mask int NULL,\
			direction tinyint DEFAULT '0',\
			rtp tinyint DEFAULT '0',\
			sip tinyint DEFAULT '0',\
			register tinyint DEFAULT '0',\
			graph tinyint DEFAULT '0',\
			wav tinyint DEFAULT '0',\
			note text);\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'filter_telnum') BEGIN\
		CREATE TABLE filter_telnum (\
			id int PRIMARY KEY IDENTITY,\
			prefix bigint NULL,\
			fixed_len int DEFAULT '0',\
			direction tinyint DEFAULT '0',\
			rtp tinyint DEFAULT '0',\
			sip tinyint DEFAULT '0',\
			register tinyint DEFAULT '0',\
			graph tinyint DEFAULT '0',\
			wav tinyint DEFAULT '0',\
			note text);\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr_sip_response') BEGIN\
		CREATE TABLE cdr_sip_response (\
			id smallint PRIMARY KEY IDENTITY,\
			lastSIPresponse varchar(255) NULL);\
		CREATE UNIQUE INDEX lastSIPresponse ON cdr_sip_response (lastSIPresponse);\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr_ua') BEGIN\
		CREATE TABLE cdr_ua (\
			id int PRIMARY KEY IDENTITY,\
			ua varchar(512) NULL);\
		CREATE UNIQUE INDEX ua ON cdr_ua (ua);\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr') BEGIN\
		CREATE TABLE cdr (\
			ID int PRIMARY KEY IDENTITY,\
			calldate datetime NOT NULL,\
			callend datetime NOT NULL,\
			duration int NULL,\
			connect_duration int NULL,\
			progress_time int NULL,\
			first_rtp_time int NULL,\
			caller varchar(255) NULL,\
			caller_domain varchar(255) NULL,\
			caller_reverse varchar(255) NULL,\
			callername varchar(255) NULL,\
			callername_reverse varchar(255) NULL,\
			called varchar(255) NULL,\
			called_domain varchar(255) NULL,\
			called_reverse varchar(255) NULL,\
			sipcallerip bigint NULL,\
			sipcalledip bigint NULL,\
			whohanged char(10) NULL,\
			bye tinyint NULL,\
			lastSIPresponse_id smallint NULL\
				FOREIGN KEY REFERENCES cdr_sip_response (id),\
			lastSIPresponseNum smallint NULL,\
			sighup tinyint NULL,\
			a_index tinyint NULL,\
			b_index tinyint NULL,\
			a_payload int NULL,\
			b_payload int NULL,\
			a_saddr bigint NULL,\
			b_saddr bigint NULL,\
			a_received int NULL,\
			b_received int NULL,\
			a_lost int NULL,\
			b_lost int NULL,\
			a_ua_id int NULL\
				FOREIGN KEY REFERENCES cdr_ua (id),\
			b_ua_id int NULL\
				FOREIGN KEY REFERENCES cdr_ua (id),\
			a_avgjitter_mult10 int NULL,\
			b_avgjitter_mult10 int NULL,\
			a_maxjitter smallint NULL,\
			b_maxjitter smallint NULL,\
			a_sl1 int NULL,\
			a_sl2 int NULL,\
			a_sl3 int NULL,\
			a_sl4 int NULL,\
			a_sl5 int NULL,\
			a_sl6 int NULL,\
			a_sl7 int NULL,\
			a_sl8 int NULL,\
			a_sl9 int NULL,\
			a_sl10 int NULL,\
			a_d50 int NULL,\
			a_d70 int NULL,\
			a_d90 int NULL,\
			a_d120 int NULL,\
			a_d150 int NULL,\
			a_d200 int NULL,\
			a_d300 int NULL,\
			b_sl1 int NULL,\
			b_sl2 int NULL,\
			b_sl3 int NULL,\
			b_sl4 int NULL,\
			b_sl5 int NULL,\
			b_sl6 int NULL,\
			b_sl7 int NULL,\
			b_sl8 int NULL,\
			b_sl9 int NULL,\
			b_sl10 int NULL,\
			b_d50 int NULL,\
			b_d70 int NULL,\
			b_d90 int NULL,\
			b_d120 int NULL,\
			b_d150 int NULL,\
			b_d200 int NULL,\
			b_d300 int NULL,\
			a_mos_f1_mult10 tinyint NULL,\
			a_mos_f2_mult10 tinyint NULL,\
			a_mos_adapt_mult10 tinyint NULL,\
			b_mos_f1_mult10 tinyint NULL,\
			b_mos_f2_mult10 tinyint NULL,\
			b_mos_adapt_mult10 tinyint NULL,\
			a_rtcp_loss smallint NULL,\
			a_rtcp_maxfr smallint NULL,\
			a_rtcp_avgfr_mult10 smallint NULL,\
			a_rtcp_maxjitter smallint NULL,\
			a_rtcp_avgjitter_mult10 smallint NULL,\
			b_rtcp_loss smallint NULL,\
			b_rtcp_maxfr smallint NULL,\
			b_rtcp_avgfr_mult10 smallint NULL,\
			b_rtcp_maxjitter smallint NULL,\
			b_rtcp_avgjitter_mult10 smallint NULL,\
			payload int NULL,\
			jitter_mult10 int NULL,\
			mos_min_mult10 tinyint NULL,\
			a_mos_min_mult10 tinyint NULL,\
			b_mos_min_mult10 tinyint NULL,\
			packet_loss_perc_mult1000 int NULL,\
			a_packet_loss_perc_mult1000 int NULL,\
			b_packet_loss_perc_mult1000 int NULL,\
			delay_sum int NULL,\
			a_delay_sum int NULL,\
			b_delay_sum int NULL,\
			delay_avg_mult100 int NULL,\
			a_delay_avg_mult100 int NULL,\
			b_delay_avg_mult100 int NULL,\
			delay_cnt int NULL,\
			a_delay_cnt int NULL,\
			b_delay_cnt int NULL,\
			rtcp_avgfr_mult10 smallint NULL,\
			rtcp_avgjitter_mult10 smallint NULL,\
			lost int NULL,\
			id_sensor smallint NULL,);\
		CREATE INDEX calldate ON cdr (calldate);\
		CREATE INDEX callend ON cdr (callend);\
		CREATE INDEX duration ON cdr (duration);\
		CREATE INDEX source ON cdr (caller);\
		CREATE INDEX source_reverse ON cdr (caller_reverse);\
		CREATE INDEX destination ON cdr (called);\
		CREATE INDEX destination_reverse ON cdr (called_reverse);\
		CREATE INDEX callername ON cdr (callername);\
		CREATE INDEX callername_reverse ON cdr (callername_reverse);\
		CREATE INDEX sipcallerip ON cdr (sipcallerip);\
		CREATE INDEX sipcalledip ON cdr (sipcalledip);\
		CREATE INDEX lastSIPresponseNum ON cdr (lastSIPresponseNum);\
		CREATE INDEX bye ON cdr (bye);\
		CREATE INDEX a_saddr ON cdr (a_saddr);\
		CREATE INDEX b_saddr ON cdr (b_saddr);\
		CREATE INDEX a_lost ON cdr (a_lost);\
		CREATE INDEX b_lost ON cdr (b_lost);\
		CREATE INDEX a_maxjitter ON cdr (a_maxjitter);\
		CREATE INDEX b_maxjitter ON cdr (b_maxjitter);\
		CREATE INDEX a_rtcp_loss ON cdr (a_rtcp_loss);\
		CREATE INDEX a_rtcp_maxfr ON cdr (a_rtcp_maxfr);\
		CREATE INDEX a_rtcp_maxjitter ON cdr (a_rtcp_maxjitter);\
		CREATE INDEX b_rtcp_loss ON cdr (b_rtcp_loss);\
		CREATE INDEX b_rtcp_maxfr ON cdr (b_rtcp_maxfr);\
		CREATE INDEX b_rtcp_maxjitter ON cdr (b_rtcp_maxjitter);\
		CREATE INDEX a_ua_id ON cdr (a_ua_id);\
		CREATE INDEX b_ua_id ON cdr (b_ua_id);\
		CREATE INDEX a_avgjitter_mult10 ON cdr (a_avgjitter_mult10);\
		CREATE INDEX b_avgjitter_mult10 ON cdr (b_avgjitter_mult10);\
		CREATE INDEX a_rtcp_avgjitter_mult10 ON cdr (a_rtcp_avgjitter_mult10);\
		CREATE INDEX b_rtcp_avgjitter_mult10 ON cdr (b_rtcp_avgjitter_mult10);\
		CREATE INDEX lastSIPresponse_id ON cdr (lastSIPresponse_id);\
		CREATE INDEX payload ON cdr (payload);\
		CREATE INDEX id_sensor ON cdr (id_sensor);\
	END");
	
	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr_next') BEGIN\
		CREATE TABLE cdr_next (\
			cdr_ID int PRIMARY KEY NOT NULL\
				FOREIGN KEY REFERENCES cdr (ID),\
			custom_header1 varchar(255) NULL,\
			fbasename varchar(255) NULL);\
		CREATE INDEX fbasename ON cdr_next (fbasename);\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr_rtp') BEGIN\
		CREATE TABLE cdr_rtp (\
			ID int PRIMARY KEY IDENTITY,\
			cdr_ID int \
				FOREIGN KEY REFERENCES cdr (ID),\
			`saddr` bigint NULL,\
			`daddr` bigint NULL,\
			`ssrc` bigint NULL,\
			`received` int NULL,\
			`loss` int NULL,\
			`firsttime` float NULL,\
			`payload` smallint NULL,\
			`maxjitter_mult10` smallint DEFAULT NULL;\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'cdr_dtmf') BEGIN\
		CREATE TABLE cdr_dtmf (\
			ID int PRIMARY KEY IDENTITY,\
			cdr_ID int \
				FOREIGN KEY REFERENCES cdr (ID),\
			`firsttime` float NULL,\
			`dtmf` char NULL\
			`daddr` bigint DEFAULT NULL,\
			`saddr` bigint DEFAULT NULL;\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'contenttype') BEGIN\
		CREATE TABLE contenttype (\
			id int PRIMARY KEY IDENTITY,\
			contenttype varchar(255) NULL);\
		CREATE INDEX contenttype ON contenttype (contenttype);\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'message') BEGIN\
		CREATE TABLE message (\
			ID int PRIMARY KEY IDENTITY,\
			id_contenttype int NOT NULL\
				FOREIGN KEY REFERENCES contenttype (id),\
			calldate datetime NOT NULL,\
			caller varchar(255) NULL,\
			caller_domain varchar(255) NULL,\
			caller_reverse varchar(255) NULL,\
			callername varchar(255) NULL,\
			callername_reverse varchar(255) NULL,\
			called varchar(255) NULL,\
			called_domain varchar(255) NULL,\
			called_reverse varchar(255) NULL,\
			sipcallerip bigint NULL,\
			sipcalledip bigint NULL,\
			bye tinyint NULL,\
			lastSIPresponse_id smallint NULL\
				FOREIGN KEY REFERENCES cdr_sip_response (id),\
			lastSIPresponseNum smallint NULL,\
			id_sensor smallint NULL,\
			a_ua_id int NULL\
				FOREIGN KEY REFERENCES cdr_ua (id),\
			b_ua_id int NULL\
				FOREIGN KEY REFERENCES cdr_ua (id),\
			fbasename varchar(255) NULL,\
			message TEXT);\
		CREATE INDEX calldate ON message (calldate);\
		CREATE INDEX caller ON message (caller);\
		CREATE INDEX caller_domain ON message (caller_domain);\
		CREATE INDEX caller_reverse ON message (caller_reverse);\
		CREATE INDEX callername ON message (callername);\
		CREATE INDEX callername_reverse ON message (callername_reverse);\
		CREATE INDEX called ON message (called);\
		CREATE INDEX called_reverse ON message (called_reverse);\
		CREATE INDEX sipcallerip ON message (sipcallerip);\
		CREATE INDEX sipcalledip ON message (sipcalledip);\
		CREATE INDEX lastSIPresponseNum ON message (lastSIPresponseNum);\
		CREATE INDEX bye ON message (bye);\
		CREATE INDEX lastSIPresponse_id ON message (lastSIPresponse_id);\
		CREATE INDEX id_sensor ON message (id_sensor);\
		CREATE INDEX a_ua_id ON message (a_ua_id);\
		CREATE INDEX b_ua_id ON message (b_ua_id);\
		CREATE INDEX fbasename ON message (fbasename);\
	END");
	
	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'register') BEGIN\
		CREATE TABLE register (\
			ID int PRIMARY KEY IDENTITY,\
			id_sensor int NULL,\
			fname bigint NULL,\
			calldate datetime NOT NULL,\
			sipcallerip bigint NOT NULL,\
			sipcalledip bigint NOT NULL,\
			from_num varchar(255) NULL,\
			from_name varchar(255) NULL,\
			from_domain varchar(255) NULL,\
			to_num varchar(255) NULL,\
			to_domain varchar(255) NULL,\
			contact_num varchar(255) NULL,\
			contact_domain varchar(255) NULL,\
			digestusername varchar(255) NULL,\
			digestrealm varchar(255) NULL,\
			expires int NULL,\
			expires_at datetime NULL,\
			state tinyint NULL,\
			ua_id int NULL);\
		CREATE INDEX calldate ON register (calldate);\
		CREATE INDEX sipcallerip ON register (sipcallerip);\
		CREATE INDEX sipcalledip ON register (sipcalledip);\
		CREATE INDEX from_num ON register (from_num);\
		CREATE INDEX digestusername ON register (digestusername)\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'register_state') BEGIN\
		CREATE TABLE register_state (\
			ID int PRIMARY KEY IDENTITY,\
			id_sensor int NULL,\
			fname bigint NULL,\
			created_at datetime NOT NULL,\
			sipcallerip bigint NOT NULL,\
			sipcalledip bigint NOT NULL,\
			from_num varchar(255) NULL,\
			to_num varchar(255) NULL,\
			contact_num varchar(255) NULL,\
			contact_domain varchar(255) NULL,\
			digestusername varchar(255) NULL,\
			expires int NULL,\
			state tinyint NULL,\
			ua_id int NULL);\
		CREATE INDEX created_at ON register_state (created_at);\
		CREATE INDEX sipcallerip ON register_state (sipcallerip);\
		CREATE INDEX sipcalledip ON register_state (sipcalledip);\
	END");
	
	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'register_failed') BEGIN\
		CREATE TABLE register_failed (\
			ID int PRIMARY KEY IDENTITY,\
			id_sensor int NULL,\
			fname bigint NULL,\
			counter int DEFAULT 0,\
			created_at datetime NOT NULL,\
			sipcallerip bigint NOT NULL,\
			sipcalledip bigint NOT NULL,\
			from_num varchar(255) NULL,\
			to_num varchar(255) NULL,\
			contact_num varchar(255) NULL,\
			contact_domain varchar(255) NULL,\
			digestusername varchar(255) NULL,\
			ua_id int NULL);\
		CREATE INDEX created_at ON register_failed (created_at);\
		CREATE INDEX sipcallerip ON register_failed (sipcallerip);\
		CREATE INDEX sipcalledip ON register_failed (sipcalledip);\
	END");
	
	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'sensors') BEGIN\
		CREATE TABLE sensors (\
		id_sensor int PRIMARY KEY IDENTITY,\
		host varchar(255) NULL,\
		port int NULL,);\
	END");

	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'ipacc') BEGIN\
		CREATE TABLE ipacc (\
			saddr bigint NOT NULL,\
			src_id_customer int NOT NULL,\
			daddr bigint NOT NULL,\
			dst_id_customer int NOT NULL,\
			port smallint NOT NULL,\
			proto smallint NOT NULL,\
			octects int NOT NULL,\
			numpackets int NOT NULL,\
			interval_time datetime NOT NULL,\
			voip int NOT NULL\
			do_agr_trigger tinyint NOT NULL);\
		CREATE INDEX saddr ON ipacc (saddr);\
		CREATE INDEX src_id_customer ON ipacc (src_id_customer);\
		CREATE INDEX daddr ON ipacc (daddr);\
		CREATE INDEX dst_id_customer ON ipacc (dst_id_customer);\
		CREATE INDEX port ON ipacc (port);\
		CREATE INDEX proto ON ipacc (proto);\
		CREATE INDEX interval_time ON ipacc (interval_time)\
	END");
	
	this->query(
	"IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'livepacket') BEGIN\
		CREATE TABLE livepacket (\
			id int PRIMARY KEY IDENTITY,\
			id_sensor INT NULL,\
			sipcallerip BIGINT NOT NULL ,\
			sipcalledip BIGINT NOT NULL ,\
			sport SMALLINT NOT NULL ,\
			dport SMALLINT NOT NULL ,\
			istcp TINYINT NOT NULL ,\
			created_at TIMESTAMP NOT NULL ,\
			microseconds INT NOT NULL ,\
			callid VARCHAR(255) NOT NULL ,\
			description VARCHAR(1024),\
			data VARBINARY(8000) NOT NULL);\
		CREATE INDEX created_at__microseconds ON livepacket (created_at, microseconds)\
	END");
	
	sql_noerror = 1;

	//5.2 -> 5.3
	if(opt_match_header[0] != '\0') {
		this->query("ALTER TABLE cdr_next\
				ADD match_header VARCHAR(128)");
		this->query("CREATE INDEX match_header ON cdr_next (match_header)");
	}
	//5.3 -> 5.4
	this->query("CREATE INDEX to_domain ON register (to_domain)");
	this->query("CREATE INDEX to_num ON register (to_num)");
	this->query("ALTER TABLE register_state\
			ADD to_domain varchar(255) NULL;");
	this->query("ALTER TABLE register_failed\
			ADD to_domain varchar(255) NULL;");
	//5.4 -> 5.5
	this->query("ALTER TABLE register_state\
			ADD sipcalledip bigint");
	this->query("CREATE INDEX sipcalledip ON register_state (sipcalledip)");
	this->query("ALTER TABLE register_failed\
			ADD sipcalledip bigint");
	this->query("CREATE INDEX sipcalledip ON register_failed (sipcalledip)");
	//6.0 -> 6.1
	this->query("ALTER TABLE message\
			ADD id_contenttype INT");
	this->query("CREATE INDEX id_contenttype ON message (id_contenttype)");

	sql_noerror = 0;
	
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'concat' AND type = 'FN') DROP FUNCTION dbo.concat");
	this->query("CREATE FUNCTION dbo.concat(@str1 VARCHAR(MAX),@str2 VARCHAR(MAX))\
			RETURNS VARCHAR(MAX) AS\
			BEGIN\
				RETURN @str1 + @str2\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'trim' AND type = 'FN') DROP FUNCTION dbo.trim");
	this->query("CREATE FUNCTION dbo.trim(@str VARCHAR(MAX))\
			RETURNS VARCHAR(MAX) AS\
			BEGIN\
				RETURN LTRIM(RTRIM(@str))\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'div' AND type = 'FN') DROP FUNCTION dbo.div");
	this->query("CREATE FUNCTION dbo.div(@oper1 FLOAT,@oper2 FLOAT)\
			RETURNS FLOAT AS\
			BEGIN\
				RETURN CASE WHEN (@oper2 is NULL or @oper2=0) THEN NULL ELSE @oper1/@oper2 END;\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'iif' AND type = 'FN') DROP FUNCTION dbo.iif");
	this->query("CREATE FUNCTION dbo.iif(@rsltCond VARCHAR(MAX),@rslt1 VARCHAR(MAX),@rslt2 VARCHAR(MAX))\
			RETURNS FLOAT AS\
			BEGIN\
				RETURN CAST((CASE WHEN (@rsltCond is not NULL and @rsltCond<>0) THEN @rslt1 ELSE @rslt2 END) as FLOAT);\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'greatest' AND type = 'FN') DROP FUNCTION dbo.greatest");
	this->query("CREATE FUNCTION dbo.greatest(@par1 FLOAT,@par2 FLOAT)\
			RETURNS FLOAT AS\
			BEGIN\
				RETURN CASE WHEN @par1>@par2 THEN @par1 ELSE coalesce(@par2, @par1) END;\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'least' AND type = 'FN') DROP FUNCTION dbo.least");
	this->query("CREATE FUNCTION dbo.least(@par1 FLOAT,@par2 FLOAT)\
			RETURNS FLOAT AS\
			BEGIN\
				RETURN CASE WHEN @par1<@par2 THEN @par1 ELSE coalesce(@par2, @par1) END;\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'inet_aton' AND type = 'FN') DROP FUNCTION dbo.inet_aton;");
	this->query("CREATE FUNCTION dbo.inet_aton (@ipstr VARCHAR(15))\
			RETURNS BIGINT AS\
			BEGIN\
				RETURN CAST(\
					CAST((256*256*256) as BIGINT) * PARSENAME(@ipstr, 4) + \
					256*256 * PARSENAME(@ipstr, 3) +\
					256 * PARSENAME(@ipstr, 2) +\
					1 * PARSENAME(@ipstr, 1) AS BIGINT);\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'inet_ntoa' AND type = 'FN') DROP FUNCTION dbo.inet_ntoa");
	this->query("CREATE FUNCTION dbo.inet_ntoa(@ipnumber BIGINT)\
			RETURNS VARCHAR(15) AS\
			BEGIN\
				RETURN CAST(\
					CAST(@ipnumber/(256*256*256) as VARCHAR(3)) + '.' +\
					CAST(@ipnumber%(256*256*256)/(256*256) as VARCHAR(3)) + '.' +\
					CAST(@ipnumber%(256*256)/(256) as VARCHAR(3)) + '.' +\
					CAST(@ipnumber%256 as VARCHAR(3)) as VARCHAR(15));\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'unix_timestamp' AND type = 'FN') DROP FUNCTION dbo.unix_timestamp");
	this->query("CREATE FUNCTION dbo.unix_timestamp(@ctimestamp DATETIME)\
			RETURNS INTEGER AS\
			BEGIN\
				RETURN DATEDIFF(SECOND, '1970-01-01', @ctimestamp)\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'now' AND type = 'FN') DROP FUNCTION dbo.now");
	this->query("CREATE FUNCTION now()\
			RETURNS DATETIME AS\
			BEGIN\
				RETURN GETDATE()\
			END");
	this->query("IF EXISTS (SELECT name FROM sys.objects WHERE name = 'subtime' AND type = 'FN') DROP FUNCTION dbo.subtime");
	this->query("CREATE FUNCTION dbo.subtime(@time1 DATETIME, @time2 DATETIME)\
			RETURNS DATETIME AS\
			BEGIN\
				RETURN DATEADD(SECOND, -DATEDIFF(second, 0, @time2), @time1)\
			END");

	this->query("ALTER TABLE message\
			ADD GeoPosition varchar(255) NULL;");
	this->query("ALTER TABLE cdr\
			ADD GeoPosition varchar(255) NULL;");
}

void SqlDb_odbc::checkSchema() {

}
