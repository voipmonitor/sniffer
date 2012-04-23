#ifndef ODBC_H
#define ODBC_H

#include <stdlib.h>
#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>

class Odbc {
public:
	Odbc();
	~Odbc();
	bool connect(const char *serverName, const char *userName, const char *password,
		     ulong odbcVersion = SQL_OV_ODBC3, ulong loginTimeOut = 10);
	void disconnect();
	bool connected();
	void bindCol(SQLUSMALLINT colNumber, SQLSMALLINT targetType, SQLPOINTER targetValuePtr, 
		     SQLLEN targetBufferLength = 0, SQLLEN *lenOrInd = NULL);
	bool query(const char *query);
	bool fetchRow();
	SQLLEN getNumRows();
	void diagError(SQLSMALLINT handleType);
	void setLastErrorString(const char *errorString);
	void clearLastError();
	SQLRETURN getLastError() { return(this->lastError); }
	SQLINTEGER getLastErrorNative() { return(this->lastErrorNative); }
	char *getLastErrorString() { return(this->lastErrorString); }
	bool okRslt(SQLRETURN rslt) { return rslt==SQL_SUCCESS || rslt==SQL_SUCCESS_WITH_INFO; } 
private:
	SQLHANDLE hEnvironment;
	SQLHANDLE hConnection;
	SQLHANDLE hStatement;
	SQLRETURN lastError;
	SQLINTEGER lastErrorNative;
	char *lastErrorString;
};

#endif
