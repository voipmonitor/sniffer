#include <string.h>
#include <stdio.h>
#include <iostream>
#include <sql.h>
#include "voipmonitor.h"

#include "odbc.h"

Odbc::Odbc() {
	this->hEnvironment = NULL;
	this->hConnection = NULL;
	this->hStatement = NULL;
	this->lastError = SQL_SUCCESS;
	this->lastErrorNative = 0;
	this->lastErrorString = NULL;
}

Odbc::~Odbc() {
	this->disconnect();
	this->clearLastError();
}

bool Odbc::connect(const char *serverName, const char *userName, const char *password,
	            ulong odbcVersion, ulong loginTimeOut) {
	SQLRETURN rslt;
	this->clearLastError();
	if(!this->hEnvironment) {
		rslt = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &this->hEnvironment);
		if(!this->okRslt(rslt)) {
			this->lastError = rslt;
			this->setLastErrorString("error in allocate environment handle");
			this->disconnect();
			return false;
		}
		if(odbcVersion) {
			rslt = SQLSetEnvAttr(hEnvironment, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)odbcVersion, 0); 
			if(!this->okRslt(rslt)) {
				this->lastError = rslt;
				this->setLastErrorString("error in set environment attributes");
				this->disconnect();
				return false;
			}
		}
	}
	if(!this->hConnection) {
		rslt = SQLAllocHandle(SQL_HANDLE_DBC, this->hEnvironment, &this->hConnection); 
		if(!this->okRslt(rslt)) { 
			this->lastError = rslt;
			this->setLastErrorString("error in allocate connection handle");
			this->disconnect();
			return false;
		}
		if(loginTimeOut) {
			SQLSetConnectAttr(this->hConnection, SQL_LOGIN_TIMEOUT, (SQLPOINTER *)loginTimeOut, 0);
		}
		rslt = SQLConnect(this->hConnection, 
				  (SQLCHAR*)serverName, SQL_NTS,
				  (SQLCHAR*)userName, SQL_NTS,
				  (SQLCHAR*)password, SQL_NTS);
		if(!this->okRslt(rslt)) { 
			this->lastError = rslt;
			this->diagError(SQL_HANDLE_DBC);
			this->disconnect();
			return(false);
		}
	}
	if(!this->hStatement) {
		rslt = SQLAllocHandle(SQL_HANDLE_STMT, hConnection, &hStatement);
		if(!this->okRslt(rslt)) {
			this->lastError = rslt;
			this->diagError(SQL_HANDLE_DBC);
			this->disconnect();
			return(false);
		}
	}
	return true;
}

void Odbc::disconnect() {
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

bool Odbc::connected() {
	return this->hEnvironment && this->hConnection && this->hEnvironment;
}

void Odbc::bindCol(SQLUSMALLINT colNumber, SQLSMALLINT targetType, SQLPOINTER targetValuePtr, 
		    SQLLEN targetBufferLength, SQLLEN *lenOrInd) {
	SQLBindCol(this->hStatement, colNumber, targetType, targetValuePtr, targetBufferLength, lenOrInd);
}

bool Odbc::query(const char *query) {
	SQLRETURN rslt = SQLExecDirect(this->hStatement, (SQLCHAR*)query, SQL_NTS);   
	if(!this->okRslt(rslt)) {
		this->lastError = rslt;
		this->diagError(SQL_HANDLE_STMT);
		return false;
	}
	return true;
}

bool Odbc::fetchRow() {
	SQLRETURN rslt = SQLFetch(hStatement);
	if(!this->okRslt(rslt) && rslt != SQL_NO_DATA) {
		this->lastError = rslt;
		this->diagError(SQL_HANDLE_STMT);
		return false;
	}
	return this->okRslt(rslt);
}

SQLLEN Odbc::getNumRows() {
	SQLLEN numRows = -1;
	SQLRETURN rslt = SQLRowCount(hStatement, &numRows);
	if(!this->okRslt(rslt)) {
		this->lastError = rslt;
		this->diagError(SQL_HANDLE_STMT);
		return -1;
	}
	return numRows;
}

void Odbc::diagError(SQLSMALLINT handleType) {
	SQLCHAR	sqlState[10];
	SQLINTEGER nativeError;
	SQLCHAR	messageText[1000];
	SQLSMALLINT messageTextLength;
	SQLRETURN rslt = SQLGetDiagRec(handleType, 
				       handleType == SQL_HANDLE_DBC ?
					this->hConnection :
					this->hStatement, 
				       1, sqlState, &nativeError, messageText, sizeof(messageText), &messageTextLength);
	if(this->okRslt(rslt)) {
		this->lastErrorNative = nativeError;
		this->setLastErrorString((char*)messageText);
	}
}

void Odbc::setLastErrorString(const char *errorString) {
	if(this->lastErrorString) {
		delete [] this->lastErrorString;
		this->lastErrorString = NULL;
	}
	if(errorString) {
		this->lastErrorString =  new FILE_LINE(14001) char[strlen(errorString)+1];
		strcpy(this->lastErrorString, errorString);
	}
}

void Odbc::clearLastError() {
	this->lastError = SQL_SUCCESS;
	this->lastErrorNative = 0;
	if(this->lastErrorString) {
		delete [] this->lastErrorString;
		this->lastErrorString = NULL;
	}
}
