#ifndef SQL_DB_GLOBAL_H
#define SQL_DB_GLOBAL_H


#include <stdlib.h>
#include <sys/types.h>
#include <map>
#include <list>
#include <string>
#include <unistd.h>

#include "tools_global.h"


using namespace std;


class SqlDb_row_def {
public:
	enum eInternalFieldType {
		_ift_na,
		_ift_string,
		_ift_int,
		_ift_int_u,
		_ift_double,
		_ift_ip,
		_ift_calldate,
		_ift_sql,
		_ift_cb_old,
		_ift_cb_string = 0x10,
		_ift_base      = 0x1F,
		_ift_null      = 0x20
	};
};

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
	static string getCondStr(list<SqlDb_condField> *cond, const char *fieldBorder, const char *contentBorder, const char *typeDb = NULL);
public:
	string field;
	string value;
	string oper;
	bool needEscapeField;
	bool needEscapeValue;
};

class cSqlDbAutoIncrement {
public:
	cSqlDbAutoIncrement();
	void setUData(void *u_data);
	void set(const char *table, const char *idColumn = NULL, class SqlDb *sqlDb = NULL, bool useLockAutoInc = true);
	u_int64_t getId(const char *table, const char *idColumn = NULL, class SqlDb *sqlDb = NULL);
private:
	u_int64_t get_last_id(const char *table, const char *idColumn = NULL, SqlDb *sqlDb = NULL);
	void lock_autoinc() {
		__SYNC_LOCK(_sync_autoinc);
	}
	void unlock_autoinc() {
		__SYNC_UNLOCK(_sync_autoinc);
	}
private:
	void *u_data;
	map<string, int64_t> autoinc;
	volatile int _sync_autoinc;
};


class cSqlDbCodebook {
public:
	enum eTypeCodebook {
		_cb_ua = 1,
		_cb_sip_response,
		_cb_sip_request,
		_cb_reason_sip,
		_cb_reason_q850,
		_cb_contenttype
	};
public:
	cSqlDbCodebook(eTypeCodebook type, const char *name, 
		       const char *table, const char *columnId, const char *columnStringValue, 
		       unsigned limitTableRows = 0, bool caseSensitive = false);
	~cSqlDbCodebook();
	void setUData(void *u_data);
	void addCond(const char *field, const char *value);
	void setAutoLoadPeriod(unsigned autoLoadPeriod);
	unsigned getId(const char *stringValue, bool enableInsert = false, bool enableAutoLoad = false,
		       cSqlDbAutoIncrement *autoincrement = NULL, string *insertQuery = NULL, SqlDb *sqlDb = NULL);
	void load(SqlDb *sqlDb = NULL);
	void loadInBackground();
	void registerAutoincrement(cSqlDbAutoIncrement *autoincrement, SqlDb *sqlDb = NULL);
private:
	void _load(map<string, unsigned> *data, bool *overflow, SqlDb *sqlDb = NULL);
	static void *_loadInBackground(void *arg);
	void lock_data() {
		__SYNC_LOCK(_sync_data);
	}
	void unlock_data() {
		__SYNC_UNLOCK(_sync_data);
	}
	void lock_load() {
		__SYNC_LOCK(_sync_load);
	}
	bool lock_load(int timeout_us) {
		__SYNC_LOCK_WHILE(_sync_load) {
			timeout_us -= 100;
			if(timeout_us < 0) {
				return(false);
			}
			USLEEP(100);
		}
		return(true);
	}
	void unlock_load() {
		__SYNC_UNLOCK(_sync_load);
	}
private:
	eTypeCodebook type;
	string name;
	string table;
	string columnId;
	string columnStringValue;
	unsigned limitTableRows;
	bool caseSensitive;
	void *u_data;
	list<SqlDb_condField> cond;
	unsigned autoLoadPeriod;
	map<string, unsigned> *data;
	bool loaded;
	bool data_overflow;
	volatile int _sync_data;
	volatile int _sync_load;
	u_long lastBeginLoadTime;
	u_long lastEndLoadTime;
friend class cSqlDbCodebooks;
};


class cSqlDbCodebooks {
public:
	cSqlDbCodebooks();
	~cSqlDbCodebooks();
	void setUData(void *u_data);
	void registerCodebook(cSqlDbCodebook *codebook);
	unsigned getId(cSqlDbCodebook::eTypeCodebook type, const char *stringValue, bool enableInsert = false, bool enableAutoLoad = false,
		       cSqlDbAutoIncrement *autoincrement = NULL, string *insertQuery = NULL, SqlDb *sqlDb = NULL);
	void loadAll(SqlDb *sqlDb = NULL);
	void setAutoincrementForAll(cSqlDbAutoIncrement *autoincrement, SqlDb *sqlDb = NULL);
	void setAutoLoadPeriodForAll(unsigned autoLoadPeriod);
	void destroyAll();
	cSqlDbCodebook::eTypeCodebook getTypeForName(const char *name);
	string getNameForType(cSqlDbCodebook::eTypeCodebook type);
private:
	void *u_data;
	map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*> codebooks;
};


class cSqlDbData {
public:
	cSqlDbData();
	~cSqlDbData();
	void init(bool loadAll, unsigned limitTableRows, SqlDb *sqlDb, bool reload = false);
	unsigned getCbId(cSqlDbCodebook::eTypeCodebook type, const char *stringValue, bool enableInsert = false, bool enableAutoLoad =  false,
			 string *insertQuery = NULL, SqlDb *sqlDb = NULL);
	unsigned getCbId(cSqlDbCodebook::eTypeCodebook type, string &stringValue, bool enableInsert = false, bool enableAutoLoad =  false,
			 string *insertQuery = NULL, SqlDb *sqlDb = NULL) {
		return(getCbId(type, stringValue.c_str(), enableInsert, enableAutoLoad,
			       insertQuery, sqlDb));
	}
	unsigned getCbId(const char *type, const char *stringValue, bool enableInsert = false, bool enableAutoLoad =  false,
			 string *insertQuery = NULL, SqlDb *sqlDb = NULL);
	u_int64_t getAiId(const char *table, const char *idColumn = NULL, SqlDb *sqlDb = NULL);
	string getCbNameForType(cSqlDbCodebook::eTypeCodebook type);
private:
	void initCodebooks(bool loadAll, unsigned limitTableRows, SqlDb *sqlDb);
	void initAutoIncrement(SqlDb *sqlDb);
	void lock_data() {
		__SYNC_LOCK(_sync_data);
	}
	void unlock_data() {
		__SYNC_UNLOCK(_sync_data);
	}
private:
	cSqlDbCodebooks *codebooks;
	cSqlDbAutoIncrement *autoincrement;
	volatile int _sync_data;
};


bool cmpStringIgnoreCase(const char* str1, const char* str2);
bool isSqlDriver(const char *sqlDriver, const char *checkSqlDriver = NULL);
bool isTypeDb(const char *typeDb, const char *checkSqlDriver = NULL, const char *checkOdbcDriver = NULL);

void fillEscTables();
string _sqlEscapeString(const char *inputString, int length, const char *typeDb, bool checkUtf = false);
void _sqlEscapeString(const char *inputStr, int length, char *outputStr, const char *typeDb, bool checkUtf = false);

inline bool checkNeedEscape(const char *inputStr, int length) {
	for(int i = 0; i < length; i++) {
		if(!(isdigit(inputStr[i]) ||
		     isalpha(inputStr[i]) ||
		     strchr(" +-_.:@#", inputStr[i]))) {
			return(true);
		}
	}
	return(false);
}
inline string sqlEscapeString(const char *inputStr, int length = 0, const char *typeDb = NULL) {
	if(!length) {
		length = strlen(inputStr);
		if(!checkNeedEscape(inputStr, length)) {
			return(inputStr);
		}
	}
	return _sqlEscapeString(inputStr, length, typeDb, true);
}
inline string sqlEscapeString(string inputStr, const char *typeDb = NULL) {
	return sqlEscapeString(inputStr.c_str(), 0, typeDb);
}
inline string sqlEscapeString_limit(string inputStr, unsigned limitLength, const char *typeDb = NULL) {
	return sqlEscapeString(limitLength > 0 && inputStr.length() > limitLength ?
				inputStr.substr(0, limitLength).c_str() :
				inputStr.c_str(),
			       0, typeDb);
}

string sqlEscapeStringBorder(string inputStr, char borderChar = '\'', const char *typeDb = NULL);
string sqlEscapeStringBorder(const char *inputStr, char borderChar = '\'', const char *typeDb = NULL);


#define _MYSQL_QUERY_END_new "_\\_'QE'_\\_;\n"
#define _MYSQL_QUERY_END_old ";\n"
#define MYSQL_QUERY_END string(useNewStore() ? _MYSQL_QUERY_END_new : _MYSQL_QUERY_END_old)
#define _MYSQL_QUERY_END_SUBST_new "_\\_'Qe'_\\_;\n"
#define _MYSQL_QUERY_END_SUBST_old ";\n"
#define MYSQL_QUERY_END_SUBST string(useNewStore() ? _MYSQL_QUERY_END_SUBST_new : _MYSQL_QUERY_END_SUBST_old)

#define MYSQL_CSV_END "\n"

#define MYSQL_IF string(":IF ")
#define MYSQL_ENDIF string(":ENDIF")
#define MYSQL_ENDIF_QE (string(":ENDIF") + MYSQL_QUERY_END)
#define _MYSQL_MAIN_INSERT_new ":MI:"
#define _MYSQL_MAIN_INSERT_new_length 4
#define _MYSQL_MAIN_INSERT_GROUP_new ":MIG:"
#define _MYSQL_MAIN_INSERT_GROUP_new_length 5
#define _MYSQL_NEXT_INSERT_new ":NI:"
#define _MYSQL_NEXT_INSERT_new_length 4
#define _MYSQL_NEXT_INSERT_GROUP_new ":NIG:"
#define _MYSQL_NEXT_INSERT_GROUP_new_length 5
#define MYSQL_MAIN_INSERT string(useNewStore() ? _MYSQL_MAIN_INSERT_new : "")
#define MYSQL_MAIN_INSERT_GROUP string(useNewStore() ? _MYSQL_MAIN_INSERT_GROUP_new : "")
#define MYSQL_NEXT_INSERT string(useNewStore() ? _MYSQL_NEXT_INSERT_new : "")
#define MYSQL_NEXT_INSERT_GROUP string(useNewStore() ? _MYSQL_NEXT_INSERT_GROUP_new : "")

#define MYSQL_MAIN_INSERT_CSV_HEADER(table) (string("csv_header:") + table + ':')
#define MYSQL_MAIN_INSERT_CSV_ROW(table) (string("csv_row:") + table + ':')

#define MYSQL_MAIN_INSERT_ID string("@MI_NEW_ID")
#define MYSQL_MAIN_INSERT_ID_OLD string("@MI_OLD_ID")
#define MYSQL_MAIN_INSERT_ID2 string("@MI_new_ID")
#define MYSQL_MAIN_INSERT_ID_OLD2 string("@MI_old_ID")
#define MYSQL_GET_MAIN_INSERT_ID (string("set ") + MYSQL_MAIN_INSERT_ID + " = last_insert_id()" + MYSQL_QUERY_END)
#define MYSQL_GET_MAIN_INSERT_ID_OLD (string("set ") + MYSQL_MAIN_INSERT_ID_OLD + " = last_insert_id()" + MYSQL_QUERY_END)
#define MYSQL_IF_MAIN_INSERT_ID (MYSQL_IF + " " + MYSQL_MAIN_INSERT_ID + " > 0 and coalesce(" + MYSQL_MAIN_INSERT_ID_OLD + ", 0) <> " + MYSQL_MAIN_INSERT_ID + MYSQL_QUERY_END)
#define MYSQL_VAR_PREFIX string("_\\_'SQL'_\\_:")
#define MYSQL_CODEBOOK_ID_PREFIX string("_\\_'CB_ID'_\\_:")
#define MYSQL_CODEBOOK_ID_PREFIX_SUBST string("_\\_'Cb_ID'_\\_:")
string MYSQL_CODEBOOK_ID(int type, string value);

#define MYSQL_EXISTS_PREFIX_L(str, prefix, length) (!strncmp((str).c_str(), prefix, length))
#define MYSQL_EXISTS_PREFIX_S(str, prefix) MYSQL_EXISTS_PREFIX_L(str, prefix.c_str(), prefix.length())
string MYSQL_ADD_QUERY_END(string query, bool enableSubstQueryEnd = true);


void __store_prepare_queries(list<string> *queries, cSqlDbData *dbData, cDbCalls *dbCalls, SqlDb *sqlDb,
			     string *queries_str, list<string> *queries_list, list<string> *cb_inserts,
			     int enable_new_store, bool enable_set_id, bool enable_multiple_rows_insert,
			     #if CLOUD_ROUTER_SERVER
			     int cdr_check_exists_callid,
			     #endif
			     long unsigned maxAllowedPacket);


#endif
