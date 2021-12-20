#include <algorithm>
#include <mysqld_error.h>

#include "tools_local.h"

#include "sql_db_global.h"
#include "sql_db.h"

#ifdef CLOUD_ROUTER_CLIENT
#include "server.h"
#include "calltable.h"
#endif


extern char sql_driver[256];
extern char odbc_driver[256];
extern bool opt_charts_cache;


string SqlDb_condField::getCondStr(list<SqlDb_condField> *cond, const char *fieldBorder, const char *contentBorder, const char *typeDb) {
	string condStr;
	for(list<SqlDb_condField>::iterator iter = cond->begin(); iter != cond->end(); iter++) {
		if(!condStr.empty()) {
			condStr += " and ";
		}
		condStr += iter->needEscapeField ?
			    (fieldBorder ? fieldBorder : "") + iter->field + (fieldBorder ? fieldBorder : "") :
			    iter->field;
		condStr += iter->oper.empty() ? " = " : " " + iter->oper + " ";
		condStr += iter->needEscapeValue ?
			    (contentBorder ? contentBorder : "") + sqlEscapeString(iter->value) + (contentBorder ? contentBorder : "") :
			    iter->value;
	}
	return(condStr);
}


cSqlDbAutoIncrement::cSqlDbAutoIncrement() {
	this->u_data = NULL;
	_sync_autoinc = 0;
}

void cSqlDbAutoIncrement::setUData(void *u_data) {
	this->u_data = u_data;
}

void cSqlDbAutoIncrement::set(const char *table, const char *idColumn, SqlDb *sqlDb, bool useLockAutoInc) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	u_int64_t last_id = get_last_id(table, idColumn ? idColumn : "id", sqlDb);
	if(useLockAutoInc) {
		lock_autoinc();
	}
	autoinc[table] = last_id;
	if(useLockAutoInc) {
		unlock_autoinc();
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

u_int64_t cSqlDbAutoIncrement::getId(const char *table, const char *idColumn, SqlDb *sqlDb) {
	u_int64_t id = 0;
	lock_autoinc();
	for(int pass = 0; pass < 2; pass++) {
		if(pass == 1) {
			set(table, idColumn, sqlDb, false);
		}
		map<string, int64_t>::iterator iter = autoinc.find(table);
		if(iter != autoinc.end()) {
			id = ++iter->second;
			break;
		}
	}
	unlock_autoinc();
	return(id);
}

u_int64_t cSqlDbAutoIncrement::get_last_id(const char *table, const char *idColumn, SqlDb *sqlDb) {
	u_int64_t last_id = 0;
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	#ifdef CLOUD_ROUTER_CLIENT
	sqlDb->query(string("select ") + idColumn + " from " + sqlDb->escapeTableName(table) + " order by id desc limit 1");
	#endif
	#ifdef CLOUD_ROUTER_SERVER
	unsigned tryCounter = 0;
	while(true) {
		if(tryCounter) {
			sleep(1);
		}
		++tryCounter;
		if(sqlDb->query(string("select ") + idColumn + " from " + sqlDb->escapeTableName(table) + " order by id desc limit 1")) {
			break;
		}
	}
	#endif
	string last_id_str = sqlDb->fetchValue();
	if(!last_id_str.empty()) {
		last_id = atoll(last_id_str.c_str());
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(last_id);
}


cSqlDbCodebook::cSqlDbCodebook(eTypeCodebook type, const char *name, 
			       const char *table, const char *columnId, const char *columnStringValue, 
			       unsigned limitTableRows, bool caseSensitive) {
	this->type = type;
	this->name = name;
	this->table = table;
	this->columnId = columnId;
	this->columnStringValue = columnStringValue;
	this->limitTableRows = limitTableRows;
	this->caseSensitive = caseSensitive;
	this->u_data = NULL;
	autoLoadPeriod = 0;
	loaded = false;
	data_overflow = false;
	_sync_data = 0;
	_sync_load = 0;
	lastBeginLoadTime = 0;
	lastEndLoadTime = 0;
}

void cSqlDbCodebook::setUData(void *u_data) {
	this->u_data = u_data;
}

void cSqlDbCodebook::addCond(const char *field, const char *value) {
	cond.push_back(SqlDb_condField(field, value));
}

void cSqlDbCodebook::setAutoLoadPeriod(unsigned autoLoadPeriod) {
	this->autoLoadPeriod = autoLoadPeriod;
}

unsigned cSqlDbCodebook::getId(const char *stringValueInput, bool enableInsert, bool enableAutoLoad,
			       cSqlDbAutoIncrement *autoincrement, string *insertQuery, SqlDb *sqlDb) {
	string stringValueInputSafe;
	extern cUtfConverter utfConverter;
	#ifdef CLOUD_ROUTER_CLIENT
	if(!(useSetId() ? utfConverter.is_ascii(stringValueInput) : utfConverter.check(stringValueInput))) {
		stringValueInputSafe = utfConverter.remove_no_ascii(stringValueInput);
	} else {
		stringValueInputSafe = stringValueInput;
	}
	#endif
	#ifdef CLOUD_ROUTER_SERVER
	if(!utfConverter.is_ascii(stringValueInput)) {
		stringValueInputSafe = utfConverter.remove_no_ascii(stringValueInput);
	} else {
		stringValueInputSafe = stringValueInput;
	}
	#endif
	string stringValue = stringValueInputSafe;
	if(!caseSensitive) {
		std::transform(stringValue.begin(), stringValue.end(), stringValue.begin(), ::toupper);
	}
	if(data_overflow) {
		return(0);
	}
	#ifdef CLOUD_ROUTER_CLIENT
	if(sverb.disable_cb_cache) {
		return(0);
	}
	#endif
	unsigned rslt = 0;
	lock_data();
	if(data.size()) {
		map<string, unsigned>::iterator iter = data.find(stringValue);
		if(iter != data.end()) {
			rslt = iter->second;
		}
	} else {
		#ifdef CLOUD_ROUTER_SERVER
		if(sqlDb && !loaded) {
			lock_load();
			this->_load(&data, NULL, sqlDb);
			unlock_load();
			if(data.size()) {
				map<string, unsigned>::iterator iter = data.find(stringValue);
				if(iter != data.end()) {
					rslt = iter->second;
				}
			}
		}
		#endif
	}
	if(!rslt) {
		#ifdef CLOUD_ROUTER_CLIENT
			if(useSetId()) {
				rslt = autoincrement->getId(this->table.c_str());
				SqlDb *sqlDb = createSqlObject();
				SqlDb_row row;
				row.add(rslt, columnId);
				row.add(sqlEscapeString(stringValueInputSafe),  columnStringValue);
				for(list<SqlDb_condField>::iterator iter = this->cond.begin(); iter != this->cond.end(); iter++) {
					row.add(sqlEscapeString(iter->value), iter->field);
				}
				extern MySqlStore *sqlStore;
				sqlStore->query_lock(MYSQL_ADD_QUERY_END(sqlDb->insertQuery(this->table, row)).c_str(), STORE_PROC_ID_OTHER, 0);
				delete sqlDb;
				data[stringValue] = rslt;
			} else if(enableInsert) {
				SqlDb *sqlDb = createSqlObject();
				list<SqlDb_condField> cond = this->cond;
				cond.push_back(SqlDb_condField(columnStringValue, stringValue));
				sqlDb->setDisableLogError();
				for(int forceLatin1 = 0; forceLatin1 < 2; forceLatin1++) {
					if(sqlDb->select(table, NULL, &cond, 1, forceLatin1 == 1)) {
						SqlDb_row row;
						if((row = sqlDb->fetchRow())) {
							rslt = atol(row[columnId].c_str());
						}
						break;
					}
					if(forceLatin1 == 1 ||
					   sqlDb->getLastError() != ER_CANT_AGGREGATE_2COLLATIONS) {
						sqlDb->checkLastError("query error in [" + sqlDb->selectQuery(table, NULL, &cond, 1, forceLatin1 == 1) + "]", true);
					}
				}
				sqlDb->setEnableLogError();
				if(!rslt) {
					SqlDb_row row;
					row.add(sqlEscapeString(stringValueInputSafe), columnStringValue);
					for(list<SqlDb_condField>::iterator iter = this->cond.begin(); iter != this->cond.end(); iter++) {
						row.add(sqlEscapeString(iter->value), iter->field);
					}
					int64_t rsltInsert = sqlDb->insert(table, row);
					if(rsltInsert > 0) {
						rslt = rsltInsert;
					}
				}
				delete sqlDb;
			}
		#endif
		#ifdef CLOUD_ROUTER_SERVER
			rslt = autoincrement->getId(this->table.c_str());
			string columns = columnId + "," + columnStringValue;
			string values = intToString(rslt) + "," + sqlEscapeStringBorder(stringValueInputSafe);
			for(list<SqlDb_condField>::iterator iter = this->cond.begin(); iter != this->cond.end(); iter++) {
				columns += "," + iter->field;
				values += "," + sqlEscapeStringBorder(iter->value);
			}
			*insertQuery = "insert into " + this->table + " (" + columns + ") values (" + values + ")";
			data[stringValue] = rslt;
		#endif
	}
	unlock_data();
	#ifdef CLOUD_ROUTER_CLIENT
	if(!rslt && enableAutoLoad && this->autoLoadPeriod && !_sync_load) {
		u_long actTime = getTimeS();
		if(lastBeginLoadTime + this->autoLoadPeriod < actTime &&
		   lastEndLoadTime + this->autoLoadPeriod < actTime) {
			loadInBackground();
		}
	}
	#endif
	return(rslt);
}

void cSqlDbCodebook::load(SqlDb *sqlDb) {
	if(lock_load(1000000)) {
		map<string, unsigned> data;
		bool data_overflow;
		_load(&data, &data_overflow, sqlDb);
		if(data.size() || data_overflow) {
			lock_data();
			this->data = data;
			this->data_overflow = data_overflow;
			unlock_data();
		}
		loaded = true;
		unlock_load();
	}
}

void cSqlDbCodebook::loadInBackground() {
	if(lock_load(1000000)) {
		pthread_t thread;
		vm_pthread_create_autodestroy("cSqlDbCodebook::loadInBackground",
					      &thread, NULL, cSqlDbCodebook::_loadInBackground, this, __FILE__, __LINE__);
	}
}

void cSqlDbCodebook::registerAutoincrement(cSqlDbAutoIncrement *autoincrement, SqlDb *sqlDb) {
	autoincrement->set(table.c_str(), columnId.c_str(), sqlDb);
}

void cSqlDbCodebook::_load(map<string, unsigned> *data, bool *overflow, SqlDb *sqlDb) {
	lastBeginLoadTime = getTimeS();
	data->clear();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	#ifdef CLOUD_ROUTER_CLIENT
		if(this->limitTableRows && sqlDb->rowsInTable(table, true) > this->limitTableRows) {
			*overflow = true;
		} else {
			if(sqlDb->select(table, NULL, &cond)) {
				SqlDb_rows rows;
				sqlDb->fetchRows(&rows);
				SqlDb_row row;
				while((row = rows.fetchRow())) {
					string stringValue = row[columnStringValue];
					unsigned id = atol(row[columnId].c_str());
					if(!caseSensitive) {
						std::transform(stringValue.begin(), stringValue.end(), stringValue.begin(), ::toupper);
					}
					(*data)[stringValue] = id;
				}
			}
			*overflow = false;
		}
	#endif
	#ifdef CLOUD_ROUTER_SERVER
		string condStr;
		if(cond.size()) {
			condStr = SqlDb_condField::getCondStr(&cond, NULL, "'");
		}
		unsigned tryCounter = 0;
		while(true) {
			if(tryCounter) {
				sleep(1);
			}
			++tryCounter;
			if(sqlDb->query("select * from " + table + (!condStr.empty() ? " where " + condStr : ""))) {
				break;
			}
		}
		vector<map<string, string_null> > *rows = sqlDb->get_rslt();
		if(rows->size()) {
			for(unsigned i = 0; i < rows->size(); i++) {
				string stringValue = (*rows)[i][columnStringValue].str;
				unsigned id = atol((*rows)[i][columnId].str.c_str());
				if(!caseSensitive) {
					std::transform(stringValue.begin(), stringValue.end(), stringValue.begin(), ::toupper);
				}
				(*data)[stringValue] = id;
			}
		}
		*overflow = false;
	#endif
	if(_createSqlObject) {
		delete sqlDb;
	}
	lastEndLoadTime = getTimeS();
}

void *cSqlDbCodebook::_loadInBackground(void *arg) {
	cSqlDbCodebook *me = (cSqlDbCodebook*)arg;
	map<string, unsigned> data;
	bool data_overflow;
	me->_load(&data, &data_overflow);
	if(data.size() || data_overflow) {
		me->lock_data();
		me->data = data;
		me->data_overflow = data_overflow;
		me->unlock_data();
	}
	me->unlock_load();
	return(NULL);
}


cSqlDbCodebooks::cSqlDbCodebooks() {
	this->u_data = NULL;
}

cSqlDbCodebooks::~cSqlDbCodebooks() {
	destroyAll();
}

void cSqlDbCodebooks::setUData(void *u_data) {
	this->u_data = u_data;
}

void cSqlDbCodebooks::registerCodebook(cSqlDbCodebook *codebook) {
	codebooks[codebook->type] = codebook;
}

unsigned cSqlDbCodebooks::getId(cSqlDbCodebook::eTypeCodebook type, const char *stringValue, bool enableInsert, bool enableAutoLoad,
				cSqlDbAutoIncrement *autoincrement, string *insertQuery, SqlDb *sqlDb) {
	map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*>::iterator iter = codebooks.find(type);
	if(iter != codebooks.end()) {
		return(iter->second->getId(stringValue, enableInsert, enableAutoLoad, 
					   autoincrement, insertQuery, sqlDb));
	}
	return(0);
}

void cSqlDbCodebooks::loadAll(SqlDb *sqlDb) {
	for(map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*>::iterator iter = codebooks.begin(); iter != codebooks.end(); iter++) {
		iter->second->load(sqlDb);
	}
}

void cSqlDbCodebooks::setAutoincrementForAll(cSqlDbAutoIncrement *autoincrement, SqlDb *sqlDb) {
	for(map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*>::iterator iter = codebooks.begin(); iter != codebooks.end(); iter++) {
		iter->second->registerAutoincrement(autoincrement, sqlDb);
	}
}

void cSqlDbCodebooks::setAutoLoadPeriodForAll(unsigned autoLoadPeriod) {
	for(map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*>::iterator iter = codebooks.begin(); iter != codebooks.end(); iter++) {
		iter->second->setAutoLoadPeriod(autoLoadPeriod);
	}
}

void cSqlDbCodebooks::destroyAll() {
	for(map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*>::iterator iter = codebooks.begin(); iter != codebooks.end(); iter++) {
		delete iter->second;
	}
}

cSqlDbCodebook::eTypeCodebook cSqlDbCodebooks::getTypeForName(const char *name) {
	for(map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*>::iterator iter = codebooks.begin(); iter != codebooks.end(); iter++) {
		if(iter->second->name == name) {
			return(iter->first);
		}
	}
	return((cSqlDbCodebook::eTypeCodebook)0);
}

string cSqlDbCodebooks::getNameForType(cSqlDbCodebook::eTypeCodebook type) {
	for(map<cSqlDbCodebook::eTypeCodebook, cSqlDbCodebook*>::iterator iter = codebooks.begin(); iter != codebooks.end(); iter++) {
		if(iter->first == type) {
			return(iter->second->name);
		}
	}
	return("");
}


cSqlDbData::cSqlDbData() {
	codebooks = NULL;
	autoincrement = NULL;
	_sync_data = 0;
}

cSqlDbData::~cSqlDbData() {
	if(codebooks) {
		delete codebooks;
	}
	if(autoincrement) {
		delete autoincrement;
	}
}

void cSqlDbData::init(bool loadAll, unsigned limitTableRows, SqlDb *sqlDb, bool reload) {
	lock_data();
	if(reload) {
		if(codebooks) {
			delete codebooks;
			codebooks = NULL;
		}
		if(autoincrement) {
			delete autoincrement;
			autoincrement = NULL;
		}
	}
	bool _initCodebooks = false;
	bool _initAutoincrement = false;
	if(!codebooks) {
		codebooks = new FILE_LINE(0) cSqlDbCodebooks;
		_initCodebooks = true;
	}
	if(!autoincrement) {
		autoincrement = new FILE_LINE(0) cSqlDbAutoIncrement;
		_initAutoincrement = true;
	}
	if(_initCodebooks) {
		initCodebooks(loadAll, limitTableRows, sqlDb);
	}
	if(_initAutoincrement && loadAll) {
		initAutoIncrement(sqlDb);
	}
	unlock_data();
}

unsigned cSqlDbData::getCbId(cSqlDbCodebook::eTypeCodebook type, const char *stringValue, bool enableInsert, bool enableAutoLoad,
			     string *insertQuery, SqlDb *sqlDb) {
	#ifdef CLOUD_ROUTER_SERVER
	lock_data();
	#endif
	unsigned rslt = codebooks->getId(type, stringValue, enableInsert, enableAutoLoad,
					 autoincrement, insertQuery, sqlDb);
	#ifdef CLOUD_ROUTER_SERVER
	unlock_data();
	#endif
	return(rslt);
}

unsigned cSqlDbData::getCbId(const char *type, const char *stringValue, bool enableInsert, bool enableAutoLoad,
			     string *insertQuery, SqlDb *sqlDb) {
	#ifdef CLOUD_ROUTER_SERVER
	lock_data();
	#endif
	unsigned rslt = codebooks->getId(codebooks->getTypeForName(type), stringValue, enableInsert, enableAutoLoad,
					 autoincrement, insertQuery, sqlDb);
	#ifdef CLOUD_ROUTER_SERVER
	unlock_data();
	#endif
	return(rslt);
}

u_int64_t cSqlDbData::getAiId(const char *table, const char *idColumn, SqlDb *sqlDb) {
	#ifdef CLOUD_ROUTER_SERVER
	lock_data();
	#endif
	u_int64_t rslt = autoincrement->getId(table, idColumn, sqlDb);
	#ifdef CLOUD_ROUTER_SERVER
	unlock_data();
	#endif
	return(rslt);
}

string cSqlDbData::getCbNameForType(cSqlDbCodebook::eTypeCodebook type) {
	#ifdef CLOUD_ROUTER_SERVER
	lock_data();
	#endif
	string rslt = codebooks->getNameForType(type);
	#ifdef CLOUD_ROUTER_SERVER
	unlock_data();
	#endif
	return(rslt);
}

void cSqlDbData::initCodebooks(bool loadAll, unsigned limitTableRows, SqlDb *sqlDb) {
	cSqlDbCodebook *cb_ua = new FILE_LINE(0) cSqlDbCodebook(cSqlDbCodebook::_cb_ua, "ua", "cdr_ua", "id", "ua", limitTableRows);
	cSqlDbCodebook *cb_sip_response = new FILE_LINE(0) cSqlDbCodebook(cSqlDbCodebook::_cb_sip_response, "sip_response", "cdr_sip_response", "id", "lastSIPresponse", limitTableRows);
	cSqlDbCodebook *cb_sip_request = new FILE_LINE(0) cSqlDbCodebook(cSqlDbCodebook::_cb_sip_request, "sip_request", "cdr_sip_request", "id", "request", limitTableRows);
	cSqlDbCodebook *cb_reason_sip = new FILE_LINE(0) cSqlDbCodebook(cSqlDbCodebook::_cb_reason_sip, "reason_sip", "cdr_reason", "id", "reason", limitTableRows);
	cb_reason_sip->addCond("type", "1");
	cSqlDbCodebook *cb_reason_q850 = new FILE_LINE(0) cSqlDbCodebook(cSqlDbCodebook::_cb_reason_q850, "reason_q850", "cdr_reason", "id", "reason", limitTableRows);
	cb_reason_q850->addCond("type", "2");
	cSqlDbCodebook *cb_contenttype = new FILE_LINE(0) cSqlDbCodebook(cSqlDbCodebook::_cb_contenttype, "contenttype", "contenttype", "id", "contenttype", limitTableRows);
	codebooks->registerCodebook(cb_ua);
	codebooks->registerCodebook(cb_sip_response);
	codebooks->registerCodebook(cb_sip_request);
	codebooks->registerCodebook(cb_reason_sip);
	codebooks->registerCodebook(cb_reason_q850);
	codebooks->registerCodebook(cb_contenttype);
	if(loadAll) {
		#ifdef CLOUD_ROUTER_CLIENT
		codebooks->setAutoLoadPeriodForAll(6 * 3600);
		#endif
		codebooks->loadAll(sqlDb);
	}
}

void cSqlDbData::initAutoIncrement(SqlDb *sqlDb) {
	autoincrement->set("cdr", "id", sqlDb);
	autoincrement->set("message", "id", sqlDb);
	codebooks->setAutoincrementForAll(autoincrement, sqlDb);
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


bool isSqlDriver(const char *sqlDriver, const char *checkSqlDriver) {
	return cmpStringIgnoreCase(checkSqlDriver ? checkSqlDriver : sql_driver, sqlDriver);
}

bool isTypeDb(const char *typeDb, const char *checkSqlDriver, const char *checkOdbcDriver) {
	return cmpStringIgnoreCase(checkSqlDriver ? checkSqlDriver : sql_driver, typeDb) ||
	       (cmpStringIgnoreCase(checkSqlDriver ? checkSqlDriver : sql_driver, "odbc") && 
	        cmpStringIgnoreCase(checkOdbcDriver ? checkOdbcDriver : odbc_driver, typeDb));
}


struct escChar {
	char ch;
	char escCh;
};
static escChar escCharsMysql[] = {
	{ '\'', '\'' },
	{ '"' , '"' },
	{ '\\', '\\' },
	{ '\n', 'n' },		// new line feed
	{ '\r', 'r' },		// cariage return
	// remove after create function test_escape
	//{ '\t', '\t' }, 	// tab
	//{ '\v', '\v' }, 	// vertical tab
	//{ '\b', '\b' }, 	// backspace
	//{ '\f', '\f' }, 	// form feed
	//{ '\a', '\a' }, 	// alert (bell)
	//{ '\e', 0 }, 		// escape
	// add after create function test_escape
	{    0, '0' },
	{   26, 'Z' }
};
static unsigned char escTableMysql[256][2];
static escChar escCharsOdbc[] = { 
	{ '\'', 2 },
	{ '\v', 0 }, 		// vertical tab
	{ '\b', 0 }, 		// backspace
	{ '\f', 0 }, 		// form feed
	{ '\a', 0 }, 		// alert (bell)
	{ '\e', 0 }, 		// escape
};
static unsigned char escTableOdbc[256][2];

void fillEscTables() {
	for(unsigned i = 0; i < sizeof(escCharsMysql) / sizeof(escCharsMysql[0]); i++) {
		escTableMysql[(unsigned char)escCharsMysql[i].ch][0] = 1;
		escTableMysql[(unsigned char)escCharsMysql[i].ch][1] = (unsigned char)escCharsMysql[i].escCh;
	}
	for(unsigned i = 0; i < sizeof(escCharsOdbc) / sizeof(escCharsOdbc[0]); i++) {
		escTableOdbc[(unsigned char)escCharsOdbc[i].ch][0] = 1;
		escTableOdbc[(unsigned char)escCharsOdbc[i].ch][1] = (unsigned char)escCharsOdbc[i].escCh;
	}
}

string _sqlEscapeString(const char *inputStr, int length, const char *typeDb, bool checkUtf) {
	bool mysql = false;
	unsigned char (*escTable)[2] = NULL;
	if(!typeDb || isTypeDb("mysql", typeDb)) {
		mysql = true;
		escTable = escTableMysql;
	} else if(isTypeDb("odbc", typeDb)) {
		escTable = escTableOdbc;
	}
	if(!length) {
		length = strlen(inputStr);
	}
	if(!escTable) {
		return(string(inputStr, length));
	}
	string rsltString;
	for(int posInputString = 0; posInputString < length; posInputString++) {
		if(escTable[(unsigned char)inputStr[posInputString]][0]) {
			if(mysql) {
				if(escTable[(unsigned char)inputStr[posInputString]][1]) {
					rsltString += '\\';
					rsltString += (char)escTable[(unsigned char)inputStr[posInputString]][1];
				}
			} else {
				if(escTable[(unsigned char)inputStr[posInputString]][1] == 2) {
					rsltString += inputStr[posInputString];
					rsltString += inputStr[posInputString];
				}
			}
		} else {
			rsltString += inputStr[posInputString];
		}
	}
	extern cUtfConverter utfConverter;
	if(checkUtf && !utfConverter.check(rsltString.c_str())) {
		rsltString = utfConverter.remove_no_ascii(rsltString.c_str());
	}
	return(rsltString);
}

void _sqlEscapeString(const char *inputStr, int length, char *outputStr, const char *typeDb, bool checkUtf) {
	bool mysql = false;
	unsigned char (*escTable)[2] = NULL;
	if(!typeDb || isTypeDb("mysql", typeDb)) {
		mysql = true;
		escTable = escTableMysql;
	} else if(isTypeDb("odbc", typeDb)) {
		escTable = escTableOdbc;
	}
	if(!length) {
		length = strlen(inputStr);
	}
	if(!escTable) {
		strncpy(outputStr, inputStr, length);
		outputStr[length] = 0;
		return;
	}
	unsigned posOutputString = 0;
	for(int posInputString = 0; posInputString < length; posInputString++) {
		if(escTable[(unsigned char)inputStr[posInputString]][0]) {
			if(mysql) {
				if(escTable[(unsigned char)inputStr[posInputString]][1]) {
					outputStr[posOutputString++] = '\\';
					outputStr[posOutputString++] = (char)escTable[(unsigned char)inputStr[posInputString]][1];
				}
			} else {
				if(escTable[(unsigned char)inputStr[posInputString]][1] == 2) {
					outputStr[posOutputString++] = inputStr[posInputString];
					outputStr[posOutputString++] = inputStr[posInputString];
				}
			}
		} else {
			outputStr[posOutputString++] = inputStr[posInputString];
		}
	}
	outputStr[posOutputString] = 0;
	extern cUtfConverter utfConverter;
	if(checkUtf && !utfConverter.check(outputStr)) {
		utfConverter._remove_no_ascii(outputStr);
	}
}

string sqlEscapeStringBorder(string inputStr, char borderChar, const char *typeDb) {
	return sqlEscapeStringBorder(inputStr.c_str(), borderChar, typeDb);
}

string sqlEscapeStringBorder(const char *inputStr, char borderChar, const char *typeDb) {
	string rsltString = sqlEscapeString(inputStr, 0, typeDb);
	if(borderChar) {
		rsltString = borderChar + rsltString + borderChar;
	}
	return rsltString;
}
 

void __store_prepare_queries(list<string> *queries, cSqlDbData *dbData, SqlDb *sqlDb,
			     string *queries_str, list<string> *queries_list, list<string> *cb_inserts,
			     int enable_new_store, bool enable_set_id, bool enable_multiple_rows_insert,
			     long unsigned maxAllowedPacket) {
	vector<string> q_delim;
	q_delim.push_back(_MYSQL_QUERY_END_new);
	q_delim.push_back(_MYSQL_QUERY_END_SUBST_new);
	list<string> ig;
	unsigned counterQueriesWithNextInsertGroup = 0;
	for(list<string>::iterator iter = queries->begin(); iter != queries->end(); ) {
		#ifdef CLOUD_ROUTER_CLIENT
		if(!strncmp(iter->c_str(), "csv", 3)) {
			cDbTablesContent *tablesContent = new FILE_LINE(0) cDbTablesContent;
			vector<string> query_vect = split(iter->c_str(), "\n", false, false);
			for(unsigned i = 0; i < query_vect.size(); i++) {
				tablesContent->addCsvRow(query_vect[i].c_str());
			}
			string mainTable = tablesContent->getMainTable();
			if(!mainTable.empty()) {
				int store_flags = 0;
				if(mainTable == "cdr") {
					int store_flags_columnIndex;
					store_flags = tablesContent->getValue_int(Call::_t_cdr, "store_flags", false, NULL, 0, &store_flags_columnIndex);
					if(store_flags_columnIndex >= 0) {
						tablesContent->removeColumn(Call::_t_cdr, store_flags_columnIndex);
					}
				}
				if(!store_flags || (store_flags & Call::_sf_db)) {
					tablesContent->substCB(dbData, cb_inserts);
					u_int64_t main_id = 0;
					tablesContent->substAI(dbData, &main_id);
					tablesContent->insertQuery(&ig, sqlDb);
				}
				if(store_flags & Call::_sf_charts_cache) {
					if(existsRemoteChartServer()) {
						extern MySqlStore *sqlStore;
						sqlStore->query_lock(iter->c_str(), STORE_PROC_ID_CHARTS_CACHE_REMOTE, 0);
						delete tablesContent;
					} else if(opt_charts_cache) {
						extern Calltable *calltable;
						calltable->lock_calls_charts_cache_queue();
						#if DEBUG_STORE_COUNT
						extern map<int, u_int64_t> _charts_cache_cnt;
						++_charts_cache_cnt[0];
						#endif
						calltable->calls_charts_cache_queue.push_back(sChartsCallData(sChartsCallData::_tables_content, tablesContent));
						calltable->unlock_calls_charts_cache_queue();
					} else {
						delete tablesContent;
					}
				} else {
					delete tablesContent;
				}
			} else {
				delete tablesContent;
			}
			iter++;
		} else {
		#endif
			vector<string> query_vect = split(iter->c_str(), q_delim, false, false, false);
			bool setIdMainRecord = false;
			u_int64_t idMainRecord = 0;
			if(enable_set_id) {
				for(unsigned i = 0; i < query_vect.size(); i++) {
					size_t cbIdPrefixPos = string::npos;
					size_t cbIdLengthSeparatorPos = string::npos;
					size_t cbIdValueSeparatorPos = string::npos;
					while((cbIdPrefixPos = query_vect[i].find(MYSQL_CODEBOOK_ID_PREFIX)) != string::npos &&
					      (cbIdLengthSeparatorPos = query_vect[i].find(":", cbIdPrefixPos + MYSQL_CODEBOOK_ID_PREFIX.length())) != string::npos &&
					      (cbIdValueSeparatorPos = query_vect[i].find(";", cbIdLengthSeparatorPos + 1)) != string::npos) {
						unsigned nameValueLength = atoi(query_vect[i].c_str() + cbIdPrefixPos + MYSQL_CODEBOOK_ID_PREFIX.length());
						unsigned endPos = cbIdLengthSeparatorPos + nameValueLength;
						if(endPos < query_vect[i].length() - 2 &&
						   (query_vect[i][endPos + 1] == ',' ||
						    query_vect[i][endPos + 1] == ')' ||
						    (query_vect[i][endPos + 1] == ' ' && query_vect[i][endPos + 2] == ')'))) {
							string cb_name = query_vect[i].substr(cbIdLengthSeparatorPos + 1, cbIdValueSeparatorPos - cbIdLengthSeparatorPos - 1);
							string cb_value = query_vect[i].substr(cbIdValueSeparatorPos + 1, nameValueLength - (cbIdValueSeparatorPos - cbIdLengthSeparatorPos - 1) - 1);
							//cout << "/" << cb_name << "/" << cb_value << "/" << endl;
							string cb_insert;
							unsigned cb_id = dbData->getCbId(cb_name.c_str(), cb_value.c_str(), true, false,
											 &cb_insert, sqlDb);
							if(!cb_insert.empty()) {
								cb_inserts->push_back(cb_insert);
							}
							string cb_id_str = cb_id ? intToString(cb_id) : "NULL";
							//cout << cb_id_str << endl;
							query_vect[i] = query_vect[i].substr(0, cbIdPrefixPos) + cb_id_str + query_vect[i].substr(cbIdLengthSeparatorPos + 1 + nameValueLength);
							//cout << query_vect[i] << endl;
						} else {
							query_vect[i] = query_vect[i].substr(0, cbIdPrefixPos) + MYSQL_CODEBOOK_ID_PREFIX_SUBST + query_vect[i].substr(cbIdPrefixPos + MYSQL_CODEBOOK_ID_PREFIX.length());
						}
					}
				}
				string tableMainRecord;
				for(unsigned i = 0; i < query_vect.size(); i++) {
					if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_MAIN_INSERT_new, _MYSQL_MAIN_INSERT_new_length) &&
					   query_vect[i].find(MYSQL_MAIN_INSERT_ID) != string::npos) {
						size_t sepTable = query_vect[i].find("INTO");
						size_t endSepTable = query_vect[i].find("(");
						if(sepTable != string::npos && endSepTable != string::npos && endSepTable > sepTable) {
							tableMainRecord = query_vect[i].substr(sepTable + 4, endSepTable - sepTable - 4);
							trim(tableMainRecord);
							setIdMainRecord = true;
							break;
						}
					}
				}
				if(setIdMainRecord) {
					idMainRecord = dbData->getAiId(tableMainRecord.c_str(), NULL, sqlDb);
				}
			}
			if(enable_multiple_rows_insert) {
				if(setIdMainRecord) {
					for(unsigned i = 0; i < query_vect.size(); ) {
						find_and_replace(query_vect[i], MYSQL_MAIN_INSERT_ID, intToString(idMainRecord));
						if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_MAIN_INSERT_new, _MYSQL_MAIN_INSERT_new_length)) {
							ig.push_back(query_vect[i].substr(_MYSQL_MAIN_INSERT_new_length));
							query_vect.erase(query_vect.begin() + i);
						} else if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_NEXT_INSERT_GROUP_new, _MYSQL_NEXT_INSERT_GROUP_new_length)) {
							ig.push_back(query_vect[i].substr(_MYSQL_NEXT_INSERT_GROUP_new_length));
							query_vect.erase(query_vect.begin() + i);
						} else {
							i++;
						}
					}
				} else {
					if(MYSQL_EXISTS_PREFIX_L(query_vect[0], _MYSQL_MAIN_INSERT_GROUP_new, _MYSQL_MAIN_INSERT_GROUP_new_length)) {
						bool allItemsIsMIG = true;
						for(unsigned i = 1; i < query_vect.size(); i++) {
							if(!MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_MAIN_INSERT_GROUP_new, _MYSQL_MAIN_INSERT_GROUP_new_length)) {
								allItemsIsMIG = false;
								break;
							}
						}
						if(allItemsIsMIG) {
							for(unsigned i = 0; i < query_vect.size(); i++) {
								ig.push_back(query_vect[i].substr(_MYSQL_MAIN_INSERT_GROUP_new_length));
							}
							queries->erase(iter++);
							continue;
						}
					}
					bool existsNIG = false;
					for(unsigned i = 1; i < query_vect.size(); i++) {
						if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_NEXT_INSERT_GROUP_new, _MYSQL_NEXT_INSERT_GROUP_new_length)) {
							existsNIG = true;
							break;
						}
					}
					if(existsNIG) {
						++counterQueriesWithNextInsertGroup;
						unsigned counterMI_ID_old = 0;
						for(unsigned i = 0; i < query_vect.size(); ) {
							find_and_replace(query_vect[i], MYSQL_MAIN_INSERT_ID, MYSQL_MAIN_INSERT_ID2 + "_" + intToString(counterQueriesWithNextInsertGroup));
							unsigned counter_replace_MI_ID_old;
							find_and_replace(query_vect[i], MYSQL_MAIN_INSERT_ID_OLD, MYSQL_MAIN_INSERT_ID_OLD2 + "_" + intToString(counterQueriesWithNextInsertGroup), &counter_replace_MI_ID_old);
							if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_NEXT_INSERT_GROUP_new, _MYSQL_NEXT_INSERT_GROUP_new_length)) {
								ig.push_back(query_vect[i].substr(_MYSQL_NEXT_INSERT_GROUP_new_length));
								query_vect.erase(query_vect.begin() + i);
							} else {
								if(counter_replace_MI_ID_old) {
									++counterMI_ID_old;
								}
								i++;
							}
						}
						for(unsigned i = 0; i < query_vect.size(); ) {
							if(i < query_vect.size() - 1 &&
							   MYSQL_EXISTS_PREFIX_S(query_vect[i], MYSQL_IF) &&
							   MYSQL_EXISTS_PREFIX_S(query_vect[i + 1], MYSQL_ENDIF)) {
								if(counterMI_ID_old > 0 &&
								   query_vect[i].find(MYSQL_MAIN_INSERT_ID_OLD2) != string::npos) {
									--counterMI_ID_old;
								}
								query_vect.erase(query_vect.begin() + i);
								query_vect.erase(query_vect.begin() + i);
							} else {
								i++;
							}
						}
						if(counterMI_ID_old == 1) {
							for(unsigned i = 0; i < query_vect.size(); ) {
								if(MYSQL_EXISTS_PREFIX_S(query_vect[i], ("set " + MYSQL_MAIN_INSERT_ID_OLD2))) {
									query_vect.erase(query_vect.begin() + i);
									break;
								} else {
									i++;
								}
							}
						}
					}
				}
			}
			for(unsigned i = 0; i < query_vect.size(); i++) {
				if(query_vect[i][0] == ':') {
					if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_MAIN_INSERT_new, _MYSQL_MAIN_INSERT_new_length)) {
						query_vect[i] = query_vect[i].substr(_MYSQL_MAIN_INSERT_new_length);
					} else if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_MAIN_INSERT_GROUP_new, _MYSQL_MAIN_INSERT_GROUP_new_length)) {
						query_vect[i] = query_vect[i].substr(_MYSQL_MAIN_INSERT_GROUP_new_length);
					} else if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_NEXT_INSERT_new, _MYSQL_NEXT_INSERT_new_length)) {
						query_vect[i] = query_vect[i].substr(_MYSQL_NEXT_INSERT_new_length);
					} else if(MYSQL_EXISTS_PREFIX_L(query_vect[i], _MYSQL_NEXT_INSERT_GROUP_new, _MYSQL_NEXT_INSERT_GROUP_new_length)) {
						query_vect[i] = query_vect[i].substr(_MYSQL_NEXT_INSERT_GROUP_new_length);
					}
				}
				if(enable_new_store == 2) {
					queries_list->push_back(query_vect[i]);
				} else {
					*queries_str += sqlEscapeString(query_vect[i]) + _MYSQL_QUERY_END_new;
				}
			}
			iter++;
		#ifdef CLOUD_ROUTER_CLIENT
		}
		#endif
	}
	#if 1
	if(ig.size()) {
		map<string, list<string> > nig_map;
		for(list<string>::iterator iter = ig.begin(); iter != ig.end(); iter++) {
			size_t sepValues = iter->find(" ) VALUES ( ");
			size_t endSep = iter->rfind(" )");
			if(sepValues != string::npos && endSep != string::npos && endSep > sepValues) {
				string tableColumns = iter->substr(0, sepValues);
				string values = iter->substr(sepValues + 12, endSep - sepValues - 12);
				nig_map[tableColumns].push_back(values);
			} else {
				if(enable_new_store == 2) {
					queries_list->push_back(*iter);
				} else {
					*queries_str += sqlEscapeString(*iter) + _MYSQL_QUERY_END_new;
				}
			}
		}
		for(map<string, list<string> >::iterator iter = nig_map.begin(); iter != nig_map.end(); iter++) {
			list<string> *values = &iter->second;
			string values_str;
			for(list<string>::iterator iter_values = values->begin(); iter_values != values->end(); iter_values++) {
				if(maxAllowedPacket && values_str.length() *1.1 > maxAllowedPacket) {
					if(enable_new_store == 2) {
						queries_list->push_back(iter->first + " ) VALUES ( " + values_str + " )");
					} else {
						*queries_str += iter->first + " ) VALUES ( " + sqlEscapeString(values_str) + " )" + _MYSQL_QUERY_END_new;
					}
					values_str = "";
				}
				if(!values_str.empty()) {
					values_str += " ),( ";
				}
				values_str += *iter_values;
			}
			if(enable_new_store == 2) {
				queries_list->push_back(iter->first + " ) VALUES ( " + values_str + " )");
			} else {
				*queries_str += iter->first + " ) VALUES ( " + sqlEscapeString(values_str) + " )" + _MYSQL_QUERY_END_new;
			}
		}
	}
	#else
	if(ig.size()) {
		for(list<string>::iterator iter = ig.begin(); iter != ig.end(); iter++) {
			*queries_str += sqlEscapeString(*iter) + _MYSQL_QUERY_END_new;
		}
	}
	#endif
}
