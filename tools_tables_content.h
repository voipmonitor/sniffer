#ifndef TOOLS_TABLES_CONTENT_H
#define TOOLS_TABLES_CONTENT_H


#include <string.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <vector>
#include <map>

#include "ip.h"

using namespace std;

#define CDR_NEXT_MAX 10

enum eDbTable {
	_t_cdr = 1,
	_t_cdr_next = 2,
	_t_cdr_next_end = 20,
	_t_cdr_country_code = 21,
	_t_cdr_proxy,
	_t_cdr_sipresp,
	_t_cdr_siphistory,
	_t_cdr_rtp,
	_t_cdr_sdp,
	_t_cdr_conference
};

struct sDbString {
	const char *begin;
	unsigned offset;
	unsigned length;
	bool icase;
	int flags;
	const char *str;
	u_int64_t cb_id;
	u_int64_t ai_id;
	void setZeroTerm() {
		*((char*)begin + offset + length) = 0;
	}
	void setNextData() {
		const char *p = begin + offset;
		flags = *p - '0';
		if(*(p + 1) == ':') {
			str = p + 2;
		} else {
			str = NULL;
		}
		cb_id = 0;
		ai_id = 0;
	}
	void setStr() {
		str = begin + offset;
	}
	const char *getStr() {
		return(begin + offset);
	}
	friend int operator == (const sDbString &s1, const sDbString &s2) {
		if(s1.length == s2.length) {
			if(s1.icase || s2.icase) {
				return(!strncasecmp(s1.begin + s1.offset, s2.begin + s2.offset, s1.length));
			} else {
				return(!strncmp(s1.begin + s1.offset, s2.begin + s2.offset, s1.length));
			}
		} else {
			return(0);
		}
	}
	friend int operator < (const sDbString &s1, const sDbString &s2) {
		if(!s1.length || !s2.length) {
			return(s1.length < s2.length);
		}
		if(s1.length == s2.length) {
			int rslt_cmp;
			if(s1.icase || s2.icase) {
				rslt_cmp = strncasecmp(s1.begin + s1.offset, s2.begin + s2.offset, s1.length);
			} else {
				rslt_cmp = strncmp(s1.begin + s1.offset, s2.begin + s2.offset, s1.length);
			}
			return(rslt_cmp < 0);
		} else {
			int rslt_cmp;
			if(s1.icase || s2.icase) {
				rslt_cmp = strncasecmp(s1.begin + s1.offset, s2.begin + s2.offset, min(s1.length, s2.length));
			} else {
				rslt_cmp = strncmp(s1.begin + s1.offset, s2.begin + s2.offset, min(s1.length, s2.length));
			}
			if(rslt_cmp == 0) {
				return(s1.length < s2.length);
			} else {
				return(rslt_cmp < 0);
			}
		}
	}
	void substCB(class cSqlDbData *dbData, list<string> *cb_inserts);
	void substAI(class cSqlDbData *dbData, u_int64_t *ai_id, const char *table_name);
};

class cDbStrings {
public:
	cDbStrings(unsigned capacity = 0, unsigned capacity_inc = 0);
	~cDbStrings();
	void add(const char *begin, unsigned offset, unsigned length, bool needUnescape = false);
	void explodeCsv(const char *csv, bool header = false);
	void setZeroTerm();
	void setNextData();
	void createMap(bool icase);
	int findIndex(const char *str, unsigned str_length = 0) {
		if(!strings_map) {
			return(-2);
		}
		sDbString _str;
		_str.begin = str;
		_str.offset = 0;
		_str.length = str_length ? str_length : strlen(str);
		_str.icase = icase_map;
		map<sDbString, unsigned>::iterator iter = strings_map->find(_str);
		if(iter != strings_map->end()) {
			return(iter->second);
		}
		return(-1);
	}
	int findIndex(string &str) {
		return(findIndex(str.c_str(), str.length()));
	}
	void substCB(class cSqlDbData *dbData, list<string> *cb_inserts);
	void substAI(class cSqlDbData *dbData, u_int64_t *ai_id, const char *table_name);
	string implodeInsertColumns();
	string implodeInsertValues(const char *table, cDbStrings *header, class SqlDb *sqlDb);
	void print();
	sDbString *strings;
	map<sDbString, unsigned> *strings_map;
	unsigned size;
	unsigned capacity;
	unsigned capacity_inc;
	bool zero_term_set;
	bool icase_map;
};

class cDbTableContent {
public:
	struct sHeader {
		sHeader() {
			items = NULL;
			content = NULL;
		}
		void destroy() {
			if(items) delete items;
			if(content) delete [] content;
		}
		cDbStrings *items;
		const char *content;
	};
	struct sRow {
		sRow() {
			items = NULL;
			content = NULL;
		}
		void destroy() {
			if(items) delete items;
			if(content) delete [] content;
		}
		cDbStrings *items;
		const char *content;
	};
public:
	cDbTableContent(const char *table_name);
	~cDbTableContent();
	void addHeader(const char *source);
	void addRow(const char *source);
	void substCB(class cSqlDbData *dbData, list<string> *cb_inserts);
	void substAI(class cSqlDbData *dbData, u_int64_t *ai_id);
	string insertQuery(SqlDb *sqlDb);
public:
	sHeader header;
	vector<sRow> rows;
	string table_name;
};

class cDbTablesContent {
public:
	cDbTablesContent();
	~cDbTablesContent();
	void addCsvRow(const char *source);
	void substCB(class cSqlDbData *dbData, list<string> *cb_inserts);
	void substAI(class cSqlDbData *dbData, u_int64_t *ai_id);
	string getMainTable();
	void insertQuery(list<string> *dst, SqlDb *sqlDb);
	sDbString *findColumn(const char *table, const char *column, unsigned rowIndex, int *columnIndex);
	sDbString *findColumn(unsigned table_enum, const char *column, unsigned rowIndex, int *columnIndex);
	int getCountRows(const char *table);
	int getCountRows(unsigned table_enum);
	bool existsColumn(unsigned table_enum, const char *column, unsigned rowIndex = 0);
	const char *getValue_str(unsigned table_enum, const char *column, bool *null = NULL, unsigned rowIndex = 0, int *columnIndex = NULL);
	const char *getValue_string(unsigned table_enum, const char *column, bool *null = NULL, unsigned rowIndex = 0) {
		const char *str = getValue_str(table_enum, column, null, rowIndex);
		if(str) {
			return(str);
		}
		return("");
	}
	long long getValue_int(unsigned table_enum, const char *column, bool onlyNotZero = false, bool *null = NULL, unsigned rowIndex = 0, int *columnIndex = NULL) {
		const char *str = getValue_str(table_enum, column, null, rowIndex, columnIndex);
		if(str) {
			long long rslt = atoll(str);
			if(onlyNotZero && !rslt && null) {
				*null = true;
			}
			return(rslt);
		}
		if(onlyNotZero && null) {
			*null = true;
		}
		return(0);
	}
	double getValue_float(unsigned table_enum, const char *column, bool onlyNotZero = false, bool *null = NULL, unsigned rowIndex = 0) {
		const char *str = getValue_str(table_enum, column, null, rowIndex);
		if(str) {
			double rslt = atof(str);
			if(onlyNotZero && !rslt && null) {
				*null = true;
			}
			return(rslt);
		}
		if(onlyNotZero && null) {
			*null = true;
		}
		return(0);
	}
	double getMinMaxValue(unsigned table_enum, const char *columns[], bool min, bool onlyNotZero, bool *null = NULL);
	vmIP getValue_ip(unsigned table_enum, const char *column, bool *null = NULL, unsigned rowIndex = 0) {
		const char *str = getValue_str(table_enum, column, null, rowIndex);
		if(str) {
			vmIP ip;
			ip.setFromString(str);
			return(ip);
		}
		return(0);
	}
	void removeColumn(unsigned table_enum, const char *column);
	void removeColumn(unsigned table_enum, unsigned columnIndex);
public:
	vector<cDbTableContent*> tables;
	map<string, cDbTableContent*> tables_map;
	map<unsigned, cDbTableContent*> tables_enum_map;
};


int getDbTableEnumIndex(string *table);


#endif
