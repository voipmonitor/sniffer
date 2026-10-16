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
#define CDR_COLUMN_SLOTS 1000


extern volatile unsigned cdr_column_slots_used;

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
	_t_cdr_text_data,
	_t_cdr_conference,
	_t_cdr_dtmf
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
		if(s1.length != s2.length) {
			return(s1.length < s2.length);
		}
		if(!s1.length) {
			return(false);
		}
		if(s1.icase || s2.icase) {
			return(strncasecmp(s1.begin + s1.offset, s2.begin + s2.offset, s1.length) < 0);
		}
		return(strncmp(s1.begin + s1.offset, s2.begin + s2.offset, s1.length) < 0);
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

inline long long dbStrToInt(const char *str) {
	const char *p = str;
	bool neg = false;
	if(*p == '-') {
		neg = true;
		p++;
	} else if(*p == '+') {
		p++;
	}
	unsigned long long v = 0;
	unsigned digits = 0;
	while(*p >= '0' && *p <= '9') {
		v = v * 10 + (unsigned)(*p - '0');
		p++;
		digits++;
	}
	if(!digits || digits > 18 || *p) {
		return(atoll(str));
	}
	return(neg ? -(long long)v : (long long)v);
}

inline double dbStrToFloat(const char *str) {
	static const double pow10[] = { 1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
					1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22 };
	const char *p = str;
	bool neg = false;
	if(*p == '-') {
		neg = true;
		p++;
	} else if(*p == '+') {
		p++;
	}
	unsigned long long m = 0;
	unsigned digits = 0;
	while(*p >= '0' && *p <= '9') {
		m = m * 10 + (unsigned)(*p - '0');
		p++;
		digits++;
	}
	unsigned dec = 0;
	if(*p == '.') {
		p++;
		while(*p >= '0' && *p <= '9') {
			m = m * 10 + (unsigned)(*p - '0');
			p++;
			digits++;
			dec++;
		}
	}
	if(!digits || digits > 15 || dec > 22 || *p) {
		return(atof(str));
	}
	double v = (double)m;
	if(dec) {
		v /= pow10[dec];
	}
	return(neg ? -v : v);
}

class cDbTableContent {
public:
	enum eColumnValues {
		_cv_int,
		_cv_float,
		_cv_ip,
		_cv_str
	};
	struct sColumnValues {
		sColumnValues(unsigned rows) {
			this->rows = rows;
			i_1 = 0;
			f_1 = 0;
			s_1 = NULL;
			n_1 = false;
			null_set = false;
			int_set = false;
			float_set = false;
			ip_set = false;
			str_set = false;
		}
		void setValue(const char *str, bool null, eColumnValues type) {
			if(!null_set) {
				if(rows == 1) n_1 = null; else v_null.push_back(null);
			}
			switch(type) {
			case _cv_int:
				{
				long long v = str ? dbStrToInt(str) : 0;
				if(rows == 1) i_1 = v; else v_int.push_back(v);
				}
				break;
			case _cv_float:
				{
				double v = str ? dbStrToFloat(str) : 0;
				if(rows == 1) f_1 = v; else v_float.push_back(v);
				}
				break;
			case _cv_ip:
				{
				vmIP v;
				if(str) v.setFromString(str); else v = 0;
				if(rows == 1) ip_1 = v; else v_ip.push_back(v);
				}
				break;
			case _cv_str:
				{
				const char *v = str ? str : "";
				if(rows == 1) s_1 = v; else v_str.push_back(v);
				}
				break;
			}
		}
		long long value_int(unsigned row) {
			return(rows == 1 ? i_1 : v_int[row]);
		}
		double value_float(unsigned row) {
			return(rows == 1 ? f_1 : v_float[row]);
		}
		vmIP value_ip(unsigned row) {
			return(rows == 1 ? ip_1 : v_ip[row]);
		}
		const char *value_str(unsigned row) {
			return(rows == 1 ? s_1 : v_str[row]);
		}
		bool isNull(unsigned row) {
			return(rows == 1 ? n_1 : v_null[row]);
		}
		vector<long long> v_int;
		vector<double> v_float;
		vector<vmIP> v_ip;
		vector<const char*> v_str;
		vector<bool> v_null;
		long long i_1;
		double f_1;
		vmIP ip_1;
		const char *s_1;
		unsigned rows;
		bool n_1;
		bool null_set;
		bool int_set;
		bool float_set;
		bool ip_set;
		bool str_set;
	};
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
	sColumnValues *getColumnValues(int columnIndex, eColumnValues type) {
		if(columnIndex >= 0 && columnIndex < (int)values_cache.size()) {
			sColumnValues *values = values_cache[columnIndex];
			if(values &&
			   ((type == _cv_int && values->int_set) ||
			    (type == _cv_float && values->float_set) ||
			    (type == _cv_ip && values->ip_set) ||
			    (type == _cv_str && values->str_set))) {
				return(values);
			}
		}
		return(getColumnValues_slow(columnIndex, type));
	}
	sColumnValues *getColumnValues_slow(int columnIndex, eColumnValues type);
	void clearColumnValues();
public:
	sHeader header;
	vector<sRow> rows;
	string table_name;
	vector<sColumnValues*> values_cache;
	vector<int> values_filled;
};

class cDbTablesContent {
public:
	cDbTablesContent();
	~cDbTablesContent();
	cDbTableContent::sColumnValues *getColumnValues(unsigned table_enum, const char *column, cDbTableContent::eColumnValues type, int *columnIndex = NULL);
	cDbTableContent::sColumnValues *getColumnValues_slot(unsigned slot, unsigned table_enum, const char *column, cDbTableContent::eColumnValues type, int *columnIndex = NULL) {
		if(slot >= slots_used || !slots[slot].resolved) {
			return(getColumnValues_slot_slow(slot, table_enum, column, type, columnIndex));
		}
		sColumnSlot *columnSlot = &slots[slot];
		if(columnIndex) {
			*columnIndex = columnSlot->columnIndex;
		}
		return(columnSlot->table ? columnSlot->table->getColumnValues(columnSlot->columnIndex, type) : NULL);
	}
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
	long long unsigned getValue_uint(unsigned table_enum, const char *column, bool onlyNotZero = false, bool *null = NULL, unsigned rowIndex = 0, int *columnIndex = NULL) {
		const char *str = getValue_str(table_enum, column, null, rowIndex, columnIndex);
		if(str) {
			char *endptr;
			long long unsigned rslt = strtoull(str, &endptr, 10);
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
	double getAvgValue(unsigned table_enum, const char *columns[], bool nullIfAnyNull, bool onlyNotZero, bool *null = NULL);
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
	void clearColumnValues() {
		for(unsigned i = 0; i < tables.size(); i++) {
			tables[i]->clearColumnValues();
		}
	}
public:
	vector<cDbTableContent*> tables;
	map<string, cDbTableContent*> tables_map;
	map<unsigned, cDbTableContent*> tables_enum_map;
private:
	struct sColumnSlot {
		cDbTableContent *table;
		int columnIndex;
		bool resolved;
	};
	cDbTableContent::sColumnValues *getColumnValues_slot_slow(unsigned slot, unsigned table_enum, const char *column, cDbTableContent::eColumnValues type, int *columnIndex);
	unsigned slots_used;
	sColumnSlot slots[CDR_COLUMN_SLOTS];
};


int getDbTableEnumIndex(string *table);


#endif
