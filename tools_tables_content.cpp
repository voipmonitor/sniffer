#include "config.h"

#include "sql_db.h"
#include "sql_db_global.h"
#include "tools_tables_content.h"


void sDbString::substCB(cSqlDbData *dbData, list<string> *cb_inserts) {
	if((flags & SqlDb_row::_ift_base) >= SqlDb_row::_ift_cb_string) {
		string cb_insert;
		cb_id = dbData->getCbId((cSqlDbCodebook::eTypeCodebook)((flags & SqlDb_row::_ift_base) - SqlDb_row::_ift_cb_string), str, true, false,
					&cb_insert);
		if(!cb_insert.empty()) {
			cb_inserts->push_back(cb_insert);
		}
		//cout << "CB: " << flags << " / " << str << " / " << cb_id << endl;
	}
}

void sDbString::substAI(cSqlDbData *dbData, u_int64_t *ai_id, const char *table_name) {
	if(flags == SqlDb_row::_ift_sql &&
	   !strcmp(str, MYSQL_MAIN_INSERT_ID.c_str())) {
		if(!*ai_id) {
			*ai_id = dbData->getAiId(table_name);
		}
		this->ai_id = *ai_id;
		//cout << "AI: " << flags << " / " << str << " / " << *ai_id << endl;
	}
}

cDbStrings::cDbStrings(unsigned capacity, unsigned capacity_inc) {
	if(capacity) {
		strings = new FILE_LINE(0) sDbString[capacity];
		this->capacity = capacity;
		this->capacity_inc = capacity_inc ? capacity_inc : capacity;
	} else {
		strings = NULL;
		this->capacity = 0;
		this->capacity_inc = capacity_inc ? capacity_inc : 1;
	}
	size = 0;
	strings_map = NULL;
	zero_term_set = false;
}

cDbStrings::~cDbStrings() {
	if(strings_map) {
		delete strings_map;
	}
	if(strings) {
		delete [] strings;
	}
}

void cDbStrings::add(const char *begin, unsigned offset, unsigned length, bool needUnescape) {
	if(size == capacity) {
		sDbString *strings_new = new FILE_LINE(0) sDbString[capacity + capacity_inc];
		if(strings) {
			memcpy(strings_new, strings, size * sizeof(sDbString));
			delete [] strings;
		}
		strings = strings_new;
		capacity += capacity_inc;
	}
	if(needUnescape) {
		const char *_begin = begin + offset;
		for(unsigned i = 0; i < length - 2; i++) {
			if(_begin[i] == '\\' && _begin[i + 1] == '"' && _begin[i + 2] == ',') {
				for(unsigned j = i; j < length - 1; j++) {
					((char*)_begin)[j] = _begin[j + 1];
				}
				--length;
			}
		}
	}
	strings[size].begin = begin;
	strings[size].offset = offset;
	strings[size].length = length;
	++size;
}

void cDbStrings::explodeCsv(const char *csv, bool header) {
	unsigned lengthCsv = strlen(csv);
	while(lengthCsv &&
	      (csv[lengthCsv - 1] == '\r' || csv[lengthCsv - 1] == '\n')) {
		--lengthCsv;
	}
	unsigned pos = 0;
	while(pos < lengthCsv) {
		bool is_string = csv[pos] == '"';
		const char *nextSep = strstr(csv + pos, is_string ? "\"," : ",");
		bool needUnescape = false;
		if(nextSep && is_string) {
			while(nextSep) {
				if(*(nextSep - 1) == '\\') {
					needUnescape = true;
				} else if(!header) {
					unsigned posNextSep = nextSep - csv;
					if((posNextSep < lengthCsv - 2 && 
					    *(nextSep + 2) == ('0' + SqlDb_row::_ift_null)) ||
					   (posNextSep < lengthCsv - 3 && 
					    *(nextSep + 2) == '"' && *(nextSep + 4) == ':' && *(nextSep + 3) >= '0' && *(nextSep + 3) < ('0' + SqlDb_row::_ift_null))) {
						break;
					}
				} else {
					break;
				}
				nextSep = strstr(nextSep + 1, is_string ? "\"," : ",");
			}
		}
		if(nextSep) {
			unsigned nextSepPos = nextSep - csv;
			if(is_string) {
				add(csv, pos + 1, nextSepPos - pos - 1, needUnescape);
			} else {
				add(csv, pos, nextSepPos - pos);
			}
			pos = nextSepPos + (is_string ? 2 : 1);
		} else {
			if(is_string) {
				add(csv, pos + 1, lengthCsv - pos - 2, needUnescape);
			} else {
				add(csv, pos, lengthCsv - pos);
			}
			break;
		}
	}
}

void cDbStrings::setZeroTerm() {
	for(unsigned i = 0; i < size; i++) {
		strings[i].setZeroTerm();
	}
	zero_term_set = true;
}

void cDbStrings::setNextData() {
	for(unsigned i = 0; i < size; i++) {
		strings[i].setNextData();
	}
}

void cDbStrings::createMap(bool icase) {
	strings_map = new FILE_LINE(0) map<sDbString, unsigned>;
	for(unsigned i = 0; i < size; i++) {
		strings[i].setStr();
		strings[i].icase = icase;
		(*strings_map)[strings[i]] = i;
	}
	icase_map = icase;
}

void cDbStrings::print() {
	for(unsigned i = 0; i < size; i++) {
		if(zero_term_set) {
			cout << '|' << string(strings[i].begin + strings[i].offset, strings[i].length) << '|' << endl;
		} else {
			cout << '|' << (strings[i].begin + strings[i].offset) << '|' << endl;
		}
	}
}

void cDbStrings::substCB(cSqlDbData *dbData, list<string> *cb_inserts) {
	for(unsigned i = 0; i < size; i++) {
		strings[i].substCB(dbData, cb_inserts);
	}
}

void cDbStrings::substAI(cSqlDbData *dbData, u_int64_t *ai_id, const char *table_name) {
	for(unsigned i = 0; i < size; i++) {
		strings[i].substAI(dbData, ai_id, table_name);
	}
}

string cDbStrings::implodeInsertColumns() {
	string separator = ",";
	string border = "`";
	string rslt;
	unsigned counter = 0;
	for(size_t i = 0; i < size; i++) {
		if(!strings[i].begin) {
			continue;
		}
		if(counter) { rslt += separator; }
		rslt += border + (strings[i].begin + strings[i].offset) + border;
		++counter;
	}
	return(rslt);
}

string cDbStrings::implodeInsertValues(const char *table, cDbStrings *header, SqlDb *sqlDb) {
	string separator = ",";
	string string_border = "'";
	string rslt = "( ";
	unsigned counter = 0;
	for(size_t i = 0; i < size; i++) {
		if(!strings[i].begin) {
			continue;
		}
		if(counter) { rslt += separator; }
		if(strings[i].flags & SqlDb_row::_ift_null) {
			rslt += "NULL";
		} else {
			switch(strings[i].flags & SqlDb_row::_ift_base) {
			case SqlDb_row::_ift_string:
				rslt += string_border + strings[i].str + string_border;
				break;
			case SqlDb_row::_ift_int:
			case SqlDb_row::_ift_int_u:
			case SqlDb_row::_ift_double:
				rslt += strings[i].str;
				break;
			case SqlDb_row::_ift_ip:
				if(VM_IPV6_B && sqlDb->isIPv6Column(table, header->strings[i].getStr())) {
					rslt += string("inet6_aton('") + strings[i].str + "')";
				} else {
					rslt += intToString(str_2_vmIP(strings[i].str).getIPv4());
				}
				break;
			case SqlDb_row::_ift_calldate:
				rslt += string_border + sqlEscapeString(sqlDateTimeString_us2ms(atoll(strings[i].str))) + string_border;
				break;
			case SqlDb_row::_ift_sql:
				if(strings[i].ai_id) {
					rslt += intToString(strings[i].ai_id);
				} else {
					rslt += strings[i].str;
				}
				break;
			default:
				if((strings[i].flags & SqlDb_row::_ift_base) >= SqlDb_row::_ift_cb_string && strings[i].cb_id) {
					rslt += intToString(strings[i].cb_id);
				} else {
					rslt += "NULL";
				}
			}
		}
		++counter;
	}
	rslt += " )";
	return(rslt);
}

cDbTableContent::cDbTableContent(const char *table_name) {
	this->table_name = table_name;
}

cDbTableContent::~cDbTableContent() {
	header.destroy();
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		iter->destroy();
	}
}

void cDbTableContent::addHeader(const char *source) {
	char *content = new FILE_LINE(0) char[strlen(source) + 1];
	strcpy(content, source);
	header.content = content;
	header.items = new FILE_LINE(0) cDbStrings(100);
	header.items->explodeCsv(content, true);
	header.items->setZeroTerm();
	header.items->createMap(true);
}

void cDbTableContent::addRow(const char *source) {
	char *content = new FILE_LINE(0) char[strlen(source) + 1];
	strcpy(content, source);
	sRow row;
	row.content = content;
	row.items = new FILE_LINE(0) cDbStrings(100);
	row.items->explodeCsv(content);
	row.items->setZeroTerm();
	row.items->setNextData();
	rows.push_back(row);
}

void cDbTableContent::substCB(class cSqlDbData *dbData, list<string> *cb_inserts) {
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		iter->items->substCB(dbData, cb_inserts);
	}
}

void cDbTableContent::substAI(class cSqlDbData *dbData, u_int64_t *ai_id) {
	//cout << "TABLE: " << table_name << endl;
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		iter->items->substAI(dbData, ai_id, table_name.c_str());
	}
}

string cDbTableContent::insertQuery(SqlDb *sqlDb) {
	string insert_str = "INSERT INTO " + table_name + " ( ";
	insert_str += header.items->implodeInsertColumns();
	insert_str += " ) VALUES ";
	unsigned counter = 0;
	for(vector<sRow>::iterator iter = rows.begin(); iter != rows.end(); iter++) {
		if(counter) {
			insert_str += ",";
		}
		insert_str += iter->items->implodeInsertValues(table_name.c_str(), header.items, sqlDb);
		++counter;
	}
	return(insert_str);
}

cDbTablesContent::cDbTablesContent() {
}

cDbTablesContent::~cDbTablesContent() {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		delete *iter;
	}
}

void cDbTablesContent::addCsvRow(const char *source) {
	bool header = false;
	bool row = false;
	string table;
	if(!strncmp(source, "csv_header:", 11)) {
		header = true;
		source += 11;
	} else if(!strncmp(source, "csv_row:", 8)) {
		row = true;
		source += 8;
	}
	if(row || header) {
		const char *tableEndSeparator = strchr(source, ':');
		if(tableEndSeparator) {
			table = string(source, tableEndSeparator - source);
			source = tableEndSeparator + 1;
			cDbTableContent *tableContent;
			map<string, cDbTableContent*>::iterator iter = tables_map.find(table);
			if(iter != tables_map.end()) {
				tableContent = iter->second;
			} else {
				tableContent = new FILE_LINE(0) cDbTableContent(table.c_str());
				tables.push_back(tableContent);
				tables_map[table] = tableContent;
				unsigned table_enum = getDbTableEnumIndex(&table);
				if(table_enum) {
					tables_enum_map[table_enum] = tableContent;
				}
			}
			if(header) {
				tableContent->addHeader(source);
			} else if(row) {
				tableContent->addRow(source);
			}
		}
	}
}

void cDbTablesContent::substCB(class cSqlDbData *dbData, list<string> *cb_inserts) {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		(*iter)->substCB(dbData, cb_inserts);
	}
}

void cDbTablesContent::substAI(class cSqlDbData *dbData, u_int64_t *ai_id) {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		(*iter)->substAI(dbData, ai_id);
	}
}

string cDbTablesContent::getMainTable() {
	if(tables.size()) {
		return(tables[0]->table_name);
	}
	return("");
}

void cDbTablesContent::insertQuery(list<string> *dst, SqlDb *sqlDb) {
	for(vector<cDbTableContent*>::iterator iter = tables.begin(); iter != tables.end(); iter++) {
		dst->push_back((*iter)->insertQuery(sqlDb));
	}
}

sDbString *cDbTablesContent::findColumn(const char *table, const char *column, unsigned rowIndex, int *columnIndex) {
	map<string, cDbTableContent*>::iterator iter = tables_map.find(table);
	if(iter != tables_map.end() && rowIndex < iter->second->rows.size()) {
		int _columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex) {
			*columnIndex = _columnIndex;
		}
		if(_columnIndex >= 0 && _columnIndex < (int)iter->second->rows[rowIndex].items->size) {
			return(&iter->second->rows[rowIndex].items->strings[_columnIndex]);
		}
	} else {
		if(columnIndex) {
			*columnIndex = -2;
		}
	}
	return(NULL);
}

sDbString *cDbTablesContent::findColumn(unsigned table_enum, const char *column, unsigned rowIndex, int *columnIndex) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end() && rowIndex < iter->second->rows.size()) {
		int _columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex) {
			*columnIndex = _columnIndex;
		}
		if(_columnIndex >= 0 && _columnIndex < (int)iter->second->rows[rowIndex].items->size) {
			return(&iter->second->rows[rowIndex].items->strings[_columnIndex]);
		}
	} else {
		if(columnIndex) {
			*columnIndex = -2;
		}
	}
	return(NULL);
}

int cDbTablesContent::getCountRows(const char *table) {
	map<string, cDbTableContent*>::iterator iter = tables_map.find(table);
	if(iter != tables_map.end()) {
		return(iter->second->rows.size());
	}
	return(-1);
}

int cDbTablesContent::getCountRows(unsigned table_enum) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end()) {
		return(iter->second->rows.size());
	}
	return(-1);
}

bool cDbTablesContent::existsColumn(unsigned table_enum, const char *column, unsigned rowIndex) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end() && rowIndex < iter->second->rows.size()) {
		int _columnIndex = iter->second->header.items->findIndex(column);
		if(_columnIndex >= 0 && _columnIndex < (int)iter->second->rows[rowIndex].items->size) {
			return(true);
		}
	}
	return(false);
}

const char *cDbTablesContent::getValue_str(unsigned table_enum, const char *column, bool *null, unsigned rowIndex, int *columnIndex) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end() && rowIndex < iter->second->rows.size()) {
		int _columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex) {
			*columnIndex = _columnIndex;
		}
		if(_columnIndex >= 0 && _columnIndex < (int)iter->second->rows[rowIndex].items->size) {
			if(null) {
				*null = iter->second->rows[rowIndex].items->strings[_columnIndex].flags & SqlDb_row::_ift_null;
			}
			return(iter->second->rows[rowIndex].items->strings[_columnIndex].str);
		} else {
			if(null) {
				*null = true;
			}
		}
	} else {
		if(columnIndex) {
			*columnIndex = -2;
		}
	}
	return(NULL);
}

double cDbTablesContent::getMinMaxValue(unsigned table_enum, const char *columns[], bool min, bool onlyNotZero, bool *null) {
	double rslt = nan("0");
	if(null) {
		*null = true;
	}
	for(unsigned i = 0; columns[i]; i++) {
		double v;
		bool v_null;
		v = getValue_float(table_enum, columns[i], false, &v_null);
		if(!v_null &&
		   (!onlyNotZero || v != 0) &&
		   (isnan(rslt) ||
		    (min ? v < rslt : v > rslt))) {
			rslt = v;
			if(null) {
				*null = false;
			}
		}
	}
	return(rslt);
}

void cDbTablesContent::removeColumn(unsigned table_enum, const char *column) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end()) {
		int columnIndex = iter->second->header.items->findIndex(column);
		if(columnIndex >= 0) {
			iter->second->header.items->strings[columnIndex].begin = NULL;
			for(unsigned i = 0; i < iter->second->rows.size(); i++) {
				iter->second->rows[i].items->strings[columnIndex].begin = NULL;
			}
		}
	}
}

void cDbTablesContent::removeColumn(unsigned table_enum, unsigned columnIndex) {
	map<unsigned, cDbTableContent*>::iterator iter = tables_enum_map.find(table_enum);
	if(iter != tables_enum_map.end()) {
		iter->second->header.items->strings[columnIndex].begin = NULL;
		for(unsigned i = 0; i < iter->second->rows.size(); i++) {
			iter->second->rows[i].items->strings[columnIndex].begin = NULL;
		}
	}
}


int getDbTableEnumIndex(string *table) {
	if(!strcasecmp(table->c_str(), "cdr")) {
		return(_t_cdr);
	} else if(!strncasecmp(table->c_str(), "cdr_next", 7)) {
		if((*table)[8] == '_') {
			int ch_index = atof(table->c_str() + 9);
			if(ch_index > 0 && ch_index <= CDR_NEXT_MAX) {
				return(_t_cdr_next + ch_index);
			}
		} else {
			return(_t_cdr_next);
		}
	}
	return(!strcasecmp(table->c_str(), "cdr_country_code") ? _t_cdr_country_code :
	       !strcasecmp(table->c_str(), "cdr_proxy") ? _t_cdr_proxy :
	       !strcasecmp(table->c_str(), "cdr_sipresp") ? _t_cdr_sipresp :
	       !strcasecmp(table->c_str(), "cdr_siphistory") ? _t_cdr_siphistory :
	       !strcasecmp(table->c_str(), "cdr_rtp") ? _t_cdr_rtp :
	       !strcasecmp(table->c_str(), "cdr_sdp") ? _t_cdr_sdp :
	       !strcasecmp(table->c_str(), "cdr_conference") ? _t_cdr_conference : 0);
}
