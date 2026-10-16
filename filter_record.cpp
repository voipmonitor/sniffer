#include "filter_record.h"
#include "sql_db.h"


string cCodebookCache::sColumn::get(u_int32_t id, bool *found) {
	map<u_int32_t, string>::iterator iter = values.find(id);
	if(found) {
		*found = iter != values.end();
	}
	return(iter != values.end() ? iter->second : "");
}

void cCodebookCache::sColumn::getList(vector<string> *values) {
	values->clear();
	for(map<u_int32_t, string>::iterator iter = this->values.begin(); iter != this->values.end(); iter++) {
		values->push_back(iter->second);
	}
}

string cCodebookCache::columnKey(const char *column, const char *condition) {
	return(condition && *condition ? string(column) + ":" + condition : column);
}

cCodebookCache::sColumn *cCodebookCache::findColumn(const char *table, const string &key) {
	map<string, sTable>::iterator iterTable = tables.find(table);
	if(iterTable == tables.end()) {
		return(NULL);
	}
	map<string, sColumn>::iterator iterColumn = iterTable->second.columns.find(key);
	return(iterColumn != iterTable->second.columns.end() ? &iterColumn->second : NULL);
}

cCodebookCache::sColumn *cCodebookCache::initColumn(const char *table, const char *column, const char *condition) {
	sColumn *columnData = &tables[table].columns[columnKey(column, condition)];
	if(columnData->column.empty()) {
		columnData->column = column;
		if(condition) {
			columnData->condition = condition;
		}
	}
	return(columnData);
}

string cCodebookCache::getValue(const char *table, const char *column, u_int32_t id, bool *loaded, bool *found) {
	if(found) {
		*found = false;
	}
	lock();
	sColumn *columnData = findColumn(table, column);
	*loaded = columnData && columnData->loaded;
	string rslt = *loaded ? columnData->get(id, found) : "";
	unlock();
	return(rslt);
}

bool cCodebookCache::getListValues(const char *table, const char *column, const char *condition, vector<string> *values, bool *loaded) {
	lock();
	sColumn *columnData = findColumn(table, columnKey(column, condition));
	*loaded = columnData && columnData->loaded;
	if(*loaded) {
		columnData->getList(values);
	}
	unlock();
	return(*loaded);
}

bool cCodebookCache::isLoaded(const char *table, const char *column, const char *condition) {
	lock();
	sColumn *columnData = findColumn(table, columnKey(column, condition));
	bool rslt = columnData && columnData->loaded;
	unlock();
	return(rslt);
}

bool cCodebookCache::loadQuery(const string &query, bool key_by_id, const char **columns, unsigned columns_count, vector<map<u_int32_t, string> > *values, bool singlePass, SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	unsigned int maxQueryPassOld = sqlDb->getMaxQueryPass();
	if(singlePass) {
		sqlDb->setMaxQueryPass(1);
	}
	values->clear();
	values->resize(columns_count);
	bool rslt = false;
	if(sqlDb->query(query)) {
		sqlDb->clearLastError();
		SqlDb_row row;
		unsigned index = 0;
		while((row = sqlDb->fetchRow())) {
			u_int32_t key = key_by_id ? atol(row["id"].c_str()) : index++;
			for(unsigned i = 0; i < columns_count; i++) {
				(*values)[i][key] = row[columns[i]];
			}
		}
		rslt = !sqlDb->isError();
	}
	if(singlePass) {
		sqlDb->setMaxQueryPass(maxQueryPassOld);
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
	return(rslt);
}

bool cCodebookCache::loadValues(const char *table, const char *column, const char *condition, map<u_int32_t, string> *values, bool singlePass, SqlDb *sqlDb) {
	bool is_list = condition && *condition;
	vector<map<u_int32_t, string> > values_columns;
	if(!loadQuery(is_list ?
		       string("select ") + column + " from " + table + " where " + condition :
		       string("select id, ") + column + " from " + table,
		      !is_list, &column, 1, &values_columns, singlePass, sqlDb)) {
		return(false);
	}
	values->swap(values_columns[0]);
	return(true);
}

bool cCodebookCache::getValues(cCodebookCache *cache, const char *table, const char *column, vector<int> *ids, map<u_int32_t, string> *values) {
	vector<map<u_int32_t, string> > values_columns;
	if(!getValues(cache, table, &column, 1, ids, &values_columns)) {
		return(false);
	}
	values->swap(values_columns[0]);
	return(true);
}

bool cCodebookCache::getValues(cCodebookCache *cache, const char *table, const char **columns, unsigned columns_count, vector<int> *ids, vector<map<u_int32_t, string> > *values) {
	values->clear();
	values->resize(columns_count);
	if(cache) {
		for(unsigned i = 0; i < columns_count; i++) {
			for(unsigned j = 0; j < ids->size(); j++) {
				bool found;
				string value = cache->get(table, columns[i], (*ids)[j], &found);
				if(found) {
					(*values)[i][(*ids)[j]] = value;
				}
			}
		}
		return(true);
	}
	if(!ids->size()) {
		return(true);
	}
	string ids_str;
	for(unsigned i = 0; i < ids->size(); i++) {
		ids_str += (ids_str.empty() ? "" : ",") + intToString((*ids)[i]);
	}
	string columns_str;
	for(unsigned i = 0; i < columns_count; i++) {
		columns_str += string(", ") + columns[i];
	}
	return(loadQuery(string("select id") + columns_str + " from " + table + " where id in (" + ids_str + ")",
			 true, columns, columns_count, values, false, NULL));
}

bool cCodebookCache::loadList(const char *table, const char *column, const char *condition, vector<string> *values) {
	map<u_int32_t, string> values_map;
	if(!loadValues(table, column, condition, &values_map, false)) {
		return(false);
	}
	values->clear();
	for(map<u_int32_t, string>::iterator iter = values_map.begin(); iter != values_map.end(); iter++) {
		values->push_back(iter->second);
	}
	return(true);
}

void cCodebookCache::setValues(const char *table, const char *column, const char *condition, map<u_int32_t, string> *values) {
	lock();
	sColumn *columnData = initColumn(table, column, condition);
	columnData->values.swap(*values);
	columnData->loaded = true;
	unlock();
}

string cCodebookCache::get(const char *table, const char *column, u_int32_t id, bool *found) {
	bool loaded;
	string rslt = getValue(table, column, id, &loaded, found);
	if(loaded) {
		return(rslt);
	}
	lock_load();
	if(!isLoaded(table, column, NULL)) {
		map<u_int32_t, string> values;
		if(loadValues(table, column, NULL, &values, true)) {
			setValues(table, column, NULL, &values);
		}
	}
	unlock_load();
	return(getValue(table, column, id, &loaded, found));
}

bool cCodebookCache::getList(const char *table, const char *column, const char *condition, vector<string> *values) {
	bool loaded;
	if(getListValues(table, column, condition, values, &loaded)) {
		return(true);
	}
	lock_load();
	if(!isLoaded(table, column, condition)) {
		map<u_int32_t, string> values_map;
		if(loadValues(table, column, condition, &values_map, true)) {
			setValues(table, column, condition, &values_map);
		}
	}
	unlock_load();
	return(getListValues(table, column, condition, values, &loaded));
}

void cCodebookCache::reload(bool singlePass, SqlDb *sqlDb) {
	static const char *codebooks[][3] = {
		{ "cb_ip_groups", "ip", NULL },
		{ "cb_number_groups", "number", NULL },
		{ "cb_domain_groups", "domain", NULL },
		{ "cb_ua_groups", "ua", NULL },
		{ "cb_ip_groups", "ip", "trunk" },
		{ "cb_domain_groups", "side", NULL },
		{ "sensors", "id_sensor", NULL },
		{ "cb_custhead_cdr_groups", "cdr_custom_headers_id", NULL },
		{ "cb_custhead_cdr_groups", "content", NULL }
	};
	vector<sName> names;
	lock();
	for(unsigned i = 0; i < sizeof(codebooks) / sizeof(codebooks[0]); i++) {
		initColumn(codebooks[i][0], codebooks[i][1], codebooks[i][2]);
	}
	for(map<string, sTable>::iterator iterTable = tables.begin(); iterTable != tables.end(); iterTable++) {
		for(map<string, sColumn>::iterator iterColumn = iterTable->second.columns.begin(); iterColumn != iterTable->second.columns.end(); iterColumn++) {
			sName name;
			name.table = iterTable->first;
			name.column = iterColumn->second.column;
			name.condition = iterColumn->second.condition;
			names.push_back(name);
		}
	}
	unlock();
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	lock_load();
	for(unsigned i = 0; i < names.size(); i++) {
		map<u_int32_t, string> values;
		if(loadValues(names[i].table.c_str(), names[i].column.c_str(), names[i].condition.c_str(), &values, singlePass, sqlDb)) {
			setValues(names[i].table.c_str(), names[i].column.c_str(), names[i].condition.c_str(), &values);
		}
	}
	unlock_load();
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cRecordFilterItem_base::getCodebookValues(const char *table, const char *column, const char *idstr, vector<string> *values) {
	vector<int> ids = split2int(idstr, ',');
	map<u_int32_t, string> values_map;
	cCodebookCache::getValues(parent ? parent->getCodebookCache() : NULL, table, column, &ids, &values_map);
	values->clear();
	for(unsigned i = 0; i < ids.size(); i++) {
		map<u_int32_t, string>::iterator iter = values_map.find(ids[i]);
		values->push_back(iter != values_map.end() ? iter->second : "");
	}
}

cRecordFilterItems::cRecordFilterItems(eCond cond) {
	this->cond = cond;
}

void cRecordFilterItems::addFilter(cRecordFilterItem_base *filter1, cRecordFilterItem_base *filter2, cRecordFilterItem_base *filter3) {
	if(!filter2 && !filter3) {
		fItems.push_back(filter1);
	} else {
		cRecordFilterItems fSubItems;
		fSubItems.addFilter(filter1);
		if(filter2) {
			fSubItems.addFilter(filter2);
		}
		if(filter3) {
			fSubItems.addFilter(filter3);
		}
		gItems.push_back(fSubItems);
	}
}

void cRecordFilterItems::addFilter(cRecordFilterItems *group) {
	while(!group->fItems.size() && group->gItems.size() == 1) {
		group = &group->gItems.front();
	}
	if(group->fItems.size() == 1 && !group->gItems.size()) {
		fItems.push_back(group->fItems.front());
		return;
	}
	gItems.push_back(*group);
}

void cRecordFilterItems::free() {
	for(unsigned i = 0; i < fItems.size(); i++) {
		delete fItems[i];
	}
	for(unsigned i = 0; i < gItems.size(); i++) {
		gItems[i].free();
	}
}

cRecordFilter::cRecordFilter(eCond cond, bool useRecordArray) {
	this->cond = cond;
	this->useRecordArray = useRecordArray;
	this->single_item = NULL;
	this->codebookCache = NULL;
}

cRecordFilter::~cRecordFilter() {
	for(unsigned i = 0; i < gItems.size(); i++) {
		gItems[i].free();
	}
}

void cRecordFilter::setCond(eCond cond) {
	this->cond = cond;
}

void cRecordFilter::setUseRecordArray(bool useRecordArray) {
	this->useRecordArray = useRecordArray;
}

void cRecordFilter::addFilter(cRecordFilterItem_base *filter1, cRecordFilterItem_base *filter2, cRecordFilterItem_base *filter3) {
	cRecordFilterItems fSubItems;
	fSubItems.addFilter(filter1);
	if(filter2) {
		fSubItems.addFilter(filter2);
	}
	if(filter3) {
		fSubItems.addFilter(filter3);
	}
	gItems.push_back(fSubItems);
	updateSingleItem();
}

void cRecordFilter::addFilter(cRecordFilterItems *group) {
	while(!group->fItems.size() && group->gItems.size() == 1) {
		group = &group->gItems.front();
	}
	gItems.push_back(*group);
	updateSingleItem();
}

void cRecordFilter::updateSingleItem() {
	single_item = gItems.size() == 1 && !gItems.front().gItems.size() && gItems.front().fItems.size() == 1 ?
		       gItems.front().fItems.front() :
		       NULL;
}

