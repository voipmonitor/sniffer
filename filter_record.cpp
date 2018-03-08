#include "filter_record.h"
#include "sql_db.h"


void cRecordFilterItem_base::setCodebook(const char *table, const char *column) {
	codebook_table = table;
	codebook_column = column;
}

string cRecordFilterItem_base::getCodebookValue(u_int32_t id) {
	/*
	if(opt_nocdr) {
		return("");
	}
	*/
	SqlDb *sqlDb = createSqlObject();
	sqlDb->query("select " + codebook_column + " as value from " + codebook_table + " where id = " + intToString(id));
	SqlDb_row row = sqlDb->fetchRow();
	string rslt;
	if(row) {
		rslt = row["value"];
	}
	delete sqlDb;
	return(rslt);
}

cRecordFilterItems::cRecordFilterItems(eCond cond) {
	this->cond = cond;
}

void cRecordFilterItems::addFilter(cRecordFilterItem_base *filter) {
	fItems.push_back(filter);
}

void cRecordFilterItems::addFilter(cRecordFilterItems *group) {
	gItems.push_back(*group);
}

void cRecordFilterItems::free() {
	for(list<cRecordFilterItem_base*>::iterator iter = fItems.begin(); iter !=fItems.end(); iter++) {
		delete *iter;
	}
	for(list<cRecordFilterItems>::iterator iter = gItems.begin(); iter !=gItems.end(); iter++) {
		iter->free();
	}
}

cRecordFilter::cRecordFilter(eCond cond, bool useRecordArray) {
	this->cond = cond;
	this->useRecordArray = useRecordArray;
}

cRecordFilter::~cRecordFilter() {
	for(list<cRecordFilterItems>::iterator iter = gItems.begin(); iter != gItems.end(); iter++) {
		iter->free();
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
}

void cRecordFilter::addFilter(cRecordFilterItems *group) {
	gItems.push_back(*group);
}

