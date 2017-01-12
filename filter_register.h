#ifndef FILTER_REGISTER_H
#define FILTER_REGISTER_H


#include "record_array.h"
#include "tools.h"


class cRegisterFilterItem_base {
public:
	cRegisterFilterItem_base(class cRegisterFilter *parent, unsigned registerFieldIndex) {
		this->parent = parent;
		this->registerFieldIndex = registerFieldIndex;
	}
	virtual ~cRegisterFilterItem_base() {
	}
	virtual bool check(void *rec, bool *findInBlackList = NULL) = 0;
	void setCodebook(const char *table, const char *column);
	string getCodebookValue(u_int32_t id);
	virtual u_int64_t getField_int(void *rec);
	virtual const char *getField_string(void *rec);
public:
	cRegisterFilter *parent;
	unsigned registerFieldIndex;
	string codebook_table;
	string codebook_column;
};

class cRegisterFilterItem_calldate : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_calldate(cRegisterFilter *parent, unsigned registerFieldIndex,
				     u_int32_t calldate, bool from = true)
	 : cRegisterFilterItem_base(parent, registerFieldIndex) {
		this->calldate = calldate;
		this->from = from;
	}
	bool check(void *rec, bool */*findInBlackList*/ = NULL) {
		if((from && getField_int(rec) < calldate) ||
		   (!from && getField_int(rec) >= calldate)) {
			return(false);
		}
		return(true);
	}
private:
	u_int32_t calldate;
	bool from;
};

class cRegisterFilterItem_IP : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_IP(cRegisterFilter *parent, unsigned registerFieldIndex)
	 : cRegisterFilterItem_base(parent, registerFieldIndex) {
	}
	void addWhite(const char *ip) {
		ipData.addWhite(ip);
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(!ipData.checkIP(getField_int(rec), findInBlackList)) {
			return(false);
		}
		return(true);
	}
private:
	ListIP_wb ipData;
};

class cRegisterFilterItem_CheckString : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_CheckString(cRegisterFilter *parent, unsigned registerFieldIndex)
	 : cRegisterFilterItem_base(parent, registerFieldIndex) {
	}
	void addWhite(const char *checkString) {
		checkStringData.addWhite(checkString);
	}
	void addWhite(const char *table, const char *column, const char * id) {
		addWhite(table, column, atol(id));
	}
	void addWhite(const char *table, const char *column, u_int32_t id) {
		setCodebook(table, column);
		checkStringData.addWhite(getCodebookValue(id).c_str());
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(!getField_string(rec) ||
		   !checkStringData.check(getField_string(rec), findInBlackList)) {
			return(false);
		}
		return(true);
	}
private:
	ListCheckString_wb checkStringData;
};

class cRegisterFilterItem_numInterval : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_numInterval(cRegisterFilter *parent, unsigned registerFieldIndex,
					double num, bool from = true)
	 : cRegisterFilterItem_base(parent, registerFieldIndex) {
		this->num = num;
		this->from = from;
	}
	bool check(void *rec, bool */*findInBlackList*/ = NULL) {
		if((from && getField_int(rec) < num) ||
		   (!from && getField_int(rec) >= num)) {
			return(false);
		}
		return(true);
	}
private:
	double num;
	bool from;
};

class cRegisterFilterItem_numList : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_numList(cRegisterFilter *parent, unsigned registerFieldIndex)
	 : cRegisterFilterItem_base(parent, registerFieldIndex) {
	}
	void addNum(u_int64_t num) {
		nums.push_back(num);
	}
	bool check(void *rec, bool */*findInBlackList*/ = NULL) {
		if(nums.size()) {
			for(list<u_int64_t>::iterator iter = nums.begin(); iter != nums.end(); iter++) {
				if(*iter == getField_int(rec)) {
					return(true);
				}
			}
			return(false);
		}
		return(true);
	}
private:
	list<u_int64_t> nums;
};

class cRegisterFilterItems {
public:
	void addFilter(cRegisterFilterItem_base *filter);
	bool check(void *rec) {
		list<cRegisterFilterItem_base*>::iterator iter;
		for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
			bool findInBlackList = false;
			if((*iter)->check(rec, &findInBlackList)) {
				return(true);
			}
			if(findInBlackList) {
				return(false);
			}
		}
		return(false);
	}
	void free();
public:
	list<cRegisterFilterItem_base*> fItems;
};

class cRegisterFilter {
public:
	cRegisterFilter(const char *filter);
	virtual ~cRegisterFilter();
	void addFilter(cRegisterFilterItem_base *filter1, cRegisterFilterItem_base *filter2 = NULL, cRegisterFilterItem_base *filter3 = NULL);
	bool check(void *rec) {
		list<cRegisterFilterItems>::iterator iter;
		for(iter = fItems.begin(); iter !=fItems.end(); iter++) {
			if(!iter->check(rec)) {
				return(false);
			}
		}
		return(true);
	}
	virtual u_int64_t getField_int(void *rec, unsigned registerFieldIndex) {
		return(((RecordArray*)rec)->fields[registerFieldIndex].i);
	}
	virtual const char *getField_string(void *rec, unsigned registerFieldIndex) {
		return(((RecordArray*)rec)->fields[registerFieldIndex].s);
	}
public:
	list<cRegisterFilterItems> fItems;
};

u_int64_t cRegisterFilterItem_base::getField_int(void *rec) {
	return(parent->getField_int(rec, registerFieldIndex));
}
const char *cRegisterFilterItem_base::getField_string(void *rec) {
	return(parent->getField_string(rec, registerFieldIndex));
}


#endif
