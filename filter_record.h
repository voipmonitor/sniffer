#ifndef FILTER_RECORD_H
#define FILTER_RECORD_H


#include "record_array.h"
#include "tools.h"


class cRecordFilterItem_base {
public:
	enum eCmpCond {
		_ge,
		_gt,
		_le,
		_lt
	};
public:
	cRecordFilterItem_base(class cRecordFilter *parent, unsigned recordFieldIndex) {
		this->parent = parent;
		this->recordFieldIndex = recordFieldIndex;
	}
	virtual ~cRecordFilterItem_base() {
	}
	virtual bool check(void *rec, bool *findInBlackList = NULL) = 0;
	void setCodebook(const char *table, const char *column);
	string getCodebookValue(u_int32_t id);
	virtual int64_t getField_int(void *rec);
	virtual vmIP getField_ip(void *rec);
	virtual double getField_float(void *rec);
	virtual const char *getField_string(void *rec);
	virtual bool getField_bool(void *rec);
public:
	cRecordFilter *parent;
	unsigned recordFieldIndex;
	string codebook_table;
	string codebook_column;
};

class cRecordFilterItem_calldate : public cRecordFilterItem_base {
public:
	cRecordFilterItem_calldate(cRecordFilter *parent, unsigned recordFieldIndex,
				   u_int32_t calldate, eCmpCond cond)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		this->calldate = calldate;
		this->cond = cond;
	}
	bool check(void *rec, bool */*findInBlackList*/ = NULL) {
		switch(cond) {
		case _ge:
			if(getField_int(rec) >= calldate) {
				return(true);
			}
			break;
		case _gt:
			if(getField_int(rec) > calldate) {
				return(true);
			}
			break;
		case _le:
			if(getField_int(rec) <= calldate) {
				return(true);
			}
			break;
		case _lt:
			if(getField_int(rec) < calldate) {
				return(true);
			}
			break;
		}
		return(false);
	}
private:
	u_int32_t calldate;
	eCmpCond cond;
};

class cRecordFilterItem_IP : public cRecordFilterItem_base {
public:
	cRecordFilterItem_IP(cRecordFilter *parent, unsigned recordFieldIndex)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
	}
	void addWhite(const char *ip) {
		ipData.addWhite(ip);
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(!ipData.checkIP(getField_ip(rec), findInBlackList)) {
			return(false);
		}
		return(true);
	}
	bool check_ip(vmIP ip, bool *findInBlackList = NULL) {
		return(ipData.checkIP(ip, findInBlackList));
	}
private:
	ListIP_wb ipData;
};

class cRecordFilterItem_CheckString : public cRecordFilterItem_base {
public:
	cRecordFilterItem_CheckString(cRecordFilter *parent, unsigned recordFieldIndex, bool enableSpaceSeparator = true)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		this->enableSpaceSeparator = enableSpaceSeparator;
	}
	void addWhite(const char *checkString) {
		checkStringData.addWhite(checkString, enableSpaceSeparator);
	}
	void addBlack(const char *checkString) {
		checkStringData.addBlack(checkString, enableSpaceSeparator);
	}
	void addWhite(const char *table, const char *column, const char * id) {
		addWhite(table, column, atol(id));
	}
	void addWhite(const char *table, const char *column, u_int32_t id) {
		setCodebook(table, column);
		checkStringData.addWhite(getCodebookValue(id).c_str(), enableSpaceSeparator);
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(!getField_string(rec) ||
		   !checkStringData.check(getField_string(rec), findInBlackList)) {
			return(false);
		}
		return(true);
	}
protected:
	ListCheckString_wb checkStringData;
	bool enableSpaceSeparator;
};

class cRecordFilterItem_bool : public cRecordFilterItem_base {
public:
	cRecordFilterItem_bool(cRecordFilter *parent, unsigned recordFieldIndex, const char *boolString)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		this->boolData = !strncasecmp(boolString, "true", 4) ||
				 !strncasecmp(boolString, "yes", 3) ||
				 atoi(boolString) > 0;
	}
	bool check(void *rec, bool */*findInBlackList*/ = NULL) {
		return(getField_bool(rec) == boolData);
	}

private:
	bool boolData;
};

class cRecordFilterItem_numInterval : public cRecordFilterItem_base {
public:
	cRecordFilterItem_numInterval(cRecordFilter *parent, unsigned recordFieldIndex,
				      double num, eCmpCond cond)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		this->num = num;
		this->cond = cond;
	}
	bool check(void *rec, bool */*findInBlackList*/ = NULL) {
		switch(cond) {
		case _ge:
			if(getField_float(rec) >= num) {
				return(true);
			}
			break;
		case _gt:
			if(getField_float(rec) > num) {
				return(true);
			}
			break;
		case _le:
			if(getField_float(rec) <= num) {
				return(true);
			}
			break;
		case _lt:
			if(getField_float(rec) < num) {
				return(true);
			}
			break;
		}
		return(false);
	}
private:
	double num;
	eCmpCond cond;
};

class cRecordFilterItem_numList : public cRecordFilterItem_base {
public:
	cRecordFilterItem_numList(cRecordFilter *parent, unsigned recordFieldIndex)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
	}
	void addNum(int64_t num, bool _not = false) {
		if(_not) {
			nums_not.push_back(num);
		} else {
			nums.push_back(num);
		}
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(nums_not.size()) {
			for(list<int64_t>::iterator iter = nums_not.begin(); iter != nums_not.end(); iter++) {
				if(*iter == getField_int(rec)) {
					if(findInBlackList) {
						*findInBlackList = true;
					}
					return(false);
				}
			}
		}
		if(nums.size()) {
			for(list<int64_t>::iterator iter = nums.begin(); iter != nums.end(); iter++) {
				if(*iter == getField_int(rec)) {
					return(true);
				}
			}
			return(false);
		}
		return(true);
	}
private:
	list<int64_t> nums;
	list<int64_t> nums_not;
};

class cRecordFilterItem_rec : public cRecordFilterItem_base {
public:
	cRecordFilterItem_rec(cRecordFilter *parent)
	 : cRecordFilterItem_base(parent, 0) {
	}
	bool check(void */*rec*/, bool */*findInBlackList*/ = NULL) {
		return(true);
	}
};

class cRecordFilterItems {
public:
	enum eCond {
		_and,
		_or
	};
public:
	cRecordFilterItems(eCond cond = _or);
	void addFilter(cRecordFilterItem_base *filter);
	void addFilter(cRecordFilterItems *group);
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(findInBlackList) {
			*findInBlackList = false;
		}
		for(list<cRecordFilterItem_base*>::iterator iter = fItems.begin(); iter != fItems.end(); iter++) {
			bool _findInBlackList = false;
			bool rsltCheck = (*iter)->check(rec, &_findInBlackList);
			if(_findInBlackList) {
				if(findInBlackList) {
					*findInBlackList = true;
				}
				return(false);
			}
			if(cond == _or) {
				if(rsltCheck) {
					return(true);
				}
			} else {
				if(!rsltCheck) {
					return(false);
				}
			}
		}
		for(list<cRecordFilterItems>::iterator iter = gItems.begin(); iter !=gItems.end(); iter++) {
			bool _findInBlackList = false;
			bool rsltCheck = (*iter).check(rec, &_findInBlackList);
			if(_findInBlackList) {
				if(findInBlackList) {
					*findInBlackList = true;
				}
				return(false);
			}
			if(cond == _or) {
				if(rsltCheck) {
					return(true);
				}
			} else {
				if(!rsltCheck) {
					return(false);
				}
			}
		}
		return(cond == _or ? false : true);
	}
	void free();
	bool isSet() {
		return(fItems.size() > 0 || gItems.size() > 0);
	}
public:
	eCond cond;
	list<cRecordFilterItem_base*> fItems;
	list<cRecordFilterItems> gItems;
};

class cRecordFilter {
public:
	enum eCond {
		_and,
		_or
	};
public:
	cRecordFilter(eCond cond = _and, bool useRecordArray = true);
	virtual ~cRecordFilter();
	void setCond(eCond cond);
	void setUseRecordArray(bool useRecordArray);
	void addFilter(cRecordFilterItem_base *filter1, cRecordFilterItem_base *filter2 = NULL, cRecordFilterItem_base *filter3 = NULL);
	void addFilter(cRecordFilterItems *group);
	bool check(void *rec) {
		for(list<cRecordFilterItems>::iterator iter = gItems.begin(); iter !=gItems.end(); iter++) {
			bool _findInBlackList = false;
			bool rsltCheck = iter->check(rec, &_findInBlackList);
			if(_findInBlackList) {
				return(false);
			}
			if(cond == _or) {
				if(rsltCheck) {
					return(true);
				}
			} else {
				if(!rsltCheck) {
					return(false);
				}
			}
		}
		return(cond == _or ? false : true);
	}
	virtual int64_t getField_int(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_int() :
			0);
	}
	virtual vmIP getField_ip(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_ip() :
			0);
	}
	virtual int64_t getField_float(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_float() :
			getField_int(rec, recordFieldIndex));
	}
	virtual const char *getField_string(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_string() :
			"");
	}
	virtual bool getField_bool(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_bool() :
			0);
	}
public:
	eCond cond;
	bool useRecordArray;
	list<cRecordFilterItems> gItems;
};

int64_t cRecordFilterItem_base::getField_int(void *rec) {
	return(parent->getField_int(rec, recordFieldIndex));
}
vmIP cRecordFilterItem_base::getField_ip(void *rec) {
	return(parent->getField_ip(rec, recordFieldIndex));
}
double cRecordFilterItem_base::getField_float(void *rec) {
	return(parent->getField_float(rec, recordFieldIndex));
}
bool cRecordFilterItem_base::getField_bool(void *rec) {
	return(parent->getField_bool(rec, recordFieldIndex));
}
const char *cRecordFilterItem_base::getField_string(void *rec) {
	return(parent->getField_string(rec, recordFieldIndex));
}


#endif
