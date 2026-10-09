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
	virtual void checkWhiteBlack(void *rec, bool *white, bool *black) {
		*black = false;
		*white = check(rec, black);
	}
	virtual bool whiteIsEmpty() {
		return(false);
	}
	virtual void setNoLock() {
	}
	void setCodebook(const char *table, const char *column);
	string getCodebookValue(u_int32_t id);
	virtual int64_t getField_int(void *rec);
	virtual vmIP getField_ip(void *rec);
	virtual double getField_float(void *rec, bool *null = NULL);
	virtual string getField_string(void *rec);
	virtual bool getField_bool(void *rec);
	virtual vmPort getField_port(void *rec);
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
		ipData.setSkipInvalid();
	}
	void addWhite(const char *ip) {
		ipData.addWhite(ip, false);
	}
	void addBlack(const char *ip) {
		ipData.addBlack(ip, false);
	}
	void addWhite(const char *table, const char *column, const char * idstr) {
		vector<string> ids = split(idstr, ',');
		for(unsigned i = 0; i < ids.size(); i++) {
			addWhite(table, column, atol(ids[i].c_str()));
		}
	}
	void addWhite(const char *table, const char *column, u_int32_t id) {
		setCodebook(table, column);
		ipData.addWhite(getCodebookValue(id).c_str(), false);
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
	void checkWhiteBlack(void *rec, bool *white, bool *black) {
		checkWhiteBlack_ip(getField_ip(rec), white, black);
	}
	void checkWhiteBlack_ip(vmIP ip, bool *white, bool *black) {
		*white = ipData.checkWhite(ip);
		*black = ipData.checkBlack(ip);
	}
	bool whiteIsEmpty() {
		return(ipData.whiteIsEmpty());
	}
	void setNoLock() {
		ipData.setNoLock();
	}
private:
	ListIP_wb ipData;
};

class cRecordFilterItem_PhoneNumber : public cRecordFilterItem_base {
public:
	cRecordFilterItem_PhoneNumber(cRecordFilter *parent, unsigned recordFieldIndex)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		enableNull = false;
	}
	void setEnableNull() {
		enableNull = true;
	}
	void addWhite(const char *number, PhoneNumber::eTypeNumber type) {
		phoneNumberData.addWhite(number, type, enableNull, true);
	}
	void addWhite(const char *table, const char *column, const char * idstr, PhoneNumber::eTypeNumber type) {
		vector<string> ids = split(idstr, ',');
		for(unsigned i = 0; i < ids.size(); i++) {
			addWhite(table, column, atol(ids[i].c_str()), type);
		}
	}
	void addWhite(const char *table, const char *column, u_int32_t id, PhoneNumber::eTypeNumber type) {
		setCodebook(table, column);
		phoneNumberData.addWhite(getCodebookValue(id).c_str(), type, enableNull, true);
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(!phoneNumberData.checkNumber(getField_string(rec).c_str(), findInBlackList)) {
			return(false);
		}
		return(true);
	}
	void checkWhiteBlack(void *rec, bool *white, bool *black) {
		string number = getField_string(rec);
		*white = phoneNumberData.checkWhite(number.c_str());
		*black = phoneNumberData.checkBlack(number.c_str());
	}
	bool whiteIsEmpty() {
		return(phoneNumberData.whiteIsEmpty());
	}
	void setNoLock() {
		phoneNumberData.setNoLock();
	}
protected:
	ListPhoneNumber_wb phoneNumberData;
	bool enableNull;
};

class cRecordFilterItem_CheckString : public cRecordFilterItem_base {
public:
	cRecordFilterItem_CheckString(cRecordFilter *parent, unsigned recordFieldIndex, bool enableSpaceSeparator = true)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		this->enableSpaceSeparator = enableSpaceSeparator;
		separators = NULL;
		separatorsSeparator = NULL;
		enableNoSplitBorders = true;
		enableNull = false;
		enableInterval = true;
		emptyAsNull = false;
	}
	void setSeparators(const char *separators, const char *separatorsSeparator) {
		this->separators = separators;
		this->separatorsSeparator = separatorsSeparator;
	}
	void setEnableNull() {
		enableNull = true;
	}
	void setDisableInterval() {
		enableInterval = false;
	}
	void setEmptyAsNull() {
		emptyAsNull = true;
	}
	void addWhite(const char *checkString) {
		checkStringData.addWhite(checkString, enableSpaceSeparator, separators, separatorsSeparator, enableNoSplitBorders, enableNull, enableInterval);
	}
	void addBlack(const char *checkString) {
		checkStringData.addBlack(checkString, enableSpaceSeparator, separators, separatorsSeparator, enableNoSplitBorders, enableNull, enableInterval);
	}
	void addWhite(const char *table, const char *column, const char * idstr) {
		vector<string> ids = split(idstr, ',');
		for(unsigned i = 0; i < ids.size(); i++) {
			addWhite(table, column, atol(ids[i].c_str()));
		}
	}
	void addWhite(const char *table, const char *column, u_int32_t id) {
		setCodebook(table, column);
		checkStringData.addWhite(getCodebookValue(id).c_str(), enableSpaceSeparator, separators, separatorsSeparator, enableNoSplitBorders, enableNull, enableInterval);
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		string checkString = getField_string(rec);
		if(emptyAsNull && checkString.empty()) {
			if(findInBlackList) {
				*findInBlackList = false;
			}
			return(checkStringData.whiteIsEmpty());
		}
		if(!checkStringData.check(checkString.c_str(), findInBlackList)) {
			return(false);
		}
		return(true);
	}
	void checkWhiteBlack(void *rec, bool *white, bool *black) {
		string checkString = getField_string(rec);
		bool null = emptyAsNull && checkString.empty();
		*white = !null && checkStringData.checkWhite(checkString.c_str());
		*black = !null && checkStringData.checkBlack(checkString.c_str());
	}
	bool whiteIsEmpty() {
		return(checkStringData.whiteIsEmpty());
	}
	void setNoLock() {
		checkStringData.setNoLock();
	}
protected:
	ListCheckString_wb checkStringData;
	bool enableSpaceSeparator;
	const char *separators;
	const char *separatorsSeparator;
	bool enableNoSplitBorders;
	bool enableNull;
	bool enableInterval;
	bool emptyAsNull;
};

class cRecordFilterItem_Port : public cRecordFilterItem_base {
public:
	cRecordFilterItem_Port(cRecordFilter *parent, unsigned recordFieldIndex, int port)
	 : cRecordFilterItem_base(parent, recordFieldIndex) {
		this->portData = port;
	}
	bool check(void *rec, bool */*findInBlackList*/ = NULL) {
		return(getField_port(rec).getPort() == portData);
	}

private:
	int portData;
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
		bool null;
		double value = getField_float(rec, &null);
		if(null) {
			return(false);
		}
		switch(cond) {
		case _ge:
			return(value >= num);
		case _gt:
			return(value > num);
		case _le:
			return(value <= num);
		case _lt:
			return(value < num);
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
	void addNumComb(const char *numStr) {
		vector<string> elems = split_filter(numStr, " |,|;|\t|\r|\n", "|");
		for(size_t i = 0; i < elems.size(); i++) {
			if(!elems[i].empty() && elems[i][0] == '!') {
				nums_not.push_back(atof_mysql(elems[i].substr(1).c_str()));
			} else {
				nums.push_back(atof_mysql(elems[i].c_str()));
			}
		}
	}
	bool check(void *rec, bool *findInBlackList = NULL) {
		if(nums_not.size()) {
			for(list<double>::iterator iter = nums_not.begin(); iter != nums_not.end(); iter++) {
				if(*iter == getField_int(rec)) {
					if(findInBlackList) {
						*findInBlackList = true;
					}
					return(false);
				}
			}
		}
		if(nums.size()) {
			for(list<double>::iterator iter = nums.begin(); iter != nums.end(); iter++) {
				if(*iter == getField_int(rec)) {
					return(true);
				}
			}
			return(false);
		}
		return(true);
	}
private:
	list<double> nums;
	list<double> nums_not;
};

class cRecordFilterItem_rec : public cRecordFilterItem_base {
public:
	cRecordFilterItem_rec(cRecordFilter *parent)
	 : cRecordFilterItem_base(parent, 0) {
	}
	bool check(void */*rec*/, bool */*findInBlackList*/ = NULL) {
		return(true);
	}
protected:
	bool isNumber(const char *str) {
		if(!str[0] || (str[0] == '0' && str[1])) {
			return(false);
		}
		for(unsigned i = 0; str[i]; i++) {
			if(!isdigit(str[i])) {
				return(false);
			}
		}
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
	void addFilter(cRecordFilterItem_base *filter1, cRecordFilterItem_base *filter2 = NULL, cRecordFilterItem_base *filter3 = NULL);
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
	void setNoLock() {
		for(list<cRecordFilterItem_base*>::iterator iter = fItems.begin(); iter != fItems.end(); iter++) {
			(*iter)->setNoLock();
		}
		for(list<cRecordFilterItems>::iterator iter = gItems.begin(); iter != gItems.end(); iter++) {
			iter->setNoLock();
		}
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
		for(list<cRecordFilterItems>::iterator iter = gItems.begin(); iter != gItems.end(); iter++) {
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
	void setNoLock() {
		for(list<cRecordFilterItems>::iterator iter = gItems.begin(); iter != gItems.end(); iter++) {
			iter->setNoLock();
		}
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
	virtual double getField_float(void *rec, unsigned recordFieldIndex, bool *null = NULL) {
		if(null) {
			*null = false;
		}
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_float() :
			getField_int(rec, recordFieldIndex));
	}
	virtual string getField_string(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_string() :
			"");
	}
	virtual bool getField_bool(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_bool() :
			0);
	}
	virtual vmPort getField_port(void *rec, unsigned recordFieldIndex) {
		return(useRecordArray ?
			((RecordArray*)rec)->fields[recordFieldIndex].get_port() :
			vmPort(0));
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
double cRecordFilterItem_base::getField_float(void *rec, bool *null) {
	return(parent->getField_float(rec, recordFieldIndex, null));
}
vmPort cRecordFilterItem_base::getField_port(void *rec) {
	return(parent->getField_port(rec, recordFieldIndex));
}
bool cRecordFilterItem_base::getField_bool(void *rec) {
	return(parent->getField_bool(rec, recordFieldIndex));
}
string cRecordFilterItem_base::getField_string(void *rec) {
	return(parent->getField_string(rec, recordFieldIndex));
}


#endif
