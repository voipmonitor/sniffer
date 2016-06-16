#ifndef REGISTER_H
#define REGISTER_H


#include <string>
#include <vector>
#include <string.h>

#include "calltable.h"


#define NEW_REGISTER_MAX_STATES 3


using namespace std;


enum eRegisterState {
	rs_na = 0,
	rs_OK = 1,
	rs_Failed = 2,
	rs_UnknownMessageOK = 3,
	rs_ManyRegMessages = 4,
	rs_Expired = 5,
	rs_Unregister = 6
};

enum eRegisterField {
	rf_id = 0,
	rf_id_sensor,
	rf_fname,
	rf_calldate,
	rf_sipcallerip,
	rf_sipcalledip,
	rf_from_num,
	rf_from_name,
	rf_from_domain,
	rf_to_num,
	rf_to_domain,
	rf_contact_num,
	rf_contact_domain,
	rf_digestusername,
	rf_digestrealm,
	rf_expires,
	rf_expires_at,
	rf_state,
	rf_ua,
	rf_rrd_avg,
	rf__max
};


class RegisterId {
public:
	inline RegisterId(class Register *reg = NULL);
	inline bool operator == (const RegisterId& other) const;
	inline bool operator < (const RegisterId& other) const;
public:
	class Register *reg;
};


class RegisterState {
public:
	inline RegisterState(Call *call, Register *reg);
	inline ~RegisterState();
	inline void copyFrom(const RegisterState *src);
	inline bool isEq(Call *call, Register *reg);
public:
	u_int32_t state_from;
	u_int32_t state_to;
	u_int32_t counter;
	eRegisterState state;
	char *from_num;
	char *from_name;
	char *from_domain;
	char *digest_realm;
	char *ua;
	u_int64_t fname;
	u_int32_t expires;
	int id_sensor;
	u_int64_t db_id;
	u_int32_t save_at;
	u_int32_t save_at_counter;
};


class Register {
public:
	inline Register(Call *call);
	inline ~Register();
	inline void addState(Call *call);
	inline void shiftStates();
	inline void expire(bool need_lock_states = true);
	inline void updateLastState(Call *call);
	inline bool eqLastState(Call *call);
	inline void clean_all();
	inline void saveStateToDb(RegisterState *state, bool enableBatchIfPossible = true);
	inline void saveFailedToDb(RegisterState *state, bool force = false, bool enableBatchIfPossible = true);
	inline eRegisterState getState();
	inline RegisterState *states_last() {
		return(countStates ? states[0] : NULL);
	}
	inline RegisterState *states_prev_last() {
		return(countStates > 1 ? states[1] : NULL);
	}
	inline bool getDataRow(struct RegisterRecord *rec);
	void lock_states() {
		while(__sync_lock_test_and_set(&_sync_states, 1));
	}
	void unlock_states() {
		__sync_lock_release(&_sync_states);
	}
	void lock_id() {
		while(__sync_lock_test_and_set(&_sync_id, 1));
	}
	void unlock_id() {
		__sync_lock_release(&_sync_id);
	}
public:
	u_int64_t id;
	u_int32_t sipcallerip;
	u_int32_t sipcalledip;
	char *to_num;
	char *to_domain;
	char *contact_num;
	char *contact_domain;
	char *digest_username;
	char *from_num;
	char *from_name;
	char *from_domain;
	char *digest_realm;
	char *ua;
	RegisterState *states[NEW_REGISTER_MAX_STATES];
	u_int16_t countStates;
	u_int64_t rrd_sum;
	u_int32_t rrd_count;
	volatile int _sync_states;
	static volatile u_int64_t _id;
	static volatile int _sync_id;
};


class Registers {
public: 
	Registers();
	~Registers();
	void add(Call *call);
	void cleanup(u_int32_t act_time);
	void clean_all();
	inline u_int64_t getNewRegisterFailedId(int sensorId);
	string getDataTableJson(eRegisterState *states, u_int32_t limit, eRegisterField sortBy, bool desc = false, char *filter = NULL);
	void lock_registers() {
		while(__sync_lock_test_and_set(&_sync_registers, 1));
	}
	void unlock_registers() {
		__sync_lock_release(&_sync_registers);
	}
	void lock_registers_erase() {
		while(__sync_lock_test_and_set(&_sync_registers_erase, 1));
	}
	void unlock_registers_erase() {
		__sync_lock_release(&_sync_registers_erase);
	}
	void lock_register_failed_id() {
		while(__sync_lock_test_and_set(&_sync_register_failed_id, 1));
	}
	void unlock_register_failed_id() {
		__sync_lock_release(&_sync_register_failed_id);
	}
public:
	map<RegisterId, Register*> registers;
	volatile int _sync_registers;
	volatile int _sync_registers_erase;
	map<int, u_int64_t> register_failed_id;
	volatile int _sync_register_failed_id;
	u_int32_t last_cleanup_time;
};


class cRegisterFilterItem_base {
public:
	cRegisterFilterItem_base(eRegisterField registerField) {
		this->registerField = registerField;
	}
	virtual ~cRegisterFilterItem_base() {
	}
	virtual bool check(struct RegisterRecord *rec) = 0;
	void setCodebook(const char *table, const char *column);
	string getCodebookValue(u_int32_t id);
public:
	eRegisterField registerField;
	string codebook_table;
	string codebook_column;
};

class cRegisterFilterItem_calldate : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_calldate(eRegisterField registerField,
				     u_int32_t calldate, bool from = true)
	 : cRegisterFilterItem_base(registerField) {
		this->calldate = calldate;
		this->from = from;
	}
	bool check(struct RegisterRecord *rec);
private:
	u_int32_t calldate;
	bool from;
};

class cRegisterFilterItem_IP : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_IP(eRegisterField registerField)
	 : cRegisterFilterItem_base(registerField) {
	}
	void addWhite(const char *ip) {
		ipData.addWhite(ip);
	}
	bool check(struct RegisterRecord *rec);
private:
	ListIP_wb ipData;
};

class cRegisterFilterItem_CheckString : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_CheckString(eRegisterField registerField)
	 : cRegisterFilterItem_base(registerField) {
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
	bool check(struct RegisterRecord *rec);
private:
	ListCheckString_wb checkStringData;
};

class cRegisterFilterItem_numInterval : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_numInterval(eRegisterField registerField,
					double num, bool from = true)
	 : cRegisterFilterItem_base(registerField) {
		this->num = num;
		this->from = from;
	}
	bool check(struct RegisterRecord *rec);
private:
	double num;
	bool from;
};

class cRegisterFilterItem_numList : public cRegisterFilterItem_base {
public:
	cRegisterFilterItem_numList(eRegisterField registerField)
	 : cRegisterFilterItem_base(registerField) {
	}
	void addNum(u_int64_t num) {
		nums.push_back(num);
	}
	bool check(struct RegisterRecord *rec);
private:
	list<u_int64_t> nums;
};

class cRegisterFilterItems {
public:
	void addFilter(cRegisterFilterItem_base *filter);
	bool check(struct RegisterRecord *rec);
	void free();
public:
	list<cRegisterFilterItem_base*> fItems;
};

class cRegisterFilter {
public:
	cRegisterFilter(char *filter);
	~cRegisterFilter();
	void addFilter(cRegisterFilterItem_base *filter1, cRegisterFilterItem_base *filter2 = NULL, cRegisterFilterItem_base *filter3 = NULL);
	bool check(struct RegisterRecord *rec);
public:
	list<cRegisterFilterItems> fItems;
};


eRegisterState convRegisterState(Call *call);
eRegisterField convRegisterFieldToFieldId(const char *field);


#endif
