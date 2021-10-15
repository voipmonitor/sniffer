#ifndef REGISTER_H
#define REGISTER_H


#include <string>
#include <vector>
#include <string.h>

#include "calltable.h"
#include "record_array.h"
#include "filter_register.h"


#define NEW_REGISTER_MAX_STATES 3

#define REG_SIPALG_DETECTED	(1 << 0)

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
	rf_sipcallerip_encaps,
	rf_sipcalledip_encaps,
	rf_sipcallerip_encaps_prot,
	rf_sipcalledip_encaps_prot,
	rf_sipcallerport,
	rf_sipcalledport,
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
	rf_spool_index,
	rf_is_sipalg_detected,
	rf_vlan,
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
	inline u_int64_t unshiftSystemTime_s(u_int64_t time_s) {
		return(time_s - time_shift_ms / 1000);
	}
public:
	u_int64_t state_from_us;
	u_int64_t state_to_us;
	int64_t time_shift_ms;
	u_int32_t counter;
	eRegisterState state;
	char *contact_num;
	char *contact_domain;
	char *from_num;
	char *from_name;
	char *from_domain;
	char *digest_realm;
	char *ua;
	int8_t spool_index;
	u_int64_t fname;
	u_int32_t expires;
	int id_sensor;
	u_int16_t vlan;
	u_int64_t db_id;
	u_int64_t save_at;
	u_int32_t save_at_counter;
	bool is_sipalg_detected;
};


class Register {
public:
	inline Register(Call *call);
	inline ~Register();
	inline void update(Call *call);
	inline void addState(Call *call);
	inline void shiftStates();
	inline void expire(bool need_lock_states = true, bool use_state_prev_last = false);
	inline void updateLastState(Call *call);
	inline void updateLastStateItem(char *callItem, char *registerItem, char **stateItem);
	inline bool eqLastState(Call *call);
	inline void clean_all();
	inline void saveStateToDb(RegisterState *state, bool enableBatchIfPossible = true);
	inline void saveFailedToDb(RegisterState *state, bool force = false, bool enableBatchIfPossible = true);
	inline eRegisterState getState();
	inline u_int32_t getStateFrom_s();
	inline RegisterState *states_last() {
		return(countStates ? states[0] : NULL);
	}
	inline RegisterState *states_prev_last() {
		return(countStates > 1 ? states[1] : NULL);
	}
	inline bool getDataRow(RecordArray *rec);
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
	inline bool getSipAlgState () {
		for (int i = 0; i < countStates; i++) {
			if (states[i]->is_sipalg_detected) {
				return(true);
			}
		}
		return(false);
	}
public:
	u_int64_t id;
	vmIP sipcallerip;
	vmIP sipcalledip;
	vmIP sipcallerip_encaps;
	vmIP sipcalledip_encaps;
	u_int8_t sipcallerip_encaps_prot;
	u_int8_t sipcalledip_encaps_prot;
	vmPort sipcallerport;
	vmPort sipcalledport;
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
	u_int16_t vlan;
	RegisterState *states[NEW_REGISTER_MAX_STATES];
	u_int16_t countStates;
	u_int64_t rrd_sum;
	u_int32_t rrd_count;
	string reg_call_id;
	list<u_int32_t> reg_tcp_seq;
	volatile int _sync_states;
	static volatile u_int64_t _id;
	static volatile int _sync_id;
};


class Registers {
public: 
	Registers();
	~Registers();
	void add(Call *call);
	bool existsDuplTcpSeqInRegOK(Call *call, u_int32_t seq);
	void cleanup(bool force = false, int expires_add = 0);
	void clean_all();
	inline u_int64_t getNewRegisterFailedId(int sensorId);
	string getDataTableJson(char *params, bool *zip = NULL);
	int getCount();
	void cleanupByJson(char *params);
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
	volatile u_int64_t register_failed_id;
	volatile int _sync_register_failed_id;
	u_int32_t last_cleanup_time;
};


eRegisterState convRegisterState(Call *call);
eRegisterField convRegisterFieldToFieldId(const char *field);


#define EQ_REG				((char*)-1)
#define REG_NEW_STR(src)		((src) == EQ_REG ? EQ_REG : (src) && *(src) ? (tmp_str = new FILE_LINE(0) char[strlen(src) + 1], strcpy(tmp_str, src), tmp_str) : NULL)
#define REG_FREE_STR(str)		((str) && (str) != EQ_REG ? (delete [] (str), str = NULL, true) : (str = NULL, false))
#define REG_EQ_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? true : (!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? false : !strcasecmp(str1, str2))
#define REG_EQ0_STR(str1, str2)		((!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? true : !strcasecmp(str1, str2))
#define REG_CMP_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? 0 : (!(str1) || !*(str1)) ? -1 : (!(str2) || !*(str2)) ? 1 : strcasecmp(str1, str2))
#define REG_CMP0_STR(str1, str2)	((!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? 0 : strcasecmp(str1, str2))
#define REG_CONV_STR(str)		((str) && (str) != EQ_REG ? string(str) : string())


#endif
