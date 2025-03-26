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
#define REG_ID_SIMPLE		(1 << 1)
#define REG_ID_COMB		(1 << 2)

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


class RegisterFailedId {
public:
	inline bool operator == (const RegisterFailedId& other) const;
	inline bool operator < (const RegisterFailedId& other) const;
public:
	int id_sensor;
	vmIP sipcallerip;
	vmIP sipcalledip;
	vmIP sipcallerip_encaps;
	vmIP sipcalledip_encaps;
};


class RegisterFailedCount {
public:
	RegisterFailedCount(Call *call);
	void saveToDb(u_int32_t time_interval);
public:
	int id_sensor;
	vmIP sipcallerip;
	vmIP sipcalledip;
	vmIP sipcallerip_encaps;
	vmIP sipcalledip_encaps;
	u_int8_t sipcallerip_encaps_prot;
	u_int8_t sipcalledip_encaps_prot;
	u_int32_t count;
	u_int32_t count_saved;
};


class RegisterFailedInterval {
public:
	RegisterFailedInterval(u_int32_t time_interval);
	~RegisterFailedInterval();
	bool add(Call *call);
	void saveToDb();
public:
	u_int32_t time_interval;
	map<RegisterFailedId, RegisterFailedCount*> failed_count;
};


class RegisterFailed {
public:
	RegisterFailed();
	~RegisterFailed();
	bool add(Call *call);
	void cleanup(bool force);
	void lock() {
		__SYNC_LOCK(_sync_failed_intervals);
	}
	void unlock() {
		__SYNC_UNLOCK(_sync_failed_intervals);
	}
public:
	map<u_int32_t, RegisterFailedInterval*> failed_intervals;
	volatile int _sync_failed_intervals;
};


class RegisterActive {
public:
	void saveToDb(u_int32_t time_s);
};


class RegisterState {
public:
	struct NextState {
		NextState(u_int64_t at, u_int64_t fname, int id_sensor) {
			this->at = at;
			this->fname = fname;
			this->id_sensor = id_sensor;
		}
		u_int64_t at;
		u_int64_t fname;
		int id_sensor;
	};
public:
	inline RegisterState(Call *call, Register *reg);
	inline ~RegisterState();
	inline void copyFrom(const RegisterState *src);
	inline bool isEq(Call *call, Register *reg, bool *exp_state);
	inline bool isOK() {
		return(state == rs_OK || state == rs_UnknownMessageOK);
	}
	inline bool isEq(Call *call, Register *reg);
	inline u_int64_t unshiftSystemTime_s(u_int64_t time_s) {
		return(time_s ? (time_s - time_shift_ms / 1000) : 0);
	}
	inline void setZombie() {
		state_from_us = state_to_us;
		fname = fname_last;
		next_states.clear();
		next_states_saved = 0;
		zombie = true;
	}
public:
	u_int64_t state_from_us;
	u_int64_t state_to_us;
	int64_t time_shift_ms;
	eRegisterState state;
	bool zombie;
	char *contact_num;
	char *contact_domain;
	char *from_num;
	char *from_name;
	char *from_domain;
	char *digest_realm;
	char *ua;
	int8_t spool_index;
	u_int64_t fname;
	u_int64_t fname_last;
	u_int32_t expires;
	int id_sensor;
	u_int16_t vlan;
	u_int64_t db_id;
	u_int64_t save_at_us;
	bool is_sipalg_detected;
	vector<NextState> next_states;
	u_int32_t next_states_saved;
};


class RegisterStates {
public:
	RegisterStates();
	~RegisterStates();
	inline void add(RegisterState *state);
	inline void shift();
	inline void clean();
	inline RegisterState *last() {
		return(count ? states[0] : NULL);
	}
	inline RegisterState *prev() {
		return(count > 1 ? states[1] : NULL);
	}
	inline bool eqLast(Call *call, class Register *reg, bool *exp_state);
	inline bool isSipAlg () {
		for(int i = 0; i < count; i++) {
			if(states[i]->is_sipalg_detected) {
				return(true);
			}
		}
		return(false);
	}
public:
	RegisterState *states[NEW_REGISTER_MAX_STATES];
	u_int16_t count;
};


class Register {
public:
	enum eTypeSaveState {
		_ss_init,
		_ss_reset,
		_ss_update,
		_ss_save,
		_ss_update_force,
		_ss_exp_state,
		_ss_end
	};
public:
	inline Register(Call *call);
	inline ~Register();
	inline void update(Call *call);
	inline void addState(Call *call);
	inline void expire(bool need_lock_states = true);
	inline void updateLastState(Call *call, RegisterStates *states);
	inline void resetLastState(Call *call, RegisterStates *states);
	inline void updateLastStateItem(const char *callItem, const char *registerItem, char **stateItem);
	inline bool eqLastState(Call *call, bool *exp_state);
	inline void clean_all();
	inline u_int8_t saveNewStateToDb(RegisterState *state);
	inline u_int8_t saveDeferredStateToDb(RegisterState *state);
	inline u_int8_t saveUpdateStateToDb(RegisterState *state);
	string getQueryStringForSaveEqNext(RegisterState *state);
	inline void saveStateToDb(RegisterState *state, eTypeSaveState typeSaveState, u_int32_t actTimeS = 0,
				  const char *file = NULL, int line = 0);
	inline bool needSaveToDb();
	inline RegisterState* getLastState();
	inline eRegisterState getState();
	inline bool stateIsOK();
	inline int getIdSensor();
	inline u_int32_t getStateFrom_s();
	inline bool getDataRow(RecordArray *rec);
	string typeSaveStateToString(eTypeSaveState typeSaveState);
	void lock_states() {
		__SYNC_LOCK(_sync_states);
	}
	void unlock_states() {
		__SYNC_UNLOCK(_sync_states);
	}
	void lock_id() {
		__SYNC_LOCK(_sync_id);
	}
	void unlock_id() {
		__SYNC_UNLOCK(_sync_id);
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
	RegisterStates states_state;
	RegisterStates states_failed;
	u_int64_t rrd_sum;
	u_int32_t rrd_count;
	string reg_call_id;
	list<u_int32_t> reg_tcp_seq;
	volatile int _sync_states;
	static volatile u_int64_t _id;
	static volatile int _sync_id;
	unsigned long int flags;
};


class RegistersTimer : public cTimer {
public:
	RegistersTimer(class Registers *registers);
protected:
	void evTimer(u_int32_t time_s, int typeTimer, void *data);
};


class Registers {
public: 
	Registers();
	~Registers();
	void init_db(SqlDb *db = NULL);
	void add(Call *call);
	bool existsDuplTcpSeqInRegOK(Call *call, u_int32_t seq);
	void cleanup(bool force = false, int expires_add = 0);
	void cleanup_from_timer(u_int32_t time_s);
	void clean_all();
	inline u_int64_t getNewRegisterId(int sensorId, bool failed, SqlDb *db = NULL);
	inline u_int64_t getNewRegisterStateId(int sensorId);
	inline u_int64_t getNewRegisterFailedId(int sensorId);
	string getDataTableJson(char *params, bool *zip = NULL);
	int getCount();
	void getCountActiveBySensors(map<int, u_int32_t> *count);
	void cleanupByJson(char *params);
	void lock_registers() {
		__SYNC_LOCK(_sync_registers);
	}
	void unlock_registers() {
		__SYNC_UNLOCK(_sync_registers);
	}
	void lock_registers_erase() {
		__SYNC_LOCK(_sync_registers_erase);
	}
	void unlock_registers_erase() {
		__SYNC_UNLOCK(_sync_registers_erase);
	}
	void lock_register_state_id() {
		__SYNC_LOCK(_sync_register_state_id);
	}
	void unlock_register_state_id() {
		__SYNC_UNLOCK(_sync_register_state_id);
	}
	void lock_register_failed_id() {
		__SYNC_LOCK(_sync_register_failed_id);
	}
	void unlock_register_failed_id() {
		__SYNC_UNLOCK(_sync_register_failed_id);
	}
	bool isEnabledDeferredSaveForState() {
		extern bool opt_sip_register_deferred_save;
		extern bool opt_sip_register_save_eq_states_time;
		extern sExistsColumns existsColumns;
		return(opt_sip_register_deferred_save &&
		       existsColumns.register_state_flags &&
		       (existsColumns.register_state_counter || opt_sip_register_save_eq_states_time));
	}
	bool isEnabledDeferredSaveForFailed() {
		extern bool opt_sip_register_deferred_save;
		extern sExistsColumns existsColumns;
		return(opt_sip_register_deferred_save &&
		       existsColumns.register_failed_flags);
	}
	bool isEnabledDeferredSave(RegisterState *state) {
		return(state->state == rs_Failed ?
			isEnabledDeferredSaveForFailed() :
			isEnabledDeferredSaveForState());
	}
	bool isEnabledIdAssignmentForState() {
		extern bool opt_sip_register_save_eq_states_time;
		extern sExistsColumns existsColumns;
		return(!isEnabledDeferredSaveForState() &&
		       (existsColumns.register_state_counter || opt_sip_register_save_eq_states_time));
	}
	bool isEnabledIdAssignmentForFailed() {
		return(!isEnabledDeferredSaveForFailed());
	}
	bool isEnabledIdAssignment(RegisterState *state) {
		return(state->state == rs_Failed ?
			isEnabledIdAssignmentForFailed() :
			isEnabledIdAssignmentForState());
	}
	void startTimer();
	void stopTimer();
	void evTimer(u_int32_t time_s, int typeTimer);
public:
	map<RegisterId, Register*> registers;
	RegisterFailed registers_failed;
	RegisterActive register_active;
	volatile int _sync_registers;
	volatile int _sync_registers_erase;
	volatile u_int64_t register_state_id;
	volatile u_int64_t register_failed_id;
	volatile int _sync_register_state_id;
	volatile int _sync_register_failed_id;
	u_int32_t last_cleanup_time;
	RegistersTimer timer;
};


eRegisterState convRegisterState(Call *call);
eRegisterField convRegisterFieldToFieldId(const char *field);

void initRegisters();
void initRegistersDb(SqlDb *sqlDb);
void termRegisters();


#define EQ_REG				((char*)-1)
#define REG_NEW_STR(src)		((src) == EQ_REG ? EQ_REG : (src) && *(src) ? (tmp_str = new FILE_LINE(0) char[strlen(src) + 1], strcpy(tmp_str, src), tmp_str) : NULL)
#define REG_FREE_STR(str)		((str) && (str) != EQ_REG ? (delete [] (str), str = NULL, true) : (str = NULL, false))
#define REG_EQ_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? true : (!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? false : !strcasecmp(str1, str2))
#define REG_EQ0_STR(str1, str2)		((!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? true : !strcasecmp(str1, str2))
#define REG_CMP_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? 0 : (!(str1) || !*(str1)) ? -1 : (!(str2) || !*(str2)) ? 1 : strcasecmp(str1, str2))
#define REG_CMP0_STR(str1, str2)	((!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? 0 : strcasecmp(str1, str2))
#define REG_CONV_STR(str)		((str) && (str) != EQ_REG ? string(str) : string())


#endif
