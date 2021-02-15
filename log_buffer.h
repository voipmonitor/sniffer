#ifndef LOG_BUFFER_H
#define LOG_BUFFER_H
 
#include <stdlib.h>
#include <string.h>
#include <string>


class cLogBuffer_var {
public:
	enum eTypeVar {
		_int,
		_str
	};
public:
	cLogBuffer_var(int var = 0) {
		type = _int;
		var_int = var;
	}
	cLogBuffer_var(int64_t var) {
		type = _int;
		var_int = var;
	}
	cLogBuffer_var(size_t var) {
		type = _int;
		var_int = var;
	}
	cLogBuffer_var(char *var) {
		type = _str;
		strncpy(var_str, var, sizeof(var_str) - 1);
		var_str[sizeof(var_str) - 1] = 0;
	}
	std::string getStr();
private:
	eTypeVar type;
	int64_t var_int;
	char var_str[1000];
friend class cLogBuffer_item;
};

class cLogBuffer_item {
public:
	void set(int type, const char *str, cLogBuffer_var var1 = 0, cLogBuffer_var var2 = 0, cLogBuffer_var var3 = 0) {
		this->type = type;
		strncpy(this->str, str, sizeof(this->str));
		this->str[sizeof(this->str) - 1] = 0;
		vars[0] = var1;
		vars[1] = var2;
		vars[2] = var3;
	}
	std::string getStr();
private:
	int type;
	char str[1000];
	cLogBuffer_var vars[3];
friend class cLogBuffer;
};

class cLogBuffer {
public:
	cLogBuffer() {
		count = 0;
		sync = 0;
	}
	void add(int type, const char *str, cLogBuffer_var var1 = 0, cLogBuffer_var var2 = 0, cLogBuffer_var var3 = 0) {
		lock();
		if(count < sizeof(items) / sizeof(items[0])) {
			items[count].set(type, str, var1, var2, var3);
		}
		++count;
		unlock();
	}
	void apply();
private:
	void lock() {
		while(__sync_lock_test_and_set(&sync, 1));
	}
	void unlock() {
		__sync_lock_release(&sync);
	}
private:
	cLogBuffer_item items[10];
	unsigned count;
	volatile int sync;
};

#endif
