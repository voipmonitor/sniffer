#include <syslog.h>
#include <stdio.h>

#include "log_buffer.h"


using namespace std;


string cLogBuffer_var::getStr() {
	char var_buffer[20];
	switch(type) {
	case _int:
		snprintf(var_buffer, sizeof(var_buffer), "%li", var_int);
		return(var_buffer);
	case _str:
		return(var_str);
	}
	return("");
}


string cLogBuffer_item::getStr() {
	string rslt = str;
	for(unsigned i = 0; i < sizeof(vars) / sizeof(vars[0]); i++) {
		size_t pos = rslt.find('%');
		if(pos != string::npos) {
			rslt = rslt.substr(0, pos) + vars[i].getStr() + rslt.substr(pos + 1);
		}
	}
	return(rslt);
}


void cLogBuffer::apply() {
	lock();
	for(unsigned i = 0; i < min(count, (unsigned)(sizeof(items) / sizeof(items[0]))); i++) {
		syslog(items[i].type, "%s", items[i].getStr().c_str());
	}
	if(count > (unsigned)(sizeof(items) / sizeof(items[0]))) {
		syslog(LOG_NOTICE, "hidden %u logs", (unsigned)(count - sizeof(items) / sizeof(items[0])));
	}
	count = 0;
	unlock();
}
