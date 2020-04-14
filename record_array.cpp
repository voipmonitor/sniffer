#include "record_array.h"
#include "tools.h"
#include "sql_db.h"


string RecordArrayField::getJson() {
	switch(tf) {
	case tf_int:
		return(intToString((long long)v.i));
	case tf_uint:
		return(intToString((u_int64_t)v.u));
	case tf_ip:
		return("\"" + v_ip.getString() + "\"");
	case tf_ip_n4:
		return(v_ip.is_v6() ?
			"\"" + v_ip.getString() + "\"" :
			intToString(v_ip.getIPv4()));
	case tf_port:
		return(v_port.getString());
	case tf_float:
		return(!isnan(v.d) ? floatToString(v.d) : "null");
	case tf_pointer:
		return('"' + pointerToString(v.p) + '"');
	case tf_time:
		return('"' + sqlDateTimeString(v.u) + '"');
	case tf_time_ms:
		return('"' + sqlDateTimeString_us2ms(v.u) + '"');
	case tf_string:
		if(v.s) {
			return('"' + json_encode(v.s) + '"');
		}
		break;
	case tf_json:
		if(v.s) {
			return(v.s);
		}
		break;
	case tf_bool:
		return(boolToString(v.b));
	default:
		break;
	}
	return("null");
}

RecordArray::RecordArray(unsigned max_fields) {
	this->max_fields = max_fields;
	fields = new FILE_LINE(18001) RecordArrayField[max_fields];
	sortBy = 0;
	sortBy2 = -1;
}

void RecordArray::free() {	
	freeFields();
	freeRecord();
}

void RecordArray::freeFields() {
	for(unsigned i = 0; i < max_fields; i++) {
		fields[i].free();
	}
}

void RecordArray::freeRecord() {
	delete [] fields;
}

string RecordArray::getJson() {
	string json = "[";
	for(unsigned i = 0; i < max_fields; i++) {
		if(i) {
			json += ",";
		}
		json += fields[i].getJson();
	}
	json += "]";
	return(json);
}
