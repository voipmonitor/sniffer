#include "record_array.h"
#include "tools.h"
#include "sql_db.h"


string RecordArrayField::getJson() {
	switch(tf) {
	case tf_int:
		return(intToString(i));
	case tf_time:
		return('"' + sqlDateTimeString(i) + '"');
	case tf_string:
		if(s) {
			return('"' + json_encode(s) + '"');
		}
	case tf_na:
		return("null");
	}
	return("null");
}

RecordArray::RecordArray(unsigned max_fields) {
	this->max_fields = max_fields;
	fields = new FILE_LINE(18001) RecordArrayField[max_fields];
	sortBy = sortBy2 = 0;
}

void RecordArray::free() {
	for(unsigned i = 0; i < max_fields; i++) {
		fields[i].free();
	}
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
