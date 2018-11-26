#ifndef RECORD_ARRAY_H
#define RECORD_ARRAY_H


#include <sys/types.h>
#include <string.h>
#include <string>

#include "heap_safe.h"


using namespace std;


#define EQ_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? true : (!(str1) || !*(str1)) || (!(str2) || !*(str2)) ? false : !strcasecmp(str1, str2))
#define CMP_STR(str1, str2)		((!(str1) || !*(str1)) && (!(str2) || !*(str2)) ? 0 : (!(str1) || !*(str1)) ? -1 : (!(str2) || !*(str2)) ? 1 : strcasecmp(str1, str2))


struct RecordArrayField {
	enum eTypeField {
		tf_na,
		tf_int,
		tf_uint,
		tf_float,
		tf_pointer,
		tf_time,
		tf_string,
		tf_json,
		tf_bool
	};
	RecordArrayField() {
		tf = tf_na;
		v.i = 0;
	}
	void free() {
		if((tf == tf_string || tf == tf_json) && v.s) {
			delete [] v.s;
			v.s = NULL;
		}
	}
	void set(int i, eTypeField tf = tf_int) {
		this->tf = tf;
		this->v.i = i;
	}
	void set(long i, eTypeField tf = tf_int) {
		this->tf = tf;
		this->v.i = i;
	}
	void set(long long i, eTypeField tf = tf_int) {
		this->tf = tf;
		this->v.i = i;
	}
	void set(unsigned u, eTypeField tf = tf_uint) {
		this->tf = tf;
		this->v.u = u;
	}
	void set(long unsigned u, eTypeField tf = tf_uint) {
		this->tf = tf;
		this->v.u = u;
	}
	void set(long long unsigned u, eTypeField tf = tf_uint) {
		this->tf = tf;
		this->v.u = u;
	}
	void set(double d, eTypeField tf = tf_float) {
		this->tf = tf;
		this->v.d = d;
	}
	void set(void *p, eTypeField tf = tf_pointer) {
		this->tf = tf;
		this->v.p = p;
	}
	void set(bool b, eTypeField tf = tf_bool) {
		this->tf = tf;
		this->v.b = b;
	}
	void set(const char *s, eTypeField tf = tf_string) {
		this->tf = tf;
		if(s && *s) {
			this->v.s = new FILE_LINE(0) char[strlen(s) + 1];
			strcpy(this->v.s, s);
		} else {
			this->v.s = NULL;
		}
	}
	int64_t get_int() {
		return(tf == tf_int || tf == tf_uint || tf == tf_pointer || tf == tf_time ?
			v.i :
		       tf == tf_float ?
			(int64_t)v.d :
			0);
	}
	u_int64_t get_uint() {
		return(tf == tf_int || tf == tf_uint || tf == tf_pointer || tf == tf_time ?
			v.u :
		       tf == tf_float ?
			(u_int64_t)v.d :
			0);
	}
	bool get_bool() {
		return(tf == tf_bool ? (bool)v.b : false);
	}
	double get_float() {
		return(tf == tf_int || tf == tf_uint || tf == tf_pointer || tf == tf_time ?
			(double)v.i :
		       tf == tf_float ?
			v.d :
			0);
	}
	void * get_pointer() {
		return(tf == tf_int || tf == tf_uint || tf == tf_pointer || tf == tf_time ?
			v.p :
			NULL);
	}
	const char *get_string() {
		return(tf == tf_string && v.s ?
			v.s :
			"");
	}
	string getJson();
	bool isSet() {
		return(tf != tf_na);
	}
	bool operator == (const RecordArrayField& other) const {
		if(tf == other.tf) {
			switch(tf) {
			case tf_na:
				return(true);
			case tf_int:
				return(v.i == other.v.i);
			case tf_uint:
			case tf_time:
				return(v.u == other.v.u);
			case tf_float:
				return(v.d == other.v.d);
			case tf_pointer:
				return(v.p == other.v.p);
			case tf_string:
			case tf_json:
				return(EQ_STR(v.s, other.v.s));
			case tf_bool:
				return(v.b == other.v.b);
			}
		}
		return(false);
	}
	bool operator < (const RecordArrayField& other) const {
		if(tf == other.tf) {
			switch(tf) {
			case tf_na:
				return(true);
			case tf_int:
				return(v.i < other.v.i);
			case tf_uint:
			case tf_time:
				return(v.u < other.v.u);
			case tf_float:
				return(v.d < other.v.d);
			case tf_pointer:
				return(v.p < other.v.p);
			case tf_string:
			case tf_json:
				return(CMP_STR(v.s, other.v.s) < 0);
			case tf_bool:
				return(false);
			}
		}
		return(tf < other.tf);
	}
	bool operator > (const RecordArrayField& other) const {  
		return(!(*this < other || *this == other));
	}
	eTypeField tf;
	union {
		int64_t i;
		u_int64_t u;
		double d;
		void *p;
		char *s;
		bool b;
	} v;
};

struct RecordArrayField2 : public RecordArrayField {
	RecordArrayField2(RecordArrayField *other, bool cloneStr = true) : RecordArrayField() {
		if(other) {
			this->tf = other->tf;
			this->v = other->v;
			if(other->tf == tf_string && other->v.s && *other->v.s && cloneStr) {
				this->v.s = new FILE_LINE(19002) char[strlen(other->v.s) + 1];
				strcpy(this->v.s, other->v.s);
			}
		}
	}
	RecordArrayField2(const RecordArrayField2 &other) {
		this->tf = other.tf;
		this->v = other.v;
		if(other.tf == tf_string && other.v.s && *other.v.s) {
			this->v.s = new FILE_LINE(19003) char[strlen(other.v.s) + 1];
			strcpy(this->v.s, other.v.s);
		}
	}
	~RecordArrayField2() {
		free();
	}
	RecordArrayField2& operator = (const RecordArrayField2& other) {
		free();
		this->tf = other.tf;
		this->v = other.v;
		if(other.tf == tf_string && other.v.s && *other.v.s) {
			this->v.s = new FILE_LINE(19004) char[strlen(other.v.s) + 1];
			strcpy(this->v.s, other.v.s);
		}
		return(*this);
	}
};

struct RecordArray {
	RecordArray(unsigned max_fields);
	void free();
	void freeFields();
	void freeRecord();
	string getJson();
	bool operator == (const RecordArray& other) const {  
		return(fields[sortBy] == other.fields[sortBy] &&
		       (sortBy2 == -1 || fields[sortBy2] == other.fields[sortBy2]));
	}
	bool operator < (const RecordArray& other) const {  
		return(fields[sortBy] < other.fields[sortBy] ? 1 : fields[sortBy] > other.fields[sortBy] ? 0 :
		       (sortBy2 >= 0 && fields[sortBy2] < other.fields[sortBy2]));
	}
	unsigned max_fields;
	RecordArrayField *fields;
	int sortBy;
	int sortBy2;
};


#endif
