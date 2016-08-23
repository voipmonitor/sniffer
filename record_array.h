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
		tf_time,
		tf_string
	};
	RecordArrayField() {
		tf = tf_na;
		i = 0;
		s = NULL;
	}
	void free() {
		if(s) {
			delete [] s;
			s = NULL;
		}
	}
	void set(u_int64_t i, eTypeField tf = tf_int) {
		this->tf = tf;
		this->i = i;
	}
	void set(const char *s) {
		tf = tf_string;
		if(s && *s) {
			this->s = new FILE_LINE(20001) char[strlen(s) + 1];
			strcpy(this->s, s);
		} else {
			this->s = NULL;
		}
		this->i = 0;
	}
	string getJson();
	bool operator == (const RecordArrayField& other) const {
		return(i == other.i &&
		       EQ_STR(s, other.s));
	}
	bool operator < (const RecordArrayField& other) const {
		return(i < other.i ? 1 : i > other.i ? 0 :
		       CMP_STR(s, other.s) < 0);
	}
	bool operator > (const RecordArrayField& other) const {  
		return(!(*this < other || *this == other));
	}
	eTypeField tf;
	u_int64_t i;
	char *s;
};

struct RecordArrayField2 : public RecordArrayField {
	RecordArrayField2(RecordArrayField *other) : RecordArrayField() {
		if(other) {
			this->tf = other->tf;
			this->i = other->i;
			if(other->s && *other->s) {
				this->s = new FILE_LINE(20002) char[strlen(other->s) + 1];
				strcpy(this->s, other->s);
			}
		}
	}
	RecordArrayField2(const RecordArrayField2 &other) {
		this->tf = other.tf;
		this->i = other.i;
		if(other.s && *other.s) {
			this->s = new FILE_LINE(20003) char[strlen(other.s) + 1];
			strcpy(this->s, other.s);
		} else {
			this->s = NULL;
		}
	}
	~RecordArrayField2() {
		free();
	}
	RecordArrayField2& operator = (const RecordArrayField2& other) {
		free();
		this->tf = other.tf;
		this->i = other.i;
		if(other.s && *other.s) {
			this->s = new FILE_LINE(20004) char[strlen(other.s) + 1];
			strcpy(this->s, other.s);
		}
		return(*this);
	}
};

struct RecordArray {
	RecordArray(unsigned max_fields);
	void free();
	string getJson();
	bool operator == (const RecordArray& other) const {  
		return(fields[sortBy] == other.fields[sortBy] &&
		       fields[sortBy2] == other.fields[sortBy2]);
	}
	bool operator < (const RecordArray& other) const {  
		return(fields[sortBy] < other.fields[sortBy] ? 1 : fields[sortBy] > other.fields[sortBy] ? 0 :
		       fields[sortBy2] < other.fields[sortBy2]);
	}
	unsigned max_fields;
	RecordArrayField *fields;
	unsigned sortBy;
	unsigned sortBy2;
};


#endif
