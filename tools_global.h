#ifndef TOOLS_GLOBAL_H
#define TOOLS_GLOBAL_H


#include <pcap.h>
#include <time.h>
#include <string>
#include <list>
#include <vector>
#include <map>
#include <regex.h>
#include <zlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <unicode/ucnv.h> 

#include "tools_define.h"
#include "tools_local.h"
#include "ip.h"

#ifdef CLOUD_ROUTER_CLIENT
#include "common.h"
#include "config.h"
#endif

#ifdef FREEBSD
#include <sys/thr.h>
#endif

#ifndef FILE_LINE
#define FILE_LINE(alloc_number)
#endif


using namespace std;


inline unsigned int get_unix_tid(void) {
#if defined(__arm__) 
	int tid = 0;
#else
	static __thread int tid = 0;
	if(tid) {
		return tid;
	}
#endif
#ifdef HAVE_PTHREAD_GETTHREADID_NP
	tid = pthread_getthreadid_np();
#elif defined(linux)
	tid = syscall(SYS_gettid);
#elif defined(__sun)
	tid = pthread_self();
#elif defined(__APPLE__)
	tid = mach_thread_self();
	mach_port_deallocate(mach_task_self(), tid);
#elif defined(__NetBSD__)
	tid = _lwp_self();
#elif defined(__FreeBSD__)
	long lwpid;
	thr_self( &lwpid );
	tid = lwpid;
#elif defined(__DragonFly__)
	tid = lwp_gettid();
#endif
	return tid;
}


#if defined(__i386__)
__inline__ unsigned long long rdtsc(void)
{
    unsigned long long int x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}
#elif defined(__x86_64__)
__inline__ unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}
#endif


#define TIME_S_TO_US(s) ((u_int64_t)((s) * 1000000ull))
#define TIME_US_TO_S(us) ((u_int32_t)((us) / 1000000ull))
#define TIME_US_TO_S_signed(us) ((int32_t)((us) / 1000000ll))
#define TIME_US_TO_SF(us) ((double)((us) / 1000000.))
#define TIME_US_TO_DEC_MS(us) ((u_int32_t)((us) % 1000000ull / 1000ull))
#define TIME_US_TO_DEC_US(us) ((u_int32_t)((us) % 1000000ull))

inline double ts2double(unsigned int sec, unsigned int usec) {
	return double((double)sec + (0.000001f * (double)usec));
}

inline u_int32_t getTimeS(pcap_pkthdr* header = NULL) {
    if(header) {
         return(header->ts.tv_sec);
    }
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec);
}

inline u_int32_t getTimeS(timeval &ts) {
    return(ts.tv_sec);
}

inline u_int32_t getTimeS(timeval *ts) {
    return(ts->tv_sec);
}

inline double getTimeSF(pcap_pkthdr* header = NULL) {
    if(header) {
         return(ts2double(header->ts.tv_sec, header->ts.tv_usec));
    }
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(ts2double(time.tv_sec, time.tv_nsec / 1000));
}

inline double getTimeSF(timeval &ts) {
    return(ts2double(ts.tv_sec, ts.tv_usec));
}

inline u_int64_t getTimeMS(pcap_pkthdr* header = NULL) {
    if(header) {
         return(header->ts.tv_sec * 1000ull + header->ts.tv_usec / 1000);
    }
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000ull + time.tv_nsec / 1000000);
}

inline u_int64_t getTimeMS(timeval &ts) {
    return(ts.tv_sec * 1000ull + ts.tv_usec / 1000);
}

inline u_int64_t getTimeMS(timeval *ts) {
    return(ts->tv_sec * 1000ull + ts->tv_usec / 1000);
}

inline u_int64_t getTimeMS(unsigned long tv_sec, unsigned long tv_usec) {
    return(tv_sec * 1000ull + tv_usec / 1000);
}

inline timeval zeroTimeval() {
	timeval ts;
	ts.tv_sec = 0;
	ts.tv_usec = 0;
	return(ts);
}

inline bool isSetTimeval(timeval &ts) {
	return(ts.tv_sec);
}

inline bool isSetTimeval(timeval *ts) {
	return(ts->tv_sec);
}

extern u_int64_t rdtsc_by_250ms;

inline void init_rdtsc_interval() {
	#if defined(__i386__) or  defined(__x86_64__)
	u_int64_t _rdtsc_1 = rdtsc();
	usleep(250000);
	u_int64_t _rdtsc_2 = rdtsc();
	usleep(0);
	u_int64_t _rdtsc_3 = rdtsc();
	rdtsc_by_250ms = _rdtsc_2 - _rdtsc_1 - (_rdtsc_3 - _rdtsc_2);
	#endif
}

inline u_int64_t getTimeMS_rdtsc(pcap_pkthdr* header = NULL) {
	if(header) {
		return(header->ts.tv_sec * 1000ull + header->ts.tv_usec / 1000);
	}
	#if defined(__i386__) or defined(__x86_64__)
	static volatile u_int64_t last_time = 0;
	static volatile u_int64_t last_rdtsc = 0;
	if(rdtsc_by_250ms && last_rdtsc) {
		u_int64_t diff_rdtsc;
		u_int64_t act_rdtsc = rdtsc();
		if(act_rdtsc > last_rdtsc &&
		   (diff_rdtsc = (act_rdtsc - last_rdtsc)) < rdtsc_by_250ms * 4 * 10) {
			return(last_time + diff_rdtsc * 250 / rdtsc_by_250ms);
		}
	}
	#endif
	timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	#if defined(__i386__) or defined(__x86_64__)
	last_time = time.tv_sec * 1000ull + time.tv_nsec / 1000000;
	last_rdtsc = rdtsc();
	#endif
	return(last_time);
}

inline u_int32_t getTimeS_rdtsc(pcap_pkthdr* header = NULL) {
	return(getTimeMS_rdtsc(header) / 1000);
}

inline u_int64_t getTimeUS() {
	timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	return(time.tv_sec * 1000000ull + time.tv_nsec / 1000);
}

inline u_int64_t getTimeUS(pcap_pkthdr *pkthdr) {
    return(pkthdr->ts.tv_sec * 1000000ull + pkthdr->ts.tv_usec);
}

inline u_int64_t getTimeUS(timeval &ts) {
    return(ts.tv_sec * 1000000ull + ts.tv_usec);
}

inline u_int64_t getTimeUS(timeval *ts) {
    return(ts->tv_sec * 1000000ull + ts->tv_usec);
}

inline u_int64_t getTimeUS(const timeval &ts) {
    return(ts.tv_sec * 1000000ull + ts.tv_usec);
}

inline u_int64_t getTimeUS(volatile timeval &ts) {
    return(ts.tv_sec * 1000000ull + ts.tv_usec);
}

inline u_int64_t getTimeUS(unsigned long tv_sec, unsigned long tv_usec) {
    return(tv_sec * 1000000ull + tv_usec);
}

inline u_int64_t getTimeNS() {
    timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return(time.tv_sec * 1000000000ull + time.tv_nsec);
}


#if defined(CLOUD_ROUTER_SERVER) or defined(CLOUD_ROUTER_SSLKEYLOGGER)
#define USLEEP(us) usleep(us);
#endif
#ifdef CLOUD_ROUTER_CLIENT
#define USLEEP(us) usleep(us, __FILE__, __LINE__);
#define USLEEP_C(us, c) usleep(us, c, __FILE__, __LINE__);
inline unsigned int usleep(unsigned int useconds, unsigned int counter, const char *file, int line) {
 	unsigned int rslt_useconds = useconds;
	if(useconds < 5000 && counter != (unsigned int)-1) {
		unsigned int useconds_min = 0;
		double useconds_multiple_inc = 0.01;
		extern double last_traffic;
		if(last_traffic >= 0) {
			if(last_traffic < 1) {
				useconds_min = 500;
				useconds_multiple_inc = 0.3;
			} else if(last_traffic < 5) {
				useconds_multiple_inc = 0.2;
			} else if(last_traffic < 20) {
				useconds_multiple_inc = 0.1;
			} else if(last_traffic < 50) {
				useconds_multiple_inc = 0.05;
			} else if(last_traffic < 100) {
				useconds_multiple_inc = 0.02;
			}
		}
		rslt_useconds = min(200, (int)(1 + counter * useconds_multiple_inc)) * useconds;
		if(rslt_useconds > 100000) {
			rslt_useconds = 100000;
		}
		if(useconds_min && rslt_useconds < useconds_min) {
			rslt_useconds = useconds_min;
		}
	}
	extern sVerbose sverb;
	if(sverb.usleep_stats) {
		void usleep_stats_add(unsigned int useconds, bool fix, const char *file, int line);
		usleep_stats_add(rslt_useconds, counter == (unsigned int)-1, file, line);
	}
	usleep(rslt_useconds);
	return(rslt_useconds);
}
inline unsigned int usleep(unsigned int useconds, const char *file, int line) {
	extern sVerbose sverb;
	if(sverb.usleep_stats) {
		void usleep_stats_add(unsigned int useconds, bool fix, const char *file, int line);
		usleep_stats_add(useconds, 1, file, line);
	}
	usleep(useconds);
	return(useconds);
}
#endif


int vm_pthread_create(const char *thread_description,
		      pthread_t *thread, pthread_attr_t *attr,
		      void *(*start_routine) (void *), void *arg, 
		      const char *src_file, int src_file_line,
		      bool autodestroy = false);
inline int vm_pthread_create_autodestroy(const char *thread_description,
					 pthread_t *thread, pthread_attr_t *attr,
					 void *(*start_routine) (void *), void *arg, 
					 const char *src_file, int src_file_line) {
	return(vm_pthread_create(thread_description,
				 thread, attr,
				 start_routine, arg, 
				 src_file, src_file_line,
				 true));
}

bool pthread_set_affinity(pthread_t thread, string cores_set, string cores_unset);
bool pthread_set_affinity(pthread_t thread, vector<int> *cores_set, vector<int> *cores_unset);
void get_list_cores(string input, vector<int> &list);
void get_list_cores(string input, list<int> &list);


void base64_init(void);
int base64decode(unsigned char *dst, const char *src, int max);
string base64_encode(const unsigned char *data, size_t input_length);
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
void _base64_encode(const unsigned char *data, size_t input_length, char *encoded_data, size_t output_length = 0);


struct string_null {
	string_null() {
		is_null = true;
	}
	string_null(const char *str, unsigned length, bool null) {
		if(str) {
			if(length) {
				this->str = string(str, length);
			} else {
				this->str = str;
			}
			is_null = null;
		} else {
			is_null = true;
		}
	}
	bool isprint() {
		if(is_null) {
			return(false);
		}
		for(unsigned i = 0; i < str.length(); i++) {
			if(!::isprint(str[i])) {
				return(false);
			}
		}
		return(true);
	}
	string out() {
		if(isprint()) {
			 return(str);
		}
		if(is_null) {
			 return("_NULL_");
		}
		return("_B64_" + base64_encode((u_char*)str.c_str(), str.length()));
	}
	void in(const char *in) {
		if(in && *in == '_') {
			if(in[1] == 'N' && !strcmp(in, "_NULL_")) {
				is_null = true;
				str = "";
				return;
			} else if(!strncmp(in, "_B64_", 5)) {
				unsigned l = strlen(in);
				if(!strcmp(in + l - 2, "==")) {
					char *buff = new char[l];
					int length = base64decode((u_char*)buff, in + 5, l);
					str = string(buff, length);
					delete [] buff;
					is_null = false;
					return;
				}
			} 
		}
		if(in) {
			str = in;
			is_null = false;
		} else {
			is_null = true;
		}
	}
	string str;
	bool is_null;
};


class JsonItem {
public:
	JsonItem(string name = "", string value = "", bool null = false);
	void parse(string valStr);
	JsonItem *getItem(string path, int index = -1);
	string getValue(string path, int index = -1);
	int getCount(string path);
	string getLocalName() { return(this->name); }
	string getLocalValue() { return(this->value); }
	bool localValueIsNull() { return(this->null); }
	JsonItem *getLocalItem(int index = -1) { return(index == -1 ? this : &this->items[index]); }
	size_t getLocalCount() { return(this->items.size()); }
private:
	JsonItem *getPathItem(string path);
	string getPathItemName(string path);
	string name;
	string value;
	bool null;
	vector<JsonItem> items;
};

class JsonExport {
public:
	enum eTypeItem {
		_object,
		_array,
		_number,
		_string,
		_null,
		_json
	};
public:
	JsonExport();
	virtual ~JsonExport();
	void setTypeItem(eTypeItem typeItem) {
		this->typeItem = typeItem;
	}
	eTypeItem getTypeItem() {
		return(typeItem);
	}
	void setName(const char *name) {
		if(name) {
			this->name = name;
		}
	}
	void add(const char *name, string content, eTypeItem typeItem = _string);
	void add(const char *name, const char *content, eTypeItem typeItem = _string);
	void add(const char *name, int content) { add_int(name, content); } 
	void add(const char *name, unsigned int content) { add_int(name, content); } 
	void add(const char *name, long int content) { add_int(name, content); } 
	void add(const char *name, long unsigned int content) { add_int(name, content); } 
	void add(const char *name, long long int content) { add_int(name, content); } 
	void add(const char *name, long long unsigned int content) { add_int(name, content); } 
	void add_int(const char *name, int64_t content);
	void add(const char *name);
	JsonExport *addArray(const char *name);
	JsonExport *addObject(const char *name);
	void addJson(const char *name, const string &content);
	void addJson(const char *name, const char *content);
	virtual string getJson(JsonExport *parent = NULL);
protected:
	eTypeItem typeItem;
	string name;
	vector<JsonExport*> items;
};

template <class type_item>
class JsonExport_template : public JsonExport {
public:
	void setContent(type_item content) {
		this->content = content;
	}
	string getJson(JsonExport *parent = NULL);
private:
	type_item content;
};

string json_string_escape(const char *str);


string intToString(short int i);
string intToString(int i);
string intToString(long int i);
string intToString(long long int i);
string intToString(unsigned short int i);
string intToString(unsigned int i);
string intToString(unsigned long int i);
string intToString(unsigned long long int i);
string floatToString(double d);
string floatToString(double d, unsigned precision, bool adjustDec = false);
string pointerToString(void *p);
string boolToString(bool b);

inline char *intToString(long long int i, char *str) {
	if(i) {
		int str_length = 0;
		bool neg = i < 0;
		if(neg) {
			i = -i;
			str[str_length++] = '-';
		}
		u_int8_t buff[100];
		int buff_length = 0;
		while(i != 0) {
			buff[buff_length++] = i % 10;
			i /= 10;
		}
		for(int i = 0; i < buff_length; i++) {
			str[str_length++] = buff[buff_length - i - 1] + '0';
		}
		str[str_length] = 0;
	} else {
		str[0] = '0';
		str[1] = 0;
	}
	return(str);
}
inline char *intToString(unsigned long long int i, char *str) {
	if(i) {
		int str_length = 0;
		u_int8_t buff[100];
		int buff_length = 0;
		while(i != 0) {
			buff[buff_length++] = i % 10;
			i /= 10;
		}
		for(int i = 0; i < buff_length; i++) {
			str[str_length++] = buff[buff_length - i - 1] + '0';
		}
		str[str_length] = 0;
	} else {
		str[0] = '0';
		str[1] = 0;
	}
	return(str);
}
inline char *intToString(short int i, char *str) { return(intToString((long long int)i, str)); }
inline char *intToString(int i, char *str) { return(intToString((long long int)i, str)); }
inline char *intToString(long int i, char *str) { return(intToString((long long int)i, str)); }
inline char *intToString(unsigned short int i, char *str) { return(intToString((unsigned long long int)i, str)); }
inline char *intToString(unsigned int i, char *str) { return(intToString((unsigned long long int)i, str)); }
inline char *intToString(unsigned long int i, char *str) { return(intToString((unsigned long long int)i, str)); }
inline char *floatToString(double d, char *str) {
	sprintf(str, "%lf", d);
	return(str);
}

void xorData(u_char *data, size_t dataLen, const char *key, size_t keyLength, size_t initPos);


string &find_and_replace(string &source, const string find, string replace, unsigned *counter_replace = NULL);
string find_and_replace(const char *source, const char *find, const char *replace, unsigned *counter_replace = NULL);
string &find_and_replace_all(string &source, const string find, string replace);

std::string &trim(std::string &s, const char *trimChars = NULL);
std::string trim_str(std::string s, const char *trimChars = NULL);
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);
std::vector<std::string> split(const std::string &s, char delim);
std::vector<std::string> &split(const char *s, const char *delim, std::vector<std::string> &elems, bool enableTrim = false, bool useEmptyItems = false);
std::vector<std::string> split(const char *s, const char *delim, bool enableTrim = false, bool useEmptyItems = false);
std::vector<std::string> split(const char *s, std::vector<std::string> delim, bool enableTrim = false, bool useEmptyItems = false, bool enableTrimString = true);
std::vector<int> split2int(const std::string &s, char delim);
std::vector<int> split2int(const std::string &s, std::vector<std::string> delim, bool enableTrim);

bool check_regexp(const char *pattern);
int reg_match(const char *string, const char *pattern, const char *file = NULL, int line = 0);
int reg_match(const char *str, const char *pattern, vector<string> *matches, bool ignoreCase, const char *file = NULL, int line = 0);
string reg_replace(const char *string, const char *pattern, const char *replace, const char *file = NULL, int line = 0);

class cRegExp {
public:
	enum eFlags {
		_regexp_icase = 1,
		_regexp_sub = 2,
		_regexp_matches = 2,
		_regexp_icase_matches = 3
	};
public:
	cRegExp(const char *pattern, eFlags flags = _regexp_icase,
		const char *file = NULL, int line = 0);
	~cRegExp();
	bool regex_create();
	void regex_delete();
	int match(const char *subject, vector<string> *matches = NULL);
	string replace(const char *subject, const char *replace);
	bool isOK() {
		return(regex_init);
	}
	bool isError() {
		return(regex_error);
	}
	const char *getPattern() {
		return(pattern.c_str());
	}
private:
	string pattern;
	eFlags flags;
	regex_t regex;
	bool regex_init;
	bool regex_error;
};


class SimpleBuffer {
public:
	SimpleBuffer(u_int32_t capacityReserve = 0) {
		buffer = NULL;
		bufferLength = 0;
		bufferCapacity = 0;
		this->capacityReserve = capacityReserve;
	}
	SimpleBuffer(void *data, u_int32_t dataLength, u_int32_t capacityReserve = 0) {
		buffer = NULL;
		bufferLength = 0;
		bufferCapacity = 0;
		this->capacityReserve = capacityReserve;
		add(data, dataLength);
	}
	SimpleBuffer(const SimpleBuffer &other) {
		this->bufferLength = other.bufferLength;
		this->bufferCapacity = other.bufferCapacity;
		this->capacityReserve = other.capacityReserve;
		if(this->bufferLength) {
			this->buffer = new FILE_LINE(39001) u_char[this->bufferCapacity];
			memcpy(this->buffer, other.buffer, this->bufferLength);
		} else { 
			this->buffer = NULL;
		}
	}
	~SimpleBuffer() {
		destroy();
	}
	void add(const char *data) {
		add((void*)data, strlen(data));
	}
	void add(void *data, u_int32_t dataLength) {
		if(!data || !dataLength) {
			return;
		}
		if(!buffer) {
			buffer = new FILE_LINE(39002) u_char[dataLength + capacityReserve + 1];
			bufferCapacity = dataLength + capacityReserve + 1;
		} else if(bufferLength + dataLength + 1 > bufferCapacity) {
			u_char *bufferNew = new FILE_LINE(39003) u_char[bufferLength + dataLength + capacityReserve + 1];
			memcpy(bufferNew, buffer, bufferLength);
			delete [] buffer;
			buffer = bufferNew;
			bufferCapacity = bufferLength + dataLength + capacityReserve + 1;
		}
		memcpy(buffer + bufferLength, data, dataLength);
		bufferLength += dataLength;
	}
	void set(const char *data) {
		clear();
		add(data);
	}
	void set(void *data, u_int32_t dataLength) {
		clear();
		add(data, dataLength);
	}
	void set_data_capacity(u_int32_t bufferCapacity) {
		if(bufferCapacity > this->bufferCapacity) {
			if(!buffer) {
				buffer = new FILE_LINE(0) u_char[bufferCapacity];
			} else {
				u_char *bufferNew = new FILE_LINE(0) u_char[bufferCapacity];
				memcpy(bufferNew, buffer, bufferLength);
				delete [] buffer;
				buffer = bufferNew;
			}
			this->bufferCapacity = bufferCapacity;
		}
	}
	u_int32_t data_capacity() {
		return(bufferCapacity);
	}
	u_char *data() {
		return(buffer);
	}
	u_char *data() const {
		return(buffer);
	}
	u_int32_t size() {
		return(bufferLength);
	}
	u_int32_t size() const {
		return(bufferLength);
	}
	u_int32_t data_len() {
		return(bufferLength);
	}
	u_int32_t data_len() const {
		return(bufferLength);
	}
	void clear() {
		bufferLength = 0;
	}
	void destroy() {
		if(buffer) {
			delete [] buffer;
			buffer = NULL;
		}
		bufferLength = 0;
		bufferCapacity = 0;
	}
	bool empty() {
		return(bufferLength == 0);
	}
	bool removeDataFromLeft(u_int32_t removeSize) {
		if(removeSize > bufferLength) {
			return(false);
		} else if(removeSize == bufferLength) {
			destroy();
		} else {
			u_char *bufferNew = new FILE_LINE(39004) u_char[bufferCapacity];
			bufferLength -= removeSize;
			memcpy(bufferNew, buffer + removeSize, bufferLength);
			delete [] buffer;
			buffer = bufferNew;
		}
		return(true);
	}
	SimpleBuffer& operator = (const SimpleBuffer &other) {
		destroy();
		this->bufferLength = other.bufferLength;
		this->bufferCapacity = other.bufferCapacity;
		this->capacityReserve = other.capacityReserve;
		if(this->bufferLength) {
			this->buffer = new FILE_LINE(39005) u_char[this->bufferCapacity];
			memcpy(this->buffer, other.buffer, this->bufferLength);
		} else { 
			this->buffer = NULL;
		}
		return(*this);
	}
	operator char*() {
		if(bufferLength == 0) {
			return((char*)"");
		} else {
			if(bufferCapacity <= bufferLength) {
				u_char *newBuffer = new FILE_LINE(39006) u_char[bufferLength + 1];
				memcpy(newBuffer, buffer, bufferLength);
				delete [] buffer;
				buffer = newBuffer;
				bufferCapacity = bufferLength + 1;
			}
			buffer[bufferLength] = 0;
			return((char*)buffer);
		}
		return((char*)"");
	}
	bool isJsonObject() {
		return(bufferLength && buffer[0] == '{' && buffer[bufferLength - 1] == '}');
	}
private:
	u_char *buffer;
	u_int32_t bufferLength;
	u_int32_t bufferCapacity;
	u_int32_t capacityReserve;
};


class SimpleChunkBuffer {
private:
	struct sChunk {
		sChunk(u_char *data, u_int32_t dataLength, u_int32_t capacity) {
			buffer = new FILE_LINE(0) u_char[max(dataLength, capacity)];
			memcpy(buffer, data, dataLength);
			length = dataLength;
			this->capacity = max(dataLength, capacity);
		}
		sChunk(u_int32_t capacity) {
			buffer = new FILE_LINE(0) u_char[capacity];
			length = 0;
			this->capacity = capacity;
		}
		~sChunk() {
			delete [] buffer;
		}
		u_int32_t add(u_char *data, u_int32_t dataLength) {
			if(isFull()) {
				return(dataLength);
			}
			u_int32_t rest = 0;
			if(dataLength > freeCapacity()) {
				rest = dataLength - freeCapacity();
				dataLength = freeCapacity();
			}
			memcpy(buffer + length, data, dataLength);
			length += dataLength;
			return(rest);
		}
		bool isFull() {
			return(length >= capacity);
		}
		u_int32_t freeCapacity() {
			return(capacity > length ? capacity - length : 0);
		}
		u_char *buffer;
		u_int32_t length;
		u_int32_t capacity;
	};
public:
	SimpleChunkBuffer(u_int32_t minChunkLength = 1024) {
		this->minChunkLength = minChunkLength;
	}
	~SimpleChunkBuffer() {
		for(std::list<sChunk*>::iterator iter = buffer.begin(); iter != buffer.end(); iter++) {
			delete *iter;
		}
	}
	void add(u_char *data, u_int32_t dataLength) {
		if(!buffer.size() || buffer.back()->isFull()) {
			sChunk *chunk = new FILE_LINE(0) sChunk(data, dataLength, minChunkLength);
			buffer.push_back(chunk);
			return;
		}
		u_int32_t rest = buffer.back()->add(data, dataLength);
		if(rest > 0) {
			sChunk *chunk = new FILE_LINE(0) sChunk(data + dataLength - rest, rest, minChunkLength);
			buffer.push_back(chunk);
		}
	}
	u_int32_t size() {
		u_int32_t size = 0;
		for(std::list<sChunk*>::iterator iter = buffer.begin(); iter != buffer.end(); iter++) {
			size += (*iter)->length;
		}
		return(size);
	}
	u_char *data() {
		u_int32_t size = this->size();
		if(!size) {
			return(NULL);
		}
		u_char* data = new FILE_LINE(0) u_char[size];
		u_int32_t pos = 0;
		for(std::list<sChunk*>::iterator iter = buffer.begin(); iter != buffer.end(); iter++) {
			memcpy(data + pos, (*iter)->buffer, (*iter)->length);
			pos += (*iter)->length;
		}
		return(data);
	}
private:
	u_int32_t minChunkLength;
	std::list<sChunk*> buffer;
};


class cGzip {
public:
	enum eOperation {
		_na,
		_compress,
		_decompress
	};
public:
	cGzip();
	~cGzip();
public:
	bool compress(u_char *buffer, size_t bufferLength, u_char **cbuffer, size_t *cbufferLength);
	bool compressString(string &str, u_char **cbuffer, size_t *cbufferLength);
	bool decompress(u_char *buffer, size_t bufferLength, u_char **dbuffer, size_t *dbufferLength);
	string decompressString(u_char *buffer, size_t bufferLength);
	bool isCompress(u_char *buffer, size_t bufferLength);
private:
	void initCompress();
	void initDecompress();
	void term();
private:
	eOperation operation;
	z_stream *zipStream;
	SimpleBuffer *destBuffer;
};


#ifdef HAVE_LIBLZO
class cLzo {
public:
	cLzo();
	~cLzo();
public:
	bool compress(u_char *buffer, size_t bufferLength, u_char **cbuffer, size_t *cbufferLength, bool withHeader = true);
	bool decompress(u_char *buffer, size_t bufferLength, u_char **dbuffer, size_t *dbufferLength);
	string decompressString(u_char *buffer, size_t bufferLength);
	bool isCompress(u_char *buffer, size_t bufferLength);
private:
	void init();
	void term();
private:
	bool use_1_11;
	u_char *wrkmem;
	const char *header_string;
};
#endif


class cResolver {
public:
	enum eTypeResolve {
		_typeResolve_default,
		_typeResolve_std,
		_typeResolve_system_host
	};
private:
	struct sIP_time {
		vector<vmIP> ips;
		time_t at;
		unsigned timeout;
	};
public:
	cResolver();
	vmIP resolve(const char *host, vector<vmIP> *ips = NULL, unsigned timeout = 0, eTypeResolve typeResolve = _typeResolve_default);
	vmIP resolve(string &host, vector<vmIP> *ips = NULL, unsigned timeout = 0, eTypeResolve typeResolve = _typeResolve_default) {
		return(resolve(host.c_str(), ips, timeout, typeResolve));
	}
	static vmIP resolve_n(const char *host, unsigned timeout = 0, eTypeResolve typeResolve = _typeResolve_default);
	static vmIP resolve_n(string &host, unsigned timeout = 0, eTypeResolve typeResolve = _typeResolve_default) {
		return(resolve_n(host.c_str(), timeout, typeResolve));
	}
	static string resolve_str(const char *host, unsigned timeout = 0, eTypeResolve typeResolve = _typeResolve_default);
	static string resolve_str(string &host, unsigned timeout = 0, eTypeResolve typeResolve = _typeResolve_default) {
		return(resolve_str(host.c_str(), timeout, typeResolve));
	}
	std::vector<string> resolve_allips_str(const char *host, unsigned timeout = 0, eTypeResolve typeResolve = _typeResolve_default);
private:
	vmIP resolve_std(const char *host, vector<vmIP> *ips);
	vmIP resolve_by_system_host(const char *host, vector<vmIP> *ips);
	void sort_ips_by_type(vector<vmIP> *ips);
private:
	void lock() {
		while(__sync_lock_test_and_set(&_sync_lock, 1)) {
			USLEEP(100);
		}
	}
	void unlock() {
		__sync_lock_release(&_sync_lock);
	}
private:
	bool use_lock;
	bool res_timeout;
	map<string, sIP_time> res_table;
	volatile int _sync_lock;
};


class cUtfConverter {
public:
	cUtfConverter();
	~cUtfConverter();
	bool check(const char *str);
	string reverse(const char *str);
	bool is_ascii(const char *str);
	string remove_no_ascii(const char *str, const char subst = '_');
	void _remove_no_ascii(const char *str, const char subst = '_');
private:
	bool init();
	void term();
	void lock() {
		while(__sync_lock_test_and_set(&_sync_lock, 1)) {
			USLEEP(100);
		}
	}
	void unlock() {
		__sync_lock_release(&_sync_lock);
	}
private:
	UConverter *cnv_utf8;
	bool init_ok;
	volatile int _sync_lock;
};


struct sClientInfo {
	sClientInfo(int handler = 0, vmIP ip = 0) {
		this->handler = handler;
		this->ip = ip;
	}
	int handler;
	vmIP ip;
};


#endif
