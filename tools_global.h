#ifndef TOOLS_GLOBAL_H
#define TOOLS_GLOBAL_H


#include <pcap.h>
#include <time.h>
#include <string>
#include <list>
#include <vector>
#include <queue>
#include <map>
#include <regex.h>
#include <zlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unicode/ucnv.h> 
#include <json.h>

#include "tools_define.h"
#include "tools_local.h"
#include "tools_rdtsc.h"
#include "ip.h"
#include "sync.h"

#ifdef CLOUD_ROUTER_CLIENT
#include "common.h"
#include "config.h"
#endif

#ifdef HAVE_LIBZSTD
#include <zstd.h>
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


#define TIME_S_TO_US(s) ((u_int64_t)((s) * 1000000ull))
#define TIME_MS_TO_US(s) ((u_int64_t)((s) * 1000ull))
#define TIME_US_TO_S(us) ((u_int32_t)((us) / 1000000ull))
#define TIME_US_TO_S_ceil_ms(us) ((u_int32_t)((us) / 1000000ull) + ((us) % 1000000ull > 1000 ? 1 : 0))
#define TIME_US_TO_S_signed(us) ((int32_t)((us) / 1000000ll))
#define TIME_US_TO_MS(us) ((u_int64_t)((us) / 1000ull))
#define TIME_US_TO_SF(us) ((double)((us) / 1000000.))
#define TIME_US_TO_DEC_MS(us) ((u_int32_t)((us) % 1000000ull / 1000ull))
#define TIME_US_TO_DEC_US(us) ((u_int32_t)((us) % 1000000ull))

#define TIME_DIFF_FIX_OVERFLOW(us1, us2) ((us1) > (us2) ? (us1) - (us2) : 0)

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

inline bool isSetTimeval(timeval &ts) {
	return(ts.tv_sec);
}

inline bool isSetTimeval(timeval *ts) {
	return(ts->tv_sec);
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
    return(ts ? ts->tv_sec * 1000000ull + ts->tv_usec : 0);
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

inline timeval getTimeval() {
	u_int64_t time_us = getTimeUS();
	timeval ts;
	ts.tv_sec = TIME_US_TO_S(time_us);
	ts.tv_usec = TIME_US_TO_DEC_US(time_us);
	return(ts);
}

inline timeval zeroTimeval() {
	timeval ts;
	ts.tv_sec = 0;
	ts.tv_usec = 0;
	return(ts);
}


#if defined(CLOUD_ROUTER_SERVER) or defined(CLOUD_ROUTER_SSLKEYLOGGER)
#define USLEEP(us) usleep(us);
#define USLEEP_C(us, c) usleep(us, c);
inline void usleep(unsigned int useconds, unsigned int counter) {
 	unsigned int rslt_useconds = useconds;
	rslt_useconds = min(100, (int)(1 + counter * 0.1)) * useconds;
	if(rslt_useconds > 100000) {
		rslt_useconds = 100000;
	}
	usleep(rslt_useconds);
}
#endif
#ifdef CLOUD_ROUTER_CLIENT
#define USLEEP(us) usleep(us, __FILE__, __LINE__);
#define USLEEP_C(us, c) usleep(us, c, __FILE__, __LINE__);
inline unsigned int usleep(unsigned int useconds, unsigned int counter, const char *file, int line) {
	extern unsigned int opt_usleep_force;
	if(opt_usleep_force) {
		useconds = opt_usleep_force;
	}
	extern unsigned int opt_usleep_minimal;
	if(opt_usleep_minimal && useconds < opt_usleep_minimal) {
		useconds = opt_usleep_minimal;
	}
	extern bool opt_usleep_progressive;
	extern double opt_usleep_progressive_index;
	extern bool opt_usleep_mod_enable;
	#if defined(__x86_64__) || defined(__i386__)
	if(opt_usleep_mod_enable && useconds <= 100 && counter != (unsigned int)-1) {
		extern unsigned opt_usleep_mod_pause_spin_limit;
		extern unsigned opt_usleep_mod_sched_yield_spin_limit;
		if(counter < opt_usleep_mod_pause_spin_limit) {
			__asm__ volatile ("pause");
			return(0);
		} else if(counter < opt_usleep_mod_pause_spin_limit + opt_usleep_mod_sched_yield_spin_limit) {
			sched_yield();
			return(0);
		} else {
			counter -= opt_usleep_mod_pause_spin_limit + opt_usleep_mod_sched_yield_spin_limit;
		}
	}
	#endif
 	unsigned int rslt_useconds = useconds;
	extern double last_traffic;
	if((opt_usleep_progressive || last_traffic < 100) && useconds < 5000 && counter != (unsigned int)-1) {
		unsigned int useconds_min = 0;
		double useconds_multiple_inc = 0.01;
		if(opt_usleep_progressive_index) {
			useconds_multiple_inc = opt_usleep_progressive_index;
		} else {
			if(last_traffic >= 0) {
				if(last_traffic < 0.5) {
					if(useconds < 40) {
						useconds = 40;
					}
					useconds_min = 500;
					useconds_multiple_inc = 1;
				} else if(last_traffic < 1) {
					if(useconds < 20) {
						useconds = 20;
					}
					useconds_min = 200;
					useconds_multiple_inc = 0.5;
				} else if(last_traffic < 2) {
					useconds_min = 100;
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
		}
		rslt_useconds = min(200, (int)(1 + counter * useconds_multiple_inc)) * useconds;
		if(rslt_useconds > 100000) {
			rslt_useconds = 100000;
		}
		if(useconds_min && rslt_useconds < useconds_min) {
			rslt_useconds = useconds_min;
		}
	}
	#if SNIFFER_THREADS_EXT
	extern sVerbose sverb;
	if(sverb.sniffer_threads_ext) {
		void usleep_stats_add(unsigned int useconds, bool fix, const char *file, int line);
		usleep_stats_add(rslt_useconds, !opt_usleep_progressive || counter == (unsigned int)-1, file, line);
	}
	#endif
	usleep(rslt_useconds);
	return(rslt_useconds);
}
inline unsigned int usleep(unsigned int useconds, const char *file, int line) {
	extern unsigned int opt_usleep_force;
	if(opt_usleep_force) {
		useconds = opt_usleep_force;
	}
	extern unsigned int opt_usleep_minimal;
	if(opt_usleep_minimal && useconds < opt_usleep_minimal) {
		useconds = opt_usleep_minimal;
	}
	#if SNIFFER_THREADS_EXT
	extern sVerbose sverb;
	if(sverb.sniffer_threads_ext) {
		void usleep_stats_add(unsigned int useconds, bool fix, const char *file, int line);
		usleep_stats_add(useconds, 1, file, line);
	}
	#endif
	usleep(useconds);
	return(useconds);
}
#endif


class cVmThreadDestructItem {
public:
	virtual ~cVmThreadDestructItem() {};
};


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

void vm_thread_destruct_item(cVmThreadDestructItem *item);

bool pthread_set_affinity(pthread_t thread, string cores_set, string cores_unset);
bool pthread_set_affinity(pthread_t thread, vector<int> *cores_set, vector<int> *cores_unset);
bool pthread_set_priority(pthread_t thread, int tid, int sched_type, int priority = -1);
bool pthread_set_priority(int sched_type, int priority = -1);
bool pthread_set_priority(const char *sched_type_priority);
inline bool pthread_set_priority(string &sched_type_priority) { if(!sched_type_priority.empty()) return(pthread_set_priority(sched_type_priority.c_str())); return(true); }
bool parse_sched_type_priority(const char *sched_type_priority, int *sched_type_out, int *priority_out);
string get_sched_type_str(int sched_type);
int get_sched_type_from_str(const char *sched_type);
void get_list_cores(string input, vector<int> &list);
void get_list_cores(string input, list<int> &list);


class cCpuCoreInfo {
public:
	struct sCpuCoreInfo {
		sCpuCoreInfo() {
			memset(this, 0, sizeof(*this));
		}
		int CPU;
		int Core;
		int Socket;
		int Node;
		int L1d;
		int L1i;
		int L2;
		int L3;
	};
public:
	cCpuCoreInfo();
	void load();
	bool ok_loaded();
	sCpuCoreInfo *get(int cpu);
	bool getHT_cpus(int cpu, vector<int> *ht_cpus);
	int getHT_index(int cpu);
	int getFreeCpu(int node, bool no_ht, bool set_use = true);
	void setUseCpu(int cpu);
	void clearUsed();
	int getCountNode();
private:
	map<int, sCpuCoreInfo> map_cpu_core_info;
	map<int, bool> used;
};


int setAffinityForOtherProcesses(vector<int> *excluded_cpus, bool only_check, bool log, const char *log_prefix, bool isolcpus_advice);
int getNumaNodeForPciDevice(const char *pci_device);


class cHugePagesTools {
public:
	static bool initHugePages(int *hugetlb_fd, u_int64_t *page_size);
	static bool setHugePagesNumber(map<unsigned, unsigned> number_by_numa_node, bool gtIsOk = true, unsigned page_size_kb = 0);
	static bool setHugePagesNumber(unsigned number, bool gtIsOk = true, int numa_node = -1, bool overcommit = false, unsigned page_size_kb = 0);
	static int64_t getHugePagesNumber(int numa_node = -1, bool overcommit = false, unsigned page_size_kb = 0);
	static string getHugePagesConfigFile(int numa_node = -1, bool overcommit = false, unsigned page_size_kb = 0);
	static unsigned getHugePageSize_kB();
	static void dropCaches();
	static void compactMemory();
	static void dropCachesAndCompactMemory();
};


extern "C" {

char *strnstr(const char *haystack, const char *needle, size_t len);
char *strncasestr(const char *haystack, const char *needle, size_t len);
char *strnchr(const char *haystack, char needle, size_t len);
char *strnrchr(const char *haystack, char needle, size_t len);
char *strncasechr(const char *haystack, char needle, size_t len);
size_t strCaseEqLengthR(const char *str1, const char *str2, bool *eqMinLength);
const char *strrstr(const char *haystack, const char *needle);

}


int strcmp_wildcard(const char *s, const char *pattern,
		    const char *one_wc = NULL, const char *multi_wc = NULL,
		    bool ignore_case = false);
inline int strcasecmp_wildcard(const char *s, const char *pattern,
			const char *one_wc = NULL, const char *multi_wc = NULL) {
	return(strcmp_wildcard(s, pattern, one_wc, multi_wc, true));
}
int strncmp_wildcard(const char *s, const char *pattern, size_t len,
                     const char *one_wc = NULL, const char *multi_wc = NULL,
                     bool ignore_case = false);
inline int strncasecmp_wildcard(const char *s, const char *pattern, size_t len,
			 const char *one_wc = NULL, const char *multi_wc = NULL) {
	return(strncmp_wildcard(s, pattern, len, one_wc, multi_wc, true));
}
char *strstr_wildcard(const char *s, const char *pattern,
                      const char *one_wc = NULL, const char *multi_wc = NULL,
                      bool ignore_case = false);
inline char *strcasestr_wildcard(const char *s, const char *pattern,
			  const char *one_wc = NULL, const char *multi_wc = NULL) {
	return(strstr_wildcard(s, pattern, one_wc, multi_wc, true));
}
char *strnstr_wildcard(const char *s, const char *pattern, size_t len,
                       const char *one_wc = NULL, const char *multi_wc = NULL,
                       bool ignore_case = false);
inline char *strncasestr_wildcard(const char *s, const char *pattern, size_t len,
			   const char *one_wc = NULL, const char *multi_wc = NULL) {
	return(strnstr_wildcard(s, pattern, len, one_wc, multi_wc, true));
}


void base64_init(void);
int base64decode(unsigned char *dst, const char *src, int max);
u_char *base64decode(const char *src, int *dst_length);
string base64_decode(const char *src);
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
			if(!(::isprint(str[i]) || str[i] == '\r' || str[i] == '\n')) {
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
				char *buff = new char[l];
				int length = base64decode((u_char*)buff, in + 5, l);
				str = string(buff, length);
				delete [] buff;
				is_null = false;
				return;
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
	json_type getType() { return(type); }
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
	json_type type;
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
	void add(const char *name, double content) { add_float(name, content); } 
	void add_int(const char *name, int64_t content);
	void add_float(const char *name, double content);
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

string escapeShellArgument(string str);
bool needShellEscape(const string &str);
string escapeShellPath(const string &str);

string intToString(short int i);
string intToString(int i);
string intToString(long int i);
string intToString(long long int i);
string intToString(unsigned short int i);
string intToString(unsigned int i);
string intToString(unsigned long int i);
string intToString(unsigned long long int i);
string intToStringHex(int i);
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
std::vector<std::string> split2chars(const std::string &s);

struct sNoSplitBorders {
	sNoSplitBorders(const char *left, const char *right, bool remove_borders = false) 
	 : left(left), right(right), remove_borders(remove_borders) {}
	string left;
	string right;
	bool remove_borders;
};
std::vector<string> split_ext(const char *str, std::vector<string> &delimiters, std::vector<sNoSplitBorders> *no_split_borders, bool enableTrim = false, bool useEmptyItems = false);

bool check_regexp(const char *pattern);
int reg_match(const char *string, const char *pattern, const char *file = NULL, int line = 0);
int reg_match(const char *str, const char *pattern, vector<string> *matches, bool ignoreCase, const char *file = NULL, int line = 0);
string reg_replace(const char *string, const char *pattern, const char *replace, const char *file = NULL, int line = 0);
bool reg_pattern_contain_subresult(const char *pattern);

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
	void add(SimpleBuffer *data) {
		if(data->bufferLength > 0) {
			add(data->buffer, data->bufferLength);
		}
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
	void set_data_len(u_int32_t bufferLength) {
		if(bufferCapacity < bufferLength) {
			set_data_capacity(bufferLength);
		}
		this->bufferLength = bufferLength;
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
	bool contains(u_char *data, unsigned len, bool at_begin = false) {
		return(at_begin ?
			bufferLength >= len && !memcmp(buffer, data, len) :
			memmem(buffer, bufferLength, data, len) != NULL);
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
	bool writeToFile(const char *file) {
		if(!size()) {
			return(false);
		}
		bool rslt = false;
		FILE *fh = fopen(file, "w");
		if(fh) {
			rslt = fwrite(data(), 1, size(), fh) == size();
			fclose(fh);
		}
		return(rslt);
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
	static bool isCompress(u_char *buffer, size_t bufferLength);
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


#ifdef HAVE_LIBZSTD
class cZstd {
public:
	cZstd();
	~cZstd();
public:
	bool compress(u_char *buffer, size_t bufferLength, u_char **cbuffer, size_t *cbufferLength);
	bool compress_simple(u_char *buffer, size_t bufferLength, u_char **cbuffer, size_t *cbufferLength);
	bool compressString(string &str, u_char **cbuffer, size_t *cbufferLength);
	bool decompress(u_char *buffer, size_t bufferLength, u_char **dbuffer, size_t *dbufferLength);
	bool decompress_simple(u_char *buffer, size_t bufferLength, u_char **dbuffer, size_t *dbufferLength, size_t originalSize = 0);
	string decompressString(u_char *buffer, size_t bufferLength);
	void setLevel(int level);
	void setStrategy(int strategy);
	static bool isCompress(u_char *buffer, size_t bufferLength);
private:
	bool initCompress();
	bool initDecompress();
	void term();
private:
	ZSTD_CCtx *cctx;
	ZSTD_DCtx* dctx;
	u_char *compressBuffer;
	size_t compressBufferLength;
	u_char *decompressBuffer;
	size_t decompressBufferLength;
	int level;
	int strategy;
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
		__SYNC_LOCK_USLEEP(_sync_lock, 100);
	}
	void unlock() {
		__SYNC_UNLOCK(_sync_lock);
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
	bool check2(const char *str);
	string reverse(const char *str);
	bool is_ascii(const char *str);
	string remove_no_ascii(const char *str, const char subst = '_');
	void _remove_no_ascii(const char *str, const char subst = '_');
	int get_max_mb(const char *str);
	void _replace_exceeding_utf8_mb(const char *str, unsigned max_mb, const char subst = '_');
	string replace_exceeding_utf8_mb(const char *str, unsigned max_mb, const char subst = '_');
private:
	bool init();
	void term();
	void lock() {
		__SYNC_LOCK_USLEEP(_sync_lock, 100);
	}
	void unlock() {
		__SYNC_UNLOCK(_sync_lock);
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


inline void vm_prefetch0(const volatile void *p) {
	asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *)p));
}


inline u_int16_t bitmaskshift_16(u_int16_t val, u_int16_t mask) {
	return((ntohs(val) & mask) >> __builtin_ctzll(mask)); 
}

inline u_int32_t bitmaskshift_32(u_int32_t val, u_int32_t mask) {
	return((ntohl(val) & mask) >> __builtin_ctzll(mask)); 
}

inline u_int16_t ntoh16(const void *p) {
    return (u_int16_t)*((const u_int8_t*)(p)+0)<<8|
           (u_int16_t)*((const u_int8_t*)(p)+1)<<0;
}

inline u_int32_t ntoh24(const void *p) {
    return (u_int32_t)*((const u_int8_t*)(p)+0)<<16|
           (u_int32_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int32_t)*((const u_int8_t*)(p)+2)<<0;
}

inline u_int32_t ntoh32(const void *p) {
    return (u_int32_t)*((const u_int8_t*)(p)+0)<<24|
           (u_int32_t)*((const u_int8_t*)(p)+1)<<16|
           (u_int32_t)*((const u_int8_t*)(p)+2)<<8|
           (u_int32_t)*((const u_int8_t*)(p)+3)<<0;
}

inline u_int64_t ntoh40(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+0)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+4)<<0;
}

inline u_int64_t ntoh48(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+0)<<40|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+4)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+5)<<0;
}

inline u_int64_t ntoh56(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+0)<<48|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<40|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+4)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+5)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+6)<<0;
}

inline u_int64_t ntoh64(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+0)<<56|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<48|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<40|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+4)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+5)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+6)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+7)<<0;
}

inline u_int16_t letoh16(const void *p) {
    return (u_int16_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int16_t)*((const u_int8_t*)(p)+0)<<0;
}

inline u_int32_t letoh24(const void *p) {
    return (u_int32_t)*((const u_int8_t*)(p)+2)<<16|
           (u_int32_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int32_t)*((const u_int8_t*)(p)+0)<<0;
}

inline u_int32_t letoh32(const void *p) {
    return (u_int32_t)*((const u_int8_t*)(p)+3)<<24|
           (u_int32_t)*((const u_int8_t*)(p)+2)<<16|
           (u_int32_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int32_t)*((const u_int8_t*)(p)+0)<<0;
}

inline u_int64_t letoh40(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+4)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+0)<<0;
}

inline u_int64_t letoh48(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+5)<<40|
           (u_int64_t)*((const u_int8_t*)(p)+4)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+0)<<0;
}

inline u_int64_t letoh56(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+6)<<48|
           (u_int64_t)*((const u_int8_t*)(p)+5)<<40|
           (u_int64_t)*((const u_int8_t*)(p)+4)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+0)<<0;
}

inline u_int64_t letoh64(const void *p) {
    return (u_int64_t)*((const u_int8_t*)(p)+7)<<56|
           (u_int64_t)*((const u_int8_t*)(p)+6)<<48|
           (u_int64_t)*((const u_int8_t*)(p)+5)<<40|
           (u_int64_t)*((const u_int8_t*)(p)+4)<<32|
           (u_int64_t)*((const u_int8_t*)(p)+3)<<24|
           (u_int64_t)*((const u_int8_t*)(p)+2)<<16|
           (u_int64_t)*((const u_int8_t*)(p)+1)<<8|
           (u_int64_t)*((const u_int8_t*)(p)+0)<<0;
}


template <class type_data>
class cBTree {
public:
	class cBTreeNode {
	public:
		inline cBTreeNode() {
			nodes = NULL;
			data = NULL;
		}
		~cBTreeNode() {
			if(nodes) {
				for(unsigned i = 0; i < 256; i++) {
					if(nodes[i]) {
						delete nodes[i];
					}
				}
				delete [] nodes;
			}
			if(data) {
				delete data;
			}
		}
		inline void add(u_char *key, unsigned key_length, type_data *data) {
			if(key_length > 0) {
				if(!nodes) {
					nodes = new FILE_LINE(0) cBTreeNode*[256];
					memset(nodes, 0, sizeof(cBTreeNode*) * 256);
				}
				if(!nodes[key[0]]) {
					nodes[key[0]] = new FILE_LINE(0) cBTreeNode();
				}
				nodes[key[0]]->add(key + 1, key_length - 1, data);
			} else {
				if(!this->data) {
					this->data = new type_data;
				}
				*this->data = *data;
			}
		}
		inline type_data *get(u_char *key, unsigned key_length) {
			if(key_length > 0) {
				if(nodes && nodes[key[0]]) {
					return(nodes[key[0]]->get(key + 1, key_length - 1));
				} else {
					return(NULL);
				}
			} else {
				return(data);
			}
		}
	public:
		cBTreeNode **nodes;
		type_data *data;
	};
public:
	inline void add(u_char *key, unsigned key_length, type_data data) {
		root.add(key, key_length, &data);
	}
	inline void add(u_char *key, unsigned key_length, type_data *data) {
		root.add(key, key_length, data);
	}
	inline type_data *get(u_char *key, unsigned key_length) {
		return(root.get(key, key_length));
	}
	inline bool check(u_char *key, unsigned key_length) {
		return(root.get(key, key_length) != NULL);
	}
private:
	cBTreeNode root;
};


class cQuickIPfilter {
public:
	inline void add(vmIP ip) {
		filter.add(ip.getPointerToIP_u_char(), ip.bytes(), true);
	}
	inline void add(vmIP *ip) {
		filter.add(ip->getPointerToIP_u_char(), ip->bytes(), true);
	}
	inline bool check(vmIP ip) {
		return(filter.check(ip.getPointerToIP_u_char(), ip.bytes()));
	}
	inline bool check(vmIP *ip) {
		return(filter.check(ip->getPointerToIP_u_char(), ip->bytes()));
	}
public:
	cBTree<bool> filter;
};


class cDbCalls {
public:
	struct sDbCallInfo {
		u_int64_t id;
		u_int64_t calldate;
		int32_t sensor_id;
		bool exists_rtp;
		int operator == (const sDbCallInfo ci) {
			return(calldate == ci.calldate &&
			       sensor_id == ci.sensor_id &&
			       exists_rtp == ci.exists_rtp);
		}
	};
	struct sDbCall : public sDbCallInfo {
		string callid;
	};
public:
	cDbCalls(unsigned max_calls = 0, unsigned max_age_calls = 0);
	void push(const char *callid, u_int64_t calldate, int32_t sensor_id, bool exists_rtp);
	void push(sDbCall *dbCall);
	void pop();
	bool exists(const char *callid, sDbCallInfo *db_call_info = NULL);
	void lock() {
		__SYNC_LOCK(_sync);
	}
	void unlock() {
		__SYNC_UNLOCK(_sync);
	}
private:
	unsigned max_calls;
	unsigned max_age_calls;
	queue<sDbCall> calls_queue;
	map<string, sDbCallInfo> calls_map;
	volatile int _sync;
};


class cNormReftabs {
public:
	struct sParams {
		sParams() {
			number_max_length = 0;
		}
		unsigned number_max_length;
	};
private:
	struct sStringDelim {
		sStringDelim(const char *str, const char *delim) {
			this->str = str;
			this->delim = delim ? delim  : "";
		}
		string str;
		string delim;
	};
public:
	static string sip_response(string value, sParams *params = NULL, bool cmp_log = false);
	static string reason(string value, bool cmp_log = false);
	static string ua(string value, bool cmp_log = false);
	static void trim(string &v, const char *trim_chars = " ") {
		ltrim(v, trim_chars);
		rtrim(v, trim_chars);
	}
private:
	static bool is_ok_ua(string &ua);
	static void split_string_with_delim(string &str, const char *delims, vector<sStringDelim> *string_delim);
	static string join_string_with_delim(vector<sStringDelim> *string_delim);
	static bool is_telnum(string v);
	static bool is_sip_uri(string &v);
	static bool is_reason_tag(string &v);
	static bool is_mac(string &v);
	static bool is_mac_with_prefix(string &v);
	static bool is_ip(string &v);
	static bool is_ip_port(string &v);
	static bool is_sn(string &v);
	static bool check_string(const char *v, bool alpha, bool digit =  false, bool hexalpha = false, const char *other = NULL);
	static bool check_string(string &v, bool alpha, bool digit =  false, bool hexalpha = false, const char *other = NULL);
	static bool check_exists(string &v, bool alpha, bool digit = false, bool hexalpha = false, const char *other = NULL);
	static void ltrim(string &v, const char *trim_chars = " ");
	static void rtrim(string &v, const char *trim_chars = " ");
};

string get_backtrace();


class cBitSet {
public:
	cBitSet(unsigned max, unsigned begin = 0) : max(max), begin(begin) {
		words = ((max - begin) + 63) / 64;
		bits = new u_int64_t[words];
		memset(bits, 0, sizeof(u_int64_t) * words);
	}
	~cBitSet() {
		delete [] bits;
	}
	cBitSet(const cBitSet&) = delete;
	cBitSet& operator = (const cBitSet&) = delete;
	int get() {
		for(unsigned i = 0; i < words; ++i) {
			if(bits[i] != UINT64_MAX) {
				u_int64_t bits_inverted = ~bits[i];
				int bit = __builtin_ffsll(bits_inverted);
				if(bit > 0) {
					int bit_index = bit - 1;
					int v = i * 64 + bit_index;
					if(v >= (int)(max -  begin)) continue;
					bits[i] |= (1ULL << bit_index);
					return(v + begin);
				}
			}
		}
		return(-1);
	}
	bool free(int v) {
		if(v < (int)begin || v >= (int)max) {
			return(false);
		}
		v -= begin;
		int word_index = v / 64;
		int bit_index = v % 64;
		bits[word_index] &= ~(1ULL << bit_index);
		return(true);
	}
private:
	unsigned max;
	unsigned begin;
	unsigned words;
	u_int64_t *bits;
};


#endif
