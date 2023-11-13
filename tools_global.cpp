#include <netdb.h>
#include <json.h>
#include <limits.h>
#include <sstream>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include "tools_global.h"

#ifdef CLOUD_ROUTER_CLIENT
#include "tools.h"
#include "common.h"
cThreadMonitor threadMonitor;
#endif

#ifdef CARESRESOLVER
#include <ares.h>
#endif

#ifdef CARESRESOLVER
static volatile int ares_flag = 0;
#endif

struct vm_pthread_struct {
	void *(*start_routine)(void *arg);
	void *arg;
	string description;
};
void *vm_pthread_create_start_routine(void *arg) {
	vm_pthread_struct thread_data = *(vm_pthread_struct*)arg;
	delete (vm_pthread_struct*)arg;
	int tid = get_unix_tid();
	#ifdef CLOUD_ROUTER_CLIENT
	if(sverb.thread_create) {
		syslog(LOG_NOTICE, "start thread '%s' %i", 
		       thread_data.description.c_str(), tid);
	}
	threadMonitor.registerThread(tid, thread_data.description.c_str());
	#endif
	void *rslt = thread_data.start_routine(thread_data.arg);
	#ifdef CLOUD_ROUTER_CLIENT
	termTimeCacheForThread();
	threadMonitor.unregisterThread(tid);
	if(sverb.thread_create) {
		syslog(LOG_NOTICE, "end thread '%s'", 
		       thread_data.description.c_str());
	}
	#endif
	return(rslt);
}
int vm_pthread_create(const char *thread_description,
		      pthread_t *thread, pthread_attr_t *attr,
		      void *(*start_routine) (void *), void *arg,
		      const char *src_file, int src_file_line, bool autodestroy) {
	#ifdef CLOUD_ROUTER_CLIENT
	if(sverb.thread_create && src_file && src_file_line) {
		syslog(LOG_NOTICE, "create thread '%s' %sfrom %s : %i", 
		       thread_description, autodestroy ? "(autodestroy) " : "", src_file, src_file_line);
	}
	#endif
	bool create_attr = false;
	pthread_attr_t _attr;
	if(!attr && autodestroy) {
		pthread_attr_init(&_attr);
		pthread_attr_setdetachstate(&_attr, PTHREAD_CREATE_DETACHED);
		create_attr = true;
		attr = &_attr;
	}
	vm_pthread_struct *thread_data = new FILE_LINE(0) vm_pthread_struct;
	thread_data->start_routine = start_routine;
	thread_data->arg = arg;
	thread_data->description = thread_description;
	int rslt = pthread_create(thread, attr, vm_pthread_create_start_routine, thread_data);
	if(create_attr) {
		pthread_attr_destroy(&_attr);
	}
	#ifdef CLOUD_ROUTER_CLIENT
	extern bool opt_use_thread_setname;
	if(opt_use_thread_setname && thread_description) {
		char thread_name[16];
		strncpy(thread_name, thread_description, sizeof(thread_name) - 1);
		thread_name[sizeof(thread_name) - 1] = 0;
		pthread_setname_np(*thread, thread_name);
	}
	extern string opt_cpu_cores;
	extern bool opt_use_dpdk;
	if(!opt_cpu_cores.empty()) {
		vector<int> cpu_cores;
		get_list_cores(opt_cpu_cores, cpu_cores);
		pthread_set_affinity(*thread, &cpu_cores, NULL);
	} else if(opt_use_dpdk) {
		extern string get_dpdk_cpu_cores(bool without_main, bool detect_ht);
		extern bool opt_thread_affinity_ht;
		string dpdk_cpu_cores_str = get_dpdk_cpu_cores(true, opt_thread_affinity_ht);
		if(!dpdk_cpu_cores_str.empty()) {
			vector<int> cpu_cores;
			get_list_cores("all", cpu_cores);
			vector<int> dpdk_cpu_cores;
			get_list_cores(dpdk_cpu_cores_str, dpdk_cpu_cores);
			pthread_set_affinity(*thread, &cpu_cores, &dpdk_cpu_cores);
		}
	}
	#endif
	return(rslt);
}

bool pthread_set_affinity(pthread_t thread, vector<int> *cores_set, vector<int> *cores_unset) {
	map<int, bool> cpuset_map;
	for(unsigned i = 0; i < cores_set->size(); i++) {
		cpuset_map[(*cores_set)[i]] = true;
	}
	if(cores_unset) {
		for(unsigned i = 0; i < cores_unset->size(); i++) {
			cpuset_map[(*cores_unset)[i]] = false;
		}
	}
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	for(map<int, bool>::iterator iter = cpuset_map.begin(); iter != cpuset_map.end(); iter++) {
		if(iter->second) {
			CPU_SET(iter->first, &cpuset);
		}
	}
	return(pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) == 0);
}

bool pthread_set_priority(pthread_t thread, int tid, int sched_type, int priority) {
	if(sched_type == 100) {
		int rslt_set = setpriority(PRIO_PROCESS, tid, priority);
		if(rslt_set != 0) {
			syslog(LOG_NOTICE, "failed (error %i) to set priority for thread %i", rslt_set, tid);
			return(false);
		} else {
			return(true);
		}
	}
	if(priority == -1) {
		priority = sched_get_priority_max(sched_type);
		if(priority == -1) {
			syslog(LOG_NOTICE, "failed to get max priority for '%s' for thread %i", get_sched_type_str(sched_type).c_str(), tid);
			return(false);
		}
	}
	sched_param sch_param; 
	sch_param.sched_priority = priority;
	int rslt_set = pthread_setschedparam(thread, sched_type, &sch_param);
	if(rslt_set != 0) {
		syslog(LOG_NOTICE, "failed (error %i) to set scheduler parameters for thread %i", rslt_set, tid);
		return(false);
	} else {
		return(true);
	}
}

bool pthread_set_priority(int sched_type, int priority) {
	return(pthread_set_priority(pthread_self(), get_unix_tid(), sched_type, priority));
}

bool pthread_set_priority(const char *sched_type_priority) {
	if(!sched_type_priority || !*sched_type_priority) {
		return(false);
	}
	int sched_type;
	int priority;
	if(!parse_sched_type_priority(sched_type_priority, &sched_type, &priority)) {
		return(false);
	}
	return(pthread_set_priority(pthread_self(), get_unix_tid(), sched_type, priority));
}

bool parse_sched_type_priority(const char *sched_type_priority, int *sched_type_out, int *priority_out) {
	string sched_type_str;
	string priority_str;
	const char *p = sched_type_priority;
	while(*p) {
		if(isalpha(*p)) {
			sched_type_str += *p;
		} else if(isdigit(*p) || *p == '-') {
			priority_str += *p;
		}
		++p;
	}
	int sched_type = get_sched_type_from_str(sched_type_str.c_str());
	if(sched_type == -1) {
		syslog(LOG_NOTICE, "unknown schedule policy %s", sched_type_str.c_str());
		*sched_type_out = -1;
		*priority_out = -1;
		return(false);
	}
	*sched_type_out = sched_type;
	*priority_out = atoi(priority_str.c_str());
	return(true);
}

string get_sched_type_str(int sched_type) {
	if (sched_type == 100) return "prio";
	#ifdef SCHED_OTHER
	if (sched_type == SCHED_OTHER) return "other";
	#endif
	#ifdef SCHED_FIFO
	if (sched_type == SCHED_FIFO) return "fifo";
	#endif
	#ifdef SCHED_RR
	if (sched_type == SCHED_RR) return "rr";
	#endif
	#ifdef SCHED_BATCH
	if (sched_type == SCHED_BATCH) return "batch";
	#endif
	#ifdef SCHED_ISO
	if (sched_type == SCHED_ISO) return "iso";
	#endif
	#ifdef SCHED_IDLE
	if (sched_type == SCHED_IDLE) return "idle";
	#endif
	#ifdef SCHED_DEADLINE
	if (sched_type == SCHED_DEADLINE) return "deadl";
	#endif
	return "?";
}

int get_sched_type_from_str(const char *sched_type) {
	if (strcasestr(sched_type, "prio")) return 100;
	#ifdef SCHED_OTHER
	if (strcasestr(sched_type, "other")) return SCHED_OTHER;
	#endif
	#ifdef SCHED_FIFO
	if (strcasestr(sched_type, "fifo")) return SCHED_FIFO;
	#endif
	#ifdef SCHED_RR
	if (strcasestr(sched_type, "rr")) return SCHED_RR;
	#endif
	#ifdef SCHED_BATCH
	if (strcasestr(sched_type, "batch")) return SCHED_BATCH;
	#endif
	#ifdef SCHED_ISO
	if (strcasestr(sched_type, "iso")) return SCHED_ISO;
	#endif
	#ifdef SCHED_IDLE
	if (strcasestr(sched_type, "idle")) return SCHED_IDLE;
	#endif
	#ifdef SCHED_DEADLINE
	if (strcasestr(sched_type, "deadl")) return SCHED_DEADLINE;
	#endif
	return -1;
}

void get_list_cores(string input, vector<int> &list) {
	int count_cores = sysconf(_SC_NPROCESSORS_ONLN);
	if(input == "all") {
		for(int i = 0; i < count_cores; i++) {
			list.push_back(i);
		}
		return;
	}
	while(input.length() && (input[0] == '(' || input[0] == ' ')) {
		input = input.substr(1);
	}
	while(input.length() && (input[input.length() - 1] == '(' || input[input.length() - 1] == ' ')) {
		input = input.substr(0, input.length() - 1);
	}
	map<int, bool> list_map;
	vector<string> input_v;
	split(input.c_str(), ",", input_v, true);
	for(unsigned i = 0; i < input_v.size(); i++) {
		vector<string> input_item_v;
		split(input_v[i].c_str(), "-", input_item_v, true);
		if(input_item_v.size() == 1) {
			int core = atoi(input_item_v[0].c_str());
			if(core >= 0 && core < count_cores) {
				list_map[core] = true;
			}
		} else if(input_item_v.size() == 2) {
			int core_from = atoi(input_item_v[0].c_str());
			int core_to = atoi(input_item_v[1].c_str());
			if(core_from <= core_to) {
				for(int core = core_from; core <= core_to; core++) {
					if(core >= 0 && core < count_cores) {
						list_map[core] = true;
					}
				}
			}
		}
	}
	for(map<int, bool>::iterator iter = list_map.begin(); iter != list_map.end(); iter++) {
		if(iter->second) {
			list.push_back(iter->first);
		}
	}
}

void get_list_cores(string input, list<int> &list) {
	vector<int> _list;
	get_list_cores(input, _list);
	for(unsigned i = 0; i < _list.size(); i++) {
		list.push_back(_list[i]);
	}
}


cCpuCoreInfo::cCpuCoreInfo() {
	load();
}

void cCpuCoreInfo::load() {
	map_cpu_core_info.clear();
	FILE *cmd_pipe;
	cmd_pipe = popen("lscpu -p", "r");
	if(cmd_pipe) {
		vector<string> columns;
		char bufRslt[512];
		while(fgets(bufRslt, sizeof(bufRslt), cmd_pipe)) {
			int length = strlen(bufRslt);
			while(length > 0 && bufRslt[length - 1] == '\n') {
				bufRslt[length - 1] = 0;
				--length;
			}
			if(bufRslt[0] == '#') {
				if(!strncasecmp(bufRslt, "# CPU", 5)) {
					columns = split(bufRslt + 2, ',');
				}
			} else if(isdigit(bufRslt[0])) {
				vector<string> row;
				row = split(bufRslt, ',');
				sCpuCoreInfo ci;
				bool setCpu = false;
				for(unsigned i = 0; i < min(columns.size(), row.size()); i++) {
					int columnValue = atoi(row[i].c_str());
					if(!strcasecmp(columns[i].c_str(), "cpu")) {
						ci.CPU = columnValue;
						setCpu = true;
					} else if(!strcasecmp(columns[i].c_str(), "core")) {
						ci.Core = columnValue;
					} else if(!strcasecmp(columns[i].c_str(), "socket")) {
						ci.Socket = columnValue;
					} else if(!strcasecmp(columns[i].c_str(), "node")) {
						ci.Node = columnValue;
					} else if(!strcasecmp(columns[i].c_str(), "l1d")) {
						ci.L1d = columnValue;
					} else if(!strcasecmp(columns[i].c_str(), "l1i")) {
						ci.L1i = columnValue;
					} else if(!strcasecmp(columns[i].c_str(), "l2")) {
						ci.L2 = columnValue;
					} else if(!strcasecmp(columns[i].c_str(), "l3")) {
						ci.L3 = columnValue;
					}
				}
				if(setCpu) {
					map_cpu_core_info[ci.CPU] = ci;
				}
			}
		}
		pclose(cmd_pipe);
	}
}

bool cCpuCoreInfo::ok_loaded() {
	return(map_cpu_core_info.size() > 0);
}

cCpuCoreInfo::sCpuCoreInfo *cCpuCoreInfo::get(int cpu) {
	map<int, sCpuCoreInfo>::iterator iter = map_cpu_core_info.find(cpu); 
	if(iter != map_cpu_core_info.end()) {
		return(&iter->second);
	}
	return(NULL);
}

bool cCpuCoreInfo::getHT_cpus(int cpu, vector<int> *ht_cpus) {
	sCpuCoreInfo *cpu_core_info = get(cpu);
	if(!cpu_core_info) {
		return(false);
	}
	for(map<int, sCpuCoreInfo>::iterator iter = map_cpu_core_info.begin(); iter != map_cpu_core_info.end(); iter++) {
		if(cpu_core_info->Core == iter->second.Core &&
		   cpu_core_info->Socket == iter->second.Socket) {
			ht_cpus->push_back(iter->second.CPU);
		}
	}
	return(ht_cpus->size() > 0);
}

int cCpuCoreInfo::getHT_index(int cpu) {
	vector<int> ht_cpus;
	if(!getHT_cpus(cpu, &ht_cpus)) {
		return(-1);
	}
	for(unsigned i = 0; i < ht_cpus.size(); i++) {
		if(ht_cpus[i] == cpu) {
			return(i);
		}
	}
	return(-1);
}


int setAffinityForOtherProcesses(vector<int> *excluded_cpus, bool only_check, bool log, const char *log_prefix, bool isolcpus_advice) {
	int main_pid = getpid();
	vector<int> other_processes;
	FILE *cmd_pipe = popen("ps -ax -o pid,tid,cmd", "r");
	if(cmd_pipe) {
		char buffRslt[512];
		while(fgets(buffRslt, 512, cmd_pipe)) {
			int buffRsltLength = strlen(buffRslt);
			while(buffRsltLength > 0 && buffRslt[buffRsltLength - 1] == '\n') {
				buffRslt[buffRsltLength - 1] = 0;
				--buffRsltLength;
			}
			if(buffRsltLength > 0) {
				int beginDigitOffsets[2] = { -1, -1 };
				for(int i = 0, j = 0; i < buffRsltLength; i++) {
					if(isdigit(buffRslt[i])) {
						beginDigitOffsets[j++] = i;
						if(j == 2) {
							break;
						}
						while(i < buffRsltLength - 1 && isdigit(buffRslt[i + 1])) {
							++i;
						}
					}
				}
				if(beginDigitOffsets[1] > 0) {
					int beginCmdOffset = beginDigitOffsets[1];
					while(beginCmdOffset < buffRsltLength && isdigit(buffRslt[beginCmdOffset])) {
						++beginCmdOffset;
					}
					while(beginCmdOffset < buffRsltLength && (buffRslt[beginCmdOffset] == ' ' || buffRslt[beginCmdOffset] == '\t')) {
						++beginCmdOffset;
					}
					int pid = atoi(buffRslt + beginDigitOffsets[0]);
					if(pid > 1 && pid != main_pid && buffRslt[beginCmdOffset] != '[') {
						int tid = atoi(buffRslt + beginDigitOffsets[1]);
						other_processes.push_back(tid);
					}
				}
			}
		}
		pclose(cmd_pipe);
	} else {
		return(-1);
	}
	int conflict_processes_count = 0;
	int conflict_processes_ok_set_count = 0;
	if(other_processes.size()) {
		for(unsigned i = 0; i < other_processes.size(); i++) {
			cpu_set_t cpuset;
			CPU_ZERO(&cpuset);
			if(!sched_getaffinity(other_processes[i], sizeof(cpu_set_t), &cpuset)) {
				map<int, bool> affinity;
				for(int i = 0; i < CPU_COUNT(&cpuset); i++) {
					if(CPU_ISSET(i, &cpuset)) {
						affinity[i] = true;
					}
				}
				if(affinity.size() > 1) {
					bool conflict = false;
					for(unsigned i = 0; i < excluded_cpus->size(); i++) {
						if(affinity[(*excluded_cpus)[i]]) {
							conflict = true;
							if(!only_check) {
								affinity[(*excluded_cpus)[i]] = false;
							}
						}
					}
					if(conflict) {
						++conflict_processes_count;
						if(!only_check) {
							CPU_ZERO(&cpuset);
							for(map<int, bool>::iterator iter = affinity.begin(); iter != affinity.end(); iter++) {
								if(iter->second) {
									CPU_SET(iter->first, &cpuset);
								}
							}
							if(!sched_setaffinity(other_processes[i], sizeof(cpu_set_t), &cpuset)) {
								++conflict_processes_ok_set_count;
							}
						}
					}
				}
			}
		}
	}
	if(log && conflict_processes_count) {
		ostringstream ostr;
		if(log_prefix) {
			ostr << log_prefix;
		}
		ostr << conflict_processes_count << " other processes seem to have conflicting cpu affinity settings";
		if(conflict_processes_ok_set_count) {
			ostr << "; " << conflict_processes_ok_set_count << " of them have had cpu affinity adjusted";
		}
		if(isolcpus_advice) {
			ostr << "; we recommend setting the kernel parameter isolcpus=";
			for(unsigned i = 0; i < excluded_cpus->size(); i++) {
				if(i > 0) ostr << ",";
				ostr << (*excluded_cpus)[i];
			}
		}
		syslog(LOG_WARNING, "%s", ostr.str().c_str());
	}
	return(only_check ? 
		conflict_processes_count == 0 :
		conflict_processes_count == 0 || conflict_processes_ok_set_count == conflict_processes_count);
}


JsonItem::JsonItem(string name, string value, bool null) {
	this->name = name;
	this->value = value;
	this->null = null;
	this->parse(value);
}

void JsonItem::parse(string valStr) {
	////cerr << "valStr: " << valStr << endl;
	if(!((valStr[0] == '{' && valStr[valStr.length() - 1] == '}') ||
	     (valStr[0] == '[' && valStr[valStr.length() - 1] == ']'))) {
		return;
	}
	json_object * object = json_tokener_parse(valStr.c_str());
	if(!object) {
		return;
	}
	json_type objectType = json_object_get_type(object);
	////cerr << "type: " << objectType << endl;
	if(objectType == json_type_object) {
		lh_table *objectItems = json_object_get_object(object);
		struct lh_entry *objectItem = objectItems->head;
		while(objectItem) {
			string fieldName = (char*)objectItem->k;
			string value;
			bool null = false;
			if(objectItem->v) {
				if(json_object_get_type((json_object*)objectItem->v) == json_type_null) {
					null = true;
				} else {
					value = json_object_get_string((json_object*)objectItem->v);
				}
			} else {
				null = true;
			}
			////cerr << "objectItem: " << fieldName << " - " << (null ? "NULL" : value) << endl;
			JsonItem newItem(fieldName, value, null);
			this->items.push_back(newItem);
			objectItem = objectItem->next;
		}
	} else if(objectType == json_type_array) {
		int length = json_object_array_length(object);
		for(int i = 0; i < length; i++) {
			json_object *obj = json_object_array_get_idx(object, i);
			string value;
			bool null = false;
			if(obj) {
				if(json_object_get_type(obj) == json_type_null) {
					null = true;
				} else {
					value = json_object_get_string(obj);
				}
				////cerr << "arrayItem: " << i << " - " << (null ? "NULL" : value) << endl;
			} else {
				null = true;
			}
			stringstream streamIndexName;
			streamIndexName << i;
			JsonItem newItem(streamIndexName.str(), value, null);
			this->items.push_back(newItem);
		}
	}
	json_object_put(object);
}

JsonItem *JsonItem::getItem(string path, int index) {
	if(index >= 0) {
		stringstream streamIndexName;
		streamIndexName << index;
		path += '/' + streamIndexName.str();
	}
	JsonItem *item = this->getPathItem(path);
	if(item) {
		string pathItemName = this->getPathItemName(path);
		if(path.length()>pathItemName.length()) {
			return(item->getItem(path.substr(pathItemName.length()+1)));
		} else {
			return(item);
		}
	}
	return(NULL);
}

string JsonItem::getValue(string path, int index) {
	JsonItem *item = this->getItem(path, index);
	return(item ? item->value : "");
}

int JsonItem::getCount(string path) {
	JsonItem *item = this->getItem(path);
	return(item ? item->items.size() : 0);
}

JsonItem *JsonItem::getPathItem(string path) {
	string pathItemName = this->getPathItemName(path);
	for(int i = 0; i < (int)this->items.size(); i++) {
		if(this->items[i].name == pathItemName) {
			return(&this->items[i]);
		}
	}
	return(NULL);
}

string JsonItem::getPathItemName(string path) {
	string pathItemName = path;
	int sepPos = pathItemName.find('/');
	if(sepPos > 0) {
		pathItemName.resize(sepPos);
	}
	return(pathItemName);
}


JsonExport::JsonExport() {
	typeItem = _object;
}

JsonExport::~JsonExport() {
	while(items.size()) {
		delete (*items.begin());
		items.erase(items.begin());
	}
}

string JsonExport::getJson(JsonExport */*parent*/) {
	ostringstream outStr;
	if(!name.empty()) {
		outStr << '\"' << name << "\":";
	}
	if(typeItem == _object) {
		outStr << '{';
	} else if(typeItem == _array) {
		outStr << '[';
	}
	vector<JsonExport*>::iterator iter;
	for(iter = items.begin(); iter != items.end(); iter++) {
		if(iter != items.begin()) {
			outStr << ',';
		}
		outStr << (*iter)->getJson(this);
	}
	if(typeItem == _object) {
		outStr << '}';
	} else if(typeItem == _array) {
		outStr << ']';
	}
	return(outStr.str());
}

void JsonExport::add(const char *name, string content, eTypeItem typeItem) {
	this->add(name, content.c_str(), typeItem);
}

void JsonExport::add(const char *name, const char *content, eTypeItem typeItem) {
	JsonExport_template<string> *item = new FILE_LINE(38010) JsonExport_template<string>;
	item->setTypeItem(typeItem);
	item->setName(name);
	item->setContent(json_string_escape(content));
	items.push_back(item);
}

void JsonExport::add_int(const char *name, int64_t content) {
	JsonExport_template<int64_t> *item = new FILE_LINE(0) JsonExport_template<int64_t>;
	item->setTypeItem(_number);
	item->setName(name);
	item->setContent(content);
	items.push_back(item);
}

void JsonExport::add(const char *name) {
	JsonExport_template<string> *item = new FILE_LINE(38011) JsonExport_template<string>;
	item->setTypeItem(_null);
	item->setName(name);
	item->setContent("null");
	items.push_back(item);
}

JsonExport *JsonExport::addArray(const char *name) {
	JsonExport *item = new FILE_LINE(38012) JsonExport;
	item->setTypeItem(_array);
	item->setName(name);
	items.push_back(item);
	return(item);
}

JsonExport *JsonExport::addObject(const char *name) {
	JsonExport *item = new FILE_LINE(38013) JsonExport;
	item->setTypeItem(_object);
	item->setName(name);
	items.push_back(item);
	return(item);
}

void JsonExport::addJson(const char *name, const string &content) {
	this->addJson(name, content.c_str());
}

void JsonExport::addJson(const char *name, const char *content) {
	JsonExport_template<string> *item = new FILE_LINE(38014) JsonExport_template<string>;
	item->setTypeItem(_json);
	item->setName(name);
	item->setContent(string(content));
	items.push_back(item);
}

template <class type_item>
string JsonExport_template<type_item>::getJson(JsonExport *parent) {
	ostringstream outStr;
	if(parent->getTypeItem() != _array || !name.empty()) {
		outStr << '\"' << name << "\":";
	}
	if(typeItem == _null) {
		outStr << "null";
	} else {
		if(typeItem == _string) {
			outStr << '\"';
		}
		outStr << content;
		if(typeItem == _string) {
			outStr << '\"';
		}
	}
	return(outStr.str());
}


string json_string_escape(const char *str) {
	string str_esc;
	const char *ptr = str;
	while(*ptr) {
		switch (*ptr) {
		case '\\':	str_esc += "\\\\"; break;
		case '"':	str_esc += "\\\""; break;
		case '/':	str_esc += "\\/"; break;
		case '\b':	str_esc += "\\b"; break;
		case '\f':	str_esc += "\\f"; break;
		case '\n':	str_esc += "\\n"; break;
		case '\r':	str_esc += "\\r"; break;
		case '\t':	str_esc += "\\t"; break;
		default:	str_esc += *ptr; break;
		}
		++ptr;
	}
	return(str_esc);
}


string intToString(short int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(long int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(long long int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(unsigned short int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(unsigned int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(unsigned long int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(unsigned long long int i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToStringHex(int i) {
	ostringstream outStr;
	outStr << hex << i;
	return(outStr.str());
}

string floatToString(double d) {
	ostringstream outStr;
	outStr << fixed;
	outStr << d;
	return(outStr.str());
}

string floatToString(double d, unsigned precision, bool adjustDec) {
	ostringstream outStr;
	outStr << fixed << setprecision(precision);
	outStr << d;
	string rslt = outStr.str();
	if(adjustDec && rslt.find('.') != string::npos) {
		while(rslt[rslt.length() - 1] == '0') {
			rslt.resize(rslt.length() - 1);
		}
		if(rslt[rslt.length() - 1] == '.') {
			rslt.resize(rslt.length() - 1);
		}
	}
	return(rslt);
}

string pointerToString(void *p) {
	char buff[100];
	snprintf(buff, sizeof(buff), "%p", p);
	buff[sizeof(buff) - 1] = 0;
	return(buff);
}

string boolToString(bool b) {
	if (b) {
		return("true");
	} else  {
		return("false");
	}
}


void xorData(u_char *data, size_t dataLen, const char *key, size_t keyLength, size_t initPos) {
	for(size_t i = 0; i < dataLen; i++) {
		data[i] = data[i] ^ key[(initPos + i) % keyLength];
	}
}


#ifdef CLOUD_ROUTER_CLIENT
struct sUsleepStatsId {
	string file;
	int line;
	int tid;
	unsigned int us;
	bool operator < (const sUsleepStatsId& other) const { 
		return(this->file < other.file ? 1 : this->file > other.file ? 0 :
		       this->line < other.line ? 1 : this->line > other.line ? 0 :
		       this->tid < other.tid ? 1 : this->tid > other.tid ? 0 :
		       this->us < other.us); 
	}
};
struct sUsleepStatsIdCnt {
	sUsleepStatsId id;
	unsigned int cnt;
	bool operator < (const sUsleepStatsIdCnt& other) const { 
		return(this->cnt < other.cnt); 
	}
};

static map<sUsleepStatsId, unsigned int> usleepStats;
static volatile int usleepStatsSync;

void usleep_stats_add(unsigned int useconds, bool fix, const char *file, int line) {
	extern bool opt_usleep_stats;
	if(opt_usleep_stats) {
		static __thread unsigned int tid = 0;
		if(!tid) {
			tid = get_unix_tid();
		}
		sUsleepStatsId id;
		id.file = file;
		id.line = line;
		id.tid = tid;
		id.us = fix ? 
			 useconds :
			 (useconds < 10 ? useconds :
			  useconds < 100 ? useconds / 10 * 10 :
			  useconds / 100 * 100);
		__SYNC_LOCK_QUICK(usleepStatsSync);
		++usleepStats[id];
		__SYNC_UNLOCK(usleepStatsSync);
	}
	if(sverb.usleep_stat) {
		static __thread cThreadMonitor::sThread *thread = NULL;
		if(!thread) {
			thread = threadMonitor.getSelfThread();
		}
		if(thread) {
			thread->usleep_sum += useconds;
		}
	}
}

string usleep_stats(unsigned int useconds_lt) {
	extern bool opt_usleep_stats;
	if(opt_usleep_stats) {
		list<sUsleepStatsIdCnt> _usleepStat;
		__SYNC_LOCK(usleepStatsSync);
		for(map<sUsleepStatsId, unsigned int>::iterator iter = usleepStats.begin(); iter != usleepStats.end(); iter++) {
			if(useconds_lt && iter->first.us >= useconds_lt) {
				continue;
			}
			sUsleepStatsIdCnt idCnt;
			idCnt.id = iter->first;
			idCnt.cnt = iter->second;
			_usleepStat.push_back(idCnt);
		}
		__SYNC_UNLOCK(usleepStatsSync);
		if(_usleepStat.size()) {
			_usleepStat.sort();
			ostringstream outStr;
			list<sUsleepStatsIdCnt>::iterator iter = _usleepStat.end();
			do {
				--iter;
				outStr << fixed
				       << left << setw(20) << iter->id.file << " : " 
				       << right << setw(6) << iter->id.line << " (" 
				       << right << setw(6) << iter->id.tid << ") " 
				       << right << setw(7) << iter->id.us << "us" 
				       << right << setw(20) << iter->cnt
				       << endl;
			} while(iter != _usleepStat.begin());
			return(outStr.str());
		} else  {
			return("usleep stat is empty\n");
		}
	} else {
		return("usleep stat is not activated\n");
	}
}

void usleep_stats_clear() {
	__SYNC_LOCK(usleepStatsSync);
	usleepStats.clear();
	__SYNC_UNLOCK(usleepStatsSync);
}
#endif


static char base64[64];
static char b2a[256];

void base64_init(void)
{
        int x;
        memset(b2a, -1, sizeof(b2a));
        /* Initialize base-64 Conversion table */
        for (x = 0; x < 26; x++) {
                /* A-Z */
                base64[x] = 'A' + x;
                b2a['A' + x] = x;
                /* a-z */
                base64[x + 26] = 'a' + x;
                b2a['a' + x] = x + 26;
                /* 0-9 */
                if (x < 10) {
                        base64[x + 52] = '0' + x;
                        b2a['0' + x] = x + 52;
                }      
        }      
        base64[62] = '+';
        base64[63] = '/';
        b2a[(int)'+'] = 62;
        b2a[(int)'/'] = 63;
}      

/*! \brief decode BASE64 encoded text */
int base64decode(unsigned char *dst, const char *src, int max)
{
        int cnt = 0;
        unsigned int byte = 0;
        unsigned int bits = 0;
        int incnt = 0;
        while(*src && *src != '=' && (cnt < max)) {
                /* Shift in 6 bits of input */
                byte <<= 6;
                byte |= (b2a[(int)(*src)]) & 0x3f;
                bits += 6;
                src++;
                incnt++;
                /* If we have at least 8 bits left over, take that character 
                   off the top */
                if (bits >= 8)  {
                        bits -= 8;
                        *dst = (byte >> bits) & 0xff;
                        dst++;
                        cnt++;
                }
        }
        /* Dont worry about left over bits, they're extra anyway */
        return cnt;
}

u_char *base64decode(const char *src, int *dst_length) {
	int src_length = strlen(src);
	unsigned char *dst = new FILE_LINE(0) u_char[src_length * 3];
	*dst_length = base64decode(dst, src, src_length);
	return(dst);
}

string base64_encode(const unsigned char *data, size_t input_length) {
	if(!input_length) {
		input_length = strlen((char*)data);
	}
	size_t output_length;
	char *encoded_data = base64_encode(data, input_length, &output_length);
	if(encoded_data) {
		string encoded_string = encoded_data;
		delete [] encoded_data;
		return(encoded_string);
	} else {
		return("");
	}
}

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
	*output_length = 4 * ((input_length + 2) / 3);
	char *encoded_data = new FILE_LINE(38028) char[*output_length + 1];
	if(encoded_data == NULL) return NULL;
	_base64_encode(data, input_length, encoded_data, *output_length);
	return encoded_data;
}

void _base64_encode(const unsigned char *data, size_t input_length, char *encoded_data, size_t output_length) {
	char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
				 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
				 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
				 'w', 'x', 'y', 'z', '0', '1', '2', '3',
				 '4', '5', '6', '7', '8', '9', '+', '/'};
	int mod_table[] = {0, 2, 1};
	for(size_t i = 0, j = 0; i < input_length;) {
	    uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
	    uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
	    uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
	    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
	    encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
	    encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
	    encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
	    encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}
	if(!output_length) {
		output_length = 4 * ((input_length + 2) / 3);
	}
	for(int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[output_length - 1 - i] = '=';
	encoded_data[output_length] = 0;
}


string &find_and_replace(string &source, const string find, string replace, unsigned *counter_replace) {
	if(counter_replace) {
		*counter_replace = 0;
	}
 	size_t j = 0;
	for ( ; (j = source.find( find, j )) != string::npos ; ) {
		source.replace( j, find.length(), replace );
		j += replace.length();
		if(counter_replace) {
			++*counter_replace;
		}
	}
	return(source);
}

string find_and_replace(const char *source, const char *find, const char *replace, unsigned *counter_replace) {
	string s_source = source;
	find_and_replace(s_source, find, replace, counter_replace);
	return(s_source);
}

string &find_and_replace_all(string &source, const string find, string replace) {
	unsigned counter_replace;
	do {
		find_and_replace(source, find, replace, &counter_replace);
	} while(counter_replace > 0);
	return(source);
}


std::string &trim(std::string &s, const char *trimChars) {
	if(!s.length()) {
		 return(s);
	}
	if(!trimChars) {
		trimChars = "\r\n\t ";
	}
	size_t length = s.length();
	size_t trimCharsLeft = 0;
	while(trimCharsLeft < length && strchr(trimChars, s[trimCharsLeft])) {
		++trimCharsLeft;
	}
	if(trimCharsLeft) {
		s = s.substr(trimCharsLeft);
		length = s.length();
	}
	size_t trimCharsRight = 0;
	while(trimCharsRight < length && strchr(trimChars, s[length - trimCharsRight - 1])) {
		++trimCharsRight;
	}
	if(trimCharsRight) {
		s = s.substr(0, length - trimCharsRight);
	}
	return(s);
}

std::string trim_str(std::string s, const char *trimChars) {
	return(trim(s, trimChars));
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

std::vector<std::string> &split(const char *s, const char *delim, std::vector<std::string> &elems, bool enableTrim, bool useEmptyItems) {
	char *p = (char*)s;
	int delim_length = strlen(delim);
	while(p) {
		char *next_delim = strstr(p, delim);
		string elem = next_delim ?
			       std::string(p).substr(0, next_delim - p) :
			       std::string(p);
		if(enableTrim) {
			trim(elem);
		}
		if(useEmptyItems || elem.length()) {
			elems.push_back(elem);
		}
		p = next_delim ? next_delim + delim_length : NULL;
	}
	return elems;
}

std::vector<std::string> split(const char *s, const char *delim, bool enableTrim, bool useEmptyItems) {
	std::vector<std::string> elems;
	split(s, delim, elems, enableTrim, useEmptyItems);
	return elems;
}

std::vector<std::string> split(const char *s, std::vector<std::string> delim, bool enableTrim, bool useEmptyItems, bool enableTrimString) {
	vector<std::string> elems;
	string elem = s;
	if(enableTrimString) {
		trim(elem);
	}
	elems.push_back(elem);
	for(size_t i = 0; i < delim.size(); i++) {
		vector<std::string> _elems;
		for(size_t j = 0; j < elems.size(); j++) {
			vector<std::string> __elems = split(elems[j].c_str(), delim[i].c_str(), enableTrim, useEmptyItems);
			for(size_t k = 0; k < __elems.size(); k++) {
				_elems.push_back(__elems[k]);
			}
		}
		elems = _elems;
	}
	return(elems);
}

std::vector<int> split2int(const std::string &s, std::vector<std::string> delim, bool enableTrim) {
    std::vector<std::string> tmpelems = split(s.c_str(), delim, enableTrim);
    std::vector<int> elems;
    for (uint i = 0; i < tmpelems.size(); i++) {
	elems.push_back(atoi(tmpelems.at(i).c_str()));
    }
    return elems;
}

std::vector<int> split2int(const std::string &s, char delim) {
    std::vector<std::string> tmpelems;
    split(s, delim, tmpelems);
    std::vector<int> elems;
    for (uint i = 0; i < tmpelems.size(); i++) {
	elems.push_back(atoi(tmpelems.at(i).c_str()));
    }
    return elems;
}

std::vector<std::string> split2chars(const std::string &s) {
	std::vector<std::string> elems;
	string _s = trim_str(s);
	for(unsigned i = 0; i < _s.length(); i++) {
		elems.push_back(_s.substr(i, 1));
	}
	return(elems);
}


bool check_regexp(const char *pattern) {
	regex_t re;
	if(regcomp(&re, pattern, REG_EXTENDED | REG_ICASE) != 0) {
		return(false);
	}
	regfree(&re);
	return(true);
}

int reg_match(const char *string, const char *pattern, const char *file, int line) {
	int status;
	regex_t re;
	if(regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
		static u_int64_t lastTimeSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			if(file) {
				syslog(LOG_ERR, "regcomp %s error in reg_match - call from %s : %i", pattern, file, line);
			} else {
				syslog(LOG_ERR, "regcomp %s error in reg_match", pattern);
			}
			lastTimeSyslog = actTime;
		}
		return(0);
	}
	status = regexec(&re, string, (size_t)0, NULL, 0);
	regfree(&re);
	return(status == 0);
}

int reg_match(const char *str, const char *pattern, vector<string> *matches, bool ignoreCase, const char *file, int line) {
	matches->clear();
	int status;
	regex_t re;
	if(regcomp(&re, pattern, REG_EXTENDED | (ignoreCase ? REG_ICASE: 0)) != 0) {
		static u_int64_t lastTimeSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			if(file) {
				syslog(LOG_ERR, "regcomp %s error in reg_replace - call from %s : %i", pattern, file, line);
			} else {
				syslog(LOG_ERR, "regcomp %s error in reg_match", pattern);
			}
			lastTimeSyslog = actTime;
		}
		return(-1);
	}
	int match_max = 20;
	regmatch_t match[match_max];
	memset(match, 0, sizeof(match));
	status = regexec(&re, str, match_max, match, 0);
	regfree(&re);
	if(status == 0) {
		int match_count = 0;
		for(int i = 0; i < match_max; i ++) {
			if(match[i].rm_so == -1 && match[i].rm_eo == -1) {
				break;
			}
			if(match[i].rm_eo > match[i].rm_so) {
				matches->push_back(string(str).substr(match[i].rm_so, match[i].rm_eo - match[i].rm_so));
				++match_count;
			}
		}
		return(match_count);
	}
	return(0);
}

string reg_replace(const char *str, const char *pattern, const char *replace, const char *file, int line) {
	int status;
	regex_t re;
	if(regcomp(&re, pattern, REG_EXTENDED | REG_ICASE) != 0) {
		static u_int64_t lastTimeSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			if(file) {
				syslog(LOG_ERR, "regcomp %s error in reg_replace - call from %s : %i", pattern, file, line);
			} else {
				syslog(LOG_ERR, "regcomp %s error in reg_replace", pattern);
			}
			lastTimeSyslog = actTime;
		}
		return("");
	}
	int match_max = 20;
	regmatch_t match[match_max];
	memset(match, 0, sizeof(match));
	status = regexec(&re, str, match_max, match, 0);
	regfree(&re);
	if(status == 0) {
		string rslt = replace;
		int match_count = 0;
		for(int i = 0; i < match_max; i ++) {
			if(match[i].rm_so == -1 && match[i].rm_eo == -1) {
				break;
			}
			++match_count;
		}
		for(int i = match_count - 1; i > 0; i--) {
			for(int j = 0; j < 2; j++) {
				char findStr[10];
				snprintf(findStr, sizeof(findStr), j ? "{$%i}" : "$%i", i);
				size_t findPos;
				while((findPos = rslt.find(findStr)) != string::npos) {
					rslt.replace(findPos, strlen(findStr), string(str).substr(match[i].rm_so, match[i].rm_eo - match[i].rm_so));
				}
			}
		}
		return(rslt);
	}
	return("");
}

bool reg_pattern_contain_subresult(const char *pattern) {
	const char *begin = NULL;
	while((begin = strchr(begin ? begin + 1 : pattern, '(')) != NULL) {
		if(begin == pattern || *(begin - 1) != '\\') {
			break;
		}
	}
	if(begin) {
		const char *end = NULL;
		while((end = strchr(end ? end + 1 : begin + 1, ')')) != NULL) {
			if(end == pattern || *(end - 1) != '\\') {
				break;
			}
		}
		if(begin && end && begin && end > begin) {
			return(true);
		}
	}
	return(false);
}


cRegExp::cRegExp(const char *pattern, eFlags flags,
		 const char *file, int line) {
	this->pattern = pattern ? pattern : "";
	this->flags = flags;
	regex_create();
	if(regex_error) {
		static u_int64_t lastTimeSyslog = 0;
		u_int64_t actTime = getTimeMS();
		if(actTime - 1000 > lastTimeSyslog) {
			if(file) {
				syslog(LOG_ERR, "regcomp %s error in cRegExp - call from %s : %i", pattern, file, line);
			} else {
				syslog(LOG_ERR, "regcomp %s error in cRegExp", pattern);
			}
			lastTimeSyslog = actTime;
		}
	}
}

cRegExp::~cRegExp() {
	regex_delete();
}

bool cRegExp::regex_create() {
	if(regcomp(&regex, pattern.c_str(), REG_EXTENDED | ((flags & _regexp_icase) ? REG_ICASE : 0) | ((flags & _regexp_sub) ? 0 : REG_NOSUB)) == 0) {
		regex_init = true;
		regex_error = false;
	} else {
		regex_error = true;
		regex_init = false;
	}
	return(regex_init);
}

void cRegExp::regex_delete() {
	if(regex_init) {
		regfree(&regex);
		regex_init = false;
	}
	regex_error = false;
}

int cRegExp::match(const char *subject, vector<string> *matches) {
	if(matches) {
		matches->clear();
	}
	if(regex_init) {
		int match_max = 20;
		regmatch_t match[match_max];
		memset(match, 0, sizeof(match));
		if(regexec(&regex, subject, match_max, match, 0) == 0) {
			if(flags & _regexp_matches) {
				int match_count = 0;
				for(int i = 0; i < match_max; i ++) {
					if(match[i].rm_so == -1 && match[i].rm_eo == -1) {
						break;
					}
					if(match[i].rm_eo > match[i].rm_so) {
						if(matches) {
							matches->push_back(string(subject).substr(match[i].rm_so, match[i].rm_eo - match[i].rm_so));
						}
						++match_count;
					}
				}
				return(match_count);
			} else  {
				return(1);
			}
		} else {
			return(0);
		}
	}
	return(-1);
}


cGzip::cGzip() {
	operation = _na;
	zipStream = NULL;
	destBuffer = NULL;
}

cGzip::~cGzip() {
	term();
}

bool cGzip::compress(u_char *buffer, size_t bufferLength, u_char **cbuffer, size_t *cbufferLength) {
	bool ok = true;
	initCompress();
	unsigned compressBufferLength = 1024 * 16;
	u_char *compressBuffer = new FILE_LINE(0) u_char[compressBufferLength];
	zipStream->avail_in = bufferLength;
	zipStream->next_in = buffer;
	do {
		zipStream->avail_out = compressBufferLength;
		zipStream->next_out = compressBuffer;
		int deflateRslt = deflate(zipStream, Z_FINISH);
		if(deflateRslt == Z_OK || deflateRslt == Z_STREAM_END) {
			unsigned have = compressBufferLength - zipStream->avail_out;
			destBuffer->add(compressBuffer, have);
		} else {
			ok = false;
			break;
		}
	} while(this->zipStream->avail_out == 0);
	delete [] compressBuffer;
	if(destBuffer->size() && ok) {
		*cbufferLength = destBuffer->size();
		*cbuffer = new FILE_LINE(0) u_char[*cbufferLength];
		memcpy(*cbuffer, destBuffer->data(), *cbufferLength);
	} else {
		*cbuffer = NULL;
		*cbufferLength = 0;
	}
	return(ok);
}

bool cGzip::compressString(string &str, u_char **cbuffer, size_t *cbufferLength) {
	return(compress((u_char*)str.c_str(), str.length(), cbuffer, cbufferLength));
}

bool cGzip::decompress(u_char *buffer, size_t bufferLength, u_char **dbuffer, size_t *dbufferLength) {
	bool ok = true;
	initDecompress();
	unsigned decompressBufferLength = 1024 * 16;
	u_char *decompressBuffer = new FILE_LINE(0) u_char[decompressBufferLength];
	zipStream->avail_in = bufferLength;
	zipStream->next_in = buffer;
	do {
		zipStream->avail_out = decompressBufferLength;
		zipStream->next_out = decompressBuffer;
		int inflateRslt = inflate(zipStream, Z_NO_FLUSH);
		if(inflateRslt == Z_OK || inflateRslt == Z_STREAM_END || inflateRslt == Z_BUF_ERROR) {
			int have = decompressBufferLength - zipStream->avail_out;
			destBuffer->add(decompressBuffer, have);
		} else {
			ok = false;
			break;
		}
	} while(zipStream->avail_out == 0);
	delete [] decompressBuffer;
	if(destBuffer->size() && ok) {
		*dbufferLength = destBuffer->size();
		*dbuffer = new FILE_LINE(0) u_char[*dbufferLength];
		memcpy(*dbuffer, destBuffer->data(), *dbufferLength);
	} else {
		*dbuffer = NULL;
		*dbufferLength = 0;
	}
	return(ok);
}

string cGzip::decompressString(u_char *buffer, size_t bufferLength) {
	u_char *dbuffer;
	size_t dbufferLength;
	if(decompress(buffer, bufferLength, &dbuffer, &dbufferLength)) {
		string rslt = string((char*)dbuffer, dbufferLength);
		delete [] dbuffer;
		return(rslt);
	} else {
		return("");
	}
}

bool cGzip::isCompress(u_char *buffer, size_t bufferLength) {
	return(bufferLength > 2 && buffer && buffer[0] == 0x1F && buffer[1] == 0x8B);
}

void cGzip::initCompress() {
	term();
	destBuffer = new FILE_LINE(0) SimpleBuffer;
	zipStream =  new FILE_LINE(0) z_stream;
	zipStream->zalloc = Z_NULL;
	zipStream->zfree = Z_NULL;
	zipStream->opaque = Z_NULL;
	deflateInit2(zipStream, 5, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY);
	operation = _compress;
}

void cGzip::initDecompress() {
	term();
	destBuffer = new FILE_LINE(0) SimpleBuffer;
	zipStream =  new FILE_LINE(0) z_stream;
	zipStream->zalloc = Z_NULL;
	zipStream->zfree = Z_NULL;
	zipStream->opaque = Z_NULL;
	zipStream->avail_in = 0;
	zipStream->next_in = Z_NULL;
	inflateInit2(zipStream, MAX_WBITS + 16);
	operation = _decompress;
}

void cGzip::term() {
	if(zipStream) {
		switch(operation) {
		case _compress:
			deflateEnd(zipStream);
			break;
		case _decompress:
			inflateEnd(zipStream);
			break;
		case _na:
			break;
		}
		delete zipStream;
		zipStream = NULL;
	}
	if(destBuffer) {
		delete destBuffer;
		destBuffer = NULL;
	}
}


#ifdef HAVE_LIBLZO
cLzo::cLzo() {
	use_1_11 = true;
	wrkmem = NULL;
	header_string = "LZO";
}

cLzo::~cLzo() {
	term();
}

bool cLzo::compress(u_char *buffer, size_t bufferLength, u_char **cbuffer, size_t *cbufferLength, bool withHeader) {
	size_t header_string_length = 0;
	size_t header_length = 0;
	size_t compress_buffer_length = bufferLength + bufferLength/16 + 64 + 3;
	if(withHeader) {
		header_string_length = strlen(header_string);
		header_length = header_string_length + sizeof(u_int32_t);
		compress_buffer_length += header_length;
	}
	*cbuffer = new FILE_LINE(0) u_char[compress_buffer_length];
	init();
	lzo_uint lzo_dst_len;
	int lzoRslt = use_1_11 ?
		       lzo1x_1_11_compress(buffer, bufferLength, *cbuffer + header_length, &lzo_dst_len, wrkmem) :
		       lzo1x_1_compress(buffer, bufferLength, *cbuffer + header_length, &lzo_dst_len, wrkmem);
	if(lzoRslt == LZO_E_OK) {
		*cbufferLength = lzo_dst_len;
		if(withHeader) {
			memcpy(*cbuffer, header_string, header_string_length);
			*(u_int32_t*)(*cbuffer + header_string_length) = bufferLength;
			*cbufferLength += header_length;
		}
		return(true);
	} else {
		delete [] *cbuffer;
		return(false);
	}
}

bool cLzo::decompress(u_char *buffer, size_t bufferLength, u_char **dbuffer, size_t *dbufferLength) {
	size_t header_string_length = strlen(header_string);
	size_t header_length = header_string_length + sizeof(u_int32_t);
	if(bufferLength < header_length) {
		return(false);
	}
	*dbufferLength = *(u_int32_t*)(buffer + header_string_length);
	*dbuffer = new FILE_LINE(0) u_char[*dbufferLength];
	init();
	lzo_uint lzo_dst_len = *dbufferLength;
	int lzoRslt = lzo1x_decompress_safe(buffer + header_length, bufferLength - header_length, *dbuffer, &lzo_dst_len, wrkmem);
	if(lzoRslt == LZO_E_OK) {
		*dbufferLength= lzo_dst_len;
		return(true);
	} else {
		delete [] *dbuffer;
		return(false);
	}
}

string cLzo::decompressString(u_char *buffer, size_t bufferLength) {
	u_char *dbuffer;
	size_t dbufferLength;
	if(decompress(buffer, bufferLength, &dbuffer, &dbufferLength)) {
		string rslt = string((char*)dbuffer, dbufferLength);
		delete [] dbuffer;
		return(rslt);
	} else {
		return("");
	}
}

void cLzo::init() {
	if(!wrkmem) {
		wrkmem = new FILE_LINE(0) u_char[use_1_11 ? LZO1X_1_11_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];
	}
}

void cLzo::term() {
	if(wrkmem) {
		delete [] wrkmem;
		wrkmem = NULL;
	}
}

bool cLzo::isCompress(u_char *buffer, size_t bufferLength) {
	size_t header_string_length = strlen(header_string);
	return(bufferLength > header_string_length && !memcmp(buffer, header_string, header_string_length));
}
#endif


cResolver::cResolver() {
	use_lock = true;
	res_timeout = 120;
	_sync_lock = 0;
}


#ifdef CARESRESOLVER
// c-ares callback function to process DNS query results
static void resolve_callback(void *arg, int status, int timeouts, struct hostent *host) {
    (void)timeouts;  // unused

    auto *data = static_cast<std::tuple<vector<vmIP>*, vmIP*, const char*>*>(arg);
    auto *ips = std::get<0>(*data);
    auto *ip = std::get<1>(*data);
    const char* hostname = std::get<2>(*data);

    if (status == ARES_SUCCESS) {
        for (int i = 0; host->h_addr_list[i] != NULL; ++i) {
            vmIP _ip;
            if (host->h_addrtype == AF_INET) {
                _ip.setIPv4(*((in_addr_t*) host->h_addr_list[i]), true);
            }
            #if VM_IPV6
            else if (VM_IPV6_B && host->h_addrtype == AF_INET6) {
                _ip.setIPv6(*((struct in6_addr*) host->h_addr_list[i]), true);
            }
            #endif
            if(_ip.isSet()) {
                syslog(LOG_NOTICE, "c-ares resolved host %s to %s", hostname, _ip.getString().c_str());
                if (!ip->isSet()) {
                    *ip = _ip;
                }
                if (ips) {
                    ips->push_back(_ip);
                } else {
                    break;
                }
            }
        }
    }
    // Indicate that the query is done
    ares_flag = 1;
}
#endif

#ifdef CARESRESOLVER
vmIP cResolver::resolve_std(const char *host, vector<vmIP> *ips) {
    vmIP ip;
    ares_channel channel;
    int status;
    struct ares_options options;
    int optmask = 0;

    // Initialize the c-ares library
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        syslog(LOG_ERR, "ares_library_init failed: %s", ares_strerror(status));
        return ip;
    }

    // Initialize a channel to the c-ares library
    status = ares_init_options(&channel, &options, optmask);
    if(status != ARES_SUCCESS) {
        syslog(LOG_ERR, "ares_init_options failed: %s", ares_strerror(status));
        ares_library_cleanup();
        return ip;
    }

    // Start the DNS query
    auto data = std::make_tuple(ips, &ip, host);
    ares_gethostbyname(channel, host, AF_UNSPEC, resolve_callback, &data);

    // Wait for the query to complete
    while (!ares_flag) {
        struct timeval *tvp, tv;
        fd_set read_fds, write_fds;
        int nfds;

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0)
            break;

        tvp = ares_timeout(channel, NULL, &tv);
        select(nfds, &read_fds, &write_fds, NULL, tvp);

        ares_process(channel, &read_fds, &write_fds);
    }

    // Clean up the c-ares library
    ares_destroy(channel);
    ares_library_cleanup();

    if (ips && ips->size() > 1) {
        sort_ips_by_type(ips);
        ip = (*ips)[0];
    }

    return ip;
}
#endif


vmIP cResolver::resolve(const char *host, vector<vmIP> *ips, unsigned timeout, eTypeResolve typeResolve) {
	if(use_lock) {
		lock();
	}
	vmIP ip;
	time_t now = time(NULL);
	map<string, sIP_time>::iterator iter_find = res_table.find(host);
	if(iter_find != res_table.end() &&
	   (iter_find->second.timeout == UINT_MAX ||
	    iter_find->second.at + iter_find->second.timeout > now) &&
	   iter_find->second.ips.size()) {
		ip = iter_find->second.ips[0];
		if (ips) {
			*ips = iter_find->second.ips;
		}
	}
	if(!ip.isSet()) {
		if(ip_is_valid(host)) {
			ip.setFromString(host);
			res_table[host].ips.clear();
			res_table[host].ips.push_back(ip);
			res_table[host].at = now;
			res_table[host].timeout = UINT_MAX;
			if (ips) {
				ips->push_back(ip);
			}
		} else {
			if(typeResolve == _typeResolve_default) {
				#if defined(__arm__)
					typeResolve = _typeResolve_system_host;
				#else
					typeResolve = _typeResolve_std;
				#endif
			}
			if(typeResolve == _typeResolve_std) {
				ip = resolve_std(host, ips);
			} else if(typeResolve == _typeResolve_system_host) {
				ip = resolve_by_system_host(host, ips);
			}
			if (ips && ips->size()) {
				res_table[host].ips.clear();
				res_table[host].ips = *ips;
				res_table[host].at = now;
				res_table[host].timeout = timeout ? timeout : 120;
			} else if(ip.isSet()) {
				res_table[host].ips.clear();
				res_table[host].ips.push_back(ip);
				res_table[host].at = now;
				res_table[host].timeout = timeout ? timeout : 120;
			}
		}
	}
	if(use_lock) {
		unlock();
	}
	return(ip);
}

vmIP cResolver::resolve_n(const char *host, unsigned timeout, eTypeResolve typeResolve) {
	extern cResolver resolver;
	return(resolver.resolve(host, NULL, timeout, typeResolve));
}

string cResolver::resolve_str(const char *host, unsigned timeout, eTypeResolve typeResolve) {
	extern cResolver resolver;
	vmIP ip = resolver.resolve(host, NULL, timeout, typeResolve);
	if(ip.isSet()) {
		return(ip.getString());
	}
	return("");
}

#ifndef CARESRESOLVER
vmIP cResolver::resolve_std(const char *host, vector<vmIP> *ips) {
	vmIP ip;
	struct addrinfo req, *res, *res_main;
	memset(&req, 0, sizeof(req));
	req.ai_family = AF_UNSPEC;
	req.ai_socktype = SOCK_STREAM;
	if(getaddrinfo(host, NULL, &req, &res) == 0) {
		res_main = res;
		while(res) {
			if(res->ai_family == AF_INET) {
				vmIP _ip;
				_ip.setIPv4(((sockaddr_in*)res->ai_addr)->sin_addr.s_addr, true);
				if(_ip.isSet()) {
					syslog(LOG_NOTICE, "getaddrinfo resolve host %s to IPV4 %s", host, _ip.getString().c_str());
					if (!ip.isSet()) {
						ip = _ip;
					}
					if (ips) {
						ips->push_back(_ip);
					} else {
						break;
					}
				}
			} 
			#if VM_IPV6
			else if(VM_IPV6_B && res->ai_family == AF_INET6) {
				vmIP _ip;
				_ip.setIPv6(((sockaddr_in6*)res->ai_addr)->sin6_addr, true);
				if(_ip.isSet()) {
					syslog(LOG_NOTICE, "getaddrinfo resolve host %s to IPV6 %s", host, _ip.getString().c_str());
					if (!ip.isSet()) {
						ip = _ip;
					}
					if (ips) {
						ips->push_back(_ip);
					} else {
						break;
					}
				}
			}
			#endif
			res = res->ai_next;
		}
		freeaddrinfo(res_main);
	}
	if (ips && ips->size() > 1) {
		sort_ips_by_type(ips);
		ip = (*ips)[0];
	}
	return(ip);
}
#endif

vmIP cResolver::resolve_by_system_host(const char *host, vector<vmIP> *ips) {
	vmIP ip;
	FILE *cmd_pipe;
	if (ips) {
		cmd_pipe = popen((string("host ") + host + " 2>/dev/null").c_str(), "r");
	} else {
		cmd_pipe = popen((string("host -t A ") + host + " 2>/dev/null").c_str(), "r");
	}
	if(cmd_pipe) {
		char bufRslt[512];
		bool okIP = false;
		while(!okIP && fgets(bufRslt, sizeof(bufRslt), cmd_pipe)) {
			vector<string> try_ip = split(bufRslt, split(",|;|\t| |\n", '|'), true);
			for(unsigned i = 0; !okIP && i < try_ip.size(); i++) {
				vmIP _ip;
				if (_ip.setFromString(try_ip[i].c_str())) {
					syslog(LOG_NOTICE, "cmd host resolve host %s to %s", host, _ip.getString().c_str());
					if (!ip.isSet()) {
						ip = _ip;
					}
					if (ips) {
						ips->push_back(_ip);
					} else {
						okIP = true;
					}
				}
			}
		}
		pclose(cmd_pipe);
	}
	if (ips && ips->size() > 1) {
		sort_ips_by_type(ips);
		ip = (*ips)[0];
	}
	return(ip);
}

void cResolver::sort_ips_by_type(vector<vmIP> *ips) {
	vector<vmIP> ip_rslt;
	for(unsigned v6 = 0; v6 < 2; v6++) {
		for(unsigned i = 0; i < ips->size(); i++) {
			if((*ips)[i].is_v6() ? v6 : !v6) {
				ip_rslt.push_back((*ips)[i]);
			}
		}
	}
	*ips = ip_rslt;
}

std::vector<string> cResolver::resolve_allips_str(const char *host, unsigned timeout, eTypeResolve typeResolve) {
	std::vector<vmIP> vmips;
	resolve(host, &vmips, timeout, typeResolve);
	std::vector<string> ips;
	if (vmips.size()) {
		for (uint i = 0; i < vmips.size(); ++i) {
			ips.push_back(vmips[i].getString());
		}
	}
	return(ips);
}

cUtfConverter::cUtfConverter() {
	cnv_utf8 = NULL;
	init_ok = false;
	_sync_lock = 0;
	init();
}

cUtfConverter::~cUtfConverter() {
	term();
}

bool cUtfConverter::check(const char *str) {
	if(!str || !*str || is_ascii(str)) {
		return(true);
	}
	bool okUtf = false;
	if(init_ok) {
		unsigned strLen = strlen(str);
		unsigned strLimit = strLen * 2 + 10;
		unsigned strUtfLimit = strLen * 2 + 10;
		UChar *strUtf = new FILE_LINE(0) UChar[strUtfLimit + 1];
		UErrorCode status = U_ZERO_ERROR;
		lock();
		ucnv_toUChars(cnv_utf8, strUtf, strUtfLimit, str, -1, &status);
		unlock();
		if(status == U_ZERO_ERROR) {
			char *str_check = new FILE_LINE(0) char[strLimit + 1];
			lock();
			ucnv_fromUChars(cnv_utf8, str_check, strLimit, strUtf, -1, &status);
			unlock();
			if(status == U_ZERO_ERROR && !strcmp(str, str_check)) {
				okUtf = true;
			}
			delete [] str_check;
		}
		delete [] strUtf;
	}
	return(okUtf);
}

string cUtfConverter::reverse(const char *str) {
	if(!str || !*str) {
		return("");
	}
	string rslt;
	bool okReverseUtf = false;
	if(init_ok && !is_ascii(str)) {
		unsigned strLen = strlen(str);
		unsigned strLimit = strLen * 2 + 10;
		unsigned strUtfLimit = strLen * 2 + 10;
		UChar *strUtf = new FILE_LINE(0) UChar[strUtfLimit + 1];
		UErrorCode status = U_ZERO_ERROR;
		lock();
		ucnv_toUChars(cnv_utf8, strUtf, strUtfLimit, str, -1, &status);
		unlock();
		if(status == U_ZERO_ERROR) {
			unsigned len = 0;
			for(unsigned i = 0; i < strUtfLimit && strUtf[i]; i++) {
				len++;
			}
			UChar *strUtf_r = new FILE_LINE(0) UChar[strUtfLimit + 1];
			for(unsigned i = 0; i < len; i++) {
				strUtf_r[len - i - 1] = strUtf[i];
			}
			strUtf_r[len] = 0;
			char *str_r = new FILE_LINE(0) char[strLimit + 1];
			lock();
			ucnv_fromUChars(cnv_utf8, str_r, strLimit, strUtf_r, -1, &status);
			unlock();
			if(status == U_ZERO_ERROR && strlen(str_r) == strLen) {
				rslt = str_r;
				okReverseUtf = true;
			}
			delete [] str_r;
			delete [] strUtf_r;
		}
		delete [] strUtf;
	}
	if(!okReverseUtf) {
		int length = strlen(str);
		for(int i = length - 1; i >= 0; i--) {
			rslt += str[i];
		}
	}
	return rslt;
}

bool cUtfConverter::is_ascii(const char *str) {
	if(!str) {
		return(true);
	}
	while(*str) {
		if((unsigned)*str > 127) {
			return(false);
		}
		++str;
	}
	return(true);
}

string cUtfConverter::remove_no_ascii(const char *str, const char subst) {
	if(!str || !*str) {
		return("");
	}
	string rslt;
	while(*str) {
		rslt += (unsigned)*str > 127 ? subst : *str;
		++str;
	}
	return(rslt);
}

void cUtfConverter::_remove_no_ascii(const char *str, const char subst) {
	if(!str) {
		return;
	}
	while(*str) {
		if((unsigned)*str > 127) {
			*(char*)str = subst;
		}
		++str;
	}
}

bool cUtfConverter::init() {
	UErrorCode status = U_ZERO_ERROR;
	cnv_utf8 = ucnv_open("utf-8", &status);
	if(status == U_ZERO_ERROR) {
		init_ok = true;
	} else {
		if(cnv_utf8) {
			ucnv_close(cnv_utf8);
		}
	}
	return(init_ok);
}

void cUtfConverter::term() {
	if(cnv_utf8) {
		ucnv_close(cnv_utf8);
	}
	init_ok = false;
}
