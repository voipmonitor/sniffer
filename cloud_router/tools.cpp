#include <string>
#include <syslog.h>
#include <json-c/json.h>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tools.h"


using namespace std;


struct vm_pthread_struct {
	void *(*start_routine)(void *arg);
	void *arg;
	string description;
};

void *vm_pthread_create_start_routine(void *arg) {
	vm_pthread_struct thread_data = *(vm_pthread_struct*)arg;
	delete (vm_pthread_struct*)arg;
	return(thread_data.start_routine(thread_data.arg));
}

int vm_pthread_create(const char *thread_description,
		      pthread_t *thread, pthread_attr_t *attr,
		      void *(*start_routine) (void *), void *arg,
		      const char *src_file, int src_file_line, bool autodestroy) {
	syslog(LOG_NOTICE, "create thread %sfrom %s : %i", 
	       autodestroy ? "(autodestroy) " : "", src_file, src_file_line);
	bool create_attr = false;
	pthread_attr_t _attr;
	if(!attr && autodestroy) {
		pthread_attr_init(&_attr);
		pthread_attr_setdetachstate(&_attr, PTHREAD_CREATE_DETACHED);
		create_attr = true;
		attr = &_attr;
	}
	vm_pthread_struct *thread_data = new vm_pthread_struct;
	thread_data->start_routine = start_routine;
	thread_data->arg = arg;
	thread_data->description = thread_description;
	int rslt = pthread_create(thread, attr, vm_pthread_create_start_routine, thread_data);
	if(create_attr) {
		pthread_attr_destroy(&_attr);
	}
	return(rslt);
}

int vm_pthread_create_autodestroy(const char *thread_description,
				  pthread_t *thread, pthread_attr_t *attr,
				  void *(*start_routine) (void *), void *arg, 
				  const char *src_file, int src_file_line) {
	return(vm_pthread_create(thread_description,
				 thread, attr,
				 start_routine, arg, 
				 src_file, src_file_line,
				 true));
}


JsonItem::JsonItem(string name, string value, bool null) {
	this->name = name;
	this->value = value;
	this->null = null;
	this->parse(value);
}

void JsonItem::parse(string valStr) {
	////cerr << "valStr: " << valStr << endl;
	if(valStr[0] != '{' && valStr[0] != '[') {
		return;
	}
	json_object * object = json_tokener_parse(valStr.c_str());
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

void JsonExport::add(const char *name, string content) {
	this->add(name, content.c_str());
}

void JsonExport::add(const char *name, const char *content) {
	JsonExport_template<string> *item = new JsonExport_template<string>;
	item->setTypeItem(_string);
	item->setName(name);
	string content_esc;
	const char *ptr = content;
	while(*ptr) {
		switch(*ptr) {
		case '"':
		case '\\':
			content_esc += "\\"; 
			break;
		}
		content_esc += *ptr;
		++ptr;
	}
	item->setContent(content_esc);
	items.push_back(item);
}

void JsonExport::add(const char *name, u_int64_t content) {
	JsonExport_template<u_int64_t> *item = new JsonExport_template<u_int64_t>;
	item->setTypeItem(_number);
	item->setName(name);
	item->setContent(content);
	items.push_back(item);
}

JsonExport *JsonExport::addArray(const char *name) {
	JsonExport *item = new JsonExport;
	item->setTypeItem(_array);
	item->setName(name);
	items.push_back(item);
	return(item);
}

JsonExport *JsonExport::addObject(const char *name) {
	JsonExport *item = new JsonExport;
	item->setTypeItem(_object);
	item->setName(name);
	items.push_back(item);
	return(item);
}

void JsonExport::addJson(const char *name, const string &content) {
	this->addJson(name, content.c_str());
}

void JsonExport::addJson(const char *name, const char *content) {
	JsonExport_template<string> *item = new JsonExport_template<string>;
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
	if(typeItem == _string) {
		outStr << '\"';
	}
	outStr << content;
	if(typeItem == _string) {
		outStr << '\"';
	}
	return(outStr.str());
}


string intToString(u_int16_t i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(int32_t i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(u_int32_t i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}

string intToString(u_int64_t i) {
	ostringstream outStr;
	outStr << i;
	return(outStr.str());
}


string inet_ntostring(u_int32_t ip) {
	struct in_addr in;
	in.s_addr = htonl(ip);
	return(inet_ntoa(in));
}


void xorData(u_char *data, size_t dataLen, const char *key, size_t keyLength, size_t initPos) {
	for(size_t i = 0; i < dataLen; i++) {
		data[i] = data[i] ^ key[(initPos + i) % keyLength];
	}
}
