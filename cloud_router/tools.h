#ifndef TOOLS_H
#define TOOLS_H


#include <pthread.h>
#include <string>
#include <vector>


using namespace std;


inline u_int64_t getTimeUS() {
	timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	return(time.tv_sec * 1000000ull + time.tv_nsec / 1000);
}

int vm_pthread_create(const char *thread_description,
		      pthread_t *thread, pthread_attr_t *attr,
		      void *(*start_routine) (void *), void *arg, 
		      const char *src_file, int src_file_line,
		      bool autodestroy = false);
int vm_pthread_create_autodestroy(const char *thread_description,
				  pthread_t *thread, pthread_attr_t *attr,
				  void *(*start_routine) (void *), void *arg, 
				  const char *src_file, int src_file_line);


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
	void add(const char *name, string content);
	void add(const char *name, const char *content);
	void add(const char *name, u_int64_t content);
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


string intToString(u_int16_t i);
string intToString(int32_t i);
string intToString(u_int32_t i);
string intToString(u_int64_t i);

string inet_ntostring(u_int32_t ip);

void xorData(u_char *data, size_t dataLen, const char *key, size_t keyLength, size_t initPos);


#endif //TOOLS_H
