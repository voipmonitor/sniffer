#ifndef CONFIG_PARAM_H
#define CONFIG_PARAM_H


#include <string>
#include <list>
#include <map>

#include "simpleini/SimpleIni.h"
#include "sniff.h"
#include "tools.h"


using namespace std;


class cConfigItem {
public:
	struct sMapValue {
		sMapValue(string str, int value) {
			this->str = str;
			this->value = value;
		}
		string str;
		int value;
	};
public:
	cConfigItem(const char *name);
	virtual ~cConfigItem() {}
	cConfigItem *addAlias(const char *name_alias);
	void setConfigFileSection(const char *config_file_section);
	cConfigItem *addValue(const char *str, int value);
	cConfigItem *addValues(const char *str_values);
	virtual string getValueStr(bool configFile = false) { return(""); }
protected:
	virtual bool setParamFromConfigFile(CSimpleIniA *ini) = 0;
	virtual bool setParamFromValueStr(string value_str) = 0;
	virtual bool setParamFromValuesStr(vector<string> list_value_str) { return(false); }
	string getValueFromConfigFile(CSimpleIniA *ini);
	vector<string> getValuesFromConfigFile(CSimpleIniA *ini);
	bool getValueFromMapValues(const char *str_value, int *rslt_value);
	string getStringFromMapValues(int value);
	void init();
	virtual void initParamPointers() {}
	virtual void initOther() {}
	virtual void initVirtParam() {}
	virtual void initBeforeSet() {}
protected:
	string config_name;
	list<string> config_name_alias;
	string config_file_section;
	class cConfig *config;
	list<sMapValue> mapValues;
	bool set;
friend class cConfig;
};

class cConfigItem_yesno : public cConfigItem {
public:
	cConfigItem_yesno(const char *name, bool *param);
	cConfigItem_yesno(const char *name, int *param = NULL);
	cConfigItem_yesno *setNeg() {
		neg = true;
		return(this);
	}
	cConfigItem_yesno *setOnlyIfParamIsNo() {
		onlyIfParamIsNo = true;
		return(this);
	}
	int getValue();
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_bool = NULL;
		param_int = NULL;
	}
	void initOther() {
		onlyIfParamIsNo = false;
		neg = false;
	}
	void initVirtParam() {
		param_virt = 0;
	}
protected:
	bool *param_bool;
	int *param_int;
	int param_virt;
	bool neg;
	bool onlyIfParamIsNo;
};

class cConfigItem_integer : public cConfigItem {
public:
	cConfigItem_integer(const char *name, int *param);
	cConfigItem_integer(const char *name, unsigned int *param);
	cConfigItem_integer(const char *name, uint64_t *param);
	cConfigItem_integer(const char *name, int64_t *param = NULL);
	cConfigItem_integer *setIp() {
		ip = true;
		return(this);
	}
	cConfigItem_integer *setMaximum(int maximum) {
		this->maximum = maximum;
		return(this);
	}
	cConfigItem_integer *setMinimum(int minimum) {
		this->minimum = minimum;
		return(this);
	}
	cConfigItem_integer *setIfZeroOrNegative(int ifZeroOrNegative) {
		this->ifZeroOrNegative = ifZeroOrNegative;
		return(this);
	}
	cConfigItem_integer *setMultiple(double multiple) {
		this->multiple = multiple;
		return(this);
	}
	cConfigItem_integer *setYes(int yesValue = 1) {
		this->yesValue = yesValue;
		return(this);
	}
	int64_t getValue();
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_int = NULL;
		param_uint = NULL;
		param_int64 = NULL;
		param_uint64 = NULL;
	}
	void initOther() {
		ip = false;
		maximum = 0;
		minimum = 0;
		ifZeroOrNegative = 0;
		multiple = 0;
		yesValue = 0;
	}
	void initVirtParam() {
		param_virt = 0;
	}
protected:
	int *param_int;
	unsigned int *param_uint;
	int64_t *param_int64;
	uint64_t *param_uint64;
	int64_t param_virt;
	bool ip;
	int maximum;
	int minimum;
	int ifZeroOrNegative;
	double multiple;
	int yesValue;
};

class cConfigItem_float : public cConfigItem {
public:
	cConfigItem_float(const char *name, float *param);
	cConfigItem_float(const char *name, double *param);
	double getValue();
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_float = NULL;
		param_double = NULL;
	}
protected:
	float *param_float;
	double *param_double;
};

class cConfigItem_string : public cConfigItem {
public:
	cConfigItem_string(const char *name, string *param = NULL);
	cConfigItem_string(const char *name, char *param, int length);
	cConfigItem_string(const char *name, vector<string> *param);
	cConfigItem_string *setPrefix(const char *prefix) {
		this->prefix = prefix;
		return(this);
	}
	cConfigItem_string *setExplodeSeparator(const char *explodeSeparator) {
		this->explodeSeparator = explodeSeparator;
		return(this);
	}
	string getValue();
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_str = NULL;
		param_strchar = NULL;
		param_strchar_length = 0;
		param_vect_str = NULL;
	}
	void initOther() {
		prefix = "";
		explodeSeparator = "";
	}
	void initVirtParam() {
		param_virt = "";
	}
protected:
	string *param_str;
	char *param_strchar;
	int param_strchar_length;
	string param_virt;
	vector<string> *param_vect_str;
	string prefix;
	string explodeSeparator;
};

class cConfigItem_hour_interval : public cConfigItem {
public:
	cConfigItem_hour_interval(const char *name, int *from, int *to);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_from = NULL;
		param_to = NULL;
	}
protected:
	int *param_from;
	int *param_to;
};

class cConfigItem_ports : public cConfigItem {
public:
	cConfigItem_ports(const char* name, char *port_matrix);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	bool setParamFromValuesStr(vector<string> list_value_str);
	void initBeforeSet();
	void initParamPointers() {
		param_port_matrix = NULL;
	}
protected:
	char *param_port_matrix;
};

class cConfigItem_hosts : public cConfigItem {
public:
	cConfigItem_hosts(const char* name, vector<u_int32_t> *adresses, vector<d_u_int32_t> *nets);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	bool setParamFromValuesStr(vector<string> list_value_str);
	void initParamPointers() {
		param_adresses = NULL;
		param_nets = NULL;
	}
protected:
	vector<u_int32_t> *param_adresses;
	vector<d_u_int32_t> *param_nets;
};

class cConfigItem_ip_port : public cConfigItem {
public:
	cConfigItem_ip_port(const char* name, ip_port *param);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_ip_port = NULL;
	}
protected:
	ip_port *param_ip_port;
};

class cConfigItem_ip_port_str_map : public cConfigItem {
public:
	cConfigItem_ip_port_str_map(const char* name, map<d_u_int32_t, string> *ip_port_string_map);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	bool setParamFromValuesStr(vector<string> list_value_str);
	void initParamPointers() {
		param_ip_port_string_map = NULL;
	}
protected:
	map<d_u_int32_t, string> *param_ip_port_string_map;
};

class cConfigItem_nat_aliases : public cConfigItem {
public:
	cConfigItem_nat_aliases(const char* name, nat_aliases_t *nat_aliases);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	bool setParamFromValuesStr(vector<string> list_value_str);
	void initParamPointers() {
		param_nat_aliases = NULL;
	}
protected:
	nat_aliases_t *param_nat_aliases;
};

class cConfigItem_custom_headers : public cConfigItem {
public:
	cConfigItem_custom_headers(const char* name, vector<dstring> *custom_headers);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_custom_headers = NULL;
	}
protected:
	vector<dstring> *param_custom_headers;
};

class cConfigItem_type_compress : public cConfigItem {
public:
	cConfigItem_type_compress(const char* name, CompressStream::eTypeCompress *type_compress);
	cConfigItem_type_compress(const char* name, FileZipHandler::eTypeCompress *type_compress);
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini);
	bool setParamFromValueStr(string value_str);
	void initParamPointers() {
		param_type_compress_cs = NULL;
		param_type_compress_fzh = NULL;
	}
protected:
	CompressStream::eTypeCompress *param_type_compress_cs;
	FileZipHandler::eTypeCompress *param_type_compress_fzh;
};


class cConfig {
public:
	cConfig();
	~cConfig();
	void addConfigItems();
	void addConfigItem(cConfigItem *configItem);
	bool loadFromConfigFileOrDirectory(const char *filename);
	bool loadFromConfigFile(const char *filename, string *error = NULL);
	void evSetConfigItem(cConfigItem *configItem);
	string getContentConfig(bool configFile = false);
private:
	void loadFromConfigFileError(const char *errorString, const char *filename, string *error);
private:
	list<string> config_list;
	map<string, cConfigItem*> config_map;
};


#endif
