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
	enum eTypeLevel {
		levelNormal,
		levelAdvanced,
		levelExpert,
		levelObsolete
	};
public:
	cConfigItem(const char *name);
	virtual ~cConfigItem() {}
	cConfigItem *addAlias(const char *name_alias);
	cConfigItem *setDefaultValueStr(const char *defaultValueStr);
	cConfigItem *setNaDefaultValueStr();
	cConfigItem *setClearBeforeFirstSet();
	cConfigItem *setMinor();
	cConfigItem *setMinorGroupIfNotSet();
	cConfigItem *setReadOnly();
	cConfigItem *setDisableIf(const char *disableIf);
	cConfigItem *setAlwaysShow();
	void setConfigFileSection(const char *config_file_section);
	cConfigItem *addValue(const char *str, int value);
	cConfigItem *addValues(const char *str_values);
	cConfigItem *addStringItem(const char *str);
	cConfigItem *addStringItems(const char *str_values);
	cConfigItem *setSubtype(const char *subtype);
	cConfigItem *setDescription(const char *description);
	cConfigItem *setHelp(const char *help);
	virtual string getValueStr(bool /*configFile*/ = false) { return(""); }
	virtual int64_t getValueInt() { return(0); }
	virtual list<string> getValueListStr() { list<string> l; l.push_back(getValueStr()); return(l); }
	virtual string normalizeStringValueForCmp(string value) { return(value); }
	virtual string normalizeStringValuesForCmp(list<string> value) { return(""); }
	virtual bool enable_normalizeStringValuesForCmp() { return(false); }
	virtual bool enableMultiValues() { return(false); }
protected:
	virtual bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false) = 0;
	virtual bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false) = 0;
	virtual bool setParamFromValuesStr(vector<string> /*list_value_str*/, bool enableClearBeforeFirstSet = false) { return(false); }
	string getValueFromConfigFile(CSimpleIniA *ini);
	vector<string> getValuesFromConfigFile(CSimpleIniA *ini);
	bool getValueFromMapValues(const char *str_value, int *rslt_value);
	string getStringFromMapValues(int value);
	void init();
	virtual void initParamPointers() {}
	virtual void initOther() {}
	virtual void initVirtParam() {}
	virtual void initBeforeSet() {}
	virtual string getTypeName() = 0;
	virtual list<sMapValue> getMenuItems();
	void addItemToMenuItems(list<sMapValue> *menu, sMapValue menuItem);
	string getJson();
	void setDefaultValue();
	void clearToDefaultValue();
	void doClearBeforeFirstSet();
	virtual void clear() {}
protected:
	string config_name;
	list<string> config_name_alias;
	string config_file_section;
	eTypeLevel level;
	string group_name;
	string subgroup_name;
	string subtype;
	string description;
	string help;
	class cConfig *config;
	list<sMapValue> mapValues;
	bool set;
	bool set_in_config;
	bool set_in_db;
	bool set_in_json;
	string value_in_config;
	string value_in_db;
	string value_in_json;
	string defaultValueStr;
	bool defaultValueStr_set;
	bool naDefaultValueStr;
	bool clearBeforeFirstSet;
	bool minor;
	bool minorGroupIfNotSet;
	bool readOnly;
	string disableIf;
	bool alwaysShow;
friend class cConfig;
};

class cConfigItem_yesno : public cConfigItem {
public:
	cConfigItem_yesno(const char *name, bool *param);
	cConfigItem_yesno(const char *name, int *param = NULL);
	cConfigItem_yesno *disableYes() {
		disable_yes = true;
		return(this);
	}
	cConfigItem_yesno *disableNo() {
		disable_no = true;
		return(this);
	}
	cConfigItem_yesno *setNeg() {
		neg = true;
		return(this);
	}
	int getValue();
	string getValueStr(bool configFile = false);
	int64_t getValueInt() { return(getValue()); }
	string normalizeStringValueForCmp(string value);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	void initParamPointers() {
		param_bool = NULL;
		param_int = NULL;
	}
	void initOther() {
		disable_yes = false;
		disable_no =  false;
		neg = false;
	}
	void initVirtParam() {
		param_virt = 0;
	}
	string getTypeName() {
		return("yesno");
	}
	list<sMapValue> getMenuItems();
protected:
	bool *param_bool;
	int *param_int;
	int param_virt;
	bool disable_yes;
	bool disable_no;
	bool neg;
};

class cConfigItem_integer : public cConfigItem {
public:
	cConfigItem_integer(const char *name, int *param);
	cConfigItem_integer(const char *name, unsigned int *param);
	cConfigItem_integer(const char *name, uint64_t *param);
	cConfigItem_integer(const char *name, int64_t *param = NULL);
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
	cConfigItem_integer *setMenuValue() {
		this->menuValue = true;
		return(this);
	}
	cConfigItem_integer *setOnlyMenu() {
		this->onlyMenu = true;
		return(this);
	}
	int64_t getValue();
	string getValueStr(bool configFile = false);
	int64_t getValueInt() { return(getValue()); }
	string normalizeStringValueForCmp(string value);
	int getMaximum() {
		return(maximum);
	}
	int getMinimum() {
		return(minimum);
	}
	bool isMenuValue() {
		return(menuValue);
	}
	bool isOnlyMenu() {
		return(onlyMenu);
	}
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	void initParamPointers() {
		param_int = NULL;
		param_uint = NULL;
		param_int64 = NULL;
		param_uint64 = NULL;
	}
	void initOther() {
		maximum = 0;
		minimum = 0;
		ifZeroOrNegative = 0;
		multiple = 0;
		yesValue = 0;
		menuValue = false;
		onlyMenu = false;
	}
	void initVirtParam() {
		param_virt = 0;
	}
	string getTypeName() {
		return("integer");
	}
protected:
	int *param_int;
	unsigned int *param_uint;
	int64_t *param_int64;
	uint64_t *param_uint64;
	int64_t param_virt;
	int maximum;
	int minimum;
	int ifZeroOrNegative;
	double multiple;
	int yesValue;
	bool menuValue;
	bool onlyMenu;
};

class cConfigItem_float : public cConfigItem {
public:
	cConfigItem_float(const char *name, float *param);
	cConfigItem_float(const char *name, double *param);
	double getValue();
	string getValueStr(bool configFile = false);
	string normalizeStringValueForCmp(string value);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	void initParamPointers() {
		param_float = NULL;
		param_double = NULL;
	}
	string getTypeName() {
		return("float");
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
	cConfigItem_string *setSuffix(const char *suffix) {
		this->suffix = suffix;
		return(this);
	}
	cConfigItem_string *setPrefixSuffix(const char *prefix, const char *suffix) {
		this->prefix = prefix;
		this->suffix = suffix;
		return(this);
	}
	cConfigItem_string *setExplodeSeparator(const char *explodeSeparator) {
		this->explodeSeparator = explodeSeparator;
		return(this);
	}
	cConfigItem_string *setPassword() {
		this->password = true;
		return(this);
	}
	string getValue();
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	string normalizeStringValueForCmp(string value);
	bool enableMultiValues();
	bool isPassword() {
	       return(password);
	}
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_values_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_str = NULL;
		param_strchar = NULL;
		param_strchar_length = 0;
		param_vect_str = NULL;
	}
	void initOther() {
		prefix = "";
		suffix = "";
		explodeSeparator = ";";
		password = false;
	}
	void initVirtParam() {
		param_virt = "";
	}
	string getTypeName() {
		return(param_vect_str ? "string_list" : "string");
	}
protected:
	string *param_str;
	char *param_strchar;
	int param_strchar_length;
	string param_virt;
	vector<string> *param_vect_str;
	string prefix;
	string suffix;
	string explodeSeparator;
	bool password;
};

class cConfigItem_hour_interval : public cConfigItem {
public:
	cConfigItem_hour_interval(const char *name, int *from, int *to);
	string getValueStr(bool configFile = false);
	string normalizeStringValueForCmp(string value);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	void initParamPointers() {
		param_from = NULL;
		param_to = NULL;
	}
	string getTypeName() {
		return("hour_interval");
	}
protected:
	int *param_from;
	int *param_to;
};

class cConfigItem_ports : public cConfigItem {
public:
	cConfigItem_ports(const char* name, char *port_matrix);
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	string normalizeStringValueForCmp(string value);
	string normalizeStringValuesForCmp(list<string> values);
	bool enable_normalizeStringValuesForCmp() { return(true); }
	bool enableMultiValues() { return(true); }
	static unsigned setPortMatrix(const char *port_str, char *port_matrix, unsigned port_max = 65535);
	static string getPortString(char *port_matrix, unsigned port_max = 65535);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_value_str, bool enableClearBeforeFirstSet = false);
	void clear();
	void initParamPointers() {
		param_port_matrix = NULL;
	}
	string getTypeName() {
		return("ports");
	}
protected:
	char *param_port_matrix;
	unsigned port_max;
};

class cConfigItem_hosts : public cConfigItem {
public:
	cConfigItem_hosts(const char* name, vector<vmIP> *adresses, vector<vmIPmask> *nets);
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	bool enableMultiValues() { return(true); }
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_value_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_adresses = NULL;
		param_nets = NULL;
	}
	string getTypeName() {
		return("hosts");
	}
protected:
	vector<vmIP> *param_adresses;
	vector<vmIPmask> *param_nets;
};

class cConfigItem_ip : public cConfigItem {
public:
	cConfigItem_ip(const char* name, vmIP *param);
	vmIP getValue();
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	void initParamPointers() {
		param_ip = NULL;
	}
	string getTypeName() {
		return("ip");
	}
protected:
	vmIP *param_ip;
};

class cConfigItem_ip_port : public cConfigItem {
public:
	cConfigItem_ip_port(const char* name, ip_port *param);
	ip_port getValue();
	string getValueStr(bool configFile = false);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	void initParamPointers() {
		param_ip_port = NULL;
	}
	string getTypeName() {
		return("ip_port");
	}
protected:
	ip_port *param_ip_port;
};

class cConfigItem_ip_ports : public cConfigItem {
public:
	cConfigItem_ip_ports(const char* name, vector<vmIPport> *param);
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	string normalizeStringValueForCmp(string value);
	bool enableMultiValues() { return(true); }
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_value_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_ip_ports = NULL;
	}
	string getTypeName() {
		return("ip_port_list");
	}
protected:
	vector<vmIPport> *param_ip_ports;
};

class cConfigItem_ip_port_str_map : public cConfigItem {
public:
	cConfigItem_ip_port_str_map(const char* name, map<vmIPport, string> *ip_port_string_map);
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	string normalizeStringValueForCmp(string value);
	bool enableMultiValues() { return(true); }
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_value_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_ip_port_string_map = NULL;
	}
	string getTypeName() {
		return("ip_port_str_list");
	}
protected:
	map<vmIPport, string> *param_ip_port_string_map;
};

class cConfigItem_nat_aliases : public cConfigItem {
public:
	cConfigItem_nat_aliases(const char* name, nat_aliases_t *nat_aliases);
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	string normalizeStringValueForCmp(string value);
	bool enableMultiValues() { return(true); }
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_value_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_nat_aliases = NULL;
	}
	string getTypeName() {
		return("nat_aliases_list");
	}
protected:
	nat_aliases_t *param_nat_aliases;
};

class cConfigItem_net_map : public cConfigItem {
public:
	typedef map<vmIPmask_order2, vmIPmask_order2> t_net_map;
public:
	cConfigItem_net_map(const char* name, t_net_map *net_map);
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	string normalizeStringValueForCmp(string value);
	bool enableMultiValues() { return(true); }
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_value_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_net_map = NULL;
	}
	string getTypeName() {
		return("net_map_list");
	}
protected:
	t_net_map *param_net_map;
public:
	static vmIP convIP(vmIP ip, t_net_map *net_map);
};

class cConfigItem_domain_map : public cConfigItem {
public:
	typedef std::map<std::string, std::string> t_domain_map;
public:
	cConfigItem_domain_map(const char* name, t_domain_map *domain_map);
	string getValueStr(bool configFile = false);
	list<string> getValueListStr();
	string normalizeStringValueForCmp(string value);
	bool enableMultiValues() { return(true); }
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	bool setParamFromValuesStr(vector<string> list_value_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_domain_map = NULL;
	}
	string getTypeName() {
		return("domain_map_list");
	}
protected:
	t_domain_map *param_domain_map;
};

class cConfigItem_custom_headers : public cConfigItem {
public:
	cConfigItem_custom_headers(const char* name, vector<dstring> *custom_headers);
	string getValueStr(bool configFile = false);
	string normalizeStringValueForCmp(string value);
protected:
	bool setParamFromConfigFile(CSimpleIniA *ini, bool enableClearBeforeFirstSet = false);
	bool setParamFromValueStr(string value_str, bool enableClearBeforeFirstSet = false);
	void initBeforeSet();
	void initParamPointers() {
		param_custom_headers = NULL;
	}
	string getTypeName() {
		return("custom_headers_list");
	}
protected:
	vector<dstring> *param_custom_headers;
};

class cConfigItem_type_compress : public cConfigItem_yesno {
public:
	cConfigItem_type_compress(const char* name, CompressStream::eTypeCompress *type_compress = NULL);
	cConfigItem_type_compress(const char* name, FileZipHandler::eTypeCompress *type_compress = NULL);
};


class cConfigMap {
public:
	struct cItem {
		list<string> values;
		void add(const char *value) {
			values.push_back(value);
		}
		string valuesToStr();
		bool operator == (cItem& other) { 
			if(this->values.size() != other.values.size()) {
				return(false);
			}
			this->values.sort();
			other.values.sort();
			list<string>::iterator iter1 = this->values.begin();
			list<string>::iterator iter2 = other.values.begin();
			while(iter1 != this->values.end() && iter2 != other.values.end()) {
				if(*iter1 != *iter2) {
					return(false);
				}
				++iter1;
				++iter2;
			}
			return(true);
		}
	};
public:
	void addItem(const char *name, const char *value);
	bool existsItem(const char *name);
	string getFirstItem(const char *name, bool toLower = false);
	string getItems(const char *name, const char *separator = ";", bool toLower = false);
	string comp(cConfigMap *other, class cConfig *config, cConfig *defaultConfig = NULL);
	bool isObsoleteParameter(string parameter);
public:
	map<string, cItem> config_map;
};


class cConfig {
public:
	struct sDiffValue {
		string config_name;
		string old_value;
		string new_value;
		string format() {
			return(config_name + " : " + old_value + " / " + new_value);
		}
	};
public:
	cConfig();
	~cConfig();
	void addConfigItems();
	void addConfigItem(cConfigItem *configItem);
	void group(const char *groupName);
	void subgroup(const char *subgroupName);
	void normal();
	void advanced();
	void expert();
	void obsolete();
	void minorBegin();
	void minorEnd();
	void minorGroupIfNotSetBegin();
	void minorGroupIfNotSetEnd();
	void setDisableIfBegin(string disableIf);
	void setDisableIfEnd();
	bool loadFromConfigFileOrDirectory(const char *filename, bool silent = false);
	bool loadFromConfigFile(const char *filename, string *error = NULL, bool silent = false);
	bool loadConfigMapConfigFileOrDirectory(cConfigMap *configMap, const char *filename);
	bool loadConfigMapFromConfigFile(cConfigMap *configMap, const char *filename);
	void evSetConfigItem(cConfigItem *configItem);
	cConfigMap getConfigMap();
	string getContentConfig(bool configFile = false, bool putDefaultValues = false);
	string getJson(bool onlyIfSet = false, vector<string> *filter = NULL);
	void setFromJson(const char *jsonStr, bool onlyIfSet = true);
	void setFromMysql(bool checkConnect = false, bool onlyIfSet = true);
	void putToMysql();
	void setDefaultValues();
	void clearToDefaultValues();
	void setDescription(const char *itemName, const char *description);
	void setHelp(const char *itemName, const char *help);
	string getMainItemName(const char *name);
	bool testEqValues(const char *itemName, const char *value1, const char *value2);
	bool testEqValues(string itemName, list<string> values1, list<string> values2);
	cConfigItem *getItem(const char *itemName);
	bool isSet();
	bool isSet(const char *itemName);
	void beginTrackDiffValues();
	void endTrackDiffValues(list<sDiffValue> *diffValues);
private:
	void loadFromConfigFileError(const char *errorString, const char *filename, string *error = NULL);
	void lock() {
		__SYNC_LOCK_USLEEP(config_sync, 100);
	}
	void unlock() {
		__SYNC_UNLOCK(config_sync);
	}
private:
	list<string> config_list;
	map<string, cConfigItem*> config_map;
	volatile int config_sync;
	cConfigItem::eTypeLevel defaultLevel;
	string defaultGroup;
	string defaultSubgroup;
	bool defaultMinor;
	bool defaultMinorGroupIfNotSet;
	string defaultDisableIf;
	bool setFromMysqlOk;
	list<sDiffValue> diffValues;
	bool diffValuesTrack;
};


#endif
