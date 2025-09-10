#include <stdio.h>
#include <syslog.h>
#include <dirent.h>
#include <iomanip>
#include <limits.h>
#include <algorithm>
#include <ctype.h>

#include "config_param.h"
#include "voipmonitor.h"
#include "sql_db.h"
#include "tools_global.h"

#ifdef FREEBSD
#include <sys/socket.h>
#endif


extern int verbosity;
extern int opt_mysqlloadconfig;


cConfigItem::cConfigItem(const char *name) {
	config_name = name;
	config_file_section = "general";
	level = levelNormal;
	set = false;
	set_in_config = false;
	set_in_db = false;
	set_in_json = false;
	exists = false;
	exists_in_config = false;
	exists_in_db = false;
	exists_in_json = false;
	defaultValueStr_set = false;
	naDefaultValueStr = false;
	clearBeforeFirstSet = false;
	minor = false;
	minorGroupIfNotSet = false;
	readOnly = false;
	alwaysShow = false;
}

cConfigItem *cConfigItem::addAlias(const char *name_alias) {
	config_name_alias.push_back(name_alias);
	return(this);
}

cConfigItem *cConfigItem::setDefaultValueStr(const char *defaultValueStr) {
	this->defaultValueStr = defaultValueStr;
	this->defaultValueStr_set = true;
	return(this);
}

cConfigItem *cConfigItem::setNaDefaultValueStr() {
	naDefaultValueStr = true;
	return(this);
}

cConfigItem *cConfigItem::setClearBeforeFirstSet() {
	clearBeforeFirstSet = true;
	return(this);
}

cConfigItem *cConfigItem::setMinor() {
	minor = true;
	return(this);
}

cConfigItem *cConfigItem::setMinorGroupIfNotSet() {
	minorGroupIfNotSet = true;
	return(this);
}

cConfigItem *cConfigItem::setReadOnly() {
	readOnly = true;
	return(this);
}

cConfigItem *cConfigItem::setAlwaysShow() {
	alwaysShow = true;
	return(this);
}

cConfigItem *cConfigItem::setDisableIf(const char *disableIf) {
	this->disableIf = disableIf;
	return(this);
}

void cConfigItem::setConfigFileSection(const char *config_file_section) {
	this->config_file_section = config_file_section;
}

cConfigItem *cConfigItem::addValue(const char *str, int value) {
	string _str = str;
	std::transform(_str.begin(), _str.end(), _str.begin(), ::tolower);
	mapValues.push_back(sMapValue(str, value));
	return(this);
}

cConfigItem *cConfigItem::addValues(const char *str_values) {
	vector<string> str_values_v = split(str_values, "|");
	for(vector<string>::iterator it = str_values_v.begin(); it != str_values_v.end(); it++) {
		vector<string> str_values_v2 = split(*it, ':');
		if(str_values_v2.size() == 2) {
			addValue(str_values_v2[0].c_str(), atoi(str_values_v2[1].c_str()));
		}
	}
	return(this);
}

cConfigItem *cConfigItem::addStringItem(const char *str) {
	mapValues.push_back(sMapValue(str, INT_MIN));
	return(this);
}

cConfigItem *cConfigItem::addStringItems(const char *str_values) {
	vector<string> str_values_v = split(str_values, "|");
	for(vector<string>::iterator it = str_values_v.begin(); it != str_values_v.end(); it++) {
		addStringItem(it->c_str());
	}
	return(this);
}

cConfigItem *cConfigItem::setSubtype(const char *subtype) {
	this->subtype = subtype ? subtype : "";
	return(this);
}

cConfigItem *cConfigItem::setDescription(const char *description) {
	this->description = description ? description : "";
	return(this);
}

cConfigItem *cConfigItem::setHelp(const char *help) {
	this->help = help ? help : "";
	return(this);
}

bool cConfigItem::existsInConfigFile(CSimpleIniA *ini) {
	const char *value = ini->GetValue("general", config_name.c_str(), NULL);
	if(value) {
		return(true);
	}
	for(list<string>::iterator iter = config_name_alias.begin(); iter != config_name_alias.end(); iter++) {
		value = ini->GetValue("general", (*iter).c_str(), NULL);
		if(value) {
			return(true);
		}
	}
	return(false);
}

string cConfigItem::getValueFromConfigFile(CSimpleIniA *ini) {
	const char *value = ini->GetValue("general", config_name.c_str(), NULL);
	if(value) {
		return(value);
	}
	for(list<string>::iterator iter = config_name_alias.begin(); iter != config_name_alias.end(); iter++) {
		value = ini->GetValue("general", (*iter).c_str(), NULL);
		if(value) {
			return(value);
		}
	}
	return("");
}

vector<string> cConfigItem::getValuesFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet) {
	vector<string> list_values;
	CSimpleIniA::TNamesDepend values;
	if(ini->GetAllValues("general", config_name.c_str(), values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		for (; i != values.end(); ++i) {
			list_values.push_back(i->pItem);
		}
	}
	return(list_values);
}

bool cConfigItem::getValueFromMapValues(const char *str_value, int *rslt_value) {
	*rslt_value = 0;
	if(mapValues.size()) {
		string _str_value = str_value;
		std::transform(_str_value.begin(), _str_value.end(), _str_value.begin(), ::tolower);
		unsigned find_length = 0;
		for(list<sMapValue>::iterator iter = mapValues.begin(); iter != mapValues.end(); iter++) {
			if(!strncmp(_str_value.c_str(), iter->str.c_str(), iter->str.length())) {
				if(!find_length || iter->str.length() > find_length) {
					*rslt_value = iter->value;
					find_length = iter->str.length();
				}
			}
		}
		if(find_length > 0) {
			return(true);
		}
	}
	return(false);
}

string cConfigItem::getStringFromMapValues(int value) {
	for(list<sMapValue>::iterator iter = mapValues.begin(); iter != mapValues.end(); iter++) {
		if(iter->value == value) {
			return(iter->str);
		}
	}
	return("");
}

void cConfigItem::init() {
	initParamPointers();
	initOther();
	initVirtParam();
}

list<cConfigItem::sMapValue> cConfigItem::getMenuItems() {
	list<sMapValue> menu;
	for(list<sMapValue>::iterator iter = mapValues.begin(); iter != mapValues.end(); iter++) {
		addItemToMenuItems(&menu, *iter);
	}
	return(menu);
}

void cConfigItem::addItemToMenuItems(list<sMapValue> *menu, sMapValue menuItem) {
	for(list<sMapValue>::iterator iter = menu->begin(); iter != menu->end(); iter++) {
		if(iter->value == INT_MIN ?
		    iter->str == menuItem.str :
		    iter->value == menuItem.value) {
			return;
		}
	}
	menu->push_back(menuItem);
}

string cConfigItem::getJson() {
	string password_value = "******";
	JsonExport json;
	json.add("name", config_name);
	json.add("type", getTypeName());
	if(subtype.length()) {
		json.add("subtype", subtype);
	}
	if(description.length()) {
		json.add("description", description);
	}
	if(help.length()) {
		json.add("help", help);
	}
	json.add("set", set);
	if(set_in_config) {
		json.add("set_in_config", set_in_config);
		if(!value_in_config.empty()) {
			json.add("value_in_config", isPassword() ? password_value : value_in_config);
		}
	}
	if(set_in_db) {
		json.add("set_in_db", set_in_db);
		if(!value_in_db.empty()) {
			json.add("value_in_db", isPassword() ? password_value : value_in_db);
		}
	}
	if(set_in_json &&
	   (!set_in_db || value_in_json != value_in_db)) {
		json.add("set_in_json", set_in_json);
		if(!value_in_json.empty()) {
			json.add("value_in_json", isPassword() ? password_value : value_in_json);
		}
	}
	json.add("value", isPassword() ? password_value : getValueStr());
	json.add("default", isPassword() ? password_value : defaultValueStr);
	json.add("group", group_name);
	json.add("subgroup", subgroup_name);
	json.add("level", level);
	extern bool opt_all_configuration_options_in_gui;
	if(!opt_all_configuration_options_in_gui) {
		json.add("minor", minor);
		json.add("minor_group_if_not_set", minorGroupIfNotSet);
	}
	json.add("read_only", readOnly);
	if(!disableIf.empty()) {
		json.add("disable_if", disableIf);
	}
	json.add("always_show", alwaysShow);
	cConfigItem_integer *dc_integer = dynamic_cast<cConfigItem_integer*>(this);
	if(dc_integer) {
		if(dc_integer->getMaximum()) {
			json.add("maximum", dc_integer->getMaximum());
		}
		if(dc_integer->getMinimum()) {
			json.add("minimum", dc_integer->getMinimum());
		}
		if(dc_integer->isMenuValue()) {
			json.add("menu_value", true);
		}
		if(dc_integer->isOnlyMenu()) {
			json.add("only_menu", true);
		}
	}
	if(dynamic_cast<cConfigItem_string*>(this) && dynamic_cast<cConfigItem_string*>(this)->isPassword()) {
		json.add("password", true);
	}
	list<sMapValue> menuItems = getMenuItems();
	if(menuItems.size()) {
		ostringstream outStr;
		int counter = 0;
		for(list<sMapValue>::iterator iter = menuItems.begin(); iter != menuItems.end(); iter++) {
			if(counter) {
				outStr << ';';
			}
			outStr << iter->str;
			if(iter->value != INT_MIN) {
				outStr << ':' << iter->value;
			}
			++counter;
		}
		json.add("menu", outStr.str());
	}
	return(json.getJson());
}

void cConfigItem::setDefaultValue() {
	if(!defaultValueStr_set && !naDefaultValueStr) {
		 defaultValueStr = getValueStr();
		 defaultValueStr_set = true;
	}
}

void cConfigItem::clearToDefaultValue() {
	if(defaultValueStr_set && !naDefaultValueStr) {
		 setParamFromValueStr(defaultValueStr);
	}
	set = false;
	set_in_config = false;
	set_in_db = false;
	set_in_json = false;
	value_in_config.clear();
	value_in_db.clear();
	value_in_json.clear();
}

void cConfigItem::doClearBeforeFirstSet() {
	if(clearBeforeFirstSet && !set) {
		clear();
	}
}

cConfigItem_yesno::cConfigItem_yesno(const char *name, bool *param) 
 : cConfigItem(name) {
	init();
	param_bool = param;
}

cConfigItem_yesno::cConfigItem_yesno(const char *name, int *param)
 : cConfigItem(name) {
	init();
	param_int = param ? param : &param_virt;
}

int cConfigItem_yesno::getValue() {
	if(param_bool) {
		return(*param_bool);
	}
	if(param_int) {
		return(*param_int);
	}
	return(0);
}

string cConfigItem_yesno::getValueStr(bool /*configFile*/) {
	int val = 0;
	if(param_bool) {
		val = *param_bool;
	}
	if(param_int) {
		val = *param_int;
	}
	string str = getStringFromMapValues(val);
	if(!str.empty()) {
		return(str);
	}
	if(neg) {
		val = !val;
	}
	return(val ? "yes" : "no");
}

string cConfigItem_yesno::normalizeStringValueForCmp(string value) {
	int _value;
	if(getValueFromMapValues(value.c_str(), &_value)) {
		return(intToString(_value));
	} else {
		return(intToString(yesno(value.c_str())));
	}
}

bool cConfigItem_yesno::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
}
	
bool cConfigItem_yesno::setParamFromValueStr(string value_str, bool /*enableInitBeforeSet*/, bool enableClearBeforeFirstSet) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
		if(enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		int _value;
		if(getValueFromMapValues(value, &_value)) {
			if(param_bool) {
				*param_bool = _value;
				++ok;
			}
			if(param_int) {
				*param_int = _value;
				++ok;
			}
			return(ok > 0);
		}
		if(param_bool) {
			*param_bool = yesno(value);
			if(neg) {
				*param_bool = !*param_bool;
			}
			++ok;
		}
		if(param_int) {
			*param_int = yesno(value);
			if(neg) {
				*param_int = !*param_int;
			}
			++ok;
		}
	}
	return(ok > 0);
}

list<cConfigItem::sMapValue> cConfigItem_yesno::getMenuItems() {
	list<sMapValue> menu;
	menu = cConfigItem::getMenuItems();
	bool existsNumYes = false, existsNumNo = false;
	for(list<sMapValue>::iterator iter = menu.begin(); iter != menu.end(); iter++) {
		if(iter->value == 1) {
			existsNumYes = true;
		} else if(iter->value == 0) {
			existsNumNo = true;
		}
	}
	if(!existsNumYes && !disable_yes) {
		menu.push_front(sMapValue("yes", 1));
	}
	if(!existsNumNo && !disable_no) {
		menu.push_back(sMapValue("no", 0));
	}
	return(menu);
}

cConfigItem_integer::cConfigItem_integer(const char *name, int *param)
 : cConfigItem(name) {
	init();
	param_int = param;
}

cConfigItem_integer::cConfigItem_integer(const char *name, unsigned int *param)
 : cConfigItem(name) {
	init();
	param_uint = param;
}

cConfigItem_integer::cConfigItem_integer(const char *name, int64_t *param)
 : cConfigItem(name) {
	init();
	param_int64 = param ? param : &param_virt;
}

cConfigItem_integer::cConfigItem_integer(const char *name, uint64_t *param)
 : cConfigItem(name) {
	init();
	param_uint64 = param;
}

cConfigItem_integer::cConfigItem_integer(const char *name, vector<int> *param)
 : cConfigItem(name) {
	init();
	param_vect_int = param;
}

int64_t cConfigItem_integer::getValue() {
	if(param_int) {
		return(*param_int);
	}
	if(param_uint) {
		return(*param_uint);
	}
	if(param_int64) {
		return(*param_int64);
	}
	if(param_uint64) {
		return(*param_uint64);
	}
	return(0);
}

string cConfigItem_integer::getValueStr(bool configFile) {
	if(param_vect_int) {
		ostringstream outStr;
		int counter = 0;
		for(vector<int>::iterator iter = param_vect_int->begin(); iter != param_vect_int->end(); iter++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << explodeSeparators[0];
				}
			}
			outStr << *iter;
			++counter;
		}
		return(outStr.str());
	}
	int64_t val = 0;
	if(param_int) {
		val = *param_int;
	}
	if(param_uint) {
		val = *param_uint;
	}
	if(param_int64) {
		val = *param_int64;
	}
	if(param_uint64) {
		val = *param_uint64;
	}
	if(!menuValue) {
		string str = getStringFromMapValues(val);
		if(!str.empty()) {
			return(str);
		}
	}
	if(multiple) {
		val /= multiple;
	}
	if(yesValue && val == yesValue) {
		return("yes");
	}
	ostringstream outStr;
	outStr << val;
	return(outStr.str());
}

list<string> cConfigItem_integer::getValueListStr() {
	list<string> l;
	if(param_vect_int) {
		for(vector<int>::iterator iter = param_vect_int->begin(); iter != param_vect_int->end(); iter++) {
			l.push_back(intToString(*iter));
		}
	} else {
		l.push_back(getValueStr());
	}
	return(l);
}

string cConfigItem_integer::normalizeStringValueForCmp(string value) {
	if(param_vect_int && !explodeSeparators.empty()) {
		vector<string> value_vect = split(value.c_str(), split2chars(explodeSeparators), true);
		string rslt;
		for(vector<string>::iterator iter = value_vect.begin(); iter != value_vect.end(); iter++) {
			if(!rslt.empty()) {
				rslt += explodeSeparators[0];
			}
			rslt += *iter;
		}
		return(rslt);
	} else {
		int _value;
		if(getValueFromMapValues(value.c_str(), &_value)) {
			return(intToString(_value));
		}
		if(value == "no") {
			return("0");
		}
		return(value);
	}
}

bool cConfigItem_integer::enableMultiValues() {
	return(param_vect_int && !explodeSeparators.empty());
}

bool cConfigItem_integer::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(param_vect_int) {
		return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
	} else {
		return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
	}
}

bool cConfigItem_integer::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
		if(enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		int _value;
		if(getValueFromMapValues(value, &_value)) {
			if(param_int) {
				*param_int = _value;
				++ok;
			}
			if(param_uint) {
				*param_uint = _value;
				++ok;
			}
			if(param_int64) {
				*param_int64 = _value;
				++ok;
			}
			if(param_uint64) {
				*param_uint64 = _value;
				++ok;
			}
			return(ok > 0);
		}
		if(param_int) {
			*param_int = atoi(value);
			if(maximum && *param_int > maximum) {
				*param_int = maximum;
			}
			if(minimum && *param_int < minimum) {
				*param_int = minimum;
			}
			if(ifZeroOrNegative && *param_int <= 0) {
				*param_int = ifZeroOrNegative;
			}
			if(multiple) {
				*param_int *= multiple;
			}
			if(!*param_int && yesValue && yesno(value)) {
				*param_int = yesValue;
			}
			++ok;
		}
		if(param_uint) {
			*param_uint = atol(value);
			if(maximum && *param_uint > (unsigned)maximum) {
				*param_uint = maximum;
			}
			if(minimum && *param_uint < (unsigned)minimum) {
				*param_uint = minimum;
			}
			if(ifZeroOrNegative && *param_uint == 0) {
				*param_uint = ifZeroOrNegative;
			}
			if(multiple) {
				*param_uint *= multiple;
			}
			if(!*param_uint && yesValue && yesno(value)) {
				*param_uint = yesValue;
			}
			++ok;
		}
		if(param_int64) {
			*param_int64 = atoll(value);
			if(maximum && *param_int64 > (unsigned)maximum) {
				*param_int64 = maximum;
			}
			if(minimum && *param_int64 < (unsigned)minimum) {
				*param_int64 = minimum;
			}
			if(ifZeroOrNegative && *param_int64 <= 0) {
				*param_int64 = ifZeroOrNegative;
			}
			if(multiple) {
				*param_int64 *= multiple;
			}
			if(!*param_int64 && yesValue && yesno(value)) {
				*param_int64 = yesValue;
			}
			++ok;
		}
		if(param_uint64) {
			*param_uint64 = atoll(value);
			if(maximum && *param_uint64 > (unsigned)maximum) {
				*param_uint64 = maximum;
			}
			if(minimum && *param_uint64 < (unsigned)minimum) {
				*param_uint64 = minimum;
			}
			if(ifZeroOrNegative && *param_uint64 <= 0) {
				*param_uint64 = ifZeroOrNegative;
			}
			if(multiple) {
				*param_uint64 *= multiple;
			}
			if(!*param_uint64 && yesValue && yesno(value)) {
				*param_uint64 = yesValue;
			}
			++ok;
		}
		if(param_vect_int && !explodeSeparators.empty()) {
			if(enableInitBeforeSet) {
				initBeforeSet();
			}
			*param_vect_int = split2int(value, split2chars(explodeSeparators), true);
		}
	}
	return(ok > 0);
}

bool cConfigItem_integer::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_vect_int) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		if(!ok && enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		vector<int> _param_vect_int = split2int(iter->c_str(), split2chars(explodeSeparators), true);
		for(unsigned i = 0; i < _param_vect_int.size(); i++) {
			param_vect_int->push_back(_param_vect_int[i]);
			++ok;
		}
	}
	return(ok > 0);
}

cConfigItem_float::cConfigItem_float(const char *name, float *param)
 : cConfigItem(name) {
	init();
	param_float = param;
}

cConfigItem_float::cConfigItem_float(const char *name, double *param)
 : cConfigItem(name) {
	init();
	param_double = param;
}

double cConfigItem_float::getValue() {
	if(param_float) {
		return(*param_float);
	}
	if(param_double) {
		return(*param_double);
	}
	return(0);
}

string cConfigItem_float::getValueStr(bool /*configFile*/) {
	double val = 0;
	if(param_float) {
		val = *param_float;
	}
	if(param_double) {
		val = *param_double;
	}
	ostringstream outStr;
	outStr << fixed << setprecision(2) << val;
	return(outStr.str());
}

string cConfigItem_float::normalizeStringValueForCmp(string value) {
	ostringstream outStr;
	outStr << atof(value.c_str());
	return(outStr.str());
}

bool cConfigItem_float::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_float::setParamFromValueStr(string value_str, bool /*enableInitBeforeSet*/, bool enableClearBeforeFirstSet) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
		if(enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		if(param_float) {
			*param_float = atof(value);
			++ok;
		}
		if(param_double) {
			*param_double = atof(value);
			++ok;
		}
	}
	return(ok > 0);
}

cConfigItem_string::cConfigItem_string(const char *name, string *param)
 : cConfigItem(name) {
	init();
	param_str = param ? param : &param_virt;
}

cConfigItem_string::cConfigItem_string(const char *name, char *param, int length)
 : cConfigItem(name) {
	init();
	param_strchar = param;
	param_strchar_length = length;
}

cConfigItem_string::cConfigItem_string(const char *name, vector<string> *param)
 : cConfigItem(name) {
	init();
	param_vect_str = param;
}

string cConfigItem_string::getValue() {
	if(param_str) {
		return(*param_str);
	}
	if(param_strchar) {
		return(param_strchar);
	}
	return("");
}

string cConfigItem_string::getValueStr(bool configFile) {
	ostringstream outStr;
	if(param_vect_str) {
		int counter = 0;
		for(vector<string>::iterator iter = param_vect_str->begin(); iter != param_vect_str->end(); iter++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << explodeSeparators[0];
				}
			}
			outStr << *iter;
			++counter;
		}
	} else {
		string val;
		if(param_str) {
			val = *param_str;
		}
		if(param_strchar) {
			val = param_strchar;
		}
		if(!prefix.empty() && prefix == val.substr(0, prefix.length())) {
			val = val.substr(prefix.length());
		}
		outStr << val;
	}
	return(outStr.str());
}

list<string> cConfigItem_string::getValueListStr() {
	list<string> l;
	if(param_vect_str) {
		for(vector<string>::iterator iter = param_vect_str->begin(); iter != param_vect_str->end(); iter++) {
			l.push_back(*iter);
		}
	} else {
		l.push_back(getValueStr());
	}
	return(l);
}

string cConfigItem_string::normalizeStringValueForCmp(string value) {
	if(param_vect_str && !explodeSeparators.empty()) {
		vector<string> value_vect = split(value.c_str(), split2chars(explodeSeparators), true);
		string rslt;
		for(vector<string>::iterator iter = value_vect.begin(); iter != value_vect.end(); iter++) {
			if(!rslt.empty()) {
				rslt += explodeSeparators[0];
			}
			rslt += *iter;
		}
		return(rslt);
	} else {
		if(!prefix.empty() && strncmp(value.c_str(), prefix.c_str(), prefix.length())) {
			value = prefix + value;
		}
		if(!suffix.empty() && strncmp(value.c_str() + value.length() - suffix.length(), suffix.c_str(), suffix.length())) {
			value = value + suffix;
		}
	}
	return(value);
}

bool cConfigItem_string::enableMultiValues() {
	return(param_vect_str && !explodeSeparators.empty());
}

bool cConfigItem_string::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(param_vect_str) {
		return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
	} else {
		return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
	}
}

bool cConfigItem_string::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
		if(enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		if(param_str) {
			*param_str = value;
			if(!prefix.empty() && strncmp(param_str->c_str(), prefix.c_str(), prefix.length())) {
				*param_str = prefix + *param_str;
			}
			if(!suffix.empty() && strncmp(param_str->c_str() + param_str->length() - suffix.length(), suffix.c_str(), suffix.length())) {
				*param_str = *param_str + suffix;
			}
			++ok;
		}
		if(param_strchar) {
			strncpy(param_strchar, value, param_strchar_length);
			param_strchar[param_strchar_length - 1] = 0;
			if(!prefix.empty() && strncmp(param_strchar, prefix.c_str(), prefix.length())) {
				strncpy(param_strchar, (prefix + param_strchar).c_str(), param_strchar_length);
				param_strchar[param_strchar_length - 1] = 0;
			}
			if(!suffix.empty() && strncmp(param_strchar + strlen(param_strchar) - suffix.length(), suffix.c_str(), suffix.length())) {
				strncpy(param_strchar, (param_strchar + suffix).c_str(), param_strchar_length);
				param_strchar[param_strchar_length - 1] = 0;
			}
			++ok;
		}
		if(param_vect_str && !explodeSeparators.empty()) {
			if(enableInitBeforeSet) {
				initBeforeSet();
			}
			*param_vect_str = split(value, split2chars(explodeSeparators), true);
		}
	}
	return(ok > 0);
}

bool cConfigItem_string::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_vect_str) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		if(!ok && enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		vector<string> _param_vect_str = split(iter->c_str(), split2chars(explodeSeparators), true);
		for(unsigned i = 0; i < _param_vect_str.size(); i++) {
			param_vect_str->push_back(_param_vect_str[i]);
			++ok;
		}
	}
	return(ok > 0);
}

void cConfigItem_string::initBeforeSet() {
	if(param_vect_str) {
		param_vect_str->clear();
	}
}

cConfigItem_hour_interval::cConfigItem_hour_interval(const char *name, int *from, int *to)
 : cConfigItem(name) {
	init();
	this->param_from = from;
	this->param_to = to;
}

string cConfigItem_hour_interval::getValueStr(bool /*configFile*/) {
	if(!param_from || !param_to || *param_from == -1 || *param_to == -1) {
		return("");
	}
	ostringstream outStr;
	outStr << *param_from << "-" << *param_to;
	return(outStr.str());
}

string cConfigItem_hour_interval::normalizeStringValueForCmp(string value) {
	find_and_replace(value, " ", "");
	return(value);
}

bool cConfigItem_hour_interval::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_hour_interval::setParamFromValueStr(string value_str, bool /*enableInitBeforeSet*/, bool enableClearBeforeFirstSet) {
	if(!param_from || !param_to ||
	   value_str.empty()) {
		return(false);
	}
	const char *value = value_str.c_str();
	if(value) {
		if(enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		string fromTo = reg_replace(value, "([0-9]+)[- ]*([0-9]+)", "$1-$2", __FILE__, __LINE__);
		if(fromTo.empty()) {
			*param_from = *param_to = atoi(value);
			if(*param_from < 0 || *param_from > 23) {
				*param_from = -1;
				*param_to = -1;
			}
		} else {
			sscanf(fromTo.c_str(), "%i-%i", param_from, param_to);
			if(*param_from < 0 || *param_from > 23 ||
			   *param_to < 0 || *param_to > 23) {
				*param_from = -1;
				*param_to = -1;
			}
		}
		return(true);
	}
	return(false);
}

cConfigItem_ports::cConfigItem_ports(const char* name, char *port_matrix)
 : cConfigItem(name) {
	init();
	param_port_matrix = port_matrix;
	param_ports = NULL;
	port_max = 65535;
}

cConfigItem_ports::cConfigItem_ports(const char* name, map<u_int16_t, bool> *ports)
 : cConfigItem(name) {
	init();
	param_ports = ports;
	param_port_matrix = NULL;
	port_max = 65535;
}

string cConfigItem_ports::getValueStr(bool configFile) {
	if(!param_port_matrix &&
	   (!param_ports || !param_ports->size())) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	if(param_port_matrix) {
		for(unsigned i = 0; i <= port_max; i++) {
			if(param_port_matrix[i]) {
				if(counter) {
					if(configFile) {
						outStr << endl << config_name << " = ";
					} else {
						outStr << ';';
					}
				}
				outStr << i;
				unsigned j;
				for(j = i; j <= (port_max-1) && param_port_matrix[j+1]; j++);
				if(j > i) {
					outStr << '-' << j;
					i = j;
				}
				++counter;
			}
		}
	}
	if(param_ports) {
		map<u_int16_t, bool>::iterator iter_i;
		for(iter_i = param_ports->begin(); iter_i != param_ports->end(); iter_i++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << ';';
				}
			}
			outStr << iter_i->first;
			map<u_int16_t, bool>::iterator iter_j = iter_i;
			while(nextMapPortIterator(iter_j) != param_ports->end() && nextMapPortIterator(iter_j)->first == iter_j->first + 1) {
				iter_j++;
			}
			if(iter_j->first > iter_i->first) {
				outStr << '-' << iter_j->first;
				iter_i = iter_j;
			}
			++counter;
		}
	}
	return(outStr.str());
}

list<string> cConfigItem_ports::getValueListStr() {
	list<string> l;
	if(param_port_matrix) {
		for(unsigned i = 0; i <= port_max; i++) {
			if(param_port_matrix[i]) {
				unsigned j;
				for(j = i; j <= (port_max-1) && param_port_matrix[j+1]; j++);
				if(j > i) {
					l.push_back(intToString(i) + "-" + intToString(j));
					i = j;
				} else  {
					l.push_back(intToString(i));
				}
			}
		}
	}
	if(param_ports) {
		map<u_int16_t, bool>::iterator iter_i;
		for(iter_i = param_ports->begin(); iter_i != param_ports->end(); iter_i++) {
			map<u_int16_t, bool>::iterator iter_j = iter_i;
			while(nextMapPortIterator(iter_j) != param_ports->end() && nextMapPortIterator(iter_j)->first == iter_j->first + 1) {
				iter_j++;
			}
			if(iter_j->first > iter_i->first) {
				l.push_back(intToString(iter_i->first) + "-" + intToString(iter_j->first));
				iter_i = iter_j;
			} else  {
				l.push_back(intToString(iter_i->first));
			}
		}
	}
	return(l);
}

string cConfigItem_ports::normalizeStringValueForCmp(string value) {
	if(param_port_matrix) {
		char *port_matrix = new char[this->port_max + 1];
		cConfigItem_ports::setPortMatrix(value.c_str(), port_matrix, this->port_max);
		string rslt = getPortString(port_matrix, this->port_max);
		delete [] port_matrix;
		return(rslt);
	}
	if(param_ports) {
		map<u_int16_t, bool> ports;
		cConfigItem_ports::setPorts(value.c_str(), &ports, this->port_max);
		string rslt = getPortString(&ports);
		return(rslt);
	}
	return("");
}

string cConfigItem_ports::normalizeStringValuesForCmp(list<string> values) {
	if(param_port_matrix) {
		char *port_matrix = new char[this->port_max + 1];
		memset(port_matrix, 0, this->port_max + 1);
		for(list<string>::iterator iter = values.begin(); iter != values.end(); iter++) {
			cConfigItem_ports::setPortMatrix(iter->c_str(), port_matrix, this->port_max);
		}
		string rslt = getPortString(port_matrix, this->port_max);
		delete [] port_matrix;
		return(rslt);
	}
	if(param_ports) {
		map<u_int16_t, bool> ports;
		for(list<string>::iterator iter = values.begin(); iter != values.end(); iter++) {
			cConfigItem_ports::setPorts(iter->c_str(), &ports, this->port_max);
		}
		string rslt = getPortString(&ports);
		return(rslt);
	}
	return("");
}

unsigned cConfigItem_ports::setPortMatrix(const char *port_str, char *port_matrix, unsigned port_max) {
	return(_setPorts(port_str, port_matrix, NULL, port_max));
}

unsigned cConfigItem_ports::setPorts(const char *port_str, map<u_int16_t, bool> *ports, unsigned port_max) {
	return(_setPorts(port_str, NULL, ports, port_max));
}

unsigned cConfigItem_ports::_setPorts(const char *port_str, char *port_matrix, map<u_int16_t, bool> *ports, unsigned port_max) {
	unsigned set = 0;
	vector<string> ports_str = split(port_str, split(",|;", "|"), true);
	for(unsigned i = 0; i < ports_str.size(); i++) {
		if(ports_str[i].find('-') == string::npos) {
			unsigned port = atoi(ports_str[i].c_str());
			if(port <= port_max) {
				if(port_matrix) {
					port_matrix[port] = 1;
					++set;
				}
				if(ports) {
					(*ports)[port] = true;
					++set;
				}
			}
		} else {
			vector<string> ports_from_to = split(ports_str[i].c_str(), "-", true);
			if(ports_from_to.size() >= 2) {
				unsigned port_from = atoi(ports_from_to[0].c_str());
				unsigned port_to = atoi(ports_from_to[1].c_str());
				if(port_from <= port_to) {
					for(unsigned port = port_from; port <= port_to; port++) {
						if(port <= port_max) {
							if(port_matrix) {
								port_matrix[port] = 1;
								++set;
							}
							if(ports) {
								(*ports)[port] = true;
								++set;
							}
						}
					}
				}
			}
		}
	}
	return(set);
}

string cConfigItem_ports::getPortString(char *port_matrix, unsigned port_max) {
	string rslt;
	for(unsigned i = 0; i <= port_max; i++) {
		if(port_matrix[i]) {
			unsigned j;
			for(j = i; j <= (port_max-1) && port_matrix[j+1]; j++);
			if(!rslt.empty()) {
				rslt += ',';
			}
			if(j > i) {
				rslt += intToString(i) + "-" + intToString(j);
				i = j;
			} else  {
				rslt += intToString(i);
			}
		}
	}
	return(rslt);
}

string cConfigItem_ports::getPortString(map<u_int16_t, bool> *ports) {
	string rslt;
	map<u_int16_t, bool>::iterator iter_i;
	for(iter_i = ports->begin(); iter_i != ports->end(); iter_i++) {
		map<u_int16_t, bool>::iterator iter_j = iter_i;
		while(nextMapPortIterator(iter_j) != ports->end() && nextMapPortIterator(iter_j)->first == iter_j->first + 1) {
			iter_j++;
		}
		if(!rslt.empty()) {
			rslt += ',';
		}
		if(iter_j->first > iter_i->first) {
			rslt += intToString(iter_i->first) + "-" + intToString(iter_j->first);
			iter_i = iter_j;
		} else  {
			rslt += intToString(iter_i->first);
		}
	}
	return(rslt);
}

bool cConfigItem_ports::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ports::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ports::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_port_matrix && !param_ports) {
		return(false);
	}
	if(list_values_str.empty()) {
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		if(!ok && enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		if(param_port_matrix) {
			ok += setPortMatrix(iter->c_str(), param_port_matrix, this->port_max);
		}
		if(param_ports) {
			ok += setPorts(iter->c_str(), param_ports, this->port_max);
		}
	}
	return(ok > 0);
}

void cConfigItem_ports::initBeforeSet() {
	clear();
}

void cConfigItem_ports::clear() {
	if(param_port_matrix) {
		for(unsigned i = 0; i <= this->port_max; i++) {
			param_port_matrix[i] = 0;
		}
	}
	if(param_ports) {
		param_ports->clear();
	}
}

cConfigItem_hosts::cConfigItem_hosts(const char* name, vector<vmIP> *adresses, vector<vmIPmask> *nets)
 : cConfigItem(name) {
	init();
	param_adresses = adresses;
	param_nets = nets;
}

string cConfigItem_hosts::getValueStr(bool configFile) {
	if((!param_adresses || !param_adresses->size()) && 
	   (!param_nets || !param_nets->size())) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	if(param_adresses) {
		for(vector<vmIP>::iterator iter = param_adresses->begin(); iter != param_adresses->end(); iter++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << ';';
				}
			}
			outStr << iter->getString();
			++counter;
		}
	}
	if(param_nets) {
		for(vector<vmIPmask>::iterator iter = param_nets->begin(); iter != param_nets->end(); iter ++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << ';';
				}
			}
			outStr << iter->ip.getString() << '/' << iter->mask;
			++counter;
		}
	}
	return(outStr.str());
}

list<string> cConfigItem_hosts::getValueListStr() {
	list<string> l;
	if(param_adresses) {
		for(vector<vmIP>::iterator iter = param_adresses->begin(); iter != param_adresses->end(); iter++) {
			l.push_back(iter->getString());
		}
	}
	if(param_nets) {
		for(vector<vmIPmask>::iterator iter = param_nets->begin(); iter != param_nets->end(); iter ++) {
			l.push_back(iter->ip.getString() + "/" + intToString(iter->mask));
		}
	}
	return(l);
}

bool cConfigItem_hosts::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_hosts::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_hosts::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_adresses && !param_nets) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		vector<string> ip_mask = split(iter->c_str(), "/", true);
		if(ip_mask.size() >= 1) {
			vmIP ip = str_2_vmIP(ip_mask[0].c_str());
			unsigned lengthMask = ip_mask.size() >= 2 ? atoi(ip_mask[1].c_str()) : 0;
			if(ip.isSet()) {
				if(!ok && enableClearBeforeFirstSet) {
					doClearBeforeFirstSet();
				}
				if(ip.is_net_mask(lengthMask)) {
					if(param_nets) {
						param_nets->push_back(vmIPmask(ip.network(lengthMask), lengthMask));
						++ok;
					}
				} else {
					if(param_adresses) {
						param_adresses->push_back(ip);
						++ok;
					}
				}
			}
		}
	}
	if(param_adresses && param_adresses->size() > 1) {
		std::sort(param_adresses->begin(), param_adresses->end());
	}
	return(ok > 0);
}

void cConfigItem_hosts::initBeforeSet() {
	if(param_nets) {
		param_nets->clear();
	}
	if(param_adresses) {
		param_adresses->clear();
	}
}

cConfigItem_ip::cConfigItem_ip(const char* name, vmIP *param)
 : cConfigItem(name) {
	init();
	param_ip = param;
}

vmIP cConfigItem_ip::getValue() {
	return(*param_ip);
}

string cConfigItem_ip::getValueStr(bool /*configFile*/) {
	return(param_ip->getString());
}

bool cConfigItem_ip::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ip::setParamFromValueStr(string value_str, bool /*enableInitBeforeSet*/, bool enableClearBeforeFirstSet) {
	if(value_str.empty()) {
		return(false);
	}
	if(enableClearBeforeFirstSet) {
		doClearBeforeFirstSet();
	}
	param_ip->setFromString(trim_str(value_str).c_str());
	return(true);
}

cConfigItem_ip_port::cConfigItem_ip_port(const char* name, ip_port *param)
 : cConfigItem(name) {
	init();
	param_ip_port = param;
}

ip_port cConfigItem_ip_port::getValue() {
	return(*param_ip_port);
}

string cConfigItem_ip_port::getValueStr(bool /*configFile*/) {
	if(!param_ip_port || !*param_ip_port) {
		return("");
	}
	ostringstream outStr;
	outStr << param_ip_port->get_ip() << ':' << param_ip_port->get_port();
	return(outStr.str());
}

bool cConfigItem_ip_port::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ip_port::setParamFromValueStr(string value_str, bool /*enableInitBeforeSet*/, bool enableClearBeforeFirstSet) {
	if(!param_ip_port ||
	   value_str.empty()) {
		return(false);
	}
	const char *value = value_str.c_str();
	char *pointToPortSeparator = (char*)strchr(value, ':');
	if(pointToPortSeparator) {
		*pointToPortSeparator = 0;
		int port = atoi(pointToPortSeparator + 1);
		if(*value && port) {
			if(enableClearBeforeFirstSet) {
				doClearBeforeFirstSet();
			}
			param_ip_port->set_ip(trim_str(value));
			param_ip_port->set_port(port);
			return(true);
		}
	}
	return(false);
}

cConfigItem_ip_ports::cConfigItem_ip_ports(const char* name, vector<vmIPport> *param)
 : cConfigItem(name) {
	init();
	param_ip_ports = param;
}

string cConfigItem_ip_ports::getValueStr(bool configFile) {
	if(!param_ip_ports || !param_ip_ports->size()) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	if(param_ip_ports) {
		for(vector<vmIPport>::iterator iter = param_ip_ports->begin(); iter != param_ip_ports->end(); iter++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << ';';
				}
			}
			outStr << iter->ip.getString(true) << ':' << iter->port.getString();
			++counter;
		}
	}
	return(outStr.str());
}

list<string> cConfigItem_ip_ports::getValueListStr() {
	list<string> l;
	if(param_ip_ports) {
		for(vector<vmIPport>::iterator iter = param_ip_ports->begin(); iter != param_ip_ports->end(); iter++) {
			l.push_back(iter->ip.getString() + ":" + iter->port.getString());
		}
	}
	return(l);
}

string cConfigItem_ip_ports::normalizeStringValueForCmp(string value) {
	find_and_replace(value, " :", ":");
	find_and_replace(value, ": ", ":");
	find_and_replace(value, "[", "");
	find_and_replace(value, "]", "");
	find_and_replace_all(value, "  ", " ");
	return(value);
}

bool cConfigItem_ip_ports::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ip_ports::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ip_ports::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_ip_ports) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		vmIP ip;
		const char *port_str;
		if(ip.setFromString(iter->c_str(), &port_str)) {
			while(*port_str == ' ' || *port_str == '\t' || *port_str == ':') {
				++port_str;
			}
			unsigned port = atoi(port_str);
			if(ip.isSet() && port) {
				if(!ok && enableClearBeforeFirstSet) {
					doClearBeforeFirstSet();
				}
				param_ip_ports->push_back(vmIPport(ip, port));
				// cout << ip.getString() << " : " << port << endl;
				++ok;
			}
		}
	}
	return(ok > 0);
}

void cConfigItem_ip_ports::initBeforeSet() {
	if(param_ip_ports) {
		param_ip_ports->clear();
	}
}

cConfigItem_ip_port_str_map::cConfigItem_ip_port_str_map(const char* name, map<vmIPport, string> *ip_port_string_map)
 : cConfigItem(name) {
	init();
	param_ip_port_string_map = ip_port_string_map;
}

string cConfigItem_ip_port_str_map::getValueStr(bool configFile) {
	if(!param_ip_port_string_map || !param_ip_port_string_map->size()) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(map<vmIPport, string>::iterator iter = param_ip_port_string_map->begin(); iter != param_ip_port_string_map->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		vmIPport ip_port = iter->first;
		outStr << ip_port.ip.getString(true) << ':' << ip_port.port.getString();
		if(!iter->second.empty()) {
			outStr << ' ' << iter->second;
		}
		++counter;
	}
	return(outStr.str());
}

list<string> cConfigItem_ip_port_str_map::getValueListStr() {
	list<string> l;
	for(map<vmIPport, string>::iterator iter = param_ip_port_string_map->begin(); iter != param_ip_port_string_map->end(); iter++) {
		vmIPport ip_port = iter->first;
		l.push_back(ip_port.ip.getString(true) + ":" + ip_port.port.getString() + 
			    (!iter->second.empty() ? " " + iter->second : ""));
	}
	return(l);
}

string cConfigItem_ip_port_str_map::normalizeStringValueForCmp(string value) {
	find_and_replace(value, " :", ":");
	find_and_replace(value, ": ", ":");
	find_and_replace(value, "[", "");
	find_and_replace(value, "]", "");
	find_and_replace_all(value, "  ", " ");
	return(value);
}

bool cConfigItem_ip_port_str_map::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ip_port_str_map::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_ip_port_str_map::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_ip_port_string_map) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		vmIP ip;
		const char *port_str_str;
		if(ip.setFromString(iter->c_str(), &port_str_str)) {
			while(*port_str_str == ' ' || *port_str_str == '\t' || *port_str_str == ':') {
				++port_str_str;
			}
			vector<string> port_str_array = split(port_str_str, " ", true);
			if(port_str_array.size() >= 1) {
				unsigned port = atoi(port_str_array[0].c_str());
				string str;
				if(port_str_array.size() >= 2) {
					str = port_str_array[1];
				}
				if(ip.isSet() && port) {
					if(!ok && enableClearBeforeFirstSet) {
						doClearBeforeFirstSet();
					}
					(*param_ip_port_string_map)[vmIPport(ip, port)] = str;
					// cout << ip.getString() << " : " << port << " " << str << endl;
					++ok;
				}
			}
		}
	}
	return(ok > 0);
}

void cConfigItem_ip_port_str_map::initBeforeSet() {
	if(param_ip_port_string_map) {
		param_ip_port_string_map->clear();
	}
}

cConfigItem_net_port_str_map::cConfigItem_net_port_str_map(const char* name, map<vmIPport, string> *ip_port_string_map, map<vmIPmask_port, string> *net_port_string_map)
 : cConfigItem(name) {
	init();
	param_ip_port_string_map = ip_port_string_map;
	param_net_port_string_map = net_port_string_map;
}

string cConfigItem_net_port_str_map::getValueStr(bool configFile) {
	if((!param_ip_port_string_map || !param_ip_port_string_map->size()) &&
	   (!param_net_port_string_map || !param_net_port_string_map->size())) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(map<vmIPport, string>::iterator iter = param_ip_port_string_map->begin(); iter != param_ip_port_string_map->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		vmIPport ip_port = iter->first;
		outStr << ip_port.ip.getString(true) << ':' << ip_port.port.getString();
		if(!iter->second.empty()) {
			outStr << ' ' << iter->second;
		}
		++counter;
	}
	for(map<vmIPmask_port, string>::iterator iter = param_net_port_string_map->begin(); iter != param_net_port_string_map->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		vmIPmask_port net_port = iter->first;
		outStr << net_port.ip_mask.getString(true) << ':' << net_port.port.getString();
		if(!iter->second.empty()) {
			outStr << ' ' << iter->second;
		}
		++counter;
	}
	return(outStr.str());
}

list<string> cConfigItem_net_port_str_map::getValueListStr() {
	list<string> l;
	for(map<vmIPport, string>::iterator iter = param_ip_port_string_map->begin(); iter != param_ip_port_string_map->end(); iter++) {
		vmIPport ip_port = iter->first;
		l.push_back(ip_port.ip.getString(true) + ":" + ip_port.port.getString() + 
			    (!iter->second.empty() ? " " + iter->second : ""));
	}
	for(map<vmIPmask_port, string>::iterator iter = param_net_port_string_map->begin(); iter != param_net_port_string_map->end(); iter++) {
		vmIPmask_port net_port = iter->first;
		l.push_back(net_port.ip_mask.getString(true) + ":" + net_port.port.getString() + 
			    (!iter->second.empty() ? " " + iter->second : ""));
	}
	return(l);
}

string cConfigItem_net_port_str_map::normalizeStringValueForCmp(string value) {
	find_and_replace(value, " :", ":");
	find_and_replace(value, ": ", ":");
	find_and_replace(value, "[", "");
	find_and_replace(value, "]", "");
	find_and_replace_all(value, "  ", " ");
	return(value);
}

bool cConfigItem_net_port_str_map::parse(const char *str_input, vmIP &ip, u_int16_t &mask, unsigned &port, string &str) {
	ip.clear();
	mask = 0;
	port = 0;
	str.clear();
	const char *after_ip_str;
	if(ip.setFromString(str_input, &after_ip_str)) {
		while(*after_ip_str == ' ' || *after_ip_str == '\t') {
			++after_ip_str;
		}
		if(*after_ip_str == '/') {
			++after_ip_str;
			while(*after_ip_str == ' ' || *after_ip_str == '\t') {
				++after_ip_str;
			}
			if(isdigit(*after_ip_str)) {
				mask = atoi(after_ip_str);
				while(isdigit(*after_ip_str) || *after_ip_str == ' ' || *after_ip_str == '\t') {
					++after_ip_str;
				}
			}
		}
		if(*after_ip_str == ':') {
			++after_ip_str;
			while(*after_ip_str == ' ' || *after_ip_str == '\t') {
				++after_ip_str;
			}
			if(isdigit(*after_ip_str)) {
				port = atoi(after_ip_str);
				while(isdigit(*after_ip_str) || *after_ip_str == ' ' || *after_ip_str == '\t') {
					++after_ip_str;
				}
			}
		}
		while(*after_ip_str == ' ' || *after_ip_str == '\t') {
			++after_ip_str;
		}
		if(*after_ip_str) {
			str = trim_str(after_ip_str);
		}
	}
	return(ip.isSet());
}

bool cConfigItem_net_port_str_map::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_net_port_str_map::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_net_port_str_map::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_ip_port_string_map && !param_net_port_string_map) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		vmIP ip;
		u_int16_t mask = 0;
		unsigned port = 0;
		string str;
		if(parse(iter->c_str(), ip, mask, port, str)) {
			if(ip.isSet() && port > 0) {
				if(!ok && enableClearBeforeFirstSet) {
					doClearBeforeFirstSet();
				}
				if(!mask) {
					(*param_ip_port_string_map)[vmIPport(ip, port)] = str;
				} else {
					(*param_net_port_string_map)[vmIPmask_port(vmIPmask(ip, mask), port)] = str;
				}
				++ok;
			}
		}
	}
	return(ok > 0);
}

void cConfigItem_net_port_str_map::initBeforeSet() {
	if(param_ip_port_string_map) {
		param_ip_port_string_map->clear();
	}
	if(param_net_port_string_map) {
		param_net_port_string_map->clear();
	}
}

cConfigItem_nat_aliases::cConfigItem_nat_aliases(const char* name, nat_aliases_t *nat_aliases)
 : cConfigItem(name) {
	init();
	param_nat_aliases = nat_aliases;
}

string cConfigItem_nat_aliases::getValueStr(bool configFile) {
	if(!param_nat_aliases || !param_nat_aliases->size()) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(nat_aliases_t::iterator iter = param_nat_aliases->begin(); iter != param_nat_aliases->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		outStr << iter->first.getString(true) << ':' << iter->second.getString(true);
		++counter;
	}
	return(outStr.str());
}

list<string> cConfigItem_nat_aliases::getValueListStr() {
	list<string> l;
	for(nat_aliases_t::iterator iter = param_nat_aliases->begin(); iter != param_nat_aliases->end(); iter++) {
		l.push_back(iter->first.getString() + ":" + iter->second.getString());
	}
	return(l);
}

string cConfigItem_nat_aliases::normalizeStringValueForCmp(string value) {
	find_and_replace(value, "=", " ");
	find_and_replace(value, ":", " ");
	find_and_replace(value, "[", "");
	find_and_replace(value, "]", "");
	find_and_replace_all(value, "  ", " ");
	return(value);
}

bool cConfigItem_nat_aliases::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_nat_aliases::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_nat_aliases::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_nat_aliases) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		vmIP ip_nat[2];
		const char *ip_nat_2_str;
		if(ip_nat[0].setFromString(iter->c_str(), &ip_nat_2_str)) {
			while(*ip_nat_2_str == ' ' || *ip_nat_2_str == '\t' || *ip_nat_2_str == ':' || *ip_nat_2_str == '=') {
				++ip_nat_2_str;
			}
			if(ip_nat[1].setFromString(ip_nat_2_str, NULL)) {
				if(!ok && enableClearBeforeFirstSet) {
					doClearBeforeFirstSet();
				}
				(*param_nat_aliases)[ip_nat[0]] = ip_nat[1];
				// cout << ip_nat[0].getString() << " : " << ip_nat[1].getString() << endl;
				++ok;
				if(verbosity > 3) {
					printf("adding local_ip[%s] = extern_ip[%s]\n", ip_nat[0].getString().c_str(), ip_nat[1].getString().c_str());
				}
			}
		}
	}
	return(ok > 0);
}

void cConfigItem_nat_aliases::initBeforeSet() {
	if(param_nat_aliases) {
		param_nat_aliases->clear();
	}
}

cConfigItem_net_map::cConfigItem_net_map(const char* name, t_net_map *net_map)
 : cConfigItem(name) {
	init();
	param_net_map = net_map;
}

string cConfigItem_net_map::getValueStr(bool configFile) {
	if(!param_net_map || !param_net_map->size()) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(t_net_map::iterator iter = param_net_map->begin(); iter != param_net_map->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		outStr << iter->first.getString(true) << ':' << iter->second.getString(true);
		++counter;
	}
	return(outStr.str());
}

list<string> cConfigItem_net_map::getValueListStr() {
	list<string> l;
	for(t_net_map::iterator iter = param_net_map->begin(); iter != param_net_map->end(); iter++) {
		l.push_back(iter->first.getString() + ":" + iter->second.getString());
	}
	return(l);
}

string cConfigItem_net_map::normalizeStringValueForCmp(string value) {
	find_and_replace(value, " /", "/");
	find_and_replace(value, "/ ", "/");
	find_and_replace(value, "=", " ");
	find_and_replace(value, ":", " ");
	find_and_replace(value, "[", "");
	find_and_replace(value, "]", "");
	find_and_replace_all(value, "  ", " ");
	return(value);
}

bool cConfigItem_net_map::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_net_map::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_net_map::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_net_map) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		vmIPmask_order2 net[2];
		const char *net_2_str;
		if(net[0].setFromString(iter->c_str(), &net_2_str)) {
			while(*net_2_str == ' ' || *net_2_str == '\t' || *net_2_str == ':' || *net_2_str == '=') {
				++net_2_str;
			}
			if(net[1].setFromString(net_2_str, NULL)) {
				if(!ok && enableClearBeforeFirstSet) {
					doClearBeforeFirstSet();
				}
				(*param_net_map)[net[0]] = net[1];
				// cout << net[0].getString() << " : " << net[1].getString() << endl;
				++ok;
				if(verbosity > 3) {
					printf("adding net[%s] => net[%s]\n", net[0].getString().c_str(), net[1].getString().c_str());
				}
			}
		}
	}
	return(ok > 0);
}

void cConfigItem_net_map::initBeforeSet() {
	if(param_net_map) {
		param_net_map->clear();
	}
}

vmIP cConfigItem_net_map::convIP(vmIP ip, t_net_map *net_map) {
	if(!net_map->size()) {
		return(ip);
	}
	vmIPmask_order2 ip_mask = vmIPmask_order2(ip, ip.bits());
	t_net_map::iterator iter = net_map->find(ip_mask);
	if(iter != net_map->end()) {
		return(iter->second.ip);
	}
	for(t_net_map::reverse_iterator iter = net_map->rbegin(); iter != net_map->rend(); iter++) {
		if(ip.network(iter->first.mask, true) == ((vmIP)iter->first.ip).network(iter->first.mask, true)) {
			if(iter->second.ip.is_v6() != ip.is_v6()) {
				if(iter->second.ip.is_v6()) {
					ip.set_to_v6();
				} else {
					ip.set_to_v4();
				}
			}
			return(((vmIP)iter->second.ip).network(iter->second.mask)
						      ._or(ip._and(ip.wildcard_mask(iter->second.mask))));
		}
	}
	return(ip);
}

cConfigItem_domain_map::cConfigItem_domain_map(const char* name, t_domain_map *domain_map)
 : cConfigItem(name) {
	init();
	param_domain_map = domain_map;
}

string cConfigItem_domain_map::getValueStr(bool configFile) {
	if(!param_domain_map || !param_domain_map->size()) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(t_domain_map::iterator iter = param_domain_map->begin(); iter != param_domain_map->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		outStr << iter->first << ':' << iter->second;
		++counter;
	}
	return(outStr.str());
}

list<string> cConfigItem_domain_map::getValueListStr() {
	list<string> l;
	for(t_domain_map::iterator iter = param_domain_map->begin(); iter != param_domain_map->end(); iter++) {
		l.push_back(iter->first + ":" + iter->second);
	}
	return(l);
}

string cConfigItem_domain_map::normalizeStringValueForCmp(string value) {
	find_and_replace(value, " /", "/");
	find_and_replace(value, "/ ", "/");
	find_and_replace(value, "=", " ");
	find_and_replace(value, ":", " ");
	find_and_replace(value, "[", "");
	find_and_replace(value, "]", "");
	find_and_replace_all(value, "  ", " ");
	return(value);
}

bool cConfigItem_domain_map::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_domain_map::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_domain_map::setParamFromValuesStr(vector<std::string> list_values_str, bool enableInitBeforeSet, bool /*enableClearBeforeFirstSet*/) {
	if(!param_domain_map) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<std::string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		string str = std::string(iter->c_str());
		size_t pos = str.find('=');
		if (pos) {
			string key = str.substr(0, pos);
			string val = str.substr(pos + 1, str.size());
			//cout << "iter: " << iter->c_str() << endl << "key:" << key << "  val:" << val << endl;
			(*param_domain_map)[key] = val;
			ok++;
		}
	}
	return(ok > 0);
}

void cConfigItem_domain_map::initBeforeSet() {
	if(param_domain_map) {
		param_domain_map->clear();
	}
}

cConfigItem_custom_headers::cConfigItem_custom_headers(const char* name, vector<dstring> *custom_headers)
 : cConfigItem(name) {
	init();
	this->param_custom_headers = custom_headers;
}

string cConfigItem_custom_headers::getValueStr(bool /*configFile*/) {
	if(!param_custom_headers || !param_custom_headers->size()) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(vector<dstring>::iterator iter = param_custom_headers->begin(); iter != param_custom_headers->end(); iter++) {
		if(counter) { 
			outStr << ';';
		}
		outStr << (*iter)[0];
		++counter;
	}
	return(outStr.str());
}

string cConfigItem_custom_headers::normalizeStringValueForCmp(string value) {
	vector<string> value_vect = split(value.c_str(), ";", true);
	string rslt;
	for(vector<string>::iterator iter = value_vect.begin(); iter != value_vect.end(); iter++) {
		if(!rslt.empty()) {
			rslt += ";";
		}
		rslt += *iter;
	}
	return(rslt);
}

bool cConfigItem_custom_headers::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValueStr(getValueFromConfigFile(ini), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_custom_headers::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	if(!param_custom_headers ||
	   value_str.empty()) {
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	const char *value = value_str.c_str();
	char *pos = (char*)value;
	while(pos && *pos) {
		if(!ok && enableClearBeforeFirstSet) {
			doClearBeforeFirstSet();
		}
		char *posSep = strchr(pos, ';');
		if(posSep) {
			*posSep = 0;
		}
		string custom_header = trim_str(pos);
		string custom_header_field = "custom_header__" + custom_header;
		std::replace(custom_header_field.begin(), custom_header_field.end(), ' ', '_');
		param_custom_headers->push_back(dstring(custom_header, custom_header_field));
		++ok;
		pos = posSep ? posSep + 1 : NULL;
	}
	return(ok > 0);
}

void cConfigItem_custom_headers::initBeforeSet() {
	if(param_custom_headers) {
		param_custom_headers->clear();
	}
}

cConfigItem_dstrings::cConfigItem_dstrings(const char* name, vector<dstring> *dstrings)
 : cConfigItem(name) {
	init();
	this->param_dstrings = dstrings;
}

string cConfigItem_dstrings::getValueStr(bool configFile) {
	if(!param_dstrings || !param_dstrings->size()) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(vector<dstring>::iterator iter = param_dstrings->begin(); iter != param_dstrings->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		outStr << iter->str[0] << ':' << iter->str[1];
		++counter;
	}
	return(outStr.str());
}

string cConfigItem_dstrings::normalizeStringValueForCmp(string value) {
	vector<string> value_vect = split(value.c_str(), ";", true);
	string rslt;
	for(vector<string>::iterator iter = value_vect.begin(); iter != value_vect.end(); iter++) {
		if(!rslt.empty()) {
			rslt += ";";
		}
		string str = *iter;
		size_t pos_sep = str.find(':');
		if(pos_sep != string::npos) {
			string str1 = trim_str(str.substr(0, pos_sep));
			string str2 = trim_str(str.substr(pos_sep + 1));
			if(str1.length() && str2.length()) {
				rslt += str1 + ':' + str2;
			}
		}
		rslt += *iter;
	}
	return(rslt);
}

bool cConfigItem_dstrings::setParamFromConfigFile(CSimpleIniA *ini, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini, enableInitBeforeSet), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_dstrings::setParamFromValueStr(string value_str, bool enableInitBeforeSet, bool enableClearBeforeFirstSet) {
	return(setParamFromValuesStr(split(value_str, ';'), enableInitBeforeSet, enableClearBeforeFirstSet));
}

bool cConfigItem_dstrings::setParamFromValuesStr(vector<string> list_values_str, bool enableInitBeforeSet, bool /*enableClearBeforeFirstSet*/) {
	if(!param_dstrings) {
		return(false);
	}
	if(list_values_str.empty()) {
		if(enableInitBeforeSet) {
			initBeforeSet();
		}
		return(false);
	}
	int ok = 0;
	if(enableInitBeforeSet) {
		initBeforeSet();
	}
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		string str = *iter;
		size_t pos_sep = str.find(':');
		if(pos_sep != string::npos) {
			string str1 = trim_str(str.substr(0, pos_sep));
			string str2 = trim_str(str.substr(pos_sep + 1));
			if(str1.length() && str2.length()) {
				param_dstrings->push_back(dstring(str1, str2));
				ok++;
			}
		}
	}
	return(ok > 0);
}

void cConfigItem_dstrings::initBeforeSet() {
	if(param_dstrings) {
		param_dstrings->clear();
	}
}

cConfigItem_type_compress::cConfigItem_type_compress(const char* name, CompressStream::eTypeCompress *type_compress)
 : cConfigItem_yesno(name, (int*)type_compress) {
	addValues(CompressStream::getConfigMenuString().c_str());
}

cConfigItem_type_compress::cConfigItem_type_compress(const char* name, FileZipHandler::eTypeCompress *type_compress)
 : cConfigItem_yesno(name, (int*)type_compress) {
	addValues(FileZipHandler::getConfigMenuString().c_str());
}


string cConfigMap::cItem::valuesToStr() {
	ostringstream outStr;
	int counter = 0;
	for(list<string>::iterator iter = values.begin(); iter != values.end(); iter++) {
		if(counter) {
			outStr << ";";
		}
		outStr << *iter;
		++counter;
	}
	return(outStr.str());
}

void cConfigMap::addItem(const char *name, const char *value) {
	config_map[name].add(value);
}

bool cConfigMap::existsItem(const char *name) {
	map<string, cItem>::iterator iter = config_map.find(name);
	return(iter != config_map.end() && iter->second.values.size());
}

string cConfigMap::getFirstItem(const char *name, bool toLower) {
	map<string, cItem>::iterator iter = config_map.find(name);
	if(iter != config_map.end() && iter->second.values.size()) {
		string rslt = *iter->second.values.begin();
		if(toLower) {
			std::transform(rslt.begin(), rslt.end(), rslt.begin(), ::tolower);
		}
		return(rslt);
	}
	return("");
}

string cConfigMap::getItems(const char *name, const char */*separator*/, bool toLower) {
	map<string, cItem>::iterator iter = config_map.find(name);
	if(iter != config_map.end() && iter->second.values.size()) {
		string rslt;
		for(list<string>::iterator iter_l = iter->second.values.begin(); iter_l != iter->second.values.begin(); iter_l++) {
			if(!rslt.empty()) {
				rslt += ";";
			}
			rslt += *iter_l;
		}
		if(toLower) {
			std::transform(rslt.begin(), rslt.end(), rslt.begin(), ::tolower);
		}
		return(rslt);
	}
	return("");
}

string cConfigMap::comp(cConfigMap *other, cConfig *config, cConfig *defaultConfig) {
	ostringstream outStr;
	map<string, cItem>::iterator iter1;
	map<string, cItem>::iterator iter2;
	for(iter1 = config_map.begin(); iter1 != config_map.end(); iter1++) {
		iter2 = other->config_map.find(iter1->first);
		if(iter2 == other->config_map.end()) {
			outStr << "(++) " << iter1->first << " = " << iter1->second.valuesToStr();
			if(isObsoleteParameter(iter1->first)) {
				outStr << " // (obsolete)";
			}
			if(defaultConfig) {
				cConfigItem *item = defaultConfig->getItem(iter1->first.c_str());
				if(item) {
					string defaultValue = item->getValueStr();
					if(!defaultValue.empty()) {
						outStr << " // (default value:) "
						       << defaultValue;
					}
				}
			}
			outStr << endl;
		} else if(!(iter1->second == iter2->second)) {
			if(!config ||
			   !config->testEqValues(iter1->first, iter1->second.values, iter2->second.values)) {
				outStr << "(//) " << iter1->first 
				       << " = " 
				       << iter1->second.valuesToStr()
				       << (defaultConfig ? " // (default value:) " : " // ")
				       << iter2->second.valuesToStr() << endl;
			}
		}
	}
	for(iter2 = other->config_map.begin(); iter2 != other->config_map.end(); iter2++) {
		if(iter2->first == "new-config") {
			continue;
		}
		iter1 = config_map.find(iter2->first);
		if(iter1 == config_map.end()) {
			if(!isObsoleteParameter(iter2->first)) {
				outStr << "(--) " << iter2->first << " = " << iter2->second.valuesToStr();
				if(defaultConfig) {
					cConfigItem *item = defaultConfig->getItem(iter2->first.c_str());
					if(item) {
						string defaultValue = item->getValueStr();
						if(!defaultValue.empty()) {
							outStr << " // (default value:) "
							       << defaultValue;
						}
					}
				}
				outStr << endl;
			}
		}
	}
	return(outStr.str());
}

bool cConfigMap::isObsoleteParameter(string parameter) {
	const char *obsoleteParameters[] = {
		"autocleanspool",
		"packetbuffer_enable",
		"destroy_call_at_bye",
		"sip-register-active-nologbin",
		"mysqltable",
		"vmbuffer",
		NULL
	};
	for(size_t io = 0; obsoleteParameters[io]; ++io) {
		if(string(obsoleteParameters[io]) == parameter) {
			return(true);
		}
	}
	return(false);
}


cConfig::cConfig() {
	config_sync = 0;
	defaultLevel = cConfigItem::levelNormal;
	defaultMinor = false;
	defaultMinorGroupIfNotSet = false;
	diffValuesTrack = true;
}

cConfig::~cConfig() {
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		delete iter->second;
	}
}

void cConfig::addConfigItem(cConfigItem *configItem) {
	lock();
	if(config_map.find(configItem->config_name) != config_map.end()) {
		cout << "warning: duplicity config item: " << configItem->config_name << endl;
	}
	configItem->config = this;
	configItem->level = defaultLevel;
	configItem->group_name = defaultGroup;
	configItem->subgroup_name = defaultSubgroup;
	if(defaultMinor) {
		configItem->minor = defaultMinor;
	}
	if(defaultMinorGroupIfNotSet) {
		configItem->minorGroupIfNotSet = defaultMinorGroupIfNotSet;
	}
	if(!defaultDisableIf.empty()) {
		configItem->disableIf = defaultDisableIf;
	}
	config_map[configItem->config_name] = configItem;
	config_list.push_back(configItem->config_name);
	unlock();
}

void cConfig::group(const char *groupName) {
	defaultGroup = groupName ? groupName : "";
	defaultSubgroup = "";
	normal();
}

void cConfig::subgroup(const char *subgroupName) {
	defaultSubgroup = subgroupName ? subgroupName : "";
	normal();
}

void cConfig::normal() {
	defaultLevel = cConfigItem::levelNormal;
}

void cConfig::advanced() {
	defaultLevel = cConfigItem::levelAdvanced;
}

void cConfig::expert() {
	defaultLevel = cConfigItem::levelExpert;
}

void cConfig::obsolete() {
	defaultLevel = cConfigItem::levelObsolete;
}

void cConfig::minorBegin() {
	defaultMinor = true;
}

void cConfig::minorEnd() {
	defaultMinor = false;
}

void cConfig::minorGroupIfNotSetBegin() {
	defaultMinorGroupIfNotSet = true;
}

void cConfig::minorGroupIfNotSetEnd() {
	defaultMinorGroupIfNotSet = true;
}

void cConfig::setDisableIfBegin(string disableIf) {
	defaultDisableIf = disableIf;
}

void cConfig::setDisableIfEnd() {
	defaultDisableIf = "";
}

bool cConfig::loadConfigFiles(const char *directory, vector<string> *files) {
	DIR *dir = opendir(directory);
	if(dir == NULL) return(false);
	struct dirent *ent;
	while((ent = readdir(dir)) != NULL) {
		if(ent->d_name[0] == '.' || is_dir(directory + string("/") + ent->d_name)) continue;
		files->push_back(ent->d_name);
	}
	closedir(dir);
	std::sort(files->begin(), files->end(), files_name_cmp);
	return(true);
}

bool cConfig::loadFromConfigFileOrDirectory(const char *filename, bool silent) {
	if(!file_exists(filename)) {
		return(false);
	}
	if(is_dir((char*)filename)) {
		vector<string> files;
		if(loadConfigFiles(filename, &files)) {
			bool rslt_load = false;
			for(vector<string>::iterator iter = files.begin(); iter != files.end(); iter++) {
				if(loadFromConfigFile((filename + string("/") + *iter).c_str(), NULL, silent, true)) {
					rslt_load = true;
				}
			}
			return(rslt_load);
		} else {
			if(!silent) {
				loadFromConfigFileError("Cannot access directory file %s!", filename);
			}
			return(false);
		}
	} else {
		return(loadFromConfigFile(filename, NULL, silent));
	}
	return(true);
}

bool cConfig::loadFromConfigFile(const char *filename, string *error, bool silent, bool nextConfigFile) {
	if(error) {
		*error = "";
	}
	if(verbosity > 1 && !silent) { 
		syslog(LOG_NOTICE, "Loading configuration from file %s", filename);
	}
	if(!silent) {
		printf("Loading configuration from file %s ", filename);
	}
	FILE *fp = fopen(filename, "rb");
	if(!fp) {
		if(!silent) {
			loadFromConfigFileError("Cannot open / access config file %s!", filename, error);
		}
		return(false);
	}
	if(fseek(fp, 0, SEEK_END) == -1) {
		if(!silent) {
			loadFromConfigFileError("Cannot access config file %s!", filename, error);
		}
		fclose(fp);
		return(false);
	}
	size_t fileSize = ftell(fp);
	if(fileSize == 0) {
		if(!silent) {
			printf("WARNING - configuration file %s is empty\n", filename);
		}
		fclose(fp);
		return(true);
	}
	size_t fileSizeWithGeneralHedaer = fileSize + 10;
	char *fileContent = new FILE_LINE(2001) char[fileSizeWithGeneralHedaer];
	if(!fileContent) {
		if(!silent) {
			loadFromConfigFileError("Cannot alloc memory for config file %s!", filename, error);
		}
		fclose(fp);
		return(false);

	}
	fileContent[0] = 0;
	strcat(fileContent, "[general]\n");
	fseek(fp, 0, SEEK_SET);
	size_t readBytes = fread(fileContent + 10, sizeof(char), fileSize, fp);
	if(readBytes != fileSize) {
		if(!silent) {
			loadFromConfigFileError("Cannot read data from config file %s!", filename, error);
		}
		fclose(fp);
		return(false);
	}
	fclose(fp);
	
	CSimpleIniA ini;
	ini.SetUnicode();
	ini.SetMultiKey(true);
	
	int rc = ini.LoadData(fileContent, readBytes + 10); //with "[general]\n" thats not included in uRead
	if (rc != 0) {
		if(!silent) {
			loadFromConfigFileError("Loading config from file %s FAILED!", filename, error);
		}
		return(false);
	}
	delete[] fileContent;
	
	string inistr;
	rc = ini.Save(inistr);
	if (rc != 0) {
		if(!silent) {
			loadFromConfigFileError("Preparing config from file %s FAILED!", filename, error);
		}
		return(false);
	}
	
	lock();
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		if(iter->second->setParamFromConfigFile(&ini, !(nextConfigFile && iter->second->set_in_config))) {
			iter->second->value_in_config = nextConfigFile && iter->second->set_in_config ?
							 iter->second->getValueStr() :
							 iter->second->getValueFromConfigFile(&ini);
			iter->second->set = true;
			iter->second->set_in_config = true;
			iter->second->exists = true;
			iter->second->exists_in_config = true;
			evSetConfigItem(iter->second);
		} else if(iter->second->existsInConfigFile(&ini)) {
			iter->second->exists = true;
			iter->second->exists_in_config = true;
		}
	}
	unlock();
	
	if (rc != 0) {
		if(!silent) {
			loadFromConfigFileError("Evaluating config from file %s FAILED!", filename, error);
		}
		return(false);
	}
	if(!silent) {
		printf("OK\n");
	}
	return(true);
}

bool cConfig::loadConfigMapConfigFileOrDirectory(cConfigMap *configMap, const char *filename) {
	if(!file_exists(filename)) {
		return(false);
	}
	if(is_dir((char*)filename)) {
		vector<string> files;
		if(loadConfigFiles(filename, &files)) {
			bool rslt_load = false;
			for(vector<string>::iterator iter = files.begin(); iter != files.end(); iter++) {
				if(loadConfigMapFromConfigFile(configMap, (filename + string("/") + *iter).c_str())) {
					rslt_load = true;
				}
			}
			return(rslt_load);
		} else {
			return(false);
		}
	} else {
		return(loadConfigMapFromConfigFile(configMap, filename));
	}
	return(true);
}

bool cConfig::loadConfigMapFromConfigFile(cConfigMap *configMap, const char *filename) {
	if(!GetFileSize(filename)) {
		return(true);
	}
	FILE *fp = fopen(filename, "r");
	if(!fp) {
		return(false);
	}
	unsigned lineBufferSize = 100000;
	char *lineBuffer = new FILE_LINE(0) char[lineBufferSize];
	lock();
	while(fgets(lineBuffer, lineBufferSize, fp)) {
		char *pointerToBegin = lineBuffer;
		while(*pointerToBegin == ' ' || *pointerToBegin == '\t') {
			++pointerToBegin;
		}
		if(!isalnum(*pointerToBegin)) {
			continue;
		}
		char *pointerToEnd = lineBuffer + strlen(lineBuffer) - 1;
		while(pointerToEnd > pointerToBegin &&
		      (*pointerToEnd == '\n' || *pointerToEnd == ' ' || *pointerToEnd == '\t')) {
			*pointerToEnd = 0;
			--pointerToEnd;
		}
		char *pointerToName = pointerToBegin;
		char *pointerToSeparator = pointerToName + 1;
		while(*pointerToSeparator && *pointerToSeparator != '=') {
			++pointerToSeparator;
		}
		if(!*pointerToSeparator) {
			continue;
		}
		string name = string(pointerToName, pointerToSeparator - pointerToName);
		while(name[name.length() - 1] == ' ' || name[name.length() - 1] == '\t') {
			name.resize(name.length() - 1);
		}
		char *pointerToValue = pointerToSeparator + 1;
		while(*pointerToValue == ' ' || *pointerToValue == '\t') {
			++pointerToValue;
		}
		if(!*pointerToValue) {
			continue;
		}
		string value = string(pointerToValue);
		size_t pos = value.find(" #");
		if(pos == string::npos) {
			pos = value.find("\t#");
		}
		if(pos != string::npos) {
			value = value.substr(0, pos);
			while(value[value.length() - 1] == ' ' || value[value.length() - 1] == '\t') {
				value.resize(value.length() - 1);
			}
		}
		if(!name.empty() && !value.empty()) {
			name = getMainItemName(name.c_str());
			map<string, cConfigItem*>::iterator iter = config_map.find(name);
			if(iter == config_map.end() ||
			   iter->second->enableMultiValues() ||
			   !configMap->existsItem(name.c_str()))
				configMap->addItem(name.c_str(), value.c_str());
		}
	}
	unlock();
	delete [] lineBuffer;
	fclose(fp);
	return(true);
}

void cConfig::loadFromConfigFileError(const char *errorString, const char *filename, string *error) {
	char error_buff[1024];
	snprintf(error_buff, sizeof(error_buff), errorString, filename);
	printf("ERROR: %s\n", error_buff);
	if(error) *error = error_buff;
	syslog(LOG_ERR, "%s", error_buff);
}

cConfigMap cConfig::getConfigMap() {
	cConfigMap configMap;
	lock();
	for(list<string>::iterator iter = config_list.begin(); iter != config_list.end(); iter++) {
		map<string, cConfigItem*>::iterator iter_map = config_map.find(*iter);
		if(iter_map != config_map.end()) {
			if(iter_map->second->set) {
				list<string> l = iter_map->second->getValueListStr();
				for(list<string>::iterator iter_l = l.begin(); iter_l != l.end(); iter_l++) {
					configMap.addItem(iter->c_str(), iter_l->c_str());
				}
			}
		}
	}
	unlock();
	return(configMap);
}

string cConfig::getContentConfig(bool configFile, bool putDefault) {
	ostringstream outStr;
	lock();
	for(list<string>::iterator iter = config_list.begin(); iter != config_list.end(); iter++) {
		map<string, cConfigItem*>::iterator iter_map = config_map.find(*iter);
		if(iter_map != config_map.end()) {
			if(iter_map->second->set) {
				outStr << *iter
				       << " = "
				       << iter_map->second->getValueStr(configFile);
				if(putDefault && iter_map->second->defaultValueStr_set) {
					if(iter_map->second->defaultValueStr != iter_map->second->getValueStr(configFile)) {
						outStr << " ## " << iter_map->second->defaultValueStr;
					} else {
						outStr << " ## ==";
					}
				}
				outStr << endl;
			}
		}
	}
	unlock();
	return(outStr.str());
}

string cConfig::getJson(bool onlyIfSet, vector<string> *filter) {
	JsonExport json;
	int counter = 1;
	lock();
	for(list<string>::iterator iter = config_list.begin(); iter != config_list.end(); iter++) {
		if(filter && filter->size()) {
			bool filter_ok = false;
			for(vector<string>::iterator iter_filter = filter->begin(); iter_filter != filter->end(); iter_filter++) {
				if(!strcasecmp(iter_filter->c_str(), iter->c_str())) {
					filter_ok = true;
					break;
				}
			}
			if(!filter_ok) {
				continue;
			}
		}
		map<string, cConfigItem*>::iterator iter_map = config_map.find(*iter);
		if(iter_map != config_map.end()) {
			if(!onlyIfSet || iter_map->second->set) {
				char counter_str_with_name[100];
				snprintf(counter_str_with_name, sizeof(counter_str_with_name), "%03i:%s", counter, iter->c_str());
				json.addJson(counter_str_with_name, iter_map->second->getJson());
				++counter;
			}
		}
	}
	unlock();
	bool okNextData = false;
	if(filter && filter->size()) {
		for(vector<string>::iterator iter_filter = filter->begin(); iter_filter != filter->end(); iter_filter++) {
			if(!strcasecmp(iter_filter->c_str(), "nextData")) {
				okNextData = true;
				break;
			}
		}
	} else {
		okNextData = true;
	}
	if(okNextData && opt_mysqlloadconfig) {
		bool setFromMysqlOk = false;
		SqlDb *sqlDb = createSqlObject();
		sqlDb->setSilentConnect();
		if(sqlDb->connect()) {
			sqlDb->setMaxQueryPass(1);
			sqlDb->setDisableLogError();
			if(sqlDb->existsTable("sensor_config")) {
				setFromMysqlOk = true;
			}
		}
		delete sqlDb;
		JsonExport nextData;
		nextData.add("setFromMysqlOk", setFromMysqlOk);
		json.addJson("nextData", nextData.getJson());
	}
	json.add("version", RTPSENSOR_VERSION);
	json.add("build", RTPSENSOR_BUILD_NUMBER);
	return(json.getJson());
}

void cConfig::setFromJson(const char *jsonStr, bool enableReadOnlyParams) {
	map<string, vector<string>* > params;
	JsonItem jsonData;
	jsonData.parse(jsonStr);
	for(size_t i = 0; i < jsonData.getLocalCount(); i++) {
		JsonItem *item = jsonData.getLocalItem(i);
		string config_name = item->getValue("name");
		string value = item->getValue("value");
		int set = 0;
		if(!config_name.empty() || !value.empty()) {
			set = atoi(item->getValue("set").c_str());
		} else {
			if(item->getLocalCount() > 0) {
				config_name = item->getLocalItem(0)->getLocalName();
				value = item->getLocalItem(0)->getLocalValue();
				set = 1;
			}
		}
		if(!config_name.empty()) {
			if(set) {
				if(!params[config_name]) {
					params[config_name] = new FILE_LINE(0) vector<string>;
				}
				params[config_name]->push_back(value);
			} else if(params.find(config_name) == params.end()) {
				params[config_name] = NULL;
			}
		}
	}
	lock();
	for(map<string, vector<string>* >::iterator iter = params.begin(); iter != params.end(); iter++) {
		string config_name = iter->first;
		bool set = iter->second != NULL && iter->second->size() > 0;
		if(set) {
			map<string, cConfigItem*>::iterator iter_map = config_map.find(config_name);
			if(iter_map == config_map.end()) {
				string config_main_name = getMainItemName(config_name.c_str());
				if(config_main_name != config_name) {
					iter_map = config_map.find(config_main_name);
				}
			}
			if(iter_map != config_map.end() &&
			   (enableReadOnlyParams || !iter_map->second->readOnly)) {
				if(set) {
					string value = iter->second->size() == 1 ? (*iter->second)[0] : implode(*iter->second, ";");
					if(iter_map->second->setParamFromValueStr(value, true, true)) {
						iter_map->second->set = true;
						iter_map->second->set_in_json = true;
						iter_map->second->value_in_json = value;
						evSetConfigItem(iter_map->second);
					}
					iter_map->second->exists = true;
					iter_map->second->exists_in_json = true;
				} else {
					iter_map->second->clearToDefaultValue();
					evSetConfigItem(iter_map->second);
				}
			}
		}
	}
	unlock();
	for(map<string, vector<string>* >::iterator iter = params.begin(); iter != params.end(); iter++) {
		if(iter->second) {
			delete iter->second;
		}
	}
}

void cConfig::setFromMysql(bool checkConnect, bool onlyIfSet) {
	SqlDb *sqlDb = createSqlObject();
	if(checkConnect) {
		sqlDb->setSilentConnect();
		if(!sqlDb->connect()) {
			delete sqlDb;
			return;
		}
	}
	sqlDb->setMaxQueryPass(1);
	sqlDb->setDisableLogError();
	ostringstream q;
	q << "SELECT * FROM sensor_config WHERE id_sensor ";
	extern int opt_id_sensor;
	if(opt_id_sensor > 0) {
		q << "= " << opt_id_sensor;
	} else {
		q << "IS NULL";
	}
	if(sqlDb->query(q.str())) {
		SqlDb_row row = sqlDb->fetchRow();
		if(row) {
			lock();
			for(size_t i = 0; i < row.getCountFields(); i++) {
				string column = row.getNameField(i);
				if(column != "id" && column != "id_sensor") {
					map<string, cConfigItem*>::iterator iter_map = config_map.find(column);
					if(iter_map != config_map.end()) {
						if(!row.isNull(column)) {
							bool oldSet = iter_map->second->set;
							string oldValueStr = iter_map->second->getValueStr();
							if(iter_map->second->setParamFromValueStr(row[column], true, true)) {
								if((!iter_map->second->naDefaultValueStr || oldSet) &&
								   oldValueStr != row[column] && diffValuesTrack) {
									sDiffValue diffValue;
									diffValue.config_name = iter_map->second->config_name;
									diffValue.old_value = oldValueStr;
									diffValue.new_value = row[column];
									diffValues.push_back(diffValue);
								}
								iter_map->second->set = true;
								iter_map->second->set_in_db = true;
								iter_map->second->value_in_db = row[column];
								evSetConfigItem(iter_map->second);
							}
							iter_map->second->exists = true;
							iter_map->second->exists_in_db = true;
						} else if(!onlyIfSet) {
							iter_map->second->clearToDefaultValue();
							evSetConfigItem(iter_map->second);
						}
					}
				}
			}
			unlock();
		}
	}
	delete sqlDb;
}

void cConfig::putToMysql() {
	SqlDb *sqlDb = createSqlObject();
	list<string> sensor_config_columns;
	sqlDb->query("show columns from sensor_config");
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		sensor_config_columns.push_back(row[0]);
	}
	ostringstream q;
	q << "SELECT * FROM sensor_config WHERE id_sensor ";
	extern int opt_id_sensor;
	if(opt_id_sensor > 0) {
		q << "= " << opt_id_sensor;
	} else {
		q << "IS NULL";
	}
	sqlDb->query(q.str());
	SqlDb_row row_get = sqlDb->fetchRow();
	SqlDb_row row_save;
	lock();
	for(list<string>::iterator iter = config_list.begin(); iter != config_list.end(); iter++) {
		map<string, cConfigItem*>::iterator iter_map = config_map.find(*iter);
		if(iter_map != config_map.end() && !iter_map->second->readOnly) {
			bool columnExists = false;
			for(list<string>::iterator iter_column = sensor_config_columns.begin(); iter_column != sensor_config_columns.end(); iter_column++) {
				if(*iter_column == *iter) {
					columnExists = true;
					break;
				}
			}
			if(iter_map->second->set) {
				if(!columnExists) {
					sqlDb->query("alter table sensor_config add column `" + *iter + "` text");
				}
				row_save.add(iter_map->second->getValueStr(), *iter);
			} else {
				if(columnExists) {
					row_save.add((const char*)NULL, *iter);
				}
			}
		}
	}
	unlock();
	if(row_get) {
		char id_cond[20];
		snprintf(id_cond, sizeof(id_cond), "ID = %i", atoi(row_get["id"].c_str()));
		sqlDb->update("sensor_config", row_save, id_cond);
	} else {
		sqlDb->insert("sensor_config", row_save);
	}
	delete sqlDb;
}

void cConfig::setDefaultValues() {
	lock();
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		iter->second->setDefaultValue();
	}
	unlock();
}

void cConfig::clearToDefaultValues() {
	lock();
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		iter->second->clearToDefaultValue();
		evSetConfigItem(iter->second);
	}
	unlock();
}

void cConfig::setDescription(const char *itemName, const char *description) {
	map<string, cConfigItem*>::iterator iter = config_map.find(itemName);
	if(iter != config_map.end()) {
		iter->second->setDescription(description);
	}
}

void cConfig::setHelp(const char *itemName, const char *help) {
	map<string, cConfigItem*>::iterator iter = config_map.find(itemName);
	if(iter != config_map.end()) {
		iter->second->setHelp(help);
	}
}

string cConfig::getMainItemName(const char *name) {
	map<string, cConfigItem*>::iterator iter = config_map.find(name);
	if(iter == config_map.end()) {
		for(iter = config_map.begin(); iter != config_map.end(); iter++) {
			list<string> *aliases = &iter->second->config_name_alias;
			for(list<string>::iterator iter_alias = aliases->begin(); iter_alias != aliases->end(); iter_alias++) {
				if(*iter_alias == name) {
					return(iter->first);
				}
			}
		}
	}
	return(name);
}

cConfigItem *cConfig::getItem(const char *itemName) {
	string mainItemName = getMainItemName(itemName);
	if(config_map.find(mainItemName) != config_map.end()) {
		return(config_map[mainItemName]);
	}
	return(NULL);
}

bool cConfig::isSet() {
	return(config_map.size() > 0);
}

bool cConfig::isSet(const char *itemName) {
	cConfigItem *item = getItem(itemName);
	return(item ? item->set : false);
}

bool cConfig::isExists(const char *itemName) {
	cConfigItem *item = getItem(itemName);
	return(item ? item->exists : false);
}

void cConfig::beginTrackDiffValues() {
	diffValuesTrack = true;
	diffValues.clear();
}

void cConfig::endTrackDiffValues(list<sDiffValue> *diffValues) {
	if(diffValues) {
		diffValues->clear();
		if(this->diffValues.size()) {
			for(list<sDiffValue>::iterator iter = this->diffValues.begin(); iter != this->diffValues.end(); iter++) {
				diffValues->push_back(*iter);
			}
		}
	}
	diffValuesTrack = false;
	this->diffValues.clear();
}

bool cConfig::testEqValues(const char *itemName, const char *value1, const char *value2) {
	string value1_str = value1;
	string value2_str = value2;
	std::transform(value1_str.begin(), value1_str.end(), value1_str.begin(), ::tolower);
	std::transform(value2_str.begin(), value2_str.end(), value2_str.begin(), ::tolower);
	if(value1_str == value2_str) {
		return(true);
	}
	map<string, cConfigItem*>::iterator iter = config_map.find(itemName);
	if(iter == config_map.end()) {
		return(false);
	}
	value1_str = iter->second->normalizeStringValueForCmp(value1_str);
	value2_str = iter->second->normalizeStringValueForCmp(value2_str);
	return(value1_str == value2_str);
}

bool cConfig::testEqValues(string itemName, list<string> values1, list<string> values2) {
	if(values1.size() != values2.size()) {
		map<string, cConfigItem*>::iterator iter = config_map.find(itemName);
		if(iter == config_map.end()) {
			return(false);
		}
		if(iter->second->enable_normalizeStringValuesForCmp()) {
			string value1_str = iter->second->normalizeStringValuesForCmp(values1);
			string value2_str = iter->second->normalizeStringValuesForCmp(values2);
			if(value1_str == value2_str) {
				return(true);
			}
		}
		return(false);
	}
	values1.sort();
	values2.sort();
	list<string>::iterator iter1 = values1.begin();
	list<string>::iterator iter2 = values2.begin();
	while(iter1 != values1.end() && iter2 != values2.end()) {
		if(!testEqValues(itemName.c_str(), iter1->c_str(), iter2->c_str())) {
			return(false);
		}
		++iter1;
		++iter2;
	}
	return(true);
}
