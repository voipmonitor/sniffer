#include <stdio.h>
#include <syslog.h>
#include <dirent.h>
#include <iomanip>

#include "config_param.h"
#include "voipmonitor.h"
#include "sql_db.h"


extern int verbosity;


cConfigItem::cConfigItem(const char *name) {
	config_name = name;
	config_file_section = "general";
	set = false;
	naDefaultValueStr = false;
	minor = false;
}

cConfigItem *cConfigItem::addAlias(const char *name_alias) {
	config_name_alias.push_back(name_alias);
	return(this);
}

cConfigItem *cConfigItem::setDefaultValueStr(const char *defaultValueStr) {
	this->defaultValueStr = defaultValueStr;
	return(this);
}

cConfigItem *cConfigItem::setNaDefaultValueStr() {
	naDefaultValueStr = true;
	return(this);
}

cConfigItem *cConfigItem::setMinor() {
	minor = true;
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

vector<string> cConfigItem::getValuesFromConfigFile(CSimpleIniA *ini) {
	vector<string> list_values;
	CSimpleIniA::TNamesDepend values;
	if(ini->GetAllValues("general", config_name.c_str(), values)) {
		CSimpleIni::TNamesDepend::const_iterator i = values.begin();
		initBeforeSet();
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
		for(list<sMapValue>::iterator iter = mapValues.begin(); iter != mapValues.end(); iter++) {
			if(!strncmp(_str_value.c_str(), iter->str.c_str(), iter->str.length())) {
				*rslt_value = iter->value;
				return(true);
			}
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
		if(iter->value == menuItem.value) {
			return;
		}
	}
	menu->push_back(menuItem);
}

string cConfigItem::getJson() {
	JsonExport json;
	json.add("name", config_name);
	json.add("type", getTypeName());
	json.add("set", set);
	json.add("value", json_encode(getValueStr()));
	json.add("default", json_encode(defaultValueStr));
	json.add("minor", minor);
	list<sMapValue> menuItems = getMenuItems();
	if(menuItems.size()) {
		ostringstream outStr;
		int counter = 0;
		for(list<sMapValue>::iterator iter = menuItems.begin(); iter != menuItems.end(); iter++) {
			if(counter) {
				outStr << ';';
			}
			outStr << iter->str << ':' << iter->value;
			++counter;
		}
		json.add("menu", json_encode(outStr.str()));
	}
	return(json.getJson());
}

void cConfigItem::setDefaultValue() {
	if(defaultValueStr.empty() && !naDefaultValueStr) {
		 defaultValueStr = getValueStr();
	}
}

void cConfigItem::clearToDefaultValue() {
	if(!defaultValueStr.empty() && !naDefaultValueStr) {
		 setParamFromValueStr(defaultValueStr);
	}
	set = false;
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

string cConfigItem_yesno::getValueStr(bool configFile) {
	int val;
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

bool cConfigItem_yesno::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}
	
bool cConfigItem_yesno::setParamFromValueStr(string value_str) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
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
	int64_t val;
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
	string str = getStringFromMapValues(val);
	if(!str.empty()) {
		return(str);
	}
	if(multiple) {
		val /= multiple;
	}
	if(yesValue && val == yesValue) {
		return("yes");
	}
	if(ip) {
		return(inet_ntostring(htonl(val)));
	}
	ostringstream outStr;
	outStr << val;
	return(outStr.str());
}

bool cConfigItem_integer::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}

bool cConfigItem_integer::setParamFromValueStr(string value_str) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
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
			if(ip) {
				struct sockaddr_in sa;
				inet_pton(AF_INET, value, &sa.sin_addr);
				*param_uint = sa.sin_addr.s_addr;
			} else  {
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

string cConfigItem_float::getValueStr(bool configFile) {
	double val;
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

bool cConfigItem_float::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}

bool cConfigItem_float::setParamFromValueStr(string value_str) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
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
				outStr << explodeSeparator;
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

bool cConfigItem_string::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}

bool cConfigItem_string::setParamFromValueStr(string value_str) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
		if(param_str) {
			*param_str = value;
			if(!prefix.empty() && strncmp(param_str->c_str(), prefix.c_str(), prefix.length())) {
				*param_str = prefix + *param_str;
			}
			++ok;
		}
		if(param_strchar) {
			strncpy(param_strchar, value, param_strchar_length);
			param_strchar[param_strchar_length - 1] = 0;
			if(!prefix.empty() && strncmp(param_strchar, prefix.c_str(), prefix.length())) {
				strncpy(param_strchar, (prefix + param_strchar).c_str(), param_strchar_length);
			}
			++ok;
		}
		if(param_vect_str && !explodeSeparator.empty()) {
			initBeforeSet();
			*param_vect_str = split(value, explodeSeparator.c_str());
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

string cConfigItem_hour_interval::getValueStr(bool configFile) {
	if(!param_from || !param_to || *param_from == -1 || *param_to == -1) {
		return("");
	}
	ostringstream outStr;
	outStr << *param_from << "-" << *param_to;
	return(outStr.str());
}

bool cConfigItem_hour_interval::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}

bool cConfigItem_hour_interval::setParamFromValueStr(string value_str) {
	if(!param_from || !param_to ||
	   value_str.empty()) {
		return(false);
	}
	const char *value = value_str.c_str();
	if(value) {
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
}

string cConfigItem_ports::getValueStr(bool configFile) {
	if(!param_port_matrix) {
		return("");
	}
	ostringstream outStr;
	int counter = 0;
	for(unsigned i = 0; i < 65535; i++) {
		if(param_port_matrix[i]) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << ';';
				}
			}
			outStr << i;
			++counter;
		}
	}
	return(outStr.str());
}

bool cConfigItem_ports::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini)));
}

bool cConfigItem_ports::setParamFromValueStr(string value_str) {
	return(setParamFromValuesStr(split(value_str, ';')));
}

bool cConfigItem_ports::setParamFromValuesStr(vector<string> list_values_str) {
	if(!param_port_matrix ||
	   list_values_str.empty()) {
		return(false);
	}
	int ok = 0;
	initBeforeSet();
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		param_port_matrix[atoi(iter->c_str())] = 1;
		++ok;
	}
	return(ok > 0);
}

void cConfigItem_ports::initBeforeSet() {
	if(param_port_matrix) {
		for(unsigned i = 0; i < 65535; i++) {
			param_port_matrix[i] = 0;
		}
	}
}

cConfigItem_hosts::cConfigItem_hosts(const char* name, vector<u_int32_t> *adresses, vector<d_u_int32_t> *nets)
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
		for(vector<u_int32_t>::iterator iter = param_adresses->begin(); iter != param_adresses->end(); iter++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << ';';
				}
			}
			outStr << inet_ntostring(*iter);
			++counter;
		}
	}
	if(param_nets) {
		for(vector<d_u_int32_t>::iterator iter = param_nets->begin(); iter != param_nets->end(); iter ++) {
			if(counter) {
				if(configFile) {
					outStr << endl << config_name << " = ";
				} else {
					outStr << ';';
				}
			}
			outStr << inet_ntostring((*iter)[0]) << '/' << (*iter)[1];
			++counter;
		}
	}
	return(outStr.str());
}

bool cConfigItem_hosts::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini)));
}

bool cConfigItem_hosts::setParamFromValueStr(string value_str) {
	return(setParamFromValuesStr(split(value_str, ';')));
}

bool cConfigItem_hosts::setParamFromValuesStr(vector<string> list_values_str) {
	if((!param_adresses && !param_nets) ||
	   list_values_str.empty()) {
		return(false);
	}
	int ok = 0;
	initBeforeSet();
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		const char *iter_str_char = iter->c_str();
		u_int32_t ip;
		int lengthMask = 32;
		char *pointToSeparatorLengthMask = strchr((char*)iter_str_char, '/');
		if(pointToSeparatorLengthMask) {
			*pointToSeparatorLengthMask = 0;
			ip = htonl(inet_addr(iter_str_char));
			lengthMask = atoi(pointToSeparatorLengthMask + 1);
		} else {
			ip = htonl(inet_addr(iter_str_char));
		}
		if(lengthMask < 32) {
			ip = ip >> (32 - lengthMask) << (32 - lengthMask);
		}
		if(ip) {
			if(lengthMask < 32) {
				if(param_nets) {
					param_nets->push_back(d_u_int32_t(ip, lengthMask));
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

cConfigItem_ip_port::cConfigItem_ip_port(const char* name, ip_port *param)
 : cConfigItem(name) {
	init();
	param_ip_port = param;
}

ip_port cConfigItem_ip_port::getValue() {
	return(*param_ip_port);
}

string cConfigItem_ip_port::getValueStr(bool configFile) {
	if(!param_ip_port || !*param_ip_port) {
		return("");
	}
	ostringstream outStr;
	outStr << param_ip_port->get_ip() << ':' << param_ip_port->get_port();
	return(outStr.str());
}

bool cConfigItem_ip_port::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}

bool cConfigItem_ip_port::setParamFromValueStr(string value_str) {
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
			param_ip_port->set_ip(trim_str(value));
			param_ip_port->set_port(port);
			return(true);
		}
	}
	return(false);
}

cConfigItem_ip_port_str_map::cConfigItem_ip_port_str_map(const char* name, map<d_u_int32_t, string> *ip_port_string_map)
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
	for(map<d_u_int32_t, string>::iterator iter = param_ip_port_string_map->begin(); iter != param_ip_port_string_map->end(); iter++) {
		if(counter) {
			if(configFile) {
				outStr << endl << config_name << " = ";
			} else {
				outStr << ';';
			}
		}
		d_u_int32_t ip_port = iter->first;
		outStr << inet_ntostring(ip_port[0]) << ':' << ip_port[1];
		if(!iter->second.empty()) {
			outStr << ' ' << iter->second;
		}
		++counter;
	}
	return(outStr.str());
}

bool cConfigItem_ip_port_str_map::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini)));
}

bool cConfigItem_ip_port_str_map::setParamFromValueStr(string value_str) {
	return(setParamFromValuesStr(split(value_str, ';')));
}

bool cConfigItem_ip_port_str_map::setParamFromValuesStr(vector<string> list_values_str) {
	if(!param_ip_port_string_map ||
	   list_values_str.empty()) {
		return(false);
	}
	int ok = 0;
	initBeforeSet();
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		const char *iter_str_char = iter->c_str();
		u_int32_t ip = 0;
		u_int32_t port = 0;
		string str;
		char *pointToSeparator = strchr((char*)iter_str_char, ':');
		if(pointToSeparator) {
			*pointToSeparator = 0;
			ip = htonl(inet_addr(iter_str_char));
			++pointToSeparator;
			while(*pointToSeparator == ' ') {
				++pointToSeparator;
			}
			port = atoi(pointToSeparator);
			while(*pointToSeparator != ' ') {
				++pointToSeparator;
			}
			while(*pointToSeparator == ' ') {
				++pointToSeparator;
			}
			str = pointToSeparator;
		}
		if(ip && port) {
			(*param_ip_port_string_map)[d_u_int32_t(ip, port)] = str;
			++ok;
		}
	}
	return(ok > 0);
}

void cConfigItem_ip_port_str_map::initBeforeSet() {
	if(param_ip_port_string_map) {
		param_ip_port_string_map->clear();
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
		outStr << inet_ntostring(htonl(iter->first)) << ':' << inet_ntostring(htonl(iter->second));
		++counter;
	}
	return(outStr.str());
}

bool cConfigItem_nat_aliases::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValuesStr(getValuesFromConfigFile(ini)));
}

bool cConfigItem_nat_aliases::setParamFromValueStr(string value_str) {
	return(setParamFromValuesStr(split(value_str, ';')));
}

bool cConfigItem_nat_aliases::setParamFromValuesStr(vector<string> list_values_str) {
	if(!param_nat_aliases || 
	   list_values_str.empty()) {
		return(false);
	}
	int ok = 0;
	initBeforeSet();
	for(vector<string>::iterator iter = list_values_str.begin(); iter != list_values_str.end(); iter++) {
		const char *iter_str_char = iter->c_str();
		char local_ip[30], extern_ip[30];
		char *s = local_ip;
		int i, j = 0;
		int len;
		for(i = 0; i < 30; i++) {
			local_ip[i] = '\0';
			extern_ip[i] = '\0';
		}
		len = strlen(iter_str_char);
		for(int i = 0; i < len; i++) {
			if(iter_str_char[i] == ' ' or iter_str_char[i] == ':' or iter_str_char[i] == '=' or iter_str_char[i] == ' ') {
				s = extern_ip;
				j = 0;
			} else {
				s[j] = iter_str_char[i];
				j++;
			}
		}
		in_addr_t nlocal_ip, nextern_ip;
		if ((int32_t)(nlocal_ip = inet_addr(local_ip)) != -1 && (int32_t)(nextern_ip = inet_addr(extern_ip)) != -1 ){
			(*param_nat_aliases)[nlocal_ip] = nextern_ip;
			++ok;
			if(verbosity > 3) {
				printf("adding local_ip[%s][%u] = extern_ip[%s][%u]\n", local_ip, nlocal_ip, extern_ip, nextern_ip);
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

cConfigItem_custom_headers::cConfigItem_custom_headers(const char* name, vector<dstring> *custom_headers)
 : cConfigItem(name) {
	init();
	this->param_custom_headers = custom_headers;
}

string cConfigItem_custom_headers::getValueStr(bool configFile) {
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

bool cConfigItem_custom_headers::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}

bool cConfigItem_custom_headers::setParamFromValueStr(string value_str) {
	if(!param_custom_headers ||
	   value_str.empty()) {
		return(false);
	}
	int ok = 0;
	initBeforeSet();
	const char *value = value_str.c_str();
	char *pos = (char*)value;
	while(pos && *pos) {
		char *posSep = strchr(pos, ';');
		if(posSep) {
			*posSep = 0;
		}
		string custom_header = pos;
		custom_header.erase(custom_header.begin(), std::find_if(custom_header.begin(), custom_header.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
		custom_header.erase(std::find_if(custom_header.rbegin(), custom_header.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), custom_header.end());
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

cConfigItem_type_compress::cConfigItem_type_compress(const char* name, CompressStream::eTypeCompress *type_compress)
 : cConfigItem(name) {
	init();
	param_type_compress_cs = type_compress;
}

cConfigItem_type_compress::cConfigItem_type_compress(const char* name, FileZipHandler::eTypeCompress *type_compress)
 : cConfigItem(name) {
	init();
	param_type_compress_fzh = type_compress;
}

string cConfigItem_type_compress::getValueStr(bool configFile) {
	if(param_type_compress_cs) {
		switch(*param_type_compress_cs) {
		case CompressStream::zip:
			return("zip");
		case CompressStream::snappy:
			return("snappy");
		case CompressStream::lz4:
			return("lz4");
		case CompressStream::lz4_stream:
			return("lz4_stream");
		default:
			return("no");
		}
	}
	if(param_type_compress_fzh) {
		if(*param_type_compress_fzh == FileZipHandler::gzip) {
			return("yes");
		} else {
			return("no");
		}
	}
	return("");
}

bool cConfigItem_type_compress::setParamFromConfigFile(CSimpleIniA *ini) {
	return(setParamFromValueStr(getValueFromConfigFile(ini)));
}

bool cConfigItem_type_compress::setParamFromValueStr(string value_str) {
	if(value_str.empty()) {
		return(false);
	}
	int ok = 0;
	const char *value = value_str.c_str();
	if(value) {
		strlwr((char*)value);
		if(param_type_compress_cs) {
			*param_type_compress_cs = CompressStream::convTypeCompress(value);
			++ok;
		}
		if(param_type_compress_fzh) {
			*param_type_compress_fzh = !strcmp(value, "zip") || yesno(value) ? FileZipHandler::gzip : FileZipHandler::compress_na;
			++ok;
		}
	}
	return(ok > 0);
}


cConfig::cConfig() {
}

cConfig::~cConfig() {
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		delete iter->second;
	}
}

void cConfig::addConfigItem(cConfigItem *configItem) {
	configItem->config = this;
	config_map[configItem->config_name] = configItem;
	config_list.push_back(configItem->config_name);
}

bool cConfig::loadFromConfigFileOrDirectory(const char *filename) {
	if(!FileExists((char*)filename)) {
		return(false);
	}
	if(DirExists((char*)filename)) {
		DIR *dir = opendir(filename);
		if(dir != NULL) {
			struct dirent *ent;
			while((ent = readdir(dir)) != NULL) {
				if (ent->d_type != 0x8) {
					continue;
				}
				char filepathname[1024];
				strcpy(filepathname, filename);
				strcat(filepathname, "/");
				strcat(filepathname, ent->d_name);
				if(!loadFromConfigFile(filepathname)) {
					return(false);
				}
			}
		} else {
			loadFromConfigFileError("Cannot access directory file %s!", filename);
			return(false);
		}
	} else {
		return(loadFromConfigFile(filename));
	}
	return(true);
}

bool cConfig::loadFromConfigFile(const char *filename, string *error) {
	if(error) {
		*error = "";
	}
	if(verbosity > 1) { 
		syslog(LOG_NOTICE, "Loading configuration from file %s", filename);
	}
	printf("Loading configuration from file %s ", filename);
	FILE *fp = fopen(filename, "rb");
	if(!fp) {
		loadFromConfigFileError("Cannot open / access config file %s!", filename, error);
		return(false);
	}
	if(fseek(fp, 0, SEEK_END) == -1) {
		loadFromConfigFileError("Cannot access config file %s!", filename, error);
		fclose(fp);
		return(false);
	}
	size_t fileSize = ftell(fp);
	if(fileSize == 0) {
		printf("WARNING - configuration file %s is empty\n", filename);
		fclose(fp);
		return(true);
	}
	size_t fileSizeWithGeneralHedaer = fileSize + 10;
	char *fileContent = new FILE_LINE char[fileSizeWithGeneralHedaer];
	if(!fileContent) {
		loadFromConfigFileError("Cannot alloc memory for config file %s!", filename, error);
		fclose(fp);
		return(false);

	}
	fileContent[0] = 0;
	strcat(fileContent, "[general]\n");
	fseek(fp, 0, SEEK_SET);
	size_t readBytes = fread(fileContent + 10, sizeof(char), fileSize, fp);
	if(readBytes != fileSize) {
		loadFromConfigFileError("Cannot read data from config file %s!", filename, error);
		fclose(fp);
		return(false);
	}
	fclose(fp);
	
	CSimpleIniA ini;
	ini.SetUnicode();
	ini.SetMultiKey(true);
	
	int rc = ini.LoadData(fileContent, readBytes + 10); //with "[general]\n" thats not included in uRead
	if (rc != 0) {
		loadFromConfigFileError("Loading config from file %s FAILED!", filename, error);
		return(false);
	}
	delete[] fileContent;
	
	string inistr;
	rc = ini.Save(inistr);
	if (rc != 0) {
		loadFromConfigFileError("Preparing config from file %s FAILED!", filename, error);
		return(false);
	}
	
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		if(iter->second->setParamFromConfigFile(&ini)) {
			iter->second->set = true;
			evSetConfigItem(iter->second);
		}
	}
	
	if (rc != 0) {
		loadFromConfigFileError("Evaluating config from file %s FAILED!", filename, error);
		return(false);
	}
	printf("OK\n");
	return(true);
}

void cConfig::loadFromConfigFileError(const char *errorString, const char *filename, string *error) {
	char error_buff[1024];
	snprintf(error_buff, sizeof(error_buff), errorString, filename);
	printf("ERROR: %s\n", error_buff);
	if(error) *error = error_buff;
	syslog(LOG_ERR, error_buff);
}

string cConfig::getContentConfig(bool configFile) {
	ostringstream outStr;
	for(list<string>::iterator iter = config_list.begin(); iter != config_list.end(); iter++) {
		map<string, cConfigItem*>::iterator iter_map = config_map.find(*iter);
		if(iter_map != config_map.end()) {
			if(iter_map->second->set) {
				outStr << *iter
				       << " = "
				       << iter_map->second->getValueStr(configFile)
				       << endl;
			}
		}
	}
	return(outStr.str());
}

string cConfig::getJson(bool onlyIfSet) {
	JsonExport json;
	int counter = 1;
	for(list<string>::iterator iter = config_list.begin(); iter != config_list.end(); iter++) {
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
	return(json.getJson());
}

void cConfig::setFromJson(const char *jsonStr, bool onlyIfSet) {
	JsonItem jsonData;
	jsonData.parse(jsonStr);
	for(size_t i = 0; i < jsonData.getLocalCount(); i++) {
		JsonItem *item = jsonData.getLocalItem(i);
		string config_name = item->getValue("name");
		string value = item->getValue("value");
		int set = atoi(item->getValue("set").c_str());
		if(!onlyIfSet || set) {
			map<string, cConfigItem*>::iterator iter_map = config_map.find(config_name);
			if(iter_map != config_map.end()) {
				if(iter_map->second->setParamFromValueStr(value)) {
					iter_map->second->set = true;
					evSetConfigItem(iter_map->second);
				}
			}
		}
	}
}

void cConfig::setFromMysql(bool checkConnect) {
	SqlDb *sqlDb = createSqlObject();
	if(checkConnect) {
		sqlDb->setSilentConnect();
		if(!sqlDb->connect()) {
			delete sqlDb;
			return;
		}
	}
	ostringstream q;
	q << "SELECT * FROM sensor_config WHERE id_sensor ";
	extern int opt_id_sensor;
	if(opt_id_sensor) {
		q << "= " << opt_id_sensor;
	} else {
		q << "IS NULL";
	}
	sqlDb->query(q.str());
	SqlDb_row row = sqlDb->fetchRow();
	if(row) {
		for(size_t i = 0; i < row.getCountFields(); i++) {
			string column = row.getNameField(i);
			if(column != "id" && column != "id_sensor" && !row.isNull(column)) {
				map<string, cConfigItem*>::iterator iter_map = config_map.find(column);
				if(iter_map != config_map.end()) {
					if(iter_map->second->setParamFromValueStr(row[column])) {
						iter_map->second->set = true;
						evSetConfigItem(iter_map->second);
					}
				}
			}
		}
	}
	delete sqlDb;
}

void cConfig::putToMysql() {
	SqlDb *sqlDb = createSqlObject();
	list<string> sensor_config_columns;
	sqlDb->query("show columns from sensor_config");
	SqlDb_row row;
	while(row = sqlDb->fetchRow()) {
		sensor_config_columns.push_back(row[0]);
	}
	ostringstream q;
	q << "SELECT * FROM sensor_config WHERE id_sensor ";
	extern int opt_id_sensor;
	if(opt_id_sensor) {
		q << "= " << opt_id_sensor;
	} else {
		q << "IS NULL";
	}
	sqlDb->query(q.str());
	SqlDb_row row_get = sqlDb->fetchRow();
	SqlDb_row row_save;
	if(row_get) {
		for(size_t i = 0; i < row_get.getCountFields(); i++) {
			string column = row_get.getNameField(i);
			if(column != "id" && column != "id_sensor" && !row_get.isNull(column)) {
				row_save.add((const char*)NULL, column);
			}
		}
	}
	for(list<string>::iterator iter = config_list.begin(); iter != config_list.end(); iter++) {
		map<string, cConfigItem*>::iterator iter_map = config_map.find(*iter);
		if(iter_map != config_map.end()) {
			if(iter_map->second->set) {
				bool columnExists = false;
				for(list<string>::iterator iter_column = sensor_config_columns.begin(); iter_column != sensor_config_columns.end(); iter_column++) {
					if(*iter_column == *iter) {
						columnExists = true;
						break;
					}
				}
				if(!columnExists) {
					sqlDb->query("alter table sensor_config add column `" + *iter + "` text");
				}
				row_save.add(iter_map->second->getValueStr(), *iter);
			}
		}
	}
	if(row_get) {
		char id_cond[20];
		sprintf(id_cond, "ID = %i", atoi(row_get["id"].c_str()));
		sqlDb->update("sensor_config", row_save, id_cond);
	} else {
		sqlDb->insert("sensor_config", row_save);
	}
	delete sqlDb;
}

void cConfig::setDefaultValues() {
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		iter->second->setDefaultValue();
	}
}

void cConfig::clearToDefaultValues() {
	for(map<string, cConfigItem*>::iterator iter = config_map.begin(); iter != config_map.end(); iter++) {
		iter->second->clearToDefaultValue();
		evSetConfigItem(iter->second);
	}
}