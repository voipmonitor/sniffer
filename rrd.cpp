#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <syslog.h>
#include <rrd.h>

#include "voipmonitor.h"
#include "rrd.h"
#include "tools.h"

#include <iostream>  
#include <sstream>  
#include <iomanip>
#include <string.h>


extern int opt_rrd;

int vm_rrd_version;


RrdChartSeries::RrdChartSeries(const char *name, const char *descr, const char *color,
			       const char *fce, const char *type, bool legend) {
	if(!fce) {
		fce = "MAX";
	}
	if(!type) {
		type = "LINE1";
	}
	this->name = name;
	this->descr = descr ? descr : "";
	this->color = color ? color : "";
	this->fce = fce;
	this->type = type;
	this->legend = legend;
	precision = 0;
	precision_avg = 2;
}

void RrdChartSeries::setFce(const char *fce) {
	this->fce = fce;
}

void RrdChartSeries::setType(const char *type) {
	this->type = type;
}

void RrdChartSeries::setLegend(bool legend) {
	this->legend = legend;
}

RrdChartSeries* RrdChartSeries::setPrecision(unsigned base, unsigned avg) {
	this->precision = base;
	this->precision_avg = avg;
	return(this);
}

RrdChartSeries* RrdChartSeries::setAdjust(const char *adj_operator, const char *adj_number) {
	this->adj_operator = adj_operator;
	this->adj_number = adj_number;
	return(this);
}

string RrdChartSeries::graphString(const char *dbFilename) {
	string rslt;
	string var_name = "_" + find_and_replace(name.c_str(), "-", "_") + "_" + fce;
	rslt = 
		"DEF:" + var_name + "=" + dbFilename + ":" + name + ":" + fce + " ";
	if(!adj_operator.empty() && !adj_number.empty()) {
		string _var_name = "_" + var_name;
		rslt += "CDEF:" + _var_name + "=" + var_name + "," + adj_number + "," + adj_operator + " ";
		var_name = _var_name;
	}
	rslt += string(type) + ":" + var_name + "#" + color + ":\"" + descr + (vm_rrd_version < 10403 && legend ? "\\t" : "\\l") + "\" ";
	if(legend) {
		rslt +=
			(vm_rrd_version < 10403 ? "" : string("COMMENT:\\u ")) +
			"GPRINT:" + var_name + ":LAST:\"Cur\\: %5." + intToString(precision) + "lf\" " +
			"GPRINT:" + var_name + ":AVERAGE:\"Avg\\: %5." + intToString(precision_avg) + "lf\" " +
			"GPRINT:" + var_name + ":MAX:\"Max\\: %5." + intToString(precision) + "lf\" " +
			"GPRINT:" + var_name + ":MIN:\"Min\\: %5." + intToString(precision) + "lf" + (vm_rrd_version < 10403 ? "\\l" : "\\r") + "\" ";
	}
	return(rslt);
}

RrdChartValue::RrdChartValue(const char *name, const char *descr, const char *color, double min, double max) :
 RrdChartSeries(name, descr, color) {
	this->min = min;
	this->max = max;
	value = RRD_VALUE_UNSET;
}

string RrdChartValue::createString(unsigned chartStep) {
	return("DS:" + name + ":GAUGE:" + intToString(chartStep * 2) + ":" + 
	       floatToString(min, precision) + ":" + floatToString(max, precision) + " ");
}

void RrdChartValue::setValue(double value, bool add) {
	if(add) {
		if(this->value == RRD_VALUE_UNSET) {
			this->value = value;
		} else {
			this->value += value;
		}
	} else {
		this->value = value;
	}
}

string RrdChartValue::getValue() {
	if(value < min || value == RRD_VALUE_UNSET) {
		return("U");
	}
	return(floatToString(value > max ? max : value));
}

RrdChartSeriesGroup::~RrdChartSeriesGroup() {
	for(list<RrdChartSeries*>::iterator iter = series.begin(); iter != series.end(); iter++) {
		delete (*iter);
	}
}

RrdChartSeries *RrdChartSeriesGroup::addSeries(RrdChartSeries *series) {
	this->series.push_back(series);
	return(series);
}

void RrdChartSeriesGroup::setName(const char *name) {
	this->name = name;
}

void RrdChartSeriesGroup::setVerticalLabel(const char *vert_label) {
	this->vert_label = vert_label;
}

string RrdChartSeriesGroup::graphString(const char *dbFilename) {
	string rslt;
	for(list<RrdChartSeries*>::iterator iter = series.begin(); iter != series.end(); iter++) {
		rslt += (*iter)->graphString(dbFilename);
	}
	return(rslt);
}

RrdChartDb::RrdChartDb(unsigned steps, unsigned rows) {
	this->steps = steps;
	this->rows = rows;
}

string RrdChartDb::createString() {
	string rslt =
		"RRA:MIN:0.5:" + intToString(steps) + ":" + intToString(rows) + " " +
		"RRA:MAX:0.5:" + intToString(steps) + ":" + intToString(rows) + " " +
		"RRA:AVERAGE:0.5:" + intToString(steps) + ":" + intToString(rows) + " ";
	return(rslt);
}

RrdChart::RrdChart(const char *dbname, const char *name, unsigned step) {
	if(!step) {
		step = 10;
	}
	this->dbname = dbname;
	this->name = name ? name : "";
	this->step = step;
}

RrdChart::~RrdChart() {
	for(list<RrdChartValue*>::iterator iter = values.begin(); iter != values.end(); iter++) {
		delete (*iter);
	}
	for(list<RrdChartDb*>::iterator iter = dbs.begin(); iter != dbs.end(); iter++) {
		delete (*iter);
	}
	for(map<string, RrdChartSeriesGroup*>::iterator iter = series_groups.begin(); iter != series_groups.end(); iter++) {
		delete iter->second;
	}
}

void RrdChart::setVerticalLabel(const char *vert_label) {
	this->vert_label = vert_label;
}

RrdChartValue* RrdChart::addValue(const char *name, const char *descr, const char *color, double min, double max) {
	RrdChartValue *value = new FILE_LINE(0) RrdChartValue(name, descr, color, min, max);
	values.push_back(value);
	return(value);
}

RrdChartDb* RrdChart::addDb(unsigned step, unsigned rows) {
	RrdChartDb *db = new FILE_LINE(0) RrdChartDb(step, rows);
	dbs.push_back(db);
	return(db);
}

void RrdChart::addSeriesGroup(const char *name, RrdChartSeriesGroup *group) {
	if(!name) {
		name = "default";
	}
	series_groups[name] = group;
}

void RrdChart::setStdDb(unsigned rows) {
	if(!rows) {
		rows = 760;
	}
	addDb(1, rows);
	addDb(24, rows);
	addDb(168, rows);
	addDb(8760, rows);
}

string RrdChart::createString() {
	string rslt =
		"create " + getDbFilename() + " " +
		"--start N --step " + intToString(step) + " ";
	for(list<RrdChartValue*>::iterator iter = values.begin(); iter != values.end(); iter++) {
		rslt += (*iter)->createString(step);
	}
	for(list<RrdChartDb*>::iterator iter = dbs.begin(); iter != dbs.end(); iter++) {
		rslt += (*iter)->createString();
	}
	return(rslt);
}

void RrdChart::parseStructFromInfo(const char *info, list<RrdChartValue> *values) {
	vector<string> infoA = split(info, "\n");
	RrdChartValue rrdValue("", "", "", 0, 0);
	for(unsigned i = 0; i < infoA.size(); i++) {
		if(infoA[i].substr(0, 3) == "ds[") {
			size_t endNamePos = infoA[i].find("].");
			size_t valueSeparator = infoA[i].find(" = ");
			if(endNamePos != string::npos && valueSeparator != string::npos) {
				string series = infoA[i].substr(3, endNamePos - 3);
				string name = infoA[i].substr(endNamePos + 2, valueSeparator - endNamePos - 2);
				string value = infoA[i].substr(valueSeparator + 3);
				if(!series.empty() && !name.empty() && !value.empty()) {
					if(value.length() > 1 && value[0] == '"' && value[value.length() - 1] == '"') {
						value = value.substr(1, value.length() - 2);
					}
					if(name == "index") {
						if(!rrdValue.name.empty()) {
							values->push_back(rrdValue);
						}
						rrdValue = RrdChartValue(series.c_str(), "", "", 0, 0);
					} else if(name == "max") {
						rrdValue.max = rrd_atof(value);
					} else if(name == "min") {
						rrdValue.min = rrd_atof(value);
					}
				}
			}
		}
	}
	if(!rrdValue.name.empty()) {
		values->push_back(rrdValue);
	}
}

void RrdChart::alterIfNeed(list<RrdChartValue> *valuesFromInfo, RrdCharts *rrdCharts) {
	for(list<RrdChartValue*>::iterator iter = values.begin(); iter != values.end(); iter++) {
		for(list<RrdChartValue>::iterator iter_info = valuesFromInfo->begin(); iter_info != valuesFromInfo->end(); iter_info++) {
			if((*iter)->name == iter_info->name) {
				if((*iter)->max != iter_info->max) {
					syslog(LOG_NOTICE, "rrd alter : %s",
					       (getDbFilename() + " : " + (*iter)->name + " : " + 
						floatToString(iter_info->max, (*iter)->precision) + " -> " + floatToString((*iter)->max, (*iter)->precision)).c_str());
					string alterStr = "tune " + getDbFilename() + " " +
							  "--maximum " + (*iter)->name + ":" + floatToString((*iter)->max, (*iter)->precision);
					rrdCharts->doRrdCmd(alterStr);
				}
			}
		}
	}
}

string RrdChart::infoString() {
	string rslt =
		"info " + getDbFilename();
	return(rslt);
}

string RrdChart::graphString(const char *seriesGroupName,
			     const char *dstfile, const char *fromTime, const char *toTime, 
			     const char *backgroundColor, unsigned resx, unsigned resy, 
			     bool slope, bool icon) {
	RrdChartSeriesGroup *seriesGroup = NULL;
	if(series_groups.size()) {
		map<string, RrdChartSeriesGroup*>::iterator iter = series_groups.find(seriesGroupName && *seriesGroupName ? seriesGroupName : "default");
		if(iter != series_groups.end()) {
			seriesGroup = iter->second;
		}
	}
	string _title = seriesGroup && !seriesGroup->name.empty() ? seriesGroup->name : name;
	string _vert_label = seriesGroup && !seriesGroup->vert_label.empty() ? seriesGroup->vert_label : vert_label;
	string rslt =
		"graph " + 
		(dstfile ? string("\"") + dstfile + "\"" : "-") + " " +
		"-w " + intToString(resx) + " -h " + intToString(resy) + " " + 
		"-a PNG " +
		"--start \"" + fromTime + "\" --end \"" + toTime + "\" " +
		"--font DEFAULT:0:Courier " +
		(!_title.empty() ? "--title \"" + _title + "\" " : "") +
		"--watermark \"`date`\" " + 
		(vm_rrd_version >= 10400 ? "--disable-rrdtool-tag " : "") +
		(!_vert_label.empty() ?  "--vertical-label \"" + _vert_label + "\" " : "") +
		"--lower-limit 0 " +
		"--units-exponent 0 " +
		(vm_rrd_version >= 10400 ? "--full-size-mode " : "") +
		(slope ? "--slope-mode " : "") +
		(icon ? "--only-graph " : "") +
		(backgroundColor ? string("-c BACK#") + backgroundColor + " -c SHADEA#" + backgroundColor + " -c SHADEB#" + backgroundColor + " " : "");
	if(seriesGroup) {
		rslt += seriesGroup->graphString(getDbFilename().c_str());
	} else {
		for(list<RrdChartValue*>::iterator iter = values.begin(); iter != values.end(); iter++) {
			rslt += (*iter)->graphString(getDbFilename().c_str());
		}
	}
	return(rslt);
}

string RrdChart::updateString() {
	string rslt =
		"update " + getDbFilename() + " N:";
	unsigned counterValues = 0;
	for(list<RrdChartValue*>::iterator iter = values.begin(); iter != values.end(); iter++) {
		if(counterValues) {
			rslt += ":";
		}
		rslt += (*iter)->getValue();
		++counterValues;
	}
	return(rslt);
}

string RrdChart::getDbFilename() {
	return(string(getRrdDir()) + "/rrd/" + dbname + ".rrd");
}

bool RrdChart::setValue(const char *valuename, double value, bool add) {
	for(list<RrdChartValue*>::iterator iter = values.begin(); iter != values.end(); iter++) {
		if((*iter)->name == valuename) {
			(*iter)->setValue(value, add);
			return(true);
		}
	}
	return(false);
}

void RrdChart::clearValues() {
	for(list<RrdChartValue*>::iterator iter = values.begin(); iter != values.end(); iter++) {
		(*iter)->value = RRD_VALUE_UNSET;
	}
}

double RrdChart::rrd_atof(string value) {
	return(value == "U" ?
		RRD_VALUE_UNSET :
		atof(find_and_replace(value, ",", ".").c_str()));
}

RrdCharts::RrdCharts() {
	sync_values = 0;
	sync_queue = 0;
	queueThreadId = 0;
	memset(queueThreadPstatData, 0, sizeof(queueThreadPstatData));
}

RrdCharts::~RrdCharts() {
	clearCharts();
}

RrdChart* RrdCharts::addChart(const char *dbname, const char *name, unsigned step) {
	RrdChart *chart = new FILE_LINE(0) RrdChart(dbname, name, step);
	charts.push_back(chart);
	return(chart);
}

string RrdCharts::graphString(const char *dbname,
			      const char *seriesGroupName,
			      const char *dstfile, const char *fromTime, const char *toTime, 
			      const char *backgroundColor, unsigned resx, unsigned resy, 
			      bool slope, bool icon) {
	RrdChart *chart = NULL;
	for(list<RrdChart*>::iterator iter = charts.begin(); iter != charts.end(); iter++) {
		if((*iter)->dbname == dbname) {
			chart = *iter;
		}
	}
	if(chart) {
		return(chart->graphString(seriesGroupName,
					  dstfile, fromTime, toTime, 
					  backgroundColor, resx, resy, 
					  slope, icon));
	}
	return("");
}

int RrdCharts::setValue(const char *valuename, double value, const char *dbname, bool add) {
	lock_values();
	map<string, sValuePtr>::iterator iter_vm = map_values.find(valuename);
	if(iter_vm != map_values.end() &&
	   iter_vm->second.counter == 1) {
		iter_vm->second.value->setValue(value, add);
		unlock_values();
		return(1);
	}
	int counterSet = 0;
	for(list<RrdChart*>::iterator iter = charts.begin(); iter != charts.end(); iter++) {
		if(!dbname || (*iter)->dbname == dbname) {
			if((*iter)->setValue(valuename, value, add)) {
				++counterSet;
			}
		}
	}
	unlock_values();
	if(!counterSet) {
		syslog(LOG_ERR, "RRD ERROR: unknown value name: %s", valuename);
	} else if(counterSet > 1) {
		syslog(LOG_ERR, "RRD ERROR: ambiguous value name: %s", valuename);
	}
	return(counterSet);
}

int RrdCharts::addValue(const char *valuename, double value, const char *dbname) {
	return(setValue(valuename, value, dbname, true));
}

void RrdCharts::clearCharts() {
	for(list<RrdChart*>::iterator iter = charts.begin(); iter != charts.end(); iter++) {
		delete (*iter);
	}
	charts.clear();
	map_values.clear();
}

void RrdCharts::clearValues() {
	lock_values();
	for(list<RrdChart*>::iterator iter = charts.begin(); iter != charts.end(); iter++) {
		(*iter)->clearValues();
	}
	unlock_values();
}

void RrdCharts::createAll(bool skipIfExist) {
	spooldir_mkdir(string(getRrdDir()) + "/rrd");
	for(list<RrdChart*>::iterator iter = charts.begin(); iter != charts.end(); iter++) {
		if(!skipIfExist || !file_exists((*iter)->getDbFilename().c_str())) {
			string createString = (*iter)->createString();
			doRrdCmd(createString);
		}
	}
}

void RrdCharts::alterAll() {
	for(list<RrdChart*>::iterator iter = charts.begin(); iter != charts.end(); iter++) {
		if(file_exists((*iter)->getDbFilename().c_str())) {
			string infoString = (*iter)->infoString();
			SimpleBuffer out;
			rrd_lock();
			if(sverb.rrd_info) {
				syslog(LOG_NOTICE, "call rrdttol: %s", (string(RRDTOOL_CMD) + " " + infoString).c_str());
			}
			vm_pexec((string(RRDTOOL_CMD) + " " + infoString).c_str(), &out);
			rrd_unlock();
			if(out.size() > 0) {
				list<RrdChartValue> structFromInfo;
				(*iter)->parseStructFromInfo((char*)out, &structFromInfo);
				if(structFromInfo.size() > 0) {
					(*iter)->alterIfNeed(&structFromInfo, this);
				}
			}
		}
	}
}

void RrdCharts::updateAll() {
	lock_values();
	for(list<RrdChart*>::iterator iter = charts.begin(); iter != charts.end(); iter++) {
		string updateString = (*iter)->updateString();
		doRrdCmd(updateString);
	}
	unlock_values();
}

bool RrdCharts::doRrdCmd(string cmd, string *error, bool syslogError) {
	if(cmd.empty()) {
		return(false);
	}
	vector<string> cmd_args;
	parse_cmd_str(cmd.c_str(), &cmd_args);
	if(cmd_args.empty()) {
		return(false);
	}
	if(sverb.rrd_info) {
		syslog(LOG_NOTICE, "call rrd command: %s", cmd.c_str());
	}
	extern char *rrd_last_cmd_global;
	rrd_last_cmd_global = new FILE_LINE(0) char[cmd.length() + 1];
	strcpy(rrd_last_cmd_global, cmd.c_str());
	rrd_last_cmd_global[cmd.length()] = 0;
	unsigned _cmd_args_length = cmd_args.size();
	char *_cmd_args[_cmd_args_length + 1];
	for(unsigned i = 0; i < _cmd_args_length; i++) {
		unsigned arg_length = cmd_args[i].length();
		_cmd_args[i] = new FILE_LINE(0) char[arg_length + 1];
		strncpy(_cmd_args[i], cmd_args[i].c_str(), arg_length);
		_cmd_args[i][arg_length] = 0;
	}
	_cmd_args[_cmd_args_length] = NULL;
	bool dllRun = false;
	rrd_lock();
	if(cmd_args[0] == "create") {
		rrd_create(_cmd_args_length, _cmd_args);
		dllRun = true;
	} else if(cmd_args[0] == "update") {
		rrd_update(_cmd_args_length, _cmd_args);
		dllRun = true;
	} else if(cmd_args[0] == "tune") {
		rrd_tune(_cmd_args_length, _cmd_args);
		dllRun = true;
	}
	rrd_unlock();
	for(unsigned i = 0; i < _cmd_args_length; i++) {
		delete [] _cmd_args[i];
	}
	delete [] rrd_last_cmd_global;
	rrd_last_cmd_global = NULL;
	if(dllRun) {
		if(rrd_test_error()) {
			string _error = rrd_get_error();
			if(error) {
				*error = _error;
			}
			if(syslogError) {
				syslog(LOG_ERR, "RRD ERROR: %s", _error.c_str());
			}
			rrd_clear_error();
			return(false);
		}
		return(true);
	} else {
		return(false);
	}
}

void RrdCharts::addToQueue(RrdChartQueueItem *queueItem) {
	lock_queue();
	if(queue.size() > 1000) {
		queueItem->error = "rrd queue is full";
		queueItem->completed = true;
	} else  {
		queue.push_back(queueItem);
	}
	unlock_queue();
}

void RrdCharts::startQueueThread() {
	vm_pthread_create_autodestroy("rrd queue thread",
				      &this->queue_thread_handle, NULL, RrdCharts::queueThread, this, __FILE__, __LINE__);
	
}

void *RrdCharts::queueThread(void *arg) {
	RrdCharts *rrd_charts = (RrdCharts*)arg;
	rrd_charts->_queueThread();
	return(NULL);
}

void RrdCharts::_queueThread() {
	queueThreadId = get_unix_tid();
	while(!is_terminating()) {
		RrdChartQueueItem *item = NULL;
		lock_queue();
		if(queue.size()) {
			item = queue.front();
			queue.pop_front();
		}
		unlock_queue();
		if(item) {
			if(item->request_type == "graph") {
				rrd_lock();
				if(sverb.rrd_info) {
					syslog(LOG_NOTICE, "call rrdttol: %s", item->rrd_cmd.c_str());
				}
				SimpleBuffer error;
				if(vm_pexec(item->rrd_cmd.c_str(), &item->result, &error)) {
					if(!item->result.size()) {
						item->error = error.size() ? (char*)error : "failed output from rrdtool";
					}
				} else {
					item->error = "failed run rrdtool";
				}
				if(sverb.rrd_info) {
					if(item->error.length()) {
						syslog(LOG_NOTICE, "rrdttol error: %s", item->error.c_str());
					} else {
						syslog(LOG_NOTICE, "rrdttol result size: %u", item->result.size());
					}
				}
				item->completed = true;
				rrd_unlock();
			}
		} else {
			USLEEP(10000);
		}
	}
}

void RrdCharts::prepareQueueThreadPstatData() {
	if(queueThreadId) {
		if(queueThreadPstatData[0].cpu_total_time) {
			queueThreadPstatData[1] = queueThreadPstatData[0];
		}
		pstat_get_data(queueThreadId, queueThreadPstatData);
	}
}

double RrdCharts::getCpuUsageQueueThreadPerc(bool preparePstatData) {
	if(preparePstatData) {
		prepareQueueThreadPstatData();
	}
	if(queueThreadId) {
		double ucpu_usage, scpu_usage;
		if(queueThreadPstatData[0].cpu_total_time && queueThreadPstatData[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(
				&queueThreadPstatData[0], &queueThreadPstatData[1],
				&ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
}

void RrdCharts::createMapValues() {
	for(list<RrdChart*>::iterator iter_ch = charts.begin(); iter_ch != charts.end(); iter_ch++) {
		for(list<RrdChartValue*>::iterator iter_v = (*iter_ch)->values.begin(); iter_v != (*iter_ch)->values.end(); iter_v++) {
			map<string, sValuePtr>::iterator iter_vm = map_values.find((*iter_v)->name);
			if(iter_vm == map_values.end()) {
				sValuePtr vp;
				vp.value = *iter_v;
				vp.counter = 1;
				map_values[(*iter_v)->name] = vp;
			} else {
				++iter_vm->second.counter;
			}
		}
	}
}

volatile int RrdCharts::sync_rrd = 0;


RrdCharts rrd_charts;


void rrd_charts_init() {
	RrdChart *ch;
	RrdChartSeriesGroup *g;
	
	// *tCPU
	ch = rrd_charts.addChart(RRD_CHART_tCPU, "CPU usage");
	ch->setStdDb();
	ch->setVerticalLabel("percent[%]");
	ch->addValue(RRD_VALUE_tCPU_t0, "t0 CPU Usage %", "0000FF", 0, 120)
			->setPrecision(1, 1);
	ch->addValue(RRD_VALUE_tCPU_t1, "t1 CPU Usage %", "00FF00", 0, 120)
			->setPrecision(1, 1);
	ch->addValue(RRD_VALUE_tCPU_t2, "t2 CPU Usage %", "FF0000", 0, 120 * 20)
			->setPrecision(1, 1);
	
	// * heap
	ch = rrd_charts.addChart(RRD_CHART_heap, "Buffer usage");
	ch->setStdDb();
	ch->setVerticalLabel("percent[%]");
	ch->addValue(RRD_VALUE_buffer, "Packet buffer %", "0000FF", 0, 1000000);
	ch->addValue(RRD_VALUE_ratio, "I/O buffer usage %", "FF0000", 0, 10000000);
	
	// * drop
	ch = rrd_charts.addChart(RRD_CHART_drop, "Packet drops");
	ch->setStdDb();
	ch->setVerticalLabel("packtets");
	ch->addValue(RRD_VALUE_exceeded, "Buffer overloaded", "0000FF", 0, 1000000);
	ch->addValue(RRD_VALUE_packets, "Packets dropped", "00FF00", 0, 1000000);
	
	// * callscounter
	ch = rrd_charts.addChart(RRD_CHART_callscounter, "Number of calls");
	ch->setStdDb();
	ch->setVerticalLabel("calls");
	ch->addValue(RRD_VALUE_inv, "INVs", "00FF00", 0, 500000);
	ch->addValue(RRD_VALUE_reg, "REGs", "99FF00", 0, 500000);
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_inv, "INVs max", "00FF00", "MAX", "AREA", true));
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_inv, "INVs avg", "0000FF", "AVERAGE", "LINE1", false));
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_inv, "INVs min", "FF0000", "MIN", "LINE1", false));
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_reg, "REGs max", "99FF00", "MAX", "AREA", true));
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_reg, "REGs avg", "9999FF", "AVERAGE", "LINE1", false));
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_reg, "REGs min", "FF9900", "MIN", "LINE1", false));
	ch->addSeriesGroup(NULL, g);
	
	// * tacCPU
	ch = rrd_charts.addChart(RRD_CHART_tacCPU, "Compression");
	ch->setStdDb();
	ch->setVerticalLabel("Total consumption");
	ch->addValue(RRD_VALUE_zipCPU, "Zip compression %", "0000FF", 0, 10000)
			->setPrecision(1, 1);
	ch->addValue(RRD_VALUE_tarCPU, "Tar compression %", "00FF00", 0, 10000)
			->setPrecision(1, 1);
	
	// * db-memusage
	ch = rrd_charts.addChart(RRD_CHART_memusage, "Memory usage");
	ch->setStdDb();
	ch->setVerticalLabel("MB");
	ch->addValue(RRD_VALUE_RSS, "Used memory (RSS)", "00FF00", 0, 1000000)
			->setType("AREA");
	
	// * speedmbs
	ch = rrd_charts.addChart(RRD_CHART_speedmbs, "Network throughput");
	ch->setStdDb();
	ch->setVerticalLabel("MB/s");
	ch->addValue(RRD_VALUE_mbs, "speed (Mb/s)", "00FF00", 0, 100000)
			->setType("AREA");
	
	// * SQL
	ch = rrd_charts.addChart(RRD_CHART_SQL);
	ch->setStdDb();
	ch->addValue(RRD_VALUE_SQLf_D, NULL, NULL, 0, 100000);
	ch->addValue(RRD_VALUE_SQLf_C, NULL, NULL, 0, 100000);
	ch->addValue(RRD_VALUE_SQLq_C, NULL, NULL, 0, 1000000);
	ch->addValue(RRD_VALUE_SQLq_M, NULL, NULL, 0, 100000);
	ch->addValue(RRD_VALUE_SQLq_R, NULL, NULL, 0, 100000);
	ch->addValue(RRD_VALUE_SQLq_Cl, NULL, NULL, 0, 100000);
	ch->addValue(RRD_VALUE_SQLq_H, NULL, NULL, 0, 100000);
	// ** SQLf
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("SQL cache files");
	g->setVerticalLabel("sec,count");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_SQLf_D, "SQL delay in s", "0000FF", "MAX", "LINE1", true))
			->setAdjust("/", "1000");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_SQLf_C, "SQL queries count", "FF0000", "MAX", "LINE1", true));
	ch->addSeriesGroup(RRD_CHART_SERIES_SQLf, g);
	// ** SQLq
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("SQL queue");
	g->setVerticalLabel("queries");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_SQLq_C, "CDR queue", "0000FF", "MAX", "LINE1", true));
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_SQLq_M, "Message queue", "00FF00", "MAX", "LINE1", true))
			->setAdjust("*", "100");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_SQLq_R, "Register queue", "FF0000", "MAX", "LINE1", true))
			->setAdjust("*", "100");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_SQLq_Cl, "Cleanspool queue", "00FFFF", "MAX", "LINE1", true))
			->setAdjust("*", "100");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_SQLq_H, "Http queue", "999966", "MAX", "LINE1", true))
			->setAdjust("*", "100");
	ch->addSeriesGroup(RRD_CHART_SERIES_SQLq, g);
	
	// * PS
	ch = rrd_charts.addChart(RRD_CHART_PS, "Packet Counter");
	ch->setStdDb();
	ch->setVerticalLabel("number of packets");
	ch->addValue(RRD_VALUE_PS_C, "calls/second", "0000FF", 0, 1000000);
	ch->addValue(RRD_VALUE_PS_S0, "valid SIP packets/second", "00FF00", 0, 1000000);
	ch->addValue(RRD_VALUE_PS_S1, "SIP packets/second", "FF0000", 0, 1000000);
	ch->addValue(RRD_VALUE_PS_SR, "SIP REG packets/second", "FF00FF", 0, 1000000);
	ch->addValue(RRD_VALUE_PS_SM, "SIP MES packets/second", "FFFF00", 0, 1000000);
	ch->addValue(RRD_VALUE_PS_R, "RTP packets/second", "00FFFF", 0, 100000000);
	ch->addValue(RRD_VALUE_PS_A, "all packets/second", "999966", 0, 100000000);
	// ** PSC
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("Calls counter");
	g->setVerticalLabel("number of calls");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_PS_C, "calls/second", "0000FF", "MAX", "LINE1", true));
	ch->addSeriesGroup(RRD_CHART_SERIES_PSC, g);
	// ** PSS
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("SIP packets counter");
	g->setVerticalLabel("number of packets");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_PS_S0, "valid SIP packets/second", "00FF00", "MAX", "LINE1", true));
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_PS_S1, "SIP packets/second", "FF0000", "MAX", "LINE1", true));
	ch->addSeriesGroup(RRD_CHART_SERIES_PSS, g);
	// ** PSSR
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("SIP register packets counter");
	g->setVerticalLabel("number of packets");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_PS_SR, "SIP REG packets/second", "FF00FF", "MAX", "LINE1", true));
	ch->addSeriesGroup(RRD_CHART_SERIES_PSSR, g);
	// ** PSSM
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("SIP message packets counter");
	g->setVerticalLabel("number of packets");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_PS_SM, "SIP MES packets/second", "FFFF00", "MAX", "LINE1", true));
	ch->addSeriesGroup(RRD_CHART_SERIES_PSSM, g);
	// ** PSR
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("RTP packets counter");
	g->setVerticalLabel("number of packets");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_PS_R, "RTP packets/second", "00FFFF", "MAX", "LINE1", true));
	ch->addSeriesGroup(RRD_CHART_SERIES_PSR, g);
	// ** PSA
	g = new FILE_LINE(0) RrdChartSeriesGroup;
	g->setName("ALL packets counter");
	g->setVerticalLabel("number of packets");
	g->addSeries(new FILE_LINE(0) RrdChartSeries(RRD_VALUE_PS_A, "all packets/second", "999966", "MAX", "LINE1", true));
	ch->addSeriesGroup(RRD_CHART_SERIES_PSA, g);
	
	// * LA
	ch = rrd_charts.addChart(RRD_CHART_LA, "Load averages");
	ch->setStdDb();
	ch->setVerticalLabel("Load");
	ch->addValue(RRD_VALUE_LA_m1, "1 minute avg", "00AA00", 0, 256)
			->setPrecision(2, 2);
	ch->addValue(RRD_VALUE_LA_m5, "5 minute avg", "FF8800", 0, 256)
			->setPrecision(2, 2);
	ch->addValue(RRD_VALUE_LA_m15, "15 minute avg", "FF0000", 0, 256)
			->setPrecision(2, 2);
			
	rrd_charts.createMapValues();
}

void rrd_charts_term() {
	if(opt_rrd) {
		rrd_charts.clearCharts();
	}
}

void rrd_charts_create() {
	if(opt_rrd) {
		rrd_charts.createAll();
	}
}

void rrd_charts_alter() {
	if(opt_rrd) {
		rrd_charts.alterAll();
	}
}

void rrd_set_value(const char *valuename, double value, const char *dbname) {
	if(opt_rrd) {
		rrd_charts.setValue(valuename, value, dbname);
	}
}

void rrd_add_value(const char *valuename, double value, const char *dbname) {
	if(opt_rrd) {
		rrd_charts.addValue(valuename, value, dbname);
	}
}

void rrd_update() {
	if(opt_rrd) {
		rrd_charts.updateAll();
		rrd_charts.clearValues();
	}
}

void rrd_add_to_queue(RrdChartQueueItem *queueItem) {
	if(opt_rrd) {
		rrd_charts.addToQueue(queueItem);
	} else {
		queueItem->error = "rrd is disabled";
		queueItem->completed = true;
	}
}

string rrd_chart_graphString(const char *dbname,
			     const char *seriesGroupName,
			     const char *dstfile, const char *fromTime, const char *toTime, 
			     const char *backgroundColor, unsigned resx, unsigned resy, 
			     bool slope, bool icon) {
	return(rrd_charts.graphString(dbname,
				      seriesGroupName,
				      dstfile, fromTime, toTime, 
				      backgroundColor, resx, resy, 
				      slope, icon));
}


void checkRrdVersion(bool silent) {
	extern int opt_rrd;
	if(vm_rrd_version || !opt_rrd) {
		return;
	}
	SimpleBuffer out;
	if(vm_pexec((char*)"rrdtool", &out) && out.size()) {
		string versionString = reg_replace((char*)out, "([0-9]+)\\.([0-9]+)\\.?([0-9]*)", "$1-$2-$3", __FILE__, __LINE__);
		if(!versionString.empty()) {
			int version[3] = { 0, 0, 0 };
			sscanf((char*)versionString.c_str(), "%i-%i-%i", &version[0], &version[1], &version[2]);
			vm_rrd_version = version[0] * 10000 + version[1] * 100 + version[2];
			if(!silent) {
				syslog(LOG_NOTICE, "detected rrdtool version %d", vm_rrd_version);
			}
		} else {
			vm_rrd_version = 1;
			if(!silent) {
				syslog(LOG_NOTICE, "unknown rrdtool version - rrd graph may be wrong");
			}
		}
	} else {
		vm_rrd_version = 0;
		if(!silent) {
			syslog(LOG_NOTICE, "for rrd graph you need install rrdtool");
		}
	}
}
