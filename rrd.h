#ifndef RRD_H
#define RRD_H


#ifndef FREEBSD
#include <values.h>
#endif


#define RRD_CHART_tCPU "2db-tCPU"
#define RRD_VALUE_tCPU_t0 "tCPU-t0"
#define RRD_VALUE_tCPU_t1 "tCPU-t1"
#define RRD_VALUE_tCPU_t2 "tCPU-t2"

#define RRD_CHART_heap "2db-heap"
#define RRD_VALUE_buffer "buffer"
#define RRD_VALUE_ratio "ratio"

#define RRD_CHART_drop "2db-drop"
#define RRD_VALUE_exceeded "exceeded"
#define RRD_VALUE_packets "packets"

#define RRD_CHART_callscounter "3db-callscounter"
#define RRD_VALUE_inv "inv"
#define RRD_VALUE_reg "reg"

#define RRD_CHART_tacCPU "2db-tacCPU"
#define RRD_VALUE_zipCPU "zipCPU"
#define RRD_VALUE_tarCPU "tarCPU"

#define RRD_CHART_memusage "db-memusage"
#define RRD_VALUE_RSS "RSS"

#define RRD_CHART_speedmbs "2db-speedmbs"
#define RRD_VALUE_mbs "mbs"

#define RRD_CHART_SQL "3db-SQL"
#define RRD_CHART_SERIES_SQLf "SQLf"
#define RRD_CHART_SERIES_SQLq "SQLq"
#define RRD_VALUE_SQLf_D "SQLf-D"
#define RRD_VALUE_SQLf_C "SQLf-C"
#define RRD_VALUE_SQLq_C "SQLq-C"
#define RRD_VALUE_SQLq_M "SQLq-M"
#define RRD_VALUE_SQLq_R "SQLq-R"
#define RRD_VALUE_SQLq_Cl "SQLq-Cl"
#define RRD_VALUE_SQLq_H "SQLq-H"

#define RRD_CHART_PS "2db-PS"
#define RRD_CHART_SERIES_PSC "PSC"
#define RRD_CHART_SERIES_PSS "PSS"
#define RRD_CHART_SERIES_PSSR "PSSR"
#define RRD_CHART_SERIES_PSSM "PSSM"
#define RRD_CHART_SERIES_PSR "PSR"
#define RRD_CHART_SERIES_PSA "PSA"
#define RRD_VALUE_PS_C "PS-C"
#define RRD_VALUE_PS_S0 "PS-S0"
#define RRD_VALUE_PS_S1 "PS-S1"
#define RRD_VALUE_PS_SR "PS-SR"
#define RRD_VALUE_PS_SM "PS-SM"
#define RRD_VALUE_PS_R "PS-R"
#define RRD_VALUE_PS_A "PS-A"

#define RRD_CHART_LA "db-LA"
#define RRD_VALUE_LA_m1 "LA-m1"
#define RRD_VALUE_LA_m5 "LA-m5"
#define RRD_VALUE_LA_m15 "LA-m15"

#define RRD_VALUE_UNSET DBL_MAX

#define RRDTOOL_CMD "rrdtool"


#include <list>
#include <map>
#include <deque>

#include "tools.h"


class RrdChartSeries {
public: 
	RrdChartSeries(const char *name, const char *descr, const char *color,
		       const char *fce = NULL, const char *type = NULL, bool legend = true);
	void setFce(const char *fce);
	void setType(const char *type);
	void setLegend(bool legend);
	string graphString(const char *dbFilename);
	RrdChartSeries *setPrecision(unsigned base, unsigned avg);
	RrdChartSeries *setAdjust(const char *adj_operator, const char *adj_number);
protected:
	string name;
	string descr;
	string color;
	string fce;
	string type;
	bool legend;
	unsigned precision;
	unsigned precision_avg;
	string adj_operator;
	string adj_number;
};

class RrdChartValue : public RrdChartSeries {
public:
	RrdChartValue(const char *name, const char *descr, const char *color, double min, double max);
	string createString(unsigned chartStep);
	void setValue(double value, bool add = false);
	string getValue();
private:
	double min;
	double max;
	double value;
friend class RrdChart;
friend class RrdCharts;
};

class RrdChartSeriesGroup {
public:
	~RrdChartSeriesGroup();
	RrdChartSeries *addSeries(RrdChartSeries *series);
	void setName(const char *name);
	void setVerticalLabel(const char *vert_label);
	string graphString(const char *dbFilename);
private:
	list<RrdChartSeries*> series;
	string name;
	string vert_label;
friend class RrdChart;
};

class RrdChartDb {
public:
	RrdChartDb(unsigned step, unsigned rows);
	string createString();
private:
	unsigned steps;
	unsigned rows;
};

class RrdChart {
public:
	RrdChart(const char *dbname, const char *name = NULL, unsigned step = 0);
	virtual ~RrdChart();
	void setVerticalLabel(const char *vert_label);
	RrdChartValue* addValue(const char *name, const char *descr, const char *color, double min, double max);
	RrdChartDb* addDb(unsigned step, unsigned rows);
	void addSeriesGroup(const char *name, RrdChartSeriesGroup *group);
	virtual void setStdDb(unsigned rows = 0);
	string createString();
	void parseStructFromInfo(const char *info, list<RrdChartValue> *values);
	void alterIfNeed(list<RrdChartValue> *valuesFromInfo, class RrdCharts *rrdCharts);
	string infoString();
	string graphString(const char *seriesGroupName,
			   const char *dstfile, const char *fromTime, const char *toTime, 
			   const char *backgroundColor, unsigned resx, unsigned resy, 
			   bool slope, bool icon);
	string updateString();
	string getDbFilename();
	bool setValue(const char *valuename, double value, bool add = false);
	void clearValues();
private:
	double rrd_atof(string value);
private:
	string dbname;
	string name;
	unsigned step;
	string vert_label;
	list<RrdChartValue*> values;
	list<RrdChartDb*> dbs;
	map<string, RrdChartSeriesGroup*> series_groups;
friend class RrdCharts;
};

class RrdChartQueueItem {
public:
	RrdChartQueueItem() {
		completed = false;
	}
public:
	string request_type;
	string rrd_cmd;
	SimpleBuffer result;
	string error;
	volatile bool completed;
};

class RrdCharts {
private:
	struct sValuePtr {
		sValuePtr() {
			value = NULL;
			counter = 0;
		}
		RrdChartValue *value;
		unsigned counter;
	};
public:
	RrdCharts();
	virtual ~RrdCharts();
	RrdChart *addChart(const char *dbname, const char *name = NULL, unsigned step = 0);
	string graphString(const char *dbname,
			   const char *seriesGroupName,
			   const char *dstfile, const char *fromTime, const char *toTime, 
			   const char *backgroundColor, unsigned resx, unsigned resy, 
			   bool slope, bool icon);
	int setValue(const char *valuename, double value, const char *dbname = NULL, bool add = false);
	int addValue(const char *valuename, double value, const char *dbname = NULL);
	void clearCharts();
	void clearValues();
	void createAll(bool skipIfExist = true);
	void alterAll();
	void updateAll();
	bool doRrdCmd(string cmd, string *error = NULL, bool syslogError = false);
	void addToQueue(RrdChartQueueItem *queueItem);
	void startQueueThread();
	static void *queueThread(void *arg);
	void _queueThread();
	void prepareQueueThreadPstatData();
	double getCpuUsageQueueThreadPerc(bool preparePstatData);
	void createMapValues();
	static void rrd_lock() {
		while(__sync_lock_test_and_set(&sync_rrd, 1));
	}
	static void rrd_unlock() {
		__sync_lock_release(&sync_rrd);
	}
private:
	void lock_values() {
		while(__sync_lock_test_and_set(&sync_values, 1));
	}
	void unlock_values() {
		__sync_lock_release(&sync_values);
	}
	void lock_queue() {
		while(__sync_lock_test_and_set(&sync_queue, 1));
	}
	void unlock_queue() {
		__sync_lock_release(&sync_queue);
	}
private:
	list<RrdChart*> charts;
	map<string, sValuePtr> map_values;
	deque<RrdChartQueueItem*> queue;
	volatile int sync_values;
	volatile int sync_queue;
	pthread_t queue_thread_handle;
	int queueThreadId;
	pstat_data queueThreadPstatData[2];
	static volatile int sync_rrd;
};


void rrd_charts_init();
void rrd_charts_term();
void rrd_charts_create();
void rrd_charts_alter();
void rrd_set_value(const char *valuename, double value, const char *dbname = NULL);
void rrd_add_value(const char *valuename, double value, const char *dbname = NULL);
void rrd_update();
string rrd_chart_graphString(const char *dbname,
			     const char *seriesGroupName,
			     const char *dstfile, const char *fromTime, const char *toTime, 
			     const char *backgroundColor, unsigned resx, unsigned resy, 
			     bool slope, bool icon);
void rrd_add_to_queue(RrdChartQueueItem *queueItem);

void checkRrdVersion(bool silent = false);


#endif //RRD_H
