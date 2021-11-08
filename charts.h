#ifndef CHARTS_H
#define CHARTS_H

#include <string>
#include <vector>
#include <queue>
#include <map>

#include "config.h"
#include "sql_db.h"
#include "calltable.h"
#include "tools_global.h"


using namespace std;


enum eChartType {
	_chartType_na		= 0,
	_chartType_total	= 1,
	_chartType_count,
	_chartType_cps,
	_chartType_minutes,
	_chartType_count_perc_short,
	_chartType_response_time_100,
	_chartType_mos,
	_chartType_mos_caller,
	_chartType_mos_called,
	_chartType_mos_xr_avg,
	_chartType_mos_xr_avg_caller,
	_chartType_mos_xr_avg_called,
	_chartType_mos_xr_min,
	_chartType_mos_xr_min_caller,
	_chartType_mos_xr_min_called,
	_chartType_mos_silence_avg,
	_chartType_mos_silence_avg_caller,
	_chartType_mos_silence_avg_called,
	_chartType_mos_silence_min,
	_chartType_mos_silence_min_caller,
	_chartType_mos_silence_min_called,
	_chartType_mos_lqo_caller,
	_chartType_mos_lqo_called,
	_chartType_packet_lost,
	_chartType_packet_lost_caller,
	_chartType_packet_lost_called,
	_chartType_jitter,
	_chartType_delay,
	_chartType_rtcp_avgjitter,
	_chartType_rtcp_maxjitter,
	_chartType_rtcp_avgfr,
	_chartType_rtcp_maxfr,
	_chartType_rtcp_avgrtd,
	_chartType_rtcp_maxrtd,
	_chartType_rtcp_avgrtd_w,
	_chartType_rtcp_maxrtd_w,
	_chartType_silence,
	_chartType_silence_caller,
	_chartType_silence_called,
	_chartType_silence_end,
	_chartType_silence_end_caller,
	_chartType_silence_end_called,
	_chartType_clipping,
	_chartType_clipping_caller,
	_chartType_clipping_called,
	_chartType_pdd,
	_chartType_acd_avg,
	_chartType_acd,
	_chartType_asr_avg,
	_chartType_asr,
	_chartType_ner_avg,
	_chartType_ner,
	_chartType_sipResp,
	_chartType_sipResponse,
	_chartType_sipResponse_base,
	_chartType_codecs,
	_chartType_IP_src,
	_chartType_IP_dst,
	_chartType_domain_src,
	_chartType_domain_dst,
	_chartType_price_customer,
	_chartType_price_operator
};

enum eChartSubType {
	_chartSubType_na = 0,
	_chartSubType_count = 1,
	_chartSubType_value = 2,
	_chartSubType_acd_asr = 3,
	_chartSubType_area = 4,
	_chartSubType_perc = 5
};

enum eChartValueType {
	_chartValueType_na,
	_chartValueType_cnt,
	_chartValueType_sum,
	_chartValueType_min,
	_chartValueType_max,
	_chartValueType_avg,
	_chartValueType_perc95,
	_chartValueType_perc99
};

enum eChartPercType {
	_chartPercType_NA,
	_chartPercType_Asc,
	_chartPercType_Desc 
};

enum eChartTypeUse {
	_chartTypeUse_NA,
	_chartTypeUse_chartCache,
	_chartTypeUse_cdrStat
};

enum eCdrStatType {
	_cdrStatType_NA,
	_cdrStatType_total = 1,
	_cdrStatType_count,
	_cdrStatType_cps,
	_cdrStatType_minutes,
	_cdrStatType_asr = 11,
	_cdrStatType_acd,
	_cdrStatType_ner,
	_cdrStatType_mos = 21,
	_cdrStatType_packet_loss,
	_cdrStatType_jitter,
	_cdrStatType_delay,
	_cdrStatType_price_customer = 31,
	_cdrStatType_price_operator
};

struct sChartTypeDef {
	u_int16_t chartType;
	u_int8_t pool;
	u_int8_t enableZero;
	eChartPercType percType;
	u_int8_t condEqLeft;
	eChartSubType subType;
};

class cChartDataItem {
public:
	cChartDataItem();
	void add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
		 class cChartSeries *series, class cChartIntervalSeriesData *intervalSeries,
		 u_int32_t calldate_from, u_int32_t calldate_to);
	string json(class cChartSeries *series);
	double getValue(class cChartSeries *series, eChartValueType typeValue = _chartValueType_na, bool *null = NULL);
private:
	double getPerc(unsigned perc, eChartPercType type, unsigned values_size = 0);
private:
	volatile double max;
	volatile double min;
	volatile double sum;
	map<float, unsigned> values;
	volatile unsigned int count;
	map<unsigned int, unsigned int> count_intervals;
	volatile unsigned int countAll;
	volatile unsigned int countConected;
	volatile unsigned int sumDuration;
	volatile unsigned int countShort;
};

class cChartDataMultiseriesItem {
public:
	cChartDataMultiseriesItem();
	~cChartDataMultiseriesItem();
	string json(class cChartSeries *series, class cChartIntervalSeriesData *intervalSeries);
private:
	map<int, cChartDataItem*> data;
friend class cChartIntervalSeriesData;
};

class cChartDataPool {
public:
	cChartDataPool();
	~cChartDataPool();
	void createPool(u_int32_t timeFrom, u_int32_t timeTo);
	void initPoolRslt();
	void add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
		 class cChartSeries *series, class cChartInterval *interval,
		 u_int32_t calldate_from, u_int32_t calldate_to);
	string json(class cChartSeries *series, class cChartInterval *interval);
	double getValue(class cChartSeries *series, class cChartInterval *interval, eChartValueType typeValue = _chartValueType_na, bool *null = NULL);
private:
	volatile unsigned int all;
	map<unsigned int, unsigned int> all_intervals;
	volatile unsigned int all_fi;
	volatile unsigned int all_li;
	volatile u_int32_t *pool;
};

class cChartIntervalSeriesData {
public:
	cChartIntervalSeriesData(eChartTypeUse typeUse, class cChartSeries *series = NULL, class cChartInterval *interval = NULL);
	~cChartIntervalSeriesData();
	void prepareData();
	void add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
		 u_int32_t calldate_from, u_int32_t calldate_to);
	double getValue(eChartValueType typeValue = _chartValueType_na, bool *null = NULL);
	string getChartData(class cChartInterval *interval);
	void store(class cChartInterval *interval, vmIP *ip, SqlDb *sqlDb);
	void lock_data() { __SYNC_LOCK(sync_data); }
	void unlock_data() { __SYNC_UNLOCK(sync_data); }
private:
	eChartTypeUse typeUse;
	class cChartSeries *series;
	class cChartInterval *interval;
	cChartDataItem *dataItem;
	cChartDataPool *dataPool;
	cChartDataMultiseriesItem *dataMultiseriesItem;
	vector<string> param;
	map<string_icase, int> param_map;
	volatile int sync_data;
	string last_chart_data;
	u_int32_t created_at_s;
	u_int32_t store_counter;
	volatile u_int32_t counter_add;
friend class cChartDataItem;
friend class cChartDataMultiseriesItem;
friend class cChartInterval;
};

class cChartSeriesId {
public:
	cChartSeriesId(unsigned int id, const char *config_id) {
		this->id = id;
		this->config_id = config_id;
	};
	friend inline const bool operator == (const cChartSeriesId &id1, const cChartSeriesId &id2) {
		return(id1.id == id2.id &&
		       id1.config_id == id2.config_id);
	}
	friend inline const bool operator < (const cChartSeriesId &id1, const cChartSeriesId &id2) {
		return(id1.id < id2.id ? 1 : id1.id > id2.id ? 0 :
		       id1.config_id < id2.config_id);
	}
private:
	unsigned int id;
	string config_id;
friend class cChartInterval;
friend class cChartIntervalSeriesData;
};

class cChartInterval {
public:
	struct sSeriesDataCdrStat {
		sSeriesDataCdrStat() {
			count = 0;
			count_connected = 0;
			store_counter = 0;
			counter_add = 0;
		}
		unsigned count;
		unsigned count_connected;
		map<u_int16_t, cChartIntervalSeriesData*> data;
		u_int32_t store_counter;
		volatile u_int32_t counter_add;
	};
	struct sFieldValue {
		string field;
		double value;
		bool null;
	};
public:
	cChartInterval(eChartTypeUse typeUse);
	~cChartInterval();
	void setInterval(u_int32_t timeFrom, u_int32_t timeTo);
	void setInterval(u_int32_t timeFrom, u_int32_t timeTo, vmIP &ip_src);
	void add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
		 u_int32_t calldate_from, u_int32_t calldate_to,
		 map<class cChartFilter*, bool> *filters_map);
	void add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
		 u_int32_t calldate_from, u_int32_t calldate_to,
		 vmIP &ip_src);
	void store(u_int32_t act_time, u_int32_t real_time, SqlDb *sqlDb);
	void init();
	void init(vmIP &ip_src);
	void clear();
private:
	eChartTypeUse typeUse;
	u_int32_t timeFrom;
	u_int32_t timeTo;
	map<cChartSeriesId, cChartIntervalSeriesData*> seriesData;
	map<vmIP, sSeriesDataCdrStat*> seriesDataCdrStat;
	u_int32_t created_at_real;
	u_int32_t last_use_at_real;
	u_int32_t last_store_at;
	u_int32_t last_store_at_real;
	volatile u_int32_t counter_add;
friend class cChartDataPool;
friend class cChartIntervalSeriesData;
friend class cCharts;
friend class cCdrStat;
};

class cChartFilter {
public:
	cChartFilter(const char *filter, const char *filter_only_sip_ip, const char *filter_without_sip_ip);
	~cChartFilter();
	bool check(sChartsCallData *call, void *callData, bool ip_comb_v6, void *ip_comb, class cFiltersCache *filtersCache, int threadIndex);
private:
	string filter;
	string filter_only_sip_ip;
	string filter_without_sip_ip;
	cEvalFormula::sSplitOperands **filter_s;
	cEvalFormula::sSplitOperands **filter_only_sip_ip_s;
	cEvalFormula::sSplitOperands **filter_without_sip_ip_s;
	bool ip_filter_contain_sipcallerip;
	bool ip_filter_contain_sipcalledip;
	volatile int used_counter;
friend class cChartSeries;
friend class cCharts;
friend class cCdrStat;
};

class cChartNerLsrFilter {
private:
	struct sFilterItem {
		sFilterItem(unsigned lsr) {
			this->lsr = lsr;
		}
		bool check(unsigned lsr) {
			while(log10(lsr) > log10(this->lsr)) {
				lsr = lsr / 10;
			}
			return(lsr == this->lsr);
		}
		unsigned lsr;
	};
public:
	void parseData(JsonItem *jsonData);
	bool check(unsigned lsr) {
		if(b.size()) {
			for(unsigned i = 0; i < b.size(); i++) {
				if(b[i].check(lsr)) {
					return(false);
				}
			}
		}
		if(w.size()) {
			for(unsigned i = 0; i < w.size(); i++) {
				if(w[i].check(lsr)) {
					return(true);
				}
			}
		}
		return(false);
	}
private:
	vector<sFilterItem> w;
	vector<sFilterItem> b;
};

class cChartSeries {
public:
	cChartSeries(unsigned int id, const char *config_id, const char *config, class cCharts *charts);
	cChartSeries(eCdrStatType cdrStatType, const char *chart_type, const char *source_data_name = NULL);
	~cChartSeries();
	void clear();
	bool isIntervals() { 
		return(intervals.size() > 0);
	}
	bool isArea() { 
		return(def.subType == _chartSubType_area); 
	}
	bool checkFilters(map<class cChartFilter*, bool> *filters_map);
private:
	eChartTypeUse typeUse;
	cChartSeriesId series_id;
	string type_source;
	string chartType;
	string sourceDataName;
	vector<double> intervals;
	vector<string> param;
	map<string_icase, int> param_map;
	vector<cChartFilter*> filters;
	cChartNerLsrFilter *ner_lsr_filter;
	sChartTypeDef def;
	volatile int used_counter;
	volatile int terminating;
friend class cChartDataItem;
friend class cChartDataPool;
friend class cChartIntervalSeriesData;
friend class cChartInterval;
friend class cCharts;
friend class cCdrStat;
};

class cCharts {
public:
	cCharts();
	~cCharts();
	void load(SqlDb *sqlDb);
	void reload();
	void initIntervals();
	void clear();
	cChartFilter* getFilter(const char *filter, bool enableAdd, 
				const char *filter_only_sip_ip, const char *filter_without_sip_ip);
	cChartFilter* addFilter(const char *filter, const char *filter_only_sip_ip, const char *filter_without_sip_ip);
	void add(sChartsCallData *call, void *callData, class cFiltersCache *filtersCache, int threadIndex);
	void checkFilters(sChartsCallData *call, void *callData, map<cChartFilter*, bool> *filters, class cFiltersCache *filtersCache, int threadIndex);
	void store(bool forceAll = false);
	void cleanup(bool forceAll = false);
	bool seriesIsUsed(cChartSeriesId series_id);
	void lock_intervals() { __SYNC_LOCK(sync_intervals); }
	void unlock_intervals() { __SYNC_UNLOCK(sync_intervals); }
private:
	map<cChartSeriesId, cChartSeries*> series;
	map<u_int32_t, cChartInterval*> intervals;
	map<string, cChartFilter*> filters;
	volatile u_int32_t first_interval;
	unsigned maxValuesPartsForPercentile;
	unsigned maxLengthSipResponseText;
	unsigned intervalStore;
	unsigned intervalCleanup;
	unsigned intervalExpiration;
	unsigned intervalReload;
	SqlDb *sqlDbStore;
	u_int32_t last_store_at;
	u_int32_t last_store_at_real;
	u_int32_t last_cleanup_at;
	u_int32_t last_cleanup_at_real;
	u_int32_t last_reload_at;
	u_int32_t last_reload_at_real;
	volatile int sync_intervals;
friend class cChartDataItem;
friend class cChartInterval;
friend class Call;
};

class cCdrStat {
public:
	enum eTypeStore {
		_typeStore_na = 0,
		_typeStore_values = 1,
		_typeStore_sources = 2,
		_typeStore_all = 4
	};
	struct sMetrics {
		sMetrics(const char *field, eCdrStatType type_stat, eChartValueType type_value) {
			this->field = field;
			this->type_stat = type_stat;
			this->type_value = type_value;
		}
		string field;
		eCdrStatType type_stat;
		eChartValueType type_value;
	};
public:
	cCdrStat();
	~cCdrStat();
	void init();
	static void init_series(vector<cChartSeries*> *series);
	static void init_metrics(vector<sMetrics> *metrics);
	void clear();
	void add(sChartsCallData *call);
	void store(bool forceAll = false);
	void cleanup(bool forceAll = false);
	void lock_intervals() { __SYNC_LOCK(sync_intervals); }
	void unlock_intervals() { __SYNC_UNLOCK(sync_intervals); }
	static string metrics_db_fields(vector<dstring> *fields = NULL);
	static bool exists_columns_check(const char *column);
	static void exists_columns_clear();
	static void exists_columns_add(const char *column);
private:
	eTypeStore typeStore;
	vector<cChartSeries*> series;
	vector<sMetrics> metrics;
	map<u_int32_t, cChartInterval*> intervals;
	volatile u_int32_t first_interval;
	unsigned maxValuesPartsForPercentile;
	unsigned mainInterval;
	unsigned intervalStore;
	unsigned intervalCleanup;
	unsigned intervalExpiration;
	SqlDb *sqlDbStore;
	u_int32_t last_store_at;
	u_int32_t last_store_at_real;
	u_int32_t last_cleanup_at;
	u_int32_t last_cleanup_at_real;
	volatile int sync_intervals;
	static map<string, bool> exists_columns;
	static volatile int exists_column_sync;
friend class cChartDataItem;
friend class cChartInterval;
};

struct sFilterCache_call_ipv4_comb {
	union {
		struct {
			u_int32_t src;
			u_int32_t dst;
			u_int32_t proxy[2];
		} d;
		u_int64_t a[2];
	} u;
	inline void set(sChartsCallData *call);
	friend inline const bool operator == (const sFilterCache_call_ipv4_comb &d1, const sFilterCache_call_ipv4_comb &d2) {
		return(d1.u.a[0] == d2.u.a[0] &&
		       d1.u.a[1] == d2.u.a[1]);
	}
	friend inline const bool operator < (const sFilterCache_call_ipv4_comb &d1, const sFilterCache_call_ipv4_comb &d2) {
		return(d1.u.a[0] < d2.u.a[0] ? 1 : d1.u.a[0] > d2.u.a[0] ? 0 :
		       d1.u.a[1] < d2.u.a[1]);
	}
};

#if VM_IPV6
struct sFilterCache_call_ipv6_comb {
	vmIP src;
	vmIP dst;
	vmIP proxy[2];
	inline void set(sChartsCallData *call);
	friend inline const bool operator == (const sFilterCache_call_ipv6_comb &d1, const sFilterCache_call_ipv6_comb &d2) {
		return(d1.src == d2.src &&
		       d1.dst == d2.dst &&
		       d1.proxy[0] == d2.proxy[0] &&
		       d1.proxy[1] == d2.proxy[1]);
	}
	friend inline const bool operator < (const sFilterCache_call_ipv6_comb &d1, const sFilterCache_call_ipv6_comb &d2) {
		return(d1.src < d2.src ? 1 : d1.src > d2.src ? 0 :
		       d1.dst < d2.dst ? 1 : d1.dst > d2.dst ? 0 :
		       d1.proxy[0] < d2.proxy[0] ? 1 : d1.proxy[0] > d2.proxy[0] ? 0 :
		       d1.proxy[1] < d2.proxy[1]);
	}
};
#endif

class cFilterCacheItem {
public:
	inline cFilterCacheItem(unsigned limit);
	inline int get(sFilterCache_call_ipv4_comb *ip_comb);
	inline void add(sFilterCache_call_ipv4_comb *ip_comb, bool set);
	#if VM_IPV6
	inline int get(sFilterCache_call_ipv6_comb *ip_comb);
	inline void add(sFilterCache_call_ipv6_comb *ip_comb, bool set);
	#endif
private:
	unsigned limit;
	queue<sFilterCache_call_ipv4_comb> ipv4_comb_queue;
	map<sFilterCache_call_ipv4_comb, bool> ipv4_comb_map;
	#if VM_IPV6
	queue<sFilterCache_call_ipv6_comb> ipv6_comb_queue;
	map<sFilterCache_call_ipv6_comb, bool> ipv6_comb_map;
	#endif
};

class cFiltersCache {
public:
	cFiltersCache(unsigned limit, unsigned limit2);
	~cFiltersCache();
	int get(cChartFilter *filter, sFilterCache_call_ipv4_comb *ip_comb);
	void add(cChartFilter *filter, sFilterCache_call_ipv4_comb *ip_comb, bool set);
	#if VM_IPV6
	int get(cChartFilter *filter, sFilterCache_call_ipv6_comb *ip_comb);
	void add(cChartFilter *filter, sFilterCache_call_ipv6_comb *ip_comb, bool set);
	#endif
private:
	unsigned limit, limit2;
	map<cChartFilter*, cFilterCacheItem*> cache_map;
};


void chartsCacheInit(SqlDb *sqlDb);
void chartsCacheTerm();
bool chartsCacheIsSet();
void chartsCacheAddCall(sChartsCallData *call, void *callData, cFiltersCache *filtersCache, int threadIndex);
void chartsCacheStore(bool forceAll = false);
void chartsCacheCleanup(bool forceAll = false);
void chartsCacheReload();
void chartsCacheInitIntervals();

void cdrStatInit(SqlDb *sqlDb);
void cdrStatTerm();
bool cdrStatIsSet();
void cdrStatAddCall(sChartsCallData *call);
void cdrStatStore(bool forceAll = false);
void cdrStatCleanup(bool forceAll = false);

inline void chartsCacheAndCdrStatAddCall(sChartsCallData *call, void *callData, cFiltersCache *filtersCache, int threadIndex) {
	chartsCacheAddCall(call, callData, filtersCache, threadIndex);
	cdrStatAddCall(call);
}

inline void chartsCacheAndCdrStatStore(bool forceAll = false) {
	chartsCacheStore(forceAll);
	cdrStatStore(forceAll);
}

inline void chartsCacheAndCdrStatCleanup(bool forceAll = false) {
	chartsCacheCleanup(forceAll);
	cdrStatCleanup(forceAll);
}


#endif //CHARTS_H
