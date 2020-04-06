#include "charts.h"


extern int opt_nocdr;
extern int opt_id_sensor;
extern MySqlStore *sqlStore;


static sChartTypeDef ChartTypeDef[] = { 
	{ _chartType_total,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_count,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_cps,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_minutes,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_count_perc_short,		0,	1,	_chartPercType_NA,	0,	_chartSubType_perc },
	{ _chartType_mos,			0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_caller,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_called,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_xr_avg,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_xr_avg_caller,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_xr_avg_called,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_xr_min,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_xr_min_caller,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_xr_min_called,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_silence_avg,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_silence_avg_caller,	0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_silence_avg_called,	0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_silence_min,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_silence_min_caller,	0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_silence_min_called,	0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_lqo_caller,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_mos_lqo_called,		0,	0,	_chartPercType_Desc,	0,	_chartSubType_value },
	{ _chartType_packet_lost,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_packet_lost_caller,	0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_packet_lost_called,	0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_jitter,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_delay,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_rtcp_avgjitter,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_rtcp_maxjitter,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_rtcp_avgfr,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_rtcp_maxfr,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_silence,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_silence_caller,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_silence_called,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_silence_end,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_silence_end_caller,	0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_silence_end_called,	0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_clipping,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_clipping_caller,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_clipping_called,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_pdd,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_acd_avg,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_acd,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_asr_avg,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_asr,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_ner_avg,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_ner,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_sipResp,			0,	1,	_chartPercType_NA,	1,	_chartSubType_count },
	{ _chartType_sipResponse,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_sipResponse_base,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_codecs,			0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_IP_src,			0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_IP_dst,			0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_domain_src,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_domain_dst,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area }
};

static cCharts *chartsCache;


static eChartType chartTypeFromString(string chartType);
static sChartTypeDef getChartTypeDef(eChartType chartType);
static bool cmpValCondEqLeft(const char *val1, const char *val2);


cChartDataItem::cChartDataItem() {
	this->max = 0;
	this->min = -1;
	this->sum = 0;
	this->count = 0;
	this->countAll = 0;
	this->countConected = 0;
	this->sumDuration = 0;
	this->countShort = 0;
}

void cChartDataItem::add(Call *call, 
			 unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			 cChartSeries *series, cChartIntervalSeriesData *intervalSeries,
			 u_int32_t calldate_from, u_int32_t calldate_to) {
	if(series->isArea() ||
	   series->isIntervals() ||
	   series->def.subType == _chartSubType_count) {
		++this->count;
		if(call_interval >= 0) {
			++this->count_intervals[call_interval];
		}
		return;
	}
	if(!(beginInInterval && firstInterval)) {
		return;
	}
	switch(series->def.subType) {
	case _chartSubType_value:
		{
		double value;
		bool value_null;
		call->getChartCacheValue(series->def.chartType, &value, NULL, &value_null, chartsCache);
		if(!value_null && (value || series->def.enableZero)) {
			if(series->def.percType != _chartPercType_NA) {
				this->values.push_back(value);
			}
			if(value > this->max) {
				this->max = value;
			}
			if(this->min == -1 || value < this->min) {
				this->min = value;
			}
			this->sum += value;
			++this->count;
		}
		}
		break;
	case _chartSubType_acd_asr:
		switch(series->def.chartType) {
		case _chartType_acd_avg:
		case _chartType_acd:
		case _chartType_asr_avg:
		case _chartType_asr:
			if(series->def.chartType == _chartType_acd ||
			   series->def.chartType == _chartType_asr ||
			   (firstInterval && beginInInterval)) {
				++this->countAll;
				if(call->connect_time_us) {
					++this->countConected;
					this->sumDuration += call->connect_duration_s();
				}
			}
			break;
		case _chartType_ner:
		case _chartType_ner_avg:
			if(series->def.chartType == _chartType_ner ||
			   (firstInterval && beginInInterval)) {
				++this->countAll;
				double lsr;
				bool lsr_null;
				call->getChartCacheValue(_chartType_sipResp, &lsr, NULL, &lsr_null, chartsCache);
				if(call->connect_time_us ||
				   series->ner_lsr_filter->check((unsigned)lsr)) {
					++this->count;
				}
			}
			break;
		}
		break;
	case _chartSubType_perc:
		switch(series->def.chartType) {
		case _chartType_count_perc_short:
			if(call->connect_time_us) {
				unsigned int connectDuration = call->connect_duration_s();
				++this->countConected;
				if(intervalSeries->param.size() && 
				   connectDuration < (unsigned)atoi(intervalSeries->param[0].c_str())) {
					++this->countShort;
				}
			}
			break;
		}
		break;
	default:
		break;
	}
}

string cChartDataItem::json(cChartSeries *series) {
	unsigned precision_base = 15;
	unsigned precision_vm = 6;
	if(series->isArea() ||
	   series->isIntervals() ||
	   series->def.subType == _chartSubType_count) {
		if(this->count_intervals.size()) {
			stringstream ci_stream;
			ci_stream << '{';
			unsigned counter = 0;
			for(map<volatile unsigned int, volatile unsigned int>::iterator iter = this->count_intervals.begin(); iter != this->count_intervals.end(); iter++) {
				if(counter) {
					ci_stream << ',';
				}
				ci_stream << '"' << iter->first << "\":" << iter->second;
				++counter;
			}
			ci_stream << '}';
			return(ci_stream.str());
		} else if(this->count > 0) {
			return(intToString(this->count));
		} else {
			return("");
		}
	}
	switch(series->def.subType) {
	case _chartSubType_value:
		if(this->count > 0) {
			std::sort(this->values.begin(), this->values.end());
			JsonExport exp;
			exp.add("_", "vcomb");
			exp.add("m", floatToString(this->max, precision_base, true), JsonExport::_number);
			exp.add("i", floatToString(this->min, precision_base, true), JsonExport::_number);
			exp.add("s", floatToString(this->sum, precision_base, true), JsonExport::_number);
			exp.add("c", this->count);
			if(this->values.size()) {
				for(unsigned i = 0; i < 2; i++) {
					int perc = i == 0 ? 95 : 99;
					size_t percIndex = ::min((size_t)round((double)this->values.size() * perc / 100), this->values.size() - 1);
					if(series->def.percType == _chartPercType_Desc) {
						percIndex = this->values.size() - 1 - percIndex;
					}
					exp.add(i == 0 ? "p5" : "p9", floatToString(this->values[percIndex], precision_base, true), JsonExport::_number);
				}
				map<double, unsigned> valuesCount;
				map<double, unsigned> valuesCountReduk;
				for(unsigned i = 0; i < this->values.size(); i++) {
					++valuesCount[this->values[i]];
				}
				map<double, unsigned> *valuesCountRslt;
				if(valuesCount.size() > chartsCache->maxValuesPartsForPercentile && 
				   (valuesCount.size() / chartsCache->maxValuesPartsForPercentile) > 1) {
					unsigned counter = 0;
					double s_v = 0;
					unsigned s_c = 0;
					for(map<double, unsigned>::iterator iter = valuesCount.begin(); iter != valuesCount.end(); iter++) {
						double v_v = iter->first;
						unsigned v_c = iter->second;
						if(counter && !(counter % (valuesCount.size() / chartsCache->maxValuesPartsForPercentile))) {
							double new_v = s_v / s_c;
							valuesCountReduk[new_v] += s_c;
							s_v = 0;
							s_c = 0;
						}
						s_v += v_v * v_c;
						s_c += v_c;
						++counter;
					}
					if(s_c) {
						double new_v = s_v / s_c;
						valuesCountReduk[new_v] += s_c;
					}
					valuesCountRslt = &valuesCountReduk;
				} else {
					valuesCountRslt = &valuesCount;
				}
				stringstream vm_stream;
				vm_stream << setprecision(precision_vm);
				vm_stream << '{';
				unsigned counter = 0;
				for(map<double, unsigned>::iterator iter = valuesCountRslt->begin(); iter != valuesCountRslt->end(); iter++) {
					if(counter) {
						vm_stream << ',';
					}
					vm_stream << '"' << iter->first << "\":" << iter->second;
					++counter;
				}
				vm_stream << '}';
				exp.addJson("vm", vm_stream.str());
			}
			return(exp.getJson());
		}
		break;
	case _chartSubType_acd_asr:
		switch(series->def.chartType) {
		case _chartType_acd_avg:
		case _chartType_acd:
			if(this->countConected) {
				JsonExport exp;
				exp.add("_", "cmp2");
				exp.add("v1", this->sumDuration);
				exp.add("v2", this->countConected);
				return(exp.getJson());
			}
			break;
		case _chartType_asr_avg:
		case _chartType_asr:
			if(this->countConected) {
				JsonExport exp;
				exp.add("_", "cmp2");
				exp.add("v1", this->countConected);
				exp.add("v2", this->countAll);
				return(exp.getJson());
			}
			break;
		case _chartType_ner_avg:
		case _chartType_ner:
			if(this->count) {
				JsonExport exp;
				exp.add("_", "cmp2");
				exp.add("v1", this->count);
				exp.add("v2", this->countAll);
				return(exp.getJson());
			}
			break;
		}
		break;
	case _chartSubType_perc:
		switch(series->def.chartType) {
		case _chartType_count_perc_short:
			if(this->countShort) {
				JsonExport exp;
				exp.add("_", "cmp2");
				exp.add("v1", this->countShort);
				exp.add("v2", this->countConected);
				return(exp.getJson());
			}
			break;
		}
		break;
	default:
		break;
	}
	return("");
}


cChartDataMultiseriesItem::cChartDataMultiseriesItem() {
}

cChartDataMultiseriesItem::~cChartDataMultiseriesItem() {
	for(map<int, cChartDataItem*>::iterator iter = data.begin(); iter != data.end(); iter++) {
		delete iter->second;
	}
}

string cChartDataMultiseriesItem::json(cChartSeries *series, cChartIntervalSeriesData *intervalSeries) {
	if(series->isIntervals()) {
		if(data.size()) {
			stringstream json_stream;
			json_stream << "{\"_\":\"array\",\"a\":[";
			unsigned counter = 0;
			unsigned intervalIndex = 0;
			for(map<int, cChartDataItem*>::iterator iter = data.begin(); iter != data.end(); iter++) {
				while((int)intervalIndex < iter->first) {
					if(counter) {
						json_stream << ",";
					}
					json_stream << 0;
					++intervalIndex;
					++counter;
				}
				if(counter) {
					json_stream << ",";
				}
				string json_str = iter->second->json(series);
				if(!json_str.empty()) {
					json_stream << json_str;
				} else {
					json_stream << 0;
				}
				intervalIndex = iter->first + 1;
				++counter;
			}
			json_stream << "]}";
			return(json_stream.str());
		}
	} else if(series->isArea()) {
		if(data.size()) {
			stringstream json_stream;
			json_stream << "{\"_\":\"area\",";
			unsigned counter = 0;
			for(map<int, cChartDataItem*>::iterator iter = data.begin(); iter != data.end(); iter++) {
				if(counter) {
					json_stream << ",";
				}
				json_stream << '"' << json_string_escape(intervalSeries->param[iter->first].c_str()) << '"' << ':';
				string json_str = iter->second->json(series);
				if(!json_str.empty()) {
					json_stream << json_str;
				} else {
					json_stream << 0;
				}
				++counter;
			}
			json_stream << "}";
			return(json_stream.str());
		}
	} else {
		if(data.size()) {
			stringstream json_stream;
			json_stream << "[";
			unsigned counter = 0;
			for(map<int, cChartDataItem*>::iterator iter = data.begin(); iter != data.end(); iter++) {
				if(counter) {
					json_stream << ",";
				}
				string json_str = iter->second->json(series);
				if(!json_str.empty()) {
					json_stream << json_str;
				} else {
					json_stream << 0;
				}
				++counter;
			}
			json_stream << "]";
			return(json_stream.str());
		}
	}
	return("");
}


cChartDataPool::cChartDataPool() {
	this->all = 0;
	this->all_fi = 0;
	this->all_li = 0;
	this->pool = NULL;
}

cChartDataPool::~cChartDataPool() {
	if(this->pool) {
		delete [] this->pool;
	}
}

void cChartDataPool::createPool(u_int32_t timeFrom, u_int32_t timeTo) {
	this->pool = new FILE_LINE(0) u_int32_t[timeTo - timeFrom + 1];
	memset((void*)this->pool, 0, (timeTo - timeFrom + 1) * sizeof(u_int32_t));
}

void cChartDataPool::add(Call *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			 cChartSeries *series, cChartInterval *interval,
			 u_int32_t calldate_from, u_int32_t calldate_to) {
	unsigned int from, to;
	switch(series->def.chartType) {
	case _chartType_total:
	case _chartType_count:
		from = ::max(calldate_from, interval->timeFrom);
		to = ::min(calldate_to, interval->timeTo - 1);
		++this->all;
		if(call_interval >= 0) {
			++this->all_intervals[call_interval];
		}
		if(beginInInterval && firstInterval) {
			++this->all_fi;
		}
		if(lastInterval) {
			++this->all_li;
		}
		for(unsigned int i = from; i <= to; i++) {
			++this->pool[i - interval->timeFrom];
		}
		break;
	case _chartType_cps:
		from = ::max(calldate_from, interval->timeFrom);
		to = ::min(calldate_to, interval->timeTo - 1);
		++this->all;
		if(beginInInterval && firstInterval) {
			++this->all_fi;
			++this->pool[from - interval->timeFrom];
		}
		break;
	case _chartType_minutes:
		unsigned int connect_duration = call->connect_duration_s();
		unsigned int duration = calldate_to - calldate_from;
		unsigned int calldate_from_connected = calldate_from + (duration - connect_duration);
		from = ::max(calldate_from_connected, interval->timeFrom);
		to = ::min(calldate_to, interval->timeTo);
		//int secondsConnected = to - calldate_from_connected + 1;
		int secondsConnected = to - from;
		if(secondsConnected > 0) {
			 this->all += secondsConnected;
			 for(unsigned int i = from; i <= to; i++) {
				 this->pool[i - interval->timeFrom] += i - calldate_from_connected + 1;
			 }
		}
		break;
	}
}

string cChartDataPool::json(class cChartSeries *series, cChartInterval *interval) {
	unsigned int max = 0;
	unsigned int min = UINT_MAX;
	unsigned int sum = 0;
	unsigned int count = 0;
	string pool_str = "[";
	for(unsigned int i = 0; i < interval->timeTo - interval->timeFrom + 1; i++) {
		if(i) {
			pool_str += ',';
		}
		pool_str += intToString(this->pool[i]);
		if(this->pool[i]) {
			min = min == UINT_MAX ?
			       this->pool[i] :
			       ((unsigned int)this->pool[i] < min ? this->pool[i] : min);
			max =  ((unsigned int)this->pool[i] > max ? this->pool[i] : max);
			sum += this->pool[i];
			++count;
		}
	}
	pool_str += "]";
	if(min == UINT_MAX) {
		min = 0;
	}
	switch(series->def.chartType) {
	case _chartType_total:
		if(this->all_intervals.size() || this->all > 0) {
			JsonExport exp;
			exp.add("_", "sum");
			if(this->all_intervals.size()) {
				string sum = "{";
				unsigned counter = 0;
				for(map<volatile unsigned int, volatile unsigned int>::iterator iter = this->all_intervals.begin(); iter != this->all_intervals.end(); iter++) {
					if(counter) {
						sum += ',';
					}
					sum += '"' + intToString(iter->first) + "\":" + intToString(iter->second);
					++counter;
				}
				sum += "}";
				return(sum);
			} else if(this->all > 0) {
				return(intToString(this->all));
			}
		}
		break;
	case _chartType_count:
	case _chartType_cps:
		if(count > 0) {
			JsonExport exp;
			exp.add("_", "mia");
			exp.add("m", max);
			exp.add("i", min);
			exp.add("s", sum);
			exp.add("c", count);
			exp.addJson("p", pool_str);
			return(exp.getJson());
		}
		break;
	case _chartType_minutes:
		if(this->all > 0) {
			return(floatToString(this->all / 60., 6, true));
		}
		break;
	}
	return("");
}


cChartIntervalSeriesData::cChartIntervalSeriesData(cChartSeries *series, cChartInterval *interval) {
	this->series = series;
	this->interval = interval;
	this->dataItem = NULL;
	this->dataPool = NULL;
	this->dataMultiseriesItem = NULL;
	this->sync_data = 0;
	__SYNC_INC(series->used_counter);
}

cChartIntervalSeriesData::~cChartIntervalSeriesData() {
	if(dataItem) {
		delete dataItem;
	}
	if(dataPool) {
		delete dataPool;
	}
	if(dataMultiseriesItem) {
		delete dataMultiseriesItem;
	}
	__SYNC_DEC(series->used_counter);
}

void cChartIntervalSeriesData::prepareData() {
	if(!series || !interval) {
		return;
	}
	if(series->def.pool) {
		this->dataPool = new FILE_LINE(0) cChartDataPool();
		this->dataPool->createPool(interval->timeFrom, interval->timeTo);
		this->dataItem = NULL;
		this->dataMultiseriesItem = NULL;
	} else {
		if(series->isArea() || series->isIntervals()) {
			this->dataMultiseriesItem = new FILE_LINE(0) cChartDataMultiseriesItem();
			this->dataItem = NULL;
			this->dataPool = NULL;
		} else {
			this->dataItem = new FILE_LINE(0) cChartDataItem();
			this->dataPool = NULL;
			this->dataMultiseriesItem = NULL;
		}
	}
	param = series->param;
	param_map = series->param_map;
}

void cChartIntervalSeriesData::add(Call *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
				   u_int32_t calldate_from, u_int32_t calldate_to) {
	lock_data();
	double value;
	string value_str;
	bool value_null;
	call->getChartCacheValue(series->def.chartType, &value, &value_str, &value_null, chartsCache);
	if(this->series->isIntervals()) {
		if(value_null) {
			unlock_data();
			return;
		}
		unsigned intervalIndex;
		for(intervalIndex = 0; intervalIndex < this->series->intervals.size(); intervalIndex++) {
			if(value < this->series->intervals[intervalIndex]) {
				break;
			}
		}
		if(!this->dataMultiseriesItem->data[intervalIndex]) {
			this->dataMultiseriesItem->data[intervalIndex] = new FILE_LINE(0) cChartDataItem();
		}
		this->dataMultiseriesItem->data[intervalIndex]->add(call, call_interval, firstInterval, lastInterval, beginInInterval,
								    this->series, this,
								    calldate_from, calldate_to);
		unlock_data();
		return;
	} else if(this->series->isArea()) {
		if(value_null) {
			unlock_data();
			return;
		}
		if(value_str.empty()) {
			if(value - floor(value) < 1e-10) {
				value_str = intToString((int)value);
			} else {
				value_str = floatToString(value, 6, true);
			}
		}
		transform(value_str.begin(), value_str.end(), value_str.begin(), ::tolower);
		map<string_icase, int>::iterator iter = this->param_map.find(value_str);
		if(iter == this->param_map.end()) {
			this->param.push_back(value_str);
			this->param_map[value_str] = this->param.size() - 1;
			iter = this->param_map.find(value_str);
		}
		if(iter != this->param_map.end()) {
			int valIndex = iter->second;
			if(!this->dataMultiseriesItem->data[valIndex]) {
				this->dataMultiseriesItem->data[valIndex] = new FILE_LINE(0) cChartDataItem();
			}
			this->dataMultiseriesItem->data[valIndex]->add(call, call_interval, firstInterval, lastInterval, beginInInterval,
								       this->series, this,
								       calldate_from, calldate_to);
		}
		unlock_data();
		return;
	}
	if(this->series->def.chartType != _chartType_count_perc_short &&
	   this->param.size()) {
		if(value_null) {
			unlock_data();
			return;
		}
		if(value_str.empty()) {
			if(value - floor(value) < 1e-10) {
				value_str = intToString((int)value);
			} else {
				value_str = floatToString(value, 6, true);
			}
		}
		if(value_str.empty()) {
			unlock_data();
			return;
		}
		bool ok = false;
		for(size_t i = 0; !ok && (i < this->param.size()); i++) {
			if(this->series->def.condEqLeft) {
				if(cmpValCondEqLeft(value_str.c_str(), this->param[i].c_str())) {
					ok = true;
				}
			} else {
				if(value_str == this->param[i]) {
					ok = true;
				}
			}
		}
		if(!ok) {
			unlock_data();
			return;
		}
	}
	if(this->dataPool) {
		this->dataPool->add(call, call_interval, firstInterval, lastInterval, beginInInterval, 
				    this->series, this->interval,
				    calldate_from, calldate_to);
	}
	if(this->dataItem) {
		this->dataItem->add(call, call_interval, firstInterval, lastInterval, beginInInterval, 
				    this->series, this,
				    calldate_from, calldate_to);
	}
	unlock_data();
}

void cChartIntervalSeriesData::store(cChartInterval *interval, SqlDb *sqlDb) {
	string chart_data;
	if(this->dataItem) {
		chart_data = this->dataItem->json(this->series);
	}
	if(this->dataPool) {
		chart_data = this->dataPool->json(this->series, interval);
	}
	if(this->dataMultiseriesItem) {
		chart_data = this->dataMultiseriesItem->json(this->series, this);
	}
	if(chart_data.empty()) {
		return;
	}
	SqlDb_row cache_row;
	cache_row.add(this->series->id, "series_id");
	cache_row.add("TA_MINUTES", "type");
	cache_row.add(sqlDateTimeString(interval->timeFrom), "from_time");
	cache_row.add(chart_data, "chart_data");
	if(opt_id_sensor > 0) {
		cache_row.add(opt_id_sensor, "id_sensor");
	}
	string insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
			    sqlDb->insertQuery("chart_sniffer_series_cache", cache_row, false, false, true));
	sqlStore->query_lock(insert_str.c_str(), STORE_PROC_ID_CDR_1);
}


cChartInterval::cChartInterval() {
	last_store_at = 0;
	last_store_at_real = getTimeS();
	counter_add = 0;
}

cChartInterval::~cChartInterval() {
	clear();
}

void cChartInterval::setInterval(u_int32_t timeFrom, u_int32_t timeTo) {
	this->timeFrom = timeFrom;
	this->timeTo = timeTo;
	init();
}

void cChartInterval::add(Call *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			 u_int32_t calldate_from, u_int32_t calldate_to,
			 map<cChartSeries*, bool> *filters) {
	for(map<string, cChartIntervalSeriesData*>::iterator iter = this->seriesData.begin(); iter != this->seriesData.end(); iter++) {
		if((*filters)[iter->second->series]) {
			iter->second->add(call, call_interval, firstInterval, lastInterval, beginInInterval, 
					  calldate_from, calldate_to);
		}
	}
	++counter_add;
}

void cChartInterval::store(u_int32_t act_time, u_int32_t real_time, SqlDb *sqlDb) {
	if(counter_add) {
		for(map<string, cChartIntervalSeriesData*>::iterator iter = this->seriesData.begin(); iter != this->seriesData.end(); iter++) {
			iter->second->store(this, sqlDb);
		}
		counter_add = 0;
	}
	this->last_store_at = act_time;
	this->last_store_at_real = real_time;
}

void cChartInterval::init() {
	for(map<string, cChartSeries*>::iterator iter = chartsCache->series.begin(); iter != chartsCache->series.end(); iter++) {
		this->seriesData[iter->second->config_id] = new FILE_LINE(0) cChartIntervalSeriesData(iter->second, this);
		this->seriesData[iter->second->config_id]->prepareData();
		
	}
}

void cChartInterval::clear() {
	for(map<string, cChartIntervalSeriesData*>::iterator iter = this->seriesData.begin(); iter != this->seriesData.end(); iter++) {
		delete iter->second;
	}
	seriesData.clear();
	counter_add = 0;
}


cChartFilter::cChartFilter(const char *filter) {
	this->filter = filter;
}

bool cChartFilter::check(Call *call, void *callData) {
	if(sverb.charts_cache_filters_eval) {
		cout << " * FILTER: " << filter << endl;
	}
	cEvalSqlFormula f(sverb.charts_cache_filters_eval);
	f.setData(call, callData);
	bool rslt = f.e(filter.c_str()).getBool();
	if(sverb.charts_cache_filters_eval) {
		cout << " * RSLT: " << rslt << endl;
	}
	return(rslt);
}


void cChartNerLsrFilter::parseData(JsonItem *jsonData) {
	JsonItem *queryItem = jsonData->getItem("w");
	for(size_t qi = 0; qi < queryItem->getLocalCount(); qi++) {
		w.push_back(atoi(queryItem->getLocalItem(qi)->getLocalValue().c_str()));
	}
	queryItem = jsonData->getItem("ws");
	for(size_t qi = 0; qi < queryItem->getLocalCount(); qi++) {
		w.push_back(atoi(queryItem->getLocalItem(qi)->getLocalValue().c_str()));
	}
	queryItem = jsonData->getItem("b");
	for(size_t qi = 0; qi < queryItem->getLocalCount(); qi++) {
		b.push_back(atoi(queryItem->getLocalItem(qi)->getLocalValue().c_str()));
	}
	queryItem = jsonData->getItem("bs");
	for(size_t qi = 0; qi < queryItem->getLocalCount(); qi++) {
		b.push_back(atoi(queryItem->getLocalItem(qi)->getLocalValue().c_str()));
	}
}


cChartSeries::cChartSeries(unsigned int id, const char *config_id, const char *config) {
	this->id = id;
	this->config_id = config_id;
	JsonItem jsonConfig;
	jsonConfig.parse(config);
	type_source = jsonConfig.getValue("type_source");
	chartType = jsonConfig.getValue("chartType");
	string _intervals = jsonConfig.getValue("intervals");
	if(!_intervals.empty()) {
		JsonItem jsonIntervals;
		jsonIntervals.parse(_intervals);
		for(unsigned i = 0; i < jsonIntervals.getLocalCount(); i++) {
			JsonItem *item = jsonIntervals.getLocalItem(i);
			string intervalsItem = item->getLocalValue();
			intervals.push_back(atof(intervalsItem.c_str()));
		}
	}
	string _param = jsonConfig.getValue("param");
	if(!_param.empty()) {
		JsonItem jsonParam;
		jsonParam.parse(_param);
		for(unsigned i = 0; i < jsonParam.getLocalCount(); i++) {
			JsonItem *item = jsonParam.getLocalItem(i);
			string paramItem = item->getLocalValue();
			param.push_back(paramItem);
			param_map[paramItem] = param.size() - 1;
		}
	}
	string _filters = jsonConfig.getValue("filters");
	if(!_filters.empty()) {
		JsonItem jsonFilters;
		jsonFilters.parse(_filters);
		for(unsigned i = 0; i < jsonFilters.getLocalCount(); i++) {
			JsonItem *item = jsonFilters.getLocalItem(i);
			string filterItem = item->getLocalValue();
			cChartFilter *filter = new FILE_LINE(0) cChartFilter(filterItem.c_str());
			filters.push_back(filter);
		}
	}
	JsonItem *nerLsrFilterItem = jsonConfig.getItem("params/nerLsrFilter");
	if(nerLsrFilterItem) {
		ner_lsr_filter = new FILE_LINE(0) cChartNerLsrFilter;
		ner_lsr_filter->parseData(nerLsrFilterItem);
	} else {
		ner_lsr_filter = NULL;
	}
	def = getChartTypeDef(chartTypeFromString(chartType));
	used_counter = 0;
}

cChartSeries::~cChartSeries() {
	clear();
}

void cChartSeries::clear() {
	for(vector<cChartFilter*>::iterator iter = filters.begin(); iter != filters.end(); iter++) {
		delete *iter;
	}
	filters.clear();
	if(ner_lsr_filter) {
		delete ner_lsr_filter;
		ner_lsr_filter = NULL;
	}
}

bool cChartSeries::checkFilters(Call *call, void *callData) {
	if(!filters.size()) {
		return(true);
	}
	bool rslt = true;
	for(unsigned i = 0; i < filters.size(); i++) {
		if(!filters[i]->check(call, callData)) {
			rslt = false;
			break;
		}
	}
	return(rslt);
}


cCharts::cCharts() {
	first_interval = 0;
	last_interval = 0;
	maxValuesPartsForPercentile = 1000;
	maxLengthSipResponseText = 0; // 24;
	intervalStorePeriod = 2 * 60;
	intervalExpiration = 30 * 60;
	intervalReload = 10 * 60;
	sqlDbStore = NULL;
	last_store_at = 0;
	last_store_at_real = 0;
	last_cleanup_at = 0;
	last_reload_at = 0;
	sync_intervals = 0;
}

cCharts::~cCharts() {
	if(sqlDbStore) {
		delete sqlDbStore;
	}
	clear();
}

void cCharts::load(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	string chart_sniffer_series_table = "chart_sniffer_series";
	if(!sqlDb->existsTable(chart_sniffer_series_table)) {
		if(_createSqlObject) {
			delete sqlDb;
		}
		return;
	}
	map<string, cChartSeries*> series_orphans = series;
	sqlDb->query("SELECT * from " + chart_sniffer_series_table);
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	while((row = rows.fetchRow())) {
		if(series.find(row["config_id"]) != series.end()) {
			series_orphans.erase(row["config_id"]);
		} else {
			cChartSeries *series_i = new FILE_LINE(0) cChartSeries(atol(row["id"].c_str()),
									       row["config_id"].c_str(), 
									       row["config"].c_str());
			series[series_i->config_id] = series_i;
		}
	}
	for(map<string, cChartSeries*>::iterator iter = series_orphans.begin(); iter != series_orphans.end(); iter++) {
		if(!iter->second->used_counter && !seriesIsUsed(iter->first.c_str())) {
			delete iter->second;
			series.erase(iter->first);
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

void cCharts::reload() {
	if(!first_interval) {
		return;
	}
	if(!last_reload_at) {
		last_reload_at = first_interval;
		return;
	}
	if(!(first_interval > last_reload_at && first_interval - last_reload_at >= intervalReload)) {
		return;
	}
	SqlDb *sqlDb = createSqlObject();
	sqlDb->setMaxQueryPass(1);
	load(sqlDb);
	delete sqlDb;
	last_reload_at = first_interval;
}

void cCharts::clear() {
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		delete iter->second;
	}
	intervals.clear();
	for(map<string, cChartSeries*>::iterator iter = series.begin(); iter != series.end(); iter++) {
		delete iter->second;
	}
	series.clear();
}

void cCharts::add(Call *call, void *callData) {
	map<cChartSeries*, bool> filters;
	this->checkFilters(call, callData, &filters);
	u_int64_t calltime_us = call->calltime_us();
	u_int64_t callend_us = call->callend_us();
	u_int64_t calltime_min_s = calltime_us / 1000 / 1000 / 60 * 60;
	u_int64_t callend_min_s = callend_us / 1000 / 1000 / 60 * 60;
	vector<u_int32_t> intervals_begin;
	for(u_int64_t acttime_min_s = calltime_min_s; acttime_min_s <= callend_min_s; acttime_min_s += 60) {
		intervals_begin.push_back(acttime_min_s);
		if(acttime_min_s > first_interval) {
			first_interval = acttime_min_s;
		}
		if(!last_interval || acttime_min_s < last_interval) {
			last_interval = acttime_min_s;
		}
	}
	for(unsigned i = 0; i < intervals_begin.size(); i++) {
		if(intervals_begin[i] <= first_interval &&
		   first_interval - intervals_begin[i] < intervalExpiration) {
			cChartInterval* interval;
			lock_intervals();
			if(!intervals[intervals_begin[i]]) {
				intervals[intervals_begin[i]] = new FILE_LINE(0) cChartInterval();
				intervals[intervals_begin[i]]->setInterval(intervals_begin[i], intervals_begin[i] + 60);
			}
			interval = intervals[intervals_begin[i]];
			unlock_intervals();
			interval->add(call, i, i == 0, i == intervals_begin.size() - 1, i == 0,
				      calltime_us / 1000 / 1000, callend_us / 1000 / 1000,
				      &filters);
		}
	}
}

void cCharts::checkFilters(Call *call, void *callData, map<cChartSeries*, bool> *filters) {
	for(map<string, cChartSeries*>::iterator iter = series.begin(); iter != series.end(); iter++) {
		(*filters)[iter->second] = iter->second->checkFilters(call, callData);
	}
}

void cCharts::store(bool forceAll) {
	if(!first_interval) {
		return;
	}
	u_int32_t real_time = getTimeS();
	if(!forceAll) {
		if(!last_store_at) {
			last_store_at = first_interval;
			last_store_at_real = real_time;
			return;
		}
		if(!((first_interval > last_store_at && first_interval - last_store_at >= intervalStorePeriod) ||
		     (real_time > last_store_at_real && real_time - last_store_at_real >= intervalStorePeriod))) {
			return;
		}
	}
	if(!sqlDbStore) {
		sqlDbStore = createSqlObject();
	}
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		if(forceAll || 
		   (!iter->second->last_store_at && first_interval > iter->first && 
		    first_interval - iter->first >= intervalStorePeriod) ||
		   (iter->second->last_store_at && first_interval > iter->second->last_store_at && 
		    first_interval - iter->second->last_store_at >= intervalStorePeriod) ||
		   (iter->second->last_store_at_real && real_time > iter->second->last_store_at_real && 
		    real_time - iter->second->last_store_at_real >= intervalStorePeriod)) {
			iter->second->store(first_interval, real_time, sqlDbStore);
		}
	}
	last_store_at = first_interval;
	last_store_at_real = real_time;
}

void cCharts::cleanup_intervals() {
	if(!first_interval) {
		return;
	}
	if(!last_cleanup_at) {
		last_cleanup_at = first_interval;
		return;
	}
	if(!(first_interval > last_cleanup_at && first_interval - last_cleanup_at >= intervalStorePeriod)) {
		return;
	}
	lock_intervals();
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); ) {
		if(first_interval > iter->first && first_interval - iter->first > intervalExpiration) {
			delete iter->second;
			intervals.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock_intervals();
	this->last_cleanup_at = first_interval;
}

bool cCharts::seriesIsUsed(const char *config_id) {
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		if(iter->second->seriesData.find(config_id) != iter->second->seriesData.end()) {
			return(true);
		}
	}
	return(false);
}


eChartType chartTypeFromString(string chartType) {
	return(chartType == "TCH_total" ? _chartType_total :
	       chartType == "TCH_count" ? _chartType_count :
	       chartType == "TCH_cps" ? _chartType_cps :
	       chartType == "TCH_minutes" ? _chartType_minutes :
	       chartType == "TCH_count_perc_short" ? _chartType_count_perc_short :
	       chartType == "TCH_mos" ? _chartType_mos :
	       chartType == "TCH_mos_caller" ? _chartType_mos_caller :
	       chartType == "TCH_mos_called" ? _chartType_mos_called :
	       chartType == "TCH_mos_xr_avg" ? _chartType_mos_xr_avg :
	       chartType == "TCH_mos_xr_avg_caller" ? _chartType_mos_xr_avg_caller :
	       chartType == "TCH_mos_xr_avg_called" ? _chartType_mos_xr_avg_called:
	       chartType == "TCH_mos_xr_min" ? _chartType_mos_xr_min :
	       chartType == "TCH_mos_xr_min_caller" ? _chartType_mos_xr_min_caller :
	       chartType == "TCH_mos_xr_min_called" ? _chartType_mos_xr_min_called :
	       chartType == "TCH_mos_silence_avg" ? _chartType_mos_silence_avg :
	       chartType == "TCH_mos_silence_avg_caller" ? _chartType_mos_silence_avg_caller :
	       chartType == "TCH_mos_silence_avg_called" ? _chartType_mos_silence_avg_called:
	       chartType == "TCH_mos_silence_min" ? _chartType_mos_silence_min :
	       chartType == "TCH_mos_silence_min_caller" ? _chartType_mos_silence_min_caller :
	       chartType == "TCH_mos_silence_min_called" ? _chartType_mos_silence_min_called :
	       chartType == "TCH_mos_lqo_caller" ? _chartType_mos_lqo_caller :
	       chartType == "TCH_mos_lqo_called" ? _chartType_mos_lqo_called :
	       chartType == "TCH_packet_lost" ? _chartType_packet_lost :
	       chartType == "TCH_packet_lost_caller" ? _chartType_packet_lost_caller :
	       chartType == "TCH_packet_lost_called" ? _chartType_packet_lost_called :
	       chartType == "TCH_jitter" ? _chartType_jitter :
	       chartType == "TCH_delay" ? _chartType_delay :
	       chartType == "TCH_rtcp_avgjitter" ? _chartType_rtcp_avgjitter :
	       chartType == "TCH_rtcp_maxjitter" ? _chartType_rtcp_maxjitter :
	       chartType == "TCH_rtcp_avgfr" ? _chartType_rtcp_avgfr :
	       chartType == "TCH_rtcp_maxfr" ? _chartType_rtcp_maxfr :
	       chartType == "TCH_silence" ? _chartType_silence :
	       chartType == "TCH_silence_caller" ? _chartType_silence_caller :
	       chartType == "TCH_silence_called" ? _chartType_silence_called :
	       chartType == "TCH_silence_end" ? _chartType_silence_end :
	       chartType == "TCH_silence_end_caller" ? _chartType_silence_end_caller :
	       chartType == "TCH_silence_end_called" ? _chartType_silence_end_called :
	       chartType == "TCH_clipping" ? _chartType_clipping :
	       chartType == "TCH_clipping_caller" ? _chartType_clipping_caller :
	       chartType == "TCH_clipping_called" ? _chartType_clipping_called :
	       chartType == "TCH_pdd" ? _chartType_pdd :
	       chartType == "TCH_acd_avg" ? _chartType_acd_avg :
	       chartType == "TCH_acd" ? _chartType_acd :
	       chartType == "TCH_asr_avg" ? _chartType_asr_avg :
	       chartType == "TCH_asr" ? _chartType_asr :
	       chartType == "TCH_ner_avg" ? _chartType_ner_avg :
	       chartType == "TCH_ner" ? _chartType_ner :
	       chartType == "TCH_sipResp" ? _chartType_sipResp :
	       chartType == "TCH_sipResponse" ? _chartType_sipResponse :
	       chartType == "TCH_sipResponse_base" ? _chartType_sipResponse_base :
	       chartType == "TCH_codecs" ? _chartType_codecs :
	       chartType == "TCH_IP_src" ? _chartType_IP_src :
	       chartType == "TCH_IP_dst" ? _chartType_IP_dst :
	       chartType == "TCH_domain_src" ? _chartType_domain_src :
	       chartType == "TCH_domain_dst" ? _chartType_domain_dst :
	       _chartType_na);
}

sChartTypeDef getChartTypeDef(eChartType chartType) {
	for(size_t i = 0; i < sizeof(ChartTypeDef) / sizeof(ChartTypeDef[0]); i++) {
		if(ChartTypeDef[i].chartType == chartType) {
			return(ChartTypeDef[i]);
		}
	}
	sChartTypeDef def;
	memset(&def, 0, sizeof(def));
	return(def);
}

bool cmpValCondEqLeft(const char *val1, const char *val2) {
	string val2_s = val2;
	while(val2_s.length() && val2_s[val2_s.length() - 1] == 'X') {
		val2_s.resize(val2_s.length() - 1);
	}
	return(val2_s.length() &&
	       !strncmp(val1, val2_s.c_str(), val2_s.length()));
}


void chartsCacheInit(SqlDb *sqlDb) {
	cCharts *_chartsCache = new FILE_LINE(0) cCharts();
	if(!opt_nocdr) {
		_chartsCache->load(sqlDb);
	}
	chartsCache = _chartsCache;
}

void chartsCacheTerm() {
	if(chartsCache) {
		delete chartsCache;
		chartsCache = NULL;
	}
}

bool chartsCacheIsSet() {
	return(chartsCache != NULL);
}

void chartsCacheAddCall(Call *call, void *callData) {
	if(chartsCache) {
		chartsCache->add(call, callData);
	}
}

void chartsCacheStore(bool forceAll) {
	if(chartsCache) {
		chartsCache->store(forceAll);
	}
}

void chartsCacheCleanupIntervals() {
	if(chartsCache) {
		chartsCache->cleanup_intervals();
	}
}

void chartsCacheReload() {
	if(chartsCache) {
		chartsCache->reload();
	}
}
