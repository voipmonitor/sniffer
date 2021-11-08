#include "charts.h"

#include "calltable.h"


extern int opt_nocdr;
extern int opt_id_sensor;
extern MySqlStore *sqlStore;
extern int opt_charts_cache_max_threads;
extern bool opt_cdr_stat_values;
extern bool opt_cdr_stat_sources;
extern int opt_cdr_stat_interval;


static sChartTypeDef ChartTypeDef[] = { 
	{ _chartType_total,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_count,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_cps,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_minutes,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_count_perc_short,		0,	1,	_chartPercType_NA,	0,	_chartSubType_perc },
	{ _chartType_response_time_100,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
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
	{ _chartType_rtcp_avgrtd,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_rtcp_maxrtd,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_rtcp_avgrtd_w,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_rtcp_maxrtd_w,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
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
	{ _chartType_domain_dst,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_price_customer,		0,	1,	_chartPercType_NA,	0,	_chartSubType_value },
	{ _chartType_price_operator,		0,	1,	_chartPercType_NA,	0,	_chartSubType_value }
};

static cCharts *chartsCache;
static cCdrStat *cdrStat;


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

void cChartDataItem::add(sChartsCallData *call, 
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
		if(call->type == sChartsCallData::_call) {
			call->call()->getChartCacheValue(series->def.chartType, &value, NULL, &value_null, chartsCache);
		} else {
			Call::getChartCacheValue(call->tables_content(), series->def.chartType, &value, NULL, &value_null, chartsCache);
		}
		if(!value_null && (value || series->def.enableZero)) {
			if(series->def.percType != _chartPercType_NA) {
				++this->values[value];
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
				if(call->type == sChartsCallData::_call) {
					if(call->call()->connect_time_us) {
						++this->countConected;
						this->sumDuration += call->call()->connect_duration_s();
					}
				} else {
					bool connect_duration_null;
					unsigned int connect_duration = call->tables_content()->getValue_int(Call::_t_cdr, "connect_duration", false, &connect_duration_null);
					if(!connect_duration_null) {
						++this->countConected;
						this->sumDuration += connect_duration;
					}
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
				if(call->type == sChartsCallData::_call) {
					call->call()->getChartCacheValue(_chartType_sipResp, &lsr, NULL, &lsr_null, chartsCache);
					if(call->call()->connect_time_us ||
					   (series->ner_lsr_filter && series->ner_lsr_filter->check((unsigned)lsr))) {
						++this->count;
					}
				} else {
					Call::getChartCacheValue(call->tables_content(), _chartType_sipResp, &lsr, NULL, &lsr_null, chartsCache);
					bool connect_duration_null;
					call->tables_content()->getValue_int(Call::_t_cdr, "connect_duration", false, &connect_duration_null);
					if(!connect_duration_null ||
					   (series->ner_lsr_filter && series->ner_lsr_filter->check((unsigned)lsr))) {
						++this->count;
					}
				}
			}
			break;
		}
		break;
	case _chartSubType_perc:
		switch(series->def.chartType) {
		case _chartType_count_perc_short:
			if(call->type == sChartsCallData::_call) {
				if(call->call()->connect_time_us) {
					unsigned int connect_duration = call->call()->connect_duration_s();
					++this->countConected;
					if(intervalSeries->param.size() && 
					   connect_duration < (unsigned)atoi(intervalSeries->param[0].c_str())) {
						++this->countShort;
					}
				}
			} else {
				bool connect_duration_null;
				unsigned int connect_duration = call->tables_content()->getValue_int(Call::_t_cdr, "connect_duration", false, &connect_duration_null);
				if(!connect_duration_null) {
					++this->countConected;
					if(intervalSeries->param.size() && 
					   connect_duration < (unsigned)atoi(intervalSeries->param[0].c_str())) {
						++this->countShort;
					}
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
			for(map<unsigned int, unsigned int>::iterator iter = this->count_intervals.begin(); iter != this->count_intervals.end(); iter++) {
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
			JsonExport exp;
			exp.add("_", "vcomb");
			exp.add("m", floatToString(this->max, precision_base, true), JsonExport::_number);
			exp.add("i", floatToString(this->min, precision_base, true), JsonExport::_number);
			exp.add("s", floatToString(this->sum, precision_base, true), JsonExport::_number);
			exp.add("c", this->count);
			unsigned values_size = 0;
			for(map<float, unsigned>::iterator iter = this->values.begin(); iter != this->values.end(); iter++) {
				values_size += iter->second;
			}
			if(values_size) {
				for(unsigned i = 0; i < 2; i++) {
					int perc = i == 0 ? 95 : 99;
					float perc_rslt = getPerc(perc, series->def.percType, values_size);
					exp.add(i == 0 ? "p5" : "p9", floatToString(perc_rslt, precision_base, true), JsonExport::_number);
				}
				map<float, unsigned> valuesReduk;
				map<float, unsigned> *valuesRslt;
				unsigned int maxValuesPartsForPercentile = series->typeUse == _chartTypeUse_chartCache ? 
									    chartsCache->maxValuesPartsForPercentile :
									    cdrStat->maxValuesPartsForPercentile;
				if(values_size > maxValuesPartsForPercentile && 
				   (this->values.size() / maxValuesPartsForPercentile) > 1) {
					unsigned counter = 0;
					float s_v = 0;
					unsigned s_c = 0;
					for(map<float, unsigned>::iterator iter = this->values.begin(); iter != this->values.end(); iter++) {
						float v_v = iter->first;
						unsigned v_c = iter->second;
						if(counter && !(counter % (this->values.size() / maxValuesPartsForPercentile))) {
							float new_v = s_v / s_c;
							valuesReduk[new_v] += s_c;
							s_v = 0;
							s_c = 0;
						}
						s_v += v_v * v_c;
						s_c += v_c;
						++counter;
					}
					if(s_c) {
						float new_v = s_v / s_c;
						valuesReduk[new_v] += s_c;
					}
					valuesRslt = &valuesReduk;
				} else {
					valuesRslt = &this->values;
				}
				stringstream vm_stream;
				vm_stream << setprecision(precision_vm);
				vm_stream << '{';
				unsigned counter = 0;
				for(map<float, unsigned>::iterator iter = valuesRslt->begin(); iter != valuesRslt->end(); iter++) {
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
			if(this->countAll) {
				JsonExport exp;
				exp.add("_", "cmp2");
				exp.add("v1", this->countConected);
				exp.add("v2", this->countAll);
				return(exp.getJson());
			}
			break;
		case _chartType_ner_avg:
		case _chartType_ner:
			if(this->countAll) {
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

double cChartDataItem::getValue(class cChartSeries *series, eChartValueType typeValue, bool *null) {
	if(null) {
		*null = this->count ? false : true;
	}
	switch(series->def.subType) {
	case _chartSubType_count:
		return(this->count);
	case _chartSubType_value:
		if(this->count) {
			switch(typeValue) {
			case _chartValueType_cnt:
				return(this->count);
			case _chartValueType_sum:
				return(this->sum);
			case _chartValueType_min:
				return(this->min);
			case _chartValueType_max:
				return(this->max);
			case _chartValueType_avg:
				return((double)this->sum / this->count);
			case _chartValueType_perc95:
				return(getPerc(95, series->def.percType));
			case _chartValueType_perc99:
				return(getPerc(99, series->def.percType));
			default:
				break;
			}
		}
		break;
	case _chartSubType_acd_asr:
		switch(series->def.chartType) {
		case _chartType_acd_avg:
		case _chartType_acd:
			if(this->countConected) {
				return((double)this->sumDuration / this->countConected);
			}
			break;
		case _chartType_asr_avg:
		case _chartType_asr:
			if(this->countAll) {
				return((double)this->countConected / this->countAll * 100);
			}
			break;
		case _chartType_ner_avg:
		case _chartType_ner:
			if(this->countAll) {
				return((double)this->count / this->countAll * 100);
			}
			break;
		}
		break;
	default:
		break;
	}
	if(null) {
		*null = true;
	}
	return(0);
}

double cChartDataItem::getPerc(unsigned perc, eChartPercType type, unsigned values_size) {
	if(!values_size) {
		for(map<float, unsigned>::iterator iter = this->values.begin(); iter != this->values.end(); iter++) {
			values_size += iter->second;
		}
	}
	unsigned percIndex = ::min((unsigned)round((double)values_size * perc / 100), values_size - 1);
	float perc_rslt = 0;
	if(type == _chartPercType_Asc) {
		unsigned count = 0;
		for(map<float, unsigned>::iterator iter = this->values.begin(); iter != this->values.end(); iter++) {
			if(percIndex >= count && percIndex < count + iter->second) {
				perc_rslt = iter->first;
				break;
			}
			count += iter->second;
		}
	} else {
		unsigned count = 0;
		for(map<float, unsigned>::reverse_iterator iter = this->values.rbegin(); iter != this->values.rend(); iter++) {
			if(percIndex >= count && percIndex < count + iter->second) {
				perc_rslt = iter->first;
				break;
			}
			count += iter->second;
		}
	}
	return(perc_rslt);
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
	this->pool = new FILE_LINE(0) u_int32_t[timeTo - timeFrom];
	memset((void*)this->pool, 0, (timeTo - timeFrom) * sizeof(u_int32_t));
}

void cChartDataPool::add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
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
		unsigned int connect_duration;
		if(call->type == sChartsCallData::_call) {
			connect_duration = call->call()->connect_duration_s();
		} else {
			connect_duration = call->tables_content()->getValue_int(Call::_t_cdr, "connect_duration");
		}
		unsigned int duration = calldate_to - calldate_from;
		unsigned int calldate_from_connected = calldate_from + (duration - connect_duration);
		from = ::max(calldate_from_connected, interval->timeFrom);
		to = ::min(calldate_to, interval->timeTo);
		//int secondsConnected = to - calldate_from_connected + 1;
		int secondsConnected = to - from;
		if(secondsConnected > 0) {
			 this->all += secondsConnected;
			 /*
			 for(unsigned int i = from; i <= to; i++) {
				 this->pool[i - interval->timeFrom] += i - calldate_from_connected + 1;
			 }
			 */
		}
		break;
	}
}

string cChartDataPool::json(class cChartSeries *series, cChartInterval *interval) {
	switch(series->def.chartType) {
	case _chartType_total:
		if(this->all_intervals.size() || this->all > 0) {
			JsonExport exp;
			exp.add("_", "sum");
			if(this->all_intervals.size()) {
				string sum = "{";
				unsigned counter = 0;
				for(map<unsigned int, unsigned int>::iterator iter = this->all_intervals.begin(); iter != this->all_intervals.end(); iter++) {
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
	case _chartType_cps: {
		unsigned int max = 0;
		unsigned int min = series->def.chartType == _chartType_cps ? 0 : UINT_MAX;
		unsigned int sum = 0;
		unsigned int count = 0;
		string pool_str = "[";
		for(unsigned int i = 0; i < interval->timeTo - interval->timeFrom; i++) {
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
		if(series->def.chartType == _chartType_cps) {
			count = interval->timeTo - interval->timeFrom;
		}
		if(count > 0) {
			JsonExport exp;
			exp.add("_", "mia");
			exp.add("m", max);
			exp.add("i", min);
			exp.add("s", sum);
			exp.add("c", count);
			exp.addJson("p", pool_str);
			return(exp.getJson());
		} }
		break;
	case _chartType_minutes:
		if(this->all > 0) {
			return(floatToString(this->all / 60., 6, true));
		}
		break;
	}
	return("");
}

double cChartDataPool::getValue(class cChartSeries *series, cChartInterval *interval, eChartValueType typeValue, bool *null) {
	if(null) {
		*null = this->all ? false : true;
	}
	switch(series->def.chartType) {
	case _chartType_total:
		if(this->all) {
			return(this->all_intervals[0]);
		}
		break;
	case _chartType_count:
	case _chartType_cps: {
		unsigned int max = 0;
		unsigned int min = series->def.chartType == _chartType_cps ? 0 : UINT_MAX;
		unsigned int sum = 0;
		unsigned int count = 0;
		for(unsigned int i = 0; i < interval->timeTo - interval->timeFrom; i++) {
			if(this->pool[i]) {
				min = min == UINT_MAX ?
				       this->pool[i] :
				       ((unsigned int)this->pool[i] < min ? this->pool[i] : min);
				max =  ((unsigned int)this->pool[i] > max ? this->pool[i] : max);
				sum += this->pool[i];
				++count;
			}
		}
		if(min == UINT_MAX) {
			min = 0;
		}
		if(series->def.chartType == _chartType_cps) {
			count = interval->timeTo - interval->timeFrom;
		}
		if(count > 0) {
			switch(typeValue) {
			case _chartValueType_cnt:
				return(count);
			case _chartValueType_sum:
				return(sum);
			case _chartValueType_min:
				return(min);
			case _chartValueType_max:
				return(max);
			case _chartValueType_avg:
				return((double)sum / count);
			default:
				break;
			}
		} }
		break;
	case _chartType_minutes:
		if(this->all) {
			return(this->all / 60.);
		}
	default:
		break;
	}
	if(null) {
		*null = true;
	}
	return(0);
}


cChartIntervalSeriesData::cChartIntervalSeriesData(eChartTypeUse typeUse, cChartSeries *series, cChartInterval *interval) {
	this->typeUse = typeUse;
	this->series = series;
	this->interval = interval;
	this->dataItem = NULL;
	this->dataPool = NULL;
	this->dataMultiseriesItem = NULL;
	this->sync_data = 0;
	this->created_at_s = getTimeS();
	this->store_counter = 0;
	this->counter_add = 0;
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

void cChartIntervalSeriesData::add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
				   u_int32_t calldate_from, u_int32_t calldate_to) {
	++counter_add;
	lock_data();
	double value;
	string value_str;
	bool value_null;
	if(call->type == sChartsCallData::_call) {
		call->call()->getChartCacheValue(series->def.chartType, &value, &value_str, &value_null, chartsCache);
	} else {
		Call::getChartCacheValue(call->tables_content(), series->def.chartType, &value, &value_str, &value_null, chartsCache);
	}
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

double cChartIntervalSeriesData::getValue(eChartValueType typeValue, bool *null) {
	if(this->dataItem) {
		return(this->dataItem->getValue(series, typeValue, null));
	}
	if(this->dataPool) {
		return(this->dataPool->getValue(series, interval, typeValue, null));
	}
	if(null) {
		*null = true;
	}
	return(0);
}

string cChartIntervalSeriesData::getChartData(cChartInterval *interval) {
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
	return(chart_data);
}

void cChartIntervalSeriesData::store(cChartInterval *interval, vmIP *ip, SqlDb *sqlDb) {
	if(!counter_add) {
		return;
	}
	string chart_data = getChartData(interval);
	if(chart_data.empty() ||
	   chart_data == last_chart_data) {
		return;
	}
	string table_name = typeUse == _chartTypeUse_chartCache ? "chart_sniffer_series_cache" : "cdr_stat_sources";
	string data_column_name = typeUse == _chartTypeUse_chartCache ? "chart_data" : "data";
	last_chart_data = chart_data;
	SqlDb_row cache_row;
	if(typeUse == _chartTypeUse_chartCache) {
		cache_row.add(this->series->series_id.id, "series_id");
		cache_row.add(sqlDateTimeString(interval->timeFrom), "from_time");
		cache_row.add("TA_MINUTES", "type");
	} else if(typeUse == _chartTypeUse_cdrStat) {
		cache_row.add(this->series->series_id.id, "series");
		cache_row.add(sqlDateTimeString(interval->timeFrom), "from_time");
		cache_row.add(*ip, "addr", false, sqlDb, table_name.c_str());
	}
	cache_row.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "sensor_id");
	cache_row.add(sqlDateTimeString(created_at_s), "created_at");
	string insert_str;
	if(!store_counter) {
		cache_row.add(sqlEscapeString(chart_data), data_column_name);
		insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
			     sqlDb->insertQuery(table_name, cache_row, true, false, true));
	} else {
		SqlDb_row cache_row_update;
		cache_row_update.add(sqlEscapeString(chart_data), data_column_name);
		cache_row_update.add(sqlDateTimeString(getTimeS()), "updated_at");
		cache_row_update.add(store_counter  + 1, "updated_counter");
		insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT +
			     sqlDb->insertQuery(table_name, cache_row, true, false, true, &cache_row_update));
	}
	sqlStore->query_lock(insert_str.c_str(), STORE_PROC_ID_CHARTS_CACHE, 0);
	++store_counter;
}


cChartInterval::cChartInterval(eChartTypeUse typeUse) {
	this->typeUse = typeUse;
	u_int32_t real_time = getTimeS();
	created_at_real = real_time;
	last_use_at_real = real_time;
	last_store_at = 0;
	last_store_at_real = real_time;
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

void cChartInterval::setInterval(u_int32_t timeFrom, u_int32_t timeTo, vmIP &ip_src) {
	this->timeFrom = timeFrom;
	this->timeTo = timeTo;
	init(ip_src);
}

void cChartInterval::add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			 u_int32_t calldate_from, u_int32_t calldate_to,
			 map<cChartFilter*, bool> *filters_map) {
	if(typeUse != _chartTypeUse_chartCache) {
		return;
	}
	bool update = false;
	for(map<cChartSeriesId, cChartIntervalSeriesData*>::iterator iter = this->seriesData.begin(); iter != this->seriesData.end(); iter++) {
		if(iter->second->series->checkFilters(filters_map)) {
			iter->second->add(call, call_interval, firstInterval, lastInterval, beginInInterval, 
					  calldate_from, calldate_to);
			++counter_add;
			update = true;
		}
	}
	if(update) {
		last_use_at_real = getTimeS();
	}
}

void cChartInterval::add(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			 u_int32_t calldate_from, u_int32_t calldate_to,
			 vmIP &ip_src) {
	if(typeUse != _chartTypeUse_cdrStat) {
		return;
	}
	bool update = false;
	map<vmIP, sSeriesDataCdrStat*>::iterator iter_ip = this->seriesDataCdrStat.find(ip_src);
	if(iter_ip != this->seriesDataCdrStat.end()) {
		if(beginInInterval && firstInterval) {
			++iter_ip->second->count;
			if(call->type == sChartsCallData::_call) {
				if(call->call()->connect_time_us) {
					++iter_ip->second->count_connected;
				}
			} else {
				bool connect_duration_null;
				call->tables_content()->getValue_int(Call::_t_cdr, "connect_duration", false, &connect_duration_null);
				if(!connect_duration_null) {
					++iter_ip->second->count_connected;
				}
			}
		}
		for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_ip->second->data.begin(); iter_series != iter_ip->second->data.end(); iter_series++) {
			iter_series->second->add(call, call_interval, firstInterval, lastInterval, beginInInterval, 
						 calldate_from, calldate_to);
		}
		update = true;
		++iter_ip->second->counter_add;
	}
	if(update) {
		++counter_add;
		last_use_at_real = getTimeS();
	}
}

void cChartInterval::store(u_int32_t act_time, u_int32_t real_time, SqlDb *sqlDb) {
	if(typeUse == _chartTypeUse_chartCache) {
		if(counter_add) {
			for(map<cChartSeriesId, cChartIntervalSeriesData*>::iterator iter = this->seriesData.begin(); iter != this->seriesData.end(); iter++) {
				iter->second->store(this, NULL, sqlDb);
			}
			counter_add = 0;
		}
	} else if(typeUse == _chartTypeUse_cdrStat) {
		if(counter_add) {
			if(opt_cdr_stat_sources) {
				for(map<vmIP, sSeriesDataCdrStat*>::iterator iter_ip = this->seriesDataCdrStat.begin(); iter_ip != this->seriesDataCdrStat.end(); iter_ip++) {
					for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_ip->second->data.begin(); iter_series != iter_ip->second->data.end(); iter_series++) {
						iter_series->second->store(this, (vmIP*)&iter_ip->first, sqlDb);
					}
				}
			}
			if(opt_cdr_stat_values) {
				for(map<vmIP, sSeriesDataCdrStat*>::iterator iter_ip = this->seriesDataCdrStat.begin(); iter_ip != this->seriesDataCdrStat.end(); iter_ip++) {
					if(iter_ip->second->counter_add) {
						list<sFieldValue> fieldValues;
						unsigned countFieldValuesNotNull = 0;
						for(unsigned metrics_i = 0; metrics_i < cdrStat->metrics.size(); metrics_i++) {
							cCdrStat::sMetrics *metrics = &cdrStat->metrics[metrics_i];
							for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_ip->second->data.begin(); iter_series != iter_ip->second->data.end(); iter_series++) {
								if(metrics->type_stat == iter_series->second->series->series_id.id) {
									sFieldValue fieldValue;
									fieldValue.field = metrics->field;
									fieldValue.value = iter_series->second->getValue(metrics->type_value, &fieldValue.null);
									fieldValues.push_back(fieldValue);
									if(!fieldValue.null) {
										++countFieldValuesNotNull;
									}
								}
							}
						}
						if(countFieldValuesNotNull) {
							string table_name = "cdr_stat_values";
							SqlDb_row cdr_stat_row;
							cdr_stat_row.add(sqlDateTimeString(timeFrom), "from_time");
							cdr_stat_row.add(iter_ip->first, "addr", false, sqlDb, table_name.c_str());
							cdr_stat_row.add(opt_id_sensor > 0 ? opt_id_sensor : 0, "sensor_id");
							cdr_stat_row.add(sqlDateTimeString(created_at_real), "created_at");
							string insert_str;
							if(!iter_ip->second->store_counter) {
								cdr_stat_row.add(iter_ip->second->count, "count_all");
								cdr_stat_row.add(iter_ip->second->count_connected, "count_connected");
								for(list<sFieldValue>::iterator iter = fieldValues.begin(); iter != fieldValues.end(); iter++) {
									if(cCdrStat::exists_columns_check(iter->field.c_str())) {
										cdr_stat_row.add(iter->value, iter->field, iter->null);
									}
								}
								for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_ip->second->data.begin(); iter_series != iter_ip->second->data.end(); iter_series++) {
									if(!iter_series->second->series->sourceDataName.empty() &&
									   cCdrStat::exists_columns_check((iter_series->second->series->sourceDataName + "_source_data").c_str())) {
										string chart_data = iter_series->second->getChartData(this);
										if(!chart_data.empty()) {
											cdr_stat_row.add(chart_data, iter_series->second->series->sourceDataName + "_source_data");
										}
									}
								}
								insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT_GROUP +
									     sqlDb->insertQuery(table_name, cdr_stat_row, true, false, true));
							} else {
								SqlDb_row cdr_stat_row_update;
								cdr_stat_row_update.add(iter_ip->second->count, "count_all");
								cdr_stat_row_update.add(iter_ip->second->count_connected, "count_connected");
								for(list<sFieldValue>::iterator iter = fieldValues.begin(); iter != fieldValues.end(); iter++) {
									if(cCdrStat::exists_columns_check(iter->field.c_str())) {
										cdr_stat_row_update.add(iter->value, iter->field, iter->null);
									}
								}
								for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_ip->second->data.begin(); iter_series != iter_ip->second->data.end(); iter_series++) {
									if(!iter_series->second->series->sourceDataName.empty() &&
									   cCdrStat::exists_columns_check((iter_series->second->series->sourceDataName + "_source_data").c_str())) {
										string chart_data = iter_series->second->getChartData(this);
										if(!chart_data.empty()) {
											cdr_stat_row_update.add(chart_data, iter_series->second->series->sourceDataName + "_source_data");
										}
									}
								}
								cdr_stat_row_update.add(sqlDateTimeString(getTimeS()), "updated_at");
								cdr_stat_row_update.add(iter_ip->second->store_counter  + 1, "updated_counter");
								insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT +
									     sqlDb->insertQuery(table_name, cdr_stat_row, true, false, true, &cdr_stat_row_update));
							}
							sqlStore->query_lock(insert_str.c_str(), STORE_PROC_ID_CHARTS_CACHE, 0);
							++iter_ip->second->store_counter;
						}
						iter_ip->second->counter_add = 0;
					}
				}
			}
			counter_add = 0;
		}
	}
	this->last_store_at = act_time;
	this->last_store_at_real = real_time;
}

void cChartInterval::init() {
	if(typeUse == _chartTypeUse_chartCache) {
		for(map<cChartSeriesId, cChartSeries*>::iterator iter = chartsCache->series.begin(); iter != chartsCache->series.end(); iter++) {
			if(!iter->second->terminating) {
				this->seriesData[iter->second->series_id] = new FILE_LINE(0) cChartIntervalSeriesData(typeUse, iter->second, this);
				this->seriesData[iter->second->series_id]->prepareData();
			}
		}
	}
}

void cChartInterval::init(vmIP &ip_src) {
	if(typeUse == _chartTypeUse_cdrStat) {
		map<vmIP, sSeriesDataCdrStat*>::iterator iter = this->seriesDataCdrStat.find(ip_src);
		if(iter == this->seriesDataCdrStat.end()) {
			sSeriesDataCdrStat *seriesDataItem = new FILE_LINE(0) sSeriesDataCdrStat;
			this->seriesDataCdrStat[ip_src] = seriesDataItem;
			for(unsigned series_i = 0; series_i < cdrStat->series.size(); series_i++) {
				seriesDataItem->data[series_i] = new FILE_LINE(0) cChartIntervalSeriesData(typeUse, cdrStat->series[series_i], this);
				seriesDataItem->data[series_i]->prepareData();
			}
		}
	}
}

void cChartInterval::clear() {
	if(typeUse == _chartTypeUse_chartCache) {
		for(map<cChartSeriesId, cChartIntervalSeriesData*>::iterator iter = this->seriesData.begin(); iter != this->seriesData.end(); iter++) {
			delete iter->second;
		}
		seriesData.clear();
	} else if(typeUse == _chartTypeUse_cdrStat) {
		for(map<vmIP, sSeriesDataCdrStat*>::iterator iter = this->seriesDataCdrStat.begin(); iter != this->seriesDataCdrStat.end(); iter++) {
			for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_2 = iter->second->data.begin(); iter_2 != iter->second->data.end(); iter_2++) {
				delete iter_2->second;
			}
			delete iter->second;
		}
		seriesDataCdrStat.clear();
	}
	counter_add = 0;
}


cChartFilter::cChartFilter(const char *filter, const char *filter_only_sip_ip, const char *filter_without_sip_ip) {
	this->filter = filter;
	this->filter_only_sip_ip = filter_only_sip_ip;
	this->filter_without_sip_ip = filter_without_sip_ip;
	this->filter_s = new FILE_LINE(0) cEvalFormula::sSplitOperands*[opt_charts_cache_max_threads];
	this->filter_only_sip_ip_s = new FILE_LINE(0) cEvalFormula::sSplitOperands*[opt_charts_cache_max_threads];
	this->filter_without_sip_ip_s = new FILE_LINE(0) cEvalFormula::sSplitOperands*[opt_charts_cache_max_threads];
	for(int i = 0; i < opt_charts_cache_max_threads; i++) {
		this->filter_s[i] = NULL;
		this->filter_only_sip_ip_s[i] = NULL;
		this->filter_without_sip_ip_s[i] = NULL;
	}
	ip_filter_contain_sipcallerip = strcasestr(filter_only_sip_ip, "sipcallerip") != NULL;
	ip_filter_contain_sipcalledip = strcasestr(filter_only_sip_ip, "sipcalledip") != NULL;
	used_counter = 0;
}

cChartFilter::~cChartFilter() {
	for(int i = 0; i < opt_charts_cache_max_threads; i++) {
		if(filter_s[i]) {
			delete filter_s[i];
		}
		if(filter_only_sip_ip_s[i]) {
			delete filter_only_sip_ip_s[i];
		}
		if(filter_without_sip_ip_s[i]) {
			delete filter_without_sip_ip_s[i];
		}
	}
	delete [] filter_s;
	delete [] filter_only_sip_ip_s;
	delete [] filter_without_sip_ip_s;
}


#define TEST_CHECK_FILTER 0
#define TEST_FILTER 1

#if TEST_CHECK_FILTER == 1
u_int64_t __cc;
u_int64_t __ss;
u_int64_t __cc2;
u_int64_t __ss2;
#endif

bool cChartFilter::check(sChartsCallData *call, void *callData, bool ip_comb_v6, void *ip_comb, cFiltersCache *filtersCache, int threadIndex) {
 
#if TEST_CHECK_FILTER == 1
 
#if TEST_FILTER == 1
 
	string filter = 
"(1=1) AND ((( ( ( ((cdr.called LIKE '114200%' OR cdr.called LIKE '114260%' OR cdr.called LIKE '14200%' OR cdr.called LIKE '14209%' OR cdr.called LIKE '14260%' OR cdr.called LIKE '14269%' OR cdr.called LIKE '14310%' OR cdr.called LIKE '14319%' OR cdr.called LIKE '131200%' OR cdr.called LIKE '131260%' OR cdr.called LIKE '31200%' OR cdr.called LIKE '31209%' OR cdr.called LIKE '31260%' OR cdr.called LIKE '31269%' OR cdr.called LIKE '31310%' OR cdr.called LIKE '31319%')) ) ) "
"AND"
" ( (((cdr.sipcalledip = inet_aton('200.170.204.162')) OR (cdr.sipcalledip = inet_aton('200.170.204.164')) OR (cdr.sipcalledip = inet_aton('200.170.204.166')))) ) AND ( ( (((cdr.sipcallerip = inet_aton('10.1.0.203')) OR (cdr.sipcallerip = inet_aton('10.1.0.185')) OR (cdr.sipcallerip = inet_aton('10.1.0.170')) OR (cdr.sipcallerip = inet_aton('10.1.0.205')) OR (cdr.sipcallerip = inet_aton('10.1.0.204')) OR (cdr.sipcallerip = inet_aton('10.1.0.206')) OR (cdr.sipcallerip = inet_aton('10.1.0.162')) OR (cdr.sipcallerip = inet_aton('10.1.0.202')) OR (cdr.sipcallerip = inet_aton('10.1.0.163')) OR (cdr.sipcallerip = inet_aton('10.1.0.207')) OR (cdr.sipcallerip = inet_aton('10.1.0.208')) OR (cdr.sipcallerip = inet_aton('10.1.0.45')) OR (cdr.sipcallerip = inet_aton('10.1.0.51')) OR (cdr.sipcallerip = inet_aton('10.1.0.164')) OR (cdr.sipcallerip = inet_aton('10.1.0.165')) OR (cdr.sipcallerip = inet_aton('10.1.0.210')) OR (cdr.sipcallerip = inet_aton('10.1.0.201')) OR (cdr.sipcallerip = inet_aton('10.1.0.209')) OR (cdr.sipcallerip = inet_aton('10.0.0.201')) OR (cdr.sipcallerip = inet_aton('10.0.0.74')) OR (cdr.sipcallerip = inet_aton('10.0.0.134')) OR (cdr.sipcallerip = inet_aton('10.0.0.197')) OR (cdr.sipcallerip = inet_aton('10.0.0.77')) OR (cdr.sipcallerip = inet_aton('10.0.0.32')) OR (cdr.sipcallerip = inet_aton('10.0.0.31')) OR (cdr.sipcallerip = inet_aton('10.0.0.82')) OR (cdr.sipcallerip = inet_aton('10.0.0.120')) OR (cdr.sipcallerip = inet_aton('10.0.0.84')) OR (cdr.sipcallerip = inet_aton('10.0.0.40')) OR (cdr.sipcallerip = inet_aton('10.0.0.41')) OR (cdr.sipcallerip = inet_aton('10.0.0.39')) OR (cdr.sipcallerip = inet_aton('10.0.0.36')) OR (cdr.sipcallerip = inet_aton('10.2.0.31')) OR (cdr.sipcallerip = inet_aton('10.1.0.64')) OR (cdr.sipcallerip = inet_aton('10.1.0.65')) OR (cdr.sipcallerip = inet_aton('10.1.0.66')) OR (cdr.sipcallerip = inet_aton('10.1.0.67')) OR (cdr.sipcallerip = inet_aton('10.1.0.63')) OR (cdr.sipcallerip = inet_aton('10.1.0.68')) OR (cdr.sipcallerip = inet_aton('10.1.0.139')) OR (cdr.sipcallerip = inet_aton('10.1.0.140')) OR (cdr.sipcallerip = inet_aton('10.1.0.141')) OR (cdr.sipcallerip = inet_aton('10.1.0.62')) OR (cdr.sipcallerip = inet_aton('10.1.0.142')))) ) ) )) OR (( ( ( ((cdr.called LIKE '64200%' OR cdr.called LIKE '64209%' OR cdr.called LIKE '64260%' OR cdr.called LIKE '64269%')) ) ) AND ( (((cdr.sipcallerip = inet_aton('200.170.204.162')) OR (cdr.sipcallerip = inet_aton('200.170.204.164')) OR (cdr.sipcallerip = inet_aton('200.170.204.166')))) ) AND ( ( (((cdr.sipcalledip = inet_aton('10.1.0.203')) OR (cdr.sipcalledip = inet_aton('10.1.0.185')) OR (cdr.sipcalledip = inet_aton('10.1.0.170')) OR (cdr.sipcalledip = inet_aton('10.1.0.205')) OR (cdr.sipcalledip = inet_aton('10.1.0.204')) OR (cdr.sipcalledip = inet_aton('10.1.0.206')) OR (cdr.sipcalledip = inet_aton('10.1.0.162')) OR (cdr.sipcalledip = inet_aton('10.1.0.202')) OR (cdr.sipcalledip = inet_aton('10.1.0.163')) OR (cdr.sipcalledip = inet_aton('10.1.0.207')) OR (cdr.sipcalledip = inet_aton('10.1.0.208')) OR (cdr.sipcalledip = inet_aton('10.1.0.45')) OR (cdr.sipcalledip = inet_aton('10.1.0.51')) OR (cdr.sipcalledip = inet_aton('10.1.0.164')) OR (cdr.sipcalledip = inet_aton('10.1.0.165')) OR (cdr.sipcalledip = inet_aton('10.1.0.210')) OR (cdr.sipcalledip = inet_aton('10.1.0.201')) OR (cdr.sipcalledip = inet_aton('10.1.0.209')) OR (cdr.sipcalledip = inet_aton('10.0.0.201')) OR (cdr.sipcalledip = inet_aton('10.0.0.74')) OR (cdr.sipcalledip = inet_aton('10.0.0.134')) OR (cdr.sipcalledip = inet_aton('10.0.0.197')) OR (cdr.sipcalledip = inet_aton('10.0.0.77')) OR (cdr.sipcalledip = inet_aton('10.0.0.32')) OR (cdr.sipcalledip = inet_aton('10.0.0.31')) OR (cdr.sipcalledip = inet_aton('10.0.0.82')) OR (cdr.sipcalledip = inet_aton('10.0.0.120')) OR (cdr.sipcalledip = inet_aton('10.0.0.84')) OR (cdr.sipcalledip = inet_aton('10.0.0.40')) OR (cdr.sipcalledip = inet_aton('10.0.0.41')) OR (cdr.sipcalledip = inet_aton('10.0.0.39')) OR (cdr.sipcalledip = inet_aton('10.0.0.36')) OR (cdr.sipcalledip = inet_aton('10.2.0.31')) OR (cdr.sipcalledip = inet_aton('10.1.0.64')) OR (cdr.sipcalledip = inet_aton('10.1.0.65')) OR (cdr.sipcalledip = inet_aton('10.1.0.66')) OR (cdr.sipcalledip = inet_aton('10.1.0.67')) OR (cdr.sipcalledip = inet_aton('10.1.0.63')) OR (cdr.sipcalledip = inet_aton('10.1.0.68')) OR (cdr.sipcalledip = inet_aton('10.1.0.139')) OR (cdr.sipcalledip = inet_aton('10.1.0.140')) OR (cdr.sipcalledip = inet_aton('10.1.0.141')) OR (cdr.sipcalledip = inet_aton('10.1.0.62')) OR (cdr.sipcalledip = inet_aton('10.1.0.142')))) ) ) )))";

	/*filter =
"( ( (((cdr.sipcallerip = inet_aton('10.1.0.203')) OR (cdr.sipcallerip = inet_aton('10.1.0.185')) OR (cdr.sipcallerip = inet_aton('10.1.0.170')) OR (cdr.sipcallerip = inet_aton('10.1.0.205')) OR (cdr.sipcallerip = inet_aton('10.1.0.204')) OR (cdr.sipcallerip = inet_aton('10.1.0.206')) OR (cdr.sipcallerip = inet_aton('10.1.0.162')) OR (cdr.sipcallerip = inet_aton('10.1.0.202')) OR (cdr.sipcallerip = inet_aton('10.1.0.163')) OR (cdr.sipcallerip = inet_aton('10.1.0.207')) OR (cdr.sipcallerip = inet_aton('10.1.0.208')) OR (cdr.sipcallerip = inet_aton('10.1.0.45')) OR (cdr.sipcallerip = inet_aton('10.1.0.51')) OR (cdr.sipcallerip = inet_aton('10.1.0.164')) OR (cdr.sipcallerip = inet_aton('10.1.0.165')) OR (cdr.sipcallerip = inet_aton('10.1.0.210')) OR (cdr.sipcallerip = inet_aton('10.1.0.201')) OR (cdr.sipcallerip = inet_aton('10.1.0.209')) OR (cdr.sipcallerip = inet_aton('10.0.0.201')) OR (cdr.sipcallerip = inet_aton('10.0.0.74')) OR (cdr.sipcallerip = inet_aton('10.0.0.134')) OR (cdr.sipcallerip = inet_aton('10.0.0.197')) OR (cdr.sipcallerip = inet_aton('10.0.0.77')) OR (cdr.sipcallerip = inet_aton('10.0.0.32')) OR (cdr.sipcallerip = inet_aton('10.0.0.31')) OR (cdr.sipcallerip = inet_aton('10.0.0.82')) OR (cdr.sipcallerip = inet_aton('10.0.0.120')) OR (cdr.sipcallerip = inet_aton('10.0.0.84')) OR (cdr.sipcallerip = inet_aton('10.0.0.40')) OR (cdr.sipcallerip = inet_aton('10.0.0.41')) OR (cdr.sipcallerip = inet_aton('10.0.0.39')) OR (cdr.sipcallerip = inet_aton('10.0.0.36')) OR (cdr.sipcallerip = inet_aton('10.2.0.31')) OR (cdr.sipcallerip = inet_aton('10.1.0.64')) OR (cdr.sipcallerip = inet_aton('10.1.0.65')) OR (cdr.sipcallerip = inet_aton('10.1.0.66')) OR (cdr.sipcallerip = inet_aton('10.1.0.67')) OR (cdr.sipcallerip = inet_aton('10.1.0.63')) OR (cdr.sipcallerip = inet_aton('10.1.0.68')) OR (cdr.sipcallerip = inet_aton('10.1.0.139')) OR (cdr.sipcallerip = inet_aton('10.1.0.140')) OR (cdr.sipcallerip = inet_aton('10.1.0.141')) OR (cdr.sipcallerip = inet_aton('10.1.0.62')) OR (cdr.sipcallerip = inet_aton('10.1.0.142')))) ) )";*/

	/*filter =
"(cdr.sipcallerip = inet_aton('10.1.0.203')) OR (cdr.sipcallerip = inet_aton('10.1.0.185'))";

	filter =
"(cdr.sipcallerip = inet_aton('10.1.0.203'))";*/

	cEvalFormula f(cEvalFormula::_est_sql, sverb.charts_cache_filters_eval);
	f.setSqlData(cEvalFormula::_estd_call, call, callData);

	u_int64_t s,e;
	/*s = getTimeUS();
	for(unsigned i = 0; i < 10000; i++) {
		f.e(filter.c_str()).getBool();
	}
	e = getTimeUS();
	cout << "0: " << floatToString((e - s) / 10000., 3) <<  endl;*/
	
	bool rslt;
	if(!filter_s) {
		filter_s = new FILE_LINE(0) cEvalFormula::sSplitOperands(0);
		rslt = f.e(filter.c_str(), 0, 0, 0, filter_s).getBool();
		unsigned c = 0;
		while(f.e_opt(filter_s)) {
			++c;
		}
		cout << "opt " << c << endl;
	} else {
		rslt = f.e(filter_s).getBool();
	}
	
	s = getTimeUS();
	unsigned l = 1000000;
	for(unsigned i = 0; i < l; i++) {
		f.e(filter_s).getBool();
	}
	e = getTimeUS();
	cout << "1: " << floatToString((e - s) / (double)l, 3) <<  endl;
	
	f.e(filter_s).getBool();
	
	return(rslt);
 
#else
 
	cout << " filter : " << filter << endl;
 
	cEvalFormula f(cEvalFormula::_est_sql, sverb.charts_cache_filters_eval);
	f.setSqlData(cEvalFormula::_estd_call, call, callData);

	u_int64_t s = getTimeUS();
	for(unsigned i = 0; i < 10000; i++) {
		f.e(filter.c_str()).getBool();
	}
	u_int64_t e = getTimeUS();
	cout << "0: " << floatToString((e - s) / 10000., 3) <<  endl;
	__ss += e - s;
	++__cc;
	cout << __cc << " / " << __ss <<  endl;
	
	bool rslt;
	if(!filter_s) {
		filter_s = new FILE_LINE(0) cEvalFormula::sSplitOperands(0);
		rslt = f.e(filter.c_str(), 0, 0, 0, filter_s).getBool();
		while(f.e_opt(filter_s));
	} else {
		rslt = f.e(filter_s).getBool();
	}
	
	s = getTimeUS();
	for(unsigned i = 0; i < 10000; i++) {
		f.e(filter_s).getBool();
	}
	e = getTimeUS();
	cout << "1: " << floatToString((e - s) / 10000., 3) <<  endl;
	__ss2 += e - s;
	++__cc2;
	cout << __cc2 << " / " << __ss2 <<  endl;
	
	return(rslt);

#endif
 
#else
 
	/*
	string f1 = "(1 + 2 * 3) * (1 + 2 * 3)";
	//string f1 = "cdr.duration > 10";
	cEvalFormula::sSplitOperands so;
	cEvalSqlFormula f2(true);
	f2.setData(call, callData);
	cEvalFormula::sValue rslt1 = f2.e(f1.c_str(), 0, 0, 0, &so);
	cout << rslt1.getString() << endl;
	cEvalFormula::sValue rslt2 = f2.e(&so);
	cout << rslt2.getString() << endl;
	cout << "---" << endl;
	*/
	
	//string filter = "((((cdr.sipcallerip = inet_aton('192.168.1.12')) OR (cdr.sipcalledip = inet_aton('192.168.1.12')))))";
	//string filter = "(( ( ( (((cdr.sipcalledip = inet_aton('187.60.52.104')))) ) ) OR cdr.id in (select cdr_id from cdr_proxy where ( ( (((dst = inet_aton('187.60.52.104')))) ) ) ))) AND ( (wvch_sip_response.lastSIPresponse LIKE '%Call Throttled') ) AND cdr.id_sensor = 72";
	//string filter = "(cdr.sipcalledip = inet_aton('187.60.52.104') OR cdr.id in (select cdr_id from cdr_proxy where dst = inet_aton('187.60.52.104'))) AND wvch_sip_response.lastSIPresponse LIKE '%Call Throttled' AND cdr.id_sensor = 72";
	//string filter = "cdr.sipcalledip = inet_aton('187.60.52.104') AND wvch_sip_response.lastSIPresponse LIKE '%Call Throttled' AND cdr.id_sensor = 72";
	//string filter = "cdr.sipcalledip = inet_aton('187.60.52.104') AND wvch_sip_response.lastSIPresponse LIKE '%Call Throttled'";
	//string filter = "cdr.sipcalledip = inet_aton('187.60.52.104')";
	//string filter = "wvch_sip_response.lastSIPresponse LIKE '%Call Throttled'";
	
	//cout << filter << endl;
	
	if(filtersCache) {
		int rsltCache = 
				#if VM_IPV6
				ip_comb_v6 ?
				 filtersCache->get(this, (sFilterCache_call_ipv6_comb*)ip_comb) :
				#endif
				 filtersCache->get(this, (sFilterCache_call_ipv4_comb*)ip_comb);
		switch(rsltCache) {
		case 1:
			if(filter_without_sip_ip.empty()) {
				return(true);
			}
			break;
		case 0:
			return(false);
		case -1:
			cEvalFormula f(cEvalFormula::_est_sql, sverb.charts_cache_filters_eval);
			f.setSqlData(cEvalFormula::_estd_call, call, callData);
			bool rslt;
			if(!filter_only_sip_ip_s[threadIndex]) {
				filter_only_sip_ip_s[threadIndex] = new FILE_LINE(0) cEvalFormula::sSplitOperands(0);
				rslt = f.e(filter_only_sip_ip.c_str(), 0, 0, 0, filter_only_sip_ip_s[threadIndex]).getBool();
				while(f.e_opt(filter_only_sip_ip_s[threadIndex]));
			} else {
				rslt = f.e(filter_only_sip_ip_s[threadIndex]).getBool();
			}
			#if VM_IPV6
			if(ip_comb_v6) {
				filtersCache->add(this, (sFilterCache_call_ipv6_comb*)ip_comb, rslt);
			} else
			#endif
			{
				filtersCache->add(this, (sFilterCache_call_ipv4_comb*)ip_comb, rslt);
			}
			if(!rslt) {
				return(false);
			}
			break;
		}
	}
	
	cEvalFormula f(cEvalFormula::_est_sql, sverb.charts_cache_filters_eval);
	f.setSqlData(cEvalFormula::_estd_call, call, callData);
	bool rslt;
	if(!filter_s[threadIndex]) {
		filter_s[threadIndex] = new FILE_LINE(0) cEvalFormula::sSplitOperands(0);
		if(sverb.charts_cache_filters_eval) {
			cout << " * FILTER: " << filter << endl;
		}
		rslt = f.e(filter.c_str(), 0, 0, 0, filter_s[threadIndex]).getBool();
		while(f.e_opt(filter_s[threadIndex]));
	} else {
		rslt = f.e(filter_s[threadIndex]).getBool();
	}
	if(sverb.charts_cache_filters_eval || sverb.charts_cache_filters_eval_rslt || sverb.charts_cache_filters_eval_rslt_true) {
		if(sverb.charts_cache_filters_eval_rslt_true || rslt) {
			if(sverb.charts_cache_filters_eval_rslt) {
				if(call->type == sChartsCallData::_call) {
					cout << call->call()->call_id;
				} else {
					cout << call->tables_content()->getValue_str(Call::_t_cdr_next, "fbasename");
				}
			}
			cout << " * RSLT: " << rslt << endl;
		}
	}
	
	return(rslt);
	
#endif
	
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


cChartSeries::cChartSeries(unsigned int id, const char *config_id, const char *config, cCharts *charts) :
 series_id(id, config_id) {
	typeUse = _chartTypeUse_chartCache;
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
			string filter_main = item->getValue("main");
			string filter_only_sip_ip = item->getValue("only_sip_ip");
			string filter_without_sip_ip = item->getValue("without_sip_ip");
			cChartFilter *filter = charts->getFilter(filter_main.c_str(), true, filter_only_sip_ip.c_str(), filter_without_sip_ip.c_str());
			__SYNC_INC(filter->used_counter);
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
	terminating = 0;
}

cChartSeries::cChartSeries(eCdrStatType cdrStatType, const char *chart_type, const char *source_data_name) :
 series_id(cdrStatType, "") {
	typeUse = _chartTypeUse_cdrStat;
	if(source_data_name) {
		sourceDataName = source_data_name;
	}
	def = getChartTypeDef(chartTypeFromString(chart_type));
	if(def.subType == _chartSubType_acd_asr &&
	   (def.chartType == _chartType_ner || def.chartType == _chartType_ner_avg)) {
		JsonItem ner_lsr_filter_config;
		ner_lsr_filter_config.parse("{\"w\":[\"603\"],\"ws\":[\"2\",\"3\",\"4\"],\"b\":null,\"bs\":null}");
		ner_lsr_filter = new FILE_LINE(0) cChartNerLsrFilter;
		ner_lsr_filter->parseData(&ner_lsr_filter_config);
	} else {
		ner_lsr_filter = NULL;
	}
	used_counter = 0;
	terminating = 0;
}

cChartSeries::~cChartSeries() {
	clear();
}

void cChartSeries::clear() {
	for(vector<cChartFilter*>::iterator iter = filters.begin(); iter != filters.end(); iter++) {
		__SYNC_DEC((*iter)->used_counter);
	}
	filters.clear();
	if(ner_lsr_filter) {
		delete ner_lsr_filter;
		ner_lsr_filter = NULL;
	}
}

bool cChartSeries::checkFilters(map<cChartFilter*, bool> *filters_map) {
	if(!filters.size()) {
		return(true);
	}
	bool rslt = true;
	for(unsigned i = 0; i < filters.size(); i++) {
		cChartFilter *filter = filters[i];
		if(!(*filters_map)[filter]) {
			rslt = false;
			break;
		}
	}
	return(rslt);
}


cCharts::cCharts() {
	first_interval = 0;
	maxValuesPartsForPercentile = 1000;
	maxLengthSipResponseText = 0; // 24;
	intervalStore = 60;
	intervalCleanup = 2 * 60;
	intervalExpiration = 2 * 60 * 60;
	intervalReload = 10 * 60;
	sqlDbStore = NULL;
	last_store_at = 0;
	last_store_at_real = 0;
	last_cleanup_at = 0;
	last_cleanup_at_real = 0;
	last_reload_at = 0;
	last_reload_at_real = 0;
	sync_intervals = 0;
}

cCharts::~cCharts() {
	if(sqlDbStore) {
		delete sqlDbStore;
	}
	clear();
}

//#define LOAD_FROM 1
//#define LOAD_TO 1000

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
	map<cChartSeriesId, cChartSeries*> series_orphans = series;
	sqlDb->query("SELECT * from " + chart_sniffer_series_table);
	SqlDb_rows rows;
	sqlDb->fetchRows(&rows);
	SqlDb_row row;
	unsigned counter_rows = 0;
	while((row = rows.fetchRow())) {
		++counter_rows;
		#ifdef LOAD_FROM
		if(counter_rows < LOAD_FROM) {
			continue;
		}
		#endif
		cChartSeriesId series_id(atol(row["id"].c_str()), row["config_id"].c_str());
		map<cChartSeriesId, cChartSeries*>::iterator iter = series.find(series_id);
		if(iter != series.end()) {
			series_orphans.erase(series_id);
			iter->second->terminating = false;
		} else {
			cChartSeries *series_i = new FILE_LINE(0) cChartSeries(atol(row["id"].c_str()),
									       row["config_id"].c_str(), 
									       row["config"].c_str(),
									       this);
			series[cChartSeriesId(series_i->series_id)] = series_i;
		}
		#ifdef LOAD_TO
		if(counter_rows > LOAD_TO) {
			break;
		}
		#endif
	}
	for(map<cChartSeriesId, cChartSeries*>::iterator iter = series_orphans.begin(); iter != series_orphans.end(); iter++) {
		if(!iter->second->used_counter && !seriesIsUsed(iter->first)) {
			delete iter->second;
			series.erase(iter->first);
		} else {
			iter->second->terminating = true;
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
	u_int32_t real_time = getTimeS();
	if(!last_reload_at || !last_reload_at_real) {
		last_reload_at = first_interval;
		last_reload_at_real = real_time;
		return;
	}
	if(!((first_interval > last_reload_at && first_interval - last_reload_at >= intervalReload) &&
	     (real_time > last_reload_at_real && real_time - last_reload_at_real >= intervalReload))) {
		return;
	}
	SqlDb *sqlDb = createSqlObject();
	sqlDb->setMaxQueryPass(1);
	load(sqlDb);
	delete sqlDb;
	last_reload_at = first_interval;
	last_reload_at_real = real_time;
}

void cCharts::initIntervals() {
	if(this->first_interval) {
		u_int32_t first_interval = getTimeS() / 60 * 60 + 10 * 60;
		lock_intervals();
		if(this->first_interval < first_interval &&
		   first_interval - this->first_interval < 2 * 60 * 60) {
			while(this->first_interval < first_interval) {
				u_int32_t interval_begin = this->first_interval + 60;
				intervals[interval_begin] = new FILE_LINE(0) cChartInterval(_chartTypeUse_chartCache);
				intervals[interval_begin]->setInterval(interval_begin, interval_begin + 60);
				this->first_interval = interval_begin;
			}
		}
		unlock_intervals();
	}
}

void cCharts::clear() {
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		delete iter->second;
	}
	intervals.clear();
	for(map<cChartSeriesId, cChartSeries*>::iterator iter = series.begin(); iter != series.end(); iter++) {
		delete iter->second;
	}
	series.clear();
	for(map<string, cChartFilter*>::iterator iter = filters.begin(); iter != filters.end(); iter++) {
		delete iter->second;
	}
	filters.clear();
}

cChartFilter* cCharts::getFilter(const char *filter, bool enableAdd,
				 const char *filter_only_sip_ip, const char *filter_without_sip_ip) {
	map<string, cChartFilter*>::iterator iter = filters.find(filter);
	if(iter != filters.end()) {
		return(iter->second);
	}
	if(enableAdd) {
		return(addFilter(filter, filter_only_sip_ip, filter_without_sip_ip));
	}
	return(NULL);
}

cChartFilter* cCharts::addFilter(const char *filter, const char *filter_only_sip_ip, const char *filter_without_sip_ip) {
	cChartFilter *chFilter = new FILE_LINE(0) cChartFilter(filter, filter_only_sip_ip, filter_without_sip_ip);
	filters[filter] = chFilter;
	return(chFilter);
}

void cCharts::add(sChartsCallData *call, void *callData, cFiltersCache *filtersCache, int threadIndex) {
	map<cChartFilter*, bool> filters_map;
	this->checkFilters(call, callData, &filters_map, filtersCache, threadIndex);
	u_int64_t calltime_us;
	u_int64_t callend_us;
	if(call->type == sChartsCallData::_call) {
		calltime_us = call->call()->calltime_us();
		callend_us = call->call()->callend_us();
	} else {
		calltime_us = call->tables_content()->getValue_int(Call::_t_cdr, "calldate");
		callend_us = call->tables_content()->getValue_int(Call::_t_cdr, "callend");
	}
	u_int32_t calltime_s = calltime_us / 1000000;
	u_int32_t callend_s = callend_us / 1000000;
	u_int64_t calltime_min_s = calltime_s / 60 * 60;
	u_int64_t callend_min_s = callend_s / 60 * 60;
	list<u_int32_t> intervals_begin;
	for(u_int64_t acttime_min_s = calltime_min_s; acttime_min_s <= callend_min_s; acttime_min_s += 60) {
		intervals_begin.push_back(acttime_min_s);
	}
	unsigned interval_counter = 0;
	for(list<u_int32_t>::iterator iter = intervals_begin.begin(); iter != intervals_begin.end(); iter++) {
		u_int32_t interval_begin = *iter;
		cChartInterval* interval = NULL;
		lock_intervals();
		interval = intervals[interval_begin];
		if(!interval) {
			if(interval_begin > first_interval) {
				first_interval = interval_begin;
			}
			interval = new FILE_LINE(0) cChartInterval(_chartTypeUse_chartCache);
			interval->setInterval(interval_begin, interval_begin + 60);
			intervals[interval_begin] = interval;
		}
		unlock_intervals();
		interval->add(call, interval_counter, interval_counter == 0, interval_counter == intervals_begin.size() - 1, interval_counter == 0,
			      calltime_s, callend_s,
			      &filters_map);
		++interval_counter;
	}
}

void cCharts::checkFilters(sChartsCallData *call, void *callData, map<cChartFilter*, bool> *filters_map, cFiltersCache *filtersCache, int threadIndex) {
	#if VM_IPV6
	if(useIPv6) {
		sFilterCache_call_ipv6_comb ipv6_comb;
		ipv6_comb.set(call);
		for(map<string, cChartFilter*>::iterator iter = filters.begin(); iter != filters.end(); iter++) {
			(*filters_map)[iter->second] = iter->second->check(call, callData, true, &ipv6_comb, filtersCache, threadIndex);
		}
	} else 
	#endif
	{
		sFilterCache_call_ipv4_comb ipv4_comb;
		ipv4_comb.set(call);
		for(map<string, cChartFilter*>::iterator iter = filters.begin(); iter != filters.end(); iter++) {
			(*filters_map)[iter->second] = iter->second->check(call, callData, false, &ipv4_comb, filtersCache, threadIndex);
		}
	}
}

void cCharts::store(bool forceAll) {
	if(!first_interval) {
		return;
	}
	u_int32_t real_time = getTimeS();
	if(!forceAll) {
		if(!last_store_at || !last_store_at_real) {
			last_store_at = first_interval;
			last_store_at_real = real_time;
			return;
		}
		if(!((first_interval > last_store_at && first_interval - last_store_at >= intervalStore / 2) ||
		     (real_time > last_store_at_real && real_time - last_store_at_real >= intervalStore / 2))) {
			return;
		}
	}
	if(!sqlDbStore) {
		sqlDbStore = createSqlObject();
	}
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		if(forceAll || 
		   (!iter->second->last_store_at && first_interval > iter->first && 
		    first_interval - iter->first >= intervalStore) ||
		   (iter->second->last_store_at && first_interval > iter->second->last_store_at && 
		    first_interval - iter->second->last_store_at >= intervalStore) ||
		   (iter->second->last_store_at_real && real_time > iter->second->last_store_at_real && 
		    real_time - iter->second->last_store_at_real >= intervalStore)) {
			iter->second->store(first_interval, real_time, sqlDbStore);
		}
	}
	last_store_at = first_interval;
	last_store_at_real = real_time;
}

void cCharts::cleanup(bool forceAll) {
	if(!first_interval) {
		return;
	}
	u_int32_t real_time = getTimeS();
	if(!forceAll) {
		if(!last_cleanup_at || !last_cleanup_at_real) {
			last_cleanup_at = first_interval;
			last_cleanup_at_real = real_time;
			return;
		}
		if(!((first_interval > last_cleanup_at && first_interval - last_cleanup_at >= intervalCleanup / 2) ||
		     (real_time > last_cleanup_at_real && real_time - last_cleanup_at_real >= intervalCleanup / 2))) {
			return;
		}
	}
	lock_intervals();
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); ) {
		if(forceAll ||
		   ((first_interval > iter->first && first_interval - iter->first > intervalExpiration) &&
		    (real_time > max(iter->second->created_at_real, iter->second->last_use_at_real) && real_time - max(iter->second->created_at_real, iter->second->last_use_at_real) > intervalExpiration))) {
			delete iter->second;
			intervals.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock_intervals();
	for(map<string, cChartFilter*>::iterator iter = filters.begin(); iter != filters.end(); ) {
		if(!iter->second->used_counter) {
			delete iter->second;
			filters.erase(iter++);
		} else {
			iter++;
		}
	}
	last_cleanup_at = first_interval;
	last_cleanup_at_real = real_time;
}

bool cCharts::seriesIsUsed(cChartSeriesId series_id) {
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		if(iter->second->seriesData.find(series_id) != iter->second->seriesData.end()) {
			return(true);
		}
	}
	return(false);
}


cCdrStat::cCdrStat() {
	init();
	typeStore = _typeStore_all;
	first_interval = 0;
	maxValuesPartsForPercentile = 1000;
	mainInterval = opt_cdr_stat_interval * 60;
	intervalStore = sverb.cdr_stat_interval_store ? sverb.cdr_stat_interval_store : mainInterval / 4;
	intervalCleanup = mainInterval * 2;
	intervalExpiration = 5 * 60 * 60;
	sqlDbStore = NULL;
	last_store_at = 0;
	last_store_at_real = 0;
	last_cleanup_at = 0;
	last_cleanup_at_real = 0;
	sync_intervals = 0;
}

cCdrStat::~cCdrStat() {
	if(sqlDbStore) {
		delete sqlDbStore;
	}
	clear();
}

void cCdrStat::init() {
	init_series(&series);
	init_metrics(&metrics);
}

void cCdrStat::init_series(vector<cChartSeries*> *series) {
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_count, "TCH_count", "cc"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_cps, "TCH_cps", "cps"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_minutes, "TCH_minutes"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_asr, "TCH_asr", "asr"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_acd, "TCH_acd", "acd"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_ner, "TCH_ner", "ner"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_mos, "TCH_mos", "mos"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_packet_loss, "TCH_packet_lost", "packet_loss"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_jitter, "TCH_jitter", "jitter"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_delay, "TCH_delay", "delay"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_price_customer, "TCH_price_customer"));
	series->push_back(new FILE_LINE(0) cChartSeries(_cdrStatType_price_operator, "TCH_price_operator"));
}

void cCdrStat::init_metrics(vector<sMetrics> *metrics) {
	metrics->push_back(sMetrics("cc_avg", _cdrStatType_count, _chartValueType_avg));
	metrics->push_back(sMetrics("cc_min", _cdrStatType_count, _chartValueType_min));
	metrics->push_back(sMetrics("cc_max", _cdrStatType_count, _chartValueType_max));
	metrics->push_back(sMetrics("cps_avg", _cdrStatType_cps, _chartValueType_avg));
	metrics->push_back(sMetrics("cps_min", _cdrStatType_cps, _chartValueType_min));
	metrics->push_back(sMetrics("cps_max", _cdrStatType_cps, _chartValueType_max));
	metrics->push_back(sMetrics("minutes", _cdrStatType_minutes, _chartValueType_max));
	metrics->push_back(sMetrics("asr", _cdrStatType_asr, _chartValueType_na));
	metrics->push_back(sMetrics("acd", _cdrStatType_acd, _chartValueType_na));
	metrics->push_back(sMetrics("ner", _cdrStatType_ner, _chartValueType_na));
	metrics->push_back(sMetrics("mos_avg", _cdrStatType_mos, _chartValueType_avg));
	metrics->push_back(sMetrics("mos_perc95", _cdrStatType_mos, _chartValueType_perc95));
	metrics->push_back(sMetrics("mos_perc99", _cdrStatType_mos, _chartValueType_perc99));
	metrics->push_back(sMetrics("packet_loss_avg", _cdrStatType_packet_loss, _chartValueType_avg));
	metrics->push_back(sMetrics("packet_loss_perc95", _cdrStatType_packet_loss, _chartValueType_perc95));
	metrics->push_back(sMetrics("packet_loss_perc99", _cdrStatType_packet_loss, _chartValueType_perc99));
	metrics->push_back(sMetrics("jitter_avg", _cdrStatType_jitter, _chartValueType_avg));
	metrics->push_back(sMetrics("jitter_perc95", _cdrStatType_jitter, _chartValueType_perc95));
	metrics->push_back(sMetrics("jitter_perc99", _cdrStatType_jitter, _chartValueType_perc99));
	metrics->push_back(sMetrics("delay_avg", _cdrStatType_delay, _chartValueType_avg));
	metrics->push_back(sMetrics("delay_perc95", _cdrStatType_delay, _chartValueType_perc95));
	metrics->push_back(sMetrics("delay_perc99", _cdrStatType_delay, _chartValueType_perc99));
	metrics->push_back(sMetrics("price_customer", _cdrStatType_price_customer, _chartValueType_sum));
	metrics->push_back(sMetrics("price_operator", _cdrStatType_price_operator, _chartValueType_sum));
}

void cCdrStat::clear() {
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		delete iter->second;
	}
	intervals.clear();
	for(vector<cChartSeries*>::iterator iter = series.begin(); iter != series.end(); iter++) {
		delete *iter;
	}
	series.clear();
}

void cCdrStat::add(sChartsCallData *call) {
	u_int64_t callbegin_us;
	u_int64_t callend_us;
	vmIP ip_src;
	if(call->type == sChartsCallData::_call) {
		callbegin_us = call->call()->calltime_us();
		callend_us = call->call()->callend_us();
		ip_src = call->call()->getSipcallerip();
	} else {
		callbegin_us = call->tables_content()->getValue_int(Call::_t_cdr, "calldate");
		callend_us = call->tables_content()->getValue_int(Call::_t_cdr, "callend");
		ip_src = call->tables_content()->getValue_ip(Call::_t_cdr, "sipcallerip");
	}
	u_int32_t callbegin_s = callbegin_us / 1000000;
	u_int32_t callend_s = callend_us / 1000000;
	u_int32_t callbegin_interval_s = callbegin_s / mainInterval * mainInterval;
	u_int32_t callend_interval_s = callend_s / mainInterval * mainInterval;
	unsigned interval_counter = 0;
	for(u_int32_t interval_iter_s = callbegin_interval_s; interval_iter_s <= callend_interval_s; interval_iter_s += mainInterval) {
		cChartInterval* interval = NULL;
		lock_intervals();
		interval = intervals[interval_iter_s];
		if(!interval) {
			if(interval_iter_s > first_interval) {
				first_interval = interval_iter_s;
			}
			interval = new FILE_LINE(0) cChartInterval(_chartTypeUse_cdrStat);
			interval->setInterval(interval_iter_s, interval_iter_s + mainInterval, ip_src);
			intervals[interval_iter_s] = interval;
		} else {
			interval->init(ip_src);
		}
		unlock_intervals();
		interval->add(call, interval_counter, interval_counter == 0, interval_iter_s == callend_interval_s, interval_counter == 0,
			      callbegin_s, callend_s,
			      ip_src);
		++interval_counter;
	}
}

void cCdrStat::store(bool forceAll) {
	if(!first_interval) {
		return;
	}
	u_int32_t real_time = getTimeS();
	if(!forceAll) {
		if(!last_store_at || !last_store_at_real) {
			last_store_at = first_interval;
			last_store_at_real = real_time;
			return;
		}
		if(!((first_interval > last_store_at && first_interval - last_store_at >= intervalStore) ||
		     (real_time > last_store_at_real && real_time - last_store_at_real >= intervalStore))) {
			return;
		}
	}
	if(!sqlDbStore) {
		sqlDbStore = createSqlObject();
	}
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		if(forceAll || 
		   (!iter->second->last_store_at && first_interval > iter->first && 
		    first_interval - iter->first >= intervalStore) ||
		   (iter->second->last_store_at && first_interval > iter->second->last_store_at && 
		    first_interval - iter->second->last_store_at >= intervalStore) ||
		   (iter->second->last_store_at_real && real_time > iter->second->last_store_at_real && 
		    real_time - iter->second->last_store_at_real >= intervalStore)) {
			iter->second->store(first_interval, real_time, sqlDbStore);
		}
	}
	last_store_at = first_interval;
	last_store_at_real = real_time;
}

void cCdrStat::cleanup(bool forceAll) {
	if(!first_interval) {
		return;
	}
	u_int32_t real_time = getTimeS();
	if(!forceAll) {
		if(!last_cleanup_at || !last_cleanup_at_real) {
			last_cleanup_at = first_interval;
			last_cleanup_at_real = real_time;
			return;
		}
		if(!((first_interval > last_cleanup_at && first_interval - last_cleanup_at >= intervalCleanup / 2) ||
		     (real_time > last_cleanup_at_real && real_time - last_cleanup_at_real >= intervalCleanup / 2))) {
			return;
		}
	}
	lock_intervals();
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); ) {
		if(forceAll ||
		   ((first_interval > iter->first && first_interval - iter->first > intervalExpiration) &&
		    (real_time > max(iter->second->created_at_real, iter->second->last_use_at_real) && real_time - max(iter->second->created_at_real, iter->second->last_use_at_real) > intervalExpiration))) {
			delete iter->second;
			intervals.erase(iter++);
		} else {
			iter++;
		}
	}
	unlock_intervals();
	last_cleanup_at = first_interval;
	last_cleanup_at_real = real_time;
}

string cCdrStat::metrics_db_fields(vector<dstring> *fields) {
	vector<dstring> _fields;
	if(!fields) {
		fields = &_fields;
	}
	vector<sMetrics> metrics;
	init_metrics(&metrics);
	vector<cChartSeries*> series;
	init_series(&series);
	fields->push_back(dstring("count_all", "int unsigned"));
	fields->push_back(dstring("count_connected", "int unsigned"));
	for(unsigned i = 0; i < metrics.size(); i++) {
		fields->push_back(dstring(metrics[i].field,
					  metrics[i].type_stat == _cdrStatType_count ||
					  metrics[i].type_stat == _cdrStatType_cps ?
					   "int unsigned" : 
					   "double"));
	}
	for(unsigned i = 0; i < series.size(); i++) {
		if(!series[i]->sourceDataName.empty()) {
			fields->push_back(dstring(series[i]->sourceDataName + "_source_data",
						  "mediumtext"));
		}
		delete series[i];
	}
	string fields_str;
	for(unsigned i = 0; i < fields->size(); i++) {
		fields_str += "`" + (*fields)[i].str[0] + "` " +
			      (*fields)[i].str[1] + ",\n";
	}
	return(fields_str);
}

bool cCdrStat::exists_columns_check(const char *column) {
	bool exists = false;
	__SYNC_LOCK(exists_column_sync);
	map<string, bool>::iterator iter = exists_columns.find(column);
	if(iter != exists_columns.end()) {
		exists = iter->second;
	}
	__SYNC_UNLOCK(exists_column_sync);
	return(exists);
}

void cCdrStat::exists_columns_clear() {
	__SYNC_LOCK(exists_column_sync);
	exists_columns.clear();
	__SYNC_UNLOCK(exists_column_sync);
}

void cCdrStat::exists_columns_add(const char *column) {
	__SYNC_LOCK(exists_column_sync);
	exists_columns[column] = true;
	__SYNC_UNLOCK(exists_column_sync);
}

map<string, bool> cCdrStat::exists_columns;
volatile int cCdrStat::exists_column_sync;


void sFilterCache_call_ipv4_comb::set(sChartsCallData *call) {
	u.a[1] = 0;
	if(call->type == sChartsCallData::_call) {
		u.d.src = call->call()->sipcallerip[0].getIPv4();
		u.d.dst = call->call()->sipcalledip_rslt.getIPv4();
		unsigned proxies_counter = 0;
		for(list<vmIP>::iterator iter = call->call()->proxies.begin(); iter != call->call()->proxies.end(); iter++) {
			u.d.proxy[proxies_counter++] = iter->getIPv4();
			if(proxies_counter == sizeof(u.d.proxy) / sizeof(u.d.proxy[0]) - 1) {
				break;
			}
		}
	} else {
		u.d.src = call->tables_content()->getValue_ip(Call::_t_cdr, "sipcallerip").getIPv4();
		u.d.dst = call->tables_content()->getValue_ip(Call::_t_cdr, "sipcalledip").getIPv4();
		int proxy_count = call->tables_content()->getCountRows(Call::_t_cdr_proxy);
		if(proxy_count > 0) {
			for(int i = 0; i < min((int)(sizeof(u.d.proxy) / sizeof(u.d.proxy[0])), proxy_count); i++) {
				u.d.proxy[i] = call->tables_content()->getValue_ip(Call::_t_cdr_proxy, "dst", NULL, i).getIPv4();
			}
		}
	}
}

#if VM_IPV6
void sFilterCache_call_ipv6_comb::set(sChartsCallData *call) {
	proxy[0].clear();
	proxy[1].clear();
	if(call->type == sChartsCallData::_call) {
		src = call->call()->sipcallerip[0].getIPv6();
		dst = call->call()->sipcalledip_rslt.getIPv6();
		unsigned proxies_counter = 0;
		for(list<vmIP>::iterator iter = call->call()->proxies.begin(); iter != call->call()->proxies.end(); iter++) {
			proxy[proxies_counter++] = *iter;
			if(proxies_counter == sizeof(proxy) / sizeof(proxy[0]) - 1) {
				break;
			}
		}
		while(proxies_counter < sizeof(proxy) / sizeof(proxy[0])) {
			proxy[proxies_counter++].clear();
		}
	} else {
		src = call->tables_content()->getValue_ip(Call::_t_cdr, "sipcallerip");
		dst = call->tables_content()->getValue_ip(Call::_t_cdr, "sipcalledip");
		unsigned proxies_counter = 0;
		int proxy_count = call->tables_content()->getCountRows(Call::_t_cdr_proxy);
		if(proxy_count > 0) {
			while(proxies_counter < min((unsigned)(sizeof(proxy) / sizeof(proxy[0])), (unsigned)proxy_count)) {
				proxy[proxies_counter] = call->tables_content()->getValue_ip(Call::_t_cdr_proxy, "dst", NULL, proxies_counter);
				++proxies_counter;
			}
		}
		while(proxies_counter < sizeof(proxy) / sizeof(proxy[0])) {
			proxy[proxies_counter++].clear();
		}
	}
}
#endif

cFilterCacheItem::cFilterCacheItem(unsigned limit) {
	this->limit = limit;
}

int cFilterCacheItem::get(sFilterCache_call_ipv4_comb *ip_comb) {
	map<sFilterCache_call_ipv4_comb, bool>::iterator iter = ipv4_comb_map.find(*ip_comb);
	if(iter != ipv4_comb_map.end()) {
		return(iter->second);
	}
	return(-1);
}

void cFilterCacheItem::add(sFilterCache_call_ipv4_comb *ip_comb, bool set) {
	while(ipv4_comb_queue.size() >= limit) {
		sFilterCache_call_ipv4_comb e_ip_comb = ipv4_comb_queue.front();
		ipv4_comb_queue.pop();
		ipv4_comb_map.erase(e_ip_comb);
	}
	ipv4_comb_queue.push(*ip_comb);
	ipv4_comb_map[*ip_comb] = set;
}

#if VM_IPV6
int cFilterCacheItem::get(sFilterCache_call_ipv6_comb *ip_comb) {
	map<sFilterCache_call_ipv6_comb, bool>::iterator iter = ipv6_comb_map.find(*ip_comb);
	if(iter != ipv6_comb_map.end()) {
		return(iter->second);
	}
	return(-1);
}

void cFilterCacheItem::add(sFilterCache_call_ipv6_comb *ip_comb, bool set) {
	while(ipv4_comb_queue.size() >= limit) {
		sFilterCache_call_ipv6_comb e_ip_comb = ipv6_comb_queue.front();
		ipv6_comb_queue.pop();
		ipv6_comb_map.erase(e_ip_comb);
	}
	ipv6_comb_queue.push(*ip_comb);
	ipv6_comb_map[*ip_comb] = set;
}
#endif

cFiltersCache::cFiltersCache(unsigned limit, unsigned limit2) {
	this->limit = limit;
	this->limit2 = limit2;
}

cFiltersCache::~cFiltersCache() {
	for(map<cChartFilter*, cFilterCacheItem*>::iterator iter = cache_map.begin(); iter != cache_map.end(); iter++) {
		delete iter->second;
	}
}

int cFiltersCache::get(cChartFilter *filter, sFilterCache_call_ipv4_comb *ip_comb) {
	cFilterCacheItem *cache_item;
	map<cChartFilter*, cFilterCacheItem*>::iterator iter = cache_map.find(filter);
	if(iter != cache_map.end()) {
		cache_item = iter->second;
	} else {
		cache_item = new FILE_LINE(0) cFilterCacheItem(limit);
		cache_map[filter] = cache_item;
	}
	return(cache_item->get(ip_comb));
}

void cFiltersCache::add(cChartFilter *filter, sFilterCache_call_ipv4_comb *ip_comb, bool set) {
	cFilterCacheItem *cache_item;
	map<cChartFilter*, cFilterCacheItem*>::iterator iter = cache_map.find(filter);
	if(iter != cache_map.end()) {
		cache_item = iter->second;
	} else {
		cache_item = new FILE_LINE(0) cFilterCacheItem(limit);
		cache_map[filter] = cache_item;
	}
	cache_item->add(ip_comb, set);
}

#if VM_IPV6
int cFiltersCache::get(cChartFilter *filter, sFilterCache_call_ipv6_comb *ip_comb) {
	cFilterCacheItem *cache_item;
	map<cChartFilter*, cFilterCacheItem*>::iterator iter = cache_map.find(filter);
	if(iter != cache_map.end()) {
		cache_item = iter->second;
	} else {
		cache_item = new FILE_LINE(0) cFilterCacheItem(limit);
		cache_map[filter] = cache_item;
	}
	return(cache_item->get(ip_comb));
}

void cFiltersCache::add(cChartFilter *filter, sFilterCache_call_ipv6_comb *ip_comb, bool set) {
	cFilterCacheItem *cache_item;
	map<cChartFilter*, cFilterCacheItem*>::iterator iter = cache_map.find(filter);
	if(iter != cache_map.end()) {
		cache_item = iter->second;
	} else {
		cache_item = new FILE_LINE(0) cFilterCacheItem(limit);
		cache_map[filter] = cache_item;
	}
	cache_item->add(ip_comb, set);
}
#endif

eChartType chartTypeFromString(string chartType) {
	return(chartType == "TCH_total" ? _chartType_total :
	       chartType == "TCH_count" ? _chartType_count :
	       chartType == "TCH_cps" ? _chartType_cps :
	       chartType == "TCH_minutes" ? _chartType_minutes :
	       chartType == "TCH_count_perc_short" ? _chartType_count_perc_short :
	       chartType == "TCH_response_time_100" ? _chartType_response_time_100 :
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
	       chartType == "TCH_rtcp_avgrtd" ? _chartType_rtcp_avgrtd :
	       chartType == "TCH_rtcp_maxrtd" ? _chartType_rtcp_maxrtd :
	       chartType == "TCH_rtcp_avgrtd_w" ? _chartType_rtcp_avgrtd_w :
	       chartType == "TCH_rtcp_maxrtd_w" ? _chartType_rtcp_maxrtd_w :
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
	       chartType == "TCH_price_customer" ? _chartType_price_customer :
	       chartType == "TCH_price_operator" ? _chartType_price_operator :
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

#define TEST_ADD_CALL 0
#define TEST_ADD_CALL_FILTERS_CACHE 0
#define TEST_ADD_CALL_PASSES_1 10
#define TEST_ADD_CALL_PASSES_2 1

void chartsCacheAddCall(sChartsCallData *call, void *callData, cFiltersCache *filtersCache, int threadIndex) {
	if(chartsCache) {
	 
		/*
		static int _i = 0;
		cout << "*** " << (++_i) << endl;
		*/
	 
#if TEST_ADD_CALL == 1

		cFiltersCache *_filtersCache = NULL;
		#if TEST_ADD_CALL_FILTERS_CACHE
		_filtersCache = filtersCache;
		#endif
	 
		u_int64_t s = getTimeUS();
		for(unsigned i = 0; i < 1; i++) {
	 
			chartsCache->add(call, callData, _filtersCache, threadIndex);
			
		}
		u_int64_t e = getTimeUS();
		cout << "*: " << e - s <<  endl;
		
		for(unsigned p = 0; p < TEST_ADD_CALL_PASSES_1; p++) {
		
		s = getTimeUS();
		for(unsigned i = 0; i < TEST_ADD_CALL_PASSES_2; i++) {
	 
			chartsCache->add(call, callData, _filtersCache, threadIndex);
			
		}
		e = getTimeUS();
		cout << "*: " << e - s <<  endl;
		
		}
		
#else

		chartsCache->add(call, callData, filtersCache, threadIndex);
		
#endif
		
	}
}

void chartsCacheStore(bool forceAll) {
	if(chartsCache) {
		chartsCache->store(forceAll);
	}
}

void chartsCacheCleanup(bool forceAll) {
	if(chartsCache) {
		chartsCache->cleanup(forceAll);
	}
}

void chartsCacheReload() {
	if(chartsCache) {
		chartsCache->reload();
	}
}

void chartsCacheInitIntervals() {
	if(chartsCache) {
		chartsCache->initIntervals();
	}
}


void cdrStatInit(SqlDb *sqlDb) {
	cdrStat = new FILE_LINE(0) cCdrStat();
}

void cdrStatTerm() {
	if(cdrStat) {
		delete cdrStat;
		cdrStat = NULL;
	}
}

bool cdrStatIsSet() {
	return(cdrStat != NULL);
}

void cdrStatAddCall(sChartsCallData *call) {
	if(cdrStat) {
		cdrStat->add(call);
	}
}

void cdrStatStore(bool forceAll) {
	if(cdrStat) {
		cdrStat->store(forceAll);
	}
}

void cdrStatCleanup(bool forceAll) {
	if(cdrStat) {
		cdrStat->cleanup(forceAll);
	}
}
