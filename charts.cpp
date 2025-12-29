#include "charts.h"

#include "calltable.h"
#include "sql_db_global.h"


extern int opt_nocdr;
extern MySqlStore *sqlStore;
extern int opt_charts_cache_max_threads;
extern int opt_cdr_stat_values;
extern bool opt_cdr_stat_sources;
extern int opt_cdr_stat_interval;
extern int opt_cdr_problems_interval;
extern int opt_cdr_summary_interval;
extern int opt_cdr_summary_number_length;
extern bool opt_cdr_summary_number_complete;
extern bool opt_cdr_summary_only_first_interval;
extern bool opt_time_precision_in_ms;
extern int absolute_timeout;


static sChartTypeDef ChartTypeDef[] = { 
	{ _chartType_total,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_count,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_cps,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_minutes,			1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
	{ _chartType_minutes_all,		1,	1,	_chartPercType_NA,	0,	_chartSubType_count },
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
	{ _chartType_packet_lost_connected,	0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_packet_lost_caller,	0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_packet_lost_caller_connected,	
						0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_packet_lost_called,	0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_packet_lost_called_connected,	
						0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_jitter,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_jitter_caller,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_jitter_called,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_delay,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_delay_caller,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_delay_called,		0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
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
	{ _chartType_pbd,			0,	1,	_chartPercType_Asc,	0,	_chartSubType_value },
	{ _chartType_acd_avg,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_acd,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_asr_avg,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_asr,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_ner_avg,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_ner,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_seer_avg,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_seer,			0,	1,	_chartPercType_NA,	0,	_chartSubType_acd_asr },
	{ _chartType_sipResp,			0,	1,	_chartPercType_NA,	1,	_chartSubType_count },
	{ _chartType_sipResponse,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_sipResponse_base,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_codecs,			0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_IP_src,			0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_IP_dst,			0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_domain_src,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_domain_dst,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_caller_countries,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_called_countries,		0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_SIP_src_IP_countries,	0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_SIP_dst_IP_countries,	0,	1,	_chartPercType_NA,	0,	_chartSubType_area },
	{ _chartType_price_customer,		0,	1,	_chartPercType_NA,	0,	_chartSubType_value },
	{ _chartType_price_operator,		0,	1,	_chartPercType_NA,	0,	_chartSubType_value }
};

static cCharts *chartsCache;
static cCdrStat *cdrStat;
static cCdrProblems *cdrProblems;
static cCdrSummary *cdrSummary;

struct sChartType {
	const char *str;
	eChartType type;
};
struct sValueType {
	const char *str;
	eChartValueType type;
};
static sChartType *getChartTypes();
static eChartType chartTypeFromString(string chartString);
static const char *chartStringFromType(eChartType chartType);
static const char *chartDbFieldTypeFromType(eChartType chartType);
static sChartTypeDef getChartTypeDef(eChartType chartType);
static eChartValueType getChartValueTypeFromString(string valueTypeStr);
static const char *getChartValueStringFromType(eChartValueType valueType);
static bool cmpValCondEqLeft(const char *val1, const char *val2);


cChartDataItem::cChartDataItem() {
	this->max = 0;
	this->min = -1;
	this->sum = 0;
	this->count = 0;
	this->count2 = 0;
	this->countAll = 0;
	this->countConected = 0;
	this->sumDuration = 0;
	this->countShort = 0;
}

void cChartDataItem::add(sChartsCallData *call, 
			 unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			 cChartSeries *series, cChartIntervalSeriesData *intervalSeries) {
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
						this->sumDuration += opt_time_precision_in_ms ?
								      call->call()->connect_duration_sf() :
								      call->call()->connect_duration_s();
					}
				} else {
					bool connect_duration_null;
					double connect_duration = call->tables_content()->getValue_float(_t_cdr, "connect_duration", false, &connect_duration_null);
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
					call->tables_content()->getValue_int(_t_cdr, "connect_duration", false, &connect_duration_null);
					if(!connect_duration_null ||
					   (series->ner_lsr_filter && series->ner_lsr_filter->check((unsigned)lsr))) {
						++this->count;
					}
				}
			}
			break;
		case _chartType_seer:
		case _chartType_seer_avg:
			if(series->def.chartType == _chartType_seer ||
			   (firstInterval && beginInInterval)) {
				double lsr;
				bool lsr_null;
				if(call->type == sChartsCallData::_call) {
					call->call()->getChartCacheValue(_chartType_sipResp, &lsr, NULL, &lsr_null, chartsCache);
					if(series->seer_lsr_filter[0] && series->seer_lsr_filter[0]->check((unsigned)lsr)) {
						++this->count;
					}
					if(series->seer_lsr_filter[1] && !series->seer_lsr_filter[1]->check((unsigned)lsr)) {
						++this->count2;
					}
				} else {
					Call::getChartCacheValue(call->tables_content(), _chartType_sipResp, &lsr, NULL, &lsr_null, chartsCache);
					if(series->seer_lsr_filter[0] && series->seer_lsr_filter[0]->check((unsigned)lsr)) {
						++this->count;
					}
					if(series->seer_lsr_filter[1] && !series->seer_lsr_filter[1]->check((unsigned)lsr)) {
						++this->count2;
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
					double connect_duration = opt_time_precision_in_ms ?
								   call->call()->connect_duration_sf() :
								   call->call()->connect_duration_s();
					++this->countConected;
					if(intervalSeries->param.size() && 
					   connect_duration < atoi(intervalSeries->param[0].c_str())) {
						++this->countShort;
					}
				}
			} else {
				bool connect_duration_null;
				double connect_duration = call->tables_content()->getValue_float(_t_cdr, "connect_duration", false, &connect_duration_null);
				if(!connect_duration_null) {
					++this->countConected;
					if(intervalSeries->param.size() && 
					   connect_duration < atoi(intervalSeries->param[0].c_str())) {
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
	unsigned precision_base = 12;
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
									   series->typeUse == _chartTypeUse_cdrStat ? 
									    cdrStat->maxValuesPartsForPercentile :
									   series->typeUse == _chartTypeUse_cdrSummary ?
									    cdrSummary->maxValuesPartsForPercentile :
									    0;
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
		case _chartType_seer_avg:
		case _chartType_seer:
			if(this->count2) {
				JsonExport exp;
				exp.add("_", "cmp2");
				exp.add("v1", this->count);
				exp.add("v2", this->count2);
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
		case _chartType_seer_avg:
		case _chartType_seer:
			if(this->count2) {
				return((double)this->count / this->count2 * 100);
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
	this->all_float = 0;
	this->all_fi = 0;
	this->all_li = 0;
	this->pool = NULL;
}

cChartDataPool::~cChartDataPool() {
	if(this->pool) {
		delete this->pool;
	}
}

void cChartDataPool::createPool(u_int32_t timeFrom, u_int32_t timeTo) {
	this->pool = new cPool(timeFrom, timeTo);
}

void cChartDataPool::add_us(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			    cChartSeries *series, cChartInterval *interval,
			    u_int64_t calldate_from_us, u_int64_t calldate_to_us) {
	unsigned int from, to;
	switch(series->def.chartType) {
	case _chartType_total:
	case _chartType_count:
		from = ::max(TIME_US_TO_S(calldate_from_us), interval->timeFrom);
		to = ::min(TIME_US_TO_S_ceil_ms(calldate_to_us), interval->timeTo - 1);
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
			this->pool->inc(i - interval->timeFrom);
		}
		break;
	case _chartType_cps:
		from = ::max(TIME_US_TO_S(calldate_from_us), interval->timeFrom);
		to = ::min(TIME_US_TO_S_ceil_ms(calldate_to_us), interval->timeTo - 1);
		++this->all;
		if(beginInInterval && firstInterval) {
			++this->all_fi;
			this->pool->inc(from - interval->timeFrom);
		}
		break;
	case _chartType_minutes: {
		double connect_duration;
		if(call->type == sChartsCallData::_call) {
			connect_duration = opt_time_precision_in_ms ?
					    call->call()->connect_duration_sf() :
					    call->call()->connect_duration_s();
		} else {
			connect_duration = call->tables_content()->getValue_float(_t_cdr, "connect_duration");
		}
		double duration = TIME_US_TO_SF(calldate_to_us - calldate_from_us);
		double calldate_from_connected = TIME_US_TO_SF(calldate_from_us) + (duration - connect_duration);
		double from_f = ::max(calldate_from_connected, (double)interval->timeFrom);
		double to_f = ::min(TIME_US_TO_SF(calldate_to_us), (double)interval->timeTo);
		//int secondsConnected = to - calldate_from_connected + 1;
		double secondsConnected = to_f - from_f;
		if(secondsConnected > 0) {
			 this->all_float += secondsConnected;
			 /*
			 for(unsigned int i = from; i <= to; i++) {
				 this->pool[i - interval->timeFrom] += i - calldate_from_connected + 1;
			 }
			 */
		}}
		break;
	case _chartType_minutes_all: {
		double connect_duration;
		if(call->type == sChartsCallData::_call) {
			connect_duration = opt_time_precision_in_ms ?
					    call->call()->connect_duration_sf() :
					    call->call()->connect_duration_s();
		} else {
			connect_duration = call->tables_content()->getValue_float(_t_cdr, "connect_duration");
		}
		if(connect_duration > 0) {
			this->all_float += connect_duration;
		}}
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
			u_int32_t pool_i = (*this->pool)[i];
			pool_str += intToString(pool_i);
			if(pool_i) {
				min = min == UINT_MAX ?
				       pool_i :
				       ((unsigned int)pool_i < min ? pool_i : min);
				max =  ((unsigned int)pool_i > max ? pool_i : max);
				sum += pool_i;
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
	case _chartType_minutes_all:
		if(this->all > 0) {
			return(floatToString(this->all / 60., 6, true));
		} else if(this->all_float > 0) {
			return(floatToString(this->all_float / 60., 6, true));
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
			u_int32_t pool_i = (*this->pool)[i];
			if(pool_i) {
				min = min == UINT_MAX ?
				       pool_i :
				       ((unsigned int)pool_i < min ? pool_i : min);
				max =  ((unsigned int)pool_i > max ? pool_i : max);
				sum += pool_i;
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
	case _chartType_minutes_all:
		if(this->all) {
			return(this->all / 60.);
		} else if(this->all_float) {
			return(this->all_float / 60.);
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

void cChartIntervalSeriesData::add_us(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
				      u_int64_t calldate_from_us, u_int64_t calldate_to_us) {
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
								    this->series, this);
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
								       this->series, this);
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
		this->dataPool->add_us(call, call_interval, firstInterval, lastInterval, beginInInterval, 
				       this->series, this->interval,
				       calldate_from_us, calldate_to_us);
	}
	if(this->dataItem) {
		this->dataItem->add(call, call_interval, firstInterval, lastInterval, beginInInterval, 
				    this->series, this);
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

unsigned int cChartIntervalSeriesData::getCountValues() {
	if(this->dataItem) {
		return(this->dataItem->getCount());
	}
	return(0);
}

void cChartIntervalSeriesData::store(cChartInterval *interval, const int *sensor_id, const vmIP *ip, SqlDb *sqlDb, int src_dst) {
	if(!counter_add) {
		return;
	}
	string chart_data = getChartData(interval);
	if(chart_data.empty() ||
	   chart_data == last_chart_data) {
		return;
	}
	string table_name = typeUse == _chartTypeUse_chartCache ? "chart_sniffer_series_cache" : ("cdr_stat_sources" + cCdrStat::tableNameSuffix(src_dst));
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
	extern int opt_id_sensor;
	cache_row.add(sensor_id ? *sensor_id : (opt_id_sensor > 0 ? opt_id_sensor : 0), "sensor_id");
	cache_row.add(sqlDateTimeString(created_at_s), "created_at");
	cache_row.add(sqlEscapeString(chart_data), data_column_name);
	SqlDb_row cache_row_update;
	cache_row_update.add(sqlEscapeString(chart_data), data_column_name);
	cache_row_update.add(sqlDateTimeString(getTimeS()), "updated_at");
	cache_row_update.add(store_counter, "updated_counter");
	string insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT +
			    sqlDb->insertQuery(table_name, cache_row, true, false, true, &cache_row_update));
	sqlStore->query_lock(insert_str.c_str(), STORE_PROC_ID_CHARTS_CACHE, 0);
	++store_counter;
}


void cChartInterval::sCdrProblems::add(sChartsCallData *call_data, int src_dst) {
	bool connected = false;
	double mos = 0;
	bool mos_null = true;
	unsigned bye = 0;
	u_int64_t flags = 0;
	bool rtp_a_set = false;
	bool rtp_b_set = false;
	if(call_data->type == sChartsCallData::_call) {
		Call *call = call_data->call();
		call->getChartCacheValue(src_dst == 0 ? _chartType_mos_caller : _chartType_mos_called, &mos, NULL, &mos_null, chartsCache);
		if(call->connect_time_us) {
			connected = true;
		}
		bye = call->rslt_save_cdr_bye;
		flags = call->rslt_save_cdr_flags;
		rtp_a_set = call->rtpab[0] && call->rtpab[0]->saddr.isSet();
		rtp_b_set = call->rtpab[1] && call->rtpab[1]->saddr.isSet();
	} else {
		Call::getChartCacheValue(call_data->tables_content(), src_dst == 0 ? _chartType_mos_caller : _chartType_mos_called, &mos, NULL, &mos_null, chartsCache);
		bool connect_duration_null;
		call_data->tables_content()->getValue_int(_t_cdr, "connect_duration", false, &connect_duration_null);
		if(!connect_duration_null) {
			connected = true;
		}
		bool setNull = true;
		bye = call_data->tables_content()->getValue_int(_t_cdr, "bye", false, &setNull);
		flags = call_data->tables_content()->getValue_uint(_t_cdr, "flags", false, &setNull);
		bool a_saddr_null = true;
		bool b_saddr_null = true;
		string a_saddr_str = call_data->tables_content()->getValue_string(_t_cdr, "a_saddr", &a_saddr_null);
		string b_saddr_str = call_data->tables_content()->getValue_string(_t_cdr, "b_saddr", &b_saddr_null);
		rtp_a_set = !a_saddr_str.empty() && !a_saddr_null;
		rtp_b_set = !b_saddr_str.empty() && !b_saddr_null;
	}
	++count_all;
	if(connected)					++count_connected;
	if(!mos_null && mos > 0 && mos < 3.1)		++count_mos_lt_31;
	if(!mos_null && mos >= 3.1 && mos < 3.6)	++count_mos_lt_36;
	if(!mos_null && mos >= 3.6 && mos < 4.0)	++count_mos_lt_40;
	if(bye == 1)					++count_interrupted_calls;
	if(connected && (rtp_a_set ^ rtp_b_set))	++count_one_way;
	if(connected && !rtp_a_set && !rtp_b_set)	++count_missing_rtp;
	if(flags & CDR_SRTP_WITHOUT_KEY)		++count_missing_srtp_key;
	if(flags & CDR_FAS_DETECTED)			++count_fas;
	if(flags & CDR_ZEROSSRC_DETECTED)		++count_zerossrc;
	if(flags & CDR_SIPALG_DETECTED)			++count_sipalg;
	if(bye == 2) 					++count_bye_code_2;
	if(bye == 102) 					++count_bye_code_102;
	if(bye == 103) 					++count_bye_code_103;
	if(bye == 104) 					++count_bye_code_104;
	if(bye == 105) 					++count_bye_code_105;
	if(bye == 101) 					++count_bye_code_101;
	if(bye == 106) 					++count_bye_code_106;
	if(bye == 107) 					++count_bye_code_107;
	if(bye == 108) 					++count_bye_code_108;
	if(bye == 109) 					++count_bye_code_109;
	if(bye == 100) 					++count_bye_code_100;
	if(bye == 110) 					++count_bye_code_110;
}

void cChartInterval::sCdrProblems::store(int sensor_id, const vmIP *ip, const string *number, eProblemType pt, int src_dst, int by_type,
					 u_int32_t timeFrom, u_int32_t created_at_real, SqlDb *sqlDb) {
	if(counter_add) {
		string table_name = "cdr_problems" + cCdrProblems::tableNameSuffix(by_type);
		SqlDb_row cdr_problems_row;
		cdr_problems_row.add(sqlDateTimeString(timeFrom), "from_time");
		cdr_problems_row.add(cCdrProblems::side_string(src_dst), "side");
		if(ip) {
			cdr_problems_row.add(*ip, "addr", false, sqlDb, table_name.c_str());
		}
		if(number) {
			cdr_problems_row.add(sqlEscapeString(*number), "number");
		}
		cdr_problems_row.add(pt, "type");
		cdr_problems_row.add(sensor_id, "sensor_id");
		cdr_problems_row.add(sqlDateTimeString(created_at_real), "created_at");
		SqlDb_row cdr_problems_row_update;
		store(&cdr_problems_row);
		store(&cdr_problems_row_update);
		cdr_problems_row_update.add(sqlDateTimeString(getTimeS()), "updated_at");
		cdr_problems_row_update.add(store_counter, "updated_counter");
		string insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT +
				    sqlDb->insertQuery(table_name, cdr_problems_row, true, false, true, &cdr_problems_row_update));
		sqlStore->query_lock(insert_str.c_str(), STORE_PROC_ID_CHARTS_CACHE, 0);
		++store_counter;
		counter_add = 0;
	}
}

void cChartInterval::sCdrProblems::store(SqlDb_row *row) {
	row->add(count_all, "count_all");
	row->add(count_connected, "count_connected");
	row->add(count_mos_lt_31, "count_mos_lt_31");
	row->add(count_mos_lt_36, "count_mos_lt_36");
	row->add(count_mos_lt_40, "count_mos_lt_40");
	row->add(count_interrupted_calls, "count_interrupted_calls");
	row->add(count_one_way, "count_one_way");
	row->add(count_missing_rtp, "count_missing_rtp");
	row->add(count_missing_srtp_key, "count_missing_srtp_key");
	row->add(count_fas, "count_fas");
	row->add(count_zerossrc, "count_zerossrc");
	row->add(count_sipalg, "count_sipalg");
	row->add(count_bye_code_2, "count_bye_code_2");
	row->add(count_bye_code_102, "count_bye_code_102");
	row->add(count_bye_code_103, "count_bye_code_103");
	row->add(count_bye_code_104, "count_bye_code_104");
	row->add(count_bye_code_105, "count_bye_code_105");
	row->add(count_bye_code_101, "count_bye_code_101");
	row->add(count_bye_code_106, "count_bye_code_106");
	row->add(count_bye_code_107, "count_bye_code_107");
	row->add(count_bye_code_108, "count_bye_code_108");
	row->add(count_bye_code_109, "count_bye_code_109");
	row->add(count_bye_code_100, "count_bye_code_100");
	row->add(count_bye_code_110, "count_bye_code_110");
}

cChartInterval::cChartInterval(eChartTypeUse typeUse) {
	this->typeUse = typeUse;
	u_int32_t real_time = getTimeS();
	created_at_real = real_time;
	last_use_at_real = real_time;
	last_store_at = 0;
	last_store_at_real = real_time;
	counter_add = 0;
	switch(typeUse) {
	case _chartTypeUse_chartCache:
		memset(&chart, 0, sizeof(chart));
		break;
	case _chartTypeUse_cdrStat:
		memset(&stat, 0, sizeof(stat));
		break;
	case _chartTypeUse_cdrProblems:
		memset(&problems, 0, sizeof(problems));
		break;
	case _chartTypeUse_cdrSummary:
		memset(&summary, 0, sizeof(summary));
		break;
	default:
		break;
	}
}

cChartInterval::~cChartInterval() {
	clear();
}

void cChartInterval::setInterval_chart(u_int32_t timeFrom, u_int32_t timeTo) {
	this->timeFrom = timeFrom;
	this->timeTo = timeTo;
	init_chart();
}

void cChartInterval::setInterval_stat(u_int32_t timeFrom, u_int32_t timeTo, sStatId &src, sStatId &dst) {
	this->timeFrom = timeFrom;
	this->timeTo = timeTo;
	init_stat(src, dst);
}

void cChartInterval::setInterval_problems(u_int32_t timeFrom, u_int32_t timeTo, sProblemId &src, sProblemId &dst) {
	this->timeFrom = timeFrom;
	this->timeTo = timeTo;
	init_problems(src, dst);
}

void cChartInterval::setInterval_summary(u_int32_t timeFrom, u_int32_t timeTo, sSummaryId &sum_id, sSummaryId &sum_nc_id) {
	this->timeFrom = timeFrom;
	this->timeTo = timeTo;
	init_summary(sum_id, sum_nc_id);
}

void cChartInterval::add_chart(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			       u_int64_t calldate_from_us, u_int64_t calldate_to_us,
			       map<cChartFilter*, bool> *filters_map) {
	if(typeUse != _chartTypeUse_chartCache) {
		return;
	}
	bool update = false;
	if(chart.data) {
		for(map<cChartSeriesId, cChartIntervalSeriesData*>::iterator iter = chart.data->begin(); iter != chart.data->end(); iter++) {
			if(iter->second->series->checkFilters(filters_map)) {
				iter->second->add_us(call, call_interval, firstInterval, lastInterval, beginInInterval, 
						     calldate_from_us, calldate_to_us);
				++counter_add;
				update = true;
			}
		}
	}
	if(update) {
		last_use_at_real = getTimeS();
	}
}

void cChartInterval::add_stat(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
			      u_int64_t calldate_from_us, u_int64_t calldate_to_us,
			      sStatId &src, sStatId &dst) {
	if(typeUse != _chartTypeUse_cdrStat) {
		return;
	}
	bool update = false;
	for(int src_dst = 0; src_dst < 2; src_dst++) {
		sStatId *stat_id = src_dst == 0 ? &src : &dst;
		map<sStatId, sSeriesDataCdrStat*> *seriesDataCdrStat = src_dst == 0 ? stat.src : stat.dst;
		if(cCdrStat::enableBySrcDst(src_dst) && stat_id->ip.isSet() && seriesDataCdrStat) {
			map<sStatId, sSeriesDataCdrStat*>::iterator iter_stat = seriesDataCdrStat->find(*stat_id);
			if(iter_stat != seriesDataCdrStat->end()) {
				if(beginInInterval && firstInterval) {
					++iter_stat->second->count;
					if(call->type == sChartsCallData::_call) {
						if(call->call()->connect_time_us) {
							++iter_stat->second->count_connected;
						}
						int lsr = call->branch_main()->lastSIPresponseNum;
						if(lsr / 100 >= 3 && lsr / 100 <= 6) {
							++iter_stat->second->count_lsr_3_6[lsr / 100 - 3];
						}
					} else {
						bool connect_duration_null;
						call->tables_content()->getValue_int(_t_cdr, "connect_duration", false, &connect_duration_null);
						if(!connect_duration_null) {
							++iter_stat->second->count_connected;
						}
						int lsr = call->tables_content()->getValue_int(_t_cdr, "lastSIPresponseNum");
						if(lsr / 100 >= 3 && lsr / 100 <= 6) {
							++iter_stat->second->count_lsr_3_6[lsr / 100 - 3];
						}
					}
				}
				for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_stat->second->data.begin(); iter_series != iter_stat->second->data.end(); iter_series++) {
					iter_series->second->add_us(call, call_interval, firstInterval, lastInterval, beginInInterval, 
								    calldate_from_us, calldate_to_us);
				}
				update = true;
				++iter_stat->second->counter_add;
			}
		}
	}
	if(update) {
		++counter_add;
		last_use_at_real = getTimeS();
	}
}

void cChartInterval::add_problems(sChartsCallData *call, sProblemId &src, sProblemId &dst) {
	if(typeUse != _chartTypeUse_cdrProblems) {
		return;
	}
	bool update = false;
	for(int src_dst = 0; src_dst < 2; src_dst++) {
	for(int by_type = 0; by_type < 3; by_type++) {
		if(cCdrProblems::enableBySrcDst(src_dst) && cCdrProblems::enableByType(by_type)) {
			sProblemId problem_id = src_dst == 0 ? src : dst;
			map<sProblemId, sCdrProblems*> *cdrProblems;
			bool ok_add = false;
			switch(by_type) {
			case 0:
				if(problem_id.ip.isSet()) {
					problem_id.str.clear();
					cdrProblems = src_dst == 0 ? problems.ip_src : problems.ip_dst;
					if(cdrProblems) {
						ok_add = true;
					}
				}
				break;
			case 1:
				if(!problem_id.str.empty()) {
					problem_id.ip.clear();
					cdrProblems = src_dst == 0 ? problems.number_src : problems.number_dst;
					if(cdrProblems) {
						ok_add = true;
					}
				}
				break;
			case 2:
				if(problem_id.ip.isSet()) {
					cdrProblems = src_dst == 0 ? problems.comb_src : problems.comb_dst;
					if(cdrProblems) {
						ok_add = true;
					}
				}
				break;
			}
			if(ok_add) {
				map<sProblemId, sCdrProblems*>::iterator iter = cdrProblems->find(problem_id);
				if(iter != cdrProblems->end()) {
					iter->second->add(call, src_dst);
					update = true;
					++iter->second->counter_add;
				}
			}
		}
	}}
	if(update) {
		++counter_add;
		last_use_at_real = getTimeS();
	}
}

void cChartInterval::add_summary(sChartsCallData *call, unsigned call_interval, bool firstInterval, bool lastInterval, bool beginInInterval,
				 u_int64_t calldate_from, u_int64_t calldate_to,
				 sSummaryId &sum_id, sSummaryId &sum_nc_id) {
	if(typeUse != _chartTypeUse_cdrSummary) {
		return;
	}
	bool update = false;
	for(int si = 0; si < 2; si++) {
		if(si == 0 || opt_cdr_summary_number_complete) {
			sSummaryId *_sum_id = si == 0 ? &sum_id : &sum_nc_id;
			map<sSummaryId, sSeriesDataCdrSummary*> *summaryData = si == 0 ? summary.sum : summary.sum_nc;
			map<sSummaryId, sSeriesDataCdrSummary*>::iterator iter_sum = summaryData->find(*_sum_id);
			if(iter_sum != summaryData->end()) {
				if(beginInInterval && firstInterval) {
					++iter_sum->second->count;
					if(call->type == sChartsCallData::_call) {
						if(call->call()->connect_time_us) {
							++iter_sum->second->count_connected;
						}
						if((call->call()->rtpab[0] && call->call()->rtpab[0]->saddr.isSet()) ||
						   (call->call()->rtpab[1] && call->call()->rtpab[1]->saddr.isSet())) {
							++iter_sum->second->count_exists_rtp;
						}
					} else {
						bool connect_duration_null;
						call->tables_content()->getValue_int(_t_cdr, "connect_duration", false, &connect_duration_null);
						if(!connect_duration_null) {
							++iter_sum->second->count_connected;
						}
						bool a_saddr_null = true;
						bool b_saddr_null = true;
						string a_saddr_str = call->tables_content()->getValue_string(_t_cdr, "a_saddr", &a_saddr_null);
						string b_saddr_str = call->tables_content()->getValue_string(_t_cdr, "b_saddr", &b_saddr_null);
						if((!a_saddr_str.empty() && !a_saddr_null) ||
						   (!b_saddr_str.empty() && !b_saddr_null)) {
							++iter_sum->second->count_exists_rtp;
						}
					}
				}
				for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_sum->second->data.begin(); iter_series != iter_sum->second->data.end(); iter_series++) {
					iter_series->second->add_us(call, call_interval, firstInterval, lastInterval, beginInInterval,
								    calldate_from, calldate_to);
				}
				update = true;
				++iter_sum->second->counter_add;
			}
		}
	}
	if(update) {
		++counter_add;
		last_use_at_real = getTimeS();
	}
}

void cChartInterval::store(u_int32_t act_time, u_int32_t real_time, SqlDb *sqlDb) {
	if(typeUse == _chartTypeUse_chartCache) {
		if(counter_add) {
			if(chart.data) {
				for(map<cChartSeriesId, cChartIntervalSeriesData*>::iterator iter = chart.data->begin(); iter != chart.data->end(); iter++) {
					iter->second->store(this, NULL, NULL, sqlDb, false);
				}
			}
			counter_add = 0;
		}
	} else if(typeUse == _chartTypeUse_cdrStat) {
		if(counter_add) {
			for(int src_dst = 0; src_dst < 2; src_dst++) {
				map<sStatId, sSeriesDataCdrStat*> *seriesDataCdrStat = src_dst == 0 ? stat.src : stat.dst;
				if(cCdrStat::enableBySrcDst(src_dst) && seriesDataCdrStat) {
					if(opt_cdr_stat_sources) {
						for(map<sStatId, sSeriesDataCdrStat*>::iterator iter_stat = seriesDataCdrStat->begin(); iter_stat != seriesDataCdrStat->end(); iter_stat++) {
							for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_stat->second->data.begin(); iter_series != iter_stat->second->data.end(); iter_series++) {
								iter_series->second->store(this, &iter_stat->first.sensor_id, &iter_stat->first.ip, sqlDb, src_dst);
							}
						}
					}
					if(opt_cdr_stat_values) {
						for(map<sStatId, sSeriesDataCdrStat*>::iterator iter_stat = seriesDataCdrStat->begin(); iter_stat != seriesDataCdrStat->end(); iter_stat++) {
							if(iter_stat->second->counter_add) {
								list<sFieldValue> fieldValues;
								unsigned countFieldValuesNotNull = 0;
								for(unsigned metrics_i = 0; metrics_i < cdrStat->metrics.size(); metrics_i++) {
									cCdrStat::sMetrics *metrics = &cdrStat->metrics[metrics_i];
									for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_stat->second->data.begin(); iter_series != iter_stat->second->data.end(); iter_series++) {
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
									string table_name = "cdr_stat_values" + cCdrStat::tableNameSuffix(src_dst);
									SqlDb_row cdr_stat_row;
									cdr_stat_row.add(sqlDateTimeString(timeFrom), "from_time");
									cdr_stat_row.add(iter_stat->first.ip, "addr", false, sqlDb, table_name.c_str());
									cdr_stat_row.add(iter_stat->first.sensor_id, "sensor_id");
									cdr_stat_row.add(sqlDateTimeString(created_at_real), "created_at");
									SqlDb_row cdr_stat_row_update;
									cdr_stat_row.add(iter_stat->second->count, "count_all");
									cdr_stat_row_update.add(iter_stat->second->count, "count_all");
									cdr_stat_row.add(iter_stat->second->count_connected, "count_connected");
									cdr_stat_row_update.add(iter_stat->second->count_connected, "count_connected");
									for(unsigned i = 0; i < sizeof(iter_stat->second->count_lsr_3_6) / sizeof(iter_stat->second->count_lsr_3_6[0]); i++) {
										string field_name = "count_lsr_" + intToString(3 + i);
										if(cCdrStat::exists_columns_check(field_name.c_str(), src_dst)) {
											cdr_stat_row.add(iter_stat->second->count_lsr_3_6[i], field_name);
											cdr_stat_row_update.add(iter_stat->second->count_lsr_3_6[i], field_name);
										}
									}
									for(list<sFieldValue>::iterator iter = fieldValues.begin(); iter != fieldValues.end(); iter++) {
										if(cCdrStat::exists_columns_check(iter->field.c_str(), src_dst)) {
											cdr_stat_row.add(iter->value, iter->field, iter->null);
											cdr_stat_row_update.add(iter->value, iter->field, iter->null);
										}
									}
									for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_stat->second->data.begin(); iter_series != iter_stat->second->data.end(); iter_series++) {
										if(!iter_series->second->series->sourceDataName.empty() &&
										   cCdrStat::exists_columns_check((iter_series->second->series->sourceDataName + "_source_data").c_str(), src_dst)) {
											string chart_data = iter_series->second->getChartData(this);
											if(!chart_data.empty()) {
												cdr_stat_row.add(chart_data, iter_series->second->series->sourceDataName + "_source_data");
												cdr_stat_row_update.add(chart_data, iter_series->second->series->sourceDataName + "_source_data");
											}
										}
									}
									cdr_stat_row_update.add(sqlDateTimeString(getTimeS()), "updated_at");
									cdr_stat_row_update.add(iter_stat->second->store_counter, "updated_counter");
									string insert_str = MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT +
											    sqlDb->insertQuery(table_name, cdr_stat_row, true, false, true, &cdr_stat_row_update));
									sqlStore->query_lock(insert_str.c_str(), STORE_PROC_ID_CHARTS_CACHE, 0);
									++iter_stat->second->store_counter;
								}
								iter_stat->second->counter_add = 0;
							}
						}
					}
				}
			}
			counter_add = 0;
		}
	} else if(typeUse == _chartTypeUse_cdrProblems) {
		if(counter_add) {
			for(int src_dst = 0; src_dst < 2; src_dst++) {
			for(int by_type = 0; by_type < 3; by_type++) {
				if(cCdrProblems::enableBySrcDst(src_dst) && cCdrProblems::enableByType(by_type)) {
					map<sProblemId, sCdrProblems*> *cdrProblems;
					switch(by_type) {
					case 0: {
						cdrProblems = src_dst == 0 ? problems.ip_src : problems.ip_dst;
						if(cdrProblems) {
							for(map<sProblemId, sCdrProblems*>::iterator iter = cdrProblems->begin(); iter != cdrProblems->end(); iter++) {
								if(iter->second->counter_add) {
									iter->second->store(iter->first.sensor_id, &iter->first.ip, NULL, iter->first.pt, src_dst, by_type,
											    timeFrom, created_at_real, sqlDb);
								}
							}
						}}
						break;
					case 1: {
						cdrProblems = src_dst == 0 ? problems.number_src : problems.number_dst;
						if(cdrProblems) {
							for(map<sProblemId, sCdrProblems*>::iterator iter = cdrProblems->begin(); iter != cdrProblems->end(); iter++) {
								if(iter->second->counter_add) {
									iter->second->store(iter->first.sensor_id, NULL, &iter->first.str, iter->first.pt, src_dst, by_type,
											    timeFrom, created_at_real, sqlDb);
								}
							}
						}}
						break;
					case 2: {
						cdrProblems = src_dst == 0 ? problems.comb_src : problems.comb_dst;
						if(cdrProblems) {
							for(map<sProblemId, sCdrProblems*>::iterator iter = cdrProblems->begin(); iter != cdrProblems->end(); iter++) {
								if(iter->second->counter_add) {
									iter->second->store(iter->first.sensor_id, &iter->first.ip, &iter->first.str, iter->first.pt, src_dst, by_type,
											    timeFrom, created_at_real, sqlDb);
								}
							}
						}}
						break;
					}
				}
			}}
			counter_add = 0;
		}
	} else if(typeUse == _chartTypeUse_cdrSummary) {
		if(counter_add) {
			for(int si = 0; si < 2; si++) {
				if(si == 0 || opt_cdr_summary_number_complete) {
					map<sSummaryId, sSeriesDataCdrSummary*> *summaryData = si == 0 ? summary.sum : summary.sum_nc;
					for(map<sSummaryId, sSeriesDataCdrSummary*>::iterator iter_sum = summaryData->begin(); iter_sum != summaryData->end(); iter_sum++) {
						if(iter_sum->second->counter_add) {
							list<sFieldValue> fieldValues;
							unsigned countFieldValuesNotNull = 0;
							for(unsigned metrics_i = 0; metrics_i < cdrSummary->metrics.size(); metrics_i++) {
								cCdrSummary::sMetrics *metrics = &cdrSummary->metrics[metrics_i];
								for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_sum->second->data.begin(); iter_series != iter_sum->second->data.end(); iter_series++) {
									if(metrics->type_series == iter_series->second->series->series_id.id) {
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
								string table_name = si == 0 ? "cdr_summary" : "cdr_summary_nc";
								SqlDb_row cdr_sum_row;
								cdr_sum_row.add(sqlDateTimeString(timeFrom), "from_time");
								cdr_sum_row.add(iter_sum->first.src_ip, "sipcallerip", false, sqlDb, table_name.c_str());
								cdr_sum_row.add(iter_sum->first.dst_ip, "sipcalledip", false, sqlDb, table_name.c_str());
								cdr_sum_row.add(iter_sum->first.src_number, "caller");
								cdr_sum_row.add(iter_sum->first.dst_number, "called");
								cdr_sum_row.add(iter_sum->first.codec, "payload");
								string lsr_query_str;
								if(useSetId()) {
									//cdr_sum_row.add_cb_string(iter_sum->first.lsr_str, "lastSIPresponse_id", cSqlDbCodebook::_cb_sip_response);
									cdr_sum_row.add(MYSQL_CODEBOOK_ID(cSqlDbCodebook::_cb_sip_response, iter_sum->first.lsr_str), "lastSIPresponse_id");
								} else {
									extern cSqlDbData *dbData;
									unsigned _cb_id = dbData->getCbId(cSqlDbCodebook::_cb_sip_response, iter_sum->first.lsr_str.c_str(), false, true);
									if(_cb_id) {
										cdr_sum_row.add(_cb_id, "lastSIPresponse_id");
									} else {
										lsr_query_str = MYSQL_ADD_QUERY_END(string("set @lSresp_id = ") +
												"getIdOrInsertSIPRES(" + sqlEscapeStringBorder(iter_sum->first.lsr_str) + ")");
										cdr_sum_row.add(MYSQL_VAR_PREFIX + "@lSresp_id", "lastSIPresponse_id");
									}
								}
								cdr_sum_row.add(iter_sum->first.sensor_id, "sensor_id");
								cdr_sum_row.add(sqlDateTimeString(created_at_real), "created_at");
								SqlDb_row cdr_sum_row_update;
								cdr_sum_row.add(iter_sum->second->count, "count_all");
								cdr_sum_row_update.add(iter_sum->second->count, "count_all");
								cdr_sum_row.add(iter_sum->second->count_connected, "count_connected");
								cdr_sum_row_update.add(iter_sum->second->count_connected, "count_connected");
								cdr_sum_row.add(iter_sum->second->count_exists_rtp, "count_exists_rtp");
								cdr_sum_row_update.add(iter_sum->second->count_exists_rtp, "count_exists_rtp");
								for(list<sFieldValue>::iterator iter = fieldValues.begin(); iter != fieldValues.end(); iter++) {
									if(cCdrSummary::exists_columns_check(iter->field.c_str(), si)) {
										cdr_sum_row.add(iter->value, iter->field, iter->null);
										cdr_sum_row_update.add(iter->value, iter->field, iter->null);
									}
								}
								for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_series = iter_sum->second->data.begin(); iter_series != iter_sum->second->data.end(); iter_series++) {
									if(iter_series->second->series->countValues && 
									   cCdrSummary::exists_columns_check((iter_series->second->series->sourceDataName + "_count").c_str(), si)) {
										cdr_sum_row.add(iter_series->second->getCountValues(), iter_series->second->series->sourceDataName + "_count");
										cdr_sum_row_update.add(iter_series->second->getCountValues(), iter_series->second->series->sourceDataName + "_count");
									}
									if(!iter_series->second->series->sourceDataName.empty() &&
									   cCdrSummary::exists_columns_check((iter_series->second->series->sourceDataName + "_source_data").c_str(), si)) {
										string chart_data = iter_series->second->getChartData(this);
										if(!chart_data.empty()) {
											cdr_sum_row.add(chart_data, iter_series->second->series->sourceDataName + "_source_data");
											cdr_sum_row_update.add(chart_data, iter_series->second->series->sourceDataName + "_source_data");
										}
									}
								}
								cdr_sum_row_update.add(sqlDateTimeString(getTimeS()), "updated_at");
								cdr_sum_row_update.add(iter_sum->second->store_counter, "updated_counter");
								string insert_str = lsr_query_str +
										    MYSQL_ADD_QUERY_END(MYSQL_MAIN_INSERT +
										    sqlDb->insertQuery(table_name, cdr_sum_row, true, false, true, &cdr_sum_row_update));
								sqlStore->query_lock(insert_str.c_str(), STORE_PROC_ID_CHARTS_CACHE, 0);
								++iter_sum->second->store_counter;
							}
							iter_sum->second->counter_add = 0;
						}
					}
				}
			}
		}
	}
	this->last_store_at = act_time;
	this->last_store_at_real = real_time;
}

void cChartInterval::init_chart() {
	if(typeUse == _chartTypeUse_chartCache) {
		for(map<cChartSeriesId, cChartSeries*>::iterator iter = chartsCache->series.begin(); iter != chartsCache->series.end(); iter++) {
			if(!iter->second->terminating) {
				if(!chart.data) {
					chart.data = new map<cChartSeriesId, cChartIntervalSeriesData*>;
				}
				(*chart.data)[iter->second->series_id] = new FILE_LINE(0) cChartIntervalSeriesData(typeUse, iter->second, this);
				(*chart.data)[iter->second->series_id]->prepareData();
			}
		}
	}
}

void cChartInterval::init_stat(sStatId &src, sStatId &dst) {
	if(typeUse == _chartTypeUse_cdrStat) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
			sStatId *stat_id = src_dst == 0 ? &src : &dst;
			if(cCdrStat::enableBySrcDst(src_dst) && stat_id->ip.isSet()) {
				map<sStatId, sSeriesDataCdrStat*> **seriesDataCdrStat = src_dst == 0 ? &stat.src : &stat.dst;
				if(!*seriesDataCdrStat) {
					*seriesDataCdrStat = new map<sStatId, sSeriesDataCdrStat*>;
				}
				map<sStatId, sSeriesDataCdrStat*>::iterator iter = (*seriesDataCdrStat)->find(*stat_id);
				if(iter == (*seriesDataCdrStat)->end()) {
					sSeriesDataCdrStat *seriesDataItem = new FILE_LINE(0) sSeriesDataCdrStat;
					(**seriesDataCdrStat)[*stat_id] = seriesDataItem;
					vector<cChartSeries*> *series = src_dst == 0 ? &cdrStat->series_src : &cdrStat->series_dst;
					for(unsigned series_i = 0; series_i < series->size(); series_i++) {
						seriesDataItem->data[series_i] = new FILE_LINE(0) cChartIntervalSeriesData(typeUse, (*series)[series_i], this);
						seriesDataItem->data[series_i]->prepareData();
					}
				}
			}
		}
	}
}

void cChartInterval::init_problems(sProblemId &src, sProblemId &dst) {
	if(typeUse == _chartTypeUse_cdrProblems) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
		for(int by_type = 0; by_type < 3; by_type++) {
			if(cCdrProblems::enableBySrcDst(src_dst) && cCdrProblems::enableByType(by_type)) {
				sProblemId problem_id = src_dst == 0 ? src : dst;
				map<sProblemId, sCdrProblems*> **cdrProblems;
				bool ok_init = false;
				switch(by_type) {
				case 0:
					if(problem_id.ip.isSet()) {
						problem_id.str.clear();
						cdrProblems = src_dst == 0 ? &problems.ip_src : &problems.ip_dst;
						ok_init = true;
					}
					break;
				case 1:
					if(!problem_id.str.empty()) {
						problem_id.ip.clear();
						cdrProblems = src_dst == 0 ? &problems.number_src : &problems.number_dst;
						ok_init = true;
					}
					break;
				case 2:
					if(problem_id.ip.isSet()) {
						cdrProblems = src_dst == 0 ? &problems.comb_src : &problems.comb_dst;
						ok_init = true;
					}
					break;
				}
				if(ok_init) {
					if(!*cdrProblems) {
						*cdrProblems = new map<sProblemId, sCdrProblems*>;
					}
					map<sProblemId, sCdrProblems*>::iterator iter = (*cdrProblems)->find(problem_id);
					if(iter == (*cdrProblems)->end()) {
						sCdrProblems *cdrProblemsItem = new FILE_LINE(0) sCdrProblems;
						(**cdrProblems)[problem_id] = cdrProblemsItem;
					}
				}
			}
		}}
	}
}

void cChartInterval::init_summary(sSummaryId &sum_id, sSummaryId &sum_nc_id) {
	if(typeUse == _chartTypeUse_cdrSummary) {
		for(int si = 0; si < 2; si++) {
			if(si == 0 || opt_cdr_summary_number_complete) {
				sSummaryId *_sum_id = si == 0 ? &sum_id : &sum_nc_id;
				map<sSummaryId, sSeriesDataCdrSummary*> **summaryData = si == 0 ? &summary.sum : &summary.sum_nc;
				if(!*summaryData) {
					*summaryData = new map<sSummaryId, sSeriesDataCdrSummary*>;
				}
				map<sSummaryId, sSeriesDataCdrSummary*>::iterator iter = (*summaryData)->find(*_sum_id);
				if(iter == (*summaryData)->end()) {
					sSeriesDataCdrSummary *seriesDataItem = new FILE_LINE(0) sSeriesDataCdrSummary;
					(**summaryData)[*_sum_id] = seriesDataItem;
					for(unsigned series_i = 0; series_i < cdrSummary->series.size(); series_i++) {
						seriesDataItem->data[series_i] = new FILE_LINE(0) cChartIntervalSeriesData(typeUse, cdrSummary->series[series_i], this);
						seriesDataItem->data[series_i]->prepareData();
					}
				}
			}
		}
	}
}

void cChartInterval::clear() {
	if(typeUse == _chartTypeUse_chartCache) {
		if(chart.data) {
			for(map<cChartSeriesId, cChartIntervalSeriesData*>::iterator iter = chart.data->begin(); iter != chart.data->end(); iter++) {
				delete iter->second;
			}
			chart.data->clear();
			delete chart.data;
			chart.data = NULL;
		}
	} else if(typeUse == _chartTypeUse_cdrStat) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
			if(cCdrStat::enableBySrcDst(src_dst)) {
				map<sStatId, sSeriesDataCdrStat*> **seriesDataCdrStat = src_dst == 0 ? &stat.src : &stat.dst;
				if(seriesDataCdrStat && *seriesDataCdrStat) {
					for(map<sStatId, sSeriesDataCdrStat*>::iterator iter = (*seriesDataCdrStat)->begin(); iter != (*seriesDataCdrStat)->end(); iter++) {
						for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_2 = iter->second->data.begin(); iter_2 != iter->second->data.end(); iter_2++) {
							delete iter_2->second;
						}
						delete iter->second;
					}
					(*seriesDataCdrStat)->clear();
					delete *seriesDataCdrStat;
					*seriesDataCdrStat = NULL;
				}
			}
		}
	} else if(typeUse == _chartTypeUse_cdrProblems) {
		for(int src_dst = 0; src_dst < 2; src_dst++) {
		for(int by_type = 0; by_type < 3; by_type++) {
			if(cCdrProblems::enableBySrcDst(src_dst) && cCdrProblems::enableByType(by_type)) {
				map<sProblemId, sCdrProblems*> **cdrProblems = NULL;
				switch(by_type) {
				case 0:
					cdrProblems = src_dst == 0 ? &problems.ip_src : &problems.ip_dst;
					break;
				case 1:
					cdrProblems = src_dst == 0 ? &problems.number_src : &problems.number_dst;
					break;
				case 2:
					cdrProblems = src_dst == 0 ? &problems.comb_src : &problems.comb_dst;
					break;
				}
				if(cdrProblems && *cdrProblems) {
					for(map<sProblemId, sCdrProblems*>::iterator iter = (*cdrProblems)->begin(); iter != (*cdrProblems)->end(); iter++) {
						delete iter->second;
					}
					(*cdrProblems)->clear();
					delete *cdrProblems;
					*cdrProblems = NULL;
				}
			}
		}}
	} else if(typeUse == _chartTypeUse_cdrSummary) {
		for(int si = 0; si < 2; si++) {
			if(si == 0 || opt_cdr_summary_number_complete) {
				map<sSummaryId, sSeriesDataCdrSummary*> **summaryData = si == 0 ? &summary.sum : &summary.sum_nc;
				if(summaryData && *summaryData) {
					for(map<sSummaryId, sSeriesDataCdrSummary*>::iterator iter = (*summaryData)->begin(); iter != (*summaryData)->end(); iter++) {
						for(map<u_int16_t, cChartIntervalSeriesData*>::iterator iter_2 = iter->second->data.begin(); iter_2 != iter->second->data.end(); iter_2++) {
							delete iter_2->second;
						}
						delete iter->second;
					}
					(*summaryData)->clear();
					delete *summaryData;
					*summaryData = NULL;
				}
			}
		}
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
					cout << call->tables_content()->getValue_str(_t_cdr_next, "fbasename");
				}
			}
			cout << " * RSLT: " << rslt << endl;
		}
	}
	
	return(rslt);
	
#endif
	
}


void cChartLsrFilter::parseData(JsonItem *jsonData) {
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
	ner_lsr_filter = NULL;
	seer_lsr_filter[0] = NULL;
	seer_lsr_filter[1] = NULL;
	JsonItem *nerLsrFilterItem = jsonConfig.getItem("params/nerLsrFilter");
	if(nerLsrFilterItem) {
		ner_lsr_filter = new FILE_LINE(0) cChartLsrFilter;
		ner_lsr_filter->parseData(nerLsrFilterItem);
	}
	for(unsigned i = 0; i < 2; i++) {
		JsonItem *seerLsrFilterItem = jsonConfig.getItem("params/seer" + intToString(i + 1) + "LsrFilter");
		if(seerLsrFilterItem) {
			seer_lsr_filter[i] = new FILE_LINE(0) cChartLsrFilter;
			seer_lsr_filter[i]->parseData(seerLsrFilterItem);
		}
	}
	def = getChartTypeDef(chartTypeFromString(chartType));
	countValues = false;
	used_counter = 0;
	terminating = 0;
}

cChartSeries::cChartSeries(eChartTypeUse typeUse, unsigned int id, const char *chart_type, const char *source_data_name, bool id_is_chart_type) :
 series_id(id, "") {
	this->typeUse = typeUse;
	if(source_data_name) {
		sourceDataName = source_data_name;
	}
	def = getChartTypeDef(id_is_chart_type ? (eChartType)id : chartTypeFromString(chart_type));
	countValues = false;
	ner_lsr_filter = NULL;
	seer_lsr_filter[0] = NULL;
	seer_lsr_filter[1] = NULL;
	if(def.subType == _chartSubType_acd_asr) {
		if(def.chartType == _chartType_ner || def.chartType == _chartType_ner_avg) {
			JsonItem ner_lsr_filter_config;
			ner_lsr_filter_config.parse("{\"w\":[\"600\",\"603\",\"604\",\"607\",\"608\"],\"ws\":[\"2\",\"3\",\"4\"],\"b\":null,\"bs\":null}");
			ner_lsr_filter = new FILE_LINE(0) cChartLsrFilter;
			ner_lsr_filter->parseData(&ner_lsr_filter_config);
		}
		if(def.chartType == _chartType_seer || def.chartType == _chartType_seer_avg) {
			for(unsigned i = 0; i < 2; i++) {
				JsonItem seer_lsr_filter_config;
				seer_lsr_filter_config.parse(i == 0 ? 
							      "{\"w\":[\"200\",\"480\",\"486\",\"600\",\"603\"],\"ws\":null,\"b\":null,\"bs\":null}" :
							      "{\"w\":null,\"ws\":[\"3\"],\"b\":null,\"bs\":null}");
				seer_lsr_filter[i] = new FILE_LINE(0) cChartLsrFilter;
				seer_lsr_filter[i]->parseData(&seer_lsr_filter_config);
			}
		}
	}
	used_counter = 0;
	terminating = 0;
}

cChartSeries::~cChartSeries() {
	clear();
}

void cChartSeries::setCountValues(bool countValues) {
	this->countValues = countValues;
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
	for(unsigned i = 0; i < 2; i++) {
		if(seer_lsr_filter[i]) {
			delete seer_lsr_filter[i];
			seer_lsr_filter[i] = NULL;
		}
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
				intervals[interval_begin]->setInterval_chart(interval_begin, interval_begin + 60);
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
		if(opt_time_precision_in_ms) {
			calltime_us = call->call()->calltime_us();
			callend_us = call->call()->callend_us();
		} else {
			calltime_us = TIME_S_TO_US(call->call()->calltime_s());
			callend_us = TIME_S_TO_US(call->call()->callend_s());
		}
	} else {
		calltime_us = call->tables_content()->getValue_int(_t_cdr, "calldate");
		callend_us = call->tables_content()->getValue_int(_t_cdr, "callend");
	}
	u_int64_t calltime_min_s = TIME_US_TO_S(calltime_us) / 60 * 60;
	u_int64_t callend_min_s = TIME_US_TO_S(callend_us) / 60 * 60;
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
			interval->setInterval_chart(interval_begin, interval_begin + 60);
			intervals[interval_begin] = interval;
		}
		unlock_intervals();
		interval->add_chart(call, interval_counter, interval_counter == 0, interval_counter == intervals_begin.size() - 1, interval_counter == 0,
				    calltime_us, callend_us,
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
		if(iter->second->chart.data &&
		   iter->second->chart.data->find(series_id) != iter->second->chart.data->end()) {
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
	intervalStore = sverb.cdr_stat_interval_store ? 
			 sverb.cdr_stat_interval_store :
			 (opt_cdr_stat_interval <= 15 ? mainInterval / 3 :
			  opt_cdr_stat_interval <= 30 ? mainInterval / 3 :
			  opt_cdr_stat_interval <= 60 ? mainInterval / 4 :
			  30 * 60);
	intervalCleanup = sverb.cdr_stat_interval_cleanup ?
			   sverb.cdr_stat_interval_cleanup :
			   mainInterval * 2;
	intervalExpiration = absolute_timeout + mainInterval * 2;
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
	for(int src_dst = 0; src_dst < 2; src_dst++) {
		init_series(src_dst == 0 ? &series_src : &series_dst, src_dst);
	}
	init_metrics(&metrics);
}

void cCdrStat::init_series(vector<cChartSeries*> *series, int src_dst) {
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_count, "TCH_count", "cc", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_cps, "TCH_cps", "cps", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_minutes, "TCH_minutes", NULL, false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_asr, "TCH_asr_avg", "asr", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_acd, "TCH_acd_avg", "acd", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_ner, "TCH_ner_avg", "ner", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_seer, "TCH_seer_avg", "seer", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_mos, src_dst == 0 ? "TCH_mos_caller" : "TCH_mos_called", "mos", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_packet_loss, src_dst == 0 ? "TCH_packet_lost_caller" : "TCH_packet_lost_called", "packet_loss", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_jitter, src_dst == 0 ? "TCH_jitter_caller" : "TCH_jitter_called", "jitter", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_delay, src_dst == 0 ? "TCH_delay_caller" : "TCH_delay_called", "delay", false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_price_customer, "TCH_price_customer", NULL, false));
	series->push_back(new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrStat, _cdrStatType_price_operator, "TCH_price_operator", NULL, false));
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
	metrics->push_back(sMetrics("seer", _cdrStatType_seer, _chartValueType_na));
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
	for(vector<cChartSeries*>::iterator iter = series_src.begin(); iter != series_src.end(); iter++) {
		delete *iter;
	}
	series_src.clear();
	for(vector<cChartSeries*>::iterator iter = series_dst.begin(); iter != series_dst.end(); iter++) {
		delete *iter;
	}
	series_dst.clear();
}

void cCdrStat::add(sChartsCallData *call) {
	/*
	static volatile int _c;
	__SYNC_INC(_c);
	cout << " ********** cCdrStat::add " << _c << endl;
	*/
	u_int64_t callbegin_us;
	u_int64_t callend_us;
	int sensor_id;
	vmIP ip_src;
	vmIP ip_dst;
	if(call->type == sChartsCallData::_call) {
		Call *_call = call->call();
		CallBranch *_branch = _call->branch_main();
		sensor_id = _call->useSensorId;
		if(opt_time_precision_in_ms) {
			callbegin_us = _call->calltime_us();
			callend_us = _call->callend_us();
		} else {
			callbegin_us = TIME_S_TO_US(_call->calltime_s());
			callend_us = TIME_S_TO_US(_call->callend_s());
		}
		if(cCdrStat::enableBySrc()) {
			ip_src = _call->getSipcallerip(_branch);
		}
		if(cCdrStat::enableByDst()) {
			ip_dst = _call->getSipcalledip(_branch);
		}
	} else {
		sensor_id = call->tables_content()->getValue_int(_t_cdr, "id_sensor");
		callbegin_us = call->tables_content()->getValue_int(_t_cdr, "calldate");
		callend_us = call->tables_content()->getValue_int(_t_cdr, "callend");
		if(cCdrStat::enableBySrc()) {
			ip_src = call->tables_content()->getValue_ip(_t_cdr, "sipcallerip");
		}
		if(cCdrStat::enableByDst()) {
			ip_dst = call->tables_content()->getValue_ip(_t_cdr, "sipcalledip");
		}
	}
	if(sensor_id < 0) {
		 sensor_id = 0;
	}
	sStatId src, dst;
	src.set(sensor_id, ip_src);
	dst.set(sensor_id, ip_dst);
	u_int32_t callbegin_interval_s = TIME_US_TO_S(callbegin_us) / mainInterval * mainInterval;
	u_int32_t callend_interval_s = TIME_US_TO_S_ceil_ms(callend_us) / mainInterval * mainInterval;
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
			interval->setInterval_stat(interval_iter_s, interval_iter_s + mainInterval, src, dst);
			intervals[interval_iter_s] = interval;
		} else {
			interval->init_stat(src, dst);
		}
		unlock_intervals();
		interval->add_stat(call, interval_counter, interval_counter == 0, interval_iter_s == callend_interval_s, interval_counter == 0,
				   callbegin_us, callend_us,
				   src, dst);
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
	init_series(&series, 0);
	fields->push_back(dstring("count_all", "int unsigned"));
	fields->push_back(dstring("count_connected", "int unsigned"));
	fields->push_back(dstring("count_lsr_3", "int unsigned"));
	fields->push_back(dstring("count_lsr_4", "int unsigned"));
	fields->push_back(dstring("count_lsr_5", "int unsigned"));
	fields->push_back(dstring("count_lsr_6", "int unsigned"));
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

bool cCdrStat::exists_columns_check(const char *column, int src_dst) {
	bool exists = false;
	__SYNC_LOCK(exists_column_sync);
	map<string, bool>::iterator iter = exists_columns[src_dst].find(column);
	if(iter != exists_columns[src_dst].end()) {
		exists = iter->second;
	}
	__SYNC_UNLOCK(exists_column_sync);
	return(exists);
}

void cCdrStat::exists_columns_clear(int src_dst) {
	__SYNC_LOCK(exists_column_sync);
	exists_columns[src_dst].clear();
	__SYNC_UNLOCK(exists_column_sync);
}

void cCdrStat::exists_columns_add(const char *column, int src_dst) {
	__SYNC_LOCK(exists_column_sync);
	exists_columns[src_dst][column] = true;
	__SYNC_UNLOCK(exists_column_sync);
}

map<string, bool> cCdrStat::exists_columns[2];
volatile int cCdrStat::exists_column_sync;


cCdrProblems::cListIP::cListIP() {
	load();
	created_at = getTimeS_rdtsc();
}

void cCdrProblems::cListIP::load(SqlDb *sqlDb) {
	bool _createSqlObject = false;
	if(!sqlDb) {
		sqlDb = createSqlObject();
		_createSqlObject = true;
	}
	if(sqlDb->existsTable("cb_ip_groups")) {
		sqlDb->query("select * from cb_ip_groups");
		SqlDb_rows rows;
		sqlDb->fetchRows(&rows);
		SqlDb_row row;
		while((row = rows.fetchRow())) {
			if(atoi(row["server"].c_str())) {
				servers.addComb(row["ip"].c_str());
			}
			if(atoi(row["trunk"].c_str())) {
				trunks.addComb(row["ip"].c_str());
			}
		}
	}
	if(_createSqlObject) {
		delete sqlDb;
	}
}

bool cCdrProblems::cListIP::isFromOwnClients(vmIP &src, vmIP &dst, list<vmIP> &proxy) {
	if(servers.checkIP(dst) && !servers.checkIP(src)) {
		return(true);
	}
	if(!servers.is_empty() && proxy.size() && !trunks.checkIP(src)) {
		for(list<vmIP>::iterator iter = proxy.begin(); iter != proxy.end(); iter++) {
			if(servers.checkIP(*iter)) {
				return(true);
			}
		}
	}
	return(false);
}

bool cCdrProblems::cListIP::isFromOwnServers(vmIP &src) {
	return(servers.checkIP(src));
}

bool cCdrProblems::cListIP::isFromPublicTrunks(vmIP &src) {
	return(trunks.checkIP(src));
}

void cCdrProblems::cListIP::fetch_ip_from_call(sChartsCallData *call, vmIP *src, vmIP *dst, list<vmIP> *proxy) {
	if(call->type == sChartsCallData::_call) {
		if(src) {
			*src = call->call()->getSipcallerip(call->call()->branch_main());
		}
		if(dst) {
			*dst = call->call()->getSipcalledip(call->call()->branch_main());
		}
		if(proxy) {
			for(list<vmIPport>::iterator iter = call->branch_main()->proxies.begin(); iter != call->branch_main()->proxies.end(); iter++) {
				proxy->push_back(iter->ip.getIPv4());
			}
		}
	} else {
		if(src) {
			*src = call->tables_content()->getValue_ip(_t_cdr, "sipcallerip");
		}
		if(dst) {
			*dst = call->tables_content()->getValue_ip(_t_cdr, "sipcalledip");
		}
		if(proxy) {
			int proxy_count = call->tables_content()->getCountRows(_t_cdr_proxy);
			if(proxy_count > 0) {
				for(int i = 0; i < proxy_count; i++) {
					vmIP ip = call->tables_content()->getValue_ip(_t_cdr_proxy, "dst", NULL, i).getIPv4();
					proxy->push_back(ip);
				}
			}
		}
	}
}

cCdrProblems::cCdrProblems() {
	first_interval = 0;
	mainInterval = opt_cdr_problems_interval * 60;
	intervalStore = sverb.cdr_problems_interval_store ? 
			 sverb.cdr_problems_interval_store :
			 (opt_cdr_problems_interval <= 15 ? mainInterval / 3 :
			  opt_cdr_problems_interval <= 30 ? mainInterval / 3 :
			  opt_cdr_problems_interval <= 60 ? mainInterval / 4 :
			  30 * 60);
	intervalCleanup = sverb.cdr_problems_interval_cleanup ?
			   sverb.cdr_problems_interval_cleanup :
			   mainInterval * 2;
	intervalExpiration = absolute_timeout + mainInterval * 2;
	sqlDbStore = NULL;
	last_store_at = 0;
	last_store_at_real = 0;
	last_cleanup_at = 0;
	last_cleanup_at_real = 0;
	sync_intervals = 0;
	list_ip = new FILE_LINE(0) cListIP();
	list_ip->load();
	list_ip_sync = 0;
	list_ip_load_sync = 0;
	list_ip_load_processed = 0;
}

cCdrProblems::~cCdrProblems() {
	if(sqlDbStore) {
		delete sqlDbStore;
	}
	if(list_ip) {
		delete list_ip;
	}
	clear();
}

void cCdrProblems::clear() {
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		delete iter->second;
	}
	intervals.clear();
}

void cCdrProblems::add(sChartsCallData *call) {
	u_int64_t callbegin_us;
	int sensor_id;
	vmIP ip_src;
	vmIP ip_dst;
	list<vmIP> ip_proxy;
	string number_src;
	string number_dst;
	if(call->type == sChartsCallData::_call) {
		Call *_call = call->call();
		CallBranch *_branch = _call->branch_main();
		sensor_id = _call->useSensorId;
		if(opt_time_precision_in_ms) {
			callbegin_us = _call->calltime_us();
		} else {
			callbegin_us = TIME_S_TO_US(_call->calltime_s());
		}
		ip_src = _call->getSipcallerip(_branch);
		ip_dst = _call->getSipcalledip(_branch);
		for(list<vmIPport>::iterator iter = _branch->proxies.begin(); iter != _branch->proxies.end(); iter++) {
			ip_proxy.push_back(iter->ip.getIPv4());
		}
		number_src = _branch->caller;
		number_dst = _call->get_called(_branch);
	} else {
		sensor_id = call->tables_content()->getValue_int(_t_cdr, "id_sensor");
		callbegin_us = call->tables_content()->getValue_int(_t_cdr, "calldate");
		ip_src = call->tables_content()->getValue_ip(_t_cdr, "sipcallerip");
		ip_dst = call->tables_content()->getValue_ip(_t_cdr, "sipcalledip");
		int proxy_count = call->tables_content()->getCountRows(_t_cdr_proxy);
		if(proxy_count > 0) {
			for(int i = 0; i < proxy_count; i++) {
				vmIP ip = call->tables_content()->getValue_ip(_t_cdr_proxy, "dst", NULL, i).getIPv4();
				ip_proxy.push_back(ip);
			}
		}
		number_src = call->tables_content()->getValue_str(_t_cdr, "caller");
		number_dst = call->tables_content()->getValue_str(_t_cdr, "called");
	}
	if(sensor_id < 0) {
		 sensor_id = 0;
	}
	for(int pt = _pt_all; pt <= _pt_from_public_trunks; pt++) {
		bool ok_type = false;
		lock_list_ip();
		switch(pt) {
		case _pt_all:
			ok_type = true;
			break;
		case _pt_from_own_clients:
			if(list_ip->isFromOwnClients(ip_src, ip_dst, ip_proxy)) {
				ok_type = true;
			}
			break;
		case _pt_from_own_servers:
			if(list_ip->isFromOwnServers(ip_src)) {
				ok_type = true;
			}
			break;
		case _pt_from_public_trunks:
			if(list_ip->isFromPublicTrunks(ip_src)) {
				ok_type = true;
			}
			break;
		}
		unlock_list_ip();
		if(ok_type) {
			sProblemId src, dst;
			src.set(sensor_id, ip_src, number_src, (eProblemType)pt);
			dst.set(sensor_id, ip_dst, number_dst, (eProblemType)pt);
			u_int32_t callbegin_interval_s = TIME_US_TO_S(callbegin_us) / mainInterval * mainInterval;
			cChartInterval* interval = NULL;
			lock_intervals();
			interval = intervals[callbegin_interval_s];
			if(!interval) {
				if(callbegin_interval_s > first_interval) {
					first_interval = callbegin_interval_s;
				}
				interval = new FILE_LINE(0) cChartInterval(_chartTypeUse_cdrProblems);
				interval->setInterval_problems(callbegin_interval_s, callbegin_interval_s + mainInterval, src, dst);
				intervals[callbegin_interval_s] = interval;
			} else {
				interval->init_problems(src, dst);
			}
			unlock_intervals();
			interval->add_problems(call, src, dst);
		}
	}
	extern int opt_cdr_problems_list_ip_refresh_interval;
	if(list_ip->created_at + opt_cdr_problems_list_ip_refresh_interval < getTimeS_rdtsc() && !list_ip_load_sync && !list_ip_load_processed) {
		load_list_ip();
	}
}

void cCdrProblems::store(bool forceAll) {
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

void cCdrProblems::cleanup(bool forceAll) {
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

void cCdrProblems::load_list_ip() {
	if(list_ip_load_sync || list_ip_load_processed) {
		return;
	}
	__SYNC_LOCK(list_ip_load_sync);
	pthread_t thread;
	vm_pthread_create("refresh list ip for record problems", &thread, NULL, cCdrProblems::load_list_ip, this, __FILE__, __LINE__);
}

void *cCdrProblems::load_list_ip(void *arg) {
	cCdrProblems *me = (cCdrProblems*)arg;
	usleep(100000);
	if(me->list_ip_load_processed) {
		__SYNC_UNLOCK(me->list_ip_load_sync);
		return(NULL);
	}
	__SYNC_SET(me->list_ip_load_processed);
	cListIP *list_ip_new = new FILE_LINE(0) cListIP;
	me->lock_list_ip();
	delete me->list_ip;
	syslog(LOG_NOTICE, "cdr problems list ip refreshed");
	me->list_ip = list_ip_new;
	me->unlock_list_ip();
	__SYNC_UNLOCK(me->list_ip_load_sync);
	__SYNC_NULL(me->list_ip_load_processed);
	return(NULL);
}

string cCdrProblems::db_fields(vector<dstring> *fields) {
	vector<dstring> _fields;
	if(!fields) {
		fields = &_fields;
	}
	fields->push_back(dstring("count_all", "int unsigned"));
	fields->push_back(dstring("count_connected", "int unsigned"));
	fields->push_back(dstring("count_mos_lt_31", "int unsigned"));
	fields->push_back(dstring("count_mos_lt_36", "int unsigned"));
	fields->push_back(dstring("count_mos_lt_40", "int unsigned"));
	fields->push_back(dstring("count_interrupted_calls", "int unsigned"));
	fields->push_back(dstring("count_one_way", "int unsigned"));
	fields->push_back(dstring("count_missing_rtp", "int unsigned"));
	fields->push_back(dstring("count_missing_srtp_key", "int unsigned"));
	fields->push_back(dstring("count_fas", "int unsigned"));
	fields->push_back(dstring("count_zerossrc", "int unsigned"));
	fields->push_back(dstring("count_sipalg", "int unsigned"));
	fields->push_back(dstring("count_bye_code_2", "int unsigned"));
	fields->push_back(dstring("count_bye_code_102", "int unsigned"));
	fields->push_back(dstring("count_bye_code_103", "int unsigned"));
	fields->push_back(dstring("count_bye_code_104", "int unsigned"));
	fields->push_back(dstring("count_bye_code_105", "int unsigned"));
	fields->push_back(dstring("count_bye_code_101", "int unsigned"));
	fields->push_back(dstring("count_bye_code_106", "int unsigned"));
	fields->push_back(dstring("count_bye_code_107", "int unsigned"));
	fields->push_back(dstring("count_bye_code_108", "int unsigned"));
	fields->push_back(dstring("count_bye_code_109", "int unsigned"));
	fields->push_back(dstring("count_bye_code_100", "int unsigned"));
	fields->push_back(dstring("count_bye_code_110", "int unsigned"));
	string fields_str;
	for(unsigned i = 0; i < fields->size(); i++) {
		fields_str += "`" + (*fields)[i].str[0] + "` " +
			      (*fields)[i].str[1] + ",\n";
	}
	return(fields_str);
}

bool cCdrProblems::exists_columns_check(const char *column, int by_type) {
	bool exists = false;
	__SYNC_LOCK(exists_column_sync);
	map<string, bool>::iterator iter = exists_columns[by_type].find(column);
	if(iter != exists_columns[by_type].end()) {
		exists = iter->second;
	}
	__SYNC_UNLOCK(exists_column_sync);
	return(exists);
}

void cCdrProblems::exists_columns_clear(int by_type) {
	__SYNC_LOCK(exists_column_sync);
	exists_columns[by_type].clear();
	__SYNC_UNLOCK(exists_column_sync);
}

void cCdrProblems::exists_columns_add(const char *column, int by_type) {
	__SYNC_LOCK(exists_column_sync);
	exists_columns[by_type][column] = true;
	__SYNC_UNLOCK(exists_column_sync);
}

map<string, bool> cCdrProblems::exists_columns[3];
volatile int cCdrProblems::exists_column_sync;


cCdrSummary::cCdrSummary() {
	init();
	first_interval = 0;
	maxValuesPartsForPercentile = 1000;
	mainInterval = opt_cdr_summary_interval * 60;
	intervalStore = sverb.cdr_summary_interval_store ?
			 sverb.cdr_summary_interval_store :
			 mainInterval / 2;
	intervalCleanup = sverb.cdr_summary_interval_cleanup ?
			   sverb.cdr_summary_interval_cleanup :
			   mainInterval * 2;
	intervalExpiration = absolute_timeout + mainInterval * 2;
	sqlDbStore = NULL;
	last_store_at = 0;
	last_store_at_real = 0;
	last_cleanup_at = 0;
	last_cleanup_at_real = 0;
	sync_intervals = 0;
}

cCdrSummary::~cCdrSummary() {
	if(sqlDbStore) {
		delete sqlDbStore;
	}
	clear();
}

void cCdrSummary::init() {
	init_series(&series);
	init_metrics(&metrics);
}

vector<cCdrSummary::sMetricType> cCdrSummary::get_metric_types() {
	vector<sMetricType> rslt;
	if(opt_cdr_summary_only_first_interval) {
		rslt.push_back(sMetricType(_chartType_minutes_all, NULL));
	} else {
		rslt.push_back(sMetricType(_chartType_count, "avg,min,max"));
		rslt.push_back(sMetricType(_chartType_cps, "avg,min,max"));
		rslt.push_back(sMetricType(_chartType_minutes, NULL));
	}
	rslt.push_back(sMetricType(_chartType_acd_avg, NULL));
	rslt.push_back(sMetricType(_chartType_asr_avg, NULL));
	rslt.push_back(sMetricType(_chartType_ner_avg, NULL));
	rslt.push_back(sMetricType(_chartType_seer_avg, NULL));
	rslt.push_back(sMetricType(_chartType_pdd, "avg,perc95,perc99"));
	rslt.push_back(sMetricType(_chartType_pbd, "avg,perc95,perc99"));
	rslt.push_back(sMetricType(_chartType_mos, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_mos_xr_min, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_mos_xr_avg, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_mos_silence_min, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_mos_silence_avg, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_packet_lost_connected, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_jitter, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_delay, "avg,perc95,perc99", true));
	rslt.push_back(sMetricType(_chartType_price_customer, "sum"));
	rslt.push_back(sMetricType(_chartType_price_operator, "sum"));
	return(rslt);
}

void cCdrSummary::init_series(vector<cChartSeries*> *series) {
	vector<sMetricType> metric_types = get_metric_types();
	for(unsigned i = 0; i < metric_types.size(); i++) {
		string chartStr = chartStringFromType(metric_types[i].chartType);
		cChartSeries *_series = new FILE_LINE(0) cChartSeries(_chartTypeUse_cdrSummary, metric_types[i].chartType, chartStr.c_str(), chartStr.substr(4).c_str(), true);
		if(metric_types[i].countValues) {
			_series->setCountValues(true);
		}
		series->push_back(_series);
	}
}

void cCdrSummary::init_metrics(vector<sMetrics> *metrics) {
	vector<sMetricType> metric_types = get_metric_types();
	for(unsigned i = 0; i < metric_types.size(); i++) {
		vector<eChartValueType> value_types;
		vector<string> value_types_str = explode(metric_types[i].valueType, ',');
		if(value_types_str.size()) {
			for(unsigned j = 0; j < value_types_str.size(); j++) {
				eChartValueType value_type = getChartValueTypeFromString(value_types_str[j]);
				if(value_type != _chartValueType_na) {
					value_types.push_back(value_type);
				}
			}
		}
		if(!value_types.size()) {
			value_types.push_back(_chartValueType_na);
		}
		for(unsigned j = 0; j < value_types.size(); j++) {
			string chartStr = chartStringFromType(metric_types[i].chartType);
			const char *valueTypeStr = getChartValueStringFromType(value_types[j]);
			string nameMetric = chartStr.substr(4) + (valueTypeStr ? string("__") + valueTypeStr : "");
			metrics->push_back(sMetrics(nameMetric.c_str(), metric_types[i].chartType, value_types[j]));
		}
	}
}

void cCdrSummary::clear() {
	for(map<u_int32_t, cChartInterval*>::iterator iter = intervals.begin(); iter != intervals.end(); iter++) {
		delete iter->second;
	}
	intervals.clear();
	for(vector<cChartSeries*>::iterator iter = series.begin(); iter != series.end(); iter++) {
		delete *iter;
	}
	series.clear();
}

void cCdrSummary::add(sChartsCallData *call) {
	/*
	static volatile int _c;
	__SYNC_INC(_c);
	cout << " ********** cCdrSummary::add " << _c << endl;
	*/
	u_int64_t callbegin_us;
	u_int64_t callend_us;
	int sensor_id;
	vmIP src_ip;
	vmIP dst_ip;
	string src_number;
	string dst_number;
	int codec;
	bool codec_null;
	int lsr_num;
	bool lsr_num_null;
	string lsr_str;
	if(call->type == sChartsCallData::_call) {
		Call *_call = call->call();
		CallBranch *_branch = _call->branch_main();
		sensor_id = _call->useSensorId;
		if(opt_time_precision_in_ms) {
			callbegin_us = _call->calltime_us();
			callend_us = _call->callend_us();
		} else {
			callbegin_us = TIME_S_TO_US(_call->calltime_s());
			callend_us = TIME_S_TO_US(_call->callend_s());
		}
		src_ip = _call->getSipcallerip(_branch);
		dst_ip = _call->getSipcalledip(_branch);
		src_number = _branch->caller;
		dst_number = _call->get_called(_branch);
		codec = _call->get_payload_rslt();
		lsr_num = _branch->lastSIPresponseNum;
		lsr_str = _branch->lastSIPresponse;
	} else {
		sensor_id = call->tables_content()->getValue_int(_t_cdr, "id_sensor");
		callbegin_us = call->tables_content()->getValue_int(_t_cdr, "calldate");
		callend_us = call->tables_content()->getValue_int(_t_cdr, "callend");
		src_ip = call->tables_content()->getValue_ip(_t_cdr, "sipcallerip");
		dst_ip = call->tables_content()->getValue_ip(_t_cdr, "sipcalledip");
		src_number = call->tables_content()->getValue_string(_t_cdr, "caller");
		dst_number = call->tables_content()->getValue_string(_t_cdr, "called");
		codec = call->tables_content()->getValue_int(_t_cdr, "payload", false, &codec_null);
		if(codec_null) codec = -1;
		lsr_num = call->tables_content()->getValue_int(_t_cdr, "lastSIPresponseNum", false, &lsr_num_null);
		if(lsr_num_null) lsr_num = -1;
		lsr_str = call->tables_content()->getValue_string(_t_cdr, "lastSIPresponse_id");
	}
	if(sensor_id < 0) {
		 sensor_id = 0;
	}
	if(lsr_str.empty() && lsr_num == 0) {
		lsr_str = "000 not response";
	}
	adjustSipResponse(lsr_str);
	sSummaryId sum_id;
	sum_id.set(sensor_id,
		   src_ip, dst_ip, src_number, dst_number,
		   codec, lsr_num, lsr_str,
		   opt_cdr_summary_number_length);
	sSummaryId sum_nc_id;
	if(opt_cdr_summary_number_complete) {
		sum_nc_id.set(sensor_id,
			      src_ip, dst_ip, src_number, dst_number,
			      codec, lsr_num, lsr_str,
			      -1);
	}
	u_int32_t callbegin_interval_s = TIME_US_TO_S(callbegin_us) / mainInterval * mainInterval;
	u_int32_t callend_interval_s = opt_cdr_summary_only_first_interval ?
					callbegin_interval_s :
					TIME_US_TO_S_ceil_ms(callend_us) / mainInterval * mainInterval;
	unsigned interval_counter = 0;
	for(u_int32_t interval_iter_s = callbegin_interval_s; interval_iter_s <= callend_interval_s; interval_iter_s += mainInterval) {
		cChartInterval* interval = NULL;
		lock_intervals();
		interval = intervals[interval_iter_s];
		if(!interval) {
			if(interval_iter_s > first_interval) {
				first_interval = interval_iter_s;
			}
			interval = new FILE_LINE(0) cChartInterval(_chartTypeUse_cdrSummary);
			interval->setInterval_summary(interval_iter_s, interval_iter_s + mainInterval, sum_id, sum_nc_id);
			intervals[interval_iter_s] = interval;
		} else {
			interval->init_summary(sum_id, sum_nc_id);
		}
		unlock_intervals();
		interval->add_summary(call, interval_counter, interval_counter == 0, interval_iter_s == callend_interval_s, interval_counter == 0,
				      callbegin_us, callend_us,
				      sum_id, sum_nc_id);
		++interval_counter;
	}
}

void cCdrSummary::store(bool forceAll) {
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

void cCdrSummary::cleanup(bool forceAll) {
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

string cCdrSummary::db_fields(vector<dstring> *fields) {
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
	fields->push_back(dstring("count_exists_rtp", "int unsigned"));
	for(unsigned i = 0; i < metrics.size(); i++) {
		fields->push_back(dstring(metrics[i].field, chartDbFieldTypeFromType((eChartType)metrics[i].type_series)));
	}
	for(unsigned i = 0; i < series.size(); i++) {
		if(series[i]->countValues) {
			fields->push_back(dstring(series[i]->sourceDataName + "_count",
						  "int unsigned"));
		}
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

bool cCdrSummary::exists_columns_check(const char *column, bool nc) {
	bool exists = false;
	__SYNC_LOCK(exists_column_sync);
	map<string, bool>::iterator iter = exists_columns[nc ? 1 : 0].find(column);
	if(iter != exists_columns[nc ? 1 : 0].end()) {
		exists = iter->second;
	}
	__SYNC_UNLOCK(exists_column_sync);
	return(exists);
}

void cCdrSummary::exists_columns_clear(bool nc) {
	__SYNC_LOCK(exists_column_sync);
	exists_columns[nc ? 1 : 0].clear();
	__SYNC_UNLOCK(exists_column_sync);
}

void cCdrSummary::exists_columns_add(const char *column, bool nc) {
	__SYNC_LOCK(exists_column_sync);
	exists_columns[nc ? 1 : 0][column] = true;
	__SYNC_UNLOCK(exists_column_sync);
}

map<string, bool> cCdrSummary::exists_columns[2];
volatile int cCdrSummary::exists_column_sync;


void sFilterCache_call_ipv4_comb::set(sChartsCallData *call) {
	u.a[1] = 0;
	if(call->type == sChartsCallData::_call) {
		CallBranch *c_branch = call->call()->branch_main();
		u.d.src = c_branch->sipcallerip[0].getIPv4();
		u.d.dst = c_branch->sipcalledip_rslt.getIPv4();
		unsigned proxies_counter = 0;
		for(list<vmIPport>::iterator iter = call->branch_main()->proxies.begin(); iter != call->branch_main()->proxies.end(); iter++) {
			u.d.proxy[proxies_counter++] = iter->ip.getIPv4();
			if(proxies_counter == sizeof(u.d.proxy) / sizeof(u.d.proxy[0]) - 1) {
				break;
			}
		}
	} else {
		u.d.src = call->tables_content()->getValue_ip(_t_cdr, "sipcallerip").getIPv4();
		u.d.dst = call->tables_content()->getValue_ip(_t_cdr, "sipcalledip").getIPv4();
		int proxy_count = call->tables_content()->getCountRows(_t_cdr_proxy);
		if(proxy_count > 0) {
			for(int i = 0; i < min((int)(sizeof(u.d.proxy) / sizeof(u.d.proxy[0])), proxy_count); i++) {
				u.d.proxy[i] = call->tables_content()->getValue_ip(_t_cdr_proxy, "dst", NULL, i).getIPv4();
			}
		}
	}
}

#if VM_IPV6
void sFilterCache_call_ipv6_comb::set(sChartsCallData *call) {
	proxy[0].clear();
	proxy[1].clear();
	if(call->type == sChartsCallData::_call) {
		CallBranch *c_branch = call->call()->branch_main();
		src = c_branch->sipcallerip[0].getIPv6();
		dst = c_branch->sipcalledip_rslt.getIPv6();
		unsigned proxies_counter = 0;
		for(list<vmIPport>::iterator iter = call->branch_main()->proxies.begin(); iter != call->branch_main()->proxies.end(); iter++) {
			proxy[proxies_counter++] = iter->ip;
			if(proxies_counter == sizeof(proxy) / sizeof(proxy[0]) - 1) {
				break;
			}
		}
		while(proxies_counter < sizeof(proxy) / sizeof(proxy[0])) {
			proxy[proxies_counter++].clear();
		}
	} else {
		src = call->tables_content()->getValue_ip(_t_cdr, "sipcallerip");
		dst = call->tables_content()->getValue_ip(_t_cdr, "sipcalledip");
		unsigned proxies_counter = 0;
		int proxy_count = call->tables_content()->getCountRows(_t_cdr_proxy);
		if(proxy_count > 0) {
			while(proxies_counter < min((unsigned)(sizeof(proxy) / sizeof(proxy[0])), (unsigned)proxy_count)) {
				proxy[proxies_counter] = call->tables_content()->getValue_ip(_t_cdr_proxy, "dst", NULL, proxies_counter);
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

sChartType *getChartTypes() {
	static sChartType types[] = {
		{ "TCH_total", _chartType_total },
		{ "TCH_count", _chartType_count },
		{ "TCH_cps", _chartType_cps },
		{ "TCH_minutes", _chartType_minutes },
		{ "TCH_minutes_all", _chartType_minutes_all },
		{ "TCH_count_perc_short", _chartType_count_perc_short },
		{ "TCH_response_time_100", _chartType_response_time_100 },
		{ "TCH_mos", _chartType_mos },
		{ "TCH_mos_caller", _chartType_mos_caller },
		{ "TCH_mos_called", _chartType_mos_called },
		{ "TCH_mos_xr_avg", _chartType_mos_xr_avg },
		{ "TCH_mos_xr_avg_caller", _chartType_mos_xr_avg_caller },
		{ "TCH_mos_xr_avg_called", _chartType_mos_xr_avg_called},
		{ "TCH_mos_xr_min", _chartType_mos_xr_min },
		{ "TCH_mos_xr_min_caller", _chartType_mos_xr_min_caller },
		{ "TCH_mos_xr_min_called", _chartType_mos_xr_min_called },
		{ "TCH_mos_silence_avg", _chartType_mos_silence_avg },
		{ "TCH_mos_silence_avg_caller", _chartType_mos_silence_avg_caller },
		{ "TCH_mos_silence_avg_called", _chartType_mos_silence_avg_called},
		{ "TCH_mos_silence_min", _chartType_mos_silence_min },
		{ "TCH_mos_silence_min_caller", _chartType_mos_silence_min_caller },
		{ "TCH_mos_silence_min_called", _chartType_mos_silence_min_called },
		{ "TCH_mos_lqo_caller", _chartType_mos_lqo_caller },
		{ "TCH_mos_lqo_called", _chartType_mos_lqo_called },
		{ "TCH_packet_lost", _chartType_packet_lost },
		{ "TCH_packet_lost", _chartType_packet_lost_connected },
		{ "TCH_packet_lost_caller", _chartType_packet_lost_caller },
		{ "TCH_packet_lost_caller", _chartType_packet_lost_caller_connected },
		{ "TCH_packet_lost_called", _chartType_packet_lost_called },
		{ "TCH_packet_lost_called", _chartType_packet_lost_called_connected },
		{ "TCH_jitter", _chartType_jitter },
		{ "TCH_jitter_caller", _chartType_jitter_caller },
		{ "TCH_jitter_called", _chartType_jitter_called },
		{ "TCH_delay", _chartType_delay },
		{ "TCH_delay_caller", _chartType_delay_caller },
		{ "TCH_delay_called", _chartType_delay_called },
		{ "TCH_rtcp_avgjitter", _chartType_rtcp_avgjitter },
		{ "TCH_rtcp_maxjitter", _chartType_rtcp_maxjitter },
		{ "TCH_rtcp_avgfr", _chartType_rtcp_avgfr },
		{ "TCH_rtcp_maxfr", _chartType_rtcp_maxfr },
		{ "TCH_rtcp_avgrtd", _chartType_rtcp_avgrtd },
		{ "TCH_rtcp_maxrtd", _chartType_rtcp_maxrtd },
		{ "TCH_rtcp_avgrtd_w", _chartType_rtcp_avgrtd_w },
		{ "TCH_rtcp_maxrtd_w", _chartType_rtcp_maxrtd_w },
		{ "TCH_silence", _chartType_silence },
		{ "TCH_silence_caller", _chartType_silence_caller },
		{ "TCH_silence_called", _chartType_silence_called },
		{ "TCH_silence_end", _chartType_silence_end },
		{ "TCH_silence_end_caller", _chartType_silence_end_caller },
		{ "TCH_silence_end_called", _chartType_silence_end_called },
		{ "TCH_clipping", _chartType_clipping },
		{ "TCH_clipping_caller", _chartType_clipping_caller },
		{ "TCH_clipping_called", _chartType_clipping_called },
		{ "TCH_pdd", _chartType_pdd },
		{ "TCH_pbd", _chartType_pbd },
		{ "TCH_acd_avg", _chartType_acd_avg },
		{ "TCH_acd", _chartType_acd },
		{ "TCH_asr_avg", _chartType_asr_avg },
		{ "TCH_asr", _chartType_asr },
		{ "TCH_ner_avg", _chartType_ner_avg },
		{ "TCH_ner", _chartType_ner },
		{ "TCH_seer_avg", _chartType_seer_avg },
		{ "TCH_seer", _chartType_seer },
		{ "TCH_sipResp", _chartType_sipResp },
		{ "TCH_sipResponse", _chartType_sipResponse },
		{ "TCH_sipResponse_base", _chartType_sipResponse_base },
		{ "TCH_codecs", _chartType_codecs },
		{ "TCH_IP_src", _chartType_IP_src },
		{ "TCH_IP_dst", _chartType_IP_dst },
		{ "TCH_domain_src", _chartType_domain_src },
		{ "TCH_domain_dst", _chartType_domain_dst },
		{ "TCH_caller_countries", _chartType_caller_countries },
		{ "TCH_called_countries", _chartType_called_countries },
		{ "TCH_SIP_src_IP_countries", _chartType_SIP_src_IP_countries },
		{ "TCH_SIP_dst_IP_countries", _chartType_SIP_dst_IP_countries },
		{ "TCH_price_customer", _chartType_price_customer },
		{ "TCH_price_operator", _chartType_price_operator },
		{ NULL, (eChartType)0 }
	};
	return(types);
}

eChartType chartTypeFromString(string chartString) {
	sChartType* types = getChartTypes();
	for(unsigned i = 0; types[i].type; i++) {
		if(types[i].str == chartString) {
			return(types[i].type);
		}
	}
	return(_chartType_na);
}

const char *chartStringFromType(eChartType chartType) {
	sChartType* types = getChartTypes();
	for(unsigned i = 0; types[i].type; i++) {
		if(types[i].type == chartType) {
			return(types[i].str);
		}
	}
	return(NULL);
}

const char *chartDbFieldTypeFromType(eChartType chartType) {
	return(chartType == _chartType_total ||
	       chartType == _chartType_count ||
	       chartType == _chartType_cps ?
		"int unsigned" :
		"double");
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

sValueType *getChartValueTypes() {
	static sValueType value_types[] = {
		{ "cnt",  _chartValueType_cnt },
		{ "sum",  _chartValueType_sum },
		{ "min",  _chartValueType_min },
		{ "max",  _chartValueType_max },
		{ "avg",  _chartValueType_avg },
		{ "perc95",  _chartValueType_perc95 },
		{ "perc99",  _chartValueType_perc99 },
		{ NULL,  (eChartValueType)0 }
	};
	return(value_types);
}

eChartValueType getChartValueTypeFromString(string valueTypeStr) {
	sValueType *value_types = getChartValueTypes();
	for(unsigned i = 0; value_types[i].type; i++) {
		if(value_types[i].str == valueTypeStr) {
			return(value_types[i].type);
		}
	}
	return(_chartValueType_na);
}

const char *getChartValueStringFromType(eChartValueType valueType) {
	sValueType *value_types = getChartValueTypes();
	for(unsigned i = 0; value_types[i].type; i++) {
		if(value_types[i].type == valueType) {
			return(value_types[i].str);
		}
	}
	return(NULL);
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


void cdrProblemsInit(SqlDb *sqlDb) {
	cdrProblems = new FILE_LINE(0) cCdrProblems();
}

void cdrProblemsTerm() {
	if(cdrProblems) {
		delete cdrProblems;
		cdrProblems = NULL;
	}
}

bool cdrProblemsIsSet() {
	return(cdrProblems != NULL);
}

void cdrProblemsAddCall(sChartsCallData *call) {
	if(cdrProblems) {
		cdrProblems->add(call);
	}
}

void cdrProblemsStore(bool forceAll) {
	if(cdrProblems) {
		cdrProblems->store(forceAll);
	}
}

void cdrProblemsCleanup(bool forceAll) {
	if(cdrProblems) {
		cdrProblems->cleanup(forceAll);
	}
}


void cdrSummaryInit(SqlDb *sqlDb) {
	cdrSummary = new FILE_LINE(0) cCdrSummary();
}

void cdrSummaryTerm() {
	if(cdrSummary) {
		delete cdrSummary;
		cdrSummary = NULL;
	}
}

bool cdrSummaryIsSet() {
	return(cdrSummary != NULL);
}

void cdrSummaryAddCall(sChartsCallData *call) {
	if(cdrSummary) {
		cdrSummary->add(call);
	}
}

void cdrSummaryStore(bool forceAll) {
	if(cdrSummary) {
		cdrSummary->store(forceAll);
	}
}

void cdrSummaryCleanup(bool forceAll) {
	if(cdrSummary) {
		cdrSummary->cleanup(forceAll);
	}
}
