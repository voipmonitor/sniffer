#include "voipmonitor.h"

#include "sql_db.h"
#include "proc_limit.h"
#include "tools_global.h"


extern bool opt_processing_limitations_active_calls_cache;
extern int opt_processing_limitations_active_calls_cache_type;
cProcessingLimitations processing_limitations;


void cProcessingLimitations::incLimitations(eType type, bool force) {
	u_int32_t time_s = getTimeS();
	if((type & _pl_rtp) &&
	   (force ||
	    !last_change_suppress_rtp_time_s ||
	    (time_s > last_change_suppress_rtp_time_s && time_s - last_change_suppress_rtp_time_s > minimum_validity_of_change_s))) {
		if(!suppress_rtp_read) {
			suppress_rtp_read = true;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "suppress rtp read");
		} else if(!suppress_rtp_selective_processing) {
			suppress_rtp_selective_processing = true;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "suppress rtp selective processing");
		} else if(!suppress_rtp_all_processing) {
			suppress_rtp_all_processing = true;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "suppress rtp all processing");
		}
	}
	if((type & _pl_active_calls) &&
	   opt_processing_limitations_active_calls_cache &&
	   (force ||
	    !last_change_active_calls_cache_timeout_time_s ||
	    (time_s > last_change_active_calls_cache_timeout_time_s && time_s - last_change_active_calls_cache_timeout_time_s > minimum_validity_of_change_s))) {
		int inc = (opt_processing_limitations_active_calls_cache_type == 1 ? 2 : 10);
		if(active_calls_cache_timeout <= active_calls_cache_timeout_max - inc) {
			active_calls_cache_timeout += inc;
			last_change_active_calls_cache_timeout_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations" , "set active calls cache timeout to: %i", active_calls_cache_timeout);
		}
	}
}

void cProcessingLimitations::decLimitations(eType type, bool force) {
	u_int32_t time_s = getTimeS();
	if((type & _pl_rtp) &&
	   (force ||
	    !last_change_suppress_rtp_time_s ||
	    (time_s > last_change_suppress_rtp_time_s && time_s - last_change_suppress_rtp_time_s > minimum_validity_of_change_s))) {
		if(suppress_rtp_all_processing) {
			suppress_rtp_all_processing = false;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "resume rtp all processing");
		} else if(suppress_rtp_selective_processing) {
			suppress_rtp_selective_processing = false;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "resume rtp selective processing");
		} else if(suppress_rtp_read) {
			suppress_rtp_read = false;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "resume rtp read");
		}
	}
	if((type & _pl_active_calls) &&
	   opt_processing_limitations_active_calls_cache &&
	   (force ||
	    !last_change_active_calls_cache_timeout_time_s ||
	    (time_s > last_change_active_calls_cache_timeout_time_s && time_s - last_change_active_calls_cache_timeout_time_s > minimum_validity_of_change_s))) {
		int dec = (opt_processing_limitations_active_calls_cache_type == 1 ? 1 : 5);
		if(active_calls_cache_timeout >= active_calls_cache_timeout_min + dec) {
			active_calls_cache_timeout -= dec;
			last_change_active_calls_cache_timeout_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "set active calls cache timeout to: %i", active_calls_cache_timeout);
		}
	}
}
