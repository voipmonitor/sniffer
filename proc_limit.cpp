#include "voipmonitor.h"

#include "sql_db.h"
#include "proc_limit.h"
#include "tools_global.h"


cProcessingLimitations processing_limitations;


void cProcessingLimitations::incLimitations(bool force) {
	u_int32_t time_s = getTimeS();
	if(force ||
	   !last_change_suppress_rtp_time_s ||
	   (time_s > last_change_suppress_rtp_time_s && time_s - last_change_suppress_rtp_time_s > minimum_validity_of_change_s)) {
		if(!suppress_rtp_read) {
			suppress_rtp_read = true;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "suppress rtp read");
		} else if(!suppress_rtp_processing) {
			suppress_rtp_processing = true;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "suppress rtp processing");
		}
	}
	if(force ||
	   !last_change_active_calls_cache_timeout_time_s ||
	   (time_s > last_change_active_calls_cache_timeout_time_s && time_s - last_change_active_calls_cache_timeout_time_s > minimum_validity_of_change_s)) {
		if(active_calls_cache_timeout < 10) {
			active_calls_cache_timeout += 2;
			last_change_active_calls_cache_timeout_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations" , "set active calls cache timeout to: %i", active_calls_cache_timeout);
		}
	}
}

void cProcessingLimitations::decLimitations(bool force) {
	u_int32_t time_s = getTimeS();
	if(force ||
	   !last_change_suppress_rtp_time_s ||
	   (time_s > last_change_suppress_rtp_time_s && time_s - last_change_suppress_rtp_time_s > minimum_validity_of_change_s)) {
		if(suppress_rtp_processing) {
			suppress_rtp_processing = false;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "resume rtp processing");
		} else if(suppress_rtp_read) {
			suppress_rtp_read = false;
			last_change_suppress_rtp_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "resume rtp read");
		}
	}
	if(force ||
	   !last_change_active_calls_cache_timeout_time_s ||
	   (time_s > last_change_active_calls_cache_timeout_time_s && time_s - last_change_active_calls_cache_timeout_time_s > minimum_validity_of_change_s)) {
		if(active_calls_cache_timeout > 2) {
			--active_calls_cache_timeout;
			last_change_active_calls_cache_timeout_time_s = time_s;
			cLogSensor::log(cLogSensor::notice, "processing limitations", "set active calls cache timeout to: %i", active_calls_cache_timeout);
		}
	}
}
