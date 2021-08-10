#ifndef PROC_LIMIT_H
#define PROC_LIMIT_H


class cProcessingLimitations {
public:
	cProcessingLimitations() {
		last_change_suppress_rtp_time_s = 0;
		last_change_active_calls_cache_timeout_time_s = 0;
		suppress_rtp_read = false;
		suppress_rtp_processing = false;
		active_calls_cache_timeout = 2;
		minimum_validity_of_change_s = 30;
	}
	void incLimitations(bool force = false);
	void decLimitations(bool force = false);
	inline bool suppressRtpRead() {
		return(suppress_rtp_read);
	}
	inline bool suppressRtpProcessing() {
		return(suppress_rtp_processing);
	}
	inline unsigned activeCallsCacheTimeout() {
		return(active_calls_cache_timeout);
	}
private:
	volatile u_int32_t last_change_suppress_rtp_time_s;
	volatile u_int32_t last_change_active_calls_cache_timeout_time_s;
	volatile bool suppress_rtp_read;
	volatile bool suppress_rtp_processing;
	volatile unsigned active_calls_cache_timeout;
	unsigned minimum_validity_of_change_s;
};


#endif
