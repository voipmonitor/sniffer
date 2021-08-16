#ifndef PROC_LIMIT_H
#define PROC_LIMIT_H


class cProcessingLimitations {
public:
	enum eType {
		_pl_rtp = 1,
		_pl_active_calls = 2,
		_pl_all = 3,
	};
public:
	cProcessingLimitations() {
		init();
	}
	void init() {
		last_change_suppress_rtp_time_s = 0;
		last_change_active_calls_cache_timeout_time_s = 0;
		suppress_rtp_read = false;
		suppress_rtp_selective_processing = false;
		suppress_rtp_all_processing = false;
		extern int opt_processing_limitations_active_calls_cache_type;
		extern int opt_processing_limitations_active_calls_cache_timeout_min;
		extern int opt_processing_limitations_active_calls_cache_timeout_max;
		active_calls_cache_timeout_min = opt_processing_limitations_active_calls_cache_timeout_min ?
						  opt_processing_limitations_active_calls_cache_timeout_min :
						  (opt_processing_limitations_active_calls_cache_type == 1 ? 2 : 10);
		active_calls_cache_timeout_max = opt_processing_limitations_active_calls_cache_timeout_max ?
						  opt_processing_limitations_active_calls_cache_timeout_max :
						  (opt_processing_limitations_active_calls_cache_type == 1 ? 10 : 30);
		active_calls_cache_timeout = active_calls_cache_timeout_min;
		minimum_validity_of_change_s = 30;
	}
	void incLimitations(eType type, bool force = false);
	void decLimitations(eType type, bool force = false);
	inline bool suppressRtpRead() {
		return(suppress_rtp_read);
	}
	inline bool suppressRtpSelectiveProcessing() {
		return(suppress_rtp_selective_processing);
	}
	inline bool suppressRtpAllProcessing() {
		return(suppress_rtp_all_processing);
	}
	inline unsigned activeCallsCacheTimeout() {
		return(active_calls_cache_timeout);
	}
private:
	volatile u_int32_t last_change_suppress_rtp_time_s;
	volatile u_int32_t last_change_active_calls_cache_timeout_time_s;
	volatile bool suppress_rtp_read;
	volatile bool suppress_rtp_selective_processing;
	volatile bool suppress_rtp_all_processing;
	unsigned active_calls_cache_timeout_min;
	unsigned active_calls_cache_timeout_max;
	volatile unsigned active_calls_cache_timeout;
	unsigned minimum_validity_of_change_s;
};


#endif
