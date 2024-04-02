#ifndef TOOLS_RDTSC_H
#define TOOLS_RDTSC_H


#include <math.h>
#include <sstream>

#include "common.h"


#if defined(__i386__)
__inline__ unsigned long long rdtsc(void)
{
    unsigned long long int x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}
#elif defined(__x86_64__)
__inline__ unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}
#endif


extern u_int64_t rdtsc_by_250ms;


inline void init_rdtsc_interval() {
	#if defined(__i386__) or  defined(__x86_64__)
	u_int64_t rdtsc_by_250ms_v[2] = { 0, 0 };
	for(int i = 0; i < 5; i++) {
		u_int64_t _rdtsc_1 = rdtsc();
		usleep(250000);
		u_int64_t _rdtsc_2 = rdtsc();
		usleep(0);
		u_int64_t _rdtsc_3 = rdtsc();
		#ifdef CLOUD_ROUTER_CLIENT
		extern sVerbose sverb;
		if(sverb.rdtsc) {
			std::ostringstream ostr;
			ostr << _rdtsc_1 << " / " 
			     << _rdtsc_2 << " / " 
			     << _rdtsc_3 << " // "
			     << (_rdtsc_2 > _rdtsc_1) << " / "
			     << (_rdtsc_3 > _rdtsc_2) << " / "
			     << ((_rdtsc_2 - _rdtsc_1) > (_rdtsc_3 - _rdtsc_2)) << " // "
			     << _rdtsc_2 - _rdtsc_1 - (_rdtsc_3 - _rdtsc_2);
			syslog(LOG_NOTICE, "init_rdtsc_interval iter %i : %s", (i + 1), ostr.str().c_str());
		}
		#endif
		if(_rdtsc_2 > _rdtsc_1 && _rdtsc_3 >= _rdtsc_2 &&
		   (_rdtsc_2 - _rdtsc_1) > (_rdtsc_3 - _rdtsc_2)) {
			rdtsc_by_250ms_v[0] = rdtsc_by_250ms_v[1];
			rdtsc_by_250ms_v[1] = _rdtsc_2 - _rdtsc_1 - (_rdtsc_3 - _rdtsc_2);
			if(rdtsc_by_250ms_v[0] && rdtsc_by_250ms_v[1] &&
			   fabs(1 - (double)rdtsc_by_250ms_v[0] / rdtsc_by_250ms_v[1]) < 0.01) {
				rdtsc_by_250ms = (rdtsc_by_250ms_v[0] + rdtsc_by_250ms_v[1]) / 2;
				#ifdef CLOUD_ROUTER_CLIENT
				if(sverb.rdtsc) {
					std::ostringstream ostr;
					ostr << rdtsc_by_250ms;
					syslog(LOG_NOTICE, "init_rdtsc_interval set: %s", ostr.str().c_str());
				}
				#endif
				break;
			}
		}
	}
	#endif
}

inline u_int64_t getTimeMS_rdtsc() {
	#if defined(__i386__) or defined(__x86_64__)
	static __thread u_int64_t last_time = 0;
	static __thread u_int64_t last_rdtsc = 0;
	if(rdtsc_by_250ms && last_rdtsc) {
		u_int64_t diff_rdtsc;
		u_int64_t act_rdtsc = rdtsc();
		if(act_rdtsc > last_rdtsc &&
		   (diff_rdtsc = (act_rdtsc - last_rdtsc)) < rdtsc_by_250ms * 4 * 10) {
			return(last_time + diff_rdtsc * 250 / rdtsc_by_250ms);
		}
	}
	#endif
	timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	#if defined(__i386__) or defined(__x86_64__)
	last_time = time.tv_sec * 1000ull + time.tv_nsec / 1000000;
	last_rdtsc = rdtsc();
	return(last_time);
	#else
	return(time.tv_sec * 1000ull + time.tv_nsec / 1000000);
	#endif
}

inline u_int32_t getTimeS_rdtsc() {
	return(getTimeMS_rdtsc() / 1000);
}


#endif
