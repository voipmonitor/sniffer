#ifndef PSTAT_H
#define PSTAT_H


struct pstat_data {
    long unsigned int utime_ticks;
    long int cutime_ticks;
    long unsigned int stime_ticks;
    long int cstime_ticks;
    long unsigned int vsize;	// virtual memory size in bytes
    long unsigned int rss;	// resident set size in bytes
    long unsigned int cpu_total_time;
};


bool pstat_get_data(const uint pid, pstat_data* result);
void pstat_calc_cpu_usage_pct(const pstat_data* cur_usage,
			      const pstat_data* last_usage,
			      double* ucpu_usage, double* scpu_usage);
void pstat_calc_cpu_usage(const pstat_data* cur_usage,
			  const pstat_data* last_usage,
			  long unsigned int* ucpu_usage,
			  long unsigned int* scpu_usage);


#endif