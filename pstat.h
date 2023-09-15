#ifndef PSTAT_H
#define PSTAT_H


#include <string>
#include <map>


struct pstat_data {
    long long unsigned int utime_ticks;
    long long int cutime_ticks;
    long long unsigned int stime_ticks;
    long long int cstime_ticks;
    long long unsigned int vsize;	// virtual memory size in bytes
    long long unsigned int rss;		// resident set size in bytes
    long long unsigned int cpu_total_time;
};

struct context_switches_data {
    long long unsigned int voluntary;
    long long unsigned int non_voluntary;
};


bool pstat_get_data(const int tid, pstat_data* result);
bool context_switches_get_data(const int tid, context_switches_data* result);
void pstat_calc_cpu_usage_pct(const pstat_data* cur_usage,
			      const pstat_data* last_usage,
			      double* ucpu_usage, double* scpu_usage);
double get_cpu_usage_perc(const int tid, pstat_data *data);
context_switches_data get_context_switches(const context_switches_data* cur, const context_switches_data* last);
long unsigned int getRss();
void getLoadAvg(double *la_1, double *la_5, double *la_15);
std::string getLoadAvgStr();
bool get_cpu_ht();
int get_cpu_count();

bool get_interrupts_counters(std::map<std::string, std::pair<std::string, u_int64_t> > *counters);


#endif

