#include <stdlib.h> 
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "voipmonitor.h"
#include "pstat.h"


bool pstat_quietly_errors = false;


bool pstat_get_data(const int pid, pstat_data* result) {
	char stat_filepath[100]; 
	//sprintf(stat_filepath, "/proc/%u/stat", pid);
	
	if(pid) {
		sprintf(stat_filepath, "/proc/%u/task/%u/stat", getpid(), pid);
	} else {
		sprintf(stat_filepath, "/proc/%u/stat", getpid());
	}
	
	FILE *fpstat = fopen(stat_filepath, "r");
	if(fpstat == NULL) {
		#ifndef FREEBSD
		if(!pstat_quietly_errors) {
			perror("pstat fopen error (/proc/[pid]/task/[taskid]/stat) ");
		}
		#endif
		return(false);
	}
	FILE *fstat = fopen("/proc/stat", "r");
	if(fstat == NULL) {
		#ifndef FREEBSD
		if(!pstat_quietly_errors) {
			perror("pstat fopen error (/proc/stat) ");
		}
		#endif
		fclose(fpstat);
		return(false);
	}
	memset(result, 0, sizeof(pstat_data));
	long long int rss = 0;
	if(fscanf(fpstat, 
		  "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu"
		  "%llu %lld %lld %*d %*d %*d %*d %*u %llu %lld",
			&result->utime_ticks, &result->stime_ticks,
			&result->cutime_ticks, &result->cstime_ticks, &result->vsize,
			&rss) == EOF) {
		fclose(fpstat);
		fclose(fstat);
		return(false);
	}
	fclose(fpstat);
	result->rss = rss * getpagesize();
	long long unsigned int cpu_time[10];
	memset(cpu_time, 0, sizeof(cpu_time));
	if(fscanf(fstat, 
		  "%*s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			&cpu_time[0], &cpu_time[1], &cpu_time[2], &cpu_time[3],
			&cpu_time[4], &cpu_time[5], &cpu_time[6], &cpu_time[7],
			&cpu_time[8], &cpu_time[9]) == EOF) {
		fclose(fstat);
		return(false);
	}
	fclose(fstat);
	for(int i = 0; i < 10 ; i++) {
		result->cpu_total_time += cpu_time[i];
	}
	return(true);
}

void pstat_calc_cpu_usage_pct(const pstat_data* cur_usage,
			      const pstat_data* last_usage,
			      double* ucpu_usage, double* scpu_usage) {
    const long unsigned int total_time_diff = cur_usage->cpu_total_time - last_usage->cpu_total_time;
    const int cpuCore = sysconf(_SC_NPROCESSORS_ONLN);
    *ucpu_usage = 100 * (((cur_usage->utime_ticks + cur_usage->cutime_ticks)
				- (last_usage->utime_ticks + last_usage->cutime_ticks))
			/ (double) total_time_diff) * cpuCore;
    *scpu_usage = 100 * ((((cur_usage->stime_ticks + cur_usage->cstime_ticks)
				- (last_usage->stime_ticks + last_usage->cstime_ticks))) /
			(double) total_time_diff) * cpuCore;
}

void pstat_calc_cpu_usage(const pstat_data* cur_usage,
			  const pstat_data* last_usage,
			  long unsigned int* ucpu_usage,
			  long unsigned int* scpu_usage) {
    *ucpu_usage = (cur_usage->utime_ticks + cur_usage->cutime_ticks)
			- (last_usage->utime_ticks + last_usage->cutime_ticks);
    *scpu_usage = (cur_usage->stime_ticks + cur_usage->cstime_ticks)
			- (last_usage->stime_ticks + last_usage->cstime_ticks);
}

long unsigned int getRss() {
	pstat_data pstatData;
	if(pstat_get_data(0, &pstatData)) {
		return(pstatData.rss);
	} else {
		return(0);
	}
}

void getLoadAvg(double *la_1, double *la_5, double *la_15) {
	if(la_1) *la_1 = 0;
	if(la_5) *la_5 = 0;
	if(la_15) *la_15 = 0;
	FILE *fla_stat = fopen("/proc/loadavg", "r");
	if(fla_stat) {
		double _la_1, _la_5, _la_15;
		int rslt_fscanf = fscanf(fla_stat, "%lf %lf %lf", &_la_1, &_la_5, &_la_15);
		if(rslt_fscanf >= 3 && la_15) *la_15 = _la_15;
		if(rslt_fscanf >= 2 && la_5) *la_5 = _la_5;
		if(rslt_fscanf >= 1 && la_1) *la_1 = _la_1;
		fclose(fla_stat);
	}
}

std::string getLoadAvgStr() {
	double la_1, la_5, la_15;
	getLoadAvg(&la_1, &la_5, &la_15);
	char buff_rslt[20];
	snprintf(buff_rslt, sizeof(buff_rslt), "%.2lf %.2lf %.2lf", la_1, la_5, la_15);
	return(buff_rslt);
}
