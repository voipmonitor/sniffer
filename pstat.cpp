#include <stdlib.h> 
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "voipmonitor.h"
#include "pstat.h"

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
		perror("pstat fopen error (/proc/[pid]/task/[taskid]/stat) ");
		#endif
		return(false);
	}
	FILE *fstat = fopen("/proc/stat", "r");
	if(fstat == NULL) {
		#ifndef FREEBSD
		perror("pstat fopen error (/proc/stat) ");
		#endif
		fclose(fpstat);
		return(false);
	}
	memset(result, 0, sizeof(pstat_data));
	long int rss = 0;
	if(fscanf(fpstat, 
		  "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu"
		  "%lu %ld %ld %*d %*d %*d %*d %*u %lu %ld",
			&result->utime_ticks, &result->stime_ticks,
			&result->cutime_ticks, &result->cstime_ticks, &result->vsize,
			&rss) == EOF) {
		fclose(fpstat);
		fclose(fstat);
		return(false);
	}
	fclose(fpstat);
	result->rss = rss * getpagesize();
	long unsigned int cpu_time[10];
	memset(cpu_time, 0, sizeof(cpu_time));
	if(fscanf(fstat, 
		  "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
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