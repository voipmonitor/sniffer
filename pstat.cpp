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
	//snprintf(stat_filepath, sizeof(stat_filepath), "/proc/%u/stat", pid);
	
	if(pid) {
		snprintf(stat_filepath, sizeof(stat_filepath), "/proc/%u/task/%u/stat", getpid(), pid);
	} else {
		snprintf(stat_filepath, sizeof(stat_filepath), "/proc/%u/stat", getpid());
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
	unsigned long long int usertime, nicetime, systemtime, idletime;
	unsigned long long int ioWait, irq, softIrq, steal, guest, guestnice;
	if(fscanf(fstat, 
		  "cpu  %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			&usertime, &nicetime, &systemtime, &idletime, 
			&ioWait, &irq, &softIrq, &steal, &guest, &guestnice) == EOF) {
		fclose(fstat);
		return(false);
	}
	fclose(fstat);
	unsigned long long int idlealltime = idletime + ioWait;
	unsigned long long int systemalltime = systemtime + irq + softIrq;
	unsigned long long int virtalltime = guest + guestnice;
	unsigned long long int totaltime = usertime + nicetime + systemalltime + idlealltime + steal + virtalltime;
	result->cpu_total_time = totaltime;
	return(true);
}

void pstat_calc_cpu_usage_pct(const pstat_data* cur_usage,
			      const pstat_data* last_usage,
			      double* ucpu_usage, double* scpu_usage) {
	const long unsigned int total_time_diff = cur_usage->cpu_total_time - last_usage->cpu_total_time;
	static int cpuCore = 0;
	if(cpuCore == 0) {
		cpuCore = sysconf(_SC_NPROCESSORS_ONLN);
	}
	static double jiffy = 0.0;
	if(jiffy == 0.0) {
		jiffy = sysconf(_SC_CLK_TCK);
	}
	double jiffytime = 1.0 / jiffy * 100;
	*ucpu_usage = 100 * ((cur_usage->utime_ticks - last_usage->utime_ticks) / (double) total_time_diff) * jiffytime * cpuCore;
	*scpu_usage = 100 * ((cur_usage->stime_ticks - last_usage->stime_ticks) / (double) total_time_diff) * jiffytime * cpuCore;
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
