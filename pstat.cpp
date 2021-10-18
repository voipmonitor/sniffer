#include <stdlib.h> 
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <algorithm>

#include "voipmonitor.h"
#include "pstat.h"


using namespace std;

extern bool opt_interrupts_counters;
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

double get_cpu_usage_perc(const int pid, pstat_data *data) {
	if(pid) {
		if(data[0].cpu_total_time) {
			data[1] = data[0];
		}
		pstat_get_data(pid, data);
		double ucpu_usage, scpu_usage;
		if(data[0].cpu_total_time && data[1].cpu_total_time) {
			pstat_calc_cpu_usage_pct(&data[0], &data[1], &ucpu_usage, &scpu_usage);
			return(ucpu_usage + scpu_usage);
		}
	}
	return(-1);
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
	int vm_cpu_count = get_cpu_count();
	bool vm_cpu_ht = get_cpu_ht();
	double la[3];
	getLoadAvg(&la[0], &la[1], &la[2]);
	bool overload = false;
	for(int i = 0; i < 3; i++) {
		if(la[i] > ((double)vm_cpu_count * (vm_cpu_ht ? 3./4 : 1))) {
			overload = true;
		}
	}
	char buff_rslt[100];
	snprintf(buff_rslt, sizeof(buff_rslt), 
		 "%sLA[%.2lf %.2lf %.2lf|%d%s]", 
		 overload ? "*" : "",
		 la[0], la[1], la[2], vm_cpu_count,
		 vm_cpu_ht ? "h" : "");
	return(buff_rslt);
}

bool get_cpu_ht() {
	static int vm_cpu_ht = -1;
        if(vm_cpu_ht < 0) {
		vm_cpu_ht=0;
		std::ifstream input("/proc/cpuinfo");
		std::string line;
		std::string needle("ht");
		while( std::getline( input, line ))
			if (!line.compare( 0, 5, "flags" )) {
				std::size_t found = line.find(needle);
				if(found == std::string::npos) continue;
				vm_cpu_ht=1;
			}
	}
        return(vm_cpu_ht);
}

int get_cpu_count() {
	static int vm_cpu_count = -1;
	if(vm_cpu_count < 0) {
		vm_cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
	}
	return(vm_cpu_count);
	
}

bool get_interrupts_counters(map<string, pair<string, u_int64_t> > *counters) {
	// If interrupt counters are disabled from config do nothing
	if(!opt_interrupts_counters)
	    return false;

	FILE *fint = fopen("/proc/interrupts", "r");
	if(fint == NULL) {
		#ifndef FREEBSD
		if(!pstat_quietly_errors) {
			perror("pstat fopen error (/proc/interrupts) ");
		}
		#endif
		return(false);
	}
	char line[10000];
	unsigned linesCounter = 0;
	unsigned countCpu = 0;
	while(fgets(line, sizeof(line), fint)) {
		++linesCounter;
		unsigned lineLength = strlen(line);
		if(line[lineLength - 1] == '\n') {
			line[lineLength - 1] = 0;
			--lineLength;
		}
		if(linesCounter == 1) {
			char *ptr = line;
			while(*ptr) {
				while(*ptr == ' ' || *ptr == '\t') {
					++ptr;
				}
				if(!strncasecmp(ptr, "CPU", 3)) {
					++countCpu;
				}
				++ptr;
			}
		} else {
			string typeInt;
			string descrInt;
			u_int64_t count = 0;
			unsigned countItems = 0;
			char *ptr = line;
			while(*ptr) {
				while(*ptr == ' ' || *ptr == '\t') {
					++ptr;
				}
				char *ptrEnd = ptr;
				while(*ptrEnd &&
				      !(*ptrEnd == ' ' || *ptrEnd == '\t')) {
					++ptrEnd;
				}
				if(countItems == 0) {
					typeInt = string(ptr, ptrEnd - ptr);
					if(typeInt[typeInt.length() - 1] == ':') {
						typeInt.resize(typeInt.length() - 1);
					}
					std::transform(typeInt.begin(), typeInt.end(), typeInt.begin(), ::tolower);
				} else if(countItems <= countCpu) {
					count += atoll(ptr);
				} else {
					descrInt = string(ptr);
					break;
				}
				++countItems;
				ptr = ptrEnd + 1;
			}
			pair<string, u_int64_t> descrCount;
			descrCount.first = descrInt;
			descrCount.second  = count;
			(*counters)[typeInt] = descrCount;
		}
	}
	fclose(fint);
	return(true);
}
