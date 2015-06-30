#ifndef CLEANSPOOL_H
#define CLEANSPOOL_H

void *clean_spooldir_run(void *dummy);
void check_spooldir_filesindex(const char *path = NULL, const char *dirfilter = NULL);
void convert_filesindex();
long long reindex_date(string date);
long long reindex_date_hour(string date, int h, bool readOnly = false, map<string, long long> *typeSize = NULL, bool quickCheck = false);
void check_filesindex();
void check_disk_free_run(bool enableRunCleanSpoolThread);
void run_check_disk_free_thread();
bool check_exists_act_records_in_files();
bool check_exists_act_files_in_filesindex();
void clean_obsolete_dirs(const char *path = NULL);
bool isSetCleanspoolParameters();
void runCleanSpoolThread();
string getMaxSpoolDate();
bool check_datehour(const char *datehour);

#endif

