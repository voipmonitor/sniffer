#ifndef CLEANSPOOL_H
#define CLEANSPOOL_H

void check_spooldir_filesindex(const char *path = NULL, const char *dirfilter = NULL);
void convert_filesindex(const char *reason);
void do_convert_filesindex(const char *reason);
long long reindex_date(string date);
long long reindex_date_hour(string date, int h, bool readOnly = false, map<string, long long> *typeSize = NULL, bool quickCheck = false);
void check_filesindex();
bool check_exists_act_records_in_files();
bool check_exists_act_files_in_filesindex();
void clean_obsolete_dirs(const char *path = NULL);
bool isSetCleanspoolParameters();
void runCleanSpoolThread();
void termCleanSpoolThread();
string getMaxSpoolDate();
bool check_datehour(const char *datehour);

#endif

