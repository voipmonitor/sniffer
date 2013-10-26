#ifndef CLEANSPOOL_H
#define CLEANSPOOL_H

void *clean_spooldir_run(void *dummy);
void check_spooldir_filesindex(const char *path = NULL, const char *dirfilter = NULL);
void convert_filesindex();

#endif