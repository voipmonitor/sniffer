#ifndef RTCP_H
#define RTCP_H

void parse_rtcp(char *data, int datalen, timeval *ts, Call *call);

#endif
