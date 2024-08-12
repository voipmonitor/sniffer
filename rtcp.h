#ifndef RTCP_H
#define RTCP_H

void parse_rtcp(char *data, int datalen, timeval *ts, CallBranch *c_branch,
		vmIP ip_src, vmPort port_src, vmIP ip_dst, vmPort port_dst, bool srtcp = false);

#endif
