#ifndef SKINNY_H
#define SKINNY_H

void *handle_skinny(pcap_pkthdr *, const u_char *, unsigned int, int, unsigned int, int, char *, int, int,
		    pcap_t *handle, int dlt, int sensor_id, u_int32_t sensor_ip);

#endif
