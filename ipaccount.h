/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#ifndef IPACCOUNT_H
#define IPACCOUNT_H

void ipaccount(time_t, struct iphdr *, int, int);
int get_customer_by_ip(unsigned int ip, bool use_cache = true, bool deleteSqlDb = false);

typedef struct {
	int all;
	unsigned long long int dst_octects;
	unsigned int dst_numpackets;
	unsigned long long int src_octects;
	unsigned int src_numpackets;
	unsigned long long int voipdst_octects;
	unsigned int voipdst_numpackets;
	unsigned long long int voipsrc_octects;
	unsigned int voipsrc_numpackets;
	unsigned long long int all_octects;
	unsigned long long int voipall_octects;
	unsigned int all_numpackets;
	unsigned int voipall_numpackets;
	unsigned int ipfilter;
	unsigned int fetch_timestamp;
} octects_live_t;

typedef struct {
	unsigned int cust_id;
	unsigned int add_timestamp;
} cust_cache_item;

#endif
