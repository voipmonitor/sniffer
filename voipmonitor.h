/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#ifndef VOIPMONITOR_H

#define RTPSENSOR_VERSION "7.0RC1.SVN"
#define NAT

#define FORMAT_WAV	1
#define FORMAT_OGG	2
#define REGISTER_CLEAN_PERIOD 60	// clean register table for expired items every 60 seconds

#define TYPE_SIP 1
#define TYPE_RTP 2
#define TYPE_RTCP 3
#define TYPE_SKINNY 4

#define STORE_PROC_ID_IPACC 91
#define STORE_PROC_ID_IPACC_AGR_HOUR 92
#define STORE_PROC_ID_IPACC_AGR_DAY 93
#define STORE_PROC_ID_IPACC_AGR2_HOUR_1 94
#define STORE_PROC_ID_IPACC_AGR2_HOUR_2 95
#define STORE_PROC_ID_IPACC_AGR2_HOUR_3 96
#define STORE_PROC_ID_IPACC_AGR2_DAY_1 97
#define STORE_PROC_ID_IPACC_AGR2_DAY_2 98
#define STORE_PROC_ID_IPACC_AGR2_DAY_3 99


/* choose what method wil be used to synchronize threads. NONBLOCK is the fastest. Do not enable both at once */
// this is now defined in Makefile 
//#define QUEUE_NONBLOCK 
//#define QUEUE_MUTEX 

/* if you want to see all new calls in syslog enable DEBUG_INVITE */
//#define DEBUG_INVITE

void reload_config();
void reload_capture_rules();

#define VOIPMONITOR_H
#endif

