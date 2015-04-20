#include <cstdlib>
#include <iostream>
#include <string>
#include <cmath>
#include <map>
#include <vector>
#include <deque>
#include <deque>

#ifndef FREEBSD
#include <sys/inotify.h>
#endif

#include "calltable.h"
#include "sniff.h"
#include "mirrorip.h"
#include "voipmonitor.h"
#include "sql_db.h"

extern bool existsColumnCalldateInCdrDtmf;
extern bool existsColumnCalldateInCdrNext;
extern bool existsColumnCalldateInCdrRtp;
extern bool opt_cdr_partition;
extern bool opt_disable_partition_operations;
extern bool opt_ipacc_agregate_only_customers_on_any_side;
extern bool opt_ipacc_agregate_only_customers_on_main_side;
extern bool opt_ipacc_sniffer_agregate;
extern bool opt_pcap_queue_compress;
extern pcap_block_store::compress_method opt_pcap_queue_compress_method;
extern Calltable *calltable;
extern char configfile[1024];
extern char daemonizeErrorTempFileName[L_tmpnam+1];
extern char get_customer_by_ip_odbc_driver[256];
extern char get_customer_by_ip_odbc_dsn[256];
extern char get_customer_by_ip_odbc_password[256];
extern char get_customer_by_ip_odbc_user[256];
extern char get_customer_by_ip_query[1024];
extern char get_customer_by_ip_sql_driver[256];
extern char get_customer_by_pn_odbc_driver[256];
extern char get_customer_by_pn_odbc_dsn[256];
extern char get_customer_by_pn_odbc_password[256];
extern char get_customer_by_pn_odbc_user[256];
extern char get_customer_by_pn_sql_driver[256];
extern char get_customers_ip_query[1024];
extern char get_customers_pn_query[1024];
extern char get_customers_radius_name_query[1024];
extern char get_radius_ip_db[256];
extern char get_radius_ip_driver[256];
extern char get_radius_ip_host[256];
extern char get_radius_ip_password[256];
extern char get_radius_ip_query_where[1024];
extern char get_radius_ip_query[1024];
extern char get_radius_ip_user[256];
extern char *httpportmatrix;
extern char *webrtcportmatrix;
extern char ifname[1024];
extern char *ipaccountportmatrix;
extern char mac[32];
extern char mysql_database[256];
extern char mysql_host[256];
extern char mysql_password[256];
extern char mysql_user[256];
extern char odbc_driver[256];
extern char odbc_dsn[256];
extern char odbc_password[256];
extern char odbc_user[256];
extern char opt_cachedir[1024];
extern char opt_clientmanager[1024];
extern char opt_database_backup_from_date[20];
extern char opt_chdir[1024];
extern char opt_keycheck[1024];
extern char opt_manager_ip[32];
extern char opt_match_header[128];
extern char opt_mirrorip_dst[20];
extern char opt_mirrorip_src[20];
extern char opt_pb_read_from_file[256];
extern char opt_php_path[1024];
extern char opt_scanpcapdir[2048];
extern char opt_silencedmtfseq[16];
extern char opt_tcpreassembly_log[1024];
extern char *sipportmatrix;
extern char sql_cdr_next_table[256];
extern char sql_cdr_sip_response_table[256];
extern char sql_cdr_table_last1d[256];
extern char sql_cdr_table_last30d[256];
extern char sql_cdr_table_last7d[256];
extern char sql_cdr_table[256];
extern char sql_cdr_ua_table[256];
extern char sql_driver[256];
extern char user_filter[10*2048];
extern int debugclean;
extern int get_customer_by_ip_flush_period;
extern int global_livesniffer;
extern int global_livesniffer_all;
extern int ipfilter_reload_do;
extern int manager_socket_server;
extern int num_threads;
extern int opt_allow_zerossrc;
extern int opt_audio_format;// define format for audio writing (if -W option)
extern int opt_callend;
extern int opt_callslimit;
extern int opt_cdronlyanswered;
extern int opt_cdronlyrtp;
extern int opt_cdrproxy;
extern bool opt_cdr_sipport;
extern int opt_cdr_ua_enable;
extern int opt_cleandatabase_cdr;
extern int opt_cleandatabase_http_enum;
extern int opt_cleandatabase_webrtc;
extern int opt_cleandatabase_register_failed;
extern int opt_cleandatabase_register_state;
extern int opt_cleanspool_interval;
extern int opt_cleanspool_sizeMB;
extern int opt_clientmanagerport;
extern int opt_convert_dlt_sll_to_en10;
extern int opt_create_old_partitions;
extern int opt_database_backup_insert_threads;
extern int opt_dbdtmf;
extern int opt_destination_number_mode;
extern int opt_domainport;
extern int opt_dscp;
extern int opt_dup_check;
extern int opt_dup_check_ipheader;
extern int opt_enable_http_enum_tables;
extern int opt_enable_http;
extern int opt_enable_webrtc;
extern int opt_enable_ssl;
extern int opt_filesclean;
extern int opt_fork;
extern FileZipHandler::eTypeCompress opt_gzipGRAPH;
extern int opt_id_sensor;
extern int opt_ipacc_interval;
extern int opt_ipaccount;
extern int opt_jitterbuffer_adapt;         // turns off/on jitterbuffer simulator to compute MOS score mos_adapt
extern int opt_jitterbuffer_f1;            // turns off/on jitterbuffer simulator to compute MOS score mos_f1
extern int opt_jitterbuffer_f2;            // turns off/on jitterbuffer simulator to compute MOS score mos_f2
extern int opt_manager_port;
extern int opt_maxpool_clean_obsolete;
extern int opt_mirrorall;
extern int opt_mirrorip;
extern int opt_mirroronly;
extern int opt_mos_g729;
extern int opt_mos_lqo;
extern int opt_mosmin_f2;
extern int opt_mysqlcompress;
extern int opt_mysql_port;
extern int opt_newdir;
extern int opt_nocdr;
extern int opt_norecord_dtmf;
extern int opt_norecord_header;
extern int opt_onewaytimeout;
extern int opt_onlyRTPheader;
extern int opt_packetbuffered;
extern int opt_packetbuffered;    // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_packetbuffered;  // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_pcap_queue;
extern int opt_pcap_queue_iface_dedup_separate_threads;
extern int opt_pcap_queue_iface_dedup_separate_threads_extend;
extern int opt_pcap_queue_iface_separate_threads;
extern int opt_pcap_queue_receive_dlt;
extern int opt_pcap_split;
extern int opt_pcap_threaded;
extern int opt_printinsertid;
extern int opt_promisc;
extern int opt_read_from_file;
extern int opt_ringbuffer;
extern int opt_rtcp;
extern int opt_rtcp;              // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_rtcp;  // Make .pcap files writing ‘‘packet-buffered’’
extern int opt_rtp_firstleg;
extern int opt_rtpnosip;
extern int opt_saveaudio_reversestereo;
extern int opt_saveGRAPH; 
extern int opt_saveGRAPH;//save GRAPH data?
extern int opt_saveGRAPH;// save GRAPH data to graph file? 
extern int opt_saveRAW;
extern int opt_saveRAW; 
extern int opt_saveRAW;                // save RTP payload RAW data?
extern int opt_saveRAW;                //save RTP payload RAW data?
extern int opt_saverfc2833;
extern int opt_saveRTCP;        // save RTCP packets to pcap file?
extern int opt_saveRTCP;// save RTCP packets to pcap file?
extern int opt_saveRTP;
extern int opt_saveRTP;         // save RTP packets to pcap file?
extern int opt_saveRTP; // save RTP packets to pcap file?
extern int opt_saveSIP;
extern int opt_saveSIP;         // save SIP packets to pcap file?
extern int opt_saveSIP;  // save SIP packets to pcap file?
extern int opt_saveudptl;
extern int opt_saveWAV;
extern int opt_saveWAV; 
extern int opt_savewav_force;
extern int opt_saveWAV;                // save RTP payload RAW data?
extern int opt_saveWAV;                //save RTP payload RAW data?
extern int opt_sipoverlap;
extern int opt_sip_register;
extern int opt_skinny;
extern int opt_skipdefault;
extern int opt_skiprtpdata;
extern int opt_tcpreassembly_pb_lock;
extern int opt_udpfrag;
extern int opt_upgrade_try_http_if_https_fail;
extern int global_pcap_dlink;
extern int readend;
extern int rtp_threaded;
extern int rtptimeout;
extern int sql_noerror;
extern int telnumfilter_reload_do;
extern int verbosity;
extern int verbosityE;
extern ip_port opt_pcap_queue_receive_from_ip_port;
extern ip_port opt_pcap_queue_send_to_ip_port;
extern MirrorIP *mirrorip;
extern nat_aliases_t nat_aliases;
extern pcap_t *global_pcap_handle;
extern pcap_t *global_pcap_handle_dead_EN10MB;
extern pthread_mutex_t daemonizeErrorTempFileLock;
extern pthread_mutex_t mysqlconnect_lock;      
extern pthread_mutex_t readpacket_thread_queue_lock;
extern rtp_read_thread *rtp_threads;
extern SqlDb_mysql *sqlDbCleanspool;
extern SqlDb_mysql *sqlDbEscape;
extern SqlDb *sqlDbSaveCall;
extern SqlDb *sqlDbSaveHttp;
extern SqlDb *sqlDbSaveIpacc;
extern char opt_mos_lqo_bin[1024];
extern char opt_mos_lqo_ref[1024];
extern char opt_mos_lqo_ref16[1024];
extern string opt_pcap_queue_disk_folder;
extern vm_atomic<string> pbStatString;
extern vm_atomic<string> storingCdrLastWriteAt;
extern struct arg_t * my_args;
extern struct pcap_stat pcapstat;
extern struct queue_state *qs_readpacket_thread_queue;
extern time_t startTime;
extern u_int opt_pcap_queue_block_max_time_ms;
extern u_int opt_pcap_queue_file_store_max_time_ms;
extern uint64_t opt_pcap_queue_bypass_max_size;
extern uint64_t opt_pcap_queue_store_queue_max_disk_size;
extern uint64_t opt_pcap_queue_store_queue_max_memory_size;
extern uint8_t opt_sdp_reverse_ipport;
extern vm_atomic<u_long> pbCountPacketDrop;
extern unsigned int duplicate_counter;
extern unsigned int graph_delimiter;
extern unsigned int graph_version;
extern unsigned int gthread_num;
extern unsigned int opt_maxpcapsize_mb;
extern unsigned int opt_maxpoolaudiodays;
extern unsigned int opt_maxpoolaudiosize;
extern unsigned int opt_maxpooldays;
extern unsigned int opt_maxpoolgraphdays;
extern unsigned int opt_maxpoolgraphsize;
extern unsigned int opt_maxpoolrtpdays;
extern unsigned int opt_maxpoolrtpsize;
extern unsigned int opt_maxpoolsipdays;
extern unsigned int opt_maxpoolsipsize;
extern unsigned int opt_maxpoolsize;
extern unsigned int pcap_qring_max;
extern unsigned long long cachedirtransfered;
extern vector<string> opt_national_prefix;
extern volatile unsigned int pcap_readit;
extern volatile unsigned int pcap_writeit;
extern vector<u_int32_t> httpip;
extern vector<d_u_int32_t> httpnet;
extern char pcapcommand[4092];
extern char filtercommand[4092];
extern unsigned int rtpthreadbuffer;  
extern unsigned int rtpthreadbuffer;
#ifndef FREEBSD
extern uint32_t opt_scanpcapmethod;  // Specifies how to watch for new files in opt_scanpcapdir
#endif
extern char opt_convert_char[64];
extern unsigned int opt_openfile_max;

void config_load_mysql();

