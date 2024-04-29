#include "tar.h"
#include "billing.h"
#include "http.h"
#include "config_param.h"
#include "cleanspool.h"
#include "sniff_proc_class.h"
#include "voipmonitor.h"


extern void dns_lookup_common_hostnames();


extern int opt_test;
extern char opt_test_arg[1024];
extern char opt_test_str[1024];

extern MySqlStore *sqlStore;
extern char opt_callidmerge_secret[128];
extern cConfigItem_net_map::t_net_map opt_anonymize_ip_map;
extern CleanSpool *cleanSpool[2];
extern char configfile[1024];
extern char mysql_host[256];
extern char mysql_host_orig[256];
extern char mysql_database[256];
extern char mysql_user[256];
extern char mysql_password[256];
extern int opt_mysql_port;
extern char mysql_socket[256];
extern mysqlSSLOptions optMySsl;
extern char cloud_host[256];
extern char cloud_token[256];
extern bool cloud_router;
extern unsigned cloud_router_port;
extern int opt_cleandatabase_cdr;
extern int opt_cleandatabase_cdr_rtp_energylevels;
extern int opt_cleandatabase_ss7;
extern int opt_cleandatabase_http_enum;
extern int opt_cleandatabase_webrtc;
extern int opt_cleandatabase_register_state;
extern int opt_cleandatabase_register_failed;
extern int opt_cleandatabase_register_time_info;
extern int opt_cleandatabase_sip_msg;
extern int opt_cleandatabase_cdr_stat;
extern int opt_cleandatabase_rtp_stat;
extern int opt_cleandatabase_log_sensor;
extern unsigned int opt_maxpoolsize;
extern unsigned int opt_maxpooldays;
extern unsigned int opt_maxpoolsipsize;
extern unsigned int opt_maxpoolsipdays;
extern unsigned int opt_maxpoolrtpsize;
extern unsigned int opt_maxpoolrtpdays;
extern unsigned int opt_maxpoolgraphsize;
extern unsigned int opt_maxpoolgraphdays;
extern unsigned int opt_maxpoolaudiosize;
extern unsigned int opt_maxpoolaudiodays;


void test_search_country_by_number() {
	CheckInternational *ci = new FILE_LINE(42040) CheckInternational();
	ci->setInternationalMinLength(9, false);
	CountryPrefixes *cp = new FILE_LINE(42041) CountryPrefixes();
	cp->load();
	vector<string> countries;
	vmIP ip;
	cout << cp->getCountry("00039123456789", ip, &countries, NULL, ci) << endl;
	for(size_t i = 0; i < countries.size(); i++) {
		cout << countries[i] << endl;
	}
	delete cp;
	delete ci;
	cout << "-" << endl;
}

void test_geoip() {
	GeoIP_country *ipc = new FILE_LINE(42042) GeoIP_country();
	ipc->load();
	cout << ipc->getCountry(str_2_vmIP("152.251.11.109")) << endl;
	delete ipc;
}

void test_filebuffer() {
	int maxFiles = 1000;
	int bufferLength = 8000;
	FILE *file[maxFiles];
	char *fbuffer[maxFiles];
	
	for(int i = 0; i < maxFiles; i++) {
		char filename[100];
		snprintf(filename, sizeof(filename), "/dev/shm/test/%i", i);
		file[i] = fopen(filename, "w");
		
		setbuf(file[i], NULL);
		
		fbuffer[i] = new FILE_LINE(42043) char[bufferLength];
		
	}
	
	printf("%d\n", BUFSIZ);
	
	char writebuffer[1000];
	memset(writebuffer, 1, 1000);
	
	for(int i = 0; i < maxFiles; i++) {
		fwrite(writebuffer, 1000, 1, file[i]);
		fclose(file[i]);
		char filename[100];
		snprintf(filename, sizeof(filename), "/dev/shm/test/%i", i);
		file[i] = fopen(filename, "a");
		
		fflush(file[i]);
		setvbuf(file[i], fbuffer[i], _IOFBF, bufferLength);
	}
	
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);
	
	cout << "---" << endl;
	u_int64_t _start = getTimeUS(tv);
	
	
	for(int p = 0; p < 5; p++)
	for(int i = 0; i < maxFiles; i++) {
		fwrite(writebuffer, 1000, 1, file[i]);
	}
	
	cout << "---" << endl;
	gettimeofday(&tv, &tz);
	u_int64_t _end = getTimeUS(tv);
	cout << (_end - _start) << endl;
}

struct XX {
	XX(int a = 0, int b = 0) {
		this->a = a;
		this->b = b;
	}
	int a;
	int b;
};
void test_safeasyncqueue() {
	SafeAsyncQueue<XX> testSAQ;
	XX xx(1,2);
	testSAQ.push(xx);
	XX yy;
	sleep(1);
	if(testSAQ.pop(&yy)) {
		cout << "y" << endl;
		cout << yy.a << "/" << yy.b << endl;
	} else {
		cout << "n" << endl;
	}
}

void test_parsepacket() {
	char *str = (char*)"INVITE sip:800123456@sip.odorik.cz SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.12:5061;rport;branch=z9hG4bK354557323\r\nFrom: <sip:706912@sip.odorik.cz>;tag=1645803335\r\nTo: <sip:800123456@sip.odorik.cz>\r\nCall-ID: 1781060762\r\nCSeq: 20 INVITE\r\nContact: <sip:jumbox@93.91.52.46>\r\nContent-Type: application/sdp\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\nMax-Forwards: 70\r\nUser-Agent: Linphone/3.6.1 (eXosip2/3.6.0)\r\nSubject: Phone call\r\nContent-Length: 453\r\n\r\nv=0\r\no=706912 1477 2440 IN IP4 93.91.52.46\r\ns=Talk\r\nc=IN IP4 93.91.52.46\r\nt=0 0\r\nm=audio 7078 RTP/AVP 125 112 111 110 96 3 0 8 101\r\na=rtpmap:125 opus/48000\r\na=fmtp:125 useinbandfec=1; usedtx=1\r\na=rtpmap:112 speex/32000\r\na=fmtp:112 vbr=on\r\na=rtpmap:111 speex/16000\r\na=fmtp:111 vbr=on\r\na=rtpmap:110 speex/8000\r\na=fmtp:110 vbr=on\r\na=rtpmap:96 GSM/11025\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-11\r\nm=video 9078 RTP/AVP 103\r\na=rtpmap:103 VP8/90000\r\n\177\026\221V";
	ParsePacket pp;
	pp.setStdParse();
	ParsePacket::ppContentsX contents;
	pp.parseData(str, strlen(str), &contents);
	pp.debugData(&contents);
}
	
void test_parsepacket2() {
 
        ParsePacket pp;
	pp.addNode("test1", ParsePacket::typeNode_std);
	pp.addNode("test2", ParsePacket::typeNode_std);
	pp.addNode("test3", ParsePacket::typeNode_std);
	
	char *str = (char*)"test1abc\ntEst2def\ntest3ghi";
	
	ParsePacket::ppContentsX contents;
	pp.parseData(str, strlen(str), &contents);
	
	cout << "test1: " << contents.getContentString("test1") << endl;
	cout << "test2: " << contents.getContentString("test2") << endl;
	cout << "test3: " << contents.getContentString("test3") << endl;
	
	pp.debugData(&contents);
}

void test_reg() {
	cout << reg_match("123456789", "456", __FILE__, __LINE__) << endl;
	cout << reg_replace("123456789", "(.*)(456)(.*)", "$1-$2-$3", __FILE__, __LINE__) << endl;
}

void test_escape() {
	char checkbuff[2] = " ";
	for(int i = 0; i < 256; i++) {
		checkbuff[0] = i;
		string escapePacket1 = sqlEscapeString(checkbuff, 1);
		string escapePacket2 = _sqlEscapeString(checkbuff, 1, "mysql");
		if(escapePacket1 != escapePacket2) {
			cout << i << endl;
			cout << escapePacket1 << endl;
			cout << escapePacket2 << endl;
			break;
		}
	}
}

void test_alloc_speed() {
	extern unsigned int HeapSafeCheck;
	uint32_t ii = 1000000;
	cout << "HeapSafeCheck: " << HeapSafeCheck << endl;
	for(int p = 0; p < 10; p++) {
		char **pointers = new FILE_LINE(42044) char*[ii];
		for(u_int32_t i = 0; i < ii; i++) {
			pointers[i] = new FILE_LINE(42045) char[1000];
		}
		for(u_int32_t i = 0; i < ii; i++) {
			delete [] pointers[i];
		}
		delete [] pointers;
	}
}

void test_alloc_speed_malloc() {
	extern unsigned int HeapSafeCheck;
	uint32_t ii = 1000000;
	cout << "HeapSafeCheck: " << HeapSafeCheck << endl;
	for(int p = 0; p < 10; p++) {
		char **pointers = new FILE_LINE(42046) char*[ii];
		for(u_int32_t i = 0; i < ii; i++) {
			pointers[i] = (char*)malloc(1000);
		}
		for(u_int32_t i = 0; i < ii; i++) {
			free(pointers[i]);
		}
		delete [] pointers;
	}
}

#ifdef HAVE_LIBTCMALLOC
#if HAVE_LIBTCMALLOC
extern "C" {
void* tc_malloc(size_t size);
void tc_free(void*);
}
void test_alloc_speed_tc() {
	extern unsigned int HeapSafeCheck;
	uint32_t ii = 1000000;
	cout << "HeapSafeCheck: " << HeapSafeCheck << endl;
	for(int p = 0; p < 10; p++) {
		char **pointers = new FILE_LINE(42047) char*[ii];
		for(u_int32_t i = 0; i < ii; i++) {
			pointers[i] = (char*)tc_malloc(1000);
		}
		for(u_int32_t i = 0; i < ii; i++) {
			tc_free(pointers[i]);
		}
		delete [] pointers;
	}
}
#endif
#endif

void test_untar() {
	Tar tar;
	tar.tar_open("/var/spool/voipmonitor_local/2015-01-30/19/26/SIP/sip_2015-01-30-19-26.tar", O_RDONLY);
	tar.tar_read("1309960312.pcap", 659493, "cdr");
}

void test_http_dumper() {
	HttpPacketsDumper dumper;
	dumper.setPcapName("/tmp/testhttp.pcap");
	//dumper.setTemplatePcapName();
	string timestamp_from = "2013-09-22 15:48:51";
	string timestamp_to = "2013-09-24 01:48:51";
	string ids = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20";
	dumper.dumpData(timestamp_from.c_str(), timestamp_to.c_str(), ids.c_str());
}

void test_pexec() {
	const char *cmdLine = "rrdtool graph - -w 582 -h 232 -a PNG --start \"now-3606s\" --end \"now-6s\" --font DEFAULT:0:Courier --title \"CPU usage\" --watermark \"`date`\" --disable-rrdtool-tag --vertical-label \"percent[%]\" --lower-limit 0 --units-exponent 0 --full-size-mode -c BACK#e9e9e9 -c SHADEA#e9e9e9 -c SHADEB#e9e9e9 DEF:t0=/var/spool/voipmonitor_local/rrd/db-tCPU.rrd:tCPU-t0:MAX DEF:t1=/var/spool/voipmonitor_local/rrd/db-tCPU.rrd:tCPU-t1:MAX DEF:t2=/var/spool/voipmonitor_local/rrd/db-tCPU.rrd:tCPU-t2:MAX LINE1:t0#0000FF:\"t0 CPU Usage %\\l\" COMMENT:\"\\u\" GPRINT:t0:LAST:\"Cur\\: %5.2lf\" GPRINT:t0:AVERAGE:\"Avg\\: %5.2lf\" GPRINT:t0:MAX:\"Max\\: %5.2lf\" GPRINT:t0:MIN:\"Min\\: %5.2lf\\r\" LINE1:t1#00FF00:\"t1 CPU Usage %\\l\" COMMENT:\"\\u\" GPRINT:t1:LAST:\"Cur\\: %5.2lf\" GPRINT:t1:AVERAGE:\"Avg\\: %5.2lf\" GPRINT:t1:MAX:\"Max\\: %5.2lf\" GPRINT:t1:MIN:\"Min\\: %5.2lf\\r\" LINE1:t2#FF0000:\"t2 CPU Usage %\\l\" COMMENT:\"\\u\" GPRINT:t2:LAST:\"Cur\\: %5.2lf\" GPRINT:t2:AVERAGE:\"Avg\\: %5.2lf\" GPRINT:t2:MAX:\"Max\\: %5.2lf\" GPRINT:t2:MIN:\"Min\\: %5.2lf\\r\"";
	//cmdLine = "sh -c 'cd /;make;'";
	
	SimpleBuffer out;
	SimpleBuffer err;
	int exitCode;
	cout << "vm_pexec rslt:" << vm_pexec(cmdLine, &out, &err, &exitCode) << endl;
	cout << "OUT SIZE:" << out.size() << endl;
	cout << "OUT:" << (char*)out << endl;
	cout << "ERR SIZE:" << err.size() << endl;
	cout << "ERR:" << (char*)err << endl;
	cout << "exit code:" << exitCode << endl;
}

bool save_packet(const char *binaryPacketFile, const char *rsltPcapFile, int length, time_t sec, suseconds_t usec) {
	FILE *file = fopen(binaryPacketFile, "rb");
	u_char *packet = new FILE_LINE(42048) u_char[length];
	if(file) {
		fread(packet, length, 1, file);
		fclose(file);
	} else {
		cerr << "failed open file: " << binaryPacketFile << endl;
		delete [] packet;
		return(false);
	}
	pcap_pkthdr header;
	memset(&header, 0, sizeof(header));
	header.caplen = length;
	header.len = length;
	header.ts.tv_sec = sec;
	header.ts.tv_usec = usec;
	PcapDumper *dumper = new FILE_LINE(42049) PcapDumper(PcapDumper::na, NULL);
	dumper->setEnableAsyncWrite(false);
	dumper->setTypeCompress(FileZipHandler::compress_na);
	bool rslt;
	if(dumper->open(tsf_na, rsltPcapFile, 1)) {
		dumper->dump(&header, packet, 1, true);
		rslt = true;
	} else {
		cerr << "failed write file: " << rsltPcapFile << endl;
		rslt = false;
	}
	delete dumper;
	delete [] packet;
	return(rslt);
}

class cTestCompress : public CompressStream {
public:
	cTestCompress(CompressStream::eTypeCompress typeCompress)
	 : CompressStream(typeCompress, 1024 * 8, 0) {
	}
	bool compress_ev(char *data, u_int32_t len, u_int32_t /*decompress_len*/, bool /*format_data*/ = false) {
		fwrite(data, 1, len, fileO);
		return(true);
	}
	bool decompress_ev(char *data, u_int32_t len) { 
		fwrite(data, 1, len, fileO);
		return(true); 
	}
	void testCompress() {
		fileI = fopen("/tmp/tc1.pcap", "rb");
		if(!fileI) {
			return;
		}
		fileO = fopen("/tmp/tc1_c.pcap", "wb");
		if(!fileO) {
			return;
		}
		char buff[5000];
		size_t readSize;
		while((readSize = fread(buff, 1, sizeof(buff), fileI))) {
			this->compress(buff, readSize, false, this);
		}
		fclose(fileI);
		fclose(fileO);
	}
	void testDecompress() {
		fileI = fopen("/tmp/tc1_c.pcap", "rb");
		if(!fileI) {
			return;
		}
		fileO = fopen("/tmp/tc1_d.pcap", "wb");
		if(!fileO) {
			return;
		}
		char buff[5000];
		size_t readSize;
		while((readSize = fread(buff, 1, sizeof(buff), fileI))) {
			this->decompress(buff, readSize, readSize * 10, false, this);
		}
		fclose(fileI);
		fclose(fileO);
	}
private:
	FILE *fileI;
	FILE *fileO;
};

void test_time_cache() {
	cout << "-----------------" << endl;
	time_t now;
	time(&now);
	for(int i = 0; i <= 4 * 60 * 6; i++) {
		cout << "-- " << i << endl;
		cout << "local " << time_r_str(&now, "local") << endl;
		cout << "gmt   " << time_r_str(&now, "GMT") << endl;
		cout << "EST   " << time_r_str(&now, "EST") << endl;
		cout << "NY    " << time_r_str(&now, "America/New_York") << endl;
		cout << "LA    " << time_r_str(&now, "America/Los_Angeles") << endl;
		cout << "NF    " << time_r_str(&now, "Canada/Newfoundland") << endl;
		now += 10;
	}
	cout << "-----------------" << endl;
}

void test_ip_groups() {
	/*
	GroupsIP gip;
	gip.load();
	GroupIP *gr = gip.getGroup("192.168.3.5");
	if(gr) {
		cout << gr->getDescr() << endl;
	}
	*/
}

void test_filezip_handler() {
	FileZipHandler *fzh = new FILE_LINE(42051) FileZipHandler(8 * 1024, 0, FileZipHandler::gzip);
	fzh->open(tsf_na, "/home/jumbox/Plocha/test.gz");
	for(int i = 0; i < 1000; i++) {
		char buff[1000];
		snprintf(buff, sizeof(buff), "abcd %80s %i\n", "x", i + 1);
		fzh->write(buff, strlen(buff));
	}
	fzh->write((char*)"eof", 3);
	fzh->close();
	delete fzh;
	fzh = new FILE_LINE(42052) FileZipHandler(8 * 1024, 0, FileZipHandler::gzip);
	fzh->open(tsf_na, "/home/jumbox/Plocha/test.gz");
	while(!fzh->is_eof() && fzh->is_ok_decompress() && fzh->read(2)) {
		string line;
		while(fzh->getLineFromReadBuffer(&line)) {
			cout << line;
		}
	}
	cout << "|" << endl;
	delete fzh;
}

void setAllocNumb() {
	// ./voipmonitor -k -v1 -c -X88
	vector<sFileLine> fileLines;
	DIR* dp = opendir(".");
	if(!dp) {
		return;
	}
	vector<string> files;
	dirent* de;
	do {
		de = readdir(dp);
		if(de && string(de->d_name) != ".." && string(de->d_name) != ".") {
			if(reg_match(de->d_name, ".*\\.cpp", __FILE__, __LINE__) ||
			   reg_match(de->d_name, ".*\\.h", __FILE__, __LINE__)) {
				files.push_back(de->d_name);
			}
		}
	} while(de);
	closedir(dp);
	std::sort(files.begin(), files.end());
	unsigned fileNumber = 1;
	for(unsigned file_i = 0; file_i < files.size(); file_i++) {
		/*
		if(files[file_i] != "filter_mysql.cpp") {
			continue;
		}
		fileNumber = 4;
		*/
		bool exists = false;
		bool mod = false;
		FILE *file_in = fopen(files[file_i].c_str(), "r");
		if(file_in) {
			char line[1000000];
			vector<string> lines;
			while(fgets(line, sizeof(line), file_in)) {
				lines.push_back(line);
			}
			fclose(file_in);
			/*
			bool fileNumberOk = true;
			unsigned allocNumberMax = 0;
			for(int pass = 0; pass < 2; pass++) {
				for(unsigned line_i = 0; line_i < lines.size(); line_i++) {
					if(!fileNumberOk) {
						allocNumberMax = 0;
					}
					strcpy(line, lines[line_i].c_str());
					if(reg_match(line, "FILE_LINE\\([0-9]+\\)")) {
						exists = true;
						string repl;
						do {
							repl = reg_replace(line, "(FILE_LINE\\([0-9]+\\))", "$1");
							if(!repl.empty()) {
								char *pos = strstr(line, repl.c_str());
								unsigned fileAllocNumberOld = atol(pos + 10);
								if(pass == 0) {
									if(fileAllocNumberOld) {
										if(fileAllocNumberOld / 1000 != fileNumber) {
											fileNumberOk = false;
											break;
										}
										allocNumberMax = max(allocNumberMax, fileAllocNumberOld % 1000);
									}
									*pos = '_';
								} else {
									unsigned fileAllocNumberNew;
									sFileLine fileLine;
									strcpy(fileLine.file, files[file_i].c_str());
									fileLine.line = line_i + 1;
									if(!fileNumberOk || !fileAllocNumberOld) {
										fileAllocNumberNew = fileNumber * 1000 + (++allocNumberMax);
									} else {
										fileAllocNumberNew = fileAllocNumberOld;
									}
									char line_mod[1000000];
									strncpy(line_mod, line, pos - line);
									line_mod[pos - line] = 0;
									strcat(line_mod, ("FILE_X_LINE(" + intToString(fileAllocNumberNew) + ")").c_str());
									strcat(line_mod, line + (pos - line) + repl.size());
									strcpy(line, line_mod);
									fileLine.alloc_number = fileAllocNumberNew;
									fileLines.push_back(fileLine);
								}
							}
						} while(!repl.empty());
						if(pass == 1) {
							string line_new = find_and_replace(line, "FILE_X_LINE" , "FILE_LINE").c_str();
							if(line_new != lines[line_i]) {
								lines[line_i] = line_new;
								mod = true;
							}
						}
					}
				}
			}
			*/
			unsigned allocNumber = 0;
			for(unsigned line_i = 0; line_i < lines.size(); line_i++) {
				strcpy(line, lines[line_i].c_str());
				if(reg_match(line, "FILE_LINE\\([0-9]+\\)")) {
					exists = true;
					string repl;
					do {
						repl = reg_replace(line, "(FILE_LINE\\([0-9]+\\))", "$1");
						if(!repl.empty()) {
							char *pos = strstr(line, repl.c_str());
							sFileLine fileLine;
							strcpy(fileLine.file, files[file_i].c_str());
							fileLine.line = line_i + 1;
							unsigned fileAllocNumberNew = fileNumber * 1000 + (++allocNumber);
							char line_mod[1000000];
							strncpy(line_mod, line, pos - line);
							line_mod[pos - line] = 0;
							strcat(line_mod, ("FILE_X_LINE(" + intToString(fileAllocNumberNew) + ")").c_str());
							strcat(line_mod, line + (pos - line) + repl.size());
							strcpy(line, line_mod);
							fileLine.alloc_number = fileAllocNumberNew;
							fileLines.push_back(fileLine);
						}
					} while(!repl.empty());
					string line_new = find_and_replace(line, "FILE_X_LINE" , "FILE_LINE").c_str();
					if(line_new != lines[line_i]) {
						lines[line_i] = line_new;
						mod = true;
					}
				}
			}
			if(mod) {
				string modFileName = files[file_i] + "_new";
				FILE *file_out = fopen(modFileName.c_str(), "w");
				if(file_out) {
					for(unsigned line_i = 0; line_i < lines.size(); line_i++) {
						fputs(lines[line_i].c_str(), file_out);
					}
					fclose(file_out);
					cout << "MOD: " << files[file_i] << endl;
					unlink(files[file_i].c_str());
					rename(modFileName.c_str(), files[file_i].c_str());
				}
			}
		}
		if(exists) {
			++fileNumber;
		}
	}
	if(fileLines.size()) {
		FILE *file_out = fopen("alloc_file_lines", "w");
		if(file_out) {
			for(unsigned i = 0; i < fileLines.size(); i++) {
				fprintf(file_out, "{ \"%s\", %u, %u },\n", fileLines[i].file, fileLines[i].line, fileLines[i].alloc_number);
			}
			fclose(file_out);
		}
	}
}

void load_rtp_pcap(const char *pcap) {
 
	extern Calltable *calltable;
	calltable = new FILE_LINE(0) Calltable;
 
	extern bool opt_read_from_file;
	opt_read_from_file = true;
	
	extern PreProcessPacket *preProcessPacket[PreProcessPacket::ppt_end_base];
	for(int i = (opt_t2_boost_direct_rtp ? PreProcessPacket::ppt_detach_x : PreProcessPacket::ppt_detach); i < PreProcessPacket::ppt_end_base; i++) {
		preProcessPacket[i] = new FILE_LINE(0) PreProcessPacket((PreProcessPacket::eTypePreProcessThread)i);
	}
 
	Call *call = new FILE_LINE(0) Call(INVITE, (char*)"1234", 4, NULL, 0);
	
	s_sdp_flags sdp_flags;
	sdp_flags.protocol = sdp_proto_srtp;
	
	const char *key = "\026\217\315\300A\253\353\355\377\062\f\377\345r\307\027\000\000\000\032\204V\307\177\000\000\000\200\327\025\000";
	unsigned key_length = 32;
	const char *salt = "j\223\\\a\341\246\363\fM\222A\251;\260";
	unsigned salt_length = 14;
	
	char key_salt[1000];
	unsigned key_salt_length = key_length + salt_length;
	memcpy(key_salt, key, key_length);
	memcpy(key_salt + key_length, salt, salt_length);
	
	size_t sdes_length;
	char *sdes = base64_encode((u_char*)key_salt, key_salt_length, &sdes_length);
	
	srtp_crypto_config srtp_cc;
	srtp_cc.tag = 0;
	srtp_cc.suite = "AES_CM_128_HMAC_SHA1_80";
	srtp_cc.key = sdes; // Fo/NwEGr6+3/Mgz/5XLHF2qTXAfhpvMMTZJBqTuw
	srtp_cc.key = "Fo/NwEGr6+3/Mgz/5XLHF2qTXAfhpvMMTZJBqTuw";
	srtp_cc.from_time_us = 0;
	
	list<srtp_crypto_config> srtp_crypto_config_list;
	srtp_crypto_config_list.push_back(srtp_cc);
	
	RTPMAP rtpmap[MAX_RTPMAP];
	memset((void*)rtpmap, 0, sizeof(rtpmap));
	
	call->add_ip_port_hash(call->branch_main(), 
			       str_2_vmIP("127.0.0.1"), str_2_vmIP("136.144.57.173"), ip_port_call_info::_ta_base, 28104, 0,
			       (char*)"", (char*)"", false,
			       &srtp_crypto_config_list, NULL,
			       (char*)"", (char*)"", (char*)"", (char*)"", (char*)"",
			       1, rtpmap, sdp_flags, 0);
	
	string error;
	if(!open_global_pcap_handle(pcap, &error)) {
		return;
	}
	
	extern pcap_t *global_pcap_handle;
	extern u_int16_t global_pcap_handle_index;
	readdump_libpcap(global_pcap_handle, global_pcap_handle_index, pcap_datalink(global_pcap_handle), NULL,
			 (is_read_from_file() ? _pp_read_file : 0) | _pp_process_calls);
	 
}

void check_bad_ether_type(const char *params) {
	if(!params || !*params) {
		cout << "missing interface as parameter" << endl;
		return;
	}
	vector<string> params_v = split(params, ' ');
	string interface = params_v[0];
	int opt_ringbuffer_mb = params_v.size() >= 2 && atoi(params_v[1].c_str()) > 0 ?
				 atoi(params_v[1].c_str()) :
				 10;
	cout << "*** check bad ether_type for interface: " << interface
	     << ", ringbuffer: " << opt_ringbuffer_mb << "MB" << endl;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1) {
		mask = PCAP_NETMASK_UNKNOWN;
	}
	cout << "pcap_lookupnet OK" << endl;
	pcap_t *pcap_handle;
	if((pcap_handle = pcap_create(interface.c_str(), errbuf)) == NULL) {
		cout << "pcap_create failed on interface '" << interface << "': " << errbuf << endl;
		return;
	}
	cout << "pcap_create OK" << endl;
	int status;
	if((status = pcap_set_snaplen(pcap_handle, 10000)) != 0) {
		cout << "error pcap_set_snaplen" << endl;
		return;
	}
	cout << "pcap_set_snaplen OK" << endl;
	int opt_promisc = 1;
	if((status = pcap_set_promisc(pcap_handle, opt_promisc)) != 0) {
		cout << "error pcap_set_promisc" << endl;
		return;
	}
	cout << "pcap_set_promisc OK" << endl;
	if((status = pcap_set_timeout(pcap_handle, 1000)) != 0) {
		cout << "error pcap_set_timeout" << endl;
		return;
	}
	cout << "pcap_set_timeout OK" << endl;
	if((status = pcap_set_buffer_size(pcap_handle, opt_ringbuffer_mb * 1024 * 1024ul)) != 0) {
		cout << "error pcap_set_buffer_size" << endl;
		return;
	}
	cout << "pcap_set_buffer_size OK" << endl;
	if((status = pcap_activate(pcap_handle)) != 0) {
		cout << "libpcap error: [" << pcap_geterr(pcap_handle) << "]" << endl;
		return;
	}
	printf("pcap_activate OK\n");
	pcap_pkthdr* header;
	const u_char* packet;
	u_int64_t counter = 0;
	u_int64_t counter_ok = 0;
	u_int64_t counter_bad = 0;
	u_int64_t end_period_time = getTimeMS_rdtsc() + 1000;
	int pcap_next_ex_rslt;
	while((pcap_next_ex_rslt = pcap_next_ex(pcap_handle, &header, &packet)) >= 0) {
		++counter;
		if(pcap_next_ex_rslt > 0) {
			if(((ether_header*)packet)->ether_type != 0xFFFF) {
				++counter_ok;
			} else {
				++counter_bad;
			}
		}
		if(getTimeMS_rdtsc() >= end_period_time) {
			cout << "calls pcap_next_ex: " << counter;
			if(counter_ok) {
				cout << ", ok packets: " << counter_ok;
			}
			if(counter_bad) {
				cout << ", bad packets (ether_type 0xFFFF): " << counter_bad;
			}
			cout << endl;
			counter = 0;
			counter_ok = 0;
			counter_bad = 0;
			end_period_time = getTimeMS_rdtsc() + 1000;
		}
	}
}

void test() {
 
	switch(opt_test) {
	 
	case 21 : {
		for(int pass = 0; pass < 1000; pass++) {
		cTestCompress *testCompress = new FILE_LINE(42053) cTestCompress(CompressStream::lzo);
		testCompress->testCompress();
		//testCompress->testDecompress();
		delete testCompress;
		}
	} break;
	case 22 : {
		for(int pass = 0; pass < 1000; pass++) {
		cTestCompress *testCompress = new FILE_LINE(42054) cTestCompress(CompressStream::snappy);
		testCompress->testCompress();
		//testCompress->testDecompress();
		delete testCompress;
		}
	} break;
	case 23 : {
		for(int pass = 0; pass < 1000; pass++) {
		cTestCompress *testCompress = new FILE_LINE(42055) cTestCompress(CompressStream::gzip);
		testCompress->setCompressLevel(1);
		testCompress->testCompress();
		//testCompress->testDecompress();
		delete testCompress;
		}
	} break;
	
	case 31: {
	 
		if(opt_callidmerge_secret[0] != '\0') {
			// header is encoded - decode it 
		 
			char *s2 = new FILE_LINE(42056) char[1024];
			strcpy(s2, opt_test_str + 2);
			int l2 = strlen(s2);
			unsigned char buf[1024];
		 
			char c;
			c = s2[l2];
			s2[l2] = '\0';
			int enclen = base64decode(buf, (const char*)s2, l2);
			static int keysize = strlen(opt_callidmerge_secret);
			s2[l2] = c;
			for(int i = 0; i < enclen; i++) {
				buf[i] = buf[i] ^ opt_callidmerge_secret[i % keysize];
			}
			// s2 is now decrypted call-id
			s2 = (char*)buf;
			l2 = enclen;
			cout << string(s2, l2) << endl;
			
		} else {
			cout << "missing callidmerge_secret" << endl;
		}
		
	} break;
	 
	case 1: {
	 
		cPartitions p;
		cout << p.dump(false);
		
		//extern int opt_cleandatabase_cdr_size;
		//opt_cleandatabase_cdr_size = 100;
		//p.cleanup_by_size();
		
		extern int opt_cleandatabase_size;
		opt_cleandatabase_size = 1600;
		p.cleanup_by_size();
		
		break;
	 
		void adjustSipResponse(string &sipResponse);
		//extern int opt_cdr_sip_response_number_max_length;
		//opt_cdr_sip_response_number_max_length = 0;
		//extern bool opt_cdr_sip_response_normalisation;
		//opt_cdr_sip_response_normalisation = true;
		//extern vector<string> opt_cdr_sip_response_reg_remove;
		//opt_cdr_sip_response_reg_remove.push_back("Not");
		string resp[] = {
			 "503 No target nodes for callid --8HbHDnHLOSe:L4@35.199.111.118",
			 "404 Did 551131812966 Not Found.",
			 "400 Bad syntax: ValueError(\"SipAddress: cannot find name-addr or addr-spec; input='!#dT) <sip:!#dT)@187.60.60.39:5060>;tag=0083"
		};
		for(unsigned i = 0; i < sizeof(resp) / sizeof(resp[0]); i++) {
			string s = resp[i];
			adjustSipResponse(s);
			cout << " *RESP* " << resp[i] << " -> " << s << endl;
		}
		//
		void adjustReason(string &reason);
		//extern bool opt_cdr_reason_normalisation;
		//opt_cdr_reason_normalisation = true;
		string reas[] = {
			 "00000ab3-fb29-4139-a6ca-d5b6bb2da949;LocalUserInitiated",
			 "0031f80c-cc4a-4a38-816d-a48299e8759d;Callee did not pickup.",
			 "1241e184-86c8-44be-bf56-c09486922be4;EstablishmentTimeout"
		};
		for(unsigned i = 0; i < sizeof(reas) / sizeof(reas[0]); i++) {
			string s = reas[i];
			adjustReason(s);
			cout << " *REAS* " << reas[i] << " -> " << s << endl;
		}
		//
		void adjustUA(string &ua);
		//extern bool opt_cdr_ua_normalisation;
		//opt_cdr_ua_normalisation = true;
		//extern vector<string> opt_cdr_ua_reg_whitelist;
		//opt_cdr_ua_reg_whitelist.push_back("Magnus");
		//opt_cdr_ua_reg_whitelist.push_back("GPT");
		//extern vector<string> opt_cdr_ua_reg_remove;
		//opt_cdr_ua_reg_remove.push_back("-N2");
		//opt_cdr_ua_reg_remove.push_back("b18");
		string ua[] = {
			 "MagnusBilling --40Q3vmCyV6k4h-@200.201.235.196",
			 "ENSR3.0.100.6-IS2-RMRG31-RG7152-CPI1-CPO10094",
			 "GPT-2731GN2A4P-N2 c03dd90c13b0 BR_SV_1.11(WVK.0)b18",
			 "AUDC-IPPhone/1.6.0.44.43 (310HD; 00908F3BAB6E)"
		};
		for(unsigned i = 0; i < sizeof(ua) / sizeof(ua[0]); i++) {
			string s = ua[i];
			adjustUA(s);
			cout << " *UA* " << ua[i] << " -> " << s << endl;
		}
		
		break;
	 
		#if defined(__x86_64__) or defined(__i386__)
		unsigned int c = 1e7;
		u_int64_t start, stop;
		unsigned buff_l = 1000;
		u_char buff[buff_l];
		for(unsigned i = 0; i < buff_l; i++) {
			buff[i] = rand();
		}
		u_int64_t s;
	 
		s = 0;
		cout << "crc32" << endl;
		start = getTimeUS();
		for(unsigned i = 0; i < c; i++) {
			s += crc32(0, buff, buff_l);
		}
		stop = getTimeUS();
		cout << stop - start << " / " << s << endl;
	 
		s = 0;
		cout << "crc32_sse" << endl;
		start = getTimeUS();
		for(unsigned i = 0; i < c; i++) {
			s+= crc32_sse(0, (const char*)buff, buff_l);
		}
		stop = getTimeUS();
		cout << stop - start << " / " << s << endl;
		#endif
		
		break;
	 
		cout <<  tuplehash(3141284542, 16118) << endl;
		cout <<  tuplehash(3141284542, 16119) << endl;
		break;
	 
		{
		sqlStore = new FILE_LINE(42059) MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket,
							   isCloud() ? cloud_host : NULL, cloud_token, cloud_router, &optMySsl);

		char query_buff[20000];
		
		const char *mpacket = "\324ò\241\002\000\004\000\000\000\000\000\000\000\000\000\200\f\000\000q\000\000\000\264\341\206d\260\377\003\000\311\005\000\000\311\005\000\000\000\000\000\001\000\006\000\t\017\t\000\024on\b\000E(\005\271\000\000\000\000m\021\374\227\300\250c\030\300\250g\v\003\236\003\235\005\245\000\000\t\216\024\201\2411\275\377\377\377\377\377\377\377\377\b\006\n\016\343uL\034\000\000\344\333,\300\250e\311\300\250e\255\023\304\023\304\021\000E`\005s\000\000\000\000@\021<?\300\250e\311\300\250e\255\023\304\023\304\005_\000\000INVITE sip:25040_9171.ESL@192.168.101.173:5060;line=648b892de469b77;realip=10.0.28.130:49262;natip=93.47.153.108:64611 SIP/2.0\r\nP-Charging-Vector: icid-value=ESL.1684338062072.virt.160102.[25040_9171.ESL-1];icid-generated-at=192.168.101.201\r\nContact: <sip:00393401009234@192.168.101.201:5067>\r\nUser-Agent: Intraswitch/10.2.37_SCF-8\r\nCSeq: 1684314886 INVITE\r\nMin-SE: 90\r\nAlert-Info: <auto>\r\nCall-Info: <sip:ESL>;answer-after=0\r\nSupported: replaces, 100rel, timer\r\nFrom: <sip:00393401009234@192.168.101.201:5067>;tag=b0399877-69c3-62bf-69cc-32331ef03d9f\r\nMax-Forwards: 69\r\nSession-Expires: 1800\r\nVia: SIP/2.0/UDP 192.168.101.201:5060;branch=z9hG4bK4cebd74a-73a5-d0e3-8064-c22f6b7a7b9e\r\nVia: SIP/2.0/UDP 192.168.101.201:5067;branch=z9hG4bKcf8e3cef-ec0d-73b3-908e-a3e233c0e4e5\r\nRecord-Route: <sip:IstraPID-109958746@192.168.101.201;lr>\r\nAnswer-Mode: auto\r\nCall-ID: c5789761-71cf-405c-ba67-939121b34dbb@192.168.101.201\r\nContent-Type: application/sdp\r\nTo: <sip:25040_9171.ESL@192.168.101.201>\r\nContent-Length: 266\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, MESSAGE, PRACK, REFER, INFO, SUBSCRIBE, NOTIFY\r\n\r\nv=0\r\no=ipbx 1686547050874 1686547050874 IN IP4 192.168.101.201\r\ns=477482417\r\nc=IN IP4 192.168.101.201\r\nt=0 0\r\nm=audio 47602 RTP/AVP 8 0 18 99\r\na=rtpmap:8 PCMA/8000/1\r\na=rtpmap:0 PCMU/8000/1\r\na=rtpmap:18 G729/8000/1\r\na=rtpmap:99 telephone-event/8000\r\na=fmtp:99 0-15\r\n";
		int mpacket_length = 1521;
		
		strcpy(query_buff, "INSERT INTO livepacket_1 SET sipcallerip = 3232261577, sipcalledip = 3232261549, id_sensor = 0, sport = 5060, dport = 5060, istcp = 0, created_at = '2023-06-12 11:13:24', microseconds = 262064, callid = 'c5789761-71cf-405c-ba67-939121b34dbb@192.168.101.201', description = 'INVITE sip:25040_9171.ESL@192.168.101.173:5060;line=648b892de469b77;realip=10.0.28.130:49262;natip=93.47.153.108:64611 SIP/2.0', vlan = NULL, data =");
		strcat(query_buff, "_latin1'#");
		_sqlEscapeString(mpacket, mpacket_length, query_buff + strlen(query_buff), NULL);
		strcat(query_buff, "#'");
		
		sqlStore->query_lock(MYSQL_ADD_QUERY_END(string(query_buff)), STORE_PROC_ID_SAVE_PACKET_SQL, 0);
		
		break;

		}
	 
		{
		cout << " --- " << endl;
		cout << "free [GB old]: " << GetFreeDiskSpace("/home") / (1024*1024*1024) << endl;
		cout << "free [GB]: " << GetFreeDiskSpace_GB("/home") << endl;
		cout << "free [%]: " << GetFreeDiskSpace_perc("/home") << endl;
		cout << "total [GB old]: " << GetTotalDiskSpace("/home") / (1024*1024*1024) << endl;
		cout << "total [GB]: " << GetTotalDiskSpace_GB("/home") << endl;
		break;
		}
	 
		{
		//vmIPmask ipm(str_2_vmIP("192.168.1.0"), 28);
		vmIPmask ipm(str_2_vmIP("::ab:dead:babe"), 120);
		cout << ipm.getString() << endl;
		list<vmIP> list_ip;
		ipm.ip_list(&list_ip);
		for(list<vmIP>::iterator iter = list_ip.begin(); iter != list_ip.end(); iter++) {
			cout << iter->getString() << endl;
		}
		cout << ipm.ip_list_size() << endl;
		
		vmIP ip = str_2_vmIP("::ab:FFFF:FFFF:FFFF:FFFF");
		ip._inc();
		ip._inc();
		cout << ip.getString() << endl;
		
		break;
		}
	 
		{
		VmCodecs *vmCodecs = new FILE_LINE(0) VmCodecs;
		string path;
		cout << vmCodecs->findVersionOK(&path) << endl;
		cout << path << endl;
		cout << "***" << endl;
		cout << vmCodecs->download(&path) << endl;
		cout << path << endl;
		cout << "***" << endl;
		delete vmCodecs;
		}
	 
		{
		char ip_str[1000];
		while(fgets(ip_str, sizeof(ip_str), stdin)) {
			if(ip_str[0] == '\n') {
				break;
			}
			cout << " v: " << string_is_look_like_ip(ip_str) << endl;
			vmIP ip;
			ip.setFromString(ip_str, NULL);
			vmIP ipc = cConfigItem_net_map::convIP(ip, &opt_anonymize_ip_map);
			cout << " c: " << ipc.getString() << endl;
		}
		}
		break;
	 
		{
		 
		string csv = "abc,,\"\",\"def\",\"ghi\"";
		cDbStrings strings;
		strings.explodeCsv(csv.c_str());
		strings.setZeroTerm();
		strings.print();
		cout << "---" << endl;
		 
		}
		break;
	 
		{
		 
		unsigned int usleepSumTime = 0;
		unsigned int usleepCounter = 0;
		
		unsigned _last = 0;
		unsigned useconds = 100;
		while(!is_terminating()) {
			unsigned _act = USLEEP_C(useconds, usleepCounter);
			if(_act != _last) {
				cout << usleepSumTime << " / " << usleepCounter << " / " << _act << " / " << (_act / useconds) << endl;
				_last = _act;
			}
			usleepSumTime += _act; 
			++usleepCounter;
		}
		break;
		 
		}
	 
		cEvalFormula f(cEvalFormula::_est_na, true);
		f.e("3*(2 * 3 + 4 * 5 + (2+8))");
		f.e("'abcd' like '%bc%' and 'abcd' like 'abc%' and 'abcd' like '%bcd'");
		break;
	 
		IP ipt("192.168.0.0");
	 
		SqlDb *sqlDb0 = createSqlObject();
		sqlDb0->query("select ip from test_ip");
		SqlDb_row row0;
		while((row0 = sqlDb0->fetchRow())) {
			vmIP ip;
			ip.setIP(&row0, "ip");
			cout << ip.getString() << endl;
		}
		delete sqlDb0;
	 
		cResolver res;
		vmIP ip = res.resolve("www.seznam.cz", NULL, 300/*, cResolver::_typeResolve_system_host*/);
		cout << ip.getString() << endl;
		break;
	 
		SqlDb *sqlDb = createSqlObject();
		sqlDb->query("select * from geoipv6_country limit 10");
		#if 0
		string rslt = sqlDb->getCsvResult();
		cout << rslt <<  endl;
		sqlDb->processResponseFromCsv(rslt.c_str());
		#else
		string rslt = sqlDb->getJsonResult();
		cout << rslt <<  endl;
		sqlDb->processResponseFromQueryBy(rslt.c_str(), NULL, 0);
		#endif
		sqlDb->setCloudParameters("c", "c", "c");
		
		cout << "---" << endl;
		
		SqlDb_row row;
		while((row = sqlDb->fetchRow())) {
			vmIP ip_from;
			ip_from.setIP(&row, "ip_from");
			vmIP ip_to;
			ip_to.setIP(&row, "ip_to");
			cout << ip_from.getString() << " / "
			     << ip_to.getString() << " / "
			     << row["country"] << endl;
		}
		
		cout << "---" << endl;
		
		//cout << sqlDb->getJsonResult() <<  endl;
		delete sqlDb;
		break;
	 
		dns_lookup_common_hostnames();

		cout << str_2_vmIP("192.168.0.0").broadcast(16).getString() << endl;
		cout << str_2_vmIP("192.168.1.1").isLocalIP() << endl;
		cout << str_2_vmIP("127.0.0.1").isLocalhost() << endl;
	 
		/*
		cGzip gzip;
		u_char *cbuffer;
		size_t cbufferLength;
		string str;
		for(unsigned i = 0; i < 1000; i++) {
			str += "abcdefgh";
		}
		gzip.compressString(str, &cbuffer, &cbufferLength);
		if(gzip.isCompress(cbuffer, cbufferLength)) {
			string str2 = gzip.decompressString(cbuffer, cbufferLength);
			cout << str2 << endl;
		}
		break;
		
		cBilling billing;
		billing.load();
		
		string calldate = "2017-01-17 08:00";
		unsigned duration = 9 * 60 * 60;
		string ip_src = "192.168.101.10";
		string ip_dst = "192.168.101.151";
		string number_src = "+4121353333";
		string number_dst = "+41792926527";
		
		double operator_price; 
		double customer_price;
		unsigned operator_currency_id;
		unsigned customer_currency_id;
		unsigned operator_id;
		unsigned customer_id;
		
		time_t calldate_time = stringToTime(calldate.c_str());
		
		tm calldate_tm = time_r(&calldate_time);
		tm next1 = getNextBeginDate(calldate_tm);
		tm next2 = dateTimeAdd(next1, 24 * 60 * 60);
		
		billing.billing(calldate_time , duration,
				str_2_vmIP(ip_src.c_str()), str_2_vmIP(ip_dst.c_str()),
				number_src.c_str(), number_dst.c_str(),
				"", "",
				&operator_price, &customer_price,
				&operator_currency_id, &customer_currency_id,
				&operator_id, &customer_id);
				
		break;
		
		for(unsigned y = 2017; y <= 2019; y++) {
			tm easter = getEasterMondayDate(y);
			cout << sqlDateString(easter) << endl;
		}
		break;
	 
		SqlDb *sqlDb = createSqlObject();
		string query = "select * from geoip_country order by ip_from";
		cout << query << endl;
		sqlDb->query(query);
		string rsltQuery = sqlDb->getJsonResult();
		cout << rsltQuery << endl;
		break;
	 
		test_thread();
		break;
	 
		extern void testPN();
		testPN();
		break;
	 
		cCsv *csv = new cCsv();
		csv->setFirstRowContainFieldNames();
		csv->load("/home/jumbox/Plocha/table.csv");
		cout << "---" << endl;
		csv->dump();
		cout << "---" << endl;
		cout << csv->getRowsCount() << endl;
		cout << "---" << endl;
		map<string, string> row;
		csv->getRow(1, &row);
		for(map<string, string>::iterator iter = row.begin(); iter != row.end(); iter++) {
			cout << iter->first << " : " << iter->second << endl;
		}
		cout << "---" << endl;
		csv->getRow(csv->getRowsCount(), &row);
		for(map<string, string>::iterator iter = row.begin(); iter != row.end(); iter++) {
			cout << iter->first << " : " << iter->second << endl;
		}
		cout << "---" << endl;
		break;
	 
		cout << _sqlEscapeString("abc'\"\\\n\rdef", 0, NULL) << endl;
		char buff[100];
		_sqlEscapeString("abc'\"\\\n\rdef", 0, buff, NULL);
		cout << buff << endl;
		break;
	 
		FifoBuffer fb;
		fb.setMinItemBufferLength(100);
		fb.setMaxItemBufferLength(1000);
		
		char *x = new char[1000000];
		for(int i = 0; i < 10000; i++) {
			fb.add((u_char*)x, 1500);
		}
		delete [] x;
		
		cout << "***: " << fb.size_get() << endl;
		
		u_int32_t sum_get_size = 0;
		while(true) {
			u_int32_t get_length = 600;
			u_char *get = fb.get(&get_length);
			if(get) {
				sum_get_size += get_length;
				delete [] get;
			} else {
				break;
			}
		}
		cout << "***: " << sum_get_size << endl;
		
		fb.free();
		
		break;
	 
		test_filezip_handler();
		break;
	 
		cout << getSystemTimezone() << endl;
		cout << getSystemTimezone(1) << endl;
		cout << getSystemTimezone(2) << endl;
		cout << getSystemTimezone(3) << endl;
	 
		//test_time_cache();
		//test_parsepacket();
		break;
	 
		//test_search_country_by_number();
	 
		map<int, string> testmap;
		testmap[1] = "aaa";
		testmap[2] = "bbb";
		
		map<int, string>::iterator iter = testmap.begin();
		
		cout << testmap[1] << testmap[2] << iter->second << endl;
	 
		test_geoip();
		cout << "---------" << endl;
		*/
		
	} break;
	case 2: {
	 
		for(int i = 0; i < 10; i++) {
			sleep(1);
			cout << "." << flush;
		}
		cout << endl;
		SqlDb *sqlDb = createSqlObject();
		sqlDb->connect();
		for(int i = 0; i < 10; i++) {
			sleep(1);
			cout << "." << flush;
		}
		cout << endl;
		sqlDb->query("drop procedure if exists __insert_test");
	 
	} break;
	case 3: {
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		if(pointToSepOptTest) {
			initFraud();
			extern GeoIP_country *geoIP_country;
			cout << geoIP_country->getCountry(pointToSepOptTest + 1) << endl;
		}
	} break;
	case 4: {
		vm_atomic<string> astr(string("000"));
		cout << astr << endl;
		astr = string("abc");
		cout << astr << endl;
		astr = "def";
		cout << astr << endl;
		
		vm_atomic<string> astr2 = astr;
		cout << astr2 << endl;
		astr2 = astr;
		cout << astr2 << endl;
		
	} break;
	case 5:
		{
		extern void testPN();
		testPN();
		}
		break;
	case 51:
		test_alloc_speed();
		break;
	case 52:
		test_alloc_speed_malloc();
		break;
	case 53:
		#if HAVE_LIBTCMALLOC
		test_alloc_speed_tc();
		#else
		cout << "tcmalloc not exists" << endl;
		#endif
		break;
	case 6:
		test_untar();
		break;
	case 7: 
		test_http_dumper(); 
		break;
	case 8: 
		test_pexec();
		break;
	case 9: {
		vector<string> param;
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		if(pointToSepOptTest) {
			param = split(pointToSepOptTest + 1, ',');
		}
		if(param.size() < 5) {
			cout << "missing parameters" << endl
			     << "example: -X9/packet.bin,packet.pcap,214,4655546,54565" << endl
			     << "description: -X9/binary source,output pcap file,length,sec,usec" << endl;
		} else {
			save_packet(param[0].c_str(), param[1].c_str(), atoi(param[2].c_str()),
				    atoi(param[3].c_str()), atoi(param[4].c_str()));
		}
		} 
		break;
	case 88:
		setAllocNumb();
		return;
	case 90:
		{
		vector<string> param;
		char *pointToSepOptTest = strchr(opt_test_str, '/');
		if(pointToSepOptTest) {
			param = split(pointToSepOptTest + 1, ',');
		}
		if(param.size() < 1) {
			cout << "missing parameters" << endl
			     << "example: -X90/coredump,outfile" << endl;
		} else {
			parse_heapsafeplus_coredump(param[0].c_str(), param.size() > 1 ? param[1].c_str() : NULL);
		}
		}
		break;
	case 95:
		vmChdir();
		CleanSpool::run_check_filesindex();
		set_terminating();
		break;
	case 96:
		{
		union {
			uint32_t i;
			char c[4];
		} e = { 0x01000000 };
		cout << "real endian : " << (e.c[0] ? "big" : "little") << endl;
		cout << "endian by cmp __BYTE_ORDER == __BIG_ENDIAN : ";
		#if __BYTE_ORDER == __BIG_ENDIAN
			cout << "big" << endl;
		#else
			cout << "little" << endl;
		#endif
		#ifdef __BYTE_ORDER
			cout << "__BYTE_ORDER value (1234 is little, 4321 is big) : " << __BYTE_ORDER << endl;
		#else
			cout << "undefined __BYTE_ORDER" << endl;
		#endif
		#ifdef BYTE_ORDER
			cout << "BYTE_ORDER value (1234 is little, 4321 is big) : " << BYTE_ORDER << endl;
		#else
			cout << "undefined BYTE_ORDER" << endl;
		#endif
		}
		break;
	case 98:
		{
		RestartUpgrade restart(true, 
				       "8.4RC15", NULL,
				       "http://www.voipmonitor.org/senzor/download/8.4RC15",
				       "cf9c2b266204be6cef845003e713e6df",
				       "58e8ae1668b596cec20fd38aa7a83e23");
		restart.runUpgrade();
		cout << restart.getRsltString();
		}
		return;
	case 99:
		for(int i = 0; i < 2; i++) {
			if(isSetSpoolDir(i) &&
			   CleanSpool::isSetCleanspoolParameters(i)) {
				cleanSpool[i] = new FILE_LINE(42058) CleanSpool(i);
			}
		}
		CleanSpool::run_check_spooldir_filesindex();
		return;
		
	case 11: 
		{
		cConfig config;
		config.addConfigItems();
		config.loadFromConfigFile(configfile);
		cout << "***" << endl;
		cout << config.getContentConfig(true); 
		cout << "***" << endl;
		string jsonStr = config.getJson(true); 
		cout << jsonStr << endl;
		cout << "***" << endl;
		config.setFromJson(jsonStr.c_str());
		cout << "***" << endl;
		config.putToMysql();
		}
		break;
		
	case _param_reindex_all:
	case _param_run_cleanspool:
	case _param_run_cleanspool_maxdays:
	case _param_test_cleanspool_load:
	case _param_clean_obsolete:
		{
		if(opt_test == _param_run_cleanspool_maxdays) {
			if(atoi(opt_test_arg) > 0) {
				opt_maxpoolsize = 0;
				opt_maxpooldays = atoi(opt_test_arg);
				opt_maxpoolsipsize = 0;
				opt_maxpoolsipdays = 0;
				opt_maxpoolrtpsize = 0;
				opt_maxpoolrtpdays = 0;
				opt_maxpoolgraphsize = 0;
				opt_maxpoolgraphdays = 0;
				opt_maxpoolaudiosize = 0;
				opt_maxpoolaudiodays = 0;
			} else {
				return;
			}
		}
		sqlStore = new FILE_LINE(42059) MySqlStore(mysql_host, mysql_user, mysql_password, mysql_database, opt_mysql_port, mysql_socket,
							   isCloud() ? cloud_host : NULL, cloud_token, cloud_router, &optMySsl);
		for(int i = 0; i < 2; i++) {
			if(isSetSpoolDir(i) &&
			   CleanSpool::isSetCleanspoolParameters(i)) {
				cleanSpool[i] = new FILE_LINE(42060) CleanSpool(i);
			}
		}
		switch(opt_test) {
		case _param_reindex_all:
			CleanSpool::run_reindex_all("");
			break;
		case _param_run_cleanspool:
		case _param_run_cleanspool_maxdays:
			CleanSpool::run_cleanProcess();
			break;
		case _param_clean_obsolete:
			CleanSpool::run_clean_obsolete();
			break;
		case _param_test_cleanspool_load:
			CleanSpool::run_test_load(opt_test_arg);
			break;
		}
		set_terminating();
		sqlStore->setEnableTerminatingIfEmpty(0, 0, true);
		sqlStore->setEnableTerminatingIfSqlError(0, 0, true);
		delete sqlStore;
		sqlStore = NULL;
		}
		break;
	case _param_run_droppartitions_maxdays:
		if(atoi(opt_test_arg) > 0) {
			opt_cleandatabase_cdr =
			opt_cleandatabase_http_enum =
			opt_cleandatabase_webrtc =
			opt_cleandatabase_register_state =
			opt_cleandatabase_register_failed = 
			opt_cleandatabase_register_time_info = 
			opt_cleandatabase_sip_msg = atoi(opt_test_arg);
		} else {
			return;
		}
		dropMysqlPartitionsCdr();
		break;
	case _param_run_droppartitions_rtp_stat_maxdays:
		if(atoi(opt_test_arg) > 0) {
			opt_cleandatabase_rtp_stat = atoi(opt_test_arg);
		} else {
			return;
		}
		dropMysqlPartitionsRtpStat();
		break;
	case _param_run_droppartitions_cdr_stat_maxdays:
		if(atoi(opt_test_arg) > 0) {
			opt_cleandatabase_cdr_stat = atoi(opt_test_arg);
		} else {
			return;
		}
		dropMysqlPartitionsCdrStat();
		break;
	case _param_conv_raw_info:
		{
		Call *call = new FILE_LINE(0) Call(0, (char*)"conv-raw-info", 0, NULL, 0);
		call->type_base = INVITE;
		call->force_spool_path = opt_test_arg;
		sverb.noaudiounlink = true;
		call->convertRawToWav();
		}
		break;
	case _param_find_country_for_number:
		{
		CountryDetectInit();
		vector<string> numbersIps = split(opt_test_arg, ';');
		vmIP testIp;
		for(unsigned i = 0; i < numbersIps.size(); i++) {
			vector<string> nip = split(numbersIps[i], '@');
			if (nip.size() == 2) {
				testIp.setFromString(nip[1].c_str());
			}
			cout << "number:           " << nip[0] << endl;
			if (testIp.isSet()) {
				cout << "IP:               " << testIp.getString() << endl;
			}
			cout << "country:          " << getCountryByPhoneNumber(nip[0].c_str(), testIp) << endl;
			cout << "is international: " << (isLocalByPhoneNumber(nip[0].c_str(), testIp) ? "N" : "Y") << endl;
			cout << "---" << endl;
		}
		}
		break;
	case _param_find_country_for_ip:
		{
		CountryDetectInit();
		vector<string> ips = split(opt_test_arg, ';');
		for(unsigned i = 0; i < ips.size(); i++) {
			cout << "ip:      " << ips[i] << endl;
			cout << "country: " << getCountryByIP(str_2_vmIP(ips[i].c_str())) << endl;
			cout << "---" << endl;
		}
		}
		break;
	case _param_test_billing:
	case _param_test_billing_json:
		{
		cBilling billing;
		billing.load();
		cout << billing.test(opt_test_arg, opt_test == _param_test_billing_json) << endl;
		}
		break;
	case _param_check_bad_ether_type:
		check_bad_ether_type(opt_test_arg);
		break;
	case _param_load_rtp_pcap:
		load_rtp_pcap(opt_test_arg);
		break;
	}
 
	/*
	sqlDb->disconnect();
	sqlDb->connect();
	
	for(int pass = 0; pass < 3000; pass++) {
		cout << "pass " << (pass + 1) << endl;
		sqlDb->query("select * from cdr order by ID DESC");
		SqlDb_row row;
		row = sqlDb->fetchRow();
		cout << row["ID"] << " : " << row["calldate"] << endl;
		sleep(1);
	}
	*/
	
	/*
	if(opt_test >= 11 && opt_test <= 13) {
		rqueue<int> test;
		switch(opt_test) {
		case 11:
			test.push(1);
			test._test();
			break;
		case 12:
			test._testPerf(true);
			break;
		case 13:
			test._testPerf(false);
			break;
		}
		return;
	}
	*/

	/*
	int pipeFh[2];
	pipe(pipeFh);
	cout << pipeFh[0] << " / " << pipeFh[1] << endl;
	
	cout << "write" << endl;
	cout << "writed " << write(pipeFh[1], "1234" , 4) << endl;
	
	cout << "read" << endl;
	char buff[10];
	memset(buff, 0, 10);
	cout << "readed " << read(pipeFh[0], buff , 4) << endl;
	cout << buff;
	
	return;
	*/
	
	/*
	char filePathName[100];
	snprintf(filePathName, sizeof(filePathName), "/__test/store_%010u", 1);
	cout << filePathName << endl;
	remove(filePathName);
	int fileHandleWrite = open(filePathName, O_WRONLY | O_CREAT, 0666);
	cout << "write handle: " << fileHandleWrite << endl;
	//write(fileHandleWrite, "1234", 4);
	//close(fileHandleWrite);
	
	int fileHandleRead = open(filePathName, O_RDONLY);
	cout << "read handle: " << fileHandleRead << endl;
	cout << errno << endl;
	return;
	*/

	/*
	int port = 9001;
	
	PcapQueue_readFromInterface *pcapQueue0;
	PcapQueue_readFromFifo *pcapQueue1;
	PcapQueue_readFromFifo *pcapQueue2;
	
	if(opt_test == 1 || opt_test == 3) {
		pcapQueue0 = new FILE_LINE(42061) PcapQueue_readFromInterface("thread0");
		pcapQueue0->setInterfaceName(ifname);
		//pcapQueue0->setFifoFileForWrite("/tmp/vm_fifo0");
		//pcapQueue0->setFifoWriteHandle(pipeFh[1]);
		pcapQueue0->setEnableAutoTerminate(false);
		
		pcapQueue1 = new FILE_LINE(42062) PcapQueue_readFromFifo("thread1", "/__test");
		//pcapQueue1->setFifoFileForRead("/tmp/vm_fifo0");
		pcapQueue1->setInstancePcapHandle(pcapQueue0);
		//pcapQueue1->setFifoReadHandle(pipeFh[0]);
		pcapQueue1->setEnableAutoTerminate(false);
		//pcapQueue1->setPacketServer("127.0.0.1", port, PcapQueue_readFromFifo::directionWrite);
		
		pcapQueue0->start();
		pcapQueue1->start();
	}
	if(opt_test == 2 || opt_test == 3) {
		pcapQueue2 = new FILE_LINE(42063) PcapQueue_readFromFifo("server", "/__test/2");
		pcapQueue2->setEnableAutoTerminate(false);
		pcapQueue2->setPacketServer("127.0.0.1", port, PcapQueue_readFromFifo::directionRead);
		
		pcapQueue2->start();
	}
	
	while(!is_terminating()) {
		if(opt_test == 1 || opt_test == 3) {
			pcapQueue1->pcapStat();
		}
		if(opt_test == 2 || opt_test == 3) {
			pcapQueue2->pcapStat();
		}
		sleep(1);
	}
	
	if(opt_test == 1 || opt_test == 3) {
		pcapQueue0->terminate();
		sleep(1);
		pcapQueue1->terminate();
		sleep(1);
		
		delete pcapQueue0;
		delete pcapQueue1;
	}
	if(opt_test == 2 || opt_test == 3) {
		pcapQueue2->terminate();
		sleep(1);
		
		delete pcapQueue2;
	}
	return;
	*/
	
	/*
	sqlDb->disconnect();
	sqlDb->connect();
	
	sqlDb->query("select * from cdr order by ID DESC limit 2");
	SqlDb_row row1;
	while((row1 = sqlDb->fetchRow())) {
		cout << row1["ID"] << " : " << row1["calldate"] << endl;
	}
	
	return;
	*/

	/*
	cout << "db major version: " << sqlDb->getDbMajorVersion() << endl
	     << "db minor version: " << sqlDb->getDbMinorVersion() << endl
	     << "db minor version: " << sqlDb->getDbMinorVersion(1) << endl;
	*/
	
	/*
	initIpacc();
	extern CustPhoneNumberCache *custPnCache;
	cust_reseller cr;
	cr = custPnCache->getCustomerByPhoneNumber("0352307212");
	cout << cr.cust_id << " - " << cr.reseller_id << endl;
	*/
	
	/*
	extern CustIpCache *custIpCache;
	custIpCache->fetchAllIpQueryFromDb();
	*/
	
	/*
	for(int i = 1; i <= 10; i++) {
	sqlStore->lock(i);
	sqlStore->query("insert into _test set test = 1", i);
	sqlStore->query("insert into _test set test = 2", i);
	sqlStore->query("insert into _test set test = 3", i);
	sqlStore->query("insert into _test set test = 4", i);
	sqlStore->unlock(i);
	}
	set_terminating();
	//sleep(2);
	*/
	
	/*
	octects_live_t a;
	a.setFilter(string("192.168.1.2,192.168.1.1").c_str());
	cout << (a.isIpInFilter(inet_addr("192.168.1.1")) ? "find" : "----") << endl;
	cout << (a.isIpInFilter(inet_addr("192.168.1.3")) ? "find" : "----") << endl;
	cout << (a.isIpInFilter(inet_addr("192.168.1.2")) ? "find" : "----") << endl;
	cout << (a.isIpInFilter(inet_addr("192.168.1.3")) ? "find" : "----") << endl;
	*/
	
	/*
	extern void ipacc_add_octets(time_t timestamp, unsigned int saddr, unsigned int daddr, int port, int proto, int packetlen, int voippacket);
	extern void ipacc_save(unsigned int interval_time_limit = 0);

	//for(int i = 0; i < 100000; i++) {
	//	ipacc_add_octets(1, rand()%5000, rand()%5000, rand()%4, rand()%3, rand(), rand()%100);
	//}
	
	ipacc_add_octets(1, 1, 2, 3, 4, 5, 6);
	ipacc_add_octets(1, 1, 2, 3, 4, 5, 6);
	
	ipacc_save();
	
	freeMemIpacc();
	*/
	
	/*
	CustIpCache *custIpCache = new FILE_LINE(42064) CustIpCache;
	custIpCache->setConnectParams(
		get_customer_by_ip_sql_driver, 
		get_customer_by_ip_odbc_dsn, 
		get_customer_by_ip_odbc_user, 
		get_customer_by_ip_odbc_password, 
		get_customer_by_ip_odbc_driver);
	custIpCache->setQueryes(
		get_customer_by_ip_query, 
		get_customers_ip_query);
	
	unsigned int cust_id = custIpCache->getCustByIp(inet_addr("192.168.1.241"));
	cout << cust_id << endl;
	
	return;
	
	cout << endl << endl;
	for(int i = 0; i < 20; i++) {
		cout << "iter:" << (i+1) << endl;
		unsigned int cust_id = custIpCache->getCustByIp(inet_addr("1.2.3.4"));
		cout << cust_id << endl;
		cust_id = custIpCache->getCustByIp(inet_addr("2.3.4.5"));
		cout << cust_id << endl;
		sleep(1);
	}
	
	return;
	*/
	
	/*
	ipfilter = new FILE_LINE(42065) IPfilter;
	ipfilter->load();
	ipfilter->dump();

	telnumfilter = new FILE_LINE(42066) TELNUMfilter;
	telnumfilter->load();
	telnumfilter->dump();
	*/
	
	/*
	sqlDb->query("select _LC_[UNIX_TIMESTAMP('1970-01-01') = 0] as eee;");
	SqlDb_row row = sqlDb->fetchRow();
	cout << row["eee"] << endl;
	*/
	
	/*
	// výmaz - příprava
	sqlDb->query("delete from cdr_sip_response where id > 0");
	cout << sqlDb->getLastErrorString() << endl;
	
	// čtení
	SqlDb_row row1;
	sqlDb->query("select * from cdr order by ID DESC");
	while((row1 = sqlDb->fetchRow())) {
		cout << row1["ID"] << " : " << row1["calldate"] << endl;
	}
	cout << sqlDb->getLastErrorString() << endl;
	
	// zápis
	SqlDb_row row2;
	row2.add("122 wrrrrrrrr", "lastSIPresponse");
	cout << sqlDb->insert("cdr_sip_response", row2) << endl;

	// unique zápis
	SqlDb_row row3;
	row3.add("123 wrrrrrrrr", "lastSIPresponse");
	cout << sqlDb->getIdOrInsert("cdr_sip_response", "id", "lastSIPresponse", row3) << endl;
	
	cout << sqlDb->getLastErrorString() << endl;
	cout << endl << "--------------" << endl;
	*/
	
	//exit(0);
}
