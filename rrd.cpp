#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <syslog.h>

#include "rrd.h"
#include "tools.h"

#include <iostream>  
#include <sstream>  
#include <iomanip>
#include <string.h>


#define TRUE		1
#define FALSE		0
#define MAX_LENGTH	10000


int rrd_vm_create_graph_PS(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"PS\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"queries\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:PSC=" << filename << ":PS-C:MAX ";
	cmdCreate << "DEF:PSS0=" << filename << ":PS-S0:MAX ";
	cmdCreate << "DEF:PSS1=" << filename << ":PS-S1:MAX ";
	cmdCreate << "DEF:PSR=" << filename << ":PS-R:MAX ";
	cmdCreate << "DEF:PSA=" << filename << ":PS-A:MAX ";
	cmdCreate << "LINE1:PSC#0000FF:\"-C\\t\" ";
	cmdCreate << "GPRINT:PSC:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSC:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:PSC:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSC:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:PSS0#00FF00:\"-S0\\t\" ";
	cmdCreate << "GPRINT:PSS0:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSS0:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:PSS0:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSS0:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:PSS1#FF0000:\"-S1\\t\" ";
	cmdCreate << "GPRINT:PSS1:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSS1:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:PSS1:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSS1:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:PSR#00FFFF:\"-R\\t\" ";
	cmdCreate << "GPRINT:PSR:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSR:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:PSR:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSR:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:PSA#FFFF00:\"-A\\t\" ";
	cmdCreate << "GPRINT:PSA:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSA:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:PSA:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:PSA:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int rrd_vm_create_graph_speed(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"Bw speed\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"MB/s\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:speed=" << filename << ":mbs:MAX ";
	cmdCreate << "AREA:speed#00FF00:\"speed (Mb/s)\" ";
	cmdCreate << "GPRINT:speed:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:speed:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:speed:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:speed:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int rrd_vm_create_graph_SQLq(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"SQLq\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"queries\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:SQLqC=" << filename << ":SQLq-C:MAX ";
	cmdCreate << "DEF:SQLqM=" << filename << ":SQLq-M:MAX ";
	cmdCreate << "DEF:SQLqR=" << filename << ":SQLq-R:MAX ";
	cmdCreate << "DEF:SQLqCl=" << filename << ":SQLq-Cl:MAX ";
	cmdCreate << "DEF:SQLqH=" << filename << ":SQLq-H:MAX ";
	cmdCreate << "LINE1:SQLqC#0000FF:\"-C\\t\" ";
	cmdCreate << "GPRINT:SQLqC:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqC:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:SQLqC:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqC:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:SQLqM#00FF00:\"-M\\t\" ";
	cmdCreate << "GPRINT:SQLqM:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqM:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:SQLqM:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqM:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:SQLqR#FF0000:\"-R\\t\" ";
	cmdCreate << "GPRINT:SQLqR:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqR:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:SQLqR:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqR:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:SQLqCl#00FFFF:\"-Cl\\t\" ";
	cmdCreate << "GPRINT:SQLqCl:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqCl:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:SQLqCl:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqCl:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:SQLqH#FFFF00:\"-H\\t\" ";
	cmdCreate << "GPRINT:SQLqH:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqH:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:SQLqH:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:SQLqH:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int rrd_vm_create_graph_tCPU(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"tCPU usage\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"percent[%]\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:t0=" << filename << ":tCPU-t0:MAX ";
	cmdCreate << "DEF:t1=" << filename << ":tCPU-t1:MAX ";
	cmdCreate << "DEF:t2=" << filename << ":tCPU-t2:MAX ";
	cmdCreate << "LINE1:t0#0000FF:\"t0 CPU Usage %\\t\" ";
	cmdCreate << "GPRINT:t0:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t0:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t0:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t0:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:t1#0000FF:\"t1 CPU Usage %\\t\" ";
	cmdCreate << "GPRINT:t1:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t1:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t1:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t1:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:t2#0000FF:\"t2 CPU Usage %\\t\" ";
	cmdCreate << "GPRINT:t2:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t2:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t2:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:t2:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int rrd_vm_create_graph_heap(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"Mem heap usage\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"percent[%]\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:buffer=" << filename << ":buffer:MAX ";
	cmdCreate << "DEF:trash=" << filename << ":trash:MAX ";
	cmdCreate << "DEF:ratio=" << filename << ":ratio:MAX ";
	cmdCreate << "LINE1:buffer#0000FF:\"Buffer usage %\\t\" ";
	cmdCreate << "GPRINT:buffer:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:buffer:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:buffer:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:buffer:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:trash#00FF00:\"Trash usage %\\t\" ";
	cmdCreate << "GPRINT:trash:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:trash:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:trash:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:trash:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:ratio#FF0000:\"Ratio %\\t\" ";
	cmdCreate << "GPRINT:ratio:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:ratio:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:ratio:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:ratio:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int rrd_vm_create_graph_drop(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"Dropping packets\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"packtets\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:exc=" << filename << ":exceeded:MAX ";
	cmdCreate << "DEF:pck=" << filename << ":packets:MAX ";
	cmdCreate << "LINE1:exc#0000FF:\"Buffer overloaded\\t\" ";
	cmdCreate << "GPRINT:exc:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:exc:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:exc:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:exc:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "LINE1:pck#00FF00:\"Packets dropped\\t\" ";
	cmdCreate << "GPRINT:pck:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:pck:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:pck:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:pck:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int rrd_vm_create_graph_calls(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"Number of calls\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"calls\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:callsmin=" << filename << ":calls:MIN ";
	cmdCreate << "DEF:callsavg=" << filename << ":calls:AVERAGE ";
	cmdCreate << "DEF:callsmax=" << filename << ":calls:MAX ";
	cmdCreate << "AREA:callsmax#00FF00:\"calls max\" ";
	cmdCreate << "LINE1:callsavg#0000FF:\"Calls avg\\t\" ";
	cmdCreate << "LINE1:callsmin#FF0000:\"Calls min\\t\" ";
	cmdCreate << "GPRINT:callsmax:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:callsmax:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:callsmax:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:callsmax:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
/*	FILE* destFile;
	destFile = fopen("/tmp/pokusne", "wb");
	fwrite(cmdCreate.str().c_str(), 1, strlen(cmdCreate.str().c_str()), destFile);
	fclose(destFile);
*/
}

int rrd_vm_create_graph_tacCPU(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"tac CPU\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"threads\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:tac=" << filename << ":tacCPU:MAX ";
	cmdCreate << "LINE1:tac#0000FF:\"Usage\\t\" ";
	cmdCreate << "GPRINT:tac:LAST:\"Cur\\: %5.2lf\" ";
	cmdCreate << "GPRINT:tac:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:tac:MAX:\"Max\\: %5.2lf\" ";
	cmdCreate << "GPRINT:tac:MIN:\"Min\\: %5.2lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int rrd_vm_create_graph_RSSVSZ(char *filename, char *fromatstyle, char *toatstyle, int resx, int resy, short slope, short icon) {
    std::ostringstream cmdCreate;

	cmdCreate << "`which rrdtool` graph " << filename << ".png ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start " << fromatstyle << " --end " << toatstyle << " ";
	cmdCreate << "--font DEFAULT:7: ";
	cmdCreate << "--title \"RSS_VSZ\" ";
	cmdCreate << "--watermark \"`date`\" ";
	cmdCreate << "--vertical-label \"MB\" ";
	cmdCreate << "--lower-limit 0 ";
	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	cmdCreate << "--full-size-mode ";
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph "; //height need to be < 32px
	cmdCreate << "DEF:rss=" << filename << ":RSS:MAX ";
	cmdCreate << "DEF:vsz=" << filename << ":VSZ:MAX ";
	cmdCreate << "AREA:vsz#00FF00:\"Mem Usage VSZ\\t\" ";
	cmdCreate << "GPRINT:vsz:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:vsz:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:vsz:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:vsz:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	cmdCreate << "AREA:rss#0000FF:\"-S0\\t\" ";
	cmdCreate << "GPRINT:rss:LAST:\"Cur\\: %5.0lf\" ";
	cmdCreate << "GPRINT:rss:AVERAGE:\"Avg\\: %5.2lf\" ";
	cmdCreate << "GPRINT:rss:MAX:\"Max\\: %5.0lf\" ";
	cmdCreate << "GPRINT:rss:MIN:\"Min\\: %5.0lf\\t\\t\\t\" ";
	int res = system(cmdCreate.str().c_str());
	if (verbosity > 1) syslog(LOG_NOTICE, "Create graph's args:%s\nRetVal:%d", cmdCreate.str().c_str(), res);
	return res;
}

int vm_rrd_create_rrddrop(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:exceeded:GAUGE:20:0:1000000 ";
    cmdCreate << "DS:packets:GAUGE:20:0:1000000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdheap(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:buffer:GAUGE:20:0:1000000 ";
    cmdCreate << "DS:trash:GAUGE:20:0:1000000 ";
    cmdCreate << "DS:ratio:GAUGE:20:0:10000000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdPS(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:PS-C:GAUGE:20:0:1000000 ";
    cmdCreate << "DS:PS-S0:GAUGE:20:0:1000000 ";
    cmdCreate << "DS:PS-S1:GAUGE:20:0:1000000 ";
    cmdCreate << "DS:PS-R:GAUGE:20:0:10000000 ";
    cmdCreate << "DS:PS-A:GAUGE:20:0:10000000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdSQLq(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:SQLq-C:GAUGE:20:0:10000 ";
    cmdCreate << "DS:SQLq-M:GAUGE:20:0:10000 ";
    cmdCreate << "DS:SQLq-R:GAUGE:20:0:10000 ";
    cmdCreate << "DS:SQLq-Cl:GAUGE:20:0:10000 ";
    cmdCreate << "DS:SQLq-H:GAUGE:20:0:10000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdtCPU(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:tCPU-t0:GAUGE:20:0:100 ";
    cmdCreate << "DS:tCPU-t1:GAUGE:20:0:100 ";
    cmdCreate << "DS:tCPU-t2:GAUGE:20:0:100 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdtacCPU(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:tacCPU:GAUGE:20:0:10000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdRSSVSZ(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:RSS:GAUGE:20:0:1000000 ";
    cmdCreate << "DS:VSZ:GAUGE:20:0:1000000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdspeedmbs(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:mbs:GAUGE:20:0:100000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdcallscounter(const char *filename) {
    std::ostringstream cmdCreate;

    cmdCreate << "create " << filename << " ";
    cmdCreate << "--start N --step 10 ";
    cmdCreate << "DS:calls:GAUGE:20:0:200000 ";
    cmdCreate << "RRA:MIN:0.5:12:1440 ";
    cmdCreate << "RRA:MAX:0.5:12:1440 ";
    cmdCreate << "RRA:AVERAGE:0.5:1:1440";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}



int vm_rrd_create(const char *filename, const char *cmdline)
{
	int res;
	if(access(filename, 0) != -1) 
	{			
		if (verbosity > 0) syslog(LOG_NOTICE, "RRD file %s already exist. Creating Skipped.\n", filename);
		res = -1;
	} else {
		//syslog(LOG_NOTICE, "Creating RRD Database file: %s\n", filename);
		res = rrd_call(cmdline);
		if (verbosity > 1) syslog (LOG_NOTICE,"CREATED RRD file %s with result of: %d\n",filename, res);
	}
	return res;
}

int vm_rrd_update(const char *filename, const char *value)
{
	std::ostringstream cmdUpdate;
	int res;
	if(access(filename, 0|2) != -1) {
		cmdUpdate << "update " << filename << " " << value;
		//syslog(LOG_NOTICE, "Updating RRD file: %s \n", filename);
		res = rrd_call(cmdUpdate.str().c_str());
		if (verbosity > 1) syslog(LOG_NOTICE, "Updated RRD file: %s with command %s resulted in retval:%d\n", filename, cmdUpdate.str().c_str(),res);
	} else {		//rrd file is unaccessible
		if (verbosity > 0) syslog(LOG_NOTICE, "Cannot update non existent RRD file: %s\n", filename);
		res = -1;
	}
	return res;
}
/*
int vm_rrd_update(char *filename, int value)
{
	int res;
	if(access(filename, 0|2) != -1)
	{				//if rrd file exist and ha w permissions, we can update it 
		syslog(LOG_NOTICE, "Updating RRD Database file: %s\n", filename);
		char *commandStr;
		int commandLen = snprintf(NULL,0,"update %s --template pl:rtt N:0:%d", filename, value);
		commandStr = (char *) malloc(commandLen + 1);
		sprintf(commandStr, "update %s --template pl:rtt N:0:%d", filename, value);
		int res = rrd_call(commandStr);
		syslog(LOG_NOTICE, "retval of rrd_call %s:%d",filename, res);
		free(commandStr);
	} else {		//rrd file is unaccessible
		syslog(LOG_NOTICE, "Cannot update non existent RRD Database file: %s\n", filename);
		res = -1;
	}
	return res;
}
*/

static char *fgetslong(
	char **aLinePtr,
	FILE * stream)
{
	char	 *linebuf;
	size_t	  bufsize = MAX_LENGTH;
	int		  eolpos = 0;

	if (feof(stream))
		return *aLinePtr = 0;
	if (!(linebuf = (char *) malloc(bufsize))) {
		perror("fgetslong: malloc");
		exit(1);
	}
	linebuf[0] = '\0';
	while (fgets(linebuf + eolpos, MAX_LENGTH, stream)) {
		eolpos += strlen(linebuf + eolpos);
		if (linebuf[eolpos - 1] == '\n')
			return *aLinePtr = linebuf;
		bufsize += MAX_LENGTH;
		if (!(linebuf = (char *) realloc(linebuf, bufsize))) {
			free(linebuf);
			perror("fgetslong: realloc");
			exit(1);
		}
	}
	
	if (linebuf[0]){
		return	*aLinePtr = linebuf;
	}
	free(linebuf);
	return *aLinePtr = 0;
}


/* HandleInputLine is NOT thread safe - due to readdir issues,
   resolving them portably is not really simple. */
static int HandleInputLine(
	int argc,
	char **argv,
	FILE * out)
{
#if defined(HAVE_OPENDIR) && defined (HAVE_READDIR)
	DIR		 *curdir;	/* to read current dir with ls */
	struct dirent *dent;
#endif

	if (argc < 3
		|| strcmp("help", argv[1]) == 0
		|| strcmp("--help", argv[1]) == 0
		|| strcmp("-help", argv[1]) == 0
		|| strcmp("-?", argv[1]) == 0 || strcmp("-h", argv[1]) == 0) {
		return 0;
	}

	if (strcmp("create", argv[1]) == 0)
		rrd_create(argc - 1, &argv[1]);
	else if (strcmp("dump", argv[1]) == 0)
		rrd_dump(argc - 1, &argv[1]);
	else if (strcmp("info", argv[1]) == 0 || strcmp("updatev", argv[1]) == 0) {
		rrd_info_t *data;

		if (strcmp("info", argv[1]) == 0)

			data = rrd_info(argc - 1, &argv[1]);
		else
			data = rrd_update_v(argc - 1, &argv[1]);
		rrd_info_print(data);
		rrd_info_free(data);
	}

	else if (strcmp("restore", argv[1]) == 0)
		rrd_restore(argc - 1, &argv[1]);
	else if (strcmp("resize", argv[1]) == 0)
		rrd_resize(argc - 1, &argv[1]);
	else if (strcmp("last", argv[1]) == 0)
		printf("%ld\n", rrd_last(argc - 1, &argv[1]));
	else if (strcmp("lastupdate", argv[1]) == 0) {
		rrd_lastupdate(argc - 1, &argv[1]);
	} else if (strcmp("first", argv[1]) == 0)
		printf("%ld\n", rrd_first(argc - 1, &argv[1]));
	else if (strcmp("update", argv[1]) == 0)
		rrd_update(argc - 1, &argv[1]);
	else if (strcmp("fetch", argv[1]) == 0) {
		time_t	  start, end, ti;
		unsigned long step, ds_cnt, i, ii;
		rrd_value_t *data, *datai;
		char	**ds_namv;

		if (rrd_fetch
			(argc - 1, &argv[1], &start, &end, &step, &ds_cnt, &ds_namv,
			 &data) == 0) {
			datai = data;
			printf("		   ");
			for (i = 0; i < ds_cnt; i++)
				printf("%20s", ds_namv[i]);
			printf("\n\n");
			for (ti = start + step; ti <= end; ti += step) {
				printf("%10lu:", ti);
				for (ii = 0; ii < ds_cnt; ii++)
					printf(" %0.10e", *(datai++));
				printf("\n");
			}
			for (i = 0; i < ds_cnt; i++)
				free(ds_namv[i]);
			free(ds_namv);
			free(data);
		}
	} else if (strcmp("xport", argv[1]) == 0) {
#ifdef HAVE_RRD_GRAPH
	  time_t	start, end;
	  unsigned long step, col_cnt;
	  rrd_value_t *data;
	  char	  **legend_v;
	  rrd_xport
	(argc - 1, &argv[1], NULL, &start, &end, &step, &col_cnt,
	 &legend_v, &data);
#else
		rrd_set_error("the instance of rrdtool has been compiled without graphics");
#endif
	} else if (strcmp("graph", argv[1]) == 0) {
#ifdef HAVE_RRD_GRAPH
		char	**calcpr;

#ifdef notused /*XXX*/
		const char *imgfile = argv[2];	/* rrd_graph changes argv pointer */
#endif
		int		  xsize, ysize;
		double	  ymin, ymax;
		int		  i;
		int		  tostdout = (strcmp(argv[2], "-") == 0);
		int		  imginfo = 0;

		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--imginfo") == 0
				|| strcmp(argv[i], "-f") == 0) {
				imginfo = 1;
				break;
			}
		}
		if (rrd_graph
			(argc - 1, &argv[1], &calcpr, &xsize, &ysize, NULL, &ymin,
			 &ymax) == 0) {
			if (!tostdout && !imginfo)
				printf("%dx%d\n", xsize, ysize);
			if (calcpr) {
				for (i = 0; calcpr[i]; i++) {
					if (!tostdout)
						printf("%s\n", calcpr[i]);
					free(calcpr[i]);
				}
				free(calcpr);
			}
		}

#else
	   rrd_set_error("the instance of rrdtool has been compiled without graphics");
#endif
	} else if (strcmp("graphv", argv[1]) == 0) {
#ifdef HAVE_RRD_GRAPH
		rrd_info_t *grinfo = NULL;	/* 1 to distinguish it from the NULL that rrd_graph sends in */

		grinfo = rrd_graph_v(argc - 1, &argv[1]);
		if (grinfo) {
			rrd_info_print(grinfo);
			rrd_info_free(grinfo);
		}
#else
	   rrd_set_error("the instance of rrdtool has been compiled without graphics");
#endif
	} else if (strcmp("tune", argv[1]) == 0)
		rrd_tune(argc - 1, &argv[1]);
	else if (strcmp("flushcached", argv[1]) == 0)
		rrd_flushcached(argc - 1, &argv[1]);
	else {
		rrd_set_error("unknown function '%s'", argv[1]);
	}
	if (rrd_test_error()) {
		fprintf(out, "ERROR: %s\n", rrd_get_error());
		rrd_clear_error();
		return 1;
	}
	return (0);
}

int vm_rrd_countArgs(
	char *aLine)
{
	int		  i = 0;
	int		  aCount = 0;
	int		  inarg = 0;

	while (aLine[i] == ' ')
		i++;
	while (aLine[i] != 0) {
		if ((aLine[i] == ' ') && inarg) {
			inarg = 0;
		}
		if ((aLine[i] != ' ') && !inarg) {
			inarg = 1;
			aCount++;
		}
		i++;
	}
	return aCount;
}

static int CountArgsC(
	const char *aLine)
{
	int		  i = 0;
	int		  aCount = 0;
	int		  inarg = 0;

	while (aLine[i] == ' ')
		i++;
	while (aLine[i] != 0) {
		if ((aLine[i] == ' ') && inarg) {
			inarg = 0;
		}
		if ((aLine[i] != ' ') && !inarg) {
			inarg = 1;
			aCount++;
		}
		i++;
	}
	return aCount;
}

/*
 * vm_rrd_createArgs - take a string (aLine) and tokenize
 */
int vm_rrd_createArgs(
	char *pName,
	char *aLine,
	char **argv)
{
	char	 *getP, *putP;
	char	**pargv = argv;
	char	  Quote = 0;
	int		  inArg = 0;
	int		  len;
	int		  argc = 1;

	len = strlen(aLine);
	/* remove trailing space and newlines */
	while (len && aLine[len] <= ' ') {
		aLine[len] = 0;
		len--;
	}
	/* sikp leading blanks */
	while (*aLine && *aLine <= ' ')
		aLine++;

	pargv[0] = pName;
	argc = 1;
	getP = aLine;
	putP = aLine;
	while (*getP) {
		switch (*getP) {
		case ' ':
			if (Quote) {
				*(putP++) = *getP;
			} else if (inArg) {
				*(putP++) = 0;
				inArg = 0;
			}
			break;
		case '"':
		case '\'':
			if (Quote != 0) {
				if (Quote == *getP)
					Quote = 0;
				else {
					*(putP++) = *getP;
				}
			} else {
				if (!inArg) {
					pargv[argc++] = putP;
					inArg = 1;
				}
				Quote = *getP;
			}
			break;
		default:
			if (!inArg) {
				pargv[argc++] = putP;
				inArg = 1;
			}
			*(putP++) = *getP;
			break;
		}
		getP++;
	}

	*putP = '\0';
	int i=0;
	while (i < argc) {
		printf("ARGC:%d Arg:[%d] = %s\n",argc,i,pargv[i]);
		i++;
	}

	if (Quote)
		return -1;
	else
		return argc;
}


int rrd_call(
	const char *aLine
	)
{
	int myargc;
	char *tmpLine;
	char **myargv;

	if ((myargc = CountArgsC(aLine)) == 0) {
		syslog(LOG_NOTICE, "rrd_call ERROR: not enough arguments\nYou gave: %s\n", aLine);
		return -1;
	}
//	printf ("CountArgs vratil %d\n",myargc);

	if ((tmpLine = (char *) malloc((strlen(aLine) + 1) * sizeof(char *))) == NULL) {
		syslog(LOG_ERR, "rrd_call malloc error\n");
		return -1;
	}
	if ((myargv = (char **) malloc((myargc + 1) * sizeof(char *))) == NULL) {
		free(tmpLine);
		syslog(LOG_ERR, "rrd_call malloc error2\n");
		return -1;
	}

	memcpy(tmpLine, aLine, strlen(aLine));
	tmpLine[strlen(aLine)] = '\0';

	if ((myargc = vm_rrd_createArgs("voipmonitor-bin", tmpLine, myargv)) > 0) {
		int result = HandleInputLine(myargc, myargv, stderr);
		free(tmpLine);
		free(myargv);
		return (result);
	} else {
		free(tmpLine);
		free(myargv);
		return -1;
	}
}

