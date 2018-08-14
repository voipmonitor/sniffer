#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <syslog.h>

#include "voipmonitor.h"
#include "rrd.h"
#include "tools.h"

#include <iostream>  
#include <sstream>  
#include <iomanip>
#include <string.h>


#define TRUE		1
#define FALSE		0
#define MAX_LENGTH	10000

int vm_rrd_version;


void rrd_vm_create_graph_tCPU_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph \"" << dstfile << "\" ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"CPU usage\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"percent[%]\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:t0=" << filename << ":tCPU-t0:MAX ";
	cmdCreate << "DEF:t1=" << filename << ":tCPU-t1:MAX ";
	cmdCreate << "DEF:t2=" << filename << ":tCPU-t2:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:t0#0000FF:\"t0 CPU Usage %\\t\" ";
		cmdCreate << "GPRINT:t0:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MIN:\"Min\\: %5.2lf\\l\" ";
		cmdCreate << "LINE1:t1#00FF00:\"t1 CPU Usage %\\t\" ";
		cmdCreate << "GPRINT:t1:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MIN:\"Min\\: %5.2lf\\l\" ";
		cmdCreate << "LINE1:t2#FF0000:\"t2 CPU Usage %\\t\" ";
		cmdCreate << "GPRINT:t2:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MIN:\"Min\\: %5.2lf\\l\" ";
	} else {
		cmdCreate << "LINE1:t0#0000FF:\"t0 CPU Usage %\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:t0:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MIN:\"Min\\: %5.2lf\\r\" ";
		cmdCreate << "LINE1:t1#00FF00:\"t1 CPU Usage %\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:t1:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MIN:\"Min\\: %5.2lf\\r\" ";
		cmdCreate << "LINE1:t2#FF0000:\"t2 CPU Usage %\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:t2:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MIN:\"Min\\: %5.2lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_heap_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Buffer usage\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"percent[%]\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:buffer=" << filename << ":buffer:MAX ";
	cmdCreate << "DEF:ratio=" << filename << ":ratio:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:buffer#0000FF:\"Packet buffer %\\t\\t\" ";
		cmdCreate << "GPRINT:buffer:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:buffer:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:buffer:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:buffer:MIN:\"Min\\: %5.2lf\\l\" ";
		cmdCreate << "LINE1:ratio#FF0000:\"I/O buffer usage %\\t\" ";
		cmdCreate << "GPRINT:ratio:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:ratio:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:ratio:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:ratio:MIN:\"Min\\: %5.2lf\\l\" ";
	} else {
		cmdCreate << "LINE1:buffer#0000FF:\"Packet buffer %\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:buffer:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:buffer:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:buffer:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:buffer:MIN:\"Min\\: %5.2lf\\r\" ";
		cmdCreate << "LINE1:ratio#FF0000:\"I/O buffer usage %\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:ratio:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:ratio:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:ratio:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:ratio:MIN:\"Min\\: %5.2lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_drop_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Packet drops\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"packtets\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:exc=" << filename << ":exceeded:MAX ";
	cmdCreate << "DEF:pck=" << filename << ":packets:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:exc#0000FF:\"Buffer overloaded\\t\" ";
		cmdCreate << "GPRINT:exc:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:exc:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:exc:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:exc:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:pck#00FF00:\"Packets dropped\\t\" ";
		cmdCreate << "GPRINT:pck:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:pck:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:pck:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:pck:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:exc#0000FF:\"Buffer overloaded\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:exc:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:exc:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:exc:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:exc:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:pck#00FF00:\"Packets dropped\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:pck:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:pck:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:pck:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:pck:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_calls_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Number of calls\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"calls\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:callsmin=" << filename << ":inv:MIN ";
	cmdCreate << "DEF:callsavg=" << filename << ":inv:AVERAGE ";
	cmdCreate << "DEF:callsmax=" << filename << ":inv:MAX ";
	cmdCreate << "DEF:regsmin=" << filename << ":reg:MIN ";
	cmdCreate << "DEF:regsavg=" << filename << ":reg:AVERAGE ";
	cmdCreate << "DEF:regsmax=" << filename << ":reg:MAX ";

	if (vm_rrd_version < 10403) {
		cmdCreate << "AREA:callsmax#00FF00:\"INVs max\\l\" ";
		cmdCreate << "LINE1:callsavg#0000FF:\"INVs avg\\l\" ";
		cmdCreate << "LINE1:callsmin#FF0000:\"INVs min\\t\" ";
		cmdCreate << "GPRINT:callsmax:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:callsmax:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:callsmax:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:callsmax:MIN:\"Min\\: %5.0lf\\l\" ";

		cmdCreate << "AREA:regsmax#99FF00:\"REGs max\\l\" ";
		cmdCreate << "LINE1:regsavg#9999FF:\"REGs avg\\l\" ";
		cmdCreate << "LINE1:regsmin#FF9900:\"REGs min\\t\" ";
		cmdCreate << "GPRINT:regsmax:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:regsmax:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:regsmax:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:regsmax:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "AREA:callsmax#00FF00:\"INVs max\\l\" ";
		cmdCreate << "LINE1:callsavg#0000FF:\"INVs avg\\l\" ";
		cmdCreate << "LINE1:callsmin#FF0000:\"INVs min\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:callsmax:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:callsmax:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:callsmax:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:callsmax:MIN:\"Min\\: %5.0lf\\r\" ";

		cmdCreate << "AREA:regsmax#99FF00:\"REGs max\\l\" ";
		cmdCreate << "LINE1:regsavg#9999FF:\"REGs avg\\l\" ";
		cmdCreate << "LINE1:regsmin#FF9900:\"REGs min\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:regsmax:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:regsmax:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:regsmax:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:regsmax:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_tacCPU_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Compression\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"Total consumption\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:zip=" << filename << ":zipCPU:MAX ";
	cmdCreate << "DEF:tar=" << filename << ":tarCPU:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:zip#0000FF:\"Zip compression %\\t\" ";
		cmdCreate << "GPRINT:zip:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:zip:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:zip:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:zip:MIN:\"Min\\: %5.2lf\\l\" ";
		cmdCreate << "LINE1:tar#00FF00:\"Tar compression %\\t\" ";
		cmdCreate << "GPRINT:tar:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:tar:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:tar:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:tar:MIN:\"Min\\: %5.2lf\\l\" ";
	} else {
		cmdCreate << "LINE1:zip#0000FF:\"Zip compression %\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:zip:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:zip:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:zip:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:zip:MIN:\"Min\\: %5.2lf\\r\" ";
		cmdCreate << "LINE1:tar#00FF00:\"Tar compression %\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:tar:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:tar:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:tar:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:tar:MIN:\"Min\\: %5.2lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_memusage_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Memory usage\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"MB\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:rss=" << filename << ":RSS:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "AREA:rss#00FF00:\"Used memory\\t\\t\\t\" ";
		cmdCreate << "GPRINT:rss:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:rss:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:rss:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:rss:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "AREA:rss#00FF00:\"Used memory (RSS)\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:rss:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:rss:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:rss:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:rss:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_speed_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Network throughput\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"MB/s\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:speed=" << filename << ":mbs:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "AREA:speed#00FF00:\"speed (Mb/s)\\t\" ";
		cmdCreate << "GPRINT:speed:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:speed:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:speed:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:speed:MIN:\"Min\\: %5.2lf\\l\" ";
	} else {
		cmdCreate << "AREA:speed#00FF00:\"speed (Mb/s)\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:speed:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:speed:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:speed:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:speed:MIN:\"Min\\: %5.2lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_SQLf_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"SQL cache files\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"sec,count\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:tmpSQLfD=" << filename << ":SQLf-D:MAX ";
	cmdCreate << "CDEF:SQLfD=tmpSQLfD,1000,/ ";  //Create seconds from ms
	cmdCreate << "DEF:SQLfC=" << filename << ":SQLf-C:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:SQLfD#0000FF:\"SQL delay in s\\t\\t\" ";
		cmdCreate << "GPRINT:SQLfD:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfD:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfD:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfD:MIN:\"Min\\: %5.2lf\\l\" ";
		cmdCreate << "LINE1:SQLfC#FF0000:\"SQL queries count\\t\\t\" ";
		cmdCreate << "GPRINT:SQLfC:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLfC:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfC:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLfC:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:SQLfD#0000FF:\"SQL delay in s\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:SQLfD:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfD:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfD:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfD:MIN:\"Min\\: %5.2lf\\r\" ";
		cmdCreate << "LINE1:SQLfC#FF0000:\"SQL queries count\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:SQLfC:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLfC:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLfC:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLfC:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_SQLq_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"SQL queue\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"queries\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:SQLqC=" << filename << ":SQLq-C:MAX ";
	cmdCreate << "DEF:SQLqM=" << filename << ":SQLq-M:MAX ";
	cmdCreate << "DEF:SQLqR=" << filename << ":SQLq-R:MAX ";
	cmdCreate << "DEF:SQLqCl=" << filename << ":SQLq-Cl:MAX ";
	cmdCreate << "DEF:SQLqH=" << filename << ":SQLq-H:MAX ";
	cmdCreate << "CDEF:SQLqCM=SQLqC,1,* ";			//multiplication of calls disabled (not needed)
	cmdCreate << "CDEF:SQLqMM=SQLqM,100,* ";
	cmdCreate << "CDEF:SQLqRM=SQLqR,100,* ";
	cmdCreate << "CDEF:SQLqClM=SQLqCl,100,* ";
	cmdCreate << "CDEF:SQLqHM=SQLqH,100,* ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:SQLqCM#0000FF:\"CDR queue\\t\\t\" ";
		cmdCreate << "GPRINT:SQLqCM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqCM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqCM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqCM:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:SQLqMM#00FF00:\"Message queue\\t\" ";
		cmdCreate << "GPRINT:SQLqMM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqMM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqMM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqMM:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:SQLqRM#FF0000:\"Register queue\\t\" ";
		cmdCreate << "GPRINT:SQLqRM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqRM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqRM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqRM:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:SQLqClM#00FFFF:\"Cleanspool queue\\t\" ";
		cmdCreate << "GPRINT:SQLqClM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqClM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqClM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqClM:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:SQLqHM#999966:\"Http queue\\t\\t\" ";
		cmdCreate << "GPRINT:SQLqHM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqHM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqHM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqHM:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:SQLqCM#0000FF:\"CDR queue\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:SQLqCM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqCM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqCM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqCM:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:SQLqMM#00FF00:\"Message queue\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:SQLqMM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqMM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqMM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqMM:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:SQLqRM#FF0000:\"Register queue\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:SQLqRM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqRM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqRM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqRM:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:SQLqClM#00FFFF:\"Cleanspool queue\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:SQLqClM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqClM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqClM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqClM:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:SQLqHM#999966:\"Http queue\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:SQLqHM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqHM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:SQLqHM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:SQLqHM:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_PS_command (char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL) 
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Packet Counter\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"number of packets\" ";
	cmdCreate << "--lower-limit 0 ";
//	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:PSC=" << filename << ":PS-C:MAX ";
	cmdCreate << "DEF:PSS0=" << filename << ":PS-S0:MAX ";
	cmdCreate << "DEF:PSS1=" << filename << ":PS-S1:MAX ";
	cmdCreate << "DEF:PSSR=" << filename << ":PS-SR:MAX ";
	cmdCreate << "DEF:PSSM=" << filename << ":PS-SM:MAX ";
	cmdCreate << "DEF:PSR=" << filename << ":PS-R:MAX ";
	cmdCreate << "DEF:PSA=" << filename << ":PS-A:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:PSC#0000FF:\"calls/second\\t\\t\\t\" ";
		cmdCreate << "GPRINT:PSC:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSC:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:PSS0#00FF00:\"valid SIP packets/second\\t\" ";
		cmdCreate << "GPRINT:PSS0:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS0:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:PSS1#FF0000:\"SIP packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSS1:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS1:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:PSSR#FF00FF:\"SIP REG packets/second\\t\" ";
		cmdCreate << "GPRINT:PSSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:PSSM#FFFF00:\"SIP MES packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSSM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:PSR#00FFFF:\"RTP packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:PSA#999966:\"all packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSA:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSA:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:PSC#0000FF:\"calls/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSC:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSC:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:PSS0#00FF00:\"valid SIP packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSS0:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS0:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:PSS1#FF0000:\"SIP packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSS1:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS1:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:PSSR#FF00FF:\"SIP REG packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:PSSM#FFFF00:\"SIP MES packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSSM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:PSR#00FFFF:\"RTP packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:PSA#999966:\"all packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSA:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSA:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_PSC_command (char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL)
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Calls counter\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"number of calls\" ";
	cmdCreate << "--lower-limit 0 ";
//	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:PSC=" << filename << ":PS-C:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:PSC#0000FF:\"calls/second\\t\\t\\t\" ";
		cmdCreate << "GPRINT:PSC:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSC:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:PSC#0000FF:\"calls/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSC:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSC:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSC:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_PSS_command (char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL)
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"SIP packets counter\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"number of packets\" ";
	cmdCreate << "--lower-limit 0 ";
//	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:PSS0=" << filename << ":PS-S0:MAX ";
	cmdCreate << "DEF:PSS1=" << filename << ":PS-S1:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:PSS0#00FF00:\"valid SIP packets/second\\t\" ";
		cmdCreate << "GPRINT:PSS0:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS0:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:MIN:\"Min\\: %5.0lf\\l\" ";
		cmdCreate << "LINE1:PSS1#FF0000:\"SIP packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSS1:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS1:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:PSS0#00FF00:\"valid SIP packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSS0:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS0:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS0:MIN:\"Min\\: %5.0lf\\r\" ";
		cmdCreate << "LINE1:PSS1#FF0000:\"SIP packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSS1:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSS1:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSS1:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_PSSR_command (char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL)
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"SIP register packets counter\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"number of packets\" ";
	cmdCreate << "--lower-limit 0 ";
//	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:PSSR=" << filename << ":PS-SR:MAX ";
	if (vm_rrd_version < 10403) {
			cmdCreate << "LINE1:PSSR#FF00FF:\"SIP REG packets/second\\t\" ";
		cmdCreate << "GPRINT:PSSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:MIN:\"Min\\: %5.0lf\\l\" ";
			} else {
		cmdCreate << "LINE1:PSSR#FF00FF:\"SIP REG packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSR:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_PSSM_command (char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL)
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"SIP message packets counter\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"number of packets\" ";
	cmdCreate << "--lower-limit 0 ";
//	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:PSSM=" << filename << ":PS-SM:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:PSSM#FFFF00:\"SIP MES packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSSM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:PSSM#FFFF00:\"SIP MES packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSSM:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSSM:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSSM:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_PSR_command (char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL)
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"RTP Packets Counter\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"number of packets\" ";
	cmdCreate << "--lower-limit 0 ";
//	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:PSR=" << filename << ":PS-R:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:PSR#00FFFF:\"RTP packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:PSR#00FFFF:\"RTP packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSR:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSR:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSR:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_PSA_command (char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL)
		cmdCreate << "rrdtool graph - ";						//graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph " << dstfile << " ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"ALL Packets Counter\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"number of packets\" ";
	cmdCreate << "--lower-limit 0 ";
//	cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:PSA=" << filename << ":PS-A:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:PSA#999966:\"all packets/second\\t\\t\" ";
		cmdCreate << "GPRINT:PSA:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSA:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:MIN:\"Min\\: %5.0lf\\l\" ";
	} else {
		cmdCreate << "LINE1:PSA#999966:\"all packets/second\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:PSA:LAST:\"Cur\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:PSA:MAX:\"Max\\: %5.0lf\" ";
		cmdCreate << "GPRINT:PSA:MIN:\"Min\\: %5.0lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

void rrd_vm_create_graph_LA_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize) {
    std::ostringstream cmdCreate;

	if (dstfile == NULL)
		cmdCreate << "rrdtool graph - ";                                                //graph to stdout instead of file
	else
		cmdCreate << "rrdtool graph \"" << dstfile << "\" ";
	cmdCreate << "-w " << resx << " -h " << resy << " -a PNG ";
	cmdCreate << "--start \"" << fromatstyle << "\" --end \"" << toatstyle << "\" ";
	cmdCreate << "--font DEFAULT:0:Courier ";
	cmdCreate << "--title \"Load averages\" ";
	cmdCreate << "--watermark \"`date`\" ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--disable-rrdtool-tag "; }
	cmdCreate << "--vertical-label \"Load\" ";
	cmdCreate << "--lower-limit 0 ";
	//cmdCreate << "--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R ";
	cmdCreate << "--units-exponent 0 ";
	if (vm_rrd_version >= 10400) { cmdCreate << "--full-size-mode "; }
	if (slope) cmdCreate << "--slope-mode ";
	if (icon) cmdCreate << "--only-graph ";
	if (color != NULL) cmdCreate << "-c BACK#" << color << " -c SHADEA#" << color << " -c SHADEB#" << color << " ";
	cmdCreate << "DEF:t0=" << filename << ":LA-m1:MAX ";
	cmdCreate << "DEF:t1=" << filename << ":LA-m5:MAX ";
	cmdCreate << "DEF:t2=" << filename << ":LA-m15:MAX ";
	if (vm_rrd_version < 10403) {
		cmdCreate << "LINE1:t0#0000FF:\"1 minute avg\\t\" ";
		cmdCreate << "GPRINT:t0:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MIN:\"Min\\: %5.2lf\\l\" ";
		cmdCreate << "LINE1:t1#00FF00:\"5 minutes avg\\t\" ";
		cmdCreate << "GPRINT:t1:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MIN:\"Min\\: %5.2lf\\l\" ";
		cmdCreate << "LINE1:t2#FF0000:\"15 minutes avg\\t\" ";
		cmdCreate << "GPRINT:t2:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MIN:\"Min\\: %5.2lf\\l\" ";
	} else {
		cmdCreate << "LINE1:t0#0000FF:\"1 minute avg\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:t0:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t0:MIN:\"Min\\: %5.2lf\\r\" ";
		cmdCreate << "LINE1:t1#00FF00:\"5 minutes avg\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:t1:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t1:MIN:\"Min\\: %5.2lf\\r\" ";
		cmdCreate << "LINE1:t2#FF0000:\"15 minutes avg\\l\" ";
		cmdCreate << "COMMENT:\"\\u\" ";
		cmdCreate << "GPRINT:t2:LAST:\"Cur\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:AVERAGE:\"Avg\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MAX:\"Max\\: %5.2lf\" ";
		cmdCreate << "GPRINT:t2:MIN:\"Min\\: %5.2lf\\r\" ";
	}
	std::size_t length = cmdCreate.str().copy(buffer, maxsize, 0);
	buffer[length]='\0';
}

int vm_rrd_create_rrddrop(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:exceeded:GAUGE:20:0:1000000 ";
	cmdCreate << "DS:packets:GAUGE:20:0:1000000 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";

	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdheap(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:buffer:GAUGE:20:0:1000000 ";
	cmdCreate << "DS:ratio:GAUGE:20:0:10000000 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";
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
	cmdCreate << "DS:PS-SR:GAUGE:20:0:1000000 ";
	cmdCreate << "DS:PS-SM:GAUGE:20:0:1000000 ";
	cmdCreate << "DS:PS-R:GAUGE:20:0:10000000 ";
	cmdCreate << "DS:PS-A:GAUGE:20:0:10000000 ";
	cmdCreate << "RRA:MIN:0.5:1:740 ";
	cmdCreate << "RRA:MAX:0.5:1:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:740 ";
	cmdCreate << "RRA:MIN:0.5:24:740 ";
	cmdCreate << "RRA:MAX:0.5:24:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:740 ";
	cmdCreate << "RRA:MIN:0.5:168:740 ";
	cmdCreate << "RRA:MAX:0.5:168:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:740 ";
	cmdCreate << "RRA:MIN:0.5:8760:740 ";
	cmdCreate << "RRA:MAX:0.5:8760:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:740";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdSQL(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:SQLf-D:GAUGE:20:0:100000 ";
	cmdCreate << "DS:SQLf-C:GAUGE:20:0:100000 ";
	cmdCreate << "DS:SQLq-C:GAUGE:20:0:100000 ";
	cmdCreate << "DS:SQLq-M:GAUGE:20:0:100000 ";
	cmdCreate << "DS:SQLq-R:GAUGE:20:0:100000 ";
	cmdCreate << "DS:SQLq-Cl:GAUGE:20:0:100000 ";
	cmdCreate << "DS:SQLq-H:GAUGE:20:0:100000 ";
	cmdCreate << "RRA:MIN:0.5:1:740 ";
	cmdCreate << "RRA:MAX:0.5:1:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:740 ";
	cmdCreate << "RRA:MIN:0.5:24:740 ";
	cmdCreate << "RRA:MAX:0.5:24:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:740 ";
	cmdCreate << "RRA:MIN:0.5:168:740 ";
	cmdCreate << "RRA:MAX:0.5:168:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:740 ";
	cmdCreate << "RRA:MIN:0.5:8760:740 ";
	cmdCreate << "RRA:MAX:0.5:8760:740 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:740";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdtCPU(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:tCPU-t0:GAUGE:20:0:120 ";
	cmdCreate << "DS:tCPU-t1:GAUGE:20:0:120 ";
	cmdCreate << "DS:tCPU-t2:GAUGE:20:0:120 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdtacCPU(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:zipCPU:GAUGE:20:0:10000 ";
	cmdCreate << "DS:tarCPU:GAUGE:20:0:10000 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdmemusage(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:RSS:GAUGE:20:0:1000000 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdspeedmbs(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:mbs:GAUGE:20:0:100000 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdcallscounter(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:inv:GAUGE:20:0:200000 ";
	cmdCreate << "DS:reg:GAUGE:20:0:200000 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create_rrdloadaverages(const char *filename) {
	std::ostringstream cmdCreate;

	cmdCreate << "create " << filename << " ";
	cmdCreate << "--start N --step 10 ";
	cmdCreate << "DS:LA-m1:GAUGE:20:0:256 ";
	cmdCreate << "DS:LA-m5:GAUGE:20:0:256 ";
	cmdCreate << "DS:LA-m15:GAUGE:20:0:256 ";
	cmdCreate << "RRA:MIN:0.5:1:760 ";
	cmdCreate << "RRA:MAX:0.5:1:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:1:760 ";
	cmdCreate << "RRA:MIN:0.5:24:760 ";
	cmdCreate << "RRA:MAX:0.5:24:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:24:760 ";
	cmdCreate << "RRA:MIN:0.5:168:760 ";
	cmdCreate << "RRA:MAX:0.5:168:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:168:760 ";
	cmdCreate << "RRA:MIN:0.5:8760:760 ";
	cmdCreate << "RRA:MAX:0.5:8760:760 ";
	cmdCreate << "RRA:AVERAGE:0.5:8760:760";
	int res = vm_rrd_create(filename, cmdCreate.str().c_str());
	return (res);
}

int vm_rrd_create(const char *filename, const char *cmdline)
{
	int res;
	if(access(filename, 0) != -1) 
	{			
		if (sverb.rrd_info) syslog(LOG_NOTICE, "RRD file %s already exist. Creating Skipped.\n", filename);
		res = -1;
	} else {
		//syslog(LOG_NOTICE, "Creating RRD Database file: %s\n", filename);
		res = rrd_call(cmdline);
		if (sverb.rrd_info) syslog (LOG_NOTICE,"CREATED RRD file %s with result of: %d\n",filename, res);
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
		//res = rrd_call(cmdUpdate.str());
		if (sverb.rrd_info) syslog(LOG_NOTICE, "Updated RRD file: %s with command %s resulted in retval:%d\n", filename, cmdUpdate.str().c_str(),res);
	} else {		//rrd file is unaccessible
		if (verbosity > 0) syslog(LOG_NOTICE, "Cannot update non existent RRD file: %s\n", filename);
		res = -1;
	}
	return res;
}

/*
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
*/

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

	if (strcmp("create", argv[0]) == 0)
		rrd_create(argc, &argv[0]);
	else if (strcmp("dump", argv[0]) == 0)
		rrd_dump(argc, &argv[0]);
	else if (strcmp("restore", argv[0]) == 0)
		rrd_restore(argc, &argv[0]);
	else if (strcmp("resize", argv[0]) == 0)
		rrd_resize(argc, &argv[0]);
	else if (strcmp("last", argv[0]) == 0)
		printf("%ld\n", rrd_last(argc, &argv[0]));
	else if (strcmp("lastupdate", argv[0]) == 0) {
		rrd_lastupdate(argc, &argv[0]);
	} else if (strcmp("first", argv[0]) == 0)
		printf("%ld\n", rrd_first(argc, &argv[0]));
	else if (strcmp("update", argv[0]) == 0)
		rrd_update(argc, &argv[0]);
	else if (strcmp("fetch", argv[0]) == 0) {
		time_t	  start, end, ti;
		unsigned long step, ds_cnt, i, ii;
		rrd_value_t *data, *datai;
		char	**ds_namv;

		if (rrd_fetch
			(argc, &argv[0], &start, &end, &step, &ds_cnt, &ds_namv,
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
/*
	} else if (strcmp("xport", argv[0]) == 0) {
#ifdef HAVE_RRD_GRAPH
	  time_t	start, end;
	  unsigned long step, col_cnt;
	  rrd_value_t *data;
	  char	  **legend_v;
	  rrd_xport
	(argc, &argv[0], NULL, &start, &end, &step, &col_cnt,
	 &legend_v, &data);
#else
		rrd_set_error("the instance of rrdtool has been compiled without graphics");
#endif
	} else if (strcmp("graph", argv[0]) == 0) {
#ifdef HAVE_RRD_GRAPH
		char	**calcpr;

#ifdef notused
		const char *imgfile = argv[1];
#endif
		int		  xsize, ysize;
		double	  ymin, ymax;
		int		  i;
		int		  tostdout = (strcmp(argv[1], "-") == 0);
		int		  imginfo = 0;

		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--imginfo") == 0
				|| strcmp(argv[i], "-f") == 0) {
				imginfo = 1;
				break;
			}
		}
		if (rrd_graph
			(argc, &argv[0], &calcpr, &xsize, &ysize, NULL, &ymin,
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
	} else if (strcmp("graphv", argv[0]) == 0) {
#ifdef HAVE_RRD_GRAPH
		rrd_info_t *grinfo = NULL;

		grinfo = rrd_graph_v(argc, &argv[0]);
		if (grinfo) {
			rrd_info_print(grinfo);
			rrd_info_free(grinfo);
		}
#else
	   rrd_set_error("the instance of rrdtool has been compiled without graphics");
#endif
*/
	} else if (strcmp("tune", argv[0]) == 0)
		rrd_tune(argc, &argv[0]);
//	else if (strcmp("flushcached", argv[0]) == 0)
//		rrd_flushcached(argc, &argv[0]);
	else {
		rrd_set_error((char*)"unknown function '%s'", argv[0]);
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

	argc = 0;
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

	if ((tmpLine = new FILE_LINE(22001) char[strlen(aLine) + 1]) == NULL) {
		syslog(LOG_ERR, "rrd_call malloc error\n");
		return -1;
	}
	if ((myargv = new FILE_LINE(22002) char*[myargc + 1]) == NULL) {
		free(tmpLine);
		syslog(LOG_ERR, "rrd_call malloc error2\n");
		return -1;
	}

	memcpy(tmpLine, aLine, strlen(aLine));
	tmpLine[strlen(aLine)] = '\0';

	if ((myargc = vm_rrd_createArgs(tmpLine, myargv)) > 0) {
		int result = HandleInputLine(myargc, myargv, stderr);
		delete [] tmpLine;
		delete [] myargv;
		return (result);
	} else {
		delete [] tmpLine;
		delete [] myargv;
		return -1;
	}
}

void checkRrdVersion(bool silent) {
	extern int opt_rrd;
	if(vm_rrd_version || !opt_rrd) {
		return;
	}
	SimpleBuffer out;
	if(vm_pexec((char*)"rrdtool", &out) && out.size()) {
		string versionString = reg_replace((char*)out, "([0-9]+)\\.([0-9]+)\\.?([0-9]*)", "$1-$2-$3", __FILE__, __LINE__);
		if(!versionString.empty()) {
			int version[3] = { 0, 0, 0 };
			sscanf((char*)versionString.c_str(), "%i-%i-%i", &version[0], &version[1], &version[2]);
			vm_rrd_version = version[0] * 10000 + version[1] * 100 + version[2];
			if(!silent) {
				syslog(LOG_NOTICE, "detected rrdtool version %d", vm_rrd_version);
			}
		} else {
			vm_rrd_version = 1;
			if(!silent) {
				syslog(LOG_NOTICE, "unknown rrdtool version - rrd graph may be wrong");
			}
		}
	} else {
		vm_rrd_version = 0;
		if(!silent) {
			syslog(LOG_NOTICE, "for rrd graph you need install rrdtool");
		}
	}
}
