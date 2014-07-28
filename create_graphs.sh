#!/bin/bash
#
## change directory to the rrdtool script dir
cd /var/www/grafy

## Graphs for last 12 hours 
## calls
/bin/rrdtool graph calls_graph.png \
-w 785 -h 120 -a PNG \
--start -43200 --end now \
--font DEFAULT:7: \
--title "Number of calls" \
--watermark "`date`" \
--vertical-label "calls" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--units-exponent 0 \
DEF:calls=/var/spool/voipmonitor/rrd/db-callscounter.rrd:calls:MAX \
AREA:calls#00FF00:calls \
LINE1:calls#00FF00:"Calls" \
GPRINT:calls:LAST:"Cur\: %5.0lf" \
GPRINT:calls:AVERAGE:"Avg\: %5.2lf" \
GPRINT:calls:MAX:"Max\: %5.0lf" \
GPRINT:calls:MIN:"Min\: %5.0lf\t\t\t"

##DROPS
/bin/rrdtool graph drop_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -43200 --end now \
--font DEFAULT:7: \
--title "Dropping packets" \
--watermark "`date`" \
--vertical-label "packets" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--units-exponent 0 \
DEF:exc=/var/spool/voipmonitor/rrd/db-drop.rrd:exceeded:MAX \
DEF:pck=/var/spool/voipmonitor/rrd/db-drop.rrd:packets:MAX \
LINE1:exc#0000FF:"Mem Usage RSS\t" \
GPRINT:exc:LAST:"Cur\: %5.0lf\t" \
GPRINT:exc:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:exc:MAX:"Max\: %5.0lf\t" \
GPRINT:exc:MIN:"Min\: %5.0lf\n" \
LINE1:pck#00FF00:"Mem Usage VSZ\t" \
GPRINT:pck:LAST:"Cur\: %5.0lf\t" \
GPRINT:pck:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:pck:MAX:"Max\: %5.0lf\t" \
GPRINT:pck:MIN:"Min\: %5.0lf\n"

##HEAP
/bin/rrdtool graph heap_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -43200 --end now \
--font DEFAULT:7: \
--title "mem heap usage" \
--watermark "`date`" \
--vertical-label "percent[%]" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--units-exponent 0 \
DEF:buffer=/var/spool/voipmonitor/rrd/db-heap.rrd:buffer:MAX \
DEF:trash=/var/spool/voipmonitor/rrd/db-heap.rrd:trash:MAX \
DEF:ratio=/var/spool/voipmonitor/rrd/db-heap.rrd:ratio:MAX \
LINE1:buffer#0000FF:"Buffer usage %\t" \
GPRINT:buffer:LAST:"Cur\: %5.2lf\t" \
GPRINT:buffer:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:buffer:MAX:"Max\: %5.2lf\t" \
GPRINT:buffer:MIN:"Min\: %5.2lf\n" \
LINE1:trash#00FF00:"Trash usage %\t" \
GPRINT:trash:LAST:"Cur\: %5.2lf\t" \
GPRINT:trash:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:trash:MAX:"Max\: %5.2lf\t" \
GPRINT:trash:MIN:"Min\: %5.2lf\n" \
LINE1:ratio#FF0000:"Ratio %\t" \
GPRINT:ratio:LAST:"Cur\: %5.2lf\t" \
GPRINT:ratio:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:ratio:MAX:"Max\: %5.2lf\t" \
GPRINT:ratio:MIN:"Min\: %5.2lf\n"
 
## PS 
/bin/rrdtool graph PS_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -43200 --end now \
--font DEFAULT:7: \
--title "PS" \
--watermark "`date`" \
--vertical-label "queries" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--units-exponent 0 \
DEF:PSC=/var/spool/voipmonitor/rrd/db-PS.rrd:PS-C:MAX \
DEF:PSS0=/var/spool/voipmonitor/rrd/db-PS.rrd:PS-S0:MAX \
DEF:PSS1=/var/spool/voipmonitor/rrd/db-PS.rrd:PS-S1:MAX \
DEF:PSR=/var/spool/voipmonitor/rrd/db-PS.rrd:PS-R:MAX \
DEF:PSA=/var/spool/voipmonitor/rrd/db-PS.rrd:PS-A:MAX \
LINE1:PSC#0000FF:"-C\t" \
GPRINT:PSC:LAST:"Cur\: %5.0lf\t" \
GPRINT:PSC:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:PSC:MAX:"Max\: %5.0lf\t" \
GPRINT:PSC:MIN:"Min\: %5.0lf\n" \
LINE1:PSS0#00FF00:"-S0\t" \
GPRINT:PSS0:LAST:"Cur\: %5.0lf\t" \
GPRINT:PSS0:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:PSS0:MAX:"Max\: %5.0lf\t" \
GPRINT:PSS0:MIN:"Min\: %5.0lf\n" \
LINE1:PSS1#FF0000:"-S1\t" \
GPRINT:PSS1:LAST:"Cur\: %5.0lf\t" \
GPRINT:PSS1:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:PSS1:MAX:"Max\: %5.0lf\t" \
GPRINT:PSS1:MIN:"Min\: %5.0lf\n" \
LINE1:PSR#00FFFF:"-R\t" \
GPRINT:PSR:LAST:"Cur\: %5.0lf\t" \
GPRINT:PSR:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:PSR:MAX:"Max\: %5.0lf\t" \
GPRINT:PSR:MIN:"Min\: %5.0lf\n" \
LINE1:PSA#FFFF00:"-H\t" \
GPRINT:PSA:LAST:"Cur\: %5.0lf\t" \
GPRINT:PSA:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:PSA:MAX:"Max\: %5.0lf\t" \
GPRINT:PSA:MIN:"Min\: %5.0lf\n"
 
## RSSVSZ 
/bin/rrdtool graph RSSVSZ_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -43200 --end now \
--font DEFAULT:7: \
--title "RSS VSZ" \
--watermark "`date`" \
--vertical-label "MB" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--units-exponent 0 \
DEF:rss=/var/spool/voipmonitor/rrd/db-RSSVSZ.rrd:RSS:MAX \
DEF:vsz=/var/spool/voipmonitor/rrd/db-RSSVSZ.rrd:VSZ:MAX \
LINE1:rss#0000FF:"Mem Usage RSS\t" \
GPRINT:rss:LAST:"Cur\: %5.0lf\t" \
GPRINT:rss:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:rss:MAX:"Max\: %5.0lf\t" \
GPRINT:rss:MIN:"Min\: %5.0lf\n" \
LINE1:vsz#00FF00:"Mem Usage VSZ\t" \
GPRINT:vsz:LAST:"Cur\: %5.0lf\t" \
GPRINT:vsz:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:vsz:MAX:"Max\: %5.0lf\t" \
GPRINT:vsz:MIN:"Min\: %5.0lf\n"
 
## speed mbs
/bin/rrdtool graph speed_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -86400 --end now \
--font DEFAULT:7: \
--title "bw speed" \
--watermark "`date`" \
--vertical-label "Mb/s" \
--lower-limit 0 \
--units-exponent 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
DEF:speed=/var/spool/voipmonitor/rrd/db-speedmbs.rrd:mbs:MAX \
AREA:speed#0000FF:speed \
LINE1:speed#0000FF:"speed(Mb/s)" \
GPRINT:speed:LAST:"Cur\: %5.2lf" \
GPRINT:speed:AVERAGE:"Avg\: %5.2lf" \
GPRINT:speed:MAX:"Max\: %5.2lf" \
GPRINT:speed:MIN:"Min\: %5.2lf\t\t\t"
 
## SQLq 
/bin/rrdtool graph SQLq_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -43200 --end now \
--font DEFAULT:7: \
--title "SQLq" \
--watermark "`date`" \
--vertical-label "queries" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--units-exponent 0 \
DEF:SQLqC=/var/spool/voipmonitor/rrd/db-SQLq.rrd:SQLq-C:MAX \
DEF:SQLqM=/var/spool/voipmonitor/rrd/db-SQLq.rrd:SQLq-M:MAX \
DEF:SQLqR=/var/spool/voipmonitor/rrd/db-SQLq.rrd:SQLq-R:MAX \
DEF:SQLqCl=/var/spool/voipmonitor/rrd/db-SQLq.rrd:SQLq-Cl:MAX \
DEF:SQLqH=/var/spool/voipmonitor/rrd/db-SQLq.rrd:SQLq-H:MAX \
LINE1:SQLqC#0000FF:"-C\t" \
GPRINT:SQLqC:LAST:"Cur\: %5.0lf\t" \
GPRINT:SQLqC:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:SQLqC:MAX:"Max\: %5.0lf\t" \
GPRINT:SQLqC:MIN:"Min\: %5.0lf\n" \
LINE1:SQLqM#00FF00:"-M\t" \
GPRINT:SQLqM:LAST:"Cur\: %5.0lf\t" \
GPRINT:SQLqM:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:SQLqM:MAX:"Max\: %5.0lf\t" \
GPRINT:SQLqM:MIN:"Min\: %5.0lf\n" \
LINE1:SQLqR#FF0000:"-R\t" \
GPRINT:SQLqR:LAST:"Cur\: %5.0lf\t" \
GPRINT:SQLqR:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:SQLqR:MAX:"Max\: %5.0lf\t" \
GPRINT:SQLqR:MIN:"Min\: %5.0lf\n" \
LINE1:SQLqCl#00FFFF:"-Cl\t" \
GPRINT:SQLqCl:LAST:"Cur\: %5.0lf\t" \
GPRINT:SQLqCl:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:SQLqCl:MAX:"Max\: %5.0lf\t" \
GPRINT:SQLqCl:MIN:"Min\: %5.0lf\n" \
LINE1:SQLqH#FFFF00:"-H\t" \
GPRINT:SQLqH:LAST:"Cur\: %5.0lf\t" \
GPRINT:SQLqH:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:SQLqH:MAX:"Max\: %5.0lf\t" \
GPRINT:SQLqH:MIN:"Min\: %5.0lf\n"
 
## tacCPU
/bin/rrdtool graph tacCPU_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -43200 --end now \
--font DEFAULT:7: \
--title "tac CPU" \
--watermark "`date`" \
--vertical-label "threads" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--y-grid 1:2 \
DEF:tac=/var/spool/voipmonitor/rrd/db-tacCPU.rrd:tacCPU:MAX \
LINE1:tac#0000FF:"Usage" \
GPRINT:tac:LAST:"Cur\: %5.2lf" \
GPRINT:tac:AVERAGE:"Avg\: %5.2lf" \
GPRINT:tac:MAX:"Max\: %5.2lf" \
GPRINT:tac:MIN:"Min\: %5.2lf\t\t\t"
 
## tCPU
/bin/rrdtool graph tCPU_graph.png \
-w 785 -h 120 -a PNG \
--slope-mode \
--start -43200 --end now \
--font DEFAULT:7: \
--title "tCPU usage" \
--watermark "`date`" \
--vertical-label "percent[%]" \
--lower-limit 0 \
--x-grid MINUTE:10:HOUR:1:MINUTE:120:0:%R \
--units-exponent 0 \
DEF:t0=/var/spool/voipmonitor/rrd/db-tCPU.rrd:tCPU-t0:MAX \
DEF:t1=/var/spool/voipmonitor/rrd/db-tCPU.rrd:tCPU-t1:MAX \
DEF:t2=/var/spool/voipmonitor/rrd/db-tCPU.rrd:tCPU-t2:MAX \
LINE1:t0#0000FF:"t0 CPU Usage %\t" \
GPRINT:t0:LAST:"Cur\: %5.2lf\t" \
GPRINT:t0:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:t0:MAX:"Max\: %5.2lf\t" \
GPRINT:t0:MIN:"Min\: %5.2lf\n" \
LINE1:t1#00FF00:"t1 CPU Usage %\t" \
GPRINT:t1:LAST:"Cur\: %5.2lf\t" \
GPRINT:t1:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:t1:MAX:"Max\: %5.2lf\t" \
GPRINT:t1:MIN:"Min\: %5.2lf\n" \
LINE1:t2#FF0000:"t2 CPU Usage %\t" \
GPRINT:t2:LAST:"Cur\: %5.2lf\t" \
GPRINT:t2:AVERAGE:"Avg\: %5.2lf\t" \
GPRINT:t2:MAX:"Max\: %5.2lf\t" \
GPRINT:t2:MIN:"Min\: %5.2lf\n"
