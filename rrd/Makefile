CC=gcc
SOLIBS=-lrrd
OPT=-fPIC -DPIC -std=gnu99
HEADERS=-I ./rrd_tool-1.x/src/
RRDLIBDIR=-L ./rrd_tool-1.x/src/

ODKUD=`pwd`

example: rrd_call_main.c rrd_call.o
	${CC} ${OPT} rrd_call_main.c rrd_call.o ${RRDLIBDIR} ${HEADERS} ${SOLIBS} -o $@

rrd_call.o:
	mv rrd_tool-1.x/configure.ac rrd_tool-1.x/configure.ac.backup
	echo "AC_CONFIG_AUX_DIR([./])" > rrd_tool-1.x/configure.ac
	cat rrd_tool-1.x/configure.ac.backup >> rrd_tool-1.x/configure.ac
	cd rrd_tool-1.x; ./MakeMakefile		
	mv rrd_tool-1.x/configure rrd_tool-1.x/configure-backup
	head -n1 rrd_tool-1.x/configure-backup > rrd_tool-1.x/configure
	echo "ac_aux_dir=./" >> rrd_tool-1.x/configure
	tail -n+2 rrd_tool-1.x/configure-backup >> rrd_tool-1.x/configure
	chmod +x rrd_tool-1.x/configure
	cd rrd_tool-1.x; ./configure --disable-rrd_graph
	make -C rrd_tool-1.x
	${CC} -c ./rrd_call.c ${RRDLIBDIR} ${HEADERS} ${SOLIBS}

clean:
	rm example
