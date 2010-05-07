objects = calltable.o rtp.o voipmonitor.o sniff.o jitterbuffer/astmm.o jitterbuffer/utils.o jitterbuffer/fixedjitterbuf.o jitterbuffer/jitterbuf.o jitterbuffer/abstract_jb.o jitterbuffer/frame.o 
args = -g3 -Wall
#args = -O2 -Wall
CFLAGS+=-I /usr/local/include/mysql++/ -I /usr/include/mysql/ -g3 -Wall -I jitterbuffer/ 
LIBS=-lpthread -lmysqlpp -lpcap

voipmonitor : $(objects) 
	g++ $(objects) ${CFLAGS} -o $@ ${LIBS}

calltable.o : calltable.cpp calltable.h
	g++ -c calltable.cpp $(args) ${CFLAGS}

rtp.o : rtp.cpp rtp.h
	g++ -c rtp.cpp $(args) ${CFLAGS}

voipmonitor.o : voipmonitor.cpp voipmonitor.h
	g++ -c voipmonitor.cpp $(args) ${CFLAGS}

sniff.o : sniff.cpp sniff.h
	g++ -c sniff.cpp $(args) ${CFLAGS}

clean :
	rm -f $(objects) voipmonitor

install: 
	install voipmonitor /usr/local/sbin/

