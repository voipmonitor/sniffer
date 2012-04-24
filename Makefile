objects = codec_alaw.o codec_ulaw.o format_slinear.o format_wav.o format_ogg.o calltable.o rtp.o voipmonitor.o sniff.o jitterbuffer/astmm.o jitterbuffer/utils.o jitterbuffer/fixedjitterbuf.o jitterbuffer/jitterbuf.o jitterbuffer/abstract_jb.o jitterbuffer/frame.o gzstream/gzstream.o gzstream/libgzstream.a manager.o tools.o filter_mysql.o hash.o mos_g729.o odbc.o
args = -g3 -Wall
#args = -O2 -Wall
CFLAGS+=-I /usr/local/include/mysql++/ -I /usr/include/mysql++/ -I /usr/include/mysql/ -g3 -Wall -I jitterbuffer/  -L/usr/local/lib/ -Lgzstream/ -Lliblfds.6/bin/
LIBS=-lpthread -lmysqlpp -lpcap -lgzstream -lz -lvorbis -lvorbisenc -logg -lodbc -llfds #-lnids
#if you want to compile it statically uncomment this line
#LIBS=-static -lpthread -L/usr/lib/mysql -lmysqlpp -lmysqlclient -lpcap -lgzstream -lz -lvorbis -lvorbisenc -logg


voipmonitor : $(objects) 
	make -C liblfds.6
	g++ $(objects) ${CFLAGS} -o $@ ${LIBS}

gzstream/gzstream.o : gzstream/gzstream.C gzstream/gzstream.h
	g++ -I. -Igzstream/ -c -o gzstream/gzstream.o gzstream/gzstream.C

gzstream/libgzstream.a : gzstream/gzstream.o
	ar cr gzstream/libgzstream.a gzstream/gzstream.o

codec_alaw.o : codec_alaw.cpp codec_alaw.h
	g++ -c codec_alaw.cpp $(args) ${CFLAGS}

codec_ulaw.o : codec_ulaw.cpp codec_ulaw.h
	g++ -c codec_ulaw.cpp $(args) ${CFLAGS}

format_slinear.o : format_slinear.cpp format_slinear.h
	g++ -c format_slinear.cpp $(args) ${CFLAGS}

format_wav.o : format_wav.cpp format_wav.h
	g++ -c format_wav.cpp $(args) ${CFLAGS}

format_ogg.o : format_ogg.cpp format_ogg.h
	g++ -c format_ogg.cpp $(args) ${CFLAGS}

calltable.o : calltable.cpp calltable.h
	g++ -c calltable.cpp $(args) ${CFLAGS}

rtp.o : rtp.cpp rtp.h
	g++ -c rtp.cpp $(args) ${CFLAGS}

voipmonitor.o : voipmonitor.cpp voipmonitor.h
	g++ -c voipmonitor.cpp $(args) ${CFLAGS}

sniff.o : sniff.cpp sniff.h
	g++ -c sniff.cpp $(args) ${CFLAGS}

manager.o : manager.cpp manager.h
	g++ -c manager.cpp $(args) ${CFLAGS}

tools.o : tools.cpp tools.h
	g++ -c tools.cpp $(args) ${CFLAGS}

filter_mysql.o : filter_mysql.cpp filter_mysql.h
	g++ -c filter_mysql.cpp $(args) ${CFLAGS}

hash.o : hash.cpp hash.h
	g++ -c hash.cpp $(args) ${CFLAGS}

mos_g729.o : mos_g729.cpp mos_g729.h
	g++ -c mos_g729.cpp $(args) ${CFLAGS}

odbc.o : odbc.cpp odbc.h
	g++ -c odbc.cpp $(args) ${CFLAGS}
	
clean :
	make -C liblfds.6 clean
	rm -f $(objects) voipmonitor gzstream/*.o libgzstream.a

install: 
	install voipmonitor /usr/local/sbin/

