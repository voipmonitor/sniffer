default: without_tcp

CC=gcc
RM=rm -f
DSTLIB=sslkeylog.so

without_tcp: CPPFLAGS=-g3
without_tcp: LDLIBS=-lstdc++
without_tcp: OBJS=sslkeylog.o
without_tcp: sslkeylog.o Makefile
	$(CC) $(LDLIBS) -shared -o $(DSTLIB) $(OBJS)

with_tcp: CPPFLAGS=-g3 $(shell pkg-config --cflags json-c) -idirafter ../../cloud_router -idirafter ../.. -DTOOLS_LOCAL_H -DCLOUD_ROUTER_H -DCLOUD_ROUTER_SSLKEYLOGGER=1 -DVM_IPV6=1 -DSSLKEYLOG_TCP
with_tcp: LDLIBS=-lstdc++ $(shell pkg-config --libs json-c)
with_tcp: OBJS=sslkeylog.o cloud_router_base.o cloud_router_client.o ip.o tools_global.o
with_tcp: sslkeylog.o cloud_router_base.o cloud_router_client.o ip.o tools_global.o Makefile
	$(CC) $(LDLIBS) -shared -o $(DSTLIB) $(OBJS)

sslkeylog.o: sslkeylog.cpp Makefile
	$(CC) -c -fPIC $(CPPFLAGS) sslkeylog.cpp -o sslkeylog.o

cloud_router_base.o: ../../cloud_router/cloud_router_base.cpp Makefile
	$(CC) -c -fPIC $(CPPFLAGS) ../../cloud_router/cloud_router_base.cpp -o cloud_router_base.o

cloud_router_client.o: ../../cloud_router/cloud_router_client.cpp Makefile
	$(CC) -c -fPIC $(CPPFLAGS) ../../cloud_router/cloud_router_client.cpp -o cloud_router_client.o

ip.o: ../../ip.cpp Makefile
	$(CC) -c -fPIC $(CPPFLAGS) ../../ip.cpp -o ip.o

tools_global.o: ../../tools_global.cpp Makefile
	$(CC) -c -fPIC $(CPPFLAGS) ../../tools_global.cpp -o tools_global.o

clean:
	$(RM) *.o *.so
