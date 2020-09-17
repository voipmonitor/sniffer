sslkeylog.so: sslkeylog.o
	cc -shared -o sslkeylog.so sslkeylog.o

sslkeylog.o: sslkeylog.c
	cc -c -fPIC sslkeylog.c -o sslkeylog.o
