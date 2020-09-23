sslkeylog.so: sslkeylog.o
	cc -shared -o sslkeylog.so sslkeylog.o

sslkeylog.o: sslkeylog.cpp
	cc -c -fPIC sslkeylog.cpp -o sslkeylog.o
