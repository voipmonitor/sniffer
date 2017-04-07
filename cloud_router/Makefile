CC=gcc
RM=rm -f

INCLUDES=-I/usr/include

CPPFLAGS=-Wall -g3 ${INCLUDES}
LDFLAGS=-g3 -O0 -fsanitize=address
LDLIBS=-lasan -lstdc++ -lpthread -ljson-c -L/usr/lib64/mysql -lmysqlclient

SRCS=cloud_router.cpp manager.cpp tools.cpp
OBJS=$(subst .cpp,.o,$(SRCS))
EXECUTABLE=cloud_router

OTHER_DEPENDS=tools.h Makefile

$(EXECUTABLE): $(OBJS) $(OTHER_DEPENDS)
	$(CC) $(LDFLAGS) -o $(EXECUTABLE) $(OBJS) $(LDLIBS) 

cloud_router.o: cloud_router.cpp cloud_router.h $(OTHER_DEPENDS)
	$(CC) $(CPPFLAGS) -c cloud_router.cpp

manager.o: manager.cpp $(OTHER_DEPENDS)
	$(CC) $(CPPFLAGS) -c manager.cpp
	
tools.o: tools.cpp tools.h $(OTHER_DEPENDS)
	$(CC) $(CPPFLAGS) -c tools.cpp
	
clean:
	$(RM) $(OBJS)
