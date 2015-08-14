CC=gcc
RM=rm -f

CPPFLAGS=-g3
LDFLAGS=-g3
LDLIBS=-lstdc++

SRCS=test.cpp
OBJS=$(subst .cpp,.o,$(SRCS))
EXECUTABLE=test

OTHER_DEPENDS=Makefile

$(EXECUTABLE): $(OBJS) $(OTHER_DEPENDS)
	$(CC) $(LDFLAGS) -o $(EXECUTABLE) $(OBJS) $(LDLIBS) 

test.o: test.cpp  $(OTHER_DEPENDS)
	$(CC) $(CPPFLAGS) -c test.cpp

clean:
	$(RM) $(OBJS)
