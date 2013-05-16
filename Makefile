HADOOP_HOME=/opt/hadoop/hadoop
PLATFORM=Linux-i386-32
JAVA_HOME=/usr/lib/jvm/java-7-sun
CPPFLAGS= -I$(HADOOP_HOME)/src/c++/libhdfs
LIB = -L$(HADOOP_HOME)/c++/Linux-i386-32/lib  -L/opt/libpcap/lib 
INC=-I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I/opt/libpcap/include
libjvm=/usr/lib/jvm/java-7-sun/jre/lib/i386/client/libjvm.so
LDFLAGS += -lhdfs

CC = gcc

CCFLAGS = -W
#LDFLAGS =

LIBS = -lpcap
#INC = -I/opt/libpcap/include
#LIB = -L/opt/libpcap/lib

all: mypcap

%.o: %.c %.h
	$(CC)	$(CCFLAGS) $(CPPFLAGS) -c -o $@  -g $(INC) $<

mypcap:mypcap.o
	${CC} -g -o $@ $(LIB) $(libjvm) $(LDFLAGS) $< ${LIBS}  

clean:
	rm -f mypcap *.o
	
