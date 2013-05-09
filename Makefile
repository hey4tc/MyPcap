CC = gcc

LIBS = -lpcap

CCFLAGS = -W
LDFLAGS =

INC = -I/opt/libpcap/include
LIB = -L/opt/libpcap/lib

all: mypcap

%.o: %.c %.h
	$(CC)	$(CCFLAGS) -c -o $@  -g $(INC) $<

mypcap:mypcap.o
	${CC} -g -o $@ $(LIB) $(LDFLAGS) $< ${LIBS}


clean:
	rm -f mypcap *.o
