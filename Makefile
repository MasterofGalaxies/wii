CC = gcc
CFLAGS = -DLARGE_FILES -D_FILE_OFFSET_BITS=64 -Wall -W -O2
LDFLAGS = -lcrypto

all: negentig

negentig: negentig.o tools.o

*.o:	*.c *.h

clean:
	-rm -f negentig negentig.o tools.o
