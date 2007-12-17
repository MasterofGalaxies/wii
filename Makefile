CC = gcc
CFLAGS = -Wall -W -O2
LDFLAGS = -lcrypto

all: negentig

negentig: negentig.o

clean:
	-rm -f negentig negentig.o
