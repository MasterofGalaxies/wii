CC = gcc
CFLAGS = -DLARGE_FILES -D_FILE_OFFSET_BITS=64 -Wall -W -O2
LDFLAGS = -lcrypto

LIB = tools.o bn.o ec.o

all: tachtig negentig tpl

tachtig: tachtig.o $(LIB)

negentig: negentig.o $(LIB)

tpl: tpl.o

*.o:	*.c *.h Makefile

clean:
	-rm -f tachtig negentig tpl
	-rm -f tachtig.o negentig.o tpl.o
	-rm -f $(LIB)
