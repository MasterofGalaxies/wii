CC = gcc
CFLAGS = -Wall -W -O2
LDFLAGS = -lcrypto

all: negentig

negentig: negentig.o
