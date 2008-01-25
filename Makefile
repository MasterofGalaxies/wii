PROGS = tachtig negentig tpl dol2elf
COMMON = tools.o bn.o ec.o
DEFINES = -DLARGE_FILES -D_FILE_OFFSET_BITS=64
LIBS = -lcrypto

CC = gcc
CFLAGS = -Wall -W -Os
LDFLAGS =


OBJS = $(patsubst %,%.o,$(PROGS)) $(COMMON)

all: $(PROGS)

$(PROGS): %: %.o $(COMMON) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $< $(COMMON) -o $@

$(OBJS): %.o: %.c tools.h Makefile
	$(CC) $(CFLAGS) $(DEFINES) -c $< -o $@

clean:
	-rm -f $(OBJS) $(PROGS)
