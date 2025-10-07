CC=gcc
EXEC=uhttps

CFLAGS  := $(IFLAGS) -O -D UNIX -Wall
LDFLAGS += -lssl -lcrypto -lpthread


all: $(EXEC)

$(EXEC): uhttps.c log.c cmd_line.c addrs2txt.c 
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm $(EXEC)
