CC=gcc
CFLAGS= -O -D UNIX -Wall -I /Users/ark/Develop/C/openssl-openssl-3.6.0/include
LDFLAGS= -lssl -lcrypto -lpthread
CFLAGS := $(CFLAGS) -I ../openssl-openssl-3.6.0/include
EXEC=uhttps


all: $(EXEC)

$(EXEC): uhttps.c log.c cmd_line.c addrs2txt.c 
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm $(EXEC)
