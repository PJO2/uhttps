CC=gcc
CFLAGS= -O -D UNIX -Wall
LDFLAGS= -lssl -lcrypto -lpthread
EXEC=uhttps


all: $(EXEC)

$(EXEC): uhttps.c log.c cmd_line.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm $(EXEC)
