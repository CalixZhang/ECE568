
CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c sharedssl.c
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: client.o sharedssl.o
	$(CC) $(LDFLAGS) client.o sharedssl.o -o client

server: server.o
	$(CC) $(LDFLAGS) server.o sharedssl.o -o server


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

sharedssl.o: sharedssl.c
	$(CC) $(CFLAGS) -c -o sharedssl.o  sharedssl.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

