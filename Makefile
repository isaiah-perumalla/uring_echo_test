CC=gcc
CFLAGS=-Wall
LIBS=/usr/lib/liburing.a
ODIR=build

all: udp_echo tcp_echo

udp_echo: echo_udp_server.o
	$(CC) $(CFLAGS) -o $@  echo_udp_server.o $(LIBS)

tcp_echo: echo_server.o
	$(CC) $(CFLAGS) -o $@ echo_server.o  $(LIBS)

.PHONY: clean

clean:
	rm -f *.o udp_echo tcp_echo