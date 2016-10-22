# Makefile for rlcompleter

V=2.0

CFLAGS=-O2 -Wall -I/usr/include/ -fPIC

DYN=rlcompleter_c.so

OBJS=rlcompleter.o

$(DYN): $(OBJS)
	$(CC) -shared -o $(DYN) $(OBJS) -ledit

clean:
	rm -f $(DYN) $(OBJS)
