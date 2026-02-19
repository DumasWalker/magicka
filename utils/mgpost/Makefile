CC=cc
CFLAGS=-I/usr/local/include
DEPS = mgpost.c
JAMLIB = ../../deps/jamlib/jamlib.a
OBJ = mgpost.o ../../src/inih/ini.o
LIBUUID = ../../deps/libuuid/.libs/libuuid.a

all: mgpost

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(JAMLIB):
	cd ../../deps/jamlib && make -f Makefile.linux

$(LIBUUID):
	rm ../../deps/libuuid/ltmain.sh ../../deps/libuuid/libtool || true
	cd ../../deps/libuuid/ && libtoolize
	cd ../../deps/libuuid/ && autoreconf
	cd ../../deps/libuuid && ./configure
	cd ../../deps/libuuid && $(MAKE)

mgpost: $(OBJ) $(JAMLIB) $(LIBUUID)
	$(CC) -o mgpost $^ $(CFLAGS) -L/usr/local/lib -lsqlite3
	
.PHONY: clean

clean:
	rm -f $(OBJ) mgpost
