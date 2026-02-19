CC=cc
CFLAGS=-I/usr/local/include -I../../deps/ 
DEPS = mnettoftn.c
JAMLIB = ../../deps/jamlib/jamlib.a
OBJ = mnettoftn.o
OBJ2 = ftntomnet.o
UUID = ../../deps/libuuid/.libs/libuuid.a

all: mnettoftn ftntomnet

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(UUID):
	cd ../deps/libuuid/ && ./configure
	cd ../deps/libuuid/ && $(MAKE)

$(JAMLIB):
	cd ../../deps/jamlib && make -f Makefile.linux

ftntomnet: $(OBJ2) $(JAMLIB) $(UUID)
	$(CC) -o ftntomnet $^ $(CFLAGS) -L/usr/local/lib 

mnettoftn: $(OBJ) $(JAMLIB)
	$(CC) -o mnettoftn $^ $(CFLAGS) -L/usr/local/lib 
	
.PHONY: clean

clean:
	rm -f $(OBJ) mnettoftn $(OBJ2) ftntomnet
