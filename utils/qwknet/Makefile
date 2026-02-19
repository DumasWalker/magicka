CC=cc
CFLAGS=-I/usr/local/include
DEPS = qwktoss.c qwkscan.c
JAMLIB = ../../deps/jamlib/jamlib.a
OBJ = qwktoss.o ../../src/inih/ini.o
SOBJ = qwkscan.o ../../src/inih/ini.o

all: qwktoss qwkscan

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(JAMLIB):
	cd ../../deps/jamlib && make -f $(JAMMAKE)

qwktoss: $(OBJ) $(JAMLIB)
	$(CC) -o qwktoss $^ $(CFLAGS) -L/usr/local/lib -lsqlite3

qwkscan: $(SOBJ) $(JAMLIB)
	$(CC) -o qwkscan $^ $(CFLAGS) -L/usr/local/lib -lsqlite3

.PHONY: clean

clean:
	rm -f $(OBJ) $(SOBJ) qwktoss qwkscan
