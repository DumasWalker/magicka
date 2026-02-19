CC=cc
CFLAGS=-I/usr/local/include
DEPS = bbslistentryscan.c bbslistentrygen.c
JAMLIB = ../../deps/jamlib/jamlib.a
OBJ = bbslistentryscan.o ../../src/inih/ini.o
SOBJ = bbslistentrygen.o ../../src/inih/ini.o
OS := $(shell uname -s)

ifeq ($(OS), SunOS)
  CC=gcc-9
endif

all: bbslistentryscan bbslistentrygen

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(JAMLIB):
	cd ../../deps/jamlib && make -f $(JAMMAKE)

bbslistentryscan: $(OBJ) $(JAMLIB)
	$(CC) -o bbslistentryscan $^ $(CFLAGS) -L/usr/local/lib -lsqlite3

bbslistentrygen: $(SOBJ) $(JAMLIB)
	$(CC) -o bbslistentrygen $^ $(CFLAGS) -L/usr/local/lib -lsqlite3

.PHONY: clean

clean:
	rm -f $(OBJ) $(SOBJ) bbslistentryscan bbslistentrygen
