CC=cc
CFLAGS=-I/usr/local/include
DEPS = repairlinkage.c
JAMLIB = ../../deps/jamlib/jamlib.a
OBJ = repairlinkage.o 
OS := $(shell uname -s)

ifeq ($(OS), SunOS)
  CC=gcc-9
endif

all: repairlinkage

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(JAMLIB):
	cd ../../deps/jamlib && make -f Makefile.linux

repairlinkage: $(OBJ) $(JAMLIB)
	$(CC) -o repairlinkage $^ $(CFLAGS) -L/usr/local/lib
	
.PHONY: clean

clean:
	rm -f $(OBJ) repairlinkage
