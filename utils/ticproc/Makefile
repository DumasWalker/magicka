OS := $(shell uname -s)

ifeq ($(OS), FreeBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3
endif
ifeq ($(OS), DragonFly)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3
endif
ifeq ($(OS), NetBSD)
  CC=cc
  CFLAGS=-I/usr/pkg/include
  LDFLAGS=-R/usr/pkg/lib -L/usr/pkg/lib -lsqlite3
endif
ifeq ($(OS), OpenBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3
endif
ifeq ($(OS), Linux)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3
endif
ifeq ($(OS), Darwin)
  CC=cc
  CFLAGS=
  LDFLAGS=-lsqlite3
endif
ifeq ($(OS), Haiku)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3
endif
ifeq ($(OS), SunOS)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3
endif

DEPS = ticproc.c

OBJ = ticproc.o ../../src/inih/ini.o crc32.o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


ticproc: $(OBJ)
	$(CC) -o ticproc $^ $(CFLAGS) $(LDFLAGS) 

.PHONY: clean

clean:
	rm -f $(OBJ) ticproc
