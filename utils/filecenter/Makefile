OS := $(shell uname -s)

ifeq ($(OS), FreeBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3 -lncurses
endif
ifeq ($(OS), DragonFly)
  CC=cc
  CFLAGS=-I/usr/local/include -I/usr/local/include/ncurses
  LDFLAGS=-L/usr/local/lib -lsqlite3 -lncurses
endif
ifeq ($(OS), NetBSD)
  CC=cc
  CFLAGS=-I/usr/pkg/include
  LDFLAGS=-R/usr/pkg/lib -L/usr/pkg/lib -lsqlite3 -lncurses
endif
ifeq ($(OS), OpenBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3 -lncurses
endif
ifeq ($(OS), Linux)
  CC=gcc
  CFLAGS=
  ifdef FTSLIB
    LDFLAGS=-lsqlite3 -lncurses -lfts
  else
    LDFLAGS=-lsqlite3 -lncurses
  endif
endif
ifeq ($(OS), Darwin)
  CC=cc
  CFLAGS=
  LDFLAGS=-lsqlite3 -lncurses
endif
ifeq ($(OS), SunOS)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3 -lcurses
endif
ifeq ($(OS), Haiku)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3 -lncurses
endif
DEPS = main.c

OBJ = main.o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -I../../deps/cdk-5.0-20161210/include/

filecenter: $(OBJ)
	$(CC) -o $@ $^ ../../deps/cdk-5.0-20161210/libcdk.a ../../src/inih/ini.o $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJ) filecenter
