OS := $(shell uname -s)

ifeq ($(OS), FreeBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib 
endif
ifeq ($(OS), DragonFly)
  CC=cc
  CFLAGS=-I/usr/local/include -I/usr/local/include/ncurses
  LDFLAGS=-L/usr/local/lib 
endif
ifeq ($(OS), NetBSD)
  CC=cc
  CFLAGS=-I/usr/pkg/include
  LDFLAGS=-R/usr/pkg/lib -L/usr/pkg/lib 
endif
ifeq ($(OS), OpenBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib 
endif
ifeq ($(OS), Linux)
  CC=gcc
  CFLAGS=
  LDFLAGS=
endif
ifeq ($(OS), Darwin)
  CC=cc
  CFLAGS=
  LDFLAGS=
endif
ifeq ($(OS), SunOS)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsocket
endif
ifeq ($(OS), Haiku)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lnetwork
endif

DEPS = main.c

OBJ = main.o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) 

shim: $(OBJ)
	$(CC) -o $@ $^  $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f $(OBJ) shim
