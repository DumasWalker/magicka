OS := $(shell uname -s)

ifeq ($(OS), FreeBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib
endif
ifeq ($(OS), DragonFly)
  CC=cc
  CFLAGS=-I/usr/local/include
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
  LDFLAGS=-L/usr/local/lib -lsqlite3 
endif
ifeq ($(OS), Linux)
  CC=gcc
  CFLAGS=
  LDFLAGS=
endif
ifeq ($(OS), Darwin)
  CC=cc
  CFLAGS=-I/opt/local/include
  LDFLAGS=-L/opt/local/lib 
endif
ifeq ($(OS), SunOS)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsocket -lnsl
endif

DEPS = mnetftpd.c

OBJ = mnetftpd.o ../../src/inih/ini.o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


mnetftpd: $(OBJ)
	$(CC) -o mnetftpd $^ $(CFLAGS) $(LDFLAGS) 

.PHONY: clean

clean:
	rm -f $(OBJ) mnetftpd
