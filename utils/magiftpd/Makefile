OS := $(shell uname -s)

ifeq ($(OS), FreeBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3 -lcrypto
endif
ifeq ($(OS), DragonFly)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3 -lcrypto
endif
ifeq ($(OS), NetBSD)
  CC=cc
  CFLAGS=-I/usr/pkg/include
  LDFLAGS=-R/usr/pkg/lib -L/usr/pkg/lib -lsqlite3 -lcrypto
endif
ifeq ($(OS), OpenBSD)
  CC=cc
  CFLAGS=-I/usr/local/include
  LDFLAGS=-L/usr/local/lib -lsqlite3 -lcrypto
endif
ifeq ($(OS), Linux)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3 -lcrypto
endif
ifeq ($(OS), Darwin)
  CC=cc
  CFLAGS=-I/opt/local/include
  LDFLAGS=-L/opt/local/lib -lsqlite3 -lcrypto
endif
ifeq ($(OS), SunOS)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3 -lcrypto -lsocket -lnsl
endif
ifeq ($(OS), Haiku)
  CC=gcc
  CFLAGS=
  LDFLAGS=-lsqlite3 -lcrypto -lnetwork
endif


DEPS = magiftpd.c

OBJ = magiftpd.o ../../src/inih/ini.o
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


magiftpd: $(OBJ)
	$(CC) -o magiftpd $^ $(CFLAGS) $(LDFLAGS) 

.PHONY: clean

clean:
	rm -f $(OBJ) magiftpd
