CC=cc
CFLAGS=-I../../deps/odoors/ -DANSI_PATH="\"$(ANSI_PATH)\"" -DDRAFT_PATH="\"$(DRAFT_PATH)\""
DEPS = main.c
OS = $(shell uname -s)
ODOORS = ../../deps/odoors/libs-${OS}/libODoors.a


ifeq ($(OS), SunOS)
	EXTRA_LIBS = -lsocket
endif

ifeq ($(OS), Haiku)
	EXTRA_LIBS = -lnetwork
endif

OBJ = main.o

all: magiedit

${ODOORS}:
	cd ../../deps/odoors && $(MAKE) MAKEFLAGS=

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

magiedit: $(OBJ) $(ODOORS)
	$(CC) -o magiedit -o $@ $^ $(CFLAGS) $(ODOORS) $(EXTRA_LIBS)

.PHONY: clean

clean:
	rm -f $(OBJ) magiedit
