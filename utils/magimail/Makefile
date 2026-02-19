# type either "make linux", "make win32", or "make os2" to compile

help:
	@echo You can use this Makefile in the following ways:
	@echo gmake freebsd ......... Make FreeBSD binaries
	@echo make linux ............ Make Linux binaries
	@echo gmake cleanfreebsd .... Remove object files under FreeBSD
	@echo make cleanlinux ....... Remove object files under Linux

all:
	mkdir -p bin
	${MAKE} -C src -f Makefile all

clean:
	rm -rf bin
	${MAKE} -C src -f Makefile clean

freebsd:	all
linux:		all
cleanfreebsd:	clean
cleanlinux:	clean
