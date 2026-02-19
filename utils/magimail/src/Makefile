# type either "make all" or "make win32" to compile

help:
	@echo You can use this Makefile in the following ways:
	@echo make linux ............ Make Linux binaries
	@echo make cleanlinux ....... Remove object files under Linux

all:
	mkdir -p obj
	${MAKE} -C cmnllib -f Makefile.linux
	${MAKE} -C oslib_linux
	${MAKE} -f Makefile.linux
		
clean:
	${MAKE} -C cmnllib -f Makefile.linux clean
	${MAKE} -C oslib_linux clean
	${MAKE} -f Makefile.linux clean


freebsd:	all
linux:		all
cleanlinux:	clean
cleanfreebsd:	clean
