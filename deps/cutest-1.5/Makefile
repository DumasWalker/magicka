LIB=		libcutest.a

OBJS=		CuTest.o

$(LIB):		$(OBJS)
		ar ru $(LIB) $(OBJS)
		ranlib $(LIB)

$(OBJS):	CuTest.h

test:		$(LIB)
		$(CC) -o AllTests AllTests.c CuTestTest.c $(LIB)
		./AllTests

clean:
		rm -f AllTests *.o $(LIB)
