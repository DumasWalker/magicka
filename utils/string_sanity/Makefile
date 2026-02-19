OS := $(shell uname -s)

DEPS = sanity.c

OBJ = sanity.o 
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


sanity: $(OBJ)
	$(CC) -o sanity $^ $(CFLAGS) $(LDFLAGS) 

.PHONY: clean

clean:
	rm -f $(OBJ) sanity
