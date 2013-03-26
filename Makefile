CFLAGS := -O2 -g -Werror -Wall -Wextra -std=gnu99 -ggdb -D_GNU_SOURCE

default: cleaved/cleaved libcleave/libcleave.so.1

cleaved/cleaved: cleaved/cleaved.c
	gcc ${CFLAGS} -o $@ $<

libcleave/libcleave.so.1: libcleave/cleave.c
	gcc -fPIC ${CFLAGS} -Ilibcleave/ -shared -Wl,-soname,libcleaved.so.1 -o $@ $<

clean:
	find . -name *.o -exec rm {} \;
	rm -f cleaved/cleaved

.PHONY: clean