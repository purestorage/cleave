CFLAGS := -O2 -g -Werror -Wall -Wextra -std=gnu99 -ggdb -D_GNU_SOURCE

default: cleaved/cleaved libcleave/libcleave.so test/test

cleaved/cleaved: cleaved/cleaved.c
	gcc ${CFLAGS} -o $@ $<

libcleave/libcleave.so: libcleave/cleave.c libcleave/syscall.c
	gcc -fPIC ${CFLAGS} -Ilibcleave/ -shared -Wl,-soname,libcleave.so -o $@ $^

test/test: test/test.c libcleave/libcleave.so
	gcc ${CFLAGS} -Ilibcleave -Llibcleave -o $@ $< -lcleave

clean:
	find . -name *.o -exec rm {} \;
	rm -f cleaved/cleaved

.PHONY: clean test