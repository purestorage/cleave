CFLAGS := -Og -g -Werror -Wall -Wextra -std=gnu99 -ggdb

default: cleaved/cleaved libcleave/libcleave.so test/test

cleaved/cleaved: cleaved/cleaved.c
	gcc ${CFLAGS} -o $@ $<

libcleave/libcleave.so: libcleave/cleave.c
	gcc -fPIC ${CFLAGS} -Ilibcleave/ -shared -Wl,-soname,libcleave.so -o $@ $^

test/test: test/test.c libcleave/libcleave.so
	gcc ${CFLAGS} -Ilibcleave -Llibcleave -o $@ $< -lcleave

clean:
	find . -name *.o -exec rm {} \;
	rm -f cleaved/cleaved test/test libcleave/libcleave.so

runtests: test/test cleaved/cleaved
	CLEAVE_CLEAVED_FILENAME=cleaved/cleaved LD_LIBRARY_PATH=libcleave test/test

runtests_gdb: test/test cleaved/cleaved
	CLEAVE_CLEAVED_FILENAME=cleaved/cleaved LD_LIBRARY_PATH=libcleave gdb test/test

.PHONY: clean test runtests runtests_gdb
