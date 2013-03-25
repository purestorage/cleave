default: cleaved/cleaved

cleaved/cleaved:
	gcc -O2 -g -Werror -Wall -Wextra -std=gnu99 -ggdb -D_GNU_SOURCE -o cleaved/cleaved cleaved/cleaved.c

clean:
	find . -name *.o -exec rm {} \;
	rm -f cleaved/cleaved

.PHONY: clean