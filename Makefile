FLAGS = -std=gnu11 -ggdb -Wall -Wextra -pedantic

all: kmesg

install: kmesg
	mv ./kmesg /usr/local/sbin

kmesg: kmesg.c
	gcc $(FLAGS) -lncurses $< -o $@

clean:
	rm -rf kmesg
