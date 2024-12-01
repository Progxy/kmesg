FLAGS = -std=gnu11 -Wall -Wextra -pedantic

all: kmesg

install: kmesg
	mv ./kmesg /usr/local/sbin

kmesg: kmesg.c
	gcc $(FLAGS) -lncurses $< -o $@

debug: kmesg.c
	gcc $(FLAGS) -ggdb -lncurses $< -o kmesg

clean:
	rm -rf kmesg
