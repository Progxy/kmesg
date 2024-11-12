
all: compile

install: compile
	mv ./kmesg /usr/local/sbin

compile: kmesg.c
	gcc -std=gnu11 -Wall -Wextra -pedantic kmesg.c -o kmesg
clean: kmesg
	rm -rf kmesg
