
all: compile

install: compile
	mv ./kmesg /usr/local/sbin

compile: kmesg.c
	gcc -std=c11 -Wall -Wextra -pedantic kmesg.c -o kmesg
