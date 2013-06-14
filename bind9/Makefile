default: all

all: time-rndc

CFLAGS=-Wall -Werror -O0 -g -std=gnu99

time-rndc: time-rndc.o
	$(CC) -o $@ $< -lcrypto
