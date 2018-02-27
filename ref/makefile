CFLAGS=-O3 -march=native -std=c89 -Wall -Wextra -pedantic -Wno-long-long

all: attack

attack:
	@$(CC) $(CFLAGS) -I../ -o attack ../attack.c opp.c
	@./attack
	@rm attack
