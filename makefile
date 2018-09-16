CFLAGS=-O3 -march=native -std=c89 -Wall -Wextra -pedantic -Wno-long-long

all: attack

attack:
	@$(CC) $(CFLAGS) -Iref -o attack attack.c ./ref/opp.c
	@./attack
	@rm attack
