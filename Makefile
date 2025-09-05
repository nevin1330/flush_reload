# created by nevin
# Simple Makefile for Flush+Reload Attack Implementation

# Compile attacker
attacker: attacker.c gnupg_config.h
	gcc -o attacker attacker.c

# Compile victim  
victim: victim.c gnupg_config.h
	gcc -o victim victim.c

# Compile main
main: main.c
	gcc -o main main.c

# Compile all
all: attacker victim main

# Run the simulation
run: all
	./main

# Clean executables
clean:
	rm -f attacker victim main

.PHONY: all run clean
