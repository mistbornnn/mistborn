CC = gcc
CFLAGS = -Wall -g

# Default target
all: vulnerable

# Compile the vulnerable program
vulnerable: src/vulnerable.c
	$(CC) $(CFLAGS) -o vulnerable src/vulnerable.c

# Run with ASan (AddressSanitizer) to detect memory issues
asan: src/vulnerable.c
	$(CC) $(CFLAGS) -fsanitize=address -o vulnerable_asan src/vulnerable.c

# Clean up generated files
clean:
	rm -f vulnerable vulnerable_asan

.PHONY: all asan clean