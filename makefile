# SecureVault — Encrypted File Archive System
# Group: Wed_9am_08
#
# Usage:
#   make          — build release binary (./vault)
#   make debug    — build with DEBUG flag enabled
#   make clean    — remove all compiled objects and binaries

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -pedantic
TARGET = securevault

SRCS = main.c vault.c encrypt.c compress.c search.c history.c
OBJS = $(SRCS:.c=.o)

# Release build
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Debug build
debug: CFLAGS += -DDEBUG -g
debug: clean $(TARGET)

# Pattern rule - compile any .c to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Header dependencies - recompile affected .o if a header changes
main.o: main.c vault.h encrypt.h compress.h search.h history.h
vault.o: vault.c vault.h encrypt.h compress.h
encrypt.o: encrypt.c encrypt.h
compress.o: compress.c compress.h
search.o: search.c search.h
history.o: history.c history.h

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: debug clean
