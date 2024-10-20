CC = gcc
CFLAGS = -Wall -Wextra -O2 -lcrypto  # Removed debugging flags for release builds

SRC_DIR = src
BIN_DIR = bin
SRC = $(shell find $(SRC_DIR) -name "*.c")
OBJ = $(SRC:.c=.o)
EXEC = jlock  # Name of the executable without bin path

PREFIX ?= /usr/local  # Default install path

all: $(BIN_DIR) $(EXEC)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $(BIN_DIR)/$(EXEC) $(CFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN_DIR)/$(EXEC)

install: all
	install -Dm755 $(BIN_DIR)/$(EXEC) $(DESTDIR)$(PREFIX)/bin/$(EXEC)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(EXEC)

.PHONY: all clean install uninstall