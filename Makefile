CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcrypto

SRC_DIR = src
BIN_DIR = bin
SRC = $(shell find $(SRC_DIR) -name "*.c")
OBJ = $(SRC:.c=.o)
EXEC = jlock  

PREFIX ?=
DESTDIR ?=

all: $(BIN_DIR) $(EXEC)

build: $(BIN_DIR) $(EXEC)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $(BIN_DIR)/$(EXEC) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN_DIR)/$(EXEC)

install: all
	install -Dm755 $(BIN_DIR)/$(EXEC) $(DESTDIR)$(PREFIX)/bin/$(EXEC)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(EXEC)

.PHONY: all clean install uninstall
