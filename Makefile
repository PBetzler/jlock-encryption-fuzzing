CC = gcc
CFLAGS = -Wall -Wextra -g -lcrypto

SRC_DIR = src
BIN_DIR = bin
SRC = $(shell find $(SRC_DIR) -name "*.c")
OBJ = $(SRC:.c=.o)
EXEC = $(BIN_DIR)/jlock

all: $(BIN_DIR) $(EXEC) clean_obj

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $(EXEC) $(CFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean_obj:
	rm -f $(OBJ)

clean:
	rm -f $(OBJ) $(EXEC)

.PHONY: all clean clean_obj
