CC = gcc
CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags openssl)
LDLIBS = $(shell pkg-config --libs openssl)
TARGET = vault

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
