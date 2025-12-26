OPENSSL_PREFIX = /usr/local/opt/openssl@3
SDL2_PREFIX = /usr/local/opt/sdl2
SDL2_TTF_PREFIX = /usr/local/opt/sdl2_ttf

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I$(OPENSSL_PREFIX)/include -I$(SDL2_PREFIX)/include/SDL2 -I$(SDL2_TTF_PREFIX)/include/SDL2
LDLIBS = -L$(OPENSSL_PREFIX)/lib -L$(SDL2_PREFIX)/lib -L$(SDL2_TTF_PREFIX)/lib -lssl -lcrypto -lSDL2 -lSDL2_ttf -framework OpenGL -lobjc

TARGET = vault
NATIVE_TARGET = vault-mac

all: $(TARGET) $(NATIVE_TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDLIBS)

$(NATIVE_TARGET): main.m main.c
	$(CC) $(CFLAGS) -DNO_MAIN -o $(NATIVE_TARGET) main.m main.c -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -framework Cocoa -framework QuartzCore

clean:
	rm -f $(TARGET) $(NATIVE_TARGET)

.PHONY: all clean