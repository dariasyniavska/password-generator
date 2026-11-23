# Збірка проєкту "Генератор паролів"
# Команди: make console | make gui | make test | make clean
# УВАГА: перед командами (gcc ..., rm ...) має стояти символ Tab, а не пробіли!

CC     = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -Iinclude

ifeq ($(OS),Windows_NT)
    LIBS = -lbcrypt -lm
    EXE  = .exe
else
    LIBS = -lm
    EXE  =
endif

# прапорці бібліотеки GTK (потрібен pkg-config і gtk+3)
GTK = $(shell pkg-config --cflags --libs gtk+-3.0 2>/dev/null)

CORE = src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c

console: $(CORE) src/main_console.c
	$(CC) $(CFLAGS) $^ -o password_console$(EXE) $(LIBS)

gui: $(CORE) src/gui_gtk.c
	$(CC) $(CFLAGS) $^ -o password_gui$(EXE) $(LIBS) $(GTK)

test: $(CORE) tests/test_mt19937.c tests/test_generator.c tests/test_checker.c tests/test_crypto.c
	$(CC) $(CFLAGS) -Itests src/mt19937.c tests/test_mt19937.c -o test_mt19937$(EXE) $(LIBS)
	$(CC) $(CFLAGS) -Itests $(CORE) tests/test_generator.c -o test_generator$(EXE) $(LIBS)
	$(CC) $(CFLAGS) -Itests $(CORE) tests/test_checker.c -o test_checker$(EXE) $(LIBS)
	$(CC) $(CFLAGS) -Itests $(CORE) tests/test_crypto.c -o test_crypto$(EXE) $(LIBS)
	./test_mt19937$(EXE)
	./test_generator$(EXE)
	./test_checker$(EXE)
	./test_crypto$(EXE)

clean:
	rm -f password_console password_gui test_mt19937 test_generator test_checker test_crypto *.exe
