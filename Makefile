CC     = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -Iinclude

ifeq ($(OS),Windows_NT)
    LIBS = -lbcrypt -lm
    EXE  = .exe
else
    LIBS = -lm
    EXE  =
endif

CORE = src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c

console: $(CORE) src/main_console.c
	$(CC) $(CFLAGS) $^ -o password_console$(EXE) $(LIBS)

gui: $(CORE) src/gui_win32.c
	$(CC) $(CFLAGS) $^ -o password_gui.exe -mwindows $(LIBS)

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
	rm -f password_console password_console.exe password_gui.exe test_mt19937 test_generator test_checker test_crypto *.exe
