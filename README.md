# Генератор паролів

Автори: Костик Крістіна, Синявська Дар’я (АВІС-2)

Програма генерує пароль за налаштуваннями (довжина, дозволені та обов’язкові символи),
перевіряє його на відповідність налаштуванням і показує орієнтовну стійкість.
Випадкові числа: Вихор Мерсенна (MT19937), початкові дані беруться з операційної системи.
Додатково: шифрування згенерованого пароля шифром ChaCha20 (RFC 8439) з випадковим ключем
(ключ береться напряму з ОС, не з Вихору Мерсенна). Ключ треба зберігати окремо від шифротексту.

## Структура
- `include/`, `src/` — вихідний код (ядро, консольна версія та графічний інтерфейс на GTK 3)
- `tests/` — автоматичні юніт-тести

## Збірка

### Через Make (рекомендовано)
    make console
    make gui
    make test

*(На Windows використовуйте `mingw32-make`; для коректного відображення кирилиці в консолі виконайте `chcp 65001`.)*

### Вручну через gcc

**macOS / Linux:**
    gcc -std=gnu11 -Wall -Wextra -Iinclude src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c src/main_console.c -o password_console -lm
    gcc -std=gnu11 -Wall -Wextra -Iinclude src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c src/gui_gtk.c -o password_gui -lm $(pkg-config --cflags --libs gtk+-3.0)

**Windows (MinGW-w64 / MSYS2):**
    gcc -std=gnu11 -Wall -Wextra -Iinclude src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c src/main_console.c -o password_console.exe -lbcrypt -lm
    gcc -std=gnu11 -Wall -Wextra -Iinclude src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c src/gui_gtk.c -o password_gui.exe -lbcrypt -lm $(pkg-config --cflags --libs gtk+-3.0)