# Генератор паролів 

Автори: Костик Крістіна, Синявська Дар’я (АВІС-2)

Програма генерує пароль за налаштуваннями (довжина, дозволені та обов’язкові символи),
перевіряє його на відповідність налаштуванням і показує орієнтовну стійкість.
Випадкові числа: Вихор Мерсенна (MT19937), початкові дані беруться з операційної системи.
Додатково: шифрування згенерованого пароля шифром ChaCha20 (RFC 8439) з випадковим ключем
(ключ береться напряму з ОС, не з Вихору Мерсенна). Ключ треба зберігати окремо від шифротексту.

## Структура
- `include/`, `src/` - вихідний код (ядро + консоль + вікно Windows)
- `tests/` - автоматичні тести
- `docs/` - презентація

## Збірка (потрібен MinGW-w64 / MSYS2 з gcc)
    gcc -Wall -Iinclude src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c src/main_console.c -o password_console.exe -lbcrypt -lm
    gcc -Wall -Iinclude src/mt19937.c src/entropy.c src/password_gen.c src/password_check.c src/crypto.c src/gui_win32.c -o password_gui.exe -mwindows -lbcrypt -lm

або `make console`, `make gui`, `make test` (на Windows - `mingw32-make`).

У консолі для української мови спершу виконайте `chcp 65001`.
