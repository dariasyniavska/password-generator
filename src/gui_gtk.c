#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "entropy.h"
#include "password_gen.h"
#include "password_check.h"
#include "crypto.h"

/* Усі елементи форми в одному місці, щоб до них був доступ з будь-якої функції */
typedef struct {
    GtkWidget *length;            /* поле зі стрілками: довжина */
    GtkWidget *allow_lower;       /* галочки "дозволено" */
    GtkWidget *allow_upper;
    GtkWidget *allow_digit;
    GtkWidget *allowed_special;   /* текстове поле: дозволені спецсимволи */
    GtkWidget *mand_lower;        /* галочки "обов'язково" */
    GtkWidget *mand_upper;
    GtkWidget *mand_digit;
    GtkWidget *mand_special;      /* текстове поле: обов'язкові спецсимволи */
    GtkWidget *password;          /* поле з паролем */
    GtkWidget *strength;          /* напис про стійкість */
    GtkWidget *key;               /* поле з ключем шифрування */
    GtkWidget *cipher;            /* поле з шифротекстом */
    GtkWidget *status;            /* напис про результат (помилки, підтвердження) */
} FormWidgets;

static FormWidgets form;
static MtState g_mt;              /* генератор випадкових чисел (один на всю програму) */

static int is_checked(GtkWidget *check)
{
    return gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check)) ? 1 : 0;
}

static void set_checked(GtkWidget *check, int value)
{
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), value ? TRUE : FALSE);
}

/* Копіює рядок, пропускаючи пробіли (користувач міг випадково їх набрати) */
static void copy_without_spaces(const char *src, char *dst, int dst_size)
{
    int j = 0;
    for (int i = 0; src[i] != '\0' && j < dst_size - 1; i++) {
        if (src[i] != ' ') {
            dst[j] = src[i];
            j++;
        }
    }
    dst[j] = '\0';
}

static void set_status(const char *text)
{
    gtk_label_set_text(GTK_LABEL(form.status), text);
}

/* Структура -> форма (використовується для стандартних налаштувань) */
static void write_settings_to_gui(const PasswordSettings *s)
{
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(form.length), s->length);

    set_checked(form.allow_lower, s->allow_lower);
    set_checked(form.allow_upper, s->allow_upper);
    set_checked(form.allow_digit, s->allow_digit);
    gtk_entry_set_text(GTK_ENTRY(form.allowed_special), s->allowed_special);

    set_checked(form.mand_lower, s->mandatory_lower);
    set_checked(form.mand_upper, s->mandatory_upper);
    set_checked(form.mand_digit, s->mandatory_digit);
    gtk_entry_set_text(GTK_ENTRY(form.mand_special), s->mandatory_special);
}

/* Форма -> структура (викликається перед генерацією і перевіркою) */
static void read_settings_from_gui(PasswordSettings *s)
{
    memset(s, 0, sizeof(*s));

    gtk_spin_button_update(GTK_SPIN_BUTTON(form.length));   /* прийняти число, яке ще набирають */
    s->length = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(form.length));

    s->allow_lower = is_checked(form.allow_lower);
    s->allow_upper = is_checked(form.allow_upper);
    s->allow_digit = is_checked(form.allow_digit);
    copy_without_spaces(gtk_entry_get_text(GTK_ENTRY(form.allowed_special)),
                        s->allowed_special, (int)sizeof(s->allowed_special));

    s->mandatory_lower = is_checked(form.mand_lower);
    s->mandatory_upper = is_checked(form.mand_upper);
    s->mandatory_digit = is_checked(form.mand_digit);
    copy_without_spaces(gtk_entry_get_text(GTK_ENTRY(form.mand_special)),
                        s->mandatory_special, (int)sizeof(s->mandatory_special));
}

static void show_strength(const PasswordSettings *s)
{
    char text[160];
    char bar[6] = "-----";
    double bits = estimate_entropy_bits(s);
    int level = strength_level(bits);

    for (int i = 0; i < level; i++) {
        bar[i] = '#';
    }
    snprintf(text, sizeof(text), "Стійкість: %s [%s]  (≈ %.0f біт)",
             strength_text(level), bar, bits);
    gtk_label_set_text(GTK_LABEL(form.strength), text);
}

static void on_generate(GtkWidget *button, gpointer data)
{
    (void)button;
    (void)data;

    PasswordSettings s;
    char password[MAX_PASSWORD_LEN + 1];

    read_settings_from_gui(&s);
    GenStatus st = generate_password(&g_mt, &s, password);

    if (st != GEN_OK) {
        gtk_entry_set_text(GTK_ENTRY(form.password), "");
        gtk_label_set_text(GTK_LABEL(form.strength), "");
        set_status(gen_status_text(st));
        return;
    }

    gtk_entry_set_text(GTK_ENTRY(form.password), password);
    show_strength(&s);
    set_status(check_status_text(check_password(password, &s)));
}

/* Перевіряє те, що зараз у полі пароля (можна вставити свій пароль) */
static void on_check(GtkWidget *button, gpointer data)
{
    (void)button;
    (void)data;

    PasswordSettings s;
    read_settings_from_gui(&s);

    const char *password = gtk_entry_get_text(GTK_ENTRY(form.password));
    set_status(check_status_text(check_password(password, &s)));
}

static void on_copy(GtkWidget *button, gpointer data)
{
    (void)button;
    (void)data;

    const char *password = gtk_entry_get_text(GTK_ENTRY(form.password));
    if (password[0] == '\0') {
        return;
    }
    gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD), password, -1);
    set_status("Пароль скопійовано в буфер обміну");
}

/* Якщо поставили "обов'язково", то "дозволено" вмикається саме */
static void on_mandatory_toggled(GtkToggleButton *mandatory, gpointer allow_widget)
{
    if (gtk_toggle_button_get_active(mandatory)) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(allow_widget), TRUE);
    }
}

static void on_encrypt(GtkWidget *button, gpointer data)
{
    (void)button;
    (void)data;

    char key_hex[KEY_HEX_SIZE];
    char cipher_hex[CIPHER_HEX_SIZE];
    const char *password = gtk_entry_get_text(GTK_ENTRY(form.password));

    CryptoStatus st = encrypt_password(password, key_hex, cipher_hex);
    if (st != CRYPTO_OK) {
        set_status(crypto_status_text(st));
        return;
    }

    gtk_entry_set_text(GTK_ENTRY(form.key), key_hex);
    gtk_entry_set_text(GTK_ENTRY(form.cipher), cipher_hex);
    set_status("Пароль зашифровано. Збережіть ключ окремо від шифротексту.");
}

/* Рядок: напис ліворуч + елемент праворуч */
static GtkWidget *make_row(const char *label_text, GtkWidget *field, gboolean field_expands)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *label = gtk_label_new(label_text);

    gtk_box_pack_start(GTK_BOX(row), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), field, field_expands, field_expands, 0);
    return row;
}

/* Рамка із заголовком навколо групи елементів */
static GtkWidget *make_frame(const char *title, GtkWidget *content)
{
    GtkWidget *frame = gtk_frame_new(title);
    gtk_container_set_border_width(GTK_CONTAINER(content), 8);
    gtk_container_add(GTK_CONTAINER(frame), content);
    return frame;
}

static GtkWidget *make_button(const char *text, GCallback on_click)
{
    GtkWidget *button = gtk_button_new_with_label(text);
    g_signal_connect(button, "clicked", on_click, NULL);
    return button;
}

/* Великий моноширинний шрифт для поля з паролем */
static void apply_style(void)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider,
        ".password { font-family: Menlo, Consolas, monospace; font-size: 18px; font-weight: bold; }",
        -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static GtkWidget *create_window(void)
{
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Генератор паролів");
    gtk_window_set_default_size(GTK_WINDOW(window), 480, -1);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(window), 12);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), main_box);

    /* --- довжина --- */
    form.length = gtk_spin_button_new_with_range(MIN_PASSWORD_LEN, MAX_PASSWORD_LEN, 1);
    gtk_box_pack_start(GTK_BOX(main_box), make_row("Довжина пароля:", form.length, FALSE), FALSE, FALSE, 0);

    /* --- дозволені символи --- */
    GtkWidget *allowed_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *allowed_checks = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    form.allow_lower = gtk_check_button_new_with_label("малі літери");
    form.allow_upper = gtk_check_button_new_with_label("великі літери");
    form.allow_digit = gtk_check_button_new_with_label("цифри");
    gtk_box_pack_start(GTK_BOX(allowed_checks), form.allow_lower, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(allowed_checks), form.allow_upper, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(allowed_checks), form.allow_digit, FALSE, FALSE, 0);
    form.allowed_special = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(allowed_box), allowed_checks, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(allowed_box), make_row("Спецсимволи:", form.allowed_special, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), make_frame("Дозволені символи", allowed_box), FALSE, FALSE, 0);

    /* --- обов'язкові символи --- */
    GtkWidget *mand_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *mand_checks = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    form.mand_lower = gtk_check_button_new_with_label("мала літера");
    form.mand_upper = gtk_check_button_new_with_label("велика літера");
    form.mand_digit = gtk_check_button_new_with_label("цифра");
    gtk_box_pack_start(GTK_BOX(mand_checks), form.mand_lower, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mand_checks), form.mand_upper, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mand_checks), form.mand_digit, FALSE, FALSE, 0);
    form.mand_special = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(mand_box), mand_checks, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mand_box), make_row("Спецсимволи:", form.mand_special, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), make_frame("Обов’язкові символи", mand_box), FALSE, FALSE, 0);

    g_signal_connect(form.mand_lower, "toggled", G_CALLBACK(on_mandatory_toggled), form.allow_lower);
    g_signal_connect(form.mand_upper, "toggled", G_CALLBACK(on_mandatory_toggled), form.allow_upper);
    g_signal_connect(form.mand_digit, "toggled", G_CALLBACK(on_mandatory_toggled), form.allow_digit);

    /* --- кнопки --- */
    GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(buttons), TRUE);
    gtk_box_pack_start(GTK_BOX(buttons), make_button("Згенерувати", G_CALLBACK(on_generate)), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), make_button("Перевірити", G_CALLBACK(on_check)), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(buttons), make_button("Копіювати", G_CALLBACK(on_copy)), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), buttons, FALSE, FALSE, 0);

    /* --- пароль і стійкість --- */
    form.password = gtk_entry_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(form.password), "password");
    gtk_box_pack_start(GTK_BOX(main_box), form.password, FALSE, FALSE, 0);

    form.strength = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(form.strength), 0.0f);
    gtk_box_pack_start(GTK_BOX(main_box), form.strength, FALSE, FALSE, 0);

    /* --- шифрування --- */
    GtkWidget *crypto_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *crypto_buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(crypto_buttons), TRUE);
    gtk_box_pack_start(GTK_BOX(crypto_buttons), make_button("Зашифрувати", G_CALLBACK(on_encrypt)), TRUE, TRUE, 0);
    form.key = gtk_entry_new();
    form.cipher = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(crypto_box), crypto_buttons, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(crypto_box), make_row("Ключ (hex):", form.key, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(crypto_box), make_row("Шифротекст:", form.cipher, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), make_frame("Шифрування (ChaCha20)", crypto_box), FALSE, FALSE, 0);

    /* --- рядок стану --- */
    form.status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(form.status), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(form.status), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(form.status), 55);
    gtk_box_pack_start(GTK_BOX(main_box), form.status, FALSE, FALSE, 0);

    return window;
}

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);

    mt_seed_from_os(&g_mt);      /* початкові дані для вихору Мерсенна беремо в ОС */
    apply_style();

    GtkWidget *window = create_window();

    PasswordSettings defaults;
    settings_set_default(&defaults);
    write_settings_to_gui(&defaults);

    gtk_widget_show_all(window);
    gtk_main();
    return 0;
}
