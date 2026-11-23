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
    GtkWidget *strength_bar;      /* графічна шкала стійкості */
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
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(form.strength_bar),
        level <= 0 ? 0.0 : (level >= 5 ? 1.0 : level / 5.0));
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
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(form.strength_bar), 0.0);
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

static GtkWidget *make_button(const char *text, GCallback on_click, const char *style_class)
{
    GtkWidget *button = gtk_button_new_with_label(text);
    if (style_class != NULL) {
        gtk_style_context_add_class(gtk_widget_get_style_context(button), style_class);
    }
    g_signal_connect(button, "clicked", on_click, NULL);
    return button;
}

/* Вбудована GTK CSS-тема без зовнішніх ресурсів. */
static void apply_style(void)
{
    static const char css[] =
        "window, window.background, scrolledwindow, viewport { background-color: #0B1324; }"
        ".app-root { background-color: #0B1324; }"
        ".app-root .section-heading { color: #94A3B8; font-size: 12px; font-weight: 800; }"
        ".app-root .section-hint { color: #8FA3BC; font-size: 12px; }"
        ".app-root progressbar trough { background-color: #24364C; min-height: 9px; border-radius: 7px; }"
        ".app-root progressbar progress { background-color: #2DD4BF; min-height: 9px; border-radius: 7px; }"
        ".app-root label { color: #E5ECF6; font-family: Sans; font-size: 13px; }"
        ".app-root .app-title { color: #F8FAFC; font-size: 25px; font-weight: 800; }"
        ".app-root .app-subtitle { color: #94A3B8; font-size: 12px; }"
        ".app-root .app-kicker { color: #2DD4BF; font-size: 11px; font-weight: 800; }"
        ".app-root frame { background-color: #131F33; border-radius: 14px; border: 1px solid #2A3B52; padding: 6px; }"
        ".app-root frame > border { border: 1px solid #2A3B52; border-radius: 14px; }"
        ".app-root frame > label { color: #9DEAE0; font-size: 13px; font-weight: 700; }"
        ".app-root entry, .app-root spinbutton { background-color: #0D192B; background-image: none; color: #F8FAFC; border: 1px solid #3C506B; border-radius: 8px; padding: 7px 9px; caret-color: #2DD4BF; }"
        ".app-root entry:focus, .app-root spinbutton:focus { border-color: #2DD4BF; }"
        ".app-root entry selection { background-color: #0D9488; color: white; }"
        ".app-root spinbutton button { background: #1B3048; color: #FFFFFF; border: none; border-radius: 5px; }"
        ".app-root checkbutton { color: #E5ECF6; }"
        ".app-root checkbutton check { background: #15253B; border: 1px solid #64748B; border-radius: 4px; color: white; }"
        ".app-root checkbutton check:checked { background: #0D9488; border-color: #2DD4BF; color: #FFFFFF; }"
        ".app-root button { background-image: none; background-color: #25364E; color: #F1F5F9; border: 1px solid #3D506A; border-radius: 9px; padding: 9px 12px; font-weight: 700; }"
        ".app-root button:hover { background-color: #334B67; }"
        ".app-root button:active { background-color: #192C43; }"
        ".app-root .primary-action { background-color: #2DD4BF; color: #052F2D; border-color: #2DD4BF; }"
        ".app-root .primary-action:hover { background-color: #5EEAD4; color: #052F2D; }"
        ".app-root .encrypt-action { background-color: #2563EB; color: #F8FAFC; border-color: #3B82F6; }"
        ".app-root .encrypt-action:hover { background-color: #3B82F6; }"
        ".app-root .password-field { font-family: Menlo, monospace; font-size: 20px; font-weight: 800; color: #E9FBF8; background-color: #0D2230; border: 1px solid #14B8A6; padding: 13px; }"
        ".app-root .strength-label { color: #5EEAD4; font-size: 13px; font-weight: 700; }"
        ".app-root .status-label { color: #A5B4C9; font-size: 12px; }"
        ".app-root .secondary-label { color: #94A3B8; font-size: 12px; font-weight: 600; }";

    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static GtkWidget *create_window(void)
{
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Password Generator");
    gtk_window_set_default_size(GTK_WINDOW(window), 1180, 780);
    gtk_window_set_resizable(GTK_WINDOW(window), TRUE);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* Прокрутка потрібна, якщо програму відкриють на маленькому екрані. */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(window), scroll);

    GtkWidget *viewport = gtk_viewport_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), viewport);

    /* Центруємо вміст замість розтягування полів на всю ширину монітора. */
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 24);
    gtk_widget_set_size_request(main_box, 1060, -1);
    gtk_widget_set_halign(main_box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(main_box, 32);
    gtk_widget_set_margin_bottom(main_box, 32);
    gtk_widget_set_margin_start(main_box, 24);
    gtk_widget_set_margin_end(main_box, 24);
    gtk_style_context_add_class(gtk_widget_get_style_context(main_box), "app-root");
    gtk_container_add(GTK_CONTAINER(viewport), main_box);

    /* Шапка застосунку. */
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *kicker = gtk_label_new("SECURITY TOOLS  /  C + GTK 3");
    GtkWidget *title = gtk_label_new("Password Generator");
    GtkWidget *subtitle = gtk_label_new("Створюй, перевіряй та шифруй паролі в одному місці");
    gtk_label_set_xalign(GTK_LABEL(kicker), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(kicker), "app-kicker");
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "app-title");
    gtk_style_context_add_class(gtk_widget_get_style_context(subtitle), "app-subtitle");
    gtk_box_pack_start(GTK_BOX(header), kicker, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header), title, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(header), subtitle, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), header, FALSE, FALSE, 0);

    /* Дві зрозумілі колонки: налаштування зліва, результат справа. */
    GtkWidget *columns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_box_set_homogeneous(GTK_BOX(columns), TRUE);
    gtk_box_pack_start(GTK_BOX(main_box), columns, FALSE, FALSE, 0);

    GtkWidget *settings_col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    GtkWidget *result_col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    gtk_box_pack_start(GTK_BOX(columns), settings_col, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(columns), result_col, TRUE, TRUE, 0);

    /* Ліва колонка: параметри й правила генерації. */
    GtkWidget *settings_heading = gtk_label_new("НАЛАШТУВАННЯ ПАРОЛЯ");
    gtk_label_set_xalign(GTK_LABEL(settings_heading), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(settings_heading), "section-heading");
    gtk_box_pack_start(GTK_BOX(settings_col), settings_heading, FALSE, FALSE, 0);

    GtkWidget *length_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    form.length = gtk_spin_button_new_with_range(MIN_PASSWORD_LEN, MAX_PASSWORD_LEN, 1);
    gtk_box_pack_start(GTK_BOX(length_box),
        make_row("Довжина (4–128):", form.length, FALSE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(settings_col),
        make_frame("Довжина пароля", length_box), FALSE, FALSE, 0);

    GtkWidget *allowed_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *allowed_checks = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    form.allow_lower = gtk_check_button_new_with_label("малі літери");
    form.allow_upper = gtk_check_button_new_with_label("великі літери");
    form.allow_digit = gtk_check_button_new_with_label("цифри");
    gtk_box_pack_start(GTK_BOX(allowed_checks), form.allow_lower, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(allowed_checks), form.allow_upper, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(allowed_checks), form.allow_digit, FALSE, FALSE, 0);
    form.allowed_special = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(form.allowed_special), "Наприклад: !@#$%^&*");
    gtk_box_pack_start(GTK_BOX(allowed_box), allowed_checks, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(allowed_box),
        make_row("Спецсимволи:", form.allowed_special, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(settings_col),
        make_frame("Дозволені символи", allowed_box), FALSE, FALSE, 0);

    GtkWidget *mandatory_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *mandatory_checks = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    form.mand_lower = gtk_check_button_new_with_label("мала літера");
    form.mand_upper = gtk_check_button_new_with_label("велика літера");
    form.mand_digit = gtk_check_button_new_with_label("цифра");
    gtk_box_pack_start(GTK_BOX(mandatory_checks), form.mand_lower, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mandatory_checks), form.mand_upper, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mandatory_checks), form.mand_digit, FALSE, FALSE, 0);
    form.mand_special = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(form.mand_special), "Необов'язково: @!");
    gtk_box_pack_start(GTK_BOX(mandatory_box), mandatory_checks, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mandatory_box),
        make_row("Спецсимволи:", form.mand_special, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(settings_col),
        make_frame("Обов'язкові символи", mandatory_box), FALSE, FALSE, 0);

    g_signal_connect(form.mand_lower, "toggled", G_CALLBACK(on_mandatory_toggled), form.allow_lower);
    g_signal_connect(form.mand_upper, "toggled", G_CALLBACK(on_mandatory_toggled), form.allow_upper);
    g_signal_connect(form.mand_digit, "toggled", G_CALLBACK(on_mandatory_toggled), form.allow_digit);

    GtkWidget *hint = gtk_label_new(
        "Обов'язкові символи автоматично враховуються під час генерації.");
    gtk_label_set_xalign(GTK_LABEL(hint), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(hint), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(hint), "section-hint");
    gtk_box_pack_start(GTK_BOX(settings_col), hint, FALSE, FALSE, 0);

    /* Права колонка: дії, пароль і шифрування. */
    GtkWidget *result_heading = gtk_label_new("РЕЗУЛЬТАТ ТА ІНСТРУМЕНТИ");
    gtk_label_set_xalign(GTK_LABEL(result_heading), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(result_heading), "section-heading");
    gtk_box_pack_start(GTK_BOX(result_col), result_heading, FALSE, FALSE, 0);

    GtkWidget *buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(buttons), TRUE);
    gtk_box_pack_start(GTK_BOX(buttons),
        make_button("Згенерувати", G_CALLBACK(on_generate), "primary-action"), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(buttons),
        make_button("Перевірити", G_CALLBACK(on_check), NULL), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(buttons),
        make_button("Копіювати", G_CALLBACK(on_copy), NULL), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(result_col), buttons, FALSE, FALSE, 0);

    GtkWidget *password_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    form.password = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(form.password), "Згенеруй або встав свій пароль");
    gtk_style_context_add_class(gtk_widget_get_style_context(form.password), "password-field");
    gtk_box_pack_start(GTK_BOX(password_box), form.password, FALSE, FALSE, 0);
    form.strength = gtk_label_new("Стійкість: ще не оцінено");
    gtk_label_set_xalign(GTK_LABEL(form.strength), 0.0f);
    gtk_style_context_add_class(gtk_widget_get_style_context(form.strength), "strength-label");
    gtk_box_pack_start(GTK_BOX(password_box), form.strength, FALSE, FALSE, 0);
    form.strength_bar = gtk_progress_bar_new();
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(form.strength_bar), 0.0);
    gtk_box_pack_start(GTK_BOX(password_box), form.strength_bar, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(result_col),
        make_frame("Згенерований пароль", password_box), FALSE, FALSE, 0);

    GtkWidget *crypto_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 9);
    gtk_box_pack_start(GTK_BOX(crypto_box),
        make_button("Зашифрувати", G_CALLBACK(on_encrypt), "encrypt-action"), FALSE, FALSE, 0);
    form.key = gtk_entry_new();
    form.cipher = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(form.key), "Ключ з'явиться після шифрування");
    gtk_entry_set_placeholder_text(GTK_ENTRY(form.cipher), "Шифротекст з'явиться після шифрування");
    gtk_editable_set_editable(GTK_EDITABLE(form.key), FALSE);
    gtk_editable_set_editable(GTK_EDITABLE(form.cipher), FALSE);
    gtk_box_pack_start(GTK_BOX(crypto_box),
        make_row("Ключ (hex):", form.key, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(crypto_box),
        make_row("Шифротекст:", form.cipher, TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(result_col),
        make_frame("Шифрування (ChaCha20)", crypto_box), FALSE, FALSE, 0);

    form.status = gtk_label_new("Готово до генерації пароля");
    gtk_label_set_xalign(GTK_LABEL(form.status), 0.0f);
    gtk_label_set_line_wrap(GTK_LABEL(form.status), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(form.status), "status-label");
    gtk_box_pack_start(GTK_BOX(result_col), form.status, FALSE, FALSE, 0);

    return window;
}

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);
    GtkSettings *gtk_settings = gtk_settings_get_default();
    if (gtk_settings != NULL) {
        g_object_set(gtk_settings, "gtk-application-prefer-dark-theme", TRUE, NULL);
    }

    mt_seed_from_os(&g_mt);      /* початкові дані для вихору Мерсенна беремо в ОС */
    apply_style();

    GtkWidget *window = create_window();

    PasswordSettings defaults;
    settings_set_default(&defaults);
    write_settings_to_gui(&defaults);

    gtk_widget_show_all(window);
    /* Велике вікно без неконтрольованого розтягування елементів. */
    gtk_window_maximize(GTK_WINDOW(window));
    gtk_main();
    return 0;
}
