/* gui.c — GTK3 front-end for pq-sign.
 *
 * A thin graphical wrapper around the same library used by the CLI: it loads
 * an armored key, derives the signed message exactly as `pq-sign sign` does
 * (SHA256( "pq-sign/v1" || SHA256(file) )), and emits one detached `.sig`
 * per selected file. Multiple files can be queued and signed in one pass; an
 * encrypted secret key is unlocked once via a passphrase dialog and reused.
 *
 * Unlike the CLI it never reads the passphrase from the controlling terminal
 * (there isn't one under a desktop launcher) — it uses the lower-level
 * key_armor_parse / key_decrypt seam so a wrong passphrase is recoverable
 * instead of fatal.
 */
#include <gtk/gtk.h>

#include "pqsign.h"
#include "keyfile_internal.h"

#include <oqs/oqs.h>
#include <stdarg.h>
#include <string.h>

/* Must match the CLI's DS_CONTEXT in main.c. */
static const char DS_CONTEXT[] = "pq-sign/v1";

/* User-facing alias -> canonical liboqs identifier, mirroring main.c. */
struct alg_alias { const char *alias; const char *canonical; const char *note; };
static const struct alg_alias ALIASES[] = {
    { "ml-dsa-44",   "ML-DSA-44",                 "lattice, NIST level 2" },
    { "ml-dsa-65",   "ML-DSA-65",                 "lattice, NIST level 3 (default)" },
    { "ml-dsa-87",   "ML-DSA-87",                 "lattice, NIST level 5" },
    { "slh-dsa-128f", "SPHINCS+-SHA2-128f-simple", "hash-based, level 1" },
    { "slh-dsa-192f", "SPHINCS+-SHA2-192f-simple", "hash-based, level 3" },
    { "slh-dsa-256f", "SPHINCS+-SHA2-256f-simple", "hash-based, level 5" },
    { NULL, NULL, NULL }
};

/* ------------------------------------------------------------------ *
 *  Shared application state
 * ------------------------------------------------------------------ */
typedef struct {
    GtkWidget    *window;
    /* keys tab */
    GtkWidget    *alg_combo;       /* GtkComboBoxText: alias -> canonical */
    GtkWidget    *encrypt_check;
    GtkWidget    *keygen_status;
    /* sign tab */
    GtkWidget    *key_chooser;     /* GtkFileChooserButton for .key      */
    GtkListStore *files_store;     /* queued files to sign               */
    GtkWidget    *files_view;
    GtkWidget    *sign_status;
    /* verify tab */
    GtkWidget    *pub_chooser;
    GtkWidget    *vfile_chooser;
    GtkWidget    *sig_chooser;
    GtkWidget    *verify_status;
} App;

/* ------------------------------------------------------------------ *
 *  Small helpers
 * ------------------------------------------------------------------ */
static void show_error(GtkWindow *parent, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    GtkWidget *d = gtk_message_dialog_new(parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
    g_free(msg);
}

/* Modal passphrase prompt. Returns a newly-allocated string (caller frees)
 * or NULL if the user cancelled. */
static char *ask_passphrase(GtkWindow *parent, const char *keyname)
{
    GtkWidget *d = gtk_dialog_new_with_buttons("Unlock secret key", parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Unlock", GTK_RESPONSE_OK, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(d), GTK_RESPONSE_OK);

    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    gtk_box_set_spacing(GTK_BOX(box), 8);

    char *lbltext = g_strdup_printf("Passphrase for “%s”:", keyname);
    GtkWidget *label = gtk_label_new(lbltext);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    g_free(lbltext);

    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(entry), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);

    gtk_container_add(GTK_CONTAINER(box), label);
    gtk_container_add(GTK_CONTAINER(box), entry);
    gtk_widget_show_all(d);

    char *pass = NULL;
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK) {
        const char *txt = gtk_entry_get_text(GTK_ENTRY(entry));
        pass = g_strdup(txt);
    }
    /* Best-effort wipe of the entry buffer before destroying. */
    gtk_entry_set_text(GTK_ENTRY(entry), "");
    gtk_widget_destroy(d);
    return pass;
}

/* Modal "set a new passphrase" prompt with confirmation. Loops until the two
 * entries match (and are non-empty) or the user cancels. Returns a newly
 * allocated string (caller frees) or NULL on cancel. */
static char *ask_new_passphrase(GtkWindow *parent)
{
    GtkWidget *d = gtk_dialog_new_with_buttons("Set key passphrase", parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_OK", GTK_RESPONSE_OK, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(d), GTK_RESPONSE_OK);

    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);
    gtk_box_set_spacing(GTK_BOX(box), 6);

    GtkWidget *l1 = gtk_label_new("Passphrase for the new secret key:");
    gtk_widget_set_halign(l1, GTK_ALIGN_START);
    GtkWidget *e1 = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(e1), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(e1), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_activates_default(GTK_ENTRY(e1), TRUE);

    GtkWidget *l2 = gtk_label_new("Confirm passphrase:");
    gtk_widget_set_halign(l2, GTK_ALIGN_START);
    GtkWidget *e2 = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(e2), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(e2), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_activates_default(GTK_ENTRY(e2), TRUE);

    gtk_container_add(GTK_CONTAINER(box), l1);
    gtk_container_add(GTK_CONTAINER(box), e1);
    gtk_container_add(GTK_CONTAINER(box), l2);
    gtk_container_add(GTK_CONTAINER(box), e2);
    gtk_widget_show_all(d);

    char *pass = NULL;
    while (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK) {
        const char *p1 = gtk_entry_get_text(GTK_ENTRY(e1));
        const char *p2 = gtk_entry_get_text(GTK_ENTRY(e2));
        if (p1[0] == '\0') {
            show_error(GTK_WINDOW(d), "Passphrase cannot be empty.");
            continue;
        }
        if (strcmp(p1, p2) != 0) {
            show_error(GTK_WINDOW(d), "Passphrases do not match — try again.");
            gtk_entry_set_text(GTK_ENTRY(e2), "");
            continue;
        }
        pass = g_strdup(p1);
        break;
    }
    gtk_entry_set_text(GTK_ENTRY(e1), "");
    gtk_entry_set_text(GTK_ENTRY(e2), "");
    gtk_widget_destroy(d);
    return pass;
}

/* ------------------------------------------------------------------ *
 *  Crypto: load a secret key (handling encryption) and sign files
 * ------------------------------------------------------------------ */

/* Load and decrypt a secret key into `out`. On an encrypted key, prompts for
 * the passphrase (retrying on a wrong one) until success or cancel. Returns
 * TRUE on success; on failure shows nothing (caller reports) unless the user
 * cancelled, in which case *cancelled is set. */
static gboolean load_secret_key(GtkWindow *parent, const char *path,
                                pqsign_key *out, gboolean *cancelled,
                                char **errmsg)
{
    *cancelled = FALSE;
    *errmsg = NULL;
    memset(out, 0, sizeof *out);

    gchar *raw = NULL;
    gsize len = 0;
    GError *gerr = NULL;
    if (!g_file_get_contents(path, &raw, &len, &gerr)) {
        *errmsg = g_strdup(gerr ? gerr->message : "cannot read key file");
        g_clear_error(&gerr);
        return FALSE;
    }

    pqsign_armor a;
    gboolean parsed = key_armor_parse((const uint8_t *)raw, len, &a);
    /* armor copies what it needs; wipe the raw text. */
    if (len) memset(raw, 0, len);
    g_free(raw);
    if (!parsed) {
        *errmsg = g_strdup("not a valid PQSIGN key file");
        return FALSE;
    }
    if (!a.is_secret) {
        *errmsg = g_strdup("this is a public key — choose a .key secret key");
        armor_free(&a);
        return FALSE;
    }

    char *keyname = g_path_get_basename(path);
    gboolean ok = FALSE;
    if (!a.encrypted) {
        ok = key_decrypt(&a, NULL, &out->key, &out->key_len);
        if (!ok) *errmsg = g_strdup("could not decode key body");
    } else {
        for (;;) {
            char *pass = ask_passphrase(parent, keyname);
            if (!pass) { *cancelled = TRUE; break; }
            ok = key_decrypt(&a, pass, &out->key, &out->key_len);
            if (pass[0]) memset(pass, 0, strlen(pass));
            g_free(pass);
            if (ok) break;
            show_error(parent, "Wrong passphrase — try again.");
        }
    }
    g_free(keyname);

    if (ok) {
        g_strlcpy(out->alg, a.alg, sizeof out->alg);
        out->is_secret = TRUE;
        out->pub = a.pub;          /* transfer ownership */
        out->pub_len = a.pub_len;
        a.pub = NULL;
    }
    armor_free(&a);
    return ok;
}

/* Derive the signed message for `file`: SHA256( ctx || SHA256(file) ). */
static void signed_message(const char *path, uint8_t out[32])
{
    uint8_t fdigest[32];
    sha256_file(path, fdigest);
    uint8_t buf[sizeof(DS_CONTEXT) - 1 + 32];
    memcpy(buf, DS_CONTEXT, sizeof(DS_CONTEXT) - 1);
    memcpy(buf + sizeof(DS_CONTEXT) - 1, fdigest, 32);
    sha256(buf, sizeof buf, out);
}

/* Sign one file; returns NULL on success or a newly-allocated error string. */
static char *sign_one_file(OQS_SIG *sig, const pqsign_key *sk,
                           const char *file)
{
    if (!g_file_test(file, G_FILE_TEST_IS_REGULAR))
        return g_strdup_printf("'%s' is not a regular file", file);

    uint8_t msg[32];
    signed_message(file, msg);

    uint8_t *signature = xmalloc(sig->length_signature);
    size_t siglen = 0;
    if (OQS_SIG_sign(sig, signature, &siglen, msg, sizeof msg, sk->key)
        != OQS_SUCCESS) {
        free(signature);
        return g_strdup_printf("signing failed for '%s'", file);
    }

    size_t blob_len = 0;
    uint8_t *blob = sigfile_build(sk->alg, sk->pub, sk->pub_len,
                                  signature, siglen, &blob_len);

    char *outpath = g_strdup_printf("%s.sig", file);
    GError *gerr = NULL;
    gboolean wrote = g_file_set_contents(outpath, (const char *)blob,
                                         blob_len, &gerr);
    char *err = NULL;
    if (!wrote)
        err = g_strdup_printf("could not write '%s': %s", outpath,
                              gerr ? gerr->message : "unknown error");
    g_clear_error(&gerr);
    g_free(outpath);

    free(blob);
    memset(signature, 0, sig->length_signature);
    free(signature);
    return err;
}

/* ------------------------------------------------------------------ *
 *  Sign tab callbacks
 * ------------------------------------------------------------------ */
static void add_files_to_store(App *app, GSList *paths)
{
    for (GSList *p = paths; p; p = p->next) {
        GtkTreeIter it;
        gtk_list_store_append(app->files_store, &it);
        gtk_list_store_set(app->files_store, &it, 0, (char *)p->data, -1);
    }
}

static void on_add_files(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *app = data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new("Choose files to sign",
        GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Add", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dlg), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        GSList *files = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dlg));
        add_files_to_store(app, files);
        g_slist_free_full(files, g_free);
    }
    gtk_widget_destroy(dlg);
}

static void on_remove_selected(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *app = data;
    GtkTreeSelection *sel =
        gtk_tree_view_get_selection(GTK_TREE_VIEW(app->files_view));
    GtkTreeModel *model;
    GList *rows = gtk_tree_selection_get_selected_rows(sel, &model);
    /* Collect references first since paths shift as rows are removed. */
    GList *refs = NULL;
    for (GList *r = rows; r; r = r->next)
        refs = g_list_prepend(refs,
            gtk_tree_row_reference_new(model, r->data));
    for (GList *r = refs; r; r = r->next) {
        GtkTreePath *path = gtk_tree_row_reference_get_path(r->data);
        GtkTreeIter it;
        if (path && gtk_tree_model_get_iter(model, &it, path))
            gtk_list_store_remove(app->files_store, &it);
        if (path) gtk_tree_path_free(path);
        gtk_tree_row_reference_free(r->data);
    }
    g_list_free(refs);
    g_list_free_full(rows, (GDestroyNotify)gtk_tree_path_free);
}

static void on_clear_files(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *app = data;
    gtk_list_store_clear(app->files_store);
}

static void on_sign(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *app = data;
    GtkWindow *win = GTK_WINDOW(app->window);

    char *keypath =
        gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(app->key_chooser));
    if (!keypath) {
        show_error(win, "Choose a secret key (.key) first.");
        return;
    }

    /* Gather queued files. */
    GPtrArray *files = g_ptr_array_new_with_free_func(g_free);
    GtkTreeIter it;
    GtkTreeModel *m = GTK_TREE_MODEL(app->files_store);
    if (gtk_tree_model_get_iter_first(m, &it)) {
        do {
            char *f = NULL;
            gtk_tree_model_get(m, &it, 0, &f, -1);
            if (f) g_ptr_array_add(files, f);
        } while (gtk_tree_model_iter_next(m, &it));
    }
    if (files->len == 0) {
        show_error(win, "Add at least one file to sign.");
        g_ptr_array_free(files, TRUE);
        g_free(keypath);
        return;
    }

    /* Load + unlock the key once. */
    pqsign_key sk;
    gboolean cancelled = FALSE;
    char *errmsg = NULL;
    if (!load_secret_key(win, keypath, &sk, &cancelled, &errmsg)) {
        if (!cancelled)
            show_error(win, "Cannot use key: %s", errmsg ? errmsg : "error");
        g_free(errmsg);
        g_ptr_array_free(files, TRUE);
        g_free(keypath);
        return;
    }

    OQS_SIG *sig = OQS_SIG_new(sk.alg);
    if (!sig) {
        show_error(win, "Algorithm '%s' from the key is unavailable.", sk.alg);
        key_free(&sk);
        g_ptr_array_free(files, TRUE);
        g_free(keypath);
        return;
    }
    gboolean sizes_ok = (sk.key_len == sig->length_secret_key) &&
                        sk.pub && sk.pub_len == sig->length_public_key;
    if (!sizes_ok) {
        show_error(win, "Key is malformed for %s (size mismatch or no "
                        "embedded public key).", sk.alg);
        OQS_SIG_free(sig);
        key_free(&sk);
        g_ptr_array_free(files, TRUE);
        g_free(keypath);
        return;
    }

    guint ok_count = 0;
    GString *failures = g_string_new(NULL);
    for (guint i = 0; i < files->len; i++) {
        char *err = sign_one_file(sig, &sk, files->pdata[i]);
        if (err) {
            g_string_append_printf(failures, "\n• %s", err);
            g_free(err);
        } else {
            ok_count++;
        }
    }

    OQS_SIG_free(sig);
    key_free(&sk);

    char *summary;
    if (failures->len == 0)
        summary = g_strdup_printf("Signed %u file%s with %s — wrote .sig "
                                  "alongside each.", ok_count,
                                  ok_count == 1 ? "" : "s", sk.alg);
    else
        summary = g_strdup_printf("Signed %u of %u file%s. Failures:%s",
                                  ok_count, files->len,
                                  files->len == 1 ? "" : "s", failures->str);
    gtk_label_set_text(GTK_LABEL(app->sign_status), summary);
    g_free(summary);

    g_string_free(failures, TRUE);
    g_ptr_array_free(files, TRUE);
    g_free(keypath);
}

/* ------------------------------------------------------------------ *
 *  Verify tab callback
 * ------------------------------------------------------------------ */
static void on_verify(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *app = data;
    GtkWindow *win = GTK_WINDOW(app->window);

    char *pubpath =
        gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(app->pub_chooser));
    char *file =
        gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(app->vfile_chooser));
    char *sigpath =
        gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(app->sig_chooser));

    if (!pubpath || !file) {
        show_error(win, "Choose a public key (.pub) and the file to verify.");
        goto done;
    }
    /* Default signature path is <file>.sig when not given. */
    char *sig_to_use = sigpath ? g_strdup(sigpath)
                               : g_strdup_printf("%s.sig", file);

    /* Load the public key (never encrypted). */
    gchar *raw = NULL; gsize len = 0; GError *gerr = NULL;
    if (!g_file_get_contents(pubpath, &raw, &len, &gerr)) {
        show_error(win, "Cannot read public key: %s",
                   gerr ? gerr->message : "error");
        g_clear_error(&gerr); g_free(sig_to_use); goto done;
    }
    pqsign_armor a;
    if (!key_armor_parse((const uint8_t *)raw, len, &a)) {
        g_free(raw);
        show_error(win, "Not a valid PQSIGN key file."); g_free(sig_to_use);
        goto done;
    }
    g_free(raw);
    if (a.is_secret) {
        armor_free(&a);
        show_error(win, "That is a secret key — choose the .pub file.");
        g_free(sig_to_use); goto done;
    }
    pqsign_key pk; memset(&pk, 0, sizeof pk);
    if (!key_decrypt(&a, NULL, &pk.key, &pk.key_len)) {
        armor_free(&a);
        show_error(win, "Could not decode the public key.");
        g_free(sig_to_use); goto done;
    }
    g_strlcpy(pk.alg, a.alg, sizeof pk.alg);
    armor_free(&a);

    /* Load and parse the detached signature blob. */
    gchar *blobg = NULL; gsize bloblen = 0;
    if (!g_file_get_contents(sig_to_use, &blobg, &bloblen, &gerr)) {
        show_error(win, "Cannot read signature: %s",
                   gerr ? gerr->message : "error");
        g_clear_error(&gerr); key_free(&pk); g_free(sig_to_use); goto done;
    }
    pqsign_sigfile sf;
    if (!sigfile_parse((const uint8_t *)blobg, bloblen, &sf)) {
        g_free(blobg);
        show_error(win, "'%s' is not a valid pq-sign signature.", sig_to_use);
        key_free(&pk); g_free(sig_to_use); goto done;
    }
    sf.raw = (uint8_t *)blobg;

    if (strcmp(sf.alg, pk.alg) != 0) {
        char *txt = g_strdup_printf(
            "✘ VERIFY FAILED: signature is %s but key is %s",
            sf.alg, pk.alg);
        gtk_label_set_text(GTK_LABEL(app->verify_status), txt);
        g_free(txt);
    } else {
        uint8_t fpr[32];
        sha256(pk.key, pk.key_len, fpr);
        OQS_SIG *sig = OQS_SIG_new(pk.alg);
        gboolean ok = FALSE;
        if (sig && pk.key_len == sig->length_public_key &&
            ct_equal(fpr, sf.pub_fpr, 32)) {
            uint8_t msg[32];
            signed_message(file, msg);
            ok = (OQS_SIG_verify(sig, msg, sizeof msg, sf.sig, sf.sig_len,
                                 pk.key) == OQS_SUCCESS);
        }
        if (sig) OQS_SIG_free(sig);
        char fprhex[65];
        to_hex(fpr, 32, fprhex);
        char *txt = ok
            ? g_strdup_printf("✔ VERIFY OK — %s\nsigner %.16s",
                              pk.alg, fprhex)
            : g_strdup("✘ VERIFY FAILED — signature is invalid or was made "
                       "for a different key.");
        gtk_label_set_text(GTK_LABEL(app->verify_status), txt);
        g_free(txt);
    }

    sigfile_free(&sf);          /* frees sf.raw == blobg */
    key_free(&pk);
    g_free(sig_to_use);

done:
    g_free(pubpath);
    g_free(file);
    g_free(sigpath);
}

/* ------------------------------------------------------------------ *
 *  Keys tab: generate a keypair (mirrors `pq-sign keygen`)
 * ------------------------------------------------------------------ */
static void on_keygen(GtkButton *btn, gpointer data)
{
    (void)btn;
    App *app = data;
    GtkWindow *win = GTK_WINDOW(app->window);

    /* Selected algorithm: the combo's active id holds the canonical name. */
    const char *canon =
        gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->alg_combo));
    if (!canon) {
        show_error(win, "Choose a signature algorithm.");
        return;
    }
    if (!OQS_SIG_alg_is_enabled(canon)) {
        show_error(win, "Algorithm '%s' is not enabled in this liboqs build.",
                   canon);
        return;
    }

    gboolean encrypt = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(app->encrypt_check));

    /* Ask where to save: the chosen path is the basename; .pub/.key are
     * derived from it (matching the CLI's --out). */
    GtkWidget *dlg = gtk_file_chooser_dialog_new("Save keypair as…", win,
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "mykey");
    if (gtk_dialog_run(GTK_DIALOG(dlg)) != GTK_RESPONSE_ACCEPT) {
        gtk_widget_destroy(dlg);
        return;
    }
    char *base = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    gtk_widget_destroy(dlg);
    if (!base)
        return;

    /* Generate the keypair. */
    OQS_SIG *sig = OQS_SIG_new(canon);
    if (!sig) {
        show_error(win, "Failed to initialise %s.", canon);
        g_free(base);
        return;
    }
    uint8_t *pub = xmalloc(sig->length_public_key);
    uint8_t *sec = secure_alloc(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pub, sec) != OQS_SUCCESS) {
        show_error(win, "Key generation failed.");
        secure_free(sec, sig->length_secret_key);
        free(pub);
        OQS_SIG_free(sig);
        g_free(base);
        return;
    }

    char *pass = NULL;
    if (encrypt) {
        pass = ask_new_passphrase(win);
        if (!pass) {            /* cancelled — discard generated material */
            secure_free(sec, sig->length_secret_key);
            free(pub);
            OQS_SIG_free(sig);
            g_free(base);
            return;
        }
    }

    char *pubpath = g_strdup_printf("%s.pub", base);
    char *secpath = g_strdup_printf("%s.key", base);
    key_write_public(pubpath, canon, pub, sig->length_public_key);
    key_write_secret(secpath, canon, sec, sig->length_secret_key,
                     pub, sig->length_public_key, pass);

    uint8_t fpr[32];
    char fprhex[65];
    sha256(pub, sig->length_public_key, fpr);
    to_hex(fpr, 32, fprhex);

    char *summary = g_strdup_printf(
        "Generated %s keypair\n"
        "public key:  %s\n"
        "secret key:  %s%s\n"
        "fingerprint: %.16s",
        canon, pubpath, secpath,
        encrypt ? "  (encrypted)" : "", fprhex);
    gtk_label_set_text(GTK_LABEL(app->keygen_status), summary);
    g_free(summary);

    if (pass) {
        memset(pass, 0, strlen(pass));
        g_free(pass);
    }
    g_free(pubpath);
    g_free(secpath);
    secure_free(sec, sig->length_secret_key);
    free(pub);
    OQS_SIG_free(sig);
    g_free(base);
}

static GtkWidget *build_keys_tab(App *app)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);

    GtkWidget *intro = gtk_label_new(
        "Generate a new keypair. The public key (.pub) can be shared; the "
        "secret key (.key) signs your files — keep it private.");
    gtk_label_set_line_wrap(GTK_LABEL(intro), TRUE);
    gtk_widget_set_halign(intro, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), intro, FALSE, FALSE, 0);

    /* Algorithm chooser, populated with the schemes this liboqs enabled. */
    GtkWidget *algrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *alglbl = gtk_label_new("Algorithm:");
    gtk_widget_set_size_request(alglbl, 90, -1);
    gtk_widget_set_halign(alglbl, GTK_ALIGN_START);
    app->alg_combo = gtk_combo_box_text_new();
    for (const struct alg_alias *a = ALIASES; a->alias; a++) {
        if (!OQS_SIG_alg_is_enabled(a->canonical))
            continue;
        char *label = g_strdup_printf("%s — %s", a->alias, a->note);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->alg_combo),
                                  a->canonical, label);
        g_free(label);
    }
    /* Default to ML-DSA-65 if available, else the first entry. */
    if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->alg_combo),
                                     PQSIGN_DEFAULT_ALG))
        gtk_combo_box_set_active(GTK_COMBO_BOX(app->alg_combo), 0);
    gtk_box_pack_start(GTK_BOX(algrow), alglbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(algrow), app->alg_combo, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), algrow, FALSE, FALSE, 0);

    app->encrypt_check = gtk_check_button_new_with_label(
        "Encrypt the secret key with a passphrase (Argon2id + AES-256-GCM)");
    gtk_box_pack_start(GTK_BOX(box), app->encrypt_check, FALSE, FALSE, 0);

    GtkWidget *gen = gtk_button_new_with_label("Generate keypair…");
    gtk_style_context_add_class(gtk_widget_get_style_context(gen),
                                "suggested-action");
    g_signal_connect(gen, "clicked", G_CALLBACK(on_keygen), app);
    gtk_box_pack_start(GTK_BOX(box), gen, FALSE, FALSE, 0);

    app->keygen_status = gtk_label_new(
        "Pick an algorithm, then Generate keypair to choose where to save.");
    gtk_label_set_line_wrap(GTK_LABEL(app->keygen_status), TRUE);
    gtk_label_set_selectable(GTK_LABEL(app->keygen_status), TRUE);
    gtk_widget_set_halign(app->keygen_status, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), app->keygen_status, FALSE, FALSE, 0);

    return box;
}

/* ------------------------------------------------------------------ *
 *  UI construction
 * ------------------------------------------------------------------ */
static GtkWidget *build_sign_tab(App *app)
{
    GtkWidget *grid = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);

    /* key row */
    GtkWidget *keyrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *keylbl = gtk_label_new("Secret key:");
    app->key_chooser = gtk_file_chooser_button_new("Select secret key (.key)",
        GTK_FILE_CHOOSER_ACTION_OPEN);
    GtkFileFilter *kf = gtk_file_filter_new();
    gtk_file_filter_set_name(kf, "Secret keys (*.key)");
    gtk_file_filter_add_pattern(kf, "*.key");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(app->key_chooser), kf);
    gtk_box_pack_start(GTK_BOX(keyrow), keylbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(keyrow), app->key_chooser, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(grid), keyrow, FALSE, FALSE, 0);

    /* file list */
    app->files_store = gtk_list_store_new(1, G_TYPE_STRING);
    app->files_view =
        gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->files_store));
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col =
        gtk_tree_view_column_new_with_attributes("Files to sign", r,
                                                 "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(app->files_view), col);
    GtkTreeSelection *sel =
        gtk_tree_view_get_selection(GTK_TREE_VIEW(app->files_view));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_MULTIPLE);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_container_add(GTK_CONTAINER(scroll), app->files_view);
    gtk_box_pack_start(GTK_BOX(grid), scroll, TRUE, TRUE, 0);

    /* file buttons */
    GtkWidget *btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *add = gtk_button_new_with_label("Add files…");
    GtkWidget *rem = gtk_button_new_with_label("Remove selected");
    GtkWidget *clr = gtk_button_new_with_label("Clear");
    g_signal_connect(add, "clicked", G_CALLBACK(on_add_files), app);
    g_signal_connect(rem, "clicked", G_CALLBACK(on_remove_selected), app);
    g_signal_connect(clr, "clicked", G_CALLBACK(on_clear_files), app);
    gtk_box_pack_start(GTK_BOX(btns), add, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btns), rem, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btns), clr, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(grid), btns, FALSE, FALSE, 0);

    /* sign action */
    GtkWidget *sign = gtk_button_new_with_label("Sign all");
    gtk_style_context_add_class(gtk_widget_get_style_context(sign),
                                "suggested-action");
    g_signal_connect(sign, "clicked", G_CALLBACK(on_sign), app);
    gtk_box_pack_start(GTK_BOX(grid), sign, FALSE, FALSE, 0);

    app->sign_status = gtk_label_new("Choose a key, add files, then Sign all.");
    gtk_label_set_line_wrap(GTK_LABEL(app->sign_status), TRUE);
    gtk_widget_set_halign(app->sign_status, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(grid), app->sign_status, FALSE, FALSE, 0);

    return grid;
}

static GtkWidget *labeled_chooser(const char *label, const char *title,
                                  GtkWidget **out_chooser)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l = gtk_label_new(label);
    gtk_widget_set_size_request(l, 90, -1);
    gtk_widget_set_halign(l, GTK_ALIGN_START);
    *out_chooser = gtk_file_chooser_button_new(title,
        GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_box_pack_start(GTK_BOX(row), l, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), *out_chooser, TRUE, TRUE, 0);
    return row;
}

static GtkWidget *build_verify_tab(App *app)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 12);

    gtk_box_pack_start(GTK_BOX(box),
        labeled_chooser("Public key:", "Select public key (.pub)",
                        &app->pub_chooser), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box),
        labeled_chooser("File:", "Select the signed file",
                        &app->vfile_chooser), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box),
        labeled_chooser("Signature:", "Select .sig (optional)",
                        &app->sig_chooser), FALSE, FALSE, 0);

    GtkWidget *hint = gtk_label_new("Leave the signature blank to use "
                                    "<file>.sig.");
    gtk_widget_set_halign(hint, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), hint, FALSE, FALSE, 0);

    GtkWidget *verify = gtk_button_new_with_label("Verify");
    g_signal_connect(verify, "clicked", G_CALLBACK(on_verify), app);
    gtk_box_pack_start(GTK_BOX(box), verify, FALSE, FALSE, 0);

    app->verify_status = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(app->verify_status), TRUE);
    gtk_widget_set_halign(app->verify_status, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(box), app->verify_status, FALSE, FALSE, 0);

    return box;
}

static void on_about(GtkButton *btn, gpointer data)
{
    App *app = data;
    const char *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const char *features =
        "Sign and verify files with NIST's post-quantum signature "
        "standards — ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).\n"
        "\n"
        "• Sign one file or many at once, with detached .sig output\n"
        "• Verify signatures, with signer-fingerprint binding\n"
        "• Encrypted secret keys (Argon2id + AES-256-GCM), unlocked once\n"
        "• Streaming SHA-256 hashing — signs files of any size\n"
        "• Self-describing signatures, interchangeable with the CLI";

    gtk_show_about_dialog(GTK_WINDOW(app->window),
        "program-name", "PQ-Sign",
        "version", PQSIGN_VERSION,
        "comments", features,
        "authors", authors,
        "copyright", "© 2026 Jean-Francois Lachance-Caumartin",
        "license-type", GTK_LICENSE_MIT_X11,
        "logo-icon-name", "pq-sign",
        NULL);
    (void)btn;
}

static void activate(GtkApplication *gapp, gpointer data)
{
    App *app = data;
    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "PQ-Sign");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 560, 460);
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);
    /* Matches the installed hicolor icon + .desktop Icon= so the window
     * manager / taskbar shows our icon. */
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "pq-sign");

    /* Let the icon be found when running uninstalled from the build tree
     * (./pq-sign-gui before `make install`). Needs a screen, so it happens
     * here rather than in main(). Harmless if the data/ dir is absent. */
    GdkScreen *screen = gtk_widget_get_screen(app->window);
    if (screen) {
        GtkIconTheme *theme = gtk_icon_theme_get_for_screen(screen);
        if (theme) gtk_icon_theme_append_search_path(theme, "data");
    }

    /* Header bar carries the title and an About button. */
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "PQ-Sign");
    GtkWidget *about = gtk_button_new_with_label("About");
    g_signal_connect(about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), header);

    GtkWidget *nb = gtk_notebook_new();
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), build_keys_tab(app),
                             gtk_label_new("Keys"));
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), build_sign_tab(app),
                             gtk_label_new("Sign"));
    gtk_notebook_append_page(GTK_NOTEBOOK(nb), build_verify_tab(app),
                             gtk_label_new("Verify"));
    gtk_container_add(GTK_CONTAINER(app->window), nb);
    gtk_widget_show_all(app->window);
}

int main(int argc, char **argv)
{
    App app;
    memset(&app, 0, sizeof app);

    /* G_APPLICATION_NON_UNIQUE: allow several windows; HANDLES_OPEN so files
     * passed on the command line (from the .desktop %F) could be opened. */
    GtkApplication *gapp =
        gtk_application_new("org.pqsign.Gui", G_APPLICATION_NON_UNIQUE);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), &app);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
