/* 
 * vault.c
 * Author: Benjamin Duncanson
 * Student Number: 25903802
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vault.h"
#include "encrypt.h"
#include "compress.h"
#include "search.h"
#include "history.h"

/* Magic bytes must match those in encrypt.c */
static const unsigned char MAGIC[4] = {0x53, 0x56, 0x4C, 0x54}; /* "SVLT" */

/* Index file path — one vault filename per line */
#define INDEX_FILE VAULT_DIR "/index.txt"

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

void vault_init(void) {
    FILE *f = fopen(INDEX_FILE, "ab");
    if (f) {
        fclose(f);
#ifdef DEBUG
        printf("[DEBUG] vault_init: vault directory ready\n");
#endif
    } else {
        #ifdef _WIN32
                system("mkdir vault");
        #else
                system("mkdir -p vault");
        #endif
                f = fopen(INDEX_FILE, "ab");
                if (f) fclose(f);
                else printf("Error: could not create vault directory.\n");
    }
}

static void make_vault_path(const char *filename, char *out, size_t out_size) {
    const char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;
    snprintf(out, out_size, "%s/%s.vault", VAULT_DIR, base);
}

static long long file_size(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long long size = ftell(fp);
    fclose(fp);
    return size;
}

/*
 * index_add
 * Appends a vault filename to the index file.
 * Checks for duplicates first to avoid repeated entries.
 */
static void index_add(const char *vault_filename) {
    FILE *f = fopen(INDEX_FILE, "r");
    if (f) {
        char line[MAX_FILENAME];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            if (strcmp(line, vault_filename) == 0) {
                fclose(f);
                return; 
            }
        }
        fclose(f);
    }
    /* Append */
    f = fopen(INDEX_FILE, "a");
    if (f) {
        fprintf(f, "%s\n", vault_filename);
        fclose(f);
    }
}

/*
 * index_remove
 * Removes a vault filename from the index file.
 * Rewrites the file without the matching line.
 */
static void index_remove(const char *vault_filename) {
    char tmp_path[MAX_FILENAME];
    snprintf(tmp_path, sizeof(tmp_path), "%s/.index_tmp.txt", VAULT_DIR);

    FILE *in = fopen(INDEX_FILE, "r");
    FILE *out = fopen(tmp_path, "w");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return;
    }

    char line[MAX_FILENAME];
    while (fgets(line, sizeof(line), in)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, vault_filename) != 0) {
            fprintf(out, "%s\n", line);
        }
    }

    fclose(in);
    fclose(out);

    remove(INDEX_FILE);
    rename(tmp_path, INDEX_FILE);
}

/*
 * index_load
 * Reads all vault filenames from the index into files[][].
 * Returns the number of entries loaded.
 */
static int index_load(char files[][MAX_FILENAME], int max) {
    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) return 0;

    int count = 0;
    char line[MAX_FILENAME];
    while (count < max && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;
        strncpy(files[count], line, MAX_FILENAME - 1);
        files[count][MAX_FILENAME - 1] = '\0';
        count++;
    }
    fclose(f);
    return count;
}

/*
 * check_magic
 * Reads first 4 bytes of decrypted_path.
 * Returns 1 if SVLT magic matches, writes remainder to stripped_path.
 * Returns 0 and deletes decrypted_path if magic fails.
 */
static int check_magic(const char *decrypted_path, const char *stripped_path) {
    FILE *in = fopen(decrypted_path, "rb");
    if (!in) return 0;

    unsigned char header[4];
    if (fread(header, 1, 4, in) < 4) {
        fclose(in);
        remove(decrypted_path);
        return 0;
    }

    if (header[0] != MAGIC[0] || header[1] != MAGIC[1] ||
        header[2] != MAGIC[2] || header[3] != MAGIC[3]) {
        fclose(in);
        remove(decrypted_path);
        return 0;
    }

    FILE *out = fopen(stripped_path, "wb");
    if (!out) {
        fclose(in);
        return 0;
    }

    unsigned char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, out);
    }

    fclose(in);
    fclose(out);
    return 1;
}

void vault_store(const char *filename, const char *password) {
    if (!filename || strlen(filename) == 0) {
        printf("Error: filename is empty.\n");
        return;
    }

    FILE *test = fopen(filename, "rb");
    if (!test) {
        printf("Error: file '%s' not found.\n", filename);
        return;
    }
    fclose(test);

    vault_init();

    char tmp_compressed[MAX_FILENAME];
    char vault_path[MAX_FILENAME];
    snprintf(tmp_compressed, sizeof(tmp_compressed), "%s/.tmp_compress.tmp", VAULT_DIR);
    make_vault_path(filename, vault_path, sizeof(vault_path));

    /* Duplicate check */
    FILE *existing = fopen(vault_path, "rb");
    if (existing) {
        fclose(existing);
        char resp[8];
        printf("Warning: '%s' already exists in vault. Overwrite? (y/n): ", vault_path);
        if (!fgets(resp, sizeof(resp), stdin)) return;
        if (resp[0] != 'y' && resp[0] != 'Y') {
            printf("Cancelled.\n");
            return;
        }
    }

    printf("Compressing '%s'...\n", filename);
    rle_compress(filename, tmp_compressed);

    printf("Encrypting...\n");
    xor_encrypt(tmp_compressed, vault_path, password);

    remove(tmp_compressed);

    /* Verify vault file was created */
    FILE *verify = fopen(vault_path, "rb");
    if (!verify) {
        printf("Error: vault file was not created. Store failed.\n");
        return;
    }
    fclose(verify);

    /* Record in index, store basename only */
    const char *base = strrchr(vault_path, '/');
    base = base ? base + 1 : vault_path;
    index_add(base);

    printf("Stored '%s' -> '%s'\n", filename, vault_path);
    history_add(vault_path);

    #ifdef DEBUG
        printf("[DEBUG] vault_store: vault file size = %lld bytes\n",
            file_size(vault_path));
    #endif
}

void vault_retrieve(const char *filename, const char *password) {
    if (!filename || strlen(filename) == 0) {
        printf("Error: filename is empty.\n");
        return;
    }

    char vault_path[MAX_FILENAME];
    if (strstr(filename, ".vault") != NULL) {
        snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, filename);
    } else {
        make_vault_path(filename, vault_path, sizeof(vault_path));
    }

    FILE *test = fopen(vault_path, "rb");
    if (!test) {
        printf("Error: '%s' not found in vault.\n", filename);
        return;
    }
    fclose(test);

    /* Strip .vault to get output name */
    char output_name[MAX_FILENAME];
    const char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;
    strncpy(output_name, base, sizeof(output_name) - 1);
    output_name[sizeof(output_name) - 1] = '\0';
    char *ext = strstr(output_name, ".vault");
    if (ext) *ext = '\0';

    char tmp_decrypted[MAX_FILENAME];
    char tmp_stripped[MAX_FILENAME];
    snprintf(tmp_decrypted, sizeof(tmp_decrypted), "%s/.tmp_decrypt.tmp",  VAULT_DIR);
    snprintf(tmp_stripped, sizeof(tmp_stripped), "%s/.tmp_stripped.tmp", VAULT_DIR);

    printf("Decrypting...\n");
    xor_decrypt(vault_path, tmp_decrypted, password);

    if (!check_magic(tmp_decrypted, tmp_stripped)) {
        printf("Error: incorrect password. File not retrieved.\n");
        remove(tmp_decrypted);
        return;
    }
    remove(tmp_decrypted);

    printf("Decompressing -> '%s'...\n", output_name);
    rle_decompress(tmp_stripped, output_name);
    remove(tmp_stripped);

    FILE *verify = fopen(output_name, "rb");
    if (!verify) {
        printf("Error: output file was not created.\n");
        return;
    }
    fclose(verify);

    printf("Retrieved '%s'\n", output_name);
    history_add(vault_path);
}

/*
 * vault_compress_only
 * Compresses filename to <stem>_compressed.txt in the current directory.
 * Does not encrypt or vault. Prints size comparison.
 */
void vault_compress_only(const char *filename) {
    if (!filename || strlen(filename) == 0) {
        printf("Error: filename is empty.\n");
        return;
    }

    FILE *test = fopen(filename, "rb");
    if (!test) {
        printf("Error: file '%s' not found.\n", filename);
        return;
    }
    fclose(test);

    const char *base = strrchr(filename, '/');
    base = base ? base + 1 : filename;

    char stem[MAX_FILENAME];
    strncpy(stem, base, sizeof(stem) - 1);
    stem[sizeof(stem) - 1] = '\0';
    char *dot = strrchr(stem, '.');
    if (dot) *dot = '\0';

    char out_path[MAX_FILENAME + 16];
    snprintf(out_path, sizeof(out_path), "%s_compressed.txt", stem);

    FILE *existing = fopen(out_path, "rb");
    if (existing) {
        fclose(existing);
        char resp[8];
        printf("Warning: '%s' already exists. Overwrite? (y/n): ", out_path);
        if (!fgets(resp, sizeof(resp), stdin)) return;
        if (resp[0] != 'y' && resp[0] != 'Y') {
            printf("Cancelled.\n");
            return;
        }
    }

    printf("Compressing '%s' -> '%s'...\n", filename, out_path);
    rle_compress(filename, out_path);

    long long in_size = file_size(filename);
    long long out_size = file_size(out_path);

    if (in_size >= 0 && out_size >= 0) {
        printf("Done. Original: %lld bytes  Compressed: %lld bytes  (%.1f%% of original)\n",
               in_size, out_size,
               in_size > 0 ? (double)out_size / in_size * 100.0 : 0.0);
    } else {
        printf("Compressed file saved as '%s'\n", out_path);
    }
}

/*
 * vault_delete
 * Verifies password via magic bytes before deleting vault file.
 * Also removes entry from index.
 */
void vault_delete(const char *filename, const char *password) {
    if (!filename || strlen(filename) == 0) {
        printf("Error: filename is empty.\n");
        return;
    }

    char vault_path[MAX_FILENAME];
    if (strstr(filename, ".vault") != NULL) {
        snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, filename);
    } else {
        make_vault_path(filename, vault_path, sizeof(vault_path));
    }

    FILE *test = fopen(vault_path, "rb");
    if (!test) {
        printf("Error: '%s' not found in vault.\n", filename);
        return;
    }
    fclose(test);

    char tmp_dec[MAX_FILENAME], tmp_stripped[MAX_FILENAME];
    snprintf(tmp_dec, sizeof(tmp_dec), "%s/.tmp_del_dec.tmp", VAULT_DIR);
    snprintf(tmp_stripped, sizeof(tmp_stripped),  "%s/.tmp_del_stripped.tmp", VAULT_DIR);

    xor_decrypt(vault_path, tmp_dec, password);

    if (!check_magic(tmp_dec, tmp_stripped)) {
        printf("Error: incorrect password. File not deleted.\n");
        remove(tmp_dec);
        return;
    }
    remove(tmp_dec);
    remove(tmp_stripped);

    if (remove(vault_path) == 0) {
        /* Remove from index */
        const char *base = strrchr(vault_path, '/');
        base = base ? base + 1 : vault_path;
        index_remove(base);
        printf("Deleted '%s' from vault.\n", vault_path);
    } else {
        printf("Error: could not delete '%s'.\n", vault_path);
    }
}

/*
 * vault_list
 * Lists vault files sorted by name or size.
 * Reads file list from index — no dirent required.
 */
void vault_list(const char *sort_by) {
    char files[256][MAX_FILENAME];
    int count = index_load(files, 256);

    if (count == 0) {
        printf("Vault is empty.\n");
        return;
    }

    if (sort_by && strcmp(sort_by, "size") == 0) {
        sort_files_by_size(files, count);
    } else {
        sort_files_by_name(files, count);
    }

    printf("\n=== Vault Contents (sorted by %s) ===\n",
           sort_by ? sort_by : "name");

    int i;
    for (i = 0; i < count; i++) {
        char full_path[MAX_FILENAME + 8];
        snprintf(full_path, sizeof(full_path), "%s/%s", VAULT_DIR, files[i]);
        long long size = file_size(full_path);
        printf("  %-40s %lld bytes\n", files[i], size >= 0 ? size : 0);
    }
}

/*
 * vault_get_files
 * Loads the vault index into the provided array.
 * Used by main.c to pass file list to search_vault.
 * Returns the number of files loaded.
 */
int vault_get_files(char files[][MAX_FILENAME], int max) {
    return index_load(files, max);
}
