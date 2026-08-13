/* 
 * search.c
 * Author: Malachi Evans
 * Student Number: 26344655
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "search.h"
#include "encrypt.h"
#include "compress.h"
#include "vault.h"

/*
 * search_vault
 * Searches all vault files for a keyword.
 * File list is provided by the caller (built from vault index).
 * Uses only stdio — no dirent.h or sys/stat.h.
 */
void search_vault(char files[][MAX_FILENAME],
                  int count,
                  const char *keyword,
                  const char *password)
{
    if (keyword == NULL || strlen(keyword) == 0) {
        printf("Error: keyword is empty.\n");
        return;
    }

    int found_any = 0;
    int i;

    for (i = 0; i < count; i++) {

        char vault_path[MAX_FILENAME];
        char tmp_dec[MAX_FILENAME];
        char tmp_strip[MAX_FILENAME];
        char tmp_plain[MAX_FILENAME];

        snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, files[i]);
        snprintf(tmp_dec, sizeof(tmp_dec), "%s/.srch_dec.tmp", VAULT_DIR);
        snprintf(tmp_strip, sizeof(tmp_strip), "%s/.srch_strip.tmp", VAULT_DIR);
        snprintf(tmp_plain, sizeof(tmp_plain), "%s/.srch_plain.tmp", VAULT_DIR);

        xor_decrypt(vault_path, tmp_dec, password);

        FILE *dec_f = fopen(tmp_dec, "rb");
        if (dec_f == NULL) continue;

        unsigned char header[4];
        int magic_ok = 0;

        if (fread(header, 1, 4, dec_f) == 4) {
            if (header[0] == 0x53 && header[1] == 0x56 &&
                header[2] == 0x4C && header[3] == 0x54) {
                magic_ok = 1;
            }
        }

        if (!magic_ok) {
            fclose(dec_f);
            remove(tmp_dec);
            continue;
        }

        FILE *strip_f = fopen(tmp_strip, "wb");
        if (strip_f == NULL) {
            fclose(dec_f);
            remove(tmp_dec);
            continue;
        }

        unsigned char buffer[1024];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), dec_f)) > 0) {
            fwrite(buffer, 1, bytes_read, strip_f);
        }
        fclose(dec_f);
        fclose(strip_f);
        remove(tmp_dec);

        rle_decompress(tmp_strip, tmp_plain);
        remove(tmp_strip);

        FILE *plain_f = fopen(tmp_plain, "r");
        if (plain_f == NULL) {
            remove(tmp_plain);
            continue;
        }

        char line[1024];
        int line_no = 0;
        int file_printed = 0;

        while (fgets(line, sizeof(line), plain_f)) {
            line_no++;
            if (strstr(line, keyword) != NULL) {
                if (!file_printed) {
                    printf("\n[%s]\n", files[i]);
                    file_printed = 1;
                    found_any = 1;
                }
                line[strcspn(line, "\n")] = '\0';
                printf("  Line %d: %s\n", line_no, line);
            }
        }

        fclose(plain_f);
        remove(tmp_plain);

#ifdef DEBUG
        if (file_printed) {
            printf("[DEBUG] search_vault: matched in '%s'\n", files[i]);
        }
#endif
    }

    if (!found_any) {
        printf("No matches found for '%s'.\n", keyword);
    }
}

/*
 * get_file_size
 * Returns file size using only stdio (fseek/ftell).
 */
static long long get_file_size(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return -1;
    fseek(fp, 0, SEEK_END);
    long long size = ftell(fp);
    fclose(fp);
    return size;
}

/*
 * sort_files_by_name
 * Insertion sort — ascending alphabetical order.
 */
void sort_files_by_name(char files[][MAX_FILENAME], int count)
{
    int i;
    for (i = 1; i < count; i++) {
        char key[MAX_FILENAME];
        strncpy(key, files[i], MAX_FILENAME - 1);
        key[MAX_FILENAME - 1] = '\0';
        int j = i - 1;
        while (j >= 0 && strcmp(files[j], key) > 0) {
            strncpy(files[j + 1], files[j], MAX_FILENAME - 1);
            files[j + 1][MAX_FILENAME - 1] = '\0';
            j--;
        }
        strncpy(files[j + 1], key, MAX_FILENAME - 1);
        files[j + 1][MAX_FILENAME - 1] = '\0';
    }
}

/*
 * sort_files_by_size
 * Insertion sort — ascending file size order.
 * Uses get_file_size() (stdio only, no sys/stat.h).
 */
void sort_files_by_size(char files[][MAX_FILENAME], int count)
{
    int i;
    for (i = 1; i < count; i++) {
        char key[MAX_FILENAME];
        strncpy(key, files[i], MAX_FILENAME - 1);
        key[MAX_FILENAME - 1] = '\0';

        char key_path[MAX_FILENAME + 8];
        snprintf(key_path, sizeof(key_path), "%s/%s", VAULT_DIR, key);
        long long key_size = get_file_size(key_path);

        int j = i - 1;
        while (j >= 0) {
            char cmp_path[MAX_FILENAME];
            snprintf(cmp_path, sizeof(cmp_path), "%s/%s", VAULT_DIR, files[j]);
            long long cmp_size = get_file_size(cmp_path);
            if (cmp_size <= key_size) break;
            strncpy(files[j + 1], files[j], MAX_FILENAME - 1);
            files[j + 1][MAX_FILENAME - 1] = '\0';
            j--;
        }
        strncpy(files[j + 1], key, MAX_FILENAME - 1);
        files[j + 1][MAX_FILENAME - 1] = '\0';
    }
}
