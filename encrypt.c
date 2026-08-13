/* 
 * encrypt.c
 * Author: Elijah Placer
 * Student Number: 26084133
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encrypt.h"

/* Magic bytes written before plaintext at store time.
 * vault_retrieve checks for these after decryption to verify
 * the password was correct. */
static const unsigned char MAGIC[4] = {0x53, 0x56, 0x4C, 0x54}; /* "SVLT" */

/* Internal helper: shared XOR logic for encrypt and decrypt. */
static int xor_process(const char *input_path, const char *output_path, const char *password) {
    if (!input_path || !output_path || !password) {
        printf("Error: NULL argument passed to xor_process.\n");
        return -1;
    }

    size_t pass_len = strlen(password);
    if (pass_len == 0) {
        printf("Error: password must not be empty.\n");
        return -1;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        printf("Error: cannot open input file '%s'.\n", input_path);
        return -1;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        printf("Error: cannot open output file '%s'.\n", output_path);
        fclose(in);
        return -1;
    }

    unsigned char buffer[1024];
    size_t bytes_read;
    size_t key_pos = 0;
    size_t total = 0;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        size_t i;
        for (i = 0; i < bytes_read; i++) {
            buffer[i] ^= (unsigned char)password[key_pos % pass_len];
            key_pos++;
        }
        fwrite(buffer, 1, bytes_read, out);
        total += bytes_read;
    }

#ifdef DEBUG
    printf("[DEBUG] xor_process: input='%s' output='%s' pass_len=%zu bytes_processed=%zu\n",
           input_path, output_path, pass_len, total);
#endif

    fclose(in);
    fclose(out);
    return 0;
}

/*
 * xor_encrypt
 * Prepends 4 magic bytes ("SVLT") to the plaintext before encrypting.
 * This allows vault_retrieve to detect a wrong password after decryption.
 */
int xor_encrypt(const char *input_path, const char *output_path, const char *password) {
    if (!input_path || !output_path || !password) {
        printf("Error: NULL argument passed to xor_encrypt.\n");
        return -1;
    }

    size_t pass_len = strlen(password);
    if (pass_len == 0) {
        printf("Error: password must not be empty.\n");
        return -1;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        printf("Error: cannot open input file '%s'.\n", input_path);
        return -1;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        printf("Error: cannot open output file '%s'.\n", output_path);
        fclose(in);
        return -1;
    }

    unsigned char buffer[1024];
    size_t bytes_read;
    size_t key_pos = 0;
    size_t total = 0;

    unsigned char magic_enc[4];
    size_t i;
    for (i = 0; i < 4; i++) {
        magic_enc[i] = MAGIC[i] ^ (unsigned char)password[key_pos % pass_len];
        key_pos++;
    }
    fwrite(magic_enc, 1, 4, out);
    total += 4;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        for (i = 0; i < bytes_read; i++) {
            buffer[i] ^= (unsigned char)password[key_pos % pass_len];
            key_pos++;
        }
        fwrite(buffer, 1, bytes_read, out);
        total += bytes_read;
    }

#ifdef DEBUG
    printf("[DEBUG] xor_encrypt: input='%s' output='%s' pass_len=%zu bytes_written=%zu\n",
           input_path, output_path, pass_len, total);
#endif

    fclose(in);
    fclose(out);
    return 0;
}

/*
 * xor_decrypt
 * Decrypts the file. Does NOT strip magic bytes — vault_retrieve handles
 * that so it can check them for password verification.
 */
int xor_decrypt(const char *input_path, const char *output_path, const char *password) {
    int result = xor_process(input_path, output_path, password);

    #ifdef DEBUG
        if (result == 0) {
            printf("[DEBUG] xor_decrypt: done — '%s' -> '%s'\n", input_path, output_path);
        }
    #endif

    return result;
}
