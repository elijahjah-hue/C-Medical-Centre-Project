/* 
 * compress.c
 * Author: Benjamin Duncanson
 * Student Number: 25903802
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "compress.h"

void rle_compress(const char *input_path, const char *output_path) {
    if (!input_path || !output_path) {
        printf("Error: NULL argument passed to rle_compress.\n");
        return;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        printf("Error: cannot open input file '%s'.\n", input_path);
        return;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        printf("Error: cannot open output file '%s'.\n", output_path);
        fclose(in);
        return;
    }

    int current = fgetc(in);
    if (current == EOF) {
        #ifdef DEBUG
                printf("[DEBUG] rle_compress: input file is empty.\n");
        #endif
                fclose(in);
                fclose(out);
                return;
    }

    size_t input_bytes = 1;
    size_t output_bytes = 0;
    unsigned char run_byte = (unsigned char)current;
    unsigned char run_count = 1;

    int next;
    while ((next = fgetc(in)) != EOF) {
        input_bytes++;
        if ((unsigned char)next == run_byte && run_count < 255) {
            run_count++;
        } else {
            fputc(run_count, out);
            fputc(run_byte, out);
            output_bytes += 2;
            run_byte = (unsigned char)next;
            run_count = 1;
        }
    }
    
    fputc(run_count, out);
    fputc(run_byte, out);
    output_bytes += 2;

    #ifdef DEBUG
        printf("[DEBUG] rle_compress: input=%zu bytes output=%zu bytes ratio=%.2f%%\n",
            input_bytes, output_bytes,
            input_bytes > 0 ? (double)output_bytes / input_bytes * 100.0 : 0.0);
    #endif

    fclose(in);
    fclose(out);
}

void rle_decompress(const char *input_path, const char *output_path) {
    if (!input_path || !output_path) {
        printf("Error: NULL argument passed to rle_decompress.\n");
        return;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        printf("Error: cannot open input file '%s'.\n", input_path);
        return;
    }

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        printf("Error: cannot open output file '%s'.\n", output_path);
        fclose(in);
        return;
    }

    int count_byte, val_byte;
    size_t output_bytes = 0;

    while ((count_byte = fgetc(in)) != EOF) {
        val_byte = fgetc(in);
        if (val_byte == EOF) {
            printf("Error: malformed RLE data — odd byte count.\n");
            break;
        }
        unsigned char count = (unsigned char)count_byte;
        unsigned char val = (unsigned char)val_byte;
        unsigned char i;
        for (i = 0; i < count; i++) {
            fputc(val, out);
            output_bytes++;
        }
    }

    #ifdef DEBUG
        printf("[DEBUG] rle_decompress: output=%zu bytes\n", output_bytes);
    #endif

    fclose(in);
    fclose(out);
}
