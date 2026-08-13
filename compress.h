/* 
 * Function: compress.h
 * Author: Benjamin Duncanson
 * Student Number: 25903802
 */

#ifndef COMPRESS_H
#define COMPRESS_H

/*
 * rle_compress
 * Compresses input_path using Run Length Encoding, writes to output_path.
 * Consecutive identical bytes are replaced with a count and the byte value.
 * Parameters:
 *   input_path - path to the file to compress
 *   output_path - path to write the compressed output
 */
void rle_compress(const char *input_path, const char *output_path);

/*
 * rle_decompress
 * Decompresses a file produced by rle_compress, writes to output_path.
 * Parameters:
 *   input_path - path to the compressed file
 *   output_path - path to write the decompressed output
 */
void rle_decompress(const char *input_path, const char *output_path);

#endif /* COMPRESS_H */
