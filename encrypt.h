/* encrypt.h */
/* AUTHOR: Elijah Placer
   STUDENT ID: 26084133 */

   
#ifndef ENCRYPT_H
#define ENCRYPT_H

/*
 * xor_encrypt
 * Encrypts a file using XOR cipher with a given password.
 * Parameters:
 *   input_path  - path to the plaintext input file
 *   output_path - path to write the encrypted output file
 *   password    - null-terminated password string
 * Returns: 0 on success, -1 on error
 */
int xor_encrypt(const char *input_path, const char *output_path, const char *password);

/*
 * xor_decrypt
 * Decrypts a file encrypted with xor_encrypt using the same password.
 * Parameters:
 *   input_path  - path to the encrypted input file
 *   output_path - path to write the decrypted output file
 *   password    - null-terminated password string
 * Returns: 0 on success, -1 on error
 */
int xor_decrypt(const char *input_path, const char *output_path, const char *password);

#endif /* ENCRYPT_H */
