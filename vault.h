/* 
 vault.h
 Author: Ben Duncanson 2590 3802
*/
#ifndef VAULT_H
#define VAULT_H

#define VAULT_DIR "vault"
#define MAX_FILENAME 256

/*
 * vault_init
 * Creates the vault directory and index file if they do not exist.
 * Must be called once at program startup before any other vault functions.
 */
void vault_init(void);

/*
 * vault_store
 * Compresses then encrypts filename, storing the result in the vault
 * directory with a .vault extension. A 4-byte magic header ("SVLT") is
 * prepended to the plaintext before encryption, enabling password
 * verification on retrieval. Records the filename in vault/index.txt.
 * Parameters:
 *   filename - path to the plaintext file to store
 *   password - null-terminated password string for encryption
 */
void vault_store(const char *filename, const char *password);

/*
 * vault_retrieve
 * Decrypts and decompresses a vault file, writing the result to the
 * current directory. Checks the first 4 bytes for the magic header
 * "SVLT" after decryption — if absent the password was wrong, the
 * garbage output is deleted and an error is printed.
 * Parameters:
 *   filename - name of the file inside the vault (with or without .vault)
 *   password - null-terminated password string for decryption
 */
void vault_retrieve(const char *filename, const char *password);

/*
 * vault_compress_only
 * Compresses filename using RLE, writing the result to
 * <stem>_compressed.txt in the current directory. Does not encrypt
 * or store in the vault. Prints original and compressed byte sizes.
 * Parameters:
 *   filename - path to the plaintext file to compress
 */
void vault_compress_only(const char *filename);

/*
 * vault_delete
 * Deletes a .vault file from the vault directory and removes it from
 * the index. Verifies the password via magic header before deletion.
 * Parameters:
 *   filename - name of the file to delete (with or without .vault)
 *   password - null-terminated password string for verification
 */
void vault_delete(const char *filename, const char *password);

/*
 * vault_list
 * Lists all .vault files in the vault sorted by the given criterion.
 * Reads the file list from vault/index.txt — no dirent required.
 * Parameters:
 *   sort_by - "name" to sort alphabetically, "size" to sort by file size
 */
void vault_list(const char *sort_by);

/*
 * vault_get_files
 * Loads the vault index into files[][MAX_FILENAME].
 * Used by main.c to pass the file list to search_vault.
 * Returns the number of files loaded.
 * Parameters:
 *   files - output array to populate
 *   max   - maximum number of entries to load
 */
int vault_get_files(char files[][MAX_FILENAME], int max);

#endif /* VAULT_H */
