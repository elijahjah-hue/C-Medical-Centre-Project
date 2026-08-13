/*
 * search.h
 * Author: Malachi Evans
 * Student Number: 26344655
 */
#ifndef SEARCH_H
#define SEARCH_H

#include "vault.h"

/*
 * search_vault
 * Searches all vault files for a keyword.
 * File list is provided by the caller via vault_get_files().
 * For each file: decrypts, verifies magic bytes, decompresses,
 * searches line by line. Files with wrong password are silently skipped.
 * Parameters:
 *   files    - array of vault filenames (basenames, no path)
 *   count    - number of entries in files[]
 *   keyword  - null-terminated string to search for (case-sensitive)
 *   password - null-terminated password string for decryption
 */
void search_vault(char files[][MAX_FILENAME],
                  int count,
                  const char *keyword,
                  const char *password);

/*
 * sort_files_by_name
 * Sorts files[][] in ascending alphabetical order using insertion sort.
 * Parameters:
 *   files - array of filenames to sort in place
 *   count - number of entries
 */
void sort_files_by_name(char files[][MAX_FILENAME], int count);

/*
 * sort_files_by_size
 * Sorts files[][] in ascending file size order using insertion sort.
 * File sizes retrieved via fseek/ftell (stdio only).
 * Parameters:
 *   files - array of filenames to sort in place
 *   count - number of entries
 */
void sort_files_by_size(char files[][MAX_FILENAME], int count);

#endif /* SEARCH_H */
