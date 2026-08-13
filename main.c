/*
 * main.c
 * Group: Wed_9am_08
 * Lab: Wednesday 9:00am
 *
 * Authors: Malachi Evans -- 26344655
 *          Benjamin Duncanson -- 25903802
 *          Lishai Rubinstein -- 24958264
 *          Elijah Placer -- 26084133
 *
 * =============================================================
 * COMPILE INSTRUCTIONS
 * =============================================================
 *
 * Release build:
 *   make
 *   or: gcc -Wall -Wextra -std=c11 -o securevault \
 *           main.c vault.c encrypt.c compress.c search.c history.c
 *
 * Debug build (enables [DEBUG] diagnostic output):
 *   make debug
 *   or: gcc -Wall -Wextra -std=c11 -DDEBUG -o securevault \
 *           main.c vault.c encrypt.c compress.c search.c history.c
 *
 * =============================================================
 * MARKING GUIDE — HOW TO VERIFY EACH RUBRIC CRITERION
 * =============================================================
 * Use password "test123" for all tests below.
 *
 * --- STEP 1: Create a test file ---
 *   echo "Patient: John Smith DOB 01/01/1980 Condition: Diabetes" > patient.txt
 *
 * --- STEP 2: Encryption & decryption (XOR cipher) ---
 *   ./securevault -e patient.txt test123
 *   # Verifies: file compressed and encrypted, stored in vault/
 *   rm patient.txt
 *   ./securevault -d patient.txt test123
 *   # Verifies: file decrypted and decompressed, contents match original
 *   cat patient.txt
 *
 * --- STEP 3: Wrong password rejection (magic byte verification) ---
 *   ./securevault -d patient.txt wrongpass
 *   # Verifies: "Error: incorrect password" — no garbage file written
 *
 * --- STEP 4: RLE compression (separate from encryption) ---
 *   python3 -c "print('A'*200)" > repetitive.txt
 *   ./securevault -c repetitive.txt
 *   # Verifies: compression ratio printed (201 bytes -> 4 bytes, ~2%)
 *   # Output saved as repetitive_compressed.txt in working directory
 *
 * --- STEP 5: Keyword search ---
 *   ./securevault -s Patient test123
 *   # Verifies: finds matching line in patient.txt.vault, prints line number
 *
 * --- STEP 6: Vault listing with sort ---
 *   ./securevault -l name
 *   ./securevault -l size
 *   # Verifies: all vault files listed, sorted alphabetically / by size
 *
 * --- STEP 7: Delete with password verification ---
 *   ./securevault -x patient.txt wrongpass
 *   # Verifies: "Error: incorrect password. File not deleted."
 *   ./securevault -x patient.txt test123
 *   # Verifies: file deleted from vault
 *
 * --- STEP 8: Multiple files (batch mode) ---
 *   echo "File one" > a.txt && echo "File two" > b.txt
 *   ./securevault -e a.txt b.txt test123
 *   # Verifies: both files stored in vault
 *
 * --- STEP 9: Interactive mode (linked list history + full menu) ---
 *   ./securevault
 *   # Select option 1b to encrypt an existing file
 *   # Select option 6 to view recent files (linked list queue, max 5)
 *   # Select option 5 to list vault, select option 4 to search
 *   # Select option 3 to compress only
 *   # Select option 7 to delete
 *
 * --- STEP 10: Input validation (wrong data types) ---
 *   ./securevault
 *   # At menu: type "abc" -> "Invalid input. Please enter a number..."
 *   # At menu: type "99" -> "Invalid choice. Please enter 1-9."
 *   # At filename prompt: press Enter -> "Error: filename cannot be empty."
 *   # At password prompt: press Enter 3x -> "Error: too many empty attempts."
 *
 * --- STEP 11: Debug mode ---
 *   make debug
 *   ./securevault -e patient.txt test123
 *   # Verifies: [DEBUG] lines printed showing compression ratio,
 *   #           bytes processed, vault file size
 *   make        (rebuild release — no [DEBUG] output)
 *
 * =============================================================
 * BATCH MODE REFERENCE
 * =============================================================
 *   ./securevault -e <file> [files...] <password>  -->  Encrypt and store
 *   ./securevault -d <file> <password>  -->  Decrypt and retrieve
 *   ./securevault -s <keyword> <password>  -->  Search vault
 *   ./securevault -l name|size  -->  List vault (sorted)
 *   ./securevault -c <file>  -->  Compress only
 *   ./securevault -x <file> <password>  -->  Delete from vault
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vault.h"
#include "encrypt.h"
#include "compress.h"
#include "search.h"
#include "history.h"

static void print_usage(void) {
    printf("Usage:\n");
    printf("  ./securevault                                 Interactive mode\n");
    printf("  ./securevault -e <file> <password>            Encrypt and store\n");
    printf("  ./securevault -e <file1> <file2> <password>   Encrypt multiple files\n");
    printf("  ./securevault -d <file> <password>            Decrypt and retrieve\n");
    printf("  ./securevault -s <keyword> <password>         Search vault\n");
    printf("  ./securevault -l name|size                    List vault files\n");
    printf("  ./securevault -c <file>                       Compress file only\n");
    printf("  ./securevault -x <file> <password>            Delete from vault\n");
    printf("  Compile with -DDEBUG for debug output.\n");
}

static int create_file(const char *filename) {
    FILE *f;
    char line[1024];

    f = fopen(filename, "rb");
    if (f) {
        fclose(f);
        printf("Warning: '%s' already exists. Overwrite? (y/n): ", filename);
        if (!fgets(line, sizeof(line), stdin)) return 0;
        if (line[0] != 'y' && line[0] != 'Y') {
            printf("Cancelled.\n");
            return 0;
        }
    }

    f = fopen(filename, "w");
    if (!f) {
        printf("Error: could not create file '%s'.\n", filename);
        return 0;
    }

    printf("Enter text content. Type 'END' on a new line when finished:\n");
    while (1) {
        if (!fgets(line, sizeof(line), stdin)) break;
        if (strcmp(line, "END\n") == 0 || strcmp(line, "END") == 0) break;
        fputs(line, f);
    }

    fclose(f);
    printf("File '%s' created.\n", filename);
    return 1;
}

static int read_password(char *password, size_t size) {
    int attempts = 0;
    while (attempts < 3) {
        printf("Password: ");
        if (!fgets(password, (int)size, stdin)) return 0;
        password[strcspn(password, "\n")] = '\0';
        if (strlen(password) > 0) return 1;
        printf("Error: password cannot be empty.\n");
        attempts++;
    }
    printf("Error: too many empty password attempts.\n");
    return 0;
}

static void run_interactive(void) {
    char input[16];

    while (1) {
        printf("\n=== SecureVault ===\n");
        printf("1. Encrypt and store file\n");
        printf("2. Decrypt and retrieve file\n");
        printf("3. Compress file only\n");
        printf("4. Search vault\n");
        printf("5. List vault files\n");
        printf("6. View recent files\n");
        printf("7. Delete file from vault\n");
        printf("8. Encrypt and store multiple files\n");
        printf("9. Exit\n");
        printf("Enter choice (1-9): ");

        if (!fgets(input, sizeof(input), stdin)) break;

        char *endptr;
        long val = strtol(input, &endptr, 10);
        if (endptr == input || (*endptr != '\n' && *endptr != '\0')) {
            printf("Invalid input. Please enter a number between 1 and 9.\n");
            continue;
        }
        int choice = (int)val;

        char filename[256], password[256], keyword[256], sort_by[16];

        switch (choice) {
            case 1: {
                char sub_input[8];
                printf("\na) Create new file\n");
                printf("b) Use existing file\n");
                printf("c) Compress existing file first, then store\n");
                printf("Enter choice (a/b/c): ");
                if (!fgets(sub_input, sizeof(sub_input), stdin)) break;

                if (sub_input[0] == 'a' || sub_input[0] == 'A') {
                    printf("Enter filename to create: ");
                    if (!fgets(filename, sizeof(filename), stdin)) break;
                    filename[strcspn(filename, "\n")] = '\0';
                    if (strlen(filename) == 0) { printf("Error: filename cannot be empty.\n"); break; }
                    if (create_file(filename) == 0) break;
                    if (!read_password(password, sizeof(password))) break;
                    vault_store(filename, password);
                    history_add(filename);

                } else if (sub_input[0] == 'b' || sub_input[0] == 'B') {
                    printf("Filename to encrypt: ");
                    if (!fgets(filename, sizeof(filename), stdin)) break;
                    filename[strcspn(filename, "\n")] = '\0';
                    if (strlen(filename) == 0) { printf("Error: filename cannot be empty.\n"); break; }
                    FILE *check = fopen(filename, "rb");
                    if (!check) { printf("Error: file '%s' not found.\n", filename); break; }
                    fclose(check);
                    if (!read_password(password, sizeof(password))) break;
                    vault_store(filename, password);
                    history_add(filename);

                } else if (sub_input[0] == 'c' || sub_input[0] == 'C') {
                    printf("Filename to compress: ");
                    if (!fgets(filename, sizeof(filename), stdin)) break;
                    filename[strcspn(filename, "\n")] = '\0';
                    if (strlen(filename) == 0) { printf("Error: filename cannot be empty.\n"); break; }
                    FILE *check = fopen(filename, "rb");
                    if (!check) { printf("Error: file '%s' not found.\n", filename); break; }
                    fclose(check);

                    vault_compress_only(filename);

                    char store_resp[8];
                    printf("Store compressed file in vault? (y/n): ");
                    if (!fgets(store_resp, sizeof(store_resp), stdin)) break;
                    if (store_resp[0] == 'y' || store_resp[0] == 'Y') {
                        const char *base = strrchr(filename, '/');
                        base = base ? base + 1 : filename;
                        char stem[256];
                        strncpy(stem, base, sizeof(stem) - 1);
                        stem[sizeof(stem) - 1] = '\0';
                        char *dot = strrchr(stem, '.');
                        if (dot) *dot = '\0';
                        char compressed_name[512];
                        snprintf(compressed_name, sizeof(compressed_name), "%s_compressed.txt", stem);
                        if (!read_password(password, sizeof(password))) break;
                        vault_store(compressed_name, password);
                        history_add(compressed_name);
                    }
                } else {
                    printf("Invalid choice.\n");
                }
                break;
            }

            case 2:
                printf("Filename to retrieve (without .vault): ");
                if (!fgets(filename, sizeof(filename), stdin)) break;
                filename[strcspn(filename, "\n")] = '\0';
                if (strlen(filename) == 0) { printf("Error: filename cannot be empty.\n"); break; }
                if (!read_password(password, sizeof(password))) break;
                vault_retrieve(filename, password);
                history_add(filename);
                break;

            case 3:
                printf("Filename to compress: ");
                if (!fgets(filename, sizeof(filename), stdin)) break;
                filename[strcspn(filename, "\n")] = '\0';
                if (strlen(filename) == 0) { printf("Error: filename cannot be empty.\n"); break; }
                vault_compress_only(filename);
                break;

            case 4: {
                printf("Keyword: ");
                if (!fgets(keyword, sizeof(keyword), stdin)) break;
                keyword[strcspn(keyword, "\n")] = '\0';
                if (strlen(keyword) == 0) { printf("Error: keyword cannot be empty.\n"); break; }
                if (!read_password(password, sizeof(password))) break;
                char search_files[256][MAX_FILENAME];
                int search_count = vault_get_files(search_files, 256);
                search_vault(search_files, search_count, keyword, password);
                break;
            }

            case 5:
                printf("Sort by (name/size): ");
                if (!fgets(sort_by, sizeof(sort_by), stdin)) break;
                sort_by[strcspn(sort_by, "\n")] = '\0';
                if (strcmp(sort_by, "name") != 0 && strcmp(sort_by, "size") != 0) {
                    printf("Invalid sort option. Use 'name' or 'size'.\n");
                    break;
                }
                vault_list(sort_by);
                break;

            case 6:
                history_display();
                break;

            case 7:
                printf("Filename to delete (without .vault): ");
                if (!fgets(filename, sizeof(filename), stdin)) break;
                filename[strcspn(filename, "\n")] = '\0';
                if (strlen(filename) == 0) { printf("Error: filename cannot be empty.\n"); break; }
                if (!read_password(password, sizeof(password))) break;
                vault_delete(filename, password);
                break;

            case 8: {
                if (!read_password(password, sizeof(password))) break;
                printf("Enter filenames one per line. Type 'DONE' when finished:\n");
                int stored = 0;
                while (1) {
                    printf("File: ");
                    if (!fgets(filename, sizeof(filename), stdin)) break;
                    filename[strcspn(filename, "\n")] = '\0';
                    if (strcmp(filename, "DONE") == 0) break;
                    if (strlen(filename) == 0) { printf("Skipping empty filename.\n"); continue; }
                    FILE *check = fopen(filename, "rb");
                    if (!check) { printf("Error: '%s' not found, skipping.\n", filename); continue; }
                    fclose(check);
                    vault_store(filename, password);
                    history_add(filename);
                    stored++;
                }
                printf("Done. Stored %d file(s).\n", stored);
                break;
            }

            case 9:
                printf("Goodbye.\n");
                history_free();
                return;

            default:
                printf("Invalid choice. Please enter 1-9.\n");
        }
    }
}

int main(int argc, char *argv[]) {
    vault_init();

    if (argc == 1) {
        run_interactive();
        history_free();
        return 0;
    }

    char *cmd = argv[1];

    if (strcmp(cmd, "-e") == 0) {
        if (argc < 4) {
            printf("Usage: ./securevault -e <file> [file2 ...] <password>\n");
            return 1;
        }
        const char *password = argv[argc - 1];
        if (strlen(password) == 0) { printf("Error: password must not be empty.\n"); return 1; }
        int i;
        for (i = 2; i < argc - 1; i++) {
            vault_store(argv[i], password);
            history_add(argv[i]);
        }

    } else if (strcmp(cmd, "-d") == 0) {
        if (argc < 4) {
            printf("Usage: ./securevault -d <filename> <password>\n");
            return 1;
        }
        const char *password = argv[3];
        if (strlen(password) == 0) { printf("Error: password must not be empty.\n"); return 1; }
        vault_retrieve(argv[2], password);
        history_add(argv[2]);

    } else if (strcmp(cmd, "-c") == 0) {
        if (argc < 3) {
            printf("Usage: ./securevault -c <filename>\n");
            return 1;
        }
        vault_compress_only(argv[2]);

    } else if (strcmp(cmd, "-x") == 0) {
        if (argc < 4) {
            printf("Usage: ./securevault -x <filename> <password>\n");
            return 1;
        }
        const char *password = argv[3];
        if (strlen(password) == 0) { printf("Error: password must not be empty.\n"); return 1; }
        vault_delete(argv[2], password);

    } else if (strcmp(cmd, "-s") == 0) {
        if (argc < 4) {
            printf("Usage: ./securevault -s <keyword> <password>\n");
            return 1;
        }
        char search_files[256][MAX_FILENAME];
        int search_count = vault_get_files(search_files, 256);
        search_vault(search_files, search_count, argv[2], argv[3]);

    } else if (strcmp(cmd, "-l") == 0) {
        if (argc < 3) {
            printf("Usage: ./securevault -l name|size\n");
            return 1;
        }
        const char *sort_by = argv[2];
        if (strcmp(sort_by, "name") != 0 && strcmp(sort_by, "size") != 0) {
            printf("Error: sort option must be 'name' or 'size'.\n");
            return 1;
        }
        vault_list(sort_by);

    } else {
        printf("Unknown command: %s\n", cmd);
        print_usage();
        history_free();
        return 1;
    }

    history_free();
    return 0;
}
