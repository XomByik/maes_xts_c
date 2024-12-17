#ifndef FILE_CRYPTO_H
#define FILE_CRYPTO_H

#include "libs/micro-AES/micro_aes.h"
#include "libs/blake3/blake3.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <linux/limits.h>

#ifdef _WIN32
    #include <conio.h>    // pre _getch() na Windows
    #include <io.h>       // pre _access() na Windows
    #define F_OK 0
    #define access _access
#else
    #include <termios.h>
    #include <unistd.h>
#endif

// Konstanty
#define SALT_SIZE 32 // Velkost soli pre derivaciu klucov
#define BUFFER_SIZE 4096  // 4 KB buffer pre citanie/zapis dat (typicka velkost stranky pamate)
#define SECTOR_SIZE 512    // Standardna velkost sektora na disku
#define BLOCK_SIZE 16      // Velkost bloku pre AES sifrovanie
#define MAX_PASSWORD_LENGTH 1024 // Maximalna dlzka hesla
#define TWEAK_LENGTH 16  // Velkost blokovej upravy

// Navratove kody

typedef enum {
    FC_SUCCESS = 0,
    FC_ERROR_FILE_OPEN = 1,
    FC_ERROR_MEMORY = 2,
    FC_ERROR_INVALID_INPUT = 3,
    FC_ERROR_FILE_WRITE = 4,
    FC_ERROR_INVALID_EXTENSION = 5,
    FC_ERROR_FILE_NOT_FOUND = 6,
    FC_ERROR_RANDOM_GENERATION= 7
} fc_status_t;

// Hlavicka sifrovaneho suboru
struct file_header {
    uint8_t salt[SALT_SIZE];        // Sol pre derivaciu klucov
    uint8_t initial_tweak[16];      // Pociatocny tweak pre XTS rezim
};

// Pomocne funkcie pre pracu so subormi
static void create_encrypted_path(const char* input_path, char* output_path, size_t max_len);
static fc_status_t create_decrypted_path(const char* input_path, char* output_path, size_t max_len);

// Funkcie pre sifrovanie/desifrovanie suborov pomocou hesla
fc_status_t fc_encrypt_file_with_password(const char* input_path,const char* output_path, const char* password);
fc_status_t fc_decrypt_file_with_password(const char* input_path,const char* output_path,const char* password);
static void calculate_sector_tweak(const unsigned char *initial_tweak, uint64_t sector_number, unsigned char *output_tweak);
static void handle_crypto_error(fc_status_t status);
static fc_status_t handle_encryption(const char* input_path, const char* password);
static fc_status_t handle_decryption(const char* input_path, const char* password);

// Funkcia pre nacitanie hesla od uzivatela
static void read_password(char* password, size_t max_len);
#endif // FILE_CRYPTO_H