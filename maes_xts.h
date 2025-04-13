/************************************************************************
 * Nazov projektu: AES-XTS sifrovanie a desifrovanie diskov pomocou
 *micro-AES
 * ----------------------------------------------------------------------------
 * Subor: maes_xts.h
 * Verzia: 1.3
 * Datum: 25.3.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre implementaciu AES-XTS sifrovania a
 * desifovania diskov pomocou micro-AES kniznice a BLAKE3 KDF.
 * Obsahuje deklaracie funkcii, struktury, konstanty a typy.
 **********************************************************************/
#ifndef MAES_XTS_H
#define MAES_XTS_H

/* ========== Kniznice ========== */

// Kniznica micro-AES pre AES-XTS
#include "libs/micro-AES/micro_aes.h"
// Kniznica BLAKE3 pre hasovanie a KDF
#include "libs/blake3/blake3.h"
// Pre funkcie na pracu so znakmi (isalnum, toupper, atd.)
#include <ctype.h>     
// Pre errno a strerror() - informacie o chybach
#include <errno.h>     
// Pre bool datovy typ (true/false)
#include <stdbool.h>   
// Pre standardne celociselne typy s pevnou velkostou
#include <stdint.h>    
// Pre standardne vstupno/vystupne funkcie
#include <stdio.h>     
// Pre funkcie alokacie pamate, konverzie a ine
#include <stdlib.h>    
// Pre funkcie manipulacie s retazcami
#include <string.h>    
// Pre casove funkcie a inicializaciu generatora nahodnych cisel
#include <time.h>      

#ifdef _WIN32
// Pre _getch() - bezpecne citanie hesiel
#include <conio.h>     
// Pre _aligned_malloc, _aligned_free - zarovnana alokacia pamate
#include <malloc.h>    
// Zakladne Windows API - subory, procesy, pamat
#include <windows.h>   
// Windows zariadenia, IOCTL volania pre pristup k diskom
#include <winioctl.h>  
#else
// Pre manipulaciu s adresarmi v Linuxe
#include <dirent.h>      
// File control operacie - flagy pre otvaranie suborov
#include <fcntl.h>       
// Linux file system specificke deklaracie a IOCTL makra
#include <linux/fs.h>    
// Hard disk specificke IOCTL volania v Linuxe
#include <linux/hdreg.h> 
// IOCTL volania v Linuxe pre ovladanie zariadeni
#include <sys/ioctl.h>   
// File status funkcie - informacie o suboroch
#include <sys/stat.h>    
// Pre ssize_t a ine systemove datove typy
#include <sys/types.h>   
// Pre terminaly a ovladanie konzoly v Linuxe
#include <termios.h>     
// POSIX API - zakladne systemove volania
#include <unistd.h>      
#endif

/* ========== Navratove kody funkcii ========== */

// Uspesne vykonanie operacie
#define MAES_SUCCESS 0       
// Chyba v micro-AES kniznici    
#define MAES_ERROR_MICROAES -1 
// Chyba pri vstupno/vystupnych operaciach  
#define MAES_ERROR_IO -2     
// Neplatny parameter funkcie    
#define MAES_ERROR_PARAM -3    
// Nedostatok pamate  
#define MAES_ERROR_MEMORY -4  
// Nedostatocne opravnenia   
#define MAES_ERROR_PERMISSION -5 
// Chyba v hlavicke (neplatna, poskodena)
#define MAES_ERROR_HEADER -7 
// Chyba pri odvodzovani kluca (KDF)    
#define MAES_ERROR_KDF -9    
// Chyba pri zadavani hesla / nezhoda    
#define MAES_ERROR_PASSWORD -10
// Chyba pri generovani soli  
#define MAES_ERROR_SALT -11      

/* ========== Velkosti bufferov a konstant ========== */

// 8 MB - velkost hlavneho buffra pre prenos dat
#define BUFFER_SIZE (8 * 1024 * 1024)
// Velkost jedneho sektora, pouziva sa na zarovnanie   
#define SECTOR_SIZE 4096                
// Velkost buffra pre chybove spravy
#define ERROR_BUFFER_SIZE 1024    
// Maximalny pocet znakov hesla       
#define PASSWORD_BUFFER_SIZE 128    
// Pocet rezervovanych sektorov pre metadata     
#define RESERVED_SECTORS 64    
// Velkost soli pre KDF v bajtoch          
#define SALT_SIZE 16              
// Kontextovy retazec pre BLAKE3 KDF      
#define KDF_CONTEXT "maes-xts-derive"   
// Minimalna dlzka hesla
#define MIN_PASSWORD_LENGTH 8
// Velkost bloku AES v bajtoch
#define AES_BLOCK_SIZE 16            
// Velkost kluca v bitoch podla makra AES___ 
#define MAES_KEY_BITS AES___     
// Velkost kluca v bajtoch               
#define MAES_KEY_BYTES (MAES_KEY_BITS / 8)     
// XTS potrebuje dva kluce  
#define MAES_XTS_KEY_BYTES (MAES_KEY_BYTES * 2) 
// Velkost tweak vektora je rovnaka ako bloku 
#define MAES_TWEAK_SIZE AES_BLOCK_SIZE   
// Pocet bitov v bajte           
#define BITS_PER_BYTE 8    
// Oznacenie rezimu sifrovania                      
#define ENCRYPT_MODE 1 
// Oznacenie rezimu desifovania                          
#define DECRYPT_MODE 0                          

/* ========== Konstanty pre hlavicku ========== */

// Magicky retazec pre identifikaciu hlavicky 
#define HEADER_MAGIC "MAESXTS"   
// Velkost magickeho retazca
#define HEADER_MAGIC_SIZE 7
// Verzia formatu hlavicky      
#define HEADER_VERSION 1   
// Cislo sektora kde je ulozena hlavicka       
#define HEADER_SECTOR 62 
// Typ sifrovania (2 = micro-AES-XTS)        
#define HEADER_ENCRYPTION_TYPE 2 

/* ========== Konstanty pre verifikaciu hesla ========== */

// Velkost verifikacneho bloku (AES block size)
#define VERIFICATION_BLOCK_SIZE AES_BLOCK_SIZE    
// Znamy plaintext pre verifikaciu (16 bytes)        
#define VERIFICATION_PLAINTEXT "MAES_VERIFY_OK\0\0" 

/* ========== Zobrazenie postupu ========== */

// Ako casto aktualizovat zobrazenie postupu (v sektoroch) 
#define PROGRESS_UPDATE_INTERVAL 10000  
// Pocet bajtov v 1 MB 
#define BYTES_PER_MB (1024 * 1024)
// Pauza medzi aktualizaciami zobrazenia v ms       
#define SLEEP_MS 10                    

/* ========== Platformovo specificke konstanty ========== */
#ifdef _WIN32
// Format pre vypis postupu vo Windows
#define PROGRESS_FORMAT "Priebeh: %.1f%% (%llu/%llu MB)\r" 
// Volanie pre pozastavenie behu vo Windows
#define SLEEP_FUNCTION Sleep(SLEEP_MS)  
// Definicia typu ssize_t pre Windows   
#define ssize_t SSIZE_T                    
#else
// Format pre vypis postupu v Linuxe
#define PROGRESS_FORMAT "Priebeh: %.1f%% (%lu/%lu MB)\r"

// Volanie pre pozastavenie behu v Linuxe
#define SLEEP_FUNCTION usleep(SLEEP_MS * 1000)
#endif

/* ========== Struktury ========== */

// Typ zariadenia (disk alebo logicky oddiel) - Windows specificke
#ifdef _WIN32
typedef enum { DEVICE_TYPE_DISK, DEVICE_TYPE_VOLUME } device_type_t;
#endif

// Hlavicka ulozena na zaciatku sifrovaneho zariadenia. Obsahuje zakladne metadata pre desifrovanie.
#pragma pack(push, 1)   // Zabezpecenie presneho rozlozenia bez paddingu
typedef struct {
    // Identifikator "MAESXTS"
    char magic[HEADER_MAGIC_SIZE]; 
    // Verzia formatu hlavicky
    uint8_t version;               
    // Typ sifrovania (2 = micro-AES-XTS)
    uint8_t encryption_type;       
    // Od ktoreho sektora zacinaju sifrovane data
    uint32_t start_sector; 
    // Velkost kluca v bitoch (musi zodpovedat MAES_KEY_BITS)
    uint32_t key_bits; 
    // Sol pre KDF (BLAKE3)
    uint8_t salt[SALT_SIZE]; 
    // Zasifrovany verifikacny blok
    uint8_t verification_tag[VERIFICATION_BLOCK_SIZE];
    // Padding na vyplnenie sektora
    uint8_t reserved[SECTOR_SIZE - HEADER_MAGIC_SIZE - 1 - 1 - 4 - 4 -
                                     SALT_SIZE -
                                     VERIFICATION_BLOCK_SIZE]; 
} maes_header_t;
// Obnovenie povodneho zarovnania
#pragma pack(pop) 

// Kontext zariadenia - obsahuje vsetky potrebne informacie pre manipulaciu so zariadenim
typedef struct {
#ifdef _WIN32
    // Handle na otvorene zariadenie vo Windows
    HANDLE handle;       
    // Velkost zariadenia v bajtoch
    LARGE_INTEGER size;  
    // Typ zariadenia (disk/oddiel)
    device_type_t type;  
    // Cesta k zariadeniu
    char path[MAX_PATH]; 
#else
    // File descriptor otvoreneho zariadenia v Linuxe
    int fd;        
    // Velkost zariadenia v bajtoch
    uint64_t size; 
#endif
} device_context_t;

/* ========== Deklaracie funkcii ========== */

// Zobrazenie priebehu operacie
void show_progress(uint64_t current, uint64_t total, uint64_t sector_num);

// Otvorenie diskoveho zariadenia pre citanie a zapis
bool open_device(const char *path, device_context_t *ctx);

// Zatvorenie diskoveho zariadenia a uvolnenie zdrojov
void close_device(device_context_t *ctx);

// Alokacia pamatoveho buffera zarovnaneho na velkost sektora
uint8_t *allocate_aligned_buffer(size_t size);

// Bezpecne vymazanie senzitivnych dat z pamate s volitelnym uvolnenim
void secure_clear_memory(void *buffer, size_t size, bool free_memory);

// Operacie s metadatovou hlavickou zariadenia (citanie/zapis)
int header_io(device_context_t *ctx, maes_header_t *header, int isWrite);

// Vypis chybovej spravy v platformovo nezavislom formate
void report_error(const char *message, int error_code);

// Proces sifrovania celeho zariadenia
int encrypt_device(device_context_t *ctx, const char *device_path,
                   const uint8_t *password);

// Proces desifovania celeho zariadenia
int decrypt_device(device_context_t *ctx, const uint8_t *password);

// Spracovanie argumentov prikazoveho riadka
bool parse_arguments(int argc, char *argv[], char *mode,
                     const char **device_path);

// Nastavenie pozicie v zariadeni pre nasledne citanie/zapis
bool set_position(device_context_t *ctx, uint64_t position);

// Platformovo nezavisle citanie dat zo zariadenia
ssize_t read_data(device_context_t *ctx, void *buffer, size_t size);

// Platformovo nezavisly zapis dat na zariadenie
ssize_t write_data(device_context_t *ctx, const void *buffer, size_t size);

// Zobrazenie napovedy pouzitia programu
void print_usage(const char *prog_name);

// Odvodenie kluca z hesla pomocou BLAKE3 KDF
int derive_key_from_password(const uint8_t *password,
                             const uint8_t salt[SALT_SIZE],
                             uint8_t *output_key, size_t key_len);

// Bezpecne nacitanie hesla od pouzivatela
void read_password(uint8_t *password, size_t max_len, const char *prompt);

// Ziskanie potvrdenia od pouzivatela pred sifrovanim
bool process_user_confirmation(const char *device_path);

// Spracovanie zadania hesla s volitelnym overovanim (pre sifrovanie)
bool process_password_input(uint8_t *password, size_t password_size,
                            int verify);

// Generovanie nahodnej soli
bool generate_salt(uint8_t *salt_buffer, size_t salt_size);

/* ========== Platformovo specificke funkcie ========== */
#ifdef _WIN32
// Kontrola ci proces bezi s administratorskymi opravneniami
BOOL is_admin(void);

// Urcenie typu zariadenia podla cesty
device_type_t get_device_type(const char *path);

// Priprava zariadenia na sifrovanie (uzamknutie, odpojenie)
bool prepare_device_for_encryption(const char *path, HANDLE *handle);

// Zistenie velkosti zariadenia v bajtoch
LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t deviceType);

// Kontrola a zobrazenie informacie o pristupe k Windows jednotke
void check_volume(const char *path);

// Odomknutie predtym zamknuteho disku
void unlock_disk(HANDLE hDevice);

// Vypis Windows chybovej spravy
void report_windows_error(const char *message);

// Otvorenie zariadenia s opakovanim
HANDLE open_device_with_retry(const char *path);

// Nastavenie pozicie suboru/zariadenia (Windows specificka implementacia)
BOOL set_file_position(HANDLE handle, LARGE_INTEGER position);

/* ========== Linux-specificke funkcie ========== */
#else
// Kontrola ci je oddiel momentalne pripojeny v systeme
bool is_partition_mounted(const char *device_path);

// Zistenie velkosti oddielu pomocou ioctl
uint64_t get_partition_size(int fd);

#endif

#endif // MAES_XTS_H