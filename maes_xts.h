/************************************************************************
 * Nazov projektu: AES-XTS sifrovanie a desifrovanie diskov pomocou micro-AES
 * ----------------------------------------------------------------------------
 * Subor: maes_xts.h
 * Verzia: 1.0
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
 
 // Include micro_aes.h for AES___ definition
 #include "libs/micro-AES/micro_aes.h"
 
 // Define BLOCK_SIZE explicitly as it's not in micro_aes.h
 #define BLOCK_SIZE 16
 
 // Now include other standard headers
 #include <stdio.h>
 #include <stdlib.h>
 #include <stdint.h>
 #include <string.h>
 #include <ctype.h>
 #include <stdbool.h>
 #include <errno.h>       // Pre errno a strerror()
 #include <time.h> // For seeding rand()
 
 // Include BLAKE3 header
 #include "libs/blake3/blake3.h"
 
 // Platformovo specificke hlavickove subory
 #ifdef _WIN32
     #include <windows.h>     // Zakladne Windows API
     #include <conio.h>       // Pre _getch() - bezpecne citanie hesiel (alebo alternativa)
     #include <winioctl.h>    // Windows zariadenia, IOCTL volania
     #include <malloc.h>      // For _aligned_malloc, _aligned_free
 #else
     #include <unistd.h>      // POSIX API
     #include <fcntl.h>       // File control operacie
     #include <sys/ioctl.h>   // IOCTL volania v Linuxe
     #include <linux/fs.h>    // Linux file system specificke deklaracie
     #include <termios.h>     // Pre terminaly a ovladanie konzoly
     #include <sys/stat.h>    // File status funkcie
     #include <linux/hdreg.h> // Hard disk specificke IOCTL volania
     #include <dirent.h>      // Pre manipulaciu s adresarmi
     #include <sys/types.h>   // For ssize_t
 #endif
 
 /* ========== Navratove kody funkcii ========== */
 #define MAES_SUCCESS            0   // Uspesne vykonanie operacie
 #define MAES_ERROR_MICROAES    -1   // Chyba v micro-AES kniznici
 #define MAES_ERROR_IO          -2   // Chyba pri vstupno/vystupnych operaciach
 #define MAES_ERROR_PARAM       -3   // Neplatny parameter funkcie
 #define MAES_ERROR_MEMORY      -4   // Nedostatok pamate
 #define MAES_ERROR_PERMISSION  -5   // Nedostatocne opravnenia
 #define MAES_ERROR_HEADER      -7   // Chyba v hlavicke (neplatna, poskodena)
 #define MAES_ERROR_KDF         -9   // Chyba pri odvodzovani kluca (KDF)
 #define MAES_ERROR_PASSWORD    -10  // Chyba pri zadavani hesla / nezhoda
 #define MAES_ERROR_SALT        -11  // Chyba pri generovani soli
 
 /* ========== Velkosti bufferov a konstant ========== */
 #define BUFFER_SIZE               (8 * 1024 * 1024)  /* 8 MB - velkost hlavneho buffra pre prenos dat */
 #define SECTOR_SIZE               4096               /* Velkost jedneho sektora, pouziva sa na zarovnanie */
 #define ERROR_BUFFER_SIZE         1024               /* Velkost buffra pre chybove spravy */
 #define PASSWORD_BUFFER_SIZE      128                /* Maximalny pocet znakov hesla */
 #define RESERVED_SECTORS          64                 /* Pocet rezervovanych sektorov pre metadata */
 #define SALT_SIZE                 16                 /* Velkost soli pre KDF v bajtoch */
 #define KDF_CONTEXT               "maes-xts-derive"  /* Kontextovy retazec pre BLAKE3 KDF */
 #define MIN_PASSWORD_LENGTH       8                  /* Minimalna dlzka hesla */
 
 
 /* ========== Kryptograficke konstanty ========== */
 // BLOCKSIZE is now defined above
 // Use AES___ macro from micro_aes.h to determine key size
 #define MAES_KEY_BITS             AES___
 #define MAES_KEY_BYTES            (MAES_KEY_BITS / 8)
 #define MAES_XTS_KEY_BYTES        (MAES_KEY_BYTES * 2) // XTS needs two keys
 #define MAES_TWEAK_SIZE           BLOCK_SIZE          // Tweak size is block size
 #define BITS_PER_BYTE             8                  /* Pocet bitov v bajte */
 #define ENCRYPT_MODE              1                  /* Oznacenie rezimu sifrovania */
 #define DECRYPT_MODE              0                  /* Oznacenie rezimu desifovania */
 
 /* ========== Konstanty pre hlavicku ========== */
 #define HEADER_MAGIC              "MAESXTS"          /* Magicky retazec pre identifikaciu hlavicky */
 #define HEADER_MAGIC_SIZE         7                  /* Velkost magickeho retazca */
 #define HEADER_VERSION            1                  /* Verzia formatu hlavicky */
 #define HEADER_SECTOR             62                 /* Cislo sektora kde je ulozena hlavicka */
 #define HEADER_ENCRYPTION_TYPE    2                  /* Typ sifrovania (2 = micro-AES-XTS) */
 
 /* ========== Konstanty pre verifikaciu hesla ========== */
 // This now uses the BLOCK_SIZE defined above
 #define VERIFICATION_BLOCK_SIZE   BLOCK_SIZE         /* Velkost verifikacneho bloku (AES block size) */
 #define VERIFICATION_PLAINTEXT    "MAES_VERIFY_OK\0\0" /* Znamy plaintext pre verifikaciu (16 bytes) */
 
 /* ========== Zobrazenie postupu ========== */
 #define PROGRESS_UPDATE_INTERVAL  10000              /* Ako casto aktualizovat zobrazenie postupu (v sektoroch) */
 #define BYTES_PER_MB              (1024 * 1024)      /* Pocet bajtov v 1 MB */
 #define SLEEP_MS                  10                 /* Pauza medzi aktualizaciami zobrazenia v ms */
 
 /* ========== Platformovo specificke konstanty ========== */
 #ifdef _WIN32
  // Format pre zobrazenie postupu vo Windows - pouziva %llu pre 64-bit cisla
  #define PROGRESS_FORMAT           "Priebeh: %.1f%% (%llu/%llu MB)\r"
  // Funkcia pre pauzu vo Windows
  #define SLEEP_FUNCTION            Sleep(SLEEP_MS)
  #define ssize_t                   SSIZE_T // Define ssize_t for Windows
 #else
  // Format pre zobrazenie postupu v Linuxe - pouziva %lu pre 64-bit cisla
  #define PROGRESS_FORMAT           "Priebeh: %.1f%% (%lu/%lu MB)\r"
  // Funkcia pre pauzu v Linuxe
  #define SLEEP_FUNCTION            usleep(SLEEP_MS * 1000)
 #endif
 
 /* ========== Struktury ========== */
 
 // Typ zariadenia (disk alebo logicky oddiel) - Windows specificke
 #ifdef _WIN32
  typedef enum {
      DEVICE_TYPE_DISK,
      DEVICE_TYPE_VOLUME
  } device_type_t;
 #endif
 
 /**
  * Hlavicka ulozena na zaciatku sifrovaneho zariadenia
  * Obsahuje zakladne metadata pre desifrovanie.
  */
  #pragma pack(push, 1) // Zabezpecenie presneho rozlozenia bez paddingu
  typedef struct {
      char magic[HEADER_MAGIC_SIZE];   // Identifikator "MAESXTS"
      uint8_t version;                 // Verzia formatu hlavicky
      uint8_t encryption_type;         // Typ sifrovania (2 = micro-AES-XTS)
      uint32_t start_sector;           // Od ktoreho sektora zacinaju sifrovane data
      uint32_t key_bits;               // Velkost kluca v bitoch (musi zodpovedat MAES_KEY_BITS)
      uint8_t salt[SALT_SIZE];         // Sol pre KDF (BLAKE3)
      // This should now use the correctly defined VERIFICATION_BLOCK_SIZE
      uint8_t verification_tag[VERIFICATION_BLOCK_SIZE]; /* Encrypted verification block */
      uint8_t reserved[SECTOR_SIZE - HEADER_MAGIC_SIZE - 1 - 1 - 4 - 4 - SALT_SIZE - VERIFICATION_BLOCK_SIZE]; // Padding to fill sector
  } maes_header_t;
  #pragma pack(pop)  // Obnovenie povodneho zarovnania
 
  /**
   * Kontext zariadenia - obsahuje vsetky potrebne informacie pre manipulaciu so zariadenim
   * Ma rozne cleny v zavislosti od operacneho systemu
   */
  typedef struct {
      #ifdef _WIN32
      HANDLE handle;            // Handle na otvorene zariadenie vo Windows
      LARGE_INTEGER size;       // Velkost zariadenia v bajtoch
      device_type_t type;       // Typ zariadenia (disk/oddiel)
      char path[MAX_PATH];      // Cesta k zariadeniu
      #else
      int fd;                   // File descriptor otvoreneho zariadenia v Linuxe
      uint64_t size;            // Velkost zariadenia v bajtoch
      #endif
  } device_context_t;
 
  /* ========== Deklaracie funkcii ========== */
 
  /**
   * Zobrazenie priebehu operacie
   */
  void show_progress(uint64_t current, uint64_t total, uint64_t sector_num);
 
  /**
   * Otvorenie diskoveho zariadenia pre citanie a zapis
   */
  bool open_device(const char *path, device_context_t *ctx);
 
  /**
   * Zatvorenie diskoveho zariadenia a uvolnenie zdrojov
   */
  void close_device(device_context_t *ctx);
 
  /**
   * Alokacia pamatoveho buffera zarovnaneho na velkost sektora
   */
  uint8_t* allocate_aligned_buffer(size_t size);
 
  /**
   * Bezpecne vymazanie senzitivnych dat z pamate s volitelnym uvolnenim
   */
  void secure_clear_memory(void *buffer, size_t size, bool free_memory);
 
  /**
   * Operacie s metadatovou hlavickou zariadenia (citanie/zapis)
   */
  int header_io(device_context_t *ctx, maes_header_t *header, int isWrite);
 
  /**
   * Vypis chybovej spravy v platformovo nezavislom formate
   */
  void report_error(const char *message, int error_code);
 
  /**
   * Proces sifrovania celeho zariadenia
   */
  int encrypt_device(device_context_t *ctx, const char *device_path, const uint8_t *password);
 
  /**
   * Proces desifovania celeho zariadenia
   */
  int decrypt_device(device_context_t *ctx, const uint8_t *password);
 
  /**
   * Spracovanie argumentov prikazoveho riadka
   */
  bool parse_arguments(int argc, char *argv[], char *mode, const char **device_path);
 
  /**
   * Nastavenie pozicie v zariadeni pre nasledne citanie/zapis
   */
  bool set_position(device_context_t *ctx, uint64_t position);
 
  /**
   * Platformovo nezavisle citanie dat zo zariadenia
   */
  ssize_t read_data(device_context_t *ctx, void *buffer, size_t size);
 
  /**
   * Platformovo nezavisly zapis dat na zariadenie
   */
  ssize_t write_data(device_context_t *ctx, const void *buffer, size_t size);
 
  /**
   * Zobrazenie napovedy pouzitia programu
   */
  void print_usage(const char *prog_name);
 
  /**
   * Odvodenie kluca z hesla pomocou BLAKE3 KDF
   */
  int derive_key_from_password(const uint8_t *password, const uint8_t salt[SALT_SIZE], uint8_t *output_key, size_t key_len);
 
  /**
   * Bezpecne nacitanie hesla od pouzivatela
   */
  void read_password(uint8_t *password, size_t max_len, const char *prompt);
 
  /**
   * Ziskanie potvrdenia od pouzivatela pred sifrovanim
   */
  bool process_user_confirmation(const char *device_path);
 
  /**
   * Spracovanie zadania hesla s volitelnym overovanim (pre sifrovanie)
   */
  bool process_password_input(uint8_t *password, size_t password_size, int verify);
 
  /**
   * Generovanie nahodnej soli
   */
  bool generate_salt(uint8_t *salt_buffer, size_t salt_size);
 
 
  /* ========== Platformovo specificke funkcie ========== */
  #ifdef _WIN32
  /**
   * Kontrola ci proces bezi s administratorskymi opravneniami
   */
  BOOL is_admin(void);
 
  /**
   * Urcenie typu zariadenia podla cesty
   */
  device_type_t get_device_type(const char *path);
 
  /**
   * Priprava zariadenia na sifrovanie (uzamknutie, odpojenie)
   */
  bool prepare_device_for_encryption(const char *path, HANDLE *handle);
 
  /**
   * Zistenie velkosti zariadenia v bajtoch
   */
  LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t deviceType);
 
  /**
   * Kontrola a zobrazenie informacie o pristupe k Windows jednotke
   */
  void check_volume(const char *path);
 
  /**
   * Odomknutie predtym zamknuteho disku
   */
  void unlock_disk(HANDLE hDevice);
 
  /**
   * Vypis Windows chybovej spravy
   */
  void report_windows_error(const char *message);
 
  /**
   * Otvorenie zariadenia s opakovanim
   */
  HANDLE open_device_with_retry(const char *path);
 
  /**
   * Nastavenie pozicie suboru/zariadenia (Windows specificka implementacia)
   */
  BOOL set_file_position(HANDLE handle, LARGE_INTEGER position);
 
 
  /* ========== Linux-specificke funkcie ========== */
  #else
  /**
   * Kontrola ci je oddiel momentalne pripojeny v systeme
   */
  bool is_partition_mounted(const char *device_path);
 
  /**
   * Zistenie velkosti oddielu pomocou ioctl
   */
  uint64_t get_partition_size(int fd);
 
  #endif
 
  #endif /* MAES_XTS_H */