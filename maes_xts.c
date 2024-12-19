/****************************************************************************
 * Nazov projektu: AES-XTS Sifrovanie a Desifrovanie Suborov pomocou microAES
 * ----------------------------------------------------------------------------
 * Subor: maes_xts.c
 * Verzia: 1.0.0
 * Datum: 16.12.2024
 * 
 * Autor: Kamil Berecky
 * 
 * Vyuzite zdroje:
 * - 
 * - https://github.com/BLAKE3-team/BLAKE3/blob/master/c/example.c
 * - https://github.com/polfosol/micro-AES/blob/master/main.c
 * - https://github.com/XomByik/aes_xts_c
 * 
 * Popis:
 * Program implementuje sifrovanie a desifrovanie suborov pomocou AES-256-XTS.
 * Vyuziva microAES kniznicu pre kryptograficke operacie a hashovaciu funkciu BLAKE3 na odvodenie klucov z hesla.
 * 
 * Pre viac info pozri README.md
 ****************************************************************************/

#include "maes_xts.h"

/**
 * Bezpecne prepisanie citlivych dat v pamati
 * 
 * Popis:
 * Bezpecne vymaze citlive data z pamate prepisanim vsetkych bajtov nulami.
 * Pouziva volatile kvalifikator a assembler barieru na zabranenie optimalizacii.
 * 
 * Proces spracovania:
 * 1. Konverzia vstupneho pointra na volatile uint8_t*s 
 * 2. Postupne prepisanie kazdej bunky pamate nulou
 * 3. Pridanie assembler bariery pre zabranenie optimalizacii
 * 
 * Volatile kvalifikator:
 * - Oznacuje premennu ktorej hodnota sa moze zmenit externe
 * - Zakazuje kompileru optimalizovat pristupy k premennej
 * - Zabranuje odstraneniu "zbytocnych" zapisov do pamate
 * - Garantuje ze kazdy zapis sa skutocne vykona
 * 
 * Assembler bariera:
 * - Zakazuje presun instrukcii cez barieru pri optimalizacii
 * - Zabranuje kompileru predpokladat stav pamate
 * 
 * Parametre:
 * @param ptr - Pointer na pamatovy blok na vymazanie
 * @param size - Velkost pamatoveho bloku v bajtoch
 * 
 * Pouzitie:
 * Na bezpecne vymazanie citlivych dat ako hesla, kluce a pod.
 */
static void secure_clear(void* ptr, size_t size) {
    // Konverzia pointra na volatile pre zabranenie optimalizacii
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    // Postupne prepisanie vsetkych bajtov nulami 
    while (size--) {
        *p++ = 0;
    }
    // Assembler bariera pre zabezpecenie vykonania zapisov
    asm volatile("" : : "r"(ptr) : "memory");
}
/**
 * Vytvorenie sifrovacieho kluca z hesla a soli
 * 
 * Popis:
 * Generuje 64-bajtovy sifrovaci kluc pomocou hashovacej funkcie BLAKE3.
 * Kombinuje heslo a sol pre zvysenie odolnosti voci slovnikovym utokom.
 * 
 * Proces spracovania:
 * 1. Overenie vstupnych parametrov
 * 2. Inicializacia BLAKE3 hashovacej funkcie
 * 3. Pridanie hesla a soli do hashu
 * 4. Generovanie 512-bitoveho kluca
 * 5. Bezpecne vymazanie docasnych dat
 * 
 * Parametre:
 * @param password - Vstupne heslo od uzivatela
 * @param salt - Nahodna sol (SALT_SIZE bajtov)
 * @param key - Vystupny buffer pre 64-bajtovy kluc
 */
static fc_status_t hash_password(const char* password, const uint8_t* salt, uint8_t* key) {
    if (!password || !salt || !key) {
        return FC_ERROR_INVALID_INPUT;
    }
    
    blake3_hasher hasher;
    // Inicializacia hashovacej funkcie BLAKE3
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (const uint8_t*)password, strlen(password));
    blake3_hasher_update(&hasher, salt, SALT_SIZE);
    // Generovanie 64-bajtoveho kluca priamo
    blake3_hasher_finalize(&hasher, key, 64);
    // Bezpecne vymazanie citlivych dat z pamate
    secure_clear(&hasher, sizeof(hasher));

    return FC_SUCCESS;
}

/**
 * Bezpecne nacitanie hesla od uzivatela
 * 
 * Popis:
 * Nacita heslo od uzivatela bez zobrazovania znakov na obrazovke.
 * Implementuje cross-platform riesenie pre Windows aj Unix systemy.
 * 
 * Proces spracovania:
 * 1. Vypnutie echa terminaloveho vstupu
 * 2. Nacitanie znakov od uzivatela
 * 3. Spracovanie specialnych znakov (backspace)
 * 4. Obnovenie povodneho nastavenia terminalu
 * 
 * Bezpecnostne opatrenia:
 * - Skryvanie zadavanych znakov
 * - Ochrana proti buffer overflow
 * - Osetrovanie specialnych znakov
 * - Obnovenie stavu terminalu aj pri chybe
 * 
 * Platformova implementacia:
 * Windows: Pouziva _getch() pre znak-po-znaku citanie
 * Unix: Pouziva termios.h pre ovladanie terminalu
 * 
 * Parametre:
 * @param password - Buffer pre ulozenie hesla
 * @param max_len - Maximalna velkost buffra
 */
static void read_password(char* password, size_t max_len) {
#ifdef _WIN32
    // Windows verzia
    size_t i = 0;
    printf("Zadajte heslo: ");
    while (i < max_len - 1) {
        char c = _getch();
        if (c == '\r' || c == '\n') {
            break;
        }
        if (c == '\b' && i > 0) {  // backspace
            i--;
            continue;
        }
        password[i++] = c;
    }
    password[i] = '\0';
    printf("\n");
#else
    // Unix verzia
    struct termios old_flags, new_flags;
    tcgetattr(STDIN_FILENO, &old_flags);
    new_flags = old_flags;
    new_flags.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_flags);
    printf("Zadajte heslo: ");
    fgets(password, max_len, stdin);
    password[strcspn(password, "\n")] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &old_flags);
    printf("\n");
#endif
}

/**
 * Sifrovanie/desifrovanie jedneho sektora v XTS rezime
 * 
 * Popis:
 * Spracovava jeden sektor dat pomocou AES-XTS sifrovania.
 * Vyuziva blokovanie upravy (tweak) pre zabezpecenie unikatnosti kazdeho sektora.
 * Podporuje aj neuplne sektory pomocou ciphertext stealing.
 * 
 * Proces spracovania:
 * 1. Vypocet blokovej upravy pre dany sektor
 * 2. Aplikacia XTS sifrovania/desifrovania na data
 * 
 * Bezpecnostne opatrenia:
 * - Unikatny tweak pre kazdy sektor
 * - Podpora neuplnych blokov pomocou ciphertext stealing
 * - In-place sifrovanie pre minimalizaciu kopirovanych dat
 * 
 * Parametre:
 * @param ptx - Pointer na vstupne data (plaintext)
 * @param ctx - Pointer na vystupne data (ciphertext)
 * @param size - Velkost dat na spracovanie v bajtoch
 * @param sector_number - Logicke cislo aktualneho sektora
 * @param key - 64-bajtovy sifrovaci kluc
 * @param initial_tweak - Pociatocna hodnota tweaku (16 bajtov)
 * @param encrypt - Priznak operacie (1 = sifrovanie, 0 = desifrovanie)
 * 
 * Vnitrorne volania:
 * - calculate_sector_tweak() pre vypocet tweaku
 * - AES_XTS_encrypt()/decrypt() pre samotne sifrovanie
 */
static void process_sector(const uint8_t* ptx, uint8_t* ctx, size_t size,
                         uint64_t sector_number,
                         const uint8_t* key, const uint8_t* initial_tweak,
                         int encrypt) {
    uint8_t tweak[16];
    calculate_sector_tweak(initial_tweak, sector_number, tweak);

    if (encrypt) {
        // Plaintext -> Ciphertext
        AES_XTS_encrypt(key, tweak, ptx, size, ctx);
    } else {
        // Ciphertext -> Plaintext
        AES_XTS_decrypt(key, tweak, ptx, size, ctx);
    }
}

/**
 * Vypocet blokovej upravy (tweak) pre sektor
 * 
 * Popis:
 * Generuje unikatnu blokovu upravu pre kazdy sektor dat.
 * Kombinuje pociatocny tweak s cislom sektora pomocou XOR operacie.
 * 
 * Proces spracovania:
 * 1. Skopirovanie pociatocneho tweaku
 * 2. XOR operacia s cislom sektora po 64-bitovych castiach
 * 3. Zachovanie celej 128-bitovej hodnoty tweaku
 * 
 * Bezpecnostne opatrenia:
 * - Unikatny tweak pre kazdy sektor
 * - Predvidatelna ale bezpecna funkcia
 * 
 * Parametre:
 * @param initial_tweak - Pociatocny tweak (16 bajtov)
 * @param sector_number - Cislo sektora
 * @param output_tweak - Vystupny buffer pre tweak (16 bajtov)
 */
static void calculate_sector_tweak(const unsigned char *initial_tweak,
                                 uint64_t sector_number,
                                 unsigned char *output_tweak) {
    // Skopirovanie pociatocneho tweaku (128 bitov)
    memcpy(output_tweak, initial_tweak, TWEAK_LENGTH);
    
    // XOR celych 128 bitov po 64-bitovych castiach
    for(int i = 0; i < TWEAK_LENGTH; i += 8) {
        uint64_t *chunk = (uint64_t *)(output_tweak + i);
        *chunk ^= sector_number;
    }
}

/**
 * Generovanie kryptograficky bezpecnych nahodnych dat
 * 
 * Popis:
 * Vyuziva nativne systemove generatory nahodnych cisel:
 * - Linux: /dev/urandom
 * - Windows: BCryptGenRandom
 * 
 * Proces spracovania:
 * 1. Detekcia operacneho systemu
 * 2. Pouzitie generatora pre dany OS
 * 3. Kontrola uspesnosti generovania
 * 
 * Bezpecnostne opatrenia:
 * - Pouzitie kryptograficky bezpecneho generatora OS s dostatocnou nahodnostou
 * - Kontrola navratovych hodnot
 * 
 * Parametre:
 * @param buffer - Vystupny buffer pre nahodne data
 * @param length - Pozadovana dlzka dat
 * 
 * @return FC_SUCCESS pri uspesnom generovani
 * @return FC_ERROR_* pri chybe
 */
static fc_status_t generate_secure_random(uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) {
        return FC_ERROR_INVALID_INPUT;
    }

#ifdef _WIN32
    // Windows implementacia pomocou BCryptGenRandom
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")

    NTSTATUS status = BCryptGenRandom(
        NULL,
        buffer,
        (ULONG)length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status)) {
        return FC_ERROR_RANDOM_GENERATION;
    }
#else
    // Linux/Unix implementacia pomocou /dev/urandom
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        return FC_ERROR_RANDOM_GENERATION;
    }

    size_t bytes_read = fread(buffer, 1, length, urandom);
    fclose(urandom);

    if (bytes_read != length) {
        return FC_ERROR_RANDOM_GENERATION;
    }
#endif

    return FC_SUCCESS;
}

/**
 * Zasifrovanie suboru pomocou hesla
 * 
 * Popis:
 * Kompletny proces sifrovania suboru v XTS rezime.
 * Vytvara zasifrovany subor s hlavickou obsahujucou metadata.
 * 
 * Proces spracovania:
 * 1. Overenie vstupnych parametrov
 * 2. Otvorenie vstupneho/vystupneho suboru
 * 3. Generovanie soli a tweaku
 * 4. Odvodenie klucov z hesla
 * 5. Vytvorenie a zapis hlavicky
 * 6. Sifrovanie dat po sektoroch
 * 7. Vycistenie/uvolnenie pamate a zatvorenie suborov
 * 
 * Bezpecnostne opatrenia:
 * - Overenie vstupov
 * - Bezpecne generovanie soli
 * - Bezpecne mazanie klucov
 * - Spracovanie chyb
 * 
 * Parametre:
 * @param input_path - Cesta k vstupnemu suboru
 * @param output_path - Cesta k vystupnemu suboru
 * @param password - Heslo od uzivatela
 * 
 * Navratove hodnoty:
 * @return FC_SUCCESS - Uspesne zasifrovanie
 * @return FC_ERROR_* - Chybovy kod pri zlyhani
 */
fc_status_t fc_encrypt_file_with_password(const char* input_path,
                                        const char* output_path,
                                        const char* password) {
    FILE *fin = NULL, *fout = NULL;
    uint8_t *buffer = NULL;
    fc_status_t status = FC_SUCCESS;
    struct file_header header;
    uint8_t key[64];  // Jeden 64-bajtovy kluc namiesto dvoch 32-bajtovych
    uint64_t sector_number = 0;
    // Kontrola platnosti vstupnych parametrov
    if (!input_path || !output_path || !password) {
        return FC_ERROR_INVALID_INPUT;
    }
    // Otvorenie suborov
    fin = fopen(input_path, "rb");
    if (!fin) return FC_ERROR_FILE_OPEN;
    
    fout = fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return FC_ERROR_FILE_OPEN;
    }
    // Alokacia buffra pre citanie/zapis dat
    buffer = (uint8_t*)malloc(BUFFER_SIZE);
    if (!buffer) {
        status = FC_ERROR_MEMORY;
        goto cleanup;
    }
    // Generovanie soli
    status = generate_secure_random(header.salt, SALT_SIZE);
    if (status != FC_SUCCESS) {
        goto cleanup;
    } 
    // Odvodenie kluca z hesla
    status = hash_password(password, header.salt, key);
    if (status != FC_SUCCESS) {
        goto cleanup;
    }
    // Generovanie pociatocneho tweaku
    status = generate_secure_random((uint8_t*)&header.initial_tweak, TWEAK_LENGTH);
    if (status != FC_SUCCESS) {
        goto cleanup;
    }
    // Zapis hlavicky
    fwrite(&header, sizeof(header), 1, fout);

    // Sifrovanie suboru po sektoroch
    uint8_t *input_buffer = buffer;
    uint8_t *output_buffer = buffer + SECTOR_SIZE;
    while (1) {
        size_t bytes_read = fread(input_buffer, 1, SECTOR_SIZE, fin);
        if (bytes_read == 0) break;

        process_sector(input_buffer, output_buffer, bytes_read,
                      sector_number, key, header.initial_tweak, 1);
                      
        if (fwrite(output_buffer, 1, bytes_read, fout) != bytes_read) {
            status = FC_ERROR_FILE_WRITE;
            goto cleanup;
        }
        sector_number++;
    }

cleanup:
    // Bezpecne odstranenie citlivych dat z pamate
    secure_clear(buffer, BUFFER_SIZE);
    secure_clear(key, sizeof(key));
    if (buffer) {
        free(buffer);
    }
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    return status;
}

/**
 * Desifrovanie suboru pomocou hesla
 * 
 * Popis:
 * Kompletny proces desifrovania suboru v XTS rezime.
 * Cita zasifrovany subor s hlavickou a obnovuje povodne data.
 * 
 * Proces spracovania:
 * 1. Otvorenie suborov
 * 2. Nacitanie a spracovanie hlavicky
 * 3. Odvodenie klucov z hesla a soli
 * 4. Desifrovanie dat po sektoroch
 * 5. Vycistenie/uvolnenie pamate a zatvorenie suborov
 * 
 * Bezpecnostne opatrenia:
 * - Overenie hlavicky
 * - Kontrola velkosti suboru
 * - Bezpecne mazanie klucov
 * - Spracovanie chyb
 * 
 * Parametre:
 * @param input_path - Cesta k zasifrovanemu suboru
 * @param output_path - Cesta k vystupnemu suboru
 * @param password - Heslo od uzivatela
 * 
 * Navratove hodnoty:
 * @return FC_SUCCESS - Uspesne desifrovanie
 * @return FC_ERROR_* - Chybovy kod pri zlyhani
 */
fc_status_t fc_decrypt_file_with_password(const char* input_path,
                                        const char* output_path,
                                        const char* password) {
    FILE *fin = NULL, *fout = NULL;
    uint8_t *buffer = NULL;
    fc_status_t status = FC_SUCCESS;
    struct file_header header;
    uint8_t key[64];
    uint64_t sector_number = 0;

    // Otvorenie vstupneho suboru
    fin = fopen(input_path, "rb");
    if (!fin) return FC_ERROR_FILE_OPEN;
    
    // Nacitanie hlavicky
    if (fread(&header, sizeof(header), 1, fin) != 1) {
        fclose(fin);
        return FC_ERROR_INVALID_INPUT;  
    }
    // Odvodenie kluca z hesla a soli
    status = hash_password(password, header.salt, key);
    if (status != FC_SUCCESS) {
        goto cleanup;
    }
    // Otvorenie vystupneho suboru
    fout = fopen(output_path, "wb");
    if (!fout) {
        fclose(fin);
        return FC_ERROR_FILE_OPEN;
    }
    // Alokacia buffra pre citanie/zapis dat
    buffer = (uint8_t*)malloc(BUFFER_SIZE);
    if (!buffer) {
        status = FC_ERROR_MEMORY;
        goto cleanup;
    }
    // Desifrovanie suboru po sektoroch az do konca
    while (1) {
        size_t bytes_read = fread(buffer, 1, SECTOR_SIZE, fin);
        if (bytes_read == 0) break; // Koniec suboru

        process_sector(buffer, buffer, bytes_read, sector_number, key, header.initial_tweak, 0);
        sector_number++;
        
        if (fwrite(buffer, 1, bytes_read, fout) != bytes_read) {
            status = FC_ERROR_FILE_WRITE;
            goto cleanup;
        }
    }

cleanup:
    // Bezpecne odstranenie citlivych dat z pamate
    secure_clear(buffer, BUFFER_SIZE);
    secure_clear(key, sizeof(key));
    if (buffer) {
        free(buffer);
    }
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    return status;
}

// Funkcia na generovanie vystupnej cesty pre zasifrovany subor
static void create_encrypted_path(const char* input_path, char* output_path, size_t max_len) {
    snprintf(output_path, max_len, "%s.enc", input_path);
}

// Funkcia na generovanie vystupnej cesty pre desifrovany subor
static fc_status_t create_decrypted_path(const char* input_path, char* output_path, size_t max_len) {
    size_t len = strlen(input_path);
    const char* enc_suffix = ".enc";
    const char* dec_prefix = "dec_";
    // Kontrola, ci ma subor priponu .enc
    if (len < strlen(enc_suffix) || strcmp(input_path + len - strlen(enc_suffix), enc_suffix) != 0) {
        return FC_ERROR_INVALID_EXTENSION;
    }
    // Odstranime .enc a pridame dec_ na zaciatok
    snprintf(output_path, max_len, "%s%.*s", dec_prefix, (int)(len - strlen(enc_suffix)), input_path);
 
    return FC_SUCCESS;
}

// Funkcia na spracovanie chyb
static void handle_crypto_error(fc_status_t status) {
    switch(status) {
        case FC_SUCCESS:
            printf("Subor bol uspesne spracovany\n");
            break;
        case FC_ERROR_FILE_OPEN:
            fprintf(stderr, "Chyba: Nepodarilo sa otvorit subor\n");
            break;
        case FC_ERROR_MEMORY:
            fprintf(stderr, "Chyba: Nepodarilo sa alokovat pamat\n");
            break;
        case FC_ERROR_INVALID_INPUT:
            fprintf(stderr, "Chyba: Neplatny vstup\n");
            break;
        case FC_ERROR_FILE_WRITE:
            fprintf(stderr, "Chyba: Chyba pri zapise suboru\n");
            break;
        case FC_ERROR_INVALID_EXTENSION:
            fprintf(stderr, "Chyba: Subor nie je sifrovany alebo ma nespravnu priponu\n");
            break;
        case FC_ERROR_FILE_NOT_FOUND:
            fprintf(stderr, "Chyba: Vstupny subor neexistuje\n");
            break;
        case FC_ERROR_RANDOM_GENERATION:
            fprintf(stderr, "Chyba: Nepodarilo sa vygenerovat nahodne data\n");
            break;
        default:
            fprintf(stderr, "Chyba: Neznama chyba (status: %d)\n", status);
    }
}
// Funkcia na spracovanie sifrovania
static fc_status_t handle_encryption(const char* input_path, const char* password) {
    char output_path[PATH_MAX];
    create_encrypted_path(input_path, output_path, PATH_MAX);
    
    printf("Sifrovanie suboru '%s' do '%s'...\n", input_path, output_path);
    return fc_encrypt_file_with_password(input_path, output_path, password);
}
// Funkcia na spracovanie desifrovania
static fc_status_t handle_decryption(const char* input_path, const char* password) {
    char output_path[PATH_MAX];
    fc_status_t status = create_decrypted_path(input_path, output_path, PATH_MAX);
    if (status == FC_SUCCESS) {
        printf("Desifrovanie suboru '%s' do '%s'...\n", input_path, output_path);
        status = fc_decrypt_file_with_password(input_path, output_path, password);
    }
    return status;
}

// Hlavna funkcia main() s argumentmi prikazoveho riadku
int main(int argc, char* argv[]) {
    // Kontrola spravneho poctu argumentov (program + volba + subor)
    if (argc != 3) {
        printf("Pouzitie: %s [-e|-d] vstupny_subor\n", argv[0]);
        printf("  -e: zasifrovat subor (zasifruje a prida priponu .enc)\n");
        printf("  -d: desifrovat subor (rozsifruje, odstrani priponu .enc a prida dec_ na zaciatok)\n");
        return 1;
    }

    // Overenie existencie vstupneho suboru
    if (access(argv[2], F_OK) != 0) {
        fprintf(stderr, "Chyba: Vstupny subor '%s' neexistuje\n", argv[2]);
        return FC_ERROR_FILE_NOT_FOUND;
    }
    // Bezpecne nacitanie hesla od uzivatela
    char password[MAX_PASSWORD_LENGTH];
    read_password(password, MAX_PASSWORD_LENGTH);
    // Spracovanie podla zvolenej operacie
    fc_status_t status;
    char output_path[PATH_MAX];

    if (strcmp(argv[1], "-e") == 0) {
        // Sifrovanie suboru
        status = handle_encryption(argv[2], password);
    }
    else if (strcmp(argv[1], "-d") == 0) {
        // Desifrovanie suboru
        status = handle_decryption(argv[2], password);
    }
    else {
        fprintf(stderr, "Neplatna volba. Pouzite -e pre sifrovanie alebo -d pre desifrovanie\n");
        return 1;
    }
    // Spracovanie a zobrazenie vysledku operacie
    handle_crypto_error(status);
    // Bezpecne vymazanie hesla z pamate
    secure_clear(password, sizeof(password));
    return status;
}
