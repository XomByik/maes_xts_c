# AES-XTS šifrovanie a dešifrovanie súborov pomocou knižnice micro-AES

## Obsah
1. [Základný prehľad](#základný-prehľad)
2. [Ako to funguje](#ako-to-funguje)
3. [Inštalácia](#inštalácia)
4. [Používanie programu](#používanie-programu)
5. [Technická dokumentácia](#technická-dokumentácia)
6. [Bezpečnostné informácie](#bezpečnostné-informácie)

## Základný prehľad

Tento program slúži na bezpečné šifrovanie a dešifrovanie súborov pomocou
lightweight implementácie AES v XTS režime. Je vhodný pre:
- Šifrovanie súborov na embedovaných zariadeniach
- Bezpečné ukladanie dát s minimálnymi nárokmi na pamäť
- Zariadenia kde nie je možné alebo vhodné použiť väčšie knižnice typu OpenSSL

### Hlavné výhody
- Využíva knižnicu micro-AES vhodnú pre embedované systémy (minimálna pamäťová
  náročnosť)
- Podporuje súbory ľubovoľnej veľkosti
- Funguje na Windows aj Linux systémoch
- Nevyžaduje externé knižnice

## Ako to funguje

### Použité technológie

**micro-AES XTS šifrovanie**
   - Využíva 256-bitové kľúče pre šifrovanie aj blokové úpravy
   - Celkový 512-bitový kľúč rozdelený na dve 256-bitové časti
   - Optimalizovaná implementácia pre embedované systémy
   - Veľkosť blokov: 16 bajtov
   - Implementované pomocou micro-AES knižnice

**BLAKE3**
   - Moderná hashovacia funkcia
   - Generuje 512-bitový kľúč z hesla
   - Využívame náhodnú soľ pre jedinečnosť každého hesla

### Proces šifrovania
1. Zadanie vstupných parametrov:
   - Súbor, ktorý chce užívateľ zašifrovať
   - Heslo od používateľa
   
2. Príprava hlavičky súboru:
   - Vygenerovanie náhodnej 128-bitovej soli cez CSPRNG
   - Vygenerovanie náhodnej 128-bitovej počiatočnej blokovej úpravy (počiatočného čísla
     sektora) cez CSPRNG
   - Uloženie salt a počiatočnej blokovej úpravy na začiatok súboru
   - Tento prístup generovania počiatočnej blokovej úpravy zabezpečuje, že súbor je možné rozšifrovať na rôznych miestach

3. Odvodenie kľúčov z hesla a soli:
   - Z hesla a soli sa pomocou BLAKE3 vytvoria dva 256-bitové kľúče
   - Prvý kľúč pre šifrovanie dát
   - Druhý kľúč pre šifrovanie blokových úprav

4. Spracovanie súboru po logických sektoroch:
   - Veľkosť sektora: 512 bajtov (typická veľkosť jedného sektoru pevného disku
     na Windows/Unix systémoch)
   - Pre každý sektor sa vypočíta jedinečná bloková úprava
   - Bloková úprava = počiatočná bloková úprava XOR číslo_sektora
   - Číslo sektora je v našom prípade logická pozícia (posun pri prechádzaní) v súbore
   - Šifrovanie dát v sektore pomocou AES-XTS s vypočítanou blokovou úpravou

### Proces dešifrovania
1. Zadanie vstupných parametrov:
   - Zašifrovaný súbor s príponou .enc
   - Heslo od používateľa
   
2. Čítanie hlavičky súboru:
   - Načítanie 32-bajtovej soli
   - Načítanie počiatočného sektora

3. Odvodenie kľúčov z hesla a soli:
   - Použitie rovnakého hesla a načítanej soli zo súboru
   - Vytvorenie rovnakých kľúčov pomocou BLAKE3
   - V prípade zlého zadaného hesla bude rozšifrovaný súbor nečitateľný

4. Spracovanie súboru po sektoroch:
   - Výpočet blokovej úpravy pre každý sektor
   - Dešifrovanie dát pomocou AES-XTS
   - Zápis dešifrovaných dát do výstupného súboru

## Inštalácia

### Požiadavky
- GCC kompilátor
- Make nástroj
- Git (voliteľné, pre stiahnutie zdrojových kódov)

### Windows
1. Inštalácia Chocolatey:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

2. Inštalácia MinGW pomocou Chocolatey:
```powershell
choco install mingw
```

3. Kompilácia:
```powershell
mingw32-make
```

### Linux (Ubuntu/Debian)

1. Inštalácia potrebných nástrojov:

```bash
sudo apt-get update
sudo apt-get install build-essential
```

2. Kompilácia:
```bash
make
```

## Používanie programu

### Šifrovanie súboru
```bash
./maes_xts -e subor.txt
```
- Vytvorí zašifrovaný súbor: subor.txt.enc

### Dešifrovanie súboru
```bash
./maes_xts -d subor.txt.enc
```
- Vytvorí dešifrovaný súbor: dec_subor.txt

## Technická dokumentácia

### Formát šifrovaného súboru
```
+----------------+---------------------+----------------------------+
| SALT           | Počiatočná bloková úprava   | Šifrované dáta     |
| (32 bajtov)    | (32 bajtov)                 | (n-bajtov)         |
+----------------+---------------------+----------------------------+
```

### Implementované funkcie

#### secure_clear
```c
static void secure_clear(void* ptr, size_t size)
```
- **Účel**: Bezpečné vymazanie citlivých dát z pamäte
- **Parametre**:
  - ptr: pointer na pamäťový blok na vymazanie
  - size: veľkosť pamäte v bajtoch
- **Proces**:
  1. Konverzia vstupného pointra na volatile uint8_t*
  2. Postupné prepisanie každej bunky pamäte nulou
  3. Pridanie assembler bariéry pre zabránenie optimalizácii

#### hash_password
```c
static fc_status_t hash_password(const char* password, const uint8_t* salt, uint8_t* key1, uint8_t* key2)
```
- **Účel**: Hashovanie hesla pomocou BLAKE3
- **Parametre**:
  - password: heslo od používateľa
  - salt: náhodná soľ
  - key1: prvý 256-bitový kľúč
  - key2: druhý 256-bitový kľúč
- **Proces**:
  1. Kombinácia hesla a soli
  2. Hashovanie pomocou BLAKE3
  3. Rozdelenie výsledného hashu na dva kľúče

#### read_password
```c
static void read_password(char* password, size_t max_len)
```
- **Účel**: Bezpečné načítanie hesla od užívateľa bez zobrazovania znakov
- **Parametre**:
  - password: buffer pre heslo
  - max_len: maximálna veľkosť buffra
- **Proces**:
  - Cross-platform implementácia pre Windows (_getch) a Unix (termios.h)

#### process_sector
```c
static void process_sector(uint8_t* buffer, size_t size, uint64_t sector_number, const uint8_t* key, const uint8_t* initial_tweak, int encrypt)
```
- **Účel**: Šifrovanie alebo dešifrovanie jedného sektora v XTS režime
- **Parametre**:
  - buffer: dáta na spracovanie
  - size: veľkosť dát
  - sector_number: číslo aktuálneho sektora
  - key: 64-bajtový šifrovací kľúč
  - initial_tweak: počiatočná bloková úprava
  - encrypt: režim operácie (1=šifrovanie, 0=dešifrovanie)
- **Proces**:
  1. Výpočet blokovej úpravy pre daný sektor
  2. XTS šifrovanie/dešifrovanie s vypočítanou blokovou úpravou
  3. Zápis šifrovaných/dešifrovaných dát do buffra

#### calculate_sector_tweak
```c
static void calculate_sector_tweak(const unsigned char *initial_tweak, uint64_t sector_number, unsigned char *output_tweak)
```
- **Účel**: Výpočet blokovej úpravy pre konkrétny sektor
- **Parametre**: 
  - initial_tweak: počiatočná bloková úprava vygenerovaná CSPRNG (128 bitov)
  - sector_number: logické číslo sektora (pozícia v súbore)
  - output_tweak: výstupný buffer pre vypočítanú blokovú úpravu (128 bitov)
- **Proces**:
  1. Skopírovanie počiatočnej blokovej úpravy
  2. XOR počiatočnej blokovej úpravy s logickým číslom sektora (po dvoch
     64-bitových častiach)

#### generate_secure_random
```c
static void generate_secure_random(uint8_t* buffer, size_t length)
```
- **Účel**: Generovanie kryptograficky bezpečných náhodných dát
- **Parametre**: 
  - buffer: výstupný buffer pre náhodné dáta
  - length: požadovaná dĺžka dát
- **Proces**:
  1. Detekcia operačného systému
  2. Windows: Použitie BCryptGenRandom
  3. Linux: Použitie /dev/urandom
  4. Kontrola úspešnosti generovania

#### fc_encrypt_file_with_password
```c
fc_status_t fc_encrypt_file_with_password(const char* input_path, const char* output_path, const char* password)
```
- **Účel**: Kompletný proces šifrovania súboru s heslom
- **Parametre**: 
  - input_path: cesta k vstupnému súboru
  - output_path: cesta k výstupnému súboru
  - password: heslo od užívateľa
- **Proces**:
  1. Overenie vstupných parametrov
  2. Vygenerovanie náhodnej soli a počiatočnej blokovej úpravy
  3. Odvodenie kľúča z hesla
  4. Vytvorenie a zápis hlavičky
  5. Šifrovanie dát po sektoroch
  6. Uvoľnenie/vyčistenie zdrojov

#### fc_decrypt_file_with_password
```c
fc_status_t fc_decrypt_file_with_password(const char* input_path, const char* output_path, const char* password)
```
- **Účel**: Kompletný proces dešifrovania súboru s heslom
- **Parametre**: 
  - input_path: cesta k zašifrovanému súboru
  - output_path: cesta k výstupnému súboru
  - password: heslo od užívateľa
- **Proces**:
  1. Načítanie a overenie hlavičky súboru
  2. Derivácia kľúča z hesla a načítanej soli
  3. Dešifrovanie dát po sektoroch
  4. Kontrola integrity dát
  5. Uvoľnenie/vyčistenie zdrojov

#### Pomocné funkcie pre prácu so súbormi
```c
static void create_encrypted_path(char *output, const char *input)
static void create_decrypted_path(char *output, const char *input)
```
- **Účel**: Generovanie ciest k výstupným súborom
- **Proces**:
  1. Analýza vstupnej cesty
  2. Pridanie/odstránenie prípon
  3. Overenie výstupnej cesty

#### Spracovanie chýb
```c
static void handle_crypto_error(fc_status_t status)
```
- **Účel**: Spracovanie chýb
- **Parametre**:
  - status: kód chyby
- **Proces**:
  1. Určenie chyby podľa kódu
  2. Výpis zodpovedajúcej chybovej správy
  3. Uvoľnenie/vyčistenie zdrojov

### Bezpečnostné vlastnosti

#### 1. Ochrana proti útokom
- Unikátna soľ pre každý súbor
- Unikátna počiatočná bloková úprava pre každý súbor

#### 2. Kryptografická bezpečnosť
- 256-bitová ekvivalentná výpočtová bezpečnosť proti útoku hrubou silou
- Bezpečné mazanie citlivých údajov z pamäte

#### 3. Odporúčania pre heslá
- Minimálna dĺžka: 8 znakov
- Použiť kombináciu:
  - Veľké písmená (A-Z)
  - Malé písmená (a-z)
  - Čísla (0-9)
  - Špeciálne znaky (!@#$%^&*)

## Odkazy na dokumentáciu

### Štandardy
- [IEEE 1619](https://standards.ieee.org/standard/1619-2018.html)
- [NIST SP 800-38E](https://csrc.nist.gov/publications/detail/sp/800-38e/final)

### Použité knižnice
- [micro-AES](https://github.com/polfosol/micro-AES)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3)
