# AES-XTS šifrovanie a dešifrovanie diskov pomocou knižnice micro-AES

## Obsah
1. [Základný prehľad](#základný-prehľad)
2. [Ako to funguje](#ako-to-funguje)
3. [Inštalácia](#inštalácia)
4. [Používanie programu](#používanie-programu)
5. [Technická dokumentácia](#technická-dokumentácia)
6. [Bezpečnostné informácie](#bezpečnostné-informácie)

## Základný prehľad

Tento program slúži na bezpečné šifrovanie a dešifrovanie diskov a logických oddielov pomocou
lightweight implementácie AES v XTS režime. Je vhodný pre:
- Šifrovanie celých diskov alebo partícií
- Bezpečné ukladanie dát s minimálnymi nárokmi na pamäť
- Zariadenia kde nie je možné alebo vhodné použiť väčšie knižnice typu OpenSSL

### Hlavné výhody
- Využíva knižnicu micro-AES vhodnú pre embedované systémy (minimálna pamäťová
  náročnosť)
- Podporuje šifrovanie celých diskov a oddielov
- Funguje na Windows aj Linux systémoch

## Ako to funguje

### Použité technológie

**micro-AES XTS šifrovanie**
   - Využíva 256-bitové kľúče pre šifrovanie aj blokové úpravy
   - Celkový 512-bitový kľúč rozdelený na dve 256-bitové časti
   - Optimalizovaná implementácia pre embedované systémy
   - Veľkosť sektorov: 4096 bajtov
   - Implementované pomocou micro-AES knižnice

**BLAKE3**
   - Moderná hashovacia funkcia
   - Používaná ako KDF na generovanie 512-bitového kľúča z hesla
   - Využíva náhodnú soľ pre jedinečnosť každého hesla

### Proces šifrovania
1. Zadanie vstupných parametrov:
   - Disk/oddiel, ktorý chce užívateľ zašifrovať
   - Heslo od používateľa
   
2. Príprava a zápis hlavičky:
   - Vygenerovanie náhodnej 16-bajtovej soli cez CSPRNG
   - Vytvorenie verifikačného bloku pre neskoršiu kontrolu správnosti hesla
   - Uloženie hlavičky do špeciálneho sektora zariadenia (sektor 62)
   
3. Odvodenie kľúčov z hesla a soli:
   - Z hesla a soli sa pomocou BLAKE3 vytvoria dva 256-bitové kľúče
   - Prvý kľúč pre šifrovanie dát
   - Druhý kľúč pre šifrovanie blokových úprav

4. Spracovanie zariadenia po logických sektoroch:
   - Veľkosť sektora: 4096 bajtov
   - Každý sektor sa šifruje s jedinečnou blokovou úpravou (tweak)
   - Bloková úprava = číslo_sektora
   - Číslo sektora je jeho logická pozícia v zariadení
   - Šifrovanie dát v sektore pomocou AES-XTS s vypočítanou blokovou úpravou
   - Sektor s hlavičkou zostáva nešifrovaný pre umožnenie dešifrovania

### Proces dešifrovania
1. Zadanie vstupných parametrov:
   - Zašifrovaný disk/oddiel
   - Heslo od používateľa
   
2. Čítanie hlavičky zariadenia:
   - Načítanie soli a metadát zo sektora hlavičky
   - Overenie správnosti formátu hlavičky

3. Odvodenie kľúčov z hesla a soli:
   - Použitie zadaného hesla a načítanej soli zo zariadenia
   - Vytvorenie kľúčov pomocou BLAKE3
   - Overenie správnosti hesla pomocou verifikačného bloku

4. Spracovanie zariadenia po sektoroch:
   - Výpočet blokovej úpravy pre každý sektor
   - Dešifrovanie dát pomocou AES-XTS
   - Preskočenie sektora s hlavičkou

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

### Šifrovanie disku/oddielu
```bash
sudo ./maes_xts encrypt /dev/sdb1
```
- Zašifruje celý oddiel /dev/sdb1

### Dešifrovanie disku/oddielu
```bash
sudo ./maes_xts decrypt /dev/sdb1
```
- Dešifruje celý oddiel /dev/sdb1

### Windows príklady
```powershell
# Administrátorské práva sú vyžadované
maes_xts encrypt \\.\PhysicalDrive1
maes_xts decrypt \\.\D:
```

## Technická dokumentácia

### Formát hlavičky
```
+----------------+---------------+-------------------+----------------+
| MAGIC (MAESXTS)| Verzia        | Typ šifrovania    | Počiatočný    |
| (7 bajtov)     | (1 bajt)      | (1 bajt)          | sektor (4 B)  |
+----------------+---------------+-------------------+----------------+
| Veľkosť kľúča  | Soľ           | Verifikačný tag   | Rezervované   |
| (4 bajty)      | (16 bajtov)   | (16 bajtov)       | (zostatok)    |
+----------------+---------------+-------------------+----------------+
```

### Implementované funkcie

#### show_progress
```c
void show_progress(uint64_t current, uint64_t total, uint64_t sector_num)
```
- **Účel**: Zobrazenie priebehu operácie
- **Parametre**:
  - current: Aktuálny počet spracovaných bajtov
  - total: Celkový počet bajtov na spracovanie
  - sector_num: Aktuálne číslo spracovávaného sektora
- **Proces**:
  1. Výpočet percentuálneho priebehu
  2. Zobrazenie aktuálneho stavu na konzolu

#### process_sectors
```c
int process_sectors(device_context_t *ctx, const uint8_t *derived_key, uint64_t start_sector, int encrypt)
```
- **Účel**: Spracovanie sektorov disku pre šifrovanie/dešifrovanie
- **Parametre**:
  - ctx: Kontext zariadenia
  - derived_key: Odvodený kryptografický kľúč
  - start_sector: Začiatočný sektor
  - encrypt: Režim operácie (1=šifrovanie, 0=dešifrovanie)
- **Proces**:
  1. Čítanie dát v blokoch
  2. Spracovanie každého sektora pomocou AES-XTS
  3. Vynechanie sektora s hlavičkou
  4. Zápis spracovaných dát späť na zariadenie

#### header_io
```c
int header_io(device_context_t *ctx, maes_header_t *header, int isWrite)
```
- **Účel**: Manipulácia s hlavičkou na zariadení
- **Parametre**: 
  - ctx: Kontext zariadenia
  - header: Štruktúra hlavičky
  - isWrite: Režim operácie (1=zápis, 0=čítanie)
- **Proces**:
  1. Nastavenie pozície pre hlavičku (sektor 62)
  2. Čítanie alebo zápis hlavičky
  3. Pri čítaní - overenie magického reťazca a verzie

#### derive_key_from_password
```c
int derive_key_from_password(const uint8_t *password, const uint8_t salt[SALT_SIZE], uint8_t *output_key, size_t key_len)
```
- **Účel**: Odvodenie kľúča z hesla pomocou BLAKE3
- **Parametre**: 
  - password: Heslo od užívateľa
  - salt: Náhodná soľ
  - output_key: Výstupný buffer pre kľúč
  - key_len: Požadovaná dĺžka kľúča
- **Proces**:
  1. Inicializácia BLAKE3 v režime KDF
  2. Hashovanie hesla a soli
  3. Získanie výstupného kľúča požadovanej dĺžky

#### secure_clear_memory
```c
void secure_clear_memory(void *buffer, size_t size, bool free_memory)
```
- **Účel**: Bezpečné vymazanie citlivých údajov z pamäte
- **Parametre**:
  - buffer: Pointer na pamäťový blok na vymazanie
  - size: Veľkosť pamäte v bajtoch
  - free_memory: Či sa má pamäť aj uvoľniť
- **Proces**:
  1. Konverzia vstupného pointra na volatile uint8_t*
  2. Postupné prepisanie každej bunky pamäte nulou
  3. Voliteľné uvoľnenie pamäte

#### read_password
```c
void read_password(uint8_t *password, size_t max_len, const char *prompt)
```
- **Účel**: Bezpečné načítanie hesla od užívateľa bez zobrazovania znakov
- **Parametre**:
  - password: Buffer pre heslo
  - max_len: Maximálna veľkosť buffra
  - prompt: Text výzvy pre užívateľa
- **Proces**:
  - Cross-platform implementácia pre Windows (_getch) a Unix (termios.h)
  - Zobrazovanie hviezdičiek namiesto znakov hesla

#### generate_salt
```c
bool generate_salt(uint8_t *salt_buffer, size_t salt_size)
```
- **Účel**: Generovanie náhodnej soli pre KDF
- **Parametre**:
  - salt_buffer: Výstupný buffer pre soľ
  - salt_size: Požadovaná veľkosť soli
- **Proces**:
  1. Použitie generátora pseudonáhodných čísiel
  2. Naplnenie buffra náhodnými hodnotami

#### encrypt_device / decrypt_device
```c
int encrypt_device(device_context_t *ctx, const char *device_path, const uint8_t *password)
int decrypt_device(device_context_t *ctx, const uint8_t *password)
```
- **Účel**: Kompletné šifrovanie/dešifrovanie zariadenia
- **Parametre**: 
  - ctx: Kontext zariadenia
  - device_path: Cesta k zariadeniu (len pre encrypt)
  - password: Heslo od užívateľa
- **Proces**:
  1. Overenie parametrov
  2. Generovanie soli / čítanie hlavičky
  3. Odvodenie kľúča
  4. Spracovanie dát po sektoroch
  5. Uvoľnenie/vyčistenie citlivých údajov

### Bezpečnostné vlastnosti

#### 1. Ochrana proti útokom
- Unikátna soľ pre každé zariadenie
- Verifikácia hesla cez špeciálny verifikačný blok
- Ochrana proti útoku cez hlavičku

#### 2. Kryptografická bezpečnosť
- 256-bitová ekvivalentná výpočtová bezpečnosť proti útoku hrubou silou
- Bezpečné mazanie citlivých údajov z pamäte
- Unikátna bloková úprava pre každý sektor

#### 3. Odporúčania pre heslá
- Minimálna dĺžka: 8 znakov
- Použiť kombináciu:
  - Veľké písmená (A-Z)
  - Malé písmená (a-z)
  - Čísla (0-9)
  - Špeciálne znaky (!@#$%^&*)

## Bezpečnostné informácie
- Pred šifrovaním/dešifrovaním celého zariadenia vytvorte zálohu dôležitých dát
- Program vyžaduje administrátorské/root oprávnenia pre priamy prístup k zariadeniam
- Pred šifrovaním sa uistite, že zariadenie nie je pripojené v systéme
- Strata hesla znamená nezvratnú stratu dát

## Odkazy na dokumentáciu

### Štandardy
- [IEEE 1619](https://standards.ieee.org/standard/1619-2018.html)
- [NIST SP 800-38E](https://csrc.nist.gov/publications/detail/sp/800-38e/final)

### Použité knižnice
- [micro-AES](https://github.com/polfosol/micro-AES)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3)
