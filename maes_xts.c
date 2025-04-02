#include "maes_xts.h"

static ssize_t read_sectors_block(device_context_t *ctx, uint8_t *buffer,
                                  size_t max_size, uint64_t currentOffset);
static ssize_t write_sectors_block(device_context_t *ctx, uint8_t *buffer,
                                   size_t bytesToWrite,
                                   uint64_t currentOffset);

void show_progress(uint64_t current, uint64_t total, uint64_t sector_num) {
  static uint64_t last_update_time = 0;
  uint64_t current_time = time(NULL);

  if (sector_num % PROGRESS_UPDATE_INTERVAL == 0 || current >= total ||
      (total > 0 && current_time - last_update_time >= 1)) {

    float percent =
        total == 0 ? 100.0f : (float)current * 100.0f / (float)total;
    if (percent > 100.0f)
      percent = 100.0f;

    uint64_t current_mb = current / BYTES_PER_MB;
    uint64_t total_mb = total / BYTES_PER_MB;

#ifdef _WIN32
    printf(PROGRESS_FORMAT, percent, current_mb, total_mb);
#else
    printf(PROGRESS_FORMAT, percent, current_mb, total_mb);
#endif

    fflush(stdout);

    last_update_time = current_time;
  }
}

int process_sectors(device_context_t *ctx, const uint8_t *derived_key,
                    uint64_t start_sector, int encrypt) {
  const uint64_t startOffset = start_sector * SECTOR_SIZE;
  const uint64_t total_size =
#ifdef _WIN32
      (uint64_t)ctx->size.QuadPart > startOffset
          ? (uint64_t)ctx->size.QuadPart - startOffset
          : 0;
#else
      ctx->size > startOffset ? ctx->size - startOffset : 0;
#endif

  if (total_size == 0) {
    printf("Ziadne data na spracovanie (start_sector=%llu).\n",
           (unsigned long long)start_sector);
    return MAES_SUCCESS;
  }

  const size_t buffer_size = BUFFER_SIZE;
  uint8_t *buffer = allocate_aligned_buffer(buffer_size);
  if (!buffer) {
    return MAES_ERROR_MEMORY;
  }
  uint8_t original_header_sector[SECTOR_SIZE];
  bool header_saved = false;
  uint8_t tweak[MAES_TWEAK_SIZE];
  int result_code = MAES_SUCCESS;

  if (!set_position(ctx, startOffset)) {
    secure_clear_memory(buffer, buffer_size, true);
    return MAES_ERROR_IO;
  }

  uint64_t currentOffset = startOffset;
  uint64_t processed_bytes = 0;
  uint64_t current_sector_num = start_sector;
  uint64_t total_mb = total_size / BYTES_PER_MB;
  const uint64_t headerPos = (uint64_t)HEADER_SECTOR * SECTOR_SIZE;

#ifdef _WIN32
  printf("Zacinam %s %llu MB dat...\n",
         encrypt ? "sifrovanie" : "desifrovanie",
         (unsigned long long)total_mb);
#else
  printf("Zacinam %s %lu MB dat...\n",
         encrypt ? "sifrovanie" : "desifrovanie", (unsigned long)total_mb);
#endif

  while (processed_bytes < total_size) {
    size_t read_size = (total_size - processed_bytes < buffer_size)
                           ? (total_size - processed_bytes)
                           : buffer_size;
    ssize_t bytesRead =
        read_sectors_block(ctx, buffer, read_size, currentOffset);

    if (bytesRead <= 0) {
      if (bytesRead < 0) {
        report_error("Chyba pri citani dat", MAES_ERROR_IO);
        result_code = MAES_ERROR_IO;
      }
      break;
    }

    header_saved = false;
    size_t header_in_buffer_offset = 0;

    if (currentOffset <= headerPos &&
        (currentOffset + (uint64_t)bytesRead) > headerPos) {
      header_in_buffer_offset = (size_t)(headerPos - currentOffset);
      if (header_in_buffer_offset + SECTOR_SIZE <= (size_t)bytesRead) {
        printf("Ukladam a preskakujem kryptografiu pre hlavicku v bloku "
               "na off=%llu...\n",
               (unsigned long long)currentOffset);
        memcpy(original_header_sector, buffer + header_in_buffer_offset,
               SECTOR_SIZE);
        header_saved = true;
      } else {
        fprintf(stderr, "Varovanie: Vypocitany offset hlavicky mimo "
                        "hranic citaneho bloku.\n");
      }
    }

    size_t num_sectors =
        ((size_t)bytesRead + SECTOR_SIZE - 1) / SECTOR_SIZE;
    int sector_result_code = M_RESULT_SUCCESS;
    char sector_op_result;

    for (size_t i = 0; i < num_sectors; i++) {

      if (header_saved && (i == header_in_buffer_offset / SECTOR_SIZE)) {
        continue;
      }

      size_t sector_offset = i * SECTOR_SIZE;
      size_t sector_size =
          (sector_offset + SECTOR_SIZE <= (size_t)bytesRead)
              ? SECTOR_SIZE
              : ((size_t)bytesRead - sector_offset);

      if (sector_size == 0)
        continue;

      uint64_t data_unit_number = current_sector_num + i;

      memset(tweak, 0, MAES_TWEAK_SIZE);
      memcpy(tweak, &data_unit_number,
             sizeof(data_unit_number) < MAES_TWEAK_SIZE
                 ? sizeof(data_unit_number)
                 : MAES_TWEAK_SIZE);

      uint8_t *current_sector_ptr = buffer + sector_offset;

      if (encrypt) {
        sector_op_result =
            AES_XTS_encrypt(derived_key, tweak, current_sector_ptr,
                            sector_size, current_sector_ptr);
      } else {
        sector_op_result =
            AES_XTS_decrypt(derived_key, tweak, current_sector_ptr,
                            sector_size, current_sector_ptr);
      }

      if (sector_op_result != M_RESULT_SUCCESS) {
        sector_result_code = sector_op_result;
        fprintf(stderr,
                "\nChyba pocas %s (micro-AES kod: %d) v sektore %llu\n",
                encrypt ? "sifrovania" : "desifrovania",
                sector_result_code, (unsigned long long)data_unit_number);
        break;
      }
    }

    if (sector_result_code != M_RESULT_SUCCESS) {
      fprintf(stderr,
              "\nSpracovanie bloku zlyhalo (prvy sektor bloku: %llu), "
              "micro-AES kod: %d\n",
              (unsigned long long)current_sector_num, sector_result_code);
      result_code = MAES_ERROR_MICROAES;
      if (header_saved) {
        secure_clear_memory(original_header_sector, SECTOR_SIZE, false);
      }
      break;
    }

    if (header_saved) {
      printf("Obnovujem povodnu hlavicku v bloku na off=%llu...\n",
             (unsigned long long)currentOffset);
      memcpy(buffer + header_in_buffer_offset, original_header_sector,
             SECTOR_SIZE);
      secure_clear_memory(original_header_sector, SECTOR_SIZE, false);
      header_saved = false;
    }

    ssize_t bytesWritten =
        write_sectors_block(ctx, buffer, bytesRead, currentOffset);
    if (bytesWritten != bytesRead) {
      report_error("Chyba pri zapise dat", MAES_ERROR_IO);
      result_code = MAES_ERROR_IO;
      break;
    }

    processed_bytes += bytesWritten;
    currentOffset += bytesWritten;
    current_sector_num +=
        ((size_t)bytesRead + SECTOR_SIZE - 1) / SECTOR_SIZE;

    show_progress(processed_bytes, total_size,
                  current_sector_num - start_sector);
  }

  if (result_code == MAES_SUCCESS) {
    show_progress(total_size, total_size,
                  (current_sector_num - start_sector));
    printf("\n");
  }

  secure_clear_memory(buffer, buffer_size, true);
  secure_clear_memory(tweak, MAES_TWEAK_SIZE, false);
  if (header_saved) {
    secure_clear_memory(original_header_sector, SECTOR_SIZE, false);
  }

  return result_code;
}

int header_io(device_context_t *ctx, maes_header_t *header, int isWrite) {
  uint8_t *sector = allocate_aligned_buffer(SECTOR_SIZE);
  if (!sector) {
    return MAES_ERROR_MEMORY;
  }

  memset(sector, 0, SECTOR_SIZE);

  const uint64_t headerPos = (uint64_t)HEADER_SECTOR * SECTOR_SIZE;
  ssize_t bytesTransferred;
  int result = MAES_SUCCESS;

  if (!set_position(ctx, headerPos)) {
    result = MAES_ERROR_IO;
    goto cleanup;
  }

  if (isWrite) {
    if (sizeof(maes_header_t) > SECTOR_SIZE) {
      fprintf(stderr,
              "Chyba: Velkost hlavicky presahuje velkost sektora!\n");
      result = MAES_ERROR_PARAM;
      goto cleanup;
    }
    memcpy(sector, header, sizeof(maes_header_t));

    bytesTransferred = write_data(ctx, sector, SECTOR_SIZE);
    if (bytesTransferred != SECTOR_SIZE) {
      report_error("Chyba pri zapise hlavicky", MAES_ERROR_IO);
      result = MAES_ERROR_IO;
      goto cleanup;
    }

#ifdef _WIN32
    if (!FlushFileBuffers(ctx->handle)) {
      report_windows_error("Chyba pri flushovani buffera");
    }
#else
    if (fsync(ctx->fd) != 0) {
      report_error("Chyba pri fsync", 0);
    }
#endif
  } else {
    bytesTransferred = read_data(ctx, sector, SECTOR_SIZE);
    if (bytesTransferred != SECTOR_SIZE) {
      report_error("Chyba pri citani hlavicky", MAES_ERROR_IO);
      result = (bytesTransferred >= 0) ? MAES_ERROR_HEADER : MAES_ERROR_IO;
      goto cleanup;
    }

    memcpy(header, sector, sizeof(maes_header_t));

    if (memcmp(header->magic, HEADER_MAGIC, HEADER_MAGIC_SIZE) != 0 ||
        header->version != HEADER_VERSION ||
        header->encryption_type != HEADER_ENCRYPTION_TYPE ||
        header->key_bits != MAES_KEY_BITS) {
      fprintf(stderr, "Chyba: Neplatna alebo nekompatibilna hlavicka.\n");
      result = MAES_ERROR_HEADER;
    }
  }

cleanup:
  secure_clear_memory(sector, SECTOR_SIZE, true);
  return result;
}

int encrypt_device(device_context_t *ctx, const char *device_path,
                   const uint8_t *password) {
  maes_header_t header = {0};
  int result = 0;
  uint8_t derived_key[MAES_XTS_KEY_BYTES];
  bool key_derived = false;
  uint8_t plaintext_verify[VERIFICATION_BLOCK_SIZE];

  printf("Pouziva sa %d-bitove sifrovanie (micro-AES)\n", MAES_KEY_BITS);

  if (!process_user_confirmation(device_path)) {
    printf("Operacia zrusena pouzivatelom.\n");
    return 0;
  }

  memcpy(header.magic, HEADER_MAGIC, HEADER_MAGIC_SIZE);
  header.version = HEADER_VERSION;
  header.encryption_type = HEADER_ENCRYPTION_TYPE;
  header.start_sector = 0;
  header.key_bits = MAES_KEY_BITS;

  if (!generate_salt(header.salt, SALT_SIZE)) {
    fprintf(stderr, "Chyba: Nepodarilo sa vygenerovat sol.\n");
    return MAES_ERROR_SALT;
  }

  result = derive_key_from_password(password, header.salt, derived_key,
                                    MAES_XTS_KEY_BYTES);
  if (result != MAES_SUCCESS) {
    fprintf(stderr, "Chyba pri odvodzovani kluca z hesla (%d).\n", result);
    return result;
  }
  key_derived = true;

  memset(plaintext_verify, 0, VERIFICATION_BLOCK_SIZE);
  strncpy((char *)plaintext_verify, VERIFICATION_PLAINTEXT,
          VERIFICATION_BLOCK_SIZE - 1);

  printf("Sifrujem verifikacny blok...\n");
  AES_ECB_encrypt(derived_key, plaintext_verify, VERIFICATION_BLOCK_SIZE,
                  header.verification_tag);

  secure_clear_memory(plaintext_verify, VERIFICATION_BLOCK_SIZE, false);

  result = header_io(ctx, &header, 1);
  if (result != MAES_SUCCESS) {
    goto cleanup_encrypt;
  }

  result = process_sectors(ctx, derived_key, 0, ENCRYPT_MODE);

cleanup_encrypt:
  if (key_derived) {
    secure_clear_memory(derived_key, MAES_XTS_KEY_BYTES, false);
  }
  return result;
}

int decrypt_device(device_context_t *ctx, const uint8_t *password) {
  maes_header_t header = {0};
  int result = 0;
  uint8_t derived_key[MAES_XTS_KEY_BYTES];
  bool key_derived = false;
  uint8_t decrypted_verify[VERIFICATION_BLOCK_SIZE];
  uint8_t expected_verify[VERIFICATION_BLOCK_SIZE];

  result = header_io(ctx, &header, 0);
  if (result != MAES_SUCCESS) {
    fprintf(stderr, "Skontrolujte, ci je zariadenie sifrovane tymto "
                    "nastrojom a spravnou verziou.\n");
    return result;
  }

  printf("Detekovane %d-bitove sifrovanie (micro-AES) podla hlavicky.\n",
         header.key_bits);

  result = derive_key_from_password(password, header.salt, derived_key,
                                    MAES_XTS_KEY_BYTES);
  if (result != MAES_SUCCESS) {
    fprintf(stderr, "Chyba pri odvodzovani kluca z hesla (%d).\n", result);
    goto cleanup_decrypt;
  }
  key_derived = true;

  printf("Overujem heslo pomocou verifikacneho bloku...\n");
  AES_ECB_decrypt(derived_key, header.verification_tag,
                  VERIFICATION_BLOCK_SIZE, decrypted_verify);

  memset(expected_verify, 0, VERIFICATION_BLOCK_SIZE);
  strncpy((char *)expected_verify, VERIFICATION_PLAINTEXT,
          VERIFICATION_BLOCK_SIZE - 1);

  if (memcmp(decrypted_verify, expected_verify, VERIFICATION_BLOCK_SIZE) !=
      0) {
    fprintf(stderr, "Chyba: Nespravne heslo alebo poskodena hlavicka "
                    "(verifikacia zlyhala).\n");
    result = MAES_ERROR_PASSWORD;
    secure_clear_memory(decrypted_verify, VERIFICATION_BLOCK_SIZE, false);
    goto cleanup_decrypt;
  }

  secure_clear_memory(decrypted_verify, VERIFICATION_BLOCK_SIZE, false);
  secure_clear_memory(expected_verify, VERIFICATION_BLOCK_SIZE, false);
  printf("Heslo uspesne overene.\n");

  result = process_sectors(ctx, derived_key, 0, DECRYPT_MODE);

cleanup_decrypt:
  if (key_derived) {
    secure_clear_memory(derived_key, MAES_XTS_KEY_BYTES, false);
  }
  return result;
}

bool parse_arguments(int argc, char *argv[], char *mode,
                     const char **device_path) {
  if (argc < 3) {
    return false;
  }

  const char *operation = argv[1];
  *device_path = NULL;
  *mode = 0;

  if (strcmp(operation, "encrypt") == 0) {
    *mode = 'e';
  } else if (strcmp(operation, "decrypt") == 0) {
    *mode = 'd';
  } else {
    fprintf(stderr,
            "Neznamy prikaz: %s. Pouzite 'encrypt' alebo 'decrypt'.\n",
            operation);
    return false;
  }

  *device_path = argv[2];

  if (argc > 3) {
    fprintf(stderr, "Varovanie: Extra argumenty ignorovane.\n");
  }

  return true;
}

void print_usage(const char *prog_name) {
  printf("MAES-XTS Nastroj na sifrovanie diskov/oddielov (micro-AES + "
         "BLAKE3 KDF)\n");
  printf("================================================================"
         "=====\n\n");
  printf("Pouzitie:\n");
  printf("  %s encrypt <zariadenie>\n", prog_name);
  printf("  %s decrypt <zariadenie>\n", prog_name);
  printf("\nArgumenty:\n");
  printf("  encrypt        Sifrovaci mod\n");
  printf("  decrypt        Desifrovaci mod\n");
  printf("  <zariadenie>   Cesta k vstupnemu/vystupnemu zariadeniu "
         "(disk/oddiel).\n");
#ifndef _WIN32
  printf("\nPriklady:\n");
  printf("  %s encrypt /dev/sdb1\n", prog_name);
  printf("  %s decrypt /dev/sdb1\n", prog_name);
#endif
#ifdef _WIN32
  printf("  %s encrypt \\\\.\\PhysicalDrive1\n", prog_name);
  printf("  %s decrypt \\\\.\\D:\n", prog_name);
#endif
}

int derive_key_from_password(const uint8_t *password,
                             const uint8_t salt[SALT_SIZE],
                             uint8_t *output_key, size_t key_len) {
  blake3_hasher hasher;

  blake3_hasher_init_derive_key(&hasher, KDF_CONTEXT);

  blake3_hasher_update(&hasher, salt, SALT_SIZE);

  blake3_hasher_update(&hasher, password, strlen((const char *)password));

  blake3_hasher_finalize(&hasher, output_key, key_len);

  return MAES_SUCCESS;
}

void read_password(uint8_t *password, size_t max_len, const char *prompt) {
  printf("%s", prompt);
  fflush(stdout);

  size_t i = 0;
  int c;

#ifdef _WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  GetConsoleMode(hStdin, &mode);
  SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
#else
  struct termios old_term, new_term;
  tcgetattr(STDIN_FILENO, &old_term);
  new_term = old_term;
  new_term.c_lflag &= ~(ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
#endif

  while (i < max_len - 1 && (c =
#ifdef _WIN32
                                 _getch()
#else
                                 getchar()
#endif
                                 ) != EOF) {
    if (c == '\r' || c == '\n') {
      break;
    } else if ((c == '\b' || c == 127) && i > 0) {
      i--;
      printf("\b \b");
      fflush(stdout);
    } else if (c >= 32 && c < 127) {
      password[i++] = (uint8_t)c;
      printf("*");
      fflush(stdout);
    }
  }

#ifdef _WIN32
  SetConsoleMode(hStdin, mode);
#else
  tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
#endif

  password[i] = '\0';
  printf("\n");
}

bool process_user_confirmation(const char *device_path) {
  printf("UPOZORNENIE: Vsetky data na zariadeni %s budu zasifrovane!\n",
         device_path);
  printf("Tato operacia je nevratna bez spravneho hesla.\n");
  printf("Chcete pokracovat? (a/n): ");

  char confirm;
  if (scanf(" %c", &confirm) != 1) {
    fprintf(stderr, "\nChyba pri citani potvrdenia.\n");
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
      ;
    return false;
  }

  int c;
  while ((c = getchar()) != '\n' && c != EOF)
    ;

  return (confirm == 'a' || confirm == 'A' || confirm == 'y' ||
          confirm == 'Y');
}

bool process_password_input(uint8_t *password, size_t password_size,
                            int verify) {
  uint8_t confirm_password[PASSWORD_BUFFER_SIZE];

  if (verify) {
    printf("\n--------------------------------------------------\n");
    printf("BEZPECNOSTNE ODPORUCANIA PRE HESLO:\n");
    printf("--------------------------------------------------\n");
    printf("- Pouzite aspon %d znakov (dlhsie heslo = lepsie)\n",
           MIN_PASSWORD_LENGTH);
    printf("- Kombinujte VELKE a male pismena, cisla a specialne znaky\n");
    printf("- Nepouzivajte lahko uhadnutelne informacie\n");
    printf("--------------------------------------------------\n");
    printf("POZOR: Ak zabudnete heslo, data NEMOZU byt obnovene!\n");
    printf("--------------------------------------------------\n\n");
  }

  read_password(password, password_size, "Zadajte heslo: ");

  if (verify && strlen((char *)password) < MIN_PASSWORD_LENGTH) {
    printf("\n!!! VAROVANIE: Pouzivate kratke heslo (menej ako %d znakov) "
           "!!!\n",
           MIN_PASSWORD_LENGTH);
    printf("!!! Kratke hesla su lahsie prelomitelne a VYRAZNE znizuju "
           "bezpecnost !!!\n\n");
  }

  if (verify) {
    read_password(confirm_password, sizeof(confirm_password),
                  "Potvrdte heslo: ");

    if (strcmp((char *)password, (char *)confirm_password) != 0) {
      fprintf(stderr, "Chyba: Hesla sa nezhoduju.\n");
      secure_clear_memory(password, password_size, false);
      secure_clear_memory(confirm_password, sizeof(confirm_password),
                          false);
      return false;
    }
    secure_clear_memory(confirm_password, sizeof(confirm_password), false);
  }

  return true;
}

bool generate_salt(uint8_t *salt_buffer, size_t salt_size) {
#ifdef _WIN32
  srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
#else
  srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
#endif

  printf("Generujem nahodnu sol (%llu bajtov)...\n",
         (unsigned long long)salt_size);
  for (size_t i = 0; i < salt_size; ++i) {
    salt_buffer[i] = (uint8_t)(rand() % 256);
  }
  return true;
}

#ifdef _WIN32

BOOL is_admin(void) {
  BOOL isAdmin = FALSE;
  SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
  PSID AdminGroup;
  if (AllocateAndInitializeSid(
          &NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
          DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
    CheckTokenMembership(NULL, AdminGroup, &isAdmin);
    FreeSid(AdminGroup);
  }
  return isAdmin;
}

device_type_t get_device_type(const char *path) {
  return (strncmp(path, "\\\\.\\PhysicalDrive", 17) == 0)
             ? DEVICE_TYPE_DISK
             : DEVICE_TYPE_VOLUME;
}

BOOL lock_and_dismount_volume(HANDLE hDevice) {
  DWORD bytesReturned;
  if (!DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0,
                       &bytesReturned, NULL)) {
    if (GetLastError() != ERROR_ACCESS_DENIED) {
      report_windows_error("Nepodarilo sa uzamknut particiu");
      return FALSE;
    }
  }
  if (!DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0,
                       &bytesReturned, NULL)) {
    report_windows_error("Nepodarilo sa odomknut particiu");
    unlock_disk(hDevice);
    return FALSE;
  }
  return TRUE;
}

void unlock_disk(HANDLE hDevice) {
  if (hDevice != INVALID_HANDLE_VALUE) {
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0,
                         &bytesReturned, NULL)) {
      DWORD error = GetLastError();
      if (error != ERROR_NOT_LOCKED) {
        report_windows_error("Nepodarilo sa odomknut particiu");
      }
    }
  }
}

void check_volume(const char *path) {
  if (strlen(path) >= 6 && path[0] == '\\' && path[1] == '\\' &&
      path[2] == '.' && path[3] == '\\' && isalpha(path[4]) &&
      path[5] == ':') {
    printf("Pristupujem k jednotke %c:\n", path[4]);
  }
}

LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t type) {
  LARGE_INTEGER size = {0};
  DWORD bytesReturned;
  BOOL success = FALSE;

  if (type == DEVICE_TYPE_VOLUME) {
    GET_LENGTH_INFORMATION lengthInfo;
    success = DeviceIoControl(hDevice, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0,
                              &lengthInfo, sizeof(lengthInfo),
                              &bytesReturned, NULL);
    if (success) {
      size = lengthInfo.Length;
    } else {
      report_windows_error("Chyba pri zistovani velkosti particie");
    }
  } else {
    DISK_GEOMETRY_EX diskGeometry;
    success = DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                              NULL, 0, &diskGeometry, sizeof(diskGeometry),
                              &bytesReturned, NULL);
    if (success) {
      size = diskGeometry.DiskSize;
    } else {
      report_windows_error("Chyba pri zistovani velkosti disku");
    }
  }
  if (!success)
    size.QuadPart = 0;
  return size;
}

HANDLE open_device_with_retry(const char *path) {
  HANDLE handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (handle == INVALID_HANDLE_VALUE) {
    handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING,
                         FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH |
                             FILE_FLAG_RANDOM_ACCESS,
                         NULL);
  }
  return handle;
}

bool prepare_device_for_encryption(const char *path, HANDLE *handle) {
  if (!is_admin()) {
    fprintf(stderr, "Chyba: Vyzaduju sa administratorske opravnenia.\n");
    return false;
  }

  check_volume(path);

  *handle = open_device_with_retry(path);

  if (*handle == INVALID_HANDLE_VALUE) {
    report_windows_error("Zlyhalo otvorenie zariadenia");
    return false;
  }

  if (get_device_type(path) == DEVICE_TYPE_VOLUME) {
    if (!lock_and_dismount_volume(*handle)) {
      CloseHandle(*handle);
      *handle = INVALID_HANDLE_VALUE;
      return false;
    }
  }

  DWORD bytesReturned;
  if (!DeviceIoControl(*handle, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0,
                       NULL, 0, &bytesReturned, NULL)) {
  }

  return true;
}

void report_windows_error(const char *message) {
  char error_message[ERROR_BUFFER_SIZE] = {0};
  DWORD error_code = GetLastError();
  if (error_code == 0)
    return;

  FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
      error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), error_message,
      ERROR_BUFFER_SIZE - 1, NULL);
  fprintf(stderr, "%s: (%lu) %s\n", message, error_code, error_message);
}

BOOL set_file_position(HANDLE handle, LARGE_INTEGER position) {
  return SetFilePointerEx(handle, position, NULL, FILE_BEGIN);
}

#else
bool is_partition_mounted(const char *device_path) {
  FILE *mtab = fopen("/proc/mounts", "r");

  if (!mtab) {
    perror("Chyba pri otvarani /proc/mounts");
    fprintf(stderr, "Varovanie: Nepodarilo sa overit, ci je zariadenie "
                    "pripojene. Predpoklada sa, ze ano.\n");
    return true;
  }

  char line[ERROR_BUFFER_SIZE];
  bool mounted = false;

  while (fgets(line, sizeof(line), mtab)) {
    char mounted_dev[256];
    if (sscanf(line, "%255s %*s %*s %*s %*d %*d", mounted_dev) == 1) {
      size_t dev_len = strlen(device_path);
      if (strncmp(mounted_dev, device_path, dev_len) == 0 &&
          (mounted_dev[dev_len] == '\0' ||
           isspace(mounted_dev[dev_len]))) {
        mounted = true;
        break;
      }
    }
  }

  fclose(mtab);
  return mounted;
}

uint64_t get_partition_size(int fd) {
  uint64_t size = 0;
  if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
    report_error("Chyba pri zistovani velkosti particie", 0);
    return 0;
  }
  return size;
}

#endif

bool open_device(const char *path, device_context_t *ctx) {
#ifdef _WIN32
  if (!prepare_device_for_encryption(path, &ctx->handle)) {
    return false;
  }
  ctx->type = get_device_type(path);
  strncpy(ctx->path, path, MAX_PATH - 1);
  ctx->path[MAX_PATH - 1] = '\0';
  ctx->size = get_device_size(ctx->handle, ctx->type);
  if (ctx->size.QuadPart == 0) {
    close_device(ctx);
    return false;
  }
  return true;
#else
  if (geteuid() != 0) {
    fprintf(stderr, "Chyba: Vyzaduju sa root opravnenia pre priamy "
                    "pristup k zariadeniu.\n");
    return false;
  }
  if (is_partition_mounted(path)) {
    fprintf(stderr,
            "Chyba: Oddiel %s je pripojeny. Odpojte ho pred operaciou.\n",
            path);
    return false;
  }
  ctx->fd = open(path, O_RDWR | O_SYNC);
  if (ctx->fd < 0) {
    report_error("Chyba pri otvarani zariadenia", 0);
    return false;
  }
  ctx->size = get_partition_size(ctx->fd);
  if (ctx->size == 0) {
    close_device(ctx);
    return false;
  }
  return true;
#endif
}

void close_device(device_context_t *ctx) {
#ifdef _WIN32
  if (ctx->handle != INVALID_HANDLE_VALUE) {
    if (get_device_type(ctx->path) == DEVICE_TYPE_VOLUME) {
      unlock_disk(ctx->handle);
    }
    CloseHandle(ctx->handle);
    ctx->handle = INVALID_HANDLE_VALUE;
  }
#else
  if (ctx->fd >= 0) {
    close(ctx->fd);
    ctx->fd = -1;
  }
#endif
}

uint8_t *allocate_aligned_buffer(size_t size) {
  uint8_t *buffer = NULL;
#ifdef _WIN32
  buffer = (uint8_t *)_aligned_malloc(size, SECTOR_SIZE);
#else
  if (posix_memalign((void **)&buffer, SECTOR_SIZE, size) != 0) {
    buffer = NULL;
  }
#endif
  if (buffer) {
    memset(buffer, 0, size);
  } else {
    fprintf(stderr,
            "Chyba: Zlyhala alokacia zarovnaneho buffera velkosti %llu\n",
            (unsigned long long)size);
  }
  return buffer;
}

void secure_clear_memory(void *buffer, size_t size, bool free_memory) {
  if (buffer) {
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    size_t i;
    for (i = 0; i < size; ++i) {
      p[i] = 0;
    }

    if (free_memory) {
#ifdef _WIN32
      _aligned_free(buffer);
#else
      free(buffer);
#endif
    }
  }
}

bool set_position(device_context_t *ctx, uint64_t position) {
#ifdef _WIN32
  LARGE_INTEGER pos;
  pos.QuadPart = (LONGLONG)position;
  if (!set_file_position(ctx->handle, pos)) {
    report_windows_error("Chyba pri nastavovani pozicie");
    return false;
  }
#else
  if (lseek(ctx->fd, (off_t)position, SEEK_SET) == (off_t)-1) {
    report_error("Chyba pri nastavovani pozicie", 0);
    return false;
  }
#endif
  return true;
}

ssize_t read_data(device_context_t *ctx, void *buffer, size_t size) {
#ifdef _WIN32
  DWORD bytesRead = 0;
  if (!ReadFile(ctx->handle, buffer, (DWORD)size, &bytesRead, NULL)) {
    DWORD error = GetLastError();
    if (error != ERROR_HANDLE_EOF && error != ERROR_BROKEN_PIPE) {
      report_windows_error("Chyba pri citani");
    }
    return (error != 0 && error != ERROR_HANDLE_EOF &&
            error != ERROR_BROKEN_PIPE)
               ? -1
               : (ssize_t)bytesRead;
  }
  return (ssize_t)bytesRead;
#else
  ssize_t ret;
  do {
    ret = read(ctx->fd, buffer, size);
  } while (ret == -1 && errno == EINTR);
  return ret;
#endif
}

ssize_t write_data(device_context_t *ctx, const void *buffer,
                   size_t size) {
#ifdef _WIN32
  DWORD bytesWritten = 0;
  if (!WriteFile(ctx->handle, buffer, (DWORD)size, &bytesWritten, NULL)) {
    report_windows_error("Chyba pri zapise");
    return -1;
  }
  return (ssize_t)bytesWritten;
#else
  ssize_t ret;
  size_t written = 0;
  const uint8_t *buf_ptr = (const uint8_t *)buffer;
  while (written < size) {
    do {
      ret = write(ctx->fd, buf_ptr + written, size - written);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
      return -1;
    if (ret == 0) {
      fprintf(stderr, "Chyba: Zapis 0 bajtov na zariadenie.\n");
      return -1;
    }
    written += ret;
  }
  return (ssize_t)written;
#endif
}

void report_error(const char *message, int error_code) {
#ifdef _WIN32
  (void)error_code;
  report_windows_error(message);
#else
  if (error_code != 0)
    fprintf(stderr, "%s: %s\n", message, strerror(error_code));
  else
    perror(message);
#endif
}

static ssize_t read_sectors_block(device_context_t *ctx, uint8_t *buffer,
                                  size_t max_size,
                                  uint64_t currentOffset) {
  size_t bytesToRead = max_size;

#ifdef _WIN32
  uint64_t device_size = (uint64_t)ctx->size.QuadPart;
#else
  uint64_t device_size = ctx->size;
#endif

  if (currentOffset >= device_size) {
    return 0;
  }
  if (currentOffset + bytesToRead > device_size) {
    bytesToRead = device_size - currentOffset;
  }

  return read_data(ctx, buffer, bytesToRead);
}

static ssize_t write_sectors_block(device_context_t *ctx, uint8_t *buffer,
                                   size_t bytesToWrite,
                                   uint64_t currentOffset) {
  if (!set_position(ctx, currentOffset)) {
    report_error("Chyba pri nastavovani pozicie pred zapisom",
                 MAES_ERROR_IO);
    return -1;
  }
  ssize_t written = write_data(ctx, buffer, bytesToWrite);
  if (written < 0) {
    report_error("Chyba pri zapise bloku dat", MAES_ERROR_IO);
  } else if ((size_t)written != bytesToWrite) {
    fprintf(
        stderr,
        "Varovanie: Nepodarilo sa zapisat cely blok dat (%lld / %llu)\n",
        (long long)written, (unsigned long long)bytesToWrite);
  }
  return written;
}

int main(int argc, char *argv[]) {
  char mode = 0;
  const char *device_path = NULL;
  int result = MAES_ERROR_PARAM;
  uint8_t password[PASSWORD_BUFFER_SIZE];

  if (!parse_arguments(argc, argv, &mode, &device_path)) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  if (!process_password_input(password, sizeof(password), (mode == 'e'))) {
    return MAES_ERROR_PASSWORD;
  }

  device_context_t ctx = {0};
#ifdef _WIN32
  ctx.handle = INVALID_HANDLE_VALUE;
#else
  ctx.fd = -1;
#endif

  if (!open_device(device_path, &ctx)) {
    secure_clear_memory(password, sizeof(password), false);
    return EXIT_FAILURE;
  }

  if (mode == 'e') {
    result = encrypt_device(&ctx, device_path, password);
  } else {
    result = decrypt_device(&ctx, password);
  }

  close_device(&ctx);
  secure_clear_memory(password, sizeof(password), false);

  if (result == MAES_SUCCESS) {
    printf("Operacia uspesne dokoncena.\n");
    return EXIT_SUCCESS;
  } else if (result == 0) {
    printf("Operacia ukoncena (kod: %d).\n", result);
    return EXIT_SUCCESS;
  } else {
    fprintf(stderr, "Operacia zlyhala s chybovym kodom %d.\n", result);
    if (result == MAES_ERROR_HEADER) {
      fprintf(stderr, "-> Skontrolujte, ci je zariadenie sifrovane "
                      "kompatibilnou verziou nastroja.\n");
    } else if (result == MAES_ERROR_IO) {
      fprintf(
          stderr,
          "-> Skontrolujte pristupove prava a dostupnost zariadenia.\n");
    } else if (result == MAES_ERROR_MICROAES) {
      fprintf(stderr,
              "-> Chyba pocas kryptografickej operacie micro-AES.\n");
    } else if (result == MAES_ERROR_KDF) {
      fprintf(stderr, "-> Chyba pri odvodzovani kluca (KDF).\n");
    } else if (result == MAES_ERROR_PASSWORD) {
      fprintf(stderr, "-> Problem s heslom (nespravne, nezhoda, alebo "
                      "chyba pri zadavani).\n");
      fprintf(stderr,
              "-> Pri desifrovani mohlo byt zadane nespravne heslo.\n");
    } else if (result == MAES_ERROR_SALT) {
      fprintf(stderr, "-> Chyba pri generovani kryptografickej soli.\n");
    } else if (result == MAES_ERROR_PERMISSION) {
      fprintf(stderr,
              "-> Nedostatocne opravnenia pre pristup k zariadeniu.\n");
    }
    return EXIT_FAILURE;
  }
}