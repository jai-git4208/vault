#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>

#define VAULT_FILE ".vault"
#define MAGIC "VAULT"
#define MAGIC_LEN 5
#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32
#define ITERATIONS 100000
#define MAX_BUFFER 65536

// ANSI Color Codes
#define C_RESET "\033[0m"
#define C_RED "\033[1;31m"
#define C_GREEN "\033[1;32m"
#define C_YELLOW "\033[1;33m"
#define C_BLUE "\033[1;34m"
#define C_MAGENTA "\033[1;35m"
#define C_CYAN "\033[1;36m"
#define C_WHITE "\033[1;37m"
#define C_DIM "\033[2m"

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

void secure_clear(void *ptr, size_t size) {
  if (ptr == NULL)
    return;
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (size--) {
    *p++ = 0;
  }
}

int derive_key(const char *password, const unsigned char *salt,
               unsigned char *key) {
  if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, ITERATIONS,
                         EVP_sha256(), KEY_LEN, key)) {
    return 0;
  }
  return 1;
}

int vault_encrypt(unsigned char *plaintext, int plaintext_len,
                  unsigned char *key, unsigned char *iv,
                  unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handle_errors();
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handle_errors();
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handle_errors();
  ciphertext_len = len;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handle_errors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int vault_decrypt(unsigned char *ciphertext, int ciphertext_len,
                  unsigned char *key, unsigned char *iv,
                  unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handle_errors();
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handle_errors();
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return -1;
  plaintext_len = len;
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    return -1;
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

char *load_decrypted_vault(const char *password, unsigned char *out_salt) {
  FILE *f = fopen(VAULT_FILE, "rb");
  if (!f)
    return NULL;

  char magic[MAGIC_LEN];
  if (fread(magic, 1, MAGIC_LEN, f) != MAGIC_LEN ||
      memcmp(magic, MAGIC, MAGIC_LEN) != 0) {
    fclose(f);
    return NULL;
  }

  unsigned char salt[SALT_LEN];
  unsigned char iv[IV_LEN];
  if (fread(salt, 1, SALT_LEN, f) != SALT_LEN) {
    fclose(f);
    return NULL;
  }
  if (fread(iv, 1, IV_LEN, f) != IV_LEN) {
    fclose(f);
    return NULL;
  }
  if (out_salt)
    memcpy(out_salt, salt, SALT_LEN);

  unsigned char ciphertext[MAX_BUFFER];
  int ciphertext_len = fread(ciphertext, 1, MAX_BUFFER, f);
  fclose(f);

  unsigned char key[KEY_LEN];
  if (!derive_key(password, salt, key)) {
    secure_clear(ciphertext, MAX_BUFFER);
    return NULL;
  }

  unsigned char *plaintext = malloc(MAX_BUFFER);
  int plaintext_len =
      vault_decrypt(ciphertext, ciphertext_len, key, iv, plaintext);

  secure_clear(key, KEY_LEN);
  secure_clear(ciphertext, MAX_BUFFER);

  if (plaintext_len < 0) {
    free(plaintext);
    return NULL;
  }
  plaintext[plaintext_len] = '\0';
  return (char *)plaintext;
}

void save_encrypted_vault(const char *password, const char *decrypted_data,
                          const unsigned char *existing_salt) {
  unsigned char salt[SALT_LEN];
  if (existing_salt) {
    memcpy(salt, existing_salt, SALT_LEN);
  } else {
    if (!RAND_bytes(salt, SALT_LEN))
      handle_errors();
  }

  unsigned char iv[IV_LEN];
  if (!RAND_bytes(iv, IV_LEN))
    handle_errors();

  unsigned char key[KEY_LEN];
  if (!derive_key(password, salt, key))
    handle_errors();

  unsigned char ciphertext[MAX_BUFFER];
  int ciphertext_len =
      vault_encrypt((unsigned char *)decrypted_data, strlen(decrypted_data),
                    key, iv, ciphertext);

  secure_clear(key, KEY_LEN);

  FILE *f = fopen(VAULT_FILE, "wb");
  if (!f) {
    perror("Failed to open vault for writing");
    exit(1);
  }
  fwrite(MAGIC, 1, MAGIC_LEN, f);
  fwrite(salt, 1, SALT_LEN, f);
  fwrite(iv, 1, IV_LEN, f);
  fwrite(ciphertext, 1, ciphertext_len, f);
  fclose(f);
}

void get_password(char *pass, size_t size) {
  if (!readpassphrase("Enter master password: ", pass, size, RPP_ECHO_OFF)) {
    fprintf(stderr, "Error reading password\n");
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf(C_CYAN "Usage: " C_WHITE "vault " C_YELLOW
                  "<init|add|list|get|delete>" C_RESET " [args]\n");
    return 1;
  }

  // 1. Disable core dumps
  struct rlimit limit;
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &limit) != 0) {
    fprintf(stderr, C_DIM "Warning: Failed to disable core dumps" C_RESET "\n");
  }

  char *command = argv[1];

  // 2. Lock password buffer in memory to prevent swapping
  char password[256];
  if (mlock(password, sizeof(password)) != 0) {
    fprintf(stderr,
            C_DIM "Warning: Failed to lock password buffer" C_RESET "\n");
  }

  if (strcmp(command, "init") == 0) {
    get_password(password, sizeof(password));
    save_encrypted_vault(password, "", NULL);
    secure_clear(password, sizeof(password));
    printf(C_GREEN "✓ Vault initialized." C_RESET "\n");
    return 0;
  }

  // All other commands require loading the vault
  get_password(password, sizeof(password));
  unsigned char salt[SALT_LEN];
  char *data = load_decrypted_vault(password, salt);
  if (!data) {
    fprintf(
        stderr, C_RED
        "✗ Failed to load vault. Incorrect password or corrupted file." C_RESET
        "\n");
    return 1;
  }

  if (strcmp(command, "add") == 0) {
    if (argc != 5) {
      printf(C_CYAN "Usage: " C_WHITE "vault add " C_YELLOW
                    "<service> <user> <pass>" C_RESET "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    char *new_data = malloc(strlen(data) + strlen(argv[2]) + strlen(argv[3]) +
                            strlen(argv[4]) + 10);
    sprintf(new_data, "%s%s %s %s\n", data, argv[2], argv[3], argv[4]);
    save_encrypted_vault(password, new_data, salt);
    printf(C_GREEN "✓ Added entry for " C_CYAN "%s" C_RESET "\n", argv[2]);
    secure_clear(new_data, strlen(new_data));
    free(new_data);
  } else if (strcmp(command, "list") == 0) {
    printf(C_MAGENTA "📦 Stored services:" C_RESET "\n");
    char *line = strtok(data, "\n");
    int count = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3) {
        printf(C_BLUE "  •" C_RESET " %s\n", s);
        count++;
        secure_clear(p, sizeof(p));
      }
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (count == 0)
      printf(C_DIM "  (empty)" C_RESET "\n");
  } else if (strcmp(command, "get") == 0) {
    if (argc != 3) {
      printf(C_CYAN "Usage: " C_WHITE "vault get " C_YELLOW "<service>" C_RESET
                    "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    char *line = strtok(data, "\n");
    int found = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3 && strcmp(s, argv[2]) == 0) {
        printf(C_CYAN "Service:  " C_WHITE "%s" C_RESET "\n", s);
        printf(C_CYAN "Username: " C_WHITE "%s" C_RESET "\n", u);
        printf(C_CYAN "Password: " C_GREEN "%s" C_RESET "\n", p);
        found = 1;
        secure_clear(p, sizeof(p));
        secure_clear(s, sizeof(s));
        secure_clear(u, sizeof(u));
        break;
      }
      secure_clear(p, sizeof(p));
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (!found)
      printf(C_YELLOW "⚠ No entry found for " C_WHITE "%s" C_RESET "\n",
             argv[2]);
  } else if (strcmp(command, "delete") == 0) {
    if (argc != 3) {
      printf(C_CYAN "Usage: " C_WHITE "vault delete " C_YELLOW
                    "<service>" C_RESET "\n");
      secure_clear(data, strlen(data));
      free(data);
      secure_clear(password, sizeof(password));
      return 1;
    }
    char *new_data = calloc(1, MAX_BUFFER);
    char *line = strtok(data, "\n");
    int deleted = 0;
    while (line) {
      char s[256], u[256], p[256];
      if (sscanf(line, "%s %s %s", s, u, p) == 3 && strcmp(s, argv[2]) == 0) {
        deleted = 1;
      } else {
        strcat(new_data, line);
        strcat(new_data, "\n");
      }
      secure_clear(p, sizeof(p));
      secure_clear(s, sizeof(s));
      secure_clear(u, sizeof(u));
      line = strtok(NULL, "\n");
    }
    if (deleted) {
      save_encrypted_vault(password, new_data, salt);
      printf(C_GREEN "✓ Deleted entry for " C_CYAN "%s" C_RESET "\n", argv[2]);
    } else {
      printf(C_YELLOW "⚠ No entry found for " C_WHITE "%s" C_RESET "\n",
             argv[2]);
    }
    free(new_data);
  } else {
    printf(C_RED "✗ Unknown command: " C_WHITE "%s" C_RESET "\n", command);
    secure_clear(data, strlen(data));
    free(data);
    secure_clear(password, sizeof(password));
    return 1;
  }

  secure_clear(data, strlen(data));
  free(data);
  secure_clear(password, sizeof(password));
  return 0;
}
