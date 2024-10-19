#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define AES_KEY_LENGTH 32
#define AES_IV_LENGTH 16
#define BUFFER_SIZE 4096
#define SALT_LENGTH 32

typedef struct {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[AES_KEY_LENGTH];
    unsigned char iv[AES_IV_LENGTH];
    unsigned char salt[SALT_LENGTH];
} crypto_ctx_t;

static void handle_errors(const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static void secure_zero_memory(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

static crypto_ctx_t *init_crypto_context(const char *password) {
    crypto_ctx_t *crypto = malloc(sizeof(crypto_ctx_t));
    if (!crypto) handle_errors("Failed to allocate crypto context");

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (!RAND_bytes(crypto->salt, SALT_LENGTH)) {
        handle_errors("Failed to generate salt");
    }

    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           crypto->salt, SALT_LENGTH,
                           10000,
                           EVP_sha256(),
                           AES_KEY_LENGTH + AES_IV_LENGTH,
                           crypto->key)) {
        handle_errors("Key derivation failed");
    }

    memcpy(crypto->iv, crypto->key + AES_KEY_LENGTH, AES_IV_LENGTH);

    crypto->ctx = EVP_CIPHER_CTX_new();
    if (!crypto->ctx) {
        secure_zero_memory(crypto, sizeof(crypto_ctx_t));
        free(crypto);
        handle_errors("Failed to create cipher context");
    }

    return crypto;
}

static void cleanup_crypto_context(crypto_ctx_t *crypto) {
    if (crypto) {
        EVP_CIPHER_CTX_free(crypto->ctx);
        secure_zero_memory(crypto, sizeof(crypto_ctx_t));
        free(crypto);
    }
    EVP_cleanup();
    ERR_free_strings();
}

static int encrypt_file(FILE *input, FILE *output, crypto_ctx_t *crypto) {
    unsigned char buffer[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, len, ciphertext_len;

    if (fwrite(crypto->salt, 1, SALT_LENGTH, output) != SALT_LENGTH) {
        return -1;
    }

    if (!EVP_EncryptInit_ex(crypto->ctx, EVP_aes_256_gcm(), NULL, crypto->key, crypto->iv)) {
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input)) > 0) {
        if (!EVP_EncryptUpdate(crypto->ctx, ciphertext, &len, buffer, bytes_read)) {
            return -1;
        }
        if (fwrite(ciphertext, 1, len, output) != len) {
            return -1;
        }
    }

    if (!EVP_EncryptFinal_ex(crypto->ctx, ciphertext, &len)) {
        return -1;
    }
    if (fwrite(ciphertext, 1, len, output) != len) {
        return -1;
    }

    unsigned char tag[16];
    if (!EVP_CIPHER_CTX_ctrl(crypto->ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        return -1;
    }
    if (fwrite(tag, 1, 16, output) != 16) {
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input file> <output file> <password>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *input = fopen(argv[1], "rb");
    if (!input) {
        fprintf(stderr, "Error opening input file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    FILE *output = fopen(argv[2], "wb");
    if (!output) {
        fprintf(stderr, "Error opening output file: %s\n", strerror(errno));
        fclose(input);
        return EXIT_FAILURE;
    }

    crypto_ctx_t *crypto = init_crypto_context(argv[3]);
    
    if (encrypt_file(input, output, crypto) != 0) {
        handle_errors("Encryption failed");
    }

    cleanup_crypto_context(crypto);
    fclose(input);
    fclose(output);

    return EXIT_SUCCESS;
}
