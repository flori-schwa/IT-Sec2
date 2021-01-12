#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "crypto/modes/cbc.h"
#include "crypto/ciphers.h"
#include "crypto/aes.h"

#include "thread.h"
#include "shell.h"
#include "shell_commands.h"
#include "random.h"
#include "od.h"

static cipher_t *cipher_ptr;

static uint8_t key[AES_KEY_SIZE] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};

static void print_data(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        char c = data[i];
        printf("%c", isprint(c) ? c : '.');
    }
}

static int encrypt_command_handler(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Syntax: %s <message>\n", argv[0]);
        return 1;
    }

    char *msg = argv[1];
    size_t len = strlen(msg);

    size_t cipher_len = sizeof(uint8_t) * (len + (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE)));

    uint8_t *plain_text = malloc(cipher_len);
    memcpy(plain_text, msg, len);
    memset(plain_text + len, 0, cipher_len - len);

    uint8_t *cipher_text = malloc(cipher_len);

    uint8_t encrypt_iv[16] = {0};
    random_bytes(encrypt_iv, 16);

    printf("------------------------------\n");
    printf("IV: \n");
    od_hex_dump(encrypt_iv, 16, 0);

    uint8_t decrypt_iv[16] = {0};
    memcpy(decrypt_iv, encrypt_iv, 16);

    printf("Plaintext: ");
    print_data(plain_text, cipher_len);
    printf("\n");
    od_hex_dump(plain_text, cipher_len, 16);

    printf("Encrypted: \n");

    int err;

    if ((err = cipher_encrypt_cbc(cipher_ptr, encrypt_iv, plain_text, cipher_len, cipher_text)) < 0)
    {
        printf("Cipher encryption failed! (%d)\n", err);
        return 1;
    }

    od_hex_dump(cipher_text, cipher_len, 16);

    printf("Decrypted: ");

    if ((err = cipher_decrypt_cbc(cipher_ptr, decrypt_iv, cipher_text, cipher_len, plain_text)) < 0)
    {
        printf("Cipher decryption failed! (%d)\n", err);
        return 1;
    }

    print_data(plain_text, cipher_len);
    printf("\n");
    od_hex_dump(plain_text, cipher_len, 16);

    free(plain_text);
    free(cipher_text);

    return 0;
}

int main(void)
{
    cipher_t cipher;

    if (cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE) < 0)
    {
        printf("Cipher init failed!\n");
        return 1;
    }

    printf("Key: \n");
    od_hex_dump(key, AES_KEY_SIZE, 0);

    cipher_ptr = &cipher;

    shell_command_t commands[] = {
        {"encrypt", "encrypt a message", encrypt_command_handler},
        {NULL, NULL, NULL}};

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
