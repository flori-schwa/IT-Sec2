#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "thread.h"
#include "shell.h"
#include "shell_commands.h"
#include "crypto/ciphers.h"
#include "crypto/aes.h"
#include "od.h"

static cipher_t *cipher_ptr;

static uint8_t key[AES_KEY_SIZE] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};
static uint8_t plain_text[AES_BLOCK_SIZE] = {0};
static uint8_t cipher_text[AES_BLOCK_SIZE] = {0};

static int encrypt_command_handler(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Syntax: %s <message>\n", argv[0]);
        return 1;
    }

    char *msg = argv[1];
    size_t len = strlen(msg);

    int n_blocks = (len / AES_BLOCK_SIZE) + (len % AES_BLOCK_SIZE ? 1 : 0);

    for (int block = 0; block < n_blocks; block++)
    {
        memcpy(plain_text, msg + block * AES_BLOCK_SIZE, (block < (n_blocks - 1) ? AES_BLOCK_SIZE : len % AES_BLOCK_SIZE));

        if (block == (n_blocks - 1))
        {
            memset(plain_text + (len % AES_BLOCK_SIZE), 0, AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE));
        }

        printf("------------------------------\n");
        printf("Block #%d\n", block);

        printf("Plaintext: \"");

        for (int i = 0; i < AES_BLOCK_SIZE; i++)
        {
            char c = plain_text[i];
            printf("%c", isprint(c) ? c : '.');
        }

        printf("\"\n");

        od_hex_dump(plain_text, AES_BLOCK_SIZE, 0);

        if (cipher_encrypt(cipher_ptr, plain_text, cipher_text) < 0)
        {
            printf("Cipher encryption failed!\n");
            return 1;
        }

        printf("Encrypted: \n");
        od_hex_dump(cipher_text, AES_BLOCK_SIZE, 0);

        if (cipher_decrypt(cipher_ptr, cipher_text, plain_text) < 0)
        {
            printf("Cipher decryption failed!\n");
            return 1;
        }

        printf("Decrypted: \"");

        for (int i = 0; i < AES_BLOCK_SIZE; i++)
        {
            char c = plain_text[i];
            printf("%c", isprint(c) ? c : '.');
        }

        printf("\"\n");

        od_hex_dump(plain_text, AES_BLOCK_SIZE, 0);
    }

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
