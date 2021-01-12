/*
 * Copyright (C) 2014 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Hello World application
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "shell.h"
#include "shell_commands.h"
#include "crypto/ciphers.h"
#include "crypto/aes.h"
#include "od.h"

static cipher_t *cipher = NULL;

static void print_printable(const uint8_t *buffer, size_t amount)
{
    for (size_t i = 0; i < amount; i++)
    {
        char c = (char)buffer[i];
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

    char *message_to_encrypt = argv[1];
    size_t message_length = strlen(message_to_encrypt);

    if (message_length > AES_BLOCK_SIZE)
    {
        printf("Message too long!\n");
        return 1;
    }

    uint8_t padded_input[AES_BLOCK_SIZE] = {0};
    memcpy(padded_input, message_to_encrypt, message_length);

    printf("Plaintext: ");
    print_printable(padded_input, AES_BLOCK_SIZE);
    printf("\n");
    od_hex_dump(padded_input, AES_BLOCK_SIZE, 0);

    uint8_t cipher_text[AES_BLOCK_SIZE] = {0};
    uint8_t decrypted_text[AES_BLOCK_SIZE] = {0};

    int err;

    if ((err = cipher_encrypt(cipher, padded_input, cipher_text)) < 0)
    {
        printf("Failed to encrypt data: %d\n", err);
        return 1;
    }

    printf("Encrypted Data: ");
    print_printable(cipher_text, AES_BLOCK_SIZE);
    printf("\n");
    od_hex_dump(cipher_text, AES_BLOCK_SIZE, 0);

    if ((err = cipher_decrypt(cipher, cipher_text, decrypted_text)) < 0)
    {
        printf("Failed to decrypt data: %d\n", err);
        return 1;
    }

    printf("Decrypted Data: ");
    print_printable(decrypted_text, AES_BLOCK_SIZE);
    printf("\n");
    od_hex_dump(decrypted_text, AES_BLOCK_SIZE, 0);

    return 0;
}

int main(void)
{
    uint8_t key[AES_KEY_SIZE] = {
        0x64, 0x52, 0x67, 0x55,
        0x6B, 0x58, 0x70, 0x32,
        0x73, 0x35, 0x75, 0x38,
        0x78, 0x2F, 0x41, 0x3F};

    cipher = malloc(sizeof(cipher_t));

    if (!cipher)
    {
        printf("Failed to allocate cipher_t\n");
        return 1;
    }

    int err;

    if ((err = cipher_init(cipher, CIPHER_AES_128, key, AES_KEY_SIZE)) < 0)
    {
        printf("Failed to initialize cipher_t: %d\n", err);

        free(cipher);
        return 1;
    }

    shell_command_t commands[] = {
        {"encrypt", "encrypt a message", encrypt_command_handler},
        {NULL, NULL, NULL}};

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    free(cipher);

    return 0;
}
