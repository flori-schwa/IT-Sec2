#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "od.h"
#include "crypto/ciphers.h"
#include "crypto/aes.h"

static cipher_t cipher;

uint8_t *decrypt(uint8_t *buffer, size_t size)
{
    if (!buffer || size <= 0 || size % AES_BLOCK_SIZE)
    {
        return NULL; // Eingabevalidierung
    }

    // Berechne die Menge an Blöcken
    size_t amount_blocks = size / AES_BLOCK_SIZE;

    // Alloziere Speicher für die Ausgabe
    uint8_t *output = malloc(size);

    // Verschlüsseln
    int err;

    for (size_t block = 0; block < amount_blocks; block++)
    {
        size_t offset = block * AES_BLOCK_SIZE;
        err = cipher_decrypt(&cipher, buffer + offset, output + offset);

        if (err != 1)
        {
            printf("Failed to decrypt data: %d\n", err);
            exit(err);
        }
    }

    return output;
}

uint8_t *encrypt(void *buffer, size_t size, size_t *size_out)
{
    if (!buffer || !size_out)
    {
        return NULL; // Eingabevalidierung
    }

    // Berechne die Menge an Blöcken
    size_t amount_blocks = size / AES_BLOCK_SIZE;

    if (size % AES_BLOCK_SIZE)
    {
        ++amount_blocks;
    }

    // Berechnung der Eingabe und Ausgabegrößen
    *size_out = sizeof(uint8_t) * (amount_blocks * AES_BLOCK_SIZE);

    // Eingabe padden
    uint8_t *input = calloc((amount_blocks * AES_BLOCK_SIZE), sizeof(uint8_t)); // calloc initialisiert den Speicher zusätzlich mit Nullen
    memcpy((void *)input, buffer, size);

    // Alloziere Speicher für die Ausgabe
    uint8_t *output = malloc(*size_out);

    // Verschlüsseln
    int err;

    for (size_t block = 0; block < amount_blocks; block++)
    {
        size_t offset = block * AES_BLOCK_SIZE;
        err = cipher_encrypt(&cipher, input + offset, output + offset);

        if (err != 1)
        {
            printf("Failed to encrypt data: %d\n", err);
            exit(err);
        }
    }

    free(input);
    return output;
}

uint8_t *encrypt_string(char *string, size_t *size_out)
{
    return encrypt((void *)string, strlen(string) + 1, size_out);
}

int main(void)
{
    uint8_t key[] = {
        0x64, 0x52, 0x67, 0x55,
        0x6B, 0x58, 0x70, 0x32,
        0x73, 0x35, 0x75, 0x38,
        0x78, 0x2F, 0x41, 0x3F};

    int err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE_128);

    if (err != CIPHER_INIT_SUCCESS)
    {
        printf("Cipher Init failed: %d\n", err);
        exit(err);
    }

    char *message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

    size_t size;
    uint8_t *encrypted = encrypt_string(message, &size);
    uint8_t *decrypted = decrypt(encrypted, size);

    od_hex_dump_ext(message, strlen(message) + 1, AES_BLOCK_SIZE, 0);
    printf("\n");
    od_hex_dump_ext(encrypted, size, AES_BLOCK_SIZE, 0);
    printf("\n");
    od_hex_dump_ext(decrypted, size, AES_BLOCK_SIZE, 0);

    free(encrypted);
    free(decrypted);

    exit(0);
}
