#include <stdio.h>

#include "crypto/ciphers.h"
#include "crypto/aes.h"
#include "crypto/modes/cbc.h"

#include "od.h"

#include "random.h"

static const uint8_t key[] = {
        0x64, 0x52, 0x67, 0x55,
        0x6B, 0x58, 0x70, 0x32,
        0x73, 0x35, 0x75, 0x38,
        0x78, 0x2F, 0x41, 0x3F};

int main(void)
{
    /*
     * Die Nachricht enthält 6 mal alle Hexadezimalen Ziffern hintereinander aufgereiht.
     * Dadurch kann man im Ciphertext gut erkennen, dass derselbe Klartextblock mit CBC verschlüsselt unterschiedliche Ergebnisse liefert.
     */
    const char* message = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    /* ======== Initialisierung des Ciphers ======== */

    cipher_t cipher;
    int err;

    if ((err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE_128)) != CIPHER_INIT_SUCCESS) {
        printf("Failed to init cipher: %d\n", err);
        return err;
    }

    /* ======== Berechnen der Längen ======== */

    int data_len = strlen(message) + 1;
    int n_required_blocks = data_len / AES_BLOCK_SIZE;

    if (data_len % AES_BLOCK_SIZE) {
        n_required_blocks++;
    }

    size_t total_len = n_required_blocks * AES_BLOCK_SIZE;

    /* ======== Erstellen der Buffer ======== */

    uint8_t* input = calloc(n_required_blocks, AES_BLOCK_SIZE);
    uint8_t* output = calloc(n_required_blocks, AES_BLOCK_SIZE);
    uint8_t* decrypted = calloc(n_required_blocks, AES_BLOCK_SIZE);

    memcpy(input, message, data_len);

    /* ======== Erstellen des IV  ======== */

    uint8_t iv[16] = {0};
    random_bytes(iv, 16); // WICHTIG: In Produktionscode, einen kryptographisch sicheren RNG nehmen!

    /* ======== Verschlüsseln und Entschlüsseln  ======== */

    if ((err = cipher_encrypt_cbc(&cipher, iv, input, total_len, output)) < 0) {
        printf("Failed to encrypt data: %d\n", err);
        return err;
    }

        if ((err = cipher_decrypt_cbc(&cipher, iv, output, total_len, decrypted)) < 0) {
        printf("Failed to decrypt data: %d\n", err);
        return err;
    }

    /* ======== Ausgabe ======== */

    printf("IV: ");
    od_hex_dump(iv, 16, 0);
    printf("\n\n");

    printf("Plaintext:\n");
    od_hex_dump(input, total_len, AES_BLOCK_SIZE);
    printf("\n\n");

    printf("Ciphertext:\n");
    od_hex_dump(output, total_len, AES_BLOCK_SIZE);
    printf("\n\n");

    printf("Decrypted Ciphertext:\n");
    od_hex_dump(input, total_len, AES_BLOCK_SIZE);
    printf("\n\n");

    /* ======== Aufräumen ======== */

    free(input);
    free(output);
    free(decrypted);

    return 0;
}
