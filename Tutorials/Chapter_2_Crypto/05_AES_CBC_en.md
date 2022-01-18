# AES-CBC

The AES-ECB mode is proven to be insecure, it is recommended to use another block mode.
The problem with AES-ECB is that with the same key and the same input, the same ciphertext is always calculated.

Example:

![Unencrypted](../../resources/Tux.jpg)

After AES-ECB encryption the image looks like this:

![AES-ECB](../../resources/Tux_ecb.jpg)

In this tutorial we will look at how to encrypt data in RIOT using AES-CBC.
AES-CBC takes a so-called initialization vector (IV) as a third parameter besides the plaintext and the key.
Before the first block is encrypted, the block with the IV is XOR'd, for all other blocks the last ciphertext block is used as IV.

The same picture, now encrypted with AES-CBC, looks like this:

![AES-ECB](../../resources/Tux_secure.jpg)

## Adjusting the makefile

We add the modules `cipher_modes` and `random`:

```diff
# application name
APPLICATION = aes_cbc_example

# standard board
BOARD ?= native

USEMODULE += shell_commands  # RIOT Shell Commands
USEMODULE += shell           # RIOT Shell Module
USEMODULE += crypto_aes      # AES encryption
USEMODULE += od              # Object Dump
USEMODULE += od_string       # Object Dump String representation
+  USEMODULE += cipher_modes # Enable AES-CBC
+  USEMODULE += random       # Generate a random IV

# Path to RIOT installation
RIOTBASE ?= ${HOME}/RIOT

include $(RIOTBASE)/Makefile.include
```

## Header `crypto/modes/cbc.h`

To encrypt data with AES-CBC in our program we have to include the header `crypto/modes/cbc.h`.

The header defines the functions `cipher_encrypt_cbc` and `cipher_decrypt_cbc`.

### Function `cipher_encrypt_cbc`

```c
/**
 * @brief Encrypt data of arbitrary length in cipher block chaining mode.
 *
 * @param cipher     Already initialized cipher struct
 * @param iv         16 octet initialization vector. Must never be used more
 *                   than once for a given key.
 * @param input      pointer to input data to encrypt
 * @param input_len  length of the input data
 * @param output     pointer to allocated memory for encrypted data. It has to
 *                   be of size data_len + BLOCK_SIZE - data_len % BLOCK_SIZE.
 *
 * @return            <0 on error
 * @return            CIPHER_ERR_INVALID_LENGTH when input_len % BLOCK_SIZE != 0
 * @return            CIPHER_ERR_ENC_FAILED on internal encryption error
 * @return            otherwise number of input bytes that aren't consumed
 */
int cipher_encrypt_cbc(const cipher_t *cipher, uint8_t iv[16], const uint8_t *input,
                       size_t input_len, uint8_t *output);
```

The `cipher_encrypt_cbc` is similar to the `cipher_encrypt` function from the previous chapter.
There are a few differences:
 - The initialization vector (IV) is given as a parameter.
 - The plaintext may now be larger than an AES block (16 bytes). If the input is larger than 16 bytes, it is chained.
 - The length of the plaintext must be given and must be a multiple of the AES block size (16).
 - The output pointer must be large enough to store the entire encrypted text.
   The size of this buffer can be easily calculated by the given formula `data_len + BLOCK_SIZE - data_len % BLOCK_SIZE`.
 - The return value on successful encryption is no longer `1`,
   but the amount of bytes that were not processed from the input.

### Function `cipher_decrypt_cbc`

```c
/**
 * @brief Decrypt encrypted data in cipher block chaining mode.
 *
 * @param cipher     Already initialized cipher struct
 * @param iv         16 octet initialization vector.
 * @param input      pointer to input data to decrypt
 * @param input_len  length of the input data
 * @param output     pointer to allocated memory for plaintext data. It has to
 *                   be of size input_len.
 *
 * @return            <0 on error
 * @return            CIPHER_ERR_INVALID_LENGTH when input_len % BLOCK_SIZE != 0
 * @return            CIPHER_ERR_DEC_FAILED on internal decryption error
 * @return            otherwise number of bytes decrypted
 */
int cipher_decrypt_cbc(const cipher_t *cipher, uint8_t iv[16], const uint8_t *input,
                       size_t input_len, uint8_t *output);
```

The `cipher_decrypt_cbc` function behaves in the same way as the `cipher_decrypt` function from the previous chapter.
The only difference to `cipher_encrypt_cbc` is that the input is not encrypted but decrypted.
The return value is the number of decrypted bytes.

# Program to enc

```c
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
     * The message contains 6 times all hexadecimal digits lined up in a row.
     * This makes it easy to see in the ciphertext that the same plaintext block encrypted with CBC gives different results.
     */
    const char* message = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    /* ======== Cipher initialization ======== */

    cipher_t cipher;
    int err;

    if ((err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE)) != CIPHER_INIT_SUCCESS) {
        printf("Failed to init cipher: %d\n", err);
        return err;
    }

    /* ======== Calculating length ======== */

    int data_len = strlen(message) + 1;
    int n_required_blocks = data_len / AES_BLOCK_SIZE;

    if (data_len % AES_BLOCK_SIZE) {
        n_required_blocks++;
    }

    size_t total_len = n_required_blocks * AES_BLOCK_SIZE;

    /* ======== Create buffers ======== */

    uint8_t* input = calloc(n_required_blocks, AES_BLOCK_SIZE);
    uint8_t* output = calloc(n_required_blocks, AES_BLOCK_SIZE);
    uint8_t* decrypted = calloc(n_required_blocks, AES_BLOCK_SIZE);

    memcpy(input, message, data_len);

    /* ======== Create IV ======== */

    uint8_t iv[16] = {0};
    random_bytes(iv, 16); // IMPORTANT: In productive environment, use a cryptographically secure RNG!

    /* ======== Encryption and Decryption ======== */

    if ((err = cipher_encrypt_cbc(&cipher, iv, input, total_len, output)) < 0) {
        printf("Failed to encrypt data: %d\n", err);
        return err;
    }

        if ((err = cipher_decrypt_cbc(&cipher, iv, output, total_len, decrypted)) < 0) {
        printf("Failed to decrypt data: %d\n", err);
        return err;
    }

    /* ======== Output ======== */

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

    /* ======== Cleanup ======== */

    free(input);
    free(output);
    free(decrypted);

    return 0;
}
```

## Console output

```
IV: 00000000  13  E9  4A  77  4D  D2  F9  59  C7  21  D0  F5  24  25  1F  10  ..JwM..Y.!..$%..


Plaintext:
00000000  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000010  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000020  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000030  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000040  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000050  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000060  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  ................


Ciphertext:
00000000  AF  71  EA  E1  6D  87  EA  38  CE  14  BC  39  4E  21  88  26  .q..m..8...9N!.&
00000010  5E  E2  28  B8  8A  9B  30  2B  53  2B  11  AD  2C  8A  1F  83  ^.(...0+S+..,...
00000020  FA  86  20  33  D4  48  12  B6  D6  3E  DA  11  C7  85  C9  A8  .. 3.H...>......
00000030  8C  CE  15  F1  7A  53  B7  F8  61  5C  7C  F8  36  70  63  E3  ....zS..a\|.6pc.
00000040  20  2D  1A  A6  3F  AE  0B  B3  9B  0F  55  B9  9C  C6  29  C4   -..?.....U...).
00000050  72  83  BF  72  CE  8E  F9  E1  19  21  44  B9  E5  80  91  ED  r..r.....!D.....
00000060  F5  0C  4F  6E  13  3D  B6  E0  F5  C0  50  25  63  22  8A  AE  ..On.=....P%c"..


Decrypted Ciphertext:
00000000  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000010  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000020  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000030  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000040  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000050  30  31  32  33  34  35  36  37  38  39  41  42  43  44  45  46  0123456789ABCDEF
00000060  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  ................
```

**IV and ciphertext changes with each execution**

# Another example program

[Here](../../tutorial_code/03_example_aes_cbc_cmd) is an example program which wraps the above encryption to a single command, parameterized with a String message.

Syntax: `encrypt <message>`

To encrypt a message with spaces simply enclose the entire text in quotation marks.

Example: `encrypt "My message"`

[Back to index](../../README.md)

[Back to Part 4: AES in Electronic Codebook (ECB) mode](04_AES_ECB_en.md)

[Continue to Part 6: Excursion UDP](06_UDP_de.md)