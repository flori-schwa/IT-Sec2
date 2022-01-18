# AES-ECB

## Adjusting the makefile

In the following program we will use the modules `shell`, `shell_commands`, `crypto_aes` and `od`


### Complete makefile

```diff
# application name
APPLICATION = aes_ecb_example

# standard board
BOARD ?= native

+  USEMODULE += shell_commands  # RIOT Shell Commands
+  USEMODULE += shell           # RIOT Shell Module
+  USEMODULE += crypto_aes      # AES encryption
+  USEMODULE += od              # Object Dump
+  USEMODULE += od_string       # Object Dump String representation

# Path to RIOT installation
RIOTBASE ?= ${HOME}/RIOT

include $(RIOTBASE)/Makefile.include
```

## Header files `crpyto/ciphers.h` and `crypto/aes.h`

In the program we will use the header files `crypto/ciphers.h` and `crypto/aes.h`.

The `ciphers.h` header file contains essential structures and functions to encrypt data with RIOT.
The most important structure is the `cipher_t` structure:

```c
/**
 * @brief basic struct for using block ciphers
 *    	contains the cipher interface and the context
 */
typedef struct {
	const cipher_interface_t *interface;    /**< BlockCipher-Interface for the Cipher-Algorithms */
	cipher_context_t context;               /**< The encryption context (buffer) for the algorithm */
} cipher_t;
```

We will not use the members of this structure per se, but `interface` is a pointer to a `cipher_interface_t` structure,
which contains information about the block size, maximum key size and function pointers to the init/encrypt and decrypt functions of the algorithm.
`cipher_context_t` is a buffer used internally by the algorithms.

We will also use the functions `cipher_init`, `cipher_encrypt` and `cipher_decrypt` from the `ciphers.h` header file:

## cipher_init

```c
/**
 * @brief Initialize new cipher state
 *
 * @param cipher        cipher struct to init (already allocated memory)
 * @param cipher_id     cipher algorithm id
 * @param key           encryption key to use
 * @param key_size      length of the encryption key
 *
 * @return CIPHER_INIT_SUCCESS if the initialization was successful.
 * @return CIPHER_ERR_BAD_CONTEXT_SIZE if CIPHER_MAX_CONTEXT_SIZE has  
 *          not been defined (which means that the cipher has not been 
 *          included in the build)
 * @return  The command may return CIPHER_ERR_INVALID_KEY_SIZE if the
 *      	key size is not valid.
 */
int cipher_init(cipher_t *cipher, cipher_id_t cipher_id,
               const uint8_t *key, uint8_t key_size);
```

The cipher_init function takes a pointer to a `cipher_t` structure, the structure may be uninitialized memory,
the function then initializes this memory with the correct context and buffer.
The second argument is a pointer to a `cipher_interface_t` structure.
In addition, the function takes the key for encryption, as well as its size.

The function returns `CIPHER_INIT_SUCCESS` if the initialization was successful,
otherwise one of the error codes `CIPHER_ERR_BAD_CONTEXT_SIZE` or `CIPHER_ERR_INVALID_KEY_SIZE`.

Example:

```c
uint8_t key[AES_KEY_SIZE] = { /* ... */ };
cipher_t cipher;

int err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

if (err != CIPHER_INIT_SUCCESS)
{
    printf("Cipher Init failed: %d\n", err);
    exit(err);
}
```

The code defines a key of size `AES_KEY_SIZE` (16).
Then creates an uninitialized `cipher_t` structure on the stack.
Calls the `cipher_init` function with the pointer to the `cipher_t` structure, 
with the cipher id `CIPHER_AES_128`, the pointer to the key and the size of the key.

The code then stores the result of the `cipher_init` call in a variable `err` and
checks if there were any errors when initializing the `cipher_t` structure.

## cipher_encrypt

```c
/**
 * @brief Encrypt data of BLOCK_SIZE length
 * *
 *
 * @param cipher    Already initialized cipher struct
 * @param input     pointer to input data to encrypt
 * @param output    pointer to allocated memory for encrypted data.
 *                  It has to be of size BLOCK_SIZE
 *
 * @return          The result of the encrypt operation of the underlying
 *                  cipher, which is always 1 in case of success
 * @return          A negative value for an error
 */
int cipher_encrypt(const cipher_t *cipher, const uint8_t *input,
               	uint8_t *output);
```

The cipher_encrypt function encrypts a data block of the block size stored in `cipher_interface_t` and takes as argument a pointer to an initialized `cipher_t` structure.
takes as argument a pointer to an initialized `cipher_t` structure,
a pointer to the plaintext buffer and a pointer to the ciphertext buffer (where the output should be written to).
The plaintext and ciphertext buffers should contain a block of the used algorithm (for AES at least 16 bytes).

The function returns 1 if the encryption was successful.

## cipher_decrypt

```c
/**
 * @brief Decrypt data of BLOCK_SIZE length
 * *
 *
 * @param cipher    Already initialized cipher struct
 * @param input     pointer to input data (of size BLOCKS_SIZE) to decrypt
 * @param output    pointer to allocated memory for decrypted data.
 *                  It has to be of size BLOCK_SIZE
 *
 * @return          The result of the decrypt operation of the underlying
 *                  cipher, which is always 1 in case of success
 * @return          A negative value for an error
 */
int cipher_decrypt(const cipher_t *cipher, const uint8_t *input,
               	uint8_t *output);
```

The `cipher_decrypt` function decrypts a data block of the block size applicable to the algorithm and
takes as argument a pointer to an initialized `cipher_t` structure, a pointer to the ciphertext,
to be decrypted and a pointer to a buffer,
into which the decrypted plaintext is to be written.

Analogous to its "sister function", the value 1 is returned on successful decryption.

## Program to encrypt a short (max. 15 characters) message

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "crypto/ciphers.h"
#include "crypto/aes.h"
#include "od.h"

int main(void)
{
	// Key for AES algorithm
	uint8_t key[AES_KEY_SIZE] = {
    	0x64, 0x52, 0x67, 0x55,
    	0x6B, 0x58, 0x70, 0x32,
    	0x73, 0x35, 0x75, 0x38,
    	0x78, 0x2F, 0x41, 0x3F};

	cipher_t cipher;
	int err;

	// Initializing the cipher_t structure
	if ((err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE)) != CIPHER_INIT_SUCCESS)
	{
    	     printf("Failed to initialize cipher_t: %d\n", err);
    	     exit(err);
	}

	uint8_t input[AES_BLOCK_SIZE] = {0};  // Initialize input buffer with zeros
	uint8_t output[AES_BLOCK_SIZE] = {0}; // Initialize output buffer with zeros

	sprintf((char *)input, "Testnachricht"); // Write message into input buffer

	// Encrypting the input
	if ((err = cipher_encrypt(&cipher, input, output)) != 1)
	{
    	     printf("Failed to encrypt data: %d\n", err);
    	     exit(err);
	}


       // Buffer output in hexadecimal and output of printable characters in ASCII
	printf("Plaintext: \t");
	od_hex_dump_ext(input, AES_BLOCK_SIZE, 0, 0);
	printf("Ciphertext: \t");
	od_hex_dump_ext(output, AES_BLOCK_SIZE, 0, 0);

	// Decrypt the encrypted input,
       // by swapping input and output,
       // the encrypted text is written back to the input buffer,
       // which should not change.
	if ((err = cipher_decrypt(&cipher, output, input)) != 1)
	{
    	     printf("Failed to decrypt data: %d\n", err);
    	     exit(err);
	}

	printf("Decrypted ciphertext: \t");
	od_hex_dump_ext(input, AES_BLOCK_SIZE, 0, 0);

	exit(0);
}
```

For the output we get:

```
Plaintext:     54 65 73 74 6E 61 63 68 72 69 63 68 74 00 00 00  Testnachricht...
Ciphertext:    BC 4E DC 18 20 A9 EB 57 59 0F 76 C0 DC 9D 5A B9  .N.. ..WY.v...Z.
Decrypted:	   54 65 73 74 6E 61 63 68 72 69 63 68 74 00 00 00  Testnachricht...
```

[Back to index](../../README.md)

[Back to Chapter 1: Basics, Part 3: Shell Commands](../Kapitel_1_Grundlagen/03_ShellCommands_de.md)

[Continue to Part 5: AES in Cipher Block Chaining (CBC) mode](05_AES_CBC_en.md)