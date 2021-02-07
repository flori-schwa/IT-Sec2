#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "net/sock/udp.h"
#include "net/ipv6/addr.h"
#include "net/gnrc/netif.h"
#include "thread.h"

#include "crypto/modes/cbc.h"
#include "crypto/ciphers.h"
#include "crypto/aes.h"

#include "od.h"

#include "random.h"

static bool server_running = false;
static sock_udp_t sock;
static uint8_t key[] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};

// Erhält als Argument den Pointer zu den ersten Befehlsargument
void *_udp_server_thread(void *args)
{

    // ################### Initialisierung der cipher_t Struktur ###################
    cipher_t cipher;

    int err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

    if (err != CIPHER_INIT_SUCCESS)
    {
        return (void *)err;
    }

    // ################### Initialisieren des UDP Socket Endpoints ###################
    sock_udp_ep_t server = {
        .port = atoi(args), // Parse den Port für den UDP Server
        .family = AF_INET6  // Nutze IPv6
    };

    // ################### Initialisieren der UDP Socket ###################
    if (sock_udp_create(&sock, &server, NULL, 0) < 0)
    {
        return NULL;
    }

    // ################### Hilfstruktur ###################
    struct
    {
        size_t encrypted_data_len; // Größe der verschlüsselten Nachricht
        void *encrypted_data_buf;  // Buffer, in dem die verschlüsselte Nachricht gespeichert werden soll
        uint8_t iv[16];            // Initialisierungsvektor
        bool has_iv;               // Ob der IV schon erhalten wurde
    } server_state = {
        .encrypted_data_len = 0,
        .encrypted_data_buf = NULL,
        .has_iv = false,
    };

    server_running = true;

    printf("Success: started UDP server on port %u\n", server.port);

    // ################### Hilfsmakro, um UDP Daten zu empfangen und auf Fehler zu Prüfen ###################
#define RECV_AND_CHECK(buffer, size)                                              \
    do                                                                            \
    {                                                                             \
        int received = sock_udp_recv(&sock, buffer, size, SOCK_NO_TIMEOUT, NULL); \
                                                                                  \
        if (received < 0)                                                         \
        {                                                                         \
            printf("Error while receiving: %d\n", received);                      \
            exit(received);                                                       \
        }                                                                         \
        else if (received == 0)                                                   \
        {                                                                         \
            puts("No data received");                                             \
            exit(received);                                                       \
        }                                                                         \
    } while (0)

    // ################### Server-Endlosschleife ###################
    while (true)
    {
        // Wenn der Initialisierungsvektor noch nicht empfangen wurde
        if (!server_state.has_iv)
        {
            RECV_AND_CHECK(server_state.iv, 16); // Lese 16 Bytes von der UDP Verbindung und speichere diese im IV-Buffer ab
            server_state.has_iv = true;          // Setze das IV-Empfangen Flag auf true

            printf("Received IV: \n"); // Konsolenausgabe der IV
            od_hex_dump_ext(server_state.iv, 16, 0, 0);

            continue;
        }
        // Wenn stattdessen die Größe der Nachricht noch nicht bekannt ist
        else if (server_state.encrypted_data_len == 0)
        {
            RECV_AND_CHECK(&server_state.encrypted_data_len, sizeof(size_t)); // Empfange die Größe der verschlüsselten Nachricht

            // Kontrolliere, ob die Größe der Nachricht legal ist
            if ((server_state.encrypted_data_len % AES_BLOCK_SIZE) != 0)
            {
                printf("Received Datalength must be a multiple of %d, got: %zu (mod %d = %zu)\n",
                       AES_BLOCK_SIZE,
                       server_state.encrypted_data_len,
                       AES_BLOCK_SIZE,
                       (server_state.encrypted_data_len % AES_BLOCK_SIZE));

                exit(1);
            }

            printf("Expecting a message of size %zu\n", server_state.encrypted_data_len);

            if (server_state.encrypted_data_len != 0)
            {
                // Alloziere den Buffer für die verschlüsselte Nachricht
                server_state.encrypted_data_buf = malloc(server_state.encrypted_data_len);
            }

            continue;
        }
        else
        {
            RECV_AND_CHECK(server_state.encrypted_data_buf, server_state.encrypted_data_len); // Empfange die verschlüsselte Nachricht
            uint8_t *decrypted = malloc(server_state.encrypted_data_len);                     // Alloziere den Buffer für die entschlüsselte Nachricht

            printf("Received encrypted Data: \n");
            od_hex_dump_ext(server_state.encrypted_data_buf, server_state.encrypted_data_len, AES_BLOCK_SIZE, 0);

            // Entschlüssle die verschlüsselte Nachricht
            int err = cipher_decrypt_cbc(&cipher, server_state.iv, server_state.encrypted_data_buf, server_state.encrypted_data_len, decrypted);

            if (err < 0)
            {
                printf("Failed to decrypt data: %d\n", err);
            }
            else
            {
                printf("Decrypted Data: \n");
                od_hex_dump_ext(decrypted, server_state.encrypted_data_len, AES_BLOCK_SIZE, 0);
            }

            // Gebe die beiden Buffer wieder frei

            free(server_state.encrypted_data_buf);
            free(decrypted);

            // Bereite vor auf die nächste Nachricht

            server_state.encrypted_data_len = 0;
            server_state.has_iv = false;
        }
    }

#undef RECV_AND_CHECK

    return NULL;
}

int udp_send(int argc, char **argv)
{
    static cipher_t cipher;
    static bool init_cipher = false;

    // ################### Überprüfe Befehl auf korrekte Syntax ###################
    if (argc != 4)
    {
        printf("Usage: %s <ipv6-addr> <port> <payload>\n", argv[0]);
        return -1;
    }

    // ################### Initialisierung der cipher_t Struktur ###################
    if (!init_cipher)
    {
        int err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

        if (err != CIPHER_INIT_SUCCESS)
        {
            return err;
        }

        init_cipher = true;
    }

    // ################### Generierung des Initialisierungsvektors ###################

    uint8_t iv[16];
    random_bytes(iv, 16); // TODO: use cryptographically secure RNG

    // ################### Initialiserung des UDP Remote Endpoints ###################
    sock_udp_ep_t remote = {.family = AF_INET6};

    // Parsen der IPv6 Adresse welche als String in argv[1] gespeichert ist
    if (ipv6_addr_from_str((ipv6_addr_t *)&remote.addr, argv[1]) == NULL)
    {
        puts("Error: unable to parse destination address");
        return 1;
    }

    if (ipv6_addr_is_link_local((ipv6_addr_t *)&remote.addr))
    {
        // Wenn es sich um eine Link-Local IPv6 Addresse handelt, nehme das Erste Interface
        // gnrc_netif_iter mit NULL gibt das erste Element der Iteration zurück
        remote.netif =  (uint16_t) (gnrc_netif_iter(NULL)->pid);
    }

    // Parse den Port
    remote.port = atoi(argv[2]);

    // ################### Hilfsmakro, um Daten an den Remote-Endpoint zu shicken, überprüft automatisch auf Fehler ###################
#define SEND_AND_CHECK(buffer, size, on_err)                   \
    do                                                         \
    {                                                          \
        int sent = sock_udp_send(NULL, buffer, size, &remote); \
                                                               \
        if (sent < 0)                                          \
        {                                                      \
            printf("Could not send data: %d\n", sent);         \
            on_err return sent;                                \
        }                                                      \
    } while (0)

    // ################### Berechnen der Finalen Nachrichtengröße (auf AES_BLOCK_SIZE) gepadded ###################

    size_t input_data_len = strlen(argv[3]) + 1; // +1 für 0 Byte
    size_t n_aes_blocks = input_data_len / AES_BLOCK_SIZE;

    if ((input_data_len % AES_BLOCK_SIZE) != 0)
    {
        n_aes_blocks++;
    }

    size_t encrypted_msg_len = n_aes_blocks * AES_BLOCK_SIZE;

    // ################### Erstellen des gepaddeten Inputs ###################

    uint8_t *padded_input = (uint8_t *)calloc(n_aes_blocks, AES_BLOCK_SIZE);
    memcpy(padded_input, argv[3], input_data_len);

    // ################### Allozieren des Ausgabebuffers ###################

    uint8_t *encrypted = (uint8_t *)malloc(encrypted_msg_len);

    // ################### Verschlüsseln des gepaddeten Inputs ###################

    int err = cipher_encrypt_cbc(&cipher, iv, padded_input, encrypted_msg_len, encrypted);

    if (err < 0)
    {
        printf("Failed to encrypt data: %d\n", err);

        free(padded_input);
        free(encrypted);

        return err;
    }

    // ################### Senden des Initialisierungsvektors ###################

    printf("Sending IV:\n");
    od_hex_dump_ext(iv, 16, 0, 0);

    SEND_AND_CHECK(iv, 16, );

    // ################### Senden der Nachrichtengröße ###################

    printf("Sending message size: %zu\n", encrypted_msg_len);
    SEND_AND_CHECK(&encrypted_msg_len, sizeof(size_t),
                   free(padded_input);
                   free(encrypted););

    // ################### Senden der verschlüsselten Nachricht ###################

    printf("Sending Encrypted data:\n");
    od_hex_dump_ext(encrypted, encrypted_msg_len, AES_BLOCK_SIZE, 0);

    SEND_AND_CHECK(encrypted, encrypted_msg_len,
                   free(padded_input);
                   free(encrypted););

    // ################### Aufräumen ###################

    free(padded_input);
    free(encrypted);

#undef SEND_AND_CHECK

    return 0;
}

int udp_server(int argc, char **argv)
{
    static char server_thread_stack[THREAD_STACKSIZE_DEFAULT]; // static, damit Lifetime buffer > Lifetime der Funktion

    if (argc != 2)
    {
        puts("Usage: udps <port>");
        return -1;
    }

    if (server_running)
    {
        printf("Server already running\n");
        return -1;
    }

    kernel_pid_t server_thread = thread_create(server_thread_stack, sizeof(server_thread_stack), THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, _udp_server_thread, argv[1], "UDP Server Thread");

    if (server_thread <= KERNEL_PID_UNDEF)
    {
        printf("Failed to start server thread\n");
        return -1;
    }

    server_running = true;

    return 0;
}
