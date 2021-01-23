#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "net/sock/udp.h"
#include "net/ipv6/addr.h"
#include "thread.h"

#include "crypto/modes/cbc.h"
#include "crypto/ciphers.h"
#include "crypto/aes.h"

#include "od.h"

#include "random.h"

#define SERVER_BUFFER_SIZE AES_BLOCK_SIZE

static bool server_running = false;
static sock_udp_t sock;
static uint8_t key[] = {
    0x64, 0x52, 0x67, 0x55,
    0x6B, 0x58, 0x70, 0x32,
    0x73, 0x35, 0x75, 0x38,
    0x78, 0x2F, 0x41, 0x3F};

// Erhält als Argument den Pointer zu den ersten Befehlsargument
void *_udp_server(void *args)
{
    cipher_t cipher;

    int err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

    if (err != CIPHER_INIT_SUCCESS)
    {
        return (void *)err;
    }

    // Initialisieren des UDP Socket Endpoints
    sock_udp_ep_t server = {
        .port = atoi(args), // Parse den Port für den UDP Server
        .family = AF_INET6  // Nutze IPv6
    };

    // Initialisieren der UDP Socket
    if (sock_udp_create(&sock, &server, NULL, 0) < 0)
    {
        return NULL;
    }

    server_running = true;
    uint8_t receive_data_buffer[SERVER_BUFFER_SIZE]; // Buffer zum Empfangen von Nachrichten

    printf("Success: started UDP server on port %u\n", server.port);

    uint8_t iv[16] = {0};
    bool got_iv = false;

    uint8_t *encrypted = NULL;
    size_t block = 0;

    while (true)
    {

        int received = sock_udp_recv(
            &sock,
            receive_data_buffer,
            SERVER_BUFFER_SIZE,
            SOCK_NO_TIMEOUT,
            NULL);

        // Annahme: Nur ein Client, bei mehreren Clients muss sich der IV für jede IP:Port Kombination gemerkt werden

        if (received < 0)
        {
            printf("Error while receiving: %d\n", received);
            continue;
        }
        else if (received == 0)
        {
            puts("No data received");
            continue;
        }
        else
        {
            printf("Read %d Bytes\n", received);
        }

        if (got_iv)
        {
            bool is_term = true;

            for (int i = 0; i < AES_BLOCK_SIZE; i++)
            {
                if (receive_data_buffer[i])
                {
                    is_term = false;
                    break;
                }
            }

            if (!is_term)
            {
                printf("Received Encrypted Data Block:\n");
                od_hex_dump_ext(receive_data_buffer, SERVER_BUFFER_SIZE, 0, 0);

                if (!encrypted)
                {
                    encrypted = (uint8_t *)malloc(AES_BLOCK_SIZE);
                    block = 0;
                }
                else
                {
                    encrypted = realloc(encrypted, (block + 1) * AES_BLOCK_SIZE);
                }

                memcpy(encrypted + block * AES_BLOCK_SIZE, receive_data_buffer, AES_BLOCK_SIZE);
                block++;
            }
            else
            {
                uint8_t* decrypted = malloc(block * AES_BLOCK_SIZE);
                int err = cipher_decrypt_cbc(&cipher, iv, encrypted, block * AES_BLOCK_SIZE, decrypted);

                if (err < 0)
                {
                    printf("Failed to decrypt data: %d\n", err);
                }
                else
                {
                    printf("Decrypted:\n");
                    od_hex_dump_ext(decrypted, block * AES_BLOCK_SIZE, 0, 0);
                }

                free(decrypted);
                free(encrypted);

                encrypted = NULL;
                got_iv = false;
            }
        }
        else
        {
            printf("Received IV:\n");
            od_hex_dump_ext(receive_data_buffer, 16, 0, 0);
            memcpy(iv, receive_data_buffer, 16);
            got_iv = true;
        }
    }

    return NULL;
}

int udp_send(int argc, char **argv)
{
    static cipher_t cipher;
    static bool init_cipher = false;

    if (!init_cipher)
    {
        int err = cipher_init(&cipher, CIPHER_AES_128, key, AES_KEY_SIZE);

        if (err != CIPHER_INIT_SUCCESS)
        {
            return err;
        }

        init_cipher = true;
    }

    uint8_t iv[16] = {0};
    random_bytes(iv, 16);

    sock_udp_ep_t remote = {.family = AF_INET6};

    if (argc != 4)
    {
        puts("Usage: udp <ipv6-addr> <port> <payload>");
        return -1;
    }

    if (ipv6_addr_from_str((ipv6_addr_t *)&remote.addr, argv[1]) == NULL)
    {
        puts("Error: unable to parse destination address");
        return 1;
    }

    if (ipv6_addr_is_link_local((ipv6_addr_t *)&remote.addr))
    {
        /* choose first interface when address is link local */
        gnrc_netif_t *netif = gnrc_netif_iter(NULL);
        remote.netif = (uint16_t)netif->pid;
    }

    remote.port = atoi(argv[2]);

    printf("Sending IV:\n");
    od_hex_dump_ext(iv, 16, 0, 0);

    int sent = sock_udp_send(NULL, iv, 16, &remote);

    if (sent < 0)
    {
        printf("Could not send IV\n");
        return sent;
    }

    size_t data_len = strlen(argv[3]) + 1; // +1 für 0 Byte
    size_t blocks = data_len / AES_BLOCK_SIZE;

    if (data_len % AES_BLOCK_SIZE)
    {
        blocks++;
    }

    uint8_t *padded_input = (uint8_t *)calloc(blocks, AES_BLOCK_SIZE);
    memcpy(padded_input, argv[3], data_len);

    uint8_t *encrypted = (uint8_t *)malloc(blocks * AES_BLOCK_SIZE);

    int err = cipher_encrypt_cbc(&cipher, iv, padded_input, blocks * AES_BLOCK_SIZE, encrypted);

    if (err < 0)
    {
        printf("Failed to encrypt data: %d\n", err);

        free(padded_input);
        free(encrypted);

        return err;
    }

    printf("Sending Encrypted data:\n");
    od_hex_dump_ext(encrypted, blocks * AES_BLOCK_SIZE, 0, 0);

    for (size_t block = 0; block < blocks; block++)
    {
        sent = sock_udp_send(NULL, encrypted + (block * AES_BLOCK_SIZE), AES_BLOCK_SIZE, &remote);

        if (sent < 0)
        {
            printf("Failed to send encrypted data\n");

            free(padded_input);
            free(encrypted);

            return -1;
        }
    }

    printf("Sending Termination Block\n");

    uint8_t term[AES_BLOCK_SIZE] = {0};
    sent = sock_udp_send(NULL, term, AES_BLOCK_SIZE, &remote);

    if (sent < 0)
    {
        printf("Failed to send termination block\n");

        free(padded_input);
        free(encrypted);

        return -1;
    }

    free(padded_input);
    free(encrypted);

    return 0;
}

int udp_server(int argc, char **argv)
{
    static char server_thread_stack[THREAD_STACKSIZE_DEFAULT];

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

    kernel_pid_t server_thread = thread_create(server_thread_stack, sizeof(server_thread_stack), THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, _udp_server, argv[1], "UDP Server");

    if (server_thread <= KERNEL_PID_UNDEF)
    {
        printf("Failed to start server\n");
        return -1;
    }

    server_running = true;

    return 0;
}
