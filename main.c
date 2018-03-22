/**
 * @file main.c
 * @author Rune Krauss
 * @author Marvin Hindmarsh
 *
 * Counter with CBC-MAC (CCM) is an operating mode (for more blocks) for AES and was
 * implemented according to RFC3610 (https://tools.ietf.org/html/rfc3610). CCM is
 * defined for 128 bit blocks. In principle, OpenSSL applies the AES algorithm to blocks.
 * There are phases like addRoundKey, subBytes, shiftRows and mixColumns.
 */
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include "helper.h"
#include "ccm.h"

#define BUF_SIZE 1024
#define USAGE_MSG "Usage: ccm -d|-e [-h] <key> <nonce>"
#define ALLOC_MSG "Failed to allocate content"
#define REALLOC_MSG "Usage: ccm -d|-e [-h] <key> <nonce>"
#define ERR_STDIN "Error while reading from stdin"

/**
 * Handles forwarded input stream (stdin) such as the text to encrypt from the console.
 * By default, a length of 1024 applies whereby with a length > 1024 further memory is allocated.
 *
 * @param len Message length
 * @return Treated input stream
 */
uint8_t *read_standard_input(int* len) {
    char buffer[BUF_SIZE];
    int content_size = 1;
    char *content = calloc(BUF_SIZE, sizeof(char));
    if (content == NULL) fail(ALLOC_MSG);
    // Null-Terminierung setzen
    content[0] = '\0';
    while (fgets(buffer, BUF_SIZE, stdin))
    {
        char *old_content = content;
        content_size += strlen(buffer);
        content = realloc(content, content_size);
        if (content == NULL)
        {
            free(old_content);
            fail(REALLOC_MSG);
        }
        strcat(content, buffer);
    }
    if (ferror(stdin))
    {
        free(content);
        fail(ERR_STDIN);
    }
#ifdef DEBUG
    printf("length:%d\n", content_size);
    printf("content:%s\n", content);
#endif
    *len = content_size -1;
    return (uint8_t*) content;
}

/**
 * Starting point of the application. In addition to conventional text, hexadecimal
 * values are also supported using the -h parameter because not all characters can
 * be entered in ASCII in the console. The respective options are parsed using getopt().
 *
 * @param argc Number of parameters (4 or 5)
 * @param argv Arguments: ccm -d|-e [-h] <key> <nonce> < plaintext > ciphertext for de- and encryption
 * @return Status
 */
int main(int argc, char *argv[]) {
    int opt;
    bool h, e, d;
    h = false;
    e = false;
    d = false;
    while ((opt = getopt(argc, argv, "edh")) != -1)
    {
        switch (opt)
        {
            case 'h':
                h = true;
                break;
            case 'e':
                e = true;
                break;
            case 'd':
                d = true;
                break;
            default:
                fail(USAGE_MSG);
                break;
        }
    }
    if (!(e ^ d)) fail(USAGE_MSG);
    uint8_t *key = calloc(BLK_SIZE, sizeof(uint8_t));
    uint8_t *nonce = calloc(15-L, sizeof(uint8_t));
    char* tmp_hex = calloc(5, sizeof(uint8_t));
    tmp_hex[0] = '0';
    tmp_hex[1] = 'x';
    // Null-Terminierung
    tmp_hex[4] = 0;
    // Konvertierung von HEX nach ASCII
    if (h)
    {
        if (argc != 5) fail(USAGE_MSG);
        for (int i = 0; i < strlen(argv[3]); i = i + 2)
        {
            tmp_hex[2] = argv[3][i];
            tmp_hex[3] = argv[3][i+1];
            long tmp = strtol(tmp_hex, NULL, 0);
            key[i/2] = (uint8_t) tmp;
        }
#ifdef DEBUG
        printf("key");
        for (int i = 0; i < BLK_SIZE; i++) printf(":%.2x", key[i]);
        printf("\n");
#endif
        for (int i = 0; i < strlen(argv[4]); i = i+2)
        {
            tmp_hex[2] = argv[4][i];
            tmp_hex[3] = argv[4][i+1];
            long tmp = strtol(tmp_hex, NULL, 0);
            nonce[i/2] = (uint8_t) tmp;
        }
#ifdef DEBUG
        printf("nonce");
        for (int i = 0; i < 15-L; i++) printf(":%.2x", nonce[i]);
        printf("\n");
#endif
    } else
    {
        if (argc != 4) fail(USAGE_MSG);
        key = (uint8_t*) argv[2];
        nonce = (uint8_t*) argv[3];
    }
    message_t message;
    message.content = read_standard_input(&message.len);
    if (e)
    {
        int len;
        uint8_t* cipher_text = ccm_encrypt(message, key, nonce, &len);
        for (int i = 0; i < len; i++) printf("%c", cipher_text[i]);
    } else if (d)
    {
        int len;
        uint8_t* decrypted_message = ccm_decrypt(message, key, nonce, &len);
        if (decrypted_message != NULL) for (int i = 0; i < len; i++) printf("%c", decrypted_message[i]);
    } else fail(ERR_STDIN);
    free(key);
    free(nonce);
    free(tmp_hex);
    return 0;
}
