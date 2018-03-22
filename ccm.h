/**
 * @file ccm.h
 * @author Rune Krauss
 * @author Marvin Hindmarsh
 * 
 * @brief CCM (CBC + MAC) is an AES operating mode defined on 128 bit blocks.
 * The procedure describes how messages are encrypted with a block cipher. Only
 * the combination of block cipher and operating mode makes it possible to encrypt
 * messages that are longer than the block length. However, the specification can
 * also be transferred to other sizes.
 */
#ifndef CCM_H
#define CCM_H

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

/**
 * Defines a message with content and length.
 */
typedef struct {
    uint8_t* content;
    int len;
} message_t;

/**
 * Defines a Boolean data type.
 */
typedef enum {
    false = 0,
    true = !false
} bool;

/**
 * Indicates the number of octets (bytes) regarding the authentication field
 * and describes an opposite dependency between the message extension and the
 * probability that an attacker can modify the message undetected. Valid values
 * are 4, 6, 8, 10, 12, 14 as well as 16 and is encoded as (M-2)/2 (important
 * for MAC determination, size of 3 bits). The larger the M is selected, the
 * more complex are the encryption and decryption (message also becomes longer).
 * A typical value would be 16.
 */
#define M 8

/**
 * Describes the number of octets (bytes) in relation to the length field. This
 * parameter requires an opposite dependency between the maximum message length
 * and the size of the random number (nonce). Valid values are between 2 and 8
 * octets (L = 1 is reserved). It is also encoded as L-1 (important for determining
 * the MAC) and has a size of 3 bits. The larger L is, the less space is available for
 * encoding the nonce and reduces the search range if you want to launch a Bruteforce
 * attack against the nonce. L should be as small as possible depending on the amount
 * of data to be sent. A typical value would be 2.
 */
#define L 5

/**
 * Coding of M is used in internal computings (MAC, flags and so on)
 */
#define M2 ((M-2) / 2)

/**
 * Coding of L2 is used in internal computings (MAC, flags and so on)
 */
#define L2 (L - 1)

/**
 * Encoded Nonce
 */
#define N (15 - L)

/**
 * Size of the blocks (defined for 128 bits) used in the algorithm specified for 16 bits.
 */
#define BLK_SIZE 16

/**
 * @brief Returns the number of required blocks.
 */
int get_block_size(int, bool);

/**
 * @brief Disambiguation between two blocks.
 */
uint8_t* uint8_array_xor(uint8_t*, uint8_t*, uint8_t*, int);

/**
 * @brief Generates the checksum for the integrity (determining whether data has changed).
 */
uint8_t* generate_mac(message_t, uint8_t*, uint8_t*, EVP_CIPHER_CTX*, int);

/**
 * @brief Generates the A-blocks.
 */
uint8_t* generate_a_blocks(uint8_t*, int);

/**
 * @brief Generates the S-blocks.
 */
uint8_t* generate_s_blocks(uint8_t*, EVP_CIPHER_CTX*, int);

/**
 * @brief Encrypts a message using a key and a nonce.
 */
uint8_t* ccm_encrypt(message_t, uint8_t*, uint8_t*, int*);

/**
 * @brief Decrypts a message using a key and a nonce.
 */
uint8_t* ccm_decrypt(message_t, uint8_t*, uint8_t*, int*);

#endif /* CCM_H */
