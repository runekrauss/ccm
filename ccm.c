/**
 * @file ccm.c
 * @author Rune Krauss
 * @author Marvin Hindmarsh
 *
 * We use ECB to implement the CCM operating mode whereby each bit is encrypted
 * independently of the plain text. However, using ECB alone would make redundancies
 * visible in the ciphertext. With CBC, therefore, the plain text is linked (XOR) with the
 * initialization vector before encryption. In the following rounds, the current plain
 * text is always linked with the previous ciphertext in relation to the blocks. Bit
 * errors would destroy the current block and lead to bit errors in the following block.
 * For parallelisation or random access CTR is recommended whereby an offset like IV is
 * transmitted with the ciphertext. However, there is a new IV in each round since this
 * is linked with the incremented counter. Thus, there is a direct access to the middle
 * of the current. Since the input cannot always be distributed exactly to the blocks,
 * they are padded.
 */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "ccm.h"

/**
 * Returns the number of blocks for the plain text that are needed.
 *
 * @param message_len Length of the plain text
 * @param a_block_more One more block (important for decryption)?
 * @return Number of blocks for the plain text
 */
int get_block_size(int message_len, bool a_block_more)
{
    if (a_block_more) return 2 + ((message_len + 15) / 16);
    else return 1 + ((message_len + 15) / 16);
}

/**
 * Linked two blocks with each other (XOR), e. g. previous ciphertext with current plaintext.
 *
 * @param block1 First block
 * @param block2 Second block
 * @return Adjointed block
 */
uint8_t *uint8_array_xor(uint8_t *block1, uint8_t *block2, uint8_t *result, int len)
{
    for (int i = 0; i < len; i++) result[i] = block1[i] ^ block2[i];
    return result;
}

/**
 * Generates the checksum for the integrity where a potential change of a data packet
 * can be determined. First, a sequence of B-blocks is determined and CBC-MAC is applied
 * to them. B_0 is coded as follows:
 *      0: Flags
 *      1..15-L: Nonce
 *      16-L..15: len (message)
 * The flags correspond to 64*a + 8*M2 + L2 (a is 0 whereby this is additional data
 * for authentication). It applies:
 *      1. Compute authentication field T = M bytes of X_{n+1} with X_1 = E(K, B_0) where
 *          X = adjunction of plaintext.
 *      2. Compute X_{i+1} = E(K, X_i ^ B_i), i = 1, ..., n.
 * E stands for the EncryptUpdate() of OpenSSL, K is the 16 byte key.
 *
 * @param message Message
 * @param key Key
 * @param nonce Random number
 * @param ctx OpenSSL context
 * @param blocks_size Number of blocks for the plaintext
 * @return MAC (Checksum)
 */
uint8_t *generate_mac(message_t message, uint8_t key[16], uint8_t nonce[N], EVP_CIPHER_CTX *ctx, int blocks_size)
{
    uint8_t flags = (uint8_t) (8*M2 + L2);
    /**
     * Computes the number of required blocks (B-blocks).
     * One more block is needed for block 0.
     */
    uint8_t blocks[blocks_size][BLK_SIZE];
    memset(blocks, 0, BLK_SIZE);
    // Set block 0
    blocks[0][0] = flags;
    for (int i = 0; i < N; i++) blocks[0][i + 1] = nonce[i];
    blocks[0][15] = (uint8_t) message.len;
    // Fill plain text into remaining blocks (with padding)
    for (int i = 0; i < blocks_size - 1; i++)
    {
        for (int j = 0; j < BLK_SIZE; j++)
        {
            if (i * BLK_SIZE + j >= message.len) blocks[i + 1][j] = 0;
            else blocks[i + 1][j] = *(message.content + i * BLK_SIZE + j);
        }
    }
#ifdef DEBUG
    printf("b-blocks:\n");
    for (int i = 0; i < blocks_size; i++)
    {
        for (int j = 0; j < BLK_SIZE; j++)
        {
            if (j == BLK_SIZE-1) printf("%.2x", blocks[i][j]);
            else printf("%.2x:", blocks[i][j]);
        }
        printf("\n");
    }
#endif
    uint8_t* result = calloc(BLK_SIZE, sizeof(uint8_t));
    int outl;
    EVP_EncryptUpdate(ctx, result, &outl, blocks[0], BLK_SIZE);
    uint8_t *temp = calloc(BLK_SIZE, sizeof(uint8_t));
    memcpy(temp, result, BLK_SIZE);
    for (int i = 1; i < blocks_size; i++)
    {
        uint8_array_xor(blocks[i], result, temp, BLK_SIZE);
        EVP_EncryptUpdate(ctx, result, &outl, temp, BLK_SIZE);
        memcpy(temp, result, BLK_SIZE);
    }
    free(temp);
    return result;
}

/**
 * Generates the A-blocks. These are formatted as follows whereby the counter
 * field i is coded according to the MSB standard:
 *      0: Flags
 *      1..15-L: Nonce n
 *      16-L..15 Counter i
 * The flags correspond to L2.
 *
 * @param nonce Random number
 * @param blocks_size Number of blocks for the plaintext
 * @return A-blocks (flags, nonce, counter)
 */
uint8_t *generate_a_blocks(uint8_t *nonce, int blocks_size)
{
    uint8_t *a_blocks = calloc(blocks_size, sizeof(uint8_t) * BLK_SIZE);
    uint8_t flags = L2;
    // Fill with nonce
    for (int i = 0; i < blocks_size; i++)
    {
        *(a_blocks+i*BLK_SIZE) = flags;
        for (int j = 1; j <= N; j++) *(a_blocks + i * BLK_SIZE + j) = nonce[j - 1];
        *(a_blocks + (i + 1) * BLK_SIZE - 1) = (uint8_t) i;
    }
#ifdef DEBUG
    printf("a-blocks:\n");
    for (int i = 0; i < blocks_size; i++){
        for (int j = 0; j < BLK_SIZE; j++) printf("%.2x:", *(a_blocks+i*BLK_SIZE+j));
        printf("\n");
    }
#endif
    return a_blocks;
}

/**
 * Generates the S-blocks or the key stream. The A-blocks are formatted as follows:
 *      0: Flags
 *      1..15-L: Nonce n
 *      16-L..15: Counter i
 * The flags are encoded as L2.
 *
 * @param a_blocks A-blocks
 * @param ctx OpenSSL context
 * @param blocks_size Number of blocks for the plaintext
 * @return S-Bloecke (encrypted A-blocks)
 */
uint8_t *generate_s_blocks(uint8_t *a_blocks, EVP_CIPHER_CTX *ctx, int blocks_size)
{
    uint8_t *s_blocks = calloc(blocks_size, sizeof(uint8_t) * BLK_SIZE);
    int useless;
    for (int i = 0; i < blocks_size; i++) EVP_EncryptUpdate(ctx, s_blocks + i * BLK_SIZE, &useless, a_blocks + i * BLK_SIZE, BLK_SIZE);
#ifdef DEBUG
    printf("s-blocks:\n");
    for (int i = 0; i < blocks_size; i++)
    {
        for (int j = 0; j < BLK_SIZE; j++) printf("%.2x:", *(s_blocks+i*BLK_SIZE+j));
        printf("\n");
    }
#endif
    return s_blocks;
}

/**
 * Encrypts a message to CTR using a key and a nonce:
 *      1. Determine A-blocks (flags, nonce, counter).
 *      2. Determine S-blocks (key stream) S_i = E(K, A_i), i = 0, 1, 2, ...
 *      3. Encrypt blockwise, i. e. D = (P ^ S_1S_2...).substr(0,len(message)).
 *      4. Compute authentication value U, i. e. U = MAC ^ S0_M
 *      5. Append this results to C = DU
 *
 * @param message Message
 * @param key Key
 * @param nonce Random number
 * @return Encrypted message
 */
uint8_t *ccm_encrypt(message_t message, uint8_t key[16], uint8_t nonce[N], int *len)
{
    uint8_t iv[BLK_SIZE];
    memset(iv, 0, BLK_SIZE);
    // Get context
    EVP_CIPHER_CTX *ctx;
    // Is something wrong?
    if (!(ctx = EVP_CIPHER_CTX_new())) return (uint8_t* ) - 1;
    // Set the key
    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    // Determine the block size
    int blocks_size = get_block_size(message.len, false);
    // Compute the MAC
    uint8_t* mac = generate_mac(message, key, nonce, ctx, blocks_size);
#ifdef DEBUG
    printf("mac");
    for (int i = 0; i < M; i++) printf(":%.2x", mac[i]);
    printf("\n");
#endif
    // Determine A-blocks
    uint8_t* a_blocks = generate_a_blocks(nonce, blocks_size+1);
    // Determine S-blocks
    uint8_t* s_blocks = generate_s_blocks(a_blocks, ctx, blocks_size+1);
    // Encrypt blockwise
    uint8_t* cipher_text = calloc(message.len, sizeof(uint8_t));
    uint8_array_xor(message.content, s_blocks+BLK_SIZE, cipher_text, message.len);
    // Compute authentication value
    uint8_t *auth = calloc(M, sizeof(uint8_t));
    uint8_array_xor(mac, s_blocks, auth, M);
    // Append this results to the cipertext
    cipher_text = realloc(cipher_text, message.len + M);
    memcpy(cipher_text + message.len, auth, M);
    *len = message.len + M;
    free(a_blocks);
    free(s_blocks);
    free(auth);
    return cipher_text;
}

/**
 * Decrypts a message using a key and a nonce:
 *      1. Compute key stream S_i.
 *      2. Compute MAC from U and S_0.
 *      3. Determine plain text P from D and S_1S_2....
 *      4. Compute MAC MAC2.
 *      5. Integrity check, i. e. MAC = MAC2 (compare M bytes)
 *
 * @param message Message
 * @param key Key
 * @param nonce Random number
 * @return Decrypted message
 */
uint8_t* ccm_decrypt(message_t message, uint8_t key[16], uint8_t nonce[N], int* len)
{
    uint8_t iv[BLK_SIZE];
    memset(iv, 0, BLK_SIZE);
    // Get context
    EVP_CIPHER_CTX *ctx;
    // Is something wrong?
    if (!(ctx = EVP_CIPHER_CTX_new())) return (uint8_t*) -1;
    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
    int message_len = message.len - M;
    int blocks_size = get_block_size((message_len), true);
    // Determine A-blocks
    uint8_t *a_blocks = generate_a_blocks(nonce, blocks_size);
    // Determine S-blocks
    uint8_t *s_blocks = generate_s_blocks(a_blocks, ctx, blocks_size);
    uint8_t* xor_ed_message = calloc(blocks_size*BLK_SIZE, sizeof(uint8_t));
    uint8_array_xor(message.content, s_blocks+BLK_SIZE, xor_ed_message, blocks_size*BLK_SIZE);
    *len = message_len;
    uint8_t encrypted_mac[M];
    uint8_t decrypted_mac[M];
    memset(decrypted_mac, 0, M);
    memcpy(encrypted_mac, message.content+message_len, M);
    uint8_array_xor(encrypted_mac, s_blocks,decrypted_mac, M);
    message_t result_message = {xor_ed_message, message_len};
    uint8_t* new_mac = generate_mac(result_message,key, nonce,ctx, get_block_size(message.len, false));
#ifdef DEBUG
    printf("mac");
    for (int i = 0; i < M; i++) printf(":%.2x", new_mac[i]);
    printf("\n");
#endif
    if (memcmp(decrypted_mac, new_mac, M) != 0)
    {
        fprintf(stderr,"integrity check failed!\n");
        return NULL;
    }
    free(a_blocks);
    free(s_blocks);
    return xor_ed_message;
}
