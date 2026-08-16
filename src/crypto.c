#include "vpn.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

/* AES-256-GCM encrypt: 
   Writes ciphertext to ciphertext buffer, tag to tag buffer.
   Returns ciphertext length (not including tag), or -1 on failure. */
int encrypt_packet(unsigned char *key,
                   unsigned char *iv,
                   unsigned char *plaintext,
                   size_t plaintext_len,
                   unsigned char *ciphertext,
                   unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    /* Initialize encryption with key and IV */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Provide AAD (empty for simplicity - length 0) */
    EVP_EncryptUpdate(ctx, NULL, &len, plaintext, plaintext_len);

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    /* Finalize encryption */
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    /* Get the authentication tag */
    unsigned int tag_len = TAG_SIZE;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len; /* Return only ciphertext length, tag is separate */
}

/* AES-256-GCM decrypt: returns plaintext length, -1 on auth failure */
int decrypt_packet(unsigned char *key,
                   unsigned char *iv,
                   unsigned char *ciphertext,
                   size_t ciphertext_len,
                   unsigned char *tag,
                   unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    /* Initialize decryption with key and IV */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Set the expected tag for authentication */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag);

    /* Decrypt and authenticate */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    /* Finalize - will fail if tag doesn't match */
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; /* Authentication failed */
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/* Encrypt an IP packet and package for UDP transmission.
   Format: [2-byte length (net)][12-byte IV][ciphertext][16-byte tag] */
int encrypt_for_udp(unsigned char *key,
                    unsigned char *packet,
                    size_t pkt_len,
                    unsigned char *output,
                    size_t output_max) {
    if (pkt_len + 2 + IV_SIZE + TAG_SIZE > output_max) {
        return -1;
    }

    /* Store length at front (network byte order) */
    uint16_t len_net = htons((uint16_t)pkt_len);
    memcpy(output, &len_net, 2);
    output += 2;

    /* Generate random IV */
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        return -1;
    }
    memcpy(output, iv, IV_SIZE);
    output += IV_SIZE;

    /* Encrypt packet - encrypt_packet returns only ciphertext length,
       tag is returned via the tag parameter */
    unsigned char tag[TAG_SIZE];
    int ct_len = encrypt_packet(key, iv, packet, pkt_len, output, tag);

    if (ct_len < 0) {
        return -1;
    }

    /* output now points past ciphertext, write tag */
    output += ct_len;
    memcpy(output, tag, TAG_SIZE);

    return 2 + IV_SIZE + ct_len + TAG_SIZE;
}

/* Decrypt a packet received from UDP.
   Input format: [2-byte length (net)][12-byte IV][ciphertext][16-byte tag] */
int decrypt_from_udp(unsigned char *key,
                     unsigned char *input,
                     size_t input_len,
                     unsigned char *output,
                     size_t output_max) {
    if (input_len < 2 + IV_SIZE + TAG_SIZE) {
        return -1;
    }

    /* Read length field (network byte order) */
    uint16_t pkt_len;
    memcpy(&pkt_len, input, 2);
    pkt_len = ntohs(pkt_len);

    if (2 + IV_SIZE + pkt_len + TAG_SIZE > input_len) {
        return -1;
    }

    /* Extract IV */
    unsigned char *iv = input + 2;

    /* Extract ciphertext (between IV and tag) */
    size_t ct_len = input_len - 2 - IV_SIZE - TAG_SIZE;
    unsigned char *ciphertext = input + 2 + IV_SIZE;

    /* Extract tag (at the end) */
    unsigned char *tag = input + 2 + IV_SIZE + pkt_len;

    /* Decrypt */
    int pt_len = decrypt_packet(key, iv, ciphertext, ct_len, tag, output);
    return pt_len;
}

/* Generate a random PSK (pre-shared key) */
void generate_psk(unsigned char *key, size_t klen) {
    if (RAND_bytes(key, klen) != 1) {
        fprintf(stderr, "Failed to generate random key\n");
        exit(1);
    }
}