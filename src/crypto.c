#include "vpn.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

int encryptPacket(unsigned char *key, unsigned char *iv, unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    EVP_EncryptUpdate(ctx, NULL, &len, plaintext, plaintext_len);
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    ciphertext_len += len;

    unsigned int tag_len = TAG_SIZE;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decryptPacket(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag);
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx); return -1;
    }
    plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void generatePSK(unsigned char *key, size_t klen) {
    if (RAND_bytes(key, klen) != 1) {
        fprintf(stderr, "Gagal generate key\n"); exit(1);
    }
}

int encryptForUDP(unsigned char *key, unsigned char *packet, size_t pkt_len, unsigned char *output, size_t output_max) {
    if (pkt_len + 2 + IV_SIZE + TAG_SIZE > output_max) return -1;

    uint16_t len_net = htons((uint16_t)pkt_len);
    memcpy(output, &len_net, 2); output += 2;

    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) return -1;
    memcpy(output, iv, IV_SIZE); output += IV_SIZE;

    unsigned char tag[TAG_SIZE];
    int enc_len = encryptPacket(key, iv, packet, pkt_len, output, tag);

    if (enc_len < 0) return -1;

    output += enc_len;
    memcpy(output, tag, TAG_SIZE);
    return 2 + IV_SIZE + enc_len + TAG_SIZE;
}

int decryptFromUDP(unsigned char *key, unsigned char *input, size_t input_len, unsigned char *output, size_t output_max) {
    if (input_len < 2 + IV_SIZE + TAG_SIZE) return -1;

    uint16_t pkt_len;
    memcpy(&pkt_len, input, 2); pkt_len = ntohs(pkt_len);
    if (2 + IV_SIZE + pkt_len + TAG_SIZE > input_len) return -1;

    unsigned char *iv = input + 2;
    size_t ct_len = input_len - 2 - IV_SIZE - TAG_SIZE;
    unsigned char *ciphertext = input + 2 + IV_SIZE;
    unsigned char *tag = input + 2 + IV_SIZE + pkt_len;

    return decryptPacket(key, iv, ciphertext, ct_len, tag, output);
}
