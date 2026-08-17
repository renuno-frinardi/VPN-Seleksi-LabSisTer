#include "vpn.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

// Enkripsi dengan AES-256-GCM, mengembalikan panjang ciphertext, -1 pada kegagalan
int encryptPacket(unsigned char *key, unsigned char *iv, unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Inisiasi enkripsi dengan kunci dan iv
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Fungsi untuk menambahkan AAD
    EVP_EncryptUpdate(ctx, NULL, &len, plaintext, plaintext_len);

    // Fungsi untuk enkripsi plaintext
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalisasi enkripsi
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Fungsi untuk mendapatkan tag autentikasi
    unsigned int tag_len = TAG_SIZE;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Dekripsi AES-256-GCM: mengembalikan panjang plaintext, -1 pada kegagalan
int decryptPacket(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Inisiasi Dekripsi dengan kunci dan IV
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set tag untuk autentikasi
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag);

    // Dekripsi dan autentikasi
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalisasi - akan gagal jika tag tidak sesuai
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Mengenkripsi paket IP dan mengembalikan dalam format UDP: [2-byte length (net)][12-byte IV][ciphertext][16-byte tag]
int encryptForUDP(unsigned char *key, unsigned char *packet, size_t pkt_len, unsigned char *output, size_t output_max) {
    if (pkt_len + 2 + IV_SIZE + TAG_SIZE > output_max) {
        return -1;
    }

    // Menyimpan panjang paket dalam format network byte order di awal output
    uint16_t len_net = htons((uint16_t)pkt_len);
    memcpy(output, &len_net, 2);
    output += 2;

    // Menghasilkan IV acak
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        return -1;
    }
    memcpy(output, iv, IV_SIZE);
    output += IV_SIZE;

    // Mengenkripsi paket IP dan mendapatkan tag
    unsigned char tag[TAG_SIZE];
    int ct_len = encryptPacket(key, iv, packet, pkt_len, output, tag);

    if (ct_len < 0) {
        return -1;
    }

    // Menyimpan tag di akhir output
    output += ct_len;
    memcpy(output, tag, TAG_SIZE);

    return 2 + IV_SIZE + ct_len + TAG_SIZE;
}

// Mendekripsi paket UDP yang diterima
int decryptFromUDP(unsigned char *key, unsigned char *input, size_t input_len, unsigned char *output, size_t output_max) {
    if (input_len < 2 + IV_SIZE + TAG_SIZE) {
        return -1;
    }

    // Membaca panjang paket dari field length (network byte order)
    uint16_t pkt_len;
    memcpy(&pkt_len, input, 2);
    pkt_len = ntohs(pkt_len);

    if (2 + IV_SIZE + pkt_len + TAG_SIZE > input_len) {
        return -1;
    }

    // Membaca IV dari input
    unsigned char *iv = input + 2;

    // Membaca ciphertext dan tag dari input
    size_t ct_len = input_len - 2 - IV_SIZE - TAG_SIZE;
    unsigned char *ciphertext = input + 2 + IV_SIZE;

    // Membaca tag dari input
    unsigned char *tag = input + 2 + IV_SIZE + pkt_len;

    // Mendekripsi paket IP dan memverifikasi tag
    int pt_len = decryptPacket(key, iv, ciphertext, ct_len, tag, output);
    return pt_len;
}

// Menggenerate PSK (pre-shared key) acak
void generatePSK(unsigned char *key, size_t klen) {
    if (RAND_bytes(key, klen) != 1) {
        fprintf(stderr, "Failed to generate random key\n");
        exit(1);
    }
}
