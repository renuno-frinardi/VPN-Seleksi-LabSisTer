#ifndef VPN_H
#define VPN_H

#include <stdint.h>
#include <string.h>

#define TUN_DEV "tun0"
#define LOCAL_IP "10.0.0.1"
#define PEER_IP "10.0.0.2"
#define PEER_PORT 5000
#define KEY_SIZE 32
#define MTU 1500
#define IV_SIZE 12
#define TAG_SIZE 16
#define MAX_PKT 4096

typedef struct {
    int tun_fd;
    int sock_fd;
    char local_ip[64];
    char peer_ip[64];
    uint16_t peer_port;
    unsigned char key[KEY_SIZE];
} vpn_ctx_t;

int tunAlloc(const char *dev);
int tunSetIP(int fd, const char *ip);
int tunRead(int fd, unsigned char *buf, int len);
int tunWrite(int fd, const unsigned char *buf, int len);
void tunClose(int fd);

void generatePSK(unsigned char *key, size_t klen);
int encryptPacket(unsigned char *key, unsigned char *iv, unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, unsigned char *tag);
int decryptPacket(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *tag, unsigned char *plaintext);
int encryptForUDP(unsigned char *key, unsigned char *packet, size_t pkt_len, unsigned char *output, size_t output_max);
int decryptFromUDP(unsigned char *key, unsigned char *input, size_t input_len, unsigned char *output, size_t output_max);

#endif
