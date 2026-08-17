#include "vpn.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_PKT 4096

/* Global simulation buffer for inter-process comm */
static unsigned char sim_rx_pool[2][MAX_PKT];
static int sim_buf_len[2] = {0, 0};

/* Kirim paket ke buffer simulasi */
void simSendPacket(int endpoint, unsigned char *packet, size_t pkt_len) {
    if (pkt_len > MAX_PKT) return;
    if (endpoint == 0) {
        if (sim_buf_len[0] + pkt_len > MAX_PKT) return;
        memcpy(sim_rx_pool[0] + sim_buf_len[0], packet, pkt_len);
        sim_buf_len[0] += pkt_len;
    } else if (endpoint == 1) {
        if (sim_buf_len[1] + pkt_len > MAX_PKT) return;
        memcpy(sim_rx_pool[1] + sim_buf_len[1], packet, pkt_len);
        sim_buf_len[1] += pkt_len;
    }
}

/* Dapatkan paket dari buffer simulasi */
int simRecvPacket(int endpoint, unsigned char *buf, size_t buf_max) {
    if (endpoint == 0) {
        if (sim_buf_len[0] == 0) return 0;
        if (sim_buf_len[0] > buf_max) return -1;
        memcpy(buf, sim_rx_pool[0], sim_buf_len[0]);
        sim_buf_len[0] = 0;
        return sim_buf_len[0];
    } else if (endpoint == 1) {
        if (sim_buf_len[1] == 0) return 0;
        if (sim_buf_len[1] > buf_max) return -1;
        memcpy(buf, sim_rx_pool[1], sim_buf_len[1]);
        sim_buf_len[1] = 0;
        return sim_buf_len[1];
    }
    return 0;
}

/* Fungsi enkripsi AES-256-GCM (dipanggil dari crypto.c) */
int encrypt_packet_wrapper(unsigned char *key,
                   unsigned char *iv,
                   unsigned char *plaintext,
                   size_t plaintext_len,
                   unsigned char *ciphertext,
                   unsigned char *tag) {
    /* Panggil fungsi dari crypto.c */
    return encrypt_packet(key, iv, plaintext, plaintext_len, ciphertext, tag);
}

/* Fungsi dekripsi AES-256-GCM (dipanggil dari crypto.c) */
int decrypt_packet_wrapper(unsigned char *key,
                   unsigned char *iv,
                   unsigned char *ciphertext,
                   size_t ciphertext_len,
                   unsigned char *tag,
                   unsigned char *plaintext) {
    /* Panggil fungsi dari crypto.c */
    return decrypt_packet(key, iv, ciphertext, ciphertext_len, tag, plaintext);
}

/* Enkripsi paket untuk UDP */
int encrypt_for_udp(unsigned char *key,
                    unsigned char *packet,
                    size_t pkt_len,
                    unsigned char *output,
                    size_t output_max) {
    if (pkt_len + 2 + IV_SIZE + TAG_SIZE > output_max) {
        return -1;
    }

    uint16_t len_net = htons((uint16_t)pkt_len);
    memcpy(output, &len_net, 2);
    output += 2;

    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        return -1;
    }
    memcpy(output, iv, IV_SIZE);
    output += IV_SIZE;

    /* Panggil encrypt_packet_wrapper */
    unsigned char tag[TAG_SIZE];
    int enc_len = encrypt_packet_wrapper(key, iv, packet, pkt_len, output, tag);

    if (enc_len < 0) return -1;

    output += enc_len;
    memcpy(output, tag, TAG_SIZE);

    return 2 + IV_SIZE + enc_len + TAG_SIZE;
}

/* Dekripsi dari UDP */
int decrypt_from_udp(unsigned char *key,
                     unsigned char *input,
                     size_t input_len,
                     unsigned char *output,
                     size_t output_max) {
    if (input_len < 2 + IV_SIZE + TAG_SIZE) return -1;

    uint16_t pkt_len;
    memcpy(&pkt_len, input, 2);
    pkt_len = ntohs(pkt_len);

    if (2 + IV_SIZE + pkt_len + TAG_SIZE > input_len) return -1;

    unsigned char *iv = input + 2;
    size_t ct_len = input_len - 2 - IV_SIZE - TAG_SIZE;
    unsigned char *ciphertext = input + 2 + IV_SIZE;
    unsigned char *tag = input + 2 + IV_SIZE + pkt_len;

    /* Panggil decrypt_packet_wrapper */
    return decrypt_packet_wrapper(key, iv, ciphertext, ct_len, tag, output);
}

/* Generate PSK */
void generate_psk(unsigned char *key, size_t klen) {
    if (RAND_bytes(key, klen) != 1) {
        fprintf(stderr, "Failed to generate random key\n");
        exit(1);
    }
}

/* Kirim paket ICMP-like ke buffer simulasi */
void simSendICMP(int endpoint) {
    unsigned char icmp_pkt[64];
    memset(icmp_pkt, 0, 64);
    icmp_pkt[0] = 0x45; /* IPv4 */
    icmp_pkt[9] = 1;    /* ICMP protocol */
    icmp_pkt[11] = 8;   /* ICMP Echo Request */

    if (endpoint == 0) simSendPacket(0, icmp_pkt, 64);
    else simSendPacket(1, icmp_pkt, 64);
}

/* Entry point utama simulasi VPN */
int run_simulation(int my_endpoint, int peer_endpoint,
                   const char *local_ip, const char *peer_ip,
                   uint16_t port) {
    /* Generate shared PSK */
    unsigned char key[KEY_SIZE];
    generate_psk(key, KEY_SIZE);

    /* Create UDP socket */
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    /* Bind to local port */
    struct sockaddr_in local_sock;
    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_port = htons(port);
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock_fd, (struct sockaddr *)&local_sock, sizeof(local_sock)) < 0) {
        perror("bind");
        close(sock_fd);
        return 1;
    }

    /* Peer address */
    struct sockaddr_in peer_sock;
    memset(&peer_sock, 0, sizeof(peer_sock));
    peer_sock.sin_family = AF_INET;
    peer_sock.sin_port = htons(port);
    inet_pton(AF_INET, peer_ip, &peer_sock.sin_addr.s_addr);

    printf("VPN SIMULATION: Endpoint %d <-> Endpoint %d\n", my_endpoint, peer_endpoint);
    printf("Local: %s:%d, Peer: %s:%d\n", local_ip, port, peer_ip, port);

    /* Kirim paket ICMP awal */
    simSendICMP(my_endpoint);

    /* Buffers */
    unsigned char decrypted_buf[MAX_PKT];
    unsigned char udp_buf[MAX_PKT];

    /* Main loop */
    fd_set read_fds;
    int max_fd = sock_fd;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(sock_fd, &read_fds)) {
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int n = recvfrom(sock_fd, udp_buf, MAX_PKT, 0,
                             (struct sockaddr *)&from, &from_len);
            if (n > 0) {
                int dec_len = decrypt_from_udp(key, udp_buf, n, decrypted_buf, MAX_PKT);
                if (dec_len > 0) {
                    simRecvPacket(peer_endpoint, decrypted_buf, dec_len);
                    printf("[SIM] Endpoint %d received decrypted packet (%d bytes)\n", peer_endpoint, dec_len);
                }
            }
        }

        int received = simRecvPacket(my_endpoint, decrypted_buf, MAX_PKT);
        if (received > 0) {
            printf("[SIM] Endpoint %d received %d bytes from tunnel:\n", my_endpoint, received);
            if (received >= 20) {
                printf("  Protocol: %d ", decrypted_buf[9]);
                if (decrypted_buf[9] == 1) printf("(ICMP)");
                printf("\n");
                if (received > 20) {
                    printf("  ICMP Type: %d\n", decrypted_buf[11]);
                }
            }
        }
    }

    close(sock_fd);
    return 0;
}

/* Entry point untuk mode simulation */
int main_simulation(int my_endpoint, const char *local_ip, const char *peer_ip,
                    uint16_t port) {
    int peer_endpoint = (my_endpoint == 0) ? 1 : 0;

    return run_simulation(my_endpoint, peer_endpoint, local_ip, peer_ip, port);
}

/* Entry point utama */
int main(int argc, char *argv[]) {
    char *local_ip = LOCAL_IP;
    char *peer_ip = PEER_IP;
    uint16_t peer_port = PEER_PORT;
    int my_endpoint = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--local") == 0) {
            local_ip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--peer") == 0) {
            peer_ip = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--port") == 0) {
            peer_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--endpoint") == 0) {
            my_endpoint = atoi(argv[++i]);
        }
    }

    int peer_endpoint = (my_endpoint == 0) ? 1 : 0;
    int ret = main_simulation(my_endpoint, local_ip, peer_ip, peer_port);

    return ret;
}