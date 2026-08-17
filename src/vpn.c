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

// Entry point dari aplikasi VPN
int main(int argc, char *argv[]) {
    char *local_ip = LOCAL_IP;
    char *peer_ip = PEER_IP;
    uint16_t peer_port = PEER_PORT;
    int my_endpoint = 0;

    // Parsing perintah baris argument
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--local") == 0) {
            local_ip = argv[++i];
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--peer") == 0) {
            peer_ip = argv[++i];
        }
        else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--port") == 0) {
            peer_port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--endpoint") == 0) {
            my_endpoint = atoi(argv[++i]);
        }
    }

    // Generate shared PSK
    unsigned char key[KEY_SIZE];
    generatePSK(key, KEY_SIZE);
    printf("[DBG] Generated PSK key (hex): ");
    for (int i = 0; i < KEY_SIZE; i++) printf("%02x", key[i]);
    printf("\n");

    // Membuat socket UDP
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }
    printf("[DBG] Socket created: %d\n", sock_fd);

    // Mengizinkan reuse address agar kedua endpoint dapat terbind ke port yang sama
    int reuse = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    // Mengikat socket ke port lokal
    struct sockaddr_in local_sock;
    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_port = htons(peer_port);
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock_fd, (struct sockaddr *)&local_sock, sizeof(local_sock)) < 0) {
        perror("bind");
        close(sock_fd);
        return 1;
    }
    printf("[DBG] Bound to port %d\n", peer_port);

    // Menentukan alamat peer
    struct sockaddr_in peer_sock;
    memset(&peer_sock, 0, sizeof(peer_sock));
    peer_sock.sin_family = AF_INET;
    peer_sock.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip, &peer_sock.sin_addr.s_addr) <= 0) {
        fprintf(stderr, "Invalid peer IP: %s\n", peer_ip);
        close(sock_fd);
        return 1;
    }
    printf("[DBG] Peer: %s:%d\n", peer_ip, ntohs(peer_sock.sin_port));

    // Menunggu paket UDP dari peer dan mengirimkan kembali
    unsigned char buf[MAX_PKT];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    printf("[DBG] Waiting for UDP packet...\n");
    int n = recvfrom(sock_fd, buf, MAX_PKT, 0, (struct sockaddr *)&from, &from_len);
    printf("[DBG] Received %d bytes from %s:%d\n", n, inet_ntoa(from.sin_addr), ntohs(from.sin_port));

    if (n > 0) {
        sendto(sock_fd, buf, n, 0, (struct sockaddr *)&peer_sock, sizeof(peer_sock));
        printf("[DBG] Sent %d bytes to peer\n", n);
    }

    close(sock_fd);
    printf("[DBG] Done.\n");
    return 0;
}
