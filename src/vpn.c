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

static unsigned char sim_rx_pool[2][MAX_PKT];
static int sim_buf_len[2] = {0, 0};

void simSendPacket(int endpoint, unsigned char *packet, size_t pkt_len) {
    if (pkt_len > MAX_PKT) return;
    if (endpoint == 0) {
        if (sim_buf_len[0] + pkt_len > MAX_PKT) return;
        memcpy(sim_rx_pool[0] + sim_buf_len[0], packet, pkt_len);
        sim_buf_len[0] += pkt_len;
    }
    else if (endpoint == 1) {
        if (sim_buf_len[1] + pkt_len > MAX_PKT) return;
        memcpy(sim_rx_pool[1] + sim_buf_len[1], packet, pkt_len);
        sim_buf_len[1] += pkt_len;
    }
}

int simRecvPacket(int endpoint, unsigned char *buf, size_t buf_max) {
    if (endpoint == 0) {
        if (sim_buf_len[0] == 0) return 0;
        if (sim_buf_len[0] > buf_max) return -1;
        memcpy(buf, sim_rx_pool[0], sim_buf_len[0]);
        sim_buf_len[0] = 0;
        return sim_buf_len[0];
    }
    else if (endpoint == 1) {
        if (sim_buf_len[1] == 0) return 0;
        if (sim_buf_len[1] > buf_max) return -1;
        memcpy(buf, sim_rx_pool[1], sim_buf_len[1]);
        sim_buf_len[1] = 0;
        return sim_buf_len[1];
    }
    return 0;
}

static int autoConfigTUN(const char *local_ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev tun0", local_ip);
    if (system(cmd) != 0) {
        fprintf(stderr, "Gagal set IP di TUN interface (coba mode simulasi)\n");
        return -1;
    }

    /* Bring interface up */
    snprintf(cmd, sizeof(cmd), "ip link set dev tun0 up");
    if (system(cmd) != 0) {
        fprintf(stderr, "Gagal up TUN interface (coba mode simulasi)\n");
        return -1;
    }

    printf("TUN interface tun0 dikonfigurasi: %s/24\n", local_ip);
    return 0;
}

// Entry point utama simulasi VPN
int runSimulation(int my_endpoint, int peer_endpoint, const char *local_ip, const char *peer_ip, uint16_t port) {
    /* Generate shared PSK */
    unsigned char key[KEY_SIZE];
    generatePSK(key, KEY_SIZE);

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

    struct sockaddr_in peer_sock;
    memset(&peer_sock, 0, sizeof(peer_sock));
    peer_sock.sin_family = AF_INET;
    peer_sock.sin_port = htons(port);
    inet_pton(AF_INET, peer_ip, &peer_sock.sin_addr.s_addr);

    printf("VPN SIMULATION: Endpoint %d <-> Endpoint %d\n", my_endpoint, peer_endpoint);
    printf("Local: %s:%d, Peer: %s:%d\n", local_ip, port, peer_ip, port);

    unsigned char decrypted_buf[MAX_PKT];
    unsigned char udp_buf[MAX_PKT];


    fd_set read_fds;
    int max_fd = sock_fd;

    unsigned char icmp_pkt[64];
    memset(icmp_pkt, 0, 64);
    icmp_pkt[0] = 0x45;
    icmp_pkt[9] = 1;
    icmp_pkt[11] = 8;
    icmp_pkt[16] = 0x12;
    icmp_pkt[17] = 0x34;

    if (my_endpoint == 0) simSendPacket(0, icmp_pkt, 64);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }

        // Handle UDP data -> decrypt -> sim buffer
        if (FD_ISSET(sock_fd, &read_fds)) {
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int n = recvfrom(sock_fd, udp_buf, MAX_PKT, 0, (struct sockaddr *)&from, &from_len);
            if (n > 0) {

                unsigned char iv[IV_SIZE];
                unsigned char tag[TAG_SIZE];
                if (n >= 2 + IV_SIZE + TAG_SIZE) {
                    memcpy(iv, udp_buf + 2, IV_SIZE);
                    memcpy(tag, udp_buf + n - TAG_SIZE, TAG_SIZE);

                    int dec_len = decryptFromUDP(key, udp_buf, n, decrypted_buf, MAX_PKT);
                    if (dec_len > 0) {

                        simRecvPacket(peer_endpoint, decrypted_buf, dec_len);
                        printf("[SIM] Endpoint %d received decrypted packet (%d bytes)\n", peer_endpoint, dec_len);
                    } else {
                        printf("[SIM] Endpoint %d decryption failed\n", peer_endpoint);
                    }
                }
            }
        }

        // Mengecek apakah endpoint kita memiliki paket yang harus diproses
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

// Entry point untuk mode simulation
int mainSimulation(int my_endpoint, const char *local_ip, const char *peer_ip, uint16_t port) {
    printf("VPN starting - attempting TUN auto-config...\n");

    int tun_fd = tunAlloc("tun0");
    if (tun_fd >= 0) {
        /* Coba otomatis konfigurasi TUN */
        if (autoConfigTUN(local_ip) == 0) {
            printf("Mode TUN real aktif.\n");
            char stop;
            while (stop != 'q') {
                printf("Enter 'q' to quit: ");
                scanf(" %c", &stop);
            }
            tunClose(tun_fd);
            return 0;
        }
        tunClose(tun_fd);
    }

    int peer_endpoint = (my_endpoint == 0) ? 1 : 0;

    return runSimulation(my_endpoint, peer_endpoint, local_ip, peer_ip, port);
}

// Loop utama
int main(int argc, char *argv[]) {
    char *local_ip = LOCAL_IP;
    char *peer_ip = PEER_IP;
    uint16_t peer_port = PEER_PORT;
    int my_endpoint = 0;

    // Parsing argumen program
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

    // Menjalankan simulasi
    int ret = mainSimulation(my_endpoint, local_ip, peer_ip, peer_port);

    return ret;
}
