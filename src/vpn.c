#include "vpn.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_tun.h>

#define MAX_PKT 4096


int hasNetAdminCAP() {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            unsigned long caps = strtoul(line + 8, NULL, 16);
            if (caps & (1 << 12)) { fclose(f); return 1; }
        }
    }
    fclose(f);
    return 0;
}

int tunAlloc(const char *dev) {
    if (!hasNetAdminCAP()) {
        fprintf(stderr, "ERROR: CAP_NET_ADMIN dibutuhkan untuk TUN device!\n");
        fprintf(stderr, "       Jalankan: sudo ./vpn -l IP -p IP -r PORT\n");
        return -1;
    }

    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return err;
    }

    printf("TUN device %s dialokasikan\n", ifr.ifr_name);
    return fd;
}

int tunSetIP(int fd, const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", ip, TUN_DEV);
    if (system(cmd) != 0) {
        fprintf(stderr, "Gagal set IP di TUN\n"); return -1;
    }
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", TUN_DEV);
    if (system(cmd) != 0) {
        fprintf(stderr, "Gagal aktifkan TUN\n"); return -1;
    }
    printf("TUN %s dikonfigurasi: %s/24\n", TUN_DEV, ip);
    return 0;
}

int tunRead(int fd, unsigned char *buf, int len) { return read(fd, buf, len); }
int tunWrite(int fd, const unsigned char *buf, int len) { return write(fd, buf, len); }
void tunClose(int fd) { close(fd); }

static unsigned char sim_rx_pool[2][MAX_PKT];
static int sim_buf_len[2] = {0, 0};

void simSendPacket(int endpoint, unsigned char *packet, size_t pkt_len) {
    if (pkt_len > MAX_PKT) return;
    if (endpoint == 0) {
        if (sim_buf_len[0] + pkt_len > MAX_PKT) return;
        memcpy(sim_rx_pool[0] + sim_buf_len[0], packet, pkt_len);
        sim_buf_len[0] += pkt_len;
    }
    else {
        if (sim_buf_len[1] + pkt_len > MAX_PKT) return;
        memcpy(sim_rx_pool[1] + sim_buf_len[1], packet, pkt_len);
        sim_buf_len[1] += pkt_len;
    }
}

int simRecvPacket(int endpoint, unsigned char *buf, size_t buf_max) {
    if (endpoint == 0) {
        if (sim_buf_len[0] == 0) return 0;
        if (sim_buf_len[0] > buf_max) return -1;
        memcpy(buf, sim_rx_pool[0], sim_buf_len[0]); sim_buf_len[0] = 0;
        return sim_buf_len[0];
    }
    else {
        if (sim_buf_len[1] == 0) return 0;
        if (sim_buf_len[1] > buf_max) return -1;
        memcpy(buf, sim_rx_pool[1], sim_buf_len[1]); sim_buf_len[1] = 0;
        return sim_buf_len[1];
    }
}

void simSendICMP(int endpoint) {
    unsigned char pkt[64]; memset(pkt, 0, 64);
    pkt[0] = 0x45; pkt[9] = 1; pkt[11] = 8;
    if (endpoint == 0) simSendPacket(0, pkt, 64);
    else simSendPacket(1, pkt, 64);
}


int runRealMode(int my_endpoint, const char *local_ip, const char *peer_ip, uint16_t port) {
    if (!hasNetAdminCAP()) {
        fprintf(stderr, "ERROR: Butuh CAP_NET_ADMIN untuk mode REAL!\n"
                "       Jalankan: sudo ./vpn -l IP -p IP -r PORT\n");
        return 1;
    }

    unsigned char key[KEY_SIZE];
    generatePSK(key, KEY_SIZE);

    int tun_fd = tunAlloc(TUN_DEV);
    if (tun_fd < 0) return 1;
    if (tunSetIP(tun_fd, local_ip) < 0) { tunClose(tun_fd); return 1; }

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) { perror("socket"); tunClose(tun_fd); return 1; }

    struct sockaddr_in local_sock;
    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_port = htons(port);
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock_fd, (struct sockaddr *)&local_sock, sizeof(local_sock)) < 0) {
        perror("bind"); close(sock_fd); tunClose(tun_fd); return 1;
    }

    struct sockaddr_in peer_sock;
    memset(&peer_sock, 0, sizeof(peer_sock));
    peer_sock.sin_family = AF_INET;
    peer_sock.sin_port = htons(port);
    inet_pton(AF_INET, peer_ip, &peer_sock.sin_addr.s_addr);

    printf("\n=== VPN REAL MODE ===\n"
           "Endpoint %d <-> Endpoint %d\n"
           "Local: %s:%d  |  Peer: %s:%d\n"
           "TUN: %s dengan IP %s/24\n\n",
           my_endpoint, 1-my_endpoint, local_ip, port, peer_ip, port,
           TUN_DEV, local_ip);

    unsigned char tun_buf[MAX_PKT], udp_buf[MAX_PKT];
    unsigned char out_buf[MAX_PKT + 64], dec_buf[MAX_PKT];
    fd_set read_fds;
    int max_fd = tun_fd > sock_fd ? tun_fd : sock_fd;

    while (1) {
        FD_ZERO(&read_fds); FD_SET(tun_fd, &read_fds); FD_SET(sock_fd, &read_fds);
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) { perror("select"); break; }

        if (FD_ISSET(tun_fd, &read_fds)) {
            int n = tunRead(tun_fd, tun_buf, MAX_PKT);
            if (n > 0) {
                unsigned char iv[IV_SIZE];
                if (RAND_bytes(iv, IV_SIZE) != 1) { fprintf(stderr, "Gagal IV\n"); continue; }
                unsigned char tag[TAG_SIZE];
                int enc = encryptPacket(key, iv, tun_buf, n, out_buf, tag);
                if (enc > 0) {
                    unsigned char pkt[2 + IV_SIZE + enc + TAG_SIZE];
                    memcpy(pkt, &n, 2); memcpy(pkt + 2, iv, IV_SIZE);
                    memcpy(pkt + 2 + IV_SIZE, out_buf, enc);
                    memcpy(pkt + 2 + IV_SIZE + enc, tag, TAG_SIZE);
                    sendto(sock_fd, pkt, sizeof(pkt), 0,
                           (struct sockaddr *)&peer_sock, sizeof(peer_sock));
                }
            }
        }

        if (FD_ISSET(sock_fd, &read_fds)) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int n = recvfrom(sock_fd, udp_buf, MAX_PKT, 0,
                             (struct sockaddr *)&from, &fl);
            if (n > 0) {
                int dl = decryptFromUDP(key, udp_buf, n, dec_buf, MAX_PKT);
                if (dl > 0) tunWrite(tun_fd, dec_buf, dl);
            }
        }
    }

    tunClose(tun_fd); close(sock_fd);
    return 0;
}

int runSimulation(int my_endpoint, int peer_endpoint, const char *local_ip, const char *peer_ip, uint16_t port) {
    unsigned char key[KEY_SIZE];
    generatePSK(key, KEY_SIZE);

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in local_sock;
    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_port = htons(port);
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock_fd, (struct sockaddr *)&local_sock, sizeof(local_sock)) < 0) {
        perror("bind"); close(sock_fd); return 1;
    }

    struct sockaddr_in peer_sock;
    memset(&peer_sock, 0, sizeof(peer_sock));
    peer_sock.sin_family = AF_INET;
    peer_sock.sin_port = htons(port);
    inet_pton(AF_INET, peer_ip, &peer_sock.sin_addr.s_addr);

    printf("\nVPN SIMULASI MODE (buffer-based, tanpa TUN device)\n"
           "Local: %s:%d  |  Peer: %s:%d\n",
           local_ip, port, peer_ip, port);

    simSendICMP(my_endpoint);

    unsigned char dec_buf[MAX_PKT], udp_buf[MAX_PKT];
    fd_set read_fds;
    int max_fd = sock_fd;

    while (1) {
        FD_ZERO(&read_fds); FD_SET(sock_fd, &read_fds);
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) { perror("select"); break; }

        if (FD_ISSET(sock_fd, &read_fds)) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int n = recvfrom(sock_fd, udp_buf, MAX_PKT, 0,
                             (struct sockaddr *)&from, &fl);
            if (n > 0) {
                int dl = decryptFromUDP(key, udp_buf, n, dec_buf, MAX_PKT);
                if (dl > 0) {
                    simRecvPacket(peer_endpoint, dec_buf, dl);
                    printf("[SIM] Endpoint %d received %d bytes\n", peer_endpoint, dl);
                }
            }
        }

        int rec = simRecvPacket(my_endpoint, dec_buf, MAX_PKT);
        if (rec > 0) {
            printf("[SIM] Endpoint %d received %d bytes from tunnel:\n", my_endpoint, rec);
            if (rec >= 20) {
                printf("  Protocol: %d ", dec_buf[9]);
                if (dec_buf[9] == 1) printf("(ICMP)");
                printf("\n  ICMP Type: %d\n", rec > 20 ? dec_buf[11] : 0);
            }
        }
    }

    close(sock_fd);
    return 0;
}

int main(int argc, char *argv[]) {
    char *local_ip = LOCAL_IP;
    char *peer_ip = PEER_IP;
    uint16_t peer_port = PEER_PORT;
    int my_endpoint = 0;
    int mode_real = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--local") == 0)
            local_ip = argv[++i];
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--peer") == 0)
            peer_ip = argv[++i];
        else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--port") == 0)
            peer_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--endpoint") == 0)
            my_endpoint = atoi(argv[++i]);
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sim") == 0)
            mode_real = 0;
        else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--real") == 0)
            mode_real = 1;
    }

    int peer_ep = (my_endpoint == 0) ? 1 : 0;
    int ret;
    if (mode_real) ret = runRealMode(my_endpoint, local_ip, peer_ip, peer_port);
    else ret = runSimulation(my_endpoint, peer_ep, local_ip, peer_ip, peer_port);

    return ret;
}
