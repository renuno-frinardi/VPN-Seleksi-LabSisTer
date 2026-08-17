#include "vpn.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Alokasi TUN device
int tunAlloc(const char *dev) {
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

    printf("TUN device %s allocated\n", ifr.ifr_name);
    return fd;
}

// Mengatur IP TUN device
int tunSetIP(int fd, const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/24 dev %s", ip, TUN_DEV);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", TUN_DEV);
    system(cmd);
    return 0;
}

// Membaca data dari TUN device
int tunRead(int fd, unsigned char *buf, int len) {
    return read(fd, buf, len);
}

// Menulis data ke TUN device
int tunWrite(int fd, const unsigned char *buf, int len) {
    return write(fd, buf, len);
}

// Menutup TUN device
void tunClose(int fd) {
    close(fd);
}
