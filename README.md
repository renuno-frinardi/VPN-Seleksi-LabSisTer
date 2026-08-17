# Aku cinta VPN!

## Pendahuluan

Implementasi sebuah VPN dari awal menggunakan transmisi paket UDP dengan sistem tunnel dari dasar dan enkripsi AES-256-GCM. Sistem dikembangkan dalam bahasa C dan menggunakan beberapa pustaka seperti, openssl. Program dikompilasi menggunakan bantuan makefile dan harus dijalankan dengan hak akses root.

## Struktur Proyek

```
VPN-Seleksi-LabSisTer/
├── build/
├── include/
│   └── vpn.h          
├── src/
│   ├── crypto.c          
│   ├── tunnel.c      
│   └── vpn.c             
├── .gitignore
├── makefile  
└── README.md   
```

## Fitur

- **Enkripsi AES-256-GCM**: Autentikasi enkripsi dengan menggunakan algoritma AES-256-GCM
- **Transport UDP**: Tunneling traffic yang dikirim melalui UDP protocol
- **Point-to-point L3 tunnel**: Tunneling traffic yang simulasikan jaringan langsung antara dua endpoint berbeda
- **Native traffic preservation**: Decrypted packets yang dikirim melalui TUN interface, sehingga OS network stack dapat memprosesnya sebagai traffic native
- **Tidak menggunakan eksternal VPN libraries**: Implementasi dari awal tanpa menggunakan library VPN eksternal
- **Tidak menggunakan packet crafting libraries**: Penyusunan raw IP packets secara manual, tanpa menggunakan pustaka yang sudah ada

### Packet Flow

1. **Egress**: Paket IP yang dikirim melalui TUN interface -> enkrip menggunakan AES-256-GCM -> encapsulated in UDP -> dikirim ke peer
2. **Ingress**: Paket UDP diterima -> dekripsi menggunakan AES-256-GCM -> ditulis ke TUN interface -> Jaringan OS memproses sebagai traffic native

### Format Enkripsi (per UDP packet)

```
+--------+----------------+------------+
| 2 bytes| 12-byte IV     | 16-byte Tag|
| (Len)  |                | (GCM Tag)  |
+--------+----------------+------------+
|      Ciphertext (variable size)      |
+--------------------------------------+
```

## Penjelasan Teknis Kriptografi

- **Algoritma**: AES-256-GCM
- **Ukuran Kunci**: 256 bits (32 bytes)
- **IV (nonce)**: 12 bytes 
- **Tag Autentikasi**: 16 bytes
- **Pembuatan Kunci**: Randomly generated dari OpenSSL's `RAND_bytes`
- **Pertukaran Kunci**: Pre-shared key (PSK) 

AES-256-GCM dipilih karena:
- Menyediakan autentikasi dan enkripsi terpadu (confidentiality + integrity in one pass)
- GCM sudah terstandarisasi di banyak tempat
- 12-byte IV optimal untuk performa dan keamanan dari GCM
- Tidak diperlukan algoritma MAC terpisah

## Kompilasi

### Prerequisites

- OpenSSL development libraries (`libssl-dev`)
- Dua Mesin berbasis Linux atau dua namespace jaringan
- GCC (GNU Compiler Collection)
- Makefile

### Tahapan Kompilasi

```bash
# 1. Unduh source code
# 2. Buka terminal dan arahkan ke direktori VPN-Seleksi-LabSisTer
# 3. Jalankan makefile untuk kompilasi
make all
# 4. Kompilasi selesai, executable 'vpn' siap digunakan
```

## Menjalankan VPN

### Perintah Command-line

```
./vpn -l <local_ip> -p <peer_ip> -r <port> [-e <endpoint_id>]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `-l` / `--local` | IP address untuk endpoint lokal | 10.0.0.1 |
| `-p` / `--peer` | IP address untuk endpoint peer | 10.0.0.2 |
| `-r` / `--port` | UDP port untuk tunneling | 5000 |
| `-e` / `--endpoint` | Endpoint ID (0 or 1, pada mode simulasi) | 0 |

### Setup and Execution

#### Pada Endpoint A:

```bash
sudo ./vpn -l 10.0.0.1 -p 10.0.0.2 -r 5000
```

#### Pada Endpoint B:

```bash
sudo ./vpn -l 10.0.0.2 -p 10.0.0.1 -r 5000
```

### Mode Simulasi

```bash
# Endpoint A 
./vpn -e 0 -l 10.0.0.1 -p 10.0.0.2 -r 5000

# Endpoint B  
./vpn -e 1 -l 10.0.0.2 -p 10.0.0.1 -r 5000
```

Pada mode simulasi, paket IP dikirim melalui buffer memori bersama, mensimulasikan alur enkripsi/dekripsi melalui jaringan.
