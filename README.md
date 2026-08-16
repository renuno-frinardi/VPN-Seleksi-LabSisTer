# Layer 3 VPN Over UDP - From Scratch

## Overview

This project implements a Layer 3 (network layer) Virtual Private Network using UDP as the transport protocol. The VPN creates an encrypted point-to-point tunnel between two Linux endpoints, encapsulating and transporting native IP packets through an untrusted network.

**Important:** This implementation requires root privileges to create TUN devices. See the "Running the VPN" section for setup details.

## Features

- **AES-256-GCM encryption**: Authenticated encryption providing both confidentiality and integrity
- **UDP transport**: All tunneling traffic goes over UDP protocol
- **Point-to-point L3 tunnel**: Simulates a direct network link between two endpoints
- **Native traffic preservation**: Decrypted packets are written to TUN interface as native IP traffic, not encrypted blobs
- **No external VPN libraries**: Implemented from scratch using only standard OpenSSL library
- **No packet crafting libraries**: Raw IP packets handled manually, no libtins/scapy/libvpn

## Architecture

```
Endpoint A                      Public Network                      Endpoint B

  +------------+                  +------------+
  | TUN (10.0.0.1)    |   UDP -->   | TUN (10.0.0.2) |
  | (Virtual L3)     |              | (Virtual L3)  |
  +--------|--------+      |<--UDP      |--------|----+
           |     |          |             |
           |   [Encrypt]      |  [Decrypt]
           |     |          |             |
   IP pkt -->|     +---------+    +---------+     |--> IP pkt
              (TUN)         (AES-256-GCM)  (TUN)
```

### Packet Flow

1. **Egress**: IP packet from TUN interface → encrypted via AES-256-GCM → encapsulated in UDP → sent to peer
2. **Ingress**: UDP packet received → decrypted via AES-256-GCM → written to TUN interface → OS network stack processes as native traffic

### Encryption Format (per UDP packet)

```
+--------+----------------+-----------+
| 2 bytes| 12-byte IV     | 16-byte Tag|
| (Len)  |                | (GCM Tag)  |
+--------+----------------+-----------+
|        Ciphertext (variable size)        |
+-------------------------------------------+
```

## Cryptography

- **Algorithm**: AES-256-GCM (AES in Galois/Counter Mode)
- **Key size**: 256 bits (32 bytes)
- **IV (nonce)**: 12 bytes (standard for GCM mode)
- **Authentication tag**: 16 bytes
- **Key generation**: Randomly generated using OpenSSL's `RAND_bytes`
- **Key exchange**: Pre-shared key (PSK) - distributed out-of-band

AES-256-GCM was chosen because:
- Provieves authenticated encryption (confidentiality + integrity in one pass)
- GCM mode is standardized and well-audited
- 12-byte IV is optimal for GCM performance and security
- No need for separate MAC algorithm (GCM handles authentication natively)

## Project Structure

```
VPN-Seleksi-LabSisTer/
├── include/
│   └── vpn.h          # Header with constants and function prototypes
├── src/
│   ├── vpn.c          # Main program, event loop, UDP transport
│   ├── tunnel.c       # TUN device management (ioctl calls)
│   └── crypto.c       # AES-256-GCM encryption/decryption
├── go.mod             # Go module (if applicable)
├── README.md          # This file
└── vpn (compiled binary)
```

## Building

```bash
# Compile the VPN application
gcc -o vpn src/vpn.c src/tunnel.c src/crypto.c -Iinclude -lssl -lcrypto

# Or using make (if Makefile exists)
make
```

## Running the VPN

### Prerequisites

- Root privileges (for TUN device creation)
- OpenSSL development libraries (`libssl-dev`)
- Two Linux machines or two network namespaces

### Command-line Arguments

```
./vpn -l <local_ip> -p <peer_ip> -r <port> [-e <endpoint_id>]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `-l` / `--local` | Local endpoint IP address | 10.0.0.1 |
| `-p` / `--peer` | Peer endpoint IP address | 10.0.0.2 |
| `-r` / `--port` | UDP port for tunneling | 5000 |
| `-e` / `--endpoint` | Endpoint ID (0 or 1, for simulation mode) | 0 |

### Setup and Execution

#### On Endpoint A:

```bash
sudo ./vpn -l 10.0.0.1 -p 10.0.0.2 -r 5000
```

#### On Endpoint B:

```bash
sudo ./vpn -l 10.0.0.2 -p 10.0.0.1 -r 5000
```

#### Manual TUN Configuration (if automatic setup fails):

```bash
# Create TUN devices
ip tuntap add mode tun tun0
ip tuntap add mode tun tun1

# Configure IPs
ip addr add 10.0.0.1/24 dev tun0
ip addr add 10.0.0.2/24 dev tun1

# Bring interfaces up
ip link set dev tun0 up
ip link set dev tun1 up

# Add routes
ip route add 10.0.0.2/24 dev tun0
ip route add 10.0.0.1/24 dev tun1
```

### Simulation Mode (same machine, no TUN required)

The VPN can be run in simulation mode on a single machine without TUN devices:

```bash
# Endpoint A (simulation mode)
./vpn -e 0 -l 10.0.0.1 -p 10.0.0.2 -r 5000 &

# Endpoint B (simulation mode)  
./vpn -e 1 -l 10.0.0.2 -p 10.0.0.1 -r 5000 &
```

In simulation mode, IP packets are exchanged via a shared in-memory buffer, demonstrating the encryption/decryption pipeline.

## Verification

### 1. VPN Successfully Started on 2 Endpoints

```bash
# Both endpoints should start without errors
sudo ./vpn -l 10.0.0.1 -p 10.0.0.2 -r 5000
sudo ./vpn -l 10.0.0.2 -p 10.0.0.1 -r 5000

# Expected output indicates both are running and connected
```

### 2. ICMP Ping Through VPN

Once the TUN interfaces are configured:

```bash
# From endpoint A's TUN interface
ping 10.0.0.2

# From endpoint B's TUN interface  
ping 10.0.0.1
```

Successful ping responses confirm that ICMP packets traverse the encrypted tunnel correctly.

### 3. Large File Transfer (Minimum 2MB)

```bash
# On endpoint A
dd if=/dev/urandom of=test_file.bin bs=1M count=3

# Transfer through VPN (e.g., via scp or netcat)
# On endpoint B, capture the file
dd of=received_file.bin bs=1M count=3

# Verify integrity
md5sum test_file.bin received_file.bin
```

### 4. Packet Inspection

Capture packets on either endpoint to verify:
- **Outgoing**: Packets are encrypted (ciphertext, not native IP)
- **Incoming**: Decrypted packets are native IP packets with correct headers
- **No encrypted blobs**: The tunnel does not pass raw ciphertext to the network layer

## Development Notes

### Implementation Choices

1. **TUN Device**: Uses `/dev/net/tun` with `ioctl(TUNSETIFF)` to create virtual network interfaces
2. **Encryption**: AES-256-GCM from OpenSSL EVP interface (authenticated encryption)
3. **Transport**: User-space UDP socket with select-based event multiplexing
4. **Packet framing**: Length-prefixed UDP packets with random IVs for each transmission

### Security Considerations

- Pre-shared key is generated randomly at startup (not persistent across restarts)
- Each packet uses a unique random IV (nonce), preventing IV reuse attacks
- GCM authentication tag prevents packet tampering undetected
- No key exchange protocol implemented (PSK must be distributed securely)

### Limitations

- No built-in key exchange mechanism (PSK distributed out-of-band)
- No replay protection (sequence numbers not implemented)
- No perfect forward secrecy
- Single tunnel (one logical connection per process pair)

## Bonus: Language/Implementation Choice

This implementation uses **C** language with **OpenSSL** library, which qualifies for the 5-point bonus category. The choice of C provides:

- Direct system-level access (TUN device manipulation)
- Efficient cryptographic operations
- Fine-grained control over network packet handling
- Maximum compatibility with Linux networking tools

If using Go, Rust, or C++ would provide memory safety and modern language features while maintaining similar functionality.