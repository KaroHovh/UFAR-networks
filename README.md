# Secure Inline TCP Channel — C / Linux

![Platform](https://img.shields.io/badge/platform-Linux-blue) ![Language](https://img.shields.io/badge/language-C11-informational) ![Crypto](https://img.shields.io/badge/crypto-OpenSSL-green) ![Status](https://img.shields.io/badge/status-lab%20prototype-orange)

A **constrained academic prototype** for protected TCP/IPv4 packets between two Linux routers. It establishes an **authenticated ephemeral X25519 Diffie–Hellman session**, derives separate directional keys with **HKDF-SHA256**, then encrypts **only TCP payload bytes** with **AES-256-GCM**. It appends the 16-byte GCM tag directly after the encrypted payload. **No UDP encapsulation and no custom data-plane header.**

> **NOT production-ready or a general-purpose VPN.** A tag changes the TCP segment's length, and header-free nonce recovery cannot support arbitrary retransmission, splitting, NAT, or packet reordering. See [Security and limitations](#security-and-limitations) before running.

## Topology

```text
PC1                Device1              Device2                PC2
10.1.0.2      LAN 10.1.0.1           LAN 10.2.0.1          10.2.0.2
    |              |                      |                       |
    +--clear TCP---+                      +-----clear TCP---------+
                   |                      |
             WAN 10.12.0.1 -------- 10.12.0.2 WAN
                      TCP payload ciphertext + 16-byte tag
                      Authenticated X25519 control handshake
```

The gateways use Linux **IP forwarding** (not NAT) and intercept the selected service (`PC1 → PC2 TCP destination port 5000`, reverse with source port 5000) with **Netfilter NFQUEUE**. Device1 encrypts forward data and decrypts reverse data; Device2 performs the opposite operations.

```text
Original:  [ IPv4 header ][ TCP header ][ plaintext bytes         ]
On WAN:    [ IPv4 header ][ TCP header ][ ciphertext bytes ][ GCM tag ]
Restored:  [ IPv4 header ][ TCP header ][ plaintext bytes         ]
```

TCP sequence and acknowledgement numbers, original IP addresses and TCP ports are retained. IPv4 total length and TCP/IPv4 checksums are recomputed because the tag adds 16 bytes; router TTL may also decrement. **Bit-for-bit preservation of the complete headers is impossible when packet length changes.**

## Project contents

| Path | Role |
| --- | --- |
| `src/main.c` | CLI, NFQUEUE interception, fail-closed accept/drop decisions |
| `src/handshake.c` | PSK-authenticated X25519 Diffie–Hellman over a dedicated TCP control socket |
| `src/crypto.c` | AES-256-GCM, HMAC-derived nonces, nonce ledger / retransmission cache |
| `src/packet.c` | TCP/IPv4 parsing, stable-header AAD, payload transformation, checksums |
| `include/secure_inline.h` | Public interfaces and shared types |
| `tests/test_packet.c` | Packet round-trip, tamper rejection, nonce conflicts, reverse direction |
| `tests/test_handshake.c` | End-to-end local handshake key agreement |
| `scripts/firewall.sh` | Install or remove NFQUEUE and conntrack-exemption rules |
| `scripts/netns_lab.sh` | Optional four-node virtual Linux topology |
| `Makefile` | Build executable and run tests |

## Requirements and build

Ubuntu / Debian Linux; root and `CAP_NET_ADMIN` for a real gateway, and OpenSSL 3.x or compatible 1.1.1+ development headers.

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev \
    libnetfilter-queue-dev iptables iproute2 ethtool tcpdump curl

make            # builds build/secure-inline
make test       # packet and handshake tests; network and root NOT required
```

`make test` uses OpenSSL only. It runs without root or `libnetfilter-queue-dev` (provided libssl-dev and a compiler are installed). `make` requires both.

## Quick start: four Linux network namespaces on ONE machine

Requires root, Linux namespaces, and permission to create `veth` pairs and iptables rules. The script creates `s_pc1`, `s_d1`, `s_d2`, and `s_pc2` with the topology above. Run from the repository directory.

**1. Build and initialize the lab**

```bash
make
sudo bash scripts/netns_lab.sh up
```

**2. Generate and provision a 32-byte random PSK (never push this file to GitHub)**

```bash
umask 077
openssl rand -out gateway.psk 32
chmod 600 gateway.psk
```

**3. Start Device1 (first terminal)**

```bash
sudo ip netns exec s_d1 ./build/secure-inline --role d1 --psk gateway.psk
```

**4. Start Device2 (second terminal)**

```bash
sudo ip netns exec s_d2 ./build/secure-inline --role d2 --psk gateway.psk
```

Wait until both print `Authenticated X25519 exchange succeeded` and `[ready]` before opening a protected connection. The control handshake uses a separate TCP/4444 channel between the two gateway management IPs. That handshake protocol is **not added to protected data packets**.

**5. Start a service on PC2 (third terminal)**

```bash
sudo ip netns exec s_pc2 python3 -m http.server 5000 --bind 10.2.0.2
```

**6. Send data from PC1 (fourth terminal)**

```bash
sudo ip netns exec s_pc1 curl -v http://10.2.0.2:5000/
```

If the lab environment supports the firewall/NFQUEUE configuration, HTTP content is restored on PC2 and returned to PC1. To capture the **inter-device** encrypted packets, in another terminal:

```bash
sudo ip netns exec s_d1 tcpdump -i d1wan -nn -s0 -XX 'tcp port 5000'
```

To stop the lab, terminate gateway/server processes (`Ctrl+C`) then run:

```bash
sudo bash scripts/netns_lab.sh down
```

### Real separate Linux gateways

Configure interfaces and static routes to match the diagram. On **both** gateways:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo bash scripts/firewall.sh install
# Replace lan0 and wan0 with your actual interface names:
sudo ethtool -K lan0 gro off gso off tso off tx off rx off || true
sudo ethtool -K wan0 gro off gso off tso off tx off rx off || true
```

Add static routes (on Device1 `10.2.0.0/24 via 10.12.0.2`, on Device2 `10.1.0.0/24 via 10.12.0.1`). PC1 and PC2 use their respective gateway IPs as routes to the opposite LAN. Set endpoint route **advertised TCP MSS to 1200**, or otherwise guarantee the extra 16 bytes fit the inter-device MTU. Avoid fragmentation. Use `scripts/firewall.sh remove` to reverse firewall changes.

Place the **same PSK file** at the configured path on both devices (`0600`, never in source control). Device1 listens on `10.12.0.1:4444` and expects the client source address `10.12.0.2`; Device2 connects to `10.12.0.1:4444`. Adjust `--listen` and `--peer` for a different network. This prototype initializes one session per pair of processes; to rekey, restart both devices together.

### Command options

```text
--role d1|d2       Required, gateway role
--psk FILE         Required, exactly 32 bytes with mode 0600
--pc1 IPV4         Default 10.1.0.2
--pc2 IPV4         Default 10.2.0.2
--port N           Protected service port, default 5000
--queue N          Netfilter queue number, default 10
--listen IPV4      Device1 management bind, default 10.12.0.1
--peer IPV4        Expected peer management IP / Device2 connection destination
--control-port N   Handshake TCP port, default 4444
--max-seen N       Maximum encryption records per session, default 20000
```

If you change port, queue, or endpoints, also set the corresponding `PORT`, `QUEUE`, `PC1`, and `PC2` environment variables when installing/removing firewall rules. **Selected forwarding traffic has no `--queue-bypass`: no queue listener means no forwarding.** This is intentional fail-closed behavior. Rules do **not** secure unselected traffic; apply an external policy to prevent sensitive traffic bypassing this selected service.

## Handshake protocol

The management/control channel uses ordinary TCP separate from the intercepted PC1–PC2 flows.

```text
D2 → D1:  "STCP1CL!" || random_c (32) || X25519_public_c (32)
D1 → D2:  "STCP1SR!" || random_s (32) || X25519_public_s (32)
           || HMAC-SHA256(PSK, transcript || "server")
D2 → D1:  HMAC-SHA256(PSK, transcript || "client")
D1 → D2:  HMAC-SHA256(PSK, transcript || "ok")
```

`transcript` contains both magic values, 32-byte randoms, and 32-byte ephemeral public keys in their exchange order, excluding the MACs. Each side derives the same 32-byte X25519 shared secret and uses HKDF-SHA256 (`salt = SHA256(transcript)`, context-specific `info`) to produce **four independent 32-byte keys**: forward AES key, reverse AES key, forward nonce key, reverse nonce key. The HMAC with a random shared PSK authenticates the exchange and prevents an unauthenticated man-in-the-middle. The PSK is externally provisioned, never sent in the handshake.

## Packet processing

1. Linux NFQUEUE selects the original PC1/PC2 IPv4 TCP flow based on IP addresses and service port.
2. Non-initial fragments (including fragments without TCP ports) are blocked for these endpoint addresses; fragmented selected packets are rejected.
3. Payload-free SYN/ACK/FIN segments pass unchanged. TCP payload segments are processed only after successful authenticated DH session establishment.
4. The encryptor computes the nonce from a direction-specific HMAC key and a canonical description of packet metadata. Canonical metadata includes IP source/destination, **IPv4 ID**, the original **complete TCP header except TCP checksum**, and payload length. It is also provided as AES-GCM **associated authenticated data (AAD)**.
5. The encryptor checks its session-lifetime nonce ledger. A new nonce receives one AES-GCM encryption. If the same nonce repeats with exactly the same plaintext/AAD, the existing ciphertext/tag is retransmitted **without re-encrypting**. If either differs, the packet is dropped.
6. The device replaces TCP payload with `ciphertext || 16-byte tag`, updates IPv4 total length and IPv4/TCP checksums, and returns `NF_ACCEPT` with modified bytes.
7. The peer derives the same nonce from visible metadata, verifies the GCM tag, and decrypts. Any tag failure gets `NF_DROP`. After removal of the 16-byte tag, the IPv4 length and checksums are updated, and plaintext forwarding resumes.

## Security and limitations

- **Nonce safety is deliberately fail-closed, not universally compatible.** No two *new AES-GCM encryption operations* use the same nonce during a session; all used nonces are stored until rekey, capped by `--max-seen`. Identical retransmissions replay an already-encrypted packet (and thus its original nonce); the system does **not** guarantee a distinct nonce for every physically transmitted duplicate wire packet. Achieving that literally while preserving all header bytes and transmitting no nonce/sequence field is not generally possible.
- **TCP correctness is constrained.** The 16-byte tag increases the inter-gateway segment length without changing TCP sequence numbers. This is feasible only for a direct, controlled link with TCP tracking disabled and strict MTU/MSS limits. Stateful middleboxes, NAT, proxying, segmentation offload, resegmentation, and fragments are out of scope.
- **ACK-only/other zero-payload packets are neither encrypted nor authenticated.** TCP payload data is authenticated, with stable IP/TCP metadata as AAD. IP TTL, IP total length/checksums, and other mutable IP fields are outside AAD. Packets cannot be treated as completely opaque TCP sessions.
- **Replay detection is incomplete.** Previously valid encrypted packets may be replayed because exact TCP retransmissions are permitted. A persistent anti-replay scheme needs a packet counter or more sophisticated TCP state tracking.
- **No forward-secrecy claim for a compromised live device.** Ephemeral X25519 protects recorded data if only the provisioned PSK leaks later (subject to X25519 assumptions), but running devices contain session keys.
- **No durable nonce state or automatic rekey.** Restart both gateways together to create a fresh session. If the nonce ledger fills, encryption fails closed, not automatically rekeyed.
- **No lossless arbitrary-traffic support.** Selected packets may be dropped on partial handshake, invalid tags, changed retransmissions, or nonce-ledger exhaustion. Kernel firewall and network offloads can disrupt the test; selected traffic must not be encrypted end-to-end by other inline devices that expect raw TCP semantics.
- **Security is only on the Device1–Device2 link.** The PC1–Device1 and Device2–PC2 links carry regular plaintext TCP. Do not use this in place of TLS, IPsec ESP, or WireGuard for production security.

## Testing and assessment evidence

```bash
make test
```

Checks include authenticated handshake key agreement; forward and reverse traffic; encryption/tag growth; restoration of plaintext and checksums; retransmission caching; rejection of a changed payload under a reused nonce; rejection of a tampered GCM tag; and rejection of changed authenticated TCP headers or fragmented selected packets.

For a network demonstration, record: the `[ready]` message from both devices, successful `curl` from PC1, `tcpdump` of cipher bytes between the devices, and the server receiving valid plaintext on PC2. **The repository's unit tests have been executed; the full NFQUEUE/network-namespace integration requires a Linux host with `libnetfilter-queue-dev` and network administration privileges and has not been run in the packaging environment.**

## References

- [OpenSSL X25519 documentation](https://docs.openssl.org/3.0/man7/EVP_PKEY-X25519/)
- [OpenSSL EVP Authenticated Encryption](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/)
- [Netfilter libnetfilter_queue](https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html)
- [NIST SP 800-38D: Galois/Counter Mode](https://csrc.nist.gov/pubs/sp/800/38/d/final)

## License

MIT License. For isolated educational / research testing only; read the limitations above.
