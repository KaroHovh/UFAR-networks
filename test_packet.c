#include "secure_inline.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void u16(uint8_t *p, unsigned x) { p[0] = (uint8_t)(x >> 8); p[1] = (uint8_t)x; }
static void u32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16); p[2] = (uint8_t)(x >> 8); p[3] = (uint8_t)x;
}
static uint16_t checksum(const uint8_t *p, size_t n) {
    uint32_t sum = 0;
    for (size_t i = 0; i < n; i += 2)
        sum += (uint32_t)p[i] << 8 | (i + 1 < n ? p[i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}
static void init_session(struct stcp_session *s) {
    memset(s, 0, sizeof(*s));
    s->max_seen = 100;
    for (int dir = 0; dir < 2; dir++) for (int j = 0; j < 32; j++) {
        s->traffic_key[dir][j] = (uint8_t)(j + dir * 61);
        s->nonce_key[dir][j] = (uint8_t)(255 - j - dir * 61);
    }
}
static void init_config(struct stcp_config *c, enum stcp_role role) {
    memset(c, 0, sizeof(*c));
    c->role = role;
    assert(inet_pton(AF_INET, "10.1.0.2", c->pc1) == 1);
    assert(inet_pton(AF_INET, "10.2.0.2", c->pc2) == 1);
    c->service_port = 5000;
}
static size_t make_packet(uint8_t *p, const uint8_t *content, size_t n,
                          uint32_t seq, int reverse) {
    memset(p, 0, STCP_MAX_PACKET);
    p[0] = 0x45; p[1] = 0;
    p[8] = 64; p[9] = 6;
    u16(p + 4, 0x1250);
    u16(p + 6, 0x4000); /* Don't fragment */
    inet_pton(AF_INET, reverse ? "10.2.0.2" : "10.1.0.2", p + 12);
    inet_pton(AF_INET, reverse ? "10.1.0.2" : "10.2.0.2", p + 16);
    u16(p + 20, reverse ? 5000 : 42000);
    u16(p + 22, reverse ? 42000 : 5000);
    u32(p + 24, seq); u32(p + 28, 8001);
    p[32] = 0x50; p[33] = 0x18; /* Data offset 5, ACK+PSH */
    u16(p + 34, 4096);
    if (n) memcpy(p + 40, content, n);
    size_t len = 40 + n;
    stcp_update_checksums(p, len, 20);
    return len;
}
static void validate_checksums(uint8_t *p, size_t len) {
    assert(((unsigned)p[2] << 8 | p[3]) == len);
    assert(checksum(p, 20) == 0);
    uint8_t *tcp = p + 20;
    const size_t tcp_len = len - 20;
    /* TCP pseudoheader: IPv4 addresses, protocol, TCP length. */
    uint8_t pseudo[12] = {0};
    memcpy(pseudo, p + 12, 8); pseudo[9] = 6;
    u16(pseudo + 10, (unsigned)tcp_len);
    uint32_t sum = (uint16_t)~checksum(pseudo, sizeof(pseudo));
    sum += (uint16_t)~checksum(tcp, tcp_len);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    assert(sum == 0xffffU);
}

int main(void) {
    struct stcp_session *a = calloc(1, sizeof(*a)), *b = calloc(1, sizeof(*b));
    assert(a && b);
    init_session(a); init_session(b);
    struct stcp_config d1, d2;
    init_config(&d1, STCP_D1); init_config(&d2, STCP_D2);
    uint8_t *pkt = calloc(1, STCP_MAX_PACKET);
    uint8_t *original = calloc(1, STCP_MAX_PACKET);
    uint8_t *encrypted = calloc(1, STCP_MAX_PACKET);
    assert(pkt && original && encrypted);
    const uint8_t hello[] = "Assessment: AES-GCM over TCP data";
    const size_t data_len = sizeof(hello) - 1;
    size_t n = make_packet(pkt, hello, data_len, 555, 0);
    memcpy(original, pkt, n);
    size_t old = n;

    assert(stcp_transform(a, &d1, pkt, &n) == STCP_MODIFIED);
    assert(n == old + STCP_TAG_LEN);
    assert(memcmp(pkt + 40, hello, data_len) != 0);
    validate_checksums(pkt, n);
    memcpy(encrypted, pkt, n);
    size_t encrypted_len = n;

    assert(stcp_transform(b, &d2, pkt, &n) == STCP_MODIFIED);
    assert(n == old && !memcmp(pkt, original, n));
    validate_checksums(pkt, n);
    puts("PASS: PC1 -> D1 encrypt -> D2 decrypt -> PC2, checksums restored");

    /* Byte-identical retransmission: no second AES-GCM invocation, cached ciphertext. */
    n = make_packet(pkt, hello, data_len, 555, 0);
    assert(stcp_transform(a, &d1, pkt, &n) == STCP_MODIFIED);
    assert(n == encrypted_len && !memcmp(pkt, encrypted, n));
    puts("PASS: exact retransmit reuses cached ciphertext");

    /* Different plaintext with same nonce identifier must NEVER be encrypted. */
    uint8_t changed[sizeof(hello)];
    memcpy(changed, hello, sizeof(hello)); changed[0] ^= 0x11;
    n = make_packet(pkt, changed, data_len, 555, 0);
    assert(stcp_transform(a, &d1, pkt, &n) == STCP_DROP);
    puts("PASS: conflicting nonce reuse rejected");

    /* Tag manipulation triggers authentication failure. */
    memcpy(pkt, encrypted, encrypted_len);
    pkt[encrypted_len - 1] ^= 0x01;
    n = encrypted_len;
    assert(stcp_transform(b, &d2, pkt, &n) == STCP_DROP);
    puts("PASS: corrupted GCM tag rejected");

    /* Authenticated TCP sequence and ports cannot be edited by an on-path attacker. */
    memcpy(pkt, encrypted, encrypted_len);
    pkt[27] ^= 0x01; /* TCP sequence number */
    n = encrypted_len;
    assert(stcp_transform(b, &d2, pkt, &n) == STCP_DROP);
    puts("PASS: authenticated TCP metadata tampering rejected");

    /* Two packets with distinct seq create distinct ciphertext; both can decrypt. */
    n = make_packet(pkt, hello, data_len, 556, 0);
    assert(stcp_transform(a, &d1, pkt, &n) == STCP_MODIFIED);
    assert(memcmp(pkt + 40, encrypted + 40, data_len) != 0);
    assert(stcp_transform(b, &d2, pkt, &n) == STCP_MODIFIED);
    assert(n == old && !memcmp(pkt + 40, hello, data_len));
    puts("PASS: different sequence number produces different encrypted bytes");

    /* Reverse-direction protection uses independent directional keys. */
    n = make_packet(pkt, hello, data_len, 9000, 1);
    memcpy(original, pkt, n);
    assert(stcp_transform(b, &d2, pkt, &n) == STCP_MODIFIED);
    assert(stcp_transform(a, &d1, pkt, &n) == STCP_MODIFIED);
    assert(!memcmp(pkt, original, n));
    puts("PASS: PC2 -> D2 encrypt -> D1 decrypt -> PC1");

    /* Pure control packets pass unmodified; fragmented selected packets fail closed. */
    n = make_packet(pkt, NULL, 0, 9200, 0);
    assert(stcp_transform(a, &d1, pkt, &n) == STCP_PASS);
    u16(pkt + 6, 0x2000);
    assert(stcp_transform(a, &d1, pkt, &n) == STCP_DROP);
    puts("PASS: payload-free TCP passes; selected IPv4 fragmentation rejected");

    stcp_session_clear(a); stcp_session_clear(b);
    free(a); free(b); free(pkt); free(original); free(encrypted);
    puts("All packet/crypto tests passed.");
    return 0;
}
