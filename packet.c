#include "secure_inline.h"

#include <string.h>

static uint16_t get16(const uint8_t *b) {
    return (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
}
static void put16(uint8_t *b, uint16_t v) {
    b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v;
}
static uint32_t checksum_add(uint32_t sum, const uint8_t *p, size_t n) {
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += ((uint32_t)p[i] << 8) | p[i + 1];
    if (n & 1U) sum += (uint32_t)p[n - 1] << 8;
    return sum;
}
static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
    return (uint16_t)~sum;
}

void stcp_update_checksums(uint8_t *p, size_t len, size_t ihl) {
    uint8_t *t = p + ihl;
    const size_t tcp_len = len - ihl;
    put16(p + 2, (uint16_t)len);
    put16(p + 10, 0);
    put16(p + 10, checksum_finish(checksum_add(0, p, ihl)));
    put16(t + 16, 0);
    uint32_t sum = 0;
    sum = checksum_add(sum, p + 12, 8); /* Source/destination IPv4 */
    sum += 6;                           /* Protocol TCP */
    sum += (uint32_t)tcp_len;           /* TCP pseudoheader length */
    sum = checksum_add(sum, t, tcp_len);
    put16(t + 16, checksum_finish(sum));
}

int stcp_transform(struct stcp_session *s, const struct stcp_config *cfg,
                   uint8_t *p, size_t *len) {
    if (!p || !len || *len < 20 || *len > STCP_MAX_PACKET) return STCP_DROP;
    if ((p[0] >> 4) != 4) return STCP_DROP;
    const size_t ihl = (size_t)(p[0] & 15U) * 4U;
    if (ihl < 20 || *len < ihl || get16(p + 2) != *len) return STCP_DROP;
    if (p[9] != 6) return STCP_PASS;
    /* All TCP fragments between these endpoint IPs are unsupported. Drop even
       later fragments (which lack the TCP header needed for port matching). */
    const int host_pair =
        (!memcmp(p + 12, cfg->pc1, 4) && !memcmp(p + 16, cfg->pc2, 4)) ||
        (!memcmp(p + 12, cfg->pc2, 4) && !memcmp(p + 16, cfg->pc1, 4));
    if (host_pair && (get16(p + 6) & 0x3fffU) != 0) return STCP_DROP;
    if (*len < ihl + 20) return STCP_DROP;

    uint8_t *t = p + ihl;
    const uint16_t sport = get16(t);
    const uint16_t dport = get16(t + 2);
    enum stcp_direction dir;
    if (!memcmp(p + 12, cfg->pc1, 4) && !memcmp(p + 16, cfg->pc2, 4) &&
        dport == cfg->service_port)
        dir = STCP_FORWARD;
    else if (!memcmp(p + 12, cfg->pc2, 4) && !memcmp(p + 16, cfg->pc1, 4) &&
             sport == cfg->service_port)
        dir = STCP_REVERSE;
    else
        return STCP_PASS;

    /* Non-initial fragments may lack TCP header. MF/offset must both be zero. */
    if ((get16(p + 6) & 0x3fffU) != 0) return STCP_DROP;
    const size_t thl = (size_t)(t[12] >> 4) * 4U;
    if (thl < 20 || ihl + thl > *len) return STCP_DROP;
    const size_t old_len = *len - ihl - thl;
    if (old_len == 0) return STCP_PASS; /* No data to encrypt: SYN/ACK/FIN/etc. */
    const int encrypt = (cfg->role == STCP_D1 && dir == STCP_FORWARD) ||
                        (cfg->role == STCP_D2 && dir == STCP_REVERSE);
    if (!encrypt && old_len <= STCP_TAG_LEN) return STCP_DROP;
    if (encrypt && *len + STCP_TAG_LEN > STCP_MAX_PACKET) return STCP_DROP;

    const size_t plain_len = encrypt ? old_len : old_len - STCP_TAG_LEN;
    /* Canonical authenticated metadata. IP ID and stable TCP header bytes give
       retransmissions with changed headers a distinct nonce when possible.
       TCP checksum is excluded because it necessarily changes with payload.
       TTL, IP checksum, and IP total length are not authenticated. */
    uint8_t aad[80]; /* 8 IP endpoints + 2 IP ID + <=60 TCP + 2 payload length */
    size_t alen = 0;
    memcpy(aad + alen, p + 12, 8); alen += 8;
    memcpy(aad + alen, p + 4, 2); alen += 2;
    memcpy(aad + alen, t, thl); alen += thl;
    aad[10 + 16] = 0; /* Neutralize TCP checksum (offset 16 inside TCP). */
    aad[10 + 17] = 0;
    put16(aad + alen, (uint16_t)plain_len); alen += 2;

    uint8_t ident[128];
    static const uint8_t label[] = "stcp-packet-v2";
    size_t idlen = sizeof(label) - 1;
    memcpy(ident, label, idlen);
    memcpy(ident + idlen, aad, alen); idlen += alen;

    const size_t new_payload_len = encrypt ? old_len + STCP_TAG_LEN : plain_len;
    /* In-place transform would overwrite the original payload before AEAD
       completes; use a bounded temporary work buffer. */
    uint8_t work[STCP_MAX_PACKET];
    const uint8_t *payload = t + thl;
    int rc = encrypt
        ? stcp_encrypt(s, dir, ident, idlen, aad, alen, payload, old_len, work)
        : stcp_decrypt(s, dir, ident, idlen, aad, alen, payload, old_len, work);
    if (rc != 0) return STCP_DROP; /* Includes authentication failure. */
    memcpy(t + thl, work, new_payload_len);
    *len = ihl + thl + new_payload_len;
    stcp_update_checksums(p, *len, ihl);
    return STCP_MODIFIED;
}
