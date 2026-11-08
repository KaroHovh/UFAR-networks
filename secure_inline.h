#ifndef SECURE_INLINE_H
#define SECURE_INLINE_H

#include <stddef.h>
#include <stdint.h>

#define STCP_KEY_LEN 32
#define STCP_TAG_LEN 16
#define STCP_NONCE_LEN 12
#define STCP_MAX_PACKET 65535U
#define STCP_BUCKETS 4096U

/* Traffic direction is based on the ORIGINAL endpoint addresses. */
enum stcp_direction { STCP_FORWARD = 0, STCP_REVERSE = 1 };
enum stcp_role { STCP_D1 = 0, STCP_D2 = 1 };
enum stcp_result { STCP_DROP = -1, STCP_PASS = 0, STCP_MODIFIED = 1 };

struct nonce_entry {
    uint8_t nonce[STCP_NONCE_LEN];
    size_t plain_len, aad_len, wire_len;
    uint8_t *plain, *aad, *wire;
    struct nonce_entry *next;
};

struct stcp_session {
    uint8_t traffic_key[2][STCP_KEY_LEN];
    uint8_t nonce_key[2][STCP_KEY_LEN];
    struct nonce_entry *seen[2][STCP_BUCKETS];
    size_t seen_count;
    size_t max_seen;
};

struct stcp_config {
    enum stcp_role role;
    uint8_t pc1[4];
    uint8_t pc2[4];
    uint16_t service_port; /* host byte order */
};

/* handshake.c: authenticated ephemeral X25519 + HKDF-SHA256. */
int stcp_handshake(enum stcp_role role, const char *listen_ip,
                   const char *peer_ip, uint16_t port,
                   const uint8_t psk[STCP_KEY_LEN], struct stcp_session *s);

/* crypto.c: sender uses deterministic nonce + session-lifetime reuse ledger. */
int stcp_encrypt(struct stcp_session *s, enum stcp_direction dir,
                 const uint8_t *ident, size_t ident_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plain, size_t plain_len,
                 uint8_t *wire /* size plain_len + STCP_TAG_LEN */);
int stcp_decrypt(struct stcp_session *s, enum stcp_direction dir,
                 const uint8_t *ident, size_t ident_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *wire, size_t wire_len,
                 uint8_t *plain /* size wire_len - STCP_TAG_LEN */);
void stcp_session_clear(struct stcp_session *s);

/* packet.c: buffer must have STCP_MAX_PACKET bytes of capacity. */
int stcp_transform(struct stcp_session *s, const struct stcp_config *cfg,
                   uint8_t *packet, size_t *len);
void stcp_update_checksums(uint8_t *packet, size_t len, size_t ip_hlen);

#endif
