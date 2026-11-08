#include "secure_inline.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

static int nonce_from_ident(const uint8_t key[STCP_KEY_LEN],
                            const uint8_t *ident, size_t ident_len,
                            uint8_t nonce[STCP_NONCE_LEN]) {
    unsigned int n = 0;
    uint8_t mac[EVP_MAX_MD_SIZE];
    if (ident_len > 256 ||
        HMAC(EVP_sha256(), key, STCP_KEY_LEN, ident, ident_len, mac, &n) == NULL || n < STCP_NONCE_LEN)
        return -1;
    memcpy(nonce, mac, STCP_NONCE_LEN);
    OPENSSL_cleanse(mac, sizeof(mac));
    return 0;
}

static unsigned nonce_bucket(const uint8_t nonce[STCP_NONCE_LEN]) {
    uint32_t x = 2166136261U;
    for (size_t i = 0; i < STCP_NONCE_LEN; ++i)
        x = (x ^ nonce[i]) * 16777619U;
    return x % STCP_BUCKETS;
}

static struct nonce_entry *lookup(struct stcp_session *s, enum stcp_direction dir,
                                   const uint8_t nonce[STCP_NONCE_LEN]) {
    for (struct nonce_entry *e = s->seen[dir][nonce_bucket(nonce)]; e; e = e->next)
        if (CRYPTO_memcmp(e->nonce, nonce, STCP_NONCE_LEN) == 0) return e;
    return NULL;
}

static int gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plain, size_t plain_len, uint8_t *wire) {
    int n = 0, last = 0, ok = -1;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, STCP_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(c, NULL, &n, aad, (int)aad_len) != 1 ||
        EVP_EncryptUpdate(c, wire, &n, plain, (int)plain_len) != 1 ||
        n != (int)plain_len ||
        EVP_EncryptFinal_ex(c, wire + n, &last) != 1 || last != 0 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, STCP_TAG_LEN, wire + plain_len) != 1)
        goto done;
    ok = 0;
done:
    EVP_CIPHER_CTX_free(c);
    return ok;
}

static int gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *wire, size_t wire_len, uint8_t *plain) {
    if (wire_len < STCP_TAG_LEN) return -1;
    const size_t text_len = wire_len - STCP_TAG_LEN;
    int n = 0, last = 0, ok = -1;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, STCP_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(c, NULL, &n, aad, (int)aad_len) != 1 ||
        EVP_DecryptUpdate(c, plain, &n, wire, (int)text_len) != 1 ||
        n != (int)text_len ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, STCP_TAG_LEN, (void *)(wire + text_len)) != 1 ||
        EVP_DecryptFinal_ex(c, plain + n, &last) != 1 || last != 0)
        goto done;
    ok = 0;
done:
    EVP_CIPHER_CTX_free(c);
    return ok;
}

int stcp_encrypt(struct stcp_session *s, enum stcp_direction dir,
                 const uint8_t *ident, size_t ident_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plain, size_t plain_len, uint8_t *wire) {
    uint8_t nonce[STCP_NONCE_LEN];
    if (plain_len == 0 || plain_len + STCP_TAG_LEN > STCP_MAX_PACKET ||
        nonce_from_ident(s->nonce_key[dir], ident, ident_len, nonce) != 0)
        return -1;
    struct nonce_entry *e = lookup(s, dir, nonce);
    if (e) {
        /* A genuine, byte-for-byte retransmission: replay the PREVIOUS encryption.
           NEVER invoke AES-GCM again with the same nonce. Changed retransmits drop. */
        if (e->plain_len != plain_len || e->aad_len != aad_len ||
            CRYPTO_memcmp(e->plain, plain, plain_len) != 0 ||
            CRYPTO_memcmp(e->aad, aad, aad_len) != 0)
            return -1;
        memcpy(wire, e->wire, e->wire_len);
        return 0;
    }
    if (s->seen_count >= s->max_seen) return -1; /* Force fresh handshake/rekey. */
    e = calloc(1, sizeof(*e));
    if (!e) return -1;
    e->plain_len = plain_len;
    e->aad_len = aad_len;
    e->wire_len = plain_len + STCP_TAG_LEN;
    e->plain = malloc(plain_len);
    e->aad = malloc(aad_len ? aad_len : 1);
    e->wire = malloc(e->wire_len);
    if (!e->plain || !e->aad || !e->wire ||
        gcm_encrypt(s->traffic_key[dir], nonce, aad, aad_len, plain, plain_len, e->wire) != 0) {
        free(e->plain); free(e->aad); free(e->wire); free(e);
        return -1;
    }
    memcpy(e->plain, plain, plain_len);
    if (aad_len) memcpy(e->aad, aad, aad_len);
    memcpy(e->nonce, nonce, sizeof(nonce));
    memcpy(wire, e->wire, e->wire_len);
    const unsigned bucket = nonce_bucket(nonce);
    e->next = s->seen[dir][bucket];
    s->seen[dir][bucket] = e;
    s->seen_count++;
    return 0;
}

int stcp_decrypt(struct stcp_session *s, enum stcp_direction dir,
                 const uint8_t *ident, size_t ident_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *wire, size_t wire_len, uint8_t *plain) {
    uint8_t nonce[STCP_NONCE_LEN];
    if (wire_len <= STCP_TAG_LEN ||
        nonce_from_ident(s->nonce_key[dir], ident, ident_len, nonce) != 0)
        return -1;
    /* Replay detection is intentionally NOT claimed. Valid TCP retransmits are accepted. */
    return gcm_decrypt(s->traffic_key[dir], nonce, aad, aad_len, wire, wire_len, plain);
}

void stcp_session_clear(struct stcp_session *s) {
    for (int d = 0; d < 2; ++d) {
        for (unsigned b = 0; b < STCP_BUCKETS; ++b) {
            struct nonce_entry *e = s->seen[d][b];
            while (e) {
                struct nonce_entry *next = e->next;
                if (e->plain) { OPENSSL_cleanse(e->plain, e->plain_len); free(e->plain); }
                free(e->aad);
                if (e->wire) { OPENSSL_cleanse(e->wire, e->wire_len); free(e->wire); }
                OPENSSL_cleanse(e, sizeof(*e));
                free(e);
                e = next;
            }
        }
    }
    OPENSSL_cleanse(s, sizeof(*s));
}
