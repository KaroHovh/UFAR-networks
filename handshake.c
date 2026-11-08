#define _POSIX_C_SOURCE 200809L
#include "secure_inline.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define HS_HELLO_LEN 72
#define HS_REPLY_LEN 104
#define HS_FINISH_LEN 32
#define HS_TRANSCRIPT_LEN 144
static const uint8_t HELLO_MAGIC[8] = {'S','T','C','P','1','C','L','!'};
static const uint8_t REPLY_MAGIC[8] = {'S','T','C','P','1','S','R','!'};

static int write_all(int fd, const uint8_t *p, size_t n) {
    while (n) {
        ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}
static int read_all(int fd, uint8_t *p, size_t n) {
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}
static int generate_ephemeral(EVP_PKEY **priv, uint8_t pub[32]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t sz = 32;
    int rc = -1;
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_keygen(ctx, priv) != 1 ||
        EVP_PKEY_get_raw_public_key(*priv, pub, &sz) != 1 || sz != 32)
        goto end;
    rc = 0;
end:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}
static int derive_secret(EVP_PKEY *priv, const uint8_t other_pub[32],
                         uint8_t secret[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, other_pub, 32);
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen = 32;
    int rc = -1;
    if (!peer) goto end;
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_derive_set_peer(ctx, peer) != 1 ||
        EVP_PKEY_derive(ctx, secret, &outlen) != 1 || outlen != 32)
        goto end;
    /* Defense in depth: reject an invalid low-order public key. */
    uint8_t zero[32] = {0};
    if (CRYPTO_memcmp(secret, zero, sizeof(zero)) == 0) goto end;
    rc = 0;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return rc;
}

static int authenticator(const uint8_t psk[32],
                         const uint8_t transcript[HS_TRANSCRIPT_LEN],
                         const char *who, uint8_t mac[32]) {
    uint8_t data[HS_TRANSCRIPT_LEN + 8];
    const size_t wlen = strlen(who);
    unsigned int n = 0;
    if (wlen > 8) return -1;
    memcpy(data, transcript, HS_TRANSCRIPT_LEN);
    memcpy(data + HS_TRANSCRIPT_LEN, who, wlen);
    return HMAC(EVP_sha256(), psk, 32, data, HS_TRANSCRIPT_LEN + wlen, mac, &n) && n == 32 ? 0 : -1;
}

static int derive_keys(struct stcp_session *s, EVP_PKEY *priv,
                       const uint8_t peer_pub[32],
                       const uint8_t transcript[HS_TRANSCRIPT_LEN]) {
    uint8_t shared[32] = {0}, salt[32] = {0}, keys[128] = {0};
    unsigned int salt_n = 0;
    size_t n = sizeof(keys);
    int rc = -1;
    EVP_PKEY_CTX *ctx = NULL;
    static const uint8_t info[] = "secure-inline-tcp-lab-v1/fwd-rev+nonces";
    if (derive_secret(priv, peer_pub, shared) != 0 ||
        EVP_Digest(transcript, HS_TRANSCRIPT_LEN, salt, &salt_n, EVP_sha256(), NULL) != 1 || salt_n != 32)
        goto end;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, shared, sizeof(shared)) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info) - 1) != 1 ||
        EVP_PKEY_derive(ctx, keys, &n) != 1 || n != sizeof(keys))
        goto end;
    memcpy(s->traffic_key[STCP_FORWARD], keys, 32);
    memcpy(s->traffic_key[STCP_REVERSE], keys + 32, 32);
    memcpy(s->nonce_key[STCP_FORWARD], keys + 64, 32);
    memcpy(s->nonce_key[STCP_REVERSE], keys + 96, 32);
    rc = 0;
end:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(keys, sizeof(keys));
    return rc;
}

static int make_addr(const char *ip, uint16_t port, struct sockaddr_in *addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    return inet_pton(AF_INET, ip, &addr->sin_addr) == 1 ? 0 : -1;
}

/* D1 server is kept on the explicitly configured management IP.
 * D2 client validates its management peer via PSK-authenticated transcript. */
static int open_control(enum stcp_role role, const char *listen_ip,
                        const char *peer_ip, uint16_t port) {
    struct sockaddr_in bind_addr, peer_addr;
    if (make_addr(peer_ip, port, &peer_addr) != 0 ||
        make_addr(listen_ip, port, &bind_addr) != 0) return -1;
    if (role == STCP_D2) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) != 0) {
            close(fd); return -1;
        }
        return fd;
    }
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return -1;
    int yes = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (bind(server, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0 ||
        listen(server, 1) != 0) { close(server); return -1; }
    fprintf(stderr, "[handshake] Waiting for Device2 on %s:%u\n", listen_ip, port);
    struct sockaddr_in remote;
    socklen_t rlen = sizeof(remote);
    int fd = accept(server, (struct sockaddr *)&remote, &rlen);
    close(server);
    if (fd < 0) return -1;
    if (remote.sin_addr.s_addr != peer_addr.sin_addr.s_addr) {
        fprintf(stderr, "[handshake] Unexpected control peer; refusing connection\n");
        close(fd); return -1;
    }
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

int stcp_handshake(enum stcp_role role, const char *listen_ip,
                   const char *peer_ip, uint16_t port,
                   const uint8_t psk[STCP_KEY_LEN], struct stcp_session *s) {
    EVP_PKEY *priv = NULL;
    uint8_t own_pub[32], random_nonce[32];
    uint8_t hello[HS_HELLO_LEN] = {0}, reply[HS_REPLY_LEN] = {0};
    uint8_t transcript[HS_TRANSCRIPT_LEN] = {0};
    uint8_t mac[32], finish[32], peer_pub[32];
    int fd = -1, rc = -1;
    if (generate_ephemeral(&priv, own_pub) != 0 ||
        RAND_bytes(random_nonce, sizeof(random_nonce)) != 1) goto end;
    fd = open_control(role, listen_ip, peer_ip, port);
    if (fd < 0) { perror("control socket"); goto end; }
    if (role == STCP_D2) {
        memcpy(hello, HELLO_MAGIC, 8);
        memcpy(hello + 8, random_nonce, 32);
        memcpy(hello + 40, own_pub, 32);
        if (write_all(fd, hello, sizeof(hello)) != 0 ||
            read_all(fd, reply, sizeof(reply)) != 0 ||
            CRYPTO_memcmp(reply, REPLY_MAGIC, 8) != 0) goto end;
        memcpy(transcript, hello, sizeof(hello));
        memcpy(transcript + sizeof(hello), reply, 72); /* Excludes responder MAC. */
        if (authenticator(psk, transcript, "server", mac) != 0 ||
            CRYPTO_memcmp(mac, reply + 72, 32) != 0) {
            fprintf(stderr, "[handshake] Device1 authentication failed\n");
            goto end;
        }
        memcpy(peer_pub, reply + 40, 32);
        if (authenticator(psk, transcript, "client", finish) != 0 ||
            write_all(fd, finish, sizeof(finish)) != 0 ||
            read_all(fd, finish, sizeof(finish)) != 0 ||
            authenticator(psk, transcript, "ok", mac) != 0 ||
            CRYPTO_memcmp(finish, mac, sizeof(mac)) != 0) goto end;
    } else {
        if (read_all(fd, hello, sizeof(hello)) != 0 ||
            CRYPTO_memcmp(hello, HELLO_MAGIC, 8) != 0) goto end;
        memcpy(reply, REPLY_MAGIC, 8);
        memcpy(reply + 8, random_nonce, 32);
        memcpy(reply + 40, own_pub, 32);
        memcpy(transcript, hello, sizeof(hello));
        memcpy(transcript + sizeof(hello), reply, 72);
        if (authenticator(psk, transcript, "server", reply + 72) != 0 ||
            write_all(fd, reply, sizeof(reply)) != 0 ||
            read_all(fd, finish, sizeof(finish)) != 0 ||
            authenticator(psk, transcript, "client", mac) != 0 ||
            CRYPTO_memcmp(mac, finish, sizeof(mac)) != 0) {
            fprintf(stderr, "[handshake] Device2 authentication failed\n");
            goto end;
        }
        memcpy(peer_pub, hello + 40, 32);
        if (authenticator(psk, transcript, "ok", mac) != 0 ||
            write_all(fd, mac, sizeof(mac)) != 0) goto end;
    }
    if (derive_keys(s, priv, peer_pub, transcript) != 0) goto end;
    fprintf(stderr, "[handshake] Authenticated X25519 exchange succeeded; session keys ready\n");
    rc = 0;
end:
    if (rc != 0) fprintf(stderr, "[handshake] Failed; refusing to activate packet processing\n");
    if (fd >= 0) close(fd);
    EVP_PKEY_free(priv);
    OPENSSL_cleanse(random_nonce, sizeof(random_nonce));
    OPENSSL_cleanse(finish, sizeof(finish));
    OPENSSL_cleanse(mac, sizeof(mac));
    OPENSSL_cleanse(peer_pub, sizeof(peer_pub));
    return rc;
}
