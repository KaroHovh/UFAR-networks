#define _POSIX_C_SOURCE 200809L
#include "secure_inline.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/crypto.h>
#include <linux/netfilter.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

struct program {
    struct stcp_session session;
    struct stcp_config cfg;
    size_t transformed, dropped;
};
static volatile sig_atomic_t stop_requested = 0;
static void stop_handler(int signum) { (void)signum; stop_requested = 1; }

static void usage(const char *name) {
    fprintf(stderr,
        "Usage: %s --role d1|d2 --psk FILE [options]\n"
        "Options:\n"
        " --pc1 IPv4         PC1 address (default: 10.1.0.2)\n"
        " --pc2 IPv4         PC2 address (default: 10.2.0.2)\n"
        " --port N           Protected TCP service (default: 5000)\n"
        " --queue N          NFQUEUE number (default: 10)\n"
        " --listen IPv4      D1 management bind (default: 10.12.0.1)\n"
        " --peer IPv4        Other device management IP (D1: 10.12.0.2; D2: 10.12.0.1)\n"
        " --control-port N   Handshake TCP port (default: 4444)\n"
        " --max-seen N       Encryption nonce ledger limit (default: 20000)\n", name);
}

static int parse_port(const char *value, int allow_zero) {
    char *end = NULL;
    errno = 0;
    unsigned long x = strtoul(value, &end, 10);
    if (errno || !value[0] || *end || x > 65535 || (!allow_zero && x == 0)) return -1;
    return (int)x;
}

static int read_psk(const char *path, uint8_t psk[32]) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 0077)) {
        fprintf(stderr, "PSK file must exist, be regular, and have mode 0600 or stricter\n");
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    uint8_t extra;
    ssize_t n = read(fd, psk, 32);
    int valid = n == 32 && read(fd, &extra, 1) == 0;
    close(fd);
    if (!valid) fprintf(stderr, "PSK file must contain exactly 32 random bytes\n");
    return valid ? 0 : -1;
}

static int queued_packet(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                         struct nfq_data *nfad, void *ctx) {
    (void)msg;
    struct program *p = ctx;
    struct nfqnl_msg_packet_hdr *h = nfq_get_msg_packet_hdr(nfad);
    if (!h) return -1;
    uint32_t id = ntohl(h->packet_id);
    unsigned char *original = NULL;
    int n = nfq_get_payload(nfad, &original);
    if (n <= 0 || n > (int)STCP_MAX_PACKET) {
        p->dropped++;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    /* Never mutate Netlink-owned memory; allow room for the appended tag. */
    uint8_t packet[STCP_MAX_PACKET];
    memcpy(packet, original, (size_t)n);
    size_t length = (size_t)n;
    int rc = stcp_transform(&p->session, &p->cfg, packet, &length);
    if (rc == STCP_DROP) {
        p->dropped++;
        if (p->dropped <= 10 || p->dropped % 100 == 0)
            fprintf(stderr, "[packet] Dropped invalid/unauthenticated packet (total=%zu)\n", p->dropped);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    if (rc == STCP_MODIFIED) {
        p->transformed++;
        if (p->transformed % 100 == 0)
            fprintf(stderr, "[packet] Transformed %zu packets\n", p->transformed);
        return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)length, packet);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct program *p = calloc(1, sizeof(*p));
    if (!p) return 1;
    const char *pc1 = "10.1.0.2", *pc2 = "10.2.0.2";
    const char *psk_path = NULL, *listen_ip = "10.12.0.1", *peer_ip = NULL;
    enum stcp_role role = STCP_D1;
    int role_given = 0, port = 5000, queue_id = 10, control_port = 4444;
    p->session.max_seen = 20000;
    static const struct option options[] = {
        {"role", required_argument, NULL, 'r'},
        {"psk", required_argument, NULL, 'k'},
        {"pc1", required_argument, NULL, 'a'},
        {"pc2", required_argument, NULL, 'b'},
        {"port", required_argument, NULL, 'p'},
        {"queue", required_argument, NULL, 'q'},
        {"listen", required_argument, NULL, 'l'},
        {"peer", required_argument, NULL, 'e'},
        {"control-port", required_argument, NULL, 'c'},
        {"max-seen", required_argument, NULL, 'm'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (opt) {
            case 'r':
                if (!strcmp(optarg, "d1")) role = STCP_D1;
                else if (!strcmp(optarg, "d2")) role = STCP_D2;
                else goto invalid;
                role_given = 1; break;
            case 'k': psk_path = optarg; break;
            case 'a': pc1 = optarg; break;
            case 'b': pc2 = optarg; break;
            case 'l': listen_ip = optarg; break;
            case 'e': peer_ip = optarg; break;
            case 'p': port = parse_port(optarg, 0); if (port < 0) goto invalid; break;
            case 'q': queue_id = parse_port(optarg, 1); if (queue_id < 0) goto invalid; break;
            case 'c': control_port = parse_port(optarg, 0); if (control_port < 0) goto invalid; break;
            case 'm': {
                char *end; errno = 0;
                unsigned long v = strtoul(optarg, &end, 10);
                if (errno || !optarg[0] || *end || v < 1 || v > 100000) goto invalid;
                p->session.max_seen = (size_t)v;
                break;
            }
            case 'h': usage(argv[0]); free(p); return 0;
            default: goto invalid;
        }
    }
    if (!role_given || !psk_path || optind != argc) goto invalid;
    if (!peer_ip) peer_ip = role == STCP_D1 ? "10.12.0.2" : "10.12.0.1";
    if (inet_pton(AF_INET, pc1, p->cfg.pc1) != 1 ||
        inet_pton(AF_INET, pc2, p->cfg.pc2) != 1) goto invalid;
    p->cfg.role = role;
    p->cfg.service_port = (uint16_t)port;
    uint8_t psk[32] = {0};
    if (read_psk(psk_path, psk) != 0) { free(p); return 1; }
    if (stcp_handshake(role, listen_ip, peer_ip, (uint16_t)control_port, psk, &p->session) != 0) {
        OPENSSL_cleanse(psk, sizeof(psk));
        stcp_session_clear(&p->session); free(p); return 1;
    }
    OPENSSL_cleanse(psk, sizeof(psk));

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); goto fail; }
    struct nfq_q_handle *qh = nfq_create_queue(h, (uint16_t)queue_id, queued_packet, p);
    if (!qh || nfq_set_mode(qh, NFQNL_COPY_PACKET, STCP_MAX_PACKET) != 0) {
        fprintf(stderr, "Failed to open/configure NFQUEUE (root and libnetfilter_queue required)\n");
        if (qh) nfq_destroy_queue(qh);
        nfq_close(h); goto fail;
    }
    if (nfq_set_queue_maxlen(qh, 4096) < 0) fprintf(stderr, "Warning: queue length unchanged\n");
    struct sigaction sa = {0};
    sa.sa_handler = stop_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    fprintf(stderr, "[ready] role=d%d queue=%d TCP/%d; session active\n",
            role == STCP_D1 ? 1 : 2, queue_id, port);
    int fd = nfq_fd(h);
    unsigned char netlink_buf[131072];
    while (!stop_requested) {
        ssize_t n = recv(fd, netlink_buf, sizeof(netlink_buf), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { perror("nfq recv"); break; }
        if (n == 0) break;
        if (nfq_handle_packet(h, (char *)netlink_buf, (int)n) < 0)
            fprintf(stderr, "[nfqueue] Warning: parse/verdict failure\n");
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
    fprintf(stderr, "[exit] transformed=%zu dropped=%zu\n", p->transformed, p->dropped);
    stcp_session_clear(&p->session); free(p);
    return 0;
invalid:
    usage(argv[0]);
    stcp_session_clear(&p->session); free(p);
    return 2;
fail:
    stcp_session_clear(&p->session); free(p);
    return 1;
}
