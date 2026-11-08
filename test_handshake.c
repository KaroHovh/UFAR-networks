#define _POSIX_C_SOURCE 200809L
#include "secure_inline.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    uint8_t psk[32];
    for (size_t i = 0; i < sizeof(psk); ++i) psk[i] = (uint8_t)i;
    int pipe_fd[2];
    assert(pipe(pipe_fd) == 0);
    const uint16_t port = (uint16_t)(20000 + (getpid() % 20000));
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(pipe_fd[0]);
        struct stcp_session *s = calloc(1, sizeof(*s));
        if (!s) _exit(1);
        s->max_seen = 10;
        int rc = stcp_handshake(STCP_D1, "127.0.0.1", "127.0.0.1", port, psk, s);
        if (rc == 0) {
            for (int d = 0; d < 2; ++d)
                if (write(pipe_fd[1], s->traffic_key[d], 32) != 32 ||
                    write(pipe_fd[1], s->nonce_key[d], 32) != 32) rc = -1;
        }
        stcp_session_clear(s); free(s);
        close(pipe_fd[1]);
        _exit(rc == 0 ? 0 : 1);
    }
    close(pipe_fd[1]);
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 200000000L };
    nanosleep(&pause, NULL); /* Allow server bind before client connect. */
    struct stcp_session *s = calloc(1, sizeof(*s));
    assert(s);
    s->max_seen = 10;
    int rc = stcp_handshake(STCP_D2, "127.0.0.1", "127.0.0.1", port, psk, s);
    assert(rc == 0);
    for (int d = 0; d < 2; ++d) {
        uint8_t traffic_key[32], nonce_key[32];
        assert(read(pipe_fd[0], traffic_key, 32) == 32);
        assert(read(pipe_fd[0], nonce_key, 32) == 32);
        assert(memcmp(traffic_key, s->traffic_key[d], 32) == 0);
        assert(memcmp(nonce_key, s->nonce_key[d], 32) == 0);
    }
    close(pipe_fd[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    stcp_session_clear(s); free(s);
    puts("PASS: authenticated X25519 handshake derives identical directional traffic and nonce keys");

    /* Negative test: mismatched PSKs must not activate either peer. */
    pid_t bad_child = fork();
    assert(bad_child >= 0);
    if (bad_child == 0) {
        struct stcp_session *server = calloc(1, sizeof(*server));
        if (!server) _exit(1);
        int result = stcp_handshake(STCP_D1, "127.0.0.1", "127.0.0.1", (uint16_t)(port + 1), psk, server);
        stcp_session_clear(server); free(server);
        _exit(result == -1 ? 0 : 1);
    }
    nanosleep(&pause, NULL);
    uint8_t bad_psk[32];
    memcpy(bad_psk, psk, sizeof(psk));
    bad_psk[0] ^= 1;
    struct stcp_session *bad = calloc(1, sizeof(*bad));
    assert(bad);
    assert(stcp_handshake(STCP_D2, "127.0.0.1", "127.0.0.1", (uint16_t)(port + 1), bad_psk, bad) == -1);
    stcp_session_clear(bad); free(bad);
    assert(waitpid(bad_child, &status, 0) == bad_child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("PASS: mismatched authentication PSK rejects handshake");
    return 0;
}
