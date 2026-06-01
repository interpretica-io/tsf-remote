/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side remote-access client
 *
 * SSH over libssh (0.9+), Telnet and the r-services over raw sockets.
 * The SSH probing never verifies the server's host key against a
 * known-hosts file - the point is to reach unknown servers and report
 * what they are - so it connects, reads the server out, and does not
 * call the known-host check.
 */

#define TE_LGR_USER     "TA remote"

#include "te_config.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>

#include <libssh/libssh.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "ta_remote.h"

/** Open an SSH session to @p host:@p port with a connect timeout. */
static ssh_session
remote_ssh_open(const char *host, int port, int timeout)
{
    ssh_session s = ssh_new();
    unsigned int p = port > 0 ? (unsigned int)port : 22;
    long tmo = timeout > 0 ? timeout : 10;
    int verbosity = SSH_LOG_NONE;

    if (s == NULL)
        return NULL;

    ssh_options_set(s, SSH_OPTIONS_HOST, host);
    ssh_options_set(s, SSH_OPTIONS_PORT, &p);
    ssh_options_set(s, SSH_OPTIONS_TIMEOUT, &tmo);
    ssh_options_set(s, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    return s;
}

/* See description in ta_remote.h */
te_errno
ta_remote_ssh_probe(const char *host, int port, int timeout,
                    te_string *banner, te_string *hostkey_type,
                    te_string *hostkey_fp, int *hostkey_bits)
{
    ssh_session s = remote_ssh_open(host, port, timeout);
    ssh_key key = NULL;
    const char *id;
    te_errno rc = 0;

    if (hostkey_bits != NULL)
        *hostkey_bits = 0;
    if (s == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);

    if (ssh_connect(s) != SSH_OK)
    {
        ERROR("ssh_connect(%s): %s", host, ssh_get_error(s));
        rc = TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
        goto out;
    }

    id = ssh_get_serverbanner(s);
    if (id != NULL && banner != NULL)
        te_string_append(banner, "%s", id);

    if (ssh_get_server_publickey(s, &key) == SSH_OK)
    {
        unsigned char *hash = NULL;
        size_t hlen = 0;
        const char *t = ssh_key_type_to_char(ssh_key_type(key));

        if (t != NULL && hostkey_type != NULL)
            te_string_append(hostkey_type, "%s", t);

        if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256,
                                   &hash, &hlen) == 0)
        {
            char *fp = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256,
                                                hash, hlen);

            if (fp != NULL && hostkey_fp != NULL)
                te_string_append(hostkey_fp, "%s", fp);
            ssh_string_free_char(fp);
            ssh_clean_pubkey_hash(&hash);
        }
        ssh_key_free(key);
    }

out:
    ssh_disconnect(s);
    ssh_free(s);
    return rc;
}

/* See description in ta_remote.h */
te_errno
ta_remote_ssh_supports(const char *host, int port, const char *kind,
                       const char *algo, int timeout)
{
    ssh_session s = remote_ssh_open(host, port, timeout);
    enum ssh_options_e opt;
    te_errno rc = 0;

    if (s == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);
    if (kind == NULL || algo == NULL)
    {
        ssh_free(s);
        return TE_RC(TE_TA_UNIX, TE_EINVAL);
    }

    if (strcmp(kind, "kex") == 0)
        opt = SSH_OPTIONS_KEY_EXCHANGE;
    else if (strcmp(kind, "cipher_cs") == 0)
        opt = SSH_OPTIONS_CIPHERS_C_S;
    else if (strcmp(kind, "cipher_sc") == 0)
        opt = SSH_OPTIONS_CIPHERS_S_C;
    else if (strcmp(kind, "mac_cs") == 0)
        opt = SSH_OPTIONS_HMAC_C_S;
    else if (strcmp(kind, "mac_sc") == 0)
        opt = SSH_OPTIONS_HMAC_S_C;
    else if (strcmp(kind, "hostkey") == 0)
        opt = SSH_OPTIONS_HOSTKEYS;
    else
    {
        ssh_free(s);
        return TE_RC(TE_TA_UNIX, TE_EINVAL);
    }

    /* Offer only this one algorithm; if KEX still completes it is supported. */
    if (ssh_options_set(s, opt, algo) != 0)
    {
        /* The local libssh does not even know the name. */
        ssh_free(s);
        return TE_RC(TE_TA_UNIX, TE_EOPNOTSUPP);
    }

    if (ssh_connect(s) != SSH_OK)
        rc = TE_RC(TE_TA_UNIX, TE_EPROTO);

    ssh_disconnect(s);
    ssh_free(s);
    return rc;
}

/* See description in ta_remote.h */
te_errno
ta_remote_ssh_auth_methods(const char *host, int port, const char *user,
                           int timeout, te_string *methods, bool *none_ok)
{
    ssh_session s = remote_ssh_open(host, port, timeout);
    int rc_none;
    int list;
    te_errno rc = 0;

    if (none_ok != NULL)
        *none_ok = false;
    if (s == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);
    if (user != NULL)
        ssh_options_set(s, SSH_OPTIONS_USER, user);

    if (ssh_connect(s) != SSH_OK)
    {
        ERROR("ssh_connect(%s): %s", host, ssh_get_error(s));
        rc = TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
        goto out;
    }

    /* The "none" probe both tells if it logs in and primes the list. */
    rc_none = ssh_userauth_none(s, NULL);
    if (rc_none == SSH_AUTH_SUCCESS && none_ok != NULL)
        *none_ok = true;

    list = ssh_userauth_list(s, NULL);
    if (methods != NULL)
    {
        if (list & SSH_AUTH_METHOD_NONE)
            te_string_append(methods, "%snone", methods->len ? "," : "");
        if (list & SSH_AUTH_METHOD_PASSWORD)
            te_string_append(methods, "%spassword", methods->len ? "," : "");
        if (list & SSH_AUTH_METHOD_PUBLICKEY)
            te_string_append(methods, "%spublickey", methods->len ? "," : "");
        if (list & SSH_AUTH_METHOD_INTERACTIVE)
            te_string_append(methods, "%skeyboard-interactive",
                             methods->len ? "," : "");
        if (list & SSH_AUTH_METHOD_HOSTBASED)
            te_string_append(methods, "%shostbased", methods->len ? "," : "");
    }

out:
    ssh_disconnect(s);
    ssh_free(s);
    return rc;
}

/* See description in ta_remote.h */
te_errno
ta_remote_ssh_auth_password(const char *host, int port, const char *user,
                            const char *password, int timeout)
{
    ssh_session s = remote_ssh_open(host, port, timeout);
    te_errno rc;

    if (s == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);
    if (user != NULL)
        ssh_options_set(s, SSH_OPTIONS_USER, user);

    if (ssh_connect(s) != SSH_OK)
    {
        ssh_free(s);
        return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
    }

    rc = ssh_userauth_password(s, NULL, password) == SSH_AUTH_SUCCESS ?
         0 : TE_RC(TE_TA_UNIX, TE_EACCES);

    ssh_disconnect(s);
    ssh_free(s);
    return rc;
}

/* See description in ta_remote.h */
te_errno
ta_remote_ssh_exec(const char *host, int port, const char *user,
                   const char *password, const char *command, int timeout,
                   te_string *output, int *exit_status)
{
    ssh_session s = remote_ssh_open(host, port, timeout);
    ssh_channel ch;
    char buf[4096];
    int n;
    te_errno rc = 0;

    if (exit_status != NULL)
        *exit_status = -1;
    if (s == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);
    if (user != NULL)
        ssh_options_set(s, SSH_OPTIONS_USER, user);

    if (ssh_connect(s) != SSH_OK)
    {
        ssh_free(s);
        return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
    }
    if (ssh_userauth_password(s, NULL, password) != SSH_AUTH_SUCCESS)
    {
        ssh_disconnect(s);
        ssh_free(s);
        return TE_RC(TE_TA_UNIX, TE_EACCES);
    }

    ch = ssh_channel_new(s);
    if (ch == NULL)
    {
        rc = TE_RC(TE_TA_UNIX, TE_ENOMEM);
        goto out;
    }
    if (ssh_channel_open_session(ch) != SSH_OK ||
        ssh_channel_request_exec(ch, command) != SSH_OK)
    {
        ssh_channel_free(ch);
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);
        goto out;
    }

    while ((n = ssh_channel_read(ch, buf, sizeof(buf), 0)) > 0)
    {
        if (output != NULL)
            te_string_append(output, "%.*s", n, buf);
    }
    ssh_channel_send_eof(ch);
    if (exit_status != NULL)
    {
#if defined(LIBSSH_VERSION_INT) && defined(SSH_VERSION_INT) && \
    (LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 11, 0))
        uint32_t code = 0;

        /* Renamed in 0.11; the old name is deprecated there. */
        ssh_channel_get_exit_state(ch, &code, NULL, NULL);
        *exit_status = (int)code;
#else
        *exit_status = ssh_channel_get_exit_status(ch);
#endif
    }
    ssh_channel_close(ch);
    ssh_channel_free(ch);

out:
    ssh_disconnect(s);
    ssh_free(s);
    return rc;
}

/** Connect a TCP socket to @p host:@p port with a timeout, or @c -1. */
static int
remote_tcp_connect(const char *host, int port, int timeout)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portstr[16];
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;

    for (ai = res; ai != NULL; ai = ai->ai_next)
    {
        struct timeval tv;

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;

        tv.tv_sec = timeout > 0 ? timeout : 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0)
            break;

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

/** Append @p n bytes of @p data, dropping Telnet IAC option sequences. */
static void
remote_strip_iac(te_string *dest, const unsigned char *data, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        if (data[i] == 0xff) /* IAC: skip the command and its option byte. */
        {
            if (i + 1 < n && (data[i + 1] == 0xfb || data[i + 1] == 0xfc ||
                              data[i + 1] == 0xfd || data[i + 1] == 0xfe))
                i += 2;
            else
                i += 1;
            continue;
        }
        if (data[i] == '\0')
            continue;
        te_string_append(dest, "%c", data[i]);
    }
}

/* See description in ta_remote.h */
te_errno
ta_remote_telnet_probe(const char *host, int port, int timeout, bool *open,
                       te_string *banner)
{
    int sock = remote_tcp_connect(host, port > 0 ? port : 23, timeout);
    unsigned char buf[2048];
    ssize_t n;

    if (open != NULL)
        *open = false;
    if (sock < 0)
        return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);

    if (open != NULL)
        *open = true;

    /* Read whatever the server offers up front (options and/or a banner). */
    n = recv(sock, buf, sizeof(buf), 0);
    if (n > 0 && banner != NULL)
        remote_strip_iac(banner, buf, (size_t)n);

    close(sock);
    return 0;
}

/* See description in ta_remote.h */
te_errno
ta_remote_rservice_probe(const char *host, int port, int timeout, bool *open,
                         te_string *banner)
{
    int sock = remote_tcp_connect(host, port > 0 ? port : 513, timeout);
    char buf[512];
    ssize_t n;

    if (open != NULL)
        *open = false;
    if (sock < 0)
        return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);

    if (open != NULL)
        *open = true;

    /*
     * The rlogin/rsh handshake starts with a NUL-terminated field from
     * the client; sending an empty one is enough to make many servers
     * answer (often with an error), which is all a reachability probe
     * needs. The bytes that come back, if any, are the banner.
     */
    if (send(sock, "\0", 1, 0) < 0)
    {
        /* Not fatal: the port answered, which is the finding. */
    }
    n = recv(sock, buf, sizeof(buf), 0);
    if (n > 0 && banner != NULL)
        te_string_append(banner, "%.*s", (int)n, buf);

    close(sock);
    return 0;
}
