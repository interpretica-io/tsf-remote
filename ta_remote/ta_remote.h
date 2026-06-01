/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side remote-access client (SSH, Telnet, r-services)
 *
 * SSH over libssh, and Telnet and the legacy r-services (rlogin/rsh)
 * over raw sockets. The SSH side is built to be driven "under many
 * sauces": force one algorithm of a class per connection and see
 * whether the key exchange still completes, the way tsf-smb forces a
 * dialect - that is how the audit learns which weak algorithms a
 * server still accepts.
 *
 * Every call names its target host and port; nothing persists between
 * calls.
 */

#ifndef __TA_REMOTE_H__
#define __TA_REMOTE_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Connect over SSH with the library defaults and report the server.
 *
 * @param[in]  host         Host name or address.
 * @param[in]  port         Port, or @c 0 for 22.
 * @param[in]  timeout      Connect timeout, seconds (0 for the default).
 * @param[out] banner       The SSH identification string.
 * @param[out] hostkey_type The server host-key type (@c "ssh-ed25519", …).
 * @param[out] hostkey_fp   Its SHA-256 fingerprint, base64.
 * @param[out] hostkey_bits Its size in bits, or @c 0 when not known.
 *
 * @return Status code.
 */
extern te_errno ta_remote_ssh_probe(const char *host, int port, int timeout,
                                    te_string *banner, te_string *hostkey_type,
                                    te_string *hostkey_fp, int *hostkey_bits);

/**
 * Force one algorithm of a class and see whether the SSH key exchange
 * still completes - whether the server supports it.
 *
 * @param host      Host.
 * @param port      Port, or @c 0 for 22.
 * @param kind      @c "kex", @c "cipher_cs", @c "cipher_sc",
 *                  @c "mac_cs", @c "mac_sc" or @c "hostkey".
 * @param algo      The single algorithm name to offer.
 * @param timeout   Timeout, seconds.
 *
 * @return @c 0 when the server accepted it, an error otherwise.
 */
extern te_errno ta_remote_ssh_supports(const char *host, int port,
                                       const char *kind, const char *algo,
                                       int timeout);

/**
 * The authentication methods the server offers a user.
 *
 * @param[in]  host     Host.
 * @param[in]  port     Port, or @c 0 for 22.
 * @param[in]  user     User name.
 * @param[in]  timeout  Timeout, seconds.
 * @param[out] methods  Comma-separated method list.
 * @param[out] none_ok  @c true when @c "none" authentication logged in.
 *
 * @return Status code.
 */
extern te_errno ta_remote_ssh_auth_methods(const char *host, int port,
                                           const char *user, int timeout,
                                           te_string *methods, bool *none_ok);

/**
 * Try one SSH password.
 *
 * @return @c 0 when it logged in, @c TE_EACCES when refused.
 */
extern te_errno ta_remote_ssh_auth_password(const char *host, int port,
                                            const char *user,
                                            const char *password, int timeout);

/**
 * Run one command over an SSH password session.
 *
 * @param[in]  host         Host.
 * @param[in]  port         Port, or @c 0 for 22.
 * @param[in]  user         User.
 * @param[in]  password     Password.
 * @param[in]  command      Command to run.
 * @param[in]  timeout      Timeout, seconds.
 * @param[out] output       Its standard output.
 * @param[out] exit_status  Its exit status.
 *
 * @return Status code.
 */
extern te_errno ta_remote_ssh_exec(const char *host, int port,
                                   const char *user, const char *password,
                                   const char *command, int timeout,
                                   te_string *output, int *exit_status);

/**
 * Reach a Telnet port, read its banner, report whether it answered.
 *
 * @param[in]  host     Host.
 * @param[in]  port     Port, or @c 0 for 23.
 * @param[in]  timeout  Timeout, seconds.
 * @param[out] open     @c true when the port answered.
 * @param[out] banner   The first text the server sent (IAC stripped).
 *
 * @return Status code.
 */
extern te_errno ta_remote_telnet_probe(const char *host, int port,
                                       int timeout, bool *open,
                                       te_string *banner);

/**
 * Reach a legacy r-service (rlogin 513, rsh/rexec 514).
 *
 * @param[in]  host     Host.
 * @param[in]  port     Port, or @c 0 for 513.
 * @param[in]  timeout  Timeout, seconds.
 * @param[out] open     @c true when the port answered.
 * @param[out] banner   Any bytes the service sent back.
 *
 * @return Status code.
 */
extern te_errno ta_remote_rservice_probe(const char *host, int port,
                                         int timeout, bool *open,
                                         te_string *banner);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_REMOTE_H__ */
