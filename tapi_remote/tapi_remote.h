/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Remote-access TAPI
 *
 * @defgroup tapi_remote Remote access (tapi_remote)
 * @{
 *
 * Remote-access services a test drives from an agent: SSH over libssh,
 * and Telnet and the legacy r-services (rlogin, rsh) over raw sockets.
 * It runs in the agent's RPC server, where the device under test is
 * reachable; this is the engine-side face of those RPCs.
 *
 * Two uses in one API. **Quality**: reach a service, read what it is,
 * force a particular SSH algorithm or authentication method and check
 * it negotiates, run a command and read its output. **Security**: the
 * same primitives, plus the audit, ask what the service exposes - a
 * plaintext Telnet or r-service at all, an SSH that still accepts a
 * broken cipher, key exchange, MAC or host key, an SSH that lets a
 * client in with no authentication or a guessable password. Point the
 * security side only at a host you are authorized to assess.
 *
 * @code
 * te_string banner = TE_STRING_INIT;
 * te_string hk = TE_STRING_INIT;
 *
 * CHECK_RC(tapi_remote_ssh_probe(rpcs, "192.0.2.1", 0, &banner, &hk,
 *                                NULL, NULL));
 * @endcode
 */

#ifndef __TAPI_REMOTE_H__
#define __TAPI_REMOTE_H__

#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#include "tapi_remote_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default per-operation timeout, seconds. */
#define TAPI_REMOTE_TIMEOUT 10

/**
 * Connect over SSH with the defaults and read the server out: its
 * identification banner, host-key type and SHA-256 fingerprint.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  host         Target host.
 * @param[in]  port         Port, or @c 0 for 22.
 * @param[out] banner       The SSH identification string, or @c NULL.
 * @param[out] hostkey_type The host-key type, or @c NULL.
 * @param[out] hostkey_fp   Its SHA-256 fingerprint, or @c NULL.
 * @param[out] hostkey_bits Its size in bits, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno tapi_remote_ssh_probe(rcf_rpc_server *rpcs, const char *host,
                                      int port, te_string *banner,
                                      te_string *hostkey_type,
                                      te_string *hostkey_fp,
                                      int *hostkey_bits);

/**
 * Does the SSH server accept this one algorithm?
 *
 * Offers @p algo alone for its class and returns whether the key
 * exchange still completes - the "under many sauces" primitive.
 *
 * @param rpcs      RPC server on the agent.
 * @param host      Target host.
 * @param port      Port, or @c 0 for 22.
 * @param kind      @c "kex", @c "cipher_cs", @c "cipher_sc",
 *                  @c "mac_cs", @c "mac_sc" or @c "hostkey".
 * @param algo      The one algorithm name.
 *
 * @return @c true when the server accepted it.
 */
extern bool tapi_remote_ssh_supports(rcf_rpc_server *rpcs, const char *host,
                                     int port, const char *kind,
                                     const char *algo);

/**
 * The SSH authentication methods offered a user.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  host     Target host.
 * @param[in]  port     Port, or @c 0 for 22.
 * @param[in]  user     User name.
 * @param[out] methods  Comma-separated method list, or @c NULL.
 * @param[out] none_ok  @c true when @c "none" authentication logged in.
 *
 * @return Status code.
 */
extern te_errno tapi_remote_ssh_auth_methods(rcf_rpc_server *rpcs,
                                             const char *host, int port,
                                             const char *user,
                                             te_string *methods,
                                             bool *none_ok);

/**
 * Try an SSH password login.
 *
 * @return @c 0 when it logged in, @c TE_EACCES when refused.
 */
extern te_errno tapi_remote_ssh_login(rcf_rpc_server *rpcs, const char *host,
                                      int port, const char *user,
                                      const char *password);

/**
 * Run one command over an SSH password session.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  host         Target host.
 * @param[in]  port         Port, or @c 0 for 22.
 * @param[in]  user         User.
 * @param[in]  password     Password.
 * @param[in]  command      Command.
 * @param[out] output       Its output, or @c NULL.
 * @param[out] exit_status  Its exit status, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno tapi_remote_ssh_exec(rcf_rpc_server *rpcs, const char *host,
                                     int port, const char *user,
                                     const char *password,
                                     const char *command, te_string *output,
                                     int *exit_status);

/**
 * Is a plaintext Telnet service answering?
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  host     Target host.
 * @param[in]  port     Port, or @c 0 for 23.
 * @param[out] banner   The banner it sent, or @c NULL.
 *
 * @return @c true when the port answered.
 */
extern bool tapi_remote_telnet_open(rcf_rpc_server *rpcs, const char *host,
                                    int port, te_string *banner);

/**
 * Is a legacy r-service (rlogin 513, rsh 514) answering?
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  host     Target host.
 * @param[in]  port     Port, or @c 0 for 513.
 * @param[out] banner   Any bytes it sent, or @c NULL.
 *
 * @return @c true when the port answered.
 */
extern bool tapi_remote_rservice_open(rcf_rpc_server *rpcs, const char *host,
                                      int port, te_string *banner);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_REMOTE_H__ */

/**@} <!-- END tapi_remote --> */
