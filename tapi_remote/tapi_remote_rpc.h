/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Remote-access TAPI: RPC client wrappers
 *
 * Client wrappers of the ssh, telnet and rservice RPCs, see
 * remote_rpc.x.m4. Tests use tapi_remote.h; these are the calls behind
 * it, one per RPC.
 */

#ifndef __TAPI_REMOTE_RPC_H__
#define __TAPI_REMOTE_RPC_H__

#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Connect over SSH with defaults and read the server out. */
extern te_errno rpc_ssh_probe(rcf_rpc_server *rpcs, const char *host,
                              int port, int timeout, te_string *banner,
                              te_string *hostkey_type, te_string *hostkey_fp,
                              int *hostkey_bits);

/** Force one algorithm and report whether the KEX still completes. */
extern te_errno rpc_ssh_supports(rcf_rpc_server *rpcs, const char *host,
                                 int port, const char *kind, const char *algo,
                                 int timeout);

/** The authentication methods offered a user. */
extern te_errno rpc_ssh_auth_methods(rcf_rpc_server *rpcs, const char *host,
                                     int port, const char *user, int timeout,
                                     te_string *methods, bool *none_ok);

/** Try one SSH password; @c 0 means it logged in. */
extern te_errno rpc_ssh_auth_password(rcf_rpc_server *rpcs, const char *host,
                                      int port, const char *user,
                                      const char *password, int timeout);

/** Run one command over an SSH password session. */
extern te_errno rpc_ssh_exec(rcf_rpc_server *rpcs, const char *host, int port,
                             const char *user, const char *password,
                             const char *command, int timeout,
                             te_string *output, int *exit_status);

/** Reach a Telnet port and read its banner. */
extern te_errno rpc_telnet_probe(rcf_rpc_server *rpcs, const char *host,
                                 int port, int timeout, bool *open,
                                 te_string *banner);

/** Reach a legacy r-service (rlogin/rsh). */
extern te_errno rpc_rservice_probe(rcf_rpc_server *rpcs, const char *host,
                                   int port, int timeout, bool *open,
                                   te_string *banner);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_REMOTE_RPC_H__ */
