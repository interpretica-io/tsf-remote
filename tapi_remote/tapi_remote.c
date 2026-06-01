/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Remote-access TAPI
 *
 * The engine-side face of the remote RPCs, with default timeouts and
 * the yes/no convenience returns a test wants.
 */

#define TE_LGR_USER     "TAPI remote"

#include "te_config.h"

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_remote.h"
#include "tapi_remote_rpc.h"

/* See description in tapi_remote.h */
te_errno
tapi_remote_ssh_probe(rcf_rpc_server *rpcs, const char *host, int port,
                      te_string *banner, te_string *hostkey_type,
                      te_string *hostkey_fp, int *hostkey_bits)
{
    return rpc_ssh_probe(rpcs, host, port, TAPI_REMOTE_TIMEOUT, banner,
                         hostkey_type, hostkey_fp, hostkey_bits);
}

/* See description in tapi_remote.h */
bool
tapi_remote_ssh_supports(rcf_rpc_server *rpcs, const char *host, int port,
                         const char *kind, const char *algo)
{
    return rpc_ssh_supports(rpcs, host, port, kind, algo,
                            TAPI_REMOTE_TIMEOUT) == 0;
}

/* See description in tapi_remote.h */
te_errno
tapi_remote_ssh_auth_methods(rcf_rpc_server *rpcs, const char *host, int port,
                             const char *user, te_string *methods,
                             bool *none_ok)
{
    return rpc_ssh_auth_methods(rpcs, host, port, user, TAPI_REMOTE_TIMEOUT,
                                methods, none_ok);
}

/* See description in tapi_remote.h */
te_errno
tapi_remote_ssh_login(rcf_rpc_server *rpcs, const char *host, int port,
                      const char *user, const char *password)
{
    return rpc_ssh_auth_password(rpcs, host, port, user, password,
                                 TAPI_REMOTE_TIMEOUT);
}

/* See description in tapi_remote.h */
te_errno
tapi_remote_ssh_exec(rcf_rpc_server *rpcs, const char *host, int port,
                     const char *user, const char *password,
                     const char *command, te_string *output,
                     int *exit_status)
{
    return rpc_ssh_exec(rpcs, host, port, user, password, command,
                        TAPI_REMOTE_TIMEOUT, output, exit_status);
}

/* See description in tapi_remote.h */
bool
tapi_remote_telnet_open(rcf_rpc_server *rpcs, const char *host, int port,
                        te_string *banner)
{
    bool open = false;

    if (rpc_telnet_probe(rpcs, host, port, TAPI_REMOTE_TIMEOUT, &open,
                         banner) != 0)
        return false;
    return open;
}

/* See description in tapi_remote.h */
bool
tapi_remote_rservice_open(rcf_rpc_server *rpcs, const char *host, int port,
                          te_string *banner)
{
    bool open = false;

    if (rpc_rservice_probe(rpcs, host, port, TAPI_REMOTE_TIMEOUT, &open,
                           banner) != 0)
        return false;
    return open;
}
