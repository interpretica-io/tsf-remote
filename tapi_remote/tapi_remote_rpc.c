/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Remote-access TAPI: RPC client wrappers
 *
 * The rcf_rpc_call() boilerplate behind tapi_remote.
 */

#define TE_LGR_USER     "TAPI remote RPC"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_rpc_internal.h"
#include "tarpc.h"

#include "tapi_remote_rpc.h"

#define CHECK_RPC_ERRNO_UNCHANGED(_func, _var) \
    CHECK_RETVAL_VAR_ERR_COND(_func, _var, false,                    \
                              TE_RC(TE_TAPI, TE_ECORRUPTED), false)

static void
take_string(te_string *dst, const char *src)
{
    if (dst != NULL && src != NULL)
        te_string_append(dst, "%s", src);
}

/* See description in tapi_remote_rpc.h */
te_errno
rpc_ssh_probe(rcf_rpc_server *rpcs, const char *host, int port, int timeout,
              te_string *banner, te_string *hostkey_type,
              te_string *hostkey_fp, int *hostkey_bits)
{
    tarpc_ssh_probe_in in;
    tarpc_ssh_probe_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.host = (char *)host;
    in.port = port;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "ssh_probe", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ssh_probe, out.retval);
    TAPI_RPC_LOG(rpcs, ssh_probe, "%s:%d", "%r hostkey=%s", host, port,
                 out.retval, out.hostkey_type != NULL ? out.hostkey_type : "");

    if (out.retval == 0)
    {
        take_string(banner, out.banner);
        take_string(hostkey_type, out.hostkey_type);
        take_string(hostkey_fp, out.hostkey_fp);
        if (hostkey_bits != NULL)
            *hostkey_bits = out.hostkey_bits;
    }
    RETVAL_TE_ERRNO(ssh_probe, out.retval);
}

/* See description in tapi_remote_rpc.h */
te_errno
rpc_ssh_supports(rcf_rpc_server *rpcs, const char *host, int port,
                 const char *kind, const char *algo, int timeout)
{
    tarpc_ssh_supports_in in;
    tarpc_ssh_supports_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.host = (char *)host;
    in.port = port;
    in.kind = (char *)kind;
    in.algo = (char *)algo;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "ssh_supports", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ssh_supports, out.retval);
    TAPI_RPC_LOG(rpcs, ssh_supports, "%s %s", "%r", kind, algo, out.retval);
    RETVAL_TE_ERRNO(ssh_supports, out.retval);
}

/* See description in tapi_remote_rpc.h */
te_errno
rpc_ssh_auth_methods(rcf_rpc_server *rpcs, const char *host, int port,
                     const char *user, int timeout, te_string *methods,
                     bool *none_ok)
{
    tarpc_ssh_auth_methods_in in;
    tarpc_ssh_auth_methods_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.host = (char *)host;
    in.port = port;
    in.user = (char *)user;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "ssh_auth_methods", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ssh_auth_methods, out.retval);
    TAPI_RPC_LOG(rpcs, ssh_auth_methods, "%s@%s", "%r methods=%s",
                 user != NULL ? user : "", host, out.retval,
                 out.methods != NULL ? out.methods : "");

    if (out.retval == 0)
    {
        take_string(methods, out.methods);
        if (none_ok != NULL)
            *none_ok = out.none_ok;
    }
    RETVAL_TE_ERRNO(ssh_auth_methods, out.retval);
}

/* See description in tapi_remote_rpc.h */
te_errno
rpc_ssh_auth_password(rcf_rpc_server *rpcs, const char *host, int port,
                      const char *user, const char *password, int timeout)
{
    tarpc_ssh_auth_password_in in;
    tarpc_ssh_auth_password_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.host = (char *)host;
    in.port = port;
    in.user = (char *)user;
    in.password = (char *)password;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "ssh_auth_password", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ssh_auth_password, out.retval);
    TAPI_RPC_LOG(rpcs, ssh_auth_password, "%s@%s", "%r",
                 user != NULL ? user : "", host, out.retval);
    RETVAL_TE_ERRNO(ssh_auth_password, out.retval);
}

/* See description in tapi_remote_rpc.h */
te_errno
rpc_ssh_exec(rcf_rpc_server *rpcs, const char *host, int port,
             const char *user, const char *password, const char *command,
             int timeout, te_string *output, int *exit_status)
{
    tarpc_ssh_exec_in in;
    tarpc_ssh_exec_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.host = (char *)host;
    in.port = port;
    in.user = (char *)user;
    in.password = (char *)password;
    in.command = (char *)command;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "ssh_exec", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ssh_exec, out.retval);
    TAPI_RPC_LOG(rpcs, ssh_exec, "%s@%s: %s", "%r status=%d",
                 user != NULL ? user : "", host,
                 command != NULL ? command : "", out.retval, out.exit_status);

    if (out.retval == 0)
    {
        take_string(output, out.output);
        if (exit_status != NULL)
            *exit_status = out.exit_status;
    }
    RETVAL_TE_ERRNO(ssh_exec, out.retval);
}

/* See description in tapi_remote_rpc.h */
te_errno
rpc_telnet_probe(rcf_rpc_server *rpcs, const char *host, int port,
                 int timeout, bool *open, te_string *banner)
{
    tarpc_telnet_probe_in in;
    tarpc_telnet_probe_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.host = (char *)host;
    in.port = port;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "telnet_probe", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(telnet_probe, out.retval);
    TAPI_RPC_LOG(rpcs, telnet_probe, "%s:%d", "%r open=%d", host, port,
                 out.retval, out.open);

    if (out.retval == 0)
    {
        if (open != NULL)
            *open = out.open;
        take_string(banner, out.banner);
    }
    RETVAL_TE_ERRNO(telnet_probe, out.retval);
}

/* See description in tapi_remote_rpc.h */
te_errno
rpc_rservice_probe(rcf_rpc_server *rpcs, const char *host, int port,
                   int timeout, bool *open, te_string *banner)
{
    tarpc_rservice_probe_in in;
    tarpc_rservice_probe_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.host = (char *)host;
    in.port = port;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "rservice_probe", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(rservice_probe, out.retval);
    TAPI_RPC_LOG(rpcs, rservice_probe, "%s:%d", "%r open=%d", host, port,
                 out.retval, out.open);

    if (out.retval == 0)
    {
        if (open != NULL)
            *open = out.open;
        take_string(banner, out.banner);
    }
    RETVAL_TE_ERRNO(rservice_probe, out.retval);
}
