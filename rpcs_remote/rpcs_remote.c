/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Remote-access RPC server library
 *
 * The ssh_*, telnet_* and rservice_* RPCs (see remote_rpc.x.m4) on top
 * of ta_remote. TARPC_FUNC_STATIC() binds an RPC to the function of
 * the same name, so each RPC has a plain C function first and the
 * wrapper after it.
 */

#define TE_LGR_USER     "RPC remote"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "rpc_server.h"

#include "ta_remote.h"

/* Hand a te_string result over to an RPC string field. */
static char *
take(te_string *str)
{
    return str->ptr != NULL ? str->ptr : TE_STRDUP("");
}

static te_errno
ssh_probe(const char *host, int port, int timeout, char **banner,
          char **hostkey_type, char **hostkey_fp, int *hostkey_bits)
{
    te_string b = TE_STRING_INIT;
    te_string t = TE_STRING_INIT;
    te_string f = TE_STRING_INIT;
    te_errno rc = ta_remote_ssh_probe(host, port, timeout, &b, &t, &f,
                                      hostkey_bits);

    *banner = take(&b);
    *hostkey_type = take(&t);
    *hostkey_fp = take(&f);
    return rc;
}

TARPC_FUNC_STATIC(ssh_probe, {},
{
    int bits = 0;

    MAKE_CALL(out->retval = func(in->host, in->port, in->timeout,
                                 &out->banner, &out->hostkey_type,
                                 &out->hostkey_fp, &bits));
    out->hostkey_bits = bits;
    out->common.errno_changed = false;
})

static te_errno
ssh_supports(const char *host, int port, const char *kind, const char *algo,
             int timeout)
{
    return ta_remote_ssh_supports(host, port, kind, algo, timeout);
}

TARPC_FUNC_STATIC(ssh_supports, {},
{
    MAKE_CALL(out->retval = func(in->host, in->port, in->kind, in->algo,
                                 in->timeout));
    out->common.errno_changed = false;
})

static te_errno
ssh_auth_methods(const char *host, int port, const char *user, int timeout,
                 char **methods, bool *none_ok)
{
    te_string m = TE_STRING_INIT;
    te_errno rc = ta_remote_ssh_auth_methods(host, port, user, timeout, &m,
                                             none_ok);

    *methods = take(&m);
    return rc;
}

TARPC_FUNC_STATIC(ssh_auth_methods, {},
{
    bool none_ok = false;

    MAKE_CALL(out->retval = func(in->host, in->port, in->user, in->timeout,
                                 &out->methods, &none_ok));
    out->none_ok = none_ok;
    out->common.errno_changed = false;
})

static te_errno
ssh_auth_password(const char *host, int port, const char *user,
                  const char *password, int timeout)
{
    return ta_remote_ssh_auth_password(host, port, user, password, timeout);
}

TARPC_FUNC_STATIC(ssh_auth_password, {},
{
    MAKE_CALL(out->retval = func(in->host, in->port, in->user, in->password,
                                 in->timeout));
    out->common.errno_changed = false;
})

static te_errno
ssh_exec(const char *host, int port, const char *user, const char *password,
         const char *command, int timeout, char **output, int *exit_status)
{
    te_string o = TE_STRING_INIT;
    te_errno rc = ta_remote_ssh_exec(host, port, user, password, command,
                                     timeout, &o, exit_status);

    *output = take(&o);
    return rc;
}

TARPC_FUNC_STATIC(ssh_exec, {},
{
    int status = -1;

    MAKE_CALL(out->retval = func(in->host, in->port, in->user, in->password,
                                 in->command, in->timeout, &out->output,
                                 &status));
    out->exit_status = status;
    out->common.errno_changed = false;
})

static te_errno
telnet_probe(const char *host, int port, int timeout, bool *open,
             char **banner)
{
    te_string b = TE_STRING_INIT;
    te_errno rc = ta_remote_telnet_probe(host, port, timeout, open, &b);

    *banner = take(&b);
    return rc;
}

TARPC_FUNC_STATIC(telnet_probe, {},
{
    bool open = false;

    MAKE_CALL(out->retval = func(in->host, in->port, in->timeout, &open,
                                 &out->banner));
    out->open = open;
    out->common.errno_changed = false;
})

static te_errno
rservice_probe(const char *host, int port, int timeout, bool *open,
               char **banner)
{
    te_string b = TE_STRING_INIT;
    te_errno rc = ta_remote_rservice_probe(host, port, timeout, open, &b);

    *banner = take(&b);
    return rc;
}

TARPC_FUNC_STATIC(rservice_probe, {},
{
    bool open = false;

    MAKE_CALL(out->retval = func(in->host, in->port, in->timeout, &open,
                                 &out->banner));
    out->open = open;
    out->common.errno_changed = false;
})
