/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief A host's remote access read as a security posture
 *
 * Plaintext services first (Telnet, rlogin, rsh answer at all), then
 * SSH: protocol 1 from the banner, then each weak key-exchange, cipher,
 * MAC and host-key algorithm forced one at a time to see if the server
 * still accepts it, then the authentication methods, and last - only
 * when a credential is given - whether a password logs in.
 */

#define TE_LGR_USER     "TAPI remote audit"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_cybersec.h"
#include "tapi_remote.h"
#include "tapi_remote_audit.h"

/* See description in tapi_remote_audit.h */
const tapi_remote_audit_policy tapi_remote_default_audit_policy = {
    .check_telnet = true,
    .check_rservices = true,
    .check_ssh = true,
    .ssh_port = 0,
    .ssh_user = NULL,
    .cred_user = NULL,
    .cred_password = NULL,
};

/** Broken key exchanges (SHA-1 and the 1024-bit group). */
static const char *const weak_kex[] = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "rsa1024-sha1",
    NULL,
};

/** Broken ciphers (CBC, the RC4 family, single DES, none). */
static const char *const weak_cipher[] = {
    "3des-cbc", "des-cbc", "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "arcfour", "arcfour128", "arcfour256", "none",
    NULL,
};

/** Broken MACs (MD5, truncated, SHA-1, none). */
static const char *const weak_mac[] = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "none",
    NULL,
};

/** Weak host-key algorithms (DSA, and RSA with SHA-1 signatures). */
static const char *const weak_hostkey[] = {
    "ssh-dss", "ssh-rsa",
    NULL,
};

/** First algorithm of @p list the server accepts, or @c NULL. */
static const char *
audit_first_accepted(rcf_rpc_server *rpcs, const char *host, int port,
                     const char *kind, const char *const *list)
{
    size_t i;

    for (i = 0; list[i] != NULL; i++)
    {
        if (tapi_remote_ssh_supports(rpcs, host, port, kind, list[i]))
            return list[i];
    }
    return NULL;
}

/** The SSH half of the audit. */
static void
audit_ssh(rcf_rpc_server *rpcs, const char *host,
          const tapi_remote_audit_policy *policy, tapi_cybersec_report *report)
{
    int port = policy->ssh_port != 0 ? policy->ssh_port : 22;
    const char *user = policy->ssh_user != NULL ? policy->ssh_user : "root";
    te_string banner = TE_STRING_INIT;
    te_string hostkey_type = TE_STRING_INIT;
    te_string methods = TE_STRING_INIT;
    const char *hit;
    bool none_ok = false;

    if (tapi_remote_ssh_probe(rpcs, host, port, &banner, &hostkey_type, NULL,
                              NULL) != 0)
    {
        te_string_free(&banner);
        te_string_free(&hostkey_type);
        return; /* No SSH here to assess. */
    }

    /* Protocol 1 shows in the banner: "SSH-1.5" or the dual "SSH-1.99". */
    if (strstr(te_string_value(&banner), "SSH-1.") != NULL)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "remote.ssh-protocol-1", host,
                                 "The SSH banner offers protocol version 1, "
                                 "which has no real integrity protection");
    }

    hit = audit_first_accepted(rpcs, host, port, "kex", weak_kex);
    if (hit != NULL)
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "remote.ssh-weak-kex", host,
                                 "The server accepts a broken key exchange "
                                 "(%s)", hit);

    hit = audit_first_accepted(rpcs, host, port, "cipher_cs", weak_cipher);
    if (hit != NULL)
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "remote.ssh-weak-cipher", host,
                                 "The server accepts a broken cipher (%s)",
                                 hit);

    hit = audit_first_accepted(rpcs, host, port, "mac_cs", weak_mac);
    if (hit != NULL)
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "remote.ssh-weak-mac", host,
                                 "The server accepts a broken MAC (%s)", hit);

    hit = audit_first_accepted(rpcs, host, port, "hostkey", weak_hostkey);
    if (hit != NULL)
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "remote.ssh-weak-hostkey", host,
                                 "The server offers a weak host-key "
                                 "algorithm (%s)", hit);

    /* Authentication methods, and the "none" that logs straight in. */
    if (tapi_remote_ssh_auth_methods(rpcs, host, port, user, &methods,
                                     &none_ok) == 0)
    {
        if (none_ok)
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                                     "remote.ssh-auth-none", host,
                                     "The server let a client in with no "
                                     "authentication");
        else if (strstr(te_string_value(&methods), "password") != NULL)
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                                     "remote.ssh-password-auth", host,
                                     "The server offers password "
                                     "authentication, open to guessing");
    }

    /* A supplied password that logs in. The verdict names no secret. */
    if (policy->cred_user != NULL && policy->cred_password != NULL &&
        tapi_remote_ssh_login(rpcs, host, port, policy->cred_user,
                              policy->cred_password) == 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "remote.ssh-weak-credentials", host,
                                 "A supplied password logged in over SSH");
    }

    te_string_free(&banner);
    te_string_free(&hostkey_type);
    te_string_free(&methods);
}

/* See description in tapi_remote_audit.h */
te_errno
tapi_remote_audit(rcf_rpc_server *rpcs, const char *host,
                  const tapi_remote_audit_policy *policy,
                  tapi_cybersec_report *report)
{
    unsigned int before;

    if (host == NULL || report == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);
    if (policy == NULL)
        policy = &tapi_remote_default_audit_policy;

    before = tapi_cybersec_report_count(report, TAPI_CYBERSEC_SEV_INFO);

    if (policy->check_telnet &&
        tapi_remote_telnet_open(rpcs, host, 23, NULL))
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "remote.telnet-enabled", host,
                                 "A plaintext Telnet service is answering");
    }

    if (policy->check_rservices)
    {
        if (tapi_remote_rservice_open(rpcs, host, 513, NULL))
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "remote.rlogin-enabled", host,
                                     "The legacy rlogin service (513) is "
                                     "answering");
        if (tapi_remote_rservice_open(rpcs, host, 514, NULL))
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "remote.rsh-enabled", host,
                                     "The legacy rsh/rexec service (514) is "
                                     "answering");
    }

    if (policy->check_ssh)
        audit_ssh(rpcs, host, policy, report);

    if (tapi_cybersec_report_count(report, TAPI_CYBERSEC_SEV_INFO) == before)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                 "remote.not-assessed", host,
                                 "No remote-access service answered to "
                                 "assess");
    }

    return 0;
}
