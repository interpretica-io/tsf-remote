/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a host's remote access is worth as a security posture
 *
 * @defgroup tapi_remote_audit Remote-access security posture
 * @ingroup tapi_remote
 * @{
 *
 * A host's remote access read as a security posture and reported
 * through tsf-cybersec: a plaintext Telnet or r-service answering at
 * all; an SSH that still speaks protocol 1, or accepts a broken key
 * exchange, cipher, MAC or host key; an SSH that lets a client in with
 * no authentication, offers password authentication, or takes a
 * guessable password.
 *
 * | Finding | Severity | Read from |
 * |---|---|---|
 * | @c remote.telnet-enabled | high | a Telnet service answers |
 * | @c remote.rlogin-enabled | high | rlogin (513) answers |
 * | @c remote.rsh-enabled | high | rsh/rexec (514) answers |
 * | @c remote.ssh-protocol-1 | critical | the SSH banner offers protocol 1 |
 * | @c remote.ssh-weak-kex | high | a broken key exchange is accepted |
 * | @c remote.ssh-weak-cipher | high | a broken cipher is accepted |
 * | @c remote.ssh-weak-mac | medium | a broken MAC is accepted |
 * | @c remote.ssh-weak-hostkey | medium | a weak host-key algorithm is offered |
 * | @c remote.ssh-auth-none | critical | the server let a client in with no auth |
 * | @c remote.ssh-password-auth | low | password authentication is offered |
 * | @c remote.ssh-weak-credentials | critical | a supplied password logged in |
 * | @c remote.not-assessed | info | nothing answered to assess |
 *
 * This connects to a real host and, when a credential is given, tries
 * to log in; use it only in an authorized assessment.
 */

#ifndef __TAPI_REMOTE_AUDIT_H__
#define __TAPI_REMOTE_AUDIT_H__

#include "te_errno.h"
#include "rcf_rpc.h"

#include "tapi_cybersec.h"
#include "tapi_remote.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What a host's remote access is expected to be. */
typedef struct tapi_remote_audit_policy {
    /** Probe Telnet (port 23). */
    bool check_telnet;
    /** Probe the r-services (ports 513 and 514). */
    bool check_rservices;
    /** Probe SSH: protocol, algorithms and authentication. */
    bool check_ssh;
    /** SSH port, or @c 0 for 22. */
    int ssh_port;
    /** User for the auth-method probe, or @c NULL for @c "root". */
    const char *ssh_user;
    /**
     * A user to try a password for (the weak-credential check), or
     * @c NULL to skip it.
     */
    const char *cred_user;
    /** The password to try for @a cred_user. */
    const char *cred_password;
} tapi_remote_audit_policy;

/**
 * The default: Telnet, the r-services and SSH all probed; SSH on 22 as
 * @c root; no credential tried.
 */
extern const tapi_remote_audit_policy tapi_remote_default_audit_policy;

/**
 * Read a host's remote-access posture into @p report.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  host     Target host.
 * @param[in]  policy   What is expected, or @c NULL for the default.
 * @param[out] report   Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 */
extern te_errno tapi_remote_audit(rcf_rpc_server *rpcs, const char *host,
                                  const tapi_remote_audit_policy *policy,
                                  tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_REMOTE_AUDIT_H__ */

/**@} <!-- END tapi_remote_audit --> */
