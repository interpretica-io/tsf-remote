/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief RPC for remote-access probing (SSH, Telnet, r-services)
 *
 * The RPCs of rpcs_remote: an SSH client over libssh, and Telnet and
 * the legacy r-services (rlogin/rsh) over raw sockets. Add this file
 * to the rpcxdr definitions of the engine and the agent platforms:
 *
 *   TE_LIB_PARMS([rpcxdr], [<platform>], [],
 *                [--with-rpcdefs=tarpc_job.x.m4,../ta_remote/remote_rpc.x.m4])
 *
 * Every call names its target host and port, so nothing persists
 * between RPCs. Results that are lists come back as text, the same
 * shape tsf-appium and tsf-upnp use.
 */

/* ssh_probe(): connect with defaults and report what the server is. */
struct tarpc_ssh_probe_in {
    struct tarpc_in_arg common;

    string host<>;
    tarpc_int port;
    tarpc_int timeout;
};

struct tarpc_ssh_probe_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
    string banner<>;            /* the SSH identification string */
    string hostkey_type<>;      /* ssh-ed25519, ssh-rsa, ecdsa-... */
    string hostkey_fp<>;        /* SHA-256 fingerprint, base64 */
    tarpc_int hostkey_bits;
};

/*
 * ssh_supports(): force one algorithm of a class and see whether the
 * key exchange still completes - i.e. whether the server supports it.
 * kind is "kex", "cipher_cs", "cipher_sc", "mac_cs", "mac_sc" or
 * "hostkey". retval 0 means the server accepted it.
 */
struct tarpc_ssh_supports_in {
    struct tarpc_in_arg common;

    string host<>;
    tarpc_int port;
    string kind<>;
    string algo<>;
    tarpc_int timeout;
};

struct tarpc_ssh_supports_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
};

/* ssh_auth_methods(): the methods the server offers for a user. */
struct tarpc_ssh_auth_methods_in {
    struct tarpc_in_arg common;

    string host<>;
    tarpc_int port;
    string user<>;
    tarpc_int timeout;
};

struct tarpc_ssh_auth_methods_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
    string methods<>;           /* e.g. "password,publickey" */
    tarpc_bool none_ok;         /* "none" authentication logged in */
};

/* ssh_auth_password(): try one password; retval 0 means it logged in. */
struct tarpc_ssh_auth_password_in {
    struct tarpc_in_arg common;

    string host<>;
    tarpc_int port;
    string user<>;
    string password<>;
    tarpc_int timeout;
};

struct tarpc_ssh_auth_password_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
};

/* ssh_exec(): run one command in a password session (functional check). */
struct tarpc_ssh_exec_in {
    struct tarpc_in_arg common;

    string host<>;
    tarpc_int port;
    string user<>;
    string password<>;
    string command<>;
    tarpc_int timeout;
};

struct tarpc_ssh_exec_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
    string output<>;
    tarpc_int exit_status;
};

/* telnet_probe(): connect, read the banner, tell plaintext Telnet is up. */
struct tarpc_telnet_probe_in {
    struct tarpc_in_arg common;

    string host<>;
    tarpc_int port;
    tarpc_int timeout;
};

struct tarpc_telnet_probe_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
    tarpc_bool open;
    string banner<>;
};

/*
 * rservice_probe(): the legacy r-services. port 513 is rlogin, 514 is
 * rsh/rexec; this reaches the port and reports whether it answers.
 */
struct tarpc_rservice_probe_in {
    struct tarpc_in_arg common;

    string host<>;
    tarpc_int port;
    tarpc_int timeout;
};

struct tarpc_rservice_probe_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
    tarpc_bool open;
    string banner<>;
};

program remote
{
    version ver0
    {
        RPC_DEF(ssh_probe)
        RPC_DEF(ssh_supports)
        RPC_DEF(ssh_auth_methods)
        RPC_DEF(ssh_auth_password)
        RPC_DEF(ssh_exec)
        RPC_DEF(telnet_probe)
        RPC_DEF(rservice_probe)
    } = 1;
} = 24;
