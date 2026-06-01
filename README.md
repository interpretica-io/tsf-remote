# tsf-remote

Remote-access probing for the OKTET Labs Test Environment (TE),
packaged as an external TE repository (consumed with the `TE_EXT_REPO`
builder directive). It drives SSH, Telnet and the legacy r-services
(rlogin, rsh) from a Test Agent over low-level C libraries — no Python
— for both quality verification and security assessment.

Three libraries:

- `ta_remote` — agent side. An SSH client over **libssh**, and Telnet
  and the r-services over raw sockets. The SSH side is built to be
  driven under many configurations: force one algorithm of a class per
  connection and see whether the key exchange still completes, the way
  `tsf-smb` forces a dialect. The agent and its RPC server both link it.
- `rpcs_remote` — the `ssh_*`, `telnet_*` and `rservice_*` RPCs for the
  agent's RPC server. The traffic originates on the agent, where the
  device under test is reachable, not on the engine.
- `tapi_remote` — engine side. `tapi_remote.h` gives a test the probe,
  the per-algorithm support check, the authentication-method list, a
  password login, a command over a session, and the Telnet and
  r-service probes; `tapi_remote_audit.h` reads a host as a security
  posture through tsf-cybersec.

TE has no SSH, Telnet or r-service client of its own.

## Authorized use only

The security side connects to a real host and, when you give it a
credential, tries to log in. It is for an **authorized** assessment — a
pilot, a CTF, a host you own or are engaged to test. Point it only at a
host you are permitted to assess.

## Agent host requirements

- **libssh** 0.9+ with its development headers (Debian: `apt install
  libssh-dev`; built and checked against 0.11). Telnet and the
  r-services need only the C library's sockets.

## Usage

Declare the repository in an external libraries catalog and pass it to
`dispatcher.sh --external=<catalog.yml>`:

```yaml
repositories:
  - name: tsf_remote
    url: https://github.com/interpretica-io/tsf-remote.git
    ref: v1.0.0
    libs:
      - ta_remote
      - rpcs_remote
      - tapi_remote
```

In `builder.conf`, bind `tapi_remote` to the engine, the agent
libraries to the agent platform, add the RPC definitions to `rpcxdr` on
both, and put `ta_remote` with `rpcs_remote` into the RPC server:

```
TE_EXT_REPO_USE([tsf_remote], [], [tapi_remote])
TE_LIB_PARMS([rpcxdr], [], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_remote/remote_rpc.x.m4])

TE_EXT_REPO_USE([tsf_remote], [<agent platform>], [ta_remote rpcs_remote])
TE_LIB_PARMS([rpcxdr], [<agent platform>], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_remote/remote_rpc.x.m4])
TE_TA_TYPE([<ta type>], [<agent platform>], [unix], [--with-rcf-rpc],
           [], [], [], [comm_net_agent rcfpch ta_remote])
TE_TA_APP([ta_rpcprovider], [<agent platform>], [<ta type>],
          [ta_rpcprovider], [], [],
          [... rpcs_job rpcs_remote ta_remote rpcserver agentlib rpcxdrta ...],
          [\${EXT_SOURCES}/build.sh], [ta_rpcs], [])
```

`rpcs_remote` must come before `rpcxdrta` in the application's library
list: `tarpc.c` in `rpcxdrta` has a weak stub for every RPC and the
linker keeps the first definition it meets, so an `rpcs_*` library
listed after it never gets linked in and the RPCs fail with
`RPC-ERPCNOTSUPP`.

The RPC program number is **24** (`program remote … = 24`). It must be
unique across every `.x.m4` in the build; the sibling modules use 20
(android), 21 (apple), 22 (appium) and 23 (upnp).

Add `tapi_remote` to the `te_libs` of the suite.

## The API

SSH, over libssh:

- **`tapi_remote_ssh_probe`** connects with the defaults and reads the
  server out: its identification banner, host-key type and SHA-256
  fingerprint.
- **`tapi_remote_ssh_supports`** offers one algorithm alone for its
  class — `kex`, `cipher_cs`, `cipher_sc`, `mac_cs`, `mac_sc` or
  `hostkey` — and returns whether the key exchange still completes. This
  is the "under many sauces" primitive: it maps exactly what a server
  will and will not negotiate.
- **`tapi_remote_ssh_auth_methods`** lists the methods offered a user
  and tells whether `none` logs straight in.
- **`tapi_remote_ssh_login`** tries a password; **`tapi_remote_ssh_exec`**
  runs a command over a password session and returns its output and
  exit status.

Telnet and the r-services, over raw sockets:

- **`tapi_remote_telnet_open`** reaches port 23, strips the IAC option
  bytes and returns the banner and whether it answered.
- **`tapi_remote_rservice_open`** reaches rlogin (513) or rsh/rexec
  (514) and reports whether the port answers.

The same primitives serve both jobs. **Quality**: does the server come
up, present the expected host key, negotiate the algorithms it should,
accept a login, run a command. **Security**: what it exposes.

## What the posture is worth

`tapi_remote_audit()` reads a host through tsf-cybersec.

| Finding | Severity | Read from |
|---|---|---|
| `remote.telnet-enabled` | high | a Telnet service answers |
| `remote.rlogin-enabled` | high | rlogin (513) answers |
| `remote.rsh-enabled` | high | rsh/rexec (514) answers |
| `remote.ssh-protocol-1` | critical | the SSH banner offers protocol 1 |
| `remote.ssh-weak-kex` | high | a broken key exchange is accepted |
| `remote.ssh-weak-cipher` | high | a broken cipher is accepted |
| `remote.ssh-weak-mac` | medium | a broken MAC is accepted |
| `remote.ssh-weak-hostkey` | medium | a weak host-key algorithm is offered |
| `remote.ssh-auth-none` | critical | the server let a client in with no auth |
| `remote.ssh-password-auth` | low | password authentication is offered |
| `remote.ssh-weak-credentials` | critical | a supplied password logged in |
| `remote.not-assessed` | info | nothing answered to assess |

The weak-algorithm findings come from forcing each name on a curated
list (`weak_kex`, `weak_cipher`, `weak_mac`, `weak_hostkey` in
`tapi_remote_audit.c`) and seeing which the server still accepts — so a
clean result means the server refused them, the hardened-server control
built in. The credential check runs only when the policy gives a user
and password, and its finding names no secret.

## What was verified, and what was not

**The SSH client — compiled against libssh.** `ta_remote.c` compiles
clean under `-Wall -Wextra -Werror` against libssh 0.11 headers,
including the 0.11 rename of the channel exit-status call (guarded by
`LIBSSH_VERSION_INT`). It has **not** yet been run against a live SSH
server through a Test Agent.

**The raw Telnet and r-service probes — written, not yet run.** The TCP
connect-with-timeout, the Telnet IAC stripping and the r-service reach
are plain sockets and were written to the protocols; they are to be
exercised on a live target.

**The RPC layer — by construction.** `remote_rpc.x.m4`, `rpcs_remote`
and `tapi_remote_rpc` follow the tsf-appium/tsf-upnp template exactly;
they compile only in the full TE build, which generates `tarpc.h` from
the `.x.m4`. Nothing here has yet run through a Test Agent.

## Scope

- **The audit connects and may log in.** It opens SSH, Telnet and
  r-service connections and, given a credential, attempts a login. Run
  the security side only where you are authorized.
- **`ssh_supports` opens one connection per algorithm.** A full weak-set
  sweep is a few dozen short connects; that is the cost of mapping a
  server precisely.
- **No host-key verification.** The SSH probing deliberately does not
  check the server against a known-hosts file — it is meant to reach
  and characterize unknown servers, which is a control-point role, not a
  client trusting a server.
- **RDP and VNC are out of scope** for now; this module is the
  shell/login family (SSH, Telnet, rlogin, rsh). They would fit as a
  later addition.
