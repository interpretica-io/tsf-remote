# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): engine-side TAPI for remote
# access (SSH, Telnet, r-services) driven on agents. Built as a shared
# library on the engine platform. It needs the remote_* RPCs in rpcxdr,
# so add ../ta_remote/remote_rpc.x.m4 to the rpcxdr definitions of the
# engine platform.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = not get_option('engine')
install_lib = install_dev

headers += files(
    'tapi_remote.h',
    'tapi_remote_rpc.h',
    'tapi_remote_audit.h',
)

sources += files(
    'tapi_remote.c',
    'tapi_remote_rpc.c',
    'tapi_remote_audit.c',
)

te_libs += [
    'tapi',
    'tapi_rpc',
    'rcfrpc',
    'confapi',
    'rcfapi',
    'rpcxdr',
    'tapi_cybersec',
    'logger_core',
    'tools',
]
