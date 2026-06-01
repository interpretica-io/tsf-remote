# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): agent-side remote-access
# client - SSH over libssh, Telnet and the r-services over raw sockets.
# The agent and its RPC server both link it.

headers += files(
    'ta_remote.h',
)

sources += files(
    'ta_remote.c',
)

te_libs += [
    'logger_core',
    'tools',
]

deps += [
    dependency('libssh'),
    dependency('threads'),
]
