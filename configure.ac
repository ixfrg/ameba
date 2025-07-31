# SPDX-License-Identifier: GPL-3.0-or-later
# AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
# Copyright (C) 2025 Hassaan Irshad
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Default version on Ubuntu 24.04
AC_PREREQ([2.71])

# Get & set version
m4_define([ameba_VERSION], m4_esyscmd([build-aux/git-version-gen .tarball-version]))
AC_INIT([ameba], [ameba_VERSION], [hassaanirshad88@gmail.com])
# Set major,minor,patch
AMEBA_DEFINE_VERSION_MAJOR([ameba_VERSION],[PACKAGE_VERSION_MAJOR])
AMEBA_DEFINE_VERSION_MINOR([ameba_VERSION],[PACKAGE_VERSION_MINOR])
AMEBA_DEFINE_VERSION_PATCH([ameba_VERSION],[PACKAGE_VERSION_PATCH])

AMEBA_ETC_CONF_DIR_NAME="ameba"
AC_SUBST([AMEBA_ETC_CONF_DIR_NAME])

# Aux script dir
AC_CONFIG_AUX_DIR([build-aux])

# All warnings are error and gnu standard not strict
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_COPYRIGHT([AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
Copyright (C) 2025  Hassaan Irshad.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.])

# Custom macros
AC_CONFIG_MACRO_DIR([m4])

# Arguments
AMEBA_ARG_ENABLE_TASK_CTX

# App entrypoint
AC_CONFIG_SRCDIR([src/user/prog/ameba/main.c])

# Path of file containing all the configurable constants
AC_CONFIG_HEADERS([src/common/config.h])

# Add config.h guard
AH_TOP([#pragma once])

# Initialize host identification vars.
AC_CANONICAL_HOST

AMEBA_DEFINE_BPF_ARCH_CPPFLAG

# Progs used as helpers
AC_PROG_GREP
AC_PROG_EGREP

# BPF
AMEBA_ARG_REQUIRE_BPF_ARGS
AMEBA_BPF_REQUIRE_HOOKS([$AMEBA_ARG_BPF_VMLINUX], [$AMEBA_ARG_BPF_AVAILABLE_EVENTS])

# Static archive creator and indexer
AM_PROG_AR
AC_PROG_RANLIB

# Checks for clang compiler and set it.
AC_PROG_CC([clang])
# Forcing clang set because it keeps defaulting to gcc.
if test "$CC" != "clang"; then
  AC_MSG_ERROR([Clang compiler is required but not found or not functional. Force set using configure CC=clang.])
fi

AC_PROG_CXX
AMEBA_CPP_REQUIRE_CPPUTEST

# Check for bpftool
AC_PATH_PROG([BPFTOOL], [bpftool], [no])
test "$BPFTOOL" != "no" || AC_MSG_ERROR([bpftool not found in PATH. Please install it.])
AC_SUBST([BPFTOOL_EXE_FILE], [$BPFTOOL])

# Set install related vars.
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([bpf], [bpf_object__open])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

AC_CHECK_DECLS([__NR_fork], [], [], [[#include <asm/unistd.h>]])
AC_CHECK_DECLS([__NR_vfork], [], [], [[#include <asm/unistd.h>]])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime memset socket strdup strstr strtol])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/common/Makefile
    src/bpf/Makefile
    src/user/Makefile
    src/user/api/Makefile
    src/user/api/request/Makefile
    src/user/api/request/get_control/Makefile
    src/user/api/response/Makefile
    src/user/api/response/error/Makefile
    src/user/api/response/get_control/Makefile
    src/user/arg/Makefile
    src/user/config/Makefile
    src/user/helper/Makefile
    src/user/include/Makefile
    src/user/jsonify/Makefile
    src/user/prog/Makefile
    src/user/prog/ameba/Makefile
    src/user/prog/control/Makefile
    src/user/prog/pin/Makefile
    src/user/prog/read/Makefile
    src/user/prog/unpin/Makefile
    src/user/record/Makefile
    src/user/record/deserializer/Makefile
    src/user/record/serializer/Makefile
    src/user/record/writer/Makefile
    src/util/Makefile
    tests/Makefile
    tests/user/arg/Makefile
])
AC_OUTPUT
