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

# m4/bpf.m4


AC_DEFUN([AMEBA_BPF_REQUIRE_JQ],
[
    AC_CHECK_PROG([HAVE_JQ], [jq], [yes], [no])
    if test "$HAVE_JQ" != "yes"; then
        AC_MSG_ERROR([jq not found. Install it.])
    fi
])

AC_DEFUN([AMEBA_BPF_REQUIRE_FILE],
[
    if test ! -f "$1"; then
        AC_MSG_ERROR([File $1 not found or not accessible.])
    fi
])

AC_DEFUN([AMEBA_BPF_REQUIRE_VMLINUX],
[
    AMEBA_BPF_REQUIRE_FILE([$1])
])

AC_DEFUN([AMEBA_BPF_REQUIRE_AVAILABLE_EVENTS],
[
    AMEBA_BPF_REQUIRE_FILE([$1])
])

AC_DEFUN([AMEBA_BPF_CREATE_BPFTOOL_BTF_FILE],
[
    if test ! -f "$2"; then
        if bpftool -j btf dump file "$1" format raw > "$2"; then
            :
        else
            AC_MSG_ERROR([failed... bpftool -j btf dump file "$1" format raw > "$2"])
        fi
    fi
])

AC_DEFUN([AMEBA_BPF_REQUIRE_HOOK_NAME_H],
[
    AMEBA_BPF_REQUIRE_FILE([$1])
])

AC_DEFUN([AMEBA_BPF_SET_HOOK_NAMES],
[
    AMEBA_BPF_HOOK_NAMES=`grep -o '"[[^"]]*"' "$1" | tr -d '"' | tr '\n' ' '`
])

AC_DEFUN([AMEBA_BPF_VALIDATE_HOOK_NAMES],
[
    for AMEBA_BPF_HOOK_NAME in $1; do
        AC_MSG_CHECKING([for BPF hook $AMEBA_BPF_HOOK_NAME])
        AMEBA_BPF_HOOK_NAME_FUNC=`echo $AMEBA_BPF_HOOK_NAME | awk -F'/' '{print $NF}'`
        if echo $AMEBA_BPF_HOOK_NAME | grep -q "^tracepoint/"; then
            if ! grep -q "^syscalls:$AMEBA_BPF_HOOK_NAME_FUNC$" "$2"; then
                AC_MSG_ERROR([Required tracepoint $AMEBA_BPF_HOOK_NAME not found in $2])
            fi
        else
            if ! jq --exit-status \
                --arg name "$AMEBA_BPF_HOOK_NAME_FUNC" \
                '.types[[]] | select(.kind == "FUNC" and .name == $name)' \
                "$3" 2>&1 &> /dev/null; then
                AC_MSG_ERROR([Required kernel function $AMEBA_BPF_HOOK_NAME not found in $3])
            fi
        fi
        AC_MSG_RESULT([yes])
    done
])

AC_DEFUN([AMEBA_BPF_REQUIRE_HOOKS],
[
    AEMBA_BPF_TMPDIR="${TMPDIR-/tmp}/confbpftest.$$"
    if ! mkdir -p "$AEMBA_BPF_TMPDIR"; then
        AC_MSG_ERROR([could not create temporary directory: $AEMBA_BPF_TMPDIR])
    fi

    AMEBA_BPF_HOOK_NAME_H="$srcdir/src/bpf/event/hook_name.bpf.h"
    AMEBA_BPF_BPFTOOL_BTF_FILE="$AEMBA_BPF_TMPDIR/vmlinux.json"
    AMEBA_BPF_HOOK_NAMES=

    AMEBA_BPF_REQUIRE_JQ
    AMEBA_BPF_REQUIRE_AVAILABLE_EVENTS([$2])
    AMEBA_BPF_REQUIRE_VMLINUX([$1])
    AMEBA_BPF_CREATE_BPFTOOL_BTF_FILE([$1], [$AMEBA_BPF_BPFTOOL_BTF_FILE])
    AMEBA_BPF_REQUIRE_HOOK_NAME_H([$AMEBA_BPF_HOOK_NAME_H])
    AMEBA_BPF_SET_HOOK_NAMES([$AMEBA_BPF_HOOK_NAME_H])
    AMEBA_BPF_VALIDATE_HOOK_NAMES([$AMEBA_BPF_HOOK_NAMES], [$2], [$AMEBA_BPF_BPFTOOL_BTF_FILE])
])