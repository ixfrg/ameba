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

# m4/args.m4


AC_DEFUN([AMEBA_ARG_ENABLE_TASK_CTX],
[
  AC_ARG_ENABLE([task-ctx],
    [AS_HELP_STRING([--enable-task-ctx], [Enable task context inclusion flag])],
    [enable_task_ctx=yes],
    [enable_task_ctx=no]
  )

  if test "x$enable_task_ctx" = "xyes"; then
    CPPFLAGS_ENABLE_TASK_CTX="-DINCLUDE_TASK_CTX_ID"
  else
    CPPFLAGS_ENABLE_TASK_CTX=""
  fi

  AC_SUBST([CPPFLAGS_ENABLE_TASK_CTX])
])

AC_DEFUN([AMEBA_ARG_REQUIRE_BPF_ARGS],
[
    AC_ARG_WITH([path-btf-vmlinux],
        [AS_HELP_STRING([--with-path-btf-vmlinux=PATH], [Set path to readable /sys/kernel/btf/vmlinux])],
        [AMEBA_ARG_BPF_VMLINUX="$withval"],
        [AMEBA_ARG_BPF_VMLINUX="/sys/kernel/btf/vmlinux"]
    )
    AC_SUBST([AMEBA_SYS_KERNEL_BTF_VMLINUX], [$AMEBA_ARG_BPF_VMLINUX])
    AC_ARG_WITH([path-tracing-available-events],
        [AS_HELP_STRING([--with-path-tracing-available-events=PATH], [Set path to readable /sys/kernel/tracing/available_events])],
        [AMEBA_ARG_BPF_AVAILABLE_EVENTS="$withval"],
        [AMEBA_ARG_BPF_AVAILABLE_EVENTS="/sys/kernel/tracing/available_events"]
    )
])