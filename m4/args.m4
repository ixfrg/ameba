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


AC_DEFUN([CUSTOM_ARG_ENABLE_TASK_CTX],
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
