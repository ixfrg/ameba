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

# m4/host.m4


AC_DEFUN([AMEBA_DEFINE_BPF_ARCH_CPPFLAG], [
    AC_REQUIRE([AC_CANONICAL_HOST])
    case "$host_cpu" in
    x86_64)
        AMEBA_BPF_ARCH_CPPFLAG="-D__TARGET_ARCH_x86"
        ;;
    aarch64)
        AMEBA_BPF_ARCH_CPPFLAG="-D__TARGET_ARCH_arm64"
        ;;
    *)
        AC_MSG_ERROR([Unsupported architecture: $host_cpu])
        ;;
    esac

    AC_SUBST([AMEBA_BPF_ARCH_CPPFLAG])
])