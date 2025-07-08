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

# m4/version.m4


AC_DEFUN([AMEBA_DEFINE_VERSION_PART],
[
    ameba_define_version_part_awk_res=`echo "$1" | awk -F'-' '{print [$]1}' | awk -F'.' '{print [$]$3}'`
    AS_IF([echo "$ameba_define_version_part_awk_res" | grep -Eq '^[[0-9]]+$'],
        [AC_DEFINE_UNQUOTED([$2], [$ameba_define_version_part_awk_res], [Package $4 number in version])],
        [AC_MSG_ERROR([Failed to extract $4 number from version: "$1"])])
])


AC_DEFUN([AMEBA_DEFINE_VERSION_MAJOR],
[
    AMEBA_DEFINE_VERSION_PART([$1], [$2], [1], [major])
])

AC_DEFUN([AMEBA_DEFINE_VERSION_MINOR],
[
    AMEBA_DEFINE_VERSION_PART([$1], [$2], [2], [minor])
])

AC_DEFUN([AMEBA_DEFINE_VERSION_PATCH],
[
    AMEBA_DEFINE_VERSION_PART([$1], [$2], [3], [patch])
])