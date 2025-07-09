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

# m4/cpp.m4


AC_DEFUN([AMEBA_CPP_REQUIRE_CPPUTEST],
[
    AC_LANG_PUSH([C++])
    AC_CHECK_HEADERS([CppUTest/CommandLineTestRunner.h], [],
        [AC_MSG_ERROR([CppUTest headers not found. Install CppUTest.])]
    )

    AMEBA_CPP_REQUIRE_CPPUTEST_LIBS="${LIBS}"
    LIBS="${LIBS} -lCppUTest -lCppUTestExt"
    AC_LINK_IFELSE(
        [
            AC_LANG_PROGRAM(
                [[#include <CppUTest/CommandLineTestRunner.h>]],
                [[int argc = 1; char* argv[] = {(char*)"test"}; CommandLineTestRunner::RunAllTests(argc, argv);]]
            )
        ],
        [cpputest_link=yes],
        [cpputest_link=no]
    )
    LIBS="${AMEBA_CPP_REQUIRE_CPPUTEST_LIBS}"

    if test "x$cpputest_link" = "xyes"; then
        AC_DEFINE([HAVE_CPPUTEST], [1], [Define if CppUTest is available])
    else
        AC_MSG_ERROR([CppUTest library not found])
    fi

    AC_LANG_POP([C++])
])
