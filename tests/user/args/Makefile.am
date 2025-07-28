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

## Process this file with automake to produce Makefile.in


AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_builddir)/src $(CPPFLAGS_ENABLE_TASK_CTX)
AM_CXXFLAGS = -Wall

noinst_LIBRARIES = libtesthelpers.a
libtesthelpers_a_SOURCES = \
    test_helper.cpp

COMMON_LDADD = \
    $(top_builddir)/src/user/arg/lib.a \
    $(top_builddir)/src/user/jsonify/lib.a \
    $(top_builddir)/src/common/lib.a \
    libtesthelpers.a \
    -lCppUTest \
    -lCppUTestExt

check_PROGRAMS = ameba control parse_state pin read unpin common_struct
TESTS = $(check_PROGRAMS)

ameba_SOURCES = ameba.cpp
ameba_LDADD = $(COMMON_LDADD)

control_SOURCES = control.cpp
control_LDADD = $(COMMON_LDADD)

parse_state_SOURCES = parse_state.cpp
parse_state_LDADD = $(COMMON_LDADD)

pin_SOURCES = pin.cpp
pin_LDADD = $(COMMON_LDADD)

read_SOURCES = read.cpp
read_LDADD = $(COMMON_LDADD)

unpin_SOURCES = unpin.cpp
unpin_LDADD = $(COMMON_LDADD)

common_struct_SOURCES = common.cpp
common_struct_LDADD = $(COMMON_LDADD)
