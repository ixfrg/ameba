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


include $(top_srcdir)/tests/common.mk

AUTOMAKE_OPTIONS = subdir-objects

noinst_HEADERS = test_helper.hpp

noinst_LIBRARIES = libtesthelpers.a
libtesthelpers_a_SOURCES = \
    test_helper.cpp

COMMON_TESTS_ARGS_LDADD = $(COMMON_TESTS_LDADD) libtesthelpers.a

check_PROGRAMS = ameba control parse_state pin read unpin common_struct
TESTS = $(check_PROGRAMS)

ameba_SOURCES = ameba.cpp
ameba_LDADD = $(COMMON_TESTS_ARGS_LDADD)

control_SOURCES = control.cpp
control_LDADD = $(COMMON_TESTS_ARGS_LDADD)

parse_state_SOURCES = parse_state.cpp
parse_state_LDADD = $(COMMON_TESTS_ARGS_LDADD)

pin_SOURCES = pin.cpp
pin_LDADD = $(COMMON_TESTS_ARGS_LDADD)

read_SOURCES = read.cpp
read_LDADD = $(COMMON_TESTS_ARGS_LDADD)

unpin_SOURCES = unpin.cpp
unpin_LDADD = $(COMMON_TESTS_ARGS_LDADD)

common_struct_SOURCES = common.cpp
common_struct_LDADD = $(COMMON_TESTS_ARGS_LDADD)
