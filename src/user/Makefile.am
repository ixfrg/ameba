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


SUBDIRS = args helpers jsonify

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_builddir)/src $(CPPFLAGS_ENABLE_TASK_CTX)
AM_CFLAGS = -Wall

noinst_LIBRARIES = \
    record/deserializer/lib.a \
    record/writer/lib.a \
    record/serializer/lib.a

record_deserializer_lib_a_SOURCES = \
    record/deserializer/deserializer.h \
    record/deserializer/binary.c
record_writer_lib_a_SOURCES = \
    record/writer/writer.h \
    record/writer/file.c record/writer/net.c
record_serializer_lib_a_SOURCES = \
    record/serializer/serializer.h \
    record/serializer/binary.c record/serializer/json.c record/serializer/serializer.c

COMMON_SOURCES = \
    types.h \
    error.h
COMMON_LDADD = \
    $(top_builddir)/src/user/args/lib.a \
    $(top_builddir)/src/common/lib.a \
    record/deserializer/lib.a \
    record/writer/lib.a \
    record/serializer/lib.a \
    $(top_builddir)/src/user/helpers/lib.a \
    $(top_builddir)/src/user/jsonify/lib.a


bin_PROGRAMS = ameba loader

ameba_SOURCES = \
    $(COMMON_SOURCES) \
    ameba.c
ameba_LDADD = $(COMMON_LDADD)

loader_SOURCES = \
    $(COMMON_SOURCES) \
    loader.c
loader_LDADD = $(COMMON_LDADD)
