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
AM_CFLAGS = -Wall

noinst_LIBRARIES = libargs.a librecorddeserializer.a librecordwriter.a librecordserializer.a libhelpers.a libjsonify.a

libargs_a_SOURCES = args/user.c args/control.c
librecorddeserializer_a_SOURCES = record/deserializer/binary.c
librecordwriter_a_SOURCES = record/writer/file.c record/writer/net.c
librecordserializer_a_SOURCES = record/serializer/binary.c record/serializer/json.c record/serializer/serializer.c
libhelpers_a_SOURCES = helpers/log.c
libjsonify_a_SOURCES = jsonify/user.c jsonify/control.c jsonify/core.c jsonify/types.c jsonify/record.c jsonify/log_msg.c

bin_PROGRAMS = ameba
ameba_SOURCES = ameba.c
ameba_LDADD = libargs.a librecorddeserializer.a librecordwriter.a librecordserializer.a libhelpers.a libjsonify.a