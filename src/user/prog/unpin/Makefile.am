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

AM_CPPFLAGS = \
    -I$(top_srcdir)/src \
    -I$(top_builddir)/src \
    $(CPPFLAGS_ENABLE_TASK_CTX) \
    -DAMEBA_CONFIG_DIR_PATH='"$(sysconfdir)/$(AMEBA_ETC_CONF_DIR_NAME)"'
AM_CFLAGS = -Wall

COMMON_LDADD = \
    $(top_builddir)/src/user/config/lib.a \
    $(top_builddir)/src/user/arg/lib.a \
    $(top_builddir)/src/user/record/deserializer/lib.a \
    $(top_builddir)/src/user/record/writer/lib.a \
    $(top_builddir)/src/user/record/serializer/lib.a \
    $(top_builddir)/src/user/helper/lib.a \
    $(top_builddir)/src/user/jsonify/lib.a \
    $(top_builddir)/src/common/lib.a

bin_PROGRAMS = unpin

unpin_SOURCES = \
    main.c
unpin_LDADD = $(COMMON_LDADD)