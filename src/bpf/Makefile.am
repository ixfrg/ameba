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
AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_builddir)/src $(CPPFLAGS_ENABLE_TASK_CTX) $(AMEBA_BPF_ARCH_CPPFLAG)
AM_CFLAGS = -O2 -Wall -target bpf -mcpu=v4

bpf_combined_obj = $(top_builddir)/src/combined.bpf.o
bpf_skel_name = ameba
bpf_skel_header = $(top_builddir)/src/$(bpf_skel_name).skel.h

noinst_LIBRARIES = libbpfobjs.a

libbpfobjs_a_SOURCES = \
    helpers/event.bpf.h helpers/copy.bpf.h helpers/map.bpf.h helpers/log.bpf.h helpers/output.bpf.h helpers/event_id.bpf.h helpers/datatype.bpf.h \
    helpers/event.bpf.c helpers/copy.bpf.c helpers/map.bpf.c helpers/log.bpf.c helpers/output.bpf.c helpers/event_id.bpf.c helpers/datatype.bpf.c \
    events/process_namespace/hook.bpf.c \
    events/kill/storage.bpf.h \
    events/kill/storage/task.bpf.c events/kill/hook.bpf.c \
    events/accept/storage.bpf.h \
    events/accept/storage/task.bpf.c events/accept/hook.bpf.c \
    events/audit_log_exit/hook.bpf.c \
    events/bind/storage.bpf.h \
    events/bind/storage/task.bpf.c events/bind/hook.bpf.c \
    events/send_recv/storage.bpf.h \
    events/send_recv/storage/task.bpf.c events/send_recv/hook.bpf.c \
    events/connect/storage.bpf.h \
    events/connect/storage/task.bpf.c events/connect/hook.bpf.c \
    license.bpf.c

$(bpf_combined_obj): $(libbpfobjs_a_OBJECTS)
	@BPFTOOL_EXE_FILE@ gen object $@ $(libbpfobjs_a_OBJECTS)

$(bpf_skel_header): $(bpf_combined_obj)
	@BPFTOOL_EXE_FILE@ gen skeleton $< name $(bpf_skel_name) > $@

bpf_objs: $(bpf_skel_header)

all-local: bpf_objs

CLEANFILES = $(bpf_combined_obj) $(bpf_skel_header)