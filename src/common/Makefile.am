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


vmlinux_h = $(top_builddir)/src/common/vmlinux.h

$(vmlinux_h):
	@BPFTOOL_EXE_FILE@ btf dump file @AMEBA_SYS_KERNEL_BTF_VMLINUX@ format c > $@

CLEANFILES = $(vmlinux_h)

all-local: $(vmlinux_h)