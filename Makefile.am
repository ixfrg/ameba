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


AM_DISTCHECK_CONFIGURE_FLAGS = CC=clang --prefix=${PWD}/ameba-local-dist-check-install

SUBDIRS = src tests

dist_doc_DATA = README.md
amebaconfigdir = $(sysconfdir)/ameba
dist_amebaconfig_DATA = \
	config/ameba.conf \
	config/control.conf \
	config/pin.conf \
	config/read.conf \
	config/unpin.conf

dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version