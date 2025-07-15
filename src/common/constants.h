// SPDX-License-Identifier: GPL-3.0-or-later
/*
AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
Copyright (C) 2025  Hassaan Irshad

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

/*

    A module for defining common (i.e. bpf and user) constants.

*/

// magic number => 'ameba' => 'ameb' => 0x616D6562
// 32 bits
#define AMEBA_MAGIC 0x616D6562

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define CONCAT_VAR_NAMES_INTERNAL(x, y) x##y
#define CONCAT_VAR_NAMES(x, y) CONCAT_VAR_NAMES_INTERNAL(x, y)

#define AMEBA_MAP_NAME_PREFIX __ameba_map__
#define AMEBA_MAP_NAME_PREFIX_STR TOSTRING(AMEBA_MAP_NAME_PREFIX)
#define AMEBA_MAP_NAME(name) CONCAT_VAR_NAMES(AMEBA_MAP_NAME_PREFIX, name)

#define AMEBA_PROG_NAME_PREFIX __ameba_prog__
#define AMEBA_PROG_NAME_PREFIX_STR TOSTRING(AMEBA_PROG_NAME_PREFIX)
#define AMEBA_PROG_NAME(name) CONCAT_VAR_NAMES(AMEBA_PROG_NAME_PREFIX, name)

// Name of the BPF ringbuf where all records are written to.
#define AMEBA_MAP_NAME_OUTPUT_RINGBUF AMEBA_MAP_NAME(output_ringbuf)
#define AMEBA_MAP_NAME_OUTPUT_RINGBUF_STR TOSTRING(AMEBA_MAP_NAME_OUTPUT_RINGBUF)

#define BPF_FS_DIR_PATH "/sys/fs/bpf"
#define AMEBA_BPF_FS_DIR_NAME "ameba"
#define AMEBA_BPF_FS_DIR_PATH BPF_FS_DIR_PATH "/" AMEBA_BPF_FS_DIR_NAME

// Sockaddr max size in kernel.
#define SOCKADDR_MAX_SIZE 128
// Task command max size in kernel.
#define COMM_MAX_SIZE 16

// The error EINPROGRESS in connect system call.
#define ERROR_EINPROGRESS -150

// The flag used in clone system call.
#define SIGCHLD 17
// The flag used in clone system call.
#define CLONE_VFORK 0x00004000
// The flag used in clone system call.
#define CLONE_VM 0x00000100

// The constants for identifying socket families in kernel.
#define PF_INET 2
#define AF_INET PF_INET
#define PF_INET6 10
#define AF_INET6 PF_INET6
