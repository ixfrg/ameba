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

// Name of the BPF ringbuf where all records are written to.
#define OUTPUT_RINGBUF_MAP_NAME ameba_output_ringbuf
#define OUTPUT_RINGBUF_MAP_NAME_STR TOSTRING(OUTPUT_RINGBUF_MAP_NAME)

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
