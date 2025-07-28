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
    Constants used within the kernel, and needed by userpsace and bpf programs.
*/

#define AMEBA_SOCKADDR_MAX_SIZE 128
#define AMEBA_COMM_MAX_SIZE 16

// The error EINPROGRESS in connect system call.
#define AMEBA_EINPROGRESS -150

// The flag used in clone system call.
#define AMEBA_SIGCHLD 17
// The flag used in clone system call.
#define AMEBA_CLONE_VFORK 0x00004000
// The flag used in clone system call.
#define AMEBA_CLONE_VM 0x00000100

// The constants for identifying socket families in kernel.
#define AMEBA_PF_INET 2
#define AMEBA_AF_INET AMEBA_PF_INET
#define AMEBA_PF_INET6 10
#define AMEBA_AF_INET6 AMEBA_PF_INET6