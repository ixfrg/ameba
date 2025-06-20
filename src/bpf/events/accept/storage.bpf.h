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

#include "common/vmlinux.h"

#include "common/types.h"


// int accept_storage_insert_local_fd(struct record_accept *map_val);
int accept_storage_insert_remote_fd(struct record_accept *map_val);
// int accept_storage_set_local_fd_saddrs(
//     inode_num_t net_ns_inum, short int sock_type, struct elem_sockaddr *local, struct elem_sockaddr *remote
// );
int accept_storage_set_remote_fd_saddrs(
    inode_num_t net_ns_inum, short int sock_type, struct elem_sockaddr *local, struct elem_sockaddr *remote
);
// int accept_storage_set_local_fd_props_on_sys_exit(pid_t pid, event_id_t event_id, int ret);
int accept_storage_set_remote_fd_props_on_sys_exit(pid_t pid, int ret_fd, event_id_t event_id);
// int accept_storage_delete_local_fd(void);
int accept_storage_delete_remote_fd(void);
int accept_storage_delete_both_fds(void);
// int accept_storage_output_local_fd(void);
int accept_storage_output_remote_fd(void);
