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


#define BPF_EVENT_HOOK_NAME_FEXIT_DO_ACCEPT "fexit/do_accept"
#define BPF_EVENT_HOOK_NAME_TP_SYS_ENTER_ACCEPT "tracepoint/syscalls/sys_enter_accept"
#define BPF_EVENT_HOOK_NAME_TP_SYS_ENTER_ACCEPT4 "tracepoint/syscalls/sys_enter_accept4"
#define BPF_EVENT_HOOK_NAME_TP_SYS_EXIT_ACCEPT "tracepoint/syscalls/sys_exit_accept"
#define BPF_EVENT_HOOK_NAME_TP_SYS_EXIT_ACCEPT4 "tracepoint/syscalls/sys_exit_accept4"

#define BPF_EVENT_HOOK_NAME_FEXIT_AUDIT_LOG_EXIT "fexit/audit_log_exit"

#define BPF_EVENT_HOOK_NAME_FEXIT_UNIX_BIND "fexit/unix_bind"
#define BPF_EVENT_HOOK_NAME_FEXIT_INET_BIND "fexit/inet_bind"
#define BPF_EVENT_HOOK_NAME_FEXIT_INET6_BIND "fexit/inet6_bind"
#define BPF_EVENT_HOOK_NAME_FEXIT___SYS_BIND "fexit/__sys_bind"

#define BPF_EVENT_HOOK_NAME_FENTRY___SYS_CONNECT "fentry/__sys_connect"
#define BPF_EVENT_HOOK_NAME_FEXIT___SYS_CONNECT "fexit/__sys_connect"
#define BPF_EVENT_HOOK_NAME_FEXIT___SYS_CONNECT_FILE "fexit/__sys_connect_file"

#define BPF_EVENT_HOOK_NAME_TP_SYS_ENTER_KILL "tracepoint/syscalls/sys_enter_kill"
#define BPF_EVENT_HOOK_NAME_TP_SYS_EXIT_KILL "tracepoint/syscalls/sys_exit_kill"

#define BPF_EVENT_HOOK_NAME_FEXIT_COPY_PROCESS "fexit/copy_process"
#define BPF_EVENT_HOOK_NAME_FEXIT_KSYS_UNSHARE "fexit/ksys_unshare"
#define BPF_EVENT_HOOK_NAME_TP_SYS_EXIT_SETNS "tracepoint/syscalls/sys_exit_setns"

#define BPF_EVENT_HOOK_NAME_FENTRY___SYS_SENDTO "fentry/__sys_sendto"
#define BPF_EVENT_HOOK_NAME_FEXIT___SYS_SENDTO "fexit/__sys_sendto"
#define BPF_EVENT_HOOK_NAME_FENTRY___SYS_SENDMSG "fentry/__sys_sendmsg"
#define BPF_EVENT_HOOK_NAME_FEXIT___SYS_SENDMSG "fexit/__sys_sendmsg"
#define BPF_EVENT_HOOK_NAME_FENTRY___SYS_RECVFROM "fentry/__sys_recvfrom"
#define BPF_EVENT_HOOK_NAME_FEXIT___SYS_RECVFROM "fexit/__sys_recvfrom"
#define BPF_EVENT_HOOK_NAME_FENTRY___SYS_RECVMSG "fentry/__sys_recvmsg"
#define BPF_EVENT_HOOK_NAME_FEXIT___SYS_RECVMSG "fexit/__sys_recvmsg"
#define BPF_EVENT_HOOK_NAME_FEXIT_SOCK_SENDMSG "fexit/sock_sendmsg"
#define BPF_EVENT_HOOK_NAME_FEXIT_SOCK_RECVMSG "fexit/sock_recvmsg"