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

#include "common/vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "common/constants.h"
#include "bpf/helpers/output.bpf.h"
#include "bpf/helpers/log.bpf.h"


struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} OUTPUT_RINGBUF_MAP_NAME SEC(".maps");


long output_record_cred(struct record_cred *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_CRED, 0);
}

long output_record_namespace(struct record_namespace *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_NAMESPACE, 0);
}

long output_record_new_process(struct record_new_process *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_NEW_PROCESS, 0);
}

long output_record_accept(struct record_accept *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_ACCEPT, 0);
}

long output_record_bind(struct record_bind *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_BIND, 0);
}

long output_record_kill(struct record_kill *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_KILL, 0);
}

long output_record_send_recv(struct record_send_recv *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_SEND_RECV, 0);
}

long output_record_connect(struct record_connect *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_CONNECT, 0);
}

long output_record_audit_log_exit(struct record_audit_log_exit *ptr)
{
    if (!ptr)
        return -1;
    return bpf_ringbuf_output(&ameba_output_ringbuf, ptr, RECORD_SIZE_AUDIT_LOG_EXIT, 0);
}
