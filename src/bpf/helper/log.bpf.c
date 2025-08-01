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

#include "bpf/helper/log.bpf.h"



int log_trace_mode(char *key, control_trace_mode_t t)
{
    char *p;
    switch (t)
    {
        case IGNORE:
            p = "ignore";
            break;
        case CAPTURE:
            p = "capture";
            break;
        default:
            p = "unknown";
            break;
    }
    LOG_WARN("%s: %s", key, p);
    return 0;
}

int log_control(struct control *ctrl) {
    if (!ctrl) {
        LOG_WARN("control is NULL");
        return 0;
    }

    LOG_WARN("=== BEGIN Control Configuration ===");
    log_trace_mode("global_mode", ctrl->global_mode);

    log_trace_mode("uid_mode", ctrl->uid_mode);
    LOG_WARN("uids_len: %d", ctrl->uids_len);
    if (ctrl->uids_len > 0) {
        for (int i = 0; i < ctrl->uids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  uid[%d]: %u", i, ctrl->uids[i]);
        }
    }

    log_trace_mode("pid_mode", ctrl->pid_mode);
    LOG_WARN("pids_len: %d", ctrl->pids_len);
    if (ctrl->pids_len > 0) {
        for (int i = 0; i < ctrl->pids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  pid[%d]: %d", i, ctrl->pids[i]);
        }
    }

    log_trace_mode("ppid_mode", ctrl->ppid_mode);
    LOG_WARN("ppids_len: %d", ctrl->ppids_len);
    if (ctrl->ppids_len > 0) {
        for (int i = 0; i < ctrl->ppids_len && i < MAX_LIST_ITEMS; i++) {
            LOG_WARN("  ppid[%d]: %d", i, ctrl->ppids[i]);
        }
    }

    log_trace_mode("netio_mode", ctrl->netio_mode);

    LOG_WARN("=== END Control Configuration ===");
    return 0;
}