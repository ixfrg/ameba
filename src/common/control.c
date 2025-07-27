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

#include "common/control.h"


void control_set_ignore_all(struct control *dst)
{
    if (!dst)
        return;
    dst->global_mode = IGNORE;
    dst->uid_mode = IGNORE;
    __builtin_memset(dst->uids, 0, sizeof(dst->uids));
    dst->uids_len = 0;
    dst->pid_mode = IGNORE;
    __builtin_memset(dst->pids, 0, sizeof(dst->pids));
    dst->pids_len = 0;
    dst->ppid_mode = IGNORE;
    __builtin_memset(dst->ppids, 0, sizeof(dst->ppids));
    dst->ppids_len = 0;
    dst->netio_mode = IGNORE;
}

void control_set_default(struct control *dst)
{
    control_set_ignore_all(dst);
}