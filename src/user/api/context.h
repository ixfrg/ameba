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


#include "user/helper/prog_op.h"


struct api_context
{
    /*
        Function to check if ameba is pinned.

        Must be called with a lock already held i.e. prog_op_create_lock_dir is already called. TODO

        Returns:
            0  => Yes, it is pinned.
            -1 => Error or not pinned.
    */
    int (*bpf_must_be_pinned)();
    /*
        Function to get current control input in pinned control input map.

        Must be called with a lock already held i.e. prog_op_create_lock_dir is already called. TODO

        Returns:
            0  => Success
            -1 => Error
    */
    int (*get_control_from_bpf_map)(struct control *control);
};