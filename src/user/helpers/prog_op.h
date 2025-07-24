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

#include "common/control.h"
#include "user/args/control.h"
#include "user/args/pin.h"
#include "user/args/unpin.h"


/*
    Function to create the directory which guards all ameba operations.

    Returns:
        0  => Success
        -1 => Failed
*/
int prog_op_create_lock_dir(void);

/*
    Function to remove the directory which guards all ameba operations.

    Returns:
        0  => Success
        -1 => Failed
*/
int prog_op_remove_lock_dir(void);

/*
    Function to check equality of versions between the versions of the program
    and the versions loaded in ebpf maps.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        0  => Equal
        -1 => Error
*/
int prog_op_compare_versions_in_loaded_maps_with_current_versions(void);

/*
    Function to check if ameba is pinned.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        0  => Yes, it is pinned.
        -1 => Error or not pinned.
*/
int prog_op_ameba_must_be_pinned(void);

/*
    Function to check if ameba is not pinned.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        0  => Not pinned.
        -1 => Error or pinned.
*/
int prog_op_ameba_must_not_be_pinned(void);

/*
    Function to set given control input in pinned control input map.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        0  => Success
        -1 => Error
*/
int prog_op_set_control_input_in_map(struct control_input *input);

/*
    Function to get current control input in pinned control input map.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        0  => Success
        -1 => Error
*/
int prog_op_get_control_input_in_map(struct control_input *input);

/*
    Function to get output ringbuf fd.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        >=0  => file descriptor
        -ive => Error
*/
int prog_op_get_output_ringbuf_fd(void);

/*
    Function to pin all bpf programs and maps.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        0    => Success
        -ive => Error
*/
int prog_op_pin_bpf_progs_and_maps(struct pin_input *arg);

/*
    Function to unpin all bpf programs and maps.

    Must be called with a lock already held i.e. prog_op_create_lock_dir is already called.

    Returns:
        0    => Success
        -ive => Error
*/
int prog_op_unpin_bpf_progs_and_maps(struct unpin_input *arg);

/*
    Function to get the ring buffer instance and setup callback
    for data on ring buffer.

    Returns:
        NULL => Error
        ptr  => Success
*/
struct ring_buffer * prog_op_setup_output_ringbuf_reader(int (*handle_ringbuf_data)(void *ctx, void *data, size_t data_len));