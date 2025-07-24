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


#include <bpf/libbpf.h>

#include "user/args/ameba.h"


/*
    Function to setup the log writer and serializer given the input.

    Returns:
        0   => Success
        -1  => Error
*/
int output_setup_log_writer(struct ameba_input *ameba_input);

/*
    Function to get the ring buffer instance and setup callback 
    for data on ring buffer.

    Returns:
        NULL => Error
        ptr  => Success
*/
struct ring_buffer * output_setup_output_ringbuf_reader();

/*
    Function to cleanup the log writer.
*/
void output_close_log_writer();