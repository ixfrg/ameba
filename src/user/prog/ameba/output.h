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

#include "user/arg/ameba.h"


/*
    Function to setup the log writer and serializer given the input.

    Returns:
        0   => Success
        -1  => Error
*/
int output_setup_log_writer(struct arg_ameba *arg);

/*
    Function to cleanup the log writer.
*/
void output_close_log_writer();

/*
    The callback function called with data from ringbuf when bpf ringbuf is being polled.

    See bpf docs for prototype doc.
*/
int output_handle_ringbuf_data(void *ctx, void *data, size_t data_len);