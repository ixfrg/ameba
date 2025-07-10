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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

#include "user/record/writer/writer.h"
#include "user/types.h"


static struct {
    int fd;
    int initialized;
    struct output_file init_args;
} state = {0};


static int set_init_args_file(void *ptr, size_t ptr_len) {
    if (ptr_len != sizeof(struct output_file))
        return -1;

    struct output_file *in = (struct output_file *)ptr;

    if (strlen(in->path) == 0 || strlen(in->path) >= PATH_MAX)
        return -1;

    memcpy(&state.init_args, in, sizeof(struct output_file));
    return 0;
}

static int init_file() {
    if (state.initialized)
        return 0;

    state.fd = open(state.init_args.path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (state.fd == -1)
        return -1;

    state.initialized = 1;
    return 0;
}

static int close_file() {
    if (state.initialized) {
        close(state.fd);
        state.fd = 0;
        state.initialized = 0;
    }
    return 0;
}

static int write_file(void *data, size_t data_len) {
    if (!state.initialized)
        return -2;

    size_t written = write(state.fd, data, data_len);
    if (written != data_len)
        return -1;

    return (int)written;
}

const struct record_writer record_writer_file = {
    .set_init_args = set_init_args_file,
    .init = init_file,
    .close = close_file,
    .write = write_file,
};