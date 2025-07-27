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

#include "user/arg/ameba.h"
#include "user/record/writer/file.h"


static struct {
    int fd;
    int initialized;
    char path[PATH_MAX];
} state = {0};


static int set_init_args_file(void *ptr, size_t ptr_len) {
    if (ptr_len != PATH_MAX)
        return -1;

    if (!ptr)
        return -1;

    char *src = (char *)ptr;
    int src_len = strnlen(src, PATH_MAX);

    if (src_len == 0 || src_len >= PATH_MAX)
        return -1;

    memcpy(&state.path, src, src_len);
    return 0;
}

static int init_file() {
    if (state.initialized)
        return 0;

    state.fd = open(state.path, O_RDWR | O_CREAT | O_APPEND, 0600);
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