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
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include "user/args/ameba.h"
#include "user/record/writer/writer.h"
#include "user/record/writer/file.h"

static struct {
    char dir[PATH_MAX];
    unsigned long long max_bytes;
    unsigned int max_files;

    unsigned long long current_bytes;
    unsigned int file_index;
    int initialized;
} state = {0};


static const struct record_writer *file_writer = &record_writer_file;


int generate_log_path(char *path_out, size_t len)
{
    DIR *dir = opendir(state.dir);
    if (!dir)
        return -1;

    unsigned int max_seen = 0;
    unsigned int found_any = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        unsigned int idx = 0;
        if (sscanf(entry->d_name, "ameba_log_%03u.log", &idx) == 1)
        {
            if (idx < state.max_files)
            {
                if (!found_any || idx > max_seen)
                {
                    max_seen = idx;
                    found_any = 1;
                }
            }
        }
    }

    closedir(dir);

    state.file_index = found_any ? ((max_seen) % state.max_files) : 0;

    int result = snprintf(
        path_out, len, "%s/ameba_log_%03u.log",
        state.dir,
        state.file_index
    );

    return (result < 0 || (size_t)result >= len) ? -1 : 0;
}

static int set_init_args_rotate(void *ptr, size_t ptr_len) {
    if (ptr_len != sizeof(struct ameba_input))
        return -1;

    const struct ameba_input *input = ptr;
    size_t path_len = strnlen(input->log_dir_path, PATH_MAX);
    if (path_len == 0 || path_len >= PATH_MAX)
        return -1;

    strncpy(state.dir, input->log_dir_path, PATH_MAX);
    state.max_bytes = input->log_file_size_bytes;
    state.max_files = input->log_file_count;
    state.current_bytes = 0;
    state.file_index = 0;
    state.initialized = 0;

    return 0;
}

static int rotate_and_init_file() {
    char path[PATH_MAX];
    if (generate_log_path(path, sizeof(path)) < 0)
        return -1;

    if (file_writer->set_init_args((void *)(&path[0]), PATH_MAX) != 0)
        return -1;

    if (file_writer->init() != 0)
        return -1;

    state.current_bytes = 0;
    state.file_index++;
    state.initialized = 1;
    return 0;
}

static int init_rotate() {
    struct stat st;
    if (stat(state.dir, &st) == -1)
    {
        if (errno == ENOENT)
        {
            if (mkdir(state.dir, 0700) == -1)
            {
                if (errno != EEXIST)
                {
                    return -1;
                }
            }
        } else
        {
            return -1;
        }
    } else if (!S_ISDIR(st.st_mode))
    {
        return -1;
    }

    return rotate_and_init_file();
}

static int write_rotate(void *data, size_t len) {
    if (!state.initialized)
        return -2;

    if (state.current_bytes + len > state.max_bytes) {
        if (rotate_and_init_file() < 0)
            return -1;
    }

    int written = file_writer->write(data, len);
    if (written > 0)
        state.current_bytes += (unsigned long long)written;

    return written;
}

static int close_rotate() {
    state.initialized = 0;
    return file_writer->close();
}

const struct record_writer record_writer_dir = {
    .set_init_args = set_init_args_rotate,
    .init = init_rotate,
    .close = close_rotate,
    .write = write_rotate,
};