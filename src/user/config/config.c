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
#include <ctype.h>
#include <libgen.h>
#include <errno.h>

#include "user/helpers/log.h"

#define MAX_LINE_LEN 200
#define MAX_ARGS     100

static char *trim_strip(char *str)
{
    char *end;

    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    *(end + 1) = '\0';
    return str;
}

int config_parse_as_argv(const char *filename, int *argc_out, char ***argv_out)
{
    int result = -1;
    FILE *f = NULL;
    char **argv = NULL;
    int argc = 0;
    char *dup_filename = NULL;

    if (!filename || !argc_out || !argv_out) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed config_parse_as_argv. NULL input");
        return -1;
    }

    f = fopen(filename, "r");
    if (!f) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to open file '%s'. Err: %s", filename, strerror(errno));
        return -1;
    }

    argv = malloc(sizeof(char *) * MAX_ARGS);
    if (!argv) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to malloc argv");
        goto cleanup;
    }

    dup_filename = strdup(filename);
    if (!dup_filename) {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed to strdup filename");
        goto cleanup;
    }

    char *f_basename = basename(dup_filename);
    argv[argc++] = strdup(f_basename);

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), f)) {
        char *trimmed = trim_strip(line);
        if (*trimmed == '\0' || *trimmed == '#')
            continue;

        char *token = strtok(trimmed, " \t");
        while (token && argc < MAX_ARGS) {
            argv[argc++] = strdup(token);
            token = strtok(NULL, " \t");
        }
    }

    *argc_out = argc;
    *argv_out = argv;
    result = 0;

cleanup:
    if (f) fclose(f);
    if (dup_filename) free(dup_filename);

    if (result != 0) {
        if (argv) {
            for (int i = 0; i < argc; i++)
                free(argv[i]);
            free(argv);
        }
    }

    return result;
}