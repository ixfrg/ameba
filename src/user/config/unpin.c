// SPDX-License-Identifier: GPL-3.0-or-later
/*
unpin - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
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

#include <stdlib.h>

#include "common/constants.h"
#include "user/config/unpin.h"
#include "user/helper/log.h"


void config_unpin_parse_config_file(char *file_path, struct arg_unpin *dst)
{
    if (!file_path || !dst)
    {
        log_state_msg(APP_STATE_STOPPED_WITH_ERROR, "Failed config_unpin_parse_config_file. NULL argument(s)");
        exit(-1);
    }

    int argc = 0;
    char **argv = NULL;

    const char *config_path = file_path;

    if (config_parse_as_argv(config_path, &argc, &argv) != 0)
    {
        exit(-1);
    }

    struct arg_unpin_with_parse_state config_arg;
    int parse_result = arg_unpin_parse(&config_arg, NULL, argc, argv);

    for (int i = 0; i < argc; ++i)
    {
        free(argv[i]);
    }
    free(argv);

    if (parse_result != 0)
    {
        exit(-1);
    }

    struct arg_parse_state *a_p_s = &(config_arg.parse_state);
    if (arg_parse_state_is_exit_set(a_p_s))
    {
        exit(arg_parse_state_get_code(a_p_s));
    }
    *dst = config_arg.arg;
}

void config_unpin_parse_default_config(struct arg_unpin *dst)
{
    config_unpin_parse_config_file(PROG_UNPIN_CONFIG_FILE_PATH, dst);
}