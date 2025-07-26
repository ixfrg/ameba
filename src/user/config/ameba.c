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

#include "common/constants.h"
#include "user/config/ameba.h"


void config_ameba_parse_config(
    char *file_path,
    struct ameba_input *dst
)
{
    int argc = 0;
    char **argv = NULL;

    const char *config_path = file_path;

    if (config_parse_as_argv(config_path, &argc, &argv) != 0) {
        return;
    }

    struct ameba_input_arg config_arg;
    user_args_ameba_parse(&config_arg, NULL, argc, argv);

    for (int i = 0; i < argc; ++i) {
        free(argv[i]);
    }
    free(argv);

    struct args_parse_state *a_p_s = &(config_arg.parse_state);
    if (user_args_parse_state_is_exit_set(a_p_s))
    {
        exit(user_args_parse_state_get_code(a_p_s));
    }
    *dst = config_arg.ameba_input;
}

void config_ameba_parse_default_config(struct ameba_input *dst)
{
    config_ameba_parse_config(PROG_AMEBA_CONFIG_FILE_PATH, dst);
}