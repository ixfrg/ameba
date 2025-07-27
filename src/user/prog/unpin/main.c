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

#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include "common/types.h"
#include "common/version.h"
#include "common/constants.h"
#include "user/helper/prog_op.h"
#include "user/helper/log.h"
#include "user/config/unpin.h"
#include "user/arg/unpin.h"


static void parse_user_input(struct arg_unpin *dst, int argc, char *argv[])
{
    struct arg_unpin initial_value;
    config_unpin_parse_default_config(&initial_value);

    struct arg_unpin_with_parse_state input_arg;
    arg_unpin_parse(&input_arg, &initial_value, argc, argv);

    struct arg_parse_state *a_p_s = &(input_arg.parse_state);
    if (arg_parse_state_is_exit_set(a_p_s))
    {
        exit(arg_parse_state_get_code(a_p_s));
    }
    *dst = input_arg.arg;
}

int main(int argc, char *argv[])
{
    int result = 0;

    struct arg_unpin unpin_input;
    parse_user_input(&unpin_input, argc, argv);

    if (prog_op_create_lock_dir() != 0)
    {
        result = -1;
        goto exit;
    }

    result = prog_op_unpin_bpf_progs_and_maps(&unpin_input);
    if (result != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    log_state_msg_with_current_pid(APP_STATE_OPERATIONAL_PID, "Unpinned");

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}
