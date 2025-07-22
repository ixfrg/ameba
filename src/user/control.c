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
#include <stdlib.h>

#include "common/types.h"
#include "common/version.h"
#include "user/helpers/log.h"
#include "user/helpers/prog_op.h"
#include "user/args/control.h"


static void parse_user_input(struct control_input_arg *input_arg, int argc, char *argv[])
{
    user_args_control_parse(input_arg, argc, argv);

    struct arg_parse_state *a_p_s = &(input_arg->parse_state);
    if (user_args_helper_state_is_exit_set(a_p_s))
    {
        exit(user_args_helper_state_get_code(a_p_s));
    }
}

int main(int argc, char *argv[])
{
    int result = 0;

    struct control_input_arg input_arg;

    parse_user_input(&input_arg, argc, argv);

    if (prog_op_create_lock_dir() != 0)
    {
        result = -1;
        goto exit;
    }

    result = prog_op_ameba_must_be_pinned();
    if (result != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    if (prog_op_compare_versions_in_loaded_maps_with_current_versions() != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    if (prog_op_set_control_input_in_map(&input_arg.control_input) != 0)
    {
        result = -1;
        goto rm_prog_op_lock_dir;
    }

    log_state_msg_with_current_pid(APP_STATE_OPERATIONAL_PID, "Updated");

rm_prog_op_lock_dir:
    prog_op_remove_lock_dir();

exit:
    return result;
}
