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

#pragma once

/*

    A module to help parse control_input from user arguments.

*/

#include "common/control.h"


/*
    A struct to encapsulate 'struct control_input' and keep parsing state.
*/
struct control_input_arg
{
    struct arg_parse_state parse_state;
    struct control_input control_input;
    int clear;
};

/*
    A properly formed argp struct.
*/
extern struct argp global_control_input_argp;

/*
    Copy the value of internal global (struct control_input_arg) to dst.
*/
void user_args_control_copy(struct control_input_arg *dst);
void user_args_control_copy_only_control_input(struct control_input *dst);

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        Always returns. Error (if any) in (struct control_input)->(struct arg_parse_state).
*/
void user_args_control_parse(struct control_input_arg *dst, struct control_input *initial_val, int argc, char **argv);
