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

    A module to help parse ameba input from user arguments.

*/

#include <limits.h>

#include "user/args/state.h"


struct ameba_input
{
    char log_dir_path[PATH_MAX];
    unsigned long long log_file_size_bytes;
    unsigned int log_file_count;
};

struct ameba_input_arg
{
    struct args_parse_state parse_state;
    struct ameba_input ameba_input;
};

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    'initial_value' is the value to which (struct ameba_input_arg)->(struct ameba_input)
    is initialized before arg parsing.

    If 'initial_value' is NULL then no initialization is done.

    Return:
        Always returns. Error (if any) in (struct ameba_input_arg)->(struct arg_parse_state).
*/
void user_args_ameba_parse(
    struct ameba_input_arg *dst,
    struct ameba_input *initial_value,
    int argc, char **argv
);