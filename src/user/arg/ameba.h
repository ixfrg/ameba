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

    A module to help parse ameba input from user/config arguments.

*/

#include <linux/limits.h>

#include "user/arg/parse_state.h"


struct arg_ameba
{
    char log_dir_path[PATH_MAX];
    unsigned long long log_file_size_bytes;
    unsigned int log_file_count;
};

struct arg_ameba_with_parse_state
{
    struct arg_parse_state parse_state;
    struct arg_ameba arg;
};

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    'initial_value' is the value to which (struct arg_ameba_with_parse_state)->(struct arg_ameba)
    is initialized before arg parsing.

    Return:
        0  => Success
        1  => Failure

    NOTE: This function's success does NOT mean that the arguments were parsed successfully. To check that use
    (struct arg_ameba_with_parse_state)->(struct arg_parse_state).
*/
int arg_ameba_parse(
    struct arg_ameba_with_parse_state *dst,
    struct arg_ameba *initial_value,
    int argc, char **argv
);