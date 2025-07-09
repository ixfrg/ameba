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

    A module to help parse user_input from user arguments.

*/

#include "user/types.h"

/*
    Default output values
*/
static enum output_type default_output_type = OUTPUT_FILE;
static const char *default_output_file_path = "/tmp/current_prov_log.json";

/*
    A properly formed argp struct.
*/
extern struct argp global_user_input_argp;

/*
    Parsed user input.
    Assumes successful call to 'user_args_user_must_parse_user_input'.
*/
extern struct user_input global_user_input;

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        0    => Success
        +ive => Failure
        -ive => Failure
*/
int user_args_user_must_parse_user_input(int argc, char **argv);