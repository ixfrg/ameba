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
    Copy value of internal global struct user_input to dst.
*/
void user_args_user_copy(struct user_input *dst);

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        0    => Success
        +ive => Failure
        -ive => Failure
*/
int user_args_user_parse(struct user_input *dst, int argc, char **argv);