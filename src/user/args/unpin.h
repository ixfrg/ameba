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

#include "user/args/helper.h"

/*

    A module to help parse unpin program arguments

*/

struct unpin_input
{

};

/*
    A struct to encapsulate unpin input and keep parsing state.
*/
struct unpin_input_arg
{
    struct arg_parse_state parse_state;
    struct unpin_input unpin_input;
};

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    Return:
        Always returns. Error (if any) in (struct unpin_input_arg)->(struct arg_parse_state).
*/
void user_args_unpin_parse(struct unpin_input_arg *dst, struct unpin_input *initial_value, int argc, char **argv);
