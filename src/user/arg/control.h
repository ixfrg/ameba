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

    A module to help parse control input from user/config arguments.

*/

#include "common/control.h"
#include "user/arg/parse_state.h"


struct arg_control
{
    struct control control;
};

struct arg_control_with_parse_state
{
    struct arg_parse_state parse_state;
    struct arg_control arg;
};

/*
    Parse user arguments (i.e. int main(int argc, char **argv)), and populate dst.

    'initial_value' is the value to which (struct arg_control_with_parse_state)->(struct arg_control)
    is initialized before arg parsing.

    Return:
        0  => Success
        1  => Failure

    NOTE: This function's success does NOT mean that the arguments were parsed successfully. To check that use
    (struct arg_control_with_parse_state)->(struct arg_parse_state).
*/
int arg_control_parse(
    struct arg_control_with_parse_state *dst,
    struct arg_control *initial_value,
    int argc, char **argv
);
