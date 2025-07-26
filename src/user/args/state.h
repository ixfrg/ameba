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
    A module to manage argument parse state.

    Each time arguments are parsed via user or via config, the state is properly set.

    This state is used for deciding post-parse whether to exit or not.

    This is necessary since argp is being used with custom configuration.
*/


struct args_parse_state
{
    int exit;
    int code;
};

/*
    Initialize to normal state.
*/
void user_args_parse_state_init(struct args_parse_state *s);

/*
    Set the error code, and corresponding state.
*/
void user_args_parse_state_set_exit_error(struct args_parse_state *s, int code);

/*
    Set exit to true.
*/
void user_args_parse_state_set_exit_no_error(struct args_parse_state *s);

/*
    Set exit to false.
*/
void user_args_parse_state_set_no_exit(struct args_parse_state *s);

/*
    Function to check if exit is set.
*/
int user_args_parse_state_is_exit_set(struct args_parse_state *s);

/*
    Get the exit code.
*/
int user_args_parse_state_get_code(struct args_parse_state *s);