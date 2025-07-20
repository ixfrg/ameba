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

#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "common/constants.h"
#include "user/args/loader.h"
#include "user/args/helper.h"


static error_t parse_opt(int key, char *arg, struct argp_state *state);


static struct loader_input_arg global_loader_input_arg;


enum
{
    OPT_VERSION = 'v',
    OPT_HELP = '?',
    OPT_USAGE = 'u'
};

// Option definitions
static struct argp_option options[] = {
    {"version", OPT_VERSION, 0, 0, "Show version"},
    {"help", OPT_HELP, 0, 0, "Show help"},
    {"usage", OPT_USAGE, 0, 0, "Show usage"},
    {0}
};

// Argp parser structure
struct argp global_loader_input_argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = ARGP_DOC_COPYRIGHT_STR("Program to load an pin BPF programs and maps"),
    .children = 0,
    .help_filter = 0,
    .argp_domain = 0
};

static struct loader_input_arg *get_global_loader_input_arg()
{
    return &global_loader_input_arg;
}

static void init_loader_input(struct loader_input_arg *input)
{
    if (!input)
        return;
    user_args_helper_state_init(&(input->parse_state));
}

static void validate_loader_input(struct loader_input_arg *input, struct argp_state *state)
{
    // Nothing
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct loader_input_arg *input = get_global_loader_input_arg();

    switch (key)
    {
    case OPT_VERSION:
        user_args_helper_print_app_version();
        user_args_helper_state_set_exit_no_error(&input->parse_state);
        break;

    case OPT_HELP:
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        user_args_helper_state_set_exit_no_error(&input->parse_state);
        break;

    case OPT_USAGE:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        user_args_helper_state_set_exit_no_error(&input->parse_state);
        break;

    case ARGP_KEY_INIT:
        init_loader_input(input);
        break;

    case ARGP_KEY_ERROR:
    case ARGP_KEY_ARG:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        user_args_helper_state_set_exit_error(&input->parse_state, -1);
        break;

    case ARGP_KEY_END:
        validate_loader_input(input, state);
        break;

    default:
        break;
    }

    return 0;
}

void user_args_loader_copy(struct loader_input_arg *dst)
{
    if (!dst)
        return;
    memcpy(dst, get_global_loader_input_arg(), sizeof(struct loader_input_arg));
}

void user_args_loader_parse(struct loader_input_arg *dst, int argc, char **argv)
{
    if (!dst)
        return;

    int argp_flags = 0;
    // ARGP_NO_EXIT & ARGP_NO_HELP because self-managed
    argp_flags = ARGP_NO_EXIT | ARGP_NO_HELP;
    argp_parse(&global_loader_input_argp, argc, argv, argp_flags, 0, 0);

    user_args_loader_copy(dst);
}
