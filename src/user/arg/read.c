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
#include "user/arg/read.h"
#include "user/jsonify/version.h"


/*
    argp function declaration.
*/
static error_t parse_opt(int key, char *arg, struct argp_state *state);

/*
    Globals.
*/
static struct arg_read_with_parse_state global_arg_with_parse_state;
static struct arg_read global_arg_initial_value;

/*
    argp options.
*/
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
static struct argp global_argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = ARGP_DOC_COPYRIGHT_STR("Program to read ameba ringbuf and write to stdout"),
    .children = 0,
    .help_filter = 0,
    .argp_domain = 0
};

static struct argp *get_global_argp()
{
    return &global_argp;
}

static struct arg_read_with_parse_state *get_global_arg_with_parse_state()
{
    return &global_arg_with_parse_state;
}

static struct arg_read *get_global_arg_initial_value()
{
    return &global_arg_initial_value;
}

static void set_global_initial_value(struct arg_read *src)
{
    if (!src)
        memset(get_global_arg_initial_value(), 0, sizeof(struct arg_read));
    else
        memcpy(get_global_arg_initial_value(), src, sizeof(struct arg_read));
}

static void copy_global_parsed_value_with_state(struct arg_read_with_parse_state *dst)
{
    memcpy(dst, get_global_arg_with_parse_state(), sizeof(struct arg_read_with_parse_state));
}

static void initialize_arg_with_parse_state(struct arg_read_with_parse_state *src)
{
    if (!src)
        return;
    memcpy(&src->arg, get_global_arg_initial_value(), sizeof(struct arg_read));
    arg_parse_state_init(&(src->parse_state));
    arg_common_init(&src->common);
}

static void validate_arg(struct arg_read_with_parse_state *src, struct argp_state *state)
{
    // Nothing
}

static void handle_argp_key_end(struct arg_read_with_parse_state *src, struct argp_state *state)
{
    if (arg_common_is_usage_help_or_version_set(&src->common))
        return;
    validate_arg(src, state);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arg_read_with_parse_state *src = get_global_arg_with_parse_state();

    switch (key)
    {
    case OPT_VERSION:
        jsonify_version_write_all_versions_to_file(stdout);
        arg_common_show_version(&src->common, &src->parse_state);
        break;

    case OPT_HELP:
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        arg_common_show_help(&src->common, &src->parse_state);
        break;

    case OPT_USAGE:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        arg_common_show_usage(&src->common, &src->parse_state);
        break;

    case ARGP_KEY_INIT:
        initialize_arg_with_parse_state(src);
        break;

    case ARGP_KEY_ERROR:
    case ARGP_KEY_ARG:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        break;

    case ARGP_KEY_END:
        handle_argp_key_end(src, state);
        break;

    default:
        break;
    }

    return 0;
}

int arg_read_parse(
    struct arg_read_with_parse_state *dst,
    struct arg_read *initial_value,
    int argc, char **argv
)
{
    if (!dst)
    {
        fprintf(stderr, "Failed arg_read_parse. NULL argument(s)");
        return -1;
    }

    set_global_initial_value(initial_value);

    int argp_flags = 0;
    // ARGP_NO_EXIT & ARGP_NO_HELP because self-managed.
    argp_flags = ARGP_NO_EXIT | ARGP_NO_HELP;
    // Error from argp_parse not handled because self-managed.
    argp_parse(get_global_argp(), argc, argv, argp_flags, 0, 0);

    copy_global_parsed_value_with_state(dst);

    return 0;
}
