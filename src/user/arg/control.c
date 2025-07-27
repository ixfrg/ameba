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
#include "common/control.h"
#include "user/jsonify/control.h"
#include "user/jsonify/version.h"
#include "user/arg/control.h"
#include "user/arg/parse_state.h"


/*
    argp function declaration.
*/
static error_t parse_opt(int key, char *arg, struct argp_state *state);

/*
    Globals.
*/
static struct arg_control_with_parse_state global_arg_with_parse_state;
static struct arg_control global_arg_initial_value;

/*
    argp options.
*/
enum
{
    OPT_GLOBAL_MODE = 'g',
    OPT_UID_MODE = 'c',
    OPT_UID_LIST = 'C',
    OPT_CLEAR_UID_LIST = 'X',
    OPT_PID_MODE = 'p',
    OPT_PID_LIST = 'P',
    OPT_CLEAR_PID_LIST = 'Y',
    OPT_PPID_MODE = 'k',
    OPT_PPID_LIST = 'K',
    OPT_CLEAR_PPID_LIST = 'Z',
    OPT_NETIO_MODE = 'n',
    // OPT_CLEAR = 'r',
    OPT_VERSION = 'v',
    OPT_HELP = '?',
    OPT_USAGE = 'u'
};

// Option definitions
static struct argp_option options[] = {
    {"global-mode", OPT_GLOBAL_MODE, "MODE", 0, "Global trace mode (ignore|capture)", 0},
    {"uid-mode", OPT_UID_MODE, "MODE", 0, "UID trace mode (ignore|capture)", 0},
    {"uid-list", OPT_UID_LIST, "UIDS", 0, "Comma-separated list of UIDs", 0},
    {"clear-uid-list", OPT_CLEAR_UID_LIST, 0, 0, "Clear UID list", 0},
    {"pid-mode", OPT_PID_MODE, "MODE", 0, "PID trace mode (ignore|capture)", 0},
    {"pid-list", OPT_PID_LIST, "PIDS", 0, "Comma-separated list of PIDs", 0},
    {"clear-pid-list", OPT_CLEAR_PID_LIST, 0, 0, "Clear PID list", 0},
    {"ppid-mode", OPT_PPID_MODE, "MODE", 0, "PPID trace mode (ignore|capture)", 0},
    {"ppid-list", OPT_PPID_LIST, "PPIDS", 0, "Comma-separated list of PPIDs", 0},
    {"clear-ppid-list", OPT_CLEAR_PPID_LIST, 0, 0, "Clear PPID list", 0},
    {"netio-mode", OPT_NETIO_MODE, "MODE", 0, "Network I/O trace mode (ignore|capture)", 0},
    // {"clear", OPT_CLEAR, 0, 0, "Clear all rules"},
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
    .doc = ARGP_DOC_COPYRIGHT_STR("Program to control ameba"),
    .children = 0,
    .help_filter = 0,
    .argp_domain = 0
};

static struct argp *get_global_argp()
{
    return &global_argp;
}

static struct arg_control_with_parse_state *get_global_arg_with_parse_state()
{
    return &global_arg_with_parse_state;
}

static struct arg_control *get_global_arg_initial_value()
{
    return &global_arg_initial_value;
}

static void set_global_initial_value(struct arg_control *src)
{
    if (!src)
        memset(get_global_arg_initial_value(), 0, sizeof(struct arg_control));
    else
        memcpy(get_global_arg_initial_value(), src, sizeof(struct arg_control));
}

static void copy_global_parsed_value_with_state(struct arg_control_with_parse_state *dst)
{
    memcpy(dst, get_global_arg_with_parse_state(), sizeof(struct arg_control_with_parse_state));
}

static void initialize_arg_with_parse_state(struct arg_control_with_parse_state *src)
{
    if (!src)
        return;
    memcpy(&src->arg, get_global_arg_initial_value(), sizeof(struct arg_control));
    arg_parse_state_init(&(src->parse_state));
}

static void validate_arg(struct arg_control_with_parse_state *src, struct argp_state *state)
{
    // Nothing
}

static int find_string_index(const char *haystack, const char *needle)
{
    char *result = strstr(haystack, needle);
    return result ? (int)(result - haystack) : -1;
}

static void parse_mode(
    struct arg_control_with_parse_state *src, control_trace_mode_t *trace_mode_dst,
    char *mode_str, struct argp_state *state
)
{
    if (find_string_index("ignore", mode_str) == 0 && strlen(mode_str) <= strlen("ignore"))
    {
        *trace_mode_dst = IGNORE;
        return;
    }
    else if (find_string_index("capture", mode_str) == 0 && strlen(mode_str) <= strlen("capture"))
    {
        *trace_mode_dst = CAPTURE;
        return;
    }
    else
    {
        // argp_error(state, "Invalid mode '%s'. Use 'ignore' or 'capture'", mode_str);
        fprintf(stderr, "Invalid mode '%s'. Use 'ignore' or 'capture'. Use --help.\n", mode_str);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }
}

static void parse_int_list(
    struct arg_control_with_parse_state *src,
    const char *list_str, int *array, int *array_len, int max_items,
    int negative_disallowed, struct argp_state *state
)
{
    char *str_copy = strdup(list_str);
    char *token;
    int len = 0;

    token = strtok(str_copy, ",");
    while (token != NULL && len < max_items)
    {
        char *endptr;
        long val = strtol(token, &endptr, 10);
        if (*endptr != '\0' || val < 0)
        {
            // NOTE: Free str_copy if not using argp_error anymore.
            // argp_error(state, "Invalid number in list: '%s'", token);
            fprintf(stderr, "Invalid number in list: '%s'. Use --help.\n", token);
            free(str_copy);
            arg_parse_state_set_exit_error(&src->parse_state, -1);
            return;
        }

        if (negative_disallowed)
        {
            if (val < 0)
            {
                // NOTE: Free str_copy if not using argp_error anymore.
                // argp_error(state, "Negative number not allowed in list: '%ld'", val);
                fprintf(stderr, "Negative number not allowed in list: '%ld'. Use --help.\n", val);
                free(str_copy);
                arg_parse_state_set_exit_error(&src->parse_state, -1);
                return;
            }
        }

        array[len++] = (int)val;
        token = strtok(NULL, ",");
    }

    free(str_copy);

    // If there are still more tokens then exceeded max items
    if (token != NULL)
    {
        // argp_error(state, "Too many items in list (max %d)", max_items);
        fprintf(stderr, "Too many items in list (max %d). Use --help.\n", max_items);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    *array_len = len;
}

static void clear_id_list(
    struct arg_control_with_parse_state *src,
    int *array, int *array_len, int max_items, struct argp_state *state
)
{
    *array_len = 0;
    __builtin_memset(array, 0, sizeof(int) * max_items);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arg_control_with_parse_state *src = get_global_arg_with_parse_state();
    int negative_disallowed = 1;

    switch (key)
    {
    // case OPT_CLEAR:
    //     input->clear = 1;
    //     break;

    case OPT_VERSION:
        jsonify_version_write_all_versions_to_file(stdout);
        arg_parse_state_set_exit_no_error(&src->parse_state);
        break;

    case OPT_HELP:
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        arg_parse_state_set_exit_no_error(&src->parse_state);
        break;

    case OPT_USAGE:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        arg_parse_state_set_exit_no_error(&src->parse_state);
        break;

    case OPT_GLOBAL_MODE:
        parse_mode(src, &src->arg.control.global_mode, arg, state);
        break;

    case OPT_UID_MODE:
        parse_mode(src, &src->arg.control.uid_mode, arg, state);
        break;

    case OPT_UID_LIST:
        parse_int_list(
            src, arg, 
            (int *)src->arg.control.uids, &src->arg.control.uids_len, MAX_LIST_ITEMS,
            negative_disallowed, state
        );
        break;

    case OPT_CLEAR_UID_LIST:
        clear_id_list(
            src,
            (int *)src->arg.control.uids, &src->arg.control.uids_len, MAX_LIST_ITEMS,
            state
        );
        break;

    case OPT_PID_MODE:
        parse_mode(src, &src->arg.control.pid_mode, arg, state);
        break;

    case OPT_PID_LIST:
        parse_int_list(
            src, arg,
            (int *)src->arg.control.pids, &src->arg.control.pids_len, MAX_LIST_ITEMS,
            negative_disallowed, state
        );
        break;

    case OPT_CLEAR_PID_LIST:
        clear_id_list(
            src,
            (int *)src->arg.control.pids, &src->arg.control.pids_len, MAX_LIST_ITEMS,
            state
        );
        break;

    case OPT_PPID_MODE:
        parse_mode(src, &src->arg.control.ppid_mode, arg, state);
        break;

    case OPT_PPID_LIST:
        parse_int_list(
            src, arg,
            (int *)src->arg.control.ppids, &src->arg.control.ppids_len, MAX_LIST_ITEMS,
            negative_disallowed, state
        );
        break;

    case OPT_CLEAR_PPID_LIST:
        clear_id_list(
            src,
            (int *)src->arg.control.ppids, &src->arg.control.ppids_len, MAX_LIST_ITEMS,
            state
        );
        break;

    case OPT_NETIO_MODE:
        parse_mode(src, &src->arg.control.netio_mode, arg, state);
        break;

    case ARGP_KEY_INIT:
        initialize_arg_with_parse_state(src);
        break;

    case ARGP_KEY_END:
        validate_arg(src, state);
        break;

    case ARGP_KEY_ERROR:
    case ARGP_KEY_ARG:
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        break;

    default:
        break;
    }

    return 0;
}

int arg_control_parse(
    struct arg_control_with_parse_state *dst,
    struct arg_control *initial_value,
    int argc, char **argv
)
{
    if (!dst)
    {
        fprintf(stderr, "Failed arg_control_parse. NULL argument(s)");
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