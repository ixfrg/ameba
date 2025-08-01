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
#include "user/jsonify/control.h"

#include "user/args/control.h"
#include "user/args/helper.h"


static error_t parse_opt(int key, char *arg, struct argp_state *state);


static struct control_input global_control_input;


enum
{
    OPT_GLOBAL_MODE = 'g',
    OPT_UID_MODE = 'c',
    OPT_UID_LIST = 'C',
    OPT_PID_MODE = 'p',
    OPT_PID_LIST = 'P',
    OPT_PPID_MODE = 'k',
    OPT_PPID_LIST = 'K',
    OPT_NETIO_MODE = 'n'
};

// Option definitions
static struct argp_option options[] = {
    {"global-mode", OPT_GLOBAL_MODE, "MODE", 0, "Global trace mode (ignore|capture)", 0},
    {"uid-mode", OPT_UID_MODE, "MODE", 0, "UID trace mode (ignore|capture)", 0},
    {"uid-list", OPT_UID_LIST, "UIDS", 0, "Comma-separated list of UIDs", 0},
    {"pid-mode", OPT_PID_MODE, "MODE", 0, "PID trace mode (ignore|capture)", 0},
    {"pid-list", OPT_PID_LIST, "PIDS", 0, "Comma-separated list of PIDs", 0},
    {"ppid-mode", OPT_PPID_MODE, "MODE", 0, "PPID trace mode (ignore|capture)", 0},
    {"ppid-list", OPT_PPID_LIST, "PPIDS", 0, "Comma-separated list of PPIDs", 0},
    {"netio-mode", OPT_NETIO_MODE, "MODE", 0, "Network I/O trace mode (ignore|capture)", 0},
    {0}
};

// Argp parser structure
struct argp global_control_input_argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = "Parse Control Input",
    .children = 0,
    .help_filter = 0,
    .argp_domain = 0
};

static struct control_input *get_global_control_input()
{
    return &global_control_input;
}

static void init_control_input(struct control_input *input)
{
    if (!input)
        return;
    input->lock = FREE;
    input->global_mode = IGNORE;
    input->uid_mode = IGNORE;
    input->uids_len = 0;
    input->pid_mode = IGNORE;
    input->pids_len = 0;
    input->ppid_mode = IGNORE;
    input->ppids_len = 0;
    input->netio_mode = IGNORE;
    user_args_helper_state_init(&(input->parse_state));
}

static int find_string_index(const char *haystack, const char *needle)
{
    char *result = strstr(haystack, needle);
    return result ? (int)(result - haystack) : -1;
}

static void parse_mode(struct control_input *input, trace_mode_t *dst, char *mode_str, struct argp_state *state)
{
    if (find_string_index("ignore", mode_str) == 0 && strlen(mode_str) <= strlen("ignore"))
    {
        *dst = IGNORE;
        return;
    }
    else if (find_string_index("capture", mode_str) == 0 && strlen(mode_str) <= strlen("capture"))
    {
        *dst = CAPTURE;
        return;
    }
    else
    {
        // argp_error(state, "Invalid mode '%s'. Use 'ignore' or 'capture'", mode_str);
        fprintf(stderr, "Invalid mode '%s'. Use 'ignore' or 'capture'. Use --help.\n", mode_str);
        user_args_helper_state_set_exit_error(&input->parse_state, -1);
        return;
    }
}

static void parse_int_list(
    struct control_input *input,
    const char *list_str, int *array, int *array_len, int max_items, int negative_disallowed, struct argp_state *state
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
            user_args_helper_state_set_exit_error(&input->parse_state, -1);
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
                user_args_helper_state_set_exit_error(&input->parse_state, -1);
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
        user_args_helper_state_set_exit_error(&input->parse_state, -1);
        return;
    }

    *array_len = len;
}

static void validate_control_input(struct control_input *input, struct argp_state *state)
{
    // Nothing
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct control_input *input = get_global_control_input();
    int negative_disallowed = 1;

    switch (key)
    {
    case OPT_GLOBAL_MODE:
        parse_mode(input, &input->global_mode, arg, state);
        break;

    case OPT_UID_MODE:
        parse_mode(input, &input->uid_mode, arg, state);
        break;

    case OPT_UID_LIST:
        parse_int_list(input, arg, (int *)input->uids, &input->uids_len, MAX_LIST_ITEMS, negative_disallowed, state);
        break;

    case OPT_PID_MODE:
        parse_mode(input, &input->pid_mode, arg, state);
        break;

    case OPT_PID_LIST:
        parse_int_list(input, arg, (int *)input->pids, &input->pids_len, MAX_LIST_ITEMS, negative_disallowed, state);
        break;

    case OPT_PPID_MODE:
        parse_mode(input, &input->ppid_mode, arg, state);
        break;

    case OPT_PPID_LIST:
        parse_int_list(input, arg, (int *)input->ppids, &input->ppids_len, MAX_LIST_ITEMS, negative_disallowed, state);
        break;

    case OPT_NETIO_MODE:
        parse_mode(input, &input->netio_mode, arg, state);
        break;

    case ARGP_KEY_INIT:
        init_control_input(input);
        break;

    case ARGP_KEY_END:
        validate_control_input(input, state);
        break;

    case ARGP_KEY_ERROR:
    case ARGP_KEY_ARG:
        user_args_helper_state_set_exit_error(&input->parse_state, -1);
        break;

    default:
        break;
    }

    return 0;
}

void user_args_control_copy(struct control_input *dst)
{
    if (!dst)
        return;
    memcpy(dst, get_global_control_input(), sizeof(struct control_input));
}

void user_args_control_parse(struct control_input *dst, int argc, char **argv)
{
    if (!dst)
        return;

    int argp_flags = 0;
    // ARGP_NO_EXIT & ARGP_NO_HELP because self-managed
    argp_flags = ARGP_NO_EXIT | ARGP_NO_HELP;
    argp_parse(&global_control_input_argp, argc, argv, argp_flags, 0, 0);

    user_args_control_copy(dst);
}
