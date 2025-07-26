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
#include "user/args/control.h"
#include "user/args/ameba.h"
#include "user/args/state.h"
#include "common/version.h"
#include "user/jsonify/types.h"
#include "user/jsonify/version.h"


static error_t parse_opt(int key, char *arg, struct argp_state *state);

static struct ameba_input_arg global_ameba_input_arg;
static struct ameba_input global_ameba_input_initial_value;

static unsigned long long min_log_file_size_bytes = (100ULL * 1024 * 1024); // 100 MB
static unsigned long long max_log_file_size_bytes = (10ULL * 1024 * 1024 * 1024); // 10 GB

static unsigned int min_log_file_count = 1;
static unsigned int max_log_file_count = 100;

enum
{
    OPT_LOG_DIR_PATH = 'o',
    OPT_LOG_FILE_SIZE_BYTES = 's',
    OPT_LOG_FILE_COUNT = 'c',
    OPT_VERSION = 'v',
    OPT_HELP = '?',
    OPT_USAGE = 'u'
};

// Option definitions
static struct argp_option options[] = {
    {"log-dir", OPT_LOG_DIR_PATH, "PATH", 0, "Directory to write the log files to", 0},
    {"log-size", OPT_LOG_FILE_SIZE_BYTES, "NUMBER", 0, "Size (in bytes) of a log file", 0},
    {"log-count", OPT_LOG_FILE_COUNT, "NUMBER", 0, "Maximum number of log files", 0},
    {"version", OPT_VERSION, 0, 0, "Show version"},
    {"help", OPT_HELP, 0, 0, "Show help"},
    {"usage", OPT_USAGE, 0, 0, "Show usage"},
    {0}
};

static struct argp global_ameba_input_argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = ARGP_DOC_COPYRIGHT_STR("Program to manage ameba"),
    .children = 0,
    .help_filter = 0,
    .argp_domain = 0
};

static struct ameba_input_arg *get_global_ameba_input_arg()
{
    return &global_ameba_input_arg;
}

static struct ameba_input *get_global_ameba_input_initial_value()
{
    return &global_ameba_input_initial_value;
}

static void init_ameba_input(struct ameba_input_arg *input)
{
    if (!input)
        return;
    memcpy(&input->ameba_input, get_global_ameba_input_initial_value(), sizeof(struct ameba_input));
    user_args_parse_state_init(&(input->parse_state));
}

static void validate_ameba_input(struct ameba_input_arg *input, struct argp_state *state)
{
    if (input->ameba_input.log_dir_path[0] == 0)
    {
        fprintf(stderr, "Must specify a valid log dir path. Use --help.\n");
        user_args_parse_state_set_exit_error(&input->parse_state, -1);
        return;
    }
    if (input->ameba_input.log_file_size_bytes < min_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at least %llu MB. Use --help.\n", (min_log_file_size_bytes / (1024 * 1024)));
        user_args_parse_state_set_exit_error(&input->parse_state, -1);
        return;
    }
    if (input->ameba_input.log_file_size_bytes > max_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at most %llu MB. Use --help.\n", (max_log_file_size_bytes / (1024 * 1024)));
        user_args_parse_state_set_exit_error(&input->parse_state, -1);
        return;
    }
    if (input->ameba_input.log_file_count < min_log_file_count)
    {
        fprintf(stderr, "Log file count should be at least %u. Use --help.\n", min_log_file_count);
        user_args_parse_state_set_exit_error(&input->parse_state, -1);
        return;
    }
    if (input->ameba_input.log_file_count > max_log_file_count)
    {
        fprintf(stderr, "Log file count should be at most %u. Use --help.\n", max_log_file_count);
        user_args_parse_state_set_exit_error(&input->parse_state, -1);
        return;
    }
}

static void parse_arg_log_dir_path(struct ameba_input_arg *dst, struct argp_state *state, char* path)
{
    if (!path || strlen(path) == 0) {
        fprintf(stderr, "Invalid log dir path: missing path\n");
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    if (path[0] != '/') {
        fprintf(stderr, "Invalid log dir path: path is not absolute\n");
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    if (strlen(path) > PATH_MAX) {
        fprintf(stderr, "Invalid log dir path: path too long\n");
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    strncpy(&(dst->ameba_input.log_dir_path[0]), path, strnlen(path, PATH_MAX));
}

static void parse_arg_log_file_size_bytes(struct ameba_input_arg *dst, struct argp_state *state, char *arg)
{
    if (!arg || strlen(arg) == 0) {
        fprintf(stderr, "Invalid log file size: missing argument\n");
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    char *endptr = NULL;
    errno = 0;

    unsigned long long bytes = strtoull(arg, &endptr, 10);

    if (errno != 0 || endptr == arg || *endptr != '\0') {
        fprintf(stderr, "Invalid log file size: not a valid number: %s\n", arg);
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    if (bytes < min_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at least %llu MB. Use --help.\n", (min_log_file_size_bytes / (1024 * 1024)));
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    if (bytes > max_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at most %llu MB. Use --help.\n", (max_log_file_size_bytes / (1024 * 1024)));
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    dst->ameba_input.log_file_size_bytes = bytes;
}

static void parse_arg_log_file_count(struct ameba_input_arg *dst, struct argp_state *state, char *arg)
{
    if (!arg || strlen(arg) == 0) {
        fprintf(stderr, "Invalid log file count: missing argument\n");
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    char *endptr = NULL;
    errno = 0;

    unsigned long count = strtoul(arg, &endptr, 10);

    if (errno != 0 || endptr == arg || *endptr != '\0') {
        fprintf(stderr, "Invalid log file count: not a valid number: %s\n", arg);
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    if (count < min_log_file_count)
    {
        fprintf(stderr, "Log file count should be at least %u. Use --help.\n", min_log_file_count);
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }
    if (count > max_log_file_count)
    {
        fprintf(stderr, "Log file count should be at most %u. Use --help.\n", max_log_file_count);
        user_args_parse_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    dst->ameba_input.log_file_count = (unsigned int)count;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct ameba_input_arg *input = get_global_ameba_input_arg();

    switch (key)
    {
    case OPT_LOG_DIR_PATH:
        parse_arg_log_dir_path(input, state, arg);
        break;

    case OPT_LOG_FILE_SIZE_BYTES:
        parse_arg_log_file_size_bytes(input, state, arg);
        break;

    case OPT_LOG_FILE_COUNT:
        parse_arg_log_file_count(input, state, arg);
        break;

    case OPT_VERSION:
        jsonify_version_write_all_versions_to_file(stdout);
        user_args_parse_state_set_exit_no_error(&input->parse_state);
        break;

    case OPT_HELP:
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        user_args_parse_state_set_exit_no_error(&input->parse_state);
        break;

    case OPT_USAGE:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        user_args_parse_state_set_exit_no_error(&input->parse_state);
        break;

    case ARGP_KEY_INIT:
        init_ameba_input(input);
        break;

    case ARGP_KEY_ERROR:
    case ARGP_KEY_ARG:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        user_args_parse_state_set_exit_error(&input->parse_state, -1);
        break;

    case ARGP_KEY_END:
        validate_ameba_input(input, state);
        break;

    default:
        break;
    }

    return 0;
}

void user_args_ameba_parse(
    struct ameba_input_arg *dst,
    struct ameba_input *initial_value,
    int argc, char **argv
)
{
    if (!dst)
        return;

    if (!initial_value)
        memset(&global_ameba_input_initial_value, 0, sizeof(struct ameba_input));
    else
        memcpy(&global_ameba_input_initial_value, initial_value, sizeof(struct ameba_input));

    int argp_flags = 0;
    // ARGP_NO_EXIT & ARGP_NO_HELP because self-managed
    argp_flags = ARGP_NO_EXIT | ARGP_NO_HELP;
    argp_parse(&global_ameba_input_argp, argc, argv, argp_flags, 0, 0);
    
    memcpy(dst, get_global_ameba_input_arg(), sizeof(struct ameba_input_arg));
}
