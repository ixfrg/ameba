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
#include <linux/limits.h>

#include "common/constants.h"
#include "user/arg/ameba.h"
#include "user/arg/parse_state.h"
#include "common/version.h"
#include "user/jsonify/types.h"
#include "user/jsonify/version.h"


/*
    argp function declaration.
*/
static error_t parse_opt(int key, char *arg, struct argp_state *state);

/*
    Constants.
*/
static unsigned long long min_log_file_size_bytes = (100ULL * 1024 * 1024); // 100 MB
static unsigned long long max_log_file_size_bytes = (10ULL * 1024 * 1024 * 1024); // 10 GB
static unsigned int min_log_file_count = 1;
static unsigned int max_log_file_count = 100;

/*
    Globals.
*/
static struct arg_ameba_with_parse_state global_arg_with_parse_state;
static struct arg_ameba global_arg_initial_value;

/*
    argp options.
*/
enum
{
    OPT_OUTPUT_TO_STDOUT = 't',
    OPT_LOG_DIR_PATH = 'o',
    OPT_LOG_FILE_SIZE_BYTES = 's',
    OPT_LOG_FILE_COUNT = 'c',
    OPT_VERSION = 'v',
    OPT_HELP = '?',
    OPT_USAGE = 'u'
};

// Option definitions
static struct argp_option options[] = {
    {"output-stdout", OPT_OUTPUT_TO_STDOUT, 0, 0, "Output to stdout instead of log file", 0},
    {"log-dir", OPT_LOG_DIR_PATH, "PATH", 0, "Directory to write the log files to", 0},
    {"log-size", OPT_LOG_FILE_SIZE_BYTES, "NUMBER", 0, "Size (in bytes) of a log file", 0},
    {"log-count", OPT_LOG_FILE_COUNT, "NUMBER", 0, "Maximum number of log files", 0},
    {"version", OPT_VERSION, 0, 0, "Show version"},
    {"help", OPT_HELP, 0, 0, "Show help"},
    {"usage", OPT_USAGE, 0, 0, "Show usage"},
    {0}
};

static struct argp global_argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = ARGP_DOC_COPYRIGHT_STR("Program to manage ameba"),
    .children = 0,
    .help_filter = 0,
    .argp_domain = 0
};

static struct argp *get_global_argp()
{
    return &global_argp;
}

static struct arg_ameba_with_parse_state *get_global_arg_with_parse_state()
{
    return &global_arg_with_parse_state;
}

static struct arg_ameba *get_global_arg_initial_value()
{
    return &global_arg_initial_value;
}

static void set_global_initial_value(struct arg_ameba *src)
{
    if (!src)
        memset(get_global_arg_initial_value(), 0, sizeof(struct arg_ameba));
    else
        memcpy(get_global_arg_initial_value(), src, sizeof(struct arg_ameba));
}

static void copy_global_parsed_value_with_state(struct arg_ameba_with_parse_state *dst)
{
    memcpy(dst, get_global_arg_with_parse_state(), sizeof(struct arg_ameba_with_parse_state));
}

static void initialize_arg_with_parse_state(struct arg_ameba_with_parse_state *src)
{
    if (!src)
        return;
    memcpy(&src->arg, get_global_arg_initial_value(), sizeof(struct arg_ameba));
    arg_parse_state_init(&(src->parse_state));
}

static void validate_arg(struct arg_ameba_with_parse_state *src, struct argp_state *state)
{
    if (src->arg.log_dir_path[0] == 0)
    {
        fprintf(stderr, "Must specify a valid log dir path. Use --help.\n");
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }
    if (src->arg.log_file_size_bytes < min_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at least %llu MB. Use --help.\n", (min_log_file_size_bytes / (1024 * 1024)));
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }
    if (src->arg.log_file_size_bytes > max_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at most %llu MB. Use --help.\n", (max_log_file_size_bytes / (1024 * 1024)));
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }
    if (src->arg.log_file_count < min_log_file_count)
    {
        fprintf(stderr, "Log file count should be at least %u. Use --help.\n", min_log_file_count);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }
    if (src->arg.log_file_count > max_log_file_count)
    {
        fprintf(stderr, "Log file count should be at most %u. Use --help.\n", max_log_file_count);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }
}

static void parse_arg_log_dir_path(struct arg_ameba_with_parse_state *src, struct argp_state *state, char* path)
{
    if (!path || strlen(path) == 0) {
        fprintf(stderr, "Invalid log dir path: missing path\n");
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    if (path[0] != '/') {
        fprintf(stderr, "Invalid log dir path: path is not absolute\n");
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    if (strlen(path) > PATH_MAX) {
        fprintf(stderr, "Invalid log dir path: path too long\n");
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    strncpy(&(src->arg.log_dir_path[0]), path, strnlen(path, PATH_MAX));
}

static void parse_arg_log_file_size_bytes(struct arg_ameba_with_parse_state *src, struct argp_state *state, char *arg)
{
    if (!arg || strlen(arg) == 0) {
        fprintf(stderr, "Invalid log file size: missing argument\n");
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    char *endptr = NULL;
    errno = 0;

    unsigned long long bytes = strtoull(arg, &endptr, 10);

    if (errno != 0 || endptr == arg || *endptr != '\0') {
        fprintf(stderr, "Invalid log file size: not a valid number: %s\n", arg);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    if (bytes < min_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at least %llu MB. Use --help.\n", (min_log_file_size_bytes / (1024 * 1024)));
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    if (bytes > max_log_file_size_bytes)
    {
        fprintf(stderr, "Log file size should be at most %llu MB. Use --help.\n", (max_log_file_size_bytes / (1024 * 1024)));
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    src->arg.log_file_size_bytes = bytes;
}

static void parse_arg_log_file_count(struct arg_ameba_with_parse_state *src, struct argp_state *state, char *arg)
{
    if (!arg || strlen(arg) == 0) {
        fprintf(stderr, "Invalid log file count: missing argument\n");
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    char *endptr = NULL;
    errno = 0;

    unsigned long count = strtoul(arg, &endptr, 10);

    if (errno != 0 || endptr == arg || *endptr != '\0') {
        fprintf(stderr, "Invalid log file count: not a valid number: %s\n", arg);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    if (count < min_log_file_count)
    {
        fprintf(stderr, "Log file count should be at least %u. Use --help.\n", min_log_file_count);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }
    if (count > max_log_file_count)
    {
        fprintf(stderr, "Log file count should be at most %u. Use --help.\n", max_log_file_count);
        arg_parse_state_set_exit_error(&src->parse_state, -1);
        return;
    }

    src->arg.log_file_count = (unsigned int)count;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arg_ameba_with_parse_state *arg_with_state = get_global_arg_with_parse_state();

    switch (key)
    {
    case OPT_OUTPUT_TO_STDOUT:
        arg_with_state->arg.output_stdout = 1;
        break;

    case OPT_LOG_DIR_PATH:
        parse_arg_log_dir_path(arg_with_state, state, arg);
        break;

    case OPT_LOG_FILE_SIZE_BYTES:
        parse_arg_log_file_size_bytes(arg_with_state, state, arg);
        break;

    case OPT_LOG_FILE_COUNT:
        parse_arg_log_file_count(arg_with_state, state, arg);
        break;

    case OPT_VERSION:
        jsonify_version_write_all_versions_to_file(stdout);
        arg_parse_state_set_exit_no_error(&arg_with_state->parse_state);
        break;

    case OPT_HELP:
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        arg_parse_state_set_exit_no_error(&arg_with_state->parse_state);
        break;

    case OPT_USAGE:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        arg_parse_state_set_exit_no_error(&arg_with_state->parse_state);
        break;

    case ARGP_KEY_INIT:
        initialize_arg_with_parse_state(arg_with_state);
        break;

    case ARGP_KEY_ERROR:
    case ARGP_KEY_ARG:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        arg_parse_state_set_exit_error(&arg_with_state->parse_state, -1);
        break;

    case ARGP_KEY_END:
        validate_arg(arg_with_state, state);
        break;

    default:
        break;
    }

    return 0;
}

int arg_ameba_parse(
    struct arg_ameba_with_parse_state *dst,
    struct arg_ameba *initial_value,
    int argc, char **argv
)
{
    if (!dst)
    {
        fprintf(stderr, "Failed arg_ameba_parse. NULL argument(s)");
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