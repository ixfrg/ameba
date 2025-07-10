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
#include <arpa/inet.h>


#include "user/args/control.h"
#include "user/args/user.h"
#include "common/version.h"
#include "user/jsonify/types.h"


static error_t parse_opt(int key, char *arg, struct argp_state *state);


static struct user_input global_user_input;


enum
{
    OPT_RECORD_OUTPUT_FILE = 'f',
    OPT_RECORD_OUTPUT_NET_IP = 'N',
    OPT_RECORD_OUTPUT_NET_PORT = 's',
    OPT_VERSION = 'v',
    OPT_HELP = '?',
    OPT_USAGE = 'u'
};

// Option definitions
static struct argp_option options[] = {
    {"file-path", OPT_RECORD_OUTPUT_FILE, "FILE_PATH", 0, "Path of the file to write the records to", 0},
    {"ip", OPT_RECORD_OUTPUT_NET_IP, "IP", 0, "IP address to write the records to", 0},
    {"port", OPT_RECORD_OUTPUT_NET_PORT, "PORT", 0, "IP port to write the records to", 0},
    {"version", OPT_VERSION, 0, 0, "Show version"},
    {"help", OPT_HELP, 0, 0, "Show help"},
    {"usage", OPT_USAGE, 0, 0, "Show usage"},
    {0}
};

static struct argp_child argp_children[] = {
    {&global_control_input_argp, 0, "Control input arguments", 0},
    {0}
};

static struct argp global_user_input_argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = "\nAMEBA  Copyright (C) 2025  Hassaan Irshad\nThis program comes with ABSOLUTELY NO WARRANTY; for details type `--help'.\nThis is free software, and you are welcome to redistribute it under certain conditions; type `--help' for details.\n",
    .children = argp_children,
    .help_filter = 0,
    .argp_domain = 0
};

static struct user_input *get_global_user_input()
{
    return &global_user_input;
}

static void init_arg_parse_state(struct arg_parse_state *s)
{
    if (!s)
        return;
    s->exit = 0;
    s->code = 0;
}

static void set_arg_parser_exit_error(struct user_input *input, int code)
{
    if (!input)
        return;
    input->parse_state.exit = 1;
    input->parse_state.code = code;
}

static void set_arg_parser_exit_no_error(struct user_input *input)
{
    if (!input)
        return;
    input->parse_state.exit = 1;
    input->parse_state.code = 0;
}

static void init_user_input(struct user_input *input)
{
    if (!input)
        return;
    memset(input, 0, sizeof(*input));
    input->o_type = default_output_type;
    memcpy(&(input->output_file.path), default_output_file_path, strlen(default_output_file_path));
    input->output_net.ip_family = 0;
    input->output_net.port = -1;
    input->output_net.ip[0] = 0;
    init_arg_parse_state(&(input->parse_state));
}

static error_t validate_user_input(struct user_input *input, struct argp_state *state)
{
    if (input->o_type == OUTPUT_NONE)
    {
        set_arg_parser_exit_error(input, -1);
        fprintf(stderr, "Must specify exactly one output method. Use --help.\n");
        return ARGP_ERR_UNKNOWN;
    }
    if (input->o_type == OUTPUT_NET)
    {
        if (input->output_net.ip[0] == 0)
        {
            set_arg_parser_exit_error(input, -1);
            fprintf(stderr, "Must specify IP for network output method. Use --help.\n");
            return ARGP_ERR_UNKNOWN;
        }
        if (input->output_net.port < 1 || input->output_net.port > 65535)
        {
            set_arg_parser_exit_error(input, -1);
            fprintf(stderr, "Must specify a valid port for network output method. Use --help.\n");
            return ARGP_ERR_UNKNOWN;
        }
    }
    return 0;
}

static int parse_arg_output_file(struct user_input *dst, char *arg, struct argp_state *state)
{
    // if (dst->o_type == OUTPUT_NET)
    // {
    //     argp_failure(state, -1, -1, "Cannot specify multiple output types.");
    //     return ARGP_ERR_UNKNOWN;
    // }
    if (!arg)
    {
        fprintf(stderr, "NULL output file path. Use --help.\n");
        return ARGP_ERR_UNKNOWN;
    }
    if (snprintf(&(dst->output_file.path[0]), PATH_MAX, "%s", arg) >= PATH_MAX)
    {
        fprintf(stderr, "Output file path too long. Use --help.\n");
        return ARGP_ERR_UNKNOWN;
    }
    dst->o_type = OUTPUT_FILE;
    return 0;
}

static int parse_ip(struct user_input *dst, char *arg, struct argp_state *state)
{
    // if (dst->o_type == OUTPUT_FILE)
    // {
    //     argp_failure(state, -1, -1, "Cannot specify multiple output types.");
    //     return ARGP_ERR_UNKNOWN;
    // }

    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (!arg) {
        fprintf(stderr, "NULL ip. Use --help.\n");
        return ARGP_ERR_UNKNOWN;
    }

    if (inet_pton(AF_INET, arg, &ipv4) == 1) {
        char *buf = (char*)&(dst->output_net.ip[0]);
        if (inet_ntop(AF_INET, &ipv4, buf, INET6_ADDRSTRLEN)) {
            dst->output_net.ip_family = AF_INET;
            dst->o_type = OUTPUT_NET;
            return 0;
        }
    }

    if (inet_pton(AF_INET6, arg, &ipv6) == 1) {
        char *buf = (char*)&(dst->output_net.ip[0]);
        if (inet_ntop(AF_INET6, &ipv6, buf, INET6_ADDRSTRLEN)) {
            dst->output_net.ip_family = AF_INET6;
            dst->o_type = OUTPUT_NET;
            return 0;
        }
    }

    fprintf(stderr, "Not an ip address: '%s'. Use --help.\n", arg);
    return ARGP_ERR_UNKNOWN;
}

static int parse_port(struct user_input *dst, char *arg, struct argp_state *state) {
    if (dst->o_type == OUTPUT_FILE)
    {
        fprintf(stderr, "Cannot specify multiple output types. Use --help.\n");
        return ARGP_ERR_UNKNOWN;
    }

    if (!arg) {
        fprintf(stderr, "NULL port. Use --help.\n");
        return ARGP_ERR_UNKNOWN;
    }

    char *endptr = NULL;
    errno = 0;
    long port = strtol(arg, &endptr, 10);

    if (*endptr != '\0' || errno != 0 || port < 1 || port > 65535)
    {
        fprintf(stderr, "Not a port number: '%s'. Use --help.\n", arg);
        return ARGP_ERR_UNKNOWN;
    }

    dst->output_net.port = (uint16_t)port;
    dst->o_type = OUTPUT_NET;
    return 0;
}

void print_app_version()
{
    int dst_len = 512;
    char dst[dst_len];

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_types_write_version(&s, "app_version", &app_version);
    jsonify_types_write_version(&s, "record_version", &record_version);
    jsonify_core_write_str(&s, "libbpf_version", libbpf_version_string());

    jsonify_core_close_obj(&s);

    fprintf(stdout, "%s\n", &dst[0]);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct user_input *input = get_global_user_input();

    switch (key)
    {
    case OPT_RECORD_OUTPUT_FILE:
        return parse_arg_output_file(input, arg, state);

    case OPT_RECORD_OUTPUT_NET_IP:
        return parse_ip(input, arg, state);

    case OPT_RECORD_OUTPUT_NET_PORT:
        return parse_port(input, arg, state);

    case OPT_VERSION:
        print_app_version();
        set_arg_parser_exit_no_error(input);
        break;

    case OPT_HELP:
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        set_arg_parser_exit_no_error(input);
        break;

    case OPT_USAGE:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        set_arg_parser_exit_no_error(input);
        break;

    case ARGP_KEY_INIT:
        init_user_input(input);
        break;

    case ARGP_KEY_ARG:
        argp_usage(state);
        break;

    case ARGP_KEY_END:
        return validate_user_input(input, state);

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

void user_args_user_copy(struct user_input *dst)
{
    if (!dst)
        return;
    memcpy(dst, get_global_user_input(), sizeof(struct user_input));
}

int user_args_user_parse(struct user_input *dst, int argc, char **argv)
{
    if (!dst)
        return -1;

    int argp_flags = 0;
    // ARGP_NO_EXIT & ARGP_NO_HELP because self-managed
    argp_flags = ARGP_NO_EXIT | ARGP_NO_HELP;
    error_t err = argp_parse(&global_user_input_argp, argc, argv, argp_flags, 0, 0);
    
    user_args_user_copy(dst);
    user_args_control_copy(&(dst->c_in));

    return err;
}
