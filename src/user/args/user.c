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

#include "common/constants.h"
#include "user/args/control.h"
#include "user/args/user.h"
#include "user/args/helper.h"
#include "common/version.h"
#include "user/jsonify/types.h"
#include "user/jsonify/version.h"


static error_t parse_opt(int key, char *arg, struct argp_state *state);


static struct user_input_arg global_user_input_arg;


enum
{
    OPT_RECORD_OUTPUT_URI = 'o',
    OPT_VERSION = 'v',
    OPT_HELP = '?',
    OPT_USAGE = 'u'
};

// Option definitions
static struct argp_option options[] = {
    {"output-uri", OPT_RECORD_OUTPUT_URI, "URI", 0, "URI to write the records to. Supported: [file://<absolute file path>], or [udp://<ip>:port]", 0},
    {"version", OPT_VERSION, 0, 0, "Show version"},
    {"help", OPT_HELP, 0, 0, "Show help"},
    {"usage", OPT_USAGE, 0, 0, "Show usage"},
    {0}
};

static struct argp_child argp_children[] = {
    {&global_control_input_argp, 0, "Control input options", 0},
    {0}
};

static struct argp global_user_input_argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "",
    .doc = ARGP_DOC_COPYRIGHT_STR("Program to manage ameba"),
    .children = argp_children,
    .help_filter = 0,
    .argp_domain = 0
};

static struct user_input_arg *get_global_user_input_arg()
{
    return &global_user_input_arg;
}

static void init_user_input(struct user_input_arg *input)
{
    if (!input)
        return;
    memset(input, 0, sizeof(*input));
    input->user_input.o_type = default_output_type;
    memcpy(&(input->user_input.output_file.path), default_output_file_path, strlen(default_output_file_path));
    input->user_input.output_net.ip_family = 0;
    input->user_input.output_net.port = -1;
    input->user_input.output_net.ip[0] = 0;
    user_args_helper_state_init(&(input->parse_state));
}

static void validate_user_input(struct user_input_arg *input, struct argp_state *state)
{
    if (input->user_input.o_type == OUTPUT_NONE)
    {
        fprintf(stderr, "Must specify exactly one output method. Use --help.\n");
        user_args_helper_state_set_exit_error(&input->parse_state, -1);
        return;
    }
    if (input->user_input.o_type == OUTPUT_NET)
    {
        if (input->user_input.output_net.ip[0] == 0)
        {
            fprintf(stderr, "Must specify IP for network output method. Use --help.\n");
            user_args_helper_state_set_exit_error(&input->parse_state, -1);
            return;
        }
        if (input->user_input.output_net.port < 1 || input->user_input.output_net.port > 65535)
        {
            fprintf(stderr, "Must specify a valid port for network output method. Use --help.\n");
            user_args_helper_state_set_exit_error(&input->parse_state, -1);
            return;
        }
    }
}

static void parse_arg_output_uri_file(struct user_input_arg *dst, struct argp_state *state, const char* path)
{
    if (!path || strlen(path) == 0) {
        fprintf(stderr, "Invalid file URI: missing path\n");
        user_args_helper_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    if (path[0] != '/') {
        fprintf(stderr, "Invalid file URI: path is not absolute\n");
        user_args_helper_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    if (strlen(path) > PATH_MAX) {
        fprintf(stderr, "Invalid file URI: path too long\n");
        user_args_helper_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    strncpy(&(dst->user_input.output_file.path[0]), path, PATH_MAX);

    dst->user_input.o_type = OUTPUT_FILE;
}

static void parse_arg_output_uri_net_udp(struct user_input_arg *dst, struct argp_state *state, const char *uri_stripped_val)
{
    const char *ip_start = uri_stripped_val;
    const char *ip_end = NULL;
    const char *port_str = NULL;
    size_t ip_len;

    if (*ip_start == '[') {
        // ipv6
        ip_start++; // skip '['
        ip_end = strchr(ip_start, ']');
        if (!ip_end) {
            fprintf(stderr, "Invalid UDP URI: unmatched '['\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        if (*(ip_end + 1) != ':') {
            fprintf(stderr, "Invalid UDP URI: expected ':' after ']'\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        ip_len = ip_end - ip_start;
        if (ip_len == 0) {
            fprintf(stderr, "Invalid UDP URI: empty IP\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        strncpy(&(dst->user_input.output_net.ip[0]), ip_start, ip_len);
        struct in6_addr ipv6;
        if (inet_pton(AF_INET6, &(dst->user_input.output_net.ip[0]), &ipv6) == 0) {
            fprintf(stderr, "Invalid UDP URI: invalid IPv6\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        port_str = ip_end + 2; // skip "]:" to point to port
        dst->user_input.output_net.ip_family = AF_INET6;
    } else {
        // ipv4
        ip_end = strchr(ip_start, ':');
        if (!ip_end) {
            fprintf(stderr, "Invalid UDP URI: missing port\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        ip_len = ip_end - ip_start;
        if (ip_len == 0) {
            fprintf(stderr, "Invalid UDP URI: empty IP\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        strncpy(&(dst->user_input.output_net.ip[0]), ip_start, ip_len);
        struct in_addr ipv4;
        if (inet_pton(AF_INET, &(dst->user_input.output_net.ip[0]), &ipv4) == 0) {
            fprintf(stderr, "Invalid UDP URI: invalid IPv4\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        port_str = ip_end + 1;
        dst->user_input.output_net.ip_family = AF_INET;
    }

    if (strlen(port_str) == 0) {
        fprintf(stderr, "Invalid UDP URI: empty port\n");
        user_args_helper_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    char *endptr = NULL;
    long port = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid UDP URI: invalid port number\n");
        user_args_helper_state_set_exit_error(&dst->parse_state, -1);
        return;
    }

    dst->user_input.output_net.port = (int)port;
    dst->user_input.o_type = OUTPUT_NET;
}

static void parse_arg_output_uri(struct user_input_arg *dst, char *arg, struct argp_state *state)
{
    if (!arg || strlen(arg) == 0) {
        fprintf(stderr, "Invalid URI: argument is empty\n");
        return;
    }

    if (strncmp(arg, "file://", 7) == 0) {
        const char *path = arg + 7;
        parse_arg_output_uri_file(dst, state, path);
    } else if (strncmp(arg, "udp://", 6) == 0) {
        const char *addr = arg + 6;
        parse_arg_output_uri_net_udp(dst, state, addr);
    } else {
        fprintf(stderr, "Unsupported URI scheme. Use file:// or udp://\n");
        user_args_helper_state_set_exit_error(&dst->parse_state, -1);
        return;
    }
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct user_input_arg *input = get_global_user_input_arg();

    switch (key)
    {
    case OPT_RECORD_OUTPUT_URI:
        parse_arg_output_uri(input, arg, state);
        break;

    case OPT_VERSION:
        jsonify_version_write_all_versions_to_file(stdout);
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
        init_user_input(input);
        break;

    case ARGP_KEY_ERROR:
    case ARGP_KEY_ARG:
        argp_state_help(state, stdout, ARGP_HELP_USAGE);
        user_args_helper_state_set_exit_error(&input->parse_state, -1);
        break;

    case ARGP_KEY_END:
        validate_user_input(input, state);
        break;

    default:
        break;
    }

    return 0;
}

void user_args_user_copy(struct user_input_arg *dst)
{
    if (!dst)
        return;
    memcpy(dst, get_global_user_input_arg(), sizeof(struct user_input_arg));
}

void user_args_user_parse(struct user_input_arg *dst, int argc, char **argv)
{
    if (!dst)
        return;

    int argp_flags = 0;
    // ARGP_NO_EXIT & ARGP_NO_HELP because self-managed
    argp_flags = ARGP_NO_EXIT | ARGP_NO_HELP;
    argp_parse(&global_user_input_argp, argc, argv, argp_flags, 0, 0);
    
    user_args_user_copy(dst);
    user_args_control_copy_only_control_input(&(dst->user_input.c_in));
}
