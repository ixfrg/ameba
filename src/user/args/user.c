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
#include "user/args/helper.h"
#include "common/version.h"
#include "user/jsonify/types.h"


extern const struct elem_version app_version;
extern const struct elem_version record_version;


static error_t parse_opt(int key, char *arg, struct argp_state *state);


static struct user_input global_user_input;


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
    user_args_helper_state_init(&(input->parse_state));
}

static void validate_user_input(struct user_input *input, struct argp_state *state)
{
    if (input->o_type == OUTPUT_NONE)
    {
        fprintf(stderr, "Must specify exactly one output method. Use --help.\n");
        user_args_helper_state_set_exit_error(&input->parse_state, -1);
        return;
    }
    if (input->o_type == OUTPUT_NET)
    {
        if (input->output_net.ip[0] == 0)
        {
            fprintf(stderr, "Must specify IP for network output method. Use --help.\n");
            user_args_helper_state_set_exit_error(&input->parse_state, -1);
            return;
        }
        if (input->output_net.port < 1 || input->output_net.port > 65535)
        {
            fprintf(stderr, "Must specify a valid port for network output method. Use --help.\n");
            user_args_helper_state_set_exit_error(&input->parse_state, -1);
            return;
        }
    }
}

static void parse_arg_output_uri_file(struct user_input *dst, struct argp_state *state, const char* path)
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

    strncpy(&(dst->output_file.path[0]), path, PATH_MAX);

    dst->o_type = OUTPUT_FILE;
}

static void parse_arg_output_uri_net_udp(struct user_input *dst, struct argp_state *state, const char *uri_stripped_val)
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

        strncpy(&(dst->output_net.ip[0]), ip_start, ip_len);
        struct in6_addr ipv6;
        if (inet_pton(AF_INET6, &(dst->output_net.ip[0]), &ipv6) == 0) {
            fprintf(stderr, "Invalid UDP URI: invalid IPv6\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        port_str = ip_end + 2; // skip "]:" to point to port
        dst->output_net.ip_family = AF_INET6;
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

        strncpy(&(dst->output_net.ip[0]), ip_start, ip_len);
        struct in_addr ipv4;
        if (inet_pton(AF_INET, &(dst->output_net.ip[0]), &ipv4) == 0) {
            fprintf(stderr, "Invalid UDP URI: invalid IPv4\n");
            user_args_helper_state_set_exit_error(&dst->parse_state, -1);
            return;
        }

        port_str = ip_end + 1;
        dst->output_net.ip_family = AF_INET;
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

    dst->output_net.port = (int)port;
    dst->o_type = OUTPUT_NET;
}

static void parse_arg_output_uri(struct user_input *dst, char *arg, struct argp_state *state)
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

void print_app_version()
{
    int dst_len = 512;
    char dst[dst_len];

    struct json_buffer s;
    jsonify_core_init(&s, dst, dst_len);
    jsonify_core_open_obj(&s);

    jsonify_types_write_version(&s, "app_version", &app_version);
    jsonify_types_write_version(&s, "record_version", &record_version);

    jsonify_core_close_obj(&s);

    fprintf(stdout, "%s\n", &dst[0]);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct user_input *input = get_global_user_input();

    switch (key)
    {
    case OPT_RECORD_OUTPUT_URI:
        parse_arg_output_uri(input, arg, state);
        break;

    case OPT_VERSION:
        print_app_version();
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

void user_args_user_copy(struct user_input *dst)
{
    if (!dst)
        return;
    memcpy(dst, get_global_user_input(), sizeof(struct user_input));
}

void user_args_user_parse(struct user_input *dst, int argc, char **argv)
{
    if (!dst)
        return;

    int argp_flags = 0;
    // ARGP_NO_EXIT & ARGP_NO_HELP because self-managed
    argp_flags = ARGP_NO_EXIT | ARGP_NO_HELP;
    argp_parse(&global_user_input_argp, argc, argv, argp_flags, 0, 0);
    
    user_args_user_copy(dst);
    user_args_control_copy(&(dst->c_in));
}
