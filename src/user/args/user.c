#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "user/args/control.h"
#include "user/args/user.h"

static char doc[] = "Parse User Input";
static char args_doc[] = "";

static void *child_parser_inputs[1];

enum
{
    OPT_RECORD_OUTPUT_FILE = 'f',
    OPT_RECORD_OUTPUT_NET_IP = 'N',
    OPT_RECORD_OUTPUT_NET_PORT = 's'
};

// Option definitions
static struct argp_option options[] = {
    {"file-path", OPT_RECORD_OUTPUT_FILE, "OUTPUT METHOD", OPTION_ARG_OPTIONAL, "Path of the file to write the records to", 0},
    {"ip", OPT_RECORD_OUTPUT_NET_IP, "OUTPUT METHOD", OPTION_ARG_OPTIONAL, "IP address to write the records to", 0},
    {"port", OPT_RECORD_OUTPUT_NET_PORT, "OUTPUT METHOD", OPTION_ARG_OPTIONAL, "IP port to write the records to", 0},
    {0}};


static error_t validate_user_input(struct user_input *input, struct argp_state *state)
{
    if (input->o_type == OUTPUT_NONE)
    {
        argp_failure(state, -1, -1, "Must specify exactly one output method");
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int parse_arg_output_file(struct user_input *dst, char *arg, struct argp_state *state)
{
    if (dst->o_type == OUTPUT_NET)
    {
        argp_failure(state, -1, -1, "Cannot specify multiple output types.");
        return ARGP_ERR_UNKNOWN;
    }
    if (!arg)
    {
        argp_failure(state, -1, -1, "NULL output file path.");
        return ARGP_ERR_UNKNOWN;
    }
    if (snprintf(&(dst->output.file.path[0]), PATH_MAX, "%s", arg) >= PATH_MAX)
    {
        argp_failure(state, -1, -1, "Output file path too long.");
        return ARGP_ERR_UNKNOWN;
    }
    dst->o_type = OUTPUT_FILE;
    return 0;
}

static int parse_ip(struct user_input *dst, char *arg, struct argp_state *state)
{
    if (dst->o_type == OUTPUT_FILE)
    {
        argp_failure(state, -1, -1, "Cannot specify multiple output types.");
        return ARGP_ERR_UNKNOWN;
    }

    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (!arg) {
        argp_failure(state, -1, -1, "NULL ip.");
        return ARGP_ERR_UNKNOWN;
    }

    if (inet_pton(AF_INET, arg, &ipv4) == 1) {
        char *buf = (char*)&(dst->output.net.ip[0]);
        if (inet_ntop(AF_INET, &ipv4, buf, INET6_ADDRSTRLEN)) {
            dst->output.net.ip_version = 4;
            dst->o_type = OUTPUT_NET;
            return 0;
        }
    }

    if (inet_pton(AF_INET6, arg, &ipv6) == 1) {
        char *buf = (char*)&(dst->output.net.ip[0]);
        if (inet_ntop(AF_INET6, &ipv6, buf, INET6_ADDRSTRLEN)) {
            dst->output.net.ip_version = 6;
            dst->o_type = OUTPUT_NET;
            return 0;
        }
    }

    argp_failure(state, -1, -1, "Not an ip address: '%s'.", arg);
    return ARGP_ERR_UNKNOWN;
}

static int parse_port(struct user_input *dst, char *arg, struct argp_state *state) {
    if (dst->o_type == OUTPUT_FILE)
    {
        argp_failure(state, -1, -1, "Cannot specify multiple output types.");
        return ARGP_ERR_UNKNOWN;
    }

    if (!arg) {
        argp_failure(state, -1, -1, "NULL port.");
        return ARGP_ERR_UNKNOWN;
    }

    char *endptr = NULL;
    errno = 0;
    long port = strtol(arg, &endptr, 10);

    if (*endptr != '\0' || errno != 0 || port < 1 || port > 65535)
    {
        argp_failure(state, -1, -1, "Not a port number: '%s'.", arg);
        return ARGP_ERR_UNKNOWN;
    }

    dst->output.net.port = (uint16_t)port;
    dst->o_type = OUTPUT_NET;
    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct user_input *input = state->input;

    switch (key)
    {
    case OPT_RECORD_OUTPUT_FILE:
        return parse_arg_output_file(input, arg, state);

    case OPT_RECORD_OUTPUT_NET_IP:
        return parse_ip(input, arg, state);

    case OPT_RECORD_OUTPUT_NET_PORT:
        return parse_port(input, arg, state);

    case ARGP_KEY_INIT:
        printf("hello %p\n", input);
        child_parser_inputs[0] = &(input->c_in);
        state->child_inputs = child_parser_inputs;
        printf("hello %p\n", state->child_inputs[0]);
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

static struct argp_child argp_children[] = {
    {&control_input_argp, 0, "Control input arguments", 0},
    {0}
};

static struct argp argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = args_doc,
    .doc = doc,
    .children = argp_children,
    .help_filter = 0,
    .argp_domain = 0};

static void init_user_input(struct user_input *input)
{
    memset(input, 0, sizeof(*input));
    input->o_type = OUTPUT_NONE;
    init_control_input(&(input->c_in));
}

int user_args_user_must_parse_user_input(struct user_input *dst, int argc, char **argv)
{
    init_user_input(dst);

    error_t err = argp_parse(&argp, argc, argv, 0, 0, dst);

    return err;
}
