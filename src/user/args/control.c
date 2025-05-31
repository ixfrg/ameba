#include <argp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "user/jsonify/control.h"

#include "user/args/control.h"

static char doc[] = "Parse Control Input";
static char args_doc[] = "";

enum
{
    OPT_GLOBAL_MODE = 'g',
    OPT_UID_MODE = 'u',
    OPT_UID_LIST = 'U',
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
    {0}};

static int find_string_index(const char *haystack, const char *needle)
{
    char *result = strstr(haystack, needle);
    return result ? (int)(result - haystack) : -1;
}

static error_t parse_mode(trace_mode_t *dst, char *mode_str, struct argp_state *state)
{
    if (find_string_index("ignore", mode_str) == 0 && strlen(mode_str) <= strlen("ignore"))
    {
        *dst = IGNORE;
        return 0;
    }
    else if (find_string_index("capture", mode_str) == 0 && strlen(mode_str) <= strlen("capture"))
    {
        *dst = CAPTURE;
        return 0;
    }
    else
    {
        // argp_error(state, "Invalid mode '%s'. Use 'ignore' or 'capture'", mode_str);
        argp_failure(state, -1, -1, "Invalid mode '%s'. Use 'ignore' or 'capture'", mode_str);
        return ARGP_ERR_UNKNOWN;
    }
}

static error_t parse_int_list(
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
            argp_failure(state, -1, -1, "Invalid number in list: '%s'", token);
            free(str_copy);
            return ARGP_ERR_UNKNOWN;
        }

        if (negative_disallowed)
        {
            if (val < 0)
            {
                // NOTE: Free str_copy if not using argp_error anymore.
                // argp_error(state, "Negative number not allowed in list: '%ld'", val);
                argp_failure(state, -1, -1, "Negative number not allowed in list: '%ld'", val);
                free(str_copy);
                return ARGP_ERR_UNKNOWN;
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
        argp_failure(state, -1, -1, "Too many items in list (max %d)", max_items);
        return ARGP_ERR_UNKNOWN;
    }

    *array_len = len;

    return 0;
}

static error_t validate_control_input(struct control_input *input, struct argp_state *state)
{
    // TODO
    /*
    if (input->global_mode == NOT_SET)
    {
        // argp_error(state, "Required option -%c is missing", OPT_GLOBAL_MODE);
        argp_failure(state, -1, -1, "Required option -%c is missing", OPT_GLOBAL_MODE);
        return ARGP_ERR_UNKNOWN;
    }
    */
    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct control_input *input = state->input;

    int negative_disallowed = 1;

    switch (key)
    {
    case OPT_GLOBAL_MODE:
        return parse_mode(&input->global_mode, arg, state);

    case OPT_UID_MODE:
        return parse_mode(&input->uid_mode, arg, state);

    case OPT_UID_LIST:
        return parse_int_list(arg, (int *)input->uids, &input->uids_len, MAX_LIST_ITEMS, negative_disallowed, state);

    case OPT_PID_MODE:
        return parse_mode(&input->pid_mode, arg, state);

    case OPT_PID_LIST:
        return parse_int_list(arg, (int *)input->pids, &input->pids_len, MAX_LIST_ITEMS, negative_disallowed, state);

    case OPT_PPID_MODE:
        return parse_mode(&input->ppid_mode, arg, state);

    case OPT_PPID_LIST:
        return parse_int_list(arg, (int *)input->ppids, &input->ppids_len, MAX_LIST_ITEMS, negative_disallowed, state);

    case OPT_NETIO_MODE:
        return parse_mode(&input->netio_mode, arg, state);

    case ARGP_KEY_ARG:
        // No positional arguments expected
        argp_usage(state);
        break;

    case ARGP_KEY_END:
        return validate_control_input(input, state);

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

// Argp parser structure TODO
static struct argp argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = args_doc,
    .doc = doc,
    .children = 0,
    .help_filter = 0,
    .argp_domain = 0};

static void init_control_input(struct control_input *input)
{
    input->lock = FREE;
    input->global_mode = IGNORE;
    input->uid_mode = IGNORE;
    input->uids_len = 0;
    input->pid_mode = IGNORE;
    input->pids_len = 0;
    input->ppid_mode = IGNORE;
    input->ppids_len = 0;
    input->netio_mode = IGNORE;
}

int user_args_control_must_parse_control_input(struct control_input *dst, int argc, char **argv)
{
    init_control_input(dst);

    error_t err = argp_parse(&argp, argc, argv, 0, 0, dst);

    // if (err == 0)
    // {
    //     print_control_input(dst);
    // }
    return err;
}
